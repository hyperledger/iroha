//! Actual nested by-call execution controls for the private pre-apply owner.
//! These exercise registered actions, not fabricated callback output claims.

use super::scheduled_time::recorded_component_block;
use super::*;
use crate::state::WorldReadOnly;
use iroha_data_model::{
    account::Account,
    events::{
        EventBox, execute_trigger::ExecuteTriggerEventFilter,
        trigger_completed::TriggerCompletedOutcome,
    },
    isi::{ExecuteTrigger, Register, SetKeyValue},
    transaction::Executable,
    trigger::{
        Trigger, TriggerId,
        action::{Action, Repeats},
    },
};

struct NestedCallbackFixture {
    state: State,
    source: SignedBlock,
    parent: TriggerId,
    child: TriggerId,
    key: Name,
    steps: Vec<DataTriggerStep>,
}

fn nested_callback_fixture(row_bytes: u64, depth: u8) -> NestedCallbackFixture {
    let state = authenticated_state(row_bytes);
    {
        let mut parameters = state.world.parameters.block();
        parameters
            .set_parameter(iroha_data_model::parameter::Parameter::SmartContract(
                iroha_data_model::parameter::SmartContractParameter::ExecutionDepth(depth),
            ))
            .expect("valid fixture parameters");
        parameters.commit();
    }
    let parent: TriggerId = "output_parent".parse().unwrap();
    let child: TriggerId = "output_child".parse().unwrap();
    let key: Name = "nested_callback_effect".parse().unwrap();
    let child_instructions = vec![
        InstructionBox::from(SetKeyValue::account(
            ALICE_ID.clone(),
            key.clone(),
            Json::new(7_u64),
        )),
        // An actual executed Log keeps the measured successful trace above the
        // maximum legal terminal-row floor. Its bytes are not synthetic output.
        InstructionBox::from(Log::new(Level::DEBUG, "x".repeat(16_384))),
    ];
    let parent_instructions = vec![InstructionBox::from(ExecuteTrigger::new(child.clone()))];
    let steps = vec![
        DataTriggerStep {
            id: parent.clone(),
            instructions: ExecutionStep(parent_instructions.clone().into()),
        },
        DataTriggerStep {
            id: child.clone(),
            instructions: ExecutionStep(child_instructions.clone().into()),
        },
    ];
    {
        let (mut setup, _setup_recording) = output_fixture_setup(&state);
        {
            let mut transaction = setup.transaction_for_callback_testing();
            Register::account(Account::new(ALICE_ID.clone()))
                .execute(&ALICE_ID, &mut transaction)
                .expect("register actual universal account");
            for (id, instructions) in [
                (child.clone(), child_instructions),
                (parent.clone(), parent_instructions),
            ] {
                let action = Action::new(
                    instructions,
                    Repeats::Exactly(1),
                    ALICE_ID.clone(),
                    ExecuteTriggerEventFilter::new()
                        .for_trigger(id.clone())
                        .under_authority(ALICE_ID.clone()),
                )
                .expect("valid actual by-call action");
                Register::trigger(Trigger::new(id, action))
                    .execute(&ALICE_ID, &mut transaction)
                    .expect("register actual by-call action");
            }
            // Setup only registers actions: no callback journal is discarded here.
            transaction.apply();
        }
        setup
            .commit_world_overlay_for_testing()
            .expect("commit fixture registry");
    }
    let header = output_fixture_header(&state);
    let mut transaction = TransactionBuilder::new(
        state.network_id,
        ALICE_ID.clone(),
        FeePaymentIntent::authority(vec![], None),
    );
    transaction.set_creation_time(
        header
            .creation_time()
            .checked_sub(std::time::Duration::from_millis(1))
            .unwrap(),
    );
    let signed = transaction
        .with_instructions([ExecuteTrigger::new(parent.clone())])
        .sign(ALICE_KEYPAIR.private_key());
    let mut builder = BlockBuilder::new(header);
    builder.set_execution_context(Some(
        iroha_data_model::block::BlockExecutionContextBundle::new(vec![
            iroha_data_model::block::ExternalExecutionContext::new(
                signed.hash_as_entrypoint(),
                iroha_model_base::topology::LaneId::SINGLE,
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            ),
        ]),
    ));
    builder.push_transaction(signed);
    let source = builder.build_with_signature(0, ALICE_KEYPAIR.private_key());
    NestedCallbackFixture {
        state,
        source,
        parent,
        child,
        key,
        steps,
    }
}

fn execute_nested_input(
    input: &TransactionEntrypoint,
    transaction: &mut StateTransaction<'_, '_>,
) -> Result<NetworkExecutionOutputV1, String> {
    let TransactionEntrypoint::External(signed) = input else {
        panic!("fixture is a real signed Network input");
    };
    let Executable::Instructions(instructions) = signed.instructions() else {
        panic!("fixture contains the actual ExecuteTrigger ISI");
    };
    let call = Hash::from(input.execution_call_hash());
    assert_eq!(transaction.tx_call_hash, Some(call));
    assert_eq!(transaction.current_tx_hash, Some(signed.hash()));
    for instruction in instructions.iter() {
        instruction
            .clone()
            .execute(signed.authority(), transaction)
            .map_err(|error| format!("actual nested callback failed: {error:?}"))?;
    }
    assert_eq!(transaction.tx_call_hash, Some(call));
    assert_eq!(transaction.current_tx_hash, Some(signed.hash()));
    // Only the real journal may supply the two callbacks, although the nested
    // ExecuteTrigger ISI itself returns no ExecutionStep to this closure.
    Ok(row(0, 0))
}

fn assert_nested_output(actual: &ExecutionOutputV1, fixture: &NestedCallbackFixture) {
    let ExecutionOutputV1::Network(network) = actual else {
        panic!("Network owner")
    };
    assert_eq!(network.input_index, 0);
    assert_eq!(
        network.result.as_ref().expect("successful callbacks"),
        &fixture.steps
    );
    assert!(network.result.batch_transfer_outcomes().is_empty());
    assert_eq!(network.completions.len(), 2);
    for (ordinal, (completion, id)) in network
        .completions
        .iter()
        .zip([&fixture.parent, &fixture.child])
        .enumerate()
    {
        assert_eq!(completion.callback_index, u32::try_from(ordinal).unwrap());
        assert_eq!(&completion.trigger_id, id);
        assert_eq!(completion.outcome, TriggerCompletedOutcome::Success);
    }
}

#[test]
fn nested_by_call_output_keeps_actual_preorder_steps_and_completions() {
    let fixture = nested_callback_fixture(65_536, 4);
    let (mut block, _recording) = recorded_component_block(&fixture.state, fixture.source.header());
    block
        .reserve_ordinary_execution_outputs(&fixture.source)
        .unwrap();
    let fragments = block.committed_fragment_count();
    block
        .produce_ordinary_execution_outputs(&fixture.source, |producer| {
            assert_eq!(
                producer.try_apply_network_success(0, execute_nested_input)?,
                NetworkSuccessDisposition::Applied
            );
            finish_empty_internal(producer)
        })
        .unwrap();
    assert_nested_output(&retained(&block).rows[0], &fixture);
    let completed: Vec<_> = block
        .world
        .external_event_buf
        .iter()
        .filter_map(|event| {
            if let EventBox::TriggerCompleted(completion) = event {
                Some(completion)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(completed.len(), 2);
    let call = fixture
        .source
        .network_entrypoint_at(0)
        .unwrap()
        .execution_call_hash();
    for (event, completion) in completed.iter().zip(retained(&block).rows[0].completions()) {
        assert_eq!(event.trigger_execution_hash(), &call);
        assert_eq!(event.trigger_id(), &completion.trigger_id);
        assert_eq!(*event.step_index(), completion.callback_index);
        assert_eq!(event.outcome(), &completion.outcome);
    }
    assert_eq!(block.committed_fragment_count(), fragments + 1);
    assert_eq!(
        block
            .world
            .account(&ALICE_ID)
            .unwrap()
            .metadata()
            .get(&fixture.key),
        Some(&Json::new(7_u64))
    );
    assert!(
        block
            .world
            .triggers
            .by_call_triggers()
            .get(&fixture.parent)
            .is_none()
    );
    assert!(
        block
            .world
            .triggers
            .by_call_triggers()
            .get(&fixture.child)
            .is_none()
    );
    drop(_recording);
    drop(block);
    let view = fixture.state.view();
    assert!(
        view.world
            .account(&ALICE_ID)
            .unwrap()
            .metadata()
            .get(&fixture.key)
            .is_none()
    );
    assert_eq!(
        view.world
            .triggers
            .by_call_triggers()
            .get(&fixture.parent)
            .unwrap()
            .repeats,
        Repeats::Exactly(1)
    );
    assert_eq!(
        view.world
            .triggers
            .by_call_triggers()
            .get(&fixture.child)
            .unwrap()
            .repeats,
        Repeats::Exactly(1)
    );
}

#[test]
fn nested_callback_full_row_exact_fit_and_one_byte_less_roll_back_atomically() {
    let mut measured = None::<ExecutionOutputV1>;
    for case in 0..3 {
        let bytes = measured
            .as_ref()
            .map(|output| u64::try_from(norito::canonical_frame_len(output).unwrap()).unwrap());
        let limit = match case {
            0 => 65_536,
            1 => bytes.unwrap(),
            _ => bytes.unwrap() - 1,
        };
        let fixture = nested_callback_fixture(limit, 4);
        let (mut block, _recording) =
            recorded_component_block(&fixture.state, fixture.source.header());
        block
            .reserve_ordinary_execution_outputs(&fixture.source)
            .unwrap();
        let fragments = block.committed_fragment_count();
        let events = block.world.external_event_buf.len();
        let before_witness = exec_witness::snapshot_exec_witness();
        block
            .produce_ordinary_execution_outputs(&fixture.source, |producer| {
                assert_eq!(
                    producer.try_apply_network_success(0, execute_nested_input)?,
                    if case < 2 {
                        NetworkSuccessDisposition::Applied
                    } else {
                        NetworkSuccessDisposition::OutputLimit
                    }
                );
                finish_empty_internal(producer)
            })
            .unwrap();
        let actual = &retained(&block).rows[0];
        if case < 2 {
            assert_nested_output(actual, &fixture);
            assert_eq!(block.committed_fragment_count(), fragments + 1);
            assert_eq!(
                block
                    .world
                    .account(&ALICE_ID)
                    .unwrap()
                    .metadata()
                    .get(&fixture.key),
                Some(&Json::new(7_u64))
            );
            assert!(block.world.external_event_buf.len() > events);
            for id in [&fixture.parent, &fixture.child] {
                assert!(block.world.triggers.by_call_triggers().get(id).is_none());
            }
            if let Some(expected) = &measured {
                assert_eq!(actual, expected);
            } else {
                measured = Some(actual.clone());
            }
        } else {
            assert_eq!(
                actual,
                &ExecutionOutputV1::network_output_limit_rejection(0)
            );
            assert!(actual.completions().is_empty());
            assert!(actual.result().batch_transfer_outcomes().is_empty());
            assert_eq!(block.committed_fragment_count(), fragments);
            assert_eq!(block.world.external_event_buf.len(), events);
            assert!(
                block
                    .world
                    .account(&ALICE_ID)
                    .unwrap()
                    .metadata()
                    .get(&fixture.key)
                    .is_none()
            );
            for id in [&fixture.parent, &fixture.child] {
                assert_eq!(
                    block
                        .world
                        .triggers
                        .by_call_triggers()
                        .get(id)
                        .unwrap()
                        .repeats,
                    Repeats::Exactly(1)
                );
            }
            assert_eq!(exec_witness::snapshot_exec_witness(), before_witness);
        }
        assert!(block.batch_transfer_outcomes.is_empty());
        assert!(block.fastpq_transcripts.is_empty());
        assert!(
            block
                .captured_fastpq_transcript_sources()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            retained(&block).row_bytes,
            u64::try_from(norito::canonical_frame_len(actual).unwrap()).unwrap()
        );
        drop(_recording);
        drop(block);
        assert!(
            fixture
                .state
                .view()
                .world
                .account(&ALICE_ID)
                .unwrap()
                .metadata()
                .get(&fixture.key)
                .is_none()
        );
    }
}

#[test]
fn early_nested_depth_failure_cannot_be_swallowed_or_drained_as_success() {
    let fixture = nested_callback_fixture(65_536, 1);
    let (mut block, _recording) = recorded_component_block(&fixture.state, fixture.source.header());
    block
        .reserve_ordinary_execution_outputs(&fixture.source)
        .unwrap();
    let fragments = block.committed_fragment_count();
    let events = block.world.external_event_buf.len();
    let before_witness = exec_witness::snapshot_exec_witness();
    assert!(
        block
            .produce_ordinary_execution_outputs(&fixture.source, |producer| {
                let error = producer
                    .try_apply_network_success(0, |input, transaction| {
                        let error = execute_nested_input(input, transaction)
                            .expect_err("child must fail before its body at depth one");
                        assert!(error.contains("MaxDepthExceeded"), "actual error: {error}");
                        assert_eq!(transaction.active_trigger_execution_depth, 0);
                        let call = Hash::from(input.execution_call_hash());
                        assert_eq!(transaction.tx_call_hash, Some(call));
                        assert!(
                            transaction.callback_journal.take(call).is_err(),
                            "early dispatch failure cannot transfer a successful trace"
                        );
                        // Even a caller that suppresses the actual rejection cannot make
                        // this failed journal publish an apparently successful empty row.
                        Ok(row(0, 0))
                    })
                    .expect_err("failed journal must refuse parent application");
                assert!(
                    matches!(error, ExecutionAttemptError::Rejected(reason) if !reason.is_empty())
                );
                Ok(())
            })
            .is_err()
    );
    assert!(matches!(
        block.execution_output_plan,
        Some(ExecutionOutputPlanState::Poisoned)
    ));
    assert_eq!(block.committed_fragment_count(), fragments);
    assert_eq!(block.world.external_event_buf.len(), events);
    assert!(
        block
            .world
            .account(&ALICE_ID)
            .unwrap()
            .metadata()
            .get(&fixture.key)
            .is_none()
    );
    for id in [&fixture.parent, &fixture.child] {
        assert_eq!(
            block
                .world
                .triggers
                .by_call_triggers()
                .get(id)
                .unwrap()
                .repeats,
            Repeats::Exactly(1)
        );
    }
    assert!(block.batch_transfer_outcomes.is_empty());
    assert!(block.fastpq_transcripts.is_empty());
    assert_eq!(exec_witness::snapshot_exec_witness(), before_witness);
    assert!(matches!(
        block.commit().unwrap_err(),
        TransactionsBlockError::ExecutionOutputCapacity
    ));
}

#[test]
fn successful_nested_callbacks_without_journal_transfer_cannot_apply() {
    for consensus_effects in [false, true] {
        let fixture = nested_callback_fixture(65_536, 4);
        let (mut block, _recording) =
            recorded_component_block(&fixture.state, fixture.source.header());
        block
            .reserve_ordinary_execution_outputs(&fixture.source)
            .unwrap();
        let fragments = block.committed_fragment_count();
        let events = block.world.external_event_buf.len();
        {
            let mut transaction = block.transaction();
            let input = fixture.source.network_entrypoint_at(0).unwrap();
            let TransactionEntrypoint::External(signed) = input else {
                unreachable!()
            };
            transaction.tx_call_hash = Some(Hash::from(input.execution_call_hash()));
            transaction.current_tx_hash = Some(signed.hash());
            transaction.current_entrypoint_index = Some(0);
            execute_nested_input(input, &mut transaction).expect("both actual callbacks succeed");
            assert_eq!(
                transaction
                    .world
                    .account(&ALICE_ID)
                    .unwrap()
                    .metadata()
                    .get(&fixture.key),
                Some(&Json::new(7_u64)),
                "effect is genuinely staged before the attempted apply"
            );
            for id in [&fixture.parent, &fixture.child] {
                assert!(
                    transaction
                        .world
                        .triggers
                        .by_call_triggers()
                        .get(id)
                        .is_none()
                );
            }
            // Deliberately bypass the producer's exact drain and full-row fit. The
            // StateTransaction guard must refuse before World/fragment publication.
            if consensus_effects {
                transaction.apply_consensus_effects();
            } else {
                transaction.apply();
            }
        }
        assert!(matches!(
            block.execution_output_plan,
            Some(ExecutionOutputPlanState::Poisoned)
        ));
        assert_eq!(block.committed_fragment_count(), fragments);
        assert_eq!(block.world.external_event_buf.len(), events);
        assert!(
            block
                .world
                .account(&ALICE_ID)
                .unwrap()
                .metadata()
                .get(&fixture.key)
                .is_none()
        );
        for id in [&fixture.parent, &fixture.child] {
            assert_eq!(
                block
                    .world
                    .triggers
                    .by_call_triggers()
                    .get(id)
                    .unwrap()
                    .repeats,
                Repeats::Exactly(1)
            );
        }
        assert!(block.batch_transfer_outcomes.is_empty());
        assert!(block.fastpq_transcripts.is_empty());
        assert!(matches!(
            block.commit().unwrap_err(),
            TransactionsBlockError::ExecutionOutputCapacity
        ));
        assert!(
            fixture
                .state
                .view()
                .world
                .account(&ALICE_ID)
                .unwrap()
                .metadata()
                .get(&fixture.key)
                .is_none()
        );
    }
}

#[test]
fn real_dfs_predispatch_failure_poison_preserves_no_earlier_callback_effects() {
    use iroha_data_model::{
        events::data::prelude::AccountEventFilter,
        parameter::SmartContractParameter,
        transaction::error::{TransactionRejectionReason, TriggerExecutionFail},
    };

    let mut fixture = nested_callback_fixture(65_536, 4);
    let cascade: TriggerId = "output_data_cascade".parse().unwrap();
    let initial_key: Name = "output_data_initial".parse().unwrap();
    let cascade_key: Name = "output_data_effect".parse().unwrap();
    let action = Action::new(
        [InstructionBox::from(SetKeyValue::account(
            ALICE_ID.clone(),
            cascade_key.clone(),
            Json::new(9_u64),
        ))],
        Repeats::Exactly(2),
        ALICE_ID.clone(),
        AccountEventFilter::new().for_account(ALICE_ID.clone()),
    )
    .expect("authority's own account is a valid data-trigger scope");
    let header = fixture.source.header();
    let mut source = TransactionBuilder::new(
        fixture.state.network_id,
        ALICE_ID.clone(),
        FeePaymentIntent::authority(vec![], None),
    );
    source.set_creation_time(
        header
            .creation_time()
            .checked_sub(std::time::Duration::from_millis(1))
            .unwrap(),
    );
    let signed = source
        .with_instructions([
            InstructionBox::from(ExecuteTrigger::new(fixture.parent.clone())),
            // Register only after the actual nested by-call work succeeds, so its
            // metadata event cannot start this new cascade inside the child body.
            InstructionBox::from(Register::trigger(Trigger::new(cascade.clone(), action))),
            InstructionBox::from(SetParameter::new(Parameter::SmartContract(
                SmartContractParameter::ExecutionDepth(1),
            ))),
            InstructionBox::from(SetKeyValue::account(
                ALICE_ID.clone(),
                initial_key.clone(),
                Json::new(8_u64),
            )),
        ])
        .sign(ALICE_KEYPAIR.private_key());
    let mut builder = BlockBuilder::new(header);
    builder.set_execution_context(Some(
        iroha_data_model::block::BlockExecutionContextBundle::new(vec![
            iroha_data_model::block::ExternalExecutionContext::new(
                signed.hash_as_entrypoint(),
                iroha_model_base::topology::LaneId::SINGLE,
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            ),
        ]),
    ));
    builder.push_transaction(signed);
    fixture.source = builder.build_with_signature(0, ALICE_KEYPAIR.private_key());
    let (mut block, _recording) = recorded_component_block(&fixture.state, fixture.source.header());
    block
        .reserve_ordinary_execution_outputs(&fixture.source)
        .unwrap();
    let fragments = block.committed_fragment_count();
    let events = block.world.external_event_buf.len();
    let before_witness = exec_witness::snapshot_exec_witness();
    assert!(
        block
            .produce_ordinary_execution_outputs(&fixture.source, |producer| {
                assert!(
                    producer
                        .try_apply_network_success(0, |input, transaction| {
                            execute_nested_input(input, transaction)?;
                            for id in [&fixture.parent, &fixture.child] {
                                assert!(
                                    transaction
                                        .world
                                        .triggers
                                        .by_call_triggers()
                                        .get(id)
                                        .is_none()
                                );
                            }
                            assert_eq!(
                                transaction
                                    .world
                                    .account(&ALICE_ID)
                                    .unwrap()
                                    .metadata()
                                    .get(&fixture.key),
                                Some(&Json::new(7_u64))
                            );
                            assert_eq!(transaction.data_trigger_firings_in_tx, 0);
                            let error = transaction
                                .execute_data_triggers_dfs(&ALICE_ID)
                                .expect_err("the real second cascade match must exceed depth one");
                            assert!(matches!(
                                error,
                                TransactionRejectionReason::TriggerExecution(
                                    TriggerExecutionFail::MaxDepthExceeded
                                )
                            ));
                            assert_eq!(
                                transaction.data_trigger_firings_in_tx, 1,
                                "depth two must be rejected before its callback body is dispatched"
                            );
                            assert_eq!(
                                transaction
                                    .world
                                    .account(&ALICE_ID)
                                    .unwrap()
                                    .metadata()
                                    .get(&cascade_key),
                                Some(&Json::new(9_u64)),
                                "the first actual data callback staged an effect"
                            );
                            assert_eq!(
                                transaction
                                    .world
                                    .triggers
                                    .data_triggers()
                                    .get(&cascade)
                                    .unwrap()
                                    .repeats,
                                Repeats::Exactly(1)
                            );
                            assert_eq!(transaction.active_trigger_execution_depth, 0);
                            assert!(
                                transaction
                                    .callback_journal
                                    .take(Hash::from(input.execution_call_hash()))
                                    .is_err(),
                                "DFS rejection cannot transfer earlier successful roots"
                            );
                            // Deliberately catch the real traversal error; it must still poison
                            // the sole producer before applying any earlier successful effect.
                            Ok(row(0, 0))
                        })
                        .is_err()
                );
                Ok(())
            })
            .is_err()
    );
    assert!(matches!(
        block.execution_output_plan,
        Some(ExecutionOutputPlanState::Poisoned)
    ));
    assert_eq!(block.committed_fragment_count(), fragments);
    assert_eq!(block.world.external_event_buf.len(), events);
    assert_eq!(block.world.parameters.smart_contract().execution_depth(), 4);
    for key in [&fixture.key, &initial_key, &cascade_key] {
        assert!(
            block
                .world
                .account(&ALICE_ID)
                .unwrap()
                .metadata()
                .get(key)
                .is_none()
        );
    }
    for id in [&fixture.parent, &fixture.child] {
        assert_eq!(
            block
                .world
                .triggers
                .by_call_triggers()
                .get(id)
                .unwrap()
                .repeats,
            Repeats::Exactly(1)
        );
    }
    assert!(block.world.triggers.data_triggers().get(&cascade).is_none());
    assert!(block.batch_transfer_outcomes.is_empty());
    assert!(block.fastpq_transcripts.is_empty());
    assert_eq!(exec_witness::snapshot_exec_witness(), before_witness);
    assert!(matches!(
        block.commit().unwrap_err(),
        TransactionsBlockError::ExecutionOutputCapacity
    ));
}
