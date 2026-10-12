//! Actual scheduled invocation ownership, full-row fit and rollback controls.
//! Fragment censuses retain actual invocation applies; an empty reward-maintenance
//! journal adds no fragment when the Time phase starts.

use super::*;
use crate::exec_witness;
use crate::state::WorldReadOnly;
use iroha_data_model::{
    account::Account,
    block::execution_output::TimeExecutionOutputV1,
    events::{
        EventBox,
        execute_trigger::ExecuteTriggerEventFilter,
        time::{ExecutionTime, TimeEventFilter},
        trigger_completed::TriggerCompletedOutcome,
    },
    isi::{ExecuteTrigger, Register, SetKeyValue, Unregister},
    transaction::Executable,
    trigger::{
        Trigger, TriggerId,
        action::{Action, Repeats},
    },
};

/// Acquire State first and bind the original recorder before component effects.
/// These synthetic output callbacks do not acquire production Network authority.
pub(super) fn recorded_component_block(
    state: &State,
    header: BlockHeader,
) -> (Box<StateBlock<'_>>, crate::exec_witness::ExecWitnessGuard) {
    let (block, recording) = state
        .block_with_owned_start_stages(
            header,
            |block| {
                let recording = crate::exec_witness::begin_exec_witness_capture()?;
                block.bind_original_execution_recorder()?;
                Ok::<_, String>(recording)
            },
            |_, recording| Ok(recording),
        )
        .expect("original recorder before component output effects");
    (block, recording)
}

fn fixture(
    row_bytes: u64,
    maximum: u32,
    registrations: Vec<Trigger>,
    network: Vec<InstructionBox>,
) -> (State, SignedBlock) {
    let state = authenticated_state(row_bytes);
    {
        let mut parameters = state.world.parameters.block();
        let mut policy = parameters.get().block().execution_output();
        policy.max_time_invocations = maximum;
        parameters
            .get_mut()
            .set_parameter(Parameter::Block(BlockParameter::ExecutionOutput(policy)))
            .expect("valid fixture parameters");
        parameters
            .get_mut()
            .set_parameter(Parameter::Block(BlockParameter::MaxTimeTriggerInvocations(
                NonZeroU32::new(maximum).unwrap(),
            )))
            .expect("valid fixture parameters");
        parameters.commit();
    }
    {
        let (mut setup, _setup_recording) = output_fixture_setup(&state);
        let mut transaction = setup.transaction_for_callback_testing();
        Register::account(Account::new(ALICE_ID.clone()))
            .execute(&ALICE_ID, &mut transaction)
            .unwrap();
        for trigger in registrations {
            Register::trigger(trigger)
                .execute(&ALICE_ID, &mut transaction)
                .unwrap();
        }
        transaction.apply();
        setup.commit_world_overlay_for_testing().unwrap();
    }
    let header = output_fixture_header(&state);
    let mut builder = TransactionBuilder::new(
        state.network_id,
        ALICE_ID.clone(),
        FeePaymentIntent::authority(vec![], None),
    );
    builder.set_creation_time(header.creation_time() - std::time::Duration::from_millis(1));
    let signed = builder
        .with_instructions(network)
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
    (
        state,
        builder.build_with_signature(0, ALICE_KEYPAIR.private_key()),
    )
}

fn time_trigger(id: &str, instructions: Vec<InstructionBox>, repeats: u32) -> Trigger {
    Trigger::new(
        id.parse().unwrap(),
        Action::new(
            instructions,
            Repeats::Exactly(repeats),
            ALICE_ID.clone(),
            TimeEventFilter::new(ExecutionTime::PreCommit),
        )
        .unwrap(),
    )
}

fn plain_network() -> Vec<InstructionBox> {
    vec![Log::new(Level::DEBUG, "actual Network source".to_owned()).into()]
}

fn execute_network(
    producer: &mut ExecutionOutputProducer<'_, '_, '_>,
) -> Result<(), ExecutionAttemptError<String>> {
    assert_eq!(
        producer.try_apply_network_success(0, |input, transaction| {
            let TransactionEntrypoint::External(signed) = input else {
                unreachable!()
            };
            let Executable::Instructions(instructions) = signed.instructions() else {
                unreachable!()
            };
            for instruction in instructions.iter() {
                instruction
                    .clone()
                    .execute(signed.authority(), transaction)
                    .map_err(|error| error.to_string())?;
            }
            Ok(row(0, 0))
        })?,
        NetworkSuccessDisposition::Applied
    );
    Ok(())
}

fn nested_fixture(row_bytes: u64) -> (State, SignedBlock) {
    let child: TriggerId = "time_child".parse().unwrap();
    let child_action = Action::new(
        vec![
            InstructionBox::from(SetKeyValue::account(
                ALICE_ID.clone(),
                "time_effect".parse().unwrap(),
                Json::new(11_u64),
            )),
            Log::new(Level::DEBUG, "x".repeat(16_384)).into(),
        ],
        Repeats::Exactly(1),
        ALICE_ID.clone(),
        ExecuteTriggerEventFilter::new()
            .for_trigger(child.clone())
            .under_authority(ALICE_ID.clone()),
    )
    .unwrap();
    fixture(
        row_bytes,
        1,
        vec![
            Trigger::new(child.clone(), child_action),
            time_trigger("time_root", vec![ExecuteTrigger::new(child).into()], 1),
        ],
        plain_network(),
    )
}

fn time_row<'a>(block: &'a StateBlock<'_>) -> &'a TimeExecutionOutputV1 {
    let ExecutionOutputV1::Time(row) = &retained(block).rows[1] else {
        panic!("one actual Time output follows Network")
    };
    row
}

#[test]
fn scheduled_time_owns_actual_root_nested_trace_and_completion_call() {
    let (state, source) = nested_fixture(65_536);
    let (mut block, _recording) = recorded_component_block(&state, source.header());
    block.reserve_ordinary_execution_outputs(&source).unwrap();
    let use_before =
        crate::smartcontracts::isi::triggers::set::invocation_identity::time_trigger_use_v1(
            &block.world.triggers,
            &"time_root".parse().unwrap(),
            2,
        )
        .unwrap();
    let fragments = block.committed_fragment_count();
    block
        .produce_ordinary_execution_outputs(&source, |producer| {
            execute_network(producer)?;
            producer.execute_scheduled_time_outputs()
        })
        .unwrap();
    let time = time_row(&block);
    assert_eq!(time.invocation.trigger, use_before);
    assert_eq!(time.invocation.schedule_index, 0);
    assert_eq!(
        time.result
            .as_ref()
            .unwrap()
            .iter()
            .map(|step| step.id.to_string())
            .collect::<Vec<_>>(),
        ["time_root", "time_child"]
    );
    assert_eq!(
        time.completions
            .iter()
            .map(|c| c.callback_index)
            .collect::<Vec<_>>(),
        [0, 1]
    );
    assert!(
        time.completions
            .iter()
            .all(|c| c.outcome == TriggerCompletedOutcome::Success)
    );
    let call =
        HashOf::from_untyped_unchecked(time.invocation.execution_call_hash(source.hash()).unwrap());
    let events = block
        .world
        .external_event_buf
        .iter()
        .filter_map(|event| match event {
            EventBox::TriggerCompleted(e) => Some(e),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 2);
    for (event, completion) in events.iter().zip(&time.completions) {
        assert_eq!(event.trigger_execution_hash(), &call);
        assert_eq!(*event.step_index(), completion.callback_index);
        assert_eq!(event.trigger_id(), &completion.trigger_id);
    }
    assert_eq!(
        block
            .world
            .account(&ALICE_ID)
            .unwrap()
            .metadata()
            .get("time_effect"),
        Some(&Json::new(11_u64))
    );
    assert!(block.world.triggers.time_triggers().is_empty());
    assert!(block.world.triggers.by_call_triggers().is_empty());
    assert_eq!(block.committed_fragment_count(), fragments + 2);
    assert!(block.gas_used_in_block > 0);
    assert!(matches!(
        block.commit().unwrap_err(),
        TransactionsBlockError::ExecutionOutputCapacity
    ));
}

#[test]
fn exact_time_row_applies_and_one_byte_less_preserves_repeats_but_charges_work() {
    let mut measured = None;
    let mut measured_gas = None;
    for case in 0..3 {
        let limit = match case {
            0 => 65_536,
            1 => measured.unwrap(),
            _ => measured.unwrap() - 1,
        };
        let (state, source) = nested_fixture(limit);
        let (mut block, _recording) = recorded_component_block(&state, source.header());
        block.reserve_ordinary_execution_outputs(&source).unwrap();
        let fragments = block.committed_fragment_count();
        block
            .produce_ordinary_execution_outputs(&source, |producer| {
                execute_network(producer)?;
                producer.execute_scheduled_time_outputs()
            })
            .unwrap();
        let output = &retained(&block).rows[1];
        if case < 2 {
            let bytes = u64::try_from(norito::canonical_frame_len(output).unwrap()).unwrap();
            assert!(output.result().is_ok());
            if let Some(previous) = measured {
                assert_eq!(bytes, previous);
            } else {
                measured = Some(bytes);
            }
            assert!(block.world.triggers.time_triggers().is_empty());
            assert!(block.world.triggers.by_call_triggers().is_empty());
            assert_eq!(block.committed_fragment_count(), fragments + 2);
        } else {
            assert!(output.is_output_limit_rejection());
            assert_eq!(output.completions().len(), 1);
            assert_eq!(output.completions()[0].callback_index, 0);
            assert!(output.result().batch_transfer_outcomes().is_empty());
            assert_eq!(
                block
                    .world
                    .triggers
                    .time_triggers()
                    .get(&"time_root".parse().unwrap())
                    .unwrap()
                    .repeats,
                Repeats::Exactly(1)
            );
            assert_eq!(
                block
                    .world
                    .triggers
                    .by_call_triggers()
                    .get(&"time_child".parse().unwrap())
                    .unwrap()
                    .repeats,
                Repeats::Exactly(1)
            );
            assert!(
                block
                    .world
                    .account(&ALICE_ID)
                    .unwrap()
                    .metadata()
                    .get("time_effect")
                    .is_none()
            );
            assert_eq!(block.committed_fragment_count(), fragments + 1);
            assert!(exec_witness::snapshot_exec_witness().writes.is_empty());
            assert_eq!(
                block
                    .world
                    .external_event_buf
                    .iter()
                    .filter(|e| matches!(e, EventBox::TriggerCompleted(_)))
                    .count(),
                1
            );
        }
        assert!(block.gas_used_in_block > 0);
        if let Some(gas) = measured_gas {
            assert_eq!(block.gas_used_in_block, gas);
        } else {
            measured_gas = Some(block.gas_used_in_block);
        }
        assert!(block.batch_transfer_outcomes.is_empty());
        assert!(block.fastpq_transcripts.is_empty());
    }
}

#[test]
fn time_matching_uses_frozen_count_and_revalidates_later_removed_action() {
    let later: TriggerId = "b_later".parse().unwrap();
    let registrations = vec![
        time_trigger(
            "a_first",
            vec![Unregister::trigger(later.clone()).into()],
            1,
        ),
        time_trigger(
            "b_later",
            vec![Log::new(Level::INFO, "must be skipped".into()).into()],
            1,
        ),
        time_trigger(
            "c_last",
            vec![Log::new(Level::INFO, "must run with frozen T=3".into()).into()],
            1,
        ),
    ];
    let network = vec![
        SetParameter::new(Parameter::Block(BlockParameter::MaxTimeTriggerInvocations(
            NonZeroU32::MIN,
        )))
        .into(),
    ];
    let (state, source) = fixture(65_536, 3, registrations, network);
    let (mut block, _recording) = recorded_component_block(&state, source.header());
    block.reserve_ordinary_execution_outputs(&source).unwrap();
    block
        .produce_ordinary_execution_outputs(&source, |producer| {
            execute_network(producer)?;
            assert_eq!(
                producer
                    .state
                    .world
                    .parameters
                    .get()
                    .block()
                    .max_time_trigger_invocations()
                    .get(),
                1
            );
            producer.execute_scheduled_time_outputs()
        })
        .unwrap();
    let times = retained(&block)
        .rows
        .iter()
        .filter_map(|output| match output {
            ExecutionOutputV1::Time(row) => Some(row),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(times.len(), 2);
    assert_eq!(
        times
            .iter()
            .map(|row| row.invocation.schedule_index)
            .collect::<Vec<_>>(),
        [0, 2]
    );
    assert_eq!(
        times[0].invocation.trigger.trigger_id.to_string(),
        "a_first"
    );
    assert_eq!(times[1].invocation.trigger.trigger_id.to_string(), "c_last");
    assert!(block.world.triggers.time_triggers().is_empty());
}

#[test]
fn real_time_failure_retains_rejection_without_retry_or_business_effects() {
    let bad: TriggerId = "missing_trigger".parse().unwrap();
    let (state, source) = fixture(
        65_536,
        1,
        vec![time_trigger(
            "bad_time",
            vec![
                SetKeyValue::account(
                    ALICE_ID.clone(),
                    "rolled_back".parse().unwrap(),
                    Json::new(true),
                )
                .into(),
                Unregister::trigger(bad).into(),
            ],
            1,
        )],
        plain_network(),
    );
    let (mut block, _recording) = recorded_component_block(&state, source.header());
    block.reserve_ordinary_execution_outputs(&source).unwrap();
    block
        .produce_ordinary_execution_outputs(&source, |producer| {
            execute_network(producer)?;
            producer.execute_scheduled_time_outputs()
        })
        .unwrap();
    let output = time_row(&block);
    assert_eq!(output.invocation.trigger.trigger_id.to_string(), "bad_time");
    let reason = output.result.as_ref().unwrap_err();
    assert!(!matches!(
        reason,
        iroha_data_model::transaction::error::TransactionRejectionReason::LimitCheck(_)
    ));
    assert!(matches!(output.failure_root, Some(
        iroha_data_model::block::execution_output::TriggerFailureRootV1::DeclaredInstructionProjection(_))));
    assert_eq!(output.completions.len(), 1);
    assert!(output.result.batch_transfer_outcomes().is_empty());
    assert!(
        block
            .world
            .account(&ALICE_ID)
            .unwrap()
            .metadata()
            .get("rolled_back")
            .is_none()
    );
    assert_eq!(
        block
            .world
            .triggers
            .time_triggers()
            .get(&"bad_time".parse().unwrap())
            .unwrap()
            .repeats,
        Repeats::Exactly(1)
    );
    assert!(matches!(
        block.commit().unwrap_err(),
        TransactionsBlockError::ExecutionOutputCapacity
    ));
}

#[test]
fn time_phase_cannot_bypass_network_or_run_twice() {
    for early in [true, false] {
        let (state, source) = nested_fixture(65_536);
        let (mut block, _recording) = recorded_component_block(&state, source.header());
        block.reserve_ordinary_execution_outputs(&source).unwrap();
        assert!(
            block
                .produce_ordinary_execution_outputs(&source, |producer| {
                    if !early {
                        execute_network(producer)?;
                        producer.execute_scheduled_time_outputs()?;
                    }
                    assert!(producer.execute_scheduled_time_outputs().is_err());
                    Ok(())
                })
                .is_err()
        );
        assert!(matches!(
            block.commit().unwrap_err(),
            TransactionsBlockError::ExecutionOutputCapacity
        ));
    }
}

// Additional actual-producer controls. Retry state below is explicit stored
// pre-State setup, not a claim that the unfinished failure policy executed.
mod retry_and_periodic {
    use super::*;
    use crate::{
        kura::tests::CommittedNetworkProofFixture,
        smartcontracts::isi::triggers::{
            set::invocation_identity::time_trigger_use_v1, specialized::TimeTriggerRetryState,
        },
    };
    use iroha_data_model::{events::time::Schedule, trigger::action::TimeTriggerRetryPolicy};
    use iroha_model_base::metadata::Metadata;
    use std::{collections::BTreeSet, sync::Arc, time::Duration};

    fn scheduled_action(instructions: Vec<InstructionBox>, repeats: u32, start_ms: u64) -> Action {
        Action::new(
            instructions,
            Repeats::Exactly(repeats),
            ALICE_ID.clone(),
            TimeEventFilter::new(ExecutionTime::Schedule(
                Schedule::starting_at(Duration::from_millis(start_ms))
                    .with_period(Duration::from_millis(60_000)),
            )),
        )
        .unwrap()
        .with_retry_policy(TimeTriggerRetryPolicy {
            max_retries: NonZeroU32::new(3).unwrap(),
            retry_after_ms: NonZeroU64::new(5).unwrap(),
        })
        .unwrap()
    }

    fn install_pending_retry(state: &State, id: &TriggerId, retry: TimeTriggerRetryState) {
        let mut triggers = state.world.triggers.block();
        let mut transaction = triggers.transaction();
        assert!(transaction.set_time_trigger_retry_state(id, Some(retry)));
        transaction.apply();
        triggers.commit();
        assert_eq!(
            state
                .world
                .triggers
                .view()
                .time_triggers()
                .get(id)
                .unwrap()
                .retry_state,
            Some(retry)
        );
    }

    #[test]
    fn real_retry_failure_advances_or_removes_action_even_when_diagnostic_is_omitted() {
        for prior in [1, 3] {
            let id: TriggerId = "actual_retry_failure".parse().unwrap();
            let original = TimeTriggerRetryState {
                retries_used: prior,
                next_retry_at_ms: 2,
            };
            let (state, source) = fixture(
                4096,
                4,
                vec![Trigger::new(
                    id.clone(),
                    scheduled_action(
                        vec![
                            SetKeyValue::account(
                                ALICE_ID.clone(),
                                "retry_rollback".parse().unwrap(),
                                Json::new(true),
                            )
                            .into(),
                            Unregister::trigger("absent".parse().unwrap()).into(),
                            Log::new(Level::DEBUG, "x".repeat(16_384)).into(),
                        ],
                        5,
                        60_000,
                    ),
                )],
                plain_network(),
            );
            install_pending_retry(&state, &id, original);
            let (mut block, _recording) = recorded_component_block(&state, source.header());
            block.reserve_ordinary_execution_outputs(&source).unwrap();
            block
                .produce_ordinary_execution_outputs(&source, |producer| {
                    execute_network(producer)?;
                    producer.execute_scheduled_time_outputs()
                })
                .unwrap();
            assert_eq!(retained(&block).rows.len(), 2);
            let row = &retained(&block).rows[1];
            assert!(row.is_internal_rejection_diagnostic_omitted());
            assert!(!row.is_output_limit_rejection());
            assert!(
                block
                    .world
                    .account(&ALICE_ID)
                    .unwrap()
                    .metadata()
                    .get("retry_rollback")
                    .is_none()
            );
            let action = block.world.triggers.time_triggers().get(&id);
            if prior == 3 {
                assert!(action.is_none());
            } else {
                let action = action.unwrap();
                assert_eq!(action.repeats, Repeats::Exactly(5));
                assert_eq!(
                    action.retry_state,
                    Some(TimeTriggerRetryState {
                        retries_used: 2,
                        next_retry_at_ms: u64::try_from(
                            source.header().creation_time().as_millis()
                        )
                        .unwrap()
                            + 5,
                    })
                );
            }
            drop(_recording);
            drop(block);
            assert_eq!(
                state
                    .world
                    .triggers
                    .view()
                    .time_triggers()
                    .get(&id)
                    .unwrap()
                    .retry_state,
                Some(original)
            );
        }
    }

    #[test]
    fn due_retry_is_one_actual_attempt_before_ordinary_matches() {
        let id: TriggerId = "z_due_retry".parse().unwrap();
        let retry = TimeTriggerRetryState {
            retries_used: 1,
            next_retry_at_ms: 2,
        };
        let (state, source) = fixture(
            65_536,
            3,
            vec![
                time_trigger(
                    "a_ordinary",
                    vec![Log::new(Level::INFO, "ordinary".into()).into()],
                    1,
                ),
                Trigger::new(
                    id.clone(),
                    scheduled_action(
                        vec![
                            SetKeyValue::account(
                                ALICE_ID.clone(),
                                "retry_ran".parse().unwrap(),
                                Json::new(true),
                            )
                            .into(),
                        ],
                        4,
                        1_000,
                    ),
                ),
            ],
            plain_network(),
        );
        install_pending_retry(&state, &id, retry);
        let parent_time = output_fixture_parent_time(&state);
        let source_time = u64::try_from(source.header().creation_time().as_millis()).unwrap();
        assert_eq!(source_time.checked_sub(parent_time), Some(2));
        assert!(
            source_time < 1_000,
            "the scheduled action is still in the future"
        );
        let (mut block, _recording) = recorded_component_block(&state, source.header());
        block.reserve_ordinary_execution_outputs(&source).unwrap();
        let expected_use = time_trigger_use_v1(&block.world.triggers, &id, 2).unwrap();
        let fragments = block.committed_fragment_count();
        block
            .produce_ordinary_execution_outputs(&source, |producer| {
                execute_network(producer)?;
                producer.execute_scheduled_time_outputs()
            })
            .unwrap();
        let outputs = &retained(&block).rows;
        assert_eq!(
            outputs.len(),
            3,
            "one Network, one retry, one ordinary invocation"
        );
        let ExecutionOutputV1::Time(first) = &outputs[1] else {
            panic!("retry row")
        };
        let ExecutionOutputV1::Time(second) = &outputs[2] else {
            panic!("ordinary row")
        };
        assert_eq!(first.invocation.trigger, expected_use);
        assert_eq!(first.invocation.schedule_index, 0);
        assert_eq!(
            second.invocation.trigger.trigger_id.to_string(),
            "a_ordinary"
        );
        assert_eq!(second.invocation.schedule_index, 1);
        // The real signed genesis is the retained parent. This exact two-ms
        // interval precedes the future action, which runs only because its retry is due.
        assert_eq!(first.invocation.event.interval.since_ms, parent_time);
        assert_eq!(
            first.invocation.event.interval.length_ms,
            source_time - parent_time
        );
        assert!(first.result.is_ok());
        assert_eq!(first.result.as_ref().unwrap().len(), 1);
        assert_eq!(first.completions.len(), 1);
        assert_eq!(first.completions[0].callback_index, 0);
        assert_eq!(
            first.completions[0].outcome,
            TriggerCompletedOutcome::Success
        );
        let action = block.world.triggers.time_triggers().get(&id).unwrap();
        assert_eq!(action.repeats, Repeats::Exactly(3));
        assert_eq!(action.retry_state, None);
        assert_eq!(
            block
                .world
                .account(&ALICE_ID)
                .unwrap()
                .metadata()
                .get("retry_ran"),
            Some(&Json::new(true))
        );
        assert_eq!(block.committed_fragment_count(), fragments + 3);
        assert!(block.batch_transfer_outcomes.is_empty());
        drop(_recording);
        drop(block);
        assert_eq!(
            state
                .world
                .triggers
                .view()
                .time_triggers()
                .get(&id)
                .unwrap()
                .retry_state,
            Some(retry)
        );
    }

    #[test]
    fn due_retry_output_limit_retains_retry_repeat_and_only_root_failure() {
        let id: TriggerId = "bounded_due_retry".parse().unwrap();
        let retry = TimeTriggerRetryState {
            retries_used: 2,
            next_retry_at_ms: 2,
        };
        let mut exact_bytes = None;
        let mut completed_gas = None;
        for case in 0..3 {
            let row_limit = match case {
                0 => 65_536,
                1 => exact_bytes.unwrap(),
                _ => exact_bytes.unwrap() - 1,
            };
            let (state, source) = fixture(
                row_limit,
                1,
                vec![Trigger::new(
                    id.clone(),
                    scheduled_action(
                        vec![
                            SetKeyValue::account(
                                ALICE_ID.clone(),
                                "retry_effect".parse().unwrap(),
                                Json::new(9_u64),
                            )
                            .into(),
                            Log::new(Level::INFO, "r".repeat(16_384)).into(),
                        ],
                        3,
                        1_000,
                    ),
                )],
                plain_network(),
            );
            install_pending_retry(&state, &id, retry);
            let (mut block, _recording) = recorded_component_block(&state, source.header());
            block.reserve_ordinary_execution_outputs(&source).unwrap();
            let expected_use = time_trigger_use_v1(&block.world.triggers, &id, 2).unwrap();
            let fragments = block.committed_fragment_count();
            block
                .produce_ordinary_execution_outputs(&source, |producer| {
                    execute_network(producer)?;
                    producer.execute_scheduled_time_outputs()
                })
                .unwrap();
            assert_eq!(retained(&block).rows.len(), 2);
            let output = &retained(&block).rows[1];
            let ExecutionOutputV1::Time(actual) = output else {
                panic!("retry Time row")
            };
            assert_eq!(actual.invocation.trigger, expected_use);
            let action = block.world.triggers.time_triggers().get(&id).unwrap();
            if case < 2 {
                let bytes = u64::try_from(norito::canonical_frame_len(output).unwrap()).unwrap();
                if let Some(previous) = exact_bytes {
                    assert_eq!(bytes, previous);
                } else {
                    exact_bytes = Some(bytes);
                }
                assert!(actual.result.is_ok());
                assert_eq!(action.retry_state, None);
                assert_eq!(action.repeats, Repeats::Exactly(2));
                assert_eq!(
                    block
                        .world
                        .account(&ALICE_ID)
                        .unwrap()
                        .metadata()
                        .get("retry_effect"),
                    Some(&Json::new(9_u64))
                );
                assert_eq!(block.committed_fragment_count(), fragments + 2);
            } else {
                assert!(output.is_output_limit_rejection());
                assert_eq!(action.retry_state, Some(retry));
                assert_eq!(action.repeats, Repeats::Exactly(3));
                assert!(
                    block
                        .world
                        .account(&ALICE_ID)
                        .unwrap()
                        .metadata()
                        .get("retry_effect")
                        .is_none()
                );
                assert_eq!(block.committed_fragment_count(), fragments + 1);
                assert_eq!(actual.completions.len(), 1);
                assert_eq!(actual.completions[0].callback_index, 0);
                assert_eq!(actual.completions[0].trigger_id, id);
                assert!(matches!(
                    actual.completions[0].outcome,
                    TriggerCompletedOutcome::Failure(_)
                ));
                assert!(exec_witness::snapshot_exec_witness().writes.is_empty());
            }
            let call = HashOf::from_untyped_unchecked(
                actual
                    .invocation
                    .execution_call_hash(source.hash())
                    .unwrap(),
            );
            let events = block
                .world
                .external_event_buf
                .iter()
                .filter_map(|event| match event {
                    EventBox::TriggerCompleted(event) => Some(event),
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].trigger_execution_hash(), &call);
            assert_eq!(*events[0].step_index(), 0);
            assert_eq!(events[0].outcome(), &actual.completions[0].outcome);
            assert!(actual.result.batch_transfer_outcomes().is_empty());
            assert!(block.batch_transfer_outcomes.is_empty());
            assert!(block.fastpq_transcripts.is_empty());
            assert!(block.gas_used_in_block > 0);
            if let Some(gas) = completed_gas {
                assert_eq!(block.gas_used_in_block, gas);
            } else {
                completed_gas = Some(block.gas_used_in_block);
            }
            drop(_recording);
            drop(block);
            let view = state.world.triggers.view();
            let original = view.time_triggers().get(&id).unwrap();
            assert_eq!(original.retry_state, Some(retry));
            assert_eq!(original.repeats, Repeats::Exactly(3));
        }
    }

    // Reuse the original executed State and its exact-wire custody as the prior
    // source for create_time_event. Fixture registrations publish World only;
    // they neither recertify history nor claim a new finalized economic result.
    fn periodic_fixture() -> (Arc<State>, SignedBlock, CommittedNetworkProofFixture) {
        let history = CommittedNetworkProofFixture::ordinary();
        let prior_wire = history.target_disk_bytes();
        let state = Arc::clone(&history.state);
        assert!(Arc::ptr_eq(&state, &history.state));
        {
            let mut parameters = state.world.parameters.block();
            let mut policy = ExecutionOutputPolicyV1::bootstrap();
            policy.max_output_bytes = 65_536;
            policy.max_pipeline_triggers = 0;
            policy.max_time_invocations = 3;
            policy.validate().unwrap();
            parameters
                .get_mut()
                .set_parameter(Parameter::Block(BlockParameter::ExecutionOutput(policy)))
                .expect("valid fixture parameters");
            parameters
                .get_mut()
                .set_parameter(Parameter::Block(BlockParameter::MaxTimeTriggerInvocations(
                    NonZeroU32::new(3).unwrap(),
                )))
                .expect("valid fixture parameters");
            parameters.commit();
        }
        {
            let (mut setup, _setup_recording) = output_fixture_setup(&state);
            let mut transaction = setup.transaction_for_callback_testing();
            Register::account(Account::new(ALICE_ID.clone()))
                .execute(&ALICE_ID, &mut transaction)
                .unwrap();
            Register::trigger(Trigger::new(
                "periodic_repeat".parse().unwrap(),
                scheduled_action(
                    vec![Log::new(Level::INFO, "identical periodic body".into()).into()],
                    3,
                    0,
                ),
            ))
            .execute(&ALICE_ID, &mut transaction)
            .unwrap();
            transaction.apply();
            setup.commit_world_overlay_for_testing().unwrap();
        }
        assert_eq!(history.target_disk_bytes(), prior_wire);
        let previous = history.target();
        let timestamp =
            u64::try_from(previous.header().creation_time().as_millis()).unwrap() + 180_000;
        let header = BlockHeader::new(
            NonZeroU64::new(3).unwrap(),
            Some(previous.hash()),
            None,
            timestamp,
            0,
        );
        let mut transaction = TransactionBuilder::new(
            state.network_id,
            ALICE_ID.clone(),
            FeePaymentIntent::authority(vec![], None),
        );
        transaction.set_creation_time(header.creation_time() - std::time::Duration::from_millis(1));
        let signed = transaction
            .with_instructions(plain_network())
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
        (state, source, history)
    }

    #[test]
    fn repeated_periodic_matches_bind_distinct_positions_and_use_time_actions() {
        let (state, source, history) = periodic_fixture();
        let id: TriggerId = "periodic_repeat".parse().unwrap();
        let (mut block, _recording) = recorded_component_block(&state, source.header());
        let initial_use = time_trigger_use_v1(&block.world.triggers, &id, 3).unwrap();
        block.reserve_ordinary_execution_outputs(&source).unwrap();
        let fragments = block.committed_fragment_count();
        block
            .produce_ordinary_execution_outputs(&source, |producer| {
                execute_network(producer)?;
                producer.execute_scheduled_time_outputs()
            })
            .unwrap();
        let outputs = &retained(&block).rows;
        assert_eq!(outputs.len(), 4);
        let mut calls = BTreeSet::new();
        let mut action_hashes = BTreeSet::new();
        let events = block
            .world
            .external_event_buf
            .iter()
            .filter_map(|event| match event {
                EventBox::TriggerCompleted(event) => Some(event),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 3);
        let mut first_result = None;
        for (index, output) in outputs[1..].iter().enumerate() {
            let ExecutionOutputV1::Time(row) = output else {
                panic!("actual repeated Time output")
            };
            assert_eq!(row.invocation.schedule_index, u32::try_from(index).unwrap());
            assert_eq!(row.invocation.trigger.trigger_id, id);
            assert_eq!(row.invocation.trigger.registered_at_height, 2);
            if index == 0 {
                assert_eq!(row.invocation.trigger, initial_use);
            }
            assert!(
                action_hashes.insert(row.invocation.trigger.action_hash),
                "repeat debit must affect the freshly bound action"
            );
            assert_eq!(
                row.invocation.event.interval.since_ms,
                u64::try_from(history.target().header().creation_time().as_millis()).unwrap()
            );
            assert_eq!(row.invocation.event.interval.length_ms, 180_000);
            let call = row.invocation.execution_call_hash(source.hash()).unwrap();
            assert!(
                calls.insert(call),
                "equal display/root work still has a distinct actual invocation"
            );
            assert_eq!(row.completions.len(), 1);
            assert_eq!(row.completions[0].callback_index, 0);
            assert_eq!(row.completions[0].outcome, TriggerCompletedOutcome::Success);
            assert!(row.result.is_ok());
            if let Some(first) = first_result {
                assert_eq!(&row.result, first);
            } else {
                first_result = Some(&row.result);
            }
            assert_eq!(
                events[index].trigger_execution_hash(),
                &HashOf::from_untyped_unchecked(call)
            );
            assert_eq!(*events[index].step_index(), 0);
        }
        assert!(block.world.triggers.time_triggers().get(&id).is_none());
        assert_eq!(block.committed_fragment_count(), fragments + 4);
        assert!(block.batch_transfer_outcomes.is_empty());
        assert!(block.fastpq_transcripts.is_empty());
        drop(_recording);
        drop(block);
        assert_eq!(
            state
                .world
                .triggers
                .view()
                .time_triggers()
                .get(&id)
                .unwrap()
                .repeats,
            Repeats::Exactly(3)
        );
    }

    #[test]
    fn retry_callback_self_replacement_keeps_fresh_repeat_policy_and_incarnation() {
        let id: TriggerId = "retry_self_replace".parse().unwrap();
        let retry = TimeTriggerRetryState {
            retries_used: 1,
            next_retry_at_ms: 2,
        };
        let replacement_policy = TimeTriggerRetryPolicy {
            max_retries: NonZeroU32::new(4).unwrap(),
            retry_after_ms: NonZeroU64::new(19).unwrap(),
        };
        let mut metadata = Metadata::default();
        metadata.insert("fresh_generation".parse().unwrap(), Json::new(true));
        let replacement = Trigger::new(
            id.clone(),
            Action::new(
                vec![InstructionBox::from(SetKeyValue::account(
                    ALICE_ID.clone(),
                    "replacement_ran".parse().unwrap(),
                    Json::new(true),
                ))],
                Repeats::Exactly(7),
                ALICE_ID.clone(),
                TimeEventFilter::new(ExecutionTime::Schedule(
                    Schedule::starting_at(Duration::from_millis(1_000))
                        .with_period(Duration::from_millis(60_000)),
                )),
            )
            .unwrap()
            .with_retry_policy(replacement_policy)
            .unwrap()
            .with_metadata(metadata),
        );
        let original = Trigger::new(
            id.clone(),
            scheduled_action(
                vec![
                    Unregister::trigger(id.clone()).into(),
                    Register::trigger(replacement).into(),
                ],
                2,
                1_000,
            ),
        );
        let (state, source) = fixture(65_536, 3, vec![original], plain_network());
        install_pending_retry(&state, &id, retry);
        let (mut block, _recording) = recorded_component_block(&state, source.header());
        block.reserve_ordinary_execution_outputs(&source).unwrap();
        let expected_use = time_trigger_use_v1(&block.world.triggers, &id, 2).unwrap();
        let fragments = block.committed_fragment_count();
        block
            .produce_ordinary_execution_outputs(&source, |producer| {
                execute_network(producer)?;
                producer.execute_scheduled_time_outputs()
            })
            .unwrap();
        assert_eq!(retained(&block).rows.len(), 2);
        let actual = time_row(&block);
        assert_eq!(actual.invocation.trigger, expected_use);
        assert!(actual.result.is_ok());
        assert_eq!(actual.completions.len(), 1);
        // Overlay generation is transaction-local. The published action's
        // incarnation is its stored registration height and complete action hash.
        let replacement_use = time_trigger_use_v1(&block.world.triggers, &id, 3).unwrap();
        assert_ne!(
            replacement_use.registered_at_height,
            expected_use.registered_at_height
        );
        assert_ne!(replacement_use.action_hash, expected_use.action_hash);
        let replacement = block.world.triggers.time_triggers().get(&id).unwrap();
        assert_eq!(replacement.repeats, Repeats::Exactly(7));
        assert_eq!(replacement.retry_policy, Some(replacement_policy));
        // Real registration creates no retry state. A retry from the removed
        // incarnation must not leak into or consume the new registered action.
        assert_eq!(replacement.retry_state, None);
        assert_eq!(
            replacement.metadata.get("fresh_generation"),
            Some(&Json::new(true))
        );
        assert_eq!(
            replacement
                .metadata
                .get("__registered_block_height")
                .unwrap()
                .try_into_any_norito::<u64>()
                .unwrap(),
            2
        );
        assert!(
            time_trigger_use_v1(&block.world.triggers, &id, 2).is_err(),
            "fresh replacement cannot execute again at its registration height"
        );
        assert!(
            block
                .world
                .account(&ALICE_ID)
                .unwrap()
                .metadata()
                .get("replacement_ran")
                .is_none()
        );
        assert_eq!(block.committed_fragment_count(), fragments + 2);
        drop(_recording);
        drop(block);
        let triggers = state.world.triggers.view();
        let original = triggers.time_triggers().get(&id).unwrap();
        assert_eq!(original.retry_state, Some(retry));
        assert_eq!(original.repeats, Repeats::Exactly(2));
    }
}

#[test]
fn scheduled_vm_refusal_does_not_advance_retry_policy_or_emit_a_failure() {
    use iroha_data_model::transaction::IvmBytecode;
    use ivm::error::ExecutionDeferral;
    let id: TriggerId = "time_local_refusal".parse().unwrap();
    let mut program = ivm::ProgramMetadata {
        max_cycles: 100,
        ..Default::default()
    }
    .encode();
    program.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
    let action = Action::new(
        Executable::Ivm(IvmBytecode::from_compiled(program)),
        Repeats::Exactly(2),
        ALICE_ID.clone(),
        TimeEventFilter::new(ExecutionTime::PreCommit),
    )
    .unwrap();
    let (state, source) = fixture(
        65_536,
        1,
        vec![Trigger::new(id.clone(), action)],
        plain_network(),
    );
    let cache_owner = state.trigger_ivm_cache.lock().prepared_contract_cache();
    let reason = ExecutionDeferral::AllocationUnavailable;
    cache_owner.set_checkout_refusal_for_test(Some(reason));
    {
        let (mut block, _recording) = recorded_component_block(&state, source.header());
        block.reserve_ordinary_execution_outputs(&source).unwrap();
        let outcome = block.produce_ordinary_execution_outputs(&source, |producer| {
            execute_network(producer)?;
            producer.execute_scheduled_time_outputs()
        });
        assert_eq!(
            outcome,
            Err(ExecutionOutputAttemptError::Deferred(reason.into()))
        );
        assert!(block.retained_execution_outputs_for_test().is_err());
        let action = block.world.triggers.time_triggers().get(&id).unwrap();
        assert_eq!(action.repeats, Repeats::Exactly(2));
        assert!(action.retry_state.is_none());
        assert!(
            block
                .world
                .external_event_buf
                .iter()
                .all(|event| !matches!(event, EventBox::TriggerCompleted(_)))
        );
    }
    cache_owner.set_checkout_refusal_for_test(None);
    let (mut retry, _recording) = recorded_component_block(&state, source.header());
    retry.reserve_ordinary_execution_outputs(&source).unwrap();
    retry
        .produce_ordinary_execution_outputs(&source, |producer| {
            execute_network(producer)?;
            producer.execute_scheduled_time_outputs()
        })
        .expect("same scheduled invocation completes after local recovery");
    let ExecutionOutputV1::Time(row) = retained(&retry).rows.last().unwrap() else {
        panic!("actual Time output");
    };
    assert!(row.result.is_ok());
    assert_eq!(
        retry
            .world
            .triggers
            .time_triggers()
            .get(&id)
            .unwrap()
            .repeats,
        Repeats::Exactly(1)
    );
}

#[test]
fn empty_time_phase_publishes_no_reward_fragment_or_callback_output() {
    let (state, source) = fixture(65_536, 1, Vec::new(), plain_network());
    let (mut block, _recording) = recorded_component_block(&state, source.header());
    block.reserve_ordinary_execution_outputs(&source).unwrap();
    block
        .produce_ordinary_execution_outputs(&source, |producer| {
            execute_network(producer)?;
            let fragments = producer.state.committed_fragment_count();
            let durable_rows = producer.state.world.smart_contract_state.len();
            producer.execute_scheduled_time_outputs()?;
            assert_eq!(producer.state.committed_fragment_count(), fragments);
            assert_eq!(
                producer.state.world.smart_contract_state.len(),
                durable_rows
            );
            assert!(producer.state.world.triggers.time_triggers().is_empty());
            Ok(())
        })
        .unwrap();
    let rows = &retained(&block).rows;
    assert_eq!(
        rows.len(),
        1,
        "maintenance cannot invent a Time invocation row"
    );
    assert!(rows[0].result().is_ok());
    assert!(rows[0].completions().is_empty());
    assert!(rows[0].result().nexus_fee_receipt().is_none());
    assert!(rows[0].result().batch_transfer_outcomes().is_empty());
    assert!(block.batch_transfer_outcomes.is_empty());
    assert!(exec_witness::snapshot_exec_witness().writes.is_empty());
    assert_eq!(
        block
            .world
            .external_event_buf
            .iter()
            .filter(|event| matches!(event, EventBox::TriggerCompleted(_)))
            .count(),
        0
    );
}
