//! Actual Pipeline event ordering, rollback, repeat and quarantine controls.

use super::*;
use iroha_data_model::{
    block::execution_output::{PipelineEventPositionV1, TriggerFailureRootV1},
    events::pipeline::{
        BlockEventFilter, BlockStatus, PipelineEventFilterBox, TransactionEventFilter,
        TransactionStatus,
    },
};

fn callback(
    id: &str,
    body: Vec<InstructionBox>,
    filter: PipelineEventFilterBox,
    repeats: u32,
) -> Trigger {
    Trigger::new(
        id.parse().unwrap(),
        Action::new(body, Repeats::Exactly(repeats), ALICE_ID.clone(), filter).unwrap(),
    )
}

fn block_filter() -> PipelineEventFilterBox {
    BlockEventFilter::new()
        .for_status(BlockStatus::Approved)
        .into()
}

fn write(key: &str) -> InstructionBox {
    SetKeyValue::account(ALICE_ID.clone(), key.parse().unwrap(), Json::new(1)).into()
}

// Keep the large fixture State out of caller frames containing execution overlays.
#[inline(never)]
fn pipeline_fixture(bytes: u64, triggers: Vec<Trigger>) -> (Box<State>, SignedBlock) {
    let state = Box::new(fixture(bytes, None));
    {
        let mut parameters = state.world.parameters.block();
        let mut policy = parameters.get().block().execution_output();
        policy.max_pipeline_triggers = u32::try_from(triggers.len()).unwrap();
        parameters
            .get_mut()
            .set_parameter(Parameter::Block(BlockParameter::ExecutionOutput(policy)))
            .expect("valid fixture parameters");
        parameters.commit();
    }
    {
        let (mut setup, _setup_recording) = output_fixture_setup(&state);
        let mut tx = setup.transaction_for_callback_testing();
        for trigger in triggers {
            Register::trigger(trigger)
                .execute(&ALICE_ID, &mut tx)
                .unwrap();
        }
        tx.apply();
        setup.commit_world_overlay_for_testing().unwrap();
    }
    let source = carrier(
        &state,
        vec![input(
            &state,
            vec![Log::new(Level::DEBUG, "Network event".to_owned()).into()],
            FeePaymentIntent::authority(vec![], None),
            false,
        )],
    );
    (state, source)
}

fn execute_all(block: &mut StateBlock<'_>, source: &SignedBlock) {
    block.reserve_ordinary_execution_outputs(source).unwrap();
    block
        .produce_ordinary_execution_outputs(source, |producer| {
            producer.execute_network_sources(None)?;
            producer.execute_pipeline_outputs()?;
            producer.execute_scheduled_time_outputs()
        })
        .unwrap();
}

#[test]
fn actual_pipeline_uses_network_then_approved_block_and_distinct_calls() {
    let (state, source) = pipeline_fixture(
        65_536,
        vec![
            callback(
                "network_event",
                vec![write("network_callback")],
                TransactionEventFilter::new()
                    .for_status(TransactionStatus::Approved)
                    .into(),
                1,
            ),
            callback(
                "block_event",
                vec![write("block_callback")],
                block_filter(),
                1,
            ),
        ],
    );
    let (mut block, _recording) = recorded_network_block(&state, &source);
    execute_all(&mut block, &source);
    let rows = &retained(&block).rows;
    assert_eq!(rows.len(), 3);
    let (ExecutionOutputV1::Pipeline(first), ExecutionOutputV1::Pipeline(second)) =
        (&rows[1], &rows[2])
    else {
        panic!("two actual Pipeline invocations")
    };
    assert_eq!(first.invocation.event, PipelineEventPositionV1::Network(0));
    assert_eq!(
        second.invocation.event,
        PipelineEventPositionV1::BlockApproved
    );
    assert_ne!(
        first.invocation.execution_call_hash(source.hash()).unwrap(),
        second
            .invocation
            .execution_call_hash(source.hash())
            .unwrap()
    );
    assert!(rows.iter().all(|row| row.result().is_ok()));
    assert!(block.world.triggers.pipeline_triggers().is_empty());
    for key in ["network_callback", "block_callback"] {
        assert_eq!(
            block.world.account(&ALICE_ID).unwrap().metadata().get(key),
            Some(&Json::new(1))
        );
    }
}

#[test]
fn real_pipeline_rejection_quarantines_only_failed_callback_and_preserves_siblings() {
    let (state, source) = pipeline_fixture(
        65_536,
        vec![
            callback("a_good", vec![write("earlier")], block_filter(), 1),
            callback(
                "b_bad",
                vec![
                    write("rolled_back"),
                    Unregister::trigger("absent".parse().unwrap()).into(),
                ],
                block_filter(),
                1,
            ),
            callback("c_good", vec![write("later")], block_filter(), 1),
        ],
    );
    let (mut block, _recording) = recorded_network_block(&state, &source);
    execute_all(&mut block, &source);
    let rows = &retained(&block).rows;
    assert_eq!(rows.len(), 4);
    let ExecutionOutputV1::Pipeline(bad) = &rows[2] else {
        panic!("failed actual Pipeline row")
    };
    assert!(bad.result.is_err());
    assert!(matches!(
        bad.failure_root,
        Some(TriggerFailureRootV1::DeclaredInstructionProjection(_))
    ));
    assert_eq!(bad.completions.len(), 1);
    assert!(!rows[2].is_output_limit_rejection());
    assert!(rows[1].result().is_ok() && rows[3].result().is_ok());
    let account = block.world.account(&ALICE_ID).unwrap();
    assert!(account.metadata().get("rolled_back").is_none());
    assert!(
        account.metadata().get("earlier").is_some() && account.metadata().get("later").is_some()
    );
    let action = block
        .world
        .triggers
        .pipeline_triggers()
        .get(&"b_bad".parse().unwrap())
        .unwrap();
    assert_eq!(action.repeats, Repeats::Exactly(1));
    assert!(!crate::smartcontracts::isi::triggers::trigger_is_enabled(
        &action.metadata
    ));
    assert!(block.gas_used_in_block > 0);
}

#[test]
fn pipeline_full_row_exact_fit_and_one_byte_below_keep_failure_policy_separate() {
    let build = |bytes| {
        pipeline_fixture(
            bytes,
            vec![callback(
                "sized",
                vec![
                    write("sized_write"),
                    Log::new(Level::DEBUG, "x".repeat(16_384)).into(),
                ],
                block_filter(),
                1,
            )],
        )
    };
    let (state, source) = build(65_536);
    let (mut block, _recording) = recorded_network_block(&state, &source);
    execute_all(&mut block, &source);
    let exact =
        u64::try_from(norito::canonical_frame_len(&retained(&block).rows[1]).unwrap()).unwrap();
    drop(_recording);
    drop(block);
    for (bytes, applied) in [(exact, true), (exact - 1, false)] {
        let (state, source) = build(bytes);
        let (mut block, _recording) = recorded_network_block(&state, &source);
        execute_all(&mut block, &source);
        let row = &retained(&block).rows[1];
        assert_eq!(row.result().is_ok(), applied);
        assert_eq!(row.is_output_limit_rejection(), !applied);
        assert_eq!(
            block
                .world
                .account(&ALICE_ID)
                .unwrap()
                .metadata()
                .get("sized_write")
                .is_some(),
            applied
        );
        let action = block
            .world
            .triggers
            .pipeline_triggers()
            .get(&"sized".parse().unwrap());
        if applied {
            assert!(action.is_none());
        } else {
            let action = action.unwrap();
            assert_eq!(action.repeats, Repeats::Exactly(1));
            assert!(crate::smartcontracts::isi::triggers::trigger_is_enabled(
                &action.metadata
            ));
        }
    }
}

#[test]
fn pipeline_stale_match_keeps_original_candidate_gap_and_cannot_repeat_phase() {
    let (state, source) = pipeline_fixture(
        65_536,
        vec![
            callback(
                "a_remove",
                vec![Unregister::trigger("b_removed".parse().unwrap()).into()],
                block_filter(),
                1,
            ),
            callback("b_removed", vec![write("never")], block_filter(), 1),
            callback("c_last", vec![write("last")], block_filter(), 1),
        ],
    );
    let (mut block, _recording) = recorded_network_block(&state, &source);
    execute_all(&mut block, &source);
    let rows = &retained(&block).rows;
    assert_eq!(rows.len(), 3);
    let ExecutionOutputV1::Pipeline(last) = &rows[2] else {
        panic!("last Pipeline row")
    };
    assert_eq!(last.invocation.candidate_index, 2);
    assert!(
        block
            .world
            .account(&ALICE_ID)
            .unwrap()
            .metadata()
            .get("never")
            .is_none()
    );
    drop(_recording);
    drop(block);
    let (mut block, _recording) = recorded_network_block(&state, &source);
    block.reserve_ordinary_execution_outputs(&source).unwrap();
    assert!(
        block
            .produce_ordinary_execution_outputs(&source, |producer| {
                producer.execute_network_sources(None)?;
                producer.execute_pipeline_outputs()?;
                assert!(producer.execute_pipeline_outputs().is_err());
                Ok(())
            })
            .is_err()
    );
}

#[test]
fn exhausted_pipeline_gas_skips_callbacks_without_failure_or_repeat_debit() {
    let (state, source) = pipeline_fixture(
        65_536,
        vec![callback(
            "uninvoked",
            vec![write("never")],
            block_filter(),
            1,
        )],
    );
    let (mut block, _recording) = recorded_network_block(&state, &source);
    block.reserve_ordinary_execution_outputs(&source).unwrap();
    block
        .produce_ordinary_execution_outputs(&source, |producer| {
            producer.execute_network_sources(None)?;
            // Isolate the existing Pipeline stop predicate after real Network work.
            producer.state.gas_limit_per_block = producer.state.gas_used_in_block.max(1);
            producer.state.gas_used_in_block = producer.state.gas_limit_per_block;
            producer.execute_pipeline_outputs()?;
            producer.execute_scheduled_time_outputs()
        })
        .unwrap();
    assert_eq!(retained(&block).rows.len(), 1);
    let action = block
        .world
        .triggers
        .pipeline_triggers()
        .get(&"uninvoked".parse().unwrap())
        .unwrap();
    assert_eq!(action.repeats, Repeats::Exactly(1));
    assert!(crate::smartcontracts::isi::triggers::trigger_is_enabled(
        &action.metadata
    ));
    assert!(
        block
            .world
            .account(&ALICE_ID)
            .unwrap()
            .metadata()
            .get("never")
            .is_none()
    );
}

#[path = "output_internal_failure_tests.rs"]
mod internal_failures;

#[test]
fn pipeline_vm_refusal_preserves_callback_repeats_and_publishes_no_rejection() {
    use iroha_data_model::transaction::IvmBytecode;
    use ivm::error::ExecutionDeferral;
    let id: TriggerId = "pipeline_local_refusal".parse().unwrap();
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
        block_filter(),
    )
    .unwrap();
    let (state, source) = pipeline_fixture(65_536, vec![Trigger::new(id.clone(), action)]);
    let reason = ExecutionDeferral::AllocationUnavailable;
    let cache_owner = state.trigger_ivm_cache.lock().prepared_contract_cache();
    cache_owner.set_checkout_refusal_for_test(Some(reason));
    {
        let (mut block, _recording) = recorded_network_block(&state, &source);
        block.reserve_ordinary_execution_outputs(&source).unwrap();
        assert!(
            matches!(&(block.execute_ordinary_output_plan(&source, None)), Err(ExecutionOutputAttemptError::Deferred(owner)) if owner.reason() == reason && owner.phase().is_none() && owner.allocation_refusal().is_none() && owner.decode_refusal().is_none() && owner.verification_refusal().is_none())
        );
        assert!(block.retained_execution_outputs_for_test().is_err());
        assert_eq!(
            block
                .world
                .triggers
                .pipeline_triggers()
                .get(&id)
                .unwrap()
                .repeats,
            Repeats::Exactly(2)
        );
        assert!(
            block
                .world
                .external_event_buf
                .iter()
                .all(|event| !matches!(event, EventBox::TriggerCompleted(_)))
        );
    }
    cache_owner.set_checkout_refusal_for_test(None);
    let (mut retry, _recording) = recorded_network_block(&state, &source);
    execute_all(&mut retry, &source);
    let ExecutionOutputV1::Pipeline(row) = &retained(&retry).rows[1] else {
        panic!("actual Pipeline output");
    };
    assert!(row.result.is_ok());
    assert_eq!(
        retry
            .world
            .triggers
            .pipeline_triggers()
            .get(&id)
            .unwrap()
            .repeats,
        Repeats::Exactly(1)
    );
}
