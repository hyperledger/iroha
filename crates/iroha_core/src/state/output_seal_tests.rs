//! Actual all-phase execution and consuming output attachment controls.
//! Successful attachment intentionally retains the unfinished publication gate.

use super::*;
use crate::state::{ExecutionOutputSealError, ExecutionOutputSealMetadata};
use iroha_data_model::events::{
    pipeline::{BlockEventFilter, BlockStatus},
    time::{ExecutionTime, TimeEventFilter},
};

#[derive(norito::NoritoSchema, norito::codec::Decode, norito::codec::Encode)]
#[norito_schema(name = "iroha_core::state::output_seal_tests::AlteredProposal")]
struct AlteredProposal {
    signatures: iroha_data_model::block::BlockSignatures,
    payload: iroha_data_model::block::BlockPayload,
    result: Option<iroha_data_model::block::BlockResult>,
    commit_certificate: Option<iroha_data_model::block::CommitCertificate>,
}

#[test]
fn altered_auxiliary_body_cannot_enter_finalizer_with_the_original_header() {
    use norito::codec::{DecodeAll, Encode};
    let (state, mut source) = seal_fixture();
    let (mut block, _recording) = recorded_network_block(&state, &source);
    run(&mut block, &source);
    let before = source.header();
    let mut raw = AlteredProposal::decode_all(&mut source.encode().as_slice()).unwrap();
    raw.payload.execution_context = Some(
        iroha_data_model::block::BlockExecutionContextBundle::new(Vec::new()),
    );
    source = SignedBlock::decode_all(&mut raw.encode().as_slice()).unwrap();
    assert_eq!(source.header(), before);
    assert!(source.validate_proposal_commitments().is_err());
    let result = block.seal_execution_outputs::<String>(&mut source, |_, _, _| {
        panic!("unauthenticated auxiliary body entered finalizer")
    });
    assert!(matches!(result, Err(ExecutionOutputSealError::Owner(_))));
    assert!(!source.has_results());
    assert!(matches!(
        block.execution_output_plan,
        Some(ExecutionOutputPlanState::Poisoned)
    ));
}

#[test]
fn unowned_receipt_accumulator_refuses_before_and_after_finalizer() {
    for after in [false, true] {
        let (state, mut source) = seal_fixture();
        let (mut block, _recording) = recorded_network_block(&state, &source);
        run(&mut block, &source);
        let foreign = HashOf::from_untyped_unchecked(Hash::new(b"unowned receipt accumulator"));
        if !after {
            block.batch_transfer_outcomes.insert(foreign, Vec::new());
        }
        let mut called = false;
        let result = block.seal_execution_outputs(&mut source, |state, source, routes| {
            called = true;
            assert!(after, "unowned prefix receipts reached finalizer");
            state.batch_transfer_outcomes.insert(foreign, Vec::new());
            metadata(state, source, routes)
        });
        assert_eq!(called, after);
        assert!(
            matches!(result, Err(ExecutionOutputSealError::Owner(error)) if error.contains("unowned business receipts"))
        );
        assert!(!source.has_results());
        assert!(matches!(
            block.execution_output_plan,
            Some(ExecutionOutputPlanState::Poisoned)
        ));
    }
}

// Keep the large fixture State out of caller frames containing execution overlays.
#[inline(never)]
fn seal_fixture() -> (Box<State>, SignedBlock) {
    let state = Box::new(fixture(65_536, None));
    {
        let mut parameters = state.world.parameters.block();
        let mut policy = parameters.get().block().execution_output();
        policy.max_pipeline_triggers = 1;
        parameters
            .get_mut()
            .set_parameter(Parameter::Block(BlockParameter::ExecutionOutput(policy)))
            .expect("valid fixture parameters");
        parameters.commit();
    }
    let write = |key: &str| {
        vec![InstructionBox::from(SetKeyValue::account(
            ALICE_ID.clone(),
            key.parse().unwrap(),
            Json::new(1),
        ))]
    };
    {
        let (mut setup, _setup_recording) = output_fixture_setup(&state);
        let mut tx = setup.transaction_for_callback_testing();
        for trigger in [
            Trigger::new(
                "seal_pipeline".parse().unwrap(),
                Action::new(
                    write("pipeline"),
                    Repeats::Exactly(1),
                    ALICE_ID.clone(),
                    BlockEventFilter::new().for_status(BlockStatus::Approved),
                )
                .unwrap(),
            ),
            Trigger::new(
                "seal_time".parse().unwrap(),
                Action::new(
                    write("time"),
                    Repeats::Exactly(1),
                    ALICE_ID.clone(),
                    TimeEventFilter::new(ExecutionTime::PreCommit),
                )
                .unwrap(),
            ),
        ] {
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
            write("network"),
            FeePaymentIntent::authority(vec![], None),
            false,
        )],
    );
    (state, source)
}

fn run(block: &mut StateBlock<'_>, source: &SignedBlock) {
    block.reserve_ordinary_execution_outputs(source).unwrap();
    block.execute_ordinary_output_plan(source, None).unwrap();
}

fn metadata(
    block: &mut StateBlock<'_>,
    source: &SignedBlock,
    routes: &[crate::queue::RoutingDecision],
) -> Result<ExecutionOutputSealMetadata, String> {
    assert_eq!(routes.len(), 1);
    Ok(ExecutionOutputSealMetadata {
        sccp_finality_header: iroha_data_model::sumeragi_finality::SccpFinalityHeaderV1::inactive(
            *block.network_id().as_bytes(),
            source.header().height().get(),
            source.header().creation_time_ms,
        )
        .expect("nonzero fixture height"),
        committed_fragment_count: u64::try_from(block.committed_fragment_count()).unwrap(),
    })
}

#[test]
fn actual_three_phase_seal_keeps_proposal_and_exact_wire_and_blocks_publication() {
    let (state, mut source) = seal_fixture();
    let header = source.header();
    let signatures = source.signatures().cloned().collect::<Vec<_>>();
    let (mut block, _recording) = recorded_network_block(&state, &source);
    run(&mut block, &source);
    assert!(block.sealed_sccp_finality_header(&source).is_err());
    let expected_x = iroha_data_model::sumeragi_finality::SccpFinalityHeaderV1::inactive(
        *block.network_id().as_bytes(),
        header.height().get(),
        header.creation_time_ms,
    )
    .unwrap();
    let rows = retained(&block).rows.clone();
    assert_eq!(rows.len(), 3);
    assert!(matches!(
        &rows[..],
        [
            ExecutionOutputV1::Network(_),
            ExecutionOutputV1::Pipeline(_),
            ExecutionOutputV1::Time(_)
        ]
    ));
    block.seal_execution_outputs(&mut source, metadata).unwrap();
    assert_eq!(source.header(), header);
    assert_eq!(
        block.sealed_sccp_finality_header(&source).unwrap(),
        expected_x
    );
    assert_eq!(source.signatures().cloned().collect::<Vec<_>>(), signatures);
    assert_eq!(source.execution_outputs(), rows);
    assert_eq!(
        block
            .verified_fastpq_source_inventory_for_capture()
            .unwrap()
            .entries()
            .len(),
        3
    );
    block.verify_execution_output_seal(&source).unwrap();
    let original_x = block.sealed_sccp_finality_header(&source).unwrap();
    assert_eq!(original_x.network_id(), *block.network_id().as_bytes());
    assert_eq!(original_x.height(), source.header().height().get());
    assert_eq!(original_x.timestamp_ms(), source.header().creation_time_ms);
    assert!(!original_x.is_active());
    for key in ["network", "pipeline", "time"] {
        assert_eq!(
            block.world.account(&ALICE_ID).unwrap().metadata().get(key),
            Some(&Json::new(1))
        );
    }
    assert!(matches!(
        block.commit().unwrap_err(),
        TransactionsBlockError::ExecutionOutputCapacity
    ));
}

#[test]
fn foreign_finality_header_cannot_replace_original_output_coordinates() {
    for changed in 0..3 {
        let (state, mut source) = seal_fixture();
        let (mut block, _recording) = recorded_network_block(&state, &source);
        assert!(block.sealed_sccp_finality_header(&source).is_err());
        run(&mut block, &source);
        let result = block.seal_execution_outputs(&mut source, |state, source, routes| {
            let mut exact = metadata(state, source, routes)?;
            let mut network = exact.sccp_finality_header.network_id();
            let mut height = exact.sccp_finality_header.height();
            let mut timestamp = exact.sccp_finality_header.timestamp_ms();
            match changed {
                0 => network[0] ^= 1,
                1 => height += 1,
                _ => timestamp += 1,
            }
            exact.sccp_finality_header =
                iroha_data_model::sumeragi_finality::SccpFinalityHeaderV1::inactive(
                    network, height, timestamp,
                )
                .unwrap();
            Ok::<_, String>(exact)
        });
        assert!(
            matches!(result, Err(ExecutionOutputSealError::Owner(reason)) if reason.contains("SCCP finality header"))
        );
        assert!(block.sealed_sccp_finality_header(&source).is_err());
        assert!(!source.has_results());
        assert!(matches!(
            block.execution_output_plan,
            Some(ExecutionOutputPlanState::Poisoned)
        ));
    }
}

#[test]
fn repeated_execution_or_seal_cannot_reapply_actual_effects() {
    let (state, mut source) = seal_fixture();
    let (mut block, _recording) = recorded_network_block(&state, &source);
    run(&mut block, &source);
    let fragments = block.committed_fragment_count();
    assert!(block.execute_ordinary_output_plan(&source, None).is_err());
    assert_eq!(block.committed_fragment_count(), fragments);
    block.seal_execution_outputs(&mut source, metadata).unwrap();
    assert!(block.seal_execution_outputs(&mut source, metadata).is_err());
    assert!(matches!(
        block.execution_output_plan,
        Some(ExecutionOutputPlanState::Poisoned)
    ));
    assert_eq!(block.committed_fragment_count(), fragments);
}

#[test]
fn foreign_proposal_and_partial_mock_sources_cannot_enter_the_finalizer() {
    for partial in [false, true] {
        let (state, mut source) = seal_fixture();
        let (mut block, _recording) = recorded_network_block(&state, &source);
        block.reserve_ordinary_execution_outputs(&source).unwrap();
        if partial {
            block
                .produce_ordinary_execution_outputs(&source, |producer| {
                    producer.execute_network_sources(None)?;
                    // Fixture-only skipping resolves budget slots but never owns actual invocations.
                    producer.skip_uninvoked(ExecutionOutputPhase::Pipeline, 2)?;
                    producer
                        .skip_uninvoked(ExecutionOutputPhase::Time, 1)
                        .map_err(Into::into)
                })
                .unwrap();
        } else {
            block.execute_ordinary_output_plan(&source, None).unwrap();
            source = carrier(
                &state,
                vec![input(
                    &state,
                    vec![Log::new(Level::INFO, "foreign".to_owned()).into()],
                    FeePaymentIntent::authority(vec![], None),
                    false,
                )],
            );
        }
        let result = block.seal_execution_outputs::<String>(&mut source, |_, _, _| {
            panic!("foreign/partial source entered finalizer")
        });
        assert!(result.is_err());
        assert!(matches!(
            block.execution_output_plan,
            Some(ExecutionOutputPlanState::Poisoned)
        ));
    }
}

#[test]
fn combined_driver_owns_actual_phases_and_finalizer_once() {
    let (state, mut source) = seal_fixture();
    let (mut block, _recording) = recorded_network_block(&state, &source);
    let mut calls = 0;
    block
        .execute_and_seal_ordinary_outputs(&mut source, None, |state, source, routes| {
            calls += 1;
            metadata(state, source, routes)
        })
        .unwrap();
    assert_eq!(calls, 1);
    assert_eq!(source.execution_outputs().len(), 3);
    block.verify_execution_output_seal(&source).unwrap();
    let fragments = block.committed_fragment_count();
    assert!(
        block
            .execute_and_seal_ordinary_outputs::<String>(&mut source, None, |_, _, _| panic!(
                "repeated finalizer"
            ))
            .is_err()
    );
    assert_eq!(block.committed_fragment_count(), fragments);
    assert!(matches!(
        block.commit().unwrap_err(),
        TransactionsBlockError::ExecutionOutputCapacity
    ));
}

#[test]
fn finalizer_error_and_unwind_poison_the_consumed_owner() {
    for unwind in [false, true] {
        let (state, mut source) = seal_fixture();
        let (mut block, _recording) = recorded_network_block(&state, &source);
        run(&mut block, &source);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            block.seal_execution_outputs(&mut source, |_, _, _| {
                if unwind {
                    panic!("crash cut inside finalizer");
                }
                Err(17_u8)
            })
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert!(matches!(
                result.unwrap(),
                Err(ExecutionOutputSealError::Finalizer(17))
            ));
        }
        assert!(!source.has_results());
        assert!(matches!(
            block.execution_output_plan,
            Some(ExecutionOutputPlanState::Poisoned)
        ));
        assert!(matches!(
            block.commit().unwrap_err(),
            TransactionsBlockError::ExecutionOutputCapacity
        ));
    }
}

#[test]
fn finalizer_must_account_for_every_applied_fragment() {
    let (state, mut source) = seal_fixture();
    let (mut block, _recording) = recorded_network_block(&state, &source);
    run(&mut block, &source);
    let result = block.seal_execution_outputs(&mut source, |state, source, routes| {
        let before = metadata(state, source, routes)?;
        let mut transaction = state.transaction();
        SetKeyValue::account(
            ALICE_ID.clone(),
            "late_finalizer".parse().unwrap(),
            Json::new(1),
        )
        .execute(&ALICE_ID, &mut transaction)
        .unwrap();
        transaction.apply();
        Ok::<_, String>(before)
    });
    assert!(
        matches!(result, Err(ExecutionOutputSealError::Owner(error)) if error.contains("every applied fragment"))
    );
    assert!(!source.has_results());
    assert!(matches!(
        block.execution_output_plan,
        Some(ExecutionOutputPlanState::Poisoned)
    ));
}

#[test]
fn changed_signature_invalidates_exact_attachment_without_changing_proposal() {
    let (state, mut source) = seal_fixture();
    let (mut block, _recording) = recorded_network_block(&state, &source);
    run(&mut block, &source);
    block.seal_execution_outputs(&mut source, metadata).unwrap();
    let proposal = source.hash();
    source
        .add_signature(iroha_data_model::block::BlockSignature::new(
            1,
            iroha_crypto::SignatureOf::new(ALICE_KEYPAIR.private_key(), &source.header()),
        ))
        .unwrap();
    assert_eq!(source.hash(), proposal);
    assert!(block.verify_execution_output_seal(&source).is_err());
    assert!(block.sealed_sccp_finality_header(&source).is_err());
}

#[test]
fn state_transaction_cannot_apply_after_output_seal() {
    for consensus_only in [false, true] {
        let (state, mut source) = seal_fixture();
        let (mut block, _recording) = recorded_network_block(&state, &source);
        run(&mut block, &source);
        block.seal_execution_outputs(&mut source, metadata).unwrap();
        let fragments = block.committed_fragment_count();
        let mut transaction = block.transaction();
        SetKeyValue::account(
            ALICE_ID.clone(),
            "after_seal".parse().unwrap(),
            Json::new(1),
        )
        .execute(&ALICE_ID, &mut transaction)
        .unwrap();
        if consensus_only {
            transaction.apply_consensus_effects();
        } else {
            transaction.apply();
        }
        assert!(
            block
                .world
                .account(&ALICE_ID)
                .unwrap()
                .metadata()
                .get("after_seal")
                .is_none()
        );
        assert_eq!(block.committed_fragment_count(), fragments);
        assert!(block.verify_execution_output_seal(&source).is_err());
        assert!(matches!(
            block.commit().unwrap_err(),
            TransactionsBlockError::ExecutionOutputCapacity
        ));
    }
}

#[test]
fn actual_seal_binds_finalizer_world_values_and_refuses_late_durable_changes() {
    let (state, mut source) = seal_fixture();
    let (mut block, _recording) = recorded_network_block(&state, &source);
    run(&mut block, &source);
    let key: iroha_model_base::state_path::StatePath = "seal/finalizer".parse().unwrap();
    block
        .seal_execution_outputs(&mut source, |state, source, routes| {
            // Direct deterministic finalizer effects belong to the sealed World delta.
            state
                .world
                .smart_contract_state
                .insert(key.clone(), vec![1]);
            metadata(state, source, routes)
        })
        .unwrap();
    block.verify_execution_output_seal(&source).unwrap();
    let wire = source.encode_wire().unwrap();
    block
        .world
        .smart_contract_state
        .insert(key.clone(), vec![2]);
    assert_eq!(source.encode_wire().unwrap(), wire);
    assert!(
        block
            .verify_execution_output_seal(&source)
            .unwrap_err()
            .contains("World values changed")
    );
    assert!(matches!(
        block.commit().unwrap_err(),
        TransactionsBlockError::ExecutionOutputCapacity
    ));
}

#[test]
fn seal_verification_uses_values_instead_of_noop_or_rolled_back_touch_history() {
    let (state, mut source) = seal_fixture();
    let (mut block, _recording) = recorded_network_block(&state, &source);
    run(&mut block, &source);
    block.seal_execution_outputs(&mut source, metadata).unwrap();
    block
        .world
        .smart_contract_state
        .remove("seal/missing".parse().unwrap());
    {
        // Exercise the actual low-level rollback; ordinary State transaction
        // application after sealing remains forbidden by its existing owner.
        let mut tx = block.world.smart_contract_state.transaction();
        tx.insert("seal/aborted".parse().unwrap(), vec![1]);
    }
    block.verify_execution_output_seal(&source).unwrap();
    let before = *block.world.soradns_last_publish_ms.get();
    *block.world.soradns_last_publish_ms.get_mut() = match before {
        None => Some(1),
        Some(_) => None,
    };
    assert!(
        block
            .verify_execution_output_seal(&source)
            .unwrap_err()
            .contains("World values changed")
    );
    assert!(matches!(
        block.commit().unwrap_err(),
        TransactionsBlockError::ExecutionOutputCapacity
    ));
}

#[test]
fn sccp_header_requires_original_completed_seal_and_rejects_later_world_changes() {
    let (state, mut source) = seal_fixture();
    let (mut block, _recording) = recorded_network_block(&state, &source);
    let expected =
        iroha_data_model::sumeragi_finality::certified_result::SccpFinalityHeaderV1::inactive(
            *state.network_id.as_bytes(),
            source.header().height().get(),
            source.header().creation_time_ms,
        )
        .unwrap();
    assert!(block.sealed_sccp_finality_header(&source).is_err());
    run(&mut block, &source);
    assert!(block.sealed_sccp_finality_header(&source).is_err());
    block.seal_execution_outputs(&mut source, metadata).unwrap();
    assert_eq!(
        block.sealed_sccp_finality_header(&source).unwrap(),
        expected
    );
    *block.world.sccp_degraded_run.get_mut() = 1;
    assert!(block.sealed_sccp_finality_header(&source).is_err());
}
