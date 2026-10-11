//! Final public transcript contents remain bound through witness capture, extraction and commit.

use super::{
    native_capture_fixture::{
        assert_native_publication_refuses, seal_native_source, with_native_capture_source,
    },
    tests::delta,
    *,
};
use crate::{
    exec_witness,
    state::{State, WorldReadOnly},
};
use iroha_data_model::{
    asset::AssetId,
    fastpq::{TransferDeltaTranscript, TransferTranscript},
};
use iroha_model_base::state_path::StatePath;
use nonzero_ext::nonzero;

type TranscriptMap = BTreeMap<Hash, Vec<TransferTranscript>>;

fn finalized_source(
    block: &mut StateBlock<'_>,
    source: &mut iroha_data_model::block::SignedBlock,
) -> TranscriptMap {
    seal_native_source(block, source).unwrap();
    let archive = source.fastpq_transcripts().clone();
    assert!(block.fastpq_transcripts.is_empty());
    assert_eq!(archive.len(), 1);
    assert!(
        archive.values().next().unwrap()[0]
            .poseidon_preimage_digest
            .is_some()
    );
    archive
}

fn cached_outputs(block: &StateBlock<'_>) -> [bool; 3] {
    [
        block.exec_witness.is_some(),
        block.fastpq_witness_context.is_some(),
        block.parliament_timed_ovn_casting_bindings.is_some(),
    ]
}

fn assert_raw_content_failure(block: &StateBlock<'_>) -> String {
    // Inspect the raw fields before any guarded getter could conceal stale outputs.
    assert_eq!(cached_outputs(block), [false; 3]);
    block
        .fastpq_source_inventory
        .as_ref()
        .expect("content failure must retain an inventory result")
        .as_ref()
        .expect_err("content failure must be latched")
        .clone()
}

fn take_output(block: &mut StateBlock<'_>, output: usize) -> bool {
    match output {
        0 => block.take_exec_witness().is_some(),
        1 => block.take_fastpq_witness_context().is_some(),
        2 => block.take_parliament_timed_ovn_casting_bindings().is_some(),
        _ => unreachable!("there are exactly three captured outputs"),
    }
}

fn assert_getters_refuse(block: &mut StateBlock<'_>, first_error: &str) {
    for output in 0..3 {
        assert!(!take_output(block, output));
        assert_eq!(assert_raw_content_failure(block), first_error);
    }
}

fn assert_recorder_discarded() {
    let remaining = exec_witness::drain_exec_witness();
    assert!(remaining.reads.is_empty());
    assert!(remaining.writes.is_empty());
    assert!(remaining.fastpq_transcripts.is_empty());
    assert!(remaining.fastpq_batches.is_empty());
}

fn change_public_content(transcript: &mut TransferTranscript, missing_digest: bool) {
    if missing_digest {
        assert!(transcript.poseidon_preimage_digest.take().is_some());
    } else {
        transcript.authority_digest = Hash::new(b"substituted final witness authority");
    }
}

fn change_private_paths(delta: &mut TransferDeltaTranscript, seed: u8) {
    for (index, path) in [&mut delta.from_smt_witness, &mut delta.to_smt_witness]
        .into_iter()
        .enumerate()
    {
        let byte = seed + u8::try_from(index).unwrap();
        path.root_before = [byte; 32];
        path.root_after = [byte + 1; 32];
        path.path_bits = vec![byte];
        path.siblings = vec![[byte + 2; 32]];
    }
}

fn marker() -> StatePath {
    "fastpq/content-capture-publication-marker".parse().unwrap()
}

fn stage_marker_and_membership(block: &mut StateBlock<'_>) {
    {
        let mut tx = block.transaction();
        tx.world.smart_contract_state.insert(marker(), vec![1]);
        tx.apply();
    }
    block
        .stage_canonical_carrier_membership(Vec::new(), nonzero!(2_usize))
        .unwrap();
    let block_hash = block._curr_block.hash();
    block.block_hashes.push(block_hash);
}

fn assert_not_published(state: &State) {
    assert!(
        state
            .world
            .smart_contract_state
            .view()
            .get(&marker())
            .is_none()
    );
    assert_eq!(state.committed_height(), 1);
    assert_eq!(state.transactions.latest_height(), 1);
    assert_eq!(
        state.latest_block_hash_fast(),
        Some(state.network_id_ref().into_genesis_hash())
    );
}

#[test]
fn raw_recorder_public_change_or_missing_digest_rejects_before_synthetic_capture() {
    for missing_digest in [false, true] {
        with_native_capture_source(
            true,
            |_state, mut block, _recording, mut native_source, source| {
                let original = finalized_source(&mut block, &mut native_source);
                let mut substituted = original.clone();
                change_public_content(
                    &mut substituted.get_mut(&source).unwrap()[0],
                    missing_digest,
                );
                exec_witness::synchronize_fastpq_transcripts(&substituted);
                assert_eq!(cached_outputs(&block), [false; 3]);

                let error = block.capture_exec_witness().unwrap_err();
                assert!(error.contains("public content differs"), "{error}");
                assert_eq!(assert_raw_content_failure(&block), error);
                assert_getters_refuse(&mut block, &error);
                assert_recorder_discarded();
                assert_eq!(original[&source][0].deltas, vec![delta()]);
                assert!(original[&source][0].poseidon_preimage_digest.is_some());
            },
        );
    }
}

#[test]
fn inactive_first_capture_rejects_even_empty_inventory_after_ordinary_witness_was_drained() {
    with_native_capture_source(
        false,
        |_state, mut block, _recording, mut native_source, _source| {
            seal_native_source(&mut block, &mut native_source).unwrap();
            assert!(native_source.fastpq_transcripts().is_empty());
            let transfer = delta();
            let asset = AssetId::of(transfer.asset_definition, transfer.from_account);
            exec_witness::record_read_asset(&asset, Some(&transfer.from_balance_before));
            exec_witness::record_write_asset(&asset, &transfer.from_balance_after);
            let omitted = exec_witness::drain_exec_witness();
            assert_eq!(omitted.reads.len(), 1);
            assert_eq!(omitted.writes.len(), 1);
            assert!(omitted.fastpq_transcripts.is_empty());

            let error = block.capture_exec_witness().unwrap_err();
            assert_eq!(error, "execution prefix recorder was reset or retired");
            assert_eq!(assert_raw_content_failure(&block), error);
            assert_getters_refuse(&mut block, &error);
            assert_recorder_discarded();
        },
    );
}

#[test]
fn original_recorder_authority_failure_is_sticky_without_consuming_another_recorder() {
    for mutation in 0..3 {
        with_native_capture_source(
            true,
            |state, mut block, recording, mut native_source, _source| {
                let mut recording = Some(recording);
                let archive = finalized_source(&mut block, &mut native_source);
                assert!(block.verified_fastpq_source_inventory_for_capture().is_ok());
                let mut foreign = None;
                let expected = match mutation {
                    0 => {
                        block.original_execution_recorder = None;
                        "State execution has no original recorder"
                    }
                    1 => {
                        exec_witness::start_block();
                        exec_witness::synchronize_fastpq_transcripts(&archive);
                        "execution prefix recorder was reset or retired"
                    }
                    2 => {
                        drop(recording.take());
                        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
                        let (finish_tx, finish_rx) = std::sync::mpsc::channel();
                        let foreign_archive = archive.clone();
                        let worker = std::thread::spawn(move || {
                            let _recording = exec_witness::begin_exec_witness_capture().unwrap();
                            exec_witness::synchronize_fastpq_transcripts(&foreign_archive);
                            ready_tx.send(()).unwrap();
                            finish_rx.recv().unwrap();
                            exec_witness::drain_exec_witness()
                        });
                        ready_rx.recv().unwrap();
                        foreign = Some((finish_tx, worker));
                        "execution prefix lost its original recording scope"
                    }
                    _ => unreachable!(),
                };
                let error = block.capture_exec_witness().unwrap_err();
                assert_eq!(error, expected);
                assert_eq!(assert_raw_content_failure(&block), error);
                assert_getters_refuse(&mut block, &error);
                assert_eq!(
                    block.capture_exec_witness(),
                    Err("FASTPQ witness capture refuses a poisoned carrier".into())
                );
                // The carrier boundary refuses retries first, while preserving
                // the exact original content or recorder failure in the inventory.
                assert_eq!(block.fastpq_source_inventory(), Err(error.as_str()));
                // A genuine Sealed/Poisoned output owner has no finality publication
                // capability. The paired native control below exercises the real
                // prepare/publish path; it cannot reach the old component enum gate.
                assert!(block.verify_execution_output_publication().is_err());
                drop(block);
                let retained = if let Some((finish, worker)) = foreign {
                    finish.send(()).unwrap();
                    worker.join().unwrap()
                } else {
                    exec_witness::drain_exec_witness()
                };
                assert_eq!(retained.fastpq_transcripts.len(), 1);
                let (source, transcripts) = archive.iter().next().unwrap();
                assert_eq!(retained.fastpq_transcripts[0].entry_hash, *source);
                assert_eq!(&retained.fastpq_transcripts[0].transcripts, transcripts);
                drop(recording);
                assert_not_published(&state);
            },
        );
    }
}

#[test]
fn content_failure_survives_resynchronization_retry_getters_and_commit() {
    {
        with_native_capture_source(
            true,
            |state, mut block, _recording, mut native_source, source| {
                stage_marker_and_membership(&mut block);
                let original = finalized_source(&mut block, &mut native_source);
                let mut substituted = original.clone();
                change_public_content(&mut substituted.get_mut(&source).unwrap()[0], false);
                exec_witness::synchronize_fastpq_transcripts(&substituted);
                let first_error = block.capture_exec_witness().unwrap_err();
                assert_eq!(assert_raw_content_failure(&block), first_error);

                // A fresh active recorder with the exact old archive is not permission to repair
                // the block's latched failure or to fabricate a new ordinary witness.
                exec_witness::start_block();
                exec_witness::synchronize_fastpq_transcripts(&original);
                assert_eq!(
                    block.capture_exec_witness(),
                    Err("FASTPQ witness capture refuses a poisoned carrier".into())
                );
                // The carrier boundary refuses retries first, while preserving
                // the exact original content or recorder failure in the inventory.
                assert_eq!(block.fastpq_source_inventory(), Err(first_error.as_str()));
                assert_eq!(assert_raw_content_failure(&block), first_error);
                assert_getters_refuse(&mut block, &first_error);
                assert_eq!(block.fastpq_source_inventory(), Err(first_error.as_str()));
                // A genuine Sealed/Poisoned output owner has no finality publication
                // capability. The paired native control below exercises the real
                // prepare/publish path; it cannot reach the old component enum gate.
                assert!(block.verify_execution_output_publication().is_err());
                drop(block);
                assert_not_published(&state);
            },
        );
    }
}

#[test]
fn cached_public_mutation_rejects_repeat_capture_and_each_getter_as_first_operation() {
    for missing_digest in [false, true] {
        for first_operation in 0..4 {
            with_native_capture_source(
                true,
                |_state, mut block, _recording, mut native_source, _source| {
                    finalized_source(&mut block, &mut native_source);
                    block.capture_exec_witness().unwrap();
                    block
                        .exec_witness
                        .as_mut()
                        .unwrap()
                        .offer_reconstructed_tamper_for_test(|offered| {
                            change_public_content(
                                &mut offered.fastpq_transcripts[0].transcripts[0],
                                missing_digest,
                            );
                        });
                    assert_eq!(cached_outputs(&block), [true; 3]);
                    if first_operation == 0 {
                        assert!(block.capture_exec_witness().is_err());
                    } else {
                        assert!(!take_output(&mut block, first_operation - 1));
                    }
                    let error = assert_raw_content_failure(&block);
                    assert!(error.contains("public content differs"), "{error}");
                    assert_getters_refuse(&mut block, &error);
                    assert_eq!(block.capture_exec_witness(), Err(error.clone()));
                    assert_eq!(assert_raw_content_failure(&block), error);
                },
            );
        }
    }
}

#[test]
fn cached_capture_rejects_restarted_active_recorder_even_with_empty_fastpq() {
    for with_transfer in [false, true] {
        with_native_capture_source(
            with_transfer,
            |_state, mut block, _recording, mut native_source, _source| {
                if with_transfer {
                    finalized_source(&mut block, &mut native_source);
                } else {
                    seal_native_source(&mut block, &mut native_source).unwrap();
                    assert!(native_source.fastpq_transcripts().is_empty());
                }
                block.capture_exec_witness().unwrap();
                assert_eq!(cached_outputs(&block), [true, with_transfer, true]);
                exec_witness::start_block();

                let error = block.capture_exec_witness().unwrap_err();
                assert_eq!(
                    error,
                    "cached witness capture has an unexpected active global recorder"
                );
                assert_eq!(assert_raw_content_failure(&block), error);
                assert_recorder_discarded();
                assert_eq!(block.capture_exec_witness(), Err(error.clone()));
                assert_getters_refuse(&mut block, &error);
            },
        );
    }
}

#[test]
fn pending_overlay_prevents_first_or_cached_capture_and_leaves_failure_sticky() {
    for already_captured in [false, true] {
        with_native_capture_source(
            true,
            |_state, mut block, _recording, mut native_source, _source| {
                let original = finalized_source(&mut block, &mut native_source);
                if already_captured {
                    block.capture_exec_witness().unwrap();
                    assert_eq!(cached_outputs(&block), [true; 3]);
                }
                let overlay = exec_witness::begin_exec_witness_overlay();
                let error = block.capture_exec_witness().unwrap_err();
                assert!(error.contains("pending current-thread overlay"), "{error}");
                assert_eq!(assert_raw_content_failure(&block), error);
                drop(overlay);
                exec_witness::start_block();
                exec_witness::synchronize_fastpq_transcripts(&original);
                let retry_error = if already_captured {
                    // A cached-content rejection clears outputs and retains its exact
                    // first error; it cannot repair or replace the original sealed owner.
                    assert!(matches!(
                        block.execution_output_plan,
                        Some(crate::state::output_capacity::ExecutionOutputPlanState::Sealed(_))
                    ));
                    error.clone()
                } else {
                    // Failed first capture poisons the unpublished original carrier.
                    assert!(matches!(
                        block.execution_output_plan,
                        Some(crate::state::output_capacity::ExecutionOutputPlanState::Poisoned)
                    ));
                    "FASTPQ witness capture refuses a poisoned carrier".into()
                };
                assert_eq!(block.capture_exec_witness(), Err(retry_error));
                // Both paths retain their first source failure and hide every output.
                assert_eq!(block.fastpq_source_inventory(), Err(error.as_str()));
                assert_eq!(assert_raw_content_failure(&block), error);
                assert_getters_refuse(&mut block, &error);
                assert!(block.verify_execution_output_publication().is_err());
            },
        );
    }
}

#[test]
fn private_path_only_changes_survive_first_repeat_and_ordered_capture_extraction() {
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        with_native_capture_source(
            true,
            |_state, mut block, _recording, mut native_source, source| {
                let mut substituted = finalized_source(&mut block, &mut native_source);
                let owned = block
                    .verified_fastpq_source_inventory_for_capture()
                    .unwrap();
                change_private_paths(&mut substituted.get_mut(&source).unwrap()[0].deltas[0], 10);
                exec_witness::synchronize_fastpq_transcripts(&substituted);
                block.capture_exec_witness().unwrap();
                assert_eq!(cached_outputs(&block), [true; 3]);
                assert_eq!(
                    block.exec_witness.as_ref().unwrap().fastpq_transcripts[0].transcripts,
                    substituted[&source],
                );
                assert!(
                    block
                        .exec_witness
                        .as_ref()
                        .unwrap()
                        .fastpq_batches
                        .is_empty()
                );
                block
                    .exec_witness
                    .as_mut()
                    .unwrap()
                    .offer_reconstructed_tamper_for_test(|offered| {
                        change_private_paths(
                            &mut offered.fastpq_transcripts[0].transcripts[0].deltas[0],
                            20,
                        );
                    });
                block.capture_exec_witness().unwrap();
                assert_eq!(cached_outputs(&block), [true; 3]);
                assert!(Arc::ptr_eq(
                    block
                        .fastpq_witness_context
                        .as_ref()
                        .unwrap()
                        ._source_inventory
                        .as_ref()
                        .unwrap(),
                    &owned,
                ));
                let mut remaining = [true; 3];
                for output in order {
                    assert!(
                        take_output(&mut block, output),
                        "extraction order {order:?}"
                    );
                    remaining[output] = false;
                    assert_eq!(cached_outputs(&block), remaining);
                }
                assert_eq!(
                    block.fastpq_source_inventory().unwrap(),
                    Some(owned.as_ref())
                );
            },
        );
    }
}

#[test]
fn directly_mutated_cached_public_bundles_cannot_commit_without_recapture_or_getters() {
    for missing_digest in [false, true] {
        {
            with_native_capture_source(
                true,
                |state, mut block, _recording, mut native_source, _source| {
                    stage_marker_and_membership(&mut block);
                    finalized_source(&mut block, &mut native_source);
                    block.capture_exec_witness().unwrap();
                    block
                        .exec_witness
                        .as_mut()
                        .unwrap()
                        .offer_reconstructed_tamper_for_test(|offered| {
                            change_public_content(
                                &mut offered.fastpq_transcripts[0].transcripts[0],
                                missing_digest,
                            );
                        });
                    assert_eq!(cached_outputs(&block), [true; 3]);
                    assert!(block.fastpq_source_inventory.as_ref().unwrap().is_ok());
                    // A genuine Sealed/Poisoned output owner has no finality publication
                    // capability. The paired native control below exercises the real
                    // prepare/publish path; it cannot reach the old component enum gate.
                    assert!(block.verify_execution_output_publication().is_err());
                    drop(block);
                    assert_not_published(&state);
                },
            );
        }
    }
}

fn unexpected_prebuilt_batch() -> iroha_data_model::fastpq::FastpqTransitionBatch {
    // Even an otherwise empty DTO is outside ordinary recorder ownership.
    iroha_data_model::fastpq::FastpqTransitionBatch {
        parameter: "unexpected-prebuilt-ordinary-batch".to_owned(),
        public_inputs: iroha_data_model::fastpq::FastpqPublicInputs {
            dsid: [0; 16],
            slot: 0,
            old_root: [0; 32],
            new_root: [0; 32],
            perm_root: [0; 32],
            tx_set_hash: [0; 32],
        },
        transitions: Vec::new(),
        metadata: BTreeMap::new(),
    }
}

#[test]
fn cached_prebuilt_batches_reject_recapture_and_every_first_getter_with_sticky_failure() {
    for with_transfer in [false, true] {
        for first_operation in 0..4 {
            with_native_capture_source(
                with_transfer,
                |state, mut block, _recording, mut native_source, _source| {
                    stage_marker_and_membership(&mut block);
                    let original = if with_transfer {
                        finalized_source(&mut block, &mut native_source)
                    } else {
                        seal_native_source(&mut block, &mut native_source).unwrap();
                        native_source.fastpq_transcripts().clone()
                    };
                    block.capture_exec_witness().unwrap();
                    assert_eq!(cached_outputs(&block), [true, with_transfer, true]);
                    block
                        .exec_witness
                        .as_mut()
                        .unwrap()
                        .offer_reconstructed_tamper_for_test(|offered| {
                            offered.fastpq_batches.push(unexpected_prebuilt_batch());
                        });
                    if first_operation == 0 {
                        assert!(block.capture_exec_witness().is_err());
                    } else {
                        assert!(!take_output(&mut block, first_operation - 1));
                    }
                    let error = assert_raw_content_failure(&block);
                    assert_eq!(
                        error,
                        "ordinary captured witness contains prebuilt FASTPQ batches"
                    );
                    assert_getters_refuse(&mut block, &error);
                    // Restarting the recorder with the original archive cannot repair the
                    // StateBlock content failure after the unauthorized batch was observed.
                    exec_witness::start_block();
                    exec_witness::synchronize_fastpq_transcripts(&original);
                    assert_eq!(block.capture_exec_witness(), Err(error.clone()));
                    assert_eq!(assert_raw_content_failure(&block), error);
                    // A genuine Sealed/Poisoned output owner has no finality publication
                    // capability. The paired native control below exercises the real
                    // prepare/publish path; it cannot reach the old component enum gate.
                    assert!(block.verify_execution_output_publication().is_err());
                    drop(block);
                    assert_not_published(&state);
                },
            );
        }
    }
}

#[test]
fn cached_prebuilt_batches_cannot_commit_without_recapture_or_getters() {
    for with_transfer in [false, true] {
        {
            with_native_capture_source(
                with_transfer,
                |state, mut block, _recording, mut native_source, _source| {
                    stage_marker_and_membership(&mut block);
                    if with_transfer {
                        finalized_source(&mut block, &mut native_source);
                    } else {
                        seal_native_source(&mut block, &mut native_source).unwrap();
                        assert!(native_source.fastpq_transcripts().is_empty());
                    }
                    block.capture_exec_witness().unwrap();
                    block
                        .exec_witness
                        .as_mut()
                        .unwrap()
                        .offer_reconstructed_tamper_for_test(|offered| {
                            offered.fastpq_batches.push(unexpected_prebuilt_batch());
                        });
                    assert_eq!(cached_outputs(&block), [true, with_transfer, true]);
                    assert!(block.fastpq_source_inventory.as_ref().unwrap().is_ok());
                    // A genuine Sealed/Poisoned output owner has no finality publication
                    // capability. The paired native control below exercises the real
                    // prepare/publish path; it cannot reach the old component enum gate.
                    assert!(block.verify_execution_output_publication().is_err());
                    drop(block);
                    assert_not_published(&state);
                },
            );
        }
    }
}

#[test]
fn failed_output_binding_publishes_no_partial_capture_and_cannot_be_retried() {
    use crate::state::output_capacity::ExecutionOutputPlanState;
    for with_transfer in [false, true] {
        with_native_capture_source(
            with_transfer,
            |state, mut block, _recording, mut native_source, _source| {
                stage_marker_and_membership(&mut block);
                let archive = if with_transfer {
                    finalized_source(&mut block, &mut native_source)
                } else {
                    seal_native_source(&mut block, &mut native_source).unwrap();
                    native_source.fastpq_transcripts().clone()
                };
                let prior_lane_seal = block.sumeragi_lane_state_seal;
                block.execution_output_plan = Some(ExecutionOutputPlanState::Running);
                let error = block.capture_exec_witness().unwrap_err();
                assert_eq!(
                    error,
                    "witness capture requires completed execution outputs"
                );
                assert_eq!(assert_raw_content_failure(&block), error);
                assert_eq!(block.sumeragi_lane_state_seal, prior_lane_seal);
                assert!(matches!(
                    block.execution_output_plan,
                    Some(ExecutionOutputPlanState::Poisoned)
                ));
                assert_recorder_discarded();

                // Neither repairing the output plan nor restoring identical public inputs
                // can turn a failed first capture into a new authority-bearing attempt.
                block.execution_output_plan = None;
                crate::exec_witness::start_block();
                crate::exec_witness::synchronize_fastpq_transcripts(&archive);
                assert_eq!(block.capture_exec_witness(), Err(error.clone()));
                assert_getters_refuse(&mut block, &error);
                // Deliberately removing the plan selects the component setup
                // surface, but cannot remove the first source-inventory failure.
                block.verify_execution_output_publication().unwrap();
                block.validate_canonical_runtime_projection().unwrap();
                block.verify_sumeragi_lane_state_publication().unwrap();
                assert!(matches!(
                    block.commit(),
                    Err(crate::state::TransactionsBlockError::FastpqSourceInventory)
                ));
                assert_not_published(&state);
                crate::exec_witness::drain_exec_witness();
            },
        );
    }
}

#[test]
fn interrupted_capture_restores_prior_lane_seal_and_latches_publication_failure() {
    use crate::state::{
        exec_witness_capture::WitnessCaptureGuard, output_capacity::ExecutionOutputPlanState,
    };
    for had_lane_seal in [false, true] {
        with_native_capture_source(
            true,
            |_state, mut block, _recording, mut native_source, _source| {
                let original = finalized_source(&mut block, &mut native_source);
                let prior = had_lane_seal.then(|| {
                    iroha_data_model::sumeragi_finality::SumeragiLaneStateCommitment::from_state(
                        block.network_id,
                        block._curr_block.height().get(),
                        block.world.sumeragi_lanes(),
                    )
                    .unwrap()
                    .state_hash()
                });
                block.sumeragi_lane_state_seal = prior;
                block.execution_output_plan = Some(ExecutionOutputPlanState::Running);
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let capture = WitnessCaptureGuard::new(&mut block);
                    capture.state.sumeragi_lane_state_seal = Some(Hash::new(b"partial lane seal"));
                    capture.state.parliament_timed_ovn_casting_bindings = Some(Vec::new());
                    let wire = crate::exec_witness::drain_exec_witness();
                    capture.state.exec_witness =
                        Some(capture.state.retain_quantity_source_witness(wire).unwrap());
                    panic!("test-only capture interruption");
                }));
                assert!(outcome.is_err());
                assert_eq!(block.sumeragi_lane_state_seal, prior);
                let error = assert_raw_content_failure(&block);
                assert_eq!(error, "execution witness capture was interrupted");
                assert!(matches!(
                    block.execution_output_plan,
                    Some(ExecutionOutputPlanState::Poisoned)
                ));
                crate::exec_witness::start_block();
                crate::exec_witness::synchronize_fastpq_transcripts(&original);
                assert_eq!(
                    block.capture_exec_witness(),
                    Err("FASTPQ witness capture refuses a poisoned carrier".into())
                );
                // Carrier poisoning takes precedence at the capture boundary; the
                // interrupted capture remains the retained first inventory failure.
                assert_eq!(block.fastpq_source_inventory(), Err(error.as_str()));
                assert_getters_refuse(&mut block, &error);
                crate::exec_witness::drain_exec_witness();
            },
        );
    }
}

/// The original local failure has already poisoned the retained output owner.
/// This native mutation controls the same refusal state without inventing a QC
/// capability or claiming the later inventory gate ran before publication checks.
fn assert_poisoned_native_source_cannot_publish(with_transfer: bool) {
    assert_native_publication_refuses(with_transfer, |original| {
        original.state.execution_output_plan =
            Some(crate::state::output_capacity::ExecutionOutputPlanState::Poisoned);
        assert_eq!(
            original
                .state
                .verified_fastpq_source_inventory_for_capture()
                .unwrap_err(),
            "FASTPQ witness capture refuses a poisoned carrier"
        );
        assert!(
            original
                .state
                .verify_execution_output_publication()
                .is_err()
        );
    });
}

#[test]
fn actual_native_prepare_and_publish_refuse_every_local_poisoned_output_shape() {
    for with_transfer in [false, true] {
        assert_poisoned_native_source_cannot_publish(with_transfer);
    }
}

#[test]
fn actual_native_public_content_mutations_cannot_publish_without_recapture_or_getters() {
    for missing_digest in [false, true] {
        assert_native_publication_refuses(true, move |mut original| {
            let inventory = original
                .state
                .verified_fastpq_source_inventory_for_capture()
                .unwrap();
            original.witness.offer_reconstructed_tamper(|offered| {
                change_public_content(
                    &mut offered.fastpq_transcripts[0].transcripts[0],
                    missing_digest,
                );
            });
            let error = inventory
                .verify_ordinary_witness_bundles(&original.witness.wire().fastpq_transcripts)
                .unwrap_err();
            assert_eq!(
                error,
                "FASTPQ final witness public content differs from the owned inventory seal"
            );
            assert!(
                original
                    .state
                    .verify_sumeragi_execution_witness(
                        original.block.as_ref(),
                        original.witness.wire()
                    )
                    .is_err()
            );
        });
    }
}

#[test]
fn actual_native_prebuilt_batches_cannot_publish_without_recapture_or_getters() {
    for with_transfer in [false, true] {
        assert_native_publication_refuses(with_transfer, |mut original| {
            original.witness.offer_reconstructed_tamper(|offered| {
                offered.fastpq_batches.push(unexpected_prebuilt_batch());
            });
            assert_eq!(original.witness.wire().fastpq_batches.len(), 1);
            assert!(
                original
                    .state
                    .verify_sumeragi_execution_witness(
                        original.block.as_ref(),
                        original.witness.wire()
                    )
                    .is_err()
            );
        });
    }
}
