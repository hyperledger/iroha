//! Final witness capture requires intact validator-owned source inventory and applied seals.

use super::{
    native_capture_fixture::{
        seal_native_source, with_native_capture_quota_source, with_native_capture_source,
    },
    tests::{
        apply_source, cache_canonical_test_transaction_set, delta, header, recorded_block, state,
    },
    *,
};
use iroha_data_model::fastpq::TransferTranscript;
use iroha_model_base::topology::LaneId;
use iroha_test_samples::ALICE_ID;

fn assert_no_cached_capture(block: &mut StateBlock<'_>) {
    assert!(block.exec_witness.is_none());
    assert!(block.fastpq_witness_context.is_none());
    assert!(block.parliament_timed_ovn_casting_bindings.is_none());
    assert!(block.take_exec_witness().is_none());
    assert!(block.take_fastpq_witness_context().is_none());
    assert!(block.take_parliament_timed_ovn_casting_bindings().is_none());
}

/// Witness, FASTPQ context and casting bindings, each exercised as the first extraction.
const CAPTURE_EXTRACTION_ORDERS: [[usize; 3]; 6] = [
    [0, 1, 2],
    [0, 2, 1],
    [1, 0, 2],
    [1, 2, 0],
    [2, 0, 1],
    [2, 1, 0],
];

fn cached_output_presence(block: &StateBlock<'_>) -> [bool; 3] {
    [
        block.exec_witness.is_some(),
        block.fastpq_witness_context.is_some(),
        block.parliament_timed_ovn_casting_bindings.is_some(),
    ]
}

fn take_capture_output(block: &mut StateBlock<'_>, output: usize) -> bool {
    match output {
        0 => block.take_exec_witness().is_some(),
        1 => block.take_fastpq_witness_context().is_some(),
        2 => block.take_parliament_timed_ovn_casting_bindings().is_some(),
        _ => unreachable!("only the three capture outputs have extraction accessors"),
    }
}

/// Inject an explicit post-seal source fault into the actual carrier's private
/// accumulator. This grants no execution owner and invokes no apply bypass;
/// all assertions below require the original sealed carrier to reject it.
fn inject_late_source_capture(block: &mut StateBlock<'_>, hash: Hash) {
    assert!(matches!(
        block.execution_output_plan,
        Some(super::super::output_capacity::ExecutionOutputPlanState::Sealed(_))
    ));
    let captured = block
        .fastpq_source_context
        .as_ref()
        .unwrap()
        .capture_transcript(
            Some(hash),
            hash,
            None,
            Some(DataSpaceId::UNIVERSAL),
            block.committed_fragment_count(),
        );
    block.fastpq_source_captures.record(captured);
    assert_eq!(
        block.fastpq_source_captures.sealed_sources().unwrap_err(),
        crate::fastpq::FastpqSourceCaptureError::AppliedAfterSeal,
    );
    let delta = delta();
    let poseidon_preimage_digest = crate::fastpq::poseidon_preimage_digest(&delta, &hash);
    let transcript = TransferTranscript {
        batch_hash: hash,
        deltas: vec![delta],
        authority_digest: crate::fastpq::authority_digest(&ALICE_ID),
        poseidon_preimage_digest: Some(poseidon_preimage_digest),
    };
    assert!(
        block
            .fastpq_transcripts
            .insert(hash, vec![transcript])
            .is_none()
    );
}

fn cache_transfer_capture(
    block: &mut StateBlock<'_>,
    source: &mut iroha_data_model::block::SignedBlock,
) {
    seal_native_source(block, source).unwrap();
    block.capture_exec_witness().unwrap();
    assert_eq!(cached_output_presence(block), [true; 3]);
}

#[test]
fn missing_or_failed_inventory_refuses_capture_before_draining_active_witness() {
    let state = state();
    for failed_inventory in [false, true] {
        let (mut block, _recording) = recorded_block(&state, header());
        cache_canonical_test_transaction_set(&mut block, &[]);
        let hash = Hash::new(b"capture requires owned inventory");
        apply_source(&mut block, hash, false, None);
        let construction_error = if failed_inventory {
            block.fastpq_transcripts.get_mut(&hash).unwrap().clear();
            Some(
                block
                    .finalize_fastpq_source_inventory(&[], &[], &[])
                    .unwrap_err(),
            )
        } else {
            None
        };
        let original_archive = block.fastpq_transcripts.clone();
        let capture_error = block.capture_exec_witness().unwrap_err();
        if let Some(expected) = construction_error {
            assert_eq!(block.fastpq_source_inventory(), Err(expected.as_str()));
            assert_eq!(
                capture_error,
                "FASTPQ witness capture refuses a poisoned carrier"
            );
        } else {
            assert!(capture_error.contains("no finalized owned inventory"));
        }
        assert_no_cached_capture(&mut block);
        assert_eq!(block.fastpq_transcripts, original_archive);
        let active = crate::exec_witness::drain_exec_witness();
        assert_eq!(active.fastpq_transcripts.len(), 1);
        assert_eq!(active.fastpq_transcripts[0].entry_hash, hash);
    }
}

#[test]
fn sealed_empty_and_transferred_inventory_capture_without_reconstruction() {
    for with_transfer in [false, true] {
        with_native_capture_source(
            with_transfer,
            |_state, mut block, _recording, mut native_source, _hash| {
                seal_native_source(&mut block, &mut native_source).unwrap();
                let owned = block
                    .verified_fastpq_source_inventory_for_capture()
                    .unwrap();
                let retained = block
                    .fastpq_source_inventory
                    .as_ref()
                    .unwrap()
                    .as_ref()
                    .unwrap();
                assert!(Arc::ptr_eq(&owned, retained));
                let archive = native_source.fastpq_transcripts().clone();
                assert!(block.fastpq_transcripts.is_empty());
                assert_eq!(archive.len(), usize::from(with_transfer));
                block.capture_exec_witness().unwrap();
                let witness = block.exec_witness.as_ref().unwrap();
                assert_eq!(witness.fastpq_transcripts.len(), usize::from(with_transfer));
                if with_transfer {
                    let context = block.fastpq_witness_context.as_ref().unwrap();
                    assert!(Arc::ptr_eq(
                        context._source_inventory.as_ref().unwrap(),
                        &owned
                    ));
                    assert_eq!(context.tx_set_hash, Some(owned.tx_set_hash()));
                } else {
                    assert_eq!(owned.entries().len(), 1);
                    assert!(owned.transcript_entry_hashes().is_empty());
                    assert!(block.fastpq_witness_context.is_none());
                }
                // A repeated capture still checks the applied seal while preserving the cached witness.
                block.capture_exec_witness().unwrap();
                assert!(block.exec_witness.is_some());
                assert!(Arc::ptr_eq(
                    &block
                        .verified_fastpq_source_inventory_for_capture()
                        .unwrap(),
                    &owned,
                ));
            },
        );
    }
}

#[test]
fn same_or_new_key_late_apply_refuses_capture_even_after_late_data_is_drained() {
    for same_key in [false, true] {
        for drain_late in [false, true] {
            with_native_capture_source(
                true,
                |_state, mut block, _recording, mut native_source, original_hash| {
                    seal_native_source(&mut block, &mut native_source).unwrap();
                    let owned = block
                        .verified_fastpq_source_inventory_for_capture()
                        .unwrap();

                    let late_hash = if same_key {
                        original_hash
                    } else {
                        Hash::new(b"late new source")
                    };
                    inject_late_source_capture(&mut block, late_hash);
                    if drain_late {
                        let drained = block.drain_transfer_transcripts_with_pending(None);
                        assert_eq!(drained.len(), 1);
                        assert!(drained.contains_key(&late_hash));
                        assert!(block.fastpq_transcripts.is_empty());
                    }
                    assert!(
                        block
                            .verified_fastpq_source_inventory_for_capture()
                            .is_err()
                    );
                    assert!(block.capture_exec_witness().is_err());
                    assert_no_cached_capture(&mut block);
                    // Draining or retrying cannot turn a late applied occurrence into a valid seal.
                    block.drain_transfer_transcripts_with_pending(None);
                    assert!(block.capture_exec_witness().is_err());
                    assert_eq!(
                        block.fastpq_source_inventory().unwrap(),
                        Some(owned.as_ref())
                    );
                },
            );
        }
    }
}

#[test]
fn rolled_back_transfer_and_empty_apply_preserve_sealed_capture() {
    with_native_capture_source(
        true,
        |_state, mut block, _recording, mut native_source, original_hash| {
            // Empty application is permitted before the completed output seal.
            // Applying any transaction after Sealed correctly poisons the carrier.
            block.transaction().apply();
            seal_native_source(&mut block, &mut native_source).unwrap();
            let owned = block
                .verified_fastpq_source_inventory_for_capture()
                .unwrap();

            {
                let witness_overlay = crate::exec_witness::begin_exec_witness_overlay();
                let mut tx = block.transaction();
                tx.tx_call_hash = Some(original_hash);
                // Reuse the actual frozen lane; this test exercises rollback of valid
                // speculative capture, not malformed routing (which poisons immediately).
                tx.current_lane_id = Some(LaneId::SINGLE);
                tx.record_test_transfer_transcripts(&ALICE_ID, original_hash, vec![delta()]);
                // Transaction rollback discards the unapplied source capture. The recorder
                // overlay separately discards its speculative raw transcript, preserving
                // the finalized global archive copied before this rollback-only attempt.
                drop(tx);
                drop(witness_overlay);
            }
            assert!(block.fastpq_transcripts.is_empty());
            assert!(Arc::ptr_eq(
                &block
                    .verified_fastpq_source_inventory_for_capture()
                    .unwrap(),
                &owned,
            ));
            block.capture_exec_witness().unwrap();
            assert!(block.exec_witness.is_some());
        },
    );
}

#[test]
fn later_applied_transfer_invalidates_and_clears_previously_cached_capture() {
    with_native_capture_source(
        true,
        |_state, mut block, _recording, mut native_source, hash| {
            seal_native_source(&mut block, &mut native_source).unwrap();

            block.capture_exec_witness().unwrap();
            assert!(block.exec_witness.is_some());
            assert!(block.fastpq_witness_context.is_some());
            inject_late_source_capture(&mut block, hash);
            block.drain_transfer_transcripts_with_pending(None);
            assert!(block.capture_exec_witness().is_err());
            assert_no_cached_capture(&mut block);
            assert!(block.capture_exec_witness().is_err());
            assert_no_cached_capture(&mut block);
        },
    );
}

#[test]
fn capture_rejects_unsealed_replaced_contexts_and_changed_source_caches() {
    for mutation in 0..8 {
        with_native_capture_source(
            true,
            |_state, mut block, _recording, mut native_source, hash| {
                seal_native_source(&mut block, &mut native_source).unwrap();

                match mutation {
                    0 => {
                        block.fastpq_source_captures =
                            crate::fastpq::FastpqSourceCaptureAccumulator::default()
                    }
                    1 => block.fastpq_source_context = None,
                    2 => {
                        Arc::make_mut(block.fastpq_source_context.as_mut().unwrap())
                            .source
                            .height += 1;
                    }
                    3 => block.fastpq_tx_set_hash = Some([42; 32]),
                    4 => block.fastpq_entry_dataspaces.clear(),
                    5 => {
                        block
                            .fastpq_entry_dataspaces
                            .insert(hash, DataSpaceId::new(23));
                    }
                    6 | 7 => {
                        let replacement_hash = if mutation == 6 {
                            Hash::new(b"replacement sealed key")
                        } else {
                            hash
                        };
                        let captured = block
                            .fastpq_source_context
                            .as_ref()
                            .unwrap()
                            .capture_transcript(
                                // Equal value reconstruction is not new authority: the
                                // retained quota journals own it. Change the actual
                                // source kind under the same key in mutation seven.
                                (mutation == 6).then_some(replacement_hash),
                                replacement_hash,
                                Some(LaneId::SINGLE),
                                Some(DataSpaceId::UNIVERSAL),
                                0,
                            );
                        let mut replacement =
                            crate::fastpq::FastpqSourceCaptureAccumulator::default();
                        replacement.record(captured);
                        replacement.seal().unwrap();
                        block.fastpq_source_captures = replacement;
                    }
                    _ => unreachable!(),
                }
                assert!(
                    block
                        .verified_fastpq_source_inventory_for_capture()
                        .is_err(),
                    "mutation {mutation}"
                );
                assert!(block.capture_exec_witness().is_err(), "mutation {mutation}");
                assert_no_cached_capture(&mut block);
            },
        );
    }
}

#[test]
fn applied_accumulator_seal_failure_publishes_no_owned_inventory_or_caches() {
    let state = state();
    let (mut block, _recording) = recorded_block(&state, header());
    cache_canonical_test_transaction_set(&mut block, &[]);
    apply_source(
        &mut block,
        Hash::new(b"already sealed captures"),
        false,
        None,
    );
    block.fastpq_source_captures.seal().unwrap();
    let error = block
        .finalize_fastpq_source_inventory(&[], &[], &[])
        .unwrap_err();
    assert_eq!(block.fastpq_source_inventory(), Err(error.as_str()));
    assert_eq!(
        block.fastpq_tx_set_hash,
        Some(
            iroha_data_model::nexus::axt_ordered_transaction_set_digest_v1(std::iter::empty::<
                &TransactionEntrypoint,
            >(),)
            .unwrap()
            .into()
        )
    );
    assert!(block.fastpq_entry_dataspaces.is_empty());
    assert_eq!(
        block
            .verified_fastpq_source_inventory_for_capture()
            .unwrap_err(),
        "FASTPQ witness capture refuses a poisoned carrier"
    );
    assert_eq!(block.fastpq_source_inventory(), Err(error.as_str()));
}

#[test]
fn unowned_capture_rejects_without_consuming_the_active_recorder() {
    let state = state();
    for failed_inventory in [false, true] {
        let (mut block, _recording) = recorded_block(&state, header());
        cache_canonical_test_transaction_set(&mut block, &[]);
        apply_source(&mut block, Hash::new(b"replay active witness"), false, None);
        if failed_inventory {
            block.fastpq_source_inventory = Some(Err("retained local construction error".into()));
        }
        let original_inventory = block.fastpq_source_inventory.clone();
        assert!(block.capture_exec_witness().is_err());
        assert_no_cached_capture(&mut block);
        assert_eq!(block.fastpq_source_inventory, original_inventory);
        let active = crate::exec_witness::drain_exec_witness();
        assert!(active.reads.is_empty());
        assert!(active.writes.is_empty());
        assert!(!active.fastpq_transcripts.is_empty());
    }
}

#[test]
fn intact_capture_outputs_can_be_taken_in_every_order_without_recapture() {
    for order in CAPTURE_EXTRACTION_ORDERS {
        with_native_capture_source(
            true,
            |_state, mut block, _recording, mut native_source, _hash| {
                cache_transfer_capture(&mut block, &mut native_source);
                let mut expected_presence = [true; 3];
                for output in order {
                    assert!(
                        take_capture_output(&mut block, output),
                        "order {order:?}, output {output}"
                    );
                    expected_presence[output] = false;
                    assert_eq!(cached_output_presence(&block), expected_presence);
                }
                assert_no_cached_capture(&mut block);
                assert!(block.verified_fastpq_source_inventory_for_capture().is_ok());
            },
        );
    }
}

#[test]
fn each_extraction_accessor_first_rejects_late_applies_without_recapture() {
    for same_key in [false, true] {
        for order in CAPTURE_EXTRACTION_ORDERS {
            with_native_capture_source(
                true,
                |_state, mut block, _recording, mut native_source, original| {
                    cache_transfer_capture(&mut block, &mut native_source);
                    let late = if same_key {
                        original
                    } else {
                        Hash::new(b"late source before direct extraction")
                    };
                    inject_late_source_capture(&mut block, late);
                    let late_archive = block.drain_transfer_transcripts_with_pending(None);
                    assert!(late_archive.contains_key(&late));
                    assert!(block.fastpq_transcripts.is_empty());
                    // All stale outputs are still present. The first getter must invalidate them
                    // without relying on a second capture or on any particular extraction order.
                    assert_eq!(cached_output_presence(&block), [true; 3]);
                    for output in order {
                        assert!(
                            !take_capture_output(&mut block, output),
                            "same_key {same_key}, order {order:?}, output {output}"
                        );
                        assert_eq!(cached_output_presence(&block), [false; 3]);
                    }
                    assert_no_cached_capture(&mut block);
                    assert!(
                        block
                            .verified_fastpq_source_inventory_for_capture()
                            .is_err()
                    );
                },
            );
        }
    }
}

#[test]
fn repeat_capture_preserves_original_cached_outputs() {
    for order in CAPTURE_EXTRACTION_ORDERS {
        with_native_capture_source(
            true,
            |_state, mut block, _recording, mut native_source, _hash| {
                cache_transfer_capture(&mut block, &mut native_source);
                let original_inventory = block.fastpq_source_inventory.clone();
                block.capture_exec_witness().unwrap();
                assert_eq!(cached_output_presence(&block), [true; 3]);
                let mut remaining = [true; 3];
                for output in order {
                    assert!(take_capture_output(&mut block, output), "order {order:?}");
                    remaining[output] = false;
                    assert_eq!(cached_output_presence(&block), remaining);
                }
                assert_eq!(block.fastpq_source_inventory, original_inventory);
                let active = crate::exec_witness::drain_exec_witness();
                assert!(active.reads.is_empty());
                assert!(active.writes.is_empty());
                assert!(active.fastpq_transcripts.is_empty());
            },
        );
    }
}

#[test]
fn original_quota_custody_rejects_same_value_applied_ordinary_and_mandatory_replacements() {
    for protocol in [false, true] {
        for order in CAPTURE_EXTRACTION_ORDERS {
            with_native_capture_quota_source(
                protocol,
                |_state, mut block, _recording, mut native_source, hash| {
                    seal_native_source(&mut block, &mut native_source).unwrap();
                    block.capture_exec_witness().unwrap();
                    assert_eq!(cached_output_presence(&block), [true; 3]);
                    let bundle = block.exec_witness.as_ref().unwrap().fastpq_transcripts[0]
                        .transcripts
                        .clone();
                    let before = block.fastpq_source_usage_for_testing();
                    let quota = block
                        .fastpq_source_quota
                        .as_mut()
                        .unwrap()
                        .as_mut()
                        .unwrap();
                    // The original journal applies a replacement and restores every public
                    // quota count. No new State movement or capture is fabricated here.
                    let mut transaction = quota.transaction().unwrap();
                    transaction.authorize_governance_purposes();
                    transaction.replace_entry(hash, protocol, []).unwrap();
                    transaction.replace_entry(hash, protocol, &bundle).unwrap();
                    transaction.commit();
                    assert_eq!(block.fastpq_source_usage_for_testing(), before);
                    assert!(block.fastpq_source_captures.sealed_sources().is_ok());
                    assert_eq!(
                        block.exec_witness.as_ref().unwrap().fastpq_transcripts[0].transcripts,
                        bundle
                    );
                    for output in order {
                        assert!(!take_capture_output(&mut block, output));
                    }
                    assert_no_cached_capture(&mut block);
                    assert!(block.capture_exec_witness().is_err());
                },
            );
        }
    }
}

#[test]
fn original_quota_custody_rejects_equal_reconstruction_and_cannot_recover_after_observation() {
    use crate::fastpq::source_reservation::admission::PreparedSourceQuota;
    use iroha_data_model::fastpq::FastpqSourceExecutionKindV1;

    for order in CAPTURE_EXTRACTION_ORDERS {
        with_native_capture_source(
            true,
            |_state, mut block, _recording, mut native_source, _hash| {
                cache_transfer_capture(&mut block, &mut native_source);
                let inventory = block
                    .verified_fastpq_source_inventory_for_capture()
                    .unwrap();
                let (profile, output_policy) = block.fastpq_source_policy_at_block_start();
                let height = block._curr_block.height().get();
                let scope = Hash::new(
                    norito::encode_canonical(&(block.network_id, height, block._curr_block.hash()))
                        .unwrap(),
                );
                let mut reconstructed = PreparedSourceQuota::new(
                    profile,
                    output_policy,
                    height,
                    scope,
                    profile.maximum_network_inputs(output_policy).unwrap(),
                )
                .unwrap();
                for entry in inventory.entries() {
                    if entry.execution_kind == FastpqSourceExecutionKindV1::ExecutionCall {
                        reconstructed
                            .retain_ordinary_entry(entry.entry_hash)
                            .unwrap();
                    }
                }
                let transcripts: BTreeMap<_, _> = block
                    .exec_witness
                    .as_ref()
                    .unwrap()
                    .fastpq_transcripts
                    .iter()
                    .map(|bundle| (bundle.entry_hash, bundle.transcripts.clone()))
                    .collect();
                let mut transaction = reconstructed.transaction().unwrap();
                transaction.authorize_governance_purposes();
                for entry in inventory.entries() {
                    if let Some(bundle) = transcripts.get(&entry.entry_hash) {
                        transaction
                            .replace_entry(
                                entry.entry_hash,
                                entry.execution_kind
                                    == FastpqSourceExecutionKindV1::ProtocolPurpose,
                                bundle,
                            )
                            .unwrap();
                    }
                }
                transaction.commit();
                reconstructed
                    .reconcile_and_retain(inventory.entries(), &transcripts)
                    .unwrap();
                assert_eq!(
                    (
                        reconstructed.ordinary_usage(),
                        reconstructed.mandatory_usage()
                    ),
                    block.fastpq_source_usage_for_testing()
                );
                let original = block.fastpq_source_quota.replace(Ok(reconstructed));
                assert!(
                    block
                        .verified_fastpq_source_inventory_for_capture()
                        .is_err()
                );
                // Restoring the original allocation after refusal cannot repair the retained
                // State custody latch, even though its entries and counters never changed.
                block.fastpq_source_quota = original;
                assert!(
                    block
                        .verified_fastpq_source_inventory_for_capture()
                        .is_err()
                );
                for output in order {
                    assert!(!take_capture_output(&mut block, output));
                }
                assert_no_cached_capture(&mut block);
                assert!(block.capture_exec_witness().is_err());
            },
        );
    }
}

#[test]
fn original_quota_custody_latches_frozen_policy_and_unavailable_journal_changes() {
    for mutation in 0..3 {
        with_native_capture_source(
            true,
            |_state, mut block, _recording, mut native_source, _hash| {
                cache_transfer_capture(&mut block, &mut native_source);
                if mutation == 0 {
                    let original = block.fastpq_source_policy_at_block_start;
                    block
                        .fastpq_source_policy_at_block_start
                        .as_mut()
                        .unwrap()
                        .0
                        .intrinsic
                        .max_deltas += 1;
                    assert!(
                        block
                            .verified_fastpq_source_inventory_for_capture()
                            .is_err()
                    );
                    block.fastpq_source_policy_at_block_start = original;
                } else {
                    let original = block.fastpq_source_quota.take();
                    if mutation == 2 {
                        block.fastpq_source_quota = Some(Err("replaced failed quota".into()));
                    }
                    assert!(
                        block
                            .verified_fastpq_source_inventory_for_capture()
                            .is_err()
                    );
                    block.fastpq_source_quota = original;
                }
                assert!(
                    block
                        .verified_fastpq_source_inventory_for_capture()
                        .is_err()
                );
                assert!(block.capture_exec_witness().is_err());
                assert_no_cached_capture(&mut block);
            },
        );
    }
}

#[test]
fn genuine_sealed_carrier_refuses_even_empty_late_application_before_state_publication() {
    with_native_capture_source(true, |state, mut block, _recording, mut source, _hash| {
        seal_native_source(&mut block, &mut source).unwrap();
        let original_inventory = Arc::clone(
            block
                .fastpq_source_inventory
                .as_ref()
                .unwrap()
                .as_ref()
                .unwrap(),
        );
        let original_source_wire = source.encode_wire().unwrap();
        let original_fragment_count = block.committed_fragment_count();
        let original_height = state.committed_height();
        block.transaction().apply();
        assert!(matches!(
            block.execution_output_plan,
            Some(super::super::output_capacity::ExecutionOutputPlanState::Poisoned)
        ));
        assert_eq!(block.committed_fragment_count(), original_fragment_count);
        assert!(block.fastpq_transcripts.is_empty());
        assert_eq!(source.encode_wire().unwrap(), original_source_wire);
        assert_eq!(
            block.fastpq_source_inventory().unwrap(),
            Some(original_inventory.as_ref())
        );
        assert_eq!(
            block.capture_exec_witness(),
            Err("FASTPQ witness capture refuses a poisoned carrier".into())
        );
        assert_no_cached_capture(&mut block);
        assert!(matches!(
            block.commit(),
            Err(crate::state::TransactionsBlockError::ExecutionOutputCapacity)
        ));
        assert_eq!(state.committed_height(), original_height);
    });
}
