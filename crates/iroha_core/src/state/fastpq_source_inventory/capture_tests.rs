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

/// The completed carrier refuses mutable projection before the offered change runs.
/// Exact inventory, source, quota and previously captured outputs stay owned in place.
fn assert_sealed_mutation_refused(
    block: &mut StateBlock<'_>,
    change: impl FnOnce(&mut StateBlock<'_>),
) {
    let inventory = block
        .verified_fastpq_source_inventory_for_capture()
        .unwrap();
    let context = Arc::clone(block.fastpq_source_context.as_ref().unwrap());
    let captures = block
        .fastpq_source_captures
        .sealed_sources()
        .unwrap()
        .clone();
    let archive = block.fastpq_transcripts.clone();
    let dataspaces = block.fastpq_entry_dataspaces.clone();
    let tx_set = block.fastpq_tx_set_hash;
    let quota = block.fastpq_source_usage_for_testing();
    let policy = block.fastpq_source_policy_at_block_start;
    let fragments = block.committed_fragment_count();
    let outputs = cached_output_presence(block);
    let bundles = block
        .exec_witness
        .as_ref()
        .map(|witness| witness.fastpq_transcripts.clone());
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| change(block)))
        .expect_err("completed carrier must refuse mutable access");
    let reason = panic
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| panic.downcast_ref::<String>().map(String::as_str));
    assert_eq!(
        reason,
        Some("completed execution retains immutable original State")
    );
    assert!(matches!(
        block.execution_output_plan,
        Some(super::super::output_capacity::ExecutionOutputPlanState::Sealed(_))
    ));
    assert!(Arc::ptr_eq(
        &inventory,
        &block
            .verified_fastpq_source_inventory_for_capture()
            .unwrap()
    ));
    assert!(Arc::ptr_eq(
        &context,
        block.fastpq_source_context.as_ref().unwrap()
    ));
    assert_eq!(
        block.fastpq_source_captures.sealed_sources().unwrap(),
        &captures
    );
    assert_eq!(block.fastpq_transcripts, archive);
    assert_eq!(block.fastpq_entry_dataspaces, dataspaces);
    assert_eq!(block.fastpq_tx_set_hash, tx_set);
    assert_eq!(block.fastpq_source_usage_for_testing(), quota);
    assert_eq!(block.fastpq_source_policy_at_block_start, policy);
    assert_eq!(block.committed_fragment_count(), fragments);
    assert_eq!(cached_output_presence(block), outputs);
    assert_eq!(
        block
            .exec_witness
            .as_ref()
            .map(|witness| witness.fastpq_transcripts.clone()),
        bundles
    );
}

/// Offer the same or a new source while preserving the original completed carrier.
fn refuse_late_source_capture(block: &mut StateBlock<'_>, hash: Hash) {
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
    // The accumulator's independent sticky-seal rule remains a live negative control.
    let mut offered = crate::fastpq::FastpqSourceCaptureAccumulator::default();
    offered.seal().unwrap();
    offered.record(captured.clone());
    assert_eq!(
        offered.sealed_sources().unwrap_err(),
        crate::fastpq::FastpqSourceCaptureError::AppliedAfterSeal
    );
    assert_sealed_mutation_refused(block, |block| block.fastpq_source_captures.record(captured));
    let delta = delta();
    let poseidon_preimage_digest = crate::fastpq::poseidon_preimage_digest(&delta, &hash);
    let transcript = TransferTranscript {
        batch_hash: hash,
        deltas: vec![delta],
        authority_digest: crate::fastpq::authority_digest(&ALICE_ID),
        poseidon_preimage_digest: Some(poseidon_preimage_digest),
    };
    assert_sealed_mutation_refused(block, |block| {
        block.fastpq_transcripts.insert(hash, vec![transcript]);
    });
}

/// Inspect original executed sources without acquiring publication authority.
/// The existing producer consumes this scope into Poisoned on every exit.
fn with_original_quota_inspection(protocol: bool, inspect: impl FnOnce(&mut StateBlock<'_>, Hash)) {
    with_native_capture_quota_source(protocol, |_state, mut block, _recording, source, hash| {
        let tx_set = iroha_data_model::nexus::axt_ordered_transaction_set_digest_v1(
            source.external_entrypoints_slice().iter(),
        )
        .unwrap();
        block.set_fastpq_tx_set_hash(tx_set.into());
        block
            .inspect_owned_execution_sources_for_test(&source, |block, sources| {
                block.finalize_fastpq_source_inventory_from(
                    None,
                    |block| block.validate_owned_fastpq_sources(sources),
                    |block, tx_set| block.build_owned_fastpq_source_inventory(sources, tx_set),
                )?;
                inspect(block, hash);
                Ok(())
            })
            .unwrap();
        assert!(matches!(
            block.execution_output_plan,
            Some(super::super::output_capacity::ExecutionOutputPlanState::Poisoned)
        ));
        assert!(block.capture_exec_witness().is_err());
        assert_no_cached_capture(&mut block);
        assert!(matches!(
            block.commit(),
            Err(crate::state::TransactionsBlockError::ExecutionOutputCapacity)
        ));
    });
}

#[test]
fn duplicate_owned_finalization_preserves_original_inventory_phase_and_refusal() {
    for protocol in [false, true] {
        with_native_capture_quota_source(protocol, |_state, mut block, _recording, source, _| {
            let tx_set = iroha_data_model::nexus::axt_ordered_transaction_set_digest_v1(
                source.external_entrypoints_slice().iter(),
            )
            .unwrap();
            block.set_fastpq_tx_set_hash(tx_set.into());
            block
                .inspect_owned_execution_sources_for_test(&source, |block, sources| {
                    // The real source inspection owns this producer's capsule and
                    // seals its canonical inventory, but cannot authorize publication.
                    block.finalize_fastpq_source_inventory_from(
                        None,
                        |block| block.validate_owned_fastpq_sources(sources),
                        |block, tx_set| block.build_owned_fastpq_source_inventory(sources, tx_set),
                    )?;
                    let original = Arc::clone(
                        block
                            .fastpq_source_inventory
                            .as_ref()
                            .unwrap()
                            .as_ref()
                            .unwrap(),
                    );
                    let quota = block.fastpq_source_usage_for_testing();
                    let fragments = block.committed_fragment_count();
                    let archive = block.fastpq_transcripts.clone();
                    let quantity_issue = block.fastpq_quantity_candidate.issue_for_test();
                    let pool = block.pipeline_ivm_prepared_cache.execution_budget().clone();
                    let retained_credit = pool.reserved_bytes();
                    let publication_refusal =
                        block.verify_execution_output_publication().unwrap_err();
                    let capture_refusal = block
                        .verified_fastpq_source_inventory_for_capture()
                        .unwrap_err();
                    block
                        .fastpq_source_quota_seal
                        .as_ref()
                        .unwrap()
                        .verify(block, &original)
                        .unwrap();
                    let error = block
                        .finalize_owned_fastpq_source_inventory_with_pending(sources, None)
                        .unwrap_err();
                    assert!(matches!(
                        error,
                        crate::execution_attempt::ExecutionAttemptError::Rejected(ref reason)
                            if reason == "FASTPQ source inventory has already been finalized"
                    ));
                    assert!(matches!(
                        block.execution_output_plan,
                        Some(super::super::output_capacity::ExecutionOutputPlanState::Inspecting)
                    ));
                    assert!(Arc::ptr_eq(
                        &original,
                        block
                            .fastpq_source_inventory
                            .as_ref()
                            .unwrap()
                            .as_ref()
                            .unwrap()
                    ));
                    block
                        .fastpq_source_quota_seal
                        .as_ref()
                        .unwrap()
                        .verify(block, &original)
                        .unwrap();
                    assert_eq!(block.fastpq_source_usage_for_testing(), quota);
                    assert_eq!(block.committed_fragment_count(), fragments);
                    assert_eq!(block.fastpq_transcripts, archive);
                    assert_eq!(
                        block.fastpq_quantity_candidate.issue_for_test(),
                        quantity_issue
                    );
                    assert_eq!(pool.reserved_bytes(), retained_credit);
                    assert_eq!(
                        block.verify_execution_output_publication(),
                        Err(publication_refusal)
                    );
                    assert_eq!(
                        block.verified_fastpq_source_inventory_for_capture(),
                        Err(capture_refusal)
                    );
                    assert_no_cached_capture(block);
                    Ok(())
                })
                .unwrap();
            // The inspection itself remains a consuming, nonpublishable scope.
            assert!(matches!(
                block.execution_output_plan,
                Some(super::super::output_capacity::ExecutionOutputPlanState::Poisoned)
            ));
        });
    }
}

/// Rebuild equal public quota contributions as an independent, nonauthoritative offer.
fn reconstructed_quota(
    block: &StateBlock<'_>,
    inventory: &FastpqSourceInventoryV1,
    transcripts: &BTreeMap<Hash, Vec<TransferTranscript>>,
) -> crate::fastpq::source_reservation::admission::PreparedSourceQuota {
    use crate::fastpq::source_reservation::admission::PreparedSourceQuota;
    use iroha_data_model::fastpq::FastpqSourceExecutionKindV1;
    let (profile, output_policy) = block.fastpq_source_policy_at_block_start();
    let height = block._curr_block.height().get();
    let scope = Hash::new(
        norito::encode_canonical(&(block.network_id, height, block._curr_block.hash())).unwrap(),
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
    let mut transaction = reconstructed.transaction().unwrap();
    transaction.authorize_governance_purposes();
    for entry in inventory.entries() {
        if let Some(bundle) = transcripts.get(&entry.entry_hash) {
            transaction
                .replace_entry(
                    entry.entry_hash,
                    entry.execution_kind == FastpqSourceExecutionKindV1::ProtocolPurpose,
                    bundle,
                )
                .unwrap();
        }
    }
    transaction.commit();
    reconstructed
        .reconcile_and_retain(inventory.entries(), transcripts)
        .unwrap();
    assert_eq!(
        (
            reconstructed.ordinary_usage(),
            reconstructed.mandatory_usage()
        ),
        block.fastpq_source_usage_for_testing()
    );
    reconstructed
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
fn same_or_new_key_late_capture_and_drain_refuse_before_original_source_changes() {
    for same_key in [false, true] {
        for drain_late in [false, true] {
            with_native_capture_source(
                true,
                |_state, mut block, _recording, mut source, original| {
                    seal_native_source(&mut block, &mut source).unwrap();
                    let wire = source.encode_wire().unwrap();
                    let inventory = block
                        .verified_fastpq_source_inventory_for_capture()
                        .unwrap();
                    let late = if same_key {
                        original
                    } else {
                        Hash::new(b"late new source")
                    };
                    refuse_late_source_capture(&mut block, late);
                    if drain_late {
                        assert_sealed_mutation_refused(&mut block, |block| {
                            block.drain_transfer_transcripts_with_pending(None);
                        });
                    }
                    assert!(block.fastpq_transcripts.is_empty());
                    block.capture_exec_witness().unwrap();
                    assert_eq!(cached_output_presence(&block), [true; 3]);
                    assert!(Arc::ptr_eq(
                        &inventory,
                        &block
                            .verified_fastpq_source_inventory_for_capture()
                            .unwrap()
                    ));
                    assert_eq!(source.encode_wire().unwrap(), wire);
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
            // After Sealed, child acquisition is refused before any effect.
            block.transaction().apply();
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
                // the original active archive before its subsequent final seal.
                drop(tx);
                drop(witness_overlay);
            }
            seal_native_source(&mut block, &mut native_source).unwrap();
            let owned = block
                .verified_fastpq_source_inventory_for_capture()
                .unwrap();
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
fn late_transfer_mutation_preserves_previously_captured_original_outputs() {
    with_native_capture_source(true, |_state, mut block, _recording, mut source, hash| {
        cache_transfer_capture(&mut block, &mut source);
        refuse_late_source_capture(&mut block, hash);
        assert_sealed_mutation_refused(&mut block, |block| {
            block.drain_transfer_transcripts_with_pending(None);
        });
        block.capture_exec_witness().unwrap();
        assert_eq!(cached_output_presence(&block), [true; 3]);
        block.capture_exec_witness().unwrap();
        assert_eq!(cached_output_presence(&block), [true; 3]);
    });
}

#[test]
fn sealed_capture_refuses_unsealed_replaced_contexts_and_changed_source_caches() {
    for mutation in 0..8 {
        with_native_capture_source(
            true,
            |_state, mut block, _recording, mut native_source, hash| {
                seal_native_source(&mut block, &mut native_source).unwrap();

                assert_sealed_mutation_refused(&mut block, |block| match mutation {
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
                });
                block.capture_exec_witness().unwrap();
                assert_eq!(
                    cached_output_presence(&block),
                    [true; 3],
                    "mutation {mutation}"
                );
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
fn each_extraction_accessor_preserves_original_after_refused_late_mutation_without_recapture() {
    for same_key in [false, true] {
        for order in CAPTURE_EXTRACTION_ORDERS {
            with_native_capture_source(
                true,
                |_state, mut block, _recording, mut source, original| {
                    cache_transfer_capture(&mut block, &mut source);
                    let late = if same_key {
                        original
                    } else {
                        Hash::new(b"late source before direct extraction")
                    };
                    refuse_late_source_capture(&mut block, late);
                    assert_sealed_mutation_refused(&mut block, |block| {
                        block.drain_transfer_transcripts_with_pending(None);
                    });
                    assert!(block.fastpq_transcripts.is_empty());
                    assert_eq!(cached_output_presence(&block), [true; 3]);
                    let mut remaining = [true; 3];
                    for output in order {
                        assert!(
                            take_capture_output(&mut block, output),
                            "same_key {same_key}, order {order:?}, output {output}"
                        );
                        remaining[output] = false;
                        assert_eq!(cached_output_presence(&block), remaining);
                    }
                    assert_no_cached_capture(&mut block);
                    assert!(block.verified_fastpq_source_inventory_for_capture().is_ok());
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
fn sealed_quota_refuses_same_value_ordinary_and_mandatory_replacements() {
    for protocol in [false, true] {
        for order in CAPTURE_EXTRACTION_ORDERS {
            with_native_capture_quota_source(
                protocol,
                |_state, mut block, _recording, mut source, hash| {
                    cache_transfer_capture(&mut block, &mut source);
                    let bundle = block.exec_witness.as_ref().unwrap().fastpq_transcripts[0]
                        .transcripts
                        .clone();
                    assert_sealed_mutation_refused(&mut block, |block| {
                        let quota = block
                            .fastpq_source_quota
                            .as_mut()
                            .unwrap()
                            .as_mut()
                            .unwrap();
                        let mut transaction = quota.transaction().unwrap();
                        transaction.authorize_governance_purposes();
                        transaction.replace_entry(hash, protocol, []).unwrap();
                        transaction.replace_entry(hash, protocol, &bundle).unwrap();
                        transaction.commit();
                    });
                    assert_eq!(
                        block.exec_witness.as_ref().unwrap().fastpq_transcripts[0].transcripts,
                        bundle
                    );
                    for output in order {
                        assert!(take_capture_output(&mut block, output));
                    }
                    assert_no_cached_capture(&mut block);
                },
            );
        }
    }
}

#[test]
fn inspected_original_quota_latches_same_value_ordinary_and_mandatory_replacements() {
    for protocol in [false, true] {
        with_original_quota_inspection(protocol, |block, hash| {
            let inventory = Arc::clone(
                block
                    .fastpq_source_inventory
                    .as_ref()
                    .unwrap()
                    .as_ref()
                    .unwrap(),
            );
            let bundle = block.fastpq_transcripts[&hash].clone();
            let before = block.fastpq_source_usage_for_testing();
            block
                .fastpq_source_quota_seal
                .as_ref()
                .unwrap()
                .verify(block, &inventory)
                .unwrap();
            let quota = block
                .fastpq_source_quota
                .as_mut()
                .unwrap()
                .as_mut()
                .unwrap();
            let mut transaction = quota.transaction().unwrap();
            transaction.authorize_governance_purposes();
            transaction.replace_entry(hash, protocol, []).unwrap();
            transaction.replace_entry(hash, protocol, &bundle).unwrap();
            transaction.commit();
            assert_eq!(block.fastpq_source_usage_for_testing(), before);
            assert!(block.fastpq_source_captures.sealed_sources().is_ok());
            assert_eq!(block.fastpq_transcripts[&hash], bundle);
            assert_eq!(
                block
                    .fastpq_source_quota_seal
                    .as_ref()
                    .unwrap()
                    .verify(block, &inventory),
                Err("FASTPQ source quota ownership changed after inventory finalization".into())
            );
            assert!(
                block
                    .fastpq_source_quota_seal
                    .as_ref()
                    .unwrap()
                    .verify(block, &inventory)
                    .is_err()
            );
        });
    }
}

#[test]
fn sealed_quota_refuses_equal_reconstruction_without_replacing_original_owner() {
    for order in CAPTURE_EXTRACTION_ORDERS {
        with_native_capture_source(true, |_state, mut block, _recording, mut source, _hash| {
            cache_transfer_capture(&mut block, &mut source);
            let inventory = block
                .verified_fastpq_source_inventory_for_capture()
                .unwrap();
            let transcripts: BTreeMap<_, _> = block
                .exec_witness
                .as_ref()
                .unwrap()
                .fastpq_transcripts
                .iter()
                .map(|bundle| (bundle.entry_hash, bundle.transcripts.clone()))
                .collect();
            let reconstructed = reconstructed_quota(&block, &inventory, &transcripts);
            let (profile, output) = block.fastpq_source_policy_at_block_start();
            assert!(!reconstructed.matches_retained(
                &block.fastpq_source_quota_seal.as_ref().unwrap().quota,
                profile,
                output
            ));
            assert_sealed_mutation_refused(&mut block, |block| {
                block.fastpq_source_quota.replace(Ok(reconstructed));
            });
            for output in order {
                assert!(take_capture_output(&mut block, output));
            }
            assert_no_cached_capture(&mut block);
            assert!(Arc::ptr_eq(
                &inventory,
                &block
                    .verified_fastpq_source_inventory_for_capture()
                    .unwrap()
            ));
        });
    }
}

#[test]
fn inspected_original_quota_rejects_equal_reconstruction_and_stays_latched_after_restore() {
    with_original_quota_inspection(false, |block, _hash| {
        let inventory = Arc::clone(
            block
                .fastpq_source_inventory
                .as_ref()
                .unwrap()
                .as_ref()
                .unwrap(),
        );
        let reconstructed = reconstructed_quota(block, &inventory, &block.fastpq_transcripts);
        block
            .fastpq_source_quota_seal
            .as_ref()
            .unwrap()
            .verify(block, &inventory)
            .unwrap();
        let original = block.fastpq_source_quota.replace(Ok(reconstructed));
        assert!(
            block
                .fastpq_source_quota_seal
                .as_ref()
                .unwrap()
                .verify(block, &inventory)
                .is_err()
        );
        block.fastpq_source_quota = original;
        assert!(
            block
                .fastpq_source_quota_seal
                .as_ref()
                .unwrap()
                .verify(block, &inventory)
                .is_err()
        );
        assert_eq!(
            block.fastpq_source_inventory().unwrap(),
            Some(inventory.as_ref())
        );
    });
}

#[test]
fn sealed_quota_refuses_frozen_policy_and_unavailable_journal_substitutions() {
    for mutation in 0..3 {
        with_native_capture_source(true, |_state, mut block, _recording, mut source, _hash| {
            cache_transfer_capture(&mut block, &mut source);
            assert_sealed_mutation_refused(&mut block, |block| match mutation {
                0 => {
                    block
                        .fastpq_source_policy_at_block_start
                        .as_mut()
                        .unwrap()
                        .0
                        .intrinsic
                        .max_deltas += 1
                }
                1 => {
                    block.fastpq_source_quota.take();
                }
                2 => block.fastpq_source_quota = Some(Err("replaced failed quota".into())),
                _ => unreachable!(),
            });
            block.capture_exec_witness().unwrap();
            assert_eq!(cached_output_presence(&block), [true; 3]);
        });
    }
}

#[test]
fn inspected_original_quota_latches_frozen_policy_and_unavailable_journal_changes() {
    for mutation in 0..3 {
        with_original_quota_inspection(false, |block, _hash| {
            let inventory = Arc::clone(
                block
                    .fastpq_source_inventory
                    .as_ref()
                    .unwrap()
                    .as_ref()
                    .unwrap(),
            );
            block
                .fastpq_source_quota_seal
                .as_ref()
                .unwrap()
                .verify(block, &inventory)
                .unwrap();
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
                        .fastpq_source_quota_seal
                        .as_ref()
                        .unwrap()
                        .verify(block, &inventory)
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
                        .fastpq_source_quota_seal
                        .as_ref()
                        .unwrap()
                        .verify(block, &inventory)
                        .is_err()
                );
                block.fastpq_source_quota = original;
            }
            assert!(
                block
                    .fastpq_source_quota_seal
                    .as_ref()
                    .unwrap()
                    .verify(block, &inventory)
                    .is_err()
            );
        });
    }
}

#[test]
fn genuine_sealed_carrier_refuses_even_empty_late_transaction_acquisition() {
    with_native_capture_source(true, |state, mut block, _recording, mut source, _hash| {
        seal_native_source(&mut block, &mut source).unwrap();
        let original_inventory = block
            .verified_fastpq_source_inventory_for_capture()
            .unwrap();
        let wire = source.encode_wire().unwrap();
        let fragments = block.committed_fragment_count();
        let height = state.committed_height();
        assert_sealed_mutation_refused(&mut block, |block| block.transaction().apply());
        assert_eq!(block.committed_fragment_count(), fragments);
        assert!(block.fastpq_transcripts.is_empty());
        assert_eq!(source.encode_wire().unwrap(), wire);
        assert_eq!(
            block.fastpq_source_inventory().unwrap(),
            Some(original_inventory.as_ref())
        );
        block.capture_exec_witness().unwrap();
        assert_eq!(cached_output_presence(&block), [true; 3]);
        // A sealed source is still not certified/finalized publication authority.
        assert!(matches!(
            block.commit(),
            Err(crate::state::TransactionsBlockError::ExecutionOutputCapacity)
        ));
        assert_eq!(state.committed_height(), height);
    });
}
