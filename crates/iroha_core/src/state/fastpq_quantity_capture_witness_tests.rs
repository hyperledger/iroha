//! Genuine completed-source witness backing, exact refusal and original archive lifetime.
use super::*;
use crate::execution_attempt::ExecutionAttemptError;
use iroha_data_model::{
    block::consensus::ExecWitness,
    execution_witness::FASTPQ_ORDINARY_SOURCE_STATEMENTS_WITNESS_KEY_V1 as D7,
    fastpq::{FastpqOrdinarySourceStatementManifestV1, FastpqSourceEffectCoverageV1},
};

#[test]
fn captured_complete_source_keeps_original_graph_and_credits_after_state_drop() {
    // Other Core tests can hold the process-global epoch for arbitrary work.
    // Execute every original witness assertion with the stock isolated harness.
    if crate::unit_test_support::run_in_isolated_harness(
        "state::fastpq_quantity_capture::tests::witness_custody::captured_complete_source_keeps_original_graph_and_credits_after_state_drop",
    ) {
        return;
    }
    // State Cell retirement is separate from this retained witness graph. Hold
    // every State generation fixed while its original final owner is dropped.
    let retirement_pin = crossbeam_epoch::pin();
    let mut retained = None;
    let mut pool = None;
    let mut tape_ptr = std::ptr::null();
    let mut digest = None;
    with_sealed_quantity_source_census(|block, _, _, _| {
        let (manifest, leaves, _) = block.finalized_quantity_source_for_test().unwrap();
        let hash = leaves[0].entry_hash;
        tape_ptr = block.fastpq_quantity_candidate.entries[&hash]
            .effects
            .as_ptr();
        digest = Some(leaves[0].effects_digest);
        let original_pool = block.pipeline_ivm_prepared_cache.execution_budget().clone();
        block.capture_exec_witness().unwrap();
        let witness = block.take_exec_witness().unwrap();
        assert_eq!(witness.manifest(), &manifest);
        assert_eq!(witness.source_entries().len(), 3);
        assert_eq!(witness.leaves().len(), 1);
        assert_eq!(witness.leaves()[0].effect_count, 1);
        assert_eq!(
            witness.manifest().coverage,
            FastpqSourceEffectCoverageV1::Complete
        );
        let entry = witness.quantity_entry(0).unwrap();
        assert_eq!(entry.effects().effects.as_ptr(), tape_ptr);
        assert_eq!(entry.leaf().effects_digest, digest.unwrap());
        assert!(std::ptr::eq(entry.pool(), witness.pool()));
        let writes = witness
            .writes
            .iter()
            .filter(|write| write.key == D7)
            .collect::<Vec<_>>();
        assert_eq!(writes.len(), 1);
        assert_eq!(
            norito::decode_canonical::<FastpqOrdinarySourceStatementManifestV1>(&writes[0].value)
                .unwrap(),
            manifest
        );
        let bytes = norito::encode_canonical(witness.wire()).unwrap();
        assert_eq!(
            norito::decode_canonical::<ExecWitness>(&bytes).unwrap(),
            *witness.wire()
        );
        let reserved = original_pool.reserved_bytes();
        assert!(witness.quantity_entry(1).is_err());
        assert!(witness.quantity_entry(usize::MAX).is_err());
        assert_eq!(original_pool.reserved_bytes(), reserved);
        retained = Some(witness);
        pool = Some(original_pool);
    });
    let witness = retained.unwrap();
    let pool = pool.unwrap();
    assert!(pool.reserved_bytes() > 0);
    assert_eq!(
        witness
            .quantity_entry(0)
            .unwrap()
            .effects()
            .effects
            .as_ptr(),
        tape_ptr
    );
    assert_eq!(
        witness.quantity_entry(0).unwrap().leaf().effects_digest,
        digest.unwrap()
    );
    let with_retired_state_generations = pool.reserved_bytes();
    drop(witness);
    assert!(
        pool.reserved_bytes() < with_retired_state_generations,
        "the final witness refunds its original graph while State retirement stays pinned"
    );
    drop(retirement_pin);
    // Drive the actual grace period before requiring the whole State pool empty.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while pool.reserved_bytes() != 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "original retired State credits remain: {}",
            pool.reserved_bytes(),
        );
        crossbeam_epoch::pin().flush();
        std::thread::yield_now();
    }
    assert_eq!(
        pool.reserved_bytes(),
        0,
        "every original graph allocation is freed before its final retained credit"
    );
}

#[test]
fn witness_d7_backing_refusal_retains_exact_original_pool_and_manifest() {
    with_sealed_quantity_source_census(|block, _, _, _| {
        let expected = block
            .finalized_quantity_source_for_test()
            .unwrap()
            .2
            .to_vec();
        let pool = block.pipeline_ivm_prepared_cache.execution_budget().clone();
        let occupied = pool
            .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
            .unwrap();
        let before = pool.reserved_bytes();
        // This genuine sealed carrier owns the checked recorder archive already.
        let wire = crate::exec_witness::drain_exec_witness();
        let failed = block.retain_quantity_source_witness(wire).unwrap_err();
        let ExecutionAttemptError::Deferred(original) = failed else {
            panic!("physical refusal cannot become a deterministic source verdict")
        };
        let Some(iroha_allocation::AllocationRefusal::Capacity {
            requested_bytes: requested,
            reserved_bytes: reserved,
            limit_bytes: limit,
            ..
        }) = original.allocation_refusal()
        else {
            panic!("the exact finite source pool refusal is retained")
        };
        assert!(*requested > 0);
        assert_eq!(*reserved, before);
        assert_eq!(*limit, pool.limit_bytes());
        assert_eq!(pool.reserved_bytes(), before);
        assert!(block.exec_witness.is_none());
        assert_eq!(
            block.finalized_quantity_source_for_test().unwrap().2,
            expected
        );
        assert_eq!(
            block
                .finalized_quantity_source_for_test()
                .unwrap()
                .0
                .coverage,
            FastpqSourceEffectCoverageV1::Complete
        );
        drop(occupied);
        assert!(
            pool.try_reserve_bytes(*requested).is_ok(),
            "same original source can be admitted after genuine release"
        );
    });
}

#[test]
fn optional_archive_loss_does_not_change_mandatory_witness_d7() {
    with_quantity_source_census_before_seal(
        |block| {
            assert_eq!(block.fastpq_quantity_candidate.issue, None);
            // Offer the optional loss before completion; sealing still has to
            // produce the exact mandatory journal from all three actual sources.
            block.fastpq_quantity_candidate.source_census = QuantitySourceCensusState::Failed;
            block.fastpq_quantity_candidate.issue = Some(QuantityCaptureIssue::Capacity);
        },
        |block, _, _, _, ()| {
            let expected = block
                .finalized_quantity_source_for_test()
                .unwrap()
                .2
                .to_vec();
            block.capture_exec_witness().unwrap();
            let witness = block.take_exec_witness().unwrap();
            assert_eq!(witness.source_entries().len(), 3);
            assert_eq!(
                witness
                    .writes
                    .iter()
                    .find(|write| write.key == D7)
                    .unwrap()
                    .value,
                expected
            );
            assert_eq!(
                witness.manifest().coverage,
                FastpqSourceEffectCoverageV1::Complete
            );
            assert_eq!(
                witness.quantity_entry(0).err(),
                Some(QuantityCaptureIssue::Capacity)
            );
            assert!(witness.verify_source_binding().is_ok());
        },
    );
}

fn with_native_wire(with_transfer: bool, action: impl FnOnce(&mut StateBlock<'_>, ExecWitness)) {
    crate::state::native_capture_fixture::with_native_capture_source(
        with_transfer,
        |_, mut block, _recording, mut source, _| {
            crate::state::native_capture_fixture::seal_native_source(&mut block, &mut source)
                .unwrap();
            let wire = crate::exec_witness::drain_exec_witness();
            action(&mut block, wire);
        },
    );
}

#[test]
fn conditional_publication_moves_exact_archive_and_releases_only_after_recheck() {
    with_native_wire(true, |block, mut wire| {
        let (expected, leaves, _) = block.finalized_quantity_source_for_test().unwrap();
        let original_bundles = wire.fastpq_transcripts.clone();
        let bundle_pointer = wire.fastpq_transcripts.as_ptr();
        let original_writes = wire.writes.len();
        wire.writes.insert(
            0,
            iroha_data_model::block::consensus::ExecKv {
                key: vec![0],
                value: vec![9],
            },
        );
        wire.writes
            .push(iroha_data_model::block::consensus::ExecKv {
                key: vec![255],
                value: vec![8],
            });
        let owner = block.retain_quantity_source_witness(wire).unwrap();
        assert!(owner.verify_current(block).is_ok());
        assert!(block.exec_witness.is_none());
        assert_eq!(owner.manifest(), &expected);
        assert_eq!(owner.leaves(), leaves);
        assert_eq!(owner.fastpq_transcripts, original_bundles);
        assert_eq!(owner.fastpq_transcripts.as_ptr(), bundle_pointer);
        assert_eq!(owner.writes.len(), original_writes + 3);
        assert_eq!(owner.writes.first().unwrap().value, vec![9]);
        assert_eq!(owner.writes.last().unwrap().value, vec![8]);
        let d7 = owner
            .writes
            .iter()
            .filter(|write| write.key == D7)
            .collect::<Vec<_>>();
        assert_eq!(d7.len(), 1);
        assert_eq!(d7[0].value, norito::encode_canonical(&expected).unwrap());
        assert!(owner.quantity_entry(0).is_ok());
        // The move-only owner deliberately provides no raw into_parts escape.
        assert!(owner.verify_current(block).is_ok());
    });
}

#[test]
fn conditional_publication_refuses_existing_family_duplicate_or_unsorted_writes() {
    for keys in [
        vec![vec![0xD7]],
        vec![vec![0xD7, 0]],
        vec![vec![2], vec![2]],
        vec![vec![3], vec![2]],
    ] {
        with_native_wire(true, |block, mut wire| {
            wire.writes = keys
                .into_iter()
                .map(|key| iroha_data_model::block::consensus::ExecKv {
                    key,
                    value: vec![0],
                })
                .collect();
            assert!(block.retain_quantity_source_witness(wire).is_err());
            assert!(block.exec_witness.is_none());
        });
    }
}

#[test]
fn conditional_publication_rejects_each_changed_d7_archive_and_transcript_owner() {
    with_native_wire(true, |block, wire| {
        let mut owner = block.retain_quantity_source_witness(wire).unwrap();
        let before = owner.pool().reserved_bytes();
        for mutation in 0..7 {
            owner.offer_reconstructed_tamper_for_test(|offered| {
                let index = offered
                    .writes
                    .iter()
                    .position(|write| write.key == D7)
                    .unwrap();
                match mutation {
                    0 => offered.writes.clear(),
                    1 => offered.writes[index].value[0] ^= 1,
                    2 => offered.writes[index].key.push(0),
                    3 => offered.writes.push(offered.writes[index].clone()),
                    // The source leaves are immutable; substitute the offered bundle
                    // identity instead of changing an original retained allocation.
                    4 => {
                        offered.fastpq_transcripts[0].entry_hash =
                            iroha_crypto::Hash::new(b"foreign archive")
                    }
                    5 => offered.fastpq_transcripts.clear(),
                    6 => {
                        offered.fastpq_transcripts[0].transcripts[0].authority_digest =
                            iroha_crypto::Hash::new(b"foreign authority")
                    }
                    _ => unreachable!(),
                }
            });
            assert!(owner.verify_current(block).is_err(), "mutation {mutation}");
            assert!(owner.quantity_entry(0).is_err(), "mutation {mutation}");
            assert_eq!(owner.pool().reserved_bytes(), before);
            assert!(block.exec_witness.is_none());
        }
        owner.offer_reconstructed_tamper_for_test(|_| {});
        assert!(owner.verify_current(block).is_ok());
    });
}

#[test]
fn conditional_publication_refuses_context_change_at_last_extraction_boundary() {
    use crate::state::native_capture_fixture::{seal_native_source, with_native_capture_source};

    with_native_capture_source(true, |state, mut block, recording, mut source, _| {
        seal_native_source(&mut block, &mut source).unwrap();
        let wire = crate::exec_witness::drain_exec_witness();
        let owner = block.retain_quantity_source_witness(wire).unwrap();
        let original_header = block._curr_block;
        let inventory = block
            .verified_fastpq_source_inventory_for_capture()
            .unwrap();
        assert!(owner.verify_current(&block).is_ok());
        let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            block._curr_block.creation_time_ms += 1;
        }))
        .expect_err("completed source must refuse a changed context before mutation");
        let reason = refused
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| refused.downcast_ref::<String>().map(String::as_str));
        assert_eq!(
            reason,
            Some("completed execution retains immutable original State")
        );
        assert_eq!(block._curr_block, original_header);
        assert!(Arc::ptr_eq(
            &inventory,
            &block
                .verified_fastpq_source_inventory_for_capture()
                .unwrap()
        ));
        assert!(owner.verify_current(&block).is_ok());
        assert!(block.exec_witness.is_none());

        // A caller can offer a different completed original, but cannot rebind
        // this retained witness to it. Execute the same inputs on the same State
        // with a changed header before acquisition; do not rewrite a sealed cut.
        let mut changed_header = source.header();
        changed_header.creation_time_ms += 1;
        let mut builder = BlockBuilder::new(changed_header);
        for entry in source.external_entrypoints_slice() {
            let iroha_data_model::transaction::TransactionEntrypoint::External(transaction) = entry
            else {
                panic!("the genuine fixture contains only signed external inputs")
            };
            builder.push_transaction(transaction.clone());
        }
        builder.set_execution_context(source.execution_context().cloned());
        let mut changed_source = builder.build_with_signature(0, ALICE_KEYPAIR.private_key());
        assert_ne!(source.hash(), changed_source.hash());
        drop(block);
        drop(recording);
        let (mut changed, _recording) = state
            .block_with_recorded_pristine_carrier_stage(
                &changed_source,
                |_| Ok::<(), String>(()),
                |error| error,
            )
            .unwrap();
        changed
            .reserve_ordinary_execution_outputs(&changed_source)
            .unwrap();
        changed
            .execute_ordinary_output_plan(&changed_source, None)
            .unwrap();
        let rows = changed.retained_execution_outputs_for_test().unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].result().is_ok());
        seal_native_source(&mut changed, &mut changed_source).unwrap();
        let changed_inventory = changed
            .verified_fastpq_source_inventory_for_capture()
            .unwrap();
        assert_eq!(changed_inventory.source(), inventory.source());
        assert_eq!(changed_inventory.entries(), inventory.entries());
        assert!(!Arc::ptr_eq(&changed_inventory, &inventory));
        assert_eq!(
            changed._curr_block.creation_time_ms,
            original_header.creation_time_ms + 1
        );
        assert_eq!(
            owner.verify_current(&changed).unwrap_err(),
            "mandatory finalized quantity source lost original custody or context"
        );
        assert!(changed.exec_witness.is_none());
        assert!(owner.verify_source_binding().is_ok());
    });
}

#[test]
fn conditional_publication_preserves_empty_and_nontransfer_source_entries() {
    for with_transfer in [false, true] {
        with_native_wire(with_transfer, |block, wire| {
            let writes = wire.writes.len();
            let owner = block.retain_quantity_source_witness(wire).unwrap();
            // An idle chain has no manufactured zero-entry block. The genuine Log
            // source is retained even though its complete effect tape is empty.
            assert_eq!(owner.manifest().executed_entry_count, 1);
            assert_eq!(owner.manifest().statement_count, u32::from(with_transfer));
            assert_eq!(owner.source_entries().len(), 1);
            assert_eq!(owner.leaves().len(), usize::from(with_transfer));
            assert_eq!(owner.writes.len(), writes + 1);
            assert!(owner.verify_current(block).is_ok());
            assert!(block.exec_witness.is_none());
        });
    }
}

#[test]
fn conditional_publication_never_accepts_prebuilt_batches_or_incomplete_bundles() {
    for prebuilt in [false, true] {
        with_native_wire(true, |block, mut wire| {
            if prebuilt {
                wire.fastpq_batches
                    .push(iroha_data_model::fastpq::FastpqTransitionBatch {
                        parameter: "unowned prebuilt batch".to_owned(),
                        public_inputs: iroha_data_model::fastpq::FastpqPublicInputs {
                            dsid: [0; 16],
                            slot: 0,
                            old_root: [0; 32],
                            new_root: [0; 32],
                            perm_root: [0; 32],
                            tx_set_hash: [0; 32],
                        },
                        transitions: Vec::new(),
                        metadata: std::collections::BTreeMap::new(),
                    });
            } else {
                wire.fastpq_transcripts.clear();
            }
            assert!(block.retain_quantity_source_witness(wire).is_err());
            assert!(block.exec_witness.is_none());
        });
    }
}

#[test]
fn genuine_complete_effect_openings_keep_whole_entries() {
    use iroha_data_model::fastpq::{
        decode_fastpq_ordinary_source_statement_opening_v1,
        verify_fastpq_ordinary_source_statement_opening_v1,
    };
    for (counts, entry_count, leaf_count, effect_count) in [
        (&[2_usize][..], 1_u32, 1_u32, 2_u32),
        (&[0_usize, 1, 2][..], 3_u32, 2_u32, 3_u32),
    ] {
        crate::state::native_capture_fixture::with_native_capture_sources(
            counts,
            |_, mut block, _recording, mut source, _| {
                crate::state::native_capture_fixture::seal_native_source(&mut block, &mut source)
                    .unwrap();
                block.capture_exec_witness().unwrap();
                let owner = block.take_exec_witness().unwrap();
                assert_eq!(
                    owner.source_entries().len(),
                    usize::try_from(entry_count).unwrap()
                );
                assert_eq!(owner.leaves().len(), usize::try_from(leaf_count).unwrap());
                assert_eq!(
                    owner
                        .leaves()
                        .iter()
                        .map(|leaf| leaf.effect_count)
                        .sum::<u32>(),
                    effect_count
                );
                let bounds = crate::fastpq::FastpqSourceOpeningBuildLimits {
                    max_ordinary_writes: owner.writes.len(),
                    max_ordinary_write_bytes: owner
                        .writes
                        .iter()
                        .map(|write| write.key.len() + write.value.len())
                        .sum(),
                    max_executed_entries: entry_count,
                    max_statements: leaf_count,
                    manifest_decode: norito::DecodeLimits::new(
                        1024,
                        32 * 1024,
                        64 * 1024,
                        512 * 1024,
                        32,
                    ),
                };
                for (index, leaf) in owner.leaves().iter().enumerate() {
                    let (opening, root) =
                        crate::fastpq::fastpq_ordinary_source_statement_opening_v1(
                            owner.wire(),
                            owner.manifest().source,
                            owner.source_entries(),
                            owner.leaves(),
                            u32::try_from(index).unwrap(),
                            bounds,
                        )
                        .unwrap();
                    let frame = norito::encode_canonical(&opening).unwrap();
                    let decoded = decode_fastpq_ordinary_source_statement_opening_v1(
                        &frame,
                        frame.len(),
                        norito::DecodeLimits::new(1024, 32 * 1024, 64 * 1024, 512 * 1024, 32),
                    )
                    .unwrap();
                    assert!(verify_fastpq_ordinary_source_statement_opening_v1(
                        &decoded,
                        leaf,
                        root,
                        entry_count,
                        leaf_count
                    ));
                    assert!(!verify_fastpq_ordinary_source_statement_opening_v1(
                        &decoded,
                        leaf,
                        root,
                        entry_count,
                        0
                    ));
                    for changed in [
                        crate::fastpq::FastpqSourceOpeningBuildLimits {
                            max_statements: 0,
                            ..bounds
                        },
                        crate::fastpq::FastpqSourceOpeningBuildLimits {
                            max_executed_entries: 0,
                            ..bounds
                        },
                    ] {
                        assert!(
                            crate::fastpq::fastpq_ordinary_source_statement_opening_v1(
                                owner.wire(),
                                owner.manifest().source,
                                owner.source_entries(),
                                owner.leaves(),
                                u32::try_from(index).unwrap(),
                                changed
                            )
                            .is_err()
                        );
                    }
                    for mutation in 0..4 {
                        let mut substituted = *leaf;
                        match mutation {
                            0 => substituted.effects_digest[0] ^= 1,
                            1 => substituted.slot += 1,
                            2 => substituted.perm_root[0] ^= 1,
                            3 => substituted.tx_set_hash[0] ^= 1,
                            _ => unreachable!(),
                        }
                        assert!(!verify_fastpq_ordinary_source_statement_opening_v1(
                            &decoded,
                            &substituted,
                            root,
                            3,
                            2
                        ));
                    }
                }
            },
        );
    }
}

#[test]
fn genuine_call_and_protocol_source_openings_preserve_native_kind() {
    use iroha_data_model::fastpq::{
        FastpqSourceExecutionKindV1, verify_fastpq_ordinary_source_statement_opening_v1,
    };
    for protocol in [false, true] {
        crate::state::native_capture_fixture::with_native_capture_quota_source(
            protocol,
            |_, mut block, _recording, mut source, hash| {
                crate::state::native_capture_fixture::seal_native_source(&mut block, &mut source)
                    .unwrap();
                block.capture_exec_witness().unwrap();
                let owner = block.take_exec_witness().unwrap();
                let index = owner
                    .leaves()
                    .iter()
                    .position(|leaf| leaf.entry_hash == hash)
                    .unwrap();
                let leaf = owner.leaves()[index];
                assert_eq!(
                    leaf.execution_kind,
                    if protocol {
                        FastpqSourceExecutionKindV1::ProtocolPurpose
                    } else {
                        FastpqSourceExecutionKindV1::ExecutionCall
                    }
                );
                let entries = u32::try_from(owner.source_entries().len()).unwrap();
                let statements = u32::try_from(owner.leaves().len()).unwrap();
                let limits = crate::fastpq::FastpqSourceOpeningBuildLimits {
                    max_ordinary_writes: owner.writes.len(),
                    max_ordinary_write_bytes: owner
                        .writes
                        .iter()
                        .map(|write| write.key.len() + write.value.len())
                        .sum(),
                    max_executed_entries: entries,
                    max_statements: statements,
                    manifest_decode: norito::DecodeLimits::new(
                        1024,
                        32 * 1024,
                        64 * 1024,
                        512 * 1024,
                        32,
                    ),
                };
                let (opening, root) = crate::fastpq::fastpq_ordinary_source_statement_opening_v1(
                    owner.wire(),
                    owner.manifest().source,
                    owner.source_entries(),
                    owner.leaves(),
                    u32::try_from(index).unwrap(),
                    limits,
                )
                .unwrap();
                assert!(verify_fastpq_ordinary_source_statement_opening_v1(
                    &opening, &leaf, root, entries, statements
                ));
                let mut changed = leaf;
                changed.execution_kind = if protocol {
                    FastpqSourceExecutionKindV1::ExecutionCall
                } else {
                    FastpqSourceExecutionKindV1::ProtocolPurpose
                };
                assert!(!verify_fastpq_ordinary_source_statement_opening_v1(
                    &opening, &changed, root, entries, statements
                ));
            },
        );
    }
}

#[test]
fn optional_archive_pool_refusal_keeps_original_release_owner_through_witness() {
    let mut retained = None;
    with_quantity_source_census_before_seal(
        |block| {
            assert_eq!(block.fastpq_quantity_candidate.issue, None);
            let pool = block.pipeline_ivm_prepared_cache.execution_budget().clone();
            let mut registration = crate::unit_test_support::release_registration(&pool);
            let baseline = pool.reserved_bytes();
            let occupied = pool
                .try_reserve_bytes(pool.limit_bytes() - baseline)
                .unwrap();
            assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
            let issue = QuantityArchiveMap::<u8>::reserve(1, &pool)
                .err()
                .expect("actual optional map refusal");
            let QuantityCaptureIssue::Admission(refusal) = &issue else {
                panic!("original pool cause erased into optional diagnostic: {issue:?}")
            };
            let iroha_allocation::AllocationRefusal::Capacity {
                requested_bytes,
                release,
                ..
            } = refusal
            else {
                panic!("occupied original pool, not immutable geometry")
            };
            let original_refusal = refusal.clone();
            let wait = release.clone();
            let mut task = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(registration.poll_wait(&wait, &mut task).is_pending());
            drop(occupied);
            assert_eq!(pool.reserved_bytes(), baseline);
            // Credits are immediately reusable, but task callbacks remain deferred
            // until the original State writers retire. Keep this exact observation.
            assert!(registration.poll_wait(&wait, &mut task).is_pending());
            let retry = QuantityArchiveMap::<u8>::reserve(1, &pool).unwrap();
            assert!(retry.belongs_to(&pool));
            assert_eq!(
                pool.reserved_bytes(),
                baseline.checked_add(*requested_bytes).unwrap()
            );
            drop(retry);
            assert_eq!(pool.reserved_bytes(), baseline);
            assert!(registration.poll_wait(&wait, &mut task).is_pending());
            block.fastpq_quantity_candidate.source_census = QuantitySourceCensusState::Failed;
            block.fastpq_quantity_candidate.issue = Some(issue);
            (pool, registration, wait, original_refusal)
        },
        |block, _, _, _, (pool, mut registration, wait, original_refusal)| {
            let original = block.finalized_quantity_source_for_test().unwrap().0;
            block.capture_exec_witness().unwrap();
            let witness = block.take_exec_witness().unwrap();
            assert_eq!(witness.source_entries().len(), 3);
            assert_eq!(
                witness.manifest(),
                &original,
                "optional refusal cannot alter canonical D7"
            );
            assert!(witness.verify_source_binding().is_ok());
            let refusal = witness.admit_quantity_archive().err().unwrap();
            assert_eq!(
                refusal,
                QuantityCaptureIssue::Admission(original_refusal.clone())
            );
            assert_eq!(witness.quantity_entry(0).err(), Some(refusal.clone()));
            assert_eq!(block.fastpq_quantity_candidate.issue, Some(refusal));
            let mut task = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(registration.poll_wait(&wait, &mut task).is_pending());
            retained = Some((witness, pool, registration, wait, original_refusal));
        },
    );
    // The normal fixture scope has now dropped its original State and all writers.
    // The captured witness still retains the same typed refusal and source owner.
    let (witness, pool, mut registration, wait, original_refusal) = retained.unwrap();
    assert!(registration.belongs_to(&pool));
    let mut task = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(registration.poll_wait(&wait, &mut task).is_ready());
    assert!(witness.verify_source_binding().is_ok());
    assert_eq!(
        witness.admit_quantity_archive().err(),
        Some(QuantityCaptureIssue::Admission(original_refusal))
    );
}

#[test]
fn optional_archive_keeps_original_oversize_separate_from_pool_capacity() {
    let pool = iroha_allocation::AllocationBudget::new(0);
    let issue = QuantityArchiveMap::<u8>::reserve(1, &pool).err().unwrap();
    assert!(matches!(
        issue,
        QuantityCaptureIssue::Admission(iroha_allocation::AllocationRefusal::ExceedsLimit { .. })
    ));
    assert_eq!(pool.reserved_bytes(), 0);
    assert_ne!(
        issue,
        QuantityCaptureIssue::Capacity,
        "diagnostic geometry is never original pool evidence"
    );
}

#[test]
fn optional_refusal_adapter_never_invents_evidence_for_physical_or_erased_capacity() {
    assert_eq!(
        QuantityCaptureIssue::from_buffer(iroha_allocation::ChargedBufferError::Allocator {
            requested_bytes: 16
        }),
        QuantityCaptureIssue::Capacity
    );
    let original = iroha_allocation::AllocationRefusal::DemandOverflow;
    assert_eq!(
        QuantityCaptureIssue::from_prepaid(iroha_allocation::PrepaidBufferError::Allocation(
            iroha_allocation::ChargedBufferError::Admission(original.clone())
        )),
        QuantityCaptureIssue::Admission(original)
    );
}
