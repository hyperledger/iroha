//! Actual native-tip certificate reads and independent quorum/availability refusals.

use super::*;
use iroha_data_model::query::error::QueryExecutionFail;

#[test]
fn ascending_native_continuation_charges_one_reverse_and_one_forward_source_pass() {
    let (chain, _) = chain();
    let view = chain.state().view();
    for start in [2_usize, 4] {
        let expected_heights: Vec<_> = std::iter::once(1_u64)
            .chain((start as u64 - 1..=chain.height()).rev())
            .chain(start as u64..=chain.height())
            .collect();
        let expected_bytes: u64 = expected_heights
            .iter()
            .map(|height| frame(&chain, *height).encode_wire().unwrap().len() as u64)
            .sum();
        let mut frames_left = expected_heights.len() as u64;
        let mut bytes_left = expected_bytes;
        let mut admit = |count, length| {
            frames_left = frames_left.checked_sub(count).ok_or(
                crate::execution_attempt::ExecutionAttemptError::Deferred(
                    ivm::error::ExecutionDeferral::CanonicalHistoryCapacity.into(),
                ),
            )?;
            bytes_left = bytes_left.checked_sub(length).ok_or(
                crate::execution_attempt::ExecutionAttemptError::Deferred(
                    ivm::error::ExecutionDeferral::CanonicalHistoryCapacity.into(),
                ),
            )?;
            Ok(())
        };
        chain.kura().reset_canonical_query_reads_for_test();
        let reader = CertifiedChain::new_with_source_admission(&view, &mut admit).unwrap();
        let (result, relations) = relation_counts::measure(|| {
            reader
                .walk_from_execution(
                    NonZeroUsize::new(start).unwrap(),
                    NonZeroUsize::new(chain.height() as usize).unwrap(),
                    &mut admit,
                )
                .collect::<Result<Vec<_>, _>>()
        });
        let blocks = result.unwrap();
        assert_eq!(
            blocks
                .iter()
                .map(|block| block.height())
                .collect::<Vec<_>>(),
            (start as u64..=chain.height()).collect::<Vec<_>>()
        );
        assert_eq!(
            relations.qcs,
            (start as u64..=chain.height()).collect::<Vec<_>>()
        );
        assert_eq!((frames_left, bytes_left), (0, 0));
        assert_eq!(
            chain.kura().canonical_query_reads_for_test(),
            (expected_heights.len(), expected_bytes)
        );
    }
}

#[test]
fn ascending_native_continuation_refuses_changed_source_and_stops_after_failure() {
    let (chain, _) = chain();
    let view = chain.state().view();
    let reader = CertifiedChain::new_with_source_admission(&view, |_, _| Ok(())).unwrap();
    let mut walk = reader.walk_from_execution(
        NonZeroUsize::new(4).unwrap(),
        NonZeroUsize::new(5).unwrap(),
        |_, _| Ok(()),
    );
    assert_eq!(walk.next().unwrap().unwrap().height(), 4);
    chain
        .kura()
        .corrupt_native_frame_for_test(NonZeroUsize::new(5).unwrap());
    assert!(walk.next().unwrap().is_err());
    assert!(walk.next().is_none());
    chain
        .kura()
        .corrupt_native_frame_for_test(NonZeroUsize::new(5).unwrap());
    chain.kura().reset_canonical_query_reads_for_test();
    let mut refused = reader.walk_from_execution(
        NonZeroUsize::new(4).unwrap(),
        NonZeroUsize::new(5).unwrap(),
        |_, _| {
            Err(crate::execution_attempt::ExecutionAttemptError::Deferred(
                ivm::error::ExecutionDeferral::CanonicalHistoryCapacity.into(),
            ))
        },
    );
    assert!(matches!(
        refused.next(),
        Some(Err(
            crate::execution_attempt::ExecutionAttemptError::Deferred(_)
        ))
    ));
    assert!(refused.next().is_none());
    assert_eq!(chain.kura().canonical_query_reads_for_test(), (0, 0));
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 128);
    assert!(matches!(
        norito::core::with_decode_limits_scope(limits, || reader
            .walk_from_execution(
                NonZeroUsize::new(4).unwrap(),
                NonZeroUsize::new(5).unwrap(),
                |_, _| Ok(())
            )
            .next()),
        Some(Err(
            crate::execution_attempt::ExecutionAttemptError::Deferred(_)
        ))
    ));
}

#[test]
fn ascending_native_continuation_refuses_same_proposal_changed_result_before_first_yield() {
    let (chain, _) = chain();
    let original = frame(&chain, 4);
    let changed = with_parts(&original, |_, qc, preimage| {
        let (original_x, mut result) = fixture_result_parts(preimage);
        result.execution.world_state_root =
            Hash::new(b"different quorum-certified execution result");
        *preimage = fixture_result_preimage(&original_x, &result);
        *qc = chain.commit_qc(
            4,
            qc.block_hash,
            result_of_preimage(preimage).unwrap(),
            Signers::Quorum,
        );
    });
    assert_eq!(changed.hash(), original.hash());
    let view = chain.state().view();
    let reader = CertifiedChain::new(&view).unwrap();
    let candidate = reader
        .verify_executed_successor(
            &chain.committed(3),
            read_frame(changed.clone(), 4, chain.root_scope()).unwrap(),
        )
        .expect("genuine quorum over the same proposal and a different result");
    assert_eq!(candidate.block_hash(), chain.committed(4).block_hash());
    assert_ne!(candidate.result(), chain.committed(4).result());
    let original_wire = original.encode_wire().unwrap();
    let changed_wire = changed.encode_wire().unwrap();
    assert_eq!(original_wire.len(), changed_wire.len());
    let path = Kura::canonical_storage_path(&chain.kura().store_root()).join("blocks.data");
    let original_file = std::fs::read(&path).unwrap();
    let offsets = original_file
        .windows(original_wire.len())
        .enumerate()
        .filter_map(|(at, bytes)| (bytes == original_wire.as_slice()).then_some(at))
        .collect::<Vec<_>>();
    assert_eq!(offsets.len(), 1);
    let mut changed_file = original_file.clone();
    changed_file[offsets[0]..offsets[0] + changed_wire.len()].copy_from_slice(&changed_wire);
    let mut reads = 0;
    let mut walk = reader.walk_from_execution(
        NonZeroUsize::new(4).unwrap(),
        NonZeroUsize::new(5).unwrap(),
        |_, _| {
            reads += 1;
            if reads == 4 {
                // Original reverse ancestry has already captured 5, 4 and parent 3.
                // Replace only R and its genuine QC before the first ascending receipt.
                std::fs::write(&path, &changed_file).unwrap();
            }
            Ok(())
        },
    );
    let result = walk.next();
    assert!(walk.next().is_none());
    drop(walk);
    std::fs::write(&path, original_file).unwrap();
    assert_eq!(reads, 4);
    assert!(
        matches!(result, Some(Err(crate::execution_attempt::ExecutionAttemptError::Rejected(QueryExecutionFail::Conversion(ref reason))))
        if reason == "certificate differs from its original execution result")
    );
}

#[test]
fn ascending_native_genesis_waits_for_genuine_successor_quorum() {
    let (chain, _) = chain();
    let view = chain.state().view();
    let reader = CertifiedChain::new_with_source_admission(&view, |_, _| Ok(())).unwrap();
    let blocks = reader
        .walk_from_execution(NonZeroUsize::MIN, NonZeroUsize::new(2).unwrap(), |_, _| {
            Ok(())
        })
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(blocks[0].verification(), QcVerification::Genesis);
    assert_eq!(blocks[1].verification(), QcVerification::Verified);
    assert!(blocks[1].extends(&blocks[0]));
    chain.corrupt_local_quorum_for_test(2, Signers::BelowQuorum);
    let mut denied =
        reader.walk_from_execution(NonZeroUsize::MIN, NonZeroUsize::new(2).unwrap(), |_, _| {
            Ok(())
        });
    assert!(
        denied.next().unwrap().is_err(),
        "genesis result cannot escape before H2 verification"
    );
    assert!(denied.next().is_none());
}

#[test]
fn ascending_native_continuation_rejects_structural_history_without_original_state_tip() {
    let (chain, _) = chain();
    let frames = (1..=chain.height())
        .map(|height| frame(&chain, height))
        .collect::<Vec<_>>();
    let state = state_with_history(&frames);
    let view = state.view();
    let reader = CertifiedChain::new_with_source_admission(&view, |_, _| Ok(())).unwrap();
    let mut walk = reader.walk_from_execution(
        NonZeroUsize::new(4).unwrap(),
        NonZeroUsize::new(5).unwrap(),
        |_, _| Ok(()),
    );
    assert!(walk.next().unwrap().is_err());
    assert!(walk.next().is_none());
}

#[test]
fn pinned_frame_reader_charges_raw_buffer_once_and_retains_cumulative_scope() {
    let (chain, _) = chain();
    let index = NonZeroUsize::new(4).unwrap();
    let expected = frame(&chain, 4).hash();
    let budget = chain.state().ivm_execution_budget();
    let original = || {
        let source = chain
            .kura()
            .native_frame_read(4, expected)
            .unwrap()
            .unwrap();
        let length = source.wire_len();
        let bytes = source.read(length, &budget).map_err(|_| ())?.ok_or(())?;
        iroha_data_model::block::decode_framed_signed_block(&bytes).map_err(|_| ())
    };
    let accepts = |limit| {
        norito::core::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, limit, 128),
            || original().is_ok(),
        )
    };
    let mut low = 0;
    let mut high = 64 * 1024 * 1024;
    assert!(accepts(high));
    while low < high {
        let middle = low + (high - low) / 2;
        if accepts(middle) {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    assert!(low > 0);
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, low, 128);
    norito::core::with_decode_limits_scope(limits, || {
        assert!(read_durable_pinned_block(chain.kura(), index, expected, &budget).is_ok());
        assert!(
            read_durable_pinned_block(chain.kura(), index, expected, &budget).is_err(),
            "second read cannot renew the original allocation budget"
        );
    });
    assert!(
        norito::core::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, low - 1, 128),
            || read_durable_pinned_block(chain.kura(), index, expected, &budget),
        )
        .is_err()
    );
}

#[test]
fn state_certificate_reads_only_target_and_parent_under_exact_source_limits() {
    let (chain, _) = chain();
    let view = chain.state().view();
    let reader = CertifiedChain::new(&view).unwrap();
    for height in [2_u64, 4, 5] {
        let source_count = chain.height() - height + 2;
        let source_bytes = (height - 1..=chain.height())
            .map(|h| frame(&chain, h).encode_wire().unwrap().len() as u64)
            .sum::<u64>();
        for (work, bytes, success) in [
            (source_count, source_bytes, true),
            (source_count - 1, source_bytes, false),
            (source_count, source_bytes - 1, false),
        ] {
            let mut remaining_work = work;
            let mut remaining_bytes = bytes;
            let (result, observed) = relation_counts::measure(|| {
                reader.certified_from_execution(
                    NonZeroUsize::new(height as usize).unwrap(),
                    |work, bytes| {
                        remaining_work = remaining_work.checked_sub(work).ok_or(
                            crate::execution_attempt::ExecutionAttemptError::Deferred(
                                ivm::error::ExecutionDeferral::CanonicalHistoryCapacity.into(),
                            ),
                        )?;
                        remaining_bytes = remaining_bytes.checked_sub(bytes).ok_or(
                            crate::execution_attempt::ExecutionAttemptError::Deferred(
                                ivm::error::ExecutionDeferral::CanonicalHistoryCapacity.into(),
                            ),
                        )?;
                        Ok(())
                    },
                )
            });
            if success {
                assert_eq!(result.unwrap().id(), chain.committed(height).id());
                assert_eq!(remaining_work, 0);
                assert_eq!(remaining_bytes, 0);
                assert_eq!(
                    observed.frames,
                    (height - 1..=chain.height()).rev().collect::<Vec<_>>()
                );
                assert_eq!(observed.qcs, [height]);
            } else {
                assert!(matches!(
                    result,
                    Err(crate::execution_attempt::ExecutionAttemptError::Deferred(_))
                ));
                assert!(observed.qcs.is_empty());
            }
        }
    }
}

#[test]
fn state_certificate_refuses_unanchored_history_and_foreign_source_modes() {
    let (chain, _) = chain();
    let frames = (1..=5)
        .map(|height| frame(&chain, height))
        .collect::<Vec<_>>();
    let hashes = frames.iter().map(|block| block.hash()).collect::<Vec<_>>();
    let unanchored = state_with_history(&frames);
    let view = unanchored.view();
    let reader = CertifiedChain::new(&view).unwrap();
    assert!(
        reader
            .certified_from_execution(NonZeroUsize::new(5).unwrap(), |_, _| Ok(()))
            .is_err()
    );
    let network = chain.network_id();
    let reader = CertifiedChain::from_frames(view.chain_id(), &network, &hashes, &frames).unwrap();
    assert!(
        reader
            .certified_from_execution(NonZeroUsize::new(5).unwrap(), |_, _| Ok(()))
            .is_err()
    );
    let view = chain.state().view();
    let reader = CertifiedChain::new(&view).unwrap();
    assert!(
        reader
            .certified_from_execution(NonZeroUsize::new(1).unwrap(), |_, _| Ok(()))
            .is_err()
    );
    chain
        .kura()
        .corrupt_canonical_body_for_testing(NonZeroUsize::new(4).unwrap())
        .unwrap();
    assert!(
        reader
            .certified_from_execution(NonZeroUsize::new(5).unwrap(), |_, _| Ok(()))
            .is_err()
    );
}

#[test]
fn state_certificate_checks_quorum_and_signed_availability_after_execution_authentication() {
    let (chain, _) = chain();
    let view = chain.state().view();
    let reader = CertifiedChain::new(&view).unwrap();
    let original = frame(&chain, 4);
    let parent = chain.committed(3);
    reader
        .verify_executed_successor(
            &parent,
            read_frame(original.clone(), 4, chain.root_scope()).unwrap(),
        )
        .unwrap();
    let (_, qc) = decode_certificate(original.commit_certificate().unwrap()).unwrap();
    for signers in [Signers::BelowQuorum, Signers::All] {
        let changed = with_parts(&original, |_, target, _| {
            *target = chain.commit_qc(4, qc.block_hash, qc.result, signers);
        });
        assert!(
            reader
                .verify_executed_successor(
                    &parent,
                    read_frame(changed, 4, chain.root_scope()).unwrap()
                )
                .is_err()
        );
    }
    let forged = with_parts(&original, |_, qc, _| qc.agg_sig.0[5] ^= 1);
    assert!(
        reader
            .verify_executed_successor(&parent, read_frame(forged, 4, chain.root_scope()).unwrap())
            .is_err()
    );
    let certificate = original.commit_certificate().unwrap();
    let mut corrupted = certificate.availability().to_vec();
    *corrupted.last_mut().unwrap() ^= 1;
    for availability in [
        Vec::new(),
        corrupted,
        frame(&chain, 3)
            .commit_certificate()
            .unwrap()
            .availability()
            .to_vec(),
    ] {
        let changed = crate::block::reserve_block_for_tests().initialize(
            original.as_ref().clone().with_commit_certificate(Some(
                CommitCertificate::from_untrusted_parts(
                    certificate.consensus_header().to_vec(),
                    certificate.commit_qc().to_vec(),
                    certificate.result_preimage().to_vec(),
                    availability,
                ),
            )),
        );
        assert!(
            read_frame(changed, 4, chain.root_scope())
                .map_err(VerificationReadError::from)
                .and_then(|current| reader.verify_executed_successor(&parent, current))
                .is_err()
        );
    }
}

#[test]
fn state_certificate_verifies_actual_native_npos_boundary() {
    let mut chain = CertifiedTestChain::npos_boundary_fixture();
    chain.commit(Vec::new());
    let view = chain.state().view();
    let reader = CertifiedChain::new(&view).unwrap();
    let result = reader
        .certified_from_execution(NonZeroUsize::new(10).unwrap(), |_, _| Ok(()))
        .unwrap();

    assert!(result.commitment().schedule.boundary.is_some());
    assert_eq!(result.id(), reader.certified(10).unwrap().id());
    let quorum = result.commit_qc().unwrap();
    assert_eq!(
        quorum.signers,
        iroha_sumeragi::types::Bitmap::from_indices(4, [0, 1, 2]).unwrap()
    );

    let original = frame(&chain, 10);
    let parent = chain.committed(9);
    for (signers, expected) in [
        (Signers::BelowQuorum, CertError::TooFewSigners),
        (Signers::All, CertError::TooManySigners),
    ] {
        let changed = with_parts(&original, |_, qc, _| {
            *qc = chain.commit_qc(10, qc.block_hash, qc.result, signers);
        });
        assert!(matches!(
            reader.verify_executed_successor(&parent, read_frame(changed, 10, chain.root_scope()).unwrap()),
            Err(VerificationReadError::Source(ChainReadError::Certificate {
                height: 10,
                error,
            })) if error == expected
        ));
    }
    let forged = with_parts(&original, |_, qc, _| qc.agg_sig.0[8] ^= 1);
    assert!(matches!(
        reader.verify_executed_successor(
            &parent,
            read_frame(forged, 10, chain.root_scope()).unwrap()
        ),
        Err(VerificationReadError::Source(ChainReadError::Certificate {
            height: 10,
            error: CertError::BadSignature,
        }))
    ));
    let current = chain.committed(10);
    let retried = reader
        .verify_executed_successor(&parent, current.clone())
        .unwrap();
    assert_eq!(retried.id(), result.id());
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        retried.block(),
        current.block()
    ));
}

#[test]
fn state_certificate_original_tip_does_not_authorize_a_corrupt_local_quorum() {
    for signers in [Signers::BelowQuorum, Signers::All] {
        let (chain, _) = chain();
        chain.corrupt_local_quorum_for_test(4, signers);
        let view = chain.state().view();
        let reader = CertifiedChain::new(&view).unwrap();
        assert!(
            reader.committed(4).is_ok(),
            "original execution remains intact"
        );
        assert!(
            reader
                .certified_from_execution(NonZeroUsize::new(4).unwrap(), |_, _| Ok(()))
                .is_err()
        );
    }
}

#[test]
fn state_certificate_genesis_admission_precedes_every_body_read() {
    let (chain, _) = chain();
    let view = chain.state().view();
    let expected = frame(&chain, 1);
    let length = expected.encode_wire().unwrap().len() as u64;
    for (work, bytes, allowed) in [
        (0, length, false),
        (1, length - 1, false),
        (1, length, true),
    ] {
        chain.kura().reset_canonical_query_reads_for_test();
        let mut charges = Vec::new();
        let result = CertifiedChain::new_with_source_admission(&view, |count, length| {
            charges.push((count, length));
            if count > work || length > bytes {
                return Err(crate::execution_attempt::ExecutionAttemptError::Deferred(
                    ivm::error::ExecutionDeferral::CanonicalHistoryCapacity.into(),
                ));
            }
            Ok(())
        });
        assert_eq!(charges, [(1, length)]);
        if allowed {
            assert_eq!(result.unwrap().genesis().as_ref(), expected.as_ref());
            assert_eq!(chain.kura().canonical_query_reads_for_test(), (1, length));
        } else {
            assert!(matches!(
                result,
                Err(crate::execution_attempt::ExecutionAttemptError::Deferred(_))
            ));
            assert_eq!(chain.kura().canonical_query_reads_for_test(), (0, 0));
        }
    }
    // An occupied corrupt frame must still be refused before I/O when unpaid,
    // and an admitted read must not substitute the old cached valid genesis.
    chain
        .kura()
        .corrupt_native_frame_for_test(NonZeroUsize::new(1).unwrap());
    chain.kura().reset_canonical_query_reads_for_test();
    assert!(matches!(
        CertifiedChain::new_with_source_admission(&view, |_, _| Err(
            crate::execution_attempt::ExecutionAttemptError::Deferred(
                ivm::error::ExecutionDeferral::CanonicalHistoryCapacity.into()
            )
        )),
        Err(crate::execution_attempt::ExecutionAttemptError::Deferred(_))
    ));
    assert_eq!(chain.kura().canonical_query_reads_for_test(), (0, 0));
    assert!(CertifiedChain::new_with_source_admission(&view, |_, _| Ok(())).is_err());
    assert_eq!(chain.kura().canonical_query_reads_for_test(), (1, length));
}

#[test]
fn state_certificate_genesis_decode_refusal_is_typed_and_retryable() {
    let (chain, _) = chain();
    let view = chain.state().view();
    let refusal =
        norito::with_decode_limits_scope(norito::DecodeLimits::new(1, 1, 1, 1, 1), || {
            CertifiedChain::new_with_source_admission(&view, |_, _| Ok(()))
        });
    assert!(
        matches!(
            refusal,
            Err(crate::execution_attempt::ExecutionAttemptError::Deferred(_))
        ),
        "{refusal:?}"
    );
    let reader = CertifiedChain::new_with_source_admission(&view, |_, _| Ok(())).unwrap();
    assert_eq!(reader.genesis().as_ref(), frame(&chain, 1).as_ref());
    assert_eq!(
        reader
            .certified_from_execution(NonZeroUsize::new(5).unwrap(), |_, _| Ok(()))
            .unwrap()
            .id(),
        chain.committed(5).id()
    );
}

#[test]
fn state_certificate_source_allowance_includes_genesis_and_recent_ancestry() {
    let (chain, _) = chain();
    let view = chain.state().view();
    for height in [2_u64, 5] {
        let count = 1 + chain.height() - height + 2;
        let bytes = frame(&chain, 1).encode_wire().unwrap().len() as u64
            + (height - 1..=chain.height())
                .map(|h| frame(&chain, h).encode_wire().unwrap().len() as u64)
                .sum::<u64>();
        for (work_limit, byte_limit, succeeds) in [
            (count, bytes, true),
            (count - 1, bytes, false),
            (count, bytes - 1, false),
        ] {
            let mut work_left = work_limit;
            let mut bytes_left = byte_limit;
            let mut admit = |work, bytes| {
                let work_next = work_left.checked_sub(work).ok_or(
                    crate::execution_attempt::ExecutionAttemptError::Deferred(
                        ivm::error::ExecutionDeferral::CanonicalHistoryCapacity.into(),
                    ),
                )?;
                let bytes_next = bytes_left.checked_sub(bytes).ok_or(
                    crate::execution_attempt::ExecutionAttemptError::Deferred(
                        ivm::error::ExecutionDeferral::CanonicalHistoryCapacity.into(),
                    ),
                )?;
                work_left = work_next;
                bytes_left = bytes_next;
                Ok(())
            };
            let reader = CertifiedChain::new_with_source_admission(&view, &mut admit).unwrap();
            let result = reader
                .certified_from_execution(NonZeroUsize::new(height as usize).unwrap(), &mut admit);
            if succeeds {
                assert_eq!(result.unwrap().id(), chain.committed(height).id());
                assert_eq!((work_left, bytes_left), (0, 0));
            } else {
                assert!(matches!(
                    result,
                    Err(crate::execution_attempt::ExecutionAttemptError::Deferred(_))
                ));
            }
        }
    }
}

#[test]
fn state_certificate_selected_ancestor_reuses_original_walk_and_adjacent_parent() {
    let (chain, _) = chain();
    let view = chain.state().view();
    let reader = CertifiedChain::new(&view).unwrap();
    let latest_id = chain.committed(5).id();
    for selected in [None, Some(4_usize), Some(3), Some(2)] {
        let last = selected.unwrap_or(5) - 1;
        let source_heights = (last as u64..=5).rev().collect::<Vec<_>>();
        let source_bytes = source_heights
            .iter()
            .map(|h| frame(&chain, *h).encode_wire().unwrap().len() as u64)
            .sum::<u64>();
        for refused in [true, false] {
            let mut work_left = source_heights.len() as u64 - u64::from(refused);
            let mut bytes_left = source_bytes;
            let (result, observed) = relation_counts::measure(|| {
                reader.certified_with_ancestor_from_execution(
                    NonZeroUsize::new(5).unwrap(),
                    |work, bytes| {
                        work_left = work_left.checked_sub(work).ok_or(
                            crate::execution_attempt::ExecutionAttemptError::Deferred(
                                ivm::error::ExecutionDeferral::CanonicalHistoryCapacity.into(),
                            ),
                        )?;
                        bytes_left = bytes_left.checked_sub(bytes).ok_or(
                            crate::execution_attempt::ExecutionAttemptError::Deferred(
                                ivm::error::ExecutionDeferral::CanonicalHistoryCapacity.into(),
                            ),
                        )?;
                        Ok(())
                    },
                    |latest| {
                        assert_eq!(latest.id(), latest_id);
                        Ok(selected.and_then(NonZeroUsize::new))
                    },
                )
            });
            if refused {
                assert!(matches!(
                    result,
                    Err(crate::execution_attempt::ExecutionAttemptError::Deferred(_))
                ));
            } else {
                let (latest, ancestor) = result.unwrap();
                assert_eq!(latest.id(), latest_id);
                assert_eq!(
                    ancestor.as_ref().map(|block| block.height()),
                    selected.map(|h| h as u64)
                );
                assert_eq!(observed.frames, source_heights);
                assert_eq!(
                    observed.qcs,
                    [Some(5), selected.map(|h| h as u64)]
                        .into_iter()
                        .flatten()
                        .collect::<Vec<_>>()
                );
                assert_eq!((work_left, bytes_left), (0, 0));
            }
        }
    }
    for invalid in [1, 5, 6] {
        assert!(
            reader
                .certified_with_ancestor_from_execution(
                    NonZeroUsize::new(5).unwrap(),
                    |_, _| Ok(()),
                    |_| Ok(NonZeroUsize::new(invalid)),
                )
                .is_err()
        );
    }
}

#[test]
fn state_certificate_selected_ancestor_checks_both_native_quorums() {
    for bad_height in [3, 5] {
        for signers in [Signers::BelowQuorum, Signers::All] {
            let (chain, _) = chain();
            chain.corrupt_local_quorum_for_test(bad_height, signers);
            let view = chain.state().view();
            let reader = CertifiedChain::new(&view).unwrap();
            assert!(
                reader.committed(bad_height).is_ok(),
                "original execution remains authenticated"
            );
            let mut selected = false;
            let result = reader.certified_with_ancestor_from_execution(
                NonZeroUsize::new(5).unwrap(),
                |_, _| Ok(()),
                |_| {
                    selected = true;
                    Ok(NonZeroUsize::new(3))
                },
            );
            assert!(
                result.is_err(),
                "both requested certificates require the exact native quorum"
            );
            assert_eq!(
                selected,
                bad_height != 5,
                "selector must not see an unverified target"
            );
        }
    }
}

#[test]
fn state_certificate_signed_availability_scratch_uses_original_query_allowance() {
    use iroha_allocation::AllocationBudget;
    use iroha_sumeragi::availability::PayloadBytes;

    let (chain, _) = chain();
    let source = frame(&chain, 3);
    let current = read_frame(Clone::clone(&source), 3, chain.root_scope()).unwrap();
    let parent = chain.committed(2);
    let schedule::ScheduledSlot::Ready(scheduled) = &parent.commitment().schedule.next else {
        panic!("original executed parent authorizes height 3");
    };
    let mut validation = EpochValidationScope::new();
    let config = scheduled
        .height_config_with_validation(&mut validation)
        .unwrap();
    let authority = VerifiedAuthority::new(scheduled.epoch.clone(), 3, &mut validation).unwrap();
    let budget = AllocationBudget::new(1 << 26);
    let artifacts = artifacts::PrefixArtifactsRead::new(Clone::clone(&source), budget.clone())
        .complete(&budget)
        .unwrap_or_else(|(_, error)| panic!("original artifact owners: {error}"));
    let (_, table, payload) = artifacts
        .into_parts(&source, current.header.as_ref().unwrap())
        .unwrap();
    let retained = budget.reserved_bytes();
    assert!(table.admitted_to(&budget) && payload.admitted_to(&budget));
    let verified = iroha_sumeragi::availability::verify_availability(
        current.header.as_ref().unwrap().instance,
        &config,
        current.header.as_ref().unwrap(),
        table.as_slice(),
        &authority.crypto,
    )
    .unwrap();
    let shape = verified.shape();
    let scratch = shape.encoded_bytes() + shape.workspace_words() * size_of::<u16>();
    let check = |limit, bytes: &PayloadBytes| {
        norito::core::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, limit, 128),
            || {
                verify_availability(
                    &current,
                    &config,
                    &authority.crypto,
                    Some((table.clone(), bytes.clone())),
                    &mut crate::sumeragi::certified_chain::state_certificate::query_scratch_admission,
                )
            },
        )
    };
    assert!(matches!(
        check(scratch - 1, &payload),
        Err(VerificationReadError::Resource(
            norito::core::DecodeResourceError::TotalAllocationExceeded { attempted, limit }
        )) if attempted == scratch as u64 && limit == (scratch - 1) as u64
    ));
    assert_eq!(budget.reserved_bytes(), retained);
    check(scratch, &payload).expect("same source and original owners retry at the exact allowance");
    assert_eq!(budget.reserved_bytes(), retained);
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        &current.block,
        &source
    ));

    let mut corrupt = payload.as_slice().to_vec();
    corrupt[0] ^= 1;
    let mut corrupt = PayloadBytes::from_untrusted(corrupt).unwrap();
    corrupt.admit(&budget).unwrap();
    assert!(matches!(
        check(scratch, &corrupt),
        Err(VerificationReadError::Source(
            ChainReadError::Malformed { .. }
        ))
    ));
    drop((corrupt, payload, table));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn state_certificate_native_qc_decode_refusal_is_capacity_and_retries_original_source() {
    let (chain, _) = chain();
    let view = chain.state().view();
    let reader = CertifiedChain::new(&view).unwrap();
    let current = chain.committed(3);
    let parent = chain.committed(2);
    let schedule::ScheduledSlot::Ready(scheduled) = &parent.commitment().schedule.next else {
        panic!("original parent authorizes the source");
    };
    let mut validation = EpochValidationScope::new();
    let authority = VerifiedAuthority::new(scheduled.epoch.clone(), 3, &mut validation).unwrap();
    let config = scheduled
        .height_config_with_validation(&mut validation)
        .unwrap();
    let check = |field_limit| {
        norito::core::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, field_limit, usize::MAX, usize::MAX, 128),
            || {
                reader.verification_context().verify_certificate_with_scratch_admission(
                    current.clone(),
                    &authority,
                    Some(&config),
                    None,
                    &mut crate::sumeragi::certified_chain::state_certificate::query_scratch_admission,
                )
            },
        )
    };
    assert!(matches!(
        check(1),
        Err(VerificationReadError::Resource(
            norito::core::DecodeResourceError::FieldLengthExceeded { limit: 1, .. }
        ))
    ));
    let certified =
        check(usize::MAX).expect("exact original source retries without a new authority");
    assert_eq!(certified.id(), current.id());
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        certified.block(),
        current.block()
    ));
}

#[test]
fn state_certificate_pairing_constructor_refusal_preserves_original_source_for_retry() {
    let (chain, _) = chain();
    let view = chain.state().view();
    let reader = CertifiedChain::new(&view).unwrap();
    let parent = chain.committed(2);
    let current = chain.committed(3);
    let backing = iroha_crypto::bls::consensus::ConsensusAggregateScratch::<()>::backing_bytes();
    let check = |limit| {
        norito::core::with_decode_limits_measured(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, limit, 128),
            || reader.verify_executed_successor(&parent, current.clone()),
        )
    };
    for _ in 0..2 {
        let ((result, usage), relations) = relation_counts::measure(|| check(backing - 1));
        assert!(
            relations.qcs.is_empty(),
            "constructor admission precedes any QC relation"
        );
        // Pure epoch validation first attempts its native context roundtrip under this same
        // cumulative allowance. Refused optional insertion retains those original charges;
        // the next failed charge must still be the exact pairing constructor backing.
        let prelude = usage.total_allocated_bytes();
        assert!(prelude > 0 && prelude < backing);
        assert!(matches!(
            result,
            Err(VerificationReadError::Resource(
                norito::core::DecodeResourceError::TotalAllocationExceeded { attempted, limit }
            )) if attempted == u64::try_from(prelude.checked_add(backing).unwrap()).unwrap()
                && limit == u64::try_from(backing - 1).unwrap()
        ));
        assert_eq!(parent.id(), chain.committed(2).id());
        assert_eq!(current.id(), chain.committed(3).id());
    }
    // Each original refused scope and its counter owner has ended before this unchanged retry.
    let ((certified, _), relations) = relation_counts::measure(|| check(1 << 26));
    assert_eq!(relations.qcs, [3]);
    let certified =
        certified.expect("same authenticated body and parent retry after local refusal");
    assert_eq!(certified.id(), current.id());
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        certified.block(),
        current.block()
    ));
    assert_eq!(parent.id(), chain.committed(2).id());
}

#[test]
fn state_certificate_original_qc_inner_limit_is_not_adopted_by_wider_query_scope() {
    let (chain, _) = chain();
    let current = chain.committed(3);
    let bytes = current.block().commit_certificate().unwrap().commit_qc();
    let original: iroha_sumeragi::message::Qc = norito::decode_canonical(bytes).unwrap();
    norito::core::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 128),
        || {
            let error = norito::core::with_decode_limits_scope(
                norito::DecodeLimits::new(usize::MAX, 1, usize::MAX, usize::MAX, 128),
                || norito::decode_canonical::<iroha_sumeragi::message::Qc>(bytes).unwrap_err(),
            );
            assert!(
                matches!(&error, norito::Error::FieldLengthExceeded { length, limit: 1 } if *length > 1)
            );
            let expected = error.to_string();
            assert!(matches!(verification_codec_error(3, error),
                VerificationReadError::Source(ChainReadError::Malformed { height: 3, reason }) if reason == expected));
            let mut malformed = bytes.to_vec();
            malformed.push(0);
            let error =
                norito::decode_canonical::<iroha_sumeragi::message::Qc>(&malformed).unwrap_err();
            assert!(error.decode_resource_error().is_none());
            assert!(matches!(
                verification_codec_error(3, error),
                VerificationReadError::Source(ChainReadError::Malformed { height: 3, .. })
            ));
        },
    );
    assert_eq!(
        norito::decode_canonical::<iroha_sumeragi::message::Qc>(bytes).unwrap(),
        original
    );
}

/// One valid quorum chosen by the proposal is common input even when the
/// independently executed source retains a different valid local certificate.
#[test]
fn parent_service_common_proposal_is_independent_of_local_certificate_subset() {
    use crate::sumeragi::certified_chain::ParentServiceError;
    let (chain, _) = chain();
    let view = chain.state().view();
    let reader = CertifiedChain::new_for_parent_service(&view).unwrap();
    let proposal = chain.proposal(Some(6_000), Vec::new());
    let offered = proposal
        .npos_consensus_effects()
        .unwrap()
        .parent_service_commit_qc
        .as_deref()
        .unwrap();
    let offered_qc: Qc = norito::decode_canonical(offered).unwrap();
    let source = frame(&chain, 5);
    let (_, source_qc) = decode_certificate(source.commit_certificate().unwrap()).unwrap();
    assert_eq!(offered_qc, source_qc);
    let other_qc = chain.commit_qc(
        5,
        source_qc.block_hash,
        source_qc.result,
        Signers::LastThree,
    );
    assert_ne!(source_qc.signers, other_qc.signers);
    let other_source = with_parts(&source, |_, qc, _| *qc = other_qc.clone());
    let predecessor = chain.committed(4);
    let left = reader
        .verify_parent_service_at(
            &proposal,
            &predecessor,
            &read_frame(source, 5, chain.root_scope()).unwrap(),
            offered,
        )
        .unwrap()
        .unwrap();
    let right = reader
        .verify_parent_service_at(
            &proposal,
            &predecessor,
            &read_frame(other_source, 5, chain.root_scope()).unwrap(),
            offered,
        )
        .unwrap()
        .unwrap();
    assert_eq!(left.height(), right.height());
    assert_eq!(left.timestamp_ms(), right.timestamp_ms());
    assert_eq!(left.signers(), right.signers());
    let full = reader
        .authenticate_parent_service(&proposal, |_, _| Ok(()))
        .unwrap()
        .unwrap();
    assert_eq!(full.signers(), left.signers());
    full.require_proposal(&proposal).unwrap();

    let mut other_proposal = proposal.clone();
    let mut effects = proposal.npos_consensus_effects().unwrap().clone();
    effects.parent_service_commit_qc = Some(norito::to_bytes(&other_qc).unwrap());
    other_proposal.set_npos_consensus_effects(Some(effects));
    assert_ne!(proposal.hash(), other_proposal.hash());
    let other = reader
        .authenticate_parent_service(&other_proposal, |_, _| Ok(()))
        .unwrap()
        .unwrap();
    assert_ne!(full.signers(), other.signers());
    assert!(matches!(
        full.require_proposal(&other_proposal),
        Err(ParentServiceError::Invalid(_))
    ));
}

#[test]
fn parent_service_proof_requires_exact_native_quorum_and_complete_subject() {
    use crate::sumeragi::certified_chain::ParentServiceError;
    let (chain, _) = chain();
    let view = chain.state().view();
    let reader = CertifiedChain::new_for_parent_service(&view).unwrap();
    let proposal = chain.proposal(Some(6_000), Vec::new());
    let offered = proposal
        .npos_consensus_effects()
        .unwrap()
        .parent_service_commit_qc
        .as_ref()
        .unwrap();
    let qc: Qc = norito::decode_canonical(offered).unwrap();
    let mut cases = Vec::new();
    for mutate in 0..7 {
        let mut changed = qc.clone();
        match mutate {
            0 => changed.instance = Hash32([0x17; 32]),
            1 => changed.height -= 1,
            2 => changed.block_hash = Hash32([0x27; 32]),
            3 => changed.result = Hash32([0x37; 32]),
            4 => changed.result.0[0] ^= 1,
            5 => changed.epoch.epoch += 1,
            6 => changed.agg_sig.0[5] ^= 1,
            _ => unreachable!(),
        }
        cases.push(norito::to_bytes(&changed).unwrap());
    }
    for signers in [Signers::BelowQuorum, Signers::All] {
        cases.push(
            norito::to_bytes(&chain.commit_qc(5, qc.block_hash, qc.result, signers)).unwrap(),
        );
    }
    cases.push(Vec::new());
    cases.push(vec![
        0;
        iroha_data_model::consensus::PARENT_SERVICE_COMMIT_QC_MAX_BYTES
            + 1
    ]);
    for bytes in cases {
        let mut changed = proposal.clone();
        let mut effects = proposal.npos_consensus_effects().unwrap().clone();
        effects.parent_service_commit_qc = Some(bytes);
        changed.set_npos_consensus_effects(Some(effects));
        assert!(matches!(
            reader.authenticate_parent_service(&changed, |_, _| Ok(())),
            Err(ParentServiceError::Invalid(_))
        ));
    }
    let mut missing = proposal.clone();
    let mut effects = proposal.npos_consensus_effects().unwrap().clone();
    effects.parent_service_commit_qc = None;
    missing.set_npos_consensus_effects((!effects.is_empty()).then_some(effects));
    assert!(matches!(
        reader.authenticate_parent_service(&missing, |_, _| Ok(())),
        Err(ParentServiceError::Invalid(_))
    ));
}

#[test]
fn parent_service_original_decode_refusal_retries_same_proposal_without_invalidity() {
    use crate::sumeragi::certified_chain::ParentServiceError;
    let (chain, _) = chain();
    let view = chain.state().view();
    let reader = CertifiedChain::new_for_parent_service(&view).unwrap();
    let proposal = chain.proposal(Some(6_000), Vec::new());
    let offered = proposal
        .npos_consensus_effects()
        .unwrap()
        .parent_service_commit_qc
        .as_ref()
        .unwrap();
    let current = chain.committed(5);
    let predecessor = chain.committed(4);
    let refused = norito::core::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 128),
        || reader.verify_parent_service_at(&proposal, &predecessor, &current, offered),
    );
    assert!(matches!(refused, Err(ParentServiceError::Deferred(_))));
    let retry = reader
        .verify_parent_service_at(&proposal, &predecessor, &current, offered)
        .unwrap()
        .unwrap();
    retry.require_proposal(&proposal).unwrap();
    assert_eq!(retry.height(), 5);
    assert!(!retry.signers().is_empty());
}

#[test]
fn parent_service_source_loss_is_recovery_without_participation_receipt() {
    use crate::sumeragi::certified_chain::ParentServiceError;
    let (chain, _) = chain();
    let proposal = chain.proposal(Some(6_000), Vec::new());
    let view = chain.state().view();
    let reader = CertifiedChain::new_for_parent_service(&view).unwrap();
    chain
        .kura()
        .corrupt_canonical_body_for_testing(NonZeroUsize::new(4).unwrap())
        .unwrap();
    assert!(matches!(
        reader.authenticate_parent_service(&proposal, |_, _| Ok(())),
        Err(ParentServiceError::Source(_))
    ));
}

#[test]
fn parent_service_source_allowance_counts_every_original_before_authentication() {
    use crate::sumeragi::certified_chain::ParentServiceError;
    let (chain, _) = chain();
    let proposal = chain.proposal(Some(6_000), Vec::new());
    let view = chain.state().view();
    let reader = CertifiedChain::new_for_parent_service(&view).unwrap();
    let bytes = (4..=5)
        .map(|height| frame(&chain, height).encode_wire().unwrap().len() as u64)
        .sum::<u64>();
    for (work, allowance, success) in [
        (2_u64, bytes, true),
        (1, bytes, false),
        (2, bytes - 1, false),
    ] {
        let mut remaining_work = work;
        let mut remaining_bytes = allowance;
        let (result, count) = relation_counts::measure(|| {
            reader.authenticate_parent_service(&proposal, |work, bytes| {
                remaining_work = remaining_work.checked_sub(work).ok_or(
                    crate::execution_attempt::ExecutionAttemptError::Deferred(
                        ivm::error::ExecutionDeferral::CanonicalHistoryCapacity.into(),
                    ),
                )?;
                remaining_bytes = remaining_bytes.checked_sub(bytes).ok_or(
                    crate::execution_attempt::ExecutionAttemptError::Deferred(
                        ivm::error::ExecutionDeferral::CanonicalHistoryCapacity.into(),
                    ),
                )?;
                Ok(())
            })
        });
        if success {
            assert_eq!(result.unwrap().unwrap().height(), 5);
            assert_eq!(remaining_work, 0);
            assert_eq!(remaining_bytes, 0);
            assert_eq!(count.qcs, [5]);
        } else {
            assert!(matches!(
                result,
                Err(ParentServiceError::Deferred(reason))
                    if reason.reason() == ivm::error::ExecutionDeferral::CanonicalHistoryCapacity
            ));
            assert!(count.qcs.is_empty());
        }
    }
}

#[test]
fn original_walk_pool_refusal_precedes_source_and_keeps_its_release_owner() {
    use crate::execution_attempt::ExecutionAttemptError;
    use iroha_allocation::{AllocationBudget, AllocationRefusal, release::ReleaseRegistration};
    use std::{
        future::Future as _,
        pin::Pin,
        task::{Context, Waker},
    };
    // Keep old State generations alive so only the explicit held owner can refund
    // the original pool and wake this test's release observation.
    let _retirement_pin = crossbeam_epoch::pin();
    let (chain, _) = chain();
    let view = chain.state().view();
    let reader = CertifiedChain::new_with_source_admission(&view, |_, _| Ok(())).unwrap();
    let budget = view.execution_budget();
    let baseline = budget.reserved_bytes();
    let mut funding = budget
        .try_reserve(ReleaseRegistration::allocation_layout())
        .unwrap();
    let mut registration = ReleaseRegistration::from_reservation(&mut funding).unwrap();
    drop(funding);
    let held = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    let mut callbacks = 0;
    chain.kura().reset_canonical_query_reads_for_test();
    let mut walk = reader.walk_from_execution(
        NonZeroUsize::new(4).unwrap(),
        NonZeroUsize::new(5).unwrap(),
        |_, _| {
            callbacks += 1;
            Ok(())
        },
    );
    let failure = walk.next().unwrap().err().unwrap();
    assert!(walk.next().is_none());
    drop(walk);
    assert_eq!(
        callbacks, 0,
        "coordinate admission precedes original source I/O"
    );
    assert_eq!(chain.kura().canonical_query_reads_for_test(), (0, 0));
    let ExecutionAttemptError::Deferred(original) = failure else {
        panic!("original local owner")
    };
    let Some(AllocationRefusal::Capacity { release, .. }) = original.allocation_refusal() else {
        panic!("original capacity release owner")
    };
    let mut wait = release.clone().wait_for_release(&mut registration);
    let mut context = Context::from_waker(Waker::noop());
    assert!(Pin::new(&mut wait).poll(&mut context).is_pending());
    let foreign = AllocationBudget::new(1);
    drop(foreign.try_reserve_bytes(1).unwrap());
    assert!(Pin::new(&mut wait).poll(&mut context).is_pending());
    drop(held);
    assert!(Pin::new(&mut wait).poll(&mut context).is_ready());
    drop(wait);
    drop(registration);
    assert_eq!(budget.reserved_bytes(), baseline);
    let blocks = reader
        .walk_from_execution(
            NonZeroUsize::new(4).unwrap(),
            NonZeroUsize::new(5).unwrap(),
            |_, _| Ok(()),
        )
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        blocks
            .iter()
            .map(|block| block.height())
            .collect::<Vec<_>>(),
        [4, 5]
    );
    drop(blocks);
    assert_eq!(budget.reserved_bytes(), baseline);
}

#[test]
fn original_walk_keeps_semantic_gas_rejection_and_refunds_partial_coordinates() {
    use crate::execution_attempt::ExecutionAttemptError;
    // Retain unrelated retired State generations while measuring the walk's exact
    // coordinate admission, error refund and abandonment against one baseline.
    let _retirement_pin = crossbeam_epoch::pin();
    let (chain, _) = chain();
    let view = chain.state().view();
    let reader = CertifiedChain::new_with_source_admission(&view, |_, _| Ok(())).unwrap();
    let budget = view.execution_budget();
    let baseline = budget.reserved_bytes();
    let refusal = std::cell::Cell::new(false);
    let mut walk = reader.walk_from_execution(
        NonZeroUsize::new(4).unwrap(),
        NonZeroUsize::new(5).unwrap(),
        |_, _| {
            if refusal.get() {
                Err(ExecutionAttemptError::Rejected(
                    QueryExecutionFail::GasBudgetExceeded,
                ))
            } else {
                Ok(())
            }
        },
    );
    let first = walk.next().unwrap().unwrap();
    assert_eq!(first.height(), 4);
    drop(first);
    assert!(
        budget.reserved_bytes() > baseline,
        "partial walk retains real original-pool coordinates"
    );
    refusal.set(true);
    chain.kura().reset_canonical_query_reads_for_test();
    assert!(matches!(
        walk.next(),
        Some(Err(ExecutionAttemptError::Rejected(
            QueryExecutionFail::GasBudgetExceeded
        )))
    ));
    assert_eq!(chain.kura().canonical_query_reads_for_test(), (0, 0));
    assert_eq!(
        budget.reserved_bytes(),
        baseline,
        "error releases scratch while exhausted iterator is still alive"
    );
    assert!(walk.next().is_none());
    drop(walk);
    let mut abandoned = reader.walk_from_execution(
        NonZeroUsize::new(4).unwrap(),
        NonZeroUsize::new(5).unwrap(),
        |_, _| Ok(()),
    );
    drop(abandoned.next().unwrap().unwrap());
    assert!(budget.reserved_bytes() > baseline);
    drop(abandoned);
    assert_eq!(
        budget.reserved_bytes(),
        baseline,
        "abandonment releases the exact funded backing"
    );
}

#[test]
fn state_certificate_consuming_completion_waits_for_original_walk_and_refunds_receipts() {
    let (chain, _) = chain();
    let view = chain.state().view();
    let latest_id = chain.committed(5).id();
    let ancestor_id = chain.committed(2).id();
    let reader = CertifiedChain::new(&view).unwrap();
    let pool = view.execution_budget();
    let baseline = pool.reserved_bytes();
    for refused in [true, false] {
        let mut work_left = 5_u64 - u64::from(refused);
        let mut completed = false;
        let (result, observed) = relation_counts::measure(|| {
            reader.certified_with_ancestor_from_execution_into(
                NonZeroUsize::new(5).unwrap(),
                |work, _| {
                    work_left = work_left.checked_sub(work).ok_or(
                        crate::execution_attempt::ExecutionAttemptError::Deferred(
                            ivm::error::ExecutionDeferral::CanonicalHistoryCapacity.into(),
                        ),
                    )?;
                    Ok(())
                },
                |latest| {
                    assert_eq!(latest.id(), latest_id);
                    Ok(NonZeroUsize::new(2))
                },
                |latest, ancestor| {
                    completed = true;
                    assert_eq!(latest.id(), latest_id);
                    assert_eq!(ancestor.as_ref().map(|block| block.id()), Some(ancestor_id));
                    (latest.id(), ancestor.as_ref().map(|block| block.id()))
                },
            )
        });
        assert_eq!(work_left, 0);
        assert_eq!(completed, !refused);
        assert_eq!(
            pool.reserved_bytes(),
            baseline,
            "completed or refused receipt ownership retires to its original pool"
        );
        if refused {
            assert!(matches!(
                result,
                Err(crate::execution_attempt::ExecutionAttemptError::Deferred(_))
            ));
            assert_eq!(observed.frames, [5, 4, 3, 2]);
            assert_eq!(observed.qcs, [5]);
        } else {
            assert_eq!(result.unwrap(), (latest_id, Some(ancestor_id)));
            assert_eq!(observed.frames, [5, 4, 3, 2, 1]);
            assert_eq!(observed.qcs, [5, 2]);
        }
    }
}

#[test]
fn admitted_receipt_malformed_frame_preserves_rejection_and_refunds_original_slots() {
    let (chain, _) = chain();
    let original = frame(&chain, 5);
    let malformed = with_parts(&original, |header, _, _| header.height = 6);
    let budget = chain.state().ivm_execution_budget();
    let baseline = budget.reserved_bytes();
    let expected = read_frame(malformed.clone(), 5, chain.root_scope()).unwrap_err();
    let actual = AdmittedCommittedBlock::read(
        malformed,
        5,
        chain.root_scope(),
        &mut EpochValidationScope::new(),
        &budget,
    )
    .err()
    .expect("the same canonical malformed frame must remain rejected");
    match (expected, actual) {
        (ExecutionAttemptError::Rejected(expected), ExecutionAttemptError::Rejected(actual)) => {
            assert_eq!(actual, expected);
        }
        errors => panic!("malformed frames must not become local refusals: {errors:?}"),
    }
    assert_eq!(budget.reserved_bytes(), baseline);
    let receipt = AdmittedCommittedBlock::read(
        original.clone(),
        5,
        chain.root_scope(),
        &mut EpochValidationScope::new(),
        &budget,
    )
    .expect("the original valid frame remains usable after malformed rejection");
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        receipt.block(),
        &original
    ));
    drop(receipt);
    assert_eq!(budget.reserved_bytes(), baseline);
}
