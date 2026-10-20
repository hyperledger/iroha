//! One-pass native prefix verification and actual successor-bound genesis execution.

use super::*;

// Keep the real NPoS boundary construction and final native commit outside the
// later streamed-reader assertion frame, retaining the original chain owner.
#[inline(never)]
fn with_native_boundary_chain(assert_original: fn(&CertifiedTestChain)) {
    let mut chain = Box::new(CertifiedTestChain::npos_boundary_fixture());
    chain.commit_with(Some(10_000), Vec::new(), Signers::LastThree);
    assert_original(&chain);
}

#[test]
fn staged_certificate_prefix_preserves_reset_target_first_order_and_original_receipts() {
    let (chain, _) = chain();
    let view = chain.state().view();
    let reader = CertifiedChain::new(&view).unwrap();
    let mut source_budgets = Vec::new();
    for (height, frames, qcs) in [
        (3, vec![1, 3, 2], vec![2, 3]),
        (4, vec![4], vec![4]),
        (2, vec![1, 2], vec![2]),
        (5, vec![5, 3, 4], vec![3, 4, 5]),
    ] {
        let source = frame(&chain, height);
        let budget = iroha_allocation::AllocationBudget::new(
            iroha_data_model::block::SharedSignedBlock::allocation_layout().size(),
        );
        let original = iroha_data_model::block::SharedSignedBlock::reserve(&budget)
            .unwrap()
            .initialize(source.as_ref().clone());
        drop(source);
        let (receipt, counts) =
            relation_counts::measure(|| reader.check_certificate(original.clone(), height));
        let receipt = receipt.unwrap();
        assert_eq!(counts.frames, frames);
        assert_eq!(counts.qcs, qcs);
        assert_eq!(receipt.height(), height);
        assert_eq!(receipt.verification(), QcVerification::Verified);
        assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
            receipt.block(),
            &original
        ));
        drop(receipt);
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
        assert!(
            source_budgets
                .iter()
                .all(|prior: &iroha_allocation::AllocationBudget| prior.reserved_bytes() == 0)
        );
        assert_eq!(reader.prefix.lock().as_ref().unwrap().tip.height(), height);
        drop(original);
        assert_eq!(
            budget.reserved_bytes(),
            budget.limit_bytes(),
            "the cursor retains its exact original source"
        );
        source_budgets.push(budget);
    }
    drop(reader);
    assert!(
        source_budgets
            .iter()
            .all(|budget| budget.reserved_bytes() == 0)
    );
}

#[test]
fn staged_certificate_prefix_refusal_preserves_cursor_and_target_before_gap_errors() {
    let (chain, _) = chain();
    let view = chain.state().view();
    let reader = CertifiedChain::new(&view).unwrap();
    let original = frame(&chain, 3);
    let refused = norito::core::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 128),
        || reader.check_certificate(original.clone(), 3),
    );
    assert!(matches!(refused, Err(ExecutionAttemptError::Deferred(_))));
    assert!(reader.prefix.lock().is_none());
    reader.certified(1).unwrap();
    let malformed = with_parts(&original, |_, _, preimage| preimage.push(0));
    let (rejected, counts) = relation_counts::measure(|| reader.check_certificate(malformed, 3));
    assert!(matches!(
        rejected,
        Err(ExecutionAttemptError::Rejected(ChainReadError::Malformed {
            height: 3,
            ..
        }))
    ));
    assert_eq!(counts.frames, [3]);
    assert!(counts.qcs.is_empty());
    assert_eq!(reader.prefix.lock().as_ref().unwrap().tip.height(), 1);
    let (receipt, counts) =
        relation_counts::measure(|| reader.check_certificate(original.clone(), 3));
    let receipt = receipt.expect("same original target and retained genesis cursor retry");
    assert_eq!(counts.frames, [3, 2]);
    assert_eq!(counts.qcs, [2, 3]);
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        receipt.block(),
        &original
    ));
}

#[test]
fn streamed_prefix_emits_genesis_execution_anchor_only_after_real_successor() {
    with_native_chain(
        assert_streamed_prefix_emits_genesis_execution_anchor_only_after_real_successor,
    );
}

#[inline(never)]
fn assert_streamed_prefix_emits_genesis_execution_anchor_only_after_real_successor(
    chain: &CertifiedTestChain,
    _entry: HashOf<TransactionEntrypoint>,
) {
    let id = ChainId::from("sumeragi-certified-test-chain");
    let mut prefix = CertifiedPrefix::new(&id, chain.network_id(), frame(chain, 1)).unwrap();
    assert_eq!(prefix.instance(), chain.instance());
    assert!(
        prefix.push(frame(chain, 3)).is_err(),
        "a skipped frame must not advance the cursor"
    );
    for height in 2..=5 {
        let (current, genesis) = prefix.push(frame(chain, height)).unwrap().into_parts();
        assert_eq!(current.verification(), QcVerification::Verified);
        assert_eq!(current.height(), height);
        if height == 2 {
            let genesis = genesis.expect("actual H2 authenticates Rg exactly once");
            assert_eq!(genesis.successor(), current.core_hash());
            assert_eq!(genesis.committed().height(), 1);
            assert!(genesis.committed().header().is_none());
            assert!(current.extends(genesis.committed()));
            assert_eq!(
                genesis.into_committed().result(),
                chain.committed(1).result()
            );
        } else {
            assert!(genesis.is_none());
        }
        assert!(
            prefix.push(frame(chain, height)).is_err(),
            "replay cannot advance twice"
        );
    }
}

#[test]
fn unsigned_changed_genesis_result_cannot_be_exported_by_streamed_reader() {
    let (chain, _) = chain();
    let id = ChainId::from("sumeragi-certified-test-chain");
    let original = frame(&chain, 1);
    let certificate = original.commit_certificate().unwrap();
    let (original_x, mut result) = fixture_result_parts(certificate.result_preimage());
    // Preserve the authenticated lane-write opening's structural consistency. This
    // attack changes a well-formed execution result which only the successor can bind.
    result.execution.world_state_root = Hash::new(b"unsigned genesis result replacement");
    let changed = crate::block::reserve_block_for_tests().initialize(
        original.as_ref().clone().with_commit_certificate(Some(
            CommitCertificate::from_untrusted_parts(
                Vec::new(),
                Vec::new(),
                fixture_result_preimage(&original_x, &result),
                Vec::new(),
            ),
        )),
    );
    assert_eq!(changed.hash(), original.hash());
    let mut prefix = CertifiedPrefix::new(&id, chain.network_id(), changed).unwrap();
    assert!(matches!(
        prefix.push(frame(&chain, 2)),
        Err(crate::execution_attempt::ExecutionAttemptError::Rejected(
            ChainReadError::Discontinuous { height: 2 }
        ))
    ));
    let mut foreign = CertifiedPrefix::new(
        &ChainId::from("foreign-instance"),
        chain.network_id(),
        original,
    )
    .unwrap();
    assert!(matches!(
        foreign.push(frame(&chain, 2)),
        Err(crate::execution_attempt::ExecutionAttemptError::Rejected(
            ChainReadError::WrongInstance { height: 2 }
        ))
    ));
}

#[test]
fn streamed_prefix_checks_exact_native_quorum_at_retained_empty_epoch_boundary() {
    with_native_boundary_chain(
        assert_streamed_prefix_checks_exact_native_quorum_at_retained_empty_epoch_boundary,
    );
}

#[inline(never)]
fn assert_streamed_prefix_checks_exact_native_quorum_at_retained_empty_epoch_boundary(
    chain: &CertifiedTestChain,
) {
    let id = ChainId::from("sumeragi-certified-test-chain");
    let mut prefix = CertifiedPrefix::new(&id, chain.network_id(), frame(chain, 1)).unwrap();
    for height in 2..10 {
        prefix.push(frame(chain, height)).unwrap();
    }
    let original = frame(chain, 10);
    for alter_result in [false, true] {
        let tampered = with_parts(&original, |_, qc, _| {
            if alter_result {
                qc.result.0[0] ^= 1;
            } else {
                qc.agg_sig.0[0] ^= 1;
            }
        });
        let (rejected, counts) = relation_counts::measure(|| prefix.push(tampered));
        // Source/result binding precedes BLS verification; the two tamper cases
        // must preserve their distinct typed errors and leave the cursor intact.
        if alter_result {
            assert!(
                matches!(
                    rejected,
                    Err(ExecutionAttemptError::Rejected(
                        ChainReadError::ResultMismatch { height: 10 }
                    ))
                ),
                "changed result must fail source binding: {rejected:?}"
            );
            assert!(counts.qcs.is_empty());
        } else {
            assert!(
                matches!(
                    rejected,
                    Err(ExecutionAttemptError::Rejected(
                        ChainReadError::Certificate { height: 10, .. }
                    ))
                ),
                "changed aggregate must fail certificate verification: {rejected:?}"
            );
            assert_eq!(counts.qcs, [10]);
        }
        assert_eq!(counts.frames, [10]);
        assert_eq!(prefix.prefix.tip.height(), 9);
    }
    let (_, qc) = decode_certificate(original.commit_certificate().unwrap()).unwrap();
    for (signers, expected) in [
        (Signers::BelowQuorum, CertError::TooFewSigners),
        (Signers::All, CertError::TooManySigners),
    ] {
        let invalid = chain.commit_qc(10, qc.block_hash, qc.result, signers);
        let tampered = with_parts(&original, |_, qc, _| *qc = invalid);
        assert_eq!(
            crate::execution_attempt::expect_completed_rejection(
                prefix.push(tampered).unwrap_err()
            ),
            ChainReadError::Certificate {
                height: 10,
                error: expected,
            }
        );
        assert_eq!(prefix.prefix.tip.height(), 9);
    }
    let (boundary, genesis) = prefix.push(original.clone()).unwrap().into_parts();
    assert!(genesis.is_none());

    assert!(boundary.commitment().schedule.boundary.is_some());
    let qc = boundary.commit_qc().unwrap();

    assert_eq!(qc.signers.count_ones(), 3);

    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        boundary.block(),
        &original
    ));
}

/// Shape reuse binds the complete context, while each subsequent QC remains independently
/// mandatory. Failed shape or signature checks never advance the streamed cursor.
#[test]
fn warmed_epoch_shape_rejects_substituted_context_and_still_checks_each_qc() {
    let (chain, _) = chain();
    let id = ChainId::from("sumeragi-certified-test-chain");
    let mut prefix = CertifiedPrefix::new(&id, chain.network_id(), frame(&chain, 1)).unwrap();
    prefix.push(frame(&chain, 2)).unwrap();
    let original = frame(&chain, 3);
    for mutate_keys in [false, true] {
        let changed = with_parts(&original, |_, _, preimage| {
            let (original_x, mut commitment) = fixture_result_parts(preimage);
            if mutate_keys {
                commitment.schedule.current.committee[0].proof_of_possession[0] ^= 1;
            } else {
                commitment.schedule.current.leader_seed = [0; 32];
            }
            // Keep the compact wire's equality requirement intact, so this is a real decoded
            // same-epoch-number substitution rather than a serialization refusal.
            let epoch = commitment.schedule.current.clone();
            for slot in [
                &mut commitment.schedule.next,
                &mut commitment.schedule.after_next,
            ] {
                let schedule::ScheduledSlot::Ready(config) = slot else {
                    panic!("permissioned fixture has ready slots");
                };
                config.epoch = epoch.clone();
            }
            *preimage = fixture_result_preimage(&original_x, &commitment);
        });
        assert!(matches!(
            prefix.push(changed),
            Err(ExecutionAttemptError::Rejected(ChainReadError::Malformed {
                height: 3,
                ..
            }))
        ));
        assert_eq!(prefix.prefix.tip.height(), 2);
    }
    let forged = with_parts(&original, |_, qc, _| qc.agg_sig.0[5] ^= 1);
    assert!(matches!(
        prefix.push(forged),
        Err(ExecutionAttemptError::Rejected(
            ChainReadError::Certificate { height: 3, .. }
        ))
    ));
    assert_eq!(prefix.prefix.tip.height(), 2);
    prefix
        .push(original)
        .expect("unchanged original height can still verify");
    prefix.push(frame(&chain, 4)).unwrap();
}

/// Reusing immutable epoch shape does not reuse any positive durable-certificate verdict,
/// either when this reader restarts its prefix or when a fresh view creates another reader.
#[test]
fn warmed_reader_rechecks_durable_prefix_and_fresh_view_after_body_removal() {
    let (chain, _) = chain();
    let view = chain.state().view();
    let reader = CertifiedChain::new(&view).unwrap();
    reader.certified(2).unwrap();
    let original = frame(&chain, 3);
    let forged = with_parts(&original, |_, qc, _| qc.agg_sig.0[5] ^= 1);
    assert!(matches!(
        reader.check_certificate(forged, 3),
        Err(ExecutionAttemptError::Rejected(
            ChainReadError::Certificate { height: 3, .. }
        ))
    ));
    reader.certified(3).unwrap();
    chain
        .kura()
        .corrupt_canonical_body_for_testing(NonZeroUsize::new(2).unwrap())
        .unwrap();
    assert!(reader.certified(3).is_err());
    let fresh = chain.state().view();
    assert!(CertifiedChain::new(&fresh).unwrap().certified(3).is_err());
}

/// A standalone structural read always owns a fresh scope and rejects the same malformed
/// original bytes as a warmed scope; neither form establishes finality by itself.
#[test]
fn standalone_and_scoped_frame_reads_agree_without_skipping_shape_checks() {
    let (chain, _) = chain();
    let original = frame(&chain, 3);
    let mut validation = EpochValidationScope::new();
    read_frame_with_validation(frame(&chain, 2), 2, chain.root_scope(), &mut validation).unwrap();
    let fresh = read_frame(original.clone(), 3, chain.root_scope()).unwrap();
    let reused =
        read_frame_with_validation(original.clone(), 3, chain.root_scope(), &mut validation)
            .unwrap();
    assert_eq!(fresh.commitment(), reused.commitment());
    assert_eq!(fresh.id(), reused.id());
    let changed = with_parts(&original, |_, _, preimage| {
        let (original_x, mut commitment) = fixture_result_parts(preimage);
        commitment.schedule.height += 1;
        *preimage = fixture_result_preimage(&original_x, &commitment);
    });
    let fresh_error = read_frame(changed.clone(), 3, chain.root_scope()).unwrap_err();
    let reused_error =
        read_frame_with_validation(changed, 3, chain.root_scope(), &mut validation).unwrap_err();
    match (&fresh_error, &reused_error) {
        (ExecutionAttemptError::Rejected(actual), ExecutionAttemptError::Rejected(expected)) => {
            assert_eq!(actual, expected)
        }
        (actual, expected) => panic!("expected completed rejections: {actual:?} != {expected:?}"),
    }
    assert!(matches!(
        fresh_error,
        ExecutionAttemptError::Rejected(ChainReadError::Malformed { height: 3, .. })
    ));
}

/// Pure epoch-shape reuse must still admit and authenticate every actual source,
/// and a later read of the same State cut must refuse a newly corrupted ancestor.
#[test]
fn scoped_reverse_walk_reads_all_original_frames_and_rechecks_corrupt_ancestors() {
    let (chain, _) = chain();
    let view = chain.state().view();
    let mut admitted = 0;
    let mut receipts = Vec::new();
    let (result, counts) = relation_counts::measure(|| {
        view.canonical_history().visit_executed_backwards(
            NonZeroUsize::new(1).unwrap(),
            NonZeroUsize::new(5).unwrap(),
            |items, bytes| {
                assert_eq!(items, 1);
                assert!(bytes > 0);
                admitted += 1;
                Ok(())
            },
            |receipt| {
                let original = read_frame(
                    frame(&chain, receipt.height()),
                    receipt.height(),
                    chain.root_scope(),
                )
                .unwrap();
                assert_eq!(receipt.id(), original.id());
                assert_eq!(receipt.commitment(), original.commitment());
                assert_eq!(
                    receipt.block().encode_wire().unwrap(),
                    original.block().encode_wire().unwrap()
                );
                receipts.push(receipt.height());
                Ok(())
            },
        )
    });
    result.unwrap();
    assert_eq!(admitted, 5);
    assert_eq!(receipts, [5, 4, 3, 2, 1]);
    assert_eq!(counts.frames, [5, 5, 4, 4, 3, 3, 2, 2, 1, 1]);
    assert!(
        counts.qcs.is_empty(),
        "local QC subsets do not select deterministic execution identity"
    );
    chain
        .kura()
        .corrupt_canonical_body_for_testing(NonZeroUsize::new(2).unwrap())
        .unwrap();
    for fresh in [false, true] {
        let next = chain.state().view();
        let source = if fresh {
            next.canonical_history()
        } else {
            view.canonical_history()
        };
        let (result, counts) = relation_counts::measure(|| {
            source.executed_receipt(NonZeroUsize::new(1).unwrap(), |_, _| Ok(()))
        });
        assert!(result.is_err());
        assert_eq!(counts.frames, [5, 4, 3]);
        assert!(counts.qcs.is_empty());
    }
}

/// Both finish forms consume the same complete native receipts and advance identical authority.
#[test]
fn checked_prefix_finish_matches_original_complete_step_and_authority() {
    let (chain, _) = chain();
    let id = ChainId::from("sumeragi-certified-test-chain");
    let mut original = CertifiedPrefix::new(&id, chain.network_id(), frame(&chain, 1)).unwrap();
    let mut projected = CertifiedPrefix::new(&id, chain.network_id(), frame(&chain, 1)).unwrap();
    let summarize = |step: CertifiedPrefixStep| {
        let (current, genesis) = step.into_parts();
        (
            current.id(),
            current.result(),
            current.height(),
            current.verification(),
            genesis.map(|anchor| {
                (
                    anchor.committed().id(),
                    anchor.committed().result(),
                    anchor.successor(),
                )
            }),
        )
    };
    let mut calls = 0;
    for height in 2..=5 {
        let expected = summarize(original.push(frame(&chain, height)).unwrap());
        let actual = projected
            .push_with_finish(frame(&chain, height), None, |step| {
                calls += 1;
                summarize(step)
            })
            .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(calls, height - 1);
        assert_eq!(projected.prefix.tip.id(), original.prefix.tip.id());
        assert_eq!(
            projected.current_epoch_context(),
            original.current_epoch_context()
        );
    }
}

/// A failed read/QC never runs finish, changes the cursor or erases original local refusal.
#[test]
fn checked_prefix_finish_preserves_refusal_rejection_and_same_source_retry() {
    let (chain, _) = chain();
    let id = ChainId::from("sumeragi-certified-test-chain");
    let mut original = CertifiedPrefix::new(&id, chain.network_id(), frame(&chain, 1)).unwrap();
    let mut projected = CertifiedPrefix::new(&id, chain.network_id(), frame(&chain, 1)).unwrap();
    let retained = projected.prefix.tip.id();
    let successor = frame(&chain, 2);
    // The first successor read is the actual consensus-header decoder. Prove the
    // same field-byte refusal separately instead of reconstructing numeric errors.
    let header_refusal = norito::core::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 128),
        || {
            norito::core::classify_decode_attempt(|| {
                norito::decode_canonical::<BlockHeader>(
                    successor.commit_certificate().unwrap().consensus_header(),
                )
            })
        },
    )
    .unwrap_err()
    .into_local_refusal()
    .expect("actual original consensus-header decoder cause");
    let mut calls = 0;
    let refusal = norito::core::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 128),
        || {
            projected.push_with_finish(successor.clone(), None, |_| {
                calls += 1;
                false
            })
        },
    )
    .unwrap_err();
    let original_refusal = norito::core::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 128),
        || original.push(successor.clone()),
    )
    .unwrap_err();
    let (ExecutionAttemptError::Deferred(actual), ExecutionAttemptError::Deferred(expected)) =
        (&refusal, &original_refusal)
    else {
        panic!("both original reads must retain decoder refusals");
    };
    assert_eq!(actual.reason(), expected.reason());
    assert_eq!(actual.phase(), expected.phase());
    assert!(actual.allocation_refusal().is_none() && expected.allocation_refusal().is_none());
    assert!(actual.verification_refusal().is_none() && expected.verification_refusal().is_none());
    let actual = actual.decode_refusal().expect("original decoder owner");
    let expected = expected
        .decode_refusal()
        .expect("independent decoder owner");
    assert_eq!(actual.kind(), expected.kind());
    assert_eq!(actual.resource_error(), expected.resource_error());
    assert_eq!(actual.kind(), header_refusal.kind());
    assert_eq!(actual.resource_error(), header_refusal.resource_error());
    assert_ne!(actual, &header_refusal);
    assert_ne!(expected, &header_refusal);
    assert_eq!(actual.allocation_bytes(), expected.allocation_bytes());
    assert_ne!(
        actual, expected,
        "independently entered budget scopes have distinct original owners"
    );
    assert!(matches!(refusal, ExecutionAttemptError::Deferred(_)));
    assert_eq!(calls, 0);
    assert_eq!(projected.prefix.tip.id(), retained);
    assert_eq!(original.prefix.tip.id(), retained);
    for changed in [
        frame(&chain, 3),
        with_parts(&successor, |_, qc, _| qc.agg_sig.0[5] ^= 1),
    ] {
        let expected = original.push(changed.clone()).unwrap_err();
        let actual = projected
            .push_with_finish(changed, None, |_| {
                calls += 1;
                false
            })
            .unwrap_err();
        match (&actual, &expected) {
            (
                ExecutionAttemptError::Rejected(actual),
                ExecutionAttemptError::Rejected(expected),
            ) => assert_eq!(actual, expected),
            (actual, expected) => {
                panic!("expected completed rejections: {actual:?} != {expected:?}")
            }
        }
        assert!(matches!(actual, ExecutionAttemptError::Rejected(_)));
        assert_eq!(calls, 0);
        assert_eq!(projected.prefix.tip.id(), retained);
        assert_eq!(original.prefix.tip.id(), retained);
    }
    let (normal, anchor) = original.push(successor.clone()).unwrap().into_parts();
    let checked = projected
        .push_with_finish(successor, None, |step| {
            calls += 1;
            step.has_genesis_anchor()
        })
        .unwrap();
    assert!(checked && anchor.is_some());
    assert_eq!(calls, 1);
    assert_eq!(projected.prefix.tip.id(), normal.id());
    assert_eq!(
        projected.current_epoch_context(),
        original.current_epoch_context()
    );
}

/// An admitted prefix initializes its source fence and preserves ordinary verification.
#[test]
fn admitted_prefix_initializes_every_field_like_the_owned_constructor() {
    let (chain, _) = chain();
    let id = ChainId::from("sumeragi-certified-test-chain");
    let mut owned = CertifiedPrefix::new(&id, chain.network_id(), frame(&chain, 1)).unwrap();
    let prefix_bytes = std::mem::size_of::<CertifiedPrefix>();
    let authority_bytes =
        funded_authority::FundedPrefixAuthority::allocation_bytes(owned.current_epoch_context())
            .unwrap();
    let budget = iroha_allocation::AllocationBudget::new(
        prefix_bytes
            + authority_bytes
            + std::mem::size_of::<CommittedBlock>()
            + std::mem::size_of::<CertifiedResultV1>(),
    );
    let mut slot =
        CertifiedPrefix::new_admitted(&id, chain.network_id(), frame(&chain, 1), &budget).unwrap();
    assert_eq!(budget.reserved_bytes(), prefix_bytes + authority_bytes);
    let admitted = &mut slot.as_mut_slice()[0];
    assert_eq!(admitted.instance(), owned.instance());
    assert_eq!(admitted.root_scope, owned.root_scope);
    assert_eq!(
        admitted.current_epoch_context(),
        owned.current_epoch_context()
    );
    assert_eq!(admitted.prefix.tip.id(), owned.prefix.tip.id());
    assert_eq!(admitted.prefix.proof_source, None);
    assert_eq!(admitted.prefix.proof_source, owned.prefix.proof_source);
    let expected = owned.push(frame(&chain, 2)).unwrap();
    let actual = admitted.push(frame(&chain, 2)).unwrap();
    assert_eq!(actual.current.id(), expected.current.id());
    assert!(actual.has_genesis_anchor() && expected.has_genesis_anchor());
    assert_eq!(admitted.prefix.proof_source, None);
    assert_eq!(budget.reserved_bytes(), prefix_bytes + authority_bytes);
    drop(slot);
    assert_eq!(budget.reserved_bytes(), 0);
}

/// Admitted completion preserves every original native receipt and refunds its exact slots.
#[test]
fn admitted_prepared_prefix_refusal_retains_metadata_slots_and_original_release() {
    use std::{
        future::Future as _,
        pin::Pin,
        task::{Context, Waker},
    };

    let (chain, _) = chain();
    let id = ChainId::from("sumeragi-certified-test-chain");
    let budget = iroha_allocation::AllocationBudget::new(32 << 20);
    let mut prefix =
        CertifiedPrefix::new_admitted(&id, chain.network_id(), frame(&chain, 1), &budget).unwrap();
    let authority_bytes = funded_authority::FundedPrefixAuthority::allocation_bytes(
        prefix.as_slice()[0].current_epoch_context(),
    )
    .unwrap();
    let base_bytes = std::mem::size_of::<CertifiedPrefix>() + authority_bytes;
    assert_eq!(budget.reserved_bytes(), base_bytes);
    let source = frame(&chain, 2);
    let artifacts = artifacts::PrefixArtifactsRead::new(source.clone(), budget.clone())
        .complete(&budget)
        .unwrap_or_else(|(_, error)| panic!("genuine prepared metadata: {error}"));
    let header_pointer = std::ptr::from_ref::<BlockHeader>(artifacts.header());
    let header_bytes = artifacts.header().allocation_bytes();
    let (qc, availability, payload) = artifacts
        .clone()
        .into_parts(&source, &PrefixHeader::Funded(artifacts.header().clone()))
        .unwrap();
    let qc_pointer = std::ptr::from_ref::<Qc>(&qc);
    let qc_bytes = qc.allocation_bytes();
    drop((availability, payload));
    let registration_bytes =
        iroha_allocation::release::ReleaseRegistration::allocation_layout().size();
    let mut reservation = budget.try_reserve_bytes(registration_bytes).unwrap();
    let mut registration =
        iroha_allocation::release::ReleaseRegistration::from_reservation(&mut reservation).unwrap();
    drop(reservation);
    let original_bytes = budget.reserved_bytes();
    let frame_bytes = std::mem::size_of::<CommittedBlock>();
    let external = budget
        .try_reserve_bytes(budget.limit_bytes() - original_bytes - frame_bytes)
        .unwrap();
    let prior = prefix.as_slice()[0].prefix.tip.id();
    let mut read = AdmittedPrefixPush::default();
    let failure = read
        .complete_prepared_with_finish(&mut prefix.as_mut_slice()[0], &artifacts, &budget, |_| {
            panic!("refused frame cannot publish a receipt")
        })
        .unwrap_err();
    let ExecutionAttemptError::Deferred(refusal) = failure else {
        panic!("original result-slot capacity refusal")
    };
    assert!(
        read.frame.committed.is_some(),
        "HC951 admitted prefix refusal must retain its original frame slot"
    );
    let slot_pointer = read.frame.committed.as_ref().unwrap().as_slice().as_ptr();
    assert!(read.frame.result.is_none());
    assert_eq!(prefix.as_slice()[0].prefix.tip.id(), prior);
    assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
    let Some(iroha_allocation::AllocationRefusal::Capacity {
        requested_bytes,
        release,
        ..
    }) = refusal.allocation_refusal()
    else {
        panic!("original result-slot release observation")
    };
    assert_eq!(*requested_bytes, std::mem::size_of::<CertifiedResultV1>());
    let mut wait = release.clone().wait_for_release(&mut registration);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(Pin::new(&mut wait).poll(&mut cx).is_pending());
    let unrelated = iroha_allocation::AllocationBudget::new(frame_bytes);
    drop(unrelated.try_reserve_bytes(frame_bytes).unwrap());
    assert!(Pin::new(&mut wait).poll(&mut cx).is_pending());
    assert_eq!(
        std::ptr::from_ref::<BlockHeader>(artifacts.header()),
        header_pointer
    );
    assert_eq!(std::ptr::from_ref::<Qc>(&qc), qc_pointer);
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        artifacts.source(),
        &source
    ));
    assert_eq!(
        read.frame.committed.as_ref().unwrap().as_slice().as_ptr(),
        slot_pointer
    );
    drop(external);
    assert!(Pin::new(&mut wait).poll(&mut cx).is_ready());
    drop(wait);
    let certified = read
        .complete_prepared_with_finish(&mut prefix.as_mut_slice()[0], &artifacts, &budget, |step| {
            step.into_parts().0
        })
        .unwrap();
    assert!(read.frame.committed.is_none() && read.frame.result.is_none());
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        certified.committed().block(),
        &source
    ));
    assert_eq!(
        std::ptr::from_ref(certified.committed().header().unwrap()),
        header_pointer
    );
    assert_eq!(
        std::ptr::from_ref(certified.commit_qc().unwrap()),
        qc_pointer
    );
    drop(artifacts);
    drop(qc);
    assert_eq!(
        budget.reserved_bytes(),
        base_bytes + header_bytes + qc_bytes + registration_bytes
    );
    drop(certified);
    assert_eq!(
        budget.reserved_bytes(),
        base_bytes + header_bytes + registration_bytes
    );
    drop(prefix);
    drop(registration);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn admitted_frame_refusal_rejects_foreign_pool_and_replacement_source_before_retry() {
    let (chain, _) = chain();
    let source = frame(&chain, 2);
    let bytes = std::mem::size_of::<CommittedBlock>() + std::mem::size_of::<CertifiedResultV1>();
    let budget = iroha_allocation::AllocationBudget::new(bytes);
    let foreign = iroha_allocation::AllocationBudget::new(bytes);
    let occupied = budget.try_reserve_bytes(bytes).unwrap();
    let mut read = AdmittedFrameRead::default();
    let mut validation = EpochValidationScope::new();
    let scope = chain.committed(2).root_scope();
    assert!(matches!(
        read.initialize(source.clone(), 2, scope, &mut validation, &budget),
        Err(ExecutionAttemptError::Deferred(_))
    ));
    assert!(read.committed.is_none() && read.result.is_none());
    let failure = read.initialize(source.clone(), 2, scope, &mut validation, &foreign);
    assert!(
        matches!(failure, Err(ExecutionAttemptError::Deferred(ref original))
        if original.reason() == ivm::error::ExecutionDeferral::LocalInvariantViolation
            && original.allocation_refusal().is_none()),
        "HC952 admitted frame retry must reject a foreign original pool before allocating"
    );
    assert_eq!(foreign.reserved_bytes(), 0);
    assert_eq!(budget.reserved_bytes(), bytes);
    drop(occupied);
    let shell_budget = iroha_allocation::AllocationBudget::new(
        iroha_data_model::block::SharedSignedBlock::allocation_layout().size(),
    );
    let replacement = iroha_data_model::block::SharedSignedBlock::reserve(&shell_budget)
        .unwrap()
        .initialize(source.as_ref().clone());
    assert!(!iroha_data_model::block::SharedSignedBlock::ptr_eq(
        &replacement,
        &source
    ));
    // Equal bytes re-read into another carrier, or another scope, are local custody faults:
    // no invalid-history verdict may depend on pointer identity.
    let local = |result: Result<(), ExecutionAttemptError<ChainReadError>>| {
        matches!(result, Err(ExecutionAttemptError::Deferred(original))
            if original.reason() == ivm::error::ExecutionDeferral::LocalInvariantViolation
                && original.allocation_refusal().is_none())
    };
    assert!(
        local(read.initialize(replacement, 2, scope, &mut validation, &budget)),
        "HC962 a retained carrier mismatch is local custody, never a history verdict"
    );
    let other_scope = SumeragiRootScope::Dataspace {
        parent_network_id: chain.network_id(),
        dataspace_id: iroha_model_base::topology::DataSpaceId::new(7),
    };
    assert!(
        local(read.initialize(source.clone(), 2, other_scope, &mut validation, &budget)),
        "HC962 a retained scope mismatch is local custody, never a history verdict"
    );
    // The original carrier at another height is still a genuine input rejection.
    assert!(matches!(
        read.initialize(source.clone(), 3, scope, &mut validation, &budget),
        Err(ExecutionAttemptError::Rejected(
            ChainReadError::HeaderMismatch { height: 3 }
        ))
    ));
    assert_eq!(budget.reserved_bytes(), 0);
    read.initialize(source.clone(), 2, scope, &mut validation, &budget)
        .unwrap();
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        read.committed().block(),
        &source
    ));
    drop(read);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn admitted_prefix_rebuilds_funded_configuration_for_same_epoch_parameter_change() {
    with_same_epoch_parameter_change(assert_same_epoch_parameter_change);
}

// Genesis admits 16 KiB of transactions per block. A permitted lag-two update raises the
// block cap that the signed-availability verifier consumes, and the activation height
// carries a genuine payload above the original cap: a stale native configuration rejects it.
const ORIGINAL_MAX_BLOCK_BYTES: u32 =
    iroha_data_model::parameter::system::BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES + 16 * 1024;
const RAISED_MAX_BLOCK_BYTES: u32 =
    iroha_data_model::parameter::system::BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES + 128 * 1024;

#[inline(never)]
fn with_same_epoch_parameter_change(check: fn(&CertifiedTestChain)) {
    use iroha_data_model::{
        isi::{Grant, SetParameter},
        parameter::{Parameter, SumeragiParameter, TransactionParameter},
        privacy::{PrivacyConsensusLimitsV1, PrivacyConsensusPolicyV1},
    };
    use std::num::{NonZeroU32, NonZeroU64};

    const INCLUDABLE: u32 = 16 * 1024;
    let mut world = World::new();
    // Every contained privacy byte bound must fit the small genesis transaction cap.
    let mut limits = PrivacyConsensusLimitsV1::taira_default();
    limits.max_proof_bytes_per_action = INCLUDABLE;
    limits.max_action_bytes = INCLUDABLE;
    limits.max_privacy_bytes_per_transaction = INCLUDABLE;
    limits.max_privacy_bytes_per_block = INCLUDABLE;
    limits.max_statement_and_encrypted_output_bytes_per_transaction = INCLUDABLE;
    limits
        .validate()
        .expect("coherent small fixture privacy limits");
    world.privacy_consensus_policy = mv::cell::Cell::new(PrivacyConsensusPolicyV1 {
        current_limits: limits,
        pending_tightening: None,
    });
    let mut config = TestChainConfig::new(world, 1_000);
    config
        .genesis_parameters
        .push(Parameter::Sumeragi(SumeragiParameter::MaxBlockBytes(
            NonZeroU32::new(ORIGINAL_MAX_BLOCK_BYTES).unwrap(),
        )));
    config
        .genesis_parameters
        .push(Parameter::Transaction(TransactionParameter::MaxTxBytes(
            NonZeroU64::new(u64::from(INCLUDABLE)).unwrap(),
        )));
    let author = config.genesis_key.clone();
    config.genesis_instructions.push(
        Grant::account_permission(
            iroha_executor_data_model::permission::parameter::CanSetParameters,
            iroha_data_model::account::AccountId::new(author.public_key().clone()),
        )
        .into(),
    );
    let mut chain = Box::new(CertifiedTestChain::start(config).unwrap());
    let update = chain.sign(
        &author,
        [
            SetParameter::new(Parameter::Sumeragi(SumeragiParameter::MaxBlockBytes(
                NonZeroU32::new(RAISED_MAX_BLOCK_BYTES).unwrap(),
            )))
            .into(),
        ],
        1_500,
    );
    assert_eq!(chain.commit_at(2_000, vec![update]), [true]);
    chain.commit_at(3_000, Vec::new());
    // Six near-cap transactions fit only the raised cap that activates at height 4.
    let large = (0..6_u64)
        .map(|index| {
            chain.sign(
                &author,
                [InstructionBox::from(Log::new(
                    Level::DEBUG,
                    "x".repeat(15_000),
                ))],
                3_500 + index,
            )
        })
        .collect();
    assert_eq!(chain.commit_at(4_000, large), [true; 6]);
    assert!(
        chain.committed(4).header().unwrap().payload_len > ORIGINAL_MAX_BLOCK_BYTES,
        "the activation height carries a payload above the original cap"
    );
    check(&chain);
}

#[inline(never)]
fn assert_same_epoch_parameter_change(chain: &CertifiedTestChain) {
    let id = ChainId::from("sumeragi-certified-test-chain");
    let original = chain.committed(1);
    let authority_bytes = funded_authority::FundedPrefixAuthority::allocation_bytes(
        &original.commitment().schedule.current,
    )
    .unwrap();
    let prefix_bytes = std::mem::size_of::<CertifiedPrefix>();
    let budget = iroha_allocation::AllocationBudget::new(
        prefix_bytes
            + 2 * authority_bytes
            + std::mem::size_of::<CommittedBlock>()
            + std::mem::size_of::<CertifiedResultV1>(),
    );
    // The unfunded portable walk derives each configuration afresh: it is the verdict oracle.
    let mut portable = CertifiedPrefix::new(&id, chain.network_id(), frame(chain, 1)).unwrap();
    let mut slot =
        CertifiedPrefix::new_admitted(&id, chain.network_id(), frame(chain, 1), &budget).unwrap();
    let prefix = &mut slot.as_mut_slice()[0];
    let incumbent = prefix.prefix.authority.clone();
    let initial_pointer = std::ptr::from_ref(incumbent.material());
    let initial_params = incumbent.funded_config().unwrap().params;
    assert_eq!(initial_params.max_block_bytes, ORIGINAL_MAX_BLOCK_BYTES);
    let mut read = AdmittedPrefixPush::default();
    for height in 2..=4 {
        let expected = prefix
            .prefix
            .schedule
            .ready(height)
            .unwrap()
            .params
            .to_core();
        let source = frame(chain, height);
        let oracle = portable
            .push(source.clone())
            .map(|step| step.into_parts().0.id());
        let funded = read
            .complete_with_finish(prefix, source, &budget, |step| step.into_parts().0.id())
            .map_err(|error| format!("{error:?}"));
        assert_eq!(
            funded.as_ref().ok(),
            oracle.as_ref().ok(),
            "HC953 same-epoch parameter activation must verify with the active native configuration: {funded:?}"
        );
        assert!(oracle.is_ok(), "genuine height {height}");
        assert_eq!(prefix.current_epoch_context(), incumbent.material());
        assert_eq!(
            prefix.prefix.authority.funded_config().unwrap().params,
            expected,
            "the funded native configuration follows the lag-two activation"
        );
        if height < 4 {
            assert_eq!(
                std::ptr::from_ref(prefix.current_epoch_context()),
                initial_pointer
            );
            assert_eq!(budget.reserved_bytes(), prefix_bytes + authority_bytes);
        } else {
            assert_eq!(expected.max_block_bytes, RAISED_MAX_BLOCK_BYTES);
            assert_ne!(
                std::ptr::from_ref(prefix.current_epoch_context()),
                initial_pointer
            );
            assert_eq!(budget.reserved_bytes(), prefix_bytes + 2 * authority_bytes);
        }
    }
    assert_eq!(incumbent.funded_config().unwrap().params, initial_params);
    drop(incumbent);
    assert_eq!(budget.reserved_bytes(), prefix_bytes + authority_bytes);
    drop(read);
    drop(slot);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn admitted_parameter_change_retains_pending_authority_across_later_scratch_refusal() {
    with_same_epoch_parameter_change(assert_pending_parameter_authority_survives_refusal);
}

#[inline(never)]
fn assert_pending_parameter_authority_survives_refusal(chain: &CertifiedTestChain) {
    use std::{
        future::Future as _,
        pin::Pin,
        task::{Context, Waker},
    };

    let id = ChainId::from("sumeragi-certified-test-chain");
    let budget = iroha_allocation::AllocationBudget::new(32 << 20);
    let mut prefix =
        CertifiedPrefix::new_admitted(&id, chain.network_id(), frame(chain, 1), &budget).unwrap();
    for height in 2..=3 {
        prefix.as_mut_slice()[0].push(frame(chain, height)).unwrap();
    }
    let prior = prefix.as_slice()[0].prefix.tip.id();
    let incumbent = prefix.as_slice()[0].prefix.authority.clone();
    let authority_bytes =
        funded_authority::FundedPrefixAuthority::allocation_bytes(incumbent.material()).unwrap();
    let source = frame(chain, 4);
    let artifacts = artifacts::PrefixArtifactsRead::new(source.clone(), budget.clone())
        .complete(&budget)
        .unwrap_or_else(|(_, error)| panic!("genuine parameter-activation artifacts: {error}"));
    let mut read = AdmittedPrefixPush::default();
    let active = &mut prefix.as_mut_slice()[0];
    read.frame
        .initialize_prepared(
            source.clone(),
            4,
            active.root_scope,
            &mut active.prefix.validation,
            &budget,
            Some(artifacts.header().clone()),
        )
        .unwrap();
    let slot_pointer = read.frame.committed.as_ref().unwrap().as_slice().as_ptr();
    let shape = active
        .prefix
        .schedule
        .ready(4)
        .unwrap()
        .epoch
        .da_layout
        .shape(u64::from(artifacts.header().payload_len))
        .unwrap();
    let scratch_bytes =
        shape.encoded_bytes() + shape.workspace_words() * std::mem::size_of::<u16>();
    let registration_bytes =
        iroha_allocation::release::ReleaseRegistration::allocation_layout().size();
    let mut registration_credit = budget.try_reserve_bytes(registration_bytes).unwrap();
    let mut registration =
        iroha_allocation::release::ReleaseRegistration::from_reservation(&mut registration_credit)
            .unwrap();
    drop(registration_credit);
    let retained = budget.reserved_bytes();
    let external = budget
        .try_reserve_bytes(budget.limit_bytes() - retained - authority_bytes)
        .unwrap();
    let failure = read
        .complete_prepared_with_finish(active, &artifacts, &budget, |_| {
            panic!("refused scratch cannot install the candidate")
        })
        .unwrap_err();
    let ExecutionAttemptError::Deferred(original) = failure else {
        panic!("original RS16 scratch capacity refusal")
    };
    let Some(iroha_allocation::AllocationRefusal::Capacity {
        requested_bytes,
        release,
        ..
    }) = original.allocation_refusal()
    else {
        panic!("actual original scratch release observation")
    };
    assert_eq!(*requested_bytes, scratch_bytes);
    let mut wait = release.clone().wait_for_release(&mut registration);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(
        Pin::new(&mut wait).poll(&mut cx).is_pending(),
        "HC957 later scratch refusal must retain the original pending authority without satisfying its own release wait"
    );
    let candidate = read
        .pending_authority
        .as_ref()
        .expect("same authority survives refusal");
    let candidate_pointer = std::ptr::from_ref(candidate.projection().material);
    assert_eq!(
        candidate.config().params.max_block_bytes,
        RAISED_MAX_BLOCK_BYTES
    );
    assert_ne!(
        incumbent.funded_config().unwrap().params.max_block_bytes,
        RAISED_MAX_BLOCK_BYTES
    );
    assert_eq!(active.prefix.tip.id(), prior);
    assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
    assert_eq!(
        read.frame.committed.as_ref().unwrap().as_slice().as_ptr(),
        slot_pointer
    );
    let foreign = iroha_allocation::AllocationBudget::new(authority_bytes);
    drop(foreign.try_reserve_bytes(authority_bytes).unwrap());
    assert!(Pin::new(&mut wait).poll(&mut cx).is_pending());

    let retained_candidate = read.pending_authority.take().unwrap();
    let PrefixAuthority::Funded(stale_parameters) = &incumbent else {
        panic!("original admitted incumbent")
    };
    read.pending_authority = Some(stale_parameters.clone());
    let mismatched = read
        .complete_prepared_with_finish(active, &artifacts, &budget, |_| {
            panic!("stale pending native parameters cannot replace the exact candidate")
        })
        .unwrap_err();
    let ExecutionAttemptError::Deferred(mismatched) = mismatched else {
        panic!("pending owner mismatch is local")
    };
    assert_eq!(
        mismatched.reason(),
        ivm::error::ExecutionDeferral::LocalInvariantViolation
    );
    assert!(mismatched.allocation_refusal().is_none());
    read.pending_authority = Some(retained_candidate);
    assert!(Pin::new(&mut wait).poll(&mut cx).is_pending());

    let foreign_candidate = funded_authority::FundedPrefixAuthority::admit(
        active.prefix.schedule.ready(4).unwrap(),
        4,
        &mut EpochValidationScope::new(),
        &foreign,
    )
    .unwrap();
    let retained_candidate = read.pending_authority.replace(foreign_candidate).unwrap();
    let mismatched = read
        .complete_prepared_with_finish(active, &artifacts, &budget, |_| {
            panic!("foreign funded candidate cannot replace original authority custody")
        })
        .unwrap_err();
    let ExecutionAttemptError::Deferred(mismatched) = mismatched else {
        panic!("foreign candidate is a local invariant violation")
    };
    assert_eq!(
        mismatched.reason(),
        ivm::error::ExecutionDeferral::LocalInvariantViolation
    );
    assert!(mismatched.allocation_refusal().is_none());
    read.pending_authority = Some(retained_candidate);
    assert_eq!(foreign.reserved_bytes(), 0);
    assert!(Pin::new(&mut wait).poll(&mut cx).is_pending());

    let repeated = read
        .complete_prepared_with_finish(active, &artifacts, &budget, |_| {
            panic!("unreleased original scratch still cannot complete")
        })
        .unwrap_err();
    assert!(matches!(repeated, ExecutionAttemptError::Deferred(_)));
    assert_eq!(
        std::ptr::from_ref(
            read.pending_authority
                .as_ref()
                .unwrap()
                .projection()
                .material
        ),
        candidate_pointer
    );
    assert!(Pin::new(&mut wait).poll(&mut cx).is_pending());
    drop(external);
    assert!(Pin::new(&mut wait).poll(&mut cx).is_ready());
    drop(wait);
    read.complete_prepared_with_finish(active, &artifacts, &budget, |step| {
        assert_eq!(step.into_parts().0.height(), 4);
    })
    .unwrap();
    assert!(read.pending_authority.is_none());
    assert_eq!(
        std::ptr::from_ref(active.current_epoch_context()),
        candidate_pointer
    );
    assert_eq!(
        active
            .prefix
            .authority
            .funded_config()
            .unwrap()
            .params
            .max_block_bytes,
        RAISED_MAX_BLOCK_BYTES
    );
    drop(read);
    drop(incumbent);
    drop(artifacts);
    drop(prefix);
    drop(registration);
    assert_eq!(budget.reserved_bytes(), 0);
}

/// Admitted completion preserves every original native receipt and refunds its exact slots.
#[test]
fn admitted_prefix_finish_matches_original_step_and_retains_original_slot_until_finish() {
    let (chain, _) = chain();
    let id = ChainId::from("sumeragi-certified-test-chain");
    let mut original = CertifiedPrefix::new(&id, chain.network_id(), frame(&chain, 1)).unwrap();
    let mut admitted = CertifiedPrefix::new(&id, chain.network_id(), frame(&chain, 1)).unwrap();
    let frame_bytes = std::alloc::Layout::array::<CommittedBlock>(1)
        .unwrap()
        .size();
    let result_bytes = std::alloc::Layout::array::<CertifiedResultV1>(1)
        .unwrap()
        .size();
    let budget = iroha_allocation::AllocationBudget::new(frame_bytes + result_bytes);
    let summarize = |step: CertifiedPrefixStep| {
        let (current, genesis) = step.into_parts();
        (
            current.id(),
            current.result(),
            current.height(),
            current.verification(),
            genesis.map(|anchor| {
                (
                    anchor.committed().id(),
                    anchor.committed().result(),
                    anchor.successor(),
                )
            }),
        )
    };
    for height in 2..=5 {
        let expected = summarize(original.push(frame(&chain, height)).unwrap());
        let actual = admitted
            .push_admitted_with_finish(frame(&chain, height), &budget, |step| {
                assert_eq!(budget.reserved_bytes(), frame_bytes);
                summarize(step)
            })
            .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(admitted.prefix.tip.id(), original.prefix.tip.id());
        assert_eq!(
            admitted.current_epoch_context(),
            original.current_epoch_context()
        );
    }
}

/// Original-pool slot and inherited decoder refusals retain the exact cursor for genuine retry.
#[test]
fn admitted_prefix_finish_preserves_original_pool_refusal_and_certificate_error_order() {
    let (chain, _) = chain();
    let id = ChainId::from("sumeragi-certified-test-chain");
    let mut original = CertifiedPrefix::new(&id, chain.network_id(), frame(&chain, 1)).unwrap();
    let mut admitted = CertifiedPrefix::new(&id, chain.network_id(), frame(&chain, 1)).unwrap();
    let frame_layout = std::alloc::Layout::array::<CommittedBlock>(1).unwrap();
    let result_layout = std::alloc::Layout::array::<CertifiedResultV1>(1).unwrap();
    let bytes = frame_layout.size() + result_layout.size();
    let budget = iroha_allocation::AllocationBudget::new(bytes);
    let blocker = budget
        .try_reserve_layouts([frame_layout, result_layout])
        .unwrap();
    let successor = frame(&chain, 2);
    // The first successor read is the actual consensus-header decoder. Prove the
    // same field-byte refusal separately instead of reconstructing numeric errors.
    let header_refusal = norito::core::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 128),
        || {
            norito::core::classify_decode_attempt(|| {
                norito::decode_canonical::<BlockHeader>(
                    successor.commit_certificate().unwrap().consensus_header(),
                )
            })
        },
    )
    .unwrap_err()
    .into_local_refusal()
    .expect("actual original consensus-header decoder cause");
    let retained = admitted.prefix.tip.id();
    let mut calls = 0;
    let refusal = admitted
        .push_admitted_with_finish(successor.clone(), &budget, |_| {
            calls += 1;
            false
        })
        .unwrap_err();
    assert!(matches!(refusal, ExecutionAttemptError::Deferred(_)));
    assert_eq!(budget.reserved_bytes(), bytes);
    assert_eq!(admitted.prefix.tip.id(), retained);
    assert_eq!(calls, 0);
    let discontinuous = admitted
        .push_admitted_with_finish(frame(&chain, 3), &budget, |_| {
            calls += 1;
            false
        })
        .unwrap_err();
    assert!(matches!(
        discontinuous,
        ExecutionAttemptError::Rejected(ChainReadError::Discontinuous { height: 3 })
    ));
    assert_eq!(budget.reserved_bytes(), bytes);
    assert_eq!(calls, 0);
    drop(blocker);
    assert_eq!(budget.reserved_bytes(), 0);
    let refusal = norito::core::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 128),
        || {
            admitted.push_admitted_with_finish(successor.clone(), &budget, |_| {
                calls += 1;
                false
            })
        },
    )
    .unwrap_err();
    let expected = norito::core::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 128),
        || original.push(successor.clone()),
    )
    .unwrap_err();
    let (ExecutionAttemptError::Deferred(actual), ExecutionAttemptError::Deferred(expected)) =
        (&refusal, &expected)
    else {
        panic!("both original reads must retain decoder refusals");
    };
    assert_eq!(actual.reason(), expected.reason());
    assert_eq!(actual.phase(), expected.phase());
    assert!(actual.allocation_refusal().is_none() && expected.allocation_refusal().is_none());
    assert!(actual.verification_refusal().is_none() && expected.verification_refusal().is_none());
    let actual = actual.decode_refusal().expect("original decoder owner");
    let expected = expected
        .decode_refusal()
        .expect("independent decoder owner");
    assert_eq!(actual.kind(), expected.kind());
    assert_eq!(actual.resource_error(), expected.resource_error());
    assert_eq!(actual.kind(), header_refusal.kind());
    assert_eq!(actual.resource_error(), header_refusal.resource_error());
    assert_ne!(actual, &header_refusal);
    assert_ne!(expected, &header_refusal);
    assert_eq!(actual.allocation_bytes(), expected.allocation_bytes());
    assert_ne!(
        actual, expected,
        "independently entered budget scopes have distinct original owners"
    );
    assert!(matches!(refusal, ExecutionAttemptError::Deferred(_)));
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(admitted.prefix.tip.id(), retained);
    assert_eq!(calls, 0);
    let forged = with_parts(&successor, |_, qc, _| qc.agg_sig.0[5] ^= 1);
    let expected = original.push(forged.clone()).unwrap_err();
    let actual = admitted
        .push_admitted_with_finish(forged, &budget, |_| {
            calls += 1;
            false
        })
        .unwrap_err();
    match (&actual, &expected) {
        (ExecutionAttemptError::Rejected(actual), ExecutionAttemptError::Rejected(expected)) => {
            assert_eq!(actual, expected)
        }
        (actual, expected) => panic!("expected completed rejections: {actual:?} != {expected:?}"),
    }
    assert!(matches!(actual, ExecutionAttemptError::Rejected(_)));
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(admitted.prefix.tip.id(), retained);
    assert_eq!(calls, 0);
    let (current, anchor) = original.push(successor.clone()).unwrap().into_parts();
    let actual = admitted
        .push_admitted_with_finish(successor, &budget, |step| {
            calls += 1;
            step.has_genesis_anchor()
        })
        .unwrap();
    assert!(actual && anchor.is_some());
    assert_eq!(calls, 1);
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(admitted.prefix.tip.id(), current.id());
    assert_eq!(
        admitted.current_epoch_context(),
        original.current_epoch_context()
    );
}

#[test]
fn walk_parent_link_retains_original_body_and_exact_native_continuity_without_result_copy() {
    with_native_chain(assert_walk_parent_link_retains_original_body);
}

fn assert_walk_parent_link_retains_original_body(
    chain: &CertifiedTestChain,
    _: HashOf<TransactionEntrypoint>,
) {
    let source = frame(chain, 2);
    let budget = iroha_allocation::AllocationBudget::new(
        iroha_data_model::block::SharedSignedBlock::allocation_layout().size(),
    );
    let original = iroha_data_model::block::SharedSignedBlock::reserve(&budget)
        .unwrap()
        .initialize(source.as_ref().clone());
    drop(source);
    let parent = read_frame(original.clone(), 2, chain.root_scope()).unwrap();
    let child = read_frame(frame(chain, 3), 3, chain.root_scope()).unwrap();
    let mut link = WalkParentLink::from_committed(&parent);
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        &link.block,
        &original
    ));
    assert!(link.block.belongs_to(&budget));
    assert_eq!(link.is_extended_by(&child), child.extends(&parent));
    assert!(link.is_extended_by(&child));
    let original_pointer: *const SignedBlock = &raw const *original;
    drop(parent);
    drop(original);
    assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
    assert!(std::ptr::eq::<SignedBlock>(
        &raw const *link.block,
        original_pointer
    ));
    assert!(link.is_extended_by(&child));

    link.height = u64::MAX;
    assert!(
        !link.is_extended_by(&child),
        "height overflow cannot extend"
    );
    link.height = 1;
    assert!(
        !link.is_extended_by(&child),
        "a skipped height cannot extend"
    );
    link.height = 2;
    let core_hash = link.core_hash;
    link.core_hash.0[0] ^= 1;
    assert!(
        !link.is_extended_by(&child),
        "the exact native parent hash is required"
    );
    link.core_hash = core_hash;
    let result = link.result;
    link.result.0[0] ^= 1;
    assert!(
        !link.is_extended_by(&child),
        "the exact parent result is required"
    );
    link.result = result;
    let block = std::mem::replace(&mut link.block, frame(chain, 1));
    assert!(
        !link.is_extended_by(&child),
        "the original iroha parent body is required"
    );
    link.block = block;
    assert!(link.is_extended_by(&child));
    assert!(!link.is_extended_by(&read_frame(frame(chain, 4), 4, chain.root_scope()).unwrap()));
    drop(link);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn one_shot_admitted_push_funds_no_owner_that_could_release_its_own_wait() {
    with_same_epoch_parameter_change(assert_one_shot_push_funds_no_successor_owner);
}

#[inline(never)]
fn assert_one_shot_push_funds_no_successor_owner(chain: &CertifiedTestChain) {
    let id = ChainId::from("sumeragi-certified-test-chain");
    let budget = iroha_allocation::AllocationBudget::new(32 << 20);
    let mut portable = CertifiedPrefix::new(&id, chain.network_id(), frame(chain, 1)).unwrap();
    let mut slot =
        CertifiedPrefix::new_admitted(&id, chain.network_id(), frame(chain, 1), &budget).unwrap();
    let prefix = &mut slot.as_mut_slice()[0];
    for height in 2..=3 {
        portable.push(frame(chain, height)).unwrap();
        prefix.push(frame(chain, height)).unwrap();
    }
    let source = frame(chain, 4);
    let artifacts = artifacts::PrefixArtifactsRead::new(source.clone(), budget.clone())
        .complete(&budget)
        .unwrap_or_else(|(_, error)| panic!("genuine activation artifacts: {error}"));
    // Height 4 needs a rebuilt authority and RS16 scratch. With the original pool exhausted,
    // a one-shot push that funded them would refuse, drop its candidate authority and refund
    // the bytes its own release wait observes. It must admit no such owner at all.
    let external = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    let expected = portable.push(source.clone()).unwrap().into_parts().0.id();
    // Prepared artifacts bind their exact carrier: equal bytes in another carrier are local
    // custody misuse, not a verdict on the history they encode.
    let replacement = crate::block::reserve_block_for_tests().initialize(source.as_ref().clone());
    let misbound = prefix
        .push_with_finish(replacement, Some(artifacts.clone()), |_| ())
        .unwrap_err();
    assert!(
        matches!(misbound, ExecutionAttemptError::Deferred(ref original)
        if original.reason() == ivm::error::ExecutionDeferral::LocalInvariantViolation
            && original.allocation_refusal().is_none())
    );
    assert_eq!(prefix.prefix.tip.height(), 3);
    let (current, genesis) = prefix
        .push_prepared(artifacts)
        .expect("HC963 one-shot pushes admit no successor owner from the original pool")
        .into_parts();
    assert!(genesis.is_none());
    assert_eq!(current.id(), expected);
    assert!(
        prefix.prefix.authority.funded_config().is_none(),
        "the one-shot successor authority stays outside original-pool custody"
    );
    assert_eq!(
        prefix.current_epoch_context(),
        portable.current_epoch_context()
    );
    drop(current);
    drop(external);
    drop(slot);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn one_shot_admitted_push_admits_both_slots_before_a_refusal_can_release_itself() {
    use std::{
        future::Future as _,
        pin::Pin,
        task::{Context, Waker},
    };

    let (chain, _) = chain();
    let id = ChainId::from("sumeragi-certified-test-chain");
    let mut admitted = CertifiedPrefix::new(&id, chain.network_id(), frame(&chain, 1)).unwrap();
    let frame_bytes = std::mem::size_of::<CommittedBlock>();
    let result_bytes = std::mem::size_of::<CertifiedResultV1>();
    let registration_bytes =
        iroha_allocation::release::ReleaseRegistration::allocation_layout().size();
    let budget =
        iroha_allocation::AllocationBudget::new(frame_bytes + result_bytes + registration_bytes);
    let mut credit = budget.try_reserve_bytes(registration_bytes).unwrap();
    let mut registration =
        iroha_allocation::release::ReleaseRegistration::from_reservation(&mut credit).unwrap();
    drop(credit);
    // Room for the receipt slot alone: a per-slot reader would admit it, refuse the result
    // slot, then refund the receipt slot into the release wait it has just returned.
    let external = budget.try_reserve_bytes(result_bytes).unwrap();
    let successor = frame(&chain, 2);
    let refusal = admitted
        .push_admitted_with_finish(successor.clone(), &budget, |_| -> u64 {
            panic!("refused slots cannot publish a receipt")
        })
        .unwrap_err();
    let ExecutionAttemptError::Deferred(refusal) = refusal else {
        panic!("original slot capacity refusal")
    };
    let Some(iroha_allocation::AllocationRefusal::Capacity {
        requested_bytes,
        release,
        ..
    }) = refusal.allocation_refusal()
    else {
        panic!("original slot release observation")
    };
    let mut wait = release.clone().wait_for_release(&mut registration);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(
        Pin::new(&mut wait).poll(&mut cx).is_pending(),
        "HC964 one-shot admitted push cannot satisfy its own release wait"
    );
    assert_eq!(*requested_bytes, frame_bytes + result_bytes);
    assert_eq!(budget.reserved_bytes(), registration_bytes + result_bytes);
    assert_eq!(admitted.prefix.tip.height(), 1);
    let foreign = iroha_allocation::AllocationBudget::new(frame_bytes);
    drop(foreign.try_reserve_bytes(frame_bytes).unwrap());
    assert!(Pin::new(&mut wait).poll(&mut cx).is_pending());
    drop(external);
    assert!(Pin::new(&mut wait).poll(&mut cx).is_ready());
    drop(wait);
    let height = admitted
        .push_admitted_with_finish(successor, &budget, |step| {
            assert_eq!(budget.reserved_bytes(), registration_bytes + frame_bytes);
            step.into_parts().0.height()
        })
        .unwrap();
    assert_eq!(height, 2);
    assert_eq!(budget.reserved_bytes(), registration_bytes);
    drop(registration);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn admitted_initialization_binds_original_pool_and_genesis_before_first_admission() {
    let (chain, _) = chain();
    let id = ChainId::from("sumeragi-certified-test-chain");
    let genesis = frame(&chain, 1);
    let prefix_bytes = std::mem::size_of::<CertifiedPrefix>();
    let budget = iroha_allocation::AllocationBudget::new(32 << 20);
    let foreign = iroha_allocation::AllocationBudget::new(32 << 20);
    let blocker = budget
        .try_reserve_bytes(budget.limit_bytes() - prefix_bytes + 1)
        .unwrap();
    let mut initialization = AdmittedPrefixInitialization::default();
    let refused = initialization.complete(&id, chain.network_id(), genesis.clone(), &budget);
    assert!(
        matches!(refused, Err(ExecutionAttemptError::Deferred(ref original))
        if original.allocation_refusal().is_some())
    );
    assert!(initialization.original.is_none());
    let local = |result: Result<_, ExecutionAttemptError<ChainReadError>>| {
        matches!(result, Err(ExecutionAttemptError::Deferred(original))
            if original.reason() == ivm::error::ExecutionDeferral::LocalInvariantViolation
                && original.allocation_refusal().is_none())
    };
    assert!(
        local(initialization.complete(&id, chain.network_id(), genesis.clone(), &foreign)),
        "HC965 retained initialization binds its original pool before the first admission"
    );
    assert_eq!(foreign.reserved_bytes(), 0);
    let replacement = crate::block::reserve_block_for_tests().initialize(genesis.as_ref().clone());
    assert!(
        local(initialization.complete(&id, chain.network_id(), replacement, &budget)),
        "HC965 retained initialization binds its original genesis before the first admission"
    );
    assert!(initialization.original.is_none());
    drop(blocker);
    let prefix = initialization
        .complete(&id, chain.network_id(), genesis.clone(), &budget)
        .unwrap();
    assert!(prefix.belongs_to(&budget));
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        prefix.as_slice()[0].prefix.tip.block(),
        &genesis
    ));
    assert!(initialization.budget.is_none() && initialization.source.is_none());
    drop(prefix);
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(foreign.reserved_bytes(), 0);
}

/// The funded prefix authority rejects every invalid frame exactly like the portable one.
#[test]
fn funded_prefix_authority_rejects_invalid_frames_exactly_like_the_portable_authority() {
    let (chain, _) = chain();
    let parent = chain.committed(2);
    let schedule::ScheduledSlot::Ready(scheduled) = &parent.commitment().schedule.next else {
        panic!("genuine executed parent authorizes height 3")
    };
    let budget = iroha_allocation::AllocationBudget::new(1 << 26);
    let mut validation = EpochValidationScope::new();
    let funded =
        funded_authority::FundedPrefixAuthority::admit(scheduled, 3, &mut validation, &budget)
            .unwrap();
    let portable = VerifiedAuthority::new(scheduled.epoch.clone(), 3, &mut validation).unwrap();
    let portable_config = scheduled
        .height_config_with_validation(&mut validation)
        .unwrap();
    assert_eq!(funded.config(), &portable_config);
    let context = PrefixVerifierContext {
        instance: chain.instance(),
        root_scope: chain.root_scope(),
    };
    let original = frame(&chain, 3);
    let changed_table = {
        let certificate = original.commit_certificate().unwrap();
        let (header, qc) = decode_certificate(certificate).unwrap();
        let table: iroha_sumeragi::availability::AvailabilityFrame =
            norito::decode_canonical(certificate.availability()).unwrap();
        let mut bytes = table.as_slice().to_vec();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let table = iroha_sumeragi::availability::AvailabilityFrame::from_untrusted(bytes).unwrap();
        crate::block::reserve_block_for_tests().initialize(
            original.as_ref().clone().with_commit_certificate(Some(
                commit_certificate(
                    &header,
                    &qc,
                    certificate.result_preimage().to_vec(),
                    norito::encode_canonical(&table).unwrap(),
                )
                .unwrap(),
            )),
        )
    };
    let cases = [
        (
            "forged aggregate signature",
            with_parts(&original, |_, qc, _| qc.agg_sig.0[5] ^= 1),
        ),
        (
            "missing signer",
            with_parts(&original, |_, qc, _| {
                let first = qc.signers.ones().next().unwrap();
                let mut bytes = qc.signers.as_bytes().to_vec();
                bytes[usize::try_from(first / 8).unwrap()] &= !(1 << (first % 8));
                qc.signers = iroha_sumeragi::types::Bitmap::from_bytes(bytes);
            }),
        ),
        (
            "extra bitmap byte",
            with_parts(&original, |_, qc, _| {
                qc.signers = iroha_sumeragi::types::Bitmap::from_bytes(
                    [qc.signers.as_bytes(), &[0]].concat(),
                );
            }),
        ),
        (
            "prepare kind",
            with_parts(&original, |_, qc, _| qc.kind = VoteKind::Prepare),
        ),
        (
            "another view",
            with_parts(&original, |_, qc, _| qc.view += 1),
        ),
        (
            "another height",
            with_parts(&original, |_, qc, _| qc.height += 1),
        ),
        (
            "another block hash",
            with_parts(&original, |_, qc, _| qc.block_hash.0[0] ^= 1),
        ),
        (
            "another result",
            with_parts(&original, |_, qc, _| qc.result.0[0] ^= 1),
        ),
        (
            "another epoch",
            with_parts(&original, |_, qc, _| qc.epoch.epoch += 1),
        ),
        (
            "another instance",
            with_parts(&original, |_, qc, _| qc.instance.0[0] ^= 1),
        ),
        (
            "another header view",
            with_parts(&original, |header, _, _| header.origin_view += 1),
        ),
        ("corrupt signed availability", changed_table),
    ];
    let verdict = |committed: &CommittedBlock,
                   authority: AuthorityRef<'_>,
                   config: &iroha_sumeragi::types::HeightConfig| {
        context
            .prepare_certificate_with_scratch_admission(
                committed,
                authority,
                Some(config),
                None,
                &mut crate::sumeragi::certified_chain::state_certificate::query_scratch_admission,
            )
            .map(|verdict| verdict.verification)
    };
    let genuine = read_frame(original.clone(), 3, chain.root_scope()).unwrap();
    assert_eq!(
        verdict(&genuine, funded.projection(), funded.config()).unwrap(),
        QcVerification::Verified
    );
    assert_eq!(
        verdict(&genuine, portable.projection(), &portable_config).unwrap(),
        QcVerification::Verified
    );
    for (label, block) in cases {
        let committed = read_frame(block, 3, chain.root_scope())
            .unwrap_or_else(|error| panic!("{label}: structural frame {error:?}"));
        let funded_verdict = verdict(&committed, funded.projection(), funded.config());
        let portable_verdict = verdict(&committed, portable.projection(), &portable_config);
        match (&funded_verdict, &portable_verdict) {
            (
                Err(VerificationReadError::Source(funded)),
                Err(VerificationReadError::Source(portable)),
            ) => assert_eq!(funded, portable, "{label}"),
            _ => panic!(
                "{label}: funded {funded_verdict:?} and portable {portable_verdict:?} must reject alike"
            ),
        }
    }
    drop(funded);
    assert_eq!(budget.reserved_bytes(), 0);
}
