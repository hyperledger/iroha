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
    let mut result = ExecutionResultCommitment::decode(certificate.result_preimage()).unwrap();
    // Preserve the authenticated lane-write opening's structural consistency. This
    // attack changes a well-formed execution result which only the successor can bind.
    result.execution.world_state_root = Hash::new(b"unsigned genesis result replacement");
    let changed = crate::block::reserve_block_for_tests().initialize(
        original.as_ref().clone().with_commit_certificate(Some(
            CommitCertificate::from_untrusted_parts(
                Vec::new(),
                Vec::new(),
                result.preimage().unwrap(),
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
            prefix.push(tampered).unwrap_err(),
            ExecutionAttemptError::Rejected(ChainReadError::Certificate {
                height: 10,
                error: expected,
            }),
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
            let mut commitment = ExecutionResultCommitment::decode(preimage).unwrap();
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
            *preimage = commitment.preimage().unwrap();
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
    read_frame_with_validation(frame(&chain, 2), 2, &mut validation).unwrap();
    let fresh = read_frame(original.clone(), 3).unwrap();
    let reused = read_frame_with_validation(original.clone(), 3, &mut validation).unwrap();
    assert_eq!(fresh.commitment(), reused.commitment());
    assert_eq!(fresh.id(), reused.id());
    let changed = with_parts(&original, |_, _, preimage| {
        let mut commitment = ExecutionResultCommitment::decode(preimage).unwrap();
        commitment.schedule.height += 1;
        *preimage = commitment.preimage().unwrap();
    });
    let fresh_error = read_frame(changed.clone(), 3).unwrap_err();
    let reused_error = read_frame_with_validation(changed, 3, &mut validation).unwrap_err();
    assert_eq!(fresh_error, reused_error);
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
                let original =
                    read_frame(frame(&chain, receipt.height()), receipt.height()).unwrap();
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
    assert_eq!(refusal, original_refusal);
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
        assert_eq!(actual, expected);
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
    let budget = iroha_allocation::AllocationBudget::new(
        prefix_bytes
            + std::mem::size_of::<CommittedBlock>()
            + std::mem::size_of::<ExecutionResultCommitment>(),
    );
    let mut slot =
        CertifiedPrefix::new_admitted(&id, chain.network_id(), frame(&chain, 1), &budget).unwrap();
    assert_eq!(budget.reserved_bytes(), prefix_bytes);
    let admitted = &mut slot.as_mut_slice()[0];
    assert_eq!(admitted.instance(), owned.instance());
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
    drop(slot);
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
    let result_bytes = std::alloc::Layout::array::<ExecutionResultCommitment>(1)
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
    let result_layout = std::alloc::Layout::array::<ExecutionResultCommitment>(1).unwrap();
    let bytes = frame_layout.size() + result_layout.size();
    let budget = iroha_allocation::AllocationBudget::new(bytes);
    let blocker = budget
        .try_reserve_layouts([frame_layout, result_layout])
        .unwrap();
    let successor = frame(&chain, 2);
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
    assert_eq!(refusal, expected);
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
    assert_eq!(actual, expected);
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
    let parent = read_frame(original.clone(), 2).unwrap();
    let child = read_frame(frame(chain, 3), 3).unwrap();
    let mut link = WalkParentLink::from_committed(&parent);
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        &link.block,
        &original
    ));
    assert!(link.block.belongs_to(&budget));
    assert_eq!(link.is_extended_by(&child), child.extends(&parent));
    assert!(link.is_extended_by(&child));
    let original_pointer: *const SignedBlock = &*original;
    drop(parent);
    drop(original);
    assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
    assert!(std::ptr::eq::<SignedBlock>(&*link.block, original_pointer));
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
    assert!(!link.is_extended_by(&read_frame(frame(chain, 4), 4).unwrap()));
    drop(link);
    assert_eq!(budget.reserved_bytes(), 0);
}
