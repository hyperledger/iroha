//! Genuine native interval source/authority, finite work and retirement controls.

use super::*;
use crate::{
    state::{StateReadOnly, World},
    sumeragi::{
        certified_chain::relation_counts,
        finality::ProofError,
        test_chain::{CertifiedTestChain, Signers, TestChainConfig},
    },
};
use norito::core::DecodeBudgetContext;

fn limits(from: u64, to: u64) -> NativeFinalityProofIntervalLimits {
    NativeFinalityProofIntervalLimits::new(
        NonZeroU64::new(from).unwrap(),
        NonZeroU64::new(to).unwrap(),
        NonZeroUsize::new(MAX_FINALITY_BLOCK_BYTES).unwrap(),
        NonZeroUsize::new(usize::MAX).unwrap(),
        Instant::now() + std::time::Duration::from_secs(900),
    )
    .unwrap()
}
fn codec_limits() -> norito::DecodeLimits {
    norito::DecodeLimits::new(
        1024 * 1024,
        MAX_FINALITY_BLOCK_BYTES,
        8 * 1024 * 1024,
        usize::MAX,
        128,
    )
}
fn test_budget(frames: iroha_allocation::AllocationBudget) -> NativeFinalityProofBudget {
    NativeFinalityProofBudget::new(
        frames,
        iroha_allocation::AllocationBudget::new(33_312_848),
        codec_limits(),
    )
}
#[inline(never)]
fn with_chain(check: fn(&CertifiedTestChain)) {
    with_chain_of(4, check);
}
#[inline(never)]
fn with_chain_of(height: u64, check: fn(&CertifiedTestChain)) {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 10_000)).unwrap();
    while chain.height() < height {
        chain.commit(Vec::new());
    }
    check(&chain);
}

#[test]
fn finite_interval_resumes_retained_prefix_with_identical_proofs() {
    with_chain_of(8, check_resumed_prefix);
}
#[inline(never)]
fn check_resumed_prefix(chain: &CertifiedTestChain) {
    let view = chain.state().view();
    let checkpoints = FinalityPrefixCheckpoints::new();
    let source = NativeFinalityProofSource::new(
        view.chain_id(),
        view.network_id(),
        view.block_hashes(),
        view.kura(),
    );
    let resumable = source.with_checkpoints(&checkpoints);
    let budget = view.execution_budget();
    let owner = test_budget(budget.clone());
    let reserved = budget.reserved_bytes();
    let cancelled = AtomicBool::new(false);
    // The first walk starts at signed genesis and retains its completed prefix.
    let (first, counts) = relation_counts::measure(|| {
        build_proof_interval(&resumable, &owner, &limits(3, 4), &cancelled)
    });
    drop(first.unwrap());
    assert_eq!(counts.qcs, [2, 3, 4]);
    assert_eq!(checkpoints.heights(), [4]);
    // A later page rechecks the retained frame and verifies only its own heights.
    let (resumed, counts) = relation_counts::measure(|| {
        build_proof_interval(&resumable, &owner, &limits(6, 7), &cancelled)
    });
    let resumed = resumed.unwrap();
    assert_eq!(counts.qcs, [5, 6, 7]);
    assert!(counts.frames.contains(&4));
    assert!(counts.frames.iter().all(|height| *height > 3));
    assert_eq!(checkpoints.heights(), [4, 7]);
    // The resumed proofs are exactly those of a full replay from signed genesis.
    let (replayed, counts) = relation_counts::measure(|| {
        build_proof_interval(&source, &owner, &limits(6, 7), &cancelled)
    });
    let replayed = replayed.unwrap();
    assert_eq!(counts.qcs, [2, 3, 4, 5, 6, 7]);
    for index in 0..2 {
        assert_eq!(
            resumed.proof(index).unwrap(),
            replayed.proof(index).unwrap()
        );
    }
    assert_eq!(
        resumed.proof(1).unwrap(),
        &super::super::build_proof(&view, 7).unwrap()
    );
    // An earlier target resumes from the nearest lower prefix, never a later one.
    let (earlier, counts) = relation_counts::measure(|| {
        build_proof_interval(&resumable, &owner, &limits(5, 5), &cancelled)
    });
    drop(earlier.unwrap());
    assert_eq!(counts.qcs, [5]);
    assert_eq!(checkpoints.heights(), [4, 5, 7]);
    drop((resumed, replayed));
    assert_eq!(
        budget.reserved_bytes(),
        reserved,
        "retained prefixes own no request-pool charge"
    );
}

#[test]
#[ignore = "timing report: cargo test -p iroha_core --features iroha-core-tests --lib -- finality_proof_cost_report --ignored --nocapture"]
fn finality_proof_cost_report() {
    with_chain_of(150, report_proof_cost);
}
#[inline(never)]
fn report_proof_cost(chain: &CertifiedTestChain) {
    let view = chain.state().view();
    let checkpoints = FinalityPrefixCheckpoints::new();
    let cold = NativeFinalityProofSource::new(
        view.chain_id(),
        view.network_id(),
        view.block_hashes(),
        view.kura(),
    );
    let resumable = cold.with_checkpoints(&checkpoints);
    let owner = test_budget(view.execution_budget());
    let cancelled = AtomicBool::new(false);
    let time = |source: &NativeFinalityProofSource<'_>, height: u64| {
        let started = Instant::now();
        drop(build_proof_interval(source, &owner, &limits(height, height), &cancelled).unwrap());
        started.elapsed()
    };
    for height in [10, 50, 100, 150] {
        println!(
            "cold single proof at height {height}: {:?}",
            time(&cold, height)
        );
    }
    let started = Instant::now();
    for height in 2..=150 {
        let _ = time(&resumable, height);
    }
    println!(
        "sequential resumed proofs 2..=150: {:?} total",
        started.elapsed()
    );
    for height in [100, 150] {
        println!(
            "resumed single proof at height {height}: {:?}",
            time(&resumable, height)
        );
    }
}

#[test]
fn finite_interval_discards_prefix_whose_retained_frame_changed() {
    with_chain_of(6, check_changed_retained_frame);
}
#[inline(never)]
fn check_changed_retained_frame(chain: &CertifiedTestChain) {
    let view = chain.state().view();
    let checkpoints = FinalityPrefixCheckpoints::new();
    let source = NativeFinalityProofSource::new(
        view.chain_id(),
        view.network_id(),
        view.block_hashes(),
        view.kura(),
    )
    .with_checkpoints(&checkpoints);
    let owner = test_budget(view.execution_budget());
    let cancelled = AtomicBool::new(false);
    drop(build_proof_interval(&source, &owner, &limits(3, 4), &cancelled).unwrap());
    assert_eq!(checkpoints.heights(), [4]);
    // Another genuine quorum of the same block changes its certificate-inclusive frame.
    let committed = chain.committed(4);
    let other = chain.commit_qc(
        4,
        committed.core_hash(),
        committed.result(),
        Signers::LastThree,
    );
    chain
        .kura()
        .corrupt_commit_certificate_for_testing(
            std::num::NonZeroUsize::new(4).unwrap(),
            Some(norito::encode_canonical(&other).unwrap()),
        )
        .unwrap();
    let (proofs, counts) = relation_counts::measure(|| {
        build_proof_interval(&source, &owner, &limits(5, 6), &cancelled)
    });
    let proofs = proofs.unwrap();
    assert_eq!(
        counts.qcs,
        [2, 3, 4, 5, 6],
        "a changed retained frame restarts the walk at signed genesis"
    );
    assert_eq!(checkpoints.heights(), [6]);
    assert_eq!(
        proofs.proof(1).unwrap(),
        &super::super::build_proof(&view, 6).unwrap()
    );
}

#[test]
fn finite_interval_retains_no_prefix_after_late_source_change() {
    with_chain(check_no_prefix_after_failed_join);
}
#[inline(never)]
fn check_no_prefix_after_failed_join(chain: &CertifiedTestChain) {
    let view = chain.state().view();
    let checkpoints = FinalityPrefixCheckpoints::new();
    let source = NativeFinalityProofSource::new(
        view.chain_id(),
        view.network_id(),
        view.block_hashes(),
        view.kura(),
    )
    .with_checkpoints(&checkpoints);
    let owner = test_budget(view.execution_budget());
    let qc = chain
        .committed(3)
        .block()
        .commit_certificate()
        .unwrap()
        .commit_qc()
        .to_vec();
    let cancelled = AtomicBool::new(false);
    let result = build_interval(&source, &owner, &limits(3, 4), &cancelled, || {
        chain.corrupt_local_quorum_for_test(3, Signers::BelowQuorum);
    });
    assert!(matches!(
        result,
        Err(NativeFinalityProofIntervalError::Source { .. })
    ));
    assert!(
        checkpoints.heights().is_empty(),
        "a walk whose source join failed is never a resume point"
    );
    chain
        .kura()
        .corrupt_commit_certificate_for_testing(std::num::NonZeroUsize::new(3).unwrap(), Some(qc))
        .unwrap();
    drop(build_proof_interval(&source, &owner, &limits(3, 4), &cancelled).unwrap());
    assert_eq!(checkpoints.heights(), [4]);
}

#[test]
fn finite_interval_rejects_earlier_real_qc_changed_after_verification_before_publication() {
    with_chain(check_late_qc_change);
}
#[inline(never)]
fn check_late_qc_change(chain: &CertifiedTestChain) {
    let view = chain.state().view();
    let source = NativeFinalityProofSource::new(
        view.chain_id(),
        view.network_id(),
        view.block_hashes(),
        view.kura(),
    );
    let budget = view.execution_budget();
    let owner = test_budget(budget.clone());
    let qc = chain
        .committed(2)
        .block()
        .commit_certificate()
        .unwrap()
        .commit_qc()
        .to_vec();
    let publication = chain
        .kura()
        .get_block(std::num::NonZeroUsize::new(2).unwrap(), &budget)
        .unwrap()
        .unwrap();
    let reserved = budget.reserved_bytes();
    let cancelled = AtomicBool::new(false);
    let result = build_interval(&source, &owner, &limits(3, 4), &cancelled, || {
        chain.corrupt_local_quorum_for_test(2, Signers::BelowQuorum);
    });
    assert!(
        matches!(result, Err(NativeFinalityProofIntervalError::Source { .. })),
        "completed interval cannot publish after an earlier real QC's source changes"
    );
    assert_eq!(budget.reserved_bytes(), reserved);
    assert!(super::super::build_proof(&view, 4).is_err());
    chain
        .kura()
        .corrupt_commit_certificate_for_testing(std::num::NonZeroUsize::new(2).unwrap(), Some(qc))
        .unwrap();
    let retained = build_proof_interval(&source, &owner, &limits(3, 4), &cancelled).unwrap();
    assert_eq!(
        retained.proof(1).unwrap(),
        &super::super::build_proof(&view, 4).unwrap()
    );
    assert!(budget.reserved_bytes() > reserved);
    drop(retained);
    assert_eq!(budget.reserved_bytes(), reserved);
    drop(publication);
}

#[cfg(unix)]
#[test]
fn finite_interval_rejects_same_bytes_replaced_original_journal_before_publication() {
    with_chain(check_late_source_replacement);
}
#[cfg(unix)]
#[inline(never)]
fn check_late_source_replacement(chain: &CertifiedTestChain) {
    struct Restore<'a> {
        path: &'a std::path::Path,
        saved: &'a std::path::Path,
    }
    impl Drop for Restore<'_> {
        fn drop(&mut self) {
            if self.saved.exists() {
                std::fs::remove_file(self.path).unwrap();
                std::fs::rename(self.saved, self.path).unwrap();
            }
        }
    }
    let view = chain.state().view();
    let source = NativeFinalityProofSource::new(
        view.chain_id(),
        view.network_id(),
        view.block_hashes(),
        view.kura(),
    );
    let budget = view.execution_budget();
    let owner = test_budget(budget.clone());
    let reserved = budget.reserved_bytes();
    let path = Kura::canonical_storage_path(&chain.kura().store_root()).join("blocks.data");
    let saved = path.with_extension("finite-proof-original");
    let restore = Restore {
        path: &path,
        saved: &saved,
    };
    let cancelled = AtomicBool::new(false);
    let result = build_interval(&source, &owner, &limits(3, 4), &cancelled, || {
        std::fs::rename(&path, &saved).unwrap();
        std::fs::copy(&saved, &path).unwrap();
        assert_eq!(
            std::fs::read(&path).unwrap(),
            std::fs::read(&saved).unwrap()
        );
    });
    drop(restore);
    assert!(
        matches!(
            result,
            Err(NativeFinalityProofIntervalError::Source { .. }
                | NativeFinalityProofIntervalError::Native(
                    NativeFinalityProofRefusal::NotInView { .. }
                ))
        ),
        "same bytes in a replacement namespace are not the original journal"
    );
    assert_eq!(budget.reserved_bytes(), reserved);
    let retried = build_proof_interval(&source, &owner, &limits(3, 4), &cancelled).unwrap();
    drop(retried);
    assert_eq!(budget.reserved_bytes(), reserved);
}

#[test]
fn finite_interval_keeps_original_malformed_target_before_bad_gap_order() {
    with_chain(check_first_target_order);
}
#[inline(never)]
fn check_first_target_order(chain: &CertifiedTestChain) {
    let view = chain.state().view();
    let source = NativeFinalityProofSource::new(
        view.chain_id(),
        view.network_id(),
        view.block_hashes(),
        view.kura(),
    );
    let owner = test_budget(view.execution_budget());
    // Preserve the genuine current fixed header and corrupt only its Norito body.
    // A one-byte whole preimage is an earlier ResultMismatch, not a body decode error.
    let mut malformed = chain
        .committed(4)
        .block()
        .commit_certificate()
        .unwrap()
        .result_preimage()
        .to_vec();
    malformed.push(0);
    assert!(crate::sumeragi::commitment::result_of_preimage(&malformed).is_some());
    chain.corrupt_local_quorum_for_test(2, Signers::BelowQuorum);
    chain
        .kura()
        .corrupt_commit_result_for_testing(std::num::NonZeroUsize::new(4).unwrap(), malformed)
        .unwrap();
    let expected = super::super::build_proof(&view, 4).unwrap_err();
    assert!(matches!(
        &expected,
        ProofError::Chain(ChainReadError::Malformed { height: 4, .. })
    ));
    let (actual, counts) = relation_counts::measure(|| {
        build_proof_interval(&source, &owner, &limits(4, 4), &AtomicBool::new(false))
    });
    assert_eq!(counts.frames, [1, 4]);
    assert!(counts.qcs.is_empty());
    assert!(
        matches!(
            &actual,
            Err(NativeFinalityProofIntervalError::Native(
                NativeFinalityProofRefusal::Malformed { height: 4 }
            ))
        ),
        "original malformed target must precede the bad gap: actual={:?}, expected={expected:?}",
        actual.as_ref().err()
    );
    let ProofError::Chain(expected) = expected else {
        panic!("single native proof must reject the same original chain relation");
    };
    let Err(NativeFinalityProofIntervalError::Native(actual)) = actual else {
        panic!("interval must retain the completed native rejection");
    };
    assert_eq!(actual, NativeFinalityProofRefusal::from(expected));
}

#[test]
fn finite_interval_keeps_invalid_target_result_header_before_bad_gap_order() {
    with_chain(check_first_target_header_order);
}
#[inline(never)]
fn check_first_target_header_order(chain: &CertifiedTestChain) {
    let view = chain.state().view();
    let source = NativeFinalityProofSource::new(
        view.chain_id(),
        view.network_id(),
        view.block_hashes(),
        view.kura(),
    );
    let owner = test_budget(view.execution_budget());
    chain.corrupt_local_quorum_for_test(2, Signers::BelowQuorum);
    chain
        .kura()
        .corrupt_commit_result_for_testing(std::num::NonZeroUsize::new(4).unwrap(), vec![0])
        .unwrap();
    let expected = super::super::build_proof(&view, 4).unwrap_err();
    assert!(matches!(
        &expected,
        ProofError::Chain(ChainReadError::ResultMismatch { height: 4 })
    ));
    let (actual, counts) = relation_counts::measure(|| {
        build_proof_interval(&source, &owner, &limits(4, 4), &AtomicBool::new(false))
    });
    assert!(matches!(
        &actual,
        Err(NativeFinalityProofIntervalError::Native(
            NativeFinalityProofRefusal::ResultMismatch { height: 4 }
        ))
    ));
    assert_eq!(counts.frames, [1, 4]);
    assert!(counts.qcs.is_empty());
    let ProofError::Chain(expected) = expected else {
        panic!("single native proof must reject the same original chain relation");
    };
    let Err(NativeFinalityProofIntervalError::Native(actual)) = actual else {
        panic!("interval must retain the completed native rejection");
    };
    assert_eq!(actual, NativeFinalityProofRefusal::from(expected));
}

#[test]
fn finite_interval_stop_retires_real_original_cursor_without_next_native_read() {
    with_chain(check_stop);
}
#[inline(never)]
fn check_stop(chain: &CertifiedTestChain) {
    let view = chain.state().view();
    let source = NativeFinalityProofSource::new(
        view.chain_id(),
        view.network_id(),
        view.block_hashes(),
        view.kura(),
    );
    let budget = view.execution_budget();
    let original = DecodeBudgetContext::new(codec_limits());
    let owner = test_budget(budget.clone());
    let reserved = budget.reserved_bytes();
    chain.kura().reset_canonical_query_reads_for_test();
    let cancelled = AtomicBool::new(true);
    let result = original.with(|| build_proof_interval(&source, &owner, &limits(3, 4), &cancelled));
    assert!(
        matches!(result, Err(NativeFinalityProofIntervalError::Cancelled)),
        "finite interval must stop before any native read under original cancellation"
    );
    assert_eq!(chain.kura().canonical_query_reads_for_test(), (0, 0));
    assert_eq!(original.consumed_allocated_bytes(), 0);
    cancelled.store(false, Ordering::Release);
    let mut expired = limits(3, 4);
    expired.deadline = Instant::now();
    assert!(matches!(
        original.with(|| build_proof_interval(&source, &owner, &expired, &cancelled)),
        Err(NativeFinalityProofIntervalError::Deadline)
    ));
    assert_eq!(chain.kura().canonical_query_reads_for_test(), (0, 0));
    let result = original.with(|| {
        build_interval(&source, &owner, &limits(3, 4), &cancelled, || {
            cancelled.store(true, Ordering::Release)
        })
    });
    assert!(matches!(
        result,
        Err(NativeFinalityProofIntervalError::Cancelled)
    ));
    assert_eq!(budget.reserved_bytes(), reserved);
    let consumed = original.consumed_allocated_bytes();
    assert!(consumed > 0);
    cancelled.store(false, Ordering::Release);
    let (retained, counts) = relation_counts::measure(|| {
        original.with(|| build_proof_interval(&source, &owner, &limits(3, 4), &cancelled))
    });
    let retained = retained.unwrap();
    assert_eq!(counts.qcs, [2, 3, 4]);
    assert!(original.consumed_allocated_bytes() > consumed);
    drop(retained);
    assert_eq!(budget.reserved_bytes(), reserved);
}
