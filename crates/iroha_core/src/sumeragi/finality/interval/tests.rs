//! Genuine native interval source/authority, finite work and retirement controls.

use super::*;
use crate::{
    state::{StateReadOnly, World},
    sumeragi::{
        certified_chain::relation_counts,
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
fn context() -> DecodeBudgetContext {
    DecodeBudgetContext::new(norito::DecodeLimits::new(
        1024 * 1024,
        MAX_FINALITY_BLOCK_BYTES,
        8 * 1024 * 1024,
        usize::MAX,
        128,
    ))
}
#[inline(never)]
fn with_chain(check: fn(&CertifiedTestChain)) {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 10_000)).unwrap();
    while chain.height() < 4 {
        chain.commit(Vec::new());
    }
    check(&chain);
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
    let owner = CanonicalHistoryReadBudget::new(budget.clone(), context());
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
    let view = chain.state().view();
    let source = NativeFinalityProofSource::new(
        view.chain_id(),
        view.network_id(),
        view.block_hashes(),
        view.kura(),
    );
    let budget = view.execution_budget();
    let owner = CanonicalHistoryReadBudget::new(budget.clone(), context());
    let reserved = budget.reserved_bytes();
    let path = Kura::canonical_storage_path(&chain.kura().store_root()).join("blocks.data");
    let saved = path.with_extension("finite-proof-original");
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
            Err(NativeFinalityProofIntervalError::Source { .. })
                | Err(NativeFinalityProofIntervalError::Proof(ProofError::Chain(
                    ChainReadError::NotInView { .. }
                )))
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
    let owner = CanonicalHistoryReadBudget::new(view.execution_budget(), context());
    chain.corrupt_local_quorum_for_test(2, Signers::BelowQuorum);
    chain
        .kura()
        .corrupt_commit_result_for_testing(std::num::NonZeroUsize::new(4).unwrap(), vec![0])
        .unwrap();
    let expected = super::super::build_proof(&view, 4).unwrap_err();
    let actual = build_proof_interval(&source, &owner, &limits(4, 4), &AtomicBool::new(false));
    assert!(matches!(
        &actual,
        Err(NativeFinalityProofIntervalError::Proof(ProofError::Chain(
            ChainReadError::Malformed { height: 4, .. }
        )))
    ));
    assert_eq!(actual.err().unwrap().to_string(), expected.to_string());
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
    let original = context();
    let owner = CanonicalHistoryReadBudget::new(budget.clone(), original.clone());
    let reserved = budget.reserved_bytes();
    chain.kura().reset_canonical_query_reads_for_test();
    let cancelled = AtomicBool::new(true);
    let result = build_proof_interval(&source, &owner, &limits(3, 4), &cancelled);
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
        build_proof_interval(&source, &owner, &expired, &cancelled),
        Err(NativeFinalityProofIntervalError::Deadline)
    ));
    assert_eq!(chain.kura().canonical_query_reads_for_test(), (0, 0));
    let result = build_interval(&source, &owner, &limits(3, 4), &cancelled, || {
        cancelled.store(true, Ordering::Release)
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
        build_proof_interval(&source, &owner, &limits(3, 4), &cancelled)
    });
    let retained = retained.unwrap();
    assert_eq!(counts.qcs, [2, 3, 4]);
    assert!(original.consumed_allocated_bytes() > consumed);
    drop(retained);
    assert_eq!(budget.reserved_bytes(), reserved);
}
