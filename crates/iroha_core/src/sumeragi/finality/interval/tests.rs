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
    let cache_budget = chain.state().ivm_execution_budget();
    let source = NativeFinalityProofSource::new(
        view.chain_id(),
        view.network_id(),
        view.block_hashes(),
        view.kura(),
    );
    let resumable = source.with_checkpoints(&checkpoints, &cache_budget);
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
    assert!(
        budget.reserved_bytes() > reserved,
        "cache keeps actual State funding"
    );
    drop(checkpoints);
    assert_eq!(
        budget.reserved_bytes(),
        reserved,
        "final cache owner releases all original State-pool storage"
    );
}

#[test]
fn finite_interval_cache_capacity_refusal_retries_original_pool_and_releases_final_owner() {
    with_chain_of(5, check_cache_capacity_and_final_owner);
}
#[inline(never)]
fn check_cache_capacity_and_final_owner(chain: &CertifiedTestChain) {
    use iroha_allocation::{AllocationRefusal, release::ReleaseRegistration};
    use std::task::{Context, Waker};

    let view = chain.state().view();
    let cache_budget = chain.state().ivm_execution_budget();
    let initial_state_bytes = cache_budget.reserved_bytes();
    let checkpoints = FinalityPrefixCheckpoints::new();
    let source = NativeFinalityProofSource::new(
        view.chain_id(),
        view.network_id(),
        view.block_hashes(),
        view.kura(),
    );
    let resumable = source.with_checkpoints(&checkpoints, &cache_budget);
    // Request leases and the persistent State source are genuinely distinct pools.
    let frames = AllocationBudget::new(cache_budget.limit_bytes());
    let graphs = AllocationBudget::new(33_312_848);
    let owner = NativeFinalityProofBudget::new(frames.clone(), graphs.clone(), codec_limits());
    let cancelled = AtomicBool::new(false);
    let expected = build_proof_interval(&source, &owner, &limits(3, 4), &cancelled).unwrap();
    checkpoints.prepare(&cache_budget).unwrap();
    let table_bytes = cache_budget.reserved_bytes();
    assert!(table_bytes > initial_state_bytes);
    let mut registration_charge = frames
        .try_reserve(ReleaseRegistration::allocation_layout())
        .unwrap();
    let mut registration = ReleaseRegistration::from_reservation(&mut registration_charge).unwrap();
    drop(registration_charge);
    let occupied = cache_budget
        .try_reserve_bytes(cache_budget.limit_bytes() - table_bytes)
        .unwrap();
    let AllocationRefusal::Capacity {
        release: observed, ..
    } = cache_budget.try_reserve_bytes(1).unwrap_err()
    else {
        panic!("the original State pool must be occupied by the fixture owner");
    };
    let (refused, counts) = relation_counts::measure(|| {
        build_proof_interval(&resumable, &owner, &limits(3, 4), &cancelled)
    });
    let refused = refused.unwrap();
    assert_eq!(counts.qcs, [2, 3, 4]);
    for at in 0..2 {
        assert_eq!(refused.proof(at), expected.proof(at));
    }
    let AllocationRefusal::Capacity {
        release,
        reserved_bytes,
        limit_bytes,
        ..
    } = refused
        .cache_retention_refusal()
        .expect("optional retention preserves its actual refusal")
        .allocation_refusal()
        .expect("actual original pool capacity refusal")
    else {
        panic!("optional cache refusal must not become proof rejection or a fixed bound");
    };
    assert_eq!(
        release, &observed,
        "the exact original State-pool observation survives"
    );
    assert_eq!(*reserved_bytes, cache_budget.limit_bytes());
    assert_eq!(*limit_bytes, cache_budget.limit_bytes());
    assert!(
        registration
            .poll_wait(release, &mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    assert!(checkpoints.heights().is_empty());
    drop(occupied);
    assert!(
        registration
            .poll_wait(release, &mut Context::from_waker(Waker::noop()))
            .is_ready()
    );
    assert_eq!(cache_budget.reserved_bytes(), table_bytes);
    let retried = build_proof_interval(&resumable, &owner, &limits(3, 4), &cancelled).unwrap();
    assert!(retried.cache_retention_refusal().is_none());
    assert_eq!(checkpoints.heights(), [4]);
    for at in 0..2 {
        assert_eq!(retried.proof(at), expected.proof(at));
    }
    let original = checkpoints.resume_point(5, &cache_budget).unwrap();
    let (next, counts) = relation_counts::measure(|| {
        build_proof_interval(&resumable, &owner, &limits(5, 5), &cancelled)
    });
    let next = next.unwrap();
    assert!(next.cache_retention_refusal().is_none());
    assert_eq!(counts.qcs, [5]);
    let retained = checkpoints.resume_point(6, &cache_budget).unwrap();
    assert!(
        original.shares_authority_with(&retained),
        "resumed interval keeps the original authority allocation"
    );
    assert!(cache_budget.reserved_bytes() > table_bytes);
    drop((expected, refused, retried, next, owner, registration));
    assert_eq!(
        frames.reserved_bytes(),
        0,
        "no request credit supplies persistent cache custody"
    );
    assert_eq!(
        graphs.reserved_bytes(),
        0,
        "the request graph lease has physically retired"
    );
    drop((checkpoints, original));
    assert!(
        cache_budget.reserved_bytes() > initial_state_bytes,
        "the final shared checkpoint still owns its actual source graph"
    );
    drop(retained);
    assert_eq!(
        cache_budget.reserved_bytes(),
        initial_state_bytes,
        "the final owner releases schedule, credentials, control and table backing"
    );
}

#[test]
fn finite_interval_cache_rejects_foreign_pool_without_changing_native_proof() {
    with_chain(check_foreign_cache_pool);
}
#[inline(never)]
fn check_foreign_cache_pool(chain: &CertifiedTestChain) {
    let view = chain.state().view();
    let cache_budget = chain.state().ivm_execution_budget();
    let initial_state_bytes = cache_budget.reserved_bytes();
    let checkpoints = FinalityPrefixCheckpoints::new();
    let source = NativeFinalityProofSource::new(
        view.chain_id(),
        view.network_id(),
        view.block_hashes(),
        view.kura(),
    );
    let resumable = source.with_checkpoints(&checkpoints, &cache_budget);
    let frames = AllocationBudget::new(cache_budget.limit_bytes());
    let owner = test_budget(frames.clone());
    let cancelled = AtomicBool::new(false);
    drop(build_proof_interval(&resumable, &owner, &limits(3, 3), &cancelled).unwrap());
    let retained_bytes = cache_budget.reserved_bytes();
    let foreign = AllocationBudget::new(cache_budget.limit_bytes());
    let wrong_owner = source.with_checkpoints(&checkpoints, &foreign);
    let (proof, counts) = relation_counts::measure(|| {
        build_proof_interval(&wrong_owner, &owner, &limits(4, 4), &cancelled)
    });
    let proof = proof.unwrap();
    assert_eq!(
        counts.qcs,
        [2, 3, 4],
        "equal pool limits cannot authorize resume"
    );
    assert_eq!(
        proof.cache_retention_refusal().unwrap().reason(),
        ivm::error::ExecutionDeferral::LocalInvariantViolation
    );
    assert!(
        proof
            .cache_retention_refusal()
            .unwrap()
            .allocation_refusal()
            .is_none()
    );
    assert_eq!(checkpoints.heights(), [3]);
    assert_eq!(cache_budget.reserved_bytes(), retained_bytes);
    assert_eq!(foreign.reserved_bytes(), 0);
    let (retried, counts) = relation_counts::measure(|| {
        build_proof_interval(&resumable, &owner, &limits(4, 4), &cancelled)
    });
    let retried = retried.unwrap();
    assert_eq!(counts.qcs, [4]);
    assert!(retried.cache_retention_refusal().is_none());
    assert_eq!(proof.proof(0), retried.proof(0));
    drop((proof, retried, owner, checkpoints));
    assert_eq!(frames.reserved_bytes(), 0);
    assert_eq!(cache_budget.reserved_bytes(), initial_state_bytes);
}

#[test]
fn finite_interval_late_cache_shell_refusal_moves_original_authority_without_query_debit() {
    with_chain(check_late_cache_shell_refusal);
}
#[inline(never)]
fn check_late_cache_shell_refusal(chain: &CertifiedTestChain) {
    use crate::sumeragi::certified_chain::{
        query_authority_shell_layout, with_refused_query_authority_shell,
    };
    use iroha_allocation::PrepaidSharedError;

    let view = chain.state().view();
    let cache_budget = chain.state().ivm_execution_budget();
    let initial_state_bytes = cache_budget.reserved_bytes();
    let checkpoints = FinalityPrefixCheckpoints::new();
    checkpoints.prepare(&cache_budget).unwrap();
    let table_bytes = cache_budget.reserved_bytes();
    let source = NativeFinalityProofSource::new(
        view.chain_id(),
        view.network_id(),
        view.block_hashes(),
        view.kura(),
    );
    let resumable = source.with_checkpoints(&checkpoints, &cache_budget);
    let frames = AllocationBudget::new(cache_budget.limit_bytes());
    let owner = test_budget(frames.clone());
    let cancelled = AtomicBool::new(false);
    let original_allowance = DecodeBudgetContext::new(codec_limits());
    let expected = original_allowance
        .with(|| build_proof_interval(&source, &owner, &limits(3, 4), &cancelled))
        .unwrap();
    let admitted = original_allowance.consumed_allocated_bytes();
    let inherited = DecodeBudgetContext::new(codec_limits());
    let actual = with_refused_query_authority_shell(|| {
        inherited.with(|| build_proof_interval(&resumable, &owner, &limits(3, 4), &cancelled))
    })
    .unwrap();
    assert_eq!(
        inherited.consumed_allocated_bytes(),
        admitted,
        "late optional failure cannot consume an extra inherited query debit"
    );
    let local = actual
        .cache_retention_refusal()
        .expect("preserve actual optional wrapper failure");
    assert_eq!(
        local.reason(),
        ivm::error::ExecutionDeferral::AllocationUnavailable
    );
    assert!(
        local.allocation_refusal().is_none(),
        "global allocation refusal cannot invent a pool wake"
    );
    assert_eq!(
        local.allocator_refusal().unwrap().shared_error(),
        Some(&PrepaidSharedError::Allocator {
            requested_bytes: query_authority_shell_layout().size(),
        })
    );
    for at in 0..2 {
        assert_eq!(actual.proof(at), expected.proof(at));
    }
    assert!(checkpoints.heights().is_empty());
    assert_eq!(
        cache_budget.reserved_bytes(),
        table_bytes,
        "failed optional shell retains no State payload charge"
    );
    let retried = build_proof_interval(&resumable, &owner, &limits(3, 4), &cancelled).unwrap();
    assert!(retried.cache_retention_refusal().is_none());
    for at in 0..2 {
        assert_eq!(retried.proof(at), expected.proof(at));
    }
    assert_eq!(checkpoints.heights(), [4]);
    drop((expected, actual, retried, checkpoints));
    assert_eq!(cache_budget.reserved_bytes(), initial_state_bytes);
    // Corruption deliberately evicts Kura's original cached body. Keep that actual
    // State-funded allocation alive while checking query/cache refunds, so eviction
    // cannot be mistaken for a refund by the optional authority wrapper.
    let original_block = chain
        .kura()
        .get_block(NonZeroUsize::new(2).unwrap(), &cache_budget)
        .unwrap()
        .unwrap();
    assert!(original_block.belongs_to(&cache_budget));
    let last_original_block = original_block.clone();
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        &original_block,
        &last_original_block,
    ));
    assert_eq!(cache_budget.reserved_bytes(), initial_state_bytes);
    // A physical optional-shell refusal cannot replace a genuine certificate error.
    chain.corrupt_local_quorum_for_test(2, Signers::BelowQuorum);
    assert_eq!(cache_budget.reserved_bytes(), initial_state_bytes);
    let rejected_cold = DecodeBudgetContext::new(codec_limits());
    let expected =
        rejected_cold.with(|| build_proof_interval(&source, &owner, &limits(3, 4), &cancelled));
    let Err(NativeFinalityProofIntervalError::Native(expected)) = expected else {
        panic!("the original cold native verifier must reject the real below-quorum certificate");
    };
    let checkpoints = FinalityPrefixCheckpoints::new();
    let resumable = source.with_checkpoints(&checkpoints, &cache_budget);
    let rejected_cached = DecodeBudgetContext::new(codec_limits());
    let actual = with_refused_query_authority_shell(|| {
        rejected_cached.with(|| build_proof_interval(&resumable, &owner, &limits(3, 4), &cancelled))
    });
    let Err(NativeFinalityProofIntervalError::Native(actual)) = actual else {
        panic!("optional wrapper refusal cannot replace the original native certificate rejection");
    };
    assert_eq!(actual, expected);
    assert_eq!(
        rejected_cached.consumed_allocated_bytes(),
        rejected_cold.consumed_allocated_bytes()
    );
    assert!(checkpoints.heights().is_empty());
    drop((owner, checkpoints));
    assert_eq!(frames.reserved_bytes(), 0);
    assert_eq!(cache_budget.reserved_bytes(), initial_state_bytes);
    drop(original_block);
    assert_eq!(cache_budget.reserved_bytes(), initial_state_bytes);
    drop(last_original_block);
    assert!(
        cache_budget.reserved_bytes() < initial_state_bytes,
        "only the final evicted-block owner releases its original physical storage"
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
    let cache_budget = chain.state().ivm_execution_budget();
    let cold = NativeFinalityProofSource::new(
        view.chain_id(),
        view.network_id(),
        view.block_hashes(),
        view.kura(),
    );
    let resumable = cold.with_checkpoints(&checkpoints, &cache_budget);
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
    let cache_budget = chain.state().ivm_execution_budget();
    let source = NativeFinalityProofSource::new(
        view.chain_id(),
        view.network_id(),
        view.block_hashes(),
        view.kura(),
    )
    .with_checkpoints(&checkpoints, &cache_budget);
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
    let cache_budget = chain.state().ivm_execution_budget();
    let source = NativeFinalityProofSource::new(
        view.chain_id(),
        view.network_id(),
        view.block_hashes(),
        view.kura(),
    )
    .with_checkpoints(&checkpoints, &cache_budget);
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
