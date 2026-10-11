//! Original native proof, durable-source and enclosing-accounting controls for lexical readers.

use super::*;
use crate::{
    state::World,
    sumeragi::{
        certified_chain::relation_counts,
        test_chain::{CertifiedTestChain, Signers, TestChainConfig},
    },
};
use norito::core::DecodeBudgetContext;
use std::num::NonZeroUsize;

// Finish genuine native construction before the assertion frame, without a second
// fixture, heap-indirected proof graph or a larger thread stack.
#[inline(never)]
fn with_chain_at(height: u64, check: fn(&CertifiedTestChain)) {
    let mut chain = if height == 10 {
        CertifiedTestChain::npos_boundary_fixture()
    } else {
        CertifiedTestChain::start(TestChainConfig::new(World::new(), 10_000)).unwrap()
    };
    while chain.height() < height {
        chain.commit(Vec::new());
    }
    assert_eq!(chain.height(), height);
    check(&chain);
}

#[inline(never)]
fn check_original_sequence(chain: &CertifiedTestChain) {
    let view = chain.state().view();
    let hashes = view.block_hashes().iter().copied().collect::<Vec<_>>();
    let budget = view.execution_budget();
    let reserved = budget.reserved_bytes();
    with_proof_reader(&view, |reader| {
        for height in 1..=chain.height() {
            let expected = build_proof(&view, height).unwrap();
            let (actual, relations) = relation_counts::measure(|| reader.proof(height));
            let actual = actual.unwrap();
            assert_eq!(actual, expected);
            assert_eq!(
                norito::encode_canonical(&actual).unwrap(),
                norito::encode_canonical(&expected).unwrap()
            );
            assert_eq!(
                actual.block_wire,
                chain.committed(height).block().encode_wire().unwrap()
            );
            actual.decode_checked().unwrap();
            assert_eq!(
                relations.frames,
                if height == 1 {
                    vec![1, 1]
                } else {
                    vec![height]
                }
            );
            assert_eq!(
                relations.qcs,
                if height == 1 {
                    Vec::new()
                } else {
                    vec![height]
                },
                "sequential production checks each real native QC exactly once"
            );
            if height == 10 {
                check_native_boundary(&view);
            }
        }
        assert!(budget.reserved_bytes() > reserved);
    });
    assert_eq!(budget.reserved_bytes(), reserved);
    assert_eq!(
        view.block_hashes().iter().copied().collect::<Vec<_>>(),
        hashes
    );
    assert_eq!(view.height(), chain.height() as usize);
}

#[inline(never)]
fn check_native_boundary(view: &impl StateReadOnly) {
    let native = CertifiedChain::new(view).unwrap().certified(10).unwrap();
    assert!(native.commitment().schedule.boundary.is_some());

    let qc = native.commit_qc().unwrap();
    assert_eq!(qc.signers.count_ones(), 3);
}

#[test]
fn scoped_genesis_proof_preserves_the_original_wire_and_releases_native_owners() {
    with_chain_at(1, check_original_sequence);
}

#[test]
fn scoped_successor_proofs_preserve_the_original_native_and_portable_admission() {
    with_chain_at(2, check_original_sequence);
}

#[test]
fn scoped_boundary_proofs_keep_every_original_exact_quorum_and_availability() {
    with_chain_at(10, check_original_sequence);
}

#[test]
fn scoped_random_and_earlier_reads_keep_original_target_first_and_cursor_reset() {
    with_chain_at(5, check_random_reads);
}

#[inline(never)]
fn check_random_reads(chain: &CertifiedTestChain) {
    let view = chain.state().view();
    let budget = view.execution_budget();
    let reserved = budget.reserved_bytes();
    with_proof_reader(&view, |reader| {
        for (height, frames, qcs) in [
            (3, vec![1, 3, 2], vec![2, 3]),
            (4, vec![4], vec![4]),
            (2, vec![1, 2], vec![2]),
            (5, vec![5, 3, 4], vec![3, 4, 5]),
        ] {
            let original = build_proof(&view, height).unwrap();
            let (actual, relations) = relation_counts::measure(|| reader.proof(height));
            assert_eq!(actual.unwrap(), original);
            assert_eq!(relations.frames, frames);
            assert_eq!(relations.qcs, qcs);
        }
        let expected = build_proof(&view, 6).unwrap_err();
        let actual = reader.proof(6).unwrap_err();
        assert!(matches!(
            actual,
            ProofError::Chain(ChainReadError::NotCommitted { height: 6 })
        ));
        assert_eq!(actual.to_string(), expected.to_string());
        let (retried, relations) = relation_counts::measure(|| reader.proof(5));
        assert_eq!(retried.unwrap(), build_proof(&view, 5).unwrap());
        assert_eq!(relations.frames, [1, 5, 2, 3, 4]);
        assert_eq!(relations.qcs, [2, 3, 4, 5]);
    });
    assert_eq!(budget.reserved_bytes(), reserved);
    assert_eq!(chain.height(), 5);
}

// Finite counters observe actual original work; they confer no physical authority.
// Native raw/decoded owners remain charged to the unchanged State execution pool.
fn caller_limits(allocation: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(
        1024 * 1024,
        iroha_data_model::sumeragi_finality::MAX_FINALITY_BLOCK_BYTES,
        8 * 1024 * 1024,
        allocation,
        128,
    )
}

fn compare_original_refusal(actual: ProofError, expected: ProofError, zero: bool) {
    assert_eq!(
        std::mem::discriminant(&actual),
        std::mem::discriminant(&expected)
    );
    assert_eq!(actual.to_string(), expected.to_string());
    match (actual, expected) {
        (ProofError::Deferred(actual), ProofError::Deferred(expected)) => {
            assert_eq!(actual, expected);
            assert_eq!(
                actual.reason(),
                ivm::error::ExecutionDeferral::ActiveMemoryCapacity
            );
            assert!(actual.allocation_refusal().is_none());
        }
        _ => assert!(
            !zero,
            "zero original native acquisition retains typed local refusal"
        ),
    }
}

#[test]
fn every_active_outer_read_replays_exact_original_physical_charges_and_refusal() {
    with_chain_at(2, check_active_accounting);
}

#[inline(never)]
fn check_active_accounting(chain: &CertifiedTestChain) {
    let view = chain.state().view();
    let source_genesis = chain.genesis().encode_wire().unwrap();
    let source_tip = chain.committed(2).block().encode_wire().unwrap();
    let hashes = view.block_hashes().iter().copied().collect::<Vec<_>>();
    let budget = view.execution_budget();
    let reserved = budget.reserved_bytes();
    let baseline = DecodeBudgetContext::new(caller_limits(64 * 1024 * 1024));
    let expected = baseline.with(|| build_proof(&view, 2)).unwrap();
    let charge = baseline.consumed_allocated_bytes();
    assert!(charge > 0 && charge < 64 * 1024 * 1024);
    let cap = usize::try_from(charge).unwrap();
    with_proof_reader(&view, |reader| {
        assert_eq!(reader.proof(2).unwrap(), expected);
        assert!(budget.reserved_bytes() > reserved);
        for _ in 0..2 {
            let exact = DecodeBudgetContext::new(caller_limits(cap));
            let (actual, relations) = relation_counts::measure(|| exact.with(|| reader.proof(2)));
            assert_eq!(actual.unwrap(), expected);
            assert_eq!(exact.consumed_allocated_bytes(), charge);
            assert_eq!(relations.frames, [1, 2]);
            assert_eq!(relations.qcs, [2]);
            assert_eq!(budget.reserved_bytes(), reserved);
        }
        for short in [0, cap - 1] {
            // Warm construction occurred outside this subsequently entered scope.
            assert_eq!(reader.proof(2).unwrap(), expected);
            let independent = DecodeBudgetContext::new(caller_limits(short));
            let expected_error = independent.with(|| build_proof(&view, 2)).unwrap_err();
            let enclosing = DecodeBudgetContext::new(caller_limits(short));
            let actual_error = enclosing.with(|| reader.proof(2)).unwrap_err();
            compare_original_refusal(actual_error, expected_error, short == 0);
            assert_eq!(
                enclosing.consumed_allocated_bytes(),
                independent.consumed_allocated_bytes()
            );
            assert_eq!(budget.reserved_bytes(), reserved);
            assert_eq!(reader.proof(2).unwrap(), expected);
        }
    });
    assert_eq!(budget.reserved_bytes(), reserved);
    assert_eq!(chain.genesis().encode_wire().unwrap(), source_genesis);
    assert_eq!(
        chain.committed(2).block().encode_wire().unwrap(),
        source_tip
    );
    assert_eq!(
        view.block_hashes().iter().copied().collect::<Vec<_>>(),
        hashes
    );
    assert_eq!(chain.height(), 2);
}

#[test]
fn scoped_producer_refuses_replaced_real_quorums_and_retries_the_original_source() {
    with_chain_at(2, check_quorum_replacement);
}

#[inline(never)]
fn check_quorum_replacement(chain: &CertifiedTestChain) {
    let view = chain.state().view();
    let original = build_proof(&view, 2).unwrap();
    let source = chain
        .committed(2)
        .block()
        .commit_certificate()
        .unwrap()
        .commit_qc()
        .to_vec();
    let budget = view.execution_budget();
    // The corruption helper evicts Kura's published owner. Retain that existing
    // physical allocation while measuring reader cleanup; no retained image
    // is offered to the proof producer or used to authenticate the new source.
    let original_publications = [chain
        .kura()
        .get_block(NonZeroUsize::new(2).unwrap(), &budget)
        .unwrap()
        .unwrap()];
    let reserved = budget.reserved_bytes();
    with_proof_reader(&view, |reader| {
        assert_eq!(reader.proof(2).unwrap(), original);
        chain.corrupt_local_quorum_for_test(2, Signers::BelowQuorum);
        let expected = build_proof(&view, 2).unwrap_err();
        let actual = reader.proof(2).unwrap_err();
        assert!(matches!(actual, ProofError::Chain(_)));
        assert_eq!(actual.to_string(), expected.to_string());
        assert_eq!(budget.reserved_bytes(), reserved);
        assert_eq!(
            chain.committed(2).block_hash(),
            original.block_header.hash()
        );
        chain
            .kura()
            .corrupt_commit_certificate_for_testing(NonZeroUsize::new(2).unwrap(), Some(source))
            .unwrap();
        assert_eq!(reader.proof(2).unwrap(), original);
        assert_eq!(
            chain.committed(2).block().encode_wire().unwrap(),
            original.block_wire
        );
    });
    assert_eq!(budget.reserved_bytes(), reserved);
    drop(original_publications);
    assert_eq!(chain.height(), 2);
}

#[test]
fn scoped_producer_keeps_malformed_target_before_corrupt_gap_and_same_source_retry() {
    with_chain_at(4, check_target_before_gap);
}

#[inline(never)]
fn check_target_before_gap(chain: &CertifiedTestChain) {
    let view = chain.state().view();
    let original = build_proof(&view, 4).unwrap();
    let qc = chain
        .committed(2)
        .block()
        .commit_certificate()
        .unwrap()
        .commit_qc()
        .to_vec();
    let result = chain
        .committed(4)
        .block()
        .commit_certificate()
        .unwrap()
        .result_preimage()
        .to_vec();
    with_proof_reader(&view, |reader| {
        reader.proof(1).unwrap();
        chain.corrupt_local_quorum_for_test(2, Signers::BelowQuorum);
        chain
            .kura()
            .corrupt_commit_result_for_testing(NonZeroUsize::new(4).unwrap(), vec![0])
            .unwrap();
        let expected = build_proof(&view, 4).unwrap_err();
        let actual = reader.proof(4).unwrap_err();
        assert!(matches!(
            actual,
            ProofError::Chain(ChainReadError::Malformed { height: 4, .. })
        ));
        assert_eq!(actual.to_string(), expected.to_string());
        chain
            .kura()
            .corrupt_commit_result_for_testing(NonZeroUsize::new(4).unwrap(), result)
            .unwrap();
        chain
            .kura()
            .corrupt_commit_certificate_for_testing(NonZeroUsize::new(2).unwrap(), Some(qc))
            .unwrap();
        assert_eq!(reader.proof(4).unwrap(), original);
        assert_eq!(
            chain.committed(4).block().encode_wire().unwrap(),
            original.block_wire
        );
    });
    assert_eq!(chain.height(), 4);
}

#[cfg(unix)]
#[test]
fn scoped_producer_refuses_missing_replaced_and_linked_journals_and_retries_original_inode() {
    with_chain_at(3, check_journal_replacement);
}

#[cfg(unix)]
#[inline(never)]
fn check_journal_replacement(chain: &CertifiedTestChain) {
    use std::os::unix::fs::MetadataExt as _;
    let view = chain.state().view();
    let original = build_proof(&view, 3).unwrap();
    let source =
        crate::kura::Kura::canonical_storage_path(&chain.kura().store_root()).join("blocks.data");
    let saved = source.with_extension("proof-reader-original");
    let bytes = std::fs::read(&source).unwrap();
    let original_identity = std::fs::metadata(&source).unwrap().ino();
    let budget = view.execution_budget();
    let reserved = budget.reserved_bytes();
    struct RestoreJournal<'a> {
        source: &'a std::path::Path,
        saved: &'a std::path::Path,
    }
    impl Drop for RestoreJournal<'_> {
        fn drop(&mut self) {
            if std::fs::symlink_metadata(self.source).is_ok() {
                std::fs::remove_file(self.source).unwrap();
            }
            std::fs::rename(self.saved, self.source).unwrap();
        }
    }
    with_proof_reader(&view, |reader| {
        for kind in ["missing", "same-bytes-replacement", "symlink"] {
            reader.proof(2).unwrap();
            std::fs::rename(&source, &saved).unwrap();
            let restore = RestoreJournal {
                source: &source,
                saved: &saved,
            };
            match kind {
                "missing" => assert!(!source.exists()),
                "same-bytes-replacement" => {
                    std::fs::copy(&saved, &source).unwrap();
                    assert_eq!(std::fs::read(&source).unwrap(), bytes);
                    assert_ne!(std::fs::metadata(&source).unwrap().ino(), original_identity);
                }
                "symlink" => std::os::unix::fs::symlink(&saved, &source).unwrap(),
                _ => unreachable!(),
            }
            let expected = build_proof(&view, 3).unwrap_err();
            let actual = reader.proof(3).unwrap_err();
            assert!(matches!(
                actual,
                ProofError::Chain(ChainReadError::NotInView { height: 1 })
            ));
            assert_eq!(actual.to_string(), expected.to_string());
            assert_eq!(budget.reserved_bytes(), reserved);
            assert_eq!(std::fs::read(&saved).unwrap(), bytes);
            drop(restore);
            assert_eq!(std::fs::metadata(&source).unwrap().ino(), original_identity);
            assert_eq!(std::fs::read(&source).unwrap(), bytes);
            assert_eq!(reader.proof(3).unwrap(), original);
        }
    });
    assert_eq!(budget.reserved_bytes(), reserved);
    assert_eq!(chain.height(), 3);
}

#[test]
fn callback_unwind_releases_the_same_native_source_pool_without_advancing_state() {
    with_chain_at(2, check_unwind_cleanup);
}

#[inline(never)]
fn check_unwind_cleanup(chain: &CertifiedTestChain) {
    let view = chain.state().view();
    let original = build_proof(&view, 2).unwrap();
    let budget = view.execution_budget();
    let reserved = budget.reserved_bytes();
    let stopped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        with_proof_reader(&view, |reader| {
            assert_eq!(reader.proof(2).unwrap(), original);
            assert!(budget.reserved_bytes() > reserved);
            panic!("stop this exclusively owned proof read");
        });
    }));
    assert!(stopped.is_err());
    assert_eq!(budget.reserved_bytes(), reserved);
    assert_eq!(chain.height(), 2);
    assert_eq!(build_proof(&view, 2).unwrap(), original);
}

#[test]
fn ascending_proofs_cannot_hide_corruption_of_a_previously_verified_real_quorum() {
    with_chain_at(3, check_earlier_quorum_loss);
}

#[inline(never)]
fn check_earlier_quorum_loss(chain: &CertifiedTestChain) {
    let view = chain.state().view();
    let original = build_proof(&view, 3).unwrap();
    let qc = chain
        .committed(2)
        .block()
        .commit_certificate()
        .unwrap()
        .commit_qc()
        .to_vec();
    let budget = view.execution_budget();
    // The corruption helper evicts Kura's published owner. Retain that existing
    // physical allocation while measuring reader cleanup; no retained image
    // is offered to the proof producer or used to authenticate the new source.
    let original_publications = [chain
        .kura()
        .get_block(NonZeroUsize::new(2).unwrap(), &budget)
        .unwrap()
        .unwrap()];
    let reserved = budget.reserved_bytes();
    with_proof_reader(&view, |reader| {
        reader.proof(2).unwrap();
        chain.corrupt_local_quorum_for_test(2, Signers::BelowQuorum);
        let expected = build_proof(&view, 3).unwrap_err();
        let actual = reader.proof(3).unwrap_err();
        assert!(matches!(actual, ProofError::Chain(_)));
        assert_eq!(actual.to_string(), expected.to_string());
        assert_eq!(budget.reserved_bytes(), reserved);
        chain
            .kura()
            .corrupt_commit_certificate_for_testing(NonZeroUsize::new(2).unwrap(), Some(qc))
            .unwrap();
        assert_eq!(reader.proof(3).unwrap(), original);
        assert_eq!(
            chain.committed(3).block().encode_wire().unwrap(),
            original.block_wire
        );
    });
    assert_eq!(budget.reserved_bytes(), reserved);
    drop(original_publications);
    assert_eq!(chain.height(), 3);
}

#[test]
fn ascending_proofs_cannot_hide_corruption_of_constructor_authenticated_genesis() {
    with_chain_at(3, check_genesis_source_loss);
}

#[inline(never)]
fn check_genesis_source_loss(chain: &CertifiedTestChain) {
    let view = chain.state().view();
    let original = build_proof(&view, 3).unwrap();
    let genesis = chain
        .committed(1)
        .block()
        .commit_certificate()
        .unwrap()
        .result_preimage()
        .to_vec();
    let budget = view.execution_budget();
    // The corruption helper evicts Kura's published owner. Retain that existing
    // physical allocation while measuring reader cleanup; no retained image
    // is offered to the proof producer or used to authenticate the new source.
    let original_publications = [chain
        .kura()
        .get_block(NonZeroUsize::new(1).unwrap(), &budget)
        .unwrap()
        .unwrap()];
    let reserved = budget.reserved_bytes();
    with_proof_reader(&view, |reader| {
        reader.proof(2).unwrap();
        chain
            .kura()
            .corrupt_commit_result_for_testing(NonZeroUsize::new(1).unwrap(), vec![0])
            .unwrap();
        let expected = build_proof(&view, 3).unwrap_err();
        let actual = reader.proof(3).unwrap_err();
        assert_eq!(actual.to_string(), expected.to_string());
        assert!(matches!(
            actual,
            ProofError::Chain(ChainReadError::Malformed { height: 1, .. })
        ));
        assert_eq!(budget.reserved_bytes(), reserved);
        chain
            .kura()
            .corrupt_commit_result_for_testing(NonZeroUsize::new(1).unwrap(), genesis)
            .unwrap();
        assert_eq!(reader.proof(3).unwrap(), original);
    });
    assert_eq!(budget.reserved_bytes(), reserved);
    drop(original_publications);
    assert_eq!(chain.height(), 3);
}

#[test]
fn mutation_after_genuine_target_verification_is_refused_before_exposing_the_proof() {
    with_chain_at(3, check_during_target_change);
}

#[test]
fn warm_target_failure_replays_the_original_earlier_gap_diagnosis_and_source_retry() {
    with_chain_at(3, check_warm_failure_order);
}

#[inline(never)]
fn check_warm_failure_order(chain: &CertifiedTestChain) {
    let view = chain.state().view();
    let original = build_proof(&view, 3).unwrap();
    let earlier_qc = chain
        .committed(2)
        .block()
        .commit_certificate()
        .unwrap()
        .commit_qc()
        .to_vec();
    let target_qc = chain
        .committed(3)
        .block()
        .commit_certificate()
        .unwrap()
        .commit_qc()
        .to_vec();
    let budget = view.execution_budget();
    // The corruption helper evicts Kura's published owner. Retain that existing
    // physical allocation while measuring reader cleanup; no retained image
    // is offered to the proof producer or used to authenticate the new source.
    let original_publications = [
        chain
            .kura()
            .get_block(NonZeroUsize::new(2).unwrap(), &budget)
            .unwrap()
            .unwrap(),
        chain
            .kura()
            .get_block(NonZeroUsize::new(3).unwrap(), &budget)
            .unwrap()
            .unwrap(),
    ];
    let reserved = budget.reserved_bytes();
    let change_original = || {
        // Corrupt the target first while its producer can still read the genuine
        // earlier prefix. Neither operation commits under the invalid local QC.
        chain.corrupt_local_quorum_for_test(3, Signers::BelowQuorum);
        chain.corrupt_local_quorum_for_test(2, Signers::BelowQuorum);
    };
    with_proof_reader(&view, |reader| {
        reader.proof(2).unwrap();
        // This changes actual original QCs after the prior prefix's fresh byte
        // fence. The warm target now fails, while a fresh reader must diagnose
        // the earlier gap before verifying the target certificate.
        reader.before_verified = Some(&change_original);
        let actual = reader.proof(3).unwrap_err();
        let expected = build_proof(&view, 3).unwrap_err();
        assert!(matches!(
            actual,
            ProofError::Chain(ChainReadError::Certificate { height: 2, .. })
        ));
        assert_eq!(actual.to_string(), expected.to_string());
        assert_eq!(budget.reserved_bytes(), reserved);
        for (height, qc) in [(2, earlier_qc), (3, target_qc)] {
            chain
                .kura()
                .corrupt_commit_certificate_for_testing(
                    NonZeroUsize::new(height).unwrap(),
                    Some(qc),
                )
                .unwrap();
        }
        assert_eq!(reader.proof(3).unwrap(), original);
        assert_eq!(
            chain.committed(3).block().encode_wire().unwrap(),
            original.block_wire
        );
    });
    assert_eq!(budget.reserved_bytes(), reserved);
    drop(original_publications);
    assert_eq!(chain.height(), 3);
}

#[inline(never)]
fn check_during_target_change(chain: &CertifiedTestChain) {
    let view = chain.state().view();
    let original = build_proof(&view, 3).unwrap();
    let qc = chain
        .committed(2)
        .block()
        .commit_certificate()
        .unwrap()
        .commit_qc()
        .to_vec();
    let budget = view.execution_budget();
    // The corruption helper evicts Kura's published owner. Retain that existing
    // physical allocation while measuring reader cleanup; no retained image
    // is offered to the proof producer or used to authenticate the new source.
    let original_publications = [chain
        .kura()
        .get_block(NonZeroUsize::new(2).unwrap(), &budget)
        .unwrap()
        .unwrap()];
    let reserved = budget.reserved_bytes();
    let change_original = || chain.corrupt_local_quorum_for_test(2, Signers::BelowQuorum);
    with_proof_reader(&view, |reader| {
        reader.proof(2).unwrap();
        reader.after_verified = Some(&change_original);
        let actual = reader.proof(3).unwrap_err();
        let expected = build_proof(&view, 3).unwrap_err();
        assert!(matches!(actual, ProofError::Chain(_)));
        assert_eq!(actual.to_string(), expected.to_string());
        assert_eq!(budget.reserved_bytes(), reserved);
        chain
            .kura()
            .corrupt_commit_certificate_for_testing(NonZeroUsize::new(2).unwrap(), Some(qc))
            .unwrap();
        assert_eq!(reader.proof(3).unwrap(), original);
        assert_eq!(
            chain.committed(3).block().encode_wire().unwrap(),
            original.block_wire
        );
    });
    assert_eq!(budget.reserved_bytes(), reserved);
    drop(original_publications);
    assert_eq!(chain.height(), 3);
}

#[test]
fn finite_finality_interval_under_original_codec_checks_each_real_quorum_once() {
    with_chain_at(10, check_finite_finality_interval);
}

#[inline(never)]
fn check_finite_finality_interval(chain: &CertifiedTestChain) {
    let view = chain.state().view();
    let from = 5;
    let to = chain.height();
    let budget = view.execution_budget();
    let reserved = budget.reserved_bytes();
    // Derive the finite allowance from this exact public producer and genuine
    // signed boundary fixture, including its durable-body/metadata prelude.
    let measured = DecodeBudgetContext::new(caller_limits(usize::MAX));
    let expected = measured.with(|| collect_original_interval(&view, from, to));
    let debit = measured.consumed_allocated_bytes();
    assert!(debit > 0);
    let finite = DecodeBudgetContext::new(caller_limits(usize::try_from(debit).unwrap()));
    chain.kura().reset_canonical_query_reads_for_test();
    let (actual, relations) = relation_counts::measure(|| {
        finite.with(|| {
            let owner =
                crate::state::CanonicalHistoryReadBudget::new(budget.clone(), finite.clone());
            let bytes = expected
                .iter()
                .map(|proof| norito::canonical_frame_len(proof).unwrap())
                .sum();
            let limits = NativeFinalityProofIntervalLimits::new(
                std::num::NonZeroU64::new(from).unwrap(),
                std::num::NonZeroU64::new(to).unwrap(),
                std::num::NonZeroUsize::new(
                    iroha_data_model::sumeragi_finality::MAX_FINALITY_BLOCK_BYTES,
                )
                .unwrap(),
                std::num::NonZeroUsize::new(bytes).unwrap(),
                std::time::Instant::now() + std::time::Duration::from_secs(900),
            )
            .unwrap();
            let retained = chain
                .state()
                .read_finality_proof_interval(
                    &owner,
                    &limits,
                    &std::sync::atomic::AtomicBool::new(false),
                )
                .unwrap();
            assert!(
                budget.reserved_bytes() > reserved,
                "original response allocations remain charged while borrowed"
            );
            // Test oracle copies only; production exposes immutable charged loans.
            let actual: Vec<_> = (0..retained.len())
                .map(|index| retained.proof(index).unwrap().clone())
                .collect();
            drop(retained);
            actual
        })
    });
    let (physical_reads, _) = chain.kura().canonical_query_reads_for_test();
    assert_eq!(
        actual, expected,
        "full portable proof bytes and committee stay identical"
    );
    assert_eq!(budget.reserved_bytes(), reserved);
    assert_eq!(
        relations.qcs,
        (2..=to).collect::<Vec<_>>(),
        "one finite original-owner interval must verify each real native quorum once; physical_reads={physical_reads}"
    );
    // Constructor + one genesis-prefix body, one target/gap walk, one final
    // complete raw-source join. No fitted elapsed-time or larger codec limit.
    assert_eq!(physical_reads, usize::try_from(to * 2 + 1).unwrap());
    assert!(finite.consumed_allocated_bytes() <= debit);
    assert_eq!(view.height(), usize::try_from(to).unwrap());
}

fn collect_original_interval(
    view: &impl StateReadOnly,
    from: u64,
    to: u64,
) -> Vec<SumeragiFinalityProof> {
    (from..=to)
        .map(|height| build_proof(view, height).unwrap())
        .collect()
}
