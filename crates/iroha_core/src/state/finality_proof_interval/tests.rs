//! Actual publisher release and versioned State append custody for finite proof work.
use super::*;
use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
use iroha_data_model::sumeragi_finality::MAX_FINALITY_BLOCK_BYTES;
use std::{
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
};

fn limits(height: u64) -> NativeFinalityProofIntervalLimits {
    NativeFinalityProofIntervalLimits::new(
        NonZeroU64::new(2).unwrap(),
        NonZeroU64::new(height).unwrap(),
        NonZeroUsize::new(MAX_FINALITY_BLOCK_BYTES).unwrap(),
        NonZeroUsize::new(usize::MAX).unwrap(),
        Instant::now() + Duration::from_secs(900),
    )
    .unwrap()
}
fn context() -> norito::core::DecodeBudgetContext {
    norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
        1_000_000,
        MAX_FINALITY_BLOCK_BYTES,
        8_000_000,
        usize::MAX,
        128,
    ))
}
fn chain() -> CertifiedTestChain {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 10_000)).unwrap();
    while chain.height() < 4 {
        chain.commit(Vec::new());
    }
    chain
}

#[test]
fn interval_busy_capture_returns_exact_writer_release_without_work_or_refund_under_guard() {
    use std::{
        future::Future,
        task::{Context, Waker},
    };
    let chain = chain();
    let state = chain.state();
    let pool = state.ivm_execution_budget();
    let counter = context();
    let owner = CanonicalHistoryReadBudget::new(pool.clone(), counter.clone());
    let mut registration = crate::unit_test_support::release_registration(&pool);
    // The original waiter is fixture-owned; measure request work after its admission.
    let reserved = pool.reserved_bytes();
    chain.kura().reset_canonical_query_reads_for_test();
    let wait = state.with_held_view_publication_for_reader_test(|expected| {
        let result = state.read_finality_proof_interval(
            &owner,
            &limits(chain.height()),
            &AtomicBool::new(false),
        );
        let Err(FinalityProofIntervalReadError::StateView(StateViewError::Busy(original))) = result
        else {
            panic!("finite proof capture must preserve the actual held publisher's Busy release");
        };
        assert_eq!(original, expected);
        assert_eq!(pool.reserved_bytes(), reserved);
        assert_eq!(counter.consumed_allocated_bytes(), 0);
        assert_eq!(chain.kura().canonical_query_reads_for_test(), (0, 0));
        let mut pending = std::pin::pin!(original.clone().wait_for_release(&mut registration));
        assert!(
            pending
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        original
    });
    let mut completed = std::pin::pin!(wait.wait_for_release(&mut registration));
    assert!(
        completed
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
    );
    let retained = state
        .read_finality_proof_interval(&owner, &limits(chain.height()), &AtomicBool::new(false))
        .unwrap();
    assert!(pool.reserved_bytes() > reserved);
    assert_eq!(
        retained.proof(2).unwrap().block_header.hash(),
        chain.committed(4).block_hash()
    );
    drop(retained);
    assert_eq!(pool.reserved_bytes(), reserved);
}

#[test]
fn interval_original_hash_generation_allows_actual_stable_tip_publication() {
    let mut chain = chain();
    let state = Arc::clone(chain.state());
    let pool = state.ivm_execution_budget();
    let original = chain.committed(4).block_hash();
    let owner = CanonicalHistoryReadBudget::new(pool, context());
    let retained = state
        .read_finality_proof_interval_after_read(
            &owner,
            &limits(4),
            &AtomicBool::new(false),
            || {
                // Real signed commit executes/publishes while the original versioned hash
                // generation is retained. There is no enclosing World or writer guard.
                chain.commit(Vec::new());
            },
        )
        .unwrap();
    assert_eq!(state.committed_height(), 5);
    assert_eq!(retained.proof(2).unwrap().block_header.hash(), original);
    assert_eq!(retained.len(), 3);
}

#[test]
fn interval_post_read_writer_refusal_retires_response_and_preserves_original_release() {
    let chain = chain();
    let state = Arc::clone(chain.state());
    let pool = state.ivm_execution_budget();
    let owner = CanonicalHistoryReadBudget::new(pool.clone(), context());
    let reserved = pool.reserved_bytes();
    let (request_tx, request_rx) = std::sync::mpsc::sync_channel(1);
    let (held_tx, held_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let (result, expected) = std::thread::scope(|scope| {
        let state = Arc::clone(&state);
        let worker = scope.spawn(move || {
            if request_rx.recv_timeout(Duration::from_secs(5)).is_err() {
                return;
            }
            state.with_held_view_publication_for_reader_test(|wait| {
                held_tx.send(wait).unwrap();
                // Natural cleanup even if the producer unexpectedly unwinds.
                let _ = release_rx.recv_timeout(Duration::from_secs(5));
            });
        });
        let mut expected = None;
        let result = chain.state().read_finality_proof_interval_after_read(
            &owner,
            &limits(4),
            &AtomicBool::new(false),
            || {
                request_tx.send(()).unwrap();
                expected = Some(held_rx.recv_timeout(Duration::from_secs(5)).unwrap());
            },
        );
        let _ = release_tx.send(());
        worker.join().unwrap();
        (result, expected)
    });
    let Err(FinalityProofIntervalReadError::StateView(StateViewError::Busy(original))) = result
    else {
        panic!(
            "finite interval must reject an actual publishing State owner after native verification and source join"
        );
    };
    assert_eq!(Some(original), expected);
    assert_eq!(
        pool.reserved_bytes(),
        reserved,
        "refused response values retire before the original pool refund"
    );
    let retained = state
        .read_finality_proof_interval(&owner, &limits(4), &AtomicBool::new(false))
        .unwrap();
    drop(retained);
    assert_eq!(pool.reserved_bytes(), reserved);
}
