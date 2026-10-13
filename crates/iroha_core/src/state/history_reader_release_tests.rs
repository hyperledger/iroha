//! Actual original reader waits must outlive State fences and executing writers.

use super::*;
use crate::query::store::LiveQueryStore;
use std::{
    future::Future,
    num::NonZeroU64,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    task::{Context, Wake, Waker},
};

struct Probe {
    state: Arc<State>,
    calls: AtomicUsize,
    blocked: AtomicBool,
}
impl Wake for Probe {
    fn wake(self: Arc<Self>) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.state.state_commit_lock.try_lock().is_none()
            || self.state.state_write_lock.try_lock().is_none()
            || self.state.lane_lifecycle_lock.try_lock().is_none()
            || !self.state.transactions.reader_test_writer_available()
        {
            self.blocked.store(true, Ordering::SeqCst);
        }
    }
}
fn state() -> Arc<State> {
    Arc::new(State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    ))
}
fn probe(state: &Arc<State>) -> Arc<Probe> {
    Arc::new(Probe {
        state: Arc::clone(state),
        calls: AtomicUsize::new(0),
        blocked: AtomicBool::new(false),
    })
}
fn waits(state: &State) -> [iroha_allocation::release::ReleaseWait; 2] {
    [
        state.block_hashes.map().unwrap().observe_reader_release(),
        state.transactions.reader_release_wait_for_tests(),
    ]
}

#[test]
fn complete_view_retains_both_native_reader_notices_beyond_state_fences() {
    for unwind in [false, true] {
        let state = state();
        let mut release_registration_0 =
            crate::unit_test_support::release_registration(&state.ivm_execution_budget());
        let mut release_registration_1 =
            crate::unit_test_support::release_registration(&state.ivm_execution_budget());
        let probe = probe(&state);
        let waker = Waker::from(Arc::clone(&probe));
        let mut context = Context::from_waker(&waker);
        let [hash, membership] = waits(&state);
        let mut hash = std::pin::pin!(hash.wait_for_release(&mut release_registration_0));
        let mut membership =
            std::pin::pin!(membership.wait_for_release(&mut release_registration_1));
        assert!(hash.as_mut().poll(&mut context).is_pending());
        assert!(membership.as_mut().poll(&mut context).is_pending());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut releases = StateViewReleases::new(&state);
            let _commit = state.state_commit_lock.lock();
            let _write = state.state_write_lock.lock();
            let _lifecycle = state.lane_lifecycle_lock.lock();
            for _ in 0..3 {
                let view = releases.try_view_once().unwrap();
                assert_eq!(view.block_hashes.len(), 0);
                drop(view);
                assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
            }
            assert!(!unwind, "original outer fence unwind")
        }));
        assert_eq!(result.is_err(), unwind);
        assert_eq!(probe.calls.load(Ordering::SeqCst), 2);
        assert!(!probe.blocked.load(Ordering::SeqCst));
        assert!(hash.as_mut().poll(&mut context).is_ready());
        assert!(membership.as_mut().poll(&mut context).is_ready());
    }
}

#[test]
fn executing_state_retains_captured_reader_notices_until_joint_writer_retirement() {
    for unwind in [false, true] {
        let state = state();
        let probe = probe(&state);
        let waker = Waker::from(Arc::clone(&probe));
        let mut context = Context::from_waker(&waker);
        let mut registrations: [_; 2] = std::array::from_fn(|_| {
            crate::unit_test_support::release_registration(&state.ivm_execution_budget())
        });
        let mut pending = None;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut block = state.block(BlockHeader::new(NonZeroU64::MIN, None, None, 1, 0));
            let futures = waits(&state);
            pending = Some(futures);
            for (future, registration) in pending.as_ref().unwrap().iter().zip(&mut registrations) {
                assert!(registration.poll_wait(future, &mut context).is_pending());
            }
            let _hash = block._read_releases.lane_execution_state_hash().unwrap();
            assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
            assert!(!state.transactions.reader_test_writer_available());
            assert!(!unwind, "original executing-State unwind");
            drop(block);
        }));
        assert_eq!(result.is_err(), unwind);
        assert_eq!(probe.calls.load(Ordering::SeqCst), 2);
        assert!(!probe.blocked.load(Ordering::SeqCst));
        for (future, registration) in pending.as_ref().unwrap().iter().zip(&mut registrations) {
            assert!(registration.poll_wait(future, &mut context).is_ready());
        }
    }
}

#[test]
fn detached_read_notices_survive_ending_the_state_borrow() {
    let state = state();
    let probe = probe(&state);
    let waker = Waker::from(Arc::clone(&probe));
    let mut context = Context::from_waker(&waker);
    let mut registrations: [_; 2] = std::array::from_fn(|_| {
        crate::unit_test_support::release_registration(&state.ivm_execution_budget())
    });
    let pending = waits(&state);
    for (future, registration) in pending.iter().zip(&mut registrations) {
        assert!(registration.poll_wait(future, &mut context).is_pending());
    }
    {
        let retirement;
        let mut releases = StateViewReleases::new(&state);
        let commit = state.state_commit_lock.lock();
        let captured =
            crate::snapshot::CapturedStateSnapshot::capture_with_releases(&mut releases).unwrap();
        assert_eq!(captured.height(), 0);
        retirement = releases.into_retirement();
        assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
        drop(commit);
        assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
        drop(retirement);
    }
    assert_eq!(probe.calls.load(Ordering::SeqCst), 2);
    assert!(!probe.blocked.load(Ordering::SeqCst));
}

#[test]
fn serializer_uses_only_the_already_captured_membership_reader() {
    let state = state();
    let mut release_registration_0 =
        crate::unit_test_support::release_registration(&state.ivm_execution_budget());
    let probe = probe(&state);
    let waker = Waker::from(Arc::clone(&probe));
    let mut context = Context::from_waker(&waker);
    let wait = state.transactions.reader_release_wait_for_tests();
    let mut pending = std::pin::pin!(wait.wait_for_release(&mut release_registration_0));
    assert!(pending.as_mut().poll(&mut context).is_pending());
    let mut releases = StateViewReleases::new(&state);
    let captured =
        crate::snapshot::CapturedStateSnapshot::capture_with_releases(&mut releases).unwrap();
    assert!(captured.as_json().contains("\"transactions\":"));
    assert_eq!(
        probe.calls.load(Ordering::SeqCst),
        0,
        "a second ordinary storage read would synchronously notify here"
    );
    drop(releases);
    assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
    assert!(pending.as_mut().poll(&mut context).is_ready());
}

#[test]
fn membership_read_refuses_foreign_original_batch_without_notifying() {
    let left = state();
    let mut release_registration_0 =
        crate::unit_test_support::release_registration(&left.ivm_execution_budget());
    let right = state();
    let probe = probe(&left);
    let waker = Waker::from(Arc::clone(&probe));
    let mut context = Context::from_waker(&waker);
    let wait = left.transactions.reader_release_wait_for_tests();
    let mut pending = std::pin::pin!(wait.wait_for_release(&mut release_registration_0));
    assert!(pending.as_mut().poll(&mut context).is_pending());
    let mut foreign = right.transactions.reader_release_batch();
    assert!(matches!(
        left.transactions.view_retaining(&mut foreign),
        Err(concread::bptree::OwnedWriteError::Changed)
    ));
    drop(foreign);
    assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
    assert!(pending.as_mut().poll(&mut context).is_pending());
}

#[test]
fn emergency_empty_history_never_substitutes_a_reader_source() {
    let history = BlockHashes::new_emergency_fast_empty();
    let mut releases = history.reader_release_batch();
    assert!(releases.is_none());
    assert!(history.view_retaining(&mut releases).is_empty());
}

#[test]
fn original_read_notices_survive_an_actual_state_swap_under_the_commit_fence() {
    struct SwapProbe {
        commit: Arc<crate::publication_lock::PublicationMutex>,
        calls: AtomicUsize,
        blocked: AtomicBool,
    }
    impl Wake for SwapProbe {
        fn wake(self: Arc<Self>) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.commit.try_lock().is_none() {
                self.blocked.store(true, Ordering::SeqCst);
            }
        }
    }
    let mut original = State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let mut replacement = State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let probe = Arc::new(SwapProbe {
        commit: Arc::clone(&original.state_commit_lock),
        calls: AtomicUsize::new(0),
        blocked: AtomicBool::new(false),
    });
    let waker = Waker::from(Arc::clone(&probe));
    let mut context = Context::from_waker(&waker);
    let mut registrations: [_; 2] = std::array::from_fn(|_| {
        crate::unit_test_support::release_registration(&original.ivm_execution_budget())
    });
    let pending = waits(&original);
    for (future, registration) in pending.iter().zip(&mut registrations) {
        assert!(registration.poll_wait(future, &mut context).is_pending());
    }
    let (hash_budget, membership_budget) = original.history_allocation_budgets();
    membership_budget.with_deferred_refund_notifications(|_| {
        hash_budget.with_deferred_refund_notifications(|_| {
            let retirement;
            let mut releases = StateViewReleases::new(&original);
            let commit = probe.commit.lock();
            drop(releases.try_view_once().unwrap());
            retirement = releases.into_retirement();
            std::mem::swap(&mut original, &mut replacement);
            drop(replacement);
            assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
            drop(commit);
            assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
            drop(retirement);
        })
    });
    assert_eq!(probe.calls.load(Ordering::SeqCst), 2);
    assert!(!probe.blocked.load(Ordering::SeqCst));
    for (future, registration) in pending.iter().zip(&mut registrations) {
        assert!(registration.poll_wait(future, &mut context).is_ready());
    }
}

#[test]
fn original_read_custody_preserves_worker_send_and_sync() {
    fn require_send_sync<T: Send + Sync>() {}
    require_send_sync::<StateViewReleases<'static>>();
    require_send_sync::<StateViewRetirement>();
}
