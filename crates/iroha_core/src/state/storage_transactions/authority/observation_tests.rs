//! Actual writer/reader contention and callback-after-unlock observation tests.

use super::*;
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

#[test]
fn native_reader_refusal_keeps_its_exact_source_and_releases_membership_writer() {
    let storage = TransactionsStorage::new();
    let mut release_registration_0 =
        crate::unit_test_support::release_registration(&storage.budget);
    let native = storage
        .blocks
        .try_write_admitted(|demand| history::admit(&storage.budget, demand))
        .expect("original funded native history writer");
    let prepared = native.prepare_commit();
    let reader_wait = storage.blocks.observe_reader_release();
    let writer_wait = storage.released.observe();
    let refusal = storage
        .try_membership_observation()
        .err()
        .expect("actual reader is held");
    assert_eq!(refusal, MembershipAdmissionError::Busy(reader_wait.clone()));
    assert_ne!(refusal.release_wait(), Some(&writer_wait));
    assert!(
        storage.reader_test_writer_available(),
        "partial acquisition releases membership"
    );
    drop(prepared);
    let mut waiting = reader_wait.wait_for_release(&mut release_registration_0);
    let mut context = Context::from_waker(Waker::noop());
    assert_eq!(Pin::new(&mut waiting).poll(&mut context), Poll::Ready(()));
    let observation = storage
        .try_membership_observation()
        .expect("same reader source is now free");
    assert_eq!(
        observation
            .membership_authority_cut(0)
            .unwrap()
            .frontier_height(),
        0
    );
    assert!(observation.publication_surface().current.is_none());
}

struct UnlockedProbe {
    storage: Arc<TransactionsStorage>,
    wakes: AtomicUsize,
}

impl Wake for UnlockedProbe {
    fn wake(self: Arc<Self>) {
        assert!(
            self.storage.reader_test_writer_available(),
            "membership writer must be free"
        );
        assert!(
            self.storage.blocks.try_read().is_ok(),
            "native reader lock must be free"
        );
        self.wakes.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn original_reader_notice_waits_for_observation_release_on_success_and_unwind() {
    for unwind in [false, true] {
        let storage = Arc::new(TransactionsStorage::new());
        let mut release_registration_0 =
            crate::unit_test_support::release_registration(&storage.budget);
        let pool_before = storage.budget.reserved_bytes();
        let wait = storage.blocks.observe_reader_release();
        let probe = Arc::new(UnlockedProbe {
            storage: Arc::clone(&storage),
            wakes: AtomicUsize::new(0),
        });
        let waker = Waker::from(Arc::clone(&probe));
        let mut context = Context::from_waker(&waker);
        let mut waiting = wait.wait_for_release(&mut release_registration_0);
        assert_eq!(Pin::new(&mut waiting).poll(&mut context), Poll::Pending);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            storage.budget.with_deferred_refund_notifications(|_| {
                let observation = storage.try_membership_observation().unwrap();
                assert_eq!(probe.wakes.load(Ordering::SeqCst), 0);
                assert!(storage.write_lock.try_lock().is_none());
                assert_eq!(
                    observation
                        .membership_authority_cut(0)
                        .unwrap()
                        .row_visits(),
                    0
                );
                assert_eq!(
                    storage.budget.reserved_bytes(),
                    pool_before,
                    "observation creates no publication allocation"
                );
                assert!(!unwind, "injected borrowed consumer unwind");
                drop(observation);
            });
        }));
        assert_eq!(result.is_err(), unwind);
        assert_eq!(probe.wakes.load(Ordering::SeqCst), 1);
        assert_eq!(Pin::new(&mut waiting).poll(&mut context), Poll::Ready(()));
        assert_eq!(storage.budget.reserved_bytes(), pool_before);
        assert!(storage.try_membership_observation().is_ok());
    }
}
