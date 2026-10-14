//! Original prepaid loop wake custody without new waiter or channel allocations.

use std::{
    sync::{
        OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    thread::Thread,
};

use iroha_allocation::{AllocationBudget, ChargedShared, shared::SharedWake};

use super::DriverError;

/// The one stable allocation shared by all input senders and release wakers.
pub(super) struct ThreadWake {
    thread: OnceLock<Thread>,
    pending: AtomicBool,
}

impl ThreadWake {
    pub(super) fn admit(budget: &AllocationBudget) -> Result<ChargedShared<Self>, DriverError> {
        let mut reservation = budget.try_reserve(ChargedShared::<Self>::allocation_layout())?;
        ChargedShared::from_reservation(
            Self {
                thread: OnceLock::new(),
                pending: AtomicBool::new(false),
            },
            &mut reservation,
        )
        .map_err(|(_, error)| error.into())
    }

    pub(super) fn bind_current(&self) {
        self.thread
            .set(std::thread::current())
            .expect("the loop binds its original wake once");
        // A worker may finish before the loop was spawned or bound to this control.
        if self.pending.load(Ordering::Acquire) {
            self.thread.get().expect("loop bound").unpark();
        }
    }

    /// Borrow the same startup-captured thread for callback-free resource waits.
    /// Cloning its handle initializes no new Thread or native parking control.
    pub(super) fn original_thread(&self) -> Thread {
        self.thread
            .get()
            .expect("loop bound before resource waits")
            .clone()
    }

    pub(super) fn notify(&self) {
        self.pending.store(true, Ordering::Release);
        if let Some(thread) = self.thread.get() {
            thread.unpark();
        }
    }

    pub(super) fn take_pending(&self) -> bool {
        self.pending.swap(false, Ordering::AcqRel)
    }
}

impl SharedWake for ThreadWake {
    fn wake(&self) {
        self.notify();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sumeragi::driver::{DriverInputs, Input};
    use iroha_allocation::{AllocationRefusal, release::ReleaseRegistration};
    use std::{
        sync::mpsc,
        task::{Context, Poll},
        time::Duration,
    };

    #[test]
    fn original_wake_is_funded_before_startup_and_retained_by_its_waker() {
        let bytes = ChargedShared::<ThreadWake>::allocation_layout().size();
        let budget = AllocationBudget::new(bytes - 1);
        assert!(matches!(
            ThreadWake::admit(&budget),
            Err(DriverError::Admission(
                AllocationRefusal::ExceedsLimit { .. }
            ))
        ));
        assert_eq!(budget.reserved_bytes(), 0);
        budget.set_limit_bytes(bytes);
        let owner = ThreadWake::admit(&budget).unwrap();
        let waker = owner.clone().into_waker();
        assert_eq!(budget.reserved_bytes(), bytes);
        drop(owner);
        assert_eq!(budget.reserved_bytes(), bytes);
        waker.wake();
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn inputs_and_original_release_keep_the_last_drain_to_park_edge() {
        let bytes = ChargedShared::<ThreadWake>::allocation_layout().size()
            + ReleaseRegistration::allocation_layout().size();
        let budget = AllocationBudget::new(bytes + 1);
        let owner = ThreadWake::admit(&budget).unwrap();
        let mut registration = ReleaseRegistration::from_reservation(
            &mut budget
                .try_reserve(ReleaseRegistration::allocation_layout())
                .unwrap(),
        )
        .unwrap();
        let held = budget.try_reserve_bytes(1).unwrap();
        let AllocationRefusal::Capacity { release, .. } = budget.try_reserve_bytes(1).unwrap_err()
        else {
            panic!("original exhausted pool")
        };
        let waker = owner.clone().into_waker();
        let mut context = Context::from_waker(&waker);
        assert_eq!(
            registration.poll_wait(&release, &mut context),
            Poll::Pending
        );
        // An actual resource releases before the loop exists. Binding preserves its edge.
        drop(held);
        assert!(owner.pending.load(Ordering::Acquire));
        owner.bind_current();
        assert!(owner.take_pending());
        assert_eq!(
            registration.poll_wait(&release, &mut context),
            Poll::Ready(())
        );
        let (sender, receiver) = mpsc::channel();
        let inputs = DriverInputs {
            sender,
            wake: owner.clone(),
        };
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        inputs.send(Input::Transactions).unwrap();
        assert!(
            owner.take_pending(),
            "input after empty drain prevents parking"
        );
        assert!(matches!(receiver.try_recv(), Ok(Input::Transactions)));
        assert!(!owner.take_pending());
        drop(inputs);
        drop(registration);
        drop(waker);
        drop(owner);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn original_release_wakes_actual_park_after_final_pending_check() {
        let bytes = ChargedShared::<ThreadWake>::allocation_layout().size()
            + ReleaseRegistration::allocation_layout().size();
        let budget = AllocationBudget::new(bytes + 1);
        let owner = ThreadWake::admit(&budget).unwrap();
        let mut registration = ReleaseRegistration::from_reservation(
            &mut budget
                .try_reserve(ReleaseRegistration::allocation_layout())
                .unwrap(),
        )
        .unwrap();
        let held = budget.try_reserve_bytes(1).unwrap();
        let AllocationRefusal::Capacity { release, .. } = budget.try_reserve_bytes(1).unwrap_err()
        else {
            panic!("original exhausted pool")
        };
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        let thread_owner = owner.clone();
        let cleanup = std::sync::Arc::new(AtomicBool::new(false));
        let helper_cleanup = cleanup.clone();
        let helper = std::thread::spawn(move || {
            thread_owner.bind_current();
            let waker = thread_owner.clone().into_waker();
            let mut context = Context::from_waker(&waker);
            assert_eq!(
                registration.poll_wait(&release, &mut context),
                Poll::Pending
            );
            assert!(!thread_owner.take_pending());
            ready_tx.send(()).unwrap();
            // Release happens after the final latch check; an early unpark is retained too.
            loop {
                std::thread::park();
                if thread_owner.take_pending() {
                    break;
                }
                // Parking may return spuriously. Parent cleanup remains independent
                // of the release callback under test, including when that callback fails.
                if helper_cleanup.load(Ordering::Acquire) {
                    return;
                }
            }
            assert_eq!(
                registration.poll_wait(&release, &mut context),
                Poll::Ready(())
            );
            done_tx.send(()).unwrap();
        });
        let ready = ready_rx.recv_timeout(Duration::from_secs(10));
        drop(held);
        let completed = done_rx.recv_timeout(Duration::from_secs(10));
        // Bounded cleanup is independent of the source wake and runs on every outcome.
        cleanup.store(true, Ordering::Release);
        helper.thread().unpark();
        let joined = helper.join();
        assert!(
            ready.is_ok(),
            "helper reached final pending check: {ready:?}"
        );
        assert!(
            completed.is_ok(),
            "original release woke the parked helper: {completed:?}"
        );
        joined.unwrap();
        drop(owner);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn original_thread_capacity_release_unparks_after_final_latch_check_with_writer_retained() {
        let bytes = ChargedShared::<ThreadWake>::allocation_layout().size()
            + ReleaseRegistration::allocation_layout().size()
            + iroha_allocation::OwnedAllocationScope::allocation_layout().size();
        let budget = AllocationBudget::new(bytes + 1);
        let owner = ThreadWake::admit(&budget).unwrap();
        let mut registration = ReleaseRegistration::from_reservation(
            &mut budget
                .try_reserve(ReleaseRegistration::allocation_layout())
                .unwrap(),
        )
        .unwrap();
        let retained_writer_scope = budget.try_owned_refund_scope().unwrap();
        let held = budget.try_reserve_bytes(1).unwrap();
        let AllocationRefusal::Capacity { release, .. } = budget.try_reserve_bytes(1).unwrap_err()
        else {
            panic!("original exhausted pool");
        };
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        let thread_owner = owner.clone();
        let cleanup = std::sync::Arc::new(AtomicBool::new(false));
        let helper_cleanup = cleanup.clone();
        let helper = std::thread::spawn(move || {
            thread_owner.bind_current();
            registration.bind_thread(thread_owner.original_thread());
            let waker = thread_owner.clone().into_waker();
            let mut context = Context::from_waker(&waker);
            assert_eq!(
                registration.poll_wait(&release, &mut context),
                Poll::Pending
            );
            assert!(!thread_owner.take_pending());
            ready_tx.send(()).unwrap();
            // This is the production drain-to-park edge. A credit return before
            // park leaves a token; one after park wakes the original thread.
            loop {
                std::thread::park();
                if helper_cleanup.load(Ordering::Acquire) {
                    return;
                }
                if registration.poll_wait(&release, &mut context).is_ready() {
                    break;
                }
            }
            assert!(
                !thread_owner.take_pending(),
                "thread release did not invoke task callback"
            );
            done_tx.send(()).unwrap();
        });
        let ready = ready_rx.recv_timeout(Duration::from_secs(10));
        drop(held);
        let completed = done_rx.recv_timeout(Duration::from_secs(10));
        // Cleanup works even if the source under test failed to unpark. It does
        // not retire the original writer scope until the verdict is captured.
        cleanup.store(true, Ordering::Release);
        helper.thread().unpark();
        let joined = helper.join();
        assert!(
            ready.is_ok(),
            "native waiter reached final latch check: {ready:?}"
        );
        assert!(
            completed.is_ok(),
            "actual credit woke native parked thread with writer retained: {completed:?}"
        );
        joined.unwrap();
        drop(retained_writer_scope);
        drop(owner);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}
