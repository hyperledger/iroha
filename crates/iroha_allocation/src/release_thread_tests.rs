//! Callback-free original thread parking and deferred physical callback custody.

use super::*;
use crate::test_support::without_allocations;
use crate::{AllocationBudget, AllocationRefusal, OwnedAllocationScope};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering::SeqCst},
};
use std::task::Wake;

fn registration(budget: &AllocationBudget) -> ReleaseRegistration {
    ReleaseRegistration::from_reservation(
        &mut budget
            .try_reserve(ReleaseRegistration::allocation_layout())
            .unwrap(),
    )
    .unwrap()
}

fn refused(budget: &AllocationBudget) -> ReleaseWait {
    let AllocationRefusal::Capacity { release, .. } = budget.try_reserve_bytes(1).unwrap_err()
    else {
        panic!("the original full pool supplies its exact capacity observation");
    };
    release
}

struct Reentry {
    writer: std::sync::Mutex<()>,
    calls: AtomicUsize,
}
impl Wake for Reentry {
    fn wake(self: Arc<Self>) {
        let _writer = self
            .writer
            .try_lock()
            .expect("physical writer retired before callback");
        self.calls.fetch_add(1, SeqCst);
    }
}

#[test]
fn real_credit_wakes_original_thread_without_running_callback_under_writer() {
    let original_thread = std::thread::current();
    let limit = 2 * ReleaseRegistration::allocation_layout().size()
        + OwnedAllocationScope::allocation_layout().size()
        + 1;
    let budget = AllocationBudget::new(limit);
    let mut native = registration(&budget);
    let mut callback = registration(&budget);
    native.bind_thread(original_thread);
    let scope = budget.try_owned_refund_scope().unwrap();
    let held = budget.try_reserve_bytes(1).unwrap();
    let release = refused(&budget);
    let probe = Arc::new(Reentry {
        writer: std::sync::Mutex::new(()),
        calls: AtomicUsize::new(0),
    });
    let waker = Waker::from(probe.clone());
    let context = &mut Context::from_waker(&waker);
    let writer = probe.writer.lock().unwrap();
    without_allocations(|| {
        assert_eq!(native.poll_wait(&release, context), Poll::Pending);
        assert_eq!(callback.poll_wait(&release, context), Poll::Pending);
        drop(held);
        assert_eq!(budget.reserved_bytes(), limit - 1);
        assert_eq!(native.poll_wait(&release, context), Poll::Ready(()));
        assert_eq!(callback.poll_wait(&release, context), Poll::Pending);
        assert_eq!(probe.calls.load(SeqCst), 0);
        assert!(native.belongs_to(&budget));
        drop(writer);
        drop(scope);
        assert_eq!(probe.calls.load(SeqCst), 1);
        assert_eq!(callback.poll_wait(&release, context), Poll::Ready(()));
    });
}

#[test]
fn credit_before_and_after_registration_is_not_lost_or_invented_by_refusal() {
    let original_thread = std::thread::current();
    for before_registration in [false, true] {
        let limit = ReleaseRegistration::allocation_layout().size()
            + OwnedAllocationScope::allocation_layout().size()
            + 1;
        let budget = AllocationBudget::new(limit);
        let foreign = AllocationBudget::new(1);
        let mut native = registration(&budget);
        native.bind_thread(original_thread.clone());
        let scope = budget.try_owned_refund_scope().unwrap();
        let held = budget.try_reserve_bytes(1).unwrap();
        let release = refused(&budget);
        let context = &mut Context::from_waker(Waker::noop());
        let mut refunds = budget.deferred_refund_batch();
        without_allocations(|| {
            // Failed and zero-byte admissions never manufacture a credit event.
            assert!(matches!(
                budget.try_reserve_bytes(1),
                Err(AllocationRefusal::Capacity { .. })
            ));
            assert!(matches!(
                budget.try_reserve_bytes(limit + 1),
                Err(AllocationRefusal::ExceedsLimit { .. })
            ));
            drop(budget.try_reserve_bytes(0).unwrap());
            drop(foreign.try_reserve_bytes(1).unwrap());
            budget.set_limit_bytes(limit);
            assert_eq!(release, refused(&budget));
            if !before_registration {
                assert_eq!(native.poll_wait(&release, context), Poll::Pending);
            }
            refunds.with_scope(|_| drop(held));
            assert_eq!(native.poll_wait(&release, context), Poll::Ready(()));
            // Register against the fresh original observation while the reused
            // credit is again occupied; draining the old callback batch alone
            // cannot grant a second native capacity retry.
            let held_again = budget.try_reserve_bytes(1).unwrap();
            let fresh = refused(&budget);
            assert_ne!(fresh, release);
            assert_eq!(native.poll_wait(&fresh, context), Poll::Pending);
            // This batch flush belongs to the already observed old credit. It
            // must not manufacture a second capacity event for the fresh wait.
            drop(refunds);
            assert_eq!(native.poll_wait(&fresh, context), Poll::Pending);
            drop(held_again);
            assert_eq!(native.poll_wait(&fresh, context), Poll::Ready(()));
            drop(scope);
        });
    }
}

#[test]
fn native_limit_growth_and_physical_release_keep_their_distinct_original_causes() {
    let original_thread = std::thread::current();
    let limit = ReleaseRegistration::allocation_layout().size()
        + OwnedAllocationScope::allocation_layout().size()
        + 1;
    let budget = AllocationBudget::new(limit);
    let mut native = registration(&budget);
    native.bind_thread(original_thread);
    let scope = budget.try_owned_refund_scope().unwrap();
    let held = budget.try_reserve_bytes(1).unwrap();
    let release = refused(&budget);
    let context = &mut Context::from_waker(Waker::noop());
    without_allocations(|| {
        assert_eq!(native.poll_wait(&release, context), Poll::Pending);
        budget.set_limit_bytes(limit - 1);
        assert_eq!(native.poll_wait(&release, context), Poll::Pending);
        budget.set_limit_bytes(limit + 1);
        assert_eq!(native.poll_wait(&release, context), Poll::Ready(()));
    });
    let physical = ReleaseNotification::default();
    let physical_release = physical.observe();
    let writer = physical.guard(());
    without_allocations(|| {
        assert_eq!(native.poll_wait(&physical_release, context), Poll::Pending);
        drop(held);
        assert_eq!(native.poll_wait(&physical_release, context), Poll::Pending);
        drop(writer);
        assert_eq!(
            native.poll_wait(&physical_release, context),
            Poll::Ready(())
        );
        drop(scope);
    });
}

#[test]
fn thread_target_replacement_cancellation_and_drop_unlink_original_prepaid_node() {
    let original_thread = std::thread::current();
    // Startup captures the other handle before allocation-free registration.
    let other_thread = std::thread::spawn(std::thread::current).join().unwrap();
    let budget = AllocationBudget::new(ReleaseRegistration::allocation_layout().size());
    let mut native = registration(&budget);
    let first = ReleaseNotification::default();
    let second = ReleaseNotification::default();
    let a = first.observe();
    let b = second.observe();
    let context = &mut Context::from_waker(Waker::noop());
    without_allocations(|| {
        native.bind_thread(original_thread);
        assert_eq!(native.poll_wait(&a, context), Poll::Pending);
        assert_eq!(first.state.lock().unwrap().threads.count, 1);
        native.bind_thread(other_thread);
        assert_eq!(first.state.lock().unwrap().threads.count, 0);
        assert_eq!(native.poll_wait(&b, context), Poll::Pending);
        assert_eq!(second.state.lock().unwrap().threads.count, 1);
        drop(first.guard(()));
        assert_eq!(native.poll_wait(&b, context), Poll::Pending);
        native.cancel();
        assert_eq!(second.state.lock().unwrap().threads.count, 0);
        assert_eq!(native.poll_wait(&b, context), Poll::Pending);
        drop(native);
        assert_eq!(second.state.lock().unwrap().threads.count, 0);
        assert_eq!(budget.reserved_bytes(), 0);
        drop(second.guard(()));
    });
}

#[test]
fn bound_thread_never_clones_or_calls_the_context_waker() {
    use std::task::{RawWaker, RawWakerVTable};
    unsafe fn forbidden_clone(_: *const ()) -> RawWaker {
        panic!("thread poll cloned caller code")
    }
    unsafe fn forbidden_wake(_: *const ()) {
        panic!("thread release invoked caller code")
    }
    unsafe fn inert_drop(_: *const ()) {}
    static VTABLE: RawWakerVTable =
        RawWakerVTable::new(forbidden_clone, forbidden_wake, forbidden_wake, inert_drop);
    // SAFETY: the static vtable carries no data or ownership. Drop is inert;
    // clone/wake deliberately fail if the thread-only path invokes caller code.
    let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
    let original_thread = std::thread::current();
    let budget = AllocationBudget::new(ReleaseRegistration::allocation_layout().size() + 1);
    let mut native = registration(&budget);
    native.bind_thread(original_thread);
    let held = budget.try_reserve_bytes(1).unwrap();
    let release = refused(&budget);
    let context = &mut Context::from_waker(&waker);
    without_allocations(|| {
        assert_eq!(native.poll_wait(&release, context), Poll::Pending);
        drop(held);
        assert_eq!(native.poll_wait(&release, context), Poll::Ready(()));
        drop(native);
    });
}

#[test]
fn capacity_sequence_saturation_releases_registered_thread_and_never_parks_again() {
    let original_thread = std::thread::current();
    let budget = AllocationBudget::new(ReleaseRegistration::allocation_layout().size() + 1);
    let mut native = registration(&budget);
    native.bind_thread(original_thread);
    let held = budget.try_reserve_bytes(1).unwrap();
    let original = refused(&budget);
    original.state.lock().unwrap().capacity_sequence = Some(u64::MAX - 1);
    let before_saturation = refused(&budget);
    let context = &mut Context::from_waker(Waker::noop());
    without_allocations(|| {
        assert_eq!(native.poll_wait(&before_saturation, context), Poll::Pending);
        assert_eq!(original.state.lock().unwrap().threads.count, 1);
        drop(held);
        {
            let source = original.state.lock().unwrap();
            assert_eq!(source.capacity_sequence, Some(u64::MAX));
            assert_eq!(
                source.threads.count, 0,
                "MAX-1 waiter was unlinked and unparked"
            );
        }
        assert_eq!(
            native.poll_wait(&before_saturation, context),
            Poll::Ready(())
        );
        let held_again = budget.try_reserve_bytes(1).unwrap();
        let saturated = refused(&budget);
        assert_eq!(native.poll_wait(&saturated, context), Poll::Ready(()));
        assert_eq!(original.state.lock().unwrap().threads.count, 0);
        drop(held_again);
        assert_eq!(
            original.state.lock().unwrap().capacity_sequence,
            Some(u64::MAX)
        );
        assert_eq!(native.poll_wait(&saturated, context), Poll::Ready(()));
    });
}
