//! Reusable original refund controls preserve funding across thread handoff.

use super::*;

#[test]
fn original_control_reactivates_without_allocation_after_pool_limit_shrinks_to_zero() {
    let bytes = OwnedAllocationScope::allocation_layout().size();
    let budget = AllocationBudget::new(bytes);
    let scope = budget.try_owned_refund_scope().unwrap();
    let control = without_allocations(|| scope.control());
    let address = ptr::from_ref(&control.control.record);
    assert!(control.belongs_to(&budget));
    assert!(control.allocation_budget().same_pool(&budget));
    assert!(!control.belongs_to(&AllocationBudget::new(bytes)));
    assert!(matches!(control.try_activate(), Err(AllocationScopeActive)));
    let cleanup = without_allocations(|| scope.clone());
    budget.set_limit_bytes(0);
    drop(scope);
    assert!(matches!(control.try_activate(), Err(AllocationScopeActive)));
    drop(cleanup);
    assert_eq!(budget.reserved_bytes(), bytes);
    without_allocations(|| {
        for _ in 0..8 {
            let active = control.try_activate().unwrap();
            assert_eq!(ptr::from_ref(&active.control.control.record), address);
            assert!(active.belongs_to(&budget));
            assert!(active.borrowed().belongs_to(&budget));
            assert_eq!(budget.reserved_bytes(), bytes);
            drop(active);
        }
    });
    drop(control);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn inactive_control_crosses_threads_with_the_same_original_backing_and_charge() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<AllocationScopeControl>();
    let bytes = OwnedAllocationScope::allocation_layout().size();
    let budget = AllocationBudget::new(bytes);
    let scope = budget.try_owned_refund_scope().unwrap();
    let control = scope.control();
    let address = ptr::from_ref(&control.control.record) as usize;
    drop(scope);
    budget.set_limit_bytes(0);
    let control = std::thread::spawn(move || {
        without_allocations(|| {
            let active = control.try_activate().unwrap();
            assert_eq!(
                ptr::from_ref(&active.control.control.record) as usize,
                address
            );
            assert_eq!(active.allocation_budget().reserved_bytes(), bytes);
            drop(active);
        });
        control
    })
    .join()
    .unwrap();
    assert_eq!(budget.reserved_bytes(), bytes);
    without_allocations(|| drop(control.try_activate().unwrap()));
    drop(control);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn concurrent_activation_has_exactly_one_winner_until_its_cleanup_retires() {
    let bytes = OwnedAllocationScope::allocation_layout().size();
    let budget = AllocationBudget::new(bytes);
    let scope = budget.try_owned_refund_scope().unwrap();
    let control = scope.control();
    drop(scope);
    budget.set_limit_bytes(0);
    let barrier = Barrier::new(8);
    let winners = AtomicUsize::new(0);
    for _ in 0..16 {
        winners.store(0, SeqCst);
        std::thread::scope(|threads| {
            for _ in 0..8 {
                threads.spawn(|| {
                    barrier.wait();
                    let active = without_allocations(|| control.try_activate());
                    if active.is_ok() {
                        winners.fetch_add(1, SeqCst);
                    }
                    barrier.wait();
                    without_allocations(|| drop(active));
                });
            }
        });
        assert_eq!(winners.load(SeqCst), 1);
        assert_eq!(budget.reserved_bytes(), bytes);
    }
    drop(control);
    assert_eq!(budget.reserved_bytes(), 0);
}

struct ReentryProbe {
    control: AllocationScopeControl,
    calls: AtomicUsize,
    blocked: AtomicUsize,
    first_writer: Arc<Mutex<()>>,
    last_writer: Arc<Mutex<()>>,
    released: AtomicUsize,
    panic: bool,
}

impl Wake for ReentryProbe {
    fn wake(self: Arc<Self>) {
        self.calls.fetch_add(1, SeqCst);
        if self.control.try_activate().is_err() {
            self.blocked.fetch_add(1, SeqCst);
        }
        if self.first_writer.try_lock().is_ok() && self.last_writer.try_lock().is_ok() {
            self.released.fetch_add(1, SeqCst);
        }
        assert!(!self.panic, "original reusable-control callback failed");
    }
}

fn probe(control: &AllocationScopeControl, panic: bool) -> Arc<ReentryProbe> {
    Arc::new(ReentryProbe {
        control: control.clone(),
        calls: AtomicUsize::new(0),
        blocked: AtomicUsize::new(0),
        first_writer: Arc::new(Mutex::new(())),
        last_writer: Arc::new(Mutex::new(())),
        released: AtomicUsize::new(0),
        panic,
    })
}

#[test]
fn final_callback_reentry_is_blocked_after_every_sibling_writer_has_released() {
    let bytes = OwnedAllocationScope::allocation_layout().size();
    let budget = AllocationBudget::new(bytes + 1);
    let registrations = AllocationBudget::new(ReleaseRegistration::allocation_layout().size());
    let mut registration = registration(&registrations);
    let scope = budget.try_owned_refund_scope().unwrap();
    let control = scope.control();
    let cleanup = scope.clone();
    let held = budget.try_reserve_bytes(1).unwrap();
    let mut wait = capacity_wait(budget.try_reserve_bytes(1).unwrap_err(), &mut registration);
    let callback = probe(&control, false);
    assert!(
        Pin::new(&mut wait)
            .poll(&mut Context::from_waker(&Waker::from(callback.clone())))
            .is_pending()
    );
    let first = callback.first_writer.lock().unwrap();
    let last = callback.last_writer.lock().unwrap();
    without_allocations(|| {
        drop(held);
        drop(first);
        drop(scope);
        assert_eq!(callback.calls.load(SeqCst), 0);
        assert!(control.try_activate().is_err());
        drop(last);
        drop(cleanup);
    });
    assert_eq!(callback.calls.load(SeqCst), 1);
    assert_eq!(callback.blocked.load(SeqCst), 1);
    assert_eq!(callback.released.load(SeqCst), 1);
    without_allocations(|| drop(control.try_activate().unwrap()));
    assert_eq!(callback.calls.load(SeqCst), 1);
}

#[test]
fn callback_unwind_keeps_reentry_blocked_through_the_remaining_cohort() {
    let bytes = OwnedAllocationScope::allocation_layout().size();
    let budget = AllocationBudget::new(bytes + 1);
    let registrations = AllocationBudget::new(2 * ReleaseRegistration::allocation_layout().size());
    let mut first_registration = registration(&registrations);
    let mut last_registration = registration(&registrations);
    let scope = budget.try_owned_refund_scope().unwrap();
    let control = scope.control();
    let held = budget.try_reserve_bytes(1).unwrap();
    let refusal = budget.try_reserve_bytes(1).unwrap_err();
    let mut first_wait = capacity_wait(refusal.clone(), &mut first_registration);
    let mut last_wait = capacity_wait(refusal, &mut last_registration);
    let first = probe(&control, true);
    let last = probe(&control, false);
    for (wait, callback) in [(&mut first_wait, &first), (&mut last_wait, &last)] {
        assert!(
            Pin::new(wait)
                .poll(&mut Context::from_waker(&Waker::from(callback.clone())))
                .is_pending()
        );
    }
    drop(held);
    let panic = catch_unwind(AssertUnwindSafe(|| drop(scope)))
        .expect_err("the first callback must retain its original panic");
    assert_eq!(
        panic.downcast_ref::<&str>().copied(),
        Some("original reusable-control callback failed")
    );
    for callback in [&first, &last] {
        assert_eq!(callback.calls.load(SeqCst), 1);
        assert_eq!(callback.blocked.load(SeqCst), 1);
        assert_eq!(callback.released.load(SeqCst), 1);
    }
    without_allocations(|| {
        let active = control.try_activate().unwrap();
        budget.with_deferred_refund_notifications(|_| {});
        drop(active);
    });
}

#[test]
fn next_activation_clears_pending_without_an_unearned_release_notification() {
    let bytes = OwnedAllocationScope::allocation_layout().size();
    let budget = AllocationBudget::new(bytes + 1);
    let registrations = AllocationBudget::new(2 * ReleaseRegistration::allocation_layout().size());
    let mut first_registration = registration(&registrations);
    let mut next_registration = registration(&registrations);
    let scope = budget.try_owned_refund_scope().unwrap();
    let control = scope.control();
    let held = budget.try_reserve_bytes(1).unwrap();
    let mut first_wait = capacity_wait(
        budget.try_reserve_bytes(1).unwrap_err(),
        &mut first_registration,
    );
    let wakes = Arc::new(WakeCount::default());
    assert!(poll(&mut first_wait, &wakes).is_pending());
    drop(held);
    drop(scope);
    assert_eq!(wakes.0.load(SeqCst), 1);
    let next_held = budget.try_reserve_bytes(1).unwrap();
    let next = without_allocations(|| control.try_activate().unwrap());
    let mut next_wait = capacity_wait(
        budget.try_reserve_bytes(1).unwrap_err(),
        &mut next_registration,
    );
    assert!(poll(&mut next_wait, &wakes).is_pending());
    without_allocations(|| drop(next));
    assert_eq!(
        wakes.0.load(SeqCst),
        1,
        "no refund occurred in the new activation"
    );
    assert!(poll(&mut next_wait, &wakes).is_pending());
    drop(next_held);
    assert_eq!(wakes.0.load(SeqCst), 2);
    assert!(poll(&mut next_wait, &wakes).is_ready());
}
