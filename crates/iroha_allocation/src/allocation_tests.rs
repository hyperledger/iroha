//! Finite capacity, prepaid splitting and scoped reclamation notifications.

use super::*;
use crate::release::ReleaseRegistration;

fn registration(budget: &AllocationBudget) -> ReleaseRegistration {
    ReleaseRegistration::from_reservation(
        &mut budget
            .try_reserve(ReleaseRegistration::allocation_layout())
            .unwrap(),
    )
    .unwrap()
}
use std::{
    future::Future,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    sync::{Barrier, Mutex, TryLockError, atomic::Ordering::SeqCst},
    task::{Context, Poll, Wake, Waker},
};

use crate::test_support::without_allocations;

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, SeqCst);
    }
}

fn poll(wait: &mut crate::release::ReleaseFuture<'_>, wakes: &Arc<WakeCount>) -> Poll<()> {
    Pin::new(wait).poll(&mut Context::from_waker(&Waker::from(Arc::clone(wakes))))
}

fn capacity_wait(
    error: AllocationRefusal,
    registration: &mut ReleaseRegistration,
) -> crate::release::ReleaseFuture<'_> {
    let AllocationRefusal::Capacity { release, .. } = error else {
        panic!("expected temporary capacity refusal: {error}");
    };
    release.wait_for_release(registration)
}

fn layout(size: usize) -> Layout {
    Layout::from_size_align(size, 1).unwrap()
}

#[test]
fn finite_limit_overflow_and_zero_never_change_credit_on_refusal() {
    let budget = AllocationBudget::new(10);
    assert_eq!(budget.limit_bytes(), 10);
    assert!(matches!(
        budget.try_reserve(layout(11)),
        Err(AllocationRefusal::ExceedsLimit {
            requested_bytes: 11,
            limit_bytes: 10
        })
    ));
    let largest = layout(isize::MAX as usize);
    assert_eq!(
        budget.try_reserve_layouts([largest; 3]).unwrap_err(),
        AllocationRefusal::DemandOverflow
    );
    assert_eq!(budget.reserved_bytes(), 0);
    let full = budget.try_reserve(layout(10)).unwrap();
    assert!(matches!(
        budget.try_reserve(layout(1)),
        Err(AllocationRefusal::Capacity {
            requested_bytes: 1,
            reserved_bytes: 10,
            limit_bytes: 10,
            ..
        })
    ));
    assert_eq!(budget.reserved_bytes(), 10);
    drop(full);
    assert_eq!(budget.reserved_bytes(), 0);

    let zero = AllocationBudget::new(0);
    let mut empty = zero.try_reserve(layout(0)).unwrap();
    let charge = empty.try_split(layout(0)).unwrap();
    assert_eq!(charge.layout().size(), 0);
    assert!(matches!(
        zero.try_reserve(layout(1)),
        Err(AllocationRefusal::ExceedsLimit { .. })
    ));
    drop(empty);
    drop(charge);
    assert_eq!(zero.reserved_bytes(), 0);
}

#[test]
fn reconfigured_limit_keeps_original_borrower_charges_through_shrink() {
    let budget = AllocationBudget::new(10);
    let borrower = budget.clone();
    let held = borrower.try_reserve_bytes(8).unwrap();
    budget.set_limit_bytes(4);
    assert_eq!(borrower.limit_bytes(), 4);
    assert!(held.belongs_to(&budget));
    assert_eq!(budget.reserved_bytes(), 8);
    assert!(matches!(
        borrower.try_reserve_bytes(1),
        Err(AllocationRefusal::Capacity {
            requested_bytes: 1,
            reserved_bytes: 8,
            limit_bytes: 4,
            ..
        })
    ));
    assert!(matches!(
        borrower.try_reserve_bytes(5),
        Err(AllocationRefusal::ExceedsLimit {
            requested_bytes: 5,
            limit_bytes: 4,
        })
    ));
    drop(held);
    let within_new_limit = borrower.try_reserve_bytes(4).unwrap();
    assert!(within_new_limit.belongs_to(&budget));
}

#[test]
fn peak_tracks_original_admissions_across_borrowers_and_limit_reload() {
    let budget = AllocationBudget::new(16);
    let borrower = budget.clone();
    assert_eq!(budget.peak_reserved_bytes(), 0);
    let first = budget.try_reserve_bytes(8).unwrap();
    let second = borrower.try_reserve_bytes(4).unwrap();
    assert_eq!(budget.peak_reserved_bytes(), 12);
    drop(first);
    assert_eq!(budget.reserved_bytes(), 4);
    budget.set_limit_bytes(4);
    assert_eq!(borrower.peak_reserved_bytes(), 12);
    assert!(matches!(
        budget.try_reserve_bytes(1),
        Err(AllocationRefusal::Capacity { .. })
    ));
    assert_eq!(budget.peak_reserved_bytes(), 12);
    drop(second);
    let third = borrower.try_reserve_bytes(4).unwrap();
    assert_eq!(budget.peak_reserved_bytes(), 12);
    drop(third);
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(budget.peak_reserved_bytes(), 12);
}

#[test]
fn growing_original_limit_wakes_waiters_after_reload_scope() {
    let budget = AllocationBudget::new(8 + ReleaseRegistration::allocation_layout().size());
    let mut budget_registration_0 = registration(&budget);
    let held = budget.try_reserve_bytes(8).unwrap();
    let mut wait = capacity_wait(
        budget.try_reserve_bytes(1).unwrap_err(),
        &mut budget_registration_0,
    );
    let wakes = Arc::new(WakeCount::default());
    assert!(poll(&mut wait, &wakes).is_pending());
    budget.with_deferred_refund_notifications(|_| {
        budget.set_limit_bytes(9 + ReleaseRegistration::allocation_layout().size());
        assert_eq!(
            budget.limit_bytes(),
            9 + ReleaseRegistration::allocation_layout().size()
        );
        assert_eq!(wakes.0.load(SeqCst), 0);
    });
    assert_eq!(wakes.0.load(SeqCst), 1);
    assert!(poll(&mut wait, &wakes).is_ready());
    let extra = budget.try_reserve_bytes(1).unwrap();
    assert!(extra.belongs_to(&budget));
    drop(held);
    drop(extra);
    assert_eq!(
        budget.reserved_bytes(),
        ReleaseRegistration::allocation_layout().size()
    );
}

#[test]
fn splitting_prepaid_credits_refunds_only_unused_remainder_and_owned_charges() {
    let budget = AllocationBudget::new(24);
    let mut prepaid = budget.try_reserve_layouts([layout(8); 3]).unwrap();
    let first = prepaid.try_split(layout(8)).unwrap();
    let second = prepaid.try_split(layout(8)).unwrap();
    assert_eq!(prepaid.remaining_bytes(), 8);
    assert_eq!(
        prepaid.try_split(layout(9)).unwrap_err(),
        InsufficientReservation {
            requested_bytes: 9,
            remaining_bytes: 8
        }
    );
    assert_eq!(prepaid.remaining_bytes(), 8);
    assert_eq!(budget.reserved_bytes(), 24);
    drop(prepaid);
    assert_eq!(budget.reserved_bytes(), 16);
    let reused = budget.try_reserve(layout(8)).unwrap();
    assert_eq!(budget.reserved_bytes(), 24);
    drop(second);
    assert_eq!(budget.reserved_bytes(), 16);
    drop(first);
    drop(reused);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn component_partitions_use_original_full_pool_without_allocation_or_new_admission() {
    let budget = AllocationBudget::new(32);
    let mut original = budget.try_reserve_bytes(32).unwrap();
    let (mut current, mut undo) = without_allocations(|| {
        let current = original.try_partition_bytes(12).unwrap();
        let undo = original.try_partition_bytes(20).unwrap();
        assert!(Arc::ptr_eq(&current.pool, &original.pool));
        assert!(Arc::ptr_eq(&undo.pool, &original.pool));
        assert_eq!(original.remaining_bytes(), 0);
        assert_eq!(budget.reserved_bytes(), 32);
        (current, undo)
    });
    assert!(matches!(
        budget.try_reserve_bytes(1),
        Err(AllocationRefusal::Capacity { .. })
    ));
    let (current_node, undo_node, undo_payload) = without_allocations(|| {
        let mut payload = undo.try_partition_bytes(8).unwrap();
        let charges = (
            current.try_split(layout(12)).unwrap(),
            undo.try_split(layout(12)).unwrap(),
            payload.try_split(layout(8)).unwrap(),
        );
        drop(payload);
        drop(original);
        drop(current);
        drop(undo);
        assert_eq!(budget.reserved_bytes(), 32);
        charges
    });
    without_allocations(|| {
        drop(undo_node);
        assert_eq!(budget.reserved_bytes(), 20);
        drop(current_node);
        assert_eq!(budget.reserved_bytes(), 8);
        drop(undo_payload);
        assert_eq!(budget.reserved_bytes(), 0);
    });
}

#[test]
fn refused_or_empty_partition_preserves_original_credits_and_release_observation() {
    let budget = AllocationBudget::new(8 + ReleaseRegistration::allocation_layout().size());
    let mut budget_registration_0 = registration(&budget);
    let other = AllocationBudget::new(8);
    let mut original = budget.try_reserve_bytes(8).unwrap();
    let mut wait = capacity_wait(
        budget.try_reserve_bytes(1).unwrap_err(),
        &mut budget_registration_0,
    );
    let wakes = Arc::new(WakeCount::default());
    assert!(poll(&mut wait, &wakes).is_pending());
    without_allocations(|| {
        assert_eq!(
            original.try_partition_bytes(usize::MAX).unwrap_err(),
            InsufficientReservation {
                requested_bytes: usize::MAX,
                remaining_bytes: 8,
            }
        );
        drop(original.try_partition_bytes(0).unwrap());
        assert_eq!(original.remaining_bytes(), 8);
        assert_eq!(
            budget.reserved_bytes(),
            8 + ReleaseRegistration::allocation_layout().size()
        );
        assert_eq!(wakes.0.load(SeqCst), 0);
    });
    let child = without_allocations(|| original.try_partition_bytes(8).unwrap());
    drop(original);
    drop(other.try_reserve_bytes(8).unwrap());
    assert_eq!(wakes.0.load(SeqCst), 0);
    assert!(poll(&mut wait, &wakes).is_pending());
    without_allocations(|| drop(child));
    assert_eq!(wakes.0.load(SeqCst), 1);
    assert!(poll(&mut wait, &wakes).is_ready());
    assert_eq!(
        budget.reserved_bytes(),
        ReleaseRegistration::allocation_layout().size()
    );
}

#[test]
fn aggregate_partitions_exceed_single_layout_limits_without_overflow() {
    let budget = AllocationBudget::new(usize::MAX);
    let mut original = budget.try_reserve_bytes(usize::MAX).unwrap();
    let mut component =
        without_allocations(|| original.try_partition_bytes(usize::MAX - 1).unwrap());
    assert_eq!(original.remaining_bytes(), 1);
    assert_eq!(component.remaining_bytes(), usize::MAX - 1);
    let first = component.try_split(layout(isize::MAX as usize)).unwrap();
    let second = component.try_split(layout(isize::MAX as usize)).unwrap();
    assert_eq!(component.remaining_bytes(), 0);
    drop(component);
    drop(original);
    assert_eq!(budget.reserved_bytes(), usize::MAX - 1);
    drop(second);
    assert_eq!(budget.reserved_bytes(), isize::MAX as usize);
    drop(first);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn exact_pool_release_wakes_waiters_including_before_their_first_poll() {
    let budget = AllocationBudget::new(8 + 2 * ReleaseRegistration::allocation_layout().size());
    let mut budget_registration_0 = registration(&budget);
    let mut budget_registration_1 = registration(&budget);
    let other = AllocationBudget::new(8);
    let owner = budget.try_reserve(layout(8)).unwrap();
    let mut registered = capacity_wait(
        budget.try_reserve(layout(1)).unwrap_err(),
        &mut budget_registration_0,
    );
    let mut unregistered = capacity_wait(
        budget.try_reserve(layout(1)).unwrap_err(),
        &mut budget_registration_1,
    );
    let wakes = Arc::new(WakeCount::default());
    assert!(poll(&mut registered, &wakes).is_pending());
    drop(other.try_reserve(layout(8)).unwrap());
    assert_eq!(wakes.0.load(SeqCst), 0);
    assert!(poll(&mut registered, &wakes).is_pending());
    drop(owner);
    assert_eq!(
        budget.reserved_bytes(),
        2 * ReleaseRegistration::allocation_layout().size()
    );
    assert_eq!(wakes.0.load(SeqCst), 1);
    assert!(poll(&mut registered, &wakes).is_ready());
    assert!(poll(&mut unregistered, &wakes).is_ready());
    drop(budget.try_reserve(layout(8)).unwrap());
}

#[test]
fn concurrent_reservations_cannot_oversubscribe_the_same_finite_pool() {
    for _ in 0..16 {
        let budget = AllocationBudget::new(32);
        let barrier = Barrier::new(8);
        let successes = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let budget = &budget;
                let barrier = &barrier;
                let successes = &successes;
                scope.spawn(move || {
                    barrier.wait();
                    let result = budget.try_reserve(layout(32));
                    if result.is_ok() {
                        successes.fetch_add(1, SeqCst);
                    } else {
                        assert!(matches!(result, Err(AllocationRefusal::Capacity { .. })));
                    }
                    barrier.wait();
                    drop(result);
                });
            }
        });
        assert_eq!(successes.load(SeqCst), 1);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn charge_keeps_original_pool_alive_after_budget_handle_is_dropped() {
    let budget = AllocationBudget::new(8);
    let observer = Arc::downgrade(&budget.pool);
    let mut prepaid = budget.try_reserve(layout(8)).unwrap();
    let charge = prepaid.try_split(layout(8)).unwrap();
    drop(prepaid);
    drop(budget);
    assert_eq!(observer.upgrade().unwrap().reserved.load(SeqCst), 8);
    std::thread::spawn(move || drop(charge)).join().unwrap();
    assert!(observer.upgrade().is_none());
}

#[test]
fn nested_original_pool_scopes_return_credits_immediately_and_coalesce_without_allocation() {
    let budget = AllocationBudget::new(8 + ReleaseRegistration::allocation_layout().size());
    let mut budget_registration_0 = registration(&budget);
    let same_pool = budget.clone();
    let owner = budget.try_reserve(layout(8)).unwrap();
    let mut wait = capacity_wait(
        budget.try_reserve(layout(1)).unwrap_err(),
        &mut budget_registration_0,
    );
    let wakes = Arc::new(WakeCount::default());
    assert!(poll(&mut wait, &wakes).is_pending());

    without_allocations(|| {
        budget.with_deferred_refund_notifications(|_| {});
        assert_eq!(wakes.0.load(SeqCst), 0);
        budget.with_deferred_refund_notifications(|_| {
            same_pool.with_deferred_refund_notifications(|_| {
                drop(owner);
                assert_eq!(
                    budget.reserved_bytes(),
                    ReleaseRegistration::allocation_layout().size()
                );
                assert_eq!(wakes.0.load(SeqCst), 0);
            });
            // Refunded capacity is reusable before any deferred notification.
            let reused = budget.try_reserve(layout(8)).unwrap();
            assert_eq!(
                budget.reserved_bytes(),
                8 + ReleaseRegistration::allocation_layout().size()
            );
            drop(reused);
            assert_eq!(
                budget.reserved_bytes(),
                ReleaseRegistration::allocation_layout().size()
            );
            assert_eq!(wakes.0.load(SeqCst), 0);
        });
    });
    assert_eq!(wakes.0.load(SeqCst), 1);
    assert!(poll(&mut wait, &wakes).is_ready());
}

#[test]
fn nested_different_pool_scopes_flush_independently() {
    let first = AllocationBudget::new(8 + ReleaseRegistration::allocation_layout().size());
    let mut first_registration_0 = registration(&first);
    let second = AllocationBudget::new(8 + ReleaseRegistration::allocation_layout().size());
    let mut second_registration_0 = registration(&second);
    let first_owner = first.try_reserve(layout(8)).unwrap();
    let second_owner = second.try_reserve(layout(8)).unwrap();
    let mut first_wait = capacity_wait(
        first.try_reserve(layout(1)).unwrap_err(),
        &mut first_registration_0,
    );
    let mut second_wait = capacity_wait(
        second.try_reserve(layout(1)).unwrap_err(),
        &mut second_registration_0,
    );
    let first_wakes = Arc::new(WakeCount::default());
    let second_wakes = Arc::new(WakeCount::default());
    assert!(poll(&mut first_wait, &first_wakes).is_pending());
    assert!(poll(&mut second_wait, &second_wakes).is_pending());

    first.with_deferred_refund_notifications(|_| {
        second.with_deferred_refund_notifications(|_| {
            // Finding the exact pool crosses an unrelated inner scope.
            drop(first_owner);
            drop(second_owner);
            assert_eq!(
                first.reserved_bytes(),
                ReleaseRegistration::allocation_layout().size()
            );
            assert_eq!(
                second.reserved_bytes(),
                ReleaseRegistration::allocation_layout().size()
            );
            assert_eq!(first_wakes.0.load(SeqCst), 0);
            assert_eq!(second_wakes.0.load(SeqCst), 0);
        });
        assert_eq!(first_wakes.0.load(SeqCst), 0);
        assert_eq!(second_wakes.0.load(SeqCst), 1);
        assert!(poll(&mut second_wait, &second_wakes).is_ready());
    });
    assert_eq!(first_wakes.0.load(SeqCst), 1);
    assert!(poll(&mut first_wait, &first_wakes).is_ready());
}

#[test]
fn another_threads_refund_notifies_while_this_threads_scope_is_still_active() {
    let budget = AllocationBudget::new(8 + ReleaseRegistration::allocation_layout().size());
    let mut budget_registration_0 = registration(&budget);
    let local = budget.try_reserve(layout(4)).unwrap();
    let remote = budget.try_reserve(layout(4)).unwrap();
    let mut wait = capacity_wait(
        budget.try_reserve(layout(1)).unwrap_err(),
        &mut budget_registration_0,
    );
    let wakes = Arc::new(WakeCount::default());
    assert!(poll(&mut wait, &wakes).is_pending());
    budget.with_deferred_refund_notifications(|_| {
        drop(local);
        assert_eq!(
            budget.reserved_bytes(),
            4 + ReleaseRegistration::allocation_layout().size()
        );
        assert_eq!(wakes.0.load(SeqCst), 0);
        std::thread::spawn(move || drop(remote)).join().unwrap();
        assert_eq!(
            budget.reserved_bytes(),
            ReleaseRegistration::allocation_layout().size()
        );
        assert_eq!(wakes.0.load(SeqCst), 1);
        assert!(poll(&mut wait, &wakes).is_ready());
    });
    assert_eq!(wakes.0.load(SeqCst), 1);
}

#[test]
fn scope_unwind_notifies_after_its_physical_writer_has_unlocked() {
    struct Probe {
        physical: Arc<Mutex<()>>,
        released: AtomicUsize,
    }
    impl Wake for Probe {
        fn wake(self: Arc<Self>) {
            // Report after catch_unwind rather than panicking during an active
            // unwind if notification regresses to running under the lock.
            let observed = match self.physical.try_lock() {
                Err(TryLockError::WouldBlock) => 1,
                Err(TryLockError::Poisoned(_)) => 2,
                Ok(_) => 3,
            };
            self.released.fetch_add(observed, SeqCst);
        }
    }
    let budget = AllocationBudget::new(8 + 2 * ReleaseRegistration::allocation_layout().size());
    let mut budget_registration_0 = registration(&budget);
    let mut budget_registration_1 = registration(&budget);
    let owner = budget.try_reserve(layout(8)).unwrap();
    let mut wait = capacity_wait(
        budget.try_reserve(layout(1)).unwrap_err(),
        &mut budget_registration_0,
    );
    let physical = Arc::new(Mutex::new(()));
    let wake = Arc::new(Probe {
        physical: Arc::clone(&physical),
        released: AtomicUsize::new(0),
    });
    let waker = Waker::from(Arc::clone(&wake));
    assert!(
        Pin::new(&mut wait)
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            budget.with_deferred_refund_notifications(|_| {
                let _held = physical.lock().unwrap();
                drop(owner);
                assert_eq!(
                    budget.reserved_bytes(),
                    2 * ReleaseRegistration::allocation_layout().size()
                );
                assert_eq!(wake.released.load(SeqCst), 0);
                panic!("original operation failed while its writer was held");
            });
        }))
        .is_err()
    );
    assert_eq!(wake.released.load(SeqCst), 2);
    assert!(
        Pin::new(&mut wait)
            .poll(&mut Context::from_waker(&waker))
            .is_ready()
    );

    let owner = budget.try_reserve(layout(8)).unwrap();
    let mut next = capacity_wait(
        budget.try_reserve(layout(1)).unwrap_err(),
        &mut budget_registration_1,
    );
    let next_wakes = Arc::new(WakeCount::default());
    assert!(poll(&mut next, &next_wakes).is_pending());
    drop(owner);
    assert_eq!(next_wakes.0.load(SeqCst), 1);
    assert!(poll(&mut next, &next_wakes).is_ready());
}

#[test]
fn caught_inner_unwind_remains_deferred_until_the_original_outer_scope_exits() {
    let budget = AllocationBudget::new(8 + ReleaseRegistration::allocation_layout().size());
    let mut budget_registration_0 = registration(&budget);
    let owner = budget.try_reserve(layout(8)).unwrap();
    let mut wait = capacity_wait(
        budget.try_reserve(layout(1)).unwrap_err(),
        &mut budget_registration_0,
    );
    let wakes = Arc::new(WakeCount::default());
    assert!(poll(&mut wait, &wakes).is_pending());
    budget.with_deferred_refund_notifications(|_| {
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                budget.with_deferred_refund_notifications(|_| {
                    drop(owner);
                    panic!("inner operation abandoned");
                });
            }))
            .is_err()
        );
        assert_eq!(
            budget.reserved_bytes(),
            ReleaseRegistration::allocation_layout().size()
        );
        assert_eq!(wakes.0.load(SeqCst), 0);
    });
    assert_eq!(wakes.0.load(SeqCst), 1);
    assert!(poll(&mut wait, &wakes).is_ready());
}

#[test]
fn refund_callback_can_reenter_scopes_and_its_panic_leaves_no_stale_tls_owner() {
    struct Reenter {
        budget: AllocationBudget,
        calls: AtomicUsize,
    }
    impl Wake for Reenter {
        fn wake(self: Arc<Self>) {
            self.budget.with_deferred_refund_notifications(|_| {
                let owner = self.budget.try_reserve(layout(8)).unwrap();
                drop(owner);
            });
            self.calls.fetch_add(1, SeqCst);
            panic!("reentrant wake failed after its nested scope completed");
        }
    }
    let budget = AllocationBudget::new(8 + 2 * ReleaseRegistration::allocation_layout().size());
    let mut budget_registration_0 = registration(&budget);
    let mut budget_registration_1 = registration(&budget);
    let owner = budget.try_reserve(layout(8)).unwrap();
    let mut wait = capacity_wait(
        budget.try_reserve(layout(1)).unwrap_err(),
        &mut budget_registration_0,
    );
    let wake = Arc::new(Reenter {
        budget: budget.clone(),
        calls: AtomicUsize::new(0),
    });
    let waker = Waker::from(Arc::clone(&wake));
    assert!(
        Pin::new(&mut wait)
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            budget.with_deferred_refund_notifications(|_| drop(owner));
        }))
        .is_err()
    );
    assert_eq!(wake.calls.load(SeqCst), 1);
    assert_eq!(
        budget.reserved_bytes(),
        2 * ReleaseRegistration::allocation_layout().size()
    );
    assert!(
        Pin::new(&mut wait)
            .poll(&mut Context::from_waker(&waker))
            .is_ready()
    );

    let owner = budget.try_reserve(layout(8)).unwrap();
    let mut next = capacity_wait(
        budget.try_reserve(layout(1)).unwrap_err(),
        &mut budget_registration_1,
    );
    let next_wakes = Arc::new(WakeCount::default());
    assert!(poll(&mut next, &next_wakes).is_pending());
    drop(owner);
    assert_eq!(next_wakes.0.load(SeqCst), 1);
    assert!(poll(&mut next, &next_wakes).is_ready());
}

#[test]
fn deferred_flush_preserves_first_panic_and_wakes_the_remaining_cohort_after_unlock() {
    struct FirstWake(AtomicUsize);
    impl Wake for FirstWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, SeqCst);
            panic!("deferred refund callback panicked");
        }
    }
    struct Survivor {
        physical: Arc<Mutex<()>>,
        wakes: AtomicUsize,
        unlocked: AtomicUsize,
    }
    impl Wake for Survivor {
        fn wake(self: Arc<Self>) {
            // The first callback is already unwinding. Observe without causing
            // a second panic if lock ordering regresses.
            self.unlocked
                .store(usize::from(self.physical.try_lock().is_ok()), SeqCst);
            self.wakes.fetch_add(1, SeqCst);
        }
    }
    let budget = AllocationBudget::new(8 + 2 * ReleaseRegistration::allocation_layout().size());
    let mut budget_registration_0 = registration(&budget);
    let mut budget_registration_1 = registration(&budget);
    let owner = budget.try_reserve(layout(8)).unwrap();
    let mut first = capacity_wait(
        budget.try_reserve(layout(1)).unwrap_err(),
        &mut budget_registration_0,
    );
    let mut second = capacity_wait(
        budget.try_reserve(layout(1)).unwrap_err(),
        &mut budget_registration_1,
    );
    let physical = Arc::new(Mutex::new(()));
    let first_wake = Arc::new(FirstWake(AtomicUsize::new(0)));
    let first_waker = Waker::from(Arc::clone(&first_wake));
    let survivor = Arc::new(Survivor {
        physical: Arc::clone(&physical),
        wakes: AtomicUsize::new(0),
        unlocked: AtomicUsize::new(0),
    });
    let second_waker = Waker::from(Arc::clone(&survivor));
    assert!(
        Pin::new(&mut first)
            .poll(&mut Context::from_waker(&first_waker))
            .is_pending()
    );
    assert!(
        Pin::new(&mut second)
            .poll(&mut Context::from_waker(&second_waker))
            .is_pending()
    );
    let panic = catch_unwind(AssertUnwindSafe(|| {
        budget.with_deferred_refund_notifications(|_| {
            let _held = physical.lock().unwrap();
            drop(owner);
            assert_eq!(
                budget.reserved_bytes(),
                2 * ReleaseRegistration::allocation_layout().size()
            );
            assert_eq!(first_wake.0.load(SeqCst), 0);
            assert_eq!(survivor.wakes.load(SeqCst), 0);
        });
    }))
    .expect_err("deferred callback panic must propagate");
    assert_eq!(
        panic.downcast_ref::<&str>().copied(),
        Some("deferred refund callback panicked")
    );
    assert_eq!(first_wake.0.load(SeqCst), 1);
    assert_eq!(survivor.wakes.load(SeqCst), 1);
    assert_eq!(survivor.unlocked.load(SeqCst), 1);
    assert!(physical.try_lock().is_ok());
    assert!(
        Pin::new(&mut first)
            .poll(&mut Context::from_waker(&first_waker))
            .is_ready()
    );
    assert!(
        Pin::new(&mut second)
            .poll(&mut Context::from_waker(&second_waker))
            .is_ready()
    );
    assert_eq!(
        budget.reserved_bytes(),
        2 * ReleaseRegistration::allocation_layout().size()
    );
}

#[test]
fn checked_aggregate_bytes_need_no_fabricated_single_allocation_layout() {
    let bytes = (isize::MAX as usize) + 1;
    assert!(Layout::from_size_align(bytes, 1).is_err());
    let budget = AllocationBudget::new(bytes);
    let mut reservation = without_allocations(|| budget.try_reserve_bytes(bytes).unwrap());
    let first = reservation.try_split(layout(isize::MAX as usize)).unwrap();
    let second = reservation.try_split(layout(1)).unwrap();
    assert_eq!(reservation.remaining_bytes(), 0);
    assert_eq!(budget.reserved_bytes(), bytes);
    assert!(matches!(
        budget.try_reserve_bytes(1),
        Err(AllocationRefusal::Capacity { .. })
    ));
    drop(reservation);
    drop(first);
    assert_eq!(budget.reserved_bytes(), 1);
    drop(second);
    assert_eq!(budget.reserved_bytes(), 0);
    assert!(matches!(
        budget.try_reserve_bytes(bytes + 1),
        Err(AllocationRefusal::ExceedsLimit { .. })
    ));
}

#[test]
fn partition_retains_exact_original_pool_and_conserves_real_credits() {
    let budget = AllocationBudget::new(64 + ReleaseRegistration::allocation_layout().size());
    let mut budget_registration_0 = registration(&budget);
    let equal_but_foreign =
        AllocationBudget::new(64 + ReleaseRegistration::allocation_layout().size());
    let mut whole = budget.try_reserve_bytes(64).unwrap();
    assert!(whole.belongs_to(&budget.clone()));
    assert!(!whole.belongs_to(&equal_but_foreign));
    let mut part = without_allocations(|| whole.try_partition_bytes(24).unwrap());
    assert!(part.belongs_to(&budget));
    assert_eq!(whole.remaining_bytes(), 40);
    assert_eq!(part.remaining_bytes(), 24);
    assert_eq!(
        budget.reserved_bytes(),
        64 + ReleaseRegistration::allocation_layout().size()
    );
    let error = without_allocations(|| whole.try_partition_bytes(41).unwrap_err());
    assert_eq!(
        error,
        InsufficientReservation {
            requested_bytes: 41,
            remaining_bytes: 40
        }
    );
    let mut wait = capacity_wait(
        budget.try_reserve_bytes(1).unwrap_err(),
        &mut budget_registration_0,
    );
    let wakes = Arc::new(WakeCount::default());
    assert!(poll(&mut wait, &wakes).is_pending());
    let zero = without_allocations(|| whole.try_partition_bytes(0).unwrap());
    assert!(zero.belongs_to(&budget));
    without_allocations(|| drop(zero));
    assert_eq!(wakes.0.load(SeqCst), 0);
    let charge = without_allocations(|| {
        part.try_split(Layout::from_size_align(16, 8).unwrap())
            .unwrap()
    });
    assert!(charge.belongs_to(&budget));
    assert!(!charge.belongs_to(&equal_but_foreign));
    budget.with_deferred_refund_notifications(|_| {
        without_allocations(|| drop(part));
        assert_eq!(
            budget.reserved_bytes(),
            56 + ReleaseRegistration::allocation_layout().size()
        );
        assert_eq!(wakes.0.load(SeqCst), 0);
        without_allocations(|| drop(whole));
        assert_eq!(
            budget.reserved_bytes(),
            16 + ReleaseRegistration::allocation_layout().size()
        );
    });
    assert_eq!(wakes.0.load(SeqCst), 1);
    assert!(poll(&mut wait, &wakes).is_ready());
    assert_eq!(equal_but_foreign.reserved_bytes(), 0);
    without_allocations(|| drop(charge));
    assert_eq!(
        budget.reserved_bytes(),
        ReleaseRegistration::allocation_layout().size()
    );
}

#[test]
fn partition_prepaid_reservation_preserves_same_pool_without_allocation_or_acquisition() {
    let budget = AllocationBudget::new(64);
    let mut parent = budget.try_reserve_bytes(64).unwrap();
    let mut child = without_allocations(|| parent.try_partition_bytes(24).unwrap());
    assert_eq!(parent.remaining_bytes(), 40);
    assert_eq!(child.remaining_bytes(), 24);
    assert_eq!(budget.reserved_bytes(), 64);
    assert!(matches!(
        budget.try_reserve_bytes(1),
        Err(AllocationRefusal::Capacity { .. })
    ));
    let charge = without_allocations(|| child.try_split(layout(24)).unwrap());
    assert_eq!(charge.layout(), layout(24));
    assert_eq!(child.remaining_bytes(), 0);
    without_allocations(|| drop(child));
    assert_eq!(budget.reserved_bytes(), 64);
    without_allocations(|| drop(parent));
    assert_eq!(budget.reserved_bytes(), 24);
    let replacement = budget.try_reserve_bytes(40).unwrap();
    assert!(matches!(
        budget.try_reserve_bytes(1),
        Err(AllocationRefusal::Capacity { .. })
    ));
    without_allocations(|| drop(charge));
    assert_eq!(budget.reserved_bytes(), 40);
    without_allocations(|| drop(replacement));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn partition_refusal_and_zero_partition_preserve_original_remaining_and_refund() {
    let budget = AllocationBudget::new(17);
    let mut parent = budget.try_reserve_bytes(17).unwrap();
    let error = without_allocations(|| parent.try_partition_bytes(18)).unwrap_err();
    assert_eq!(
        error,
        InsufficientReservation {
            requested_bytes: 18,
            remaining_bytes: 17
        }
    );
    assert_eq!(parent.remaining_bytes(), 17);
    assert_eq!(budget.reserved_bytes(), 17);
    let empty = without_allocations(|| parent.try_partition_bytes(0).unwrap());
    assert_eq!(empty.remaining_bytes(), 0);
    assert_eq!(parent.remaining_bytes(), 17);
    without_allocations(|| drop(empty));
    assert_eq!(budget.reserved_bytes(), 17);
    let child = without_allocations(|| parent.try_partition_bytes(17).unwrap());
    assert_eq!(parent.remaining_bytes(), 0);
    without_allocations(|| drop(parent));
    assert_eq!(budget.reserved_bytes(), 17);
    without_allocations(|| drop(child));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn owned_refund_scope_reserves_original_control_until_last_custodian() {
    let bytes = OwnedAllocationScope::allocation_layout().size();
    let small = AllocationBudget::new(bytes - 1);
    assert!(matches!(
        small.try_owned_refund_scope(),
        Err(AllocationRefusal::ExceedsLimit { .. })
    ));
    assert_eq!(small.reserved_bytes(), 0);
    let budget = AllocationBudget::new(bytes + 1 + ReleaseRegistration::allocation_layout().size());
    let mut budget_registration_0 = registration(&budget);
    let scope = budget.try_owned_refund_scope().unwrap();
    assert_eq!(
        budget.reserved_bytes(),
        bytes + ReleaseRegistration::allocation_layout().size()
    );
    let last = without_allocations(|| scope.clone());
    let held = budget.try_reserve_bytes(1).unwrap();
    let mut wait = capacity_wait(
        budget.try_reserve_bytes(1).unwrap_err(),
        &mut budget_registration_0,
    );
    let wakes = Arc::new(WakeCount::default());
    assert!(poll(&mut wait, &wakes).is_pending());
    drop(held);
    drop(scope);
    assert_eq!(wakes.0.load(SeqCst), 0);
    assert_eq!(
        budget.reserved_bytes(),
        bytes + ReleaseRegistration::allocation_layout().size()
    );
    drop(last);
    assert!(wakes.0.load(SeqCst) > 0);
    assert!(poll(&mut wait, &wakes).is_ready());
    assert_eq!(
        budget.reserved_bytes(),
        ReleaseRegistration::allocation_layout().size()
    );
}

#[test]
fn owned_refund_scopes_unlink_out_of_order_across_lexical_and_foreign_scopes() {
    let bytes = OwnedAllocationScope::allocation_layout().size();
    let budget =
        AllocationBudget::new(bytes * 3 + 1 + ReleaseRegistration::allocation_layout().size());
    let mut budget_registration_0 = registration(&budget);
    let other = AllocationBudget::new(bytes + 1);
    let outer = budget.try_owned_refund_scope().unwrap();
    let foreign = other.try_owned_refund_scope().unwrap();
    let retained =
        budget.with_deferred_refund_notifications(|_| budget.try_owned_refund_scope().unwrap());
    let held = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    let mut wait = capacity_wait(
        budget.try_reserve_bytes(1).unwrap_err(),
        &mut budget_registration_0,
    );
    let wakes = Arc::new(WakeCount::default());
    assert!(poll(&mut wait, &wakes).is_pending());
    drop(held);
    drop(outer);
    drop(foreign);
    assert_eq!(wakes.0.load(SeqCst), 0);
    assert_eq!(other.reserved_bytes(), 0);
    drop(retained);
    assert!(wakes.0.load(SeqCst) > 0);
    assert_eq!(
        budget.reserved_bytes(),
        ReleaseRegistration::allocation_layout().size()
    );
    // The TLS chain must contain no pointer into any freed owned/lexical record.
    without_allocations(|| budget.with_deferred_refund_notifications(|_| {}));
}

#[path = "allocation/refund_batch_tests.rs"]
mod refund_batch_tests;

#[path = "allocation/refund_control_tests.rs"]
mod refund_control_tests;

#[test]
fn pool_identity_requires_same_owner_and_never_admits_credit() {
    let original = AllocationBudget::new(0);
    let shared = original.clone();
    let independent = AllocationBudget::new(0);
    assert!(original.same_pool(&shared));
    assert!(shared.same_pool(&original));
    assert!(!original.same_pool(&independent));
    assert!(!independent.same_pool(&shared));
    shared.set_limit_bytes(17);
    assert!(original.same_pool(&shared));
    assert_eq!(original.limit_bytes(), 17);
    assert_eq!(independent.limit_bytes(), 0);
    assert_eq!(original.reserved_bytes(), 0);
    assert_eq!(independent.reserved_bytes(), 0);
}

#[test]
fn prepaid_shared_exact_charge_retains_refused_original_and_last_reader() {
    use crate::test_support::refusing_allocation;
    let layout = ChargedShared::<[u8; 33]>::allocation_layout();
    let budget = AllocationBudget::new(layout.size());
    let mut reservation = budget.try_reserve(layout).unwrap();
    let charge = reservation.try_split(layout).unwrap();
    let (charge, error) = refusing_allocation(layout, || {
        ChargedShared::<[u8; 33]>::reserve_from_charge(charge)
    })
    .err()
    .unwrap();
    assert_eq!(error, SharedFromChargeError::Allocator { layout });
    assert!(charge.belongs_to(&budget));
    assert_eq!(charge.layout(), layout);
    assert_eq!(budget.reserved_bytes(), layout.size());
    budget.set_limit_bytes(0);
    let shell = ChargedShared::<[u8; 33]>::reserve_from_charge(charge)
        .unwrap_or_else(|_| panic!("unchanged charge retry"));
    assert!(shell.belongs_to(&budget));
    let owner = without_allocations(|| shell.initialize([7; 33]));
    let reader = without_allocations(|| owner.clone());
    without_allocations(|| drop(owner));
    assert_eq!(budget.reserved_bytes(), layout.size());
    assert_eq!(*reader, [7; 33]);
    without_allocations(|| drop(reader));
    assert_eq!(budget.reserved_bytes(), 0);
}
#[test]
fn prepaid_shared_charge_rejects_wrong_size_and_alignment_before_allocation() {
    #[repr(align(64))]
    struct Aligned;
    let exact = ChargedShared::<Aligned>::allocation_layout();
    for wrong in [
        Layout::from_size_align(exact.size() + 1, exact.align()).unwrap(),
        Layout::from_size_align(exact.size(), 1).unwrap(),
    ] {
        let budget = AllocationBudget::new(wrong.size());
        let mut reservation = budget.try_reserve(wrong).unwrap();
        let charge = reservation.try_split(wrong).unwrap();
        let (charge, error) =
            without_allocations(|| ChargedShared::<Aligned>::reserve_from_charge(charge))
                .err()
                .unwrap();
        assert_eq!(
            error,
            SharedFromChargeError::LayoutMismatch {
                expected: exact,
                actual: wrong
            }
        );
        assert!(charge.belongs_to(&budget));
        assert_eq!(charge.layout(), wrong);
        assert_eq!(budget.reserved_bytes(), wrong.size());
        drop(charge);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}
