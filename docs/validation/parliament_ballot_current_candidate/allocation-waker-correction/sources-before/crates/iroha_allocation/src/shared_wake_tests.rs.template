//! Runtime wakers retain one canonical prepaid control through callback and unwind.

use super::SharedWake;
use crate::test_support::{refusing_allocation, without_allocations};
use crate::{AllocationBudget, ChargedShared, PrepaidSharedError};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering::SeqCst},
    },
};

#[derive(Debug)]
struct WakeTarget {
    pool: AllocationBudget,
    identity: Arc<AtomicUsize>,
    wakes: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
    panic: bool,
}
impl SharedWake for WakeTarget {
    fn wake(&self) {
        assert_eq!(
            std::ptr::from_ref(self) as usize,
            self.identity.load(SeqCst)
        );
        assert_eq!(
            self.pool.reserved_bytes(),
            ChargedShared::<Self>::allocation_layout().size()
        );
        self.wakes.fetch_add(1, SeqCst);
        assert!(!self.panic, "original wake callback panicked");
    }
}
impl Drop for WakeTarget {
    fn drop(&mut self) {
        assert_eq!(
            self.pool.reserved_bytes(),
            ChargedShared::<Self>::allocation_layout().size()
        );
        self.drops.fetch_add(1, SeqCst);
    }
}

fn target(pool: &AllocationBudget, panic: bool) -> WakeTarget {
    WakeTarget {
        pool: pool.clone(),
        identity: Arc::new(AtomicUsize::new(0)),
        wakes: Arc::new(AtomicUsize::new(0)),
        drops: Arc::new(AtomicUsize::new(0)),
        panic,
    }
}

#[test]
fn charged_waker_conversion_clones_callbacks_and_final_drop_allocate_nothing() {
    let layout = ChargedShared::<WakeTarget>::allocation_layout();
    let budget = AllocationBudget::new(layout.size());
    let value = target(&budget, false);
    let wake_count = Arc::clone(&value.wakes);
    let drops = Arc::clone(&value.drops);
    let owner =
        ChargedShared::from_reservation(value, &mut budget.try_reserve(layout).unwrap()).unwrap();
    owner
        .identity
        .store(std::ptr::from_ref(&*owner) as usize, SeqCst);
    let waker = without_allocations(|| owner.into_waker());
    let clone = without_allocations(|| waker.clone());
    assert!(waker.will_wake(&clone));
    without_allocations(|| waker.wake_by_ref());
    without_allocations(|| clone.wake());
    assert_eq!(wake_count.load(SeqCst), 2);
    assert_eq!(drops.load(SeqCst), 0);
    assert_eq!(budget.reserved_bytes(), layout.size());
    without_allocations(|| drop(waker));
    assert_eq!(drops.load(SeqCst), 1);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn consumed_and_borrowed_wake_panics_preserve_exact_reference_custody() {
    for consume in [false, true] {
        let layout = ChargedShared::<WakeTarget>::allocation_layout();
        let budget = AllocationBudget::new(layout.size());
        let value = target(&budget, true);
        let wake_count = Arc::clone(&value.wakes);
        let drops = Arc::clone(&value.drops);
        let owner =
            ChargedShared::from_reservation(value, &mut budget.try_reserve(layout).unwrap())
                .unwrap();
        owner
            .identity
            .store(std::ptr::from_ref(&*owner) as usize, SeqCst);
        let waker = owner.into_waker();
        if consume {
            assert!(catch_unwind(AssertUnwindSafe(|| waker.wake())).is_err());
        } else {
            assert!(catch_unwind(AssertUnwindSafe(|| waker.wake_by_ref())).is_err());
            assert_eq!(budget.reserved_bytes(), layout.size());
            assert_eq!(drops.load(SeqCst), 0);
            drop(waker);
        }
        assert_eq!(wake_count.load(SeqCst), 1);
        assert_eq!(drops.load(SeqCst), 1);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn refused_wake_control_returns_unchanged_target_before_any_waker_exists() {
    let layout = ChargedShared::<WakeTarget>::allocation_layout();
    let budget = AllocationBudget::new(layout.size());
    let value = target(&budget, false);
    let identity = Arc::clone(&value.identity);
    let drops = Arc::clone(&value.drops);
    let mut original = budget.try_reserve(layout).unwrap();
    let (value, error) = refusing_allocation(layout, || {
        ChargedShared::from_reservation(value, &mut original)
    })
    .unwrap_err();
    assert_eq!(
        error,
        PrepaidSharedError::Allocator {
            requested_bytes: layout.size()
        }
    );
    assert!(Arc::ptr_eq(&identity, &value.identity));
    assert_eq!(drops.load(SeqCst), 0);
    assert_eq!(original.remaining_bytes(), 0);
    assert_eq!(budget.reserved_bytes(), 0);
    let owner =
        ChargedShared::from_reservation(value, &mut budget.try_reserve(layout).unwrap()).unwrap();
    owner
        .identity
        .store(std::ptr::from_ref(&*owner) as usize, SeqCst);
    owner.into_waker().wake();
    assert_eq!(drops.load(SeqCst), 1);
    assert_eq!(budget.reserved_bytes(), 0);
}
