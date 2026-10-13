//! Thread-local allocation observer; every request is forwarded unchanged to System.
#![allow(unsafe_code)]
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};
struct ObservedAllocator;
thread_local! {
    static ENABLED: Cell<bool> = const { Cell::new(false) };
    static COUNT: Cell<usize> = const { Cell::new(0) };
}
#[global_allocator]
static ALLOCATOR: ObservedAllocator = ObservedAllocator;
fn record() {
    let _ = ENABLED.try_with(|enabled| {
        if enabled.get() {
            let _ = COUNT.try_with(|count| count.set(count.get().saturating_add(1)));
        }
    });
}
unsafe impl GlobalAlloc for ObservedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record();
        // SAFETY: forward the original allocator request unchanged.
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record();
        // SAFETY: forward the original allocator request unchanged.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record();
        // SAFETY: forward the caller's original allocation and new size unchanged.
        unsafe { System.realloc(pointer, layout, size) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: forward the caller's matching pointer/layout unchanged.
        unsafe { System.dealloc(pointer, layout) }
    }
}
fn measured<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            ENABLED.with(|enabled| enabled.set(false));
        }
    }
    ENABLED.with(|enabled| assert!(!enabled.get(), "nested measurement"));
    COUNT.with(|count| count.set(0));
    ENABLED.with(|enabled| enabled.set(true));
    let reset = Reset;
    let value = operation();
    drop(reset);
    (value, COUNT.with(Cell::get))
}
#[test]
fn observer_counts_all_three_allocation_routes_and_resets_after_unwind() {
    let ((), count) = measured(|| {
        // SAFETY: every successful exact-layout allocation is deallocated with
        // its matching final layout; failed reallocation retains the old pointer.
        unsafe {
            let layout = Layout::from_size_align(16, 8).unwrap();
            let pointer = std::alloc::alloc(layout);
            assert!(!pointer.is_null());
            std::hint::black_box(pointer);
            let grown = std::alloc::realloc(pointer, layout, 32);
            if grown.is_null() {
                std::alloc::dealloc(pointer, layout);
                panic!("allocator refused observer self-test");
            }
            std::hint::black_box(grown);
            std::alloc::dealloc(grown, Layout::from_size_align(32, 8).unwrap());
            let zero = std::alloc::alloc_zeroed(layout);
            assert!(!zero.is_null());
            std::hint::black_box(zero);
            std::alloc::dealloc(zero, layout);
        }
    });
    assert_eq!(count, 3);
    let panic = std::panic::catch_unwind(|| measured(|| panic!("observer unwind control")));
    assert!(panic.is_err());
    assert!(!ENABLED.with(Cell::get));
    assert_eq!(measured(|| std::hint::black_box(7)).1, 0);
}

use super::super::super::tests::balance;
use super::super::*;
use iroha_test_samples::ALICE_ID;

#[test]
fn retirement_fixed_units_and_arithmetic_allocate_nothing() {
    let kind = FastpqExecutionEffectKindV1::Retire(balance(&ALICE_ID).asset);
    for scale in 0..=28 {
        let ((values, operation), allocations) = measured(|| {
            let values = normalized_values(std::hint::black_box(&kind), scale).unwrap();
            let [amount, before, after, present, absent] = values;
            let operation =
                check_effect_arithmetic(&kind, amount, &[before, after, present, absent]).unwrap();
            (values, operation)
        });
        assert_eq!(allocations, 0);
        assert_eq!(operation, FastpqOperationKind::MetaSet);
        assert_eq!(values[1].scale(), scale);
        assert!(values[1].limbs().iter().all(|limb| *limb == 0));
        assert_eq!(values[2], values[1]);
        assert_eq!(values[3].scale(), 0);
        assert_eq!(values[3].try_to_u64(), Some(1));
        assert_eq!(values[4].scale(), 0);
        assert_eq!(values[4].try_to_u64(), Some(0));
    }
}
