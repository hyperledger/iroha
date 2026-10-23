//! Physical signed-decimal allocation/refund and move-only custody controls.

#![allow(unsafe_code)]

use iroha_allocation::{AllocationBudget, ChargedBufferError};
use iroha_primitives::numeric::{ChargedNumeric, Numeric, NumericDecimalAdmissionError};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

struct ObservingAllocator;
thread_local! {
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
    static DENY: Cell<bool> = const { Cell::new(false) };
    static REQUESTS: Cell<usize> = const { Cell::new(0) };
    static ORIGINAL: Cell<usize> = const { Cell::new(0) };
    static RETIREMENTS: Cell<usize> = const { Cell::new(0) };
    static POOL: Cell<*const AllocationBudget> = const { Cell::new(std::ptr::null()) };
    static CREDIT_AT_RETIREMENT: Cell<usize> = const { Cell::new(0) };
}
fn request() -> bool {
    if !ACTIVE.with(Cell::get) {
        return false;
    }
    REQUESTS.with(|v| v.set(v.get() + 1));
    DENY.with(|v| v.replace(false))
}
fn record(pointer: *mut u8) {
    if ACTIVE.with(Cell::get) && !pointer.is_null() {
        ORIGINAL.with(|v| v.set(pointer as usize));
    }
}
// SAFETY: forwarding preserves every pointer/layout. The sole injected failure
// returns null before allocation; observation never takes ownership of storage.
unsafe impl GlobalAlloc for ObservingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if request() {
            return std::ptr::null_mut();
        }
        let pointer = unsafe { System.alloc(layout) };
        record(pointer);
        pointer
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if request() {
            return std::ptr::null_mut();
        }
        let pointer = unsafe { System.alloc_zeroed(layout) };
        record(pointer);
        pointer
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if request() {
            return std::ptr::null_mut();
        }
        let pointer = unsafe { System.realloc(pointer, layout, size) };
        record(pointer);
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if ACTIVE.with(Cell::get) && ORIGINAL.with(Cell::get) == pointer as usize {
            RETIREMENTS.with(|v| v.set(v.get() + 1));
            let pool = POOL.with(Cell::get);
            if !pool.is_null() {
                // SAFETY: Observation retains an immutable pool borrow for the
                // entire same-thread observation and clears this pointer on drop.
                CREDIT_AT_RETIREMENT.with(|v| v.set(unsafe { &*pool }.reserved_bytes()));
            }
        }
        unsafe { System.dealloc(pointer, layout) };
    }
}
#[global_allocator]
static ALLOCATOR: ObservingAllocator = ObservingAllocator;
struct Observation<'a>(&'a AllocationBudget);
impl<'a> Observation<'a> {
    fn start(pool: &'a AllocationBudget, deny: bool) -> Self {
        assert!(!ACTIVE.with(Cell::get));
        REQUESTS.with(|v| v.set(0));
        ORIGINAL.with(|v| v.set(0));
        RETIREMENTS.with(|v| v.set(0));
        CREDIT_AT_RETIREMENT.with(|v| v.set(0));
        DENY.with(|v| v.set(deny));
        POOL.with(|v| v.set(pool));
        ACTIVE.with(|v| v.set(true));
        Self(pool)
    }
}
impl Drop for Observation<'_> {
    fn drop(&mut self) {
        ACTIVE.with(|v| v.set(false));
        POOL.with(|v| v.set(std::ptr::null()));
        let _ = self.0;
    }
}

#[test]
fn borrowed_numeric_physical_refusal_is_exact_typed_and_same_source_retries() {
    let source = "-123456789012345678901234567890.125";
    let expected: Numeric = source.parse().unwrap();
    let bytes = expected.admission_clone_layout().unwrap().size();
    let pool = AllocationBudget::new(bytes);
    let observation = Observation::start(&pool, true);
    let error = ChargedNumeric::try_from_decimal(source, &pool).unwrap_err();
    assert!(
        matches!(error,NumericDecimalAdmissionError::Allocation(ChargedBufferError::Allocator{requested_bytes}) if requested_bytes==bytes)
    );
    assert_eq!(REQUESTS.with(Cell::get), 1);
    assert_eq!(pool.reserved_bytes(), 0);
    drop(observation);
    let owner = ChargedNumeric::try_from_decimal(source, &pool).unwrap();
    assert_eq!(owner.get(), &expected);
    drop(owner);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn borrowed_numeric_moves_original_mantissa_once_and_refunds_after_physical_retirement() {
    let source = "-123456789012345678901234567890.125";
    let expected: Numeric = source.parse().unwrap();
    let bytes = expected.admission_clone_layout().unwrap().size();
    let pool = AllocationBudget::new(bytes);
    let observation = Observation::start(&pool, false);
    let owner = ChargedNumeric::try_from_decimal(source, &pool).unwrap();
    assert_eq!(REQUESTS.with(Cell::get), 1);
    assert_ne!(ORIGINAL.with(Cell::get), 0);
    assert_eq!(RETIREMENTS.with(Cell::get), 0);
    struct Closed {
        value: Numeric,
        charge: iroha_allocation::AllocationCharge,
    }
    // SAFETY: immediate transfer into an immutable value-first closed owner.
    let (value, charge) = unsafe { owner.into_allocation_parts() };
    let moved = Closed { value, charge };
    assert_eq!(REQUESTS.with(Cell::get), 1);
    assert_eq!(RETIREMENTS.with(Cell::get), 0);
    assert_eq!(&moved.value, &expected);
    assert!(moved.charge.belongs_to(&pool));
    drop(moved);
    assert_eq!(RETIREMENTS.with(Cell::get), 1);
    assert_eq!(CREDIT_AT_RETIREMENT.with(Cell::get), bytes);
    assert_eq!(pool.reserved_bytes(), 0);
    drop(observation);
}

#[test]
fn borrowed_numeric_zero_never_enters_allocator() {
    let pool = AllocationBudget::new(0);
    let observation = Observation::start(&pool, true);
    let owner = ChargedNumeric::try_from_decimal("-000.000", &pool).unwrap();
    assert!(owner.get().is_zero());
    drop(owner);
    assert_eq!(REQUESTS.with(Cell::get), 0);
    assert!(DENY.with(Cell::get));
    assert_eq!(pool.reserved_bytes(), 0);
    drop(observation);
}
