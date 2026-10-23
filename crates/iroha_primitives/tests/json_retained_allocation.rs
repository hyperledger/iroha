//! Physical allocator refusals preserve JSON's original finite-pool custody.

#![cfg(feature = "json")]
#![allow(unsafe_code)]

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

use iroha_allocation::AllocationBudget;
use iroha_primitives::json::{Json, JsonRetentionError};

struct FailingAllocator;

thread_local! {
    static FAIL_AT: Cell<usize> = const { Cell::new(0) };
}

fn refuse() -> bool {
    FAIL_AT.with(|remaining| match remaining.get() {
        0 => false,
        1 => {
            remaining.set(0);
            true
        }
        next => {
            remaining.set(next - 1);
            false
        }
    })
}

// SAFETY: all non-injected operations forward the exact layout/pointer to System.
unsafe impl GlobalAlloc for FailingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if refuse() {
            std::ptr::null_mut()
        } else {
            unsafe { System.alloc(layout) }
        }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if refuse() {
            std::ptr::null_mut()
        } else {
            unsafe { System.alloc_zeroed(layout) }
        }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if refuse() {
            std::ptr::null_mut()
        } else {
            unsafe { System.realloc(pointer, layout, size) }
        }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: FailingAllocator = FailingAllocator;

fn fail_allocation<T>(index: usize, operation: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            FAIL_AT.with(|remaining| remaining.set(0));
        }
    }
    FAIL_AT.with(|remaining| remaining.set(index));
    let _reset = Reset;
    operation()
}

#[test]
fn control_then_text_allocator_failures_refund_exact_pool_and_leave_source_retryable() {
    let source = Json::new("unchanged canonical allocation source");
    let pool = AllocationBudget::new(4096);
    let control = fail_allocation(1, || source.try_retain_in(&pool));
    assert!(matches!(control, Err(JsonRetentionError::Shared(_))));
    assert_eq!(pool.reserved_bytes(), 0);
    let text = fail_allocation(2, || source.try_retain_in(&pool));
    assert!(matches!(text, Err(JsonRetentionError::Text(_))));
    assert_eq!(pool.reserved_bytes(), 0);
    let retained = source.try_retain_in(&pool).unwrap();
    assert_eq!(retained, source);
    assert!(retained.belongs_to(&pool));
    drop(retained);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn same_pool_retention_and_raw_clone_use_no_allocator_and_keep_custody() {
    let source = Json::new("shared lifetime");
    let pool = AllocationBudget::new(4096);
    let retained = source.try_retain_in(&pool).unwrap();
    let original_bytes = pool.reserved_bytes();
    pool.set_limit_bytes(0);
    let (same, raw, unspent) = fail_allocation(1, || {
        let same = retained.try_retain_in(&pool).unwrap();
        let raw = retained.clone();
        (same, raw, FAIL_AT.with(Cell::get))
    });
    assert_eq!(unspent, 1);
    assert!(same.ptr_eq(&retained));
    assert!(raw.ptr_eq(&retained));
    drop(retained);
    drop(same);
    assert_eq!(pool.reserved_bytes(), original_bytes);
    drop(raw);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn direct_decode_refunds_original_scratch_control_and_text_allocator_refusals() {
    let source = r#"{"a":"value"}"#;
    let pool = AllocationBudget::new(4096);
    for index in 1..=3 {
        let result = fail_allocation(index, || {
            let mut parser = norito::json::Parser::new(source);
            Json::try_decode_json(&mut parser, &pool)
        });
        match (index, result) {
            (1, Err(JsonRetentionError::Scratch(_)))
            | (2, Err(JsonRetentionError::Shared(_)))
            | (3, Err(JsonRetentionError::Text(_))) => {}
            (_, result) => panic!("wrong original allocation refusal at {index}: {result:?}"),
        }
        assert_eq!(pool.reserved_bytes(), 0);
    }
    let retained = Json::try_decode_json(&mut norito::json::Parser::new(source), &pool).unwrap();
    assert_eq!(retained.get(), source);
    assert!(retained.belongs_to(&pool));
    drop(retained);
    assert_eq!(pool.reserved_bytes(), 0);
}
