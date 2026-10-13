//! Observe physical allocation on a tiny hostile get-method stack before accepting its depth.

use iroha_sccp::v1::ton_cell::CellBuilder;
use iroha_sccp_wallet::pure::ton::{TonError, TvmIntV1, parse_int_stack};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

thread_local! {
    static LARGEST: Cell<Option<usize>> = const { Cell::new(None) };
}
struct ObservedAllocator;
fn observe(bytes: usize) {
    let _ = LARGEST.try_with(|largest| {
        if let Some(previous) = largest.get() {
            largest.set(Some(previous.max(bytes)));
        }
    });
}
// SAFETY: every request and release is forwarded unchanged to System; observation is thread-local.
#[allow(
    unsafe_code,
    reason = "test-only allocator forwards exact original layouts to System and observes physical allocation"
)]
unsafe impl GlobalAlloc for ObservedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        observe(layout.size());
        // SAFETY: the caller supplied the original valid layout.
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        observe(layout.size());
        // SAFETY: the caller supplied the original valid layout.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        observe(size);
        // SAFETY: pointer, its original live layout and the requested size are unchanged.
        unsafe { System.realloc(pointer, layout, size) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: pointer and its original live layout are unchanged.
        unsafe { System.dealloc(pointer, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: ObservedAllocator = ObservedAllocator;

#[test]
fn hostile_stack_depth_is_refused_before_advertised_output_allocation() {
    const DEPTH: usize = 0xff_ffff;
    let mut root = CellBuilder::new();
    root.store_uint(DEPTH as u128, 24).unwrap();
    let wire = root.build().to_boc().unwrap();
    assert!(wire.len() < 64, "genuine tiny encoded stack");
    LARGEST.with(|largest| largest.set(Some(0)));
    let result = parse_int_stack(&wire);
    let largest = LARGEST.with(|largest| largest.replace(None).unwrap());
    assert_eq!(result, Err(TonError::BadStack));
    let advertised = DEPTH * std::mem::size_of::<Option<TvmIntV1>>();
    assert!(
        largest < advertised,
        "attempted {largest} bytes for {advertised} advertised output bytes"
    );
    assert!(
        largest <= wire.len() * 64,
        "parser allocation {largest} must remain proportional to this physical input"
    );
}

#[test]
fn hostile_cell_count_is_refused_before_index_or_cell_allocation() {
    for indexed in [false, true] {
        // 8192 claimed cells, zero cell bytes: tiny input, within the absolute cell cap.
        let wire = [
            0xb5,
            0xee,
            0x9c,
            0x72,
            if indexed { 0x82 } else { 0x02 },
            1,
            0x20,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
        ];
        LARGEST.with(|largest| largest.set(Some(0)));
        let result = parse_int_stack(&wire);
        let largest = LARGEST.with(|largest| largest.replace(None).unwrap());
        assert!(result.is_err());
        assert!(
            largest <= wire.len() * 64,
            "allocated {largest} for {} physical bytes",
            wire.len()
        );
    }
}
