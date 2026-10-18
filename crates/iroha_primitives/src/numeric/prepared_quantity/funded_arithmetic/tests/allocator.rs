//! Thread-local observation of the first exact native-digit backing allocation.

#![allow(unsafe_code)]

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

use iroha_allocation::AllocationBudget;

#[derive(Clone, Copy)]
pub(super) struct Observation {
    budget: *const AllocationBudget,
    layout: Layout,
    pointer: usize,
    refuse: bool,
    pub(super) allocations: usize,
    pub(super) deallocations: usize,
    pub(super) minimum_reserved: usize,
    pub(super) exact_deallocation_layout: bool,
}

thread_local! {
    static OBSERVATION: Cell<Option<Observation>> = const { Cell::new(None) };
}

struct ObservedAllocator;

#[global_allocator]
static ALLOCATOR: ObservedAllocator = ObservedAllocator;

impl Observation {
    fn observe_custody(&mut self) {
        // SAFETY: observe keeps this borrowed budget live until its synchronous
        // closure returns or unwinds, and clears the thread-local pointer first.
        let reserved = unsafe { &*self.budget }.reserved_bytes();
        self.minimum_reserved = self.minimum_reserved.min(reserved);
    }
}

// SAFETY: all successful allocations and frees use System with the caller's
// original layout. A selected null result follows GlobalAlloc's contract.
unsafe impl GlobalAlloc for ObservedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let selected = OBSERVATION
            .try_with(|slot| {
                let mut observed = slot.get()?;
                if observed.allocations != 0 || observed.layout != layout {
                    return None;
                }
                observed.allocations += 1;
                observed.observe_custody();
                slot.set(Some(observed));
                Some(observed.refuse)
            })
            .ok()
            .flatten();
        if selected == Some(true) {
            return std::ptr::null_mut();
        }
        let pointer = unsafe { System.alloc(layout) };
        if selected == Some(false) {
            let _ = OBSERVATION.try_with(|slot| {
                if let Some(mut observed) = slot.get() {
                    observed.pointer = pointer.addr();
                    slot.set(Some(observed));
                }
            });
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let selected = OBSERVATION
            .try_with(|slot| {
                let mut observed = slot.get()?;
                if observed.pointer != pointer.addr() {
                    return None;
                }
                observed.observe_custody();
                observed.exact_deallocation_layout = observed.layout == layout;
                slot.set(Some(observed));
                Some(())
            })
            .ok()
            .flatten()
            .is_some();
        unsafe { System.dealloc(pointer, layout) };
        if selected {
            let _ = OBSERVATION.try_with(|slot| {
                if let Some(mut observed) = slot.get() {
                    observed.observe_custody();
                    observed.deallocations += 1;
                    observed.pointer = 0;
                    slot.set(Some(observed));
                }
            });
        }
    }
}

pub(super) fn observe<T>(
    budget: &AllocationBudget,
    layout: Layout,
    refuse: bool,
    operation: impl FnOnce() -> T,
) -> (T, Observation) {
    assert!(OBSERVATION.with(Cell::get).is_none());
    struct Clear;
    impl Drop for Clear {
        fn drop(&mut self) {
            OBSERVATION.with(|slot| slot.set(None));
        }
    }
    OBSERVATION.with(|slot| {
        slot.set(Some(Observation {
            budget,
            layout,
            pointer: 0,
            refuse,
            allocations: 0,
            deallocations: 0,
            minimum_reserved: usize::MAX,
            exact_deallocation_layout: false,
        }));
    });
    let guard = Clear;
    let value = operation();
    let observed = OBSERVATION
        .with(Cell::get)
        .expect("original observation survives");
    drop(guard);
    (value, observed)
}
