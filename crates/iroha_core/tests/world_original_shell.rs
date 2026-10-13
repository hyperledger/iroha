//! Actual allocator refusal and reclamation of the original admitted World shell.

use iroha_allocation::AllocationBudget;
use iroha_core::state::{World, WorldBlockFields};
use mv::storage::AdmittedStorageError;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    ptr,
};

#[derive(Clone, Copy)]
struct Observed {
    layout: Layout,
    fail: bool,
    allocations: usize,
    frees: usize,
    pointer: usize,
    original_budget: *const AllocationBudget,
    reserved_at_free: usize,
}
thread_local! {
    static OBSERVED: Cell<Option<Observed>> = const { Cell::new(None) };
}
struct Allocator;

#[allow(unsafe_code)]
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let refuse = OBSERVED
            .try_with(|active| {
                let Some(mut value) = active.get() else {
                    return false;
                };
                if value.layout != layout {
                    return false;
                }
                value.allocations += 1;
                let refuse = value.fail;
                value.fail = false;
                active.set(Some(value));
                refuse
            })
            .unwrap_or(false);
        if refuse {
            return ptr::null_mut();
        }
        // SAFETY: forward the caller's unchanged allocation request.
        let pointer = unsafe { System.alloc(layout) };
        let _ = OBSERVED.try_with(|active| {
            if let Some(mut value) = active.get()
                && value.layout == layout
            {
                value.pointer = pointer as usize;
                active.set(Some(value));
            }
        });
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let _ = OBSERVED.try_with(|active| {
            if let Some(mut value) = active.get()
                && value.layout == layout
                && value.pointer == pointer as usize
            {
                // SAFETY: Scope retains this borrow on this thread until
                // observation is disabled; the test destroys its World
                // shell inside that scope. No pointer escapes the observer.
                value.reserved_at_free = unsafe { &*value.original_budget }.reserved_bytes();
                value.frees += 1;
                active.set(Some(value));
            }
        });
        // SAFETY: the original pointer/layout pair is returned unchanged.
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        // SAFETY: preserve the caller's live allocation and requested size.
        unsafe { System.realloc(pointer, layout, size) }
    }
}
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

struct Scope<'a>(&'a AllocationBudget);
impl<'a> Scope<'a> {
    fn new(source: &'a AllocationBudget, fail: bool) -> Self {
        assert!(OBSERVED.with(Cell::get).is_none());
        OBSERVED.with(|active| {
            active.set(Some(Observed {
                layout: Layout::new::<WorldBlockFields<'static>>(),
                fail,
                allocations: 0,
                frees: 0,
                pointer: 0,
                original_budget: ptr::from_ref(source),
                reserved_at_free: 0,
            }))
        });
        Self(source)
    }
    fn read(&self) -> Observed {
        let _ = self.0;
        OBSERVED.with(Cell::get).unwrap()
    }
}
impl Drop for Scope<'_> {
    fn drop(&mut self) {
        OBSERVED.with(|active| active.set(None));
    }
}

#[test]
fn exact_original_world_shell_allocator_refusal_and_release_in_both_modes() {
    for replacement in [false, true] {
        let world = World::default();
        let source = AllocationBudget::new(64 * 1024 * 1024);
        let foreign = AllocationBudget::new(source.limit_bytes());
        {
            let observed = Scope::new(&source, true);
            let result = if replacement {
                world.try_block_and_revert(&source)
            } else {
                world.try_block(&source)
            };
            let error = match result {
                Ok(_) => panic!("actual shell allocator must refuse"),
                Err(error) => error,
            };
            assert_eq!(
                error,
                AdmittedStorageError::Allocator {
                    layout: Layout::new::<WorldBlockFields<'static>>()
                }
            );
            assert!(
                error.release_wait().is_none(),
                "no fabricated capacity observation"
            );
            assert_eq!(observed.read().allocations, 1);
            assert_eq!(observed.read().frees, 0, "no backing exists on refusal");
            assert_eq!(source.reserved_bytes(), 0);
            assert_eq!(foreign.reserved_bytes(), 0);
        }
        {
            let observed = Scope::new(&source, false);
            let original = if replacement {
                world.try_block_and_revert(&source)
            } else {
                world.try_block(&source)
            }
            .unwrap();
            assert_eq!(observed.read().allocations, 1);
            assert_eq!(observed.read().pointer, ptr::from_ref(&*original) as usize);
            let occupied = source.reserved_bytes();
            assert!(occupied > Layout::new::<WorldBlockFields<'static>>().size());
            source.set_limit_bytes(0);
            assert_eq!(source.reserved_bytes(), occupied);
            drop(original);
            assert_eq!(observed.read().frees, 1);
            assert!(
                observed.read().reserved_at_free
                    >= Layout::new::<WorldBlockFields<'static>>().size(),
                "original backing remains charged until its real deallocation"
            );
            assert_eq!(source.reserved_bytes(), 0);
            assert_eq!(foreign.reserved_bytes(), 0);
        }
        // Every actual field writer is available after both refusal and abort.
        drop(world.try_block(&foreign).unwrap());
        assert_eq!(foreign.reserved_bytes(), 0);
    }
}
