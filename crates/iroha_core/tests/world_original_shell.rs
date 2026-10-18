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
        let original_limit = 64 * 1024 * 1024;
        let source = AllocationBudget::new(original_limit);
        // Prepaid current roots must already belong to the source being observed.
        // Keep World construction outside the shell allocator observation itself.
        let world = World::try_with_execution_budget([], [], [], &source).unwrap();
        let baseline = source.reserved_bytes();
        assert!(
            baseline > 0,
            "live World retains its original current roots"
        );
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
            assert_eq!(source.reserved_bytes(), baseline);
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
            assert!(occupied > baseline + Layout::new::<WorldBlockFields<'static>>().size());
            source.set_limit_bytes(0);
            assert_eq!(source.reserved_bytes(), occupied);
            drop(original);
            assert_eq!(observed.read().frees, 1);
            assert!(
                observed.read().reserved_at_free
                    >= baseline + Layout::new::<WorldBlockFields<'static>>().size(),
                "original backing remains charged until its real deallocation"
            );
            assert_eq!(source.reserved_bytes(), baseline);
            assert_eq!(foreign.reserved_bytes(), 0);
        }
        // A foreign pool cannot supply the retained current roots' authority, even
        // though it still has its original capacity while the source limit is zero.
        assert!(matches!(
            if replacement {
                world.try_block_and_revert(&foreign)
            } else {
                world.try_block(&foreign)
            },
            Err(AdmittedStorageError::ScopeIdentity)
        ));
        assert_eq!(foreign.reserved_bytes(), 0);
        assert_eq!(source.reserved_bytes(), baseline);
        assert_eq!(source.limit_bytes(), 0);
        // Restore only the initial ceiling for the final reuse. Every actual field
        // writer must be available after physical refusal, abort and wrong-pool refusal.
        source.set_limit_bytes(original_limit);
        drop(world.try_block(&source).unwrap());
        assert_eq!(source.reserved_bytes(), baseline);
        let retirement_pin = crossbeam_epoch::pin();
        drop(world);
        retirement_pin.flush();
        assert_eq!(
            source.reserved_bytes(),
            world_cell_generation_bytes(),
            "all seven funded current/undo pairs retain their original charges while pinned"
        );
        drop(retirement_pin);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while source.reserved_bytes() != 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "original World EBR charges did not retire"
            );
            crossbeam_epoch::pin().flush();
            std::thread::yield_now();
        }
        assert_eq!(source.reserved_bytes(), 0);
        assert_eq!(foreign.reserved_bytes(), 0);
    }
}

// These are the seven funded Cell types of the initial World; the integration
// boundary does not expose their private fields or treat their values as charges.
fn world_cell_generation_bytes() -> usize {
    use iroha_allocation::AllocationCharge;
    use iroha_core::{
        smartcontracts::isi::sccp::anchor_record::RetainedSccpAnchors,
        sumeragi::amx::RetainedNativeAmx,
    };
    use mv::cell::Cell;
    [
        Cell::<RetainedNativeAmx, AllocationCharge>::allocation_layouts(),
        Cell::<u64, AllocationCharge>::allocation_layouts(), // Musubi shortfall releases.
        Cell::<u64, AllocationCharge>::allocation_layouts(), // SCCP current committee.
        Cell::<u64, AllocationCharge>::allocation_layouts(), // SCCP liability clock.
        Cell::<u32, AllocationCharge>::allocation_layouts(), // SCCP degraded run.
        Cell::<RetainedSccpAnchors, AllocationCharge>::allocation_layouts(),
        Cell::<Option<u64>, AllocationCharge>::allocation_layouts(), // SCCP forgery maximum.
    ]
    .into_iter()
    .flatten()
    .map(|layout| layout.size())
    .sum()
}
