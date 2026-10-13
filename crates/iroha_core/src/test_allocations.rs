//! Shared thread-local allocation census for exact Core ownership controls.
//!
//! Production builds use no instrumentation. Each observation disables itself
//! during unwinding; other test threads remain outside its counter.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

thread_local! {
    static TRACK_ALLOCATIONS: Cell<bool> = const { Cell::new(false) };
    static ALLOCATION_COUNT: Cell<usize> = const { Cell::new(0) };
    static REFUSAL_ACTIVE: Cell<bool> = const { Cell::new(false) };
    static REFUSE_LAYOUT: Cell<Option<Layout>> = const { Cell::new(None) };
    static REFUSAL_OBSERVED: Cell<bool> = const { Cell::new(false) };
}

struct CountingAllocator;

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn record_allocation() {
    let _ = TRACK_ALLOCATIONS.try_with(|tracking| {
        if tracking.get() {
            let _ = ALLOCATION_COUNT.try_with(|count| count.set(count.get() + 1));
        }
    });
}

fn refuse_allocation(layout: Layout) -> bool {
    REFUSE_LAYOUT
        .try_with(|expected| {
            if expected.get() == Some(layout) {
                expected.set(None);
                let _ = REFUSAL_OBSERVED.try_with(|observed| observed.set(true));
                true
            } else {
                false
            }
        })
        .unwrap_or(false)
}

// SAFETY: successful operations delegate to System with the original allocation layout.
// A test-scoped null result follows GlobalAlloc's failure contract and leaves realloc's
// original live owner untouched.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if refuse_allocation(layout) {
            return std::ptr::null_mut();
        }
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            record_allocation();
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if refuse_allocation(layout) {
            return std::ptr::null_mut();
        }
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            record_allocation();
        }
        pointer
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if Layout::from_size_align(size, layout.align()).is_ok_and(refuse_allocation) {
            return std::ptr::null_mut();
        }
        let result = unsafe { System.realloc(pointer, layout, size) };
        if !result.is_null() {
            record_allocation();
        }
        result
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
    }
}

/// Count successful heap allocations on this thread only, including reallocations.
///
/// # Panics
/// Rejects nested observation before changing the active counter or tracking guard.
pub(crate) fn allocations_during(f: impl FnOnce()) -> usize {
    struct StopTracking;
    impl Drop for StopTracking {
        fn drop(&mut self) {
            TRACK_ALLOCATIONS.with(|tracking| tracking.set(false));
        }
    }
    assert!(
        !TRACK_ALLOCATIONS.with(Cell::get),
        "nested allocation census would invalidate the outer observation"
    );
    ALLOCATION_COUNT.with(|count| count.set(0));
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(true));
    let stop = StopTracking;
    f();
    drop(stop);
    ALLOCATION_COUNT.with(Cell::get)
}

/// Refuse one exact physical layout on this thread, then restore the allocator.
/// The closure must use a fallible allocation path for this selected layout.
///
/// # Panics
/// Rejects nested refusal before changing the outer observation.
pub(crate) fn refuse_one_layout_during<T>(layout: Layout, f: impl FnOnce() -> T) -> (T, bool) {
    struct RestoreAllocator;
    impl Drop for RestoreAllocator {
        fn drop(&mut self) {
            REFUSE_LAYOUT.with(|expected| expected.set(None));
            REFUSAL_ACTIVE.with(|active| active.set(false));
        }
    }
    assert!(
        !REFUSAL_ACTIVE.with(Cell::get),
        "nested allocation refusal would replace its original owner"
    );
    REFUSAL_ACTIVE.with(|active| active.set(true));
    REFUSE_LAYOUT.with(|expected| expected.set(Some(layout)));
    REFUSAL_OBSERVED.with(|observed| observed.set(false));
    let guard = RestoreAllocator;
    let result = f();
    let refused = REFUSAL_OBSERVED.with(Cell::get);
    drop(guard);
    (result, refused)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        hint::black_box,
        sync::atomic::{AtomicBool, Ordering},
    };

    #[test]
    fn physical_refusal_is_exact_once_and_restores_the_allocator() {
        let layout = Layout::array::<u8>(37).unwrap();
        let (result, refused) = refuse_one_layout_during(layout, || {
            let mut other = Vec::<u8>::new();
            other.try_reserve_exact(19).unwrap();
            let mut selected = Vec::<u8>::new();
            let refused = selected.try_reserve_exact(37);
            selected.try_reserve_exact(37).unwrap();
            refused
        });
        assert!(refused);
        assert!(result.is_err());
        assert!(!REFUSAL_ACTIVE.with(Cell::get));
        let mut ordinary = Vec::<u8>::new();
        ordinary.try_reserve_exact(37).unwrap();
    }

    #[test]
    fn physical_refusal_restores_after_unwind_and_rejects_nested_replacement() {
        let layout = Layout::array::<u8>(37).unwrap();
        let (nested, refused) = refuse_one_layout_during(layout, || {
            let nested = std::panic::catch_unwind(|| {
                refuse_one_layout_during(Layout::array::<u8>(43).unwrap(), || ())
            });
            assert!(REFUSAL_ACTIVE.with(Cell::get));
            let mut selected = Vec::<u8>::new();
            assert!(selected.try_reserve_exact(37).is_err());
            nested
        });
        assert!(nested.is_err());
        assert!(refused);
        let unwound = std::panic::catch_unwind(|| {
            refuse_one_layout_during(layout, || panic!("refusal unwind"))
        });
        assert!(unwound.is_err());
        assert!(!REFUSAL_ACTIVE.with(Cell::get));
        let mut ordinary = Vec::<u8>::new();
        ordinary.try_reserve_exact(37).unwrap();
    }

    #[test]
    fn physical_refusal_covers_zeroed_and_reallocated_storage_without_losing_original() {
        let selected = Layout::array::<u8>(37).unwrap();
        let (pointer, refused) =
            refuse_one_layout_during(selected, || unsafe { std::alloc::alloc_zeroed(selected) });
        assert!(refused);
        assert!(pointer.is_null());
        let original = Layout::array::<u8>(19).unwrap();
        let pointer = unsafe { std::alloc::alloc(original) };
        assert!(!pointer.is_null());
        unsafe {
            pointer.write(42);
        }
        let (replacement, refused) = refuse_one_layout_during(selected, || unsafe {
            std::alloc::realloc(pointer, original, selected.size())
        });
        assert!(refused);
        assert!(replacement.is_null());
        assert_eq!(
            unsafe { pointer.read() },
            42,
            "refusal leaves the original allocation live"
        );
        unsafe {
            std::alloc::dealloc(pointer, original);
        }
    }

    #[test]
    fn physical_refusal_excludes_other_threads() {
        let ready = AtomicBool::new(false);
        let start = AtomicBool::new(false);
        let done = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                ready.store(true, Ordering::Release);
                while !start.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
                let mut ordinary = Vec::<u8>::new();
                let result = ordinary.try_reserve_exact(37);
                done.store(true, Ordering::Release);
                result
            });
            while !ready.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            let (result, refused) =
                refuse_one_layout_during(Layout::array::<u8>(37).unwrap(), || {
                    start.store(true, Ordering::Release);
                    while !done.load(Ordering::Acquire) {
                        std::thread::yield_now();
                    }
                    let mut selected = Vec::<u8>::new();
                    selected.try_reserve_exact(37)
                });
            worker
                .join()
                .unwrap()
                .expect("other thread retains its original allocator");
            assert!(refused);
            assert!(result.is_err());
        });
    }

    #[test]
    fn allocation_census_has_positive_and_zero_controls() {
        assert_eq!(allocations_during(|| {}), 0);
        assert_eq!(
            allocations_during(|| drop(black_box(Box::new([42_u8; 64])))),
            1
        );
        assert!(!TRACK_ALLOCATIONS.with(Cell::get));
    }

    #[test]
    fn allocation_census_clears_tracking_on_unwind() {
        let result = std::panic::catch_unwind(|| allocations_during(|| panic!("census unwind")));
        assert!(result.is_err());
        assert!(!TRACK_ALLOCATIONS.with(Cell::get));
        assert_eq!(allocations_during(|| {}), 0);
    }

    #[test]
    fn nested_allocation_census_cannot_reset_or_disable_outer_observation() {
        let nested_ran = Cell::new(false);
        let mut nested_result = None;
        let mut before = 0;
        let mut after = 0;
        let mut still_tracking = false;
        let count = allocations_during(|| {
            drop(black_box(Box::new([3_u8; 64])));
            before = ALLOCATION_COUNT.with(Cell::get);
            nested_result = Some(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                || allocations_during(|| nested_ran.set(true)),
            )));
            after = ALLOCATION_COUNT.with(Cell::get);
            still_tracking = TRACK_ALLOCATIONS.with(Cell::get);
            drop(black_box(Box::new([4_u8; 64])));
        });
        assert!(nested_result.unwrap().is_err());
        assert!(!nested_ran.get());
        assert_eq!(before, 1);
        assert!(
            after >= before,
            "panic custody may allocate; the outer count cannot decrease"
        );
        assert!(still_tracking);
        assert_eq!(count, after + 1);
        assert!(!TRACK_ALLOCATIONS.with(Cell::get));
    }

    #[test]
    fn allocation_census_excludes_other_threads() {
        let ready = AtomicBool::new(false);
        let start = AtomicBool::new(false);
        let done = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                ready.store(true, Ordering::Release);
                while !start.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
                for _ in 0..16 {
                    drop(black_box(Box::new([1_u8; 128])));
                }
                done.store(true, Ordering::Release);
            });
            while !ready.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            let allocations = allocations_during(|| {
                start.store(true, Ordering::Release);
                while !done.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
            });
            worker.join().unwrap();
            assert_eq!(allocations, 0);
        });
    }
}
