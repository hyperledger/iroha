//! Finite capacity, prepaid splitting and scoped reclamation notifications.

use iroha_allocation::AllocationRefusal;
use std::{
    alloc::Layout,
    cell::Cell,
    sync::{Arc, atomic::AtomicUsize},
};
use std::{
    alloc::{GlobalAlloc, System},
    future::Future,
    pin::Pin,
    sync::atomic::Ordering::SeqCst,
    task::{Context, Poll, Wake, Waker},
};

thread_local! {
    static ALLOCATION_COUNT: Cell<Option<usize>> = const { Cell::new(None) };
    static LAYOUT_TRACE: Cell<Option<LayoutTrace>> = const { Cell::new(None) };
    // Exact layout and how many matching allocations still pass before one refusal.
    static REFUSE: Cell<Option<(Layout, usize)>> = const { Cell::new(None) };
}

/// This thread's allocations of one exact layout, with the running count recorded
/// at each caller-defined phase boundary (for example a policy admission).
#[derive(Clone, Copy, Debug)]
pub(crate) struct LayoutTrace {
    layout: Layout,
    /// Matching allocations requested during the traced operation.
    pub(crate) seen: usize,
    /// `seen` at each of the first marked boundaries, in order.
    pub(crate) marks: [usize; 8],
    /// Number of boundaries marked, including any beyond `marks`.
    pub(crate) marked: usize,
}

struct ObservedAllocator;

fn record_allocation() {
    let _ = ALLOCATION_COUNT.try_with(|count| {
        if let Some(previous) = count.get() {
            count.set(Some(previous.saturating_add(1)));
        }
    });
}

// Count, trace and possibly refuse one new allocation without allocating.
fn admit_allocation(layout: Layout) -> bool {
    record_allocation();
    let _ = LAYOUT_TRACE.try_with(|trace| {
        if let Some(mut current) = trace.get()
            && current.layout == layout
        {
            current.seen += 1;
            trace.set(Some(current));
        }
    });
    REFUSE
        .try_with(|refuse| match refuse.get() {
            Some((expected, 0)) if expected == layout => {
                refuse.set(None);
                false
            }
            Some((expected, remaining)) if expected == layout => {
                refuse.set(Some((expected, remaining - 1)));
                true
            }
            _ => true,
        })
        .unwrap_or(true)
}

unsafe impl GlobalAlloc for ObservedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !admit_allocation(layout) {
            return std::ptr::null_mut();
        }
        // SAFETY: forward the unchanged request to the system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if !admit_allocation(layout) {
            return std::ptr::null_mut();
        }
        // SAFETY: preserve the original zeroing and layout contract.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record_allocation();
        // SAFETY: preserve the live allocation, old layout and requested size.
        unsafe { System.realloc(pointer, layout, size) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: forward the original allocation and its exact layout.
        unsafe { System.dealloc(pointer, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: ObservedAllocator = ObservedAllocator;

pub(crate) fn without_allocations<R>(operation: impl FnOnce() -> R) -> R {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            ALLOCATION_COUNT.with(|count| count.set(None));
        }
    }
    assert!(
        ALLOCATION_COUNT
            .with(|count| count.replace(Some(0)))
            .is_none()
    );
    let reset = Reset;
    let output = operation();
    let allocations = ALLOCATION_COUNT.with(|count| count.replace(None)).unwrap();
    drop(reset);
    assert_eq!(allocations, 0, "lexical refund handling allocated storage");
    output
}

/// Trace this thread's allocations of exactly `layout` while `operation` runs.
pub(crate) fn trace_layout_during<R>(
    layout: Layout,
    operation: impl FnOnce() -> R,
) -> (R, LayoutTrace) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            LAYOUT_TRACE.with(|trace| trace.set(None));
        }
    }
    let start = LayoutTrace {
        layout,
        seen: 0,
        marks: [0; 8],
        marked: 0,
    };
    assert!(
        LAYOUT_TRACE
            .with(|trace| trace.replace(Some(start)))
            .is_none()
    );
    let reset = Reset;
    let output = operation();
    let trace = LAYOUT_TRACE.with(Cell::get).expect("active layout trace");
    drop(reset);
    (output, trace)
}

/// Record the running count of an active layout trace at one phase boundary.
pub(crate) fn mark_layout_trace() {
    let _ = LAYOUT_TRACE.try_with(|trace| {
        if let Some(mut current) = trace.get() {
            if let Some(mark) = current.marks.get_mut(current.marked) {
                *mark = current.seen;
            }
            current.marked += 1;
            trace.set(Some(current));
        }
    });
}

/// Refuse the `occurrence`-th (zero-based) allocation of exactly `layout` on this
/// thread while `operation` runs, reporting whether that allocation was reached.
pub(crate) fn refuse_layout_during<R>(
    layout: Layout,
    occurrence: usize,
    operation: impl FnOnce() -> R,
) -> (R, bool) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            REFUSE.with(|refuse| refuse.set(None));
        }
    }
    assert!(
        REFUSE
            .with(|refuse| refuse.replace(Some((layout, occurrence))))
            .is_none()
    );
    let reset = Reset;
    let output = operation();
    let reached = REFUSE.with(Cell::get).is_none();
    drop(reset);
    (output, reached)
}

#[derive(Default)]
pub(crate) struct WakeCount(pub(crate) AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, SeqCst);
    }
}

pub(crate) fn poll(
    wait: &mut iroha_allocation::release::ReleaseFuture<'_>,
    wakes: &Arc<WakeCount>,
) -> Poll<()> {
    Pin::new(wait).poll(&mut Context::from_waker(&Waker::from(Arc::clone(wakes))))
}

pub(crate) fn capacity_wait(
    error: AllocationRefusal,
    registration: &mut iroha_allocation::release::ReleaseRegistration,
) -> iroha_allocation::release::ReleaseFuture<'_> {
    let AllocationRefusal::Capacity { release, .. } = error else {
        panic!("expected temporary capacity refusal: {error}");
    };
    release.wait_for_release(registration)
}

pub(crate) fn layout(size: usize) -> Layout {
    Layout::from_size_align(size, 1).unwrap()
}
