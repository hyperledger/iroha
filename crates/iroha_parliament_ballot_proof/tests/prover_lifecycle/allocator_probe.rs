//! Observation of selected, still-live buffers immediately before System
//! deallocation. Callbacks perform no explicit Rust allocations; native TLS
//! setup may allocate separately and is not measured here.
//! Test fixture bytes only; no freed-memory reads.
//! The witness-allocation pause is a test scheduling barrier, not a prover hook.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

/// Serialize tests that use these four fixed observation slots.
pub static SERIAL: Mutex<()> = Mutex::new(());

/// The selected owned allocation.
#[derive(Clone, Copy)]
pub enum Buffer {
    Secret = 0,
    Tape = 1,
    Witness = 2,
    Proof = 3,
}

struct Slot {
    pointer: AtomicUsize,
    length: AtomicUsize,
    released: AtomicBool,
    zero: AtomicBool,
}

impl Slot {
    const fn new() -> Self {
        Self {
            pointer: AtomicUsize::new(0),
            length: AtomicUsize::new(0),
            released: AtomicBool::new(false),
            zero: AtomicBool::new(false),
        }
    }
}

static SLOTS: [Slot; 4] = [const { Slot::new() }; 4];
static REACHED: AtomicBool = AtomicBool::new(false);
static RELEASE: AtomicBool = AtomicBool::new(false);
thread_local! { static WITNESS_SIZE: Cell<usize> = const { Cell::new(0) }; }

/// Pass-through allocator with no allocating or unwinding observation path.
pub struct ProbeAllocator;

#[global_allocator]
static ALLOCATOR: ProbeAllocator = ProbeAllocator;

unsafe impl GlobalAlloc for ProbeAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: preserve the GlobalAlloc caller's layout contract.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: preserve the GlobalAlloc caller's layout contract.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            // SAFETY: System::alloc_zeroed returned this initialized, live
            // range for the requested nonzero GlobalAlloc layout.
            let bytes = unsafe { std::slice::from_raw_parts(pointer, layout.size()) };
            observe_zeroed_allocation(bytes, layout.align());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        for slot in &SLOTS {
            if slot
                .pointer
                .compare_exchange(pointer as usize, 0, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                let length = slot.length.load(Ordering::Acquire);
                let mut zero = length <= layout.size();
                if zero {
                    for offset in 0..length {
                        // SAFETY: the tracked initialized range is bounded by
                        // this still-live allocation. No read follows dealloc.
                        zero &= unsafe { pointer.add(offset).read_volatile() } == 0;
                    }
                }
                slot.zero.store(zero, Ordering::Relaxed);
                slot.released.store(true, Ordering::Release);
            }
        }
        // SAFETY: delegate the original pointer and layout exactly once.
        unsafe { System.dealloc(pointer, layout) };
    }

    // The default realloc uses this allocator's alloc/copy/dealloc. None of the
    // selected final-size owners reallocates; an unexpected realloc is seen as
    // an early release and fails zeroization assertions.
}

fn observe_zeroed_allocation(bytes: &[u8], alignment: usize) {
    let selected = WITNESS_SIZE
        .try_with(|size| {
            if size.get() != 0 && size.get() == bytes.len() && alignment == 1 {
                size.set(0);
                true
            } else {
                false
            }
        })
        .unwrap_or(false);
    if selected {
        track(Buffer::Witness, bytes);
        REACHED.store(true, Ordering::Release);
        while !RELEASE.load(Ordering::Acquire) {
            std::hint::spin_loop();
        }
    }
}

/// Register the exact initialized allocation range, before its owner drops.
pub fn track(buffer: Buffer, bytes: &[u8]) {
    let slot = &SLOTS[buffer as usize];
    slot.length.store(bytes.len(), Ordering::Relaxed);
    slot.pointer
        .store(bytes.as_ptr() as usize, Ordering::Release);
}

/// Clear slots while the previous test's selected owners are all gone.
pub fn reset() {
    for slot in &SLOTS {
        assert_eq!(
            slot.pointer.load(Ordering::Acquire),
            0,
            "live tracked owner"
        );
        slot.length.store(0, Ordering::Relaxed);
        slot.released.store(false, Ordering::Relaxed);
        slot.zero.store(false, Ordering::Relaxed);
    }
    REACHED.store(false, Ordering::Relaxed);
    RELEASE.store(false, Ordering::Relaxed);
}

/// Arm only this worker, immediately before the real proving call. At S=3,
/// profile and statement construction have no allocation of this size. The
/// selected 4480/6688-byte allocation is `build_witness`'s final-size zeroed Vec
/// (src/proving.rs), before that witness buffer is populated. The vote prover
/// may already have copied the pad to its stack; stack erasure is not observed.
pub fn arm_witness(bytes: usize) {
    WITNESS_SIZE.set(bytes);
}

/// Release on ordinary scope exit, including assertion unwinding in test mode.
/// This avoids a test assertion leaving a joining worker parked at the probe.
pub struct ReleaseGuard;
impl Drop for ReleaseGuard {
    fn drop(&mut self) {
        release();
    }
}

/// Wait for an actual in-prover allocation; timeout fails instead of treating
/// elapsed time as proof that computation started.
pub fn wait_for_witness() -> bool {
    let started = Instant::now();
    while !REACHED.load(Ordering::Acquire) {
        if started.elapsed() > Duration::from_secs(30) {
            return false;
        }
        std::thread::yield_now();
    }
    true
}

/// Let the real synchronous prover continue after cancellation is requested.
pub fn release() {
    RELEASE.store(true, Ordering::Release);
}

/// Require release of exactly the tracked range with every byte zero.
pub fn assert_erased(buffer: Buffer, length: usize) {
    let slot = &SLOTS[buffer as usize];
    assert_eq!(slot.length.load(Ordering::Acquire), length);
    assert!(
        slot.released.load(Ordering::Acquire),
        "selected allocation not released"
    );
    assert!(
        slot.zero.load(Ordering::Acquire),
        "selected allocation not all zero before release"
    );
    assert_eq!(slot.pointer.load(Ordering::Acquire), 0);
}

/// Require that no proof buffer has been observed, such as after an error.
pub fn assert_no_proof() {
    assert_eq!(
        SLOTS[Buffer::Proof as usize].length.load(Ordering::Acquire),
        0
    );
}

/// Calibration: require release with at least one nonzero byte observed.
pub fn assert_not_erased(buffer: Buffer) {
    let slot = &SLOTS[buffer as usize];
    assert!(slot.released.load(Ordering::Acquire));
    assert!(!slot.zero.load(Ordering::Acquire));
    assert_eq!(slot.pointer.load(Ordering::Acquire), 0);
}

/// Require the selected owner is still live at a scheduling checkpoint.
pub fn assert_live(buffer: Buffer) {
    assert_ne!(SLOTS[buffer as usize].pointer.load(Ordering::Acquire), 0);
    assert!(!SLOTS[buffer as usize].released.load(Ordering::Acquire));
}
