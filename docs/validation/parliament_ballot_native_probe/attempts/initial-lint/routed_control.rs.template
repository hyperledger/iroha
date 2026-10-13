//! Fresh-process controls for routed versus direct-System/TLS allocation.

use super::*;
use std::{alloc::GlobalAlloc, cell::RefCell};
thread_local! { static PROBE_TLS: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) }; }

struct Control {
    kind: u64,
}
extern "C" fn control(argument: *mut libc::c_void) -> *mut libc::c_void {
    // SAFETY: run keeps the control alive until join.
    let request = unsafe { &*argument.cast::<Control>() };
    crate::observer::begin();
    ACTIVE.store(true, Ordering::Release);
    match request.kind {
        0 => {}
        1 => {
            let value = Box::new([0x5au8; 4096]);
            std::hint::black_box(&*value);
            drop(value);
        }
        2 => {
            let layout = Layout::from_size_align(4096, 16).unwrap();
            // SAFETY: exact nonzero layout, checked pointer, same-layout release.
            unsafe {
                let pointer = System.alloc(layout);
                if pointer.is_null() {
                    libc::_exit(76);
                }
                pointer.write_volatile(0x5a);
                std::hint::black_box(pointer);
                System.dealloc(pointer, layout);
            }
        }
        3 => {
            std::hint::black_box(std::thread::current());
        }
        4 => {
            PROBE_TLS.with(|slot| *slot.borrow_mut() = Some(vec![0x5a; 4096]));
        }
        5 => panic!("native observer deliberate panic control"),
        _ => unsafe { libc::_exit(76) },
    }
    ACTIVE.store(false, Ordering::Release);
    crate::observer::end();
    ptr::null_mut()
}

/// Run one calibration on the actual arena and native stack, then join cleanup.
pub fn run(kind: u64) -> Result<usize, native::NativeError> {
    if INVOKED.swap(true, Ordering::AcqRel) {
        return Err(native::NativeError("repeated_control", 0));
    }
    let mapping = native::Mapping::new(HEAP_BYTES)?;
    if ARENA
        .compare_exchange(
            ptr::null_mut(),
            mapping.arena(),
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return Err(native::NativeError("control_concurrency", 0));
    }
    let mut request = Control { kind };
    // SAFETY: request and mapping outlive the joined callback; no unwind crosses C.
    let joined = unsafe { mapping.run(control, ptr::from_mut(&mut request).cast()) };
    let stats = unsafe { &*mapping.arena() }.stats();
    if stats.live_blocks != 0 {
        unsafe { libc::_exit(74) };
    }
    // Same pointer-provenance lifetime policy as the frozen one-call worker.
    std::mem::forget(mapping);
    joined?;
    Ok(stats.allocations)
}
