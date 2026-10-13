//! Fresh-process recorder controls, included inside the derived workspace.

use super::*;
use crate::trace;
use std::alloc::{alloc, dealloc, realloc};

struct Control {
    kind: u64,
    okay: bool,
}

extern "C" fn control(argument: *mut libc::c_void) -> *mut libc::c_void {
    // SAFETY: run retains exclusive access to this request through join.
    let request = unsafe { &mut *argument.cast::<Control>() };
    trace::begin();
    ACTIVE.store(true, Ordering::Release);
    request.okay = match request.kind {
        0 => true,
        1 => allocation_control(false),
        2 => allocation_control(true),
        3 => {
            // CAPACITY records fit; the next pair must invalidate, not wrap.
            for _ in 0..=trace::CAPACITY / 2 {
                if !allocation_control(false) {
                    request.okay = false;
                    ACTIVE.store(false, Ordering::Release);
                    trace::end();
                    return ptr::null_mut();
                }
            }
            true
        }
        4 => {
            trace::collision_control();
            true
        }
        _ => false,
    };
    ACTIVE.store(false, Ordering::Release);
    trace::end();
    ptr::null_mut()
}

fn allocation_control(grow: bool) -> bool {
    let layout = Layout::from_size_align(73, 16).expect("constant layout");
    // SAFETY: valid layouts; nonzero allocations are checked, and release uses
    // the current allocation layout. Volatile accesses prevent dead-work removal.
    unsafe {
        let pointer = alloc(layout);
        if pointer.is_null() {
            return false;
        }
        pointer.write_volatile(0xa5);
        pointer.add(72).write_volatile(0x5a);
        std::hint::black_box(pointer);
        if !grow {
            let okay = pointer.read_volatile() == 0xa5 && pointer.add(72).read_volatile() == 0x5a;
            dealloc(pointer, layout);
            return okay;
        }
        let grown = realloc(pointer, layout, 257);
        if grown.is_null() {
            dealloc(pointer, layout);
            return false;
        }
        let okay = grown.read_volatile() == 0xa5 && grown.add(72).read_volatile() == 0x5a;
        grown.add(256).write_volatile(0x33);
        std::hint::black_box(grown);
        dealloc(
            grown,
            Layout::from_size_align(257, 16).expect("constant layout"),
        );
        okay
    }
}

/// Run an empty/routed/realloc/overflow/collision calibration on the actual arena.
/// The intentional last two controls must subsequently produce invalid traces.
pub fn run(kind: u64) -> Result<usize, native::NativeError> {
    if kind > 4 || INVOKED.swap(true, Ordering::AcqRel) {
        return Err(native::NativeError("invalid_or_repeated_trace_control", 0));
    }
    let mapping = native::Mapping::new(HEAP_BYTES)?;
    // Mapping::arena is the full mapping base in the pinned native source;
    // the heap begins immediately after its fixed control partition.
    trace::set_base(
        mapping
            .arena()
            .cast::<u8>()
            .wrapping_add(native::CONTROL_BYTES),
    );
    if ARENA
        .compare_exchange(
            ptr::null_mut(),
            mapping.arena(),
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return Err(native::NativeError("trace_control_concurrency", 0));
    }
    let mut request = Control { kind, okay: false };
    // SAFETY: callback, request and mapping remain live until successful join.
    let joined = unsafe { mapping.run(control, ptr::from_mut(&mut request).cast()) };
    let stats = unsafe { &*mapping.arena() }.stats();
    if stats.live_blocks != 0 || stats.live_requested != 0 {
        unsafe { libc::_exit(74) };
    }
    // After publication, never unmap while another allocator might hold ARENA.
    std::mem::forget(mapping);
    joined?;
    if !request.okay {
        return Err(native::NativeError("trace_control_data_or_kind", 0));
    }
    Ok(stats.allocations)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_control_checks_initial_and_reallocated_bytes() {
        // Global arena is unarmed in the test harness. Full stream controls run
        // as fresh child processes, since the real arena permits one invocation.
        assert!(allocation_control(false));
        assert!(allocation_control(true));
    }
}
