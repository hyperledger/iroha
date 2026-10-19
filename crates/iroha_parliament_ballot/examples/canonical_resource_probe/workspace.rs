//! One-shot canonical-input native worker; owned inputs and all verifier drops are charged.
//!
//! Default allocations route through the reused fixed arena only while ACTIVE. The
//! driver performs no concurrent work during the synchronous raw-pthread invocation.
//! Direct System/TLS/native behavior remains outside this routing guarantee.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    ptr,
    sync::atomic::{AtomicBool, AtomicPtr, Ordering},
};

use iroha_data_model::{NetworkId, governance::types::BodyInstanceId};
use norito::json::JsonSerialize;

use super::{
    arena::{Arena, HEAP_BYTES},
    budget::{Budget, Charge},
    fatal, hook_scope, native,
    verify::{self, Outcome},
};

static ARENA: AtomicPtr<Arena> = AtomicPtr::new(ptr::null_mut());
static INVOKED: AtomicBool = AtomicBool::new(false);
static ACTIVE: AtomicBool = AtomicBool::new(false);

struct Routed;

// SAFETY: before/after the one joined worker default allocation uses System.
// While ACTIVE, a live published mapping serves every default allocation with no
// fallback. Frees dispatch by address provenance even after ACTIVE is cleared.
unsafe impl GlobalAlloc for Routed {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ACTIVE.load(Ordering::Acquire) {
            let arena = ARENA.load(Ordering::Acquire);
            if arena.is_null() {
                unsafe { libc::_exit(74) };
            }
            let pointer = unsafe { &*arena }.allocate(layout);
            if pointer.is_null() {
                fatal::exhausted();
            }
            pointer
        } else {
            unsafe { System.alloc(layout) }
        }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let arena = ARENA.load(Ordering::Acquire);
        if !arena.is_null() && unsafe { &*arena }.contains(pointer) {
            unsafe { (&*arena).release(pointer, layout) };
        } else {
            unsafe { System.dealloc(pointer, layout) };
        }
    }
}

#[global_allocator]
static ALLOCATOR: Routed = Routed;

#[derive(Clone, Copy)]
pub struct Options<'a> {
    pub envelope: &'a [u8],
    pub context: &'a [u8],
    pub network: NetworkId,
    pub body: BodyInstanceId,
    pub heap_limit: usize,
    pub units: u64,
    pub input_bytes: u64,
}

#[derive(Clone, Copy)]
struct ResultState {
    outcome: Outcome,
    charge: Charge,
}

impl ResultState {
    const fn uncharged(outcome: Outcome) -> Self {
        Self {
            outcome,
            charge: Charge { units: 0, bytes: 0 },
        }
    }
}

struct Request {
    envelope: *const u8,
    envelope_length: usize,
    context: *const u8,
    context_length: usize,
    network: NetworkId,
    body: BodyInstanceId,
    units: u64,
    input_bytes: u64,
    stack: *mut u8,
    result: ResultState,
}

#[derive(Debug, JsonSerialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct Report {
    pub outcome: &'static str,
    pub verifier_stage: &'static str,
    pub charged_units: u64,
    pub charged_bytes: u64,
    pub envelope_bytes: usize,
    pub context_bytes: usize,
    pub heap_reserved_bytes: usize,
    pub metadata_reserved_bytes: usize,
    pub stack_usable_bytes: usize,
    pub guard_bytes: usize,
    pub control_reserved_bytes: usize,
    pub fatal_control_reserved_bytes: usize,
    pub workspace_reserved_bytes: usize,
    pub heap_limit_bytes: usize,
    pub arena_peak_block_bytes: usize,
    pub arena_peak_requested_bytes: usize,
    pub arena_live_exit_block_bytes: usize,
    pub arena_live_exit_requested_bytes: usize,
    pub arena_allocations: usize,
    pub arena_enforced: bool,
    pub validity_only: bool,
    pub protocol_effect: bool,
    pub acceleration_identity_external: bool,
    pub complete_workspace_certificate: bool,
    pub profile_qualified: bool,
}

/// Borrow both staged owners until synchronous join; no arena value may escape.
pub fn run(options: Options<'_>) -> Result<(Report, i32), native::NativeError> {
    if INVOKED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(native::NativeError("repeated_invocation", 0));
    }
    if options.heap_limit > HEAP_BYTES {
        return Err(native::NativeError("heap_limit", 0));
    }
    let fatal_bytes = fatal::reserved_bytes().map_err(|e| native::NativeError(e.0, e.1))?;
    if std::mem::size_of::<Arena>() > 4096
        || std::mem::size_of::<Request>() > native::CONTROL_BYTES - 4096
        || std::mem::align_of::<Request>() > 4096
    {
        return Err(native::NativeError("control_layout", 0));
    }
    let mapping = native::Mapping::new(options.heap_limit)?;
    let total = counted_workspace(mapping.length(), fatal_bytes)
        .ok_or(native::NativeError("workspace_partition", 0))?;
    #[allow(clippy::cast_ptr_alignment)]
    let request = mapping.control().cast::<Request>();
    // SAFETY: the mapping's aligned control region holds this fixed-size request.
    // Both raw pointer/length pairs come from the same borrow, live until run returns.
    unsafe {
        request.write(Request {
            envelope: options.envelope.as_ptr(),
            envelope_length: options.envelope.len(),
            context: options.context.as_ptr(),
            context_length: options.context.len(),
            network: options.network,
            body: options.body,
            units: options.units,
            input_bytes: options.input_bytes,
            stack: mapping.stack(),
            result: ResultState::uncharged(Outcome::unavailable("not_started")),
        });
    }
    if ARENA
        .compare_exchange(
            ptr::null_mut(),
            mapping.arena(),
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return Err(native::NativeError("concurrent_invocation", 0));
    }
    // SAFETY: callback cannot unwind across C; request, borrowed owners and supplied
    // stack remain live until join. Join failure exits the child instead of returning.
    let joined = unsafe { mapping.run(worker, request.cast()) };
    ACTIVE.store(false, Ordering::Release);
    let stats = unsafe { &*mapping.arena() }.stats();
    if stats.live_blocks != 0 || stats.live_requested != 0 {
        // A surviving arena owner is not an invalid ballot. End this diagnostic child.
        unsafe { libc::_exit(74) };
    }
    let guard_bytes = mapping.guard_bytes();
    // The published pointer may already have been read by a deallocator. Retain the
    // one-shot mapping until process exit rather than unmap without a hazard protocol.
    std::mem::forget(mapping);
    joined?;
    let result = unsafe { (*request).result };
    Ok((
        Report {
            outcome: result.outcome.outcome,
            verifier_stage: result.outcome.stage,
            charged_units: result.charge.units,
            charged_bytes: result.charge.bytes,
            envelope_bytes: options.envelope.len(),
            context_bytes: options.context.len(),
            heap_reserved_bytes: HEAP_BYTES,
            metadata_reserved_bytes: native::METADATA_BYTES,
            stack_usable_bytes: native::STACK_BYTES,
            guard_bytes,
            control_reserved_bytes: native::CONTROL_BYTES,
            fatal_control_reserved_bytes: fatal_bytes,
            workspace_reserved_bytes: total,
            heap_limit_bytes: options.heap_limit,
            arena_peak_block_bytes: stats.peak_blocks,
            arena_peak_requested_bytes: stats.peak_requested,
            arena_live_exit_block_bytes: stats.live_blocks,
            arena_live_exit_requested_bytes: stats.live_requested,
            arena_allocations: stats.allocations,
            arena_enforced: true,
            validity_only: true,
            protocol_effect: false,
            acceleration_identity_external: true,
            complete_workspace_certificate: false,
            profile_qualified: false,
        },
        result.outcome.exit,
    ))
}

fn counted_workspace(mapping: usize, fatal: usize) -> Option<usize> {
    mapping
        .checked_add(fatal)
        .filter(|sum| *sum <= native::WORKSPACE_LIMIT)
}

extern "C" fn worker(argument: *mut libc::c_void) -> *mut libc::c_void {
    // SAFETY: run supplies an exclusive Request in the retained control region.
    let request = unsafe { &mut *argument.cast::<Request>() };
    if !native::current_stack()
        .is_ok_and(|(base, size)| base == request.stack && size == native::STACK_BYTES)
    {
        request.result = ResultState::uncharged(Outcome::unavailable("native_stack_mismatch"));
        return ptr::null_mut();
    }
    request.result = execute(request);
    // Both copies, decoded inputs, context, Arc and all result/error owners ended in
    // execute. Native TLS teardown is not silently covered by the routing assertion.
    ACTIVE.store(false, Ordering::Release);
    ptr::null_mut()
}

fn execute(request: &Request) -> ResultState {
    let mut budget = Budget::new(request.units, request.input_bytes);
    let reservation = match budget.reserve(request.envelope_length, request.context_length) {
        Ok(reservation) => reservation,
        Err(reason) => {
            return ResultState::uncharged(Outcome::new("admission_rejected", reason.stage(), 2));
        }
    };
    let charge = reservation.charge();
    fatal::admit(charge.units, charge.bytes);
    ACTIVE.store(true, Ordering::Release);
    // SAFETY: paired pointers/lengths originate in immutable live caller borrows.
    // Lengths are independently capped before either allocation or slice access.
    let envelope =
        unsafe { std::slice::from_raw_parts(request.envelope, request.envelope_length) }.to_vec();
    let context =
        unsafe { std::slice::from_raw_parts(request.context, request.context_length) }.to_vec();
    let outcome = match reservation.consume(&envelope, &context) {
        Ok(_) => {
            hook_scope::run(|| verify::cold(&envelope, &context, request.network, request.body))
                .unwrap_or_else(|()| Outcome::unavailable("verification_panic"))
        }
        Err(_) => Outcome::unavailable("input_length"),
    };
    // Explicit drops keep the complete owned-input lifetime inside ACTIVE.
    drop(context);
    drop(envelope);
    ResultState { outcome, charge }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fatal_page_is_part_of_checked_workspace_sum() {
        let ordinary =
            native::CONTROL_BYTES + HEAP_BYTES + native::METADATA_BYTES + native::STACK_BYTES;
        for page in [4096, 16384, 65536] {
            assert_eq!(
                counted_workspace(ordinary + 2 * page, page),
                Some(ordinary + 3 * page)
            );
        }
        assert_eq!(counted_workspace(native::WORKSPACE_LIMIT, 1), None);
        assert_eq!(counted_workspace(usize::MAX, 1), None);
    }

    #[test]
    fn request_fits_counted_control_and_initial_state_has_no_debit() {
        assert!(std::mem::size_of::<Request>() <= native::CONTROL_BYTES - 4096);
        assert!(std::mem::align_of::<Request>() <= 4096);
        let state = ResultState::uncharged(Outcome::unavailable("not_started"));
        assert_eq!(state.charge, Charge { units: 0, bytes: 0 });
        assert_eq!(state.outcome.exit, 4);
    }
}
