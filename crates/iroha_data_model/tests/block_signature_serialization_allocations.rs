//! Wire-parity and allocation regressions for block-signature serialization.
// This isolated integration test is the narrow exception that needs `GlobalAlloc`
// to observe steady-state heap traffic in the production serialization path.
#![allow(unsafe_code)]

use iroha_crypto::{Signature, SignatureOf};
use iroha_data_model::block::{BlockHeader, BlockSignature, header::wire::BlockSignatureWire};
use norito::core::{DecodeFlagsGuard, Encoder, SerializePayload, header_flags};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};
struct TrackingAllocator;
thread_local! {
    static TRACKING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static REFUSE: Cell<Option<Layout>> = const { Cell::new(None) };
    static REFUSE_SKIP_MATCHES: Cell<usize> = const { Cell::new(0) };
}
#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;
fn record_allocation() {
    TRACKING.with(|tracking| {
        if tracking.get() {
            ALLOCATIONS.with(|allocations| allocations.set(allocations.get() + 1));
        }
    });
}
unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        if REFUSE
            .try_with(|next| {
                if next.get() == Some(layout) {
                    REFUSE_SKIP_MATCHES.with(|skip| {
                        if skip.get() == 0 {
                            next.set(None);
                            true
                        } else {
                            skip.set(skip.get() - 1);
                            false
                        }
                    })
                } else {
                    false
                }
            })
            .unwrap_or(false)
        {
            return std::ptr::null_mut();
        }
        // SAFETY: the allocation request is delegated unchanged to `System`.
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        // SAFETY: the allocation request is delegated unchanged to `System`.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` and `layout` came from the matching `System` allocation.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record_allocation();
        // SAFETY: the original allocation and the resized request are forwarded to `System`.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}
fn allocations_during(operation: impl FnOnce()) -> usize {
    TRACKING.with(|tracking| tracking.set(false));
    ALLOCATIONS.with(|allocations| allocations.set(0));
    TRACKING.with(|tracking| tracking.set(true));
    operation();
    TRACKING.with(|tracking| tracking.set(false));
    ALLOCATIONS.with(Cell::get)
}
fn bare_bytes(value: &dyn SerializePayload, flags: u8) -> Vec<u8> {
    let _guard = DecodeFlagsGuard::enter(flags);
    let exact = value
        .encoded_len_exact()
        .expect("block-signature fixture must have an exact length");
    let mut output = Vec::with_capacity(exact);
    let mut encoder = Encoder::for_buffer(&mut output);
    value.serialize(&mut encoder).expect("serialize fixture");
    assert_eq!(output.len(), exact);
    output
}
#[test]
fn borrowed_block_signature_codec_preserves_tuple_wire_bytes() {
    const FLAGS: [u8; 2] = [0, header_flags::COMPACT_LEN];
    let cases = [
        ("empty", Vec::new()),
        ("small", vec![0x11, 0xA5, 0x7F]),
        ("large", vec![0xC3; 64 * 1024]),
    ];
    for (label, payload) in cases {
        let index = 0x1122_3344_5566_7788;
        let signature = BlockSignature::new(
            index,
            SignatureOf::<BlockHeader>::from_signature(Signature::from_bytes(&payload)),
        );
        let wire = BlockSignatureWire(index, payload.clone());
        for flags in FLAGS {
            let expected = bare_bytes(&(index, payload.clone()), flags);
            assert_eq!(
                bare_bytes(&signature, flags),
                expected,
                "BlockSignature wire changed for {label} payload and flags {flags:#04x}",
            );
            assert_eq!(
                bare_bytes(&wire, flags),
                expected,
                "BlockSignatureWire wire changed for {label} payload and flags {flags:#04x}",
            );
        }
    }
}
fn assert_preallocated_serialization_does_not_allocate(value: &dyn SerializePayload) {
    let flags = header_flags::COMPACT_LEN;
    let _guard = DecodeFlagsGuard::enter(flags);
    let exact = value
        .encoded_len_exact()
        .expect("block signature must have an exact wire length");
    let mut output = Vec::with_capacity(exact);
    // Initialize serializer and thread-local state before measuring the steady-state path.
    {
        let mut encoder = Encoder::for_buffer(&mut output);
        value.serialize(&mut encoder).expect("warm serialization");
    }
    assert_eq!(output.len(), exact);
    output.clear();
    assert_eq!(value.encoded_len_exact(), Some(exact));
    let allocations = allocations_during(|| {
        assert_eq!(value.encoded_len_exact(), Some(exact));
        let mut encoder = Encoder::for_buffer(&mut output);
        value
            .serialize(&mut encoder)
            .expect("measured serialization");
    });
    assert_eq!(output.len(), exact);
    assert_eq!(allocations, 0, "exact sizing and serialization allocated");
}
#[test]
fn large_block_signature_streams_without_payload_scratch() {
    let index = 42;
    let payload = vec![0xA7; 1024 * 1024];
    let signature = BlockSignature::new(
        index,
        SignatureOf::<BlockHeader>::from_signature(Signature::from_bytes(&payload)),
    );
    let wire = BlockSignatureWire(index, payload);
    assert_preallocated_serialization_does_not_allocate(&signature);
    assert_preallocated_serialization_does_not_allocate(&wire);
}

#[path = "block_signature_serialization_allocations/certificate_custody.rs"]
mod certificate_custody;

#[path = "block_signature_serialization_allocations/da_policy_custody.rs"]
mod da_policy_custody;

#[path = "block_signature_serialization_allocations/da_commitment_custody.rs"]
mod da_commitment_custody;

#[path = "block_signature_serialization_allocations/pulse_inline_custody.rs"]
mod pulse_inline_custody;

#[path = "block_signature_serialization_allocations/header_inline_custody.rs"]
mod header_inline_custody;

#[path = "block_signature_serialization_allocations/evidence_codec_custody.rs"]
mod evidence_codec_custody;
