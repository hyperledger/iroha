//! Real bounded native output allocation denial, canonical parity and cache retry.
//!
//! Only the selected thread's exact byte allocation is denied, once per scope.
//! No production hook, exhaustion workload or invented pool notification is used.

use iroha_plonk::verification_attempt::{
    NativeVerifierInitError, VerificationAttemptError, VerificationRefusal, VerificationRefusalKind,
};
use norito::core::{BoundedEncodeError, DecodeFlagsGuard, DecodeLimits};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    sync::{Mutex, OnceLock},
};

// Compile the exact internal producer/cache implementation, not a test imitation.
mod native_pipa_r {
    pub use iroha_core_zk::native_pipa_r::{CompiledVerifyingKeyV1, MAX_KEY_BYTES};
}
#[path = "../src/native_key_carrier.rs"]
mod native_key_carrier;
use native_pipa_r::{CompiledVerifyingKeyV1, MAX_KEY_BYTES};

#[derive(Clone, Copy, Default)]
struct Denial {
    bytes: usize,
    armed: bool,
    refused: usize,
}

thread_local! {
    static DENIAL: Cell<Denial> = const { Cell::new(Denial {
        bytes: 0, armed: false, refused: 0,
    }) };
}

struct ScopedAllocator;

fn refuse(bytes: usize, align: usize) -> bool {
    DENIAL
        .try_with(|slot| {
            let mut state = slot.get();
            if state.armed && state.bytes == bytes && align == 1 {
                state.armed = false;
                state.refused += 1;
                slot.set(state);
                true
            } else {
                false
            }
        })
        .unwrap_or(false)
}

#[global_allocator]
static ALLOCATOR: ScopedAllocator = ScopedAllocator;

// SAFETY: unchanged System ownership/layout is used for every non-denied request;
// a denied request returns null before allocating. Denial state is thread-local,
// allocation-free and disabled before assertions or error formatting.
#[allow(unsafe_code)]
unsafe impl GlobalAlloc for ScopedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if refuse(layout.size(), layout.align()) {
            return core::ptr::null_mut();
        }
        // SAFETY: forward the original valid layout unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if refuse(layout.size(), layout.align()) {
            return core::ptr::null_mut();
        }
        // SAFETY: forward the original valid zeroed request unchanged.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: successful requests all came from System with this layout.
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, bytes: usize) -> *mut u8 {
        if refuse(bytes, layout.align()) {
            return core::ptr::null_mut();
        }
        // SAFETY: preserve original System allocation and requested new size.
        unsafe { System.realloc(pointer, layout, bytes) }
    }
}

struct DenialGuard(Denial);

impl Drop for DenialGuard {
    fn drop(&mut self) {
        DENIAL.with(|slot| slot.set(self.0));
    }
}

fn denying<T>(bytes: usize, operation: impl FnOnce() -> T) -> (T, usize) {
    assert!(bytes > 0 && bytes <= MAX_KEY_BYTES);
    let guard = DenialGuard(DENIAL.with(|slot| {
        slot.replace(Denial {
            bytes,
            armed: true,
            refused: 0,
        })
    }));
    let result = operation();
    let refused = DENIAL.with(|slot| slot.get().refused);
    drop(guard);
    (result, refused)
}

fn owned(descriptor: &[u8], key: &[u8]) -> CompiledVerifyingKeyV1 {
    CompiledVerifyingKeyV1 {
        descriptor: descriptor.to_vec(),
        key: key.to_vec(),
    }
}

fn assert_original_allocation(owner: &VerificationRefusal, expected: usize) {
    assert_eq!(
        owner.kind(),
        VerificationRefusalKind::InitializationUnavailable
    );
    assert!(owner.decode_refusal().is_none());
    assert!(owner.native_verification_error().is_none());
    assert!(matches!(owner.initialization_error(),
        Some(NativeVerifierInitError::Encoding(BoundedEncodeError::AllocationFailed { bytes }))
        if *bytes == expected));
    let initialization = std::error::Error::source(owner).unwrap();
    assert!(
        initialization
            .downcast_ref::<NativeVerifierInitError>()
            .is_some()
    );
    assert!(
        matches!(initialization.source().unwrap().downcast_ref::<BoundedEncodeError>(),
        Some(BoundedEncodeError::AllocationFailed { bytes }) if *bytes == expected)
    );
}

#[test]
fn borrowed_key_frames_match_owned_canonical_bytes_and_restore_flags() {
    for (descriptor_len, key_len) in [(0, 0), (1, 7), (127, 128), (255, 8193)] {
        let descriptor = vec![0x35; descriptor_len];
        let key = vec![0xac; key_len];
        let carrier = owned(&descriptor, &key);
        let expected = norito::encode_canonical(&carrier).unwrap();
        for ambient in [0, norito::core::header_flags::COMPACT_LEN] {
            let _flags = DecodeFlagsGuard::enter(ambient);
            let actual = native_key_carrier::encode(&descriptor, &key).unwrap();
            // Complete equality covers schema hash, padding, flags, length, checksum and payload.
            assert_eq!(actual, expected);
            assert_eq!(norito::core::effective_decode_flags(), Some(ambient));
            assert_eq!(
                norito::decode_canonical::<CompiledVerifyingKeyV1>(&actual).unwrap(),
                carrier
            );
        }
    }
}

#[test]
fn complete_public_cap_is_checked_before_output_allocation() {
    // Find the boundary from actual canonical counting, without assuming header/length overhead.
    let key = vec![0x71; MAX_KEY_BYTES];
    let mut low = 0;
    let mut high = key.len();
    while low < high {
        let middle = low + (high - low).div_ceil(2);
        if norito::encode_canonical(&owned(&[], &key[..middle]))
            .unwrap()
            .len()
            <= MAX_KEY_BYTES
        {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    let admitted = norito::encode_canonical(&owned(&[], &key[..low])).unwrap();
    assert_eq!(admitted.len(), MAX_KEY_BYTES);
    assert_eq!(
        native_key_carrier::encode(&[], &key[..low]).unwrap(),
        admitted
    );
    let over = norito::encode_canonical(&owned(&[], &key[..=low])).unwrap();
    let (error, refusals) = denying(MAX_KEY_BYTES, || {
        native_key_carrier::encode(&[], &key[..=low])
    });
    assert_eq!(refusals, 0);
    let owner = VerificationRefusal::initialization(error.unwrap_err());
    assert_eq!(
        owner.kind(),
        VerificationRefusalKind::LocalInvariantViolation
    );
    assert!(matches!(owner.initialization_error(),
        Some(NativeVerifierInitError::Encoding(BoundedEncodeError::FrameTooLarge { encoded_bytes, max_bytes }))
        if *encoded_bytes == over.len() && *max_bytes == MAX_KEY_BYTES));
}

#[test]
fn exact_native_cache_helper_keeps_denied_original_and_publishes_only_retry() {
    let descriptor = [0x39; 131];
    let key = [0xa4; 257];
    let expected = norito::encode_canonical(&owned(&descriptor, &key)).unwrap();
    let cache = OnceLock::new();
    let gate = Mutex::new(());
    let (attempt, refusals) = denying(expected.len(), || {
        native_key_carrier::cached_success(
            &cache,
            &gate,
            || native_key_carrier::encode(&descriptor, &key),
            NativeVerifierInitError::CachePoisoned,
        )
    });
    assert_eq!(refusals, 1);
    assert!(cache.get().is_none());
    assert!(!gate.is_poisoned());
    let owner = VerificationRefusal::initialization(attempt.unwrap_err());
    assert_original_allocation(&owner, expected.len());
    let owner = owner.into_decode_refusal().unwrap_err();
    assert_original_allocation(&owner, expected.len());
    let ready = native_key_carrier::cached_success(
        &cache,
        &gate,
        || native_key_carrier::encode(&descriptor, &key),
        NativeVerifierInitError::CachePoisoned,
    )
    .unwrap();
    assert_eq!(*ready, expected);
    let again = native_key_carrier::cached_success(
        &cache,
        &gate,
        || -> Result<Vec<u8>, _> { panic!("successful cache was reconstructed") },
        NativeVerifierInitError::CachePoisoned,
    )
    .unwrap();
    assert!(core::ptr::eq(ready, again));
    assert_original_allocation(&owner, expected.len());
}

#[test]
fn original_scoped_output_cause_survives_retirement_without_fake_decode_projection() {
    let limits = DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
    let original = norito::with_decode_limits_scope(limits, || {
        native_key_carrier::encode(b"descriptor", b"key")
    })
    .unwrap_err();
    let NativeVerifierInitError::Encoding(BoundedEncodeError::Serialization(
        norito::Error::ScopedDecodeResource(scope),
    )) = &original
    else {
        panic!("actual scoped output reservation owner was not retained");
    };
    let expected_scope = scope.clone();
    let owner = VerificationRefusal::initialization(original);
    assert_eq!(
        owner.kind(),
        VerificationRefusalKind::InitializationUnavailable
    );
    assert!(owner.decode_refusal().is_none());
    let owner = owner.into_decode_refusal().unwrap_err();
    let Some(NativeVerifierInitError::Encoding(BoundedEncodeError::Serialization(
        norito::Error::ScopedDecodeResource(retained),
    ))) = owner.initialization_error()
    else {
        panic!("lost original bounded writer scope");
    };
    assert_eq!(retained, &expected_scope);
    let other = norito::with_decode_limits_scope(limits, || {
        native_key_carrier::encode(b"descriptor", b"key")
    })
    .unwrap_err();
    let NativeVerifierInitError::Encoding(BoundedEncodeError::Serialization(
        norito::Error::ScopedDecodeResource(foreign),
    )) = other
    else {
        panic!("missing independent scoped refusal");
    };
    assert_ne!(&foreign, retained);
    assert!(native_key_carrier::encode(b"descriptor", b"key").is_ok());
}

#[test]
fn actual_kaigi_cache_does_not_publish_denied_output_and_retries_same_material() {
    use iroha_core_zk::native_pipa_r::{
        BACKEND, NativeRelationV1, kaigi_verifying_key, validate_key,
    };
    use kaigi_zk::native::NativeRelationV1 as KaigiRelation;
    let kind = KaigiRelation::Usage;
    // Key-graph initialization is deliberately outside denial. This test qualifies the
    // complete carrier output/cache path, not all allocations in native key construction.
    let verifier = kind.verifier().unwrap();
    let expected =
        norito::encode_canonical(&owned(verifier.descriptor_bytes(), verifier.key_bytes()))
            .unwrap();
    for _ in 0..2 {
        let (attempt, refusals) = denying(expected.len(), || kaigi_verifying_key(kind));
        assert_eq!(refusals, 1);
        let VerificationAttemptError::Deferred(owner) = attempt.unwrap_err() else {
            panic!("native output denial became a proof rejection");
        };
        assert_original_allocation(&owner, expected.len());
    }
    let ready = kaigi_verifying_key(kind).unwrap();
    assert_eq!(ready.bytes, expected);
    // Authenticating the existing cache does not clone a caller-owned output Vec.
    let (cached, refusals) = denying(expected.len(), || {
        validate_key(BACKEND, kind.circuit_id(), &ready)
    });
    assert_eq!(refusals, 0);
    assert_eq!(cached.unwrap(), NativeRelationV1::KaigiUsage);
}
