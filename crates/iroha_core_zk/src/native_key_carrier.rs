//! Borrowed canonical native key output and success-only material publication.

use crate::native_pipa_r::{CompiledVerifyingKeyV1, MAX_KEY_BYTES};
use iroha_plonk::verification_attempt::NativeVerifierInitError;
use norito::NoritoSchema;
use std::sync::{Mutex, OnceLock};

// Byte slices have the same field serialization as the owned Vec<u8> fields.
// The frame explicitly projects to the one public carrier identity; its borrowed
// nominal identity remains distinct and never enters the registry.
#[derive(norito::Encode)]
struct BorrowedKeyCarrier<'a> {
    descriptor: &'a [u8],
    key: &'a [u8],
}

// Root padding is defined by the original carrier's archived payload alignment.
const _: () = assert!(
    norito::core::archived_payload_align::<BorrowedKeyCarrier<'static>>()
        == norito::core::archived_payload_align::<CompiledVerifyingKeyV1>()
);

impl NoritoSchema for BorrowedKeyCarrier<'_> {
    fn nominal_name() -> String {
        Self::static_nominal_name()
            .expect("declared literal")
            .to_owned()
    }

    fn static_nominal_name() -> Option<&'static str> {
        Some("iroha_core_zk::native_key_carrier::BorrowedKeyCarrier<'_>")
    }

    fn frame_name() -> String {
        CompiledVerifyingKeyV1::frame_name()
    }

    fn static_frame_name() -> Option<&'static str> {
        CompiledVerifyingKeyV1::static_frame_name()
    }
}

/// Encode already constructed native components under their complete public registry bound.
///
/// Both passes borrow the original components. The bounded writer reserves its exact output
/// once and retains either the actual null-allocation error or its original scoped refusal.
/// This does not qualify earlier descriptor/key construction or later caller-owned copies.
pub fn encode(descriptor: &[u8], key: &[u8]) -> Result<Vec<u8>, NativeVerifierInitError> {
    let _canonical = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    // The existing observer also supports checked writers. Its callback cannot fail:
    // keep the bounded result nested so even a scoped serialization failure remains
    // the original BoundedEncodeError, never a fabricated DecodeLocalRefusal.
    norito::core::classify_decode_attempt(|| {
        Ok(norito::core::to_bytes_bounded(
            &BorrowedKeyCarrier { descriptor, key },
            MAX_KEY_BYTES,
        ))
    })
    .expect("checked-writer observer callback is infallible")
    .map_err(NativeVerifierInitError::Encoding)
}

/// Publish only successful immutable material and serialize first construction.
///
/// A failed attempt returns its original error and leaves the cache empty for a later retry.
/// The second cache lookup prevents concurrent callers from constructing duplicate key graphs.
pub fn cached_success<'a, T, E>(
    cache: &'a OnceLock<T>,
    gate: &Mutex<()>,
    initialize: impl FnOnce() -> Result<T, E>,
    poisoned: E,
) -> Result<&'a T, E> {
    if let Some(ready) = cache.get() {
        return Ok(ready);
    }
    let _guard = gate.lock().map_err(|_| poisoned)?;
    if let Some(ready) = cache.get() {
        return Ok(ready);
    }
    let ready = initialize()?;
    Ok(cache.get_or_init(|| ready))
}
