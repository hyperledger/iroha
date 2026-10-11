//! Norito serialization framework.
//!
//! Provides deterministic serialization and zero-copy deserialization for common Rust data
//! structures. Derive macros are always available through [`norito::derive`].
//!
//! Layout selection
//! - Norito primarily uses an Array-of-Structs (AoS) layout via derives.
//! - For some homogeneous sequences we expose an adaptive API that can choose a
//!   columnar layout internally for better cache locality and size. See
//!   `norito::columnar` adaptive helpers. For small inputs (AoS path), those
//!   helpers use compact, ad-hoc AoS formats that honor runtime decode flags
//!   (`COMPACT_LEN` varints when enabled; u64 otherwise).
//!
//! Checksum: payloads carry a CRC64-XZ checksum (ECMA polynomial `0x42F0E1EBA9EA3693`, reflected
//! with init/xor all ones) computed using the `crc64fast` crate. [`hardware_crc64`] enables the
//! SIMD-accelerated path when available, while [`crc64_fallback`] forces the portable table
//! implementation.
//!
//! V1 layout selection
//! - Header-framed decoders (`deserialize_stream`, `decode_from_bytes`,
//!   `decode_from_reader`) validate the Norito header, require the fixed v1
//!   minor (`VERSION_MINOR = 0x00`), and apply the header flag byte as the
//!   authoritative layout selection (unknown bits are rejected). Bare,
//!   headerless decoders (`codec::Decode`) are internal-only for hashing/bench
//!   scenarios and use the fixed v1 default flags.
//! - V1 has exactly two layouts: `COMPACT_LEN` (`0x02`, default) and
//!   fixed-width per-value prefixes (`0x00`). Every other header bit is
//!   rejected. Sequence count headers are always fixed `u64`.
//!
//! Helpers
//! - [`SerializePayload`] owns object-safe bare serialization and size hints.
//!   Borrowed field adapters can derive this contract without a frame identity.
//!   [`NoritoSerialize`] adds the typed frame contract used by framed encoders.
//! - [`encode_canonical`], [`decode_canonical`], and
//!   [`decode_canonical_with_limits`] provide exact uncompressed V1 boundaries
//!   with payload-derived decode budgets and byte-for-byte re-encoding checks.
//! - `norito::core::frame_bare_with_header_flags<T>(payload, flags)` prefixes a
//!   headerless (“bare”) payload with a Norito header that exactly matches the
//!   supplied layout flags. `norito::codec::encode_with_header_flags(value)`
//!   returns both the bare payload and the recorded flags so callers can persist
//!   the metadata alongside the bytes without relying on thread-local state.
mod norito_mutation_guard;

extern crate self as norito;
use std::{
    alloc::{Layout, alloc, dealloc},
    cell::Cell,
    collections::{BTreeMap, HashMap},
    io::{Read, Write},
    ptr,
    sync::OnceLock,
};
// std imported selectively where needed
pub mod aos;
pub mod columnar;
pub mod core;
pub mod schema;
pub use schema::identity::NoritoSchema;
pub mod streaming;
pub use core::{
    Archived, ArchivedBox, Compression, CompressionConfig, DecodeLimits, DeserializePayload,
    Encoder, Error, NoritoDeserialize, NoritoSerialize, SerializePayload, crc64_fallback,
    default_encode_flags, from_bytes, from_compressed_bytes, hardware_crc64, to_bytes,
    to_bytes_auto, to_bytes_in, to_compressed_bytes, with_decode_limits, with_decode_limits_scope,
};
#[doc(hidden)]
pub use core::{SequencePlan, SequenceSpan, plan_binary_sequence};
struct ArchiveSlice {
    ptr: *mut u8,
    len: usize,
    layout: Option<Layout>,
}
impl ArchiveSlice {
    fn new_owned(src: &[u8], align: usize) -> Result<Self, Error> {
        let align = align.max(1);
        if src.is_empty() {
            return Ok(Self {
                ptr: align as *mut u8,
                len: 0,
                layout: None,
            });
        }
        let layout =
            Layout::from_size_align(src.len(), align).map_err(|_| Error::LengthMismatch)?;
        core::reserve_decode_allocation(src.len())?;
        unsafe {
            let ptr = alloc(layout);
            if ptr.is_null() {
                return Err(Error::AllocationFailed {
                    bytes: u64::try_from(src.len()).unwrap_or(u64::MAX),
                });
            }
            ptr::copy_nonoverlapping(src.as_ptr(), ptr, src.len());
            Ok(Self {
                ptr,
                len: src.len(),
                layout: Some(layout),
            })
        }
    }
    fn new(src: &[u8], align: usize) -> Result<Self, Error> {
        if src.is_empty() {
            Ok(Self {
                ptr: align.max(1) as *mut u8,
                len: 0,
                layout: None,
            })
        } else if align <= 1 || (src.as_ptr() as usize).is_multiple_of(align) {
            Ok(Self {
                ptr: src.as_ptr() as *mut u8,
                len: src.len(),
                layout: None,
            })
        } else {
            Self::new_owned(src, align)
        }
    }
    fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr as *const u8, self.len) }
    }
}
impl Drop for ArchiveSlice {
    fn drop(&mut self) {
        if let Some(layout) = self.layout {
            unsafe {
                dealloc(self.ptr, layout);
            }
        }
    }
}
#[doc(hidden)]
#[inline]
pub fn debug_trace_enabled() -> bool {
    // Environment-based trace toggles are limited to debug/test builds; release
    // builds ignore the flag to keep runtime behaviour config-driven.
    #[cfg(test)]
    {
        std::env::var_os("NORITO_TRACE").is_some()
    }
    #[cfg(all(debug_assertions, not(test)))]
    {
        static ENABLED: OnceLock<bool> = OnceLock::new();
        *ENABLED.get_or_init(|| std::env::var_os("NORITO_TRACE").is_some())
    }
    #[cfg(not(any(test, debug_assertions)))]
    {
        false
    }
}
mod debug_trace;
pub use debug_trace::trace_struct_decode;
#[cfg(test)]
mod trace_tests {
    use super::debug_trace_enabled;
    use std::env;
    #[test]
    fn debug_trace_follows_env_flag() {
        let env_enabled = env::var_os("NORITO_TRACE").is_some();
        assert_eq!(debug_trace_enabled(), env_enabled);
    }
}
// Re-export selected JSON traits at the crate root for convenience
pub use self::json::FastJsonWrite;
pub mod yaml;
pub mod derive {
    pub use norito_derive::{
        Decode, DeserializePayload, Encode, FastJson, FastJsonWrite, JsonDeserialize,
        JsonSerialize, NoritoDeserialize, NoritoSchema, NoritoSerialize, SerializePayload,
    };
}
pub use derive::*;
/// Bare Norito `Encode` and `Decode` traits used for compact payloads without a Norito header.
pub mod codec {
    pub use super::Error;
    use super::{DeserializePayload, SerializePayload, core};
    pub use crate::derive::{Decode, Encode};
    use std::io::{Read, Write};
    struct CountingWriter<'a, W: Write> {
        inner: &'a mut W,
        bytes_written: usize,
    }
    impl<'a, W: Write> CountingWriter<'a, W> {
        fn new(inner: &'a mut W) -> Self {
            Self {
                inner,
                bytes_written: 0,
            }
        }
        fn bytes_written(&self) -> usize {
            self.bytes_written
        }
    }
    impl<W: Write> Write for CountingWriter<'_, W> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let written = self.inner.write(buf)?;
            self.bytes_written = self.bytes_written.saturating_add(written);
            Ok(written)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }
    /// Encode values into bytes using Norito.
    pub trait Encode: SerializePayload + Sized {
        /// Encode `self` into a new `Vec<u8>` without compression.
        ///
        /// Uses the fixed v1 bare layout (no adaptive layout flags).
        fn encode(&self) -> Vec<u8> {
            encode_adaptive(self)
        }
        /// Encode `self` into the given writer without compression.
        fn encode_to<W: Write>(&self, writer: &mut W) {
            encode_adaptive_into(self, writer).expect("encoding should not fail");
        }
        /// Return the encoded length for `self` without allocating a buffer.
        fn encoded_len(&self) -> usize {
            let mut sink = std::io::sink();
            encode_adaptive_into(self, &mut sink).expect("encoding should not fail")
        }
    }
    impl<T: SerializePayload + Sized> Encode for T {}
    /// Input stream for decoding.
    pub trait Input: Read {}
    impl<T: Read> Input for T {}
    /// Decode values from a byte stream produced by [`Encode`].
    pub trait Decode: for<'de> DeserializePayload<'de> + SerializePayload + Sized {
        /// Attempt to decode `Self` from the given input.
        fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
            // Ensure a clean thread-local decode state for headerless payloads.
            core::reset_decode_state();
            let mut buf = Vec::new();
            input.read_to_end(&mut buf)?;
            decode_adaptive::<Self>(&buf)
        }
    }
    impl<T> Decode for T where T: for<'de> DeserializePayload<'de> + SerializePayload + Sized {}
    /// Bare encode using the fixed v1 layout flags.
    pub fn encode_adaptive<T: SerializePayload>(value: &T) -> Vec<u8> {
        encode_adaptive_with_flags(value, core::default_encode_flags())
    }
    fn encode_adaptive_with_flags<T: SerializePayload>(value: &T, flags: u8) -> Vec<u8> {
        core::validate_header_flags(flags).expect("adaptive encode flags must be supported");
        #[cfg(debug_assertions)]
        if crate::debug_trace_enabled() {
            eprintln!("norito.codec.encode_adaptive: flags=0x{flags:02x}");
        }
        let _flags = core::DecodeFlagsGuard::enter(flags);
        let (payload, _final_flags) =
            core::encode_bare_with_flags(value).expect("bare Norito encoding should succeed");
        #[cfg(debug_assertions)]
        if crate::debug_trace_enabled() {
            eprintln!("norito.codec.encode_adaptive: final_flags=0x{_final_flags:02x}");
        }
        payload
    }
    /// Bare encode into the provided writer using the fixed v1 layout flags.
    ///
    /// Returns the number of payload bytes written.
    pub fn encode_adaptive_into<T: SerializePayload, W: Write>(
        value: &T,
        writer: &mut W,
    ) -> Result<usize, Error> {
        encode_adaptive_into_with_flags(value, writer, core::default_encode_flags())
    }
    fn encode_adaptive_into_with_flags<T: SerializePayload, W: Write>(
        value: &T,
        writer: &mut W,
        flags: u8,
    ) -> Result<usize, Error> {
        core::validate_header_flags(flags)?;
        #[cfg(debug_assertions)]
        if crate::debug_trace_enabled() {
            eprintln!("norito.codec.encode_adaptive_into: flags=0x{flags:02x}");
        }
        let mut counting = CountingWriter::new(writer);
        {
            let _fg = core::DecodeFlagsGuard::enter(flags);
            let mut encoder = core::Encoder::new(&mut counting);
            SerializePayload::serialize(value, &mut encoder)?;
        }
        let payload_len = counting.bytes_written();
        Ok(payload_len)
    }
    /// Verify that a value emits exactly the supplied fixed V1 bare payload.
    ///
    /// The comparison borrows the original bytes and streams serialization over
    /// them without allocating another output buffer. It uses the same fixed
    /// layout as [`Encode::encode`] and preserves the surrounding encode context.
    /// Custom serializers remain responsible for any allocations they perform.
    ///
    /// # Errors
    /// Returns [`Error::NonCanonicalEncoding`] for changed bytes, an overrun, or
    /// an unconsumed suffix. Serializer errors are preserved when no byte mismatch
    /// occurred.
    pub fn verify_exact_payload<T: SerializePayload>(
        value: &T,
        expected: &[u8],
    ) -> Result<(), Error> {
        let _context = core::EncodeContextGuard::enter();
        let mut exact = core::ExactSliceWriter::new(expected);
        let result = encode_adaptive_into(value, &mut exact);
        if exact.mismatched() {
            return Err(Error::NonCanonicalEncoding);
        }
        result?;
        if !exact.is_complete() {
            return Err(Error::NonCanonicalEncoding);
        }
        Ok(())
    }
    #[cfg(test)]
    #[allow(clippy::items_after_test_module)]
    mod encode_tests {
        use super::Encode;
        use crate::SerializePayload;
        use std::sync::atomic::{AtomicUsize, Ordering};
        static HINT_CALLS: AtomicUsize = AtomicUsize::new(0);
        static EXACT_CALLS: AtomicUsize = AtomicUsize::new(0);
        #[derive(Clone, Copy)]
        struct Hinted(u8);

        impl SerializePayload for Hinted {
            fn serialize(
                &self,
                encoder: &mut crate::core::Encoder<'_>,
            ) -> Result<(), crate::Error> {
                encoder.write_all(&[self.0])?;
                Ok(())
            }
            fn encoded_len_hint(&self) -> Option<usize> {
                HINT_CALLS.fetch_add(1, Ordering::Relaxed);
                Some(1)
            }
            fn encoded_len_exact(&self) -> Option<usize> {
                None
            }
        }
        struct ExactLenOnly(u8);

        impl SerializePayload for ExactLenOnly {
            fn serialize(
                &self,
                encoder: &mut crate::core::Encoder<'_>,
            ) -> Result<(), crate::Error> {
                encoder.write_all(&[self.0])?;
                Ok(())
            }
            fn encoded_len_exact(&self) -> Option<usize> {
                EXACT_CALLS.fetch_add(1, Ordering::Relaxed);
                Some(1)
            }
        }
        struct HugeHint(u8);

        impl SerializePayload for HugeHint {
            fn serialize(
                &self,
                encoder: &mut crate::core::Encoder<'_>,
            ) -> Result<(), crate::Error> {
                encoder.write_all(&[self.0])?;
                Ok(())
            }
            fn encoded_len_hint(&self) -> Option<usize> {
                Some(usize::MAX)
            }
        }
        struct AlwaysFails;

        impl SerializePayload for AlwaysFails {
            fn serialize(
                &self,
                _encoder: &mut crate::core::Encoder<'_>,
            ) -> Result<(), crate::Error> {
                Err(crate::Error::Message(
                    "intentional serializer failure".into(),
                ))
            }
        }
        #[test]
        fn encode_to_matches_encode() {
            let value = vec![1u8, 2, 3, 4, 5];
            let bytes = value.encode();
            let mut out = Vec::new();
            value.encode_to(&mut out);
            assert_eq!(bytes, out);
        }
        #[test]
        fn encoded_len_matches_encoded_bytes() {
            let value = (42u32, vec![7u8, 8, 9]);
            let bytes = value.encode();
            assert_eq!(value.encoded_len(), bytes.len());
        }
        #[test]
        fn encoded_len_counts_serialized_bytes_instead_of_trusting_exact_len() {
            EXACT_CALLS.store(0, Ordering::Relaxed);
            let value = ExactLenOnly(7);
            assert_eq!(value.encoded_len(), 1);
            assert_eq!(EXACT_CALLS.load(Ordering::Relaxed), 0);
        }
        #[test]
        fn seq_encoding_does_not_trust_length_hints() {
            HINT_CALLS.store(0, Ordering::Relaxed);
            let items = vec![Hinted(1), Hinted(2), Hinted(3)];
            assert_eq!(items.encode().last(), Some(&3));
            assert_eq!(HINT_CALLS.load(Ordering::Relaxed), 0);
        }
        #[test]
        fn huge_length_hint_is_capped_before_reservation() {
            assert_eq!(HugeHint(9).encode(), vec![9]);
        }
        #[test]
        fn exact_bare_payload_verifier_checks_every_byte_and_complete_length() {
            let value = (42_u32, vec!["first".to_owned(), "second".to_owned()]);
            let original = value.encode();
            super::verify_exact_payload(&value, &original).unwrap();
            let mut changed = original.clone();
            *changed.last_mut().unwrap() ^= 1;
            assert!(matches!(
                super::verify_exact_payload(&value, &changed),
                Err(crate::Error::NonCanonicalEncoding)
            ));
            assert!(matches!(
                super::verify_exact_payload(&value, &original[..original.len() - 1]),
                Err(crate::Error::NonCanonicalEncoding)
            ));
            let mut extended = original.clone();
            extended.push(0);
            assert!(matches!(
                super::verify_exact_payload(&value, &extended),
                Err(crate::Error::NonCanonicalEncoding)
            ));
            super::verify_exact_payload(&(), &[]).unwrap();
        }
        #[test]
        fn exact_bare_payload_verifier_preserves_ambient_flags_and_encode_context() {
            let value = vec![1_u8, 2, 3];
            let original = value.encode();
            let alternate =
                crate::core::default_encode_flags() ^ crate::core::header_flags::COMPACT_LEN;
            let _flags = crate::core::DecodeFlagsGuard::enter(alternate);
            let _context = crate::core::EncodeContextGuard::enter();
            crate::core::note_compact_len_emitted();
            super::verify_exact_payload(&value, &original).unwrap();
            assert_eq!(crate::core::effective_decode_flags(), Some(alternate));
            assert!(crate::core::compact_len_used());
            assert!(super::verify_exact_payload(&value, &[]).is_err());
            assert_eq!(crate::core::effective_decode_flags(), Some(alternate));
            assert!(crate::core::compact_len_used());
        }
        #[test]
        fn exact_bare_payload_verifier_preserves_original_serializer_errors() {
            let error = super::verify_exact_payload(&AlwaysFails, b"remaining")
                .expect_err("serializer failure is not an observed byte mismatch");
            assert!(matches!(
                error,
                crate::Error::Message(message) if message == "intentional serializer failure"
            ));
        }
        #[test]
        fn adaptive_writer_propagates_serializer_errors() {
            let mut out = Vec::new();
            let error = super::encode_adaptive_into(&AlwaysFails, &mut out)
                .expect_err("fallible writer API must propagate serializer errors");
            assert!(
                matches!(error, crate::Error::Message(message) if message == "intentional serializer failure")
            );
            assert!(out.is_empty());
        }
    }
    /// Encode `value` and return both the bare payload and the exact header flags required
    /// to frame it for header-based decoding.
    pub fn encode_with_header_flags<T: SerializePayload>(value: &T) -> (Vec<u8>, u8) {
        let (payload, flags) =
            core::encode_bare_with_flags(value).expect("encode_with_header_flags should succeed");
        (payload, flags)
    }
    /// Bare decode using the fixed v1 layout flags.
    pub fn decode_adaptive<T>(bytes: &[u8]) -> Result<T, Error>
    where
        T: for<'de> DeserializePayload<'de> + SerializePayload,
    {
        core::reset_decode_state();
        let flags = core::default_encode_flags();
        if crate::debug_trace_enabled() {
            eprintln!(
                "norito.codec.decode_adaptive: len={} align={} ptr={:?}",
                bytes.len(),
                core::archived_payload_align::<T>(),
                bytes.as_ptr()
            );
        }
        let _reset = DecodeResetGuard;
        let _flags = core::DecodeFlagsGuard::enter(flags);
        crate::with_decode_limits(crate::canonical_decode_limits(bytes.len()), || {
            super::decode_payload_exact(bytes)
        })
    }
    /// Bare decode from an exact slice using a type-provided slice decoder.
    ///
    /// Unlike [`Decode::decode`], this avoids copying when the caller already has the full payload
    /// in memory. The type's [`core::DecodeFromSlice`] implementation must prove that all bytes are
    /// consumed. Payload-derived resource limits are always active, so an encoded sequence length
    /// cannot request more elements or allocation than the complete input can justify.
    pub fn decode_exact_from_slice<T>(bytes: &[u8]) -> Result<T, Error>
    where
        T: for<'de> DeserializePayload<'de> + for<'de> core::DecodeFromSlice<'de>,
    {
        core::reset_decode_state();
        let _reset = DecodeResetGuard;
        crate::with_decode_limits(crate::canonical_decode_limits(bytes.len()), || {
            decode_exact_from_slice_under_active_limits(bytes)
        })
    }
    /// Bare decode from an exact slice under additional schema-specific limits.
    ///
    /// The caller-provided limits compose with the payload-derived defaults by taking the stricter
    /// bound in every dimension. This lets protocol boundaries constrain their exact maximum vector
    /// counts without losing the generic allocation-bomb protection.
    pub fn decode_exact_from_slice_with_limits<T>(
        bytes: &[u8],
        limits: crate::DecodeLimits,
    ) -> Result<T, Error>
    where
        T: for<'de> DeserializePayload<'de> + for<'de> core::DecodeFromSlice<'de>,
    {
        core::reset_decode_state();
        let _reset = DecodeResetGuard;
        crate::with_decode_limits(crate::canonical_decode_limits(bytes.len()), || {
            crate::with_decode_limits(limits, || {
                decode_exact_from_slice_under_active_limits(bytes)
            })
        })
    }
    fn decode_exact_from_slice_under_active_limits<T>(bytes: &[u8]) -> Result<T, Error>
    where
        T: for<'de> DeserializePayload<'de> + for<'de> core::DecodeFromSlice<'de>,
    {
        let (value, used) = core::decode_field_canonical_from_slice::<T>(bytes)?;
        if used != bytes.len() {
            return Err(Error::LengthMismatch);
        }
        Ok(value)
    }
    struct DecodeResetGuard;
    impl Drop for DecodeResetGuard {
        fn drop(&mut self) {
            crate::core::reset_decode_state();
        }
    }
    /// Decode values ensuring the input contains no trailing bytes.
    pub trait DecodeAll: Decode {
        /// Decode `Self` from `input` verifying that the entire stream is consumed.
        fn decode_all<I: Input>(input: &mut I) -> Result<Self, Error> {
            // The bare decoder enforces exact payload consumption.
            <Self as Decode>::decode(input)
        }
    }
    impl<T: Decode> DecodeAll for T {}
}
/// Telemetry helpers aggregating Norito metrics for easy ingestion.
pub mod telemetry {
    /// Reset all Norito telemetry buckets (columnar and compression).
    /// Intended for examples/benches/tests.
    pub fn reset_all() {
        crate::columnar::adaptive_metrics_reset();
        crate::core::compression_metrics_reset();
    }
    /// Build a compact JSON value aggregating columnar and compression telemetry.
    pub fn snapshot_json_value() -> crate::json::Value {
        let mut root = crate::json::Map::new();
        root.insert(
            "columnar".into(),
            crate::columnar::adaptive_metrics_json_value(),
        );
        root.insert(
            "compression".into(),
            crate::core::compression_metrics_json_value(),
        );
        crate::json::Value::Object(root)
    }
    /// Serialize the aggregated telemetry snapshot into a compact JSON string.
    pub fn snapshot_json_string() -> String {
        let v = snapshot_json_value();
        crate::json::to_string(&v).unwrap_or_else(|_| String::from("{}"))
    }
    /// JSON: compute fieldwise delta for the aggregated telemetry map.
    pub fn snapshot_delta_json(
        prev: &crate::json::Value,
        curr: &crate::json::Value,
    ) -> crate::json::Value {
        use crate::json::Value;
        let mut out = crate::json::Map::new();
        let empty = crate::json::Map::new();
        let p = prev.as_object().unwrap_or(&empty);
        let c = curr.as_object().unwrap_or(&empty);
        out.insert(
            "columnar".into(),
            crate::columnar::adaptive_metrics_delta_json(
                p.get("columnar").unwrap_or(&Value::Null),
                c.get("columnar").unwrap_or(&Value::Null),
            ),
        );
        out.insert(
            "compression".into(),
            crate::core::compression_metrics_delta_json(
                p.get("compression").unwrap_or(&Value::Null),
                c.get("compression").unwrap_or(&Value::Null),
            ),
        );
        Value::Object(out)
    }
}
/// Minimal JSON serialization/deserialization helpers without `serde`.
///
/// This module implements a compact JSON writer and a simple, recursive-descent
/// parser that covers a subset of JSON sufficient for benchmarking and common
/// Norito demos: numbers (integers and simple floats), booleans, strings with
/// escaping, `null`, arrays, and user-defined objects via manual trait impls.
///
/// Types implement [`JsonSerialize`] and/or [`JsonDeserialize`] to participate
/// in the JSON codec. Container impls are provided for `Option<T>` and
/// `Vec<T>`. Object encoding/decoding is done in user code by writing keys and
/// dispatching field decoders with the [`json::Parser`]. For zero‑copy streaming,
/// use the token [`json::Reader`] and convert borrowed string slices into owned
/// `String`s with [`json::unescape_json_string`] when needed.
///
/// Notes and limitations:
/// - The token `Reader` yields borrowed string slices without unescaping; users
///   should parse/unescape as needed.
/// - Unicode escapes (`\uXXXX`) are decoded to Unicode scalars, including
///   surrogate pairs (two `\u` sequences representing one code point) which are
///   combined into a single character when valid.
/// - Leading zeros in numbers are rejected to match JSON rules.
/// - Number parsing is conservative and aims for correctness over breadth for
///   benchmarking scenarios.
pub mod json {
    use std::cell::Cell;
    use url::Url;
    mod exact_string;
    mod key_codec;
    mod key_hash;
    pub use super::{
        JsonDeserialize as Deserialize, JsonDeserialize, JsonSerialize as Serialize, JsonSerialize,
    };
    pub use key_codec::JsonKeyCodec;
    /// Maximum structural nesting accepted while constructing a JSON [`Value`].
    ///
    /// The extra structural level covers a required boundary envelope around a value at the
    /// codec's recursively owned value limit. Kotodama's larger logical type budget uses a flat
    /// node tape and therefore does not consume one JSON parser frame per logical type level.
    pub const MAX_JSON_VALUE_NESTING_DEPTH: usize = crate::core::MAX_VALUE_NESTING_DEPTH + 1;
    thread_local! {
        static OWNED_VALUE_DECODE_DEPTH: Cell<usize> = const { Cell::new(0) };
    }
    struct OwnedValueDecodeDepthGuard;
    impl OwnedValueDecodeDepthGuard {
        fn enter() -> Result<Self, Error> {
            OWNED_VALUE_DECODE_DEPTH.with(|depth| {
                let next = depth.get().saturating_add(1);
                if next > crate::core::MAX_VALUE_NESTING_DEPTH {
                    return Err(Error::NestingDepthExceeded {
                        depth: next,
                        limit: crate::core::MAX_VALUE_NESTING_DEPTH,
                        context: "owned JSON value",
                    });
                }
                depth.set(next);
                Ok(Self)
            })
        }
    }
    impl Drop for OwnedValueDecodeDepthGuard {
        fn drop(&mut self) {
            OWNED_VALUE_DECODE_DEPTH.with(|depth| {
                debug_assert!(depth.get() > 0, "owned JSON decode depth underflow");
                depth.set(depth.get().saturating_sub(1));
            });
        }
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum UnexpectedToken {
        Char(char),
        Eof,
    }
    impl std::fmt::Display for UnexpectedToken {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                UnexpectedToken::Char(c) => write!(f, "character `{c}`"),
                UnexpectedToken::Eof => write!(f, "end of input"),
            }
        }
    }
    // Dedicated error type for Norito JSON helpers (parser/writer/tape).
    #[derive(Debug, thiserror::Error, Clone)]
    pub enum Error {
        #[error("JSON error: {msg} at byte {byte} (line {line}, col {col})")]
        WithPos {
            msg: &'static str,
            byte: usize,
            line: usize,
            col: usize,
        },
        #[error("JSON error: unexpected {found} at byte {byte} (line {line}, col {col})")]
        UnexpectedCharacter {
            found: UnexpectedToken,
            byte: usize,
            line: usize,
            col: usize,
        },
        #[error("JSON error: expected digits at byte {byte} (line {line}, col {col})")]
        ExpectedDigits {
            byte: usize,
            line: usize,
            col: usize,
        },
        #[error("JSON error: expected frac digits at byte {byte} (line {line}, col {col})")]
        ExpectedFracDigits {
            byte: usize,
            line: usize,
            col: usize,
        },
        #[error("JSON error: expected exp digits at byte {byte} (line {line}, col {col})")]
        ExpectedExpDigits {
            byte: usize,
            line: usize,
            col: usize,
        },
        #[error("JSON error: unexpected value at byte {byte} (line {line}, col {col})")]
        UnexpectedValue {
            byte: usize,
            line: usize,
            col: usize,
        },
        #[error("JSON error: unexpected quote at byte {byte} (line {line}, col {col})")]
        UnexpectedQuote {
            byte: usize,
            line: usize,
            col: usize,
        },
        #[error("JSON error: unexpected comma at byte {byte} (line {line}, col {col})")]
        UnexpectedComma {
            byte: usize,
            line: usize,
            col: usize,
        },
        #[error("JSON error: unexpected ':' at byte {byte} (line {line}, col {col})")]
        UnexpectedColon {
            byte: usize,
            line: usize,
            col: usize,
        },
        #[error("JSON error: unexpected object end at byte {byte} (line {line}, col {col})")]
        UnexpectedObjectEnd {
            byte: usize,
            line: usize,
            col: usize,
        },
        #[error("JSON error: unexpected array end at byte {byte} (line {line}, col {col})")]
        UnexpectedArrayEnd {
            byte: usize,
            line: usize,
            col: usize,
        },
        #[error("JSON error: u64 overflow at byte {byte} (line {line}, col {col})")]
        U64Overflow {
            byte: usize,
            line: usize,
            col: usize,
        },
        #[error("JSON error: unterminated string at byte {byte} (line {line}, col {col})")]
        UnterminatedString {
            byte: usize,
            line: usize,
            col: usize,
        },
        #[error("JSON error: unexpected eof at byte {byte} (line {line}, col {col})")]
        UnexpectedEof {
            byte: usize,
            line: usize,
            col: usize,
        },
        #[error("JSON error: eof escape at byte {byte} (line {line}, col {col})")]
        EofEscape {
            byte: usize,
            line: usize,
            col: usize,
        },
        #[error("JSON error: eof hex at byte {byte} (line {line}, col {col})")]
        EofHex {
            byte: usize,
            line: usize,
            col: usize,
        },
        #[error("JSON error: invalid hex at byte {byte} (line {line}, col {col})")]
        InvalidHex {
            byte: usize,
            line: usize,
            col: usize,
        },
        #[error("JSON error: control in string at byte {byte} (line {line}, col {col})")]
        ControlInString {
            byte: usize,
            line: usize,
            col: usize,
        },
        #[error("JSON error: expected null at byte {byte} (line {line}, col {col})")]
        ExpectedNull {
            byte: usize,
            line: usize,
            col: usize,
        },
        #[error("JSON error: expected bool at byte {byte} (line {line}, col {col})")]
        ExpectedBool {
            byte: usize,
            line: usize,
            col: usize,
        },
        #[error("JSON error: trailing characters at byte {byte} (line {line}, col {col})")]
        TrailingCharacters {
            byte: usize,
            line: usize,
            col: usize,
        },
        #[error("JSON error: expected object start at byte {byte} (line {line}, col {col})")]
        ExpectedObjectStart {
            byte: usize,
            line: usize,
            col: usize,
        },
        #[error("JSON error: expected object end at byte {byte} (line {line}, col {col})")]
        ExpectedObjectEnd {
            byte: usize,
            line: usize,
            col: usize,
        },
        #[error("JSON error: expected array start at byte {byte} (line {line}, col {col})")]
        ExpectedArrayStart {
            byte: usize,
            line: usize,
            col: usize,
        },
        #[error("JSON error: expected array end at byte {byte} (line {line}, col {col})")]
        ExpectedArrayEnd {
            byte: usize,
            line: usize,
            col: usize,
        },
        #[error("JSON error: expected key string at byte {byte} (line {line}, col {col})")]
        ExpectedKeyString {
            byte: usize,
            line: usize,
            col: usize,
        },
        #[error("JSON error: expected key quote at byte {byte} (line {line}, col {col})")]
        ExpectedKeyHashQuote {
            byte: usize,
            line: usize,
            col: usize,
        },
        #[error("JSON error: unterminated key at byte {byte} (line {line}, col {col})")]
        UnterminatedKey {
            byte: usize,
            line: usize,
            col: usize,
        },
        #[error("JSON error: expected ':' at byte {byte} (line {line}, col {col})")]
        ExpectedColon {
            byte: usize,
            line: usize,
            col: usize,
        },
        #[error("JSON error: expected , or ] at byte {byte} (line {line}, col {col})")]
        ExpectedCommaOrArrayEnd {
            byte: usize,
            line: usize,
            col: usize,
        },
        #[error("JSON error: expected , or }} at byte {byte} (line {line}, col {col})")]
        ExpectedCommaOrObjectEnd {
            byte: usize,
            line: usize,
            col: usize,
        },
        #[error("JSON error: invalid field `{field}`: {message}")]
        InvalidField { field: String, message: String },
        #[error("JSON error: missing field `{field}`")]
        MissingField { field: String },
        #[error("JSON error: unknown field `{field}`")]
        UnknownField { field: String },
        #[error("JSON error: duplicate field `{field}`")]
        DuplicateField { field: String },
        #[error("{context} nesting depth {depth} exceeds limit {limit}")]
        NestingDepthExceeded {
            depth: usize,
            limit: usize,
            context: &'static str,
        },
        /// A checked bound or resource owner refused work without recorded decoder fields.
        #[error("JSON decode resource limit exceeded")]
        DecodeResourceLimit,
        /// Exact unscoped binary decoder resource fields, without observer provenance.
        #[error(transparent)]
        DecodeResource(crate::core::DecodeResourceError),
        /// Original resource refusal retained across a canonical binary/JSON boundary.
        #[error(transparent)]
        ScopedDecodeResource(crate::core::ScopedDecodeResourceError),
        /// A fallible allocation needed by the JSON decoder failed without a recorded size.
        #[error("JSON decode allocation failed")]
        AllocationFailed,
        #[error("invalid utf8")]
        InvalidUtf8,
        #[error("{0}")]
        Message(String),
    }
    impl Error {
        #[inline]
        pub fn missing_field(field: impl Into<String>) -> Self {
            Self::MissingField {
                field: field.into(),
            }
        }
        #[inline]
        pub fn duplicate_field(field: impl Into<String>) -> Self {
            Self::DuplicateField {
                field: field.into(),
            }
        }
        #[inline]
        pub fn unknown_field(field: impl Into<String>) -> Self {
            Self::UnknownField {
                field: field.into(),
            }
        }
        /// Return whether decoding stopped at a caller-provided resource bound.
        #[doc(hidden)]
        #[must_use]
        pub const fn is_decode_resource_limit(&self) -> bool {
            matches!(
                self,
                Self::DecodeResourceLimit
                    | Self::ScopedDecodeResource(_)
                    | Self::DecodeResource(_)
                    | Self::AllocationFailed
                    | Self::NestingDepthExceeded { .. }
            )
        }
        /// Preserve exact resource fields and any original private scope identity.
        ///
        /// Non-resource errors keep their terminal diagnostic; they never become allocator
        /// refusals. Field-only errors do not acquire a canonical observer identity.
        #[doc(hidden)]
        pub fn from_decode_resource(error: crate::core::Error) -> Self {
            match error {
                crate::core::Error::ScopedDecodeResource(origin) => {
                    Self::ScopedDecodeResource(origin)
                }
                error => match error.decode_resource_error() {
                    Some(_) if cfg!(all(test, sumeragi_norito_mutation = "NC4")) => {
                        Self::DecodeResourceLimit
                    }
                    Some(resource) => Self::DecodeResource(resource),
                    None if cfg!(all(test, sumeragi_norito_mutation = "NC5")) => {
                        Self::AllocationFailed
                    }
                    None => Self::Message(error.to_string()),
                },
            }
        }
        /// Preserve an original scoped refusal when returning to binary decoding.
        ///
        /// Other JSON errors retain their JSON category. A native allocation failure has no
        /// recorded byte count; zero reports that unavailable size without inventing a scope.
        #[doc(hidden)]
        pub fn into_core_error(self) -> crate::core::Error {
            match self {
                Self::ScopedDecodeResource(origin) => {
                    crate::core::Error::ScopedDecodeResource(origin)
                }
                Self::DecodeResource(resource) => resource.into(),
                Self::AllocationFailed => crate::core::Error::AllocationFailed { bytes: 0 },
                error => crate::core::Error::Json(error),
            }
        }
    }
    mod bounded;
    mod canonical_base64;
    mod validated;
    pub use bounded::{
        BoundedJsonError, FastJsonWrite, JsonWriteSink, to_json_bounded, to_json_bounded_boxed,
        visit_json_display_text, write_json_display_to, write_json_string_to, write_json_unbounded,
    };
    #[doc(hidden)]
    pub use canonical_base64::{
        write_bare_norito_base64_json, write_bare_norito_base64_json_to, write_base64_json,
        write_base64_json_to, write_canonical_base64_json, write_canonical_base64_json_to,
        write_with_unbounded_sink,
    };
    #[doc(hidden)]
    pub use validated::write_validated_json_to;
    /// Stream bytes as one uppercase-hex JSON string through a checked sink.
    #[doc(hidden)]
    pub fn write_upper_hex_json_string_to(
        bytes: &[u8],
        output: &mut dyn JsonWriteSink,
    ) -> Result<(), BoundedJsonError> {
        bounded::write_hex_to(bytes, output)
    }
    impl From<String> for Error {
        fn from(s: String) -> Self {
            Error::Message(s)
        }
    }
    impl From<&str> for Error {
        fn from(s: &str) -> Self {
            Error::Message(s.to_owned())
        }
    }
    impl From<super::Error> for Error {
        fn from(e: super::Error) -> Self {
            Self::from_decode_resource(e)
        }
    }
    pub mod value {
        pub use super::RawValue;
        use super::{Error, Value, parse_value, to_json};
        pub fn to_raw_value(value: &Value) -> Result<Box<RawValue>, Error> {
            let json = to_json(value)?;
            Ok(Box::new(RawValue::from_string(json)))
        }
        pub fn from_raw_value(raw: &RawValue) -> Result<Value, Error> {
            parse_value(raw.get())
        }
        pub fn from_value<T: super::JsonDeserialize>(value: Value) -> Result<T, Error> {
            super::from_value(value)
        }
        pub fn to_value<T: super::JsonSerialize>(value: &T) -> Result<Value, Error> {
            super::to_value(value)
        }
    }
    // Native, serde-free JSON types and helpers
    #[inline]
    pub(crate) fn pos_from_offset(s: &str, pos: usize) -> (usize, usize, usize) {
        let bytes = s.as_bytes();
        let mut line = 1usize;
        let mut col = 1usize;
        let mut i = 0usize;
        while i < pos && i < bytes.len() {
            if bytes[i] == b'\n' {
                line += 1;
                col = 1;
            } else {
                col += 1;
            }
            i += 1;
        }
        (pos, line, col)
    }
    pub mod native {
        use super::ValueIndex;
        use core::mem;
        use std::{collections::BTreeMap, ops::Index};
        #[derive(Debug, Clone, Copy)]
        pub enum Number {
            I64(i64),
            U64(u64),
            U128(u128),
            F64(f64),
        }
        const F64_TWO_POW_63: f64 = f64::from_bits((1023_u64 + 63) << 52);
        const F64_TWO_POW_64: f64 = f64::from_bits((1023_u64 + 64) << 52);
        const F64_TWO_POW_128: f64 = f64::from_bits((1023_u64 + 128) << 52);

        fn i64_equals_f64(integer: i64, float: f64) -> bool {
            float.is_finite()
                && float.fract() == 0.0
                && (-F64_TWO_POW_63..F64_TWO_POW_63).contains(&float)
                && (float as i64) == integer
        }

        fn u64_equals_f64(integer: u64, float: f64) -> bool {
            float.is_finite()
                && float.fract() == 0.0
                && (0.0..F64_TWO_POW_64).contains(&float)
                && (float as u64) == integer
        }

        fn u128_equals_f64(integer: u128, float: f64) -> bool {
            float.is_finite()
                && float.fract() == 0.0
                && (0.0..F64_TWO_POW_128).contains(&float)
                && (float as u128) == integer
        }

        impl Number {
            pub fn as_i64(&self) -> Option<i64> {
                match self {
                    Number::I64(v) => Some(*v),
                    Number::U64(v) => i64::try_from(*v).ok(),
                    Number::U128(v) => i64::try_from(*v).ok(),
                    Number::F64(_) => None,
                }
            }
            pub fn as_u64(&self) -> Option<u64> {
                match self {
                    Number::U64(v) => Some(*v),
                    Number::U128(v) => u64::try_from(*v).ok(),
                    Number::I64(v) if *v >= 0 => Some(*v as u64),
                    _ => None,
                }
            }
            pub fn as_u128(&self) -> Option<u128> {
                match self {
                    Number::U64(v) => Some(u128::from(*v)),
                    Number::U128(v) => Some(*v),
                    Number::I64(v) if *v >= 0 => Some(*v as u128),
                    _ => None,
                }
            }
            pub fn as_f64(&self) -> Option<f64> {
                match self {
                    Number::F64(v) => Some(*v),
                    Number::I64(v) => Some(*v as f64),
                    Number::U64(v) => Some(*v as f64),
                    Number::U128(v) => Some(*v as f64),
                }
            }
            pub fn from_f64(v: f64) -> Option<Self> {
                if v.is_finite() {
                    Some(Number::F64(v))
                } else {
                    None
                }
            }
        }
        impl From<i64> for Number {
            fn from(v: i64) -> Self {
                Number::I64(v)
            }
        }
        impl From<u64> for Number {
            fn from(v: u64) -> Self {
                Number::U64(v)
            }
        }
        impl From<u128> for Number {
            fn from(v: u128) -> Self {
                Number::U128(v)
            }
        }
        impl From<f64> for Number {
            fn from(v: f64) -> Self {
                Number::F64(v)
            }
        }
        impl PartialEq for Number {
            fn eq(&self, other: &Self) -> bool {
                match (self, other) {
                    (Number::I64(a), Number::I64(b)) => a == b,
                    (Number::U64(a), Number::U64(b)) => a == b,
                    (Number::U128(a), Number::U128(b)) => a == b,
                    (Number::F64(a), Number::F64(b)) => a == b,
                    (Number::I64(a), Number::U64(b)) => *a >= 0 && (*a as u64) == *b,
                    (Number::U64(a), Number::I64(b)) => *b >= 0 && *a == (*b as u64),
                    (Number::I64(a), Number::U128(b)) => *a >= 0 && (*a as u128) == *b,
                    (Number::U128(a), Number::I64(b)) => *b >= 0 && *a == (*b as u128),
                    (Number::U64(a), Number::U128(b)) => u128::from(*a) == *b,
                    (Number::U128(a), Number::U64(b)) => *a == u128::from(*b),
                    (Number::I64(a), Number::F64(b)) => i64_equals_f64(*a, *b),
                    (Number::F64(a), Number::I64(b)) => i64_equals_f64(*b, *a),
                    (Number::U64(a), Number::F64(b)) => u64_equals_f64(*a, *b),
                    (Number::F64(a), Number::U64(b)) => u64_equals_f64(*b, *a),
                    (Number::U128(a), Number::F64(b)) => u128_equals_f64(*a, *b),
                    (Number::F64(a), Number::U128(b)) => u128_equals_f64(*b, *a),
                }
            }
        }
        pub type Map = BTreeMap<String, Value>;
        fn decode_pointer_segment(segment: &str) -> Option<String> {
            if !segment.contains('~') {
                return Some(segment.to_owned());
            }
            let mut out = String::with_capacity(segment.len());
            let mut chars = segment.chars();
            while let Some(ch) = chars.next() {
                if ch == '~' {
                    match chars.next() {
                        Some('0') => out.push('~'),
                        Some('1') => out.push('/'),
                        _ => return None,
                    }
                } else {
                    out.push(ch);
                }
            }
            Some(out)
        }
        /// One owned native JSON value.
        ///
        /// Parsing and parse-error cleanup are iterative, but the public derived `Clone`, `Debug`,
        /// equality, and ordinary owner drop surfaces remain recursive. Callers handling
        /// adversarial values near [`super::MAX_JSON_VALUE_NESTING_DEPTH`] on a constrained stack
        /// must consume or dismantle them with an iterative walker or enforce their own shallower
        /// depth guard.
        #[derive(Debug, Clone, PartialEq)]
        pub enum Value {
            Null,
            Bool(bool),
            Number(Number),
            String(String),
            Array(Vec<Value>),
            Object(Map),
        }
        impl Eq for Value {}
        impl Value {
            pub fn is_null(&self) -> bool {
                matches!(self, Value::Null)
            }
            pub fn is_bool(&self) -> bool {
                matches!(self, Value::Bool(_))
            }
            pub fn is_number(&self) -> bool {
                matches!(self, Value::Number(_))
            }
            pub fn is_string(&self) -> bool {
                matches!(self, Value::String(_))
            }
            pub fn is_array(&self) -> bool {
                matches!(self, Value::Array(_))
            }
            pub fn is_object(&self) -> bool {
                matches!(self, Value::Object(_))
            }
            pub fn as_array(&self) -> Option<&Vec<Value>> {
                if let Value::Array(a) = self {
                    Some(a)
                } else {
                    None
                }
            }
            pub fn as_array_mut(&mut self) -> Option<&mut Vec<Value>> {
                if let Value::Array(a) = self {
                    Some(a)
                } else {
                    None
                }
            }
            pub fn as_object(&self) -> Option<&Map> {
                if let Value::Object(map) = self {
                    Some(map)
                } else {
                    None
                }
            }
            pub fn as_object_mut(&mut self) -> Option<&mut Map> {
                if let Value::Object(map) = self {
                    Some(map)
                } else {
                    None
                }
            }
            pub fn get<I>(&self, index: I) -> Option<&Value>
            where
                I: ValueIndex,
            {
                index.index_into(self)
            }
            pub fn get_mut<I>(&mut self, index: I) -> Option<&mut Value>
            where
                I: ValueIndex,
            {
                index.index_into_mut(self)
            }
            pub fn as_str(&self) -> Option<&str> {
                if let Value::String(s) = self {
                    Some(s)
                } else {
                    None
                }
            }
            pub fn as_bool(&self) -> Option<bool> {
                if let Value::Bool(b) = self {
                    Some(*b)
                } else {
                    None
                }
            }
            pub fn as_u64(&self) -> Option<u64> {
                if let Value::Number(n) = self {
                    n.as_u64()
                } else {
                    None
                }
            }
            pub fn as_u128(&self) -> Option<u128> {
                if let Value::Number(n) = self {
                    n.as_u128()
                } else {
                    None
                }
            }
            pub fn as_i64(&self) -> Option<i64> {
                if let Value::Number(n) = self {
                    n.as_i64()
                } else {
                    None
                }
            }
            pub fn as_f64(&self) -> Option<f64> {
                if let Value::Number(n) = self {
                    n.as_f64()
                } else {
                    None
                }
            }
            pub fn pointer(&self, pointer: &str) -> Option<&Value> {
                if pointer.is_empty() {
                    return Some(self);
                }
                if !pointer.starts_with('/') {
                    return None;
                }
                let mut current = self;
                for segment in pointer.split('/').skip(1) {
                    let key = decode_pointer_segment(segment)?;
                    match current {
                        Value::Object(map) => {
                            current = map.get(key.as_str())?;
                        }
                        Value::Array(arr) => {
                            let idx = key.parse::<usize>().ok()?;
                            current = arr.get(idx)?;
                        }
                        _ => return None,
                    }
                }
                Some(current)
            }
            pub fn pointer_mut(&mut self, pointer: &str) -> Option<&mut Value> {
                if pointer.is_empty() {
                    return Some(self);
                }
                if !pointer.starts_with('/') {
                    return None;
                }
                let mut current = self;
                for segment in pointer.split('/').skip(1) {
                    let key = decode_pointer_segment(segment)?;
                    match current {
                        Value::Object(map) => {
                            current = map.get_mut(key.as_str())?;
                        }
                        Value::Array(arr) => {
                            let idx = key.parse::<usize>().ok()?;
                            current = arr.get_mut(idx)?;
                        }
                        _ => return None,
                    }
                }
                Some(current)
            }
            pub fn take(&mut self) -> Value {
                mem::replace(self, Value::Null)
            }
        }
        impl From<bool> for Value {
            fn from(v: bool) -> Self {
                Value::Bool(v)
            }
        }
        impl From<u64> for Value {
            fn from(v: u64) -> Self {
                Value::Number(Number::U64(v))
            }
        }
        impl From<u128> for Value {
            fn from(v: u128) -> Self {
                Value::Number(Number::U128(v))
            }
        }
        impl From<u32> for Value {
            fn from(v: u32) -> Self {
                Value::Number(Number::U64(v as u64))
            }
        }
        impl From<u16> for Value {
            fn from(v: u16) -> Self {
                Value::Number(Number::U64(v as u64))
            }
        }
        impl From<u8> for Value {
            fn from(v: u8) -> Self {
                Value::Number(Number::U64(v as u64))
            }
        }
        impl From<i64> for Value {
            fn from(v: i64) -> Self {
                Value::Number(Number::I64(v))
            }
        }
        impl From<i32> for Value {
            fn from(v: i32) -> Self {
                Value::Number(Number::I64(v as i64))
            }
        }
        impl From<i16> for Value {
            fn from(v: i16) -> Self {
                Value::Number(Number::I64(v as i64))
            }
        }
        impl From<i8> for Value {
            fn from(v: i8) -> Self {
                Value::Number(Number::I64(v as i64))
            }
        }
        impl From<usize> for Value {
            fn from(v: usize) -> Self {
                Value::Number(Number::U64(v as u64))
            }
        }
        impl From<isize> for Value {
            fn from(v: isize) -> Self {
                Value::Number(Number::I64(v as i64))
            }
        }
        impl From<f64> for Value {
            fn from(v: f64) -> Self {
                Value::Number(Number::F64(v))
            }
        }
        impl From<String> for Value {
            fn from(v: String) -> Self {
                Value::String(v)
            }
        }
        impl From<&str> for Value {
            fn from(v: &str) -> Self {
                Value::String(v.to_string())
            }
        }
        impl From<Vec<Value>> for Value {
            fn from(v: Vec<Value>) -> Self {
                Value::Array(v)
            }
        }
        impl From<Map> for Value {
            fn from(map: Map) -> Self {
                Value::Object(map)
            }
        }
        static NULL: Value = Value::Null;
        impl Index<&str> for Value {
            type Output = Value;
            fn index(&self, index: &str) -> &Self::Output {
                if let Value::Object(map) = self {
                    map.get(index).unwrap_or(&NULL)
                } else {
                    &NULL
                }
            }
        }
        impl Index<usize> for Value {
            type Output = Value;
            fn index(&self, idx: usize) -> &Self::Output {
                if let Value::Array(a) = self {
                    a.get(idx).unwrap_or(&NULL)
                } else {
                    &NULL
                }
            }
        }
    }
    pub trait ValueIndex {
        fn index_into<'a>(&self, value: &'a Value) -> Option<&'a Value>;
        fn index_into_mut<'a>(&self, value: &'a mut Value) -> Option<&'a mut Value>;
    }
    impl ValueIndex for &str {
        fn index_into<'a>(&self, value: &'a Value) -> Option<&'a Value> {
            if let Value::Object(map) = value {
                map.get(*self)
            } else {
                None
            }
        }
        fn index_into_mut<'a>(&self, value: &'a mut Value) -> Option<&'a mut Value> {
            if let Value::Object(map) = value {
                map.get_mut(*self)
            } else {
                None
            }
        }
    }
    impl ValueIndex for String {
        fn index_into<'a>(&self, value: &'a Value) -> Option<&'a Value> {
            if let Value::Object(map) = value {
                map.get(self.as_str())
            } else {
                None
            }
        }
        fn index_into_mut<'a>(&self, value: &'a mut Value) -> Option<&'a mut Value> {
            if let Value::Object(map) = value {
                map.get_mut(self.as_str())
            } else {
                None
            }
        }
    }
    impl ValueIndex for usize {
        fn index_into<'a>(&self, value: &'a Value) -> Option<&'a Value> {
            if let Value::Array(arr) = value {
                arr.get(*self)
            } else {
                None
            }
        }
        fn index_into_mut<'a>(&self, value: &'a mut Value) -> Option<&'a mut Value> {
            if let Value::Array(arr) = value {
                arr.get_mut(*self)
            } else {
                None
            }
        }
    }
    pub type Map = native::Map;
    pub type Number = native::Number;
    pub type Value = native::Value;
    #[macro_export]
    macro_rules! json {
        (null) => { $crate::json::Value::Null };
        ([$($elem:tt),* $(,)?]) => {{
            let values = vec![$($crate::json!($elem)),*];
            $crate::json::Value::Array(values)
        }};
        ({$($key:literal : $val:tt),* $(,)?}) => {{
            let mut map = $crate::json::Map::new();
            $( map.insert($key.to_string(), $crate::json!($val)); )*
            $crate::json::Value::Object(map)
        }};
        ($other:expr) => {{
            match $crate::json::to_value(&$other) {
                Ok(value) => value,
                Err(err) => panic!("norito::json! failed to serialize expression: {err}"),
            }
        }};
    }
    mod schema_support {
        use super::{JsonSerialize, Map, Number, Value};
        use core::any::TypeId;
        use iroha_schema::{
            ArrayMeta, BitmapMask, BitmapMeta, EnumMeta, EnumVariant, FixedMeta, FloatMode, Ident,
            IntMode, IntoSchema, MapMeta, MetaMap, MetaMapEntry, Metadata, NamedFieldsMeta,
            ResultMeta, TypeId as SchemaTypeId, UnnamedFieldsMeta,
        };
        use std::collections::{BTreeMap, btree_map::Entry as BTreeEntry};
        type EntryMap = BTreeMap<TypeId, MetaMapEntry>;
        impl JsonSerialize for MetaMap {
            fn json_serialize(&self, out: &mut String) {
                let entries: EntryMap = self.clone().into_iter().collect();
                let mut sorted: BTreeMap<String, Value> = BTreeMap::new();
                let mut duplicates: BTreeMap<String, Vec<Value>> = BTreeMap::new();
                for entry in entries.values() {
                    let value = metadata_to_value(&entry.metadata, &entries);
                    match sorted.entry(entry.type_name.clone()) {
                        BTreeEntry::Vacant(slot) => {
                            slot.insert(value);
                        }
                        BTreeEntry::Occupied(slot) => {
                            if slot.get() != &value {
                                let dup = duplicates
                                    .entry(entry.type_name.clone())
                                    .or_insert_with(|| vec![slot.get().clone()]);
                                dup.push(value);
                            }
                        }
                    }
                }
                assert!(
                    duplicates.is_empty(),
                    "Duplicate type names: {duplicates:#?}"
                );
                let mut map = Map::new();
                for (type_name, value) in sorted {
                    map.insert(type_name, value);
                }
                Value::Object(map).json_serialize(out);
            }
        }
        fn metadata_to_value(meta: &Metadata, entries: &EntryMap) -> Value {
            match meta {
                Metadata::String => {
                    Value::String(lookup(entries, TypeId::of::<String>(), "Metadata::String"))
                }
                Metadata::Bool => {
                    Value::String(lookup(entries, TypeId::of::<bool>(), "Metadata::Bool"))
                }
                Metadata::Option(inner) => single_entry(
                    "Option",
                    Value::String(lookup(entries, *inner, "Metadata::Option")),
                ),
                Metadata::Int(mode) => single_entry("Int", int_mode_to_value(*mode)),
                Metadata::Float(mode) => single_entry("Float", float_mode_to_value(*mode)),
                Metadata::Tuple(tuple) => tuple_metadata_to_value(tuple, entries),
                Metadata::Struct(named) => {
                    single_entry("Struct", struct_fields_to_value(named, entries))
                }
                Metadata::Enum(enum_meta) => {
                    single_entry("Enum", enum_variants_to_value(enum_meta, entries))
                }
                Metadata::FixedPoint(fixed) => {
                    single_entry("FixedPoint", fixed_meta_to_value(fixed, entries))
                }
                Metadata::Array(array) => {
                    single_entry("Array", array_meta_to_value(array, entries))
                }
                Metadata::Vec(vec_meta) => single_entry(
                    "Vec",
                    Value::String(lookup(entries, vec_meta.ty, "Metadata::Vec")),
                ),
                Metadata::Map(map_meta) => {
                    single_entry("Map", map_meta_to_value(map_meta, entries))
                }
                Metadata::Result(result) => {
                    single_entry("Result", result_meta_to_value(result, entries))
                }
                Metadata::Bitmap(bitmap) => {
                    single_entry("Bitmap", bitmap_meta_to_value(bitmap, entries))
                }
            }
        }
        fn lookup(entries: &EntryMap, type_id: TypeId, context: &'static str) -> String {
            entries
                .get(&type_id)
                .map(|entry| entry.type_name.clone())
                .unwrap_or_else(|| {
                    panic!("Failed to find type id `{type_id:?}` while serializing {context}")
                })
        }
        fn tuple_metadata_to_value(meta: &UnnamedFieldsMeta, entries: &EntryMap) -> Value {
            match meta.types.as_slice() {
                [] => Value::Null,
                [ty] => Value::String(lookup(entries, *ty, "Tuple::Single")),
                types => {
                    let items = types
                        .iter()
                        .map(|ty| Value::String(lookup(entries, *ty, "Tuple::Multi")))
                        .collect();
                    single_entry("Tuple", Value::Array(items))
                }
            }
        }
        fn struct_fields_to_value(meta: &NamedFieldsMeta, entries: &EntryMap) -> Value {
            let mut out = Vec::with_capacity(meta.declarations.len());
            for decl in &meta.declarations {
                let mut field = Map::new();
                field.insert("name".to_owned(), Value::String(decl.name.clone()));
                field.insert(
                    "type".to_owned(),
                    Value::String(lookup(entries, decl.ty, "StructDecl")),
                );
                out.push(Value::Object(field));
            }
            Value::Array(out)
        }
        fn enum_variants_to_value(meta: &EnumMeta, entries: &EntryMap) -> Value {
            let mut out = Vec::with_capacity(meta.variants.len());
            for EnumVariant {
                tag,
                discriminant,
                ty,
            } in &meta.variants
            {
                let mut variant = Map::new();
                variant.insert("tag".to_owned(), Value::String(tag.clone()));
                variant.insert(
                    "discriminant".to_owned(),
                    Value::from(u64::from(*discriminant)),
                );
                if let Some(type_id) = ty {
                    variant.insert(
                        "type".to_owned(),
                        Value::String(lookup(entries, *type_id, "EnumDecl")),
                    );
                }
                out.push(Value::Object(variant));
            }
            Value::Array(out)
        }
        fn fixed_meta_to_value(meta: &FixedMeta, entries: &EntryMap) -> Value {
            let mut obj = Map::new();
            obj.insert(
                "base".to_owned(),
                Value::String(lookup(entries, meta.base, "FixedPoint::base")),
            );
            obj.insert(
                "decimal_places".to_owned(),
                Value::from(u64::from(meta.decimal_places)),
            );
            Value::Object(obj)
        }
        fn array_meta_to_value(meta: &ArrayMeta, entries: &EntryMap) -> Value {
            let mut obj = Map::new();
            obj.insert(
                "type".to_owned(),
                Value::String(lookup(entries, meta.ty, "ArrayMeta::type")),
            );
            obj.insert("len".to_owned(), u128_to_value(meta.len));
            Value::Object(obj)
        }
        fn map_meta_to_value(meta: &MapMeta, entries: &EntryMap) -> Value {
            let mut obj = Map::new();
            obj.insert(
                "key".to_owned(),
                Value::String(lookup(entries, meta.key, "MapMeta::key")),
            );
            obj.insert(
                "value".to_owned(),
                Value::String(lookup(entries, meta.value, "MapMeta::value")),
            );
            Value::Object(obj)
        }
        fn result_meta_to_value(meta: &ResultMeta, entries: &EntryMap) -> Value {
            let mut obj = Map::new();
            obj.insert(
                "ok".to_owned(),
                Value::String(lookup(entries, meta.ok, "ResultMeta::ok")),
            );
            obj.insert(
                "err".to_owned(),
                Value::String(lookup(entries, meta.err, "ResultMeta::err")),
            );
            Value::Object(obj)
        }
        fn bitmap_meta_to_value(meta: &BitmapMeta, entries: &EntryMap) -> Value {
            let mut obj = Map::new();
            obj.insert(
                "repr".to_owned(),
                Value::String(lookup(entries, meta.repr, "BitmapMeta::repr")),
            );
            obj.insert("masks".to_owned(), bitmap_masks_to_value(&meta.masks));
            Value::Object(obj)
        }
        fn bitmap_masks_to_value(masks: &[BitmapMask]) -> Value {
            let mut out = Vec::with_capacity(masks.len());
            for mask in masks {
                let mut obj = Map::new();
                obj.insert("name".to_owned(), Value::String(mask.name.clone()));
                obj.insert("mask".to_owned(), Value::from(mask.mask));
                out.push(Value::Object(obj));
            }
            Value::Array(out)
        }
        fn int_mode_to_value(mode: IntMode) -> Value {
            match mode {
                IntMode::FixedWidth => Value::String("FixedWidth".to_owned()),
                IntMode::Compact => Value::String("Compact".to_owned()),
            }
        }
        fn float_mode_to_value(mode: FloatMode) -> Value {
            match mode {
                FloatMode::Binary32 => Value::String("Binary32".to_owned()),
                FloatMode::Binary64 => Value::String("Binary64".to_owned()),
            }
        }
        #[inline]
        fn type_name_of<T>() -> Ident {
            core::any::type_name::<T>().to_owned()
        }
        impl SchemaTypeId for Number {
            fn id() -> Ident {
                type_name_of::<Self>()
            }
        }
        impl IntoSchema for Number {
            fn type_name() -> Ident {
                type_name_of::<Self>()
            }
            fn update_schema_map(map: &mut MetaMap) {
                if map.contains_key::<Self>() {
                    return;
                }
                let variants = vec![
                    EnumVariant {
                        tag: "I64".to_owned(),
                        discriminant: 0,
                        ty: Some(TypeId::of::<i64>()),
                    },
                    EnumVariant {
                        tag: "U64".to_owned(),
                        discriminant: 1,
                        ty: Some(TypeId::of::<u64>()),
                    },
                    EnumVariant {
                        tag: "U128".to_owned(),
                        discriminant: 2,
                        ty: Some(TypeId::of::<u128>()),
                    },
                    EnumVariant {
                        tag: "F64".to_owned(),
                        discriminant: 3,
                        ty: Some(TypeId::of::<f64>()),
                    },
                ];
                map.insert::<Self>(Metadata::Enum(EnumMeta { variants }));
                <i64 as IntoSchema>::update_schema_map(map);
                <u64 as IntoSchema>::update_schema_map(map);
                <u128 as IntoSchema>::update_schema_map(map);
                <f64 as IntoSchema>::update_schema_map(map);
            }
        }
        impl SchemaTypeId for Value {
            fn id() -> Ident {
                type_name_of::<Self>()
            }
        }
        impl IntoSchema for Value {
            fn type_name() -> Ident {
                type_name_of::<Self>()
            }
            fn update_schema_map(map: &mut MetaMap) {
                if map.contains_key::<Self>() {
                    return;
                }
                let variants = vec![
                    EnumVariant {
                        tag: "Null".to_owned(),
                        discriminant: 0,
                        ty: None,
                    },
                    EnumVariant {
                        tag: "Bool".to_owned(),
                        discriminant: 1,
                        ty: Some(TypeId::of::<bool>()),
                    },
                    EnumVariant {
                        tag: "Number".to_owned(),
                        discriminant: 2,
                        ty: Some(TypeId::of::<Number>()),
                    },
                    EnumVariant {
                        tag: "String".to_owned(),
                        discriminant: 3,
                        ty: Some(TypeId::of::<String>()),
                    },
                    EnumVariant {
                        tag: "Array".to_owned(),
                        discriminant: 4,
                        ty: Some(TypeId::of::<Vec<Value>>()),
                    },
                    EnumVariant {
                        tag: "Object".to_owned(),
                        discriminant: 5,
                        ty: Some(TypeId::of::<Map>()),
                    },
                ];
                map.insert::<Self>(Metadata::Enum(EnumMeta { variants }));
                <bool as IntoSchema>::update_schema_map(map);
                <Number as IntoSchema>::update_schema_map(map);
                <String as IntoSchema>::update_schema_map(map);
                <Vec<Value> as IntoSchema>::update_schema_map(map);
                <std::collections::BTreeMap<String, Value> as IntoSchema>::update_schema_map(map);
            }
        }
        fn u128_to_value(len: u128) -> Value {
            Value::from(len)
        }
        fn single_entry(key: &str, value: Value) -> Value {
            let mut map = Map::new();
            map.insert(key.to_owned(), value);
            Value::Object(map)
        }
    }
    /// Compute a compile-time key hash for JSON object field dispatch.
    ///
    /// The hash function mirrors `TapeWalker::read_key_hash` on plain ASCII keys without escapes.
    /// For typical field identifiers (letters, digits, `_`), this matches exactly. When the
    /// `crc-key-hash` feature is enabled we use a software CRC32C update and widen to 64 bits using
    /// a fixed avalanche to minimize collisions. Otherwise we default to 64-bit FNV-1a.
    pub const fn key_hash_const(s: &str) -> u64 {
        key_hash::hash_const(s)
    }

    #[inline]
    fn write_f64_json(x: f64, out: &mut String) {
        if !x.is_finite() {
            out.push_str("null");
            return;
        }
        let mut buffer = ryu::Buffer::new();
        let formatted = buffer.format_finite(x);
        if let Some(exp_index) = formatted.as_bytes().iter().position(|byte| *byte == b'e') {
            out.push_str(&formatted[..=exp_index]);
            match formatted.as_bytes().get(exp_index + 1) {
                Some(b'+') | Some(b'-') => out.push_str(&formatted[exp_index + 1..]),
                Some(_) => {
                    out.push('+');
                    out.push_str(&formatted[exp_index + 1..]);
                }
                None => {}
            }
        } else {
            out.push_str(formatted);
        }
    }
    // Native variants for Value
    fn write_value_to_string(v: &Value, out: &mut String, pretty: bool, depth: usize) {
        use native::Value as V;
        enum Task<'a> {
            Value(&'a Value, usize),
            Array {
                values: &'a [Value],
                index: usize,
                depth: usize,
            },
            Object {
                entries: std::collections::btree_map::Iter<'a, String, Value>,
                first: bool,
                depth: usize,
            },
        }
        fn write_line_indent(out: &mut String, depth: usize) {
            out.push('\n');
            for _ in 0..depth {
                out.push_str("  ");
            }
        }
        let mut tasks = vec![Task::Value(v, depth)];
        while let Some(task) = tasks.pop() {
            match task {
                Task::Value(value, depth) => match value {
                    V::Null => out.push_str("null"),
                    V::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
                    V::Number(value) => match value {
                        native::Number::I64(value) => out.push_str(&value.to_string()),
                        native::Number::U64(value) => out.push_str(&value.to_string()),
                        native::Number::U128(value) => out.push_str(&value.to_string()),
                        native::Number::F64(value) => write_f64_json(*value, out),
                    },
                    V::String(value) => write_json_string(value, out),
                    V::Array(values) => {
                        out.push('[');
                        if values.is_empty() {
                            out.push(']');
                        } else {
                            tasks.push(Task::Array {
                                values,
                                index: 0,
                                depth,
                            });
                        }
                    }
                    V::Object(values) => {
                        out.push('{');
                        if values.is_empty() {
                            out.push('}');
                        } else {
                            tasks.push(Task::Object {
                                entries: values.iter(),
                                first: true,
                                depth,
                            });
                        }
                    }
                },
                Task::Array {
                    values,
                    index,
                    depth,
                } => {
                    let Some(value) = values.get(index) else {
                        if pretty {
                            write_line_indent(out, depth);
                        }
                        out.push(']');
                        continue;
                    };
                    if index != 0 {
                        out.push(',');
                    }
                    if pretty {
                        write_line_indent(out, depth + 1);
                    }
                    tasks.push(Task::Array {
                        values,
                        index: index + 1,
                        depth,
                    });
                    tasks.push(Task::Value(value, depth + 1));
                }
                Task::Object {
                    mut entries,
                    first,
                    depth,
                } => {
                    let Some((key, value)) = entries.next() else {
                        if pretty {
                            write_line_indent(out, depth);
                        }
                        out.push('}');
                        continue;
                    };
                    if !first {
                        out.push(',');
                    }
                    if pretty {
                        write_line_indent(out, depth + 1);
                    }
                    write_json_string(key, out);
                    out.push(':');
                    if pretty {
                        out.push(' ');
                    }
                    tasks.push(Task::Object {
                        entries,
                        first: false,
                        depth,
                    });
                    tasks.push(Task::Value(value, depth + 1));
                }
            }
        }
    }
    /// serde-style API: serialize any `JsonSerialize` payload to a compact string.
    pub fn to_string<T: JsonSerialize + ?Sized>(value: &T) -> Result<String, Error> {
        to_json(value)
    }
    /// serde-style API: serialize any `JsonSerialize` payload to a pretty string.
    pub fn to_string_pretty<T: JsonSerialize + ?Sized>(value: &T) -> Result<String, Error> {
        to_json_pretty(value)
    }
    pub fn to_vec<T: JsonSerialize + ?Sized>(value: &T) -> Result<Vec<u8>, Error> {
        Ok(to_json(value)?.into_bytes())
    }
    /// serde-style API: serialize to a pretty-printed `Vec<u8>` (alloc-only helper).
    pub fn to_vec_pretty<T: JsonSerialize + ?Sized>(value: &T) -> Result<Vec<u8>, Error> {
        Ok(to_json_pretty(value)?.into_bytes())
    }
    /// Parse a typed value directly from `&str` using Norito's native JSON stack.
    ///
    /// This path intentionally avoids first constructing a recursive [`Value`]
    /// tree, reducing allocations and allowing type-specific depth guards to
    /// reject hostile input before domain objects are returned.
    pub fn from_str<T: JsonDeserialize>(s: &str) -> Result<T, Error> {
        from_json(s)
    }
    /// Parse from a UTF‑8 byte slice using Norito's native parser.
    ///
    /// This is the byte-slice counterpart of the direct typed [`from_str`]
    /// path and does not build an owned [`Value`] intermediate.
    pub fn from_slice<T: JsonDeserialize>(bytes: &[u8]) -> Result<T, Error> {
        let s = std::str::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)?;
        from_str(s)
    }
    /// Alias for `from_slice` for convenience.
    pub fn from_bytes<T: JsonDeserialize>(bytes: &[u8]) -> Result<T, Error> {
        from_slice(bytes)
    }
    /// Convert a native JSON `Value` into `T` using `JsonDeserialize`.
    pub fn from_value<T: JsonDeserialize>(v: Value) -> Result<T, Error> {
        let result = T::json_from_value(&v);
        drop_json_value_iteratively(v);
        result
    }
    /// Convert `value` into a native JSON `Value` using `JsonSerialize`.
    pub fn to_value<T: JsonSerialize + ?Sized>(value: &T) -> Result<Value, Error> {
        let json = to_json(value)?;
        parse_value(&json)
    }
    /// Convenience: parse a JSON `Value` from `&str` using Norito's parser.
    pub fn parse_value(s: &str) -> Result<Value, Error> {
        let mut parser = super::json::Parser::new(s);
        let mut value = IterativeValueDropGuard::new(parse_value_internal(&mut parser, 1)?);
        parser.skip_ws();
        if !parser.eof() {
            let (byte, line, col) = parser.pos_meta(parser.position());
            return Err(Error::TrailingCharacters { byte, line, col });
        }
        Ok(value.take())
    }
    /// Validate one complete JSON document without constructing an owned recursive [`Value`] tree.
    ///
    /// This uses the same bounded grammar as [`parse_value`], including strict
    /// number, escape, surrogate, duplicate-key, and trailing-byte checks.
    pub fn validate_json(s: &str) -> Result<(), Error> {
        validate_json_at_depth(s, 1)
    }
    /// Validate one complete JSON document whose root will be embedded at
    /// `root_depth` in a larger document.
    ///
    /// The root of a standalone document has depth 1. Callers that splice a validated fragment into
    /// an already-open object or array pass the fragment's eventual root depth so the global V1
    /// nesting limit remains enforceable without allocating the enclosing document.
    #[doc(hidden)]
    pub fn validate_json_at_depth(s: &str, root_depth: usize) -> Result<(), Error> {
        if root_depth == 0 {
            return Err(Error::Message(
                "JSON root depth must be at least 1".to_owned(),
            ));
        }
        let mut parser = Parser::new(s);
        parser.skip_value_at_depth(root_depth)?;
        parser.skip_ws();
        if !parser.eof() {
            let (byte, line, col) = parser.pos_meta(parser.position());
            return Err(Error::TrailingCharacters { byte, line, col });
        }
        Ok(())
    }
    fn ensure_json_value_depth(depth: usize) -> Result<(), Error> {
        if depth > MAX_JSON_VALUE_NESTING_DEPTH {
            return Err(Error::NestingDepthExceeded {
                depth,
                limit: MAX_JSON_VALUE_NESTING_DEPTH,
                context: "JSON value",
            });
        }
        Ok(())
    }
    fn try_decode_vec_with_capacity<T>(entries: usize) -> Result<Vec<T>, Error> {
        let requested_bytes = entries
            .checked_mul(core::mem::size_of::<T>())
            .ok_or(Error::DecodeResourceLimit)?;
        crate::core::reserve_decode_allocation(requested_bytes)
            .map_err(Error::from_decode_resource)?;
        exact_string::allocate(entries)
    }
    fn try_decode_string_copy(value: &str) -> Result<String, Error> {
        crate::core::reserve_decode_allocation(value.len()).map_err(Error::from_decode_resource)?;
        let mut decoded = exact_string::allocate(value.len())?;
        decoded.extend_from_slice(value.as_bytes());
        // SAFETY: `value` is UTF-8 and was copied without modification.
        Ok(unsafe { String::from_utf8_unchecked(decoded) })
    }
    mod value_drop;
    pub use value_drop::drop_json_value_iteratively;
    use value_drop::{IterativeValueDropGuard, ValueParseFrame, ValueParseState};
    fn parse_object_key(p: &mut Parser<'_>) -> Result<String, Error> {
        let key = p.parse_string()?;
        p.skip_ws();
        if p.peek() == Some(b':') {
            p.bump();
            Ok(key)
        } else {
            let (byte, line, col) = p.pos_meta(p.position());
            Err(Error::ExpectedColon { byte, line, col })
        }
    }
    fn parse_value_internal(p: &mut Parser<'_>, depth: usize) -> Result<Value, Error> {
        enum AttachAction {
            ParseNext(usize),
            Close,
        }
        p.skip_ws();
        let (profile, _) = preflight::value_profile_at_depth(p.input(), p.position(), depth)
            .map_err(|error| p.lexical_preflight_error(error))?;
        let frame_capacity = profile.max_nesting_depth().saturating_sub(depth);
        let mut state = ValueParseState::with_frame_capacity(frame_capacity)?;
        let mut next_depth = depth;
        'parse: loop {
            ensure_json_value_depth(next_depth)?;
            p.skip_ws();
            state.completed = match p.peek() {
                Some(b'"') => Some(Value::String(p.parse_string()?)),
                Some(b'n') => {
                    p.parse_null()?;
                    Some(Value::Null)
                }
                Some(b't') | Some(b'f') => Some(Value::Bool(p.parse_bool()?)),
                Some(b'[') => {
                    let entries = p.preflight_container_entries(b'[')?;
                    let values = try_decode_vec_with_capacity(entries)?;
                    p.bump();
                    p.skip_ws();
                    if p.peek() == Some(b']') {
                        p.bump();
                        Some(Value::Array(values))
                    } else {
                        let child_depth = next_depth.saturating_add(1);
                        state.frames.push(ValueParseFrame::Array {
                            values,
                            child_depth,
                        });
                        next_depth = child_depth;
                        continue 'parse;
                    }
                }
                Some(b'{') => {
                    let entries = p.preflight_container_entries(b'{')?;
                    crate::core::reserve_decode_btree_allocation::<String, Value>(entries)
                        .map_err(Error::from_decode_resource)?;
                    p.bump();
                    p.skip_ws();
                    if p.peek() == Some(b'}') {
                        p.bump();
                        Some(Value::Object(Map::new()))
                    } else {
                        let key = parse_object_key(p)?;
                        let child_depth = next_depth.saturating_add(1);
                        state.frames.push(ValueParseFrame::Object {
                            values: Map::new(),
                            key: Some(key),
                            child_depth,
                        });
                        next_depth = child_depth;
                        continue 'parse;
                    }
                }
                Some(b'-') | Some(b'0'..=b'9') => Some(parse_number_value(p)?),
                Some(_) => return Err(p.err_unexpected_char()),
                None => {
                    let (byte, line, col) = p.pos_meta(p.position());
                    return Err(Error::UnexpectedEof { byte, line, col });
                }
            };
            loop {
                let mut completed = IterativeValueDropGuard::new(state.take_completed());
                if state.frames.is_empty() {
                    return Ok(completed.take());
                }
                let action = match state
                    .frames
                    .last_mut()
                    .expect("non-empty iterative JSON frame stack")
                {
                    ValueParseFrame::Array {
                        values,
                        child_depth,
                    } => {
                        values.push(completed.take());
                        p.skip_ws();
                        match p.peek() {
                            Some(b',') => {
                                p.bump();
                                p.skip_ws();
                                AttachAction::ParseNext(*child_depth)
                            }
                            Some(b']') => {
                                p.bump();
                                AttachAction::Close
                            }
                            _ => {
                                let (byte, line, col) = p.pos_meta(p.position());
                                return Err(Error::ExpectedCommaOrArrayEnd { byte, line, col });
                            }
                        }
                    }
                    ValueParseFrame::Object {
                        values,
                        key: pending_key,
                        child_depth,
                    } => {
                        let key = pending_key
                            .take()
                            .expect("iterative JSON object frame has no pending key");
                        if values.contains_key(&key) {
                            return Err(Error::duplicate_field(key));
                        }
                        values.insert(key, completed.take());
                        p.skip_ws();
                        match p.peek() {
                            Some(b',') => {
                                p.bump();
                                p.skip_ws();
                                *pending_key = Some(parse_object_key(p)?);
                                AttachAction::ParseNext(*child_depth)
                            }
                            Some(b'}') => {
                                p.bump();
                                AttachAction::Close
                            }
                            _ => {
                                let (byte, line, col) = p.pos_meta(p.position());
                                return Err(Error::ExpectedCommaOrObjectEnd { byte, line, col });
                            }
                        }
                    }
                };
                match action {
                    AttachAction::ParseNext(depth) => {
                        next_depth = depth;
                        continue 'parse;
                    }
                    AttachAction::Close => {
                        let frame = state
                            .frames
                            .pop()
                            .expect("iterative JSON frame stack became empty");
                        state.completed = Some(frame.finish());
                    }
                }
            }
        }
    }
    fn parse_number_value(p: &mut super::json::Parser<'_>) -> Result<Value, Error> {
        let s = p.input();
        let bytes = s.as_bytes();
        let start = p.position();
        let mut i = start;
        let len = bytes.len();
        let mut neg = false;
        if i < len && bytes[i] == b'-' {
            neg = true;
            i += 1;
        }
        let int_start = i;
        let mut saw = false;
        while i < len && bytes[i].is_ascii_digit() {
            saw = true;
            i += 1;
        }
        if !saw {
            let (byte, line, col) = p.pos_meta(i.min(len));
            return Err(Error::ExpectedDigits { byte, line, col });
        }
        if bytes[int_start] == b'0' && i > int_start + 1 {
            return Err(p.err_at(int_start + 1, Parser::LEADING_ZERO_MSG));
        }
        let mut is_float = false;
        if i < len && bytes[i] == b'.' {
            is_float = true;
            i += 1;
            let mut has_frac = false;
            while i < len && bytes[i].is_ascii_digit() {
                has_frac = true;
                i += 1;
            }
            if !has_frac {
                let (byte, line, col) = p.pos_meta(i.min(len));
                return Err(Error::ExpectedFracDigits { byte, line, col });
            }
        }
        if i < len && (bytes[i] == b'e' || bytes[i] == b'E') {
            is_float = true;
            i += 1;
            if i < len && (bytes[i] == b'+' || bytes[i] == b'-') {
                i += 1;
            }
            let mut has_exp = false;
            while i < len && bytes[i].is_ascii_digit() {
                has_exp = true;
                i += 1;
            }
            if !has_exp {
                let (byte, line, col) = p.pos_meta(i.min(len));
                return Err(Error::ExpectedExpDigits { byte, line, col });
            }
        }
        let num_slice = &s[start..i];
        p.i = i;
        if is_float {
            let v: f64 = num_slice.parse().map_err(|_| {
                let (byte, line, col) = p.pos_meta(p.position());
                Error::WithPos {
                    msg: "float parse",
                    byte,
                    line,
                    col,
                }
            })?;
            let n = Number::from_f64(v).ok_or_else(|| {
                let (byte, line, col) = p.pos_meta(p.position());
                Error::WithPos {
                    msg: "NaN/Inf",
                    byte,
                    line,
                    col,
                }
            })?;
            return Ok(Value::Number(n));
        }
        if neg && &s[int_start..i] == "0" {
            let n = Number::from_f64(-0.0).ok_or_else(|| {
                let (byte, line, col) = p.pos_meta(p.position());
                Error::WithPos {
                    msg: "NaN/Inf",
                    byte,
                    line,
                    col,
                }
            })?;
            return Ok(Value::Number(n));
        }
        let digits = &s[int_start..i];
        if !neg {
            if let Ok(u) = digits.parse::<u64>() {
                return Ok(Value::Number(Number::from(u)));
            }
            if let Ok(u) = digits.parse::<u128>() {
                return Ok(Value::Number(Number::from(u)));
            }
        } else if let Ok(u) = digits.parse::<u64>() {
            if u == (i64::MAX as u64) + 1 {
                return Ok(Value::Number(Number::from(i64::MIN)));
            }
            if u <= i64::MAX as u64 {
                let v = -(u as i64);
                return Ok(Value::Number(Number::from(v)));
            }
        }
        let (byte, line, col) = p.pos_meta(p.position());
        Err(Error::WithPos {
            msg: "integer out of range",
            byte,
            line,
            col,
        })
    }
    /// Convenience: parse a JSON `Value` from a byte slice.
    pub fn from_slice_value(bytes: &[u8]) -> Result<Value, Error> {
        let s = std::str::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)?;
        parse_value(s)
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::json;
        #[test]
        fn core_resource_errors_roundtrip_exact_fields_without_fresh_scope() {
            use crate::core::{
                DecodeAttemptErrorKind, DecodeResourceError, classify_decode_attempt,
            };
            let originals = [
                DecodeResourceError::ArchiveLengthExceeded {
                    length: 29,
                    limit: 23,
                },
                DecodeResourceError::SequenceLengthExceeded {
                    length: 7,
                    limit: 5,
                },
                DecodeResourceError::FieldLengthExceeded {
                    length: 19,
                    limit: 17,
                },
                DecodeResourceError::TotalElementsExceeded {
                    attempted: 13,
                    limit: 11,
                },
                DecodeResourceError::TotalAllocationExceeded {
                    attempted: 137,
                    limit: 131,
                },
                DecodeResourceError::AllocationFailed { bytes: 149 },
                DecodeResourceError::NestingDepthExceeded {
                    depth: 3,
                    limit: 2,
                    context: "typed JSON fixture",
                },
            ];
            for original in originals {
                let implicit = Error::from(crate::Error::from(original));
                assert!(
                    implicit.is_decode_resource_limit(),
                    "JSON must retain every actual resource refusal field without a scope"
                );
                assert_eq!(
                    implicit.into_core_error().decode_resource_error(),
                    Some(original),
                    "JSON must retain every actual resource refusal field without a scope"
                );
                let error = Error::from_decode_resource(original.into());
                assert!(error.is_decode_resource_limit());
                let restored = error.into_core_error();
                assert_eq!(
                    restored.decode_resource_error(),
                    Some(original),
                    "JSON must retain every actual resource refusal field without a scope"
                );
                let expected = if matches!(original, DecodeResourceError::AllocationFailed { .. }) {
                    DecodeAttemptErrorKind::Allocator
                } else {
                    DecodeAttemptErrorKind::Invalid
                };
                assert_eq!(
                    classify_decode_attempt(|| Err::<(), _>(restored))
                        .unwrap_err()
                        .kind(),
                    expected,
                    "copied resource fields cannot establish an enclosing observer origin"
                );
            }
        }
        #[test]
        fn non_resource_core_errors_cannot_become_json_allocator_refusals() {
            use crate::core::{DecodeAttemptErrorKind, classify_decode_attempt};
            for original in [crate::Error::InvalidMagic, crate::Error::LengthMismatch] {
                let diagnostic = original.to_string();
                let error = Error::from_decode_resource(original);
                assert!(
                    !error.is_decode_resource_limit(),
                    "malformed input is not allocation pressure"
                );
                assert_eq!(error.to_string(), diagnostic);
                let error = error.into_core_error();
                assert!(error.decode_resource_error().is_none());
                assert_eq!(
                    classify_decode_attempt(|| Err::<(), _>(error))
                        .unwrap_err()
                        .kind(),
                    DecodeAttemptErrorKind::Invalid
                );
            }
        }
        #[test]
        fn direct_json_parser_retains_unscoped_fields_and_same_input_retry() {
            let pool = iroha_allocation::AllocationBudget::new(65_536);
            let limits =
                crate::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
            let original = crate::core::DecodeBudgetContext::try_new_owned(limits, &pool).unwrap();
            let baseline = pool.reserved_bytes();
            let input = r#""retained""#;
            let refusal = original
                .with(|| Parser::new(input).parse_string())
                .unwrap_err();
            assert_eq!(
                refusal.into_core_error().decode_resource_error(),
                Some(crate::core::DecodeResourceError::TotalAllocationExceeded {
                    attempted: 8,
                    limit: 0
                }),
                "the actual direct parser must preserve its exact unobserved allocation refusal"
            );
            assert_eq!(pool.reserved_bytes(), baseline);
            assert_eq!(Parser::new(input).parse_string().unwrap(), "retained");
            drop(original);
            assert_eq!(pool.reserved_bytes(), 0);
        }
        #[test]
        fn json_resource_conversion_keeps_scoped_identity_and_rejects_saved_origin() {
            use crate::core::{DecodeAttemptErrorKind, classify_decode_attempt};
            let pool = iroha_allocation::AllocationBudget::new(65_536);
            let limits =
                crate::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
            let original = crate::core::DecodeBudgetContext::try_new_owned(limits, &pool).unwrap();
            let baseline = pool.reserved_bytes();
            let mut saved = None;
            let refusal = original
                .with(|| {
                    classify_decode_attempt(|| {
                        let error = crate::core::reserve_decode_allocation(1).unwrap_err();
                        let crate::Error::ScopedDecodeResource(origin) = &error else {
                            panic!("genuine original observer error");
                        };
                        saved = Some(origin.clone());
                        Err::<(), _>(Error::from_decode_resource(error).into_core_error())
                    })
                })
                .unwrap_err();
            assert_eq!(refusal.kind(), DecodeAttemptErrorKind::EnclosingLimit);
            let crate::Error::ScopedDecodeResource(restored) = refusal.into_error() else {
                panic!("JSON conversion must retain its original private scope");
            };
            let saved = saved.unwrap();
            assert_eq!(restored, saved);
            let replay = original
                .with(|| {
                    classify_decode_attempt(|| {
                        drop(crate::core::reserve_decode_allocation(1).unwrap_err());
                        Err::<(), _>(
                            Error::from_decode_resource(crate::Error::ScopedDecodeResource(saved))
                                .into_core_error(),
                        )
                    })
                })
                .unwrap_err();
            assert_eq!(replay.kind(), DecodeAttemptErrorKind::Invalid);
            drop(replay);
            drop(restored);
            assert_eq!(pool.reserved_bytes(), baseline);
            drop(original);
            assert_eq!(pool.reserved_bytes(), 0);
        }
        #[test]
        fn owned_value_decode_depth_guard_is_bounded_and_restores() {
            let guards = (0..crate::core::MAX_VALUE_NESTING_DEPTH)
                .map(|_| OwnedValueDecodeDepthGuard::enter().expect("depth within JSON limit"))
                .collect::<Vec<_>>();
            assert!(matches!(
                OwnedValueDecodeDepthGuard::enter(),
                Err(Error::NestingDepthExceeded {
                    depth,
                    limit: crate::core::MAX_VALUE_NESTING_DEPTH,
                    context: "owned JSON value",
                }) if depth == crate::core::MAX_VALUE_NESTING_DEPTH + 1
            ));
            drop(guards);
            OwnedValueDecodeDepthGuard::enter().expect("failed guard must restore JSON depth");
        }
        #[test]
        fn value_parser_enforces_structural_nesting_limit() {
            let at_limit = format!(
                "{}null{}",
                "[".repeat(MAX_JSON_VALUE_NESTING_DEPTH - 1),
                "]".repeat(MAX_JSON_VALUE_NESTING_DEPTH - 1)
            );
            let value = parse_value(&at_limit).expect("JSON nesting at the limit must decode");
            drop_json_value_iteratively(value);
            let over_limit = format!(
                "{}null{}",
                "[".repeat(MAX_JSON_VALUE_NESTING_DEPTH),
                "]".repeat(MAX_JSON_VALUE_NESTING_DEPTH)
            );
            match parse_value(&over_limit) {
                Err(Error::NestingDepthExceeded {
                    depth,
                    limit: MAX_JSON_VALUE_NESTING_DEPTH,
                    context: "JSON value",
                }) if depth == MAX_JSON_VALUE_NESTING_DEPTH + 1 => {}
                Ok(value) => {
                    drop_json_value_iteratively(value);
                    panic!("owned parser accepted over-limit nesting");
                }
                Err(error) => panic!("owned parser returned wrong over-limit error: {error}"),
            }
            assert!(matches!(
                validate_json(&over_limit),
                Err(Error::NestingDepthExceeded {
                    depth,
                    limit: MAX_JSON_VALUE_NESTING_DEPTH,
                    context: "JSON value",
                }) if depth == MAX_JSON_VALUE_NESTING_DEPTH + 1
            ));
        }
        #[test]
        fn iterative_skip_enforces_structural_nesting_limit() {
            let at_limit = format!(
                "{}null{}",
                "[".repeat(MAX_JSON_VALUE_NESTING_DEPTH - 1),
                "]".repeat(MAX_JSON_VALUE_NESTING_DEPTH - 1)
            );
            Parser::new(&at_limit)
                .skip_value()
                .expect("iterative skip must accept JSON nesting at the limit");
            let over_limit = format!(
                "{}null{}",
                "[".repeat(MAX_JSON_VALUE_NESTING_DEPTH),
                "]".repeat(MAX_JSON_VALUE_NESTING_DEPTH)
            );
            assert!(matches!(
                Parser::new(&over_limit).skip_value(),
                Err(Error::NestingDepthExceeded {
                    depth,
                    limit: MAX_JSON_VALUE_NESTING_DEPTH,
                    context: "JSON value",
                }) if depth == MAX_JSON_VALUE_NESTING_DEPTH + 1
            ));
        }
        #[test]
        fn tape_walker_skip_reuses_strict_bounded_value_walk() {
            let at_limit = format!(
                "{}null{}",
                "[".repeat(MAX_JSON_VALUE_NESTING_DEPTH - 1),
                "]".repeat(MAX_JSON_VALUE_NESTING_DEPTH - 1)
            );
            let mut walker = TapeWalker::new(&at_limit);
            walker
                .skip_value()
                .expect("fast skip must accept JSON nesting at the limit");
            assert_eq!(walker.raw_pos(), at_limit.len());
            let over_limit = format!(
                "{}null{}",
                "[".repeat(MAX_JSON_VALUE_NESTING_DEPTH),
                "]".repeat(MAX_JSON_VALUE_NESTING_DEPTH)
            );
            let mut walker = TapeWalker::new(&over_limit);
            assert!(matches!(
                walker.skip_value(),
                Err(Error::NestingDepthExceeded {
                    depth,
                    limit: MAX_JSON_VALUE_NESTING_DEPTH,
                    context: "JSON value",
                }) if depth == MAX_JSON_VALUE_NESTING_DEPTH + 1
            ));
            for malformed in ["[}", r#"{"key":]}"#, "[1 2]", r#"{"key":1,"key":2}"#] {
                let mut walker = TapeWalker::new(malformed);
                assert!(
                    walker.skip_value().is_err(),
                    "fast skip accepted malformed JSON {malformed:?}"
                );
            }
        }
        #[test]
        fn canonical_document_depth_scan_is_quote_aware_and_caps_at_first_failure() {
            assert_eq!(document_json_value_depth("   \n\t"), 0);
            assert_eq!(document_json_value_depth("null"), 1);
            assert_eq!(document_json_value_depth("{}"), 1);
            assert_eq!(
                document_json_value_depth(r#"{"text":"[[[{{{]]]}}}"}"#),
                2,
                "container punctuation inside a JSON string must not affect depth"
            );
            assert_eq!(
                document_json_value_depth(r#"{"text":"\\\"[[["}"#),
                2,
                "an escaped quote must keep following punctuation inside the string"
            );
            assert_eq!(
                document_json_value_depth(r#"{"text":"\\\\","nested":[null]}"#),
                3,
                "an even backslash run must leave the following quote unescaped"
            );
            let far_over_limit = format!(
                "{}null{}",
                "[".repeat(MAX_JSON_VALUE_NESTING_DEPTH + 64),
                "]".repeat(MAX_JSON_VALUE_NESTING_DEPTH + 64)
            );
            assert_eq!(
                document_json_value_depth(&far_over_limit),
                MAX_JSON_VALUE_NESTING_DEPTH + 1,
                "depth errors must report the first forbidden level"
            );
        }
        #[test]
        fn reader_enforces_complete_document_depth() {
            let at_limit = format!(
                "{}null{}",
                "[".repeat(MAX_JSON_VALUE_NESTING_DEPTH - 1),
                "]".repeat(MAX_JSON_VALUE_NESTING_DEPTH - 1)
            );
            let mut reader = Reader::new(&at_limit);
            let mut token_count = 0_usize;
            while reader
                .next_token()
                .expect("Reader must accept a document at the depth limit")
                .is_some()
            {
                token_count += 1;
            }
            assert_eq!(token_count, 2 * MAX_JSON_VALUE_NESTING_DEPTH - 1);
            let over_limit = format!(
                "{}null{}",
                "[".repeat(MAX_JSON_VALUE_NESTING_DEPTH),
                "]".repeat(MAX_JSON_VALUE_NESTING_DEPTH)
            );
            let mut reader = Reader::new(&over_limit);
            assert!(matches!(
                reader.next_token(),
                Err(Error::NestingDepthExceeded {
                    depth,
                    limit: MAX_JSON_VALUE_NESTING_DEPTH,
                    context: "JSON value",
                }) if depth == MAX_JSON_VALUE_NESTING_DEPTH + 1
            ));
        }
        #[test]
        fn strict_validator_accounts_for_an_enclosing_document_depth() {
            let root_depth = 4;
            let wrappers = MAX_JSON_VALUE_NESTING_DEPTH - root_depth;
            let at_limit = format!("{}null{}", "[".repeat(wrappers), "]".repeat(wrappers));
            validate_json_at_depth(&at_limit, root_depth)
                .expect("fragment at the enclosing-document depth boundary must pass");
            let over_limit = format!("[{at_limit}]");
            assert!(matches!(
                validate_json_at_depth(&over_limit, root_depth),
                Err(Error::NestingDepthExceeded {
                    depth,
                    limit: MAX_JSON_VALUE_NESTING_DEPTH,
                    context: "JSON value",
                }) if depth == MAX_JSON_VALUE_NESTING_DEPTH + 1
            ));
            assert_eq!(
                validate_json_at_depth("null", 0)
                    .expect_err("zero is not a valid JSON root depth")
                    .to_string(),
                "JSON root depth must be at least 1"
            );
        }
        #[test]
        fn strict_validator_matches_owned_parser_for_edge_grammar() {
            for valid in [
                "null",
                "-0",
                "-0.0",
                "1.25e-3",
                r#""\uD834\uDD1E""#,
                r#"{"a":1,"b":[true,false,null]}"#,
            ] {
                validate_json(valid).unwrap_or_else(|error| {
                    panic!("validator rejected valid JSON {valid:?}: {error}")
                });
                let value = parse_value(valid).unwrap_or_else(|error| {
                    panic!("owned parser rejected valid JSON {valid:?}: {error}")
                });
                drop_json_value_iteratively(value);
            }
            for invalid in [
                "01",
                "1.",
                "1e",
                r#""\q""#,
                r#""\u12xz""#,
                r#""\uD834""#,
                r#""\uDD1E""#,
                r#"{"a":1,"a":2}"#,
                r#"{"a":1,"\u0061":2}"#,
                "[1,]",
                r#"{"a":1,}"#,
                "true false",
            ] {
                assert!(
                    validate_json(invalid).is_err(),
                    "validator accepted invalid JSON {invalid:?}"
                );
                assert!(
                    parse_value(invalid).is_err(),
                    "owned parser accepted invalid JSON {invalid:?}"
                );
            }
            for invalid in [r#""\uDD1E""#, r#"{"a":1,"a":}"#] {
                let validator_error =
                    validate_json(invalid).expect_err("validator must reject diagnostic fixture");
                let parser_error =
                    parse_value(invalid).expect_err("owned parser must reject diagnostic fixture");
                assert_eq!(
                    validator_error.to_string(),
                    parser_error.to_string(),
                    "validator/parser diagnostic drift for {invalid:?}"
                );
            }
        }
        #[test]
        fn iterative_parser_and_error_cleanup_fit_a_128k_stack() {
            let worker = std::thread::Builder::new()
                .name("norito-json-iterative-boundary".into())
                .stack_size(128 * 1024)
                .spawn(|| -> Result<(), String> {
                    let wrappers = crate::core::MAX_VALUE_NESTING_DEPTH - 1;
                    let at_255 = format!("{}null{}", "[".repeat(wrappers), "]".repeat(wrappers));
                    validate_json(&at_255).map_err(|error| error.to_string())?;
                    let value = parse_value(&at_255).map_err(|error| error.to_string())?;
                    let mut cursor = &value;
                    for _ in 0..wrappers {
                        let Value::Array(items) = cursor else {
                            return Err("boundary JSON stopped being an array".to_owned());
                        };
                        if items.len() != 1 {
                            return Err("boundary JSON array is not unary".to_owned());
                        }
                        cursor = &items[0];
                    }
                    if !cursor.is_null() {
                        return Err("boundary JSON leaf is not null".to_owned());
                    }
                    let rendered = to_json(&value).map_err(|error| error.to_string())?;
                    if rendered != at_255 {
                        return Err("iterative JSON writer changed the boundary value".to_owned());
                    }
                    drop_json_value_iteratively(value);
                    let value = from_json::<Value>(&at_255).map_err(|error| error.to_string())?;
                    let raw = from_value::<RawValue>(value).map_err(|error| error.to_string())?;
                    if raw.get() != at_255 {
                        return Err("owned Value conversion changed boundary JSON".to_owned());
                    }
                    let trailing = format!("{at_255} null");
                    match from_json::<Value>(&trailing) {
                        Err(Error::TrailingCharacters { .. }) => {}
                        Ok(value) => {
                            drop_json_value_iteratively(value);
                            return Err(
                                "typed Value parser accepted trailing characters".to_owned()
                            );
                        }
                        Err(error) => {
                            return Err(format!(
                                "typed Value parser returned the wrong trailing error: {error}"
                            ));
                        }
                    }
                    let invalid_256th_wrapper = format!("[{at_255},]");
                    if validate_json(&invalid_256th_wrapper).is_ok() {
                        return Err("validator accepted a trailing comma".to_owned());
                    }
                    if let Ok(value) = parse_value(&invalid_256th_wrapper) {
                        drop_json_value_iteratively(value);
                        return Err("owned parser accepted a trailing comma".to_owned());
                    }
                    let over_limit = format!(
                        "{}null{}",
                        "[".repeat(MAX_JSON_VALUE_NESTING_DEPTH),
                        "]".repeat(MAX_JSON_VALUE_NESTING_DEPTH)
                    );
                    match parse_value(&over_limit) {
                        Err(Error::NestingDepthExceeded { .. }) => {}
                        Ok(value) => {
                            drop_json_value_iteratively(value);
                            return Err("owned parser accepted over-limit nesting".to_owned());
                        }
                        Err(error) => {
                            return Err(format!(
                                "owned parser returned the wrong over-limit error: {error}"
                            ));
                        }
                    }
                    Ok(())
                })
                .map_err(|error| error.to_string())
                .expect("spawn 128KiB JSON parser test");
            worker
                .join()
                .expect("128KiB JSON parser thread")
                .expect("iterative JSON parser boundary");
        }
        #[test]
        fn parse_value_str_and_bytes_match() {
            let s = "{\"k\": [1, true, \"x\"]}";
            let v1 = parse_value(s).expect("parse_value");
            let v2 = from_slice_value(s.as_bytes()).expect("from_slice_value");
            assert_eq!(v1, v2);
        }
        #[test]
        fn json_serialize_from_reference() {
            let value = "hello".to_string();
            let rendered = to_json(&&value).expect("serialize reference");
            assert_eq!(rendered, "\"hello\"");
        }
        #[test]
        fn finite_f64_json_roundtrips_exact_bits_and_overflow_is_rejected() {
            for value in [
                0.0,
                -0.0,
                1.0,
                -1.0,
                f64::from_bits(1),
                f64::MIN_POSITIVE,
                core::f64::consts::PI,
                f64::MAX,
                f64::MIN,
            ] {
                let encoded = to_json(&value).expect("finite float must serialize");
                let decoded =
                    from_json::<f64>(&encoded).expect("serialized finite float must decode");
                assert_eq!(
                    decoded.to_bits(),
                    value.to_bits(),
                    "float JSON changed exact bits for {value:?} via {encoded}"
                );
                let mut walker = TapeWalker::new(&encoded);
                let fast_decoded = walker
                    .parse_f64_inline()
                    .expect("fast parser must accept serialized finite float");
                assert_eq!(
                    fast_decoded.to_bits(),
                    value.to_bits(),
                    "fast float JSON changed exact bits for {value:?} via {encoded}"
                );
            }
            for overflow in ["1e309", "-1e309"] {
                assert!(
                    from_json::<f64>(overflow).is_err(),
                    "typed parser accepted non-finite overflow {overflow}"
                );
                let mut walker = TapeWalker::new(overflow);
                assert!(
                    walker.parse_f64_inline().is_err(),
                    "fast parser accepted non-finite overflow {overflow}"
                );
            }
        }
        #[test]
        fn fast_writer_handles_reference_fields() {
            use crate::derive::JsonSerialize;
            #[derive(JsonSerialize)]
            struct Borrowed<'a> {
                field: &'a u32,
            }
            let inner = 42u32;
            let borrowed = Borrowed { field: &inner };
            let rendered = to_json(&borrowed).expect("serialize borrowed struct");
            assert_eq!(rendered, "{\"field\":42}");
        }
        #[test]
        fn object_macro_basic() {
            let value = json!({"key": 1u32, "flag": true});
            let string = to_json(&value).expect("json render");
            assert_eq!(string, "{\"flag\":true,\"key\":1}");
            let alt = norito::json!({"another": 2u32});
            let alt_string = to_json(&alt).expect("json render alt");
            assert_eq!(alt_string, "{\"another\":2}");
        }
        #[test]
        fn helpers_convert_to_value() {
            let value = crate::json::to_value(&42u32).expect("to_value");
            assert_eq!(
                value,
                crate::json::Value::Number(crate::json::Number::U64(42))
            );
            let array = crate::json::array([1u32, 2u32]).expect("array helper");
            assert_eq!(
                array,
                crate::json::Value::Array(vec![json!(1u32), json!(2u32)])
            );
            let object = crate::json::object([
                ("alpha", crate::json::Value::from(1u32)),
                ("beta", crate::json::Value::from(true)),
            ])
            .expect("object helper");
            assert_eq!(object["alpha"], json!(1u32));
            assert_eq!(object["beta"], json!(true));
        }
        #[test]
        fn pretty_writer_handles_multibyte_strings() {
            let sample: String = [
                '\u{ff87}', '\u{ff88}', '\u{ff8a}', '\u{ff8b}', '\u{ff8c}', '\u{ff8d}', '\u{ff8e}',
                '\u{ff8f}', '\u{ff90}', '\u{ff91}', '\u{ff92}', '\u{ff93}', '\u{ff94}', '\u{ff95}',
                '\u{ff96}', '\u{ff97}',
            ]
            .iter()
            .copied()
            .collect();
            let value =
                json::object([("input", Value::from(sample.clone()))]).expect("object render");
            let rendered = json::to_string_pretty(&value).expect("json render with multibyte");
            let reparsed: Value = json::from_str(&rendered).expect("parse pretty-printed output");
            assert_eq!(reparsed["input"], Value::from(sample));
        }
        #[test]
        fn string_writer_emits_utf8_for_astral_scalars() {
            let mut rendered = String::new();
            write_json_string("emoji 😀", &mut rendered);
            assert_eq!(rendered, "\"emoji 😀\"");
        }
        #[test]
        fn string_writer_emits_utf8_for_line_separators() {
            let sample = format!("left{}\u{2029}right", '\u{2028}');
            let mut rendered = String::new();
            write_json_string(&sample, &mut rendered);
            assert_eq!(rendered, format!("\"{sample}\""));
        }
        #[test]
        fn string_writer_escapes_identically_on_every_path() {
            // Short strings take the scalar path; long ASCII strings take the
            // SIMD paths where the build enables them. All must agree.
            for padding in [0usize, 7, 15, 16, 31, 32, 63, 64] {
                let pad = "x".repeat(padding);
                let input = format!("{pad}a\u{08}b\u{0C}c\u{0B}\"\\\n{pad}\u{08}\u{0C}");
                let expected = format!("\"{pad}a\\bb\\fc\\u000b\\\"\\\\\\n{pad}\\b\\f\"");
                let mut rendered = String::new();
                write_json_string(&input, &mut rendered);
                assert_eq!(rendered, expected, "padding {padding}");
                let mut charwise = String::new();
                write_json_string_charwise(&input, &mut charwise);
                assert_eq!(charwise, expected, "charwise padding {padding}");
            }
        }
        #[test]
        fn string_writer_uses_lowercase_hex_for_control_escapes() {
            let mut rendered = String::new();
            write_json_string("a\u{000b}b", &mut rendered);
            assert_eq!(rendered, "\"a\\u000bb\"");
        }
        #[test]
        fn unescape_json_string_preserves_utf8_bytes() {
            let raw = format!("price: {}\\nend", '\u{00A2}');
            let out = unescape_json_string(&raw).expect("unescape");
            let expected = format!("price: {}\nend", '\u{00A2}');
            assert_eq!(out, expected);
        }
        #[test]
        fn parse_u64_rejects_leading_zero() {
            let mut parser = Parser::new("01");
            let err = parser
                .parse_u64()
                .expect_err("leading zero should be rejected");
            match err {
                Error::WithPos { msg, .. } => assert_eq!(msg, Parser::LEADING_ZERO_MSG),
                other => panic!("unexpected error variant: {other:?}"),
            }
        }
        #[test]
        fn parse_i64_from_parser_rejects_leading_zero() {
            let mut parser = Parser::new("-012");
            let err = parse_i64_from_parser(&mut parser)
                .expect_err("leading zero in signed number should be rejected");
            match err {
                Error::WithPos { msg, .. } => assert_eq!(msg, Parser::LEADING_ZERO_MSG),
                other => panic!("unexpected error variant: {other:?}"),
            }
        }
        #[test]
        fn parse_number_token_rejects_leading_zero() {
            for sample in ["01", "-012"] {
                let mut parser = Parser::new(sample);
                let err = parse_number_token(&mut parser)
                    .expect_err("leading zero in Value parser should be rejected");
                match err {
                    Error::WithPos { msg, .. } => assert_eq!(msg, Parser::LEADING_ZERO_MSG),
                    other => panic!("unexpected error variant for {sample:?}: {other:?}"),
                }
            }
        }
        #[test]
        fn parse_value_rejects_leading_zero() {
            for sample in ["01", "-012"] {
                let err = parse_value(sample).expect_err("leading zero should be rejected");
                match err {
                    Error::WithPos { msg, .. } => assert_eq!(msg, Parser::LEADING_ZERO_MSG),
                    other => panic!("unexpected error variant for {sample:?}: {other:?}"),
                }
            }
        }
    }
    /// Write JSON to an `io::Write` sink.
    #[cfg(feature = "json-std-io")]
    pub fn to_writer<W: std::io::Write, T: JsonSerialize>(
        mut writer: W,
        value: &T,
    ) -> Result<(), Error> {
        let json = to_json(value)?;
        writer
            .write_all(json.as_bytes())
            .map_err(|e| Error::Message(e.to_string()))
    }
    /// Write pretty-printed JSON to an `io::Write` sink.
    #[cfg(feature = "json-std-io")]
    pub fn to_writer_pretty<W: std::io::Write, T: JsonSerialize>(
        mut writer: W,
        value: &T,
    ) -> Result<(), Error> {
        let json = to_json_pretty(value)?;
        writer
            .write_all(json.as_bytes())
            .map_err(|e| Error::Message(e.to_string()))
    }
    /// Parse JSON from an `io::Read` source.
    #[cfg(feature = "json-std-io")]
    pub fn from_reader<R: std::io::Read, T: JsonDeserialize>(mut reader: R) -> Result<T, Error> {
        let mut buf = String::new();
        reader
            .read_to_string(&mut buf)
            .map_err(|e| Error::Message(e.to_string()))?;
        from_str(&buf)
    }
    /// Simple bump arena for unescaped string storage.
    pub struct Arena {
        buf: Vec<u8>,
    }
    impl Default for Arena {
        fn default() -> Self {
            Self::new()
        }
    }
    impl Arena {
        pub fn new() -> Self {
            Self { buf: Vec::new() }
        }
        pub fn clear(&mut self) {
            self.buf.clear();
        }
        fn alloc_str(&mut self, bytes: &[u8]) -> &str {
            let start = self.buf.len();
            self.buf.extend_from_slice(bytes);
            let end = self.buf.len();
            // SAFETY: callers must guarantee valid UTF‑8 bytes; we return an immutable
            // slice to the exact range we just appended so future arena growth does not
            // change the visible contents or rely on tail length.
            unsafe { std::str::from_utf8_unchecked(&self.buf[start..end]) }
        }
    }
    /// Serialize a JSON string with proper escaping into `out`.
    fn write_json_string_charwise(s: &str, out: &mut String) {
        out.reserve(s.len() + 2);
        out.push('"');
        for ch in s.chars() {
            match ch {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                '\u{08}' => out.push_str("\\b"),
                '\u{0C}' => out.push_str("\\f"),
                c if (c as u32) < 0x20 => {
                    out.push_str("\\u00");
                    const HEX: &[u8; 16] = b"0123456789abcdef";
                    out.push(HEX[((c as u32 >> 4) & 0xF) as usize] as char);
                    out.push(HEX[(c as u32 & 0xF) as usize] as char);
                }
                _ => out.push(ch),
            }
        }
        out.push('"');
    }
    pub fn write_json_string(s: &str, out: &mut String) {
        if !s.is_ascii() {
            write_json_string_charwise(s, out);
            return;
        }
        // aarch64 NEON fast path using LUT classification + chunked copy
        #[cfg(all(
            feature = "simd-accel",
            target_arch = "aarch64",
            target_feature = "neon"
        ))]
        {
            unsafe fn write_neon(s: &str, out: &mut String) {
                use core::arch::aarch64::*;
                unsafe {
                    out.reserve(s.len() + 2);
                    out.push('"');
                    let bytes = s.as_bytes();
                    let mut i = 0usize;
                    let lut_lo = vld1q_u8([0u8; 16].as_ptr()); // not used; we do compares instead
                    let _ = lut_lo; // silence unused
                    while i < bytes.len() {
                        // Load 16 bytes or less
                        let rem = bytes.len() - i;
                        if rem >= 16 {
                            let v = vld1q_u8(bytes.as_ptr().add(i));
                            let is_quote = vceqq_u8(v, vdupq_n_u8(b'"'));
                            let is_bslash = vceqq_u8(v, vdupq_n_u8(b'\\'));
                            let ctrl = vcltq_u8(v, vdupq_n_u8(0x20));
                            let specials = vorrq_u8(vorrq_u8(is_quote, is_bslash), ctrl);
                            let mut mask = 0u16;
                            let msb = vshrq_n_u8(specials, 7);
                            let mut tmp = [0u8; 16];
                            vst1q_u8(tmp.as_mut_ptr(), msb);
                            for (j, value) in tmp.iter().enumerate() {
                                mask |= ((value & 1) as u16) << j;
                            }
                            if mask == 0 {
                                // No specials in this block; copy raw
                                out.push_str(std::str::from_utf8_unchecked(&bytes[i..i + 16]));
                                i += 16;
                                continue;
                            } else {
                                // Copy up to first special, then handle escape
                                let tz = mask.trailing_zeros() as usize;
                                if tz > 0 {
                                    out.push_str(std::str::from_utf8_unchecked(&bytes[i..i + tz]));
                                    i += tz;
                                }
                            }
                        }
                        // Scalar escape for the special
                        let b = bytes[i];
                        match b {
                            b'"' => out.push_str("\\\""),
                            b'\\' => out.push_str("\\\\"),
                            b'\n' => out.push_str("\\n"),
                            b'\r' => out.push_str("\\r"),
                            b'\t' => out.push_str("\\t"),
                            0x08 => out.push_str("\\b"),
                            0x0C => out.push_str("\\f"),
                            c if c < 0x20 => {
                                out.push_str("\\u00");
                                const HEX: &[u8; 16] = b"0123456789abcdef";
                                out.push(HEX[(c >> 4) as usize] as char);
                                out.push(HEX[(c & 0x0F) as usize] as char);
                            }
                            _ => {
                                // Should not happen; caught by NEON mask as non-special
                                out.push(b as char);
                            }
                        }
                        i += 1;
                    }
                    out.push('"');
                }
            }
            unsafe {
                write_neon(s, out);
            }
        }
        // x86_64 AVX2 fast path using vector compares + movemask
        #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
        {
            unsafe fn write_avx2(s: &str, out: &mut String) {
                use core::arch::x86_64::*;
                unsafe {
                    out.reserve(s.len() + 2);
                    out.push('"');
                    let bytes = s.as_bytes();
                    let mut i = 0usize;
                    let v_quote = _mm256_set1_epi8(b'"' as i8);
                    let v_bslash = _mm256_set1_epi8(b'\\' as i8);
                    while i < bytes.len() {
                        let rem = bytes.len() - i;
                        if rem >= 32 {
                            let v = _mm256_loadu_si256(bytes.as_ptr().add(i) as *const __m256i);
                            let is_q = _mm256_cmpeq_epi8(v, v_quote);
                            let is_b = _mm256_cmpeq_epi8(v, v_bslash);
                            // ctrl < 0x20: compare signed; emulate by subtracting 0x20 and test negative
                            let ctrl = _mm256_cmpgt_epi8(_mm256_set1_epi8(0x20i8), v);
                            let specials = _mm256_or_si256(_mm256_or_si256(is_q, is_b), ctrl);
                            let mask = _mm256_movemask_epi8(specials) as u32;
                            if mask == 0 {
                                out.push_str(std::str::from_utf8_unchecked(&bytes[i..i + 32]));
                                i += 32;
                                continue;
                            } else {
                                let tz = mask.trailing_zeros() as usize;
                                if tz > 0 {
                                    out.push_str(std::str::from_utf8_unchecked(&bytes[i..i + tz]));
                                    i += tz;
                                }
                            }
                        }
                        let b = bytes[i];
                        match b {
                            b'"' => out.push_str("\\\""),
                            b'\\' => out.push_str("\\\\"),
                            b'\n' => out.push_str("\\n"),
                            b'\r' => out.push_str("\\r"),
                            b'\t' => out.push_str("\\t"),
                            0x08 => out.push_str("\\b"),
                            0x0C => out.push_str("\\f"),
                            c if c < 0x20 => {
                                out.push_str("\\u00");
                                const HEX: &[u8; 16] = b"0123456789abcdef";
                                out.push(HEX[(c >> 4) as usize] as char);
                                out.push(HEX[(c & 0x0F) as usize] as char);
                            }
                            _ => out.push(b as char),
                        }
                        i += 1;
                    }
                    out.push('"');
                }
            }
            unsafe {
                write_avx2(s, out);
            }
            return;
        }
        // x86_64 AVX2 runtime path when binary is not compiled with avx2 by default
        #[cfg(all(
            target_arch = "x86_64",
            feature = "simd-accel",
            not(target_feature = "avx2")
        ))]
        {
            if std::is_x86_feature_detected!("avx2") {
                #[target_feature(enable = "avx2")]
                unsafe fn write_avx2_rt(s: &str, out: &mut String) {
                    use core::arch::x86_64::*;
                    unsafe {
                        out.reserve(s.len() + 2);
                        out.push('"');
                        let bytes = s.as_bytes();
                        let mut i = 0usize;
                        let v_quote = _mm256_set1_epi8(b'"' as i8);
                        let v_bslash = _mm256_set1_epi8(b'\\' as i8);
                        while i < bytes.len() {
                            let rem = bytes.len() - i;
                            if rem >= 32 {
                                let v = _mm256_loadu_si256(bytes.as_ptr().add(i) as *const __m256i);
                                let is_q = _mm256_cmpeq_epi8(v, v_quote);
                                let is_b = _mm256_cmpeq_epi8(v, v_bslash);
                                // ctrl < 0x20: compare signed; emulate by subtracting 0x20 and test negative
                                let ctrl = _mm256_cmpgt_epi8(_mm256_set1_epi8(0x20i8), v);
                                let specials = _mm256_or_si256(_mm256_or_si256(is_q, is_b), ctrl);
                                let mask = _mm256_movemask_epi8(specials) as u32;
                                if mask == 0 {
                                    out.push_str(std::str::from_utf8_unchecked(&bytes[i..i + 32]));
                                    i += 32;
                                    continue;
                                } else {
                                    let tz = mask.trailing_zeros() as usize;
                                    if tz > 0 {
                                        out.push_str(std::str::from_utf8_unchecked(
                                            &bytes[i..i + tz],
                                        ));
                                        i += tz;
                                    }
                                }
                            }
                            let b = bytes[i];
                            match b {
                                b'"' => out.push_str("\\\""),
                                b'\\' => out.push_str("\\\\"),
                                b'\n' => out.push_str("\\n"),
                                b'\r' => out.push_str("\\r"),
                                b'\t' => out.push_str("\\t"),
                                0x08 => out.push_str("\\b"),
                                0x0C => out.push_str("\\f"),
                                c if c < 0x20 => {
                                    out.push_str("\\u00");
                                    const HEX: &[u8; 16] = b"0123456789abcdef";
                                    out.push(HEX[(c >> 4) as usize] as char);
                                    out.push(HEX[(c & 0x0F) as usize] as char);
                                }
                                _ => out.push(b as char),
                            }
                            i += 1;
                        }
                        out.push('"');
                    }
                }
                unsafe {
                    write_avx2_rt(s, out);
                }
                return;
            }
        }
        #[cfg(not(any(
            all(
                feature = "simd-accel",
                target_arch = "aarch64",
                target_feature = "neon"
            ),
            all(
                feature = "simd-accel",
                target_arch = "x86_64",
                target_feature = "avx2"
            )
        )))]
        {
            // Scalar fallback: chunked copy + escape
            out.reserve(s.len() + 2);
            out.push('"');
            let bytes = s.as_bytes();
            let mut i = 0usize;
            while i < bytes.len() {
                let mut j = i;
                while j < bytes.len() {
                    let b = bytes[j];
                    if b == b'"' || b == b'\\' || b < 0x20 {
                        break;
                    }
                    j += 1;
                }
                if j > i {
                    out.push_str(unsafe { std::str::from_utf8_unchecked(&bytes[i..j]) });
                }
                if j == bytes.len() {
                    break;
                }
                match bytes[j] {
                    b'"' => out.push_str("\\\""),
                    b'\\' => out.push_str("\\\\"),
                    b'\n' => out.push_str("\\n"),
                    b'\r' => out.push_str("\\r"),
                    b'\t' => out.push_str("\\t"),
                    0x08 => out.push_str("\\b"),
                    0x0C => out.push_str("\\f"),
                    c if c < 0x20 => {
                        out.push_str("\\u00");
                        const HEX: &[u8; 16] = b"0123456789abcdef";
                        out.push(HEX[(c >> 4) as usize] as char);
                        out.push(HEX[(c & 0x0F) as usize] as char);
                    }
                    _ => unreachable!(),
                }
                i = j + 1;
            }
            out.push('"');
        }
    }
    /// A type whose values have one injective canonical JSON object-key text.
    ///
    /// Implementations provide unescaped key text in bounded chunks. The map
    /// serializer applies Norito's canonical JSON string escaping exactly once.
    ///
    /// Composite and optional values intentionally do not implement this trait.
    ///
    /// ```compile_fail
    /// use std::collections::BTreeMap;
    /// let values = BTreeMap::from([(vec![1_u8], 1_u8)]);
    /// let _ = norito::json::to_json(&values);
    /// ```
    ///
    /// ```compile_fail
    /// use std::collections::BTreeMap;
    /// let values = BTreeMap::from([(("left".to_owned(), "right".to_owned()), 1_u8)]);
    /// let _ = norito::json::to_json(&values);
    /// ```
    ///
    /// ```compile_fail
    /// use std::collections::BTreeMap;
    /// let values = BTreeMap::from([(Some("value".to_owned()), 1_u8)]);
    /// let _ = norito::json::to_json(&values);
    /// ```
    pub trait JsonObjectKey {
        /// Visit the canonical unescaped object-key text.
        ///
        /// Concatenating every visited chunk must produce one injective canonical
        /// representation. Implementations can only return errors from `visitor`.
        fn visit_json_key_text<E>(
            &self,
            visitor: impl FnMut(&str) -> Result<(), E>,
        ) -> Result<(), E>;

        /// Visit the key text through a checked serialization path.
        ///
        /// Types whose canonical key conversion can fail override this method.
        fn visit_json_key_text_checked(
            &self,
            visitor: impl FnMut(&str) -> Result<(), BoundedJsonError>,
        ) -> Result<(), BoundedJsonError> {
            self.visit_json_key_text(visitor)
        }
    }

    /// An owned JSON object key that can be reconstructed from canonical key text.
    pub trait JsonObjectKeyOwned: JsonObjectKey + Sized {
        /// Parse one unescaped JSON object-key string.
        fn from_json_key_text(key: &str) -> Result<Self, Error>;
    }

    /// Trait for types that can be serialized to JSON.
    pub trait JsonSerialize {
        /// Serialize `self` into `out` as JSON.
        fn json_serialize(&self, out: &mut String);
        /// Serialize `self` into a checked JSON sink.
        ///
        /// Manual serializers retain their ordinary behaviour but fail closed
        /// for bounded sinks until they explicitly implement this method.
        fn json_serialize_to(&self, out: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
            let Some(unbounded) = out.unbounded_output() else {
                return Err(BoundedJsonError::Unsupported);
            };
            self.json_serialize(unbounded);
            Ok(())
        }
    }
    #[inline]
    fn encode_hex(bytes: &[u8], out: &mut String) {
        const LOOKUP: &[u8; 16] = b"0123456789ABCDEF";
        out.reserve(bytes.len() * 2 + 2);
        out.push('"');
        for &byte in bytes {
            out.push(LOOKUP[(byte >> 4) as usize] as char);
            out.push(LOOKUP[(byte & 0x0f) as usize] as char);
        }
        out.push('"');
    }
    fn decode_hex<const N: usize>(s: &str) -> Result<[u8; N], Error> {
        if s.len() != N * 2 {
            return Err(Error::Message(format!(
                "expected {N} byte hex string, got length {}",
                s.len()
            )));
        }
        let mut out = [0u8; N];
        let bytes = s.as_bytes();
        for i in 0..N {
            let hi = decode_nibble(bytes[2 * i]).ok_or_else(|| {
                Error::Message(format!(
                    "invalid hex digit `{}` at position {}",
                    bytes[2 * i] as char,
                    2 * i
                ))
            })?;
            let lo = decode_nibble(bytes[2 * i + 1]).ok_or_else(|| {
                Error::Message(format!(
                    "invalid hex digit `{}` at position {}",
                    bytes[2 * i + 1] as char,
                    2 * i + 1
                ))
            })?;
            out[i] = (hi << 4) | lo;
        }
        Ok(out)
    }
    #[inline]
    const fn decode_nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    #[inline]
    fn write_u128_json(out: &mut String, mut v: u128) {
        const BUF_LEN: usize = 39; // ceil(log10(2^128))
        let mut buf = [0u8; BUF_LEN];
        let mut i = buf.len();
        if v == 0 {
            out.push('0');
            return;
        }
        while v > 0 {
            let d = (v % 10) as u8;
            v /= 10;
            i -= 1;
            buf[i] = b'0' + d;
        }
        unsafe {
            out.push_str(std::str::from_utf8_unchecked(&buf[i..]));
        }
    }
    #[inline]
    fn write_u64_json(out: &mut String, v: u64) {
        write_u128_json(out, v as u128)
    }
    #[inline]
    fn write_i64_json(out: &mut String, v: i64) {
        if v >= 0 {
            write_u64_json(out, v as u64);
        } else {
            out.push('-');
            write_u64_json(out, v.unsigned_abs());
        }
    }
    impl<T: JsonDeserialize> JsonDeserialize for Box<T> {
        fn json_deserialize(parser: &mut Parser<'_>) -> Result<Self, Error> {
            let _depth_guard = OwnedValueDecodeDepthGuard::enter()?;
            crate::core::reserve_decode_box_allocation::<T>()
                .map_err(Error::from_decode_resource)?;
            let value = T::json_deserialize(parser)?;
            Ok(Box::new(value))
        }
        fn json_from_value(value: &Value) -> Result<Self, Error> {
            let _depth_guard = OwnedValueDecodeDepthGuard::enter()?;
            crate::core::reserve_decode_box_allocation::<T>()
                .map_err(Error::from_decode_resource)?;
            T::json_from_value(value).map(Box::new)
        }
    }
    impl JsonDeserialize for Box<str> {
        fn json_deserialize(parser: &mut Parser<'_>) -> Result<Self, Error> {
            let string = String::json_deserialize(parser)?;
            Ok(string.into_boxed_str())
        }
        fn json_from_value(value: &Value) -> Result<Self, Error> {
            if let Some(s) = value.as_str() {
                return try_decode_string_copy(s).map(String::into_boxed_str);
            }
            String::json_from_value(value).map(String::into_boxed_str)
        }
    }
    impl JsonObjectKey for Box<str> {
        fn visit_json_key_text<E>(
            &self,
            visitor: impl FnMut(&str) -> Result<(), E>,
        ) -> Result<(), E> {
            self.as_ref().visit_json_key_text(visitor)
        }
    }
    impl JsonObjectKeyOwned for Box<str> {
        fn from_json_key_text(key: &str) -> Result<Self, Error> {
            try_decode_string_copy(key).map(String::into_boxed_str)
        }
    }
    /// Serialize `value` into a compact JSON string.
    pub fn to_json<T: JsonSerialize + ?Sized>(value: &T) -> Result<String, Error> {
        let mut out = String::new();
        value.json_serialize(&mut out);
        Ok(out)
    }
    /// Build a Norito JSON array from an iterator of serializable values.
    pub fn array<T, I>(values: I) -> Result<Value, Error>
    where
        T: JsonSerialize,
        I: IntoIterator<Item = T>,
    {
        let mut out = Vec::new();
        for item in values {
            out.push(to_value(&item)?);
        }
        Ok(Value::Array(out))
    }
    /// Build a Norito JSON object from key/value pairs.
    pub fn object<K, V, I>(pairs: I) -> Result<Value, Error>
    where
        K: Into<String>,
        V: JsonSerialize,
        I: IntoIterator<Item = (K, V)>,
    {
        let mut map = Map::new();
        for (key, value) in pairs {
            map.insert(key.into(), to_value(&value)?);
        }
        Ok(Value::Object(map))
    }
    /// Serialize `value` into a compact JSON string using the fast typed writer.
    ///
    /// Alias for `to_json` kept for symmetry with `to_json_pretty`.
    pub fn to_json_fast<T: JsonSerialize + ?Sized>(value: &T) -> Result<String, Error> {
        to_json(value)
    }
    /// Pretty-print the JSON representation of `value` deterministically.
    ///
    /// Rules:
    /// - Two-space indentation
    /// - Newlines after `,`, `[` and `{` when appropriate
    /// - Canonical escaping preserved from the typed writer
    pub fn to_json_pretty<T: JsonSerialize + ?Sized>(value: &T) -> Result<String, Error> {
        let minified = to_json(value)?;
        Ok(pretty_format_minified_json(&minified))
    }
    /// Pretty-format a minified JSON string without reparsing.
    fn pretty_format_minified_json(input: &str) -> String {
        let bytes = input.as_bytes();
        let mut out = String::with_capacity(input.len() + input.len() / 4);
        let mut indent = 0usize;
        let mut i = 0usize;
        while i < bytes.len() {
            match bytes[i] {
                b' ' | b'\n' | b'\r' | b'\t' => {
                    i += 1; // drop whitespace
                }
                b'"' => {
                    let start = i;
                    i += 1;
                    while i < bytes.len() {
                        match bytes[i] {
                            b'\\' => {
                                i += 1;
                                if i < bytes.len() {
                                    i += 1;
                                }
                            }
                            b'"' => {
                                i += 1;
                                break;
                            }
                            _ => i += 1,
                        }
                    }
                    out.push_str(&input[start..i]);
                }
                b'{' | b'[' => {
                    let open = bytes[i];
                    let close = if open == b'{' { b'}' } else { b']' };
                    if bytes.get(i + 1) == Some(&close) {
                        out.push(open as char);
                        out.push(close as char);
                        i += 2;
                        continue;
                    }
                    out.push(open as char);
                    indent += 1;
                    out.push('\n');
                    for _ in 0..indent {
                        out.push_str("  ");
                    }
                    i += 1;
                }
                b'}' | b']' => {
                    if indent > 0 {
                        indent = indent.saturating_sub(1);
                    }
                    out.push('\n');
                    for _ in 0..indent {
                        out.push_str("  ");
                    }
                    out.push(bytes[i] as char);
                    i += 1;
                }
                b',' => {
                    out.push(',');
                    out.push('\n');
                    for _ in 0..indent {
                        out.push_str("  ");
                    }
                    i += 1;
                }
                b':' => {
                    out.push(':');
                    out.push(' ');
                    i += 1;
                }
                other => {
                    out.push(other as char);
                    i += 1;
                }
            }
        }
        out
    }
    /// Unescape a borrowed JSON string (without surrounding quotes) into an owned `String`.
    ///
    /// Intended for use with `Reader` tokens (`StringBorrowed` and `KeyBorrowed`).
    ///
    /// Escapes → Code Points
    /// - `\"` → `U+0022` (double quote)
    /// - `\\` → `U+005C` (backslash)
    /// - `\/` → `U+002F` (forward slash)
    /// - `\b` → `U+0008` (backspace)
    /// - `\f` → `U+000C` (form feed)
    /// - `\n` → `U+000A` (line feed)
    /// - `\r` → `U+000D` (carriage return)
    /// - `\t` → `U+0009` (tab)
    /// - `\uXXXX` → Unicode code unit; surrogate pairs (`\uD800..\uDBFF` + `\uDC00..\uDFFF`) are combined into a single scalar.
    ///
    /// Errors include invalid hex digits in `\uXXXX`, unexpected/isolated low surrogates, missing low surrogates after a high surrogate, and control
    /// characters (`< 0x20`) appearing unescaped.
    pub fn unescape_json_string(s: &str) -> Result<String, Error> {
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0usize;
        while i < bytes.len() {
            let b = bytes[i];
            i += 1;
            if b != b'\\' {
                if b < 0x20 {
                    return Err(Error::ControlInString {
                        byte: i - 1,
                        line: 1,
                        col: 1,
                    });
                }
                out.push(b);
                continue;
            }
            if i >= bytes.len() {
                return Err(Error::EofEscape {
                    byte: i,
                    line: 1,
                    col: 1,
                });
            }
            let esc = bytes[i];
            i += 1;
            match esc {
                b'"' => out.push(b'"'),
                b'\\' => out.push(b'\\'),
                b'/' => out.push(b'/'),
                b'b' => out.push(0x08),
                b'f' => out.push(0x0C),
                b'n' => out.push(b'\n'),
                b'r' => out.push(b'\r'),
                b't' => out.push(b'\t'),
                b'u' => {
                    let hex_to_u32 = |idx: &mut usize| -> Result<u32, Error> {
                        let mut v: u32 = 0;
                        for _ in 0..4 {
                            if *idx >= bytes.len() {
                                return Err(Error::EofHex {
                                    byte: *idx,
                                    line: 1,
                                    col: 1,
                                });
                            }
                            let c = bytes[*idx];
                            *idx += 1;
                            v = (v << 4)
                                | match c {
                                    b'0'..=b'9' => (c - b'0') as u32,
                                    b'a'..=b'f' => (c - b'a' + 10) as u32,
                                    b'A'..=b'F' => (c - b'A' + 10) as u32,
                                    _ => {
                                        return Err(Error::InvalidHex {
                                            byte: *idx - 1,
                                            line: 1,
                                            col: 1,
                                        });
                                    }
                                };
                        }
                        Ok(v)
                    };
                    let hi = hex_to_u32(&mut i)?;
                    let cp = if (0xD800..=0xDBFF).contains(&hi) {
                        if i + 6 > bytes.len() || bytes[i] != b'\\' || bytes[i + 1] != b'u' {
                            return Err(Error::WithPos {
                                msg: "expected low surrogate",
                                byte: i,
                                line: 1,
                                col: 1,
                            });
                        }
                        i += 2; // skip \\u
                        let lo = hex_to_u32(&mut i)?;
                        if !(0xDC00..=0xDFFF).contains(&lo) {
                            return Err(Error::WithPos {
                                msg: "invalid low surrogate",
                                byte: i - 1,
                                line: 1,
                                col: 1,
                            });
                        }
                        0x10000 + (((hi - 0xD800) << 10) | (lo - 0xDC00))
                    } else if (0xDC00..=0xDFFF).contains(&hi) {
                        return Err(Error::WithPos {
                            msg: "unexpected low surrogate",
                            byte: i - 1,
                            line: 1,
                            col: 1,
                        });
                    } else {
                        hi
                    };
                    if let Some(ch) = char::from_u32(cp) {
                        let mut buf = [0u8; 4];
                        let n = ch.encode_utf8(&mut buf).len();
                        out.extend_from_slice(&buf[..n]);
                    } else {
                        return Err(Error::WithPos {
                            msg: "invalid codepoint",
                            byte: i - 1,
                            line: 1,
                            col: 1,
                        });
                    }
                }
                _ => {
                    return Err(Error::WithPos {
                        msg: "bad escape",
                        byte: i - 1,
                        line: 1,
                        col: 1,
                    });
                }
            }
        }
        String::from_utf8(out).map_err(|_| Error::InvalidUtf8)
    }
    /// A minimal JSON parser over `&str`.
    #[derive(Clone, Copy)]
    pub struct Parser<'a> {
        s: &'a [u8],
        i: usize,
    }
    impl<'a> Parser<'a> {
        const LEADING_ZERO_MSG: &'static str = "leading zeros are not allowed in JSON numbers";
        /// Apply the original complete-document depth preflight before a typed field walk.
        ///
        /// This shares the allocation-free depth helper used by [`from_json`]. It
        /// neither parses fields nor changes the cursor or inherited decode context.
        ///
        /// # Errors
        /// Returns the original document nesting refusal before invoking a field decoder.
        pub fn preflight_document(&self) -> Result<(), Error> {
            ensure_json_value_depth(document_json_value_depth(self.input()))
        }
        /// Finish the original document with the exact ordinary trailing-position error.
        ///
        /// Whitespace is consumed. No trailing token is parsed or discarded, and no
        /// cursor, source or decoder budget is replaced. Callers retire their typed
        /// result on failure using its existing owner/drop contract.
        ///
        /// # Errors
        /// Returns the same trailing-character byte/line/column as [`from_json`].
        pub fn finish_document(&mut self) -> Result<(), Error> {
            self.skip_ws();
            if !self.eof() {
                let (byte, line, col) = pos_from_offset(self.input(), self.position());
                return Err(Error::TrailingCharacters { byte, line, col });
            }
            Ok(())
        }

        #[inline]
        fn pos_meta(&self, pos: usize) -> (usize, usize, usize) {
            let bytes = self.s;
            let mut line = 1usize;
            let mut col = 1usize;
            let mut i = 0usize;
            while i < pos && i < bytes.len() {
                if bytes[i] == b'\n' {
                    line += 1;
                    col = 1;
                } else {
                    col += 1;
                }
                i += 1;
            }
            (pos, line, col)
        }
        #[inline]
        fn err_at(&self, pos: usize, msg: &'static str) -> Error {
            let (byte, line, col) = self.pos_meta(pos);
            Error::WithPos {
                msg,
                byte,
                line,
                col,
            }
        }
        #[inline]
        fn err_unexpected_char(&self) -> Error {
            let (byte, line, col) = self.pos_meta(self.i.min(self.s.len()));
            let found = if self.i < self.s.len() {
                UnexpectedToken::Char(self.s[self.i] as char)
            } else {
                UnexpectedToken::Eof
            };
            Error::UnexpectedCharacter {
                found,
                byte,
                line,
                col,
            }
        }
        #[inline]
        fn err_expected_digits(&self) -> Error {
            let (byte, line, col) = self.pos_meta(self.i.min(self.s.len()));
            Error::ExpectedDigits { byte, line, col }
        }
        #[inline]
        fn err_u64_overflow(&self) -> Error {
            let (byte, line, col) = self.pos_meta(self.i.min(self.s.len()));
            Error::U64Overflow { byte, line, col }
        }
        #[inline]
        fn err_here(&self, msg: &'static str) -> Error {
            self.err_at(self.i.min(self.s.len()), msg)
        }
        /// Create a new parser over string slice `s`.
        pub fn new(s: &'a str) -> Self {
            Self {
                s: s.as_bytes(),
                i: 0,
            }
        }
        /// Create a new parser starting at byte position `pos`.
        ///
        /// # Panics
        ///
        /// Panics when `pos` is outside the input or is not a UTF-8 character boundary.
        pub fn new_at(s: &'a str, pos: usize) -> Self {
            assert!(
                pos <= s.len() && s.is_char_boundary(pos),
                "JSON parser start must be a UTF-8 character boundary"
            );
            Self {
                s: s.as_bytes(),
                i: pos,
            }
        }
        /// Current byte position in the input stream.
        pub fn position(&self) -> usize {
            self.i
        }
        /// Borrow the remaining input as a `&str` from the current position to the end.
        ///
        /// # Panics
        ///
        /// Panics if a caller used the byte-level [`Self::bump`] API to stop
        /// inside a raw multi-byte UTF-8 scalar.
        pub fn input_from_pos(&self) -> &'a str {
            self.input()
                .get(self.i..)
                .expect("JSON parser position must remain a UTF-8 character boundary")
        }
        /// Borrow the full original input as a `&str`.
        pub fn input(&self) -> &'a str {
            // SAFETY: `self.s` is borrowed immutably from the `&str` supplied
            // to `new` or `new_at`; only the cursor changes.
            unsafe { std::str::from_utf8_unchecked(self.s) }
        }
        /// Return true if no more input remains.
        pub fn eof(&self) -> bool {
            self.i >= self.s.len()
        }
        /// Peek at the next byte without consuming it.
        pub fn peek(&self) -> Option<u8> {
            self.s.get(self.i).copied()
        }
        /// Consume and return the next byte.
        pub fn bump(&mut self) -> Option<u8> {
            let b = self.s.get(self.i).copied();
            if b.is_some() {
                self.i += 1;
            }
            b
        }
        /// Skip any ASCII whitespace.
        pub fn skip_ws(&mut self) {
            while let Some(b) = self.peek() {
                if matches!(b, b' ' | b'\n' | b'\r' | b'\t') {
                    self.i += 1;
                } else {
                    break;
                }
            }
        }
        /// Expect the next non-whitespace byte to equal `b`.
        pub fn expect(&mut self, b: u8) -> Result<(), Error> {
            self.skip_ws();
            match self.peek() {
                Some(x) if x == b => {
                    // Consume only on success to keep error position stable
                    self.bump();
                    Ok(())
                }
                _ => Err(self.err_unexpected_char()),
            }
        }
        /// Compatibility: consume an expected byte (alias of expect).
        pub fn consume_char(&mut self, b: u8) -> Result<(), Error> {
            self.expect(b)
        }
        /// Compatibility: try to consume an expected byte, returning true if consumed.
        pub fn try_consume_char(&mut self, b: u8) -> Result<bool, Error> {
            self.skip_ws();
            if self.peek() == Some(b) {
                self.bump();
                Ok(true)
            } else {
                Ok(false)
            }
        }
        /// Compatibility: consume a comma if present after optional whitespace.
        pub fn consume_comma_if_present(&mut self) -> Result<bool, Error> {
            self.skip_ws();
            if self.peek() == Some(b',') {
                self.bump();
                Ok(true)
            } else {
                Ok(false)
            }
        }
        /// Parse a JSON `null` token.
        pub fn parse_null(&mut self) -> Result<(), Error> {
            self.skip_ws();
            let rest = &self.s.get(self.i..).ok_or_else(|| self.err_here("eof"))?;
            if rest.starts_with(b"null") {
                self.i += 4;
                Ok(())
            } else {
                let (byte, line, col) = self.pos_meta(self.i);
                Err(Error::ExpectedNull { byte, line, col })
            }
        }
        /// Parse a boolean.
        pub fn parse_bool(&mut self) -> Result<bool, Error> {
            self.skip_ws();
            let rest = &self.s[self.i..];
            if rest.starts_with(b"true") {
                self.i += 4;
                Ok(true)
            } else if rest.starts_with(b"false") {
                self.i += 5;
                Ok(false)
            } else {
                let (byte, line, col) = self.pos_meta(self.i);
                Err(Error::ExpectedBool { byte, line, col })
            }
        }
        /// Parse a non-negative integer into `u64`.
        pub fn parse_u64(&mut self) -> Result<u64, Error> {
            self.skip_ws();
            let bytes = self.s;
            let mut i = self.i;
            let start = i;
            let mut val: u64 = 0;
            let mut any = false;
            while i < bytes.len() {
                let b = bytes[i];
                if b.wrapping_sub(b'0') <= 9 {
                    // fast digit test
                    let d = (b - b'0') as u64;
                    // Overflow check: val*10 + d <= u64::MAX
                    if val > (u64::MAX - d) / 10 {
                        return Err(self.err_u64_overflow());
                    }
                    val = val * 10 + d;
                    i += 1;
                    any = true;
                } else {
                    break;
                }
            }
            if !any {
                return Err(self.err_expected_digits());
            }
            if bytes[start] == b'0' && i > start + 1 {
                return Err(self.err_at(start + 1, Self::LEADING_ZERO_MSG));
            }
            self.i = i;
            Ok(val)
        }
        /// Parse a JSON string with escaping support.
        pub fn parse_string(&mut self) -> Result<String, Error> {
            let bytes =
                self.parse_string_with_output(exact_string::allocate, |bytes, _, chunk| {
                    bytes.extend_from_slice(chunk);
                    Ok(())
                })?;
            // SAFETY: the shared parser consumes UTF-8 input and validates every escape.
            Ok(unsafe { String::from_utf8_unchecked(bytes) })
        }
        /// Decode a string into an exact caller-owned initialized byte destination.
        ///
        /// The ordinary string's exact length and active logical allocation charge are
        /// determined in the same order before `allocate` runs. The callback may refuse
        /// with its original typed local cause. Every byte is initialized through the
        /// shared string decoder; the destination must expose exactly `length` bytes.
        /// This funds no enclosing source, control, key or diagnostic allocation.
        ///
        /// # Errors
        /// Preserves original JSON syntax/resource errors and callback refusals. A caller
        /// destination with a different length is rejected before any copied byte.
        pub fn parse_string_with_buffer<B, E>(
            &mut self,
            allocate: impl FnOnce(usize) -> Result<B, E>,
        ) -> Result<B, E>
        where
            B: AsMut<[u8]>,
            E: From<Error>,
        {
            self.parse_string_with_output(
                |length| {
                    let mut buffer = allocate(length)?;
                    if buffer.as_mut().len() != length {
                        return Err(Error::Message(
                            "JSON string destination length differs".into(),
                        )
                        .into());
                    }
                    Ok(buffer)
                },
                |buffer: &mut B, start, chunk| {
                    let end = start.checked_add(chunk.len()).ok_or_else(|| {
                        E::from(Error::Message(
                            "JSON string destination length overflow".into(),
                        ))
                    })?;
                    let destination = buffer.as_mut().get_mut(start..end).ok_or_else(|| {
                        E::from(Error::Message(
                            "JSON string destination length differs".into(),
                        ))
                    })?;
                    destination.copy_from_slice(chunk);
                    Ok(())
                },
            )
        }
        fn parse_string_with_output<B, E: From<Error>>(
            &mut self,
            allocate: impl FnOnce(usize) -> Result<B, E>,
            mut write: impl FnMut(&mut B, usize, &[u8]) -> Result<(), E>,
        ) -> Result<B, E> {
            self.skip_ws();
            let token_start = self.i;
            self.expect(b'"')?;
            let start = self.i;
            let bytes = self.s;
            let mut i = start;
            while i < bytes.len() {
                let b = bytes[i];
                if b == b'"' {
                    let slice = &bytes[start..i];
                    self.i = i + 1;
                    let text = std::str::from_utf8(slice)
                        .map_err(|_| self.err_at(start, "invalid utf8"))?;
                    crate::core::reserve_decode_allocation(text.len())
                        .map_err(Error::from_decode_resource)?;
                    let mut buffer = allocate(text.len())?;
                    write(&mut buffer, 0, text.as_bytes())?;
                    return Ok(buffer);
                }
                if b == b'\\' || b < 0x20 {
                    break;
                }
                i += 1;
            }
            let decoded_bytes = {
                let mut preflight = Parser::new_at(self.input(), token_start);
                preflight.skip_string_bounded(usize::MAX)?
            };
            crate::core::reserve_decode_allocation(decoded_bytes)
                .map_err(Error::from_decode_resource)?;
            let mut buffer = allocate(decoded_bytes)?;
            self.decode_string_with_output(&mut buffer, write, decoded_bytes)?;
            Ok(buffer)
        }
        fn decode_string_with_output<B, E: From<Error>>(
            &mut self,
            buffer: &mut B,
            write: impl FnMut(&mut B, usize, &[u8]) -> Result<(), E>,
            expected: usize,
        ) -> Result<(), E> {
            struct Output<'a, B, W, E> {
                buffer: &'a mut B,
                write: W,
                written: usize,
                expected: usize,
                error: std::marker::PhantomData<E>,
            }
            impl<B, E: From<Error>, W: FnMut(&mut B, usize, &[u8]) -> Result<(), E>> Output<'_, B, W, E> {
                fn push(&mut self, byte: u8) -> Result<(), E> {
                    self.extend_from_slice(&[byte])
                }
                fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<(), E> {
                    let end = self
                        .written
                        .checked_add(bytes.len())
                        .filter(|end| *end <= self.expected)
                        .ok_or_else(|| {
                            E::from(Error::Message(
                                "JSON string preflight length differs".into(),
                            ))
                        })?;
                    (self.write)(self.buffer, self.written, bytes)?;
                    self.written = end;
                    Ok(())
                }
            }
            let mut output = Output {
                buffer,
                write,
                written: 0,
                expected,
                error: std::marker::PhantomData,
            };
            loop {
                let b = self.bump().ok_or_else(|| {
                    let (byte, line, col) = self.pos_meta(self.i);
                    Error::UnterminatedString { byte, line, col }
                })?;
                match b {
                    b'"' => break,
                    b'\\' => {
                        let esc = self.bump().ok_or_else(|| {
                            let (byte, line, col) = self.pos_meta(self.i);
                            Error::EofEscape { byte, line, col }
                        })?;
                        match esc {
                            b'"' => output.push(b'"')?,
                            b'\\' => output.push(b'\\')?,
                            b'/' => output.push(b'/')?,
                            b'b' => output.push(0x08)?,
                            b'f' => output.push(0x0C)?,
                            b'n' => output.push(b'\n')?,
                            b'r' => output.push(b'\r')?,
                            b't' => output.push(b'\t')?,
                            b'u' => {
                                let mut hi: u32 = 0;
                                for _ in 0..4 {
                                    let h = self.bump().ok_or_else(|| {
                                        let (byte, line, col) = self.pos_meta(self.i);
                                        Error::EofHex { byte, line, col }
                                    })?;
                                    hi = (hi << 4)
                                        | match h {
                                            b'0'..=b'9' => (h - b'0') as u32,
                                            b'a'..=b'f' => (h - b'a' + 10) as u32,
                                            b'A'..=b'F' => (h - b'A' + 10) as u32,
                                            _ => {
                                                let (byte, line, col) = self.pos_meta(self.i - 1);
                                                return Err((Error::InvalidHex {
                                                    byte,
                                                    line,
                                                    col,
                                                })
                                                .into());
                                            }
                                        };
                                }
                                if (0xD800..=0xDBFF).contains(&hi) {
                                    // Expect a following \uDC00..\uDFFF low surrogate
                                    if self.peek() != Some(b'\\') {
                                        let (byte, line, col) = self.pos_meta(self.i);
                                        return Err((Error::WithPos {
                                            msg: "expected low surrogate",
                                            byte,
                                            line,
                                            col,
                                        })
                                        .into());
                                    }
                                    self.bump();
                                    if self.bump() != Some(b'u') {
                                        let (byte, line, col) = self.pos_meta(self.i);
                                        return Err((Error::WithPos {
                                            msg: "expected \\u for low surrogate",
                                            byte,
                                            line,
                                            col,
                                        })
                                        .into());
                                    }
                                    let mut lo: u32 = 0;
                                    for _ in 0..4 {
                                        let h = self.bump().ok_or_else(|| {
                                            let (byte, line, col) = self.pos_meta(self.i);
                                            Error::EofHex { byte, line, col }
                                        })?;
                                        lo = (lo << 4)
                                            | match h {
                                                b'0'..=b'9' => (h - b'0') as u32,
                                                b'a'..=b'f' => (h - b'a' + 10) as u32,
                                                b'A'..=b'F' => (h - b'A' + 10) as u32,
                                                _ => {
                                                    let (byte, line, col) =
                                                        self.pos_meta(self.i - 1);
                                                    return Err((Error::InvalidHex {
                                                        byte,
                                                        line,
                                                        col,
                                                    })
                                                    .into());
                                                }
                                            };
                                    }
                                    if !(0xDC00..=0xDFFF).contains(&lo) {
                                        let (byte, line, col) = self.pos_meta(self.i - 1);
                                        return Err((Error::WithPos {
                                            msg: "invalid low surrogate",
                                            byte,
                                            line,
                                            col,
                                        })
                                        .into());
                                    }
                                    let cp: u32 = 0x10000 + (((hi - 0xD800) << 10) | (lo - 0xDC00));
                                    if let Some(ch) = char::from_u32(cp) {
                                        let mut buf = [0u8; 4];
                                        let n = ch.encode_utf8(&mut buf).len();
                                        output.extend_from_slice(&buf[..n])?;
                                    } else {
                                        let (byte, line, col) = self.pos_meta(self.i - 1);
                                        return Err((Error::WithPos {
                                            msg: "invalid codepoint",
                                            byte,
                                            line,
                                            col,
                                        })
                                        .into());
                                    }
                                } else if (0xDC00..=0xDFFF).contains(&hi) {
                                    let (byte, line, col) = self.pos_meta(self.i - 1);
                                    return Err((Error::WithPos {
                                        msg: "unexpected low surrogate",
                                        byte,
                                        line,
                                        col,
                                    })
                                    .into());
                                } else if let Some(ch) = char::from_u32(hi) {
                                    let mut buf = [0u8; 4];
                                    let n = ch.encode_utf8(&mut buf).len();
                                    output.extend_from_slice(&buf[..n])?;
                                } else {
                                    let (byte, line, col) = self.pos_meta(self.i - 1);
                                    return Err((Error::WithPos {
                                        msg: "invalid codepoint",
                                        byte,
                                        line,
                                        col,
                                    })
                                    .into());
                                }
                            }
                            _ => {
                                let (byte, line, col) = self.pos_meta(self.i - 1);
                                return Err((Error::WithPos {
                                    msg: "bad escape",
                                    byte,
                                    line,
                                    col,
                                })
                                .into());
                            }
                        }
                    }
                    b if b < 0x20 => {
                        let (byte, line, col) = self.pos_meta(self.i - 1);
                        return Err((Error::ControlInString { byte, line, col }).into());
                    }
                    b => output.push(b)?,
                }
            }
            if output.written != expected {
                return Err(Error::Message("JSON string preflight length differs".into()).into());
            }
            Ok(())
        }
        /// Parse a JSON array into `Vec<T>` using `JsonDeserialize` for elements.
        pub fn parse_array<T: JsonDeserialize>(&mut self) -> Result<Vec<T>, Error> {
            let entries = self.preflight_container_entries(b'[')?;
            let mut out = try_decode_vec_with_capacity(entries)?;
            self.skip_ws();
            self.expect(b'[')?;
            self.skip_ws();
            if matches!(self.peek(), Some(b']')) {
                self.bump(); // consume ']'
                return Ok(out);
            }
            loop {
                let v = T::json_deserialize(self)?;
                out.push(v);
                self.skip_ws();
                match self.bump() {
                    Some(b',') => continue,
                    Some(b']') => break,
                    _ => {
                        let (byte, line, col) = self.pos_meta(self.i);
                        return Err(Error::ExpectedCommaOrArrayEnd { byte, line, col });
                    }
                }
            }
            Ok(out)
        }
        /// Parse a JSON `f64` number using the generic implementation.
        #[inline]
        pub fn parse_f64(&mut self) -> Result<f64, Error> {
            <f64 as JsonDeserialize>::json_deserialize(self)
        }
        /// Try to consume a JSON `null` token without erroring when absent.
        #[inline]
        pub fn try_consume_null(&mut self) -> Result<bool, Error> {
            self.skip_ws();
            if let Some(rest) = self.s.get(self.i..)
                && rest.starts_with(b"null")
            {
                self.i += 4;
                return Ok(true);
            }
            Ok(false)
        }
        /// Parse and skip a JSON string without allocating; validates structure.
        pub fn skip_string(&mut self) -> Result<(), Error> {
            self.skip_string_bounded(usize::MAX).map(|_| ())
        }
        /// Parse and skip a JSON string while enforcing its exact decoded
        /// UTF-8 byte length before any owned string allocation.
        ///
        /// Returns the decoded byte length. JSON escapes and surrogate pairs count as the bytes of
        /// their decoded Unicode scalar value rather than their source spelling.
        pub fn skip_string_bounded(
            &mut self,
            maximum_decoded_bytes: usize,
        ) -> Result<usize, Error> {
            self.skip_ws();
            self.expect(b'"')?;
            let mut decoded_bytes = 0usize;
            loop {
                let b = self.bump().ok_or_else(|| {
                    let (byte, line, col) = self.pos_meta(self.i);
                    Error::UnterminatedString { byte, line, col }
                })?;
                let added = match b {
                    b'"' => break,
                    b'\\' => {
                        let esc = self.bump().ok_or_else(|| {
                            let (byte, line, col) = self.pos_meta(self.i);
                            Error::EofEscape { byte, line, col }
                        })?;
                        match esc {
                            b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => 1,
                            b'u' => {
                                let hi = self.skip_string_hex_quad()?;
                                if (0xD800..=0xDBFF).contains(&hi) {
                                    if self.peek() != Some(b'\\') {
                                        let (byte, line, col) = self.pos_meta(self.i);
                                        return Err(Error::WithPos {
                                            msg: "expected low surrogate",
                                            byte,
                                            line,
                                            col,
                                        });
                                    }
                                    self.bump();
                                    if self.bump() != Some(b'u') {
                                        let (byte, line, col) = self.pos_meta(self.i);
                                        return Err(Error::WithPos {
                                            msg: "expected \\u for low surrogate",
                                            byte,
                                            line,
                                            col,
                                        });
                                    }
                                    let lo = self.skip_string_hex_quad()?;
                                    if !(0xDC00..=0xDFFF).contains(&lo) {
                                        let (byte, line, col) =
                                            self.pos_meta(self.i.saturating_sub(1));
                                        return Err(Error::WithPos {
                                            msg: "invalid low surrogate",
                                            byte,
                                            line,
                                            col,
                                        });
                                    }
                                    let scalar = 0x1_0000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
                                    char::from_u32(scalar)
                                        .expect("validated JSON surrogate pair")
                                        .len_utf8()
                                } else if (0xDC00..=0xDFFF).contains(&hi) {
                                    let (byte, line, col) = self.pos_meta(self.i.saturating_sub(1));
                                    return Err(Error::WithPos {
                                        msg: "unexpected low surrogate",
                                        byte,
                                        line,
                                        col,
                                    });
                                } else {
                                    char::from_u32(hi)
                                        .expect("validated non-surrogate JSON scalar")
                                        .len_utf8()
                                }
                            }
                            _ => {
                                let (byte, line, col) = self.pos_meta(self.i.saturating_sub(1));
                                return Err(Error::WithPos {
                                    msg: "bad escape",
                                    byte,
                                    line,
                                    col,
                                });
                            }
                        }
                    }
                    b if b < 0x20 => {
                        let (byte, line, col) = self.pos_meta(self.i.saturating_sub(1));
                        return Err(Error::ControlInString { byte, line, col });
                    }
                    raw if raw.is_ascii() => 1,
                    _ => {
                        // The scanner starts at a character boundary. Advance
                        // over the complete raw scalar before checking the
                        // limit so even an error leaves the public parser at a
                        // valid UTF-8 boundary.
                        let scalar_start = self.i - 1;
                        let width = match b {
                            0xC2..=0xDF => 2,
                            0xE0..=0xEF => 3,
                            0xF0..=0xF4 => 4,
                            _ => return Err(Error::InvalidUtf8),
                        };
                        let scalar_end =
                            scalar_start.checked_add(width).ok_or(Error::InvalidUtf8)?;
                        let scalar_bytes = self
                            .s
                            .get(scalar_start..scalar_end)
                            .ok_or(Error::InvalidUtf8)?;
                        debug_assert!(std::str::from_utf8(scalar_bytes).is_ok());
                        self.i = scalar_end;
                        width
                    }
                };
                decoded_bytes = decoded_bytes.checked_add(added).ok_or_else(|| {
                    Error::Message("decoded JSON string byte length overflow".into())
                })?;
                if decoded_bytes > maximum_decoded_bytes {
                    return Err(Error::Message(format!(
                        "decoded JSON string exceeds the {maximum_decoded_bytes}-byte limit"
                    )));
                }
            }
            Ok(decoded_bytes)
        }
        fn skip_string_hex_quad(&mut self) -> Result<u32, Error> {
            let mut value = 0u32;
            for _ in 0..4 {
                let hex = self.bump().ok_or_else(|| {
                    let (byte, line, col) = self.pos_meta(self.i);
                    Error::EofHex { byte, line, col }
                })?;
                value = (value << 4)
                    | match hex {
                        b'0'..=b'9' => u32::from(hex - b'0'),
                        b'a'..=b'f' => u32::from(hex - b'a' + 10),
                        b'A'..=b'F' => u32::from(hex - b'A' + 10),
                        _ => {
                            let (byte, line, col) = self.pos_meta(self.i.saturating_sub(1));
                            return Err(Error::InvalidHex { byte, line, col });
                        }
                    };
            }
            Ok(value)
        }
        fn skip_object_key(&mut self) -> Result<String, Error> {
            let key = self.parse_string()?;
            self.skip_ws();
            if self.peek() == Some(b':') {
                self.bump();
                Ok(key)
            } else {
                let (byte, line, col) = self.pos_meta(self.i);
                Err(Error::ExpectedColon { byte, line, col })
            }
        }
        fn preflight_container_entries(&mut self, opening: u8) -> Result<usize, Error> {
            self.skip_ws();
            if self.peek() != Some(opening) {
                let (byte, line, col) = self.pos_meta(self.i);
                return Err(if opening == b'[' {
                    Error::ExpectedArrayStart { byte, line, col }
                } else {
                    Error::ExpectedObjectStart { byte, line, col }
                });
            }
            let (profile, _) = preflight::container_profile_at_depth(self.input(), self.i, 1)
                .map_err(|error| self.lexical_preflight_error(error))?;
            let entries = profile.root_container_entries();
            crate::core::enforce_decode_sequence_length(
                u64::try_from(entries).map_err(|_| Error::DecodeResourceLimit)?,
            )
            .map_err(Error::from_decode_resource)?;
            Ok(entries)
        }
        /// Count and charge the entries in the next object without allocating.
        #[doc(hidden)]
        pub fn preflight_object_entries(&mut self) -> Result<usize, Error> {
            self.preflight_container_entries(b'{')
        }
        /// Count and charge the entries in the next array without allocating.
        #[doc(hidden)]
        pub fn preflight_array_entries(&mut self) -> Result<usize, Error> {
            self.preflight_container_entries(b'[')
        }
        /// Borrow the exact source spelling of the next JSON value.
        ///
        /// The value boundary is found with the allocation-free bounded lexical scanner. This is
        /// intended for typed dispatch (notably tagged enums) that immediately parses the borrowed
        /// fragment and therefore must not copy an attacker-sized `content` subtree first.
        pub fn raw_value_slice(&mut self) -> Result<&'a str, Error> {
            self.skip_ws();
            let start = self.i;
            let end = preflight::value_end_at_depth(self.input(), start, 1)
                .map_err(|error| self.lexical_preflight_error(error))?;
            self.i = end;
            Ok(&self.input()[start..end])
        }
        /// Skip the next JSON value with bounded stack and no owned value tree.
        ///
        /// Duplicate object names remain the responsibility of a typed object
        /// decoder. The lexical walk validates the complete value grammar,
        /// including strings, numbers, delimiters, and nesting depth.
        pub fn skip_value_lexical(&mut self) -> Result<(), Error> {
            self.skip_ws();
            let start = self.i;
            self.i = preflight::value_end_at_depth(self.input(), start, 1)
                .map_err(|error| self.lexical_preflight_error(error))?;
            Ok(())
        }
        fn lexical_preflight_error(&self, error: preflight::JsonPreflightError) -> Error {
            if error.resource_kind() == Some(preflight::JsonPreflightResource::NestingDepth) {
                return Error::NestingDepthExceeded {
                    depth: error.attempted(),
                    limit: error.limit(),
                    context: "JSON value",
                };
            }
            let (byte, line, col) = self.pos_meta(error.offset());
            if error.syntax_kind() == Some(preflight::JsonPreflightSyntax::UnexpectedToken) {
                let found = self
                    .s
                    .get(error.offset())
                    .map_or(UnexpectedToken::Eof, |byte| {
                        UnexpectedToken::Char(char::from(*byte))
                    });
                return Error::UnexpectedCharacter {
                    found,
                    byte,
                    line,
                    col,
                };
            }
            Error::WithPos {
                msg: error.syntax_kind().map_or(
                    "JSON lexical counter overflow",
                    preflight::JsonPreflightSyntax::message,
                ),
                byte,
                line,
                col,
            }
        }
        /// Skip over the next exact JSON value without constructing an owned
        /// recursive [`Value`] tree.
        ///
        /// The walk is iterative and enforces the same structural depth, number, string, surrogate,
        /// and duplicate-key rules as [`parse_value`].
        pub fn skip_value(&mut self) -> Result<(), Error> {
            self.skip_value_at_depth(1)
        }
        /// Skip an exact JSON value that will appear at `root_depth` in its enclosing document.
        #[doc(hidden)]
        pub fn skip_value_at_depth(&mut self, root_depth: usize) -> Result<(), Error> {
            if root_depth == 0 {
                return Err(Error::Message(
                    "JSON root depth must be at least 1".to_owned(),
                ));
            }
            enum Frame {
                Array {
                    child_depth: usize,
                },
                Object {
                    keys: std::collections::BTreeSet<String>,
                    pending_key: Option<String>,
                    child_depth: usize,
                },
            }
            enum Action {
                ParseNext(usize),
                Close,
            }
            let mut frames = Vec::<Frame>::new();
            let mut next_depth = root_depth;
            'parse: loop {
                ensure_json_value_depth(next_depth)?;
                self.skip_ws();
                match self.peek() {
                    Some(b'{') => {
                        self.bump();
                        self.skip_ws();
                        if self.peek() == Some(b'}') {
                            self.bump();
                        } else {
                            let pending_key = Some(self.skip_object_key()?);
                            let child_depth = next_depth.saturating_add(1);
                            frames.push(Frame::Object {
                                keys: std::collections::BTreeSet::new(),
                                pending_key,
                                child_depth,
                            });
                            next_depth = child_depth;
                            continue 'parse;
                        }
                    }
                    Some(b'[') => {
                        self.bump();
                        self.skip_ws();
                        if self.peek() == Some(b']') {
                            self.bump();
                        } else {
                            let child_depth = next_depth.saturating_add(1);
                            frames.push(Frame::Array { child_depth });
                            next_depth = child_depth;
                            continue 'parse;
                        }
                    }
                    Some(b'"') => self.skip_string()?,
                    Some(b't') | Some(b'f') => {
                        self.parse_bool()?;
                    }
                    Some(b'n') => self.parse_null()?,
                    Some(b'-') | Some(b'0'..=b'9') => {
                        parse_number_value(self)?;
                    }
                    Some(_) => return Err(self.err_unexpected_char()),
                    None => {
                        let (byte, line, col) = self.pos_meta(self.i);
                        return Err(Error::UnexpectedEof { byte, line, col });
                    }
                }
                loop {
                    let Some(frame) = frames.last_mut() else {
                        return Ok(());
                    };
                    self.skip_ws();
                    let action = match frame {
                        Frame::Array { child_depth } => match self.peek() {
                            Some(b',') => {
                                self.bump();
                                self.skip_ws();
                                Action::ParseNext(*child_depth)
                            }
                            Some(b']') => {
                                self.bump();
                                Action::Close
                            }
                            _ => {
                                let (byte, line, col) = self.pos_meta(self.i);
                                return Err(Error::ExpectedCommaOrArrayEnd { byte, line, col });
                            }
                        },
                        Frame::Object {
                            keys,
                            pending_key,
                            child_depth,
                        } => {
                            let key = pending_key
                                .take()
                                .expect("iterative JSON object frame has no pending key");
                            if !keys.insert(key.clone()) {
                                return Err(Error::duplicate_field(key));
                            }
                            match self.peek() {
                                Some(b',') => {
                                    self.bump();
                                    self.skip_ws();
                                    *pending_key = Some(self.skip_object_key()?);
                                    Action::ParseNext(*child_depth)
                                }
                                Some(b'}') => {
                                    self.bump();
                                    Action::Close
                                }
                                _ => {
                                    let (byte, line, col) = self.pos_meta(self.i);
                                    return Err(Error::ExpectedCommaOrObjectEnd {
                                        byte,
                                        line,
                                        col,
                                    });
                                }
                            }
                        }
                    };
                    match action {
                        Action::ParseNext(depth) => {
                            next_depth = depth;
                            continue 'parse;
                        }
                        Action::Close => {
                            frames.pop();
                        }
                    }
                }
            }
        }
        /// Read a JSON object key using the same hash as compile-time and tape dispatch.
        /// The existing string parser borrows unescaped keys and validates/unescapes
        /// escaped keys. The colon remains unconsumed, as with the tape reader.
        pub fn read_key_hash(&mut self) -> Result<u64, Error> {
            let mut arena = Arena::new();
            let key = self.parse_string_ref(&mut arena)?;
            Ok(key_hash_const(match key {
                StrRef::Borrowed(value) | StrRef::Owned(value) => value,
            }))
        }
        /// Parse a JSON object key and return a borrowed `&str` when no escapes are present,
        /// or an owned `String` otherwise. This avoids allocating in the common fast path.
        ///
        /// After reading the key string, this function also consumes the mandatory colon `:`
        /// delimiter (with optional surrounding whitespace), positioning the parser at the start of
        /// the value. This matches the typical caller contract used across tests and benches.
        pub fn parse_key(&mut self) -> Result<KeyRef<'a>, Error> {
            self.parse_key_with_owned(|parser| parser.parse_string())
        }
        /// Read a key with an exact caller-owned destination for its escaped text.
        ///
        /// Unescaped keys remain original input borrows and never invoke `allocate`.
        /// Escaped keys use the sole string/escape decoder and its logical charge
        /// before the typed allocation callback. The same key/colon kernel preserves
        /// syntax order; no ordinary String or intermediate Value is constructed.
        /// The caller funds and retains its original destination and decoder context,
        /// and scopes any refunds beyond enclosing State or storage guards.
        ///
        /// # Errors
        /// Preserves original JSON errors and the callback's exact typed refusal.
        /// The destination must expose exactly the decoded length. Refusal retains
        /// no key progress across calls; the enclosing record/source owner controls retry.
        pub fn parse_key_with_buffer<B, E>(
            &mut self,
            allocate: impl FnOnce(usize) -> Result<B, E>,
        ) -> Result<KeyRef<'a, B>, E>
        where
            B: AsMut<[u8]>,
            E: From<Error>,
        {
            self.parse_key_with_owned(|parser| parser.parse_string_with_buffer(allocate))
        }
        fn parse_key_with_owned<B, E: From<Error>>(
            &mut self,
            parse_owned: impl FnOnce(&mut Parser<'a>) -> Result<B, E>,
        ) -> Result<KeyRef<'a, B>, E> {
            self.skip_ws();
            let pre = self.i;
            self.expect(b'"')?;
            let start = self.i;
            let bytes = self.s;
            let mut i = start;
            while i < bytes.len() {
                let b = bytes[i];
                if b == b'"' {
                    // No escapes encountered; borrow directly from input
                    let slice = &bytes[start..i];
                    self.i = i + 1;
                    // Consume the mandatory colon after the key
                    self.skip_ws();
                    match self.bump() {
                        Some(b':') => {}
                        _ => {
                            let (byte, line, col) = self.pos_meta(self.i);
                            return Err(Error::WithPos {
                                msg: "expected :",
                                byte,
                                line,
                                col,
                            }
                            .into());
                        }
                    }
                    let st = std::str::from_utf8(slice).map_err(|_| Error::InvalidUtf8)?;
                    return Ok(KeyRef::Borrowed(st));
                }
                if b == b'\\' || b < 0x20 {
                    break;
                }
                i += 1;
            }
            // Slow path: re-parse from the opening quote using the general string parser
            let mut tmp = Parser::new_at(
                // SAFETY: Parser holds the same original string underlying `self.s`.
                unsafe { std::str::from_utf8_unchecked(self.s) },
                pre,
            );
            let s = parse_owned(&mut tmp)?;
            self.i = tmp.i;
            // Consume the mandatory colon after the key
            self.skip_ws();
            match self.bump() {
                Some(b':') => {}
                _ => {
                    let (byte, line, col) = self.pos_meta(self.i);
                    return Err(Error::WithPos {
                        msg: "expected :",
                        byte,
                        line,
                        col,
                    }
                    .into());
                }
            }
            Ok(KeyRef::Owned(s))
        }
    }
    /// Trait for types that can be deserialized from JSON using the simple parser.
    pub trait JsonDeserialize: Sized {
        /// Parse `Self` from the parser.
        fn json_deserialize(p: &mut Parser<'_>) -> Result<Self, Error>;
        /// Drop a value constructed before a top-level parse error is known.
        ///
        /// Most deserialized types use ordinary drop. Recursive native JSON
        /// values override this hook so malformed trailing input cannot turn
        /// otherwise bounded parsing into recursive error cleanup.
        #[doc(hidden)]
        fn json_drop_after_error(self) {}
        /// Convert a pre-parsed [`Value`] into `Self`.
        fn json_from_value(value: &Value) -> Result<Self, Error> {
            json_from_value_via_string::<Self>(value)
        }
    }
    /// Marker trait mirroring `serde::de::DeserializeOwned` for Norito JSON.
    pub trait JsonDeserializeOwned: JsonDeserialize {}
    impl<T: JsonDeserialize> JsonDeserializeOwned for T {}
    pub use JsonDeserializeOwned as DeserializeOwned;
    fn json_from_value_via_string<T: JsonDeserialize>(value: &Value) -> Result<T, Error> {
        let json = to_json(value)?;
        let mut parser = Parser::new(&json);
        let result = T::json_deserialize(&mut parser)?;
        parser.skip_ws();
        if !parser.eof() {
            let (byte, line, col) = parser.pos_meta(parser.position());
            result.json_drop_after_error();
            return Err(Error::TrailingCharacters { byte, line, col });
        }
        Ok(result)
    }
    impl JsonDeserialize for bool {
        fn json_deserialize(p: &mut Parser<'_>) -> Result<Self, Error> {
            p.parse_bool()
        }
        fn json_from_value(value: &Value) -> Result<Self, Error> {
            value
                .as_bool()
                .ok_or_else(|| Error::Message("expected bool".into()))
        }
    }
    impl JsonObjectKeyOwned for bool {
        fn from_json_key_text(key: &str) -> Result<Self, Error> {
            match key {
                "true" => Ok(true),
                "false" => Ok(false),
                _ => Err(Error::Message("expected bool".into())),
            }
        }
    }
    fn parse_u128_from_parser(p: &mut Parser<'_>) -> Result<u128, Error> {
        p.skip_ws();
        let bytes = p.s;
        let mut i = p.i;
        if i < bytes.len() && bytes[i] == b'-' {
            let (byte, line, col) = p.pos_meta(i);
            return Err(Error::WithPos {
                msg: "negative not allowed",
                byte,
                line,
                col,
            });
        }
        let mut val: u128 = 0;
        let mut any = false;
        while i < bytes.len() {
            let c = bytes[i];
            if c.wrapping_sub(b'0') <= 9 {
                let d = (c - b'0') as u128;
                if val > (u128::MAX - d) / 10 {
                    let (byte, line, col) = p.pos_meta(i);
                    return Err(Error::WithPos {
                        msg: "u128 overflow",
                        byte,
                        line,
                        col,
                    });
                }
                val = val * 10 + d;
                i += 1;
                any = true;
            } else {
                break;
            }
        }
        if !any {
            let (byte, line, col) = p.pos_meta(p.i.min(bytes.len()));
            return Err(Error::WithPos {
                msg: "expected number",
                byte,
                line,
                col,
            });
        }
        if i < bytes.len() && (bytes[i] == b'.' || bytes[i] == b'e' || bytes[i] == b'E') {
            let (byte, line, col) = p.pos_meta(i);
            return Err(Error::WithPos {
                msg: "expected integer",
                byte,
                line,
                col,
            });
        }
        p.i = i;
        p.skip_ws();
        Ok(val)
    }
    impl JsonDeserialize for u128 {
        fn json_deserialize(p: &mut Parser<'_>) -> Result<Self, Error> {
            parse_u128_from_parser(p)
        }
        fn json_from_value(value: &Value) -> Result<Self, Error> {
            if let Value::Number(number) = value
                && let Some(u) = number.as_u128()
            {
                return Ok(u);
            }
            json_from_value_via_string(value)
        }
    }
    impl JsonObjectKeyOwned for u128 {
        fn from_json_key_text(key: &str) -> Result<Self, Error> {
            key.parse::<u128>()
                .map_err(|_| Error::Message("expected u128".into()))
        }
    }
    impl JsonDeserialize for core::num::NonZeroU128 {
        fn json_deserialize(p: &mut Parser<'_>) -> Result<Self, Error> {
            let value = parse_u128_from_parser(p)?;
            core::num::NonZeroU128::new(value)
                .ok_or_else(|| Error::Message("expected non-zero u128".into()))
        }
        fn json_from_value(value: &Value) -> Result<Self, Error> {
            let value = u128::json_from_value(value)?;
            core::num::NonZeroU128::new(value)
                .ok_or_else(|| Error::Message("expected non-zero u128".into()))
        }
    }
    impl JsonObjectKeyOwned for core::num::NonZeroU128 {
        fn from_json_key_text(key: &str) -> Result<Self, Error> {
            let value = <u128 as JsonObjectKeyOwned>::from_json_key_text(key)?;
            core::num::NonZeroU128::new(value)
                .ok_or_else(|| Error::Message("expected non-zero u128".into()))
        }
    }
    impl JsonDeserialize for u64 {
        fn json_deserialize(p: &mut Parser<'_>) -> Result<Self, Error> {
            p.parse_u64()
        }
        fn json_from_value(value: &Value) -> Result<Self, Error> {
            if let Some(n) = value.as_u64() {
                return Ok(n);
            }
            json_from_value_via_string(value)
        }
    }
    impl JsonObjectKeyOwned for u64 {
        fn from_json_key_text(key: &str) -> Result<Self, Error> {
            key.parse::<u64>()
                .map_err(|_| Error::Message("expected u64".into()))
        }
    }
    impl JsonDeserialize for core::num::NonZeroU64 {
        fn json_deserialize(p: &mut Parser<'_>) -> Result<Self, Error> {
            let value = p.parse_u64()?;
            core::num::NonZeroU64::new(value)
                .ok_or_else(|| Error::Message("expected non-zero u64".into()))
        }
        fn json_from_value(value: &Value) -> Result<Self, Error> {
            let value = u64::json_from_value(value)?;
            core::num::NonZeroU64::new(value)
                .ok_or_else(|| Error::Message("expected non-zero u64".into()))
        }
    }
    impl JsonObjectKeyOwned for core::num::NonZeroU64 {
        fn from_json_key_text(key: &str) -> Result<Self, Error> {
            let value = <u64 as JsonObjectKeyOwned>::from_json_key_text(key)?;
            core::num::NonZeroU64::new(value)
                .ok_or_else(|| Error::Message("expected non-zero u64".into()))
        }
    }
    impl JsonDeserialize for core::num::NonZeroU32 {
        fn json_deserialize(p: &mut Parser<'_>) -> Result<Self, Error> {
            let value = p.parse_u64()?;
            let value = u32::try_from(value).map_err(|_| Error::Message("u32 overflow".into()))?;
            core::num::NonZeroU32::new(value)
                .ok_or_else(|| Error::Message("expected non-zero u32".into()))
        }
        fn json_from_value(value: &Value) -> Result<Self, Error> {
            let value = u32::json_from_value(value)?;
            core::num::NonZeroU32::new(value)
                .ok_or_else(|| Error::Message("expected non-zero u32".into()))
        }
    }
    impl JsonObjectKeyOwned for core::num::NonZeroU32 {
        fn from_json_key_text(key: &str) -> Result<Self, Error> {
            let value = <u32 as JsonObjectKeyOwned>::from_json_key_text(key)?;
            core::num::NonZeroU32::new(value)
                .ok_or_else(|| Error::Message("expected non-zero u32".into()))
        }
    }
    impl JsonDeserialize for u32 {
        fn json_deserialize(p: &mut Parser<'_>) -> Result<Self, Error> {
            let n = p.parse_u64()?;
            u32::try_from(n).map_err(|_| Error::Message("u32 overflow".into()))
        }
        fn json_from_value(value: &Value) -> Result<Self, Error> {
            if let Some(n) = value.as_u64() {
                return u32::try_from(n).map_err(|_| Error::Message("u32 overflow".into()));
            }
            json_from_value_via_string(value)
        }
    }
    impl JsonObjectKeyOwned for u32 {
        fn from_json_key_text(key: &str) -> Result<Self, Error> {
            key.parse::<u32>()
                .map_err(|_| Error::Message("u32 overflow".into()))
        }
    }
    impl JsonDeserialize for u16 {
        fn json_deserialize(p: &mut Parser<'_>) -> Result<Self, Error> {
            let n = p.parse_u64()?;
            u16::try_from(n).map_err(|_| Error::Message("u16 overflow".into()))
        }
    }
    impl JsonObjectKeyOwned for u16 {
        fn from_json_key_text(key: &str) -> Result<Self, Error> {
            key.parse::<u16>()
                .map_err(|_| Error::Message("u16 overflow".into()))
        }
    }
    impl JsonDeserialize for core::num::NonZeroU16 {
        fn json_deserialize(p: &mut Parser<'_>) -> Result<Self, Error> {
            let n = p.parse_u64()?;
            let value = u16::try_from(n).map_err(|_| Error::Message("u16 overflow".into()))?;
            core::num::NonZeroU16::new(value)
                .ok_or_else(|| Error::Message("expected non-zero u16".into()))
        }
    }
    impl JsonObjectKeyOwned for core::num::NonZeroU16 {
        fn from_json_key_text(key: &str) -> Result<Self, Error> {
            let value = <u16 as JsonObjectKeyOwned>::from_json_key_text(key)?;
            core::num::NonZeroU16::new(value)
                .ok_or_else(|| Error::Message("expected non-zero u16".into()))
        }
    }
    impl JsonDeserialize for core::num::NonZeroUsize {
        fn json_deserialize(p: &mut Parser<'_>) -> Result<Self, Error> {
            let n = p.parse_u64()?;
            let value = usize::try_from(n).map_err(|_| Error::Message("usize overflow".into()))?;
            core::num::NonZeroUsize::new(value)
                .ok_or_else(|| Error::Message("expected non-zero usize".into()))
        }
        fn json_from_value(value: &Value) -> Result<Self, Error> {
            let value = usize::json_from_value(value)?;
            core::num::NonZeroUsize::new(value)
                .ok_or_else(|| Error::Message("expected non-zero usize".into()))
        }
    }
    impl JsonObjectKeyOwned for core::num::NonZeroUsize {
        fn from_json_key_text(key: &str) -> Result<Self, Error> {
            let value = <usize as JsonObjectKeyOwned>::from_json_key_text(key)?;
            core::num::NonZeroUsize::new(value)
                .ok_or_else(|| Error::Message("expected non-zero usize".into()))
        }
    }
    impl JsonDeserialize for u8 {
        fn json_deserialize(p: &mut Parser<'_>) -> Result<Self, Error> {
            let n = p.parse_u64()?;
            u8::try_from(n).map_err(|_| Error::Message("u8 overflow".into()))
        }
        fn json_from_value(value: &Value) -> Result<Self, Error> {
            if let Some(n) = value.as_u64() {
                return u8::try_from(n).map_err(|_| Error::Message("u8 overflow".into()));
            }
            json_from_value_via_string(value)
        }
    }
    impl JsonObjectKeyOwned for u8 {
        fn from_json_key_text(key: &str) -> Result<Self, Error> {
            key.parse::<u8>()
                .map_err(|_| Error::Message("u8 overflow".into()))
        }
    }
    impl JsonDeserialize for usize {
        fn json_deserialize(p: &mut Parser<'_>) -> Result<Self, Error> {
            let n = p.parse_u64()?;
            usize::try_from(n).map_err(|_| Error::Message("usize overflow".into()))
        }
        fn json_from_value(value: &Value) -> Result<Self, Error> {
            if let Some(n) = value.as_u64() {
                return usize::try_from(n).map_err(|_| Error::Message("usize overflow".into()));
            }
            json_from_value_via_string(value)
        }
    }
    impl JsonObjectKeyOwned for usize {
        fn from_json_key_text(key: &str) -> Result<Self, Error> {
            key.parse::<usize>()
                .map_err(|_| Error::Message("usize overflow".into()))
        }
    }
    fn parse_i64_from_parser(p: &mut Parser<'_>) -> Result<i64, Error> {
        p.skip_ws();
        let input = p.input();
        let bytes = p.s;
        let start = p.i;
        let mut idx = start;
        if idx >= bytes.len() {
            let (byte, line, col) = pos_from_offset(input, idx);
            return Err(Error::UnexpectedEof { byte, line, col });
        }
        if bytes[idx] == b'-' {
            idx += 1;
        }
        let int_start = idx;
        if idx >= bytes.len() || !bytes[idx].is_ascii_digit() {
            let (byte, line, col) = pos_from_offset(input, idx);
            return Err(Error::WithPos {
                msg: "expected integer",
                byte,
                line,
                col,
            });
        }
        while idx < bytes.len() && bytes[idx].is_ascii_digit() {
            idx += 1;
        }
        let int_end = idx;
        if bytes[int_start] == b'0' && int_end > int_start + 1 {
            let (byte, line, col) = pos_from_offset(input, int_start + 1);
            return Err(Error::WithPos {
                msg: Parser::LEADING_ZERO_MSG,
                byte,
                line,
                col,
            });
        }
        if idx < bytes.len() && matches!(bytes[idx], b'.' | b'e' | b'E') {
            let (byte, line, col) = pos_from_offset(input, idx);
            return Err(Error::WithPos {
                msg: "expected integer",
                byte,
                line,
                col,
            });
        }
        let slice = &bytes[start..idx];
        let text = std::str::from_utf8(slice).map_err(|_| {
            let (byte, line, col) = pos_from_offset(input, start);
            Error::WithPos {
                msg: "invalid integer",
                byte,
                line,
                col,
            }
        })?;
        let value = text.parse::<i64>().map_err(|_| {
            let (byte, line, col) = pos_from_offset(input, start);
            Error::WithPos {
                msg: "i64 overflow",
                byte,
                line,
                col,
            }
        })?;
        p.i = idx;
        Ok(value)
    }
    impl JsonDeserialize for i64 {
        fn json_deserialize(p: &mut Parser<'_>) -> Result<Self, Error> {
            parse_i64_from_parser(p)
        }
    }
    impl JsonObjectKeyOwned for i64 {
        fn from_json_key_text(key: &str) -> Result<Self, Error> {
            key.parse::<i64>()
                .map_err(|_| Error::Message("i64 overflow".into()))
        }
    }
    impl JsonDeserialize for i32 {
        fn json_deserialize(p: &mut Parser<'_>) -> Result<Self, Error> {
            let v = parse_i64_from_parser(p)?;
            i32::try_from(v).map_err(|_| Error::Message("i32 overflow".into()))
        }
    }
    impl JsonObjectKeyOwned for i32 {
        fn from_json_key_text(key: &str) -> Result<Self, Error> {
            key.parse::<i32>()
                .map_err(|_| Error::Message("i32 overflow".into()))
        }
    }
    impl JsonDeserialize for i16 {
        fn json_deserialize(p: &mut Parser<'_>) -> Result<Self, Error> {
            let v = parse_i64_from_parser(p)?;
            i16::try_from(v).map_err(|_| Error::Message("i16 overflow".into()))
        }
    }
    impl JsonObjectKeyOwned for i16 {
        fn from_json_key_text(key: &str) -> Result<Self, Error> {
            key.parse::<i16>()
                .map_err(|_| Error::Message("i16 overflow".into()))
        }
    }
    impl JsonDeserialize for i8 {
        fn json_deserialize(p: &mut Parser<'_>) -> Result<Self, Error> {
            let v = parse_i64_from_parser(p)?;
            i8::try_from(v).map_err(|_| Error::Message("i8 overflow".into()))
        }
    }
    impl JsonObjectKeyOwned for i8 {
        fn from_json_key_text(key: &str) -> Result<Self, Error> {
            key.parse::<i8>()
                .map_err(|_| Error::Message("i8 overflow".into()))
        }
    }
    impl JsonDeserialize for isize {
        fn json_deserialize(p: &mut Parser<'_>) -> Result<Self, Error> {
            let v = parse_i64_from_parser(p)?;
            isize::try_from(v).map_err(|_| Error::Message("isize overflow".into()))
        }
    }
    impl JsonObjectKeyOwned for isize {
        fn from_json_key_text(key: &str) -> Result<Self, Error> {
            key.parse::<isize>()
                .map_err(|_| Error::Message("isize overflow".into()))
        }
    }
    impl JsonDeserialize for f64 {
        fn json_deserialize(p: &mut Parser<'_>) -> Result<Self, Error> {
            p.skip_ws();
            let start = p.position();
            // Reuse skip logic to locate the end of the number
            // Minimal scan: [-]? digits [. digits]? ([eE] [+-]? digits)?
            let mut i = start;
            let s = std::str::from_utf8(p.s).map_err(|_| Error::InvalidUtf8)?;
            let bytes = p.s;
            if i < bytes.len() && bytes[i] == b'-' {
                i += 1;
            }
            let mut saw = false;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
                saw = true;
            }
            if i < bytes.len() && bytes[i] == b'.' {
                i += 1;
                let mut d = false;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                    d = true;
                }
                if !d {
                    let (byte, line, col) = pos_from_offset(p.input(), i);
                    return Err(Error::ExpectedFracDigits { byte, line, col });
                }
            }
            if i < bytes.len() && (bytes[i] == b'e' || bytes[i] == b'E') {
                i += 1;
                if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
                    i += 1;
                }
                let mut d = false;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                    d = true;
                }
                if !d {
                    let (byte, line, col) = pos_from_offset(p.input(), i);
                    return Err(Error::ExpectedExpDigits { byte, line, col });
                }
            }
            if !saw {
                let (byte, line, col) = pos_from_offset(p.input(), start);
                return Err(Error::ExpectedDigits { byte, line, col });
            }
            let num_str = &s[start..i];
            let v: f64 = num_str
                .parse()
                .map_err(|e| Error::Message(format!("failed to parse float `{num_str}`: {e}")))?;
            if !v.is_finite() {
                let (byte, line, col) = pos_from_offset(p.input(), start);
                return Err(Error::WithPos {
                    msg: "non-finite float",
                    byte,
                    line,
                    col,
                });
            }
            p.i = i;
            Ok(v)
        }
    }
    impl JsonDeserialize for String {
        fn json_deserialize(p: &mut Parser<'_>) -> Result<Self, Error> {
            p.parse_string()
        }
        fn json_from_value(value: &Value) -> Result<Self, Error> {
            if let Some(s) = value.as_str() {
                return try_decode_string_copy(s);
            }
            json_from_value_via_string(value)
        }
    }
    impl JsonObjectKeyOwned for String {
        fn from_json_key_text(key: &str) -> Result<Self, Error> {
            try_decode_string_copy(key)
        }
    }
    impl JsonDeserialize for Url {
        fn json_deserialize(parser: &mut Parser<'_>) -> Result<Self, Error> {
            let raw = String::json_deserialize(parser)?;
            raw.parse()
                .map_err(|e| Error::Message(format!("invalid url: {e}")))
        }
        fn json_from_value(value: &Value) -> Result<Self, Error> {
            if let Some(s) = value.as_str() {
                return s
                    .parse()
                    .map_err(|e| Error::Message(format!("invalid url: {e}")));
            }
            json_from_value_via_string(value)
        }
    }
    impl JsonObjectKeyOwned for Url {
        fn from_json_key_text(key: &str) -> Result<Self, Error> {
            key.parse()
                .map_err(|e| Error::Message(format!("invalid url: {e}")))
        }
    }
    impl JsonDeserialize for std::time::Duration {
        fn json_deserialize(p: &mut Parser<'_>) -> Result<Self, Error> {
            let mut map = MapVisitor::new(p)?;
            let mut secs: Option<u64> = None;
            let mut nanos: Option<u32> = None;
            while let Some(key) = map.next_key()? {
                match key.as_str() {
                    "secs" => {
                        if secs.is_some() {
                            return Err(Error::duplicate_field("secs"));
                        }
                        secs = Some(map.parse_value::<u64>()?);
                    }
                    "nanos" => {
                        if nanos.is_some() {
                            return Err(Error::duplicate_field("nanos"));
                        }
                        nanos = Some(map.parse_value::<u32>()?);
                    }
                    _ => map.skip_value()?,
                }
            }
            map.finish()?;
            let secs = secs.ok_or_else(|| Error::missing_field("secs"))?;
            let nanos = nanos.ok_or_else(|| Error::missing_field("nanos"))?;
            Ok(std::time::Duration::from_secs(secs)
                + std::time::Duration::from_nanos(u64::from(nanos)))
        }
    }
    impl JsonSerialize for std::path::PathBuf {
        fn json_serialize(&self, out: &mut String) {
            write_json_string(&self.to_string_lossy(), out);
        }
    }
    impl JsonDeserialize for std::path::PathBuf {
        fn json_deserialize(p: &mut Parser<'_>) -> Result<Self, Error> {
            let raw = p.parse_string()?;
            Ok(std::path::PathBuf::from(raw))
        }
    }
    // NOTE: arena-backed string parsing API can be added here in a follow-up using a
    // dedicated reference type to handle lifetimes of input vs arena correctly.
    impl<T: JsonDeserialize> JsonDeserialize for Option<T> {
        fn json_deserialize(p: &mut Parser<'_>) -> Result<Self, Error> {
            p.skip_ws();
            if let Some(rest) = p.s.get(p.i..)
                && rest.starts_with(b"null")
            {
                p.i += 4;
                return Ok(None);
            }
            let v = T::json_deserialize(p)?;
            Ok(Some(v))
        }
        fn json_from_value(value: &Value) -> Result<Self, Error> {
            if value.is_null() {
                Ok(None)
            } else {
                T::json_from_value(value).map(Some)
            }
        }
    }
    impl JsonDeserialize for () {
        fn json_deserialize(p: &mut Parser<'_>) -> Result<Self, Error> {
            p.skip_ws();
            if p.try_consume_null()? {
                Ok(())
            } else {
                Err(Error::Message("expected null".into()))
            }
        }
    }
    impl<T: JsonDeserialize> JsonDeserialize for Vec<T> {
        fn json_deserialize(p: &mut Parser<'_>) -> Result<Self, Error> {
            p.parse_array::<T>()
        }
        fn json_from_value(value: &Value) -> Result<Self, Error> {
            if let Value::Array(items) = value {
                let mut out = try_decode_vec_with_capacity(items.len())?;
                for item in items {
                    out.push(T::json_from_value(item)?);
                }
                Ok(out)
            } else {
                json_from_value_via_string(value)
            }
        }
    }
    impl<T> JsonDeserialize for std::collections::BTreeSet<T>
    where
        T: JsonDeserialize + Ord,
    {
        fn json_deserialize(p: &mut Parser<'_>) -> Result<Self, Error> {
            let entries = p.preflight_container_entries(b'[')?;
            crate::core::reserve_decode_btree_allocation::<T, ()>(entries)
                .map_err(Error::from_decode_resource)?;
            let mut set = std::collections::BTreeSet::new();
            p.skip_ws();
            p.expect(b'[')?;
            p.skip_ws();
            if p.try_consume_char(b']')? {
                return Ok(set);
            }
            loop {
                let value = T::json_deserialize(p)?;
                if !set.insert(value) {
                    return Err(Error::Message("duplicate element in set".into()));
                }
                p.skip_ws();
                if p.try_consume_char(b',')? {
                    continue;
                }
                p.expect(b']')?;
                break;
            }
            Ok(set)
        }
        fn json_from_value(value: &Value) -> Result<Self, Error> {
            if let Value::Array(items) = value {
                crate::core::reserve_decode_btree_allocation::<T, ()>(items.len())
                    .map_err(Error::from_decode_resource)?;
                let mut set = std::collections::BTreeSet::new();
                for item in items {
                    let v = T::json_from_value(item)?;
                    if !set.insert(v) {
                        return Err(Error::Message("duplicate element in set".into()));
                    }
                }
                Ok(set)
            } else {
                json_from_value_via_string(value)
            }
        }
    }
    impl JsonDeserialize for Value {
        fn json_deserialize(p: &mut Parser<'_>) -> Result<Self, Error> {
            parse_value_internal(p, 1)
        }
        fn json_drop_after_error(self) {
            drop_json_value_iteratively(self);
        }
        fn json_from_value(value: &Value) -> Result<Self, Error> {
            Ok(value.clone())
        }
    }
    /// Structural index (scalar) representing offsets of JSON structural characters
    /// outside of strings. This is a scalar reference implementation; SIMD paths can
    /// replace the builder without changing the downstream walker.
    pub struct StructIndex {
        pub offsets: Vec<u32>,
    }
    #[cfg(any(feature = "metal-stage1", feature = "cuda-stage1", test))]
    type Stage1HelperFn = unsafe extern "C" fn(
        in_ptr: *const u8,
        len: usize,
        out_offsets: *mut u32,
        out_capacity: usize,
        out_len: *mut usize,
    ) -> i32;
    #[cfg(any(feature = "metal-stage1", feature = "cuda-stage1", test))]
    fn try_build_struct_index_with_helper(
        input: &str,
        func: Stage1HelperFn,
    ) -> Option<StructIndex> {
        let bytes = input.as_bytes();
        let mut offsets: Vec<u32> = Vec::with_capacity(bytes.len());
        let mut out_len: usize = 0;
        let rc = unsafe {
            func(
                bytes.as_ptr(),
                bytes.len(),
                offsets.as_mut_ptr(),
                offsets.capacity(),
                &mut out_len,
            )
        };
        if rc != 0 || out_len > offsets.capacity() {
            return None;
        }
        unsafe {
            offsets.set_len(out_len);
        }
        Some(StructIndex { offsets })
    }
    #[inline]
    fn accel_tape_is_sane(input: &str, acc: &StructIndex) -> bool {
        let bytes = input.as_bytes();
        let mut prev: Option<usize> = None;
        for &off in &acc.offsets {
            let off = off as usize;
            if off >= bytes.len() {
                return false;
            }
            if let Some(prev) = prev
                && off <= prev
            {
                return false;
            }
            match bytes[off] {
                b'"' | b'{' | b'}' | b'[' | b']' | b':' | b',' => {}
                _ => return false,
            }
            prev = Some(off);
        }
        true
    }
    #[cfg(any(feature = "metal-stage1", feature = "cuda-stage1", test))]
    fn stage1_helper_self_test<F>(mut build: F) -> bool
    where
        F: FnMut(&str) -> Option<StructIndex>,
    {
        const CASES: &[&str] = &[
            "{\"a\":1}",
            "{\"nested\":[{\"quote\":\"a\\\\\\\"b\"},2,3],\"tail\":true}",
            "[{\"k\":\"v\"}, {\"esc\":\"\\\\\\\\\"}, [1,2,{\"z\":0}]]",
        ];
        for input in CASES {
            let Some(acc) = build(input) else {
                return false;
            };
            if !accel_tape_is_sane(input, &acc) {
                return false;
            }
            if acc.offsets != build_struct_index_scalar(input).offsets {
                return false;
            }
        }
        true
    }
    /// Build a structural index for `input`.
    ///
    /// Attempts a SIMD (NEON) path on AArch64 when enabled via the `simd-accel`
    /// feature and supported at runtime; otherwise falls back to a portable
    /// scalar implementation. Both paths must produce identical results.
    #[inline(always)]
    fn debug_stage1_backend(tag: &str) {
        #[cfg(debug_assertions)]
        {
            if crate::debug_trace_enabled() {
                eprintln!("norito/json: stage1 backend = {tag}");
            }
        }
        let _ = tag;
    }
    #[cfg(all(debug_assertions, feature = "stage1-validate"))]
    #[inline]
    fn validate_accel(tag: &str, input: &str, acc: StructIndex) -> StructIndex {
        static BANNER: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        BANNER.get_or_init(|| {
            if crate::debug_trace_enabled() {
                eprintln!("norito/json: stage1-validate enabled (debug), validating accelerated tapes against scalar for inputs ≤256KiB");
            }
        });
        if !accel_tape_is_sane(input, &acc) {
            if crate::debug_trace_enabled() {
                eprintln!(
                    "norito/json: stage1 {} returned malformed offsets; falling back to scalar",
                    tag
                );
            }
            return build_struct_index_scalar(input);
        }
        const VALIDATE_MAX_BYTES: usize = 256 * 1024;
        if input.len() <= VALIDATE_MAX_BYTES {
            let scalar = build_struct_index_scalar(input);
            if scalar.offsets != acc.offsets {
                if crate::debug_trace_enabled() {
                    eprintln!(
                        "norito/json: stage1 {} mismatch; falling back to scalar (acc={} vs scalar={})",
                        tag,
                        acc.offsets.len(),
                        scalar.offsets.len()
                    );
                }
                return scalar;
            }
        }
        acc
    }
    #[cfg(not(all(debug_assertions, feature = "stage1-validate")))]
    #[inline]
    #[allow(dead_code)]
    fn validate_accel(tag: &str, input: &str, acc: StructIndex) -> StructIndex {
        if accel_tape_is_sane(input, &acc) {
            return acc;
        }
        if crate::debug_trace_enabled() {
            eprintln!(
                "norito/json: stage1 {} returned malformed offsets; falling back to scalar",
                tag
            );
        }
        build_struct_index_scalar(input)
    }
    #[cfg(test)]
    mod accel_tape_validation_tests {
        #[cfg(feature = "parallel-stage1")]
        use super::build_struct_index_parallel;
        use super::{
            StructIndex, build_struct_index_scalar, extend_struct_index_scalar,
            stage1_helper_self_test, try_build_struct_index_with_helper, validate_accel,
        };
        use std::{ptr, slice};
        #[test]
        fn validate_accel_rejects_out_of_bounds_offsets() {
            let input = "{\"a\":1}";
            let got = validate_accel("test", input, StructIndex { offsets: vec![999] });
            assert_eq!(got.offsets, build_struct_index_scalar(input).offsets);
        }
        #[test]
        fn validate_accel_rejects_non_structural_offsets() {
            let input = "{\"a\":1}";
            let got = validate_accel("test", input, StructIndex { offsets: vec![2] });
            assert_eq!(got.offsets, build_struct_index_scalar(input).offsets);
        }
        unsafe extern "C" fn stage1_helper_match(
            in_ptr: *const u8,
            len: usize,
            out_offsets: *mut u32,
            out_capacity: usize,
            out_len: *mut usize,
        ) -> i32 {
            let input =
                unsafe { std::str::from_utf8_unchecked(slice::from_raw_parts(in_ptr, len)) };
            let tape = build_struct_index_scalar(input);
            unsafe {
                *out_len = tape.offsets.len();
            }
            if tape.offsets.len() > out_capacity {
                return 2;
            }
            unsafe {
                ptr::copy_nonoverlapping(tape.offsets.as_ptr(), out_offsets, tape.offsets.len());
            }
            0
        }
        unsafe extern "C" fn stage1_helper_mismatch(
            in_ptr: *const u8,
            len: usize,
            out_offsets: *mut u32,
            out_capacity: usize,
            out_len: *mut usize,
        ) -> i32 {
            let input =
                unsafe { std::str::from_utf8_unchecked(slice::from_raw_parts(in_ptr, len)) };
            let mut tape = build_struct_index_scalar(input);
            if let Some(first) = tape.offsets.first_mut() {
                *first = first.saturating_add(1);
            }
            unsafe {
                *out_len = tape.offsets.len();
            }
            if tape.offsets.len() > out_capacity {
                return 2;
            }
            unsafe {
                ptr::copy_nonoverlapping(tape.offsets.as_ptr(), out_offsets, tape.offsets.len());
            }
            0
        }
        unsafe extern "C" fn stage1_helper_error(
            _in_ptr: *const u8,
            _len: usize,
            _out_offsets: *mut u32,
            _out_capacity: usize,
            _out_len: *mut usize,
        ) -> i32 {
            7
        }
        unsafe extern "C" fn stage1_helper_invalid_len(
            _in_ptr: *const u8,
            _len: usize,
            _out_offsets: *mut u32,
            out_capacity: usize,
            out_len: *mut usize,
        ) -> i32 {
            unsafe {
                *out_len = out_capacity.saturating_add(1);
            }
            0
        }
        #[test]
        fn stage1_helper_self_test_accepts_matching_offsets() {
            assert!(stage1_helper_self_test(|input| {
                try_build_struct_index_with_helper(input, stage1_helper_match)
            }));
        }
        #[test]
        fn stage1_helper_self_test_rejects_mismatched_offsets() {
            assert!(!stage1_helper_self_test(|input| {
                try_build_struct_index_with_helper(input, stage1_helper_mismatch)
            }));
        }
        #[test]
        fn stage1_helper_self_test_rejects_helper_errors() {
            assert!(!stage1_helper_self_test(|input| {
                try_build_struct_index_with_helper(input, stage1_helper_error)
            }));
        }
        #[test]
        fn helper_builder_rejects_invalid_reported_length() {
            let input = "{\"a\":1}";
            assert!(try_build_struct_index_with_helper(input, stage1_helper_invalid_len).is_none());
        }
        #[cfg(feature = "cuda-stage1")]
        #[test]
        fn cuda_stage1_backend_matches_scalar_when_required_or_available() {
            let mut input = String::from("{\"rows\":[");
            for idx in 0..2048 {
                if idx != 0 {
                    input.push(',');
                }
                input.push_str("{\"id\":");
                input.push_str(&idx.to_string());
                input.push_str(",\"name\":\"row\\\\\\\"");
                input.push_str(&(idx % 17).to_string());
                input.push_str("\",\"values\":[1,2,3]}");
            }
            input.push_str("]}");
            let got = super::cuda::build_struct_index_cuda(&input);
            let Some(got) = got else {
                if std::env::var_os("JSONSTAGE1_CUDA_REQUIRE").is_some() {
                    panic!(
                        "JSONSTAGE1_CUDA_REQUIRE requires Norito to load the CUDA Stage-1 helper"
                    );
                }
                eprintln!("jsonstage1_cuda unavailable; skipping Norito CUDA Stage-1 assertion");
                return;
            };
            assert_eq!(got.offsets, build_struct_index_scalar(&input).offsets);
        }
        #[test]
        fn scalar_resume_matches_full_scan_across_mid_string_split() {
            let input = r#"{"s":"abc\\\"def\\\\ghi"}"#;
            let split = input.find("\\\"").expect("escape in input") + 1;
            let mut resumed = Vec::new();
            let (in_string, carry_bs_run_len) =
                extend_struct_index_scalar(&input.as_bytes()[..split], 0, &mut resumed, false, 0);
            let (tail_in_string, tail_carry_bs_run_len) = extend_struct_index_scalar(
                &input.as_bytes()[split..],
                split,
                &mut resumed,
                in_string,
                carry_bs_run_len,
            );
            let full = build_struct_index_scalar(input);
            assert_eq!(resumed, full.offsets);
            assert!(!tail_in_string);
            assert_eq!(tail_carry_bs_run_len, 0);
        }
        #[cfg(feature = "parallel-stage1")]
        #[test]
        fn parallel_stage1_matches_scalar_when_chunk_starts_inside_string() {
            let mut input = String::from("{\"s\":\"");
            input.push_str(&"a".repeat(300 * 1024));
            input.push_str("\",\"x\":1,\"tail\":[true,false,null]}");
            let scalar = build_struct_index_scalar(&input);
            let parallel =
                build_struct_index_parallel(&input).expect("parallel stage1 should plan chunks");
            assert_eq!(parallel.offsets, scalar.offsets);
        }
        #[cfg(feature = "parallel-stage1")]
        #[test]
        fn parallel_stage1_matches_scalar_when_chunk_splits_escaped_quote() {
            let chunk_goal = 256usize * 1024;
            let mut input = String::from("{\"s\":\"");
            let filler = chunk_goal
                .checked_sub(input.len() + 1)
                .expect("test prefix shorter than first chunk");
            input.push_str(&"a".repeat(filler));
            input.push('\\');
            input.push('"');
            input.push_str("still in string\",\"x\":1}");
            let scalar = build_struct_index_scalar(&input);
            let parallel =
                build_struct_index_parallel(&input).expect("parallel stage1 should plan chunks");
            assert_eq!(parallel.offsets, scalar.offsets);
        }
        #[cfg(target_arch = "x86_64")]
        #[test]
        fn avx2_tail_resume_matches_scalar_at_string_boundary() {
            if !std::arch::is_x86_feature_detected!("avx2") {
                return;
            }
            let doc = {
                let doc = r#"{"s":"abcdefghijklmnopqrstuvwxyz"}"#;
                let target_sub = r#""}"#;
                let width = 32;
                let bytes = doc.as_bytes();
                let sub = target_sub.as_bytes();
                let pos = bytes
                    .windows(sub.len())
                    .position(|w| w == sub)
                    .expect("substring present");
                let cur = pos % width;
                let pad = (width - cur) % width;
                let mut padded = String::with_capacity(pad + doc.len());
                for _ in 0..pad {
                    padded.push(' ');
                }
                padded.push_str(doc);
                padded
            };
            let scalar = build_struct_index_scalar(&doc);
            let avx2 = unsafe { super::build_struct_index_avx2(&doc) }.expect("avx2 stage1");
            assert_eq!(scalar.offsets, avx2.offsets, "doc: {doc}");
        }
        #[cfg(target_arch = "x86_64")]
        #[test]
        fn avx2_tail_resume_matches_scalar_with_backslash_carry() {
            if !std::arch::is_x86_feature_detected!("avx2") {
                return;
            }
            let doc = {
                let doc = r#"{"s":"abcdefghijklmnopqrstuvwx\\\\"}"#;
                let target_sub = r#"\\\\"}"#;
                let lane = 29;
                let width = 32;
                let bytes = doc.as_bytes();
                let sub = target_sub.as_bytes();
                let pos = bytes
                    .windows(sub.len())
                    .position(|w| w == sub)
                    .expect("substring present");
                let cur = pos % width;
                let want = lane % width;
                let pad = (width + want - cur) % width;
                let mut padded = String::with_capacity(pad + doc.len());
                for _ in 0..pad {
                    padded.push(' ');
                }
                padded.push_str(doc);
                padded
            };
            let scalar = build_struct_index_scalar(&doc);
            let avx2 = unsafe { super::build_struct_index_avx2(&doc) }.expect("avx2 stage1");
            assert_eq!(scalar.offsets, avx2.offsets, "doc: {doc}");
        }
        #[cfg(all(feature = "simd-accel", target_arch = "aarch64"))]
        #[test]
        fn neon_tail_resume_matches_scalar_at_string_boundary() {
            let doc = {
                let doc = r#"{"s":"abcdefghijklmnop"}"#;
                let target_sub = r#""}"#;
                let width = 16;
                let bytes = doc.as_bytes();
                let sub = target_sub.as_bytes();
                let pos = bytes
                    .windows(sub.len())
                    .position(|w| w == sub)
                    .expect("substring present");
                let cur = pos % width;
                let pad = (width - cur) % width;
                let mut padded = String::with_capacity(pad + doc.len());
                for _ in 0..pad {
                    padded.push(' ');
                }
                padded.push_str(doc);
                padded
            };
            let scalar = build_struct_index_scalar(&doc);
            let neon = unsafe { super::build_struct_index_neon(&doc) }.expect("neon stage1");
            assert_eq!(scalar.offsets, neon.offsets, "doc: {doc}");
        }
        #[cfg(all(feature = "simd-accel", target_arch = "aarch64"))]
        #[test]
        fn neon_tail_resume_matches_scalar_with_backslash_carry() {
            let doc = {
                let doc = r#"{"s":"abcdefghijklm\\\\"}"#;
                let target_sub = r#"\\\\"}"#;
                let lane = 13;
                let width = 16;
                let bytes = doc.as_bytes();
                let sub = target_sub.as_bytes();
                let pos = bytes
                    .windows(sub.len())
                    .position(|w| w == sub)
                    .expect("substring present");
                let cur = pos % width;
                let want = lane % width;
                let pad = (width + want - cur) % width;
                let mut padded = String::with_capacity(pad + doc.len());
                for _ in 0..pad {
                    padded.push(' ');
                }
                padded.push_str(doc);
                padded
            };
            let scalar = build_struct_index_scalar(&doc);
            let neon = unsafe { super::build_struct_index_neon(&doc) }.expect("neon stage1");
            assert_eq!(scalar.offsets, neon.offsets, "doc: {doc}");
        }
    }
    pub fn build_struct_index(input: &str) -> StructIndex {
        // Small inputs: prefer the scalar reference to avoid accelerator overheads
        // Benchmarks (`examples/stage1_cutover`) show SIMD wins start to dominate
        // around 6–8 KiB, with a slight regression at ~4 KiB; set the cutover a
        // bit higher than before to avoid thrashing on tiny payloads while still
        // exercising accelerated paths for typical documents.
        const SMALL_BYTES: usize = 4096;
        if input.len() < SMALL_BYTES {
            return build_struct_index_scalar(input);
        }
        #[cfg(feature = "parallel-stage1")]
        {
            // Parallel tape build for large inputs; deterministic merge.
            if input.len() >= par_min_bytes()
                && let Some(t) = build_struct_index_parallel(input)
            {
                debug_stage1_backend("parallel");
                return t;
            }
        }
        // Compile-time preferred paths when target features are enabled
        #[cfg(all(
            feature = "simd-accel",
            target_arch = "aarch64",
            target_feature = "neon"
        ))]
        {
            if let Some(t) = unsafe { build_struct_index_neon(input) } {
                debug_stage1_backend("neon-ct");
                return validate_accel("neon-ct", input, t);
            }
        }
        #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
        {
            if let Some(t) = unsafe { build_struct_index_avx2(input) } {
                debug_stage1_backend("avx2-ct");
                return validate_accel("avx2-ct", input, t);
            }
        }
        #[cfg(feature = "metal-stage1")]
        {
            if input.len() >= stage1_gpu_min_bytes()
                && let Some(t) = metal::build_struct_index_metal(input)
            {
                debug_stage1_backend("metal");
                return validate_accel("metal", input, t);
            }
        }
        #[cfg(feature = "cuda-stage1")]
        {
            if input.len() >= stage1_gpu_min_bytes()
                && let Some(t) = cuda::build_struct_index_cuda(input)
            {
                debug_stage1_backend("cuda");
                return validate_accel("cuda", input, t);
            }
        }
        #[cfg(target_arch = "x86_64")]
        {
            if std::arch::is_x86_feature_detected!("avx2") {
                // SAFETY: guarded by runtime feature detection
                if let Some(t) = unsafe { build_struct_index_avx2(input) } {
                    debug_stage1_backend("avx2");
                    return validate_accel("avx2", input, t);
                }
            }
        }
        #[cfg(all(feature = "simd-accel", target_arch = "aarch64"))]
        {
            if std::arch::is_aarch64_feature_detected!("neon") {
                // SAFETY: guarded by runtime feature detection
                if let Some(t) = unsafe { build_struct_index_neon(input) } {
                    debug_stage1_backend("neon");
                    return validate_accel("neon", input, t);
                }
            }
        }
        debug_stage1_backend("scalar");
        build_struct_index_scalar(input)
    }
    #[cfg(feature = "parallel-stage1")]
    const PAR_STAGE1_MIN_BYTES_DEFAULT: usize = 1 << 20;
    #[cfg(any(test, debug_assertions))]
    #[cfg(feature = "parallel-stage1")]
    fn par_min_bytes() -> usize {
        use std::sync::OnceLock;
        static V: OnceLock<usize> = OnceLock::new();
        *V.get_or_init(|| {
            std::env::var("NORITO_PAR_STAGE1_MIN")
                .ok()
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(PAR_STAGE1_MIN_BYTES_DEFAULT) // 1 MiB default
        })
    }
    #[cfg(all(feature = "parallel-stage1", not(any(test, debug_assertions))))]
    fn par_min_bytes() -> usize {
        PAR_STAGE1_MIN_BYTES_DEFAULT
    }
    #[cfg(any(feature = "metal-stage1", feature = "cuda-stage1", test))]
    fn stage1_gpu_min_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .expect("stage1 gpu min mutex")
    }
    #[cfg(any(feature = "metal-stage1", feature = "cuda-stage1", test))]
    const STAGE1_GPU_MIN_DEFAULT: usize = 192 * 1024;
    #[cfg(any(feature = "metal-stage1", feature = "cuda-stage1", test))]
    static STAGE1_GPU_MIN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    #[cfg(any(feature = "metal-stage1", feature = "cuda-stage1", test))]
    fn stage1_gpu_min_bytes_locked(_guard: &std::sync::MutexGuard<'static, ()>) -> usize {
        use std::sync::atomic::Ordering;
        let cached = STAGE1_GPU_MIN.load(Ordering::Relaxed);
        if cached != 0 {
            return cached;
        }
        let parsed = if cfg!(any(test, debug_assertions)) {
            std::env::var("NORITO_STAGE1_GPU_MIN_BYTES")
                .ok()
                .and_then(|s| s.parse::<usize>().ok())
                .filter(|v| *v > 0)
        } else {
            None
        };
        // Tuned via `examples/stage1_cutover` runs (see `benchmarks/norito_stage1/cutover.csv`):
        // SIMD catches up around 6–8 KiB and GPU tapers in around ~192 KiB once launch
        // overheads and chunked CRC64/Stage1 kernels are amortised.
        let min_bytes = parsed.unwrap_or(STAGE1_GPU_MIN_DEFAULT);
        STAGE1_GPU_MIN.store(min_bytes, Ordering::Relaxed);
        min_bytes
    }
    #[cfg(any(feature = "metal-stage1", feature = "cuda-stage1"))]
    fn stage1_gpu_min_bytes() -> usize {
        let guard = stage1_gpu_min_lock();
        stage1_gpu_min_bytes_locked(&guard)
    }
    #[cfg(test)]
    mod stage1_gpu_min_tests {
        use super::{STAGE1_GPU_MIN, stage1_gpu_min_bytes_locked};
        use std::sync::atomic::Ordering;
        #[test]
        fn defaults_when_env_missing() {
            let guard = super::stage1_gpu_min_lock();
            unsafe { std::env::remove_var("NORITO_STAGE1_GPU_MIN_BYTES") };
            STAGE1_GPU_MIN.store(0, Ordering::Relaxed);
            assert_eq!(stage1_gpu_min_bytes_locked(&guard), 192 * 1024);
            STAGE1_GPU_MIN.store(0, Ordering::Relaxed);
        }
        #[test]
        fn respects_env_override() {
            let guard = super::stage1_gpu_min_lock();
            unsafe { std::env::set_var("NORITO_STAGE1_GPU_MIN_BYTES", "65536") };
            STAGE1_GPU_MIN.store(0, Ordering::Relaxed);
            assert_eq!(stage1_gpu_min_bytes_locked(&guard), 65_536);
            unsafe { std::env::remove_var("NORITO_STAGE1_GPU_MIN_BYTES") };
            STAGE1_GPU_MIN.store(0, Ordering::Relaxed);
        }
    }
    #[cfg(feature = "parallel-stage1")]
    fn build_struct_index_parallel(input: &str) -> Option<StructIndex> {
        let ncpu = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(2);
        let len = input.len();
        let chunk_goal = 256 * 1024; // 256 KiB target
        let max_chunks = ncpu * 4; // avoid oversharding
        let chunks = len.div_ceil(chunk_goal).clamp(2, max_chunks);
        // Partition input
        let mut ranges = Vec::with_capacity(chunks);
        let mut start = 0usize;
        for _ in 0..chunks {
            if start >= len {
                break;
            }
            let end = (start + chunk_goal).min(len);
            ranges.push((start, end));
            start = end;
        }
        // Compute all incoming quote-state variants per chunk, then compose the
        // states in chunk order. This keeps chunking parallel without assuming a
        // chunk starts outside a string.
        #[cfg(feature = "parallel-stage1-rayon")]
        let mut parts: Vec<Stage1ChunkPlan> = {
            use rayon::prelude::*;
            ranges
                .into_par_iter()
                .map(|(s, e)| plan_stage1_chunk(s, &input.as_bytes()[s..e]))
                .collect()
        };
        #[cfg(not(feature = "parallel-stage1-rayon"))]
        let mut parts: Vec<Stage1ChunkPlan> = {
            use std::thread;
            let mut handles = Vec::new();
            for (s, e) in ranges.into_iter() {
                // Spawn with an owned slice to satisfy the 'static bound on thread::spawn.
                let chunk = input.as_bytes()[s..e].to_vec();
                handles.push(thread::spawn(move || plan_stage1_chunk(s, &chunk)));
            }
            let mut v = Vec::new();
            for h in handles {
                v.push(h.join().ok()?);
            }
            v
        };
        parts.sort_by_key(|part| part.base);
        Some(compose_stage1_chunks(parts))
    }
    #[cfg(all(feature = "parallel-stage1", feature = "bench-internal"))]
    pub fn build_struct_index_parallel_bench(input: &str) -> StructIndex {
        build_struct_index_parallel(input).unwrap_or_else(|| build_struct_index_scalar(input))
    }
    #[cfg(all(feature = "parallel-stage1", feature = "bench-internal"))]
    pub fn build_struct_index_parallel_with_chunks(
        input: &str,
        chunks_override: usize,
    ) -> StructIndex {
        use std::thread;
        let len = input.len();
        let chunks = chunks_override.max(1);
        let step = len.div_ceil(chunks);
        let mut handles = Vec::new();
        for c in 0..chunks {
            let start = c * step;
            if start >= len {
                break;
            }
            let end = ((c + 1) * step).min(len);
            let chunk = input.as_bytes()[start..end].to_vec();
            handles.push(thread::spawn(move || plan_stage1_chunk(start, &chunk)));
        }
        let mut parts = Vec::new();
        for h in handles {
            parts.push(h.join().unwrap());
        }
        parts.sort_by_key(|part| part.base);
        compose_stage1_chunks(parts)
    }
    #[cfg(feature = "parallel-stage1")]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Stage1ChunkState {
        Outside,
        InsideEvenBackslash,
        InsideOddBackslash,
    }
    #[cfg(feature = "parallel-stage1")]
    impl Stage1ChunkState {
        fn initial(self) -> (bool, usize) {
            match self {
                Self::Outside => (false, 0),
                Self::InsideEvenBackslash => (true, 0),
                Self::InsideOddBackslash => (true, 1),
            }
        }
        fn from_end(in_string: bool, carry_bs_run_len: usize) -> Self {
            if !in_string {
                Self::Outside
            } else if (carry_bs_run_len & 1) == 0 {
                Self::InsideEvenBackslash
            } else {
                Self::InsideOddBackslash
            }
        }
        fn index(self) -> usize {
            match self {
                Self::Outside => 0,
                Self::InsideEvenBackslash => 1,
                Self::InsideOddBackslash => 2,
            }
        }
    }
    #[cfg(feature = "parallel-stage1")]
    struct Stage1ChunkVariant {
        offsets: Vec<u32>,
        end_state: Stage1ChunkState,
    }
    #[cfg(feature = "parallel-stage1")]
    struct Stage1ChunkPlan {
        base: usize,
        variants: [Stage1ChunkVariant; 3],
    }
    #[cfg(feature = "parallel-stage1")]
    fn plan_stage1_chunk(base: usize, input: &[u8]) -> Stage1ChunkPlan {
        Stage1ChunkPlan {
            base,
            variants: [
                scan_stage1_chunk_variant(base, input, Stage1ChunkState::Outside),
                scan_stage1_chunk_variant(base, input, Stage1ChunkState::InsideEvenBackslash),
                scan_stage1_chunk_variant(base, input, Stage1ChunkState::InsideOddBackslash),
            ],
        }
    }
    #[cfg(feature = "parallel-stage1")]
    fn scan_stage1_chunk_variant(
        base: usize,
        input: &[u8],
        state: Stage1ChunkState,
    ) -> Stage1ChunkVariant {
        let (in_string, carry_bs_run_len) = state.initial();
        let mut offsets = Vec::new();
        let (end_in_string, end_carry_bs_run_len) =
            extend_struct_index_scalar(input, base, &mut offsets, in_string, carry_bs_run_len);
        Stage1ChunkVariant {
            offsets,
            end_state: Stage1ChunkState::from_end(end_in_string, end_carry_bs_run_len),
        }
    }
    #[cfg(feature = "parallel-stage1")]
    fn compose_stage1_chunks(parts: Vec<Stage1ChunkPlan>) -> StructIndex {
        let mut state = Stage1ChunkState::Outside;
        let mut offsets = Vec::new();
        for part in parts {
            let variant = part
                .variants
                .into_iter()
                .nth(state.index())
                .expect("stage1 chunk variant index is valid");
            offsets.extend(variant.offsets);
            state = variant.end_state;
        }
        StructIndex { offsets }
    }
    // Continue the scalar structural scan from an arbitrary byte boundary while
    // preserving quote state and a trailing run of backslashes from the prior chunk.
    fn extend_struct_index_scalar(
        input: &[u8],
        base: usize,
        offsets: &mut Vec<u32>,
        mut in_string: bool,
        mut carry_bs_run_len: usize,
    ) -> (bool, usize) {
        if !in_string {
            carry_bs_run_len = 0;
        }
        for (idx, &byte) in input.iter().enumerate() {
            let off = (base + idx) as u32;
            if in_string {
                match byte {
                    b'\\' => {
                        carry_bs_run_len += 1;
                    }
                    b'"' => {
                        if (carry_bs_run_len & 1) == 0 {
                            in_string = false;
                            offsets.push(off);
                        }
                        carry_bs_run_len = 0;
                    }
                    _ => {
                        carry_bs_run_len = 0;
                    }
                }
                continue;
            }
            match byte {
                b'"' => {
                    in_string = true;
                    offsets.push(off);
                }
                b'{' | b'}' | b'[' | b']' | b':' | b',' => offsets.push(off),
                _ => {}
            }
        }
        if !in_string {
            carry_bs_run_len = 0;
        }
        (in_string, carry_bs_run_len)
    }
    /// Reference scalar builder used for correctness and as a fallback.
    ///
    /// The fast paths (`build_struct_index_neon` / `build_struct_index_avx2`) already
    /// implement the nibble-LUT SIMD classification. This scalar implementation
    /// remains the canonical, portable baseline.
    fn build_struct_index_scalar(input: &str) -> StructIndex {
        let mut offsets = Vec::new();
        let _ = extend_struct_index_scalar(input.as_bytes(), 0, &mut offsets, false, 0);
        StructIndex { offsets }
    }
    #[cfg(all(feature = "simd-accel", target_arch = "aarch64"))]
    /// NEON-accelerated structural indexer with bitboard iteration.
    ///
    /// Computes quote/backslash/structural bitmasks per 16-byte block and iterates
    /// bitboards (trailing-zeros) instead of per-byte scans. Maintains carry for
    /// trailing backslash runs and in-string parity across blocks to match scalar.
    unsafe fn build_struct_index_neon(input: &str) -> Option<StructIndex> {
        use core::arch::aarch64::*;
        unsafe {
            let bytes = input.as_bytes();
            let mut offsets: Vec<u32> = Vec::new();
            let mut i = 0usize;
            let mut in_string = false;
            let mut carry_bs_run_len: usize = 0;
            #[inline(always)]
            fn to_mask(v: uint8x16_t) -> u16 {
                unsafe {
                    // Extract MSBs and pack into a 16-bit mask (LSB=lane0)
                    let msb = vshrq_n_u8(v, 7);
                    let mut tmp = [0u8; 16];
                    vst1q_u8(tmp.as_mut_ptr(), msb);
                    let mut m: u16 = 0;
                    let mut j = 0;
                    while j < 16 {
                        m |= ((tmp[j] & 1) as u16) << j;
                        j += 1;
                    }
                    m
                }
            }
            while i + 16 <= bytes.len() {
                let ptr = bytes.as_ptr().add(i);
                let v = vld1q_u8(ptr);
                // Quote predicate
                let is_quote = vceqq_u8(v, vdupq_n_u8(b'"'));
                let qmask = to_mask(is_quote);
                // Nibble-LUT classification for structurals { } [ ] : ,
                // Map low-nibble -> allowed high-nibble groups (bits: 1=>0x2, 2=>0x3, 4=>0x5, 8=>0x7)
                const STRUCT_LO: [u8; 16] = [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,  /*0xA ':' -> hi=0x3*/
                    12, /*0xB '{' or '[' -> hi=0x7 or 0x5*/
                    1,  /*0xC ',' -> hi=0x2*/
                    12, /*0xD '}' or ']' -> hi=0x7 or 0x5*/
                    0,  /*0xE */
                    0,  /*0xF */
                ];
                // Map high-nibble -> group bitmask as above
                const HI_GROUP: [u8; 16] = [0, 0, 1, 2, 0, 4, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0];
                let lo = vandq_u8(v, vdupq_n_u8(0x0f));
                let hi = vshrq_n_u8(v, 4);
                let struct_lo_tbl = vld1q_u8(STRUCT_LO.as_ptr());
                let hi_group_tbl = vld1q_u8(HI_GROUP.as_ptr());
                let lo_map = vqtbl1q_u8(struct_lo_tbl, lo);
                let hi_map = vqtbl1q_u8(hi_group_tbl, hi);
                // Test for nonzero intersection per lane -> 0xFF where true
                let structurals = vtstq_u8(lo_map, hi_map);
                let smask = to_mask(structurals);
                // Compute mask of unescaped quotes using quote and backslash bitboards.
                let bslash = vceqq_u8(v, vdupq_n_u8(b'\\'));
                let bmask = to_mask(bslash);
                let mut unescaped: u16 = 0;
                let mut qm: u16 = qmask;
                while qm != 0 {
                    let tz = qm.trailing_zeros() as usize;
                    // Count immediate preceding backslashes via bitboard
                    let mut run = 0usize;
                    let mut p = tz as isize - 1;
                    while p >= 0 {
                        if ((bmask >> (p as usize)) & 1) == 1 {
                            run += 1;
                            p -= 1;
                        } else {
                            break;
                        }
                    }
                    if p < 0 {
                        run += carry_bs_run_len;
                    }
                    if (run & 1) == 0 {
                        unescaped |= 1u16 << tz;
                    }
                    qm &= qm - 1; // clear lowest set bit
                }
                // Iterate union of unescaped quotes and structurals; toggle in_string on quotes
                let mut union = unescaped | smask;
                while union != 0 {
                    let tz = union.trailing_zeros() as usize;
                    let bit = 1u16 << tz;
                    if (unescaped & bit) != 0 {
                        in_string = !in_string;
                        offsets.push((i + tz) as u32);
                    } else if !in_string {
                        // structural outside string
                        offsets.push((i + tz) as u32);
                    }
                    union &= union - 1;
                }
                // Trailing backslash run length becomes carry for next block
                // We still examine the block tail directly (cheaper than reconstructing a rank prefix)
                let mut arr = [0u8; 16];
                vst1q_u8(arr.as_mut_ptr(), v);
                let mut t = 0usize;
                let mut p = 15isize;
                while p >= 0 && arr[p as usize] == b'\\' {
                    t += 1;
                    p -= 1;
                }
                carry_bs_run_len = t;
                i += 16;
            }
            if i < bytes.len() {
                let _ = extend_struct_index_scalar(
                    &bytes[i..],
                    i,
                    &mut offsets,
                    in_string,
                    carry_bs_run_len,
                );
            }
            Some(StructIndex { offsets })
        }
    }
    /// Helper to access the scalar reference builder for parity tests.
    ///
    /// Exposed under the `json` feature for integration tests comparing
    /// optimized builders to the scalar reference.
    pub fn build_struct_index_scalar_test(input: &str) -> StructIndex {
        build_struct_index_scalar(input)
    }
    #[cfg(feature = "bench-internal")]
    /// Expose scalar builder to benchmarks to compare against NEON and future GPU paths.
    pub fn build_struct_index_scalar_bench(input: &str) -> StructIndex {
        build_struct_index_scalar(input)
    }
    /// AVX2 Stage-1 builder using nibble-LUT (vpshufb) and bitboard iteration.
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn build_struct_index_avx2(input: &str) -> Option<StructIndex> {
        use core::arch::x86_64::*;
        unsafe {
            let bytes = input.as_bytes();
            let mut offsets: Vec<u32> = Vec::new();
            let mut i = 0usize;
            let mut in_string = false;
            let mut carry_bs_run_len: usize = 0;
            // Prepare 32-byte lookup tables (lo/hi replicated)
            let lo_tbl_16: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 12, 1, 12, 0, 0];
            let hi_tbl_16: [u8; 16] = [0, 0, 1, 2, 0, 4, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0];
            let lo_tbl = _mm256_set_m128i(
                _mm_loadu_si128(lo_tbl_16.as_ptr() as *const __m128i),
                _mm_loadu_si128(lo_tbl_16.as_ptr() as *const __m128i),
            );
            let hi_tbl = _mm256_set_m128i(
                _mm_loadu_si128(hi_tbl_16.as_ptr() as *const __m128i),
                _mm_loadu_si128(hi_tbl_16.as_ptr() as *const __m128i),
            );
            let mask_0f = _mm256_set1_epi8(0x0f_i8);
            let zero = _mm256_setzero_si256();
            while i + 32 <= bytes.len() {
                let ptr = bytes.as_ptr().add(i) as *const __m256i;
                let v = _mm256_loadu_si256(ptr);
                // Quotes
                let quote = _mm256_cmpeq_epi8(v, _mm256_set1_epi8(b'"' as i8));
                let mut qmask = _mm256_movemask_epi8(quote) as u32;
                // Structurals via LUT
                let lo = _mm256_and_si256(v, mask_0f);
                let hi = _mm256_and_si256(_mm256_srli_epi16(v, 4), mask_0f);
                let lo_map = _mm256_shuffle_epi8(lo_tbl, lo);
                let hi_map = _mm256_shuffle_epi8(hi_tbl, hi);
                let inter = _mm256_and_si256(lo_map, hi_map);
                let nonzero =
                    _mm256_xor_si256(_mm256_cmpeq_epi8(inter, zero), _mm256_set1_epi8(-1));
                let smask = _mm256_movemask_epi8(nonzero) as u32;
                // Backslash bitboard for escaped-quote parity
                let bslash = _mm256_cmpeq_epi8(v, _mm256_set1_epi8(b'\\' as i8));
                let bmask = _mm256_movemask_epi8(bslash) as u32;
                // Unescaped quotes: iterate only quote bits
                let mut unescaped: u32 = 0;
                while qmask != 0 {
                    let tz = qmask.trailing_zeros() as usize;
                    // Count immediate preceding backslashes using the bitboard
                    let mut run = 0usize;
                    let mut p = tz as isize - 1;
                    while p >= 0 {
                        if ((bmask >> (p as usize)) & 1) == 1 {
                            run += 1;
                            p -= 1;
                        } else {
                            break;
                        }
                    }
                    if p < 0 {
                        run += carry_bs_run_len;
                    }
                    if (run & 1) == 0 {
                        unescaped |= 1u32 << tz;
                    }
                    qmask &= qmask - 1;
                }
                // Iterate union and push offsets
                let mut union = unescaped | smask;
                while union != 0 {
                    let tz = union.trailing_zeros() as usize;
                    let bit = 1u32 << tz;
                    if (unescaped & bit) != 0 {
                        in_string = !in_string;
                        offsets.push((i + tz) as u32);
                    } else if !in_string {
                        offsets.push((i + tz) as u32);
                    }
                    union &= union - 1;
                }
                // Trailing backslash run carry: examine bytes directly for the tail
                let mut arr = [0u8; 32];
                _mm256_storeu_si256(arr.as_mut_ptr() as *mut __m256i, v);
                let mut t = 0usize;
                let mut p = 31isize;
                while p >= 0 && arr[p as usize] == b'\\' {
                    t += 1;
                    p -= 1;
                }
                carry_bs_run_len = t;
                i += 32;
            }
            if i < bytes.len() {
                let _ = extend_struct_index_scalar(
                    &bytes[i..],
                    i,
                    &mut offsets,
                    in_string,
                    carry_bs_run_len,
                );
            }
            Some(StructIndex { offsets })
        }
    }
    #[cfg(feature = "metal-stage1")]
    mod metal {
        use super::StructIndex;
        use std::{
            ffi::{c_char, c_int, c_void},
            sync::{Mutex, OnceLock},
        };
        #[cfg(unix)]
        unsafe extern "C" {
            fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
            fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
            fn dlclose(handle: *mut c_void) -> c_int;
        }
        const RTLD_LAZY: c_int = 1;
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        #[link(name = "Metal", kind = "framework")]
        unsafe extern "C" {
            fn MTLCreateSystemDefaultDevice() -> *mut c_void;
        }
        #[link(name = "objc")]
        unsafe extern "C" {
            fn objc_autoreleasePoolPush() -> *mut c_void;
            fn objc_autoreleasePoolPop(pool: *mut c_void);
        }
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        struct MetalLib {
            _handle: *mut c_void,
            func: super::Stage1HelperFn,
        }
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        unsafe impl Send for MetalLib {}
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        unsafe impl Sync for MetalLib {}
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        static METAL_LIB: OnceLock<Mutex<Option<MetalLib>>> = OnceLock::new();
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        pub(super) fn reset_cached_library() {
            if let Some(cache) = METAL_LIB.get() {
                *cache.lock().expect("metal cache poisoned") = None;
            }
        }
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        unsafe fn load_metal_library() -> Option<MetalLib> {
            unsafe {
                // Wrap device creation in an autorelease pool to avoid leaks.
                let pool = objc_autoreleasePoolPush();
                let avail = !MTLCreateSystemDefaultDevice().is_null();
                objc_autoreleasePoolPop(pool);
                if !avail {
                    return None;
                }
                use std::{env, ffi::CString, os::unix::ffi::OsStrExt, path::PathBuf};
                let mut lib = std::ptr::null_mut();
                let mut candidates: Vec<PathBuf> = Vec::new();
                if let Ok(exe) = env::current_exe()
                    && let Some(dir) = exe.parent()
                {
                    candidates.push(dir.join("libjsonstage1_metal.dylib"));
                    candidates.push(dir.join("../lib/libjsonstage1_metal.dylib"));
                }
                for path in candidates {
                    let bytes = path.as_os_str().as_bytes();
                    if bytes.contains(&0) {
                        continue;
                    }
                    if let Ok(cpath) = CString::new(bytes) {
                        let handle = dlopen(cpath.as_ptr(), RTLD_LAZY);
                        if !handle.is_null() {
                            lib = handle;
                            break;
                        }
                    }
                }
                if lib.is_null() {
                    return None;
                }
                let sym = dlsym(lib, c"json_stage1_build_tape".as_ptr());
                if sym.is_null() {
                    let _ = dlclose(lib);
                    return None;
                }
                let func: super::Stage1HelperFn = std::mem::transmute(sym);
                if !super::stage1_helper_self_test(|input| {
                    super::try_build_struct_index_with_helper(input, func)
                }) {
                    let _ = dlclose(lib);
                    return None;
                }
                Some(MetalLib { _handle: lib, func })
            }
        }
        /// Attempt to build a structural tape using a dynamically loaded Metal implementation.
        /// Returns None when Metal is unavailable or the helper dylib is not present.
        pub fn build_struct_index_metal(input: &str) -> Option<StructIndex> {
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            unsafe {
                let cache = METAL_LIB.get_or_init(|| Mutex::new(None));
                let mut guard = cache.lock().expect("metal cache poisoned");
                if guard.is_none() {
                    *guard = load_metal_library();
                }
                let lib = guard.as_ref()?;
                super::try_build_struct_index_with_helper(input, lib.func)
            }
            #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
            {
                let _ = input;
                None
            }
        }
    }
    #[cfg(feature = "cuda-stage1")]
    mod cuda {
        use super::StructIndex;
        use std::{
            ffi::{c_char, c_int, c_void},
            sync::{Mutex, OnceLock},
        };
        #[cfg(unix)]
        unsafe extern "C" {
            fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
            fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
            fn dlclose(handle: *mut c_void) -> c_int;
        }
        const RTLD_LAZY: c_int = 1;
        struct CudaLib {
            _handle: *mut c_void,
            func: super::Stage1HelperFn,
        }
        unsafe impl Send for CudaLib {}
        unsafe impl Sync for CudaLib {}
        static CUDA_LIB: OnceLock<Mutex<Option<CudaLib>>> = OnceLock::new();
        pub(super) fn reset_cached_library() {
            if let Some(cache) = CUDA_LIB.get() {
                *cache.lock().expect("cuda cache poisoned") = None;
            }
        }
        #[cfg(target_os = "macos")]
        unsafe fn load_cuda_library() -> Option<CudaLib> {
            use std::{env, ffi::CString, os::unix::ffi::OsStrExt, path::PathBuf};
            let mut h = std::ptr::null_mut();
            let mut candidates: Vec<PathBuf> = Vec::new();
            if let Ok(exe) = env::current_exe()
                && let Some(dir) = exe.parent()
            {
                candidates.push(dir.join("libjsonstage1_cuda.dylib"));
                candidates.push(dir.join("../lib/libjsonstage1_cuda.dylib"));
                candidates.push(dir.join("libjsonstage1_cuda.so"));
                candidates.push(dir.join("../lib/libjsonstage1_cuda.so"));
            }
            for path in candidates {
                let bytes = path.as_os_str().as_bytes();
                if bytes.contains(&0) {
                    continue;
                }
                if let Ok(cpath) = CString::new(bytes) {
                    let handle = unsafe { dlopen(cpath.as_ptr(), RTLD_LAZY) };
                    if !handle.is_null() {
                        h = handle;
                        break;
                    }
                }
            }
            if h.is_null() {
                return None;
            }
            let sym = unsafe { dlsym(h, c"json_stage1_build_tape".as_ptr()) };
            if sym.is_null() {
                let _ = unsafe { dlclose(h) };
                return None;
            }
            let func: super::Stage1HelperFn = unsafe { std::mem::transmute(sym) };
            if !super::stage1_helper_self_test(|input| {
                super::try_build_struct_index_with_helper(input, func)
            }) {
                let _ = unsafe { dlclose(h) };
                return None;
            }
            Some(CudaLib { _handle: h, func })
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        unsafe fn load_cuda_library() -> Option<CudaLib> {
            use std::{env, ffi::CString, os::unix::ffi::OsStrExt, path::PathBuf};
            let mut h = std::ptr::null_mut();
            let mut candidates: Vec<PathBuf> = Vec::new();
            if let Ok(exe) = env::current_exe()
                && let Some(dir) = exe.parent()
            {
                candidates.push(dir.join("libjsonstage1_cuda.so"));
                candidates.push(dir.join("../lib/libjsonstage1_cuda.so"));
            }
            for path in candidates {
                let bytes = path.as_os_str().as_bytes();
                if bytes.contains(&0) {
                    continue;
                }
                if let Ok(cpath) = CString::new(bytes) {
                    let handle = unsafe { dlopen(cpath.as_ptr(), RTLD_LAZY) };
                    if !handle.is_null() {
                        h = handle;
                        break;
                    }
                }
            }
            if h.is_null() {
                return None;
            }
            let sym = unsafe { dlsym(h, c"json_stage1_build_tape".as_ptr()) };
            if sym.is_null() {
                let _ = unsafe { dlclose(h) };
                return None;
            }
            let func: super::Stage1HelperFn = unsafe { std::mem::transmute(sym) };
            if !super::stage1_helper_self_test(|input| {
                super::try_build_struct_index_with_helper(input, func)
            }) {
                let _ = unsafe { dlclose(h) };
                return None;
            }
            Some(CudaLib { _handle: h, func })
        }
        #[cfg(windows)]
        unsafe fn load_cuda_library() -> Option<CudaLib> {
            use std::{env, os::windows::ffi::OsStrExt, path::PathBuf, ptr};
            unsafe extern "system" {
                fn SetDefaultDllDirectories(directory_flags: u32) -> i32;
                fn LoadLibraryExW(
                    lp_lib_file_name: *const u16,
                    h_file: *mut c_void,
                    dw_flags: u32,
                ) -> *mut c_void;
                fn GetProcAddress(h_module: *mut c_void, lp_proc_name: *const u8) -> *mut c_void;
                fn FreeLibrary(h_lib_module: *mut c_void) -> i32;
            }
            const LOAD_LIBRARY_SEARCH_DEFAULT_DIRS: u32 = 0x0000_1000;
            const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;
            const LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR: u32 = 0x0000_0100;
            static DLL_DIRECTORY_SETUP: OnceLock<bool> = OnceLock::new();
            if !*DLL_DIRECTORY_SETUP.get_or_init(|| unsafe {
                let flags = LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_SYSTEM32;
                SetDefaultDllDirectories(flags) != 0
            }) {
                return None;
            }
            let mut candidates: Vec<PathBuf> = Vec::new();
            if let Ok(exe) = env::current_exe()
                && let Some(dir) = exe.parent()
            {
                candidates.push(dir.join("jsonstage1_cuda.dll"));
                candidates.push(dir.join("../lib").join("jsonstage1_cuda.dll"));
            }
            for path in candidates {
                let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
                let search_flags = LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32;
                let h = unsafe { LoadLibraryExW(wide.as_ptr(), ptr::null_mut(), search_flags) };
                if h.is_null() {
                    continue;
                }
                let sym = unsafe { GetProcAddress(h, b"json_stage1_build_tape\0".as_ptr()) };
                if sym.is_null() {
                    let _ = unsafe { FreeLibrary(h) };
                    continue;
                }
                let func: super::Stage1HelperFn = unsafe { std::mem::transmute(sym) };
                if !super::stage1_helper_self_test(|input| {
                    super::try_build_struct_index_with_helper(input, func)
                }) {
                    let _ = unsafe { FreeLibrary(h) };
                    continue;
                }
                return Some(CudaLib { _handle: h, func });
            }
            None
        }
        #[cfg(not(any(target_os = "macos", all(unix, not(target_os = "macos")), windows)))]
        unsafe fn load_cuda_library() -> Option<CudaLib> {
            None
        }
        pub fn build_struct_index_cuda(input: &str) -> Option<StructIndex> {
            unsafe {
                let cache = CUDA_LIB.get_or_init(|| Mutex::new(None));
                let mut guard = cache.lock().expect("cuda cache poisoned");
                if guard.is_none() {
                    *guard = load_cuda_library();
                }
                let lib = guard.as_ref()?;
                super::try_build_struct_index_with_helper(input, lib.func)
            }
        }
    }
    fn document_json_value_depth(input: &str) -> usize {
        let bytes = input.as_bytes();
        let mut container_depth = 0_usize;
        let mut maximum_depth = usize::from(
            bytes
                .iter()
                .any(|byte| !matches!(byte, b' ' | b'\n' | b'\r' | b'\t')),
        );
        let first_forbidden_depth = MAX_JSON_VALUE_NESTING_DEPTH.saturating_add(1);
        let mut in_string = false;
        let mut escaped = false;
        for (offset, &byte) in bytes.iter().enumerate() {
            if in_string {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    in_string = false;
                }
                continue;
            }
            if byte == b'"' {
                in_string = true;
                continue;
            }
            let matching_close = match byte {
                b'{' => Some(b'}'),
                b'[' => Some(b']'),
                b'}' | b']' => {
                    container_depth = container_depth.saturating_sub(1);
                    None
                }
                _ => None,
            };
            let Some(matching_close) = matching_close else {
                continue;
            };
            container_depth = container_depth.saturating_add(1);
            maximum_depth = maximum_depth.max(container_depth);
            if maximum_depth >= first_forbidden_depth {
                return first_forbidden_depth;
            }
            let mut next = offset.saturating_add(1);
            while matches!(bytes.get(next), Some(b' ' | b'\n' | b'\r' | b'\t')) {
                next = next.saturating_add(1);
            }
            if bytes.get(next).copied() != Some(matching_close) {
                maximum_depth = maximum_depth.max(container_depth.saturating_add(1));
                if maximum_depth >= first_forbidden_depth {
                    return first_forbidden_depth;
                }
            }
        }
        maximum_depth
    }
    /// A light walker over the structural index.
    pub struct TapeWalker<'a> {
        input: &'a str,
        pub idx: usize,
        pub tape: StructIndex,
        raw: usize,
        last_key_lo: usize,
        last_key_hi: usize,
        document_value_depth: usize,
    }
    /// Reset cached dynamic libraries used by the Stage-1 GPU/Metal accelerators.
    /// This allows callers to retry loading helper libraries without restarting the process.
    pub fn reset_stage1_backends() {
        #[cfg(feature = "metal-stage1")]
        {
            metal::reset_cached_library();
        }
        #[cfg(feature = "cuda-stage1")]
        {
            cuda::reset_cached_library();
        }
    }
    impl<'a> TapeWalker<'a> {
        pub fn new(input: &'a str) -> Self {
            let tape = build_struct_index(input);
            // Depth enforcement is consensus-facing, so derive it from one
            // canonical scalar scan independently of the selected hardware
            // Stage-1 implementation.
            let document_value_depth = document_json_value_depth(input);
            Self {
                input,
                idx: 0,
                tape,
                raw: 0,
                last_key_lo: 0,
                last_key_hi: 0,
                document_value_depth,
            }
        }
        /// Reject a structurally over-deep enclosing document before a fast
        /// typed parser enters generated or custom recursive code.
        #[doc(hidden)]
        pub fn ensure_document_depth(&self) -> Result<(), Error> {
            ensure_json_value_depth(self.document_value_depth)
        }
        pub fn input(&self) -> &'a str {
            self.input
        }
        pub fn raw_pos(&self) -> usize {
            self.raw
        }
        pub fn sync_to_raw(&mut self, pos: usize) {
            self.raw = pos;
            while self.idx < self.tape.offsets.len()
                && (self.tape.offsets[self.idx] as usize) < self.raw
            {
                self.idx += 1;
            }
        }
        /// Skip ASCII whitespace from the current raw position.
        pub fn skip_ws(&mut self) {
            let bytes = self.input.as_bytes();
            while self.raw < bytes.len() {
                match bytes[self.raw] {
                    b' ' | b'\n' | b'\r' | b'\t' => self.raw += 1,
                    _ => break,
                }
            }
            // Re-sync structural index if needed
            while self.idx < self.tape.offsets.len()
                && (self.tape.offsets[self.idx] as usize) < self.raw
            {
                self.idx += 1;
            }
        }
        pub fn next_struct(&mut self) -> Option<(usize, u8)> {
            if self.idx >= self.tape.offsets.len() {
                return None;
            }
            let off = self.tape.offsets[self.idx] as usize;
            self.idx += 1;
            Some((off, self.input.as_bytes()[off]))
        }
        pub fn peek_struct(&self) -> Option<(usize, u8)> {
            let i = self.idx;
            if i >= self.tape.offsets.len() {
                None
            } else {
                let off = self.tape.offsets[i] as usize;
                Some((off, self.input.as_bytes()[off]))
            }
        }
        /// Expect the next structural to be `{` and advance past it.
        pub fn expect_object_start(&mut self) -> Result<(), Error> {
            self.ensure_document_depth()?;
            match self.next_struct() {
                Some((off, b'{')) => {
                    self.raw = off + 1;
                    Ok(())
                }
                Some((off, _)) => {
                    let (byte, line, col) = pos_from_offset(self.input, off);
                    Err(Error::ExpectedObjectStart { byte, line, col })
                }
                None => {
                    let (byte, line, col) = pos_from_offset(self.input, self.raw);
                    Err(Error::UnexpectedEof { byte, line, col })
                }
            }
        }
        /// Return true if the next structural is `}`.
        pub fn peek_object_end(&self) -> Result<bool, Error> {
            Ok(matches!(self.peek_struct(), Some((_, b'}'))))
        }
        /// Expect the next structural to be `}` and advance past it.
        pub fn expect_object_end(&mut self) -> Result<(), Error> {
            match self.next_struct() {
                Some((off, b'}')) => {
                    self.raw = off + 1;
                    Ok(())
                }
                Some((off, _)) => {
                    let (byte, line, col) = pos_from_offset(self.input, off);
                    Err(Error::ExpectedObjectEnd { byte, line, col })
                }
                None => {
                    let (byte, line, col) = pos_from_offset(self.input, self.raw);
                    Err(Error::UnexpectedEof { byte, line, col })
                }
            }
        }
        /// Expect the next structural to be `[` and advance past it.
        pub fn expect_array_start(&mut self) -> Result<(), Error> {
            self.ensure_document_depth()?;
            match self.next_struct() {
                Some((off, b'[')) => {
                    self.raw = off + 1;
                    Ok(())
                }
                Some((off, _)) => {
                    let (byte, line, col) = pos_from_offset(self.input, off);
                    Err(Error::ExpectedArrayStart { byte, line, col })
                }
                None => {
                    let (byte, line, col) = pos_from_offset(self.input, self.raw);
                    Err(Error::UnexpectedEof { byte, line, col })
                }
            }
        }
        /// Expect the next structural to be `]` and advance past it.
        pub fn expect_array_end(&mut self) -> Result<(), Error> {
            match self.next_struct() {
                Some((off, b']')) => {
                    self.raw = off + 1;
                    Ok(())
                }
                Some((off, _)) => {
                    let (byte, line, col) = pos_from_offset(self.input, off);
                    Err(Error::ExpectedArrayEnd { byte, line, col })
                }
                None => {
                    let (byte, line, col) = pos_from_offset(self.input, self.raw);
                    Err(Error::UnexpectedEof { byte, line, col })
                }
            }
        }
        /// Expect the next structural to be `:` and advance past it.
        pub fn expect_colon(&mut self) -> Result<(), Error> {
            match self.next_struct() {
                Some((off, b':')) => {
                    self.raw = off + 1;
                    Ok(())
                }
                Some((off, ch)) => {
                    if ch == b'"' {
                        let (byte, line, col) = pos_from_offset(self.input, off);
                        return Err(Error::WithPos {
                            msg: "unexpected quote",
                            byte,
                            line,
                            col,
                        });
                    }
                    let (byte, line, col) = pos_from_offset(self.input, off);
                    Err(Error::ExpectedColon { byte, line, col })
                }
                None => {
                    let (byte, line, col) = pos_from_offset(self.input, self.raw);
                    Err(Error::ExpectedColon { byte, line, col })
                }
            }
        }
        /// Robust colon consumption: if the structural index got ahead/behind, resync until the next ':' at or after raw.
        pub fn expect_colon_resync(&mut self) -> Result<(), Error> {
            if self.expect_colon().is_ok() {
                return Ok(());
            }
            // Try to resync by advancing idx to the first ':' whose offset >= raw
            loop {
                match self.peek_struct() {
                    Some((off, _)) if off < self.raw => {
                        let _ = self.next_struct();
                        continue;
                    }
                    Some((off, b':')) => {
                        let _ = self.next_struct();
                        self.raw = off + 1;
                        return Ok(());
                    }
                    Some((off, b',' | b'}')) => {
                        let (byte, line, col) = pos_from_offset(self.input, off);
                        return Err(Error::ExpectedColon { byte, line, col });
                    }
                    Some((_off, _)) => {
                        let _ = self.next_struct();
                        continue;
                    }
                    None => {
                        let (byte, line, col) = pos_from_offset(self.input, self.raw);
                        return Err(Error::ExpectedColon { byte, line, col });
                    }
                }
            }
        }
        /// If the next structural is `,`, consume and return true.
        pub fn consume_comma_if_present(&mut self) -> Result<bool, Error> {
            if let Some((off, b',')) = self.peek_struct() {
                let _ = self.next_struct();
                self.raw = off + 1;
                Ok(true)
            } else {
                // Fallback: raw-based check in case the tape index drifted
                self.skip_ws_raw();
                if self.raw < self.input.len() && self.input.as_bytes()[self.raw] == b',' {
                    self.raw += 1;
                    // Re-sync idx to raw position after consuming comma
                    self.skip_ws();
                    return Ok(true);
                }
                Ok(false)
            }
        }
        /// Read the next object key and return a 64-bit hash (FNV‑1a by default).
        ///
        /// When the `crc-key-hash` feature is enabled and the CPU supports CRC32C instructions
        /// (aarch64 `crc` or x86_64 SSE4.2), a CRC32C‑based key hash is used for faster dispatch.
        /// Collisions must be guarded by a string‑equality fallback at call sites.
        pub fn read_key_hash(&mut self) -> Result<u64, Error> {
            let (open_off, ch) = match self.next_struct() {
                Some(v) => v,
                None => {
                    let (byte, line, col) = pos_from_offset(self.input, self.raw);
                    return Err(Error::ExpectedKeyHashQuote { byte, line, col });
                }
            };
            if ch != b'"' {
                let (byte, line, col) = pos_from_offset(self.input, open_off);
                return Err(Error::ExpectedKeyHashQuote { byte, line, col });
            }
            let (close_off, ch2) = match self.next_struct() {
                Some(v) => v,
                None => {
                    let (byte, line, col) = pos_from_offset(self.input, self.raw);
                    return Err(Error::UnterminatedKey { byte, line, col });
                }
            };
            if ch2 != b'"' {
                let (byte, line, col) = pos_from_offset(self.input, close_off);
                return Err(Error::UnterminatedKey { byte, line, col });
            }
            let bytes = self.input.as_bytes();
            let mut hash = key_hash::KeyHasher::new();
            let mut i = open_off + 1;
            while i < close_off {
                let b = bytes[i];
                if b == b'\\' {
                    i += 1;
                    if i >= close_off {
                        let (byte, line, col) = pos_from_offset(self.input, i);
                        return Err(Error::EofEscape { byte, line, col });
                    }
                    let esc = bytes[i];
                    i += 1;
                    match esc {
                        b'"' | b'\\' | b'/' => {
                            hash.update(esc);
                        }
                        b'b' => {
                            hash.update(0x08);
                        }
                        b'f' => {
                            hash.update(0x0C);
                        }
                        b'n' => {
                            hash.update(b'\n');
                        }
                        b'r' => {
                            hash.update(b'\r');
                        }
                        b't' => {
                            hash.update(b'\t');
                        }
                        b'u' => {
                            // Parse 4 hex digits, handle surrogate pair, hash UTF‑8
                            let hex_to_u32 = |bytes: &[u8],
                                              idx: &mut usize|
                             -> Result<u32, Error> {
                                let mut v: u32 = 0;
                                for _ in 0..4 {
                                    if *idx >= close_off {
                                        let (byte, line, col) = pos_from_offset(self.input, *idx);
                                        return Err(Error::EofHex { byte, line, col });
                                    }
                                    let c = bytes[*idx];
                                    *idx += 1;
                                    v = (v << 4)
                                        | match c {
                                            b'0'..=b'9' => (c - b'0') as u32,
                                            b'a'..=b'f' => (c - b'a' + 10) as u32,
                                            b'A'..=b'F' => (c - b'A' + 10) as u32,
                                            _ => {
                                                let (byte, line, col) =
                                                    pos_from_offset(self.input, *idx - 1);
                                                return Err(Error::InvalidHex { byte, line, col });
                                            }
                                        };
                                }
                                Ok(v)
                            };
                            let mut idx = i;
                            let hi = hex_to_u32(bytes, &mut idx)?;
                            let cp = if (0xD800..=0xDBFF).contains(&hi) {
                                // Require next sequence to be \uXXXX
                                if idx + 6 > close_off
                                    || bytes[idx] != b'\\'
                                    || bytes[idx + 1] != b'u'
                                {
                                    let (byte, line, col) = pos_from_offset(self.input, idx);
                                    return Err(Error::WithPos {
                                        msg: "expected low surrogate",
                                        byte,
                                        line,
                                        col,
                                    });
                                }
                                idx += 2; // skip \\u
                                let lo = hex_to_u32(bytes, &mut idx)?;
                                if !(0xDC00..=0xDFFF).contains(&lo) {
                                    let (byte, line, col) =
                                        pos_from_offset(self.input, idx.saturating_sub(1));
                                    return Err(Error::WithPos {
                                        msg: "invalid low surrogate",
                                        byte,
                                        line,
                                        col,
                                    });
                                }
                                0x10000 + (((hi - 0xD800) << 10) | (lo - 0xDC00))
                            } else if (0xDC00..=0xDFFF).contains(&hi) {
                                let (byte, line, col) =
                                    pos_from_offset(self.input, idx.saturating_sub(1));
                                return Err(Error::WithPos {
                                    msg: "unexpected low surrogate",
                                    byte,
                                    line,
                                    col,
                                });
                            } else {
                                hi
                            };
                            i = idx; // advance input index
                            if let Some(ch) = char::from_u32(cp) {
                                let mut buf = [0u8; 4];
                                let s = ch.encode_utf8(&mut buf);
                                for &bb in s.as_bytes() {
                                    hash.update(bb);
                                }
                            } else {
                                let (byte, line, col) =
                                    pos_from_offset(self.input, idx.saturating_sub(1));
                                return Err(Error::WithPos {
                                    msg: "invalid codepoint",
                                    byte,
                                    line,
                                    col,
                                });
                            }
                        }
                        _ => {
                            let (byte, line, col) =
                                pos_from_offset(self.input, i.saturating_sub(1));
                            return Err(Error::WithPos {
                                msg: "bad escape",
                                byte,
                                line,
                                col,
                            });
                        }
                    }
                } else {
                    hash.update(b);
                    i += 1;
                }
            }
            self.last_key_lo = open_off + 1;
            self.last_key_hi = close_off;
            self.raw = close_off + 1;
            // Validate that a colon follows the key (do not consume here)
            match self.peek_struct() {
                Some((off, b':')) => {
                    let _ = off; // presence validated; consumption left to caller
                }
                Some((off, b'"')) => {
                    let (byte, line, col) = pos_from_offset(self.input, off);
                    return Err(Error::WithPos {
                        msg: "unexpected quote",
                        byte,
                        line,
                        col,
                    });
                }
                Some((off, _)) => {
                    let (byte, line, col) = pos_from_offset(self.input, off);
                    return Err(Error::ExpectedColon { byte, line, col });
                }
                None => {
                    let (byte, line, col) = pos_from_offset(self.input, close_off);
                    return Err(Error::ExpectedColon { byte, line, col });
                }
            }
            Ok(hash.finish())
        }
        fn skip_ws_raw(&mut self) {
            let bytes = self.input.as_bytes();
            while self.raw < bytes.len() {
                match bytes[self.raw] {
                    b' ' | b'\n' | b'\r' | b'\t' => self.raw += 1,
                    _ => break,
                }
            }
        }
        /// Skip over the next JSON value using the structural index when possible.
        pub fn skip_value(&mut self) -> Result<(), Error> {
            self.ensure_document_depth()?;
            self.skip_ws_raw();
            let bytes = self.input.as_bytes();
            if self.raw >= bytes.len() {
                let (byte, line, col) = pos_from_offset(self.input, self.raw.min(bytes.len()));
                return Err(Error::UnexpectedEof { byte, line, col });
            }
            // Reuse the iterative parser walk so an unknown value cannot use
            // mismatched delimiters, malformed container syntax, duplicate
            // keys, or an unbounded skipped subtree. The complete document's
            // global depth was checked above, so the local walk only needs to
            // validate the exact subtree grammar while advancing `raw`.
            let mut parser = Parser::new_at(self.input, self.raw);
            parser.skip_value()?;
            self.sync_to_raw(parser.position());
            Ok(())
        }
        /// Return the last read key slice (without quotes), borrowed from input.
        pub fn last_key(&self) -> &'a str {
            // SAFETY: input is valid UTF-8, keys are inside quotes and by JSON rules contain valid UTF-8 bytes
            unsafe {
                std::str::from_utf8_unchecked(
                    &self.input.as_bytes()[self.last_key_lo..self.last_key_hi],
                )
            }
        }
        /// Fast inline parse of a boolean at the current raw position.
        /// Advances `raw` past the token.
        pub fn parse_bool_inline(&mut self) -> Result<bool, Error> {
            self.skip_ws_raw();
            let b = self.input.as_bytes();
            let i = self.raw;
            if i + 4 <= b.len() && &b[i..i + 4] == b"true" {
                self.raw = i + 4;
                return Ok(true);
            }
            if i + 5 <= b.len() && &b[i..i + 5] == b"false" {
                self.raw = i + 5;
                return Ok(false);
            }
            let (byte, line, col) = pos_from_offset(self.input, i.min(b.len()));
            Err(Error::ExpectedBool { byte, line, col })
        }
        /// Fast inline parse of a non-negative u64 at the current raw position.
        /// Advances `raw` past the number.
        pub fn parse_u64_inline(&mut self) -> Result<u64, Error> {
            self.skip_ws_raw();
            let b = self.input.as_bytes();
            let mut i = self.raw;
            if i < b.len() && b[i] == b'-' {
                let (byte, line, col) = pos_from_offset(self.input, i);
                return Err(Error::WithPos {
                    msg: "negative not allowed",
                    byte,
                    line,
                    col,
                });
            }
            let mut val: u64 = 0;
            let mut any = false;
            while i < b.len() {
                let c = b[i];
                if c.wrapping_sub(b'0') <= 9 {
                    let d = (c - b'0') as u64;
                    if val > (u64::MAX - d) / 10 {
                        let (byte, line, col) = pos_from_offset(self.input, i);
                        return Err(Error::U64Overflow { byte, line, col });
                    }
                    val = val * 10 + d;
                    i += 1;
                    any = true;
                } else {
                    break;
                }
            }
            if !any {
                let (byte, line, col) = pos_from_offset(self.input, self.raw.min(b.len()));
                return Err(Error::UnexpectedValue { byte, line, col });
            }
            self.raw = i;
            self.skip_ws();
            Ok(val)
        }
        /// Fast inline parse of a signed i64 at the current raw position.
        /// Advances `raw` past the number.
        pub fn parse_i64_inline(&mut self) -> Result<i64, Error> {
            self.skip_ws_raw();
            let b = self.input.as_bytes();
            let mut i = self.raw;
            let neg = if i < b.len() && b[i] == b'-' {
                i += 1;
                true
            } else {
                false
            };
            let _start_digits = i;
            let mut mag: u128 = 0;
            let mut any = false;
            while i < b.len() {
                let c = b[i];
                if c.wrapping_sub(b'0') <= 9 {
                    let d = (c - b'0') as u128;
                    // mag = mag*10 + d with overflow check up to 128 bits
                    if mag > (u128::MAX - d) / 10 {
                        let (byte, line, col) = pos_from_offset(self.input, i);
                        return Err(Error::WithPos {
                            msg: "i64 overflow",
                            byte,
                            line,
                            col,
                        });
                    }
                    mag = mag * 10 + d;
                    i += 1;
                    any = true;
                } else {
                    break;
                }
            }
            if !any {
                let (byte, line, col) = pos_from_offset(self.input, self.raw.min(b.len()));
                return Err(Error::UnexpectedValue { byte, line, col });
            }
            // Disallow fractional/exponent in i64 path
            if i < b.len() && (b[i] == b'.' || b[i] == b'e' || b[i] == b'E') {
                let (byte, line, col) = pos_from_offset(self.input, i);
                return Err(Error::WithPos {
                    msg: "expected integer",
                    byte,
                    line,
                    col,
                });
            }
            let v = if neg {
                // Allow mag up to 2^63, where 2^63 => i64::MIN
                const LIM: u128 = (i64::MAX as u128) + 1;
                if mag > LIM {
                    let (byte, line, col) = pos_from_offset(self.input, i);
                    return Err(Error::WithPos {
                        msg: "i64 overflow",
                        byte,
                        line,
                        col,
                    });
                }
                if mag == LIM { i64::MIN } else { -(mag as i64) }
            } else {
                if mag > (i64::MAX as u128) {
                    let (byte, line, col) = pos_from_offset(self.input, i);
                    return Err(Error::WithPos {
                        msg: "i64 overflow",
                        byte,
                        line,
                        col,
                    });
                }
                mag as i64
            };
            self.raw = i;
            self.skip_ws();
            Ok(v)
        }
        /// Fast inline parse of a non-negative u128 at the current raw position.
        /// Advances `raw` past the number.
        pub fn parse_u128_inline(&mut self) -> Result<u128, Error> {
            self.skip_ws_raw();
            let b = self.input.as_bytes();
            let mut i = self.raw;
            if i < b.len() && b[i] == b'-' {
                let (byte, line, col) = pos_from_offset(self.input, i);
                return Err(Error::WithPos {
                    msg: "negative not allowed",
                    byte,
                    line,
                    col,
                });
            }
            let mut val: u128 = 0;
            let mut any = false;
            while i < b.len() {
                let c = b[i];
                if c.wrapping_sub(b'0') <= 9 {
                    let d = (c - b'0') as u128;
                    if val > (u128::MAX - d) / 10 {
                        let (byte, line, col) = pos_from_offset(self.input, i);
                        return Err(Error::WithPos {
                            msg: "u128 overflow",
                            byte,
                            line,
                            col,
                        });
                    }
                    val = val * 10 + d;
                    i += 1;
                    any = true;
                } else {
                    break;
                }
            }
            if !any {
                let (byte, line, col) = pos_from_offset(self.input, self.raw.min(b.len()));
                return Err(Error::WithPos {
                    msg: "expected number",
                    byte,
                    line,
                    col,
                });
            }
            // Disallow fractional/exponent in integer path
            if i < b.len() && (b[i] == b'.' || b[i] == b'e' || b[i] == b'E') {
                let (byte, line, col) = pos_from_offset(self.input, i);
                return Err(Error::WithPos {
                    msg: "expected integer",
                    byte,
                    line,
                    col,
                });
            }
            self.raw = i;
            self.skip_ws();
            Ok(val)
        }
        /// Fast inline parse of an f64 at the current raw position. Advances `raw` past the number.
        pub fn parse_f64_inline(&mut self) -> Result<f64, Error> {
            self.skip_ws_raw();
            let b = self.input.as_bytes();
            let mut i = self.raw;
            if i >= b.len() {
                let (byte, line, col) = pos_from_offset(self.input, i);
                return Err(Error::UnexpectedEof { byte, line, col });
            }
            // optional sign
            if b[i] == b'-' {
                i += 1;
            }
            let _start = i;
            let mut saw_digit = false;
            while i < b.len() && (b[i].wrapping_sub(b'0') <= 9) {
                i += 1;
                saw_digit = true;
            }
            // JSON requires at least one integer digit before optional fraction/exponent.
            if !saw_digit {
                let (byte, line, col) = pos_from_offset(self.input, i.min(b.len()));
                return Err(Error::ExpectedDigits { byte, line, col });
            }
            // optional fraction
            if i < b.len() && b[i] == b'.' {
                i += 1;
                let mut frac_digit = false;
                while i < b.len() && (b[i].wrapping_sub(b'0') <= 9) {
                    i += 1;
                    frac_digit = true;
                }
                if !frac_digit {
                    let (byte, line, col) = pos_from_offset(self.input, i);
                    return Err(Error::ExpectedFracDigits { byte, line, col });
                }
            }
            // optional exponent
            if i < b.len() && (b[i] == b'e' || b[i] == b'E') {
                i += 1;
                if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
                    i += 1;
                }
                let mut exp_digit = false;
                while i < b.len() && (b[i].wrapping_sub(b'0') <= 9) {
                    i += 1;
                    exp_digit = true;
                }
                if !exp_digit {
                    let (byte, line, col) = pos_from_offset(self.input, i);
                    return Err(Error::ExpectedExpDigits { byte, line, col });
                }
            }
            let end = i;
            if end <= self.raw || end > b.len() {
                let (byte, line, col) = pos_from_offset(self.input, self.raw);
                return Err(Error::UnexpectedValue { byte, line, col });
            }
            let s = unsafe { std::str::from_utf8_unchecked(&b[self.raw..end]) };
            let v: f64 = s.parse().map_err(|_| {
                let (byte, line, col) = pos_from_offset(self.input, self.raw);
                Error::WithPos {
                    msg: "invalid number",
                    byte,
                    line,
                    col,
                }
            })?;
            if !v.is_finite() {
                let (byte, line, col) = pos_from_offset(self.input, self.raw);
                return Err(Error::WithPos {
                    msg: "non-finite float",
                    byte,
                    line,
                    col,
                });
            }
            self.raw = end;
            self.skip_ws();
            Ok(v)
        }
        /// Fast inline parse of a JSON string, returning a borrowed slice or an arena-owned string when escaping occurs.
        /// Advances `raw` past the string token.
        pub fn parse_string_ref_inline<'arena>(
            &mut self,
            arena: &'arena mut Arena,
        ) -> Result<StrRef<'a, 'arena>, Error> {
            self.skip_ws_raw();
            let b = self.input.as_bytes();
            let mut i = self.raw;
            if i >= b.len() || b[i] != b'"' {
                let (byte, line, col) = pos_from_offset(self.input, i.min(b.len()));
                return Err(Error::WithPos {
                    msg: "expected string",
                    byte,
                    line,
                    col,
                });
            }
            i += 1;
            let start = i;
            let mut has_escape = false;
            while i < b.len() {
                let c = b[i];
                if c == b'"' {
                    if !has_escape {
                        // borrow directly
                        let s = unsafe { std::str::from_utf8_unchecked(&b[start..i]) };
                        self.raw = i + 1;
                        self.skip_ws();
                        return Ok(StrRef::Borrowed(s));
                    }
                    // slow path: unescape into arena (supports surrogate pairs)
                    let mut out = Vec::with_capacity(i - start);
                    let mut j = start;
                    while j < i {
                        match b[j] {
                            b'\\' => {
                                j += 1;
                                if j >= i {
                                    let (byte, line, col) = pos_from_offset(self.input, j);
                                    return Err(Error::EofEscape { byte, line, col });
                                }
                                let esc = b[j];
                                j += 1;
                                match esc {
                                    b'"' => out.push(b'"'),
                                    b'\\' => out.push(b'\\'),
                                    b'/' => out.push(b'/'),
                                    b'b' => out.push(0x08),
                                    b'f' => out.push(0x0C),
                                    b'n' => out.push(b'\n'),
                                    b'r' => out.push(b'\r'),
                                    b't' => out.push(b'\t'),
                                    b'u' => {
                                        if j + 4 > i {
                                            let (byte, line, col) = pos_from_offset(self.input, j);
                                            return Err(Error::EofHex { byte, line, col });
                                        }
                                        // Read high 16-bit code unit
                                        let mut hi: u32 = 0;
                                        for _ in 0..4 {
                                            let h = b[j];
                                            hi = (hi << 4)
                                                | match h {
                                                    b'0'..=b'9' => (h - b'0') as u32,
                                                    b'a'..=b'f' => (h - b'a' + 10) as u32,
                                                    b'A'..=b'F' => (h - b'A' + 10) as u32,
                                                    _ => {
                                                        let (byte, line, col) =
                                                            pos_from_offset(self.input, j);
                                                        return Err(Error::InvalidHex {
                                                            byte,
                                                            line,
                                                            col,
                                                        });
                                                    }
                                                };
                                            j += 1;
                                        }
                                        let cp = if (0xD800..=0xDBFF).contains(&hi) {
                                            // High surrogate: require a following \uDC00..\uDFFF
                                            if j + 6 > i || b[j] != b'\\' || b[j + 1] != b'u' {
                                                let (byte, line, col) =
                                                    pos_from_offset(self.input, j.min(i));
                                                return Err(Error::WithPos {
                                                    msg: "expected low surrogate",
                                                    byte,
                                                    line,
                                                    col,
                                                });
                                            }
                                            j += 2; // skip \\u
                                            let mut lo: u32 = 0;
                                            for _ in 0..4 {
                                                let h = b[j];
                                                lo = (lo << 4)
                                                    | match h {
                                                        b'0'..=b'9' => (h - b'0') as u32,
                                                        b'a'..=b'f' => (h - b'a' + 10) as u32,
                                                        b'A'..=b'F' => (h - b'A' + 10) as u32,
                                                        _ => {
                                                            let (byte, line, col) =
                                                                pos_from_offset(self.input, j);
                                                            return Err(Error::InvalidHex {
                                                                byte,
                                                                line,
                                                                col,
                                                            });
                                                        }
                                                    };
                                                j += 1;
                                            }
                                            if !(0xDC00..=0xDFFF).contains(&lo) {
                                                let (byte, line, col) = pos_from_offset(
                                                    self.input,
                                                    j.saturating_sub(1),
                                                );
                                                return Err(Error::WithPos {
                                                    msg: "invalid low surrogate",
                                                    byte,
                                                    line,
                                                    col,
                                                });
                                            }
                                            0x10000 + (((hi - 0xD800) << 10) | (lo - 0xDC00))
                                        } else if (0xDC00..=0xDFFF).contains(&hi) {
                                            let (byte, line, col) =
                                                pos_from_offset(self.input, j.saturating_sub(1));
                                            return Err(Error::WithPos {
                                                msg: "unexpected low surrogate",
                                                byte,
                                                line,
                                                col,
                                            });
                                        } else {
                                            hi
                                        };
                                        let ch = char::from_u32(cp).ok_or_else(|| {
                                            let (byte, line, col) =
                                                pos_from_offset(self.input, j.saturating_sub(1));
                                            Error::WithPos {
                                                msg: "invalid codepoint",
                                                byte,
                                                line,
                                                col,
                                            }
                                        })?;
                                        let mut buf = [0u8; 4];
                                        let n = ch.encode_utf8(&mut buf).len();
                                        out.extend_from_slice(&buf[..n]);
                                    }
                                    _ => {
                                        let (byte, line, col) =
                                            pos_from_offset(self.input, j.saturating_sub(1));
                                        return Err(Error::WithPos {
                                            msg: "bad escape",
                                            byte,
                                            line,
                                            col,
                                        });
                                    }
                                }
                            }
                            x if x < 0x20 => {
                                let (byte, line, col) = pos_from_offset(self.input, j);
                                return Err(Error::ControlInString { byte, line, col });
                            }
                            x => {
                                out.push(x);
                                j += 1;
                            }
                        }
                    }
                    let st = std::str::from_utf8(&out).map_err(|_| Error::InvalidUtf8)?;
                    let intern = arena.alloc_str(st.as_bytes());
                    self.raw = i + 1;
                    self.skip_ws();
                    return Ok(StrRef::Owned(intern));
                }
                if c == b'\\' {
                    has_escape = true;
                    i += 2;
                    continue;
                }
                if c < 0x20 {
                    let (byte, line, col) = pos_from_offset(self.input, i);
                    return Err(Error::ControlInString { byte, line, col });
                }
                i += 1;
            }
            let (byte, line, col) = pos_from_offset(self.input, i.min(b.len()));
            Err(Error::UnterminatedString { byte, line, col })
        }
    }
    /// Streaming tokens over JSON input.
    #[derive(Debug, PartialEq)]
    pub enum Token<'a> {
        StartObject,
        EndObject,
        StartArray,
        EndArray,
        KeyBorrowed(&'a str),
        StringBorrowed(&'a str),
        Number(&'a str),
        Bool(bool),
        Null,
    }
    enum Ctx {
        Object { expecting_key: bool },
        Array,
    }
    /// Reader producing a zero-copy token stream using the structural tape.
    pub struct Reader<'a> {
        w: TapeWalker<'a>,
        stack: Vec<Ctx>,
    }
    impl<'a> Reader<'a> {
        pub fn new(input: &'a str) -> Self {
            Self {
                w: TapeWalker::new(input),
                stack: Vec::new(),
            }
        }
        fn skip_commas(&mut self) {
            loop {
                self.w.skip_ws();
                match self.w.peek_struct() {
                    Some((off, b',')) if off == self.w.raw_pos() => {
                        // Do not consume commas at top level; surface an error in next_token instead
                        if self.stack.is_empty() {
                            break;
                        }
                        let _ = self.w.consume_comma_if_present();
                        continue;
                    }
                    _ => break,
                }
            }
        }
        /// Return the next token or None at end of input.
        pub fn next_token(&mut self) -> Result<Option<Token<'a>>, Error> {
            self.w.ensure_document_depth()?;
            self.skip_commas();
            let s = self.w.input();
            let bytes = s.as_bytes();
            if self.w.raw_pos() >= bytes.len() {
                return Ok(None);
            }
            // Handle immediate structural at raw without relying on the current idx
            let raw = self.w.raw_pos();
            match bytes[raw] {
                b'{' => {
                    self.w.sync_to_raw(raw);
                    let (off, _ch) = self.w.next_struct().ok_or_else(|| {
                        let (byte, line, col) = pos_from_offset(s, self.w.raw_pos());
                        Error::UnexpectedEof { byte, line, col }
                    })?;
                    self.w.sync_to_raw(off + 1);
                    self.stack.push(Ctx::Object {
                        expecting_key: true,
                    });
                    return Ok(Some(Token::StartObject));
                }
                b'}' => {
                    self.w.sync_to_raw(raw);
                    let (off, _ch) = self.w.next_struct().ok_or_else(|| {
                        let (byte, line, col) = pos_from_offset(s, self.w.raw_pos());
                        Error::UnexpectedEof { byte, line, col }
                    })?;
                    self.w.sync_to_raw(off + 1);
                    match self.stack.pop() {
                        Some(Ctx::Object { .. }) => return Ok(Some(Token::EndObject)),
                        Some(Ctx::Array) | None => {
                            let (byte, line, col) = pos_from_offset(s, off);
                            return Err(Error::UnexpectedObjectEnd { byte, line, col });
                        }
                    }
                }
                b'[' => {
                    self.w.sync_to_raw(raw);
                    let (off, _ch) = self.w.next_struct().ok_or_else(|| {
                        let (byte, line, col) = pos_from_offset(s, self.w.raw_pos());
                        Error::UnexpectedEof { byte, line, col }
                    })?;
                    self.w.sync_to_raw(off + 1);
                    self.stack.push(Ctx::Array);
                    return Ok(Some(Token::StartArray));
                }
                b']' => {
                    self.w.sync_to_raw(raw);
                    let (off, _ch) = self.w.next_struct().ok_or_else(|| {
                        let (byte, line, col) = pos_from_offset(s, self.w.raw_pos());
                        Error::UnexpectedEof { byte, line, col }
                    })?;
                    self.w.sync_to_raw(off + 1);
                    match self.stack.pop() {
                        Some(Ctx::Array) => return Ok(Some(Token::EndArray)),
                        Some(Ctx::Object { .. }) | None => {
                            let (byte, line, col) = pos_from_offset(s, off);
                            return Err(Error::UnexpectedArrayEnd { byte, line, col });
                        }
                    }
                }
                b',' => {
                    self.w.sync_to_raw(raw);
                    if self.stack.is_empty() {
                        let (byte, line, col) = pos_from_offset(s, raw);
                        return Err(Error::UnexpectedComma { byte, line, col });
                    }
                    let consumed = self.w.consume_comma_if_present()?;
                    if !consumed {
                        // Structural index may have advanced past this comma; ensure progress.
                        self.w.sync_to_raw(raw + 1);
                    }
                    if let Some(Ctx::Object { expecting_key }) = self.stack.last_mut() {
                        *expecting_key = true;
                    }
                    return self.next_token();
                }
                b':' => {
                    self.w.sync_to_raw(raw);
                    if !matches!(self.stack.last(), Some(Ctx::Object { expecting_key: _ })) {
                        let (byte, line, col) = pos_from_offset(s, raw);
                        return Err(Error::UnexpectedColon { byte, line, col });
                    }
                    self.w.expect_colon()?;
                    return self.next_token();
                }
                _ => {}
            }
            // If the next structural is ahead of raw, parse a scalar (number/bool/null) as value
            if let Some((off, ch)) = self.w.peek_struct() {
                if off > self.w.raw_pos() {
                    let c = bytes[self.w.raw_pos()];
                    return self.parse_scalar(c);
                }
                if off == self.w.raw_pos() {
                    match ch {
                        b'{' => {
                            let (off, _ch) = self.w.next_struct().ok_or_else(|| {
                                let (byte, line, col) = pos_from_offset(s, self.w.raw_pos());
                                Error::UnexpectedEof { byte, line, col }
                            })?;
                            self.w.sync_to_raw(off + 1);
                            self.stack.push(Ctx::Object {
                                expecting_key: true,
                            });
                            return Ok(Some(Token::StartObject));
                        }
                        b'}' => {
                            let (off, _ch) = self.w.next_struct().ok_or_else(|| {
                                let (byte, line, col) = pos_from_offset(s, self.w.raw_pos());
                                Error::UnexpectedEof { byte, line, col }
                            })?;
                            self.w.sync_to_raw(off + 1);
                            match self.stack.pop() {
                                Some(Ctx::Object { .. }) => return Ok(Some(Token::EndObject)),
                                Some(Ctx::Array) | None => {
                                    let (byte, line, col) = pos_from_offset(s, off);
                                    return Err(Error::UnexpectedObjectEnd { byte, line, col });
                                }
                            }
                        }
                        b'[' => {
                            let (off, _ch) = self.w.next_struct().ok_or_else(|| {
                                let (byte, line, col) = pos_from_offset(s, self.w.raw_pos());
                                Error::UnexpectedEof { byte, line, col }
                            })?;
                            self.w.sync_to_raw(off + 1);
                            self.stack.push(Ctx::Array);
                            return Ok(Some(Token::StartArray));
                        }
                        b']' => {
                            let (off, _ch) = self.w.next_struct().ok_or_else(|| {
                                let (byte, line, col) = pos_from_offset(s, self.w.raw_pos());
                                Error::UnexpectedEof { byte, line, col }
                            })?;
                            self.w.sync_to_raw(off + 1);
                            match self.stack.pop() {
                                Some(Ctx::Array) => return Ok(Some(Token::EndArray)),
                                Some(Ctx::Object { .. }) | None => {
                                    let (byte, line, col) = pos_from_offset(s, off);
                                    return Err(Error::UnexpectedArrayEnd { byte, line, col });
                                }
                            }
                        }
                        b'"' => {
                            // Distinguish key vs value string using object sub-state.
                            let i = self.w.idx;
                            let in_object = matches!(self.stack.last(), Some(Ctx::Object { .. }));
                            if in_object
                                && matches!(
                                    self.stack.last(),
                                    Some(Ctx::Object {
                                        expecting_key: true
                                    })
                                )
                            {
                                // Expect a closing quote next on the structural tape
                                let open = self.w.tape.offsets[i] as usize;
                                let close_opt = self.w.tape.offsets.get(i + 1).copied();
                                if close_opt.is_none() || bytes[close_opt.unwrap() as usize] != b'"'
                                {
                                    // unterminated key
                                    let (byte, line, col) = pos_from_offset(s, self.w.raw_pos());
                                    return Err(Error::UnterminatedKey { byte, line, col });
                                }
                                let close = close_opt.unwrap() as usize;
                                // Valid key path
                                let _ = self.w.next_struct();
                                let _ = self.w.next_struct();
                                let key = &s[open + 1..close];
                                self.w.expect_colon()?;
                                if let Some(Ctx::Object { expecting_key }) = self.stack.last_mut() {
                                    *expecting_key = false;
                                }
                                return Ok(Some(Token::KeyBorrowed(key)));
                            } else {
                                // Value string (in object or not)
                                let (open_off, _) = self.w.next_struct().ok_or_else(|| {
                                    let (byte, line, col) = pos_from_offset(s, self.w.raw_pos());
                                    Error::UnexpectedEof { byte, line, col }
                                })?;
                                let (close_off, _) = self.w.next_struct().ok_or_else(|| {
                                    let (byte, line, col) = pos_from_offset(s, self.w.raw_pos());
                                    Error::UnexpectedEof { byte, line, col }
                                })?;
                                let val = &s[open_off + 1..close_off];
                                self.w.sync_to_raw(close_off + 1);
                                if let Some(Ctx::Object { expecting_key }) = self.stack.last_mut() {
                                    *expecting_key = true;
                                }
                                return Ok(Some(Token::StringBorrowed(val)));
                            }
                        }
                        b',' | b':' => {
                            // Should be handled by skip_commas/expect_colon; advance and continue
                            let _ = self.w.next_struct();
                            return self.next_token();
                        }
                        _ => {}
                    }
                }
            }
            // Scalar path
            let c = bytes[self.w.raw_pos()];
            self.parse_scalar(c)
        }
        fn parse_scalar(&mut self, c: u8) -> Result<Option<Token<'a>>, Error> {
            let s = self.w.input();
            match c {
                b't' | b'f' => {
                    let mut p = Parser::new_at(s, self.w.raw_pos());
                    let b = p.parse_bool()?;
                    self.w.sync_to_raw(p.position());
                    if let Some(Ctx::Object { expecting_key }) = self.stack.last_mut() {
                        *expecting_key = true;
                    }
                    Ok(Some(Token::Bool(b)))
                }
                b'n' => {
                    let mut p = Parser::new_at(s, self.w.raw_pos());
                    p.parse_null()?;
                    self.w.sync_to_raw(p.position());
                    if let Some(Ctx::Object { expecting_key }) = self.stack.last_mut() {
                        *expecting_key = true;
                    }
                    Ok(Some(Token::Null))
                }
                b'-' | b'0'..=b'9' => {
                    let start = self.w.raw_pos();
                    let bytes = s.as_bytes();
                    let mut i = start;
                    if bytes[i] == b'-' {
                        i += 1;
                    }
                    let mut saw = false;
                    while i < bytes.len() && (bytes[i]).is_ascii_digit() {
                        i += 1;
                        saw = true;
                    }
                    if i < bytes.len() && bytes[i] == b'.' {
                        i += 1;
                        let mut d = false;
                        while i < bytes.len() && bytes[i].is_ascii_digit() {
                            i += 1;
                            d = true;
                        }
                        if !d {
                            let (byte, line, col) = pos_from_offset(s, i);
                            return Err(Error::ExpectedFracDigits { byte, line, col });
                        }
                    }
                    if i < bytes.len() && (bytes[i] == b'e' || bytes[i] == b'E') {
                        i += 1;
                        if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
                            i += 1;
                        }
                        let mut d = false;
                        while i < bytes.len() && bytes[i].is_ascii_digit() {
                            i += 1;
                            d = true;
                        }
                        if !d {
                            let (byte, line, col) = pos_from_offset(s, i);
                            return Err(Error::ExpectedExpDigits { byte, line, col });
                        }
                    }
                    if !saw {
                        let (byte, line, col) = pos_from_offset(s, start);
                        return Err(Error::ExpectedDigits { byte, line, col });
                    }
                    let num = &s[start..i];
                    self.w.sync_to_raw(i);
                    if let Some(Ctx::Object { expecting_key }) = self.stack.last_mut() {
                        *expecting_key = true;
                    }
                    Ok(Some(Token::Number(num)))
                }
                _ => {
                    let (byte, line, col) = pos_from_offset(s, self.w.raw_pos());
                    Err(Error::UnexpectedValue { byte, line, col })
                }
            }
        }
        /// Return an iterator over tokens borrowing from this reader.
        pub fn tokens(&mut self) -> Tokens<'_, 'a> {
            Tokens { reader: self }
        }
        /// Inherent helper for tokenizing: returns the next token or None at end of input.
        /// This API matches tests/examples that expect `Result<Option<Token>, Error>`.
        #[allow(clippy::should_implement_trait)]
        pub fn next(&mut self) -> Result<Option<Token<'a>>, Error> {
            self.next_token()
        }
    }
    /// Iterator wrapper over `Reader`.
    pub struct Tokens<'r, 'a> {
        reader: &'r mut Reader<'a>,
    }
    impl<'r, 'a> Iterator for Tokens<'r, 'a> {
        type Item = Result<Token<'a>, Error>;
        fn next(&mut self) -> Option<Self::Item> {
            match self.reader.next_token() {
                Ok(Some(tok)) => Some(Ok(tok)),
                Ok(None) => None,
                Err(e) => Some(Err(e)),
            }
        }
    }
    /// Deserialize `T` from JSON using the generic `JsonDeserialize` path.
    pub fn from_json<T: JsonDeserialize>(s: &str) -> Result<T, Error> {
        // Preflight the complete document once, before a generated typed
        // decoder can recurse or skip a subtree with a locally rooted Parser.
        // Internal Parser::new_at calls deliberately do not repeat this scan.
        let mut p = Parser::new(s);
        p.preflight_document()?;
        p.skip_ws();
        let v = T::json_deserialize(&mut p)?;
        if let Err(error) = p.finish_document() {
            v.json_drop_after_error();
            return Err(error);
        }
        Ok(v)
    }
    /// Deserialize `T` using a `FastFromJson` implementation plus the structural tape.
    pub fn from_json_fast<'a, T>(s: &'a str) -> Result<T, Error>
    where
        T: FastFromJson<'a> + JsonDeserialize,
    {
        // Tape-first path: build structural index, then invoke the type's fast parser.
        let mut w = TapeWalker::new(s);
        w.ensure_document_depth()?;
        let mut arena = Arena::new();
        let value = T::parse(&mut w, &mut arena).map_err(|e| Error::Message(e.to_string()))?;
        // After parsing a top-level value, ensure no trailing non-whitespace remains.
        w.skip_ws();
        if w.raw_pos() < s.len() {
            let (byte, line, col) = pos_from_offset(s, w.raw_pos());
            value.json_drop_after_error();
            return Err(Error::TrailingCharacters { byte, line, col });
        }
        Ok(value)
    }
    /// Smart fast path: skip the tape for tiny inputs using the generic typed parser.
    /// Falls back to the tape-based path for larger inputs.
    pub fn from_json_fast_smart<'a, T>(s: &'a str) -> Result<T, Error>
    where
        T: FastFromJson<'a> + JsonDeserialize,
    {
        const SMALL_BYTES: usize = 256;
        if s.len() <= SMALL_BYTES {
            // Avoid structural tape for tiny inputs and use the typed parser.
            return from_json::<T>(s);
        }
        from_json_fast::<T>(s)
    }
    /// Auto-select JSON decode path for typed values.
    ///
    /// - For small inputs (<= 256 bytes), prefers the lightweight generic typed parser to
    ///   avoid structural-tape overhead.
    /// - For larger inputs, uses the `FastFromJson` structural-tape path.
    ///
    /// Note: This initial implementation requires `T` to implement both `FastFromJson` and
    /// `JsonDeserialize`. This guarantees correctness for both branches without unstable
    /// specialization. A future refinement can relax this restriction once a stable trait
    /// detection pattern lands.
    pub fn from_json_auto<'a, T>(s: &'a str) -> Result<T, Error>
    where
        T: FastFromJson<'a> + JsonDeserialize,
    {
        const SMALL_BYTES: usize = 256;
        if s.len() <= SMALL_BYTES {
            // Small inputs: avoid tape build and use the generic typed parser
            return from_json::<T>(s);
        }
        from_json_fast::<T>(s)
    }
    /// String reference that can borrow from input or from an arena.
    pub enum StrRef<'s, 'a> {
        Borrowed(&'s str),
        Owned(&'a str),
    }
    impl<'s, 'a> core::fmt::Display for StrRef<'s, 'a> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                StrRef::Borrowed(s) => f.write_str(s),
                StrRef::Owned(s) => f.write_str(s),
            }
        }
    }
    impl<'a> Parser<'a> {
        /// Parse a JSON string and return a reference either borrowed from input or
        /// allocated in the provided arena when unescaping is required.
        pub fn parse_string_ref<'b>(
            &mut self,
            arena: &'b mut Arena,
        ) -> Result<StrRef<'a, 'b>, Error> {
            self.skip_ws();
            self.expect(b'"')?;
            let b = self.s;
            let start = self.i;
            let mut i = self.i;
            let mut has_escape = false;
            while i < b.len() {
                match b[i] {
                    b'"' => {
                        if !has_escape {
                            let slice = &b[start..i];
                            let st = std::str::from_utf8(slice).map_err(|_| Error::InvalidUtf8)?;
                            self.i = i + 1;
                            return Ok(StrRef::Borrowed(st));
                        }
                        // slow path: unescape into arena (supports surrogate pairs)
                        let mut out = Vec::with_capacity(i - start);
                        let mut j = start;
                        while j < i {
                            match b[j] {
                                b'\\' => {
                                    j += 1;
                                    let esc = b.get(j).copied().ok_or_else(|| {
                                        let (byte, line, col) = self.pos_meta(j);
                                        Error::EofEscape { byte, line, col }
                                    })?;
                                    j += 1;
                                    match esc {
                                        b'"' => out.push(b'"'),
                                        b'\\' => out.push(b'\\'),
                                        b'/' => out.push(b'/'),
                                        b'b' => out.push(0x08),
                                        b'f' => out.push(0x0C),
                                        b'n' => out.push(b'\n'),
                                        b'r' => out.push(b'\r'),
                                        b't' => out.push(b'\t'),
                                        b'u' => {
                                            // Read high 16-bit code unit
                                            let mut hi: u32 = 0;
                                            for _ in 0..4 {
                                                let h = b.get(j).copied().ok_or_else(|| {
                                                    let (byte, line, col) = self.pos_meta(j);
                                                    Error::EofHex { byte, line, col }
                                                })?;
                                                hi = (hi << 4)
                                                    | match h {
                                                        b'0'..=b'9' => (h - b'0') as u32,
                                                        b'a'..=b'f' => (h - b'a' + 10) as u32,
                                                        b'A'..=b'F' => (h - b'A' + 10) as u32,
                                                        _ => {
                                                            let (byte, line, col) =
                                                                self.pos_meta(j);
                                                            return Err(Error::InvalidHex {
                                                                byte,
                                                                line,
                                                                col,
                                                            });
                                                        }
                                                    };
                                                j += 1;
                                            }
                                            let cp = if (0xD800..=0xDBFF).contains(&hi) {
                                                // Expect a following low surrogate
                                                if j + 6 > i || b[j] != b'\\' || b[j + 1] != b'u' {
                                                    let (byte, line, col) = self.pos_meta(j.min(i));
                                                    return Err(Error::WithPos {
                                                        msg: "expected low surrogate",
                                                        byte,
                                                        line,
                                                        col,
                                                    });
                                                }
                                                j += 2; // skip \\u
                                                let mut lo: u32 = 0;
                                                for _ in 0..4 {
                                                    let h = b.get(j).copied().ok_or_else(|| {
                                                        let (byte, line, col) = self.pos_meta(j);
                                                        Error::EofHex { byte, line, col }
                                                    })?;
                                                    lo = (lo << 4)
                                                        | match h {
                                                            b'0'..=b'9' => (h - b'0') as u32,
                                                            b'a'..=b'f' => (h - b'a' + 10) as u32,
                                                            b'A'..=b'F' => (h - b'A' + 10) as u32,
                                                            _ => {
                                                                let (byte, line, col) =
                                                                    self.pos_meta(j);
                                                                return Err(Error::InvalidHex {
                                                                    byte,
                                                                    line,
                                                                    col,
                                                                });
                                                            }
                                                        };
                                                    j += 1;
                                                }
                                                if !(0xDC00..=0xDFFF).contains(&lo) {
                                                    let (byte, line, col) =
                                                        self.pos_meta(j.saturating_sub(1));
                                                    return Err(Error::WithPos {
                                                        msg: "invalid low surrogate",
                                                        byte,
                                                        line,
                                                        col,
                                                    });
                                                }
                                                0x10000 + (((hi - 0xD800) << 10) | (lo - 0xDC00))
                                            } else if (0xDC00..=0xDFFF).contains(&hi) {
                                                let (byte, line, col) =
                                                    self.pos_meta(j.saturating_sub(1));
                                                return Err(Error::WithPos {
                                                    msg: "unexpected low surrogate",
                                                    byte,
                                                    line,
                                                    col,
                                                });
                                            } else {
                                                hi
                                            };
                                            let ch = char::from_u32(cp).ok_or_else(|| {
                                                let (byte, line, col) =
                                                    self.pos_meta(j.saturating_sub(1));
                                                Error::WithPos {
                                                    msg: "invalid codepoint",
                                                    byte,
                                                    line,
                                                    col,
                                                }
                                            })?;
                                            let mut buf = [0u8; 4];
                                            let n = ch.encode_utf8(&mut buf).len();
                                            out.extend_from_slice(&buf[..n]);
                                        }
                                        _ => {
                                            let (byte, line, col) =
                                                self.pos_meta(j.saturating_sub(1));
                                            return Err(Error::WithPos {
                                                msg: "bad escape",
                                                byte,
                                                line,
                                                col,
                                            });
                                        }
                                    }
                                }
                                x => {
                                    out.push(x);
                                    j += 1;
                                }
                            }
                        }
                        let st = std::str::from_utf8(&out).map_err(|_| Error::InvalidUtf8)?;
                        let intern = arena.alloc_str(st.as_bytes());
                        self.i = i + 1;
                        return Ok(StrRef::Owned(intern));
                    }
                    b'\\' => {
                        has_escape = true;
                        // If the backslash is the last character, report EOF escape
                        if i + 1 >= b.len() {
                            let (byte, line, col) = self.pos_meta(i + 1);
                            return Err(Error::EofEscape { byte, line, col });
                        }
                        i += 2;
                    }
                    x if x < 0x20 => {
                        let (byte, line, col) = self.pos_meta(i);
                        return Err(Error::ControlInString { byte, line, col });
                    }
                    _ => i += 1,
                }
            }
            let (byte, line, col) = self.pos_meta(i.min(b.len()));
            if has_escape {
                // If scanning saw an escape and we ran out of input without a closing quote,
                // prefer reporting an EOF-in-escape to help diagnostics for trailing '\\'.
                Err(Error::EofEscape { byte, line, col })
            } else {
                Err(Error::UnterminatedString { byte, line, col })
            }
        }
    }
    /// Typed, tape-first decode (prototype): parse using the structural tape directly.
    /// Error type used by FastFromJson derives.
    pub type FastPathError = super::Error;
    pub trait FastFromJson<'a>: Sized {
        fn parse<'b>(w: &mut TapeWalker<'a>, arena: &'b mut Arena) -> Result<Self, FastPathError>;
    }
    impl<const N: usize> JsonDeserialize for [u8; N] {
        fn json_deserialize(parser: &mut Parser<'_>) -> Result<Self, Error> {
            let raw = parser.parse_string()?;
            decode_hex::<N>(&raw)
        }
        fn json_from_value(value: &Value) -> Result<Self, Error> {
            if let Some(s) = value.as_str() {
                decode_hex::<N>(s)
            } else {
                json_from_value_via_string(value)
            }
        }
    }
    impl<const N: usize> JsonObjectKeyOwned for [u8; N] {
        fn from_json_key_text(key: &str) -> Result<Self, Error> {
            decode_hex::<N>(key)
        }
    }
    impl<const N: usize> FastJsonWrite for [u8; N] {
        fn write_json(&self, out: &mut String) {
            encode_hex(self, out);
        }
        fn write_json_to(&self, out: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
            bounded::write_hex_to(self, out)
        }
    }
    impl<const N: usize> JsonObjectKey for [u8; N] {
        fn visit_json_key_text<E>(
            &self,
            mut visitor: impl FnMut(&str) -> Result<(), E>,
        ) -> Result<(), E> {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            for byte in self {
                let chunk = [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 0x0f)]];
                // SAFETY: both bytes come from the ASCII hexadecimal alphabet.
                visitor(unsafe { std::str::from_utf8_unchecked(&chunk) })?;
            }
            Ok(())
        }
    }
    impl<K, V> JsonDeserialize for std::collections::HashMap<K, V>
    where
        K: JsonObjectKeyOwned + Eq + core::hash::Hash,
        V: JsonDeserialize,
    {
        fn json_deserialize(parser: &mut Parser<'_>) -> Result<Self, Error> {
            let mut visitor = MapVisitor::new(parser)?;
            let entries = visitor.total_entries();
            crate::core::reserve_decode_hash_table_allocation::<(K, V)>(entries)
                .map_err(Error::from_decode_resource)?;
            let mut map = std::collections::HashMap::new();
            map.try_reserve(entries)
                .map_err(|_| Error::AllocationFailed)?;
            while let Some(key) = visitor.next_key()? {
                let key_ref = match &key {
                    KeyRef::Borrowed(s) => *s,
                    KeyRef::Owned(s) => s.as_str(),
                };
                let parsed_key = K::from_json_key_text(key_ref)?;
                let value = visitor.parse_value::<V>()?;
                if map.insert(parsed_key, value).is_some() {
                    return Err(MapVisitor::duplicate_field(key_ref));
                }
            }
            visitor.finish()?;
            Ok(map)
        }
        fn json_from_value(value: &Value) -> Result<Self, Error> {
            if let Value::Object(obj) = value {
                crate::core::reserve_decode_hash_table_allocation::<(K, V)>(obj.len())
                    .map_err(Error::from_decode_resource)?;
                let mut map = std::collections::HashMap::new();
                map.try_reserve(obj.len())
                    .map_err(|_| Error::AllocationFailed)?;
                for (k, v) in obj.iter() {
                    let parsed_key = K::from_json_key_text(k)?;
                    if map.insert(parsed_key, V::json_from_value(v)?).is_some() {
                        return Err(Error::duplicate_field(k));
                    }
                }
                Ok(map)
            } else {
                json_from_value_via_string(value)
            }
        }
    }
    impl<K, V> JsonDeserialize for std::collections::BTreeMap<K, V>
    where
        K: JsonObjectKeyOwned + Ord,
        V: JsonDeserialize,
    {
        fn json_deserialize(parser: &mut Parser<'_>) -> Result<Self, Error> {
            let mut visitor = MapVisitor::new(parser)?;
            let entries = visitor.total_entries();
            crate::core::reserve_decode_btree_allocation::<K, V>(entries)
                .map_err(Error::from_decode_resource)?;
            let mut map = std::collections::BTreeMap::new();
            while let Some(key) = visitor.next_key()? {
                let key_ref = match &key {
                    KeyRef::Borrowed(s) => *s,
                    KeyRef::Owned(s) => s.as_str(),
                };
                let parsed_key = K::from_json_key_text(key_ref)?;
                let value = visitor.parse_value::<V>()?;
                if map.insert(parsed_key, value).is_some() {
                    return Err(MapVisitor::duplicate_field(key_ref));
                }
            }
            visitor.finish()?;
            Ok(map)
        }
        fn json_from_value(value: &Value) -> Result<Self, Error> {
            if let Value::Object(obj) = value {
                crate::core::reserve_decode_btree_allocation::<K, V>(obj.len())
                    .map_err(Error::from_decode_resource)?;
                let mut map = std::collections::BTreeMap::new();
                for (k, v) in obj.iter() {
                    let parsed_key = K::from_json_key_text(k)?;
                    if map.insert(parsed_key, V::json_from_value(v)?).is_some() {
                        return Err(Error::duplicate_field(k));
                    }
                }
                Ok(map)
            } else {
                json_from_value_via_string(value)
            }
        }
    }
    impl<T> JsonDeserialize for std::collections::HashSet<T>
    where
        T: JsonDeserialize + Eq + core::hash::Hash,
    {
        fn json_deserialize(parser: &mut Parser<'_>) -> Result<Self, Error> {
            let entries = parser.preflight_array_entries()?;
            crate::core::reserve_decode_hash_table_allocation::<T>(entries)
                .map_err(Error::from_decode_resource)?;
            parser.skip_ws();
            parser.expect(b'[')?;
            let mut set = std::collections::HashSet::new();
            set.try_reserve(entries)
                .map_err(|_| Error::AllocationFailed)?;
            parser.skip_ws();
            if parser.try_consume_char(b']')? {
                return Ok(set);
            }
            loop {
                let value = T::json_deserialize(parser)?;
                if !set.insert(value) {
                    return Err(Error::Message("duplicate element in set".into()));
                }
                parser.skip_ws();
                if parser.try_consume_char(b',')? {
                    continue;
                }
                parser.expect(b']')?;
                break;
            }
            Ok(set)
        }
        fn json_from_value(value: &Value) -> Result<Self, Error> {
            if let Value::Array(items) = value {
                crate::core::reserve_decode_hash_table_allocation::<T>(items.len())
                    .map_err(Error::from_decode_resource)?;
                let mut set = std::collections::HashSet::new();
                set.try_reserve(items.len())
                    .map_err(|_| Error::AllocationFailed)?;
                for item in items {
                    let v = T::json_from_value(item)?;
                    if !set.insert(v) {
                        return Err(Error::Message("duplicate element in set".into()));
                    }
                }
                Ok(set)
            } else {
                json_from_value_via_string(value)
            }
        }
    }
    impl<T> FastJsonWrite for std::collections::HashSet<T>
    where
        T: JsonSerialize + Eq + core::hash::Hash + Ord,
    {
        fn write_json(&self, out: &mut String) {
            let mut values: Vec<&T> = self.iter().collect();
            values.sort();
            out.push('[');
            let mut iter = values.into_iter();
            if let Some(first) = iter.next() {
                first.json_serialize(out);
                for value in iter {
                    out.push(',');
                    value.json_serialize(out);
                }
            }
            out.push(']');
        }
        fn write_json_to(&self, out: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
            out.begin_container()?;
            let result = (|| {
                out.push('[')?;
                let mut previous: Option<&T> = None;
                for index in 0..self.len() {
                    let mut next: Option<&T> = None;
                    for candidate in self {
                        if previous.is_some_and(|value| candidate <= value) {
                            continue;
                        }
                        if next.is_none_or(|value| candidate < value) {
                            next = Some(candidate);
                        }
                    }
                    let Some(value) = next else {
                        return Err(BoundedJsonError::LengthMismatch);
                    };
                    if index != 0 {
                        out.push(',')?;
                    }
                    value.json_serialize_to(out)?;
                    previous = Some(value);
                }
                out.push(']')?;
                Ok(())
            })();
            out.end_container();
            result
        }
    }
    impl FastJsonWrite for Url {
        fn write_json(&self, out: &mut String) {
            write_json_string(self.as_str(), out);
        }
        fn write_json_to(&self, out: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
            write_json_string_to(self.as_str(), out)
        }
    }
    impl JsonObjectKey for Url {
        fn visit_json_key_text<E>(
            &self,
            mut visitor: impl FnMut(&str) -> Result<(), E>,
        ) -> Result<(), E> {
            visitor(self.as_str())
        }
    }
    /// Original borrowed key text or the caller's exact decoded key destination.
    ///
    /// Ordinary parsing retains a String. Seeded parsing may retain move-only
    /// admitted backing instead; this is lexical storage, not authenticated authority.
    pub enum KeyRef<'a, B = String> {
        /// Unescaped UTF-8 key text borrowed directly from the original input.
        Borrowed(&'a str),
        /// Escaped key text decoded into the caller's original destination.
        Owned(B),
    }
    impl<'a> KeyRef<'a> {
        #[inline]
        pub fn as_str(&self) -> &str {
            match self {
                KeyRef::Borrowed(s) => s,
                KeyRef::Owned(s) => s.as_str(),
            }
        }
        // Note: prefer `as_str()` or the `AsRef<str>` impl over an inherent
        // `as_ref` method to avoid clippy's confusion with the trait method.
    }
    impl<'a> AsRef<str> for KeyRef<'a> {
        #[inline]
        fn as_ref(&self) -> &str {
            self.as_str()
        }
    }
    /// Wrapper around a parsed JSON object key that offers typed conversions.
    pub struct CoerceKey<'a> {
        inner: KeyRef<'a>,
    }
    impl<'a> From<KeyRef<'a>> for CoerceKey<'a> {
        fn from(inner: KeyRef<'a>) -> Self {
            Self { inner }
        }
    }
    impl<'a> CoerceKey<'a> {
        #[inline]
        pub fn as_str(&self) -> &str {
            self.inner.as_str()
        }
        #[inline]
        pub fn into_owned(self) -> String {
            match self.inner {
                KeyRef::Borrowed(s) => s.to_owned(),
                KeyRef::Owned(s) => s,
            }
        }
        pub fn parse<T>(&self) -> Result<T, Error>
        where
            T: core::str::FromStr,
            T::Err: core::fmt::Display,
        {
            let key = self.inner.as_str();
            key.parse::<T>()
                .map_err(|e| Error::Message(format!("failed to parse map key `{key}`: {e}")))
        }
    }
    mod raw_value;
    pub use raw_value::RawValue;
    mod preflight;
    pub use preflight::{
        JsonPreflightError, JsonPreflightLimits, JsonPreflightProfile, JsonPreflightResource,
        JsonPreflightSyntax, preflight_slice,
    };
    mod visitors;
    pub use visitors::{MapVisitor, SeqVisitor};
    pub trait Visitor<'a> {
        type Value;
        fn visit_null(self) -> Result<Self::Value, Error>;
        fn visit_bool(self, v: bool) -> Result<Self::Value, Error>;
        fn visit_i64(self, v: i64) -> Result<Self::Value, Error>;
        fn visit_u64(self, v: u64) -> Result<Self::Value, Error>;
        fn visit_u128(self, v: u128) -> Result<Self::Value, Error>
        where
            Self: Sized,
        {
            let value = u64::try_from(v)
                .map_err(|_| Error::Message("visitor does not accept u128 values".to_owned()))?;
            self.visit_u64(value)
        }
        fn visit_f64(self, v: f64) -> Result<Self::Value, Error>;
        fn visit_string(self, v: String) -> Result<Self::Value, Error>;
        fn visit_map(self, visitor: MapVisitor<'a, '_>) -> Result<Self::Value, Error>;
        fn visit_seq(self, visitor: SeqVisitor<'a, '_>) -> Result<Self::Value, Error>;
    }
    pub fn visit_value<'a, V>(parser: &mut Parser<'a>, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'a>,
    {
        parser.skip_ws();
        match parser.peek() {
            Some(b'n') => {
                parser.parse_null()?;
                visitor.visit_null()
            }
            Some(b't') | Some(b'f') => {
                let v = parser.parse_bool()?;
                visitor.visit_bool(v)
            }
            Some(b'"') => {
                let s = parser.parse_string()?;
                visitor.visit_string(s)
            }
            Some(b'{') => {
                let map = MapVisitor::new(parser)?;
                visitor.visit_map(map)
            }
            Some(b'[') => {
                let seq = SeqVisitor::new(parser)?;
                visitor.visit_seq(seq)
            }
            Some(b'-') | Some(b'0'..=b'9') => {
                let number = parse_number_token(parser)?;
                match number {
                    Number::I64(v) => visitor.visit_i64(v),
                    Number::U64(v) => visitor.visit_u64(v),
                    Number::U128(v) => visitor.visit_u128(v),
                    Number::F64(v) => visitor.visit_f64(v),
                }
            }
            Some(other) => {
                let (byte, line, col) =
                    crate::json::pos_from_offset(parser.input(), parser.position());
                Err(Error::UnexpectedCharacter {
                    found: UnexpectedToken::Char(other as char),
                    byte,
                    line,
                    col,
                })
            }
            None => {
                let (byte, line, col) =
                    crate::json::pos_from_offset(parser.input(), parser.position());
                Err(Error::UnexpectedEof { byte, line, col })
            }
        }
    }
    fn parse_number_token(parser: &mut Parser<'_>) -> Result<Number, Error> {
        parser.skip_ws();
        let s = parser.input();
        let bytes = s.as_bytes();
        let mut idx = parser.position();
        let len = bytes.len();
        if idx >= len {
            let (byte, line, col) = crate::json::pos_from_offset(s, idx);
            return Err(Error::UnexpectedEof { byte, line, col });
        }
        let start = idx;
        let mut neg = false;
        if bytes[idx] == b'-' {
            neg = true;
            idx += 1;
        }
        let mut saw_digit = false;
        let int_start = idx;
        while idx < len && bytes[idx].is_ascii_digit() {
            saw_digit = true;
            idx += 1;
        }
        if !saw_digit {
            let (byte, line, col) = crate::json::pos_from_offset(s, idx.min(len));
            return Err(Error::ExpectedDigits { byte, line, col });
        }
        let int_end = idx;
        if bytes[int_start] == b'0' && int_end > int_start + 1 {
            let (byte, line, col) = crate::json::pos_from_offset(s, int_start + 1);
            return Err(Error::WithPos {
                msg: Parser::LEADING_ZERO_MSG,
                byte,
                line,
                col,
            });
        }
        let mut is_float = false;
        if idx < len && bytes[idx] == b'.' {
            is_float = true;
            idx += 1;
            let mut frac_digits = false;
            while idx < len && bytes[idx].is_ascii_digit() {
                frac_digits = true;
                idx += 1;
            }
            if !frac_digits {
                let (byte, line, col) = crate::json::pos_from_offset(s, idx.min(len));
                return Err(Error::ExpectedFracDigits { byte, line, col });
            }
        }
        if idx < len && (bytes[idx] == b'e' || bytes[idx] == b'E') {
            is_float = true;
            idx += 1;
            if idx < len && (bytes[idx] == b'+' || bytes[idx] == b'-') {
                idx += 1;
            }
            let mut exp_digits = false;
            while idx < len && bytes[idx].is_ascii_digit() {
                exp_digits = true;
                idx += 1;
            }
            if !exp_digits {
                let (byte, line, col) = crate::json::pos_from_offset(s, idx.min(len));
                return Err(Error::ExpectedExpDigits { byte, line, col });
            }
        }
        let slice = &s[start..idx];
        parser.i = idx;
        if is_float {
            let v: f64 = slice
                .parse()
                .map_err(|_| Error::Message("float parse".to_owned()))?;
            let n = Number::from_f64(v)
                .ok_or_else(|| Error::Message("json float out of range".to_owned()))?;
            return Ok(n);
        }
        if neg && &s[int_start..idx] == "0" {
            let n = Number::from_f64(-0.0)
                .ok_or_else(|| Error::Message("json float out of range".to_owned()))?;
            return Ok(n);
        }
        let digits = &s[int_start..idx];
        if !neg {
            if let Ok(u) = digits.parse::<u64>() {
                return Ok(Number::from(u));
            }
            if let Ok(u) = digits.parse::<u128>() {
                return Ok(Number::from(u));
            }
        } else if let Ok(u) = digits.parse::<u64>() {
            if u == (i64::MAX as u64) + 1 {
                return Ok(Number::from(i64::MIN));
            }
            if u <= i64::MAX as u64 {
                return Ok(Number::from(-(u as i64)));
            }
        }
        Err(Error::Message("json integer out of range".to_owned()))
    }
}
/// Serialize an object into the given writer.
pub fn serialize_into<W: Write, T: NoritoSerialize>(
    mut writer: W,
    value: &T,
    compression: Compression,
) -> Result<(), Error> {
    match compression {
        Compression::None => core::write_frame_to_writer(value, &mut writer)?,
        Compression::Zstd => {
            let bytes = to_compressed_bytes(value, Some(CompressionConfig::default()))?;
            writer.write_all(&bytes)?;
        }
    }
    Ok(())
}
/// Deserialize an object from the provided reader.
pub fn deserialize_from<R: Read, T>(reader: R) -> Result<T, Error>
where
    T: NoritoSerialize,
    for<'de> T: NoritoDeserialize<'de>,
{
    deserialize_stream(reader)
}
/// Deserialize an object from a stream, validating header and checksum without
/// buffering the entire input.
pub fn deserialize_stream<R: Read, T>(mut reader: R) -> Result<T, Error>
where
    T: NoritoSerialize,
    for<'de> T: NoritoDeserialize<'de>,
{
    use core::Header;
    let header = Header::read(&mut reader)?;
    core::prepare_header_decode(header.flags, false)?;
    if header.schema != norito::schema::identity::frame_hash::<T>() {
        return Err(Error::SchemaMismatch);
    }
    let payload_len = core::payload_len_to_usize(header.length)?;
    // Set decode flags for this stream
    let _guard = core::DecodeFlagsGuard::enter(header.flags);
    core::reserve_decode_allocation(payload_len)?;
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(payload_len)
        .map_err(|_| Error::AllocationFailed {
            bytes: u64::try_from(payload_len).unwrap_or(u64::MAX),
        })?;
    match header.compression {
        Compression::None => {
            let mut buf = [0u8; 64 * 1024];
            let padding = core::payload_alignment_padding_for::<T>();
            if padding != 0 {
                core::stream::skip_padding(&mut reader, padding)?;
            }
            let mut remaining = payload_len;
            while remaining > 0 {
                let chunk = remaining.min(buf.len());
                let read = reader.read(&mut buf[..chunk])?;
                if read == 0 {
                    return Err(Error::LengthMismatch);
                }
                payload.extend_from_slice(&buf[..read]);
                remaining -= read;
            }
            if reader.read(&mut [0u8; 1])? != 0 {
                return Err(Error::LengthMismatch);
            }
        }
        Compression::Zstd => {
            #[cfg(feature = "compression")]
            {
                let mut decoder = zstd::Decoder::new(reader)?.single_frame();
                let mut buf = [0u8; 64 * 1024];
                let mut remaining = payload_len;
                while remaining > 0 {
                    let chunk = remaining.min(buf.len());
                    let read = decoder.read(&mut buf[..chunk])?;
                    if read == 0 {
                        return Err(Error::LengthMismatch);
                    }
                    payload.extend_from_slice(&buf[..read]);
                    remaining -= read;
                }
                if decoder.read(&mut [0u8; 1])? != 0 {
                    return Err(Error::LengthMismatch);
                }
                let mut compressed = decoder.finish();
                if compressed.read(&mut [0u8; 1])? != 0 {
                    return Err(Error::LengthMismatch);
                }
            }
            #[cfg(not(feature = "compression"))]
            {
                let _ = reader;
                return Err(std::io::Error::other("compression support disabled").into());
            }
        }
    }
    let crc = core::hardware_crc64(&payload);
    if crc != header.checksum {
        return Err(Error::ChecksumMismatch);
    }
    decode_payload_exact(&payload)
}
fn decode_from_uncompressed_bytes<T>(bytes: &[u8], header: core::Header) -> Result<T, Error>
where
    T: NoritoSerialize,
    for<'de> T: NoritoDeserialize<'de>,
{
    let payload = checked_uncompressed_payload::<T>(bytes, &header)?;
    let _flags = core::DecodeFlagsGuard::enter(header.flags);
    decode_payload_exact(payload)
}
fn checked_uncompressed_payload<'a, T: NoritoSerialize>(
    bytes: &'a [u8],
    header: &core::Header,
) -> Result<&'a [u8], Error> {
    core::prepare_header_decode(header.flags, false)?;
    if header.compression != Compression::None {
        return Err(Error::unsupported_compression_with(
            header.compression as u8,
            &[Compression::None],
        ));
    }
    if header.schema != norito::schema::identity::frame_hash::<T>() {
        return Err(Error::SchemaMismatch);
    }
    let payload_len = core::payload_len_to_usize(header.length)?;
    let padding = core::payload_alignment_padding_for::<T>();
    let slice = bytes
        .get(core::Header::SIZE..)
        .ok_or(Error::LengthMismatch)?;
    let payload = core::payload_without_leading_padding_exact(slice, payload_len, padding)?;
    if core::hardware_crc64(payload) != header.checksum {
        return Err(Error::ChecksumMismatch);
    }
    Ok(payload)
}

/// Decode one complete bare payload under the already-selected layout flags.
///
/// Instrumented decoders report complete consumption without another encode.
/// Custom decoders that do not report complete byte access fall back to an
/// allocation-free canonical byte comparison inside `decode_field_canonical`.
fn decode_payload_exact<T>(payload: &[u8]) -> Result<T, Error>
where
    T: SerializePayload,
    for<'de> T: DeserializePayload<'de>,
{
    let (value, used) = core::decode_field_canonical::<T>(payload)?;
    if used != payload.len() {
        return Err(Error::LengthMismatch);
    }
    Ok(value)
}
/// Prelude with commonly used items.
pub mod prelude {
    pub use super::{
        Compression, DeserializePayload, Error, NoritoDeserialize, NoritoSerialize,
        derive::{Decode, Encode},
        deserialize_from, serialize_into,
    };
}
/// Encode a value with the canonical V1 layout and no compression.
///
/// The result is independent of ambient layout guards.
pub fn encode_canonical<T>(value: &T) -> Result<Vec<u8>, Error>
where
    T: NoritoSerialize,
{
    let _canonical_flags = core::DecodeFlagsGuard::enter(core::default_encode_flags());
    core::to_bytes(value)
}
/// Count the exact uncompressed V1 frame produced by [`encode_canonical`].
///
/// A real serialization pass counts bytes without allocating an output frame or trusting
/// serializer length hints. Ambient layout guards are restored before returning.
///
/// # Errors
///
/// Returns the serialization error or [`Error::LengthMismatch`] on length overflow.
pub fn canonical_frame_len<T: NoritoSerialize>(value: &T) -> Result<usize, Error> {
    let _canonical_flags = core::DecodeFlagsGuard::enter(core::default_encode_flags());
    core::encoded_frame_len(value)
}
const CANONICAL_DECODE_ALLOCATION_EXTRA_MULTIPLIER: usize = 63;
const CANONICAL_DECODE_MAX_EXTRA_ALLOCATION_BYTES: usize = 256 * 1024 * 1024;
const CANONICAL_DECODE_FIXED_ALLOCATION_BYTES: usize = 64 * 1024;
/// Return conservative decode limits derived from one complete encoded value.
///
/// Packed boolean sequences may carry eight logical elements per encoded byte, so sequence and
/// cumulative element budgets use an eightfold allowance. Allocation includes the encoded length,
/// up to 63 further encoded lengths for heterogeneous owned object graphs and nested canonical
/// values, and a fixed 64 KiB floor for small structural values. The amplified extra is capped at
/// 256 MiB, so small reviewed frames retain the `64 * length + 64 KiB` envelope while large
/// configured archives cannot multiply their complete size by 64. Independent field, element, and
/// nesting limits remain in force.
///
/// Saturating arithmetic prevents integer wrap; safety also relies on the
/// archive maximum and protocol frame-size limits rejecting excessive encoded
/// inputs before this decoder policy is applied.
#[must_use]
pub const fn canonical_decode_limits(payload_len: usize) -> DecodeLimits {
    let amplified_extra = payload_len.saturating_mul(CANONICAL_DECODE_ALLOCATION_EXTRA_MULTIPLIER);
    let amplified_extra = if amplified_extra < CANONICAL_DECODE_MAX_EXTRA_ALLOCATION_BYTES {
        amplified_extra
    } else {
        CANONICAL_DECODE_MAX_EXTRA_ALLOCATION_BYTES
    };
    let allocation_limit = payload_len
        .saturating_add(amplified_extra)
        .saturating_add(CANONICAL_DECODE_FIXED_ALLOCATION_BYTES);
    DecodeLimits::new(
        payload_len.saturating_mul(8),
        payload_len,
        payload_len.saturating_mul(8),
        allocation_limit,
        core::MAX_VALUE_NESTING_DEPTH,
    )
}

include!("framed_decode.rs");
fn decode_from_bytes_inner<T>(bytes: &[u8]) -> Result<T, Error>
where
    T: NoritoSerialize,
    for<'de> T: NoritoDeserialize<'de>,
{
    use std::io::Cursor;
    let mut cursor = Cursor::new(bytes);
    let header = core::Header::read(&mut cursor)?;
    if header.compression == Compression::None {
        return decode_from_uncompressed_bytes::<T>(bytes, header);
    }
    let mut cursor = Cursor::new(bytes);
    let value = deserialize_stream(&mut cursor)?;
    if cursor.position() != bytes.len() as u64 {
        return Err(Error::LengthMismatch);
    }
    Ok(value)
}
/// Decode a Norito archive with explicit per-value and cumulative resource limits.
///
/// This enters the private decoder directly rather than recursively invoking [`decode_from_bytes`],
/// so a caller can provide a larger, still-finite budget for trusted high-compression data. Nested
/// bounded decodes continue to inherit the stricter of the inner and outer limits.
///
/// # Errors
/// Returns an archive-validation, deserialization, or resource-budget error.
pub fn decode_from_bytes_with_limits<T>(bytes: &[u8], limits: DecodeLimits) -> Result<T, Error>
where
    T: NoritoSerialize,
    for<'de> T: NoritoDeserialize<'de>,
{
    with_decode_limits(limits, || decode_from_bytes_inner(bytes))
}
/// Decode one exact canonical V1 frame under payload-derived resource limits.
///
/// In addition to ordinary validation, this rejects compression, alternate layout flags, and any
/// byte representation that does not exactly match [`encode_canonical`].
pub fn decode_canonical<T>(bytes: &[u8]) -> Result<T, Error>
where
    T: NoritoSerialize,
    for<'de> T: NoritoDeserialize<'de>,
{
    decode_canonical_with_limits(bytes, canonical_decode_limits(bytes.len()))
}
/// Verify that `value` encodes to exactly `expected` under the active layout.
///
/// The comparison streams the complete header, alignment padding, and payload directly over
/// `expected`; it does not allocate a second frame-sized buffer. This preserves the ambient layout
/// behavior of [`core::to_bytes`]. Callers that require the fixed canonical V1 layout should use
/// [`verify_exact_canonical_frame`] instead.
///
/// # Errors
///
/// Returns [`Error::NonCanonicalEncoding`] when bytes differ, the stream overruns `expected`, or a suffix remains.
/// Serializer and framing errors are returned unchanged when no mismatch was observed.
#[doc(hidden)]
pub fn verify_exact_frame<T>(value: &T, expected: &[u8]) -> Result<(), Error>
where
    T: NoritoSerialize,
{
    let mut exact = core::ExactSliceWriter::new(expected);
    let encode_result = core::write_frame_to_writer(value, &mut exact);
    if exact.mismatched() {
        return Err(Error::NonCanonicalEncoding);
    }
    encode_result?;
    if !exact.is_complete() {
        return Err(Error::NonCanonicalEncoding);
    }
    Ok(())
}
/// Verify that `value` encodes to the supplied exact canonical V1 frame.
///
/// This streams the canonical header, padding and payload over `expected` without allocating a
/// second frame and ignores ambient layout flags. It is useful when a caller already owns exact
/// canonical bytes and must bind a borrowed value to those bytes before a side effect.
///
/// # Errors
/// Returns [`Error::NonCanonicalEncoding`] on byte drift, overrun or a trailing suffix; returns
/// the underlying serializer error when no mismatch was observed.
pub fn verify_exact_canonical_frame<T>(value: &T, expected: &[u8]) -> Result<(), Error>
where
    T: NoritoSerialize,
{
    let mut exact = core::ExactSliceWriter::new(expected);
    let encode_result = core::write_canonical_to_writer(value, &mut exact);
    if exact.mismatched() {
        return Err(Error::NonCanonicalEncoding);
    }
    encode_result?;
    if !exact.is_complete() {
        return Err(Error::NonCanonicalEncoding);
    }
    Ok(())
}

/// Decode one exact canonical V1 frame while retaining the original admission refusal.
///
/// The complete synchronous decode and canonical byte comparison use the same implementation as
/// [`decode_canonical_with_limits`]. Default and schema ceilings remain protocol errors. An actual
/// refusal from an enclosing decode budget is identified by its original scope, including cumulative
/// limits; matching numeric ceilings alone cannot establish that origin. This does not alter the
/// wire encoding or provide an allocation-pool release owner.
///
/// # Errors
/// Returns the original decoder error with an opaque classification established before its scopes
/// unwind. Reconstructed resource errors without current-attempt provenance are invalid input.
pub fn decode_canonical_for_admission<T>(
    bytes: &[u8],
    limits: DecodeLimits,
) -> Result<T, core::DecodeAttemptError>
where
    T: NoritoSerialize,
    for<'de> T: NoritoDeserialize<'de>,
{
    core::classify_decode_attempt(|| decode_canonical_with_limits(bytes, limits))
}

fn checked_canonical_header(bytes: &[u8]) -> Result<core::Header, Error> {
    let header = core::Header::read(std::io::Cursor::new(bytes))?;
    if header.compression != Compression::None || core::validate_header_flags(header.flags).is_err()
    {
        return Err(Error::NonCanonicalEncoding);
    }
    Ok(header)
}

/// Decode one exact canonical V1 frame under default and schema-specific limits.
///
/// Nested Norito limit scopes compose by taking the stricter value in every dimension, so the
/// payload-derived default remains active when `limits` is looser.
pub fn decode_canonical_with_limits<T>(bytes: &[u8], limits: DecodeLimits) -> Result<T, Error>
where
    T: NoritoSerialize,
    for<'de> T: NoritoDeserialize<'de>,
{
    checked_canonical_header(bytes)?;
    let defaults = canonical_decode_limits(bytes.len());
    with_decode_limits(defaults, || {
        let _canonical_flags = core::DecodeFlagsGuard::enter(core::default_encode_flags());
        let _payload_context = core::PayloadCtxGuard::enter(bytes);
        let value = match decode_from_bytes_with_limits(bytes, limits) {
            Ok(value) => value,
            Err(Error::DecodeFlagsMismatch { .. }) => {
                return Err(Error::NonCanonicalEncoding);
            }
            Err(Error::UnsupportedCompression { found, .. })
                if found == Compression::Zstd as u8 =>
            {
                return Err(Error::NonCanonicalEncoding);
            }
            Err(error) => return Err(error),
        };
        let mut exact = core::ExactSliceWriter::new(bytes);
        let canonical_result = core::write_canonical_to_writer(&value, &mut exact);
        if exact.mismatched() {
            return Err(Error::NonCanonicalEncoding);
        }
        canonical_result?;
        if !exact.is_complete() {
            return Err(Error::NonCanonicalEncoding);
        }
        Ok(value)
    })
}
include!("canonical_codec_tests.rs");
/// Convenience helper identical to `decode_from_bytes`.
/// Accepts either compressed or uncompressed Norito payloads and returns `T`.
pub fn decode_from_compressed_bytes<T>(bytes: &[u8]) -> Result<T, Error>
where
    T: NoritoSerialize,
    for<'de> T: NoritoDeserialize<'de>,
{
    decode_from_bytes(bytes)
}
/// Decode from any `Read` implementor, validating header and checksum.
/// This is a thin wrapper over `deserialize_stream` for convenience.
pub fn decode_from_reader<R: Read, T>(reader: R) -> Result<T, Error>
where
    T: NoritoSerialize,
    for<'de> T: NoritoDeserialize<'de>,
{
    deserialize_stream(reader)
}
/// Decode from a reader with explicit per-value and cumulative resource limits.
///
/// # Errors
///
/// Returns an I/O, archive-validation, deserialization, or resource-budget error.
pub fn decode_from_reader_with_limits<R: Read, T>(
    reader: R,
    limits: DecodeLimits,
) -> Result<T, Error>
where
    T: NoritoSerialize,
    for<'de> T: NoritoDeserialize<'de>,
{
    with_decode_limits(limits, || deserialize_stream(reader))
}
/// Streaming fold over a top-level `Vec<T>` payload without materializing the full payload.
///
/// Validates header and CRC64 incrementally and feeds each element `T` to the folder `f`,
/// returning the final accumulator. Works for both compressed and uncompressed payloads.
#[inline]
pub(crate) fn guarded_try_deserialize<T, F>(f: F) -> Result<T, Error>
where
    F: FnOnce() -> Result<T, Error>,
{
    catch_decode_panic(std::any::type_name::<T>(), f)
}
/// Run a type-erased field decoder with the same panic policy as [`guarded_try_deserialize`].
///
/// Keeping this executor non-generic lets field decoding share the panic and
/// error machinery while retaining the concrete type name in diagnostics.
#[inline(never)]
pub(crate) fn guarded_try_deserialize_erased(
    type_name: &'static str,
    decode: &mut dyn FnMut() -> Result<(), Error>,
) -> Result<(), Error> {
    catch_decode_panic(type_name, decode)
}
thread_local! {
    static DECODE_PANIC_DEPTH: Cell<u32> = const { Cell::new(0) };
}
struct DecodePanicGuard;
impl DecodePanicGuard {
    fn enter() -> Self {
        DECODE_PANIC_DEPTH.with(|depth| depth.set(depth.get().saturating_add(1)));
        Self
    }
}
impl Drop for DecodePanicGuard {
    fn drop(&mut self) {
        DECODE_PANIC_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}
fn catch_decode_panic<T>(
    type_name: &'static str,
    decode: impl FnOnce() -> Result<T, Error>,
) -> Result<T, Error> {
    install_decode_panic_hook();
    let _guard = DecodePanicGuard::enter();
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(decode)) {
        Ok(result) => result,
        Err(payload) => {
            if crate::debug_trace_enabled() {
                let message = payload
                    .downcast_ref::<&str>()
                    .copied()
                    .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                    .unwrap_or("<non-string panic>");
                eprintln!("norito.decode suppressed panic while decoding {type_name}: {message}");
            }
            Err(Error::decode_panic(type_name))
        }
    }
}
/// Returns true when a Norito decode is running under panic suppression.
#[must_use]
pub fn decode_panic_suppressed() -> bool {
    DECODE_PANIC_DEPTH.with(|depth| depth.get() > 0)
}
#[cfg(test)]
thread_local! {
    static SUPPRESSED_DECODE_PANICS: Cell<usize> = const { Cell::new(0) };
}
fn install_decode_panic_hook() {
    static HOOK: OnceLock<()> = OnceLock::new();
    HOOK.get_or_init(|| {
        let default = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let suppressed = DECODE_PANIC_DEPTH.with(|depth| depth.get() > 0);
            if suppressed {
                #[cfg(test)]
                SUPPRESSED_DECODE_PANICS.with(|counter| {
                    counter.set(counter.get().saturating_add(1));
                });
                return;
            }
            default(info);
        }));
    });
}
#[cfg(test)]
mod guarded_tests {
    use super::{
        Error, SUPPRESSED_DECODE_PANICS, decode_panic_suppressed, guarded_try_deserialize,
    };
    #[test]
    fn guarded_try_deserialize_catches_panics() {
        SUPPRESSED_DECODE_PANICS.with(|counter| counter.set(0));
        let result = guarded_try_deserialize::<(), _>(|| -> Result<(), Error> {
            panic!("trigger panic");
        });
        assert!(matches!(result, Err(Error::DecodePanic { .. })));
        assert_eq!(
            SUPPRESSED_DECODE_PANICS.with(|counter| counter.get()),
            1,
            "panic hook suppression counter should increment"
        );
    }
    #[test]
    fn decode_panic_suppressed_tracks_scope() {
        assert!(!decode_panic_suppressed());
        let result = guarded_try_deserialize::<(), _>(|| -> Result<(), Error> {
            assert!(decode_panic_suppressed());
            Ok(())
        });
        assert!(result.is_ok());
        assert!(!decode_panic_suppressed());
    }
}
#[allow(dead_code)]
fn stream_seq_fold_core<R, T, Acc, Init, F>(
    reader: R,
    init: Init,
    f: F,
    expected_schema: [u8; 16],
    padding: usize,
) -> Result<Acc, Error>
where
    R: Read,
    T: for<'de> NoritoDeserialize<'de> + core::NoritoSerialize,
    Init: FnOnce(usize) -> Result<Acc, Error>,
    F: FnMut(Acc, T) -> Acc,
{
    core::stream::fold_sequence_from_reader(reader, init, f, expected_schema, padding)
}
/// Streaming fold over a top-level `Vec<T>` payload without materializing the full payload.
pub fn stream_vec_fold_from_reader<R, T, Acc, F>(reader: R, acc: Acc, f: F) -> Result<Acc, Error>
where
    R: Read,
    T: for<'de> NoritoDeserialize<'de> + core::NoritoSerialize,
    F: FnMut(Acc, T) -> Acc,
{
    type Top<U> = Vec<U>;
    stream_seq_fold_core(
        reader,
        move |_| Ok(acc),
        f,
        norito::schema::identity::frame_hash::<Top<T>>(),
        core::payload_alignment_padding_for::<Top<T>>(),
    )
}
/// Inspect the element count of a top-level `Vec<T>` under an exact semantic cap.
///
/// This uses the same header, compression, layout-flag, and sequence-length decoder as
/// [`stream_vec_collect_from_reader`]. It stops after the sequence plan, so it is suitable only for
/// resource-admission preflight: callers must still perform a complete decode to validate element
/// bytes, the payload checksum, and trailing data.
///
/// # Errors
///
/// Returns a header, schema, layout, length, decompression, or resource-limit error. A count above
/// `max_elements` is rejected before element prefixes are read or output storage is allocated.
pub fn inspect_stream_vec_len_bounded_from_reader<R, T>(
    reader: R,
    max_elements: usize,
) -> Result<usize, Error>
where
    R: Read,
    T: for<'de> NoritoDeserialize<'de> + core::NoritoSerialize,
{
    type Top<U> = Vec<U>;
    core::stream::inspect_sequence_len_from_reader(
        reader,
        norito::schema::identity::frame_hash::<Top<T>>(),
        core::payload_alignment_padding_for::<Top<T>>(),
        max_elements,
    )
}
/// Collect a top-level `Vec<T>` by streaming, without buffering the entire payload.
pub fn stream_vec_collect_from_reader<R, T>(reader: R) -> Result<Vec<T>, Error>
where
    R: Read,
    T: for<'de> NoritoDeserialize<'de> + core::NoritoSerialize,
{
    stream_seq_fold_core(
        reader,
        |len| {
            let bytes = len
                .checked_mul(std::mem::size_of::<T>())
                .ok_or(Error::LengthMismatch)?;
            core::reserve_decode_allocation(bytes)?;
            let mut values = Vec::new();
            values
                .try_reserve(len)
                .map_err(|_| Error::AllocationFailed {
                    bytes: u64::try_from(bytes).unwrap_or(u64::MAX),
                })?;
            Ok(values)
        },
        |mut acc: Vec<T>, item| {
            acc.push(item);
            acc
        },
        crate::schema::identity::frame_hash::<Vec<T>>(),
        core::payload_alignment_padding_for::<Vec<T>>(),
    )
}
/// Collect a top-level `VecDeque<T>` by streaming.
pub fn stream_vecdeque_collect_from_reader<R, T>(
    reader: R,
) -> Result<std::collections::VecDeque<T>, Error>
where
    R: Read,
    T: for<'de> NoritoDeserialize<'de> + core::NoritoSerialize,
{
    use std::collections::VecDeque;
    stream_seq_fold_core(
        reader,
        |len| {
            let bytes = len
                .checked_mul(std::mem::size_of::<T>())
                .ok_or(Error::LengthMismatch)?;
            core::reserve_decode_allocation(bytes)?;
            let mut values = VecDeque::new();
            values
                .try_reserve(len)
                .map_err(|_| Error::AllocationFailed {
                    bytes: u64::try_from(bytes).unwrap_or(u64::MAX),
                })?;
            Ok(values)
        },
        |mut acc: VecDeque<T>, item| {
            acc.push_back(item);
            acc
        },
        crate::schema::identity::frame_hash::<VecDeque<T>>(),
        core::payload_alignment_padding_for::<VecDeque<T>>(),
    )
}
/// Collect a top-level `LinkedList<T>` by streaming.
pub fn stream_linkedlist_collect_from_reader<R, T>(
    reader: R,
) -> Result<std::collections::LinkedList<T>, Error>
where
    R: Read,
    T: for<'de> NoritoDeserialize<'de> + core::NoritoSerialize,
{
    use std::collections::LinkedList;
    stream_seq_fold_core(
        reader,
        |_| Ok(LinkedList::new()),
        |mut acc: LinkedList<T>, item| {
            acc.push_back(item);
            acc
        },
        crate::schema::identity::frame_hash::<LinkedList<T>>(),
        core::payload_alignment_padding_for::<LinkedList<T>>(),
    )
}
/// Collect a top-level `HashSet<T>` by streaming.
pub fn stream_hashset_collect_from_reader<R, T>(
    reader: R,
) -> Result<std::collections::HashSet<T>, Error>
where
    R: Read,
    T: for<'de> NoritoDeserialize<'de> + std::hash::Hash + Eq + Ord + core::NoritoSerialize,
{
    use std::collections::HashSet;
    stream_seq_fold_core(
        reader,
        |len| {
            let bytes = len
                .checked_mul(std::mem::size_of::<T>())
                .ok_or(Error::LengthMismatch)?;
            core::reserve_decode_allocation(bytes)?;
            let mut values = HashSet::new();
            values
                .try_reserve(len)
                .map_err(|_| Error::AllocationFailed {
                    bytes: u64::try_from(bytes).unwrap_or(u64::MAX),
                })?;
            Ok(values)
        },
        |mut acc: HashSet<T>, item| {
            acc.insert(item);
            acc
        },
        crate::schema::identity::frame_hash::<HashSet<T>>(),
        core::payload_alignment_padding_for::<HashSet<T>>(),
    )
}
/// Collect a top-level `BTreeSet<T>` by streaming.
pub fn stream_btreeset_collect_from_reader<R, T>(
    reader: R,
) -> Result<std::collections::BTreeSet<T>, Error>
where
    R: Read,
    T: for<'de> NoritoDeserialize<'de> + Ord + core::NoritoSerialize,
{
    use std::collections::BTreeSet;
    stream_seq_fold_core(
        reader,
        |_| Ok(BTreeSet::new()),
        |mut acc: BTreeSet<T>, item| {
            acc.insert(item);
            acc
        },
        crate::schema::identity::frame_hash::<BTreeSet<T>>(),
        core::payload_alignment_padding_for::<BTreeSet<T>>(),
    )
}
fn stream_map_collect_core<R, K, V, M, Init, Insert>(
    reader: R,
    expected_schema: [u8; 16],
    padding: usize,
    init: Init,
    mut insert: Insert,
) -> Result<M, Error>
where
    R: Read,
    K: for<'de> NoritoDeserialize<'de> + NoritoSerialize,
    V: for<'de> NoritoDeserialize<'de> + NoritoSerialize,
    Init: FnOnce(usize) -> Result<M, Error>,
    Insert: FnMut(&mut M, K, V) -> Result<(), Error>,
{
    use core::{Header, header_flags};
    let mut reader = reader;
    let header = Header::read(&mut reader)?;
    core::prepare_header_decode(header.flags, false)?;
    if header.schema != expected_schema {
        return Err(Error::SchemaMismatch);
    }
    let flags = header.flags;
    let payload_len = core::payload_len_to_usize(header.length)?;
    let padding = match header.compression {
        Compression::None => padding,
        Compression::Zstd => 0,
    };
    if padding != 0 {
        core::stream::skip_padding(&mut reader, padding)?;
    }
    let _fg = core::DecodeFlagsGuard::enter(flags);
    let boxed: Box<dyn Read> = match header.compression {
        Compression::None => Box::new(reader),
        Compression::Zstd => {
            #[cfg(feature = "compression")]
            {
                Box::new(zstd::Decoder::new(reader)?)
            }
            #[cfg(not(feature = "compression"))]
            {
                return Err(std::io::Error::other("compression support disabled").into());
            }
        }
    };
    let mut digesting = core::stream::DigestingReader::new(boxed);
    let mut remaining = payload_len;
    #[inline]
    fn read_exact_update<Rd: Read>(
        reader: &mut core::stream::DigestingReader<Rd>,
        remaining: &mut usize,
        buf: &mut [u8],
    ) -> Result<(), Error> {
        let new_remaining = remaining
            .checked_sub(buf.len())
            .ok_or(Error::LengthMismatch)?;
        reader.read_exact(buf)?;
        *remaining = new_remaining;
        Ok(())
    }
    #[inline]
    fn read_u64_update<Rd: Read>(
        reader: &mut core::stream::DigestingReader<Rd>,
        remaining: &mut usize,
    ) -> Result<u64, Error> {
        let mut b = [0u8; 8];
        read_exact_update(reader, remaining, &mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    #[inline]
    fn read_varint_update<Rd: Read>(
        reader: &mut core::stream::DigestingReader<Rd>,
        remaining: &mut usize,
    ) -> Result<u64, Error> {
        let mut result = 0u64;
        let mut shift = 0u32;
        let mut used = 0usize;
        let mut buf = [0u8; 1];
        for _ in 0..STREAM_MAX_VARINT_BYTES {
            read_exact_update(reader, remaining, &mut buf)?;
            used += 1;
            let byte = buf[0];
            let payload = (byte & 0x7f) as u64;
            if shift == 63 && payload > 1 {
                return Err(Error::LengthMismatch);
            }
            result |= payload << shift;
            if byte & 0x80 == 0 {
                if used != core::varint_encoded_len_u64(result) {
                    return Err(Error::LengthMismatch);
                }
                return Ok(result);
            }
            shift += 7;
            if shift >= 64 {
                break;
            }
        }
        Err(Error::LengthMismatch)
    }
    let entries = {
        let v = read_u64_update(&mut digesting, &mut remaining)?;
        core::enforce_decode_sequence_length(v)?;
        core::stream::u64_to_usize(v)?
    };
    let len_bytes = if (flags & header_flags::COMPACT_LEN) != 0 {
        1usize
    } else {
        8usize
    };
    let per_entry = len_bytes.checked_mul(2).ok_or(Error::LengthMismatch)?;
    let min_headers = entries
        .checked_mul(per_entry)
        .ok_or(Error::LengthMismatch)?;
    if min_headers > remaining {
        return Err(Error::LengthMismatch);
    }
    let mut map = init(entries)?;
    let mut key_buf = Vec::new();
    let mut val_buf = Vec::new();
    for _ in 0..entries {
        let key_len = if (flags & header_flags::COMPACT_LEN) != 0 {
            let v = read_varint_update(&mut digesting, &mut remaining)?;
            core::enforce_decode_field_length(v)?;
            core::stream::u64_to_usize(v)?
        } else {
            let v = read_u64_update(&mut digesting, &mut remaining)?;
            core::enforce_decode_field_length(v)?;
            core::stream::u64_to_usize(v)?
        };
        if key_len > remaining {
            return Err(Error::LengthMismatch);
        }
        try_resize_decode_buffer(&mut key_buf, key_len)?;
        read_exact_update(&mut digesting, &mut remaining, &mut key_buf)?;
        let _gk = core::PayloadCtxGuard::enter(&key_buf);
        let _key_depth = core::DecodeDepthGuard::enter()?;
        let ak = unsafe { &*(key_buf.as_ptr() as *const Archived<K>) };
        let key = guarded_try_deserialize(|| K::try_deserialize(ak))?;
        drop(_key_depth);
        drop(_gk);
        let val_len = if (flags & header_flags::COMPACT_LEN) != 0 {
            let v = read_varint_update(&mut digesting, &mut remaining)?;
            core::enforce_decode_field_length(v)?;
            core::stream::u64_to_usize(v)?
        } else {
            let v = read_u64_update(&mut digesting, &mut remaining)?;
            core::enforce_decode_field_length(v)?;
            core::stream::u64_to_usize(v)?
        };
        if val_len > remaining {
            return Err(Error::LengthMismatch);
        }
        try_resize_decode_buffer(&mut val_buf, val_len)?;
        read_exact_update(&mut digesting, &mut remaining, &mut val_buf)?;
        let _gv = core::PayloadCtxGuard::enter(&val_buf);
        let _value_depth = core::DecodeDepthGuard::enter()?;
        let av = unsafe { &*(val_buf.as_ptr() as *const Archived<V>) };
        let value = guarded_try_deserialize(|| V::try_deserialize(av))?;
        insert(&mut map, key, value)?;
    }
    if remaining != 0 {
        return Err(Error::LengthMismatch);
    }
    let _ = digesting.finalize(payload_len, header.checksum)?;
    Ok(map)
}
/// Collect a top-level `HashMap<K,V>` by streaming with minimal buffering.
///
/// Entries stream one by one (len+key, len+value) without buffering the payload.
pub fn stream_hashmap_collect_from_reader<R, K, V>(reader: R) -> Result<HashMap<K, V>, Error>
where
    R: Read,
    K: for<'de> NoritoDeserialize<'de> + NoritoSerialize + Eq + std::hash::Hash + Ord,
    V: for<'de> NoritoDeserialize<'de> + NoritoSerialize,
{
    stream_map_collect_core(
        reader,
        crate::schema::identity::frame_hash::<HashMap<K, V>>(),
        core::payload_alignment_padding_for::<HashMap<K, V>>(),
        |entries| {
            let bytes = entries
                .checked_mul(std::mem::size_of::<(K, V)>())
                .ok_or(Error::LengthMismatch)?;
            core::reserve_decode_allocation(bytes)?;
            let mut map = HashMap::new();
            map.try_reserve(entries)
                .map_err(|_| Error::AllocationFailed {
                    bytes: u64::try_from(bytes).unwrap_or(u64::MAX),
                })?;
            Ok(map)
        },
        |map, key, value| {
            if map.insert(key, value).is_some() {
                Err(Error::LengthMismatch)
            } else {
                Ok(())
            }
        },
    )
}
/// Collect a top-level `BTreeMap<K,V>` by streaming with minimal buffering.
pub fn stream_btreemap_collect_from_reader<R, K, V>(reader: R) -> Result<BTreeMap<K, V>, Error>
where
    R: Read,
    K: for<'de> NoritoDeserialize<'de> + NoritoSerialize + Ord,
    V: for<'de> NoritoDeserialize<'de> + NoritoSerialize,
{
    stream_map_collect_core(
        reader,
        crate::schema::identity::frame_hash::<BTreeMap<K, V>>(),
        core::payload_alignment_padding_for::<BTreeMap<K, V>>(),
        |_| Ok(BTreeMap::new()),
        |map, key, value| {
            if map.insert(key, value).is_some() {
                Err(Error::LengthMismatch)
            } else {
                Ok(())
            }
        },
    )
}
/// Types that can be finalized via `finish()` to verify integrity
/// (e.g., CRC) when a stream is not fully consumed.
pub trait Finishable {
    fn finish(self) -> Result<(), Error>;
}
impl<T> Finishable for StreamSeqIter<T>
where
    T: for<'de> NoritoDeserialize<'de> + core::NoritoSerialize,
{
    fn finish(self) -> Result<(), Error> {
        StreamSeqIter::finish(self)
    }
}
impl<K, V> Finishable for StreamMapIter<K, V>
where
    K: for<'de> NoritoDeserialize<'de> + core::NoritoSerialize,
    V: for<'de> NoritoDeserialize<'de> + core::NoritoSerialize,
{
    fn finish(self) -> Result<(), Error> {
        StreamMapIter::finish(self)
    }
}
/// RAII guard that calls `finish()` on drop and logs errors.
pub struct StreamFinishGuard<T: Finishable> {
    inner: Option<T>,
    name: &'static str,
}
impl<T: Finishable> StreamFinishGuard<T> {
    pub fn new(iter: T, name: &'static str) -> Self {
        Self {
            inner: Some(iter),
            name,
        }
    }
    pub fn into_inner(mut self) -> T {
        self.inner.take().unwrap()
    }
    /// Leak the inner iterator without calling `finish()` on drop.
    /// Useful for debugging when you deliberately skip integrity checks.
    pub fn leak(self) -> T {
        self.into_inner()
    }
}
impl<T: Finishable> Drop for StreamFinishGuard<T> {
    fn drop(&mut self) {
        if let Some(iter) = self.inner.take()
            && let Err(e) = iter.finish()
        {
            eprintln!("StreamFinishGuard({}): finish() error: {:?}", self.name, e);
        }
    }
}
#[cfg(test)]
mod json_stage1_reset_tests {
    #[test]
    fn reset_stage1_backends_is_callable() {
        crate::json::reset_stage1_backends();
    }
}
/// Canonical JSON literal helpers used by higher-level codecs.
pub mod literal;
/// Convenience to wrap a stream iterator and ensure `finish()` is called on drop.
pub fn finish_on_drop<T: Finishable>(iter: T, name: &'static str) -> StreamFinishGuard<T> {
    StreamFinishGuard::new(iter, name)
}
/// Convenience constructor for a streaming iterator over a top-level `Vec<T>` payload.
pub fn stream_seq_iter<R, T>(reader: R) -> Result<StreamSeqIter<T>, Error>
where
    R: Read + 'static,
    T: for<'de> NoritoDeserialize<'de> + core::NoritoSerialize,
{
    StreamSeqIter::<T>::new(reader)
}
/// Construct a streaming sequence iterator with an owned decode-resource
/// budget that remains active for every iteration and for [`StreamSeqIter::finish`].
///
/// # Errors
///
/// Returns an error when the archive header is invalid or the top-level
/// sequence already exceeds `limits`.
pub fn stream_seq_iter_with_limits<R, T>(
    reader: R,
    limits: DecodeLimits,
) -> Result<StreamSeqIter<T>, Error>
where
    R: Read + 'static,
    T: for<'de> NoritoDeserialize<'de> + core::NoritoSerialize,
{
    StreamSeqIter::<T>::new_with_limits(reader, limits)
}
/// Streaming iterator over a top-level `Vec<T>` payload.
pub struct StreamSeqIter<T> {
    reader: Option<core::stream::DigestingReader<Box<dyn Read>>>,
    len_decoder: core::stream::SeqLenDecoder,
    remaining: usize,
    payload_len: usize,
    checksum: u64,
    flags_guard: core::DecodeFlagsGuard,
    scratch: core::stream::AlignedScratch,
    archived_align: usize,
    decode_budget: Option<core::DecodeBudgetContext>,
    _marker: std::marker::PhantomData<T>,
}
impl<T> StreamSeqIter<T>
where
    T: for<'de> NoritoDeserialize<'de> + core::NoritoSerialize,
{
    /// Construct an unbounded iterator for trusted input.
    ///
    /// # Errors
    ///
    /// Returns an error when the archive header or sequence metadata is invalid.
    pub fn new<R: Read + 'static>(mut reader: R) -> Result<Self, Error> {
        use core::Header;
        let header = Header::read(&mut reader)?;
        core::prepare_header_decode(header.flags, true)?;
        type Top<U> = Vec<U>;
        if header.schema != norito::schema::identity::frame_hash::<Top<T>>() {
            return Err(Error::SchemaMismatch);
        }
        let payload_len = core::payload_len_to_usize(header.length)?;
        let flags = header.flags;
        let padding = match header.compression {
            Compression::None => core::payload_alignment_padding_for::<Top<T>>(),
            Compression::Zstd => 0,
        };
        if padding != 0 {
            core::stream::skip_padding(&mut reader, padding)?;
        }
        let flags_guard = core::DecodeFlagsGuard::enter(flags);
        let boxed: Box<dyn Read> = match header.compression {
            Compression::None => Box::new(reader),
            Compression::Zstd => {
                #[cfg(feature = "compression")]
                {
                    Box::new(zstd::Decoder::new(reader)?)
                }
                #[cfg(not(feature = "compression"))]
                {
                    return Err(std::io::Error::other("compression support disabled").into());
                }
            }
        };
        let mut digesting = core::stream::DigestingReader::new(boxed);
        let len_decoder = core::stream::SeqLenDecoder::new(&mut digesting, flags, payload_len)?;
        let remaining = len_decoder.total_len();
        Ok(Self {
            reader: Some(digesting),
            len_decoder,
            remaining,
            payload_len,
            checksum: header.checksum,
            flags_guard,
            scratch: core::stream::AlignedScratch::new(),
            archived_align: core::archived_payload_align::<T>(),
            decode_budget: None,
            _marker: std::marker::PhantomData,
        })
    }
    /// Construct an iterator that owns and reapplies `limits` for its complete lazy lifetime.
    ///
    /// # Errors
    ///
    /// Returns an error when the archive header or sequence metadata is invalid,
    /// or when the top-level sequence exceeds `limits`.
    pub fn new_with_limits<R: Read + 'static>(
        reader: R,
        limits: DecodeLimits,
    ) -> Result<Self, Error> {
        let context = core::DecodeBudgetContext::new(limits);
        let mut iterator = context.with(|| Self::new(reader))?;
        iterator.decode_budget = Some(context);
        Ok(iterator)
    }
    fn finalize(
        reader: core::stream::DigestingReader<Box<dyn Read>>,
        payload_len: usize,
        checksum: u64,
    ) -> Result<(), Error> {
        let _ = reader.finalize(payload_len, checksum)?;
        Ok(())
    }
}
impl<T> Iterator for StreamSeqIter<T>
where
    T: for<'de> NoritoDeserialize<'de> + core::NoritoSerialize,
{
    type Item = Result<T, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        let decode_budget = self.decode_budget.clone();
        core::with_optional_decode_budget(decode_budget.as_ref(), || {
            let _ = &self.flags_guard;
            let reader = self.reader.as_mut()?;
            if self.remaining == 0 {
                let mut reader = self.reader.take().unwrap();
                let tail = match self
                    .payload_len
                    .checked_sub(reader.consumed())
                    .ok_or(Error::LengthMismatch)
                    .and_then(|remaining| self.len_decoder.finish(&mut reader, remaining))
                {
                    Ok(()) => reader,
                    Err(err) => return Some(Err(err)),
                };
                if let Err(e) = Self::finalize(tail, self.payload_len, self.checksum) {
                    return Some(Err(e));
                }
                return None;
            }
            match self.len_decoder.next_len(reader) {
                Ok(Some(len)) => {
                    match self.payload_len.checked_sub(reader.consumed()) {
                        Some(available) if len <= available => {}
                        _ => return Some(Err(Error::LengthMismatch)),
                    }
                    let _depth = match core::DecodeDepthGuard::enter() {
                        Ok(guard) => guard,
                        Err(error) => return Some(Err(error)),
                    };
                    let value = if len == 0 {
                        if core::archived_payload_size::<T>() != 0 {
                            Err(Error::LengthMismatch)
                        } else {
                            let _pg = core::PayloadCtxGuard::enter(&[]);
                            let archived = core::empty_archived_marker::<T>();
                            guarded_try_deserialize(|| T::try_deserialize(archived))
                        }
                    } else {
                        unsafe {
                            let ptr = match self.scratch.ensure(len, self.archived_align) {
                                Ok(ptr) => ptr,
                                Err(e) => return Some(Err(e)),
                            };
                            let tmp_slice_mut = std::slice::from_raw_parts_mut(ptr, len);
                            if let Err(e) = reader.read_exact_into(tmp_slice_mut) {
                                return Some(Err(e.into()));
                            }
                            let tmp_slice = std::slice::from_raw_parts(ptr as *const u8, len);
                            let _pg = core::PayloadCtxGuard::enter(tmp_slice);
                            let archived = &*(ptr as *const core::Archived<T>);
                            guarded_try_deserialize(|| T::try_deserialize(archived))
                        }
                    };
                    self.remaining -= 1;
                    if self.remaining == 0 {
                        let mut reader = self.reader.take().unwrap();
                        match self
                            .payload_len
                            .checked_sub(reader.consumed())
                            .ok_or(Error::LengthMismatch)
                            .and_then(|remaining| self.len_decoder.finish(&mut reader, remaining))
                        {
                            Ok(()) => {
                                if let Err(e) =
                                    Self::finalize(reader, self.payload_len, self.checksum)
                                {
                                    return Some(Err(e));
                                }
                            }
                            Err(err) => return Some(Err(err)),
                        }
                    }
                    Some(value)
                }
                Ok(None) => {
                    let reader = self.reader.take().unwrap();
                    if let Err(e) = Self::finalize(reader, self.payload_len, self.checksum) {
                        return Some(Err(e));
                    }
                    Some(Err(Error::LengthMismatch))
                }
                Err(e) => Some(Err(e)),
            }
        })
    }
}
impl<T> StreamSeqIter<T>
where
    T: for<'de> NoritoDeserialize<'de> + core::NoritoSerialize,
{
    /// Consume every unread element body and verify the payload checksum.
    ///
    /// # Errors
    ///
    /// Returns an error when unread sequence metadata or bodies are malformed,
    /// checksum verification fails, or the iterator's decode budget is exceeded.
    pub fn finish(mut self) -> Result<(), Error> {
        let decode_budget = self.decode_budget.clone();
        core::with_optional_decode_budget(decode_budget.as_ref(), || {
            let _ = &self.flags_guard;
            if let Some(mut reader) = self.reader.take() {
                while self.remaining > 0 {
                    let len = match self.len_decoder.next_len(&mut reader)? {
                        Some(len) => len,
                        None => return Err(Error::LengthMismatch),
                    };
                    if len > 0 {
                        let available = self
                            .payload_len
                            .checked_sub(reader.consumed())
                            .ok_or(Error::LengthMismatch)?;
                        if len > available {
                            return Err(Error::LengthMismatch);
                        }
                        unsafe {
                            let ptr = self.scratch.ensure(len, self.archived_align)?;
                            let tmp = std::slice::from_raw_parts_mut(ptr, len);
                            reader.read_exact_into(tmp)?;
                        }
                    }
                    self.remaining -= 1;
                }
                let remaining = self
                    .payload_len
                    .checked_sub(reader.consumed())
                    .ok_or(Error::LengthMismatch)?;
                self.len_decoder.finish(&mut reader, remaining)?;
                Self::finalize(reader, self.payload_len, self.checksum)?;
            }
            Ok(())
        })
    }
}
/// Streaming iterator over a top-level `HashMap<K,V>`/`BTreeMap<K,V>` payload.
pub struct StreamMapIter<K, V> {
    reader: Box<dyn Read>,
    flags: u8,
    entries: usize,
    idx: usize,
    digest: crc64fast::Digest,
    payload_remaining: usize,
    checksum: u64,
    flags_guard: core::DecodeFlagsGuard,
    decode_budget: Option<core::DecodeBudgetContext>,
    _marker: std::marker::PhantomData<(K, V)>,
    // Reusable buffers for key/value bodies
    kbuf: Vec<u8>,
    vbuf: Vec<u8>,
}
const STREAM_MAX_VARINT_BYTES: usize = 10;
fn try_resize_decode_buffer(buffer: &mut Vec<u8>, length: usize) -> Result<(), Error> {
    if length > buffer.capacity() {
        let additional = length
            .checked_sub(buffer.len())
            .ok_or(Error::LengthMismatch)?;
        core::reserve_decode_allocation(additional)?;
        buffer
            .try_reserve(additional)
            .map_err(|_| Error::AllocationFailed {
                bytes: u64::try_from(length).unwrap_or(u64::MAX),
            })?;
    }
    buffer.resize(length, 0);
    Ok(())
}
impl<K, V> StreamMapIter<K, V>
where
    K: for<'de> NoritoDeserialize<'de>,
    V: for<'de> NoritoDeserialize<'de>,
{
    #[inline]
    fn read_exact_update_buf(
        reader: &mut dyn Read,
        digest: &mut crc64fast::Digest,
        remaining: &mut usize,
        buf: &mut [u8],
    ) -> Result<(), Error> {
        let new_remaining = remaining
            .checked_sub(buf.len())
            .ok_or(Error::LengthMismatch)?;
        reader.read_exact(buf)?;
        digest.write(buf);
        *remaining = new_remaining;
        Ok(())
    }
    #[inline]
    fn read_exact_update_kbuf(&mut self) -> Result<(), Error> {
        let buf = &mut self.kbuf;
        Self::read_exact_update_buf(
            &mut *self.reader,
            &mut self.digest,
            &mut self.payload_remaining,
            buf,
        )
    }
    #[inline]
    fn read_exact_update_vbuf(&mut self) -> Result<(), Error> {
        let buf = &mut self.vbuf;
        Self::read_exact_update_buf(
            &mut *self.reader,
            &mut self.digest,
            &mut self.payload_remaining,
            buf,
        )
    }
    #[inline]
    fn read_u64_update(&mut self) -> Result<u64, Error> {
        let mut b = [0u8; 8];
        Self::read_exact_update_buf(
            &mut *self.reader,
            &mut self.digest,
            &mut self.payload_remaining,
            &mut b,
        )?;
        Ok(u64::from_le_bytes(b))
    }
    #[inline]
    fn read_len(&mut self) -> Result<usize, Error> {
        let raw = if (self.flags & core::header_flags::COMPACT_LEN) != 0 {
            self.read_varint_update()?
        } else {
            self.read_u64_update()?
        };
        core::enforce_decode_field_length(raw)?;
        core::stream::u64_to_usize(raw)
    }
    #[inline]
    fn read_varint_update(&mut self) -> Result<u64, Error> {
        let mut result = 0u64;
        let mut shift = 0u32;
        let mut used = 0usize;
        let mut buf = [0u8; 1];
        for _ in 0..STREAM_MAX_VARINT_BYTES {
            Self::read_exact_update_buf(
                &mut *self.reader,
                &mut self.digest,
                &mut self.payload_remaining,
                &mut buf,
            )?;
            used += 1;
            let byte = buf[0];
            let payload = (byte & 0x7f) as u64;
            if shift == 63 && payload > 1 {
                return Err(Error::LengthMismatch);
            }
            result |= payload << shift;
            if byte & 0x80 == 0 {
                if used != core::varint_encoded_len_u64(result) {
                    return Err(Error::LengthMismatch);
                }
                return Ok(result);
            }
            shift += 7;
            if shift >= 64 {
                break;
            }
        }
        Err(Error::LengthMismatch)
    }
}
impl<K, V> StreamMapIter<K, V>
where
    K: for<'de> NoritoDeserialize<'de> + core::NoritoSerialize,
    V: for<'de> NoritoDeserialize<'de> + core::NoritoSerialize,
{
    fn new_with_schema<R: Read + 'static>(
        mut reader: R,
        expected_schema: [u8; 16],
        uncompressed_padding: usize,
    ) -> Result<Self, Error> {
        use core::{Header, header_flags};
        let header = Header::read(&mut reader)?;
        core::prepare_header_decode(header.flags, false)?;
        if header.schema != expected_schema {
            return Err(Error::SchemaMismatch);
        }
        let payload_len = core::payload_len_to_usize(header.length)?;
        let flags = header.flags;
        let padding = match header.compression {
            Compression::None => uncompressed_padding,
            Compression::Zstd => 0,
        };
        if padding != 0 {
            core::stream::skip_padding(&mut reader, padding)?;
        }
        let flags_guard = core::DecodeFlagsGuard::enter(flags);
        let mut r: Box<dyn Read> = match header.compression {
            Compression::None => Box::new(reader),
            Compression::Zstd => {
                #[cfg(feature = "compression")]
                {
                    Box::new(zstd::Decoder::new(reader)?)
                }
                #[cfg(not(feature = "compression"))]
                {
                    return Err(std::io::Error::other("compression support disabled").into());
                }
            }
        };
        let mut digest = crc64fast::Digest::new();
        let mut remaining = payload_len;
        #[inline]
        fn read_exact_update<Rd: Read>(
            src: &mut Rd,
            dst: &mut [u8],
            d: &mut crc64fast::Digest,
            remaining: &mut usize,
        ) -> Result<(), Error> {
            let new_remaining = remaining
                .checked_sub(dst.len())
                .ok_or(Error::LengthMismatch)?;
            src.read_exact(dst)?;
            d.write(dst);
            *remaining = new_remaining;
            Ok(())
        }
        #[inline]
        fn read_u64_update<Rd: Read>(
            src: &mut Rd,
            d: &mut crc64fast::Digest,
            remaining: &mut usize,
        ) -> Result<u64, Error> {
            let mut b = [0u8; 8];
            read_exact_update(src, &mut b, d, remaining)?;
            Ok(u64::from_le_bytes(b))
        }
        let entries = {
            let v = read_u64_update(&mut r, &mut digest, &mut remaining)?;
            core::enforce_decode_sequence_length(v)?;
            core::stream::u64_to_usize(v)?
        };
        let len_bytes = if (flags & header_flags::COMPACT_LEN) != 0 {
            1usize
        } else {
            8usize
        };
        let per_entry = len_bytes.checked_mul(2).ok_or(Error::LengthMismatch)?;
        let min_headers = entries
            .checked_mul(per_entry)
            .ok_or(Error::LengthMismatch)?;
        if min_headers > remaining {
            return Err(Error::LengthMismatch);
        }
        Ok(StreamMapIter {
            reader: r,
            flags,
            entries,
            idx: 0,
            digest,
            payload_remaining: remaining,
            checksum: header.checksum,
            flags_guard,
            decode_budget: None,
            _marker: std::marker::PhantomData,
            kbuf: Vec::new(),
            vbuf: Vec::new(),
        })
    }
    pub fn new_hash<R: Read + 'static>(reader: R) -> Result<Self, Error>
    where
        K: Eq + std::hash::Hash + Ord,
    {
        type Top<KK, VV> = HashMap<KK, VV>;
        Self::new_with_schema(
            reader,
            norito::schema::identity::frame_hash::<Top<K, V>>(),
            core::payload_alignment_padding_for::<Top<K, V>>(),
        )
    }
    /// Construct a bounded lazy iterator over a `HashMap` archive.
    ///
    /// # Errors
    ///
    /// Returns an error when the archive metadata is invalid or exceeds `limits`.
    pub fn new_hash_with_limits<R: Read + 'static>(
        reader: R,
        limits: DecodeLimits,
    ) -> Result<Self, Error>
    where
        K: Eq + std::hash::Hash + Ord,
    {
        let context = core::DecodeBudgetContext::new(limits);
        let mut iterator = context.with(|| Self::new_hash(reader))?;
        iterator.decode_budget = Some(context);
        Ok(iterator)
    }
    pub fn new_btree<R: Read + 'static>(reader: R) -> Result<Self, Error>
    where
        K: Ord,
    {
        type Top<KK, VV> = BTreeMap<KK, VV>;
        Self::new_with_schema(
            reader,
            norito::schema::identity::frame_hash::<Top<K, V>>(),
            core::payload_alignment_padding_for::<Top<K, V>>(),
        )
    }
    /// Construct a bounded lazy iterator over a `BTreeMap` archive.
    ///
    /// # Errors
    ///
    /// Returns an error when the archive metadata is invalid or exceeds `limits`.
    pub fn new_btree_with_limits<R: Read + 'static>(
        reader: R,
        limits: DecodeLimits,
    ) -> Result<Self, Error>
    where
        K: Ord,
    {
        let context = core::DecodeBudgetContext::new(limits);
        let mut iterator = context.with(|| Self::new_btree(reader))?;
        iterator.decode_budget = Some(context);
        Ok(iterator)
    }
    /// Finish the map stream by consuming remaining bytes and verifying CRC.
    ///
    /// # Errors
    ///
    /// Returns an error when unread map metadata or bodies are malformed,
    /// checksum verification fails, or the iterator's decode budget is exceeded.
    pub fn finish(mut self) -> Result<(), Error> {
        let decode_budget = self.decode_budget.clone();
        core::with_optional_decode_budget(decode_budget.as_ref(), || {
            let _ = &self.flags_guard;
            while self.idx < self.entries {
                // read and skip key
                let klen = self.read_len()?;
                if klen > self.payload_remaining {
                    return Err(Error::LengthMismatch);
                }
                try_resize_decode_buffer(&mut self.kbuf, klen)?;
                self.read_exact_update_kbuf()?;
                // read and skip value
                let vlen = self.read_len()?;
                if vlen > self.payload_remaining {
                    return Err(Error::LengthMismatch);
                }
                try_resize_decode_buffer(&mut self.vbuf, vlen)?;
                self.read_exact_update_vbuf()?;
                self.idx += 1;
            }
            if self.payload_remaining != 0 {
                return Err(Error::LengthMismatch);
            }
            if self.digest.sum64() != self.checksum {
                return Err(Error::ChecksumMismatch);
            }
            Ok(())
        })
    }
}
include!("stream_map_iterator.rs");
#[cfg(test)]
include!("lib_tail_tests.rs");
