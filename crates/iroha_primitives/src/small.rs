//! Types that store small data inline to avoid heap allocations.
//!
//! This module wraps Iroha's [`ConstString`] and the `smallvec` crate.
//! Short strings use the architecture-dependent inline capacity of
//! [`ConstString`], while [`SmallVec`] can be tuned to store a handful of
//! elements on the stack before spilling onto the heap.
use crate::conststr::ConstString;
use core::fmt;
use iroha_schema::{IntoSchema, TypeId};
use norito::{
    DeserializePayload, SerializePayload, core as ncore,
    json::{self, FastJsonWrite, JsonDeserialize, JsonSerialize},
};
pub use small_string::SmallStr;
pub use small_vector::SmallVec;
pub use smallvec::{Array, smallvec};
use std::{format, string::String, vec::Vec};
/// The go-to size for `SmallVec`. When in doubt, use this.
pub const SMALL_SIZE: usize = 8_usize;
mod small_string {
    use super::*;
    #[derive(Debug, derive_more::Display, Clone, PartialEq, Eq, IntoSchema)]
    /// Immutable string that stores short values inline using [`ConstString`].
    #[schema(transparent = "String")]
    #[repr(transparent)]
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_primitives::small::small_string::SmallStr")]
    pub struct SmallStr(ConstString);
    impl SmallStr {
        #[must_use]
        #[inline]
        /// Construct [`Self`] by taking ownership of a [`String`].
        pub fn from_string(other: String) -> Self {
            Self(ConstString::from(other))
        }
        #[must_use]
        #[inline]
        #[allow(clippy::should_implement_trait)]
        /// Construct [`Self`] infallibly without taking ownership of a
        /// string slice. This is not an implementation of [`FromStr`](core::str::FromStr),
        /// because the latter implies **fallible** conversion, while this
        /// particular conversion is **infallible**.
        pub fn from_str(other: &str) -> Self {
            Self(ConstString::from(other))
        }
        #[inline]
        /// Checks if the specified pattern is the prefix of given string.
        pub fn starts_with(&self, pattern: &str) -> bool {
            self.0.starts_with(pattern)
        }
    }
    impl AsRef<str> for SmallStr {
        fn as_ref(&self) -> &str {
            self.0.as_ref()
        }
    }
    impl SmallStr {
        #[inline]
        fn as_str(&self) -> &str {
            self.0.as_ref()
        }
    }
    impl FastJsonWrite for SmallStr {
        fn write_json(&self, out: &mut String) {
            json::write_json_string(self.as_str(), out);
        }
        fn write_json_to(
            &self,
            out: &mut dyn json::JsonWriteSink,
        ) -> Result<(), json::BoundedJsonError> {
            json::write_json_string_to(self.as_str(), out)
        }
    }
    impl JsonDeserialize for SmallStr {
        fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
            let value = parser.parse_string()?;
            Ok(Self::from_string(value))
        }
    }

    impl SerializePayload for SmallStr {
        fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), ncore::Error> {
            <&str as SerializePayload>::serialize(&self.as_str(), writer)
        }
    }

    impl<'a> DeserializePayload<'a> for SmallStr {
        fn deserialize(archived: &'a ncore::Archived<Self>) -> Self {
            let archived_str: &ncore::Archived<String> = archived.cast();
            let string = <String as DeserializePayload>::deserialize(archived_str);
            Self::from_string(string)
        }
        fn try_deserialize(archived: &'a ncore::Archived<Self>) -> Result<Self, ncore::Error> {
            let string = <String as DeserializePayload>::try_deserialize(archived.cast())?;
            // The String decoder has already admitted an exact owned allocation.
            // Transfer it instead of retaining a second, unaccounted copy.
            Ok(Self::from_string(string))
        }
    }
    impl<'a> ncore::DecodeFromSlice<'a> for SmallStr {
        fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), ncore::Error> {
            // The existing String decoder charges and allocates exactly the decoded
            // bytes. Transfer that buffer; short strings then move inline.
            let (value, used) = <String as ncore::DecodeFromSlice>::decode_from_slice(bytes)
                .map_err(|error| match error {
                    // Preserve the public slice decoder's existing UTF-8 error.
                    ncore::Error::InvalidUtf8 => ncore::Error::Message("invalid utf8".into()),
                    other => other,
                })?;
            Ok((Self::from_string(value), used))
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use norito::{
        DeserializePayload, SerializePayload,
        codec::{Decode, Encode},
        core as ncore, decode_from_bytes, json, to_bytes,
    };

    fn smallstr_boundary_samples() -> Vec<String> {
        let mut samples = vec![
            String::new(),
            "Δfire🔥".to_owned(),
            "é".to_owned(),
            "e\u{301}".to_owned(),
            "quote\" slash\\ newline\n null\0".to_owned(),
        ];
        samples.extend(
            [1, 6, 7, 8, 14, 15, 16, 31, 32, 33, 127, 128, 255, 256, 4096]
                .into_iter()
                .map(|len| "a".repeat(len)),
        );
        samples
    }

    // The expected payload is constructed from the V1 string-length contract, independently of
    // SmallStr and String serializers. Both explicitly advertised layouts remain readable.
    fn smallstr_expected_payload(value: &str, flags: u8) -> Vec<u8> {
        let mut len = u64::try_from(value.len()).expect("fixture length fits u64");
        let mut payload = Vec::new();
        if flags == 0 {
            payload.extend_from_slice(&len.to_le_bytes());
        } else {
            assert_eq!(flags, ncore::header_flags::COMPACT_LEN);
            while len >= 128 {
                payload.push(u8::try_from(len & 0x7f).expect("seven bits") | 0x80);
                len >>= 7;
            }
            payload.push(u8::try_from(len).expect("terminal seven bits"));
        }
        payload.extend_from_slice(value.as_bytes());
        payload
    }

    fn smallstr_golden_bytes(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0);
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let hi = char::from(pair[0]).to_digit(16).expect("golden hex");
                let lo = char::from(pair[1]).to_digit(16).expect("golden hex");
                u8::try_from((hi << 4) | lo).expect("one golden byte")
            })
            .collect()
    }

    #[test]
    fn smallstr_boundaries_preserve_ownership_unicode_and_clone_lifetime() {
        fn assert_thread_safe<T: Send + Sync>() {}
        assert_thread_safe::<SmallStr>();
        for sample in smallstr_boundary_samples() {
            let borrowed = SmallStr::from_str(&sample);
            let mut oversized = String::with_capacity(sample.len() + 37);
            oversized.push_str(&sample);
            let owned = SmallStr::from_string(oversized);
            assert_eq!(owned, borrowed);
            assert_eq!(owned.as_ref().as_bytes(), sample.as_bytes());
            assert_eq!(owned.to_string(), sample);
            assert!(owned.starts_with(""));
            assert_eq!(owned.starts_with("a"), sample.starts_with('a'));
            let cloned = owned.clone();
            drop(owned);
            drop(borrowed);
            assert_eq!(cloned.as_ref().as_bytes(), sample.as_bytes());
            let encoded_json = json::to_json(&cloned).expect("SmallStr JSON");
            assert_eq!(encoded_json, json::to_json(&sample).expect("String JSON"));
            let decoded: SmallStr = json::from_json(&encoded_json).expect("SmallStr JSON decode");
            assert_eq!(decoded, cloned);
        }
        // The storage replacement must not introduce Unicode normalization.
        assert_ne!(SmallStr::from_str("é"), SmallStr::from_str("e\u{301}"));
        assert_eq!(<SmallStr as IntoSchema>::type_name(), "String");
        assert_eq!(<SmallStr as TypeId>::id(), "SmallStr");
    }

    // Fixed canonical frames for both supported length layouts.
    const SMALLSTR_GOLDEN_FRAMES: [(usize, u8, &str); 16] = [
        (
            0_usize,
            0_u8,
            "4e52543000005333e7064f0e992f6660a7e123240cbc000800000000000000c0ca824265736ab6000000000000000000",
        ),
        (
            0_usize,
            2_u8,
            "4e52543000005333e7064f0e992f6660a7e123240cbc000100000000000000593f676473a1ad1f0200",
        ),
        (
            1_usize,
            0_u8,
            "4e52543000005333e7064f0e992f6660a7e123240cbc0017000000000000002de3772840e8535e000f00000000000000616161616161616161616161616161",
        ),
        (
            1_usize,
            2_u8,
            "4e52543000005333e7064f0e992f6660a7e123240cbc001000000000000000cf4fc47984928fb2020f616161616161616161616161616161",
        ),
        (
            2_usize,
            0_u8,
            "4e52543000005333e7064f0e992f6660a7e123240cbc001800000000000000eecdbc90e171b98200100000000000000061616161616161616161616161616161",
        ),
        (
            2_usize,
            2_u8,
            "4e52543000005333e7064f0e992f6660a7e123240cbc001100000000000000ea834c75f6722702021061616161616161616161616161616161",
        ),
        (
            3_usize,
            0_u8,
            "4e52543000005333e7064f0e992f6660a7e123240cbc00280000000000000062464e0110a615420020000000000000006161616161616161616161616161616161616161616161616161616161616161",
        ),
        (
            3_usize,
            2_u8,
            "4e52543000005333e7064f0e992f6660a7e123240cbc0021000000000000007596aa4322fc82dc02206161616161616161616161616161616161616161616161616161616161616161",
        ),
        (
            4_usize,
            0_u8,
            "4e52543000005333e7064f0e992f6660a7e123240cbc002900000000000000f2423d0b1724d13a002100000000000000616161616161616161616161616161616161616161616161616161616161616161",
        ),
        (
            4_usize,
            2_u8,
            "4e52543000005333e7064f0e992f6660a7e123240cbc002200000000000000a79c374b61a905710221616161616161616161616161616161616161616161616161616161616161616161",
        ),
        (
            5_usize,
            0_u8,
            "4e52543000005333e7064f0e992f6660a7e123240cbc000a0000000000000079771454a860cfc0000200000000000000c3a9",
        ),
        (
            5_usize,
            2_u8,
            "4e52543000005333e7064f0e992f6660a7e123240cbc000300000000000000d3ccdd540d57eb0e0202c3a9",
        ),
        (
            6_usize,
            0_u8,
            "4e52543000005333e7064f0e992f6660a7e123240cbc000b00000000000000307811c21b39fac700030000000000000065cc81",
        ),
        (
            6_usize,
            2_u8,
            "4e52543000005333e7064f0e992f6660a7e123240cbc0004000000000000006d1f209bd3c20fe2020365cc81",
        ),
        (
            7_usize,
            0_u8,
            "4e52543000005333e7064f0e992f6660a7e123240cbc001600000000000000938a3f2c38b31638000e00000000000000ce9466697265f09f94a5000a225c",
        ),
        (
            7_usize,
            2_u8,
            "4e52543000005333e7064f0e992f6660a7e123240cbc000f0000000000000037f906f0b35fb362020ece9466697265f09f94a5000a225c",
        ),
    ];

    #[test]
    fn smallstr_canonical_header_and_payload_goldens() {
        // Generated independently from the fixed type-name SHA-256 domain and CRC64-XZ framing.
        assert_eq!(
            core::any::type_name::<SmallStr>(),
            "iroha_primitives::small::small_string::SmallStr"
        );
        assert_eq!(
            norito::schema::identity::frame_hash::<SmallStr>(),
            [
                0x53, 0x33, 0xe7, 0x06, 0x4f, 0x0e, 0x99, 0x2f, 0x66, 0x60, 0xa7, 0xe1, 0x23, 0x24,
                0x0c, 0xbc
            ]
        );
        let samples = [
            String::new(),
            "a".repeat(15),
            "a".repeat(16),
            "a".repeat(32),
            "a".repeat(33),
            "é".to_owned(),
            "e\u{301}".to_owned(),
            "Δfire🔥\0\n\"\\".to_owned(),
        ];

        for (index, flags, golden) in SMALLSTR_GOLDEN_FRAMES {
            let _flags = ncore::DecodeFlagsGuard::enter(flags);
            let value = SmallStr::from_str(&samples[index]);
            let encoded = to_bytes(&value).expect("SmallStr frame");
            assert_eq!(encoded, smallstr_golden_bytes(golden));
            let header = ncore::Header::read(encoded.as_slice()).expect("frame header");
            assert_eq!(header.flags, flags);
            let expected_payload = smallstr_expected_payload(&samples[index], flags);
            assert_eq!(
                header.length,
                u64::try_from(expected_payload.len()).expect("length")
            );
            assert_eq!(&encoded[ncore::Header::SIZE..], expected_payload);
            let decoded: SmallStr = decode_from_bytes(&encoded).expect("golden frame decode");
            assert_eq!(decoded, value);
            assert_eq!(to_bytes(&decoded).expect("golden re-encode"), encoded);
            if flags == ncore::header_flags::COMPACT_LEN {
                assert_eq!(
                    norito::encode_canonical(&value).expect("canonical frame"),
                    encoded
                );
            }
        }
    }

    #[test]
    fn smallstr_slice_layout_boundaries_report_exact_consumption() {
        for flags in [0, ncore::header_flags::COMPACT_LEN] {
            let _flags = ncore::DecodeFlagsGuard::enter(flags);
            for sample in smallstr_boundary_samples() {
                let expected = smallstr_expected_payload(&sample, flags);
                let value = SmallStr::from_str(&sample);
                let mut encoded = Vec::new();
                ncore::serialize_to_buffer(&value, &mut encoded).expect("bare SmallStr");
                assert_eq!(encoded, expected);
                encoded.push(0xa5);
                let (decoded, used) =
                    <SmallStr as ncore::DecodeFromSlice>::decode_from_slice(&encoded)
                        .expect("one slice value");
                assert_eq!(decoded, value);
                assert_eq!(used, expected.len());
                assert_eq!(encoded[used], 0xa5);
                assert!(
                    <SmallStr as ncore::DecodeFromSlice>::decode_from_slice(
                        &expected[..expected.len() - 1]
                    )
                    .is_err()
                );
            }
        }
    }

    #[test]
    fn smallstr_rejects_invalid_utf8_and_frame_substitutions() {
        for flags in [0, ncore::header_flags::COMPACT_LEN] {
            let _flags = ncore::DecodeFlagsGuard::enter(flags);
            for invalid in [&[0xff][..], &[0xc0, 0xaf][..], &[0xed, 0xa0, 0x80][..]] {
                let mut payload = smallstr_expected_payload(&"a".repeat(invalid.len()), flags);
                let start = payload.len() - invalid.len();
                payload[start..].copy_from_slice(invalid);
                assert!(<SmallStr as ncore::DecodeFromSlice>::decode_from_slice(&payload).is_err());
                let frame = ncore::frame_bare_with_header_flags::<SmallStr>(&payload, flags)
                    .expect("frame invalid text with valid checksum");
                assert!(decode_from_bytes::<SmallStr>(&frame).is_err());
            }
            let value = SmallStr::from_str("retained proof label Δ");
            let frame = to_bytes(&value).expect("valid frame");
            assert_eq!(
                decode_from_bytes::<SmallStr>(&frame).expect("control"),
                value
            );
            let mut wrong_type = frame.clone();
            wrong_type[6] ^= 1;
            assert!(matches!(
                decode_from_bytes::<SmallStr>(&wrong_type),
                Err(ncore::Error::SchemaMismatch)
            ));
            let mut changed_payload = frame.clone();
            *changed_payload.last_mut().expect("payload byte") ^= 1;
            assert!(matches!(
                decode_from_bytes::<SmallStr>(&changed_payload),
                Err(ncore::Error::ChecksumMismatch)
            ));
            let mut outer_trailer = frame;
            outer_trailer.push(0);
            assert!(decode_from_bytes::<SmallStr>(&outer_trailer).is_err());
            let mut inner_trailer = smallstr_expected_payload(value.as_ref(), flags);
            inner_trailer.push(0);
            let frame = ncore::frame_bare_with_header_flags::<SmallStr>(&inner_trailer, flags)
                .expect("valid checksum over trailing payload");
            assert!(decode_from_bytes::<SmallStr>(&frame).is_err());
        }
    }

    fn smallstr_decode_limits(bytes: usize) -> ncore::DecodeLimits {
        ncore::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
    }

    #[test]
    fn smallstr_slice_and_json_decode_preserve_exact_allocation_limits() {
        for sample in ["a".repeat(16), "a".repeat(33), "Δ🔥\\\n".repeat(32)] {
            for flags in [0, ncore::header_flags::COMPACT_LEN] {
                let _flags = ncore::DecodeFlagsGuard::enter(flags);
                let bytes = smallstr_expected_payload(&sample, flags);
                let (decoded, usage) = ncore::with_decode_limits_measured(
                    smallstr_decode_limits(sample.len()),
                    || <SmallStr as ncore::DecodeFromSlice>::decode_from_slice(&bytes),
                );
                assert_eq!(decoded.expect("exact budget").0.as_ref(), sample);
                assert_eq!(usage.total_allocated_bytes(), sample.len());
                let rejected =
                    ncore::with_decode_limits(smallstr_decode_limits(sample.len() - 1), || {
                        <SmallStr as ncore::DecodeFromSlice>::decode_from_slice(&bytes)
                    });
                assert!(matches!(
                    rejected,
                    Err(ncore::Error::TotalAllocationExceeded { .. })
                ));
            }
            let input = json::to_json(&sample).expect("fixture JSON");
            let (decoded, usage) =
                ncore::with_decode_limits_measured(smallstr_decode_limits(sample.len()), || {
                    json::from_json::<SmallStr>(&input)
                });
            assert_eq!(
                decoded.expect("exact JSON retained-byte budget").as_ref(),
                sample
            );
            assert_eq!(usage.total_allocated_bytes(), sample.len());
            let rejected =
                ncore::with_decode_limits_scope(smallstr_decode_limits(sample.len() - 1), || {
                    json::from_json::<SmallStr>(&input)
                });
            assert!(matches!(
                rejected,
                Err(json::Error::DecodeResource(
                    norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
                ))
            ));
        }
    }

    #[test]
    fn smallstr_fallible_archive_returns_budget_errors_without_unwinding() {
        for flags in [0, ncore::header_flags::COMPACT_LEN] {
            let _flags = ncore::DecodeFlagsGuard::enter(flags);
            let sample = "z".repeat(4096);
            let payload = smallstr_expected_payload(&sample, flags);
            // Prepare aligned archive storage before measuring decoder-owned retention. This
            // isolates the string allocation from the framing/scratch allocation budget.
            let archived =
                ncore::archived_from_slice::<SmallStr>(&payload).expect("archive storage");
            let _payload = ncore::PayloadCtxGuard::enter(archived.bytes());
            let (decoded, usage) =
                ncore::with_decode_limits_measured(smallstr_decode_limits(sample.len()), || {
                    <SmallStr as DeserializePayload>::try_deserialize(archived.archived())
                });
            assert_eq!(
                decoded.expect("exact retained-byte budget").as_ref(),
                sample
            );
            assert_eq!(usage.total_allocated_bytes(), sample.len());
            let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                ncore::with_decode_limits(smallstr_decode_limits(sample.len() - 1), || {
                    <SmallStr as DeserializePayload>::try_deserialize(archived.archived())
                })
            }));
            assert!(matches!(
                rejected,
                Ok(Err(ncore::Error::TotalAllocationExceeded { .. }))
            ));
        }
    }

    #[test]
    fn smallstr_explicit_schema_matches_current_nominal_frame() {
        let nominal = "iroha_primitives::small::small_string::SmallStr";
        assert_eq!(<SmallStr as norito::NoritoSchema>::nominal_name(), nominal);
        assert_eq!(<SmallStr as norito::NoritoSchema>::frame_name(), nominal);
        let _flags = ncore::DecodeFlagsGuard::enter(ncore::header_flags::COMPACT_LEN);
        let frame = to_bytes(&SmallStr::from_str("schema")).expect("current nominal frame");
        assert_eq!(
            frame,
            smallstr_golden_bytes(
                "4e52543000005333e7064f0e992f6660a7e123240cbc000700000000000000f0cc6a48150062b80206736368656d61"
            )
        );
    }

    #[test]
    fn smallstr_owned_exact_heap_buffer_is_transferred_without_cloning() {
        let value = "x".repeat(4096);
        assert_eq!(value.capacity(), value.len());
        let pointer = value.as_ptr();
        let small = SmallStr::from_string(value);
        assert_eq!(small.as_ref().as_ptr(), pointer);
        assert_eq!(small.as_ref(), "x".repeat(4096));
    }

    #[test]
    fn smallstr_empty_and_inline_decodes_keep_length_budget_accounting() {
        for len in [0, 1, 6, 7, 8, 14, 15] {
            let sample = "a".repeat(len);
            for flags in [0, ncore::header_flags::COMPACT_LEN] {
                let _flags = ncore::DecodeFlagsGuard::enter(flags);
                let bytes = smallstr_expected_payload(&sample, flags);
                let (decoded, usage) =
                    ncore::with_decode_limits_measured(smallstr_decode_limits(len), || {
                        <SmallStr as ncore::DecodeFromSlice>::decode_from_slice(&bytes)
                    });
                assert_eq!(
                    decoded.expect("exact short-string budget").0.as_ref(),
                    sample
                );
                assert_eq!(usage.total_allocated_bytes(), len);
                if len > 0 {
                    assert!(matches!(
                        ncore::with_decode_limits(smallstr_decode_limits(len - 1), || {
                            <SmallStr as ncore::DecodeFromSlice>::decode_from_slice(&bytes)
                        }),
                        Err(ncore::Error::TotalAllocationExceeded { .. })
                    ));
                }
            }
        }
    }

    #[test]
    fn smallstr_slice_utf8_error_remains_the_existing_message() {
        for flags in [0, ncore::header_flags::COMPACT_LEN] {
            let _flags = ncore::DecodeFlagsGuard::enter(flags);
            let mut bytes = smallstr_expected_payload("a", flags);
            *bytes.last_mut().expect("one byte") = 0xff;
            assert!(matches!(
                <SmallStr as ncore::DecodeFromSlice>::decode_from_slice(&bytes),
                Err(ncore::Error::Message(message)) if message == "invalid utf8"
            ));
        }
    }

    // Encoding and decoding a `SmallVec` should produce an identical vector.
    #[test]
    fn smallvec_encode_decode_round_trip() {
        let vec: SmallVec<[u32; 4]> = SmallVec(smallvec![1, 2, 3]);
        let bytes = vec.encode();
        let decoded = SmallVec::<[u32; 4]>::decode(&mut bytes.as_slice()).expect("decode");
        assert_eq!(vec, decoded);
    }
    #[test]
    fn nested_smallvec_counts_once_and_retains_fixed_element_prefixes() {
        struct Leaf<'a>(&'a std::cell::Cell<usize>);

        impl SerializePayload for Leaf<'_> {
            fn serialize(&self, writer: &mut ncore::Encoder<'_>) -> Result<(), ncore::Error> {
                self.0.set(self.0.get() + 1);
                writer.write_all(&[0xAB])?;
                Ok(())
            }
        }
        for flags in (0..=ncore::supported_header_flags())
            .filter(|flags| ncore::validate_header_flags(*flags).is_ok())
        {
            let _flags = ncore::DecodeFlagsGuard::enter(flags);
            let calls = std::cell::Cell::new(0);
            let inner: SmallVec<[Leaf<'_>; 1]> = SmallVec(smallvec![Leaf(&calls)]);
            let value: SmallVec<[SmallVec<[Leaf<'_>; 1]>; 1]> = SmallVec(smallvec![inner]);
            assert_eq!(ncore::encoded_payload_len(&value).unwrap(), 33);
            assert_eq!(calls.get(), 1);
            let mut bytes = Vec::new();
            ncore::serialize_to_buffer(&value, &mut bytes).unwrap();
            let mut expected = [1_u64, 17, 1, 1]
                .into_iter()
                .flat_map(u64::to_le_bytes)
                .collect::<Vec<_>>();
            expected.push(0xAB);
            assert_eq!(bytes, expected, "fixed prefix layout for flags {flags:#x}");
        }
    }
    #[test]
    fn smallvec_decode_heap_allocation() {
        let vec: SmallVec<[u32; 4]> = SmallVec(smallvec![0, 1, 2, 3, 4, 5, 6, 7, 8]);
        let bytes = vec.encode();
        let decoded = SmallVec::<[u32; 4]>::decode(&mut bytes.as_slice()).expect("decode");
        assert_eq!(vec, decoded);
    }
    #[test]
    fn smallstr_constructors_prefix_and_display() {
        let owned = SmallStr::from_string(String::from("ledger-alpha"));
        let borrowed = SmallStr::from_str("ledger-alpha");
        assert_eq!(owned, borrowed);
        assert_eq!(owned.as_ref(), "ledger-alpha");
        assert!(owned.starts_with("ledger"));
        assert!(!owned.starts_with("account"));
        assert_eq!(owned.to_string(), "ledger-alpha");
    }
    #[test]
    fn smallstr_decode_from_slice_reports_used_bytes() {
        let value = SmallStr::from_str("slice-value");
        let mut bytes = Vec::new();
        ncore::serialize_to_buffer(&value, &mut bytes).expect("serialize SmallStr");
        let (decoded, used) =
            <SmallStr as ncore::DecodeFromSlice>::decode_from_slice(&bytes).expect("decode slice");
        assert_eq!(decoded, value);
        assert_eq!(used, bytes.len());
    }
    #[test]
    fn smallstr_json_roundtrip() {
        for sample in ["", "abc", "Δfire🔥"] {
            let small = SmallStr::from_str(sample);
            let json_repr = json::to_json(&small).expect("serialize SmallStr");
            let expected = json::to_json(&sample.to_string()).expect("serialize string");
            assert_eq!(json_repr, expected);
            let decoded: SmallStr = json::from_json(&json_repr).expect("deserialize SmallStr");
            assert_eq!(decoded, small);
        }
    }
    #[test]
    fn smallvec_json_roundtrip() {
        let vec: SmallVec<[u32; 4]> = SmallVec(smallvec![1, 2, 3, 4]);
        let json_repr = json::to_json(&vec).expect("serialize SmallVec");
        assert_eq!(json_repr, "[1,2,3,4]");
        let decoded: SmallVec<[u32; 4]> =
            json::from_json(&json_repr).expect("deserialize SmallVec");
        assert_eq!(decoded, vec);
    }
    #[test]
    fn smallstr_norito_roundtrip() {
        let value = SmallStr::from_str("tiny");
        let bytes = to_bytes(&value).expect("encode SmallStr");
        let decoded: SmallStr = decode_from_bytes(&bytes).expect("decode SmallStr");
        assert_eq!(decoded, value);
    }
    #[test]
    fn smallvec_norito_roundtrip() {
        let value: SmallVec<[u32; 4]> = SmallVec(smallvec![4, 3, 2, 1]);
        let bytes = to_bytes(&value).expect("encode SmallVec");
        let decoded: SmallVec<[u32; 4]> = decode_from_bytes(&bytes).expect("decode SmallVec");
        assert_eq!(decoded, value);
    }
    #[test]
    fn smallvec_api_methods_preserve_order() {
        let mut vec = SmallVec::<[u32; 4]>::new();
        vec.push(1);
        vec.extend([2, 3, 4, 5]);
        assert_eq!(&*vec, &[1, 2, 3, 4, 5]);
        assert_eq!(vec.remove(1), 2);
        assert_eq!(vec.clone().into_vec(), vec![1, 3, 4, 5]);
        vec.clear();
        assert!(vec.is_empty());
    }
    #[test]
    fn smallvec_from_vec_from_iter_and_into_iter_preserve_order() {
        let from_vec = SmallVec::<[u32; 2]>::from(vec![7, 8, 9]);
        let from_iter = [7_u32, 8, 9].into_iter().collect::<SmallVec<[u32; 2]>>();
        assert_eq!(from_vec, from_iter);
        assert_eq!(from_vec.into_iter().collect::<Vec<_>>(), vec![7, 8, 9]);
    }
    #[test]
    fn smallvec_decode_rejects_truncated_element_payload() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1_u64.to_le_bytes());
        bytes.extend_from_slice(&4_u64.to_le_bytes());
        bytes.extend_from_slice(&[0xAA, 0xBB]);
        let err = <SmallVec<[u32; 4]> as ncore::DecodeFromSlice>::decode_from_slice(&bytes)
            .expect_err("truncated element payload should fail");
        assert!(matches!(err, ncore::Error::LengthMismatch));
    }
    #[test]
    fn smallvec_try_deserialize_honors_zero_payload_context() {
        let value: SmallVec<[u32; 4]> = SmallVec(smallvec![1, 2, 3]);
        let bytes = to_bytes(&value).expect("encode SmallVec");
        let archived = norito::core::from_bytes::<SmallVec<[u32; 4]>>(&bytes).expect("archive");
        let _payload_ctx = ncore::PayloadCtxGuard::enter_with_len(&[], 0);
        let decoded =
            <SmallVec<[u32; 4]> as DeserializePayload>::try_deserialize(archived).expect("decode");
        assert!(decoded.is_empty());
    }
    #[test]
    fn smallvec_zero_sized_round_trip() {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        struct Zst;

        impl SerializePayload for Zst {
            fn serialize(
                &self,
                _writer: &mut norito::core::Encoder<'_>,
            ) -> Result<(), ncore::Error> {
                Ok(())
            }
        }

        impl<'a> DeserializePayload<'a> for Zst {
            fn deserialize(_: &'a ncore::Archived<Self>) -> Self {
                Self
            }
        }
        impl<'a> ncore::DecodeFromSlice<'a> for Zst {
            fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), ncore::Error> {
                if !bytes.is_empty() {
                    return Err(ncore::Error::LengthMismatch);
                }
                Ok((Self, 0))
            }
        }
        let vec: SmallVec<[Zst; 4]> = SmallVec(smallvec![Zst, Zst, Zst]);
        let bytes = vec.encode();
        let decoded = SmallVec::<[Zst; 4]>::decode(&mut bytes.as_slice()).expect("decode");
        assert_eq!(decoded, vec);
    }
}
mod small_vector {
    use super::*;
    /// Wrapper struct around [`smallvec::SmallVec`] type. Keeps `N` elements on the stack if
    /// `self.len()` is less than `N`, if not, produces a heap-allocated vector.
    ///
    /// To instantiate a vector with `N` stack elements,
    /// ```ignore
    /// use iroha_data_model::small::SmallVec;
    ///
    /// let a: SmallVec<[u8; 24]> = SmallVec(smallvec::smallvec![32]);
    /// ```
    #[repr(transparent)]
    pub struct SmallVec<A: Array>(pub smallvec::SmallVec<A>);
    impl<A: Array> Default for SmallVec<A> {
        fn default() -> Self {
            Self(smallvec::SmallVec::new())
        }
    }
    impl<A: Array> Clone for SmallVec<A>
    where
        A::Item: Clone,
    {
        fn clone(&self) -> Self {
            Self(self.0.clone())
        }
    }
    impl<A: Array> fmt::Debug for SmallVec<A>
    where
        A::Item: fmt::Debug,
    {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_tuple("SmallVec").field(&self.0).finish()
        }
    }
    impl<A: Array> FromIterator<A::Item> for SmallVec<A> {
        fn from_iter<T: IntoIterator<Item = A::Item>>(iter: T) -> Self {
            Self(iter.into_iter().collect())
        }
    }
    #[allow(clippy::unconditional_recursion)] // False-positive
    impl<A: Array> PartialEq for SmallVec<A>
    where
        A::Item: PartialEq,
    {
        fn eq(&self, other: &Self) -> bool {
            self.0.eq(&other.0)
        }
    }
    impl<A: Array> PartialOrd for SmallVec<A>
    where
        A::Item: PartialOrd,
    {
        fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
            self.0.partial_cmp(&other.0)
        }
    }
    impl<A: Array> Ord for SmallVec<A>
    where
        A::Item: Ord,
    {
        fn cmp(&self, other: &Self) -> core::cmp::Ordering {
            self.0.cmp(&other.0)
        }
    }
    impl<A: Array> core::ops::Deref for SmallVec<A> {
        type Target = <smallvec::SmallVec<A> as core::ops::Deref>::Target;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }
    impl<A: Array> core::ops::DerefMut for SmallVec<A> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }
    impl<A: Array> Eq for SmallVec<A> where A::Item: Eq {}
    impl<A: Array> SmallVec<A> {
        /// Construct new empty [`SmallVec`]
        #[inline]
        #[must_use]
        pub fn new() -> Self {
            Self(smallvec::SmallVec::new())
        }
        /// Append an item to the vector.
        #[inline]
        pub fn push(&mut self, value: A::Item) {
            self.0.push(value);
        }
        /// Remove all elements from the vector without altering capacity.
        #[inline]
        pub fn clear(&mut self) {
            self.0.clear();
        }
        /// Remove and return the element at position `index`, shifting all elements after it to the
        /// left.
        ///
        /// Panics if `index` is out of bounds.
        #[inline]
        pub fn remove(&mut self, index: usize) -> A::Item {
            self.0.remove(index)
        }
        /// Convert a [`SmallVec`] to a [`Vec`], without reallocating if the [`SmallVec`]
        /// has already spilled onto the heap.
        #[inline]
        #[must_use]
        pub fn into_vec(self) -> Vec<A::Item> {
            self.0.into_vec()
        }
    }
    impl<A: Array> From<Vec<A::Item>> for SmallVec<A> {
        fn from(vec: Vec<A::Item>) -> Self {
            Self(vec.into_iter().collect())
        }
    }
    impl<A: Array> IntoIterator for SmallVec<A> {
        type Item = <A as smallvec::Array>::Item;
        type IntoIter = <smallvec::SmallVec<A> as IntoIterator>::IntoIter;
        fn into_iter(self) -> Self::IntoIter {
            self.0.into_iter()
        }
    }
    impl<A: smallvec::Array + 'static> TypeId for SmallVec<A>
    where
        A::Item: TypeId,
    {
        #[inline]
        fn id() -> String {
            Vec::<A::Item>::id()
        }
    }
    impl<A: smallvec::Array + 'static> IntoSchema for SmallVec<A>
    where
        A::Item: IntoSchema,
    {
        #[inline]
        fn type_name() -> String {
            Vec::<A::Item>::type_name()
        }
        #[inline]
        fn update_schema_map(map: &mut iroha_schema::MetaMap) {
            if !map.contains_key::<Self>() {
                if !map.contains_key::<Vec<A::Item>>() {
                    Vec::<A::Item>::update_schema_map(map);
                }
                if let Some(schema) = map.get::<Vec<A::Item>>() {
                    map.insert::<Self>(schema.clone());
                }
            }
        }
    }
    impl<A: smallvec::Array> Extend<A::Item> for SmallVec<A> {
        fn extend<T: IntoIterator<Item = A::Item>>(&mut self, iter: T) {
            self.0.extend(iter);
        }
    }
    impl<A: smallvec::Array> FastJsonWrite for SmallVec<A>
    where
        A::Item: JsonSerialize,
    {
        fn write_json(&self, out: &mut String) {
            out.push('[');
            let mut iter = self.0.iter();
            if let Some(first) = iter.next() {
                first.json_serialize(out);
                for item in iter {
                    out.push(',');
                    item.json_serialize(out);
                }
            }
            out.push(']');
        }
        fn write_json_to(
            &self,
            out: &mut dyn json::JsonWriteSink,
        ) -> Result<(), json::BoundedJsonError> {
            out.begin_container()?;
            let result = (|| -> Result<(), json::BoundedJsonError> {
                out.push('[')?;
                for (index, item) in self.0.iter().enumerate() {
                    if index != 0 {
                        out.push(',')?;
                    }
                    item.json_serialize_to(out)?;
                }
                out.push(']')?;
                Ok(())
            })();
            out.end_container();
            result
        }
    }
    impl<A: smallvec::Array> JsonDeserialize for SmallVec<A>
    where
        A::Item: JsonDeserialize,
    {
        fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
            let values = parser.parse_array::<A::Item>()?;
            let mut out = smallvec::SmallVec::<A>::with_capacity(values.len());
            out.extend(values);
            Ok(Self(out))
        }
    }
    impl<A: Array + norito::NoritoSchema> norito::NoritoSchema for SmallVec<A> {
        fn nominal_name() -> String {
            norito::schema::identity::generic_name(
                "iroha_primitives::small::small_vector::SmallVec",
                &[A::nominal_name()],
            )
        }
    }

    impl<A: Array> SerializePayload for SmallVec<A>
    where
        A::Item: SerializePayload,
    {
        fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), ncore::Error> {
            use ncore::WriteBytesExt;
            writer.write_u64::<ncore::LittleEndian>(
                u64::try_from(self.0.len()).map_err(|_| ncore::Error::LengthMismatch)?,
            )?;
            for item in &self.0 {
                ncore::write_fixed_len_prefixed(writer, item)?;
            }
            Ok(())
        }
    }

    impl<'a, A: Array> DeserializePayload<'a> for SmallVec<A>
    where
        A::Item: DeserializePayload<'a> + for<'slice> ncore::DecodeFromSlice<'slice>,
    {
        fn deserialize(archived: &'a ncore::Archived<Self>) -> Self {
            Self::try_deserialize(archived).unwrap_or_else(|err| {
                panic!(
                    "SmallVec<{}> decode failed: {err:?}",
                    core::any::type_name::<A::Item>()
                )
            })
        }
        fn try_deserialize(archived: &'a ncore::Archived<Self>) -> Result<Self, ncore::Error> {
            if let Some((_, len)) = ncore::payload_ctx()
                && len == 0
            {
                return Ok(Self::new());
            }
            let ptr = core::ptr::from_ref(archived).cast::<u8>();
            let ctx_len = ncore::payload_ctx().map(|(_, len)| len);
            let bytes_full = ncore::payload_slice_from_ptr(ptr)?;
            let bytes = ctx_len
                .and_then(|len| bytes_full.get(..len))
                .unwrap_or(bytes_full);
            let (value, _used) = <Self as ncore::DecodeFromSlice>::decode_from_slice(bytes)?;
            Ok(value)
        }
    }
    impl<'a, A: Array> ncore::DecodeFromSlice<'a> for SmallVec<A>
    where
        A::Item: ncore::DecodeFromSlice<'a>,
    {
        fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), ncore::Error> {
            let (len, mut offset) = <u64 as ncore::DecodeFromSlice>::decode_from_slice(bytes)?;
            let len = usize::try_from(len).map_err(|_| ncore::Error::LengthMismatch)?;
            let mut out = smallvec::SmallVec::<A>::with_capacity(len);
            for _ in 0..len {
                let (elem_len, used_len) =
                    <u64 as ncore::DecodeFromSlice>::decode_from_slice(&bytes[offset..])?;
                offset = offset
                    .checked_add(used_len)
                    .ok_or(ncore::Error::LengthMismatch)?;
                let elem_len =
                    usize::try_from(elem_len).map_err(|_| ncore::Error::LengthMismatch)?;
                if elem_len == 0 {
                    if ncore::archived_payload_size::<A::Item>() != 0 {
                        return Err(ncore::Error::LengthMismatch);
                    }
                    let (value, used) =
                        <A::Item as ncore::DecodeFromSlice>::decode_from_slice(&[])?;
                    if used != 0 {
                        return Err(ncore::Error::LengthMismatch);
                    }
                    out.push(value);
                    continue;
                }
                let end = offset
                    .checked_add(elem_len)
                    .ok_or(ncore::Error::LengthMismatch)?;
                let slice = bytes.get(offset..end).ok_or(ncore::Error::LengthMismatch)?;
                let (value, used) = <A::Item as ncore::DecodeFromSlice>::decode_from_slice(slice)?;
                if used != elem_len {
                    return Err(ncore::Error::LengthMismatch);
                }
                out.push(value);
                offset = end;
            }
            Ok((Self(out), offset))
        }
    }
}
