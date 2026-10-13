//! Structures, traits and impls related to versioning.
//!
//! Versioned containers (`SignedTransaction`, `SignedQuery`,
//! ...) implement [`Version`] and the [`codec`] traits by hand; the leading
//! version byte is followed by the exact Norito payload. Blocks have their own
//! canonical framed wire and do not implement these headerless codec traits.
use core::ops::Range;
/// Re-export Norito codec helpers required by consumers of versioned types.
pub use norito::codec::{Decode, DecodeAll, Encode};
use std::{format, vec::Vec};
/// Module which contains error and result for versioning
/// Error types emitted while working with versioned containers.
pub mod error {
    use super::UnsupportedVersion;
    use super::*;
    use iroha_macro::FromVariant;
    use std::{borrow::ToOwned, boxed::Box, fmt};
    /// Versioning errors
    #[derive(Debug, FromVariant, thiserror::Error)]
    pub enum Error {
        /// This is not a versioned object
        NotVersioned,
        /// Original codec error without an inferred local decode provenance.
        NoritoCodec(norito::Error),
        /// Original classified decoder refusal retained across scope retirement.
        NoritoResourceLimit(#[skip_from] norito::core::DecodeAttemptError),
        /// Input version unsupported
        UnsupportedVersion(Box<UnsupportedVersion>),
        /// Buffer is not empty after decoding. Returned by `decode_all_versioned()`
        ExtraBytesLeft(u64),
    }
    impl From<norito::core::DecodeAttemptError> for Error {
        fn from(error: norito::core::DecodeAttemptError) -> Self {
            match error.kind() {
                norito::core::DecodeAttemptErrorKind::Allocator
                | norito::core::DecodeAttemptErrorKind::EnclosingLimit => {
                    Self::NoritoResourceLimit(error)
                }
                norito::core::DecodeAttemptErrorKind::Invalid => {
                    Self::NoritoCodec(error.into_error())
                }
            }
        }
    }
    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let msg = match self {
                Self::NotVersioned => "Not a versioned object".to_owned(),
                Self::NoritoCodec(x) => format!("Norito (de)serialization issue: {x}"),
                Self::NoritoResourceLimit(_) => {
                    "Norito decoding exceeded its resource limit".to_owned()
                }
                Self::UnsupportedVersion(v) => {
                    format!("Input version {} is unsupported", v.version)
                }
                Self::ExtraBytesLeft(n) => format!("Buffer contains {n} bytes after decoding"),
            };
            write!(f, "{msg}")
        }
    }
    impl Error {
        /// Return whether decoding reported an original resource failure or format ceiling.
        #[must_use]
        pub const fn is_decode_resource_limit(&self) -> bool {
            match self {
                Self::NoritoResourceLimit(_) => true,
                Self::NoritoCodec(error) => error.is_decode_resource_limit(),
                _ => false,
            }
        }

        /// Whether the original operation failed locally and may be retried unchanged.
        ///
        /// Only a captured enclosing refusal or an actual allocator failure grants
        /// this classification. Numeric resource fields and later scopes do not.
        #[must_use]
        pub const fn is_local_resource_refusal(&self) -> bool {
            match self {
                Self::NoritoResourceLimit(error) => matches!(
                    error.kind(),
                    norito::core::DecodeAttemptErrorKind::Allocator
                        | norito::core::DecodeAttemptErrorKind::EnclosingLimit
                ),
                Self::NoritoCodec(norito::Error::AllocationFailed { .. }) => true,
                _ => false,
            }
        }
    }
    /// Result type for versioning
    pub type Result<T, E = Error> = core::result::Result<T, E>;
}
/// General trait describing if this is a versioned container.
pub trait Version {
    /// Version of the data contained inside.
    fn version(&self) -> u8;
    /// Supported versions.
    fn supported_versions() -> Range<u8>;
    /// If the contents' version is currently supported.
    fn is_supported(&self) -> bool {
        Self::supported_versions().contains(&self.version())
    }
}
/// Structure describing a container content which version is not supported.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    thiserror::Error,
    norito::Encode,
    norito::Decode,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_version::UnsupportedVersion")]
#[error(
    "Unsupported version. Expected: {}, got: {version}",
    Self::expected_version()
)]
pub struct UnsupportedVersion {
    /// Version of the content.
    pub version: u8,
    /// Raw content.
    pub raw: RawVersioned,
}
impl UnsupportedVersion {
    /// Constructs [`UnsupportedVersion`].
    #[must_use]
    #[inline]
    pub const fn new(version: u8, raw: RawVersioned) -> Self {
        Self { version, raw }
    }
    /// Expected version
    pub const fn expected_version() -> u8 {
        1
    }
}
/// Raw versioned content, serialized.
///
/// Versioned containers are Norito-only; tag 1 is the retained explicit tag of
/// the Norito byte payload.
#[derive(
    Debug, Clone, PartialEq, Eq, norito::codec::Encode, norito::codec::Decode, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_version::RawVersioned")]
pub enum RawVersioned {
    /// In Norito format.
    #[codec(index = 1)]
    NoritoBytes(Vec<u8>),
}
impl<'a> norito::core::DecodeFromSlice<'a> for RawVersioned {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        norito::core::decode_field_canonical::<Self>(bytes)
    }
}
/// Norito related versioned (de)serialization traits.
pub mod codec {
    use super::{Version, error::Result};
    use norito::{
        DeserializePayload,
        codec::{DecodeAll, Encode},
        core::DecodeFromSlice,
    };
    /// [`norito::codec::Decode`] versioned analog.
    pub trait DecodeVersioned: DecodeAll + Version {
        /// Use this function for versioned objects instead of `decode_all`.
        ///
        /// # Errors
        /// - Version is unsupported
        /// - Input won't have enough bytes for decoding
        /// - Input has extra bytes
        fn decode_all_versioned(input: &[u8]) -> Result<Self>;
    }
    /// [`norito::codec::Encode`] versioned analog.
    pub trait EncodeVersioned: Encode + Version {
        /// Use this function for versioned objects instead of `encode`.
        fn encode_versioned(&self) -> Vec<u8>;
    }
    /// Decode a leading-version Norito payload using exact-slice semantics.
    ///
    /// The input must contain the version byte followed by the exact Norito
    /// payload for `T`. This bare decoder requires no frame identity.
    /// Unsupported versions preserve the original bytes in the
    /// returned [`crate::UnsupportedVersion`] payload for diagnostics.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Error::NotVersioned`] when the input is empty,
    /// [`crate::error::Error::UnsupportedVersion`] when the leading byte is not supported by `T`,
    /// or a wrapped Norito decode error when the payload body is malformed.
    pub fn decode_exact_versioned<T>(input: &[u8]) -> Result<T>
    where
        T: Version + for<'de> DeserializePayload<'de> + for<'de> DecodeFromSlice<'de>,
    {
        decode_exact_versioned_with_raw(input, input)
    }
    /// Decode a versioned Norito payload while preserving custom raw bytes for
    /// unsupported-version errors.
    ///
    /// This is used by callers that first deframe an outer transport envelope
    /// but still want unsupported-version diagnostics to point at the original
    /// raw bytes rather than the deframed bare versioned slice.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`decode_exact_versioned`].
    pub fn decode_exact_versioned_with_raw<T>(
        bare_versioned: &[u8],
        raw_for_error: &[u8],
    ) -> Result<T>
    where
        T: Version + for<'de> DeserializePayload<'de> + for<'de> DecodeFromSlice<'de>,
    {
        use crate::{RawVersioned, UnsupportedVersion, error::Error};
        let Some((&version, payload)) = bare_versioned.split_first() else {
            return Err(Error::NotVersioned);
        };
        if !T::supported_versions().contains(&version) {
            return Err(Error::UnsupportedVersion(Box::new(
                UnsupportedVersion::new(version, RawVersioned::NoritoBytes(raw_for_error.to_vec())),
            )));
        }
        norito::core::classify_decode_attempt(|| norito::codec::decode_exact_from_slice(payload))
            .map_err(Error::from)
    }
}
/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{codec::*, *};
}
#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Debug, Clone, PartialEq, Eq, norito::Encode, norito::Decode)]
    #[norito(decode_from_slice)]
    struct ExactPayload(u32);
    impl Version for ExactPayload {
        fn version(&self) -> u8 {
            1
        }
        fn supported_versions() -> Range<u8> {
            1..2
        }
    }
    impl crate::codec::EncodeVersioned for ExactPayload {
        fn encode_versioned(&self) -> Vec<u8> {
            let mut bytes = Vec::with_capacity(1);
            bytes.push(self.version());
            bytes.extend(norito::codec::encode_adaptive(self));
            bytes
        }
    }
    pub struct VersionedContainer(pub u8);
    impl Version for VersionedContainer {
        fn version(&self) -> u8 {
            let VersionedContainer(version) = self;
            *version
        }
        fn supported_versions() -> Range<u8> {
            1..10
        }
    }
    #[test]
    fn supported_version() {
        assert!(!VersionedContainer(0).is_supported());
        assert!(VersionedContainer(1).is_supported());
        assert!(VersionedContainer(5).is_supported());
        assert!(!VersionedContainer(10).is_supported());
        assert!(!VersionedContainer(11).is_supported());
    }
    #[test]
    fn raw_versioned_roundtrip() {
        let original = RawVersioned::NoritoBytes(b"test".to_vec());
        let bytes = original.encode();
        let decoded = RawVersioned::decode_all(&mut &bytes[..]).expect("decode");
        assert_eq!(decoded, original);
    }
    #[test]
    fn unsupported_version_roundtrip() {
        let original = UnsupportedVersion::new(2, RawVersioned::NoritoBytes(b"test".to_vec()));
        let bytes = original.encode();
        let decoded = UnsupportedVersion::decode_all(&mut &bytes[..]).expect("decode");
        assert_eq!(decoded.version, original.version);
        assert_eq!(decoded.encode(), bytes);
    }
    #[test]
    fn decode_exact_versioned_roundtrip() {
        let encoded = crate::codec::EncodeVersioned::encode_versioned(&ExactPayload(42));
        let decoded =
            crate::codec::decode_exact_versioned::<ExactPayload>(&encoded).expect("decode");
        assert_eq!(decoded, ExactPayload(42));
    }
    #[test]
    fn versioned_payload_decoders_reject_truncation_and_trailing_bytes_without_frame_identity() {
        let encoded = crate::codec::EncodeVersioned::encode_versioned(&ExactPayload(42));
        for len in 0..encoded.len() {
            assert!(crate::codec::decode_exact_versioned::<ExactPayload>(&encoded[..len]).is_err());
            assert!(
                crate::codec::decode_exact_versioned_with_raw::<ExactPayload>(
                    &encoded[..len],
                    b"original envelope",
                )
                .is_err()
            );
        }
        let mut trailing = encoded;
        trailing.push(0);
        assert!(crate::codec::decode_exact_versioned::<ExactPayload>(&trailing).is_err());
        assert!(
            crate::codec::decode_exact_versioned_with_raw::<ExactPayload>(
                &trailing,
                b"original envelope",
            )
            .is_err()
        );
    }
    #[test]
    fn decode_exact_versioned_with_raw_preserves_custom_error_bytes() {
        let err = crate::codec::decode_exact_versioned_with_raw::<ExactPayload>(&[9, 0], b"raw")
            .expect_err("unsupported version must fail");
        let crate::error::Error::UnsupportedVersion(version) = err else {
            panic!("unexpected error: {err}");
        };
        assert_eq!(version.version, 9);
        assert_eq!(version.raw, RawVersioned::NoritoBytes(b"raw".to_vec()));
    }
    #[test]
    fn raw_numeric_resource_fields_do_not_create_local_provenance() {
        let error = crate::error::Error::from(norito::Error::TotalAllocationExceeded {
            attempted: 2,
            limit: 1,
        });
        assert!(
            error.is_decode_resource_limit(),
            "the request-bound category survives"
        );
        assert!(!error.is_local_resource_refusal());
        let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 1, 64);
        norito::with_decode_limits_scope(limits, || {
            assert!(
                !error.is_local_resource_refusal(),
                "equal fields grant no origin"
            );
        });
        assert!(matches!(
            error,
            crate::error::Error::NoritoCodec(norito::Error::TotalAllocationExceeded {
                attempted: 2,
                limit: 1
            })
        ));
    }

    #[test]
    fn direct_writer_allocation_failure_keeps_original_without_decoder_provenance() {
        let error = crate::error::Error::from(norito::Error::AllocationFailed { bytes: 17 });
        assert!(error.is_local_resource_refusal());
        assert!(
            matches!(
                error,
                crate::error::Error::NoritoCodec(norito::Error::AllocationFailed { bytes: 17 })
            ),
            "a writer error is never relabelled as a captured decoder attempt"
        );
    }
}

#[cfg(test)]
mod resource_provenance_tests {
    //! Genuine reads preserve the original attempt after its scope retires.
    use super::*;
    use norito::core::{DecodeAttemptErrorKind, DecodeResourceError};

    #[derive(Debug, PartialEq, Eq, norito::Encode, norito::Decode)]
    #[norito(decode_from_slice)]
    struct TextPayload(String);
    impl Version for TextPayload {
        fn version(&self) -> u8 {
            1
        }
        fn supported_versions() -> Range<u8> {
            1..2
        }
    }

    fn allocation_limit(bytes: usize) -> norito::DecodeLimits {
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, 64)
    }

    fn wire() -> (TextPayload, Vec<u8>) {
        let original = TextPayload("original canonical payload".into());
        let mut bytes = vec![1];
        bytes.extend(norito::codec::encode_adaptive(&original));
        (original, bytes)
    }

    #[test]
    fn original_versioned_refusal_survives_retired_equal_foreign_scope_and_retry() {
        let (original, wire) = wire();
        let (measured, usage) =
            norito::core::with_decode_limits_measured(allocation_limit(usize::MAX), || {
                codec::decode_exact_versioned::<TextPayload>(&wire)
            });
        assert_eq!(measured.unwrap(), original);
        assert!(usage.total_allocated_bytes() > 0);
        for limit in [0, usage.total_allocated_bytes() - 1] {
            let wrapped = norito::with_decode_limits_scope(allocation_limit(limit), || {
                codec::decode_exact_versioned::<TextPayload>(&wire).unwrap_err()
            });
            assert!(wrapped.is_local_resource_refusal());
            assert!(wrapped.is_decode_resource_limit());
            let error::Error::NoritoResourceLimit(ref attempt) = wrapped else {
                panic!("original classified attempt was lost: {wrapped:?}")
            };
            assert_eq!(attempt.kind(), DecodeAttemptErrorKind::EnclosingLimit);
            assert!(matches!(attempt.error().decode_resource_error(),
                Some(DecodeResourceError::TotalAllocationExceeded { attempted, limit: original_limit })
                if original_limit == u64::try_from(limit).unwrap() && attempted > original_limit
            ));
            norito::with_decode_limits_scope(allocation_limit(limit), || {
                assert!(wrapped.is_local_resource_refusal());
                assert_eq!(attempt.kind(), DecodeAttemptErrorKind::EnclosingLimit);
            });
            assert_eq!(
                codec::decode_exact_versioned::<TextPayload>(&wire).unwrap(),
                original
            );
        }
        let mut malformed = wire;
        malformed.push(0);
        let error = codec::decode_exact_versioned::<TextPayload>(&malformed).unwrap_err();
        assert!(!error.is_local_resource_refusal());
        assert!(!error.is_decode_resource_limit());
    }

    #[derive(Debug, norito::Encode, norito::Decode)]
    struct IntrinsicallyBoundedText(String);
    impl Version for IntrinsicallyBoundedText {
        fn version(&self) -> u8 {
            1
        }
        fn supported_versions() -> Range<u8> {
            1..2
        }
    }
    impl<'de> norito::core::DecodeFromSlice<'de> for IntrinsicallyBoundedText {
        fn decode_from_slice(bytes: &'de [u8]) -> Result<(Self, usize), norito::Error> {
            norito::with_decode_limits_scope(allocation_limit(0), || {
                <TextPayload as norito::core::DecodeFromSlice>::decode_from_slice(bytes)
                    .map(|(text, used)| (Self(text.0), used))
            })
        }
    }

    #[test]
    fn production_version_reader_preserves_intrinsic_schema_bound_as_invalid() {
        let (_, wire) = wire();
        for limit in [0, 4096] {
            let error = norito::with_decode_limits_scope(allocation_limit(limit), || {
                codec::decode_exact_versioned::<IntrinsicallyBoundedText>(&wire).unwrap_err()
            });
            assert!(error.is_decode_resource_limit());
            assert!(!error.is_local_resource_refusal());
            let error::Error::NoritoCodec(original) = error else {
                panic!("intrinsic schema failure must remain deterministic: {error:?}");
            };
            assert!(
                matches!(
                    original.decode_resource_error(),
                    Some(DecodeResourceError::TotalAllocationExceeded { limit: 0, .. })
                ),
                "original scoped codec error retained: {original:?}"
            );
        }
    }

    #[test]
    fn actual_intrinsic_decoder_ceiling_cannot_become_a_local_refusal() {
        let (_, wire) = wire();
        // This is an intrinsic bound inside the observer, not its enclosing caller.
        let attempt = norito::core::classify_decode_attempt(|| {
            norito::codec::decode_exact_from_slice_with_limits::<TextPayload>(
                &wire[1..],
                allocation_limit(0),
            )
        })
        .unwrap_err();
        assert_eq!(attempt.kind(), DecodeAttemptErrorKind::Invalid);
        let wrapped = error::Error::NoritoResourceLimit(attempt);
        assert!(wrapped.is_decode_resource_limit());
        assert!(!wrapped.is_local_resource_refusal());
        for limit in [0, 4096] {
            norito::with_decode_limits_scope(allocation_limit(limit), || {
                assert!(!wrapped.is_local_resource_refusal());
            });
        }
    }
}
