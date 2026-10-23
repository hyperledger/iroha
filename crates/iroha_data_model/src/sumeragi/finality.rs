//! Native finality transport: the original canonical block frame, without projected authority.
//!
//! Decoding authenticates the source layout only. Consumers must verify signed genesis and
//! the consecutive native header/result/quorum graph against independent chain configuration.
//! Genesis has no CommitQC; its execution result needs independent execution or a successor.

use crate::block::{SignedBlock, decode_framed_signed_block};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

/// Maximum one-block source accepted by the public native finality transport.
pub const NATIVE_FINALITY_MAX_BLOCK_BYTES: usize =
    crate::block::proofs::AUTHENTICATED_BLOCK_PROOFS_MAX_BLOCK_WIRE_BYTES_V1;
/// Maximum complete journal source admitted by the first-release offline verifier.
pub const NATIVE_FINALITY_MAX_JOURNAL_BYTES: usize = 64 * 1024 * 1024;
/// Maximum number of consecutive source frames in one bounded journal.
pub const NATIVE_FINALITY_MAX_BLOCK_COUNT: usize = 65_536;

mod prepared_source;
pub use prepared_source::{
    NativeFinalityChargedFrame, NativeFinalityFrame, NativeFinalityFrames, NativeFinalitySource,
    PreparedNativeFinalityDestinationError, PreparedNativeFinalityError,
    PreparedNativeFinalityJournal,
};

/// Explicit caller-owned admission bounds. There is no implicit unbounded/default mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeFinalityLimits {
    /// Maximum canonical wire bytes per block.
    pub block_bytes: usize,
    /// Maximum aggregate canonical wire bytes across the complete journal.
    pub journal_bytes: usize,
    /// Maximum consecutive block count, including signed genesis.
    pub block_count: usize,
    /// Maximum cumulative decoded allocation bytes for one whole journal operation.
    pub allocated_bytes: usize,
}
impl NativeFinalityLimits {
    /// Reject zero, contradictory or above-protocol source bounds before processing input.
    ///
    /// # Errors
    /// Rejects zero, contradictory or above-protocol source limits and a zero allocation limit.
    pub fn validate(self) -> Result<(), String> {
        if self.block_bytes == 0
            || self.block_bytes > NATIVE_FINALITY_MAX_BLOCK_BYTES
            || self.journal_bytes < self.block_bytes
            || self.journal_bytes > NATIVE_FINALITY_MAX_JOURNAL_BYTES
            || self.block_count == 0
            || self.block_count > NATIVE_FINALITY_MAX_BLOCK_COUNT
            || self.allocated_bytes == 0
        {
            return Err("native finality limits are invalid".into());
        }
        Ok(())
    }

    /// Norito allocation accounting for an entire journal operation, not a fresh per-block pool.
    ///
    /// # Errors
    /// Rejects limits that fail [`Self::validate`].
    pub fn decode_limits(self) -> Result<norito::DecodeLimits, String> {
        self.validate()?;
        Ok(norito::DecodeLimits::new(
            self.block_bytes,
            self.block_bytes,
            self.journal_bytes,
            self.allocated_bytes,
            128,
        ))
    }
}

/// One original canonical `SignedBlockWire`, including its native certificate and result.
///
/// This is untrusted transport data, never an authority capability. H1 is signed genesis;
/// ordinary heights carry native `CommitQCs`. No other finality layout is accepted.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sumeragi::finality::NativeFinalityArtifact")]
#[norito(deny_unknown_fields, decode_fields)]
pub struct NativeFinalityArtifact {
    /// The only source body. JSON transports the same bytes as base64.
    #[norito(
        with = "crate::json_helpers::base64_vec",
        bounded_with = "crate::json_helpers::base64_vec::serialize_bounded"
    )]
    pub block_wire: Vec<u8>,
}
/// Canonical artifact construction failure, preserving local resource refusals.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NativeFinalityArtifactError {
    /// Invalid caller limits or malformed canonical source serialization.
    #[error("native finality artifact: {0}")]
    Invalid(String),
    /// The caller's original byte/allocation allowance or physical allocator refused.
    #[error("native finality artifact resource: {0}")]
    Resource(norito::core::DecodeResourceError),
}

impl NativeFinalityArtifactError {
    fn codec(error: &norito::Error) -> Self {
        error
            .decode_resource_error()
            .map_or_else(|| Self::Invalid(error.to_string()), Self::Resource)
    }
}

/// Native finality source decoding, retaining the original caller resource cause.
#[derive(Debug, thiserror::Error)]
pub enum NativeFinalityDecodeError {
    /// A source or configured protocol bound is invalid.
    #[error("native finality: {0}")]
    Invalid(String),
    /// The frame fails intrinsic canonical decoding.
    #[error("native finality frame is invalid")]
    Malformed(#[source] norito::core::DecodeAttemptError),
    /// The caller's original decoder allowance or allocator refused.
    #[error("native finality decoder is unavailable")]
    Resource(#[source] norito::core::DecodeAttemptError),
}
impl From<String> for NativeFinalityDecodeError {
    fn from(value: String) -> Self {
        Self::Invalid(value)
    }
}
impl From<&str> for NativeFinalityDecodeError {
    fn from(value: &str) -> Self {
        Self::Invalid(value.into())
    }
}
impl From<norito::core::DecodeAttemptError> for NativeFinalityDecodeError {
    fn from(value: norito::core::DecodeAttemptError) -> Self {
        match value.kind() {
            norito::core::DecodeAttemptErrorKind::Invalid => Self::Malformed(value),
            norito::core::DecodeAttemptErrorKind::Allocator
            | norito::core::DecodeAttemptErrorKind::EnclosingLimit => Self::Resource(value),
        }
    }
}

/// Borrow one native source under operation bounds and the sole canonical block decoder.
///
/// # Errors
/// Retains malformed-frame and original local decoder-refusal causes separately.
pub fn decode_native_finality_block(
    wire: &[u8],
    limits: NativeFinalityLimits,
) -> Result<SignedBlock, NativeFinalityDecodeError> {
    limits.validate()?;
    if wire.is_empty() || wire.len() > limits.block_bytes {
        return Err("native block frame exceeds its configured source bound".into());
    }
    norito::core::with_decode_limits_scope(limits.decode_limits()?, || {
        decode_framed_signed_block(wire).map_err(Into::into)
    })
}

impl NativeFinalityArtifact {
    /// Encode a block only after counting its exact canonical size against the supplied cap.
    /// This is an offchain transport allocation, not production execution-pool admission.
    ///
    /// # Errors
    /// Rejects invalid limits, canonical encoding or size failures, and source allocation refusal.
    pub fn from_block(
        block: &SignedBlock,
        limits: NativeFinalityLimits,
    ) -> Result<Self, NativeFinalityArtifactError> {
        limits
            .validate()
            .map_err(NativeFinalityArtifactError::Invalid)?;
        let len = {
            let _flags =
                norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
            norito::core::encoded_payload_len(block)
                .map_err(|error| NativeFinalityArtifactError::codec(&error))?
                .checked_add(1 + norito::core::Header::SIZE)
                .ok_or_else(|| {
                    NativeFinalityArtifactError::Invalid(
                        "native block frame length overflow".into(),
                    )
                })?
        };
        if len > limits.block_bytes {
            return Err(NativeFinalityArtifactError::Resource(
                norito::core::DecodeResourceError::ArchiveLengthExceeded {
                    length: len as u64,
                    limit: limits.block_bytes as u64,
                },
            ));
        }
        norito::core::with_decode_limits_scope(
            limits
                .decode_limits()
                .map_err(NativeFinalityArtifactError::Invalid)?,
            || {
                norito::core::reserve_decode_allocation(len)
                    .map_err(|error| NativeFinalityArtifactError::codec(&error))?;
                let mut block_wire = Vec::new();
                block_wire.try_reserve_exact(len).map_err(|_| {
                    NativeFinalityArtifactError::Resource(
                        norito::core::DecodeResourceError::AllocationFailed { bytes: len as u64 },
                    )
                })?;
                block_wire.resize(len, 0);
                block_wire[0] = crate::block::SignedBlock::WIRE_VERSION;
                let mut writer = std::io::Cursor::new(&mut block_wire[1..]);
                norito::core::write_canonical_to_writer(block, &mut writer)
                    .map_err(|error| NativeFinalityArtifactError::codec(&error))?;
                if writer.position()
                    != u64::try_from(len - 1).map_err(|_| {
                        NativeFinalityArtifactError::Invalid("native frame length overflow".into())
                    })?
                {
                    return Err(NativeFinalityArtifactError::Invalid(
                        "native block canonical length changed during streaming".into(),
                    ));
                }
                Ok(Self { block_wire })
            },
        )
    }

    /// Decode one canonical source under explicit allocation limits.
    ///
    /// An outer journal scope remains charged cumulatively: Norito nested limits compose;
    /// this per-frame scope cannot reset or raise its outer budget. Exact source length is
    /// checked before the canonical decoder allocates.
    ///
    /// # Errors
    /// Rejects invalid limits, empty or oversized sources, noncanonical encoding, or exhausted
    /// aggregate decoding and allocation limits.
    pub fn decode_block(
        &self,
        limits: NativeFinalityLimits,
    ) -> Result<SignedBlock, NativeFinalityDecodeError> {
        decode_native_finality_block(&self.block_wire, limits)
    }
}

/// A complete native source prefix, beginning with the independently pinned signed genesis.
/// There is no arbitrary start-height field: a truncated suffix is not a trust root.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sumeragi::finality::NativeFinalityJournal")]
#[norito(deny_unknown_fields, decode_fields)]
pub struct NativeFinalityJournal {
    /// Exact canonical source frames in ascending one-based height order.
    pub blocks: Vec<NativeFinalityArtifact>,
}
impl NativeFinalityJournal {
    /// Check aggregate source lengths and count before any block decode.
    ///
    /// # Errors
    /// Rejects invalid limits, empty or excessive block counts, invalid frame sizes, or an
    /// overflowing or excessive aggregate source length.
    pub fn validate_source(&self, limits: NativeFinalityLimits) -> Result<(), String> {
        NativeFinalitySource::from(self).validate(limits)
    }

    /// Decode a canonical journal archive within the supplied aggregate byte/allocation caps.
    ///
    /// # Errors
    /// Rejects invalid limits, empty or excessive archive bytes, noncanonical decoding,
    /// allocation refusal, or a journal whose source sizes fail validation.
    pub fn decode(
        bytes: &[u8],
        limits: NativeFinalityLimits,
    ) -> Result<Self, NativeFinalityDecodeError> {
        limits.validate()?;
        if bytes.is_empty() || bytes.len() > limits.journal_bytes {
            return Err("native journal archive exceeds its configured byte bound".into());
        }
        let journal: Self =
            norito::core::with_decode_limits_scope(limits.decode_limits()?, || {
                norito::decode_canonical_for_admission(
                    bytes,
                    norito::canonical_decode_limits(bytes.len()),
                )
            })?;
        journal.validate_source(limits)?;
        Ok(journal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{BlockHeader, builder::BlockBuilder};
    use std::num::NonZeroU64;

    fn limits() -> NativeFinalityLimits {
        NativeFinalityLimits {
            block_bytes: 65536,
            journal_bytes: 131_072,
            block_count: 4,
            allocated_bytes: 1024 * 1024,
        }
    }
    fn source() -> SignedBlock {
        // Codec-only fixture: this unsigned body is not a finality or authority proof.
        BlockBuilder::new(BlockHeader::new(
            NonZeroU64::new(2).unwrap(),
            None,
            None,
            2,
            0,
        ))
        .build(crate::block::BlockSignatures::default())
    }
    #[test]
    fn codec_error_keeps_resource_refusal_distinct_from_malformed_source() {
        let resource = norito::core::DecodeResourceError::AllocationFailed { bytes: 123 };
        assert_eq!(
            NativeFinalityArtifactError::codec(&norito::Error::from(resource)),
            NativeFinalityArtifactError::Resource(resource)
        );
        assert_eq!(
            NativeFinalityArtifactError::codec(&norito::Error::InvalidMagic),
            NativeFinalityArtifactError::Invalid("invalid magic header".into())
        );
    }

    #[test]
    fn exact_native_source_roundtrips_binary_and_json() {
        let artifact = NativeFinalityArtifact::from_block(&source(), limits()).unwrap();
        assert_eq!(artifact.block_wire, source().encode_wire().unwrap());
        let decoded =
            norito::core::with_decode_limits_scope(limits().decode_limits().unwrap(), || {
                artifact.decode_block(limits())
            })
            .unwrap();
        assert_eq!(decoded, source());
        let bytes = norito::encode_canonical(&artifact).unwrap();
        assert_eq!(
            norito::decode_canonical::<NativeFinalityArtifact>(&bytes).unwrap(),
            artifact
        );
        let json = norito::json::to_json(&artifact).unwrap();
        assert_eq!(
            norito::json::from_str::<NativeFinalityArtifact>(&json).unwrap(),
            artifact
        );
    }
    #[test]
    fn artifact_allocation_refusal_remains_typed_and_retries_original_source() {
        let block = source();
        let original = block.encode_wire().unwrap();
        let denied = NativeFinalityLimits {
            allocated_bytes: original.len() - 1,
            ..limits()
        };
        assert_eq!(
            NativeFinalityArtifact::from_block(&block, denied),
            Err(NativeFinalityArtifactError::Resource(
                norito::core::DecodeResourceError::TotalAllocationExceeded {
                    attempted: original.len() as u64,
                    limit: denied.allocated_bytes as u64,
                }
            ),)
        );
        let admitted = NativeFinalityLimits {
            allocated_bytes: original.len(),
            ..limits()
        };
        assert_eq!(
            NativeFinalityArtifact::from_block(&block, admitted)
                .unwrap()
                .block_wire,
            original
        );
        assert!(matches!(
            NativeFinalityArtifact::from_block(
                &block,
                NativeFinalityLimits {
                    block_bytes: 0,
                    ..limits()
                }
            ),
            Err(NativeFinalityArtifactError::Invalid(_))
        ));
    }

    #[test]
    fn bounds_and_noncanonical_source_fail_closed() {
        let artifact = NativeFinalityArtifact::from_block(&source(), limits()).unwrap();
        let tiny = NativeFinalityLimits {
            block_bytes: artifact.block_wire.len() - 1,
            ..limits()
        };
        assert!(NativeFinalityArtifact::from_block(&source(), tiny).is_err());
        assert!(artifact.decode_block(tiny).is_err());
        let mut changed = artifact.clone();
        changed.block_wire.push(0);
        assert!(changed.decode_block(limits()).is_err());
        let mut changed = artifact;
        changed.block_wire.remove(1); // No headerless/guessed-layout fallback.
        assert!(changed.decode_block(limits()).is_err());
        assert!(
            NativeFinalityLimits {
                allocated_bytes: 0,
                ..limits()
            }
            .validate()
            .is_err()
        );
        assert!(
            NativeFinalityLimits {
                block_count: 0,
                ..limits()
            }
            .decode_limits()
            .is_err()
        );
        assert!(
            NativeFinalityLimits {
                block_bytes: NATIVE_FINALITY_MAX_BLOCK_BYTES + 1,
                ..limits()
            }
            .validate()
            .is_err()
        );
    }
    #[test]
    fn journal_archive_and_cumulative_source_bounds_are_exact() {
        let artifact = NativeFinalityArtifact::from_block(&source(), limits()).unwrap();
        let journal = NativeFinalityJournal {
            blocks: vec![artifact.clone(), artifact],
        };
        journal.validate_source(limits()).unwrap();
        let bytes = norito::encode_canonical(&journal).unwrap();
        assert_eq!(
            NativeFinalityJournal::decode(&bytes, limits()).unwrap(),
            journal
        );
        assert!(
            journal
                .validate_source(NativeFinalityLimits {
                    block_count: 1,
                    ..limits()
                })
                .is_err()
        );
        assert!(
            NativeFinalityJournal { blocks: Vec::new() }
                .validate_source(limits())
                .is_err()
        );
        assert!(
            NativeFinalityJournal::decode(
                &bytes,
                NativeFinalityLimits {
                    allocated_bytes: 1,
                    ..limits()
                }
            )
            .is_err()
        );
        let mut trailing = bytes;
        trailing.push(0);
        assert!(NativeFinalityJournal::decode(&trailing, limits()).is_err());
    }

    #[test]
    fn native_finality_decoders_preserve_original_scope_refusal_and_exact_retry() {
        // The empty codec-only block is now decoded directly without heap storage.
        // Exercise real refusal using a nonempty signature owner, not a retired scratch copy.
        let empty = NativeFinalityArtifact::from_block(&source(), limits()).unwrap();
        let header = source().header();
        let key =
            iroha_crypto::KeyPair::from_seed(vec![0x51; 32], iroha_crypto::Algorithm::Ed25519);
        let signature = crate::block::BlockSignature::new(
            0,
            iroha_crypto::SignatureOf::try_from_hash(key.private_key(), header.hash()).unwrap(),
        );
        let expected = SignedBlock::presigned(signature, header, Vec::new());
        let artifact = NativeFinalityArtifact::from_block(&expected, limits()).unwrap();
        let journal = NativeFinalityJournal {
            blocks: vec![artifact.clone()],
        };
        let bytes = norito::encode_canonical(&journal).unwrap();
        let no_allocation =
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
        assert_eq!(
            norito::core::with_decode_limits_scope(no_allocation, || empty.decode_block(limits()))
                .unwrap(),
            source(),
        );
        let errors = [
            norito::core::with_decode_limits_scope(no_allocation, || {
                artifact.decode_block(limits())
            })
            .unwrap_err(),
            norito::core::with_decode_limits_scope(no_allocation, || {
                NativeFinalityJournal::decode(&bytes, limits())
            })
            .unwrap_err(),
        ];
        for error in errors {
            let NativeFinalityDecodeError::Resource(original) = error else {
                panic!("{error:?}");
            };
            assert_eq!(
                original.kind(),
                norito::core::DecodeAttemptErrorKind::EnclosingLimit
            );
            assert!(matches!(
                original.into_error().decode_resource_error(),
                Some(norito::core::DecodeResourceError::TotalAllocationExceeded { limit: 0, .. })
            ));
        }
        assert_eq!(artifact.decode_block(limits()).unwrap(), expected);
        assert_eq!(
            NativeFinalityJournal::decode(&bytes, limits()).unwrap(),
            journal
        );
        let mut changed = artifact;
        changed.block_wire[0] = 99;
        assert!(
            matches!(changed.decode_block(limits()), Err(NativeFinalityDecodeError::Malformed(e)) if e.kind() == norito::core::DecodeAttemptErrorKind::Invalid)
        );
        let mut trailing = bytes;
        trailing.push(0);
        assert!(
            matches!(NativeFinalityJournal::decode(&trailing, limits()), Err(NativeFinalityDecodeError::Malformed(e)) if e.kind() == norito::core::DecodeAttemptErrorKind::Invalid)
        );
    }
}
