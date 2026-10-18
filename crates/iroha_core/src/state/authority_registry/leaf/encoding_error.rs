//! Fixed rejection custody at the canonical leaf's codec/hash boundaries.
//!
//! No adapter boxes an upstream error or renders an owned diagnostic. This does
//! not fund allocations performed inside an arbitrary caller-supplied serializer;
//! closed native capture must separately qualify its concrete codecs.

use super::LeafError;
use std::io;

/// Exact operation which failed before a retained leaf could be returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum EncodingOperation {
    /// First canonical pass determining exact bytes and length.
    #[error("measure canonical payload")]
    MeasurePayload,
    /// Second canonical pass into the admitted frame owner.
    #[error("write admitted canonical frame")]
    WriteFrame,
    /// Second canonical pass shared by paired value commitments.
    #[error("hash paired canonical value")]
    HashPairedValue,
    /// Direct typed leaf payload commitment.
    #[error("hash typed canonical payload")]
    HashTypedPayload,
}

/// Bounded failure information; formatting occurs only at a caller boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum EncodingReason {
    /// The concrete serializer rejected its input.
    #[error("canonical serializer rejected the input")]
    Codec,
    /// A concrete serializer rejected a statically named semantic value.
    #[error("invalid canonical {0}")]
    InvalidValue(&'static str),
    /// A writer or reader failed, retaining its local I/O category.
    #[error("canonical I/O failure: {0:?}")]
    Io(io::ErrorKind),
    /// A nested codec reported a physical allocation failure, never semantic invalidity.
    #[error("canonical codec could not allocate {bytes} bytes")]
    Allocation {
        /// Original requested byte count reported by the codec.
        bytes: u64,
    },
    /// A serializer violated its own exact child-length contract.
    #[error("canonical codec length mismatch")]
    CodecLength,
    /// Second-pass output differs in length or exceeds its original bound.
    #[error("canonical table payload changed length between bounded passes")]
    ChangedLength,
    /// Equal-length second-pass output differs in bytes.
    #[error("canonical table payload changed between bounded passes")]
    ChangedPayload,
}

/// Copy-sized operation/reason pair with no retained diagnostic allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{operation}: {reason}")]
pub(crate) struct EncodingError {
    operation: EncodingOperation,
    reason: EncodingReason,
}

impl EncodingError {
    /// Whether the original codec or I/O owner reported physical allocation failure.
    pub(in crate::state) const fn is_allocation_refusal(&self) -> bool {
        matches!(
            self.reason,
            EncodingReason::Allocation { .. } | EncodingReason::Io(io::ErrorKind::OutOfMemory)
        )
    }

    /// Exact codec-reported bytes, without inventing a demand for generic I/O failure.
    pub(in crate::state) const fn allocation_bytes(&self) -> Option<u64> {
        match self.reason {
            EncodingReason::Allocation { bytes } => Some(bytes),
            _ => None,
        }
    }

    pub(super) fn new(operation: EncodingOperation, reason: EncodingReason) -> Self {
        Self { operation, reason }
    }

    pub(super) fn codec(operation: EncodingOperation, error: norito::Error) -> Self {
        let reason = match error {
            norito::Error::Io(error) => EncodingReason::Io(error.kind()),
            norito::Error::AllocationFailed { bytes } => EncodingReason::Allocation { bytes },
            norito::Error::LengthMismatch => EncodingReason::CodecLength,
            norito::Error::InvalidValue { context } => EncodingReason::InvalidValue(context),
            // Detailed owned codec diagnostics are unnecessary for a failed
            // scoped leaf. Drop the original owner without copying/rendering it.
            _ => EncodingReason::Codec,
        };
        Self::new(operation, reason)
    }

    pub(super) fn io(operation: EncodingOperation, error: io::Error) -> Self {
        Self::new(operation, EncodingReason::Io(error.kind()))
    }
}

impl From<EncodingError> for LeafError {
    fn from(error: EncodingError) -> Self {
        Self::Encoding(error)
    }
}

#[cfg(test)]
mod capture_tests {
    use super::*;
    use crate::state::{
        authority_registry::{FrozenMusubiError, leaf::RetainedSemanticError},
        publication::capture_deferral::materialization_refusal,
        storage_transactions::TransactionsBlockError,
    };

    #[test]
    fn codec_allocation_is_local_but_canonical_shape_failure_requires_recovery() {
        for (input, allocation, bytes) in [
            (
                norito::Error::AllocationFailed { bytes: 8193 },
                true,
                Some(8193),
            ),
            (
                norito::Error::Io(io::ErrorKind::OutOfMemory.into()),
                true,
                None,
            ),
            (norito::Error::LengthMismatch, false, None),
            (
                norito::Error::Io(io::ErrorKind::InvalidData.into()),
                false,
                None,
            ),
        ] {
            let original = EncodingError::codec(EncodingOperation::HashPairedValue, input);
            assert_eq!(original.is_allocation_refusal(), allocation);
            assert_eq!(original.allocation_bytes(), bytes);
            let display = original.to_string();
            let classified = materialization_refusal(FrozenMusubiError::Encoding(
                RetainedSemanticError::Table(LeafError::Encoding(original)),
            ));
            if allocation {
                let TransactionsBlockError::CaptureDeferred(owner) = classified else {
                    panic!("a failed codec allocation cannot become invalid State");
                };
                assert_eq!(owner.codec_allocation_bytes(), bytes);
                assert!(owner.allocation_refusal().is_none());
                assert!(owner.release_wait().is_none());
                assert!(owner.to_string().contains(&display));
            } else {
                assert!(matches!(
                    classified,
                    TransactionsBlockError::SnapshotObservationChanged
                ));
            }
        }
    }
}
