//! Verifying keys, proving keys and key generation (task T10).
//!
//! - [`vk`]: [`VerifyingKey`], the vendored `0x02` byte layout with a strict
//!   reader that decodes against the circuit descriptor, and the
//!   descriptor-bound `transcript_repr`;
//! - [`pk`]: [`ProvingKey`], which owns the fixed and permutation
//!   polynomials, the masks, the exact quotient cosets
//!   ([`pk::QuotientDomain`]), the fixed-coset cache and optional
//!   commitment-key tables;
//! - [`keygen`]: deterministic key generation from a circuit or from explicit
//!   assignment tables, with the permutation cycles built exactly as halo2
//!   builds them.
//!
//! [`DescriptorBinding`] is a validated descriptor together with its canonical
//! frame and digest: the only way keys refer to a descriptor, so a key can
//! never be bound to an unvalidated one.

use core::fmt;

use iroha_pasta::{fft::FftError, msm::MsmError};

use crate::{
    cs::{
        CircuitDescriptorV1, CircuitDescriptorV2, CsError, DescriptorError, PermutationError,
        ProtocolDescriptor, descriptor_digest,
    },
    frontend,
};

pub mod keygen;
pub mod pk;
mod source_fingerprint;
#[cfg(test)]
mod tests;
pub mod vk;

pub use keygen::{
    KeygenConfig, KeygenConfigV2, RebuildError, SourceAdmissionSealV2, SourceBoundVerifyingKeyV2,
    SourceBoundViewV2, keygen_from_tables, keygen_from_tables_v2, keygen_pk, keygen_pk_from_vk_v2,
    keygen_pk_from_vk_v2_cancellable, keygen_pk_v2, keygen_pk_v2_cancellable, keygen_vk,
    keygen_vk_v2, keygen_vk_with_binding_v2, keygen_vk_with_binding_v2_cancellable,
    permutation_values, source_fingerprint_v2,
};
pub use pk::{
    CosetCachePolicy, CosetMasks, CosetPolynomial, KeyConstraintSystem, ProvingKey, QuotientDomain,
};
pub use source_fingerprint::SourceFingerprintV2;
pub use vk::{VK_VERSION, VerifyingKey, VkError};

/// A validated descriptor, its canonical Norito frame `D` and
/// `descriptor_digest = BLAKE2b(32, "PIPA-v1-CircDesc", D)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DescriptorBinding {
    descriptor: ProtocolDescriptor,
    encoded: Vec<u8>,
    digest: [u8; 32],
}

impl DescriptorBinding {
    /// Validates and encodes `descriptor`.
    ///
    /// # Errors
    ///
    /// [`DescriptorError`] when a validation rule fails or encoding fails.
    pub fn new(descriptor: CircuitDescriptorV1) -> Result<Self, DescriptorError> {
        descriptor.validate()?;
        let encoded = descriptor.encode()?;
        let digest = descriptor_digest(&encoded);
        Ok(Self {
            descriptor: descriptor.into(),
            encoded,
            digest,
        })
    }

    /// Admission-decodes a canonical descriptor frame.
    ///
    /// # Errors
    ///
    /// [`DescriptorError`] naming the failed rule.
    pub fn decode(bytes: &[u8]) -> Result<Self, DescriptorError> {
        let descriptor = CircuitDescriptorV1::decode(bytes)?;
        Ok(Self {
            descriptor: descriptor.into(),
            encoded: bytes.to_vec(),
            digest: descriptor_digest(bytes),
        })
    }

    /// Validates and binds an explicit V2 descriptor.
    ///
    /// # Errors
    /// An arithmetic, instance-type or transcript-profile rule fails.
    pub fn new_v2(descriptor: CircuitDescriptorV2) -> Result<Self, DescriptorError> {
        descriptor.validate()?;
        let encoded = descriptor.encode()?;
        let digest = crate::cs::descriptor_v2::descriptor_digest_v2(&encoded);
        Ok(Self {
            descriptor: descriptor.into(),
            encoded,
            digest,
        })
    }

    /// Admits V2 only; it never attempts V1 decoding.
    ///
    /// # Errors
    /// The bytes are not exactly one valid canonical V2 descriptor.
    pub fn decode_v2(bytes: &[u8]) -> Result<Self, DescriptorError> {
        Self::new_v2(CircuitDescriptorV2::decode(bytes)?)
    }

    /// Whether this binding is from the explicit V2 schema.
    #[must_use]
    pub fn is_v2(&self) -> bool {
        self.descriptor.instance_types.is_some()
    }

    /// The descriptor.
    #[must_use]
    pub fn descriptor(&self) -> &ProtocolDescriptor {
        &self.descriptor
    }

    /// The canonical frame `D`.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// `descriptor_digest`.
    #[must_use]
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// The domain size `n = 2^k` (validated, so it fits `usize`).
    #[must_use]
    pub fn n(&self) -> usize {
        1_usize << self.descriptor.k
    }
}

/// Key generation or proving-key construction failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// The caller cancelled key arithmetic before completion.
    Cancelled,
    /// The circuit failed to configure or synthesize.
    Synthesis(frontend::Error),
    /// The constraint system is unusable.
    ConstraintSystem(CsError),
    /// The descriptor could not be built or validated.
    Descriptor(DescriptorError),
    /// A copy constraint could not be recorded.
    Permutation(PermutationError),
    /// An input table has the wrong shape.
    Shape {
        /// What has the wrong length.
        what: &'static str,
        /// The required length.
        expected: usize,
        /// The supplied length.
        actual: usize,
    },
    /// The parameters' curve is unknown.
    UnknownCurve,
    /// The circuit degree does not admit exact quotient cosets.
    UnsupportedDegree {
        /// The degree.
        degree: usize,
    },
    /// An FFT failed.
    Fft(FftError),
    /// An MSM failed (budget or size).
    Msm(MsmError),
    /// The verifying-key parts were rejected.
    VerifyingKey(VkError),
    /// A key commitment is the identity (probability negligible).
    IdentityCommitment {
        /// The index in VK encoding order (fixed, then permutation).
        index: usize,
    },
    /// A coset-cache request named a missing polynomial or coset.
    CosetIndex,
    /// A key-generation table touches a row at or beyond the usable rows: a
    /// copy, an enabled selector or a nonzero fixed value.
    UnusableRow {
        /// `"copy"`, `"selector"` or `"fixed"`.
        what: &'static str,
        /// The equality position, selector or fixed column.
        column: usize,
        /// The row.
        row: usize,
    },
}

impl KeyError {
    /// Whether this failure is cooperative cancellation, never an invalid proof.
    pub fn is_cancelled(&self) -> bool {
        match self {
            Self::Cancelled | Self::ConstraintSystem(CsError::Cancelled) => true,
            Self::Descriptor(error) => error.is_cancelled(),
            Self::VerifyingKey(error) => error.is_cancelled(),
            Self::Synthesis(error) => matches!(error, frontend::Error::Cancelled),
            Self::Msm(error) => matches!(error, MsmError::Cancelled),
            Self::Fft(error) => matches!(error, FftError::Cancelled),
            _ => false,
        }
    }
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => f.write_str("operation cancelled"),
            Self::Synthesis(error) => write!(f, "synthesis: {error}"),
            Self::ConstraintSystem(error) => write!(f, "constraint system: {error}"),
            Self::Descriptor(error) => write!(f, "descriptor: {error}"),
            Self::Permutation(error) => write!(f, "permutation: {error}"),
            Self::Shape {
                what,
                expected,
                actual,
            } => write!(f, "{what}: {actual} supplied, {expected} expected"),
            Self::UnknownCurve => f.write_str("unknown curve"),
            Self::UnsupportedDegree { degree } => {
                write!(f, "degree {degree} admits no exact quotient cosets")
            }
            Self::Fft(error) => write!(f, "FFT: {error}"),
            Self::Msm(error) => write!(f, "MSM: {error}"),
            Self::VerifyingKey(error) => write!(f, "verifying key: {error}"),
            Self::IdentityCommitment { index } => {
                write!(f, "key commitment {index} is the identity")
            }
            Self::CosetIndex => f.write_str("no such coset polynomial"),
            Self::UnusableRow { what, column, row } => {
                write!(f, "{what} column {column} touches unusable row {row}")
            }
        }
    }
}

impl std::error::Error for KeyError {}
impl From<iroha_pasta::Cancelled> for KeyError {
    fn from(_: iroha_pasta::Cancelled) -> Self {
        Self::Cancelled
    }
}

impl From<frontend::Error> for KeyError {
    fn from(error: frontend::Error) -> Self {
        if matches!(error, frontend::Error::Cancelled) {
            Self::Cancelled
        } else {
            Self::Synthesis(error)
        }
    }
}

impl From<CsError> for KeyError {
    fn from(error: CsError) -> Self {
        if matches!(error, CsError::Cancelled) {
            Self::Cancelled
        } else {
            Self::ConstraintSystem(error)
        }
    }
}

impl From<DescriptorError> for KeyError {
    fn from(error: DescriptorError) -> Self {
        if error.is_cancelled() {
            Self::Cancelled
        } else {
            Self::Descriptor(error)
        }
    }
}

impl From<PermutationError> for KeyError {
    fn from(error: PermutationError) -> Self {
        Self::Permutation(error)
    }
}

impl From<VkError> for KeyError {
    fn from(error: VkError) -> Self {
        match error {
            VkError::Cancelled => Self::Cancelled,
            VkError::Point {
                index,
                error: crate::transcript::TranscriptError::IdentityPoint,
            } => Self::IdentityCommitment { index },
            other => Self::VerifyingKey(other),
        }
    }
}

impl From<FftError> for KeyError {
    fn from(error: FftError) -> Self {
        if matches!(error, FftError::Cancelled) {
            Self::Cancelled
        } else {
            Self::Fft(error)
        }
    }
}

impl From<MsmError> for KeyError {
    fn from(error: MsmError) -> Self {
        if matches!(error, MsmError::Cancelled) {
            Self::Cancelled
        } else {
            Self::Msm(error)
        }
    }
}

/// Checks a length.
pub(crate) fn check_shape(
    what: &'static str,
    expected: usize,
    actual: usize,
) -> Result<(), KeyError> {
    if expected == actual {
        Ok(())
    } else {
        Err(KeyError::Shape {
            what,
            expected,
            actual,
        })
    }
}

#[cfg(test)]
mod error_tests {
    use super::*;
    use crate::cs::DescriptorRule;

    #[test]
    fn errors_convert_and_display() {
        assert_eq!(
            check_shape("rows", 4, 3),
            Err(KeyError::Shape {
                what: "rows",
                expected: 4,
                actual: 3
            })
        );
        assert_eq!(check_shape("rows", 4, 4), Ok(()));
        let error = KeyError::from(DescriptorError::Invalid(DescriptorRule::Degree));
        assert!(error.to_string().contains("Degree"));
        assert_eq!(
            KeyError::from(VkError::Point {
                index: 3,
                error: crate::transcript::TranscriptError::IdentityPoint
            }),
            KeyError::IdentityCommitment { index: 3 }
        );
        assert_eq!(
            KeyError::from(VkError::Shape),
            KeyError::VerifyingKey(VkError::Shape)
        );
        assert!(
            KeyError::UnsupportedDegree { degree: 2 }
                .to_string()
                .contains('2')
        );
    }

    #[test]
    fn binding_rejects_non_canonical_frames() {
        assert!(DescriptorBinding::decode(&[0, 1, 2]).is_err());
    }
}
