//! Iroha `VeRange` Type-1 profile over P-256.
//!
//! This is a clean-room implementation of the Type-1 equations in Figure 1 of
//! ePrint 2025/528.  The first release intentionally closes the parameter space
//! to `N = 32, J = K = 6` and `N = 64, J = K = 8`.  It proves an existing
//! Pedersen commitment `C = G·value + Q·blinding` opens to a value in
//! `[0, 2^N)`.
use super::p256::{
    CanonicalScalarV1, CompressedPointV1, P256EngineError, SecretScalarV1, TranscriptBindingV1,
    TranscriptV1, generator_digest, hash_to_curve_rfc9380, health_checked_p256_rng_v1,
    random_nonzero_scalar, validate_generator_independence,
};
use once_cell::sync::Lazy;
use p256::{ProjectivePoint, Scalar, elliptic_curve::Field};
use rand_core_06::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use thiserror::Error;
/// Closed suite identifier committed by every `VeRange` transcript.
pub const VERANGE_TYPE1_SUITE_V1: &[u8] = b"iroha.verange.type1.p256.sha256.v1";
/// Proof wire version.
pub const VERANGE_TYPE1_PROOF_VERSION_V1: u8 = 1;
/// Primary-source profile implemented by this engine.
pub const VERANGE_TYPE1_SOURCE_PROFILE_V1: &[u8] = b"eprint:2025/528:figure-1:type-1";
/// Tight decoder bound for the closed Type-1 matrices.
///
/// The largest admitted proof (`N=64`, `J=K=8`) contains 18 points and 66
/// scalars; 16 KiB leaves ample Norito framing headroom while preventing an
/// attacker from reaching the broader 8 MiB action limit through this engine.
pub const MAX_VERANGE_TYPE1_PROOF_BYTES_V1: usize = 16 * 1024;
/// Initial maximum count of independently proven commitments in one batch.
pub const MAX_VERANGE_TYPE1_BATCH_COMMITMENTS_V1: usize = 8;
/// Tight decoder bound for an eight-proof independent Type-1 batch.
pub const MAX_VERANGE_TYPE1_BATCH_PROOF_BYTES_V1: usize =
    MAX_VERANGE_TYPE1_PROOF_BYTES_V1 * MAX_VERANGE_TYPE1_BATCH_COMMITMENTS_V1 + 4096;
const VERANGE_G_DST_V1: &[u8] = b"IROHA-VERANGE-V1-G-P256_XMD:SHA-256_SSWU_RO_";
const VERANGE_Q_DST_V1: &[u8] = b"IROHA-VERANGE-V1-Q-P256_XMD:SHA-256_SSWU_RO_";
const VERANGE_H_DST_V1: &[u8] = b"IROHA-VERANGE-V1-H-P256_XMD:SHA-256_SSWU_RO_";
const PARAMETER_DIGEST_DOMAIN_V1: &[u8] = b"iroha.verange.type1.parameters.v1";
const BATCH_COMMITMENT_DIGEST_DOMAIN_V1: &[u8] = b"iroha.verange.type1.batch-commitments.v1";
const MAX_PROVER_RESTARTS: usize = 128;
const MAX_VERANGE_TYPE1_SEQUENCE_ELEMENTS_V1: usize = 64;
const MAX_VERANGE_TYPE1_TOTAL_ELEMENTS_V1: usize = 8 + 8 + 64;
const MAX_VERANGE_TYPE1_BATCH_TOTAL_ELEMENTS_V1: usize =
    MAX_VERANGE_TYPE1_BATCH_COMMITMENTS_V1 * (1 + MAX_VERANGE_TYPE1_TOTAL_ELEMENTS_V1);
fn verange_proof_decode_limits(payload_len: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(
        MAX_VERANGE_TYPE1_SEQUENCE_ELEMENTS_V1,
        payload_len,
        MAX_VERANGE_TYPE1_TOTAL_ELEMENTS_V1,
        MAX_VERANGE_TYPE1_PROOF_BYTES_V1.saturating_mul(4),
        16,
    )
}
fn verange_batch_decode_limits(payload_len: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(
        MAX_VERANGE_TYPE1_SEQUENCE_ELEMENTS_V1,
        payload_len,
        MAX_VERANGE_TYPE1_BATCH_TOTAL_ELEMENTS_V1,
        MAX_VERANGE_TYPE1_BATCH_PROOF_BYTES_V1.saturating_mul(4),
        24,
    )
}
/// Admitted `VeRange` bit widths and their exact matrix geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VeRangeBitLengthV1 {
    /// `N = 32`, `J = K = 6`.
    Bits32,
    /// `N = 64`, `J = K = 8`.
    Bits64,
}
/// Deterministic descriptor frozen into governed `VeRange` activation material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VeRangeProfileDescriptorV1 {
    /// Exact suite bytes absorbed by Fiat--Shamir transcripts.
    pub suite: &'static [u8],
    /// Exact proof wire version.
    pub proof_version: u8,
    /// Primary-source relation/profile bytes.
    pub source_profile: &'static [u8],
    /// Closed bit length `N`.
    pub bit_length: u16,
    /// Matrix row count `J`.
    pub rows: u16,
    /// Matrix column count `K`.
    pub columns: u16,
    /// Digest of the complete closed parameter profile.
    pub parameter_digest: [u8; 32],
    /// Digest of the exact RFC 9380 generator basis.
    pub generator_digest: [u8; 32],
    /// Tight maximum canonical bytes for one child proof.
    pub max_single_proof_bytes: u32,
    /// Initial maximum independent batch count.
    pub max_batch_commitments: u32,
    /// Tight maximum canonical bytes for an independent batch.
    pub max_batch_proof_bytes: u32,
}
impl VeRangeBitLengthV1 {
    /// Return `N`.
    #[must_use]
    pub const fn bits(self) -> u16 {
        match self {
            Self::Bits32 => 32,
            Self::Bits64 => 64,
        }
    }
    /// Return `J`.
    #[must_use]
    pub const fn rows(self) -> usize {
        match self {
            Self::Bits32 => 6,
            Self::Bits64 => 8,
        }
    }
    /// Return `K`.
    #[must_use]
    pub const fn columns(self) -> usize {
        self.rows()
    }
    fn from_bits(bits: u16) -> Result<Self, VeRangeError> {
        match bits {
            32 => Ok(Self::Bits32),
            64 => Ok(Self::Bits64),
            _ => Err(VeRangeError::UnsupportedBitLength { bits }),
        }
    }
    fn value_is_admitted(self, value: u64) -> bool {
        match self {
            Self::Bits32 => value < (1_u64 << 32),
            Self::Bits64 => true,
        }
    }
}
/// Deterministic transparent parameter basis for one `VeRange` profile.
#[derive(Clone)]
pub struct VeRangeParametersV1 {
    profile: VeRangeBitLengthV1,
    g: ProjectivePoint,
    q: ProjectivePoint,
    h: Vec<ProjectivePoint>,
    generator_digest: [u8; 32],
    parameter_digest: [u8; 32],
}
impl VeRangeParametersV1 {
    /// Return cached parameters for a closed first-release profile.
    ///
    /// # Errors
    ///
    /// Returns an error only if RFC 9380 derivation fails or the independently
    /// derived basis contains an equality/inverse collision.
    pub fn for_profile(profile: VeRangeBitLengthV1) -> Result<&'static Self, VeRangeError> {
        let parameter_set = VERANGE_PARAMETER_SET.as_ref().map_err(Clone::clone)?;
        Ok(match profile {
            VeRangeBitLengthV1::Bits32 => &parameter_set.bits_32,
            VeRangeBitLengthV1::Bits64 => &parameter_set.bits_64,
        })
    }
    /// Return the profile.
    #[must_use]
    pub const fn profile(&self) -> VeRangeBitLengthV1 {
        self.profile
    }
    /// Return the canonical generator-basis digest.
    #[must_use]
    pub const fn generator_digest(&self) -> [u8; 32] {
        self.generator_digest
    }
    /// Return the canonical closed-profile digest.
    #[must_use]
    pub const fn parameter_digest(&self) -> [u8; 32] {
        self.parameter_digest
    }
    #[cfg(any(test, feature = "test-utils"))]
    /// Return `G` as canonical compressed SEC1.
    #[must_use]
    pub fn value_generator(&self) -> CompressedPointV1 {
        CompressedPointV1::from_projective(self.g)
            .expect("derived VeRange value generator is non-identity")
    }
    /// Return `Q` as canonical compressed SEC1.
    #[must_use]
    pub fn blinding_generator(&self) -> CompressedPointV1 {
        CompressedPointV1::from_projective(self.q)
            .expect("derived VeRange blinding generator is non-identity")
    }
    #[cfg(test)]
    /// Return the `H_j` basis as canonical compressed SEC1.
    #[must_use]
    pub fn row_generators(&self) -> Vec<CompressedPointV1> {
        self.h
            .iter()
            .copied()
            .map(|point| {
                CompressedPointV1::from_projective(point)
                    .expect("derived VeRange row generator is non-identity")
            })
            .collect()
    }
    /// Return every deterministic input needed to govern this compiled profile.
    #[must_use]
    pub fn descriptor(&self) -> VeRangeProfileDescriptorV1 {
        VeRangeProfileDescriptorV1 {
            suite: VERANGE_TYPE1_SUITE_V1,
            proof_version: VERANGE_TYPE1_PROOF_VERSION_V1,
            source_profile: VERANGE_TYPE1_SOURCE_PROFILE_V1,
            bit_length: self.profile.bits(),
            rows: u16::try_from(self.profile.rows()).expect("VeRange row count fits u16"),
            columns: u16::try_from(self.profile.columns()).expect("VeRange column count fits u16"),
            parameter_digest: self.parameter_digest,
            generator_digest: self.generator_digest,
            max_single_proof_bytes: u32::try_from(MAX_VERANGE_TYPE1_PROOF_BYTES_V1)
                .expect("single proof cap fits u32"),
            max_batch_commitments: u32::try_from(MAX_VERANGE_TYPE1_BATCH_COMMITMENTS_V1)
                .expect("batch count fits u32"),
            max_batch_proof_bytes: u32::try_from(MAX_VERANGE_TYPE1_BATCH_PROOF_BYTES_V1)
                .expect("batch proof cap fits u32"),
        }
    }
    fn derive_subprofile(profile: VeRangeBitLengthV1) -> Result<Self, VeRangeError> {
        let profile_bytes = profile.bits().to_be_bytes();
        let g = hash_to_curve_rfc9380(VERANGE_G_DST_V1, &profile_bytes)?;
        let q = hash_to_curve_rfc9380(VERANGE_Q_DST_V1, &profile_bytes)?;
        let mut h = Vec::with_capacity(profile.rows());
        for row in 0..profile.rows() {
            let row = u32::try_from(row).expect("VeRange row count fits u32");
            let mut message = [0_u8; 6];
            message[..2].copy_from_slice(&profile_bytes);
            message[2..].copy_from_slice(&row.to_be_bytes());
            h.push(hash_to_curve_rfc9380(VERANGE_H_DST_V1, &message)?);
        }
        let mut encoded = Vec::with_capacity(2 + h.len());
        encoded.push(CompressedPointV1::from_projective(g)?);
        encoded.push(CompressedPointV1::from_projective(q)?);
        for point in &h {
            encoded.push(CompressedPointV1::from_projective(*point)?);
        }
        validate_generator_independence(&encoded)?;
        let generator_digest = generator_digest(VERANGE_TYPE1_SUITE_V1, &encoded)?;
        Ok(Self {
            profile,
            g,
            q,
            h,
            generator_digest,
            parameter_digest: [0; 32],
        })
    }
}
struct VeRangeParameterSetV1 {
    bits_32: VeRangeParametersV1,
    bits_64: VeRangeParametersV1,
}
impl VeRangeParameterSetV1 {
    fn derive() -> Result<Self, VeRangeError> {
        let mut bits_32 = VeRangeParametersV1::derive_subprofile(VeRangeBitLengthV1::Bits32)?;
        let mut bits_64 = VeRangeParametersV1::derive_subprofile(VeRangeBitLengthV1::Bits64)?;
        let mut parameter_hash = Sha256::new();
        parameter_hash.update(PARAMETER_DIGEST_DOMAIN_V1);
        parameter_hash.update(
            u16::try_from(VERANGE_TYPE1_SOURCE_PROFILE_V1.len())
                .expect("source profile label is bounded")
                .to_be_bytes(),
        );
        parameter_hash.update(VERANGE_TYPE1_SOURCE_PROFILE_V1);
        parameter_hash.update(
            u16::try_from(VERANGE_TYPE1_SUITE_V1.len())
                .expect("suite label is bounded")
                .to_be_bytes(),
        );
        parameter_hash.update(VERANGE_TYPE1_SUITE_V1);
        parameter_hash.update([VERANGE_TYPE1_PROOF_VERSION_V1]);
        parameter_hash.update(2_u16.to_be_bytes());
        for parameters in [&bits_32, &bits_64] {
            parameter_hash.update(parameters.profile.bits().to_be_bytes());
            parameter_hash.update(
                u16::try_from(parameters.profile.rows())
                    .expect("VeRange row count fits u16")
                    .to_be_bytes(),
            );
            parameter_hash.update(
                u16::try_from(parameters.profile.columns())
                    .expect("VeRange column count fits u16")
                    .to_be_bytes(),
            );
            parameter_hash.update(parameters.generator_digest);
        }
        let parameter_digest = parameter_hash.finalize().into();
        bits_32.parameter_digest = parameter_digest;
        bits_64.parameter_digest = parameter_digest;
        Ok(Self { bits_32, bits_64 })
    }
}
static VERANGE_PARAMETER_SET: Lazy<Result<VeRangeParameterSetV1, VeRangeError>> =
    Lazy::new(VeRangeParameterSetV1::derive);
/// Fully bound public input to one `VeRange` Type-1 proof.
#[derive(Clone, Copy, Debug)]
pub struct VeRangeType1StatementV1<'a> {
    profile: VeRangeBitLengthV1,
    commitment: CompressedPointV1,
    transcript_binding: TranscriptBindingV1<'a>,
    batch_index: u32,
    batch_count: u32,
    batch_commitment_digest: [u8; 32],
}
impl<'a> VeRangeType1StatementV1<'a> {
    /// Construct and validate a statement.
    ///
    /// The caller must pass the digest of the full typed ledger statement in
    /// `transcript_binding.statement_digest`.  The governed parameter and
    /// generator digests must exactly match this closed engine profile.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid commitment or mismatched transcript binding.
    pub fn new(
        profile: VeRangeBitLengthV1,
        commitment: CompressedPointV1,
        transcript_binding: TranscriptBindingV1<'a>,
    ) -> Result<Self, VeRangeError> {
        let _ = commitment.to_projective()?;
        let parameters = VeRangeParametersV1::for_profile(profile)?;
        if transcript_binding.parameter_digest != parameters.parameter_digest {
            return Err(VeRangeError::ParameterDigestMismatch);
        }
        if transcript_binding.generator_digest != parameters.generator_digest {
            return Err(VeRangeError::GeneratorDigestMismatch);
        }
        transcript_binding.validate()?;
        let batch_commitment_digest = ordered_commitment_digest(&[commitment]);
        Ok(Self {
            profile,
            commitment,
            transcript_binding,
            batch_index: 0,
            batch_count: 1,
            batch_commitment_digest,
        })
    }
    /// Return the selected profile.
    #[must_use]
    pub const fn profile(&self) -> VeRangeBitLengthV1 {
        self.profile
    }
    /// Return the externally supplied Pedersen commitment.
    #[must_use]
    pub const fn commitment(&self) -> CompressedPointV1 {
        self.commitment
    }
    fn for_batch(
        profile: VeRangeBitLengthV1,
        commitment: CompressedPointV1,
        transcript_binding: TranscriptBindingV1<'a>,
        batch_index: u32,
        batch_count: u32,
        batch_commitment_digest: [u8; 32],
    ) -> Self {
        Self {
            profile,
            commitment,
            transcript_binding,
            batch_index,
            batch_count,
            batch_commitment_digest,
        }
    }
}
/// Ordered public input to an independently transcript-separated Type-1 batch.
#[derive(Clone, Debug)]
pub struct VeRangeType1BatchStatementV1<'a> {
    profile: VeRangeBitLengthV1,
    commitments: Vec<CompressedPointV1>,
    transcript_binding: TranscriptBindingV1<'a>,
    commitment_digest: [u8; 32],
}
impl<'a> VeRangeType1BatchStatementV1<'a> {
    /// Construct a batch for one to eight ordered, distinct commitments.
    ///
    /// Every child proof binds the full ordered commitment digest, its exact
    /// position, and the batch count.  Proofs therefore cannot be reordered or
    /// transplanted even though this conservative wrapper uses independent Figure-1 challenges
    /// instead of the paper's separate aggregation protocol.
    ///
    /// # Errors
    ///
    /// Returns an error for a count outside `1..=8`, duplicate/invalid
    /// commitments, or mismatched governed parameters.
    pub fn new(
        profile: VeRangeBitLengthV1,
        commitments: Vec<CompressedPointV1>,
        transcript_binding: TranscriptBindingV1<'a>,
    ) -> Result<Self, VeRangeError> {
        if commitments.is_empty() || commitments.len() > MAX_VERANGE_TYPE1_BATCH_COMMITMENTS_V1 {
            return Err(VeRangeError::InvalidBatchCount {
                count: commitments.len(),
                max: MAX_VERANGE_TYPE1_BATCH_COMMITMENTS_V1,
            });
        }
        let parameters = VeRangeParametersV1::for_profile(profile)?;
        if transcript_binding.parameter_digest != parameters.parameter_digest {
            return Err(VeRangeError::ParameterDigestMismatch);
        }
        if transcript_binding.generator_digest != parameters.generator_digest {
            return Err(VeRangeError::GeneratorDigestMismatch);
        }
        transcript_binding.validate()?;
        for (index, commitment) in commitments.iter().copied().enumerate() {
            let _ = commitment.to_projective()?;
            if commitments[..index].contains(&commitment) {
                return Err(VeRangeError::DuplicateBatchCommitment { index });
            }
        }
        let commitment_digest = ordered_commitment_digest(&commitments);
        Ok(Self {
            profile,
            commitments,
            transcript_binding,
            commitment_digest,
        })
    }
    /// Return the ordered commitments.
    #[must_use]
    pub fn commitments(&self) -> &[CompressedPointV1] {
        &self.commitments
    }
    /// Return the exact batch count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.commitments.len()
    }
    /// Return whether this batch is empty.
    ///
    /// A constructed batch is never empty; this method exists to accompany [`Self::len`].
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.commitments.is_empty()
    }
    fn child(&self, index: usize) -> VeRangeType1StatementV1<'a> {
        VeRangeType1StatementV1::for_batch(
            self.profile,
            self.commitments[index],
            self.transcript_binding,
            u32::try_from(index).expect("batch index fits u32"),
            u32::try_from(self.commitments.len()).expect("batch count fits u32"),
            self.commitment_digest,
        )
    }
}
/// Canonical opaque payload for a `VeRange` Type-1 proof.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::privacy_engines::verange::VeRangeType1ProofV1")]
#[derive(
    Clone, Debug, PartialEq, Eq, norito::derive::NoritoSerialize, norito::derive::NoritoDeserialize,
)]
#[norito(decode_from_slice)]
pub struct VeRangeType1ProofV1 {
    version: u8,
    bit_length: u16,
    w_commitments: Vec<CompressedPointV1>,
    t_commitments: Vec<CompressedPointV1>,
    r_commitment: CompressedPointV1,
    s_commitment: CompressedPointV1,
    responses: Vec<CanonicalScalarV1>,
    eta_1: CanonicalScalarV1,
    eta_2: CanonicalScalarV1,
}
impl VeRangeType1ProofV1 {
    /// Encode this closed proof as canonical Norito bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        norito::codec::encode_adaptive(self)
    }
    /// Decode exactly one canonical Norito proof.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, truncated, trailing, malformed,
    /// non-canonical, wrong-version, or wrong-shape encodings.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, VeRangeError> {
        if bytes.len() > MAX_VERANGE_TYPE1_PROOF_BYTES_V1 {
            return Err(P256EngineError::ProofTooLarge {
                actual: bytes.len(),
                max: MAX_VERANGE_TYPE1_PROOF_BYTES_V1,
            }
            .into());
        }
        let proof = norito::codec::decode_exact_from_slice_with_limits::<Self>(
            bytes,
            verange_proof_decode_limits(bytes.len()),
        )
        .map_err(|_| P256EngineError::InvalidProofEncoding)?;
        if proof.encode().as_slice() != bytes {
            return Err(P256EngineError::InvalidProofEncoding.into());
        }
        proof.validate_wire()?;
        Ok(proof)
    }
    /// Return the encoded bit length.
    #[must_use]
    pub const fn bit_length(&self) -> u16 {
        self.bit_length
    }
    fn profile(&self) -> Result<VeRangeBitLengthV1, VeRangeError> {
        VeRangeBitLengthV1::from_bits(self.bit_length)
    }
    fn validate_wire(&self) -> Result<(), VeRangeError> {
        if self.version != VERANGE_TYPE1_PROOF_VERSION_V1 {
            return Err(VeRangeError::UnsupportedProofVersion {
                version: self.version,
            });
        }
        let profile = self.profile()?;
        let columns = profile.columns();
        let response_count = profile
            .rows()
            .checked_mul(columns)
            .expect("closed VeRange dimensions fit usize");
        if self.w_commitments.len() != columns
            || self.t_commitments.len() != columns
            || self.responses.len() != response_count
        {
            return Err(VeRangeError::InvalidProofShape {
                expected_columns: columns,
                actual_w: self.w_commitments.len(),
                actual_t: self.t_commitments.len(),
                expected_responses: response_count,
                actual_responses: self.responses.len(),
            });
        }
        for point in self
            .w_commitments
            .iter()
            .chain(&self.t_commitments)
            .chain([&self.r_commitment, &self.s_commitment])
        {
            let _ = point.to_projective()?;
        }
        for scalar in self.responses.iter().chain([&self.eta_1, &self.eta_2]) {
            let _ = scalar.to_scalar()?;
        }
        Ok(())
    }
}
/// Canonical ordered wrapper of independent Type-1 proofs.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::privacy_engines::verange::VeRangeType1BatchProofV1")]
#[derive(
    Clone, Debug, PartialEq, Eq, norito::derive::NoritoSerialize, norito::derive::NoritoDeserialize,
)]
#[norito(decode_from_slice)]
pub struct VeRangeType1BatchProofV1 {
    version: u8,
    bit_length: u16,
    proofs: Vec<VeRangeType1ProofV1>,
}
impl VeRangeType1BatchProofV1 {
    /// Encode this ordered batch as canonical Norito.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        norito::codec::encode_adaptive(self)
    }
    /// Decode exactly one bounded canonical batch.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, truncated, trailing, malformed,
    /// unknown-version, mixed-profile, empty, or over-cap encodings.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, VeRangeError> {
        if bytes.len() > MAX_VERANGE_TYPE1_BATCH_PROOF_BYTES_V1 {
            return Err(P256EngineError::ProofTooLarge {
                actual: bytes.len(),
                max: MAX_VERANGE_TYPE1_BATCH_PROOF_BYTES_V1,
            }
            .into());
        }
        let proof = norito::codec::decode_exact_from_slice_with_limits::<Self>(
            bytes,
            verange_batch_decode_limits(bytes.len()),
        )
        .map_err(|_| P256EngineError::InvalidProofEncoding)?;
        if proof.encode().as_slice() != bytes {
            return Err(P256EngineError::InvalidProofEncoding.into());
        }
        proof.validate_wire()?;
        Ok(proof)
    }
    /// Return the number of child proofs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.proofs.len()
    }
    /// Return whether no child proof is present.
    ///
    /// A decoded or constructed batch is never empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.proofs.is_empty()
    }
    fn validate_wire(&self) -> Result<(), VeRangeError> {
        if self.version != VERANGE_TYPE1_PROOF_VERSION_V1 {
            return Err(VeRangeError::UnsupportedProofVersion {
                version: self.version,
            });
        }
        let profile = VeRangeBitLengthV1::from_bits(self.bit_length)?;
        if self.proofs.is_empty() || self.proofs.len() > MAX_VERANGE_TYPE1_BATCH_COMMITMENTS_V1 {
            return Err(VeRangeError::InvalidBatchCount {
                count: self.proofs.len(),
                max: MAX_VERANGE_TYPE1_BATCH_COMMITMENTS_V1,
            });
        }
        for proof in &self.proofs {
            proof.validate_wire()?;
            if proof.profile()? != profile {
                return Err(VeRangeError::ProfileMismatch);
            }
        }
        Ok(())
    }
}
/// `VeRange` proof construction or verification failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum VeRangeError {
    /// Shared P-256 substrate failure.
    #[error(transparent)]
    P256(#[from] P256EngineError),
    /// A proof selected a bit length outside the first-release profile.
    #[error("unsupported VeRange Type-1 bit length {bits}; expected 32 or 64")]
    UnsupportedBitLength {
        /// Supplied bit length.
        bits: u16,
    },
    /// A proof wire version is unknown.
    #[error("unsupported VeRange Type-1 proof version {version}")]
    UnsupportedProofVersion {
        /// Supplied version.
        version: u8,
    },
    /// Proof vector dimensions did not match the closed profile.
    #[error(
        "invalid VeRange proof shape: W {actual_w}/{expected_columns}, T {actual_t}/{expected_columns}, responses {actual_responses}/{expected_responses}"
    )]
    InvalidProofShape {
        /// Expected number of `W_k` and `T_k` points.
        expected_columns: usize,
        /// Supplied `W_k` count.
        actual_w: usize,
        /// Supplied `T_k` count.
        actual_t: usize,
        /// Expected `v_jk` response count.
        expected_responses: usize,
        /// Supplied response count.
        actual_responses: usize,
    },
    /// A 32-bit proof witness exceeded its range.
    #[error("witness value {value} is outside the selected {bits}-bit range")]
    WitnessOutOfRange {
        /// Supplied witness.
        value: u64,
        /// Selected bit width.
        bits: u16,
    },
    /// The supplied witness did not open the external commitment.
    #[error("VeRange witness does not open the externally supplied commitment")]
    CommitmentOpeningMismatch,
    /// The statement selected a different closed proof profile.
    #[error("VeRange proof bit length does not match the statement")]
    ProfileMismatch,
    /// The governed parameter digest did not match the closed engine profile.
    #[error("VeRange governed parameter digest mismatch")]
    ParameterDigestMismatch,
    /// The generator digest did not match the RFC 9380 basis.
    #[error("VeRange generator digest mismatch")]
    GeneratorDigestMismatch,
    /// A batch count was zero or exceeded the first-release cap.
    #[error("VeRange Type-1 batch count {count} is outside 1..={max}")]
    InvalidBatchCount {
        /// Supplied count.
        count: usize,
        /// First-release maximum.
        max: usize,
    },
    /// The ordered statement repeated a commitment.
    #[error("VeRange Type-1 batch commitment at index {index} is duplicated")]
    DuplicateBatchCommitment {
        /// Index of the second occurrence.
        index: usize,
    },
    /// Witness and proof vectors did not exactly match the statement count.
    #[error(
        "VeRange Type-1 batch length mismatch: statements {statements}, values {values}, blindings {blindings}, proofs {proofs}"
    )]
    BatchLengthMismatch {
        /// Statement commitment count.
        statements: usize,
        /// Witness value count.
        values: usize,
        /// Witness blinding count.
        blindings: usize,
        /// Proof count, or zero during proving.
        proofs: usize,
    },
    /// The range-membership equation failed.
    #[error("VeRange Type-1 range-membership equation failed")]
    RangeEquationFailed,
    /// The response-to-column-commitment equation failed.
    #[error("VeRange Type-1 response-binding equation failed")]
    ResponseEquationFailed,
    /// The external commitment was not the product of `W_k`.
    #[error("VeRange Type-1 external commitment equation failed")]
    ExternalCommitmentEquationFailed,
    /// Prover randomness repeatedly produced a prohibited zero/identity intermediate.
    #[error("VeRange prover exhausted its fixed restart bound")]
    ProverRestartExhausted,
    /// A locally produced proof failed the independent public verifier.
    #[error("VeRange prover self-check failed")]
    ProverSelfCheckFailed,
}
/// Commit to a value under the exact generator basis for `profile`.
///
/// # Errors
///
/// Returns an error if parameter derivation fails or the result is the identity.
pub fn commit(
    profile: VeRangeBitLengthV1,
    value: u64,
    blinding: &SecretScalarV1,
) -> Result<CompressedPointV1, VeRangeError> {
    if !profile.value_is_admitted(value) {
        return Err(VeRangeError::WitnessOutOfRange {
            value,
            bits: profile.bits(),
        });
    }
    let parameters = VeRangeParametersV1::for_profile(profile)?;
    let point = parameters.g * Scalar::from(value) + parameters.q * blinding.expose_scalar();
    Ok(CompressedPointV1::from_projective(point)?)
}
/// Create a non-interactive `VeRange` Type-1 proof.
///
/// All masks are sampled independently and uniformly from non-zero canonical
/// P-256 scalars.  The one constrained `r_W[K-1]` value is rejected and the
/// proof restarted if it is zero.
///
/// # Errors
///
/// Returns an error for a false statement, invalid binding, exhausted entropy,
/// or a negligibly probable identity intermediate.
pub fn prove<R>(
    statement: &VeRangeType1StatementV1<'_>,
    value: u64,
    blinding: &SecretScalarV1,
    rng: &mut R,
) -> Result<VeRangeType1ProofV1, VeRangeError>
where
    R: CryptoRng + RngCore,
{
    validate_prover_witness(statement, value, blinding)?;
    let mut checked_rng = health_checked_p256_rng_v1(rng)?;
    prove_validated(statement, value, blinding, &mut checked_rng)
}
fn validate_prover_witness(
    statement: &VeRangeType1StatementV1<'_>,
    value: u64,
    blinding: &SecretScalarV1,
) -> Result<(), VeRangeError> {
    if !statement.profile.value_is_admitted(value) {
        return Err(VeRangeError::WitnessOutOfRange {
            value,
            bits: statement.profile.bits(),
        });
    }
    if commit(statement.profile, value, blinding)? != statement.commitment {
        return Err(VeRangeError::CommitmentOpeningMismatch);
    }
    Ok(())
}
fn prove_validated<R>(
    statement: &VeRangeType1StatementV1<'_>,
    value: u64,
    blinding: &SecretScalarV1,
    rng: &mut R,
) -> Result<VeRangeType1ProofV1, VeRangeError>
where
    R: CryptoRng + RngCore,
{
    let parameters = VeRangeParametersV1::for_profile(statement.profile)?;
    for _ in 0..MAX_PROVER_RESTARTS {
        match prove_once(statement, value, blinding, rng, parameters) {
            Ok(proof) => {
                verify(statement, &proof).map_err(|_| VeRangeError::ProverSelfCheckFailed)?;
                return Ok(proof);
            }
            Err(VeRangeError::P256(
                P256EngineError::IdentityPoint | P256EngineError::ZeroScalar,
            )) => continue,
            Err(error) => return Err(error),
        }
    }
    Err(VeRangeError::ProverRestartExhausted)
}
fn prove_once<R>(
    statement: &VeRangeType1StatementV1<'_>,
    value: u64,
    blinding: &SecretScalarV1,
    rng: &mut R,
    parameters: &VeRangeParametersV1,
) -> Result<VeRangeType1ProofV1, VeRangeError>
where
    R: CryptoRng + RngCore,
{
    let rows = statement.profile.rows();
    let columns = statement.profile.columns();
    let matrix_len = rows * columns;
    let mut weights = Vec::with_capacity(matrix_len);
    for row in 0..rows {
        for column in 0..columns {
            let bit_index = column * rows + row;
            let weight = if bit_index < usize::from(statement.profile.bits())
                && ((value >> bit_index) & 1) == 1
            {
                scalar_power_of_two(bit_index)
            } else {
                Scalar::ZERO
            };
            weights.push(weight);
        }
    }
    let mut r_jk = Vec::with_capacity(matrix_len);
    for _ in 0..matrix_len {
        r_jk.push(random_nonzero_scalar(rng)?);
    }
    let mut r_w = Vec::with_capacity(columns);
    let mut r_w_sum = Scalar::ZERO;
    for _ in 0..columns - 1 {
        let mask = random_nonzero_scalar(rng)?;
        r_w_sum += mask;
        r_w.push(mask);
    }
    let last_r_w = blinding.expose_scalar() - r_w_sum;
    if bool::from(last_r_w.is_zero()) {
        return Err(P256EngineError::ZeroScalar.into());
    }
    r_w.push(last_r_w);
    let mut r_t = Vec::with_capacity(columns);
    for _ in 0..columns {
        r_t.push(random_nonzero_scalar(rng)?);
    }
    let r_r = random_nonzero_scalar(rng)?;
    let r_s = random_nonzero_scalar(rng)?;
    let mut w_commitments = Vec::with_capacity(columns);
    let mut t_commitments = Vec::with_capacity(columns);
    for column in 0..columns {
        let mut column_weight = Scalar::ZERO;
        let mut t_point = ProjectivePoint::IDENTITY;
        for row in 0..rows {
            let index = matrix_index(row, column, columns);
            let weight = weights[index];
            column_weight += weight;
            let target = scalar_power_or_zero(column * rows + row, statement.profile.bits());
            let t_jk = r_jk[index] * (target - weight - weight);
            t_point += parameters.h[row] * t_jk;
        }
        let w_point = parameters.g * column_weight + parameters.q * r_w[column];
        t_point += parameters.q * r_t[column];
        w_commitments.push(CompressedPointV1::from_projective(w_point)?);
        t_commitments.push(CompressedPointV1::from_projective(t_point)?);
    }
    let sum_r_jk = r_jk.iter().copied().fold(Scalar::ZERO, |sum, r| sum + r);
    let r_commitment =
        CompressedPointV1::from_projective(parameters.g * sum_r_jk + parameters.q * r_r)?;
    let mut s_point = ProjectivePoint::IDENTITY;
    for row in 0..rows {
        let row_square_sum = (0..columns).fold(Scalar::ZERO, |sum, column| {
            let r = r_jk[matrix_index(row, column, columns)];
            sum + r * r
        });
        s_point -= parameters.h[row] * row_square_sum;
    }
    s_point += parameters.q * r_s;
    let s_commitment = CompressedPointV1::from_projective(s_point)?;
    let mut transcript = proof_transcript(
        statement,
        &w_commitments,
        &t_commitments,
        &r_commitment,
        &s_commitment,
    )?;
    let mut epsilon = Vec::with_capacity(columns);
    for column in 0..columns {
        epsilon.push(
            transcript
                .challenge_nonzero_scalar(
                    b"epsilon",
                    u32::try_from(column).expect("column count fits u32"),
                )?
                .to_scalar()?,
        );
    }
    let mut responses = Vec::with_capacity(matrix_len);
    for row in 0..rows {
        for column in 0..columns {
            let index = matrix_index(row, column, columns);
            responses.push(CanonicalScalarV1::from_scalar(
                weights[index] * epsilon[column] + r_jk[index],
            ));
        }
    }
    let eta_1 = r_t
        .iter()
        .zip(&epsilon)
        .fold(r_s, |sum, (mask, challenge)| sum + *mask * *challenge);
    let eta_2 = r_w
        .iter()
        .zip(&epsilon)
        .fold(r_r, |sum, (mask, challenge)| sum + *mask * *challenge);
    let proof = VeRangeType1ProofV1 {
        version: VERANGE_TYPE1_PROOF_VERSION_V1,
        bit_length: statement.profile.bits(),
        w_commitments,
        t_commitments,
        r_commitment,
        s_commitment,
        responses,
        eta_1: CanonicalScalarV1::from_scalar(eta_1),
        eta_2: CanonicalScalarV1::from_scalar(eta_2),
    };
    proof.validate_wire()?;
    Ok(proof)
}
/// Verify a `VeRange` Type-1 proof against its externally supplied commitment.
///
/// # Errors
///
/// Returns a typed error for malformed proof material, any transcript/profile
/// mismatch, or any of the three Type-1 verification equations.
pub fn verify(
    statement: &VeRangeType1StatementV1<'_>,
    proof: &VeRangeType1ProofV1,
) -> Result<(), VeRangeError> {
    proof.validate_wire()?;
    if proof.profile()? != statement.profile {
        return Err(VeRangeError::ProfileMismatch);
    }
    let parameters = VeRangeParametersV1::for_profile(statement.profile)?;
    if statement.transcript_binding.parameter_digest != parameters.parameter_digest {
        return Err(VeRangeError::ParameterDigestMismatch);
    }
    if statement.transcript_binding.generator_digest != parameters.generator_digest {
        return Err(VeRangeError::GeneratorDigestMismatch);
    }
    let w = proof
        .w_commitments
        .iter()
        .copied()
        .map(CompressedPointV1::to_projective)
        .collect::<Result<Vec<_>, _>>()?;
    let t = proof
        .t_commitments
        .iter()
        .copied()
        .map(CompressedPointV1::to_projective)
        .collect::<Result<Vec<_>, _>>()?;
    let r = proof.r_commitment.to_projective()?;
    let s = proof.s_commitment.to_projective()?;
    let responses = proof
        .responses
        .iter()
        .copied()
        .map(CanonicalScalarV1::to_scalar)
        .collect::<Result<Vec<_>, _>>()?;
    let eta_1 = proof.eta_1.to_scalar()?;
    let eta_2 = proof.eta_2.to_scalar()?;
    let mut transcript = proof_transcript(
        statement,
        &proof.w_commitments,
        &proof.t_commitments,
        &proof.r_commitment,
        &proof.s_commitment,
    )?;
    let columns = statement.profile.columns();
    let rows = statement.profile.rows();
    let mut epsilon = Vec::with_capacity(columns);
    for column in 0..columns {
        epsilon.push(
            transcript
                .challenge_nonzero_scalar(
                    b"epsilon",
                    u32::try_from(column).expect("column count fits u32"),
                )?
                .to_scalar()?,
        );
    }
    let mut left_range = parameters.q * eta_1;
    for row in 0..rows {
        let exponent = (0..columns).fold(Scalar::ZERO, |sum, column| {
            let index = matrix_index(row, column, columns);
            let v = responses[index];
            let target = scalar_power_or_zero(column * rows + row, statement.profile.bits());
            let u = target * epsilon[column] - v;
            sum + v * u
        });
        left_range += parameters.h[row] * exponent;
    }
    let right_range = t
        .iter()
        .zip(&epsilon)
        .fold(s, |sum, (point, challenge)| sum + *point * *challenge);
    if left_range != right_range {
        return Err(VeRangeError::RangeEquationFailed);
    }
    let response_sum = responses
        .iter()
        .copied()
        .fold(Scalar::ZERO, |sum, value| sum + value);
    let left_response = parameters.g * response_sum + parameters.q * eta_2;
    let right_response = w
        .iter()
        .zip(&epsilon)
        .fold(r, |sum, (point, challenge)| sum + *point * *challenge);
    if left_response != right_response {
        return Err(VeRangeError::ResponseEquationFailed);
    }
    let external = statement.commitment.to_projective()?;
    let column_sum = w
        .iter()
        .copied()
        .fold(ProjectivePoint::IDENTITY, |sum, point| sum + point);
    if external != column_sum {
        return Err(VeRangeError::ExternalCommitmentEquationFailed);
    }
    Ok(())
}
#[cfg(test)]
/// Decode and verify canonical opaque proof bytes in one bounded operation.
///
/// # Errors
///
/// Returns the same typed decode and verification failures as
/// [`VeRangeType1ProofV1::decode_exact`] and [`verify`].
pub fn verify_encoded(
    statement: &VeRangeType1StatementV1<'_>,
    proof_bytes: &[u8],
) -> Result<(), VeRangeError> {
    let proof = VeRangeType1ProofV1::decode_exact(proof_bytes)?;
    verify(statement, &proof)
}
/// Prove every commitment in an ordered Type-1 batch independently.
///
/// This is a conservative composition, not the aggregated protocol in §3.3 of
/// ePrint 2025/528.  Each child receives an independent Fiat--Shamir transcript
/// bound to the full ordered commitment list and its own index.
///
/// # Errors
///
/// Returns an error unless statement, value, and blinding counts match exactly,
/// or if any child proof fails to construct.
pub fn prove_batch<R>(
    statement: &VeRangeType1BatchStatementV1<'_>,
    values: &[u64],
    blindings: &[SecretScalarV1],
    rng: &mut R,
) -> Result<VeRangeType1BatchProofV1, VeRangeError>
where
    R: CryptoRng + RngCore,
{
    if values.len() != statement.len() || blindings.len() != statement.len() {
        return Err(VeRangeError::BatchLengthMismatch {
            statements: statement.len(),
            values: values.len(),
            blindings: blindings.len(),
            proofs: 0,
        });
    }
    for index in 0..statement.len() {
        validate_prover_witness(&statement.child(index), values[index], &blindings[index])?;
    }
    let mut checked_rng = health_checked_p256_rng_v1(rng)?;
    let mut proofs = Vec::with_capacity(statement.len());
    for index in 0..statement.len() {
        proofs.push(prove_validated(
            &statement.child(index),
            values[index],
            &blindings[index],
            &mut checked_rng,
        )?);
    }
    let batch = VeRangeType1BatchProofV1 {
        version: VERANGE_TYPE1_PROOF_VERSION_V1,
        bit_length: statement.profile.bits(),
        proofs,
    };
    batch.validate_wire()?;
    verify_batch(statement, &batch).map_err(|_| VeRangeError::ProverSelfCheckFailed)?;
    Ok(batch)
}
/// Verify every ordered child of an independent Type-1 batch.
///
/// # Errors
///
/// Returns an error for a malformed/mismatched count or the first failing child
/// proof.  No commitment is skipped.
pub fn verify_batch(
    statement: &VeRangeType1BatchStatementV1<'_>,
    proof: &VeRangeType1BatchProofV1,
) -> Result<(), VeRangeError> {
    proof.validate_wire()?;
    if proof.proofs.len() != statement.len() {
        return Err(VeRangeError::BatchLengthMismatch {
            statements: statement.len(),
            values: 0,
            blindings: 0,
            proofs: proof.proofs.len(),
        });
    }
    if VeRangeBitLengthV1::from_bits(proof.bit_length)? != statement.profile {
        return Err(VeRangeError::ProfileMismatch);
    }
    for (index, child_proof) in proof.proofs.iter().enumerate() {
        verify(&statement.child(index), child_proof)?;
    }
    Ok(())
}
/// Decode and verify exact opaque batch bytes.
///
/// # Errors
///
/// Returns the same typed errors as [`VeRangeType1BatchProofV1::decode_exact`]
/// and [`verify_batch`].
pub fn verify_batch_encoded(
    statement: &VeRangeType1BatchStatementV1<'_>,
    proof_bytes: &[u8],
) -> Result<(), VeRangeError> {
    let proof = VeRangeType1BatchProofV1::decode_exact(proof_bytes)?;
    verify_batch(statement, &proof)
}
fn proof_transcript(
    statement: &VeRangeType1StatementV1<'_>,
    w: &[CompressedPointV1],
    t: &[CompressedPointV1],
    r: &CompressedPointV1,
    s: &CompressedPointV1,
) -> Result<TranscriptV1, VeRangeError> {
    let mut transcript = TranscriptV1::new(VERANGE_TYPE1_SUITE_V1, &statement.transcript_binding)?;
    transcript.append_message(b"bit_length", &statement.profile.bits().to_be_bytes())?;
    transcript.append_message(b"batch_index", &statement.batch_index.to_be_bytes())?;
    transcript.append_message(b"batch_count", &statement.batch_count.to_be_bytes())?;
    transcript.append_message(
        b"batch_commitment_digest",
        &statement.batch_commitment_digest,
    )?;
    transcript.append_point(b"external_commitment", &statement.commitment)?;
    transcript.append_message(
        b"column_count",
        &u16::try_from(statement.profile.columns())
            .expect("column count fits u16")
            .to_be_bytes(),
    )?;
    for point in w {
        transcript.append_point(b"W_k", point)?;
    }
    for point in t {
        transcript.append_point(b"T_k", point)?;
    }
    transcript.append_point(b"R", r)?;
    transcript.append_point(b"S", s)?;
    Ok(transcript)
}
fn ordered_commitment_digest(commitments: &[CompressedPointV1]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(BATCH_COMMITMENT_DIGEST_DOMAIN_V1);
    hash.update(
        u32::try_from(commitments.len())
            .expect("closed VeRange commitment count fits u32")
            .to_be_bytes(),
    );
    for commitment in commitments {
        hash.update(commitment.as_bytes());
    }
    hash.finalize().into()
}
fn matrix_index(row: usize, column: usize, columns: usize) -> usize {
    row * columns + column
}
fn scalar_power_or_zero(bit_index: usize, bit_length: u16) -> Scalar {
    if bit_index < usize::from(bit_length) {
        scalar_power_of_two(bit_index)
    } else {
        Scalar::ZERO
    }
}
fn scalar_power_of_two(exponent: usize) -> Scalar {
    let mut value = Scalar::ONE;
    for _ in 0..exponent {
        value = value + value;
    }
    value
}
#[cfg(test)]
mod tests {
    use super::*;
    use rand_core_06::{CryptoRng, Error as RngError, RngCore};
    struct KatRng {
        seed: [u8; 32],
        counter: u64,
    }
    impl KatRng {
        fn new(seed: [u8; 32]) -> Self {
            Self { seed, counter: 0 }
        }
    }
    impl RngCore for KatRng {
        fn next_u32(&mut self) -> u32 {
            let mut bytes = [0_u8; 4];
            self.fill_bytes(&mut bytes);
            u32::from_be_bytes(bytes)
        }
        fn next_u64(&mut self) -> u64 {
            let mut bytes = [0_u8; 8];
            self.fill_bytes(&mut bytes);
            u64::from_be_bytes(bytes)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let mut offset = 0;
            while offset < dest.len() {
                let mut hash = Sha256::new();
                hash.update(b"iroha.verange.kat.rng.v1");
                hash.update(self.seed);
                hash.update(self.counter.to_be_bytes());
                self.counter = self.counter.wrapping_add(1);
                let block: [u8; 32] = hash.finalize().into();
                let take = (dest.len() - offset).min(block.len());
                dest[offset..offset + take].copy_from_slice(&block[..take]);
                offset += take;
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl CryptoRng for KatRng {}
    #[derive(Clone, Copy)]
    enum AdversarialRngMode {
        Periodic,
        PartialFailure,
        Panic,
    }
    struct AdversarialRng(AdversarialRngMode);
    impl RngCore for AdversarialRng {
        fn next_u32(&mut self) -> u32 {
            panic!("VeRange must use the fallible RNG interface")
        }
        fn next_u64(&mut self) -> u64 {
            panic!("VeRange must use the fallible RNG interface")
        }
        fn fill_bytes(&mut self, _destination: &mut [u8]) {
            panic!("VeRange must use the fallible RNG interface")
        }
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RngError> {
            match self.0 {
                AdversarialRngMode::Periodic => {
                    for (index, byte) in destination.iter_mut().enumerate() {
                        *byte = ((index % 8) as u8).wrapping_mul(37).wrapping_add(11);
                    }
                    Ok(())
                }
                AdversarialRngMode::PartialFailure => {
                    for (index, byte) in destination.iter_mut().take(17).enumerate() {
                        *byte = index as u8;
                    }
                    Err(RngError::new("injected partial VeRange entropy failure"))
                }
                AdversarialRngMode::Panic => {
                    panic!("invalid VeRange witness consumed entropy")
                }
            }
        }
    }
    impl CryptoRng for AdversarialRng {}
    fn scalar(value: u8) -> SecretScalarV1 {
        let mut bytes = [0_u8; 32];
        bytes[31] = value;
        SecretScalarV1::from_bytes(bytes).expect("test scalar")
    }
    fn binding(profile: VeRangeBitLengthV1) -> TranscriptBindingV1<'static> {
        let parameters = VeRangeParametersV1::for_profile(profile).expect("parameters");
        TranscriptBindingV1 {
            network_id: &[0x11; 32],
            genesis_hash: [0x11; 32],
            action_index: 3,
            statement_digest: [0x22; 32],
            parameter_id: [0x23; 32],
            parameter_digest: parameters.parameter_digest(),
            verifier_digest: [0x24; 32],
            statement_schema_digest: [0x25; 32],
            engine_manifest_digest: [0x26; 32],
            generator_digest: parameters.generator_digest(),
        }
    }
    fn fixture(
        profile: VeRangeBitLengthV1,
        value: u64,
    ) -> (
        VeRangeType1StatementV1<'static>,
        SecretScalarV1,
        VeRangeType1ProofV1,
    ) {
        let blinding = scalar(7);
        let commitment = commit(profile, value, &blinding).expect("commitment");
        let statement =
            VeRangeType1StatementV1::new(profile, commitment, binding(profile)).expect("statement");
        let mut rng = KatRng::new([0x42; 32]);
        let proof = prove(&statement, value, &blinding, &mut rng).expect("proof");
        (statement, blinding, proof)
    }
    #[test]
    fn both_closed_profiles_roundtrip_and_verify() {
        for (profile, values) in [
            (VeRangeBitLengthV1::Bits32, vec![0, 1, (1_u64 << 32) - 1]),
            (VeRangeBitLengthV1::Bits64, vec![0, 1, u64::MAX]),
        ] {
            for value in values {
                let (statement, _, proof) = fixture(profile, value);
                verify(&statement, &proof).expect("valid Type-1 proof");
                verify_encoded(&statement, &proof.encode()).expect("encoded proof");
            }
        }
    }
    #[test]
    fn ordered_batch_proves_every_commitment_without_shared_challenges() {
        let profile = VeRangeBitLengthV1::Bits32;
        let values = [0_u64, 7, 42, (1_u64 << 32) - 1];
        let blindings = [scalar(3), scalar(5), scalar(7), scalar(11)];
        let commitments = values
            .iter()
            .zip(&blindings)
            .map(|(value, blinding)| commit(profile, *value, blinding).expect("commitment"))
            .collect();
        let statement = VeRangeType1BatchStatementV1::new(profile, commitments, binding(profile))
            .expect("batch statement");
        let mut rng = KatRng::new([0x81; 32]);
        let proof = prove_batch(&statement, &values, &blindings, &mut rng).expect("batch proof");
        assert_eq!(proof.len(), values.len());
        verify_batch(&statement, &proof).expect("batch verify");
        verify_batch_encoded(&statement, &proof.encode()).expect("encoded batch");
        let mut reordered = proof.clone();
        reordered.proofs.swap(0, 1);
        assert!(verify_batch(&statement, &reordered).is_err());
        let mut duplicated = proof.clone();
        duplicated.proofs[1] = duplicated.proofs[0].clone();
        assert!(verify_batch(&statement, &duplicated).is_err());
        let mut reordered_commitments = statement.commitments().to_vec();
        reordered_commitments.swap(0, 1);
        let reordered_statement =
            VeRangeType1BatchStatementV1::new(profile, reordered_commitments, binding(profile))
                .expect("reordered statement");
        assert!(verify_batch(&reordered_statement, &proof).is_err());
        let other_blindings = [scalar(13), scalar(17), scalar(19), scalar(23)];
        let other_commitments = values
            .iter()
            .zip(&other_blindings)
            .map(|(value, blinding)| commit(profile, *value, blinding).expect("commitment"))
            .collect();
        let other_statement =
            VeRangeType1BatchStatementV1::new(profile, other_commitments, binding(profile))
                .expect("other statement");
        let mut other_rng = KatRng::new([0x91; 32]);
        let other_proof = prove_batch(&other_statement, &values, &other_blindings, &mut other_rng)
            .expect("other proof");
        let mut transplanted = proof.clone();
        transplanted.proofs[2] = other_proof.proofs[2].clone();
        assert!(verify_batch(&statement, &transplanted).is_err());
        let mut missing = proof.clone();
        missing.proofs.pop();
        assert!(matches!(
            verify_batch(&statement, &missing),
            Err(VeRangeError::BatchLengthMismatch { .. })
        ));
    }
    #[test]
    fn batch_rejects_empty_over_cap_duplicate_and_witness_count_mismatch() {
        let profile = VeRangeBitLengthV1::Bits32;
        assert!(matches!(
            VeRangeType1BatchStatementV1::new(profile, Vec::new(), binding(profile)),
            Err(VeRangeError::InvalidBatchCount { count: 0, .. })
        ));
        let blinding = scalar(3);
        let commitment = commit(profile, 1, &blinding).expect("commitment");
        assert!(matches!(
            VeRangeType1BatchStatementV1::new(
                profile,
                vec![commitment; MAX_VERANGE_TYPE1_BATCH_COMMITMENTS_V1 + 1],
                binding(profile)
            ),
            Err(VeRangeError::InvalidBatchCount { .. })
        ));
        assert!(matches!(
            VeRangeType1BatchStatementV1::new(
                profile,
                vec![commitment, commitment],
                binding(profile)
            ),
            Err(VeRangeError::DuplicateBatchCommitment { index: 1 })
        ));
        let statement =
            VeRangeType1BatchStatementV1::new(profile, vec![commitment], binding(profile))
                .expect("statement");
        let mut rng = KatRng::new([0x82; 32]);
        assert!(matches!(
            prove_batch(&statement, &[], &[], &mut rng),
            Err(VeRangeError::BatchLengthMismatch { .. })
        ));
    }
    #[test]
    fn batch_accepts_exact_first_release_maximum() {
        let profile = VeRangeBitLengthV1::Bits32;
        let values = [0_u64, 1, 2, 3, 4, 5, 6, u32::MAX.into()];
        let blindings = [
            scalar(3),
            scalar(5),
            scalar(7),
            scalar(11),
            scalar(13),
            scalar(17),
            scalar(19),
            scalar(23),
        ];
        let commitments = values
            .iter()
            .zip(&blindings)
            .map(|(value, blinding)| commit(profile, *value, blinding).expect("commitment"))
            .collect();
        let statement = VeRangeType1BatchStatementV1::new(profile, commitments, binding(profile))
            .expect("max batch statement");
        assert_eq!(statement.len(), MAX_VERANGE_TYPE1_BATCH_COMMITMENTS_V1);
        let mut rng = KatRng::new([0x84; 32]);
        let proof =
            prove_batch(&statement, &values, &blindings, &mut rng).expect("max batch proof");
        assert_eq!(proof.len(), MAX_VERANGE_TYPE1_BATCH_COMMITMENTS_V1);
        verify_batch_encoded(&statement, &proof.encode()).expect("max batch verify");
    }
    #[test]
    fn batch_decoder_rejects_truncation_trailing_and_mixed_profiles() {
        let profile = VeRangeBitLengthV1::Bits32;
        let blindings = [scalar(3), scalar(5)];
        let values = [1_u64, 2_u64];
        let commitments = values
            .iter()
            .zip(&blindings)
            .map(|(value, blinding)| commit(profile, *value, blinding).expect("commitment"))
            .collect();
        let statement = VeRangeType1BatchStatementV1::new(profile, commitments, binding(profile))
            .expect("statement");
        let mut rng = KatRng::new([0x83; 32]);
        let proof = prove_batch(&statement, &values, &blindings, &mut rng).expect("proof");
        let bytes = proof.encode();
        for end in 0..bytes.len() {
            assert!(VeRangeType1BatchProofV1::decode_exact(&bytes[..end]).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(VeRangeType1BatchProofV1::decode_exact(&trailing).is_err());
        let (_, _, proof64) = fixture(VeRangeBitLengthV1::Bits64, 3);
        let mut mixed = proof;
        mixed.proofs[1] = proof64;
        assert!(matches!(
            VeRangeType1BatchProofV1::decode_exact(&mixed.encode()),
            Err(VeRangeError::ProfileMismatch)
        ));
        let empty = VeRangeType1BatchProofV1 {
            version: VERANGE_TYPE1_PROOF_VERSION_V1,
            bit_length: 32,
            proofs: Vec::new(),
        };
        assert!(matches!(
            VeRangeType1BatchProofV1::decode_exact(&empty.encode()),
            Err(VeRangeError::InvalidBatchCount { count: 0, .. })
        ));
        let child = mixed.proofs[0].clone();
        let over_cap = VeRangeType1BatchProofV1 {
            version: VERANGE_TYPE1_PROOF_VERSION_V1,
            bit_length: 32,
            proofs: vec![child; MAX_VERANGE_TYPE1_BATCH_COMMITMENTS_V1 + 1],
        };
        assert!(matches!(
            VeRangeType1BatchProofV1::decode_exact(&over_cap.encode()),
            Err(VeRangeError::InvalidBatchCount { .. })
        ));
        let mut unknown_version = mixed.clone();
        unknown_version.version += 1;
        assert!(matches!(
            VeRangeType1BatchProofV1::decode_exact(&unknown_version.encode()),
            Err(VeRangeError::UnsupportedProofVersion { .. })
        ));
        let mut unsupported_profile = mixed;
        unsupported_profile.bit_length = 63;
        assert!(matches!(
            VeRangeType1BatchProofV1::decode_exact(&unsupported_profile.encode()),
            Err(VeRangeError::UnsupportedBitLength { bits: 63 })
        ));
        assert!(matches!(
            VeRangeType1BatchProofV1::decode_exact(&vec![
                0;
                MAX_VERANGE_TYPE1_BATCH_PROOF_BYTES_V1 + 1
            ]),
            Err(VeRangeError::P256(P256EngineError::ProofTooLarge { .. }))
        ));
    }
    #[test]
    fn closed_parameter_set_initializes_with_a_shared_digest() {
        let bits_32 =
            VeRangeParametersV1::for_profile(VeRangeBitLengthV1::Bits32).unwrap_or_else(|error| {
                panic!("32-bit VeRange parameter initialization failed: {error:?}")
            });
        let bits_64 =
            VeRangeParametersV1::for_profile(VeRangeBitLengthV1::Bits64).unwrap_or_else(|error| {
                panic!("64-bit VeRange parameter initialization failed: {error:?}")
            });
        assert_eq!(bits_32.profile(), VeRangeBitLengthV1::Bits32);
        assert_eq!(bits_64.profile(), VeRangeBitLengthV1::Bits64);
        assert_eq!(bits_32.parameter_digest(), bits_64.parameter_digest());
        assert_ne!(bits_32.generator_digest(), bits_64.generator_digest());
    }
    #[test]
    fn deterministic_known_answer_vector_is_stable() {
        let (statement, _, proof) = fixture(VeRangeBitLengthV1::Bits32, 0xdead_beef);
        verify(&statement, &proof).expect("proof");
        let proof_digest = Sha256::digest(proof.encode());
        let parameters =
            VeRangeParametersV1::for_profile(VeRangeBitLengthV1::Bits32).expect("parameters");
        let parameters_64 =
            VeRangeParametersV1::for_profile(VeRangeBitLengthV1::Bits64).expect("parameters 64");
        let descriptor = parameters.descriptor();
        assert_eq!(descriptor.suite, VERANGE_TYPE1_SUITE_V1);
        assert_eq!(descriptor.source_profile, VERANGE_TYPE1_SOURCE_PROFILE_V1);
        assert_eq!(descriptor.proof_version, VERANGE_TYPE1_PROOF_VERSION_V1);
        assert_eq!(
            (descriptor.bit_length, descriptor.rows, descriptor.columns),
            (32, 6, 6)
        );
        assert_eq!(descriptor.parameter_digest, parameters.parameter_digest());
        assert_eq!(descriptor.generator_digest, parameters.generator_digest());
        assert_eq!(
            descriptor.max_batch_commitments,
            MAX_VERANGE_TYPE1_BATCH_COMMITMENTS_V1 as u32
        );
        assert_eq!(
            (
                hex::encode(parameters.parameter_digest()),
                hex::encode(parameters.generator_digest()),
                hex::encode(parameters_64.generator_digest()),
                hex::encode(proof_digest),
            ),
            (
                "3d79fe744741f956cb589f45774f922b849cf93833e6a9ebdedf1f815f1b7b44".to_owned(),
                "50115a3ba086b8d50a2d3f834b22b3a2e81dee1be85cb1fa4c3d6d25a4807c23".to_owned(),
                "7a5a99665e13b111b38f13348de65e66664aa832cdab0183ad468cab0736be21".to_owned(),
                "a994999cfa5caba42aa623dd8ac74cf4bc72349e85ad3aec8ddace0e2e013f2b".to_owned(),
            )
        );
    }
    #[test]
    fn rejects_32_bit_boundary_and_false_opening() {
        let blinding = scalar(5);
        assert!(matches!(
            commit(VeRangeBitLengthV1::Bits32, 1_u64 << 32, &blinding),
            Err(VeRangeError::WitnessOutOfRange { .. })
        ));
        let profile = VeRangeBitLengthV1::Bits32;
        let commitment = commit(profile, 9, &blinding).expect("commitment");
        let statement =
            VeRangeType1StatementV1::new(profile, commitment, binding(profile)).expect("statement");
        let mut rng = KatRng::new([1; 32]);
        assert!(matches!(
            prove(&statement, 10, &blinding, &mut rng),
            Err(VeRangeError::CommitmentOpeningMismatch)
        ));
    }
    #[test]
    fn prover_entropy_is_health_checked_after_witness_validation() {
        let profile = VeRangeBitLengthV1::Bits32;
        let value = 19;
        let blinding = scalar(9);
        let commitment = commit(profile, value, &blinding).expect("commitment");
        let statement =
            VeRangeType1StatementV1::new(profile, commitment, binding(profile)).expect("statement");
        assert!(matches!(
            prove(
                &statement,
                value,
                &blinding,
                &mut AdversarialRng(AdversarialRngMode::Periodic),
            ),
            Err(VeRangeError::P256(
                P256EngineError::RandomnessHealthCheckFailed
            ))
        ));
        assert!(matches!(
            prove(
                &statement,
                value,
                &blinding,
                &mut AdversarialRng(AdversarialRngMode::PartialFailure),
            ),
            Err(VeRangeError::P256(P256EngineError::RandomnessUnavailable))
        ));
        assert!(matches!(
            prove(
                &statement,
                value + 1,
                &blinding,
                &mut AdversarialRng(AdversarialRngMode::Panic),
            ),
            Err(VeRangeError::CommitmentOpeningMismatch)
        ));
    }
    #[test]
    fn exact_decoder_rejects_every_truncation_and_trailing_data() {
        let (_, _, proof) = fixture(VeRangeBitLengthV1::Bits32, 17);
        let bytes = proof.encode();
        for end in 0..bytes.len() {
            assert!(
                VeRangeType1ProofV1::decode_exact(&bytes[..end]).is_err(),
                "truncation at {end} was accepted"
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(VeRangeType1ProofV1::decode_exact(&trailing).is_err());
        assert!(matches!(
            VeRangeType1ProofV1::decode_exact(&vec![0; MAX_VERANGE_TYPE1_PROOF_BYTES_V1 + 1]),
            Err(VeRangeError::P256(P256EngineError::ProofTooLarge { .. }))
        ));
    }
    #[test]
    fn decoder_preflights_oversized_and_forged_vector_counts() {
        let (_, _, mut proof) = fixture(VeRangeBitLengthV1::Bits32, 19);
        proof.responses.resize(
            MAX_VERANGE_TYPE1_SEQUENCE_ELEMENTS_V1 + 1,
            proof.responses[0],
        );
        let encoded = proof.encode();
        assert!(matches!(
            VeRangeType1ProofV1::decode_exact(&encoded),
            Err(VeRangeError::P256(P256EngineError::InvalidProofEncoding))
        ));
        let encoded_count = 65_u64.to_le_bytes();
        let count_offset = encoded
            .windows(encoded_count.len())
            .position(|window| window == encoded_count)
            .expect("oversized response count is present in canonical wire");
        let mut forged = encoded;
        forged[count_offset..count_offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(
            VeRangeType1ProofV1::decode_exact(&forged),
            Err(VeRangeError::P256(P256EngineError::InvalidProofEncoding))
        ));
    }
    #[test]
    fn decoder_rejects_unknown_version_shape_noncanonical_scalar_and_identity() {
        let (_, _, proof) = fixture(VeRangeBitLengthV1::Bits32, 23);
        let mut unknown = proof.clone();
        unknown.version = 2;
        assert!(matches!(
            VeRangeType1ProofV1::decode_exact(&unknown.encode()),
            Err(VeRangeError::UnsupportedProofVersion { version: 2 })
        ));
        let mut malformed_shapes = Vec::new();
        let mut changed = proof.clone();
        changed.w_commitments.pop();
        malformed_shapes.push(changed);
        let mut changed = proof.clone();
        changed.w_commitments.push(proof.w_commitments[0]);
        malformed_shapes.push(changed);
        let mut changed = proof.clone();
        changed.t_commitments.pop();
        malformed_shapes.push(changed);
        let mut changed = proof.clone();
        changed.t_commitments.push(proof.t_commitments[0]);
        malformed_shapes.push(changed);
        let mut changed = proof.clone();
        changed.responses.pop();
        malformed_shapes.push(changed);
        let mut changed = proof.clone();
        changed.responses.push(proof.responses[0]);
        malformed_shapes.push(changed);
        for wrong_shape in malformed_shapes {
            assert!(matches!(
                VeRangeType1ProofV1::decode_exact(&wrong_shape.encode()),
                Err(VeRangeError::InvalidProofShape { .. })
            ));
        }
        let mut unsupported_profile = proof.clone();
        unsupported_profile.bit_length = 31;
        assert!(matches!(
            VeRangeType1ProofV1::decode_exact(&unsupported_profile.encode()),
            Err(VeRangeError::UnsupportedBitLength { bits: 31 })
        ));
        let mut noncanonical = proof.clone();
        noncanonical.eta_1 = CanonicalScalarV1::from_unchecked_bytes(
            hex::decode("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
                .expect("order")
                .try_into()
                .expect("32 bytes"),
        );
        assert!(matches!(
            VeRangeType1ProofV1::decode_exact(&noncanonical.encode()),
            Err(VeRangeError::P256(P256EngineError::InvalidScalarEncoding))
        ));
        let mut identity_form = proof;
        identity_form.r_commitment = CompressedPointV1::from_unchecked_bytes([0; 33]);
        assert!(VeRangeType1ProofV1::decode_exact(&identity_form.encode()).is_err());
    }
    #[test]
    fn every_bound_statement_field_changes_verification() {
        let (statement, _, proof) = fixture(VeRangeBitLengthV1::Bits32, 41);
        let different_commitment =
            commit(VeRangeBitLengthV1::Bits32, 42, &scalar(9)).expect("different commitment");
        let changed_commitment = VeRangeType1StatementV1::new(
            statement.profile,
            different_commitment,
            statement.transcript_binding,
        )
        .expect("statement");
        assert!(verify(&changed_commitment, &proof).is_err());
        let mut changed_bindings = Vec::new();
        let mut changed = statement.transcript_binding;
        changed.network_id = &[0x12; 32];
        changed.genesis_hash = [0x12; 32];
        changed_bindings.push(changed);
        let mut changed = statement.transcript_binding;
        changed.genesis_hash[0] ^= 1;
        assert!(
            VeRangeType1StatementV1::new(statement.profile, statement.commitment, changed).is_err(),
            "network/genesis disagreement must reject before proof evaluation"
        );
        let mut changed = statement.transcript_binding;
        changed.action_index += 1;
        changed_bindings.push(changed);
        let mut changed = statement.transcript_binding;
        changed.parameter_id[0] ^= 1;
        changed_bindings.push(changed);
        let mut changed = statement.transcript_binding;
        changed.verifier_digest[0] ^= 1;
        changed_bindings.push(changed);
        let mut changed = statement.transcript_binding;
        changed.statement_schema_digest[0] ^= 1;
        changed_bindings.push(changed);
        let mut changed = statement.transcript_binding;
        changed.engine_manifest_digest[0] ^= 1;
        changed_bindings.push(changed);
        let mut changed = statement.transcript_binding;
        changed.statement_digest[0] ^= 1;
        changed_bindings.push(changed);
        for binding in changed_bindings {
            let changed =
                VeRangeType1StatementV1::new(statement.profile, statement.commitment, binding)
                    .expect("bound statement");
            assert!(verify(&changed, &proof).is_err());
        }
        let mut wrong_parameter = statement.transcript_binding;
        wrong_parameter.parameter_digest[0] ^= 1;
        assert!(matches!(
            VeRangeType1StatementV1::new(statement.profile, statement.commitment, wrong_parameter),
            Err(VeRangeError::ParameterDigestMismatch)
        ));
        let mut wrong_generators = statement.transcript_binding;
        wrong_generators.generator_digest[0] ^= 1;
        assert!(matches!(
            VeRangeType1StatementV1::new(statement.profile, statement.commitment, wrong_generators),
            Err(VeRangeError::GeneratorDigestMismatch)
        ));
    }
    #[test]
    fn mutations_of_each_proof_component_are_rejected() {
        let (statement, _, proof) = fixture(VeRangeBitLengthV1::Bits64, 0x1234_5678_9abc_def0);
        for index in 0..proof.w_commitments.len() {
            let mut changed = proof.clone();
            changed.w_commitments[index] = proof.t_commitments[index];
            assert!(verify(&statement, &changed).is_err());
        }
        for index in 0..proof.t_commitments.len() {
            let mut changed = proof.clone();
            changed.t_commitments[index] = proof.w_commitments[index];
            assert!(verify(&statement, &changed).is_err());
        }
        for index in 0..proof.responses.len() {
            let mut changed = proof.clone();
            let scalar = changed.responses[index].to_scalar().expect("scalar") + Scalar::ONE;
            changed.responses[index] = CanonicalScalarV1::from_scalar(scalar);
            assert!(verify(&statement, &changed).is_err());
        }
        let mut changed = proof.clone();
        changed.r_commitment = proof.s_commitment;
        assert!(verify(&statement, &changed).is_err());
        let mut changed = proof.clone();
        changed.s_commitment = proof.r_commitment;
        assert!(verify(&statement, &changed).is_err());
        let mut changed = proof.clone();
        changed.eta_1 =
            CanonicalScalarV1::from_scalar(proof.eta_1.to_scalar().expect("eta 1") + Scalar::ONE);
        assert!(verify(&statement, &changed).is_err());
        let mut changed = proof;
        changed.eta_2 =
            CanonicalScalarV1::from_scalar(changed.eta_2.to_scalar().expect("eta 2") + Scalar::ONE);
        assert!(verify(&statement, &changed).is_err());
    }
    #[test]
    fn proof_profile_mismatch_and_generator_relation_substitution_fail() {
        let (_, _, proof32) = fixture(VeRangeBitLengthV1::Bits32, 5);
        let parameters32 =
            VeRangeParametersV1::for_profile(VeRangeBitLengthV1::Bits32).expect("parameters32");
        let parameters64 =
            VeRangeParametersV1::for_profile(VeRangeBitLengthV1::Bits64).expect("parameters64");
        assert_eq!(
            parameters32.parameter_digest(),
            parameters64.parameter_digest(),
            "one immutable activation admits both subprofiles"
        );
        assert_ne!(
            parameters32.generator_digest(),
            parameters64.generator_digest(),
            "subprofiles retain independently bound bases"
        );
        let blinding = scalar(7);
        let commitment64 = commit(VeRangeBitLengthV1::Bits64, 5, &blinding).expect("commitment64");
        let statement64 = VeRangeType1StatementV1::new(
            VeRangeBitLengthV1::Bits64,
            commitment64,
            binding(VeRangeBitLengthV1::Bits64),
        )
        .expect("statement64");
        assert!(matches!(
            verify(&statement64, &proof32),
            Err(VeRangeError::ProfileMismatch)
        ));
        let mut cross_profile_binding = binding(VeRangeBitLengthV1::Bits32);
        cross_profile_binding.generator_digest = parameters64.generator_digest();
        assert!(matches!(
            VeRangeType1StatementV1::new(
                VeRangeBitLengthV1::Bits32,
                commit(VeRangeBitLengthV1::Bits32, 5, &blinding).expect("commitment32"),
                cross_profile_binding
            ),
            Err(VeRangeError::GeneratorDigestMismatch)
        ));
        let mut encodings = parameters32.row_generators();
        encodings.push(parameters32.value_generator());
        encodings.push(parameters32.value_generator());
        assert!(matches!(
            validate_generator_independence(&encodings),
            Err(P256EngineError::GeneratorCollision)
        ));
        let mut inverse_encodings = parameters32.row_generators();
        inverse_encodings.push(parameters32.value_generator());
        inverse_encodings.push(
            CompressedPointV1::from_projective(
                -parameters32
                    .value_generator()
                    .to_projective()
                    .expect("generator"),
            )
            .expect("inverse generator"),
        );
        assert!(matches!(
            validate_generator_independence(&inverse_encodings),
            Err(P256EngineError::GeneratorCollision)
        ));
    }
}
