//! Strict fixed-width Bootle/Lantern presentation and blind-issuance wires.
use super::params::{
    APPLICATION_RING_DEGREE_V1, CHALLENGE_OMEGA_V1, PROOF_MODULUS_V1, PROOF_RESIDUE_BYTES_V1,
};
use super::ring::ProofPolynomialV1;
use super::transcript::challenge_eta_is_valid_v1;
use thiserror::Error;
/// Proof wire magic.
pub const PROOF_MAGIC_V1: [u8; 4] = *b"ILN1";
/// Blind-issuance-request proof wire magic.
pub const BLIND_ISSUANCE_REQUEST_PROOF_MAGIC_V1: [u8; 4] = *b"ILB1";
/// Complete holder-to-issuer blind-issuance request wire magic.
pub const BLIND_ISSUANCE_REQUEST_MAGIC_V1: [u8; 4] = *b"ILQ1";
/// Proof wire version.
pub const PROOF_VERSION_V1: u8 = 1;
/// Complete holder-to-issuer blind-issuance request wire version.
pub const BLIND_ISSUANCE_REQUEST_VERSION_V1: u8 = 1;
/// Purpose tag carried by every blind-issuance-request proof header.
pub const BLIND_ISSUANCE_REQUEST_PROOF_PURPOSE_TAG_V1: u8 = 1;
/// Purpose tag carried by every complete blind-issuance request header.
pub const BLIND_ISSUANCE_REQUEST_PURPOSE_TAG_V1: u8 = 1;
/// Fixed header width.
pub const PROOF_HEADER_BYTES_V1: usize = 8;
/// Fixed `ILQ1` header width.
pub const BLIND_ISSUANCE_REQUEST_HEADER_BYTES_V1: usize = 16;
/// Exact target polynomial count encoded by `ILQ1`.
pub const BLIND_ISSUANCE_REQUEST_TARGET_POLYNOMIALS_V1: u16 = 8;
/// Exact target polynomial degree encoded by `ILQ1`.
pub const BLIND_ISSUANCE_REQUEST_RING_DEGREE_V1: u16 = 64;
/// Exact canonical `ILA1` issuer-authorization wire length.
pub const BLIND_ISSUANCE_AUTHORIZATION_BYTES_V1: usize = 320;
/// Exact canonical `ILR1` issuer-response wire length.
pub const BLIND_ISSUANCE_RESPONSE_BYTES_V1: usize =
    8 + 24 * APPLICATION_RING_DEGREE_V1 * 2 + 3 * 32;
/// Polynomial counts in canonical proof order.
pub const T_B_POLYNOMIALS_V1: usize = 12;
/// Polynomial counts in canonical proof order.
pub const H_POLYNOMIALS_V1: usize = 2;
/// Polynomial counts in canonical proof order.
pub const T_A1_POLYNOMIALS_V1: usize = 20;
/// Polynomial counts in canonical proof order.
pub const CHALLENGE_POLYNOMIALS_V1: usize = 1;
/// Polynomial counts in canonical proof order.
pub const HINT_POLYNOMIALS_V1: usize = 20;
/// Polynomial counts in canonical proof order.
pub const Z1_POLYNOMIALS_V1: usize = 50;
/// Polynomial counts in canonical proof order.
pub const Z21_POLYNOMIALS_V1: usize = 44;
/// Polynomial counts in canonical proof order.
pub const Z3_POLYNOMIALS_V1: usize = 4;
/// Polynomial counts in canonical proof order.
pub const Z4_POLYNOMIALS_V1: usize = 4;
/// Total polynomial count.
pub const PROOF_POLYNOMIALS_V1: usize = T_B_POLYNOMIALS_V1
    + H_POLYNOMIALS_V1
    + T_A1_POLYNOMIALS_V1
    + CHALLENGE_POLYNOMIALS_V1
    + HINT_POLYNOMIALS_V1
    + Z1_POLYNOMIALS_V1
    + Z21_POLYNOMIALS_V1
    + Z3_POLYNOMIALS_V1
    + Z4_POLYNOMIALS_V1;
/// Total residue count.
pub const PROOF_COEFFICIENTS_V1: usize = PROOF_POLYNOMIALS_V1 * APPLICATION_RING_DEGREE_V1;
/// Exact canonical proof byte length.
pub const PROOF_BYTES_V1: usize =
    PROOF_HEADER_BYTES_V1 + PROOF_COEFFICIENTS_V1 * PROOF_RESIDUE_BYTES_V1;
/// Exact canonical `ILQ1` holder-to-issuer request wire length.
pub const BLIND_ISSUANCE_REQUEST_BYTES_V1: usize = BLIND_ISSUANCE_REQUEST_HEADER_BYTES_V1
    + BLIND_ISSUANCE_REQUEST_TARGET_POLYNOMIALS_V1 as usize
        * BLIND_ISSUANCE_REQUEST_RING_DEGREE_V1 as usize
        * 2
    + 6 * 32
    + PROOF_BYTES_V1;
const T_B_START: usize = 0;
const H_START: usize = T_B_START + T_B_POLYNOMIALS_V1 * APPLICATION_RING_DEGREE_V1;
const T_A1_START: usize = H_START + H_POLYNOMIALS_V1 * APPLICATION_RING_DEGREE_V1;
const CHALLENGE_START: usize = T_A1_START + T_A1_POLYNOMIALS_V1 * APPLICATION_RING_DEGREE_V1;
const HINT_START: usize = CHALLENGE_START + CHALLENGE_POLYNOMIALS_V1 * APPLICATION_RING_DEGREE_V1;
const Z1_START: usize = HINT_START + HINT_POLYNOMIALS_V1 * APPLICATION_RING_DEGREE_V1;
const Z21_START: usize = Z1_START + Z1_POLYNOMIALS_V1 * APPLICATION_RING_DEGREE_V1;
const Z3_START: usize = Z21_START + Z21_POLYNOMIALS_V1 * APPLICATION_RING_DEGREE_V1;
const Z4_START: usize = Z3_START + Z3_POLYNOMIALS_V1 * APPLICATION_RING_DEGREE_V1;
const PROOF_END: usize = Z4_START + Z4_POLYNOMIALS_V1 * APPLICATION_RING_DEGREE_V1;
const T_A1_RESIDUE_BOUND_V1: u64 = 1_u64 << 36;
#[derive(Clone, Debug, PartialEq, Eq)]
struct ValidatedProofBodyV1 {
    coefficients: Box<[u64]>,
}
impl ValidatedProofBodyV1 {
    fn from_coefficients(coefficients: Box<[u64]>) -> Result<Self, ProofCodecErrorV1> {
        validate_coefficients(&coefficients)?;
        Ok(Self { coefficients })
    }
}
/// Strictly decoded canonical presentation proof.
///
/// Coefficients are stored in one fixed-size logical array. The sole heap
/// allocation is exactly `PROOF_COEFFICIENTS_V1 * size_of::<u64>()`; attacker
/// lengths are rejected before allocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootleLanternPresentationProofV1 {
    body: ValidatedProofBodyV1,
}
impl BootleLanternPresentationProofV1 {
    /// Construct from an exact canonical flat coefficient vector.
    ///
    /// # Errors
    ///
    /// Rejects a wrong count, a residue outside `[0,q)`, a non-compressed
    /// `tA1` coefficient, or a malformed auto-stable challenge.
    pub fn from_coefficients(coefficients: Box<[u64]>) -> Result<Self, ProofCodecErrorV1> {
        Ok(Self {
            body: ValidatedProofBodyV1::from_coefficients(coefficients)?,
        })
    }
    /// Decode exactly one fixed-width proof.
    ///
    /// # Errors
    ///
    /// Rejects the configured ceiling first, then every non-canonical length,
    /// header, residue, compressed commitment, or challenge representation.
    pub fn decode_exact(bytes: &[u8], max_bytes: u32) -> Result<Self, ProofCodecErrorV1> {
        Ok(Self {
            body: decode_exact_body_v1(bytes, max_bytes, ProofWirePurposeV1::Presentation)?,
        })
    }
    /// Encode the unique fixed-width representation.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        encode_body_v1(&self.body, ProofWirePurposeV1::Presentation)
    }
    /// Borrow all canonical residues in wire order.
    #[must_use]
    pub fn coefficients(&self) -> &[u64] {
        &self.body.coefficients
    }
    /// Borrow `tB`.
    #[must_use]
    pub fn t_b(&self) -> &[u64] {
        &self.body.coefficients[T_B_START..H_START]
    }
    /// Borrow `h`.
    #[must_use]
    pub fn h(&self) -> &[u64] {
        &self.body.coefficients[H_START..T_A1_START]
    }
    /// Borrow compressed `tA1`.
    #[must_use]
    pub fn t_a1(&self) -> &[u64] {
        &self.body.coefficients[T_A1_START..CHALLENGE_START]
    }
    /// Borrow the auto-stable challenge polynomial.
    #[must_use]
    pub fn challenge(&self) -> &[u64] {
        &self.body.coefficients[CHALLENGE_START..HINT_START]
    }
    /// Borrow the commitment hint.
    #[must_use]
    pub fn hint(&self) -> &[u64] {
        &self.body.coefficients[HINT_START..Z1_START]
    }
    /// Borrow `z1`.
    #[must_use]
    pub fn z1(&self) -> &[u64] {
        &self.body.coefficients[Z1_START..Z21_START]
    }
    /// Borrow `z21`.
    #[must_use]
    pub fn z21(&self) -> &[u64] {
        &self.body.coefficients[Z21_START..Z3_START]
    }
    /// Borrow `z3`.
    #[must_use]
    pub fn z3(&self) -> &[u64] {
        &self.body.coefficients[Z3_START..Z4_START]
    }
    /// Borrow `z4`.
    #[must_use]
    pub fn z4(&self) -> &[u64] {
        &self.body.coefficients[Z4_START..PROOF_END]
    }
    /// Return one typed `tB` polynomial.
    #[must_use]
    pub fn t_b_polynomial(&self, index: usize) -> Option<ProofPolynomialV1> {
        typed_polynomial(self.t_b(), index)
    }
    /// Return one typed `h` polynomial.
    #[must_use]
    pub fn h_polynomial(&self, index: usize) -> Option<ProofPolynomialV1> {
        typed_polynomial(self.h(), index)
    }
    /// Return one typed compressed `tA1` polynomial.
    #[must_use]
    pub fn t_a1_polynomial(&self, index: usize) -> Option<ProofPolynomialV1> {
        typed_polynomial(self.t_a1(), index)
    }
    /// Return the typed auto-stable challenge polynomial.
    #[must_use]
    pub fn challenge_polynomial(&self) -> ProofPolynomialV1 {
        typed_polynomial(self.challenge(), 0)
            .expect("validated proof contains exactly one challenge polynomial")
    }
    /// Return one typed reconciliation-hint polynomial.
    #[must_use]
    pub fn hint_polynomial(&self, index: usize) -> Option<ProofPolynomialV1> {
        typed_polynomial(self.hint(), index)
    }
    /// Return one typed `z1` polynomial.
    #[must_use]
    pub fn z1_polynomial(&self, index: usize) -> Option<ProofPolynomialV1> {
        typed_polynomial(self.z1(), index)
    }
    /// Return one typed `z21` polynomial.
    #[must_use]
    pub fn z21_polynomial(&self, index: usize) -> Option<ProofPolynomialV1> {
        typed_polynomial(self.z21(), index)
    }
    /// Return one typed `z3` polynomial.
    #[must_use]
    pub fn z3_polynomial(&self, index: usize) -> Option<ProofPolynomialV1> {
        typed_polynomial(self.z3(), index)
    }
    /// Return one typed `z4` polynomial.
    #[must_use]
    pub fn z4_polynomial(&self, index: usize) -> Option<ProofPolynomialV1> {
        typed_polynomial(self.z4(), index)
    }
}
/// Strictly decoded canonical blind-issuance-request proof.
///
/// This nominal P1 type deliberately has no public conversion to or from
/// [`BootleLanternPresentationProofV1`]. Its body uses the same validated fixed-profile polynomial
/// layout, but its `ILB1` header and nonzero purpose tag prevent an encoded P1 request from being
/// accepted as an `ILN1` presentation. The distinct transcript purpose supplies the cryptographic
/// separation after structural decoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootleLanternBlindIssuanceRequestProofV1 {
    validated_body: BootleLanternPresentationProofV1,
}
impl BootleLanternBlindIssuanceRequestProofV1 {
    /// Decode exactly one fixed-width blind-issuance-request proof.
    ///
    /// # Errors
    ///
    /// Rejects the configured ceiling first, then every non-canonical length, `ILB1` header,
    /// purpose tag, residue, compressed commitment, or challenge representation.
    pub fn decode_exact(bytes: &[u8], max_bytes: u32) -> Result<Self, ProofCodecErrorV1> {
        Ok(Self {
            validated_body: BootleLanternPresentationProofV1 {
                body: decode_exact_body_v1(
                    bytes,
                    max_bytes,
                    ProofWirePurposeV1::BlindIssuanceRequest,
                )?,
            },
        })
    }
    /// Encode the unique fixed-width `ILB1` representation.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        encode_body_v1(
            &self.validated_body.body,
            ProofWirePurposeV1::BlindIssuanceRequest,
        )
    }
    pub(super) fn from_validated_body_v1(body: BootleLanternPresentationProofV1) -> Self {
        Self {
            validated_body: body,
        }
    }
    pub(super) const fn validated_body_v1(&self) -> &BootleLanternPresentationProofV1 {
        &self.validated_body
    }
}
#[derive(Clone, Copy)]
enum ProofWirePurposeV1 {
    Presentation,
    BlindIssuanceRequest,
}
impl ProofWirePurposeV1 {
    const fn magic(self) -> [u8; 4] {
        match self {
            Self::Presentation => PROOF_MAGIC_V1,
            Self::BlindIssuanceRequest => BLIND_ISSUANCE_REQUEST_PROOF_MAGIC_V1,
        }
    }
    const fn header_tag(self) -> u8 {
        match self {
            Self::Presentation => 0,
            Self::BlindIssuanceRequest => BLIND_ISSUANCE_REQUEST_PROOF_PURPOSE_TAG_V1,
        }
    }
    fn validate_header_tag(self, actual: u8) -> Result<(), ProofCodecErrorV1> {
        match self {
            Self::Presentation if actual != 0 => {
                Err(ProofCodecErrorV1::NonZeroFlags { flags: actual })
            }
            Self::BlindIssuanceRequest if actual != BLIND_ISSUANCE_REQUEST_PROOF_PURPOSE_TAG_V1 => {
                Err(ProofCodecErrorV1::InvalidPurposeTag { purpose: actual })
            }
            _ => Ok(()),
        }
    }
}
fn decode_exact_body_v1(
    bytes: &[u8],
    max_bytes: u32,
    purpose: ProofWirePurposeV1,
) -> Result<ValidatedProofBodyV1, ProofCodecErrorV1> {
    let observed = u64::try_from(bytes.len()).map_err(|_| ProofCodecErrorV1::LengthOverflow)?;
    if observed > u64::from(max_bytes) {
        return Err(ProofCodecErrorV1::TooLarge {
            bytes: observed,
            max: max_bytes,
        });
    }
    if bytes.len() != PROOF_BYTES_V1 {
        return Err(ProofCodecErrorV1::WrongLength {
            bytes: observed,
            expected: u64::try_from(PROOF_BYTES_V1).expect("fixed proof length fits u64"),
        });
    }
    if bytes[..4] != purpose.magic() {
        return Err(ProofCodecErrorV1::InvalidMagic);
    }
    if bytes[4] != PROOF_VERSION_V1 {
        return Err(ProofCodecErrorV1::UnsupportedVersion { version: bytes[4] });
    }
    purpose.validate_header_tag(bytes[5])?;
    let reserved = u16::from_le_bytes([bytes[6], bytes[7]]);
    if reserved != 0 {
        return Err(ProofCodecErrorV1::NonZeroReserved { reserved });
    }
    let mut coefficients = Vec::with_capacity(PROOF_COEFFICIENTS_V1);
    for (index, encoded) in bytes[PROOF_HEADER_BYTES_V1..]
        .chunks_exact(PROOF_RESIDUE_BYTES_V1)
        .enumerate()
    {
        let mut wide = [0_u8; 8];
        wide[..PROOF_RESIDUE_BYTES_V1].copy_from_slice(encoded);
        let residue = u64::from_le_bytes(wide);
        if residue >= PROOF_MODULUS_V1 {
            return Err(ProofCodecErrorV1::NonCanonicalResidue {
                index: u32::try_from(index).expect("fixed coefficient index fits u32"),
                residue,
            });
        }
        if (T_A1_START..CHALLENGE_START).contains(&index) && residue >= T_A1_RESIDUE_BOUND_V1 {
            return Err(ProofCodecErrorV1::NonCanonicalCompressedCommitment {
                index: u32::try_from(index - T_A1_START).expect("fixed tA1 index fits u32"),
                residue,
            });
        }
        coefficients.push(residue);
    }
    ValidatedProofBodyV1::from_coefficients(coefficients.into_boxed_slice())
}
fn encode_body_v1(body: &ValidatedProofBodyV1, purpose: ProofWirePurposeV1) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(PROOF_BYTES_V1);
    encoded.extend_from_slice(&purpose.magic());
    encoded.push(PROOF_VERSION_V1);
    encoded.push(purpose.header_tag());
    encoded.extend_from_slice(&0_u16.to_le_bytes());
    for residue in &body.coefficients {
        encoded.extend_from_slice(&residue.to_le_bytes()[..PROOF_RESIDUE_BYTES_V1]);
    }
    debug_assert_eq!(encoded.len(), PROOF_BYTES_V1);
    encoded
}
fn typed_polynomial(residues: &[u64], index: usize) -> Option<ProofPolynomialV1> {
    let start = index.checked_mul(APPLICATION_RING_DEGREE_V1)?;
    let end = start.checked_add(APPLICATION_RING_DEGREE_V1)?;
    let coefficients: [u64; APPLICATION_RING_DEGREE_V1] =
        residues.get(start..end)?.try_into().ok()?;
    Some(
        ProofPolynomialV1::new(coefficients)
            .expect("strict proof decoder already established canonical residues"),
    )
}
fn validate_coefficients(coefficients: &[u64]) -> Result<(), ProofCodecErrorV1> {
    if coefficients.len() != PROOF_COEFFICIENTS_V1 {
        return Err(ProofCodecErrorV1::WrongCoefficientCount {
            count: u64::try_from(coefficients.len())
                .map_err(|_| ProofCodecErrorV1::LengthOverflow)?,
            expected: u64::try_from(PROOF_COEFFICIENTS_V1)
                .expect("fixed coefficient count fits u64"),
        });
    }
    for (index, residue) in coefficients.iter().copied().enumerate() {
        if residue >= PROOF_MODULUS_V1 {
            return Err(ProofCodecErrorV1::NonCanonicalResidue {
                index: u32::try_from(index).expect("fixed coefficient index fits u32"),
                residue,
            });
        }
        if (T_A1_START..CHALLENGE_START).contains(&index) && residue >= T_A1_RESIDUE_BOUND_V1 {
            return Err(ProofCodecErrorV1::NonCanonicalCompressedCommitment {
                index: u32::try_from(index - T_A1_START).expect("fixed tA1 index fits u32"),
                residue,
            });
        }
    }
    validate_challenge(&coefficients[CHALLENGE_START..HINT_START])
}
fn validate_challenge(challenge: &[u64]) -> Result<(), ProofCodecErrorV1> {
    debug_assert_eq!(challenge.len(), APPLICATION_RING_DEGREE_V1);
    for (index, residue) in challenge[..32].iter().copied().enumerate() {
        let centered = center_residue(residue);
        if !(-CHALLENGE_OMEGA_V1..=CHALLENGE_OMEGA_V1).contains(&centered) {
            return Err(ProofCodecErrorV1::ChallengeCoefficientOutOfRange {
                index: u8::try_from(index).expect("challenge index fits u8"),
                value: centered,
            });
        }
    }
    if challenge[32] != 0 {
        return Err(ProofCodecErrorV1::ChallengeMiddleCoefficientNonZero {
            residue: challenge[32],
        });
    }
    for index in 33..APPLICATION_RING_DEGREE_V1 {
        let source = APPLICATION_RING_DEGREE_V1 - index;
        let expected = negate_residue(challenge[source]);
        if challenge[index] != expected {
            return Err(ProofCodecErrorV1::ChallengeAntisymmetryMismatch {
                index: u8::try_from(index).expect("challenge index fits u8"),
                expected,
                actual: challenge[index],
            });
        }
    }
    let challenge = ProofPolynomialV1::new(
        challenge
            .try_into()
            .expect("strict challenge slice has the fixed ring degree"),
    )
    .expect("all challenge residues were already proved canonical");
    if !challenge_eta_is_valid_v1(&challenge) {
        return Err(ProofCodecErrorV1::ChallengeEtaBoundExceeded);
    }
    Ok(())
}
fn center_residue(residue: u64) -> i64 {
    if residue <= PROOF_MODULUS_V1 / 2 {
        i64::try_from(residue).expect("proof residue fits i64")
    } else {
        i64::try_from(residue).expect("proof residue fits i64")
            - i64::try_from(PROOF_MODULUS_V1).expect("proof modulus fits i64")
    }
}
fn negate_residue(residue: u64) -> u64 {
    if residue == 0 {
        0
    } else {
        PROOF_MODULUS_V1 - residue
    }
}
/// Strict proof-codec failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ProofCodecErrorV1 {
    /// Platform length could not be represented.
    #[error("Bootle/Lantern proof length overflow")]
    LengthOverflow,
    /// Proof exceeds the active consensus ceiling.
    #[error("Bootle/Lantern proof uses {bytes} bytes, exceeding maximum {max}")]
    TooLarge {
        /// Observed bytes.
        bytes: u64,
        /// Active ceiling.
        max: u32,
    },
    /// Proof does not have the unique fixed length.
    #[error("Bootle/Lantern proof uses {bytes} bytes; expected exactly {expected}")]
    WrongLength {
        /// Observed bytes.
        bytes: u64,
        /// Exact bytes.
        expected: u64,
    },
    /// Header magic differs.
    #[error("Bootle/Lantern proof magic is invalid")]
    InvalidMagic,
    /// Header version is unsupported.
    #[error("Bootle/Lantern proof version {version} is unsupported")]
    UnsupportedVersion {
        /// Rejected version.
        version: u8,
    },
    /// Header flags are not zero.
    #[error("Bootle/Lantern proof flags {flags:#04x} must be zero")]
    NonZeroFlags {
        /// Rejected flags.
        flags: u8,
    },
    /// Blind-issuance-request purpose tag is not the canonical P1 value.
    #[error("Bootle/Lantern blind-issuance proof purpose tag {purpose:#04x} is invalid")]
    InvalidPurposeTag {
        /// Rejected purpose tag.
        purpose: u8,
    },
    /// Header reserved bits are not zero.
    #[error("Bootle/Lantern proof reserved value {reserved:#06x} must be zero")]
    NonZeroReserved {
        /// Rejected reserved value.
        reserved: u16,
    },
    /// Flat constructor received the wrong coefficient count.
    #[error("Bootle/Lantern proof has {count} coefficients; expected {expected}")]
    WrongCoefficientCount {
        /// Observed coefficient count.
        count: u64,
        /// Exact coefficient count.
        expected: u64,
    },
    /// One full residue is outside `[0,q)`.
    #[error("Bootle/Lantern proof coefficient {index} has non-canonical residue {residue}")]
    NonCanonicalResidue {
        /// Flat coefficient index.
        index: u32,
        /// Rejected residue.
        residue: u64,
    },
    /// One compressed `tA1` coefficient is at least `2^36`.
    #[error("Bootle/Lantern compressed tA1 coefficient {index} is {residue}, not below 2^36")]
    NonCanonicalCompressedCommitment {
        /// Coefficient index within `tA1`.
        index: u32,
        /// Rejected residue.
        residue: u64,
    },
    /// One independent challenge coefficient is outside `[-8,8]`.
    #[error("Bootle/Lantern challenge coefficient {index}={value} is outside -8..=8")]
    ChallengeCoefficientOutOfRange {
        /// Challenge coefficient index.
        index: u8,
        /// Centered value.
        value: i64,
    },
    /// The degree-32 challenge coefficient is nonzero.
    #[error("Bootle/Lantern challenge coefficient 32 has nonzero residue {residue}")]
    ChallengeMiddleCoefficientNonZero {
        /// Rejected residue.
        residue: u64,
    },
    /// The upper half of the challenge is not the required antisymmetric image.
    #[error(
        "Bootle/Lantern challenge coefficient {index} has residue {actual}; expected {expected}"
    )]
    ChallengeAntisymmetryMismatch {
        /// Challenge coefficient index.
        index: u8,
        /// Required residue.
        expected: u64,
        /// Rejected residue.
        actual: u64,
    },
    /// The challenge exceeds the exact integer-ring LNP22 eta bound.
    #[error("Bootle/Lantern challenge exceeds the exact integer-ring eta bound")]
    ChallengeEtaBoundExceeded,
}
#[cfg(test)]
mod tests {
    use super::*;
    fn valid_proof() -> BootleLanternPresentationProofV1 {
        let mut coefficients = vec![0_u64; PROOF_COEFFICIENTS_V1];
        let challenge = &mut coefficients[CHALLENGE_START..HINT_START];
        challenge[0] = 8;
        challenge[1] = PROOF_MODULUS_V1 - 3;
        challenge[7] = 5;
        challenge[31] = 2;
        for index in 33..APPLICATION_RING_DEGREE_V1 {
            let source = APPLICATION_RING_DEGREE_V1 - index;
            challenge[index] = negate_residue(challenge[source]);
        }
        BootleLanternPresentationProofV1::from_coefficients(coefficients.into_boxed_slice())
            .expect("canonical synthetic proof")
    }
    fn valid_blind_issuance_request_proof() -> BootleLanternBlindIssuanceRequestProofV1 {
        BootleLanternBlindIssuanceRequestProofV1::from_validated_body_v1(valid_proof())
    }
    fn write_residue(encoded: &mut [u8], index: usize, residue: u64) {
        let offset = PROOF_HEADER_BYTES_V1 + index * PROOF_RESIDUE_BYTES_V1;
        encoded[offset..offset + PROOF_RESIDUE_BYTES_V1]
            .copy_from_slice(&residue.to_le_bytes()[..PROOF_RESIDUE_BYTES_V1]);
    }
    #[test]
    fn exact_wire_roundtrips_and_component_ranges_partition_the_body() {
        let proof = valid_proof();
        let encoded = proof.encode();
        assert_eq!(PROOF_POLYNOMIALS_V1, 157);
        assert_eq!(PROOF_COEFFICIENTS_V1, 10_048);
        assert_eq!(PROOF_BYTES_V1, 70_344);
        assert_eq!(
            &encoded[..PROOF_HEADER_BYTES_V1],
            &[b'I', b'L', b'N', b'1', 1, 0, 0, 0]
        );
        assert_eq!(
            BootleLanternPresentationProofV1::decode_exact(
                &encoded,
                u32::try_from(PROOF_BYTES_V1).expect("fixed proof length fits u32")
            )
            .expect("strict decode"),
            proof
        );
        assert_eq!(proof.t_b().len(), 12 * 64);
        assert_eq!(proof.h().len(), 2 * 64);
        assert_eq!(proof.t_a1().len(), 20 * 64);
        assert_eq!(proof.challenge().len(), 64);
        assert_eq!(proof.hint().len(), 20 * 64);
        assert_eq!(proof.z1().len(), 50 * 64);
        assert_eq!(proof.z21().len(), 44 * 64);
        assert_eq!(proof.z3().len(), 4 * 64);
        assert_eq!(proof.z4().len(), 4 * 64);
        assert_eq!(PROOF_END, proof.coefficients().len());
        let component_getters: [(
            usize,
            fn(&BootleLanternPresentationProofV1, usize) -> Option<ProofPolynomialV1>,
        ); 8] = [
            (
                T_B_POLYNOMIALS_V1,
                BootleLanternPresentationProofV1::t_b_polynomial,
            ),
            (
                H_POLYNOMIALS_V1,
                BootleLanternPresentationProofV1::h_polynomial,
            ),
            (
                T_A1_POLYNOMIALS_V1,
                BootleLanternPresentationProofV1::t_a1_polynomial,
            ),
            (
                HINT_POLYNOMIALS_V1,
                BootleLanternPresentationProofV1::hint_polynomial,
            ),
            (
                Z1_POLYNOMIALS_V1,
                BootleLanternPresentationProofV1::z1_polynomial,
            ),
            (
                Z21_POLYNOMIALS_V1,
                BootleLanternPresentationProofV1::z21_polynomial,
            ),
            (
                Z3_POLYNOMIALS_V1,
                BootleLanternPresentationProofV1::z3_polynomial,
            ),
            (
                Z4_POLYNOMIALS_V1,
                BootleLanternPresentationProofV1::z4_polynomial,
            ),
        ];
        for (count, get) in component_getters {
            assert!((0..count).all(|index| get(&proof, index).is_some()));
            assert!(get(&proof, count).is_none());
            assert!(get(&proof, usize::MAX).is_none());
        }
        assert_eq!(
            proof.challenge_polynomial().coefficients(),
            proof.challenge()
        );
    }
    #[test]
    fn blind_issuance_wire_roundtrips_with_distinct_magic_and_purpose() {
        let proof = valid_blind_issuance_request_proof();
        let encoded = proof.encode();
        assert_eq!(encoded.len(), PROOF_BYTES_V1);
        assert_eq!(
            &encoded[..PROOF_HEADER_BYTES_V1],
            &[b'I', b'L', b'B', b'1', 1, 1, 0, 0]
        );
        assert_eq!(
            BootleLanternBlindIssuanceRequestProofV1::decode_exact(
                &encoded,
                u32::try_from(PROOF_BYTES_V1).expect("fixed proof length fits u32")
            )
            .expect("strict P1 decode"),
            proof
        );
    }
    #[test]
    fn p1_and_p2_cross_magic_and_partial_header_swaps_fail_closed() {
        let presentation = valid_proof().encode();
        let blind_issuance = valid_blind_issuance_request_proof().encode();
        let cap = u32::try_from(PROOF_BYTES_V1).expect("fixed proof length fits u32");
        assert_eq!(
            BootleLanternPresentationProofV1::decode_exact(&blind_issuance, cap),
            Err(ProofCodecErrorV1::InvalidMagic)
        );
        assert_eq!(
            BootleLanternBlindIssuanceRequestProofV1::decode_exact(&presentation, cap),
            Err(ProofCodecErrorV1::InvalidMagic)
        );
        // A magic-only substitution cannot turn the P1 header into P2: the
        // nonzero purpose tag is invalid in P2's zero-only flags byte.
        let mut p1_with_p2_magic = blind_issuance.clone();
        p1_with_p2_magic[..4].copy_from_slice(&PROOF_MAGIC_V1);
        assert_eq!(
            BootleLanternPresentationProofV1::decode_exact(&p1_with_p2_magic, cap),
            Err(ProofCodecErrorV1::NonZeroFlags {
                flags: BLIND_ISSUANCE_REQUEST_PROOF_PURPOSE_TAG_V1
            })
        );
        // Conversely, an ILB1 magic substitution retains P2's zero flags and
        // therefore lacks the mandatory P1 purpose tag.
        let mut p2_with_p1_magic = presentation;
        p2_with_p1_magic[..4].copy_from_slice(&BLIND_ISSUANCE_REQUEST_PROOF_MAGIC_V1);
        assert_eq!(
            BootleLanternBlindIssuanceRequestProofV1::decode_exact(&p2_with_p1_magic, cap),
            Err(ProofCodecErrorV1::InvalidPurposeTag { purpose: 0 })
        );
    }
    #[test]
    fn blind_issuance_decoder_rejects_lengths_headers_and_noncanonical_body() {
        let canonical = valid_blind_issuance_request_proof().encode();
        let cap = u32::try_from(PROOF_BYTES_V1).expect("fixed proof length fits u32");
        for length in 0..PROOF_BYTES_V1 {
            assert!(matches!(
                BootleLanternBlindIssuanceRequestProofV1::decode_exact(&canonical[..length], cap),
                Err(ProofCodecErrorV1::WrongLength { .. })
            ));
        }
        let mut trailing = canonical.clone();
        trailing.push(0);
        assert!(matches!(
            BootleLanternBlindIssuanceRequestProofV1::decode_exact(&trailing, cap + 1),
            Err(ProofCodecErrorV1::WrongLength { .. })
        ));
        assert!(matches!(
            BootleLanternBlindIssuanceRequestProofV1::decode_exact(&canonical, cap - 1),
            Err(ProofCodecErrorV1::TooLarge { .. })
        ));
        for magic_byte in 0..4 {
            for bit in 0..8 {
                let mut malformed = canonical.clone();
                malformed[magic_byte] ^= 1_u8 << bit;
                assert_eq!(
                    BootleLanternBlindIssuanceRequestProofV1::decode_exact(&malformed, cap),
                    Err(ProofCodecErrorV1::InvalidMagic)
                );
            }
        }
        for version in 0..=u8::MAX {
            if version == PROOF_VERSION_V1 {
                continue;
            }
            let mut malformed = canonical.clone();
            malformed[4] = version;
            assert_eq!(
                BootleLanternBlindIssuanceRequestProofV1::decode_exact(&malformed, cap),
                Err(ProofCodecErrorV1::UnsupportedVersion { version })
            );
        }
        for purpose in 0..=u8::MAX {
            if purpose == BLIND_ISSUANCE_REQUEST_PROOF_PURPOSE_TAG_V1 {
                continue;
            }
            let mut malformed = canonical.clone();
            malformed[5] = purpose;
            assert_eq!(
                BootleLanternBlindIssuanceRequestProofV1::decode_exact(&malformed, cap),
                Err(ProofCodecErrorV1::InvalidPurposeTag { purpose })
            );
        }
        for bit in 0..16 {
            let mut malformed = canonical.clone();
            let reserved = 1_u16 << bit;
            malformed[6..8].copy_from_slice(&reserved.to_le_bytes());
            assert_eq!(
                BootleLanternBlindIssuanceRequestProofV1::decode_exact(&malformed, cap),
                Err(ProofCodecErrorV1::NonZeroReserved { reserved })
            );
        }
        let mut malformed = canonical.clone();
        write_residue(&mut malformed, 0, PROOF_MODULUS_V1);
        assert_eq!(
            BootleLanternBlindIssuanceRequestProofV1::decode_exact(&malformed, cap),
            Err(ProofCodecErrorV1::NonCanonicalResidue {
                index: 0,
                residue: PROOF_MODULUS_V1
            })
        );
        malformed = canonical.clone();
        write_residue(&mut malformed, T_A1_START, T_A1_RESIDUE_BOUND_V1);
        assert_eq!(
            BootleLanternBlindIssuanceRequestProofV1::decode_exact(&malformed, cap),
            Err(ProofCodecErrorV1::NonCanonicalCompressedCommitment {
                index: 0,
                residue: T_A1_RESIDUE_BOUND_V1
            })
        );
        malformed = canonical;
        write_residue(&mut malformed, CHALLENGE_START, 9);
        assert_eq!(
            BootleLanternBlindIssuanceRequestProofV1::decode_exact(&malformed, cap),
            Err(ProofCodecErrorV1::ChallengeCoefficientOutOfRange { index: 0, value: 9 })
        );
    }
    #[test]
    fn decoder_rejects_every_truncation_trailing_bytes_headers_and_ceiling() {
        let proof = valid_proof();
        let encoded = proof.encode();
        let cap = u32::try_from(PROOF_BYTES_V1).expect("fixed proof length fits u32");
        for length in 0..PROOF_BYTES_V1 {
            assert!(matches!(
                BootleLanternPresentationProofV1::decode_exact(&encoded[..length], cap),
                Err(ProofCodecErrorV1::WrongLength { .. })
            ));
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            BootleLanternPresentationProofV1::decode_exact(&trailing, cap + 1),
            Err(ProofCodecErrorV1::WrongLength { .. })
        ));
        assert!(matches!(
            BootleLanternPresentationProofV1::decode_exact(&encoded, cap - 1),
            Err(ProofCodecErrorV1::TooLarge { .. })
        ));
        let mut malformed = encoded.clone();
        malformed[0] ^= 1;
        assert_eq!(
            BootleLanternPresentationProofV1::decode_exact(&malformed, cap),
            Err(ProofCodecErrorV1::InvalidMagic)
        );
        malformed = encoded.clone();
        malformed[4] = 2;
        assert_eq!(
            BootleLanternPresentationProofV1::decode_exact(&malformed, cap),
            Err(ProofCodecErrorV1::UnsupportedVersion { version: 2 })
        );
        malformed = encoded.clone();
        malformed[5] = 1;
        assert_eq!(
            BootleLanternPresentationProofV1::decode_exact(&malformed, cap),
            Err(ProofCodecErrorV1::NonZeroFlags { flags: 1 })
        );
        malformed = encoded;
        malformed[7] = 1;
        assert_eq!(
            BootleLanternPresentationProofV1::decode_exact(&malformed, cap),
            Err(ProofCodecErrorV1::NonZeroReserved { reserved: 256 })
        );
    }
    #[test]
    fn decoder_rejects_noncanonical_residues_compression_and_challenges() {
        let cap = u32::try_from(PROOF_BYTES_V1).expect("fixed proof length fits u32");
        let canonical = valid_proof().encode();
        for residue in [PROOF_MODULUS_V1, PROOF_MODULUS_V1 + 1, (1_u64 << 56) - 1] {
            let mut malformed = canonical.clone();
            write_residue(&mut malformed, 0, residue);
            assert!(matches!(
                BootleLanternPresentationProofV1::decode_exact(&malformed, cap),
                Err(ProofCodecErrorV1::NonCanonicalResidue { index: 0, .. })
            ));
        }
        let mut malformed = canonical.clone();
        write_residue(&mut malformed, T_A1_START, T_A1_RESIDUE_BOUND_V1);
        assert_eq!(
            BootleLanternPresentationProofV1::decode_exact(&malformed, cap),
            Err(ProofCodecErrorV1::NonCanonicalCompressedCommitment {
                index: 0,
                residue: T_A1_RESIDUE_BOUND_V1
            })
        );
        malformed = canonical.clone();
        write_residue(&mut malformed, CHALLENGE_START, 9);
        assert_eq!(
            BootleLanternPresentationProofV1::decode_exact(&malformed, cap),
            Err(ProofCodecErrorV1::ChallengeCoefficientOutOfRange { index: 0, value: 9 })
        );
        malformed = canonical.clone();
        write_residue(&mut malformed, CHALLENGE_START + 32, 1);
        assert_eq!(
            BootleLanternPresentationProofV1::decode_exact(&malformed, cap),
            Err(ProofCodecErrorV1::ChallengeMiddleCoefficientNonZero { residue: 1 })
        );
        malformed = canonical;
        write_residue(&mut malformed, CHALLENGE_START + 63, 4);
        assert_eq!(
            BootleLanternPresentationProofV1::decode_exact(&malformed, cap),
            Err(ProofCodecErrorV1::ChallengeAntisymmetryMismatch {
                index: 63,
                expected: 3,
                actual: 4
            })
        );
        let mut eta_exceeded = valid_proof().coefficients().to_vec();
        let challenge = &mut eta_exceeded[CHALLENGE_START..HINT_START];
        challenge[..32].fill(8);
        challenge[32] = 0;
        for index in 33..APPLICATION_RING_DEGREE_V1 {
            challenge[index] = PROOF_MODULUS_V1 - 8;
        }
        assert_eq!(
            BootleLanternPresentationProofV1::from_coefficients(
                eta_exceeded.clone().into_boxed_slice()
            ),
            Err(ProofCodecErrorV1::ChallengeEtaBoundExceeded)
        );
        let mut encoded_eta_exceeded = valid_proof().encode();
        for (index, residue) in eta_exceeded[CHALLENGE_START..HINT_START]
            .iter()
            .copied()
            .enumerate()
        {
            write_residue(&mut encoded_eta_exceeded, CHALLENGE_START + index, residue);
        }
        assert_eq!(
            BootleLanternPresentationProofV1::decode_exact(
                &encoded_eta_exceeded,
                u32::try_from(PROOF_BYTES_V1).expect("fixed proof length fits u32")
            ),
            Err(ProofCodecErrorV1::ChallengeEtaBoundExceeded)
        );
    }
}
