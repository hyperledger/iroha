//! Fixed-width canonical proof wire for revised Jindo Figs. 2--7.
use super::{
    JINDO_ENCODING_SLOTS_V1, JINDO_FIELD_ELEMENT_BYTES_V1, JINDO_MAX_BATCH_SIZE_V1,
    JINDO_RING_DEGREE_V1,
    field::JindoFieldElementV1,
    parameters::{JINDO_PARALLEL_REPETITIONS_V1, JINDO_PARAMETERS_V1},
    ring::{
        JINDO_INNER_MODULI_V1, JINDO_OUTER_MODULI_V1, JindoPrimeModulusV1, JindoRnsPolynomialV1,
    },
};
use thiserror::Error;
pub const JINDO_PROOF_MAGIC_V1: [u8; 4] = *b"IJP3";
pub const JINDO_PROOF_VERSION_V1: u8 = 3;
pub const JINDO_PROOF_HEADER_BYTES_V1: usize = 8;
pub const JINDO_PROOF_OUTER_POLYNOMIALS_V1: usize = 7 * JINDO_PARALLEL_REPETITIONS_V1;
pub const JINDO_PROOF_INNER_POLYNOMIALS_V1: usize = 12 * JINDO_PARALLEL_REPETITIONS_V1;
pub const JINDO_PROOF_FIELD_ELEMENTS_V1: usize = 128 * JINDO_PARALLEL_REPETITIONS_V1 + 4 + 512;
pub const JINDO_PROOF_OUTER_RESIDUE_BYTES_V1: usize = 5;
pub const JINDO_PROOF_INNER_RESIDUE_BYTES_V1: usize = 6;
pub const JINDO_PROOF_OUTER_POLYNOMIAL_BYTES_V1: usize =
    2 * JINDO_RING_DEGREE_V1 * JINDO_PROOF_OUTER_RESIDUE_BYTES_V1;
pub const JINDO_PROOF_INNER_POLYNOMIAL_BYTES_V1: usize =
    2 * JINDO_RING_DEGREE_V1 * JINDO_PROOF_INNER_RESIDUE_BYTES_V1;
pub const JINDO_PROOF_BYTES_V1: usize = JINDO_PROOF_HEADER_BYTES_V1
    + JINDO_PROOF_OUTER_POLYNOMIALS_V1 * JINDO_PROOF_OUTER_POLYNOMIAL_BYTES_V1
    + JINDO_PROOF_INNER_POLYNOMIALS_V1 * JINDO_PROOF_INNER_POLYNOMIAL_BYTES_V1
    + JINDO_PROOF_FIELD_ELEMENTS_V1 * JINDO_FIELD_ELEMENT_BYTES_V1;
pub const MASK_COMMITMENTS_PER_REPETITION: usize = 3;
pub const PARTIALS_PER_REPETITION: usize = 1;
pub const ENCODE_RESPONSES_PER_REPETITION: usize = 3;
pub const MLWE_RESPONSES_PER_REPETITION: usize = 8;
pub const INNER_COMMITMENTS_PER_REPETITION: usize = 4;
pub const MASK_SPLIT_EVALUATIONS_PER_REPETITION: usize = JINDO_ENCODING_SLOTS_V1;
const MASK_COMMITMENTS: usize = MASK_COMMITMENTS_PER_REPETITION * JINDO_PARALLEL_REPETITIONS_V1;
const PARTIALS: usize = PARTIALS_PER_REPETITION * JINDO_PARALLEL_REPETITIONS_V1;
const ENCODE_RESPONSES: usize = ENCODE_RESPONSES_PER_REPETITION * JINDO_PARALLEL_REPETITIONS_V1;
const MLWE_RESPONSES: usize = MLWE_RESPONSES_PER_REPETITION * JINDO_PARALLEL_REPETITIONS_V1;
const INNER_COMMITMENTS: usize = INNER_COMMITMENTS_PER_REPETITION * JINDO_PARALLEL_REPETITIONS_V1;
const MASK_SPLIT_EVALUATIONS: usize =
    MASK_SPLIT_EVALUATIONS_PER_REPETITION * JINDO_PARALLEL_REPETITIONS_V1;
const BLIND_EVALUATIONS: usize = JINDO_MAX_BATCH_SIZE_V1;
const SPLIT_EVALUATIONS: usize =
    JINDO_MAX_BATCH_SIZE_V1 * JINDO_PARAMETERS_V1.split * JINDO_ENCODING_SLOTS_V1;
const _: () = {
    assert!(MASK_COMMITMENTS + INNER_COMMITMENTS == JINDO_PROOF_OUTER_POLYNOMIALS_V1);
    assert!(PARTIALS + ENCODE_RESPONSES + MLWE_RESPONSES == JINDO_PROOF_INNER_POLYNOMIALS_V1);
    assert!(
        MASK_SPLIT_EVALUATIONS + BLIND_EVALUATIONS + SPLIT_EVALUATIONS
            == JINDO_PROOF_FIELD_ELEMENTS_V1
    );
    assert!(JINDO_INNER_MODULI_V1[0].modulus() < (1_u64 << 48));
    assert!(JINDO_INNER_MODULI_V1[1].modulus() < (1_u64 << 48));
    assert!(JINDO_OUTER_MODULI_V1[0].modulus() < (1_u64 << 40));
    assert!(JINDO_OUTER_MODULI_V1[1].modulus() < (1_u64 << 40));
};
#[derive(Clone, Copy, Debug)]
pub struct JindoEvaluationProofRepetitionV1<'a> {
    pub(crate) mask_commitments: &'a [JindoRnsPolynomialV1],
    pub(crate) mask_split_evaluation: &'a [JindoFieldElementV1],
    pub(crate) partials: &'a [JindoRnsPolynomialV1],
    pub(crate) encode_responses: &'a [JindoRnsPolynomialV1],
    pub(crate) mlwe_responses: &'a [JindoRnsPolynomialV1],
    pub(crate) inner_commitments: &'a [JindoRnsPolynomialV1],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JindoEvaluationProofV1 {
    pub(crate) mask_commitments: Vec<JindoRnsPolynomialV1>,
    pub(crate) mask_split_evaluation: Vec<JindoFieldElementV1>,
    pub(crate) partials: Vec<JindoRnsPolynomialV1>,
    pub(crate) encode_responses: Vec<JindoRnsPolynomialV1>,
    pub(crate) mlwe_responses: Vec<JindoRnsPolynomialV1>,
    pub(crate) inner_commitments: Vec<JindoRnsPolynomialV1>,
    pub(crate) blind_evaluations: Vec<JindoFieldElementV1>,
    pub(crate) split_evaluations: Vec<JindoFieldElementV1>,
}
impl JindoEvaluationProofV1 {
    pub(crate) fn repetition(&self, repetition: usize) -> JindoEvaluationProofRepetitionV1<'_> {
        fn range(repetition: usize, width: usize) -> core::ops::Range<usize> {
            repetition * width..(repetition + 1) * width
        }
        debug_assert!(repetition < JINDO_PARALLEL_REPETITIONS_V1);
        JindoEvaluationProofRepetitionV1 {
            mask_commitments: &self.mask_commitments
                [range(repetition, MASK_COMMITMENTS_PER_REPETITION)],
            mask_split_evaluation: &self.mask_split_evaluation
                [range(repetition, MASK_SPLIT_EVALUATIONS_PER_REPETITION)],
            partials: &self.partials[range(repetition, PARTIALS_PER_REPETITION)],
            encode_responses: &self.encode_responses
                [range(repetition, ENCODE_RESPONSES_PER_REPETITION)],
            mlwe_responses: &self.mlwe_responses[range(repetition, MLWE_RESPONSES_PER_REPETITION)],
            inner_commitments: &self.inner_commitments
                [range(repetition, INNER_COMMITMENTS_PER_REPETITION)],
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        mask_commitments: Vec<JindoRnsPolynomialV1>,
        mask_split_evaluation: Vec<JindoFieldElementV1>,
        partials: Vec<JindoRnsPolynomialV1>,
        encode_responses: Vec<JindoRnsPolynomialV1>,
        mlwe_responses: Vec<JindoRnsPolynomialV1>,
        inner_commitments: Vec<JindoRnsPolynomialV1>,
        blind_evaluations: Vec<JindoFieldElementV1>,
        split_evaluations: Vec<JindoFieldElementV1>,
    ) -> Result<Self, JindoProofCodecErrorV1> {
        for (section, actual, expected) in [
            (
                JindoProofSectionV1::MaskCommitments,
                mask_commitments.len(),
                MASK_COMMITMENTS,
            ),
            (
                JindoProofSectionV1::MaskSplitEvaluation,
                mask_split_evaluation.len(),
                MASK_SPLIT_EVALUATIONS,
            ),
            (JindoProofSectionV1::Partials, partials.len(), PARTIALS),
            (
                JindoProofSectionV1::EncodeResponses,
                encode_responses.len(),
                ENCODE_RESPONSES,
            ),
            (
                JindoProofSectionV1::MlweResponses,
                mlwe_responses.len(),
                MLWE_RESPONSES,
            ),
            (
                JindoProofSectionV1::InnerCommitments,
                inner_commitments.len(),
                INNER_COMMITMENTS,
            ),
            (
                JindoProofSectionV1::BlindEvaluations,
                blind_evaluations.len(),
                BLIND_EVALUATIONS,
            ),
            (
                JindoProofSectionV1::SplitEvaluations,
                split_evaluations.len(),
                SPLIT_EVALUATIONS,
            ),
        ] {
            if actual != expected {
                return Err(JindoProofCodecErrorV1::WrongElementCount {
                    section,
                    count: u16::try_from(actual).unwrap_or(u16::MAX),
                    expected: u16::try_from(expected).expect("fixed count fits u16"),
                });
            }
        }
        Ok(Self {
            mask_commitments,
            mask_split_evaluation,
            partials,
            encode_responses,
            mlwe_responses,
            inner_commitments,
            blind_evaluations,
            split_evaluations,
        })
    }
    pub(crate) fn decode_exact(
        bytes: &[u8],
        expected_batch_count: usize,
        max_bytes: u32,
    ) -> Result<Self, JindoProofCodecErrorV1> {
        if expected_batch_count != JINDO_MAX_BATCH_SIZE_V1 {
            return Err(JindoProofCodecErrorV1::BatchCountMismatch {
                proof: u8::try_from(JINDO_MAX_BATCH_SIZE_V1)
                    .expect("fixed proof header count fits u8"),
                statement: u8::try_from(expected_batch_count).unwrap_or(u8::MAX),
            });
        }
        let observed =
            u64::try_from(bytes.len()).map_err(|_| JindoProofCodecErrorV1::LengthOverflow)?;
        if observed > u64::from(max_bytes) {
            return Err(JindoProofCodecErrorV1::TooLarge {
                bytes: observed,
                max: max_bytes,
            });
        }
        if bytes.len() != JINDO_PROOF_BYTES_V1 {
            return Err(JindoProofCodecErrorV1::WrongLength {
                bytes: observed,
                expected: JINDO_PROOF_BYTES_V1 as u64,
            });
        }
        if bytes[..4] != JINDO_PROOF_MAGIC_V1 {
            return Err(JindoProofCodecErrorV1::InvalidMagic);
        }
        if bytes[4] != JINDO_PROOF_VERSION_V1 {
            return Err(JindoProofCodecErrorV1::UnsupportedVersion { version: bytes[4] });
        }
        if bytes[5] as usize != JINDO_MAX_BATCH_SIZE_V1 {
            return Err(JindoProofCodecErrorV1::BatchCountMismatch {
                proof: bytes[5],
                statement: u8::try_from(JINDO_MAX_BATCH_SIZE_V1)
                    .expect("fixed proof header count fits u8"),
            });
        }
        if bytes[6] as usize != JINDO_PARALLEL_REPETITIONS_V1 {
            return Err(JindoProofCodecErrorV1::ParallelRepetitionCountMismatch {
                proof: bytes[6],
                expected: u8::try_from(JINDO_PARALLEL_REPETITIONS_V1)
                    .expect("fixed proof header count fits u8"),
            });
        }
        if bytes[7] != 0 {
            return Err(JindoProofCodecErrorV1::NonZeroReserved { reserved: bytes[7] });
        }
        let mut cursor = JINDO_PROOF_HEADER_BYTES_V1;
        let mut polynomial_index = 0_u16;
        let mask_commitments = read_polynomials(
            bytes,
            &mut cursor,
            &mut polynomial_index,
            MASK_COMMITMENTS,
            JINDO_OUTER_MODULI_V1,
            JINDO_PROOF_OUTER_RESIDUE_BYTES_V1,
        )?;
        let mask_split_evaluation = read_fields(bytes, &mut cursor, MASK_SPLIT_EVALUATIONS)?;
        let partials = read_polynomials(
            bytes,
            &mut cursor,
            &mut polynomial_index,
            PARTIALS,
            JINDO_INNER_MODULI_V1,
            JINDO_PROOF_INNER_RESIDUE_BYTES_V1,
        )?;
        let encode_responses = read_polynomials(
            bytes,
            &mut cursor,
            &mut polynomial_index,
            ENCODE_RESPONSES,
            JINDO_INNER_MODULI_V1,
            JINDO_PROOF_INNER_RESIDUE_BYTES_V1,
        )?;
        let mlwe_responses = read_polynomials(
            bytes,
            &mut cursor,
            &mut polynomial_index,
            MLWE_RESPONSES,
            JINDO_INNER_MODULI_V1,
            JINDO_PROOF_INNER_RESIDUE_BYTES_V1,
        )?;
        let inner_commitments = read_polynomials(
            bytes,
            &mut cursor,
            &mut polynomial_index,
            INNER_COMMITMENTS,
            JINDO_OUTER_MODULI_V1,
            JINDO_PROOF_OUTER_RESIDUE_BYTES_V1,
        )?;
        let blind_evaluations = read_fields(bytes, &mut cursor, BLIND_EVALUATIONS)?;
        let split_evaluations = read_fields(bytes, &mut cursor, SPLIT_EVALUATIONS)?;
        debug_assert_eq!(cursor, bytes.len());
        Self::new(
            mask_commitments,
            mask_split_evaluation,
            partials,
            encode_responses,
            mlwe_responses,
            inner_commitments,
            blind_evaluations,
            split_evaluations,
        )
    }
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(JINDO_PROOF_BYTES_V1);
        out.extend_from_slice(&JINDO_PROOF_MAGIC_V1);
        out.extend_from_slice(&[
            JINDO_PROOF_VERSION_V1,
            u8::try_from(JINDO_MAX_BATCH_SIZE_V1).expect("fixed proof header count fits u8"),
            u8::try_from(JINDO_PARALLEL_REPETITIONS_V1).expect("fixed proof header count fits u8"),
            0,
        ]);
        write_polynomials(
            &mut out,
            &self.mask_commitments,
            JINDO_PROOF_OUTER_RESIDUE_BYTES_V1,
        );
        write_fields(&mut out, &self.mask_split_evaluation);
        write_polynomials(&mut out, &self.partials, JINDO_PROOF_INNER_RESIDUE_BYTES_V1);
        write_polynomials(
            &mut out,
            &self.encode_responses,
            JINDO_PROOF_INNER_RESIDUE_BYTES_V1,
        );
        write_polynomials(
            &mut out,
            &self.mlwe_responses,
            JINDO_PROOF_INNER_RESIDUE_BYTES_V1,
        );
        write_polynomials(
            &mut out,
            &self.inner_commitments,
            JINDO_PROOF_OUTER_RESIDUE_BYTES_V1,
        );
        write_fields(&mut out, &self.blind_evaluations);
        write_fields(&mut out, &self.split_evaluations);
        debug_assert_eq!(out.len(), JINDO_PROOF_BYTES_V1);
        out
    }
}
fn read_polynomials(
    bytes: &[u8],
    cursor: &mut usize,
    polynomial_index: &mut u16,
    count: usize,
    moduli: [JindoPrimeModulusV1; 2],
    residue_bytes: usize,
) -> Result<Vec<JindoRnsPolynomialV1>, JindoProofCodecErrorV1> {
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let mut residues = [[0_u64; JINDO_RING_DEGREE_V1]; 2];
        for (modulus_index, (row, modulus)) in residues.iter_mut().zip(moduli).enumerate() {
            for (coefficient_index, coefficient) in row.iter_mut().enumerate() {
                let end = *cursor + residue_bytes;
                let mut encoded = [0_u8; 8];
                encoded[..residue_bytes].copy_from_slice(&bytes[*cursor..end]);
                let value = u64::from_le_bytes(encoded);
                *cursor = end;
                if value >= modulus.modulus() {
                    return Err(JindoProofCodecErrorV1::NonCanonicalResidue {
                        polynomial_index: *polynomial_index,
                        modulus_index: u8::try_from(modulus_index)
                            .map_err(|_| JindoProofCodecErrorV1::LengthOverflow)?,
                        coefficient_index: u16::try_from(coefficient_index)
                            .map_err(|_| JindoProofCodecErrorV1::LengthOverflow)?,
                        residue: value,
                        modulus: modulus.modulus(),
                    });
                }
                *coefficient = value;
            }
        }
        out.push(JindoRnsPolynomialV1::from_residues(residues, moduli).expect("validated"));
        *polynomial_index += 1;
    }
    Ok(out)
}
fn read_fields(
    bytes: &[u8],
    cursor: &mut usize,
    count: usize,
) -> Result<Vec<JindoFieldElementV1>, JindoProofCodecErrorV1> {
    let mut out = Vec::with_capacity(count);
    for index in 0..count {
        let end = *cursor + JINDO_FIELD_ELEMENT_BYTES_V1;
        let encoded: [u8; 32] = bytes[*cursor..end].try_into().expect("length prechecked");
        *cursor = end;
        out.push(JindoFieldElementV1::from_canonical_bytes(encoded).ok_or(
            JindoProofCodecErrorV1::NonCanonicalFieldElement {
                index: u16::try_from(index).map_err(|_| JindoProofCodecErrorV1::LengthOverflow)?,
            },
        )?);
    }
    Ok(out)
}
fn write_polynomials(out: &mut Vec<u8>, values: &[JindoRnsPolynomialV1], residue_bytes: usize) {
    for value in values {
        for residue in value.residues().iter().flatten() {
            out.extend_from_slice(&residue.to_le_bytes()[..residue_bytes]);
        }
    }
}
fn write_fields(out: &mut Vec<u8>, values: &[JindoFieldElementV1]) {
    for value in values {
        out.extend_from_slice(&value.to_canonical_bytes());
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Fixed-width section of a canonical Jindo proof.
pub enum JindoProofSectionV1 {
    /// Outer `ΠSplit` mask commitments.
    MaskCommitments,
    /// `ΠSplit` evaluations of the commitment masks.
    MaskSplitEvaluation,
    /// `ΠAgg` partial-evaluation polynomial.
    Partials,
    /// `ΠQuad` coefficient-encoding responses.
    EncodeResponses,
    /// `ΠQuad` MLWE responses.
    MlweResponses,
    /// `ΠQuad` inner commitments.
    InnerCommitments,
    /// Evaluations of the commitment blinders.
    BlindEvaluations,
    /// Split evaluations for the committed polynomials.
    SplitEvaluations,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
/// Failure to encode or decode the canonical Jindo proof wire format.
pub enum JindoProofCodecErrorV1 {
    /// A computed proof length cannot be represented by the wire format.
    #[error("Jindo proof length cannot be represented")]
    LengthOverflow,
    /// The encoded proof exceeds the configured byte limit.
    #[error("Jindo proof uses {bytes} bytes, exceeding maximum {max}")]
    TooLarge {
        /// Actual encoded proof length.
        bytes: u64,
        /// Maximum accepted proof length.
        max: u32,
    },
    /// The encoded proof does not have the fixed length for this version.
    #[error("Jindo proof uses {bytes} bytes; expected exactly {expected}")]
    WrongLength {
        /// Actual encoded proof length.
        bytes: u64,
        /// Required encoded proof length.
        expected: u64,
    },
    /// The proof header does not start with the Jindo magic bytes.
    #[error("Jindo proof magic is invalid")]
    InvalidMagic,
    /// The proof declares an unsupported wire-format version.
    #[error("Jindo proof version {version} is unsupported")]
    UnsupportedVersion {
        /// Version byte found in the proof header.
        version: u8,
    },
    /// The proof batch size differs from the statement batch size.
    #[error("Jindo proof batch count {proof} differs from statement count {statement}")]
    BatchCountMismatch {
        /// Batch count encoded in the proof.
        proof: u8,
        /// Batch count required by the statement.
        statement: u8,
    },
    /// The proof does not contain the exact 32 parallel repetitions.
    #[error("Jindo proof declares {proof} parallel repetitions; expected {expected}")]
    ParallelRepetitionCountMismatch {
        /// Repetition count encoded in the proof.
        proof: u8,
        /// Repetition count required by the compiled profile.
        expected: u8,
    },
    /// A reserved proof-header byte is non-zero.
    #[error("Jindo proof reserved byte must be zero, got {reserved}")]
    NonZeroReserved {
        /// Non-zero reserved byte found in the header.
        reserved: u8,
    },
    /// A fixed-width proof section has the wrong element count.
    #[error("Jindo proof section {section:?} has {count} elements; expected {expected}")]
    WrongElementCount {
        /// Section whose length is invalid.
        section: JindoProofSectionV1,
        /// Actual number of elements.
        count: u16,
        /// Required number of elements.
        expected: u16,
    },
    /// A polynomial residue is outside its modulus's canonical range.
    #[error(
        "Jindo proof polynomial {polynomial_index}, modulus {modulus_index}, coefficient {coefficient_index} has residue {residue} outside [0,{modulus})"
    )]
    NonCanonicalResidue {
        /// Index of the polynomial in proof wire order.
        polynomial_index: u16,
        /// Index of the RNS modulus within the polynomial.
        modulus_index: u8,
        /// Index of the offending polynomial coefficient.
        coefficient_index: u16,
        /// Non-canonical residue found on the wire.
        residue: u64,
        /// Exclusive upper bound for a canonical residue.
        modulus: u64,
    },
    /// A proof field element is not canonically encoded.
    #[error("Jindo proof field element {index} is non-canonical")]
    NonCanonicalFieldElement {
        /// Index of the field element in proof wire order.
        index: u16,
    },
}
#[cfg(test)]
mod tests {
    use super::*;
    const MASK_COMMITMENTS_OFFSET: usize = JINDO_PROOF_HEADER_BYTES_V1;
    const MASK_SPLIT_EVALUATION_OFFSET: usize =
        MASK_COMMITMENTS_OFFSET + MASK_COMMITMENTS * JINDO_PROOF_OUTER_POLYNOMIAL_BYTES_V1;
    const PARTIALS_OFFSET: usize =
        MASK_SPLIT_EVALUATION_OFFSET + MASK_SPLIT_EVALUATIONS * JINDO_FIELD_ELEMENT_BYTES_V1;
    const ENCODE_RESPONSES_OFFSET: usize =
        PARTIALS_OFFSET + PARTIALS * JINDO_PROOF_INNER_POLYNOMIAL_BYTES_V1;
    const MLWE_RESPONSES_OFFSET: usize =
        ENCODE_RESPONSES_OFFSET + ENCODE_RESPONSES * JINDO_PROOF_INNER_POLYNOMIAL_BYTES_V1;
    const INNER_COMMITMENTS_OFFSET: usize =
        MLWE_RESPONSES_OFFSET + MLWE_RESPONSES * JINDO_PROOF_INNER_POLYNOMIAL_BYTES_V1;
    const BLIND_EVALUATIONS_OFFSET: usize =
        INNER_COMMITMENTS_OFFSET + INNER_COMMITMENTS * JINDO_PROOF_OUTER_POLYNOMIAL_BYTES_V1;
    const SPLIT_EVALUATIONS_OFFSET: usize =
        BLIND_EVALUATIONS_OFFSET + BLIND_EVALUATIONS * JINDO_FIELD_ELEMENT_BYTES_V1;
    fn proof() -> JindoEvaluationProofV1 {
        JindoEvaluationProofV1::new(
            vec![JindoRnsPolynomialV1::zero(); MASK_COMMITMENTS],
            vec![JindoFieldElementV1::ZERO; MASK_SPLIT_EVALUATIONS],
            vec![JindoRnsPolynomialV1::zero(); PARTIALS],
            vec![JindoRnsPolynomialV1::zero(); ENCODE_RESPONSES],
            vec![JindoRnsPolynomialV1::zero(); MLWE_RESPONSES],
            vec![JindoRnsPolynomialV1::zero(); INNER_COMMITMENTS],
            vec![JindoFieldElementV1::ZERO; BLIND_EVALUATIONS],
            vec![JindoFieldElementV1::ZERO; SPLIT_EVALUATIONS],
        )
        .unwrap()
    }
    #[test]
    fn exact_shape_roundtrips_and_has_frozen_size() {
        assert_eq!(JINDO_PROOF_BYTES_V1, 7_159_944);
        let encoded = proof().encode();
        assert_eq!(
            JindoEvaluationProofV1::decode_exact(
                &encoded,
                4,
                u32::try_from(encoded.len()).expect("fixed proof fixture length fits u32")
            )
            .unwrap(),
            proof()
        );
    }
    #[test]
    fn malformed_wire_fails_before_variable_allocation() {
        let encoded = proof().encode();
        for end in [0, 1, 7, encoded.len() - 1] {
            assert!(
                JindoEvaluationProofV1::decode_exact(
                    &encoded[..end],
                    4,
                    u32::try_from(encoded.len()).expect("fixed proof fixture length fits u32")
                )
                .is_err()
            );
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(
            JindoEvaluationProofV1::decode_exact(
                &trailing,
                4,
                u32::try_from(trailing.len()).expect("fixed proof fixture length fits u32")
            )
            .is_err()
        );
        assert!(
            JindoEvaluationProofV1::decode_exact(
                &encoded,
                3,
                u32::try_from(encoded.len()).expect("fixed proof fixture length fits u32")
            )
            .is_err()
        );
    }
    #[test]
    fn every_header_field_and_legacy_magic_fail_closed() {
        let encoded = proof().encode();
        for magic in [b"IJP1", b"IJP2"] {
            let mut legacy = encoded.clone();
            legacy[..4].copy_from_slice(magic);
            assert_eq!(
                JindoEvaluationProofV1::decode_exact(
                    &legacy,
                    4,
                    u32::try_from(legacy.len()).expect("fixed proof fixture length fits u32")
                ),
                Err(JindoProofCodecErrorV1::InvalidMagic)
            );
        }
        let mut exact_old_wire = vec![0_u8; 331_912];
        exact_old_wire[..4].copy_from_slice(b"IJP2");
        exact_old_wire[4] = 2;
        exact_old_wire[5] = 4;
        assert_eq!(
            JindoEvaluationProofV1::decode_exact(
                &exact_old_wire,
                4,
                u32::try_from(JINDO_PROOF_BYTES_V1).expect("fixed proof fixture length fits u32"),
            ),
            Err(JindoProofCodecErrorV1::WrongLength {
                bytes: 331_912,
                expected: JINDO_PROOF_BYTES_V1 as u64,
            })
        );
        for (index, replacement, expected) in [
            (
                4,
                2,
                JindoProofCodecErrorV1::UnsupportedVersion { version: 2 },
            ),
            (
                5,
                3,
                JindoProofCodecErrorV1::BatchCountMismatch {
                    proof: 3,
                    statement: 4,
                },
            ),
            (
                6,
                31,
                JindoProofCodecErrorV1::ParallelRepetitionCountMismatch {
                    proof: 31,
                    expected: 32,
                },
            ),
            (
                7,
                1,
                JindoProofCodecErrorV1::NonZeroReserved { reserved: 1 },
            ),
        ] {
            let mut mutated = encoded.clone();
            mutated[index] = replacement;
            assert_eq!(
                JindoEvaluationProofV1::decode_exact(
                    &mutated,
                    4,
                    u32::try_from(mutated.len()).expect("fixed proof fixture length fits u32")
                ),
                Err(expected)
            );
        }
        assert_eq!(
            JindoEvaluationProofV1::decode_exact(
                &encoded,
                4,
                u32::try_from(JINDO_PROOF_BYTES_V1 - 1)
                    .expect("fixed proof fixture length fits u32"),
            ),
            Err(JindoProofCodecErrorV1::TooLarge {
                bytes: JINDO_PROOF_BYTES_V1 as u64,
                max: u32::try_from(JINDO_PROOF_BYTES_V1 - 1)
                    .expect("fixed proof fixture length fits u32"),
            })
        );
    }
    #[test]
    fn every_rns_phase_rejects_a_residue_equal_to_its_modulus() {
        let encoded = proof().encode();
        for (offset, polynomial_index, modulus, width) in [
            (
                MASK_COMMITMENTS_OFFSET,
                0,
                JINDO_OUTER_MODULI_V1[0],
                JINDO_PROOF_OUTER_RESIDUE_BYTES_V1,
            ),
            (
                PARTIALS_OFFSET,
                96,
                JINDO_INNER_MODULI_V1[0],
                JINDO_PROOF_INNER_RESIDUE_BYTES_V1,
            ),
            (
                ENCODE_RESPONSES_OFFSET,
                128,
                JINDO_INNER_MODULI_V1[0],
                JINDO_PROOF_INNER_RESIDUE_BYTES_V1,
            ),
            (
                MLWE_RESPONSES_OFFSET,
                224,
                JINDO_INNER_MODULI_V1[0],
                JINDO_PROOF_INNER_RESIDUE_BYTES_V1,
            ),
            (
                INNER_COMMITMENTS_OFFSET,
                480,
                JINDO_OUTER_MODULI_V1[0],
                JINDO_PROOF_OUTER_RESIDUE_BYTES_V1,
            ),
        ] {
            let mut mutated = encoded.clone();
            mutated[offset..offset + width]
                .copy_from_slice(&modulus.modulus().to_le_bytes()[..width]);
            assert_eq!(
                JindoEvaluationProofV1::decode_exact(
                    &mutated,
                    4,
                    u32::try_from(mutated.len()).expect("fixed proof fixture length fits u32")
                ),
                Err(JindoProofCodecErrorV1::NonCanonicalResidue {
                    polynomial_index,
                    modulus_index: 0,
                    coefficient_index: 0,
                    residue: modulus.modulus(),
                    modulus: modulus.modulus(),
                })
            );
        }
    }
    #[test]
    fn every_field_phase_rejects_the_field_modulus() {
        let encoded = proof().encode();
        let mut modulus = [0_u8; JINDO_FIELD_ELEMENT_BYTES_V1];
        for (chunk, limb) in modulus
            .chunks_exact_mut(8)
            .zip(JindoFieldElementV1::MODULUS)
        {
            chunk.copy_from_slice(&limb.to_le_bytes());
        }
        for offset in [
            MASK_SPLIT_EVALUATION_OFFSET,
            BLIND_EVALUATIONS_OFFSET,
            SPLIT_EVALUATIONS_OFFSET,
        ] {
            let mut mutated = encoded.clone();
            mutated[offset..offset + JINDO_FIELD_ELEMENT_BYTES_V1].copy_from_slice(&modulus);
            assert_eq!(
                JindoEvaluationProofV1::decode_exact(
                    &mutated,
                    4,
                    u32::try_from(mutated.len()).expect("fixed proof fixture length fits u32")
                ),
                Err(JindoProofCodecErrorV1::NonCanonicalFieldElement { index: 0 })
            );
        }
    }
    #[test]
    fn late_noncanonical_values_report_exact_wire_indices() {
        let encoded = proof().encode();
        let polynomial_index = MASK_COMMITMENTS - 1;
        let modulus_index = 1;
        let coefficient_index = JINDO_RING_DEGREE_V1 - 1;
        let offset = MASK_COMMITMENTS_OFFSET
            + polynomial_index * JINDO_PROOF_OUTER_POLYNOMIAL_BYTES_V1
            + (modulus_index * JINDO_RING_DEGREE_V1 + coefficient_index)
                * JINDO_PROOF_OUTER_RESIDUE_BYTES_V1;
        let mut residue = encoded.clone();
        let modulus = JINDO_OUTER_MODULI_V1[modulus_index].modulus();
        residue[offset..offset + JINDO_PROOF_OUTER_RESIDUE_BYTES_V1]
            .copy_from_slice(&modulus.to_le_bytes()[..JINDO_PROOF_OUTER_RESIDUE_BYTES_V1]);
        let max_bytes = u32::try_from(encoded.len()).expect("fixed fixture length fits u32");
        assert_eq!(
            JindoEvaluationProofV1::decode_exact(&residue, JINDO_MAX_BATCH_SIZE_V1, max_bytes),
            Err(JindoProofCodecErrorV1::NonCanonicalResidue {
                polynomial_index: u16::try_from(polynomial_index).expect("fixed polynomial index"),
                modulus_index: u8::try_from(modulus_index).expect("two RNS moduli"),
                coefficient_index: u16::try_from(coefficient_index).expect("fixed ring degree"),
                residue: modulus,
                modulus,
            })
        );
        let index = MASK_SPLIT_EVALUATIONS - 1;
        let offset = MASK_SPLIT_EVALUATION_OFFSET + index * JINDO_FIELD_ELEMENT_BYTES_V1;
        let mut field = encoded;
        for (chunk, limb) in field[offset..offset + JINDO_FIELD_ELEMENT_BYTES_V1]
            .chunks_exact_mut(8)
            .zip(JindoFieldElementV1::MODULUS)
        {
            chunk.copy_from_slice(&limb.to_le_bytes());
        }
        assert_eq!(
            JindoEvaluationProofV1::decode_exact(&field, JINDO_MAX_BATCH_SIZE_V1, max_bytes),
            Err(JindoProofCodecErrorV1::NonCanonicalFieldElement {
                index: u16::try_from(index).expect("fixed evaluation count"),
            })
        );
    }
    #[test]
    fn frozen_phase_offsets_cover_the_wire_without_gaps() {
        assert_eq!(MASK_COMMITMENTS_OFFSET, 8);
        assert_eq!(MASK_SPLIT_EVALUATION_OFFSET, 983_048);
        assert_eq!(PARTIALS_OFFSET, 1_114_120);
        assert_eq!(ENCODE_RESPONSES_OFFSET, 1_507_336);
        assert_eq!(MLWE_RESPONSES_OFFSET, 2_686_984);
        assert_eq!(INNER_COMMITMENTS_OFFSET, 5_832_712);
        assert_eq!(BLIND_EVALUATIONS_OFFSET, 7_143_432);
        assert_eq!(SPLIT_EVALUATIONS_OFFSET, 7_143_560);
        assert_eq!(
            SPLIT_EVALUATIONS_OFFSET + SPLIT_EVALUATIONS * JINDO_FIELD_ELEMENT_BYTES_V1,
            JINDO_PROOF_BYTES_V1
        );
    }
}
