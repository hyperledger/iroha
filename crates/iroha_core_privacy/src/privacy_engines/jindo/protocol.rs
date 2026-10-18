//! Revised Jindo `ΠSplit` → `ΠAgg` → `ΠQuad` implementation.
//!
//! This is a clean-room native-Rust implementation of the current paper's
//! univariate coefficient-encoding specialization. The transcript and wire
//! are Iroha-specific and intentionally have no legacy decoder.
#[cfg(test)]
use super::sampling::health_checked_jindo_rng_v1;
use super::{
    JINDO_ENCODING_BASE_V1, JINDO_ENCODING_EXPONENT_V1, JINDO_ENCODING_SLOTS_V1,
    JINDO_MAX_BATCH_SIZE_V1, JINDO_MAX_COEFFICIENTS_V1, JINDO_RING_DEGREE_V1,
    JindoCanonicalPolynomialErrorV1,
    codec::{
        JINDO_PROOF_BYTES_V1, JindoEvaluationProofRepetitionV1, JindoEvaluationProofV1,
        JindoProofCodecErrorV1,
    },
    crs::{commit_key_v1, crs_digest_v1},
    encoding::{
        decode_coefficient_slots_v1, decode_exact_coefficient_slots_v1, encode_coefficient_slots_v1,
    },
    field::JindoFieldElementV1,
    norm::{
        JINDO_DECOMPOSED_NORM_SQUARED_BOUND_V1, JINDO_RESPONSE_NORM_SQUARED_BOUND_V1,
        two_norm_squared_is_below_v1,
    },
    parameters::{
        JINDO_PARALLEL_REPETITIONS_V1, JINDO_PARAMETER_MANIFEST_V1, JINDO_PARAMETERS_V1,
        JINDO_SOURCE_PROVENANCE_V1, JindoGaussianWidthV1,
    },
    ring::{
        JINDO_INNER_MODULI_V1, JINDO_OUTER_MODULI_V1, JindoPrimeModulusV1, JindoRnsPolynomialV1,
    },
    sampling::{
        JindoSamplingErrorV1, accept_aggregation_rejection_v1, sample_gaussian_polynomial_v1,
        sample_mlwe_polynomial_v1, sample_uniform_encoding_polynomial_v1,
    },
    transcript::{JindoSignedMonomialChallengeV1, JindoTranscriptErrorV1, JindoTranscriptV1},
    validate_canonical_polynomial_v1,
};
use crate::privacy_engines::p256::TranscriptBindingV1;
use iroha_data_model::privacy::{
    IROHA_JINDO_LATTICE_COMMITMENT_BYTES_V1, IROHA_JINDO_MAX_ROUNDED_COMMITMENT_COEFFICIENT_V1,
    IROHA_JINDO_MIN_ROUNDED_COMMITMENT_COEFFICIENT_V1, IrohaJindoPolynomialCommitmentStatementV1,
    PrivacyJindoFieldElementV1, PrivacyJindoLatticeCommitmentV1, PrivacyStatementV1,
};
use rand_core_06::{CryptoRng, RngCore};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};
/// Exact byte length of a canonical native Jindo proof.
pub const JINDO_NATIVE_PROOF_BYTES_V1: usize = JINDO_PROOF_BYTES_V1;
/// Reviewed source and parameter profile implemented by this protocol version.
pub const JINDO_SOURCE_PROFILE_V1: &[u8] =
    b"eprint-2026-044-current-figures-2-7-univariate-coefficient-specialization-32x-signed-monomial-hard-cut";
/// Domain identifier for this Jindo protocol suite.
pub const JINDO_SUITE_V1: &[u8] =
    b"iroha-jindo-current-pisplit-piagg-piquad-signed-monomial-32x-v1";
const JINDO_INNER_MODULUS_PRODUCT_V1: u128 =
    JINDO_INNER_MODULI_V1[0].modulus() as u128 * JINDO_INNER_MODULI_V1[1].modulus() as u128;
const JINDO_INNER_BALANCED_MAX_V1: u128 = JINDO_INNER_MODULUS_PRODUCT_V1 / 2;
const JINDO_AGGREGATED_COEFFICIENT_ABS_BOUND_V1: u128 = JindoGaussianWidthV1::AggregateMask
    .tail_radius() as u128
    + JINDO_MAX_BATCH_SIZE_V1 as u128
        * JINDO_PARAMETERS_V1.challenge_l1_bound as u128
        * JINDO_ENCODING_BASE_V1 as u128;
const JINDO_FINAL_RESPONSE_COEFFICIENT_ABS_BOUND_V1: u128 =
    JINDO_PARAMETERS_V1.challenge_l1_bound as u128 * JINDO_AGGREGATED_COEFFICIENT_ABS_BOUND_V1;
const JINDO_EXACT_PARTIAL_ACCUMULATOR_ABS_BOUND_V1: u128 = (JINDO_PARAMETERS_V1.rows as u128 + 1)
    * JINDO_ENCODING_EXPONENT_V1 as u128
    * JINDO_AGGREGATED_COEFFICIENT_ABS_BOUND_V1
    * JINDO_ENCODING_BASE_V1 as u128;
const JINDO_OUTER_RELATION_POLYNOMIALS_V1: usize =
    JINDO_PARAMETERS_V1.inner_msis_rank + JINDO_PARAMETERS_V1.outer_msis_rank;
const JINDO_INNER_RELATION_POLYNOMIALS_V1: usize = JINDO_PARAMETERS_V1.rows
    + 1
    + JINDO_PARAMETERS_V1.mlwe_rank
    + JINDO_PARAMETERS_V1.inner_msis_rank
    + JINDO_PARAMETERS_V1.inner_msis_rank;
const _: () = {
    // Each pre-challenge mask coefficient and each aggregated response
    // coefficient has a unique balanced inner-RNS lift. Exact split
    // evaluation then stays far inside `i128`; the final partial is admitted
    // only when its exact lift also stays inside the balanced inner interval.
    assert!(JINDO_AGGREGATED_COEFFICIENT_ABS_BOUND_V1 < JINDO_INNER_BALANCED_MAX_V1);
    assert!(JINDO_FINAL_RESPONSE_COEFFICIENT_ABS_BOUND_V1 < JINDO_INNER_BALANCED_MAX_V1);
    assert!(JINDO_EXACT_PARTIAL_ACCUMULATOR_ABS_BOUND_V1 < i128::MAX as u128);
    assert!(JINDO_OUTER_RELATION_POLYNOMIALS_V1 == 7);
    assert!(JINDO_INNER_RELATION_POLYNOMIALS_V1 == 15);
};
#[derive(Clone)]
/// Secret opening material for a Jindo polynomial commitment.
///
/// The opening is returned by [`commit_polynomial_v1`] and must match the
/// corresponding witness and commitment passed to [`prove_batched_evaluation_v1`].
pub struct JindoOpeningV1 {
    polynomial: Zeroizing<Vec<JindoFieldElementV1>>,
    blinder: Zeroizing<Vec<JindoFieldElementV1>>,
    encoded: Zeroizing<Vec<JindoRnsPolynomialV1>>,
    mlwe: Zeroizing<Vec<JindoRnsPolynomialV1>>,
    inner_commitments: Zeroizing<Vec<JindoRnsPolynomialV1>>,
    commitment_encoding: Vec<u8>,
}
impl core::fmt::Debug for JindoOpeningV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("JindoOpeningV1([REDACTED])")
    }
}
impl Drop for JindoOpeningV1 {
    fn drop(&mut self) {
        self.commitment_encoding.zeroize();
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Consensus-bound transcript field that failed validation.
pub enum JindoBindingFieldV1 {
    /// Genesis-header-derived network identity.
    NetworkId,
    /// Transaction action index.
    ActionIndex,
    /// Digest of the public statement.
    StatementDigest,
    /// Privacy parameter identifier.
    ParameterId,
    /// Digest of the privacy parameters.
    ParameterDigest,
    /// Digest of the verifier implementation.
    VerifierDigest,
    /// Digest of the statement schema.
    StatementSchemaDigest,
    /// Digest of the privacy-engine manifest.
    EngineManifestDigest,
    /// Digest of the transparent common reference string.
    CrsDigest,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
/// Failure while committing, proving, or verifying with Jindo.
pub enum JindoErrorV1 {
    /// The polynomial batch does not have the protocol's exact size.
    #[error("Jindo requires exactly {expected} polynomials, got {count}")]
    InvalidPolynomialCount {
        /// Actual polynomial count.
        count: usize,
        /// Required polynomial count.
        expected: usize,
    },
    /// A polynomial contains no coefficients.
    #[error("Jindo polynomial {index} is empty")]
    EmptyPolynomial {
        /// Index of the empty polynomial.
        index: usize,
    },
    /// A polynomial exceeds the protocol's coefficient limit.
    #[error("Jindo polynomial {index} has {count} coefficients; maximum is {max}")]
    PolynomialTooLarge {
        /// Index of the oversized polynomial.
        index: usize,
        /// Actual coefficient count.
        count: usize,
        /// Maximum accepted coefficient count.
        max: usize,
    },
    /// A polynomial coefficient is not a canonical field element.
    #[error("Jindo polynomial {polynomial_index} coefficient {coefficient_index} is non-canonical")]
    NonCanonicalCoefficient {
        /// Index of the polynomial containing the coefficient.
        polynomial_index: usize,
        /// Index of the non-canonical coefficient.
        coefficient_index: usize,
    },
    /// A polynomial uses a non-canonical trailing zero coefficient.
    #[error("Jindo polynomial {index} has a trailing zero coefficient")]
    TrailingZeroCoefficient {
        /// Index of the polynomial with the trailing zero.
        index: usize,
    },
    /// The statement's evaluation point is not canonically encoded.
    #[error("Jindo statement evaluation point is non-canonical")]
    NonCanonicalEvaluationPoint,
    /// A claimed evaluation is not canonically encoded.
    #[error("Jindo statement claim {index} is non-canonical")]
    NonCanonicalClaim {
        /// Index of the non-canonical claim.
        index: usize,
    },
    /// The number of claimed evaluations differs from the exact batch size.
    #[error("Jindo claimed-evaluation count differs from the exact batch")]
    ClaimCountMismatch,
    /// The number of commitment openings differs from the exact batch size.
    #[error("Jindo opening count differs from the exact batch")]
    OpeningCountMismatch,
    /// An opening does not match its witness polynomial or public commitment.
    #[error("Jindo opening {index} belongs to another polynomial or commitment")]
    OpeningMismatch {
        /// Index of the mismatched opening.
        index: usize,
    },
    /// A witness polynomial does not evaluate to its public claim.
    #[error("Jindo witness polynomial {index} does not evaluate to its public claim")]
    ClaimMismatch {
        /// Index of the mismatched witness polynomial.
        index: usize,
    },
    /// A public commitment does not have the canonical fixed-width encoding.
    #[error("Jindo commitment {index} has a malformed fixed encoding")]
    InvalidCommitmentEncoding {
        /// Index of the malformed commitment.
        index: usize,
    },
    /// A public commitment uses the forbidden all-zero sentinel.
    #[error("Jindo commitment {index} is the all-zero sentinel")]
    ZeroCommitment {
        /// Index of the all-zero commitment.
        index: usize,
    },
    /// A public commitment duplicates an earlier commitment in the batch.
    #[error("Jindo commitment {index} duplicates an earlier commitment")]
    DuplicateCommitment {
        /// Index of the duplicate commitment.
        index: usize,
    },
    /// The transaction-intent digest required by the binding is zero.
    #[error("Jindo transaction-intent digest must be non-zero")]
    ZeroTransactionIntentDigest,
    /// The action index is not valid for the first protocol release.
    #[error("Jindo first-release action index must be zero, got {index}")]
    InvalidActionIndex {
        /// Unsupported action index.
        index: u32,
    },
    /// A rounded commitment coefficient cannot be represented canonically.
    #[error("Jindo rounded commitment coefficient cannot fit the canonical wire")]
    RoundedCommitmentOutOfRange,
    /// A supplied consensus binding field differs from the statement metadata.
    #[error("Jindo consensus binding mismatches {field:?}")]
    BindingMismatch {
        /// Binding field that differs.
        field: JindoBindingFieldV1,
    },
    /// Canonical encoding of the public statement failed.
    #[error("Jindo statement digest could not be canonically encoded")]
    StatementEncoding,
    /// Sampling prover randomness failed.
    #[error("Jindo prover randomness failed: {0}")]
    Sampling(JindoSamplingErrorV1),
    /// Constructing or deriving the Fiat--Shamir transcript failed.
    #[error("Jindo transcript failed: {0}")]
    Transcript(JindoTranscriptErrorV1),
    /// Encoding or decoding the canonical proof failed.
    #[error("Jindo proof encoding failed: {0}")]
    ProofCodec(JindoProofCodecErrorV1),
    /// Exact coefficient evaluation exceeded the reviewed integer bound.
    #[error("Jindo exact coefficient evaluation exceeded its reviewed integer bound")]
    ExactEvaluationArithmeticOverflow,
    /// The `ΠSplit` augmented-evaluation relation is not satisfied.
    #[error("Jindo ΠSplit augmented-evaluation relation failed")]
    SplitRelation,
    /// The `ΠAgg` outer commitment relation is not satisfied.
    #[error("Jindo ΠAgg outer commitment relation failed")]
    OuterCommitmentRelation,
    /// The `ΠQuad` inner commitment relation is not satisfied.
    #[error("Jindo ΠQuad inner commitment relation failed")]
    InnerCommitmentRelation,
    /// The `ΠQuad` response-consistency relation is not satisfied.
    #[error("Jindo ΠQuad response consistency relation failed")]
    EvaluationConsistency,
    /// The `ΠAgg` partial-evaluation relation is not satisfied.
    #[error("Jindo ΠAgg partial-evaluation relation failed")]
    EvaluationRelation,
    /// The aggregation rejection/no-wrap loop exhausted its fixed budget.
    #[error("Jindo aggregation rejection/no-wrap loop exhausted its fixed budget")]
    AggregationRejectionBudgetExhausted,
    /// The prover's mandatory local verification rejected its generated proof.
    #[error("Jindo prover produced a proof rejected by its own verifier")]
    ProverSelfCheck,
}
impl From<JindoSamplingErrorV1> for JindoErrorV1 {
    fn from(v: JindoSamplingErrorV1) -> Self {
        Self::Sampling(v)
    }
}
impl From<JindoTranscriptErrorV1> for JindoErrorV1 {
    fn from(v: JindoTranscriptErrorV1) -> Self {
        Self::Transcript(v)
    }
}
impl From<JindoProofCodecErrorV1> for JindoErrorV1 {
    fn from(v: JindoProofCodecErrorV1) -> Self {
        Self::ProofCodec(v)
    }
}
impl From<JindoCanonicalPolynomialErrorV1> for JindoErrorV1 {
    fn from(v: JindoCanonicalPolynomialErrorV1) -> Self {
        match v {
            JindoCanonicalPolynomialErrorV1::Empty { polynomial_index } => Self::EmptyPolynomial {
                index: polynomial_index,
            },
            JindoCanonicalPolynomialErrorV1::TooLarge {
                polynomial_index,
                count,
            } => Self::PolynomialTooLarge {
                index: polynomial_index,
                count,
                max: JINDO_MAX_COEFFICIENTS_V1,
            },
            JindoCanonicalPolynomialErrorV1::NonCanonicalCoefficient {
                polynomial_index,
                coefficient_index,
            } => Self::NonCanonicalCoefficient {
                polynomial_index,
                coefficient_index,
            },
            JindoCanonicalPolynomialErrorV1::TrailingZeroCoefficient { polynomial_index } => {
                Self::TrailingZeroCoefficient {
                    index: polynomial_index,
                }
            }
        }
    }
}
#[must_use]
/// Returns the digest of the compiled transparent common reference string.
pub fn jindo_crs_digest_v1() -> [u8; 32] {
    crs_digest_v1()
}
/// Evaluates a canonical Jindo polynomial at a canonical field point.
///
/// # Errors
///
/// Returns an error if the polynomial or evaluation point is not canonical or
/// if the polynomial violates the protocol's size constraints.
pub fn evaluate_polynomial_v1(
    coefficients: &[PrivacyJindoFieldElementV1],
    evaluation_point: PrivacyJindoFieldElementV1,
) -> Result<PrivacyJindoFieldElementV1, JindoErrorV1> {
    let polynomial = parse_polynomial(coefficients, 0)?;
    let point = JindoFieldElementV1::from_canonical_bytes(evaluation_point.encoding)
        .ok_or(JindoErrorV1::NonCanonicalEvaluationPoint)?;
    Ok(PrivacyJindoFieldElementV1::new(
        evaluate_polynomial(&polynomial, point).to_canonical_bytes(),
    ))
}
#[cfg(test)]
/// Commits to a canonical Jindo polynomial and returns its secret opening.
///
/// # Errors
///
/// Returns an error if the polynomial is invalid or randomness sampling fails.
pub fn commit_polynomial_v1<R>(
    coefficients: &[PrivacyJindoFieldElementV1],
    rng: &mut R,
) -> Result<(PrivacyJindoLatticeCommitmentV1, JindoOpeningV1), JindoErrorV1>
where
    R: CryptoRng + RngCore,
{
    let polynomial = parse_polynomial(coefficients, 0)?;
    let mut rng = health_checked_jindo_rng_v1(rng)?;
    commit_parsed_polynomial_v1(polynomial, &mut rng)
}
pub(super) fn commit_polynomial_with_checked_rng_v1<R>(
    coefficients: &[PrivacyJindoFieldElementV1],
    rng: &mut R,
) -> Result<(PrivacyJindoLatticeCommitmentV1, JindoOpeningV1), JindoErrorV1>
where
    R: CryptoRng + RngCore,
{
    commit_parsed_polynomial_v1(parse_polynomial(coefficients, 0)?, rng)
}
fn commit_parsed_polynomial_v1<R>(
    polynomial: Zeroizing<Vec<JindoFieldElementV1>>,
    rng: &mut R,
) -> Result<(PrivacyJindoLatticeCommitmentV1, JindoOpeningV1), JindoErrorV1>
where
    R: CryptoRng + RngCore,
{
    let mut encoded = Zeroizing::new(Vec::with_capacity(JINDO_PARAMETERS_V1.rows + 1));
    for row in 0..JINDO_PARAMETERS_V1.rows {
        let start = row * JINDO_ENCODING_SLOTS_V1;
        encoded.push(
            encode_coefficient_slots_v1(&polynomial[start..start + JINDO_ENCODING_SLOTS_V1])
                .expect("fixed row length"),
        );
    }
    encoded.push(sample_uniform_encoding_polynomial_v1(rng)?);
    let blinder =
        Zeroizing::new(decode_coefficient_slots_v1(&encoded[JINDO_PARAMETERS_V1.rows]).to_vec());
    let count = JINDO_PARAMETERS_V1.mlwe_rank + JINDO_PARAMETERS_V1.inner_msis_rank;
    let mut mlwe = Zeroizing::new(Vec::with_capacity(count));
    for _ in 0..count {
        mlwe.push(sample_mlwe_polynomial_v1(rng)?);
    }
    let inner_commitments = Zeroizing::new(compute_inner_commitments(&encoded, &mlwe));
    let outer = compute_outer_commitment(&inner_commitments);
    let commitment_encoding = encode_public_commitment(&outer)?;
    if commitment_encoding.iter().all(|b| *b == 0) {
        return Err(JindoErrorV1::ZeroCommitment { index: 0 });
    }
    Ok((
        PrivacyJindoLatticeCommitmentV1::new(commitment_encoding.clone()),
        JindoOpeningV1 {
            polynomial,
            blinder,
            encoded,
            mlwe,
            inner_commitments,
            commitment_encoding,
        },
    ))
}
#[cfg(test)]
/// Proves the exact batched-evaluation statement with fresh operating-system randomness.
///
/// # Errors
///
/// Returns an error if the statement, binding, witnesses, commitments, or openings are invalid, or
/// if proof generation or its mandatory self-check fails.
pub fn prove_batched_evaluation_v1(
    statement: &IrohaJindoPolynomialCommitmentStatementV1,
    witness_polynomials: &[Vec<PrivacyJindoFieldElementV1>],
    openings: &[JindoOpeningV1],
    binding: &TranscriptBindingV1<'_>,
) -> Result<Vec<u8>, JindoErrorV1> {
    let mut os_rng = rand_core_06::OsRng;
    let mut rng = health_checked_jindo_rng_v1(&mut os_rng)?;
    prove_batched_evaluation_with_checked_rng_v1(
        statement,
        witness_polynomials,
        openings,
        binding,
        &mut rng,
    )
}
pub(super) fn prove_batched_evaluation_with_checked_rng_v1<R>(
    statement: &IrohaJindoPolynomialCommitmentStatementV1,
    witness_polynomials: &[Vec<PrivacyJindoFieldElementV1>],
    openings: &[JindoOpeningV1],
    binding: &TranscriptBindingV1<'_>,
    rng: &mut R,
) -> Result<Vec<u8>, JindoErrorV1>
where
    R: CryptoRng + RngCore,
{
    let public = validate_statement_and_binding(statement, binding)?;
    require_exact_batch(witness_polynomials.len())?;
    if openings.len() != JINDO_MAX_BATCH_SIZE_V1 {
        return Err(JindoErrorV1::OpeningCountMismatch);
    }
    for index in 0..JINDO_MAX_BATCH_SIZE_V1 {
        let polynomial = parse_polynomial(&witness_polynomials[index], index)?;
        if evaluate_polynomial(&polynomial, public.evaluation_point) != public.claims[index] {
            return Err(JindoErrorV1::ClaimMismatch { index });
        }
        let opening = &openings[index];
        if opening.polynomial.as_slice() != polynomial.as_slice()
            || opening.commitment_encoding != statement.polynomial_commitments[index].encoding
            || !opening_has_fixed_shape(opening)
        {
            return Err(JindoErrorV1::OpeningMismatch { index });
        }
    }
    let mut transcript = statement_transcript(statement, binding)?;
    let blind_evaluations: Vec<_> = openings
        .iter()
        .map(|opening| evaluate_polynomial(&opening.blinder, public.evaluation_point))
        .collect();
    absorb_fields(
        &mut transcript,
        b"split-blind-evaluation",
        &blind_evaluations,
    )?;
    let x_star = transcript.field_challenge(b"split-x-star", 0)?;
    let x_star_ring = encode_scalar(x_star);
    let left = evaluation_left_vector(public.evaluation_point);
    let mut split_evaluations =
        Vec::with_capacity(JINDO_MAX_BATCH_SIZE_V1 * JINDO_ENCODING_SLOTS_V1);
    for opening in openings {
        split_evaluations.extend(split_evaluation(&opening.encoded, &left, &x_star_ring)?);
    }
    verify_split_relations(&public, &blind_evaluations, &split_evaluations, x_star)?;
    absorb_fields(&mut transcript, b"split-evaluation", &split_evaluations)?;
    let aggregation_base = transcript;
    let mut mask_commitments =
        Vec::with_capacity(JINDO_PARALLEL_REPETITIONS_V1 * JINDO_PARAMETERS_V1.outer_msis_rank);
    let mut mask_split_evaluation =
        Vec::with_capacity(JINDO_PARALLEL_REPETITIONS_V1 * JINDO_ENCODING_SLOTS_V1);
    let mut partials = Vec::with_capacity(JINDO_PARALLEL_REPETITIONS_V1);
    let mut encode_responses =
        Vec::with_capacity(JINDO_PARALLEL_REPETITIONS_V1 * (JINDO_PARAMETERS_V1.rows + 1));
    let mut mlwe_responses = Vec::with_capacity(
        JINDO_PARALLEL_REPETITIONS_V1
            * (JINDO_PARAMETERS_V1.mlwe_rank + JINDO_PARAMETERS_V1.inner_msis_rank),
    );
    let mut inner_commitments =
        Vec::with_capacity(JINDO_PARALLEL_REPETITIONS_V1 * JINDO_PARAMETERS_V1.inner_msis_rank);
    for repetition in 0..JINDO_PARALLEL_REPETITIONS_V1 {
        let mut accepted_state = None;
        for _ in 0..JINDO_PARAMETERS_V1.max_rejection_attempts {
            let mut mask_encoded = Zeroizing::new(Vec::with_capacity(JINDO_PARAMETERS_V1.rows + 1));
            for _ in 0..=JINDO_PARAMETERS_V1.rows {
                mask_encoded.push(sample_gaussian_polynomial_v1(
                    JindoGaussianWidthV1::AggregateMask,
                    JINDO_INNER_MODULI_V1,
                    &mut *rng,
                )?);
            }
            let mut mask_mlwe = Zeroizing::new(Vec::with_capacity(
                JINDO_PARAMETERS_V1.mlwe_rank + JINDO_PARAMETERS_V1.inner_msis_rank,
            ));
            for _ in 0..(JINDO_PARAMETERS_V1.mlwe_rank + JINDO_PARAMETERS_V1.inner_msis_rank) {
                mask_mlwe.push(sample_gaussian_polynomial_v1(
                    JindoGaussianWidthV1::AggregateMask,
                    JINDO_INNER_MODULI_V1,
                    &mut *rng,
                )?);
            }
            let mask_inner = compute_inner_commitments(&mask_encoded, &mask_mlwe);
            let repetition_mask_commitments = compute_outer_commitment(&mask_inner);
            let repetition_mask_split_evaluation =
                split_evaluation(&mask_encoded, &left, &x_star_ring)?;
            let mut trial = aggregation_base.clone();
            trial.append_message(
                b"parallel-repetition",
                &u32::try_from(repetition)
                    .expect("fixed Jindo repetition count fits u32")
                    .to_be_bytes(),
            )?;
            absorb_polynomials(
                &mut trial,
                b"aggregation-mask-commitment",
                &repetition_mask_commitments,
            )?;
            absorb_fields(
                &mut trial,
                b"aggregation-mask-evaluation",
                &repetition_mask_split_evaluation,
            )?;
            let alpha =
                monomial_challenges(&mut trial, b"aggregation-alpha", JINDO_MAX_BATCH_SIZE_V1)?;
            let no_mask_encoded = combine_opening_polynomials(openings, &alpha, |o| &o.encoded);
            let no_mask_mlwe = combine_opening_polynomials(openings, &alpha, |o| &o.mlwe);
            let exponent =
                rejection_exponent(&mask_encoded, &no_mask_encoded, &mask_mlwe, &no_mask_mlwe)?;
            if !accept_aggregation_rejection_v1(exponent, &mut *rng)? {
                continue;
            }
            let repetition_encoded_responses =
                add_polynomial_vectors(&mask_encoded, &no_mask_encoded, JINDO_INNER_MODULI_V1);
            let repetition_mlwe_responses =
                add_polynomial_vectors(&mask_mlwe, &no_mask_mlwe, JINDO_INNER_MODULI_V1);
            let Some(partial) =
                response_partial_without_wrap(&repetition_encoded_responses, &left, &x_star_ring)?
            else {
                // The reference implementation's ambient basis establishes
                // the exact integer value before reducing to the proof basis.
                // Only a unique balanced lift is allowed onto the proof wire.
                continue;
            };
            let combined_inner_no_mask =
                combine_opening_polynomials(openings, &alpha, |o| &o.inner_commitments);
            let repetition_inner_commitments =
                add_polynomial_vectors(&mask_inner, &combined_inner_no_mask, JINDO_OUTER_MODULI_V1);
            accepted_state = Some((
                trial,
                repetition_mask_commitments,
                repetition_mask_split_evaluation,
                repetition_encoded_responses,
                repetition_mlwe_responses,
                repetition_inner_commitments,
                partial,
            ));
            break;
        }
        let Some((
            mut repetition_transcript,
            repetition_mask_commitments,
            repetition_mask_split_evaluation,
            aggregated_encoded,
            aggregated_mlwe,
            repetition_inner_commitments,
            partial,
        )) = accepted_state
        else {
            return Err(JindoErrorV1::AggregationRejectionBudgetExhausted);
        };
        absorb_polynomials(
            &mut repetition_transcript,
            b"quadratic-partial",
            core::slice::from_ref(&partial),
        )?;
        let c = repetition_transcript.monomial_challenge(b"quadratic-column", 0)?;
        let c_inner = c.inner_polynomial();
        encode_responses.extend(
            aggregated_encoded
                .iter()
                .map(|value| value.mul(&c_inner, JINDO_INNER_MODULI_V1)),
        );
        mlwe_responses.extend(
            aggregated_mlwe
                .iter()
                .map(|value| value.mul(&c_inner, JINDO_INNER_MODULI_V1)),
        );
        mask_commitments.extend(repetition_mask_commitments);
        mask_split_evaluation.extend(repetition_mask_split_evaluation);
        partials.push(partial);
        inner_commitments.extend(repetition_inner_commitments);
    }
    let proof = JindoEvaluationProofV1::new(
        mask_commitments,
        mask_split_evaluation,
        partials,
        encode_responses,
        mlwe_responses,
        inner_commitments,
        blind_evaluations,
        split_evaluations,
    )?;
    let encoded = proof.encode();
    verify_batched_evaluation_v1(statement, &encoded, binding, encoded.len() as u32)
        .map_err(|_| JindoErrorV1::ProverSelfCheck)?;
    Ok(encoded)
}
/// Verifies a canonical proof for an exact batched-evaluation statement.
///
/// # Errors
///
/// Returns an error if the statement or consensus binding is invalid, the
/// proof wire is malformed or too large, or any Jindo relation fails.
pub fn verify_batched_evaluation_v1(
    statement: &IrohaJindoPolynomialCommitmentStatementV1,
    proof_bytes: &[u8],
    binding: &TranscriptBindingV1<'_>,
    max_proof_bytes: u32,
) -> Result<(), JindoErrorV1> {
    let public = validate_statement_and_binding(statement, binding)?;
    let proof = JindoEvaluationProofV1::decode_exact(
        proof_bytes,
        JINDO_MAX_BATCH_SIZE_V1,
        max_proof_bytes,
    )?;
    let commitments = statement
        .polynomial_commitments
        .iter()
        .enumerate()
        .map(|(i, c)| parse_public_commitment(c, i))
        .collect::<Result<Vec<_>, _>>()?;
    let mut transcript = statement_transcript(statement, binding)?;
    absorb_fields(
        &mut transcript,
        b"split-blind-evaluation",
        &proof.blind_evaluations,
    )?;
    let x_star = transcript.field_challenge(b"split-x-star", 0)?;
    absorb_fields(
        &mut transcript,
        b"split-evaluation",
        &proof.split_evaluations,
    )?;
    verify_split_relations(
        &public,
        &proof.blind_evaluations,
        &proof.split_evaluations,
        x_star,
    )?;
    let aggregation_base = transcript;
    for repetition in 0..JINDO_PARALLEL_REPETITIONS_V1 {
        let repetition_proof = proof.repetition(repetition);
        let mut repetition_transcript = aggregation_base.clone();
        repetition_transcript.append_message(
            b"parallel-repetition",
            &u32::try_from(repetition)
                .expect("fixed Jindo repetition count fits u32")
                .to_be_bytes(),
        )?;
        absorb_polynomials(
            &mut repetition_transcript,
            b"aggregation-mask-commitment",
            repetition_proof.mask_commitments,
        )?;
        absorb_fields(
            &mut repetition_transcript,
            b"aggregation-mask-evaluation",
            repetition_proof.mask_split_evaluation,
        )?;
        let alpha = monomial_challenges(
            &mut repetition_transcript,
            b"aggregation-alpha",
            JINDO_MAX_BATCH_SIZE_V1,
        )?;
        absorb_polynomials(
            &mut repetition_transcript,
            b"quadratic-partial",
            repetition_proof.partials,
        )?;
        let c = repetition_transcript.monomial_challenge(b"quadratic-column", 0)?;
        verify_outer_relation(&repetition_proof, &commitments, &alpha)?;
        verify_inner_relation(&repetition_proof, &c)?;
        verify_consistency_relation(&repetition_proof, public.evaluation_point, x_star, &c)?;
        verify_evaluation_relation(&repetition_proof, &proof.split_evaluations, &alpha)?;
    }
    Ok(())
}
struct ParsedPublicStatementV1 {
    evaluation_point: JindoFieldElementV1,
    claims: Vec<JindoFieldElementV1>,
}
fn require_exact_batch(count: usize) -> Result<(), JindoErrorV1> {
    if count != JINDO_MAX_BATCH_SIZE_V1 {
        return Err(JindoErrorV1::InvalidPolynomialCount {
            count,
            expected: JINDO_MAX_BATCH_SIZE_V1,
        });
    }
    Ok(())
}
fn validate_statement_and_binding(
    statement: &IrohaJindoPolynomialCommitmentStatementV1,
    binding: &TranscriptBindingV1<'_>,
) -> Result<ParsedPublicStatementV1, JindoErrorV1> {
    binding
        .validate()
        .map_err(JindoTranscriptErrorV1::Binding)?;
    require_exact_batch(statement.polynomial_commitments.len())?;
    if statement.claimed_evaluations.len() != JINDO_MAX_BATCH_SIZE_V1 {
        return Err(JindoErrorV1::ClaimCountMismatch);
    }
    for (index, commitment) in statement.polynomial_commitments.iter().enumerate() {
        parse_public_commitment(commitment, index)?;
        if statement.polynomial_commitments[..index]
            .iter()
            .any(|v| v.encoding == commitment.encoding)
        {
            return Err(JindoErrorV1::DuplicateCommitment { index });
        }
    }
    let evaluation_point =
        JindoFieldElementV1::from_canonical_bytes(statement.evaluation_point.encoding)
            .ok_or(JindoErrorV1::NonCanonicalEvaluationPoint)?;
    let claims = statement
        .claimed_evaluations
        .iter()
        .enumerate()
        .map(|(index, v)| {
            JindoFieldElementV1::from_canonical_bytes(v.encoding)
                .ok_or(JindoErrorV1::NonCanonicalClaim { index })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let context = &statement.context;
    if context.transaction_intent_digest.is_zero() {
        return Err(JindoErrorV1::ZeroTransactionIntentDigest);
    }
    if context.action_index != 0 {
        return Err(JindoErrorV1::InvalidActionIndex {
            index: context.action_index,
        });
    }
    for (field, supplied, expected) in [
        (
            JindoBindingFieldV1::ParameterId,
            binding.parameter_id,
            *context.parameter_id.as_bytes(),
        ),
        (
            JindoBindingFieldV1::ParameterDigest,
            binding.parameter_digest,
            *context.parameter_digest.as_bytes(),
        ),
        (
            JindoBindingFieldV1::VerifierDigest,
            binding.verifier_digest,
            *context.verifier_digest.as_bytes(),
        ),
        (
            JindoBindingFieldV1::StatementSchemaDigest,
            binding.statement_schema_digest,
            *context.statement_schema_digest.as_bytes(),
        ),
        (
            JindoBindingFieldV1::EngineManifestDigest,
            binding.engine_manifest_digest,
            *context.engine_manifest_digest.as_bytes(),
        ),
    ] {
        if supplied != expected {
            return Err(JindoErrorV1::BindingMismatch { field });
        }
    }
    if binding.network_id != context.network_id.as_bytes() {
        return Err(JindoErrorV1::BindingMismatch {
            field: JindoBindingFieldV1::NetworkId,
        });
    }
    if binding.action_index != context.action_index {
        return Err(JindoErrorV1::BindingMismatch {
            field: JindoBindingFieldV1::ActionIndex,
        });
    }
    if binding.generator_digest != crs_digest_v1() {
        return Err(JindoErrorV1::BindingMismatch {
            field: JindoBindingFieldV1::CrsDigest,
        });
    }
    let digest = PrivacyStatementV1::IrohaJindoPolynomialCommitmentV1(statement.clone())
        .digest()
        .map_err(|_| JindoErrorV1::StatementEncoding)?;
    if binding.statement_digest != *digest.as_bytes() {
        return Err(JindoErrorV1::BindingMismatch {
            field: JindoBindingFieldV1::StatementDigest,
        });
    }
    Ok(ParsedPublicStatementV1 {
        evaluation_point,
        claims,
    })
}
fn statement_transcript(
    statement: &IrohaJindoPolynomialCommitmentStatementV1,
    binding: &TranscriptBindingV1<'_>,
) -> Result<JindoTranscriptV1, JindoErrorV1> {
    let mut t = JindoTranscriptV1::new(binding, crs_digest_v1())?;
    t.append_message(b"suite", JINDO_SUITE_V1)?;
    t.append_message(b"source-profile", JINDO_SOURCE_PROFILE_V1)?;
    t.append_message(b"source-provenance", JINDO_SOURCE_PROVENANCE_V1)?;
    t.append_message(b"parameter-manifest", JINDO_PARAMETER_MANIFEST_V1)?;
    t.append_message(
        b"batch-count",
        &(JINDO_MAX_BATCH_SIZE_V1 as u32).to_be_bytes(),
    )?;
    for (i, c) in statement.polynomial_commitments.iter().enumerate() {
        t.append_message(&indexed_label(b"commitment", i), &c.encoding)?;
    }
    t.append_message(b"evaluation-point", &statement.evaluation_point.encoding)?;
    for (i, y) in statement.claimed_evaluations.iter().enumerate() {
        t.append_message(&indexed_label(b"claim", i), &y.encoding)?;
    }
    Ok(t)
}
fn parse_polynomial(
    values: &[PrivacyJindoFieldElementV1],
    index: usize,
) -> Result<Zeroizing<Vec<JindoFieldElementV1>>, JindoErrorV1> {
    validate_canonical_polynomial_v1(values, index)?;
    let mut out = Zeroizing::new(vec![JindoFieldElementV1::ZERO; JINDO_MAX_COEFFICIENTS_V1]);
    for (coefficient_index, value) in values.iter().enumerate() {
        out[coefficient_index] = JindoFieldElementV1::from_canonical_bytes(value.encoding).ok_or(
            JindoErrorV1::NonCanonicalCoefficient {
                polynomial_index: index,
                coefficient_index,
            },
        )?;
    }
    Ok(out)
}
fn compute_inner_commitments(
    encoded: &[JindoRnsPolynomialV1],
    mlwe: &[JindoRnsPolynomialV1],
) -> Vec<JindoRnsPolynomialV1> {
    let key = commit_key_v1();
    (0..JINDO_PARAMETERS_V1.inner_msis_rank)
        .map(|row| {
            let mut value = JindoRnsPolynomialV1::zero();
            for (matrix, secret) in key.inner[row].iter().zip(encoded) {
                value.add_assign(
                    &matrix.mul(secret, JINDO_INNER_MODULI_V1),
                    JINDO_INNER_MODULI_V1,
                );
            }
            for (matrix, secret) in key.mlwe[row]
                .iter()
                .zip(&mlwe[..JINDO_PARAMETERS_V1.mlwe_rank])
            {
                value.add_assign(
                    &matrix.mul(secret, JINDO_INNER_MODULI_V1),
                    JINDO_INNER_MODULI_V1,
                );
            }
            value.add_assign(
                &mlwe[JINDO_PARAMETERS_V1.mlwe_rank + row],
                JINDO_INNER_MODULI_V1,
            );
            cut_power_of_two_and_change_basis(
                &value,
                JINDO_INNER_MODULI_V1,
                JINDO_OUTER_MODULI_V1,
                JINDO_PARAMETERS_V1.log_inner_cutoff,
            )
        })
        .collect()
}
fn compute_outer_commitment(inner: &[JindoRnsPolynomialV1]) -> Vec<JindoRnsPolynomialV1> {
    let key = commit_key_v1();
    (0..JINDO_PARAMETERS_V1.outer_msis_rank)
        .map(|row| {
            let mut value = JindoRnsPolynomialV1::zero();
            for (matrix, secret) in key.outer[row].iter().zip(inner) {
                value.add_assign(
                    &matrix.mul(secret, JINDO_OUTER_MODULI_V1),
                    JINDO_OUTER_MODULI_V1,
                );
            }
            cut_power_of_two_and_change_basis(
                &value,
                JINDO_OUTER_MODULI_V1,
                JINDO_OUTER_MODULI_V1,
                JINDO_PARAMETERS_V1.log_outer_cutoff,
            )
        })
        .collect()
}
fn encode_public_commitment(polynomials: &[JindoRnsPolynomialV1]) -> Result<Vec<u8>, JindoErrorV1> {
    let mut out = Vec::with_capacity(IROHA_JINDO_LATTICE_COMMITMENT_BYTES_V1);
    for polynomial in polynomials {
        for index in 0..JINDO_RING_DEGREE_V1 {
            let value =
                i32::try_from(polynomial.balanced_coefficient(index, JINDO_OUTER_MODULI_V1))
                    .map_err(|_| JindoErrorV1::RoundedCommitmentOutOfRange)?;
            if !(IROHA_JINDO_MIN_ROUNDED_COMMITMENT_COEFFICIENT_V1
                ..=IROHA_JINDO_MAX_ROUNDED_COMMITMENT_COEFFICIENT_V1)
                .contains(&value)
            {
                return Err(JindoErrorV1::RoundedCommitmentOutOfRange);
            }
            out.extend_from_slice(&value.to_le_bytes());
        }
    }
    Ok(out)
}
fn parse_public_commitment(
    c: &PrivacyJindoLatticeCommitmentV1,
    index: usize,
) -> Result<Vec<JindoRnsPolynomialV1>, JindoErrorV1> {
    if c.encoding.len() != IROHA_JINDO_LATTICE_COMMITMENT_BYTES_V1 {
        return Err(JindoErrorV1::InvalidCommitmentEncoding { index });
    }
    let mut any = false;
    let mut out = Vec::with_capacity(JINDO_PARAMETERS_V1.outer_msis_rank);
    for row in 0..JINDO_PARAMETERS_V1.outer_msis_rank {
        let mut coefficients = [0_i128; JINDO_RING_DEGREE_V1];
        for (column, coefficient) in coefficients.iter_mut().enumerate() {
            let offset = (row * JINDO_RING_DEGREE_V1 + column) * 4;
            let value = i32::from_le_bytes(
                c.encoding[offset..offset + 4]
                    .try_into()
                    .expect("width checked"),
            );
            if !(IROHA_JINDO_MIN_ROUNDED_COMMITMENT_COEFFICIENT_V1
                ..=IROHA_JINDO_MAX_ROUNDED_COMMITMENT_COEFFICIENT_V1)
                .contains(&value)
            {
                return Err(JindoErrorV1::InvalidCommitmentEncoding { index });
            }
            any |= value != 0;
            *coefficient = i128::from(value);
        }
        out.push(JindoRnsPolynomialV1::from_balanced_coefficients(
            coefficients,
            JINDO_OUTER_MODULI_V1,
        ));
    }
    if !any {
        return Err(JindoErrorV1::ZeroCommitment { index });
    }
    Ok(out)
}
fn evaluation_left_vector(x: JindoFieldElementV1) -> Vec<JindoRnsPolynomialV1> {
    (0..JINDO_PARAMETERS_V1.rows)
        .map(|row| {
            encode_scalar(field_pow(
                x,
                row * JINDO_PARAMETERS_V1.columns * JINDO_ENCODING_SLOTS_V1,
            ))
        })
        .collect()
}
fn encode_scalar(value: JindoFieldElementV1) -> JindoRnsPolynomialV1 {
    encode_coefficient_slots_v1(&[value]).expect("one slot")
}
fn split_evaluation(
    encoded: &[JindoRnsPolynomialV1],
    left: &[JindoRnsPolynomialV1],
    x_star: &JindoRnsPolynomialV1,
) -> Result<Vec<JindoFieldElementV1>, JindoErrorV1> {
    // The Go oracle uses its third ambient CRT prime for this step. Evaluate
    // the same integer polynomial exactly instead of decoding a potentially
    // wrapped two-prime residue.
    Ok(
        decode_exact_coefficient_slots_v1(&exact_augmented_evaluation_coefficients(
            encoded, left, x_star,
        )?)
        .to_vec(),
    )
}
fn exact_augmented_evaluation_coefficients(
    encoded: &[JindoRnsPolynomialV1],
    left: &[JindoRnsPolynomialV1],
    x_star: &JindoRnsPolynomialV1,
) -> Result<[i128; JINDO_RING_DEGREE_V1], JindoErrorV1> {
    debug_assert_eq!(encoded.len(), JINDO_PARAMETERS_V1.rows + 1);
    debug_assert_eq!(left.len(), JINDO_PARAMETERS_V1.rows);
    let mut value = [0_i128; JINDO_RING_DEGREE_V1];
    for row in 0..JINDO_PARAMETERS_V1.rows {
        add_exact_encoded_scalar_product(&mut value, &encoded[row], &left[row])?;
    }
    add_exact_encoded_scalar_product(&mut value, &encoded[JINDO_PARAMETERS_V1.rows], x_star)?;
    Ok(value)
}
fn add_exact_encoded_scalar_product(
    accumulator: &mut [i128; JINDO_RING_DEGREE_V1],
    polynomial: &JindoRnsPolynomialV1,
    encoded_scalar: &JindoRnsPolynomialV1,
) -> Result<(), JindoErrorV1> {
    // Coefficient encoding of one scalar has exactly eight possible nonzero
    // digits, at offsets `0, 128, ..., 896`. This is the fixed-profile
    // negacyclic convolution, performed over the integers.
    for digit in 0..JINDO_ENCODING_EXPONENT_V1 {
        let scalar_index = digit * JINDO_ENCODING_SLOTS_V1;
        let scalar = encoded_scalar.balanced_coefficient(scalar_index, JINDO_INNER_MODULI_V1);
        for polynomial_index in 0..JINDO_RING_DEGREE_V1 {
            let product = polynomial
                .balanced_coefficient(polynomial_index, JINDO_INNER_MODULI_V1)
                .checked_mul(scalar)
                .ok_or(JindoErrorV1::ExactEvaluationArithmeticOverflow)?;
            let unfolded_index = polynomial_index + scalar_index;
            let (target_index, contribution) = if unfolded_index < JINDO_RING_DEGREE_V1 {
                (unfolded_index, product)
            } else {
                (
                    unfolded_index - JINDO_RING_DEGREE_V1,
                    product
                        .checked_neg()
                        .ok_or(JindoErrorV1::ExactEvaluationArithmeticOverflow)?,
                )
            };
            accumulator[target_index] = accumulator[target_index]
                .checked_add(contribution)
                .ok_or(JindoErrorV1::ExactEvaluationArithmeticOverflow)?;
        }
    }
    Ok(())
}
fn response_partial_without_wrap(
    encoded: &[JindoRnsPolynomialV1],
    left: &[JindoRnsPolynomialV1],
    x_star: &JindoRnsPolynomialV1,
) -> Result<Option<JindoRnsPolynomialV1>, JindoErrorV1> {
    let coefficients = exact_augmented_evaluation_coefficients(encoded, left, x_star)?;
    if !coefficients_have_unique_inner_balanced_lift(&coefficients) {
        return Ok(None);
    }
    let exact =
        JindoRnsPolynomialV1::from_balanced_coefficients(coefficients, JINDO_INNER_MODULI_V1);
    debug_assert_eq!(exact, response_partial(encoded, left, x_star));
    Ok(Some(exact))
}
fn coefficients_have_unique_inner_balanced_lift(
    coefficients: &[i128; JINDO_RING_DEGREE_V1],
) -> bool {
    coefficients
        .iter()
        .all(|coefficient| coefficient.unsigned_abs() <= JINDO_INNER_BALANCED_MAX_V1)
}
fn response_partial(
    encoded: &[JindoRnsPolynomialV1],
    left: &[JindoRnsPolynomialV1],
    x_star: &JindoRnsPolynomialV1,
) -> JindoRnsPolynomialV1 {
    let mut value = JindoRnsPolynomialV1::zero();
    for row in 0..JINDO_PARAMETERS_V1.rows {
        value.add_assign(
            &encoded[row].mul(&left[row], JINDO_INNER_MODULI_V1),
            JINDO_INNER_MODULI_V1,
        );
    }
    value.add_assign(
        &encoded[JINDO_PARAMETERS_V1.rows].mul(x_star, JINDO_INNER_MODULI_V1),
        JINDO_INNER_MODULI_V1,
    );
    value
}
fn monomial_challenges(
    t: &mut JindoTranscriptV1,
    label: &[u8],
    count: usize,
) -> Result<Vec<JindoSignedMonomialChallengeV1>, JindoErrorV1> {
    (0..count)
        .map(|i| t.monomial_challenge(label, i as u32).map_err(Into::into))
        .collect()
}
fn combine_opening_polynomials<F>(
    openings: &[JindoOpeningV1],
    alpha: &[JindoSignedMonomialChallengeV1],
    field: F,
) -> Vec<JindoRnsPolynomialV1>
where
    F: Fn(&JindoOpeningV1) -> &[JindoRnsPolynomialV1],
{
    let count = field(&openings[0]).len();
    let moduli = if count == JINDO_PARAMETERS_V1.inner_msis_rank {
        JINDO_OUTER_MODULI_V1
    } else {
        JINDO_INNER_MODULI_V1
    };
    let mut out = vec![JindoRnsPolynomialV1::zero(); count];
    for (opening, challenge) in openings.iter().zip(alpha) {
        let polynomial = challenge.polynomial(moduli);
        for (target, source) in out.iter_mut().zip(field(opening)) {
            target.add_assign(&source.mul(&polynomial, moduli), moduli);
        }
    }
    out
}
fn add_polynomial_vectors(
    left: &[JindoRnsPolynomialV1],
    right: &[JindoRnsPolynomialV1],
    moduli: [JindoPrimeModulusV1; 2],
) -> Vec<JindoRnsPolynomialV1> {
    left.iter()
        .zip(right)
        .map(|(a, b)| {
            let mut v = a.clone();
            v.add_assign(b, moduli);
            v
        })
        .collect()
}
fn rejection_exponent(
    mask_encoded: &[JindoRnsPolynomialV1],
    value_encoded: &[JindoRnsPolynomialV1],
    mask_mlwe: &[JindoRnsPolynomialV1],
    value_mlwe: &[JindoRnsPolynomialV1],
) -> Result<i128, JindoErrorV1> {
    let mut total = 0_i128;
    for (mask, value) in mask_encoded
        .iter()
        .chain(mask_mlwe)
        .zip(value_encoded.iter().chain(value_mlwe))
    {
        for index in 0..JINDO_RING_DEGREE_V1 {
            let y = mask.balanced_coefficient(index, JINDO_INNER_MODULI_V1);
            let v = value.balanced_coefficient(index, JINDO_INNER_MODULI_V1);
            let term = v
                .checked_mul(v)
                .and_then(|sq| {
                    y.checked_mul(v)
                        .and_then(|yv| yv.checked_mul(2).and_then(|twice| sq.checked_add(twice)))
                })
                .ok_or(JindoSamplingErrorV1::ArithmeticOverflow)?;
            total = total
                .checked_sub(term)
                .ok_or(JindoSamplingErrorV1::ArithmeticOverflow)?;
        }
    }
    Ok(total)
}
fn verify_split_relations(
    public: &ParsedPublicStatementV1,
    blinds: &[JindoFieldElementV1],
    splits: &[JindoFieldElementV1],
    x_star: JindoFieldElementV1,
) -> Result<(), JindoErrorV1> {
    if blinds.len() != 4 || splits.len() != 4 * JINDO_ENCODING_SLOTS_V1 {
        return Err(JindoErrorV1::SplitRelation);
    }
    for i in 0..4 {
        let expected = public.claims[i] + x_star * blinds[i];
        let actual = splits[i * JINDO_ENCODING_SLOTS_V1..(i + 1) * JINDO_ENCODING_SLOTS_V1]
            .iter()
            .rev()
            .fold(JindoFieldElementV1::ZERO, |sum, value| {
                sum * public.evaluation_point + *value
            });
        if expected != actual {
            return Err(JindoErrorV1::SplitRelation);
        }
    }
    Ok(())
}
fn verify_outer_relation(
    proof: &JindoEvaluationProofRepetitionV1<'_>,
    commitments: &[Vec<JindoRnsPolynomialV1>],
    alpha: &[JindoSignedMonomialChallengeV1],
) -> Result<(), JindoErrorV1> {
    let key = commit_key_v1();
    let mut relation = proof.inner_commitments.to_vec();
    relation.reserve(JINDO_PARAMETERS_V1.outer_msis_rank);
    for row in 0..JINDO_PARAMETERS_V1.outer_msis_rank {
        let mut commitment = proof.mask_commitments[row].clone();
        for (public, challenge) in commitments.iter().zip(alpha) {
            commitment.add_assign(
                &public[row].mul(&challenge.outer_polynomial(), JINDO_OUTER_MODULI_V1),
                JINDO_OUTER_MODULI_V1,
            );
        }
        let mut residual = commitment
            .scale_power_of_two(JINDO_PARAMETERS_V1.log_outer_cutoff, JINDO_OUTER_MODULI_V1);
        for (matrix, value) in key.outer[row].iter().zip(proof.inner_commitments.iter()) {
            residual.sub_assign(
                &matrix.mul(value, JINDO_OUTER_MODULI_V1),
                JINDO_OUTER_MODULI_V1,
            );
        }
        relation.push(residual);
    }
    debug_assert_eq!(relation.len(), JINDO_OUTER_RELATION_POLYNOMIALS_V1);
    if !two_norm_squared_is_below_v1(
        &relation,
        JINDO_OUTER_MODULI_V1,
        JINDO_DECOMPOSED_NORM_SQUARED_BOUND_V1,
    ) {
        return Err(JindoErrorV1::OuterCommitmentRelation);
    }
    Ok(())
}
fn verify_inner_relation(
    proof: &JindoEvaluationProofRepetitionV1<'_>,
    c: &JindoSignedMonomialChallengeV1,
) -> Result<(), JindoErrorV1> {
    let key = commit_key_v1();
    let c_inner = c.inner_polynomial();
    let mut relation = Vec::with_capacity(JINDO_INNER_RELATION_POLYNOMIALS_V1);
    relation.extend(proof.encode_responses.iter().cloned());
    relation.extend(proof.mlwe_responses.iter().cloned());
    for row in 0..JINDO_PARAMETERS_V1.inner_msis_rank {
        let embedded = change_basis(
            &proof.inner_commitments[row],
            JINDO_OUTER_MODULI_V1,
            JINDO_INNER_MODULI_V1,
        );
        let mut residual = embedded
            .mul(&c_inner, JINDO_INNER_MODULI_V1)
            .scale_power_of_two(JINDO_PARAMETERS_V1.log_inner_cutoff, JINDO_INNER_MODULI_V1);
        for (matrix, value) in key.inner[row].iter().zip(proof.encode_responses.iter()) {
            residual.sub_assign(
                &matrix.mul(value, JINDO_INNER_MODULI_V1),
                JINDO_INNER_MODULI_V1,
            );
        }
        for (matrix, value) in key.mlwe[row]
            .iter()
            .zip(&proof.mlwe_responses[..JINDO_PARAMETERS_V1.mlwe_rank])
        {
            residual.sub_assign(
                &matrix.mul(value, JINDO_INNER_MODULI_V1),
                JINDO_INNER_MODULI_V1,
            );
        }
        residual.sub_assign(
            &proof.mlwe_responses[JINDO_PARAMETERS_V1.mlwe_rank + row],
            JINDO_INNER_MODULI_V1,
        );
        relation.push(residual);
    }
    debug_assert_eq!(relation.len(), JINDO_INNER_RELATION_POLYNOMIALS_V1);
    if !two_norm_squared_is_below_v1(
        &relation,
        JINDO_INNER_MODULI_V1,
        JINDO_RESPONSE_NORM_SQUARED_BOUND_V1,
    ) {
        return Err(JindoErrorV1::InnerCommitmentRelation);
    }
    Ok(())
}
fn verify_consistency_relation(
    proof: &JindoEvaluationProofRepetitionV1<'_>,
    x: JindoFieldElementV1,
    x_star: JindoFieldElementV1,
    c: &JindoSignedMonomialChallengeV1,
) -> Result<(), JindoErrorV1> {
    let left = evaluation_left_vector(x);
    let x_star = encode_scalar(x_star);
    let mut relation = response_partial(proof.encode_responses, &left, &x_star);
    relation.sub_assign(
        &proof.partials[0].mul(&c.inner_polynomial(), JINDO_INNER_MODULI_V1),
        JINDO_INNER_MODULI_V1,
    );
    if !relation.is_zero() {
        return Err(JindoErrorV1::EvaluationConsistency);
    }
    Ok(())
}
fn verify_evaluation_relation(
    proof: &JindoEvaluationProofRepetitionV1<'_>,
    split_evaluations: &[JindoFieldElementV1],
    alpha: &[JindoSignedMonomialChallengeV1],
) -> Result<(), JindoErrorV1> {
    let mut expected =
        encode_coefficient_slots_v1(proof.mask_split_evaluation).expect("fixed slots");
    for (split, challenge) in split_evaluations
        .chunks_exact(JINDO_ENCODING_SLOTS_V1)
        .zip(alpha)
    {
        let encoded = encode_coefficient_slots_v1(split).expect("fixed slots");
        expected.add_assign(
            &encoded.mul(&challenge.inner_polynomial(), JINDO_INNER_MODULI_V1),
            JINDO_INNER_MODULI_V1,
        );
    }
    if decode_coefficient_slots_v1(&expected) != decode_coefficient_slots_v1(&proof.partials[0]) {
        return Err(JindoErrorV1::EvaluationRelation);
    }
    Ok(())
}
/// Apply the paper/oracle `Pow2Cutter.CutTo` map coefficient-wise.
///
/// For a centered integer `x`, the upstream algebra subtracts the canonical residue modulo
/// `2^exponent` and divides the result by `2^exponent`. This is exactly Euclidean floor division,
/// including for negative coefficients; it is deliberately not nearest-integer rounding.
fn cut_power_of_two_and_change_basis(
    p: &JindoRnsPolynomialV1,
    source: [JindoPrimeModulusV1; 2],
    dest: [JindoPrimeModulusV1; 2],
    exponent: u32,
) -> JindoRnsPolynomialV1 {
    let coefficients = core::array::from_fn(|i| {
        cut_power_of_two_coefficient(p.balanced_coefficient(i, source), exponent)
    });
    JindoRnsPolynomialV1::from_balanced_coefficients(coefficients, dest)
}
fn cut_power_of_two_coefficient(value: i128, exponent: u32) -> i128 {
    value.div_euclid(1_i128 << exponent)
}
fn change_basis(
    p: &JindoRnsPolynomialV1,
    source: [JindoPrimeModulusV1; 2],
    dest: [JindoPrimeModulusV1; 2],
) -> JindoRnsPolynomialV1 {
    JindoRnsPolynomialV1::from_balanced_coefficients(
        core::array::from_fn(|i| p.balanced_coefficient(i, source)),
        dest,
    )
}
fn evaluate_polynomial(
    poly: &[JindoFieldElementV1],
    x: JindoFieldElementV1,
) -> JindoFieldElementV1 {
    poly.iter()
        .rev()
        .fold(JindoFieldElementV1::ZERO, |v, c| v * x + *c)
}
fn field_pow(mut base: JindoFieldElementV1, mut exponent: usize) -> JindoFieldElementV1 {
    let mut out = JindoFieldElementV1::ONE;
    while exponent != 0 {
        if exponent & 1 == 1 {
            out = out * base
        }
        base = base * base;
        exponent >>= 1
    }
    out
}
fn opening_has_fixed_shape(o: &JindoOpeningV1) -> bool {
    o.polynomial.len() == 256
        && o.blinder.len() == 128
        && o.encoded.len() == 3
        && o.mlwe.len() == 8
        && o.inner_commitments.len() == 4
        && o.commitment_encoding.len() == IROHA_JINDO_LATTICE_COMMITMENT_BYTES_V1
}
fn indexed_label(prefix: &[u8], index: usize) -> Vec<u8> {
    let mut v = prefix.to_vec();
    v.extend_from_slice(&(index as u32).to_be_bytes());
    v
}
fn encode_rns(p: &JindoRnsPolynomialV1) -> Vec<u8> {
    let mut v = Vec::with_capacity(2 * JINDO_RING_DEGREE_V1 * 8);
    for x in p.residues().iter().flatten() {
        v.extend_from_slice(&x.to_le_bytes())
    }
    v
}
fn absorb_polynomials(
    t: &mut JindoTranscriptV1,
    prefix: &[u8],
    values: &[JindoRnsPolynomialV1],
) -> Result<(), JindoErrorV1> {
    for (i, v) in values.iter().enumerate() {
        t.append_message(&indexed_label(prefix, i), &encode_rns(v))?
    }
    Ok(())
}
fn absorb_fields(
    t: &mut JindoTranscriptV1,
    prefix: &[u8],
    values: &[JindoFieldElementV1],
) -> Result<(), JindoErrorV1> {
    for (i, v) in values.iter().enumerate() {
        t.append_message(&indexed_label(prefix, i), &v.to_canonical_bytes())?
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_batch_boundary_rejects_every_other_count() {
        for count in [0, 1, 3, 5] {
            assert_eq!(
                require_exact_batch(count),
                Err(JindoErrorV1::InvalidPolynomialCount { count, expected: 4 })
            );
        }
        assert_eq!(require_exact_batch(4), Ok(()));
    }
    #[test]
    fn proof_wire_and_source_are_current_only() {
        assert_eq!(JINDO_NATIVE_PROOF_BYTES_V1, 7_159_944);
        assert_eq!(JINDO_PARALLEL_REPETITIONS_V1, 32);
        assert!(
            core::str::from_utf8(JINDO_SOURCE_PROFILE_V1)
                .unwrap()
                .contains("figures-2-7")
        );
        assert!(
            !core::str::from_utf8(JINDO_SOURCE_PROFILE_V1)
                .unwrap()
                .contains("v1-figures")
        );
    }
    #[test]
    fn rejection_exponent_matches_direct_small_relation() {
        let mut y = [0_i128; JINDO_RING_DEGREE_V1];
        y[0] = 3;
        let mut v = [0_i128; JINDO_RING_DEGREE_V1];
        v[0] = -2;
        let y = JindoRnsPolynomialV1::from_balanced_coefficients(y, JINDO_INNER_MODULI_V1);
        let v = JindoRnsPolynomialV1::from_balanced_coefficients(v, JINDO_INNER_MODULI_V1);
        assert_eq!(rejection_exponent(&[y], &[v], &[], &[]).unwrap(), 8);
    }
    #[test]
    fn response_and_exact_evaluation_bounds_close_the_rns_no_wrap_argument() {
        assert_eq!(
            JINDO_INNER_MODULUS_PRODUCT_V1,
            4_951_760_149_791_787_244_536_621_057
        );
        assert_eq!(
            JINDO_AGGREGATED_COEFFICIENT_ABS_BOUND_V1,
            57_689_264_276_404_197
        );
        assert_eq!(
            JINDO_FINAL_RESPONSE_COEFFICIENT_ABS_BOUND_V1,
            57_689_264_276_404_197
        );
        assert_eq!(
            JINDO_EXACT_PARTIAL_ACCUMULATOR_ABS_BOUND_V1,
            5_000_445_822_007_837_186_721_192_448
        );
        const { assert!(JINDO_FINAL_RESPONSE_COEFFICIENT_ABS_BOUND_V1 < JINDO_INNER_BALANCED_MAX_V1) };
        assert!(JINDO_EXACT_PARTIAL_ACCUMULATOR_ABS_BOUND_V1 < i128::MAX as u128);
        const {
            assert!(
                JINDO_EXACT_PARTIAL_ACCUMULATOR_ABS_BOUND_V1 > JINDO_INNER_BALANCED_MAX_V1,
                "the exact partial needs the explicit balanced-lift admission check"
            )
        };
        let mut coefficients = [0_i128; JINDO_RING_DEGREE_V1];
        coefficients[0] = u128::cast_signed(JINDO_INNER_BALANCED_MAX_V1);
        coefficients[1] = -u128::cast_signed(JINDO_INNER_BALANCED_MAX_V1);
        assert!(coefficients_have_unique_inner_balanced_lift(&coefficients));
        coefficients[2] = u128::cast_signed(JINDO_INNER_BALANCED_MAX_V1 + 1);
        assert!(!coefficients_have_unique_inner_balanced_lift(&coefficients));
    }
    #[test]
    fn verifier_relation_dimensions_match_figures_six_and_seven() {
        assert_eq!(JINDO_OUTER_RELATION_POLYNOMIALS_V1, 4 + 3);
        assert_eq!(JINDO_INNER_RELATION_POLYNOMIALS_V1, 3 + 8 + 4);
    }
    #[test]
    fn power_of_two_cut_matches_upstream_algebra_at_signed_boundaries() {
        let expected = [-2_i128, -1, -1, -1, 0, 0, 0, 1, 1];
        for exponent in [
            JINDO_PARAMETERS_V1.log_inner_cutoff,
            JINDO_PARAMETERS_V1.log_outer_cutoff,
        ] {
            let power = 1_i128 << exponent;
            let inputs = [
                -power - 1,
                -power,
                -power + 1,
                -1,
                0,
                1,
                power - 1,
                power,
                power + 1,
            ];
            assert_eq!(
                inputs.map(|value| cut_power_of_two_coefficient(value, exponent)),
                expected,
                "Pow2Cutter.CutTo boundary drift at exponent {exponent}"
            );
        }
    }
}
