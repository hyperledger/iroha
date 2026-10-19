//! Native fixed-profile Bootle/Lantern P1/P2 prover and verifier.
//!
//! This module implements the blind-issuance-request (P1) and presentation (P2) paths over their
//! distinct transcript purposes and nominal wire types: transparent commitments, projected norm
//! witnesses, Schwartz compression, the generic quadratic linearization, ABDLOP response
//! compression, strict proof construction, verifier-side challenge reconstruction, and prover
//! self-verification. It also owns the sealed two-pass presentation transaction builder so no
//! proof, statement, genesis, policy, or intent binding can be replaced between proving and
//! signing.
use super::{
    bounds::{ResponseBoundErrorV1, validate_public_response_bounds_v1},
    codec::{
        BootleLanternBlindIssuanceRequestProofV1, BootleLanternPresentationProofV1,
        H_POLYNOMIALS_V1, HINT_POLYNOMIALS_V1, PROOF_COEFFICIENTS_V1, ProofCodecErrorV1,
        T_A1_POLYNOMIALS_V1, T_B_POLYNOMIALS_V1, Z1_POLYNOMIALS_V1, Z3_POLYNOMIALS_V1,
        Z4_POLYNOMIALS_V1, Z21_POLYNOMIALS_V1,
    },
    compression::{
        CompressionErrorV1, gamma_decompose_v1, make_gamma_hint_v1, power2round_v1,
        use_gamma_hint_v1,
    },
    params::{
        APPLICATION_RELATION_QUOTIENT_BOUND_V1, APPLICATION_RING_DEGREE_V1, COMPRESSION_GAMMA_V1,
        DECOMPOSITION_BITS_V1, MAX_PROJECTION_SAMPLING_ATTEMPTS_PER_PROVE_ATTEMPT_V1,
        MAX_PROOF_SAMPLING_ATTEMPTS_V1, MAX_RESPONSE_SAMPLING_ATTEMPTS_PER_PROVE_ATTEMPT_V1,
        PROOF_INVERSE_TWO_V1, RESPONSE_NORM_SQUARED_BOUND_V1, TBOX_KMSIS_V1, TBOX_LEXT_V1,
        TBOX_M1_V1, TBOX_M2_V1, Z3_NORM_SQUARED_BOUND_V1, Z4_INFINITY_NORM_BOUND_V1,
    },
    relation::{BootleLanternApplicationRelationV1, BootleLanternPresentationWitnessV1},
    ring::ProofPolynomialV1,
    sampling::{BootleSamplingProfileV1, ProofRandomnessV1, SamplingErrorV1},
    toolbox::{
        COMBINED_QUADRATIC_EQUATIONS_V1, EVALUATION_CONSTRAINTS_V1, InternalMatricesV1,
        PROJECTION_COORDINATES_V1, PROJECTION_POLYNOMIALS_V1, QUADRATIC_MESSAGE_POLYNOMIALS_V1,
        QuadraticEquationV1, QuadraticVariablesV1, S21_POLYNOMIALS_V1, SCHWARTZ_ACCUMULATORS_V1,
        ToolboxErrorV1, application_quotient_v1, application_relation_digest_v1,
        boxed_polynomial_array_from_fn_v1, boxed_zero_polynomial_array_v1,
        commit_extended_messages_v1, encode_polynomials_v1, expand_projection_matrix_v1,
        flatten_polynomials, lift_short_witness_v1, matrix_vector_product_v1,
        projected_norm_witness_v1,
    },
    transcript::{
        BlindIssuanceRequestTranscriptV1, PresentationTranscriptV1, ProofTranscriptCoreV1,
    },
};
#[cfg(test)]
use core::{num::NonZeroU32, time::Duration};
#[cfg(test)]
use iroha_crypto::{Hash, PrivateKey, PublicKey};
use iroha_data_model::transaction::SignedTransaction;
#[cfg(test)]
use iroha_data_model::{
    account::AccountId,
    isi::privacy::SubmitPrivacyProofV1,
    prelude::NetworkId,
    privacy::{
        BootleLanternDisclosedAttributeV1, BootleLanternIssuerPolicyLifecycleV1,
        IrohaBootleLanternAnoncredStatementV1, PrivacyConsensusLimitsV1, PrivacyProofBytesV1,
        PrivacyProofEnvelopeV1, PrivacyProofV1, PrivacyProtocolIdV1, PrivacyStatementContextV1,
        PrivacyStatementV1, PrivacyTransactionIntentDigestV1,
    },
    transaction::{
        Executable, FeePaymentIntent, TransactionBuilder, signed::TransactionSignatureError,
    },
};
#[cfg(test)]
use iroha_data_model::{privacy::BootleLanternIssuerPolicyV1, transaction::TransactionPayload};
#[cfg(test)]
use iroha_model_base::metadata::Metadata;
use rand_core_06::{CryptoRng, RngCore};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};
const PROJECTION_R_STAGE_V1: &[u8] = b"projection-r-v1";
const PROJECTION_R_PRIME_STAGE_V1: &[u8] = b"projection-r-prime-v1";
const SCHWARTZ_WEIGHT_STAGE_V1: &[u8] = b"schwartz-weights-v1";
const EQUATION_MULTIPLIER_STAGE_V1: &[u8] = b"quadratic-equation-multipliers-v1";
const Y3_MESSAGE_START_V1: usize = 0;
const Y4_MESSAGE_START_V1: usize = 4;
const BETA_MESSAGE_INDEX_V1: usize = 8;
const G_MESSAGE_START_V1: usize = 9;
const LINEARIZATION_MESSAGE_INDEX_V1: usize = 11;
#[cfg(test)]
const PROVER_PRECOMPUTED_QUADRATIC_EVALUATIONS_V1: usize = 2;
#[cfg(test)]
const PROVER_QUADRATIC_EVALUATIONS_PER_MASK_RETRY_V1: usize = 3;
const VERIFIER_QUADRATIC_EVALUATIONS_V1: usize = 3;
#[cfg(test)]
const MAX_QUADRATIC_EVALUATIONS_PER_PROVE_ATTEMPT_V1: usize =
    PROVER_PRECOMPUTED_QUADRATIC_EVALUATIONS_V1
        + PROVER_QUADRATIC_EVALUATIONS_PER_MASK_RETRY_V1
            * MAX_RESPONSE_SAMPLING_ATTEMPTS_PER_PROVE_ATTEMPT_V1 as usize;
#[cfg(test)]
const MIN_RESPONSE_CONTEXTS_AT_GLOBAL_BUDGET_V1: usize = (MAX_PROOF_SAMPLING_ATTEMPTS_V1 as usize
    + MAX_RESPONSE_SAMPLING_ATTEMPTS_PER_PROVE_ATTEMPT_V1 as usize)
    / (MAX_RESPONSE_SAMPLING_ATTEMPTS_PER_PROVE_ATTEMPT_V1 as usize + 1);
// Spending all B shared draws on the evaluation-heavy path needs at least
// ceil(B / (R + 1)) contexts: one projection draw plus at most R response
// draws apiece.  Treating every draw as three evaluations and replacing each
// required projection draw by its two-evaluation context prelude gives the
// tight prover bound 3B-contexts; a successful proof adds three verifier
// evaluations.
#[cfg(test)]
const MAX_TOP_LEVEL_QUADRATIC_EVALUATIONS_V1: usize = 3 * MAX_PROOF_SAMPLING_ATTEMPTS_V1 as usize
    - MIN_RESPONSE_CONTEXTS_AT_GLOBAL_BUDGET_V1
    + VERIFIER_QUADRATIC_EVALUATIONS_V1;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProofRejectionStageV1 {
    Projection,
    ResponseMask,
}
#[derive(Default, PartialEq, Eq)]
struct ProofRejectionStatsV1 {
    projection: u32,
    response_sampling: u32,
    response_norm: u32,
}
impl core::fmt::Debug for ProofRejectionStatsV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProofRejectionStatsV1(<redacted>)")
    }
}
impl Zeroize for ProofRejectionStatsV1 {
    fn zeroize(&mut self) {
        self.projection.zeroize();
        self.response_sampling.zeroize();
        self.response_norm.zeroize();
    }
}
impl Drop for ProofRejectionStatsV1 {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ProofRejectionStatsV1 {
    fn increment(counter: &mut u32) {
        *counter = counter
            .checked_add(1)
            .expect("a rejection count cannot exceed the shared u32 draw budget");
    }
}
struct ProofRejectionBudgetV1 {
    remaining: u32,
    projection_draws: u32,
    response_mask_draws: u32,
    rejections: ProofRejectionStatsV1,
}
impl core::fmt::Debug for ProofRejectionBudgetV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProofRejectionBudgetV1(<redacted>)")
    }
}
impl Zeroize for ProofRejectionBudgetV1 {
    fn zeroize(&mut self) {
        self.remaining.zeroize();
        self.projection_draws.zeroize();
        self.response_mask_draws.zeroize();
        self.rejections.zeroize();
    }
}
impl Drop for ProofRejectionBudgetV1 {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ProofRejectionBudgetV1 {
    const fn new(limit: u32) -> Self {
        Self {
            remaining: limit,
            projection_draws: 0,
            response_mask_draws: 0,
            rejections: ProofRejectionStatsV1 {
                projection: 0,
                response_sampling: 0,
                response_norm: 0,
            },
        }
    }
    fn reserve(&mut self, stage: ProofRejectionStageV1) -> bool {
        let Some(remaining) = self.remaining.checked_sub(1) else {
            return false;
        };
        self.remaining = remaining;
        let draws = match stage {
            ProofRejectionStageV1::Projection => &mut self.projection_draws,
            ProofRejectionStageV1::ResponseMask => &mut self.response_mask_draws,
        };
        *draws = draws
            .checked_add(1)
            .expect("draw count cannot exceed its u32 budget");
        true
    }
    #[cfg(test)]
    const fn remaining(&self) -> u32 {
        self.remaining
    }
    const fn is_exhausted(&self) -> bool {
        self.remaining == 0
    }
    fn total_draws(&self) -> u32 {
        self.projection_draws
            .checked_add(self.response_mask_draws)
            .expect("stage draws cannot exceed their shared u32 budget")
    }
    fn record_projection_rejection(&mut self) {
        ProofRejectionStatsV1::increment(&mut self.rejections.projection);
    }
    fn record_response_sampling_rejection(&mut self) {
        ProofRejectionStatsV1::increment(&mut self.rejections.response_sampling);
    }
    fn record_response_norm_rejection(&mut self) {
        ProofRejectionStatsV1::increment(&mut self.rejections.response_norm);
    }
    fn exhaustion_error(&self) -> PresentationProofErrorV1 {
        PresentationProofErrorV1::SamplingBudgetExhausted
    }
}
struct SecretPolynomialVectorV1<const N: usize> {
    polynomials: Box<[ProofPolynomialV1; N]>,
}
impl<const N: usize> SecretPolynomialVectorV1<N> {
    fn zero() -> Self {
        Self {
            polynomials: boxed_zero_polynomial_array_v1(),
        }
    }
    fn from_polynomials(polynomials: Box<[ProofPolynomialV1; N]>) -> Self {
        Self { polynomials }
    }
}
impl<const N: usize> core::fmt::Debug for SecretPolynomialVectorV1<N> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SecretPolynomialVectorV1(<redacted>)")
    }
}
impl<const N: usize> Drop for SecretPolynomialVectorV1<N> {
    fn drop(&mut self) {
        self.polynomials.as_mut().zeroize();
    }
}
struct ProjectionProofV1 {
    projection_r: Box<[i8]>,
    projection_r_prime: Box<[i8]>,
    z3: SecretPolynomialVectorV1<PROJECTION_POLYNOMIALS_V1>,
    z4: SecretPolynomialVectorV1<PROJECTION_POLYNOMIALS_V1>,
}
/// Prove one validated anonymous-credential presentation.
///
/// The borrowed transcript must carry `application_relation_digest_v1(relation)`.
/// Randomness is obtained once from the caller's fallible cryptographic RNG,
/// then every internal stream is independently domain-separated.
///
/// # Errors
///
/// Fails closed on a relation/transcript mismatch, invalid witness, random
/// source failure, bounded rejection exhaustion, arithmetic/compression
/// failure, non-canonical proof construction, or failed prover self-check.
///
/// # Timing boundary
///
/// This is a local prover API. Its bounded Gaussian and response rejection
/// samplers are intentionally variable-work. Deployments must not expose proof
/// completion timing to an untrusted remote observer or a hostile co-tenant;
/// use process isolation and a local authenticated invocation boundary.
pub fn prove_presentation_v1<R: CryptoRng + RngCore>(
    relation: &BootleLanternApplicationRelationV1,
    witness: &BootleLanternPresentationWitnessV1,
    transcript: &PresentationTranscriptV1,
    rng: &mut R,
) -> Result<BootleLanternPresentationProofV1, PresentationProofErrorV1> {
    prove_with_transcript_core_v1(
        relation,
        witness,
        &transcript.proof_core(),
        rng,
        MAX_PROOF_SAMPLING_ATTEMPTS_V1,
    )
}
pub(crate) fn prove_blind_issuance_request_v1<R: CryptoRng + RngCore>(
    relation: &BootleLanternApplicationRelationV1,
    witness: &BootleLanternPresentationWitnessV1,
    transcript: &BlindIssuanceRequestTranscriptV1,
    rng: &mut R,
) -> Result<BootleLanternBlindIssuanceRequestProofV1, PresentationProofErrorV1> {
    let body = prove_with_transcript_core_v1(
        relation,
        witness,
        &transcript.proof_core(),
        rng,
        MAX_PROOF_SAMPLING_ATTEMPTS_V1,
    )?;
    Ok(BootleLanternBlindIssuanceRequestProofV1::from_validated_body_v1(body))
}
#[cfg(test)]
fn prove_presentation_with_rejection_limit_v1<R: CryptoRng + RngCore>(
    relation: &BootleLanternApplicationRelationV1,
    witness: &BootleLanternPresentationWitnessV1,
    transcript: &PresentationTranscriptV1,
    rng: &mut R,
    rejection_draw_limit: u32,
) -> Result<BootleLanternPresentationProofV1, PresentationProofErrorV1> {
    prove_with_transcript_core_v1(
        relation,
        witness,
        &transcript.proof_core(),
        rng,
        rejection_draw_limit,
    )
}
fn prove_with_transcript_core_v1<R: CryptoRng + RngCore>(
    relation: &BootleLanternApplicationRelationV1,
    witness: &BootleLanternPresentationWitnessV1,
    transcript: &ProofTranscriptCoreV1,
    rng: &mut R,
    rejection_draw_limit: u32,
) -> Result<BootleLanternPresentationProofV1, PresentationProofErrorV1> {
    if rejection_draw_limit == 0 || rejection_draw_limit > MAX_PROOF_SAMPLING_ATTEMPTS_V1 {
        return Err(PresentationProofErrorV1::InternalInvariant);
    }
    require_relation_digest(relation, transcript)?;
    let short =
        lift_short_witness_v1(relation, witness).map_err(PresentationProofErrorV1::Toolbox)?;
    let mut randomness =
        ProofRandomnessV1::from_rng(rng).map_err(PresentationProofErrorV1::Sampling)?;
    let matrices =
        InternalMatricesV1::expand(transcript).map_err(PresentationProofErrorV1::Toolbox)?;
    let mut rejection_budget = ProofRejectionBudgetV1::new(rejection_draw_limit);
    while !rejection_budget.is_exhausted() {
        let draws_before = rejection_budget.total_draws();
        if let Some(proof) = prove_attempt(
            relation,
            &short,
            transcript,
            &matrices,
            &mut randomness,
            &mut rejection_budget,
        )? {
            if let Err(_error) = verify_with_transcript_core_v1(relation, transcript, &proof) {
                #[cfg(test)]
                eprintln!("Bootle/Lantern prover self-check detail: {_error:?}");
                return Err(PresentationProofErrorV1::ProverSelfCheckFailed);
            }
            return Ok(proof);
        }
        if rejection_budget.total_draws() <= draws_before {
            return Err(PresentationProofErrorV1::InternalInvariant);
        }
    }
    Err(rejection_budget.exhaustion_error())
}
/// Verify one strictly decoded presentation proof against the borrowed transcript.
///
/// # Errors
///
/// Fails on any transcript/relation mismatch, public response bound, reconciliation equation,
/// Schwartz commitment shape, or Fiat--Shamir challenge mismatch.
pub fn verify_presentation_v1(
    relation: &BootleLanternApplicationRelationV1,
    transcript: &PresentationTranscriptV1,
    proof: &BootleLanternPresentationProofV1,
) -> Result<(), PresentationProofErrorV1> {
    verify_with_transcript_core_v1(relation, &transcript.proof_core(), proof)
}
pub(crate) fn verify_blind_issuance_request_v1(
    relation: &BootleLanternApplicationRelationV1,
    transcript: &BlindIssuanceRequestTranscriptV1,
    proof: &BootleLanternBlindIssuanceRequestProofV1,
) -> Result<(), PresentationProofErrorV1> {
    verify_with_transcript_core_v1(
        relation,
        &transcript.proof_core(),
        proof.validated_body_v1(),
    )
}
fn verify_with_transcript_core_v1(
    relation: &BootleLanternApplicationRelationV1,
    transcript: &ProofTranscriptCoreV1,
    proof: &BootleLanternPresentationProofV1,
) -> Result<(), PresentationProofErrorV1> {
    require_relation_digest(relation, transcript)?;
    validate_public_response_bounds_v1(proof).map_err(PresentationProofErrorV1::ResponseBound)?;
    let t_b = proof_polynomial_array::<T_B_POLYNOMIALS_V1>(|index| proof.t_b_polynomial(index))?;
    let h = proof_polynomial_array::<H_POLYNOMIALS_V1>(|index| proof.h_polynomial(index))?;
    let t_a1 = proof_polynomial_array::<T_A1_POLYNOMIALS_V1>(|index| proof.t_a1_polynomial(index))?;
    let hint = proof_polynomial_array::<HINT_POLYNOMIALS_V1>(|index| proof.hint_polynomial(index))?;
    let z1 = proof_polynomial_array::<Z1_POLYNOMIALS_V1>(|index| proof.z1_polynomial(index))?;
    let z21 = proof_polynomial_array::<Z21_POLYNOMIALS_V1>(|index| proof.z21_polynomial(index))?;
    let z3 = proof_polynomial_array::<Z3_POLYNOMIALS_V1>(|index| proof.z3_polynomial(index))?;
    let z4 = proof_polynomial_array::<Z4_POLYNOMIALS_V1>(|index| proof.z4_polynomial(index))?;
    let challenge = proof.challenge_polynomial();
    require_schwartz_commitment_shape(&h)?;
    let matrices =
        InternalMatricesV1::expand(transcript).map_err(PresentationProofErrorV1::Toolbox)?;
    let (projection_r, projection_r_prime) = derive_projection_matrices(transcript, &t_b)?;
    let weights = derive_schwartz_weights(transcript, &t_b)?;
    let multipliers = derive_equation_multipliers(transcript, &t_b, &h, &z3, &z4)?;
    let equation = QuadraticEquationV1::new(
        relation,
        projection_r,
        projection_r_prime,
        z3.clone(),
        z4.clone(),
        h.clone(),
        weights,
        multipliers,
    )
    .map_err(PresentationProofErrorV1::Toolbox)?;
    let recovered_w1 = recover_gamma_high(&matrices, &z1, &z21, &t_a1, &challenge, &hint)?;
    validate_compressed_response_bound(&matrices, &z1, &z21, &t_a1, &challenge, &recovered_w1)?;
    let b_z21 = matrix_vector_product_v1(&matrices.b_prime, z21.as_ref())
        .map_err(PresentationProofErrorV1::Toolbox)?;
    let variables = QuadraticVariablesV1 {
        short: z1,
        message: boxed_polynomial_array_from_fn_v1(|index| {
            challenge.multiply(t_b[index]).sub(b_z21[index])
        }),
    };
    let f = challenge
        .multiply(t_b[LINEARIZATION_MESSAGE_INDEX_V1])
        .sub(b_z21[LINEARIZATION_MESSAGE_INDEX_V1]);
    // A quadratic map is completely split into its constant, linear, and
    // homogeneous-quadratic parts by Q(0), Q(z), and Q(-z).  Keep those
    // three expensive black-box evaluations shared by both reconstructions.
    let [q0, q_z, q_negative_z]: [ProofPolynomialV1; VERIFIER_QUADRATIC_EVALUATIONS_V1] = [
        equation
            .evaluate(&QuadraticVariablesV1::zero())
            .map_err(PresentationProofErrorV1::Toolbox)?,
        equation
            .evaluate(&variables)
            .map_err(PresentationProofErrorV1::Toolbox)?,
        equation
            .evaluate(&variables.negate())
            .map_err(PresentationProofErrorV1::Toolbox)?,
    ];
    let (linear_z, q2_z) = decompose_signed_quadratic_evaluations(&q0, &q_z, &q_negative_z)?;
    let recovered_v = q2_z
        .add(challenge.multiply(linear_z))
        .add(challenge.multiply(challenge).multiply(q0))
        .sub(f);
    let pre_challenge = pre_challenge_wire(&t_b, &h, &t_a1, &z3, &z4, &recovered_w1, &recovered_v)?;
    let expected = transcript
        .derive_final_challenge(&pre_challenge)
        .map_err(|error| PresentationProofErrorV1::Toolbox(ToolboxErrorV1::Transcript(error)))?;
    if expected != challenge {
        return Err(PresentationProofErrorV1::ChallengeMismatch);
    }
    Ok(())
}
fn prove_attempt(
    relation: &BootleLanternApplicationRelationV1,
    short: &super::toolbox::ShortWitnessV1,
    transcript: &ProofTranscriptCoreV1,
    matrices: &InternalMatricesV1,
    randomness: &mut ProofRandomnessV1,
    rejection_budget: &mut ProofRejectionBudgetV1,
) -> Result<Option<BootleLanternPresentationProofV1>, PresentationProofErrorV1> {
    let s2 = sample_ternary_vector::<TBOX_M2_V1>(randomness, b"s2")?;
    let (t_a1, t_a2) = commit_short_witness(matrices, short.polynomials(), &s2.polynomials)?;
    let mut messages = SecretPolynomialVectorV1::<TBOX_LEXT_V1>::zero();
    let projection = match prove_projected_responses(
        relation,
        short.polynomials(),
        transcript,
        matrices,
        &s2.polynomials,
        &mut messages.polynomials,
        randomness,
        rejection_budget,
    )? {
        Some(projection) => projection,
        None => return Ok(None),
    };
    messages.polynomials[G_MESSAGE_START_V1] = sample_uniform_g(randomness, b"schwartz-g0")?;
    messages.polynomials[G_MESSAGE_START_V1 + 1] = sample_uniform_g(randomness, b"schwartz-g1")?;
    let mut t_b = Zeroizing::new(
        commit_extended_messages_v1(
            &matrices.b_prime,
            array_prefix::<S21_POLYNOMIALS_V1, TBOX_M2_V1>(&s2.polynomials),
            &messages.polynomials,
        )
        .map_err(PresentationProofErrorV1::Toolbox)?,
    );
    let weights = derive_schwartz_weights(transcript, &t_b)?;
    let variables = QuadraticVariablesV1 {
        short: short
            .polynomials()
            .to_vec()
            .into_boxed_slice()
            .try_into()
            .unwrap_or_else(|_| unreachable!("short witness shape is fixed")),
        message: boxed_polynomial_array_from_fn_v1(|index| messages.polynomials[index]),
    };
    let z3 = projection.z3;
    let z4 = projection.z4;
    let mut equation = QuadraticEquationV1::new(
        relation,
        projection.projection_r,
        projection.projection_r_prime,
        z3.polynomials.clone(),
        z4.polynomials.clone(),
        boxed_zero_polynomial_array_v1(),
        weights,
        boxed_zero_polynomial_array_v1(),
    )
    .map_err(PresentationProofErrorV1::Toolbox)?;
    let schwartz = Zeroizing::new(
        equation
            .schwartz_polynomials(&variables)
            .map_err(PresentationProofErrorV1::Toolbox)?,
    );
    let h = boxed_polynomial_array_from_fn_v1(|index| {
        messages.polynomials[G_MESSAGE_START_V1 + index].add(schwartz[index])
    });
    require_schwartz_commitment_shape(&h)?;
    let multipliers =
        derive_equation_multipliers(transcript, &t_b, &h, &z3.polynomials, &z4.polynomials)?;
    equation.bind_final_equations(h.clone(), multipliers);
    // These two values are invariant across every response-mask retry.  In
    // particular, checking Q(secret) here preserves the witness soundness
    // check while avoiding its former repetition inside the retry loop.
    let q0 = equation
        .evaluate(&QuadraticVariablesV1::zero())
        .map_err(PresentationProofErrorV1::Toolbox)?;
    let q_secret = Zeroizing::new(
        equation
            .evaluate(&variables)
            .map_err(PresentationProofErrorV1::Toolbox)?,
    );
    if !q_secret.is_zero() {
        return Err(PresentationProofErrorV1::ConstraintSystemRejectedWitness);
    }
    // B' * s21 is independent of the response mask as well.  Retain only
    // the coordinate used by the linearization and zeroize the full product.
    let b_s21 = matrix_vector_product_v1(
        &matrices.b_prime,
        array_prefix::<S21_POLYNOMIALS_V1, TBOX_M2_V1>(&s2.polynomials),
    )
    .map_err(PresentationProofErrorV1::Toolbox)?;
    let b_s21_linearization = Zeroizing::new(b_s21[LINEARIZATION_MESSAGE_INDEX_V1]);
    for _ in 0..MAX_RESPONSE_SAMPLING_ATTEMPTS_PER_PROVE_ATTEMPT_V1 {
        if !rejection_budget.reserve(ProofRejectionStageV1::ResponseMask) {
            return Ok(None);
        }
        let y1 =
            sample_gaussian_vector::<TBOX_M1_V1>(randomness, BootleSamplingProfileV1::ResponseZ1)?;
        let y2 =
            sample_gaussian_vector::<TBOX_M2_V1>(randomness, BootleSamplingProfileV1::ResponseZ2)?;
        let (t_candidate, v) = quadratic_linearization(
            &equation,
            &variables,
            &q0,
            &q_secret,
            matrices,
            &b_s21_linearization,
            &y1.polynomials,
            array_prefix::<S21_POLYNOMIALS_V1, TBOX_M2_V1>(&y2.polynomials),
        )?;
        let t_candidate = Zeroizing::new(t_candidate);
        t_b[LINEARIZATION_MESSAGE_INDEX_V1] = *t_candidate;
        let (w1, w0) = decompose_mask_commitment(
            matrices,
            &y1.polynomials,
            array_prefix::<S21_POLYNOMIALS_V1, TBOX_M2_V1>(&y2.polynomials),
            array_suffix::<TBOX_KMSIS_V1, TBOX_M2_V1>(&y2.polynomials),
        )?;
        let pre_challenge =
            pre_challenge_wire(&t_b, &h, &t_a1, &z3.polynomials, &z4.polynomials, &w1, &v)?;
        let challenge = transcript
            .derive_final_challenge(&pre_challenge)
            .map_err(|error| {
                PresentationProofErrorV1::Toolbox(ToolboxErrorV1::Transcript(error))
            })?;
        let c_short = SecretPolynomialVectorV1::from_polynomials(multiply_vector_by_polynomial(
            short.polynomials(),
            &challenge,
        ));
        let c_s2 = SecretPolynomialVectorV1::from_polynomials(multiply_vector_by_polynomial(
            &s2.polynomials,
            &challenge,
        ));
        let z1 = SecretPolynomialVectorV1::from_polynomials(add_arrays(
            &y1.polynomials,
            &c_short.polynomials,
        ));
        let mut z2 = SecretPolynomialVectorV1::from_polynomials(add_arrays(
            &y2.polynomials,
            &c_s2.polynomials,
        ));
        let z1_centered = Zeroizing::new(centered_vector(z1.polynomials.as_ref()));
        let c_short_centered = Zeroizing::new(centered_vector(c_short.polynomials.as_ref()));
        let z2_centered = Zeroizing::new(centered_vector(z2.polynomials.as_ref()));
        let c_s2_centered = Zeroizing::new(centered_vector(c_s2.polynomials.as_ref()));
        let accept_z1 = randomness
            .accept_rejection(
                z1_centered.as_ref(),
                c_short_centered.as_ref(),
                BootleSamplingProfileV1::ResponseZ1,
            )
            .map_err(PresentationProofErrorV1::Sampling)?;
        let accept_z2 = randomness
            .accept_rejection(
                z2_centered.as_ref(),
                c_s2_centered.as_ref(),
                BootleSamplingProfileV1::ResponseZ2,
            )
            .map_err(PresentationProofErrorV1::Sampling)?;
        if !accept_z1 || !accept_z2 {
            rejection_budget.record_response_sampling_rejection();
            continue;
        }
        let c_t_a2 = SecretPolynomialVectorV1::from_polynomials(multiply_vector_by_polynomial(
            &t_a2.polynomials,
            &challenge,
        ));
        for index in 0..TBOX_KMSIS_V1 {
            let response_index = S21_POLYNOMIALS_V1 + index;
            z2.polynomials[response_index] = z2.polynomials[response_index]
                .sub(c_t_a2.polynomials[index])
                .sub(w0.polynomials[index]);
        }
        if centered_squared_norm(z2.polynomials.as_ref())?
            > u128::from(RESPONSE_NORM_SQUARED_BOUND_V1)
        {
            rejection_budget.record_response_norm_rejection();
            continue;
        }
        let hint = make_hint(
            &w1,
            array_suffix::<TBOX_KMSIS_V1, TBOX_M2_V1>(&z2.polynomials),
        )?;
        let proof = construct_proof(
            &t_b,
            &h,
            &t_a1,
            &challenge,
            &hint,
            &z1.polynomials,
            array_prefix::<S21_POLYNOMIALS_V1, TBOX_M2_V1>(&z2.polynomials),
            &z3.polynomials,
            &z4.polynomials,
        )?;
        validate_public_response_bounds_v1(&proof)
            .map_err(PresentationProofErrorV1::ResponseBound)?;
        return Ok(Some(proof));
    }
    Ok(None)
}
fn prove_projected_responses(
    relation: &BootleLanternApplicationRelationV1,
    short: &[ProofPolynomialV1; TBOX_M1_V1],
    transcript: &ProofTranscriptCoreV1,
    matrices: &InternalMatricesV1,
    s2: &[ProofPolynomialV1; TBOX_M2_V1],
    messages: &mut [ProofPolynomialV1; TBOX_LEXT_V1],
    randomness: &mut ProofRandomnessV1,
    rejection_budget: &mut ProofRejectionBudgetV1,
) -> Result<Option<ProjectionProofV1>, PresentationProofErrorV1> {
    let s3 = projected_norm_witness_v1(short);
    let s4 = Zeroizing::new(
        application_quotient_v1(relation, short).map_err(PresentationProofErrorV1::Toolbox)?,
    );
    if s4.iter().any(|polynomial| {
        polynomial
            .coefficients()
            .iter()
            .enumerate()
            .any(|(index, _)| {
                polynomial.centered_coefficient(index).unsigned_abs()
                    > APPLICATION_RELATION_QUOTIENT_BOUND_V1
            })
    }) {
        return Err(PresentationProofErrorV1::ApplicationQuotientBoundExceeded);
    }
    let s3_coefficients = Zeroizing::new(centered_vector(s3.polynomials()));
    let s4_coefficients = Zeroizing::new(centered_vector(s4.as_ref()));
    for _ in 0..MAX_PROJECTION_SAMPLING_ATTEMPTS_PER_PROVE_ATTEMPT_V1 {
        if !rejection_budget.reserve(ProofRejectionStageV1::Projection) {
            return Ok(None);
        }
        let y3 = sample_gaussian_vector::<PROJECTION_POLYNOMIALS_V1>(
            randomness,
            BootleSamplingProfileV1::ProjectionZ3,
        )?;
        let y4 = sample_gaussian_vector::<PROJECTION_POLYNOMIALS_V1>(
            randomness,
            BootleSamplingProfileV1::ProjectionZ4,
        )?;
        let beta3 = randomness.sign(b"z3-sign");
        let beta4 = randomness.sign(b"z4-sign");
        messages[Y3_MESSAGE_START_V1..Y3_MESSAGE_START_V1 + PROJECTION_POLYNOMIALS_V1]
            .copy_from_slice(y3.polynomials.as_ref());
        messages[Y4_MESSAGE_START_V1..Y4_MESSAGE_START_V1 + PROJECTION_POLYNOMIALS_V1]
            .copy_from_slice(y4.polynomials.as_ref());
        let mut beta_coefficients = [0_i64; APPLICATION_RING_DEGREE_V1];
        beta_coefficients[0] = beta3;
        beta_coefficients[APPLICATION_RING_DEGREE_V1 / 2] = beta4;
        messages[BETA_MESSAGE_INDEX_V1] =
            ProofPolynomialV1::from_centered_coefficients(beta_coefficients);
        let t_b = commit_extended_messages_v1(
            &matrices.b_prime,
            array_prefix::<S21_POLYNOMIALS_V1, TBOX_M2_V1>(s2),
            messages,
        )
        .map_err(PresentationProofErrorV1::Toolbox)?;
        let (projection_r, projection_r_prime) = derive_projection_matrices(transcript, &t_b)?;
        let projected_s3 = project_centered(
            &projection_r,
            s3_coefficients.len(),
            s3_coefficients.as_ref(),
        )?;
        let projected_s4 = project_centered(
            &projection_r_prime,
            s4_coefficients.len(),
            s4_coefficients.as_ref(),
        )?;
        let mut z3_centered = Zeroizing::new(centered_vector(y3.polynomials.as_ref()));
        let mut z4_centered = Zeroizing::new(centered_vector(y4.polynomials.as_ref()));
        for index in 0..PROJECTION_COORDINATES_V1 {
            z3_centered[index] = z3_centered[index]
                .checked_add(
                    beta3
                        .checked_mul(projected_s3[index])
                        .ok_or(PresentationProofErrorV1::ArithmeticOverflow)?,
                )
                .ok_or(PresentationProofErrorV1::ArithmeticOverflow)?;
            z4_centered[index] = z4_centered[index]
                .checked_add(
                    beta4
                        .checked_mul(projected_s4[index])
                        .ok_or(PresentationProofErrorV1::ArithmeticOverflow)?,
                )
                .ok_or(PresentationProofErrorV1::ArithmeticOverflow)?;
        }
        let z3 = SecretPolynomialVectorV1::from_polynomials(polynomials_from_centered_projection(
            z3_centered.as_ref(),
        ));
        let z4 = SecretPolynomialVectorV1::from_polynomials(polynomials_from_centered_projection(
            z4_centered.as_ref(),
        ));
        let accept_z3 = randomness
            .accept_rejection(
                z3_centered.as_ref(),
                projected_s3.as_ref(),
                BootleSamplingProfileV1::ProjectionZ3,
            )
            .map_err(PresentationProofErrorV1::Sampling)?;
        let accept_z4 = randomness
            .accept_rejection(
                z4_centered.as_ref(),
                projected_s4.as_ref(),
                BootleSamplingProfileV1::ProjectionZ4,
            )
            .map_err(PresentationProofErrorV1::Sampling)?;
        let z3_norm = centered_squared_norm(z3.polynomials.as_ref())?;
        let z4_infinity = z4
            .polynomials
            .iter()
            .flat_map(ProofPolynomialV1::coefficients)
            .enumerate()
            .map(|(index, residue)| {
                let polynomial = index / APPLICATION_RING_DEGREE_V1;
                let coefficient = index % APPLICATION_RING_DEGREE_V1;
                let _ = residue;
                z4.polynomials[polynomial]
                    .centered_coefficient(coefficient)
                    .unsigned_abs()
            })
            .max()
            .unwrap_or(0);
        if accept_z3
            && accept_z4
            && z3_norm <= u128::from(Z3_NORM_SQUARED_BOUND_V1)
            && z4_infinity <= Z4_INFINITY_NORM_BOUND_V1
        {
            return Ok(Some(ProjectionProofV1 {
                projection_r,
                projection_r_prime,
                z3,
                z4,
            }));
        }
        rejection_budget.record_projection_rejection();
    }
    Ok(None)
}
fn derive_projection_matrices(
    transcript: &ProofTranscriptCoreV1,
    t_b: &[ProofPolynomialV1; TBOX_LEXT_V1],
) -> Result<(Box<[i8]>, Box<[i8]>), PresentationProofErrorV1> {
    let projection_commitments = encode_polynomials_v1(&t_b[..BETA_MESSAGE_INDEX_V1 + 1]);
    let components = [projection_commitments.as_slice()];
    let projection_r = expand_projection_matrix_v1(
        transcript,
        PROJECTION_R_STAGE_V1,
        &components,
        50 * APPLICATION_RING_DEGREE_V1,
    )
    .map_err(PresentationProofErrorV1::Toolbox)?;
    let projection_r_prime = expand_projection_matrix_v1(
        transcript,
        PROJECTION_R_PRIME_STAGE_V1,
        &components,
        8 * APPLICATION_RING_DEGREE_V1,
    )
    .map_err(PresentationProofErrorV1::Toolbox)?;
    Ok((projection_r, projection_r_prime))
}
fn derive_schwartz_weights(
    transcript: &ProofTranscriptCoreV1,
    t_b: &[ProofPolynomialV1; TBOX_LEXT_V1],
) -> Result<Box<[u64]>, PresentationProofErrorV1> {
    let commitment = encode_polynomials_v1(&t_b[..QUADRATIC_MESSAGE_POLYNOMIALS_V1]);
    transcript
        .derive_uniform_scalars(
            SCHWARTZ_WEIGHT_STAGE_V1,
            &[commitment.as_slice()],
            SCHWARTZ_ACCUMULATORS_V1 * EVALUATION_CONSTRAINTS_V1,
        )
        .map(Vec::into_boxed_slice)
        .map_err(|error| PresentationProofErrorV1::Toolbox(ToolboxErrorV1::Transcript(error)))
}
fn derive_equation_multipliers(
    transcript: &ProofTranscriptCoreV1,
    t_b: &[ProofPolynomialV1; TBOX_LEXT_V1],
    h: &[ProofPolynomialV1; H_POLYNOMIALS_V1],
    z3: &[ProofPolynomialV1; Z3_POLYNOMIALS_V1],
    z4: &[ProofPolynomialV1; Z4_POLYNOMIALS_V1],
) -> Result<Box<[ProofPolynomialV1; COMBINED_QUADRATIC_EQUATIONS_V1]>, PresentationProofErrorV1> {
    let t_b_wire = encode_polynomials_v1(&t_b[..QUADRATIC_MESSAGE_POLYNOMIALS_V1]);
    let h_wire = encode_polynomials_v1(h);
    let z3_wire = encode_polynomials_v1(z3);
    let z4_wire = encode_polynomials_v1(z4);
    let multipliers = transcript
        .derive_uniform_polynomials(
            EQUATION_MULTIPLIER_STAGE_V1,
            &[
                t_b_wire.as_slice(),
                h_wire.as_slice(),
                z3_wire.as_slice(),
                z4_wire.as_slice(),
            ],
            COMBINED_QUADRATIC_EQUATIONS_V1,
        )
        .map_err(|error| PresentationProofErrorV1::Toolbox(ToolboxErrorV1::Transcript(error)))?;
    multipliers
        .into_boxed_slice()
        .try_into()
        .map_err(|_| PresentationProofErrorV1::InternalInvariant)
}
fn commit_short_witness(
    matrices: &InternalMatricesV1,
    short: &[ProofPolynomialV1; TBOX_M1_V1],
    s2: &[ProofPolynomialV1; TBOX_M2_V1],
) -> Result<
    (
        Box<[ProofPolynomialV1; T_A1_POLYNOMIALS_V1]>,
        SecretPolynomialVectorV1<T_A1_POLYNOMIALS_V1>,
    ),
    PresentationProofErrorV1,
> {
    let a1_short =
        matrix_vector_product_v1(&matrices.a1, short).map_err(PresentationProofErrorV1::Toolbox)?;
    let a2_s21 = matrix_vector_product_v1(
        &matrices.a2_prime,
        array_prefix::<S21_POLYNOMIALS_V1, TBOX_M2_V1>(s2),
    )
    .map_err(PresentationProofErrorV1::Toolbox)?;
    let s22 = array_suffix::<TBOX_KMSIS_V1, TBOX_M2_V1>(s2);
    let mut high = boxed_zero_polynomial_array_v1();
    let mut low = SecretPolynomialVectorV1::zero();
    for row in 0..T_A1_POLYNOMIALS_V1 {
        let commitment = Zeroizing::new(a1_short[row].add(a2_s21[row]).add(s22[row]));
        let mut high_coefficients = Zeroizing::new([0_u64; APPLICATION_RING_DEGREE_V1]);
        let mut low_coefficients = Zeroizing::new([0_i64; APPLICATION_RING_DEGREE_V1]);
        for index in 0..APPLICATION_RING_DEGREE_V1 {
            let rounded = power2round_v1(commitment.coefficients()[index])
                .map_err(PresentationProofErrorV1::Compression)?;
            high_coefficients[index] = rounded.high;
            low_coefficients[index] = rounded.low;
        }
        high[row] = ProofPolynomialV1::new(*high_coefficients)
            .map_err(|_| PresentationProofErrorV1::InternalInvariant)?;
        low.polynomials[row] = ProofPolynomialV1::from_centered_coefficients(*low_coefficients);
    }
    Ok((high, low))
}
fn quadratic_linearization(
    equation: &QuadraticEquationV1<'_>,
    secret: &QuadraticVariablesV1,
    q0: &ProofPolynomialV1,
    q_secret: &ProofPolynomialV1,
    matrices: &InternalMatricesV1,
    b_s21_linearization: &ProofPolynomialV1,
    y1: &[ProofPolynomialV1; TBOX_M1_V1],
    y21: &[ProofPolynomialV1; S21_POLYNOMIALS_V1],
) -> Result<(ProofPolynomialV1, ProofPolynomialV1), PresentationProofErrorV1> {
    let b_y21 = matrix_vector_product_v1(&matrices.b_prime, y21)
        .map_err(PresentationProofErrorV1::Toolbox)?;
    let mask = QuadraticVariablesV1 {
        short: y1
            .to_vec()
            .into_boxed_slice()
            .try_into()
            .unwrap_or_else(|_| unreachable!("response mask shape is fixed")),
        message: boxed_polynomial_array_from_fn_v1(|index| b_y21[index].negate()),
    };
    let (bilinear, linear_mask, quadratic_mask) =
        decompose_mask_quadratic_evaluations(secret, &mask, q0, q_secret, |variables| {
            equation
                .evaluate(variables)
                .map_err(PresentationProofErrorV1::Toolbox)
        })?;
    let g1 = bilinear.add(linear_mask);
    let t = b_s21_linearization.add(g1);
    let v = quadratic_mask.add(b_y21[LINEARIZATION_MESSAGE_INDEX_V1]);
    Ok((t, v))
}
fn decompose_signed_quadratic_evaluations(
    q0: &ProofPolynomialV1,
    q_positive: &ProofPolynomialV1,
    q_negative: &ProofPolynomialV1,
) -> Result<(ProofPolynomialV1, ProofPolynomialV1), PresentationProofErrorV1> {
    let linear = q_positive
        .sub(*q_negative)
        .scale_canonical(PROOF_INVERSE_TWO_V1)
        .map_err(|_| PresentationProofErrorV1::InternalInvariant)?;
    let quadratic = q_positive
        .add(*q_negative)
        .sub(q0.scale_centered(2))
        .scale_canonical(PROOF_INVERSE_TWO_V1)
        .map_err(|_| PresentationProofErrorV1::InternalInvariant)?;
    Ok((linear, quadratic))
}
fn decompose_mask_quadratic_evaluations(
    secret: &QuadraticVariablesV1,
    mask: &QuadraticVariablesV1,
    q0: &ProofPolynomialV1,
    q_secret: &ProofPolynomialV1,
    mut evaluate: impl FnMut(
        &QuadraticVariablesV1,
    ) -> Result<ProofPolynomialV1, PresentationProofErrorV1>,
) -> Result<(ProofPolynomialV1, ProofPolynomialV1, ProofPolynomialV1), PresentationProofErrorV1> {
    // Polarization needs exactly Q(mask), Q(-mask), and Q(secret + mask).
    // Q(0) and Q(secret) are supplied by the invariant prelude.
    let q_mask = Zeroizing::new(evaluate(mask)?);
    let q_negative_mask = Zeroizing::new(evaluate(&mask.negate())?);
    let q_sum = Zeroizing::new(evaluate(&secret.add(mask))?);
    let bilinear = (*q_sum).sub(*q_secret).sub(*q_mask).add(*q0);
    let (linear, quadratic) =
        decompose_signed_quadratic_evaluations(q0, &q_mask, &q_negative_mask)?;
    Ok((bilinear, linear, quadratic))
}
fn decompose_mask_commitment(
    matrices: &InternalMatricesV1,
    y1: &[ProofPolynomialV1; TBOX_M1_V1],
    y21: &[ProofPolynomialV1; S21_POLYNOMIALS_V1],
    y22: &[ProofPolynomialV1; TBOX_KMSIS_V1],
) -> Result<
    (
        [ProofPolynomialV1; TBOX_KMSIS_V1],
        SecretPolynomialVectorV1<TBOX_KMSIS_V1>,
    ),
    PresentationProofErrorV1,
> {
    let a1_y1 =
        matrix_vector_product_v1(&matrices.a1, y1).map_err(PresentationProofErrorV1::Toolbox)?;
    let a2_y21 = matrix_vector_product_v1(&matrices.a2_prime, y21)
        .map_err(PresentationProofErrorV1::Toolbox)?;
    let mut high = [ProofPolynomialV1::ZERO; TBOX_KMSIS_V1];
    let mut low = SecretPolynomialVectorV1::zero();
    for row in 0..TBOX_KMSIS_V1 {
        let commitment = Zeroizing::new(a1_y1[row].add(a2_y21[row]).add(y22[row]));
        let mut high_coefficients = Zeroizing::new([0_u64; APPLICATION_RING_DEGREE_V1]);
        let mut low_coefficients = Zeroizing::new([0_i64; APPLICATION_RING_DEGREE_V1]);
        for index in 0..APPLICATION_RING_DEGREE_V1 {
            let decomposition = gamma_decompose_v1(commitment.coefficients()[index])
                .map_err(PresentationProofErrorV1::Compression)?;
            high_coefficients[index] = decomposition.high;
            low_coefficients[index] = decomposition.low;
        }
        high[row] = ProofPolynomialV1::new(*high_coefficients)
            .map_err(|_| PresentationProofErrorV1::InternalInvariant)?;
        low.polynomials[row] = ProofPolynomialV1::from_centered_coefficients(*low_coefficients);
    }
    Ok((high, low))
}
fn make_hint(
    w1: &[ProofPolynomialV1; TBOX_KMSIS_V1],
    adjusted_z22: &[ProofPolynomialV1; TBOX_KMSIS_V1],
) -> Result<[ProofPolynomialV1; HINT_POLYNOMIALS_V1], PresentationProofErrorV1> {
    // LNP22 Figure 18 applies MakeGHint to the complete centered z2,2
    // response.  Its low part is not a gamma-decomposition remainder and
    // therefore must not be truncated or rejected at +/-gamma/2; only the
    // resulting centered hint is bounded modulo m.
    let mut hints = Zeroizing::new([ProofPolynomialV1::ZERO; HINT_POLYNOMIALS_V1]);
    for row in 0..TBOX_KMSIS_V1 {
        let gamma_high = w1[row]
            .scale_canonical(COMPRESSION_GAMMA_V1)
            .map_err(|_| PresentationProofErrorV1::InternalInvariant)?;
        let base = Zeroizing::new(gamma_high.sub(adjusted_z22[row]));
        let mut coefficients = Zeroizing::new([0_i64; APPLICATION_RING_DEGREE_V1]);
        for index in 0..APPLICATION_RING_DEGREE_V1 {
            let correction = Zeroizing::new(adjusted_z22[row].centered_coefficient(index));
            let hint = make_gamma_hint_v1(base.coefficients()[index], *correction)
                .map_err(PresentationProofErrorV1::Compression)?;
            let recovered = use_gamma_hint_v1(base.coefficients()[index], hint)
                .map_err(PresentationProofErrorV1::Compression)?;
            if recovered != w1[row].coefficients()[index] {
                return Err(PresentationProofErrorV1::InternalInvariant);
            }
            coefficients[index] = hint;
        }
        hints[row] = ProofPolynomialV1::from_centered_coefficients(*coefficients);
    }
    Ok(*hints)
}
fn recover_gamma_high(
    matrices: &InternalMatricesV1,
    z1: &[ProofPolynomialV1; Z1_POLYNOMIALS_V1],
    z21: &[ProofPolynomialV1; Z21_POLYNOMIALS_V1],
    t_a1: &[ProofPolynomialV1; T_A1_POLYNOMIALS_V1],
    challenge: &ProofPolynomialV1,
    hint: &[ProofPolynomialV1; HINT_POLYNOMIALS_V1],
) -> Result<[ProofPolynomialV1; TBOX_KMSIS_V1], PresentationProofErrorV1> {
    let tmp1 = compressed_response_residue(matrices, z1, z21, t_a1, challenge)?;
    let mut recovered = [ProofPolynomialV1::ZERO; TBOX_KMSIS_V1];
    for row in 0..TBOX_KMSIS_V1 {
        let mut coefficients = [0_u64; APPLICATION_RING_DEGREE_V1];
        for index in 0..APPLICATION_RING_DEGREE_V1 {
            let centered_hint = hint[row].centered_coefficient(index);
            coefficients[index] = use_gamma_hint_v1(tmp1[row].coefficients()[index], centered_hint)
                .map_err(PresentationProofErrorV1::Compression)?;
        }
        recovered[row] = ProofPolynomialV1::new(coefficients)
            .map_err(|_| PresentationProofErrorV1::InternalInvariant)?;
    }
    Ok(recovered)
}
fn compressed_response_residue(
    matrices: &InternalMatricesV1,
    z1: &[ProofPolynomialV1; Z1_POLYNOMIALS_V1],
    z21: &[ProofPolynomialV1; Z21_POLYNOMIALS_V1],
    t_a1: &[ProofPolynomialV1; T_A1_POLYNOMIALS_V1],
    challenge: &ProofPolynomialV1,
) -> Result<[ProofPolynomialV1; TBOX_KMSIS_V1], PresentationProofErrorV1> {
    let a1_z1 =
        matrix_vector_product_v1(&matrices.a1, z1).map_err(PresentationProofErrorV1::Toolbox)?;
    let a2_z21 = matrix_vector_product_v1(&matrices.a2_prime, z21)
        .map_err(PresentationProofErrorV1::Toolbox)?;
    let shifted_challenge = challenge.scale_centered(1_i64 << DECOMPOSITION_BITS_V1);
    Ok(core::array::from_fn(|index| {
        a1_z1[index]
            .add(a2_z21[index])
            .sub(shifted_challenge.multiply(t_a1[index]))
    }))
}
fn validate_compressed_response_bound(
    matrices: &InternalMatricesV1,
    z1: &[ProofPolynomialV1; Z1_POLYNOMIALS_V1],
    z21: &[ProofPolynomialV1; Z21_POLYNOMIALS_V1],
    t_a1: &[ProofPolynomialV1; T_A1_POLYNOMIALS_V1],
    challenge: &ProofPolynomialV1,
    recovered_w1: &[ProofPolynomialV1; TBOX_KMSIS_V1],
) -> Result<(), PresentationProofErrorV1> {
    let tmp1 = compressed_response_residue(matrices, z1, z21, t_a1, challenge)?;
    let mut norm = centered_squared_norm(z21)?;
    for row in 0..TBOX_KMSIS_V1 {
        let residual = tmp1[row].sub(
            recovered_w1[row]
                .scale_canonical(COMPRESSION_GAMMA_V1)
                .map_err(|_| PresentationProofErrorV1::InternalInvariant)?,
        );
        norm = norm
            .checked_add(residual.centered_squared_norm())
            .ok_or(PresentationProofErrorV1::ArithmeticOverflow)?;
    }
    if norm > u128::from(RESPONSE_NORM_SQUARED_BOUND_V1) {
        return Err(PresentationProofErrorV1::CompressedResponseBoundExceeded);
    }
    Ok(())
}
fn construct_proof(
    t_b: &[ProofPolynomialV1; T_B_POLYNOMIALS_V1],
    h: &[ProofPolynomialV1; H_POLYNOMIALS_V1],
    t_a1: &[ProofPolynomialV1; T_A1_POLYNOMIALS_V1],
    challenge: &ProofPolynomialV1,
    hint: &[ProofPolynomialV1; HINT_POLYNOMIALS_V1],
    z1: &[ProofPolynomialV1; Z1_POLYNOMIALS_V1],
    z21: &[ProofPolynomialV1; Z21_POLYNOMIALS_V1],
    z3: &[ProofPolynomialV1; Z3_POLYNOMIALS_V1],
    z4: &[ProofPolynomialV1; Z4_POLYNOMIALS_V1],
) -> Result<BootleLanternPresentationProofV1, PresentationProofErrorV1> {
    let mut coefficients = Vec::with_capacity(PROOF_COEFFICIENTS_V1);
    for section in [
        t_b.as_slice(),
        h.as_slice(),
        t_a1.as_slice(),
        core::slice::from_ref(challenge),
        hint.as_slice(),
        z1.as_slice(),
        z21.as_slice(),
        z3.as_slice(),
        z4.as_slice(),
    ] {
        coefficients.extend(flatten_polynomials(section));
    }
    if coefficients.len() != PROOF_COEFFICIENTS_V1 {
        return Err(PresentationProofErrorV1::InternalInvariant);
    }
    BootleLanternPresentationProofV1::from_coefficients(coefficients.into_boxed_slice())
        .map_err(PresentationProofErrorV1::Codec)
}
fn pre_challenge_wire(
    t_b: &[ProofPolynomialV1; T_B_POLYNOMIALS_V1],
    h: &[ProofPolynomialV1; H_POLYNOMIALS_V1],
    t_a1: &[ProofPolynomialV1; T_A1_POLYNOMIALS_V1],
    z3: &[ProofPolynomialV1; Z3_POLYNOMIALS_V1],
    z4: &[ProofPolynomialV1; Z4_POLYNOMIALS_V1],
    w1: &[ProofPolynomialV1; TBOX_KMSIS_V1],
    v: &ProofPolynomialV1,
) -> Result<Vec<u8>, PresentationProofErrorV1> {
    let mut output = Vec::new();
    for (tag, section) in [
        (1_u8, t_b.as_slice()),
        (2, h.as_slice()),
        (3, t_a1.as_slice()),
        (4, z3.as_slice()),
        (5, z4.as_slice()),
        (6, w1.as_slice()),
        (7, core::slice::from_ref(v)),
    ] {
        let encoded = encode_polynomials_v1(section);
        output.push(tag);
        output.extend_from_slice(
            &u32::try_from(encoded.len())
                .map_err(|_| PresentationProofErrorV1::ArithmeticOverflow)?
                .to_be_bytes(),
        );
        output.extend_from_slice(&encoded);
    }
    Ok(output)
}
fn require_relation_digest(
    relation: &BootleLanternApplicationRelationV1,
    transcript: &ProofTranscriptCoreV1,
) -> Result<(), PresentationProofErrorV1> {
    if transcript.relation_digest() != application_relation_digest_v1(relation) {
        return Err(PresentationProofErrorV1::RelationDigestMismatch);
    }
    Ok(())
}
fn require_schwartz_commitment_shape(
    h: &[ProofPolynomialV1; H_POLYNOMIALS_V1],
) -> Result<(), PresentationProofErrorV1> {
    if h.iter().any(|polynomial| {
        polynomial.coefficients()[0] != 0
            || polynomial.coefficients()[APPLICATION_RING_DEGREE_V1 / 2] != 0
    }) {
        return Err(PresentationProofErrorV1::InvalidSchwartzCommitment);
    }
    Ok(())
}
fn sample_ternary_vector<const N: usize>(
    randomness: &mut ProofRandomnessV1,
    domain: &[u8],
) -> Result<SecretPolynomialVectorV1<N>, PresentationProofErrorV1> {
    let mut output = SecretPolynomialVectorV1::zero();
    for polynomial in output.polynomials.iter_mut() {
        *polynomial = randomness
            .ternary_polynomial(domain)
            .map_err(PresentationProofErrorV1::Sampling)?;
    }
    Ok(output)
}
fn sample_gaussian_vector<const N: usize>(
    randomness: &mut ProofRandomnessV1,
    profile: BootleSamplingProfileV1,
) -> Result<SecretPolynomialVectorV1<N>, PresentationProofErrorV1> {
    if N != profile.expected_polynomials() {
        return Err(PresentationProofErrorV1::Sampling(
            SamplingErrorV1::InvalidGaussianShape,
        ));
    }
    let mut output = SecretPolynomialVectorV1::zero();
    for polynomial in output.polynomials.iter_mut() {
        *polynomial = randomness
            .gaussian_polynomial(profile)
            .map_err(PresentationProofErrorV1::Sampling)?;
    }
    Ok(output)
}
fn sample_uniform_g(
    randomness: &mut ProofRandomnessV1,
    domain: &[u8],
) -> Result<ProofPolynomialV1, PresentationProofErrorV1> {
    let uniform = randomness
        .uniform_polynomial(domain)
        .map_err(PresentationProofErrorV1::Sampling)?;
    let mut coefficients = *uniform.coefficients();
    coefficients[0] = 0;
    coefficients[APPLICATION_RING_DEGREE_V1 / 2] = 0;
    ProofPolynomialV1::new(coefficients).map_err(|_| PresentationProofErrorV1::InternalInvariant)
}
fn project_centered(
    matrix: &[i8],
    columns: usize,
    vector: &[i64],
) -> Result<Zeroizing<Vec<i64>>, PresentationProofErrorV1> {
    if columns == 0
        || vector.len() != columns
        || matrix.len()
            != PROJECTION_COORDINATES_V1
                .checked_mul(columns)
                .ok_or(PresentationProofErrorV1::ArithmeticOverflow)?
    {
        return Err(PresentationProofErrorV1::InternalInvariant);
    }
    let mut output = Zeroizing::new(vec![0_i64; PROJECTION_COORDINATES_V1]);
    for (row, value) in output.iter_mut().enumerate() {
        let start = row * columns;
        let mut accumulator = 0_i128;
        for (coefficient, secret) in matrix[start..start + columns]
            .iter()
            .copied()
            .zip(vector.iter().copied())
        {
            accumulator = accumulator
                .checked_add(i128::from(coefficient) * i128::from(secret))
                .ok_or(PresentationProofErrorV1::ArithmeticOverflow)?;
        }
        *value =
            i64::try_from(accumulator).map_err(|_| PresentationProofErrorV1::ArithmeticOverflow)?;
    }
    Ok(output)
}
fn polynomials_from_centered_projection(
    coefficients: &[i64],
) -> Box<[ProofPolynomialV1; PROJECTION_POLYNOMIALS_V1]> {
    debug_assert_eq!(coefficients.len(), PROJECTION_COORDINATES_V1);
    boxed_polynomial_array_from_fn_v1(|polynomial| {
        let start = polynomial * APPLICATION_RING_DEGREE_V1;
        let mut array = [0_i64; APPLICATION_RING_DEGREE_V1];
        array.copy_from_slice(&coefficients[start..start + APPLICATION_RING_DEGREE_V1]);
        ProofPolynomialV1::from_centered_coefficients(array)
    })
}
fn multiply_vector_by_polynomial<const N: usize>(
    vector: &[ProofPolynomialV1; N],
    scalar: &ProofPolynomialV1,
) -> Box<[ProofPolynomialV1; N]> {
    boxed_polynomial_array_from_fn_v1(|index| scalar.multiply(vector[index]))
}
fn add_arrays<const N: usize>(
    lhs: &[ProofPolynomialV1; N],
    rhs: &[ProofPolynomialV1; N],
) -> Box<[ProofPolynomialV1; N]> {
    boxed_polynomial_array_from_fn_v1(|index| lhs[index].add(rhs[index]))
}
fn centered_vector(polynomials: &[ProofPolynomialV1]) -> Vec<i64> {
    let mut output = Vec::with_capacity(polynomials.len() * APPLICATION_RING_DEGREE_V1);
    for polynomial in polynomials {
        for index in 0..APPLICATION_RING_DEGREE_V1 {
            output.push(polynomial.centered_coefficient(index));
        }
    }
    output
}
fn centered_squared_norm(
    polynomials: &[ProofPolynomialV1],
) -> Result<u128, PresentationProofErrorV1> {
    let mut norm = 0_u128;
    for polynomial in polynomials {
        norm = norm
            .checked_add(polynomial.centered_squared_norm())
            .ok_or(PresentationProofErrorV1::ArithmeticOverflow)?;
    }
    Ok(norm)
}
fn proof_polynomial_array<const N: usize>(
    mut polynomial: impl FnMut(usize) -> Option<ProofPolynomialV1>,
) -> Result<Box<[ProofPolynomialV1; N]>, PresentationProofErrorV1> {
    let mut output = Vec::with_capacity(N);
    for index in 0..N {
        output.push(polynomial(index).ok_or(PresentationProofErrorV1::MalformedProof)?);
    }
    output
        .into_boxed_slice()
        .try_into()
        .map_err(|_| PresentationProofErrorV1::InternalInvariant)
}
fn array_prefix<const N: usize, const M: usize>(
    input: &[ProofPolynomialV1; M],
) -> &[ProofPolynomialV1; N] {
    input[..N]
        .try_into()
        .expect("fixed profile prefix shape is valid")
}
fn array_suffix<const N: usize, const M: usize>(
    input: &[ProofPolynomialV1; M],
) -> &[ProofPolynomialV1; N] {
    input[M - N..]
        .try_into()
        .expect("fixed profile suffix shape is valid")
}
/// Complete native presentation proof failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum PresentationProofErrorV1 {
    /// The transcript named another compiled application relation.
    #[error("Bootle/Lantern transcript relation digest mismatch")]
    RelationDigestMismatch,
    /// Native sampling failed.
    #[error("Bootle/Lantern presentation sampling failed: {0}")]
    Sampling(SamplingErrorV1),
    /// Constraint compilation or transparent expansion failed.
    #[error("Bootle/Lantern presentation toolbox failed: {0}")]
    Toolbox(ToolboxErrorV1),
    /// Canonical compression or reconciliation failed.
    #[error("Bootle/Lantern presentation compression failed: {0}")]
    Compression(CompressionErrorV1),
    /// Strict proof construction failed.
    #[error("Bootle/Lantern presentation proof codec failed: {0}")]
    Codec(ProofCodecErrorV1),
    /// A public response exceeded its fixed theorem-derived bound.
    #[error("Bootle/Lantern presentation public response bound failed: {0}")]
    ResponseBound(ResponseBoundErrorV1),
    /// The lifted application quotient exceeded the fixed ARP bound.
    #[error("Bootle/Lantern lifted application quotient exceeds its fixed bound")]
    ApplicationQuotientBoundExceeded,
    /// The compressed, partially hidden `z2` response exceeded its bound.
    #[error("Bootle/Lantern compressed response exceeds its fixed squared-norm bound")]
    CompressedResponseBoundExceeded,
    /// A public Schwartz commitment exposed a non-zero checked coefficient.
    #[error("Bootle/Lantern Schwartz commitment has a non-zero checked coefficient")]
    InvalidSchwartzCommitment,
    /// The exact constraint system rejected a purported valid witness.
    #[error("Bootle/Lantern constraint system rejected the presentation witness")]
    ConstraintSystemRejectedWitness,
    /// The stored challenge did not match verifier reconstruction.
    #[error("Bootle/Lantern Fiat--Shamir challenge mismatch")]
    ChallengeMismatch,
    /// A typed section was unexpectedly absent from a validated proof.
    #[error("Bootle/Lantern validated proof has a malformed typed section")]
    MalformedProof,
    /// The shared bounded rejection-sampling budget was exhausted.
    ///
    /// The public error deliberately omits the retry stage and counters because
    /// those diagnostics are derived from secret prover work.
    #[error("Bootle/Lantern sampling exhausted the shared proof work budget")]
    SamplingBudgetExhausted,
    /// Prover output failed the independent verifier.
    #[error("Bootle/Lantern prover self-check failed")]
    ProverSelfCheckFailed,
    /// Checked arithmetic overflowed.
    #[error("Bootle/Lantern presentation arithmetic overflowed")]
    ArithmeticOverflow,
    /// A fixed implementation invariant failed.
    #[error("Bootle/Lantern presentation internal invariant failed")]
    InternalInvariant,
}
// INTEGER_ONLY_PROOF_PRODUCTION_END
#[cfg(test)]
/// Sole privacy-action index in a canonical first-release Bootle/Lantern presentation transaction.
pub const BOOTLE_LANTERN_PRESENTATION_PRIVACY_ACTION_INDEX_V1: u32 = 0;
#[cfg(test)]
/// Exact signature-bound transaction fields for one direct Bootle/Lantern presentation.
#[derive(Clone, Debug)]
pub struct BootleLanternPresentationPrivacyActionTransactionContextV1 {
    /// Exact genesis-header-derived transaction security domain.
    pub network_id: NetworkId,
    /// Exact single-key transaction authority.
    pub authority: AccountId,
    /// Required creation time, resolved once before intent derivation.
    pub creation_time: Duration,
    /// Optional transaction TTL.
    pub time_to_live: Option<Duration>,
    /// Optional transaction nonce.
    pub nonce: Option<NonZeroU32>,
    /// Exact signature-bound fee payer and maxima.
    pub fee_payment: FeePaymentIntent,
    /// Exact transaction metadata.
    pub metadata: Metadata,
}
/// Exact ledger effect certified by a first-release Bootle/Lantern presentation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootleLanternPresentationPrivacyActionEffectV1 {
    /// Consensus verifies and finalizes the presentation without inferring a
    /// balance, nullifier, or credential-registry mutation.
    PresentationVerificationAndFinalityOnly,
}
#[cfg(test)]
/// Pure Bootle/Lantern proving output ready for transaction signing.
///
/// The final payload, canonical genesis binding, and exact governed issuer policy are private. This
/// type deliberately implements neither `Clone` nor a serialization trait. Its only public
/// production transition is the consuming
/// [`sign_prepared_bootle_lantern_presentation_privacy_action_v1`] boundary.
pub struct BootleLanternPreparedPresentationPrivacyActionV1 {
    payload: TransactionPayload,
    canonical_genesis_hash: [u8; 32],
    issuer_policy: BootleLanternIssuerPolicyV1,
    issuer_policy_hash: [u8; 32],
    transaction_intent_digest: [u8; 32],
    statement_digest: [u8; 32],
    proof_envelope_hash: [u8; 32],
    statement_bytes: u32,
    proof_bytes: u32,
    encoded_proof_envelope_bytes: u32,
}
#[cfg(test)]
impl core::fmt::Debug for BootleLanternPreparedPresentationPrivacyActionV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BootleLanternPreparedPresentationPrivacyActionV1")
            .field("issuer_policy_hash", &self.issuer_policy_hash)
            .field("transaction_intent_digest", &self.transaction_intent_digest)
            .field("statement_digest", &self.statement_digest)
            .field("proof_envelope_hash", &self.proof_envelope_hash)
            .field("statement_bytes", &self.statement_bytes)
            .field("proof_bytes", &self.proof_bytes)
            .field(
                "encoded_proof_envelope_bytes",
                &self.encoded_proof_envelope_bytes,
            )
            .finish_non_exhaustive()
    }
}
#[cfg(test)]
impl BootleLanternPreparedPresentationPrivacyActionV1 {
    /// Exact state effect certified by the prepared presentation.
    #[must_use]
    pub const fn effect(&self) -> BootleLanternPresentationPrivacyActionEffectV1 {
        BootleLanternPresentationPrivacyActionEffectV1::PresentationVerificationAndFinalityOnly
    }
    /// Hash of the exact canonical governed issuer-policy encoding.
    #[must_use]
    pub const fn issuer_policy_hash(&self) -> [u8; 32] {
        self.issuer_policy_hash
    }
    /// Canonical proof-independent transaction-intent digest.
    #[must_use]
    pub const fn transaction_intent_digest(&self) -> [u8; 32] {
        self.transaction_intent_digest
    }
    /// Canonical complete typed-statement digest.
    #[must_use]
    pub const fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }
    /// Hash of the exact canonical proof envelope.
    #[must_use]
    pub const fn proof_envelope_hash(&self) -> [u8; 32] {
        self.proof_envelope_hash
    }
    /// Canonical encoded typed-statement byte count.
    #[must_use]
    pub const fn statement_bytes(&self) -> u32 {
        self.statement_bytes
    }
    /// Exact fixed-profile native presentation proof byte count.
    #[must_use]
    pub const fn proof_bytes(&self) -> u32 {
        self.proof_bytes
    }
    /// Canonical encoded proof-envelope byte count.
    #[must_use]
    pub const fn encoded_proof_envelope_bytes(&self) -> u32 {
        self.encoded_proof_envelope_bytes
    }
}
/// Complete signed result produced by the canonical Bootle/Lantern presentation path.
pub struct SignedBootleLanternPresentationPrivacyActionV1 {
    signed_transaction: SignedTransaction,
    transaction_hash: [u8; 32],
    adaptive_signed_transaction_bytes: u32,
    issuer_policy_hash: [u8; 32],
    transaction_intent_digest: [u8; 32],
    statement_digest: [u8; 32],
    proof_envelope_hash: [u8; 32],
    statement_bytes: u32,
    proof_bytes: u32,
    encoded_proof_envelope_bytes: u32,
}
impl core::fmt::Debug for SignedBootleLanternPresentationPrivacyActionV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SignedBootleLanternPresentationPrivacyActionV1")
            .field("transaction_hash", &self.transaction_hash)
            .field(
                "adaptive_signed_transaction_bytes",
                &self.adaptive_signed_transaction_bytes,
            )
            .field("issuer_policy_hash", &self.issuer_policy_hash)
            .field("transaction_intent_digest", &self.transaction_intent_digest)
            .field("statement_digest", &self.statement_digest)
            .field("proof_envelope_hash", &self.proof_envelope_hash)
            .field("statement_bytes", &self.statement_bytes)
            .field("proof_bytes", &self.proof_bytes)
            .field(
                "encoded_proof_envelope_bytes",
                &self.encoded_proof_envelope_bytes,
            )
            .finish_non_exhaustive()
    }
}
impl SignedBootleLanternPresentationPrivacyActionV1 {
    /// Borrow the exact signed transaction.
    #[must_use]
    pub const fn signed_transaction(&self) -> &SignedTransaction {
        &self.signed_transaction
    }
    /// Consume the result and return the exact signed transaction.
    #[must_use]
    pub fn into_signed_transaction(self) -> SignedTransaction {
        self.signed_transaction
    }
    /// Canonical transaction hash.
    #[must_use]
    pub const fn transaction_hash(&self) -> [u8; 32] {
        self.transaction_hash
    }
    /// Canonical adaptive signed-transaction byte count.
    #[must_use]
    pub const fn adaptive_signed_transaction_bytes(&self) -> u32 {
        self.adaptive_signed_transaction_bytes
    }
    /// Exact state effect certified by the signed presentation.
    #[must_use]
    pub const fn effect(&self) -> BootleLanternPresentationPrivacyActionEffectV1 {
        BootleLanternPresentationPrivacyActionEffectV1::PresentationVerificationAndFinalityOnly
    }
    /// Hash of the exact canonical governed issuer-policy encoding.
    #[must_use]
    pub const fn issuer_policy_hash(&self) -> [u8; 32] {
        self.issuer_policy_hash
    }
    /// Canonical proof-independent transaction-intent digest.
    #[must_use]
    pub const fn transaction_intent_digest(&self) -> [u8; 32] {
        self.transaction_intent_digest
    }
    /// Canonical complete typed-statement digest.
    #[must_use]
    pub const fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }
    /// Hash of the exact canonical proof envelope.
    #[must_use]
    pub const fn proof_envelope_hash(&self) -> [u8; 32] {
        self.proof_envelope_hash
    }
    /// Canonical encoded typed-statement byte count.
    #[must_use]
    pub const fn statement_bytes(&self) -> u32 {
        self.statement_bytes
    }
    /// Exact fixed-profile native presentation proof byte count.
    #[must_use]
    pub const fn proof_bytes(&self) -> u32 {
        self.proof_bytes
    }
    /// Canonical encoded proof-envelope byte count.
    #[must_use]
    pub const fn encoded_proof_envelope_bytes(&self) -> u32 {
        self.encoded_proof_envelope_bytes
    }
}
#[cfg(test)]
/// Failure while constructing or validating a canonical Bootle/Lantern
/// presentation transaction intent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum BootleLanternPresentationPrivacyActionIntentErrorV1 {
    /// Creation time cannot be represented in the transaction wire.
    #[error("Bootle/Lantern presentation creation time cannot be represented in milliseconds")]
    CreationTimeOutOfRange,
    /// TTL cannot be represented in the transaction wire.
    #[error("Bootle/Lantern presentation TTL cannot be represented in milliseconds")]
    TimeToLiveOutOfRange,
    /// Fee intent, TTL, or fee metadata violates canonical transaction policy.
    #[error("Bootle/Lantern presentation transaction context is not canonical")]
    InvalidTransactionContext,
    /// The locally compiled governed Bootle/Lantern profile is unavailable.
    #[error("the compiled native Bootle/Lantern profile is unavailable")]
    CompiledProfileUnavailable,
    /// The issuer policy is malformed, revoked, or not the exact active record.
    #[error("the Bootle/Lantern presentation issuer policy is not an active canonical record")]
    InvalidIssuerPolicy,
    /// The statement or its exact compiled context is invalid.
    #[error("the locally produced Bootle/Lantern presentation statement failed validation")]
    StatementValidation,
    /// The typed statement could not derive its canonical digest.
    #[error("Bootle/Lantern presentation statement digest derivation failed")]
    StatementDigest,
    /// The unsigned payload could not derive its canonical privacy intent.
    #[error("Bootle/Lantern presentation transaction-intent derivation failed")]
    TransactionIntent,
    /// The final one-action payload did not reproduce the stored intent binding.
    #[error("the locally produced Bootle/Lantern presentation payload failed intent validation")]
    FinalIntentBinding,
}
#[cfg(test)]
/// Closed failure for the canonical prove-then-sign Bootle/Lantern presentation path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum BootleLanternPresentationPrivacyActionBuildErrorV1 {
    /// Two-pass transaction-intent construction failed.
    #[error(transparent)]
    Intent(#[from] BootleLanternPresentationPrivacyActionIntentErrorV1),
    /// The all-zero genesis sentinel is never a canonical chain binding.
    #[error("Bootle/Lantern presentation requires a non-zero canonical genesis hash")]
    ZeroGenesisHash,
    /// The signed transaction domain does not equal the supplied canonical genesis hash.
    #[error(
        "Bootle/Lantern presentation transaction network does not match the canonical genesis hash"
    )]
    NetworkIdMismatch,
    /// Native relation compilation, proof construction, or verification failed.
    #[error(transparent)]
    Native(#[from] super::BoundPresentationErrorV1),
    /// The typed statement could not derive its canonical digest.
    #[error("Bootle/Lantern presentation statement digest derivation failed")]
    StatementDigest,
    /// The typed statement could not be canonically encoded.
    #[error("the locally produced Bootle/Lantern presentation statement could not be encoded")]
    StatementEncoding,
    /// The governed issuer policy could not be canonically encoded.
    #[error("the governed Bootle/Lantern issuer policy could not be encoded")]
    IssuerPolicyEncoding,
    /// The complete proof envelope failed intrinsic consensus validation.
    #[error("the locally produced Bootle/Lantern proof envelope failed validation")]
    EnvelopeValidation,
    /// The complete proof envelope could not be canonically encoded.
    #[error("the locally produced Bootle/Lantern proof envelope could not be encoded")]
    EnvelopeEncoding,
    /// A bounded canonical byte length did not fit its public result field.
    #[error("a canonical Bootle/Lantern presentation byte length overflowed")]
    EncodedLengthOverflow,
    /// The final proved payload did not reproduce the draft-derived intent.
    #[error("the locally produced Bootle/Lantern payload failed final intent validation")]
    FinalIntentBinding,
    /// The sealed prepared payload no longer matches its integrity record.
    #[error("the prepared Bootle/Lantern presentation failed integrity validation")]
    PreparedPayloadDrift,
    /// The authority is multisig and cannot use the single-key constructor.
    #[error("the Bootle/Lantern presentation authority is not a single-key authority")]
    UnsupportedAuthority,
    /// The supplied private key does not control the exact authority.
    #[error("the supplied Bootle/Lantern signing key does not control the authority")]
    AuthorityKeyMismatch,
    /// The transaction signature backend failed without exposing key material.
    #[error("Bootle/Lantern presentation transaction signing failed")]
    TransactionSigning,
    /// The signed payload differs from the prepared proof or intent.
    #[error("signed Bootle/Lantern presentation differs from the prepared action")]
    SignedIntentMismatch,
}
#[cfg(test)]
fn validate_bootle_lantern_presentation_transaction_context_v1(
    context: &BootleLanternPresentationPrivacyActionTransactionContextV1,
) -> Result<(), BootleLanternPresentationPrivacyActionIntentErrorV1> {
    if context.creation_time.as_millis() > u128::from(u64::MAX) {
        return Err(BootleLanternPresentationPrivacyActionIntentErrorV1::CreationTimeOutOfRange);
    }
    if context
        .time_to_live
        .is_some_and(|ttl| ttl.as_millis() > u128::from(u64::MAX))
    {
        return Err(BootleLanternPresentationPrivacyActionIntentErrorV1::TimeToLiveOutOfRange);
    }
    let mut builder = TransactionBuilder::new(
        context.network_id,
        context.authority.clone(),
        context.fee_payment.clone(),
    )
    .with_metadata(context.metadata.clone());
    builder.set_creation_time(context.creation_time);
    if let Some(ttl) = context.time_to_live {
        builder.set_ttl(ttl);
    }
    if let Some(nonce) = context.nonce {
        builder.set_nonce(nonce);
    }
    builder
        .into_payload()
        .map(|_| ())
        .map_err(|_| BootleLanternPresentationPrivacyActionIntentErrorV1::InvalidTransactionContext)
}
#[cfg(test)]
fn validate_bootle_lantern_active_issuer_policy_v1(
    policy: &BootleLanternIssuerPolicyV1,
) -> Result<(), BootleLanternPresentationPrivacyActionIntentErrorV1> {
    policy
        .validate()
        .map_err(|_| BootleLanternPresentationPrivacyActionIntentErrorV1::InvalidIssuerPolicy)?;
    if policy.lifecycle != BootleLanternIssuerPolicyLifecycleV1::Active {
        return Err(BootleLanternPresentationPrivacyActionIntentErrorV1::InvalidIssuerPolicy);
    }
    Ok(())
}
#[cfg(test)]
fn bootle_lantern_presentation_statement_context_v1(
    context: &BootleLanternPresentationPrivacyActionTransactionContextV1,
    profile: crate::privacy_profiles::CompiledPrivacyProfileV1,
    transaction_intent_digest: PrivacyTransactionIntentDigestV1,
) -> PrivacyStatementContextV1 {
    PrivacyStatementContextV1 {
        network_id: context.network_id,
        action_index: BOOTLE_LANTERN_PRESENTATION_PRIVACY_ACTION_INDEX_V1,
        transaction_intent_digest,
        parameter_id: profile.parameter_id,
        parameter_digest: profile.parameter_digest,
        verifier_digest: profile.verifier_digest,
        statement_schema_digest: profile.statement_schema_digest,
        engine_manifest_digest: profile.engine_manifest_digest,
    }
}
#[cfg(test)]
fn bootle_lantern_presentation_statement_v1(
    context: PrivacyStatementContextV1,
    policy: &BootleLanternIssuerPolicyV1,
    disclosures: Vec<BootleLanternDisclosedAttributeV1>,
) -> IrohaBootleLanternAnoncredStatementV1 {
    IrohaBootleLanternAnoncredStatementV1 {
        context,
        issuer_id: policy.issuer_id,
        policy_id: policy.policy_id,
        issuer_policy_epoch: policy.epoch,
        issuer_policy_record_digest: policy.record_digest,
        issuer_parameter_id: policy.issuer_parameter_id,
        issuer_parameter_digest: policy.issuer_parameter_digest,
        disclosures,
    }
}
#[cfg(test)]
fn bootle_lantern_presentation_transaction_payload_v1(
    context: &BootleLanternPresentationPrivacyActionTransactionContextV1,
    envelope: PrivacyProofEnvelopeV1,
) -> Result<TransactionPayload, BootleLanternPresentationPrivacyActionIntentErrorV1> {
    let mut builder = TransactionBuilder::new(
        context.network_id,
        context.authority.clone(),
        context.fee_payment.clone(),
    )
    .with_instructions([SubmitPrivacyProofV1::new(envelope)])
    .with_metadata(context.metadata.clone());
    builder.set_creation_time(context.creation_time);
    if let Some(ttl) = context.time_to_live {
        builder.set_ttl(ttl);
    }
    if let Some(nonce) = context.nonce {
        builder.set_nonce(nonce);
    }
    builder
        .into_payload()
        .map_err(|_| BootleLanternPresentationPrivacyActionIntentErrorV1::InvalidTransactionContext)
}
#[cfg(test)]
fn bootle_lantern_presentation_envelope_v1(
    statement: IrohaBootleLanternAnoncredStatementV1,
    proof: Vec<u8>,
) -> PrivacyProofEnvelopeV1 {
    PrivacyProofEnvelopeV1::bind_v1(
        PrivacyStatementV1::IrohaBootleLanternAnoncredV1(statement),
        PrivacyProofV1::IrohaBootleLanternAnoncredV1(PrivacyProofBytesV1::new(proof)),
    )
    .expect("a Bootle/Lantern statement binds its own proof variant")
}
#[cfg(test)]
fn bootle_lantern_statement_matches_policy_v1(
    statement: &IrohaBootleLanternAnoncredStatementV1,
    policy: &BootleLanternIssuerPolicyV1,
) -> bool {
    let authoritative_issuer_epoch = policy.epoch;
    statement.issuer_id == policy.issuer_id
        && statement.policy_id == policy.policy_id
        && statement.issuer_policy_epoch == authoritative_issuer_epoch
        && statement.issuer_policy_record_digest == policy.record_digest
        && statement.issuer_parameter_id == policy.issuer_parameter_id
        && statement.issuer_parameter_digest == policy.issuer_parameter_digest
}
#[cfg(test)]
/// Construct the canonical single-action Bootle/Lantern statement and derive
/// its proof-independent transaction-intent digest.
///
/// The proof-empty projection is local to this function and cannot escape as a
/// prepared or signable payload.
///
/// # Errors
///
/// Returns a closed error for an invalid transaction context, unavailable compiled profile,
/// non-active issuer policy, malformed disclosures, or final intent-binding drift.
pub fn prepare_bootle_lantern_presentation_transaction_intent_v1(
    context: &BootleLanternPresentationPrivacyActionTransactionContextV1,
    policy: &BootleLanternIssuerPolicyV1,
    disclosures: Vec<BootleLanternDisclosedAttributeV1>,
) -> Result<
    IrohaBootleLanternAnoncredStatementV1,
    BootleLanternPresentationPrivacyActionIntentErrorV1,
> {
    validate_bootle_lantern_presentation_transaction_context_v1(context)?;
    validate_bootle_lantern_active_issuer_policy_v1(policy)?;
    let profile = crate::privacy_profiles::compiled_privacy_profile_v1(
        PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1,
    )
    .map_err(|_| BootleLanternPresentationPrivacyActionIntentErrorV1::CompiledProfileUnavailable)?;
    let mut statement = bootle_lantern_presentation_statement_v1(
        bootle_lantern_presentation_statement_context_v1(
            context,
            profile,
            PrivacyTransactionIntentDigestV1::new([0; 32]),
        ),
        policy,
        disclosures,
    );
    let projection = bootle_lantern_presentation_envelope_v1(statement.clone(), Vec::new());
    let transaction_intent_digest =
        bootle_lantern_presentation_transaction_payload_v1(context, projection)?
            .privacy_transaction_intent_digest_v1()
            .map_err(|_| BootleLanternPresentationPrivacyActionIntentErrorV1::TransactionIntent)?;
    statement.context.transaction_intent_digest = transaction_intent_digest;
    let validated =
        validate_bootle_lantern_presentation_transaction_intent_v1(context, policy, &statement)?;
    if validated != transaction_intent_digest {
        return Err(BootleLanternPresentationPrivacyActionIntentErrorV1::FinalIntentBinding);
    }
    Ok(statement)
}
#[cfg(test)]
/// Validate a prepared Bootle/Lantern statement against its exact direct
/// transaction context and active governed issuer policy.
///
/// # Errors
///
/// Returns a closed error for context, profile, policy, statement, digest, or final intent drift.
pub fn validate_bootle_lantern_presentation_transaction_intent_v1(
    context: &BootleLanternPresentationPrivacyActionTransactionContextV1,
    policy: &BootleLanternIssuerPolicyV1,
    statement: &IrohaBootleLanternAnoncredStatementV1,
) -> Result<PrivacyTransactionIntentDigestV1, BootleLanternPresentationPrivacyActionIntentErrorV1> {
    validate_bootle_lantern_presentation_transaction_context_v1(context)?;
    validate_bootle_lantern_active_issuer_policy_v1(policy)?;
    let profile = crate::privacy_profiles::compiled_privacy_profile_v1(
        PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1,
    )
    .map_err(|_| BootleLanternPresentationPrivacyActionIntentErrorV1::CompiledProfileUnavailable)?;
    let expected_context = bootle_lantern_presentation_statement_context_v1(
        context,
        profile,
        statement.context.transaction_intent_digest,
    );
    if statement.context != expected_context
        || !bootle_lantern_statement_matches_policy_v1(statement, policy)
    {
        return Err(BootleLanternPresentationPrivacyActionIntentErrorV1::StatementValidation);
    }
    let typed_statement = PrivacyStatementV1::IrohaBootleLanternAnoncredV1(statement.clone());
    typed_statement
        .validate(&PrivacyConsensusLimitsV1::taira_default())
        .map_err(|_| BootleLanternPresentationPrivacyActionIntentErrorV1::StatementValidation)?;
    typed_statement
        .digest()
        .map_err(|_| BootleLanternPresentationPrivacyActionIntentErrorV1::StatementDigest)?;
    let projection = bootle_lantern_presentation_envelope_v1(statement.clone(), Vec::new());
    let validated = bootle_lantern_presentation_transaction_payload_v1(context, projection)?
        .validate_privacy_transaction_intent_binding_v1()
        .map_err(|_| BootleLanternPresentationPrivacyActionIntentErrorV1::FinalIntentBinding)?;
    if validated != statement.context.transaction_intent_digest {
        return Err(BootleLanternPresentationPrivacyActionIntentErrorV1::FinalIntentBinding);
    }
    Ok(validated)
}
#[cfg(test)]
#[derive(Clone, Copy)]
struct BootleLanternPresentationPrivacyActionIntegrityV1 {
    canonical_genesis_hash: [u8; 32],
    issuer_policy_hash: [u8; 32],
    transaction_intent_digest: [u8; 32],
    statement_digest: [u8; 32],
    proof_envelope_hash: [u8; 32],
    statement_bytes: u32,
    proof_bytes: u32,
    encoded_proof_envelope_bytes: u32,
}
#[cfg(test)]
impl BootleLanternPreparedPresentationPrivacyActionV1 {
    #[cfg(test)]
    const fn integrity(&self) -> BootleLanternPresentationPrivacyActionIntegrityV1 {
        BootleLanternPresentationPrivacyActionIntegrityV1 {
            canonical_genesis_hash: self.canonical_genesis_hash,
            issuer_policy_hash: self.issuer_policy_hash,
            transaction_intent_digest: self.transaction_intent_digest,
            statement_digest: self.statement_digest,
            proof_envelope_hash: self.proof_envelope_hash,
            statement_bytes: self.statement_bytes,
            proof_bytes: self.proof_bytes,
            encoded_proof_envelope_bytes: self.encoded_proof_envelope_bytes,
        }
    }
}
#[cfg(test)]
fn bootle_lantern_issuer_policy_hash_v1(
    policy: &BootleLanternIssuerPolicyV1,
) -> Result<[u8; 32], BootleLanternPresentationPrivacyActionBuildErrorV1> {
    let encoding = norito::to_bytes(policy)
        .map_err(|_| BootleLanternPresentationPrivacyActionBuildErrorV1::IssuerPolicyEncoding)?;
    Ok(*Hash::new(&encoding).as_ref())
}
#[cfg(test)]
fn validate_bootle_lantern_presentation_signing_authority_v1(
    authority: &AccountId,
    private_key: &PrivateKey,
) -> Result<(), BootleLanternPresentationPrivacyActionBuildErrorV1> {
    let expected = authority
        .try_signatory()
        .ok_or(BootleLanternPresentationPrivacyActionBuildErrorV1::UnsupportedAuthority)?;
    let derived = PublicKey::from(private_key.clone());
    if expected != &derived {
        return Err(BootleLanternPresentationPrivacyActionBuildErrorV1::AuthorityKeyMismatch);
    }
    Ok(())
}
#[cfg(test)]
fn validate_bootle_lantern_presentation_payload_integrity_v1(
    payload: &TransactionPayload,
    policy: &BootleLanternIssuerPolicyV1,
    expected: BootleLanternPresentationPrivacyActionIntegrityV1,
) -> Result<(), ()> {
    if expected.canonical_genesis_hash == [0; 32]
        || payload
            .network_id()
            .is_none_or(|network_id| network_id.as_bytes() != &expected.canonical_genesis_hash)
        || validate_bootle_lantern_active_issuer_policy_v1(policy).is_err()
    {
        return Err(());
    }
    let policy_encoding = norito::to_bytes(policy).map_err(|_| ())?;
    if *Hash::new(&policy_encoding).as_ref() != expected.issuer_policy_hash {
        return Err(());
    }
    match payload.instructions() {
        Executable::Instructions(instructions)
            if instructions.len() == 1
                && instructions[0]
                    .as_any()
                    .downcast_ref::<SubmitPrivacyProofV1>()
                    .is_some() => {}
        _ => return Err(()),
    }
    if payload.attachments.is_some() {
        return Err(());
    }
    let (intent, submission) = payload
        .privacy_transaction_intent_binding_if_present_v1()
        .map_err(|_| ())?
        .ok_or(())?;
    if intent.as_bytes() != &expected.transaction_intent_digest {
        return Err(());
    }
    let envelope = &submission.envelope;
    envelope
        .validate_with_limits(&PrivacyConsensusLimitsV1::taira_default())
        .map_err(|_| ())?;
    let profile = crate::privacy_profiles::compiled_privacy_profile_v1(
        PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1,
    )
    .map_err(|_| ())?;
    if envelope.protocol_id != profile.protocol_id
        || envelope.proof_system_id != profile.proof_system_id
        || envelope.engine_id != profile.engine_id
        || envelope.parameter_id != profile.parameter_id
        || envelope.parameter_digest != profile.parameter_digest
        || envelope.verifier_digest != profile.verifier_digest
        || envelope.statement_schema_digest != profile.statement_schema_digest
        || envelope.engine_manifest_digest != profile.engine_manifest_digest
        || envelope.statement_digest.as_bytes() != &expected.statement_digest
    {
        return Err(());
    }
    let PrivacyStatementV1::IrohaBootleLanternAnoncredV1(statement) = &envelope.statement else {
        return Err(());
    };
    if statement.context.action_index != BOOTLE_LANTERN_PRESENTATION_PRIVACY_ACTION_INDEX_V1
        || statement.context.transaction_intent_digest.as_bytes()
            != &expected.transaction_intent_digest
        || !bootle_lantern_statement_matches_policy_v1(statement, policy)
    {
        return Err(());
    }
    let statement_digest = envelope.statement.digest().map_err(|_| ())?;
    if statement_digest.as_bytes() != &expected.statement_digest {
        return Err(());
    }
    let statement_encoding = norito::to_bytes(&envelope.statement).map_err(|_| ())?;
    if u32::try_from(statement_encoding.len()).map_err(|_| ())? != expected.statement_bytes {
        return Err(());
    }
    let PrivacyProofV1::IrohaBootleLanternAnoncredV1(proof) = &envelope.proof else {
        return Err(());
    };
    let fixed_proof_bytes = u32::try_from(super::codec::PROOF_BYTES_V1).map_err(|_| ())?;
    if u32::try_from(proof.as_bytes().len()).map_err(|_| ())? != expected.proof_bytes
        || expected.proof_bytes != fixed_proof_bytes
    {
        return Err(());
    }
    let decoded =
        BootleLanternPresentationProofV1::decode_exact(proof.as_bytes(), fixed_proof_bytes)
            .map_err(|_| ())?;
    super::verify_bound_presentation_v1(
        statement,
        policy,
        expected.canonical_genesis_hash,
        &decoded,
    )
    .map_err(|_| ())?;
    let envelope_encoding = norito::to_bytes(envelope).map_err(|_| ())?;
    if u32::try_from(envelope_encoding.len()).map_err(|_| ())?
        != expected.encoded_proof_envelope_bytes
        || *Hash::new(&envelope_encoding).as_ref() != expected.proof_envelope_hash
    {
        return Err(());
    }
    Ok(())
}
#[cfg(test)]
fn finalize_bootle_lantern_prepared_presentation_privacy_action_v1(
    context: &BootleLanternPresentationPrivacyActionTransactionContextV1,
    issuer_policy: BootleLanternIssuerPolicyV1,
    statement: IrohaBootleLanternAnoncredStatementV1,
    proof: BootleLanternPresentationProofV1,
    canonical_genesis_hash: [u8; 32],
) -> Result<
    BootleLanternPreparedPresentationPrivacyActionV1,
    BootleLanternPresentationPrivacyActionBuildErrorV1,
> {
    let profile = crate::privacy_profiles::compiled_privacy_profile_v1(
        PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1,
    )
    .map_err(|_| BootleLanternPresentationPrivacyActionIntentErrorV1::CompiledProfileUnavailable)?;
    let typed_statement = PrivacyStatementV1::IrohaBootleLanternAnoncredV1(statement.clone());
    typed_statement
        .validate(&PrivacyConsensusLimitsV1::taira_default())
        .map_err(|_| BootleLanternPresentationPrivacyActionBuildErrorV1::EnvelopeValidation)?;
    let statement_digest = typed_statement
        .digest()
        .map_err(|_| BootleLanternPresentationPrivacyActionBuildErrorV1::StatementDigest)?;
    let statement_bytes = u32::try_from(
        norito::to_bytes(&typed_statement)
            .map_err(|_| BootleLanternPresentationPrivacyActionBuildErrorV1::StatementEncoding)?
            .len(),
    )
    .map_err(|_| BootleLanternPresentationPrivacyActionBuildErrorV1::EncodedLengthOverflow)?;
    let proof_encoding = proof.encode();
    if proof_encoding.len() != super::codec::PROOF_BYTES_V1 {
        return Err(BootleLanternPresentationPrivacyActionBuildErrorV1::EncodedLengthOverflow);
    }
    let proof_bytes = u32::try_from(proof_encoding.len())
        .map_err(|_| BootleLanternPresentationPrivacyActionBuildErrorV1::EncodedLengthOverflow)?;
    let final_envelope = bootle_lantern_presentation_envelope_v1(statement, proof_encoding);
    if !profile.matches_envelope_v1(&final_envelope) {
        return Err(BootleLanternPresentationPrivacyActionBuildErrorV1::EnvelopeValidation);
    }
    final_envelope
        .validate_with_limits(&PrivacyConsensusLimitsV1::taira_default())
        .map_err(|_| BootleLanternPresentationPrivacyActionBuildErrorV1::EnvelopeValidation)?;
    let envelope_encoding = norito::to_bytes(&final_envelope)
        .map_err(|_| BootleLanternPresentationPrivacyActionBuildErrorV1::EnvelopeEncoding)?;
    let encoded_proof_envelope_bytes = u32::try_from(envelope_encoding.len())
        .map_err(|_| BootleLanternPresentationPrivacyActionBuildErrorV1::EncodedLengthOverflow)?;
    let proof_envelope_hash = *Hash::new(&envelope_encoding).as_ref();
    let issuer_policy_hash = bootle_lantern_issuer_policy_hash_v1(&issuer_policy)?;
    let final_payload =
        bootle_lantern_presentation_transaction_payload_v1(context, final_envelope)?;
    let transaction_intent_digest = final_payload
        .validate_privacy_transaction_intent_binding_v1()
        .map_err(|_| BootleLanternPresentationPrivacyActionBuildErrorV1::FinalIntentBinding)?;
    let prepared = BootleLanternPreparedPresentationPrivacyActionV1 {
        payload: final_payload,
        canonical_genesis_hash,
        issuer_policy,
        issuer_policy_hash,
        transaction_intent_digest: *transaction_intent_digest.as_bytes(),
        statement_digest: *statement_digest.as_bytes(),
        proof_envelope_hash,
        statement_bytes,
        proof_bytes,
        encoded_proof_envelope_bytes,
    };
    validate_bootle_lantern_presentation_payload_integrity_v1(
        &prepared.payload,
        &prepared.issuer_policy,
        prepared.integrity(),
    )
    .map_err(|()| BootleLanternPresentationPrivacyActionBuildErrorV1::PreparedPayloadDrift)?;
    Ok(prepared)
}
#[cfg(test)]
/// Prepare and prove one canonical Bootle/Lantern presentation with
/// caller-provided cryptographically secure randomness.
///
/// The function accepts the final statement returned by
/// [`prepare_bootle_lantern_presentation_transaction_intent_v1`], revalidates
/// every public binding before the first random draw, proves the exact governed
/// relation, and returns one sealed non-cloneable final payload.
///
/// # Errors
///
/// Returns a closed context, policy, statement, relation, witness, native
/// proof, encoding, or integrity failure.
pub fn prepare_bootle_lantern_presentation_privacy_action_with_rng_v1<R>(
    context: BootleLanternPresentationPrivacyActionTransactionContextV1,
    issuer_policy: BootleLanternIssuerPolicyV1,
    statement: IrohaBootleLanternAnoncredStatementV1,
    witness: &BootleLanternPresentationWitnessV1,
    canonical_genesis_hash: [u8; 32],
    rng: &mut R,
) -> Result<
    BootleLanternPreparedPresentationPrivacyActionV1,
    BootleLanternPresentationPrivacyActionBuildErrorV1,
>
where
    R: CryptoRng + RngCore,
{
    if canonical_genesis_hash == [0; 32] {
        return Err(BootleLanternPresentationPrivacyActionBuildErrorV1::ZeroGenesisHash);
    }
    if context.network_id.as_bytes() != &canonical_genesis_hash {
        return Err(BootleLanternPresentationPrivacyActionBuildErrorV1::NetworkIdMismatch);
    }
    validate_bootle_lantern_presentation_transaction_intent_v1(
        &context,
        &issuer_policy,
        &statement,
    )?;
    let proof = super::prove_bound_presentation_v1(
        &statement,
        &issuer_policy,
        canonical_genesis_hash,
        witness,
        rng,
    )?;
    finalize_bootle_lantern_prepared_presentation_privacy_action_v1(
        &context,
        issuer_policy,
        statement,
        proof,
        canonical_genesis_hash,
    )
}
#[cfg(test)]
/// Consume and sign a payload returned by the canonical Bootle/Lantern presentation prover.
///
/// The complete proof, statement, envelope, active issuer policy, genesis
/// binding, and proof-independent transaction intent are independently
/// revalidated immediately before and after signing.
///
/// # Errors
///
/// Returns a closed failure for prepared drift, unsupported authority,
/// authority/key mismatch, signing failure, or post-sign drift.
pub fn sign_prepared_bootle_lantern_presentation_privacy_action_v1(
    prepared: BootleLanternPreparedPresentationPrivacyActionV1,
    private_key: &PrivateKey,
) -> Result<
    SignedBootleLanternPresentationPrivacyActionV1,
    BootleLanternPresentationPrivacyActionBuildErrorV1,
> {
    validate_bootle_lantern_presentation_signing_authority_v1(
        prepared.payload.authority(),
        private_key,
    )?;
    let integrity = prepared.integrity();
    validate_bootle_lantern_presentation_payload_integrity_v1(
        &prepared.payload,
        &prepared.issuer_policy,
        integrity,
    )
    .map_err(|()| BootleLanternPresentationPrivacyActionBuildErrorV1::PreparedPayloadDrift)?;
    let BootleLanternPreparedPresentationPrivacyActionV1 {
        payload,
        issuer_policy,
        ..
    } = prepared;
    let signed_transaction = TransactionBuilder::from_payload(payload)
        .map_err(|_| {
            BootleLanternPresentationPrivacyActionIntentErrorV1::InvalidTransactionContext
        })?
        .try_sign(private_key)
        .map_err(|error| match error {
            TransactionSignatureError::UnsupportedMultisigAuthority => {
                BootleLanternPresentationPrivacyActionBuildErrorV1::UnsupportedAuthority
            }
            TransactionSignatureError::AuthorityKeyMismatch => {
                BootleLanternPresentationPrivacyActionBuildErrorV1::AuthorityKeyMismatch
            }
            TransactionSignatureError::InvalidFeePaymentIntent(_) => {
                BootleLanternPresentationPrivacyActionIntentErrorV1::InvalidTransactionContext
                    .into()
            }
            _ => BootleLanternPresentationPrivacyActionBuildErrorV1::TransactionSigning,
        })?;
    validate_bootle_lantern_presentation_payload_integrity_v1(
        signed_transaction.payload(),
        &issuer_policy,
        integrity,
    )
    .map_err(|()| BootleLanternPresentationPrivacyActionBuildErrorV1::SignedIntentMismatch)?;
    let transaction_hash = *signed_transaction.hash().as_ref();
    let adaptive_signed_transaction_bytes =
        u32::try_from(norito::codec::encode_adaptive(&signed_transaction).len()).map_err(|_| {
            BootleLanternPresentationPrivacyActionBuildErrorV1::EncodedLengthOverflow
        })?;
    Ok(SignedBootleLanternPresentationPrivacyActionV1 {
        signed_transaction,
        transaction_hash,
        adaptive_signed_transaction_bytes,
        issuer_policy_hash: integrity.issuer_policy_hash,
        transaction_intent_digest: integrity.transaction_intent_digest,
        statement_digest: integrity.statement_digest,
        proof_envelope_hash: integrity.proof_envelope_hash,
        statement_bytes: integrity.statement_bytes,
        proof_bytes: integrity.proof_bytes,
        encoded_proof_envelope_bytes: integrity.encoded_proof_envelope_bytes,
    })
}
#[cfg(test)]
/// Build, prove, bind, and sign one canonical Bootle/Lantern presentation with
/// caller-provided cryptographically secure randomness.
///
/// Authority validation precedes all proof randomness and proof work.
///
/// # Errors
///
/// Returns a closed validation, proving, binding, or signing failure.
pub fn build_signed_bootle_lantern_presentation_privacy_action_with_rng_v1<R>(
    context: BootleLanternPresentationPrivacyActionTransactionContextV1,
    issuer_policy: BootleLanternIssuerPolicyV1,
    statement: IrohaBootleLanternAnoncredStatementV1,
    witness: &BootleLanternPresentationWitnessV1,
    canonical_genesis_hash: [u8; 32],
    private_key: &PrivateKey,
    rng: &mut R,
) -> Result<
    SignedBootleLanternPresentationPrivacyActionV1,
    BootleLanternPresentationPrivacyActionBuildErrorV1,
>
where
    R: CryptoRng + RngCore,
{
    validate_bootle_lantern_presentation_signing_authority_v1(&context.authority, private_key)?;
    let prepared = prepare_bootle_lantern_presentation_privacy_action_with_rng_v1(
        context,
        issuer_policy,
        statement,
        witness,
        canonical_genesis_hash,
        rng,
    )?;
    sign_prepared_bootle_lantern_presentation_privacy_action_v1(prepared, private_key)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_engines::bootle_lantern::{
        BOOTLE_LANTERN_FULL_ENGINE_AVAILABLE_V1, BoundPresentationEncodedErrorV1,
        BoundPresentationErrorV1,
        codec::{PROOF_BYTES_V1, PROOF_HEADER_BYTES_V1},
        compression::proof_residue_from_centered_v1,
        issuer::{
            BootleLanternInMemoryIssuanceStoreV1, BootleLanternIssuerKeyPairV1,
            BootleLanternIssuerPolicyMetadataV1, holder_finalize_blind_issuance_v1,
            holder_prepare_blind_issuance_with_rng_v1, issuer_authorize_blind_issuance_with_rng_v1,
            issuer_blind_issue_once_with_rng_v1,
        },
        params::{
            APPLICATION_MODULUS_V1, CHALLENGE_OMEGA_V1, COMPRESSION_MODULUS_V1, PROOF_MODULUS_V1,
            Z4_INFINITY_NORM_BOUND_V1,
        },
        prove_bound_presentation_v1,
        relation::{compile_application_relation_v1, validate_presentation_witness_v1},
        ring::ApplicationPolynomialV1,
        transcript::{
            BlindIssuanceRequestChallengeBindingV1, MatrixSeedV1, PresentationChallengeBindingV1,
            matrix_seed_v1,
        },
        verify_bound_presentation_encoded_v1, verify_bound_presentation_v1,
    };
    use core::num::NonZeroU64;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::privacy::{
        BootleLanternAllowedAttributeValuesV1, BootleLanternAttributeValueV1,
        BootleLanternDisclosedAttributeV1, BootleLanternIssuerPolicyV1,
        IrohaBootleLanternAnoncredStatementV1, PrivacyBootleLanternIssuerPolicyDigestV1,
        PrivacyEngineManifestDigestV1, PrivacyIssuerIdV1, PrivacyParameterDigestV1,
        PrivacyParameterIdV1, PrivacyPolicyIdV1, PrivacyStatementContextV1,
        PrivacyStatementSchemaDigestV1, PrivacyStatementV1, PrivacyTransactionIntentDigestV1,
        PrivacyVerifierDigestV1,
    };
    use rand_core_06::{CryptoRng, Error as RngError, RngCore};
    use sha3::{Digest, Sha3_256};
    use std::sync::OnceLock;
    const H_START_TEST: usize = T_B_POLYNOMIALS_V1 * APPLICATION_RING_DEGREE_V1;
    const T_A1_START_TEST: usize = H_START_TEST + H_POLYNOMIALS_V1 * APPLICATION_RING_DEGREE_V1;
    const CHALLENGE_START_TEST: usize =
        T_A1_START_TEST + T_A1_POLYNOMIALS_V1 * APPLICATION_RING_DEGREE_V1;
    const HINT_START_TEST: usize = CHALLENGE_START_TEST + APPLICATION_RING_DEGREE_V1;
    const Z1_START_TEST: usize = HINT_START_TEST + HINT_POLYNOMIALS_V1 * APPLICATION_RING_DEGREE_V1;
    const Z21_START_TEST: usize = Z1_START_TEST + Z1_POLYNOMIALS_V1 * APPLICATION_RING_DEGREE_V1;
    const Z3_START_TEST: usize = Z21_START_TEST + Z21_POLYNOMIALS_V1 * APPLICATION_RING_DEGREE_V1;
    const Z4_START_TEST: usize = Z3_START_TEST + Z3_POLYNOMIALS_V1 * APPLICATION_RING_DEGREE_V1;
    struct TestRng {
        state: u64,
        fail: bool,
        stuck: Option<u8>,
        period: Option<u8>,
    }
    struct PanicRng;
    impl RngCore for PanicRng {
        fn next_u32(&mut self) -> u32 {
            panic!("Bootle/Lantern public preflight reached the random source")
        }
        fn next_u64(&mut self) -> u64 {
            panic!("Bootle/Lantern public preflight reached the random source")
        }
        fn fill_bytes(&mut self, _destination: &mut [u8]) {
            panic!("Bootle/Lantern public preflight reached the random source")
        }
        fn try_fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), RngError> {
            panic!("Bootle/Lantern public preflight reached the random source")
        }
    }
    impl CryptoRng for PanicRng {}
    impl TestRng {
        const fn healthy(seed: u64) -> Self {
            Self {
                state: seed,
                fail: false,
                stuck: None,
                period: None,
            }
        }
        const fn failed() -> Self {
            Self {
                state: 1,
                fail: true,
                stuck: None,
                period: None,
            }
        }
        const fn stuck(byte: u8) -> Self {
            Self {
                state: 1,
                fail: false,
                stuck: Some(byte),
                period: None,
            }
        }
        const fn periodic(period: u8) -> Self {
            Self {
                state: 1,
                fail: false,
                stuck: None,
                period: Some(period),
            }
        }
    }
    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            let mut bytes = [0_u8; 4];
            self.fill_bytes(&mut bytes);
            u32::from_le_bytes(bytes)
        }
        fn next_u64(&mut self) -> u64 {
            let mut bytes = [0_u8; 8];
            self.fill_bytes(&mut bytes);
            u64::from_le_bytes(bytes)
        }
        fn fill_bytes(&mut self, destination: &mut [u8]) {
            self.try_fill_bytes(destination)
                .expect("infallible test invocation");
        }
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RngError> {
            if self.fail {
                return Err(RngError::new("injected Bootle/Lantern RNG failure"));
            }
            if let Some(byte) = self.stuck {
                destination.fill(byte);
                return Ok(());
            }
            if let Some(period) = self.period {
                for (index, byte) in destination.iter_mut().enumerate() {
                    *byte = ((index % usize::from(period)) as u8)
                        .wrapping_mul(31)
                        .wrapping_add(5);
                }
                return Ok(());
            }
            for byte in destination {
                self.state ^= self.state << 13;
                self.state ^= self.state >> 7;
                self.state ^= self.state << 17;
                *byte = self.state as u8;
            }
            Ok(())
        }
    }
    impl CryptoRng for TestRng {}
    struct Fixture {
        policy: BootleLanternIssuerPolicyV1,
        statement: IrohaBootleLanternAnoncredStatementV1,
        genesis_hash: [u8; 32],
        relation: BootleLanternApplicationRelationV1,
        witness: BootleLanternPresentationWitnessV1,
        transcript: PresentationTranscriptV1,
    }
    fn raw(seed: u8) -> [u8; 32] {
        [seed; 32]
    }
    fn compiled_bootle_lantern_profile() -> crate::privacy_profiles::CompiledPrivacyProfileV1 {
        crate::privacy_profiles::compiled_privacy_profile_v1(
            PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1,
        )
        .expect("compiled Bootle/Lantern profile")
    }
    fn matrix_seed() -> MatrixSeedV1 {
        matrix_seed_v1([0x31; 32]).expect("valid governed matrix seed")
    }
    fn statement_context() -> PrivacyStatementContextV1 {
        PrivacyStatementContextV1 {
            network_id: NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
                iroha_data_model::block::BlockHeader,
            >::from_untyped_unchecked(
                Hash::prehashed([0x32; 32])
            )),
            action_index: 3,
            transaction_intent_digest: PrivacyTransactionIntentDigestV1::new(raw(1)),
            parameter_id: PrivacyParameterIdV1::new(raw(2)),
            parameter_digest: PrivacyParameterDigestV1::new([0x31; 32]),
            verifier_digest: PrivacyVerifierDigestV1::new(raw(4)),
            statement_schema_digest: PrivacyStatementSchemaDigestV1::new(raw(5)),
            engine_manifest_digest: PrivacyEngineManifestDigestV1::new(raw(6)),
        }
    }
    fn statement(policy: &BootleLanternIssuerPolicyV1) -> IrohaBootleLanternAnoncredStatementV1 {
        IrohaBootleLanternAnoncredStatementV1 {
            context: statement_context(),
            issuer_id: policy.issuer_id,
            policy_id: policy.policy_id,
            issuer_policy_epoch: policy.epoch,
            issuer_policy_record_digest: policy.record_digest,
            issuer_parameter_id: policy.issuer_parameter_id,
            issuer_parameter_digest: policy.issuer_parameter_digest,
            disclosures: vec![BootleLanternDisclosedAttributeV1 {
                index: 1,
                value: BootleLanternAttributeValueV1::new([1; 8]),
            }],
        }
    }
    struct IssuedFixture {
        policy: BootleLanternIssuerPolicyV1,
        statement: IrohaBootleLanternAnoncredStatementV1,
        witness: BootleLanternPresentationWitnessV1,
        p1_relation: BootleLanternApplicationRelationV1,
        p1_transcript: BlindIssuanceRequestTranscriptV1,
        p1_proof: BootleLanternBlindIssuanceRequestProofV1,
    }
    fn issued_fixture() -> &'static IssuedFixture {
        static FIXTURE: OnceLock<IssuedFixture> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            let mut keygen_rng = TestRng::healthy(0x6a09_e667_f3bc_c908);
            let issuer_key_pair = BootleLanternIssuerKeyPairV1::generate_with_rng_v1(
                PrivacyParameterIdV1::new(raw(13)),
                &mut keygen_rng,
            )
            .expect("native issuer key generation");
            let policy = issuer_key_pair
                .active_policy_v1(BootleLanternIssuerPolicyMetadataV1 {
                    issuer_id: PrivacyIssuerIdV1::new(raw(11)),
                    policy_id: PrivacyPolicyIdV1::new(raw(12)),
                    epoch: 1,
                    required_disclosure_bitmap: 0b0000_0010,
                    allowed_values: (0..8)
                        .map(|index| BootleLanternAllowedAttributeValuesV1 {
                            values: if index == 1 {
                                vec![BootleLanternAttributeValueV1::new([1; 8])]
                            } else {
                                Vec::new()
                            },
                        })
                        .collect(),
                })
                .expect("active native issuer policy");
            let context = statement_context();
            let genesis_hash = *statement_context().network_id.as_bytes();
            let issuance_store = BootleLanternInMemoryIssuanceStoreV1::new();
            let mut authorization_rng = TestRng::healthy(0x1f83_d9ab_fb41_bd6b);
            let authorization = issuer_authorize_blind_issuance_with_rng_v1(
                &issuer_key_pair,
                &context,
                genesis_hash,
                &policy,
                [0x71; 32],
                10,
                20,
                &issuance_store,
                &mut authorization_rng,
            )
            .expect("one-shot issuer authorization");
            let mut attributes = [[0_u8; 8]; 8];
            attributes[1] = [1; 8];
            let mut holder_issuance_rng = TestRng::healthy(0xbb67_ae85_84ca_a73b);
            let (request, state) = holder_prepare_blind_issuance_with_rng_v1(
                &context,
                genesis_hash,
                &policy,
                &authorization,
                attributes,
                &mut holder_issuance_rng,
            )
            .expect("holder blind-issuance request");
            let (p1_relation, p1_transcript) = request
                .compile_transcript_v1(&context, genesis_hash, &policy, &authorization)
                .expect("canonical P1 relation and transcript");
            let p1_proof = request.proof_v1().clone();
            verify_blind_issuance_request_v1(&p1_relation, &p1_transcript, &p1_proof)
                .expect("holder's nominal P1 proof verifies before issuance");
            let mut issuer_issuance_rng = TestRng::healthy(0xa54f_f53a_5f1d_36f1);
            let response = issuer_blind_issue_once_with_rng_v1(
                &issuer_key_pair,
                &context,
                genesis_hash,
                &policy,
                &authorization,
                &request,
                11,
                &issuance_store,
                &mut issuer_issuance_rng,
            )
            .expect("native blind issuance");
            let credential =
                holder_finalize_blind_issuance_v1(state, &context, genesis_hash, &policy, response)
                    .expect("holder issuance finalization");
            let statement = statement(&policy);
            let witness = credential
                .presentation_witness_v1(&statement, &policy, genesis_hash)
                .expect("issued presentation witness");
            IssuedFixture {
                policy,
                statement,
                witness,
                p1_relation,
                p1_transcript,
                p1_proof,
            }
        })
    }
    struct SealedIssuedFixture {
        policy: BootleLanternIssuerPolicyV1,
        statement: IrohaBootleLanternAnoncredStatementV1,
        witness: BootleLanternPresentationWitnessV1,
    }
    fn sealed_statement_context() -> PrivacyStatementContextV1 {
        let profile = compiled_bootle_lantern_profile();
        PrivacyStatementContextV1 {
            network_id: NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
                iroha_data_model::block::BlockHeader,
            >::from_untyped_unchecked(
                Hash::prehashed([0x32; 32])
            )),
            action_index: 3,
            transaction_intent_digest: PrivacyTransactionIntentDigestV1::new(raw(1)),
            parameter_id: profile.parameter_id,
            parameter_digest: profile.parameter_digest,
            verifier_digest: profile.verifier_digest,
            statement_schema_digest: profile.statement_schema_digest,
            engine_manifest_digest: profile.engine_manifest_digest,
        }
    }
    fn sealed_issued_fixture() -> &'static SealedIssuedFixture {
        static FIXTURE: OnceLock<SealedIssuedFixture> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            let mut keygen_rng = TestRng::healthy(0x6a09_e667_f3bc_c908);
            let issuer_key_pair = BootleLanternIssuerKeyPairV1::generate_with_rng_v1(
                PrivacyParameterIdV1::new(raw(13)),
                &mut keygen_rng,
            )
            .expect("native sealed-fixture issuer key generation");
            let policy = issuer_key_pair
                .active_policy_v1(BootleLanternIssuerPolicyMetadataV1 {
                    issuer_id: PrivacyIssuerIdV1::new(raw(11)),
                    policy_id: PrivacyPolicyIdV1::new(raw(12)),
                    epoch: 1,
                    required_disclosure_bitmap: 0b0000_0010,
                    allowed_values: (0..8)
                        .map(|index| BootleLanternAllowedAttributeValuesV1 {
                            values: if index == 1 {
                                vec![BootleLanternAttributeValueV1::new([1; 8])]
                            } else {
                                Vec::new()
                            },
                        })
                        .collect(),
                })
                .expect("active sealed-fixture issuer policy");
            let context = sealed_statement_context();
            let genesis_hash = *statement_context().network_id.as_bytes();
            let issuance_store = BootleLanternInMemoryIssuanceStoreV1::new();
            let mut authorization_rng = TestRng::healthy(0x1f83_d9ab_fb41_bd6b);
            let authorization = issuer_authorize_blind_issuance_with_rng_v1(
                &issuer_key_pair,
                &context,
                genesis_hash,
                &policy,
                [0x71; 32],
                10,
                20,
                &issuance_store,
                &mut authorization_rng,
            )
            .expect("sealed-fixture issuer authorization");
            let mut attributes = [[0_u8; 8]; 8];
            attributes[1] = [1; 8];
            let mut holder_issuance_rng = TestRng::healthy(0xbb67_ae85_84ca_a73b);
            let (request, state) = holder_prepare_blind_issuance_with_rng_v1(
                &context,
                genesis_hash,
                &policy,
                &authorization,
                attributes,
                &mut holder_issuance_rng,
            )
            .expect("sealed-fixture holder blind-issuance request");
            let (p1_relation, p1_transcript) = request
                .compile_transcript_v1(&context, genesis_hash, &policy, &authorization)
                .expect("sealed-fixture P1 relation and transcript");
            verify_blind_issuance_request_v1(&p1_relation, &p1_transcript, request.proof_v1())
                .expect("sealed-fixture P1 proof verifies before issuance");
            let mut issuer_issuance_rng = TestRng::healthy(0xa54f_f53a_5f1d_36f1);
            let response = issuer_blind_issue_once_with_rng_v1(
                &issuer_key_pair,
                &context,
                genesis_hash,
                &policy,
                &authorization,
                &request,
                11,
                &issuance_store,
                &mut issuer_issuance_rng,
            )
            .expect("sealed-fixture native blind issuance");
            let credential =
                holder_finalize_blind_issuance_v1(state, &context, genesis_hash, &policy, response)
                    .expect("sealed-fixture holder issuance finalization");
            let mut statement = statement(&policy);
            statement.context = context;
            let witness = credential
                .presentation_witness_v1(&statement, &policy, genesis_hash)
                .expect("sealed-fixture presentation witness");
            SealedIssuedFixture {
                policy,
                statement,
                witness,
            }
        })
    }
    fn valid_witness() -> BootleLanternPresentationWitnessV1 {
        issued_fixture().witness.clone()
    }
    fn fixture() -> Fixture {
        let issued = issued_fixture();
        let policy = issued.policy.clone();
        let statement = issued.statement.clone();
        let genesis_hash = *statement_context().network_id.as_bytes();
        let relation =
            compile_application_relation_v1(&statement, &policy, matrix_seed(), genesis_hash)
                .expect("compiled application relation");
        let witness = issued.witness.clone();
        validate_presentation_witness_v1(&relation, &witness).expect("valid presentation witness");
        let statement_digest = PrivacyStatementV1::IrohaBootleLanternAnoncredV1(statement.clone())
            .digest()
            .expect("canonical typed statement digest");
        let transcript = PresentationTranscriptV1::new(
            PresentationChallengeBindingV1 {
                parameter_digest: *statement.context.parameter_digest.as_bytes(),
                genesis_hash,
                statement_digest: *statement_digest.as_bytes(),
                issuer_policy_record_digest: *statement.issuer_policy_record_digest.as_bytes(),
                transaction_intent_digest: *statement.context.transaction_intent_digest.as_bytes(),
            },
            matrix_seed(),
            application_relation_digest_v1(&relation),
        )
        .expect("fully bound presentation transcript");
        Fixture {
            policy,
            statement,
            genesis_hash,
            relation,
            witness,
            transcript,
        }
    }
    fn proof_from_mutation(
        proof: &BootleLanternPresentationProofV1,
        mutate: impl FnOnce(&mut [u64]),
    ) -> BootleLanternPresentationProofV1 {
        let mut coefficients = proof.coefficients().to_vec();
        mutate(&mut coefficients);
        BootleLanternPresentationProofV1::from_coefficients(coefficients.into_boxed_slice())
            .expect("mutation remains a canonical proof encoding")
    }
    fn alternate_residue(residue: u64) -> u64 {
        if residue == 0 { 1 } else { 0 }
    }
    fn presentation_action_signer(seed: u8) -> KeyPair {
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("derive Bootle/Lantern presentation signer")
    }
    fn presentation_action_context(
        signer: &KeyPair,
    ) -> BootleLanternPresentationPrivacyActionTransactionContextV1 {
        BootleLanternPresentationPrivacyActionTransactionContextV1 {
            network_id: NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
                iroha_data_model::block::BlockHeader,
            >::from_untyped_unchecked(
                Hash::prehashed([0x32; 32])
            )),
            authority: AccountId::new(signer.public_key().clone()),
            creation_time: Duration::from_millis(1_800_000_000_321),
            time_to_live: Some(Duration::from_secs(60)),
            nonce: NonZeroU32::new(17),
            fee_payment: FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(5_000_000)),
            metadata: Metadata::default(),
        }
    }
    fn presentation_action_statement(
        context: &BootleLanternPresentationPrivacyActionTransactionContextV1,
        policy: &BootleLanternIssuerPolicyV1,
    ) -> IrohaBootleLanternAnoncredStatementV1 {
        prepare_bootle_lantern_presentation_transaction_intent_v1(
            context,
            policy,
            sealed_issued_fixture().statement.disclosures.clone(),
        )
        .expect("derive canonical Bootle/Lantern presentation transaction intent")
    }
    fn clone_prepared_for_adversary(
        prepared: &BootleLanternPreparedPresentationPrivacyActionV1,
    ) -> BootleLanternPreparedPresentationPrivacyActionV1 {
        BootleLanternPreparedPresentationPrivacyActionV1 {
            payload: prepared.payload.clone(),
            canonical_genesis_hash: prepared.canonical_genesis_hash,
            issuer_policy: prepared.issuer_policy.clone(),
            issuer_policy_hash: prepared.issuer_policy_hash,
            transaction_intent_digest: prepared.transaction_intent_digest,
            statement_digest: prepared.statement_digest,
            proof_envelope_hash: prepared.proof_envelope_hash,
            statement_bytes: prepared.statement_bytes,
            proof_bytes: prepared.proof_bytes,
            encoded_proof_envelope_bytes: prepared.encoded_proof_envelope_bytes,
        }
    }
    fn replace_prepared_envelope_for_adversary(
        prepared: &mut BootleLanternPreparedPresentationPrivacyActionV1,
        context: &BootleLanternPresentationPrivacyActionTransactionContextV1,
        mutate: impl FnOnce(&mut PrivacyProofEnvelopeV1),
    ) {
        let mut envelope = prepared
            .payload
            .privacy_transaction_intent_binding_if_present_v1()
            .expect("canonical prepared privacy scan")
            .expect("one prepared Bootle/Lantern presentation")
            .1
            .envelope
            .clone();
        mutate(&mut envelope);
        prepared.payload = bootle_lantern_presentation_transaction_payload_v1(context, envelope)
            .expect("adversarial payload remains structurally constructible");
    }
    #[test]
    fn sealed_presentation_builder_preflights_public_failures_before_randomness() {
        let signer = presentation_action_signer(90);
        let context = presentation_action_context(&signer);
        let policy = sealed_issued_fixture().policy.clone();
        let statement = presentation_action_statement(&context, &policy);
        assert!(matches!(
            prepare_bootle_lantern_presentation_privacy_action_with_rng_v1(
                context,
                policy,
                statement,
                &sealed_issued_fixture().witness,
                [0; 32],
                &mut PanicRng,
            ),
            Err(BootleLanternPresentationPrivacyActionBuildErrorV1::ZeroGenesisHash)
        ));
        let signer = presentation_action_signer(90);
        let context = presentation_action_context(&signer);
        let policy = sealed_issued_fixture().policy.clone();
        let statement = presentation_action_statement(&context, &policy);
        assert!(matches!(
            prepare_bootle_lantern_presentation_privacy_action_with_rng_v1(
                context,
                policy,
                statement,
                &sealed_issued_fixture().witness,
                [0x33; 32],
                &mut PanicRng,
            ),
            Err(BootleLanternPresentationPrivacyActionBuildErrorV1::NetworkIdMismatch)
        ));
        let signer = presentation_action_signer(90);
        let foreign = presentation_action_signer(91);
        let context = presentation_action_context(&signer);
        let policy = sealed_issued_fixture().policy.clone();
        let statement = presentation_action_statement(&context, &policy);
        assert!(matches!(
            build_signed_bootle_lantern_presentation_privacy_action_with_rng_v1(
                context,
                policy,
                statement,
                &sealed_issued_fixture().witness,
                *statement_context().network_id.as_bytes(),
                foreign.private_key(),
                &mut PanicRng,
            ),
            Err(BootleLanternPresentationPrivacyActionBuildErrorV1::AuthorityKeyMismatch)
        ));
        let signer = presentation_action_signer(90);
        let context = presentation_action_context(&signer);
        let mut revoked_policy = sealed_issued_fixture().policy.clone();
        revoked_policy.lifecycle = BootleLanternIssuerPolicyLifecycleV1::Revoked;
        revoked_policy.record_digest = revoked_policy
            .computed_record_digest()
            .expect("recompute adversarial revoked policy digest");
        let mut statement =
            presentation_action_statement(&context, &sealed_issued_fixture().policy);
        statement.issuer_policy_record_digest = revoked_policy.record_digest;
        assert!(matches!(
            prepare_bootle_lantern_presentation_privacy_action_with_rng_v1(
                context,
                revoked_policy,
                statement,
                &sealed_issued_fixture().witness,
                *statement_context().network_id.as_bytes(),
                &mut PanicRng,
            ),
            Err(BootleLanternPresentationPrivacyActionBuildErrorV1::Intent(
                BootleLanternPresentationPrivacyActionIntentErrorV1::InvalidIssuerPolicy
            ))
        ));
        let signer = presentation_action_signer(90);
        let context = presentation_action_context(&signer);
        let policy = sealed_issued_fixture().policy.clone();
        let mut disallowed = sealed_issued_fixture().statement.disclosures.clone();
        disallowed[0].value = BootleLanternAttributeValueV1::new([2; 8]);
        let statement = prepare_bootle_lantern_presentation_transaction_intent_v1(
            &context, &policy, disallowed,
        )
        .expect("structural statement intent remains derivable");
        assert!(matches!(
            prepare_bootle_lantern_presentation_privacy_action_with_rng_v1(
                context,
                policy,
                statement,
                &sealed_issued_fixture().witness,
                *statement_context().network_id.as_bytes(),
                &mut PanicRng,
            ),
            Err(BootleLanternPresentationPrivacyActionBuildErrorV1::Native(
                super::super::BoundPresentationErrorV1::Relation(_)
            ))
        ));
    }
    #[test]
    fn sealed_presentation_builder_revalidates_every_binding_before_and_after_signing() {
        let signer = presentation_action_signer(90);
        let context = presentation_action_context(&signer);
        let policy = sealed_issued_fixture().policy.clone();
        let statement = presentation_action_statement(&context, &policy);
        let prepared = prepare_bootle_lantern_presentation_privacy_action_with_rng_v1(
            context.clone(),
            policy,
            statement,
            &sealed_issued_fixture().witness,
            *statement_context().network_id.as_bytes(),
            &mut TestRng::healthy(0x510e_527f_ade6_82d1),
        )
        .expect("prepare sealed Bootle/Lantern presentation action");
        assert_eq!(
            prepared.effect(),
            BootleLanternPresentationPrivacyActionEffectV1::PresentationVerificationAndFinalityOnly
        );
        assert_ne!(prepared.issuer_policy_hash(), [0; 32]);
        assert_ne!(prepared.transaction_intent_digest(), [0; 32]);
        assert_ne!(prepared.statement_digest(), [0; 32]);
        assert_ne!(prepared.proof_envelope_hash(), [0; 32]);
        assert!(prepared.statement_bytes() > 0);
        assert_eq!(
            prepared.proof_bytes(),
            u32::try_from(PROOF_BYTES_V1).expect("fixed proof length fits u32")
        );
        assert!(prepared.encoded_proof_envelope_bytes() > prepared.proof_bytes());
        validate_bootle_lantern_presentation_payload_integrity_v1(
            &prepared.payload,
            &prepared.issuer_policy,
            prepared.integrity(),
        )
        .expect("prepared presentation independently revalidates");
        match prepared.payload.instructions() {
            Executable::Instructions(instructions) => {
                assert_eq!(instructions.len(), 1, "exactly one direct presentation");
                assert!(
                    instructions[0]
                        .as_any()
                        .downcast_ref::<SubmitPrivacyProofV1>()
                        .is_some(),
                    "the sole action is the typed privacy submission"
                );
            }
            other => panic!("unexpected Bootle/Lantern executable: {other:?}"),
        }
        assert!(prepared.payload.attachments.is_none());
        let prepared_debug = format!("{prepared:?}");
        assert!(!prepared_debug.contains("TransactionPayload"));
        assert!(!prepared_debug.contains("issuer_policy:"));
        assert!(!prepared_debug.contains("canonical_genesis_hash"));
        let expected_intent = prepared.transaction_intent_digest();
        let expected_statement = prepared.statement_digest();
        let expected_envelope = prepared.proof_envelope_hash();
        let expected_policy = prepared.issuer_policy_hash();
        let signed = sign_prepared_bootle_lantern_presentation_privacy_action_v1(
            clone_prepared_for_adversary(&prepared),
            signer.private_key(),
        )
        .expect("consume and sign sealed Bootle/Lantern presentation");
        signed
            .signed_transaction()
            .verify_signature()
            .expect("locally signed Bootle/Lantern transaction verifies");
        assert_eq!(signed.transaction_intent_digest(), expected_intent);
        assert_eq!(signed.statement_digest(), expected_statement);
        assert_eq!(signed.proof_envelope_hash(), expected_envelope);
        assert_eq!(signed.issuer_policy_hash(), expected_policy);
        assert_eq!(
            signed.transaction_hash(),
            *signed.signed_transaction().hash().as_ref()
        );
        assert_eq!(
            signed.adaptive_signed_transaction_bytes(),
            u32::try_from(norito::codec::encode_adaptive(signed.signed_transaction()).len())
                .expect("bounded signed Bootle/Lantern transaction")
        );
        let assert_drift = |candidate| {
            assert!(matches!(
                sign_prepared_bootle_lantern_presentation_privacy_action_v1(
                    candidate,
                    signer.private_key(),
                ),
                Err(BootleLanternPresentationPrivacyActionBuildErrorV1::PreparedPayloadDrift)
            ));
        };
        let mut nonce_substitution = clone_prepared_for_adversary(&prepared);
        nonce_substitution.payload.nonce = NonZeroU32::new(18);
        assert_drift(nonce_substitution);
        let mut genesis_substitution = clone_prepared_for_adversary(&prepared);
        genesis_substitution.canonical_genesis_hash[0] ^= 1;
        assert_drift(genesis_substitution);
        let mut payload_substitution = clone_prepared_for_adversary(&prepared);
        payload_substitution.payload.instructions = Executable::Instructions(Vec::new().into());
        assert_drift(payload_substitution);
        let mut statement_substitution = clone_prepared_for_adversary(&prepared);
        replace_prepared_envelope_for_adversary(
            &mut statement_substitution,
            &context,
            |envelope| {
                let PrivacyStatementV1::IrohaBootleLanternAnoncredV1(statement) =
                    &mut envelope.statement
                else {
                    unreachable!()
                };
                statement.issuer_policy_epoch = statement
                    .issuer_policy_epoch
                    .checked_add(1)
                    .expect("fixture policy epoch increment");
            },
        );
        assert_drift(statement_substitution);
        let mut envelope_substitution = clone_prepared_for_adversary(&prepared);
        replace_prepared_envelope_for_adversary(&mut envelope_substitution, &context, |envelope| {
            envelope.engine_manifest_digest = PrivacyEngineManifestDigestV1::new([0xE1; 32]);
        });
        assert_drift(envelope_substitution);
        let mut proof_substitution = clone_prepared_for_adversary(&prepared);
        replace_prepared_envelope_for_adversary(&mut proof_substitution, &context, |envelope| {
            let PrivacyProofV1::IrohaBootleLanternAnoncredV1(proof) = &envelope.proof else {
                unreachable!()
            };
            let mut bytes = proof.as_bytes().to_vec();
            bytes[PROOF_HEADER_BYTES_V1] ^= 1;
            envelope.proof =
                PrivacyProofV1::IrohaBootleLanternAnoncredV1(PrivacyProofBytesV1::new(bytes));
        });
        assert_drift(proof_substitution);
        let mut policy_substitution = clone_prepared_for_adversary(&prepared);
        policy_substitution.issuer_policy.epoch = policy_substitution
            .issuer_policy
            .epoch
            .checked_add(1)
            .expect("fixture policy epoch increment");
        assert_drift(policy_substitution);
        let mut integrity_substitution = clone_prepared_for_adversary(&prepared);
        integrity_substitution.proof_envelope_hash[0] ^= 1;
        assert_drift(integrity_substitution);
    }
    #[test]
    fn blind_issuance_and_presentation_purposes_derive_distinct_challenges() {
        let seed = matrix_seed();
        let relation_digest = [0x95; 32];
        let presentation = PresentationTranscriptV1::new(
            PresentationChallengeBindingV1 {
                parameter_digest: [0x31; 32],
                genesis_hash: *statement_context().network_id.as_bytes(),
                statement_digest: [0x33; 32],
                issuer_policy_record_digest: [0x34; 32],
                transaction_intent_digest: [0x35; 32],
            },
            seed,
            relation_digest,
        )
        .expect("canonical P2 transcript");
        let blind_issuance = BlindIssuanceRequestTranscriptV1::new(
            BlindIssuanceRequestChallengeBindingV1 {
                parameter_digest: [0x31; 32],
                genesis_hash: *statement_context().network_id.as_bytes(),
                issuer_profile_digest: [0x33; 32],
                credential_scope_digest: [0x36; 32],
                issuer_policy_record_digest: [0x34; 32],
                masked_target_digest: [0x37; 32],
                issuance_authorization_digest: [0x35; 32],
            },
            seed,
            relation_digest,
        )
        .expect("canonical P1 transcript");
        let pre_challenge = b"same canonical fixed-profile proof body";
        assert_ne!(
            presentation
                .proof_core()
                .derive_final_challenge(pre_challenge)
                .expect("P2 challenge"),
            blind_issuance
                .proof_core()
                .derive_final_challenge(pre_challenge)
                .expect("P1 challenge"),
            "P1 and P2 must not share a Fiat--Shamir challenge namespace"
        );
    }
    fn quadratic_test_variables(
        x: &ProofPolynomialV1,
        y: &ProofPolynomialV1,
    ) -> QuadraticVariablesV1 {
        let mut variables = QuadraticVariablesV1::zero();
        variables.short[0] = *x;
        variables.message[0] = *y;
        variables
    }
    fn quadratic_test_map(variables: &QuadraticVariablesV1) -> ProofPolynomialV1 {
        // Q(x, y) = 3x² - 5xy + 2y² + 7x - 11y - 13.
        let x = variables.short[0];
        let y = variables.message[0];
        x.multiply(x)
            .scale_centered(3)
            .add(x.multiply(y).scale_centered(-5))
            .add(y.multiply(y).scale_centered(2))
            .add(x.scale_centered(7))
            .add(y.scale_centered(-11))
            .add(ProofPolynomialV1::constant_centered(-13))
    }
    fn actual_quadratic_equation<'a>(fixture: &'a Fixture) -> QuadraticEquationV1<'a> {
        let t_b = boxed_polynomial_array_from_fn_v1::<TBOX_LEXT_V1>(|polynomial| {
            ProofPolynomialV1::from_centered_coefficients(core::array::from_fn(|coefficient| {
                let polynomial = i64::try_from(polynomial).expect("polynomial index fits i64");
                let coefficient = i64::try_from(coefficient).expect("coefficient index fits i64");
                (polynomial * 37 + coefficient * 19).rem_euclid(257) - 128
            }))
        });
        let z3 = boxed_polynomial_array_from_fn_v1::<PROJECTION_POLYNOMIALS_V1>(|polynomial| {
            ProofPolynomialV1::from_centered_coefficients(core::array::from_fn(|coefficient| {
                let polynomial = i64::try_from(polynomial).expect("polynomial index fits i64");
                let coefficient = i64::try_from(coefficient).expect("coefficient index fits i64");
                (polynomial * 43 + coefficient * 23).rem_euclid(193) - 96
            }))
        });
        let z4 = boxed_polynomial_array_from_fn_v1::<PROJECTION_POLYNOMIALS_V1>(|polynomial| {
            ProofPolynomialV1::from_centered_coefficients(core::array::from_fn(|coefficient| {
                let polynomial = i64::try_from(polynomial).expect("polynomial index fits i64");
                let coefficient = i64::try_from(coefficient).expect("coefficient index fits i64");
                87 - (polynomial * 31 + coefficient * 17).rem_euclid(175)
            }))
        });
        let h = boxed_polynomial_array_from_fn_v1::<H_POLYNOMIALS_V1>(|polynomial| {
            ProofPolynomialV1::from_centered_coefficients(core::array::from_fn(|coefficient| {
                if coefficient == 0 || coefficient == APPLICATION_RING_DEGREE_V1 / 2 {
                    0
                } else {
                    let polynomial = i64::try_from(polynomial).expect("polynomial index fits i64");
                    let coefficient =
                        i64::try_from(coefficient).expect("coefficient index fits i64");
                    (polynomial * 29 + coefficient * 11).rem_euclid(127) - 63
                }
            }))
        });
        let proof_core = fixture.transcript.proof_core();
        let (projection_r, projection_r_prime) = derive_projection_matrices(&proof_core, &t_b)
            .expect("transcript-bound projection matrices");
        let weights = derive_schwartz_weights(&proof_core, &t_b).expect("Schwartz weights");
        let multipliers = derive_equation_multipliers(&proof_core, &t_b, &h, &z3, &z4)
            .expect("ring equation multipliers");
        QuadraticEquationV1::new(
            &fixture.relation,
            projection_r,
            projection_r_prime,
            z3,
            z4,
            h,
            weights,
            multipliers,
        )
        .expect("fully compiled actual quadratic equation")
    }
    fn actual_quadratic_variables() -> QuadraticVariablesV1 {
        let short = boxed_polynomial_array_from_fn_v1::<TBOX_M1_V1>(|polynomial| {
            ProofPolynomialV1::new(core::array::from_fn(|coefficient| {
                match (polynomial + coefficient) % 7 {
                    0 => 0,
                    1 => 1,
                    2 => 2,
                    3 => PROOF_MODULUS_V1 - 1,
                    4 => PROOF_MODULUS_V1 - 2,
                    5 => u64::try_from((polynomial * 65_537 + coefficient * 131_071) % 1_000_003)
                        .expect("small patterned residue fits u64"),
                    _ => {
                        PROOF_MODULUS_V1
                            - 1
                            - u64::try_from((polynomial + 3 * coefficient) % 19)
                                .expect("small residue fits u64")
                    }
                }
            }))
            .expect("all adversarial residues are canonical")
        });
        let mut message =
            boxed_polynomial_array_from_fn_v1::<QUADRATIC_MESSAGE_POLYNOMIALS_V1>(|polynomial| {
                ProofPolynomialV1::from_centered_coefficients(core::array::from_fn(|coefficient| {
                    let polynomial = i64::try_from(polynomial).expect("polynomial index fits i64");
                    let coefficient =
                        i64::try_from(coefficient).expect("coefficient index fits i64");
                    (polynomial * 53 + coefficient * 97).rem_euclid(509) - 254
                }))
            });
        let mut beta = [0_i64; APPLICATION_RING_DEGREE_V1];
        beta[0] = -1;
        beta[APPLICATION_RING_DEGREE_V1 / 2] = 1;
        message[BETA_MESSAGE_INDEX_V1] = ProofPolynomialV1::from_centered_coefficients(beta);
        QuadraticVariablesV1 { short, message }
    }
    fn scale_quadratic_variables(
        variables: &QuadraticVariablesV1,
        scalar: &ProofPolynomialV1,
    ) -> QuadraticVariablesV1 {
        QuadraticVariablesV1 {
            short: boxed_polynomial_array_from_fn_v1(|index| {
                scalar.multiply(variables.short[index])
            }),
            message: boxed_polynomial_array_from_fn_v1(|index| {
                scalar.multiply(variables.message[index])
            }),
        }
    }
    fn actual_quadratic_parts(
        equation: &QuadraticEquationV1<'_>,
        variables: &QuadraticVariablesV1,
    ) -> (ProofPolynomialV1, ProofPolynomialV1) {
        let q0 = equation
            .evaluate(&QuadraticVariablesV1::zero())
            .expect("actual Q at zero");
        let positive = equation.evaluate(variables).expect("actual Q");
        let negative = equation
            .evaluate(&variables.negate())
            .expect("actual Q at negated variables");
        decompose_signed_quadratic_evaluations(&q0, &positive, &negative)
            .expect("fixed inverse of two")
    }
    fn autostable_challenges() -> [ProofPolynomialV1; 3] {
        let sparse = {
            let mut coefficients = [0_i64; APPLICATION_RING_DEGREE_V1];
            coefficients[0] = 1;
            coefficients[1] = 1;
            coefficients[APPLICATION_RING_DEGREE_V1 - 1] = -1;
            ProofPolynomialV1::from_centered_coefficients(coefficients)
        };
        let boundary = {
            let mut coefficients = [0_i64; APPLICATION_RING_DEGREE_V1];
            coefficients[0] = -CHALLENGE_OMEGA_V1;
            coefficients[31] = CHALLENGE_OMEGA_V1;
            coefficients[33] = -CHALLENGE_OMEGA_V1;
            ProofPolynomialV1::from_centered_coefficients(coefficients)
        };
        let patterned = {
            let mut coefficients = [0_i64; APPLICATION_RING_DEGREE_V1];
            for (index, coefficient) in coefficients[..32].iter_mut().enumerate() {
                *coefficient = i64::try_from((index * 7) % 17).expect("small residue") - 8;
            }
            for index in 33..APPLICATION_RING_DEGREE_V1 {
                coefficients[index] = -coefficients[APPLICATION_RING_DEGREE_V1 - index];
            }
            ProofPolynomialV1::from_centered_coefficients(coefficients)
        };
        for challenge in [sparse, boundary, patterned] {
            assert_eq!(challenge, challenge.automorphism());
            assert!(!challenge.is_zero());
        }
        [sparse, boundary, patterned]
    }
    fn adversarial_quadratic_inputs() -> [(
        ProofPolynomialV1,
        ProofPolynomialV1,
        ProofPolynomialV1,
        ProofPolynomialV1,
    ); 4] {
        let patterned_positive =
            ProofPolynomialV1::from_centered_coefficients(core::array::from_fn(|index| {
                i64::try_from(index).expect("ring index fits i64") * 65_537 - 2_000_000
            }));
        let patterned_negative =
            ProofPolynomialV1::from_centered_coefficients(core::array::from_fn(|index| {
                1_700_000 - i64::try_from(index).expect("ring index fits i64") * 131_071
            }));
        let canonical_minus_one =
            ProofPolynomialV1::new([PROOF_MODULUS_V1 - 1; APPLICATION_RING_DEGREE_V1])
                .expect("q - 1 is canonical");
        let canonical_boundary_pattern = ProofPolynomialV1::new(core::array::from_fn(|index| {
            PROOF_MODULUS_V1 - 1 - u64::try_from(index % 3).expect("small residue")
        }))
        .expect("boundary residues are canonical");
        [
            (
                ProofPolynomialV1::ZERO,
                ProofPolynomialV1::ZERO,
                ProofPolynomialV1::ZERO,
                ProofPolynomialV1::ZERO,
            ),
            (
                ProofPolynomialV1::constant_centered(19),
                ProofPolynomialV1::constant_centered(-23),
                ProofPolynomialV1::constant_centered(-29),
                ProofPolynomialV1::constant_centered(31),
            ),
            (
                patterned_positive,
                patterned_negative,
                patterned_negative,
                patterned_positive,
            ),
            (
                canonical_minus_one,
                canonical_boundary_pattern,
                canonical_boundary_pattern,
                canonical_minus_one,
            ),
        ]
    }
    #[test]
    fn verifier_quadratic_reuse_matches_legacy_formulas_at_adversarial_residues() {
        for (x, y, _, _) in adversarial_quadratic_inputs() {
            let variables = quadratic_test_variables(&x, &y);
            let zero = QuadraticVariablesV1::zero();
            let q0 = quadratic_test_map(&zero);
            let q_positive = quadratic_test_map(&variables);
            let q_negative = quadratic_test_map(&variables.negate());
            let (linear, quadratic) =
                decompose_signed_quadratic_evaluations(&q0, &q_positive, &q_negative)
                    .expect("fixed inverse of two");
            let legacy_linear = q_positive
                .sub(q_negative)
                .scale_canonical(PROOF_INVERSE_TWO_V1)
                .expect("fixed inverse of two");
            let legacy_quadratic = q_positive
                .add(q_negative)
                .sub(q0.scale_centered(2))
                .scale_canonical(PROOF_INVERSE_TWO_V1)
                .expect("fixed inverse of two");
            assert_eq!(linear, legacy_linear);
            assert_eq!(quadratic, legacy_quadratic);
            assert_eq!(linear, x.scale_centered(7).add(y.scale_centered(-11)));
            assert_eq!(
                quadratic,
                x.multiply(x)
                    .scale_centered(3)
                    .add(x.multiply(y).scale_centered(-5))
                    .add(y.multiply(y).scale_centered(2))
            );
            assert_eq!(q_positive, quadratic.add(linear).add(q0));
        }
    }
    #[test]
    fn prover_mask_reuse_is_exactly_three_evaluations_and_matches_legacy_formulas() {
        for (secret_x, secret_y, mask_x, mask_y) in adversarial_quadratic_inputs() {
            let secret = quadratic_test_variables(&secret_x, &secret_y);
            let mask = quadratic_test_variables(&mask_x, &mask_y);
            let zero = QuadraticVariablesV1::zero();
            let q0 = quadratic_test_map(&zero);
            let q_secret = quadratic_test_map(&secret);
            let expected_inputs = [mask.clone(), mask.negate(), secret.add(&mask)];
            let evaluations = [
                quadratic_test_map(&expected_inputs[0]),
                quadratic_test_map(&expected_inputs[1]),
                quadratic_test_map(&expected_inputs[2]),
            ];
            let mut calls = 0_usize;
            let (bilinear, linear, quadratic) =
                decompose_mask_quadratic_evaluations(&secret, &mask, &q0, &q_secret, |variables| {
                    assert!(
                        calls < PROVER_QUADRATIC_EVALUATIONS_PER_MASK_RETRY_V1,
                        "the retry kernel must not make a fourth evaluation"
                    );
                    assert_eq!(variables, &expected_inputs[calls]);
                    let evaluation = evaluations[calls];
                    calls += 1;
                    Ok(evaluation)
                })
                .expect("fixed inverse of two");
            assert_eq!(calls, PROVER_QUADRATIC_EVALUATIONS_PER_MASK_RETRY_V1);
            let [q_mask, q_negative_mask, q_sum] = evaluations;
            let legacy_bilinear = q_sum.sub(q_secret).sub(q_mask).add(q0);
            let legacy_linear = q_mask
                .sub(q_negative_mask)
                .scale_canonical(PROOF_INVERSE_TWO_V1)
                .expect("fixed inverse of two");
            let legacy_quadratic = q_mask
                .add(q_negative_mask)
                .sub(q0.scale_centered(2))
                .scale_canonical(PROOF_INVERSE_TWO_V1)
                .expect("fixed inverse of two");
            assert_eq!(bilinear, legacy_bilinear);
            assert_eq!(linear, legacy_linear);
            assert_eq!(quadratic, legacy_quadratic);
            let expected_bilinear = secret_x
                .multiply(mask_x)
                .scale_centered(6)
                .add(
                    secret_x
                        .multiply(mask_y)
                        .add(mask_x.multiply(secret_y))
                        .scale_centered(-5),
                )
                .add(secret_y.multiply(mask_y).scale_centered(4));
            assert_eq!(bilinear, expected_bilinear);
            assert_eq!(
                linear,
                mask_x.scale_centered(7).add(mask_y.scale_centered(-11))
            );
            assert_eq!(
                quadratic,
                mask_x
                    .multiply(mask_x)
                    .scale_centered(3)
                    .add(mask_x.multiply(mask_y).scale_centered(-5))
                    .add(mask_y.multiply(mask_y).scale_centered(2))
            );
        }
    }
    #[test]
    fn prover_mask_reuse_fails_closed_at_each_black_box_evaluation() {
        let secret = QuadraticVariablesV1::zero();
        let mask = QuadraticVariablesV1::zero();
        for failure_index in 0..PROVER_QUADRATIC_EVALUATIONS_PER_MASK_RETRY_V1 {
            let mut calls = 0_usize;
            let result = decompose_mask_quadratic_evaluations(
                &secret,
                &mask,
                &ProofPolynomialV1::ZERO,
                &ProofPolynomialV1::ZERO,
                |_| {
                    let index = calls;
                    calls += 1;
                    if index == failure_index {
                        Err(PresentationProofErrorV1::InternalInvariant)
                    } else {
                        Ok(ProofPolynomialV1::ZERO)
                    }
                },
            );
            assert_eq!(result, Err(PresentationProofErrorV1::InternalInvariant));
            assert_eq!(
                calls,
                failure_index + 1,
                "evaluation must stop immediately after the injected failure"
            );
        }
    }
    #[test]
    fn actual_zq_compiler_checked_coefficients_match_scalar_oracle() {
        let fixture = fixture();
        let equation = actual_quadratic_equation(&fixture);
        let variables = actual_quadratic_variables();
        let canonical_constraints = equation
            .constraints(&variables)
            .expect("canonical coefficient constraints");
        let lifted_constraints = equation
            .lifted_constraints(&variables)
            .expect("homogeneous coefficient-field lift");
        assert_eq!(
            lifted_constraints, canonical_constraints,
            "a correctly shaped beta must make the homogeneous lift exactly canonical"
        );
        let scalar = equation
            .scalar_schwartz_accumulators(&variables)
            .expect("cfg(test) scalar oracle");
        let lifted = equation
            .lifted_schwartz_accumulators(&variables)
            .expect("cfg(test) homogeneous-lift oracle");
        assert_eq!(lifted, scalar);
        let masked = equation
            .schwartz_polynomials(&variables)
            .expect("masked Zq-to-Rq compiler");
        assert_eq!(masked[0].coefficients()[0], scalar[0]);
        assert_eq!(
            masked[0].coefficients()[APPLICATION_RING_DEGREE_V1 / 2],
            scalar[1]
        );
        assert_eq!(masked[1].coefficients()[0], scalar[2]);
        assert_eq!(
            masked[1].coefficients()[APPLICATION_RING_DEGREE_V1 / 2],
            scalar[3]
        );
    }
    #[test]
    fn actual_zq_compiler_matches_augmented_oracle_for_adversarial_beta_shape_noise() {
        let fixture = fixture();
        let equation = actual_quadratic_equation(&fixture);
        for (index, noise) in [(1, 7_i64), (17, -11), (31, 19), (47, -23), (63, 29)] {
            let mut variables = actual_quadratic_variables();
            let mut beta = core::array::from_fn(|coefficient| {
                variables.message[BETA_MESSAGE_INDEX_V1].centered_coefficient(coefficient)
            });
            beta[index] = noise;
            variables.message[BETA_MESSAGE_INDEX_V1] =
                ProofPolynomialV1::from_centered_coefficients(beta);
            let canonical_constraints = equation
                .constraints(&variables)
                .expect("canonical coefficient constraints");
            let lifted_constraints = equation
                .lifted_constraints(&variables)
                .expect("homogeneous coefficient-field lift");
            assert!(
                canonical_constraints[..2 * (APPLICATION_RING_DEGREE_V1 - 1)]
                    .iter()
                    .any(|constraint| *constraint != 0),
                "each injected beta coefficient must trip an independent shape equation"
            );
            let projection_start = EVALUATION_CONSTRAINTS_V1 - 2 * PROJECTION_COORDINATES_V1;
            assert!(
                canonical_constraints[projection_start..]
                    .iter()
                    .zip(&lifted_constraints[projection_start..])
                    .any(|(canonical, lifted)| canonical != lifted),
                "shape noise must exercise the augmented projection lift"
            );
            let lifted = equation
                .lifted_schwartz_accumulators(&variables)
                .expect("cfg(test) homogeneous-lift oracle");
            let masked = equation
                .schwartz_polynomials(&variables)
                .expect("masked Zq-to-Rq compiler");
            assert_eq!(masked[0].coefficients()[0], lifted[0]);
            assert_eq!(
                masked[0].coefficients()[APPLICATION_RING_DEGREE_V1 / 2],
                lifted[1]
            );
            assert_eq!(masked[1].coefficients()[0], lifted[2]);
            assert_eq!(
                masked[1].coefficients()[APPLICATION_RING_DEGREE_V1 / 2],
                lifted[3]
            );
        }
    }
    #[test]
    fn actual_quadratic_equation_is_equivariant_for_adversarial_autostable_challenges() {
        let fixture = fixture();
        let equation = actual_quadratic_equation(&fixture);
        let variables = actual_quadratic_variables();
        let (linear, quadratic) = actual_quadratic_parts(&equation, &variables);
        for challenge in autostable_challenges() {
            let scaled = scale_quadratic_variables(&variables, &challenge);
            let (scaled_linear, scaled_quadratic) = actual_quadratic_parts(&equation, &scaled);
            assert_eq!(
                scaled_linear,
                challenge.multiply(linear),
                "actual linear part must commute with the full ring challenge"
            );
            assert_eq!(
                scaled_quadratic,
                challenge.multiply(challenge).multiply(quadratic),
                "actual homogeneous-quadratic part must commute with challenge squared"
            );
        }
    }
    #[test]
    fn quadratic_evaluation_budgets_are_fixed_and_bounded() {
        assert_eq!(PROVER_PRECOMPUTED_QUADRATIC_EVALUATIONS_V1, 2);
        assert_eq!(PROVER_QUADRATIC_EVALUATIONS_PER_MASK_RETRY_V1, 3);
        assert_eq!(VERIFIER_QUADRATIC_EVALUATIONS_V1, 3);
        assert_eq!(MAX_QUADRATIC_EVALUATIONS_PER_PROVE_ATTEMPT_V1, 3_074);
        assert_eq!(
            MAX_QUADRATIC_EVALUATIONS_PER_PROVE_ATTEMPT_V1,
            PROVER_PRECOMPUTED_QUADRATIC_EVALUATIONS_V1
                + PROVER_QUADRATIC_EVALUATIONS_PER_MASK_RETRY_V1
                    * MAX_RESPONSE_SAMPLING_ATTEMPTS_PER_PROVE_ATTEMPT_V1 as usize
        );
        assert_eq!(MIN_RESPONSE_CONTEXTS_AT_GLOBAL_BUDGET_V1, 4);
        assert_eq!(MAX_TOP_LEVEL_QUADRATIC_EVALUATIONS_V1, 12_287);
    }
    #[test]
    fn native_secret_workspaces_are_heap_backed_for_validator_worker_stacks() {
        assert_eq!(
            core::mem::size_of::<SecretPolynomialVectorV1<TBOX_M2_V1>>(),
            core::mem::size_of::<Box<[ProofPolynomialV1; TBOX_M2_V1]>>()
        );
        assert_eq!(
            core::mem::size_of::<QuadraticVariablesV1>(),
            core::mem::size_of::<Box<[ProofPolynomialV1; TBOX_M1_V1]>>()
                + core::mem::size_of::<Box<[ProofPolynomialV1; QUADRATIC_MESSAGE_POLYNOMIALS_V1]>>(
                )
        );
        assert_eq!(
            core::mem::size_of::<super::super::toolbox::ShortWitnessV1>(),
            core::mem::size_of::<Box<[ProofPolynomialV1; TBOX_M1_V1]>>()
        );
    }
    #[test]
    fn shared_rejection_budget_exhausts_projection_stage_exactly() {
        let mut budget = ProofRejectionBudgetV1::new(7);
        for draw in 0..7 {
            assert!(budget.reserve(ProofRejectionStageV1::Projection));
            assert_eq!(budget.projection_draws, draw + 1);
            assert_eq!(budget.response_mask_draws, 0);
            assert_eq!(budget.remaining(), 6 - draw);
        }
        assert!(!budget.reserve(ProofRejectionStageV1::Projection));
        assert_eq!(budget.projection_draws, 7);
        assert_eq!(budget.response_mask_draws, 0);
        assert_eq!(budget.remaining(), 0);
        assert_eq!(
            budget.exhaustion_error(),
            PresentationProofErrorV1::SamplingBudgetExhausted
        );
    }
    #[test]
    fn shared_rejection_budget_exhausts_response_stage_exactly() {
        let mut budget = ProofRejectionBudgetV1::new(7);
        for draw in 0..7 {
            assert!(budget.reserve(ProofRejectionStageV1::ResponseMask));
            assert_eq!(budget.projection_draws, 0);
            assert_eq!(budget.response_mask_draws, draw + 1);
            assert_eq!(budget.remaining(), 6 - draw);
        }
        assert!(!budget.reserve(ProofRejectionStageV1::ResponseMask));
        assert_eq!(budget.projection_draws, 0);
        assert_eq!(budget.response_mask_draws, 7);
        assert_eq!(budget.remaining(), 0);
        assert_eq!(
            budget.exhaustion_error(),
            PresentationProofErrorV1::SamplingBudgetExhausted
        );
    }
    #[test]
    fn shared_rejection_budget_cannot_multiply_across_stages() {
        let mut budget = ProofRejectionBudgetV1::new(MAX_PROOF_SAMPLING_ATTEMPTS_V1);
        let projection_draws = MAX_PROJECTION_SAMPLING_ATTEMPTS_PER_PROVE_ATTEMPT_V1;
        for _ in 0..projection_draws {
            assert!(budget.reserve(ProofRejectionStageV1::Projection));
        }
        let response_draws = MAX_PROOF_SAMPLING_ATTEMPTS_V1 - projection_draws;
        for _ in 0..response_draws {
            assert!(budget.reserve(ProofRejectionStageV1::ResponseMask));
        }
        assert!(!budget.reserve(ProofRejectionStageV1::Projection));
        assert_eq!(budget.projection_draws, projection_draws);
        assert_eq!(budget.response_mask_draws, response_draws);
        assert_eq!(
            budget
                .projection_draws
                .checked_add(budget.response_mask_draws),
            Some(MAX_PROOF_SAMPLING_ATTEMPTS_V1)
        );
    }
    #[test]
    fn rejection_accounting_preserves_each_actual_failure_boundary() {
        let mut budget = ProofRejectionBudgetV1::new(3);
        assert!(budget.reserve(ProofRejectionStageV1::Projection));
        budget.record_projection_rejection();
        assert!(budget.reserve(ProofRejectionStageV1::ResponseMask));
        budget.record_response_sampling_rejection();
        assert!(budget.reserve(ProofRejectionStageV1::ResponseMask));
        budget.record_response_norm_rejection();
        assert!(!budget.reserve(ProofRejectionStageV1::ResponseMask));
        assert_eq!(budget.rejections.projection, 1);
        assert_eq!(budget.rejections.response_sampling, 1);
        assert_eq!(budget.rejections.response_norm, 1);
        assert_eq!(
            budget.exhaustion_error(),
            PresentationProofErrorV1::SamplingBudgetExhausted
        );
    }
    #[test]
    fn secret_rejection_diagnostics_are_invariant_and_fully_redacted() {
        let untouched = ProofRejectionBudgetV1::new(4_095);
        let mut exercised = ProofRejectionBudgetV1::new(17);
        assert!(exercised.reserve(ProofRejectionStageV1::Projection));
        exercised.record_projection_rejection();
        assert!(exercised.reserve(ProofRejectionStageV1::ResponseMask));
        exercised.record_response_sampling_rejection();
        exercised.record_response_norm_rejection();
        assert_eq!(
            format!("{untouched:?}"),
            "ProofRejectionBudgetV1(<redacted>)"
        );
        assert_eq!(format!("{exercised:?}"), format!("{untouched:?}"));
        assert_eq!(
            format!("{:?}", &exercised.rejections),
            "ProofRejectionStatsV1(<redacted>)"
        );
        assert_eq!(
            format!("{:?}", ProofRejectionStatsV1::default()),
            format!("{:?}", &exercised.rejections)
        );
        assert_eq!(
            format!("{}", exercised.exhaustion_error()),
            "Bootle/Lantern sampling exhausted the shared proof work budget"
        );
    }
    #[test]
    #[ignore = "explicit short-budget diagnostic for the expensive native prover"]
    fn short_budget_reports_the_first_native_rejection_boundary() {
        let fixture = fixture();
        let mut rng = TestRng::healthy(0x9e37_79b9_7f4a_7c15);
        match prove_presentation_with_rejection_limit_v1(
            &fixture.relation,
            &fixture.witness,
            &fixture.transcript,
            &mut rng,
            32,
        ) {
            Ok(proof) => {
                verify_presentation_v1(&fixture.relation, &fixture.transcript, &proof)
                    .expect("short-budget proof self-verifies");
                eprintln!("short-budget diagnostic: proof accepted");
            }
            Err(error) => eprintln!("short-budget diagnostic: {error:?}"),
        }
    }
    #[test]
    fn complete_native_proof_round_trip_and_adversarial_matrix() {
        const {
            assert!(
                BOOTLE_LANTERN_FULL_ENGINE_AVAILABLE_V1,
                "the first-release public Bootle/Lantern engine must be active"
            )
        };
        let fixture = fixture();
        let mut rng = TestRng::healthy(0x9e37_79b9_7f4a_7c15);
        let proof = prove_bound_presentation_v1(
            &fixture.statement,
            &fixture.policy,
            fixture.genesis_hash,
            &fixture.witness,
            &mut rng,
        )
        .expect("fully governed native proof");
        verify_presentation_v1(&fixture.relation, &fixture.transcript, &proof)
            .expect("native proof verifies");
        verify_bound_presentation_v1(
            &fixture.statement,
            &fixture.policy,
            fixture.genesis_hash,
            &proof,
        )
        .expect("governed native proof verifies");
        let encoded = proof.encode();
        assert_eq!(encoded.len(), PROOF_BYTES_V1);
        assert_eq!(
            hex::encode(Sha3_256::digest(&encoded)),
            "9e2e054d0eaa242ba0ca7b9e704737282d55013e4f3f006b5e4a8cdd4c001de1"
        );
        let decoded = BootleLanternPresentationProofV1::decode_exact(
            &encoded,
            u32::try_from(encoded.len()).expect("proof length fits u32"),
        )
        .expect("strict wire round trip");
        assert_eq!(decoded, proof);
        verify_presentation_v1(&fixture.relation, &fixture.transcript, &decoded)
            .expect("decoded native proof verifies");
        verify_bound_presentation_encoded_v1(
            &fixture.statement,
            &fixture.policy,
            fixture.genesis_hash,
            &encoded,
            u32::try_from(encoded.len()).expect("proof length fits u32"),
        )
        .expect("strictly decoded governed proof verifies");
        let issued = issued_fixture();
        let p1_encoded = issued.p1_proof.encode();
        let proof_cap = u32::try_from(PROOF_BYTES_V1).expect("fixed proof length fits u32");
        let decoded_p1 =
            BootleLanternBlindIssuanceRequestProofV1::decode_exact(&p1_encoded, proof_cap)
                .expect("strict nominal P1 wire round trip");
        verify_blind_issuance_request_v1(&issued.p1_relation, &issued.p1_transcript, &decoded_p1)
            .expect("decoded nominal P1 proof verifies");
        assert_ne!(
            proof.challenge_polynomial(),
            issued.p1_proof.validated_body_v1().challenge_polynomial(),
            "the issued P1 request and P2 presentation must not reuse a challenge"
        );
        assert_eq!(
            BootleLanternPresentationProofV1::decode_exact(&p1_encoded, proof_cap),
            Err(ProofCodecErrorV1::InvalidMagic)
        );
        assert_eq!(
            BootleLanternBlindIssuanceRequestProofV1::decode_exact(&encoded, proof_cap),
            Err(ProofCodecErrorV1::InvalidMagic)
        );
        // Replacing the complete nominal header makes either shared-layout
        // body structurally decodable as the other protocol. The respective
        // transcript-bound verifier must still reject the substitution.
        let mut p1_body_with_p2_header = p1_encoded.clone();
        p1_body_with_p2_header[..PROOF_HEADER_BYTES_V1]
            .copy_from_slice(&encoded[..PROOF_HEADER_BYTES_V1]);
        let p1_body_as_p2 =
            BootleLanternPresentationProofV1::decode_exact(&p1_body_with_p2_header, proof_cap)
                .expect("P1 body remains structurally canonical under a complete P2 header splice");
        let p1_binding = issued.p1_transcript.binding();
        let p2_transcript_for_p1_relation = PresentationTranscriptV1::new(
            PresentationChallengeBindingV1 {
                parameter_digest: p1_binding.parameter_digest,
                genesis_hash: p1_binding.genesis_hash,
                statement_digest: p1_binding.issuer_profile_digest,
                issuer_policy_record_digest: p1_binding.issuer_policy_record_digest,
                transaction_intent_digest: p1_binding.issuance_authorization_digest,
            },
            issued.p1_transcript.proof_core().matrix_seed(),
            issued.p1_transcript.proof_core().relation_digest(),
        )
        .expect("P2-purpose transcript over the exact P1 relation");
        assert!(
            verify_presentation_v1(
                &issued.p1_relation,
                &p2_transcript_for_p1_relation,
                &p1_body_as_p2,
            )
            .is_err(),
            "a P1 body with a P2 header must fail the P2 purpose over the same relation"
        );
        let mut p2_body_with_p1_header = encoded.clone();
        p2_body_with_p1_header[..PROOF_HEADER_BYTES_V1]
            .copy_from_slice(&p1_encoded[..PROOF_HEADER_BYTES_V1]);
        let p2_body_as_p1 = BootleLanternBlindIssuanceRequestProofV1::decode_exact(
            &p2_body_with_p1_header,
            proof_cap,
        )
        .expect("P2 body remains structurally canonical under a complete P1 header splice");
        let p2_binding = fixture.transcript.binding();
        let p1_transcript_for_p2_relation = BlindIssuanceRequestTranscriptV1::new(
            BlindIssuanceRequestChallengeBindingV1 {
                parameter_digest: p2_binding.parameter_digest,
                genesis_hash: p2_binding.genesis_hash,
                issuer_profile_digest: p2_binding.statement_digest,
                credential_scope_digest: p2_binding.transaction_intent_digest,
                issuer_policy_record_digest: p2_binding.issuer_policy_record_digest,
                masked_target_digest: p2_binding.statement_digest,
                issuance_authorization_digest: p2_binding.transaction_intent_digest,
            },
            fixture.transcript.matrix_seed(),
            fixture.transcript.relation_digest(),
        )
        .expect("P1-purpose transcript over the exact P2 relation");
        assert!(
            verify_blind_issuance_request_v1(
                &fixture.relation,
                &p1_transcript_for_p2_relation,
                &p2_body_as_p1,
            )
            .is_err(),
            "a P2 body with a P1 header must fail the P1 purpose over the same relation"
        );
        let proof_ceiling =
            u32::try_from(encoded.len() - 1).expect("fixed proof length minus one fits u32");
        assert!(matches!(
            verify_bound_presentation_encoded_v1(
                &fixture.statement,
                &fixture.policy,
                fixture.genesis_hash,
                &encoded,
                proof_ceiling,
            ),
            Err(BoundPresentationEncodedErrorV1::Codec(
                ProofCodecErrorV1::TooLarge { .. }
            ))
        ));
        assert!(matches!(
            verify_bound_presentation_encoded_v1(
                &fixture.statement,
                &fixture.policy,
                fixture.genesis_hash,
                &encoded[..encoded.len() - 1],
                u32::try_from(encoded.len()).expect("proof length fits u32"),
            ),
            Err(BoundPresentationEncodedErrorV1::Codec(
                ProofCodecErrorV1::WrongLength { .. }
            ))
        ));
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            verify_bound_presentation_encoded_v1(
                &fixture.statement,
                &fixture.policy,
                fixture.genesis_hash,
                &trailing,
                u32::try_from(trailing.len()).expect("proof length fits u32"),
            ),
            Err(BoundPresentationEncodedErrorV1::Codec(
                ProofCodecErrorV1::WrongLength { .. }
            ))
        ));
        let mut noncanonical = encoded.clone();
        noncanonical[PROOF_HEADER_BYTES_V1
            ..PROOF_HEADER_BYTES_V1 + super::super::params::PROOF_RESIDUE_BYTES_V1]
            .copy_from_slice(
                &PROOF_MODULUS_V1.to_le_bytes()[..super::super::params::PROOF_RESIDUE_BYTES_V1],
            );
        assert!(matches!(
            verify_bound_presentation_encoded_v1(
                &fixture.statement,
                &fixture.policy,
                fixture.genesis_hash,
                &noncanonical,
                u32::try_from(noncanonical.len()).expect("proof length fits u32"),
            ),
            Err(BoundPresentationEncodedErrorV1::Codec(
                ProofCodecErrorV1::NonCanonicalResidue { index: 0, .. }
            ))
        ));
        let mut bad_magic = encoded.clone();
        bad_magic[0] ^= 1;
        assert!(matches!(
            verify_bound_presentation_encoded_v1(
                &fixture.statement,
                &fixture.policy,
                fixture.genesis_hash,
                &bad_magic,
                u32::try_from(bad_magic.len()).expect("proof length fits u32"),
            ),
            Err(BoundPresentationEncodedErrorV1::Codec(
                ProofCodecErrorV1::InvalidMagic
            ))
        ));
        assert!(matches!(
            verify_bound_presentation_v1(&fixture.statement, &fixture.policy, [0x33; 32], &proof,),
            Err(BoundPresentationErrorV1::Relation(
                super::super::relation::RelationErrorV1::InvalidCredentialScope
            ))
        ));
        let mut changed_intent = fixture.statement.clone();
        changed_intent.context.transaction_intent_digest =
            PrivacyTransactionIntentDigestV1::new(raw(0x61));
        assert!(
            verify_bound_presentation_v1(
                &changed_intent,
                &fixture.policy,
                fixture.genesis_hash,
                &proof,
            )
            .is_err()
        );
        let mut changed_action = fixture.statement.clone();
        changed_action.context.action_index += 1;
        assert!(
            verify_bound_presentation_v1(
                &changed_action,
                &fixture.policy,
                fixture.genesis_hash,
                &proof,
            )
            .is_err()
        );
        let mut changed_parameter = fixture.statement.clone();
        changed_parameter.context.parameter_digest = PrivacyParameterDigestV1::new(raw(0x62));
        assert!(
            verify_bound_presentation_v1(
                &changed_parameter,
                &fixture.policy,
                fixture.genesis_hash,
                &proof,
            )
            .is_err()
        );
        let mut changed_disclosure = fixture.statement.clone();
        changed_disclosure.disclosures[0].value = BootleLanternAttributeValueV1::new([2; 8]);
        assert!(matches!(
            verify_bound_presentation_v1(
                &changed_disclosure,
                &fixture.policy,
                fixture.genesis_hash,
                &proof,
            ),
            Err(BoundPresentationErrorV1::Relation(_))
        ));
        let mut changed_policy_digest = fixture.statement.clone();
        changed_policy_digest.issuer_policy_record_digest =
            PrivacyBootleLanternIssuerPolicyDigestV1::new(raw(0x63));
        assert!(matches!(
            verify_bound_presentation_v1(
                &changed_policy_digest,
                &fixture.policy,
                fixture.genesis_hash,
                &proof,
            ),
            Err(BoundPresentationErrorV1::Relation(_))
        ));
        let mut substituted_policy = fixture.policy.clone();
        substituted_policy.policy_id = PrivacyPolicyIdV1::new(raw(0x64));
        substituted_policy.record_digest = PrivacyBootleLanternIssuerPolicyDigestV1::new([0; 32]);
        substituted_policy.record_digest = substituted_policy
            .computed_record_digest()
            .expect("substituted policy digest");
        substituted_policy
            .validate()
            .expect("independently valid substituted policy");
        assert!(matches!(
            verify_bound_presentation_v1(
                &fixture.statement,
                &substituted_policy,
                fixture.genesis_hash,
                &proof,
            ),
            Err(BoundPresentationErrorV1::Relation(_))
        ));
        // Every canonical proof section is transcript- or equation-bound.
        for index in [
            0,
            H_START_TEST + 1,
            T_A1_START_TEST,
            HINT_START_TEST,
            Z1_START_TEST,
            Z21_START_TEST,
            Z3_START_TEST,
            Z4_START_TEST,
        ] {
            let changed = proof_from_mutation(&proof, |coefficients| {
                coefficients[index] = alternate_residue(coefficients[index]);
            });
            assert!(
                verify_presentation_v1(&fixture.relation, &fixture.transcript, &changed).is_err(),
                "mutation at flat coefficient {index} must fail"
            );
        }
        // Keep the challenge encoding canonical while changing its value.
        let challenge_changed = proof_from_mutation(&proof, |coefficients| {
            let current = proof.challenge_polynomial().centered_coefficient(0);
            let replacement = if current == CHALLENGE_OMEGA_V1 {
                current - 1
            } else {
                current + 1
            };
            coefficients[CHALLENGE_START_TEST] = proof_residue_from_centered_v1(replacement);
        });
        assert!(
            verify_presentation_v1(&fixture.relation, &fixture.transcript, &challenge_changed)
                .is_err()
        );
        let invalid_h = proof_from_mutation(&proof, |coefficients| {
            coefficients[H_START_TEST] = 1;
        });
        assert!(matches!(
            verify_presentation_v1(&fixture.relation, &fixture.transcript, &invalid_h),
            Err(PresentationProofErrorV1::InvalidSchwartzCommitment)
        ));
        let excessive_z1 = proof_from_mutation(&proof, |coefficients| {
            coefficients[Z1_START_TEST] = proof_residue_from_centered_v1(1_040_728_452);
        });
        assert!(matches!(
            verify_presentation_v1(&fixture.relation, &fixture.transcript, &excessive_z1),
            Err(PresentationProofErrorV1::ResponseBound(
                ResponseBoundErrorV1::Z1NormExceeded
            ))
        ));
        let invalid_hint = proof_from_mutation(&proof, |coefficients| {
            coefficients[HINT_START_TEST] = proof_residue_from_centered_v1(
                i64::try_from(COMPRESSION_MODULUS_V1 / 2 + 1).expect("hint bound fits i64"),
            );
        });
        assert!(matches!(
            verify_presentation_v1(&fixture.relation, &fixture.transcript, &invalid_hint),
            Err(PresentationProofErrorV1::ResponseBound(
                ResponseBoundErrorV1::HintOutOfRange
            ))
        ));
        let excessive_z3 = proof_from_mutation(&proof, |coefficients| {
            coefficients[Z3_START_TEST] = proof_residue_from_centered_v1(10_661_921);
        });
        assert!(matches!(
            verify_presentation_v1(&fixture.relation, &fixture.transcript, &excessive_z3),
            Err(PresentationProofErrorV1::ResponseBound(
                ResponseBoundErrorV1::Z3NormExceeded
            ))
        ));
        let excessive_z4 = proof_from_mutation(&proof, |coefficients| {
            coefficients[Z4_START_TEST] = proof_residue_from_centered_v1(
                i64::try_from(Z4_INFINITY_NORM_BOUND_V1 + 1).expect("z4 bound fits i64"),
            );
        });
        assert!(matches!(
            verify_presentation_v1(&fixture.relation, &fixture.transcript, &excessive_z4),
            Err(PresentationProofErrorV1::ResponseBound(
                ResponseBoundErrorV1::Z4InfinityNormExceeded
            ))
        ));
        // A replay under another public statement or transaction intent fails.
        for changed_binding in [
            PresentationChallengeBindingV1 {
                statement_digest: [0x51; 32],
                ..fixture.transcript.binding()
            },
            PresentationChallengeBindingV1 {
                genesis_hash: [0x54; 32],
                ..fixture.transcript.binding()
            },
            PresentationChallengeBindingV1 {
                transaction_intent_digest: [0x52; 32],
                ..fixture.transcript.binding()
            },
            PresentationChallengeBindingV1 {
                issuer_policy_record_digest: [0x53; 32],
                ..fixture.transcript.binding()
            },
        ] {
            let changed_transcript = PresentationTranscriptV1::new(
                changed_binding,
                fixture.transcript.matrix_seed(),
                fixture.transcript.relation_digest(),
            )
            .expect("changed transcript remains structurally valid");
            assert!(
                verify_presentation_v1(&fixture.relation, &changed_transcript, &proof).is_err()
            );
        }
        let wrong_relation_transcript = PresentationTranscriptV1::new(
            fixture.transcript.binding(),
            fixture.transcript.matrix_seed(),
            [0x61; 32],
        )
        .expect("non-zero wrong relation digest");
        assert!(matches!(
            verify_presentation_v1(&fixture.relation, &wrong_relation_transcript, &proof),
            Err(PresentationProofErrorV1::RelationDigestMismatch)
        ));
        // The all-zero algebraic forgery is canonical on the wire but invalid.
        let zero_forgery = BootleLanternPresentationProofV1::from_coefficients(
            vec![0_u64; PROOF_COEFFICIENTS_V1].into_boxed_slice(),
        )
        .expect("zero proof has a canonical challenge representation");
        assert!(
            verify_presentation_v1(&fixture.relation, &fixture.transcript, &zero_forgery).is_err()
        );
    }
    #[test]
    fn prover_rejects_rng_failure_health_sentinels_and_invalid_witnesses() {
        let fixture = fixture();
        for mut rng in [
            TestRng::failed(),
            TestRng::stuck(0),
            TestRng::stuck(0x7f),
            TestRng::periodic(8),
        ] {
            assert!(matches!(
                prove_presentation_v1(
                    &fixture.relation,
                    &fixture.witness,
                    &fixture.transcript,
                    &mut rng
                ),
                Err(PresentationProofErrorV1::Sampling(
                    SamplingErrorV1::RandomnessUnavailable
                        | SamplingErrorV1::RandomnessHealthCheckFailed
                ))
            ));
        }
        let mut invalid = valid_witness();
        invalid.signature_one[0] = ApplicationPolynomialV1::constant(APPLICATION_MODULUS_V1 / 2)
            .expect("canonical application coefficient");
        let mut rng = TestRng::healthy(0x243f_6a88_85a3_08d3);
        assert!(matches!(
            prove_presentation_v1(&fixture.relation, &invalid, &fixture.transcript, &mut rng),
            Err(PresentationProofErrorV1::Toolbox(_))
        ));
    }
    #[test]
    fn proof_constructor_rejects_noncanonical_residues_before_verification() {
        let mut coefficients = vec![0_u64; PROOF_COEFFICIENTS_V1];
        coefficients[0] = PROOF_MODULUS_V1;
        assert!(matches!(
            BootleLanternPresentationProofV1::from_coefficients(coefficients.into_boxed_slice()),
            Err(ProofCodecErrorV1::NonCanonicalResidue { index: 0, .. })
        ));
    }
}
