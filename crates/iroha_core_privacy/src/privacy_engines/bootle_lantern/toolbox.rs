//! Typed fixed-profile Lantern/LNP22 constraint toolbox.
//!
//! The presentation relation is reduced to the exact 642 scalar evaluation
//! constraints used by the fixed anonymous-credential profile:
//!
//! - 63 coefficients force each of `beta3` and `beta4` to be constant;
//! - one positive integer equation proves the two norm-slack polynomials are
//!   binary;
//! - one positive integer equation proves the tag and attributes are binary;
//! - two equations bind the exact squared norms and their binary slack;
//! - 256 ternary projections bind `z4` to the lifted application relation;
//! - 256 ternary projections bind `z3` to the binary and norm witnesses.
//!
//! Four independently weighted scalar accumulators are compiled into two
//! masked proof-ring equations.  For an accumulator polynomial `a`, the
//! sigma-minus-one trace `Tr(a) = (a + sigma(a)) / 2` preserves coefficient
//! zero and clears coefficient 32.  Pairing two traced accumulators as
//! `Tr(a) + X^32 Tr(b)` therefore exposes exactly their two checked
//! coefficients while retaining the remaining coefficients as masked
//! garbage.  Unlike embedding evaluated scalars as constant polynomials,
//! this compiler commutes with the auto-stable proof challenge and is a
//! genuine input to the generic quadratic opening proof.
use super::{
    params::{
        APPLICATION_MODULUS_INVERSE_IN_PROOF_V1, APPLICATION_RING_DEGREE_V1, APPLICATION_ROWS_V1,
        APPLICATION_WITNESS_POLYNOMIALS_V1, BINARY_POLYNOMIALS_V1, MAX_PROJECTION_COLUMNS_V1,
        PROOF_INVERSE_TWO_V1, PROOF_MODULUS_V1, RANDOMNESS_NORM_SQUARED_BOUND_V1,
        SIGNATURE_NORM_SQUARED_BOUND_V1, TBOX_KMSIS_V1, TBOX_LEXT_V1, TBOX_M1_V1, TBOX_M2_V1,
    },
    relation::{
        BootleLanternApplicationRelationV1, BootleLanternPresentationWitnessV1,
        canonical_witness_vector_v1, validate_presentation_witness_v1,
    },
    ring::ProofPolynomialV1,
    transcript::{
        MatrixRoleV1, ProofMatrixV1, ProofTranscriptCoreV1, TranscriptErrorV1,
        expand_proof_matrix_v1,
    },
};
use sha3::{Digest, Sha3_256};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};
/// Number of polynomials in the first, public part of `s2`.
pub const S21_POLYNOMIALS_V1: usize = TBOX_M2_V1 - TBOX_KMSIS_V1;
/// Number of projected field coordinates.
pub const PROJECTION_COORDINATES_V1: usize = 256;
/// Number of proof-ring polynomials carrying one projected vector.
pub const PROJECTION_POLYNOMIALS_V1: usize = PROJECTION_COORDINATES_V1 / APPLICATION_RING_DEGREE_V1;
/// Number of secret extended-message polynomials consumed by the quadratic
/// equation.  The twelfth `tB` row commits its linearization and is public.
pub const QUADRATIC_MESSAGE_POLYNOMIALS_V1: usize = TBOX_LEXT_V1 - 1;
/// Exact number of scalar evaluation constraints.
pub const EVALUATION_CONSTRAINTS_V1: usize =
    2 * (APPLICATION_RING_DEGREE_V1 - 1) + 2 + 2 + 2 * PROJECTION_COORDINATES_V1;
/// Number of independent Schwartz accumulators.
pub const SCHWARTZ_ACCUMULATORS_V1: usize = 4;
/// Number of full ring equations after Schwartz compression.
pub const COMBINED_QUADRATIC_EQUATIONS_V1: usize = 4;
const SCALAR_QUADRATIC_RELATIONS_V1: usize = 4;
const BETA3_SHAPE_START_V1: usize = 0;
const BETA4_SHAPE_START_V1: usize = BETA3_SHAPE_START_V1 + APPLICATION_RING_DEGREE_V1 - 1;
const SLACK_BINARY_INDEX_V1: usize = BETA4_SHAPE_START_V1 + APPLICATION_RING_DEGREE_V1 - 1;
const CREDENTIAL_BINARY_INDEX_V1: usize = SLACK_BINARY_INDEX_V1 + 1;
const RANDOMNESS_NORM_INDEX_V1: usize = CREDENTIAL_BINARY_INDEX_V1 + 1;
const SIGNATURE_NORM_INDEX_V1: usize = RANDOMNESS_NORM_INDEX_V1 + 1;
const Z4_PROJECTION_START_V1: usize = SIGNATURE_NORM_INDEX_V1 + 1;
const Z3_PROJECTION_START_V1: usize = Z4_PROJECTION_START_V1 + PROJECTION_COORDINATES_V1;
const BINARY_SHORT_INDICES_V1: [usize; BINARY_POLYNOMIALS_V1] = [
    16, 17, 18, 19, 20, 21, 22, 23, 40, 41, 42, 43, 44, 45, 46, 47,
];
const RANDOMNESS_SHORT_START_V1: usize = 0;
const RANDOMNESS_SHORT_END_V1: usize = 16;
const SIGNATURE_SHORT_START_V1: usize = 24;
const SIGNATURE_SHORT_END_V1: usize = 40;
const RANDOMNESS_SLACK_INDEX_V1: usize = 48;
const SIGNATURE_SLACK_INDEX_V1: usize = 49;
const Y3_MESSAGE_START_V1: usize = 0;
const Y4_MESSAGE_START_V1: usize = 4;
const BETA_MESSAGE_INDEX_V1: usize = 8;
const G_MESSAGE_START_V1: usize = 9;
const RELATION_DIGEST_DOMAIN_V1: &[u8] = b"iroha.privacy.bootle-lantern.application-relation.v1";
/// The 50 short witness polynomials, zeroized on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct ShortWitnessV1 {
    polynomials: Box<[ProofPolynomialV1; TBOX_M1_V1]>,
}
impl core::fmt::Debug for ShortWitnessV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ShortWitnessV1")
            .field("polynomials", &"<redacted>")
            .finish()
    }
}
impl ShortWitnessV1 {
    #[must_use]
    pub(crate) fn polynomials(&self) -> &[ProofPolynomialV1; TBOX_M1_V1] {
        &self.polynomials
    }
}
impl Zeroize for ShortWitnessV1 {
    fn zeroize(&mut self) {
        self.polynomials.as_mut().zeroize();
    }
}
impl Drop for ShortWitnessV1 {
    fn drop(&mut self) {
        self.zeroize();
    }
}
/// Secret variables of the generic quadratic equation.
#[derive(Clone, PartialEq, Eq)]
pub struct QuadraticVariablesV1 {
    pub(crate) short: Box<[ProofPolynomialV1; TBOX_M1_V1]>,
    pub(crate) message: Box<[ProofPolynomialV1; QUADRATIC_MESSAGE_POLYNOMIALS_V1]>,
}
impl core::fmt::Debug for QuadraticVariablesV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("QuadraticVariablesV1")
            .field("variables", &"<redacted>")
            .finish()
    }
}
impl QuadraticVariablesV1 {
    /// Add component-wise in the proof ring.
    #[must_use]
    pub(crate) fn add(&self, rhs: &Self) -> Self {
        Self {
            short: boxed_polynomial_array_from_fn_v1(|index| {
                self.short[index].add(rhs.short[index])
            }),
            message: boxed_polynomial_array_from_fn_v1(|index| {
                self.message[index].add(rhs.message[index])
            }),
        }
    }
    /// Negate component-wise in the proof ring.
    #[must_use]
    pub(crate) fn negate(&self) -> Self {
        Self {
            short: boxed_polynomial_array_from_fn_v1(|index| self.short[index].negate()),
            message: boxed_polynomial_array_from_fn_v1(|index| self.message[index].negate()),
        }
    }
    /// All-zero variable vector.
    #[must_use]
    pub(crate) fn zero() -> Self {
        Self {
            short: boxed_zero_polynomial_array_v1(),
            message: boxed_zero_polynomial_array_v1(),
        }
    }
}
impl Zeroize for QuadraticVariablesV1 {
    fn zeroize(&mut self) {
        self.short.as_mut().zeroize();
        self.message.as_mut().zeroize();
    }
}
impl Drop for QuadraticVariablesV1 {
    fn drop(&mut self) {
        self.zeroize();
    }
}
/// Allocate one exact fixed-shape polynomial array directly on the heap.
///
/// Large proof workspaces must not be materialized as temporary stack arrays:
/// validators commonly execute on Rust's default 2 MiB worker stacks.
pub fn boxed_polynomial_array_from_fn_v1<const N: usize>(
    mut polynomial: impl FnMut(usize) -> ProofPolynomialV1,
) -> Box<[ProofPolynomialV1; N]> {
    let mut values = Vec::with_capacity(N);
    for index in 0..N {
        values.push(polynomial(index));
    }
    values
        .into_boxed_slice()
        .try_into()
        .unwrap_or_else(|_| unreachable!("fixed polynomial array has exact length"))
}
/// Allocate an exact all-zero polynomial array directly on the heap.
pub fn boxed_zero_polynomial_array_v1<const N: usize>() -> Box<[ProofPolynomialV1; N]> {
    boxed_polynomial_array_from_fn_v1(|_| ProofPolynomialV1::ZERO)
}
/// Pre-expanded transparent matrices used by one proof or verification.
#[derive(Clone, Debug)]
pub struct InternalMatricesV1 {
    pub(crate) a1: ProofMatrixV1,
    pub(crate) a2_prime: ProofMatrixV1,
    pub(crate) b_prime: ProofMatrixV1,
}
impl InternalMatricesV1 {
    /// Expand all fixed internal matrices from the transcript-bound seed.
    pub(crate) fn expand(transcript: &ProofTranscriptCoreV1) -> Result<Self, ToolboxErrorV1> {
        let seed = transcript.matrix_seed();
        Ok(Self {
            a1: expand_proof_matrix_v1(seed, MatrixRoleV1::InternalA1)
                .map_err(ToolboxErrorV1::Transcript)?,
            a2_prime: expand_proof_matrix_v1(seed, MatrixRoleV1::InternalA2Prime)
                .map_err(ToolboxErrorV1::Transcript)?,
            b_prime: expand_proof_matrix_v1(seed, MatrixRoleV1::InternalBPrime)
                .map_err(ToolboxErrorV1::Transcript)?,
        })
    }
}
/// Public material required to evaluate the one combined quadratic equation.
pub struct QuadraticEquationV1<'a> {
    relation: &'a BootleLanternApplicationRelationV1,
    schwartz_compilers: Box<[SchwartzAccumulatorCompilerV1; SCHWARTZ_ACCUMULATORS_V1]>,
    #[cfg(test)]
    projection_r: Box<[i8]>,
    #[cfg(test)]
    projection_r_prime: Box<[i8]>,
    #[cfg(test)]
    z3: Box<[ProofPolynomialV1; PROJECTION_POLYNOMIALS_V1]>,
    #[cfg(test)]
    z4: Box<[ProofPolynomialV1; PROJECTION_POLYNOMIALS_V1]>,
    h: Box<[ProofPolynomialV1; 2]>,
    #[cfg(test)]
    schwartz_weights: Box<[u64]>,
    equation_multipliers: Box<[ProofPolynomialV1; COMBINED_QUADRATIC_EQUATIONS_V1]>,
}
/// One precompressed field-constraint accumulator.
///
/// The transcript-derived scalar weights and ternary projection rows are
/// public.  Compressing them once avoids rebuilding 642 separate ring
/// polynomials during every prover-mask retry and verifier reconstruction.
struct SchwartzAccumulatorCompilerV1 {
    beta3_shape_weights: ProofPolynomialV1,
    beta4_shape_weights: ProofPolynomialV1,
    scalar_relation_weights: [u64; SCALAR_QUADRATIC_RELATIONS_V1],
    projection_r_weights: Box<[ProofPolynomialV1; 50]>,
    projection_r_prime_weights: Box<[ProofPolynomialV1; APPLICATION_ROWS_V1]>,
    coordinate3_weights: Box<[ProofPolynomialV1; PROJECTION_POLYNOMIALS_V1]>,
    coordinate4_weights: Box<[ProofPolynomialV1; PROJECTION_POLYNOMIALS_V1]>,
    public_z3_accumulator: ProofPolynomialV1,
    public_z4_accumulator: ProofPolynomialV1,
}
impl core::fmt::Debug for QuadraticEquationV1<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("QuadraticEquationV1")
            .field("constraints", &EVALUATION_CONSTRAINTS_V1)
            .finish_non_exhaustive()
    }
}
impl<'a> QuadraticEquationV1<'a> {
    /// Construct one fully shaped public equation.
    pub(crate) fn new(
        relation: &'a BootleLanternApplicationRelationV1,
        projection_r: Box<[i8]>,
        projection_r_prime: Box<[i8]>,
        z3: Box<[ProofPolynomialV1; PROJECTION_POLYNOMIALS_V1]>,
        z4: Box<[ProofPolynomialV1; PROJECTION_POLYNOMIALS_V1]>,
        h: Box<[ProofPolynomialV1; 2]>,
        schwartz_weights: Box<[u64]>,
        equation_multipliers: Box<[ProofPolynomialV1; COMBINED_QUADRATIC_EQUATIONS_V1]>,
    ) -> Result<Self, ToolboxErrorV1> {
        let expected_r = PROJECTION_COORDINATES_V1
            .checked_mul(50 * APPLICATION_RING_DEGREE_V1)
            .ok_or(ToolboxErrorV1::ArithmeticOverflow)?;
        let expected_r_prime = PROJECTION_COORDINATES_V1
            .checked_mul(APPLICATION_ROWS_V1 * APPLICATION_RING_DEGREE_V1)
            .ok_or(ToolboxErrorV1::ArithmeticOverflow)?;
        let expected_weights = SCHWARTZ_ACCUMULATORS_V1
            .checked_mul(EVALUATION_CONSTRAINTS_V1)
            .ok_or(ToolboxErrorV1::ArithmeticOverflow)?;
        if projection_r.len() != expected_r
            || projection_r_prime.len() != expected_r_prime
            || schwartz_weights.len() != expected_weights
        {
            return Err(ToolboxErrorV1::InvalidShape);
        }
        if projection_r
            .iter()
            .chain(projection_r_prime.iter())
            .any(|coefficient| !(-1..=1).contains(coefficient))
            || schwartz_weights
                .iter()
                .any(|coefficient| *coefficient >= PROOF_MODULUS_V1)
        {
            return Err(ToolboxErrorV1::NonCanonicalPublicInput);
        }
        let schwartz_compilers = compile_schwartz_accumulators_v1(
            &projection_r,
            &projection_r_prime,
            &z3,
            &z4,
            &schwartz_weights,
        )?;
        Ok(Self {
            relation,
            schwartz_compilers,
            #[cfg(test)]
            projection_r,
            #[cfg(test)]
            projection_r_prime,
            #[cfg(test)]
            z3,
            #[cfg(test)]
            z4,
            h,
            #[cfg(test)]
            schwartz_weights,
            equation_multipliers,
        })
    }
    /// Install the public Schwartz commitments and the final equation
    /// multipliers after both have been transcript-derived.
    pub(crate) fn bind_final_equations(
        &mut self,
        h: Box<[ProofPolynomialV1; 2]>,
        equation_multipliers: Box<[ProofPolynomialV1; COMBINED_QUADRATIC_EQUATIONS_V1]>,
    ) {
        self.h = h;
        self.equation_multipliers = equation_multipliers;
    }
    /// Evaluate the exact 642 scalar constraints as a test oracle.
    ///
    /// Production proof evaluation must use the sigma-compatible ring
    /// compiler in `schwartz_polynomials`; directly embedding these evaluated
    /// scalars does not commute with a non-constant ring challenge.
    #[cfg(test)]
    pub(crate) fn constraints(
        &self,
        variables: &QuadraticVariablesV1,
    ) -> Result<[u64; EVALUATION_CONSTRAINTS_V1], ToolboxErrorV1> {
        let mut constraints = [0_u64; EVALUATION_CONSTRAINTS_V1];
        let (beta3, beta4) = beta_polynomials_v1(variables.message[BETA_MESSAGE_INDEX_V1])?;
        constraints[BETA3_SHAPE_START_V1..BETA4_SHAPE_START_V1]
            .copy_from_slice(&beta3.coefficients()[1..]);
        constraints[BETA4_SHAPE_START_V1..SLACK_BINARY_INDEX_V1]
            .copy_from_slice(&beta4.coefficients()[1..]);
        constraints[SLACK_BINARY_INDEX_V1] = binary_inner_product(&[
            variables.short[RANDOMNESS_SLACK_INDEX_V1],
            variables.short[SIGNATURE_SLACK_INDEX_V1],
        ]);
        constraints[CREDENTIAL_BINARY_INDEX_V1] =
            binary_inner_product(&BINARY_SHORT_INDICES_V1.map(|index| variables.short[index]));
        constraints[RANDOMNESS_NORM_INDEX_V1] = norm_slack_equation(
            &variables.short[RANDOMNESS_SHORT_START_V1..RANDOMNESS_SHORT_END_V1],
            variables.short[RANDOMNESS_SLACK_INDEX_V1],
            RANDOMNESS_NORM_SQUARED_BOUND_V1,
        );
        constraints[SIGNATURE_NORM_INDEX_V1] = norm_slack_equation(
            &variables.short[SIGNATURE_SHORT_START_V1..SIGNATURE_SHORT_END_V1],
            variables.short[SIGNATURE_SLACK_INDEX_V1],
            SIGNATURE_NORM_SQUARED_BOUND_V1,
        );
        let s4 = Zeroizing::new(application_quotient_v1(self.relation, &variables.short)?);
        let s3 = projected_norm_witness_v1(&variables.short);
        let s4_coefficients = Zeroizing::new(flatten_polynomials(s4.as_ref()));
        let s3_coefficients = Zeroizing::new(flatten_polynomials(s3.polynomials()));
        let y3 = Zeroizing::new(flatten_polynomials(
            &variables.message
                [Y3_MESSAGE_START_V1..Y3_MESSAGE_START_V1 + PROJECTION_POLYNOMIALS_V1],
        ));
        let y4 = Zeroizing::new(flatten_polynomials(
            &variables.message
                [Y4_MESSAGE_START_V1..Y4_MESSAGE_START_V1 + PROJECTION_POLYNOMIALS_V1],
        ));
        let z3 = flatten_polynomials(self.z3.as_ref());
        let z4 = flatten_polynomials(self.z4.as_ref());
        let beta3_scalar = beta3.coefficients()[0];
        let beta4_scalar = beta4.coefficients()[0];
        let r_columns = s3_coefficients.len();
        let r_prime_columns = s4_coefficients.len();
        for row in 0..PROJECTION_COORDINATES_V1 {
            let r_prime_start = row * r_prime_columns;
            let projected_s4 = ternary_dot(
                &self.projection_r_prime[r_prime_start..r_prime_start + r_prime_columns],
                s4_coefficients.as_ref(),
            );
            constraints[Z4_PROJECTION_START_V1 + row] = sub_mod(
                add_mod(mul_mod(beta4_scalar, projected_s4), y4[row]),
                z4[row],
            );
            let r_start = row * r_columns;
            let projected_s3 = ternary_dot(
                &self.projection_r[r_start..r_start + r_columns],
                s3_coefficients.as_ref(),
            );
            constraints[Z3_PROJECTION_START_V1 + row] = sub_mod(
                add_mod(mul_mod(beta3_scalar, projected_s3), y3[row]),
                z3[row],
            );
        }
        Ok(constraints)
    }
    /// Evaluate the four scalar Schwartz accumulators as a test oracle.
    #[cfg(test)]
    pub(crate) fn scalar_schwartz_accumulators(
        &self,
        variables: &QuadraticVariablesV1,
    ) -> Result<[u64; SCHWARTZ_ACCUMULATORS_V1], ToolboxErrorV1> {
        let constraints = self.constraints(variables)?;
        Ok(self.accumulate_scalar_constraints(&constraints))
    }
    /// Evaluate the coefficient-field lift used by the ring compiler.
    ///
    /// For a malformed, non-constant `beta`, multiplying a projected ring
    /// witness by `beta` also mixes its non-constant coefficients.  Those
    /// augmented projection equations are deliberate: the independent beta
    /// shape equations force all mixed terms to zero, so the lifted and
    /// canonical systems have exactly the same zero set.  Unlike the
    /// canonical scalar oracle, this lift remains homogeneous under
    /// multiplication by an auto-stable Fiat--Shamir challenge.
    #[cfg(test)]
    pub(crate) fn lifted_schwartz_accumulators(
        &self,
        variables: &QuadraticVariablesV1,
    ) -> Result<[u64; SCHWARTZ_ACCUMULATORS_V1], ToolboxErrorV1> {
        let constraints = self.lifted_constraints(variables)?;
        Ok(self.accumulate_scalar_constraints(&constraints))
    }
    #[cfg(test)]
    fn accumulate_scalar_constraints(
        &self,
        constraints: &[u64; EVALUATION_CONSTRAINTS_V1],
    ) -> [u64; SCHWARTZ_ACCUMULATORS_V1] {
        core::array::from_fn(|accumulator| {
            let weights_start = accumulator * EVALUATION_CONSTRAINTS_V1;
            constraints
                .iter()
                .copied()
                .zip(
                    &self.schwartz_weights
                        [weights_start..weights_start + EVALUATION_CONSTRAINTS_V1],
                )
                .fold(0_u64, |sum, (constraint, weight)| {
                    add_mod(sum, mul_mod(constraint, *weight))
                })
        })
    }
    #[cfg(test)]
    pub(crate) fn lifted_constraints(
        &self,
        variables: &QuadraticVariablesV1,
    ) -> Result<[u64; EVALUATION_CONSTRAINTS_V1], ToolboxErrorV1> {
        let mut constraints = self.constraints(variables)?;
        let (beta3, beta4) = beta_polynomials_v1(variables.message[BETA_MESSAGE_INDEX_V1])?;
        let s4 = Zeroizing::new(application_quotient_v1(self.relation, &variables.short)?);
        let s3 = projected_norm_witness_v1(&variables.short);
        let beta4_s4 = Zeroizing::new(
            s4.iter()
                .copied()
                .map(|polynomial| beta4.multiply(polynomial))
                .collect::<Vec<_>>(),
        );
        let beta3_s3 = Zeroizing::new(
            s3.polynomials()
                .iter()
                .copied()
                .map(|polynomial| beta3.multiply(polynomial))
                .collect::<Vec<_>>(),
        );
        let beta4_s4_coefficients = Zeroizing::new(flatten_polynomials(beta4_s4.as_slice()));
        let beta3_s3_coefficients = Zeroizing::new(flatten_polynomials(beta3_s3.as_slice()));
        let y3 = Zeroizing::new(flatten_polynomials(
            &variables.message
                [Y3_MESSAGE_START_V1..Y3_MESSAGE_START_V1 + PROJECTION_POLYNOMIALS_V1],
        ));
        let y4 = Zeroizing::new(flatten_polynomials(
            &variables.message
                [Y4_MESSAGE_START_V1..Y4_MESSAGE_START_V1 + PROJECTION_POLYNOMIALS_V1],
        ));
        let z3 = flatten_polynomials(self.z3.as_ref());
        let z4 = flatten_polynomials(self.z4.as_ref());
        let r_columns = beta3_s3_coefficients.len();
        let r_prime_columns = beta4_s4_coefficients.len();
        for row in 0..PROJECTION_COORDINATES_V1 {
            let r_prime_start = row * r_prime_columns;
            constraints[Z4_PROJECTION_START_V1 + row] = sub_mod(
                add_mod(
                    ternary_dot(
                        &self.projection_r_prime[r_prime_start..r_prime_start + r_prime_columns],
                        beta4_s4_coefficients.as_slice(),
                    ),
                    y4[row],
                ),
                z4[row],
            );
            let r_start = row * r_columns;
            constraints[Z3_PROJECTION_START_V1 + row] = sub_mod(
                add_mod(
                    ternary_dot(
                        &self.projection_r[r_start..r_start + r_columns],
                        beta3_s3_coefficients.as_slice(),
                    ),
                    y3[row],
                ),
                z3[row],
            );
        }
        Ok(constraints)
    }
    /// Return the two masked, sigma-compatible constraint polynomials.
    pub(crate) fn schwartz_polynomials(
        &self,
        variables: &QuadraticVariablesV1,
    ) -> Result<[ProofPolynomialV1; 2], ToolboxErrorV1> {
        let (beta3, beta4) = beta_polynomials_v1(variables.message[BETA_MESSAGE_INDEX_V1])?;
        let beta3 = Zeroizing::new(beta3);
        let beta4 = Zeroizing::new(beta4);
        let s4 = Zeroizing::new(application_quotient_v1(self.relation, &variables.short)?);
        let s3 = projected_norm_witness_v1(&variables.short);
        let scalar_relations = Zeroizing::new([
            binary_relation_polynomial_v1(&[
                variables.short[RANDOMNESS_SLACK_INDEX_V1],
                variables.short[SIGNATURE_SLACK_INDEX_V1],
            ]),
            binary_relation_polynomial_v1(
                &BINARY_SHORT_INDICES_V1.map(|index| variables.short[index]),
            ),
            norm_slack_relation_polynomial_v1(
                &variables.short[RANDOMNESS_SHORT_START_V1..RANDOMNESS_SHORT_END_V1],
                variables.short[RANDOMNESS_SLACK_INDEX_V1],
                RANDOMNESS_NORM_SQUARED_BOUND_V1,
            )?,
            norm_slack_relation_polynomial_v1(
                &variables.short[SIGNATURE_SHORT_START_V1..SIGNATURE_SHORT_END_V1],
                variables.short[SIGNATURE_SLACK_INDEX_V1],
                SIGNATURE_NORM_SQUARED_BOUND_V1,
            )?,
        ]);
        let evaluate = |compiler: &SchwartzAccumulatorCompilerV1| {
            compiler.evaluate(
                *beta3,
                *beta4,
                &scalar_relations,
                s3.polynomials(),
                &s4,
                &variables.message
                    [Y3_MESSAGE_START_V1..Y3_MESSAGE_START_V1 + PROJECTION_POLYNOMIALS_V1],
                &variables.message
                    [Y4_MESSAGE_START_V1..Y4_MESSAGE_START_V1 + PROJECTION_POLYNOMIALS_V1],
            )
        };
        let accumulators = Zeroizing::new([
            evaluate(&self.schwartz_compilers[0])?,
            evaluate(&self.schwartz_compilers[1])?,
            evaluate(&self.schwartz_compilers[2])?,
            evaluate(&self.schwartz_compilers[3])?,
        ]);
        let traces = Zeroizing::new([
            trace_sigma_minus_one_v1(accumulators[0])?,
            trace_sigma_minus_one_v1(accumulators[1])?,
            trace_sigma_minus_one_v1(accumulators[2])?,
            trace_sigma_minus_one_v1(accumulators[3])?,
        ]);
        let output = [
            traces[0].add(traces[1].multiply_by_monomial(APPLICATION_RING_DEGREE_V1 / 2)),
            traces[2].add(traces[3].multiply_by_monomial(APPLICATION_RING_DEGREE_V1 / 2)),
        ];
        Ok(output)
    }
    /// Evaluate the combined quadratic ring equation.
    pub(crate) fn evaluate(
        &self,
        variables: &QuadraticVariablesV1,
    ) -> Result<ProofPolynomialV1, ToolboxErrorV1> {
        let schwartz = Zeroizing::new(self.schwartz_polynomials(variables)?);
        let (beta3, beta4) = beta_polynomials_v1(variables.message[BETA_MESSAGE_INDEX_V1])?;
        let beta3 = Zeroizing::new(beta3);
        let beta4 = Zeroizing::new(beta4);
        let one = ProofPolynomialV1::constant(1).map_err(|_| ToolboxErrorV1::InternalInvariant)?;
        let equations = Zeroizing::new([
            schwartz[0]
                .add(variables.message[G_MESSAGE_START_V1])
                .sub(self.h[0]),
            schwartz[1]
                .add(variables.message[G_MESSAGE_START_V1 + 1])
                .sub(self.h[1]),
            beta3.multiply(*beta3).sub(one),
            beta4.multiply(*beta4).sub(one),
        ]);
        Ok(equations
            .iter()
            .copied()
            .zip(self.equation_multipliers.iter().copied())
            .fold(ProofPolynomialV1::ZERO, |sum, (equation, multiplier)| {
                sum.add(multiplier.multiply(equation))
            }))
    }
}
impl SchwartzAccumulatorCompilerV1 {
    fn evaluate(
        &self,
        beta3: ProofPolynomialV1,
        beta4: ProofPolynomialV1,
        scalar_relations: &[ProofPolynomialV1; SCALAR_QUADRATIC_RELATIONS_V1],
        s3: &[ProofPolynomialV1; 50],
        s4: &[ProofPolynomialV1; APPLICATION_ROWS_V1],
        y3: &[ProofPolynomialV1],
        y4: &[ProofPolynomialV1],
    ) -> Result<ProofPolynomialV1, ToolboxErrorV1> {
        let mut accumulator = Zeroizing::new(
            beta3
                .multiply(self.beta3_shape_weights.automorphism())
                .add(beta4.multiply(self.beta4_shape_weights.automorphism())),
        );
        for (relation, weight) in scalar_relations
            .iter()
            .copied()
            .zip(self.scalar_relation_weights)
        {
            *accumulator = (*accumulator).add(
                relation
                    .scale_canonical(weight)
                    .map_err(|_| ToolboxErrorV1::InternalInvariant)?,
            );
        }
        let projected_s4 = Zeroizing::new(ring_inner_product_v1(
            s4,
            self.projection_r_prime_weights.as_ref(),
        )?);
        let projected_y4 = Zeroizing::new(ring_inner_product_v1(
            y4,
            self.coordinate4_weights.as_ref(),
        )?);
        *accumulator = (*accumulator)
            .add(beta4.multiply(*projected_s4))
            .add(*projected_y4)
            .sub(self.public_z4_accumulator);
        let projected_s3 = Zeroizing::new(ring_inner_product_v1(
            s3,
            self.projection_r_weights.as_ref(),
        )?);
        let projected_y3 = Zeroizing::new(ring_inner_product_v1(
            y3,
            self.coordinate3_weights.as_ref(),
        )?);
        *accumulator = (*accumulator)
            .add(beta3.multiply(*projected_s3))
            .add(*projected_y3)
            .sub(self.public_z3_accumulator);
        Ok(*accumulator)
    }
}
fn compile_schwartz_accumulators_v1(
    projection_r: &[i8],
    projection_r_prime: &[i8],
    z3: &[ProofPolynomialV1; PROJECTION_POLYNOMIALS_V1],
    z4: &[ProofPolynomialV1; PROJECTION_POLYNOMIALS_V1],
    schwartz_weights: &[u64],
) -> Result<Box<[SchwartzAccumulatorCompilerV1; SCHWARTZ_ACCUMULATORS_V1]>, ToolboxErrorV1> {
    let mut compilers = Vec::with_capacity(SCHWARTZ_ACCUMULATORS_V1);
    for accumulator in 0..SCHWARTZ_ACCUMULATORS_V1 {
        let start = accumulator
            .checked_mul(EVALUATION_CONSTRAINTS_V1)
            .ok_or(ToolboxErrorV1::ArithmeticOverflow)?;
        let weights = schwartz_weights
            .get(start..start + EVALUATION_CONSTRAINTS_V1)
            .ok_or(ToolboxErrorV1::InvalidShape)?;
        let beta3_shape_weights =
            polynomial_from_coefficients_v1(core::array::from_fn(|coefficient| {
                if coefficient == 0 {
                    0
                } else {
                    weights[BETA3_SHAPE_START_V1 + coefficient - 1]
                }
            }))?;
        let beta4_shape_weights =
            polynomial_from_coefficients_v1(core::array::from_fn(|coefficient| {
                if coefficient == 0 {
                    0
                } else {
                    weights[BETA4_SHAPE_START_V1 + coefficient - 1]
                }
            }))?;
        let coordinate4_weights = coordinate_weight_polynomials_v1(
            &weights[Z4_PROJECTION_START_V1..Z4_PROJECTION_START_V1 + PROJECTION_COORDINATES_V1],
        )?;
        let coordinate3_weights = coordinate_weight_polynomials_v1(
            &weights[Z3_PROJECTION_START_V1..Z3_PROJECTION_START_V1 + PROJECTION_COORDINATES_V1],
        )?;
        let projection_r_prime_weights = compress_projection_rows_v1::<APPLICATION_ROWS_V1>(
            projection_r_prime,
            &weights[Z4_PROJECTION_START_V1..Z4_PROJECTION_START_V1 + PROJECTION_COORDINATES_V1],
        )?;
        let projection_r_weights = compress_projection_rows_v1::<50>(
            projection_r,
            &weights[Z3_PROJECTION_START_V1..Z3_PROJECTION_START_V1 + PROJECTION_COORDINATES_V1],
        )?;
        let public_z4_accumulator = ring_inner_product_v1(z4, coordinate4_weights.as_ref())?;
        let public_z3_accumulator = ring_inner_product_v1(z3, coordinate3_weights.as_ref())?;
        compilers.push(SchwartzAccumulatorCompilerV1 {
            beta3_shape_weights,
            beta4_shape_weights,
            scalar_relation_weights: [
                weights[SLACK_BINARY_INDEX_V1],
                weights[CREDENTIAL_BINARY_INDEX_V1],
                weights[RANDOMNESS_NORM_INDEX_V1],
                weights[SIGNATURE_NORM_INDEX_V1],
            ],
            projection_r_weights,
            projection_r_prime_weights,
            coordinate3_weights,
            coordinate4_weights,
            public_z3_accumulator,
            public_z4_accumulator,
        });
    }
    compilers
        .into_boxed_slice()
        .try_into()
        .map_err(|_| ToolboxErrorV1::InternalInvariant)
}
fn coordinate_weight_polynomials_v1(
    weights: &[u64],
) -> Result<Box<[ProofPolynomialV1; PROJECTION_POLYNOMIALS_V1]>, ToolboxErrorV1> {
    if weights.len() != PROJECTION_COORDINATES_V1 {
        return Err(ToolboxErrorV1::InvalidShape);
    }
    let mut polynomials = Vec::with_capacity(PROJECTION_POLYNOMIALS_V1);
    for polynomial in 0..PROJECTION_POLYNOMIALS_V1 {
        let start = polynomial * APPLICATION_RING_DEGREE_V1;
        let coefficients: [u64; APPLICATION_RING_DEGREE_V1] = weights
            [start..start + APPLICATION_RING_DEGREE_V1]
            .try_into()
            .map_err(|_| ToolboxErrorV1::InvalidShape)?;
        polynomials.push(polynomial_from_coefficients_v1(coefficients)?);
    }
    polynomials
        .into_boxed_slice()
        .try_into()
        .map_err(|_| ToolboxErrorV1::InternalInvariant)
}
fn compress_projection_rows_v1<const POLYNOMIALS: usize>(
    projection: &[i8],
    weights: &[u64],
) -> Result<Box<[ProofPolynomialV1; POLYNOMIALS]>, ToolboxErrorV1> {
    let columns = POLYNOMIALS
        .checked_mul(APPLICATION_RING_DEGREE_V1)
        .ok_or(ToolboxErrorV1::ArithmeticOverflow)?;
    if weights.len() != PROJECTION_COORDINATES_V1
        || projection.len()
            != PROJECTION_COORDINATES_V1
                .checked_mul(columns)
                .ok_or(ToolboxErrorV1::ArithmeticOverflow)?
    {
        return Err(ToolboxErrorV1::InvalidShape);
    }
    let mut polynomials = Vec::with_capacity(POLYNOMIALS);
    for polynomial in 0..POLYNOMIALS {
        let coefficients = core::array::from_fn(|coefficient| {
            let column = polynomial * APPLICATION_RING_DEGREE_V1 + coefficient;
            (0..PROJECTION_COORDINATES_V1).fold(0_u64, |sum, row| {
                match projection[row * columns + column] {
                    -1 => sub_mod(sum, weights[row]),
                    0 => sum,
                    1 => add_mod(sum, weights[row]),
                    _ => unreachable!("projection matrix was validated before compression"),
                }
            })
        });
        polynomials.push(polynomial_from_coefficients_v1(coefficients)?);
    }
    polynomials
        .into_boxed_slice()
        .try_into()
        .map_err(|_| ToolboxErrorV1::InternalInvariant)
}
fn ring_inner_product_v1(
    lhs: &[ProofPolynomialV1],
    rhs: &[ProofPolynomialV1],
) -> Result<ProofPolynomialV1, ToolboxErrorV1> {
    if lhs.len() != rhs.len() {
        return Err(ToolboxErrorV1::InvalidShape);
    }
    Ok(lhs
        .iter()
        .copied()
        .zip(rhs.iter().copied())
        .fold(ProofPolynomialV1::ZERO, |sum, (lhs, rhs)| {
            sum.add(lhs.multiply(rhs.automorphism()))
        }))
}
fn polynomial_from_coefficients_v1(
    coefficients: [u64; APPLICATION_RING_DEGREE_V1],
) -> Result<ProofPolynomialV1, ToolboxErrorV1> {
    ProofPolynomialV1::new(coefficients).map_err(|_| ToolboxErrorV1::InternalInvariant)
}
fn binary_relation_polynomial_v1(polynomials: &[ProofPolynomialV1]) -> ProofPolynomialV1 {
    let ones = ProofPolynomialV1::new([1; APPLICATION_RING_DEGREE_V1])
        .expect("one is a canonical proof-field residue");
    polynomials
        .iter()
        .copied()
        .fold(ProofPolynomialV1::ZERO, |sum, polynomial| {
            sum.add(polynomial.multiply(polynomial.sub(ones).automorphism()))
        })
}
fn norm_slack_relation_polynomial_v1(
    polynomials: &[ProofPolynomialV1],
    slack: ProofPolynomialV1,
    bound: u64,
) -> Result<ProofPolynomialV1, ToolboxErrorV1> {
    let mut power = 1_u64;
    let powers = polynomial_from_coefficients_v1(core::array::from_fn(|_| {
        let current = power;
        power = add_mod(power, power);
        current
    }))?;
    let squared_norm = polynomials
        .iter()
        .copied()
        .fold(ProofPolynomialV1::ZERO, |sum, polynomial| {
            sum.add(polynomial.multiply(polynomial.automorphism()))
        });
    let bound = ProofPolynomialV1::constant(bound % PROOF_MODULUS_V1)
        .map_err(|_| ToolboxErrorV1::InternalInvariant)?;
    Ok(squared_norm
        .add(slack.multiply(powers.automorphism()))
        .sub(bound))
}
fn trace_sigma_minus_one_v1(
    polynomial: ProofPolynomialV1,
) -> Result<ProofPolynomialV1, ToolboxErrorV1> {
    polynomial
        .add(polynomial.automorphism())
        .scale_canonical(PROOF_INVERSE_TWO_V1)
        .map_err(|_| ToolboxErrorV1::InternalInvariant)
}
/// Compute the canonical digest of the complete compiled application relation.
#[must_use]
pub fn application_relation_digest_v1(relation: &BootleLanternApplicationRelationV1) -> [u8; 32] {
    let mut hash = Sha3_256::new();
    hash.update(
        u32::try_from(RELATION_DIGEST_DOMAIN_V1.len())
            .expect("fixed digest domain fits u32")
            .to_be_bytes(),
    );
    hash.update(RELATION_DIGEST_DOMAIN_V1);
    hash.update(
        u16::try_from(relation.rows())
            .expect("fixed rows fit u16")
            .to_be_bytes(),
    );
    hash.update(
        u16::try_from(relation.columns())
            .expect("fixed columns fit u16")
            .to_be_bytes(),
    );
    hash.update([relation.disclosure_bitmap()]);
    for row in 0..relation.rows() {
        for column in 0..relation.columns() {
            let polynomial = relation
                .get(row, column)
                .expect("fixed relation coordinates exist");
            for coefficient in polynomial.coefficients() {
                hash.update(coefficient.to_le_bytes());
            }
        }
    }
    for polynomial in relation.public_offset() {
        for coefficient in polynomial.coefficients() {
            hash.update(coefficient.to_le_bytes());
        }
    }
    hash.finalize().into()
}
/// Validate and lift an application witness, including the two binary norm slack polynomials.
pub fn lift_short_witness_v1(
    relation: &BootleLanternApplicationRelationV1,
    witness: &BootleLanternPresentationWitnessV1,
) -> Result<ShortWitnessV1, ToolboxErrorV1> {
    validate_presentation_witness_v1(relation, witness)
        .map_err(|_| ToolboxErrorV1::InvalidApplicationWitness)?;
    let application = canonical_witness_vector_v1(witness, relation.disclosure_bitmap());
    let mut short = ShortWitnessV1 {
        polynomials: boxed_zero_polynomial_array_v1(),
    };
    for (output, input) in short.polynomials[..APPLICATION_WITNESS_POLYNOMIALS_V1]
        .iter_mut()
        .zip(application.polynomials())
    {
        *output = ProofPolynomialV1::from_application_centered(*input);
    }
    let randomness_norm = Zeroizing::new(
        application.polynomials()[RANDOMNESS_SHORT_START_V1..RANDOMNESS_SHORT_END_V1]
            .iter()
            .map(super::ring::ApplicationPolynomialV1::centered_squared_norm)
            .sum::<u64>(),
    );
    let signature_norm = Zeroizing::new(
        application.polynomials()[SIGNATURE_SHORT_START_V1..SIGNATURE_SHORT_END_V1]
            .iter()
            .map(super::ring::ApplicationPolynomialV1::centered_squared_norm)
            .sum::<u64>(),
    );
    let randomness_slack = Zeroizing::new(
        RANDOMNESS_NORM_SQUARED_BOUND_V1
            .checked_sub(*randomness_norm)
            .ok_or(ToolboxErrorV1::InvalidApplicationWitness)?,
    );
    let signature_slack = Zeroizing::new(
        SIGNATURE_NORM_SQUARED_BOUND_V1
            .checked_sub(*signature_norm)
            .ok_or(ToolboxErrorV1::InvalidApplicationWitness)?,
    );
    short.polynomials[RANDOMNESS_SLACK_INDEX_V1] = binary_expansion_polynomial(*randomness_slack);
    short.polynomials[SIGNATURE_SLACK_INDEX_V1] = binary_expansion_polynomial(*signature_slack);
    Ok(short)
}
/// Matrix-vector product in the proof ring.
pub fn matrix_vector_product_v1(
    matrix: &ProofMatrixV1,
    vector: &[ProofPolynomialV1],
) -> Result<Zeroizing<Vec<ProofPolynomialV1>>, ToolboxErrorV1> {
    if vector.len() != usize::from(matrix.columns()) {
        return Err(ToolboxErrorV1::InvalidShape);
    }
    let mut output = Zeroizing::new(vec![ProofPolynomialV1::ZERO; usize::from(matrix.rows())]);
    for row in 0..usize::from(matrix.rows()) {
        for (column, polynomial) in vector.iter().copied().enumerate() {
            let coefficient = *matrix
                .get(
                    u16::try_from(row).map_err(|_| ToolboxErrorV1::InvalidShape)?,
                    u16::try_from(column).map_err(|_| ToolboxErrorV1::InvalidShape)?,
                )
                .ok_or(ToolboxErrorV1::InvalidShape)?;
            output[row] = output[row].add(coefficient.multiply(polynomial));
        }
    }
    Ok(output)
}
/// Compute `B' * vector` and add the supplied message vector.
pub fn commit_extended_messages_v1(
    b_prime: &ProofMatrixV1,
    s21: &[ProofPolynomialV1; S21_POLYNOMIALS_V1],
    messages: &[ProofPolynomialV1; TBOX_LEXT_V1],
) -> Result<[ProofPolynomialV1; TBOX_LEXT_V1], ToolboxErrorV1> {
    let product = matrix_vector_product_v1(b_prime, s21)?;
    if product.len() != TBOX_LEXT_V1 {
        return Err(ToolboxErrorV1::InvalidShape);
    }
    Ok(core::array::from_fn(|index| {
        product[index].add(messages[index])
    }))
}
/// Flatten canonical polynomial coefficients in polynomial-major order.
#[must_use]
pub fn flatten_polynomials(polynomials: &[ProofPolynomialV1]) -> Vec<u64> {
    let mut output = Vec::with_capacity(polynomials.len() * APPLICATION_RING_DEGREE_V1);
    for polynomial in polynomials {
        output.extend_from_slice(polynomial.coefficients());
    }
    output
}
/// Encode canonical proof polynomials without a header for transcript stages.
#[must_use]
pub fn encode_polynomials_v1(polynomials: &[ProofPolynomialV1]) -> Vec<u8> {
    let mut output = Vec::with_capacity(polynomials.len() * APPLICATION_RING_DEGREE_V1 * 7);
    for coefficient in flatten_polynomials(polynomials) {
        output.extend_from_slice(&coefficient.to_le_bytes()[..7]);
    }
    output
}
/// Expand all projection rows from a transcript stage.
pub fn expand_projection_matrix_v1(
    transcript: &ProofTranscriptCoreV1,
    stage: &[u8],
    components: &[&[u8]],
    columns: usize,
) -> Result<Box<[i8]>, ToolboxErrorV1> {
    if columns > MAX_PROJECTION_COLUMNS_V1 {
        return Err(ToolboxErrorV1::Transcript(
            TranscriptErrorV1::FixedProfileCapacityExceeded {
                field: "ternary_columns",
            },
        ));
    }
    let capacity = PROJECTION_COORDINATES_V1
        .checked_mul(columns)
        .ok_or(ToolboxErrorV1::ArithmeticOverflow)?;
    let mut output = Vec::new();
    output.try_reserve_exact(capacity).map_err(|_| {
        ToolboxErrorV1::Transcript(TranscriptErrorV1::AllocationFailed {
            field: "projection_matrix",
        })
    })?;
    for row in 0..PROJECTION_COORDINATES_V1 {
        output.extend(
            transcript
                .derive_ternary_row(
                    stage,
                    components,
                    u16::try_from(row).map_err(|_| ToolboxErrorV1::InvalidShape)?,
                    columns,
                )
                .map_err(ToolboxErrorV1::Transcript)?,
        );
    }
    Ok(output.into_boxed_slice())
}
fn beta_polynomials_v1(
    beta: ProofPolynomialV1,
) -> Result<(ProofPolynomialV1, ProofPolynomialV1), ToolboxErrorV1> {
    let beta_auto = beta.automorphism();
    let beta3 = beta
        .add(beta_auto)
        .scale_canonical(PROOF_INVERSE_TWO_V1)
        .map_err(|_| ToolboxErrorV1::InternalInvariant)?;
    let beta4 = beta_auto
        .sub(beta)
        .multiply_by_monomial(APPLICATION_RING_DEGREE_V1 / 2)
        .scale_canonical(PROOF_INVERSE_TWO_V1)
        .map_err(|_| ToolboxErrorV1::InternalInvariant)?;
    Ok((beta3, beta4))
}
/// Reorder the short witness under the same heap-owned, zeroizing custody.
/// Returning the owner avoids materializing or copying a 25 KiB secret array
/// through the caller's stack before it can establish its zeroizing guard.
pub fn projected_norm_witness_v1(short: &[ProofPolynomialV1; TBOX_M1_V1]) -> ShortWitnessV1 {
    let mut output = ShortWitnessV1 {
        polynomials: boxed_zero_polynomial_array_v1(),
    };
    for (destination, source) in BINARY_SHORT_INDICES_V1.into_iter().enumerate() {
        output.polynomials[destination] = short[source];
    }
    output.polynomials[16..32]
        .copy_from_slice(&short[RANDOMNESS_SHORT_START_V1..RANDOMNESS_SHORT_END_V1]);
    output.polynomials[32..48]
        .copy_from_slice(&short[SIGNATURE_SHORT_START_V1..SIGNATURE_SHORT_END_V1]);
    output.polynomials[48] = short[RANDOMNESS_SLACK_INDEX_V1];
    output.polynomials[49] = short[SIGNATURE_SLACK_INDEX_V1];
    output
}
pub fn application_quotient_v1(
    relation: &BootleLanternApplicationRelationV1,
    short: &[ProofPolynomialV1; TBOX_M1_V1],
) -> Result<[ProofPolynomialV1; APPLICATION_ROWS_V1], ToolboxErrorV1> {
    let mut output = Zeroizing::new([ProofPolynomialV1::ZERO; APPLICATION_ROWS_V1]);
    for row in 0..APPLICATION_ROWS_V1 {
        let mut equation = Zeroizing::new(ProofPolynomialV1::from_application_centered(
            relation.public_offset()[row],
        ));
        for (column, witness) in short[..APPLICATION_WITNESS_POLYNOMIALS_V1]
            .iter()
            .copied()
            .enumerate()
        {
            let coefficient = ProofPolynomialV1::from_application_centered(
                *relation
                    .get(row, column)
                    .ok_or(ToolboxErrorV1::InvalidShape)?,
            );
            *equation = (*equation).add(coefficient.multiply(witness));
        }
        output[row] = (*equation)
            .scale_canonical(APPLICATION_MODULUS_INVERSE_IN_PROOF_V1)
            .map_err(|_| ToolboxErrorV1::InternalInvariant)?;
    }
    Ok(*output)
}
#[cfg(test)]
fn binary_inner_product(polynomials: &[ProofPolynomialV1]) -> u64 {
    polynomials
        .iter()
        .flat_map(ProofPolynomialV1::coefficients)
        .copied()
        .fold(0_u64, |sum, coefficient| {
            add_mod(sum, mul_mod(coefficient, sub_mod(coefficient, 1)))
        })
}
#[cfg(test)]
fn norm_slack_equation(
    polynomials: &[ProofPolynomialV1],
    slack: ProofPolynomialV1,
    bound: u64,
) -> u64 {
    let norm = polynomials
        .iter()
        .flat_map(ProofPolynomialV1::coefficients)
        .copied()
        .fold(0_u64, |sum, coefficient| {
            add_mod(sum, mul_mod(coefficient, coefficient))
        });
    let mut power = 1_u64;
    let mut slack_value = 0_u64;
    for bit in slack.coefficients() {
        slack_value = add_mod(slack_value, mul_mod(*bit, power));
        power = add_mod(power, power);
    }
    sub_mod(add_mod(norm, slack_value), bound % PROOF_MODULUS_V1)
}
fn binary_expansion_polynomial(value: u64) -> ProofPolynomialV1 {
    let coefficients = Zeroizing::new(core::array::from_fn(|index| (value >> index) & 1));
    ProofPolynomialV1::new(*coefficients).expect("binary residues are canonical")
}
#[cfg(test)]
fn polynomial_at_zero_and_half(zero: u64, half: u64) -> Result<ProofPolynomialV1, ToolboxErrorV1> {
    let mut coefficients = [0_u64; APPLICATION_RING_DEGREE_V1];
    coefficients[0] = zero;
    coefficients[APPLICATION_RING_DEGREE_V1 / 2] = half;
    ProofPolynomialV1::new(coefficients).map_err(|_| ToolboxErrorV1::InternalInvariant)
}
#[cfg(test)]
fn ternary_dot(row: &[i8], vector: &[u64]) -> u64 {
    row.iter()
        .copied()
        .zip(vector.iter().copied())
        .fold(0_u64, |sum, (coefficient, value)| match coefficient {
            -1 => sub_mod(sum, value),
            0 => sum,
            1 => add_mod(sum, value),
            _ => unreachable!("validated ternary matrix"),
        })
}
fn add_mod(lhs: u64, rhs: u64) -> u64 {
    iroha_fhe::modular::add_mod_u64(lhs, rhs, PROOF_MODULUS_V1)
}
fn sub_mod(lhs: u64, rhs: u64) -> u64 {
    iroha_fhe::modular::sub_mod_u64(lhs, rhs, PROOF_MODULUS_V1)
}
#[cfg(test)]
fn mul_mod(lhs: u64, rhs: u64) -> u64 {
    u64::try_from(u128::from(lhs) * u128::from(rhs) % u128::from(PROOF_MODULUS_V1))
        .expect("reduced residue fits u64")
}
/// Fixed-profile constraint-toolbox failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ToolboxErrorV1 {
    /// The application witness failed its exact relation or bound.
    #[error("Bootle/Lantern application witness is invalid")]
    InvalidApplicationWitness,
    /// A fixed vector or matrix had the wrong shape.
    #[error("Bootle/Lantern proof toolbox shape mismatch")]
    InvalidShape,
    /// A public projection, weight, or residue was non-canonical.
    #[error("Bootle/Lantern proof toolbox public input is non-canonical")]
    NonCanonicalPublicInput,
    /// Transcript expansion failed.
    #[error("Bootle/Lantern proof toolbox transcript expansion failed: {0}")]
    Transcript(TranscriptErrorV1),
    /// Checked size arithmetic overflowed.
    #[error("Bootle/Lantern proof toolbox size arithmetic overflowed")]
    ArithmeticOverflow,
    /// A fixed internal invariant failed.
    #[error("Bootle/Lantern proof toolbox internal invariant failed")]
    InternalInvariant,
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_engines::bootle_lantern::transcript::{
        MatrixSeedV1, PresentationChallengeBindingV1, PresentationTranscriptV1,
    };
    fn projection_test_transcript() -> ProofTranscriptCoreV1 {
        let parameter_digest = [0x11; 32];
        PresentationTranscriptV1::new(
            PresentationChallengeBindingV1 {
                parameter_digest,
                genesis_hash: [0x22; 32],
                statement_digest: [0x33; 32],
                issuer_policy_record_digest: [0x44; 32],
                transaction_intent_digest: [0x55; 32],
            },
            MatrixSeedV1::new(parameter_digest, [0x66; 32]).expect("valid matrix seed"),
            [0x77; 32],
        )
        .expect("fully bound projection transcript")
        .proof_core()
    }
    #[test]
    fn projected_norm_witness_keeps_exact_order_and_zeroizing_heap_custody() {
        let short = ShortWitnessV1 {
            polynomials: boxed_polynomial_array_from_fn_v1(|row| {
                ProofPolynomialV1::from_centered_coefficients(core::array::from_fn(|column| {
                    i64::try_from(1 + row * APPLICATION_RING_DEGREE_V1 + column)
                        .expect("fixed witness geometry fits i64")
                }))
            }),
        };
        let mut projected = projected_norm_witness_v1(short.polynomials());
        // The return value carries one owner, never another by-value witness.
        assert_eq!(
            core::mem::size_of_val(&projected),
            core::mem::size_of::<usize>()
        );
        let expected_indices = (16..24)
            .chain(40..48)
            .chain(0..16)
            .chain(24..40)
            .chain([48, 49]);
        let mut checked = 0;
        for (actual, source) in projected.polynomials().iter().zip(expected_indices) {
            assert_eq!(*actual, short.polynomials()[source]);
            checked += 1;
        }
        assert_eq!(checked, 50);
        projected.zeroize();
        assert!(
            projected
                .polynomials()
                .iter()
                .all(ProofPolynomialV1::is_zero)
        );
        assert!(
            short
                .polynomials()
                .iter()
                .all(|polynomial| !polynomial.is_zero())
        );
    }
    #[test]
    fn fixed_constraint_layout_is_exact() {
        assert_eq!(S21_POLYNOMIALS_V1, 44);
        assert_eq!(PROJECTION_POLYNOMIALS_V1, 4);
        assert_eq!(QUADRATIC_MESSAGE_POLYNOMIALS_V1, 11);
        assert_eq!(EVALUATION_CONSTRAINTS_V1, 642);
        assert_eq!(Z3_PROJECTION_START_V1 + PROJECTION_COORDINATES_V1, 642);
        assert_eq!(
            MAX_PROJECTION_COLUMNS_V1,
            TBOX_M1_V1 * APPLICATION_RING_DEGREE_V1
        );
    }
    #[test]
    fn oversized_projection_is_rejected_before_arithmetic_allocation_or_transcript_work() {
        let transcript = projection_test_transcript();
        let expected =
            ToolboxErrorV1::Transcript(TranscriptErrorV1::FixedProfileCapacityExceeded {
                field: "ternary_columns",
            });
        // An empty stage would fail as soon as row derivation starts. Seeing
        // the capacity error for both values proves the whole-matrix preflight
        // runs first; `usize::MAX` also proves multiplication never executes.
        for columns in [
            MAX_PROJECTION_COLUMNS_V1 + 1,
            MAX_PROJECTION_COLUMNS_V1 * 2,
            usize::MAX,
        ] {
            assert_eq!(
                expand_projection_matrix_v1(&transcript, b"", &[], columns)
                    .expect_err("oversized projection must fail before expansion"),
                expected
            );
        }
        assert_eq!(
            expand_projection_matrix_v1(&transcript, b"projection", &[], 0),
            Err(ToolboxErrorV1::Transcript(
                TranscriptErrorV1::EmptyProjectionRow
            ))
        );
    }
    #[test]
    fn beta_extraction_is_exact_and_rejects_shape_noise() {
        for beta3_sign in [-1_i64, 1] {
            for beta4_sign in [-1_i64, 1] {
                let mut beta_coefficients = [0_i64; APPLICATION_RING_DEGREE_V1];
                beta_coefficients[0] = beta3_sign;
                beta_coefficients[APPLICATION_RING_DEGREE_V1 / 2] = beta4_sign;
                let beta = ProofPolynomialV1::from_centered_coefficients(beta_coefficients);
                let (beta3, beta4) = beta_polynomials_v1(beta).expect("fixed inverse");
                assert_eq!(beta3.centered_coefficient(0), beta3_sign);
                assert_eq!(beta4.centered_coefficient(0), beta4_sign);
                assert!(
                    beta3.coefficients()[1..]
                        .iter()
                        .all(|coefficient| *coefficient == 0)
                );
                assert!(
                    beta4.coefficients()[1..]
                        .iter()
                        .all(|coefficient| *coefficient == 0)
                );
            }
        }
        let mut noisy = [0_i64; APPLICATION_RING_DEGREE_V1];
        noisy[1] = 7;
        let (beta3, beta4) =
            beta_polynomials_v1(ProofPolynomialV1::from_centered_coefficients(noisy))
                .expect("fixed inverse");
        assert!(
            beta3.coefficients()[1..]
                .iter()
                .chain(&beta4.coefficients()[1..])
                .any(|coefficient| *coefficient != 0)
        );
    }
    #[test]
    fn binary_and_norm_equations_detect_adversarial_coefficients() {
        let binary = binary_expansion_polynomial(34_034_725);
        assert_eq!(binary_inner_product(&[binary]), 0);
        assert_eq!(
            norm_slack_equation(
                &[ProofPolynomialV1::constant(1).expect("one")],
                binary,
                34_034_726,
            ),
            0
        );
        let mut non_binary = [0_u64; APPLICATION_RING_DEGREE_V1];
        non_binary[17] = 2;
        let non_binary = ProofPolynomialV1::new(non_binary).expect("canonical");
        assert_ne!(binary_inner_product(&[non_binary]), 0);
    }
    #[test]
    fn sigma_trace_preserves_and_packs_exact_checked_coefficients() {
        let polynomial =
            ProofPolynomialV1::from_centered_coefficients(core::array::from_fn(|index| {
                i64::try_from(index).expect("ring index fits i64") * 17 - 411
            }));
        let other = ProofPolynomialV1::from_centered_coefficients(core::array::from_fn(|index| {
            701 - i64::try_from(index).expect("ring index fits i64") * 29
        }));
        let trace = trace_sigma_minus_one_v1(polynomial).expect("fixed inverse of two");
        let other_trace = trace_sigma_minus_one_v1(other).expect("fixed inverse of two");
        assert_eq!(trace, trace.automorphism());
        assert_eq!(trace.coefficients()[0], polynomial.coefficients()[0]);
        assert_eq!(trace.coefficients()[APPLICATION_RING_DEGREE_V1 / 2], 0);
        let packed = trace.add(other_trace.multiply_by_monomial(APPLICATION_RING_DEGREE_V1 / 2));
        assert_eq!(packed.coefficients()[0], polynomial.coefficients()[0]);
        assert_eq!(
            packed.coefficients()[APPLICATION_RING_DEGREE_V1 / 2],
            other.coefficients()[0]
        );
        let mut challenge_coefficients = [0_i64; APPLICATION_RING_DEGREE_V1];
        challenge_coefficients[0] = 1;
        challenge_coefficients[1] = 1;
        challenge_coefficients[APPLICATION_RING_DEGREE_V1 - 1] = -1;
        let challenge = ProofPolynomialV1::from_centered_coefficients(challenge_coefficients);
        assert_eq!(challenge, challenge.automorphism());
        assert_eq!(
            trace_sigma_minus_one_v1(challenge.multiply(polynomial)).expect("fixed inverse of two"),
            challenge.multiply(trace)
        );
        let non_stable = ProofPolynomialV1::constant(1)
            .expect("one")
            .multiply_by_monomial(1);
        assert_ne!(non_stable, non_stable.automorphism());
        assert_ne!(
            trace_sigma_minus_one_v1(non_stable.multiply(polynomial))
                .expect("fixed inverse of two"),
            non_stable.multiply(trace)
        );
    }
    #[test]
    fn scalar_packing_counterexample_is_repaired_by_sigma_lift() {
        fn split(
            q0: ProofPolynomialV1,
            positive: ProofPolynomialV1,
            negative: ProofPolynomialV1,
        ) -> (ProofPolynomialV1, ProofPolynomialV1) {
            let linear = positive
                .sub(negative)
                .scale_canonical(PROOF_INVERSE_TWO_V1)
                .expect("fixed inverse of two");
            let quadratic = positive
                .add(negative)
                .sub(q0.scale_centered(2))
                .scale_canonical(PROOF_INVERSE_TWO_V1)
                .expect("fixed inverse of two");
            (linear, quadratic)
        }
        let mut challenge_coefficients = [0_i64; APPLICATION_RING_DEGREE_V1];
        challenge_coefficients[0] = 1;
        challenge_coefficients[1] = 1;
        challenge_coefficients[APPLICATION_RING_DEGREE_V1 - 1] = -1;
        let challenge = ProofPolynomialV1::from_centered_coefficients(challenge_coefficients);
        assert_eq!(challenge, challenge.automorphism());
        let old_map = |polynomial| {
            polynomial_at_zero_and_half(binary_inner_product(&[polynomial]), 0)
                .expect("canonical scalar packing")
        };
        let old_q0 = old_map(ProofPolynomialV1::ZERO);
        let (old_linear, old_quadratic) =
            split(old_q0, old_map(challenge), old_map(challenge.negate()));
        let old_recovered = old_quadratic.add(challenge.multiply(old_linear));
        let mut expected = [0_i64; APPLICATION_RING_DEGREE_V1];
        expected[0] = 2;
        expected[1] = -1;
        expected[APPLICATION_RING_DEGREE_V1 - 1] = 1;
        assert_eq!(
            old_recovered,
            ProofPolynomialV1::from_centered_coefficients(expected)
        );
        assert!(!old_recovered.is_zero());
        let lifted_map = |polynomial| {
            trace_sigma_minus_one_v1(binary_relation_polynomial_v1(&[polynomial]))
                .expect("fixed inverse of two")
        };
        let secret = ProofPolynomialV1::constant(1).expect("one");
        let scaled_secret = challenge.multiply(secret);
        let lifted_q0 = lifted_map(ProofPolynomialV1::ZERO);
        let (secret_linear, secret_quadratic) =
            split(lifted_q0, lifted_map(secret), lifted_map(secret.negate()));
        let (scaled_linear, scaled_quadratic) = split(
            lifted_q0,
            lifted_map(scaled_secret),
            lifted_map(scaled_secret.negate()),
        );
        assert_eq!(scaled_linear, challenge.multiply(secret_linear));
        assert_eq!(
            scaled_quadratic,
            challenge.multiply(challenge).multiply(secret_quadratic)
        );
    }
    #[test]
    fn quadratic_black_box_decomposition_identity_holds() {
        // Q(x) = x^2 + 7x + 11, embedded as constant polynomials.
        fn q(x: ProofPolynomialV1) -> ProofPolynomialV1 {
            x.multiply(x)
                .add(x.scale_centered(7))
                .add(ProofPolynomialV1::constant(11).expect("constant"))
        }
        let x = ProofPolynomialV1::constant(19).expect("x");
        let zero = ProofPolynomialV1::ZERO;
        let q0 = q(zero);
        let q2 = q(x)
            .add(q(x.negate()))
            .sub(q0.scale_centered(2))
            .scale_canonical(PROOF_INVERSE_TWO_V1)
            .expect("inverse");
        let linear = q(x)
            .sub(q(x.negate()))
            .scale_canonical(PROOF_INVERSE_TWO_V1)
            .expect("inverse");
        assert_eq!(q2, x.multiply(x));
        assert_eq!(linear, x.scale_centered(7));
        assert_eq!(q(x), q2.add(linear).add(q0));
    }
}
