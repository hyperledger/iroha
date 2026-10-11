//! PIPA-v1 protocol tables shared by the prover and the verifier.
//!
//! Everything here is a pure function of a validated [`ProtocolDescriptor`]:
//!
//! - [`Shape`]: the counts of spec section 1 (`n`, `d`, `b`, `u`, the column,
//!   query, permutation-set and lookup counts, the instance mode and the
//!   proof suffix);
//! - [`Protocol`]: the shape plus the opening query list of spec section 9.1,
//!   its static [`OpeningPlan`], the rotation-0 query of every permutation
//!   column and the exact proof length of spec section 7;
//! - [`evaluate_expression`]: the explicit-stack evaluation of a postfix
//!   descriptor expression on query evaluations (the verifier's evaluator);
//! - [`lagrange_evaluations`] and [`instance_evaluation`]: Lagrange basis
//!   values at the challenge `x`;
//! - [`check_zero_knowledge_budget`]: the S7 zero-knowledge budget computed
//!   from the opening plan itself, independently of descriptor rule 9;
//! - [`Protocol::constraint_terms`] and [`Protocol::transcript_schedule`]
//!   ([`schedule`]): the constraint fold and the transcript schedule as data,
//!   which every verifier (native and in-circuit) walks (S11).
//!
//! The prover and the verifier derive the proof layout, the opening queries
//! and their grouping from these tables only, so the two sides cannot drift
//! apart. Nothing here reads `configure()`: the descriptor is what is hashed
//! and what is evaluated (spec section 4).

use core::fmt;

use ff::{Field, PrimeField};
use iroha_pasta::{PastaCurve, PastaField, msm::MemoryBudget};

use crate::{
    cs::{
        DescriptorSource, InstanceModeV1, ProofSuffixV1, ProtocolDescriptor,
        descriptor::{ColumnKindV1, ExprNodeV1, MAX_EXPRESSION_STACK},
    },
    pcs::{
        ipa::{PinnedParams, commit::Msm},
        multiopen::{MultiopenError, OpeningPlan, OpeningQuery, Slot, SlotKind},
    },
    transcript::{MESSAGE_BYTES, decode_scalar},
};

pub mod schedule;

pub(crate) use schedule::{AllTerms, ConstraintFilter};
pub use schedule::{
    Challenge, CommonInput, ConstraintTerm, HashOperation, LookupAt, LookupConstraint,
    PermutationAt, ProofMessage, RoundSide, TranscriptStep,
};

/// A protocol table could not be derived from a descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    /// A size computation overflowed or a count does not fit its type.
    Overflow,
    /// A permutation column has no rotation-0 query (descriptor rule 7).
    PermutationQuery {
        /// The index of the permutation column in equality order.
        column: usize,
    },
    /// The opening plan could not be built.
    Plan(MultiopenError),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Overflow => f.write_str("a protocol size computation overflowed"),
            Self::PermutationQuery { column } => {
                write!(f, "permutation column {column} has no rotation-0 query")
            }
            Self::Plan(error) => write!(f, "opening plan: {error}"),
        }
    }
}

impl std::error::Error for ProtocolError {}

impl From<MultiopenError> for ProtocolError {
    fn from(error: MultiopenError) -> Self {
        Self::Plan(error)
    }
}

/// The counts of spec section 1 for one descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Shape {
    /// `log2(n)`.
    pub k: u32,
    /// The domain size `n = 2^k`.
    pub n: usize,
    /// The circuit degree `d`.
    pub degree: usize,
    /// The blinding factors `b`.
    pub blinding_factors: usize,
    /// The usable rows `u = n - b - 1`; row `u` is `l_last`.
    pub usable_rows: usize,
    /// Columns per permutation set, `d - 2`.
    pub chunk_len: usize,
    /// Quotient pieces, `d - 1`.
    pub quotient_pieces: usize,
    /// Fixed columns (selector columns included).
    pub num_fixed: usize,
    /// Advice columns `n_a`.
    pub num_advice: usize,
    /// Instance columns.
    pub num_instance: usize,
    /// Fixed queries `q_f`.
    pub fixed_queries: usize,
    /// Advice queries `q_a`.
    pub advice_queries: usize,
    /// Instance queries `q_i`.
    pub instance_queries: usize,
    /// Equality columns `m`.
    pub permutation_columns: usize,
    /// Permutation sets `n_z = ceil(m / (d - 2))`.
    pub permutation_sets: usize,
    /// Lookups `n_l`.
    pub lookups: usize,
    /// Whether instance columns are committed and opened.
    pub committed_instances: bool,
    /// Whether the proof ends with the folded generator `G'_0`.
    pub folded_generator_suffix: bool,
}

impl Shape {
    /// The shape of `descriptor`.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Overflow`] when `k`, `d` or `b` are outside the
    /// ranges a validated descriptor guarantees.
    pub fn new(source: &impl DescriptorSource) -> Result<Self, ProtocolError> {
        let normalized = source.protocol_descriptor();
        let descriptor = normalized.as_ref();
        let k = u32::from(descriptor.k);
        if !(1..=crate::cs::constraint_system::MAX_K).contains(&k) {
            return Err(ProtocolError::Overflow);
        }
        let n = 1_usize.checked_shl(k).ok_or(ProtocolError::Overflow)?;
        let degree = usize::from(descriptor.degree);
        let blinding_factors = usize::from(descriptor.blinding_factors);
        let usable_rows = n
            .checked_sub(blinding_factors)
            .and_then(|rows| rows.checked_sub(1))
            .ok_or(ProtocolError::Overflow)?;
        let chunk_len = degree.checked_sub(2).filter(|chunk| *chunk >= 1);
        let chunk_len = chunk_len.ok_or(ProtocolError::Overflow)?;
        let quotient_pieces = degree.checked_sub(1).ok_or(ProtocolError::Overflow)?;
        let permutation_columns = descriptor.permutation.len();
        Ok(Self {
            k,
            n,
            degree,
            blinding_factors,
            usable_rows,
            chunk_len,
            quotient_pieces,
            num_fixed: usize::try_from(descriptor.num_fixed_columns)
                .map_err(|_| ProtocolError::Overflow)?,
            num_advice: usize::try_from(descriptor.num_advice_columns)
                .map_err(|_| ProtocolError::Overflow)?,
            num_instance: descriptor.instance_lengths.len(),
            fixed_queries: descriptor.fixed_queries.len(),
            advice_queries: descriptor.advice_queries.len(),
            instance_queries: descriptor.instance_queries.len(),
            permutation_columns,
            permutation_sets: permutation_columns.div_ceil(chunk_len),
            lookups: descriptor.lookups.len(),
            committed_instances: descriptor.instance_mode == InstanceModeV1::Committed,
            folded_generator_suffix: descriptor.proof_suffix == ProofSuffixV1::FoldedGenerator,
        })
    }

    /// The rotation `-(b + 1)` that links consecutive permutation sets.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Overflow`] when `b + 1` does not fit `i32`.
    pub fn last_rotation(&self) -> Result<i32, ProtocolError> {
        let b = i32::try_from(self.blinding_factors).map_err(|_| ProtocolError::Overflow)?;
        b.checked_add(1)
            .map(|value| -value)
            .ok_or(ProtocolError::Overflow)
    }

    /// The number of proof messages that are points.
    fn point_messages(&self) -> Option<usize> {
        // n_a + 3 n_l + n_z + d + 2 + 2k + [suffix]
        let k = usize::try_from(self.k).ok()?;
        self.num_advice
            .checked_add(self.lookups.checked_mul(3)?)?
            .checked_add(self.permutation_sets)?
            .checked_add(self.degree)?
            .checked_add(2)?
            .checked_add(k.checked_mul(2)?)?
            .checked_add(usize::from(self.folded_generator_suffix))
    }

    /// The number of proof messages that are scalars, for `point_sets`
    /// opening point sets.
    fn scalar_messages(&self, point_sets: usize) -> Option<usize> {
        // [Committed] q_i + q_a + q_f + 1 + m + max(3 n_z - 1, 0) + 5 n_l + n_s + 2
        let instance = if self.committed_instances {
            self.instance_queries
        } else {
            0
        };
        instance
            .checked_add(self.advice_queries)?
            .checked_add(self.fixed_queries)?
            .checked_add(1)?
            .checked_add(self.permutation_columns)?
            .checked_add(self.permutation_sets.checked_mul(3)?.saturating_sub(1))?
            .checked_add(self.lookups.checked_mul(5)?)?
            .checked_add(point_sets)?
            .checked_add(2)
    }
}

/// How a permutation column is read: its kind, its index and the index of
/// its rotation-0 query in the query table of its kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PermutationColumn {
    /// The column kind.
    pub kind: ColumnKindV1,
    /// The column index within its kind.
    pub column: usize,
    /// The index of `(column, 0)` in the query table of its kind.
    pub query: usize,
}

/// The protocol tables of one descriptor (see the module documentation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Protocol {
    shape: Shape,
    queries: Vec<OpeningQuery>,
    plan: OpeningPlan,
    permutation: Vec<PermutationColumn>,
    proof_length: usize,
    constraint_terms: Vec<ConstraintTerm>,
    schedule: Vec<TranscriptStep>,
}

/// A count as a slot index.
fn slot_index(index: usize) -> Result<u32, ProtocolError> {
    u32::try_from(index).map_err(|_| ProtocolError::Overflow)
}

impl Protocol {
    /// Derives the tables of a validated descriptor.
    ///
    /// # Errors
    ///
    /// [`ProtocolError`] when the descriptor breaks an invariant that
    /// validation guarantees (a missing rotation-0 query, an overflow).
    pub fn new(source: &impl DescriptorSource) -> Result<Self, ProtocolError> {
        let normalized = source.protocol_descriptor();
        let descriptor = normalized.as_ref();
        let shape = Shape::new(descriptor)?;
        let queries = opening_queries(descriptor, &shape)?;
        let plan = OpeningPlan::new(&queries)?;
        let permutation = descriptor
            .permutation
            .iter()
            .enumerate()
            .map(|(position, column)| {
                let table = match column.kind {
                    ColumnKindV1::Advice => &descriptor.advice_queries,
                    ColumnKindV1::Fixed => &descriptor.fixed_queries,
                    ColumnKindV1::Instance => &descriptor.instance_queries,
                };
                let query = table
                    .iter()
                    .position(|query| query.column == column.index && query.rotation == 0)
                    .ok_or(ProtocolError::PermutationQuery { column: position })?;
                Ok(PermutationColumn {
                    kind: column.kind,
                    column: usize::try_from(column.index).map_err(|_| ProtocolError::Overflow)?,
                    query,
                })
            })
            .collect::<Result<Vec<_>, ProtocolError>>()?;
        let messages = shape
            .point_messages()
            .and_then(|points| points.checked_add(shape.scalar_messages(plan.sets().len())?))
            .ok_or(ProtocolError::Overflow)?;
        let proof_length = messages
            .checked_mul(MESSAGE_BYTES)
            .ok_or(ProtocolError::Overflow)?;
        let constraint_terms = schedule::constraint_terms(descriptor, &shape)?;
        let schedule = schedule::transcript_schedule(descriptor, &shape, plan.sets().len());
        Ok(Self {
            shape,
            queries,
            plan,
            permutation,
            proof_length,
            constraint_terms,
            schedule,
        })
    }

    /// The shape.
    #[must_use]
    pub fn shape(&self) -> &Shape {
        &self.shape
    }

    /// The opening queries in spec 9.1 order.
    #[must_use]
    pub fn queries(&self) -> &[OpeningQuery] {
        &self.queries
    }

    /// The static grouping of the opening queries.
    #[must_use]
    pub fn plan(&self) -> &OpeningPlan {
        &self.plan
    }

    /// Every permutation column with its rotation-0 query, in equality order.
    #[must_use]
    pub fn permutation_columns(&self) -> &[PermutationColumn] {
        &self.permutation
    }

    /// The exact proof length in bytes (spec section 7).
    #[must_use]
    pub fn proof_length(&self) -> usize {
        self.proof_length
    }

    /// The constraints in fold order (spec section 2): gate polynomials, the
    /// permutation items 1-4, then the five constraints of every lookup. The
    /// verifier folds exactly this list (S11).
    #[must_use]
    pub fn constraint_terms(&self) -> &[ConstraintTerm] {
        &self.constraint_terms
    }

    /// Every absorb, message and squeeze of a production proof in order
    /// (spec sections 6.3 and 7), the unabsorbed suffix included (S11).
    #[must_use]
    pub fn transcript_schedule(&self) -> &[TranscriptStep] {
        &self.schedule
    }
}

/// The opening queries of spec section 9.1, in order.
fn opening_queries(
    descriptor: &ProtocolDescriptor,
    shape: &Shape,
) -> Result<Vec<OpeningQuery>, ProtocolError> {
    let mut queries = Vec::new();
    let slot = |kind, index: usize| slot_index(index).map(|index| Slot::new(kind, index));
    if shape.committed_instances {
        for query in &descriptor.instance_queries {
            queries.push(OpeningQuery::new(
                Slot::new(SlotKind::Instance, query.column),
                query.rotation,
            ));
        }
    }
    for query in &descriptor.advice_queries {
        queries.push(OpeningQuery::new(
            Slot::new(SlotKind::Advice, query.column),
            query.rotation,
        ));
    }
    for set in 0..shape.permutation_sets {
        let product = slot(SlotKind::PermutationProduct, set)?;
        queries.push(OpeningQuery::new(product, 0));
        queries.push(OpeningQuery::new(product, 1));
    }
    let last = shape.last_rotation()?;
    for set in (0..shape.permutation_sets.saturating_sub(1)).rev() {
        queries.push(OpeningQuery::new(
            slot(SlotKind::PermutationProduct, set)?,
            last,
        ));
    }
    for lookup in 0..shape.lookups {
        let product = slot(SlotKind::LookupProduct, lookup)?;
        let input = slot(SlotKind::LookupPermutedInput, lookup)?;
        let table = slot(SlotKind::LookupPermutedTable, lookup)?;
        queries.push(OpeningQuery::new(product, 0));
        queries.push(OpeningQuery::new(input, 0));
        queries.push(OpeningQuery::new(table, 0));
        queries.push(OpeningQuery::new(input, -1));
        queries.push(OpeningQuery::new(product, 1));
    }
    for query in &descriptor.fixed_queries {
        queries.push(OpeningQuery::new(
            Slot::new(SlotKind::Fixed, query.column),
            query.rotation,
        ));
    }
    for column in 0..shape.permutation_columns {
        queries.push(OpeningQuery::new(
            slot(SlotKind::PermutationSigma, column)?,
            0,
        ));
    }
    queries.push(OpeningQuery::new(Slot::new(SlotKind::Vanishing, 0), 0));
    queries.push(OpeningQuery::new(Slot::new(SlotKind::Random, 0), 0));
    Ok(queries)
}

/// The generator `omega = ROOT_OF_UNITY^(2^(S - k))` of the size-`2^k`
/// subgroup, or `None` for `k > S`.
#[must_use]
pub fn omega<F: PrimeField>(k: u32) -> Option<F> {
    if k > F::S {
        return None;
    }
    let mut omega = F::ROOT_OF_UNITY;
    for _ in k..F::S {
        omega = omega.square();
    }
    Some(omega)
}

/// `x * omega^rotation`.
#[must_use]
pub fn rotate<F: Field>(x: F, omega: F, omega_inv: F, rotation: i32) -> F {
    let base = if rotation >= 0 { omega } else { omega_inv };
    x * base.pow_vartime([u64::from(rotation.unsigned_abs())])
}

/// `l_i(x) = omega^i (x^n - 1) / (n (x - omega^i))` for every `i` in
/// `indices` (each below `n`), with `xn = x^n`.
///
/// Returns `None` when `x` lies in the subgroup (then `x^n = 1` and the
/// formula is undefined); the verifier rejects such an `x` before calling.
#[must_use]
pub fn lagrange_evaluations<F: PastaField>(
    x: F,
    xn: F,
    k: u32,
    indices: &[usize],
) -> Option<Vec<F>> {
    let omega = omega::<F>(k)?;
    let n_inv = F::TWO_INV.pow_vartime([u64::from(k)]);
    let common = (xn - F::ONE) * n_inv;
    let powers: Vec<F> = indices
        .iter()
        .map(|index| omega.pow_vartime([u64::try_from(*index).unwrap_or(u64::MAX)]))
        .collect();
    let mut denominators: Vec<F> = powers.iter().map(|power| x - power).collect();
    if denominators
        .iter()
        .any(|denominator| bool::from(denominator.is_zero()))
    {
        return None;
    }
    iroha_pasta::field::batch_invert_vartime(&mut denominators);
    Some(
        powers
            .iter()
            .zip(&denominators)
            .map(|(power, inverse)| *power * common * inverse)
            .collect(),
    )
}

/// The Direct-mode instance evaluation `I(omega^r x) = sum_j v_j l_{j-r}(x)`
/// (indices modulo `n`, spec 6.3) of the zero-padded column `values`.
///
/// Returns `None` when `x` lies in the subgroup.
#[must_use]
pub fn instance_evaluation<F: PastaField>(
    values: &[F],
    rotation: i32,
    x: F,
    xn: F,
    k: u32,
) -> Option<F> {
    let n = i64::try_from(1_u64.checked_shl(k)?).ok()?;
    let indices: Vec<usize> = (0..values.len())
        .map(|j| {
            let index = i64::try_from(j).ok()?.checked_sub(i64::from(rotation))?;
            usize::try_from(index.rem_euclid(n)).ok()
        })
        .collect::<Option<Vec<_>>>()?;
    let basis = lagrange_evaluations(x, xn, k, &indices)?;
    Some(
        values
            .iter()
            .zip(&basis)
            .fold(F::ZERO, |acc, (value, l)| acc + *value * l),
    )
}

/// The instance commitment `sum_i v_i g_lagrange[i] + W` of a column whose
/// first values are `values` and whose remaining rows are zero (spec 6.3,
/// Committed mode). Public data: the MSM falls back to a slower path rather
/// than failing for lack of memory (S10).
#[must_use]
pub fn instance_commitment<C: PastaCurve>(
    params: &PinnedParams<C>,
    values: &[C::ScalarExt],
    budget: MemoryBudget,
) -> C::AffineExt {
    instance_commitment_cancellable(params, values, budget, None).expect("no cancellation signal")
}
/// The same public instance commitment with an explicit operation signal.
/// # Errors
/// Cancellation after complete-kernel workers join; no partial commitment escapes.
pub fn instance_commitment_cancellable<C: PastaCurve>(
    params: &PinnedParams<C>,
    values: &[C::ScalarExt],
    budget: MemoryBudget,
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> Result<C::AffineExt, iroha_pasta::Cancelled> {
    iroha_pasta::CancellationToken::checkpoint(cancellation)?;
    let p = params.params();
    let mut msm = Msm::<C>::new();
    for (index, (value, base)) in values.iter().zip(p.g_lagrange()).enumerate() {
        if index % 1024 == 0 {
            iroha_pasta::CancellationToken::checkpoint(cancellation)?;
        }
        msm.push(*value, *base);
    }
    msm.push(C::ScalarExt::ONE, p.w());
    Ok(msm.evaluate_cancellable(budget, cancellation)?.to_affine())
}

/// Evaluates a postfix descriptor expression on query evaluations with an
/// explicit stack (spec section 4). `fixed`, `advice` and `instance` are
/// indexed by query index.
///
/// Returns `None` for a malformed expression: an index out of range, a
/// non-canonical constant, a stack underflow, a stack deeper than
/// [`MAX_EXPRESSION_STACK`] or a result other than exactly one value.
/// Validated descriptors never produce `None`.
#[must_use]
pub fn evaluate_expression<F: PastaField>(
    expression: &[ExprNodeV1],
    fixed: &[F],
    advice: &[F],
    instance: &[F],
) -> Option<F> {
    let mut stack: Vec<F> = Vec::new();
    for node in expression {
        match node {
            ExprNodeV1::Constant(bytes) => stack.push(decode_scalar::<F>(bytes).ok()?),
            ExprNodeV1::Fixed(index) => stack.push(*fixed.get(usize::try_from(*index).ok()?)?),
            ExprNodeV1::Advice(index) => stack.push(*advice.get(usize::try_from(*index).ok()?)?),
            ExprNodeV1::Instance(index) => {
                stack.push(*instance.get(usize::try_from(*index).ok()?)?);
            }
            ExprNodeV1::Negated => {
                let value = stack.pop()?;
                stack.push(-value);
            }
            ExprNodeV1::Scaled(bytes) => {
                let factor = decode_scalar::<F>(bytes).ok()?;
                let value = stack.pop()?;
                stack.push(value * factor);
            }
            ExprNodeV1::Sum | ExprNodeV1::Product => {
                let right = stack.pop()?;
                let left = stack.pop()?;
                stack.push(if matches!(node, ExprNodeV1::Sum) {
                    left + right
                } else {
                    left * right
                });
            }
        }
        if stack.len() > MAX_EXPRESSION_STACK {
            return None;
        }
    }
    match stack.as_slice() {
        [value] => Some(*value),
        _ => None,
    }
}

/// A witness polynomial whose openings exceed the S7 zero-knowledge budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ZeroKnowledgeViolation {
    /// The witness polynomial.
    pub slot: Slot,
    /// Distinct evaluation points it reveals, `x_3` included.
    pub revealed: usize,
    /// The budget `b - 1`.
    pub budget: usize,
}

impl fmt::Display for ZeroKnowledgeViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} {} reveals {} evaluations, above the zero-knowledge budget {}",
            self.slot.kind, self.slot.index, self.revealed, self.budget
        )
    }
}

impl std::error::Error for ZeroKnowledgeViolation {}

/// Whether a slot holds a witness polynomial (blinded with `b` random rows).
const fn is_witness_slot(kind: SlotKind) -> bool {
    matches!(
        kind,
        SlotKind::Advice
            | SlotKind::LookupPermutedInput
            | SlotKind::LookupPermutedTable
            | SlotKind::LookupProduct
            | SlotKind::PermutationProduct
    )
}

/// The S7 zero-knowledge budget (spec section 12), computed from the opening
/// plan the prover actually runs: every witness polynomial reveals at most
/// `b - 1` evaluations, counting its distinct opening points plus one for the
/// multiopen point `x_3`.
///
/// Descriptor rule 9 checks the same bound from the query tables; this
/// derivation from the opening plan is an independent cross-check.
///
/// # Errors
///
/// The first [`ZeroKnowledgeViolation`] in plan order.
pub fn check_zero_knowledge_budget(protocol: &Protocol) -> Result<(), ZeroKnowledgeViolation> {
    let budget = protocol.shape.blinding_factors.saturating_sub(1);
    for slot in protocol.plan.slots() {
        if !is_witness_slot(slot.slot.kind) {
            continue;
        }
        let revealed = slot.points.len().saturating_add(1);
        if revealed > budget {
            return Err(ZeroKnowledgeViolation {
                slot: slot.slot,
                revealed,
                budget,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use iroha_pasta::{Fp, Fq};

    use super::*;

    fn expression_constant(value: u64) -> ExprNodeV1 {
        ExprNodeV1::Constant(Fp::from(value).to_repr())
    }

    #[test]
    fn postfix_evaluation_uses_an_explicit_stack() {
        let fixed = [Fp::from(2)];
        let advice = [Fp::from(3), Fp::from(5)];
        let instance = [Fp::from(7)];
        // (a0 * a1 + f0) * 4 - i0 = (15 + 2) * 4 - 7 = 61
        let expression = [
            ExprNodeV1::Advice(0),
            ExprNodeV1::Advice(1),
            ExprNodeV1::Product,
            ExprNodeV1::Fixed(0),
            ExprNodeV1::Sum,
            ExprNodeV1::Scaled(Fp::from(4).to_repr()),
            ExprNodeV1::Instance(0),
            ExprNodeV1::Negated,
            ExprNodeV1::Sum,
        ];
        assert_eq!(
            evaluate_expression(&expression, &fixed, &advice, &instance),
            Some(Fp::from(61))
        );
        assert_eq!(
            evaluate_expression(&[expression_constant(9)], &fixed, &advice, &instance),
            Some(Fp::from(9))
        );
        // Malformed: underflow, two results, an index out of range, a
        // non-canonical constant.
        for malformed in [
            vec![ExprNodeV1::Sum],
            vec![expression_constant(1), expression_constant(2)],
            vec![ExprNodeV1::Advice(2)],
            vec![ExprNodeV1::Constant([0xff; 32])],
            vec![],
        ] {
            assert_eq!(
                evaluate_expression(&malformed, &fixed, &advice, &instance),
                None
            );
        }
        let deep: Vec<ExprNodeV1> = (0..=MAX_EXPRESSION_STACK as u64)
            .map(expression_constant)
            .collect();
        assert_eq!(evaluate_expression(&deep, &fixed, &advice, &instance), None);
    }

    #[test]
    fn lagrange_basis_values_interpolate() {
        let k = 3;
        let n = 8;
        let x = Fq::from(1234);
        let xn = x.pow_vartime([n as u64]);
        let indices: Vec<usize> = (0..n).collect();
        let basis = lagrange_evaluations(x, xn, k, &indices).expect("x outside H");
        // sum_i l_i(x) = 1 and sum_i omega^i l_i(x) = x.
        assert_eq!(basis.iter().fold(Fq::ZERO, |acc, l| acc + l), Fq::ONE);
        let generator = omega::<Fq>(k).expect("omega");
        let weighted = basis.iter().enumerate().fold(Fq::ZERO, |acc, (i, l)| {
            acc + generator.pow_vartime([i as u64]) * l
        });
        assert_eq!(weighted, x);
        // x in the subgroup has no Lagrange values.
        assert_eq!(lagrange_evaluations(generator, Fq::ONE, k, &indices), None);
        assert_eq!(omega::<Fq>(33), None);
        let inverse = generator.invert().expect("nonzero");
        assert_eq!(rotate(x, generator, inverse, -2) * generator.square(), x);
        assert_eq!(rotate(x, generator, inverse, 3), x * generator.cube());
    }

    #[test]
    fn instance_evaluation_matches_the_interpolated_polynomial() {
        let k = 4;
        let n = 16_usize;
        let values = [Fp::from(3), Fp::from(9), Fp::from(27)];
        let mut padded = values.to_vec();
        padded.resize(n, Fp::ZERO);
        let domain = iroha_pasta::fft::FftDomain::<Fp>::new(k).expect("domain");
        domain.ifft(&mut padded).expect("ifft");
        let x = Fp::from(77);
        let xn = x.pow_vartime([n as u64]);
        let omega = domain.omega();
        for rotation in [-3, -1, 0, 1, 5] {
            let point = rotate(x, omega, domain.omega_inv(), rotation);
            assert_eq!(
                instance_evaluation(&values, rotation, x, xn, k),
                Some(crate::pcs::ipa::evaluate_polynomial(&padded, point)),
                "rotation {rotation}"
            );
        }
    }

    #[test]
    fn errors_and_budget_display() {
        assert!(
            ProtocolError::PermutationQuery { column: 2 }
                .to_string()
                .contains('2')
        );
        assert!(ProtocolError::Overflow.to_string().contains("overflow"));
        let violation = ZeroKnowledgeViolation {
            slot: Slot::new(SlotKind::Advice, 1),
            revealed: 5,
            budget: 4,
        };
        assert!(violation.to_string().contains("budget 4"));
        assert_eq!(
            ProtocolError::from(MultiopenError::NoQueries),
            ProtocolError::Plan(MultiopenError::NoQueries)
        );
        assert!(is_witness_slot(SlotKind::Advice));
        assert!(!is_witness_slot(SlotKind::Fixed));
    }
}
