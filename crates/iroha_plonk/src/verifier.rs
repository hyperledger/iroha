//! The PIPA-v1 verifier (task T13, spec sections 6-9 and 11).
//!
//! Verification depends only on `(D, VK bytes, params, instances, proof)`:
//! the descriptor `D` is decoded and validated, never rebuilt from
//! `configure()`, and its postfix expressions are what the verifier
//! evaluates (hash what you verify). The checklist of spec section 8:
//!
//! 1. the descriptor is validated ([`DescriptorBinding`]), the verifying key
//!    is decoded strictly against it and must be bound to its digest, and the
//!    parameters must be [`PinnedParams`] of the descriptor's curve and `k`
//!    (S5: derived, or bytes matching the pinned digest);
//! 2. `transcript_repr` comes from the descriptor digest and the VK bytes; the
//!    instance column count and every length must equal the descriptor's in
//!    both instance modes (S4); the proof must have exactly the length the
//!    descriptor implies, so trailing bytes are rejected before any message is
//!    read;
//! 3. the prelude absorbs `transcript_repr` and the instance frame, then the
//!    instances (committed, or absorbed by value); every message is decoded
//!    canonically (no reduction, on-curve, never the identity);
//! 4. `x = 0` and `x^n = 1` are rejected as [`VerifyError::DegenerateChallenge`];
//! 5. Direct-mode instance evaluations are computed from the values, the masks
//!    `l_first`, `l_last`, `l_blind` from `x`;
//! 6. the constraints are folded with `y` in the spec section 2 order into
//!    the expected `h(x)`;
//! 7. the multiopen groups queries statically by slot (S1), rejects a
//!    repeated query with a different evaluation (S3) and an `x_3` that
//!    equals an opening point;
//! 8. the IPA rejects a zero round challenge;
//! 9. [`verify_full`] accepts iff the opening equation holds with
//!    `G'_0 = <s(u), g>` (a `FoldedGenerator` suffix must equal it);
//!    [`accumulate_succinct`] checks it with the suffix in place of `G'_0` and
//!    returns a `#[must_use]` [`PendingAccumulator`], which only `decide` or
//!    `batch_decide` accept. Its `Ok` is satisfiable for false statements
//!    until the accumulator is decided, so it is never a verdict.
//!
//! Every failure is a typed [`VerifyError`]; the verifier never panics. A
//! memory budget only slows public MSMs down; it never rejects (S10).

use core::fmt;

use ff::Field;
use iroha_pasta::{PastaCurve, PastaField, msm::MemoryBudget, poseidon::PoseidonField};

use crate::{
    cs::{
        DescriptorError, DescriptorRule, ProofSuffixV1, ProtocolDescriptor,
        descriptor::ColumnKindV1,
    },
    keys::{DescriptorBinding, VerifyingKey, VkError},
    pcs::{
        ipa::{
            IpaError, PinnedParams,
            accumulator::{
                BATCH_KIND_ACCUMULATOR, BATCH_KIND_PROOF, PendingAccumulator, batch_item_digest,
                batch_weights, proof_item_body,
            },
            commit::Msm,
            fold_scalars,
            verifier::PendingOpening,
        },
        multiopen::{MultiopenError, SlotKind, verifier::verify as verify_opening},
    },
    protocol::{
        AllTerms, ConstraintFilter, ConstraintTerm, LookupConstraint, PermutationColumn, Protocol,
        ProtocolError, evaluate_expression, instance_evaluation, lagrange_evaluations,
    },
    transcript::{
        DescriptorHash, Transcript, TranscriptError, TranscriptRead, TranscriptReader,
        TranscriptRepr, absorb_prelude, absorb_prelude_v2,
    },
};

/// Why a proof was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The caller cancelled verification; no proof verdict was produced.
    Cancelled,
    /// The descriptor frame failed admission decoding or validation.
    Descriptor(DescriptorError),
    /// The verifying key failed strict decoding against the descriptor.
    VerifyingKey(VkError),
    /// The verifying key is bound to another descriptor.
    KeyMismatch,
    /// The parameters are not the pinned parameters of the descriptor's curve
    /// and `k`.
    ParamsMismatch,
    /// The number of instance columns differs from the descriptor (S4).
    /// An instance value is outside its declared integer type.
    InstanceType {
        /// Instance column.
        column: usize,
        /// Row within the column.
        row: usize,
    },
    /// Incorrect instance-column count.
    InstanceColumns {
        /// The descriptor's count.
        expected: usize,
        /// The supplied count.
        found: usize,
    },
    /// An instance column does not have its exact declared length (S4).
    InstanceLength {
        /// The column.
        column: usize,
        /// The declared length.
        expected: usize,
        /// The supplied length.
        found: usize,
    },
    /// The proof does not have the exact length the descriptor implies
    /// (trailing bytes included).
    ProofLength {
        /// The required length.
        expected: usize,
        /// The supplied length.
        actual: usize,
    },
    /// A proof message failed canonical decoding (non-canonical scalar,
    /// invalid point, identity point, truncation, trailing bytes).
    Transcript(TranscriptError),
    /// A verifier-computed instance commitment is the identity.
    IdentityInstanceCommitment {
        /// The instance column.
        column: usize,
    },
    /// `x = 0` or `x^n = 1`.
    DegenerateChallenge,
    /// The multiopen rejected (conflicting repeated evaluations, a
    /// degenerate `x_3`, a shape mismatch).
    Multiopen(MultiopenError),
    /// The inner-product argument rejected (zero round challenge, failed
    /// opening equation, folded-generator mismatch).
    Ipa(IpaError),
    /// Succinct verification needs a `FoldedGenerator` proof suffix.
    SuffixRequired,
    /// The protocol tables could not be derived from the descriptor.
    Protocol(ProtocolError),
    /// An item of a batch was rejected before the batch equation.
    BatchItem {
        /// The item index.
        index: usize,
        /// Why it was rejected.
        error: Box<VerifyError>,
    },
    /// The weighted batch equation does not hold.
    BatchRejected,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => f.write_str("verification cancelled"),
            Self::InstanceType { column, row } => {
                write!(f, "instance ({column}, {row}) is outside its declared type")
            }
            Self::Descriptor(error) => write!(f, "descriptor: {error}"),
            Self::VerifyingKey(error) => write!(f, "verifying key: {error}"),
            Self::KeyMismatch => f.write_str("the verifying key is bound to another descriptor"),
            Self::ParamsMismatch => f.write_str("the parameters do not match the descriptor"),
            Self::InstanceColumns { expected, found } => {
                write!(f, "{found} instance columns supplied, {expected} declared")
            }
            Self::InstanceLength {
                column,
                expected,
                found,
            } => write!(
                f,
                "instance column {column} has {found} values, {expected} declared"
            ),
            Self::ProofLength { expected, actual } => {
                write!(f, "proof has {actual} bytes, expected {expected}")
            }
            Self::Transcript(error) => write!(f, "proof encoding: {error}"),
            Self::IdentityInstanceCommitment { column } => {
                write!(f, "instance column {column} commits to the identity")
            }
            Self::DegenerateChallenge => f.write_str("the challenge x is degenerate"),
            Self::Multiopen(error) => write!(f, "multiopen: {error}"),
            Self::Ipa(error) => write!(f, "IPA: {error}"),
            Self::SuffixRequired => {
                f.write_str("succinct verification needs a FoldedGenerator suffix")
            }
            Self::Protocol(error) => write!(f, "protocol: {error}"),
            Self::BatchItem { index, error } => write!(f, "batch item {index}: {error}"),
            Self::BatchRejected => f.write_str("the batch equation does not hold"),
        }
    }
}

impl std::error::Error for VerifyError {}
impl From<iroha_pasta::Cancelled> for VerifyError {
    fn from(_: iroha_pasta::Cancelled) -> Self {
        Self::Cancelled
    }
}
impl VerifyError {
    /// Whether this is cancellation rather than an incoming proof failure.
    pub fn is_cancelled(&self) -> bool {
        match self {
            Self::Cancelled => true,
            Self::Ipa(error) => error.is_cancelled(),
            Self::Multiopen(error) => error.is_cancelled(),
            Self::BatchItem { error, .. } => error.is_cancelled(),
            _ => false,
        }
    }
}

impl From<DescriptorError> for VerifyError {
    fn from(error: DescriptorError) -> Self {
        Self::Descriptor(error)
    }
}

impl From<VkError> for VerifyError {
    fn from(error: VkError) -> Self {
        Self::VerifyingKey(error)
    }
}

impl From<TranscriptError> for VerifyError {
    fn from(error: TranscriptError) -> Self {
        Self::Transcript(error)
    }
}

impl From<IpaError> for VerifyError {
    fn from(error: IpaError) -> Self {
        match error {
            IpaError::Cancelled => Self::Cancelled,
            IpaError::Transcript(error) => Self::Transcript(error),
            other => Self::Ipa(other),
        }
    }
}

impl From<MultiopenError> for VerifyError {
    fn from(error: MultiopenError) -> Self {
        match error {
            MultiopenError::Cancelled => Self::Cancelled,
            MultiopenError::Ipa(error) => error.into(),
            other => Self::Multiopen(other),
        }
    }
}

impl From<ProtocolError> for VerifyError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

/// How the transcript is primed (production, or oracle mode with the
/// vendored `transcript_repr`, spec 6.4).
#[derive(Clone, Copy, Debug)]
struct Mode<C: PastaCurve> {
    oracle: bool,
    transcript_repr: TranscriptRepr<C>,
}

/// A read proof: the pending IPA opening and the optional suffix.
struct ReadProof<C: PastaCurve> {
    pending: PendingOpening<C>,
    suffix: Option<C::AffineExt>,
    #[cfg(test)]
    challenges: Vec<C::ScalarExt>,
}

/// Checks the instance shape against the descriptor (S4).
fn check_instances<F: PastaField>(
    descriptor: &ProtocolDescriptor,
    instances: &[Vec<F>],
) -> Result<(), VerifyError> {
    if instances.len() != descriptor.instance_lengths.len() {
        return Err(VerifyError::InstanceColumns {
            expected: descriptor.instance_lengths.len(),
            found: instances.len(),
        });
    }
    for (column, (values, length)) in instances
        .iter()
        .zip(&descriptor.instance_lengths)
        .enumerate()
    {
        let expected = usize::try_from(*length).map_err(|_| ProtocolError::Overflow)?;
        if values.len() != expected {
            return Err(VerifyError::InstanceLength {
                column,
                expected,
                found: values.len(),
            });
        }
    }
    if let Some((column, row)) = descriptor.invalid_instance(instances) {
        return Err(VerifyError::InstanceType { column, row });
    }
    Ok(())
}

/// Reads `count` points.
fn read_points<C: PastaCurve, T: TranscriptRead<C>>(
    transcript: &mut T,
    count: usize,
) -> Result<Vec<C::AffineExt>, VerifyError> {
    (0..count)
        .map(|_| transcript.read_point().map_err(VerifyError::from))
        .collect()
}

/// Reads `count` scalars.
fn read_scalars<C: PastaCurve, T: TranscriptRead<C>>(
    transcript: &mut T,
    count: usize,
) -> Result<Vec<C::ScalarExt>, VerifyError> {
    (0..count)
        .map(|_| transcript.read_scalar().map_err(VerifyError::from))
        .collect()
}

/// An element of `items` by descriptor index.
fn at<T>(items: &[T], index: impl TryInto<usize>) -> Result<&T, VerifyError> {
    index
        .try_into()
        .ok()
        .and_then(|index| items.get(index))
        .ok_or(VerifyError::Descriptor(DescriptorError::Invalid(
            DescriptorRule::Expression,
        )))
}

/// Rejects the degenerate challenges `x = 0` and `x^n = 1` (spec section 8,
/// step 4): the Lagrange masks and the vanishing division are undefined on
/// the subgroup, and the vendored verifier panics there.
fn check_challenge<F: Field>(x: F, xn: F) -> Result<(), VerifyError> {
    if bool::from(x.is_zero()) || xn == F::ONE {
        Err(VerifyError::DegenerateChallenge)
    } else {
        Ok(())
    }
}

/// The evaluations of one permutation set.
#[derive(Clone, Copy, Debug)]
struct SetEvals<F> {
    product: F,
    next: F,
    last: Option<F>,
}

/// The evaluations of one lookup.
#[derive(Clone, Copy, Debug)]
struct LookupEvals<F> {
    product: F,
    product_next: F,
    input: F,
    input_prev: F,
    table: F,
}

/// The Lagrange masks at `x`: `l_first`, `l_last` and `1 - l_last - l_blind`.
#[derive(Clone, Copy, Debug)]
struct Masks<F> {
    first: F,
    last: F,
    active: F,
}

/// Everything a constraint term reads at `x`.
struct ConstraintEvaluations<'a, F> {
    descriptor: &'a ProtocolDescriptor,
    protocol: &'a Protocol,
    /// The gate polynomials, flattened in descriptor order.
    gates: Vec<&'a crate::cs::descriptor::ExprV1>,
    fixed: &'a [F],
    advice: &'a [F],
    instance: &'a [F],
    sigma: &'a [F],
    sets: &'a [SetEvals<F>],
    lookups: &'a [LookupEvals<F>],
    masks: Masks<F>,
    theta: F,
    beta: F,
    gamma: F,
    x: F,
}

impl<F: PastaField> ConstraintEvaluations<'_, F> {
    /// A descriptor expression at `x`.
    fn expression(&self, expression: &crate::cs::descriptor::ExprV1) -> Result<F, VerifyError> {
        evaluate_expression(expression, self.fixed, self.advice, self.instance)
            .ok_or_else(|| VerifyError::Descriptor(DescriptorRule::Expression.into()))
    }

    /// The `theta`-compression of lookup expressions.
    fn compress(&self, expressions: &[crate::cs::descriptor::ExprV1]) -> Result<F, VerifyError> {
        expressions.iter().try_fold(F::ZERO, |acc, expression| {
            self.expression(expression)
                .map(|value| acc * self.theta + value)
        })
    }

    /// The rotation-0 evaluation of a permutation column.
    fn column(&self, column: &PermutationColumn) -> Result<F, VerifyError> {
        let table = match column.kind {
            ColumnKindV1::Advice => self.advice,
            ColumnKindV1::Fixed => self.fixed,
            ColumnKindV1::Instance => self.instance,
        };
        at(table, column.query).copied()
    }

    /// The value of one constraint term at `x` (spec section 2).
    fn term(&self, term: ConstraintTerm) -> Result<F, VerifyError> {
        let one = F::ONE;
        let masks = self.masks;
        Ok(match term {
            ConstraintTerm::Gate { polynomial } => self.expression(at(&self.gates, polynomial)?)?,
            ConstraintTerm::PermutationFirst => {
                masks.first * (one - self.sets.first().ok_or(ProtocolError::Overflow)?.product)
            }
            ConstraintTerm::PermutationLast => {
                let last = self.sets.last().ok_or(ProtocolError::Overflow)?.product;
                masks.last * (last.square() - last)
            }
            ConstraintTerm::PermutationLink { set } => {
                let previous = set
                    .checked_sub(1)
                    .and_then(|previous| self.sets.get(previous))
                    .and_then(|previous| previous.last)
                    .ok_or(ProtocolError::Overflow)?;
                (at(self.sets, set)?.product - previous) * masks.first
            }
            ConstraintTerm::PermutationProduct { set } => {
                let chunk = self.protocol.shape().chunk_len;
                let first = set.checked_mul(chunk).ok_or(ProtocolError::Overflow)?;
                let columns = self
                    .protocol
                    .permutation_columns()
                    .chunks(chunk)
                    .nth(set)
                    .ok_or(ProtocolError::Overflow)?;
                let sigmas = self
                    .sigma
                    .chunks(chunk)
                    .nth(set)
                    .ok_or(ProtocolError::Overflow)?;
                let evals = at(self.sets, set)?;
                let first = u64::try_from(first).map_err(|_| ProtocolError::Overflow)?;
                let mut delta = self.beta * self.x * F::DELTA.pow_vartime([first]);
                let mut left = evals.next;
                for (column, sigma) in columns.iter().zip(sigmas) {
                    left *= self.column(column)? + self.beta * sigma + self.gamma;
                }
                let mut right = evals.product;
                for column in columns {
                    right *= self.column(column)? + delta + self.gamma;
                    delta *= F::DELTA;
                }
                (left - right) * masks.active
            }
            ConstraintTerm::Lookup { lookup, part } => {
                let evals = at(self.lookups, lookup)?;
                let argument = at(&self.descriptor.lookups, lookup)?;
                let a_minus_s = evals.input - evals.table;
                match part {
                    LookupConstraint::First => masks.first * (one - evals.product),
                    LookupConstraint::Last => masks.last * (evals.product.square() - evals.product),
                    LookupConstraint::Product => {
                        let input = self.compress(&argument.inputs)?;
                        let table = self.compress(&argument.tables)?;
                        (evals.product_next
                            * (evals.input + self.beta)
                            * (evals.table + self.gamma)
                            - evals.product * (input + self.beta) * (table + self.gamma))
                            * masks.active
                    }
                    LookupConstraint::Start => masks.first * a_minus_s,
                    LookupConstraint::Step => {
                        a_minus_s * (evals.input - evals.input_prev) * masks.active
                    }
                }
            }
        })
    }
}

/// Steps 1-8 of the checklist; returns the pending opening and the suffix.
/// `filter` is [`AllTerms`] for every real verification; the
/// malicious-prover tests omit terms to show which one rejects.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn read_proof<C: PastaCurve>(
    params: &PinnedParams<C>,
    binding: &DescriptorBinding,
    vk: &VerifyingKey<C>,
    instances: &[Vec<C::ScalarExt>],
    proof: &[u8],
    mode: Mode<C>,
    budget: MemoryBudget,
    filter: &impl ConstraintFilter,
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> Result<ReadProof<C>, VerifyError>
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    iroha_pasta::CancellationToken::checkpoint(cancellation)?;
    let descriptor = binding.descriptor();
    if vk.descriptor_digest() != binding.digest() {
        return Err(VerifyError::KeyMismatch);
    }
    if params.curve() != descriptor.curve || params.k() != u32::from(descriptor.k) {
        return Err(VerifyError::ParamsMismatch);
    }
    check_instances(descriptor, instances)?;
    let protocol = Protocol::new(descriptor)?;
    let shape = *protocol.shape();
    if proof.len() != protocol.proof_length() {
        return Err(VerifyError::ProofLength {
            expected: protocol.proof_length(),
            actual: proof.len(),
        });
    }

    let hash = if mode.oracle {
        oracle_hash::<C>(descriptor)?
    } else {
        DescriptorHash::<C>::production(descriptor.transcript)
    };
    let mut transcript = TranscriptReader::<C, _>::new(hash, proof);
    #[cfg(test)]
    if mode.oracle {
        transcript.record_challenges();
    }
    if mode.oracle {
        transcript.common_scalar(
            mode.transcript_repr
                .scalar()
                .ok_or(TranscriptError::ProfileMismatch)?,
        );
    } else if let Some(types) = &descriptor.instance_types {
        absorb_prelude_v2::<C, _>(
            &mut transcript,
            &mode.transcript_repr,
            &descriptor.instance_lengths,
            types,
        )?;
    } else {
        absorb_prelude::<C, _>(
            &mut transcript,
            mode.transcript_repr
                .scalar()
                .ok_or(TranscriptError::ProfileMismatch)?,
            &descriptor.instance_lengths,
        );
    }
    let mut instance_commitments = Vec::new();
    if shape.committed_instances {
        for (column, values) in instances.iter().enumerate() {
            let commitment = crate::protocol::instance_commitment_cancellable(
                params,
                values,
                budget,
                cancellation,
            )?;
            transcript
                .common_point(&commitment)
                .map_err(|error| match error {
                    TranscriptError::IdentityPoint => {
                        VerifyError::IdentityInstanceCommitment { column }
                    }
                    other => VerifyError::Transcript(other),
                })?;
            instance_commitments.push(commitment);
        }
    } else {
        for (index, value) in instances.iter().flatten().enumerate() {
            if index % 1024 == 0 {
                iroha_pasta::CancellationToken::checkpoint(cancellation)?;
            }
            transcript.common_scalar(value);
        }
    }

    // Rows 1-6.
    let advice_commitments = read_points::<C, _>(&mut transcript, shape.num_advice)?;
    let theta = transcript.squeeze_challenge();
    let mut permuted = Vec::with_capacity(shape.lookups);
    for _ in 0..shape.lookups {
        let input = transcript.read_point()?;
        let table = transcript.read_point()?;
        permuted.push((input, table));
    }
    let beta = transcript.squeeze_challenge();
    let gamma = transcript.squeeze_challenge();
    let products = read_points::<C, _>(&mut transcript, shape.permutation_sets)?;
    let lookup_products = read_points::<C, _>(&mut transcript, shape.lookups)?;
    let random_commitment = transcript.read_point()?;
    let y = transcript.squeeze_challenge();
    let h_commitments = read_points::<C, _>(&mut transcript, shape.quotient_pieces)?;
    let x = transcript.squeeze_challenge();
    let n = u64::try_from(shape.n).map_err(|_| ProtocolError::Overflow)?;
    let xn = x.pow_vartime([n]);
    check_challenge(x, xn)?;

    // Rows 7-11.
    let instance_evals = if shape.committed_instances {
        read_scalars::<C, _>(&mut transcript, shape.instance_queries)?
    } else {
        descriptor
            .instance_queries
            .iter()
            .map(|query| {
                instance_evaluation(at(instances, query.column)?, query.rotation, x, xn, shape.k)
                    .ok_or(VerifyError::DegenerateChallenge)
            })
            .collect::<Result<Vec<_>, _>>()?
    };
    let advice_evals = read_scalars::<C, _>(&mut transcript, shape.advice_queries)?;
    let fixed_evals = read_scalars::<C, _>(&mut transcript, shape.fixed_queries)?;
    let random_eval = transcript.read_scalar()?;
    let sigma_evals = read_scalars::<C, _>(&mut transcript, shape.permutation_columns)?;
    let mut set_evals = Vec::with_capacity(shape.permutation_sets);
    for set in 0..shape.permutation_sets {
        let product = transcript.read_scalar()?;
        let next = transcript.read_scalar()?;
        let last = if set + 1 < shape.permutation_sets {
            Some(transcript.read_scalar()?)
        } else {
            None
        };
        set_evals.push(SetEvals {
            product,
            next,
            last,
        });
    }
    let mut lookup_evals = Vec::with_capacity(shape.lookups);
    for _ in 0..shape.lookups {
        lookup_evals.push(LookupEvals {
            product: transcript.read_scalar()?,
            product_next: transcript.read_scalar()?,
            input: transcript.read_scalar()?,
            input_prev: transcript.read_scalar()?,
            table: transcript.read_scalar()?,
        });
    }

    // Masks: l_last = l_u, l_blind = sum of l_{u+1..n}, l_first.
    let mut indices: Vec<usize> = (shape.usable_rows..shape.n).collect();
    indices.push(0);
    let masks =
        lagrange_evaluations(x, xn, shape.k, &indices).ok_or(VerifyError::DegenerateChallenge)?;
    let (l_last, rest) = masks.split_first().ok_or(ProtocolError::Overflow)?;
    let (l_first, blind_masks) = rest.split_last().ok_or(ProtocolError::Overflow)?;
    let (l_last, l_first) = (*l_last, *l_first);
    let l_blind = blind_masks
        .iter()
        .fold(C::ScalarExt::ZERO, |acc, value| acc + value);

    // The constraints, folded with y by interpreting the protocol's
    // constraint-term table (spec section 2, S11).
    let evaluations = ConstraintEvaluations {
        descriptor,
        protocol: &protocol,
        gates: descriptor.gates.iter().flatten().collect(),
        fixed: &fixed_evals,
        advice: &advice_evals,
        instance: &instance_evals,
        sigma: &sigma_evals,
        sets: &set_evals,
        lookups: &lookup_evals,
        masks: Masks {
            first: l_first,
            last: l_last,
            active: C::ScalarExt::ONE - (l_last + l_blind),
        },
        theta,
        beta,
        gamma,
        x,
    };
    let mut expected = C::ScalarExt::ZERO;
    for term in protocol.constraint_terms() {
        iroha_pasta::CancellationToken::checkpoint(cancellation)?;
        let value = if filter.keeps(*term) {
            evaluations.term(*term)?
        } else {
            C::ScalarExt::ZERO
        };
        expected = expected * y + value;
    }
    // x^n != 1 was checked, so the inverse exists.
    let one = C::ScalarExt::ONE;
    let expected_h = expected
        * Option::<C::ScalarExt>::from((xn - one).invert())
            .ok_or(VerifyError::DegenerateChallenge)?;

    // The evaluations in opening-query order (spec 9.1).
    let mut evaluations = Vec::with_capacity(protocol.queries().len());
    if shape.committed_instances {
        evaluations.extend_from_slice(&instance_evals);
    }
    evaluations.extend_from_slice(&advice_evals);
    for set in &set_evals {
        evaluations.push(set.product);
        evaluations.push(set.next);
    }
    for set in set_evals.iter().rev().skip(1) {
        evaluations.push(set.last.ok_or(ProtocolError::Overflow)?);
    }
    for evals in &lookup_evals {
        evaluations.extend_from_slice(&[
            evals.product,
            evals.input,
            evals.table,
            evals.input_prev,
            evals.product_next,
        ]);
    }
    evaluations.extend_from_slice(&fixed_evals);
    evaluations.extend_from_slice(&sigma_evals);
    evaluations.push(expected_h);
    evaluations.push(random_eval);

    // The commitment of every plan slot, by kind and index (S1).
    let mut h_commitment = Msm::<C>::new();
    for commitment in h_commitments.iter().rev() {
        h_commitment.scale(&xn);
        h_commitment.push(one, *commitment);
    }
    let plan = protocol.plan();
    let commitments = plan
        .slots()
        .iter()
        .map(|slot| {
            let index = slot.slot.index;
            Ok(match slot.slot.kind {
                SlotKind::Instance => Msm::from_point(*at(&instance_commitments, index)?),
                SlotKind::Advice => Msm::from_point(*at(&advice_commitments, index)?),
                SlotKind::Fixed => Msm::from_point(*at(vk.fixed_commitments(), index)?),
                SlotKind::PermutationSigma => {
                    Msm::from_point(*at(vk.permutation_commitments(), index)?)
                }
                SlotKind::PermutationProduct => Msm::from_point(*at(&products, index)?),
                SlotKind::LookupProduct => Msm::from_point(*at(&lookup_products, index)?),
                SlotKind::LookupPermutedInput => Msm::from_point(at(&permuted, index)?.0),
                SlotKind::LookupPermutedTable => Msm::from_point(at(&permuted, index)?.1),
                SlotKind::Vanishing => h_commitment.clone(),
                SlotKind::Random => Msm::from_point(random_commitment),
            })
        })
        .collect::<Result<Vec<_>, VerifyError>>()?;
    let omega = crate::protocol::omega::<C::ScalarExt>(shape.k).ok_or(ProtocolError::Overflow)?;
    let points = plan.points(x, omega);
    let pending = verify_opening(
        plan,
        &points,
        &commitments,
        &evaluations,
        shape.k,
        &mut transcript,
    )?;
    let suffix = if shape.folded_generator_suffix {
        Some(transcript.read_unabsorbed_point()?)
    } else {
        None
    };
    #[cfg(test)]
    let challenges = transcript.take_challenges();
    transcript.finish()?;
    Ok(ReadProof {
        pending,
        suffix,
        #[cfg(test)]
        challenges,
    })
}

/// The oracle-mode hash of the descriptor's transcript.
#[cfg(test)]
fn oracle_hash<C: PastaCurve>(
    descriptor: &ProtocolDescriptor,
) -> Result<DescriptorHash<C>, TranscriptError>
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    Ok(DescriptorHash::<C>::oracle(
        descriptor
            .transcript
            .retained()
            .ok_or(TranscriptError::ProfileMismatch)?,
    ))
}

/// Oracle mode is unavailable in shipping builds and explicitly rejects use.
#[cfg(not(test))]
fn oracle_hash<C: PastaCurve>(
    _descriptor: &ProtocolDescriptor,
) -> Result<DescriptorHash<C>, TranscriptError>
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    Err(TranscriptError::ProfileMismatch)
}

/// The production mode of a verifying key.
fn production<C: PastaCurve>(vk: &VerifyingKey<C>) -> Mode<C> {
    Mode {
        oracle: false,
        transcript_repr: *vk.transcript_repr(),
    }
}

/// Full verification (spec section 8, step 9): accepts iff the proof is
/// valid for `instances` under the descriptor of `binding` and `vk`.
///
/// # Errors
///
/// The typed [`VerifyError`] of the first failed check.
pub fn verify_full<C: PastaCurve>(
    params: &PinnedParams<C>,
    binding: &DescriptorBinding,
    vk: &VerifyingKey<C>,
    instances: &[Vec<C::ScalarExt>],
    proof: &[u8],
    budget: MemoryBudget,
) -> Result<(), VerifyError>
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    verify_full_cancellable(params, binding, vk, instances, proof, budget, None)
}

/// Verifies with explicit cancellation and no partial acceptance verdict.
///
/// # Errors
/// As [`verify_full`], or [`VerifyError::Cancelled`].
pub fn verify_full_cancellable<C: PastaCurve>(
    params: &PinnedParams<C>,
    binding: &DescriptorBinding,
    vk: &VerifyingKey<C>,
    instances: &[Vec<C::ScalarExt>],
    proof: &[u8],
    budget: MemoryBudget,
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> Result<(), VerifyError>
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    iroha_pasta::CancellationToken::checkpoint(cancellation)?;
    let read = read_proof(
        params,
        binding,
        vk,
        instances,
        proof,
        production(vk),
        budget,
        &AllTerms,
        cancellation,
    )?;
    iroha_pasta::CancellationToken::checkpoint(cancellation)?;
    Ok(read
        .pending
        .verify_full_cancellable(params, read.suffix.as_ref(), budget, cancellation)?)
}

/// Succinct accumulation (spec section 11): steps 1-8, then the opening
/// equation with the `FoldedGenerator` suffix `G` in place of `G'_0`. The MSM
/// size does not depend on `n`.
///
/// **`Ok` is not an acceptance and says nothing about the statement.** The
/// suffix is read after every challenge (the round challenges, `c` and `f`)
/// and is not absorbed, so for any statement a prover can write well-formed
/// messages and then solve the equation for `G`; this function returns
/// `Ok(accumulator)` for such a false statement. The returned
/// [`PendingAccumulator`] carries the claim `G = <s(u), g>`, and only
/// [`PendingAccumulator::decide`] or [`batch_decide`](crate::batch_decide)
/// accept; [`verify_full`] and [`batch_verify`] decide it themselves. Use this
/// only to defer that decision (for example into a recursive accumulator),
/// never as a verdict.
///
/// # Errors
///
/// [`VerifyError::SuffixRequired`] without a `FoldedGenerator` suffix, and
/// the typed [`VerifyError`] of the first failed decoding, shape or opening
/// check.
pub fn accumulate_succinct<C: PastaCurve>(
    params: &PinnedParams<C>,
    binding: &DescriptorBinding,
    vk: &VerifyingKey<C>,
    instances: &[Vec<C::ScalarExt>],
    proof: &[u8],
    budget: MemoryBudget,
) -> Result<PendingAccumulator<C>, VerifyError>
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    accumulate_succinct_cancellable(params, binding, vk, instances, proof, budget, None)
}

/// Deferred verification with an explicit signal; no partial claim is returned.
/// # Errors
/// As the ordinary entry point, or cooperative cancellation.
pub fn accumulate_succinct_cancellable<C: PastaCurve>(
    params: &PinnedParams<C>,
    binding: &DescriptorBinding,
    vk: &VerifyingKey<C>,
    instances: &[Vec<C::ScalarExt>],
    proof: &[u8],
    budget: MemoryBudget,
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> Result<PendingAccumulator<C>, VerifyError>
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    iroha_pasta::CancellationToken::checkpoint(cancellation)?;
    if binding.descriptor().proof_suffix != ProofSuffixV1::FoldedGenerator {
        return Err(VerifyError::SuffixRequired);
    }
    let read = read_proof(
        params,
        binding,
        vk,
        instances,
        proof,
        production(vk),
        budget,
        &AllTerms,
        cancellation,
    )?;
    iroha_pasta::CancellationToken::checkpoint(cancellation)?;
    let folded = read.suffix.ok_or(VerifyError::SuffixRequired)?;
    let claim = read.pending.accumulate(
        params,
        &folded,
        vk.transcript_repr()
            .scalar()
            .ok_or(TranscriptError::ProfileMismatch)?,
        budget,
    )?;
    iroha_pasta::CancellationToken::checkpoint(cancellation)?;
    Ok(claim)
}

/// [`verify_full`] from the canonical descriptor frame `D` and the `0x02`
/// verifying-key bytes: `D` is admission-decoded and validated, and the key
/// is decoded strictly against it.
///
/// # Errors
///
/// [`VerifyError::Descriptor`], [`VerifyError::VerifyingKey`] and the
/// errors of [`verify_full`].
pub fn verify_full_from_bytes<C: PastaCurve>(
    params: &PinnedParams<C>,
    descriptor: &[u8],
    vk: &[u8],
    instances: &[Vec<C::ScalarExt>],
    proof: &[u8],
    budget: MemoryBudget,
) -> Result<(), VerifyError>
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    let binding = DescriptorBinding::decode(descriptor)?;
    let vk = VerifyingKey::<C>::read(vk, &binding)?;
    verify_full(params, &binding, &vk, instances, proof, budget)
}

/// [`verify_full`] in oracle mode (spec 6.4): the vendored
/// `transcript_repr`, `fe_to_fe` Poseidon point absorption, no instance
/// frame. Unit tests only.
///
/// # Errors
///
/// As [`verify_full`].
#[cfg(test)]
#[doc(hidden)]
pub fn verify_full_oracle<C: PastaCurve>(
    params: &PinnedParams<C>,
    binding: &DescriptorBinding,
    vk: &VerifyingKey<C>,
    instances: &[Vec<C::ScalarExt>],
    proof: &[u8],
    budget: MemoryBudget,
    vendored_transcript_repr: C::ScalarExt,
) -> Result<(), VerifyError>
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    let mode = Mode {
        oracle: true,
        transcript_repr: TranscriptRepr::Scalar(vendored_transcript_repr),
    };
    let read = read_proof(
        params, binding, vk, instances, proof, mode, budget, &AllTerms, None,
    )?;
    Ok(read
        .pending
        .verify_full(params, read.suffix.as_ref(), budget)?)
}

/// Deferred oracle verification with the vendored transcript framing.
///
/// This exposes the same unchecked generator obligation as
/// [`accumulate_succinct`] solely for independent oracle comparisons. A returned
/// claim must still be decided; it is never a proof acceptance.
/// The second tuple element records every actual native transcript squeeze.
///
/// # Errors
/// As [`accumulate_succinct`], using the supplied vendored transcript scalar.
#[cfg(test)]
#[doc(hidden)]
pub fn accumulate_succinct_oracle<C: PastaCurve>(
    params: &PinnedParams<C>,
    binding: &DescriptorBinding,
    vk: &VerifyingKey<C>,
    instances: &[Vec<C::ScalarExt>],
    proof: &[u8],
    budget: MemoryBudget,
    vendored_transcript_repr: C::ScalarExt,
) -> Result<(PendingAccumulator<C>, Vec<C::ScalarExt>), VerifyError>
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    if binding.descriptor().proof_suffix != ProofSuffixV1::FoldedGenerator {
        return Err(VerifyError::SuffixRequired);
    }
    let mode = Mode {
        oracle: true,
        transcript_repr: TranscriptRepr::Scalar(vendored_transcript_repr),
    };
    let read = read_proof(
        params, binding, vk, instances, proof, mode, budget, &AllTerms, None,
    )?;
    let folded = read.suffix.ok_or(VerifyError::SuffixRequired)?;
    let pending = read
        .pending
        .accumulate(params, &folded, &vendored_transcript_repr, budget)?;
    Ok((pending, read.challenges))
}

/// [`verify_full`] with a constraint filter (malicious-prover tests only):
/// a verifier that omits the filtered terms, used to show that a forgery is
/// rejected exactly because of the terms it violates.
#[cfg(test)]
pub(crate) fn verify_full_filtered<C: PastaCurve>(
    params: &PinnedParams<C>,
    binding: &DescriptorBinding,
    vk: &VerifyingKey<C>,
    instances: &[Vec<C::ScalarExt>],
    proof: &[u8],
    filter: &impl ConstraintFilter,
) -> Result<(), VerifyError>
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    let budget = MemoryBudget::DEFAULT;
    let read = read_proof(
        params,
        binding,
        vk,
        instances,
        proof,
        production(vk),
        budget,
        filter,
        None,
    )?;
    Ok(read
        .pending
        .verify_full(params, read.suffix.as_ref(), budget)?)
}

/// One proof of a batch: its parameters, descriptor, verifying key,
/// instances and bytes.
#[derive(Clone, Copy, Debug)]
pub struct BatchItem<'a, C: PastaCurve> {
    /// The pinned parameters of the proof's `k`.
    pub params: &'a PinnedParams<C>,
    /// The descriptor.
    pub binding: &'a DescriptorBinding,
    /// The verifying key bound to the descriptor.
    pub vk: &'a VerifyingKey<C>,
    /// The instance columns.
    pub instances: &'a [Vec<C::ScalarExt>],
    /// The proof bytes.
    pub proof: &'a [u8],
}

/// Batch verification with deterministic weights (spec section 11): every
/// proof runs steps 1-8, then one equation checks the weighted sum of every
/// step-9 left-hand side with `G'_0 = <s(u), g>` folded into one merged `g`
/// MSM. A `FoldedGenerator` suffix enters the batch as an accumulator item
/// (`G = <s(u), g>`) with its own weight.
///
/// The weights are derived after every item is fixed: item `i` of kind
/// `0x00` has the [`proof_item_body`] of its descriptor digest,
/// `transcript_repr`, instances and proof; a suffix is an item of kind
/// `0x01` with its `AccumulatorV1` bytes; then `rho_0 = 1` and `rho_i =
/// F::from_uniform_bytes(BLAKE2b(64, "PIPA-v1-BatchWgt", seed ||
/// u64_le(i)))`. If a weight is zero, every proof is verified individually.
/// Items may mix values of `k`: the merged MSM uses the generators of the
/// largest parameters, of which the smaller ones are a prefix.
///
/// An empty batch claims nothing and is accepted.
///
/// # Errors
///
/// [`VerifyError::BatchItem`] naming the first item rejected by steps 1-8
/// (or by full verification when a weight is zero), and
/// [`VerifyError::BatchRejected`] when the batch equation fails.
pub fn batch_verify<C: PastaCurve>(
    items: &[BatchItem<'_, C>],
    budget: MemoryBudget,
) -> Result<(), VerifyError>
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    let item_error = |index: usize, error: VerifyError| VerifyError::BatchItem {
        index,
        error: Box::new(error),
    };
    let mut reads = Vec::with_capacity(items.len());
    let mut digests = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let read = read_proof(
            item.params,
            item.binding,
            item.vk,
            item.instances,
            item.proof,
            production(item.vk),
            budget,
            &AllTerms,
            None,
        )
        .map_err(|error| item_error(index, error))?;
        let body = proof_item_body(
            item.binding.digest(),
            item.vk
                .transcript_repr()
                .scalar()
                .ok_or(TranscriptError::ProfileMismatch)?,
            item.instances,
            item.proof,
        )
        .map_err(|_| item_error(index, ProtocolError::Overflow.into()))?;
        digests.push(batch_item_digest(BATCH_KIND_PROOF, &body));
        reads.push(read);
    }
    let mut suffixes = Vec::new();
    for (item, read) in items.iter().zip(&reads) {
        if let Some(folded) = read.suffix {
            let claim = PendingAccumulator::<C>::new(
                *item
                    .vk
                    .transcript_repr()
                    .scalar()
                    .ok_or(TranscriptError::ProfileMismatch)?,
                read.pending.k(),
                folded,
                read.pending.challenges().to_vec(),
            );
            digests.push(batch_item_digest(BATCH_KIND_ACCUMULATOR, &claim.to_bytes()));
            suffixes.push(claim);
        }
    }
    let weights = batch_weights::<C::ScalarExt>(&digests);
    if weights.iter().any(|weight| bool::from(weight.is_zero())) {
        // Probability about N / 2^254: decide every item on its own.
        for (index, (item, read)) in items.iter().zip(reads).enumerate() {
            read.pending
                .verify_full(item.params, read.suffix.as_ref(), budget)
                .map_err(|error| item_error(index, error.into()))?;
        }
        return Ok(());
    }
    let Some(largest) = items
        .iter()
        .map(|item| item.params)
        .max_by_key(|params| params.k())
    else {
        return Ok(());
    };
    let generators = largest.params().g();
    let mut combined = vec![C::ScalarExt::ZERO; generators.len()];
    let mut msm = Msm::<C>::new();
    let add_folded = |combined: &mut [C::ScalarExt], challenges: &[C::ScalarExt], init| {
        for (total, value) in combined.iter_mut().zip(fold_scalars(challenges, init)) {
            *total += value;
        }
    };
    let (proof_weights, suffix_weights) = weights.split_at(items.len());
    for ((item, read), weight) in items.iter().zip(reads).zip(proof_weights) {
        let (mut terms, neg_c, challenges) = read.pending.into_batch_terms(item.params);
        terms.scale(weight);
        msm.add_msm(&terms);
        add_folded(&mut combined, &challenges, neg_c * weight);
    }
    for (claim, weight) in suffixes.iter().zip(suffix_weights) {
        msm.push(*weight, *claim.g());
        add_folded(&mut combined, claim.challenges(), -*weight);
    }
    for (scalar, base) in combined.iter().zip(generators) {
        msm.push(*scalar, *base);
    }
    if msm.is_identity(budget) {
        Ok(())
    } else {
        Err(VerifyError::BatchRejected)
    }
}

#[cfg(test)]
mod captured_succinct_tests;
#[cfg(test)]
mod tests;

/// Succinctly checks a proof and returns a provenance-free generator obligation.
/// The descriptor and instances bind provenance; this result still must be
/// decided or folded exactly once by its recursive consumer.
///
/// # Errors
/// Missing suffix, malformed proof/profile/instances, or failed succinct equation.
pub fn accumulate_generator<C: PastaCurve>(
    params: &PinnedParams<C>,
    binding: &DescriptorBinding,
    vk: &VerifyingKey<C>,
    instances: &[Vec<C::ScalarExt>],
    proof: &[u8],
    budget: MemoryBudget,
) -> Result<crate::pcs::ipa::GeneratorClaim<C>, VerifyError>
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    accumulate_generator_cancellable(params, binding, vk, instances, proof, budget, None)
}

/// Deferred verification with an explicit signal; no partial claim is returned.
/// # Errors
/// As the ordinary entry point, or cooperative cancellation.
pub fn accumulate_generator_cancellable<C: PastaCurve>(
    params: &PinnedParams<C>,
    binding: &DescriptorBinding,
    vk: &VerifyingKey<C>,
    instances: &[Vec<C::ScalarExt>],
    proof: &[u8],
    budget: MemoryBudget,
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> Result<crate::pcs::ipa::GeneratorClaim<C>, VerifyError>
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    iroha_pasta::CancellationToken::checkpoint(cancellation)?;
    if binding.descriptor().proof_suffix != ProofSuffixV1::FoldedGenerator {
        return Err(VerifyError::SuffixRequired);
    }
    let read = read_proof(
        params,
        binding,
        vk,
        instances,
        proof,
        production(vk),
        budget,
        &AllTerms,
        cancellation,
    )?;
    iroha_pasta::CancellationToken::checkpoint(cancellation)?;
    let folded = read.suffix.ok_or(VerifyError::SuffixRequired)?;
    let claim = read.pending.into_generator_claim(params, &folded, budget)?;
    iroha_pasta::CancellationToken::checkpoint(cancellation)?;
    Ok(claim)
}

/// Fully verifies using explicit V2 descriptor admission, without V1 fallback.
///
/// # Errors
/// The V2 descriptor, VK and proof validation errors.
pub fn verify_full_from_bytes_v2<C: PastaCurve>(
    params: &PinnedParams<C>,
    descriptor: &[u8],
    vk: &[u8],
    instances: &[Vec<C::ScalarExt>],
    proof: &[u8],
    budget: MemoryBudget,
) -> Result<(), VerifyError>
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    let binding = DescriptorBinding::decode_v2(descriptor)?;
    let vk = VerifyingKey::read(vk, &binding)?;
    verify_full(params, &binding, &vk, instances, proof, budget)
}
