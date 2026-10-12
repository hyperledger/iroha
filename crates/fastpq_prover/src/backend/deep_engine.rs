//! Bounded verification of the canonical masked DEEP compact protocol.
//!
//! This owner joins the full statement, typed whole-message transcript, one OOD
//! AIR identity, exact authenticated fibers and the complete linear terminal.
//! It constructs neither a witness nor a trace/FFT/LDE. Its inputs are the
//! caller-prepared transfer relation and the canonical bounded proof frame.
//! The Quantity facade joins the bounded masked producer, whose complete
//! terminal satisfies this fixed profile's degree-below-two terminal bound.
//! Checking the complete terminal enforces polynomial geometry; it cannot
//! establish masking, source authority or FRI soundness.
//! TODO: Qualify generated artifacts and independently review source/finality
//! authentication, privacy and cryptographic/resource bounds.

use fastpq_isi::keccak256::Sha3Digest256V1 as Digest;
use iroha_data_model::fastpq::FastpqCommitmentV1 as WireDigest;

use super::{
    air::{
        SemanticAir,
        q77::{SealedView, VerifierLimits},
    },
    compact_public_columns::COMMITTED_COLUMN_COUNT,
    deep_binding::{BindingError, Context, Message, Oracle, Transcript},
    deep_composition::DeepComposition,
    deep_geometry::{
        CONSTRAINTS, DeepGeometry, FRI_ARITIES, FRI_DEGREES, FRI_LENGTHS, LDE_ROWS, QUERY_COUNT,
    },
    deep_proof::{self, DeepProof, OpeningPlans},
    deep_relation::DeepRelation,
    fri_fold::FriFoldPlan,
    merkle_multiproof::MultiproofPlan,
};
use crate::{Error, Result, field::GoldilocksFp4V1 as F, gadgets::compact_smt_air::COLUMN_COUNT};

/// Quotient values opened with each query: the two quotient chunks.
pub(super) const QUERY_CHUNK_VALUES: usize = 2;
/// Field values authenticated in one quotient leaf: both chunks and the composition mask.
const QUOTIENT_LEAF_VALUES: usize = QUERY_CHUNK_VALUES + 1;
/// Largest opened FRI group, in values.
pub(super) const MAX_FRI_GROUP_VALUES: usize = max_arity();
/// Authentication path length of the initial evaluation domain.
pub(super) const QUERY_PATH_LEN: usize = LDE_ROWS.ilog2() as usize;

/// Declared structural work charge of one bounded verification.
///
/// One unit is charged for each enumerated field-value slot and each numerator
/// evaluation, the unit the uncommitted reference charges: the single
/// out-of-domain evaluation of all 923 slots over both complete 342-cell rows,
/// the carried out-of-domain answers, every retained row, quotient leaf and FRI
/// group of the 77 queries at its full arity, and the complete terminal. Query
/// deduplication and the omitted known fiber coordinate only lower what a
/// frame carries.
///
/// This is a declared profile charge. It is not a count of every runtime field
/// read, a complete arithmetic cost, consensus gas or a work-security
/// statement, and hashing is bounded separately by the query, path and layer
/// ceilings.
/// TODO: B.2 and F.2 complete the verifier's resource accounting.
pub(super) const VERIFICATION_WORK_UNITS: usize = CONSTRAINTS
    + 2 * COLUMN_COUNT
    + 2 * COMMITTED_COLUMN_COUNT
    + QUERY_CHUNK_VALUES
    + QUERY_COUNT * (COMMITTED_COLUMN_COUNT + QUOTIENT_LEAF_VALUES + arity_sum())
    + deep_proof::TERMINAL_VALUES;

const fn max_arity() -> usize {
    let mut maximum = 0;
    let mut round = 0;
    while round < FRI_ARITIES.len() {
        if FRI_ARITIES[round] > maximum {
            maximum = FRI_ARITIES[round];
        }
        round += 1;
    }
    maximum
}

const fn arity_sum() -> usize {
    let mut sum = 0;
    let mut round = 0;
    while round < FRI_ARITIES.len() {
        sum += FRI_ARITIES[round];
        round += 1;
    }
    sum
}

/// Actual bounded work of one fully verified proof; no caller authority.
///
/// Published through [`crate::air::q77`] for process observers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerificationWork {
    /// Complete canonical input frame length.
    pub proof_bytes: usize,
    /// Exactly one evaluation of all 923 AIR slots at the sampled OOD point.
    pub air_evaluations: usize,
    /// Authenticated row, quotient, FRI-fiber and terminal leaves.
    pub leaf_hashes: usize,
    /// All reconstructed binary Merkle parents, including the sole terminal parent.
    pub parent_hashes: usize,
    /// All commitment, OOD and transcript-chain H calls.
    pub h_calls: usize,
    /// Complete indivisible verifier messages.
    pub verifier_messages: usize,
    /// Materialized raw G bytes including every rejected and unused suffix word.
    pub g_tape_bytes: usize,
    /// Checked distinct incoming fold edges, including every coordinate in shared fibers.
    pub fold_checks: usize,
    /// Every terminal value checked against one degree-below-two polynomial.
    pub terminal_values: usize,
}

/// Authenticated row commitment and measured work from one complete verification.
/// Private fields prevent decoded or partially checked proofs from minting success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct VerifiedDeepProof {
    row_root: WireDigest,
    work: VerificationWork,
}

impl VerifiedDeepProof {
    /// The row root of the same decoded proof which passed every check.
    pub(super) const fn row_root(&self) -> WireDigest {
        self.row_root
    }

    /// Measured verification work for that authenticated proof.
    pub(super) const fn work(&self) -> VerificationWork {
        self.work
    }
}

/// Check caller ceilings against fixed geometry before decoding or private proving.
///
/// `limits` is the typed [`crate::air::q77::VerifierLimits`] of the AIR
/// interface; the engine has no other verifier limit type.
/// `proof_bytes` may be `MAX_FRAME_BYTES` for conservative producer preflight.
/// Transition count belongs to the enclosing prepared public bundle and remains
/// checked there before constructing a segment; it cannot be read from proof bytes.
/// AIR rows have 301 retained values, quotient chunks have two Fp4 values, and
/// FRI groups have at most 16 values. The complete 128-value terminal has its own
/// immutable DTO/engine bound; it is not a queried FRI group.
///
/// After the geometry ceilings and the closed relation envelope, the relation's
/// own declared shape, read through its sealed interface view, and the
/// verification's declared payload and work are checked against `limits.work`.
pub(super) fn preflight(
    relation: &impl DeepRelation,
    proof_bytes: usize,
    limits: VerifierLimits,
) -> Result<()> {
    check_limits(&[
        (
            "max_proof_bytes",
            proof_bytes,
            limits.max_proof_bytes.min(deep_proof::MAX_FRAME_BYTES),
        ),
        (
            "max_compact_statement_bytes",
            relation.statement_bytes().len(),
            limits.work.max_statement_bytes,
        ),
        ("max_fri_layers", FRI_LENGTHS.len(), limits.max_fri_layers),
        ("max_queries", QUERY_COUNT, limits.max_queries),
        (
            "max_query_chunk_values",
            QUERY_CHUNK_VALUES,
            limits.max_query_chunk_values,
        ),
        (
            "max_query_path_len",
            QUERY_PATH_LEN,
            limits.max_query_path_len,
        ),
        (
            "max_fri_round_values",
            MAX_FRI_GROUP_VALUES,
            limits.max_fri_round_values,
        ),
        (
            "max_air_row_values",
            COMMITTED_COLUMN_COUNT,
            limits.max_air_row_values,
        ),
    ])?;
    Context::preflight_relation(relation).map_err(binding_error)?;
    let schema = SealedView::new(relation).schema();
    check_limits(&[
        (
            "max_trace_rows",
            schema.trace_rows,
            limits.work.max_trace_rows,
        ),
        (
            "max_trace_cells",
            schema.trace_cells(),
            limits.work.max_trace_cells,
        ),
        (
            "max_constraints",
            schema.constraints,
            limits.work.max_constraints,
        ),
        (
            "max_verifier_payload_bytes",
            verification_payload_bytes(proof_bytes, limits.max_decode_allocation_charges),
            limits.work.max_payload_bytes,
        ),
        (
            "max_verifier_work_units",
            VERIFICATION_WORK_UNITS,
            limits.work.max_work_units,
        ),
    ])
}

/// Declared payload charge of one verification: the canonical frame it reads
/// and the decode allocation charges it admits for that frame.
///
/// It does not cover transcript, opening-plan or evaluation scratch and is not
/// a peak-memory bound; that accounting remains open under B.2 and F.2.
pub(super) const fn verification_payload_bytes(
    proof_bytes: usize,
    max_decode_allocation_charges: usize,
) -> usize {
    let admitted = if max_decode_allocation_charges < deep_proof::MAX_ALLOCATION_CHARGES {
        max_decode_allocation_charges
    } else {
        deep_proof::MAX_ALLOCATION_CHARGES
    };
    proof_bytes.saturating_add(admitted)
}

/// Refuse the first `(name, actual, maximum)` whose actual exceeds its maximum.
fn check_limits(limits: &[(&'static str, usize, usize)]) -> Result<()> {
    for &(name, actual, maximum) in limits {
        if actual > maximum {
            return Err(Error::VerifierLimitExceeded {
                limit: name,
                actual,
                max: maximum,
            });
        }
    }
    Ok(())
}

/// Verify with all segment policies and return only its authenticated commitment.
///
/// One canonical decode remains within the caller's allocation ceiling and any
/// stricter enclosing Norito scope. The same object then receives exactly one
/// full OOD AIR evaluation and all transcript, Merkle, FRI and terminal checks.
///
/// The registered [`crate::air::q77`] process observer receives the public
/// outcome after the result is fixed; it cannot change that result.
pub(super) fn verify_committed(
    relation: &impl DeepRelation,
    bytes: &[u8],
    limits: VerifierLimits,
) -> Result<VerifiedDeepProof> {
    let result = (|| {
        preflight(relation, bytes.len(), limits)?;
        let proof = deep_proof::decode_with_allocation(
            bytes,
            limits.max_proof_bytes,
            limits.max_decode_allocation_charges,
        )?;
        verify_decoded(relation, &proof, bytes.len())
    })();
    super::air::q77::observe_verification(
        relation,
        result.as_ref().map(VerifiedDeepProof::work).map_err(|_| ()),
    );
    result
}

/// Test diagnostic using the same decoder and complete verifier implementation.
#[cfg(test)]
pub(super) fn verify(
    relation: &impl DeepRelation,
    bytes: &[u8],
    max_proof_bytes: usize,
) -> Result<VerificationWork> {
    // Decode enforces byte, aggregate allocation/element and shape ceilings
    // before any transcript expansion or public AIR preparation below.
    let proof = deep_proof::decode(bytes, max_proof_bytes)?;
    Ok(verify_decoded(relation, &proof, bytes.len())?.work())
}

fn verify_decoded(
    relation: &impl DeepRelation,
    proof: &DeepProof,
    proof_bytes: usize,
) -> Result<VerifiedDeepProof> {
    let binding = Context::for_relation(relation).map_err(binding_error)?;
    verify_bound(relation, proof, proof_bytes, &binding)
}

/// Verify a decoded frame under a binding context other than the relation's
/// frozen one, for binding-mutation tests only. A proof must not verify
/// under any context that differs from the one it was built under.
#[cfg(test)]
pub(super) fn verify_under_binding_for_test(
    relation: &impl DeepRelation,
    bytes: &[u8],
    binding: &Context,
) -> Result<VerificationWork> {
    let proof = deep_proof::decode(bytes, deep_proof::MAX_FRAME_BYTES)?;
    Ok(verify_bound(relation, &proof, bytes.len(), binding)?.work())
}

/// The complete verification under one binding context: transcript replay,
/// the out-of-domain identity, authentication of every opening against the
/// committed roots, every fold and the whole terminal.
fn verify_bound(
    relation: &impl DeepRelation,
    proof: &DeepProof,
    proof_bytes: usize,
    binding: &Context,
) -> Result<VerifiedDeepProof> {
    let geometry = DeepGeometry::new()?;
    let mut transcript = Transcript::new(binding.clone());
    if transcript.challenge().map_err(binding_error)? != Message::Dummy {
        return Err(shape(
            "DEEP transcript must start with its complete dummy message",
        ));
    }
    transcript
        .commit_root(Oracle::Row, proof.row_root.as_fastpq())
        .map_err(binding_error)?;
    let alphas = fields(&mut transcript, CONSTRAINTS)?;
    transcript
        .commit_root(Oracle::QuotientAndMask, proof.quotient_root.as_fastpq())
        .map_err(binding_error)?;
    let z = fields(&mut transcript, 1)?[0];
    let composition = geometry.check_ood(
        relation.deep_relation(),
        &alphas,
        z,
        &proof.ood.current,
        &proof.ood.next,
        &proof.ood.quotient,
    )?;
    transcript
        .commit_ood(&proof.ood.current, &proof.ood.next, &proof.ood.quotient)
        .map_err(binding_error)?;
    let lambda = fields(&mut transcript, 1)?[0];
    let mut betas = [F::ZERO; 5];
    for (round, beta) in (0_u8..).zip(betas.iter_mut()) {
        transcript
            .commit_root(
                Oracle::Fri(round),
                proof.fri_roots[usize::from(round)].as_fastpq(),
            )
            .map_err(binding_error)?;
        *beta = fields(&mut transcript, 1)?[0];
    }
    transcript
        .commit_root(Oracle::Terminal, proof.fri_roots[5].as_fastpq())
        .map_err(binding_error)?;
    let Message::Queries(queries) = transcript.challenge().map_err(binding_error)? else {
        return Err(shape(
            "DEEP final transcript message must contain complete queries",
        ));
    };
    let queries: Vec<_> = queries.into_iter().map(|index| index as usize).collect();
    let plans = deep_proof::preflight(proof, &queries)?;
    let (initial_leaves, initial_parents) = authenticate(binding, proof, &plans)?;
    let (fold_checks, fri_leaves, fri_parents) = check_chains(
        &geometry,
        &composition,
        lambda,
        &betas,
        &queries,
        proof,
        binding,
        &plans,
    )?;
    let leaf_hashes = initial_leaves + fri_leaves;
    let parent_hashes = initial_parents + fri_parents;
    let work = VerificationWork {
        proof_bytes,
        air_evaluations: 1,
        leaf_hashes,
        parent_hashes,
        h_calls: leaf_hashes + parent_hashes + 9 + 1,
        verifier_messages: 10,
        g_tape_bytes: 30_920,
        fold_checks,
        terminal_values: proof.terminal.len(),
    };
    Ok(VerifiedDeepProof {
        row_root: proof.row_root,
        work,
    })
}

fn fields(transcript: &mut Transcript, expected: usize) -> Result<Vec<F>> {
    match transcript.challenge().map_err(binding_error)? {
        Message::Fields(values) if values.len() == expected => Ok(values),
        _ => Err(shape("DEEP transcript field message has another dimension")),
    }
}

fn authenticate(
    binding: &Context,
    proof: &DeepProof,
    plans: &OpeningPlans,
) -> Result<(usize, usize)> {
    let rows = proof
        .rows
        .iter()
        .map(|row| {
            let bytes: Vec<_> = row
                .values
                .iter()
                .flat_map(|value| value.to_le_bytes())
                .collect();
            binding
                .hash_leaf(Oracle::Row, row.index, &bytes)
                .map_err(binding_error)
        })
        .collect::<Result<Vec<_>>>()?;
    let mut parents = verify_tree(
        binding,
        Oracle::Row,
        &plans.initial,
        proof.row_root,
        &rows,
        &proof.row_siblings,
    )?;
    let pairs = proof
        .quotients
        .iter()
        .map(|pair| {
            let mut bytes = [0_u8; 96];
            bytes[..32].copy_from_slice(&pair.low.to_le_bytes());
            bytes[32..64].copy_from_slice(&pair.high.to_le_bytes());
            bytes[64..].copy_from_slice(&pair.composition_mask.to_le_bytes());
            binding
                .hash_leaf(Oracle::QuotientAndMask, pair.index, &bytes)
                .map_err(binding_error)
        })
        .collect::<Result<Vec<_>>>()?;
    parents += verify_tree(
        binding,
        Oracle::QuotientAndMask,
        &plans.initial,
        proof.quotient_root,
        &pairs,
        &proof.quotient_siblings,
    )?;
    let leaves = rows.len() + pairs.len();
    let terminal: Vec<_> = proof
        .terminal
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect();
    let terminal_leaf = binding
        .hash_leaf(Oracle::Terminal, 0, &terminal)
        .map_err(binding_error)?;
    parents += verify_tree(
        binding,
        Oracle::Terminal,
        &plans.terminal,
        proof.fri_roots[5],
        &[terminal_leaf],
        &[],
    )?;
    Ok((leaves + 1, parents))
}

fn verify_tree(
    binding: &Context,
    oracle: Oracle,
    plan: &MultiproofPlan,
    root: WireDigest,
    leaves: &[Digest],
    siblings: &[WireDigest],
) -> Result<usize> {
    let siblings: Vec<_> = siblings.iter().map(|value| value.as_fastpq()).collect();
    let work = plan.verify_parallel_with(
        root.as_fastpq(),
        leaves,
        &siblings,
        |level, index, left, right| {
            let level =
                u32::try_from(level).map_err(|_| shape("DEEP Merkle parent level exceeds u32"))?;
            let index =
                u32::try_from(index).map_err(|_| shape("DEEP Merkle parent index exceeds u32"))?;
            binding
                .hash_parent(oracle, level, index, left, right)
                .map_err(binding_error)
        },
    )?;
    Ok(work.parent_hashes)
}

// Called only after exact preflight, row/Q/R authentication and OOD checking.
// A layer stores at most q known values. Full reconstructed fibers never persist
// beyond their round; the proof supplies no omitted-coordinate selector.
#[allow(
    clippy::too_many_arguments,
    reason = "all authenticated protocol owners are explicit"
)]
fn check_chains(
    geometry: &DeepGeometry,
    composition: &DeepComposition,
    lambda: F,
    betas: &[F; 5],
    queries: &[usize],
    proof: &DeepProof,
    binding: &Context,
    plans: &OpeningPlans,
) -> Result<(usize, usize, usize)> {
    walk_chains(
        geometry,
        composition,
        lambda,
        betas,
        queries,
        proof,
        binding,
        plans,
        |round, oracle, digests| {
            verify_tree(
                binding,
                oracle,
                &plans.rounds[round],
                proof.fri_roots[round],
                digests,
                &proof.rounds[round].siblings,
            )
        },
    )
}
#[allow(
    clippy::too_many_arguments,
    reason = "fixed reconstruction dependencies and internal authentication callback"
)]
fn walk_chains(
    geometry: &DeepGeometry,
    composition: &DeepComposition,
    lambda: F,
    betas: &[F; 5],
    queries: &[usize],
    proof: &DeepProof,
    binding: &Context,
    plans: &OpeningPlans,
    mut authenticate_round: impl FnMut(usize, Oracle, &[Digest]) -> Result<usize>,
) -> Result<(usize, usize, usize)> {
    let mut domain = geometry.domain();
    let mut known = Vec::with_capacity(QUERY_COUNT);
    for (ordinal, &index) in queries.iter().enumerate() {
        let pair = &proof.quotients[ordinal];
        let value = composition
            .base_value_at(
                domain.point(index),
                &proof.rows[ordinal].values,
                &[pair.low, pair.high],
                lambda,
            )?
            .mul(lambda)
            .add(pair.composition_mask);
        known.push((index, value));
    }
    let mut checks = 0;
    let mut leaves = 0;
    let mut parents = 0;
    for (round, &arity) in FRI_ARITIES.iter().enumerate() {
        let next_len = FRI_LENGTHS[round + 1];
        let fold = FriFoldPlan::new(arity, domain.coset_generator(next_len))?;
        let oracle = Oracle::Fri(u8::try_from(round).expect("five rounds"));
        let mut digests = Vec::with_capacity(plans.round_indices[round].len());
        let mut next = Vec::with_capacity(plans.round_indices[round].len());
        for group in &proof.rounds[round].groups {
            let group_index = group.index as usize;
            let first = known
                .iter()
                .find(|(index, _)| index % next_len == group_index)
                .ok_or_else(|| shape("compact FRI group has no incoming edge"))?;
            let omitted = plans.omitted_coordinate(round, group_index)?;
            if first.0 / next_len != omitted {
                return Err(shape(
                    "compact FRI omission differs from canonical incoming index",
                ));
            }
            let full = group.values.expand(omitted, first.1)?;
            // Retain every incoming equality, including nonomitted coordinates
            // when multiple queries enter the same authenticated fiber.
            for &(index, value) in &known {
                if index % next_len == group_index {
                    if full[index / next_len] != value {
                        return Err(shape(
                            "DEEP composition or folded value differs from its authenticated fiber",
                        ));
                    }
                    checks += 1;
                }
            }
            let mut bytes = [0; 16 * F::BYTES];
            for (target, value) in bytes.chunks_exact_mut(F::BYTES).zip(&full[..arity]) {
                target.copy_from_slice(&value.to_le_bytes());
            }
            digests.push(
                binding
                    .hash_leaf(oracle, group.index, &bytes[..arity * F::BYTES])
                    .map_err(binding_error)?,
            );
            next.push((
                group_index,
                fold.fold_coset(&full[..arity], betas[round], domain.point(group_index))?,
            ));
        }
        parents += authenticate_round(round, oracle, &digests)?;
        leaves += digests.len();
        known = next;
        domain = domain.folded(arity);
    }
    check_terminal_degree(domain, &proof.terminal)?;
    for (index, value) in known {
        if proof.terminal[index] != value {
            return Err(shape(
                "DEEP final folded value differs from its authenticated terminal",
            ));
        }
    }
    Ok((checks, leaves, parents))
}

/// Require all authenticated values to lie on one polynomial over the folded coset.
fn check_terminal_degree(domain: super::FriDomain, terminal: &[F]) -> Result<()> {
    if !domain.evaluations_have_degree_below(terminal, FRI_DEGREES[5])? {
        return Err(shape(
            "DEEP terminal does not represent a degree-below-two polynomial",
        ));
    }
    Ok(())
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "point-free `Result::map_err` adapter, which always hands the error over by value"
)]
fn binding_error(error: BindingError) -> Error {
    Error::InvalidTraceShape {
        details: format!("DEEP binding: {error}"),
    }
}

fn shape(details: &'static str) -> Error {
    Error::InvalidTraceShape {
        details: details.to_owned(),
    }
}

#[cfg(test)]
#[path = "deep_engine/tests.rs"]
mod tests;
