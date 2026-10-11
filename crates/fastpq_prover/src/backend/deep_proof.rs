//! Canonical bounded wire owner for the masked DEEP compact protocol.
//!
//! This DTO fixes 301 retained columns, 77 initial queries, a paired quotient plus composition mask,
//! five folds [16,16,8,8,4], fixed raw FRI fibers, and all 128 terminal values. Minimal frontiers derive
//! from sorted unique positions; a distinct frame admits no legacy fallback.
//! Decoding checks bytes and cumulative resource budgets before shape preflight.
//!
//! The verifier binds this DTO to its transcript, public statement, OOD/AIR
//! checks and authenticated openings. TODO: Independently qualify the integrated
//! protocol and source-context authentication.
//! Successful decode or shape preflight is not proof verification. In particular,
//! the verifier must compare the positions to its own final transcript challenge.

use std::collections::BTreeSet;

use iroha_data_model::fastpq::FastpqCommitmentV1 as Digest;
use norito::{DecodeLimits, NoritoDeserialize, NoritoSerialize};

use super::{
    compact_public_columns::COMMITTED_COLUMN_COUNT,
    deep_geometry::FRI_LENGTHS,
    merkle_multiproof::{MultiproofLimits, MultiproofPlan},
    polynomial_field::PolynomialField,
};
use crate::{Error, GoldilocksFp4V1 as Fp4, Result};

#[path = "deep_proof/row_values.rs"]
mod row_values;
pub(super) use row_values::RowValues;
#[path = "deep_proof/fri_values.rs"]
mod fri_values;
pub(super) use fri_values::FriValues;

pub(super) use super::deep_geometry::{FRI_ARITIES as ARITIES, LDE_ROWS, QUERY_COUNT};
/// Merkle leaf counts for the five grouped FRI commitments.
pub(super) const GROUP_LEAVES: [usize; 5] = [
    FRI_LENGTHS[1],
    FRI_LENGTHS[2],
    FRI_LENGTHS[3],
    FRI_LENGTHS[4],
    FRI_LENGTHS[5],
];
/// Full terminal vector, checked by the eventual verifier rather than sampled.
pub(super) const TERMINAL_VALUES: usize = FRI_LENGTHS[5];
/// Exact serialized upper envelope for the fixed canonical DTO.
pub(super) const MAX_FRAME_BYTES: usize = 500_084;
/// Existing production-sized single-proof byte target; this is not admission.
pub(super) const PROOF_BYTE_TARGET: usize = 512 * 1024;
/// Fixed maximum cumulative Norito allocation charges for one proof decode.
pub(super) const MAX_ALLOCATION_CHARGES: usize = 8 * 1024 * 1024;
/// Longest single sequence a maximal frame holds.
pub(super) const MAX_SEQUENCE_ELEMENTS: usize = 1283;
/// Cumulative sequence elements of a maximal frame.
pub(super) const MAX_TOTAL_ELEMENTS: usize = 6182;
/// Deepest nesting admitted while decoding one frame.
pub(super) const MAX_DECODE_DEPTH: usize = 16;

/// Sole canonical frame for the proposed DEEP proof layout.
#[derive(Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "fastpq_prover::backend::deep_proof::DeepProof",
    frame = "fastpq_prover::deep_compact::Sha3MaskedCompositionProofV1"
)]
pub(super) struct DeepProof {
    pub(super) row_root: Digest,
    pub(super) quotient_root: Digest,
    pub(super) fri_roots: Vec<Digest>,
    pub(super) ood: OodAnswers,
    pub(super) rows: Vec<RowOpening>,
    pub(super) quotients: Vec<QuotientMaskOpening>,
    pub(super) row_siblings: Vec<Digest>,
    pub(super) quotient_siblings: Vec<Digest>,
    pub(super) rounds: Vec<FriRound>,
    pub(super) terminal: Vec<Fp4>,
}

/// Ordered claims at z and g*z, followed by the two quotient halves at z.
#[derive(Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
pub(super) struct OodAnswers {
    pub(super) current: Vec<Fp4>,
    pub(super) next: Vec<Fp4>,
    pub(super) quotient: Vec<Fp4>,
}

/// One complete retained base-field row at an initial query position.
#[derive(Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
pub(super) struct RowOpening {
    pub(super) index: u32,
    pub(super) values: RowValues,
}

/// Both quotient chunks and the composition mask authenticated at one query.
#[derive(Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
pub(super) struct QuotientMaskOpening {
    pub(super) index: u32,
    pub(super) low: Fp4,
    pub(super) high: Fp4,
    pub(super) composition_mask: Fp4,
}

/// Complete selected fibers and their canonical minimal Merkle frontier.
#[derive(Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
pub(super) struct FriRound {
    pub(super) groups: Vec<FriGroup>,
    pub(super) siblings: Vec<Digest>,
}

/// One ordered fiber; the round's fixed arity determines its exact value count.
#[derive(Clone, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
pub(super) struct FriGroup {
    pub(super) index: u32,
    pub(super) values: FriValues,
}

/// Fixed-profile plans, derived from caller-owned transcript query positions.
pub(super) struct OpeningPlans {
    /// Same initial positions and shape for row and quotient-pair commitments.
    pub(super) initial: MultiproofPlan,
    /// Ordered positions for each folded domain, independent of proof metadata.
    pub(super) round_indices: [Vec<usize>; 5],
    /// Exact minimal frontiers for the five grouped FRI trees.
    pub(super) rounds: [MultiproofPlan; 5],
    /// Whole terminal is one leaf with its existing duplicate-child parent rule.
    pub(super) terminal: MultiproofPlan,
}

fn shape(details: &'static str) -> Error {
    Error::InvalidTraceShape {
        details: details.to_owned(),
    }
}

fn limit(name: &'static str, actual: usize, maximum: usize) -> Result<()> {
    if actual > maximum {
        return Err(Error::VerifierLimitExceeded {
            limit: name,
            actual,
            max: maximum,
        });
    }
    Ok(())
}

#[cfg(test)]
fn maximum_siblings(leaves: usize, selected: usize) -> usize {
    let depth = leaves.ilog2() as usize;
    (0..depth)
        .map(|level| selected.min(1 << level))
        .sum::<usize>()
        - selected
        + 1
}

fn plan(leaves: usize, indices: &[usize]) -> Result<MultiproofPlan> {
    let depth = (leaves.ilog2() as usize).max(1);
    MultiproofPlan::new(
        leaves,
        indices,
        MultiproofLimits {
            max_depth: 23,
            max_queried_leaves: QUERY_COUNT,
            max_siblings: QUERY_COUNT * depth,
            max_parent_hashes: QUERY_COUNT * depth,
        },
    )
}

impl OpeningPlans {
    /// The smallest independently known incoming index selects the omitted cell.
    /// No selector is supplied by the proof, and every shared incoming edge is checked.
    pub(super) fn omitted_coordinate(&self, round: usize, group: usize) -> Result<usize> {
        let incoming = if round == 0 {
            self.initial.queried_indices()
        } else {
            self.round_indices
                .get(round - 1)
                .ok_or_else(|| shape("FRI round outside fixed geometry"))?
        };
        let next = *GROUP_LEAVES
            .get(round)
            .ok_or_else(|| shape("FRI round outside fixed geometry"))?;
        incoming
            .iter()
            .find(|&&index| index % next == group)
            .map(|index| index / next)
            .ok_or_else(|| shape("FRI group has no incoming known coordinate"))
    }
    /// Validate exactly 77 sorted unique initial positions, then derive all groups.
    pub(super) fn new(queries: &[usize]) -> Result<Self> {
        if queries.len() != QUERY_COUNT {
            return Err(shape("DEEP proof needs exactly 77 initial query positions"));
        }
        let initial = plan(LDE_ROWS, queries)?;
        let mut current = queries.to_vec();
        let round_indices = core::array::from_fn(|round| {
            current = current
                .iter()
                .map(|index| index % GROUP_LEAVES[round])
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            current.clone()
        });
        let rounds = round_indices
            .iter()
            .enumerate()
            .map(|(round, indices)| plan(GROUP_LEAVES[round], indices))
            .collect::<Result<Vec<_>>>()?
            .try_into()
            .expect("five fixed rounds");
        Ok(Self {
            initial,
            round_indices,
            rounds,
            terminal: plan(1, &[0])?,
        })
    }
}

fn canonical(values: &[Fp4], length: usize, context: &'static str) -> Result<()> {
    if values.len() != length {
        return Err(shape("DEEP field vector has another fixed length"));
    }
    for (index, &value) in values.iter().enumerate() {
        value.validate(context, &[index])?;
    }
    Ok(())
}

fn exact_indices(actual: impl Iterator<Item = u32>, expected: &[usize]) -> Result<()> {
    if !actual
        .map(|index| index as usize)
        .eq(expected.iter().copied())
    {
        return Err(shape(
            "DEEP opening positions differ from the exact derived query set",
        ));
    }
    Ok(())
}

/// Check dimensions/canonical values and exact transcript-derived minimal shapes.
///
/// `queries` must come from the verifier's final transcript challenge. This
/// performs no transcript, hash, AIR, OOD, or terminal-polynomial verification.
pub(super) fn preflight(proof: &DeepProof, queries: &[usize]) -> Result<OpeningPlans> {
    if proof.fri_roots.len() != 6 || proof.rounds.len() != 5 {
        return Err(shape(
            "DEEP proof has another FRI commitment or round count",
        ));
    }
    canonical(
        &proof.ood.current,
        COMMITTED_COLUMN_COUNT,
        "deep_ood_current",
    )?;
    canonical(&proof.ood.next, COMMITTED_COLUMN_COUNT, "deep_ood_next")?;
    canonical(&proof.ood.quotient, 2, "deep_ood_quotient")?;
    canonical(&proof.terminal, TERMINAL_VALUES, "deep_terminal")?;
    let plans = OpeningPlans::new(queries)?;
    exact_indices(proof.rows.iter().map(|row| row.index), queries)?;
    exact_indices(proof.quotients.iter().map(|row| row.index), queries)?;
    for row in &proof.rows {
        row.values.validate()?;
    }
    for row in &proof.quotients {
        row.low
            .validate("deep_quotient_low", &[row.index as usize])?;
        row.high
            .validate("deep_quotient_high", &[row.index as usize])?;
        row.composition_mask
            .validate("deep_composition_mask", &[row.index as usize])?;
    }
    if proof.row_siblings.len() != plans.initial.work().siblings
        || proof.quotient_siblings.len() != plans.initial.work().siblings
    {
        return Err(shape("DEEP initial frontier is not minimal and exact"));
    }
    for (round, proof_round) in proof.rounds.iter().enumerate() {
        exact_indices(
            proof_round.groups.iter().map(|group| group.index),
            &plans.round_indices[round],
        )?;
        if proof_round.siblings.len() != plans.rounds[round].work().siblings {
            return Err(shape("DEEP FRI frontier is not minimal and exact"));
        }
        for group in &proof_round.groups {
            if group.values.arity() != ARITIES[round] {
                return Err(shape("compact FRI fiber arity differs from fixed round"));
            }
            canonical(&group.values, ARITIES[round] - 1, "deep_fri_group")?;
        }
    }
    Ok(plans)
}

/// Exact finite aggregate limits for the sole canonical DTO, before raw decoding.
#[cfg(test)]
pub(super) fn decode_limits(frame_bytes: usize) -> DecodeLimits {
    decode_limits_with_allocation(frame_bytes, MAX_ALLOCATION_CHARGES)
}

fn decode_limits_with_allocation(frame_bytes: usize, allocation_charges: usize) -> DecodeLimits {
    DecodeLimits::new(
        MAX_SEQUENCE_ELEMENTS,
        frame_bytes,
        MAX_TOTAL_ELEMENTS,
        allocation_charges.min(MAX_ALLOCATION_CHARGES),
        MAX_DECODE_DEPTH,
    )
}

/// Decode the canonical masked frame inside the fixed profile and caller byte ceiling.
///
/// The byte check precedes header/checksum parsing. Sequence/allocation/depth
/// budgets remain active through canonical re-encoding. The proof's positions
/// are checked for internal shape only: final verification must call `preflight`
/// again with independently transcript-derived positions after replay.
#[cfg(test)]
pub(super) fn decode(bytes: &[u8], caller_max_bytes: usize) -> Result<DeepProof> {
    decode_with_allocation(bytes, caller_max_bytes, MAX_ALLOCATION_CHARGES)
}

/// Canonical decode with the stricter caller/profile allocation-charge ceiling.
/// Enclosing request scopes remain cumulative and cannot be reset by this call.
pub(super) fn decode_with_allocation(
    bytes: &[u8],
    caller_max_bytes: usize,
    allocation_charges: usize,
) -> Result<DeepProof> {
    limit(
        "max_proof_bytes",
        bytes.len(),
        caller_max_bytes.min(MAX_FRAME_BYTES),
    )?;
    let proof: DeepProof = norito::decode_canonical_with_limits(
        bytes,
        decode_limits_with_allocation(bytes.len(), allocation_charges),
    )?;
    if proof.rows.len() != QUERY_COUNT {
        return Err(shape("DEEP proof needs exactly 77 complete retained rows"));
    }
    let positions: Vec<_> = proof.rows.iter().map(|row| row.index as usize).collect();
    preflight(&proof, &positions)?;
    Ok(proof)
}

/// Exact maximum framed bytes derived from the implemented Norito DTO's fields.
///
/// Each frontier maximum is attainable simultaneously by the linked query set
/// in the size test. Fixed field payload lengths do not depend on scalar values.
#[cfg(test)]
pub(super) fn maximum_frame_bytes() -> usize {
    let field = |payload| {
        payload
            + norito::core::len_prefix_len_with_flags(payload, norito::core::default_encode_flags())
    };
    let vector = |count, payload| 8 + count * field(payload);
    let row = field(4) + field(RowValues::BYTES);
    let quotient = field(4) + 3 * field(Fp4::BYTES);
    let ood = 2 * field(vector(COMMITTED_COLUMN_COUNT, Fp4::BYTES)) + field(vector(2, Fp4::BYTES));
    let rounds = 8 + ARITIES
        .iter()
        .enumerate()
        .map(|(round, &arity)| {
            let group = field(4) + field(FriValues::encoded_bytes(arity));
            field(
                field(vector(QUERY_COUNT, group))
                    + field(vector(
                        maximum_siblings(GROUP_LEAVES[round], QUERY_COUNT),
                        Digest::BYTES,
                    )),
            )
        })
        .sum::<usize>();
    norito::core::Header::SIZE
        + [
            Digest::BYTES,
            Digest::BYTES,
            vector(6, Digest::BYTES),
            ood,
            vector(QUERY_COUNT, row),
            vector(QUERY_COUNT, quotient),
            vector(maximum_siblings(LDE_ROWS, QUERY_COUNT), Digest::BYTES),
            vector(maximum_siblings(LDE_ROWS, QUERY_COUNT), Digest::BYTES),
            rounds,
            vector(TERMINAL_VALUES, Fp4::BYTES),
        ]
        .into_iter()
        .map(field)
        .sum::<usize>()
}

#[cfg(test)]
#[path = "deep_proof/tests.rs"]
mod tests;
