//! Complete-effect ordinary carrier using the canonical cumulative decode and proof accounting.
//!
//! The source leaf and statement expectations are supplied independently by the
//! caller. A decoded carrier has no authority, and every ordered segment must
//! verify before a result exposes any row commitment.
//! TODO: qualify the complete-effect source-to-artifact route with fresh native
//! proofs and resource measurements; prior transfer-only measurements do not
//! qualify this distinct relation or its complete source context.

use super::*;
use crate::{
    backend::compact_execution_effect_batch::{EffectBatchLimits, ExecutionEffectBatch},
    gadgets::public_transfer_statement::execution_effect::{
        ExecutionEffectExpectations, ExecutionEffectLimits, SourceExecutionEffectStatement,
    },
};
use iroha_allocation::{AllocationBudget, AllocationReservation};
use iroha_data_model::fastpq::FastpqOrdinarySourceStatementLeafV1;

/// Sole complete-effect carrier; ordinary transfer and AXT frames cannot decode here.
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(
    name = "fastpq_prover::backend::compact_bundle::execution_effect::EffectBundleWire",
    frame = "fastpq_prover::compact_v1::ExecutionEffectBundleV1"
)]
pub(in crate::backend) struct EffectBundleWire {
    pub(in crate::backend) version: u16,
    pub(in crate::backend) intermediate_roots: Vec<[u8; 32]>,
    pub(in crate::backend) segments: Vec<Vec<u8>>,
}

/// Original offered view and independently authenticated source expectations.
pub(in crate::backend) struct EffectVerificationInputs<'a, 'b> {
    pub(in crate::backend) statement: &'a SourceExecutionEffectStatement<'b>,
    pub(in crate::backend) source: &'a FastpqOrdinarySourceStatementLeafV1,
    pub(in crate::backend) expected: ExecutionEffectExpectations,
}

/// Public, per-child and cumulative policy remain separate explicit ceilings.
#[derive(Clone, Copy)]
pub(in crate::backend) struct EffectVerificationLimits {
    pub(in crate::backend) public: ExecutionEffectLimits,
    pub(in crate::backend) bundle: BundleLimits,
    pub(in crate::backend) max_segment_decode_allocation_charges: usize,
}

/// Serialize the exact bounded effect carrier without asserting proof validity.
#[cfg(test)]
pub(in crate::backend) fn encode(
    wire: &EffectBundleWire,
    count: usize,
    limits: BundleLimits,
) -> Result<Vec<u8>> {
    encode_parts(
        wire.version,
        &wire.intermediate_roots,
        &wire.segments,
        count,
        limits,
    )
}

struct Roots<'a>(&'a [[u8; 32]]);
impl norito::SerializePayload for Roots<'_> {
    fn serialize(
        &self,
        writer: &mut norito::core::Encoder<'_>,
    ) -> std::result::Result<(), norito::Error> {
        norito::core::write_element_sequence::<[u8; 32], _>(writer, self.0.iter())
    }
}
struct Segments<'a>(&'a [Vec<u8>]);
impl norito::SerializePayload for Segments<'_> {
    fn serialize(
        &self,
        writer: &mut norito::core::Encoder<'_>,
    ) -> std::result::Result<(), norito::Error> {
        norito::core::write_element_sequence::<Vec<u8>, _>(writer, self.0.iter())
    }
}
#[derive(norito::SerializePayload, norito::NoritoSchema)]
#[norito_schema(
    name = "fastpq_prover::backend::compact_bundle::execution_effect::BorrowedEffectBundle",
    frame = "fastpq_prover::compact_v1::ExecutionEffectBundleV1"
)]
struct BorrowedEffectBundle<'a> {
    version: u16,
    intermediate_roots: Roots<'a>,
    segments: Segments<'a>,
}
/// Encode the same carrier directly from original charged roots and retained child frames.
/// No root or child-frame clone is introduced to create the canonical output.
pub(in crate::backend) fn encode_parts(
    version: u16,
    roots: &[[u8; 32]],
    segments: &[Vec<u8>],
    count: usize,
    limits: BundleLimits,
) -> Result<Vec<u8>> {
    preflight_wire_parts(version, roots, segments, count, limits)?;
    let wire = BorrowedEffectBundle {
        version,
        intermediate_roots: Roots(roots),
        segments: Segments(segments),
    };
    check_limit(
        "max_bundle_wire_bytes",
        norito::canonical_frame_len(&wire)?,
        limits.max_wire_bytes,
    )?;
    Ok(norito::encode_canonical(&wire)?)
}

/// Complete verification reuses unchanged parent decode/query/byte/work controls.
pub(in crate::backend) fn verify(
    inputs: &EffectVerificationInputs<'_, '_>,
    bytes: &[u8],
    policy: EffectVerificationLimits,
    budget: &AllocationBudget,
    reservation: &mut AllocationReservation,
) -> Result<VerifiedBundle> {
    if !reservation.belongs_to(budget) {
        return Err(Error::AllocationForeignPool);
    }
    let limits = policy.bundle;
    check_limit("max_bundle_wire_bytes", bytes.len(), limits.max_wire_bytes)?;
    let count = inputs.statement.effects().effects.len();
    let verifier = DeepVerifier {
        max_decode_allocation_charges: policy.max_segment_decode_allocation_charges,
    };
    preflight_count_for(count, limits, verifier)?;
    let rows = count
        .checked_mul(2)
        .ok_or_else(|| shape("effect participant count overflows"))?;
    check_limit("max_transitions", rows, limits.segment.max_transitions)?;
    check_limit(
        "max_batch_bytes",
        norito::canonical_frame_len(inputs.statement)?,
        limits.segment.max_batch_bytes,
    )?;
    norito::core::with_decode_limits_scope(
        DecodeLimits::new(
            usize::MAX,
            usize::MAX,
            usize::MAX,
            limits.max_total_decode_allocation_charges,
            MAX_DECODE_DEPTH,
        ),
        || {
            let wire: EffectBundleWire = norito::decode_canonical_with_limits(
                bytes,
                wire_decode_limits_for(bytes, count, limits, verifier)?,
            )?;
            preflight_wire_parts_for(
                wire.version,
                &wire.intermediate_roots,
                &wire.segments,
                count,
                limits,
                verifier,
            )?;
            let batch = ExecutionEffectBatch::new(
                inputs.statement,
                inputs.source,
                inputs.expected,
                &wire.intermediate_roots,
                EffectBatchLimits {
                    public: policy.public,
                    context: BatchContextLimits {
                        max_segments: limits.max_segments,
                        max_total_statement_bytes: limits.max_total_statement_bytes,
                    },
                },
                budget,
                reservation,
            )?;
            check_limit(
                "max_compact_statement_bytes",
                batch.max_statement_bytes(),
                limits.segment.max_batch_bytes,
            )?;
            let mut work = BundleVerificationWork::default();
            let mut row_roots = Vec::with_capacity(count);
            for (ordinal, frame) in wire.segments.iter().enumerate() {
                let relation = batch.segment(ordinal)?;
                let child = verifier.verify_frame_committed(&relation, frame, limits.segment)?;
                add_work(&mut work, BundleVerificationWork::from_deep(child.work())?)?;
                row_roots.push(child.row_root());
            }
            let public = inputs.expected.public_inputs;
            Ok(VerifiedBundle {
                public_io: PublicIO {
                    dsid: public.dsid,
                    slot: public.slot,
                    old_root: public.old_root,
                    new_root: public.new_root,
                    perm_root: public.perm_root,
                    tx_set_hash: public.tx_set_hash,
                    ordering_hash: inputs.statement.ordering_hash(),
                },
                segments: count,
                wire_bytes: bytes.len(),
                statement_bytes: batch.total_statement_bytes(),
                work,
                row_roots,
            })
        },
    )
}

#[cfg(test)]
#[path = "execution_effect/tests.rs"]
mod tests;
