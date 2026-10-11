//! Sequential ordinary proving from one borrowed original complete-effect statement.

use super::*;
use crate::{
    backend::{
        compact_bundle::execution_effect as bundle,
        compact_execution_effect_batch::{EffectBatchLimits, ExecutionEffectBatch},
        offline_compact::{
            ExecutionEffectVerificationLimits, ExpectedExecutionEffects,
            execution_effect_profile_id, quantity_ordinary_allocation_bytes,
            verify_quantity_ordinary_artifact,
        },
    },
    gadgets::public_transfer_statement::execution_effect::{
        SourceExecutionEffectStatement, prepare_source_execution_effect_view,
    },
};
use iroha_allocation::ChargedBuffer;
use iroha_data_model::fastpq::{FastpqCompactProfileIdV1, FastpqOrdinarySourceStatementLeafV1};

struct Field<'a, T>(&'a T);
impl<T: norito::SerializePayload> norito::SerializePayload for Field<'_, T> {
    fn serialize(
        &self,
        writer: &mut norito::core::Encoder<'_>,
    ) -> std::result::Result<(), norito::Error> {
        self.0.serialize(writer)
    }
}
struct Bytes<'a>(&'a [u8]);
impl norito::SerializePayload for Bytes<'_> {
    fn serialize(
        &self,
        writer: &mut norito::core::Encoder<'_>,
    ) -> std::result::Result<(), norito::Error> {
        norito::SerializePayload::serialize(&self.0, writer)
    }
}
/// Encode-only projection of the single canonical model layout, not a second accepted wire.
#[derive(norito::SerializePayload, norito::NoritoSchema)]
#[norito_schema(
    name = "fastpq_prover::backend::compact_quantity_producer::execution_effect::BorrowedArtifact",
    frame = "iroha_data_model::fastpq::FastpqOrdinaryCompactArtifactV1"
)]
struct BorrowedArtifact<'a, 'b> {
    profile_id: FastpqCompactProfileIdV1,
    source: Field<'a, FastpqOrdinarySourceStatementLeafV1>,
    statement: Field<'a, SourceExecutionEffectStatement<'b>>,
    bundle_frame: Bytes<'a>,
}
fn artifact<'a, 'b>(
    statement: &'a SourceExecutionEffectStatement<'b>,
    source: &'a FastpqOrdinarySourceStatementLeafV1,
    bundle: &'a [u8],
) -> BorrowedArtifact<'a, 'b> {
    BorrowedArtifact {
        profile_id: execution_effect_profile_id(),
        source: Field(source),
        statement: Field(statement),
        bundle_frame: Bytes(bundle),
    }
}
fn preflight(
    statement: &SourceExecutionEffectStatement<'_>,
    expected: ExpectedExecutionEffects<'_>,
    proving: ProvingLimits,
    limits: &ExecutionEffectVerificationLimits,
) -> Result<usize> {
    let count = statement.effects().effects.len();
    let public = limits.public_policy();
    check("max_execution_effects", count, public.max_effects)?;
    let rows = count
        .checked_mul(2)
        .ok_or_else(|| invalid("effect participant count overflows"))?;
    check("max_execution_effect_rows", rows, public.max_rows)?;
    check(
        "max_transitions",
        rows,
        limits.bundle.segment.max_transitions,
    )?;
    let policy = limits.proof_policy();
    let plan = quantity_artifact_resources(count, 0)?;
    plan.check_proving_limits(proving, policy)?;
    decode_policy::preflight_decode_policy(count, &policy)?;
    let length = norito::canonical_frame_len(statement)?;
    check(
        "max_compact_producer_statement_bytes",
        length,
        public.max_public_bytes,
    )?;
    check(
        "max_batch_bytes",
        length,
        limits.bundle.segment.max_batch_bytes,
    )?;
    if statement.digest(public.max_public_bytes)? != expected.statement.statement_digest {
        return Err(Error::PublicIoMismatch {
            field: "compact_public_statement_digest",
        });
    }
    let empty = norito::canonical_frame_len(&artifact(statement, expected.source, &[]))?;
    check(
        "max_compact_producer_artifact_bytes",
        add(empty, add(plan.maximum_bundle_frame_bytes, 32)?)?,
        limits.transport.max_wire_bytes,
    )?;
    Ok(count)
}

#[cfg(test)]
pub(super) fn preflight_for_test(
    statement: &SourceExecutionEffectStatement<'_>,
    expected: ExpectedExecutionEffects<'_>,
    proving: ProvingLimits,
    limits: &ExecutionEffectVerificationLimits,
) -> Result<usize> {
    preflight(statement, expected, proving, limits)
}

// The single final encoding path is also directly exercised at exact byte limits.
pub(super) fn encode_artifact(
    statement: &SourceExecutionEffectStatement<'_>,
    source: &FastpqOrdinarySourceStatementLeafV1,
    bundle: &[u8],
    limits: &ExecutionEffectVerificationLimits,
) -> Result<Vec<u8>> {
    check(
        "max_compact_producer_bundle_bytes",
        bundle.len(),
        limits.transport.max_bundle_frame_bytes,
    )?;
    let wire = artifact(statement, source, bundle);
    check(
        "max_compact_producer_artifact_bytes",
        norito::canonical_frame_len(&wire)?,
        limits.transport.max_wire_bytes,
    )?;
    norito::encode_canonical(&wire).map_err(Error::from)
}

pub(in crate::backend) fn prove(
    statement: &SourceExecutionEffectStatement<'_>,
    expected: ExpectedExecutionEffects<'_>,
    proving: ProvingLimits,
    limits: &ExecutionEffectVerificationLimits,
    budget: &AllocationBudget,
    reservation: &mut AllocationReservation,
) -> std::result::Result<(Vec<u8>, crate::offline_compact::VerifiedArtifact), ProvingError> {
    if !reservation.belongs_to(budget) {
        return Err(Error::AllocationForeignPool.into());
    }
    let _exclusive = acquire(&PRODUCER)?;
    let _canonical = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let count = preflight(statement, expected, proving, limits)?;
    let demand = quantity_ordinary_allocation_bytes(statement.effects(), proving, limits)?;
    let mut credit = reservation
        .try_partition_bytes(demand)
        .map_err(Error::from)?;
    crate::digest384_batch::preflight_last_fields_execution(proving.digest_execution)?;
    let bytes = {
        let prepared = prepare_source_execution_effect_view(
            statement,
            expected.source,
            expected.statement,
            limits.public_policy(),
            budget,
            &mut credit,
        )?;
        // Exact independently expected roots are retained; no local root replacement occurs here.
        let private = prepared.build_smt_witnesses(proving.private_smt, budget, &mut credit)?;
        if private.pairs().len() != count {
            return Err(invalid("effect private/public pair count differs").into());
        }
        drop(prepared);
        let mut roots =
            ChargedBuffer::from_reservation(count - 1, &mut credit).map_err(Error::from)?;
        for pair in private.pairs().iter().take(count - 1) {
            roots.push_reserved(pair[1].root_after);
        }
        let batch = ExecutionEffectBatch::new(
            statement,
            expected.source,
            expected.statement,
            roots.as_slice(),
            EffectBatchLimits {
                public: limits.public_policy(),
                context: BatchContextLimits {
                    max_segments: limits.bundle.max_segments,
                    max_total_statement_bytes: limits.bundle.max_total_statement_bytes,
                },
            },
            budget,
            &mut credit,
        )?;
        let frames = segments(
            batch.statements(),
            private.pairs(),
            |ordinal| batch.segment(ordinal),
            proving,
            limits.proof_policy(),
        )?;
        let bundle = bundle::encode_parts(
            1,
            roots.as_slice(),
            &frames,
            count,
            limits.bundle.internal(),
        )?;
        encode_artifact(statement, expected.source, &bundle, limits)?
    };
    let verified =
        verify_quantity_ordinary_artifact(&bytes, expected, limits, budget, &mut credit)?;
    Ok((bytes, verified))
}

#[cfg(test)]
#[path = "execution_effect/tests.rs"]
mod tests;
