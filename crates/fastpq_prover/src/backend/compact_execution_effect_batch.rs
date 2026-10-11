//! Complete-effect contexts for the shared private two-update SMT relation.
//!
//! Each segment binds the whole canonical effect statement, independent D7 source
//! leaf, complete root chain and exact ordinal before the first challenge. Public
//! arithmetic, lifecycle and chronology are checked before AIR construction.
//! Preparation, context and port backing retain original-pool custody. Inner
//! AIR statement scratch remains bounded by the existing per-statement ceiling.
//! The ordinary producer and artifact verifier consume this complete-effect batch;
//! source finality remains the caller's independent obligation.
//! TODO: qualify the composed finalized-source route with fresh native proofs;
//! prior transfer-only resource measurements do not qualify this relation.

#[cfg(test)]
use super::compact_protocol::PreparedAir;
use super::{
    compact_protocol::{FixedAir, FixedAirSchema},
    compact_public_batch::BatchContextLimits,
    compact_transfer_air::CompactTransferAir,
};
#[cfg(test)]
use crate::gadgets::public_transfer_statement::execution_effect::preparation_allocation_bytes;
use crate::{
    Error, Result, VerifyLimits,
    gadgets::{
        compact_smt_air::PublicStatement,
        public_transfer_statement::execution_effect::{
            ExecutionEffectExpectations, ExecutionEffectLimits, SourceExecutionEffectStatement,
            prepare_source_execution_effect_view,
        },
    },
};
use iroha_allocation::{AllocationBudget, AllocationReservation, ChargedBuffer};
use iroha_data_model::fastpq::FastpqOrdinarySourceStatementLeafV1;
use std::io::Write;
pub(super) const IDENTITY: &str =
    "fastpq:compact:v1:execution-effect-bundle-segment:v1:342cols:923slots:65536rows";

struct Field<'a, T>(&'a T);
impl<T: norito::SerializePayload> norito::SerializePayload for Field<'_, T> {
    fn serialize(
        &self,
        w: &mut norito::core::Encoder<'_>,
    ) -> std::result::Result<(), norito::Error> {
        self.0.serialize(w)
    }
}
struct Roots<'a>(&'a [[u8; 32]]);
impl norito::SerializePayload for Roots<'_> {
    fn serialize(
        &self,
        w: &mut norito::core::Encoder<'_>,
    ) -> std::result::Result<(), norito::Error> {
        norito::core::write_element_sequence::<[u8; 32], _>(w, self.0.iter())
    }
}
struct Bytes<'a>(&'a [u8]);
impl norito::SerializePayload for Bytes<'_> {
    fn serialize(
        &self,
        w: &mut norito::core::Encoder<'_>,
    ) -> std::result::Result<(), norito::Error> {
        norito::SerializePayload::serialize(&self.0, w)
    }
}
#[derive(norito::SerializePayload, norito::NoritoSchema)]
#[norito_schema(
    name = "fastpq_prover::backend::compact_execution_effect_batch::BoundBatchContext",
    frame = "fastpq_prover::compact_v1::ExecutionEffectBatchContextV1"
)]
struct BoundBatchContext<'a, 'b> {
    version: u16,
    segment_count: u32,
    source: Field<'a, FastpqOrdinarySourceStatementLeafV1>,
    statement: Field<'a, SourceExecutionEffectStatement<'b>>,
    intermediate_roots: Roots<'a>,
}
#[derive(norito::SerializePayload, norito::NoritoSchema)]
#[norito_schema(
    name = "fastpq_prover::backend::compact_execution_effect_batch::BoundSegmentContext",
    frame = "fastpq_prover::compact_v1::ExecutionEffectSegmentContextV1"
)]
struct BoundSegmentContext<'a> {
    version: u16,
    segment_count: u32,
    ordinal: u32,
    batch_context: Bytes<'a>,
}
/// Actual complete-effect context projections bound by the compiled profile.
pub(super) fn context_frame_hashes() -> [[u8; 16]; 2] {
    [
        norito::schema::identity::frame_hash::<BoundBatchContext<'static, 'static>>(),
        norito::schema::identity::frame_hash::<BoundSegmentContext<'static>>(),
    ]
}
/// Separate public preparation and cumulative context limits.
#[derive(Clone, Copy)]
pub(super) struct EffectBatchLimits {
    pub(super) public: ExecutionEffectLimits,
    pub(super) context: BatchContextLimits,
}
/// All checked public ports and the complete original context, with original credit.
pub(super) struct ExecutionEffectBatch {
    context: ChargedBuffer<u8>,
    statements: ChargedBuffer<PublicStatement>,
    total_statement_bytes: usize,
    max_statement_bytes: usize,
}
impl ExecutionEffectBatch {
    /// Test-only exact demand oracle for public preparation, ports and context.
    /// The facade reserves its conservative whole-operation demand once.
    /// This creates no backing and establishes no source or semantic authority.
    /// Bounded segment context/AIR Vec scratch is outside this demand.
    #[cfg(test)]
    pub(super) fn allocation_bytes(
        statement: &SourceExecutionEffectStatement<'_>,
        source: &FastpqOrdinarySourceStatementLeafV1,
        roots: &[[u8; 32]],
        limits: EffectBatchLimits,
    ) -> Result<usize> {
        let (count, public) = preflight(statement, roots, limits)?;
        let preparation = preparation_allocation_bytes(statement.effects(), public)?;
        let binding = BoundBatchContext {
            version: 1,
            segment_count: narrow(count)?,
            source: Field(source),
            statement: Field(statement),
            intermediate_roots: Roots(roots),
        };
        let length = norito::canonical_frame_len(&binding)?;
        check(
            "max_compact_statement_bytes",
            length,
            VerifyLimits::default().max_batch_bytes,
        )?;
        check(
            "max_compact_bundle_statement_bytes",
            mul(count, length)?,
            limits.context.max_total_statement_bytes,
        )?;
        let ports = std::alloc::Layout::array::<PublicStatement>(count)
            .map_err(|_| iroha_allocation::AllocationRefusal::DemandOverflow)?
            .size();
        add(add(preparation, ports)?, length)
    }

    /// Prepare a complete independently expected statement before constructing segments.
    pub(super) fn new(
        statement: &SourceExecutionEffectStatement<'_>,
        source: &FastpqOrdinarySourceStatementLeafV1,
        expected: ExecutionEffectExpectations,
        roots: &[[u8; 32]],
        limits: EffectBatchLimits,
        budget: &AllocationBudget,
        reservation: &mut AllocationReservation,
    ) -> Result<Self> {
        if !reservation.belongs_to(budget) {
            return Err(Error::AllocationForeignPool);
        }
        let (count, public) = preflight(statement, roots, limits)?;
        let fixed = ExecutionEffectLimits::default();
        let prepared = prepare_source_execution_effect_view(
            statement,
            source,
            expected,
            public,
            budget,
            reservation,
        )?;
        check(
            "max_execution_effect_bytes",
            prepared.work().public_bytes,
            fixed.max_public_bytes,
        )?;
        check(
            "max_execution_effect_keys",
            prepared.keys().len(),
            fixed.max_unique_keys,
        )?;
        check(
            "max_execution_effect_allocation_steps",
            prepared.work().allocation_steps,
            fixed.max_allocation_steps,
        )?;
        let statements = prepared.compact_statements(roots, budget, reservation)?;
        let binding = BoundBatchContext {
            version: 1,
            segment_count: narrow(count)?,
            source: Field(source),
            statement: Field(statement),
            intermediate_roots: Roots(roots),
        };
        let length = norito::canonical_frame_len(&binding)?;
        check(
            "max_compact_statement_bytes",
            length,
            VerifyLimits::default().max_batch_bytes,
        )?;
        check(
            "max_compact_bundle_statement_bytes",
            mul(count, length)?,
            limits.context.max_total_statement_bytes,
        )?;
        let mut context = ChargedBuffer::from_reservation(length, reservation)?;
        norito::core::write_canonical_to_writer(&binding, &mut BufferWriter(&mut context))?;
        if context.as_slice().len() != length {
            return Err(invalid(
                "effect context differs from measured canonical frame",
            ));
        }
        let mut result = Self {
            context,
            statements,
            total_statement_bytes: 0,
            max_statement_bytes: 0,
        };
        for ordinal in 0..count {
            let context = result.segment_context(ordinal)?;
            let bytes = CompactTransferAir::encoded_statement_len(
                &result.statements.as_slice()[ordinal],
                Some(&context),
            )?;
            result.total_statement_bytes = add(result.total_statement_bytes, bytes)?;
            result.max_statement_bytes = result.max_statement_bytes.max(bytes);
            check(
                "max_compact_bundle_statement_bytes",
                result.total_statement_bytes,
                limits.context.max_total_statement_bytes,
            )?;
        }
        Ok(result)
    }
    pub(super) fn statements(&self) -> &[PublicStatement] {
        self.statements.as_slice()
    }
    pub(super) const fn total_statement_bytes(&self) -> usize {
        self.total_statement_bytes
    }
    pub(super) const fn max_statement_bytes(&self) -> usize {
        self.max_statement_bytes
    }
    pub(super) fn segment(&self, ordinal: usize) -> Result<ExecutionEffectSegmentAir> {
        let statement =
            self.statements
                .as_slice()
                .get(ordinal)
                .ok_or(Error::QueryIndexOutOfRange {
                    index: ordinal,
                    len: self.statements.as_slice().len(),
                })?;
        let context = self.segment_context(ordinal)?;
        Ok(ExecutionEffectSegmentAir {
            inner: CompactTransferAir::new(statement, Some(&context))?,
        })
    }
    fn segment_context(&self, ordinal: usize) -> Result<Vec<u8>> {
        if ordinal >= self.statements.as_slice().len() {
            return Err(Error::QueryIndexOutOfRange {
                index: ordinal,
                len: self.statements.as_slice().len(),
            });
        }
        let bound = BoundSegmentContext {
            version: 1,
            segment_count: narrow(self.statements.as_slice().len())?,
            ordinal: narrow(ordinal)?,
            batch_context: Bytes(self.context.as_slice()),
        };
        check(
            "max_compact_statement_bytes",
            norito::canonical_frame_len(&bound)?,
            VerifyLimits::default().max_batch_bytes,
        )?;
        Ok(norito::encode_canonical(&bound)?)
    }
}
fn preflight(
    statement: &SourceExecutionEffectStatement<'_>,
    roots: &[[u8; 32]],
    limits: EffectBatchLimits,
) -> Result<(usize, ExecutionEffectLimits)> {
    let count = statement.effects().effects.len();
    let fixed = ExecutionEffectLimits::default();
    if count == 0 || roots.len() != count - 1 {
        return Err(invalid("complete effect bundle count/root chain mismatch"));
    }
    check(
        "max_compact_bundle_segments",
        count,
        limits.context.max_segments.min(fixed.max_effects),
    )?;
    check("max_execution_effect_rows", mul(count, 2)?, fixed.max_rows)?;
    // A caller may tighten each preparation cap, but cannot authorize
    // backing or work beyond the fixed relation's public defaults.
    let public = ExecutionEffectLimits {
        max_effects: limits.public.max_effects.min(fixed.max_effects),
        max_rows: limits.public.max_rows.min(fixed.max_rows),
        max_public_bytes: limits.public.max_public_bytes.min(fixed.max_public_bytes),
        max_unique_keys: limits.public.max_unique_keys.min(fixed.max_unique_keys),
        max_allocation_steps: limits
            .public
            .max_allocation_steps
            .min(fixed.max_allocation_steps),
    };
    Ok((count, public))
}

pub(super) struct ExecutionEffectSegmentAir {
    inner: CompactTransferAir,
}
impl super::deep_relation::sealed::Sealed for ExecutionEffectSegmentAir {}
impl super::deep_relation::DeepRelation for ExecutionEffectSegmentAir {
    fn deep_relation(&self) -> &CompactTransferAir {
        &self.inner
    }
}
impl FixedAir for ExecutionEffectSegmentAir {
    fn schema(&self) -> FixedAirSchema {
        FixedAirSchema {
            identity: IDENTITY,
            ..self.inner.schema()
        }
    }
    fn statement_bytes(&self) -> &[u8] {
        self.inner.statement_bytes()
    }
    #[cfg(test)]
    fn evaluate(&self, point: u64, current: &[u64], next: &[u64]) -> Result<Vec<u64>> {
        self.inner.evaluate(point, current, next)
    }
    #[cfg(test)]
    fn prepare_prover(&self) -> Result<Box<dyn PreparedAir + '_>> {
        self.inner.prepare_prover()
    }
}
struct BufferWriter<'a>(&'a mut ChargedBuffer<u8>);
impl Write for BufferWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.append(bytes)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn invalid(details: &'static str) -> Error {
    Error::TransferInvariant {
        details: details.to_owned(),
    }
}
fn narrow(value: usize) -> Result<u32> {
    u32::try_from(value).map_err(|_| invalid("effect count/ordinal exceeds u32"))
}
fn add(left: usize, right: usize) -> Result<usize> {
    left.checked_add(right)
        .ok_or_else(|| invalid("effect context bytes overflow"))
}
fn mul(left: usize, right: usize) -> Result<usize> {
    left.checked_mul(right)
        .ok_or_else(|| invalid("effect context bytes overflow"))
}
fn check(limit: &'static str, actual: usize, max: usize) -> Result<()> {
    if actual > max {
        Err(Error::VerifierLimitExceeded { limit, actual, max })
    } else {
        Ok(())
    }
}
#[cfg(test)]
#[path = "compact_execution_effect_batch/tests.rs"]
pub(super) mod tests;
