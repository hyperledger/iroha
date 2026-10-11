//! Finite complete-effect work borrowed from the actual native source owner.
use crate::{
    fastpq::finalized_source::AdmittedFinalizedFastpqSource, state::CapturedQuantityEntry,
};
use fastpq_prover::{
    gadgets::public_transfer_statement::execution_effect::{
        ExecutionEffectExpectations, SourceExecutionEffectMaterialization,
        materialization_allocation_bytes, materialize_source_execution_effect_statement,
    },
    offline_compact::{self, ExecutionEffectVerificationLimits, ProvingLimits},
};
use iroha_allocation::{AllocationRefusal, AllocationReservation};

/// Local refusal preserves the source; none changes block validity, D7 or native R.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SourceWorkError {
    /// Original archive or requested original entry is unavailable or inconsistent.
    #[error("original FASTPQ source entry is unavailable: {0:?}")]
    Source(crate::state::QuantityCaptureIssue),
    /// Exact original-pool refusal, including its original capacity/release observation.
    #[error(transparent)]
    Allocation(#[from] AllocationRefusal),
    /// Deterministic source, shape or finite materialization failure.
    #[error(transparent)]
    Preparation(#[from] fastpq_prover::Error),
}

/// One finite materialization and its remaining original prepaid proving admission.
/// Both original tape and leaf are borrowed directly from the native source owner.
/// Generated transition/path backing retains its charges until it is destroyed;
/// dropping generated allocations never refreshes this reservation.
pub(super) struct PreparedSourceEntry<'a> {
    pub(super) original: CapturedQuantityEntry<'a>,
    pub(super) materialized: SourceExecutionEffectMaterialization<'a>,
    pub(super) reservation: AllocationReservation,
    pub(super) expectations: ExecutionEffectExpectations,
}
/// Checked total consumed original credit before any materialization is attempted.
/// Proof payload/decode/RSS ceilings remain distinct; this is backing-credit demand.
pub(super) fn allocation_bytes(
    entry: &CapturedQuantityEntry<'_>,
    proving: ProvingLimits,
    verification: &ExecutionEffectVerificationLimits,
) -> Result<usize, SourceWorkError> {
    let materialize = materialization_allocation_bytes(
        entry.effects(),
        verification.public_statement,
        proving.private_smt,
    )?;
    let prove = offline_compact::quantity_ordinary_allocation_bytes(
        entry.effects(),
        proving,
        verification,
    )?;
    materialize
        .checked_add(prove)
        .ok_or(AllocationRefusal::DemandOverflow.into())
}

/// Independently derive touched-key roots and the full statement commitment from
/// original captured effects. No offered artifact, ambient World root template,
/// caller-supplied source context or replayed transcript supplies expectations.
pub(super) fn prepare<'a>(
    source: &'a AdmittedFinalizedFastpqSource,
    index: usize,
    proving: ProvingLimits,
    verification: &ExecutionEffectVerificationLimits,
) -> Result<PreparedSourceEntry<'a>, SourceWorkError> {
    let original = source.entry(index).map_err(SourceWorkError::Source)?;
    let bytes = allocation_bytes(&original, proving, verification)?;
    let mut reservation = original.pool().try_reserve_bytes(bytes)?;
    let materialized = materialize_source_execution_effect_statement(
        original.effects(),
        original.leaf(),
        verification.public_statement,
        proving.private_smt,
        original.pool(),
        &mut reservation,
    )?;
    let statement = materialized.statement();
    let expectations = ExecutionEffectExpectations {
        effects_digest: iroha_crypto::Hash::from_marked_bytes(original.leaf().effects_digest)
            .ok_or_else(|| fastpq_prover::Error::InvalidTraceShape {
                details: "original source effect commitment is noncanonical".into(),
            })?,
        statement_digest: statement.digest(verification.public_statement.max_public_bytes)?,
        public_inputs: statement.public_inputs(),
    };
    Ok(PreparedSourceEntry {
        original,
        materialized,
        reservation,
        expectations,
    })
}
