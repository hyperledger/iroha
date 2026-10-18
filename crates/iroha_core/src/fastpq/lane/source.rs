//! Finite complete-effect work borrowed from the actual native source owner.
use crate::query::native_context_archive::fastpq_source::AuthenticatedRecoveredFastpqSource;
use crate::sumeragi::certified_chain::AuthenticatedExecutionBlock;
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
use iroha_allocation::{AllocationBudget, AllocationRefusal, AllocationReservation};
use iroha_data_model::fastpq::{
    FastpqExecutionEffectsV1, FastpqOrdinarySourceStatementLeafV1,
    FastpqOrdinarySourceStatementManifestV1,
};

/// One authenticated source owner; recovery joins are issued only by the archive verifier.
/// This is the existing lane's source sum, not a second work queue or authority parser.
pub(crate) enum SourceOwner {
    Original(AdmittedFinalizedFastpqSource),
    Recovered(AuthenticatedRecoveredFastpqSource),
}
pub(crate) enum SourceEntry<'a> {
    Original(CapturedQuantityEntry<'a>),
    Recovered {
        effects: &'a FastpqExecutionEffectsV1,
        leaf: &'a FastpqOrdinarySourceStatementLeafV1,
        pool: &'a AllocationBudget,
    },
}
impl<'a> SourceEntry<'a> {
    pub(crate) fn effects(&self) -> &'a FastpqExecutionEffectsV1 {
        match self {
            Self::Original(v) => v.effects(),
            Self::Recovered { effects, .. } => effects,
        }
    }
    pub(crate) fn leaf(&self) -> &'a FastpqOrdinarySourceStatementLeafV1 {
        match self {
            Self::Original(v) => v.leaf(),
            Self::Recovered { leaf, .. } => leaf,
        }
    }
    pub(crate) fn pool(&self) -> &'a AllocationBudget {
        match self {
            Self::Original(v) => v.pool(),
            Self::Recovered { pool, .. } => pool,
        }
    }
}
impl SourceOwner {
    pub(crate) fn native(&self) -> &AuthenticatedExecutionBlock {
        match self {
            Self::Original(v) => v.native(),
            Self::Recovered(v) => v.native(),
        }
    }
    #[cfg(test)]
    pub(crate) fn pool(&self) -> &AllocationBudget {
        match self {
            Self::Original(v) => v.pool(),
            Self::Recovered(v) => v.pool(),
        }
    }
    pub(crate) fn leaves(&self) -> &[FastpqOrdinarySourceStatementLeafV1] {
        match self {
            Self::Original(v) => v.leaves(),
            Self::Recovered(v) => v.leaves(),
        }
    }
    pub(crate) fn manifest(&self) -> &FastpqOrdinarySourceStatementManifestV1 {
        match self {
            Self::Original(v) => v.original().manifest(),
            Self::Recovered(v) => v.manifest(),
        }
    }
    pub(crate) fn entry(&self, index: usize) -> Result<SourceEntry<'_>, SourceWorkError> {
        match self {
            Self::Original(v) => v
                .entry(index)
                .map(SourceEntry::Original)
                .map_err(SourceWorkError::Source),
            Self::Recovered(v) => v
                .entry(index)
                .map(|(effects, leaf)| SourceEntry::Recovered {
                    effects,
                    leaf,
                    pool: v.pool(),
                })
                .ok_or(SourceWorkError::Identity(
                    "recovered source has no requested complete entry",
                )),
        }
    }
    #[cfg(test)]
    pub(crate) fn verify_current(
        &self,
    ) -> Result<(), crate::fastpq::finalized_source::FinalizedFastpqSourceError> {
        match self {
            Self::Original(v) => v.verify_current(),
            Self::Recovered(_) => Ok(()),
        }
    }
}

/// Local refusal preserves the source; none changes block validity, D7 or native R.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SourceWorkError {
    /// Invalid local source position; this is never a capacity refusal.
    #[error("FASTPQ source identity: {0}")]
    Identity(&'static str),
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
    pub(super) original: SourceEntry<'a>,
    pub(super) materialized: SourceExecutionEffectMaterialization<'a>,
    pub(super) reservation: AllocationReservation,
    pub(super) expectations: ExecutionEffectExpectations,
}
/// Checked total consumed original credit before any materialization is attempted.
/// Proof payload/decode/RSS ceilings remain distinct; this is backing-credit demand.
pub(super) fn allocation_bytes(
    entry: &SourceEntry<'_>,
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
    source: &'a SourceOwner,
    index: usize,
    proving: ProvingLimits,
    verification: &ExecutionEffectVerificationLimits,
) -> Result<PreparedSourceEntry<'a>, SourceWorkError> {
    prepare_owned(source, index, proving, verification, true)
}

/// Same original source/materializer, reserving only verification work on recovery.
pub(super) fn prepare_for_verification<'a>(
    source: &'a SourceOwner,
    index: usize,
    proving: ProvingLimits,
    verification: &ExecutionEffectVerificationLimits,
) -> Result<PreparedSourceEntry<'a>, SourceWorkError> {
    prepare_owned(source, index, proving, verification, false)
}

fn prepare_owned<'a>(
    source: &'a SourceOwner,
    index: usize,
    proving: ProvingLimits,
    verification: &ExecutionEffectVerificationLimits,
    prove: bool,
) -> Result<PreparedSourceEntry<'a>, SourceWorkError> {
    let original = source.entry(index)?;
    let bytes = if prove {
        allocation_bytes(&original, proving, verification)?
    } else {
        materialization_allocation_bytes(
            original.effects(),
            verification.public_statement,
            proving.private_smt,
        )?
        .checked_add(
            offline_compact::quantity_ordinary_verification_allocation_bytes(
                original.effects(),
                verification,
            )?,
        )
        .ok_or(AllocationRefusal::DemandOverflow)?
    };
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
