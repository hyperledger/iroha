//! Original sealed native execution admission for a first Prepare.

use super::*;
use iroha_allocation::ChargedShared;
use iroha_data_model::sumeragi_amx::{AmxRecordKind, amx_record_witness_kind};
use iroha_sumeragi::{
    crypto::SigningError,
    prepare_admission::{ExecutionAdmission, PrepareAdmission, PrepareSigningRequest},
};

/// Fixed local facts extracted only from the exact original captured execution witness.
/// No wire decoder, public constructor or caller-supplied sensitivity policy exists.
pub(super) struct NativePrepareAdmission {
    instance: Hash32,
    epoch: iroha_sumeragi::types::EpochId,
    height: u64,
    block_hash: Hash32,
    result: Hash32,
    block_time_ms: u64,
    max_lag_ms: u64,
    max_clock_drift_ms: u64,
    sensitive: bool,
    time_source: iroha_primitives::time::TimeSource,
    progress_clock: Option<crate::smartcontracts::isi::sccp::keepalive::ProgressClock>,
}
impl core::fmt::Debug for NativePrepareAdmission {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("NativePrepareAdmission")
            .field("block_hash", &self.block_hash)
            .field("result", &self.result)
            .finish_non_exhaustive()
    }
}
impl NativePrepareAdmission {
    pub(super) fn capture(
        original: &Finishing<'_>,
        result: Hash32,
        time_source: &iroha_primitives::time::TimeSource,
        root_scope: iroha_data_model::block::consensus::SumeragiRootScope,
    ) -> Result<ChargedShared<Self>, PublicationError> {
        original
            .witness
            .verify_source_binding()
            .map_err(PublicationError::RecoveryRequired)?;
        let mut sensitive = false;
        for entry in &original.witness.writes {
            let kind = amx_record_witness_kind(&entry.key)
                .map_err(|error| PublicationError::RecoveryRequired(error.to_string()))?;
            sensitive |= root_scope
                == iroha_data_model::block::consensus::SumeragiRootScope::Global
                && matches!(kind, Some(AmxRecordKind::Begin | AmxRecordKind::Decision));
        }
        let block_time_ms =
            u64::try_from(original.valid.as_ref().header().creation_time().as_millis()).map_err(
                |_| PublicationError::RecoveryRequired("original native timestamp overflow".into()),
            )?;
        let value = Self {
            instance: original.header.instance,
            epoch: original.header.epoch,
            height: original.height,
            block_hash: original.block_hash,
            result,
            block_time_ms,
            max_lag_ms: original.due_work_max_lag_ms,
            max_clock_drift_ms: original.max_clock_drift_ms,
            sensitive,
            time_source: time_source.clone(),
            progress_clock: original.progress_clock,
        };
        let mut reservation = original
            .witness
            .pool()
            .try_reserve(ChargedShared::<Self>::allocation_layout())
            .map_err(|error| {
                PublicationError::Deferred(
                    crate::execution_attempt::ExecutionDeferred::from(error).into(),
                )
            })?;
        ChargedShared::from_reservation(value, &mut reservation).map_err(|(_, error)| {
            PublicationError::Deferred(PublicationDeferral::SharedControl(error))
        })
    }

    /// This uses a fresh actual clock observation at each attempt, including after waits.
    /// A genuine matching certificate exempts clock admission before the clock is read.
    pub(super) fn check_freshness(&self, certified: bool) -> Result<(), PublicationError> {
        self.freshness(certified).map_err(|error| match error {
            SigningError::StaleExecution {
                block_time_ms,
                observed_ms,
                max_lag_ms,
            } => PublicationError::Deferred(PublicationDeferral::StaleDueWork {
                block_time_ms,
                observed_ms,
                max_lag_ms,
            }),
            SigningError::Refused => PublicationError::Retryable("StaleDueWork".into()),
            _ => PublicationError::RecoveryRequired(error.to_string()),
        })
    }

    fn freshness(&self, certified: bool) -> Result<(), SigningError> {
        if certified {
            return Ok(());
        }
        let observed_ms = u64::try_from(self.time_source.now().as_millis())
            .map_err(|_| SigningError::InvalidInput)?;
        self.freshness_at(observed_ms)
    }

    fn freshness_at(&self, observed_ms: u64) -> Result<(), SigningError> {
        if self.sensitive && observed_ms.saturating_sub(self.block_time_ms) > self.max_lag_ms {
            return Err(SigningError::StaleExecution {
                block_time_ms: self.block_time_ms,
                observed_ms,
                max_lag_ms: self.max_lag_ms,
            });
        }
        if self
            .progress_clock
            .as_ref()
            .is_some_and(|clock| clock.is_stale(observed_ms, false).unwrap_or(true))
        {
            return Err(SigningError::Refused);
        }
        Ok(())
    }
}
impl PrepareAdmission for NativePrepareAdmission {
    fn result(&self) -> Hash32 {
        self.result
    }
    fn check(&self, request: &PrepareSigningRequest) -> Result<(), SigningError> {
        if !cfg!(all(test, sumeragi_core_mutation = "HC336"))
            && (request.instance() != self.instance
                || request.epoch() != self.epoch
                || request.height() != self.height
                || request.block_hash() != self.block_hash
                || request.result() != self.result)
        {
            return Err(SigningError::InvalidInput);
        }
        // Execution may have completed before a local stage/signing wait. Retain the
        // original parent's allowance and refuse only this first signing attempt.
        if request.certified() {
            return Ok(());
        }
        let observed_ms = u64::try_from(self.time_source.now().as_millis())
            .map_err(|_| SigningError::InvalidInput)?;
        if self.height > 1
            && !cfg!(all(test, sumeragi_core_mutation = "HC382"))
            && self.block_time_ms.saturating_sub(observed_ms) > self.max_clock_drift_ms
        {
            return Err(SigningError::ClockAhead {
                block_time_ms: self.block_time_ms,
                observed_ms,
                max_clock_drift_ms: self.max_clock_drift_ms,
            });
        }
        if cfg!(all(test, sumeragi_core_mutation = "HC337")) {
            return Ok(());
        }
        self.freshness_at(observed_ms)
    }
}

pub(super) fn erased(owner: &ChargedShared<NativePrepareAdmission>) -> ExecutionAdmission {
    ExecutionAdmission::from_owner(owner.clone().project::<dyn PrepareAdmission>(|value| value))
}
