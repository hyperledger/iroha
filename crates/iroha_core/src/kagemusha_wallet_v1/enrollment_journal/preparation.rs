//! Durable worker incarnation and pre-E1 preparation, before publishing a key permit.

use super::*;
use iroha_core_zk::kagemusha_wallet_enrollment_v1::{
    PreKeyDispatchV1,
    issuer_worker::{VerifierExchangeV1, VerifierPreparationV1},
};

#[derive(Clone, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core.kagemusha.enrollment.worker_prepared.v1")]
pub(super) struct PreparedOriginal {
    pub exchange: [u8; 32],
    pub response: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core.kagemusha.enrollment.worker_preparation.v1")]
pub(super) struct WorkerPreparationSelection {
    pub dispatch: Vec<u8>,
    pub configuration: [u8; 32],
    pub incarnation: [u8; 32],
    pub original: Vec<u8>,
    pub ready: Option<PreparedOriginal>,
}
impl WorkerPreparationSelection {
    pub(super) fn validate(&self) -> Result<()> {
        if self.configuration == [0; 32]
            || self.incarnation == [0; 32]
            || self.dispatch.is_empty()
            || self.dispatch.len() > SCOPE_MAX
            || self.original.is_empty()
            || self.original.len() > SCOPE_MAX
            || self.ready.as_ref().is_some_and(|ready| {
                ready.exchange == [0; 32]
                    || ready.response.is_empty()
                    || ready.response.len() > ORIGINAL_MAX
            })
        {
            return Err(Invalid);
        }
        Ok(())
    }
}

impl EnrollmentJournalV1 {
    /// Freeze the authenticated worker's actual incarnation and exact prepared E1 before any
    /// permit exposes that E1. The service must independently authenticate worker custody,
    /// configuration and current account eligibility; a digest alone establishes none of them.
    /// Exact retries preserve the first worker selection, including after lost pipe output.
    /// # Errors
    /// Changed scope/worker, consumed attempt, malformed originals or uncertain publication.
    pub fn select_worker_preparation(
        &mut self,
        attempt: &mut EnrollmentAttemptV1,
        dispatch: &PreKeyDispatchV1,
        configuration: [u8; 32],
        incarnation: [u8; 32],
    ) -> Result<VerifierPreparationV1> {
        self.require_current(attempt)?;
        if attempt.phase() != EnrollmentJournalPhaseV1::Selected {
            return Err(Conflict);
        }
        if dispatch.stable_selection().map_err(|_| Invalid)? != attempt.selection().stable_selection
            || attempt
                .selection()
                .created_at_ms
                .checked_add(dispatch.policy.challenge_lifetime_ms)
                != Some(attempt.selection().expires_at_ms)
        {
            return Err(Conflict);
        }
        let preparation = VerifierPreparationV1::from_selected(
            dispatch,
            attempt.selection().challenge,
            attempt.selection().created_at_ms,
            configuration,
        )
        .map_err(|_| Invalid)?;
        let selected = WorkerPreparationSelection {
            dispatch: dispatch.encode().map_err(|_| Invalid)?,
            configuration,
            incarnation,
            original: preparation.original().to_vec(),
            ready: None,
        };
        selected.validate()?;
        if let Some(prior) = &attempt.record.worker_preparation {
            // A Resume dispatch may have a fresh native nonce; it must retain the same
            // stable preparation and initial dispatch original, never rewrite the worker row.
            return if prior.configuration == selected.configuration
                && prior.incarnation == selected.incarnation
                && prior.original == selected.original
            {
                self.worker_preparation(attempt, configuration)
            } else {
                Err(Conflict)
            };
        }
        let mut record = attempt.record.clone();
        record.worker_preparation = Some(selected);
        self.advance(attempt, record)?;
        Ok(preparation)
    }

    /// Reconstruct only the selected original preparation; no peer-provided replacement or
    /// newer worker configuration can recover an existing attempt.
    /// # Errors
    /// Missing preparation, substituted originals, stale cursor or unavailable custody.
    pub fn worker_preparation(
        &self,
        attempt: &EnrollmentAttemptV1,
        configuration: [u8; 32],
    ) -> Result<VerifierPreparationV1> {
        self.require_current(attempt)?;
        let selected = attempt.record.worker_preparation.as_ref().ok_or(Conflict)?;
        selected.validate()?;
        if configuration != selected.configuration {
            return Err(Conflict);
        }
        let dispatch = PreKeyDispatchV1::decode(&selected.dispatch).map_err(|_| Invalid)?;
        if dispatch.stable_selection().map_err(|_| Invalid)? != attempt.selection().stable_selection
        {
            return Err(Conflict);
        }
        let preparation = VerifierPreparationV1::from_selected(
            &dispatch,
            attempt.selection().challenge,
            attempt.selection().created_at_ms,
            configuration,
        )
        .map_err(|_| Invalid)?;
        if preparation.original() != selected.original
            || attempt
                .selection()
                .created_at_ms
                .checked_add(dispatch.policy.challenge_lifetime_ms)
                != Some(attempt.selection().expires_at_ms)
        {
            return Err(Conflict);
        }
        Ok(preparation)
    }

    /// Create a fresh exchange for the same selected worker preparation before E5 selection.
    /// After E5 is selected, only Complete/Recover may reach the worker; a missing worker row
    /// must never be reconstructed by resending Prepare after an uncertain verification.
    /// # Errors
    /// Missing/substituted selection, empty exchange identity or unavailable custody.
    pub fn worker_preparation_exchange(
        &self,
        attempt: &EnrollmentAttemptV1,
        configuration: [u8; 32],
        exchange: [u8; 32],
    ) -> Result<VerifierExchangeV1> {
        if attempt.phase() != EnrollmentJournalPhaseV1::Selected {
            return Err(Conflict);
        }
        let preparation = self.worker_preparation(attempt, configuration)?;
        let selected = attempt.record.worker_preparation.as_ref().ok_or(Conflict)?;
        preparation
            .packet(selected.incarnation, exchange)
            .map_err(|_| Invalid)
    }

    /// Retain a checked acknowledgement from the already authenticated worker before exposing
    /// E1 in a permit. Preserve the first original reply; retries must reverify their envelope.
    /// # Errors
    /// Foreign packet/incarnation/configuration, non-prepared outcome or uncertain publication.
    pub fn retain_worker_prepared(
        &mut self,
        attempt: &mut EnrollmentAttemptV1,
        configuration: [u8; 32],
        exchange: [u8; 32],
        response: &[u8],
    ) -> Result<()> {
        self.worker_preparation_exchange(attempt, configuration, exchange)?
            .prepared_response(response)
            .map_err(|_| Invalid)?;
        let selected = attempt.record.worker_preparation.as_ref().ok_or(Conflict)?;
        if selected.ready.is_some() {
            self.require_worker_prepared(attempt, configuration)?;
            return Ok(());
        }
        if attempt.phase() != EnrollmentJournalPhaseV1::Selected {
            return Err(Conflict);
        }
        let mut record = attempt.record.clone();
        record.worker_preparation.as_mut().ok_or(Conflict)?.ready = Some(PreparedOriginal {
            exchange,
            response: response.to_vec(),
        });
        self.advance(attempt, record)
    }

    pub(super) fn require_worker_prepared(
        &self,
        attempt: &EnrollmentAttemptV1,
        configuration: [u8; 32],
    ) -> Result<VerifierPreparationV1> {
        let preparation = self.worker_preparation(attempt, configuration)?;
        let selected = attempt.record.worker_preparation.as_ref().ok_or(Conflict)?;
        let ready = selected.ready.as_ref().ok_or(Conflict)?;
        preparation
            .packet(selected.incarnation, ready.exchange)
            .and_then(|packet| packet.prepared_response(&ready.response))
            .map_err(|_| Invalid)?;
        Ok(preparation)
    }
}

#[cfg(test)]
pub(super) mod tests;
