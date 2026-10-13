//! Durable SCCP transfer state machines over the original signed submission.
//!
//! Preparation retains the verified evidence and exact public transaction bytes before
//! dispatch. A submitted step is observed on its original chain after a restart; it is
//! never signed again. An unavailable observation leaves it pending; an explicit recovery
//! choice may resend only identical original bytes under that chain's replay protection.
//! Only an authenticated terminal outcome permits the next step or a replacement attempt.

use crate::journal::{
    JournalError, SccpEvidenceItemV1, SccpFlowIdV1, SccpFlowJournal, SccpFlowKindV1,
    SccpJournalOutcomeV1, SccpJournalRecordV1, SccpJournalStep, SccpStepOutcomeKindV1,
    SccpStepStateV1,
};
use iroha_data_model::bridge::SccpNetworkV1;

/// Closed action vocabulary of the transfer and destination-maintenance flows.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
)]
#[norito(tag = "action", content = "detail")]
pub enum SccpFlowActionV1 {
    /// Record a Taira outbound message.
    Record,
    /// Apply an authenticated destination committee catch-up page.
    Checkpoint,
    /// Apply the newest authenticated destination control.
    Control,
    /// Finalize an outbound message on its destination.
    Finalize,
    /// Burn external tokens for the canonical Taira recipient.
    Burn,
    /// Apply one bounded source light-client advance or backfill.
    Advance,
    /// Prove a source burn on Taira.
    ProveInbound,
    /// Retry a pending inbound settlement.
    SettleInbound,
    /// Void an expired outbound message on its destination.
    Void,
    /// Prove a destination void on Taira.
    ProveVoid,
    /// Retry a pending outbound refund.
    SettleRefund,
    /// Retain an authenticated final message status without submitting a transaction.
    ObserveComplete,
    /// Submit locally verified native forgery evidence; Core validates it again.
    RecordEvidence,
    /// Deploy one deterministic destination from the retained original committee pin.
    Deploy,
    /// Fund progress of an immutable TON recovery operation id.
    RetryRecovery,
}

impl SccpFlowActionV1 {
    fn accepts_phase(self, phase: SccpFlowPhaseV1) -> bool {
        match (phase, self) {
            (SccpFlowPhaseV1::Complete, _)
            | (
                SccpFlowPhaseV1::AwaitingSettlement,
                Self::Advance | Self::ProveInbound | Self::ProveVoid | Self::Void,
            ) => false,
            (_, Self::Record | Self::Burn) => phase == SccpFlowPhaseV1::Ready,
            _ => true,
        }
    }

    fn accepts(self, kind: SccpFlowKindV1, chain: SccpNetworkV1) -> bool {
        use SccpFlowActionV1 as A;
        use SccpFlowKindV1 as F;
        let action_matches = matches!(
            (kind, self),
            (
                F::Outbound,
                A::Record | A::Checkpoint | A::Control | A::Finalize | A::ObserveComplete
            ) | (
                F::Inbound,
                A::Burn | A::Advance | A::ProveInbound | A::SettleInbound | A::ObserveComplete
            ) | (
                F::Refund,
                A::Void | A::Advance | A::ProveVoid | A::SettleRefund | A::ObserveComplete
            ) | (
                F::CommitteeSync,
                A::Checkpoint | A::Control | A::ObserveComplete
            ) | (F::ControlApply, A::Control | A::ObserveComplete)
                | (F::EvidenceSubmission, A::RecordEvidence)
                | (F::Deployment, A::Deploy)
                | (F::TonRecovery, A::RetryRecovery)
        );
        let chain_matches = match self {
            A::Record
            | A::Advance
            | A::ProveInbound
            | A::SettleInbound
            | A::ProveVoid
            | A::SettleRefund
            | A::RecordEvidence => chain == SccpNetworkV1::SoraTaira,
            A::Checkpoint | A::Control | A::Finalize | A::Burn | A::Void | A::Deploy => {
                chain != SccpNetworkV1::SoraTaira
            }
            A::ObserveComplete => true,
            A::RetryRecovery => chain == SccpNetworkV1::TonMainnet,
        };
        action_matches && chain_matches
    }
}

/// Transfer progress derived from the durable ordered action history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SccpFlowPhaseV1 {
    /// No confirmed mutation yet; imported already-recorded messages may start here.
    Ready,
    /// The transfer was recorded or burned; its final effect is still pending.
    AwaitingProof,
    /// The proof was accepted; Taira settlement may still need a retry.
    AwaitingSettlement,
    /// An authenticated final effect was recorded.
    Complete,
}

fn invalid(message: &str) -> JournalError {
    JournalError::Inconsistent(message.to_owned())
}

/// One typed flow, backed by a network-scoped, owner-private durable journal.
#[derive(Debug)]
pub struct SccpFlowV1 {
    journal: SccpFlowJournal,
    network_id: [u8; 32],
}

impl SccpFlowV1 {
    /// Bind an existing journal to its original Taira network and validate its history.
    ///
    /// # Errors
    /// Refuses invalid storage, another network, action/chain mismatches and steps after completion.
    pub fn open(journal: SccpFlowJournal, network_id: [u8; 32]) -> Result<Self, JournalError> {
        let flow = Self {
            journal,
            network_id,
        };
        flow.phase()?;
        Ok(flow)
    }

    /// Stable identity printed for later recovery.
    #[must_use]
    pub fn id(&self) -> SccpFlowIdV1 {
        self.journal.flow()
    }

    /// Read and validate the current phase without altering any record.
    ///
    /// # Errors
    /// Refuses inconsistent or noncanonical history.
    pub fn phase(&self) -> Result<SccpFlowPhaseV1, JournalError> {
        let mut phase = SccpFlowPhaseV1::Ready;
        for step in self.journal.steps()? {
            if phase == SccpFlowPhaseV1::Complete {
                return Err(invalid("a completed transfer has another step"));
            }
            let Some(record) = step.record else { continue };
            self.validate(&record)?;
            if !record.action.accepts_phase(phase) {
                return Err(invalid(
                    "the action does not follow the durable transfer phase",
                ));
            }
            if !matches!(
                step.state,
                SccpStepStateV1::Completed(
                    SccpStepOutcomeKindV1::Confirmed | SccpStepOutcomeKindV1::Superseded
                )
            ) {
                continue;
            }
            phase = match record.action {
                SccpFlowActionV1::Record | SccpFlowActionV1::Burn | SccpFlowActionV1::Void => {
                    SccpFlowPhaseV1::AwaitingProof
                }
                SccpFlowActionV1::ProveInbound
                | SccpFlowActionV1::ProveVoid
                | SccpFlowActionV1::SettleInbound
                | SccpFlowActionV1::SettleRefund => SccpFlowPhaseV1::AwaitingSettlement,
                SccpFlowActionV1::Finalize
                | SccpFlowActionV1::Deploy
                | SccpFlowActionV1::ObserveComplete
                | SccpFlowActionV1::RecordEvidence => SccpFlowPhaseV1::Complete,
                SccpFlowActionV1::Checkpoint
                | SccpFlowActionV1::Control
                | SccpFlowActionV1::Advance
                | SccpFlowActionV1::RetryRecovery => phase,
            };
        }
        Ok(phase)
    }

    fn validate(&self, record: &SccpJournalRecordV1) -> Result<(), JournalError> {
        if record.network_id != self.network_id
            || record.flow != self.id()
            || !record.action.accepts(self.id().kind, record.chain)
            || (record.submission.is_empty()
                != (record.action == SccpFlowActionV1::ObserveComplete))
            || record.evidence.is_empty()
        {
            return Err(invalid(
                "flow identity, action, signed bytes or verified evidence mismatch",
            ));
        }
        Ok(())
    }

    /// Prepare the next exact signed operation, or reopen the same pending preparation.
    /// A caller must check [`Self::pending`] before acquiring a new nonce or signing.
    ///
    /// # Errors
    /// Refuses another pending operation, a completed transfer, wrong chain or absent evidence.
    pub fn prepare(
        &self,
        action: SccpFlowActionV1,
        chain: SccpNetworkV1,
        submission: Vec<u8>,
        evidence: Vec<SccpEvidenceItemV1>,
    ) -> Result<SccpJournalStep, JournalError> {
        if !action.accepts_phase(self.phase()?) {
            return Err(invalid(
                "the action does not follow the durable transfer phase",
            ));
        }
        let pending = self.journal.resume_point()?;
        let index = pending
            .as_ref()
            .map_or_else(|| self.journal.step_count(), |step| Ok(step.index))?;
        let record = SccpJournalRecordV1 {
            network_id: self.network_id,
            flow: self.id(),
            step: index,
            chain,
            action,
            submission,
            evidence,
        };
        self.validate(&record)?;
        if let Some(previous) = pending.and_then(|step| step.record) {
            if previous != record {
                return Err(invalid(
                    "resume the original signed operation before preparing another",
                ));
            }
            return self.journal.open_step(index);
        }
        self.journal.append(&record)
    }

    /// Lock the original pending signed step, without creating or signing a replacement.
    ///
    /// # Errors
    /// Refuses an invalid history or an occupied lock. An empty pre-preparation step is absent.
    pub fn pending(&self) -> Result<Option<SccpJournalStep>, JournalError> {
        self.phase()?;
        self.journal
            .resume_point()?
            .filter(|step| step.record.is_some())
            .map(|step| self.journal.open_step(step.index))
            .transpose()
    }

    /// Reopen the most recent exact action carrying a retained intent digest.
    /// This lets a repeated command return its original result without signing again.
    ///
    /// # Errors
    /// Refuses inconsistent storage or a competing step lock.
    pub fn find_intent(
        &self,
        action: SccpFlowActionV1,
        intent: &[u8; 32],
    ) -> Result<Option<SccpJournalStep>, JournalError> {
        self.phase()?;
        for step in self.journal.steps()?.into_iter().rev() {
            if step.record.as_ref().is_some_and(|record| {
                record.action == action
                    && record.evidence.iter().any(|item| {
                        item.label == "sccp.intent.sha256" && item.bytes.as_slice() == intent
                    })
            }) {
                return self.journal.open_step(step.index).map(Some);
            }
        }
        Ok(None)
    }

    /// Reopen the newest retained step of one action, before refreshing any discovery state.
    ///
    /// # Errors
    /// Refuses inconsistent history or a competing step lock.
    pub fn latest(
        &self,
        action: SccpFlowActionV1,
    ) -> Result<Option<SccpJournalStep>, JournalError> {
        self.phase()?;
        for step in self.journal.steps()?.into_iter().rev() {
            if step
                .record
                .as_ref()
                .is_some_and(|record| record.action == action)
            {
                return self.journal.open_step(step.index).map(Some);
            }
        }
        Ok(None)
    }
}

/// Advance one locked step. `observe` must use its retained original transaction identity and
/// authenticated effect evidence; `None` means unknown, never proof of failure. `dispatch`
/// receives only the exact bytes already durable on disk. Its error leaves the marker intact.
///
/// # Errors
/// Propagates storage, observation or dispatch errors without replacing the original operation.
pub fn drive_step<E: From<JournalError>>(
    step: &SccpJournalStep,
    observe: impl FnMut(&SccpJournalRecordV1) -> Result<Option<SccpJournalOutcomeV1>, E>,
    dispatch: impl FnMut(&[u8]) -> Result<(), E>,
) -> Result<Option<SccpJournalOutcomeV1>, E> {
    drive_step_with_rebroadcast(step, false, observe, dispatch)
}

/// Recover by reconciliation, with an explicit choice to resend the identical retained bytes.
/// Only a chain adapter whose original signed transaction has native replay protection may
/// enable this mode. It never rebuilds, re-signs or infers failure from absence.
///
/// # Errors
/// Preserves the original step on observation, dispatch or durability failure.
pub fn drive_step_with_rebroadcast<E: From<JournalError>>(
    step: &SccpJournalStep,
    rebroadcast: bool,
    mut observe: impl FnMut(&SccpJournalRecordV1) -> Result<Option<SccpJournalOutcomeV1>, E>,
    mut dispatch: impl FnMut(&[u8]) -> Result<(), E>,
) -> Result<Option<SccpJournalOutcomeV1>, E> {
    if let Some(outcome) = step.outcome()? {
        return Ok(Some(outcome));
    }
    if let Some(outcome) = observe(step.record())? {
        require_outcome(&outcome)?;
        step.complete(&outcome)?;
        return Ok(Some(outcome));
    }
    if step.record().action == SccpFlowActionV1::ObserveComplete {
        return Ok(None);
    }
    if step.begin_submission()? || rebroadcast {
        dispatch(&step.record().submission)?;
    }
    let outcome = observe(step.record())?;
    if let Some(outcome) = &outcome {
        require_outcome(outcome)?;
        step.complete(outcome)?;
    }
    Ok(outcome)
}

fn require_outcome(outcome: &SccpJournalOutcomeV1) -> Result<(), JournalError> {
    if outcome.evidence.is_empty() {
        return Err(invalid("a terminal outcome needs its chain evidence"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
