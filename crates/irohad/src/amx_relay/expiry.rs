//! Bounded local Decision recovery before a funded Global expiry carrier is dispatched.

use super::*;
use iroha_core::{
    query::native_receipts::{
        NativeAmxExpiryDecisionCursorV1, NativeAmxExpiryDecisionPollV1, expiry_amx_decision,
    },
    state::StateReadOnly,
};

/// Only scheduling state: restart reconstructs source authority from certified history.
#[derive(Default)]
pub(super) struct ExpiryRecovery {
    active: Option<[u8; 32]>,
    cursor: NativeAmxExpiryDecisionCursorV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ExpiryProgress {
    Ordinary,
    Waiting,
    Ready,
    Decided,
}

impl ExpiryRecovery {
    // Keep one finite cursor per configured Global route. Revisiting other historical
    // Begins cannot repeatedly reset an unfinished scan; ordinary relays remain independent.
    fn select(&mut self, identity: [u8; 32]) -> bool {
        if self.active.is_some_and(|active| active != identity) {
            return false;
        }
        self.active = Some(identity);
        true
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn observe<V: StateReadOnly>(
        &mut self,
        view: &V,
        intent: &NativeAmxRelayIntentV1,
        now_ms: u64,
        max_polls: usize,
        runtime: &tokio::runtime::Handle,
        shutdown: &ShutdownSignal,
        cadence: Duration,
    ) -> Result<ExpiryProgress> {
        let Some(ready_at) = intent.descriptor().ready_at_ms() else {
            return Ok(ExpiryProgress::Ordinary);
        };
        if !ready(now_ms, ready_at) {
            return Ok(ExpiryProgress::Waiting);
        }
        let identity = plan(
            intent.descriptor(),
            ledger::instruction_digest(intent.instruction())?,
        )?
        .request_context_digest;
        if !self.select(identity) {
            return Ok(ExpiryProgress::Waiting);
        }
        let mut read = expiry_amx_decision(view, intent, &mut self.cursor)?;
        let mut polls = 0usize;
        loop {
            if shutdown.is_sent() {
                // Shutdown explicitly retires the borrower and all its owned custody.
                return Ok(ExpiryProgress::Waiting);
            }
            match read.poll() {
                Ok(NativeAmxExpiryDecisionPollV1::Complete(decision)) => {
                    self.active = None;
                    return Ok(if decision.is_some() {
                        // A verified business decision suppresses redundant submission.
                        // It never changes an unknown/rejected local carrier to Applied.
                        ExpiryProgress::Decided
                    } else {
                        // Absence is only within the captured prefix. A competing decision
                        // may arrive next; native Expire execution resolves that race.
                        ExpiryProgress::Ready
                    });
                }
                Ok(NativeAmxExpiryDecisionPollV1::Pending) => {
                    polls = polls.saturating_add(1);
                    if polls >= max_polls.max(1) && read.can_retire() {
                        return Ok(ExpiryProgress::Waiting);
                    }
                }
                Err(error) if read.can_retire() => return Err(error.into()),
                Err(error) => {
                    // Before issuance the exact job borrows this State view. Keep both
                    // through refusal instead of restarting certification with new credit.
                    iroha_logger::warn!(%error, "AMX expiry original source retained for retry");
                    if wait(runtime, shutdown, cadence) {
                        return Ok(ExpiryProgress::Waiting);
                    }
                }
            }
        }
    }
}

// The caller has independently verified the business Decision. This helper can only
// reconcile an already existing exact carrier; it cannot create, sign, or dispatch one.
pub(super) async fn recover_carrier(
    engine: &WorkflowEngine,
    ledger: &dyn WorkflowLedger,
    plan: WorkflowPlanV1,
    cadence: Duration,
) -> Result<()> {
    let handle = engine.workflow(plan)?;
    if handle.progress()?.is_none() {
        return Ok(());
    }
    let progress = handle
        .recover(
            None,
            &WorkflowRunOptions {
                observation_timeout: cadence,
                poll_interval: cadence,
                retransmit_identical_bytes: false,
                retry_rejected_step: false,
            },
        )
        .await?;
    if cfg!(all(test, sumeragi_daemon_mutation = "HC340")) {
        // Mutation: decoded terminal journal progress replaces a fresh exact-carrier read.
        return Ok(());
    }
    if let Some(identity) = progress
        .steps
        .first()
        .and_then(|step| step.identities.last())
        .and_then(|attempt| attempt.identity.as_ref())
    {
        match ledger.committed_outcome(identity).await {
            CommittedOutcome::Applied { .. } | CommittedOutcome::Rejected { .. } => {}
            _ => {
                return Err(eyre!(
                    "AMX business decision is verified; exact expiry carrier remains unresolved"
                ));
            }
        }
    }
    Ok(())
}

fn ready(now_ms: u64, ready_at_ms: u64) -> bool {
    now_ms >= ready_at_ms
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_signed_wake_is_inclusive_and_never_changes_with_local_observation() {
        for (now, expected) in [(9_999, false), (10_000, true), (10_001, true), (0, false)] {
            assert_eq!(ready(now, 10_000), expected);
        }
        assert!(ready(u64::MAX, u64::MAX));
        assert!(!ready(u64::MAX - 1, u64::MAX));
    }

    #[test]
    fn historical_rescans_cannot_replace_the_unfinished_expiry_cursor() {
        let mut recovery = ExpiryRecovery::default();
        assert!(recovery.select([2; 32]));
        assert!(!recovery.select([1; 32]));
        assert!(!recovery.select([3; 32]));
        assert!(recovery.select([2; 32]));
        recovery.active = None;
        assert!(recovery.select([3; 32]));
        assert!(ExpiryRecovery::default().select([1; 32]));
    }
}
