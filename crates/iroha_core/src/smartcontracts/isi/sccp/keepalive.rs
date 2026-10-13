//! Shared progress carriers and the SCCP half of the deterministic due-work clock.
//!
//! Heartbeat eligibility always borrows the original parent. Parliament due-work is an
//! explicit unavailable dependency until its owner provides the G1–G3 iterator and receipt.

use super::eligibility::{Current, EligibilityRead};
use crate::state::{StateTransaction, WorldReadOnly};
use iroha_crypto::Algorithm;
use iroha_data_model::{
    account::AccountId,
    isi::{chain::Keepalive, error::InstructionExecutionError},
    parameter::governance_clock::GovernanceClockParametersV1,
    transaction::{Executable, TransactionEntrypoint, TransactionPayload},
};

/// The external Parliament due-work observation has not been supplied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("Parliament G1–G3 due-work observation is unavailable")]
pub struct DueWorkUnavailable;

/// Read and validate the same committed governance clock policy on every peer.
/// # Errors
/// Rejects malformed committed policy or a clock relation inconsistent with Sumeragi.
pub fn clock_parameters(
    world: &(impl WorldReadOnly + ?Sized),
) -> Result<GovernanceClockParametersV1, &'static str> {
    let parameters = world.parameters();
    let policy = parameters
        .custom()
        .get(GovernanceClockParametersV1::parameter_id())
        .map(GovernanceClockParametersV1::from_custom_parameter)
        .transpose()?
        .unwrap_or_default();
    policy.validate(
        parameters.sumeragi().max_clock_drift_ms(),
        parameters.sumeragi().block_cadence_ms.get(),
    )?;
    Ok(policy)
}

/// The exact standalone shared carrier executable.
#[must_use]
pub fn is_standalone(executable: &Executable) -> bool {
    matches!(executable, Executable::Instructions(instructions)
        if matches!(instructions.as_ref(), [only] if only.as_any().is::<Keepalive>()))
}

/// Count all direct Keepalive instructions, including malformed mixed transactions.
pub(crate) fn count(executable: &Executable) -> usize {
    match executable {
        Executable::Instructions(instructions) => instructions
            .iter()
            .filter(|isi| isi.as_any().is::<Keepalive>())
            .count(),
        _ => 0,
    }
}

/// Borrow the exact signed payload of an executable Network source.
pub(crate) fn payload(input: &TransactionEntrypoint) -> Option<&TransactionPayload> {
    match input {
        TransactionEntrypoint::External(signed) => Some(signed.payload()),
        TransactionEntrypoint::SealedReveal(reveal) => Some(reveal.signed_transaction().payload()),
        TransactionEntrypoint::SealedCommitment(_) => None,
    }
}

/// K3/K5 signed shape: one Keepalive, an Ed25519 authority and canonical empty fee intent.
#[must_use]
pub fn valid_shape(payload: &TransactionPayload) -> bool {
    if cfg!(all(test, sumeragi_core_mutation = "HC279")) {
        return is_standalone(&payload.instructions);
    }
    is_standalone(&payload.instructions)
        && payload
            .authority
            .try_signatory()
            .is_some_and(|key| key.algorithm() == Algorithm::Ed25519)
        && payload.fee_payment.sponsor_program().is_none()
        && payload.fee_payment.charge_limits().is_empty()
        && payload.fee_payment.gas_limit().is_none()
}

/// Parent-state SCCP heartbeat predicate, independent of this height's finalizer outcome.
pub(crate) fn heartbeat_due(source: &(impl EligibilityRead + ?Sized), time_ms: u64) -> bool {
    let Some(parameters) = source.parameters() else {
        return false;
    };
    let Some((start_ms, degraded_run)) = source.heartbeat_facts() else {
        return false;
    };
    (degraded_run < 2 || cfg!(all(test, sumeragi_core_mutation = "HC278")))
        && start_ms
            .checked_add(parameters.committee_heartbeat_ms)
            .is_some_and(|due| time_ms >= due)
}

/// Observe the shared due predicate against an original parent.
pub(crate) fn due_from(
    source: &(impl EligibilityRead + ?Sized),
    next_height: u64,
    time_ms: u64,
) -> Result<bool, DueWorkUnavailable> {
    if heartbeat_due(source, time_ms)
        || source
            .reconciliation_due_at_ms()
            .is_some_and(|due| due <= time_ms)
    {
        return Ok(true);
    }
    super::parliament_iface::governance_due(next_height, time_ms)
}

/// Read shared admission/proposer due work from one committed World observation.
/// # Errors
/// Preserves unavailable Parliament work instead of treating it as an empty due set.
pub fn due(
    world: &(impl WorldReadOnly + ?Sized),
    next_height: u64,
    time_ms: u64,
) -> Result<bool, DueWorkUnavailable> {
    due_from(&Current(world), next_height, time_ms)
}

/// Original current SCCP heartbeat deadline, when repeated degraded heights permit it.
#[must_use]
pub fn next_heartbeat_at_ms(world: &(impl WorldReadOnly + ?Sized)) -> Option<u64> {
    let source = Current(world);
    let parameters = source.parameters()?;
    let (start, degraded) = source.heartbeat_facts()?;
    (degraded < 2)
        .then(|| start.checked_add(parameters.committee_heartbeat_ms))
        .flatten()
}

/// Earliest open reconciliation deadline from the original ordered due index.
#[must_use]
pub fn next_reconciliation_at_ms(world: &(impl WorldReadOnly + ?Sized)) -> Option<u64> {
    Current(world).reconciliation_due_at_ms()
}

/// Earliest independently known SCCP progress deadline, even after degraded heartbeats stop.
/// Parliament work remains unavailable until its authoritative iterator is supplied.
#[must_use]
pub fn next_progress_at_ms(world: &(impl WorldReadOnly + ?Sized)) -> Option<u64> {
    next_heartbeat_at_ms(world)
        .into_iter()
        .chain(next_reconciliation_at_ms(world))
        .min()
}

/// K5 admission before ordinary fee handling, including one pending key per authority.
/// # Errors
/// Rejects malformed, future, no-longer-due or dependency-unavailable carriers.
pub fn admit(
    world: &(impl WorldReadOnly + ?Sized),
    payload: &TransactionPayload,
    next_height: u64,
    wall_ms: u64,
) -> Result<Option<super::admission::SccpAdmissionKeysV1>, super::admission::SccpAdmissionRejectV1>
{
    use super::admission::{SccpAdmissionKeysV1, SccpAdmissionRejectV1, SccpExemptClassV1};
    if count(&payload.instructions) == 0 {
        return Ok(None);
    }
    if !valid_shape(payload) {
        return Err(SccpAdmissionRejectV1::new(
            "Keepalive requires one standalone Ed25519 instruction and empty authority fee intent",
        ));
    }
    if payload.creation_time_ms
        > wall_ms.saturating_add(world.parameters().sumeragi().max_clock_drift_ms())
    {
        return Err(SccpAdmissionRejectV1::new(
            "Keepalive creation exceeds local clock plus committed drift",
        ));
    }
    let candidate = payload
        .creation_time_ms
        .checked_add(1)
        .ok_or_else(|| SccpAdmissionRejectV1::new("Keepalive creation time overflows"))?;
    match due(world, next_height, candidate) {
        Ok(true) => Ok(Some(
            SccpAdmissionKeysV1::new(SccpExemptClassV1::Keepalive)
                .with_exclusive(&payload.authority),
        )),
        Ok(false) => Err(SccpAdmissionRejectV1::new("Keepalive is no longer due")),
        Err(error) => Err(SccpAdmissionRejectV1::new(error.to_string())),
    }
}

/// K1 block-wide carrier count, regardless of instruction or transaction result.
pub(crate) fn check_count(count: usize) -> Result<(), &'static str> {
    if count > 1 && !cfg!(all(test, sumeragi_core_mutation = "HC277")) {
        Err("DuplicateKeepalive")
    } else {
        Ok(())
    }
}

/// CT5 applies only to an uncertified global candidate whose timestamp is too stale.
/// # Errors
/// Returns the original unavailable dependency if stale work cannot yet be classified.
pub fn stale_due_work(
    world: &(impl WorldReadOnly + ?Sized),
    next_height: u64,
    time_ms: u64,
    wall_ms: u64,
    certified: bool,
) -> Result<bool, DueWorkUnavailable> {
    ProgressClock::capture(world, next_height, time_ms)?.is_stale(wall_ms, certified)
}

/// Fixed-size observation of the original parent used again after execution and on retries.
/// It borrows no candidate writes and grants no certified-execution authority.
#[derive(Clone, Copy)]
pub(crate) struct ProgressClock {
    time_ms: u64,
    maximum_lag_ms: u64,
    due: Result<bool, DueWorkUnavailable>,
}

impl ProgressClock {
    pub(crate) fn capture(
        world: &(impl WorldReadOnly + ?Sized),
        next_height: u64,
        time_ms: u64,
    ) -> Result<Self, DueWorkUnavailable> {
        let clock = clock_parameters(world).map_err(|_| DueWorkUnavailable)?;
        Ok(Self {
            time_ms,
            maximum_lag_ms: clock.due_work_max_lag_ms,
            due: due(world, next_height, time_ms),
        })
    }

    pub(crate) fn is_stale(
        &self,
        wall_ms: u64,
        certified: bool,
    ) -> Result<bool, DueWorkUnavailable> {
        if (certified && !cfg!(all(test, sumeragi_core_mutation = "HC282")))
            || cfg!(all(test, sumeragi_core_mutation = "HC281"))
        {
            return Ok(false);
        }
        if wall_ms.saturating_sub(self.time_ms) <= self.maximum_lag_ms {
            return Ok(false);
        }
        self.due
    }
}

/// K4 refresh threshold for an already-due candidate. The keeper owns fresh signatures.
#[must_use]
pub fn needs_fresh_carrier(candidate_ms: u64, wall_ms: u64, maximum_lag_ms: u64) -> bool {
    !cfg!(all(test, sumeragi_core_mutation = "HC280"))
        && wall_ms.saturating_sub(candidate_ms) > maximum_lag_ms / 2
}

/// Execute only the exact admitted direct source; the instruction itself has no effects.
/// # Errors
/// Rejects callback, nested, substituted or replayed carrier execution.
pub fn execute(
    _: Keepalive,
    _: &AccountId,
    state: &mut StateTransaction<'_, '_>,
) -> Result<(), InstructionExecutionError> {
    state.consume_direct_keepalive()
}

#[cfg(test)]
mod tests;
