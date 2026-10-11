//! Closed unsigned dispatch transitions; concrete owners retain every native preflight and wallet.

use super::*;
use crate::managed::{
    native_operation::authorization::DispatchAuthorization,
    native_operation::{now_ms, require_deadline},
};
use std::time::Instant;

/// The ordinary public one-intent API can retain exactly one explicit authorization. It cannot
/// replace an expired request or select a successor without the generated worker capability.
pub(in crate::managed) fn initial(
    mut history: History,
    terms: Terms,
    observation: Observation,
    deadline: Instant,
    mut inspect: impl FnMut(&Attempt) -> Result<VerifiedNativePreparation>,
    mut retain_request: impl FnMut(&Attempt, Observation, Instant) -> Result<VerifiedNativePreparation>,
) -> Result<()> {
    require_deadline(deadline)?;
    history.scope.require_active()?;
    // The concrete owner selected these terms from this exact canonical History. Its original
    // native handles stay live; wallet inspection revalidates all custody before and after.
    history.verify_wallets(&mut inspect)?;
    if history.reservation_pending() {
        let reserved = &history
            .dispatch
            .as_ref()
            .ok_or_else(|| invalid("reserved dispatch absent"))?
            .highest;
        if reserved.origin != Origin::Explicit || reserved.terms != terms {
            return Err(invalid("explicit reserved dispatch changed original terms"));
        }
        require_deadline(deadline)?;
        history.finish_reserved(&history.operation, false)?;
        // Only finishing a retained reservation changed dispatch metadata. The unchanged path
        // already passed the complete current-custody checks around wallet inspection.
        history = history.reread()?;
    }
    if let Some(last) = history.last() {
        last.terms()
            .matches(terms.requested_deadline_unix_ms, &terms.options(deadline))?;
        if last.terms() != &terms {
            return Err(invalid("original dispatch signing ceiling changed"));
        }
        if last.is_committed() {
            return Ok(());
        }
        if history.attempts.len() != 1 || last.origin() != &Origin::Explicit {
            return Err(ManagedBootstrapFailure::TransitionPending.into());
        }
        history.retain_root(&history.operation)?;
        let observed = last.observation.unwrap_or(observation);
        last.retain_observation(observed)?;
        let preparation = retain_request(last, observed, terms.signing_deadline(deadline)?)?;
        return commit(last, None, observed, &preparation);
    }
    let attempt = history.reserve(&history.operation, Origin::Explicit, terms)?;
    attempt.retain_observation(observation)?;
    let preparation = retain_request(
        &attempt,
        observation,
        attempt.terms().signing_deadline(deadline)?,
    )?;
    commit(&attempt, None, observation, &preparation)
}

/// The generated worker may finish an original attempt or replace one proven unsigned request.
/// Native policy/intent comparison happens before this call. `fresh` remains the concrete native
/// owner's authenticated prerequisite; it cannot be supplied by an external caller. The wallet
/// retainer is purpose-closed and performs no HTTP, fee quote, payload creation or signing.
pub(in crate::managed) fn generated(
    operation: &PrivateDirectory,
    purpose: Purpose,
    semantic: [u8; 32],
    scope: &HistoryScope,
    authorization: &dyn DispatchAuthorization,
    deadline: Instant,
    body_expiry: Option<u64>,
    mut inspect: impl FnMut(&Attempt) -> Result<VerifiedNativePreparation>,
    mut retire: impl FnMut(&Attempt) -> Result<RetiredNativeRequest>,
    mut retain_request: impl FnMut(&Attempt, Observation, Instant) -> Result<VerifiedNativePreparation>,
    mut fresh: impl FnMut(&Terms, Instant) -> Result<Observation>,
    mut observation_usable: impl FnMut(&Attempt) -> Result<bool>,
) -> Result<()> {
    authorization.check(purpose, deadline)?;
    scope.require_active()?;
    let history = History::read(operation, purpose, semantic, scope)?;
    history.require_fees(authorization.fees())?;
    history.verify_wallets(&mut inspect)?;
    if history.reservation_pending() {
        authorization.check(purpose, deadline)?;
        history.finish_reserved(operation, false)?;
    }
    let history = history.reread()?;
    history.verify_wallets(&mut inspect)?;
    let origin = authorization.origin()?;
    if let Some(last) = history.last() {
        if last.is_committed() {
            let preparation = inspect(last)?;
            match preparation.phase() {
                NativePreparationPhase::Signed => return Ok(()),
                NativePreparationPhase::PayloadRetained => {
                    if preparation.unprepared_status()
                        == Some(iroha_wallet::operations::OperationStatus::Expired)
                        || now_ms()? >= last.terms().signing_deadline_unix_ms
                    {
                        return Err(ManagedBootstrapFailure::PayloadExpired.into());
                    }
                    return Ok(());
                }
                NativePreparationPhase::RequestOnly => {
                    if now_ms()? < last.terms().signing_deadline_unix_ms
                        && preparation.unprepared_status()
                            != Some(iroha_wallet::operations::OperationStatus::Expired)
                    {
                        if !observation_usable(last)? {
                            return Err(
                                ManagedBootstrapFailure::EnrollmentObservationExpired.into()
                            );
                        }
                        return Ok(());
                    }
                    if last.origin() == &origin {
                        return Err(ManagedBootstrapFailure::AuthorizationExpired.into());
                    }
                }
                NativePreparationPhase::Missing => {
                    return Err(invalid(
                        "committed dispatch lost its original wallet request",
                    ));
                }
                NativePreparationPhase::Retired => {
                    return Err(invalid(
                        "selected wallet retired without its reserved successor",
                    ));
                }
            }
        } else if last.origin() == &origin || now_ms()? < last.terms().signing_deadline_unix_ms {
            // A new worker may finish a still-live unsigned prefix, but keeps every original
            // term and observation; it neither claims replacement nor selects a new attempt.
            if last.observation.is_some() && !observation_usable(last)? {
                return Err(ManagedBootstrapFailure::EnrollmentObservationExpired.into());
            }
            history.retain_root(operation)?;
            if let Some(previous) = history.predecessor() {
                authorization.check(purpose, deadline)?;
                retire_predecessor(previous, last, &mut inspect, &mut retire)?;
            }
            let fresh_observation = fresh(last.terms(), authorization.check(purpose, deadline)?)?;
            let observed = last.observation.unwrap_or(fresh_observation);
            authorization.check(purpose, deadline)?;
            last.retain_observation(observed)?;
            let preparation =
                retain_request(last, observed, authorization.check(purpose, deadline)?)?;
            authorization.check(purpose, deadline)?;
            return commit(last, history.predecessor(), observed, &preparation);
        }
        authorization.claim_replacement(last.digest()?, deadline)?;
        // Reconcile an exact older transition before closing its still-unsigned reservation.
        if !last.is_committed() {
            history.retain_root(operation)?;
            if let Some(previous) = history.predecessor() {
                authorization.check(purpose, deadline)?;
                retire_predecessor(previous, last, &mut inspect, &mut retire)?;
            }
        }
    }
    // Retirement or root publication may have completed an interrupted local prefix. Re-read
    // all metadata and inspect all canonical wallets before adding the next authorization.
    let history = history.reread()?;
    history.verify_wallets(&mut inspect)?;
    authorization.check(purpose, deadline)?;
    let terms = authorization.terms(deadline, body_expiry)?;
    let successor = history.reserve(operation, origin, terms)?;
    if let Some(previous) = history.last() {
        authorization.check(purpose, deadline)?;
        retire_predecessor(previous, &successor, &mut inspect, &mut retire)?;
    }
    let observed = fresh(successor.terms(), authorization.check(purpose, deadline)?)?;
    authorization.check(purpose, deadline)?;
    successor.retain_observation(observed)?;
    let preparation = retain_request(
        &successor,
        observed,
        authorization.check(purpose, deadline)?,
    )?;
    authorization.check(purpose, deadline)?;
    commit(&successor, history.last(), observed, &preparation)
}

pub(super) fn retire_predecessor(
    previous: &Attempt,
    successor: &Attempt,
    inspect: &mut impl FnMut(&Attempt) -> Result<VerifiedNativePreparation>,
    retire: &mut impl FnMut(&Attempt) -> Result<RetiredNativeRequest>,
) -> Result<()> {
    if previous.observation.is_none() {
        return retire_missing(previous, successor);
    }
    match inspect(previous)?.phase() {
        NativePreparationPhase::Missing => retire_missing(previous, successor),
        NativePreparationPhase::RequestOnly | NativePreparationPhase::Retired => {
            let receipt = retire(previous)?;
            retire_request(previous, successor, &receipt)
        }
        NativePreparationPhase::PayloadRetained | NativePreparationPhase::Signed => Err(invalid(
            "bootstrap epoch cannot replace retained paid material",
        )),
    }
}
