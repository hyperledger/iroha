//! Closed unsigned dispatch transitions; concrete owners retain every native preflight and wallet.

use super::*;
use crate::managed::{
    native_operation::authorization::DispatchAuthorization,
    native_operation::{now_ms, require_deadline},
};
use std::time::Instant;

/// Concrete prerequisite request at the sole generated transition's original boundary.
/// An optional first reservation is a native owner, never a scalar native-state approval.
pub(in crate::managed) struct GeneratedPrerequisite<'a> {
    terms: &'a Terms,
    first: Option<FirstReservation<'a>>,
}
impl<'a> GeneratedPrerequisite<'a> {
    fn current(terms: &'a Terms) -> Self {
        Self { terms, first: None }
    }
    fn reserved(
        history: &'a History,
        operation: &'a PrivateDirectory,
        attempt: &'a Attempt,
    ) -> Self {
        let first = (!norito::core::decode_limits_active()
            && matches!(history.scope, HistoryScope::FixedBody)
            && matches!(
                history.purpose,
                Purpose::ReservePolicy | Purpose::CustodyConfigure(_)
            )
            && history.dispatch.is_none()
            && history.root.is_none()
            && history.attempts.is_empty()
            && !history.empty_tail
            && history.closing.is_none()
            && history.closed.is_none())
        .then_some(FirstReservation {
            history,
            operation,
            attempt,
        });
        Self {
            terms: attempt.terms(),
            first,
        }
    }
    /// Consume the native first-reservation view, if this is still an inactive decode owner.
    pub(in crate::managed) fn into_first(self) -> Option<FirstReservation<'a>> {
        if norito::core::decode_limits_active() {
            None
        } else {
            self.first
        }
    }
}

impl std::ops::Deref for GeneratedPrerequisite<'_> {
    type Target = Terms;
    fn deref(&self) -> &Self::Target {
        self.terms
    }
}

/// The sole generated producer's newly published first reservation over an empty History.
/// All fields are private; no caller may manufacture this view from a path or ordinal.
pub(in crate::managed) struct FirstReservation<'a> {
    history: &'a History,
    operation: &'a PrivateDirectory,
    attempt: &'a Attempt,
}
impl FirstReservation<'_> {
    pub(in crate::managed) fn validate(
        &self,
        operation: &PrivateDirectory,
        purpose: Purpose,
        semantic: [u8; 32],
    ) -> Result<()> {
        if !std::ptr::eq(operation, self.operation)
            || self.history.purpose != purpose
            || self.history.semantic != semantic
            || self.attempt.authorization.ordinal != 1
            || self.attempt.authorization.previous.is_some()
            || !matches!(self.attempt.origin(), Origin::Generated { .. })
        {
            return Err(invalid(
                "initial admission belongs to another first reservation",
            ));
        }
        // Reopen through the canonical producer after our own reservation. This is one body,
        // and preserves complete namespace/Original/authorization/handle refusal before reuse.
        let current = History::read_retained(
            operation,
            purpose,
            semantic,
            &HistoryScope::FixedBody,
            self.history,
        )?;
        if current.attempts.len() != 1
            || current.reservation_pending()
            || current.empty_tail
            || current.closing.is_some()
            || current.closed.is_some()
            || current.last().is_none_or(|attempt| {
                attempt.authorization != self.attempt.authorization
                    || attempt.observation.is_some()
                    || attempt.commit.is_some()
                    || attempt.retirement.is_some()
            })
        {
            return Err(invalid(
                "initial reservation acquired another retained stage",
            ));
        }
        current.verify_wallets(|_| Err(invalid("initial reservation acquired a wallet")))
    }
}

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
    retire: impl FnMut(&Attempt) -> Result<RetiredNativeRequest>,
    retain_request: impl FnMut(&Attempt, Observation, Instant) -> Result<VerifiedNativePreparation>,
    fresh: impl FnMut(GeneratedPrerequisite<'_>, Instant) -> Result<Observation>,
    observation_usable: impl FnMut(&Attempt) -> Result<bool>,
) -> Result<()> {
    generated_with_inspection(
        operation,
        purpose,
        semantic,
        scope,
        authorization,
        deadline,
        body_expiry,
        GeneratedInspection::Generic(&mut inspect),
        retire,
        retain_request,
        fresh,
        observation_usable,
    )
}

/// Concrete enrollment inspector may consolidate only the empty read-only prefix.
/// Every existing-attempt callback and effect remains in the shared generated owner.
pub(in crate::managed) fn generated_native(
    operation: &PrivateDirectory,
    purpose: Purpose,
    semantic: [u8; 32],
    scope: &HistoryScope,
    authorization: &dyn DispatchAuthorization,
    deadline: Instant,
    body_expiry: Option<u64>,
    native: &crate::managed::stream_token_custody::body_history::NativeClosureInspector<'_>,
    mut inspect: impl FnMut(&Attempt) -> Result<VerifiedNativePreparation>,
    retire: impl FnMut(&Attempt) -> Result<RetiredNativeRequest>,
    retain_request: impl FnMut(&Attempt, Observation, Instant) -> Result<VerifiedNativePreparation>,
    fresh: impl FnMut(GeneratedPrerequisite<'_>, Instant) -> Result<Observation>,
    observation_usable: impl FnMut(&Attempt) -> Result<bool>,
) -> Result<()> {
    generated_with_inspection(
        operation,
        purpose,
        semantic,
        scope,
        authorization,
        deadline,
        body_expiry,
        GeneratedInspection::Native(native, &mut inspect),
        retire,
        retain_request,
        fresh,
        observation_usable,
    )
}

enum GeneratedInspection<'borrow, 'source> {
    Generic(&'borrow mut dyn FnMut(&Attempt) -> Result<VerifiedNativePreparation>),
    Native(
        &'borrow crate::managed::stream_token_custody::body_history::NativeClosureInspector<
            'source,
        >,
        &'borrow mut dyn FnMut(&Attempt) -> Result<VerifiedNativePreparation>,
    ),
}
impl GeneratedInspection<'_, '_> {
    fn inspect(&mut self, attempt: &Attempt) -> Result<VerifiedNativePreparation> {
        match self {
            Self::Generic(inspect) => inspect(attempt),
            Self::Native(_, inspect) => inspect(attempt),
        }
    }
}

fn generated_with_inspection(
    operation: &PrivateDirectory,
    purpose: Purpose,
    semantic: [u8; 32],
    scope: &HistoryScope,
    authorization: &dyn DispatchAuthorization,
    deadline: Instant,
    body_expiry: Option<u64>,
    mut inspection: GeneratedInspection<'_, '_>,
    mut retire: impl FnMut(&Attempt) -> Result<RetiredNativeRequest>,
    mut retain_request: impl FnMut(&Attempt, Observation, Instant) -> Result<VerifiedNativePreparation>,
    mut fresh: impl FnMut(GeneratedPrerequisite<'_>, Instant) -> Result<Observation>,
    mut observation_usable: impl FnMut(&Attempt) -> Result<bool>,
) -> Result<()> {
    authorization.check(purpose, deadline)?;
    scope.require_active()?;
    let history = History::read(operation, purpose, semantic, scope)?;
    history.require_fees(authorization.fees())?;
    let (history, progress) = match &inspection {
        GeneratedInspection::Native(inspector, _) => {
            generated_read_phase::read_empty_prefix(history, authorization, inspector)?
        }
        GeneratedInspection::Generic(_) => (history, generated_read_phase::Progress::Initial),
    };
    let mut inspect = |attempt: &Attempt| inspection.inspect(attempt);
    let (history, origin, ready) = match progress {
        generated_read_phase::Progress::BeforeFinalWallet(origin) => {
            history.verify_wallets(&mut inspect)?;
            (history, origin, true)
        }
        generated_read_phase::Progress::Complete(origin) => (history, origin, true),
        progress @ (generated_read_phase::Progress::Initial
        | generated_read_phase::Progress::BeforeFirstWallet) => {
            let history = if matches!(progress, generated_read_phase::Progress::Initial) {
                history.verify_wallets(&mut inspect)?;
                if history.reservation_pending() {
                    authorization.check(purpose, deadline)?;
                    history.finish_reserved(operation, false)?;
                }
                history.reread()?
            } else {
                history
            };
            history.verify_wallets(&mut inspect)?;
            (history, authorization.origin()?, false)
        }
    };
    if !ready && let Some(last) = history.last() {
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
            let fresh_observation = fresh(
                GeneratedPrerequisite::current(last.terms()),
                authorization.check(purpose, deadline)?,
            )?;
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
    let history = if ready {
        history
    } else {
        let history = history.reread()?;
        history.verify_wallets(&mut inspect)?;
        history
    };
    authorization.check(purpose, deadline)?;
    let terms = authorization.terms(deadline, body_expiry)?;
    let successor = history.reserve(operation, origin, terms)?;
    if let Some(previous) = history.last() {
        authorization.check(purpose, deadline)?;
        retire_predecessor(previous, &successor, &mut inspect, &mut retire)?;
    }
    let observed = fresh(
        GeneratedPrerequisite::reserved(&history, operation, &successor),
        authorization.check(purpose, deadline)?,
    )?;
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
