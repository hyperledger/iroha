//! Finite generated custody renewal. The process owner withdraws Ready before calling this owner.
//! Existing enrollment journals own signatures and once-only dispatch; no transaction is replaced.

use super::{
    activation::{self, Budget, ReadinessExpiry, Restart, validate_live},
    owned::OwnedGateway,
    progress::{Failure, Phase, Progress},
    readiness,
};
use crate::localnet::service_authorities::RetainedProviderServicePlan;
use crate::managed::{
    ManagedStreamTokenCustody, PreparedLocalnet, Result,
    gateway_compliance::{ManagedGatewayCompliance, PromotedGeneratedCatalog},
    native_operation::{ManagedTransactionFinality, invalid, now_ms},
    service_bootstrap::ManagedServiceBootstrap,
    stream_token_custody::RetainedCustodyEnrollment,
};
use iroha_data_model::sorafs::capacity::ProviderId;
use iroha_wallet::operations::BoundedTransactionOptions;
use std::{
    collections::BTreeMap,
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};

const TURN_MAXIMUM: Duration = Duration::from_secs(120);

/// Scheduling coordinates grant no authority. The actual renewal independently observes native
/// custody, and the renderer checks its exact successor and successful transaction again.
#[derive(Clone, Copy)]
struct Schedule {
    sequence: u64,
    midpoint: u64,
    provider_end: u64,
    expiry: ReadinessExpiry,
}
impl Schedule {
    fn select(
        sequence: u64,
        issued: u64,
        expires: u64,
        provider_end: u64,
        observed_at: Instant,
        observed_utc: u64,
    ) -> Result<Self> {
        if !(1..=64).contains(&sequence)
            || issued > observed_utc
            || issued >= expires
            || expires > provider_end
            || provider_end == u64::MAX
        {
            return Err(invalid("invalid original renewal schedule"));
        }
        Ok(Self {
            sequence,
            // Match the sole custody owner's inclusive latter-half boundary for odd intervals.
            midpoint: issued + (expires - issued).div_ceil(2),
            provider_end,
            expiry: ReadinessExpiry::select(expires, observed_at, observed_utc)?,
        })
    }
    fn due_at(&self, utc: u64) -> bool {
        self.sequence < 64 && self.expiry.utc_ceiling() < self.provider_end && utc >= self.midpoint
    }
    fn budget(&self, cancelled: Arc<AtomicBool>, progress: Arc<Progress>) -> Result<Budget> {
        let started = Instant::now();
        let deadline = self.expiry.deadline(TURN_MAXIMUM)?;
        let timeout = deadline
            .checked_duration_since(started)
            .filter(|value| !value.is_zero())
            .ok_or_else(|| invalid("renewal interval expired"))?
            .min(TURN_MAXIMUM);
        progress.enter(Phase::CustodyRenewal);
        Ok(Budget {
            started,
            timeout,
            startup_deadline_ns: None,
            utc_ceiling_unix_ms: Some(self.expiry.utc_ceiling()),
            cancelled,
            progress,
        })
    }
}

/// The exact paid receipt and original finite enrollment timer survive ordinary refreshes.
/// Refresh cannot remap the enrollment expiry onto a later monotonic clock.
#[derive(Clone)]
pub(super) struct Continuation {
    receipt: Arc<readiness::Receipt>,
    provider: ProviderId,
    record_digest: [u8; 32],
    schedule: Schedule,
}
impl Continuation {
    /// Consume freshly selected original interval intent; the receipt and native enrollment
    /// keep their independent owners and the caller's original observation clocks.
    pub(super) fn new(
        plan: &RetainedProviderServicePlan,
        receipt: Arc<readiness::Receipt>,
        enrollment: &RetainedCustodyEnrollment,
        observed_at: Instant,
        observed_utc: u64,
    ) -> Result<Self> {
        let provider_end = plan
            .admission_material()
            .retention_epoch
            .checked_mul(1_000)
            .ok_or_else(|| invalid("original provider interval overflow"))?;
        let statement = enrollment.statement();
        Ok(Self {
            receipt,
            provider: plan.provider_id(),
            record_digest: enrollment.record_digest(),
            schedule: Schedule::select(
                statement.sequence,
                statement.issued_at_unix_ms,
                statement.expires_at_unix_ms,
                provider_end,
                observed_at,
                observed_utc,
            )?,
        })
    }
    pub(super) fn provider(&self) -> ProviderId {
        self.provider
    }
    pub(super) fn revalidate(
        &self,
        provider: ProviderId,
        enrollment: &RetainedCustodyEnrollment,
        receipt: &Arc<readiness::Receipt>,
    ) -> Result<()> {
        if self.provider != provider
            || !Arc::ptr_eq(&self.receipt, receipt)
            || self.record_digest != enrollment.record_digest()
            || self.schedule.sequence != enrollment.statement().sequence
            || self.schedule.expiry.utc_ceiling() != enrollment.statement().expires_at_unix_ms
            || !self.schedule.expiry.current()?
        {
            return Err(invalid(
                "unchanged provider continuation differs or expired",
            ));
        }
        Ok(())
    }
    pub(super) fn expiry(&self) -> ReadinessExpiry {
        self.schedule.expiry
    }

    pub(super) fn begin(
        &self,
        terminal: ManagedTransactionFinality,
        cancelled: Arc<AtomicBool>,
        progress: Arc<Progress>,
        originals: [Continuation; 3],
        catalogs: [PromotedGeneratedCatalog; 3],
    ) -> Result<Option<Turn>> {
        if !self.schedule.expiry.current()? {
            return Err(invalid("original enrollment timer expired"));
        }
        if !self.schedule.due_at(now_ms()?) {
            return Ok(None);
        }
        let mut budget = self.schedule.budget(cancelled, progress)?;
        if originals
            .iter()
            .filter(|value| {
                value.provider == self.provider && value.record_digest == self.record_digest
            })
            .count()
            != 1
        {
            return Err(invalid("renewal lost original aggregate continuation"));
        }
        budget.cap_to_expiries(originals.iter().map(Continuation::expiry), TURN_MAXIMUM)?;
        Ok(Some(Turn {
            budget: Arc::new(budget),
            provider: self.provider,
            originals,
            catalogs,
            sequence: self.schedule.sequence + 1,
            receipt: Arc::clone(&self.receipt),
            previous_terminal: terminal,
        }))
    }
}

/// Only a current observation can hand this turn to the main loop before it withdraws Ready.
pub(super) struct Turn {
    pub(super) budget: Arc<Budget>,
    provider: ProviderId,
    originals: [Continuation; 3],
    catalogs: [PromotedGeneratedCatalog; 3],
    sequence: u64,
    receipt: Arc<readiness::Receipt>,
    previous_terminal: ManagedTransactionFinality,
}

impl Turn {
    pub(super) fn provider(&self) -> ProviderId {
        self.provider
    }
}

/// Both a Catalog startup and a withdrawn-Ready renewal use this one bounded custody owner.
/// The caller holds the actual child guard. This function never creates a readiness Receipt.
pub(super) fn reconcile(
    prepared: &PreparedLocalnet,
    budget: &Budget,
    live: &mut OwnedGateway,
    minimum: ManagedTransactionFinality,
    expected_sequence: Option<u64>,
) -> std::result::Result<(), Failure> {
    use crate::managed::{
        native_operation::Fees,
        stream_token_custody::renewal::{GeneratedRenewalTurn, Reconciliation},
    };
    budget.check()?;
    validate_live(prepared, live, budget)?;
    let provider = live.provider();
    let policies = budget.call(|_| ManagedServiceBootstrap::open(prepared)?.selected_policies())?;
    let options = BoundedTransactionOptions {
        fee_payment: policies.network.runtime_fee_payment.clone(),
        max_total_fees: BTreeMap::from([(
            policies.network.reserve.asset_definition.clone(),
            iroha_primitives::numeric::Quantity::from(1_u64),
        )]),
        deadline: budget.deadline()?,
    };
    let mut turn = budget.call(|deadline| {
        with_custody(prepared, provider, |custody| {
            GeneratedRenewalTurn::begin(
                custody,
                &policies.provider(provider)?.custody,
                Fees::from_options(&options)?,
                minimum,
                deadline,
                Arc::clone(&budget.cancelled),
            )
        })
    })?;
    loop {
        budget.check()?;
        validate_live(prepared, live, budget)?;
        let deadline = budget.deadline()?;
        let result = with_custody(prepared, provider, |custody| {
            custody.reconcile_generated_renewal(&mut turn, deadline)
        });
        budget.check()?;
        validate_live(prepared, live, budget)?;
        match result {
            Ok(Reconciliation::Current(enrollment)) => {
                if expected_sequence
                    .is_some_and(|expected| expected != enrollment.statement().sequence)
                {
                    return Err(budget.progress.unconfirmed());
                }
                return Ok(());
            }
            Ok(Reconciliation::Pending(progress)) => {
                // Only independent inclusion plus a following fresh native head can finish.
                // Public Applied/Expired statuses are not replacement permission.
                let _ = progress;
            }
            Err(crate::managed::Error::Bootstrap(reason)) => {
                return Err(Failure::Bootstrap(reason));
            }
            Err(_) => {}
        }
        budget.wait()?;
    }
}

// Runtime validation independently reopens each provider's custody. Keep an operation's
// exclusive owner inside this call, including on errors; only the same finite renewal turn
// survives between calls. Its original lease, cancellation and deadline are never replaced.
pub(super) fn with_custody<T>(
    prepared: &PreparedLocalnet,
    provider: ProviderId,
    action: impl FnOnce(&mut ManagedStreamTokenCustody) -> Result<T>,
) -> Result<T> {
    let mut custody = ManagedStreamTokenCustody::open(prepared, provider)?;
    action(&mut custody)
}

/// Called only after the main process owner has durably left Ready. An exhausted original fails
/// closed; neither a retry nor a later worker silently renews its retained transaction authority.
pub(super) fn advance(
    prepared: &PreparedLocalnet,
    turn: Turn,
    mut live: OwnedGateway,
) -> std::result::Result<activation::Outcome, Failure> {
    let budget = &turn.budget;
    budget.progress.enter(Phase::CustodyRenewal);
    budget.check()?;
    if live.provider() != turn.provider {
        return Err(budget.progress.unconfirmed());
    }
    validate_live(prepared, &mut live, budget)?;
    budget.call(|_| {
        let previous = live.selected_enrollment(turn.previous_terminal)?;
        if previous.statement().sequence.checked_add(1) != Some(turn.sequence) {
            return Err(invalid("renewal differs from actual launch predecessor"));
        }
        Ok(())
    })?;
    reconcile(
        prepared,
        budget,
        &mut live,
        turn.previous_terminal,
        Some(turn.sequence),
    )?;
    let (owner, revision) =
        budget.call(|deadline| live.prepare_successor(turn.sequence, deadline))?;
    budget.call(|_| activation::require_carriers(&revision))?;
    activation::confirm_carriers(prepared, revision.required_transactions(), budget)?;
    // Refresh through the existing catalog coordinator before the old gateway is stopped.
    // The ACK remains separate from exact promoted readback and fresh post-restart discovery.
    budget.progress.enter(Phase::Catalog);
    let catalog = budget.call(|deadline| {
        let publisher = ManagedGatewayCompliance::open(prepared, turn.provider)?;
        publisher.advance(&mut live, deadline)
    })?;
    validate_live(prepared, &mut live, budget)?;
    let plans = budget.call(|_| {
        prepared
            .provider_service_plans()?
            .ok_or_else(|| invalid("original provider plans absent"))
    })?;
    let index = plans
        .iter()
        .position(|plan| plan.provider_id() == turn.provider)
        .ok_or_else(|| budget.progress.unconfirmed())?;
    let mut catalogs = turn.catalogs;
    catalogs[index] = catalog;
    budget
        .call(|_| {
            Restart::renewed(
                turn.receipt,
                owner,
                revision,
                catalogs,
                turn.originals,
                turn.provider,
            )
        })
        .map(activation::Outcome::Restart)
}

#[cfg(test)]
mod tests;
