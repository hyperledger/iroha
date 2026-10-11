//! Bounded maintenance replaces an observation only after exact catalog and fresh native checks.
//! It never starts/stops children, renews initial custody, submits a transaction or extends a timer.

use super::{
    activation::{Budget, ReadinessExpiry, validate_live},
    owned::OwnedGateway,
    progress::{Failure, Phase, Progress},
    renewal,
};
use crate::localnet::service_authorities::RetainedProviderServicePlan;
use crate::managed::{
    ManagedProviderAdvertisement, PreparedLocalnet, Result,
    build_registry::{self, DISCOVERY_FRESHNESS, GeneratedServiceObservation},
    gateway_compliance::{ManagedGatewayCompliance, PromotedGeneratedCatalog},
    native_operation::{ManagedTransactionFinality, invalid, now_ms},
};
use std::{
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};

const TURN_MAXIMUM: Duration = Duration::from_secs(15);
const RETRY_DELAY: Duration = Duration::from_secs(1);

#[derive(Clone, Copy)]
struct Interval {
    issued: u64,
    expires: u64,
}
impl Interval {
    fn new(issued: u64, expires: u64) -> Result<Self> {
        if issued >= expires || expires == u64::MAX {
            return Err(invalid("invalid signed maintenance interval"));
        }
        Ok(Self { issued, expires })
    }
    fn midpoint(self) -> u64 {
        // The difference is bounded by expires; adding it to issued cannot overflow.
        self.issued + (self.expires - self.issued) / 2
    }
}

#[derive(Clone)]
pub(super) struct Selection {
    continuation: renewal::Continuation,
    terminal: ManagedTransactionFinality,
    catalog: PromotedGeneratedCatalog,
    advert_interval: Interval,
    catalog_interval: Interval,
}

/// A finite observation and its exact original selections. Neither a timer nor a transport ACK
/// can construct a replacement; native discovery remains the only constructor input below.
#[derive(Clone)]
pub(super) struct ProviderObservation {
    selection: Selection,
    timing: Timing,
}
#[derive(Clone, Copy)]
struct Timing {
    expiry: ReadinessExpiry,
    next_monotonic: Instant,
    next_utc: u64,
}
impl Timing {
    fn select(
        valid_until: u64,
        advert: Interval,
        catalog: Interval,
        observed_at: Instant,
        observed_utc: u64,
    ) -> Result<Self> {
        let freshness_ms = u64::try_from(DISCOVERY_FRESHNESS.as_millis())
            .map_err(|_| invalid("discovery freshness interval overflow"))?;
        let freshness_end = observed_utc
            .checked_add(freshness_ms)
            .ok_or_else(|| invalid("discovery freshness interval overflow"))?;
        let expiry =
            ReadinessExpiry::select(valid_until.min(freshness_end), observed_at, observed_utc)?;
        let next_utc = observed_utc
            .checked_add(freshness_ms / 2)
            .ok_or_else(|| invalid("discovery refresh interval overflow"))?
            .min(advert.midpoint())
            .min(catalog.midpoint());
        let mut timing = Self {
            expiry,
            next_monotonic: observed_at,
            next_utc: observed_utc,
        };
        // A stale but still valid signed interval can request an immediate refresh. Bound it
        // by one retry delay to avoid a busy loop if a server keeps returning the same bytes.
        timing.schedule(next_utc, observed_at, observed_utc)?;
        Ok(timing)
    }
    fn schedule(&mut self, requested: u64, now: Instant, utc: u64) -> Result<()> {
        let minimum = utc
            .checked_add(
                u64::try_from(RETRY_DELAY.as_millis())
                    .map_err(|_| invalid("maintenance retry interval overflow"))?,
            )
            .ok_or_else(|| invalid("maintenance retry interval overflow"))?;
        let next_utc = requested.max(minimum);
        let delay = Duration::from_millis(next_utc.saturating_sub(utc));
        // A pending retry may never postpone the original expiry or create a new lease.
        self.next_monotonic = now
            .checked_add(delay)
            .ok_or_else(|| invalid("maintenance schedule overflow"))?
            .min(self.expiry.deadline(Duration::MAX)?);
        self.next_utc = next_utc;
        Ok(())
    }
    fn current_at(&self, enrollment: ReadinessExpiry, now: Instant, utc: u64) -> bool {
        self.expiry.current_at(now, utc) && enrollment.current_at(now, utc)
    }
    fn due_at(&self, now: Instant, utc: u64) -> bool {
        now >= self.next_monotonic || utc >= self.next_utc
    }
}
impl ProviderObservation {
    pub(super) fn new(
        continuation: renewal::Continuation,
        terminal: ManagedTransactionFinality,
        catalog: PromotedGeneratedCatalog,
        current: GeneratedServiceObservation,
        observed_at: Instant,
        observed_utc: u64,
    ) -> Result<Self> {
        let (issued, expires) = current.advert_interval();
        let advert_interval = Interval::new(issued, expires)?;
        let catalog_interval = Interval::new(
            catalog
                .generated_at_unix
                .checked_mul(1_000)
                .ok_or_else(|| invalid("catalog interval overflow"))?,
            catalog
                .valid_until_unix
                .checked_mul(1_000)
                .ok_or_else(|| invalid("catalog interval overflow"))?,
        )?;
        let timing = Timing::select(
            current.valid_until_unix_ms().min(catalog_interval.expires),
            advert_interval,
            catalog_interval,
            observed_at,
            observed_utc,
        )?;
        Ok(Self {
            selection: Selection {
                continuation,
                terminal,
                catalog,
                advert_interval,
                catalog_interval,
            },
            timing,
        })
    }
    pub(super) fn due(&self) -> Result<bool> {
        Ok(self.timing.due_at(Instant::now(), now_ms()?))
    }
    pub(super) fn begin(&self, cancelled: Arc<AtomicBool>) -> Result<(Selection, Budget)> {
        let started = Instant::now();
        let deadline = self.timing.expiry.deadline(TURN_MAXIMUM)?;
        let timeout = deadline
            .checked_duration_since(started)
            .filter(|value| !value.is_zero())
            .ok_or_else(|| invalid("maintenance observation expired"))?;
        Ok((
            self.selection.clone(),
            Budget {
                started,
                timeout,
                startup_deadline_ns: None,
                utc_ceiling_unix_ms: Some(self.timing.expiry.utc_ceiling()),
                cancelled,
                progress: Arc::new(Progress::default()),
            },
        ))
    }
    pub(super) fn retry(&mut self) -> Result<()> {
        let utc = now_ms()?;
        self.timing.schedule(utc, Instant::now(), utc)
    }
}

/// One refresh attempt. Every signature uses its existing original-only owner; the old observation
/// remains held by the main loop throughout the attempt and wins over a late success.
fn refresh_provider(
    prepared: &PreparedLocalnet,
    selected: Selection,
    mut live: OwnedGateway,
    budget: &Budget,
) -> std::result::Result<ProviderObservation, Failure> {
    budget.check()?;
    if live.provider() != selected.continuation.provider() {
        return Err(budget.progress.unconfirmed());
    }
    validate_live(prepared, &mut live, budget)?;
    let now = budget.call(|_| now_ms())?;
    if now >= selected.advert_interval.midpoint() {
        budget.progress.enter(Phase::ProviderAdvertisement);
        budget.call(|deadline| {
            ManagedProviderAdvertisement::open(prepared, live.provider())?.publish(deadline)
        })?;
        validate_live(prepared, &mut live, budget)?;
    }
    let publisher = budget.call(|_| ManagedGatewayCompliance::open(prepared, live.provider()))?;
    let catalog = if now >= selected.catalog_interval.midpoint() {
        budget.progress.enter(Phase::Catalog);
        budget.call(|deadline| publisher.advance(&mut live, deadline))?
    } else {
        selected.catalog
    };
    budget.progress.enter(Phase::PromotedCatalog);
    budget.call(|deadline| publisher.observe_promoted(&mut live, catalog, deadline))?;
    drop(publisher);
    budget.progress.enter(Phase::Discovery);
    let observed_at = Instant::now();
    let observed_utc = budget.call(|_| now_ms())?;
    let current = budget.call(|deadline| {
        let enrollment = live.selected_enrollment(selected.terminal)?;
        build_registry::observe_generated_service(
            prepared,
            live.provider(),
            enrollment,
            selected.terminal,
            deadline,
        )
    })?;
    let observation = budget.call(|_| {
        ProviderObservation::new(
            selected.continuation,
            selected.terminal,
            catalog,
            current,
            observed_at,
            observed_utc,
        )
    })?;
    validate_live(prepared, &mut live, budget)?;
    budget.check()?;
    Ok(observation)
}

/// All three finite observations, in the original profile's validated provider-slot order.
#[derive(Clone)]
pub(super) struct Observation {
    providers: [ProviderObservation; 3],
}

pub(super) struct RefreshSelection {
    selected: Selection,
    original: Observation,
    slot: usize,
}
impl RefreshSelection {
    pub(super) fn provider(&self) -> iroha_data_model::sorafs::capacity::ProviderId {
        self.selected.continuation.provider()
    }
}
impl Observation {
    /// Combine observations only after the caller freshly selects the original provider order.
    /// The plans carry no current provider eligibility or replacement observation clocks.
    pub(super) fn new(
        plans: &[RetainedProviderServicePlan; 3],
        providers: [ProviderObservation; 3],
    ) -> Result<Self> {
        for (plan, observed) in plans.iter().zip(&providers) {
            if plan.provider_id() != observed.selection.continuation.provider() {
                return Err(invalid(
                    "aggregate observation changed original provider order",
                ));
            }
        }
        let value = Self { providers };
        if !value.current()? {
            return Err(invalid("aggregate provider observation expired"));
        }
        Ok(value)
    }
    pub(super) fn current(&self) -> Result<bool> {
        let mono = Instant::now();
        let utc = now_ms()?;
        Ok(self.providers.iter().all(|value| {
            value
                .timing
                .current_at(value.selection.continuation.expiry(), mono, utc)
        }))
    }
    pub(super) fn due(&self) -> Result<bool> {
        let mono = Instant::now();
        let utc = now_ms()?;
        Ok(self
            .providers
            .iter()
            .any(|value| value.timing.due_at(mono, utc)))
    }
    pub(super) fn begin(&self, cancelled: Arc<AtomicBool>) -> Result<(RefreshSelection, Budget)> {
        if !self.current()? {
            return Err(invalid("aggregate refresh observation expired"));
        }
        let mono = Instant::now();
        let utc = now_ms()?;
        let slot = self
            .providers
            .iter()
            .position(|value| value.timing.due_at(mono, utc))
            .ok_or_else(|| invalid("no original provider observation is due"))?;
        let (selected, mut budget) = self.providers[slot].begin(cancelled)?;
        budget.cap_to_expiries(
            self.providers
                .iter()
                .flat_map(|value| [value.timing.expiry, value.selection.continuation.expiry()]),
            TURN_MAXIMUM,
        )?;
        Ok((
            RefreshSelection {
                selected,
                original: self.clone(),
                slot,
            },
            budget,
        ))
    }
    pub(super) fn retry(&mut self) -> Result<()> {
        for value in &mut self.providers {
            if value.due()? {
                value.retry()?;
            }
        }
        if !self.current()? {
            return Err(invalid("aggregate retry observation expired"));
        }
        Ok(())
    }
    pub(super) fn renewal(
        &self,
        cancelled: Arc<AtomicBool>,
        progress: Arc<Progress>,
    ) -> Result<Option<renewal::Turn>> {
        if !self.current()? {
            return Err(invalid("aggregate renewal observation expired"));
        }
        let continuations =
            std::array::from_fn(|index| self.providers[index].selection.continuation.clone());
        let catalogs = std::array::from_fn(|index| self.providers[index].selection.catalog);
        for value in &self.providers {
            if let Some(turn) = value.selection.continuation.begin(
                value.selection.terminal,
                Arc::clone(&cancelled),
                Arc::clone(&progress),
                continuations.clone(),
                catalogs,
            )? {
                return Ok(Some(turn));
            }
        }
        Ok(None)
    }
}

/// One physical background refresh preserves every other provider's exact original timer.
pub(super) fn refresh(
    prepared: &PreparedLocalnet,
    selected: RefreshSelection,
    live: OwnedGateway,
    budget: &Budget,
) -> std::result::Result<Observation, Failure> {
    budget.check()?;
    let RefreshSelection {
        selected,
        mut original,
        slot,
    } = selected;
    let next = refresh_provider(prepared, selected, live, budget)?;
    // Refuse success across any gap in the old aggregate, including an unchanged provider.
    if !original.current().unwrap_or(false) {
        return Err(Failure::ObservationExpired);
    }
    original.providers[slot] = next;
    budget.call(|_| {
        // Refresh keeps its original standalone capture after the owned gateway has dropped.
        let plans = prepared
            .provider_service_plans()?
            .ok_or_else(|| invalid("original provider plans absent"))?;
        Observation::new(&plans, original.providers)
    })
}

#[cfg(test)]
mod tests;
