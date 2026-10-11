//! Bounded generated-service activation; actual child creation and restart belong to the main loop.

use super::{
    POLL, PreparedLocalnet, Result, maintenance,
    owned::{GeneratedLaunch, OwnedGateway},
    progress::{Failure, Phase, Progress},
    readiness, renewal,
};
use crate::{
    localnet::LocalnetServiceProfile,
    managed::{
        ManagedProviderAdvertisement, build_registry,
        gateway_compliance::{
            LiveGatewayProcess, ManagedGatewayCompliance, PromotedGeneratedCatalog,
        },
        generated_service_runtime::{
            GeneratedRuntimeStage, GeneratedServiceRuntime, GeneratedServiceRuntimeRevision,
        },
        native_operation::{ManagedTransactionFinality, invalid, now_ms},
        service_bootstrap::{
            GeneratedBootstrapAuthorization, ManagedServiceBootstrap, ServiceBootstrapProgress,
        },
    },
};
use iroha_data_model::sorafs::capacity::ProviderId;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

#[path = "activation/catalog.rs"]
mod catalog;

pub(super) struct Budget {
    pub(super) started: Instant,
    pub(super) timeout: Duration,
    pub(super) startup_deadline_ns: Option<u128>,
    pub(super) utc_ceiling_unix_ms: Option<u64>,
    pub(super) cancelled: Arc<AtomicBool>,
    pub(super) progress: Arc<Progress>,
}
impl Budget {
    pub(super) fn check(&self) -> std::result::Result<Duration, Failure> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(self.progress.cancelled());
        }
        let remaining = self
            .timeout
            .checked_sub(self.started.elapsed())
            .filter(|value| !value.is_zero())
            .ok_or_else(|| self.progress.deadline())?;
        let remaining = if let Some(deadline) = self.startup_deadline_ns {
            remaining.min(
                super::continuous_remaining(deadline)
                    .map_err(|_| self.progress.unconfirmed())?
                    .ok_or_else(|| self.progress.deadline())?,
            )
        } else {
            remaining
        };
        let Some(ceiling) = self.utc_ceiling_unix_ms else {
            return Ok(remaining);
        };
        let now = now_ms().map_err(|_| self.progress.unconfirmed())?;
        let utc_remaining = ceiling
            .checked_sub(now)
            .and_then(|value| value.checked_sub(1))
            .filter(|value| *value > 0)
            .map(Duration::from_millis)
            .ok_or(Failure::ObservationExpired)?;
        Ok(remaining.min(utc_remaining))
    }
    pub(super) fn deadline(&self) -> std::result::Result<Instant, Failure> {
        let observed = Instant::now();
        let remaining = self.check()?;
        let original = self
            .started
            .checked_add(self.timeout)
            .ok_or_else(|| self.progress.unconfirmed())?;
        Ok(observed
            .checked_add(remaining)
            .ok_or_else(|| self.progress.unconfirmed())?
            .min(original))
    }
    /// Intersect a turn with every original timer without remapping any monotonic expiry.
    /// Commit both caps together only after every finite input and the result remain current.
    pub(super) fn cap_to_expiries(
        &mut self,
        expiries: impl IntoIterator<Item = ReadinessExpiry>,
        maximum: Duration,
    ) -> Result<()> {
        let mut timeout = self.timeout.min(maximum);
        let mut utc_ceiling = self.utc_ceiling_unix_ms;
        for expiry in expiries {
            let remaining = expiry
                .deadline(maximum)?
                .checked_duration_since(self.started)
                .filter(|value| !value.is_zero())
                .ok_or_else(|| invalid("aggregate service interval expired"))?;
            timeout = timeout.min(remaining);
            utc_ceiling =
                Some(utc_ceiling.map_or(expiry.utc_ceiling(), |old| old.min(expiry.utc_ceiling())));
        }
        let end = self
            .started
            .checked_add(timeout)
            .ok_or_else(|| invalid("aggregate service deadline overflow"))?;
        let utc = now_ms()?;
        if timeout.is_zero()
            || Instant::now() >= end
            || utc_ceiling.is_some_and(|end| end.saturating_sub(1) <= utc)
        {
            return Err(invalid("aggregate service interval expired"));
        }
        self.timeout = timeout;
        self.utc_ceiling_unix_ms = utc_ceiling;
        Ok(())
    }

    pub(super) fn call<T>(
        &self,
        action: impl FnOnce(Instant) -> Result<T>,
    ) -> std::result::Result<T, Failure> {
        let result = action(self.deadline()?);
        self.check()?;
        result.map_err(|error| match error {
            crate::managed::Error::Bootstrap(reason) => Failure::Bootstrap(reason),
            _ => self.progress.unconfirmed(),
        })
    }
    pub(super) fn wait(&self) -> std::result::Result<(), Failure> {
        thread::sleep(POLL.min(self.check()?));
        self.check().map(|_| ())
    }
}

/// Capability handoff contains the actual paid receipt and opaque renderer product.
/// Public reports alone cannot manufacture this private value.
pub(super) struct Restart {
    receipt: Arc<readiness::Receipt>,
    owner: Arc<GeneratedServiceRuntime>,
    revision: GeneratedServiceRuntimeRevision,
    required: Vec<ManagedTransactionFinality>,
    catalogs: [PromotedGeneratedCatalog; 3],
    retained: Option<RetainedContinuations>,
}
pub(super) enum Outcome {
    Restart(Restart),
    Complete(Option<maintenance::Observation>),
}

/// One non-cloneable startup handoff. Only the initial background task receives its finite
/// bootstrap capability; launches, maintenance and owned restarts never retain it.
pub(super) struct Startup {
    pub(super) launch: Option<Arc<GeneratedLaunch>>,
    pub(super) authorization: Option<GeneratedBootstrapAuthorization>,
}

/// Local original selection and explicit authorization for this newly started worker only.
pub(super) fn prepare(
    prepared: &PreparedLocalnet,
    budget: &Budget,
) -> std::result::Result<Startup, Failure> {
    budget.progress.enter(Phase::Selection);
    budget.check()?;
    if prepared.service_profile != LocalnetServiceProfile::StreamTokenAuthorities {
        return Ok(Startup {
            launch: None,
            authorization: None,
        });
    }
    budget.call(|deadline| {
        let mut parent = ManagedServiceBootstrap::open(prepared)?;
        let authorization =
            parent.authorize_generated_startup(deadline, Arc::clone(&budget.cancelled))?;
        drop(parent);
        let owner = Arc::new(GeneratedServiceRuntime::open(prepared)?);
        let revision = owner.prepare_catalog(deadline)?;
        if revision.stage() != GeneratedRuntimeStage::Catalog
            || !revision.required_transactions().is_empty()
        {
            return Err(invalid(
                "initial generated launch is not the catalog posture",
            ));
        }
        let launch = GeneratedLaunch::new(owner, revision, prepared)?;
        Ok(Startup {
            launch: Some(launch),
            authorization,
        })
    })
}

pub(super) fn initial(
    prepared: &PreparedLocalnet,
    budget: &Budget,
    generated: Option<(Arc<GeneratedServiceRuntime>, [OwnedGateway; 3])>,
    authorization: Option<GeneratedBootstrapAuthorization>,
) -> std::result::Result<Outcome, Failure> {
    budget.progress.enter(Phase::InitialReadiness);
    budget.check()?;
    let receipt = Arc::new(readiness::prove(
        prepared,
        budget.started,
        budget
            .deadline()?
            .checked_duration_since(budget.started)
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| budget.progress.deadline())?,
        &budget.cancelled,
        &budget.progress.readiness,
    )?);
    budget.check()?;
    let Some((owner, mut live)) = generated else {
        return Ok(Outcome::Complete(None));
    };
    budget.progress.enter(Phase::Bootstrap);
    let bootstrap = loop {
        validate_gateways(prepared, &mut live, budget)?;
        let result = {
            let mut parent = budget.call(|_| owner.open_original_bootstrap(prepared))?;
            match &authorization {
                Some(authorization) => parent.advance(authorization, budget.deadline()?),
                None => parent.recover(budget.deadline()?),
            }
        };
        budget.check()?;
        validate_gateways(prepared, &mut live, budget)?;
        match result {
            Ok(ServiceBootstrapProgress::Complete(history)) => {
                break budget.call(|_| history.ordered_carriers())?;
            }
            Err(crate::managed::Error::Bootstrap(reason)) => {
                return Err(Failure::Bootstrap(reason));
            }
            _ => {}
        }
        budget.wait()?;
    };
    // Catalog is a real owned launch without active token custody. Reconcile original paid
    // renewal history before strict current-use rendering, including an expired native head.
    let terminal = bootstrap
        .last()
        .copied()
        .ok_or_else(|| budget.progress.unconfirmed())?;
    budget.progress.enter(Phase::CustodyMaterial);
    loop {
        validate_gateways(prepared, &mut live, budget)?;
        let material = owner.retain_current_custody_material(budget.deadline()?);
        budget.check()?;
        validate_gateways(prepared, &mut live, budget)?;
        match material {
            Ok(()) => break,
            Err(crate::managed::Error::Bootstrap(reason)) => {
                return Err(Failure::Bootstrap(reason));
            }
            Err(_) => budget.wait()?,
        }
    }
    budget.progress.enter(Phase::CustodyRenewal);
    for gateway in &mut live {
        renewal::reconcile(prepared, budget, gateway, terminal, None)?;
    }
    budget.progress.enter(Phase::StreamTokenRevision);
    let revision = budget.call(|deadline| owner.prepare_current_stream_tokens(deadline))?;
    budget.call(|_| {
        require_carriers(&revision)?;
        require_original_transactions(&bootstrap, revision.required_transactions())
    })?;
    let required = revision.required_transactions().to_vec();
    confirm_carriers(prepared, &required, budget)?;
    budget.progress.enter(Phase::Catalog);
    let parallel = budget.call(|_| owner.fresh_catalog_round())?;
    let catalogs = catalog::promote(prepared, &mut live, budget, parallel)?;
    validate_gateways(prepared, &mut live, budget)?;
    Ok(Outcome::Restart(Restart {
        receipt,
        owner,
        revision,
        required,
        catalogs,
        retained: None,
    }))
}

struct RetainedContinuations {
    renewed: ProviderId,
    originals: [renewal::Continuation; 3],
}
impl Restart {
    pub(super) fn renewed(
        receipt: Arc<readiness::Receipt>,
        owner: Arc<GeneratedServiceRuntime>,
        revision: GeneratedServiceRuntimeRevision,
        catalogs: [PromotedGeneratedCatalog; 3],
        originals: [renewal::Continuation; 3],
        renewed: ProviderId,
    ) -> Result<Self> {
        require_carriers(&revision)?;
        if originals
            .iter()
            .filter(|value| value.provider() == renewed)
            .count()
            != 1
        {
            return Err(invalid("renewal changed its original provider selection"));
        }
        for original in &originals {
            if original.provider() != renewed {
                let enrollment = revision
                    .selected_enrollment(original.provider())?
                    .ok_or_else(|| invalid("unchanged provider enrollment absent"))?;
                original.revalidate(original.provider(), enrollment, &receipt)?;
            }
        }
        let required = revision.required_transactions().to_vec();
        Ok(Self {
            receipt,
            owner,
            revision,
            required,
            catalogs,
            retained: Some(RetainedContinuations { renewed, originals }),
        })
    }
    pub(super) fn into_launch(
        self,
        prepared: &PreparedLocalnet,
        budget: &Budget,
    ) -> std::result::Result<(Arc<GeneratedLaunch>, Recheck), Failure> {
        budget.progress.enter(Phase::Restart);
        budget.call(|_| require_carriers(&self.revision))?;
        let launch = budget.call(|_| GeneratedLaunch::new(self.owner, self.revision, prepared))?;
        Ok((
            launch,
            Recheck {
                receipt: self.receipt,
                required: self.required,
                catalogs: self.catalogs,
                retained: self.retained,
            },
        ))
    }
}

pub(super) struct Recheck {
    receipt: Arc<readiness::Receipt>,
    required: Vec<ManagedTransactionFinality>,
    catalogs: [PromotedGeneratedCatalog; 3],
    retained: Option<RetainedContinuations>,
}
impl Recheck {
    pub(super) fn finish(
        self,
        prepared: &PreparedLocalnet,
        mut live: [OwnedGateway; 3],
        budget: &Budget,
    ) -> std::result::Result<Outcome, Failure> {
        budget.progress.enter(Phase::Receipt);
        validate_gateways(prepared, &mut live, budget)?;
        readiness::reprove(
            prepared,
            &self.receipt,
            budget.started,
            budget
                .deadline()?
                .checked_duration_since(budget.started)
                .filter(|remaining| !remaining.is_zero())
                .ok_or_else(|| budget.progress.deadline())?,
            &budget.cancelled,
            &budget.progress.readiness,
        )?;
        budget.check()?;
        confirm_carriers(prepared, &self.required, budget)?;
        let mut observations = Vec::with_capacity(3);
        for (index, gateway) in live.iter_mut().enumerate() {
            let provider = gateway.provider();
            let floor = budget.call(|_| {
                if gateway.required_transactions()? != self.required.as_slice() {
                    return Err(invalid(
                        "restarted launch changed exact required transactions",
                    ));
                }
                gateway.observation_floor()
            })?;
            budget.progress.enter(Phase::PromotedCatalog);
            budget.call(|deadline| {
                ManagedGatewayCompliance::open(prepared, provider)?.observe_promoted(
                    gateway,
                    self.catalogs[index],
                    deadline,
                )
            })?;
            budget.progress.enter(Phase::ProviderAdvertisement);
            validate_live(prepared, gateway, budget)?;
            budget.call(|deadline| {
                ManagedProviderAdvertisement::open(prepared, provider)?.publish(deadline)
            })?;
            validate_live(prepared, gateway, budget)?;
            budget.progress.enter(Phase::Discovery);
            let observed_at = Instant::now();
            let observed_utc = budget.call(|_| now_ms())?;
            let current = budget.call(|deadline| {
                build_registry::observe_generated_service(
                    prepared,
                    provider,
                    gateway.selected_enrollment(floor)?,
                    floor,
                    deadline,
                )
            })?;
            let continuation = budget.call(|_| {
                let enrollment = gateway.selected_enrollment(floor)?;
                match &self.retained {
                    Some(retained) if provider != retained.renewed => {
                        let original = &retained.originals[index];
                        original.revalidate(provider, enrollment, &self.receipt)?;
                        Ok(original.clone())
                    }
                    _ => {
                        let plan = gateway
                            .original_provider_plan(prepared)?
                            .ok_or_else(|| invalid("renewal requires original provider plan"))?;
                        renewal::Continuation::new(
                            &plan,
                            Arc::clone(&self.receipt),
                            enrollment,
                            observed_at,
                            observed_utc,
                        )
                    }
                }
            })?;
            observations.push(budget.call(|_| {
                maintenance::ProviderObservation::new(
                    continuation,
                    floor,
                    self.catalogs[index],
                    current,
                    observed_at,
                    observed_utc,
                )
            })?);
            validate_live(prepared, gateway, budget)?;
        }
        let observations = observations
            .try_into()
            .map_err(|_| budget.progress.unconfirmed())?;
        let observation = budget.call(|_| {
            let plans = live[0]
                .original_provider_plans(prepared)?
                .ok_or_else(|| invalid("original provider plans absent"))?;
            maintenance::Observation::new(&plans, observations)
        })?;
        validate_gateways(prepared, &mut live, budget)?;
        budget.check()?;
        Ok(Outcome::Complete(Some(observation)))
    }
}

pub(super) fn validate_gateways(
    prepared: &PreparedLocalnet,
    live: &mut [OwnedGateway; 3],
    budget: &Budget,
) -> std::result::Result<(), Failure> {
    if !norito::core::decode_limits_active() {
        return OwnedGateway::validate_shared_round(prepared, live, budget);
    }
    let plans = budget.call(|_| {
        live[0]
            .original_provider_plans(prepared)?
            .ok_or_else(|| invalid("original provider plans absent"))
    })?;
    for (plan, gateway) in plans.iter().zip(live) {
        if plan.provider_id() != gateway.provider() {
            return Err(budget.progress.unconfirmed());
        }
        validate_live(prepared, gateway, budget)?;
    }
    budget.check()?;
    Ok(())
}

/// Finite observation timer, not provider authority or a promise of continuing availability.
/// Maintenance may replace it only after repeating the exact current native checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ReadinessExpiry {
    valid_until_unix_ms: u64,
    monotonic_end: Instant,
}
impl ReadinessExpiry {
    pub(super) fn select(
        valid_until_unix_ms: u64,
        observed_at: Instant,
        observed_utc: u64,
    ) -> Result<Self> {
        // Millisecond UTC readings are floored. Reserve one millisecond when mapping them
        // to the monotonic clock so the timer cannot run past the exclusive signed boundary.
        let remaining = valid_until_unix_ms
            .checked_sub(observed_utc)
            .and_then(|duration| duration.checked_sub(1))
            .filter(|duration| *duration > 0)
            .ok_or_else(|| invalid("service observation expired"))?;
        let monotonic_end = observed_at
            .checked_add(Duration::from_millis(remaining))
            .ok_or_else(|| invalid("service observation interval overflows"))?;
        let selected = Self {
            valid_until_unix_ms,
            monotonic_end,
        };
        if !selected.current()? {
            return Err(invalid("service observation expired"));
        }
        Ok(selected)
    }
    pub(super) fn current(&self) -> Result<bool> {
        Ok(self.current_at(Instant::now(), now_ms()?))
    }
    pub(super) fn utc_ceiling(&self) -> u64 {
        self.valid_until_unix_ms
    }

    pub(super) fn deadline(&self, maximum: Duration) -> Result<Instant> {
        let now = Instant::now();
        let utc = now_ms()?;
        let remaining = self
            .valid_until_unix_ms
            .checked_sub(utc)
            .and_then(|value| value.checked_sub(1))
            .filter(|value| *value > 0)
            .map(Duration::from_millis)
            .ok_or_else(|| invalid("service observation expired"))?
            .min(
                self.monotonic_end
                    .checked_duration_since(now)
                    .filter(|value| !value.is_zero())
                    .ok_or_else(|| invalid("service observation expired"))?,
            )
            .min(maximum);
        now.checked_add(remaining)
            .ok_or_else(|| invalid("service observation deadline overflow"))
    }

    pub(super) fn current_at(&self, monotonic: Instant, utc: u64) -> bool {
        monotonic < self.monotonic_end && utc < self.valid_until_unix_ms
    }
}

pub(super) fn validate_live(
    prepared: &PreparedLocalnet,
    live: &mut OwnedGateway,
    budget: &Budget,
) -> std::result::Result<(), Failure> {
    budget.call(|_| {
        let plan = live
            .original_gateway_compliance_plan(prepared)?
            .ok_or_else(|| invalid("generated gateway plan absent"))?;
        live.validate(prepared, &plan)
    })
}

pub(super) fn require_carriers(revision: &GeneratedServiceRuntimeRevision) -> Result<()> {
    let required = revision.required_transactions();
    if revision.stage() != GeneratedRuntimeStage::StreamTokens
        || required.is_empty()
        || required.len() > 32
    {
        return Err(invalid(
            "generated restart is not the aggregate token posture",
        ));
    }
    for provider in revision.provider_ids() {
        let enrollment = revision
            .selected_enrollment(provider)?
            .ok_or_else(|| invalid("generated runtime omitted provider enrollment"))?;
        if !required.contains(enrollment.finalized()) {
            return Err(invalid("generated runtime omitted provider transaction"));
        }
    }
    Ok(())
}

/// Exact membership retains transaction identity even when several originals share a carrier.
/// The renderer and native child owners, not this structural check, authenticate every record.
fn require_original_transactions(
    originals: &[ManagedTransactionFinality],
    required: &[ManagedTransactionFinality],
) -> Result<()> {
    if originals.is_empty()
        || originals.len() > 32
        || required.is_empty()
        || required.len() > 32
        || originals
            .iter()
            .any(|original| original.height < 2 || !required.contains(original))
    {
        return Err(invalid(
            "runtime omitted or changed an original bootstrap transaction",
        ));
    }
    Ok(())
}
pub(super) fn confirm_carriers(
    prepared: &PreparedLocalnet,
    required: &[ManagedTransactionFinality],
    budget: &Budget,
) -> std::result::Result<(), Failure> {
    if required.is_empty() || required.len() > 32 {
        return Err(budget.progress.unconfirmed());
    }
    budget.call(|_| {
        if prepared.peers.len() != 4 {
            return Err(invalid("original generated committee differs"));
        }
        Ok(())
    })?;
    confirm_carriers_with(prepared, required, budget, |builder| builder)?;
    budget.check()?;
    Ok(())
}

// Bind each peer once and retain all four blocking runtimes until the entire barrier returns:
// a shared pool connection may have been initialized on any earlier peer's runtime. Deadline
// views share those owners; no context or observation is reused across separate barriers.
fn confirm_carriers_with(
    prepared: &PreparedLocalnet,
    required: &[ManagedTransactionFinality],
    budget: &Budget,
    configure: impl Fn(iroha::client::ClientBuilder) -> iroha::client::ClientBuilder,
) -> std::result::Result<(), Failure> {
    let (original_file, snapshot, original_bytes) = budget.call(|_| {
        let original_file = iroha_fs::RetainedFile::open_private(&prepared.context.client_config)?;
        let snapshot = original_file.snapshot()?;
        let bytes = iroha_fs::read_private(
            &prepared.context.client_config,
            crate::managed::MAX_METADATA,
        )?;
        Ok((original_file, snapshot, bytes))
    })?;
    let mut original = None;
    let mut clients: Vec<iroha::blocking::Client> = Vec::with_capacity(4);
    for terminal in required {
        // Preserve the prior per-receipt private-file and retained identity admission. Context
        // reuse also requires the exact original bytes and object, so replacement or edited
        // settings cannot silently continue through an already-bound transport.
        let config = budget.call(|_| {
            let config = prepared.context.load_client_config()?;
            let current = iroha_fs::read_private(
                &prepared.context.client_config,
                crate::managed::MAX_METADATA,
            )?;
            if current.as_slice() != original_bytes.as_slice()
                || original_file.snapshot()? != snapshot
            {
                return Err(invalid("original carrier client configuration changed"));
            }
            Ok(config)
        })?;
        let original =
            original.get_or_insert_with(|| configure(iroha::client::Client::builder(config)));
        // Keep the caller's original sequential decode/admission recipe under active limits.
        // Otherwise the four exact local reads for this one carrier are independent. The next
        // carrier's private-file admission cannot begin until all four workers have closed.
        let parallel = !norito::core::decode_limits_active();
        for (index, (peer, phase)) in prepared.peers.iter().zip(CARRIER_PHASES).enumerate() {
            budget.progress.enter(phase);
            let remaining = budget.check()?;
            budget.call(|deadline| {
                if clients.len() == index {
                    let mut selected = clients
                        .first()
                        .map_or_else(|| original.clone(), |client| client.client().to_builder());
                    selected.torii_url = peer
                        .torii_url
                        .parse()
                        .map_err(|_| invalid("invalid original peer endpoint"))?;
                    let client = selected
                        .build()
                        .map_err(|_| invalid("cannot construct original carrier client"))?
                        .with_request_deadline(deadline);
                    clients.push(
                        iroha::blocking::Client::from_client(client)
                            .map_err(|_| invalid("cannot construct original carrier client"))?,
                    );
                }
                if !parallel {
                    read_carrier_peer(&clients[index], terminal, remaining, deadline)?;
                }
                Ok(())
            })?;
        }
        if parallel {
            budget.progress.enter(Phase::CarrierPeers);
            let result = join_carrier_peer_reads(|index| {
                confirm_carrier_peer(&clients[index], terminal, budget, CARRIER_PHASES[index])
            });
            // A cancellation or late ordinary response must not succeed just because one peer
            // returned earlier. All original transport runtimes remain alive through this join.
            budget.check()?;
            result?;
        }
    }
    Ok(())
}

const CARRIER_PHASES: [Phase; 4] = [
    Phase::Carrier0,
    Phase::Carrier1,
    Phase::Carrier2,
    Phase::Carrier3,
];

fn confirm_carrier_peer(
    client: &iroha::blocking::Client,
    terminal: &ManagedTransactionFinality,
    budget: &Budget,
    phase: Phase,
) -> std::result::Result<(), Failure> {
    let result = (|| {
        let remaining = budget.check()?;
        budget.call(|deadline| read_carrier_peer(client, terminal, remaining, deadline))
    })();
    result.map_err(|failure| match failure {
        Failure::Activation { cause, .. } => Failure::Activation { phase, cause },
        other => other,
    })
}

fn read_carrier_peer(
    client: &iroha::blocking::Client,
    terminal: &ManagedTransactionFinality,
    remaining: Duration,
    deadline: Instant,
) -> Result<()> {
    let client = client
        .with_request_deadline(deadline)
        .map_err(|_| invalid("cannot bound original carrier client"))?;
    let applied = client
        .wait_for_transaction_applied_local(
            terminal.transaction_hash,
            iroha::client::TransactionWaitOptions {
                timeout: remaining,
                poll_interval: POLL,
            },
        )
        .map_err(|_| invalid("original bootstrap transaction is not locally Applied"))?;
    // SDK verifies exact hash, local scope and state-resolved Applied. Its optional
    // carrier hint must also agree with the independently authenticated original.
    if applied.block_height != Some(terminal.height) {
        return Err(invalid(
            "local bootstrap carrier height differs from original",
        ));
    }
    Ok(())
}

// Scheduling only: all four exact owners are borrowed and the first error is selected in
// validator order after every started worker has exited. Nothing here creates finality.
fn join_carrier_peer_reads(
    read: impl Fn(usize) -> std::result::Result<(), Failure> + Sync,
) -> std::result::Result<(), Failure> {
    thread::scope(|scope| {
        let read = &read;
        let handles = std::array::from_fn::<_, 4, _>(|index| {
            thread::Builder::new().spawn_scoped(scope, move || read(index))
        });
        let results = handles
            .into_iter()
            .enumerate()
            .map(|(index, handle)| {
                let failed = || Failure::Activation {
                    phase: CARRIER_PHASES[index],
                    cause: super::progress::Cause::Unconfirmed,
                };
                match handle {
                    Ok(handle) => handle.join().unwrap_or_else(|_| Err(failed())),
                    Err(_) => Err(failed()),
                }
            })
            .collect::<Vec<_>>();
        // Collecting consumes every handle even after an ordinary error, panic or spawn error.
        for result in results {
            result?;
        }
        Ok(())
    })
}

#[cfg(test)]
#[path = "activation/peer_round_tests.rs"]
mod peer_round_tests;

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "activation/transport_tests.rs"]
mod transport_tests;
