//! In-node SCCP keeper (`specs/sccp.md` §4.13.4).
//!
//! The keeper is a supervised task of its own. It signs with a node-local Ed25519 keeper key
//! that it generates on first start into the owner-only key directory ([`key_store`]). The key
//! is neither registered nor funded: every transaction the keeper submits is fee-exempt on
//! success, and an exempt keeper advance is admitted from any authority (§4.19). An unusable
//! key directory leaves the keeper inert (`sccp_keeper_unconfigured`); the node never aborts
//! because of SCCP.
//!
//! # Duties
//!
//! **Light-client advances** (`[sccp.light_client_keeper]`). The keeper keeps Taira's inbound
//! light clients fresh: when a light client's head is older than `advance_after` (default
//! `ws_bound_ms / 4`), it builds an advance from the configured (or compiled public) endpoints
//! and submits it fee-exempt from the keeper key's account. Each advance is stepped to the
//! light client's `max_updates_per_advance` and the keeper's `max_advance_bytes` (the builders
//! keep the longest prefix of updates that fits), so a light client far behind catches up over
//! several polls instead of being dropped; an advance that still does not fit is dropped with
//! a warning instead of being submitted. Several keepers are harmless: the advance carries the
//! expected state hash, so only the first one moves the head and the rest fail admission
//! instead of paying. Ethereum and BSC advances use HTTP endpoints, TON advances ADNL
//! liteservers.
//!
//! TODO: WP-S3: the keepalive duty (`[sccp.keeper].keepalive`, `keepalive_stagger_ms`, §4.7.4)
//! on its own schedule, which does no network I/O.
//!
//! TODO: WP-S6: the watch duty (`[sccp.keeper].watch`) over the registered destinations, and
//! the L5 feed that also advances a light client whose finalized source time lags the deadline
//! of a retained, ended generation.
//!
//! # Task structure of the light-client duty
//!
//! Each network is a [`Lane`] with its own schedule, so a slow, firewalled or hostile endpoint
//! of one chain delays neither block production nor the other chains. The lanes run
//! concurrently and a poll of one lane is:
//!
//! 1. **Read** ([`KeeperHost::local`], on a blocking worker): take one committed state view,
//!    copy out the light client and whether it aged out of its weak-subjectivity window at the
//!    latest committed block time, and drop the view.
//! 2. **Decide** ([`decide`]): idle (SCCP absent or no light client), needs Parliament
//!    recovery (frozen or aged: no RPC is spent on it until it is re-initialized), fresh, or
//!    stale.
//! 3. **Build** (stale only, on a blocking worker that holds no state view): build the advance
//!    under the lane's [`PollBudget`] of `poll_budget`. A build still running after 5/4 ×
//!    `poll_budget` counts as a failed poll; the lane starts no other poll until it returns. A
//!    build that fails on the data it was served (malformed, inconsistent or incomplete) moves
//!    the lane's clients to their next endpoints ([`AdvanceSource::rotate_endpoints`]).
//! 4. **Submit** ([`KeeperHost::submit`]): quote, sign with the keeper key and enqueue the
//!    advance, fee-exempt on success (§4.19).
//!
//! A lane polls again `poll_interval` later plus up to a quarter of jitter; each consecutive
//! failed poll doubles that wait, up to 64 × `poll_interval` ([`Cadence`]).
//!
//! TODO(ws34): export the health states as telemetry gauges; they are logged today.

#[path = "sccp_keeper/key_store.rs"]
mod key_store;

use std::{
    sync::Arc,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use eyre::WrapErr as _;
use iroha_config::parameters::actual::{SccpKeeper, SccpLightClientKeeper};
use iroha_core::{
    executor::quote_nexus_fee_admission_draft,
    queue::Queue,
    smartcontracts::isi::sccp::{light_clients::WorldLightClientView, store},
    state::{State, StateReadOnly, WorldReadOnly},
    tx::AcceptedTransaction,
};
use iroha_crypto::KeyPair;
use iroha_data_model::{
    account::AccountId,
    bridge::SccpNetworkV1,
    isi::{InstructionBox, sccp::AdvanceSccpLightClientV1},
    sccp::light_client::{SccpLcAdvanceBytesV1, SccpLightClientV1},
    transaction::{FeePaymentIntent, TransactionBuilder},
};
use iroha_futures::supervisor::{Child, OnShutdown, ShutdownSignal};
use iroha_model_base::peer::PeerId;
use iroha_sccp_rpc::{
    BeaconClient, EvmClient, HttpEndpointKind, HttpTransport, PollBudget,
    builders::{
        AdvanceBudgetV1, BuildError, SourceChainBuilder, bsc::BscBuilder,
        ethereum::EthereumBuilder, ton::TonBuilder,
    },
    endpoints::endpoint_seed,
    ton::LiteClient,
};
use tokio::task::{JoinHandle, JoinSet};

use self::key_store::KeyStore;
use crate::panic_recovery::{join_recoverable, recover_joined, spawn_blocking_recoverable};

/// How often the keeper looks for a new TON key block: TON light clients have no
/// `ws_bound_ms` (their freshness comes from the epoch's own validity).
const TON_ADVANCE_AFTER_MS: u64 = 3_600_000;
/// Consecutive failed polls after which a lane's wait stops doubling: at most
/// `2^6 = 64 × poll_interval`.
const MAX_BACKOFF_DOUBLINGS: u32 = 6;
/// The networks the keeper advances, one lane each, in this order.
const NETWORKS: [SccpNetworkV1; 3] = [
    SccpNetworkV1::EthereumMainnet,
    SccpNetworkV1::BscMainnet,
    SccpNetworkV1::TonMainnet,
];
/// Shutdown wait of the keeper task: it holds no work that must finish.
const SHUTDOWN_WAIT: Duration = Duration::from_secs(1);

/// Start the keeper of the node `peer` as its own supervised task.
///
/// The keeper key is loaded from `config`'s key directory, or generated into it on first
/// start, before the task is spawned. Returns no task when the keeper is disabled, when its
/// key directory is unusable, or when no duty is enabled.
pub fn start(
    state: Arc<State>,
    queue: Arc<Queue>,
    peer: &PeerId,
    config: &SccpKeeper,
    light_client_config: SccpLightClientKeeper,
    shutdown_signal: ShutdownSignal,
) -> Option<Child> {
    if !config.enabled {
        iroha_logger::info!("SCCP keeper disabled by configuration");
        return None;
    }
    let dir = config.key_dir_path();
    let key = match KeyStore::open(&dir).and_then(|store| store.load_or_generate()) {
        Ok(key) => key,
        Err(error) => {
            iroha_logger::error!(
                %error,
                health = "sccp_keeper_unconfigured",
                "SCCP keeper is inert: the keeper-key directory is unusable"
            );
            return None;
        }
    };
    iroha_logger::info!(
        keeper = %key.public_key(),
        key_dir = %dir.display(),
        "SCCP keeper key loaded"
    );
    // TODO: WP-S3: start the keepalive duty here when `config.keepalive`, staggered by
    // `config.keepalive_stagger` per canonical committee index (§4.7.4).
    // TODO: WP-S6: start the watch duty here when `config.watch`.
    // Seeds the starting endpoints and jitter per node, so validators sharing the compiled
    // endpoint lists spread over them.
    let seed = endpoint_seed(peer.to_string().as_bytes());
    start_advances(
        Arc::new(NodeHost { state, queue, key }),
        light_client_config,
        seed,
        shutdown_signal,
    )
}

/// Start the light-client advance duty as a supervised task, or return `None` when it is
/// disabled.
///
/// The task never exits before shutdown, also when no network has usable endpoints, because
/// the supervisor stops the node when a child exits early and the node never stops over SCCP.
fn start_advances<H: KeeperHost>(
    host: Arc<H>,
    config: SccpLightClientKeeper,
    seed: u64,
    shutdown_signal: ShutdownSignal,
) -> Option<Child> {
    if !config.enabled {
        iroha_logger::info!("SCCP light-client keeper disabled by configuration");
        return None;
    }
    let config = Arc::new(config);
    let task = tokio::task::spawn(async move {
        let lanes = build(Arc::clone(&config), seed).await;
        run(lanes, host, config, shutdown_signal).await;
    });
    Some(Child::new(task, OnShutdown::Wait(SHUTDOWN_WAIT)))
}

fn wall_clock_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Run `lanes` concurrently until `shutdown`, then stop them.
///
/// Returns only on shutdown. A lane that stops early (a bug) is logged and the other lanes go
/// on.
async fn run<H: KeeperHost>(
    lanes: Vec<Lane>,
    host: Arc<H>,
    config: Arc<SccpLightClientKeeper>,
    shutdown: ShutdownSignal,
) {
    let mut running = JoinSet::new();
    for lane in lanes {
        running.spawn(run_lane(
            lane,
            Arc::clone(&host),
            Arc::clone(&config),
            shutdown.clone(),
        ));
    }
    loop {
        tokio::select! {
            () = shutdown.receive() => break,
            Some(joined) = running.join_next() => {
                if joined.is_err() {
                    iroha_logger::error!("SCCP keeper: a network lane stopped unexpectedly");
                }
            }
        }
    }
    running.shutdown().await;
}

/// Poll one lane on its own schedule until `shutdown`.
async fn run_lane<H: KeeperHost>(
    mut lane: Lane,
    host: Arc<H>,
    config: Arc<SccpLightClientKeeper>,
    shutdown: ShutdownSignal,
) {
    let mut wait = lane.cadence.first();
    loop {
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            () = shutdown.receive() => return,
        }
        let succeeded = tokio::select! {
            succeeded = lane.poll(&host, &config) => succeeded,
            () = shutdown.receive() => return,
        };
        wait = if succeeded {
            lane.cadence.after_success()
        } else {
            lane.cadence.after_failure()
        };
    }
}

/// One network's advance builder: an `iroha_sccp_rpc` builder in the node, a fake in tests.
///
/// Builds block on network I/O, so the keeper calls them only on blocking workers and never
/// while it holds a state view.
trait AdvanceSource: Send + Sync + 'static {
    /// Build an advance of a light client whose newest stored set is `latest_set_id`, stepped
    /// to `budget` (the longest prefix of at most `budget.max_items` items whose frame fits
    /// `budget.max_bytes`).
    ///
    /// # Errors
    ///
    /// Any endpoint failure, an inconsistent answer, or nothing to advance yet.
    fn advance(
        &self,
        latest_set_id: u64,
        budget: AdvanceBudgetV1,
    ) -> Result<SccpLcAdvanceBytesV1, BuildError>;

    /// Move every client of the source to its next endpoint, so the next build starts
    /// elsewhere. Does no I/O.
    fn rotate_endpoints(&self);
}

impl AdvanceSource for EthereumBuilder {
    fn advance(
        &self,
        latest_set_id: u64,
        budget: AdvanceBudgetV1,
    ) -> Result<SccpLcAdvanceBytesV1, BuildError> {
        SourceChainBuilder::advance(self, latest_set_id, budget)
    }

    fn rotate_endpoints(&self) {
        EthereumBuilder::rotate_endpoints(self);
    }
}

impl AdvanceSource for BscBuilder {
    fn advance(
        &self,
        latest_set_id: u64,
        budget: AdvanceBudgetV1,
    ) -> Result<SccpLcAdvanceBytesV1, BuildError> {
        SourceChainBuilder::advance(self, latest_set_id, budget)
    }

    fn rotate_endpoints(&self) {
        BscBuilder::rotate_endpoints(self);
    }
}

impl AdvanceSource for TonBuilder {
    fn advance(
        &self,
        latest_set_id: u64,
        budget: AdvanceBudgetV1,
    ) -> Result<SccpLcAdvanceBytesV1, BuildError> {
        SourceChainBuilder::advance(self, latest_set_id, budget)
    }

    fn rotate_endpoints(&self) {
        TonBuilder::rotate_endpoints(self);
    }
}

/// Whether a failed build blames the data its endpoints served (malformed, inconsistent or
/// missing what the advance needs), so the lane moves to other endpoints for the next poll.
/// RPC failures are not: the transports already failed over, or moved past an endpoint whose
/// answer discredited it.
fn blames_served_data(error: &BuildError) -> bool {
    !matches!(error, BuildError::Rpc(_))
}

/// What one poll of a lane needs from local state, copied out of one short-lived committed
/// view.
#[derive(Default)]
struct Local {
    /// The installed light client of the lane's network.
    light_client: Option<SccpLightClientV1>,
    /// Whether that light client's newest signing set is beyond its weak-subjectivity bound at
    /// the latest committed block time, the time admission checks advances against.
    aged: bool,
}

/// The node services a lane uses. Both calls block and run on blocking workers only.
trait KeeperHost: Send + Sync + 'static {
    /// Read what a poll of `network` needs. An implementation holds a state view only inside
    /// this call, never across the network I/O that follows.
    fn local(&self, network: SccpNetworkV1) -> Local;

    /// Quote, sign with the keeper key as its account and enqueue `advance`, fee-exempt on
    /// success (§4.19).
    ///
    /// # Errors
    ///
    /// When building, quoting, signing, admission or enqueueing fails.
    fn submit(&self, advance: AdvanceSccpLightClientV1) -> eyre::Result<()>;
}

/// The node's [`KeeperHost`]: committed state, the local queue and the keeper key.
struct NodeHost {
    /// Committed state.
    state: Arc<State>,
    /// Local transaction queue.
    queue: Arc<Queue>,
    /// The node's Ed25519 keeper key; its account is neither registered nor funded.
    key: KeyPair,
}

impl KeeperHost for NodeHost {
    fn local(&self, network: SccpNetworkV1) -> Local {
        let view = self.state.view();
        let world = view.world();
        if view.height() == 0 || store::parameters::get(world).is_none() {
            return Local::default();
        }
        let light_client = store::light_clients::get(world, &network).copied();
        // TODO: WP-S6: the L5 feed also reads here whether the light client's finalized source
        // time lags the deadline of a retained, ended generation (§4.8).
        let aged = light_client.is_some()
            && iroha_sccp::light_client::is_aged(
                &WorldLightClientView(world),
                network,
                view.query_ledger_time_ms(),
            ) == Ok(true);
        Local { light_client, aged }
    }

    fn submit(&self, advance: AdvanceSccpLightClientV1) -> eyre::Result<()> {
        submit_transaction(
            &self.state,
            &self.queue,
            &self.key,
            InstructionBox::from(advance),
        )
    }
}

/// Quote, sign with the keeper `key` as its own account and enqueue one transaction carrying
/// `instruction`.
///
/// The keeper key's account is neither registered nor funded, so the transaction is submitted
/// only when it is quoted fee-exempt (§4.19).
fn submit_transaction(
    state: &State,
    queue: &Queue,
    key: &KeyPair,
    instruction: InstructionBox,
) -> eyre::Result<()> {
    let authority = AccountId::new(key.public_key().clone());
    let mut payload = TransactionBuilder::new(
        *state.network_id_ref(),
        authority,
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([instruction])
    .into_payload()
    .wrap_err("build SCCP transaction")?;
    let route = queue
        .route_payload_plan_with_state(&payload, state)
        .wrap_err("route SCCP transaction")?;
    let iroha_core::queue::RoutingPlan::Single(route) = route else {
        eyre::bail!("SCCP submission requires one resolved route");
    };
    let quote_view = state.query_view();
    let sccp_committed_time_ms =
        iroha_core::smartcontracts::isi::sccp::hold::committed_time_ms(&quote_view)
            .map_err(|error| eyre::eyre!("fee quote has invalid committed time: {error:?}"))?;
    let observation_time_ms = sccp_committed_time_ms.unwrap_or(0);
    let next_block_height = u64::try_from(quote_view.height())?
        .checked_add(1)
        .ok_or_else(|| eyre::eyre!("fee quote committed height overflow"))?;
    let quote = {
        quote_nexus_fee_admission_draft(
            quote_view.world(),
            quote_view.nexus(),
            quote_view.pipeline(),
            &quote_view.zk().gas,
            &payload,
            observation_time_ms,
            sccp_committed_time_ms,
            next_block_height,
            Some(route.route.dataspace_id),
        )
    }
    .map_err(|error| eyre::eyre!("quote SCCP transaction: {error:?}"))?;
    drop(quote_view);
    eyre::ensure!(
        quote.quote.charges.is_empty(),
        "the SCCP keeper submits only fee-exempt transactions"
    );
    payload.fee_payment = quote.recommended_intent;
    let transaction = TransactionBuilder::from_payload(payload)
        .wrap_err("rebuild quoted SCCP transaction")?
        .try_sign(key.private_key())
        .map_err(|error| eyre::eyre!("sign SCCP transaction: {error:?}"))?;
    let (max_clock_drift, transaction_params) = {
        let world = state.world_view();
        let params = world.parameters();
        (params.sumeragi().max_clock_drift(), params.transaction())
    };
    let crypto = state.crypto();
    let accepted = AcceptedTransaction::accept(
        transaction,
        state.network_id_ref(),
        max_clock_drift,
        transaction_params,
        crypto.as_ref(),
    )
    .wrap_err("accept SCCP transaction")?;
    queue
        .push_with_lane_with_state(accepted, state)
        .map(|_| ())
        .map_err(|failure| eyre::eyre!("enqueue SCCP transaction: {}", failure.err))
}

/// What a lane does with one reading of local state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// SCCP absent, or no installed light client: nothing to do.
    Idle,
    /// The light client cannot be advanced until a Parliament `InitializeLightClient`
    /// re-seeds it, so no RPC is spent on it.
    Recovery(Recovery),
    /// The head is newer than the staleness bound.
    Fresh,
    /// The head is stale: build and submit an advance.
    Advance,
}

/// Why a light client needs Parliament recovery (§4.13.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Recovery {
    /// The light client is frozen.
    Frozen,
    /// Its newest signing set is beyond the weak-subjectivity bound.
    Aged,
}

/// Decide one poll from `local` at wall-clock time `now_ms`.
fn decide(config: &SccpLightClientKeeper, local: &Local, now_ms: u64) -> Step {
    let Some(light_client) = &local.light_client else {
        return Step::Idle;
    };
    if light_client.is_frozen() {
        return Step::Recovery(Recovery::Frozen);
    }
    if local.aged {
        return Step::Recovery(Recovery::Aged);
    }
    if is_stale(config, light_client, now_ms) {
        Step::Advance
    } else {
        Step::Fresh
    }
}

/// One lane's schedule.
///
/// After a poll that needed no RPC or submitted an advance, the next poll comes
/// `poll_interval` later plus up to a quarter of that as jitter. Each consecutive failed poll
/// doubles the base wait, up to `2^MAX_BACKOFF_DOUBLINGS × poll_interval`. Jitter is a fixed
/// function of the seed and the number of draws, so tests are deterministic and lanes and
/// validators with different seeds drift apart.
#[derive(Debug, Clone)]
struct Cadence {
    interval: Duration,
    seed: u64,
    failures: u32,
    draws: u64,
}

impl Cadence {
    /// A schedule of `interval` with jitter seeded by `seed`.
    fn new(interval: Duration, seed: u64) -> Self {
        Self {
            interval,
            seed,
            failures: 0,
            draws: 0,
        }
    }

    /// Wait before the first poll: up to a quarter of the interval, so lanes and validators do
    /// not start in lockstep.
    fn first(&mut self) -> Duration {
        self.jitter(self.interval / 4)
    }

    /// Wait after a poll that needed no RPC or submitted an advance; resets the backoff.
    fn after_success(&mut self) -> Duration {
        self.failures = 0;
        self.next()
    }

    /// Wait after a failed or overrun poll; doubles the base wait up to the cap.
    fn after_failure(&mut self) -> Duration {
        self.failures = self.failures.saturating_add(1);
        self.next()
    }

    /// Consecutive failed polls.
    #[cfg(test)]
    fn failures(&self) -> u32 {
        self.failures
    }

    /// The base wait of the current failure count.
    fn base(&self) -> Duration {
        self.interval
            .saturating_mul(1_u32 << self.failures.min(MAX_BACKOFF_DOUBLINGS))
    }

    fn next(&mut self) -> Duration {
        let base = self.base();
        base.saturating_add(self.jitter(base / 4))
    }

    /// A draw in `[0, span]`.
    fn jitter(&mut self, span: Duration) -> Duration {
        self.draws = self.draws.wrapping_add(1);
        let span = u64::try_from(span.as_nanos()).unwrap_or(u64::MAX);
        if span == 0 {
            return Duration::ZERO;
        }
        let draw = splitmix64(self.seed ^ self.draws.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        Duration::from_nanos(draw % span.saturating_add(1))
    }
}

/// `SplitMix64` finalizer: a fixed, platform-independent mixing function.
fn splitmix64(seed: u64) -> u64 {
    let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// The jitter seed of `network`'s lane on a node with `seed`.
fn lane_seed(seed: u64, network: SccpNetworkV1) -> u64 {
    let mut bytes = seed.to_le_bytes().to_vec();
    bytes.extend_from_slice(network.profile_key().as_bytes());
    endpoint_seed(&bytes)
}

/// A build result as it comes back from its blocking worker.
type BuildJob = JoinHandle<thread::Result<Result<SccpLcAdvanceBytesV1, BuildError>>>;

/// One network: its advance source, poll budget and schedule.
struct Lane {
    network: SccpNetworkV1,
    source: Arc<dyn AdvanceSource>,
    /// Shared with the source's transports, which stop at its deadline.
    budget: PollBudget,
    cadence: Cadence,
    /// A build that overran its poll and still runs on its blocking worker.
    overrun: Option<BuildJob>,
    /// State hash of the light client last reported as needing recovery.
    reported_recovery: Option<[u8; 32]>,
}

impl Lane {
    /// A lane of `network` building with `source`, whose transports carry `budget`.
    fn new(
        network: SccpNetworkV1,
        source: Arc<dyn AdvanceSource>,
        budget: PollBudget,
        cadence: Cadence,
    ) -> Self {
        Self {
            network,
            source,
            budget,
            cadence,
            overrun: None,
            reported_recovery: None,
        }
    }

    /// The lane's network.
    #[cfg(test)]
    fn network(&self) -> SccpNetworkV1 {
        self.network
    }

    /// Poll once; returns whether the poll succeeded (needed no RPC or submitted an advance).
    async fn poll<H: KeeperHost>(
        &mut self,
        host: &Arc<H>,
        config: &Arc<SccpLightClientKeeper>,
    ) -> bool {
        let network = self.network;
        let profile = network.profile_key();
        if let Some(job) = &self.overrun {
            if !job.is_finished() {
                iroha_logger::warn!(
                    network = profile,
                    "SCCP keeper: the previous poll still runs past its budget; skipping this poll"
                );
                return false;
            }
            self.overrun = None;
        }
        let now_ms = wall_clock_ms();
        let read = {
            let host = Arc::clone(host);
            join_recoverable(spawn_blocking_recoverable(move || host.local(network))).await
        };
        let local = match read {
            Ok(local) => local,
            Err(_panic) => {
                iroha_logger::error!(
                    network = profile,
                    "SCCP keeper: reading local state panicked"
                );
                return false;
            }
        };
        match decide(config, &local, now_ms) {
            Step::Idle | Step::Fresh => {
                self.reported_recovery = None;
                return true;
            }
            Step::Recovery(reason) => {
                let state_hash = local
                    .light_client
                    .map(|light_client| light_client.state_hash);
                if self.reported_recovery != state_hash {
                    self.reported_recovery = state_hash;
                    iroha_logger::warn!(
                        network = profile,
                        ?reason,
                        health = "sccp_keeper_needs_recovery",
                        "SCCP keeper: the light client is frozen or aged out of its weak-subjectivity \
                         window and is not advanced until a Parliament InitializeLightClient re-seeds it"
                    );
                }
                return true;
            }
            Step::Advance => {}
        }
        let Some(light_client) = local.light_client else {
            return true;
        };
        let Some(advance) = self
            .build(
                &light_client,
                advance_budget(config, &light_client),
                config.poll_budget,
            )
            .await
        else {
            return false;
        };
        if !fits_advance_bound(config, network, &advance) {
            return false;
        }
        let instruction = AdvanceSccpLightClientV1 {
            network,
            expected_state_hash: Some(light_client.state_hash),
            advance,
        };
        let submitted = {
            let host = Arc::clone(host);
            join_recoverable(spawn_blocking_recoverable(move || host.submit(instruction))).await
        };
        match submitted {
            Ok(Ok(())) => true,
            Ok(Err(error)) => {
                iroha_logger::warn!(
                    ?error,
                    network = profile,
                    "SCCP keeper: submitting an advance failed"
                );
                false
            }
            Err(_panic) => {
                iroha_logger::error!(
                    network = profile,
                    "SCCP keeper: submitting an advance panicked"
                );
                false
            }
        }
    }

    /// Build an advance of `light_client`, stepped to `advance_budget`, on a blocking worker
    /// under the lane's poll budget.
    ///
    /// The worker owns only the source and plain values, never a state view. A build that has
    /// not returned after 5/4 × `poll_budget` is kept as the lane's overrun and counts as
    /// failed. A build that fails on the data it was served ([`blames_served_data`]) rotates
    /// the source's endpoints.
    async fn build(
        &mut self,
        light_client: &SccpLightClientV1,
        advance_budget: AdvanceBudgetV1,
        poll_budget: Duration,
    ) -> Option<SccpLcAdvanceBytesV1> {
        let profile = self.network.profile_key();
        let source = Arc::clone(&self.source);
        let budget = self.budget.clone();
        let latest = light_client.head.latest_set_id;
        let mut job: BuildJob = spawn_blocking_recoverable(move || {
            let _poll = budget.start(poll_budget);
            source.advance(latest, advance_budget)
        });
        let overdue = poll_budget.saturating_add(poll_budget / 4);
        let joined = match tokio::time::timeout(overdue, &mut job).await {
            Ok(joined) => joined,
            Err(_elapsed) => {
                iroha_logger::warn!(
                    network = profile,
                    ?poll_budget,
                    "SCCP keeper: building an advance overran its poll budget"
                );
                self.overrun = Some(job);
                return None;
            }
        };
        match recover_joined(joined) {
            Ok(Ok(advance)) => Some(advance),
            Ok(Err(error)) => {
                iroha_logger::warn!(
                    %error,
                    network = profile,
                    "SCCP keeper: building an advance failed"
                );
                if blames_served_data(&error) {
                    self.source.rotate_endpoints();
                }
                None
            }
            Err(_panic) => {
                iroha_logger::error!(
                    network = profile,
                    "SCCP keeper: building an advance panicked"
                );
                None
            }
        }
    }
}

/// Build the lanes on a blocking worker of the current Tokio runtime.
///
/// The HTTP transports own blocking `reqwest` clients. Building one starts the client's
/// internal runtime thread and blocks until it runs, which must never happen on an async
/// worker thread: debug builds panic there and release builds block the worker. A panic while
/// building leaves the keeper without lanes, because the node never aborts over SCCP.
async fn build(config: Arc<SccpLightClientKeeper>, seed: u64) -> Vec<Lane> {
    match join_recoverable(spawn_blocking_recoverable(move || {
        build_lanes(&config, seed)
    }))
    .await
    {
        Ok(lanes) => lanes,
        Err(_panic) => {
            iroha_logger::error!(
                "SCCP keeper: building the endpoint clients panicked; the keeper stays idle"
            );
            Vec::new()
        }
    }
}

/// One lane per network whose endpoints are usable. `seed` (derived from the peer id) seeds
/// the starting endpoints, the failover jitter and the lanes' schedules.
///
/// Blocks while the HTTP clients start, so async callers use [`build`].
fn build_lanes(config: &SccpLightClientKeeper, seed: u64) -> Vec<Lane> {
    let mut lanes = Vec::new();
    for network in NETWORKS {
        let budget = PollBudget::new();
        match build_source(config, network, seed, &budget) {
            Ok(source) => lanes.push(Lane::new(
                network,
                source,
                budget,
                Cadence::new(config.poll_interval, lane_seed(seed, network)),
            )),
            Err(error) => iroha_logger::warn!(
                %error,
                network = network.profile_key(),
                "SCCP keeper: the endpoints are unusable; this network is not kept"
            ),
        }
    }
    lanes
}

/// The advance builder of `network` over the keeper's endpoints, every transport bounded by
/// `budget`.
fn build_source(
    config: &SccpLightClientKeeper,
    network: SccpNetworkV1,
    seed: u64,
    budget: &PollBudget,
) -> Result<Arc<dyn AdvanceSource>, String> {
    let http = |kind| {
        HttpTransport::from_keeper_config(config, kind, seed)
            .map(|transport| transport.with_budget(budget.clone()))
            .map_err(|error| error.to_string())
    };
    Ok(match network {
        SccpNetworkV1::EthereumMainnet => Arc::new(EthereumBuilder::new(
            BeaconClient::new(http(HttpEndpointKind::EthereumBeacon)?),
            EvmClient::new(http(HttpEndpointKind::EthereumExecution)?),
        )),
        SccpNetworkV1::BscMainnet => Arc::new(BscBuilder::new(EvmClient::new(http(
            HttpEndpointKind::Bsc,
        )?))),
        SccpNetworkV1::TonMainnet => Arc::new(TonBuilder::new(
            LiteClient::from_keeper_config(config, seed)
                .map_err(|error| error.to_string())?
                .with_budget(budget.clone()),
        )),
        SccpNetworkV1::SoraTaira => {
            return Err("Taira has no inbound light client".to_owned());
        }
    })
}

/// The budget the builders step an advance of `light_client` to: its
/// `max_updates_per_advance`, and the lower of its `max_advance_bytes` and the keeper's.
fn advance_budget(
    config: &SccpLightClientKeeper,
    light_client: &SccpLightClientV1,
) -> AdvanceBudgetV1 {
    AdvanceBudgetV1::for_params(&light_client.params, config.max_advance_bytes.get())
}

/// Whether a built `advance` fits the configured `max_advance_bytes`. The builders step their
/// advances to this budget; an advance that still exceeds it is dropped with a warning instead
/// of being submitted.
fn fits_advance_bound(
    config: &SccpLightClientKeeper,
    network: SccpNetworkV1,
    advance: &SccpLcAdvanceBytesV1,
) -> bool {
    let max_advance_bytes = config.max_advance_bytes.get();
    let fits = advance.len() <= max_advance_bytes;
    if !fits {
        iroha_logger::warn!(
            network = network.profile_key(),
            advance_bytes = advance.len(),
            max_advance_bytes,
            "SCCP keeper: dropping an advance larger than max_advance_bytes"
        );
    }
    fits
}

/// Whether `light_client` is unfrozen and its head is older than the keeper's staleness bound.
fn is_stale(config: &SccpLightClientKeeper, light_client: &SccpLightClientV1, now_ms: u64) -> bool {
    let after_ms = if light_client.params.ws_bound_ms == 0 {
        TON_ADVANCE_AFTER_MS
    } else {
        let after = config.advance_after_for(light_client.params.ws_bound_ms);
        u64::try_from(after.as_millis()).unwrap_or(u64::MAX)
    };
    !light_client.is_frozen()
        && now_ms.saturating_sub(light_client.head.last_progress_taira_ms) >= after_ms
}

/// Test doubles of a keeper's node and sources.
#[cfg(test)]
mod fakes {
    use std::{
        collections::BTreeMap,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
        time::Instant,
    };

    use iroha_data_model::sccp::light_client::{
        SccpLcHeadV1, SccpLcPointV1, SccpLightClientParamsV1,
    };
    use parking_lot::{Condvar, Mutex};

    use super::*;

    /// A light client of `network` whose head last progressed at Taira time
    /// `last_progress_taira_ms`.
    pub(super) fn light_client(
        network: SccpNetworkV1,
        last_progress_taira_ms: u64,
    ) -> SccpLightClientV1 {
        SccpLightClientV1 {
            params: SccpLightClientParamsV1::defaults_for(network).expect("external network"),
            head: SccpLcHeadV1 {
                latest_set_id: 1,
                latest_finalized: SccpLcPointV1 {
                    source_height: 1,
                    block_hash: [1; 32],
                    source_time_ms: 1,
                },
                last_progress_taira_ms,
            },
            frozen: None,
            state_hash: [0; 32],
        }
    }

    /// `source` as a lane's advance source.
    pub(super) fn shared<S: AdvanceSource>(source: &Arc<S>) -> Arc<dyn AdvanceSource> {
        let source: Arc<S> = Arc::clone(source);
        source
    }

    /// A keeper configuration with millisecond cadences.
    pub(super) fn fast_config(poll_interval_ms: u64, poll_budget_ms: u64) -> SccpLightClientKeeper {
        SccpLightClientKeeper {
            poll_interval: Duration::from_millis(poll_interval_ms),
            poll_budget: Duration::from_millis(poll_budget_ms),
            ..SccpLightClientKeeper::default()
        }
    }

    /// A node whose installed light clients are all stale (head at Taira time 0); it records
    /// reads and submissions per network.
    #[derive(Default)]
    pub(super) struct FakeHost {
        aged: Mutex<BTreeMap<&'static str, bool>>,
        reads: Mutex<BTreeMap<&'static str, usize>>,
        submissions: Mutex<Vec<AdvanceSccpLightClientV1>>,
        refusing: AtomicBool,
    }

    impl FakeHost {
        /// Marks the light client of `network` as aged out of its window.
        pub(super) fn set_aged(&self, network: SccpNetworkV1, aged: bool) {
            self.aged.lock().insert(network.profile_key(), aged);
        }

        /// Makes the node refuse (or accept again) every submission.
        pub(super) fn set_refusing(&self, refusing: bool) {
            self.refusing.store(refusing, Ordering::SeqCst);
        }

        /// Local-state reads of `network` so far.
        pub(super) fn reads(&self, network: SccpNetworkV1) -> usize {
            self.reads
                .lock()
                .get(network.profile_key())
                .copied()
                .unwrap_or(0)
        }

        /// Advances submitted for `network` so far.
        pub(super) fn submissions(&self, network: SccpNetworkV1) -> usize {
            self.submissions
                .lock()
                .iter()
                .filter(|advance| advance.network == network)
                .count()
        }
    }

    impl KeeperHost for FakeHost {
        fn local(&self, network: SccpNetworkV1) -> Local {
            *self.reads.lock().entry(network.profile_key()).or_default() += 1;
            Local {
                light_client: Some(light_client(network, 0)),
                aged: self
                    .aged
                    .lock()
                    .get(network.profile_key())
                    .copied()
                    .unwrap_or(false),
            }
        }

        fn submit(&self, advance: AdvanceSccpLightClientV1) -> eyre::Result<()> {
            eyre::ensure!(
                !self.refusing.load(Ordering::SeqCst),
                "the node refuses the advance"
            );
            self.submissions.lock().push(advance);
            Ok(())
        }
    }

    /// A source whose every build blocks until it is opened, ignoring the poll budget like a
    /// hung endpoint would.
    #[derive(Default)]
    pub(super) struct GatedSource {
        open: Mutex<bool>,
        opened: Condvar,
        entered: AtomicUsize,
    }

    impl GatedSource {
        /// Lets every blocked and later build return.
        pub(super) fn open(&self) {
            *self.open.lock() = true;
            self.opened.notify_all();
        }

        /// Builds started so far.
        pub(super) fn entered(&self) -> usize {
            self.entered.load(Ordering::SeqCst)
        }
    }

    impl AdvanceSource for GatedSource {
        fn advance(
            &self,
            _latest_set_id: u64,
            _budget: AdvanceBudgetV1,
        ) -> Result<SccpLcAdvanceBytesV1, BuildError> {
            self.entered.fetch_add(1, Ordering::SeqCst);
            let mut open = self.open.lock();
            while !*open {
                self.opened.wait(&mut open);
            }
            Ok(SccpLcAdvanceBytesV1::new(vec![1]).expect("advance bytes"))
        }

        fn rotate_endpoints(&self) {}
    }

    /// A source that answers at once, successfully or not, and records when it was called, the
    /// budget of each call and how often its endpoints were rotated.
    pub(super) struct ScriptedSource {
        error: Option<fn() -> BuildError>,
        calls: Mutex<Vec<Instant>>,
        budgets: Mutex<Vec<AdvanceBudgetV1>>,
        rotations: AtomicUsize,
    }

    impl ScriptedSource {
        /// A source whose builds all succeed (`fail == false`) or all fail as unavailable.
        pub(super) fn new(fail: bool) -> Self {
            let unavailable: fn() -> BuildError =
                || BuildError::Unavailable("scripted failure".to_owned());
            Self::scripted(fail.then_some(unavailable))
        }

        /// A source whose builds all fail with `error()`.
        pub(super) fn failing_with(error: fn() -> BuildError) -> Self {
            Self::scripted(Some(error))
        }

        fn scripted(error: Option<fn() -> BuildError>) -> Self {
            Self {
                error,
                calls: Mutex::new(Vec::new()),
                budgets: Mutex::new(Vec::new()),
                rotations: AtomicUsize::new(0),
            }
        }

        /// When each build was called.
        pub(super) fn calls(&self) -> Vec<Instant> {
            self.calls.lock().clone()
        }

        /// The advance budget of each build.
        pub(super) fn budgets(&self) -> Vec<AdvanceBudgetV1> {
            self.budgets.lock().clone()
        }

        /// How often the endpoints were rotated.
        pub(super) fn rotations(&self) -> usize {
            self.rotations.load(Ordering::SeqCst)
        }
    }

    impl AdvanceSource for ScriptedSource {
        fn advance(
            &self,
            _latest_set_id: u64,
            budget: AdvanceBudgetV1,
        ) -> Result<SccpLcAdvanceBytesV1, BuildError> {
            self.calls.lock().push(Instant::now());
            self.budgets.lock().push(budget);
            self.error.map_or_else(
                || Ok(SccpLcAdvanceBytesV1::new(vec![1]).expect("advance bytes")),
                |error| Err(error()),
            )
        }

        fn rotate_endpoints(&self) {
            self.rotations.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{num::NonZeroUsize, os::unix::fs::PermissionsExt as _, path::Path, time::Instant};

    use iroha_config::parameters::actual::Queue as QueueConfig;
    use iroha_config_base::WithOrigin;
    use iroha_core::{kura::Kura, query::store::LiveQueryStore, state::World};
    use iroha_data_model::sccp::light_client::{SccpLcFreezeReasonV1, SccpLcParliamentFreezeV1};

    use super::{fakes::*, *};

    #[test]
    fn staleness_follows_the_configured_or_derived_bound() {
        let network = SccpNetworkV1::EthereumMainnet;
        let mut config = SccpLightClientKeeper {
            advance_after: Some(Duration::from_secs(10)),
            ..SccpLightClientKeeper::default()
        };
        assert!(!is_stale(&config, &light_client(network, 5_000), 14_000));
        assert!(is_stale(&config, &light_client(network, 5_000), 15_000));
        config.advance_after = None;
        let derived = light_client(network, 0).params.ws_bound_ms / 4;
        assert!(!is_stale(&config, &light_client(network, 0), derived - 1));
        assert!(is_stale(&config, &light_client(network, 0), derived));
    }

    #[test]
    fn ton_light_clients_are_polled_hourly() {
        let config = SccpLightClientKeeper::default();
        let ton = light_client(SccpNetworkV1::TonMainnet, 0);
        assert!(!is_stale(&config, &ton, TON_ADVANCE_AFTER_MS - 1));
        assert!(is_stale(&config, &ton, TON_ADVANCE_AFTER_MS));
    }

    #[test]
    fn advances_above_max_advance_bytes_are_dropped() {
        let config = SccpLightClientKeeper {
            max_advance_bytes: NonZeroUsize::new(4).expect("nonzero bound"),
            ..SccpLightClientKeeper::default()
        };
        let advance = |len: usize| SccpLcAdvanceBytesV1::new(vec![0; len]).expect("advance bytes");
        let network = SccpNetworkV1::EthereumMainnet;
        assert!(fits_advance_bound(&config, network, &advance(1)));
        assert!(fits_advance_bound(&config, network, &advance(4)));
        assert!(!fits_advance_bound(&config, network, &advance(5)));
        let default = SccpLightClientKeeper::default();
        let bound = default.max_advance_bytes.get();
        assert!(fits_advance_bound(&default, network, &advance(bound)));
        assert!(!fits_advance_bound(&default, network, &advance(bound + 1)));
    }

    #[test]
    fn advances_are_stepped_to_the_keeper_byte_bound() {
        let network = SccpNetworkV1::EthereumMainnet;
        let mut config = SccpLightClientKeeper::default();
        let budget = advance_budget(&config, &light_client(network, 0));
        assert_eq!(budget.max_items, 16);
        assert_eq!(budget.max_bytes, 262_144);
        config.max_advance_bytes = NonZeroUsize::new(usize::MAX).expect("nonzero bound");
        let mut wide = light_client(network, 0);
        wide.params.max_advance_bytes = 300_000;
        wide.params.max_updates_per_advance = 4;
        let budget = advance_budget(&config, &wide);
        assert_eq!(budget.max_items, 4);
        assert_eq!(budget.max_bytes, 300_000);
    }

    #[test]
    fn decisions_skip_idle_fresh_and_unrecoverable_light_clients() {
        let config = SccpLightClientKeeper::default();
        let network = SccpNetworkV1::BscMainnet;
        let bound = config.advance_after_for(light_client(network, 0).params.ws_bound_ms);
        let stale_at = u64::try_from(bound.as_millis()).expect("bound fits");
        let local =
            |light_client: Option<SccpLightClientV1>, aged: bool| Local { light_client, aged };
        let stale = Some(light_client(network, 0));
        assert_eq!(decide(&config, &Local::default(), stale_at), Step::Idle);
        assert_eq!(decide(&config, &local(None, true), stale_at), Step::Idle);
        assert_eq!(
            decide(&config, &local(stale, false), stale_at - 1),
            Step::Fresh
        );
        // A stale light client is advanced without any registered key of this node.
        assert_eq!(
            decide(&config, &local(stale, false), stale_at),
            Step::Advance
        );
        assert_eq!(
            decide(&config, &local(stale, true), stale_at),
            Step::Recovery(Recovery::Aged)
        );
        let mut frozen = light_client(network, 0);
        frozen.frozen = Some(SccpLcFreezeReasonV1::Parliament(SccpLcParliamentFreezeV1 {
            proposal_id: [3; 32],
        }));
        assert_eq!(
            decide(&config, &local(Some(frozen), false), stale_at),
            Step::Recovery(Recovery::Frozen)
        );
    }

    #[test]
    fn cadence_backs_off_per_failure_with_bounded_jitter() {
        let interval = Duration::from_secs(60);
        let mut cadence = Cadence::new(interval, 42);
        let first = cadence.first();
        assert!(first <= interval / 4, "{first:?}");
        let within = |wait: Duration, base: Duration| wait >= base && wait <= base + base / 4;
        let success = cadence.after_success();
        assert!(within(success, interval), "{success:?}");
        for doublings in 1..=MAX_BACKOFF_DOUBLINGS {
            let wait = cadence.after_failure();
            assert_eq!(cadence.failures(), doublings);
            assert!(
                within(wait, interval * (1 << doublings)),
                "{doublings}: {wait:?}"
            );
        }
        let cap = interval * (1 << MAX_BACKOFF_DOUBLINGS);
        for _ in 0..5 {
            let wait = cadence.after_failure();
            assert!(within(wait, cap), "capped: {wait:?}");
        }
        let reset = cadence.after_success();
        assert_eq!(cadence.failures(), 0);
        assert!(within(reset, interval), "{reset:?}");
    }

    #[test]
    fn cadence_jitter_is_deterministic_per_seed() {
        let interval = Duration::from_secs(60);
        let waits = |seed: u64| {
            let mut cadence = Cadence::new(interval, seed);
            let mut waits = vec![cadence.first()];
            waits.extend((0..8).map(|_| cadence.after_success()));
            waits
        };
        assert_eq!(waits(7), waits(7));
        assert_ne!(waits(7), waits(8));
        let spread: std::collections::BTreeSet<_> = waits(7).into_iter().skip(1).collect();
        assert!(spread.len() > 1, "jitter varies between polls");
        let mut zero = Cadence::new(Duration::ZERO, 1);
        assert_eq!(zero.first(), Duration::ZERO);
        assert_eq!(zero.after_failure(), Duration::ZERO);
    }

    #[test]
    fn lanes_of_one_node_get_distinct_seeds() {
        let seeds: std::collections::BTreeSet<_> = NETWORKS
            .iter()
            .map(|network| lane_seed(5, *network))
            .collect();
        assert_eq!(seeds.len(), NETWORKS.len());
        assert_eq!(
            lane_seed(5, SccpNetworkV1::TonMainnet),
            lane_seed(5, SccpNetworkV1::TonMainnet)
        );
        assert_ne!(
            lane_seed(5, SccpNetworkV1::TonMainnet),
            lane_seed(6, SccpNetworkV1::TonMainnet)
        );
    }

    #[test]
    fn a_disabled_light_client_duty_starts_no_task() {
        let config = SccpLightClientKeeper {
            enabled: false,
            ..SccpLightClientKeeper::default()
        };
        let host = Arc::new(FakeHost::default());
        assert!(start_advances(host, config, 0, ShutdownSignal::new()).is_none());
    }

    /// An empty node: committed state without SCCP and a local queue.
    fn node() -> (Arc<State>, Arc<Queue>) {
        let state = Arc::new(State::new_for_testing(
            World::new(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        ));
        let (events, _) = tokio::sync::broadcast::channel(1);
        let queue = Arc::new(Queue::from_config(QueueConfig::default(), events));
        (state, queue)
    }

    /// The default `[sccp.keeper]` of a node whose Kura store is `dir`.
    fn keeper_config(dir: &Path) -> SccpKeeper {
        SccpKeeper::defaults_for_kura_store_dir(&WithOrigin::inline(dir.to_path_buf()))
    }

    fn mode(path: &Path) -> u32 {
        std::fs::symlink_metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    }

    #[tokio::test]
    async fn the_keeper_generates_its_key_on_first_start_and_keeps_it() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let shutdown = ShutdownSignal::new();
        let peer = PeerId::new(KeyPair::random().public_key().clone());
        let config = keeper_config(dir.path());
        let key_dir = dir.path().join("sccp").join("keeper-key");
        assert_eq!(config.key_dir_path(), key_dir);
        let started = |config: &SccpKeeper, light_client: SccpLightClientKeeper| {
            let (state, queue) = node();
            start(state, queue, &peer, config, light_client, shutdown.clone()).is_some()
        };
        let idle = || SccpLightClientKeeper {
            enabled: false,
            ..SccpLightClientKeeper::default()
        };

        // A disabled keeper touches nothing.
        let mut disabled = config.clone();
        disabled.enabled = false;
        assert!(!started(&disabled, SccpLightClientKeeper::default()));
        assert!(!key_dir.exists());

        // The first start generates the key into the empty, owner-only directory; the node
        // holds no registered key of any kind.
        assert!(started(&config, SccpLightClientKeeper::default()));
        let key_file = key_dir.join(key_store::KEY_FILE_NAME);
        assert_eq!(mode(&key_dir), 0o700);
        assert_eq!(mode(&key_file), 0o600);
        let key = std::fs::read(&key_file).expect("key file");

        // Later starts keep the key, also when only the key is needed.
        assert!(started(&config, SccpLightClientKeeper::default()));
        assert!(!started(&config, idle()), "no duty is enabled");
        assert_eq!(std::fs::read(&key_file).expect("key file"), key);

        // The key is generated even when the light-client duty is off.
        let other = tempfile::tempdir().expect("temporary directory");
        assert!(!started(&keeper_config(other.path()), idle()));
        assert!(
            other
                .path()
                .join("sccp/keeper-key")
                .join(key_store::KEY_FILE_NAME)
                .is_file()
        );

        // An unusable key directory leaves the keeper inert; the node goes on.
        let mut unusable = config.clone();
        let not_a_directory = dir.path().join("file");
        std::fs::write(&not_a_directory, b"x").expect("write file");
        unusable.key_dir = WithOrigin::inline(not_a_directory);
        assert!(!started(&unusable, SccpLightClientKeeper::default()));
        let mut linked = config;
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&key_dir, &link).expect("symlink");
        linked.key_dir = WithOrigin::inline(link);
        assert!(!started(&linked, SccpLightClientKeeper::default()));
        shutdown.send();
    }

    /// A decodable advance of `network` that proves nothing.
    fn empty_advance(network: SccpNetworkV1) -> AdvanceSccpLightClientV1 {
        use iroha_sccp::light_client::{
            bsc::BscLcAdvanceV1, ethereum::EthereumLcAdvanceV1, proof::SccpLcAdvanceV1,
        };
        let advance = if network == SccpNetworkV1::BscMainnet {
            SccpLcAdvanceV1::Bsc(BscLcAdvanceV1 { steps: Vec::new() })
        } else {
            SccpLcAdvanceV1::Ethereum(EthereumLcAdvanceV1 {
                updates: Vec::new(),
            })
        };
        AdvanceSccpLightClientV1 {
            network,
            expected_state_hash: None,
            advance: advance.to_bytes().expect("bounded advance"),
        }
    }

    #[tokio::test]
    async fn submissions_on_a_node_without_sccp_fail_without_panicking() {
        let (state, queue) = node();
        let key = KeyPair::random();
        let advance = empty_advance(SccpNetworkV1::BscMainnet);
        assert!(
            submit_transaction(&state, &queue, &key, InstructionBox::from(advance)).is_err(),
            "an advance on a node without SCCP is refused"
        );
        let host = NodeHost { state, queue, key };
        let local = host.local(SccpNetworkV1::BscMainnet);
        assert!(local.light_client.is_none() && !local.aged);
        assert!(
            host.submit(empty_advance(SccpNetworkV1::EthereumMainnet))
                .is_err()
        );
    }

    /// With SCCP in committed state, an advance signed by a fresh keeper key (no account, no
    /// funds) is quoted fee-exempt and passes the queue's authority gate: what refuses it is
    /// SCCP pre-verification of the advance itself.
    #[tokio::test]
    async fn the_unregistered_keeper_key_reaches_sccp_pre_verification() {
        use std::num::NonZeroU64;

        use iroha_data_model::{
            block::{
                BlockHeader,
                consensus::{SumeragiGenesisContextParameters, SumeragiRootScope},
            },
            parameter::{
                Parameter,
                custom::CustomParameter,
                system::{
                    ConsensusFingerprint, ConsensusHandshakeMetadata, SumeragiConsensusMode,
                    consensus_metadata,
                },
            },
            sccp::params::SccpParametersV1,
        };

        // Fee quoting needs the explicit immutable root scope of the network.
        let mut context = SumeragiGenesisContextParameters::recommended();
        context.root_scope = SumeragiRootScope::Global;
        let metadata = ConsensusHandshakeMetadata {
            mode: SumeragiConsensusMode::Permissioned,
            block_cadence_ms: NonZeroU64::new(1_000).expect("nonzero"),
            wire_protocol_version: u32::from(iroha_data_model::sumeragi::PROTOCOL_VERSION),
            consensus_fingerprint: ConsensusFingerprint::new([0x5c; 32]),
            sumeragi_context: context,
        };
        metadata.validate().expect("valid metadata");
        let world = World::new();
        {
            let mut block = world.block();
            block
                .parameters
                .set_parameter(Parameter::Custom(CustomParameter::new(
                    consensus_metadata::handshake_meta_id(),
                    iroha_primitives::json::Json::new(metadata),
                )))
                .expect("install the signed SCCP handshake fixture");
            block.commit();
        }
        let state = Arc::new(State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        ));
        let (_, queue) = node();
        {
            let header = BlockHeader::new(NonZeroU64::new(1).expect("nonzero"), None, None, 0, 0);
            let mut block = state.block(header);
            let mut transaction = block.transaction();
            store::parameters::set(&mut transaction, Some(SccpParametersV1::taira_default()));
            transaction.apply();
            block
                .commit_world_overlay_for_testing()
                .expect("commit SCCP parameters");
        }
        let key = KeyPair::random();
        let authority = AccountId::new(key.public_key().clone());
        assert!(
            state.view().world().account(&authority).is_err(),
            "the keeper key has no account"
        );
        let advance = empty_advance(SccpNetworkV1::EthereumMainnet);
        let error = submit_transaction(&state, &queue, &key, InstructionBox::from(advance))
            .expect_err("no light client is installed");
        let reason = format!("{error:#}");
        assert!(
            reason.contains("the light client is not installed"),
            "{reason}"
        );
        // A `Backfill` is not exempt, so the same key is refused before SCCP looks at it.
        let backfill = AdvanceSccpLightClientV1 {
            network: SccpNetworkV1::EthereumMainnet,
            expected_state_hash: None,
            advance: iroha_sccp::light_client::proof::SccpLcAdvanceV1::Backfill {
                segment: iroha_sccp::light_client::proof::SccpLcSegmentV1::Ethereum(
                    iroha_sccp::light_client::ethereum::EthereumHeaderSegmentV1 {
                        headers: Vec::new(),
                    },
                ),
            }
            .to_bytes()
            .expect("bounded advance"),
        };
        let error = submit_transaction(&state, &queue, &key, InstructionBox::from(backfill))
            .expect_err("a Backfill owes the ordinary fee");
        let reason = format!("{error:#}");
        assert!(
            !reason.contains("the light client is not installed"),
            "{reason}"
        );
    }

    /// Every chain of the default configuration has a lane, in [`NETWORKS`] order.
    fn assert_default_lanes(lanes: &[Lane]) {
        let networks: Vec<_> = lanes.iter().map(Lane::network).collect();
        assert_eq!(networks, NETWORKS);
    }

    #[tokio::test]
    async fn the_default_keeper_builds_inside_a_current_thread_runtime() {
        let lanes = build(Arc::new(SccpLightClientKeeper::default()), 1).await;
        assert_default_lanes(&lanes);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_default_keeper_builds_inside_a_multi_thread_runtime() {
        let lanes = build(Arc::new(SccpLightClientKeeper::default()), 1).await;
        assert_default_lanes(&lanes);
        // The lanes, like the keeper task that owns them, are dropped on an async worker.
        drop(lanes);
    }

    #[tokio::test]
    async fn an_enabled_keeper_runs_until_shutdown() {
        let shutdown = ShutdownSignal::new();
        let host = Arc::new(FakeHost::default());
        let config = fast_config(3_600_000, 1_000);
        let task = tokio::spawn(run(Vec::new(), host, Arc::new(config), shutdown.clone()));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !task.is_finished(),
            "a keeper without lanes waits for shutdown"
        );
        shutdown.send();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the keeper stops on shutdown")
            .expect("the keeper does not panic");
    }

    /// Waits (asynchronously, so a current-thread runtime keeps running) until `ready`.
    async fn eventually(what: &str, ready: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !ready() {
            assert!(Instant::now() < deadline, "timed out waiting until {what}");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn networks_are_scheduled_independently_with_backoff() {
        let shutdown = ShutdownSignal::new();
        let host = Arc::new(FakeHost::default());
        host.set_aged(SccpNetworkV1::TonMainnet, true);
        let config = Arc::new(fast_config(25, 1_000));
        let working = Arc::new(ScriptedSource::new(false));
        let failing = Arc::new(ScriptedSource::new(true));
        let aged = Arc::new(ScriptedSource::new(false));
        let lane = |network, source: Arc<dyn AdvanceSource>| {
            Lane::new(
                network,
                source,
                PollBudget::new(),
                Cadence::new(config.poll_interval, lane_seed(9, network)),
            )
        };
        let lanes = vec![
            lane(SccpNetworkV1::BscMainnet, shared(&working)),
            lane(SccpNetworkV1::EthereumMainnet, shared(&failing)),
            lane(SccpNetworkV1::TonMainnet, shared(&aged)),
        ];
        let keeper = tokio::spawn(run(
            lanes,
            Arc::clone(&host),
            Arc::clone(&config),
            shutdown.clone(),
        ));
        eventually("the working network was advanced ten times", || {
            host.submissions(SccpNetworkV1::BscMainnet) >= 10
        })
        .await;
        // The aged TON light client is read but no RPC is spent on it.
        assert!(host.reads(SccpNetworkV1::TonMainnet) >= 2);
        assert!(aged.calls().is_empty());
        assert_eq!(host.submissions(SccpNetworkV1::TonMainnet), 0);
        // The failing Ethereum network backs off: its waits grow while BSC keeps its cadence.
        let ethereum = failing.calls();
        let bsc = working.calls();
        assert!(
            ethereum.len() < bsc.len(),
            "Ethereum {} vs BSC {}",
            ethereum.len(),
            bsc.len()
        );
        assert_eq!(host.submissions(SccpNetworkV1::EthereumMainnet), 0);
        eventually("Ethereum failed three times", || failing.calls().len() >= 3).await;
        assert!(
            failing.rotations() >= 2,
            "each failed Ethereum build moved to other endpoints"
        );
        assert_eq!(working.rotations(), 0);
        let ethereum = failing.calls();
        let first_gap = ethereum[1].duration_since(ethereum[0]);
        let second_gap = ethereum[2].duration_since(ethereum[1]);
        assert!(
            first_gap >= config.poll_interval * 2,
            "the first retry waits twice the interval: {first_gap:?}"
        );
        assert!(
            second_gap >= config.poll_interval * 4,
            "the second retry waits four times the interval: {second_gap:?}"
        );
        // Re-initialization makes the aged light client advanceable again.
        host.set_aged(SccpNetworkV1::TonMainnet, false);
        eventually("TON was advanced after recovery", || {
            host.submissions(SccpNetworkV1::TonMainnet) >= 1
        })
        .await;
        shutdown.send();
        tokio::time::timeout(Duration::from_secs(5), keeper)
            .await
            .expect("the keeper stops on shutdown")
            .expect("the keeper does not panic");
    }

    /// The async side of the keeper runs on the only thread of a current-thread runtime while a
    /// hung endpoint blocks a build on a blocking worker.
    #[tokio::test(flavor = "current_thread")]
    async fn a_hung_endpoint_blocks_neither_the_runtime_nor_the_other_networks() {
        let shutdown = ShutdownSignal::new();
        let host = Arc::new(FakeHost::default());
        let config = Arc::new(fast_config(10, 50));
        let hung = Arc::new(GatedSource::default());
        let working = Arc::new(ScriptedSource::new(false));
        let lane = |network, source: Arc<dyn AdvanceSource>| {
            Lane::new(
                network,
                source,
                PollBudget::new(),
                Cadence::new(config.poll_interval, lane_seed(1, network)),
            )
        };
        let keeper = tokio::spawn(run(
            vec![
                lane(SccpNetworkV1::EthereumMainnet, shared(&hung)),
                lane(SccpNetworkV1::TonMainnet, shared(&working)),
            ],
            Arc::clone(&host),
            Arc::clone(&config),
            shutdown.clone(),
        ));
        eventually("the build hung", || hung.entered() == 1).await;
        let before = host.submissions(SccpNetworkV1::TonMainnet);
        eventually("the other network kept its cadence", || {
            host.submissions(SccpNetworkV1::TonMainnet) >= before + 5
        })
        .await;
        assert_eq!(hung.entered(), 1, "the hung build is still the only one");
        assert_eq!(host.submissions(SccpNetworkV1::EthereumMainnet), 0);
        hung.open();
        eventually("the keeper submitted after the endpoint answered", || {
            host.submissions(SccpNetworkV1::EthereumMainnet) >= 1
        })
        .await;
        shutdown.send();
        tokio::time::timeout(Duration::from_secs(10), keeper)
            .await
            .expect("the keeper stops on shutdown")
            .expect("the keeper does not panic");
    }

    #[tokio::test]
    async fn a_refused_submission_fails_the_poll() {
        let host = Arc::new(FakeHost::default());
        let config = Arc::new(fast_config(25, 1_000));
        let source = Arc::new(ScriptedSource::new(false));
        let mut lane = Lane::new(
            SccpNetworkV1::BscMainnet,
            shared(&source),
            PollBudget::new(),
            Cadence::new(config.poll_interval, 1),
        );
        host.set_refusing(true);
        assert!(
            !lane.poll(&host, &config).await,
            "a refused submission is a failed poll, which backs the lane off"
        );
        assert_eq!(host.submissions(SccpNetworkV1::BscMainnet), 0);
        assert_eq!(source.rotations(), 0, "the endpoints are not to blame");
        host.set_refusing(false);
        assert!(lane.poll(&host, &config).await);
        assert_eq!(host.submissions(SccpNetworkV1::BscMainnet), 1);
        // An aged light client spends neither a build nor a submission.
        host.set_aged(SccpNetworkV1::BscMainnet, true);
        assert!(lane.poll(&host, &config).await);
        assert_eq!(source.calls().len(), 2);
        assert_eq!(host.submissions(SccpNetworkV1::BscMainnet), 1);
    }

    #[test]
    fn only_failures_on_served_data_blame_the_endpoints() {
        let rpc = BuildError::Rpc(iroha_sccp_rpc::RpcError::Timeout {
            endpoint: "https://rpc.example.org".to_owned(),
        });
        assert!(!blames_served_data(&rpc));
        for error in [
            BuildError::Json("an update is not an object".to_owned()),
            BuildError::Inconsistent("a header does not hash to its hash".to_owned()),
            BuildError::Unavailable("block 7 is not served".to_owned()),
        ] {
            assert!(blames_served_data(&error), "{error}");
        }
    }

    #[tokio::test]
    async fn builds_failing_on_served_data_rotate_the_lane_endpoints() {
        fn inconsistent() -> BuildError {
            BuildError::Inconsistent("a header does not hash to its hash".to_owned())
        }
        fn malformed() -> BuildError {
            BuildError::Json("an update is not an object".to_owned())
        }
        fn exhausted() -> BuildError {
            BuildError::Rpc(iroha_sccp_rpc::RpcError::Exhausted {
                failures: Vec::new(),
            })
        }
        let host = Arc::new(FakeHost::default());
        let config = Arc::new(fast_config(25, 1_000));
        let lane = |source: Arc<dyn AdvanceSource>| {
            Lane::new(
                SccpNetworkV1::BscMainnet,
                source,
                PollBudget::new(),
                Cadence::new(config.poll_interval, 1),
            )
        };
        let cases: [(fn() -> BuildError, usize); 3] =
            [(inconsistent, 1), (malformed, 1), (exhausted, 0)];
        for (error, rotations) in cases {
            let source = Arc::new(ScriptedSource::failing_with(error));
            let mut failing = lane(shared(&source));
            assert!(
                !failing.poll(&host, &config).await,
                "a failed build fails the poll"
            );
            assert_eq!(source.calls().len(), 1);
            assert_eq!(source.rotations(), rotations, "{}", error());
        }
        assert_eq!(host.submissions(SccpNetworkV1::BscMainnet), 0);
        let working = Arc::new(ScriptedSource::new(false));
        let mut advancing = lane(shared(&working));
        assert!(advancing.poll(&host, &config).await);
        assert_eq!(working.rotations(), 0);
        assert_eq!(host.submissions(SccpNetworkV1::BscMainnet), 1);
        assert_eq!(
            working.budgets(),
            vec![advance_budget(
                &config,
                &light_client(SccpNetworkV1::BscMainnet, 0)
            )],
            "the lane steps its advance to the light client's and the keeper's bounds"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_overrun_poll_fails_and_blocks_only_its_own_network() {
        let shutdown = ShutdownSignal::new();
        let host = Arc::new(FakeHost::default());
        let config = Arc::new(fast_config(20, 60));
        let hung = Arc::new(GatedSource::default());
        let working = Arc::new(ScriptedSource::new(false));
        let lane = |network, source: Arc<dyn AdvanceSource>| {
            Lane::new(
                network,
                source,
                PollBudget::new(),
                Cadence::new(config.poll_interval, lane_seed(3, network)),
            )
        };
        let keeper = tokio::spawn(run(
            vec![
                lane(SccpNetworkV1::EthereumMainnet, shared(&hung)),
                lane(SccpNetworkV1::BscMainnet, shared(&working)),
            ],
            Arc::clone(&host),
            Arc::clone(&config),
            shutdown.clone(),
        ));
        eventually("the build hung", || hung.entered() == 1).await;
        // Several overrun budgets later the hung build is still the only one.
        tokio::time::sleep(config.poll_budget * 5).await;
        // The hung Ethereum build never delays the other networks.
        eventually("the working network was advanced ten times", || {
            host.submissions(SccpNetworkV1::BscMainnet) >= 10
        })
        .await;
        assert_eq!(
            hung.entered(),
            1,
            "one hung build, no second poll beside it"
        );
        assert_eq!(host.submissions(SccpNetworkV1::EthereumMainnet), 0);
        // Once the endpoint answers, a later poll builds and submits again.
        hung.open();
        eventually("a later poll submitted", || {
            host.submissions(SccpNetworkV1::EthereumMainnet) >= 1
        })
        .await;
        assert!(hung.entered() >= 2);
        shutdown.send();
        tokio::time::timeout(Duration::from_secs(5), keeper)
            .await
            .expect("the keeper stops on shutdown")
            .expect("the keeper does not panic");
    }
}
