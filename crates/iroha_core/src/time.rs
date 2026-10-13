//! Network Time Service (NTS)
//!
//! A lightweight time synchronization service that computes a network time
//! offset using NTP-style pings to peers and a trimmed-median aggregator.
//! - Periodically samples key-ACL-filtered configured logical peers with `TimePing`
//!   messages and collects `TimePong` replies, including through relay hubs.
//! - Computes per-sample offset and RTT using t1..t4 timestamps and filters
//!   high-RTT outliers.
//! - Aggregates offsets via trimmed median; exposes `now()` for Torii and
//!   timers.
//! The process anchors Unix time once and advances timestamps, RTT and retained
//! deadlines with the native suspend-inclusive elapsed clock. Clock refusal or
//! regression marks status as an unhealthy fallback and prevents time probes
//! from authenticating samples until the original clock recovers.
use crate::IrohaNetwork;
use iroha_config::parameters::actual::NtsEnforcementMode;
use iroha_data_model::peer::Peer;
use iroha_futures::supervisor::{Child, OnShutdown, ShutdownSignal};
use iroha_primitives::time::NativeContinuousReading;
use norito::codec::{Decode, Encode};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        Mutex, MutexGuard, OnceLock, RwLock,
        atomic::{AtomicU8, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};
/// Outbound time probe message (peer → peer).
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::time::TimePing")]
#[derive(Clone, Copy, Debug, Encode, Decode)]
pub struct TimePing {
    /// Monotonic probe identifier.
    pub id: u64,
    /// Local send timestamp (ms since UNIX epoch).
    pub t1_ms: u64,
}
/// Inbound time probe response (peer → peer).
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::time::TimePong")]
#[derive(Clone, Copy, Debug, Encode, Decode)]
pub struct TimePong {
    /// Echoed probe identifier.
    pub id: u64,
    /// Receiver timestamp at arrival.
    pub t2_ms: u64,
    /// Receiver timestamp at response send.
    pub t3_ms: u64,
}
/// Snapshot of the current network time estimation.
#[derive(Clone, Copy, Debug)]
pub struct NetworkTimeStatus {
    /// Adjusted current time based on the estimated offset.
    pub now: std::time::SystemTime,
    /// Estimated offset from local clock in milliseconds.
    pub offset_ms: i64,
    /// Robust dispersion estimate in milliseconds (median absolute deviation).
    pub confidence_ms: u64,
    /// Number of peer samples used in the current aggregation (post-filter).
    pub sample_count: usize,
    /// Number of peers with at least one recent sample (pre-filter).
    pub peer_count: usize,
    /// Whether NTS fell back to local time due to missing/invalid samples.
    pub fallback: bool,
    /// Health evaluation flags for the current status snapshot.
    pub health: NtsHealth,
}
/// Network-time and admission-policy values captured atomically.
#[derive(Clone, Copy, Debug)]
pub struct NetworkTimeAdmissionSnapshot {
    /// Current network-time estimate and health evaluation.
    pub status: NetworkTimeStatus,
    /// Admission behavior paired with this exact service generation.
    pub enforcement_mode: NtsEnforcementMode,
}
/// Health evaluation flags for the current NTS snapshot.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug)]
pub struct NtsHealth {
    /// Whether the minimum sample threshold has been met.
    pub min_samples_ok: bool,
    /// Whether the absolute offset is within configured bounds.
    pub offset_ok: bool,
    /// Whether the confidence (MAD) is within configured bounds.
    pub confidence_ok: bool,
    /// Overall health status (true only when all checks pass and no fallback).
    pub healthy: bool,
}
/// Health policy thresholds for evaluating NTS snapshots.
#[derive(Debug, Clone, Copy)]
pub struct NtsHealthPolicy {
    /// Minimum number of peer samples required before NTS is considered healthy.
    pub min_samples: usize,
    /// Maximum absolute offset (ms) permitted before NTS is considered unhealthy (0 disables).
    pub max_offset_ms: u64,
    /// Maximum confidence (MAD) in ms permitted before NTS is considered unhealthy (0 disables).
    pub max_confidence_ms: u64,
}
impl NtsHealthPolicy {
    fn evaluate(
        self,
        sample_count: usize,
        offset_ms: i64,
        confidence_ms: u64,
        fallback: bool,
    ) -> NtsHealth {
        let min_samples_ok = sample_count >= self.min_samples.max(1);
        let offset_ok = self.max_offset_ms == 0 || offset_ms.unsigned_abs() <= self.max_offset_ms;
        let confidence_ok = self.max_confidence_ms == 0 || confidence_ms <= self.max_confidence_ms;
        let healthy = !fallback && min_samples_ok && offset_ok && confidence_ok;
        NtsHealth {
            min_samples_ok,
            offset_ok,
            confidence_ok,
            healthy,
        }
    }
}
impl Default for NtsHealthPolicy {
    fn default() -> Self {
        Self {
            min_samples: iroha_config::parameters::defaults::time::NTS_MIN_SAMPLES,
            max_offset_ms: iroha_config::parameters::defaults::time::NTS_MAX_OFFSET_MS,
            max_confidence_ms: iroha_config::parameters::defaults::time::NTS_MAX_CONFIDENCE_MS,
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct Sample {
    offset_ms: i64,
    rtt_ms: u64,
    probe_sent_at: Instant,
    received_at: Instant,
    expires_at: Instant,
}
#[derive(Clone, Copy)]
struct OutstandingProbe {
    t1_ms: u64,
    sent_at: Instant,
    expires_at: Instant,
}
const RTT_BUCKET_BOUNDS_MS: &[u64] = &[1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, u64::MAX];
const MIN_SAMPLE_INTERVAL: Duration = Duration::from_millis(100);
const MAX_EXPIRY_REPLAY_EVENTS_PER_PRUNE: usize = 64;

fn bounded_expiry_replay_deadlines(
    mut deadlines: Vec<Instant>,
    observed_at: Instant,
) -> Vec<Instant> {
    deadlines.sort_unstable();
    deadlines.dedup();
    if deadlines.len() <= MAX_EXPIRY_REPLAY_EVENTS_PER_PRUNE {
        return deadlines;
    }
    deadlines.truncate(MAX_EXPIRY_REPLAY_EVENTS_PER_PRUNE - 1);
    if deadlines.last().copied() != Some(observed_at) {
        deadlines.push(observed_at);
    }
    deadlines
}
/// Runtime parameters for the Network Time Service.
#[derive(Debug, Clone, Copy)]
pub struct Params {
    /// Sampling interval for peer time probes.
    pub sample_interval: std::time::Duration,
    /// Maximum peers to sample per round.
    pub sample_cap_per_round: usize,
    /// Maximum acceptable round-trip time (milliseconds) for samples.
    pub max_rtt_ms: u64,
    /// Trim percent for median aggregation (0–45 allowed; 10 typical).
    pub trim_percent: u8,
    /// Per-peer ring buffer capacity for samples.
    pub per_peer_buffer: usize,
    /// Enable EMA smoothing of network offset.
    pub smoothing_enabled: bool,
    /// EMA alpha in [0,1]; higher means more responsive.
    pub smoothing_alpha: f64,
    /// Maximum allowed adjustment per minute (ms) when smoothing.
    pub max_adjust_ms_per_min: u64,
    /// Health policy thresholds for NTS status evaluation.
    pub health_policy: NtsHealthPolicy,
    /// Enforcement mode for unhealthy NTS during admission.
    pub enforcement_mode: NtsEnforcementMode,
}
impl Default for Params {
    fn default() -> Self {
        Self {
            sample_interval: std::time::Duration::from_secs(5),
            sample_cap_per_round: 8,
            max_rtt_ms: 500,
            trim_percent: 10,
            per_peer_buffer: 16,
            smoothing_enabled: false,
            smoothing_alpha: 0.2,
            max_adjust_ms_per_min: 50,
            health_policy: NtsHealthPolicy::default(),
            enforcement_mode: NtsEnforcementMode::Warn,
        }
    }
}
impl Params {
    fn normalized(mut self) -> Self {
        let defaults = Self::default();
        self.sample_interval = self.sample_interval.max(MIN_SAMPLE_INTERVAL);
        if self.sample_cap_per_round == 0 {
            self.sample_cap_per_round = defaults.sample_cap_per_round;
        }
        if self.max_rtt_ms == 0 {
            self.max_rtt_ms = defaults.max_rtt_ms;
        }
        self.trim_percent = self.trim_percent.min(45);
        if self.per_peer_buffer == 0 {
            self.per_peer_buffer = defaults.per_peer_buffer;
        }
        self.health_policy.min_samples = self.health_policy.min_samples.max(1);
        if !self.smoothing_alpha.is_finite() {
            self.smoothing_alpha = defaults.smoothing_alpha;
        } else {
            self.smoothing_alpha = self.smoothing_alpha.clamp(0.0, 1.0);
        }
        self
    }
}
impl From<&iroha_config::parameters::actual::Nts> for Params {
    fn from(x: &iroha_config::parameters::actual::Nts) -> Self {
        Self {
            sample_interval: x.sample_interval,
            sample_cap_per_round: x.sample_cap_per_round,
            max_rtt_ms: x.max_rtt_ms,
            trim_percent: x.trim_percent,
            per_peer_buffer: x.per_peer_buffer,
            smoothing_enabled: x.smoothing_enabled,
            smoothing_alpha: x.smoothing_alpha,
            max_adjust_ms_per_min: x.max_adjust_ms_per_min,
            health_policy: NtsHealthPolicy {
                min_samples: x.min_samples,
                max_offset_ms: x.max_offset_ms,
                max_confidence_ms: x.max_confidence_ms,
            },
            enforcement_mode: x.enforcement_mode,
        }
    }
}
struct Service {
    outstanding: BTreeMap<(iroha_model_base::peer::PeerId, u64), OutstandingProbe>,
    per_peer: BTreeMap<iroha_model_base::peer::PeerId, VecDeque<Sample>>, // ring buffer
    id_counter: u64,
    params: Params,
    network: Option<IrohaNetwork>,
    configured_peer_generation: Option<u64>,
    configured_peer_count: usize,
    // Smoothing state
    smoothed_offset_ms: f64,
    aggregate_dirty: bool,
    last_smooth_update: Instant,
    // RTT histogram aggregates
    rtt_bounds_ms: &'static [u64],
    rtt_bucket_counts: Vec<u64>,
    rtt_ms_sum: u64,
    rtt_ms_count: u64,
}
impl Service {
    fn new(params: Params) -> Self {
        Self {
            outstanding: BTreeMap::new(),
            per_peer: BTreeMap::new(),
            id_counter: 1,
            params,
            network: None,
            configured_peer_generation: None,
            configured_peer_count: 1,
            smoothed_offset_ms: 0.0,
            aggregate_dirty: false,
            last_smooth_update: local_clock_sample().observed_at,
            rtt_bounds_ms: RTT_BUCKET_BOUNDS_MS,
            rtt_bucket_counts: vec![0; RTT_BUCKET_BOUNDS_MS.len()],
            rtt_ms_sum: 0,
            rtt_ms_count: 0,
        }
    }
    fn reset(&mut self, params: Params) {
        // Probe ids stay process-monotonic across sampler restarts so a delayed
        // pong from the previous generation cannot match a new outstanding id.
        let id_counter = self.id_counter;
        *self = Self::new(params);
        self.id_counter = id_counter;
    }
    fn apply_configured_membership(
        &mut self,
        generation: u64,
        peer_count: usize,
        observed_at: Instant,
    ) -> bool {
        if self.configured_peer_generation == Some(generation)
            && self.configured_peer_count == peer_count
        {
            return false;
        }
        // Membership epochs are a security boundary. Invalidating the complete
        // retained aggregate also covers a peer removed and re-added between
        // two NTS polls; no sample or in-flight reply crosses that boundary.
        self.outstanding.clear();
        self.per_peer.clear();
        self.smoothed_offset_ms = 0.0;
        self.aggregate_dirty = false;
        self.last_smooth_update = observed_at;
        self.configured_peer_generation = Some(generation);
        self.configured_peer_count = peer_count;
        true
    }
    fn attach_network(&mut self, network: IrohaNetwork, observed_at: Instant) {
        let (generation, peer_count) = network.configured_peer_generation_and_count();
        self.network = Some(network);
        let _ = self.apply_configured_membership(generation, peer_count, observed_at);
    }
    fn reconcile_network_membership(&mut self, observed_at: Instant) -> bool {
        let Some(network) = self.network.as_ref() else {
            return false;
        };
        let (generation, peer_count) = network.configured_peer_generation_and_count();
        self.apply_configured_membership(generation, peer_count, observed_at)
    }
    fn with_reconciled_network_membership<R>(
        &mut self,
        observed_at: Instant,
        f: impl FnOnce(&mut Self) -> R,
    ) -> R {
        let Some(network) = self.network.clone() else {
            return f(self);
        };
        network.with_configured_peer_generation_and_count(|generation, peer_count| {
            let _ = self.apply_configured_membership(generation, peer_count, observed_at);
            f(self)
        })
    }
    fn probe_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.params.max_rtt_ms)
    }
    fn sample_freshness_window(&self) -> std::time::Duration {
        let peers_per_round = self.params.sample_cap_per_round.max(1);
        let rounds_per_sweep = self.configured_peer_count.max(1).div_ceil(peers_per_round);
        let rounds_per_sweep = u32::try_from(rounds_per_sweep).unwrap_or(u32::MAX);
        let retained_rounds = u32::try_from(self.params.per_peer_buffer.max(1)).unwrap_or(u32::MAX);
        self.params
            .sample_interval
            .saturating_mul(rounds_per_sweep)
            .saturating_mul(retained_rounds)
            .saturating_add(self.probe_timeout())
    }
    fn deadline_after(now: Instant, duration: std::time::Duration) -> Instant {
        // An unrepresentable deadline must not turn into unbounded state retention.
        now.checked_add(duration).unwrap_or(now)
    }
    fn probe_deadline(&self, sent_at: Instant) -> Instant {
        Self::deadline_after(sent_at, self.probe_timeout())
    }
    fn sample_deadline(&self, freshness_base: Instant) -> Instant {
        Self::deadline_after(freshness_base, self.sample_freshness_window())
    }
    fn prune_expired(&mut self, now: Instant) {
        self.outstanding.retain(|_, probe| probe.expires_at > now);

        // A contributing sample expiry is an aggregate event just like a new
        // measurement. Replay those events at their protocol deadlines so the
        // slew result does not depend on when an API reader happens to notice
        // the expiry. Sample deadlines are monotonic within each peer ring, so
        // only the latest sample can contribute an aggregate transition.
        let aggregate_deadlines = self
            .per_peer
            .values()
            .filter_map(|samples| samples.back())
            .filter(|sample| sample.expires_at <= now)
            .map(|sample| sample.expires_at)
            .collect::<Vec<_>>();
        for deadline in bounded_expiry_replay_deadlines(aggregate_deadlines, now) {
            let mut aggregate_changed = false;
            self.per_peer.retain(|_, samples| {
                let latest_before = samples.back().copied();
                samples.retain(|sample| sample.expires_at > deadline);
                aggregate_changed |= samples.back().copied() != latest_before;
                !samples.is_empty()
            });
            if aggregate_changed {
                self.aggregate_dirty = true;
                self.refresh_smoothing(deadline);
            }
        }

        // Historical entries never affect the aggregate, but still need to be
        // discarded even when their peer's latest sample remains live.
        self.per_peer.retain(|_, samples| {
            samples.retain(|sample| sample.expires_at > now);
            !samples.is_empty()
        });
    }
    fn take_live_probe(
        &mut self,
        peer: &iroha_model_base::peer::PeerId,
        id: u64,
        received_at: Instant,
    ) -> Option<OutstandingProbe> {
        self.prune_expired(received_at);
        self.outstanding.remove(&(peer.clone(), id))
    }
    fn insert_outstanding_probe(
        &mut self,
        peer: iroha_model_base::peer::PeerId,
        id: u64,
        probe: OutstandingProbe,
    ) -> bool {
        // At most one unanswered probe per configured peer. Do not replace a
        // live request: configurations whose interval is shorter than their RTT
        // still need to leave one full reply window for that peer.
        if self
            .outstanding
            .range((peer.clone(), u64::MIN)..=(peer.clone(), u64::MAX))
            .next()
            .is_some()
        {
            return false;
        }
        self.outstanding.insert((peer, id), probe);
        true
    }
    #[cfg(test)]
    fn debug_snapshot(&mut self, now: Instant) -> Vec<(String, i64, u64, usize)> {
        self.with_reconciled_network_membership(now, |service| {
            service.debug_snapshot_reconciled(now)
        })
    }
    fn debug_snapshot_reconciled(&mut self, now: Instant) -> Vec<(String, i64, u64, usize)> {
        self.prune_expired(now);
        self.per_peer
            .iter()
            .filter_map(|(pid, samples)| {
                samples
                    .back()
                    .map(|last| (pid.to_string(), last.offset_ms, last.rtt_ms, samples.len()))
            })
            .collect()
    }
    fn record_sample(&mut self, peer: iroha_model_base::peer::PeerId, sample: Sample) {
        let cap = self.params.per_peer_buffer.max(1);
        let samples = self.per_peer.entry(peer).or_default();
        while samples.len() >= cap {
            let _ = samples.pop_front();
        }
        samples.push_back(sample);
        self.aggregate_dirty = true;
    }
    fn observe_rtt(&mut self, rtt_ms: u64) {
        for (bound, count) in self
            .rtt_bounds_ms
            .iter()
            .zip(self.rtt_bucket_counts.iter_mut())
        {
            if rtt_ms <= *bound {
                *count = count.saturating_add(1);
            }
        }
        self.rtt_ms_sum = self.rtt_ms_sum.saturating_add(rtt_ms);
        self.rtt_ms_count = self.rtt_ms_count.saturating_add(1);
    }
    fn record_measurement(
        &mut self,
        peer: iroha_model_base::peer::PeerId,
        offset_ms: i64,
        rtt_ms: u64,
        probe_sent_at: Instant,
        received_at: Instant,
    ) -> bool {
        self.observe_rtt(rtt_ms);
        if rtt_ms > self.params.max_rtt_ms {
            return false;
        }
        if self
            .per_peer
            .get(&peer)
            .and_then(|samples| samples.back())
            .is_some_and(|latest| latest.probe_sent_at >= probe_sent_at)
        {
            // Relay tasks can finish out of order. Never let an older or
            // duplicate reply replace a newer sample from the same peer.
            return false;
        }
        let freshness_base = self
            .per_peer
            .get(&peer)
            .and_then(|samples| samples.back())
            .map_or(received_at, |latest| latest.received_at.max(received_at));
        self.record_sample(
            peer,
            Sample {
                offset_ms,
                rtt_ms,
                probe_sent_at,
                received_at,
                expires_at: self.sample_deadline(freshness_base),
            },
        );
        self.refresh_smoothing(freshness_base);
        true
    }
    #[allow(clippy::cast_precision_loss, clippy::suboptimal_flops)]
    fn apply_smoothing_step(&mut self, median: i64, observed_at: Instant) {
        let prev = self.smoothed_offset_ms;
        let alpha = if self.params.smoothing_alpha.is_finite() {
            self.params.smoothing_alpha.clamp(0.0, 1.0)
        } else {
            Params::default().smoothing_alpha
        };
        let ema_next = alpha.mul_add(median as f64, (1.0 - alpha) * prev);
        let elapsed_min = observed_at
            .saturating_duration_since(self.last_smooth_update)
            .as_secs_f64()
            / 60.0;
        let max_delta = (self.params.max_adjust_ms_per_min as f64) * elapsed_min;
        self.smoothed_offset_ms += (ema_next - prev).clamp(-max_delta, max_delta);
        if observed_at > self.last_smooth_update {
            self.last_smooth_update = observed_at;
        }
    }
    fn raw_aggregate(&self) -> Option<(i64, u64, usize)> {
        let mut offsets = self
            .per_peer
            .values()
            .filter_map(|samples| samples.back())
            .filter(|sample| sample.rtt_ms <= self.params.max_rtt_ms)
            .map(|sample| sample.offset_ms)
            .collect::<Vec<_>>();
        let sample_count = offsets.len();
        (!offsets.is_empty()).then(|| {
            let (median, mad) = trimmed_median_and_mad(&mut offsets, self.params.trim_percent);
            (median, mad, sample_count)
        })
    }
    #[allow(clippy::cast_possible_truncation)]
    fn applied_offset(
        &mut self,
        median: i64,
        mad: u64,
        sample_count: usize,
        observed_at: Instant,
    ) -> (i64, NtsHealth) {
        let raw_health = self
            .params
            .health_policy
            .evaluate(sample_count, median, mad, false);
        if self.aggregate_dirty {
            if self.params.smoothing_enabled && raw_health.healthy {
                self.apply_smoothing_step(median, observed_at);
            }
            self.aggregate_dirty = false;
        }
        let offset = if self.params.smoothing_enabled && raw_health.healthy {
            self.smoothed_offset_ms.round() as i64
        } else {
            median
        };
        (offset, raw_health)
    }
    fn refresh_smoothing(&mut self, observed_at: Instant) {
        if let Some((median, mad, sample_count)) = self.raw_aggregate() {
            let _ = self.applied_offset(median, mad, sample_count, observed_at);
        } else {
            self.aggregate_dirty = false;
        }
    }
}
fn claim_service<'a>(
    cell: &'a OnceLock<Mutex<Service>>,
    state: &AtomicU8,
    params: Params,
) -> Option<&'a Mutex<Service>> {
    state
        .compare_exchange(
            SAMPLER_STOPPED,
            SAMPLER_RESERVED,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .ok()?;
    let service = cell.get_or_init(|| Mutex::new(Service::new(params)));
    lock_service(service).reset(params);
    Some(service)
}
fn release_service(cell: &OnceLock<Mutex<Service>>, state: &AtomicU8) {
    // STOPPING is not claimable and is not considered active by readers. It
    // closes the gap between invalidating old samples and permitting restart.
    state.store(SAMPLER_STOPPING, Ordering::Release);
    if let Some(service) = cell.get() {
        let mut service = lock_service(service);
        let params = service.params;
        service.reset(params);
    }
    // Clear the service before making the singleton claim available. A new
    // sampler can therefore never have its freshly reset state erased by the
    // previous sampler's shutdown path.
    state.store(SAMPLER_STOPPED, Ordering::Release);
}
struct SamplerOwnership {
    service: &'static OnceLock<Mutex<Service>>,
    state: &'static AtomicU8,
}
impl Drop for SamplerOwnership {
    fn drop(&mut self) {
        release_service(self.service, self.state);
    }
}
fn sampler_interval(period: std::time::Duration) -> tokio::time::Interval {
    let mut ticker = tokio::time::interval(period);
    // Replaying missed rounds creates a burst of probes whose cardinality is
    // unrelated to the configured sampling rate and RTT lifetime.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    ticker
}
static SERVICE: OnceLock<Mutex<Service>> = OnceLock::new();
const SAMPLER_STOPPED: u8 = 0;
const SAMPLER_RESERVED: u8 = 1;
const SAMPLER_RUNNING: u8 = 2;
const SAMPLER_STOPPING: u8 = 3;
static SAMPLER_STATE: AtomicU8 = AtomicU8::new(SAMPLER_STOPPED);
static PARAMS_SNAPSHOT: OnceLock<RwLock<ParamsSnapshot>> = OnceLock::new();
#[derive(Clone, Copy, Debug)]
struct ParamsSnapshot {
    enforcement_mode: NtsEnforcementMode,
    health_policy: NtsHealthPolicy,
}
fn params_snapshot_store() -> &'static RwLock<ParamsSnapshot> {
    PARAMS_SNAPSHOT.get_or_init(|| {
        RwLock::new(ParamsSnapshot {
            enforcement_mode: NtsEnforcementMode::Warn,
            health_policy: NtsHealthPolicy::default(),
        })
    })
}
fn params_snapshot() -> ParamsSnapshot {
    params_snapshot_store()
        .read()
        .map_or_else(|err| *err.into_inner(), |guard| *guard)
}
fn claim_service_with_policy<'a>(
    cell: &'a OnceLock<Mutex<Service>>,
    state: &AtomicU8,
    policy_store: &RwLock<ParamsSnapshot>,
    params: Params,
) -> Option<&'a Mutex<Service>> {
    // Hold the policy writer across the state transition. A reader that sees
    // RESERVED/STOPPED must therefore observe either the complete old
    // generation or the complete newly claimed generation, never a mixture.
    let mut policy = policy_store
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let service = claim_service(cell, state, params)?;
    *policy = ParamsSnapshot {
        enforcement_mode: params.enforcement_mode,
        health_policy: params.health_policy,
    };
    Some(service)
}
fn configure_policy_if_stopped(
    state: &AtomicU8,
    policy_store: &RwLock<ParamsSnapshot>,
    params: Params,
) -> bool {
    let snapshot = ParamsSnapshot {
        enforcement_mode: params.enforcement_mode,
        health_policy: params.health_policy,
    };
    let mut guard = policy_store
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if state.load(Ordering::Acquire) != SAMPLER_STOPPED {
        return false;
    }
    *guard = snapshot;
    true
}
/// Configure the NTS admission policy snapshot used before the service starts.
///
/// Returns `false` when a sampler reservation already owns the process-local
/// service. This prevents a fallback-only startup from overwriting the active
/// sampler generation's admission policy.
pub fn configure(params: Params) -> bool {
    configure_policy_if_stopped(&SAMPLER_STATE, params_snapshot_store(), params)
}
fn lock_service(mutex: &Mutex<Service>) -> MutexGuard<'_, Service> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
struct MonotonicSystemClock {
    monotonic_anchor: Instant,
    system_anchor: SystemTime,
    continuous_anchor: Option<(NativeContinuousReading, Duration)>,
    last_elapsed: Duration,
}
impl MonotonicSystemClock {
    fn new() -> Self {
        let monotonic_before = Instant::now();
        let continuous_before = NativeContinuousReading::now().ok();
        let system_anchor = SystemTime::now();
        let continuous_after = NativeContinuousReading::now().ok();
        let monotonic_after = Instant::now();
        let mut clock = Self::from_bracket(monotonic_before, system_anchor, monotonic_after);
        clock.continuous_anchor =
            continuous_before
                .zip(continuous_after)
                .and_then(|(before, after)| {
                    after
                        .elapsed_since(&before)
                        .ok()
                        .map(|bracket| (before, bracket / 2))
                });
        clock
    }
    fn from_bracket(
        monotonic_before: Instant,
        system_anchor: SystemTime,
        monotonic_after: Instant,
    ) -> Self {
        let bracket = monotonic_after.saturating_duration_since(monotonic_before);
        let monotonic_anchor = monotonic_before
            .checked_add(bracket / 2)
            .unwrap_or(monotonic_before);
        Self {
            monotonic_anchor,
            system_anchor,
            continuous_anchor: None,
            last_elapsed: Duration::ZERO,
        }
    }
    fn sample(&mut self) -> LocalClockSample {
        let continuous_elapsed = self.continuous_anchor.and_then(|(anchor, midpoint)| {
            NativeContinuousReading::now()
                .ok()?
                .elapsed_since(&anchor)
                .ok()?
                .checked_sub(midpoint)
        });
        let monotonic_elapsed = Instant::now().saturating_duration_since(self.monotonic_anchor);
        self.sample_elapsed(monotonic_elapsed, continuous_elapsed)
    }
    #[cfg(test)]
    fn at(mut self, now: Instant) -> SystemTime {
        self.sample_elapsed(now.saturating_duration_since(self.monotonic_anchor), None)
            .local_now
    }
    fn sample_elapsed(
        &mut self,
        monotonic_elapsed: Duration,
        continuous_elapsed: Option<Duration>,
    ) -> LocalClockSample {
        let continuous_elapsed = if cfg!(all(test, sumeragi_core_mutation = "HC53")) {
            None
        } else {
            continuous_elapsed
        };
        // The native elapsed source includes host suspension without consulting
        // mutable wall time again. Keep probe deadlines and Unix timestamps on
        // this same timeline; Instant alone pauses on supported Apple hosts.
        let continuous_elapsed = continuous_elapsed.filter(|elapsed| *elapsed >= self.last_elapsed);
        let elapsed =
            continuous_elapsed.unwrap_or_else(|| monotonic_elapsed.max(self.last_elapsed));
        let pair = self
            .monotonic_anchor
            .checked_add(elapsed)
            .zip(self.system_anchor.checked_add(elapsed));
        let (observed_at, local_now, suspend_inclusive) =
            if let Some((observed_at, local_now)) = pair {
                self.last_elapsed = elapsed;
                (observed_at, local_now, continuous_elapsed.is_some())
            } else {
                // Retain the last representable point and mark the clock unhealthy.
                // A clock read, regression or overflow must never authenticate NTS.
                (
                    self.monotonic_anchor
                        .checked_add(self.last_elapsed)
                        .unwrap_or(self.monotonic_anchor),
                    self.system_anchor
                        .checked_add(self.last_elapsed)
                        .unwrap_or(self.system_anchor),
                    false,
                )
            };
        LocalClockSample {
            observed_at,
            local_now,
            suspend_inclusive,
        }
    }
}
struct LocalClockSample {
    observed_at: Instant,
    local_now: SystemTime,
    suspend_inclusive: bool,
}
static LOCAL_CLOCK: OnceLock<Mutex<MonotonicSystemClock>> = OnceLock::new();
static LAST_NETWORK_TIME: OnceLock<Mutex<Option<SystemTime>>> = OnceLock::new();
fn local_clock_sample() -> LocalClockSample {
    let mut clock = LOCAL_CLOCK
        .get_or_init(|| Mutex::new(MonotonicSystemClock::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    clock.sample()
}
fn epoch_ms(time: SystemTime) -> u64 {
    use std::time::UNIX_EPOCH;
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(0)
}
fn clamp_monotonic_output(floor: &Mutex<Option<SystemTime>>, candidate: SystemTime) -> SystemTime {
    let mut floor = floor
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match *floor {
        Some(previous) if previous > candidate => previous,
        _ => {
            *floor = Some(candidate);
            candidate
        }
    }
}
fn signed_offset_ms(time: SystemTime, local_time: SystemTime) -> i64 {
    match time.duration_since(local_time) {
        Ok(offset) => i64::try_from(offset.as_millis()).unwrap_or(i64::MAX),
        Err(error) => {
            i64::try_from(error.duration().as_millis()).map_or(i64::MIN, |offset| -offset)
        }
    }
}
fn finalize_status_time_with_floor(
    mut status: NetworkTimeStatus,
    local_now: SystemTime,
    policy: NtsHealthPolicy,
    floor: &Mutex<Option<SystemTime>>,
) -> NetworkTimeStatus {
    let candidate = status.now;
    status.now = clamp_monotonic_output(floor, candidate);
    if status.now != candidate {
        status.offset_ms = signed_offset_ms(status.now, local_now);
        let effective_health = policy.evaluate(
            status.sample_count,
            status.offset_ms,
            status.confidence_ms,
            false,
        );
        status.fallback |= !effective_health.healthy;
        status.health = policy.evaluate(
            status.sample_count,
            status.offset_ms,
            status.confidence_ms,
            status.fallback,
        );
    }
    status
}
fn finalize_status_time(
    status: NetworkTimeStatus,
    local_now: SystemTime,
    policy: NtsHealthPolicy,
) -> NetworkTimeStatus {
    finalize_status_time_with_floor(
        status,
        local_now,
        policy,
        LAST_NETWORK_TIME.get_or_init(|| Mutex::new(None)),
    )
}
/// Exclusive, drop-safe reservation for the process-local NTS sampler.
///
/// Reserve this before starting fallible daemon subsystems, then pass it to
/// [`start_reserved`]. Dropping an unused reservation releases the singleton
/// and clears its service state.
#[must_use = "an unused sampler reservation is released immediately"]
pub struct SamplerReservation {
    service: &'static Mutex<Service>,
    params: Params,
    ownership: SamplerOwnership,
}
/// Reserve and initialize the process-local NTS service without spawning it.
///
/// Returns `None` when another reservation or sampler already owns the service.
pub fn reserve(params: Params) -> Option<SamplerReservation> {
    let params = params.normalized();
    let service =
        claim_service_with_policy(&SERVICE, &SAMPLER_STATE, params_snapshot_store(), params)?;
    let ownership = SamplerOwnership {
        service: &SERVICE,
        state: &SAMPLER_STATE,
    };
    Some(SamplerReservation {
        service,
        params,
        ownership,
    })
}
/// Start the NTS background sampler and return its supervised task.
///
/// Returns `None` when this process already owns the singleton sampler.
pub fn start(
    network: IrohaNetwork,
    params: Params,
    shutdown_signal: ShutdownSignal,
) -> Option<Child> {
    let reservation = reserve(params)?;
    Some(start_reserved(network, reservation, shutdown_signal))
}
/// Hold a sampler reservation for a fallback-only daemon until shutdown.
///
/// The service remains stopped, so every status is an unhealthy local-clock
/// fallback, while the reservation prevents another in-process daemon startup
/// from replacing its admission policy.
pub fn hold_fallback_reserved(
    reservation: SamplerReservation,
    shutdown_signal: ShutdownSignal,
) -> Child {
    let task = tokio::task::spawn(async move {
        let _reservation = reservation;
        shutdown_signal.receive().await;
    });
    Child::new(task, OnShutdown::Wait(Duration::from_secs(1)))
}
/// Spawn a previously reserved NTS sampler and return its supervised task.
pub fn start_reserved(
    network: IrohaNetwork,
    reservation: SamplerReservation,
    shutdown_signal: ShutdownSignal,
) -> Child {
    let SamplerReservation {
        service: guard,
        params,
        ownership,
    } = reservation;
    lock_service(guard).attach_network(network.clone(), local_clock_sample().observed_at);
    SAMPLER_STATE.store(SAMPLER_RUNNING, Ordering::Release);
    // Ownership was constructed before spawning. If the task is aborted before
    // its first poll (or spawning unwinds), dropping the captured guard still
    // releases the singleton and invalidates its samples.
    let task = tokio::task::spawn(async move {
        let _ownership = ownership;
        let mut ticker = sampler_interval(params.sample_interval);
        let mut peer_start_index = 0usize;
        loop {
            tokio::select! {
                () = shutdown_signal.receive() => break,
                _ = ticker.tick() => {}
            }
            // Every probe has a protocol RTT deadline. Expire unanswered work even
            // when no configured target is currently reachable; otherwise rotating or
            // disconnected peers retain their identity and request record indefinitely.
            {
                let mut svc = lock_service(guard);
                let observed_at = local_clock_sample().observed_at;
                let _ = svc.reconcile_network_membership(observed_at);
                svc.prune_expired(observed_at);
            }
            // Limit per-interval probes to avoid flooding
            let max_per_round = params.sample_cap_per_round;
            // Keep transient memory proportional to the round cap while rotating
            // through the complete, canonically ordered peer-id space. Taking a
            // `HashSet` prefix every round permanently starved the other peers.
            let batch = network.configured_peer_ids_bounded(peer_start_index, max_per_round);
            peer_start_index = batch.next_start_index;
            let batch_generation = batch.generation;
            for pid in batch.peer_ids {
                let probe = {
                    let mut svc = lock_service(guard);
                    let observed_at = local_clock_sample().observed_at;
                    svc.with_reconciled_network_membership(observed_at, |service| {
                        if service.configured_peer_generation != Some(batch_generation) {
                            return None;
                        }
                        let sample = local_clock_sample();
                        let sent_at = sample.observed_at;
                        service.prune_expired(sent_at);
                        if !sample.suspend_inclusive {
                            return Some(None);
                        }
                        let t1 = epoch_ms(sample.local_now);
                        let id = service.id_counter;
                        let expires_at = service.probe_deadline(sent_at);
                        if !service.insert_outstanding_probe(
                            pid.clone(),
                            id,
                            OutstandingProbe {
                                t1_ms: t1,
                                sent_at,
                                expires_at,
                            },
                        ) {
                            return Some(None);
                        }
                        service.id_counter = service.id_counter.wrapping_add(1).max(1);
                        Some(Some((id, t1)))
                    })
                };
                let (id, t1_ms) = match probe {
                    None => break,
                    Some(None) => continue,
                    Some(Some(probe)) => probe,
                };
                let ping = crate::NetworkMessage::TimePing(Box::new(TimePing { id, t1_ms }));
                network.post(iroha_p2p::Post {
                    data: ping,
                    peer_id: pid,
                    priority: iroha_p2p::Priority::Low,
                });
            }
        }
    });
    Child::new(task, OnShutdown::Wait(Duration::from_secs(1)))
}
/// Whether the process-local NTS sampler is currently running.
pub fn is_running() -> bool {
    SAMPLER_STATE.load(Ordering::Acquire) == SAMPLER_RUNNING
}
fn sample_measurement(
    t1_ms: u64,
    t2_ms: u64,
    t3_ms: u64,
    t4_ms: u64,
    local_elapsed_ms: u64,
) -> Option<(i64, u64)> {
    let remote_processing_ms = t3_ms.checked_sub(t2_ms)?;
    let t1 = i128::from(t1_ms);
    let t2 = i128::from(t2_ms);
    let t3 = i128::from(t3_ms);
    let t4 = i128::from(t4_ms);
    let offset_ms = i64::try_from(i128::midpoint(t2 - t1, t3 - t4)).ok()?;
    let rtt_ms = local_elapsed_ms.checked_sub(remote_processing_ms)?;
    Some((offset_ms, rtt_ms))
}
/// Handle incoming time messages from the network relay.
pub fn handle_message(peer: Peer, msg: crate::NetworkMessage, network: &IrohaNetwork) {
    match msg {
        crate::NetworkMessage::TimePing(p) => {
            let arrival = local_clock_sample();
            let reply = local_clock_sample();
            if !arrival.suspend_inclusive || !reply.suspend_inclusive {
                return;
            }
            let t2 = epoch_ms(arrival.local_now);
            let pong = TimePong {
                id: p.id,
                t2_ms: t2,
                t3_ms: epoch_ms(reply.local_now),
            };
            network.post(iroha_p2p::Post {
                data: crate::NetworkMessage::TimePong(Box::new(pong)),
                peer_id: peer.id().clone(),
                priority: iroha_p2p::Priority::Low,
            });
        }
        crate::NetworkMessage::TimePong(p) => {
            if !is_running() {
                return;
            }
            let sample = local_clock_sample();
            if !sample.suspend_inclusive {
                return;
            }
            let received_at = sample.observed_at;
            let t4 = epoch_ms(sample.local_now);
            let pid = peer.id().clone();
            let Some(service) = SERVICE.get() else {
                return;
            };
            let mut svc = lock_service(service);
            if !is_running() {
                return;
            }
            svc.with_reconciled_network_membership(received_at, |service| {
                // A late pong cannot be correlated with a live probe. Pruning before
                // removal enforces the same deadline whether or not the sampler ticked.
                let Some(probe) = service.take_live_probe(&pid, p.id, received_at) else {
                    return;
                };
                let local_elapsed_ms = received_at
                    .saturating_duration_since(probe.sent_at)
                    .as_millis()
                    .try_into()
                    .unwrap_or(u64::MAX);
                let Some((offset_ms, rtt_ms)) =
                    sample_measurement(probe.t1_ms, p.t2_ms, p.t3_ms, t4, local_elapsed_ms)
                else {
                    return;
                };
                let _accepted =
                    service.record_measurement(pid, offset_ms, rtt_ms, probe.sent_at, received_at);
            });
        }
        _ => {}
    }
}
/// Compute a network-time snapshot from the current service state.
#[allow(
    clippy::cast_precision_loss,
    clippy::suboptimal_flops,
    clippy::cast_possible_truncation
)]
fn status_from_service(
    svc: &mut Service,
    observed_at: Instant,
    local_now: SystemTime,
) -> NetworkTimeStatus {
    svc.with_reconciled_network_membership(observed_at, |service| {
        status_from_reconciled_service(service, observed_at, local_now)
    })
}
fn status_from_clock(svc: &mut Service, sample: &LocalClockSample) -> NetworkTimeStatus {
    if sample.suspend_inclusive {
        status_from_service(svc, sample.observed_at, sample.local_now)
    } else {
        svc.with_reconciled_network_membership(sample.observed_at, |service| {
            service.prune_expired(sample.observed_at);
            fallback_status_with_policy(sample.local_now, service.params.health_policy)
        })
    }
}
fn status_from_reconciled_service(
    svc: &mut Service,
    observed_at: Instant,
    local_now: SystemTime,
) -> NetworkTimeStatus {
    svc.prune_expired(observed_at);
    let peer_count = svc.per_peer.len();
    let Some((median, mad, sample_count)) = svc.raw_aggregate() else {
        svc.aggregate_dirty = false;
        let fallback = true;
        return NetworkTimeStatus {
            now: local_now,
            offset_ms: 0,
            confidence_ms: 0,
            sample_count: 0,
            peer_count,
            fallback,
            health: svc.params.health_policy.evaluate(0, 0, 0, fallback),
        };
    };
    // Never initialize or advance smoothing from an unhealthy raw aggregate.
    // Otherwise a single pre-quorum or wildly skewed sample can poison the
    // applied offset long after a healthy quorum appears.
    let (offset, raw_health) = svc.applied_offset(median, mad, sample_count, observed_at);
    let adjusted_now = if offset >= 0 {
        local_now.checked_add(Duration::from_millis(offset.unsigned_abs()))
    } else {
        local_now.checked_sub(Duration::from_millis(offset.unsigned_abs()))
    };
    let applied_health = svc
        .params
        .health_policy
        .evaluate(sample_count, offset, mad, false);
    let fallback = !raw_health.healthy || !applied_health.healthy || adjusted_now.is_none();
    let health = svc
        .params
        .health_policy
        .evaluate(sample_count, offset, mad, fallback);
    NetworkTimeStatus {
        now: adjusted_now.filter(|_| !fallback).unwrap_or(local_now),
        offset_ms: offset,
        confidence_ms: mad,
        sample_count,
        peer_count,
        fallback,
        health,
    }
}
/// Compute current network time status using a trimmed median.
pub fn now() -> NetworkTimeStatus {
    admission_snapshot().status
}
/// Capture network time and its admission policy from one service generation.
pub fn admission_snapshot() -> NetworkTimeAdmissionSnapshot {
    if !is_running() {
        let params = params_snapshot();
        let local_now = local_clock_sample().local_now;
        return NetworkTimeAdmissionSnapshot {
            status: finalize_status_time(
                fallback_status_with_policy(local_now, params.health_policy),
                local_now,
                params.health_policy,
            ),
            enforcement_mode: params.enforcement_mode,
        };
    }
    let Some(svc_lock) = SERVICE.get() else {
        let params = params_snapshot();
        let local_now = local_clock_sample().local_now;
        return NetworkTimeAdmissionSnapshot {
            status: finalize_status_time(
                fallback_status_with_policy(local_now, params.health_policy),
                local_now,
                params.health_policy,
            ),
            enforcement_mode: params.enforcement_mode,
        };
    };
    let mut service = lock_service(svc_lock);
    if !is_running() {
        // Reservation publishes policy while holding policy -> service locks.
        // Release the service first to preserve that global lock order.
        drop(service);
        let params = params_snapshot();
        let local_now = local_clock_sample().local_now;
        return NetworkTimeAdmissionSnapshot {
            status: finalize_status_time(
                fallback_status_with_policy(local_now, params.health_policy),
                local_now,
                params.health_policy,
            ),
            enforcement_mode: params.enforcement_mode,
        };
    }
    let enforcement_mode = service.params.enforcement_mode;
    let health_policy = service.params.health_policy;
    let sample = local_clock_sample();
    let local_now = sample.local_now;
    NetworkTimeAdmissionSnapshot {
        status: finalize_status_time(
            status_from_clock(&mut service, &sample),
            local_now,
            health_policy,
        ),
        enforcement_mode,
    }
}
fn fallback_status_with_policy(
    local_now: SystemTime,
    policy: NtsHealthPolicy,
) -> NetworkTimeStatus {
    let fallback = true;
    NetworkTimeStatus {
        now: local_now,
        offset_ms: 0,
        confidence_ms: 0,
        sample_count: 0,
        peer_count: 0,
        fallback,
        health: policy.evaluate(0, 0, 0, fallback),
    }
}
/// Compute a trimmed median and MAD (median absolute deviation) from a list of offsets.
/// Mutates the input vector by sorting it.
fn trimmed_median_and_mad(offsets: &mut [i64], trim_percent: u8) -> (i64, u64) {
    if offsets.is_empty() {
        return (0, 0);
    }
    offsets.sort_unstable();
    let n = offsets.len();
    let tp = usize::from(trim_percent.min(45));
    let trim = (n * tp) / 100; // symmetric trim, integer math
    let hi = (n - trim).max(trim + 1);
    let slice = &offsets[trim..hi];
    let median = slice[slice.len() / 2];
    let mut devs: Vec<u64> = slice.iter().map(|&x| x.abs_diff(median)).collect();
    devs.sort_unstable();
    let mad = devs[devs.len() / 2];
    (median, mad)
}
#[cfg(test)]
/// Debug snapshot of per-peer samples for diagnostics endpoints.
pub fn debug_snapshot() -> Vec<(String, i64, u64, usize)> {
    if !is_running() {
        return Vec::new();
    }
    let Some(svc_lock) = SERVICE.get() else {
        return Vec::new();
    };
    let mut svc = lock_service(svc_lock);
    if !is_running() {
        return Vec::new();
    }
    let sample = local_clock_sample();
    if !sample.suspend_inclusive {
        return Vec::new();
    }
    svc.debug_snapshot(sample.observed_at)
}
/// Atomic snapshot of NTS RTT histogram counters.
#[derive(Clone, Debug)]
pub struct RttSnapshot {
    /// Inclusive upper bound of every cumulative bucket, in milliseconds.
    pub bounds_ms: &'static [u64],
    /// Cumulative observation count corresponding to each bucket bound.
    pub bucket_counts: Vec<u64>,
    /// Saturating sum of all observed RTT values, in milliseconds.
    pub sum_ms: u64,
    /// Saturating count of all observed RTT values.
    pub count: u64,
}
/// One internally consistent operator snapshot of the network time service.
#[derive(Clone, Debug)]
pub struct NetworkTimeDiagnostics {
    /// Current network-time estimate and health evaluation.
    pub status: NetworkTimeStatus,
    /// Latest retained sample for every contributing peer.
    pub samples: Vec<(String, i64, u64, usize)>,
    /// RTT histogram captured under the same service lock.
    pub rtt: RttSnapshot,
    /// Admission policy active for time-sensitive transactions.
    pub enforcement_mode: NtsEnforcementMode,
    /// Whether the background sampler owned the service at capture time.
    pub running: bool,
}
/// Status and RTT counters captured from one service generation.
#[derive(Clone, Debug)]
pub struct NetworkTimeTelemetrySnapshot {
    /// Current network-time estimate and health evaluation.
    pub status: NetworkTimeStatus,
    /// RTT histogram captured under the same service lock.
    pub rtt: RttSnapshot,
}
/// Return one internally consistent RTT histogram snapshot.
pub fn rtt_snapshot() -> RttSnapshot {
    if is_running()
        && let Some(lock) = SERVICE.get()
    {
        let svc = lock_service(lock);
        if is_running() {
            return RttSnapshot {
                bounds_ms: svc.rtt_bounds_ms,
                bucket_counts: svc.rtt_bucket_counts.clone(),
                sum_ms: svc.rtt_ms_sum,
                count: svc.rtt_ms_count,
            };
        }
    }
    RttSnapshot {
        bounds_ms: RTT_BUCKET_BOUNDS_MS,
        bucket_counts: vec![0; RTT_BUCKET_BOUNDS_MS.len()],
        sum_ms: 0,
        count: 0,
    }
}
/// Return one atomic status and RTT snapshot for telemetry collection.
pub fn telemetry_snapshot() -> NetworkTimeTelemetrySnapshot {
    if is_running()
        && let Some(lock) = SERVICE.get()
    {
        let mut svc = lock_service(lock);
        if is_running() {
            let sample = local_clock_sample();
            let local_now = sample.local_now;
            let health_policy = svc.params.health_policy;
            let status = finalize_status_time(
                status_from_clock(&mut svc, &sample),
                local_now,
                health_policy,
            );
            return NetworkTimeTelemetrySnapshot {
                status,
                rtt: RttSnapshot {
                    bounds_ms: svc.rtt_bounds_ms,
                    bucket_counts: svc.rtt_bucket_counts.clone(),
                    sum_ms: svc.rtt_ms_sum,
                    count: svc.rtt_ms_count,
                },
            };
        }
    }
    let params = params_snapshot();
    let local_now = local_clock_sample().local_now;
    NetworkTimeTelemetrySnapshot {
        status: finalize_status_time(
            fallback_status_with_policy(local_now, params.health_policy),
            local_now,
            params.health_policy,
        ),
        rtt: RttSnapshot {
            bounds_ms: RTT_BUCKET_BOUNDS_MS,
            bucket_counts: vec![0; RTT_BUCKET_BOUNDS_MS.len()],
            sum_ms: 0,
            count: 0,
        },
    }
}
/// Return one atomic status, peer-sample, policy, and RTT snapshot.
pub fn diagnostics_snapshot() -> NetworkTimeDiagnostics {
    if is_running()
        && let Some(lock) = SERVICE.get()
    {
        let mut svc = lock_service(lock);
        if is_running() {
            let sample = local_clock_sample();
            let local_now = sample.local_now;
            let observed_at = sample.observed_at;
            let (status, samples) =
                svc.with_reconciled_network_membership(observed_at, |service| {
                    if !sample.suspend_inclusive {
                        service.prune_expired(observed_at);
                        return (
                            fallback_status_with_policy(local_now, service.params.health_policy),
                            Vec::new(),
                        );
                    }
                    let status = status_from_reconciled_service(service, observed_at, local_now);
                    let samples = service.debug_snapshot_reconciled(observed_at);
                    (status, samples)
                });
            let status = finalize_status_time(status, local_now, svc.params.health_policy);
            let rtt = RttSnapshot {
                bounds_ms: svc.rtt_bounds_ms,
                bucket_counts: svc.rtt_bucket_counts.clone(),
                sum_ms: svc.rtt_ms_sum,
                count: svc.rtt_ms_count,
            };
            return NetworkTimeDiagnostics {
                status,
                samples,
                rtt,
                enforcement_mode: svc.params.enforcement_mode,
                running: true,
            };
        }
    }
    let params = params_snapshot();
    let local_now = local_clock_sample().local_now;
    NetworkTimeDiagnostics {
        status: finalize_status_time(
            fallback_status_with_policy(local_now, params.health_policy),
            local_now,
            params.health_policy,
        ),
        samples: Vec::new(),
        rtt: RttSnapshot {
            bounds_ms: RTT_BUCKET_BOUNDS_MS,
            bucket_counts: vec![0; RTT_BUCKET_BOUNDS_MS.len()],
            sum_ms: 0,
            count: 0,
        },
        enforcement_mode: params.enforcement_mode,
        running: false,
    }
}
/// RTT histogram counts per bucket.
pub fn rtt_bucket_counts() -> Vec<u64> {
    rtt_snapshot().bucket_counts
}
/// RTT histogram sum of observed RTTs in ms.
pub fn rtt_ms_sum() -> u64 {
    rtt_snapshot().sum_ms
}
/// RTT histogram count of observations.
pub fn rtt_ms_count() -> u64 {
    rtt_snapshot().count
}
/// Current NTS enforcement mode for time-sensitive admission.
pub fn enforcement_mode() -> NtsEnforcementMode {
    if is_running()
        && let Some(lock) = SERVICE.get()
    {
        let svc = lock_service(lock);
        if is_running() {
            return svc.params.enforcement_mode;
        }
    }
    params_snapshot().enforcement_mode
}
#[cfg(test)]
mod tests {
    use super::*;
    fn service_for_tests(params: Params) -> Service {
        let mut service = Service::new(params);
        // These pure fixtures supply their own Instant timeline. It must not
        // inherit suspension accumulated by the process-wide native clock.
        service.last_smooth_update = Instant::now();
        service
    }
    fn test_peer_id() -> iroha_model_base::peer::PeerId {
        let key_pair =
            iroha_crypto::KeyPair::try_random_with_algorithm(iroha_crypto::Algorithm::Ed25519)
                .expect("generate test peer key");
        iroha_model_base::peer::PeerId::new(key_pair.public_key().clone())
    }
    fn insert_sample(
        svc: &mut Service,
        peer: iroha_model_base::peer::PeerId,
        received_at: Instant,
    ) {
        insert_sample_with(svc, peer, received_at, 0, 1);
    }
    fn insert_sample_with(
        svc: &mut Service,
        peer: iroha_model_base::peer::PeerId,
        received_at: Instant,
        offset_ms: i64,
        rtt_ms: u64,
    ) {
        let expires_at = svc.sample_deadline(received_at);
        svc.record_sample(
            peer,
            Sample {
                offset_ms,
                rtt_ms,
                probe_sent_at: received_at,
                received_at,
                expires_at,
            },
        );
    }
    #[test]
    fn sampler_ownership_is_exclusive_and_restartable() {
        let cell = OnceLock::new();
        let state = AtomicU8::new(SAMPLER_STOPPED);
        let first_params = Params {
            enforcement_mode: NtsEnforcementMode::Reject,
            health_policy: NtsHealthPolicy {
                min_samples: 1,
                max_offset_ms: 0,
                max_confidence_ms: 0,
            },
            ..Params::default()
        };
        let first = claim_service(&cell, &state, first_params).expect("first sampler owns service");
        assert_eq!(state.load(Ordering::Acquire), SAMPLER_RESERVED);
        assert!(claim_service(&cell, &state, Params::default()).is_none());
        let received_at = Instant::now();
        assert!(lock_service(first).record_measurement(
            test_peer_id(),
            10,
            1,
            received_at,
            received_at,
        ));
        lock_service(first).id_counter = 42;
        release_service(&cell, &state);
        assert_eq!(state.load(Ordering::Acquire), SAMPLER_STOPPED);
        let released = lock_service(first);
        assert!(released.per_peer.is_empty());
        assert!(released.outstanding.is_empty());
        assert_eq!(released.rtt_ms_count, 0);
        assert_eq!(released.id_counter, 42);
        drop(released);
        let second_params = Params {
            enforcement_mode: NtsEnforcementMode::Warn,
            ..Params::default()
        };
        let second = claim_service(&cell, &state, second_params).expect("restart reclaims service");
        assert_eq!(state.load(Ordering::Acquire), SAMPLER_RESERVED);
        assert!(std::ptr::eq(first, second));
        assert_eq!(
            lock_service(second).params.enforcement_mode,
            NtsEnforcementMode::Warn
        );
        release_service(&cell, &state);
    }
    #[test]
    fn failed_sampler_claim_and_fallback_configure_preserve_owned_policy() {
        let cell = OnceLock::new();
        let state = AtomicU8::new(SAMPLER_STOPPED);
        let policy_store = RwLock::new(ParamsSnapshot {
            enforcement_mode: NtsEnforcementMode::Warn,
            health_policy: NtsHealthPolicy::default(),
        });
        let owned = Params {
            enforcement_mode: NtsEnforcementMode::Reject,
            health_policy: NtsHealthPolicy {
                min_samples: 5,
                max_offset_ms: 10,
                max_confidence_ms: 20,
            },
            ..Params::default()
        };
        let service = claim_service_with_policy(&cell, &state, &policy_store, owned)
            .expect("first sampler owns the policy generation");
        assert!(
            claim_service_with_policy(&cell, &state, &policy_store, Params::default()).is_none()
        );
        assert!(!configure_policy_if_stopped(
            &state,
            &policy_store,
            Params::default()
        ));
        let policy = *policy_store
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(policy.enforcement_mode, NtsEnforcementMode::Reject);
        assert_eq!(policy.health_policy.min_samples, 5);
        assert_eq!(
            lock_service(service).params.enforcement_mode,
            NtsEnforcementMode::Reject
        );
        release_service(&cell, &state);
    }
    #[test]
    fn programmatic_params_are_normalized_before_startup() {
        let normalized = Params {
            sample_interval: Duration::from_nanos(1),
            sample_cap_per_round: 0,
            max_rtt_ms: 0,
            trim_percent: u8::MAX,
            per_peer_buffer: 0,
            smoothing_alpha: f64::NAN,
            health_policy: NtsHealthPolicy {
                min_samples: 0,
                ..NtsHealthPolicy::default()
            },
            ..Params::default()
        }
        .normalized();
        assert_eq!(normalized.sample_interval, MIN_SAMPLE_INTERVAL);
        assert!(normalized.sample_cap_per_round > 0);
        assert!(normalized.max_rtt_ms > 0);
        assert_eq!(normalized.trim_percent, 45);
        assert!(normalized.per_peer_buffer > 0);
        assert_eq!(normalized.health_policy.min_samples, 1);
        assert!(normalized.smoothing_alpha.is_finite());
        assert!((0.0..=1.0).contains(&normalized.smoothing_alpha));
    }
    #[tokio::test(flavor = "current_thread")]
    async fn service_lock_is_safe_on_a_current_thread_runtime() {
        let service = Mutex::new(Service::new(Params::default()));
        assert_eq!(lock_service(&service).id_counter, 1);
    }
    #[tokio::test]
    async fn sampler_interval_skips_missed_rounds() {
        let ticker = sampler_interval(std::time::Duration::from_millis(10));
        assert_eq!(
            ticker.missed_tick_behavior(),
            tokio::time::MissedTickBehavior::Skip
        );
        tokio::task::yield_now().await;
    }
    #[test]
    fn sample_ring_allocates_lazily_and_honors_its_limit() {
        let large_params = Params {
            per_peer_buffer: 1_000_000,
            ..Params::default()
        };
        let mut svc = service_for_tests(large_params);
        let peer = test_peer_id();
        let received_at = Instant::now();
        insert_sample(&mut svc, peer.clone(), received_at);
        let first_capacity = svc.per_peer[&peer].capacity();
        assert!(
            first_capacity < large_params.per_peer_buffer,
            "the first sample must not reserve the configured ring limit"
        );
        let params = Params {
            per_peer_buffer: 8,
            ..Params::default()
        };
        let mut svc = service_for_tests(params);
        let peer = test_peer_id();
        for _ in 0..(params.per_peer_buffer * 2) {
            insert_sample(&mut svc, peer.clone(), received_at);
        }
        assert_eq!(svc.per_peer[&peer].len(), params.per_peer_buffer);
    }
    #[test]
    fn trimmed_median_and_mad_basics() {
        let mut v = vec![10, 12, 13, 1000, 11, 9, 8, 10, 12, -1000];
        let (median, mad) = trimmed_median_and_mad(&mut v, 10);
        // Extreme outliers should be trimmed; median around 11
        assert!(
            (10..=12).contains(&median),
            "median {median} not in expected range"
        );
        // MAD should be small given tight cluster around ~11
        assert!(mad <= 2, "mad {mad} too large");
    }
    #[test]
    fn trimmed_median_and_mad_handles_integer_endpoints() {
        let mut offsets = [i64::MIN, i64::MAX];
        assert_eq!(
            trimmed_median_and_mad(&mut offsets, 0),
            (i64::MAX, u64::MAX)
        );
    }
    #[test]
    fn sample_measurement_rejects_unrepresentable_or_negative_values() {
        assert_eq!(sample_measurement(100, 110, 112, 122, 22), Some((0, 20)));
        assert_eq!(sample_measurement(0, u64::MAX, u64::MAX, 0, 0), None);
        assert_eq!(sample_measurement(0, 0, 2, 1, 1), None);
        assert_eq!(sample_measurement(100, 110, 105, 120, 20), None);
    }
    #[test]
    fn high_rtt_measurement_does_not_replace_a_valid_sample() {
        let params = Params {
            max_rtt_ms: 10,
            ..Params::default()
        };
        let mut svc = service_for_tests(params);
        let peer = test_peer_id();
        let start = Instant::now();
        assert!(svc.record_measurement(peer.clone(), 7, 10, start, start));
        assert!(!svc.record_measurement(peer.clone(), 500, 11, start, start));
        let samples = &svc.per_peer[&peer];
        assert_eq!(samples.len(), 1);
        assert_eq!(samples.back().expect("valid sample retained").offset_ms, 7);
    }
    #[test]
    fn out_of_order_replies_cannot_replace_samples_or_rewind_smoothing() {
        let params = Params {
            smoothing_enabled: true,
            smoothing_alpha: 1.0,
            max_adjust_ms_per_min: 60,
            health_policy: NtsHealthPolicy {
                min_samples: 1,
                max_offset_ms: 0,
                max_confidence_ms: 0,
            },
            ..Params::default()
        };
        let mut svc = service_for_tests(params);
        let peer = test_peer_id();
        let start = svc.last_smooth_update;
        let newer_probe = start + Duration::from_secs(1);
        let newer_receipt = start + Duration::from_secs(10);
        assert!(svc.record_measurement(peer.clone(), 100, 1, newer_probe, newer_receipt,));
        assert_eq!(svc.smoothed_offset_ms.to_bits(), 10.0_f64.to_bits());
        assert!(!svc.record_measurement(
            peer.clone(),
            10_000,
            1,
            start,
            start + Duration::from_secs(11),
        ));
        assert_eq!(
            svc.per_peer[&peer]
                .back()
                .expect("newer sample retained")
                .offset_ms,
            100
        );
        assert_eq!(svc.last_smooth_update, newer_receipt);
        assert!(svc.record_measurement(
            peer,
            100,
            1,
            start + Duration::from_secs(2),
            start + Duration::from_secs(12),
        ));
        assert_eq!(svc.smoothed_offset_ms.to_bits(), 12.0_f64.to_bits());
    }
    #[test]
    fn rtt_histogram_buckets_are_cumulative_and_include_overflow() {
        let mut svc = service_for_tests(Params::default());
        svc.observe_rtt(3);
        assert_eq!(&svc.rtt_bucket_counts[..2], [0, 0]);
        assert!(svc.rtt_bucket_counts[2..].iter().all(|count| *count == 1));
        svc.observe_rtt(3_000);
        assert_eq!(svc.rtt_bucket_counts[11], 1);
        assert_eq!(svc.rtt_bucket_counts[12], 2);
        assert_eq!(svc.rtt_ms_sum, 3_003);
        assert_eq!(svc.rtt_ms_count, 2);
    }
    #[test]
    fn smoothing_is_sample_driven_fractional_and_slew_bounded() {
        let params = Params {
            smoothing_enabled: true,
            smoothing_alpha: 1.0,
            max_adjust_ms_per_min: 50,
            health_policy: NtsHealthPolicy {
                min_samples: 1,
                max_offset_ms: 0,
                max_confidence_ms: 0,
            },
            ..Params::default()
        };
        let start = Instant::now();
        let mut frequent = service_for_tests(params);
        frequent.apply_smoothing_step(0, start);
        for step in 1_u32..=600 {
            frequent
                .apply_smoothing_step(10_000, start + Duration::from_millis(u64::from(step) * 100));
        }
        let frequent_result = frequent
            .applied_offset(10_000, 0, 1, start + Duration::from_secs(60))
            .0;
        assert_eq!(frequent_result, 50);
        frequent.aggregate_dirty = false;
        assert_eq!(
            frequent
                .applied_offset(10_000, 0, 1, start + Duration::from_secs(120))
                .0,
            frequent_result,
            "reads without a new aggregate must not advance smoothing"
        );
        let mut single = service_for_tests(params);
        single.apply_smoothing_step(0, start);
        single.apply_smoothing_step(10_000, start + Duration::from_secs(60));
        assert_eq!(
            single
                .applied_offset(10_000, 0, 1, start + Duration::from_secs(60))
                .0,
            frequent_result
        );
    }
    #[test]
    fn first_smoothed_aggregate_obeys_the_slew_cap() {
        let params = Params {
            smoothing_enabled: true,
            smoothing_alpha: 1.0,
            max_adjust_ms_per_min: 60,
            health_policy: NtsHealthPolicy {
                min_samples: 1,
                max_offset_ms: 0,
                max_confidence_ms: 0,
            },
            ..Params::default()
        };
        let mut svc = service_for_tests(params);
        let start = svc.last_smooth_update;
        svc.apply_smoothing_step(10_000, start + Duration::from_secs(1));
        assert_eq!(svc.smoothed_offset_ms.to_bits(), 1.0_f64.to_bits());
    }
    #[test]
    fn smoothing_does_not_depend_on_reads_between_measurements() {
        let params = Params {
            smoothing_enabled: true,
            smoothing_alpha: 0.2,
            max_adjust_ms_per_min: u64::MAX,
            health_policy: NtsHealthPolicy {
                min_samples: 1,
                max_offset_ms: 0,
                max_confidence_ms: 0,
            },
            ..Params::default()
        };
        let start = Instant::now();
        let local_now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let peer = test_peer_id();
        let mut observed = service_for_tests(params);
        let mut batched = service_for_tests(params);
        assert!(observed.record_measurement(peer.clone(), 0, 1, start, start));
        assert!(batched.record_measurement(peer.clone(), 0, 1, start, start));
        for step in 1_u32..=5 {
            let at = start + Duration::from_secs(u64::from(step));
            assert!(observed.record_measurement(peer.clone(), 100, 1, at, at));
            let _ = status_from_service(&mut observed, at, local_now);
            assert!(batched.record_measurement(peer.clone(), 100, 1, at, at));
        }
        let at = start + Duration::from_secs(5);
        assert_eq!(
            status_from_service(&mut observed, at, local_now).offset_ms,
            status_from_service(&mut batched, at, local_now).offset_ms
        );
    }
    #[test]
    fn expiring_noncontributing_history_does_not_advance_smoothing() {
        let params = Params {
            smoothing_enabled: true,
            health_policy: NtsHealthPolicy {
                min_samples: 1,
                ..NtsHealthPolicy::default()
            },
            ..Params::default()
        };
        let mut svc = service_for_tests(params);
        let peer = test_peer_id();
        let start = Instant::now();
        svc.record_sample(
            peer.clone(),
            Sample {
                offset_ms: 10,
                rtt_ms: 1,
                probe_sent_at: start,
                received_at: start,
                expires_at: start + Duration::from_secs(1),
            },
        );
        svc.record_sample(
            peer,
            Sample {
                offset_ms: 20,
                rtt_ms: 1,
                probe_sent_at: start,
                received_at: start,
                expires_at: start + Duration::from_secs(2),
            },
        );
        svc.smoothed_offset_ms = 20.0;
        svc.last_smooth_update = start;
        let local_now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let initial = status_from_service(&mut svc, start, local_now);
        assert_eq!(initial.offset_ms, 20);
        assert!(!svc.aggregate_dirty);
        svc.prune_expired(start + Duration::from_millis(1_500));
        assert!(
            !svc.aggregate_dirty,
            "only expiry of the latest contributing sample changes the aggregate"
        );
        let after = status_from_service(&mut svc, start + Duration::from_millis(1_500), local_now);
        assert_eq!(after.offset_ms, initial.offset_ms);
    }
    #[test]
    fn contributing_expiry_smoothing_is_independent_of_read_cadence() {
        let params = Params {
            smoothing_enabled: true,
            smoothing_alpha: 1.0,
            max_adjust_ms_per_min: 60,
            health_policy: NtsHealthPolicy {
                min_samples: 1,
                max_offset_ms: 0,
                max_confidence_ms: 0,
            },
            ..Params::default()
        };
        let start = Instant::now();
        let first_expiry = start + Duration::from_secs(1);
        let later_expiry = start + Duration::from_secs(120);
        let peers = [test_peer_id(), test_peer_id(), test_peer_id()];
        let make_service = || {
            let mut svc = service_for_tests(params);
            for (peer, offset_ms, expires_at) in [
                (peers[0].clone(), 0, first_expiry),
                (peers[1].clone(), 100, later_expiry),
                (peers[2].clone(), 200, later_expiry),
            ] {
                svc.record_sample(
                    peer,
                    Sample {
                        offset_ms,
                        rtt_ms: 1,
                        probe_sent_at: start,
                        received_at: start,
                        expires_at,
                    },
                );
            }
            svc.smoothed_offset_ms = 100.0;
            svc.last_smooth_update = start;
            svc.aggregate_dirty = false;
            svc
        };
        let local_now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let final_read = start + Duration::from_secs(61);

        let mut frequent = make_service();
        assert_eq!(
            status_from_service(&mut frequent, first_expiry, local_now).offset_ms,
            101
        );
        let frequent_result = status_from_service(&mut frequent, final_read, local_now).offset_ms;

        let mut delayed = make_service();
        let delayed_result = status_from_service(&mut delayed, final_read, local_now).offset_ms;
        assert_eq!(delayed_result, frequent_result);
    }
    #[test]
    fn unhealthy_raw_offset_falls_back_before_smoothing_can_hide_it() {
        let params = Params {
            smoothing_enabled: true,
            smoothing_alpha: 0.2,
            health_policy: NtsHealthPolicy {
                min_samples: 1,
                max_offset_ms: 1_000,
                max_confidence_ms: 500,
            },
            ..Params::default()
        };
        let mut svc = service_for_tests(params);
        let peer = test_peer_id();
        let start = Instant::now();
        let local_now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        insert_sample_with(&mut svc, peer.clone(), start, 0, 1);
        assert!(
            status_from_service(&mut svc, start, local_now)
                .health
                .healthy
        );
        insert_sample_with(&mut svc, peer, start, 10_000, 1);
        let status = status_from_service(&mut svc, start, local_now);
        assert_eq!(status.offset_ms, 10_000);
        assert!(!status.health.offset_ok);
        assert!(status.fallback);
        assert_eq!(status.now, local_now);
    }
    #[test]
    fn insufficient_quorum_does_not_apply_a_peer_offset() {
        let mut svc = service_for_tests(Params::default());
        let start = Instant::now();
        let local_now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        insert_sample_with(&mut svc, test_peer_id(), start, 500, 1);
        let status = status_from_service(&mut svc, start, local_now);
        assert_eq!(status.offset_ms, 500);
        assert!(!status.health.min_samples_ok);
        assert!(status.fallback);
        assert_eq!(status.now, local_now);
    }
    #[test]
    fn monotonic_clock_progress_does_not_reconsult_wall_time() {
        let monotonic_anchor = Instant::now();
        let system_anchor = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let clock =
            MonotonicSystemClock::from_bracket(monotonic_anchor, system_anchor, monotonic_anchor);
        assert_eq!(
            clock.at(monotonic_anchor + Duration::from_secs(2)),
            system_anchor + Duration::from_secs(2)
        );
    }
    #[test]
    fn monotonic_clock_uses_the_midpoint_of_its_sampling_bracket() {
        let monotonic_before = Instant::now();
        let monotonic_after = monotonic_before + Duration::from_secs(10);
        let system_anchor = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let clock =
            MonotonicSystemClock::from_bracket(monotonic_before, system_anchor, monotonic_after);
        assert_eq!(
            clock.at(monotonic_after),
            system_anchor + Duration::from_secs(5),
            "constructor delay must not be counted in full as forward clock bias"
        );
    }
    #[test]
    fn suspend_inclusive_clock_advances_admission_and_expires_retained_probes() {
        let start = Instant::now();
        let system_anchor = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let mut clock = MonotonicSystemClock::from_bracket(start, system_anchor, start);
        let awake_elapsed = Duration::from_secs(2);
        let suspended_elapsed = Duration::from_millis(171_665);
        let sample = clock.sample_elapsed(awake_elapsed, Some(awake_elapsed + suspended_elapsed));
        assert_eq!(
            sample.local_now,
            system_anchor + awake_elapsed + suspended_elapsed
        );
        assert_eq!(
            sample.observed_at.duration_since(start),
            awake_elapsed + suspended_elapsed
        );

        let mut service = Service::new(Params::default());
        let peer = test_peer_id();
        assert!(service.insert_outstanding_probe(
            peer.clone(),
            1,
            OutstandingProbe {
                t1_ms: epoch_ms(system_anchor),
                sent_at: start,
                expires_at: service.probe_deadline(start),
            }
        ));
        insert_sample_with(&mut service, peer.clone(), start, 0, 1);
        assert!(
            service
                .take_live_probe(&peer, 1, sample.observed_at)
                .is_none()
        );
        let status = status_from_service(&mut service, sample.observed_at, sample.local_now);
        assert_eq!(status.now, sample.local_now);
        assert_eq!(status.sample_count, 0);
        assert!(status.fallback);
        assert!(!status.health.healthy);
    }
    #[test]
    fn suspend_inclusive_clock_counts_entire_probe_round_trip() {
        let start = Instant::now();
        let system_anchor = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let mut clock = MonotonicSystemClock::from_bracket(start, system_anchor, start);
        let first = clock.sample_elapsed(Duration::from_secs(1), Some(Duration::from_secs(1)));
        let awake_rtt = Duration::from_millis(14);
        let suspended = Duration::from_millis(171_665);
        let received = clock.sample_elapsed(
            Duration::from_secs(1) + awake_rtt,
            Some(Duration::from_secs(1) + awake_rtt + suspended),
        );
        let elapsed = received.observed_at.duration_since(first.observed_at);
        assert_eq!(elapsed, awake_rtt + suspended);
        let elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap();
        let (offset, rtt) = sample_measurement(
            epoch_ms(first.local_now),
            epoch_ms(first.local_now),
            epoch_ms(first.local_now),
            epoch_ms(received.local_now),
            elapsed_ms,
        )
        .unwrap();
        assert_eq!(rtt, 171_679);
        let mut service = Service::new(Params::default());
        assert!(!service.record_measurement(
            test_peer_id(),
            offset,
            rtt,
            first.observed_at,
            received.observed_at
        ));
        assert!(service.per_peer.is_empty());
    }
    #[test]
    fn suspend_clock_failure_preserves_floor_and_cannot_reuse_healthy_samples() {
        let start = Instant::now();
        let system_anchor = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let mut clock = MonotonicSystemClock::from_bracket(start, system_anchor, start);
        let first = clock.sample_elapsed(Duration::from_secs(2), Some(Duration::from_secs(173)));
        assert!(first.suspend_inclusive);
        let failed = clock.sample_elapsed(Duration::from_secs(3), None);
        assert!(!failed.suspend_inclusive);
        assert_eq!(failed.observed_at, first.observed_at);
        assert_eq!(failed.local_now, first.local_now);
        let regressed =
            clock.sample_elapsed(Duration::from_secs(4), Some(Duration::from_secs(172)));
        assert!(!regressed.suspend_inclusive);
        assert_eq!(regressed.local_now, first.local_now);
        let mut service = Service::new(Params {
            health_policy: NtsHealthPolicy {
                min_samples: 1,
                ..NtsHealthPolicy::default()
            },
            ..Params::default()
        });
        insert_sample_with(&mut service, test_peer_id(), first.observed_at, 0, 1);
        assert!(status_from_clock(&mut service, &first).health.healthy);
        let status = status_from_clock(&mut service, &failed);
        assert!(status.fallback);
        assert!(!status.health.healthy);
        assert_eq!(status.sample_count, 0);
        assert_eq!(status.now, first.local_now);
        let recovered =
            clock.sample_elapsed(Duration::from_secs(5), Some(Duration::from_secs(174)));
        assert!(recovered.suspend_inclusive);
        assert_eq!(
            recovered.local_now,
            system_anchor + Duration::from_secs(174)
        );
    }
    #[cfg(any(target_vendor = "apple", target_os = "android", target_os = "linux"))]
    #[test]
    fn native_continuous_clock_uses_actual_process_readings() {
        let mut clock = MonotonicSystemClock::new();
        assert!(clock.continuous_anchor.is_some());
        let first = clock.sample();
        let second = clock.sample();
        assert!(first.suspend_inclusive);
        assert!(second.suspend_inclusive);
        assert_eq!(
            second.local_now.duration_since(first.local_now).unwrap(),
            second.observed_at.duration_since(first.observed_at)
        );
    }
    #[test]
    fn suspend_clock_overflow_retains_last_representable_unhealthy_point() {
        let start = Instant::now();
        let system_anchor = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let mut clock = MonotonicSystemClock::from_bracket(start, system_anchor, start);
        let first = clock.sample_elapsed(Duration::from_secs(2), Some(Duration::from_secs(173)));
        let overflow = clock.sample_elapsed(Duration::MAX, Some(Duration::MAX));
        assert!(!overflow.suspend_inclusive);
        assert_eq!(overflow.local_now, first.local_now);
        assert_eq!(overflow.observed_at, first.observed_at);
        let recovered =
            clock.sample_elapsed(Duration::from_secs(3), Some(Duration::from_secs(174)));
        assert!(recovered.suspend_inclusive);
        assert_eq!(
            recovered.local_now,
            system_anchor + Duration::from_secs(174)
        );
    }
    #[test]
    fn public_time_floor_never_moves_backwards() {
        let floor = Mutex::new(None);
        let first = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let earlier = SystemTime::UNIX_EPOCH + Duration::from_secs(90);
        let later = SystemTime::UNIX_EPOCH + Duration::from_secs(101);
        assert_eq!(clamp_monotonic_output(&floor, first), first);
        assert_eq!(clamp_monotonic_output(&floor, earlier), first);
        assert_eq!(clamp_monotonic_output(&floor, later), later);
    }
    #[test]
    fn public_time_floor_recomputes_offset_and_health_consistently() {
        let local_now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let candidate = local_now + Duration::from_millis(10);
        let retained_floor = local_now + Duration::from_millis(100);
        let status_for = |policy: NtsHealthPolicy| NetworkTimeStatus {
            now: candidate,
            offset_ms: 10,
            confidence_ms: 0,
            sample_count: 1,
            peer_count: 1,
            fallback: false,
            health: policy.evaluate(1, 10, 0, false),
        };

        let permissive = NtsHealthPolicy {
            min_samples: 1,
            max_offset_ms: 1_000,
            max_confidence_ms: 1,
        };
        let permissive_floor = Mutex::new(Some(retained_floor));
        let status = finalize_status_time_with_floor(
            status_for(permissive),
            local_now,
            permissive,
            &permissive_floor,
        );
        assert_eq!(status.now, retained_floor);
        assert_eq!(status.offset_ms, 100);
        assert!(!status.fallback);
        assert!(status.health.healthy);

        let strict = NtsHealthPolicy {
            max_offset_ms: 50,
            ..permissive
        };
        let strict_floor = Mutex::new(Some(retained_floor));
        let status =
            finalize_status_time_with_floor(status_for(strict), local_now, strict, &strict_floor);
        assert_eq!(status.now, retained_floor);
        assert_eq!(status.offset_ms, 100);
        assert!(status.fallback);
        assert!(!status.health.offset_ok);
        assert!(!status.health.healthy);
    }
    #[test]
    fn now_fallback_without_service() {
        // SERVICE is unset in this test process; ensure fallback path returns without panicking
        let s = now();
        // Confidence is 0 when no samples; offset 0
        assert_eq!(s.offset_ms, 0);
        assert_eq!(s.confidence_ms, 0);
        assert_eq!(s.sample_count, 0);
        assert_eq!(s.peer_count, 0);
        assert!(s.fallback);
        assert!(!s.health.healthy);
    }
    #[test]
    fn membership_epoch_change_invalidates_samples_and_probes() {
        let mut svc = service_for_tests(Params::default());
        let start = Instant::now();
        let sampled_peer = test_peer_id();
        let probing_peer = test_peer_id();
        assert!(svc.apply_configured_membership(7, 2, start));
        insert_sample(&mut svc, sampled_peer, start);
        assert!(svc.insert_outstanding_probe(
            probing_peer,
            1,
            OutstandingProbe {
                t1_ms: 0,
                sent_at: start,
                expires_at: svc.probe_deadline(start),
            },
        ));
        svc.smoothed_offset_ms = 50.0;
        assert!(!svc.apply_configured_membership(7, 2, start));
        assert!(!svc.per_peer.is_empty());
        assert!(!svc.outstanding.is_empty());

        let changed_at = start + Duration::from_millis(1);
        assert!(svc.apply_configured_membership(8, 2, changed_at));
        assert!(svc.per_peer.is_empty());
        assert!(svc.outstanding.is_empty());
        assert_eq!(svc.smoothed_offset_ms.to_bits(), 0.0_f64.to_bits());
        assert_eq!(svc.last_smooth_update, changed_at);
    }
    #[test]
    fn freshness_window_covers_a_complete_rotating_peer_sweep() {
        let params = Params {
            sample_interval: Duration::from_secs(5),
            sample_cap_per_round: 2,
            per_peer_buffer: 3,
            max_rtt_ms: 100,
            ..Params::default()
        };
        let mut svc = service_for_tests(params);
        svc.configured_peer_count = 7;
        assert_eq!(
            svc.sample_freshness_window(),
            Duration::from_secs(5 * 4 * 3) + Duration::from_millis(100)
        );
    }
    #[test]
    fn one_live_probe_per_peer_preserves_the_full_reply_window() {
        let mut svc = service_for_tests(Params::default());
        let peer = test_peer_id();
        let start = Instant::now();
        let first_probe = OutstandingProbe {
            t1_ms: 0,
            sent_at: start,
            expires_at: svc.probe_deadline(start),
        };
        assert!(svc.insert_outstanding_probe(peer.clone(), 1, first_probe));
        let newer = start + Duration::from_millis(1);
        let second_probe = OutstandingProbe {
            t1_ms: 0,
            sent_at: newer,
            expires_at: svc.probe_deadline(newer),
        };
        assert!(!svc.insert_outstanding_probe(peer.clone(), 2, second_probe));
        assert_eq!(svc.outstanding.len(), 1);
        assert!(svc.take_live_probe(&peer, 1, newer).is_some());
        assert!(svc.insert_outstanding_probe(peer.clone(), 2, second_probe));
        assert!(svc.take_live_probe(&peer, 2, newer).is_some());
    }
    #[test]
    fn sample_freshness_is_anchored_to_packet_reception() {
        let params = Params {
            sample_interval: Duration::from_secs(10),
            sample_cap_per_round: 1,
            per_peer_buffer: 1,
            max_rtt_ms: 1_000,
            ..Params::default()
        };
        let mut svc = service_for_tests(params);
        let received_at = Instant::now();
        assert!(svc.record_measurement(test_peer_id(), 0, 1, received_at, received_at,));
        let deadline = received_at + svc.sample_freshness_window();
        svc.prune_expired(deadline);
        assert!(svc.per_peer.is_empty());
    }
    #[test]
    fn mass_expiry_replay_is_coalesced_to_a_fixed_work_bound() {
        let start = Instant::now();
        let observed_at = start + Duration::from_secs(2);
        let deadlines = (0..1_000_u64)
            .map(|millis| start + Duration::from_millis(millis))
            .collect();
        let replay = bounded_expiry_replay_deadlines(deadlines, observed_at);
        assert_eq!(replay.len(), MAX_EXPIRY_REPLAY_EVENTS_PER_PRUNE);
        assert_eq!(replay.last(), Some(&observed_at));
    }
    #[test]
    fn unanswered_probes_are_bounded_by_the_rtt_deadline() {
        let params = Params {
            sample_interval: std::time::Duration::from_millis(10),
            sample_cap_per_round: 3,
            max_rtt_ms: 25,
            ..Params::default()
        };
        let mut svc = service_for_tests(params);
        let start = Instant::now();
        assert!(svc.probe_timeout() > params.sample_interval);
        let interval_nanos = params.sample_interval.as_nanos();
        let active_rounds =
            usize::try_from(svc.probe_timeout().as_nanos().div_ceil(interval_nanos))
                .expect("test round count fits");
        let maximum_live_probes = params.sample_cap_per_round * active_rounds;
        let mut saw_overlapping_rounds = false;
        for round in 0_u32..128 {
            let now = start
                .checked_add(params.sample_interval.saturating_mul(round))
                .expect("test deadline fits");
            svc.prune_expired(now);
            for probe in 0..params.sample_cap_per_round {
                let peer = test_peer_id();
                svc.outstanding.insert(
                    (
                        peer,
                        u64::from(round) << 32 | u64::try_from(probe).expect("probe fits"),
                    ),
                    OutstandingProbe {
                        t1_ms: 0,
                        sent_at: now,
                        expires_at: svc.probe_deadline(now),
                    },
                );
            }
            saw_overlapping_rounds |= svc.outstanding.len() > params.sample_cap_per_round;
            assert!(
                svc.outstanding.len() <= maximum_live_probes,
                "timed-out probes must not accumulate across rounds"
            );
        }
        assert!(
            saw_overlapping_rounds,
            "the test must exercise several simultaneously live probe rounds"
        );
        let after_last_deadline = start
            .checked_add(
                params
                    .sample_interval
                    .saturating_mul(127)
                    .saturating_add(svc.probe_timeout()),
            )
            .expect("test deadline fits");
        svc.prune_expired(after_last_deadline);
        assert!(svc.outstanding.is_empty());
        let peer = test_peer_id();
        svc.outstanding.insert(
            (peer.clone(), 999),
            OutstandingProbe {
                t1_ms: 0,
                sent_at: start,
                expires_at: start,
            },
        );
        assert!(
            svc.take_live_probe(&peer, 999, start).is_none(),
            "a pong received at or after the RTT deadline must be ignored"
        );
    }
    #[test]
    fn rotating_peer_samples_and_diagnostics_remain_bounded_by_ring_horizon() {
        let params = Params {
            sample_interval: std::time::Duration::from_millis(10),
            sample_cap_per_round: 3,
            max_rtt_ms: 5,
            per_peer_buffer: 3,
            ..Params::default()
        };
        let mut svc = service_for_tests(params);
        let start = Instant::now();
        let maximum_live_peers = params.sample_cap_per_round * (params.per_peer_buffer + 1);
        for round in 0_u32..128 {
            let now = start
                .checked_add(params.sample_interval.saturating_mul(round))
                .expect("test deadline fits");
            svc.prune_expired(now);
            for _ in 0..params.sample_cap_per_round {
                insert_sample(&mut svc, test_peer_id(), now);
            }
            let snapshot = svc.debug_snapshot(now);
            assert_eq!(snapshot.len(), svc.per_peer.len());
            assert!(
                snapshot.len() <= maximum_live_peers,
                "diagnostics must only clone samples in the configured retention horizon"
            );
        }
        let recent = start
            .checked_add(params.sample_interval.saturating_mul(128))
            .expect("test deadline fits");
        let peer = test_peer_id();
        insert_sample(&mut svc, peer, recent);
        svc.prune_expired(
            recent
                .checked_add(std::time::Duration::from_millis(params.max_rtt_ms + 1))
                .expect("test deadline fits"),
        );
        assert!(
            !svc.per_peer.is_empty(),
            "a sample remains usable beyond its RTT deadline for the ring horizon"
        );
        let after_horizon = recent
            .checked_add(svc.sample_freshness_window())
            .expect("test deadline fits");
        svc.prune_expired(after_horizon);
        assert!(svc.per_peer.is_empty());
        assert!(svc.debug_snapshot(after_horizon).is_empty());
    }
    #[test]
    fn nts_health_policy_evaluates_thresholds() {
        let policy = NtsHealthPolicy {
            min_samples: 2,
            max_offset_ms: 100,
            max_confidence_ms: 50,
        };
        let ok = policy.evaluate(2, 10, 20, false);
        assert!(ok.min_samples_ok);
        assert!(ok.offset_ok);
        assert!(ok.confidence_ok);
        assert!(ok.healthy);
        let offset_bad = policy.evaluate(2, 250, 20, false);
        assert!(offset_bad.min_samples_ok);
        assert!(!offset_bad.offset_ok);
        assert!(offset_bad.confidence_ok);
        assert!(!offset_bad.healthy);
        let samples_bad = policy.evaluate(1, 10, 20, false);
        assert!(!samples_bad.min_samples_ok);
        assert!(samples_bad.offset_ok);
        assert!(samples_bad.confidence_ok);
        assert!(!samples_bad.healthy);
        let fallback = policy.evaluate(2, 10, 20, true);
        assert!(!fallback.healthy);
        let zero_threshold = NtsHealthPolicy {
            min_samples: 0,
            max_offset_ms: 0,
            max_confidence_ms: 0,
        };
        assert!(
            !zero_threshold.evaluate(0, 0, 0, false).min_samples_ok,
            "zero must not disable the peer quorum"
        );
    }
}
