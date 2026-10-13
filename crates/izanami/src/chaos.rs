//! Orchestration layer that wires configuration, workload generation, and fault injection together.
use crate::{
    config::{ChaosConfig, WorkloadProfile},
    faults::{
        self, CpuStressConfig, DiskSaturationConfig, FaultConfig, NetworkLatencyConfig,
        NetworkPartitionConfig,
    },
    instructions::{
        self, AccountRecord, PlanUpdate, PreparedChaos, TransactionPlan, WorkloadEngine,
    },
};
use color_eyre::{
    Result,
    eyre::{WrapErr, eyre},
};
use iroha::{
    blocking::Client,
    client::{PreparedTransactionPayload, TransactionWaitOptions, TransactionWaitOutcome},
};
use iroha_config::kura::FsyncMode;
use iroha_crypto::{ExposedPrivateKey, KeyPair};
use iroha_data_model::{
    isi::{
        RegisterBox,
        register::RegisterPeerWithPop,
        staking::{ActivatePublicLaneValidator, RegisterPublicLaneValidator},
    },
    parameter::BlockParameter,
    parameter::custom::{CustomParameter, CustomParameterId},
    parameter::system::SumeragiNposParameters,
    prelude::*,
    query::trigger::prelude::FindTriggers,
    trigger::action::Repeats,
};
use iroha_executor_data_model::permission::{
    asset::CanMintAssetWithDefinition, nexus::CanPublishSpaceDirectoryManifest,
};
use iroha_genesis::GenesisBlock;
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_model_base::peer::PeerId;
use iroha_model_base::topology::DataSpaceId;
use iroha_model_base::topology::LaneId;
use iroha_primitives::json::Json;
use iroha_test_network::{Network, NetworkBuilder, NetworkPeer, Signatory};
use rand::{RngCore, SeedableRng, rngs::StdRng, seq::SliceRandom};
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs,
    future::Future,
    io::Write,
    num::NonZeroU64,
    path::Path,
    sync::{
        Arc, Mutex as StdMutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc},
    task::{JoinHandle, JoinSet, spawn_blocking},
    time,
};
use toml::{Table, Value as TomlValue};
use tracing::{debug, info, warn};
// Cover the largest admitted validator roster plus the standard core peer capacity.
const IZANAMI_MAX_TOTAL_CONNECTIONS: usize =
    iroha_config::parameters::defaults::network::lane_profile::CORE_MAX_TOTAL_CONNECTIONS;
const IZANAMI_P2P_QUEUE_CAP_HIGH: i64 = 65_536;
const IZANAMI_P2P_QUEUE_CAP_LOW: i64 = 65_536;
const IZANAMI_P2P_POST_QUEUE_CAP: i64 = 8_192;
const IZANAMI_P2P_SUBSCRIBER_QUEUE_CAP: i64 = 16_384;
const IZANAMI_QUEUE_CAPACITY: i64 = 65_536;
const IZANAMI_TORII_PREAUTH_RATE_PER_IP_PER_SEC: i64 = 1_000_000;
const IZANAMI_TORII_PREAUTH_BURST_PER_IP: i64 = 2_000_000;
const IZANAMI_PREBUILT_SUBMIT_BATCH_SIZE: usize = 32;
const IZANAMI_HIGH_TPS_ACCOUNT_THRESHOLD: f64 = 1_000.0;
const IZANAMI_HIGH_TPS_ACCOUNT_COUNT: usize = 4_096;
const IZANAMI_HIGH_TPS_STABLE_ACCOUNT_COUNT: usize = 8_192;
const IZANAMI_TRANSACTION_GOSSIP_PERIOD_MS: i64 = 250;
const IZANAMI_TRANSACTION_GOSSIP_SIZE: u32 =
    iroha_config::parameters::defaults::network::TRANSACTION_GOSSIP_SIZE.get();
const IZANAMI_TRANSACTION_GOSSIP_RESEND_TICKS: i64 = 1;
const IZANAMI_TRANSACTION_GOSSIP_PUBLIC_TARGET_CAP: i64 = 64;
const IZANAMI_NEXUS_FUSION_FLOOR_TEU: i64 = 16_000_000;
const IZANAMI_NEXUS_FUSION_EXIT_TEU: i64 = 24_000_000;
const IZANAMI_IVM_GAS_LIMIT_PER_BLOCK: u64 = 2_000_000_000;
const IZANAMI_NPOS_BLOCK_TIME_MS: i64 = 120;
const IZANAMI_NPOS_COMMIT_TIME_MS: i64 = 180;
const IZANAMI_PIPELINE_ACCESS_SET_CACHE_ENABLED: bool = true;
const IZANAMI_PIPELINE_PARALLEL_OVERLAY: bool = true;
const IZANAMI_PIPELINE_PARALLEL_APPLY: bool = true;
const IZANAMI_PIPELINE_WORKERS: i64 = 0;
const IZANAMI_PIPELINE_SIGNATURE_BATCH_MAX_ED25519: i64 = 128;
const IZANAMI_PIPELINE_SIGNATURE_BATCH_MAX_SECP256K1: i64 = 128;
const IZANAMI_PIPELINE_SIGNATURE_BATCH_MAX_PQC: i64 = 64;
const IZANAMI_PIPELINE_SIGNATURE_BATCH_MAX_BLS: i64 = 32;
const IZANAMI_PIPELINE_STATELESS_CACHE_CAP: i64 = 16_384;
const IZANAMI_KURA_FSYNC_MODE: FsyncMode = FsyncMode::Batched;
const IZANAMI_INGRESS_MAX_ATTEMPTS: usize = 3;
const IZANAMI_INGRESS_UNHEALTHY_FAILURE_THRESHOLD: u32 = 2;
const IZANAMI_INGRESS_UNHEALTHY_COOLDOWN_MS: u64 = 5_000;
const IZANAMI_INGRESS_REPROBE_INTERVAL_MS: u64 = 1_000;
const IZANAMI_INGRESS_REQUEST_TIMEOUT_MS: u64 = 15_000;
const IZANAMI_INGRESS_STATUS_TIMEOUT_MS: u64 = 60_000;
const IZANAMI_THROUGHPUT_CONFIRMATION_TIMEOUT_MS: u64 = 150_000;
const IZANAMI_NPOS_RECOVERY_CONFIRMATION_TIMEOUT_MS: u64 = 180_000;
const IZANAMI_STABLE_INGRESS_MAX_INFLIGHT_CAP: usize = 64;
const IZANAMI_STRESS_STABLE_INGRESS_CAP_BYPASS_TPS: f64 = 200.0;
const IZANAMI_STABLE_SEVERE_STOPPING_MAX_INFLIGHT_CAP: usize = 8;
const IZANAMI_STABLE_SEVERE_STOPPING_TPS_CAP: f64 = 10.0;
const IZANAMI_QUEUE_TIMEOUT_RETRY_ATTEMPTS: u32 = 2;
const IZANAMI_QUEUE_TIMEOUT_RETRY_BACKOFF_MS: u64 = 250;
const IZANAMI_QUEUE_TIMEOUT_ENDPOINT_BACKPRESSURE_RETRY_MULTIPLIER: u32 = 2;
const IZANAMI_WORKER_SHUTDOWN_TIMEOUT_SECS: u64 = 240;
const IZANAMI_WORKER_FAILURE_SHUTDOWN_TIMEOUT_SECS: u64 = 2;
const IZANAMI_PEER_LOG_BASE_LEVEL: &str = "WARN";
const IZANAMI_TELEMETRY_PROFILE: &str = "developer";
const IZANAMI_STRICT_HEIGHT_DIVERGENCE_MAX_BLOCKS: u64 = 16;
const IZANAMI_STRICT_HEIGHT_DIVERGENCE_MAX_WINDOW_SECS: u64 = 60;
const IZANAMI_SHARED_HOST_SOAK_MIN_DURATION_SECS: u64 = 3_600;
const IZANAMI_SHARED_HOST_SOAK_TPS_FLOOR: f64 = 5.0;
const IZANAMI_SHARED_HOST_SOAK_MAX_INFLIGHT_FLOOR: usize = 8;
const IZANAMI_THROUGHPUT_CONFIRMATION_SAMPLE_PERCENT: u64 = 1;
const IZANAMI_THROUGHPUT_CONFIRMATION_CAP_PER_MINUTE_PER_ENDPOINT: u32 = 100;
const IZANAMI_THROUGHPUT_CONFIRMATION_WINDOW_SECS: u64 = 60;
const IZANAMI_THROUGHPUT_CONFIRMATION_QUEUE_CAP: usize = 4_096;
const IZANAMI_THROUGHPUT_CONFIRMATION_POLL_INTERVAL_MS: u64 = 100;
const IZANAMI_SUBMISSION_BACKLOG_MULTIPLIER: usize = 4;
const IZANAMI_PREBUILD_ATTEMPT_MULTIPLIER: usize = 16;
const IZANAMI_PREBUILD_PROGRESS_LOG_STEP: usize = 50_000;
const IZANAMI_PREBUILD_FEED_TICK_MS: u64 = 5;
const IZANAMI_STATUS_SAMPLE_MAX_PEERS: usize = 3;
const IZANAMI_STATUS_SAMPLE_REQUEST_TIMEOUT_MS: u64 = 2_000;
const IZANAMI_SHARED_HOST_SOAK_PROGRESS_TIMEOUT_FLOOR_SECS: u64 = 600;
const IZANAMI_SHARED_HOST_SOAK_PIPELINE_TIME_MS: u64 = 150;
// Shared-host stable soaks now use the hard latency gate as an acceptance check for the
// DA-enabled 4-peer steady-state envelope. The aspirational sub-1s target remains available via
// explicit `--latency-p95-threshold`, but the default gate should match the observed healthy run.
const IZANAMI_SHARED_HOST_SOAK_LATENCY_P95_THRESHOLD_SECS: u64 = 3;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SubmissionConfirmationMode {
    BlockingApplied,
    AcceptedByIngress,
}
#[derive(Clone, Copy, Debug)]
struct IngressEndpointPoolConfig {
    max_attempts: usize,
    unhealthy_failure_threshold: u32,
    unhealthy_cooldown: Duration,
    reprobe_interval: Duration,
}
impl Default for IngressEndpointPoolConfig {
    fn default() -> Self {
        Self {
            max_attempts: IZANAMI_INGRESS_MAX_ATTEMPTS,
            unhealthy_failure_threshold: IZANAMI_INGRESS_UNHEALTHY_FAILURE_THRESHOLD,
            unhealthy_cooldown: Duration::from_millis(IZANAMI_INGRESS_UNHEALTHY_COOLDOWN_MS),
            reprobe_interval: Duration::from_millis(IZANAMI_INGRESS_REPROBE_INTERVAL_MS),
        }
    }
}
#[derive(Default)]
struct IngressStats {
    failover_total: AtomicU64,
    endpoint_unhealthy_total: AtomicU64,
    endpoint_stats: StdMutex<Vec<IngressEndpointStats>>,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct IngressStatsSnapshot {
    failover_total: u64,
    endpoint_unhealthy_total: u64,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct IngressEndpointStats {
    endpoint: String,
    failover_total: u64,
    unhealthy_total: u64,
}
impl IngressStats {
    fn ensure_endpoints(&self, labels: &[String]) {
        if let Ok(mut guard) = self.endpoint_stats.lock() {
            if guard.is_empty() {
                *guard = labels
                    .iter()
                    .cloned()
                    .map(|endpoint| IngressEndpointStats {
                        endpoint,
                        failover_total: 0,
                        unhealthy_total: 0,
                    })
                    .collect();
            }
        }
    }
    fn record_failover(&self, endpoint_idx: usize) {
        self.failover_total.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut guard) = self.endpoint_stats.lock()
            && let Some(endpoint) = guard.get_mut(endpoint_idx)
        {
            endpoint.failover_total = endpoint.failover_total.saturating_add(1);
        }
    }
    fn record_endpoint_unhealthy(&self, endpoint_idx: usize) {
        self.endpoint_unhealthy_total
            .fetch_add(1, Ordering::Relaxed);
        if let Ok(mut guard) = self.endpoint_stats.lock()
            && let Some(endpoint) = guard.get_mut(endpoint_idx)
        {
            endpoint.unhealthy_total = endpoint.unhealthy_total.saturating_add(1);
        }
    }
    fn snapshot(&self) -> IngressStatsSnapshot {
        IngressStatsSnapshot {
            failover_total: self.failover_total.load(Ordering::Relaxed),
            endpoint_unhealthy_total: self.endpoint_unhealthy_total.load(Ordering::Relaxed),
        }
    }
    fn endpoint_snapshots(&self) -> Vec<IngressEndpointStats> {
        self.endpoint_stats
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IngressEndpointState {
    Healthy,
    LaggingExcluded,
    QueuePressureCooldown {
        streak: u32,
        next_probe_window: Instant,
    },
    UnhealthyRetryable {
        next_probe_window: Instant,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EndpointHealthState {
    consecutive_failures: u32,
    consecutive_queue_pressure_failures: u32,
    unhealthy_until: Option<Instant>,
    last_probe_at: Option<Instant>,
    sticky_unhealthy_until: Option<Instant>,
    endpoint_state: IngressEndpointState,
}
impl Default for EndpointHealthState {
    fn default() -> Self {
        Self {
            consecutive_failures: 0,
            consecutive_queue_pressure_failures: 0,
            unhealthy_until: None,
            last_probe_at: None,
            sticky_unhealthy_until: None,
            endpoint_state: IngressEndpointState::Healthy,
        }
    }
}
#[derive(Clone, Debug)]
struct IngressLagSnapshot {
    quorum_min_height: u64,
    peer_heights: Vec<Option<u64>>,
    observed_at: Instant,
}
#[derive(Clone)]
struct EndpointHealthPool {
    labels: Arc<Vec<String>>,
    state: Arc<StdMutex<Vec<EndpointHealthState>>>,
    all_unhealthy_probe_at: Arc<StdMutex<Option<Instant>>>,
    lag_snapshot: Arc<StdMutex<Option<IngressLagSnapshot>>>,
    cursor: Arc<AtomicU64>,
    config: IngressEndpointPoolConfig,
    ingress_stats: Arc<IngressStats>,
}
impl EndpointHealthPool {
    fn new(
        labels: Vec<String>,
        config: IngressEndpointPoolConfig,
        ingress_stats: Arc<IngressStats>,
    ) -> Self {
        let len = labels.len();
        ingress_stats.ensure_endpoints(&labels);
        Self {
            labels: Arc::new(labels),
            state: Arc::new(StdMutex::new(vec![EndpointHealthState::default(); len])),
            all_unhealthy_probe_at: Arc::new(StdMutex::new(None)),
            lag_snapshot: Arc::new(StdMutex::new(None)),
            cursor: Arc::new(AtomicU64::new(0)),
            config,
            ingress_stats,
        }
    }
    fn update_lag_snapshot(&self, snapshot: IngressLagSnapshot) {
        if let Ok(mut guard) = self.lag_snapshot.lock() {
            *guard = Some(snapshot);
        }
    }
    fn run_with_failover_preferred<T, F>(
        &self,
        op_name: &'static str,
        preferred_endpoint_idx: usize,
        operation: F,
    ) -> Result<T>
    where
        F: FnMut(usize, &str) -> Result<T>,
    {
        self.run_with_failover_at_with_preference(
            op_name,
            Some(preferred_endpoint_idx),
            Instant::now(),
            operation,
        )
    }
    fn run_with_failover_excluding<T, F>(
        &self,
        op_name: &'static str,
        excluded_endpoint_idx: usize,
        operation: F,
    ) -> Result<T>
    where
        F: FnMut(usize, &str) -> Result<T>,
    {
        self.run_with_failover_excluding_at(
            op_name,
            excluded_endpoint_idx,
            Instant::now(),
            operation,
        )
    }
    fn select_endpoint_preferred(
        &self,
        op_name: &'static str,
        preferred_endpoint_idx: usize,
    ) -> Result<usize> {
        self.select_endpoint_at_with_preference(
            op_name,
            Some(preferred_endpoint_idx),
            Instant::now(),
        )
    }
    #[cfg(test)]
    fn select_endpoint_at(&self, op_name: &'static str, now: Instant) -> Result<usize> {
        self.select_endpoint_at_with_preference(op_name, None, now)
    }
    fn select_endpoint_at_with_preference(
        &self,
        op_name: &'static str,
        preferred_endpoint_idx: Option<usize>,
        now: Instant,
    ) -> Result<usize> {
        self.attempt_order_at_with_preference(now, preferred_endpoint_idx)
            .into_iter()
            .next()
            .ok_or_else(|| eyre!("no ingress endpoints available for operation `{op_name}`"))
    }
    fn run_on_endpoint<T, F>(
        &self,
        op_name: &'static str,
        endpoint_idx: usize,
        operation: F,
    ) -> Result<T>
    where
        F: FnOnce(usize, &str) -> Result<T>,
    {
        self.run_on_endpoint_at(op_name, endpoint_idx, Instant::now(), operation)
    }
    fn run_on_endpoint_at<T, F>(
        &self,
        op_name: &'static str,
        endpoint_idx: usize,
        now: Instant,
        operation: F,
    ) -> Result<T>
    where
        F: FnOnce(usize, &str) -> Result<T>,
    {
        let label = self
            .labels
            .get(endpoint_idx)
            .map(String::as_str)
            .ok_or_else(|| eyre!("endpoint index {endpoint_idx} out of range"))?;
        match operation(endpoint_idx, label) {
            Ok(value) => {
                self.mark_success_at(endpoint_idx, now);
                Ok(value)
            }
            Err(err) => {
                let failure_class = classify_ingress_failure(&err);
                let retryable = failure_class.is_retryable();
                let transitioned_unhealthy = ingress_failure_affects_submit_health(op_name)
                    && self.mark_failure_at(endpoint_idx, now, failure_class);
                if transitioned_unhealthy {
                    self.ingress_stats.record_endpoint_unhealthy(endpoint_idx);
                    if should_log_ingress_retry_at_debug(op_name, failure_class, retryable) {
                        debug!(
                                target: "izanami::ingress",
                                operation = op_name,
                            endpoint = label,
                            failure_class = failure_class.as_str(),
                            "marking pinned ingress endpoint unhealthy"
                        );
                    } else {
                        warn!(
                                target: "izanami::ingress",
                                operation = op_name,
                            endpoint = label,
                            failure_class = failure_class.as_str(),
                            "marking pinned ingress endpoint unhealthy"
                        );
                    }
                }
                if should_log_ingress_retry_at_debug(op_name, failure_class, retryable) {
                    debug!(
                        target: "izanami::ingress",
                        ?err,
                        operation = op_name,
                        endpoint = label,
                        failure_class = failure_class.as_str(),
                        retryable,
                        "pinned ingress endpoint request failed"
                    );
                } else {
                    warn!(
                        target: "izanami::ingress",
                        ?err,
                        operation = op_name,
                        endpoint = label,
                        failure_class = failure_class.as_str(),
                        retryable,
                        "pinned ingress endpoint request failed"
                    );
                }
                Err(err)
            }
        }
    }
    #[cfg(test)]
    fn run_with_failover_at<T, F>(
        &self,
        op_name: &'static str,
        now: Instant,
        operation: F,
    ) -> Result<T>
    where
        F: FnMut(usize, &str) -> Result<T>,
    {
        self.run_with_failover_at_with_preference(op_name, None, now, operation)
    }
    fn run_with_failover_at_with_preference<T, F>(
        &self,
        op_name: &'static str,
        preferred_endpoint_idx: Option<usize>,
        now: Instant,
        mut operation: F,
    ) -> Result<T>
    where
        F: FnMut(usize, &str) -> Result<T>,
    {
        let attempt_order = self.attempt_order_at_with_preference(now, preferred_endpoint_idx);
        if attempt_order.is_empty() {
            return Err(eyre!(
                "no ingress endpoints available for operation `{op_name}`"
            ));
        }
        let max_attempts = self.config.max_attempts.max(1).min(attempt_order.len());
        let mut last_error = None;
        let mut attempted = 0usize;
        for (attempt_idx, endpoint_idx) in attempt_order.into_iter().take(max_attempts).enumerate()
        {
            if attempt_idx > 0 {
                self.ingress_stats.record_failover(endpoint_idx);
            }
            let label = self
                .labels
                .get(endpoint_idx)
                .map(String::as_str)
                .unwrap_or("<unknown>");
            attempted = attempted.saturating_add(1);
            match operation(endpoint_idx, label) {
                Ok(value) => {
                    self.mark_success_at(endpoint_idx, now);
                    return Ok(value);
                }
                Err(err) => {
                    let failure_class = classify_ingress_failure(&err);
                    let retryable = failure_class.is_retryable();
                    let transitioned_unhealthy = ingress_failure_affects_submit_health(op_name)
                        && self.mark_failure_at(endpoint_idx, now, failure_class);
                    if transitioned_unhealthy {
                        self.ingress_stats.record_endpoint_unhealthy(endpoint_idx);
                        if should_log_ingress_retry_at_debug(op_name, failure_class, retryable) {
                            debug!(
                                target: "izanami::ingress",
                                operation = op_name,
                                endpoint = label,
                                attempt = attempt_idx + 1,
                                failure_class = failure_class.as_str(),
                                "marking ingress endpoint unhealthy"
                            );
                        } else {
                            warn!(
                                target: "izanami::ingress",
                                operation = op_name,
                                endpoint = label,
                                attempt = attempt_idx + 1,
                                failure_class = failure_class.as_str(),
                                "marking ingress endpoint unhealthy"
                            );
                        }
                    }
                    if should_log_ingress_retry_at_debug(op_name, failure_class, retryable) {
                        debug!(
                            target: "izanami::ingress",
                            ?err,
                            operation = op_name,
                            endpoint = label,
                            attempt = attempt_idx + 1,
                            failure_class = failure_class.as_str(),
                            retryable,
                            "ingress endpoint request failed; trying failover"
                        );
                    } else {
                        warn!(
                            target: "izanami::ingress",
                            ?err,
                            operation = op_name,
                            endpoint = label,
                            attempt = attempt_idx + 1,
                            failure_class = failure_class.as_str(),
                            retryable,
                            "ingress endpoint request failed"
                        );
                    }
                    last_error = Some(err);
                    if !retryable {
                        break;
                    }
                }
            }
        }
        match last_error {
            Some(err) => Err(err).wrap_err_with(|| {
                format!("ingress operation `{op_name}` failed after {attempted} attempt(s)")
            }),
            None => Err(eyre!(
                "ingress operation `{op_name}` failed without making an endpoint attempt"
            )),
        }
    }
    fn run_with_failover_until_some_at_with_preference_and_limit<T, F>(
        &self,
        op_name: &'static str,
        preferred_endpoint_idx: Option<usize>,
        now: Instant,
        max_attempts: usize,
        mut operation: F,
    ) -> Result<Option<(usize, T)>>
    where
        F: FnMut(usize, &str) -> Result<Option<T>>,
    {
        let attempt_order = self.attempt_order_at_with_preference(now, preferred_endpoint_idx);
        if attempt_order.is_empty() {
            return Err(eyre!(
                "no ingress endpoints available for operation `{op_name}`"
            ));
        }
        let max_attempts = max_attempts.max(1).min(attempt_order.len());
        let mut last_error = None;
        let mut attempted = 0usize;
        let mut observed_empty = false;
        for (attempt_idx, endpoint_idx) in attempt_order.into_iter().take(max_attempts).enumerate()
        {
            if attempt_idx > 0 {
                self.ingress_stats.record_failover(endpoint_idx);
            }
            let label = self
                .labels
                .get(endpoint_idx)
                .map(String::as_str)
                .unwrap_or("<unknown>");
            attempted = attempted.saturating_add(1);
            match operation(endpoint_idx, label) {
                Ok(Some(value)) => {
                    self.mark_success_at(endpoint_idx, now);
                    return Ok(Some((endpoint_idx, value)));
                }
                Ok(None) => {
                    observed_empty = true;
                    self.mark_success_at(endpoint_idx, now);
                }
                Err(err) => {
                    let failure_class = classify_ingress_failure(&err);
                    let retryable = failure_class.is_retryable();
                    let transitioned_unhealthy = ingress_failure_affects_submit_health(op_name)
                        && self.mark_failure_at(endpoint_idx, now, failure_class);
                    if transitioned_unhealthy {
                        self.ingress_stats.record_endpoint_unhealthy(endpoint_idx);
                        if should_log_ingress_retry_at_debug(op_name, failure_class, retryable) {
                            debug!(
                                target: "izanami::ingress",
                                operation = op_name,
                                endpoint = label,
                                attempt = attempt_idx + 1,
                                failure_class = failure_class.as_str(),
                                "marking ingress endpoint unhealthy"
                            );
                        } else {
                            warn!(
                                target: "izanami::ingress",
                                operation = op_name,
                                endpoint = label,
                                attempt = attempt_idx + 1,
                                failure_class = failure_class.as_str(),
                                "marking ingress endpoint unhealthy"
                            );
                        }
                    }
                    if should_log_ingress_retry_at_debug(op_name, failure_class, retryable) {
                        debug!(
                            target: "izanami::ingress",
                            ?err,
                            operation = op_name,
                            endpoint = label,
                            attempt = attempt_idx + 1,
                            failure_class = failure_class.as_str(),
                            retryable,
                            "ingress endpoint request failed; trying failover"
                        );
                    } else {
                        warn!(
                            target: "izanami::ingress",
                            ?err,
                            operation = op_name,
                            endpoint = label,
                            attempt = attempt_idx + 1,
                            failure_class = failure_class.as_str(),
                            retryable,
                            "ingress endpoint request failed"
                        );
                    }
                    last_error = Some(err);
                    if !retryable {
                        break;
                    }
                }
            }
        }
        if observed_empty {
            return Ok(None);
        }
        match last_error {
            Some(err) => Err(err).wrap_err_with(|| {
                format!("ingress operation `{op_name}` failed after {attempted} attempt(s)")
            }),
            None => Err(eyre!(
                "ingress operation `{op_name}` failed without making an endpoint attempt"
            )),
        }
    }
    fn run_with_failover_excluding_at<T, F>(
        &self,
        op_name: &'static str,
        excluded_endpoint_idx: usize,
        now: Instant,
        mut operation: F,
    ) -> Result<T>
    where
        F: FnMut(usize, &str) -> Result<T>,
    {
        let attempt_order: Vec<_> = self
            .attempt_order_at(now)
            .into_iter()
            .filter(|idx| *idx != excluded_endpoint_idx)
            .collect();
        if attempt_order.is_empty() {
            return Err(eyre!(
                "no alternate ingress endpoints available for operation `{op_name}`"
            ));
        }
        let max_attempts = self.config.max_attempts.max(1).min(attempt_order.len());
        let mut last_error = None;
        let mut attempted = 0usize;
        for (attempt_idx, endpoint_idx) in attempt_order.into_iter().take(max_attempts).enumerate()
        {
            if attempt_idx > 0 {
                self.ingress_stats.record_failover(endpoint_idx);
            }
            let label = self
                .labels
                .get(endpoint_idx)
                .map(String::as_str)
                .unwrap_or("<unknown>");
            attempted = attempted.saturating_add(1);
            match operation(endpoint_idx, label) {
                Ok(value) => {
                    self.mark_success_at(endpoint_idx, now);
                    return Ok(value);
                }
                Err(err) => {
                    let failure_class = classify_ingress_failure(&err);
                    let retryable = failure_class.is_retryable();
                    let transitioned_unhealthy = ingress_failure_affects_submit_health(op_name)
                        && self.mark_failure_at(endpoint_idx, now, failure_class);
                    if transitioned_unhealthy {
                        self.ingress_stats.record_endpoint_unhealthy(endpoint_idx);
                        if should_log_ingress_retry_at_debug(op_name, failure_class, retryable) {
                            debug!(
                                target: "izanami::ingress",
                                operation = op_name,
                                endpoint = label,
                                attempt = attempt_idx + 1,
                                failure_class = failure_class.as_str(),
                                "marking ingress endpoint unhealthy"
                            );
                        } else {
                            warn!(
                                target: "izanami::ingress",
                                operation = op_name,
                                endpoint = label,
                                attempt = attempt_idx + 1,
                                failure_class = failure_class.as_str(),
                                "marking ingress endpoint unhealthy"
                            );
                        }
                    }
                    if should_log_ingress_retry_at_debug(op_name, failure_class, retryable) {
                        debug!(
                            target: "izanami::ingress",
                            ?err,
                            operation = op_name,
                            endpoint = label,
                            attempt = attempt_idx + 1,
                            failure_class = failure_class.as_str(),
                            retryable,
                            "alternate ingress endpoint request failed; trying failover"
                        );
                    } else {
                        warn!(
                            target: "izanami::ingress",
                            ?err,
                            operation = op_name,
                            endpoint = label,
                            attempt = attempt_idx + 1,
                            failure_class = failure_class.as_str(),
                            retryable,
                            "alternate ingress endpoint request failed"
                        );
                    }
                    last_error = Some(err);
                    if !retryable {
                        break;
                    }
                }
            }
        }
        match last_error {
            Some(err) => Err(err).wrap_err_with(|| {
                format!(
                    "ingress operation `{op_name}` failed after {attempted} alternate attempt(s)"
                )
            }),
            None => Err(eyre!(
                "ingress operation `{op_name}` failed without making an alternate endpoint attempt"
            )),
        }
    }
    fn probe_due_at(&self, state: &EndpointHealthState, now: Instant) -> bool {
        state
            .last_probe_at
            .is_none_or(|last| now.saturating_duration_since(last) >= self.config.reprobe_interval)
    }
    fn all_unhealthy_probe_slot_available(&self, now: Instant, reserve: bool) -> bool {
        let Ok(mut guard) = self.all_unhealthy_probe_at.lock() else {
            return true;
        };
        let due = guard
            .is_none_or(|last| now.saturating_duration_since(last) >= self.config.reprobe_interval);
        if due && reserve {
            *guard = Some(now);
        }
        due
    }
    fn lagging_flags_at(&self, now: Instant, len: usize) -> Vec<bool> {
        let lag_snapshot = self
            .lag_snapshot
            .lock()
            .ok()
            .and_then(|guard| (*guard).clone())
            .filter(|snapshot| snapshot.peer_heights.len() == len);
        let _lag_snapshot_age = lag_snapshot
            .as_ref()
            .map(|snapshot| now.saturating_duration_since(snapshot.observed_at));
        lag_snapshot
            .as_ref()
            .map(|snapshot| {
                snapshot
                    .peer_heights
                    .iter()
                    .map(|height| {
                        height.is_some_and(|height| {
                            snapshot.quorum_min_height.saturating_sub(height)
                                > IZANAMI_STRICT_HEIGHT_DIVERGENCE_MAX_BLOCKS
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec![false; len])
    }
    fn attempt_order_with_state(
        &self,
        state: &mut [EndpointHealthState],
        lagging_flags: &[bool],
        now: Instant,
        base_idx: usize,
        mark_probe_timestamps: bool,
    ) -> Vec<usize> {
        let len = state.len();
        let has_non_lagging_endpoint = lagging_flags.iter().any(|flag| !flag);
        let mut healthy = Vec::with_capacity(len);
        let mut probes = Vec::new();
        let mut sticky_probe_candidates = Vec::new();
        let mut lagging_fallback_healthy = Vec::new();
        let mut lagging_fallback_unhealthy = Vec::new();
        let mut forced_probe: Option<(usize, Instant)> = None;
        for offset in 0..len {
            let idx = (base_idx + offset) % len;
            let excluded_by_lag = has_non_lagging_endpoint && lagging_flags[idx];
            let endpoint_state = &mut state[idx];
            let still_unhealthy = endpoint_state
                .unhealthy_until
                .is_some_and(|until| now < until);
            if excluded_by_lag {
                if !still_unhealthy {
                    endpoint_state.endpoint_state = IngressEndpointState::LaggingExcluded;
                }
                if still_unhealthy {
                    lagging_fallback_unhealthy.push(idx);
                } else {
                    lagging_fallback_healthy.push(idx);
                }
                continue;
            }
            if !still_unhealthy {
                endpoint_state.unhealthy_until = None;
                endpoint_state.sticky_unhealthy_until = None;
                endpoint_state.endpoint_state = IngressEndpointState::Healthy;
                healthy.push(idx);
                continue;
            }
            if self.probe_due_at(endpoint_state, now) {
                let sticky_active = endpoint_state
                    .sticky_unhealthy_until
                    .is_some_and(|until| now < until);
                if sticky_active {
                    if let Some(next_probe_window) = endpoint_state.sticky_unhealthy_until {
                        endpoint_state.endpoint_state =
                            IngressEndpointState::QueuePressureCooldown {
                                streak: endpoint_state.consecutive_queue_pressure_failures.max(1),
                                next_probe_window,
                            };
                    }
                    sticky_probe_candidates.push(idx);
                } else {
                    if let Some(next_probe_window) = endpoint_state.unhealthy_until {
                        endpoint_state.endpoint_state =
                            IngressEndpointState::UnhealthyRetryable { next_probe_window };
                    }
                    probes.push(idx);
                }
            }
            if let Some(unhealthy_until) = endpoint_state.unhealthy_until {
                let should_replace = forced_probe
                    .map(|(_, current_until)| unhealthy_until < current_until)
                    .unwrap_or(true);
                if should_replace {
                    forced_probe = Some((idx, unhealthy_until));
                }
            }
        }
        if healthy.is_empty() {
            if !probes.is_empty() {
                // Keep exactly one unhealthy probe candidate per ordering pass.
                probes.truncate(1);
            } else if let Some(idx) = sticky_probe_candidates.first().copied() {
                probes.push(idx);
            }
        }
        if healthy.is_empty() && probes.is_empty() {
            if let Some(idx) = lagging_fallback_healthy.first().copied() {
                probes.push(idx);
            } else if let Some(idx) = lagging_fallback_unhealthy.first().copied() {
                let probe_due = state
                    .get(idx)
                    .is_some_and(|endpoint_state| self.probe_due_at(endpoint_state, now));
                if probe_due {
                    probes.push(idx);
                }
            } else if let Some((idx, _)) = forced_probe {
                let probe_due = state
                    .get(idx)
                    .is_some_and(|endpoint_state| self.probe_due_at(endpoint_state, now));
                if probe_due {
                    probes.push(idx);
                }
            }
        }
        if healthy.is_empty()
            && !probes.is_empty()
            && !self.all_unhealthy_probe_slot_available(now, mark_probe_timestamps)
        {
            probes.clear();
        }
        if mark_probe_timestamps {
            for idx in &probes {
                if let Some(endpoint_state) = state.get_mut(*idx) {
                    endpoint_state.last_probe_at = Some(now);
                }
            }
        }
        healthy.extend(probes);
        healthy
    }
    fn attempt_order_preview_at(&self, now: Instant) -> Vec<usize> {
        self.attempt_order_preview_at_with_preference(now, None)
    }
    fn attempt_order_preview_at_with_preference(
        &self,
        now: Instant,
        preferred_endpoint_idx: Option<usize>,
    ) -> Vec<usize> {
        let len = self.labels.len();
        if len == 0 {
            return Vec::new();
        }
        let lagging_flags = self.lagging_flags_at(now, len);
        let base_idx = self.base_index(len, preferred_endpoint_idx, false);
        let state = self
            .state
            .lock()
            .expect("endpoint health state mutex should not be poisoned")
            .clone();
        let mut preview_state = state;
        self.attempt_order_with_state(
            preview_state.as_mut_slice(),
            &lagging_flags,
            now,
            base_idx,
            false,
        )
    }
    fn submission_backpressure_delay_at(&self, now: Instant) -> Option<Duration> {
        if !self.attempt_order_preview_at(now).is_empty() {
            return None;
        }
        let guard = self
            .state
            .lock()
            .expect("endpoint health state mutex should not be poisoned");
        let mut next_delay: Option<Duration> = None;
        for endpoint_state in guard.iter() {
            if let Some(last_probe_at) = endpoint_state.last_probe_at {
                let elapsed = now.saturating_duration_since(last_probe_at);
                if elapsed < self.config.reprobe_interval {
                    let remaining = self.config.reprobe_interval.saturating_sub(elapsed);
                    next_delay =
                        Some(next_delay.map_or(remaining, |current| current.min(remaining)));
                }
            }
            if let Some(unhealthy_until) = endpoint_state.unhealthy_until
                && now < unhealthy_until
            {
                let remaining = unhealthy_until.saturating_duration_since(now);
                next_delay = Some(next_delay.map_or(remaining, |current| current.min(remaining)));
            }
        }
        Some(
            next_delay
                .unwrap_or_else(|| Duration::from_millis(IZANAMI_QUEUE_TIMEOUT_RETRY_BACKOFF_MS))
                .max(Duration::from_millis(1)),
        )
    }
    fn attempt_order_at(&self, now: Instant) -> Vec<usize> {
        self.attempt_order_at_with_preference(now, None)
    }
    fn attempt_order_at_with_preference(
        &self,
        now: Instant,
        preferred_endpoint_idx: Option<usize>,
    ) -> Vec<usize> {
        let len = self.labels.len();
        if len == 0 {
            return Vec::new();
        }
        let lagging_flags = self.lagging_flags_at(now, len);
        let base_idx = self.base_index(len, preferred_endpoint_idx, true);
        let mut guard = self
            .state
            .lock()
            .expect("endpoint health state mutex should not be poisoned");
        self.attempt_order_with_state(guard.as_mut_slice(), &lagging_flags, now, base_idx, true)
    }
    fn base_index(
        &self,
        len: usize,
        preferred_endpoint_idx: Option<usize>,
        increment_cursor: bool,
    ) -> usize {
        if len == 0 {
            return 0;
        }
        if let Some(preferred_endpoint_idx) = preferred_endpoint_idx {
            return preferred_endpoint_idx % len;
        }
        let base = if increment_cursor {
            self.cursor.fetch_add(1, Ordering::Relaxed)
        } else {
            self.cursor.load(Ordering::Relaxed)
        };
        let base_idx_u64 = base % u64::try_from(len).unwrap_or(1);
        usize::try_from(base_idx_u64).unwrap_or(0)
    }
    fn mark_success_at(&self, endpoint_idx: usize, now: Instant) {
        if let Ok(mut guard) = self.state.lock() {
            let all_endpoints_unhealthy = guard
                .iter()
                .all(|state| state.unhealthy_until.is_some_and(|until| now < until));
            if let Some(state) = guard.get_mut(endpoint_idx) {
                if state
                    .sticky_unhealthy_until
                    .is_some_and(|until| now < until)
                {
                    if all_endpoints_unhealthy {
                        state.consecutive_failures = 0;
                        state.consecutive_queue_pressure_failures = 0;
                        state.unhealthy_until = None;
                        state.sticky_unhealthy_until = None;
                        state.endpoint_state = IngressEndpointState::Healthy;
                        return;
                    }
                    if let Some(next_probe_window) = state.sticky_unhealthy_until {
                        state.endpoint_state = IngressEndpointState::QueuePressureCooldown {
                            streak: state.consecutive_queue_pressure_failures.max(1),
                            next_probe_window,
                        };
                    }
                    return;
                }
                state.consecutive_failures = 0;
                state.consecutive_queue_pressure_failures = 0;
                state.unhealthy_until = None;
                state.sticky_unhealthy_until = None;
                state.endpoint_state = IngressEndpointState::Healthy;
            }
        }
    }
    fn mark_failure_at(
        &self,
        endpoint_idx: usize,
        now: Instant,
        failure_class: IngressFailureClass,
    ) -> bool {
        let Ok(mut guard) = self.state.lock() else {
            return false;
        };
        let Some(state) = guard.get_mut(endpoint_idx) else {
            return false;
        };
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        if matches!(failure_class, IngressFailureClass::QueuePressure) {
            state.consecutive_queue_pressure_failures =
                state.consecutive_queue_pressure_failures.saturating_add(1);
        } else {
            state.consecutive_queue_pressure_failures = 0;
        }
        if !failure_class.is_retryable() {
            return false;
        }
        let failure_threshold = self.config.unhealthy_failure_threshold;
        if state.consecutive_failures < failure_threshold {
            return false;
        }
        let cooldown = self.config.unhealthy_cooldown;
        let was_unhealthy = state.unhealthy_until.is_some_and(|until| now < until);
        let unhealthy_until = now.checked_add(cooldown).unwrap_or(now);
        state.unhealthy_until = Some(unhealthy_until);
        if matches!(failure_class, IngressFailureClass::QueuePressure) {
            state.sticky_unhealthy_until = Some(unhealthy_until);
            state.endpoint_state = IngressEndpointState::QueuePressureCooldown {
                streak: state.consecutive_queue_pressure_failures.max(1),
                next_probe_window: unhealthy_until,
            };
        } else {
            state.sticky_unhealthy_until = None;
            state.endpoint_state = IngressEndpointState::UnhealthyRetryable {
                next_probe_window: unhealthy_until,
            };
        }
        !was_unhealthy
    }
    fn mark_endpoint_sticky_unhealthy_until(&self, endpoint_idx: usize, until: Instant) {
        let Ok(mut guard) = self.state.lock() else {
            return;
        };
        let Some(state) = guard.get_mut(endpoint_idx) else {
            return;
        };
        state.consecutive_failures = self.config.unhealthy_failure_threshold.max(1);
        state.consecutive_queue_pressure_failures = 0;
        state.unhealthy_until = Some(until);
        state.sticky_unhealthy_until = Some(until);
        state.endpoint_state = IngressEndpointState::UnhealthyRetryable {
            next_probe_window: until,
        };
    }
    #[cfg(test)]
    fn endpoint_state(&self, endpoint_idx: usize) -> EndpointHealthState {
        self.state
            .lock()
            .expect("endpoint health state mutex should not be poisoned")
            .get(endpoint_idx)
            .copied()
            .unwrap_or_default()
    }
}
#[derive(Clone)]
struct IngressEndpoint {
    peer: NetworkPeer,
    label: String,
}
#[derive(Clone)]
struct IngressEndpointPool {
    endpoints: Arc<Vec<IngressEndpoint>>,
    endpoint_index_by_peer: Arc<BTreeMap<PeerId, usize>>,
    submit_client_cache: Arc<StdMutex<BTreeMap<(usize, String), Client>>>,
    submit_request_timeout: Duration,
    health: EndpointHealthPool,
}
impl IngressEndpointPool {
    fn from_peers(
        peers: &[NetworkPeer],
        config: IngressEndpointPoolConfig,
        ingress_stats: Arc<IngressStats>,
        submit_request_timeout: Duration,
    ) -> Self {
        let mut endpoints: Vec<_> = peers
            .iter()
            .cloned()
            .map(|peer| IngressEndpoint {
                label: peer.torii_url(),
                peer,
            })
            .collect();
        endpoints.sort_by(|lhs, rhs| {
            lhs.peer
                .id()
                .cmp(&rhs.peer.id())
                .then_with(|| lhs.label.cmp(&rhs.label))
        });
        let labels = endpoints
            .iter()
            .map(|endpoint| endpoint.label.clone())
            .collect();
        let endpoint_index_by_peer = endpoints
            .iter()
            .enumerate()
            .map(|(idx, endpoint)| (endpoint.peer.id().clone(), idx))
            .collect();
        let health = EndpointHealthPool::new(labels, config, ingress_stats);
        Self {
            endpoints: Arc::new(endpoints),
            endpoint_index_by_peer: Arc::new(endpoint_index_by_peer),
            submit_client_cache: Arc::new(StdMutex::new(BTreeMap::new())),
            submit_request_timeout,
            health,
        }
    }
    fn reserve_fault_target_ingress_until(
        &self,
        peers: &[NetworkPeer],
        fault_targets: &[usize],
        until: Instant,
    ) {
        for peer_idx in fault_targets {
            let Some(peer) = peers.get(*peer_idx) else {
                continue;
            };
            let Some(endpoint_idx) = self.endpoint_index_by_peer.get(&peer.id()).copied() else {
                continue;
            };
            self.health
                .mark_endpoint_sticky_unhealthy_until(endpoint_idx, until);
            debug!(
                target: "izanami::ingress",
                peer_index = *peer_idx,
                endpoint_idx,
                endpoint = %self
                    .endpoints
                    .get(endpoint_idx)
                    .map(|endpoint| endpoint.label.as_str())
                    .unwrap_or("<unknown>"),
                "reserved fault-target peer away from client ingress"
            );
        }
    }
    fn update_lag_snapshot(
        &self,
        quorum_min_height: u64,
        sampled_heights: &[(PeerId, u64)],
        sampled_at: Instant,
    ) {
        let mut peer_heights = vec![None; self.endpoints.len()];
        for (peer_id, height) in sampled_heights {
            if let Some(endpoint_idx) = self.endpoint_index_by_peer.get(peer_id)
                && let Some(slot) = peer_heights.get_mut(*endpoint_idx)
            {
                *slot = Some(*height);
            }
        }
        self.health.update_lag_snapshot(IngressLagSnapshot {
            quorum_min_height,
            peer_heights,
            observed_at: sampled_at,
        });
    }
    fn run_with_failover_preferred_with_endpoint<T, F>(
        &self,
        op_name: &'static str,
        submitter_idx: usize,
        mut operation: F,
    ) -> Result<(usize, T)>
    where
        F: FnMut(&NetworkPeer) -> Result<T>,
    {
        let endpoints = Arc::clone(&self.endpoints);
        let preferred_endpoint_idx = self.preferred_endpoint_index(submitter_idx).unwrap_or(0);
        self.health.run_with_failover_preferred(
            op_name,
            preferred_endpoint_idx,
            move |endpoint_idx, _label| {
                let endpoint = endpoints
                    .get(endpoint_idx)
                    .ok_or_else(|| eyre!("endpoint index {endpoint_idx} out of range"))?;
                operation(&endpoint.peer).map(|value| (endpoint_idx, value))
            },
        )
    }
    async fn run_with_failover_preferred_with_endpoint_async<T, F, Fut>(
        &self,
        op_name: &'static str,
        submitter_idx: usize,
        mut operation: F,
    ) -> Result<(usize, T)>
    where
        F: FnMut(usize, NetworkPeer) -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let preferred_endpoint_idx = self.preferred_endpoint_index(submitter_idx).unwrap_or(0);
        let attempt_order = self
            .health
            .attempt_order_at_with_preference(Instant::now(), Some(preferred_endpoint_idx));
        if attempt_order.is_empty() {
            return Err(eyre!(
                "no ingress endpoints available for operation `{op_name}`"
            ));
        }
        let max_attempts = self
            .health
            .config
            .max_attempts
            .max(1)
            .min(attempt_order.len());
        let mut last_error = None;
        let mut attempted = 0usize;
        for (attempt_idx, endpoint_idx) in attempt_order.into_iter().take(max_attempts).enumerate()
        {
            if attempt_idx > 0 {
                self.health.ingress_stats.record_failover(endpoint_idx);
            }
            let endpoint = self
                .endpoints
                .get(endpoint_idx)
                .ok_or_else(|| eyre!("endpoint index {endpoint_idx} out of range"))?
                .clone();
            attempted = attempted.saturating_add(1);
            match operation(endpoint_idx, endpoint.peer).await {
                Ok(value) => {
                    self.health.mark_success_at(endpoint_idx, Instant::now());
                    return Ok((endpoint_idx, value));
                }
                Err(err) => {
                    let failure_class = classify_ingress_failure(&err);
                    let retryable = failure_class.is_retryable();
                    let transitioned_unhealthy = ingress_failure_affects_submit_health(op_name)
                        && self
                            .health
                            .mark_failure_at(endpoint_idx, Instant::now(), failure_class);
                    if transitioned_unhealthy {
                        self.health
                            .ingress_stats
                            .record_endpoint_unhealthy(endpoint_idx);
                        if should_log_ingress_retry_at_debug(op_name, failure_class, retryable) {
                            debug!(
                                target: "izanami::ingress",
                                operation = op_name,
                                endpoint = %endpoint.label,
                                attempt = attempt_idx + 1,
                                failure_class = failure_class.as_str(),
                                "marking ingress endpoint unhealthy"
                            );
                        } else {
                            warn!(
                                target: "izanami::ingress",
                                operation = op_name,
                                endpoint = %endpoint.label,
                                attempt = attempt_idx + 1,
                                failure_class = failure_class.as_str(),
                                "marking ingress endpoint unhealthy"
                            );
                        }
                    }
                    if should_log_ingress_retry_at_debug(op_name, failure_class, retryable) {
                        debug!(
                            target: "izanami::ingress",
                            ?err,
                            operation = op_name,
                            endpoint = %endpoint.label,
                            attempt = attempt_idx + 1,
                            failure_class = failure_class.as_str(),
                            retryable,
                            "ingress endpoint request failed; trying failover"
                        );
                    } else {
                        warn!(
                            target: "izanami::ingress",
                            ?err,
                            operation = op_name,
                            endpoint = %endpoint.label,
                            attempt = attempt_idx + 1,
                            failure_class = failure_class.as_str(),
                            retryable,
                            "ingress endpoint request failed"
                        );
                    }
                    last_error = Some(err);
                    if !retryable {
                        break;
                    }
                }
            }
        }
        match last_error {
            Some(err) => Err(err).wrap_err_with(|| {
                format!("ingress operation `{op_name}` failed after {attempted} attempt(s)")
            }),
            None => Err(eyre!(
                "ingress operation `{op_name}` failed without making an endpoint attempt"
            )),
        }
    }
    fn run_with_failover_excluding<T, F>(
        &self,
        op_name: &'static str,
        excluded_endpoint_idx: usize,
        mut operation: F,
    ) -> Result<(usize, T)>
    where
        F: FnMut(&NetworkPeer) -> Result<T>,
    {
        let endpoints = Arc::clone(&self.endpoints);
        self.health.run_with_failover_excluding(
            op_name,
            excluded_endpoint_idx,
            move |endpoint_idx, _label| {
                let endpoint = endpoints
                    .get(endpoint_idx)
                    .ok_or_else(|| eyre!("endpoint index {endpoint_idx} out of range"))?;
                operation(&endpoint.peer).map(|value| (endpoint_idx, value))
            },
        )
    }
    fn select_endpoint_preferred(
        &self,
        op_name: &'static str,
        submitter_idx: usize,
    ) -> Result<usize> {
        let preferred_endpoint_idx = self.preferred_endpoint_index(submitter_idx).unwrap_or(0);
        self.health
            .select_endpoint_preferred(op_name, preferred_endpoint_idx)
    }
    fn run_on_endpoint<T, F>(
        &self,
        op_name: &'static str,
        endpoint_idx: usize,
        operation: F,
    ) -> Result<T>
    where
        F: FnOnce(&NetworkPeer) -> Result<T>,
    {
        let endpoints = Arc::clone(&self.endpoints);
        self.health
            .run_on_endpoint(op_name, endpoint_idx, move |idx, _label| {
                let endpoint = endpoints
                    .get(idx)
                    .ok_or_else(|| eyre!("endpoint index {idx} out of range"))?;
                operation(&endpoint.peer)
            })
    }
    fn cached_submit_client_for(
        &self,
        endpoint_idx: usize,
        signer: &AccountRecord,
        mode: SubmissionConfirmationMode,
    ) -> Result<Client> {
        let cache_key = (endpoint_idx, signer.id.to_string());
        if let Ok(guard) = self.submit_client_cache.lock()
            && let Some(client) = guard.get(&cache_key)
        {
            return Ok(client.clone());
        }
        let endpoint = self
            .endpoints
            .get(endpoint_idx)
            .ok_or_else(|| eyre!("endpoint index {endpoint_idx} out of range"))?;
        let client = tune_ingress_client(
            endpoint
                .peer
                .client_for(&signer.id, signer.key_pair.private_key().clone()),
            mode,
            self.submit_request_timeout,
        )?;
        if let Ok(mut guard) = self.submit_client_cache.lock() {
            guard.insert(cache_key, client.clone());
        }
        Ok(client)
    }
    fn endpoint_count(&self) -> usize {
        self.endpoints.len()
    }
    fn submission_backpressure_delay(&self, now: Instant) -> Option<Duration> {
        self.health.submission_backpressure_delay_at(now)
    }
    fn preferred_endpoint_index(&self, submitter_idx: usize) -> Option<usize> {
        (!self.endpoints.is_empty()).then_some(submitter_idx % self.endpoints.len())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IngressFailureClass {
    NonRetryable,
    Retryable,
    QueuePressure,
}
impl IngressFailureClass {
    const fn is_retryable(self) -> bool {
        !matches!(self, Self::NonRetryable)
    }
    const fn as_str(self) -> &'static str {
        match self {
            Self::NonRetryable => "non_retryable",
            Self::Retryable => "retryable",
            Self::QueuePressure => "queue_pressure",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IngressOperationClass {
    Submit,
    StatusRead,
}
fn classify_ingress_operation(op_name: &str) -> IngressOperationClass {
    if op_name.contains("query") || op_name.contains("confirmation") || op_name.contains("precheck")
    {
        IngressOperationClass::StatusRead
    } else {
        IngressOperationClass::Submit
    }
}
fn ingress_failure_affects_submit_health(op_name: &str) -> bool {
    matches!(
        classify_ingress_operation(op_name),
        IngressOperationClass::Submit
    )
}
fn should_log_ingress_retry_at_debug(
    op_name: &str,
    failure_class: IngressFailureClass,
    retryable: bool,
) -> bool {
    retryable
        && (matches!(
            classify_ingress_operation(op_name),
            IngressOperationClass::StatusRead
        ) || matches!(failure_class, IngressFailureClass::QueuePressure))
}
fn is_shutdown_noise_status_read_failure(
    op_name: &str,
    error: &color_eyre::Report,
    run_control: &RunControl,
) -> bool {
    run_control.should_stop()
        && matches!(
            classify_ingress_operation(op_name),
            IngressOperationClass::StatusRead
        )
        && {
            let message = ingress_error_message(error);
            message.contains("connection refused") || message.contains("transaction did not reach")
        }
}
fn is_audit_confirmation_window_elapsed(error: &color_eyre::Report) -> bool {
    let message = ingress_error_message(error);
    message.contains("transaction did not reach")
        && message.contains("state-resolved applied")
        && message.contains("within")
}
fn ingress_error_message(error: &color_eyre::Report) -> String {
    format!("{error:#}").to_ascii_lowercase()
}
fn is_route_unavailable_message(message: &str) -> bool {
    message.contains("route_unavailable")
}
fn is_route_unavailable_error(error: &color_eyre::Report) -> bool {
    is_route_unavailable_message(&ingress_error_message(error))
}
fn is_idempotent_duplicate_submission_message(message: &str) -> bool {
    message.contains("repeated instruction")
        || message.contains("repetition of")
        || message.contains("already exists")
}
fn is_idempotent_duplicate_submission(error: &color_eyre::Report) -> bool {
    let message = ingress_error_message(error);
    is_idempotent_duplicate_submission_message(&message)
}
fn is_ingress_queue_pressure_message(message: &str) -> bool {
    message.contains("transaction queued for too long")
        || message.contains("transaction did not reach")
        || message.contains("status_timeout_ms")
        || message.contains("haven't got tx confirmation within")
        || contains_http_429_status(message)
}
fn is_ingress_endpoint_backpressure_message(message: &str) -> bool {
    message.contains("no ingress endpoints available for operation")
}
fn classify_ingress_failure(error: &color_eyre::Report) -> IngressFailureClass {
    let message = ingress_error_message(error);
    if is_ingress_queue_pressure_message(&message) {
        return IngressFailureClass::QueuePressure;
    }
    if message.contains("timed out")
        || message.contains("timeout")
        || message.contains("connection refused")
        || message.contains("connection reset")
        || message.contains("connection closed before message completed")
        || message.contains("can't assign requested address")
        || message.contains("broken pipe")
        || contains_http_5xx_status(&message)
    {
        IngressFailureClass::Retryable
    } else {
        IngressFailureClass::NonRetryable
    }
}
#[cfg(test)]
fn is_ingress_failover_retryable(error: &color_eyre::Report) -> bool {
    classify_ingress_failure(error).is_retryable()
}
fn is_ingress_queue_timeout_retryable(error: &color_eyre::Report) -> bool {
    let message = ingress_error_message(error);
    is_ingress_queue_pressure_message(&message)
        || is_ingress_endpoint_backpressure_message(&message)
}
#[cfg(test)]
fn queue_timeout_retry_delay(
    backoff: Duration,
    endpoint_backpressure: bool,
    dynamic_backpressure_delay: Option<Duration>,
) -> Duration {
    if endpoint_backpressure {
        backoff.max(
            dynamic_backpressure_delay
                .unwrap_or_else(|| Duration::from_millis(IZANAMI_INGRESS_REPROBE_INTERVAL_MS)),
        )
    } else {
        backoff
    }
}
#[cfg(test)]
fn run_with_queue_timeout_retry_with_policy<F>(
    plan_label: &'static str,
    max_retry_attempts: u32,
    initial_backoff: Duration,
    submit: F,
) -> Result<()>
where
    F: FnMut() -> Result<()>,
{
    run_with_queue_timeout_retry_with_policy_and_delay(
        plan_label,
        max_retry_attempts,
        initial_backoff,
        || None,
        submit,
    )
}
#[cfg(test)]
fn run_with_queue_timeout_retry_with_policy_and_delay<F, G>(
    plan_label: &'static str,
    max_retry_attempts: u32,
    initial_backoff: Duration,
    mut no_endpoint_backpressure_delay: G,
    mut submit: F,
) -> Result<()>
where
    F: FnMut() -> Result<()>,
    G: FnMut() -> Option<Duration>,
{
    let mut backoff = initial_backoff;
    let mut retryable_attempts = 0_u32;
    let mut endpoint_backpressure_retries = 0_u32;
    let max_endpoint_backpressure_retries = max_retry_attempts
        .saturating_mul(IZANAMI_QUEUE_TIMEOUT_ENDPOINT_BACKPRESSURE_RETRY_MULTIPLIER)
        .max(1);
    loop {
        match submit() {
            Ok(()) => return Ok(()),
            Err(err) if is_idempotent_duplicate_submission(&err) => {
                warn!(
                    target: "izanami::workload",
                    plan = plan_label,
                    ?err,
                    "treating duplicate submission rejection as idempotent success"
                );
                return Ok(());
            }
            Err(err) if is_ingress_queue_timeout_retryable(&err) => {
                let error_message = ingress_error_message(&err);
                let endpoint_backpressure =
                    is_ingress_endpoint_backpressure_message(&error_message);
                let retry_budget_available = if endpoint_backpressure {
                    endpoint_backpressure_retries < max_endpoint_backpressure_retries
                } else {
                    retryable_attempts < max_retry_attempts
                };
                if !retry_budget_available {
                    return Err(err);
                }
                let dynamic_backpressure_delay = if endpoint_backpressure {
                    no_endpoint_backpressure_delay()
                } else {
                    None
                };
                if endpoint_backpressure {
                    endpoint_backpressure_retries = endpoint_backpressure_retries.saturating_add(1);
                } else {
                    retryable_attempts = retryable_attempts.saturating_add(1);
                }
                let retry_in = queue_timeout_retry_delay(
                    backoff,
                    endpoint_backpressure,
                    dynamic_backpressure_delay,
                );
                let next_attempt = retryable_attempts
                    .saturating_add(endpoint_backpressure_retries)
                    .saturating_add(1);
                debug!(
                    target: "izanami::workload",
                    plan = plan_label,
                    next_attempt,
                    max_attempts = max_retry_attempts
                        .saturating_add(max_endpoint_backpressure_retries)
                        .saturating_add(1),
                    endpoint_backpressure,
                    ?dynamic_backpressure_delay,
                    ?retry_in,
                    ?err,
                    "submission ingress backpressure observed; retrying plan submission"
                );
                if !retry_in.is_zero() {
                    std::thread::sleep(retry_in);
                }
                backoff = backoff.saturating_mul(2);
            }
            Err(err) => return Err(err),
        }
    }
}
fn run_with_queue_timeout_retry_with_policy_and_delay_result<T, F, G>(
    plan_label: &'static str,
    max_retry_attempts: u32,
    initial_backoff: Duration,
    mut no_endpoint_backpressure_delay: G,
    mut submit: F,
) -> Result<T>
where
    F: FnMut() -> Result<T>,
    G: FnMut() -> Option<Duration>,
{
    let mut backoff = initial_backoff;
    let mut retryable_attempts = 0_u32;
    let mut endpoint_backpressure_retries = 0_u32;
    let max_endpoint_backpressure_retries = max_retry_attempts
        .saturating_mul(IZANAMI_QUEUE_TIMEOUT_ENDPOINT_BACKPRESSURE_RETRY_MULTIPLIER)
        .max(1);
    loop {
        match submit() {
            Ok(value) => return Ok(value),
            Err(err) if is_ingress_queue_timeout_retryable(&err) => {
                let error_message = ingress_error_message(&err);
                let endpoint_backpressure =
                    is_ingress_endpoint_backpressure_message(&error_message);
                let retry_budget_available = if endpoint_backpressure {
                    endpoint_backpressure_retries < max_endpoint_backpressure_retries
                } else {
                    retryable_attempts < max_retry_attempts
                };
                if !retry_budget_available {
                    warn!(
                        target: "izanami::workload",
                        plan = plan_label,
                        endpoint_backpressure,
                        retryable_attempts,
                        endpoint_backpressure_retries,
                        max_retry_attempts,
                        max_endpoint_backpressure_retries,
                        ?err,
                        "ingress queue timeout retry budget exhausted"
                    );
                    return Err(err);
                }
                if endpoint_backpressure {
                    endpoint_backpressure_retries = endpoint_backpressure_retries.saturating_add(1);
                } else {
                    retryable_attempts = retryable_attempts.saturating_add(1);
                }
                let delay = no_endpoint_backpressure_delay().unwrap_or(backoff);
                debug!(
                    target: "izanami::workload",
                    plan = plan_label,
                    retryable_attempts,
                    endpoint_backpressure_retries,
                    max_retry_attempts,
                    max_endpoint_backpressure_retries,
                    delay_ms = delay.as_millis(),
                    endpoint_backpressure,
                    ?err,
                    "retrying after ingress queue timeout"
                );
                std::thread::sleep(delay);
                if !endpoint_backpressure {
                    backoff = backoff.saturating_mul(2);
                }
            }
            Err(err) if is_idempotent_duplicate_submission(&err) => {
                warn!(
                    target: "izanami::workload",
                    plan = plan_label,
                    ?err,
                    "duplicate submission rejected because the caller requires a concrete outcome"
                );
                return Err(err);
            }
            Err(err) => return Err(err),
        }
    }
}
async fn run_with_queue_timeout_retry_with_policy_and_delay_result_async<T, F, Fut, G>(
    plan_label: &'static str,
    max_retry_attempts: u32,
    initial_backoff: Duration,
    mut no_endpoint_backpressure_delay: G,
    mut submit: F,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
    G: FnMut() -> Option<Duration>,
{
    let mut backoff = initial_backoff;
    let mut retryable_attempts = 0_u32;
    let mut endpoint_backpressure_retries = 0_u32;
    let max_endpoint_backpressure_retries = max_retry_attempts
        .saturating_mul(IZANAMI_QUEUE_TIMEOUT_ENDPOINT_BACKPRESSURE_RETRY_MULTIPLIER)
        .max(1);
    loop {
        match submit().await {
            Ok(value) => return Ok(value),
            Err(err) if is_ingress_queue_timeout_retryable(&err) => {
                let error_message = ingress_error_message(&err);
                let endpoint_backpressure =
                    is_ingress_endpoint_backpressure_message(&error_message);
                let retry_budget_available = if endpoint_backpressure {
                    endpoint_backpressure_retries < max_endpoint_backpressure_retries
                } else {
                    retryable_attempts < max_retry_attempts
                };
                if !retry_budget_available {
                    warn!(
                        target: "izanami::workload",
                        plan = plan_label,
                        endpoint_backpressure,
                        retryable_attempts,
                        endpoint_backpressure_retries,
                        max_retry_attempts,
                        max_endpoint_backpressure_retries,
                        ?err,
                        "ingress queue timeout retry budget exhausted"
                    );
                    return Err(err);
                }
                if endpoint_backpressure {
                    endpoint_backpressure_retries = endpoint_backpressure_retries.saturating_add(1);
                } else {
                    retryable_attempts = retryable_attempts.saturating_add(1);
                }
                let delay = no_endpoint_backpressure_delay().unwrap_or(backoff);
                debug!(
                    target: "izanami::workload",
                    plan = plan_label,
                    retryable_attempts,
                    endpoint_backpressure_retries,
                    max_retry_attempts,
                    max_endpoint_backpressure_retries,
                    delay_ms = delay.as_millis(),
                    endpoint_backpressure,
                    ?err,
                    "retrying after ingress queue timeout"
                );
                if !delay.is_zero() {
                    time::sleep(delay).await;
                }
                if !endpoint_backpressure {
                    backoff = backoff.saturating_mul(2);
                }
            }
            Err(err) if is_idempotent_duplicate_submission(&err) => {
                warn!(
                    target: "izanami::workload",
                    plan = plan_label,
                    ?err,
                    "duplicate submission rejected because the caller requires a concrete outcome"
                );
                return Err(err);
            }
            Err(err) => return Err(err),
        }
    }
}
fn contains_http_5xx_status(message: &str) -> bool {
    (500..=599).any(|status| {
        let code = status.to_string();
        message.contains(&format!("status code: {code}"))
            || message.contains(&format!("status: {code}"))
            || message.contains(&format!("http {code}"))
            || message.contains(&format!(" {code} "))
    })
}
fn contains_http_429_status(message: &str) -> bool {
    message.contains("429 too many requests")
        || message.contains("status code: 429")
        || message.contains("status: 429")
        || message.contains("http 429")
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct NposGenesisPreflightSummary {
    peer_with_pop_count: usize,
    register_validator_count: usize,
    activate_validator_count: usize,
    min_self_bond: Quantity,
    stake_distribution: Vec<(Quantity, usize)>,
}
fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis())
        .unwrap_or(u64::MAX)
        .max(1)
}
fn latency_gate_soft_target_blocks(duration: Duration, threshold: Duration) -> u64 {
    duration_ms(duration)
        .div_ceil(duration_ms(threshold))
        .max(1)
}
fn default_nexus_pipeline_time() -> Duration {
    let block_ms =
        u64::try_from(IZANAMI_NPOS_BLOCK_TIME_MS).expect("izanami block time must be non-negative");
    let commit_ms = u64::try_from(IZANAMI_NPOS_COMMIT_TIME_MS)
        .expect("izanami commit time must be non-negative");
    Duration::from_millis(block_ms.saturating_add(commit_ms))
}
fn default_izanami_pipeline_time() -> Duration {
    default_nexus_pipeline_time()
}
fn sumeragi_phase_operator_keypair() -> KeyPair {
    Signatory::Peer.key_pair().clone()
}
fn izanami_npos_parameters(peer_count: usize) -> SumeragiNposParameters {
    let mut params = SumeragiNposParameters::default();
    params.max_validators = u32::try_from(peer_count.max(1)).unwrap_or(u32::MAX);
    params
}
fn npos_min_self_bond_from_genesis(genesis: &GenesisBlock) -> Result<Quantity> {
    let mut params = Parameters::default();
    for tx in genesis.0.external_transactions() {
        let Executable::Instructions(instructions) = tx.instructions() else {
            continue;
        };
        for instruction in instructions {
            let Some(set_param) = instruction.as_any().downcast_ref::<SetParameter>() else {
                continue;
            };
            params.set_parameter(set_param.inner().clone());
        }
    }
    Ok(params
        .custom()
        .get(&SumeragiNposParameters::parameter_id())
        .map(SumeragiNposParameters::from_custom_parameter)
        .transpose()?
        .flatten()
        .unwrap_or_default()
        .min_self_bond()
        .clone())
}
fn instruction_registers_peer_with_pop(instruction: &InstructionBox) -> bool {
    if instruction
        .as_any()
        .downcast_ref::<RegisterPeerWithPop>()
        .is_some()
    {
        return true;
    }
    matches!(
        instruction.as_any().downcast_ref::<RegisterBox>(),
        Some(RegisterBox::Peer(_))
    )
}
#[allow(single_use_lifetimes)]
fn audit_npos_preflight_instructions<'a>(
    instructions: impl IntoIterator<Item = &'a InstructionBox>,
    peer_count: usize,
    bootstrap_public_lanes: &[LaneId],
    min_self_bond: &Quantity,
) -> Result<NposGenesisPreflightSummary> {
    let expected_peers = peer_count.max(1);
    let expected_bootstrap_bindings = expected_peers.saturating_mul(bootstrap_public_lanes.len());
    let expected_bootstrap_lanes: BTreeSet<_> = bootstrap_public_lanes.iter().copied().collect();
    let mut peer_with_pop_count = 0usize;
    let mut register_validator_count = 0usize;
    let mut activate_validator_count = 0usize;
    let mut validator_stakes = BTreeMap::<(LaneId, AccountId), Quantity>::new();
    let mut activated_validators = BTreeSet::<(LaneId, AccountId)>::new();
    for instruction in instructions {
        if instruction_registers_peer_with_pop(instruction) {
            peer_with_pop_count = peer_with_pop_count.saturating_add(1);
        }
        if let Some(register) = instruction
            .as_any()
            .downcast_ref::<RegisterPublicLaneValidator>()
        {
            register_validator_count = register_validator_count.saturating_add(1);
            if !expected_bootstrap_lanes.is_empty()
                && !expected_bootstrap_lanes.contains(&register.lane_id)
            {
                return Err(eyre!(
                    "Izanami NPoS preflight failed: unexpected bootstrap lane {} for validator {}",
                    register.lane_id,
                    register.validator
                ));
            }
            let stake = register.initial_stake.clone();
            if &stake < min_self_bond {
                return Err(eyre!(
                    "Izanami NPoS preflight failed: validator {} initial_stake={} below min_self_bond={}",
                    register.validator,
                    stake,
                    min_self_bond
                ));
            }
            validator_stakes.insert((register.lane_id, register.validator.clone()), stake);
        }
        if let Some(activate) = instruction
            .as_any()
            .downcast_ref::<ActivatePublicLaneValidator>()
        {
            activate_validator_count = activate_validator_count.saturating_add(1);
            activated_validators.insert((activate.lane_id, activate.validator.clone()));
        }
    }
    if peer_with_pop_count != expected_peers {
        return Err(eyre!(
            "Izanami NPoS preflight failed: RegisterPeerWithPop count={} expected={}",
            peer_with_pop_count,
            expected_peers
        ));
    }
    if register_validator_count != expected_bootstrap_bindings {
        return Err(eyre!(
            "Izanami NPoS preflight failed: RegisterPublicLaneValidator count={} expected={}",
            register_validator_count,
            expected_bootstrap_bindings
        ));
    }
    if activate_validator_count != expected_bootstrap_bindings {
        return Err(eyre!(
            "Izanami NPoS preflight failed: ActivatePublicLaneValidator count={} expected={}",
            activate_validator_count,
            expected_bootstrap_bindings
        ));
    }
    let registered_validators: BTreeSet<_> = validator_stakes.keys().cloned().collect();
    let missing_activation: Vec<_> = registered_validators
        .difference(&activated_validators)
        .cloned()
        .collect();
    if !missing_activation.is_empty() {
        return Err(eyre!(
            "Izanami NPoS preflight failed: validator activation missing for {} account(s)",
            missing_activation.len()
        ));
    }
    let unexpected_activation: Vec<_> = activated_validators
        .difference(&registered_validators)
        .cloned()
        .collect();
    if !unexpected_activation.is_empty() {
        return Err(eyre!(
            "Izanami NPoS preflight failed: activation references {} unregistered validator account(s)",
            unexpected_activation.len()
        ));
    }
    let mut stake_distribution = BTreeMap::<Quantity, usize>::new();
    for stake in validator_stakes.values().cloned() {
        *stake_distribution.entry(stake).or_insert(0) += 1;
    }
    if expected_bootstrap_bindings > 0 && stake_distribution.len() != 1 {
        return Err(eyre!(
            "Izanami NPoS preflight failed: validator initial_stake distribution is non-uniform: {:?}",
            stake_distribution
        ));
    }
    Ok(NposGenesisPreflightSummary {
        peer_with_pop_count,
        register_validator_count,
        activate_validator_count,
        min_self_bond: min_self_bond.clone(),
        stake_distribution: stake_distribution.into_iter().collect(),
    })
}
fn audit_npos_genesis_preflight(
    genesis: &GenesisBlock,
    peer_count: usize,
    bootstrap_public_lanes: &[LaneId],
) -> Result<NposGenesisPreflightSummary> {
    let min_self_bond = npos_min_self_bond_from_genesis(genesis)?;
    let mut instructions = Vec::<InstructionBox>::new();
    for tx in genesis.0.external_transactions() {
        let Executable::Instructions(tx_instructions) = tx.instructions() else {
            continue;
        };
        instructions.extend(tx_instructions.iter().cloned());
    }
    audit_npos_preflight_instructions(
        instructions.iter(),
        peer_count,
        bootstrap_public_lanes,
        &min_self_bond,
    )
}
fn is_shared_host_stable_soak(config: &ChaosConfig) -> bool {
    matches!(config.workload_profile, WorkloadProfile::Stable)
        && config.faulty_peers <= 1
        && config.peer_count >= 4
        && config.duration >= Duration::from_secs(IZANAMI_SHARED_HOST_SOAK_MIN_DURATION_SECS)
}
fn is_severe_stopping_recovery_run(config: &ChaosConfig) -> bool {
    matches!(config.workload_profile, WorkloadProfile::Stable)
        && config.peer_count >= 4
        && config.faults.crash_restart()
        && config.faulty_peers.saturating_mul(3) >= config.peer_count.saturating_mul(2)
}
fn submission_confirmation_mode(config: &ChaosConfig) -> SubmissionConfirmationMode {
    if matches!(config.workload_profile, WorkloadProfile::Stable) {
        SubmissionConfirmationMode::AcceptedByIngress
    } else {
        SubmissionConfirmationMode::BlockingApplied
    }
}
fn effective_submission_max_inflight(config: &ChaosConfig) -> usize {
    if matches!(
        submission_confirmation_mode(config),
        SubmissionConfirmationMode::AcceptedByIngress
    ) {
        if !is_severe_stopping_recovery_run(config)
            && config.tps > IZANAMI_STRESS_STABLE_INGRESS_CAP_BYPASS_TPS
        {
            return config.max_inflight.max(1);
        }
        let stable_cap = if is_severe_stopping_recovery_run(config) {
            IZANAMI_STABLE_SEVERE_STOPPING_MAX_INFLIGHT_CAP
        } else {
            IZANAMI_STABLE_INGRESS_MAX_INFLIGHT_CAP
        };
        config.max_inflight.min(stable_cap).max(1)
    } else {
        config.max_inflight.max(1)
    }
}
fn effective_submission_tps(config: &ChaosConfig) -> f64 {
    if matches!(
        submission_confirmation_mode(config),
        SubmissionConfirmationMode::AcceptedByIngress
    ) && is_severe_stopping_recovery_run(config)
    {
        config.tps.min(IZANAMI_STABLE_SEVERE_STOPPING_TPS_CAP)
    } else {
        config.tps
    }
}
fn effective_network_queue_capacity(config: &ChaosConfig) -> i64 {
    let stress_capacity = if config.prebuild_tx_buffer > 0
        && config.tps > IZANAMI_STRESS_STABLE_INGRESS_CAP_BYPASS_TPS
    {
        config.prebuild_tx_buffer
    } else {
        0
    };
    let capacity = stress_capacity.max(usize::try_from(IZANAMI_QUEUE_CAPACITY).expect("positive"));
    i64::try_from(capacity).unwrap_or(i64::MAX)
}
fn effective_ingress_request_timeout(config: &ChaosConfig) -> Duration {
    let baseline = Duration::from_millis(IZANAMI_INGRESS_REQUEST_TIMEOUT_MS);
    if config.prebuild_tx_buffer > 0 && config.tps > IZANAMI_STRESS_STABLE_INGRESS_CAP_BYPASS_TPS {
        config.shutdown_drain_timeout.max(baseline)
    } else {
        baseline
    }
}
fn apply_shared_host_stable_soak_profile(config: &mut ChaosConfig) {
    if !is_shared_host_stable_soak(config) {
        return;
    }
    let original_tps = config.tps;
    let original_max_inflight = config.max_inflight;
    let original_progress_timeout = config.progress_timeout;
    let original_pipeline_time = config.pipeline_time;
    let original_latency_p95_threshold = config.latency_p95_threshold;
    // Preserve operator-selected stress settings while enforcing a minimum load floor
    // for shared-host soaks so runs remain comparable at low load.
    config.tps = config.tps.max(IZANAMI_SHARED_HOST_SOAK_TPS_FLOOR);
    // Keep enough in-flight room to sustain the configured TPS without permit starvation.
    let inflight_floor_from_tps = usize::try_from((config.tps * 2.0).ceil() as u64).unwrap_or(1);
    config.max_inflight = config
        .max_inflight
        .max(IZANAMI_SHARED_HOST_SOAK_MAX_INFLIGHT_FLOOR)
        .max(inflight_floor_from_tps.max(1));
    config.progress_timeout = config.progress_timeout.max(Duration::from_secs(
        IZANAMI_SHARED_HOST_SOAK_PROGRESS_TIMEOUT_FLOOR_SECS,
    ));
    let pipeline_time_floor = Duration::from_millis(IZANAMI_SHARED_HOST_SOAK_PIPELINE_TIME_MS);
    config.pipeline_time = Some(
        config
            .pipeline_time
            .map_or(pipeline_time_floor, |existing| {
                existing.max(pipeline_time_floor)
            }),
    );
    if config.latency_p95_threshold.is_none() {
        config.latency_p95_threshold = Some(Duration::from_secs(
            IZANAMI_SHARED_HOST_SOAK_LATENCY_P95_THRESHOLD_SECS,
        ));
    }
    if (config.tps - original_tps).abs() > f64::EPSILON
        || config.max_inflight != original_max_inflight
        || config.progress_timeout != original_progress_timeout
        || config.pipeline_time != original_pipeline_time
        || config.latency_p95_threshold != original_latency_p95_threshold
    {
        info!(
            target: "izanami::profile",
            peers = config.peer_count,
            duration_secs = config.duration.as_secs(),
            target_blocks = config.target_blocks.unwrap_or_default(),
            original_tps,
            tuned_tps = config.tps,
            original_max_inflight,
            tuned_max_inflight = config.max_inflight,
            original_progress_timeout_secs = original_progress_timeout.as_secs(),
            tuned_progress_timeout_secs = config.progress_timeout.as_secs(),
            original_pipeline_time_ms = original_pipeline_time
                .map(|duration| duration.as_millis())
                .unwrap_or_default(),
            tuned_pipeline_time_ms = config
                .pipeline_time
                .map(|duration| duration.as_millis())
                .unwrap_or_default(),
            original_latency_p95_threshold_ms = original_latency_p95_threshold
                .map(|duration| duration.as_millis())
                .unwrap_or_default(),
            tuned_latency_p95_threshold_ms = config
                .latency_p95_threshold
                .map(|duration| duration.as_millis())
                .unwrap_or_default(),
            "applied shared-host stable soak profile for deterministic long-run progress"
        );
    }
}
fn consensus_mode_label(config: &ChaosConfig) -> &'static str {
    if config.nexus.is_some() {
        "npos"
    } else {
        "permissioned"
    }
}
fn log_effective_consensus_soak_overrides(config: &ChaosConfig) {
    let latency_p95_gate_ms = config
        .latency_p95_threshold
        .map(|threshold| u64::try_from(threshold.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default();
    let block_cadence_ms = u64::try_from(
        config
            .pipeline_time
            .map_or_else(default_izanami_pipeline_time, |duration| duration)
            .as_millis(),
    )
    .unwrap_or(u64::MAX);
    info!(
        target: "izanami::profile",
        consensus_mode = consensus_mode_label(config),
        shared_host_stable_soak = is_shared_host_stable_soak(config),
        latency_p95_gate_configured = config.latency_p95_threshold.is_some(),
        latency_p95_gate_ms,
        block_cadence_ms,
        max_transactions = config.sumeragi_block_max_transactions,
        "effective native Sumeragi soak profile"
    );
}
fn workload_account_count(config: &ChaosConfig) -> usize {
    let baseline = config.peer_count.saturating_mul(3).max(6);
    if config.tps >= IZANAMI_HIGH_TPS_ACCOUNT_THRESHOLD || config.prebuild_tx_buffer > baseline {
        let high_tps_floor = if matches!(config.workload_profile, WorkloadProfile::Stable) {
            IZANAMI_HIGH_TPS_STABLE_ACCOUNT_COUNT
        } else {
            IZANAMI_HIGH_TPS_ACCOUNT_COUNT
        };
        baseline.max(high_tps_floor)
    } else {
        baseline
    }
}
#[cfg(test)]
fn make_network_builder(
    config: &ChaosConfig,
    genesis: Vec<Vec<InstructionBox>>,
) -> Result<NetworkBuilder> {
    make_network_builder_with_sorafs(config, genesis, BTreeMap::new())
}
fn make_network_builder_with_sorafs(
    config: &ChaosConfig,
    genesis: Vec<Vec<InstructionBox>>,
    sorafs_provider_owners: BTreeMap<String, String>,
) -> Result<NetworkBuilder> {
    let max_total_connections = i64::try_from(IZANAMI_MAX_TOTAL_CONNECTIONS)
        .wrap_err("Izanami network connection capacity exceeds TOML limits")?;
    let mut genesis = genesis;
    let nexus_bootstrap_post_topology = if let Some(profile) = config.nexus.as_ref() {
        let post_topology =
            extract_nexus_bootstrap_post_topology(&mut genesis, config.peer_count, profile)?;
        compact_nexus_retained_genesis(&mut genesis);
        post_topology
    } else {
        Vec::new()
    };
    let phase_operator_keypair = sumeragi_phase_operator_keypair();
    let torii_receipt_public_key = phase_operator_keypair.public_key().to_string();
    let torii_receipt_private_key =
        ExposedPrivateKey(phase_operator_keypair.private_key().clone()).to_string();
    let mut builder = NetworkBuilder::new()
        .with_peers(config.peer_count)
        .with_base_seed(instructions::IZANAMI_BASE_SEED);
    if !sorafs_provider_owners.is_empty() {
        let provider_owners = sorafs_provider_owners
            .into_iter()
            .map(|(provider, owner)| (provider, TomlValue::String(owner)))
            .collect::<Table>();
        builder = builder.with_config_layer(move |layer| {
            layer.write(
                ["governance", "sorafs_provider_owners"],
                TomlValue::Table(provider_owners.clone()),
            );
        });
    }
    builder = if config.nexus.is_some() {
        builder.with_npos_consensus()
    } else {
        builder.with_permissioned_consensus()
    };
    let npos_params = izanami_npos_parameters(config.peer_count);
    let pipeline_time = config
        .pipeline_time
        .unwrap_or_else(default_izanami_pipeline_time);
    builder = builder.with_block_cadence(pipeline_time);
    if let Some(profile) = &config.nexus {
        builder = builder.with_config_table(profile.config_layer.clone());
        let gas_account_id = instructions::nexus_gas_account_id()?.to_string();
        builder = builder.with_config_layer(move |layer| {
            layer
                .write(
                    ["pipeline", "gas", "tech_account_id"],
                    gas_account_id.clone(),
                )
                .write(
                    ["nexus", "fees", "fee_sink_account_id"],
                    gas_account_id.clone(),
                )
                .write(
                    ["nexus", "staking", "stake_escrow_account_id"],
                    gas_account_id.clone(),
                )
                .write(
                    ["nexus", "staking", "slash_sink_account_id"],
                    gas_account_id.clone(),
                );
        });
    }
    if let Some(profile) = config.nexus.as_ref() {
        builder = builder.without_npos_genesis_bootstrap();
        for transaction in nexus_bootstrap_post_topology {
            builder = builder.with_genesis_post_topology_isi(transaction);
        }
        builder =
            builder.with_genesis_post_topology_isi(instructions::npos_post_topology_instructions(
                config.peer_count,
                profile.bootstrap_public_lanes.as_slice(),
                npos_params.min_self_bond(),
                &profile.stake_asset_id,
                &instructions::nexus_gas_account_id()?,
            )?);
    }
    if let Ok(filter) = std::env::var("RUST_LOG") {
        let filter = filter.trim();
        if !filter.is_empty() {
            let filter = filter.to_string();
            // Keep peer logs sparse by default, while still allowing targeted directives via RUST_LOG.
            builder = builder.with_config_layer(|layer| {
                layer
                    .write(["logger", "level"], IZANAMI_PEER_LOG_BASE_LEVEL)
                    .write(["logger", "filter"], filter);
            });
        }
    }
    // The signed genesis selects consensus mode and DA layout. Only finite block
    // limits and the NPoS election snapshot are injected here.
    let block_max_transactions = NonZeroU64::new(config.sumeragi_block_max_transactions)
        .expect("Izanami block transaction cap non-zero");
    let block_gas_limit = CustomParameter::new(
        CustomParameterId::new(
            "ivm_gas_limit_per_block"
                .parse()
                .expect("static gas-limit parameter name is valid"),
        ),
        Json::new(IZANAMI_IVM_GAS_LIMIT_PER_BLOCK),
    );
    let mut injected_block_limits = vec![
        InstructionBox::from(SetParameter::new(Parameter::Block(
            BlockParameter::MaxTransactions(block_max_transactions),
        ))),
        InstructionBox::from(SetParameter::new(Parameter::Custom(block_gas_limit))),
    ];
    if let Some(last_tx) = genesis.last_mut() {
        last_tx.append(&mut injected_block_limits);
    } else {
        genesis.push(injected_block_limits);
    }
    if config.nexus.is_some() {
        let injected = InstructionBox::from(SetParameter::new(Parameter::Custom(
            npos_params.into_custom_parameter(),
        )));
        if let Some(last_tx) = genesis.last_mut() {
            last_tx.push(injected);
        } else {
            genesis.push(vec![injected]);
        }
    }
    // Tune execution throughput while retaining only the bounded network queues.
    let queue_capacity = effective_network_queue_capacity(config);
    builder = builder.with_config_layer(move |layer| {
        layer
            .write(
                ["pipeline", "access_set_cache_enabled"],
                IZANAMI_PIPELINE_ACCESS_SET_CACHE_ENABLED,
            )
            .write(
                ["pipeline", "parallel_overlay"],
                IZANAMI_PIPELINE_PARALLEL_OVERLAY,
            )
            .write(
                ["pipeline", "parallel_apply"],
                IZANAMI_PIPELINE_PARALLEL_APPLY,
            )
            .write(["pipeline", "workers"], IZANAMI_PIPELINE_WORKERS)
            .write(
                ["pipeline", "signature_batch_max_ed25519"],
                IZANAMI_PIPELINE_SIGNATURE_BATCH_MAX_ED25519,
            )
            .write(
                ["pipeline", "signature_batch_max_secp256k1"],
                IZANAMI_PIPELINE_SIGNATURE_BATCH_MAX_SECP256K1,
            )
            .write(
                ["pipeline", "signature_batch_max_pqc"],
                IZANAMI_PIPELINE_SIGNATURE_BATCH_MAX_PQC,
            )
            .write(
                ["pipeline", "signature_batch_max_bls"],
                IZANAMI_PIPELINE_SIGNATURE_BATCH_MAX_BLS,
            )
            .write(
                ["pipeline", "stateless_cache_cap"],
                IZANAMI_PIPELINE_STATELESS_CACHE_CAP,
            )
            .write(
                ["torii", "receipt_public_key"],
                torii_receipt_public_key.clone(),
            )
            .write(
                ["torii", "receipt_private_key"],
                torii_receipt_private_key.clone(),
            )
            .write(["telemetry_profile"], IZANAMI_TELEMETRY_PROFILE)
            .write(["kura", "fsync_mode"], IZANAMI_KURA_FSYNC_MODE.to_string())
            .write(
                ["network", "p2p_queue_cap_high"],
                IZANAMI_P2P_QUEUE_CAP_HIGH,
            )
            .write(["network", "p2p_queue_cap_low"], IZANAMI_P2P_QUEUE_CAP_LOW)
            .write(
                ["network", "p2p_post_queue_cap"],
                IZANAMI_P2P_POST_QUEUE_CAP,
            )
            .write(
                ["network", "p2p_subscriber_queue_cap"],
                IZANAMI_P2P_SUBSCRIBER_QUEUE_CAP,
            )
            .write(["queue", "capacity"], queue_capacity)
            .write(["queue", "capacity_per_user"], queue_capacity)
            .write(
                ["torii", "preauth_allow_cidrs"],
                TomlValue::Array(vec![
                    TomlValue::String("127.0.0.0/8".into()),
                    TomlValue::String("::1/128".into()),
                ]),
            )
            .write(
                ["torii", "api_rate_limit_bypass_cidrs"],
                TomlValue::Array(vec![
                    TomlValue::String("127.0.0.0/8".into()),
                    TomlValue::String("::1/128".into()),
                ]),
            )
            .write(
                ["torii", "preauth_rate_per_ip_per_sec"],
                IZANAMI_TORII_PREAUTH_RATE_PER_IP_PER_SEC,
            )
            .write(
                ["torii", "preauth_burst_per_ip"],
                IZANAMI_TORII_PREAUTH_BURST_PER_IP,
            )
            .write(["torii", "api_high_load_tx_threshold"], queue_capacity)
            .write(
                ["network", "transaction_gossip_period_ms"],
                IZANAMI_TRANSACTION_GOSSIP_PERIOD_MS,
            )
            .write(
                ["network", "transaction_gossip_size"],
                i64::from(IZANAMI_TRANSACTION_GOSSIP_SIZE),
            )
            .write(
                ["network", "transaction_gossip_resend_ticks"],
                IZANAMI_TRANSACTION_GOSSIP_RESEND_TICKS,
            )
            .write(
                ["network", "transaction_gossip_public_target_cap"],
                IZANAMI_TRANSACTION_GOSSIP_PUBLIC_TARGET_CAP,
            )
            .write(["network", "max_total_connections"], max_total_connections)
            .write(["sumeragi", "role"], "validator")
            .write(
                ["sumeragi", "keys", "allowed_algorithms"],
                TomlValue::Array(vec![TomlValue::String("bls_normal".into())]),
            )
            .write(
                ["nexus", "fusion", "floor_teu"],
                IZANAMI_NEXUS_FUSION_FLOOR_TEU,
            )
            .write(
                ["nexus", "fusion", "exit_teu"],
                IZANAMI_NEXUS_FUSION_EXIT_TEU,
            );
    });
    let genesis_len = genesis.len();
    for (idx, transaction) in genesis.into_iter().enumerate() {
        for isi in transaction {
            builder = builder.with_genesis_instruction(isi);
        }
        if idx + 1 < genesis_len {
            builder = builder.next_genesis_transaction();
        }
    }
    Ok(builder)
}
fn extract_nexus_bootstrap_post_topology(
    genesis: &mut Vec<Vec<InstructionBox>>,
    peer_count: usize,
    profile: &crate::config::NexusProfile,
) -> Result<Vec<Vec<InstructionBox>>> {
    let nexus_domain: DomainId =
        DomainId::parse_fully_qualified("nexus.universal").expect("nexus domain");
    let ivm_domain: DomainId =
        DomainId::parse_fully_qualified("ivm.universal").expect("ivm domain");
    let universal_domain: DomainId =
        DomainId::parse_fully_qualified("universal.universal").expect("universal domain");
    let gas_account = instructions::nexus_gas_account_id()?;
    let mut validator_accounts = BTreeSet::new();
    for index in 0..peer_count.max(1) {
        validator_accounts.insert(AccountId::new(
            instructions::peer_keypair(index)?.public_key().clone(),
        ));
    }
    let stake_asset = profile.stake_asset_id.clone();
    let fee_asset = profile.fee_asset_id.clone();
    let mut neutral_tx = Vec::new();
    let mut stake_tx = Vec::new();
    let mut fee_tx = Vec::new();
    let mut stake_grant_tx = Vec::new();
    let mut fee_grant_tx = Vec::new();
    for tx in genesis.iter_mut() {
        let mut retained = Vec::with_capacity(tx.len());
        for instruction in tx.drain(..) {
            match classify_nexus_bootstrap_instruction(
                &instruction,
                &nexus_domain,
                &ivm_domain,
                &universal_domain,
                &gas_account,
                &validator_accounts,
                &stake_asset,
                &fee_asset,
            ) {
                Some(NexusBootstrapTxKind::Neutral) => neutral_tx.push(instruction),
                Some(NexusBootstrapTxKind::Stake) => stake_tx.push(instruction),
                Some(NexusBootstrapTxKind::Fee) => fee_tx.push(instruction),
                Some(NexusBootstrapTxKind::StakeGrant) => stake_grant_tx.push(instruction),
                Some(NexusBootstrapTxKind::FeeGrant) => fee_grant_tx.push(instruction),
                None => retained.push(instruction),
            }
        }
        *tx = retained;
    }
    genesis.retain(|tx| !tx.is_empty());
    let mut bootstrap = Vec::new();
    if !neutral_tx.is_empty() {
        bootstrap.push(neutral_tx);
    }
    if !stake_tx.is_empty() {
        bootstrap.push(stake_tx);
    }
    if !fee_tx.is_empty() {
        bootstrap.push(fee_tx);
    }
    if !stake_grant_tx.is_empty() {
        bootstrap.push(stake_grant_tx);
    }
    if !fee_grant_tx.is_empty() {
        bootstrap.push(fee_grant_tx);
    }
    Ok(bootstrap)
}
fn compact_nexus_retained_genesis(genesis: &mut Vec<Vec<InstructionBox>>) {
    if genesis.len() <= 1 {
        return;
    }
    let mut compacted: Vec<Vec<InstructionBox>> = Vec::with_capacity(genesis.len());
    for transaction in genesis.drain(..) {
        if is_universal_dataspace_grant_transaction(&transaction) && !compacted.is_empty() {
            compacted
                .first_mut()
                .expect("checked non-empty compacted genesis")
                .extend(transaction);
        } else {
            compacted.push(transaction);
        }
    }
    *genesis = compacted;
}
fn is_universal_dataspace_grant_transaction(transaction: &[InstructionBox]) -> bool {
    !transaction.is_empty()
        && transaction.iter().all(|instruction| {
            instruction
                .as_any()
                .downcast_ref::<GrantBox>()
                .is_some_and(|grant| match grant {
                    GrantBox::Permission(permission) => {
                        permission.object
                            == CanPublishSpaceDirectoryManifest {
                                dataspace: DataSpaceId::UNIVERSAL,
                            }
                            .into()
                    }
                    _ => false,
                })
        })
}
#[allow(clippy::too_many_arguments)]
fn classify_nexus_bootstrap_instruction(
    instruction: &InstructionBox,
    nexus_domain: &DomainId,
    ivm_domain: &DomainId,
    universal_domain: &DomainId,
    gas_account: &AccountId,
    validator_accounts: &BTreeSet<AccountId>,
    stake_asset: &AssetDefinitionId,
    fee_asset: &AssetDefinitionId,
) -> Option<NexusBootstrapTxKind> {
    if let Some(register) = instruction.as_any().downcast_ref::<RegisterBox>() {
        return match register {
            RegisterBox::Domain(domain) => {
                let domain_id = &domain.object.id;
                (domain_id == nexus_domain
                    || domain_id == ivm_domain
                    || domain_id == universal_domain)
                    .then_some(NexusBootstrapTxKind::Neutral)
            }
            RegisterBox::Account(account) => {
                let account_id = &account.object.id;
                (account_id == gas_account || validator_accounts.contains(account_id))
                    .then_some(NexusBootstrapTxKind::Neutral)
            }
            RegisterBox::AssetDefinition(definition) => {
                let definition_id = &definition.object.id;
                if definition_id == stake_asset {
                    Some(NexusBootstrapTxKind::Stake)
                } else if definition_id == fee_asset {
                    Some(NexusBootstrapTxKind::Fee)
                } else {
                    None
                }
            }
            _ => None,
        };
    }
    if let Some(mint) = instruction.as_any().downcast_ref::<MintBox>() {
        return match mint {
            MintBox::Asset(asset) if asset.destination.definition() == stake_asset => {
                Some(NexusBootstrapTxKind::Stake)
            }
            MintBox::Asset(asset) if asset.destination.definition() == fee_asset => {
                Some(NexusBootstrapTxKind::Fee)
            }
            _ => None,
        };
    }
    if let Some(grant) = instruction.as_any().downcast_ref::<GrantBox>() {
        return match grant {
            GrantBox::Permission(permission)
                if permission.object
                    == CanMintAssetWithDefinition {
                        asset_definition: stake_asset.clone(),
                    }
                    .into() =>
            {
                Some(NexusBootstrapTxKind::StakeGrant)
            }
            GrantBox::Permission(permission)
                if permission.object
                    == CanMintAssetWithDefinition {
                        asset_definition: fee_asset.clone(),
                    }
                    .into() =>
            {
                Some(NexusBootstrapTxKind::FeeGrant)
            }
            _ => None,
        };
    }
    None
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NexusBootstrapTxKind {
    Neutral,
    Stake,
    Fee,
    StakeGrant,
    FeeGrant,
}
/// Deterministically select which peers should receive fault injection tasks.
fn select_fault_targets(peers_len: usize, faulty_peers: usize, rng: &mut StdRng) -> Vec<usize> {
    if peers_len == 0 || faulty_peers == 0 {
        return Vec::new();
    }
    let target_count = faulty_peers.min(peers_len);
    let mut indices: Vec<_> = (0..peers_len).collect();
    indices.shuffle(rng);
    indices.into_iter().take(target_count).collect()
}
fn uses_sumeragi_leader_fault_targeting(config: &ChaosConfig) -> bool {
    config.faulty_peers == 1
        && !config.faults.crash_restart()
        && !config.faults.wipe_storage()
        && !config.faults.spam_invalid_transactions()
        && !config.faults.network_latency()
        && config.faults.network_partition()
        && !config.faults.cpu_stress()
        && !config.faults.disk_saturation()
}
fn fault_config_for(config: &ChaosConfig) -> FaultConfig {
    let toggles = config.faults;
    FaultConfig {
        interval: config.fault_interval.clone(),
        crash_restart: toggles.crash_restart(),
        wipe_storage: toggles.wipe_storage(),
        spam_invalid_transactions: toggles.spam_invalid_transactions(),
        network_latency: toggles
            .network_latency()
            .then_some(NetworkLatencyConfig::default()),
        network_partition: toggles
            .network_partition()
            .then_some(NetworkPartitionConfig::default()),
        cpu_stress: toggles.cpu_stress().then_some(CpuStressConfig::default()),
        disk_saturation: toggles
            .disk_saturation()
            .then_some(DiskSaturationConfig::default()),
    }
}
/// Index of the current round's leader (a peer's Sumeragi status `leader`) among `peers`.
fn sumeragi_leader_index(
    leader: Option<&iroha_crypto::PublicKey>,
    peers: &[iroha_crypto::PublicKey],
) -> Option<usize> {
    let leader = leader?;
    peers.iter().position(|key| key == leader)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SumeragiLeaderTarget {
    peer_index: usize,
    sampled_from_peer_index: usize,
}
async fn sample_sumeragi_leader_target(
    peers: Arc<Vec<NetworkPeer>>,
) -> Result<SumeragiLeaderTarget, String> {
    spawn_blocking(move || {
        let mut last_error = None;
        for (sampled_from_peer_index, peer) in peers.iter().cloned().enumerate() {
            let client = peer.client();
            match client.client().get_sumeragi_status() {
                Ok(status) => {
                    let keys = peers
                        .iter()
                        .map(|peer| peer.public_key().clone())
                        .collect::<Vec<_>>();
                    let Some(peer_index) = sumeragi_leader_index(status.leader.as_ref(), &keys) else {
                        last_error = Some(format!(
                            "status from peer index {sampled_from_peer_index} names no leader in the {}-peer topology",
                            peers.len()
                        ));
                        continue;
                    };
                    return Ok(SumeragiLeaderTarget {
                        peer_index,
                        sampled_from_peer_index,
                    });
                }
                Err(err) => {
                    last_error = Some(format!(
                        "failed to sample Sumeragi leader from peer index {sampled_from_peer_index}: {err}"
                    ));
                }
            }
        }
        Err(last_error.unwrap_or_else(|| "no peers available for leader sampling".to_string()))
    })
    .await
    .map_err(|err| format!("leader sampling task failed: {err}"))?
}
#[derive(Clone)]
struct RunControl {
    stop: Arc<AtomicBool>,
    stop_notify: Arc<Notify>,
    deadline: Instant,
}
impl RunControl {
    fn new(deadline: Instant) -> Self {
        Self {
            stop: Arc::new(AtomicBool::new(false)),
            stop_notify: Arc::new(Notify::new()),
            deadline,
        }
    }
    fn deadline(&self) -> Instant {
        self.deadline
    }
    fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
        self.stop_notify.notify_waiters();
    }
    fn stop_requested(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }
    fn should_stop(&self) -> bool {
        self.stop.load(Ordering::Relaxed) || Instant::now() >= self.deadline
    }
    fn stop_notifier(&self) -> Arc<Notify> {
        Arc::clone(&self.stop_notify)
    }
}
fn fault_window_start_at(
    config: &ChaosConfig,
    run_started_at: Instant,
    run_deadline: Instant,
) -> Instant {
    config
        .fault_window_start
        .and_then(|offset| run_started_at.checked_add(offset))
        .map_or(run_started_at, |start| start.min(run_deadline))
}
fn fault_window_end_at(
    config: &ChaosConfig,
    run_started_at: Instant,
    run_deadline: Instant,
) -> Instant {
    config
        .fault_window_end
        .and_then(|offset| run_started_at.checked_add(offset))
        .map_or(run_deadline, |end| end.min(run_deadline))
}
async fn wait_for_fault_window_start(
    stop: &AtomicBool,
    stop_notify: &Notify,
    fault_start: Instant,
    run_deadline: Instant,
) -> bool {
    if stop.load(Ordering::Relaxed) || Instant::now() >= run_deadline {
        return false;
    }
    if let Some(delay) = fault_start.checked_duration_since(Instant::now())
        && !delay.is_zero()
    {
        tokio::select! {
            () = time::sleep(delay) => {},
            () = stop_notify.notified() => return false,
            () = time::sleep_until(run_deadline.into()) => return false,
        }
    }
    !stop.load(Ordering::Relaxed) && Instant::now() < run_deadline
}
pub struct IzanamiRunner {
    config: ChaosConfig,
    network: Network,
    peers: Vec<NetworkPeer>,
    workload: Arc<WorkloadEngine>,
    base_domain: DomainId,
}
impl IzanamiRunner {
    pub async fn new(config: ChaosConfig) -> Result<Self> {
        let mut config = config;
        apply_shared_host_stable_soak_profile(&mut config);
        log_effective_consensus_soak_overrides(&config);
        if !config.allow_net {
            return Err(eyre!(
                "allow_net=false: enable networking via --allow-net or persisted configuration"
            ));
        }
        let account_qty = workload_account_count(&config);
        let PreparedChaos {
            state,
            genesis,
            recipes,
            sorafs_provider_owners,
        } = instructions::prepare_state(
            account_qty,
            Some(config.peer_count),
            config.nexus.as_ref(),
            config.workload_profile,
            config.allow_contract_deploy_in_stable,
        )?;
        let base_domain = state.base_domain().clone();
        let builder = make_network_builder_with_sorafs(&config, genesis, sorafs_provider_owners)?;
        let network = builder.start().await?;
        if config.nexus.is_some() {
            let genesis = network.genesis();
            let preflight = audit_npos_genesis_preflight(
                &genesis,
                config.peer_count,
                config
                    .nexus
                    .as_ref()
                    .map(|profile| profile.bootstrap_public_lanes.as_slice())
                    .unwrap_or(&[]),
            )?;
            info!(
                target: "izanami::preflight",
                peer_with_pop_count = preflight.peer_with_pop_count,
                register_validator_count = preflight.register_validator_count,
                activate_validator_count = preflight.activate_validator_count,
                min_self_bond = %preflight.min_self_bond,
                validator_stake_distribution = ?preflight.stake_distribution,
                validator_stake_distribution_entries = preflight.stake_distribution.len(),
                "validated Izanami NPoS genesis preflight"
            );
        }
        let peers = network.peers().clone();
        let workload = Arc::new(WorkloadEngine::new(state, recipes));
        Ok(Self {
            config,
            network,
            peers,
            workload,
            base_domain,
        })
    }
    pub async fn run(self) -> Result<()> {
        let mut rng = self.seeded_rng()?;
        let config_layers = Arc::new(
            self.network
                .config_layers()
                .map(Cow::into_owned)
                .collect::<Vec<_>>(),
        );
        let genesis = Arc::new(self.network.genesis());
        let metrics = Arc::new(Metrics::default());
        metrics.set_submitters(self.config.submitters);
        let ingress_stats = Arc::new(IngressStats::default());
        let confirmation_audit_seed = rng.next_u64();
        let fault_targets =
            select_fault_targets(self.peers.len(), self.config.faulty_peers, &mut rng);
        let ingress_pool = Arc::new(IngressEndpointPool::from_peers(
            &self.peers,
            IngressEndpointPoolConfig::default(),
            Arc::clone(&ingress_stats),
            effective_ingress_request_timeout(&self.config),
        ));
        let submission_counter = Arc::new(AtomicU64::new(0));
        let submission_confirmation = submission_confirmation_mode(&self.config);
        let prebuilt_pool = self
            .prebuild_transaction_pool(
                &metrics,
                &ingress_pool,
                &mut rng,
                &submission_counter,
                submission_confirmation,
            )
            .await;
        let sumeragi_status_start = sample_sumeragi_status_digest(&self.peers).await.ok();
        let run_started_at = Instant::now();
        let deadline = run_started_at + self.config.duration;
        let run_control = Arc::new(RunControl::new(deadline));
        if uses_sumeragi_leader_fault_targeting(&self.config) {
            info!(
                target: "izanami::faults",
                fallback_fault_targets = ?fault_targets,
                "leader-isolation profile detected; fault target will follow Sumeragi leader telemetry"
            );
        } else {
            ingress_pool.reserve_fault_target_ingress_until(&self.peers, &fault_targets, deadline);
        }
        let confirmation_audit_wait_options =
            throughput_confirmation_wait_options_for(&self.config);
        let (confirmation_audit_tx, confirmation_audit_handle) = if matches!(
            submission_confirmation,
            SubmissionConfirmationMode::AcceptedByIngress
        ) {
            let (tx, rx) = mpsc::channel(IZANAMI_THROUGHPUT_CONFIRMATION_QUEUE_CAP);
            (
                Some(tx),
                Some(self.spawn_confirmation_audit_worker(
                    &metrics,
                    &ingress_pool,
                    &run_control,
                    rx,
                    confirmation_audit_wait_options.clone(),
                )),
            )
        } else {
            (None, None)
        };
        let faulty_handles = self.spawn_fault_tasks(
            &config_layers,
            &genesis,
            &run_control,
            &ingress_pool,
            run_started_at,
            &mut rng,
            &fault_targets,
        );
        let load_handles = self.spawn_load_supervisors(
            &metrics,
            &ingress_pool,
            &run_control,
            &mut rng,
            &submission_counter,
            prebuilt_pool,
            confirmation_audit_tx.clone(),
            confirmation_audit_seed,
            confirmation_audit_wait_options.clone(),
        );
        drop(confirmation_audit_tx);
        let soft_target_kpi =
            self.config.target_blocks.is_some() && is_shared_host_stable_soak(&self.config);
        let fault_start_at = fault_window_start_at(&self.config, run_started_at, deadline);
        let fault_end_at = fault_window_end_at(&self.config, run_started_at, deadline);
        let target_result = if let Some(target_blocks) = self.config.target_blocks {
            wait_for_target_blocks(
                &self.peers,
                target_blocks,
                self.config.faulty_peers,
                self.config.progress_interval,
                self.config.progress_timeout,
                self.config.latency_p95_threshold,
                &run_control,
                Some(ingress_pool.as_ref()),
                Some(metrics.as_ref()),
                soft_target_kpi,
                fault_start_at,
                fault_end_at,
            )
            .await
        } else if let Some(threshold) = self.config.latency_p95_threshold {
            let target_blocks = latency_gate_soft_target_blocks(self.config.duration, threshold);
            info!(
                target: "izanami::progress",
                target_blocks,
                latency_p95_threshold_ms = duration_ms(threshold),
                duration_secs = self.config.duration.as_secs(),
                "monitoring duration-only block cadence gate"
            );
            wait_for_target_blocks(
                &self.peers,
                target_blocks,
                self.config.faulty_peers,
                self.config.progress_interval,
                self.config.progress_timeout,
                self.config.latency_p95_threshold,
                &run_control,
                Some(ingress_pool.as_ref()),
                Some(metrics.as_ref()),
                true,
                fault_start_at,
                fault_end_at,
            )
            .await
        } else {
            wait_for_duration_deadline(
                &run_control,
                &self.peers,
                self.config.faulty_peers,
                Some(ingress_pool.as_ref()),
                fault_start_at,
                fault_end_at,
            )
            .await
        };
        let mut run_error = None;
        let mut progress_snapshot = None;
        match target_result {
            Ok(target_progress) => {
                progress_snapshot = Some(target_progress);
                if soft_target_kpi && let Some(target_blocks) = self.config.target_blocks {
                    if target_progress.target_reached {
                        info!(
                            target: "izanami::progress",
                            target_blocks,
                            quorum_min_height = target_progress.quorum_min_height,
                            strict_min_height = target_progress.strict_min_height,
                            "stable soak duration completed and target_blocks KPI was reached"
                        );
                    } else {
                        warn!(
                            target: "izanami::progress",
                            target_blocks,
                            quorum_min_height = target_progress.quorum_min_height,
                            strict_min_height = target_progress.strict_min_height,
                            "stable soak duration completed without target_blocks KPI; reporting as warning (non-fatal)"
                        );
                    }
                }
            }
            Err(err) => {
                warn!(
                    target: "izanami::progress",
                    ?err,
                    "target progress monitoring failed; stopping run"
                );
                run_control.stop();
                run_error = Some(err);
            }
        }
        run_control.stop();
        if run_error.is_some() {
            // Cut off peer services first on fatal progress failure so blocking submitters
            // terminate quickly instead of draining through long status timeouts.
            self.network.shutdown().await;
        }
        let shutdown_timeout = if run_error.is_some() {
            Duration::from_secs(IZANAMI_WORKER_FAILURE_SHUTDOWN_TIMEOUT_SECS)
        } else {
            Duration::from_secs(IZANAMI_WORKER_SHUTDOWN_TIMEOUT_SECS)
        };
        await_worker_shutdown_with_timeout(load_handles, "load", shutdown_timeout).await;
        if let Some(handle) = confirmation_audit_handle {
            await_worker_shutdown_with_timeout(vec![handle], "audit", shutdown_timeout).await;
        }
        await_worker_shutdown_with_timeout(faulty_handles, "fault", shutdown_timeout).await;
        let sumeragi_status_delta = if run_error.is_none() {
            match (
                sumeragi_status_start,
                sample_sumeragi_status_digest(&self.peers).await.ok(),
            ) {
                (Some(start), Some(end)) => Some(end.delta_from(start)),
                _ => None,
            }
        } else {
            None
        };
        if run_error.is_none() {
            self.network.shutdown().await;
        }
        if let Some(diagnostic_dir) = &self.config.diagnostic_dir {
            if let Err(err) =
                copy_network_diagnostics(&self.network, &self.peers, diagnostic_dir.as_path())
            {
                warn!(
                    target: "izanami::diagnostics",
                    diagnostic_dir = %diagnostic_dir.display(),
                    ?err,
                    "failed to copy test-network diagnostic artifacts"
                );
            } else {
                info!(
                    target: "izanami::diagnostics",
                    diagnostic_dir = %diagnostic_dir.display(),
                    "copied test-network diagnostic artifacts"
                );
            }
        }
        let snapshot = metrics.snapshot();
        let ingress_snapshot = ingress_stats.snapshot();
        let ingress_endpoint_stats = ingress_stats.endpoint_snapshots();
        if let Some(err) = run_error {
            warn!(
                target: "izanami::summary",
                offered = snapshot.offered,
                ingress_accepted = snapshot.ingress_accepted,
                blocking_applied_success = snapshot.blocking_applied_success,
                confirmation_sampled = snapshot.confirmation_sampled,
                confirmation_applied = snapshot.confirmation_applied,
                confirmation_failed = snapshot.confirmation_failed,
                confirmation_budget_skipped = snapshot.confirmation_budget_skipped,
                confirmation_queue_dropped = snapshot.confirmation_queue_dropped,
                confirmation_shutdown_noise = snapshot.confirmation_shutdown_noise,
                submit_plans_started = snapshot.submit_plans_started,
                submit_plans_shutdown_skipped = snapshot.submit_plans_shutdown_skipped,
                submit_tasks_shutdown_aborted = snapshot.submit_tasks_shutdown_aborted,
                submit_latency_samples = snapshot.submit_latency_samples,
                submit_latency_p50_ms = snapshot.submit_latency_p50_ms,
                submit_latency_p95_ms = snapshot.submit_latency_p95_ms,
                submit_latency_p99_ms = snapshot.submit_latency_p99_ms,
                submit_latency_max_ms = snapshot.submit_latency_max_ms,
                prebuilt_tx_buffer_capacity = snapshot.prebuilt_tx_buffer_capacity,
                prebuilt_tx_workers = snapshot.prebuilt_tx_workers,
                prebuilt_tx_built = snapshot.prebuilt_tx_built,
                prebuilt_tx_used = snapshot.prebuilt_tx_used,
                prebuilt_tx_fallback = snapshot.prebuilt_tx_fallback,
                prebuilt_tx_skipped = snapshot.prebuilt_tx_skipped,
                prebuilt_tx_build_failures = snapshot.prebuilt_tx_build_failures,
                successes = snapshot.successes,
                failures = snapshot.failures,
                expected_failures = snapshot.expected_failures,
                unexpected_successes = snapshot.unexpected_successes,
                inflight_current = snapshot.inflight_current,
                inflight_peak = snapshot.inflight_peak,
                backlog_depth = snapshot.backlog_depth,
                backlog_peak = snapshot.backlog_peak,
                submitters = snapshot.submitters,
                izanami_ingress_failover_total = ingress_snapshot.failover_total,
                izanami_ingress_endpoint_unhealthy_total = ingress_snapshot.endpoint_unhealthy_total,
                final_quorum_min_height = progress_snapshot.map(|progress| progress.quorum_min_height),
                final_strict_min_height = progress_snapshot.map(|progress| progress.strict_min_height),
                final_max_peer_height_skew = progress_snapshot.map(|progress| progress.max_peer_height_skew),
                final_quorum_block_interval_p50_ms = progress_snapshot.and_then(|progress| progress.quorum_block_interval_p50_ms),
                final_quorum_block_interval_p95_ms = progress_snapshot.and_then(|progress| progress.quorum_block_interval_p95_ms),
                final_quorum_block_interval_samples = progress_snapshot.and_then(|progress| progress.quorum_block_interval_samples),
                final_strict_block_interval_p50_ms = progress_snapshot.and_then(|progress| progress.strict_block_interval_p50_ms),
                final_strict_block_interval_p95_ms = progress_snapshot.and_then(|progress| progress.strict_block_interval_p95_ms),
                final_strict_block_interval_samples = progress_snapshot.and_then(|progress| progress.strict_block_interval_samples),
                final_quorum_min_txs_approved = progress_snapshot.map(|progress| progress.quorum_min_txs_approved),
                final_strict_min_txs_approved = progress_snapshot.map(|progress| progress.strict_min_txs_approved),
                final_max_peer_txs_approved_skew = progress_snapshot.map(|progress| progress.max_peer_txs_approved_skew),
                first_progress_after_fault_start_height = progress_snapshot.and_then(|progress| progress.first_progress_after_fault_start_height),
                first_progress_after_fault_end_height = progress_snapshot.and_then(|progress| progress.first_progress_after_fault_end_height),
                ?sumeragi_status_delta,
                ?ingress_endpoint_stats,
                ?err,
                "izanami run finished with errors"
            );
            Err(err)
        } else {
            info!(
                target: "izanami::summary",
                offered = snapshot.offered,
                ingress_accepted = snapshot.ingress_accepted,
                blocking_applied_success = snapshot.blocking_applied_success,
                confirmation_sampled = snapshot.confirmation_sampled,
                confirmation_applied = snapshot.confirmation_applied,
                confirmation_failed = snapshot.confirmation_failed,
                confirmation_budget_skipped = snapshot.confirmation_budget_skipped,
                confirmation_queue_dropped = snapshot.confirmation_queue_dropped,
                confirmation_shutdown_noise = snapshot.confirmation_shutdown_noise,
                submit_plans_started = snapshot.submit_plans_started,
                submit_plans_shutdown_skipped = snapshot.submit_plans_shutdown_skipped,
                submit_tasks_shutdown_aborted = snapshot.submit_tasks_shutdown_aborted,
                submit_latency_samples = snapshot.submit_latency_samples,
                submit_latency_p50_ms = snapshot.submit_latency_p50_ms,
                submit_latency_p95_ms = snapshot.submit_latency_p95_ms,
                submit_latency_p99_ms = snapshot.submit_latency_p99_ms,
                submit_latency_max_ms = snapshot.submit_latency_max_ms,
                prebuilt_tx_buffer_capacity = snapshot.prebuilt_tx_buffer_capacity,
                prebuilt_tx_workers = snapshot.prebuilt_tx_workers,
                prebuilt_tx_built = snapshot.prebuilt_tx_built,
                prebuilt_tx_used = snapshot.prebuilt_tx_used,
                prebuilt_tx_fallback = snapshot.prebuilt_tx_fallback,
                prebuilt_tx_skipped = snapshot.prebuilt_tx_skipped,
                prebuilt_tx_build_failures = snapshot.prebuilt_tx_build_failures,
                successes = snapshot.successes,
                failures = snapshot.failures,
                expected_failures = snapshot.expected_failures,
                unexpected_successes = snapshot.unexpected_successes,
                inflight_current = snapshot.inflight_current,
                inflight_peak = snapshot.inflight_peak,
                backlog_depth = snapshot.backlog_depth,
                backlog_peak = snapshot.backlog_peak,
                submitters = snapshot.submitters,
                izanami_ingress_failover_total = ingress_snapshot.failover_total,
                izanami_ingress_endpoint_unhealthy_total = ingress_snapshot.endpoint_unhealthy_total,
                final_quorum_min_height = progress_snapshot.map(|progress| progress.quorum_min_height),
                final_strict_min_height = progress_snapshot.map(|progress| progress.strict_min_height),
                final_max_peer_height_skew = progress_snapshot.map(|progress| progress.max_peer_height_skew),
                final_quorum_block_interval_p50_ms = progress_snapshot.and_then(|progress| progress.quorum_block_interval_p50_ms),
                final_quorum_block_interval_p95_ms = progress_snapshot.and_then(|progress| progress.quorum_block_interval_p95_ms),
                final_quorum_block_interval_samples = progress_snapshot.and_then(|progress| progress.quorum_block_interval_samples),
                final_strict_block_interval_p50_ms = progress_snapshot.and_then(|progress| progress.strict_block_interval_p50_ms),
                final_strict_block_interval_p95_ms = progress_snapshot.and_then(|progress| progress.strict_block_interval_p95_ms),
                final_strict_block_interval_samples = progress_snapshot.and_then(|progress| progress.strict_block_interval_samples),
                final_quorum_min_txs_approved = progress_snapshot.map(|progress| progress.quorum_min_txs_approved),
                final_strict_min_txs_approved = progress_snapshot.map(|progress| progress.strict_min_txs_approved),
                final_max_peer_txs_approved_skew = progress_snapshot.map(|progress| progress.max_peer_txs_approved_skew),
                first_progress_after_fault_start_height = progress_snapshot.and_then(|progress| progress.first_progress_after_fault_start_height),
                first_progress_after_fault_end_height = progress_snapshot.and_then(|progress| progress.first_progress_after_fault_end_height),
                ?sumeragi_status_delta,
                ?ingress_endpoint_stats,
                "izanami run complete"
            );
            Ok(())
        }
    }
    fn seeded_rng(&self) -> Result<StdRng> {
        seeded_rng_from_seed(self.config.seed)
    }
    fn spawn_fault_tasks(
        &self,
        config_layers: &Arc<Vec<Table>>,
        genesis: &Arc<GenesisBlock>,
        run_control: &Arc<RunControl>,
        ingress_pool: &Arc<IngressEndpointPool>,
        run_started_at: Instant,
        rng: &mut StdRng,
        targets: &[usize],
    ) -> Vec<JoinHandle<()>> {
        if targets.is_empty() {
            return Vec::new();
        }
        if uses_sumeragi_leader_fault_targeting(&self.config) {
            return self.spawn_sumeragi_leader_fault_task(
                config_layers,
                genesis,
                run_control,
                ingress_pool,
                run_started_at,
                rng,
                targets[0],
            );
        }
        let deadline = run_control.deadline();
        let fault_start = fault_window_start_at(&self.config, run_started_at, deadline);
        let fault_deadline = fault_window_end_at(&self.config, run_started_at, deadline);
        let mut handles = Vec::new();
        let fault_cfg = fault_config_for(&self.config);
        for (offset, idx) in targets.iter().copied().enumerate() {
            let peer = self.peers[idx].clone();
            let config_layers = Arc::clone(config_layers);
            let genesis = Arc::clone(genesis);
            let base_domain = self.base_domain.clone();
            let stop = Arc::clone(&run_control.stop);
            let stop_notify = run_control.stop_notifier();
            let cfg = fault_cfg.clone();
            let seed = rng.next_u64();
            handles.push(tokio::spawn(async move {
                if !wait_for_fault_window_start(
                    stop.as_ref(),
                    stop_notify.as_ref(),
                    fault_start,
                    deadline,
                )
                .await
                {
                    return;
                }
                if Instant::now() >= fault_deadline {
                    debug!(
                        target: "izanami::faults",
                        peer = peer.mnemonic(),
                        "fault window closed before worker became active"
                    );
                    return;
                }
                info!(
                    target: "izanami::faults",
                    peer = peer.mnemonic(),
                    active_after_ms = fault_start
                        .saturating_duration_since(run_started_at)
                        .as_millis(),
                    active_until_ms = fault_deadline
                        .saturating_duration_since(run_started_at)
                        .as_millis(),
                    "fault worker entering timed injection window"
                );
                faults::run_fault_loop(
                    peer,
                    cfg,
                    genesis,
                    config_layers,
                    base_domain,
                    stop,
                    stop_notify,
                    fault_deadline,
                    seed,
                )
                .await;
            }));
            debug!(target: "izanami::faults", peer_index = idx, worker = offset, "spawned fault worker");
        }
        handles
    }
    #[allow(clippy::too_many_arguments)]
    fn spawn_sumeragi_leader_fault_task(
        &self,
        config_layers: &Arc<Vec<Table>>,
        genesis: &Arc<GenesisBlock>,
        run_control: &Arc<RunControl>,
        ingress_pool: &Arc<IngressEndpointPool>,
        run_started_at: Instant,
        rng: &mut StdRng,
        fallback_target: usize,
    ) -> Vec<JoinHandle<()>> {
        let deadline = run_control.deadline();
        let fault_start = fault_window_start_at(&self.config, run_started_at, deadline);
        let fault_deadline = fault_window_end_at(&self.config, run_started_at, deadline);
        let fault_cfg = fault_config_for(&self.config);
        let peers = Arc::new(self.peers.clone());
        let config_layers = Arc::clone(config_layers);
        let genesis = Arc::clone(genesis);
        let base_domain = self.base_domain.clone();
        let stop = Arc::clone(&run_control.stop);
        let stop_notify = run_control.stop_notifier();
        let ingress_pool = Arc::clone(ingress_pool);
        let seed = rng.next_u64();
        vec![tokio::spawn(async move {
            if !wait_for_fault_window_start(
                stop.as_ref(),
                stop_notify.as_ref(),
                fault_start,
                deadline,
            )
            .await
            {
                return;
            }
            if Instant::now() >= fault_deadline {
                debug!(
                    target: "izanami::faults",
                    "leader-targeted fault window closed before worker became active"
                );
                return;
            }
            info!(
                target: "izanami::faults",
                active_after_ms = fault_start
                    .saturating_duration_since(run_started_at)
                    .as_millis(),
                active_until_ms = fault_deadline
                    .saturating_duration_since(run_started_at)
                    .as_millis(),
                "leader-targeted fault worker entering timed injection window"
            );
            let mut rng = StdRng::seed_from_u64(seed);
            while Instant::now() < fault_deadline && !stop.load(Ordering::Relaxed) {
                let target = match sample_sumeragi_leader_target(Arc::clone(&peers)).await {
                    Ok(target) => target,
                    Err(err) => {
                        warn!(
                            target: "izanami::faults",
                            ?err,
                            fallback_peer_index = fallback_target,
                            "failed to sample Sumeragi leader; using deterministic fallback fault target"
                        );
                        SumeragiLeaderTarget {
                            peer_index: fallback_target.min(peers.len().saturating_sub(1)),
                            sampled_from_peer_index: fallback_target,
                        }
                    }
                };
                let Some(peer) = peers.get(target.peer_index).cloned() else {
                    warn!(
                        target: "izanami::faults",
                        peer_index = target.peer_index,
                        "leader-targeted fault target is outside the peer set"
                    );
                    break;
                };
                ingress_pool.reserve_fault_target_ingress_until(
                    peers.as_slice(),
                    &[target.peer_index],
                    fault_deadline,
                );
                info!(
                    target: "izanami::faults",
                    peer_index = target.peer_index,
                    sampled_from_peer_index = target.sampled_from_peer_index,
                    peer = peer.mnemonic(),
                    "injecting fault into current Sumeragi leader"
                );
                match faults::apply_random_fault_once(
                    &peer,
                    &fault_cfg,
                    &config_layers,
                    &genesis,
                    &base_domain,
                    &mut rng,
                    fault_deadline,
                )
                .await
                {
                    Ok(scenario) => {
                        debug!(
                            target: "izanami::faults",
                            peer_index = target.peer_index,
                            ?scenario,
                            "leader-targeted fault scenario completed"
                        );
                    }
                    Err(err) => {
                        warn!(
                            target: "izanami::faults",
                            peer_index = target.peer_index,
                            ?err,
                            "leader-targeted fault scenario failed"
                        );
                    }
                }
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let delay = fault_cfg.sample_interval(&mut rng);
                let Some(remaining) = fault_deadline.checked_duration_since(Instant::now()) else {
                    break;
                };
                if remaining.is_zero() {
                    break;
                }
                let delay = delay.min(remaining);
                tokio::select! {
                    () = time::sleep(delay) => {},
                    () = stop_notify.notified() => break,
                }
            }
        })]
    }
    async fn prebuild_transaction_pool(
        &self,
        metrics: &Arc<Metrics>,
        ingress_pool: &Arc<IngressEndpointPool>,
        rng: &mut StdRng,
        submission_counter: &Arc<AtomicU64>,
        submission_confirmation: SubmissionConfirmationMode,
    ) -> Option<PrebuiltTransactionPool> {
        let buffer_capacity = self.config.prebuild_tx_buffer;
        if buffer_capacity == 0 {
            return None;
        }
        if !matches!(
            submission_confirmation,
            SubmissionConfirmationMode::AcceptedByIngress
        ) {
            warn!(
                target: "izanami::prebuild",
                buffer_capacity,
                "prebuilt transaction buffer is enabled but the workload requires blocking confirmation; disabling prebuild"
            );
            return None;
        }
        let worker_count = effective_prebuild_tx_workers(&self.config);
        if worker_count == 0 || ingress_pool.endpoint_count() == 0 {
            warn!(
                target: "izanami::prebuild",
                worker_count,
                endpoints = ingress_pool.endpoint_count(),
                "prebuilt transaction buffer could not start"
            );
            return None;
        }
        metrics.configure_prebuilt_tx_buffer(buffer_capacity, worker_count);
        info!(
            target: "izanami::prebuild",
            buffer_capacity,
            worker_count,
            "warming prebuilt transaction buffer before load window"
        );
        let (tx, mut rx) = mpsc::channel(worker_count.saturating_mul(4).max(1));
        let built_count = Arc::new(AtomicU64::new(0));
        let attempt_count = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let max_attempts = prebuild_attempt_limit(buffer_capacity, worker_count);
        let mut handles = Vec::with_capacity(worker_count);
        for worker_idx in 0..worker_count {
            let mut prebuild_rng = StdRng::seed_from_u64(rng.next_u64());
            let tx = tx.clone();
            let workload = Arc::clone(&self.workload);
            let ingress_pool = Arc::clone(ingress_pool);
            let metrics = Arc::clone(metrics);
            let submission_counter = Arc::clone(submission_counter);
            let built_count = Arc::clone(&built_count);
            let attempt_count = Arc::clone(&attempt_count);
            let stop = Arc::clone(&stop);
            let endpoint_idx = worker_idx % ingress_pool.endpoint_count();
            handles.push(tokio::spawn(async move {
                loop {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    if built_count.load(Ordering::Relaxed) >= buffer_capacity as u64 {
                        break;
                    }
                    if attempt_count.fetch_add(1, Ordering::Relaxed) >= max_attempts {
                        break;
                    }
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let (order, plan) = match workload.next_ordered_plan(&mut prebuild_rng).await {
                        Ok(ordered_plan) => ordered_plan,
                        Err(err) => {
                            metrics.record_prebuilt_tx_build_failure();
                            warn!(
                                target: "izanami::prebuild",
                                ?err,
                                worker_idx,
                                "failed to build prebuilt transaction plan"
                            );
                            continue;
                        }
                    };
                    if !plan_is_prebuild_safe(&plan, submission_confirmation) {
                        metrics.record_prebuilt_tx_skipped();
                        continue;
                    }
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let client = match ingress_pool.cached_submit_client_for(
                        endpoint_idx,
                        &plan.signer,
                        SubmissionConfirmationMode::AcceptedByIngress,
                    ) {
                        Ok(client) => client,
                        Err(err) => {
                            metrics.record_prebuilt_tx_build_failure();
                            warn!(
                                target: "izanami::prebuild",
                                ?err,
                                worker_idx,
                                endpoint_idx,
                                "failed to resolve client for prebuilt transaction"
                            );
                            continue;
                        }
                    };
                    let metadata = submission_metadata(submission_counter.as_ref());
                    let transaction = match {
                        let account = client.account_client();
                        account
                            .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                                plan.instructions.clone(),
                                iroha_data_model::transaction::FeePaymentIntent::authority(
                                    Vec::new(),
                                    None,
                                ),
                                metadata,
                            ))
                            .and_then(|payload| account.sign_transaction(payload))
                    } {
                        Ok(transaction) => transaction,
                        Err(err) => {
                            metrics.record_prebuilt_tx_build_failure();
                            warn!(
                                target: "izanami::prebuild",
                                ?err,
                                worker_idx,
                                endpoint_idx,
                                "failed to build prebuilt transaction"
                            );
                            continue;
                        }
                    };
                    let payload =
                        iroha::client::PreparedTransactionPayload::from_transaction(&transaction);
                    let next_index = built_count.fetch_add(1, Ordering::Relaxed);
                    if next_index >= buffer_capacity as u64 {
                        break;
                    }
                    let prepared = PreparedTransactionSubmission {
                        order,
                        plan,
                        payload,
                    };
                    if tx.send(prepared).await.is_err() {
                        break;
                    }
                    metrics.record_prebuilt_tx_built();
                    tokio::task::yield_now().await;
                }
                debug!(
                    target: "izanami::prebuild",
                    worker_idx,
                    "prebuilt transaction worker stopped"
                );
            }));
        }
        drop(tx);
        let mut prepared = Vec::with_capacity(buffer_capacity);
        while prepared.len() < buffer_capacity {
            let Some(submission) = rx.recv().await else {
                break;
            };
            prepared.push(submission);
            if prepared.len() % IZANAMI_PREBUILD_PROGRESS_LOG_STEP == 0 {
                info!(
                    target: "izanami::prebuild",
                    prepared = prepared.len(),
                    target = buffer_capacity,
                    "prebuilt transaction warmup progress"
                );
            }
        }
        stop.store(true, Ordering::Relaxed);
        drop(rx);
        for handle in handles {
            let _ = handle.await;
        }
        prepared.sort_by_key(|submission| submission.order);
        if prepared.len() < buffer_capacity {
            warn!(
                target: "izanami::prebuild",
                prepared = prepared.len(),
                target = buffer_capacity,
                attempts = attempt_count.load(Ordering::Relaxed),
                "prebuilt transaction warmup ended before the requested target was full"
            );
        } else {
            info!(
                target: "izanami::prebuild",
                prepared = prepared.len(),
                "prebuilt transaction warmup complete"
            );
        }
        Some(PrebuiltTransactionPool::new(prepared))
    }
    fn spawn_load_supervisors(
        &self,
        metrics: &Arc<Metrics>,
        ingress_pool: &Arc<IngressEndpointPool>,
        run_control: &Arc<RunControl>,
        rng: &mut StdRng,
        submission_counter: &Arc<AtomicU64>,
        prebuilt_pool: Option<PrebuiltTransactionPool>,
        confirmation_audit_tx: Option<mpsc::Sender<SubmissionAuditCandidate>>,
        confirmation_audit_seed: u64,
        confirmation_audit_wait_options: TransactionWaitOptions,
    ) -> Vec<JoinHandle<()>> {
        let submission_confirmation = submission_confirmation_mode(&self.config);
        let workload = Arc::clone(&self.workload);
        let mut handles = Vec::new();
        let submission_max_inflight = effective_submission_max_inflight(&self.config);
        let submission_tps = effective_submission_tps(&self.config);
        if submission_max_inflight != self.config.max_inflight
            || (submission_tps - self.config.tps).abs() > f64::EPSILON
        {
            info!(
                target: "izanami::ingress",
                configured_tps = self.config.tps,
                effective_tps = submission_tps,
                configured_max_inflight = self.config.max_inflight,
                effective_max_inflight = submission_max_inflight,
                faulty_peers = self.config.faulty_peers,
                peer_count = self.config.peer_count,
                "adaptive stable ingress pacing enabled"
            );
        }
        let semaphore = Arc::new(Semaphore::new(submission_max_inflight));
        let backlog_limit = submission_backlog_limit(submission_max_inflight);
        if let Some(prebuilt_pool) = prebuilt_pool {
            return vec![spawn_prebuilt_load_supervisor(PrebuiltLoadSupervisor {
                metrics: Arc::clone(metrics),
                ingress_pool: Arc::clone(ingress_pool),
                run_control: Arc::clone(run_control),
                workload,
                prebuilt_pool,
                semaphore,
                backlog_limit,
                submission_tps,
                submitters: self.config.submitters,
                submission_confirmation,
                confirmation_audit_tx,
                confirmation_audit_seed,
                confirmation_audit_wait_options,
                shutdown_drain_timeout: self.config.shutdown_drain_timeout,
            })];
        }
        let per_submitter_interval =
            Duration::from_secs_f64(self.config.submitters as f64 / submission_tps);
        let shutdown_drain_timeout = self.config.shutdown_drain_timeout;
        handles.extend((0..self.config.submitters).map(|submitter_idx| {
                let mut load_rng = StdRng::seed_from_u64(rng.next_u64());
                let phase_delay =
                    Duration::from_secs_f64(submitter_idx as f64 / submission_tps);
                let metrics = Arc::clone(metrics);
                let ingress_pool = Arc::clone(ingress_pool);
                let run_control = Arc::clone(run_control);
                let stop_notify = run_control.stop_notifier();
                let deadline = run_control.deadline();
                let submission_counter = Arc::clone(submission_counter);
                let workload = Arc::clone(&workload);
                let semaphore = Arc::clone(&semaphore);
                let confirmation_audit_tx = confirmation_audit_tx.clone();
                let confirmation_audit_wait_options = confirmation_audit_wait_options.clone();
                tokio::spawn(async move {
                    let start = Instant::now();
                    let mut next_tick = start + phase_delay;
                    let mut submissions = JoinSet::new();
                    let mut shutdown_skip_recorded = false;
                    while !run_control.should_stop() {
                        tokio::select! {
                            () = time::sleep_until(next_tick.into()) => {},
                            () = stop_notify.notified() => {
                                record_submit_plan_shutdown_skip_once(
                                    &metrics,
                                    &mut shutdown_skip_recorded,
                                );
                                break;
                            },
                            () = time::sleep_until(deadline.into()) => {
                                record_submit_plan_shutdown_skip_once(
                                    &metrics,
                                    &mut shutdown_skip_recorded,
                                );
                                break;
                            },
                        }
                        next_tick = next_tick
                            .checked_add(per_submitter_interval)
                            .unwrap_or(deadline);
                        drain_ready_submissions(&mut submissions);
                        if run_control.should_stop() {
                            record_submit_plan_shutdown_skip_once(
                                &metrics,
                                &mut shutdown_skip_recorded,
                            );
                            break;
                        }
                        if !wait_for_submission_capacity(
                            &mut submissions,
                            backlog_limit,
                            stop_notify.as_ref(),
                            deadline,
                        )
                        .await
                        {
                            if run_control.should_stop() || Instant::now() >= deadline {
                                record_submit_plan_shutdown_skip_once(
                                    &metrics,
                                    &mut shutdown_skip_recorded,
                                );
                            }
                            break;
                        }
                        if run_control.should_stop() {
                            record_submit_plan_shutdown_skip_once(
                                &metrics,
                                &mut shutdown_skip_recorded,
                            );
                            break;
                        }
                        if !submission_has_deadline_budget(
                            Instant::now(),
                            deadline,
                            submission_confirmation,
                        ) {
                            record_submit_plan_shutdown_skip_once(
                                &metrics,
                                &mut shutdown_skip_recorded,
                            );
                            debug!(
                                target: "izanami::workload",
                                submitter_idx,
                                "closing workload submitter because remaining run window cannot cover ingress retry budget"
                            );
                            wait_until_deadline_or_stop(stop_notify.as_ref(), deadline).await;
                            break;
                        }
                        if let Some(retry_after) =
                            ingress_pool.submission_backpressure_delay(Instant::now())
                        {
                            debug!(
                                target: "izanami::ingress",
                                submitter_idx,
                                ?retry_after,
                                "deferring workload submit while ingress endpoints remain in cooldown"
                            );
                            tokio::select! {
                                () = time::sleep(retry_after) => {},
                                () = stop_notify.notified() => {
                                    record_submit_plan_shutdown_skip_once(
                                        &metrics,
                                        &mut shutdown_skip_recorded,
                                    );
                                    break;
                                },
                                () = time::sleep_until(deadline.into()) => {
                                    record_submit_plan_shutdown_skip_once(
                                        &metrics,
                                        &mut shutdown_skip_recorded,
                                    );
                                    break;
                                },
                            }
                            continue;
                        }
                        let plan = match workload.next_plan(&mut load_rng).await {
                            Ok(plan) => plan,
                            Err(err) => {
                                warn!(target: "izanami::workload", ?err, submitter_idx, "failed to build transaction plan");
                                continue;
                            }
                        };
                        let effective_submission_confirmation = effective_submission_confirmation(
                            submission_confirmation,
                            &plan.state_updates,
                        );
                        if !submission_has_deadline_budget(
                            Instant::now(),
                            deadline,
                            effective_submission_confirmation,
                        ) {
                            record_submit_plan_shutdown_skip_once(
                                &metrics,
                                &mut shutdown_skip_recorded,
                            );
                            debug!(
                                target: "izanami::workload",
                                submitter_idx,
                                plan = plan.label,
                                "dropping late workload plan because it requires more confirmation budget than remains"
                            );
                            wait_until_deadline_or_stop(stop_notify.as_ref(), deadline).await;
                            break;
                        }
                        metrics.record_submit_plan_started();
                        metrics.record_backlog_spawn();
                        let metrics = Arc::clone(&metrics);
                        let ingress_pool = Arc::clone(&ingress_pool);
                        let submission_counter = Arc::clone(&submission_counter);
                        let workload = Arc::clone(&workload);
                        let semaphore = Arc::clone(&semaphore);
                        let confirmation_audit_tx = confirmation_audit_tx.clone();
                        let run_control = Arc::clone(&run_control);
                        let confirmation_audit_wait_options =
                            confirmation_audit_wait_options.clone();
                        submissions.spawn(async move {
                            let _backlog_guard = BacklogGuard::new(Arc::clone(&metrics));
                            submit_plan(
                                &ingress_pool,
                                plan,
                                submission_confirmation,
                                semaphore,
                                &metrics,
                                &submission_counter,
                                &workload,
                                submitter_idx,
                                confirmation_audit_tx,
                                confirmation_audit_seed,
                                &run_control,
                                &confirmation_audit_wait_options,
                            )
                            .await;
                        });
                    }
                    let aborted =
                        drain_submissions_for_shutdown(&mut submissions, shutdown_drain_timeout)
                            .await;
                    if aborted > 0 {
                        metrics.record_submit_tasks_shutdown_aborted(aborted);
                        warn!(
                            target: "izanami::workload",
                            submitter_idx,
                            aborted,
                            ?shutdown_drain_timeout,
                            "submission drain timeout expired; aborted leftover tasks"
                        );
                    }
                })
            }));
        handles
    }
    fn spawn_confirmation_audit_worker(
        &self,
        metrics: &Arc<Metrics>,
        ingress_pool: &Arc<IngressEndpointPool>,
        run_control: &Arc<RunControl>,
        mut confirmation_audit_rx: mpsc::Receiver<SubmissionAuditCandidate>,
        wait_options: TransactionWaitOptions,
    ) -> JoinHandle<()> {
        let metrics = Arc::clone(metrics);
        let ingress_pool = Arc::clone(ingress_pool);
        let run_control = Arc::clone(run_control);
        tokio::spawn(async move {
            let mut budgets = vec![SubmissionAuditBudget::default(); ingress_pool.endpoint_count()];
            let stop_notify = run_control.stop_notifier();
            let deadline = run_control.deadline();
            loop {
                if run_control.should_stop() {
                    break;
                }
                let candidate = tokio::select! {
                    candidate = confirmation_audit_rx.recv() => candidate,
                    () = stop_notify.notified() => break,
                    () = time::sleep_until(deadline.into()) => break,
                };
                let Some(candidate) = candidate else {
                    break;
                };
                let now = Instant::now();
                if !confirmation_audit_has_deadline_budget(now, deadline, &wait_options) {
                    metrics.record_confirmation_audit_budget_skipped();
                    debug!(
                        target: "izanami::audit",
                        endpoint_idx = candidate.endpoint_idx,
                        hash = %candidate.hash,
                        plan = candidate.plan_label,
                        remaining_ms = deadline
                            .checked_duration_since(now)
                            .map(|duration| duration.as_millis())
                            .unwrap_or_default(),
                        timeout_ms = wait_options.timeout.as_millis(),
                        "skipping sampled confirmation because the remaining run window is too short"
                    );
                    continue;
                }
                let Some(budget) = budgets.get_mut(candidate.endpoint_idx) else {
                    metrics.record_confirmation_audit_failed();
                    warn!(
                        target: "izanami::audit",
                        endpoint_idx = candidate.endpoint_idx,
                        hash = %candidate.hash,
                        plan = candidate.plan_label,
                        "skipping sampled confirmation because the ingress endpoint index is invalid"
                    );
                    continue;
                };
                if !budget.acquire_at(now) {
                    metrics.record_confirmation_audit_budget_skipped();
                    debug!(
                        target: "izanami::audit",
                        endpoint_idx = candidate.endpoint_idx,
                        hash = %candidate.hash,
                        plan = candidate.plan_label,
                        "skipping sampled confirmation because the per-endpoint budget is exhausted"
                    );
                    continue;
                }
                audit_submitted_transaction(
                    &ingress_pool,
                    &run_control,
                    &metrics,
                    candidate,
                    wait_options.clone(),
                )
                .await;
            }
        })
    }
}
async fn wait_until_deadline_or_stop(stop_notify: &Notify, deadline: Instant) {
    tokio::select! {
        () = stop_notify.notified() => {},
        () = time::sleep_until(deadline.into()) => {},
    }
}
fn drain_ready_submissions(submissions: &mut JoinSet<()>) {
    while let Some(result) = submissions.try_join_next() {
        let _ = result;
    }
}
fn record_submit_plan_shutdown_skip_once(metrics: &Metrics, recorded: &mut bool) {
    if !*recorded {
        metrics.record_submit_plan_shutdown_skipped();
        *recorded = true;
    }
}
async fn drain_submissions_for_shutdown(submissions: &mut JoinSet<()>, timeout: Duration) -> u64 {
    if submissions.is_empty() {
        return 0;
    }
    let deadline = Instant::now() + timeout;
    while !submissions.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or_default();
        if remaining.is_zero() {
            break;
        }
        match time::timeout(remaining, submissions.join_next()).await {
            Ok(Some(result)) => {
                let _ = result;
                drain_ready_submissions(submissions);
            }
            Ok(None) => return 0,
            Err(_) => break,
        }
    }
    let aborted = submissions.len() as u64;
    if aborted > 0 {
        submissions.abort_all();
        while let Some(result) = submissions.join_next().await {
            let _ = result;
        }
    }
    aborted
}
fn submission_backlog_limit(max_inflight: usize) -> usize {
    max_inflight
        .max(1)
        .saturating_mul(IZANAMI_SUBMISSION_BACKLOG_MULTIPLIER)
}
fn effective_prebuild_tx_workers(config: &ChaosConfig) -> usize {
    if config.prebuild_tx_buffer == 0 {
        return 0;
    }
    if config.prebuild_tx_workers > 0 {
        return config.prebuild_tx_workers;
    }
    let host_parallelism = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1);
    host_parallelism.min(config.submitters.max(1)).max(1)
}
fn effective_prebuilt_submit_batch_size(submission_tps: f64) -> usize {
    if submission_tps >= IZANAMI_STRESS_STABLE_INGRESS_CAP_BYPASS_TPS as f64 {
        IZANAMI_PREBUILT_SUBMIT_BATCH_SIZE
    } else {
        1
    }
}
fn prebuild_attempt_limit(buffer_capacity: usize, worker_count: usize) -> u64 {
    buffer_capacity
        .saturating_mul(IZANAMI_PREBUILD_ATTEMPT_MULTIPLIER)
        .max(buffer_capacity)
        .max(worker_count)
        .min(u64::MAX as usize) as u64
}
fn plan_is_prebuild_safe(
    plan: &TransactionPlan,
    submission_confirmation: SubmissionConfirmationMode,
) -> bool {
    plan.expect_success
        && matches!(
            effective_submission_confirmation(submission_confirmation, &plan.state_updates),
            SubmissionConfirmationMode::AcceptedByIngress
        )
        && plan.state_updates.is_empty()
}
const fn should_run_trigger_precheck(submission_confirmation: SubmissionConfirmationMode) -> bool {
    matches!(
        submission_confirmation,
        SubmissionConfirmationMode::BlockingApplied
    )
}
fn state_updates_require_applied_confirmation(state_updates: &[PlanUpdate]) -> bool {
    state_updates.iter().any(|update| {
        matches!(
            update,
            PlanUpdate::TrackAccount(_)
                | PlanUpdate::TrackAssetInstance(_)
                | PlanUpdate::RegisterTrigger(_)
                | PlanUpdate::RegisterCallTrigger(_)
                | PlanUpdate::TrackRepeatableTrigger(_)
                | PlanUpdate::MintTriggerRepetitions { .. }
                | PlanUpdate::BurnTriggerRepetitions { .. }
                | PlanUpdate::ReleaseTriggerRepetitionsReservation { .. }
                | PlanUpdate::SetTriggerMetadata { .. }
                | PlanUpdate::ClearTriggerMetadata(_)
        )
    })
}
fn effective_submission_confirmation(
    submission_confirmation: SubmissionConfirmationMode,
    state_updates: &[PlanUpdate],
) -> SubmissionConfirmationMode {
    if matches!(
        submission_confirmation,
        SubmissionConfirmationMode::AcceptedByIngress
    ) && state_updates_require_applied_confirmation(state_updates)
    {
        SubmissionConfirmationMode::BlockingApplied
    } else {
        submission_confirmation
    }
}
fn tracked_repeatable_trigger(state_updates: &[PlanUpdate]) -> Option<TriggerId> {
    state_updates.iter().find_map(|update| match update {
        PlanUpdate::TrackRepeatableTrigger(trigger_id) => Some(trigger_id.clone()),
        _ => None,
    })
}
fn is_trigger_not_found_error(error: &color_eyre::Report) -> bool {
    let message = ingress_error_message(error);
    message.contains("trigger with id") && message.contains("not found")
}
async fn wait_for_submission_capacity(
    submissions: &mut JoinSet<()>,
    backlog_limit: usize,
    stop_notify: &Notify,
    deadline: Instant,
) -> bool {
    while submissions.len() >= backlog_limit {
        let joined = tokio::select! {
            result = submissions.join_next() => result,
            () = stop_notify.notified() => return false,
            () = time::sleep_until(deadline.into()) => return false,
        };
        match joined {
            Some(result) => {
                let _ = result;
                drain_ready_submissions(submissions);
            }
            None => return false,
        }
    }
    true
}
fn tune_ingress_client(
    client: Client,
    mode: SubmissionConfirmationMode,
    request_timeout: Duration,
) -> Result<Client> {
    let mut inner = client.client().to_builder();
    inner.torii_request_timeout = request_timeout;
    if matches!(mode, SubmissionConfirmationMode::AcceptedByIngress) {
        inner
            .headers
            .insert("prefer".to_owned(), "return=minimal".to_owned());
    }
    if matches!(mode, SubmissionConfirmationMode::BlockingApplied) {
        inner.transaction_status_timeout = Duration::from_millis(IZANAMI_INGRESS_STATUS_TIMEOUT_MS);
    }
    Client::from_client(inner.build()?).wrap_err("failed to bind tuned ingress client")
}
async fn await_worker_shutdown_with_timeout(
    handles: Vec<JoinHandle<()>>,
    worker_kind: &'static str,
    timeout: Duration,
) {
    for mut handle in handles {
        match time::timeout(timeout, &mut handle).await {
            Ok(result) => {
                let _ = result;
            }
            Err(_) => {
                warn!(
                    target: "izanami::run",
                    worker_kind,
                    ?timeout,
                    "worker shutdown timed out; aborting task"
                );
                handle.abort();
                let _ = handle.await;
            }
        }
    }
}
fn seeded_rng_from_seed(seed: Option<u64>) -> Result<StdRng> {
    seed.map_or_else(
        || StdRng::try_from_os_rng().wrap_err("failed to seed Izanami chaos RNG from OS"),
        |seed| Ok(StdRng::seed_from_u64(seed)),
    )
}
fn sampled_peer_heights_with_ids(peers: &[NetworkPeer]) -> Vec<(PeerId, u64)> {
    peers
        .iter()
        .map(|peer| {
            (
                peer.id().clone(),
                peer.best_effort_block_height()
                    .map(|height| height.total)
                    .unwrap_or(0),
            )
        })
        .collect()
}
async fn sampled_peer_txs_approved(peers: &[NetworkPeer]) -> Vec<u64> {
    let mut approved = Vec::with_capacity(peers.len());
    for peer in peers {
        match time::timeout(
            Duration::from_millis(IZANAMI_STATUS_SAMPLE_REQUEST_TIMEOUT_MS),
            peer.status(),
        )
        .await
        {
            Ok(Ok(status)) => approved.push(status.txs_approved),
            Ok(Err(err)) => {
                warn!(
                    target: "izanami::progress",
                    peer = peer.mnemonic(),
                    ?err,
                    "failed to sample final tx approval count"
                );
            }
            Err(_) => {
                warn!(
                    target: "izanami::progress",
                    peer = peer.mnemonic(),
                    timeout_ms = IZANAMI_STATUS_SAMPLE_REQUEST_TIMEOUT_MS,
                    "timed out sampling final tx approval count"
                );
            }
        }
    }
    approved
}
fn tolerated_peer_failures(peer_count: usize) -> usize {
    if peer_count < 4 {
        0
    } else {
        peer_count.saturating_sub(1) / 3
    }
}
fn effective_tolerated_peer_failures(peer_count: usize, configured_faulty_peers: usize) -> usize {
    tolerated_peer_failures(peer_count).min(configured_faulty_peers)
}
fn quorum_min_height_from_samples(mut heights: Vec<u64>, tolerated_failures: usize) -> u64 {
    if heights.is_empty() {
        return 0;
    }
    heights.sort_unstable();
    let index = tolerated_failures.min(heights.len().saturating_sub(1));
    heights[index]
}
fn strict_divergence_reference_height_from_samples(
    mut heights: Vec<u64>,
    tolerated_failures: usize,
) -> u64 {
    if heights.is_empty() {
        return 0;
    }
    heights.sort_unstable();
    let index = heights
        .len()
        .saturating_sub(tolerated_failures.saturating_add(1));
    heights[index]
}
fn strict_divergence_lagging_peer_count(
    heights: &[u64],
    reference_height: u64,
    max_allowed_divergence: u64,
) -> usize {
    heights
        .iter()
        .filter(|height| reference_height.saturating_sub(**height) > max_allowed_divergence)
        .count()
}
fn should_enforce_strict_progress_timeout(lagging_peers: usize, tolerated_failures: usize) -> bool {
    lagging_peers == 0 || lagging_peers > tolerated_failures
}
fn strict_progress_stall_scope_message(
    lagging_peers: usize,
    tolerated_failures: usize,
) -> &'static str {
    if lagging_peers == 0 {
        "strict block height is stalled with no lagging peers; if this persists until the strict timeout the run will fail"
    } else if lagging_peers > tolerated_failures {
        "strict block height is stalled with broad peer lag beyond tolerated failures; if this persists until the strict timeout the run will fail"
    } else {
        "strict block height is stalled under tolerated outlier lag; continuing with quorum progress"
    }
}
struct ProgressState {
    last_height: u64,
    last_progress_at: Instant,
}
impl ProgressState {
    fn new(now: Instant) -> Self {
        Self {
            last_height: 0,
            last_progress_at: now,
        }
    }
    fn update(&mut self, now: Instant, height: u64) -> Option<(u64, Duration)> {
        if height > self.last_height {
            let blocks_advanced = height.saturating_sub(self.last_height);
            let elapsed = now.duration_since(self.last_progress_at);
            self.last_height = height;
            self.last_progress_at = now;
            Some((blocks_advanced, elapsed))
        } else {
            None
        }
    }
    fn stalled(&self, now: Instant, timeout: Duration) -> bool {
        now.duration_since(self.last_progress_at) >= timeout
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WeightedIntervalSample {
    interval_ms: u64,
    weight: u64,
}
#[derive(Default)]
struct BlockIntervalTracker {
    samples: Vec<WeightedIntervalSample>,
    total_weight: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BlockIntervalSummary {
    p50_ms: u64,
    p95_ms: u64,
    samples: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct SumeragiStatusDigest {
    status: iroha_data_model::sumeragi::SumeragiStatus,
    committed_height_advance: u64,
}
impl SumeragiStatusDigest {
    fn from_status(status: iroha_data_model::sumeragi::SumeragiStatus) -> Self {
        Self {
            status,
            committed_height_advance: 0,
        }
    }
    fn delta_from(self, start: Self) -> Self {
        Self {
            committed_height_advance: self
                .status
                .committed_height
                .saturating_sub(start.status.committed_height),
            ..self
        }
    }
}
async fn sample_sumeragi_status_digest(
    peers: &[NetworkPeer],
) -> Result<SumeragiStatusDigest, String> {
    if peers.is_empty() {
        return Err("no peers available for status sampling".to_owned());
    }
    let peers = peers
        .iter()
        .take(IZANAMI_STATUS_SAMPLE_MAX_PEERS)
        .cloned()
        .collect::<Vec<_>>();
    spawn_blocking(move || {
        let mut last_error = None;
        for peer in peers {
            let client = peer.client();
            let mut builder = client.client().to_builder();
            builder.operator_key_pair = Some(sumeragi_phase_operator_keypair());
            builder.torii_request_timeout =
                bounded_sumeragi_status_sample_request_timeout(builder.torii_request_timeout);
            let inner = match builder.build() {
                Ok(client) => client,
                Err(error) => {
                    last_error = Some(format!("invalid status sampling context: {error}"));
                    continue;
                }
            };
            match inner.get_sumeragi_status() {
                Ok(status) => return Ok(SumeragiStatusDigest::from_status(status)),
                Err(err) => {
                    last_error = Some(format!(
                        "failed to fetch native Sumeragi status snapshot: {err}"
                    ));
                }
            }
        }
        Err(last_error.unwrap_or_else(|| "no peers available for status sampling".to_owned()))
    })
    .await
    .map_err(|err| format!("status sampling task failed: {err}"))?
}
fn copy_network_diagnostics(
    network: &Network,
    peers: &[NetworkPeer],
    diagnostic_dir: &Path,
) -> Result<()> {
    fs::create_dir_all(diagnostic_dir).wrap_err_with(|| {
        format!(
            "failed to create diagnostic directory {}",
            diagnostic_dir.display()
        )
    })?;
    let source_root = network.env_dir();
    let copied_root = diagnostic_dir.join("test-network");
    copy_selected_diagnostic_files(source_root, source_root, &copied_root)?;
    let mut index = fs::File::create(diagnostic_dir.join("peer-log-index.tsv"))
        .wrap_err("failed to create peer diagnostic log index")?;
    writeln!(
        index,
        "peer_index\tmnemonic\tapi_address\tp2p_address\tstdout\tstderr"
    )?;
    for (peer_index, peer) in peers.iter().enumerate() {
        let stdout = peer.latest_stdout_log_path();
        let stderr = peer.latest_stderr_log_path();
        for path in stdout.iter().chain(stderr.iter()) {
            copy_diagnostic_file(source_root, path, &copied_root)?;
        }
        writeln!(
            index,
            "{peer_index}\t{}\t{}\t{}\t{}\t{}",
            peer.mnemonic(),
            peer.api_address(),
            peer.p2p_address(),
            stdout
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_default(),
            stderr
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_default()
        )?;
    }
    Ok(())
}
fn copy_selected_diagnostic_files(
    source_root: &Path,
    current: &Path,
    copied_root: &Path,
) -> Result<()> {
    let entries = fs::read_dir(current).wrap_err_with(|| {
        format!(
            "failed to read diagnostic source directory {}",
            current.display()
        )
    })?;
    for entry in entries {
        let entry = entry.wrap_err("failed to read diagnostic directory entry")?;
        let path = entry.path();
        let metadata = entry
            .metadata()
            .wrap_err_with(|| format!("failed to inspect {}", path.display()))?;
        if metadata.is_dir() {
            if should_skip_diagnostic_dir(&path) {
                continue;
            }
            copy_selected_diagnostic_files(source_root, &path, copied_root)?;
        } else if metadata.is_file() && diagnostic_file_should_copy(&path) {
            copy_diagnostic_file(source_root, &path, copied_root)?;
        }
    }
    Ok(())
}
fn copy_diagnostic_file(source_root: &Path, source: &Path, copied_root: &Path) -> Result<()> {
    if !source.is_file() {
        return Ok(());
    }
    let destination =
        match source.strip_prefix(source_root) {
            Ok(relative) => copied_root.join(relative),
            Err(_) => copied_root.join(source.file_name().ok_or_else(|| {
                eyre!("diagnostic source has no file name: {}", source.display())
            })?),
        };
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).wrap_err_with(|| {
            format!(
                "failed to create diagnostic destination directory {}",
                parent.display()
            )
        })?;
    }
    fs::copy(source, &destination).wrap_err_with(|| {
        format!(
            "failed to copy diagnostic artifact {} to {}",
            source.display(),
            destination.display()
        )
    })?;
    Ok(())
}
fn diagnostic_file_should_copy(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let lower_name = name.to_ascii_lowercase();
    if lower_name.contains("genesis") || lower_name.contains("config") {
        return true;
    }
    matches!(
        path.extension()
            .and_then(|extension| extension.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("log" | "toml" | "json" | "nrt")
    )
}
fn should_skip_diagnostic_dir(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    matches!(
        name.to_ascii_lowercase().as_str(),
        "storage" | "store" | "kura" | "blocks" | "blockstore" | "pipeline_sidecars"
    )
}
fn bounded_sumeragi_status_sample_request_timeout(current: Duration) -> Duration {
    let status_sample_timeout = Duration::from_millis(IZANAMI_STATUS_SAMPLE_REQUEST_TIMEOUT_MS);
    if current.is_zero() || current > status_sample_timeout {
        status_sample_timeout
    } else {
        current
    }
}
impl BlockIntervalTracker {
    fn record(&mut self, blocks_advanced: u64, elapsed: Duration) -> Option<u64> {
        if blocks_advanced == 0 {
            return None;
        }
        let elapsed_ms = u64::try_from(elapsed.as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        let interval_ms = elapsed_ms.div_ceil(blocks_advanced);
        self.samples.push(WeightedIntervalSample {
            interval_ms,
            weight: blocks_advanced,
        });
        self.total_weight = self.total_weight.saturating_add(blocks_advanced);
        Some(interval_ms)
    }
    fn summary(&self) -> Option<BlockIntervalSummary> {
        if self.total_weight == 0 {
            return None;
        }
        Some(BlockIntervalSummary {
            p50_ms: self.quantile_ms(0.50),
            p95_ms: self.quantile_ms(0.95),
            samples: self.total_weight,
        })
    }
    fn quantile_ms(&self, quantile: f64) -> u64 {
        debug_assert!((0.0..=1.0).contains(&quantile));
        if self.total_weight == 0 {
            return 0;
        }
        let mut sorted = self.samples.clone();
        sorted.sort_unstable_by_key(|sample| sample.interval_ms);
        let rank = ((self.total_weight as f64) * quantile)
            .ceil()
            .clamp(1.0, self.total_weight as f64) as u64;
        let mut cumulative = 0u64;
        for sample in sorted {
            cumulative = cumulative.saturating_add(sample.weight);
            if cumulative >= rank {
                return sample.interval_ms;
            }
        }
        0
    }
}
struct HeightDivergenceState {
    first_seen_above_threshold: Option<Instant>,
}
impl HeightDivergenceState {
    fn new() -> Self {
        Self {
            first_seen_above_threshold: None,
        }
    }
    fn observe(
        &mut self,
        now: Instant,
        divergence_blocks: u64,
        max_allowed_divergence: u64,
    ) -> bool {
        if divergence_blocks > max_allowed_divergence {
            if self.first_seen_above_threshold.is_none() {
                self.first_seen_above_threshold = Some(now);
                return true;
            }
        } else {
            self.first_seen_above_threshold = None;
        }
        false
    }
    fn violated(&self, now: Instant, max_window: Duration) -> bool {
        self.first_seen_above_threshold
            .is_some_and(|started| now.saturating_duration_since(started) >= max_window)
    }
}
#[derive(Clone, Copy, Debug, Default)]
struct TargetProgressResult {
    target_reached: bool,
    quorum_min_height: u64,
    strict_min_height: u64,
    max_peer_height_skew: u64,
    quorum_block_interval_p50_ms: Option<u64>,
    quorum_block_interval_p95_ms: Option<u64>,
    quorum_block_interval_samples: Option<u64>,
    strict_block_interval_p50_ms: Option<u64>,
    strict_block_interval_p95_ms: Option<u64>,
    strict_block_interval_samples: Option<u64>,
    quorum_min_txs_approved: u64,
    strict_min_txs_approved: u64,
    max_peer_txs_approved_skew: u64,
    first_progress_after_fault_start_height: Option<u64>,
    first_progress_after_fault_end_height: Option<u64>,
}
impl TargetProgressResult {
    fn attach_txs_approved_samples(&mut self, samples: &[u64], tolerated_failures: usize) {
        self.quorum_min_txs_approved =
            quorum_min_height_from_samples(samples.to_vec(), tolerated_failures);
        self.strict_min_txs_approved = samples.iter().copied().min().unwrap_or(0);
        self.max_peer_txs_approved_skew = max_peer_height_skew_from_samples(samples);
    }
    fn attach_block_interval_summaries(
        &mut self,
        quorum_summary: Option<BlockIntervalSummary>,
        strict_summary: Option<BlockIntervalSummary>,
    ) {
        if let Some(summary) = quorum_summary {
            self.quorum_block_interval_p50_ms = Some(summary.p50_ms);
            self.quorum_block_interval_p95_ms = Some(summary.p95_ms);
            self.quorum_block_interval_samples = Some(summary.samples);
        }
        if let Some(summary) = strict_summary {
            self.strict_block_interval_p50_ms = Some(summary.p50_ms);
            self.strict_block_interval_p95_ms = Some(summary.p95_ms);
            self.strict_block_interval_samples = Some(summary.samples);
        }
    }
}
fn duration_deadline_progress_result(
    heights: &[u64],
    tolerated_failures: usize,
) -> TargetProgressResult {
    let quorum_min_height = quorum_min_height_from_samples(heights.to_vec(), tolerated_failures);
    let strict_min_height = heights.iter().copied().min().unwrap_or(0);
    let max_peer_height_skew = max_peer_height_skew_from_samples(heights);
    TargetProgressResult {
        target_reached: false,
        quorum_min_height,
        strict_min_height,
        max_peer_height_skew,
        quorum_block_interval_p50_ms: None,
        quorum_block_interval_p95_ms: None,
        quorum_block_interval_samples: None,
        strict_block_interval_p50_ms: None,
        strict_block_interval_p95_ms: None,
        strict_block_interval_samples: None,
        quorum_min_txs_approved: 0,
        strict_min_txs_approved: 0,
        max_peer_txs_approved_skew: 0,
        first_progress_after_fault_start_height: None,
        first_progress_after_fault_end_height: None,
    }
}
fn max_peer_height_skew_from_samples(heights: &[u64]) -> u64 {
    let Some(min_height) = heights.iter().copied().min() else {
        return 0;
    };
    heights
        .iter()
        .copied()
        .max()
        .unwrap_or(min_height)
        .saturating_sub(min_height)
}
async fn wait_for_duration_deadline(
    run_control: &RunControl,
    peers: &[NetworkPeer],
    configured_faulty_peers: usize,
    ingress_pool: Option<&IngressEndpointPool>,
    _fault_start_at: Instant,
    _fault_end_at: Instant,
) -> Result<TargetProgressResult> {
    if run_control.stop_requested() {
        return Err(eyre!("izanami run stopped before duration completed"));
    }
    let stop_notify = run_control.stop_notifier();
    tokio::select! {
        () = stop_notify.notified() => Err(eyre!("izanami run stopped before duration completed")),
        () = time::sleep_until(run_control.deadline().into()) => {
            let sampled_heights = sampled_peer_heights_with_ids(peers);
            let heights: Vec<_> = sampled_heights.iter().map(|(_, height)| *height).collect();
            let tolerated_failures =
                effective_tolerated_peer_failures(peers.len(), configured_faulty_peers);
            let mut progress = duration_deadline_progress_result(&heights, tolerated_failures);
            run_control.stop();
            let txs_approved_samples = sampled_peer_txs_approved(peers).await;
            progress.attach_txs_approved_samples(&txs_approved_samples, tolerated_failures);
            let now = Instant::now();
            if let Some(ingress_pool) = ingress_pool {
                ingress_pool.update_lag_snapshot(
                    progress.quorum_min_height,
                    sampled_heights.as_slice(),
                    now,
                );
            }
            info!(
                target: "izanami::progress",
                quorum_min_height = progress.quorum_min_height,
                strict_min_height = progress.strict_min_height,
                max_peer_height_skew = progress.max_peer_height_skew,
                quorum_min_txs_approved = progress.quorum_min_txs_approved,
                strict_min_txs_approved = progress.strict_min_txs_approved,
                max_peer_txs_approved_skew = progress.max_peer_txs_approved_skew,
                first_progress_after_fault_start_height = progress.first_progress_after_fault_start_height,
                first_progress_after_fault_end_height = progress.first_progress_after_fault_end_height,
                tolerated_failures,
                sampled_peers = heights.len(),
                sampled_statuses = txs_approved_samples.len(),
                "duration deadline reached with sampled block heights"
            );
            Ok(progress)
        },
    }
}
fn enforce_latency_p95_gate(
    block_intervals: &BlockIntervalTracker,
    strict_block_intervals: &BlockIntervalTracker,
    latency_p95_threshold: Option<Duration>,
    target_blocks: u64,
    elapsed: Duration,
    checkpoint: &'static str,
) -> Result<()> {
    let Some(threshold) = latency_p95_threshold else {
        return Ok(());
    };
    let threshold_ms = u64::try_from(threshold.as_millis()).unwrap_or(u64::MAX);
    let Some(summary) = block_intervals.summary() else {
        if checkpoint == "duration_deadline" {
            return Err(eyre!(
                "p95 block interval samples unavailable at checkpoint {} (threshold {}ms, target {}, elapsed {:?})",
                checkpoint,
                threshold_ms,
                target_blocks,
                elapsed
            ));
        }
        warn!(
            target: "izanami::progress",
            target_blocks,
            threshold_ms,
            checkpoint,
            elapsed = ?elapsed,
            "latency p95 gate is configured but quorum interval samples are unavailable; skipping gate evaluation"
        );
        return Ok(());
    };
    if summary.p95_ms > threshold_ms {
        return Err(eyre!(
            "quorum p95 block interval {}ms exceeded threshold {}ms (samples {}, target {}, elapsed {:?}, checkpoint {})",
            summary.p95_ms,
            threshold_ms,
            summary.samples,
            target_blocks,
            elapsed,
            checkpoint
        ));
    }
    if let Some(strict_summary) = strict_block_intervals.summary()
        && strict_summary.p95_ms > threshold_ms
    {
        return Err(eyre!(
            "strict p95 block interval {}ms exceeded threshold {}ms (samples {}, target {}, elapsed {:?}, checkpoint {})",
            strict_summary.p95_ms,
            threshold_ms,
            strict_summary.samples,
            target_blocks,
            elapsed,
            checkpoint
        ));
    }
    Ok(())
}
async fn wait_for_target_blocks(
    peers: &[NetworkPeer],
    target_blocks: u64,
    configured_faulty_peers: usize,
    progress_interval: Duration,
    progress_timeout: Duration,
    latency_p95_threshold: Option<Duration>,
    run_control: &RunControl,
    ingress_pool: Option<&IngressEndpointPool>,
    metrics: Option<&Metrics>,
    target_blocks_soft_kpi: bool,
    fault_start_at: Instant,
    fault_end_at: Instant,
) -> Result<TargetProgressResult> {
    let start = Instant::now();
    let mut progress = ProgressState::new(start);
    let mut strict_progress = ProgressState::new(start);
    let mut strict_tolerated_stall_logged_at: Option<Instant> = None;
    let mut divergence = HeightDivergenceState::new();
    let mut block_intervals = BlockIntervalTracker::default();
    let mut strict_block_intervals = BlockIntervalTracker::default();
    let mut target_reached = false;
    let mut max_peer_height_skew = 0u64;
    let mut first_progress_after_fault_start_height = None;
    let mut first_progress_after_fault_end_height = None;
    let tolerated_failures =
        effective_tolerated_peer_failures(peers.len(), configured_faulty_peers);
    let strict_divergence_window =
        Duration::from_secs(IZANAMI_STRICT_HEIGHT_DIVERGENCE_MAX_WINDOW_SECS);
    loop {
        if run_control.stop_requested() {
            return Err(eyre!("izanami run stopped before target blocks reached"));
        }
        let now = Instant::now();
        let sampled_heights = sampled_peer_heights_with_ids(peers);
        let heights: Vec<_> = sampled_heights.iter().map(|(_, height)| *height).collect();
        max_peer_height_skew =
            max_peer_height_skew.max(max_peer_height_skew_from_samples(&heights));
        let strict_min_height = heights.iter().copied().min().unwrap_or(0);
        let min_height = quorum_min_height_from_samples(heights.clone(), tolerated_failures);
        if let Some(ingress_pool) = ingress_pool {
            ingress_pool.update_lag_snapshot(min_height, sampled_heights.as_slice(), now);
        }
        let strict_reference_height =
            strict_divergence_reference_height_from_samples(heights.clone(), tolerated_failures);
        let divergence_blocks = strict_reference_height.saturating_sub(strict_min_height);
        let lagging_peers = strict_divergence_lagging_peer_count(
            &heights,
            strict_reference_height,
            IZANAMI_STRICT_HEIGHT_DIVERGENCE_MAX_BLOCKS,
        );
        let strict_guard_active =
            should_enforce_strict_progress_timeout(lagging_peers, tolerated_failures);
        if now >= run_control.deadline() {
            if target_blocks_soft_kpi {
                enforce_latency_p95_gate(
                    &block_intervals,
                    &strict_block_intervals,
                    latency_p95_threshold,
                    target_blocks,
                    now.duration_since(start),
                    "duration_deadline",
                )?;
                let mut result = TargetProgressResult {
                    target_reached,
                    quorum_min_height: min_height,
                    strict_min_height,
                    max_peer_height_skew,
                    quorum_block_interval_p50_ms: None,
                    quorum_block_interval_p95_ms: None,
                    quorum_block_interval_samples: None,
                    strict_block_interval_p50_ms: None,
                    strict_block_interval_p95_ms: None,
                    strict_block_interval_samples: None,
                    quorum_min_txs_approved: 0,
                    strict_min_txs_approved: 0,
                    max_peer_txs_approved_skew: 0,
                    first_progress_after_fault_start_height,
                    first_progress_after_fault_end_height,
                };
                result.attach_block_interval_summaries(
                    block_intervals.summary(),
                    strict_block_intervals.summary(),
                );
                run_control.stop();
                let txs_approved_samples = sampled_peer_txs_approved(peers).await;
                result.attach_txs_approved_samples(&txs_approved_samples, tolerated_failures);
                return Ok(result);
            }
            return Err(eyre!(
                "timed out before reaching target blocks (quorum min height {}, strict min {}, target {}, tolerated_failures {})",
                progress.last_height,
                strict_min_height,
                target_blocks,
                tolerated_failures
            ));
        }
        let divergence_started = if strict_guard_active {
            divergence.observe(
                now,
                divergence_blocks,
                IZANAMI_STRICT_HEIGHT_DIVERGENCE_MAX_BLOCKS,
            )
        } else {
            // A single tolerated outlier should not start the strict divergence timer.
            let _ = divergence.observe(now, 0, IZANAMI_STRICT_HEIGHT_DIVERGENCE_MAX_BLOCKS);
            false
        };
        if divergence_started {
            warn!(
                target: "izanami::progress",
                quorum_min_height = min_height,
                strict_reference_height,
                strict_min_height,
                divergence_blocks,
                lagging_peers,
                tolerated_failures,
                max_allowed_divergence = IZANAMI_STRICT_HEIGHT_DIVERGENCE_MAX_BLOCKS,
                max_window = ?strict_divergence_window,
                "detected quorum/strict height divergence above safety threshold"
            );
        }
        if strict_guard_active && divergence.violated(now, strict_divergence_window) {
            return Err(eyre!(
                "height divergence exceeded safety window (divergence {}, threshold {}, window {:?}, quorum min {}, strict reference {}, strict min {}, lagging peers {}, target {}, tolerated_failures {})",
                divergence_blocks,
                IZANAMI_STRICT_HEIGHT_DIVERGENCE_MAX_BLOCKS,
                strict_divergence_window,
                min_height,
                strict_reference_height,
                strict_min_height,
                lagging_peers,
                target_blocks,
                tolerated_failures
            ));
        }
        if min_height > progress.last_height {
            if now >= fault_start_at && first_progress_after_fault_start_height.is_none() {
                first_progress_after_fault_start_height = Some(min_height);
                info!(
                    target: "izanami::progress",
                    quorum_min_height = min_height,
                    strict_min_height,
                    fault_start_elapsed = ?now.saturating_duration_since(fault_start_at),
                    "first block height progress after fault window start"
                );
            }
            if now >= fault_end_at && first_progress_after_fault_end_height.is_none() {
                first_progress_after_fault_end_height = Some(min_height);
                info!(
                    target: "izanami::progress",
                    quorum_min_height = min_height,
                    strict_min_height,
                    fault_end_elapsed = ?now.saturating_duration_since(fault_end_at),
                    "first block height progress after fault window end"
                );
            }
        }
        if min_height >= target_blocks && !target_reached {
            target_reached = true;
            let progress_metrics = metrics.map_or_else(MetricsSnapshot::default, Metrics::snapshot);
            let strict_summary = strict_block_intervals.summary();
            if let Some(summary) = block_intervals.summary() {
                info!(
                    target: "izanami::progress",
                    quorum_min_height = min_height,
                    strict_min_height,
                    tolerated_failures,
                    target_blocks,
                    offered = progress_metrics.offered,
                    ingress_accepted = progress_metrics.ingress_accepted,
                    blocking_applied_success = progress_metrics.blocking_applied_success,
                    confirmation_sampled = progress_metrics.confirmation_sampled,
                    confirmation_applied = progress_metrics.confirmation_applied,
                    confirmation_failed = progress_metrics.confirmation_failed,
                    inflight_current = progress_metrics.inflight_current,
                    backlog_depth = progress_metrics.backlog_depth,
                    submitters = progress_metrics.submitters,
                    interval_p50_ms = summary.p50_ms,
                    interval_p95_ms = summary.p95_ms,
                    interval_samples = summary.samples,
                    strict_interval_p50_ms = strict_summary.map(|item| item.p50_ms),
                    strict_interval_p95_ms = strict_summary.map(|item| item.p95_ms),
                    strict_interval_samples = strict_summary.map(|item| item.samples),
                    elapsed = ?now.duration_since(start),
                    "target block height reached"
                );
                enforce_latency_p95_gate(
                    &block_intervals,
                    &strict_block_intervals,
                    latency_p95_threshold,
                    target_blocks,
                    now.duration_since(start),
                    "target_reached",
                )?;
            } else {
                info!(
                    target: "izanami::progress",
                    quorum_min_height = min_height,
                    strict_min_height,
                    tolerated_failures,
                    target_blocks,
                    offered = progress_metrics.offered,
                    ingress_accepted = progress_metrics.ingress_accepted,
                    blocking_applied_success = progress_metrics.blocking_applied_success,
                    confirmation_sampled = progress_metrics.confirmation_sampled,
                    confirmation_applied = progress_metrics.confirmation_applied,
                    confirmation_failed = progress_metrics.confirmation_failed,
                    inflight_current = progress_metrics.inflight_current,
                    backlog_depth = progress_metrics.backlog_depth,
                    submitters = progress_metrics.submitters,
                    elapsed = ?now.duration_since(start),
                    "target block height reached"
                );
            }
            if !target_blocks_soft_kpi {
                let mut result = TargetProgressResult {
                    target_reached: true,
                    quorum_min_height: min_height,
                    strict_min_height,
                    max_peer_height_skew,
                    quorum_block_interval_p50_ms: None,
                    quorum_block_interval_p95_ms: None,
                    quorum_block_interval_samples: None,
                    strict_block_interval_p50_ms: None,
                    strict_block_interval_p95_ms: None,
                    strict_block_interval_samples: None,
                    quorum_min_txs_approved: 0,
                    strict_min_txs_approved: 0,
                    max_peer_txs_approved_skew: 0,
                    first_progress_after_fault_start_height,
                    first_progress_after_fault_end_height,
                };
                result.attach_block_interval_summaries(
                    block_intervals.summary(),
                    strict_block_intervals.summary(),
                );
                run_control.stop();
                let txs_approved_samples = sampled_peer_txs_approved(peers).await;
                result.attach_txs_approved_samples(&txs_approved_samples, tolerated_failures);
                return Ok(result);
            }
            info!(
                target: "izanami::progress",
                target_blocks,
                quorum_min_height = min_height,
                strict_min_height,
                tolerated_failures,
                "target_blocks KPI reached; continuing until soak deadline"
            );
        }
        if let Some((blocks_advanced, elapsed)) = strict_progress.update(now, strict_min_height) {
            let interval_ms = strict_block_intervals
                .record(blocks_advanced, elapsed)
                .unwrap_or_default();
            let progress_metrics = metrics.map_or_else(MetricsSnapshot::default, Metrics::snapshot);
            strict_tolerated_stall_logged_at = None;
            info!(
                target: "izanami::progress",
                strict_min_height,
                target_blocks,
                blocks_advanced,
                interval_ms,
                offered = progress_metrics.offered,
                ingress_accepted = progress_metrics.ingress_accepted,
                blocking_applied_success = progress_metrics.blocking_applied_success,
                confirmation_sampled = progress_metrics.confirmation_sampled,
                confirmation_applied = progress_metrics.confirmation_applied,
                confirmation_failed = progress_metrics.confirmation_failed,
                inflight_current = progress_metrics.inflight_current,
                backlog_depth = progress_metrics.backlog_depth,
                submitters = progress_metrics.submitters,
                "strict block height advanced"
            );
        } else if strict_progress.stalled(now, progress_timeout) {
            if strict_guard_active {
                return Err(eyre!(
                    "no strict block height progress for {:?} (strict min height {}, quorum min height {}, target {}, tolerated_failures {})",
                    progress_timeout,
                    strict_min_height,
                    min_height,
                    target_blocks,
                    tolerated_failures
                ));
            }
            let should_log = strict_tolerated_stall_logged_at.map_or(true, |last| {
                now.saturating_duration_since(last) >= progress_interval
            });
            if should_log {
                let lagging = sampled_heights
                    .iter()
                    .filter_map(|(peer_id, height)| {
                        (strict_reference_height.saturating_sub(*height)
                            > IZANAMI_STRICT_HEIGHT_DIVERGENCE_MAX_BLOCKS)
                            .then_some((peer_id.clone(), *height))
                    })
                    .collect::<Vec<_>>();
                warn!(
                    target: "izanami::progress",
                    strict_min_height,
                    quorum_min_height = min_height,
                    strict_reference_height,
                    lagging_peers,
                    tolerated_failures,
                    strict_timeout = ?progress_timeout,
                    ?lagging,
                    "strict block height is stalled past strict timeout under tolerated outlier lag; continuing with quorum progress"
                );
                strict_tolerated_stall_logged_at = Some(now);
            }
        } else {
            let should_log = strict_tolerated_stall_logged_at.map_or(true, |last| {
                now.saturating_duration_since(last) >= progress_interval
            });
            if should_log && strict_progress.stalled(now, progress_interval) {
                let lagging = sampled_heights
                    .iter()
                    .filter_map(|(peer_id, height)| {
                        (strict_reference_height.saturating_sub(*height)
                            > IZANAMI_STRICT_HEIGHT_DIVERGENCE_MAX_BLOCKS)
                            .then_some((peer_id.clone(), *height))
                    })
                    .collect::<Vec<_>>();
                warn!(
                    target: "izanami::progress",
                    strict_min_height,
                    quorum_min_height = min_height,
                    strict_reference_height,
                    lagging_peers,
                    tolerated_failures,
                    strict_timeout = ?progress_timeout,
                    ?lagging,
                    "{}",
                    strict_progress_stall_scope_message(lagging_peers, tolerated_failures)
                );
                strict_tolerated_stall_logged_at = Some(now);
            }
        }
        if let Some((blocks_advanced, elapsed)) = progress.update(now, min_height) {
            if now >= fault_start_at && first_progress_after_fault_start_height.is_none() {
                first_progress_after_fault_start_height = Some(min_height);
                info!(
                    target: "izanami::progress",
                    quorum_min_height = min_height,
                    strict_min_height,
                    fault_start_elapsed = ?now.saturating_duration_since(fault_start_at),
                    "first block height progress after fault window start"
                );
            }
            if now >= fault_end_at && first_progress_after_fault_end_height.is_none() {
                first_progress_after_fault_end_height = Some(min_height);
                info!(
                    target: "izanami::progress",
                    quorum_min_height = min_height,
                    strict_min_height,
                    fault_end_elapsed = ?now.saturating_duration_since(fault_end_at),
                    "first block height progress after fault window end"
                );
            }
            let interval_ms = block_intervals
                .record(blocks_advanced, elapsed)
                .unwrap_or_default();
            let progress_metrics = metrics.map_or_else(MetricsSnapshot::default, Metrics::snapshot);
            info!(
                target: "izanami::progress",
                quorum_min_height = min_height,
                strict_min_height,
                tolerated_failures,
                target_blocks,
                blocks_advanced,
                interval_ms,
                offered = progress_metrics.offered,
                ingress_accepted = progress_metrics.ingress_accepted,
                blocking_applied_success = progress_metrics.blocking_applied_success,
                confirmation_sampled = progress_metrics.confirmation_sampled,
                confirmation_applied = progress_metrics.confirmation_applied,
                confirmation_failed = progress_metrics.confirmation_failed,
                inflight_current = progress_metrics.inflight_current,
                backlog_depth = progress_metrics.backlog_depth,
                submitters = progress_metrics.submitters,
                "block height advanced"
            );
        } else if progress.stalled(now, progress_timeout) {
            return Err(eyre!(
                "no block height progress for {:?} (quorum min height {}, strict min {}, target {}, tolerated_failures {})",
                progress_timeout,
                min_height,
                strict_min_height,
                target_blocks,
                tolerated_failures
            ));
        }
        let remaining = run_control
            .deadline()
            .checked_duration_since(Instant::now())
            .unwrap_or_default();
        if remaining.is_zero() {
            if target_blocks_soft_kpi {
                enforce_latency_p95_gate(
                    &block_intervals,
                    &strict_block_intervals,
                    latency_p95_threshold,
                    target_blocks,
                    now.duration_since(start),
                    "duration_deadline",
                )?;
                let mut result = TargetProgressResult {
                    target_reached,
                    quorum_min_height: min_height,
                    strict_min_height,
                    max_peer_height_skew,
                    quorum_block_interval_p50_ms: None,
                    quorum_block_interval_p95_ms: None,
                    quorum_block_interval_samples: None,
                    strict_block_interval_p50_ms: None,
                    strict_block_interval_p95_ms: None,
                    strict_block_interval_samples: None,
                    quorum_min_txs_approved: 0,
                    strict_min_txs_approved: 0,
                    max_peer_txs_approved_skew: 0,
                    first_progress_after_fault_start_height,
                    first_progress_after_fault_end_height,
                };
                result.attach_block_interval_summaries(
                    block_intervals.summary(),
                    strict_block_intervals.summary(),
                );
                run_control.stop();
                let txs_approved_samples = sampled_peer_txs_approved(peers).await;
                result.attach_txs_approved_samples(&txs_approved_samples, tolerated_failures);
                return Ok(result);
            }
            return Err(eyre!(
                "timed out before reaching target blocks (quorum min height {}, strict min {}, target {}, tolerated_failures {})",
                min_height,
                strict_min_height,
                target_blocks,
                tolerated_failures
            ));
        }
        time::sleep(progress_interval.min(remaining)).await;
    }
}
static SUBMISSION_METADATA_KEY: OnceLock<Name> = OnceLock::new();
fn submission_metadata(counter: &AtomicU64) -> Metadata {
    let key = SUBMISSION_METADATA_KEY
        .get_or_init(|| "izanami_submission_id".parse().expect("valid metadata key"));
    let mut metadata = Metadata::default();
    metadata.insert(key.clone(), counter.fetch_add(1, Ordering::Relaxed));
    metadata
}
#[derive(Clone)]
struct SubmissionAuditCandidate {
    endpoint_idx: usize,
    signer: AccountRecord,
    hash: HashOf<SignedTransaction>,
    plan_label: &'static str,
}
struct PreparedTransactionSubmission {
    order: u64,
    plan: TransactionPlan,
    payload: PreparedTransactionPayload,
}
#[derive(Clone)]
struct PrebuiltTransactionPool {
    queue: Arc<StdMutex<VecDeque<PreparedTransactionSubmission>>>,
    target_len: u64,
}
impl PrebuiltTransactionPool {
    fn new(submissions: Vec<PreparedTransactionSubmission>) -> Self {
        let target_len = u64::try_from(submissions.len()).unwrap_or(u64::MAX);
        Self {
            queue: Arc::new(StdMutex::new(VecDeque::from(submissions))),
            target_len,
        }
    }
    fn try_pop(&self) -> Option<PreparedTransactionSubmission> {
        self.queue.lock().ok()?.pop_front()
    }
    fn target_len(&self) -> u64 {
        self.target_len
    }
}
#[derive(Clone, Copy)]
struct SubmissionAuditBudget {
    window_started_at: Option<Instant>,
    confirmations_in_window: u32,
}
impl SubmissionAuditBudget {
    fn acquire_at(&mut self, now: Instant) -> bool {
        match self.window_started_at {
            Some(start)
                if now.saturating_duration_since(start)
                    < Duration::from_secs(IZANAMI_THROUGHPUT_CONFIRMATION_WINDOW_SECS) =>
            {
                if self.confirmations_in_window
                    >= IZANAMI_THROUGHPUT_CONFIRMATION_CAP_PER_MINUTE_PER_ENDPOINT
                {
                    return false;
                }
            }
            _ => {
                self.window_started_at = Some(now);
                self.confirmations_in_window = 0;
            }
        }
        self.confirmations_in_window = self.confirmations_in_window.saturating_add(1);
        true
    }
}
impl Default for SubmissionAuditBudget {
    fn default() -> Self {
        Self {
            window_started_at: None,
            confirmations_in_window: 0,
        }
    }
}
struct SubmissionOutcome {
    endpoint_idx: usize,
    hash: HashOf<SignedTransaction>,
}
fn should_audit_throughput_confirmation(
    confirmation_mode: SubmissionConfirmationMode,
    expect_success: bool,
) -> bool {
    expect_success
        && matches!(
            confirmation_mode,
            SubmissionConfirmationMode::AcceptedByIngress
        )
}
fn should_sample_throughput_confirmation(hash: &HashOf<SignedTransaction>, seed: u64) -> bool {
    should_sample_throughput_confirmation_bytes(hash.as_ref(), seed)
}
fn should_sample_throughput_confirmation_bytes(hash_bytes: &[u8], seed: u64) -> bool {
    throughput_confirmation_sample_bucket(hash_bytes, seed)
        < IZANAMI_THROUGHPUT_CONFIRMATION_SAMPLE_PERCENT
}
fn throughput_confirmation_sample_bucket(hash_bytes: &[u8], seed: u64) -> u64 {
    let mut mixed = seed ^ 0x9E37_79B9_7F4A_7C15;
    for chunk in hash_bytes.chunks(8) {
        let mut padded = [0_u8; 8];
        padded[..chunk.len()].copy_from_slice(chunk);
        mixed ^= u64::from_le_bytes(padded).rotate_left(13);
        mixed = mixed.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }
    mixed % 100
}
fn try_schedule_submission_audit(
    confirmation_audit_tx: &mpsc::Sender<SubmissionAuditCandidate>,
    metrics: &Metrics,
    candidate: SubmissionAuditCandidate,
    run_control: &RunControl,
    wait_options: &TransactionWaitOptions,
) {
    let endpoint_idx = candidate.endpoint_idx;
    let hash = candidate.hash;
    let plan_label = candidate.plan_label;
    let now = Instant::now();
    if run_control.stop_requested() {
        metrics.record_confirmation_audit_shutdown_noise();
        debug!(
            target: "izanami::audit",
            endpoint_idx,
            hash = %hash,
            plan = plan_label,
            "skipping sampled confirmation because the run is stopping"
        );
        return;
    }
    if !confirmation_audit_has_deadline_budget(now, run_control.deadline(), wait_options) {
        metrics.record_confirmation_audit_budget_skipped();
        debug!(
            target: "izanami::audit",
            endpoint_idx,
            hash = %hash,
            plan = plan_label,
            remaining_ms = run_control
                .deadline()
                .checked_duration_since(now)
                .map(|duration| duration.as_millis())
                .unwrap_or_default(),
            timeout_ms = wait_options.timeout.as_millis(),
            "skipping sampled confirmation before enqueue because the remaining run window is too short"
        );
        return;
    }
    match confirmation_audit_tx.try_send(candidate) {
        Ok(()) => metrics.record_confirmation_audit_sampled(),
        Err(mpsc::error::TrySendError::Full(_)) => {
            metrics.record_confirmation_audit_queue_dropped();
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            if run_control.should_stop() {
                metrics.record_confirmation_audit_shutdown_noise();
                debug!(
                    target: "izanami::audit",
                    endpoint_idx,
                    hash = %hash,
                    plan = plan_label,
                    "sampled confirmation audit channel closed during shutdown"
                );
            } else {
                metrics.record_confirmation_audit_failed();
                warn!(
                    target: "izanami::audit",
                    endpoint_idx,
                    hash = %hash,
                    plan = plan_label,
                    "sampled confirmation audit channel closed before the run deadline"
                );
            }
        }
    }
}
fn repetitions_from_repeats(repeats: Repeats) -> Option<u32> {
    match repeats {
        Repeats::Exactly(count) => Some(count),
        Repeats::Indefinitely => None,
    }
}
#[derive(Debug, PartialEq, Eq)]
enum MintPrecheck {
    Proceed { on_chain: u32 },
    SkipMissing,
    SkipQueryFailed,
}
fn evaluate_mint_precheck<E>(result: Result<Option<u32>, E>) -> MintPrecheck {
    match result {
        Ok(Some(0)) | Ok(None) => MintPrecheck::SkipMissing,
        Ok(Some(on_chain)) => MintPrecheck::Proceed { on_chain },
        Err(_) => MintPrecheck::SkipQueryFailed,
    }
}
#[derive(Debug, PartialEq, Eq)]
enum BurnPrecheck {
    Proceed { on_chain: u32 },
    SkipMissing,
    SkipInsufficient { on_chain: u32 },
    SkipQueryFailed,
}
fn evaluate_burn_precheck<E>(result: Result<Option<u32>, E>, burn_amount: u32) -> BurnPrecheck {
    match result {
        Ok(None) => BurnPrecheck::SkipMissing,
        Ok(Some(on_chain)) if on_chain <= burn_amount => {
            BurnPrecheck::SkipInsufficient { on_chain }
        }
        Ok(Some(on_chain)) => BurnPrecheck::Proceed { on_chain },
        Err(_) => BurnPrecheck::SkipQueryFailed,
    }
}
fn query_trigger_repetitions(client: &Client, trigger_id: &TriggerId) -> Result<Option<u32>> {
    let iter = client.client().query(FindTriggers::new()).execute()?;
    for trigger in iter {
        let trigger = trigger?;
        if trigger.id() == trigger_id {
            return Ok(repetitions_from_repeats(trigger.action().repeats()));
        }
    }
    Ok(None)
}
fn record_plan_skip(
    metrics: &Metrics,
    plan_label: &'static str,
    expect_success: bool,
    reason: &'static str,
) {
    debug!(
        target: "izanami::workload",
        plan = plan_label,
        reason,
        "skipping plan submission"
    );
    if expect_success {
        metrics.record_failure();
    } else {
        metrics.record_expected_failure();
    }
}
struct PrebuiltLoadSupervisor {
    metrics: Arc<Metrics>,
    ingress_pool: Arc<IngressEndpointPool>,
    run_control: Arc<RunControl>,
    workload: Arc<WorkloadEngine>,
    prebuilt_pool: PrebuiltTransactionPool,
    semaphore: Arc<Semaphore>,
    backlog_limit: usize,
    submission_tps: f64,
    submitters: usize,
    submission_confirmation: SubmissionConfirmationMode,
    confirmation_audit_tx: Option<mpsc::Sender<SubmissionAuditCandidate>>,
    confirmation_audit_seed: u64,
    confirmation_audit_wait_options: TransactionWaitOptions,
    shutdown_drain_timeout: Duration,
}
fn spawn_prebuilt_load_supervisor(args: PrebuiltLoadSupervisor) -> JoinHandle<()> {
    tokio::spawn(async move {
        let PrebuiltLoadSupervisor {
            metrics,
            ingress_pool,
            run_control,
            workload,
            prebuilt_pool,
            semaphore,
            backlog_limit,
            submission_tps,
            submitters,
            submission_confirmation,
            confirmation_audit_tx,
            confirmation_audit_seed,
            confirmation_audit_wait_options,
            shutdown_drain_timeout,
        } = args;
        let submitters = submitters.max(1);
        let deadline = run_control.deadline();
        let stop_notify = run_control.stop_notifier();
        let started_at = Instant::now();
        let feed_tick = Duration::from_millis(IZANAMI_PREBUILD_FEED_TICK_MS);
        let prebuilt_target = prebuilt_pool.target_len();
        let submit_batch_size = effective_prebuilt_submit_batch_size(submission_tps);
        let mut submissions = JoinSet::new();
        let mut launched = 0_u64;
        let mut shutdown_skip_recorded = false;
        loop {
            drain_ready_submissions(&mut submissions);
            let now = Instant::now();
            let due_by_now = (now.saturating_duration_since(started_at).as_secs_f64()
                * submission_tps)
                .floor() as u64;
            let due_by_now = due_by_now.min(prebuilt_target);
            while launched < due_by_now {
                if run_control.stop_requested() {
                    record_submit_plan_shutdown_skip_once(&metrics, &mut shutdown_skip_recorded);
                    break;
                }
                if !wait_for_submission_capacity(
                    &mut submissions,
                    backlog_limit,
                    stop_notify.as_ref(),
                    deadline,
                )
                .await
                {
                    if run_control.stop_requested() || Instant::now() >= deadline {
                        record_submit_plan_shutdown_skip_once(
                            &metrics,
                            &mut shutdown_skip_recorded,
                        );
                    }
                    break;
                }
                let batch_start = launched;
                let mut batch = Vec::with_capacity(submit_batch_size);
                while launched < due_by_now && batch.len() < submit_batch_size {
                    let Some(prebuilt) = prebuilt_pool.try_pop() else {
                        metrics.record_prebuilt_tx_fallback();
                        break;
                    };
                    metrics.record_prebuilt_tx_used();
                    metrics.record_submit_plan_started();
                    batch.push(prebuilt);
                    launched = launched.saturating_add(1);
                }
                if batch.is_empty() {
                    break;
                }
                metrics.record_backlog_spawn();
                let submitter_idx = (batch_start as usize) % submitters;
                let metrics_for_task = Arc::clone(&metrics);
                let ingress_pool_for_task = Arc::clone(&ingress_pool);
                let workload_for_task = Arc::clone(&workload);
                let semaphore_for_task = Arc::clone(&semaphore);
                let confirmation_audit_tx_for_task = confirmation_audit_tx.clone();
                let run_control_for_task = Arc::clone(&run_control);
                let confirmation_audit_wait_options_for_task =
                    confirmation_audit_wait_options.clone();
                submissions.spawn(async move {
                    let _backlog_guard = BacklogGuard::new(Arc::clone(&metrics_for_task));
                    submit_prebuilt_batch(
                        &ingress_pool_for_task,
                        batch,
                        submission_confirmation,
                        semaphore_for_task,
                        &metrics_for_task,
                        &workload_for_task,
                        submitter_idx,
                        confirmation_audit_tx_for_task,
                        confirmation_audit_seed,
                        &run_control_for_task,
                        &confirmation_audit_wait_options_for_task,
                    )
                    .await;
                });
            }
            let now = Instant::now();
            if run_control.stop_requested() || now >= deadline {
                record_submit_plan_shutdown_skip_once(&metrics, &mut shutdown_skip_recorded);
                break;
            }
            let sleep_for = deadline
                .checked_duration_since(now)
                .unwrap_or_default()
                .min(feed_tick);
            tokio::select! {
                () = time::sleep(sleep_for) => {},
                () = stop_notify.notified() => {
                    record_submit_plan_shutdown_skip_once(
                        &metrics,
                        &mut shutdown_skip_recorded,
                    );
                    break;
                },
            }
        }
        let aborted =
            drain_submissions_for_shutdown(&mut submissions, shutdown_drain_timeout).await;
        if aborted > 0 {
            metrics.record_submit_tasks_shutdown_aborted(aborted);
            warn!(
                target: "izanami::workload",
                aborted,
                ?shutdown_drain_timeout,
                "prebuilt submission drain timeout expired; aborted leftover tasks"
            );
        }
    })
}
async fn submit_prebuilt_plan(
    ingress_pool: &Arc<IngressEndpointPool>,
    prepared: PreparedTransactionSubmission,
    submission_confirmation: SubmissionConfirmationMode,
    semaphore: Arc<Semaphore>,
    metrics: &Arc<Metrics>,
    workload: &Arc<WorkloadEngine>,
    submitter_idx: usize,
    confirmation_audit_tx: Option<mpsc::Sender<SubmissionAuditCandidate>>,
    confirmation_audit_seed: u64,
    run_control: &RunControl,
    confirmation_audit_wait_options: &TransactionWaitOptions,
) {
    let PreparedTransactionSubmission { plan, payload, .. } = prepared;
    let signer = plan.signer.clone();
    let plan_label = plan.label;
    let expect_success = plan.expect_success;
    let effective_submission_confirmation =
        effective_submission_confirmation(submission_confirmation, &plan.state_updates);
    if !matches!(
        effective_submission_confirmation,
        SubmissionConfirmationMode::AcceptedByIngress
    ) {
        warn!(
            target: "izanami::prebuild",
            plan = plan_label,
            "prebuilt plan required blocking confirmation; falling back to failure accounting"
        );
        if expect_success {
            metrics.record_failure();
        } else {
            metrics.record_expected_failure();
        }
        workload.record_result(&plan, false).await;
        return;
    }
    let permit = match semaphore.acquire_owned().await {
        Ok(permit) => permit,
        Err(_) => {
            warn!(
                target: "izanami::workload",
                plan = plan_label,
                submitter_idx,
                "submission permit channel closed before prebuilt submit"
            );
            if expect_success {
                metrics.record_failure();
            } else {
                metrics.record_expected_failure();
            }
            workload.record_result(&plan, false).await;
            return;
        }
    };
    metrics.record_inflight_acquired();
    let _inflight_guard = InflightGuard::new(Arc::clone(metrics), permit);
    let ingress_pool_for_submit = Arc::clone(ingress_pool);
    let ingress_pool_for_retry_delay = Arc::clone(ingress_pool);
    let signer_for_submit = signer.clone();
    let submission_result = run_submission_future_result(
        plan_label,
        expect_success,
        Arc::clone(metrics),
        effective_submission_confirmation,
        async move {
            run_with_queue_timeout_retry_with_policy_and_delay_result_async(
                plan_label,
                IZANAMI_QUEUE_TIMEOUT_RETRY_ATTEMPTS,
                Duration::from_millis(IZANAMI_QUEUE_TIMEOUT_RETRY_BACKOFF_MS),
                move || ingress_pool_for_retry_delay.submission_backpressure_delay(Instant::now()),
                move || {
                    let ingress_pool_for_submit = Arc::clone(&ingress_pool_for_submit);
                    let payload = payload.clone();
                    let signer_for_submit = signer_for_submit.clone();
                    async move {
                        let ingress_pool_for_operation = Arc::clone(&ingress_pool_for_submit);
                        ingress_pool_for_submit
                            .run_with_failover_preferred_with_endpoint_async(
                                "submit_prebuilt_transaction_plan",
                                submitter_idx,
                                move |endpoint_idx, _peer| {
                                    let ingress_pool_for_submit =
                                        Arc::clone(&ingress_pool_for_operation);
                                    let payload = payload.clone();
                                    let signer_for_submit = signer_for_submit.clone();
                                    async move {
                                        let client = ingress_pool_for_submit
                                            .cached_submit_client_for(
                                                endpoint_idx,
                                                &signer_for_submit,
                                                SubmissionConfirmationMode::AcceptedByIngress,
                                            )?;
                                        client
                                            .account_client()
                                            .submit_prepared_transaction_payload(&payload)
                                            .await
                                    }
                                },
                            )
                            .await
                            .map(|(endpoint_idx, hash)| SubmissionOutcome { endpoint_idx, hash })
                    }
                },
            )
            .await
        },
    )
    .await;
    match submission_result {
        Ok(submission_outcome) => {
            workload.record_result(&plan, true).await;
            if should_audit_throughput_confirmation(
                effective_submission_confirmation,
                expect_success,
            ) && should_sample_throughput_confirmation(
                &submission_outcome.hash,
                confirmation_audit_seed,
            ) && let Some(confirmation_audit_tx) = confirmation_audit_tx.as_ref()
            {
                try_schedule_submission_audit(
                    confirmation_audit_tx,
                    metrics.as_ref(),
                    SubmissionAuditCandidate {
                        endpoint_idx: submission_outcome.endpoint_idx,
                        signer,
                        hash: submission_outcome.hash,
                        plan_label,
                    },
                    run_control,
                    confirmation_audit_wait_options,
                );
            }
        }
        Err(_err) => {
            workload.record_result(&plan, false).await;
        }
    }
}
async fn submit_prebuilt_batch(
    ingress_pool: &Arc<IngressEndpointPool>,
    mut batch: Vec<PreparedTransactionSubmission>,
    submission_confirmation: SubmissionConfirmationMode,
    semaphore: Arc<Semaphore>,
    metrics: &Arc<Metrics>,
    workload: &Arc<WorkloadEngine>,
    submitter_idx: usize,
    confirmation_audit_tx: Option<mpsc::Sender<SubmissionAuditCandidate>>,
    confirmation_audit_seed: u64,
    run_control: &RunControl,
    confirmation_audit_wait_options: &TransactionWaitOptions,
) {
    if batch.len() == 1 {
        if let Some(prepared) = batch.pop() {
            submit_prebuilt_plan(
                ingress_pool,
                prepared,
                submission_confirmation,
                semaphore,
                metrics,
                workload,
                submitter_idx,
                confirmation_audit_tx,
                confirmation_audit_seed,
                run_control,
                confirmation_audit_wait_options,
            )
            .await;
        }
        return;
    }
    let batch_len = batch.len();
    let permit_count = u32::try_from(batch_len).unwrap_or(u32::MAX);
    let permit = match semaphore.clone().acquire_many_owned(permit_count).await {
        Ok(permit) => permit,
        Err(_) => {
            warn!(
                target: "izanami::workload",
                batch_len,
                submitter_idx,
                "submission permit channel closed before prebuilt batch submit"
            );
            for submission in batch {
                if submission.plan.expect_success {
                    metrics.record_failure();
                } else {
                    metrics.record_expected_failure();
                }
                workload.record_result(&submission.plan, false).await;
            }
            return;
        }
    };
    metrics.record_inflight_acquired_many(u64::try_from(batch_len).unwrap_or(u64::MAX));
    let _inflight_guard = InflightBatchGuard::new(Arc::clone(metrics), permit, batch_len);
    let signer_for_submit = batch[0].plan.signer.clone();
    let payloads = Arc::new(
        batch
            .iter()
            .map(|submission| submission.payload.clone())
            .collect::<Vec<_>>(),
    );
    let hashes = payloads
        .iter()
        .map(PreparedTransactionPayload::hash)
        .collect::<Vec<_>>();
    let ingress_pool_for_submit = Arc::clone(ingress_pool);
    let ingress_pool_for_retry_delay = Arc::clone(ingress_pool);
    let started_at = Instant::now();
    let submission_result = run_with_queue_timeout_retry_with_policy_and_delay_result_async(
        "submit_prebuilt_transaction_batch",
        IZANAMI_QUEUE_TIMEOUT_RETRY_ATTEMPTS,
        Duration::from_millis(IZANAMI_QUEUE_TIMEOUT_RETRY_BACKOFF_MS),
        move || ingress_pool_for_retry_delay.submission_backpressure_delay(Instant::now()),
        move || {
            let ingress_pool_for_submit = Arc::clone(&ingress_pool_for_submit);
            let payloads = Arc::clone(&payloads);
            let signer_for_submit = signer_for_submit.clone();
            async move {
                let ingress_pool_for_operation = Arc::clone(&ingress_pool_for_submit);
                ingress_pool_for_submit
                    .run_with_failover_preferred_with_endpoint_async(
                        "submit_prebuilt_transaction_batch",
                        submitter_idx,
                        move |endpoint_idx, _peer| {
                            let ingress_pool_for_submit = Arc::clone(&ingress_pool_for_operation);
                            let payloads = Arc::clone(&payloads);
                            let signer_for_submit = signer_for_submit.clone();
                            async move {
                                let client = ingress_pool_for_submit.cached_submit_client_for(
                                    endpoint_idx,
                                    &signer_for_submit,
                                    SubmissionConfirmationMode::AcceptedByIngress,
                                )?;
                                client
                                    .account_client()
                                    .submit_prepared_transaction_payload_batch(payloads.as_slice())
                                    .await
                            }
                        },
                    )
                    .await
            }
        },
    )
    .await;
    let elapsed = started_at.elapsed();
    let succeeded = submission_result.is_ok();
    if let Err(err) = &submission_result {
        warn!(
            target: "izanami::workload",
            ?err,
            batch_len,
            "prebuilt transaction batch submission failed"
        );
    }
    for submission in &batch {
        metrics.record_submit_latency(elapsed);
        match (succeeded, submission.plan.expect_success) {
            (true, true) => metrics.record_success(),
            (true, false) => metrics.record_unexpected_success(),
            (false, true) => metrics.record_failure(),
            (false, false) => metrics.record_expected_failure(),
        }
        if succeeded {
            metrics.record_ingress_accepted();
        }
    }
    let endpoint_idx = submission_result
        .as_ref()
        .ok()
        .map(|(endpoint_idx, _)| *endpoint_idx);
    for (submission, hash) in batch.into_iter().zip(hashes) {
        workload.record_result(&submission.plan, succeeded).await;
        if succeeded
            && should_audit_throughput_confirmation(
                SubmissionConfirmationMode::AcceptedByIngress,
                submission.plan.expect_success,
            )
            && should_sample_throughput_confirmation(&hash, confirmation_audit_seed)
            && let (Some(endpoint_idx), Some(confirmation_audit_tx)) =
                (endpoint_idx, confirmation_audit_tx.as_ref())
        {
            try_schedule_submission_audit(
                confirmation_audit_tx,
                metrics.as_ref(),
                SubmissionAuditCandidate {
                    endpoint_idx,
                    signer: submission.plan.signer,
                    hash,
                    plan_label: submission.plan.label,
                },
                run_control,
                confirmation_audit_wait_options,
            );
        }
    }
}
async fn submit_plan(
    ingress_pool: &Arc<IngressEndpointPool>,
    plan: TransactionPlan,
    submission_confirmation: SubmissionConfirmationMode,
    semaphore: Arc<Semaphore>,
    metrics: &Arc<Metrics>,
    submission_counter: &Arc<AtomicU64>,
    workload: &Arc<WorkloadEngine>,
    submitter_idx: usize,
    confirmation_audit_tx: Option<mpsc::Sender<SubmissionAuditCandidate>>,
    confirmation_audit_seed: u64,
    run_control: &RunControl,
    confirmation_audit_wait_options: &TransactionWaitOptions,
) {
    let ingress_pool = Arc::clone(ingress_pool);
    let signer = plan.signer.clone();
    let instructions = plan.instructions.clone();
    let plan_label = plan.label;
    let expect_success = plan.expect_success;
    let metrics = Arc::clone(metrics);
    let submission_counter = Arc::clone(submission_counter);
    let workload = Arc::clone(workload);
    let burn_target = plan.burn_trigger_repetitions();
    let mint_target = plan.mint_trigger_repetitions();
    let register_target = tracked_repeatable_trigger(&plan.state_updates);
    let repeatable_trigger_target = burn_target
        .as_ref()
        .map(|(trigger_id, _)| trigger_id.clone())
        .or_else(|| {
            mint_target
                .as_ref()
                .map(|(trigger_id, _)| trigger_id.clone())
        })
        .or(register_target);
    let effective_submission_confirmation =
        effective_submission_confirmation(submission_confirmation, &plan.state_updates);
    let run_trigger_precheck = should_run_trigger_precheck(effective_submission_confirmation);
    let mut pinned_trigger_endpoint = if repeatable_trigger_target.is_some() {
        match ingress_pool
            .select_endpoint_preferred("submit_repeatable_trigger_plan", submitter_idx)
        {
            Ok(endpoint_idx) => Some(endpoint_idx),
            Err(err) => {
                warn!(
                    target: "izanami::workload",
                    ?err,
                    plan = plan_label,
                    submitter_idx,
                    "failed to select pinned ingress endpoint for repeatable trigger plan"
                );
                if expect_success {
                    metrics.record_failure();
                } else {
                    metrics.record_expected_failure();
                }
                if let Some(trigger_id) = repeatable_trigger_target {
                    workload.mark_trigger_unknown(&trigger_id).await;
                }
                workload.record_result(&plan, false).await;
                return;
            }
        }
    } else {
        None
    };
    if run_trigger_precheck && let Some((trigger_id, burn_amount)) = burn_target.clone() {
        let endpoint_idx =
            pinned_trigger_endpoint.expect("repeatable trigger plan should pin ingress");
        let query_result = query_trigger_repetitions_on_endpoint(
            &ingress_pool,
            endpoint_idx,
            &signer,
            trigger_id.clone(),
        )
        .await;
        let precheck = match query_result {
            Ok((resolved_endpoint_idx, on_chain)) => {
                pinned_trigger_endpoint = Some(resolved_endpoint_idx);
                evaluate_burn_precheck(Ok::<Option<u32>, color_eyre::Report>(on_chain), burn_amount)
            }
            Err(err) => {
                evaluate_burn_precheck(Err::<Option<u32>, color_eyre::Report>(err), burn_amount)
            }
        };
        match precheck {
            BurnPrecheck::Proceed { on_chain } => {
                workload
                    .sync_trigger_repetitions(&trigger_id, Some(on_chain))
                    .await;
            }
            BurnPrecheck::SkipMissing => {
                workload.sync_trigger_repetitions(&trigger_id, None).await;
                record_plan_skip(
                    &metrics,
                    plan_label,
                    expect_success,
                    "on-chain trigger repetition drift",
                );
                workload.record_result(&plan, false).await;
                return;
            }
            BurnPrecheck::SkipInsufficient { on_chain } => {
                workload
                    .sync_trigger_repetitions(&trigger_id, Some(on_chain))
                    .await;
                record_plan_skip(
                    &metrics,
                    plan_label,
                    expect_success,
                    "on-chain trigger repetition drift",
                );
                workload.record_result(&plan, false).await;
                return;
            }
            BurnPrecheck::SkipQueryFailed => {
                reconcile_repeatable_trigger_with_endpoint(
                    &workload,
                    &ingress_pool,
                    endpoint_idx,
                    &signer,
                    &trigger_id,
                )
                .await;
                record_plan_skip(
                    &metrics,
                    plan_label,
                    expect_success,
                    "trigger repetition query failed",
                );
                workload.record_result(&plan, false).await;
                return;
            }
        }
    }
    if run_trigger_precheck && let Some((trigger_id, _mint_amount)) = mint_target.clone() {
        let endpoint_idx =
            pinned_trigger_endpoint.expect("repeatable trigger plan should pin ingress");
        let query_result = query_trigger_repetitions_on_endpoint(
            &ingress_pool,
            endpoint_idx,
            &signer,
            trigger_id.clone(),
        )
        .await;
        let precheck = match query_result {
            Ok((resolved_endpoint_idx, on_chain)) => {
                pinned_trigger_endpoint = Some(resolved_endpoint_idx);
                evaluate_mint_precheck(Ok::<Option<u32>, color_eyre::Report>(on_chain))
            }
            Err(err) => evaluate_mint_precheck(Err::<Option<u32>, color_eyre::Report>(err)),
        };
        match precheck {
            MintPrecheck::Proceed { on_chain } => {
                workload
                    .sync_trigger_repetitions(&trigger_id, Some(on_chain))
                    .await;
            }
            MintPrecheck::SkipMissing => {
                workload.sync_trigger_repetitions(&trigger_id, None).await;
                record_plan_skip(
                    &metrics,
                    plan_label,
                    expect_success,
                    "on-chain trigger repetition drift",
                );
                workload.record_result(&plan, false).await;
                return;
            }
            MintPrecheck::SkipQueryFailed => {
                reconcile_repeatable_trigger_with_endpoint(
                    &workload,
                    &ingress_pool,
                    endpoint_idx,
                    &signer,
                    &trigger_id,
                )
                .await;
                record_plan_skip(
                    &metrics,
                    plan_label,
                    expect_success,
                    "trigger repetition query failed",
                );
                workload.record_result(&plan, false).await;
                return;
            }
        }
    }
    let permit = match semaphore.acquire_owned().await {
        Ok(permit) => permit,
        Err(_) => {
            warn!(
                target: "izanami::workload",
                plan = plan_label,
                submitter_idx,
                "submission permit channel closed before submit"
            );
            if expect_success {
                metrics.record_failure();
            } else {
                metrics.record_expected_failure();
            }
            workload.record_result(&plan, false).await;
            return;
        }
    };
    metrics.record_inflight_acquired();
    let _inflight_guard = InflightGuard::new(Arc::clone(&metrics), permit);
    let submission_result: Result<SubmissionOutcome> = if let Some(endpoint_idx) =
        pinned_trigger_endpoint
    {
        let ingress_pool_for_submit = Arc::clone(&ingress_pool);
        let signer_for_submit = signer.clone();
        let instructions_for_submit = instructions.clone();
        let submission_counter_for_submit = Arc::clone(&submission_counter);
        run_submission_result(
            plan_label,
            expect_success,
            Arc::clone(&metrics),
            effective_submission_confirmation,
            move || {
                submit_repeatable_trigger_plan_on_endpoint(
                    &ingress_pool_for_submit,
                    endpoint_idx,
                    &signer_for_submit,
                    &instructions_for_submit,
                    effective_submission_confirmation,
                    submission_counter_for_submit.as_ref(),
                )
            },
        )
        .await
    } else if matches!(
        effective_submission_confirmation,
        SubmissionConfirmationMode::AcceptedByIngress
    ) {
        let ingress_pool_for_submit = Arc::clone(&ingress_pool);
        let ingress_pool_for_retry_delay = Arc::clone(&ingress_pool);
        let signer_for_submit = signer.clone();
        let instructions_for_submit = instructions.clone();
        let submission_counter_for_submit = Arc::clone(&submission_counter);
        run_submission_future_result(
            plan_label,
            expect_success,
            Arc::clone(&metrics),
            effective_submission_confirmation,
            async move {
                run_with_queue_timeout_retry_with_policy_and_delay_result_async(
                    plan_label,
                    IZANAMI_QUEUE_TIMEOUT_RETRY_ATTEMPTS,
                    Duration::from_millis(IZANAMI_QUEUE_TIMEOUT_RETRY_BACKOFF_MS),
                    move || {
                        ingress_pool_for_retry_delay.submission_backpressure_delay(Instant::now())
                    },
                    move || {
                        let ingress_pool_for_submit = Arc::clone(&ingress_pool_for_submit);
                        let signer_for_submit = signer_for_submit.clone();
                        let instructions_for_submit = instructions_for_submit.clone();
                        let submission_counter_for_submit =
                            Arc::clone(&submission_counter_for_submit);
                        async move {
                            let ingress_pool_for_operation = Arc::clone(&ingress_pool_for_submit);
                            ingress_pool_for_submit
                                .run_with_failover_preferred_with_endpoint_async(
                                    "submit_transaction_plan",
                                    submitter_idx,
                                    move |endpoint_idx, _peer| {
                                        let ingress_pool_for_submit =
                                            Arc::clone(&ingress_pool_for_operation);
                                        let signer_for_submit = signer_for_submit.clone();
                                        let instructions_for_submit =
                                            instructions_for_submit.clone();
                                        let submission_counter_for_submit =
                                            Arc::clone(&submission_counter_for_submit);
                                        async move {
                                            let client = ingress_pool_for_submit
                                                .cached_submit_client_for(
                                                    endpoint_idx,
                                                    &signer_for_submit,
                                                    SubmissionConfirmationMode::AcceptedByIngress,
                                                )?;
                                            let metadata = submission_metadata(
                                                submission_counter_for_submit.as_ref(),
                                            );
                                            let transaction ={
    let account = client
                                                .account_client();
    account
        .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                                                instructions_for_submit,
                                                iroha_data_model::transaction::FeePaymentIntent::authority(
                                                    Vec::new(),
                                                    None,
                                                ),
                                                metadata,
                                            ))
        .and_then(|payload| account.sign_transaction(payload))
}?;
                                            let hash = transaction.hash();
                                            client
                                                .account_client()
                                                .submit_transaction(&transaction)
                                                .await
                                                .map(|_| hash)
                                        }
                                    },
                                )
                                .await
                                .map(|(endpoint_idx, hash)| SubmissionOutcome {
                                    endpoint_idx,
                                    hash,
                                })
                        }
                    },
                )
                .await
            },
        )
        .await
    } else {
        let ingress_pool_for_submit = Arc::clone(&ingress_pool);
        let signer_for_submit = signer.clone();
        let instructions_for_submit = instructions.clone();
        let submission_counter_for_submit = Arc::clone(&submission_counter);
        run_submission_result(
            plan_label,
            expect_success,
            Arc::clone(&metrics),
            effective_submission_confirmation,
            move || {
                let ingress_pool_for_retry_delay = Arc::clone(&ingress_pool_for_submit);
                let submitted = run_with_queue_timeout_retry_with_policy_and_delay_result(
                    plan_label,
                    IZANAMI_QUEUE_TIMEOUT_RETRY_ATTEMPTS,
                    Duration::from_millis(IZANAMI_QUEUE_TIMEOUT_RETRY_BACKOFF_MS),
                    move || {
                        ingress_pool_for_retry_delay.submission_backpressure_delay(Instant::now())
                    },
                    || {
                        ingress_pool_for_submit
                            .run_with_failover_preferred_with_endpoint(
                                "submit_transaction_plan",
                                submitter_idx,
                                |peer| {
                                    let client = tune_ingress_client(
                                        peer.client_for(
                                            &signer_for_submit.id,
                                            signer_for_submit.key_pair.private_key().clone(),
                                        ),
                                        SubmissionConfirmationMode::AcceptedByIngress,
                                        ingress_pool_for_submit.submit_request_timeout,
                                    )?;
                                    let metadata =
                                        submission_metadata(submission_counter_for_submit.as_ref());
                                    let transaction = {
                                        let account = client.account_client();
                                        account
        .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                                        instructions_for_submit.clone(),
                                        iroha_data_model::transaction::FeePaymentIntent::authority(
                                            Vec::new(),
                                            None,
                                        ),
                                        metadata,
                                    ))
        .and_then(|payload| account.sign_transaction(payload))
                                    }?;
                                    let hash = transaction.hash();
                                    client.submit_transaction(&transaction).map(|_| hash)
                                },
                            )
                            .map(|(endpoint_idx, hash)| SubmissionOutcome { endpoint_idx, hash })
                    },
                )?;
                if matches!(
                    effective_submission_confirmation,
                    SubmissionConfirmationMode::BlockingApplied
                ) {
                    let _ = wait_for_transaction_applied_with_failover(
                        &ingress_pool_for_submit,
                        "confirm_transaction_plan",
                        submitted.endpoint_idx,
                        &signer_for_submit,
                        submitted.hash.clone(),
                        applied_confirmation_wait_options(),
                    )?;
                }
                Ok(submitted)
            },
        )
        .await
    };
    match submission_result {
        Ok(submission_outcome) => {
            pinned_trigger_endpoint = Some(submission_outcome.endpoint_idx);
            workload.record_result(&plan, true).await;
            if should_audit_throughput_confirmation(
                effective_submission_confirmation,
                expect_success,
            ) && should_sample_throughput_confirmation(
                &submission_outcome.hash,
                confirmation_audit_seed,
            ) && let Some(confirmation_audit_tx) = confirmation_audit_tx.as_ref()
            {
                try_schedule_submission_audit(
                    confirmation_audit_tx,
                    metrics.as_ref(),
                    SubmissionAuditCandidate {
                        endpoint_idx: submission_outcome.endpoint_idx,
                        signer: signer.clone(),
                        hash: submission_outcome.hash,
                        plan_label,
                    },
                    run_control,
                    confirmation_audit_wait_options,
                );
            }
            if let (Some(endpoint_idx), Some(trigger_id)) =
                (pinned_trigger_endpoint, repeatable_trigger_target.as_ref())
            {
                reconcile_repeatable_trigger_with_endpoint(
                    &workload,
                    &ingress_pool,
                    endpoint_idx,
                    &signer,
                    trigger_id,
                )
                .await;
            }
        }
        Err(err) => {
            workload.record_result(&plan, false).await;
            if let Some(trigger_id) = repeatable_trigger_target.as_ref() {
                if is_trigger_not_found_error(&err) {
                    workload.sync_trigger_repetitions(trigger_id, None).await;
                } else if let Some(endpoint_idx) = pinned_trigger_endpoint {
                    reconcile_repeatable_trigger_with_endpoint(
                        &workload,
                        &ingress_pool,
                        endpoint_idx,
                        &signer,
                        trigger_id,
                    )
                    .await;
                } else {
                    workload.mark_trigger_unknown(trigger_id).await;
                }
            }
        }
    }
}
async fn query_trigger_repetitions_on_endpoint(
    ingress_pool: &Arc<IngressEndpointPool>,
    endpoint_idx: usize,
    signer: &AccountRecord,
    trigger_id: TriggerId,
) -> Result<(usize, Option<u32>)> {
    let ingress_pool = Arc::clone(ingress_pool);
    let signer = signer.clone();
    match spawn_blocking(move || {
        match ingress_pool.run_on_endpoint("query_trigger_repetitions", endpoint_idx, |peer| {
            let client = tune_ingress_client(
                peer.client_for(&signer.id, signer.key_pair.private_key().clone()),
                SubmissionConfirmationMode::AcceptedByIngress,
                ingress_pool.submit_request_timeout,
            )?;
            query_trigger_repetitions(&client, &trigger_id)
        }) {
            Ok(result) => Ok((endpoint_idx, result)),
            Err(err) if is_route_unavailable_error(&err) => {
                warn!(
                    target: "izanami::workload",
                    ?err,
                    trigger = %trigger_id,
                    endpoint_idx,
                    "repinning repeatable trigger query after route_unavailable"
                );
                ingress_pool.run_with_failover_excluding(
                    "query_trigger_repetitions_route_failover",
                    endpoint_idx,
                    |peer| {
                        let client = tune_ingress_client(
                            peer.client_for(&signer.id, signer.key_pair.private_key().clone()),
                            SubmissionConfirmationMode::AcceptedByIngress,
                            ingress_pool.submit_request_timeout,
                        )?;
                        query_trigger_repetitions(&client, &trigger_id)
                    },
                )
            }
            Err(err) => Err(err),
        }
    })
    .await
    {
        Ok(result) => result,
        Err(err) => Err(err.into()),
    }
}
fn submit_repeatable_trigger_plan_on_endpoint(
    ingress_pool: &IngressEndpointPool,
    endpoint_idx: usize,
    signer: &AccountRecord,
    instructions: &[InstructionBox],
    submission_confirmation: SubmissionConfirmationMode,
    submission_counter: &AtomicU64,
) -> Result<SubmissionOutcome> {
    let submit_to_endpoint = |resolved_endpoint_idx: usize, peer: &NetworkPeer| {
        let client = tune_ingress_client(
            peer.client_for(&signer.id, signer.key_pair.private_key().clone()),
            SubmissionConfirmationMode::AcceptedByIngress,
            ingress_pool.submit_request_timeout,
        )?;
        let metadata = submission_metadata(submission_counter);
        client
            .submit_all_with_metadata(
                instructions.to_vec(),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                metadata,
            )
            .map(|hash| SubmissionOutcome {
                endpoint_idx: resolved_endpoint_idx,
                hash,
            })
    };
    let submission =
        match ingress_pool.run_on_endpoint("submit_repeatable_trigger_plan", endpoint_idx, |peer| {
            submit_to_endpoint(endpoint_idx, peer)
        }) {
            Ok(outcome) => outcome,
            Err(err) if is_route_unavailable_error(&err) => {
                warn!(
                    target: "izanami::workload",
                    ?err,
                    endpoint_idx,
                    "repinning repeatable trigger submit after route_unavailable"
                );
                let (resolved_endpoint_idx, hash) = ingress_pool.run_with_failover_excluding(
                    "submit_repeatable_trigger_plan_route_failover",
                    endpoint_idx,
                    |peer| submit_to_endpoint(endpoint_idx, peer).map(|outcome| outcome.hash),
                )?;
                SubmissionOutcome {
                    endpoint_idx: resolved_endpoint_idx,
                    hash,
                }
            }
            Err(err) => return Err(err),
        };
    if matches!(
        submission_confirmation,
        SubmissionConfirmationMode::BlockingApplied
    ) {
        let _ = wait_for_transaction_applied_with_failover(
            ingress_pool,
            "confirm_repeatable_trigger_plan",
            submission.endpoint_idx,
            signer,
            submission.hash.clone(),
            applied_confirmation_wait_options(),
        )?;
    }
    Ok(submission)
}
async fn reconcile_repeatable_trigger_with_endpoint(
    workload: &Arc<WorkloadEngine>,
    ingress_pool: &Arc<IngressEndpointPool>,
    endpoint_idx: usize,
    signer: &AccountRecord,
    trigger_id: &TriggerId,
) {
    match query_trigger_repetitions_on_endpoint(
        ingress_pool,
        endpoint_idx,
        signer,
        trigger_id.clone(),
    )
    .await
    {
        Ok((_resolved_endpoint_idx, Some(on_chain))) if on_chain > 0 => {
            workload
                .sync_trigger_repetitions(trigger_id, Some(on_chain))
                .await;
        }
        Ok((_resolved_endpoint_idx, Some(_))) | Ok((_resolved_endpoint_idx, None)) => {
            workload.sync_trigger_repetitions(trigger_id, None).await;
        }
        Err(err) => {
            warn!(
                target: "izanami::workload",
                ?err,
                trigger = %trigger_id,
                endpoint_idx,
                "failed to reconcile repeatable trigger state from pinned ingress endpoint"
            );
            workload.mark_trigger_unknown(trigger_id).await;
        }
    }
}
fn applied_confirmation_wait_options() -> TransactionWaitOptions {
    TransactionWaitOptions {
        timeout: Duration::from_millis(IZANAMI_INGRESS_STATUS_TIMEOUT_MS),
        poll_interval: Duration::from_millis(IZANAMI_THROUGHPUT_CONFIRMATION_POLL_INTERVAL_MS),
    }
}
fn confirmation_wait_options_with_timeout(timeout: Duration) -> TransactionWaitOptions {
    TransactionWaitOptions {
        timeout,
        poll_interval: Duration::from_millis(IZANAMI_THROUGHPUT_CONFIRMATION_POLL_INTERVAL_MS),
    }
}
fn throughput_confirmation_wait_options() -> TransactionWaitOptions {
    confirmation_wait_options_with_timeout(Duration::from_millis(
        IZANAMI_THROUGHPUT_CONFIRMATION_TIMEOUT_MS,
    ))
}
fn npos_extended_confirmation_window_needed(config: &ChaosConfig) -> bool {
    config.nexus.is_some()
}
fn throughput_confirmation_wait_options_for(config: &ChaosConfig) -> TransactionWaitOptions {
    if npos_extended_confirmation_window_needed(config) {
        confirmation_wait_options_with_timeout(Duration::from_millis(
            IZANAMI_NPOS_RECOVERY_CONFIRMATION_TIMEOUT_MS,
        ))
    } else {
        throughput_confirmation_wait_options()
    }
}
fn confirmation_audit_has_deadline_budget(
    now: Instant,
    deadline: Instant,
    options: &TransactionWaitOptions,
) -> bool {
    deadline
        .checked_duration_since(now)
        .is_some_and(|remaining| remaining > options.timeout.saturating_add(options.poll_interval))
}
fn submission_deadline_budget(mode: SubmissionConfirmationMode) -> Duration {
    let request_budget = Duration::from_millis(IZANAMI_INGRESS_REQUEST_TIMEOUT_MS)
        .saturating_mul(IZANAMI_INGRESS_MAX_ATTEMPTS as u32)
        .saturating_add(
            Duration::from_millis(IZANAMI_QUEUE_TIMEOUT_RETRY_BACKOFF_MS)
                .saturating_mul(IZANAMI_QUEUE_TIMEOUT_RETRY_ATTEMPTS),
        )
        .saturating_add(Duration::from_millis(
            IZANAMI_THROUGHPUT_CONFIRMATION_POLL_INTERVAL_MS,
        ));
    if matches!(mode, SubmissionConfirmationMode::BlockingApplied) {
        let wait_options = applied_confirmation_wait_options();
        request_budget
            .saturating_add(wait_options.timeout)
            .saturating_add(wait_options.poll_interval)
    } else {
        request_budget
    }
}
fn submission_has_deadline_budget(
    now: Instant,
    deadline: Instant,
    mode: SubmissionConfirmationMode,
) -> bool {
    deadline
        .checked_duration_since(now)
        .is_some_and(|remaining| remaining > submission_deadline_budget(mode))
}
fn elapsed_ms_u64(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}
fn exact_transaction_wait_poll_interval(poll_interval: Duration) -> Result<Duration> {
    if poll_interval == Duration::ZERO {
        return Err(eyre!(
            "transaction wait poll_interval must be greater than zero"
        ));
    }
    Ok(poll_interval)
}
fn is_state_resolved_terminal_failure(kind: &str, scope: &str, resolved_from: &str) -> bool {
    scope == "global" && resolved_from == "state" && matches!(kind, "Rejected" | "Expired")
}
fn wait_for_transaction_applied_with_failover(
    ingress_pool: &IngressEndpointPool,
    op_name: &'static str,
    preferred_endpoint_idx: usize,
    signer: &AccountRecord,
    hash: HashOf<SignedTransaction>,
    options: TransactionWaitOptions,
) -> Result<(usize, TransactionWaitOutcome)> {
    let TransactionWaitOptions {
        timeout,
        poll_interval,
    } = options;
    let poll_interval = exact_transaction_wait_poll_interval(poll_interval)?;
    let expected_hash = hash.to_string();
    let start = Instant::now();
    let mut preferred_endpoint_idx = Some(preferred_endpoint_idx);
    let mut attempts = 0_u64;
    let mut last_error = None;
    let mut last_observed_statuses: Vec<String> = Vec::new();
    loop {
        attempts = attempts.saturating_add(1);
        let mut observed_statuses = Vec::new();
        let endpoints = Arc::clone(&ingress_pool.endpoints);
        match ingress_pool
            .health
            .run_with_failover_until_some_at_with_preference_and_limit(
                op_name,
                preferred_endpoint_idx.take(),
                Instant::now(),
                ingress_pool.endpoints.len(),
                |endpoint_idx, _label| {
                    let endpoint = endpoints
                        .get(endpoint_idx)
                        .ok_or_else(|| eyre!("endpoint index {endpoint_idx} out of range"))?;
                    let peer = &endpoint.peer;
                    let client = tune_ingress_client(
                        peer.client_for(&signer.id, signer.key_pair.private_key().clone()),
                        SubmissionConfirmationMode::AcceptedByIngress,
                        ingress_pool.submit_request_timeout,
                    )?;
                    let Some(response) = client
                        .client()
                        .get_transaction_status_response_global(hash.clone())?
                    else {
                        return Ok(None);
                    };
                    let kind = response.status.kind.as_str();
                    if response.hash != expected_hash || response.scope != "global" {
                        return Err(eyre!(
                            "global pipeline status response is not bound to transaction {expected_hash}"
                        ));
                    }
                    match kind {
                        "Applied" if response.resolved_from == "state" => {
                            return Ok(Some(response));
                        }
                        "Rejected" | "Expired"
                            if is_state_resolved_terminal_failure(
                                kind,
                                &response.scope,
                                &response.resolved_from,
                            ) =>
                        {
                            return Ok(Some(response));
                        }
                        "Queued" | "Approved" | "Committed" | "Applied" | "Rejected"
                        | "Expired" => {}
                        _ => {
                            return Err(eyre!("unsupported pipeline status kind `{kind}`"));
                        }
                    }
                    observed_statuses.push(format!(
                        "endpoint={endpoint_idx},kind={},from={}",
                        response.status.kind, response.resolved_from
                    ));
                    Ok(None)
                },
            ) {
            Ok(Some((endpoint_idx, response))) => {
                let kind = response.status.kind.as_str();
                if is_state_resolved_terminal_failure(
                    kind,
                    &response.scope,
                    &response.resolved_from,
                ) {
                    return Err(eyre!(
                        "transaction {} reached fixed terminal failure status `{kind}` (resolved_from={})",
                        response.hash,
                        response.resolved_from
                    ));
                }
                if kind != "Applied" || response.resolved_from != "state" {
                    return Err(eyre!(
                        "transaction {} returned non-final global status `{kind}` from {}",
                        response.hash,
                        response.resolved_from
                    ));
                }
                return Ok((
                    endpoint_idx,
                    TransactionWaitOutcome {
                        hash: response.hash.clone(),
                        terminal_kind: kind.to_owned(),
                        attempts,
                        elapsed_ms: elapsed_ms_u64(start.elapsed()),
                        block_height: response.status.block_height,
                        scope: response.scope.clone(),
                        resolved_from: response.resolved_from.clone(),
                        r#final: response,
                    },
                ));
            }
            Ok(None) => {
                if !observed_statuses.is_empty() {
                    if last_observed_statuses.len() != observed_statuses.len()
                        || last_observed_statuses != observed_statuses
                    {
                        debug!(
                            target: "izanami::audit",
                            op = op_name,
                            hash = %hash,
                            ?observed_statuses,
                            "transaction status poll observed only non-terminal statuses"
                        );
                    }
                    last_observed_statuses = observed_statuses;
                }
            }
            Err(err) => last_error = Some(err),
        }
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            let observed = if last_observed_statuses.is_empty() {
                String::new()
            } else {
                format!(
                    "; last observed statuses: {}",
                    last_observed_statuses.join("; ")
                )
            };
            let timeout_error = eyre!(
                "transaction did not reach state-resolved Applied within {} ms{observed}",
                timeout.as_millis()
            );
            return if let Some(err) = last_error {
                Err(err.wrap_err(timeout_error))
            } else {
                Err(timeout_error)
            };
        }
        std::thread::sleep(poll_interval.min(timeout.saturating_sub(elapsed)));
    }
}
async fn audit_submitted_transaction(
    ingress_pool: &Arc<IngressEndpointPool>,
    run_control: &Arc<RunControl>,
    metrics: &Arc<Metrics>,
    candidate: SubmissionAuditCandidate,
    wait_options: TransactionWaitOptions,
) {
    let SubmissionAuditCandidate {
        endpoint_idx,
        signer,
        hash,
        plan_label,
    } = candidate;
    let log_hash = hash.clone();
    let ingress_pool = Arc::clone(ingress_pool);
    let run_control = Arc::clone(run_control);
    let metrics = Arc::clone(metrics);
    let result = spawn_blocking(move || {
        wait_for_transaction_applied_with_failover(
            &ingress_pool,
            "audit_confirmation",
            endpoint_idx,
            &signer,
            hash,
            wait_options,
        )
    })
    .await;
    match result {
        Ok(Ok((_resolved_endpoint_idx, outcome))) => {
            if outcome.terminal_kind == "Applied"
                && outcome.scope == "global"
                && outcome.resolved_from == "state"
            {
                metrics.record_confirmation_audit_applied();
            } else {
                metrics.record_confirmation_audit_failed();
                warn!(
                    target: "izanami::audit",
                    endpoint_idx,
                    hash = %log_hash,
                    plan = plan_label,
                    terminal_kind = outcome.terminal_kind,
                    scope = outcome.scope,
                    resolved_from = outcome.resolved_from,
                    "sampled confirmation violated fixed global Applied finality"
                );
            }
        }
        Ok(Err(err)) => {
            if is_shutdown_noise_status_read_failure("audit_confirmation", &err, &run_control) {
                metrics.record_confirmation_audit_shutdown_noise();
                debug!(
                    target: "izanami::audit",
                    endpoint_idx,
                    hash = %log_hash,
                    plan = plan_label,
                    ?err,
                    "ignoring sampled confirmation failure during shutdown"
                );
            } else if is_audit_confirmation_window_elapsed(&err) {
                metrics.record_confirmation_audit_budget_skipped();
                debug!(
                    target: "izanami::audit",
                    endpoint_idx,
                    hash = %log_hash,
                    plan = plan_label,
                    "sampled confirmation audit window elapsed before terminal status"
                );
            } else {
                metrics.record_confirmation_audit_failed();
                warn!(
                    target: "izanami::audit",
                    endpoint_idx,
                    hash = %log_hash,
                    plan = plan_label,
                    ?err,
                    "sampled confirmation failed"
                );
            }
        }
        Err(err) => {
            metrics.record_confirmation_audit_failed();
            warn!(
                target: "izanami::audit",
                endpoint_idx,
                hash = %log_hash,
                plan = plan_label,
                ?err,
                "sampled confirmation worker panicked"
            );
        }
    }
}
async fn run_submission_result<T, F>(
    plan_label: &'static str,
    expect_success: bool,
    metrics: Arc<Metrics>,
    confirmation_mode: SubmissionConfirmationMode,
    blocking: F,
) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    let started_at = Instant::now();
    let result = match spawn_blocking(blocking).await {
        Ok(result) => result,
        Err(err) => Err(err.into()),
    };
    metrics.record_submit_latency(started_at.elapsed());
    record_submission_result_metrics(
        plan_label,
        expect_success,
        &metrics,
        confirmation_mode,
        &result,
    );
    result
}
async fn run_submission_future_result<T, Fut>(
    plan_label: &'static str,
    expect_success: bool,
    metrics: Arc<Metrics>,
    confirmation_mode: SubmissionConfirmationMode,
    future: Fut,
) -> Result<T>
where
    Fut: Future<Output = Result<T>>,
{
    let started_at = Instant::now();
    let result = future.await;
    metrics.record_submit_latency(started_at.elapsed());
    record_submission_result_metrics(
        plan_label,
        expect_success,
        &metrics,
        confirmation_mode,
        &result,
    );
    result
}
fn record_submission_result_metrics<T>(
    plan_label: &'static str,
    expect_success: bool,
    metrics: &Metrics,
    confirmation_mode: SubmissionConfirmationMode,
    result: &Result<T>,
) {
    let succeeded = result.is_ok();
    debug!(
        target: "izanami::workload",
        plan = plan_label,
        expect_success,
        succeeded,
        "submitted chaos transaction plan"
    );
    match (&result, expect_success) {
        (Ok(_), true) => metrics.record_success(),
        (Ok(_), false) => metrics.record_unexpected_success(),
        (Err(_), true) => metrics.record_failure(),
        (Err(_), false) => metrics.record_expected_failure(),
    }
    if result.is_ok() {
        metrics.record_ingress_accepted();
        if matches!(
            confirmation_mode,
            SubmissionConfirmationMode::BlockingApplied
        ) {
            metrics.record_blocking_applied_success();
        }
    }
    if let Err(err) = &result {
        warn!(
            target: "izanami::workload",
            ?err,
            plan = plan_label,
            "plan submission failed"
        );
    }
}
#[cfg(test)]
async fn run_submission<F>(
    plan_label: &'static str,
    expect_success: bool,
    metrics: Arc<Metrics>,
    blocking: F,
) -> bool
where
    F: FnOnce() -> Result<()> + Send + 'static,
{
    run_submission_result(
        plan_label,
        expect_success,
        metrics,
        SubmissionConfirmationMode::AcceptedByIngress,
        blocking,
    )
    .await
    .is_ok()
}
#[derive(Default)]
struct Metrics {
    offered: AtomicU64,
    submit_plans_started: AtomicU64,
    submit_plans_shutdown_skipped: AtomicU64,
    submit_tasks_shutdown_aborted: AtomicU64,
    submit_latency_ms: StdMutex<Vec<u64>>,
    prebuilt_tx_buffer_capacity: AtomicU64,
    prebuilt_tx_workers: AtomicU64,
    prebuilt_tx_built: AtomicU64,
    prebuilt_tx_used: AtomicU64,
    prebuilt_tx_fallback: AtomicU64,
    prebuilt_tx_skipped: AtomicU64,
    prebuilt_tx_build_failures: AtomicU64,
    ingress_accepted: AtomicU64,
    blocking_applied_success: AtomicU64,
    confirmation_sampled: AtomicU64,
    confirmation_applied: AtomicU64,
    confirmation_failed: AtomicU64,
    confirmation_budget_skipped: AtomicU64,
    confirmation_queue_dropped: AtomicU64,
    confirmation_shutdown_noise: AtomicU64,
    successes: AtomicU64,
    failures: AtomicU64,
    expected_failures: AtomicU64,
    unexpected_successes: AtomicU64,
    inflight_current: AtomicU64,
    inflight_peak: AtomicU64,
    backlog_depth: AtomicU64,
    backlog_peak: AtomicU64,
    submitters: AtomicU64,
}
impl Metrics {
    fn set_submitters(&self, count: usize) {
        self.submitters.store(count as u64, Ordering::Relaxed);
    }
    fn record_submit_plan_started(&self) {
        self.submit_plans_started.fetch_add(1, Ordering::Relaxed);
        self.offered.fetch_add(1, Ordering::Relaxed);
    }
    fn record_submit_plan_shutdown_skipped(&self) {
        self.submit_plans_shutdown_skipped
            .fetch_add(1, Ordering::Relaxed);
    }
    fn record_submit_tasks_shutdown_aborted(&self, count: u64) {
        self.submit_tasks_shutdown_aborted
            .fetch_add(count, Ordering::Relaxed);
    }
    fn record_submit_latency(&self, latency: Duration) {
        let latency_ms = u64::try_from(latency.as_millis()).unwrap_or(u64::MAX);
        if let Ok(mut samples) = self.submit_latency_ms.lock() {
            samples.push(latency_ms);
        }
    }
    fn configure_prebuilt_tx_buffer(&self, capacity: usize, workers: usize) {
        self.prebuilt_tx_buffer_capacity
            .store(capacity as u64, Ordering::Relaxed);
        self.prebuilt_tx_workers
            .store(workers as u64, Ordering::Relaxed);
    }
    fn record_prebuilt_tx_built(&self) {
        self.prebuilt_tx_built.fetch_add(1, Ordering::Relaxed);
    }
    fn record_prebuilt_tx_used(&self) {
        self.prebuilt_tx_used.fetch_add(1, Ordering::Relaxed);
    }
    fn record_prebuilt_tx_fallback(&self) {
        self.prebuilt_tx_fallback.fetch_add(1, Ordering::Relaxed);
    }
    fn record_prebuilt_tx_skipped(&self) {
        self.prebuilt_tx_skipped.fetch_add(1, Ordering::Relaxed);
    }
    fn record_prebuilt_tx_build_failure(&self) {
        self.prebuilt_tx_build_failures
            .fetch_add(1, Ordering::Relaxed);
    }
    fn record_ingress_accepted(&self) {
        self.ingress_accepted.fetch_add(1, Ordering::Relaxed);
    }
    fn record_blocking_applied_success(&self) {
        self.blocking_applied_success
            .fetch_add(1, Ordering::Relaxed);
    }
    fn record_confirmation_audit_sampled(&self) {
        self.confirmation_sampled.fetch_add(1, Ordering::Relaxed);
    }
    fn record_confirmation_audit_applied(&self) {
        self.confirmation_applied.fetch_add(1, Ordering::Relaxed);
    }
    fn record_confirmation_audit_failed(&self) {
        self.confirmation_failed.fetch_add(1, Ordering::Relaxed);
    }
    fn record_confirmation_audit_budget_skipped(&self) {
        self.confirmation_budget_skipped
            .fetch_add(1, Ordering::Relaxed);
    }
    fn record_confirmation_audit_queue_dropped(&self) {
        self.confirmation_queue_dropped
            .fetch_add(1, Ordering::Relaxed);
    }
    fn record_confirmation_audit_shutdown_noise(&self) {
        self.confirmation_shutdown_noise
            .fetch_add(1, Ordering::Relaxed);
    }
    fn record_success(&self) {
        self.successes.fetch_add(1, Ordering::Relaxed);
    }
    fn record_failure(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
    }
    fn record_expected_failure(&self) {
        self.expected_failures.fetch_add(1, Ordering::Relaxed);
    }
    fn record_unexpected_success(&self) {
        self.unexpected_successes.fetch_add(1, Ordering::Relaxed);
    }
    fn record_inflight_acquired(&self) {
        let current = self.inflight_current.fetch_add(1, Ordering::Relaxed) + 1;
        update_peak(&self.inflight_peak, current);
    }
    fn record_inflight_acquired_many(&self, count: u64) {
        if count == 0 {
            return;
        }
        let current = self.inflight_current.fetch_add(count, Ordering::Relaxed) + count;
        update_peak(&self.inflight_peak, current);
    }
    fn record_inflight_released(&self) {
        self.inflight_current.fetch_sub(1, Ordering::Relaxed);
    }
    fn record_inflight_released_many(&self, count: u64) {
        if count > 0 {
            self.inflight_current.fetch_sub(count, Ordering::Relaxed);
        }
    }
    fn record_backlog_spawn(&self) {
        let current = self.backlog_depth.fetch_add(1, Ordering::Relaxed) + 1;
        update_peak(&self.backlog_peak, current);
    }
    fn record_backlog_complete(&self) {
        self.backlog_depth.fetch_sub(1, Ordering::Relaxed);
    }
    fn snapshot(&self) -> MetricsSnapshot {
        let submit_latency = self
            .submit_latency_ms
            .lock()
            .ok()
            .map(|samples| LatencySummary::from_samples(&samples))
            .unwrap_or_default();
        MetricsSnapshot {
            offered: self.offered.load(Ordering::Relaxed),
            submit_plans_started: self.submit_plans_started.load(Ordering::Relaxed),
            submit_plans_shutdown_skipped: self
                .submit_plans_shutdown_skipped
                .load(Ordering::Relaxed),
            submit_tasks_shutdown_aborted: self
                .submit_tasks_shutdown_aborted
                .load(Ordering::Relaxed),
            submit_latency_samples: submit_latency.samples,
            submit_latency_p50_ms: submit_latency.p50_ms,
            submit_latency_p95_ms: submit_latency.p95_ms,
            submit_latency_p99_ms: submit_latency.p99_ms,
            submit_latency_max_ms: submit_latency.max_ms,
            prebuilt_tx_buffer_capacity: self.prebuilt_tx_buffer_capacity.load(Ordering::Relaxed),
            prebuilt_tx_workers: self.prebuilt_tx_workers.load(Ordering::Relaxed),
            prebuilt_tx_built: self.prebuilt_tx_built.load(Ordering::Relaxed),
            prebuilt_tx_used: self.prebuilt_tx_used.load(Ordering::Relaxed),
            prebuilt_tx_fallback: self.prebuilt_tx_fallback.load(Ordering::Relaxed),
            prebuilt_tx_skipped: self.prebuilt_tx_skipped.load(Ordering::Relaxed),
            prebuilt_tx_build_failures: self.prebuilt_tx_build_failures.load(Ordering::Relaxed),
            ingress_accepted: self.ingress_accepted.load(Ordering::Relaxed),
            blocking_applied_success: self.blocking_applied_success.load(Ordering::Relaxed),
            confirmation_sampled: self.confirmation_sampled.load(Ordering::Relaxed),
            confirmation_applied: self.confirmation_applied.load(Ordering::Relaxed),
            confirmation_failed: self.confirmation_failed.load(Ordering::Relaxed),
            confirmation_budget_skipped: self.confirmation_budget_skipped.load(Ordering::Relaxed),
            confirmation_queue_dropped: self.confirmation_queue_dropped.load(Ordering::Relaxed),
            confirmation_shutdown_noise: self.confirmation_shutdown_noise.load(Ordering::Relaxed),
            successes: self.successes.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
            expected_failures: self.expected_failures.load(Ordering::Relaxed),
            unexpected_successes: self.unexpected_successes.load(Ordering::Relaxed),
            inflight_current: self.inflight_current.load(Ordering::Relaxed),
            inflight_peak: self.inflight_peak.load(Ordering::Relaxed),
            backlog_depth: self.backlog_depth.load(Ordering::Relaxed),
            backlog_peak: self.backlog_peak.load(Ordering::Relaxed),
            submitters: self.submitters.load(Ordering::Relaxed),
        }
    }
}
fn update_peak(peak: &AtomicU64, candidate: u64) {
    let _ = peak.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        (candidate > current).then_some(candidate)
    });
}
struct BacklogGuard {
    metrics: Arc<Metrics>,
}
impl BacklogGuard {
    fn new(metrics: Arc<Metrics>) -> Self {
        Self { metrics }
    }
}
impl Drop for BacklogGuard {
    fn drop(&mut self) {
        self.metrics.record_backlog_complete();
    }
}
struct InflightGuard {
    metrics: Arc<Metrics>,
    _permit: OwnedSemaphorePermit,
}
impl InflightGuard {
    fn new(metrics: Arc<Metrics>, permit: OwnedSemaphorePermit) -> Self {
        Self {
            metrics,
            _permit: permit,
        }
    }
}
impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.metrics.record_inflight_released();
    }
}
struct InflightBatchGuard {
    metrics: Arc<Metrics>,
    count: u64,
    _permit: OwnedSemaphorePermit,
}
impl InflightBatchGuard {
    fn new(metrics: Arc<Metrics>, permit: OwnedSemaphorePermit, count: usize) -> Self {
        let count = u64::try_from(count).unwrap_or(u64::MAX);
        Self {
            metrics,
            count,
            _permit: permit,
        }
    }
}
impl Drop for InflightBatchGuard {
    fn drop(&mut self) {
        self.metrics.record_inflight_released_many(self.count);
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct LatencySummary {
    samples: u64,
    p50_ms: u64,
    p95_ms: u64,
    p99_ms: u64,
    max_ms: u64,
}
impl LatencySummary {
    fn from_samples(samples: &[u64]) -> Self {
        if samples.is_empty() {
            return Self::default();
        }
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        Self {
            samples: sorted.len() as u64,
            p50_ms: percentile_from_sorted(&sorted, 0.50),
            p95_ms: percentile_from_sorted(&sorted, 0.95),
            p99_ms: percentile_from_sorted(&sorted, 0.99),
            max_ms: *sorted.last().unwrap_or(&0),
        }
    }
}
fn percentile_from_sorted(sorted: &[u64], percentile: f64) -> u64 {
    debug_assert!(!sorted.is_empty());
    debug_assert!((0.0..=1.0).contains(&percentile));
    let len = sorted.len() as f64;
    let rank = (len * percentile).ceil().clamp(1.0, len) as usize;
    sorted[rank.saturating_sub(1)]
}
#[derive(Clone, Copy, Default)]
struct MetricsSnapshot {
    offered: u64,
    submit_plans_started: u64,
    submit_plans_shutdown_skipped: u64,
    submit_tasks_shutdown_aborted: u64,
    submit_latency_samples: u64,
    submit_latency_p50_ms: u64,
    submit_latency_p95_ms: u64,
    submit_latency_p99_ms: u64,
    submit_latency_max_ms: u64,
    prebuilt_tx_buffer_capacity: u64,
    prebuilt_tx_workers: u64,
    prebuilt_tx_built: u64,
    prebuilt_tx_used: u64,
    prebuilt_tx_fallback: u64,
    prebuilt_tx_skipped: u64,
    prebuilt_tx_build_failures: u64,
    ingress_accepted: u64,
    blocking_applied_success: u64,
    confirmation_sampled: u64,
    confirmation_applied: u64,
    confirmation_failed: u64,
    confirmation_budget_skipped: u64,
    confirmation_queue_dropped: u64,
    confirmation_shutdown_noise: u64,
    successes: u64,
    failures: u64,
    expected_failures: u64,
    unexpected_successes: u64,
    inflight_current: u64,
    inflight_peak: u64,
    backlog_depth: u64,
    backlog_peak: u64,
    submitters: u64,
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        DEFAULT_PROGRESS_INTERVAL, DEFAULT_PROGRESS_TIMEOUT, DEFAULT_SHUTDOWN_DRAIN_TIMEOUT,
        DEFAULT_SUMERAGI_BLOCK_MAX_TRANSACTIONS, FaultArgs, FaultToggles, IzanamiArgs,
        NexusProfile, WorkloadProfile,
    };
    use color_eyre::eyre::{WrapErr, eyre};
    use iroha_crypto::Hash;
    use iroha_data_model::isi::SetParameter;
    use iroha_test_network::init_instruction_registry;
    use std::{env, io};
    use tokio::time::timeout;
    fn allow_net_for_tests() -> bool {
        std::env::var("IZANAMI_ALLOW_NET")
            .or_else(|_| std::env::var("IROHA_ALLOW_NET"))
            .ok()
            .map(|val| {
                matches!(
                    val.to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on" | "y"
                )
            })
            .unwrap_or(false)
    }
    fn checked_izanami_ed25519_key_fixture() -> KeyPair {
        KeyPair::try_random_with_algorithm(iroha_crypto::Algorithm::Ed25519)
            .expect("generate checked Izanami Ed25519 key fixture")
    }
    fn test_chaos_config() -> ChaosConfig {
        ChaosConfig {
            allow_net: true,
            peer_count: 4,
            faulty_peers: 0,
            duration: Duration::from_secs(1),
            pipeline_time: None,
            target_blocks: None,
            progress_interval: DEFAULT_PROGRESS_INTERVAL,
            progress_timeout: DEFAULT_PROGRESS_TIMEOUT,
            shutdown_drain_timeout: DEFAULT_SHUTDOWN_DRAIN_TIMEOUT,
            latency_p95_threshold: None,
            fault_window_start: None,
            fault_window_end: None,
            seed: Some(7),
            tps: 1.0,
            max_inflight: 4,
            submitters: 1,
            prebuild_tx_buffer: 0,
            prebuild_tx_workers: 0,
            sumeragi_block_max_transactions: DEFAULT_SUMERAGI_BLOCK_MAX_TRANSACTIONS,

            workload_profile: WorkloadProfile::Stable,
            allow_contract_deploy_in_stable: false,
            fault_interval: Duration::from_secs(1)..=Duration::from_secs(1),
            log_filter: "warn".to_string(),
            faults: FaultToggles::from_enabled_flags([
                true, true, true, false, false, false, false,
            ]),
            nexus: None,
            diagnostic_dir: None,
        }
    }
    fn test_endpoint_pool(
        endpoints: &[&str],
        max_attempts: usize,
        unhealthy_failure_threshold: u32,
        unhealthy_cooldown: Duration,
        reprobe_interval: Duration,
    ) -> (EndpointHealthPool, Arc<IngressStats>) {
        let ingress_stats = Arc::new(IngressStats::default());
        let pool = EndpointHealthPool::new(
            endpoints
                .iter()
                .map(|endpoint| (*endpoint).to_owned())
                .collect(),
            IngressEndpointPoolConfig {
                max_attempts,
                unhealthy_failure_threshold,
                unhealthy_cooldown,
                reprobe_interval,
            },
            Arc::clone(&ingress_stats),
        );
        (pool, ingress_stats)
    }
    fn test_prepared_network_builder(config: &ChaosConfig) -> Result<NetworkBuilder> {
        let account_qty = config.peer_count.saturating_mul(3).max(6);
        let PreparedChaos { genesis, .. } = instructions::prepare_state(
            account_qty,
            Some(config.peer_count),
            config.nexus.as_ref(),
            config.workload_profile,
            config.allow_contract_deploy_in_stable,
        )?;
        make_network_builder(config, genesis)
    }
    async fn start_test_prepared_network(config: &ChaosConfig) -> Result<Option<Network>> {
        let builder = test_prepared_network_builder(config)?;
        match builder.start().await {
            Ok(network) => Ok(Some(network)),
            Err(err) => {
                let looks_like_permission_denied = err
                    .downcast_ref::<io::Error>()
                    .is_some_and(|io_err| io_err.kind() == io::ErrorKind::PermissionDenied)
                    || err.to_string().contains("Operation not permitted");
                if looks_like_permission_denied {
                    // CI sandboxes (or restricted environments) may block binding loopback ports.
                    // Treat this as a skipped test rather than a hard failure so other coverage runs.
                    return Ok(None);
                }
                Err(err)
            }
        }
    }
    fn build_test_prepared_network(config: &ChaosConfig) -> Result<Option<Network>> {
        let builder = test_prepared_network_builder(config)?;
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| builder.build())) {
            Ok(network) => Ok(Some(network)),
            Err(payload) => {
                let msg = payload
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| payload.downcast_ref::<&str>().map(ToString::to_string))
                    .unwrap_or_default();
                if msg.contains("Operation not permitted") || msg.contains("permission denied") {
                    return Ok(None);
                }
                std::panic::resume_unwind(payload);
            }
        }
    }
    #[test]
    fn izanami_fixture_uses_checked_ed25519_key_generation() {
        let key_pair = checked_izanami_ed25519_key_fixture();
        let algorithm = key_pair
            .public_key()
            .try_algorithm()
            .expect("Izanami fixture key advertises a valid algorithm");
        assert_eq!(algorithm, iroha_crypto::Algorithm::Ed25519);
    }
    fn synthetic_audit_candidate(byte: u8) -> SubmissionAuditCandidate {
        let key_pair = checked_izanami_ed25519_key_fixture();
        SubmissionAuditCandidate {
            endpoint_idx: 0,
            signer: AccountRecord {
                id: AccountId::new(key_pair.public_key().clone()),
                key_pair,
                uaid: None,
            },
            hash: HashOf::from_untyped_unchecked(Hash::prehashed([byte; Hash::LENGTH])),
            plan_label: "synthetic_audit",
        }
    }
    struct EnvGuard {
        key: &'static str,
        original: Option<String>,
    }
    impl EnvGuard {
        #[allow(unsafe_code)]
        fn set(key: &'static str, value: &str) -> Self {
            let original = env::var(key).ok();
            // Safety: test-only environment changes are scoped to the guard.
            unsafe {
                env::set_var(key, value);
            }
            Self { key, original }
        }
    }
    impl Drop for EnvGuard {
        #[allow(unsafe_code)]
        fn drop(&mut self) {
            if let Some(value) = &self.original {
                // Safety: test-only environment changes are scoped to the guard.
                unsafe {
                    env::set_var(self.key, value);
                }
            } else {
                // Safety: test-only environment changes are scoped to the guard.
                unsafe {
                    env::remove_var(self.key);
                }
            }
        }
    }
    fn synthetic_npos_preflight_assets() -> (AssetDefinitionId, AccountId) {
        let definition = AssetDefinitionId::derive_from_components(
            iroha_model_base::domain::DomainId::try_new("preflight", "universal")
                .expect("fixture domain"),
            "stake".parse().expect("fixture asset name"),
        );
        let custody = AccountId::new(
            KeyPair::try_from_seed(vec![0x51; 32], iroha_crypto::Algorithm::Ed25519)
                .expect("checked preflight custody key")
                .public_key()
                .clone(),
        );
        (definition, custody)
    }
    fn synthetic_npos_preflight_instructions(
        peer_count: usize,
        bootstrap_public_lanes: &[LaneId],
        include_pop: bool,
        include_activation: bool,
        stake_values: &[Quantity],
    ) -> Vec<InstructionBox> {
        let mut instructions = Vec::new();
        // These instructions are inspected structurally, not executed against a node.
        // Author custody explicitly so every negative isolates its stated preflight failure.
        let (stake_asset, custody) = synthetic_npos_preflight_assets();
        let fallback_stake = SumeragiNposParameters::default().min_self_bond().clone();
        for idx in 0..peer_count {
            let key_pair = checked_izanami_ed25519_key_fixture();
            let validator = AccountId::new(key_pair.public_key().clone());
            let stake = stake_values
                .get(idx)
                .cloned()
                .unwrap_or_else(|| fallback_stake.clone());
            if include_pop {
                instructions.push(InstructionBox::from(RegisterPeerWithPop::new(
                    PeerId::new(key_pair.public_key().clone()),
                    vec![u8::try_from(idx).unwrap_or(u8::MAX)],
                )));
            }
            for &lane_id in bootstrap_public_lanes {
                instructions.push(
                    <RegisterPublicLaneValidator as iroha_data_model::isi::Instruction>::into_instruction_box(
                        Box::new(RegisterPublicLaneValidator {
                            lane_id,
                            validator: validator.clone(),
                            peer_id: PeerId::new(key_pair.public_key().clone()),
                            stake_account: validator.clone(),
                            initial_stake: stake.clone(),
                            metadata: Metadata::default(),
                            monetary_plan: iroha_data_model::nexus::PublicLaneMonetaryPlanV1::genesis_registration(
                                AssetId::new(stake_asset.clone(), validator.clone()),
                                AssetId::new(stake_asset.clone(), custody.clone()),
                                stake.clone(),
                            ),
                        }),
                    ),
                );
                if include_activation {
                    instructions.push(
                        <ActivatePublicLaneValidator as iroha_data_model::isi::Instruction>::into_instruction_box(
                            Box::new(ActivatePublicLaneValidator {
                                lane_id,
                                validator: validator.clone(),
                            }),
                        ),
                    );
                }
            }
        }
        instructions
    }
    #[test]
    fn repetitions_from_repeats_exactly_returns_value() {
        assert_eq!(repetitions_from_repeats(Repeats::Exactly(7)), Some(7));
    }
    #[test]
    fn repetitions_from_repeats_indefinitely_returns_none() {
        assert_eq!(repetitions_from_repeats(Repeats::Indefinitely), None);
    }
    #[test]
    fn evaluate_mint_precheck_handles_trigger_states() {
        assert_eq!(
            evaluate_mint_precheck::<color_eyre::eyre::Report>(Ok(Some(3))),
            MintPrecheck::Proceed { on_chain: 3 }
        );
        assert_eq!(
            evaluate_mint_precheck::<color_eyre::eyre::Report>(Ok(Some(0))),
            MintPrecheck::SkipMissing
        );
        assert_eq!(
            evaluate_mint_precheck::<color_eyre::eyre::Report>(Ok(None)),
            MintPrecheck::SkipMissing
        );
        assert_eq!(
            evaluate_mint_precheck::<&'static str>(Err("boom")),
            MintPrecheck::SkipQueryFailed
        );
    }
    #[test]
    fn evaluate_burn_precheck_handles_trigger_states() {
        assert_eq!(
            evaluate_burn_precheck::<color_eyre::eyre::Report>(Ok(Some(5)), 3),
            BurnPrecheck::Proceed { on_chain: 5 }
        );
        assert_eq!(
            evaluate_burn_precheck::<color_eyre::eyre::Report>(Ok(Some(3)), 3),
            BurnPrecheck::SkipInsufficient { on_chain: 3 }
        );
        assert_eq!(
            evaluate_burn_precheck::<color_eyre::eyre::Report>(Ok(Some(1)), 2),
            BurnPrecheck::SkipInsufficient { on_chain: 1 }
        );
        assert_eq!(
            evaluate_burn_precheck::<color_eyre::eyre::Report>(Ok(None), 1),
            BurnPrecheck::SkipMissing
        );
        assert_eq!(
            evaluate_burn_precheck::<&'static str>(Err("boom"), 1),
            BurnPrecheck::SkipQueryFailed
        );
    }
    #[test]
    fn progress_state_update_reports_advanced_blocks_and_elapsed() {
        let start = Instant::now();
        let mut progress = ProgressState::new(start);
        assert_eq!(progress.update(start, 0), None);
        let advanced = progress
            .update(start + Duration::from_millis(120), 3)
            .expect("height increase should report progress");
        assert_eq!(advanced.0, 3);
        assert!(advanced.1 >= Duration::from_millis(120));
    }
    #[test]
    fn block_interval_tracker_reports_weighted_quantiles() {
        let mut tracker = BlockIntervalTracker::default();
        assert_eq!(tracker.summary(), None);
        assert_eq!(tracker.record(1, Duration::from_millis(100)), Some(100));
        assert_eq!(tracker.record(4, Duration::from_millis(2_000)), Some(500));
        let summary = tracker.summary().expect("tracker should have samples");
        assert_eq!(
            summary,
            BlockIntervalSummary {
                p50_ms: 500,
                p95_ms: 500,
                samples: 5,
            }
        );
    }
    #[test]
    fn target_progress_result_records_block_interval_summaries() {
        let mut quorum_tracker = BlockIntervalTracker::default();
        let mut strict_tracker = BlockIntervalTracker::default();
        assert_eq!(
            quorum_tracker.record(2, Duration::from_millis(4_000)),
            Some(2_000)
        );
        assert_eq!(
            strict_tracker.record(1, Duration::from_millis(2_500)),
            Some(2_500)
        );
        let mut result = TargetProgressResult::default();
        result.attach_block_interval_summaries(quorum_tracker.summary(), strict_tracker.summary());
        assert_eq!(result.quorum_block_interval_p50_ms, Some(2_000));
        assert_eq!(result.quorum_block_interval_p95_ms, Some(2_000));
        assert_eq!(result.quorum_block_interval_samples, Some(2));
        assert_eq!(result.strict_block_interval_p50_ms, Some(2_500));
        assert_eq!(result.strict_block_interval_p95_ms, Some(2_500));
        assert_eq!(result.strict_block_interval_samples, Some(1));
    }
    #[test]
    fn latency_gate_soft_target_blocks_rounds_duration_up_to_threshold() {
        assert_eq!(
            latency_gate_soft_target_blocks(Duration::from_secs(120), Duration::from_secs(3)),
            40
        );
        assert_eq!(
            latency_gate_soft_target_blocks(Duration::from_millis(120_001), Duration::from_secs(3)),
            41
        );
    }
    #[test]
    fn latency_p95_gate_requires_duration_deadline_samples() {
        let err = enforce_latency_p95_gate(
            &BlockIntervalTracker::default(),
            &BlockIntervalTracker::default(),
            Some(Duration::from_secs(3)),
            40,
            Duration::from_secs(120),
            "duration_deadline",
        )
        .expect_err("duration cadence gate should fail when no block intervals were sampled");
        assert!(
            err.to_string().contains("p95 block interval")
                && err.to_string().contains("checkpoint duration_deadline"),
            "unexpected latency gate error: {err}"
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn npos_network_progresses() -> Result<()> {
        if !allow_net_for_tests() {
            // Restricted sandboxes may forbid binding loopback ports; treat this as a skipped check.
            return Ok(());
        }
        crate::config::init_tracing_with_filter("warn");
        init_instruction_registry();
        let nexus = NexusProfile::sora_defaults()?;
        let config = ChaosConfig {
            duration: Duration::from_secs(2),
            seed: Some(42),
            fault_interval: Duration::from_secs(5)..=Duration::from_secs(5),
            faults: FaultToggles::from_enabled_flags([true, true, true, true, true, true, true]),
            nexus: Some(nexus),
            ..test_chaos_config()
        };
        let Some(network) = start_test_prepared_network(&config).await? else {
            return Ok(());
        };
        network
            .ensure_blocks_with(|height| height.total >= 4)
            .await
            .wrap_err("NPoS network failed to reach expected height")?;
        network.shutdown().await;
        Ok(())
    }
    #[test]
    fn npos_preflight_audit_passes_for_generated_genesis() -> Result<()> {
        init_instruction_registry();
        let profile = crate::config::NexusProfile::sora_defaults()?;
        let config = ChaosConfig {
            seed: Some(23),
            tps: 2.0,
            nexus: Some(profile),
            ..test_chaos_config()
        };
        let network = test_prepared_network_builder(&config)?.build();
        let summary = audit_npos_genesis_preflight(
            &network.genesis(),
            config.peer_count,
            config
                .nexus
                .as_ref()
                .map(|profile| profile.bootstrap_public_lanes.as_slice())
                .unwrap_or(&[]),
        )?;
        let expected_bootstrap_bindings = config.nexus.as_ref().map_or(0, |profile| {
            config
                .peer_count
                .saturating_mul(profile.bootstrap_public_lanes.len())
        });
        assert_eq!(summary.peer_with_pop_count, config.peer_count);
        assert_eq!(
            summary.register_validator_count,
            expected_bootstrap_bindings
        );
        assert_eq!(
            summary.activate_validator_count,
            expected_bootstrap_bindings
        );
        assert_eq!(
            summary.stake_distribution.len(),
            1,
            "generated NPoS genesis should have a uniform validator self-bond distribution"
        );
        Ok(())
    }
    #[test]
    fn generated_npos_genesis_bootstraps_stake_assets_before_validator_activation() -> Result<()> {
        init_instruction_registry();
        let profile = crate::config::NexusProfile::sora_defaults()?;
        let config = ChaosConfig {
            seed: Some(31),
            tps: 2.0,
            nexus: Some(profile.clone()),
            ..test_chaos_config()
        };
        let network = test_prepared_network_builder(&config)?.build();
        let mut bootstrap_tx_index = None;
        let mut validator_tx_index = None;
        let mut tx_index = 0usize;
        for tx in network.genesis().0.external_transactions() {
            let Executable::Instructions(instructions) = tx.instructions() else {
                tx_index = tx_index.saturating_add(1);
                continue;
            };
            let has_bootstrap_assets = instructions.iter().any(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<RegisterBox>()
                    .is_some_and(|register| match register {
                        RegisterBox::AssetDefinition(definition) => {
                            definition.object.id == profile.stake_asset_id
                                || definition.object.id == profile.fee_asset_id
                        }
                        _ => false,
                    })
            });
            if has_bootstrap_assets && bootstrap_tx_index.is_none() {
                bootstrap_tx_index = Some(tx_index);
            }
            let has_validator_activation = instructions.iter().any(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<RegisterPublicLaneValidator>()
                    .is_some()
            });
            if has_validator_activation && validator_tx_index.is_none() {
                validator_tx_index = Some(tx_index);
            }
            tx_index = tx_index.saturating_add(1);
        }
        let bootstrap_tx_index = bootstrap_tx_index.expect("bootstrap asset tx should exist");
        let validator_tx_index = validator_tx_index.expect("validator bootstrap tx should exist");
        assert!(
            bootstrap_tx_index < validator_tx_index,
            "stake/fee asset bootstrap must execute before validator registration"
        );
        Ok(())
    }
    #[test]
    fn generated_npos_genesis_registers_each_bootstrap_asset_definition_once() -> Result<()> {
        init_instruction_registry();
        let profile = crate::config::NexusProfile::sora_defaults()?;
        let config = ChaosConfig {
            seed: Some(41),
            tps: 2.0,
            nexus: Some(profile.clone()),
            ..test_chaos_config()
        };
        let network = test_prepared_network_builder(&config)?.build();
        let mut registrations = BTreeMap::<AssetDefinitionId, Vec<usize>>::new();
        let mut tx_asset_registrations = BTreeMap::<usize, Vec<AssetDefinitionId>>::new();
        for (tx_index, tx) in network.genesis().0.external_transactions().enumerate() {
            let Executable::Instructions(instructions) = tx.instructions() else {
                continue;
            };
            for instruction in instructions {
                let Some(register) = instruction.as_any().downcast_ref::<RegisterBox>() else {
                    continue;
                };
                let RegisterBox::AssetDefinition(definition) = register else {
                    continue;
                };
                registrations
                    .entry(definition.object.id.clone())
                    .or_default()
                    .push(tx_index);
                tx_asset_registrations
                    .entry(tx_index)
                    .or_default()
                    .push(definition.object.id.clone());
            }
        }
        for asset_id in [&profile.stake_asset_id, &profile.fee_asset_id] {
            let txs = registrations.get(asset_id).cloned().unwrap_or_default();
            let tx_details: Vec<_> = txs
                .iter()
                .map(|tx_index| {
                    let asset_ids: Vec<_> = tx_asset_registrations
                        .get(tx_index)
                        .cloned()
                        .unwrap_or_default()
                        .into_iter()
                        .map(|id| id.to_string())
                        .collect();
                    (*tx_index, asset_ids)
                })
                .collect();
            assert_eq!(
                txs,
                vec![
                    *txs.first()
                        .expect("bootstrap asset definition should exist")
                ],
                "bootstrap asset definition {asset_id} must be registered exactly once; found txs {txs:?} with asset registrations {tx_details:?}"
            );
        }
        Ok(())
    }
    #[test]
    fn synthetic_npos_preflight_has_complete_genesis_transfers() {
        init_instruction_registry();
        let amount = SumeragiNposParameters::default().min_self_bond().clone();
        let instructions = synthetic_npos_preflight_instructions(
            4,
            &[LaneId::SINGLE, LaneId::new(3)],
            true,
            true,
            &vec![amount.clone(); 4],
        );
        let summary = audit_npos_preflight_instructions(
            instructions.iter(),
            4,
            &[LaneId::SINGLE, LaneId::new(3)],
            &amount,
        )
        .expect("complete synthetic fixture passes its structural preflight");
        assert_eq!(summary.register_validator_count, 8);
        let (definition, custody) = synthetic_npos_preflight_assets();
        for registration in instructions.iter().filter_map(|instruction| {
            instruction
                .as_any()
                .downcast_ref::<RegisterPublicLaneValidator>()
        }) {
            assert_ne!(registration.validator, custody);
            assert_eq!(registration.stake_account, registration.validator);
            assert_eq!(
                registration.monetary_plan,
                iroha_data_model::nexus::PublicLaneMonetaryPlanV1::genesis_registration(
                    AssetId::new(definition.clone(), registration.stake_account.clone()),
                    AssetId::new(definition.clone(), custody.clone()),
                    registration.initial_stake.clone(),
                )
            );
            assert!(registration.monetary_plan.has_canonical_shape());
        }
    }
    #[test]
    fn npos_preflight_audit_fails_on_missing_activation() {
        init_instruction_registry();
        let min_self_bond = SumeragiNposParameters::default().min_self_bond().clone();
        let instructions = synthetic_npos_preflight_instructions(
            4,
            &[LaneId::SINGLE],
            true,
            false,
            &vec![min_self_bond.clone(); 4],
        );
        let err = audit_npos_preflight_instructions(
            instructions.iter(),
            4,
            &[LaneId::SINGLE],
            &min_self_bond,
        )
        .expect_err("missing activation should fail preflight");
        let message = err.to_string();
        assert!(
            message.contains("ActivatePublicLaneValidator count="),
            "unexpected error message: {message}"
        );
    }
    #[test]
    fn npos_preflight_audit_fails_on_missing_pop() {
        init_instruction_registry();
        let min_self_bond = SumeragiNposParameters::default().min_self_bond().clone();
        let instructions = synthetic_npos_preflight_instructions(
            4,
            &[LaneId::SINGLE],
            false,
            true,
            &vec![min_self_bond.clone(); 4],
        );
        let err = audit_npos_preflight_instructions(
            instructions.iter(),
            4,
            &[LaneId::SINGLE],
            &min_self_bond,
        )
        .expect_err("missing pop should fail preflight");
        let message = err.to_string();
        assert!(
            message.contains("RegisterPeerWithPop count="),
            "unexpected error message: {message}"
        );
    }
    #[test]
    fn npos_preflight_audit_fails_on_unequal_initial_stake() {
        init_instruction_registry();
        let min_self_bond = SumeragiNposParameters::default().min_self_bond().clone();
        let larger_bond = min_self_bond
            .try_add(&Quantity::from(1_u64))
            .expect("test bond increment must remain representable");
        let instructions = synthetic_npos_preflight_instructions(
            4,
            &[LaneId::SINGLE],
            true,
            true,
            &[
                min_self_bond.clone(),
                larger_bond,
                min_self_bond.clone(),
                min_self_bond.clone(),
            ],
        );
        let err = audit_npos_preflight_instructions(
            instructions.iter(),
            4,
            &[LaneId::SINGLE],
            &min_self_bond,
        )
        .expect_err("unequal initial stake should fail preflight");
        let message = err.to_string();
        assert!(
            message.contains("non-uniform"),
            "unexpected error message: {message}"
        );
    }
    #[test]
    fn shared_host_stable_soak_profile_caps_load_and_timeout() {
        let mut config = ChaosConfig {
            duration: Duration::from_secs(3_600),
            target_blocks: Some(3_600),
            progress_timeout: Duration::from_secs(300),
            tps: 5.0,
            max_inflight: 8,
            faults: FaultToggles::from_enabled_flags([true, true, true, true, true, true, true]),
            nexus: Some(NexusProfile::sora_defaults().expect("nexus profile")),
            ..test_chaos_config()
        };
        assert!(is_shared_host_stable_soak(&config));
        apply_shared_host_stable_soak_profile(&mut config);
        assert_eq!(
            config.tps, 5.0,
            "shared-host soak should preserve canonical 5 TPS pacing"
        );
        assert!(
            config.max_inflight >= IZANAMI_SHARED_HOST_SOAK_MAX_INFLIGHT_FLOOR,
            "shared-host soak should enforce max-inflight floor"
        );
        assert!(
            config.progress_timeout
                >= Duration::from_secs(IZANAMI_SHARED_HOST_SOAK_PROGRESS_TIMEOUT_FLOOR_SECS),
            "shared-host soak should raise progress-timeout floor"
        );
        assert_eq!(
            config.pipeline_time,
            Some(Duration::from_millis(
                IZANAMI_SHARED_HOST_SOAK_PIPELINE_TIME_MS
            )),
            "shared-host soak should enforce a conservative pipeline-time floor"
        );
        assert_eq!(
            config.latency_p95_threshold,
            Some(Duration::from_secs(
                IZANAMI_SHARED_HOST_SOAK_LATENCY_P95_THRESHOLD_SECS
            )),
            "shared-host soak should default the quorum latency gate to the DA steady-state envelope when unset"
        );
    }
    #[test]
    fn shared_host_stable_soak_profile_applies_to_permissioned_long_run() {
        let mut config = ChaosConfig {
            duration: Duration::from_secs(3_600),
            target_blocks: Some(2_000),
            progress_timeout: Duration::from_secs(300),
            seed: Some(21),
            tps: 7.0,
            max_inflight: 13,
            faults: FaultToggles::from_enabled_flags([true, true, true, true, true, true, true]),
            ..test_chaos_config()
        };
        assert!(is_shared_host_stable_soak(&config));
        apply_shared_host_stable_soak_profile(&mut config);
        assert_eq!(
            config.pipeline_time,
            Some(Duration::from_millis(
                IZANAMI_SHARED_HOST_SOAK_PIPELINE_TIME_MS
            )),
            "permissioned long-run soak should use the same conservative pipeline floor"
        );
        assert_eq!(
            config.latency_p95_threshold,
            Some(Duration::from_secs(
                IZANAMI_SHARED_HOST_SOAK_LATENCY_P95_THRESHOLD_SECS
            )),
            "permissioned shared-host soak should use the same DA steady-state latency gate default"
        );
        assert_eq!(config.tps, 7.0);
        assert_eq!(config.max_inflight, 14);
        assert!(
            config.progress_timeout
                >= Duration::from_secs(IZANAMI_SHARED_HOST_SOAK_PROGRESS_TIMEOUT_FLOOR_SECS)
        );
    }
    #[test]
    fn shared_host_stable_soak_profile_pins_canonical_load_shape() {
        let mut config = ChaosConfig {
            duration: Duration::from_secs(3_600),
            target_blocks: Some(3_600),
            progress_timeout: Duration::from_secs(300),
            seed: Some(17),
            tps: 3.0,
            max_inflight: 6,
            faults: FaultToggles::from_enabled_flags([true, true, true, true, true, true, true]),
            nexus: Some(NexusProfile::sora_defaults().expect("nexus profile")),
            ..test_chaos_config()
        };
        assert!(is_shared_host_stable_soak(&config));
        apply_shared_host_stable_soak_profile(&mut config);
        assert_eq!(
            config.tps, IZANAMI_SHARED_HOST_SOAK_TPS_FLOOR,
            "shared-host soak should enforce canonical minimum TPS for deterministic pilots"
        );
        assert_eq!(
            config.max_inflight, 10,
            "shared-host soak should enforce max_inflight floor derived from canonical TPS floor"
        );
    }
    #[test]
    fn shared_host_stable_soak_profile_does_not_touch_non_soak_runs() {
        let mut config = ChaosConfig {
            duration: Duration::from_secs(600),
            target_blocks: Some(600),
            progress_timeout: Duration::from_secs(300),
            seed: Some(9),
            tps: 5.0,
            max_inflight: 8,
            faults: FaultToggles::from_enabled_flags([true, true, true, true, true, true, true]),
            nexus: Some(NexusProfile::sora_defaults().expect("nexus profile")),
            ..test_chaos_config()
        };
        assert!(!is_shared_host_stable_soak(&config));
        apply_shared_host_stable_soak_profile(&mut config);
        assert!((config.tps - 5.0).abs() <= f64::EPSILON);
        assert_eq!(config.max_inflight, 8);
        assert_eq!(config.progress_timeout, Duration::from_secs(300));
        assert_eq!(config.pipeline_time, None);
    }
    #[test]
    fn shared_host_stable_soak_profile_applies_with_single_frozen_peer() {
        let mut config = ChaosConfig {
            faulty_peers: 1,
            duration: Duration::from_secs(3_600),
            target_blocks: Some(2_000),
            progress_timeout: Duration::from_secs(300),
            seed: Some(29),
            tps: 4.0,
            max_inflight: 6,
            faults: FaultToggles::from_enabled_flags([true, true, true, true, true, true, true]),
            nexus: Some(NexusProfile::sora_defaults().expect("nexus profile")),
            ..test_chaos_config()
        };
        assert!(
            is_shared_host_stable_soak(&config),
            "single frozen peer should still use shared-host stable soak policy"
        );
        apply_shared_host_stable_soak_profile(&mut config);
        assert_eq!(config.tps, IZANAMI_SHARED_HOST_SOAK_TPS_FLOOR);
        assert_eq!(
            config.pipeline_time,
            Some(Duration::from_millis(
                IZANAMI_SHARED_HOST_SOAK_PIPELINE_TIME_MS
            ))
        );
        assert_eq!(
            config.latency_p95_threshold,
            Some(Duration::from_secs(
                IZANAMI_SHARED_HOST_SOAK_LATENCY_P95_THRESHOLD_SECS
            ))
        );
    }
    #[test]
    fn submission_confirmation_mode_uses_ingress_acceptance_for_stable_no_faults() {
        let config = ChaosConfig {
            duration: Duration::from_secs(600),
            target_blocks: Some(200),
            progress_timeout: Duration::from_secs(300),
            seed: Some(5),
            tps: 5.0,
            max_inflight: 8,
            faults: FaultToggles::from_enabled_flags([true, true, true, true, true, true, true]),
            ..test_chaos_config()
        };
        assert_eq!(
            submission_confirmation_mode(&config),
            SubmissionConfirmationMode::AcceptedByIngress
        );
    }
    #[test]
    fn submission_confirmation_mode_uses_ingress_acceptance_for_stable_fault_runs() {
        let mut config = ChaosConfig {
            faulty_peers: 1,
            duration: Duration::from_secs(600),
            target_blocks: Some(200),
            progress_timeout: Duration::from_secs(300),
            seed: Some(5),
            tps: 5.0,
            max_inflight: 8,
            faults: FaultToggles::from_enabled_flags([true, true, true, true, true, true, true]),
            ..test_chaos_config()
        };
        assert_eq!(
            submission_confirmation_mode(&config),
            SubmissionConfirmationMode::AcceptedByIngress
        );
        config.faulty_peers = 0;
        config.workload_profile = WorkloadProfile::Chaos;
        assert_eq!(
            submission_confirmation_mode(&config),
            SubmissionConfirmationMode::BlockingApplied
        );
    }
    #[test]
    fn stable_ingress_effective_max_inflight_is_capped() {
        let mut config = ChaosConfig {
            duration: Duration::from_secs(600),
            target_blocks: Some(200),
            progress_timeout: Duration::from_secs(300),
            seed: Some(5),
            tps: 5.0,
            max_inflight: IZANAMI_STABLE_INGRESS_MAX_INFLIGHT_CAP * 8,
            faults: FaultToggles::from_enabled_flags([true, true, true, true, true, true, true]),
            ..test_chaos_config()
        };
        assert_eq!(
            effective_submission_max_inflight(&config),
            IZANAMI_STABLE_INGRESS_MAX_INFLIGHT_CAP
        );
        config.max_inflight = IZANAMI_STABLE_INGRESS_MAX_INFLIGHT_CAP / 2;
        assert_eq!(
            effective_submission_max_inflight(&config),
            IZANAMI_STABLE_INGRESS_MAX_INFLIGHT_CAP / 2
        );
        config.max_inflight = 0;
        assert_eq!(effective_submission_max_inflight(&config), 1);
    }
    #[test]
    fn severe_stopping_stable_ingress_pacing_is_capped() {
        let mut config = ChaosConfig {
            peer_count: 20,
            faulty_peers: 18,
            duration: Duration::from_secs(800),
            progress_timeout: Duration::from_secs(300),
            tps: 200.0,
            max_inflight: 512,
            submitters: 20,
            faults: FaultToggles::from_enabled_flags([
                true, false, false, false, false, false, false,
            ]),
            ..test_chaos_config()
        };
        assert!(is_severe_stopping_recovery_run(&config));
        assert_eq!(
            effective_submission_max_inflight(&config),
            IZANAMI_STABLE_SEVERE_STOPPING_MAX_INFLIGHT_CAP
        );
        assert!(
            (effective_submission_tps(&config) - IZANAMI_STABLE_SEVERE_STOPPING_TPS_CAP).abs()
                <= f64::EPSILON
        );
        config.tps = 0.5;
        config.max_inflight = 4;
        assert_eq!(effective_submission_max_inflight(&config), 4);
        assert!((effective_submission_tps(&config) - 0.5).abs() <= f64::EPSILON);
    }
    #[test]
    fn non_stopping_stable_ingress_pacing_keeps_configured_rate() {
        let mut config = ChaosConfig {
            peer_count: 20,
            faulty_peers: 5,
            duration: Duration::from_secs(800),
            progress_timeout: Duration::from_secs(300),
            tps: 200.0,
            max_inflight: 512,
            submitters: 20,
            faults: FaultToggles::from_enabled_flags([
                false, false, false, true, true, false, false,
            ]),
            ..test_chaos_config()
        };
        assert!(!is_severe_stopping_recovery_run(&config));
        assert_eq!(
            effective_submission_max_inflight(&config),
            IZANAMI_STABLE_INGRESS_MAX_INFLIGHT_CAP
        );
        assert!((effective_submission_tps(&config) - 200.0).abs() <= f64::EPSILON);
        config.tps = 400.0;
        assert_eq!(effective_submission_max_inflight(&config), 512);
        assert!((effective_submission_tps(&config) - 400.0).abs() <= f64::EPSILON);
        config.workload_profile = WorkloadProfile::Chaos;
        assert_eq!(effective_submission_max_inflight(&config), 512);
        assert!((effective_submission_tps(&config) - 400.0).abs() <= f64::EPSILON);
    }
    #[test]
    fn prebuilt_stress_queue_capacity_scales_to_buffer() {
        let mut config = ChaosConfig {
            duration: Duration::from_secs(120),
            progress_timeout: Duration::from_secs(300),
            tps: 20_000.0,
            max_inflight: 2_400_000,
            submitters: 4096,
            prebuild_tx_buffer: 2_400_000,
            prebuild_tx_workers: 20,
            faults: FaultToggles::default(),
            ..test_chaos_config()
        };
        assert_eq!(effective_network_queue_capacity(&config), 2_400_000);
        assert_eq!(
            workload_account_count(&config),
            IZANAMI_HIGH_TPS_STABLE_ACCOUNT_COUNT
        );
        config.workload_profile = WorkloadProfile::Chaos;
        assert_eq!(
            workload_account_count(&config),
            IZANAMI_HIGH_TPS_ACCOUNT_COUNT
        );
        config.workload_profile = WorkloadProfile::Stable;
        config.shutdown_drain_timeout = Duration::from_secs(120);
        assert_eq!(
            effective_ingress_request_timeout(&config),
            Duration::from_secs(120)
        );
        config.tps = 100.0;
        assert_eq!(
            effective_network_queue_capacity(&config),
            IZANAMI_QUEUE_CAPACITY
        );
        assert_eq!(
            effective_ingress_request_timeout(&config),
            Duration::from_millis(IZANAMI_INGRESS_REQUEST_TIMEOUT_MS)
        );
        config.prebuild_tx_buffer = 0;
        config.tps = 20_000.0;
        assert_eq!(
            effective_network_queue_capacity(&config),
            IZANAMI_QUEUE_CAPACITY
        );
        assert_eq!(
            workload_account_count(&config),
            IZANAMI_HIGH_TPS_STABLE_ACCOUNT_COUNT
        );
        assert_eq!(
            effective_ingress_request_timeout(&config),
            Duration::from_millis(IZANAMI_INGRESS_REQUEST_TIMEOUT_MS)
        );
        config.tps = 100.0;
        assert_eq!(workload_account_count(&config), config.peer_count * 3);
    }
    #[test]
    fn status_sample_request_timeout_is_short_and_bounded() {
        let sample_timeout = Duration::from_millis(IZANAMI_STATUS_SAMPLE_REQUEST_TIMEOUT_MS);
        assert_eq!(
            bounded_sumeragi_status_sample_request_timeout(Duration::ZERO),
            sample_timeout
        );
        assert_eq!(
            bounded_sumeragi_status_sample_request_timeout(Duration::from_secs(70)),
            sample_timeout
        );
        assert_eq!(
            bounded_sumeragi_status_sample_request_timeout(Duration::from_millis(250)),
            Duration::from_millis(250)
        );
    }
    #[test]
    fn blocking_ingress_effective_max_inflight_preserves_configured_limit() {
        let config = ChaosConfig {
            duration: Duration::from_secs(600),
            target_blocks: Some(200),
            progress_timeout: Duration::from_secs(300),
            seed: Some(5),
            tps: 5.0,
            max_inflight: IZANAMI_STABLE_INGRESS_MAX_INFLIGHT_CAP * 8,
            workload_profile: WorkloadProfile::Chaos,
            faults: FaultToggles::from_enabled_flags([true, true, true, true, true, true, true]),
            ..test_chaos_config()
        };
        assert_eq!(
            effective_submission_max_inflight(&config),
            IZANAMI_STABLE_INGRESS_MAX_INFLIGHT_CAP * 8
        );
    }
    #[test]
    fn trigger_precheck_runs_only_for_blocking_confirmation() {
        assert!(should_run_trigger_precheck(
            SubmissionConfirmationMode::BlockingApplied
        ));
        assert!(!should_run_trigger_precheck(
            SubmissionConfirmationMode::AcceptedByIngress
        ));
    }
    #[test]
    fn trigger_state_updates_force_blocking_confirmation() {
        let updates = vec![PlanUpdate::TrackRepeatableTrigger(
            "repeat_trigger_test".parse().expect("valid trigger id"),
        )];
        assert_eq!(
            effective_submission_confirmation(
                SubmissionConfirmationMode::AcceptedByIngress,
                &updates,
            ),
            SubmissionConfirmationMode::BlockingApplied
        );
    }
    #[test]
    fn asset_and_account_state_updates_force_blocking_confirmation() {
        let key_pair = checked_izanami_ed25519_key_fixture();
        let account = AccountRecord {
            id: AccountId::new(key_pair.public_key().clone()),
            key_pair,
            uaid: None,
        };
        let asset = AssetId::new(
            AssetDefinitionId::derive_from_components(
                DomainId::parse_fully_qualified("chaosnet.universal").expect("domain id"),
                "chaos_coin".parse().expect("asset name"),
            ),
            account.id.clone(),
        );
        for updates in [
            vec![PlanUpdate::TrackAccount(account)],
            vec![PlanUpdate::TrackAssetInstance(asset)],
        ] {
            assert_eq!(
                effective_submission_confirmation(
                    SubmissionConfirmationMode::AcceptedByIngress,
                    &updates,
                ),
                SubmissionConfirmationMode::BlockingApplied
            );
        }
    }
    #[test]
    fn non_trigger_state_updates_keep_ingress_confirmation() {
        let updates = Vec::<PlanUpdate>::new();
        assert_eq!(
            effective_submission_confirmation(
                SubmissionConfirmationMode::AcceptedByIngress,
                &updates,
            ),
            SubmissionConfirmationMode::AcceptedByIngress
        );
    }
    #[test]
    fn stable_transfer_plan_never_escalates_to_blocking_applied() {
        let PreparedChaos { mut state, .. } =
            instructions::prepare_state(3, None, None, WorkloadProfile::Stable, false)
                .expect("state prepared");
        let mut rng = StdRng::seed_from_u64(17);
        let plan = state
            .produce_plan_for_test(instructions::RecipeKind::TransferAsset, &mut rng)
            .expect("transfer plan");
        assert_eq!(
            effective_submission_confirmation(
                SubmissionConfirmationMode::AcceptedByIngress,
                &plan.state_updates,
            ),
            SubmissionConfirmationMode::AcceptedByIngress
        );
    }
    #[test]
    fn stable_transfer_plan_is_prebuild_safe() {
        let PreparedChaos { mut state, .. } =
            instructions::prepare_state(3, None, None, WorkloadProfile::Stable, false)
                .expect("state prepared");
        let mut rng = StdRng::seed_from_u64(19);
        let plan = state
            .produce_plan_for_test(instructions::RecipeKind::TransferAsset, &mut rng)
            .expect("transfer plan");
        assert!(plan_is_prebuild_safe(
            &plan,
            SubmissionConfirmationMode::AcceptedByIngress
        ));
    }
    #[test]
    fn stateful_plans_are_not_prebuild_safe() {
        let PreparedChaos { mut state, .. } =
            instructions::prepare_state(3, None, None, WorkloadProfile::Chaos, false)
                .expect("state prepared");
        let mut rng = StdRng::seed_from_u64(23);
        let plan = state
            .produce_plan_for_test(instructions::RecipeKind::RegisterAccount, &mut rng)
            .expect("register account plan");
        assert!(!plan_is_prebuild_safe(
            &plan,
            SubmissionConfirmationMode::AcceptedByIngress
        ));
    }
    #[test]
    fn prebuild_worker_count_uses_auto_parallelism_when_enabled() {
        let mut config = ChaosConfig {
            progress_interval: Duration::from_secs(1),
            progress_timeout: Duration::from_secs(2),
            shutdown_drain_timeout: Duration::from_secs(1),
            seed: None,
            max_inflight: 1,
            submitters: 7,
            prebuild_tx_buffer: 128,
            log_filter: "info".to_string(),
            faults: FaultToggles::default(),
            ..test_chaos_config()
        };
        let workers = effective_prebuild_tx_workers(&config);
        assert!(workers >= 1);
        assert!(workers <= config.submitters);
        config.prebuild_tx_workers = 11;
        assert_eq!(effective_prebuild_tx_workers(&config), 11);
        config.prebuild_tx_buffer = 0;
        assert_eq!(effective_prebuild_tx_workers(&config), 0);
    }
    #[test]
    fn prebuild_attempt_limit_allows_skips_without_unbounded_warmup() {
        assert_eq!(
            prebuild_attempt_limit(10, 4),
            (10 * IZANAMI_PREBUILD_ATTEMPT_MULTIPLIER) as u64
        );
        assert_eq!(prebuild_attempt_limit(0, 8), 8);
    }
    #[test]
    fn tracked_repeatable_trigger_extracts_registration_target() {
        let trigger_id: TriggerId = "repeat_trigger_test".parse().expect("valid trigger id");
        let updates = vec![PlanUpdate::TrackRepeatableTrigger(trigger_id.clone())];
        assert_eq!(tracked_repeatable_trigger(&updates), Some(trigger_id));
    }
    #[test]
    fn trigger_not_found_error_is_detected() {
        let err = eyre!("Trigger with id repeat_trigger_7 not found");
        assert!(
            is_trigger_not_found_error(&err),
            "repeatable trigger drift should classify missing-trigger errors"
        );
    }
    #[test]
    fn endpoint_pool_can_pin_and_reuse_same_endpoint() {
        let (pool, _) = test_endpoint_pool(
            &["http://127.0.0.1:101", "http://127.0.0.1:102"],
            2,
            1,
            Duration::from_secs(5),
            Duration::from_millis(500),
        );
        let now = Instant::now();
        let endpoint_idx = pool
            .select_endpoint_at("repeatable_trigger_plan", now)
            .expect("an endpoint should be selectable");
        let mut attempts = Vec::new();
        let precheck: Result<()> = pool.run_on_endpoint_at(
            "repeatable_trigger_precheck",
            endpoint_idx,
            now,
            |idx, _| {
                attempts.push(idx);
                Ok(())
            },
        );
        assert!(precheck.is_ok(), "pinned precheck should succeed");
        let submit: Result<()> =
            pool.run_on_endpoint_at("repeatable_trigger_submit", endpoint_idx, now, |idx, _| {
                attempts.push(idx);
                Ok(())
            });
        assert!(
            submit.is_ok(),
            "pinned submit should reuse the same endpoint"
        );
        assert_eq!(
            attempts,
            vec![endpoint_idx, endpoint_idx],
            "repeatable trigger precheck and submit must stay on the pinned endpoint"
        );
    }
    #[test]
    fn endpoint_pool_failover_excluding_skips_pinned_endpoint() {
        #[rustfmt::skip]
        let (pool, _) = test_endpoint_pool(
            &["http://127.0.0.1:201", "http://127.0.0.1:202", "http://127.0.0.1:203"],
            3,
            2,
            Duration::from_secs(5),
            Duration::from_millis(500),
        );
        let now = Instant::now();
        let mut attempts = Vec::new();
        let result: Result<&'static str> = pool.run_with_failover_excluding_at(
            "repeatable_trigger_route_failover",
            0,
            now,
            |idx, _| {
                attempts.push(idx);
                Ok("ok")
            },
        );
        assert_eq!(
            result.expect("alternate endpoint should satisfy route failover"),
            "ok"
        );
        assert_eq!(
            attempts,
            vec![1],
            "alternate failover should skip the pinned endpoint that just returned route_unavailable"
        );
    }
    #[test]
    fn route_unavailable_error_is_detected() {
        let err = eyre!(
            "Unexpected query response; status: 503 Service Unavailable; reject code: route_unavailable; response body: route_unavailable: no reachable authoritative peers are available for lane 1 dataspace 1"
        );
        assert!(
            is_route_unavailable_error(&err),
            "route_unavailable should trigger repeatable-trigger repinning"
        );
    }
    #[test]
    fn shared_host_stable_soak_profile_keeps_higher_pipeline_time() {
        let mut config = ChaosConfig {
            duration: Duration::from_secs(3_600),
            pipeline_time: Some(Duration::from_millis(1_200)),
            target_blocks: Some(3_600),
            progress_timeout: Duration::from_secs(300),
            latency_p95_threshold: Some(Duration::from_secs(2)),
            seed: Some(11),
            tps: 5.0,
            max_inflight: 8,
            faults: FaultToggles::from_enabled_flags([true, true, true, true, true, true, true]),
            nexus: Some(NexusProfile::sora_defaults().expect("nexus profile")),
            ..test_chaos_config()
        };
        assert!(is_shared_host_stable_soak(&config));
        apply_shared_host_stable_soak_profile(&mut config);
        assert_eq!(config.pipeline_time, Some(Duration::from_millis(1_200)));
        assert_eq!(config.latency_p95_threshold, Some(Duration::from_secs(2)));
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn nexus_status_reports_teu_metrics() -> Result<()> {
        if !allow_net_for_tests() {
            return Ok(());
        }
        crate::config::init_tracing_with_filter("warn");
        init_instruction_registry();
        let nexus = NexusProfile::sora_defaults().expect("nexus profile");
        let config = ChaosConfig {
            duration: Duration::from_secs(2),
            fault_interval: Duration::from_secs(5)..=Duration::from_secs(5),
            faults: FaultToggles::from_enabled_flags([true, true, true, true, true, true, true]),
            nexus: Some(nexus.clone()),
            ..test_chaos_config()
        };
        let Some(network) = start_test_prepared_network(&config).await? else {
            return Ok(());
        };
        let status = match network.peer().status().await {
            Ok(status) => status,
            Err(err) => {
                let looks_like_permission_denied = err
                    .downcast_ref::<io::Error>()
                    .is_some_and(|io_err| io_err.kind() == io::ErrorKind::PermissionDenied)
                    || err.to_string().contains("Operation not permitted");
                if looks_like_permission_denied {
                    return Ok(());
                }
                return Err(err);
            }
        };
        let expected_lanes = nexus.lane_catalog.lane_count().get() as usize;
        assert!(
            status.teu_lane_commit.len() >= expected_lanes,
            "expected at least {expected_lanes} lane TEU snapshots"
        );
        assert!(
            status.teu_dataspace_backlog.len() >= nexus.dataspace_catalog.entries().len(),
            "dataspace backlog telemetry should be populated"
        );
        network.shutdown().await;
        Ok(())
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_submission_records_success() {
        let metrics = Arc::new(Metrics::default());
        let succeeded = run_submission("success", true, Arc::clone(&metrics), || Ok(())).await;
        assert!(succeeded);
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.successes, 1);
        assert_eq!(snapshot.failures, 0);
        assert_eq!(snapshot.expected_failures, 0);
        assert_eq!(snapshot.unexpected_successes, 0);
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_submission_records_failure() {
        let metrics = Arc::new(Metrics::default());
        let succeeded = run_submission("failure", true, Arc::clone(&metrics), || {
            Err(eyre!("submission failed"))
        })
        .await;
        assert!(!succeeded);
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.successes, 0);
        assert_eq!(snapshot.failures, 1);
        assert_eq!(snapshot.expected_failures, 0);
        assert_eq!(snapshot.unexpected_successes, 0);
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_submission_records_expected_failure() {
        let metrics = Arc::new(Metrics::default());
        let succeeded = run_submission("expected_failure", false, Arc::clone(&metrics), || {
            Err(eyre!("submission failed"))
        })
        .await;
        assert!(!succeeded);
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.successes, 0);
        assert_eq!(snapshot.failures, 0);
        assert_eq!(snapshot.expected_failures, 1);
        assert_eq!(snapshot.unexpected_successes, 0);
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_submission_records_unexpected_success() {
        let metrics = Arc::new(Metrics::default());
        let succeeded =
            run_submission("unexpected_success", false, Arc::clone(&metrics), || Ok(())).await;
        assert!(succeeded);
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.successes, 0);
        assert_eq!(snapshot.failures, 0);
        assert_eq!(snapshot.expected_failures, 0);
        assert_eq!(snapshot.unexpected_successes, 1);
    }
    #[test]
    fn run_with_queue_timeout_retry_retries_and_succeeds() {
        let attempts = AtomicU64::new(0);
        let result =
            run_with_queue_timeout_retry_with_policy("retry_success", 2, Duration::ZERO, || {
                let attempt = attempts.fetch_add(1, Ordering::Relaxed);
                if attempt == 0 {
                    Err(eyre!("transaction queued for too long"))
                } else {
                    Ok(())
                }
            });
        assert!(result.is_ok(), "queue-timeout retries should recover");
        assert_eq!(
            attempts.load(Ordering::Relaxed),
            2,
            "helper should perform one retry before succeeding"
        );
    }
    #[tokio::test]
    async fn async_queue_timeout_retry_retries_and_succeeds() {
        let attempts = Arc::new(AtomicU64::new(0));
        let attempts_for_submit = Arc::clone(&attempts);
        let result = run_with_queue_timeout_retry_with_policy_and_delay_result_async(
            "retry_success_async",
            2,
            Duration::ZERO,
            || None,
            move || {
                let attempts_for_submit = Arc::clone(&attempts_for_submit);
                async move {
                    let attempt = attempts_for_submit.fetch_add(1, Ordering::Relaxed);
                    if attempt == 0 {
                        Err(eyre!("transaction queued for too long"))
                    } else {
                        Ok("accepted")
                    }
                }
            },
        )
        .await;
        assert_eq!(
            result.expect("async queue-timeout retry should recover"),
            "accepted"
        );
        assert_eq!(
            attempts.load(Ordering::Relaxed),
            2,
            "async helper should perform one retry before succeeding"
        );
    }
    #[test]
    fn run_with_queue_timeout_retry_retries_on_no_endpoint_backpressure() {
        let attempts = AtomicU64::new(0);
        let result = run_with_queue_timeout_retry_with_policy(
            "retry_no_endpoint_backpressure",
            2,
            Duration::ZERO,
            || {
                let attempt = attempts.fetch_add(1, Ordering::Relaxed);
                if attempt == 0 {
                    Err(eyre!(
                        "no ingress endpoints available for operation `submit_all_with_metadata`"
                    ))
                } else {
                    Ok(())
                }
            },
        );
        assert!(
            result.is_ok(),
            "temporary no-endpoint backpressure should be retried"
        );
        assert_eq!(
            attempts.load(Ordering::Relaxed),
            2,
            "helper should perform one retry before succeeding after no-endpoint backpressure"
        );
    }
    #[test]
    fn queue_timeout_retry_delay_uses_dynamic_floor_for_no_endpoint_backpressure() {
        let backoff = Duration::from_millis(250);
        let dynamic = Duration::from_secs(3);
        assert_eq!(
            queue_timeout_retry_delay(backoff, true, Some(dynamic)),
            dynamic,
            "no-endpoint backpressure should honor the pool-derived cooldown floor"
        );
        assert_eq!(
            queue_timeout_retry_delay(backoff, true, None),
            Duration::from_millis(IZANAMI_INGRESS_REPROBE_INTERVAL_MS),
            "no-endpoint backpressure without a pool delay should fall back to reprobe floor"
        );
        assert_eq!(
            queue_timeout_retry_delay(backoff, false, Some(dynamic)),
            backoff,
            "non-endpoint retryable failures should keep exponential backoff pacing"
        );
    }
    #[test]
    fn run_with_queue_timeout_retry_stops_on_non_retryable_error() {
        let attempts = AtomicU64::new(0);
        let result = run_with_queue_timeout_retry_with_policy(
            "retry_non_retryable",
            2,
            Duration::ZERO,
            || {
                attempts.fetch_add(1, Ordering::Relaxed);
                Err(eyre!("permission denied"))
            },
        );
        assert!(result.is_err(), "non-retryable errors should bubble up");
        assert_eq!(
            attempts.load(Ordering::Relaxed),
            1,
            "non-retryable failures must not be retried"
        );
    }
    #[test]
    fn run_with_queue_timeout_retry_treats_duplicate_rejection_as_success() {
        let attempts = AtomicU64::new(0);
        let result = run_with_queue_timeout_retry_with_policy(
            "retry_duplicate_idempotent",
            2,
            Duration::ZERO,
            || {
                attempts.fetch_add(1, Ordering::Relaxed);
                Err(eyre!(
                    "Transaction rejected: Repetition of `Register` for id `chaos_nft_4$chaosnet`"
                ))
            },
        );
        assert!(
            result.is_ok(),
            "duplicate register rejections should be treated as idempotent success"
        );
        assert_eq!(
            attempts.load(Ordering::Relaxed),
            1,
            "idempotent duplicate should not trigger extra retries"
        );
    }
    #[test]
    fn ingress_failover_marks_queue_timeout_retryable() {
        let err = eyre!("transaction queued for too long");
        assert!(
            is_ingress_failover_retryable(&err),
            "queue timeout errors should trigger endpoint failover"
        );
    }
    #[test]
    fn ingress_failover_marks_transaction_wait_timeout_retryable() {
        let err = eyre!("transaction did not reach Applied within 20000 ms");
        assert!(
            is_ingress_failover_retryable(&err),
            "transaction wait timeouts should trigger endpoint failover"
        );
    }
    #[test]
    fn ingress_failover_marks_http_429_retryable() {
        let err = eyre!("Failed to get pipeline transaction status: 429 Too Many Requests");
        assert!(
            is_ingress_failover_retryable(&err),
            "HTTP 429 should be treated as queue-pressure backpressure"
        );
    }
    #[test]
    fn ingress_failover_marks_closed_send_request_retryable() {
        let err = eyre!("client error (SendRequest): connection closed before message completed");
        assert!(
            is_ingress_failover_retryable(&err),
            "closed transport sends should trigger endpoint failover"
        );
    }
    #[test]
    fn ingress_failover_marks_local_port_exhaustion_retryable() {
        let err = eyre!("tcp connect error: Can't assign requested address (os error 49)");
        assert!(
            is_ingress_failover_retryable(&err),
            "local port exhaustion is transient driver pressure, not a payload failure"
        );
    }
    #[test]
    fn retryable_status_and_queue_pressure_failures_log_at_debug() {
        assert!(should_log_ingress_retry_at_debug(
            "query_confirmation",
            IngressFailureClass::QueuePressure,
            true,
        ));
        assert!(should_log_ingress_retry_at_debug(
            "submit_transaction_plan",
            IngressFailureClass::QueuePressure,
            true,
        ));
        assert!(!should_log_ingress_retry_at_debug(
            "submit_transaction_plan",
            IngressFailureClass::NonRetryable,
            false,
        ));
    }
    #[test]
    fn ingress_queue_timeout_retryable_for_no_endpoint_backpressure() {
        let err = eyre!("no ingress endpoints available for operation `submit_all_with_metadata`");
        assert!(
            is_ingress_queue_timeout_retryable(&err),
            "no-endpoint ingress backpressure should be retryable for submit helper"
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn await_worker_shutdown_returns_for_completed_tasks() {
        let handle = tokio::spawn(async {});
        await_worker_shutdown_with_timeout(vec![handle], "test", Duration::from_millis(100)).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn await_worker_shutdown_aborts_hung_tasks() {
        let handle = tokio::spawn(async {
            loop {
                time::sleep(Duration::from_secs(60)).await;
            }
        });
        timeout(
            Duration::from_secs(1),
            await_worker_shutdown_with_timeout(vec![handle], "test", Duration::from_millis(10)),
        )
        .await
        .expect("worker shutdown should return after aborting hung tasks");
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_submission_drain_counts_aborted_tasks() {
        let mut submissions = JoinSet::new();
        submissions.spawn(async {});
        submissions.spawn(async {
            loop {
                time::sleep(Duration::from_secs(60)).await;
            }
        });
        let aborted = timeout(
            Duration::from_secs(1),
            drain_submissions_for_shutdown(&mut submissions, Duration::from_millis(10)),
        )
        .await
        .expect("submission drain should return after aborting hung submissions");
        assert_eq!(aborted, 1);
        assert!(submissions.is_empty());
    }
    #[test]
    fn endpoint_pool_rotates_on_retryable_failure() {
        let (pool, ingress_stats) = test_endpoint_pool(
            &["http://127.0.0.1:1", "http://127.0.0.1:2"],
            3,
            1,
            Duration::from_secs(5),
            Duration::from_millis(500),
        );
        let now = Instant::now();
        let mut attempts = Vec::new();
        let result: Result<&'static str> = pool.run_with_failover_at("submit", now, |idx, _| {
            attempts.push(idx);
            if idx == 0 {
                Err(eyre!("connection refused"))
            } else {
                Ok("ok")
            }
        });
        assert_eq!(result.expect("alternate endpoint should succeed"), "ok");
        assert_eq!(attempts, vec![0, 1]);
        assert_eq!(
            ingress_stats.snapshot(),
            IngressStatsSnapshot {
                failover_total: 1,
                endpoint_unhealthy_total: 1
            }
        );
    }
    #[test]
    fn endpoint_pool_query_confirmation_fails_over() {
        let (pool, _) = test_endpoint_pool(
            &["http://127.0.0.1:11", "http://127.0.0.1:12"],
            3,
            1,
            Duration::from_secs(5),
            Duration::from_millis(500),
        );
        let now = Instant::now();
        let mut attempts = Vec::new();
        let result: Result<Option<u32>> =
            pool.run_with_failover_at("query_confirmation", now, |idx, _| {
                attempts.push(idx);
                if idx == 0 {
                    Err(eyre!("request timed out"))
                } else {
                    Ok(Some(9))
                }
            });
        assert_eq!(
            result.expect("query should fail over to alternate endpoint"),
            Some(9)
        );
        assert_eq!(attempts, vec![0, 1]);
    }
    #[test]
    fn endpoint_pool_status_read_prefers_hint_then_fails_over() {
        #[rustfmt::skip]
        let (pool, _) = test_endpoint_pool(
            &["http://127.0.0.1:21", "http://127.0.0.1:22", "http://127.0.0.1:23"],
            3,
            1,
            Duration::from_secs(5),
            Duration::from_millis(500),
        );
        let now = Instant::now();
        let mut attempts = Vec::new();
        let result: Result<usize> = pool.run_with_failover_at_with_preference(
            "audit_confirmation",
            Some(1),
            now,
            |idx, _| {
                attempts.push(idx);
                if idx == 1 {
                    Err(eyre!("connection refused"))
                } else {
                    Ok(idx)
                }
            },
        );
        assert_eq!(result.expect("status read should fail over"), 2);
        assert_eq!(attempts, vec![1, 2]);
    }
    #[test]
    fn endpoint_pool_status_fanout_continues_after_empty_response() {
        #[rustfmt::skip]
        let (pool, _) = test_endpoint_pool(
            &["http://127.0.0.1:24", "http://127.0.0.1:25", "http://127.0.0.1:26"],
            3,
            1,
            Duration::from_secs(5),
            Duration::from_millis(500),
        );
        let now = Instant::now();
        let mut attempts = Vec::new();
        let result: Result<Option<(usize, &'static str)>> = pool
            .run_with_failover_until_some_at_with_preference_and_limit(
                "audit_confirmation",
                Some(0),
                now,
                3,
                |idx, _| {
                    attempts.push(idx);
                    if idx == 0 {
                        Ok(None)
                    } else {
                        Ok(Some("applied"))
                    }
                },
            );
        assert_eq!(
            result.expect("status fanout should succeed"),
            Some((1, "applied"))
        );
        assert_eq!(attempts, vec![0, 1]);
    }
    #[test]
    fn endpoint_pool_status_fanout_can_override_submit_attempt_cap() {
        let (pool, _) = test_endpoint_pool(
            &[
                "http://127.0.0.1:34",
                "http://127.0.0.1:35",
                "http://127.0.0.1:36",
                "http://127.0.0.1:37",
            ],
            1,
            1,
            Duration::from_secs(5),
            Duration::from_millis(500),
        );
        let now = Instant::now();
        let mut attempts = Vec::new();
        let result: Result<Option<(usize, &'static str)>> = pool
            .run_with_failover_until_some_at_with_preference_and_limit(
                "audit_confirmation",
                Some(0),
                now,
                4,
                |idx, _| {
                    attempts.push(idx);
                    if idx < 3 {
                        Ok(None)
                    } else {
                        Ok(Some("applied"))
                    }
                },
            );
        assert_eq!(
            result.expect("status fanout should honor override"),
            Some((3, "applied"))
        );
        assert_eq!(attempts, vec![0, 1, 2, 3]);
    }
    #[test]
    fn endpoint_pool_status_query_429_does_not_mark_endpoint_unhealthy() {
        let (pool, ingress_stats) = test_endpoint_pool(
            &["http://127.0.0.1:31", "http://127.0.0.1:32"],
            3,
            1,
            Duration::from_secs(5),
            Duration::from_millis(500),
        );
        let now = Instant::now();
        let mut attempts = Vec::new();
        let result: Result<Option<u32>> =
            pool.run_with_failover_at("query_confirmation", now, |idx, _| {
                attempts.push(idx);
                if idx == 0 {
                    Err(eyre!(
                        "Failed to get pipeline transaction status: 429 Too Many Requests"
                    ))
                } else {
                    Ok(Some(7))
                }
            });
        assert_eq!(result.expect("status query should fail over"), Some(7));
        assert_eq!(attempts, vec![0, 1]);
        assert_eq!(
            ingress_stats.snapshot(),
            IngressStatsSnapshot {
                failover_total: 1,
                endpoint_unhealthy_total: 0,
            }
        );
    }
    #[test]
    fn endpoint_pool_submit_queue_pressure_marks_endpoint_unhealthy() {
        let (pool, ingress_stats) = test_endpoint_pool(
            &["http://127.0.0.1:41", "http://127.0.0.1:42"],
            3,
            1,
            Duration::from_secs(5),
            Duration::from_millis(500),
        );
        let now = Instant::now();
        let mut attempts = Vec::new();
        let result: Result<&'static str> =
            pool.run_with_failover_at("submit_transaction_plan", now, |idx, _| {
                attempts.push(idx);
                if idx == 0 {
                    Err(eyre!("transaction queued for too long"))
                } else {
                    Ok("ok")
                }
            });
        assert_eq!(result.expect("submit should fail over"), "ok");
        assert_eq!(attempts, vec![0, 1]);
        assert_eq!(
            ingress_stats.snapshot(),
            IngressStatsSnapshot {
                failover_total: 1,
                endpoint_unhealthy_total: 1,
            }
        );
    }
    #[test]
    fn endpoint_pool_respects_cooldown_then_reprobes() {
        let (pool, _) = test_endpoint_pool(
            &["http://127.0.0.1:21", "http://127.0.0.1:22"],
            3,
            1,
            Duration::from_secs(10),
            Duration::from_secs(2),
        );
        let start = Instant::now();
        let first: Result<&'static str> = pool.run_with_failover_at("submit", start, |idx, _| {
            if idx == 0 {
                Err(eyre!("connection refused"))
            } else {
                Ok("ok")
            }
        });
        assert_eq!(first.expect("second endpoint should succeed"), "ok");
        assert!(
            pool.endpoint_state(0).unhealthy_until.is_some(),
            "first endpoint should enter cooldown after retryable failure"
        );
        let mut attempts_before_reprobe = Vec::new();
        let second: Result<&'static str> =
            pool.run_with_failover_at("submit", start + Duration::from_secs(1), |idx, _| {
                attempts_before_reprobe.push(idx);
                Ok("ok")
            });
        assert_eq!(
            second.expect("healthy endpoint should continue serving"),
            "ok"
        );
        assert_eq!(
            attempts_before_reprobe,
            vec![1],
            "cooldown should suppress early reprobes"
        );
        let mut attempts_after_reprobe = Vec::new();
        let third: Result<&'static str> =
            pool.run_with_failover_at("submit", start + Duration::from_secs(3), |idx, _| {
                attempts_after_reprobe.push(idx);
                if idx == 1 {
                    Err(eyre!("timed out"))
                } else {
                    Ok("recovered")
                }
            });
        assert_eq!(
            third.expect("pool should reprobe cooled endpoint and recover"),
            "recovered"
        );
        assert_eq!(
            attempts_after_reprobe,
            vec![1, 0],
            "reprobe should include the unhealthy endpoint after the interval"
        );
    }
    #[test]
    fn ingress_pool_excludes_lagging_endpoint_when_healthy_alternatives_exist() {
        #[rustfmt::skip]
        let (pool, _) = test_endpoint_pool(
            &["http://127.0.0.1:61", "http://127.0.0.1:62", "http://127.0.0.1:63"],
            3,
            1,
            Duration::from_secs(10),
            Duration::from_secs(5),
        );
        let now = Instant::now();
        pool.update_lag_snapshot(IngressLagSnapshot {
            quorum_min_height: 220,
            peer_heights: vec![Some(180), Some(220), Some(221)],
            observed_at: now,
        });
        let mut attempts = Vec::new();
        let result: Result<&'static str> = pool.run_with_failover_at("submit", now, |idx, _| {
            attempts.push(idx);
            Ok("ok")
        });
        assert_eq!(
            result.expect("healthy non-lagging endpoint should succeed"),
            "ok"
        );
        assert_eq!(
            attempts,
            vec![1],
            "lagging endpoint should be excluded while healthy non-lagging alternatives exist"
        );
    }
    #[test]
    fn ingress_pool_forced_probe_when_all_endpoints_excluded_or_unhealthy() {
        #[rustfmt::skip]
        let (pool, _) = test_endpoint_pool(
            &["http://127.0.0.1:71", "http://127.0.0.1:72", "http://127.0.0.1:73"],
            3,
            1,
            Duration::from_secs(30),
            Duration::from_secs(30),
        );
        let start = Instant::now();
        assert!(pool.mark_failure_at(1, start, IngressFailureClass::Retryable));
        assert!(pool.mark_failure_at(2, start, IngressFailureClass::Retryable));
        {
            let mut guard = pool
                .state
                .lock()
                .expect("endpoint health state mutex should not be poisoned");
            if let Some(state) = guard.get_mut(1) {
                state.last_probe_at = Some(start);
            }
            if let Some(state) = guard.get_mut(2) {
                state.last_probe_at = Some(start);
            }
        }
        pool.update_lag_snapshot(IngressLagSnapshot {
            quorum_min_height: 300,
            peer_heights: vec![Some(250), Some(300), Some(301)],
            observed_at: start,
        });
        let mut attempts = Vec::new();
        let result: Result<&'static str> =
            pool.run_with_failover_at("submit", start + Duration::from_secs(1), |idx, _| {
                attempts.push(idx);
                Ok("forced")
            });
        assert_eq!(
            result.expect("forced probe should avoid a dead-end"),
            "forced"
        );
        assert_eq!(
            attempts,
            vec![0],
            "when all non-lagging endpoints are unavailable, forced probe should use the excluded lagging endpoint"
        );
    }
    #[test]
    fn queue_pressure_sticky_cooldown_blocks_early_reprobe_after_threshold() {
        let (pool, _) = test_endpoint_pool(
            &["http://127.0.0.1:81", "http://127.0.0.1:82"],
            2,
            3,
            Duration::from_secs(5),
            Duration::from_millis(500),
        );
        let start = Instant::now();
        let first: Result<&'static str> = pool.run_with_failover_at("submit", start, |idx, _| {
            if idx == 0 {
                Err(eyre!("transaction queued for too long"))
            } else {
                Ok("ok")
            }
        });
        assert_eq!(
            first.expect("healthy alternate endpoint should succeed"),
            "ok"
        );
        assert!(
            pool.endpoint_state(0).unhealthy_until.is_none(),
            "first queue-pressure failure should not quarantine endpoint before threshold"
        );
        assert!(
            !pool.mark_failure_at(
                0,
                start + Duration::from_millis(10),
                IngressFailureClass::QueuePressure
            ),
            "second queue-pressure failure should still remain below threshold"
        );
        assert!(
            pool.mark_failure_at(
                0,
                start + Duration::from_millis(20),
                IngressFailureClass::QueuePressure
            ),
            "queue-pressure endpoint should become unhealthy once threshold is reached"
        );
        let mut attempts = Vec::new();
        let second: Result<&'static str> =
            pool.run_with_failover_at("submit", start + Duration::from_secs(1), |idx, _| {
                attempts.push(idx);
                Ok("ok")
            });
        assert_eq!(second.expect("submission should still succeed"), "ok");
        assert_eq!(
            attempts,
            vec![1],
            "sticky queue-pressure endpoint should not be reprobed early while healthy alternatives exist"
        );
    }
    #[test]
    fn ingress_fsm_excludes_lagging_when_healthy_alternative_exists() {
        ingress_pool_excludes_lagging_endpoint_when_healthy_alternatives_exist();
    }
    #[test]
    fn ingress_fsm_forced_probe_when_all_excluded_or_unhealthy() {
        ingress_pool_forced_probe_when_all_endpoints_excluded_or_unhealthy();
    }
    #[test]
    fn ingress_queue_pressure_cooldown_blocks_early_reprobe_once_threshold_reached() {
        queue_pressure_sticky_cooldown_blocks_early_reprobe_after_threshold();
    }
    #[test]
    fn ingress_submission_backpressure_defers_when_all_endpoints_recently_probed_and_unhealthy() {
        let (pool, _) = test_endpoint_pool(
            &["http://127.0.0.1:91", "http://127.0.0.1:92"],
            2,
            1,
            Duration::from_secs(10),
            Duration::from_secs(2),
        );
        let start = Instant::now();
        assert!(pool.mark_failure_at(0, start, IngressFailureClass::QueuePressure));
        assert!(pool.mark_failure_at(1, start, IngressFailureClass::Retryable));
        {
            let mut guard = pool
                .state
                .lock()
                .expect("endpoint health state mutex should not be poisoned");
            for endpoint_state in guard.iter_mut() {
                endpoint_state.last_probe_at = Some(start);
            }
        }
        let now = start + Duration::from_millis(100);
        let attempt_order = pool.attempt_order_at(now);
        assert!(
            attempt_order.is_empty(),
            "no endpoint should be reprobed before reprobe interval elapses"
        );
        let backpressure = pool
            .submission_backpressure_delay_at(now)
            .expect("backpressure should be active while all endpoints are cooling down");
        assert!(
            backpressure >= Duration::from_millis(1),
            "backpressure delay should be bounded and positive"
        );
        assert!(
            backpressure <= Duration::from_secs(2),
            "backpressure should be bounded by reprobe interval under cooldown saturation"
        );
    }
    #[test]
    fn all_unhealthy_pool_promotes_successful_probe_to_healthy_endpoint() {
        #[rustfmt::skip]
        let (pool, _) = test_endpoint_pool(
            &["http://127.0.0.1:111", "http://127.0.0.1:112", "http://127.0.0.1:113"],
            3,
            1,
            Duration::from_secs(30),
            Duration::from_secs(2),
        );
        let start = Instant::now();
        assert!(pool.mark_failure_at(0, start, IngressFailureClass::QueuePressure));
        assert!(pool.mark_failure_at(1, start, IngressFailureClass::QueuePressure));
        assert!(pool.mark_failure_at(2, start, IngressFailureClass::QueuePressure));
        let mut first_attempts = Vec::new();
        let first: Result<&'static str> =
            pool.run_with_failover_at("submit", start + Duration::from_secs(1), |idx, _| {
                first_attempts.push(idx);
                Ok("probe")
            });
        assert_eq!(first.expect("first unhealthy probe should run"), "probe");
        assert_eq!(
            first_attempts.len(),
            1,
            "all-unhealthy path should probe only one endpoint per interval"
        );
        let mut second_attempts = Vec::new();
        let second: Result<&'static str> =
            pool.run_with_failover_at("submit", start + Duration::from_secs(1), |idx, _| {
                second_attempts.push(idx);
                Ok("recovered")
            });
        assert_eq!(
            second.expect("successful probe should recover one endpoint immediately"),
            "recovered"
        );
        assert_eq!(
            second_attempts.len(),
            1,
            "after successful probe promotion, a single healthy endpoint should serve follow-up requests"
        );
        let mut third_attempts = Vec::new();
        let third: Result<&'static str> =
            pool.run_with_failover_at("submit", start + Duration::from_secs(3), |idx, _| {
                third_attempts.push(idx);
                Ok("probe")
            });
        assert_eq!(
            third.expect("probe should reopen after reprobe interval"),
            "probe"
        );
        assert_eq!(
            third_attempts.len(),
            1,
            "reopened all-unhealthy interval should still probe exactly one endpoint"
        );
    }
    #[test]
    fn ingress_submission_backpressure_is_disabled_when_endpoint_is_ready() {
        let (pool, _) = test_endpoint_pool(
            &["http://127.0.0.1:93", "http://127.0.0.1:94"],
            2,
            1,
            Duration::from_secs(10),
            Duration::from_secs(2),
        );
        let now = Instant::now();
        assert!(pool.mark_failure_at(0, now, IngressFailureClass::QueuePressure));
        assert!(
            pool.submission_backpressure_delay_at(now + Duration::from_millis(100))
                .is_none(),
            "healthy endpoint availability should disable submit backpressure"
        );
    }
    #[test]
    fn endpoint_pool_queue_timeout_respects_unhealthy_failure_threshold() {
        let (pool, _) = test_endpoint_pool(
            &["http://127.0.0.1:31"],
            1,
            3,
            Duration::from_secs(5),
            Duration::from_millis(500),
        );
        let now = Instant::now();
        let result: Result<()> = pool.run_with_failover_at("submit", now, |_idx, _| {
            Err(eyre!("transaction queued for too long"))
        });
        assert!(result.is_err(), "queue-timeout failure should bubble up");
        let state_after_first_failure = pool.endpoint_state(0);
        assert!(
            state_after_first_failure.unhealthy_until.is_none(),
            "first queue-timeout failure should stay below unhealthy threshold"
        );
        let second_result: Result<()> =
            pool.run_with_failover_at("submit", now + Duration::from_millis(10), |_idx, _| {
                Err(eyre!("transaction queued for too long"))
            });
        assert!(
            second_result.is_err(),
            "second queue-timeout failure should still bubble up"
        );
        let state_after_second_failure = pool.endpoint_state(0);
        assert!(
            state_after_second_failure.unhealthy_until.is_none(),
            "second queue-timeout failure should stay below unhealthy threshold"
        );
        let third_result: Result<()> =
            pool.run_with_failover_at("submit", now + Duration::from_millis(20), |_idx, _| {
                Err(eyre!("transaction queued for too long"))
            });
        assert!(
            third_result.is_err(),
            "third queue-timeout failure should bubble up"
        );
        let state = pool.endpoint_state(0);
        assert!(
            state.unhealthy_until.is_some(),
            "queue-timeout endpoint should become unhealthy after threshold failures"
        );
        assert_eq!(
            state.sticky_unhealthy_until, state.unhealthy_until,
            "queue-timeout unhealthy state should use sticky cooldown tracking"
        );
    }
    #[test]
    fn endpoint_pool_queue_timeout_sticky_cooldown_clears_on_success_when_all_endpoints_unhealthy()
    {
        let (pool, _) = test_endpoint_pool(
            &["http://127.0.0.1:41"],
            1,
            1,
            Duration::from_secs(5),
            Duration::from_millis(500),
        );
        let start = Instant::now();
        let first: Result<()> = pool.run_with_failover_at("submit", start, |_idx, _| {
            Err(eyre!("transaction queued for too long"))
        });
        assert!(first.is_err(), "first queue-timeout should fail");
        let state_after_failure = pool.endpoint_state(0);
        let cooldown_until = state_after_failure
            .unhealthy_until
            .expect("queue-timeout should set cooldown");
        assert!(
            cooldown_until > start,
            "cooldown should extend beyond initial failure timestamp"
        );
        let early = start + Duration::from_secs(1);
        let second: Result<&'static str> =
            pool.run_with_failover_at("submit", early, |_idx, _| Ok("ok"));
        assert_eq!(
            second.expect("early probe success should still complete request"),
            "ok"
        );
        let state_after_early_success = pool.endpoint_state(0);
        assert!(
            state_after_early_success.unhealthy_until.is_none(),
            "successful probe should immediately clear sticky cooldown when all endpoints were unhealthy"
        );
        let after_expiry = cooldown_until + Duration::from_millis(1);
        let third: Result<&'static str> =
            pool.run_with_failover_at("submit", after_expiry, |_idx, _| Ok("ok"));
        assert_eq!(
            third.expect("endpoint should recover after sticky cooldown expiry"),
            "ok"
        );
        assert!(
            pool.endpoint_state(0).unhealthy_until.is_none(),
            "sticky queue-timeout cooldown should clear after expiry"
        );
    }
    #[test]
    fn endpoint_pool_queue_timeout_cooldown_uses_configured_unhealthy_cooldown() {
        let (pool, _) = test_endpoint_pool(
            &["http://127.0.0.1:51"],
            1,
            1,
            Duration::from_secs(1),
            Duration::from_millis(500),
        );
        let start = Instant::now();
        let result: Result<()> = pool.run_with_failover_at("submit", start, |_idx, _| {
            Err(eyre!("transaction queued for too long"))
        });
        assert!(result.is_err(), "queue-timeout failure should bubble up");
        let state = pool.endpoint_state(0);
        let unhealthy_until = state
            .unhealthy_until
            .expect("queue-timeout failure should set unhealthy cooldown");
        assert!(
            unhealthy_until.saturating_duration_since(start) >= Duration::from_secs(1),
            "queue-timeout cooldown should respect configured unhealthy cooldown"
        );
        assert!(
            unhealthy_until.saturating_duration_since(start) < Duration::from_secs(2),
            "queue-timeout cooldown should not be stretched to status-timeout floor"
        );
    }
    #[test]
    fn seeded_rng_is_deterministic_for_same_seed() {
        let mut rng_a = seeded_rng_from_seed(Some(777)).expect("seeded RNG A");
        let mut rng_b = seeded_rng_from_seed(Some(777)).expect("seeded RNG B");
        let sample_a: [u64; 3] = [rng_a.next_u64(), rng_a.next_u64(), rng_a.next_u64()];
        let sample_b: [u64; 3] = [rng_b.next_u64(), rng_b.next_u64(), rng_b.next_u64()];
        assert_eq!(
            sample_a, sample_b,
            "identical seeds must yield same sequence"
        );
    }
    #[test]
    fn seeded_rng_diverges_for_different_seeds() {
        let mut rng_a = seeded_rng_from_seed(Some(1)).expect("seeded RNG A");
        let mut rng_b = seeded_rng_from_seed(Some(2)).expect("seeded RNG B");
        let sample_a: [u64; 3] = [rng_a.next_u64(), rng_a.next_u64(), rng_a.next_u64()];
        let sample_b: [u64; 3] = [rng_b.next_u64(), rng_b.next_u64(), rng_b.next_u64()];
        assert_ne!(
            sample_a, sample_b,
            "different seeds should produce different sequences"
        );
    }
    #[test]
    fn progress_state_tracks_stalls() {
        let start = Instant::now();
        let mut state = ProgressState::new(start);
        assert!(!state.stalled(start, Duration::from_secs(5)));
        assert!(state.update(start, 0).is_none());
        assert!(!state.stalled(start + Duration::from_secs(2), Duration::from_secs(5)));
        assert!(state.update(start + Duration::from_secs(3), 2).is_some());
        assert!(!state.stalled(start + Duration::from_secs(6), Duration::from_secs(5)));
        assert!(state.stalled(start + Duration::from_secs(9), Duration::from_secs(5)));
    }
    #[test]
    fn divergence_state_trips_after_sustained_window() {
        let start = Instant::now();
        let mut state = HeightDivergenceState::new();
        let threshold = 2;
        let window = Duration::from_secs(30);
        assert!(state.observe(start, 3, threshold));
        assert!(!state.violated(start + Duration::from_secs(29), window));
        assert!(state.violated(start + Duration::from_secs(30), window));
    }
    #[test]
    fn divergence_state_resets_when_converged() {
        let start = Instant::now();
        let mut state = HeightDivergenceState::new();
        let threshold = 2;
        let window = Duration::from_secs(30);
        assert!(state.observe(start, 4, threshold));
        assert!(!state.observe(start + Duration::from_secs(10), 1, threshold));
        assert!(!state.violated(start + Duration::from_secs(40), window));
        assert!(
            state.observe(start + Duration::from_secs(41), 5, threshold),
            "fresh divergence window should start after convergence reset"
        );
        assert!(!state.violated(start + Duration::from_secs(60), window));
        assert!(state.violated(start + Duration::from_secs(71), window));
    }
    #[test]
    fn tolerated_peer_failures_matches_bft_window() {
        assert_eq!(tolerated_peer_failures(0), 0);
        assert_eq!(tolerated_peer_failures(1), 0);
        assert_eq!(tolerated_peer_failures(3), 0);
        assert_eq!(tolerated_peer_failures(4), 1);
        assert_eq!(tolerated_peer_failures(7), 2);
    }
    #[test]
    fn effective_tolerated_peer_failures_honors_configured_fault_budget() {
        assert_eq!(effective_tolerated_peer_failures(4, 0), 0);
        assert_eq!(effective_tolerated_peer_failures(4, 1), 1);
        assert_eq!(
            effective_tolerated_peer_failures(7, 1),
            1,
            "strict guard should only tolerate the configured injected-fault budget"
        );
        assert_eq!(
            effective_tolerated_peer_failures(7, 5),
            2,
            "configured budget must still remain bounded by protocol tolerance"
        );
    }
    #[test]
    fn quorum_min_height_respects_effective_tolerance() {
        assert_eq!(quorum_min_height_from_samples(vec![], 0), 0);
        assert_eq!(
            quorum_min_height_from_samples(vec![246, 316, 316, 316], 0),
            246,
            "healthy runs should fail-open on no unexpected stragglers"
        );
        assert_eq!(
            quorum_min_height_from_samples(vec![246, 316, 316, 316], 1),
            316
        );
        assert_eq!(
            quorum_min_height_from_samples(vec![0, 0, 316, 316], 1),
            0,
            "two failed peers should not be hidden for a 4-peer run"
        );
        assert_eq!(quorum_min_height_from_samples(vec![9, 10, 11], 0), 9);
    }
    #[test]
    fn strict_divergence_reference_height_trims_only_effectively_tolerated_outliers() {
        assert_eq!(
            strict_divergence_reference_height_from_samples(vec![], 0),
            0
        );
        assert_eq!(
            strict_divergence_reference_height_from_samples(vec![120, 149, 149, 149], 1),
            149,
            "single lagging outlier should not lower the strict divergence reference"
        );
        assert_eq!(
            strict_divergence_reference_height_from_samples(vec![120, 149, 149, 149], 0),
            149,
            "zero tolerated failures should anchor the strict reference on the highest healthy sample"
        );
        assert_eq!(
            strict_divergence_reference_height_from_samples(vec![120, 121, 149, 149], 1),
            149,
            "two lagging peers should keep the strict reference on the healthy quorum side"
        );
        assert_eq!(
            strict_divergence_reference_height_from_samples(vec![120, 120, 120, 149], 1),
            120,
            "single leading outlier should not raise the strict divergence reference"
        );
    }
    #[test]
    fn strict_divergence_lagging_peer_count_respects_threshold() {
        let strict_reference = 149_u64;
        assert_eq!(
            strict_divergence_lagging_peer_count(&[141, 149, 149, 149], strict_reference, 16),
            0,
            "lag below threshold should not count as strict divergence"
        );
        assert_eq!(
            strict_divergence_lagging_peer_count(&[141, 149, 149, 149], strict_reference, 2),
            1,
            "lag above threshold should be counted"
        );
    }
    #[test]
    fn strict_divergence_guard_requires_more_than_tolerated_outliers() {
        let heights_one_outlier = vec![120_u64, 149, 149, 149];
        let strict_reference_one =
            strict_divergence_reference_height_from_samples(heights_one_outlier.clone(), 1);
        let lagging_one =
            strict_divergence_lagging_peer_count(&heights_one_outlier, strict_reference_one, 16);
        assert_eq!(lagging_one, 1);
        assert!(
            lagging_one <= tolerated_peer_failures(heights_one_outlier.len()),
            "a single outlier in a 4-peer run should stay within tolerated failures"
        );
        let heights_two_outliers = vec![120_u64, 121, 149, 149];
        let strict_reference_two =
            strict_divergence_reference_height_from_samples(heights_two_outliers.clone(), 1);
        assert_eq!(
            strict_reference_two, 149,
            "strict reference should stay on the healthy quorum side for two lagging peers"
        );
        let lagging_two =
            strict_divergence_lagging_peer_count(&heights_two_outliers, strict_reference_two, 16);
        assert_eq!(lagging_two, 2);
        assert!(
            lagging_two > tolerated_peer_failures(heights_two_outliers.len()),
            "strict divergence guard should activate once outliers exceed tolerated failures"
        );
    }
    #[test]
    fn strict_progress_timeout_enforcement_respects_bft_tolerance() {
        assert!(
            should_enforce_strict_progress_timeout(0, 1),
            "global stalls with no lagging peers must enforce strict-timeout failure"
        );
        assert!(
            !should_enforce_strict_progress_timeout(1, 1),
            "a tolerated single outlier should not force strict-timeout failure"
        );
        assert!(
            should_enforce_strict_progress_timeout(2, 1),
            "strict-timeout should be enforced once lagging peers exceed BFT tolerance"
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drain_ready_submissions_clears_completed_tasks() {
        let mut set = JoinSet::new();
        set.spawn(async {});
        set.spawn(async {});
        let deadline = Instant::now() + Duration::from_secs(1);
        while set.len() > 0 && Instant::now() < deadline {
            tokio::task::yield_now().await;
            drain_ready_submissions(&mut set);
        }
        assert_eq!(
            set.len(),
            0,
            "drain should clear completed submissions within timeout"
        );
    }
    #[test]
    fn submission_backlog_limit_scales_from_max_inflight() {
        assert_eq!(
            submission_backlog_limit(8),
            8 * IZANAMI_SUBMISSION_BACKLOG_MULTIPLIER
        );
        assert_eq!(
            submission_backlog_limit(0),
            IZANAMI_SUBMISSION_BACKLOG_MULTIPLIER
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn submission_permit_scope_does_not_block_precheck_phase() {
        let semaphore = Arc::new(Semaphore::new(1));
        let saturated = semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("must acquire permit");
        let precheck_started = Arc::new(Notify::new());
        let submit_started = Arc::new(Notify::new());
        let semaphore_for_task = Arc::clone(&semaphore);
        let precheck_for_task = Arc::clone(&precheck_started);
        let submit_for_task = Arc::clone(&submit_started);
        let task = tokio::spawn(async move {
            precheck_for_task.notify_one();
            let permit = semaphore_for_task
                .acquire_owned()
                .await
                .expect("submit stage should acquire permit once available");
            submit_for_task.notify_one();
            drop(permit);
        });
        timeout(Duration::from_millis(200), precheck_started.notified())
            .await
            .expect("precheck phase should proceed even when submit permits are saturated");
        assert!(
            timeout(Duration::from_millis(100), submit_started.notified())
                .await
                .is_err(),
            "submit stage should remain blocked while permits are saturated"
        );
        drop(saturated);
        timeout(Duration::from_secs(1), submit_started.notified())
            .await
            .expect("submit stage should proceed after permit release");
        task.await.expect("permit-scope task should finish");
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wait_for_submission_capacity_enforces_backlog_bound() {
        let backlog_limit = submission_backlog_limit(1);
        let gate = Arc::new(Notify::new());
        let mut submissions = JoinSet::new();
        for _ in 0..backlog_limit {
            let gate = Arc::clone(&gate);
            submissions.spawn(async move {
                gate.notified().await;
            });
        }
        assert_eq!(submissions.len(), backlog_limit);
        let stop_notify = Notify::new();
        let deadline = Instant::now() + Duration::from_secs(2);
        {
            let wait_future = wait_for_submission_capacity(
                &mut submissions,
                backlog_limit,
                &stop_notify,
                deadline,
            );
            tokio::pin!(wait_future);
            assert!(
                timeout(Duration::from_millis(100), &mut wait_future)
                    .await
                    .is_err(),
                "capacity wait should block while backlog remains saturated"
            );
            gate.notify_one();
            assert!(
                timeout(Duration::from_secs(1), &mut wait_future)
                    .await
                    .expect("capacity wait should complete after one task finishes"),
                "capacity wait should continue when stop/deadline are not reached"
            );
        }
        assert!(
            submissions.len() < backlog_limit,
            "draining one completed submission should reduce backlog below the cap"
        );
        let gate_for_new_submission = Arc::clone(&gate);
        submissions.spawn(async move {
            gate_for_new_submission.notified().await;
        });
        assert!(
            submissions.len() <= backlog_limit,
            "queued submissions should stay bounded by max_inflight * backlog multiplier"
        );
        submissions.abort_all();
        while let Some(result) = submissions.join_next().await {
            let _ = result;
        }
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wait_for_target_blocks_reaches_target() -> Result<()> {
        if !allow_net_for_tests() {
            return Ok(());
        }
        crate::config::init_tracing_with_filter("warn");
        init_instruction_registry();
        let config = ChaosConfig {
            duration: Duration::from_secs(4),
            pipeline_time: Some(Duration::from_millis(250)),
            seed: Some(9),
            fault_interval: Duration::from_secs(5)..=Duration::from_secs(5),
            ..test_chaos_config()
        };
        let Some(network) = start_test_prepared_network(&config).await? else {
            return Ok(());
        };
        let run_control = RunControl::new(Instant::now() + Duration::from_secs(20));
        let progress = wait_for_target_blocks(
            network.peers(),
            2,
            0,
            Duration::from_millis(200),
            Duration::from_secs(5),
            None,
            &run_control,
            None,
            None,
            false,
            Instant::now(),
            Instant::now(),
        )
        .await?;
        assert!(progress.target_reached);
        network.shutdown().await;
        Ok(())
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wait_for_target_blocks_soft_kpi_allows_duration_completion_without_target()
    -> Result<()> {
        if !allow_net_for_tests() {
            return Ok(());
        }
        crate::config::init_tracing_with_filter("warn");
        init_instruction_registry();
        let config = ChaosConfig {
            duration: Duration::from_secs(4),
            pipeline_time: Some(Duration::from_millis(250)),
            seed: Some(10),
            fault_interval: Duration::from_secs(5)..=Duration::from_secs(5),
            ..test_chaos_config()
        };
        let Some(network) = start_test_prepared_network(&config).await? else {
            return Ok(());
        };
        let run_control = RunControl::new(Instant::now() + Duration::from_secs(3));
        let target_blocks = 10_000;
        let progress = wait_for_target_blocks(
            network.peers(),
            target_blocks,
            0,
            Duration::from_millis(200),
            Duration::from_secs(30),
            None,
            &run_control,
            None,
            None,
            true,
            Instant::now(),
            Instant::now(),
        )
        .await?;
        assert!(
            !progress.target_reached,
            "soft-KPI monitoring should complete duration without forcing a target hit"
        );
        assert!(
            progress.quorum_min_height < target_blocks,
            "expected unmet target for soft-KPI duration test"
        );
        network.shutdown().await;
        Ok(())
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wait_for_target_blocks_soft_kpi_enforces_latency_gate_at_duration_end() -> Result<()> {
        if !allow_net_for_tests() {
            return Ok(());
        }
        crate::config::init_tracing_with_filter("warn");
        init_instruction_registry();
        let config = ChaosConfig {
            duration: Duration::from_secs(4),
            pipeline_time: Some(Duration::from_millis(250)),
            seed: Some(11),
            fault_interval: Duration::from_secs(5)..=Duration::from_secs(5),
            ..test_chaos_config()
        };
        let Some(network) = start_test_prepared_network(&config).await? else {
            return Ok(());
        };
        let run_control = RunControl::new(Instant::now() + Duration::from_secs(3));
        let target_blocks = 10_000;
        let result = wait_for_target_blocks(
            network.peers(),
            target_blocks,
            0,
            Duration::from_millis(200),
            Duration::from_secs(30),
            Some(Duration::from_millis(1)),
            &run_control,
            None,
            None,
            true,
            Instant::now(),
            Instant::now(),
        )
        .await;
        network.shutdown().await;
        let err = result.expect_err(
            "soft-KPI runs should fail when the latency p95 gate is exceeded at duration end",
        );
        assert!(
            err.to_string().contains("p95 block interval")
                && err.to_string().contains("checkpoint duration_deadline"),
            "expected duration-end latency gate error, got: {err}"
        );
        Ok(())
    }
    #[tokio::test(flavor = "current_thread")]
    async fn wait_for_target_blocks_explicit_stop_is_error_even_in_soft_kpi_mode() {
        let run_control = RunControl::new(Instant::now() + Duration::from_secs(30));
        run_control.stop();
        let err = wait_for_target_blocks(
            &[],
            100,
            0,
            Duration::from_millis(5),
            Duration::from_secs(1),
            None,
            &run_control,
            None,
            None,
            true,
            Instant::now(),
            Instant::now(),
        )
        .await
        .expect_err("explicit stop must terminate target monitoring");
        assert!(
            err.to_string()
                .contains("izanami run stopped before target blocks reached"),
            "unexpected stop error: {err}"
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn allow_net_false_rejects_runner() {
        let config = ChaosConfig {
            allow_net: false,
            seed: Some(5),
            tps: 0.1,
            max_inflight: 1,
            ..test_chaos_config()
        };
        let err = IzanamiRunner::new(config)
            .await
            .err()
            .expect("runner must reject allow_net=false");
        assert!(
            err.to_string().contains("allow_net=false"),
            "error should mention allow_net guard: {err:?}"
        );
    }
    #[test]
    fn fault_target_selection_is_deterministic() {
        let mut rng_a = StdRng::seed_from_u64(5);
        let mut rng_b = StdRng::seed_from_u64(5);
        let first = select_fault_targets(7, 2, &mut rng_a);
        let second = select_fault_targets(7, 2, &mut rng_b);
        assert_eq!(first, second, "same seed must yield same targets");
        assert_eq!(first.len(), 2);
    }
    #[test]
    fn sumeragi_leader_targeting_detects_leader_isolation_profile() {
        let mut args = IzanamiArgs::defaults();
        args.allow_net = true;
        args.faulty = 1;
        args.faults = FaultArgs {
            crash_restart: false,
            wipe_storage: false,
            spam_invalid_transactions: false,
            network_latency: false,
            network_partition: true,
            cpu_stress: false,
            disk_saturation: false,
        };
        let config = ChaosConfig::try_from(args).expect("leader-isolation profile should parse");
        assert!(
            uses_sumeragi_leader_fault_targeting(&config),
            "single-peer partition-only faults should follow Sumeragi leader telemetry"
        );
    }
    #[test]
    fn sumeragi_leader_index_maps_the_status_leader_to_a_peer() {
        let keys = (0..4)
            .map(|_| KeyPair::random().public_key().clone())
            .collect::<Vec<_>>();
        assert_eq!(sumeragi_leader_index(None, &keys), None);
        assert_eq!(sumeragi_leader_index(Some(&keys[3]), &keys), Some(3));
        let stranger = KeyPair::random().public_key().clone();
        assert_eq!(sumeragi_leader_index(Some(&stranger), &keys), None);
    }
    #[test]
    fn fault_target_selection_diverges_with_different_seeds() {
        let mut rng_a = StdRng::seed_from_u64(11);
        let mut rng_b = StdRng::seed_from_u64(19);
        let first = select_fault_targets(8, 3, &mut rng_a);
        let second = select_fault_targets(8, 3, &mut rng_b);
        assert_eq!(first.len(), 3);
        assert_eq!(second.len(), 3);
        assert_ne!(
            first, second,
            "different seeds should produce different fault targets"
        );
    }
    #[test]
    fn metrics_snapshot_accumulates_counts() {
        let metrics = Metrics::default();
        metrics.set_submitters(3);
        metrics.record_submit_plan_started();
        metrics.record_submit_plan_shutdown_skipped();
        metrics.record_submit_tasks_shutdown_aborted(2);
        metrics.record_submit_latency(Duration::from_millis(10));
        metrics.record_submit_latency(Duration::from_millis(20));
        metrics.record_submit_latency(Duration::from_millis(30));
        metrics.configure_prebuilt_tx_buffer(128, 4);
        metrics.record_prebuilt_tx_built();
        metrics.record_prebuilt_tx_used();
        metrics.record_prebuilt_tx_fallback();
        metrics.record_prebuilt_tx_skipped();
        metrics.record_prebuilt_tx_build_failure();
        metrics.record_ingress_accepted();
        metrics.record_blocking_applied_success();
        metrics.record_confirmation_audit_sampled();
        metrics.record_confirmation_audit_applied();
        metrics.record_confirmation_audit_failed();
        metrics.record_confirmation_audit_budget_skipped();
        metrics.record_confirmation_audit_queue_dropped();
        metrics.record_confirmation_audit_shutdown_noise();
        metrics.record_backlog_spawn();
        metrics.record_inflight_acquired();
        metrics.record_success();
        metrics.record_success();
        metrics.record_failure();
        metrics.record_expected_failure();
        metrics.record_unexpected_success();
        metrics.record_inflight_released();
        metrics.record_backlog_complete();
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.offered, 1);
        assert_eq!(snapshot.submit_plans_started, 1);
        assert_eq!(snapshot.submit_plans_shutdown_skipped, 1);
        assert_eq!(snapshot.submit_tasks_shutdown_aborted, 2);
        assert_eq!(snapshot.submit_latency_samples, 3);
        assert_eq!(snapshot.submit_latency_p50_ms, 20);
        assert_eq!(snapshot.submit_latency_p95_ms, 30);
        assert_eq!(snapshot.submit_latency_p99_ms, 30);
        assert_eq!(snapshot.submit_latency_max_ms, 30);
        assert_eq!(snapshot.prebuilt_tx_buffer_capacity, 128);
        assert_eq!(snapshot.prebuilt_tx_workers, 4);
        assert_eq!(snapshot.prebuilt_tx_built, 1);
        assert_eq!(snapshot.prebuilt_tx_used, 1);
        assert_eq!(snapshot.prebuilt_tx_fallback, 1);
        assert_eq!(snapshot.prebuilt_tx_skipped, 1);
        assert_eq!(snapshot.prebuilt_tx_build_failures, 1);
        assert_eq!(snapshot.ingress_accepted, 1);
        assert_eq!(snapshot.blocking_applied_success, 1);
        assert_eq!(snapshot.confirmation_sampled, 1);
        assert_eq!(snapshot.confirmation_applied, 1);
        assert_eq!(snapshot.confirmation_failed, 1);
        assert_eq!(snapshot.confirmation_budget_skipped, 1);
        assert_eq!(snapshot.confirmation_queue_dropped, 1);
        assert_eq!(snapshot.confirmation_shutdown_noise, 1);
        assert_eq!(snapshot.successes, 2);
        assert_eq!(snapshot.failures, 1);
        assert_eq!(snapshot.expected_failures, 1);
        assert_eq!(snapshot.unexpected_successes, 1);
        assert_eq!(snapshot.inflight_current, 0);
        assert_eq!(snapshot.inflight_peak, 1);
        assert_eq!(snapshot.backlog_depth, 0);
        assert_eq!(snapshot.backlog_peak, 1);
        assert_eq!(snapshot.submitters, 3);
    }
    #[test]
    fn sumeragi_status_digest_preserves_native_status_and_tracks_progress() {
        let fixture = include_str!("../../../fixtures/sumeragi/native_status_v1.tsv")
            .lines()
            .find(|line| line.starts_with("validator\t"))
            .expect("shared Rust-produced validator status");
        let status: iroha_data_model::sumeragi::SumeragiStatus =
            norito::json::from_str(fixture.split('\t').nth(1).expect("fixture JSON column"))
                .expect("canonical native status");
        let start = SumeragiStatusDigest::from_status(status.clone());
        assert_eq!(start.status, status);
        assert_eq!(start.committed_height_advance, 0);
        let mut current = status;
        current.height += 3;
        current.committed_height += 3;
        current.applied_height += 3;
        current.view = 4;
        current.high_qc_view = Some(3);
        current.awaiting = true;
        let end = SumeragiStatusDigest::from_status(current.clone());
        let delta = end.clone().delta_from(start.clone());
        assert_eq!(delta.status, current);
        assert_eq!(delta.status.protocol_version, 1);
        assert_eq!(delta.committed_height_advance, 3);
        assert_eq!(start.delta_from(end).committed_height_advance, 0);
    }
    #[test]
    fn diagnostic_copy_preserves_logs_configs_and_genesis_payloads() -> Result<()> {
        let unique = format!(
            "izanami-diagnostic-copy-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time should be after epoch")
                .as_nanos()
        );
        let source = env::temp_dir().join(&unique).join("source");
        let destination = env::temp_dir().join(&unique).join("destination");
        let peer_dir = source.join("peer-0");
        let storage_dir = peer_dir.join("storage");
        fs::create_dir_all(&storage_dir)?;
        fs::write(peer_dir.join("run-1-stdout.log"), b"stdout")?;
        fs::write(peer_dir.join("run-1-stderr.log"), b"stderr")?;
        fs::write(peer_dir.join("run-1-config.toml"), b"extends = []")?;
        fs::write(peer_dir.join("run-1-genesis.nrt"), b"genesis")?;
        fs::write(storage_dir.join("large-store.log"), b"skip")?;
        copy_selected_diagnostic_files(&source, &source, &destination)?;
        assert!(destination.join("peer-0/run-1-stdout.log").exists());
        assert!(destination.join("peer-0/run-1-stderr.log").exists());
        assert!(destination.join("peer-0/run-1-config.toml").exists());
        assert!(destination.join("peer-0/run-1-genesis.nrt").exists());
        assert!(!destination.join("peer-0/storage/large-store.log").exists());
        fs::remove_dir_all(env::temp_dir().join(unique))?;
        Ok(())
    }
    #[test]
    fn latency_summary_uses_ceil_rank_percentiles() {
        let summary = LatencySummary::from_samples(&[100, 10, 20, 30, 40, 50, 60, 70, 80, 90]);
        assert_eq!(summary.samples, 10);
        assert_eq!(summary.p50_ms, 50);
        assert_eq!(summary.p95_ms, 100);
        assert_eq!(summary.p99_ms, 100);
        assert_eq!(summary.max_ms, 100);
    }
    #[test]
    fn throughput_confirmation_sampling_is_deterministic_for_seed() {
        let hash = [0x5Au8; 32];
        let first = throughput_confirmation_sample_bucket(&hash, 7);
        let second = throughput_confirmation_sample_bucket(&hash, 7);
        assert_eq!(
            first, second,
            "same seed must produce the same sample bucket"
        );
        assert!(
            first < 100,
            "sample bucket must stay within the fixed percentage range"
        );
    }
    #[test]
    fn confirmation_audit_scheduler_skips_when_deadline_budget_is_gone() {
        let metrics = Metrics::default();
        let (tx, _rx) = mpsc::channel(1);
        let run_control = RunControl::new(Instant::now() + Duration::from_millis(1));
        let wait_options = throughput_confirmation_wait_options();
        try_schedule_submission_audit(
            &tx,
            &metrics,
            synthetic_audit_candidate(0xA1),
            &run_control,
            &wait_options,
        );
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.confirmation_sampled, 0);
        assert_eq!(snapshot.confirmation_budget_skipped, 1);
        assert_eq!(snapshot.confirmation_queue_dropped, 0);
        assert_eq!(snapshot.confirmation_failed, 0);
    }
    #[test]
    fn confirmation_audit_scheduler_counts_full_queue_as_drop() {
        let metrics = Metrics::default();
        let (tx, _rx) = mpsc::channel(1);
        tx.try_send(synthetic_audit_candidate(0xB1))
            .expect("seeded audit queue should have capacity");
        let run_control = RunControl::new(Instant::now() + Duration::from_secs(300));
        let wait_options = throughput_confirmation_wait_options();
        try_schedule_submission_audit(
            &tx,
            &metrics,
            synthetic_audit_candidate(0xB2),
            &run_control,
            &wait_options,
        );
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.confirmation_sampled, 0);
        assert_eq!(snapshot.confirmation_budget_skipped, 0);
        assert_eq!(snapshot.confirmation_queue_dropped, 1);
        assert_eq!(snapshot.confirmation_failed, 0);
    }
    #[test]
    fn confirmation_audit_scheduler_marks_early_channel_close_as_failure() {
        let metrics = Metrics::default();
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let run_control = RunControl::new(Instant::now() + Duration::from_secs(300));
        let wait_options = throughput_confirmation_wait_options();
        try_schedule_submission_audit(
            &tx,
            &metrics,
            synthetic_audit_candidate(0xC1),
            &run_control,
            &wait_options,
        );
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.confirmation_sampled, 0);
        assert_eq!(snapshot.confirmation_budget_skipped, 0);
        assert_eq!(snapshot.confirmation_queue_dropped, 0);
        assert_eq!(snapshot.confirmation_failed, 1);
    }
    #[test]
    fn submission_audit_budget_caps_then_resets() {
        let mut budget = SubmissionAuditBudget::default();
        let start = Instant::now();
        for offset in 0..IZANAMI_THROUGHPUT_CONFIRMATION_CAP_PER_MINUTE_PER_ENDPOINT {
            assert!(
                budget.acquire_at(start + Duration::from_millis(u64::from(offset))),
                "budget should admit confirmations before the cap"
            );
        }
        assert!(
            !budget.acquire_at(start + Duration::from_secs(1)),
            "budget should reject confirmations after the cap is reached"
        );
        assert!(
            budget.acquire_at(
                start + Duration::from_secs(IZANAMI_THROUGHPUT_CONFIRMATION_WINDOW_SECS + 1)
            ),
            "budget should reset after the window expires"
        );
    }
    #[test]
    fn applied_confirmation_wait_options_use_fixed_finality_timing() {
        let options = applied_confirmation_wait_options();
        assert_eq!(
            options.timeout,
            Duration::from_millis(IZANAMI_INGRESS_STATUS_TIMEOUT_MS)
        );
        assert_eq!(
            options.poll_interval,
            Duration::from_millis(IZANAMI_THROUGHPUT_CONFIRMATION_POLL_INTERVAL_MS)
        );
    }
    #[test]
    fn throughput_confirmation_wait_options_use_extended_audit_timeout() {
        let options = throughput_confirmation_wait_options();
        assert_eq!(
            options.timeout,
            Duration::from_millis(IZANAMI_THROUGHPUT_CONFIRMATION_TIMEOUT_MS)
        );
        assert!(
            options.timeout > applied_confirmation_wait_options().timeout,
            "sampled throughput audits should tolerate local quick-run NPoS tail latency"
        );
        assert_eq!(
            options.poll_interval,
            Duration::from_millis(IZANAMI_THROUGHPUT_CONFIRMATION_POLL_INTERVAL_MS)
        );
    }
    fn chaos_config_for_audit_window(
        nexus: bool,
        faulty_peers: usize,
        faults: FaultToggles,
    ) -> ChaosConfig {
        ChaosConfig {
            allow_net: true,
            peer_count: 4,
            faulty_peers,
            duration: Duration::from_secs(120),
            pipeline_time: None,
            target_blocks: None,
            progress_interval: DEFAULT_PROGRESS_INTERVAL,
            progress_timeout: DEFAULT_PROGRESS_TIMEOUT,
            shutdown_drain_timeout: DEFAULT_SHUTDOWN_DRAIN_TIMEOUT,
            latency_p95_threshold: None,
            fault_window_start: None,
            fault_window_end: None,
            seed: Some(7),
            tps: 15.0,
            max_inflight: 64,
            submitters: 4,
            prebuild_tx_buffer: 0,
            prebuild_tx_workers: 0,
            sumeragi_block_max_transactions: DEFAULT_SUMERAGI_BLOCK_MAX_TRANSACTIONS,

            workload_profile: WorkloadProfile::Stable,
            allow_contract_deploy_in_stable: false,
            fault_interval: Duration::from_secs(5)..=Duration::from_secs(20),
            log_filter: "info".to_string(),
            faults,
            nexus: nexus.then(|| NexusProfile::sora_defaults().expect("nexus profile")),
            diagnostic_dir: None,
        }
    }
    #[test]
    fn fault_window_uses_run_bounds_when_unset() {
        let config = chaos_config_for_audit_window(false, 1, FaultToggles::default());
        let started = Instant::now();
        let deadline = started + Duration::from_secs(120);
        assert_eq!(fault_window_start_at(&config, started, deadline), started);
        assert_eq!(fault_window_end_at(&config, started, deadline), deadline);
    }
    #[test]
    fn fault_window_resolves_paper_offsets() {
        let mut config = chaos_config_for_audit_window(false, 1, FaultToggles::default());
        config.duration = Duration::from_secs(800);
        config.fault_window_start = Some(Duration::from_secs(133));
        config.fault_window_end = Some(Duration::from_secs(266));
        let started = Instant::now();
        let deadline = started + config.duration;
        assert_eq!(
            fault_window_start_at(&config, started, deadline),
            started + Duration::from_secs(133)
        );
        assert_eq!(
            fault_window_end_at(&config, started, deadline),
            started + Duration::from_secs(266)
        );
    }
    #[tokio::test]
    async fn fault_window_wait_stops_when_run_control_stops() {
        let stop = AtomicBool::new(true);
        let notify = Notify::new();
        let now = Instant::now();
        assert!(
            !wait_for_fault_window_start(
                &stop,
                &notify,
                now + Duration::from_secs(5),
                now + Duration::from_secs(10),
            )
            .await
        );
    }
    #[test]
    fn npos_crash_restart_faults_use_extended_confirmation_window() {
        let config = chaos_config_for_audit_window(
            true,
            1,
            FaultToggles::from_enabled_flags([true, false, false, false, false, false, false]),
        );
        let options = throughput_confirmation_wait_options_for(&config);
        assert!(npos_extended_confirmation_window_needed(&config));
        assert_eq!(
            options.timeout,
            Duration::from_millis(IZANAMI_NPOS_RECOVERY_CONFIRMATION_TIMEOUT_MS)
        );
        assert!(
            options.timeout > throughput_confirmation_wait_options().timeout,
            "NPoS restart recovery audits need a longer Applied-finality window"
        );
    }
    #[test]
    fn npos_targeted_load_uses_extended_confirmation_window() {
        let config = chaos_config_for_audit_window(
            true,
            0,
            FaultToggles::from_enabled_flags([false, false, false, false, false, false, false]),
        );
        let options = throughput_confirmation_wait_options_for(&config);
        assert!(npos_extended_confirmation_window_needed(&config));
        assert_eq!(
            options.timeout,
            Duration::from_millis(IZANAMI_NPOS_RECOVERY_CONFIRMATION_TIMEOUT_MS)
        );
    }
    #[test]
    fn permissioned_faults_keep_baseline_confirmation_window() {
        let config = chaos_config_for_audit_window(
            false,
            1,
            FaultToggles::from_enabled_flags([true, false, false, false, false, false, false]),
        );
        let options = throughput_confirmation_wait_options_for(&config);
        assert!(!npos_extended_confirmation_window_needed(&config));
        assert_eq!(
            options.timeout,
            Duration::from_millis(IZANAMI_THROUGHPUT_CONFIRMATION_TIMEOUT_MS)
        );
    }
    #[test]
    fn worker_shutdown_timeout_covers_confirmation_audit_window() {
        assert!(
            Duration::from_secs(IZANAMI_WORKER_SHUTDOWN_TIMEOUT_SECS)
                > Duration::from_millis(IZANAMI_NPOS_RECOVERY_CONFIRMATION_TIMEOUT_MS),
            "audit workers need enough shutdown grace to finish an in-flight confirmation wait"
        );
    }
    #[test]
    fn confirmation_audit_deadline_budget_requires_full_wait_window() {
        let options = throughput_confirmation_wait_options();
        let now = Instant::now();
        assert!(confirmation_audit_has_deadline_budget(
            now,
            now + options.timeout + options.poll_interval + Duration::from_millis(1),
            &options
        ));
        assert!(!confirmation_audit_has_deadline_budget(
            now,
            now + options.timeout,
            &options
        ));
    }
    #[test]
    fn audit_confirmation_window_elapsed_is_not_a_hard_failure_marker() {
        let timeout = eyre!("transaction did not reach state-resolved Applied within 150000 ms");
        let route_error = eyre!("route_unavailable: no reachable authoritative peers");
        assert!(is_audit_confirmation_window_elapsed(&timeout));
        assert!(!is_audit_confirmation_window_elapsed(&route_error));
    }
    #[test]
    fn audit_confirmation_uses_exact_polling_and_state_finality() {
        assert!(exact_transaction_wait_poll_interval(Duration::ZERO).is_err());
        assert_eq!(
            exact_transaction_wait_poll_interval(Duration::from_millis(1))
                .expect("nonzero poll interval"),
            Duration::from_millis(1)
        );
        for kind in ["Rejected", "Expired"] {
            assert!(is_state_resolved_terminal_failure(kind, "global", "state"));
            for source in ["cache", "queue"] {
                assert!(!is_state_resolved_terminal_failure(kind, "global", source));
            }
        }
        assert!(!is_state_resolved_terminal_failure(
            "Applied", "global", "state"
        ));
        assert!(!is_state_resolved_terminal_failure(
            "Rejected", "local", "state"
        ));
    }
    #[test]
    fn submission_deadline_budget_covers_ingress_retries() {
        let budget = submission_deadline_budget(SubmissionConfirmationMode::AcceptedByIngress);
        let minimum_retry_window = Duration::from_millis(IZANAMI_INGRESS_REQUEST_TIMEOUT_MS)
            .saturating_mul(IZANAMI_INGRESS_MAX_ATTEMPTS as u32);
        assert!(
            budget >= minimum_retry_window,
            "submitter deadline guard must cover the configured ingress retry window"
        );
    }
    #[test]
    fn blocking_submission_deadline_budget_covers_terminal_wait() {
        let accepted = submission_deadline_budget(SubmissionConfirmationMode::AcceptedByIngress);
        let blocking = submission_deadline_budget(SubmissionConfirmationMode::BlockingApplied);
        let wait_options = applied_confirmation_wait_options();
        assert!(
            blocking >= accepted.saturating_add(wait_options.timeout),
            "blocking submissions need enough budget to finish Applied-finality confirmation"
        );
    }
    #[test]
    fn submission_deadline_budget_requires_full_wait_window() {
        let now = Instant::now();
        let budget = submission_deadline_budget(SubmissionConfirmationMode::AcceptedByIngress);
        assert!(submission_has_deadline_budget(
            now,
            now + budget + Duration::from_millis(1),
            SubmissionConfirmationMode::AcceptedByIngress
        ));
        assert!(!submission_has_deadline_budget(
            now,
            now + budget,
            SubmissionConfirmationMode::AcceptedByIngress
        ));
    }
    #[tokio::test]
    async fn wait_for_duration_deadline_completes_when_no_target_blocks_are_set() {
        let run_control = RunControl::new(Instant::now() + Duration::from_millis(5));
        let result =
            wait_for_duration_deadline(&run_control, &[], 0, None, Instant::now(), Instant::now())
                .await
                .expect("duration wait should complete normally");
        assert!(!result.target_reached);
        assert_eq!(result.quorum_min_height, 0);
        assert_eq!(result.strict_min_height, 0);
        assert_eq!(result.quorum_block_interval_p95_ms, None);
        assert_eq!(result.strict_block_interval_p95_ms, None);
        assert_eq!(result.quorum_min_txs_approved, 0);
        assert_eq!(result.strict_min_txs_approved, 0);
        assert_eq!(result.first_progress_after_fault_start_height, None);
        assert_eq!(result.first_progress_after_fault_end_height, None);
    }
    #[test]
    fn duration_deadline_progress_result_does_not_infer_post_fault_progress() {
        let result = duration_deadline_progress_result(&[5, 7, 8, 8], 1);
        assert!(!result.target_reached);
        assert_eq!(result.quorum_min_height, 7);
        assert_eq!(result.strict_min_height, 5);
        assert_eq!(result.max_peer_height_skew, 3);
        assert_eq!(result.quorum_min_txs_approved, 0);
        assert_eq!(result.strict_min_txs_approved, 0);
        assert_eq!(result.first_progress_after_fault_start_height, None);
        assert_eq!(result.first_progress_after_fault_end_height, None);
    }
    #[tokio::test]
    async fn wait_for_duration_deadline_reports_explicit_stop() {
        let run_control = RunControl::new(Instant::now() + Duration::from_secs(60));
        run_control.stop();
        let err =
            wait_for_duration_deadline(&run_control, &[], 0, None, Instant::now(), Instant::now())
                .await
                .expect_err("explicit stop should end duration wait with an error");
        assert!(
            err.to_string().contains("before duration completed"),
            "unexpected duration wait error: {err}"
        );
    }
    #[test]
    fn shutdown_noise_only_applies_to_status_reads_after_stop() {
        let deadline = Instant::now() + Duration::from_secs(5);
        let run_control = RunControl::new(deadline);
        let err = eyre!("connection refused");
        assert!(
            !is_shutdown_noise_status_read_failure("audit_confirmation", &err, &run_control),
            "status reads should not be ignored before shutdown starts"
        );
        let elapsed_run_control = RunControl::new(Instant::now() - Duration::from_secs(1));
        assert!(
            is_shutdown_noise_status_read_failure("audit_confirmation", &err, &elapsed_run_control),
            "status reads should be ignored after the run deadline elapses"
        );
        run_control.stop();
        assert!(
            is_shutdown_noise_status_read_failure("audit_confirmation", &err, &run_control),
            "status reads should be ignored during shutdown"
        );
        let timeout_err = eyre!("transaction did not reach state-resolved Applied within 90000 ms");
        assert!(
            is_shutdown_noise_status_read_failure("audit_confirmation", &timeout_err, &run_control),
            "status read timeouts should be ignored once shutdown has started"
        );
        assert!(
            !is_shutdown_noise_status_read_failure("submit_transaction_plan", &err, &run_control),
            "submit-path failures must remain visible during shutdown"
        );
    }
    #[test]
    fn endpoint_pool_preferred_endpoint_round_robins_submitters() {
        #[rustfmt::skip]
        let (pool, _) = test_endpoint_pool(
            &["http://127.0.0.1:401", "http://127.0.0.1:402", "http://127.0.0.1:403"],
            3,
            1,
            Duration::from_secs(5),
            Duration::from_millis(500),
        );
        assert_eq!(
            pool.select_endpoint_preferred("submit", 0)
                .expect("submitter 0 should resolve a preferred endpoint"),
            0
        );
        assert_eq!(
            pool.select_endpoint_preferred("submit", 1)
                .expect("submitter 1 should resolve a preferred endpoint"),
            1
        );
        assert_eq!(
            pool.select_endpoint_preferred("submit", 2)
                .expect("submitter 2 should resolve a preferred endpoint"),
            2
        );
        assert_eq!(
            pool.select_endpoint_preferred("submit", 3)
                .expect("submitter 3 should wrap to the first endpoint"),
            0
        );
    }
    #[test]
    fn endpoint_pool_skips_reserved_fault_target_when_alternate_is_healthy() {
        #[rustfmt::skip]
        let (pool, _) = test_endpoint_pool(
            &["http://127.0.0.1:411", "http://127.0.0.1:412", "http://127.0.0.1:413"],
            3,
            1,
            Duration::from_secs(5),
            Duration::from_millis(500),
        );
        let now = Instant::now();
        pool.mark_endpoint_sticky_unhealthy_until(0, now + Duration::from_secs(60));
        assert_eq!(
            pool.attempt_order_preview_at_with_preference(now, Some(0)),
            vec![1, 2]
        );
        assert_eq!(
            pool.attempt_order_preview_at_with_preference(now + Duration::from_secs(61), Some(0)),
            vec![0, 1, 2]
        );
    }
    #[test]
    fn submission_metadata_increments_counter() {
        let counter = AtomicU64::new(0);
        let meta_a = submission_metadata(&counter);
        let meta_b = submission_metadata(&counter);
        assert_eq!(counter.load(Ordering::Relaxed), 2);
        let key = SUBMISSION_METADATA_KEY
            .get_or_init(|| "izanami_submission_id".parse().expect("valid metadata key"));
        let value_a = meta_a
            .get(key)
            .and_then(|value| value.try_into_any::<u64>().ok())
            .expect("first metadata entry should decode");
        let value_b = meta_b
            .get(key)
            .and_then(|value| value.try_into_any::<u64>().ok())
            .expect("second metadata entry should decode");
        assert_ne!(value_a, value_b, "each submission should be unique");
    }
    mod network_builder_config;
    #[test]
    fn make_network_builder_derives_nexus_keys() -> Result<()> {
        init_instruction_registry();
        let profile = crate::config::NexusProfile::sora_defaults()?;
        let config = ChaosConfig {
            seed: Some(23),
            nexus: Some(profile),
            ..test_chaos_config()
        };
        let _builder = test_prepared_network_builder(&config)?;
        Ok(())
    }
    #[test]
    fn make_network_builder_injects_npos_parameters() -> Result<()> {
        init_instruction_registry();
        let profile = crate::config::NexusProfile::sora_defaults()?;
        let config = ChaosConfig {
            seed: Some(19),
            nexus: Some(profile),
            ..test_chaos_config()
        };
        let Some(network) = build_test_prepared_network(&config)? else {
            return Ok(());
        };
        let mut params = Parameters::default();
        for tx in network.genesis_isi() {
            for isi in tx {
                let Some(set_param) = isi.as_any().downcast_ref::<SetParameter>() else {
                    continue;
                };
                params.set_parameter(set_param.inner().clone());
            }
        }
        assert_eq!(
            network.block_cadence(),
            default_nexus_pipeline_time(),
            "nexus runs without explicit pipeline_time should use Izanami fast pipeline defaults"
        );
        let injected_npos_params = params
            .custom()
            .get(&SumeragiNposParameters::parameter_id())
            .map(SumeragiNposParameters::from_custom_parameter)
            .transpose()?
            .flatten()
            .expect("nexus runs should inject sumeragi_npos custom parameter");
        assert_eq!(
            injected_npos_params.max_validators(),
            u32::try_from(config.peer_count).unwrap_or(u32::MAX),
            "izanami should cap NPoS election set to active peer count in soak runs"
        );
        let read_str = |layer: &Table, path: &[&str]| -> Option<String> {
            let mut current = layer;
            for (idx, key) in path.iter().enumerate() {
                let value = current.get(*key)?;
                if idx + 1 == path.len() {
                    return value.as_str().map(ToString::to_string);
                }
                current = value.as_table()?;
            }
            None
        };
        let layers: Vec<Table> = network.config_layers().map(Cow::into_owned).collect();
        let expected_gas_account = instructions::nexus_gas_account_id()?.to_string();
        for path in [
            &["pipeline", "gas", "tech_account_id"][..],
            &["nexus", "fees", "fee_sink_account_id"][..],
            &["nexus", "staking", "stake_escrow_account_id"][..],
            &["nexus", "staking", "slash_sink_account_id"][..],
        ] {
            let actual = layers.iter().rev().find_map(|layer| read_str(layer, path));
            assert_eq!(
                actual.as_deref(),
                Some(expected_gas_account.as_str()),
                "config override for {:?} should use deterministic Izanami gas account",
                path
            );
        }
        Ok(())
    }
    #[test]
    fn make_network_builder_npos_genesis_stays_within_transaction_cap() -> Result<()> {
        init_instruction_registry();
        let profile = crate::config::NexusProfile::sora_defaults()?;
        let config = ChaosConfig {
            seed: Some(23),
            nexus: Some(profile),
            ..test_chaos_config()
        };
        let Some(network) = build_test_prepared_network(&config)? else {
            return Ok(());
        };
        let tx_count = network.genesis().0.external_transactions().len();
        assert!(
            (1..=16).contains(&tx_count),
            "NPoS genesis must fit Iroha's startup validation cap; got {tx_count} transactions"
        );
        Ok(())
    }
    #[test]
    fn make_network_builder_uses_fast_pipeline_default_without_nexus() -> Result<()> {
        init_instruction_registry();
        let config = ChaosConfig {
            seed: Some(71),
            ..test_chaos_config()
        };
        let Some(network) = build_test_prepared_network(&config)? else {
            return Ok(());
        };
        assert_eq!(network.block_cadence(), default_izanami_pipeline_time());
        Ok(())
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn runner_respects_deadline_and_shuts_down() -> Result<()> {
        if !allow_net_for_tests() {
            return Ok(());
        }
        crate::config::init_tracing_with_filter("warn");
        init_instruction_registry();
        let config = ChaosConfig {
            seed: Some(13),
            tps: 0.5,
            max_inflight: 2,
            fault_interval: Duration::from_secs(5)..=Duration::from_secs(5),
            ..test_chaos_config()
        };
        let runner = match IzanamiRunner::new(config).await {
            Ok(runner) => runner,
            Err(err) => {
                let looks_like_permission_denied = err
                    .downcast_ref::<io::Error>()
                    .is_some_and(|io_err| io_err.kind() == io::ErrorKind::PermissionDenied)
                    || err.to_string().contains("Operation not permitted");
                if looks_like_permission_denied {
                    return Ok(());
                }
                return Err(err);
            }
        };
        timeout(Duration::from_secs(20), runner.run())
            .await
            .map_err(|_| eyre!("runner timed out before deadline"))??;
        Ok(())
    }
    #[test]
    fn nexus_profile_keeps_da_out_of_node_local_sumeragi_config() -> Result<()> {
        init_instruction_registry();
        let nexus = NexusProfile::sora_defaults()?;
        let config = ChaosConfig {
            seed: Some(23),
            nexus: Some(nexus.clone()),
            ..test_chaos_config()
        };
        let Some(network) = build_test_prepared_network(&config)? else {
            return Ok(());
        };
        let layers: Vec<_> = network.config_layers().collect();
        let lookup = |path: &[&str]| {
            layers.iter().rev().find_map(|layer| {
                let mut current = layer.as_ref();
                for (idx, key) in path.iter().enumerate() {
                    let value = current.get(*key)?;
                    if idx + 1 == path.len() {
                        return Some(value);
                    }
                    current = value.as_table()?;
                }
                None
            })
        };
        assert!(
            layers.len() >= 2,
            "expected base layer plus nexus config layer"
        );
        assert_eq!(
            lookup(&["network", "max_total_connections"]).and_then(TomlValue::as_integer),
            Some(
                i64::try_from(IZANAMI_MAX_TOTAL_CONNECTIONS)
                    .expect("connection capacity fits TOML")
            ),
            "Izanami's admissible reply-source bound must override the Nexus profile"
        );
        assert!(lookup(&["sumeragi", "queues"]).is_none());
        assert!(lookup(&["sumeragi", "block"]).is_none());
        let has_nexus_layer = layers.iter().any(|layer| {
            layer
                .as_ref()
                .get("nexus")
                .and_then(toml::Value::as_table)
                .is_some_and(|table| {
                    table.contains_key("lane_catalog") && table.contains_key("dataspace_catalog")
                })
        });
        assert!(has_nexus_layer, "nexus config layer must be attached");
        assert!(lookup(&["nexus", "enabled"]).is_none());
        assert!(
            layers.iter().all(|layer| {
                layer
                    .as_ref()
                    .get("sumeragi")
                    .and_then(toml::Value::as_table)
                    .is_none_or(|sumeragi| {
                        !sumeragi.contains_key("da")
                            && !sumeragi.contains_key("consensus_mode")
                            && !sumeragi.contains_key("advanced")
                            && !sumeragi.contains_key("recovery")
                    })
            }),
            "DA and consensus mode must come from signed genesis, not local Sumeragi config"
        );
        let lane_catalog = layers.iter().find_map(|layer| {
            layer
                .as_ref()
                .get("nexus")
                .and_then(toml::Value::as_table)
                .and_then(|table| table.get("lane_catalog"))
                .and_then(toml::Value::as_array)
        });
        let Some(lane_catalog) = lane_catalog else {
            return Err(eyre!("expected nexus lane_catalog in config layer"));
        };
        let missing_metadata = lane_catalog.iter().any(|entry| {
            entry
                .as_table()
                .and_then(|table| table.get("metadata"))
                .and_then(toml::Value::as_table)
                .is_none()
        });
        assert!(
            !missing_metadata,
            "nexus lane_catalog entries must include metadata"
        );
        Ok(())
    }
}
