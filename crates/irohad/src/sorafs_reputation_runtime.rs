//! Supervised daemon lifecycle for the committed SoraFS reputation projector.
//!
//! This module owns scheduling and payload-free health projection only. It
//! never fabricates ledger pages, signatures, DAG acknowledgements, or native
//! journal transactions: those operations remain behind deployment-injected,
//! identity-pinned runtime adapters.
use crate::sorafs_reputation_finalized_query::ReputationFinalizedArchiveRetentionControlV1;
use eyre::{Result, WrapErr, bail};
use iroha_config::parameters::{actual::SorafsReputationRuntime, is_production_runtime_handle};
use iroha_data_model::{
    NetworkId,
    query::sorafs::prelude::FindSorafsReputationJournalAuthorityPolicy,
    sorafs::{capacity::ProviderId, reputation::PorTerminalOutcomeV1},
};
use iroha_futures::supervisor::{Child, OnShutdown, ShutdownSignal};
use sorafs_manifest::{
    ReputationSnapshotTrustPolicyV1, ReputationWeightsV1, reputation::REPUTATION_WEIGHTS_VERSION_V1,
};
#[cfg(test)]
use sorafs_node::reputation::runtime::{
    ReputationJournalCheckpointExternalErrorV1, ReputationJournalSealedCheckpointRecordV1,
};
use sorafs_node::reputation::{
    ReputationIngestMetricsSnapshot, ReputationIngestPolicyV1, ReputationIngestService,
    ReputationIngestStatusV1,
    runtime::{
        PorTerminalReputationAdmissionV1, REPUTATION_RUNTIME_PROVIDER_QUALIFICATION_REVISION_V1,
        ReputationCommittedProjectorRuntimeV1, ReputationCommittedReadApiV1,
        ReputationCommittedReadProjectionV1, ReputationFinalizedQueryPolicyV1,
        ReputationFinalizedQueryV1, ReputationGovernanceDagClientV1,
        ReputationJournalCheckpointRuntimeV1, ReputationJournalCheckpointSealingPolicyV1,
        ReputationJournalDeliveryFinalizedViewV1, ReputationJournalDeliveryMetricsV1,
        ReputationJournalDeliveryPolicyV1, ReputationJournalDeliveryWorkerV1,
        ReputationJournalProducerOutboxV1, ReputationJournalProducerPolicyV1,
        ReputationJournalTransactionSubmitterV1, ReputationPublicationPolicyV1,
        ReputationPublicationReconcilerV1, ReputationRuntimeError,
        ReputationRuntimeProviderQualificationV1, ReputationRuntimeStatusV1,
        ReputationRuntimeSupervisorV1, ReputationThresholdSignerClientV1,
        reputation_journal_submitter_policy_digest_v1,
    },
};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
const SHUTDOWN_WAIT: Duration = Duration::from_secs(2);
const MIN_RECONCILIATION_TIMEOUT: Duration = Duration::from_secs(30);
const RECONCILIATION_TIMEOUT_POLL_MULTIPLIER: u32 = 3;
const RECONCILIATION_FRESHNESS_GRACE_POLLS: u32 = 2;
type ReputationReconciliationResult =
    Result<sorafs_node::reputation::runtime::ReputationRuntimeTickOutcomeV1>;
type ReputationJoinedReconciliationResult =
    std::result::Result<ReputationReconciliationResult, crate::panic_recovery::RecoverablePanic>;
/// Runtime-only dependencies for the committed reputation worker.
#[derive(Clone)]
pub(crate) struct ReputationRuntimeDependenciesV1 {
    pub(crate) finalized_query: Arc<dyn ReputationFinalizedQueryV1>,
    pub(crate) journal_checkpoint_provider: Arc<dyn ReputationJournalCheckpointRuntimeV1>,
    pub(crate) journal_transaction_submitter: Arc<dyn ReputationJournalTransactionSubmitterV1>,
    pub(crate) threshold_signer: Arc<dyn ReputationThresholdSignerClientV1>,
    pub(crate) governance_dag: Arc<dyn ReputationGovernanceDagClientV1>,
    pub(crate) retention_control: Option<Arc<dyn ReputationFinalizedArchiveRetentionControlV1>>,
}
impl ReputationRuntimeDependenciesV1 {
    /// Require every runtime-only production adapter before daemon assembly.
    pub(crate) fn require(
        finalized_query: Option<Arc<dyn ReputationFinalizedQueryV1>>,
        journal_checkpoint_provider: Option<Arc<dyn ReputationJournalCheckpointRuntimeV1>>,
        journal_transaction_submitter: Option<Arc<dyn ReputationJournalTransactionSubmitterV1>>,
        threshold_signer: Option<Arc<dyn ReputationThresholdSignerClientV1>>,
        governance_dag: Option<Arc<dyn ReputationGovernanceDagClientV1>>,
        retention_control: Option<Arc<dyn ReputationFinalizedArchiveRetentionControlV1>>,
    ) -> Result<Self> {
        let finalized_query = finalized_query.ok_or_else(|| {
            eyre::eyre!("missing immutable historical exact-anchor finalized-query adapter")
        })?;
        let journal_checkpoint_provider = journal_checkpoint_provider.ok_or_else(|| {
            eyre::eyre!("missing external monotonic reputation journal-checkpoint provider")
        })?;
        let journal_transaction_submitter = journal_transaction_submitter.ok_or_else(|| {
            eyre::eyre!("missing runtime-only reputation journal transaction submitter")
        })?;
        let threshold_signer = threshold_signer
            .ok_or_else(|| eyre::eyre!("missing external threshold-signer adapter"))?;
        let governance_dag = governance_dag.ok_or_else(|| {
            eyre::eyre!("missing authenticated Governance DAG publication/readback adapter")
        })?;
        Ok(Self {
            finalized_query,
            journal_checkpoint_provider,
            journal_transaction_submitter,
            threshold_signer,
            governance_dag,
            retention_control,
        })
    }
}
/// Payload-free daemon health projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReputationDaemonStatusV1 {
    /// Status of committed ingest and external publication.
    pub runtime: ReputationRuntimeStatusV1,
    /// Detailed committed projector status.
    pub ingest: ReputationIngestStatusV1,
    /// Monotonic supervised-worker liveness state.
    pub liveness: ReputationDaemonLivenessStatusV1,
    /// Whether the supervised native journal worker is fully caught up with
    /// no pending or dead-lettered rows.
    pub journal_transaction_submitter_ready: bool,
    /// Overall daemon readiness, including the native journal producer path.
    pub ready: bool,
}
/// Payload-free monotonic liveness state for the supervised reputation worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReputationDaemonLivenessStatusV1 {
    /// Whether every runtime-bound external adapter and the configured
    /// retention control passed the latest completed supervised tick. This is
    /// false before the first tick.
    pub external_dependencies_healthy: bool,
    /// Whether a reconciliation tick completed within the monotonic freshness
    /// bound. This is false before the first completed tick.
    pub last_tick_fresh: bool,
    /// Whether one bounded reconciliation attempt is currently running.
    pub tick_in_flight: bool,
}
/// Payload-free supervised-worker counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReputationDaemonMetricsV1 {
    /// Reconciliation ticks that completed without error.
    pub successful_ticks: u64,
    /// Reconciliation ticks that returned a typed error.
    pub failed_ticks: u64,
    /// Spawn-blocking tasks that panicked or were cancelled.
    pub panicked_ticks: u64,
    /// Reconciliation ticks that exceeded their monotonic deadline.
    pub timed_out_ticks: u64,
    /// Deterministic projector counters.
    pub ingest: ReputationIngestMetricsSnapshot,
    /// Native journal delivery counters, or `None` when the required worker
    /// was not attached.
    pub journal_delivery: Option<ReputationJournalDeliveryMetricsV1>,
}
#[derive(Debug, Default)]
struct ReputationDaemonCounters {
    successful: AtomicU64,
    failed: AtomicU64,
    panicked: AtomicU64,
    timed_out: AtomicU64,
}
#[derive(Debug)]
struct ReputationDaemonLiveness {
    last_completed_at: Mutex<Option<Instant>>,
    external_dependencies_healthy: AtomicBool,
    tick_in_flight: AtomicBool,
    shutting_down: AtomicBool,
    tick_timeout: Duration,
    freshness_timeout: Duration,
}
#[derive(Debug)]
struct ReputationDaemonShutdownGuard {
    liveness: Arc<ReputationDaemonLiveness>,
}
impl Drop for ReputationDaemonShutdownGuard {
    fn drop(&mut self) {
        self.liveness.mark_shutdown();
    }
}
impl ReputationDaemonLiveness {
    fn new(poll_interval: Duration) -> Self {
        let tick_timeout = poll_interval
            .saturating_mul(RECONCILIATION_TIMEOUT_POLL_MULTIPLIER)
            .max(MIN_RECONCILIATION_TIMEOUT);
        let freshness_timeout = tick_timeout
            .saturating_add(poll_interval.saturating_mul(RECONCILIATION_FRESHNESS_GRACE_POLLS));
        Self {
            last_completed_at: Mutex::new(None),
            external_dependencies_healthy: AtomicBool::new(false),
            tick_in_flight: AtomicBool::new(false),
            shutting_down: AtomicBool::new(false),
            tick_timeout,
            freshness_timeout,
        }
    }
    fn begin_tick(&self) {
        self.tick_in_flight.store(true, Ordering::Release);
    }
    fn finish_tick(&self, healthy: bool) -> Result<(), ReputationRuntimeError> {
        let last_completed_at = self.last_completed_at.lock();
        let Ok(mut last_completed_at) = last_completed_at else {
            self.tick_in_flight.store(false, Ordering::Release);
            self.external_dependencies_healthy
                .store(false, Ordering::Release);
            return Err(ReputationRuntimeError::RuntimePoisoned);
        };
        *last_completed_at = Some(Instant::now());
        self.tick_in_flight.store(false, Ordering::Release);
        self.external_dependencies_healthy
            .store(healthy, Ordering::Release);
        Ok(())
    }
    fn mark_timeout(&self) {
        self.external_dependencies_healthy
            .store(false, Ordering::Release);
    }
    fn mark_late_tick_finished(&self) {
        self.tick_in_flight.store(false, Ordering::Release);
    }
    fn mark_shutdown(&self) {
        self.shutting_down.store(true, Ordering::Release);
        self.tick_in_flight.store(false, Ordering::Release);
        self.external_dependencies_healthy
            .store(false, Ordering::Release);
    }
    fn status(&self) -> Result<(bool, bool, bool), ReputationRuntimeError> {
        let last_completed_at = self
            .last_completed_at
            .lock()
            .map_err(|_| ReputationRuntimeError::RuntimePoisoned)?;
        let external_dependencies_healthy =
            self.external_dependencies_healthy.load(Ordering::Acquire);
        let tick_in_flight = self.tick_in_flight.load(Ordering::Acquire);
        let shutting_down = self.shutting_down.load(Ordering::Acquire);
        let last_tick_fresh = !shutting_down
            && last_completed_at.is_some_and(|completed| {
                Instant::now().saturating_duration_since(completed) <= self.freshness_timeout
            });
        Ok((
            external_dependencies_healthy,
            last_tick_fresh,
            tick_in_flight,
        ))
    }
}
/// Cloneable status/metrics handle retained by `irohad`.
#[derive(Debug, Clone)]
pub struct ReputationRuntimeHandleV1 {
    active: Arc<Mutex<Option<ActiveReputationRuntimeV1>>>,
}
#[derive(Debug, Clone)]
struct ActiveReputationRuntimeV1 {
    runtime: Arc<ReputationRuntimeSupervisorV1>,
    retention_control: Option<Arc<dyn ReputationFinalizedArchiveRetentionControlV1>>,
    counters: Arc<ReputationDaemonCounters>,
    liveness: Arc<ReputationDaemonLiveness>,
}
impl ActiveReputationRuntimeV1 {
    fn check_external_bindings(&self) -> Result<(), ReputationRuntimeError> {
        self.runtime.check_external_bindings()?;
        if let Some(retention_control) = &self.retention_control {
            retention_control
                .revalidate()
                .map_err(|_| ReputationRuntimeError::RuntimeBindingChanged)?;
        }
        Ok(())
    }
}
impl ReputationRuntimeHandleV1 {
    fn from_active(active: ActiveReputationRuntimeV1) -> Self {
        Self {
            active: Arc::new(Mutex::new(Some(active))),
        }
    }
    fn deferred() -> Self {
        Self {
            active: Arc::new(Mutex::new(None)),
        }
    }
    fn active(&self) -> Result<ActiveReputationRuntimeV1, ReputationRuntimeError> {
        self.active
            .lock()
            .map_err(|_| ReputationRuntimeError::RuntimePoisoned)?
            .clone()
            .ok_or(ReputationRuntimeError::RuntimeBindingMismatch)
    }
    /// Return whether deferred runtime assembly has installed the active
    /// deployment-owned dependencies.
    ///
    /// # Errors
    ///
    /// Returns an error when the runtime slot is poisoned or its active binding is invalid.
    pub fn activation_state(
        &self,
    ) -> Result<
        sorafs_node::reputation::runtime::PorTerminalReputationAdmissionStateV1,
        ReputationRuntimeError,
    > {
        let slot = self
            .active
            .lock()
            .map_err(|_| ReputationRuntimeError::RuntimePoisoned)?;
        let Some(active) = slot.clone() else {
            return Ok(
                sorafs_node::reputation::runtime::PorTerminalReputationAdmissionStateV1::Deferred,
            );
        };
        drop(slot);
        active.check_external_bindings()?;
        Ok(sorafs_node::reputation::runtime::PorTerminalReputationAdmissionStateV1::Active)
    }
    fn install_active(
        &self,
        active: ActiveReputationRuntimeV1,
    ) -> Result<(), ReputationRuntimeError> {
        let mut slot = self
            .active
            .lock()
            .map_err(|_| ReputationRuntimeError::RuntimePoisoned)?;
        if slot.is_some() {
            return Err(ReputationRuntimeError::RuntimeBindingMismatch);
        }
        *slot = Some(active);
        Ok(())
    }
    /// Return payload-free health and readiness without performing work.
    ///
    /// # Errors
    ///
    /// Returns a runtime-state or liveness-lock error.
    pub fn status(&self) -> Result<ReputationDaemonStatusV1, ReputationRuntimeError> {
        let active = self.active()?;
        let runtime = active.runtime.status()?;
        let ingest = active.runtime.ingest_status()?;
        let (external_dependencies_healthy, last_tick_fresh, tick_in_flight) =
            active.liveness.status()?;
        let journal_transaction_submitter_ready =
            runtime.journal_delivery.is_some_and(|status| status.ready);
        let ready = runtime.ready && external_dependencies_healthy && last_tick_fresh;
        Ok(ReputationDaemonStatusV1 {
            runtime,
            ingest,
            liveness: ReputationDaemonLivenessStatusV1 {
                external_dependencies_healthy,
                last_tick_fresh,
                tick_in_flight,
            },
            journal_transaction_submitter_ready,
            ready,
        })
    }
    /// Return payload-free supervised and deterministic counters.
    #[must_use]
    pub fn metrics(&self) -> ReputationDaemonMetricsV1 {
        let Ok(active) = self.active() else {
            return ReputationDaemonMetricsV1 {
                successful_ticks: 0,
                failed_ticks: 0,
                panicked_ticks: 0,
                timed_out_ticks: 0,
                ingest: ReputationIngestMetricsSnapshot::default(),
                journal_delivery: None,
            };
        };
        ReputationDaemonMetricsV1 {
            successful_ticks: active.counters.successful.load(Ordering::Relaxed),
            failed_ticks: active.counters.failed.load(Ordering::Relaxed),
            panicked_ticks: active.counters.panicked.load(Ordering::Relaxed),
            timed_out_ticks: active.counters.timed_out.load(Ordering::Relaxed),
            ingest: active.runtime.ingest_metrics(),
            journal_delivery: active.runtime.journal_delivery_metrics().ok().flatten(),
        }
    }
    /// Return the exact durable committed reputation read projection.
    ///
    /// Threshold-signer output and submitter-side Governance DAG success are
    /// never exposed before authenticated readback and projector
    /// acknowledgement complete.
    ///
    /// # Errors
    ///
    /// Returns a durable-state or runtime-lock error.
    pub fn committed_read_projection(
        &self,
    ) -> Result<ReputationCommittedReadProjectionV1, ReputationRuntimeError> {
        self.active()?.runtime.committed_read_projection()
    }
    /// Return one exact retained authoritative snapshot by its identifier.
    ///
    /// # Errors
    ///
    /// Returns a durable-state or runtime-lock error.
    pub fn committed_snapshot_by_id(
        &self,
        snapshot_id: [u8; 16],
    ) -> Result<Option<sorafs_manifest::ReputationSnapshotV1>, ReputationRuntimeError> {
        self.active()?.runtime.committed_snapshot_by_id(snapshot_id)
    }
    /// Return only the retained committed-event suffix after `sequence`.
    ///
    /// # Errors
    ///
    /// Returns a durable-state or runtime-lock error.
    pub fn committed_events_after(
        &self,
        sequence: u64,
    ) -> Result<Vec<sorafs_manifest::ReputationSnapshotEventV1>, ReputationRuntimeError> {
        self.active()?.runtime.committed_events_after(sequence)
    }
    /// Durably enqueue one actual native `PoR` terminal callback.
    ///
    /// This is a fail-closed injection point for a `PoR` terminal owner and
    /// returns only after the producer checkpoint is durable. The standard
    /// daemon's supervised worker invokes it for every retained native terminal.
    /// Every call revalidates all active external bindings before and after the
    /// durable enqueue; a post-enqueue drift fails the call while an exact retry
    /// replays the retained admission.
    ///
    /// # Errors
    ///
    /// Returns a runtime-binding or durable producer error.
    pub fn record_por_terminal(
        &self,
        provider_id: ProviderId,
        outcome: PorTerminalOutcomeV1,
    ) -> Result<
        sorafs_node::reputation::runtime::ReputationJournalEnqueueOutcomeV1,
        ReputationRuntimeError,
    > {
        let active = self.active()?;
        active.check_external_bindings()?;
        let result = active
            .runtime
            .por_journal_producer()
            .ok_or(ReputationRuntimeError::RuntimeBindingMismatch)?
            .enqueue_terminal(provider_id, outcome);
        active.check_external_bindings()?;
        result
    }
}
impl ReputationCommittedReadApiV1 for ReputationRuntimeHandleV1 {
    fn committed_read_projection(
        &self,
    ) -> Result<ReputationCommittedReadProjectionV1, ReputationRuntimeError> {
        ReputationRuntimeHandleV1::committed_read_projection(self)
    }
    fn committed_snapshot_by_id(
        &self,
        snapshot_id: [u8; 16],
    ) -> Result<Option<sorafs_manifest::ReputationSnapshotV1>, ReputationRuntimeError> {
        ReputationRuntimeHandleV1::committed_snapshot_by_id(self, snapshot_id)
    }
    fn committed_events_after(
        &self,
        sequence: u64,
    ) -> Result<Vec<sorafs_manifest::ReputationSnapshotEventV1>, ReputationRuntimeError> {
        ReputationRuntimeHandleV1::committed_events_after(self, sequence)
    }
}
impl PorTerminalReputationAdmissionV1 for ReputationRuntimeHandleV1 {
    fn activation_state(
        &self,
    ) -> Result<
        sorafs_node::reputation::runtime::PorTerminalReputationAdmissionStateV1,
        ReputationRuntimeError,
    > {
        ReputationRuntimeHandleV1::activation_state(self)
    }
    fn record_por_terminal(
        &self,
        provider_id: ProviderId,
        outcome: PorTerminalOutcomeV1,
    ) -> Result<
        sorafs_node::reputation::runtime::ReputationJournalEnqueueOutcomeV1,
        ReputationRuntimeError,
    > {
        ReputationRuntimeHandleV1::record_por_terminal(self, provider_id, outcome)
    }
}
/// Assemble and start the committed reputation runtime.
///
/// Missing, test-marked, stale, or identity/revision/policy-mismatched adapters
/// fail startup before durable state is opened or any worker is spawned.
pub(crate) fn start(
    config: &SorafsReputationRuntime,
    network_id: &NetworkId,
    trust_policy: &ReputationSnapshotTrustPolicyV1,
    dependencies: ReputationRuntimeDependenciesV1,
    shutdown_signal: ShutdownSignal,
) -> Result<(ReputationRuntimeHandleV1, Child)> {
    let poll_interval = config.poll_interval;
    let handle = assemble(config, network_id, trust_policy, dependencies)?;
    let active = handle
        .active()
        .wrap_err("access assembled committed reputation runtime")?;
    record_status_metrics(&handle);
    let status_handle = handle.clone();
    let task = tokio::task::spawn(async move {
        run_active_worker(active, status_handle, poll_interval, shutdown_signal).await;
    });
    Ok((handle, Child::new(task, OnShutdown::Wait(SHUTDOWN_WAIT))))
}
/// Nonblocking finalized-archive activation probe.
pub(crate) type ReputationRuntimeActivationProbeV1 =
    Arc<dyn Fn() -> Result<bool> + Send + Sync + 'static>;
/// Validate runtime-only identities immediately, then defer durable reputation
/// assembly until the finalized archive has its first live exact anchor.
///
/// The returned handle stays fail-closed while deferred. The supervised
/// activator revalidates every adapter and policy during final assembly; an
/// invalidated archive boundary or substituted dependency triggers daemon
/// shutdown instead of installing a partial runtime.
pub(crate) fn start_deferred(
    config: &SorafsReputationRuntime,
    network_id: &NetworkId,
    trust_policy: &ReputationSnapshotTrustPolicyV1,
    dependencies: ReputationRuntimeDependenciesV1,
    activation_probe: ReputationRuntimeActivationProbeV1,
    shutdown_signal: ShutdownSignal,
) -> Result<(ReputationRuntimeHandleV1, Child)> {
    validate_actual_config(config)?;
    let policies =
        build_and_qualify_runtime_policies(config, network_id, trust_policy, &dependencies)?;
    validate_retention_control(config, &dependencies)?;
    revalidate_before_durable_state(&policies, &dependencies)?;
    let poll_interval = config.poll_interval;
    let config = config.clone();
    let network_id = *network_id;
    let trust_policy = trust_policy.clone();
    let handle = ReputationRuntimeHandleV1::deferred();
    record_status_metrics(&handle);
    let activation_handle = handle.clone();
    let mut dependencies = Some(dependencies);
    let task = tokio::task::spawn(async move {
        let mut interval = tokio::time::interval(poll_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match activation_probe() {
                        Ok(false) => {
                            iroha_logger::debug!(
                                "committed SoraFS reputation runtime is awaiting finalized archive activation"
                            );
                            continue;
                        }
                        Err(error) => {
                            iroha_logger::error!(
                                ?error,
                                "committed SoraFS reputation archive activation failed closed"
                            );
                            shutdown_signal.send();
                            return;
                        }
                        Ok(true) => {}
                    }
                    let Some(dependencies) = dependencies.take() else {
                        iroha_logger::error!(
                            "deferred committed SoraFS reputation dependencies were already consumed"
                        );
                        shutdown_signal.send();
                        return;
                    };
                    let active = match assemble_active(
                        &config,
                        &network_id,
                        &trust_policy,
                        dependencies,
                    ) {
                        Ok(active) => active,
                        Err(error) => {
                            iroha_logger::error!(
                                ?error,
                                "deferred committed SoraFS reputation runtime assembly failed"
                            );
                            shutdown_signal.send();
                            return;
                        }
                    };
                    if let Err(error) = activation_handle.install_active(active.clone()) {
                        iroha_logger::error!(
                            %error,
                            "deferred committed SoraFS reputation runtime activation was duplicated"
                        );
                        shutdown_signal.send();
                        return;
                    }
                    record_status_metrics(&activation_handle);
                    iroha_logger::info!(
                        "activated committed SoraFS reputation runtime after finalized archive capture"
                    );
                    run_active_worker(
                        active,
                        activation_handle,
                        poll_interval,
                        shutdown_signal.clone(),
                    )
                    .await;
                    return;
                }
                () = shutdown_signal.receive() => return,
                else => return,
            }
        }
    });
    Ok((handle, Child::new(task, OnShutdown::Wait(SHUTDOWN_WAIT))))
}
async fn run_active_worker(
    worker: ActiveReputationRuntimeV1,
    status_handle: ReputationRuntimeHandleV1,
    poll_interval: Duration,
    shutdown_signal: ShutdownSignal,
) {
    let _shutdown_guard = ReputationDaemonShutdownGuard {
        liveness: Arc::clone(&worker.liveness),
    };
    let mut interval = tokio::time::interval(poll_interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    'worker: loop {
        tokio::select! {
            _ = interval.tick() => {
                let runtime = Arc::clone(&worker.runtime);
                let retention_control = worker.retention_control.clone();
                worker.liveness.begin_tick();
                let mut reconciliation =
                    crate::panic_recovery::spawn_blocking_recoverable(move || {
                        let outcome = runtime.reconcile_once().map_err(eyre::Report::new)?;
                        reconcile_retention_control(retention_control.as_deref())?;
                        Ok(outcome)
                    });
                let timely_result = tokio::select! {
                    result = &mut reconciliation => {
                        Some(crate::panic_recovery::recover_joined(result))
                    },
                    () = tokio::time::sleep(worker.liveness.tick_timeout) => None,
                    () = shutdown_signal.receive() => {
                        worker.liveness.mark_shutdown();
                        reconciliation.abort();
                        record_status_metrics(&status_handle);
                        iroha_logger::debug!(
                            "committed SoraFS reputation runtime shut down during reconciliation"
                        );
                        break 'worker;
                    }
                };
                if let Some(result) = timely_result {
                    record_reputation_tick_result(&worker, result);
                    record_status_metrics(&status_handle);
                    continue;
                }
                worker.liveness.mark_timeout();
                worker
                    .counters
                    .timed_out
                    .fetch_add(1, Ordering::Relaxed);
                record_tick_metric("failure");
                record_status_metrics(&status_handle);
                iroha_logger::error!(
                    timeout_ms = u64::try_from(worker.liveness.tick_timeout.as_millis())
                        .unwrap_or(u64::MAX),
                    "committed SoraFS reputation reconciliation exceeded its deadline"
                );
                let late_result = tokio::select! {
                    result = &mut reconciliation => {
                        Some(crate::panic_recovery::recover_joined(result))
                    },
                    () = shutdown_signal.receive() => {
                        worker.liveness.mark_shutdown();
                        reconciliation.abort();
                        record_status_metrics(&status_handle);
                        iroha_logger::warn!(
                            "committed SoraFS reputation runtime shut down with a timed-out blocking reconciliation still outstanding"
                        );
                        break 'worker;
                    }
                };
                worker.liveness.mark_late_tick_finished();
                if let Some(Err(_panic)) = late_result {
                    worker
                        .counters
                        .panicked
                        .fetch_add(1, Ordering::Relaxed);
                    iroha_logger::error!(
                        "timed-out SoraFS reputation reconciliation later failed"
                    );
                } else {
                    iroha_logger::warn!(
                        "timed-out SoraFS reputation reconciliation finished late; its result was not used for readiness"
                    );
                }
                record_status_metrics(&status_handle);
            }
            () = shutdown_signal.receive() => {
                worker.liveness.mark_shutdown();
                record_status_metrics(&status_handle);
                iroha_logger::debug!(
                    "committed SoraFS reputation runtime is being shut down"
                );
                break;
            }
            else => break,
        }
    }
}
fn reconcile_retention_control(
    retention_control: Option<&dyn ReputationFinalizedArchiveRetentionControlV1>,
) -> Result<()> {
    if let Some(retention_control) = retention_control {
        let _ = retention_control
            .reconcile_once()
            .map_err(eyre::Report::new)?;
    }
    Ok(())
}
fn record_reputation_tick_result(
    worker: &ActiveReputationRuntimeV1,
    result: ReputationJoinedReconciliationResult,
) {
    match result {
        Ok(Ok(_)) => {
            if let Err(error) = worker.liveness.finish_tick(true) {
                worker.liveness.mark_timeout();
                iroha_logger::error!(
                    error = %error,
                    "committed SoraFS reputation liveness state is poisoned"
                );
                return;
            }
            worker.counters.successful.fetch_add(1, Ordering::Relaxed);
            record_tick_metric("success");
        }
        Ok(Err(error)) => {
            if let Err(liveness_error) = worker.liveness.finish_tick(false) {
                worker.liveness.mark_timeout();
                iroha_logger::error!(
                    error = %liveness_error,
                    "committed SoraFS reputation liveness state is poisoned"
                );
            }
            worker.counters.failed.fetch_add(1, Ordering::Relaxed);
            record_tick_metric("failure");
            iroha_logger::warn!(
                error = %error,
                "committed SoraFS reputation reconciliation failed"
            );
        }
        Err(_panic) => {
            if let Err(liveness_error) = worker.liveness.finish_tick(false) {
                worker.liveness.mark_timeout();
                iroha_logger::error!(
                    error = %liveness_error,
                    "committed SoraFS reputation liveness state is poisoned"
                );
            }
            worker.counters.panicked.fetch_add(1, Ordering::Relaxed);
            record_tick_metric("panic");
            iroha_logger::error!("committed SoraFS reputation worker task failed");
        }
    }
}
struct ReputationRuntimePoliciesV1 {
    ingest: ReputationIngestPolicyV1,
    query: ReputationFinalizedQueryPolicyV1,
    journal_checkpoint_sealing: ReputationJournalCheckpointSealingPolicyV1,
    journal_delivery: ReputationJournalDeliveryPolicyV1,
    publication: ReputationPublicationPolicyV1,
}
fn assemble(
    config: &SorafsReputationRuntime,
    network_id: &NetworkId,
    trust_policy: &ReputationSnapshotTrustPolicyV1,
    dependencies: ReputationRuntimeDependenciesV1,
) -> Result<ReputationRuntimeHandleV1> {
    assemble_active(config, network_id, trust_policy, dependencies)
        .map(ReputationRuntimeHandleV1::from_active)
}
fn assemble_active(
    config: &SorafsReputationRuntime,
    network_id: &NetworkId,
    trust_policy: &ReputationSnapshotTrustPolicyV1,
    dependencies: ReputationRuntimeDependenciesV1,
) -> Result<ActiveReputationRuntimeV1> {
    validate_actual_config(config)?;
    let poll_interval = config.poll_interval;
    let policies =
        build_and_qualify_runtime_policies(config, network_id, trust_policy, &dependencies)?;
    validate_retention_control(config, &dependencies)?;
    let bootstrap_delivery_view = read_bootstrap_delivery_view(
        network_id,
        &policies.query,
        &policies.journal_delivery,
        &dependencies,
    )?;
    revalidate_before_durable_state(&policies, &dependencies)?;
    let ReputationRuntimePoliciesV1 {
        ingest,
        query,
        journal_checkpoint_sealing,
        journal_delivery,
        publication,
    } = policies;
    let projector = Arc::new(
        ReputationIngestService::open(&config.state_dir, ingest.clone())
            .wrap_err("open committed reputation projector")?,
    );
    let finalized = ReputationCommittedProjectorRuntimeV1::new(
        Arc::clone(&projector),
        &ingest,
        query,
        Arc::clone(&dependencies.finalized_query),
    )
    .wrap_err("bind committed reputation finalized-query runtime")?;
    let producer_policy = ReputationJournalProducerPolicyV1::strict_v1(
        *network_id,
        bootstrap_delivery_view.authority_policy.policy.clone(),
    )
    .wrap_err("construct reputation journal producer policy")?;
    let journal_outbox =
        ReputationJournalProducerOutboxV1::open_sealed_with_authority_policy_history(
            &config.state_dir,
            producer_policy,
            &bootstrap_delivery_view.authority_policy_history,
            bootstrap_delivery_view.journal_page.finalized_cursor,
            journal_checkpoint_sealing,
            dependencies.journal_checkpoint_provider,
        )
        .wrap_err("open and recover durable reputation journal producer outbox")?;
    let journal_outbox = Arc::new(journal_outbox);
    let journal_delivery = ReputationJournalDeliveryWorkerV1::new(
        journal_outbox,
        journal_delivery,
        Arc::clone(&dependencies.finalized_query),
        Arc::clone(&dependencies.journal_transaction_submitter),
    )
    .wrap_err("bind reputation journal delivery worker")?;
    let publication = ReputationPublicationReconcilerV1::open(
        &config.state_dir,
        Arc::clone(&projector),
        trust_policy.clone(),
        publication,
        dependencies.threshold_signer,
        dependencies.governance_dag,
    )
    .wrap_err("open committed reputation publication reconciler")?;
    let runtime = Arc::new(
        ReputationRuntimeSupervisorV1::new(projector, finalized, publication)
            .and_then(|runtime| runtime.with_journal_delivery(journal_delivery))
            .wrap_err("assemble committed reputation runtime")?,
    );
    Ok(ActiveReputationRuntimeV1 {
        runtime,
        retention_control: dependencies.retention_control,
        counters: Arc::new(ReputationDaemonCounters::default()),
        liveness: Arc::new(ReputationDaemonLiveness::new(poll_interval)),
    })
}
fn validate_retention_control(
    config: &SorafsReputationRuntime,
    dependencies: &ReputationRuntimeDependenciesV1,
) -> Result<()> {
    match (
        config.finalized_archive_retention_authority.is_some(),
        dependencies.retention_control.as_ref(),
    ) {
        (true, None) => {
            bail!(
                "configured finalized reputation archive retention requires its explicit committed-request control"
            )
        }
        (false, Some(_)) => {
            bail!(
                "manual finalized reputation archive mode rejects an unexpected retention control"
            )
        }
        (false, None) => Ok(()),
        (true, Some(control)) => control
            .revalidate()
            .map_err(eyre::Report::new)
            .wrap_err("revalidate explicit finalized reputation archive retention control"),
    }
}
fn build_and_qualify_runtime_policies(
    config: &SorafsReputationRuntime,
    network_id: &NetworkId,
    trust_policy: &ReputationSnapshotTrustPolicyV1,
    dependencies: &ReputationRuntimeDependenciesV1,
) -> Result<ReputationRuntimePoliciesV1> {
    let ingest = build_reputation_ingest_policy(config, network_id, trust_policy)?;
    let query = build_reputation_finalized_query_policy(config, &ingest)?;
    let journal_checkpoint_sealing = ReputationJournalCheckpointSealingPolicyV1::try_new(
        config.journal_checkpoint_provider_handle.clone(),
        config.journal_checkpoint_provider_revision,
        config.journal_checkpoint_provider_policy_digest,
    )
    .wrap_err("construct reputation journal-checkpoint sealing policy")?;
    let journal_delivery_policy = ReputationJournalDeliveryPolicyV1::strict_v1(
        *network_id,
        config.finalized_query_handle.clone(),
        query.query_qualification(),
        config.journal_transaction_submitter_handle.clone(),
    )
    .wrap_err("construct reputation journal delivery policy")?;
    let publication_policy = ReputationPublicationPolicyV1::try_new(
        trust_policy,
        config.threshold_signer_handle.clone(),
        config.governance_dag_handle.clone(),
        config.governance_publisher_peer_id.clone(),
        config.governance_publisher_public_key,
        config.publication_checkpoint_max_bytes.0,
    )
    .wrap_err("construct committed reputation publication policy")?;
    let journal_submitter_qualification = ReputationRuntimeProviderQualificationV1::new(
        REPUTATION_RUNTIME_PROVIDER_QUALIFICATION_REVISION_V1,
        reputation_journal_submitter_policy_digest_v1(
            network_id,
            &config.journal_transaction_submitter_handle,
        )
        .wrap_err("derive reputation journal transaction-submitter qualification")?,
    );
    validate_configured_runtime_provider_qualifications(
        config,
        journal_submitter_qualification,
        publication_policy.threshold_signer_qualification(),
        publication_policy.governance_dag_qualification(),
    )?;
    validate_dependency_handle(
        "finalized query",
        &config.finalized_query_handle,
        dependencies.finalized_query.handle(),
    )?;
    validate_dependency_handle(
        "journal checkpoint",
        &config.journal_checkpoint_provider_handle,
        dependencies.journal_checkpoint_provider.handle(),
    )?;
    validate_dependency_handle(
        "journal transaction submitter",
        &config.journal_transaction_submitter_handle,
        dependencies.journal_transaction_submitter.handle(),
    )?;
    validate_dependency_handle(
        "threshold signer",
        &config.threshold_signer_handle,
        dependencies.threshold_signer.handle(),
    )?;
    validate_dependency_handle(
        "Governance DAG",
        &config.governance_dag_handle,
        dependencies.governance_dag.handle(),
    )?;
    query
        .revalidate_provider(dependencies.finalized_query.as_ref())
        .wrap_err("committed reputation finalized-query adapter is not qualified")?;
    journal_checkpoint_sealing
        .revalidate_provider(dependencies.journal_checkpoint_provider.as_ref())
        .wrap_err("reputation journal-checkpoint provider is not qualified")?;
    journal_delivery_policy
        .revalidate_query_provider(dependencies.finalized_query.as_ref())
        .wrap_err("reputation journal finalized-query adapter is not qualified")?;
    journal_delivery_policy
        .revalidate_submitter_provider(dependencies.journal_transaction_submitter.as_ref())
        .wrap_err("reputation journal transaction submitter is not qualified")?;
    publication_policy
        .revalidate_threshold_signer(dependencies.threshold_signer.as_ref())
        .wrap_err("committed reputation threshold-signer adapter is not qualified")?;
    publication_policy
        .revalidate_governance_dag(dependencies.governance_dag.as_ref())
        .wrap_err("committed reputation Governance DAG adapter is not qualified")?;
    Ok(ReputationRuntimePoliciesV1 {
        ingest,
        query,
        journal_checkpoint_sealing,
        journal_delivery: journal_delivery_policy,
        publication: publication_policy,
    })
}
fn validate_configured_runtime_provider_qualifications(
    config: &SorafsReputationRuntime,
    journal_submitter: ReputationRuntimeProviderQualificationV1,
    threshold_signer: ReputationRuntimeProviderQualificationV1,
    governance_dag: ReputationRuntimeProviderQualificationV1,
) -> Result<()> {
    if config.journal_transaction_submitter_revision
        != REPUTATION_RUNTIME_PROVIDER_QUALIFICATION_REVISION_V1
    {
        bail!("configured reputation journal transaction-submitter revision is not V1");
    }
    if config.journal_transaction_submitter_policy_digest != journal_submitter.policy_digest() {
        bail!(
            "configured reputation journal transaction-submitter policy digest does not match the derived V1 policy"
        );
    }
    if config.threshold_signer_revision != REPUTATION_RUNTIME_PROVIDER_QUALIFICATION_REVISION_V1 {
        bail!("configured reputation threshold-signer revision is not V1");
    }
    if config.threshold_signer_policy_digest != threshold_signer.policy_digest() {
        bail!(
            "configured reputation threshold-signer policy digest does not match the derived V1 policy"
        );
    }
    if config.governance_dag_revision != REPUTATION_RUNTIME_PROVIDER_QUALIFICATION_REVISION_V1 {
        bail!("configured reputation Governance DAG revision is not V1");
    }
    if config.governance_dag_policy_digest != governance_dag.policy_digest() {
        bail!(
            "configured reputation Governance DAG policy digest does not match the derived V1 policy"
        );
    }
    Ok(())
}
fn read_bootstrap_delivery_view(
    network_id: &NetworkId,
    query_policy: &ReputationFinalizedQueryPolicyV1,
    journal_delivery_policy: &ReputationJournalDeliveryPolicyV1,
    dependencies: &ReputationRuntimeDependenciesV1,
) -> Result<ReputationJournalDeliveryFinalizedViewV1> {
    query_policy
        .revalidate_provider(dependencies.finalized_query.as_ref())
        .wrap_err("revalidate exact finalized reputation query before bootstrap read")?;
    let bootstrap_delivery_view_result = dependencies
        .finalized_query
        .reputation_journal_delivery_view(
            network_id,
            u64::MAX,
            FindSorafsReputationJournalAuthorityPolicy,
            None,
            1,
        );
    query_policy
        .revalidate_provider(dependencies.finalized_query.as_ref())
        .wrap_err("revalidate exact finalized reputation query after bootstrap read")?;
    let bootstrap_delivery_view = bootstrap_delivery_view_result
        .wrap_err("read exact finalized reputation journal authority policy")?;
    bootstrap_delivery_view
        .validate_for_request(network_id, None, 1, u64::MAX)
        .wrap_err("validate exact finalized reputation journal bootstrap view")?;
    let authority = &bootstrap_delivery_view
        .authority_policy
        .policy
        .por_recorder_authority;
    journal_delivery_policy
        .revalidate_submitter_provider(dependencies.journal_transaction_submitter.as_ref())
        .wrap_err("revalidate reputation journal submitter before authority check")?;
    let supports_authority = dependencies
        .journal_transaction_submitter
        .supports_authority(authority);
    journal_delivery_policy
        .revalidate_submitter_provider(dependencies.journal_transaction_submitter.as_ref())
        .wrap_err("revalidate reputation journal submitter after authority check")?;
    if !supports_authority {
        bail!("reputation journal submitter does not own the governed PoR recorder identity");
    }
    Ok(bootstrap_delivery_view)
}
fn revalidate_before_durable_state(
    policies: &ReputationRuntimePoliciesV1,
    dependencies: &ReputationRuntimeDependenciesV1,
) -> Result<()> {
    policies
        .query
        .revalidate_provider(dependencies.finalized_query.as_ref())
        .wrap_err("finalized-query qualification changed before durable state")?;
    policies
        .journal_checkpoint_sealing
        .revalidate_provider(dependencies.journal_checkpoint_provider.as_ref())
        .wrap_err("journal-checkpoint provider qualification changed before durable state")?;
    policies
        .journal_delivery
        .revalidate_submitter_provider(dependencies.journal_transaction_submitter.as_ref())
        .wrap_err("journal-submitter qualification changed before durable state")?;
    policies
        .publication
        .revalidate_threshold_signer(dependencies.threshold_signer.as_ref())
        .wrap_err("threshold-signer qualification changed before durable state")?;
    policies
        .publication
        .revalidate_governance_dag(dependencies.governance_dag.as_ref())
        .wrap_err("Governance DAG qualification changed before durable state")?;
    if let Some(retention_control) = &dependencies.retention_control {
        retention_control
            .revalidate()
            .map_err(eyre::Report::new)
            .wrap_err("retention-control qualification changed before durable state")?;
    }
    Ok(())
}
fn build_reputation_ingest_policy(
    config: &SorafsReputationRuntime,
    network_id: &NetworkId,
    trust_policy: &ReputationSnapshotTrustPolicyV1,
) -> Result<ReputationIngestPolicyV1> {
    let trust_policy_digest = trust_policy
        .canonical_digest()
        .wrap_err("derive configured reputation trust-policy digest")?;
    let weights = ReputationWeightsV1 {
        version: REPUTATION_WEIGHTS_VERSION_V1,
        por_success_bps: config.por_success_bps,
        pdp_success_bps: config.pdp_success_bps,
        potr_success_bps: config.potr_success_bps,
        latency_bps: config.latency_bps,
        dispute_bps: config.dispute_bps,
        token_violation_bps: config.token_violation_bps,
        repair_breach_bps: config.repair_breach_bps,
    };
    weights
        .validate()
        .wrap_err("validate configured reputation weights")?;
    let mut ingest_policy = ReputationIngestPolicyV1::strict_v1(
        *network_id,
        config.window_start_height,
        config.window_end_height,
        trust_policy_digest,
        weights,
    );
    ingest_policy.max_providers = config.max_providers;
    ingest_policy.max_pending_events = config.max_pending_events;
    ingest_policy.max_replay_receipts = config.max_replay_receipts;
    ingest_policy.max_pages_per_batch = config.max_pages_per_batch;
    ingest_policy.max_material_delivery_failures = config.max_material_delivery_failures;
    ingest_policy.checkpoint_max_bytes = config.ingest_checkpoint_max_bytes.0;
    ingest_policy
        .validate()
        .wrap_err("validate configured committed reputation ingest policy")?;
    Ok(ingest_policy)
}
fn build_reputation_finalized_query_policy(
    config: &SorafsReputationRuntime,
    ingest_policy: &ReputationIngestPolicyV1,
) -> Result<ReputationFinalizedQueryPolicyV1> {
    ReputationFinalizedQueryPolicyV1::try_new(
        ingest_policy,
        config.finalized_query_handle.clone(),
        config.page_items,
        config.max_pages_per_batch,
    )
    .wrap_err("construct committed reputation finalized-query policy")
}
/// Derive the exact provider qualification for the daemon-owned archive
/// adapter from the same committed ingest policy used by worker assembly.
pub(crate) fn finalized_query_qualification_v1(
    config: &SorafsReputationRuntime,
    network_id: &NetworkId,
    trust_policy: &ReputationSnapshotTrustPolicyV1,
) -> Result<ReputationRuntimeProviderQualificationV1> {
    validate_actual_config(config)?;
    let ingest_policy = build_reputation_ingest_policy(config, network_id, trust_policy)?;
    Ok(build_reputation_finalized_query_policy(config, &ingest_policy)?.query_qualification())
}
fn validate_actual_config(config: &SorafsReputationRuntime) -> Result<()> {
    if !config.state_dir.is_absolute()
        || config.state_dir.file_name().is_none()
        || config.state_dir.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
        || config.window_start_height == 0
        || config.window_end_height < config.window_start_height
        || config.journal_checkpoint_provider_revision == 0
        || config.journal_checkpoint_provider_policy_digest == [0; 32]
        || config.journal_transaction_submitter_revision == 0
        || config.journal_transaction_submitter_policy_digest == [0; 32]
        || config.threshold_signer_revision == 0
        || config.threshold_signer_policy_digest == [0; 32]
        || config.governance_dag_revision == 0
        || config.governance_dag_policy_digest == [0; 32]
        || config.poll_interval < Duration::from_millis(100)
        || config.poll_interval > Duration::from_secs(60)
    {
        bail!("committed reputation runtime configuration is invalid");
    }
    for handle in [
        &config.finalized_query_handle,
        &config.journal_checkpoint_provider_handle,
        &config.journal_transaction_submitter_handle,
        &config.threshold_signer_handle,
        &config.governance_dag_handle,
    ] {
        if !is_production_runtime_handle(handle) {
            bail!("committed reputation runtime dependency handle is not production-safe");
        }
    }
    Ok(())
}
fn validate_dependency_handle(label: &str, expected: &str, actual: &str) -> Result<()> {
    if !is_production_runtime_handle(actual) || actual != expected {
        bail!("{label} adapter identity does not match committed reputation configuration");
    }
    Ok(())
}
#[cfg(feature = "telemetry")]
fn record_status_metrics(handle: &ReputationRuntimeHandleV1) {
    let Some(metrics) = iroha_telemetry::metrics::global() else {
        return;
    };
    match handle.status() {
        Ok(status) => metrics.record_sorafs_reputation_runtime_status(
            iroha_telemetry::metrics::SorafsReputationRuntimeMetricSnapshot {
                runtime: iroha_telemetry::metrics::SorafsRuntimeHealthMetricSnapshot {
                    live: status.runtime.finalized.live,
                    ready: status.ready,
                    external_dependencies_ready: status.liveness.external_dependencies_healthy,
                },
                publication: iroha_telemetry::metrics::SorafsReputationPublicationMetricSnapshot {
                    journal_transaction_submitter_ready: status.journal_transaction_submitter_ready,
                    material_acknowledged: status.runtime.material_acknowledged,
                },
                latest_finalized_height: status
                    .ingest
                    .latest_finalized
                    .map_or(0, |identity| identity.height),
                consecutive_failures: status.runtime.finalized.consecutive_failures,
                provider_count: status.ingest.providers,
            },
        ),
        Err(_) => metrics.record_sorafs_reputation_runtime_status(
            iroha_telemetry::metrics::SorafsReputationRuntimeMetricSnapshot {
                runtime: iroha_telemetry::metrics::SorafsRuntimeHealthMetricSnapshot {
                    live: false,
                    ready: false,
                    external_dependencies_ready: false,
                },
                publication: iroha_telemetry::metrics::SorafsReputationPublicationMetricSnapshot {
                    journal_transaction_submitter_ready: false,
                    material_acknowledged: false,
                },
                latest_finalized_height: 0,
                consecutive_failures: 1,
                provider_count: 0,
            },
        ),
    }
}
#[cfg(not(feature = "telemetry"))]
fn record_status_metrics(_handle: &ReputationRuntimeHandleV1) {}
#[cfg(feature = "telemetry")]
fn record_tick_metric(result: &str) {
    if let Some(metrics) = iroha_telemetry::metrics::global() {
        metrics.inc_sorafs_reputation_runtime_tick(result);
    }
}
#[cfg(not(feature = "telemetry"))]
fn record_tick_metric(_result: &str) {}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_config::base::util::Bytes;
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
    use iroha_data_model::sorafs::{
        reputation::ReputationJournalPolicyOriginV1,
        stream_token_gateway::native::StreamTokenGatewayExecutionV1,
    };
    use iroha_data_model::{
        account::AccountId,
        query::sorafs::prelude::FindSorafsReputationJournalEventBySourceId,
        sorafs::{
            capacity::ProviderId,
            moderation_ledger::{RepairFinalizedEventCursorV1, RepairFinalizedEventPageV1},
            orderbook::{OrderbookFinalizedEventCursorV1, OrderbookFinalizedEventPageV1},
            proof_ledger::{ProofOutcomeFinalizedEventCursorV1, ProofOutcomeFinalizedEventPageV1},
            reputation::{
                PorTerminalOutcomeV1, PorTerminalStatusV1,
                REPUTATION_JOURNAL_AUTHORITY_POLICY_VERSION_V1,
                ReputationJournalAuthorityPolicyRecordV1, ReputationJournalAuthorityPolicyV1,
                ReputationJournalFinalizedCursorV1, ReputationJournalFinalizedEventCursorV1,
                ReputationJournalFinalizedEventPageV1,
            },
            reserve::{
                ReserveFinalizedEventCursorV1, ReserveFinalizedEventPageV1,
                ReserveProviderAccountPageV1,
            },
        },
    };
    use sorafs_manifest::{
        SignedReputationSnapshotV1,
        reputation::signed::{
            REPUTATION_SNAPSHOT_TRUST_POLICY_VERSION_V1, REPUTATION_TRUSTED_SIGNER_VERSION_V1,
            ReputationTrustedSignerV1,
        },
    };
    use sorafs_node::reputation::runtime::{
        REPUTATION_RUNTIME_PROVIDER_QUALIFICATION_REVISION_V1, ReputationExternalFailureV1,
        ReputationFinalizedAnchorV1, ReputationGovernanceDagPublicationRequestV1,
        ReputationGovernanceDagReadbackV1, ReputationJournalDeliveryFinalizedViewV1,
        ReputationJournalSourceFinalizedViewV1, ReputationJournalTransactionRequestV1,
        ReputationJournalTransactionSubmitOutcomeV1, ReputationRuntimeProviderV1,
        ReputationThresholdSigningRequestV1, reputation_governance_dag_policy_digest_v1,
        reputation_journal_submitter_policy_digest_v1,
    };
    use std::path::PathBuf;
    use tempfile::TempDir;
    fn network_id(label: &str) -> NetworkId {
        NetworkId::from_genesis_hash(
            HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(Hash::new(
                label.as_bytes(),
            )),
        )
    }
    #[derive(Debug)]
    struct CountingRetentionControl {
        reconciliations: AtomicU64,
        ready: AtomicBool,
        external_calls: Option<Arc<ExternalProviderCallCounters>>,
    }
    impl CountingRetentionControl {
        fn new(ready: bool) -> Self {
            Self {
                reconciliations: AtomicU64::new(0),
                ready: AtomicBool::new(ready),
                external_calls: None,
            }
        }
        fn with_external_calls(
            ready: bool,
            external_calls: Arc<ExternalProviderCallCounters>,
        ) -> Self {
            Self {
                reconciliations: AtomicU64::new(0),
                ready: AtomicBool::new(ready),
                external_calls: Some(external_calls),
            }
        }
    }
    impl ReputationFinalizedArchiveRetentionControlV1 for CountingRetentionControl {
        fn revalidate(
            &self,
        ) -> std::result::Result<
            (),
            crate::sorafs_reputation_finalized_query::ReputationFinalizedArchiveRetentionControlErrorV1,
        >{
            ExternalProviderCallCounters::record_readiness(&self.external_calls);
            if self.ready.load(Ordering::Acquire) {
                Ok(())
            } else {
                Err(
                    crate::sorafs_reputation_finalized_query::ReputationFinalizedArchiveRetentionControlErrorV1::Boundary {
                        reason: "test retention authority is stale",
                    },
                )
            }
        }
        fn reconcile_once(
            &self,
        ) -> std::result::Result<
            crate::sorafs_reputation_finalized_query::ReputationFinalizedArchiveRetentionControlOutcomeV1,
            crate::sorafs_reputation_finalized_query::ReputationFinalizedArchiveRetentionControlErrorV1,
        >{
            self.revalidate()?;
            ExternalProviderCallCounters::record_operation(&self.external_calls);
            self.reconciliations.fetch_add(1, Ordering::AcqRel);
            Ok(
                crate::sorafs_reputation_finalized_query::ReputationFinalizedArchiveRetentionControlOutcomeV1::NoRequest,
            )
        }
    }
    #[derive(Debug)]
    struct DriftingRetentionControl {
        drift_armed: AtomicBool,
        remaining_good_revalidations: AtomicU64,
    }
    impl DriftingRetentionControl {
        fn new() -> Self {
            Self {
                drift_armed: AtomicBool::new(false),
                remaining_good_revalidations: AtomicU64::new(0),
            }
        }
        fn arm_after(&self, good_revalidations: u64) {
            self.remaining_good_revalidations
                .store(good_revalidations, Ordering::SeqCst);
            self.drift_armed.store(true, Ordering::SeqCst);
        }
        fn restore(&self) {
            self.drift_armed.store(false, Ordering::SeqCst);
        }
    }
    impl ReputationFinalizedArchiveRetentionControlV1 for DriftingRetentionControl {
        fn revalidate(
            &self,
        ) -> std::result::Result<
            (),
            crate::sorafs_reputation_finalized_query::ReputationFinalizedArchiveRetentionControlErrorV1,
        >{
            if self.drift_armed.load(Ordering::SeqCst)
                && self
                    .remaining_good_revalidations
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                        remaining.checked_sub(1)
                    })
                    .is_err()
            {
                return Err(
                    crate::sorafs_reputation_finalized_query::ReputationFinalizedArchiveRetentionControlErrorV1::Boundary {
                        reason: "test retention authority changed",
                    },
                );
            }
            Ok(())
        }
        fn reconcile_once(
            &self,
        ) -> std::result::Result<
            crate::sorafs_reputation_finalized_query::ReputationFinalizedArchiveRetentionControlOutcomeV1,
            crate::sorafs_reputation_finalized_query::ReputationFinalizedArchiveRetentionControlErrorV1,
        >{
            self.revalidate()?;
            Ok(
                crate::sorafs_reputation_finalized_query::ReputationFinalizedArchiveRetentionControlOutcomeV1::NoRequest,
            )
        }
    }
    #[derive(Debug, Default)]
    struct ExternalProviderCallCounters {
        handles: AtomicU64,
        qualifications: AtomicU64,
        readiness: AtomicU64,
        operations: AtomicU64,
    }
    impl ExternalProviderCallCounters {
        fn assert_zero(&self, case: &str) {
            assert_eq!(
                [
                    self.handles.load(Ordering::Acquire),
                    self.qualifications.load(Ordering::Acquire),
                    self.readiness.load(Ordering::Acquire),
                    self.operations.load(Ordering::Acquire),
                ],
                [0; 4],
                "{case}: configured qualification rejection must precede every external provider call"
            );
        }
        #[expect(
            clippy::ref_option,
            reason = "test providers share the same optional counter slot"
        )]
        fn record_handle(calls: &Option<Arc<Self>>) {
            if let Some(calls) = calls {
                calls.handles.fetch_add(1, Ordering::AcqRel);
            }
        }
        #[expect(
            clippy::ref_option,
            reason = "test providers share the same optional counter slot"
        )]
        fn record_qualification(calls: &Option<Arc<Self>>) {
            if let Some(calls) = calls {
                calls.qualifications.fetch_add(1, Ordering::AcqRel);
            }
        }
        #[expect(
            clippy::ref_option,
            reason = "test providers share the same optional counter slot"
        )]
        fn record_readiness(calls: &Option<Arc<Self>>) {
            if let Some(calls) = calls {
                calls.readiness.fetch_add(1, Ordering::AcqRel);
            }
        }
        #[expect(
            clippy::ref_option,
            reason = "test providers share the same optional counter slot"
        )]
        fn record_operation(calls: &Option<Arc<Self>>) {
            if let Some(calls) = calls {
                calls.operations.fetch_add(1, Ordering::AcqRel);
            }
        }
    }
    #[derive(Debug)]
    struct UnavailableQuery {
        handle: String,
        ready: bool,
        qualification: ReputationRuntimeProviderQualificationV1,
        malformed_bootstrap_continuation: bool,
        external_calls: Option<Arc<ExternalProviderCallCounters>>,
    }
    impl ReputationRuntimeProviderV1 for UnavailableQuery {
        fn handle(&self) -> &str {
            ExternalProviderCallCounters::record_handle(&self.external_calls);
            &self.handle
        }
        fn qualification(
            &self,
        ) -> std::result::Result<
            ReputationRuntimeProviderQualificationV1,
            ReputationExternalFailureV1,
        > {
            ExternalProviderCallCounters::record_qualification(&self.external_calls);
            if self.ready {
                Ok(self.qualification)
            } else {
                Err(ReputationExternalFailureV1::try_new([0x91; 32])
                    .expect("non-zero readiness failure receipt"))
            }
        }
    }
    impl ReputationFinalizedQueryV1 for UnavailableQuery {
        fn finalized_at_or_before(
            &self,
            _network_id: &NetworkId,
            _maximum_height: u64,
        ) -> Result<ReputationFinalizedAnchorV1, ReputationExternalFailureV1> {
            ExternalProviderCallCounters::record_operation(&self.external_calls);
            unreachable!("assembly must not query external state")
        }
        fn reputation_journal_delivery_view(
            &self,
            network_id: &NetworkId,
            _maximum_height: u64,
            _policy_query: FindSorafsReputationJournalAuthorityPolicy,
            _after: Option<ReputationJournalFinalizedEventCursorV1>,
            _limit: u32,
        ) -> Result<ReputationJournalDeliveryFinalizedViewV1, ReputationExternalFailureV1> {
            ExternalProviderCallCounters::record_operation(&self.external_calls);
            let anchor = ReputationFinalizedAnchorV1 {
                network_id: *network_id,
                identity: sorafs_node::reputation::ReputationFinalizedIdentityV1 {
                    height: 2,
                    block_hash: [0x81; 32],
                },
                finalized_at_unix_ms: 1_800_000_000_000,
            };
            let policy = ReputationJournalAuthorityPolicyV1 {
                version: REPUTATION_JOURNAL_AUTHORITY_POLICY_VERSION_V1,
                revision: 1,
                predecessor_policy_digest: None,
                por_recorder_authority: account(1),
                dispute_recorder_authority: account(2),
                token_recorder_authority: account(3),
                stream_token_delivery: iroha_data_model::sorafs::reputation::stream_token_delivery::StreamTokenReputationDeliveryTemplateV1::default(),
                max_source_age_ms: 86_400_000,
            };
            let authority_policy = ReputationJournalAuthorityPolicyRecordV1::try_new(
                policy,
                account(4),
                anchor.finalized_at_unix_ms,
                ReputationJournalPolicyOriginV1::Network(StreamTokenGatewayExecutionV1 {
                    height: 2,
                    transaction_hash: [0x61; 32],
                    entry_index: 0,
                    instruction_index: 0,
                    recorded_at_unix_ms: anchor.finalized_at_unix_ms,
                    authority: account(4),
                }),
            )
            .expect("authority policy record");
            let mut view = ReputationJournalDeliveryFinalizedViewV1 {
                authority_policy_history: vec![authority_policy.clone()],
                authority_policy,
                journal_page: ReputationJournalFinalizedEventPageV1 {
                    finalized_cursor: ReputationJournalFinalizedCursorV1 {
                        height: anchor.identity.height,
                        block_hash: anchor.identity.block_hash,
                        finalized_at_unix_ms: anchor.finalized_at_unix_ms,
                    },
                    events: Vec::new(),
                    has_more: false,
                    next_after: None,
                },
                anchor,
            };
            if self.malformed_bootstrap_continuation {
                view.journal_page.has_more = true;
            }
            Ok(view)
        }
        fn reputation_journal_event_by_source_id(
            &self,
            network_id: &NetworkId,
            maximum_height: u64,
            query: FindSorafsReputationJournalEventBySourceId,
        ) -> Result<ReputationJournalSourceFinalizedViewV1, ReputationExternalFailureV1> {
            ExternalProviderCallCounters::record_operation(&self.external_calls);
            let view = ReputationJournalSourceFinalizedViewV1 {
                anchor: ReputationFinalizedAnchorV1 {
                    network_id: *network_id,
                    identity: sorafs_node::reputation::ReputationFinalizedIdentityV1 {
                        height: 2,
                        block_hash: [0x81; 32],
                    },
                    finalized_at_unix_ms: 1_800_000_000_000,
                },
                event: None,
            };
            view.validate_for_request(network_id, maximum_height, query)
                .map_err(|_| {
                    ReputationExternalFailureV1::try_new([0x93; 32])
                        .expect("non-zero source-query failure receipt")
                })?;
            Ok(view)
        }
        fn proof_outcome_page(
            &self,
            _anchor: &ReputationFinalizedAnchorV1,
            _after: Option<ProofOutcomeFinalizedEventCursorV1>,
            _limit: u32,
        ) -> Result<ProofOutcomeFinalizedEventPageV1, ReputationExternalFailureV1> {
            ExternalProviderCallCounters::record_operation(&self.external_calls);
            unreachable!("assembly must not query external state")
        }
        fn reputation_journal_page(
            &self,
            _anchor: &ReputationFinalizedAnchorV1,
            _after: Option<ReputationJournalFinalizedEventCursorV1>,
            _limit: u32,
        ) -> Result<ReputationJournalFinalizedEventPageV1, ReputationExternalFailureV1> {
            ExternalProviderCallCounters::record_operation(&self.external_calls);
            unreachable!("assembly must not query external state")
        }
        fn repair_page(
            &self,
            _anchor: &ReputationFinalizedAnchorV1,
            _after: Option<RepairFinalizedEventCursorV1>,
            _limit: u32,
        ) -> Result<RepairFinalizedEventPageV1, ReputationExternalFailureV1> {
            ExternalProviderCallCounters::record_operation(&self.external_calls);
            unreachable!("assembly must not query external state")
        }
        fn orderbook_page(
            &self,
            _anchor: &ReputationFinalizedAnchorV1,
            _after: Option<OrderbookFinalizedEventCursorV1>,
            _limit: u32,
        ) -> Result<OrderbookFinalizedEventPageV1, ReputationExternalFailureV1> {
            ExternalProviderCallCounters::record_operation(&self.external_calls);
            unreachable!("assembly must not query external state")
        }
        fn reserve_page(
            &self,
            _anchor: &ReputationFinalizedAnchorV1,
            _after: Option<ReserveFinalizedEventCursorV1>,
            _limit: u32,
        ) -> Result<ReserveFinalizedEventPageV1, ReputationExternalFailureV1> {
            ExternalProviderCallCounters::record_operation(&self.external_calls);
            unreachable!("assembly must not query external state")
        }
        fn reserve_provider_page(
            &self,
            _anchor: &ReputationFinalizedAnchorV1,
            _after_provider_id: Option<ProviderId>,
            _limit: u32,
        ) -> Result<ReserveProviderAccountPageV1, ReputationExternalFailureV1> {
            ExternalProviderCallCounters::record_operation(&self.external_calls);
            unreachable!("assembly must not query external state")
        }
    }
    #[derive(Debug)]
    struct PendingThresholdSigner {
        handle: String,
        qualification: ReputationRuntimeProviderQualificationV1,
        external_calls: Option<Arc<ExternalProviderCallCounters>>,
    }
    #[derive(Debug)]
    struct DriftingThresholdSigner {
        handle: String,
        qualification: ReputationRuntimeProviderQualificationV1,
        drift_armed: AtomicBool,
        remaining_good_qualifications: AtomicU64,
    }
    impl DriftingThresholdSigner {
        fn arm_after(&self, good_qualifications: u64) {
            self.remaining_good_qualifications
                .store(good_qualifications, Ordering::SeqCst);
            self.drift_armed.store(true, Ordering::SeqCst);
        }
        fn restore(&self) {
            self.drift_armed.store(false, Ordering::SeqCst);
        }
    }
    #[derive(Debug)]
    struct PendingJournalCheckpointProvider {
        handle: String,
        qualification: ReputationRuntimeProviderQualificationV1,
        latest: Mutex<Option<ReputationJournalSealedCheckpointRecordV1>>,
        external_calls: Option<Arc<ExternalProviderCallCounters>>,
    }
    impl ReputationRuntimeProviderV1 for PendingJournalCheckpointProvider {
        fn handle(&self) -> &str {
            ExternalProviderCallCounters::record_handle(&self.external_calls);
            &self.handle
        }
        fn qualification(
            &self,
        ) -> std::result::Result<
            ReputationRuntimeProviderQualificationV1,
            ReputationExternalFailureV1,
        > {
            ExternalProviderCallCounters::record_qualification(&self.external_calls);
            Ok(self.qualification)
        }
    }
    impl ReputationJournalCheckpointRuntimeV1 for PendingJournalCheckpointProvider {
        fn load_latest(
            &self,
        ) -> std::result::Result<
            Option<ReputationJournalSealedCheckpointRecordV1>,
            ReputationJournalCheckpointExternalErrorV1,
        > {
            ExternalProviderCallCounters::record_operation(&self.external_calls);
            Ok(self
                .latest
                .lock()
                .expect("journal checkpoint provider lock")
                .clone())
        }
        fn compare_and_swap_latest(
            &self,
            expected_revision: Option<[u8; 32]>,
            next: &ReputationJournalSealedCheckpointRecordV1,
        ) -> std::result::Result<(), ReputationJournalCheckpointExternalErrorV1> {
            ExternalProviderCallCounters::record_operation(&self.external_calls);
            let mut latest = self
                .latest
                .lock()
                .expect("journal checkpoint provider lock");
            if latest
                .as_ref()
                .map(ReputationJournalSealedCheckpointRecordV1::revision)
                != expected_revision
            {
                return Err(ReputationJournalCheckpointExternalErrorV1::Rejected);
            }
            *latest = Some(next.clone());
            Ok(())
        }
    }
    #[derive(Debug)]
    struct PendingJournalSubmitter {
        handle: String,
        authority: AccountId,
        qualification: ReputationRuntimeProviderQualificationV1,
        external_calls: Option<Arc<ExternalProviderCallCounters>>,
    }
    impl ReputationRuntimeProviderV1 for PendingJournalSubmitter {
        fn handle(&self) -> &str {
            ExternalProviderCallCounters::record_handle(&self.external_calls);
            &self.handle
        }
        fn qualification(
            &self,
        ) -> std::result::Result<
            ReputationRuntimeProviderQualificationV1,
            ReputationExternalFailureV1,
        > {
            ExternalProviderCallCounters::record_qualification(&self.external_calls);
            Ok(self.qualification)
        }
    }
    impl ReputationJournalTransactionSubmitterV1 for PendingJournalSubmitter {
        fn supports_authority(&self, authority: &AccountId) -> bool {
            ExternalProviderCallCounters::record_readiness(&self.external_calls);
            authority == &self.authority
        }
        fn submit(
            &self,
            request: &ReputationJournalTransactionRequestV1,
        ) -> ReputationJournalTransactionSubmitOutcomeV1 {
            ExternalProviderCallCounters::record_operation(&self.external_calls);
            ReputationJournalTransactionSubmitOutcomeV1::Ambiguous {
                receipt: request.idempotency_key,
            }
        }
    }
    impl ReputationRuntimeProviderV1 for PendingThresholdSigner {
        fn handle(&self) -> &str {
            ExternalProviderCallCounters::record_handle(&self.external_calls);
            &self.handle
        }
        fn qualification(
            &self,
        ) -> std::result::Result<
            ReputationRuntimeProviderQualificationV1,
            ReputationExternalFailureV1,
        > {
            ExternalProviderCallCounters::record_qualification(&self.external_calls);
            Ok(self.qualification)
        }
    }
    impl ReputationThresholdSignerClientV1 for PendingThresholdSigner {
        fn reconcile_signature(
            &self,
            _request: &ReputationThresholdSigningRequestV1,
        ) -> Result<Option<SignedReputationSnapshotV1>, ReputationExternalFailureV1> {
            ExternalProviderCallCounters::record_operation(&self.external_calls);
            Ok(None)
        }
    }
    impl ReputationRuntimeProviderV1 for DriftingThresholdSigner {
        fn handle(&self) -> &str {
            &self.handle
        }
        fn qualification(
            &self,
        ) -> std::result::Result<
            ReputationRuntimeProviderQualificationV1,
            ReputationExternalFailureV1,
        > {
            if self.drift_armed.load(Ordering::SeqCst)
                && self
                    .remaining_good_qualifications
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                        remaining.checked_sub(1)
                    })
                    .is_err()
            {
                return Ok(ReputationRuntimeProviderQualificationV1::new(
                    REPUTATION_RUNTIME_PROVIDER_QUALIFICATION_REVISION_V1,
                    [0xE7; 32],
                ));
            }
            Ok(self.qualification)
        }
    }
    impl ReputationThresholdSignerClientV1 for DriftingThresholdSigner {
        fn reconcile_signature(
            &self,
            _request: &ReputationThresholdSigningRequestV1,
        ) -> Result<Option<SignedReputationSnapshotV1>, ReputationExternalFailureV1> {
            Ok(None)
        }
    }
    #[derive(Debug)]
    struct PendingGovernanceDag {
        handle: String,
        qualification: ReputationRuntimeProviderQualificationV1,
        external_calls: Option<Arc<ExternalProviderCallCounters>>,
    }
    impl ReputationRuntimeProviderV1 for PendingGovernanceDag {
        fn handle(&self) -> &str {
            ExternalProviderCallCounters::record_handle(&self.external_calls);
            &self.handle
        }
        fn qualification(
            &self,
        ) -> std::result::Result<
            ReputationRuntimeProviderQualificationV1,
            ReputationExternalFailureV1,
        > {
            ExternalProviderCallCounters::record_qualification(&self.external_calls);
            Ok(self.qualification)
        }
    }
    impl ReputationGovernanceDagClientV1 for PendingGovernanceDag {
        fn reconcile_publication(
            &self,
            _request: &ReputationGovernanceDagPublicationRequestV1,
        ) -> Result<Option<ReputationGovernanceDagReadbackV1>, ReputationExternalFailureV1>
        {
            ExternalProviderCallCounters::record_operation(&self.external_calls);
            Ok(None)
        }
    }
    fn public_key(seed: u8) -> [u8; 32] {
        let key = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("deterministic Ed25519 key");
        key.public_key()
            .to_bytes()
            .1
            .try_into()
            .expect("Ed25519 public key is 32 bytes")
    }
    fn account(seed: u8) -> AccountId {
        let key = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("deterministic account");
        AccountId::new(key.public_key().clone())
    }
    fn trust_policy() -> Arc<ReputationSnapshotTrustPolicyV1> {
        Arc::new(ReputationSnapshotTrustPolicyV1 {
            version: REPUTATION_SNAPSHOT_TRUST_POLICY_VERSION_V1,
            policy_id: [0x72; 32],
            valid_from_unix: 1_800_000_000,
            valid_until_unix: 1_900_000_000,
            max_snapshot_age_secs: 600,
            max_future_skew_secs: 30,
            min_signatures: 1,
            signers: vec![ReputationTrustedSignerV1 {
                version: REPUTATION_TRUSTED_SIGNER_VERSION_V1,
                signer_id: "threshold-a".to_owned(),
                public_key: public_key(0x71),
            }],
            revoked_signer_ids: Vec::new(),
        })
    }
    fn config(
        state_dir: PathBuf,
        network_id: &NetworkId,
        trust_policy: &ReputationSnapshotTrustPolicyV1,
    ) -> SorafsReputationRuntime {
        let finalized_archive_root = state_dir.with_extension("finalized-archive");
        let journal_checkpoint_provider_handle = "sealed.reputation.journal.primary".to_owned();
        let journal_transaction_submitter_handle = "queue.reputation.journal".to_owned();
        let threshold_signer_handle = "provider.reputation.threshold".to_owned();
        let governance_dag_handle = "governance.dag.publisher".to_owned();
        let governance_publisher_peer_id = b"12D3KooWProductionPublisher".to_vec();
        let governance_publisher_public_key = public_key(0x73);
        let journal_transaction_submitter_qualification =
            ReputationRuntimeProviderQualificationV1::new(
                REPUTATION_RUNTIME_PROVIDER_QUALIFICATION_REVISION_V1,
                reputation_journal_submitter_policy_digest_v1(
                    network_id,
                    &journal_transaction_submitter_handle,
                )
                .expect("journal transaction-submitter policy digest"),
            );
        let publication_policy = ReputationPublicationPolicyV1::try_new(
            trust_policy,
            threshold_signer_handle.clone(),
            governance_dag_handle.clone(),
            governance_publisher_peer_id.clone(),
            governance_publisher_public_key,
            32 * 1024 * 1024,
        )
        .expect("publication policy");
        let threshold_signer_qualification = publication_policy.threshold_signer_qualification();
        let governance_dag_qualification = publication_policy.governance_dag_qualification();
        SorafsReputationRuntime {
            state_dir,
            finalized_archive_root,
            finalized_archive_max_record_bytes: 4 * 1024 * 1024,
            finalized_archive_max_entries: 4_096,
            finalized_archive_max_total_bytes: 256 * 1024 * 1024,
            finalized_archive_max_kura_tip_lag_blocks: 2,
            finalized_archive_retention_authority: None,
            window_start_height: 1,
            window_end_height: 10,
            finalized_query_handle: "ledger.finalized.primary".to_owned(),
            journal_checkpoint_provider_handle,
            journal_checkpoint_provider_revision:
                REPUTATION_RUNTIME_PROVIDER_QUALIFICATION_REVISION_V1,
            journal_checkpoint_provider_policy_digest: [0x64; 32],
            journal_transaction_submitter_handle,
            journal_transaction_submitter_revision: journal_transaction_submitter_qualification
                .revision(),
            journal_transaction_submitter_policy_digest:
                journal_transaction_submitter_qualification.policy_digest(),
            threshold_signer_handle,
            threshold_signer_revision: threshold_signer_qualification.revision(),
            threshold_signer_policy_digest: threshold_signer_qualification.policy_digest(),
            governance_dag_handle,
            governance_dag_revision: governance_dag_qualification.revision(),
            governance_dag_policy_digest: governance_dag_qualification.policy_digest(),
            governance_publisher_peer_id,
            governance_publisher_public_key,
            poll_interval: Duration::from_secs(1),
            page_items: 64,
            max_pages_per_batch: 4_096,
            max_providers: 65_536,
            max_pending_events: 65_536,
            max_replay_receipts: 262_144,
            max_material_delivery_failures: 64,
            ingest_checkpoint_max_bytes: Bytes(64 * 1024 * 1024),
            publication_checkpoint_max_bytes: Bytes(32 * 1024 * 1024),
            por_success_bps: 2_200,
            pdp_success_bps: 2_000,
            potr_success_bps: 1_800,
            latency_bps: 1_500,
            dispute_bps: 1_000,
            token_violation_bps: 500,
            repair_breach_bps: 1_000,
        }
    }
    fn dependencies(
        config: &SorafsReputationRuntime,
        network_id: &NetworkId,
        trust_policy: &ReputationSnapshotTrustPolicyV1,
        query_handle: &str,
    ) -> ReputationRuntimeDependenciesV1 {
        dependencies_with_calls(config, network_id, trust_policy, query_handle, None)
    }
    fn dependencies_with_calls(
        config: &SorafsReputationRuntime,
        network_id: &NetworkId,
        trust_policy: &ReputationSnapshotTrustPolicyV1,
        query_handle: &str,
        external_calls: Option<Arc<ExternalProviderCallCounters>>,
    ) -> ReputationRuntimeDependenciesV1 {
        let weights = ReputationWeightsV1 {
            version: REPUTATION_WEIGHTS_VERSION_V1,
            por_success_bps: config.por_success_bps,
            pdp_success_bps: config.pdp_success_bps,
            potr_success_bps: config.potr_success_bps,
            latency_bps: config.latency_bps,
            dispute_bps: config.dispute_bps,
            token_violation_bps: config.token_violation_bps,
            repair_breach_bps: config.repair_breach_bps,
        };
        let mut ingest_policy = ReputationIngestPolicyV1::strict_v1(
            *network_id,
            config.window_start_height,
            config.window_end_height,
            trust_policy
                .canonical_digest()
                .expect("trust-policy digest"),
            weights,
        );
        ingest_policy.max_providers = config.max_providers;
        ingest_policy.max_pending_events = config.max_pending_events;
        ingest_policy.max_replay_receipts = config.max_replay_receipts;
        ingest_policy.max_pages_per_batch = config.max_pages_per_batch;
        ingest_policy.max_material_delivery_failures = config.max_material_delivery_failures;
        ingest_policy.checkpoint_max_bytes = config.ingest_checkpoint_max_bytes.0;
        let query_qualification = ReputationFinalizedQueryPolicyV1::try_new(
            &ingest_policy,
            &config.finalized_query_handle,
            config.page_items,
            config.max_pages_per_batch,
        )
        .expect("query policy")
        .query_qualification();
        let submitter_qualification = ReputationRuntimeProviderQualificationV1::new(
            config.journal_transaction_submitter_revision,
            config.journal_transaction_submitter_policy_digest,
        );
        ReputationRuntimeDependenciesV1 {
            finalized_query: Arc::new(UnavailableQuery {
                handle: query_handle.to_owned(),
                ready: true,
                qualification: query_qualification,
                malformed_bootstrap_continuation: false,
                external_calls: external_calls.clone(),
            }),
            journal_checkpoint_provider: Arc::new(PendingJournalCheckpointProvider {
                handle: config.journal_checkpoint_provider_handle.clone(),
                qualification: ReputationRuntimeProviderQualificationV1::new(
                    config.journal_checkpoint_provider_revision,
                    config.journal_checkpoint_provider_policy_digest,
                ),
                latest: Mutex::new(None),
                external_calls: external_calls.clone(),
            }),
            journal_transaction_submitter: Arc::new(PendingJournalSubmitter {
                handle: config.journal_transaction_submitter_handle.clone(),
                authority: account(1),
                qualification: submitter_qualification,
                external_calls: external_calls.clone(),
            }),
            threshold_signer: Arc::new(PendingThresholdSigner {
                handle: config.threshold_signer_handle.clone(),
                qualification: ReputationRuntimeProviderQualificationV1::new(
                    config.threshold_signer_revision,
                    config.threshold_signer_policy_digest,
                ),
                external_calls: external_calls.clone(),
            }),
            governance_dag: Arc::new(PendingGovernanceDag {
                handle: config.governance_dag_handle.clone(),
                qualification: ReputationRuntimeProviderQualificationV1::new(
                    config.governance_dag_revision,
                    config.governance_dag_policy_digest,
                ),
                external_calls,
            }),
            retention_control: None,
        }
    }
    fn counting_dependencies(
        config: &SorafsReputationRuntime,
        network_id: &NetworkId,
        trust_policy: &ReputationSnapshotTrustPolicyV1,
    ) -> (
        ReputationRuntimeDependenciesV1,
        Arc<ExternalProviderCallCounters>,
    ) {
        let calls = Arc::new(ExternalProviderCallCounters::default());
        let mut dependencies = dependencies_with_calls(
            config,
            network_id,
            trust_policy,
            &config.finalized_query_handle,
            Some(Arc::clone(&calls)),
        );
        dependencies.retention_control = Some(Arc::new(
            CountingRetentionControl::with_external_calls(true, Arc::clone(&calls)),
        ));
        (dependencies, calls)
    }
    fn por_terminal(marker: u8) -> PorTerminalOutcomeV1 {
        PorTerminalOutcomeV1 {
            challenge_id: [marker; 32],
            manifest_digest: [marker.wrapping_add(1); 32],
            epoch_id: 7,
            drand_round: 11,
            forced: false,
            sample_count: 4,
            failed_samples: 0,
            issued_at_unix_ms: 1_800_000_000_000,
            deadline_at_unix_ms: 1_800_000_001_000,
            responded_at_unix_ms: Some(1_800_000_000_500),
            decided_at_unix_ms: 1_800_000_001_500,
            proof_digest: Some([marker.wrapping_add(2); 32]),
            repair_task_id: None,
            verifier_latency_ms: Some(1_000),
            status: PorTerminalStatusV1::Verified,
        }
    }
    #[tokio::test]
    async fn deferred_start_is_nonblocking_and_fail_closed_before_activation() {
        let temp = TempDir::new().expect("tempdir");
        let network_id = network_id("reputation-runtime-deferred");
        let trust_policy = trust_policy();
        let mut config = config(
            temp.path().join("deferred-state"),
            &network_id,
            trust_policy.as_ref(),
        );
        config.poll_interval = Duration::from_millis(100);
        let dependencies = dependencies(
            &config,
            &network_id,
            trust_policy.as_ref(),
            &config.finalized_query_handle,
        );
        let shutdown = ShutdownSignal::new();
        let activation_probe: ReputationRuntimeActivationProbeV1 = Arc::new(|| Ok(false));
        let (handle, _child) = start_deferred(
            &config,
            &network_id,
            trust_policy.as_ref(),
            dependencies,
            activation_probe,
            shutdown.clone(),
        )
        .expect("deferred runtime identity preflight");
        tokio::task::yield_now().await;
        assert_eq!(
            handle.activation_state(),
            Ok(sorafs_node::reputation::runtime::PorTerminalReputationAdmissionStateV1::Deferred)
        );
        assert!(matches!(
            handle.status(),
            Err(ReputationRuntimeError::RuntimeBindingMismatch)
        ));
        assert_eq!(handle.metrics().successful_ticks, 0);
        assert!(matches!(
            handle.committed_read_projection(),
            Err(ReputationRuntimeError::RuntimeBindingMismatch)
        ));
        shutdown.send();
    }
    #[test]
    fn daemon_owned_query_qualification_matches_worker_policy() {
        let temp = TempDir::new().expect("tempdir");
        let network_id = network_id("reputation-runtime-test");
        let trust_policy = trust_policy();
        let config = config(
            temp.path().join("qualification-state"),
            &network_id,
            trust_policy.as_ref(),
        );
        let expected = dependencies(
            &config,
            &network_id,
            trust_policy.as_ref(),
            &config.finalized_query_handle,
        )
        .finalized_query
        .qualification()
        .expect("fixture query qualification");
        let actual = finalized_query_qualification_v1(&config, &network_id, trust_policy.as_ref())
            .expect("derive daemon-owned query qualification");
        assert_eq!(actual, expected);
    }
    #[test]
    fn por_terminal_trait_is_object_safe_and_exactly_idempotent() {
        let temp = TempDir::new().expect("tempdir");
        let network_id = network_id("reputation-runtime-native-admission");
        let trust_policy = trust_policy();
        let config = config(
            temp.path().join("native-admission-state"),
            &network_id,
            trust_policy.as_ref(),
        );
        let handle = assemble(
            &config,
            &network_id,
            trust_policy.as_ref(),
            dependencies(
                &config,
                &network_id,
                trust_policy.as_ref(),
                &config.finalized_query_handle,
            ),
        )
        .expect("assemble native admission runtime");
        assert_eq!(
            handle.activation_state(),
            Ok(sorafs_node::reputation::runtime::PorTerminalReputationAdmissionStateV1::Active)
        );
        let admission: &dyn PorTerminalReputationAdmissionV1 = &handle;
        let activation_unix_ms: u64 = 1_800_000_000_000;
        let terminal_at = |challenge_id: u8, decided_at_unix_ms: u64| PorTerminalOutcomeV1 {
            challenge_id: [challenge_id; 32],
            manifest_digest: [0x21; 32],
            epoch_id: 7,
            drand_round: 11,
            forced: false,
            sample_count: 4,
            failed_samples: 0,
            issued_at_unix_ms: decided_at_unix_ms.saturating_sub(2_000),
            deadline_at_unix_ms: decided_at_unix_ms.saturating_sub(500),
            responded_at_unix_ms: Some(decided_at_unix_ms.saturating_sub(750)),
            decided_at_unix_ms,
            proof_digest: Some([0x22; 32]),
            repair_task_id: None,
            verifier_latency_ms: Some(250),
            status: PorTerminalStatusV1::Verified,
        };
        assert!(matches!(
            admission.record_por_terminal(
                ProviderId::new([0x23; 32]),
                terminal_at(0x24, activation_unix_ms.saturating_sub(1)),
            ),
            Err(ReputationRuntimeError::InvalidAuthorityPolicy)
        ));
        assert!(matches!(
            admission
                .record_por_terminal(
                    ProviderId::new([0x25; 32]),
                    terminal_at(0x26, activation_unix_ms),
                )
                .expect("activation-boundary callback"),
            sorafs_node::reputation::runtime::ReputationJournalEnqueueOutcomeV1::Inserted { .. }
        ));
        let terminal = PorTerminalOutcomeV1 {
            challenge_id: [0x31; 32],
            manifest_digest: [0x32; 32],
            epoch_id: 7,
            drand_round: 11,
            forced: false,
            sample_count: 4,
            failed_samples: 0,
            issued_at_unix_ms: 1_800_000_000_000,
            deadline_at_unix_ms: 1_800_000_001_000,
            responded_at_unix_ms: Some(1_800_000_000_500),
            decided_at_unix_ms: 1_800_000_001_500,
            proof_digest: Some([0x33; 32]),
            repair_task_id: None,
            verifier_latency_ms: Some(1_000),
            status: PorTerminalStatusV1::Verified,
        };
        let inserted = admission
            .record_por_terminal(ProviderId::new([0x34; 32]), terminal)
            .expect("durably insert native PoR terminal");
        let replay = admission
            .record_por_terminal(ProviderId::new([0x34; 32]), terminal)
            .expect("exact PoR terminal replay");
        assert!(matches!(
            (inserted, replay),
            (
                sorafs_node::reputation::runtime::ReputationJournalEnqueueOutcomeV1::Inserted {
                    event_id: inserted
                },
                sorafs_node::reputation::runtime::ReputationJournalEnqueueOutcomeV1::ExactReplay {
                    event_id: replay
                }
            ) if inserted == replay
        ));
    }
    #[test]
    fn native_admission_revalidates_bindings_before_and_after_durable_enqueue() {
        let temp = TempDir::new().expect("tempdir");
        let network_id = network_id("reputation-runtime-native-binding");
        let trust_policy = trust_policy();
        let config = config(
            temp.path().join("native-admission-binding-state"),
            &network_id,
            trust_policy.as_ref(),
        );
        let mut runtime_dependencies = dependencies(
            &config,
            &network_id,
            trust_policy.as_ref(),
            &config.finalized_query_handle,
        );
        let signer = Arc::new(DriftingThresholdSigner {
            handle: config.threshold_signer_handle.clone(),
            qualification: runtime_dependencies
                .threshold_signer
                .qualification()
                .expect("threshold-signer qualification"),
            drift_armed: AtomicBool::new(false),
            remaining_good_qualifications: AtomicU64::new(0),
        });
        runtime_dependencies.threshold_signer = signer.clone();
        let handle = assemble(
            &config,
            &network_id,
            trust_policy.as_ref(),
            runtime_dependencies,
        )
        .expect("assemble native admission runtime");
        let admission: &dyn PorTerminalReputationAdmissionV1 = &handle;
        let terminal = PorTerminalOutcomeV1 {
            challenge_id: [0x61; 32],
            manifest_digest: [0x62; 32],
            epoch_id: 7,
            drand_round: 11,
            forced: false,
            sample_count: 4,
            failed_samples: 0,
            issued_at_unix_ms: 1_800_000_000_000,
            deadline_at_unix_ms: 1_800_000_001_000,
            responded_at_unix_ms: Some(1_800_000_000_500),
            decided_at_unix_ms: 1_800_000_001_500,
            proof_digest: Some([0x63; 32]),
            repair_task_id: None,
            verifier_latency_ms: Some(1_000),
            status: PorTerminalStatusV1::Verified,
        };
        signer.arm_after(1);
        assert!(matches!(
            admission.record_por_terminal(ProviderId::new([0x64; 32]), terminal),
            Err(ReputationRuntimeError::RuntimeBindingChanged)
        ));
        signer.restore();
        assert!(matches!(
            admission
                .record_por_terminal(ProviderId::new([0x64; 32]), terminal)
                .expect("exact retry after post-enqueue drift"),
            sorafs_node::reputation::runtime::ReputationJournalEnqueueOutcomeV1::ExactReplay { .. }
        ));
    }
    #[test]
    fn native_admission_rejects_stale_retention_before_mutation() {
        let temp = TempDir::new().expect("tempdir");
        let network_id = network_id("reputation-runtime-native-retention-stale");
        let trust_policy = trust_policy();
        let mut config = config(
            temp.path().join("native-admission-retention-stale-state"),
            &network_id,
            trust_policy.as_ref(),
        );
        config.finalized_archive_retention_authority = Some(
            iroha_config::parameters::actual::SorafsReputationFinalizedArchiveRetentionAuthority {
                handle: "sealed.reputation.archive.primary".to_owned(),
                revision: 7,
                policy_digest: [0xA7; 32],
            },
        );
        let mut runtime_dependencies = dependencies(
            &config,
            &network_id,
            trust_policy.as_ref(),
            &config.finalized_query_handle,
        );
        let retention = Arc::new(CountingRetentionControl::new(true));
        runtime_dependencies.retention_control = Some(retention.clone());
        let handle = assemble(
            &config,
            &network_id,
            trust_policy.as_ref(),
            runtime_dependencies,
        )
        .expect("assemble retention-bound native admission runtime");
        let producer_before = handle
            .active()
            .expect("active runtime")
            .runtime
            .status()
            .expect("runtime status")
            .journal_delivery
            .expect("journal delivery")
            .producer;
        retention.ready.store(false, Ordering::Release);
        assert_eq!(
            handle.activation_state(),
            Err(ReputationRuntimeError::RuntimeBindingChanged)
        );
        assert_eq!(
            handle.record_por_terminal(ProviderId::new([0x71; 32]), por_terminal(0x72)),
            Err(ReputationRuntimeError::RuntimeBindingChanged)
        );
        let producer_after = handle
            .active()
            .expect("active runtime")
            .runtime
            .status()
            .expect("runtime status")
            .journal_delivery
            .expect("journal delivery")
            .producer;
        assert_eq!(
            producer_after, producer_before,
            "a stale pre-enqueue retention binding must not mutate the durable outbox"
        );
    }
    #[test]
    fn native_admission_replays_after_post_enqueue_retention_drift() {
        let temp = TempDir::new().expect("tempdir");
        let network_id = network_id("reputation-runtime-native-retention-drift");
        let trust_policy = trust_policy();
        let mut config = config(
            temp.path().join("native-admission-retention-drift-state"),
            &network_id,
            trust_policy.as_ref(),
        );
        config.finalized_archive_retention_authority = Some(
            iroha_config::parameters::actual::SorafsReputationFinalizedArchiveRetentionAuthority {
                handle: "sealed.reputation.archive.primary".to_owned(),
                revision: 7,
                policy_digest: [0xA7; 32],
            },
        );
        let mut runtime_dependencies = dependencies(
            &config,
            &network_id,
            trust_policy.as_ref(),
            &config.finalized_query_handle,
        );
        let retention = Arc::new(DriftingRetentionControl::new());
        runtime_dependencies.retention_control = Some(retention.clone());
        let handle = assemble(
            &config,
            &network_id,
            trust_policy.as_ref(),
            runtime_dependencies,
        )
        .expect("assemble drifting-retention native admission runtime");
        let provider_id = ProviderId::new([0x73; 32]);
        let terminal = por_terminal(0x74);
        retention.arm_after(1);
        assert_eq!(
            handle.record_por_terminal(provider_id, terminal),
            Err(ReputationRuntimeError::RuntimeBindingChanged)
        );
        let producer_after_drift = handle
            .active()
            .expect("active runtime")
            .runtime
            .status()
            .expect("runtime status")
            .journal_delivery
            .expect("journal delivery")
            .producer;
        assert_eq!(
            producer_after_drift.ready, 1,
            "post-enqueue drift must retain the one durable admission"
        );
        retention.restore();
        assert!(matches!(
            handle
                .record_por_terminal(provider_id, terminal)
                .expect("exact retry after restoring retention binding"),
            sorafs_node::reputation::runtime::ReputationJournalEnqueueOutcomeV1::ExactReplay { .. }
        ));
        assert_eq!(
            handle.activation_state(),
            Ok(sorafs_node::reputation::runtime::PorTerminalReputationAdmissionStateV1::Active)
        );
    }
    #[test]
    fn production_config_rejects_null_test_handles_and_unsafe_paths() {
        let temp = TempDir::new().expect("tempdir");
        let network_id = network_id("reputation-runtime-config-test");
        let trust_policy = trust_policy();
        for rejected in [
            "null-query.test",
            "https://operator:secret@reputation.example",
            "https://reputation.example/query?token=secret",
            "https://reputation.example/query#fragment",
            "provider://reputation/dummy/signer",
        ] {
            let mut invalid_handle_config = config(
                temp.path().to_path_buf(),
                &network_id,
                trust_policy.as_ref(),
            );
            invalid_handle_config.finalized_query_handle = rejected.to_owned();
            assert!(
                validate_actual_config(&invalid_handle_config).is_err(),
                "{rejected:?} must fail before runtime construction"
            );
        }
        let mut unsafe_path_config = config(
            PathBuf::from("/var/lib/iroha/../reputation"),
            &network_id,
            trust_policy.as_ref(),
        );
        unsafe_path_config.finalized_query_handle = "ledger.finalized.primary".to_owned();
        assert!(validate_actual_config(&unsafe_path_config).is_err());
    }
    #[test]
    fn daemon_liveness_is_fail_closed_freshness_bounded_and_shutdown_safe() {
        let liveness = Arc::new(ReputationDaemonLiveness::new(Duration::from_secs(1)));
        assert_eq!(
            liveness.status().expect("initial liveness"),
            (false, false, false)
        );
        liveness.begin_tick();
        assert_eq!(
            liveness.status().expect("in-flight liveness"),
            (false, false, true)
        );
        liveness.finish_tick(true).expect("complete healthy tick");
        assert_eq!(
            liveness.status().expect("healthy liveness"),
            (true, true, false)
        );
        *liveness
            .last_completed_at
            .lock()
            .expect("liveness timestamp lock") = Instant::now().checked_sub(
            liveness
                .freshness_timeout
                .saturating_add(Duration::from_millis(1)),
        );
        assert_eq!(
            liveness.status().expect("stale liveness"),
            (true, false, false)
        );
        drop(ReputationDaemonShutdownGuard {
            liveness: Arc::clone(&liveness),
        });
        assert_eq!(
            liveness.status().expect("shutdown liveness"),
            (false, false, false)
        );
    }
    #[test]
    fn configured_provider_qualification_matrix_fails_before_external_calls_or_state_open() {
        type ConfigMutation = fn(&mut SorafsReputationRuntime);
        let cases: [(&str, ConfigMutation, &str); 6] = [
            (
                "journal-submitter-revision",
                |config| {
                    config.journal_transaction_submitter_revision =
                        REPUTATION_RUNTIME_PROVIDER_QUALIFICATION_REVISION_V1 + 1;
                },
                "configured reputation journal transaction-submitter revision is not V1",
            ),
            (
                "journal-submitter-policy-digest",
                |config| {
                    config.journal_transaction_submitter_policy_digest[0] ^= 1;
                },
                "configured reputation journal transaction-submitter policy digest does not match the derived V1 policy",
            ),
            (
                "threshold-signer-revision",
                |config| {
                    config.threshold_signer_revision =
                        REPUTATION_RUNTIME_PROVIDER_QUALIFICATION_REVISION_V1 + 1;
                },
                "configured reputation threshold-signer revision is not V1",
            ),
            (
                "threshold-signer-policy-digest",
                |config| {
                    config.threshold_signer_policy_digest[0] ^= 1;
                },
                "configured reputation threshold-signer policy digest does not match the derived V1 policy",
            ),
            (
                "governance-dag-revision",
                |config| {
                    config.governance_dag_revision =
                        REPUTATION_RUNTIME_PROVIDER_QUALIFICATION_REVISION_V1 + 1;
                },
                "configured reputation Governance DAG revision is not V1",
            ),
            (
                "governance-dag-policy-digest",
                |config| {
                    config.governance_dag_policy_digest[0] ^= 1;
                },
                "configured reputation Governance DAG policy digest does not match the derived V1 policy",
            ),
        ];
        let temp = TempDir::new().expect("tempdir");
        let network_id = network_id("reputation-runtime-config-pins");
        let trust_policy = trust_policy();
        for (case, mutate, expected_error) in cases {
            let state_dir = temp.path().join(case);
            let mut config = config(state_dir.clone(), &network_id, trust_policy.as_ref());
            config.finalized_archive_retention_authority = Some(
                iroha_config::parameters::actual::SorafsReputationFinalizedArchiveRetentionAuthority {
                    handle: "sealed.reputation.archive.primary".to_owned(),
                    revision: 7,
                    policy_digest: [0xA7; 32],
                },
            );
            let (dependencies, calls) =
                counting_dependencies(&config, &network_id, trust_policy.as_ref());
            mutate(&mut config);
            let error = assemble(&config, &network_id, trust_policy.as_ref(), dependencies)
                .expect_err("substituted configured qualification must fail startup");
            assert_eq!(error.to_string(), expected_error, "{case}");
            assert!(
                !state_dir.exists(),
                "{case}: configured qualification must fail before durable state"
            );
            calls.assert_zero(case);
        }
    }
    #[test]
    fn assembly_rejects_adapter_identity_substitution_before_external_calls() {
        let temp = TempDir::new().expect("tempdir");
        let network_id = network_id("reputation-runtime-test");
        let trust_policy = trust_policy();
        let config = config(
            temp.path().to_path_buf(),
            &network_id,
            trust_policy.as_ref(),
        );
        let dependencies = dependencies(
            &config,
            &network_id,
            trust_policy.as_ref(),
            "ledger.finalized.substituted",
        );
        let error = assemble(&config, &network_id, trust_policy.as_ref(), dependencies)
            .expect_err("mismatched query identity must fail startup");
        assert!(error.to_string().contains("identity"));
    }
    #[test]
    fn configured_retention_control_is_required_invoked_and_fail_closed() {
        let network_id = network_id("reputation-retention-runtime-test");
        let trust_policy = trust_policy();
        let mut config = config(
            PathBuf::from("/var/lib/iroha/reputation"),
            &network_id,
            trust_policy.as_ref(),
        );
        config.finalized_archive_retention_authority = Some(
            iroha_config::parameters::actual::SorafsReputationFinalizedArchiveRetentionAuthority {
                handle: "sealed.reputation.archive.primary".to_owned(),
                revision: 7,
                policy_digest: [0xA7; 32],
            },
        );
        let mut dependencies = dependencies(
            &config,
            &network_id,
            trust_policy.as_ref(),
            &config.finalized_query_handle,
        );
        assert!(
            validate_retention_control(&config, &dependencies).is_err(),
            "configured retention must not start without its controller"
        );
        let control = Arc::new(CountingRetentionControl::new(true));
        dependencies.retention_control = Some(control.clone());
        validate_retention_control(&config, &dependencies)
            .expect("qualified explicit retention control");
        reconcile_retention_control(dependencies.retention_control.as_deref())
            .expect("supervised tick invokes explicit retention");
        assert_eq!(control.reconciliations.load(Ordering::Acquire), 1);
        control.ready.store(false, Ordering::Release);
        assert!(validate_retention_control(&config, &dependencies).is_err());
        assert!(
            reconcile_retention_control(dependencies.retention_control.as_deref()).is_err(),
            "stale authority must fail supervised tick readiness"
        );
        assert_eq!(
            control.reconciliations.load(Ordering::Acquire),
            1,
            "failed qualification must not claim work"
        );
    }
    #[test]
    fn startup_rejects_each_missing_runtime_adapter() {
        let network_id = network_id("reputation-runtime-test");
        let trust_policy = trust_policy();
        let config = config(
            PathBuf::from("/var/lib/iroha/reputation"),
            &network_id,
            trust_policy.as_ref(),
        );
        let complete = dependencies(
            &config,
            &network_id,
            trust_policy.as_ref(),
            "ledger.finalized.primary",
        );
        assert!(
            ReputationRuntimeDependenciesV1::require(
                None,
                Some(Arc::clone(&complete.journal_checkpoint_provider)),
                Some(Arc::clone(&complete.journal_transaction_submitter)),
                Some(Arc::clone(&complete.threshold_signer)),
                Some(Arc::clone(&complete.governance_dag)),
                None,
            )
            .is_err()
        );
        assert!(
            ReputationRuntimeDependenciesV1::require(
                Some(Arc::clone(&complete.finalized_query)),
                None,
                Some(Arc::clone(&complete.journal_transaction_submitter)),
                Some(Arc::clone(&complete.threshold_signer)),
                Some(Arc::clone(&complete.governance_dag)),
                None,
            )
            .is_err()
        );
        assert!(
            ReputationRuntimeDependenciesV1::require(
                Some(Arc::clone(&complete.finalized_query)),
                Some(Arc::clone(&complete.journal_checkpoint_provider)),
                None,
                Some(Arc::clone(&complete.threshold_signer)),
                Some(Arc::clone(&complete.governance_dag)),
                None,
            )
            .is_err()
        );
        assert!(
            ReputationRuntimeDependenciesV1::require(
                Some(Arc::clone(&complete.finalized_query)),
                Some(Arc::clone(&complete.journal_checkpoint_provider)),
                Some(Arc::clone(&complete.journal_transaction_submitter)),
                None,
                Some(Arc::clone(&complete.governance_dag)),
                None,
            )
            .is_err()
        );
        assert!(
            ReputationRuntimeDependenciesV1::require(
                Some(Arc::clone(&complete.finalized_query)),
                Some(Arc::clone(&complete.journal_checkpoint_provider)),
                Some(Arc::clone(&complete.journal_transaction_submitter)),
                Some(Arc::clone(&complete.threshold_signer)),
                None,
                None,
            )
            .is_err()
        );
    }
    #[test]
    fn assembly_requires_the_por_recorder_and_does_not_require_the_token_recorder() {
        let temp = TempDir::new().expect("tempdir");
        let network_id = network_id("reputation-runtime-test");
        let trust_policy = trust_policy();
        for (authority, admitted) in [(account(1), true), (account(3), false)] {
            let state_dir = temp.path().join(if admitted { "por" } else { "token" });
            let config = config(state_dir.clone(), &network_id, trust_policy.as_ref());
            let mut dependencies = dependencies(
                &config,
                &network_id,
                trust_policy.as_ref(),
                "ledger.finalized.primary",
            );
            dependencies.journal_transaction_submitter = Arc::new(PendingJournalSubmitter {
                handle: config.journal_transaction_submitter_handle.clone(),
                authority,
                qualification: ReputationRuntimeProviderQualificationV1::new(
                    config.journal_transaction_submitter_revision,
                    config.journal_transaction_submitter_policy_digest,
                ),
                external_calls: None,
            });
            let result = assemble(&config, &network_id, trust_policy.as_ref(), dependencies);
            if admitted {
                result.expect("the governed PoR recorder is sufficient for the PoR outbox");
            } else {
                let error = result.expect_err("the token recorder cannot replace the PoR recorder");
                assert!(error.to_string().contains("governed PoR recorder identity"));
                assert!(!state_dir.exists(), "reject before opening durable state");
            }
        }
    }
    #[test]
    fn assembly_rejects_unready_adapter_before_state_open() {
        let temp = TempDir::new().expect("tempdir");
        let state_dir = temp.path().join("must-not-exist");
        let network_id = network_id("reputation-runtime-test");
        let trust_policy = trust_policy();
        let config = config(state_dir.clone(), &network_id, trust_policy.as_ref());
        let mut dependencies = dependencies(
            &config,
            &network_id,
            trust_policy.as_ref(),
            "ledger.finalized.primary",
        );
        let query_qualification = dependencies
            .finalized_query
            .qualification()
            .expect("query qualification");
        dependencies.finalized_query = Arc::new(UnavailableQuery {
            handle: "ledger.finalized.primary".to_owned(),
            ready: false,
            qualification: query_qualification,
            malformed_bootstrap_continuation: false,
            external_calls: None,
        });
        let error = assemble(&config, &network_id, trust_policy.as_ref(), dependencies)
            .expect_err("unready query adapter must fail startup");
        assert!(error.to_string().contains("not qualified"));
        assert!(
            !state_dir.exists(),
            "adapter qualification must be verified before state is opened"
        );
    }
    #[test]
    fn assembly_rejects_malformed_bootstrap_view_before_state_open() {
        let temp = TempDir::new().expect("tempdir");
        let state_dir = temp.path().join("malformed-bootstrap-must-not-exist");
        let network_id = network_id("reputation-runtime-test");
        let trust_policy = trust_policy();
        let config = config(state_dir.clone(), &network_id, trust_policy.as_ref());
        let mut dependencies = dependencies(
            &config,
            &network_id,
            trust_policy.as_ref(),
            "ledger.finalized.primary",
        );
        let query_qualification = dependencies
            .finalized_query
            .qualification()
            .expect("query qualification");
        dependencies.finalized_query = Arc::new(UnavailableQuery {
            handle: "ledger.finalized.primary".to_owned(),
            ready: true,
            qualification: query_qualification,
            malformed_bootstrap_continuation: true,
            external_calls: None,
        });
        let error = assemble(&config, &network_id, trust_policy.as_ref(), dependencies)
            .expect_err("malformed exact bootstrap view must fail startup");
        assert!(error.to_string().contains("bootstrap view"));
        assert!(
            !state_dir.exists(),
            "bootstrap view must be validated before state is opened"
        );
    }
    #[test]
    fn assembly_rejects_same_key_different_governance_peer_before_state_open() {
        let temp = TempDir::new().expect("tempdir");
        let state_dir = temp.path().join("substituted-dag-peer-must-not-exist");
        let network_id = network_id("reputation-runtime-test");
        let trust_policy = trust_policy();
        let config = config(state_dir.clone(), &network_id, trust_policy.as_ref());
        let mut dependencies = dependencies(
            &config,
            &network_id,
            trust_policy.as_ref(),
            "ledger.finalized.primary",
        );
        dependencies.governance_dag = Arc::new(PendingGovernanceDag {
            handle: config.governance_dag_handle.clone(),
            qualification: ReputationRuntimeProviderQualificationV1::new(
                REPUTATION_RUNTIME_PROVIDER_QUALIFICATION_REVISION_V1,
                reputation_governance_dag_policy_digest_v1(
                    b"12D3KooWSubstitutedPublisher",
                    config.governance_publisher_public_key,
                )
                .expect("substituted publisher qualification"),
            ),
            external_calls: None,
        });
        let error = assemble(&config, &network_id, trust_policy.as_ref(), dependencies)
            .expect_err("same-key different-peer DAG adapter must fail startup");
        assert!(error.to_string().contains("not qualified"));
        assert!(
            !state_dir.exists(),
            "DAG peer qualification must fail before durable state"
        );
    }
    #[test]
    fn assembly_rejects_policy_mismatched_and_test_marked_providers_before_state_open() {
        let temp = TempDir::new().expect("tempdir");
        let network_id = network_id("reputation-runtime-test");
        let trust_policy = trust_policy();
        let mismatched_state_dir = temp.path().join("mismatched-must-not-exist");
        let mismatched_config = config(
            mismatched_state_dir.clone(),
            &network_id,
            trust_policy.as_ref(),
        );
        let mut mismatched_dependencies = dependencies(
            &mismatched_config,
            &network_id,
            trust_policy.as_ref(),
            "ledger.finalized.primary",
        );
        mismatched_dependencies.threshold_signer = Arc::new(PendingThresholdSigner {
            handle: mismatched_config.threshold_signer_handle.clone(),
            qualification: ReputationRuntimeProviderQualificationV1::new(
                REPUTATION_RUNTIME_PROVIDER_QUALIFICATION_REVISION_V1,
                [0xE1; 32],
            ),
            external_calls: None,
        });
        let mismatch = assemble(
            &mismatched_config,
            &network_id,
            trust_policy.as_ref(),
            mismatched_dependencies,
        )
        .expect_err("policy-substituted signer must fail startup");
        assert!(mismatch.to_string().contains("not qualified"));
        assert!(
            !mismatched_state_dir.exists(),
            "qualification mismatch must fail before durable state"
        );
        let test_marked_state_dir = temp.path().join("test-marked-must-not-exist");
        let test_marked_config = config(
            test_marked_state_dir.clone(),
            &network_id,
            trust_policy.as_ref(),
        );
        let mut test_marked_dependencies = dependencies(
            &test_marked_config,
            &network_id,
            trust_policy.as_ref(),
            "ledger.finalized.primary",
        );
        let query_qualification = test_marked_dependencies
            .finalized_query
            .qualification()
            .expect("query qualification");
        test_marked_dependencies.finalized_query = Arc::new(UnavailableQuery {
            handle: "test:ledger-finalized".to_owned(),
            ready: true,
            qualification: query_qualification,
            malformed_bootstrap_continuation: false,
            external_calls: None,
        });
        let _ = assemble(
            &test_marked_config,
            &network_id,
            trust_policy.as_ref(),
            test_marked_dependencies,
        )
        .expect_err("test-marked provider must fail startup");
        assert!(
            !test_marked_state_dir.exists(),
            "test-marked provider must fail before durable state"
        );
    }
    #[test]
    fn checkpoint_runtime_reopens_without_claiming_journal_readiness() {
        let temp = TempDir::new().expect("tempdir");
        let network_id = network_id("reputation-runtime-test");
        let trust_policy = trust_policy();
        let config = config(
            temp.path().to_path_buf(),
            &network_id,
            trust_policy.as_ref(),
        );
        let runtime_dependencies = dependencies(
            &config,
            &network_id,
            trust_policy.as_ref(),
            "ledger.finalized.primary",
        );
        let first = assemble(
            &config,
            &network_id,
            trust_policy.as_ref(),
            runtime_dependencies.clone(),
        )
        .expect("first assembly");
        let first_status = first.status().expect("first status");
        let external_dependencies_ready = first_status.liveness.external_dependencies_healthy;
        let last_tick_fresh = first_status.liveness.last_tick_fresh;
        let tick_in_flight = first_status.liveness.tick_in_flight;
        assert_eq!(
            (
                external_dependencies_ready,
                first_status.journal_transaction_submitter_ready,
                last_tick_fresh,
                tick_in_flight,
                first_status.ready,
            ),
            (false, false, false, false, false),
            "internal liveness grouping must preserve every externally projected readiness value",
        );
        let committed_reader: &dyn ReputationCommittedReadApiV1 = &first;
        assert!(
            committed_reader
                .committed_read_projection()
                .expect("object-safe committed read")
                .latest
                .is_none()
        );
        assert!(
            runtime_dependencies
                .journal_checkpoint_provider
                .load_latest()
                .expect("fixture checkpoint head")
                .is_some()
        );
        drop(first);
        let restarted = assemble(
            &config,
            &network_id,
            trust_policy.as_ref(),
            runtime_dependencies,
        )
        .expect("restart assembly");
        let restarted_status = restarted.status().expect("restart status");
        assert_eq!(restarted_status.ingest.latest_finalized, None);
        assert!(!restarted_status.ready);
        assert!(!restarted_status.liveness.external_dependencies_healthy);
        assert!(!restarted_status.liveness.last_tick_fresh);
        assert!(!restarted_status.journal_transaction_submitter_ready);
        assert!(
            restarted
                .committed_read_projection()
                .expect("restarted committed read")
                .latest
                .is_none()
        );
    }
}
