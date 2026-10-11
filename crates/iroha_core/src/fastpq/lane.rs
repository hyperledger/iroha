//! Background complete-effect work retaining its original authenticated native source.
mod source;
use crate::{
    fastpq::finalized_source::{
        AdmittedFinalizedFastpqSource, FinalizedFastpqSource, FinalizedFastpqWorkError,
    },
    kura::Kura,
};
use fastpq_prover::{
    DigestExecutionV1, MetalOverrides, apply_metal_overrides,
    gadgets::public_transfer_statement::execution_effect::SourceExecutionEffectStatement,
    offline_compact::{
        self, ExecutionEffectVerificationLimits, ExpectedExecutionEffects, ProvingError,
        ProvingLimits,
    },
    set_metal_queue_policy,
};
use iroha_allocation::{AllocationBudget, AllocationReservation};
use iroha_config::parameters::actual::{Fastpq, FastpqExecutionMode, FastpqPoseidonMode};
use iroha_crypto::HashOf;
use iroha_data_model::{block::BlockHeader, fastpq::FastpqArtifactIdentityDescriptionV1};
use iroha_futures::supervisor::ShutdownSignal;
use iroha_logger::{debug, info, warn};
use std::{
    sync::{
        Arc, Mutex, MutexGuard, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};
use tokio::sync::{mpsc, oneshot};

/// Handle for a bounded original-source work queue.
#[derive(Clone)]
pub struct FastpqLaneHandle {
    tx: mpsc::Sender<WorkRequest>,
    generation: u64,
    backpressure: Option<crate::queue::BackpressureHandle>,
    ready: Arc<AtomicBool>,
}
/// Local queue refusal; it never consumes the original source owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FastpqQueueRefusal {
    Unavailable,
    Backpressure,
    Full,
    Closed,
}
impl FastpqLaneHandle {
    /// Retain the returned receiver until it yields the original source and result.
    /// A refusal returns the exact original job; retry never reconstructs authority.
    pub(crate) fn submit(
        &self,
        job: FastpqWitnessJob,
    ) -> Result<oneshot::Receiver<FastpqJobOutcome>, (FastpqWitnessJob, FastpqQueueRefusal)> {
        if self.generation != 0
            && !lock_global_lane().current.as_ref().is_some_and(|active| {
                active.generation == self.generation && !active.shutdown.is_sent()
            })
        {
            return Err((job, FastpqQueueRefusal::Closed));
        }
        if !self.ready.load(Ordering::Acquire) {
            debug!(
                height = job.height(),
                view = job.view(),
                "fastpq lane: queueing while backend is initialising"
            );
        }
        if self
            .backpressure
            .as_ref()
            .is_some_and(|handle| handle.snapshot().is_saturated())
        {
            return Err((job, FastpqQueueRefusal::Backpressure));
        }
        let (reply, receiver) = oneshot::channel();
        match self.tx.try_send(WorkRequest {
            job: Some(job),
            reply: Some(reply),
        }) {
            Ok(()) => Ok(receiver),
            Err(mpsc::error::TrySendError::Full(request)) => {
                Err((request.into_parts().0, FastpqQueueRefusal::Full))
            }
            Err(mpsc::error::TrySendError::Closed(request)) => {
                Err((request.into_parts().0, FastpqQueueRefusal::Closed))
            }
        }
    }
    #[cfg(test)]
    fn is_ready_for_test(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }
}
struct WorkRequest {
    job: Option<FastpqWitnessJob>,
    reply: Option<oneshot::Sender<FastpqJobOutcome>>,
}
impl WorkRequest {
    fn into_parts(mut self) -> (FastpqWitnessJob, oneshot::Sender<FastpqJobOutcome>) {
        (
            self.job.take().expect("original queued job"),
            self.reply.take().expect("original completion sender"),
        )
    }
}
impl Drop for WorkRequest {
    fn drop(&mut self) {
        // Receiver destruction (including async supervisor cancellation) returns
        // every not-yet-started original job instead of silently dropping custody.
        if let (Some(job), Some(reply)) = (self.job.take(), self.reply.take()) {
            deliver(
                reply,
                FastpqJobOutcome::Deferred {
                    job,
                    error: FastpqWorkRefusal::WorkerStopped,
                },
            );
        }
    }
}
/// Move-only job; metadata comes only from the retained actual native result.
/// TODO: connect completed entries to durable proof admission before automatic dispatch.
pub(crate) struct FastpqWitnessJob {
    source: AdmittedFinalizedFastpqSource,
    next_statement: usize,
}
impl std::fmt::Debug for FastpqWitnessJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FastpqWitnessJob")
            .field("height", &self.height())
            .field("next_statement", &self.next_statement)
            .finish_non_exhaustive()
    }
}
impl FastpqWitnessJob {
    pub(crate) fn from_finalized(
        source: FinalizedFastpqSource,
    ) -> Result<Self, (FinalizedFastpqSource, FinalizedFastpqWorkError)> {
        Ok(Self {
            source: source.into_work()?,
            next_statement: 0,
        })
    }
    pub(crate) fn height(&self) -> u64 {
        self.source.native().committed().height()
    }
    pub(crate) fn block_hash(&self) -> HashOf<BlockHeader> {
        self.source.native().block().hash()
    }
    pub(crate) fn view(&self) -> u64 {
        self.source.native().block().header().view_change_index()
    }
}
/// Production output is the original successful facade owner. Component-only
/// test outputs cannot manufacture its private verification receipt.
#[derive(Debug)]
enum FastpqProofOutput {
    Produced(offline_compact::ProducedExecutionEffectArtifact),
    #[cfg(test)]
    Component {
        proof_bytes: Vec<u8>,
        identity: FastpqArtifactIdentityDescriptionV1,
    },
}
impl FastpqProofOutput {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Produced(value) => value.bytes(),
            #[cfg(test)]
            Self::Component { proof_bytes, .. } => proof_bytes,
        }
    }
    fn identity(&self) -> &FastpqArtifactIdentityDescriptionV1 {
        match self {
            Self::Produced(value) => value.verified().identity(),
            #[cfg(test)]
            Self::Component { identity, .. } => identity,
        }
    }
}
/// A completed entry keeps the exact original source and complete artifact inseparable.
/// Metadata-only Kura sidecars do not consume or acknowledge this owner.
pub(crate) struct FastpqCompletedEntry {
    job: FastpqWitnessJob,
    output: FastpqProofOutput,
    generation: u64,
}
impl FastpqCompletedEntry {
    /// Original worker generation. It is not a durable-storage acknowledgement.
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
    /// A point-in-time lifecycle observation, never authority to persist after shutdown.
    pub(crate) fn generation_is_current(&self) -> bool {
        lock_global_lane().current.as_ref().is_some_and(|active| {
            active.generation == self.generation && !active.shutdown.is_sent()
        })
    }
    pub(crate) fn source(&self) -> &FinalizedFastpqSource {
        self.job.source.original()
    }
    pub(crate) fn statement_index(&self) -> usize {
        self.job.next_statement
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        self.output.bytes()
    }
    pub(crate) fn identity(&self) -> &FastpqArtifactIdentityDescriptionV1 {
        self.output.identity()
    }
    pub(crate) fn verified(&self) -> Option<&offline_compact::VerifiedArtifact> {
        match &self.output {
            FastpqProofOutput::Produced(value) => Some(value.verified()),
            #[cfg(test)]
            FastpqProofOutput::Component { .. } => None,
        }
    }
    /// Explicit retry preserves the original cursor/source; it grants no durable acknowledgement.
    pub(crate) fn retry(self) -> FastpqWitnessJob {
        self.job
    }
}
/// One entry per turn bounds retained artifacts independently of source entry count.
pub(crate) enum FastpqJobOutcome {
    Complete(FastpqCompletedEntry),
    Deferred {
        job: FastpqWitnessJob,
        error: FastpqWorkRefusal,
    },
    Exhausted(FastpqWitnessJob),
}
#[derive(Debug, thiserror::Error)]
pub(crate) enum FastpqWorkRefusal {
    #[error("FASTPQ completion receiver was explicitly cancelled")]
    ReceiverCancelled,
    #[error("FASTPQ lane is shutting down")]
    Shutdown,
    #[error("FASTPQ worker stopped before processing the queued original source")]
    WorkerStopped,
    #[error("FASTPQ background producer panicked; original source returned")]
    BackendPanicked,
    #[error("FASTPQ backend is unavailable")]
    BackendUnavailable,
    #[error(transparent)]
    Source(#[from] source::SourceWorkError),
    #[error(transparent)]
    Prove(#[from] ProvingError),
}
/// Private backend injection cannot create a finalized job or replace source expectations.
trait FastpqProofEngine: Send + Sync + 'static {
    fn limits(&self) -> (ProvingLimits, ExecutionEffectVerificationLimits);
    fn prove(
        &self,
        statement: &SourceExecutionEffectStatement<'_>,
        expected: ExpectedExecutionEffects<'_>,
        budget: &AllocationBudget,
        reservation: &mut AllocationReservation,
    ) -> Result<FastpqProofOutput, ProvingError>;
}
struct RealProofEngine {
    proving: ProvingLimits,
    verification: ExecutionEffectVerificationLimits,
}
impl FastpqProofEngine for RealProofEngine {
    fn limits(&self) -> (ProvingLimits, ExecutionEffectVerificationLimits) {
        (self.proving, self.verification)
    }
    fn prove(
        &self,
        statement: &SourceExecutionEffectStatement<'_>,
        expected: ExpectedExecutionEffects<'_>,
        budget: &AllocationBudget,
        reservation: &mut AllocationReservation,
    ) -> Result<FastpqProofOutput, ProvingError> {
        // The facade owner retains the mandatory self-verifier identity;
        // no extra verification or second allocation reservation is performed here.
        let produced = offline_compact::prove_quantity_ordinary_artifact(
            statement,
            expected,
            self.proving,
            &self.verification,
            budget,
            reservation,
        )?;
        Ok(FastpqProofOutput::Produced(produced))
    }
}
struct RegisteredFastpqLane {
    generation: u64,
    handle: FastpqLaneHandle,
    shutdown: ShutdownSignal,
}
#[derive(Default)]
struct FastpqLaneRegistry {
    generation: u64,
    current: Option<RegisteredFastpqLane>,
}
struct FastpqLaneGenerationLease {
    generation: u64,
}
impl Drop for FastpqLaneGenerationLease {
    fn drop(&mut self) {
        // The async worker and any live `spawn_blocking` operation share this lease. A
        // supervisor abort can therefore drop the worker without making a replacement lane
        // visible until the detached blocking operation has actually stopped.
        clear_generation(self.generation);
    }
}
static GLOBAL_LANE: OnceLock<Mutex<FastpqLaneRegistry>> = OnceLock::new();
#[cfg(test)]
static TEST_ENGINE: OnceLock<Arc<dyn FastpqProofEngine>> = OnceLock::new();
fn global_lane() -> &'static Mutex<FastpqLaneRegistry> {
    GLOBAL_LANE.get_or_init(|| Mutex::new(FastpqLaneRegistry::default()))
}
fn lock_global_lane() -> MutexGuard<'static, FastpqLaneRegistry> {
    match global_lane().lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            warn!("fastpq lane registry mutex was poisoned; recovering registry state");
            poisoned.into_inner()
        }
    }
}
/// Start the FASTPQ prover lane. Returns the handle and the spawned task when successful.
pub fn start(cfg: &Fastpq) -> Option<(FastpqLaneHandle, tokio::task::JoinHandle<()>)> {
    start_with_backpressure(cfg, None, None)
}
/// Start the FASTPQ prover lane with optional queue backpressure.
/// Kura lifecycle context remains supplied by the node, but metadata snapshots do not
/// acknowledge the complete artifact; automatic durable dispatch is still pending.
pub fn start_with_backpressure(
    cfg: &Fastpq,
    backpressure: Option<crate::queue::BackpressureHandle>,
    kura: Option<Arc<Kura>>,
) -> Option<(FastpqLaneHandle, tokio::task::JoinHandle<()>)> {
    start_with_options(cfg, backpressure, kura, None)
}
/// Start the FASTPQ prover lane with queue integration and a node shutdown signal.
pub fn start_with_backpressure_and_shutdown(
    cfg: &Fastpq,
    backpressure: Option<crate::queue::BackpressureHandle>,
    kura: Option<Arc<Kura>>,
    shutdown: ShutdownSignal,
) -> Option<(FastpqLaneHandle, tokio::task::JoinHandle<()>)> {
    start_with_options(cfg, backpressure, kura, Some(shutdown))
}
fn start_with_options(
    cfg: &Fastpq,
    backpressure: Option<crate::queue::BackpressureHandle>,
    kura: Option<Arc<Kura>>,
    external_shutdown: Option<ShutdownSignal>,
) -> Option<(FastpqLaneHandle, tokio::task::JoinHandle<()>)> {
    let cfg = cfg.clone();
    start_with_builder(backpressure, kura, external_shutdown, move || {
        build_engine(&cfg)
    })
}
fn start_with_builder(
    backpressure: Option<crate::queue::BackpressureHandle>,
    kura: Option<Arc<Kura>>,
    external_shutdown: Option<ShutdownSignal>,
    build_engine: impl FnOnce() -> Option<Arc<dyn FastpqProofEngine>> + Send + 'static,
) -> Option<(FastpqLaneHandle, tokio::task::JoinHandle<()>)> {
    let mut registry = lock_global_lane();
    if registry.current.is_some() {
        return None;
    }
    registry.generation = registry
        .generation
        .checked_add(1)
        .expect("FASTPQ lane generation exhausted");
    let generation = registry.generation;
    let (tx, rx) = mpsc::channel::<WorkRequest>(32);
    let ready = Arc::new(AtomicBool::new(false));
    let handle = FastpqLaneHandle {
        tx,
        generation,
        backpressure,
        ready: Arc::clone(&ready),
    };
    let shutdown = ShutdownSignal::new();
    registry.current = Some(RegisteredFastpqLane {
        generation,
        handle: handle.clone(),
        shutdown: shutdown.clone(),
    });
    // A new generation must start fail-closed. `build_engine` performs the one hardware
    // preflight for this generation and enables the digest path only after it succeeds.
    crate::fastpq::set_poseidon_digest_acceleration_enabled(false);
    drop(registry);
    let generation_lease = Arc::new(FastpqLaneGenerationLease { generation });
    let task = spawn_worker(
        rx,
        ready,
        kura,
        generation_lease,
        shutdown,
        external_shutdown,
        build_engine,
    );
    Some((handle, task))
}
/// Submit only an original native source job, preserving it on every queue refusal.
pub(crate) fn try_submit(
    job: FastpqWitnessJob,
) -> Result<oneshot::Receiver<FastpqJobOutcome>, (FastpqWitnessJob, FastpqQueueRefusal)> {
    let handle = lock_global_lane()
        .current
        .as_ref()
        .map(|registered| registered.handle.clone());
    match handle {
        Some(handle) => handle.submit(job),
        None => Err((job, FastpqQueueRefusal::Unavailable)),
    }
}
/// Request shutdown of the active FASTPQ lane, if any.
pub fn shutdown() {
    let shutdown = lock_global_lane()
        .current
        .as_ref()
        .map(|registered| registered.shutdown.clone());
    if let Some(shutdown) = shutdown {
        shutdown.send();
    }
}
fn clear_generation(generation: u64) {
    let mut registry = lock_global_lane();
    if registry
        .current
        .as_ref()
        .is_some_and(|registered| registered.generation == generation)
    {
        if let Some(registered) = registry.current.take() {
            registered.handle.ready.store(false, Ordering::Release);
        }
    }
}
fn build_engine(cfg: &Fastpq) -> Option<Arc<dyn FastpqProofEngine>> {
    #[cfg(test)]
    if let Some(engine) = TEST_ENGINE.get().cloned() {
        return Some(engine);
    }
    if let Err(err) = apply_metal_overrides(metal_overrides_from_config(cfg)) {
        warn!(%err, "fastpq lane: failed to apply Metal overrides");
    }
    if let Err(err) =
        set_metal_queue_policy(cfg.metal_queue_fanout, cfg.metal_queue_column_threshold)
    {
        warn!(%err, "fastpq lane: failed to apply Metal queue policy override");
    }
    let digest_execution = match configured_digest_execution(cfg) {
        Ok(execution) => execution,
        Err(err) => {
            warn!(%err, "fastpq lane: required digest device failed preflight");
            return None;
        }
    };
    let mut verification = ExecutionEffectVerificationLimits::default();
    verification.transport.max_wire_bytes = verification
        .transport
        .max_wire_bytes
        .min(usize::try_from(cfg.proof_sidecar_max_bytes.get()).unwrap_or(usize::MAX));
    Some(Arc::new(RealProofEngine {
        proving: ProvingLimits {
            digest_execution,
            ..ProvingLimits::default()
        },
        verification,
    }))
}
fn configured_digest_execution(cfg: &Fastpq) -> fastpq_prover::Result<DigestExecutionV1> {
    let required_device = matches!(cfg.execution_mode, FastpqExecutionMode::Gpu)
        || matches!(cfg.poseidon_mode, FastpqPoseidonMode::Gpu);
    if !required_device {
        crate::fastpq::set_poseidon_digest_acceleration_enabled(false);
        return Ok(DigestExecutionV1::Cpu);
    }
    #[cfg(feature = "fastpq-gpu")]
    {
        let backend = if cfg!(target_os = "macos") {
            fastpq_prover::Digest384GpuBackendV1::Metal
        } else {
            fastpq_prover::Digest384GpuBackendV1::Cuda
        };
        fastpq_prover::preflight_digest384_continuation_v1(backend).map_err(|error| {
            fastpq_prover::Error::NativeDigestExecution {
                details: error.to_string(),
            }
        })?;
        let enabled = crate::fastpq::poseidon_digest_acceleration_configured(cfg)
            && fastpq_prover::preflight_bn254_poseidon_word_batches();
        crate::fastpq::set_poseidon_digest_acceleration_enabled(enabled);
        Ok(DigestExecutionV1::Device(backend))
    }
    #[cfg(not(feature = "fastpq-gpu"))]
    Err(fastpq_prover::Error::NativeDigestExecution {
        details: "required FASTPQ digest device support is not compiled".into(),
    })
}
fn spawn_worker(
    mut rx: mpsc::Receiver<WorkRequest>,
    ready: Arc<AtomicBool>,
    _kura: Option<Arc<Kura>>,
    generation_lease: Arc<FastpqLaneGenerationLease>,
    shutdown: ShutdownSignal,
    external_shutdown: Option<ShutdownSignal>,
    build_engine: impl FnOnce() -> Option<Arc<dyn FastpqProofEngine>> + Send + 'static,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let engine_generation_lease = Arc::clone(&generation_lease);
        let mut engine_task = tokio::task::spawn_blocking(move || {
            let _generation_lease = engine_generation_lease;
            build_engine()
        });
        let engine_result = tokio::select! {
            result = &mut engine_task => Some(result),
            () = wait_for_shutdown(shutdown.clone(), external_shutdown.clone()) => None,
        };
        let Some(engine_result) = engine_result else {
            rx.close();
            // `spawn_blocking` work cannot be cancelled after it starts. Keep this generation
            // registered until initialisation actually finishes so a retry cannot race global
            // Metal/prover setup from the retiring worker.
            let _ = engine_task.await;
            return_buffered(&mut rx, true);
            return;
        };
        let engine = match engine_result {
            Ok(Some(engine)) => engine,
            Ok(None) => {
                warn!("fastpq lane: failed to initialise prover backend; lane disabled");
                rx.close();
                return_buffered(&mut rx, false);
                return;
            }
            Err(err) => {
                warn!(
                    ?err,
                    "fastpq lane: prover backend initialisation task panicked"
                );
                rx.close();
                return_buffered(&mut rx, false);
                return;
            }
        };
        ready.store(true, Ordering::Release);
        loop {
            let job = tokio::select! {
                job = rx.recv() => job,
                () = wait_for_shutdown(shutdown.clone(), external_shutdown.clone()) => {
                    rx.close();
                    None
                },
            };
            let Some(request) = job else {
                break;
            };
            let (job, reply) = request.into_parts();
            if reply.is_closed() {
                // Caller explicitly abandoned its receipt before proof work. Drop
                // this original owner with an observable cancellation disposition.
                deliver(
                    reply,
                    FastpqJobOutcome::Deferred {
                        job,
                        error: FastpqWorkRefusal::ReceiverCancelled,
                    },
                );
                continue;
            }
            let engine = Arc::clone(&engine);
            let prove_shutdown = shutdown.clone();
            let prove_external_shutdown = external_shutdown.clone();
            let prove_generation_lease = Arc::clone(&generation_lease);
            let mut prove_task = tokio::task::spawn_blocking(move || {
                let generation = prove_generation_lease.generation;
                let _generation_lease = prove_generation_lease;
                let outcome = process_job(
                    &engine,
                    job,
                    generation,
                    &prove_shutdown,
                    prove_external_shutdown.as_ref(),
                );
                deliver(reply, outcome);
            });
            tokio::select! {
                result = &mut prove_task => {
                    if let Err(err) = result {
                        warn!(?err, "fastpq lane: prover task panicked");
                    }
                }
                () = wait_for_shutdown(shutdown.clone(), external_shutdown.clone()) => {
                    rx.close();
                    // Blocking work finishes naturally. Keep its generation until it
                    // returns original custody; no old worker can cross a restart unnoticed.
                    if let Err(err) = prove_task.await {
                        warn!(?err, "fastpq lane: prover task panicked during shutdown");
                    }
                    break;
                }
            }
        }
        return_buffered(&mut rx, true);
        ready.store(false, Ordering::Release);
    })
}
async fn wait_for_shutdown(shutdown: ShutdownSignal, external: Option<ShutdownSignal>) {
    if let Some(external) = external {
        tokio::select! {
            () = shutdown.receive() => {}
            () = external.receive() => {}
        }
    } else {
        shutdown.receive().await;
    }
}
fn metal_overrides_from_config(cfg: &Fastpq) -> MetalOverrides {
    MetalOverrides {
        max_in_flight: cfg.metal_max_in_flight,
        threadgroup_size: cfg.metal_threadgroup_width,
        dispatch_trace: cfg.metal_trace,
        debug_enum: cfg.metal_debug_enum,
    }
}
fn return_buffered(rx: &mut mpsc::Receiver<WorkRequest>, shutdown: bool) {
    rx.close();
    while let Ok(request) = rx.try_recv() {
        let error = if shutdown {
            FastpqWorkRefusal::Shutdown
        } else {
            FastpqWorkRefusal::BackendUnavailable
        };
        let (job, reply) = request.into_parts();
        deliver(reply, FastpqJobOutcome::Deferred { job, error });
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Delivery {
    DeliveredToReceiver,
    ReceiverAbandoned,
}
fn deliver(reply: oneshot::Sender<FastpqJobOutcome>, outcome: FastpqJobOutcome) -> Delivery {
    match reply.send(outcome) {
        Ok(()) => Delivery::DeliveredToReceiver,
        Err(abandoned) => {
            let (job, artifact_bytes) = match &abandoned {
                FastpqJobOutcome::Complete(completed) => (&completed.job, completed.bytes().len()),
                FastpqJobOutcome::Deferred { job, .. } | FastpqJobOutcome::Exhausted(job) => {
                    (job, 0)
                }
            };
            warn!(
                height = job.height(),
                statement_index = job.next_statement,
                artifact_bytes,
                "fastpq lane: receiver abandoned completion; original source and local artifact are being dropped, no durable retention acknowledged"
            );
            drop(abandoned);
            Delivery::ReceiverAbandoned
        }
    }
}
fn process_job(
    engine: &Arc<dyn FastpqProofEngine>,
    job: FastpqWitnessJob,
    generation: u64,
    shutdown: &ShutdownSignal,
    external_shutdown: Option<&ShutdownSignal>,
) -> FastpqJobOutcome {
    if shutdown_requested(shutdown, external_shutdown) {
        return FastpqJobOutcome::Deferred {
            job,
            error: FastpqWorkRefusal::Shutdown,
        };
    }
    if job.next_statement == job.source.leaves().len() {
        return FastpqJobOutcome::Exhausted(job);
    }
    let started = Instant::now();
    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prove_entry(engine, &job)))
            .unwrap_or_else(|_| Err(FastpqWorkRefusal::BackendPanicked));
    // Blocking proof work finishes naturally, but shutdown prevents handing a
    // completion to persistence. Return original source for an explicit later retry.
    if shutdown_requested(shutdown, external_shutdown) {
        return FastpqJobOutcome::Deferred {
            job,
            error: FastpqWorkRefusal::Shutdown,
        };
    }
    match result {
        Ok(output) => {
            info!(
                height = job.height(),
                view = job.view(),
                statement_index = job.next_statement,
                proof_bytes = output.bytes().len(),
                elapsed_ms = started.elapsed().as_secs_f64() * 1_000.0,
                "fastpq lane: produced local completion awaiting receiver handoff"
            );
            FastpqJobOutcome::Complete(FastpqCompletedEntry {
                job,
                output,
                generation,
            })
        }
        Err(error) => FastpqJobOutcome::Deferred { job, error },
    }
}
fn prove_entry(
    engine: &Arc<dyn FastpqProofEngine>,
    job: &FastpqWitnessJob,
) -> Result<FastpqProofOutput, FastpqWorkRefusal> {
    let (proving, verification) = engine.limits();
    let mut prepared = source::prepare(&job.source, job.next_statement, proving, &verification)?;
    let expected = ExpectedExecutionEffects {
        source: prepared.original.leaf(),
        statement: prepared.expectations,
    };
    let output = engine.prove(
        &prepared.materialized.statement(),
        expected,
        prepared.original.pool(),
        &mut prepared.reservation,
    )?;
    Ok(output)
}
fn shutdown_requested(
    shutdown: &ShutdownSignal,
    external_shutdown: Option<&ShutdownSignal>,
) -> bool {
    shutdown.is_sent() || external_shutdown.is_some_and(ShutdownSignal::is_sent)
}
/// Install a deterministic FASTPQ engine for tests, bypassing the real prover backend.
///
/// This lets unit tests inject a mock [`FastpqProofEngine`] so the lane can
/// exercise batching logic without spawning the real GPU/CPU prover pipeline.
#[cfg(test)]
fn install_test_engine(engine: Arc<dyn FastpqProofEngine>) {
    let _ = TEST_ENGINE.set(engine);
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::fastpq::{
        DigestAccelerationTestGuard, FASTPQ_CANONICAL_PARAMETER_SET, FastpqPublicInputsTemplate,
        authority_digest, batches_from_bundles, transition_batch_to_dto,
    };
    use fastpq_prover::TransitionBatch;
    use iroha_crypto::Hash;
    use iroha_data_model::fastpq::{
        TransferDeltaTranscript, TransferTranscript, TransferTranscriptBundle,
    };
    use iroha_model_base::domain::DomainId;
    use iroha_primitives::numeric::Quantity;
    use iroha_test_samples::{ALICE_ID, BOB_ID};
    use std::{sync::atomic::AtomicBool, time::Duration};
    static LANE_REGISTRY_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    fn gpu_execution_cpu_poseidon_config() -> Fastpq {
        Fastpq {
            execution_mode: FastpqExecutionMode::Gpu,
            poseidon_mode: FastpqPoseidonMode::Cpu,
            proof_sidecar_queue_cap:
                iroha_config::parameters::defaults::zk::fastpq::PROOF_SIDECAR_QUEUE_CAP,
            proof_sidecar_max_bytes:
                iroha_config::parameters::defaults::zk::fastpq::PROOF_SIDECAR_MAX_BYTES,
            proof_sidecar_max_retries:
                iroha_config::parameters::defaults::zk::fastpq::PROOF_SIDECAR_MAX_RETRIES,
            device_class: None,
            chip_family: None,
            gpu_kind: None,
            metal_queue_fanout: None,
            metal_queue_column_threshold: None,
            metal_max_in_flight: None,
            metal_threadgroup_width: None,
            metal_trace: iroha_config::parameters::defaults::zk::fastpq::METAL_TRACE,
            metal_debug_enum: iroha_config::parameters::defaults::zk::fastpq::METAL_DEBUG_ENUM,
        }
    }
    #[tokio::test]
    async fn lane_processes_transcripts_with_mock_engine() {
        use tokio::time::{Instant, sleep};
        let _registry_lock = LANE_REGISTRY_TEST_LOCK.lock().await;
        let _digest_guard = DigestAccelerationTestGuard::new();
        let calls = Arc::new(std::sync::Mutex::new(0usize));
        install_test_engine(Arc::new(MockEngine {
            calls: Arc::clone(&calls),
        }));
        let cfg = Fastpq {
            execution_mode: FastpqExecutionMode::Cpu,
            poseidon_mode: FastpqPoseidonMode::Cpu,
            proof_sidecar_queue_cap:
                iroha_config::parameters::defaults::zk::fastpq::PROOF_SIDECAR_QUEUE_CAP,
            proof_sidecar_max_bytes:
                iroha_config::parameters::defaults::zk::fastpq::PROOF_SIDECAR_MAX_BYTES,
            proof_sidecar_max_retries:
                iroha_config::parameters::defaults::zk::fastpq::PROOF_SIDECAR_MAX_RETRIES,
            device_class: None,
            chip_family: None,
            gpu_kind: None,
            metal_queue_fanout: None,
            metal_queue_column_threshold: None,
            metal_max_in_flight: None,
            metal_threadgroup_width: None,
            metal_trace: iroha_config::parameters::defaults::zk::fastpq::METAL_TRACE,
            metal_debug_enum: iroha_config::parameters::defaults::zk::fastpq::METAL_DEBUG_ENUM,
        };
        let (handle, task) = start(&cfg).expect("lane starts");
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if handle.is_ready_for_test() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "fastpq lane mock engine did not initialise"
            );
            sleep(Duration::from_millis(10)).await;
        }
        let job = sample_job();
        let receipt = try_submit(job).expect("native job queues");
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if *calls.lock().unwrap() > 0 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "fastpq lane mock engine was not invoked"
            );
            sleep(Duration::from_millis(10)).await;
        }
        assert!(matches!(
            receipt.await.unwrap(),
            FastpqJobOutcome::Complete(_)
        ));
        shutdown();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("fastpq lane stops after shutdown")
            .expect("fastpq worker joins cleanly");
    }
    #[tokio::test]
    async fn worker_start_does_not_wait_for_backend_initialisation() {
        use std::time::Instant as StdInstant;
        use tokio::time::sleep;
        let (_tx, rx) = mpsc::channel::<WorkRequest>(1);
        let ready = Arc::new(AtomicBool::new(false));
        let started_at = StdInstant::now();
        let task = spawn_worker(
            rx,
            Arc::clone(&ready),
            None,
            Arc::new(FastpqLaneGenerationLease { generation: 0 }),
            ShutdownSignal::new(),
            None,
            || {
                std::thread::sleep(Duration::from_millis(200));
                None
            },
        );
        assert!(
            started_at.elapsed() < Duration::from_millis(100),
            "worker startup waited for backend initialisation"
        );
        assert!(!ready.load(Ordering::Acquire));
        sleep(Duration::from_millis(250)).await;
        assert!(!ready.load(Ordering::Acquire));
        task.await.expect("worker task joins");
    }
    #[tokio::test]
    async fn new_lane_generation_starts_with_digest_acceleration_disabled() {
        let _registry_lock = LANE_REGISTRY_TEST_LOCK.lock().await;
        let _digest_guard = DigestAccelerationTestGuard::new();
        crate::fastpq::set_poseidon_digest_acceleration_enabled(true);

        let (_handle, task) =
            start_with_builder(None, None, None, || None).expect("lane generation registers");
        assert!(
            !crate::fastpq::poseidon_digest_acceleration_enabled(),
            "a new lane must stay on the CPU digest path until its one preflight succeeds"
        );

        task.await.expect("failed worker joins cleanly");
    }
    #[tokio::test]
    async fn failed_backend_initialisation_allows_lane_retry() {
        use tokio::time::{Instant, sleep};
        let _registry_lock = LANE_REGISTRY_TEST_LOCK.lock().await;
        let _digest_guard = DigestAccelerationTestGuard::new();
        let (_failed_handle, failed_task) =
            start_with_builder(None, None, None, || None).expect("failed lane attempt registers");
        failed_task.await.expect("failed worker joins cleanly");
        assert!(
            lock_global_lane().current.is_none(),
            "failed generation must release the global lane registration"
        );

        let calls = Arc::new(std::sync::Mutex::new(0usize));
        let retry_calls = Arc::clone(&calls);
        let (retry_handle, retry_task) = start_with_builder(None, None, None, move || {
            Some(Arc::new(MockEngine { calls: retry_calls }))
        })
        .expect("lane retry registers");
        let deadline = Instant::now() + Duration::from_secs(1);
        while !retry_handle.is_ready_for_test() {
            assert!(
                Instant::now() < deadline,
                "retried lane did not become ready"
            );
            sleep(Duration::from_millis(10)).await;
        }
        shutdown();
        tokio::time::timeout(Duration::from_secs(1), retry_task)
            .await
            .expect("retried lane observes shutdown")
            .expect("retried worker joins cleanly");
    }
    #[tokio::test]
    async fn external_shutdown_closes_idle_lane_receiver() {
        use tokio::time::{Instant, sleep};
        let _registry_lock = LANE_REGISTRY_TEST_LOCK.lock().await;
        let _digest_guard = DigestAccelerationTestGuard::new();
        let external_shutdown = ShutdownSignal::new();
        let calls = Arc::new(std::sync::Mutex::new(0usize));
        let (handle, task) =
            start_with_builder(None, None, Some(external_shutdown.clone()), move || {
                Some(Arc::new(MockEngine { calls }))
            })
            .expect("lane registers");
        let deadline = Instant::now() + Duration::from_secs(1);
        while !handle.is_ready_for_test() {
            assert!(Instant::now() < deadline, "lane did not become ready");
            sleep(Duration::from_millis(10)).await;
        }

        external_shutdown.send();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("idle lane exits on node shutdown")
            .expect("worker joins cleanly");
        assert!(
            lock_global_lane().current.is_none(),
            "shutdown generation must release the global lane registration"
        );
        assert!(
            matches!(
                handle.submit(sample_job()),
                Err((_, FastpqQueueRefusal::Closed))
            ),
            "closed lane receiver must reject submissions"
        );
    }
    #[tokio::test]
    async fn shutdown_keeps_generation_until_blocking_initialisation_finishes() {
        let _registry_lock = LANE_REGISTRY_TEST_LOCK.lock().await;
        let _digest_guard = DigestAccelerationTestGuard::new();
        let external_shutdown = ShutdownSignal::new();
        // Await startup without blocking this test's single Tokio thread.
        // Dropping the release sender also frees the blocking initializer if
        // an assertion fails, so runtime teardown cannot hang on the fixture.
        let (started, started_rx) = tokio::sync::oneshot::channel();
        let (release, release_rx) = std::sync::mpsc::channel();
        let (_handle, task) =
            start_with_builder(None, None, Some(external_shutdown.clone()), move || {
                if started.send(()).is_ok() {
                    let _ = release_rx.recv();
                }
                None
            })
            .expect("lane registers");
        tokio::time::timeout(Duration::from_secs(5), started_rx)
            .await
            .expect("blocking setup starts without blocking the runtime")
            .expect("blocking setup reports startup");
        external_shutdown.send();
        tokio::task::yield_now().await;
        assert!(
            lock_global_lane().current.is_some(),
            "retiring generation must remain registered while blocking setup is alive"
        );
        assert!(!task.is_finished());

        release
            .send(())
            .expect("blocking setup remains alive until explicitly released");
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("lane exits once blocking setup returns")
            .expect("worker joins cleanly");
        assert!(lock_global_lane().current.is_none());
    }
    #[tokio::test]
    async fn aborted_worker_releases_generation_after_blocking_initialisation_finishes() {
        use tokio::time::{Instant, sleep};
        let _registry_lock = LANE_REGISTRY_TEST_LOCK.lock().await;
        let _digest_guard = DigestAccelerationTestGuard::new();
        let external_shutdown = ShutdownSignal::new();
        // Await startup without blocking this test's single Tokio thread.
        // Dropping the release sender also frees the blocking initializer if
        // an assertion fails, so runtime teardown cannot hang on the fixture.
        let (started, started_rx) = tokio::sync::oneshot::channel();
        let (release, release_rx) = std::sync::mpsc::channel();
        let (_handle, task) =
            start_with_builder(None, None, Some(external_shutdown.clone()), move || {
                if started.send(()).is_ok() {
                    let _ = release_rx.recv();
                }
                None
            })
            .expect("lane registers");
        tokio::time::timeout(Duration::from_secs(5), started_rx)
            .await
            .expect("blocking setup starts without blocking the runtime")
            .expect("blocking setup reports startup");
        external_shutdown.send();
        task.abort();
        let join_error = task.await.expect_err("aborted worker reports cancellation");
        assert!(join_error.is_cancelled());
        assert!(
            lock_global_lane().current.is_some(),
            "detached blocking setup must retain its generation lease"
        );

        release
            .send(())
            .expect("blocking setup remains alive until explicitly released");
        let deadline = Instant::now() + Duration::from_secs(1);
        while lock_global_lane().current.is_some() {
            assert!(
                Instant::now() < deadline,
                "completed detached setup did not release the lane generation"
            );
            sleep(Duration::from_millis(10)).await;
        }
    }
    #[test]
    fn handle_buffers_jobs_while_backend_is_initialising() {
        let (tx, mut rx) = mpsc::channel(1);
        let handle = FastpqLaneHandle {
            tx,
            generation: 0,
            backpressure: None,
            ready: Arc::new(AtomicBool::new(false)),
        };
        let job = sample_job();
        let height = job.height();
        let view = job.view();
        let original = std::ptr::from_ref(job.source.entry(0).unwrap().effects()) as usize;
        let _receipt = handle.submit(job).expect("native pre-ready job queues");
        let queued = rx
            .try_recv()
            .expect("pre-ready job is buffered")
            .into_parts()
            .0;
        assert_eq!(queued.height(), height);
        assert_eq!(queued.view(), view);
        assert_eq!(
            std::ptr::from_ref(queued.source.entry(0).unwrap().effects()) as usize,
            original
        );
    }
    #[derive(Clone)]
    struct MockEngine {
        calls: Arc<std::sync::Mutex<usize>>,
    }
    impl FastpqProofEngine for MockEngine {
        fn limits(&self) -> (ProvingLimits, ExecutionEffectVerificationLimits) {
            (
                ProvingLimits::default(),
                ExecutionEffectVerificationLimits::default(),
            )
        }
        fn prove(
            &self,
            statement: &SourceExecutionEffectStatement<'_>,
            expected: ExpectedExecutionEffects<'_>,
            budget: &AllocationBudget,
            reservation: &mut AllocationReservation,
        ) -> Result<FastpqProofOutput, ProvingError> {
            assert!(reservation.belongs_to(budget));
            assert_eq!(
                expected.source.effects_digest,
                <[u8; 32]>::from(expected.statement.effects_digest)
            );
            assert_eq!(expected.statement.public_inputs, statement.public_inputs());
            assert_eq!(
                expected.statement.statement_digest,
                statement
                    .digest(self.limits().1.public_statement.max_public_bytes)
                    .unwrap()
            );
            *self.calls.lock().unwrap() += 1;
            let proof_bytes = b"component-only-fastpq-proof".to_vec();
            Ok(FastpqProofOutput::Component {
                identity: mock_identity(statement, &proof_bytes),
                proof_bytes,
            })
        }
    }
    struct ShutdownDuringProofEngine {
        shutdown: ShutdownSignal,
    }
    impl FastpqProofEngine for ShutdownDuringProofEngine {
        fn limits(&self) -> (ProvingLimits, ExecutionEffectVerificationLimits) {
            (
                ProvingLimits::default(),
                ExecutionEffectVerificationLimits::default(),
            )
        }
        fn prove(
            &self,
            statement: &SourceExecutionEffectStatement<'_>,
            _expected: ExpectedExecutionEffects<'_>,
            _budget: &AllocationBudget,
            _reservation: &mut AllocationReservation,
        ) -> Result<FastpqProofOutput, ProvingError> {
            self.shutdown.send();
            let proof_bytes = b"proof-completed-after-shutdown".to_vec();
            Ok(FastpqProofOutput::Component {
                identity: mock_identity(statement, &proof_bytes),
                proof_bytes,
            })
        }
    }
    fn sample_bundle() -> TransferTranscriptBundle {
        let mut bundle = TransferTranscriptBundle {
            entry_hash: Hash::prehashed([0x11; 32]),
            transcripts: vec![TransferTranscript {
                batch_hash: Hash::prehashed([0x22; 32]),
                deltas: vec![TransferDeltaTranscript {
                    from_account: (*ALICE_ID).clone(),
                    to_account: (*BOB_ID).clone(),
                    asset_definition:
                        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                            DomainId::try_new("wonderland", "universal").unwrap(),
                            "rose".parse().unwrap(),
                        ),
                    amount: Quantity::from(10u32),
                    from_balance_before: Quantity::from(100u32),
                    from_balance_after: Quantity::from(90u32),
                    to_balance_before: Quantity::from(5u32),
                    to_balance_after: Quantity::from(15u32),
                    from_smt_witness: iroha_data_model::fastpq::TransferSmtWitness::default(),
                    to_smt_witness: iroha_data_model::fastpq::TransferSmtWitness::default(),
                }],
                authority_digest: authority_digest(&ALICE_ID),
                poseidon_preimage_digest: None,
            }],
        };
        let transcript = &mut bundle.transcripts[0];
        transcript.poseidon_preimage_digest = Some(crate::fastpq::poseidon_preimage_digest(
            &transcript.deltas[0],
            &transcript.batch_hash,
        ));
        bundle
    }
    fn sample_batches(bundle: &TransferTranscriptBundle) -> Vec<TransitionBatch> {
        batches_from_bundles(
            FASTPQ_CANONICAL_PARAMETER_SET,
            FastpqPublicInputsTemplate {
                dsid: [0; 16],
                slot: 0,
                old_root: [0; 32],
                new_root: [0; 32],
                perm_root: [0; 32],
            },
            [0; 32],
            [bundle],
        )
        .expect("sample FASTPQ batch")
    }
    #[test]
    fn proof_completed_during_shutdown_is_not_enqueued() {
        let lane_shutdown = ShutdownSignal::new();
        let supervisor_shutdown = ShutdownSignal::new();
        let engine: Arc<dyn FastpqProofEngine> = Arc::new(ShutdownDuringProofEngine {
            shutdown: supervisor_shutdown.clone(),
        });
        let job = sample_job();
        let original_hash = job.block_hash();
        let tx_set_hash = job.source.leaves()[0].tx_set_hash;
        let prepared = prepare_job(&job);
        assert_eq!(job.source.leaves().len(), 1);
        assert_eq!(
            prepared
                .materialized
                .statement()
                .public_inputs()
                .tx_set_hash,
            tx_set_hash
        );
        drop(prepared);
        let kura = Kura::blank_kura_for_testing();
        let outcome = process_job(&engine, job, 0, &lane_shutdown, Some(&supervisor_shutdown));
        assert!(supervisor_shutdown.is_sent());
        assert!(!lane_shutdown.is_sent());
        assert_eq!(
            kura.fastpq_proof_queue_len_for_testing(),
            0,
            "a detached proof must not persist after shutdown"
        );
        let FastpqJobOutcome::Deferred {
            job,
            error: FastpqWorkRefusal::Shutdown,
        } = outcome
        else {
            panic!("shutdown returns original custody without completion")
        };
        assert_eq!(job.block_hash(), original_hash);
        job.source.verify_current().unwrap();
    }
    #[test]
    fn maps_config_to_metal_overrides() {
        let cfg = Fastpq {
            execution_mode: FastpqExecutionMode::Gpu,
            poseidon_mode: FastpqPoseidonMode::Gpu,
            proof_sidecar_queue_cap:
                iroha_config::parameters::defaults::zk::fastpq::PROOF_SIDECAR_QUEUE_CAP,
            proof_sidecar_max_bytes:
                iroha_config::parameters::defaults::zk::fastpq::PROOF_SIDECAR_MAX_BYTES,
            proof_sidecar_max_retries:
                iroha_config::parameters::defaults::zk::fastpq::PROOF_SIDECAR_MAX_RETRIES,
            device_class: None,
            chip_family: None,
            gpu_kind: None,
            metal_queue_fanout: None,
            metal_queue_column_threshold: None,
            metal_max_in_flight: Some(8),
            metal_threadgroup_width: Some(256),
            metal_trace: true,
            metal_debug_enum: true,
        };
        let overrides = metal_overrides_from_config(&cfg);
        assert_eq!(overrides.max_in_flight, Some(8));
        assert_eq!(overrides.threadgroup_size, Some(256));
        assert!(overrides.dispatch_trace);
        assert!(overrides.debug_enum);
    }
    fn mock_identity(
        statement: &SourceExecutionEffectStatement<'_>,
        bytes: &[u8],
    ) -> FastpqArtifactIdentityDescriptionV1 {
        use iroha_data_model::fastpq::{
            FastpqCommitmentDescriptionV1, FastpqOrderedCompactAirCommitmentsV1, FastpqProofKindV1,
        };
        FastpqArtifactIdentityDescriptionV1 {
            proof_kind: FastpqProofKindV1::OrdinaryCompact,
            profile_id: offline_compact::execution_effect_profile_id(),
            public_statement_digest: statement
                .digest(
                    ExecutionEffectVerificationLimits::default()
                        .public_statement
                        .max_public_bytes,
                )
                .unwrap()
                .into(),
            artifact_digest: Hash::new(bytes).into(),
            inner_bundle_digest: Hash::new(b"mock inner bundle").into(),
            artifact_bytes: u64::try_from(bytes.len()).unwrap(),
            commitments: FastpqCommitmentDescriptionV1::OrderedCompactAir(
                FastpqOrderedCompactAirCommitmentsV1 {
                    segment_count: 1,
                    segment_air_row_roots: vec![
                        iroha_data_model::fastpq::FastpqCommitmentV1::from_bytes([0x31; 32]),
                    ],
                },
            ),
        }
    }
    fn sample_job() -> FastpqWitnessJob {
        native_job(Quantity::from(100_u32), &[10])
    }
    fn native_job(balance: Quantity, amounts: &[u32]) -> FastpqWitnessJob {
        native_job_with_chain(balance, amounts).1
    }
    fn native_job_with_chain(
        balance: Quantity,
        amounts: &[u32],
    ) -> (
        crate::sumeragi::test_chain::CertifiedTestChain,
        FastpqWitnessJob,
    ) {
        let (chain, source) =
            crate::fastpq::finalized_source::test_fixture::original_source(balance, amounts);
        let job = match FastpqWitnessJob::from_finalized(source) {
            Ok(job) => job,
            Err((_, error)) => panic!("genuine source admission failed: {error}"),
        };
        // These assertions measure the whole original State pool, including its
        // serialized executor and archives. Their fixture owners must stay alive
        // until the measured handoff finishes; dropping its detached worker can
        // release unrelated charges concurrently with an exact source comparison.
        (chain, job)
    }
    fn prepare_job(job: &FastpqWitnessJob) -> source::PreparedSourceEntry<'_> {
        source::prepare(
            &job.source,
            job.next_statement,
            ProvingLimits::default(),
            &ExecutionEffectVerificationLimits::default(),
        )
        .unwrap()
    }
    #[test]
    fn finalized_job_preserves_full_quantities_context_and_original_entry_identity() {
        use iroha_data_model::fastpq::FastpqExecutionEffectKindV1;
        let job = native_job(Quantity::from(u128::MAX), &[10]);
        let original_entry = job.source.entry(0).unwrap();
        let original = norito::encode_canonical(original_entry.effects()).unwrap();
        let original_pointer = std::ptr::from_ref(original_entry.effects());
        let leaf = original_entry.leaf();
        let prepared = prepare_job(&job);
        assert_eq!(job.source.leaves().len(), 1);
        let statement = prepared.materialized.statement();
        assert_eq!(
            leaf.entry_hash,
            statement.effects().context.entry.entry_hash
        );
        let mut dsid = [0; 16];
        dsid[..8].copy_from_slice(&leaf.dataspace_id.as_u64().to_le_bytes());
        assert_eq!(statement.public_inputs().dsid, dsid);
        assert_eq!(statement.public_inputs().slot, leaf.slot);
        assert_eq!(statement.public_inputs().perm_root, leaf.perm_root);
        assert_eq!(statement.public_inputs().tx_set_hash, leaf.tx_set_hash);
        let FastpqExecutionEffectKindV1::Transfer(effect) = &statement.effects().effects[0].kind
        else {
            panic!("genuine transfer")
        };
        assert_eq!(effect.source_before, Quantity::from(u128::MAX));
        let owned: iroha_data_model::fastpq::FastpqExecutionEffectStatementV1 =
            norito::decode_canonical(&norito::encode_canonical(&statement).unwrap()).unwrap();
        assert_eq!(owned.transitions.len(), 2);
        assert_eq!(
            norito::encode_canonical(original_entry.effects()).unwrap(),
            original
        );
        assert!(std::ptr::eq(statement.effects(), original_pointer));
    }
    #[test]
    fn finalized_job_requires_source_context_and_rejects_missing_digest_without_repair() {
        // Mutate offered wire before the consuming immutable work admission.
        let (_, mut source) = crate::fastpq::finalized_source::test_fixture::original_source(
            Quantity::from(100_u32),
            &[10],
        );
        for mutation in 0..5 {
            source.offer_reconstructed_tamper_for_test(|offered| {
                let key=iroha_data_model::execution_witness::FASTPQ_ORDINARY_SOURCE_STATEMENTS_WITNESS_KEY_V1;
                match mutation {
                    0=>offered.writes.retain(|write|write.key!=key),
                    1=>offered.writes.iter_mut().find(|write|write.key==key).unwrap().value.clear(),
                    2=>offered.writes.iter_mut().find(|write|write.key==key).unwrap().value.push(0),
                    3=>offered.fastpq_transcripts[0].transcripts[0].poseidon_preimage_digest=None,
                    _=>{offered.fastpq_batches=sample_batches(&sample_bundle()).iter().map(transition_batch_to_dto).collect();offered.fastpq_transcripts.clear();}
                }
            });
            let before = norito::encode_canonical(source.offered_wire_for_test()).unwrap();
            let counts = AdmittedFinalizedFastpqSource::scan_counts_for_test();
            let (returned, error) = match FastpqWitnessJob::from_finalized(source) {
                Ok(_) => panic!("substituted source admitted"),
                Err(rejected) => rejected,
            };
            assert!(matches!(error, FinalizedFastpqWorkError::Native(_)));
            assert_eq!(
                norito::encode_canonical(returned.offered_wire_for_test()).unwrap(),
                before
            );
            assert_eq!(
                AdmittedFinalizedFastpqSource::scan_counts_for_test().2,
                counts.2,
                "substitution must fail before any archive digest visit"
            );
            source = returned;
        }
        let empty = native_job(Quantity::from(100_u32), &[]);
        assert!(empty.source.leaves().is_empty());
        empty.source.verify_current().unwrap();
    }
    #[test]
    fn finalized_job_requires_every_dataspace_before_any_private_materialization() {
        let (_, mut source) = crate::fastpq::finalized_source::test_fixture::original_source(
            Quantity::from(100_u32),
            &[3, 5],
        );
        let original_root = source.native().committed().result();
        for missing_position in 0..2 {
            source.offer_reconstructed_tamper_for_test(|offered| {
                offered.fastpq_transcripts.remove(missing_position);
            });
            let before = norito::encode_canonical(source.offered_wire_for_test()).unwrap();
            let reserved = source.pool().reserved_bytes();
            let (returned, error) = match FastpqWitnessJob::from_finalized(source) {
                Ok(_) => panic!("missing original source admitted"),
                Err(rejected) => rejected,
            };
            assert!(matches!(error, FinalizedFastpqWorkError::Native(_)));
            assert_eq!(
                returned.pool().reserved_bytes(),
                reserved,
                "missing source position {missing_position} reached private construction"
            );
            assert_eq!(
                norito::encode_canonical(returned.offered_wire_for_test()).unwrap(),
                before
            );
            assert_eq!(returned.native().committed().result(), original_root);
            source = returned;
        }
        source.offer_reconstructed_tamper_for_test(|_| {});
        let job = match FastpqWitnessJob::from_finalized(source) {
            Ok(job) => job,
            Err((_, error)) => panic!("original restored: {error}"),
        };
        let prepared = prepare_job(&job);
        let mut dsid = [0; 16];
        dsid[..8].copy_from_slice(&job.source.leaves()[0].dataspace_id.as_u64().to_le_bytes());
        assert_eq!(
            prepared.materialized.statement().public_inputs().dsid,
            dsid,
            "only the actual source dataspace supplies this input"
        );
    }
    #[test]
    fn precomputed_batches_cannot_override_finalized_statement_or_entry() {
        let (_, mut source) = crate::fastpq::finalized_source::test_fixture::original_source(
            Quantity::from(100_u32),
            &[10],
        );
        let original = norito::encode_canonical(source.entry(0).unwrap().effects()).unwrap();
        source.offer_reconstructed_tamper_for_test(|offered| {
            let mut batch = sample_batches(&sample_bundle()).remove(0);
            batch.public_inputs.tx_set_hash = [0xE1; 32];
            batch.public_inputs.dsid = [0xE2; 16];
            batch.metadata.clear();
            offered.fastpq_batches = vec![transition_batch_to_dto(&batch)];
        });
        let (mut source, error) = match FastpqWitnessJob::from_finalized(source) {
            Ok(_) => panic!("prebuilt offered source admitted"),
            Err(rejected) => rejected,
        };
        assert!(matches!(error, FinalizedFastpqWorkError::Native(_)));
        source.offer_reconstructed_tamper_for_test(|_| {});
        let job = match FastpqWitnessJob::from_finalized(source) {
            Ok(job) => job,
            Err((_, error)) => panic!("original restored: {error}"),
        };
        let prepared = prepare_job(&job);
        assert_eq!(
            norito::encode_canonical(prepared.materialized.effects()).unwrap(),
            original
        );
        assert_eq!(
            prepared.expectations.public_inputs.tx_set_hash,
            job.source.leaves()[0].tx_set_hash
        );
    }
    #[test]
    fn statement_expectations_are_canonical_and_bind_every_ambient_layout() {
        use fastpq_prover::gadgets::public_transfer_statement::execution_effect::ExecutionEffectExpectations;
        let job = sample_job();
        let prepared = prepare_job(&job);
        let statement = prepared.materialized.statement();
        let canonical = norito::encode_canonical(&statement).unwrap();
        let expected = prepared.expectations;
        let mut frame = b"fastpq:execution-effects:v1:statement|".to_vec();
        frame.extend_from_slice(&canonical);
        assert_eq!(expected.statement_digest, Hash::new(&frame));
        for flags in
            (u8::MIN..=u8::MAX).filter(|&flags| norito::core::validate_header_flags(flags).is_ok())
        {
            let _ambient = norito::core::DecodeFlagsGuard::enter(flags);
            assert_eq!(
                statement
                    .digest(
                        ExecutionEffectVerificationLimits::default()
                            .public_statement
                            .max_public_bytes
                    )
                    .unwrap(),
                expected.statement_digest
            );
            assert_eq!(norito::core::effective_decode_flags(), Some(flags));
        }
        let mut changed: iroha_data_model::fastpq::FastpqExecutionEffectStatementV1 =
            norito::decode_canonical(&canonical).unwrap();
        changed.ordering_hash[0] ^= 1;
        let altered = SourceExecutionEffectStatement::from_owned(&changed);
        let altered_expected = ExecutionEffectExpectations {
            statement_digest: altered
                .digest(
                    ExecutionEffectVerificationLimits::default()
                        .public_statement
                        .max_public_bytes,
                )
                .unwrap(),
            ..expected
        };
        assert_ne!(altered_expected, expected);
    }
    #[test]
    fn real_engine_enforces_artifact_output_limit_before_proof_work() {
        let job = sample_job();
        let mut verification = ExecutionEffectVerificationLimits::default();
        verification.transport.max_wire_bytes = 0;
        let engine: Arc<dyn FastpqProofEngine> = Arc::new(RealProofEngine {
            proving: ProvingLimits::default(),
            verification,
        });
        assert!(prove_entry(&engine, &job).is_err());
    }
    #[test]
    fn cpu_policy_uses_canonical_producer_without_device_readiness() {
        let _digest_guard = DigestAccelerationTestGuard::new();
        let mut cfg = gpu_execution_cpu_poseidon_config();
        cfg.execution_mode = FastpqExecutionMode::Cpu;
        assert_eq!(
            configured_digest_execution(&cfg).unwrap(),
            DigestExecutionV1::Cpu
        );
    }
    #[cfg(not(feature = "fastpq-gpu"))]
    #[test]
    fn explicit_device_policy_without_device_feature_fails_closed() {
        let _digest_guard = DigestAccelerationTestGuard::new();
        let mut cfg = gpu_execution_cpu_poseidon_config();
        assert!(configured_digest_execution(&cfg).is_err());
        cfg.execution_mode = FastpqExecutionMode::Cpu;
        cfg.poseidon_mode = FastpqPoseidonMode::Gpu;
        assert!(configured_digest_execution(&cfg).is_err());
    }
    #[test]
    fn full_queue_returns_the_exact_original_source_without_reconstruction() {
        let (tx, mut rx) = mpsc::channel(1);
        let handle = FastpqLaneHandle {
            tx,
            generation: 0,
            backpressure: None,
            ready: Arc::new(AtomicBool::new(true)),
        };
        let (_first_chain, first) = native_job_with_chain(Quantity::from(100_u32), &[10]);
        let first_hash = first.block_hash();
        let _first_receipt = handle.submit(first).expect("first queue slot");
        let (_second_chain, second) = native_job_with_chain(Quantity::from(100_u32), &[10]);
        let pointer = std::ptr::from_ref(second.source.entry(0).unwrap().effects()) as usize;
        let credits = second.source.pool().reserved_bytes();
        let Err((returned, refusal)) = handle.submit(second) else {
            panic!("bounded queue refuses");
        };
        assert_eq!(refusal, FastpqQueueRefusal::Full);
        assert_eq!(
            std::ptr::from_ref(returned.source.entry(0).unwrap().effects()) as usize,
            pointer
        );
        assert_eq!(returned.source.pool().reserved_bytes(), credits);
        returned.source.verify_current().unwrap();
        assert_eq!(
            rx.try_recv().unwrap().into_parts().0.block_hash(),
            first_hash
        );
    }
    #[test]
    fn receiver_destruction_returns_queued_original_source_to_waiting_submitter() {
        let (tx, rx) = mpsc::channel(1);
        let handle = FastpqLaneHandle {
            tx,
            generation: 0,
            backpressure: None,
            ready: Arc::new(AtomicBool::new(false)),
        };
        let job = sample_job();
        let pointer = std::ptr::from_ref(job.source.entry(0).unwrap().effects()) as usize;
        let mut receipt = handle.submit(job).expect("queued source");
        drop(rx);
        let FastpqJobOutcome::Deferred {
            job,
            error: FastpqWorkRefusal::WorkerStopped,
        } = receipt.try_recv().unwrap()
        else {
            panic!("worker destruction must return custody")
        };
        assert_eq!(
            std::ptr::from_ref(job.source.entry(0).unwrap().effects()) as usize,
            pointer
        );
        job.source.verify_current().unwrap();
    }
    #[test]
    fn original_pool_capacity_refusal_preserves_job_and_can_retry_after_release() {
        let calls = Arc::new(std::sync::Mutex::new(0));
        let engine: Arc<dyn FastpqProofEngine> = Arc::new(MockEngine {
            calls: Arc::clone(&calls),
        });
        let (_chain, job) = native_job_with_chain(Quantity::from(100_u32), &[10]);
        let pool = job.source.pool().clone();
        let before = pool.reserved_bytes();
        let demand = source::allocation_bytes(
            &job.source.entry(0).unwrap(),
            ProvingLimits::default(),
            &ExecutionEffectVerificationLimits::default(),
        )
        .unwrap();
        assert!(
            demand <= pool.limit_bytes(),
            "configured original pool must cover the ordinary native fixture"
        );
        let occupied = pool.try_reserve_bytes(pool.limit_bytes() - before).unwrap();
        let result = process_job(&engine, job, 0, &ShutdownSignal::new(), None);
        let FastpqJobOutcome::Deferred {
            job,
            error:
                FastpqWorkRefusal::Source(source::SourceWorkError::Allocation(
                    iroha_allocation::AllocationRefusal::Capacity {
                        requested_bytes,
                        reserved_bytes,
                        limit_bytes,
                        ..
                    },
                )),
        } = result
        else {
            panic!("exact original capacity refusal required")
        };
        assert_eq!(requested_bytes, demand);
        assert_eq!(reserved_bytes, pool.limit_bytes());
        assert_eq!(limit_bytes, pool.limit_bytes());
        assert_eq!(*calls.lock().unwrap(), 0);
        job.source.verify_current().unwrap();
        drop(occupied);
        assert_eq!(pool.reserved_bytes(), before);
        let FastpqJobOutcome::Complete(completed) =
            process_job(&engine, job, 0, &ShutdownSignal::new(), None)
        else {
            panic!("same original job retries")
        };
        assert_eq!(*calls.lock().unwrap(), 1);
        assert_eq!(completed.statement_index(), 0);
        assert_eq!(
            pool.reserved_bytes(),
            before,
            "temporary backing owners finish before completion; original source remains"
        );
    }
    struct RefusingEngine {
        panic: bool,
    }
    impl FastpqProofEngine for RefusingEngine {
        fn limits(&self) -> (ProvingLimits, ExecutionEffectVerificationLimits) {
            (
                ProvingLimits::default(),
                ExecutionEffectVerificationLimits::default(),
            )
        }
        fn prove(
            &self,
            _statement: &SourceExecutionEffectStatement<'_>,
            _expected: ExpectedExecutionEffects<'_>,
            _budget: &AllocationBudget,
            _reservation: &mut AllocationReservation,
        ) -> Result<FastpqProofOutput, ProvingError> {
            assert!(!self.panic, "component backend panic probe");
            Err(ProvingError::Busy)
        }
    }
    #[test]
    fn backend_refusal_and_panic_return_original_job_and_release_only_work_credit() {
        for panic in [false, true] {
            let (_chain, job) = native_job_with_chain(Quantity::from(100_u32), &[10]);
            let pointer = std::ptr::from_ref(job.source.entry(0).unwrap().effects()) as usize;
            let credits = job.source.pool().reserved_bytes();
            let engine: Arc<dyn FastpqProofEngine> = Arc::new(RefusingEngine { panic });
            let FastpqJobOutcome::Deferred { job, error } =
                process_job(&engine, job, 0, &ShutdownSignal::new(), None)
            else {
                panic!("backend cannot consume source on refusal")
            };
            assert!(if panic {
                matches!(error, FastpqWorkRefusal::BackendPanicked)
            } else {
                matches!(error, FastpqWorkRefusal::Prove(ProvingError::Busy))
            });
            assert_eq!(
                std::ptr::from_ref(job.source.entry(0).unwrap().effects()) as usize,
                pointer
            );
            assert_eq!(job.source.pool().reserved_bytes(), credits);
            job.source.verify_current().unwrap();
        }
    }
    #[test]
    fn receiver_cancellation_is_explicit_abandonment_not_retention() {
        let engine: Arc<dyn FastpqProofEngine> = Arc::new(MockEngine {
            calls: Arc::new(std::sync::Mutex::new(0)),
        });
        let (_chain, job) = native_job_with_chain(Quantity::from(100_u32), &[10]);
        let pool = job.source.pool().clone();
        let before = pool.reserved_bytes();
        let outcome = process_job(&engine, job, 0, &ShutdownSignal::new(), None);
        let FastpqJobOutcome::Complete(ref completed) = outcome else {
            panic!("component completion")
        };
        assert!(!completed.bytes().is_empty());
        assert!(
            completed.verified().is_none(),
            "component mock does not manufacture verified proof authority"
        );
        assert_eq!(pool.reserved_bytes(), before);
        let (reply, receiver) = oneshot::channel();
        drop(receiver);
        assert_eq!(deliver(reply, outcome), Delivery::ReceiverAbandoned);
        assert!(
            pool.reserved_bytes() < before,
            "explicit abandoned receiver releases original owners"
        );
    }
    #[tokio::test]
    async fn completed_receipt_retains_source_and_bytes_across_generation_retirement() {
        let _registry_lock = LANE_REGISTRY_TEST_LOCK.lock().await;
        let _digest_guard = DigestAccelerationTestGuard::new();
        let (handle, task) = start_with_builder(None, None, None, || {
            Some(Arc::new(MockEngine {
                calls: Arc::new(std::sync::Mutex::new(0)),
            }))
        })
        .expect("lane starts");
        let job = sample_job();
        let original_hash = job.block_hash();
        let original_pointer = std::ptr::from_ref(job.source.entry(0).unwrap().effects()) as usize;
        let receipt = handle.submit(job).expect("native source queues");
        let FastpqJobOutcome::Complete(completed) =
            tokio::time::timeout(Duration::from_secs(30), receipt)
                .await
                .expect("bounded native preparation completes")
                .unwrap()
        else {
            panic!("one retained completion")
        };
        assert_eq!(completed.generation(), handle.generation);
        assert!(completed.generation_is_current());
        assert!(!completed.bytes().is_empty());
        assert_eq!(
            completed.identity().artifact_bytes,
            u64::try_from(completed.bytes().len()).unwrap()
        );
        shutdown();
        task.await.unwrap();
        assert!(
            !completed.generation_is_current(),
            "retired completion is not a live-generation admission"
        );
        assert_eq!(completed.source().native().block().hash(), original_hash);
        assert_eq!(
            std::ptr::from_ref(completed.source().entry(0).unwrap().effects()) as usize,
            original_pointer
        );
        assert!(
            !completed.bytes().is_empty(),
            "receipt retains actual artifact bytes until explicitly consumed"
        );
        let retry = completed.retry();
        assert_eq!(
            retry.next_statement, 0,
            "retry grants no fabricated persistence acknowledgement"
        );
        assert_eq!(
            std::ptr::from_ref(retry.source.entry(0).unwrap().effects()) as usize,
            original_pointer
        );
    }
    #[tokio::test]
    async fn cancelled_receiver_prevents_background_proof_work() {
        let calls = Arc::new(std::sync::Mutex::new(0));
        let engine_calls = Arc::clone(&calls);
        let (tx, rx) = mpsc::channel(1);
        let job = sample_job();
        let (reply, receiver) = oneshot::channel();
        tx.try_send(WorkRequest {
            job: Some(job),
            reply: Some(reply),
        })
        .unwrap_or_else(|_| panic!("queue"));
        drop(receiver);
        drop(tx);
        let task = spawn_worker(
            rx,
            Arc::new(AtomicBool::new(false)),
            None,
            Arc::new(FastpqLaneGenerationLease { generation: 0 }),
            ShutdownSignal::new(),
            None,
            move || {
                Some(Arc::new(MockEngine {
                    calls: engine_calls,
                }))
            },
        );
        task.await.unwrap();
        assert_eq!(
            *calls.lock().unwrap(),
            0,
            "explicit cancellation precedes private work"
        );
    }
    #[tokio::test]
    async fn failed_initialization_returns_buffered_original_source() {
        let (tx, rx) = mpsc::channel(1);
        let job = sample_job();
        let pointer = std::ptr::from_ref(job.source.entry(0).unwrap().effects()) as usize;
        let (reply, receiver) = oneshot::channel();
        tx.try_send(WorkRequest {
            job: Some(job),
            reply: Some(reply),
        })
        .unwrap_or_else(|_| panic!("queue"));
        let task = spawn_worker(
            rx,
            Arc::new(AtomicBool::new(false)),
            None,
            Arc::new(FastpqLaneGenerationLease { generation: 0 }),
            ShutdownSignal::new(),
            None,
            || None,
        );
        task.await.unwrap();
        let FastpqJobOutcome::Deferred {
            job,
            error: FastpqWorkRefusal::BackendUnavailable,
        } = receiver.await.unwrap()
        else {
            panic!("failed initialization returns original source")
        };
        assert_eq!(
            std::ptr::from_ref(job.source.entry(0).unwrap().effects()) as usize,
            pointer
        );
        job.source.verify_current().unwrap();
    }
    #[test]
    fn authenticated_zero_effect_job_finishes_without_proving_or_inventing_artifact() {
        let calls = Arc::new(std::sync::Mutex::new(0));
        let engine: Arc<dyn FastpqProofEngine> = Arc::new(MockEngine {
            calls: Arc::clone(&calls),
        });
        let job = native_job(Quantity::from(100_u32), &[]);
        let hash = job.block_hash();
        let FastpqJobOutcome::Exhausted(job) =
            process_job(&engine, job, 0, &ShutdownSignal::new(), None)
        else {
            panic!("zero effects has no ordinary proof")
        };
        assert_eq!(job.block_hash(), hash);
        assert!(job.source.leaves().is_empty());
        assert_eq!(*calls.lock().unwrap(), 0);
        job.source.verify_current().unwrap();
    }
    #[test]
    fn work_admission_scans_source_once_and_each_original_tape_once() {
        for count in [1_usize, 2, 4] {
            let amounts = (1..=u32::try_from(count).unwrap()).collect::<Vec<_>>();
            let (_chain, source) = crate::fastpq::finalized_source::test_fixture::original_source(
                Quantity::from(100_u32),
                &amounts,
            );
            let before = AdmittedFinalizedFastpqSource::scan_counts_for_test();
            let source_bytes = norito::encode_canonical(source.manifest()).unwrap();
            let pool = source.pool().clone();
            let reserved = pool.reserved_bytes();
            let job = match FastpqWitnessJob::from_finalized(source) {
                Ok(job) => job,
                Err((_, error)) => panic!("genuine source: {error}"),
            };
            let admitted = AdmittedFinalizedFastpqSource::scan_counts_for_test();
            assert_eq!(
                (
                    admitted.0 - before.0,
                    admitted.1 - before.1,
                    admitted.2 - before.2,
                    admitted.3 - before.3
                ),
                (1, 2, count, 0),
                "one native check, two bounded wire passes and each original tape exactly once"
            );
            assert_eq!(
                pool.reserved_bytes(),
                reserved,
                "admission only shares the original charged handles"
            );
            for index in 0..count {
                let prepared = source::prepare(
                    &job.source,
                    index,
                    ProvingLimits::default(),
                    &ExecutionEffectVerificationLimits::default(),
                )
                .unwrap();
                assert_eq!(prepared.original.leaf(), &job.source.leaves()[index]);
                assert!(std::ptr::eq(
                    prepared.materialized.effects(),
                    prepared.original.effects()
                ));
                drop(prepared);
                let now = AdmittedFinalizedFastpqSource::scan_counts_for_test();
                assert_eq!(
                    (now.0, now.1, now.2),
                    (admitted.0, admitted.1, admitted.2),
                    "turn {index} must not rescan original source or rehash unrelated tape"
                );
                assert_eq!(
                    now.3 - admitted.3,
                    index + 1,
                    "one admitted selection per turn"
                );
                assert_eq!(pool.reserved_bytes(), reserved);
            }
            assert_eq!(
                norito::encode_canonical(job.source.original().manifest()).unwrap(),
                source_bytes
            );
        }
    }
    #[test]
    fn unavailable_or_unsupported_optional_archive_never_creates_work_admission() {
        // Whole-pool equality includes published State generations unrelated
        // to this rejected handoff; retain them through the measured operation.
        let _retirement_pin = crossbeam_epoch::pin();
        for issue in [
            crate::state::QuantityCaptureIssue::Capacity,
            crate::state::QuantityCaptureIssue::UnsupportedOwner,
        ] {
            // Keep the fixture State and serialized worker alive until all
            // source-custody assertions finish; dropping the sender detaches cleanup.
            let (_chain, mut source) =
                crate::fastpq::finalized_source::test_fixture::original_source(
                    Quantity::from(100_u32),
                    &[3, 5],
                );
            let manifest = norito::encode_canonical(source.manifest()).unwrap();
            let native = source.native().committed().result();
            // Explicit local optional-archive fault before admission. It changes no
            // mandatory D7 facts, source coverage or native authority.
            source.withhold_optional_archive_for_test(issue);
            source.verify_current().unwrap();
            let reserved = source.pool().reserved_bytes();
            let before = AdmittedFinalizedFastpqSource::scan_counts_for_test();
            let (source, error) = match FastpqWitnessJob::from_finalized(source) {
                Ok(_) => panic!("unavailable archive admitted"),
                Err(rejected) => rejected,
            };
            assert!(matches!(error,FinalizedFastpqWorkError::Archive(actual) if actual==issue));
            assert_eq!(source.pool().reserved_bytes(), reserved);
            assert_eq!(
                AdmittedFinalizedFastpqSource::scan_counts_for_test().2,
                before.2
            );
            assert_eq!(source.native().committed().result(), native);
            assert_eq!(
                norito::encode_canonical(source.manifest()).unwrap(),
                manifest
            );
            source.verify_current().unwrap();
        }
    }
}
