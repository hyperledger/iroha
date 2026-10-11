//! ZK lane: capture IVM diagnostic traces, check them in the background, and report.
//!
//! This module provides a lightweight, non-forking background worker that can receive formal
//! execution traces from IVM runs, check recorded constraints and authenticated
//! register-log entries, and report outcomes. It does not verify VM transition
//! semantics or memory-event membership, does not mutate WSV, and is intended
//! purely for diagnostics/telemetry.
//!
//! Integration points:
//! - Overlay builder: after running IVM to collect queued ISIs, capture the
//!   formal trace and submit a job if ZK is enabled in config.
//! - Node startup: call `start()` once to initialize the worker.
#![deny(missing_docs)]
#[cfg(test)]
use iroha_crypto::HashOf;
use iroha_crypto::{Hash, streaming::TransportCapabilityResolutionSnapshot};
use ivm::zk::{Constraint, DiagnosticTraceSnapshot};
#[cfg(test)]
use ivm::zk::{MemEvent, RegEvent, RegisterState, StepEntry};
use norito::streaming::CapabilityFlags;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    num::NonZeroU64,
    sync::mpsc as std_mpsc,
    sync::{Arc, OnceLock},
    thread,
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
/// Capture optional local diagnostic records without changing execution admission.
/// All four overlay producers use this same original-pool ownership path.
#[cfg(any(test, feature = "iroha-core-tests"))]
pub(crate) fn capture_and_submit(
    vm: &ivm::IVM,
    budget: &iroha_allocation::AllocationBudget,
    tx_hash: Option<Hash>,
    program: ivm::cache_memory::SharedAllocation<u8>,
    header: Option<iroha_data_model::block::BlockHeader>,
    transport_capabilities: Option<TransportCapabilityResolutionSnapshot>,
    negotiated_capabilities: Option<CapabilityFlags>,
) -> bool {
    let snapshot = match vm.try_diagnostic_snapshot(budget) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            record_lane_drop("diagnostic_capture_refused");
            iroha_logger::warn!(?error, "zk_lane: optional diagnostic capture refused");
            return false;
        }
    };
    if snapshot.states().is_empty() {
        return false;
    }
    try_submit(ZkTask {
        tx_hash,
        code_hash: vm.code_hash(),
        program,
        header,
        snapshot,
        transport_capabilities,
        negotiated_capabilities,
    })
}

/// Task carrying a single IVM execution's formal trace and metadata.
pub struct ZkTask {
    /// Transaction hash if available (zero when not applicable).
    pub tx_hash: Option<Hash>,
    /// Code hash of the executed bytecode.
    pub code_hash: [u8; 32],
    /// Shared immutable program bytes executed to produce this trace.
    pub program: ivm::cache_memory::SharedAllocation<u8>,
    /// Optional block header associated with this trace (for warnings/events). If not provided, the
    /// ZK lane will emit a warning with a minimal header carrying height=1.
    pub header: Option<iroha_data_model::block::BlockHeader>,
    /// Move-only, prepaid diagnostic records with original-pool final-owner custody.
    pub snapshot: DiagnosticTraceSnapshot,
    /// Transport capabilities negotiated for the session (if available).
    pub transport_capabilities: Option<TransportCapabilityResolutionSnapshot>,
    /// Negotiated feature flags advertised by the peer (if available).
    pub negotiated_capabilities: Option<CapabilityFlags>,
}
impl ZkTask {
    /// Compute a stable digest of the task contents for idempotence/logging.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"iroha.zk-lane.task.v1");
        h.update(self.code_hash);
        match &self.tx_hash {
            Some(tx) => {
                h.update([1]);
                h.update(tx.as_ref());
            }
            None => h.update([0]),
        }
        h.update((self.program.len() as u64).to_le_bytes());
        h.update(self.program.as_ref());
        match &self.header {
            Some(header) => {
                h.update([1]);
                h.update(header.hash().as_ref().as_ref());
            }
            None => h.update([0]),
        }

        self.hash_trace(&mut h);
        self.hash_constraints(&mut h);
        self.hash_memory_log(&mut h);
        self.hash_register_log(&mut h);
        self.hash_step_log(&mut h);
        self.hash_transport_metadata(&mut h);
        h.finalize().into()
    }
    fn hash_trace(&self, h: &mut Sha256) {
        h.update((self.snapshot.states().len() as u64).to_le_bytes());
        for state in self.snapshot.states() {
            h.update(state.pc.to_le_bytes());
            for value in &state.gpr {
                h.update(value.to_le_bytes());
            }
            for tag in &state.tags {
                h.update([u8::from(*tag)]);
            }
        }
    }
    fn hash_constraints(&self, h: &mut Sha256) {
        h.update((self.snapshot.constraints().len() as u64).to_le_bytes());
        for constraint in self.snapshot.constraints() {
            match constraint {
                Constraint::Zero { reg, cycle } => {
                    h.update([0]);
                    h.update((*reg as u64).to_le_bytes());
                    h.update(cycle.to_le_bytes());
                }
                Constraint::Eq { reg1, reg2, cycle } => {
                    h.update([1]);
                    h.update((*reg1 as u64).to_le_bytes());
                    h.update((*reg2 as u64).to_le_bytes());
                    h.update(cycle.to_le_bytes());
                }
                Constraint::Range { reg, bits, cycle } => {
                    h.update([2]);
                    h.update((*reg as u64).to_le_bytes());
                    h.update([*bits]);
                    h.update(cycle.to_le_bytes());
                }
            }
        }
    }
    fn hash_memory_log(&self, h: &mut Sha256) {
        h.update((self.snapshot.memory_event_count() as u64).to_le_bytes());
        for event in self.snapshot.memory_events() {
            h.update([u8::from(event.written)]);
            h.update(event.address.to_le_bytes());
            h.update(event.value.to_le_bytes());
            h.update([event.size]);
            h.update((event.path.len() as u64).to_le_bytes());
            for sibling in event.path {
                h.update(sibling);
            }
            h.update(event.root);
        }
    }
    fn hash_register_log(&self, h: &mut Sha256) {
        h.update((self.snapshot.register_event_count() as u64).to_le_bytes());
        for event in self.snapshot.register_events() {
            h.update([u8::from(event.written)]);
            h.update((event.index as u64).to_le_bytes());
            h.update(event.value.to_le_bytes());
            h.update([u8::from(event.tag)]);
            h.update((event.path.len() as u64).to_le_bytes());
            for sibling in event.path {
                h.update(sibling);
            }
            h.update(event.root);
        }
    }
    fn hash_step_log(&self, h: &mut Sha256) {
        h.update((self.snapshot.steps().len() as u64).to_le_bytes());
        for step in self.snapshot.steps() {
            h.update(step.pc.to_le_bytes());
            h.update(step.reg_root.as_ref().as_ref());
            h.update(step.mem_root.as_ref().as_ref());
        }
    }
    fn hash_transport_metadata(&self, h: &mut Sha256) {
        match &self.transport_capabilities {
            Some(caps) => {
                h.update([1]);
                h.update(caps.hpke_suite.suite_id().to_le_bytes());
                h.update([u8::from(caps.use_datagram)]);
                h.update(caps.max_segment_datagram_size.to_le_bytes());
                h.update(caps.fec_feedback_interval_ms.to_le_bytes());
                h.update([caps.privacy_bucket_granularity as u8]);
            }
            None => h.update([0]),
        }
        match self.negotiated_capabilities {
            Some(flags) => {
                h.update([1]);
                h.update(flags.bits().to_le_bytes());
            }
            None => h.update([0]),
        }
    }
}
/// Result of a background diagnostic trace check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceCheckOutcome {
    /// All supported diagnostic checks passed.
    Checked,
    /// A constraint or authenticated register path failed its diagnostic check.
    Rejected,
}
/// Handle for submitting ZK tasks to the background worker.
#[derive(Clone)]
pub struct ZkLaneHandle {
    tx: mpsc::Sender<ZkTask>,
    enqueue_wait: Duration,
    enqueue_poll: Duration,
    retry_ring: Arc<RetryRing>,
}
impl ZkLaneHandle {
    /// Submit a task; returns false only if admission fails after bounded wait/retry handling.
    pub fn submit(&self, task: ZkTask) -> bool {
        let digest = task.digest();
        if let Some(cache) = RESULT_CACHE.get() {
            match cache.admit(digest, Instant::now()) {
                CacheAdmission::Cached => return true,
                CacheAdmission::Inflight => return true,
                CacheAdmission::Accepted => {}
            }
        }
        let mut task = task;
        let started = Instant::now();
        loop {
            match self.tx.try_send(task) {
                Ok(()) => {
                    if started.elapsed() > Duration::ZERO {
                        record_enqueue_wait();
                    }
                    return true;
                }
                Err(mpsc::error::TrySendError::Full(returned)) => {
                    task = returned;
                    if started.elapsed() >= self.enqueue_wait {
                        record_enqueue_timeout();
                        if task.tx_hash.is_some() {
                            let accepted = enqueue_retry_task(
                                &self.retry_ring,
                                task,
                                "ingress_retry_ring_full",
                            );
                            if !accepted {
                                clear_inflight_digest(digest);
                            }
                            return accepted;
                        }
                        record_lane_drop("ingress_enqueue_timeout");
                        clear_inflight_digest(digest);
                        return false;
                    }
                    if self.enqueue_poll > Duration::ZERO {
                        thread::sleep(self.enqueue_poll);
                    }
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    record_lane_drop("ingress_channel_closed");
                    clear_inflight_digest(digest);
                    return false;
                }
            }
        }
    }
}
static GLOBAL_SENDER: OnceLock<ZkLaneHandle> = OnceLock::new();
static EVENTS: OnceLock<crate::EventsSender> = OnceLock::new();
static RESULT_CACHE: OnceLock<Arc<ZkResultCache>> = OnceLock::new();
const ZK_RESULT_CACHE_CAP: usize = 8_192;
const ZK_RESULT_CACHE_TTL_MS: u64 = 300_000;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CacheAdmission {
    Accepted,
    Inflight,
    Cached,
}
#[derive(Debug, Clone, Copy)]
struct ZkResultEntry {
    recorded_at: Instant,
}
#[derive(Debug)]
struct ZkResultCache {
    cap: usize,
    ttl: Duration,
    inner: std::sync::Mutex<ZkResultCacheInner>,
}
#[derive(Debug, Default)]
struct ZkResultCacheInner {
    entries: BTreeMap<[u8; 32], ZkResultEntry>,
    order: VecDeque<[u8; 32]>,
    inflight: BTreeSet<[u8; 32]>,
}
impl ZkResultCache {
    fn new(cap: usize, ttl: Duration) -> Self {
        Self {
            cap,
            ttl,
            inner: std::sync::Mutex::new(ZkResultCacheInner::default()),
        }
    }
    fn admit(&self, key: [u8; 32], now: Instant) -> CacheAdmission {
        let mut inner = match self.inner.lock() {
            Ok(guard) => guard,
            Err(err) => {
                iroha_logger::warn!(?err, "zk_lane: result cache lock poisoned during admit");
                return CacheAdmission::Accepted;
            }
        };
        inner.gc(now, self.ttl);
        if let Some(entry) = inner.entries.get(&key) {
            if self.ttl == Duration::ZERO
                || now.saturating_duration_since(entry.recorded_at) <= self.ttl
            {
                inner.touch(key);
                return CacheAdmission::Cached;
            }
            inner.remove_entry(&key);
        }
        if inner.inflight.contains(&key) {
            return CacheAdmission::Inflight;
        }
        inner.inflight.insert(key);
        CacheAdmission::Accepted
    }
    fn record(&self, key: [u8; 32], now: Instant) {
        let mut inner = match self.inner.lock() {
            Ok(guard) => guard,
            Err(err) => {
                iroha_logger::warn!(?err, "zk_lane: result cache lock poisoned during record");
                return;
            }
        };
        inner.inflight.remove(&key);
        if self.cap == 0 {
            return;
        }
        inner
            .entries
            .insert(key, ZkResultEntry { recorded_at: now });
        inner.touch(key);
        inner.gc(now, self.ttl);
        while inner.entries.len() > self.cap {
            let Some(oldest) = inner.order.pop_front() else {
                break;
            };
            inner.entries.remove(&oldest);
        }
    }
    fn clear_inflight(&self, key: [u8; 32]) {
        match self.inner.lock() {
            Ok(mut guard) => {
                guard.inflight.remove(&key);
            }
            Err(err) => {
                iroha_logger::warn!(
                    ?err,
                    "zk_lane: result cache lock poisoned while clearing inflight"
                );
            }
        }
    }
}
impl ZkResultCacheInner {
    fn touch(&mut self, key: [u8; 32]) {
        self.order.retain(|entry| entry != &key);
        self.order.push_back(key);
    }
    fn remove_entry(&mut self, key: &[u8; 32]) {
        self.entries.remove(key);
        self.order.retain(|entry| entry != key);
    }
    fn gc(&mut self, now: Instant, ttl: Duration) {
        if ttl == Duration::ZERO {
            return;
        }
        let mut stale = Vec::new();
        for (key, entry) in &self.entries {
            if now.saturating_duration_since(entry.recorded_at) > ttl {
                stale.push(*key);
            }
        }
        for key in stale {
            self.remove_entry(&key);
        }
    }
}
fn clear_inflight_digest(digest: [u8; 32]) {
    if let Some(cache) = RESULT_CACHE.get() {
        cache.clear_inflight(digest);
    }
}
struct RetryTask {
    task: ZkTask,
    attempts: u32,
}
#[derive(Debug, Clone, Copy, Default)]
struct RetryDrainStats {
    replayed: u64,
    exhausted: u64,
    depth: usize,
}
struct RetryRing {
    cap: usize,
    max_attempts: u32,
    inner: std::sync::Mutex<VecDeque<RetryTask>>,
}
impl RetryRing {
    fn new(cap: usize, max_attempts: u32) -> Self {
        Self {
            cap: cap.max(1),
            max_attempts: max_attempts.max(1),
            inner: std::sync::Mutex::new(VecDeque::new()),
        }
    }
    fn enqueue(&self, task: ZkTask) -> Result<usize, ZkTask> {
        match self.inner.lock() {
            Ok(mut queue) => {
                if queue.len() >= self.cap {
                    return Err(task);
                }
                queue.push_back(RetryTask { task, attempts: 0 });
                Ok(queue.len())
            }
            Err(err) => {
                iroha_logger::warn!(?err, "zk_lane: retry ring lock poisoned during enqueue");
                Err(task)
            }
        }
    }
    fn drain_into_pending(&self, pending: &mut Vec<ZkTask>, pending_cap: usize) -> RetryDrainStats {
        let mut stats = RetryDrainStats::default();
        if pending.len() >= pending_cap {
            let expired = {
                let mut queue = match self.inner.lock() {
                    Ok(queue) => queue,
                    Err(err) => {
                        iroha_logger::warn!(?err, "zk_lane: retry ring lock poisoned during drain");
                        return stats;
                    }
                };
                for entry in queue.iter_mut() {
                    entry.attempts = entry.attempts.saturating_add(1);
                }
                queue
                    .iter()
                    .filter(|entry| entry.attempts >= self.max_attempts)
                    .count()
            };
            // Detach at most the expired census. New enqueues have zero attempts
            // and are not retired by this pass; surviving queue order is unchanged.
            for _ in 0..expired {
                let removed = {
                    let mut queue = match self.inner.lock() {
                        Ok(queue) => queue,
                        Err(_) => break,
                    };
                    queue
                        .iter()
                        .position(|entry| entry.attempts >= self.max_attempts)
                        .and_then(|index| queue.remove(index))
                };
                let Some(entry) = removed else {
                    break;
                };
                clear_inflight_digest(entry.task.digest());
                drop(entry);
                stats.exhausted = stats.exhausted.saturating_add(1);
            }
        } else {
            let initial = self.depth().min(pending_cap - pending.len());
            for _ in 0..initial {
                let removed = {
                    let mut queue = match self.inner.lock() {
                        Ok(queue) => queue,
                        Err(_) => break,
                    };
                    queue.pop_front()
                };
                let Some(entry) = removed else {
                    break;
                };
                pending.push(entry.task);
                stats.replayed = stats.replayed.saturating_add(1);
            }
        }
        stats.depth = self.depth();
        stats
    }
    fn clear(&self) -> usize {
        // Swap the complete queue owner without allocating. Its entries and
        // backing are dropped only after the physical mutex guard is gone.
        let removed = match self.inner.lock() {
            Ok(mut queue) => std::mem::take(&mut *queue),
            Err(err) => {
                iroha_logger::warn!(?err, "zk_lane: retry ring lock poisoned during clear");
                return 0;
            }
        };
        let dropped = removed.len();
        for entry in removed {
            clear_inflight_digest(entry.task.digest());
            drop(entry);
        }
        dropped
    }
    fn depth(&self) -> usize {
        match self.inner.lock() {
            Ok(queue) => queue.len(),
            Err(err) => {
                iroha_logger::warn!(
                    ?err,
                    "zk_lane: retry ring lock poisoned while reading depth"
                );
                0
            }
        }
    }
}
fn with_metrics(mut apply: impl FnMut(&iroha_telemetry::metrics::Metrics)) {
    if let Some(metrics) = iroha_telemetry::metrics::global() {
        apply(metrics.as_ref());
    }
}
fn record_lane_drop(reason: &str) {
    with_metrics(|metrics| {
        metrics
            .zk_lane_drop_total
            .with_label_values(&[reason])
            .inc();
    });
}
fn record_lane_drop_by(reason: &str, count: u64) {
    if count == 0 {
        return;
    }
    with_metrics(|metrics| {
        metrics
            .zk_lane_drop_total
            .with_label_values(&[reason])
            .inc_by(count);
    });
}
fn record_enqueue_wait() {
    with_metrics(|metrics| {
        metrics.zk_lane_enqueue_wait_total.inc();
    });
}
fn record_enqueue_timeout() {
    with_metrics(|metrics| {
        metrics.zk_lane_enqueue_timeout_total.inc();
    });
}
fn set_pending_depth(depth: usize) {
    with_metrics(|metrics| {
        metrics
            .zk_lane_pending_depth
            .set(u64::try_from(depth).unwrap_or(u64::MAX));
    });
}
fn set_retry_ring_depth(depth: usize) {
    with_metrics(|metrics| {
        metrics
            .zk_lane_retry_ring_depth
            .set(u64::try_from(depth).unwrap_or(u64::MAX));
    });
}
fn enqueue_retry_task(retry_ring: &RetryRing, task: ZkTask, full_reason: &str) -> bool {
    match retry_ring.enqueue(task) {
        Ok(depth) => {
            with_metrics(|metrics| {
                metrics.zk_lane_retry_enqueued_total.inc();
            });
            set_retry_ring_depth(depth);
            true
        }
        Err(_) => {
            record_lane_drop(full_reason);
            false
        }
    }
}
struct WorkerPool {
    work_txs: Vec<std_mpsc::SyncSender<ZkTask>>,
    join_handles: Vec<thread::JoinHandle<()>>,
    next_worker: usize,
}
const AUTO_WORKER_MIN: usize = 2;
const AUTO_WORKER_MAX: usize = 8;
impl WorkerPool {
    fn spawn(worker_threads: usize, work_queue_cap: usize) -> Self {
        let mut work_txs = Vec::with_capacity(worker_threads);
        let mut join_handles = Vec::with_capacity(worker_threads);
        for idx in 0..worker_threads {
            let (work_tx, work_rx) = std_mpsc::sync_channel::<ZkTask>(work_queue_cap);
            work_txs.push(work_tx);
            let name = format!("zk-lane-check-{idx}");
            let join_handle = thread::Builder::new()
                .name(name)
                .spawn(move || {
                    while let Ok(job) = work_rx.recv() {
                        process_job(job);
                    }
                })
                .expect("failed to spawn zk lane verifier thread");
            join_handles.push(join_handle);
        }
        Self {
            work_txs,
            join_handles,
            next_worker: 0,
        }
    }
    fn dispatch(&mut self, mut job: ZkTask) -> Result<(), ZkTask> {
        if self.work_txs.is_empty() {
            return Err(job);
        }
        let total = self.work_txs.len();
        let mut disconnected = Vec::new();
        for _ in 0..total {
            let idx = self.next_worker % total;
            self.next_worker = self.next_worker.saturating_add(1);
            let work_tx = &self.work_txs[idx];
            match work_tx.try_send(job) {
                Ok(()) => {
                    if !disconnected.is_empty() {
                        self.prune_disconnected(disconnected);
                    }
                    return Ok(());
                }
                Err(std_mpsc::TrySendError::Full(returned)) => {
                    job = returned;
                }
                Err(std_mpsc::TrySendError::Disconnected(returned)) => {
                    job = returned;
                    disconnected.push(idx);
                }
            }
        }
        if !disconnected.is_empty() {
            self.prune_disconnected(disconnected);
        }
        Err(job)
    }
    fn prune_disconnected(&mut self, mut disconnected: Vec<usize>) {
        disconnected.sort_unstable();
        disconnected.dedup();
        for idx in disconnected.into_iter().rev() {
            if idx < self.work_txs.len() {
                self.work_txs.swap_remove(idx);
            }
        }
        if self.next_worker >= self.work_txs.len() {
            self.next_worker = 0;
        }
    }
}
fn resolve_worker_threads(configured: usize) -> usize {
    if configured == 0 {
        let detected = std::thread::available_parallelism()
            .map(|count| count.get())
            .unwrap_or(1);
        detected.clamp(AUTO_WORKER_MIN, AUTO_WORKER_MAX)
    } else {
        configured.max(1)
    }
}
fn resolve_queue_cap(configured: usize, workers: usize) -> usize {
    if configured == 0 {
        workers.saturating_mul(4).max(128)
    } else {
        configured.max(1)
    }
}
fn resolve_enqueue_wait_ms(configured: u64) -> Duration {
    Duration::from_millis(configured)
}
fn resolve_retry_tick_ms(configured: u64) -> Duration {
    Duration::from_millis(configured.max(1))
}
fn resolve_enqueue_poll(wait: Duration) -> Duration {
    if wait > Duration::ZERO {
        Duration::from_millis(1)
    } else {
        Duration::ZERO
    }
}
fn dispatch_pending(pool: &mut WorkerPool, pending: &mut Vec<ZkTask>) {
    if pending.is_empty() {
        set_pending_depth(0);
        return;
    }
    let mut retained = Vec::new();
    for job in pending.drain(..) {
        if let Err(job) = pool.dispatch(job) {
            retained.push(job);
        }
    }
    *pending = retained;
    set_pending_depth(pending.len());
}
fn process_job(job: ZkTask) {
    let dig = job.digest();
    let outcome = ivm::zk::check_diagnostic_trace(&job.snapshot)
        .map(|()| TraceCheckOutcome::Checked)
        .unwrap_or(TraceCheckOutcome::Rejected);
    if let Some(cache) = RESULT_CACHE.get() {
        cache.record(dig, Instant::now());
    }
    emit_outcome(job, dig, outcome);
}
fn emit_outcome(job: ZkTask, dig: [u8; 32], outcome: TraceCheckOutcome) {
    let transport_desc = job.transport_capabilities.as_ref().map(|caps| {
        format!(
            "suite={}, datagram={}, max_dgram={}, feedback_ms={}, privacy={:?}",
            caps.hpke_suite.suite_id(),
            caps.use_datagram,
            caps.max_segment_datagram_size,
            caps.fec_feedback_interval_ms,
            caps.privacy_bucket_granularity
        )
    });
    let negotiated_desc = job
        .negotiated_capabilities
        .map(|flags| format!("0x{:x}", flags.bits()));
    iroha_logger::info!(
        code_hash = %hex::encode(job.code_hash),
        tx_hash = job.tx_hash.as_ref().map(|hash| hex::encode(hash.as_ref())),
        transport = transport_desc.as_deref(),
        negotiated_capabilities = negotiated_desc.as_deref(),
        digest = %hex::encode(dig),
        outcome = ?outcome,
        cycles = job.snapshot.states().len(),
        constraints = job.snapshot.constraints().len(),
        mem_events = job.snapshot.memory_event_count(),
        reg_events = job.snapshot.register_event_count(),
        "zk_lane: checked diagnostic trace"
    );
    if let Some(es) = EVENTS.get() {
        let header = job.header.unwrap_or_else(|| {
            iroha_data_model::block::BlockHeader::new(
                NonZeroU64::new(1).expect("non-zero constant"),
                None,
                None,
                0,
                0,
            )
        });
        let (kind, details) = match outcome {
            TraceCheckOutcome::Checked => (
                "zk_trace_checked",
                format!(
                    "diagnostic trace checks passed: code_hash={}, digest={}, transport={:?}, negotiated={:?}",
                    hex::encode(job.code_hash),
                    hex::encode(dig),
                    transport_desc,
                    negotiated_desc
                ),
            ),
            TraceCheckOutcome::Rejected => (
                "zk_trace_rejected",
                format!(
                    "diagnostic trace check rejected: code_hash={}, digest={}, transport={:?}, negotiated={:?}",
                    hex::encode(job.code_hash),
                    hex::encode(dig),
                    transport_desc,
                    negotiated_desc
                ),
            ),
        };
        let warn = iroha_data_model::events::pipeline::PipelineWarning {
            header,
            kind: kind.to_string(),
            details,
        };
        let _ = es.send(iroha_data_model::events::EventBox::from(
            iroha_data_model::events::pipeline::PipelineEventBox::Warning(warn),
        ));
    }
}
/// Try to submit a task through a globally registered lane, if present.
pub fn try_submit(task: ZkTask) -> bool {
    GLOBAL_SENDER
        .get()
        .is_some_and(|handle| handle.submit(task))
}
/// Register a global events sender to receive diagnostic trace-check warnings.
/// No-op if already registered.
pub fn register_events_sender(sender: crate::EventsSender) {
    let _ = EVENTS.set(sender);
}
/// Start the background diagnostic trace lane when local trace checking is enabled.
///
/// Returns an optional handle and a `tokio` task `JoinHandle` wrapped for supervisor registration.
/// If the lane is already running, returns the existing handle and no new task.
pub fn start(
    cfg: &iroha_config::parameters::actual::DiagnosticTrace,
) -> Option<(ZkLaneHandle, tokio::task::JoinHandle<()>)> {
    let workers = if cfg.enabled {
        resolve_worker_threads(cfg.worker_threads)
    } else {
        0
    };
    let queue_cap = if cfg.enabled {
        resolve_queue_cap(cfg.queue_cap, workers)
    } else {
        0
    };
    with_metrics(|metrics| {
        let worker_threads = u64::try_from(workers).unwrap_or(u64::MAX);
        let queue_cap = u64::try_from(queue_cap).unwrap_or(u64::MAX);
        metrics.zk_trace_enabled.set(u64::from(cfg.enabled));
        metrics.zk_trace_max_batch.set(u64::from(cfg.max_batch));
        metrics.zk_trace_worker_threads.set(worker_threads);
        metrics.zk_trace_queue_cap.set(queue_cap);
        *metrics
            .trace_status
            .write()
            .expect("trace status lock poisoned") =
            iroha_torii_shared::status::DiagnosticTraceStatus {
                enabled: cfg.enabled,
                max_batch: cfg.max_batch,
                worker_threads,
                queue_cap,
            };
    });
    if !cfg.enabled {
        return None;
    }
    if let Some(existing) = GLOBAL_SENDER.get() {
        // Already started in this process.
        return Some((existing.clone(), tokio::spawn(async {})));
    }
    let _ = RESULT_CACHE.set(Arc::new(ZkResultCache::new(
        ZK_RESULT_CACHE_CAP,
        Duration::from_millis(ZK_RESULT_CACHE_TTL_MS),
    )));
    let enqueue_wait = resolve_enqueue_wait_ms(cfg.enqueue_wait_ms);
    let enqueue_poll = resolve_enqueue_poll(enqueue_wait);
    let retry_tick = resolve_retry_tick_ms(cfg.retry_tick_ms);
    let retry_ring = Arc::new(RetryRing::new(cfg.retry_ring_cap, cfg.retry_max_attempts));
    let worker_queue_cap = queue_cap.saturating_div(workers).max(1);
    let (tx, mut rx) = mpsc::channel::<ZkTask>(queue_cap);
    let handle = ZkLaneHandle {
        tx: tx.clone(),
        enqueue_wait,
        enqueue_poll,
        retry_ring: Arc::clone(&retry_ring),
    };
    let _ = GLOBAL_SENDER.set(handle.clone());
    set_pending_depth(0);
    set_retry_ring_depth(0);
    let max_batch = cfg.max_batch.max(1) as usize;
    let task = tokio::spawn(async move {
        let mut worker_pool = WorkerPool::spawn(workers, worker_queue_cap);
        let mut pending: Vec<ZkTask> = Vec::with_capacity(max_batch);
        loop {
            tokio::select! {
                biased;
                maybe = rx.recv() => {
                    if let Some(job) = maybe {
                        let job = job;
                        let started = Instant::now();
                        loop {
                            if pending.len() < queue_cap {
                                pending.push(job);
                                set_pending_depth(pending.len());
                                if started.elapsed() > Duration::ZERO {
                                    record_enqueue_wait();
                                }
                                break;
                            }
                            dispatch_pending(&mut worker_pool, &mut pending);
                            if started.elapsed() >= enqueue_wait {
                                record_enqueue_timeout();
                                if job.tx_hash.is_some() {
                                    let accepted = enqueue_retry_task(
                                        retry_ring.as_ref(),
                                        job,
                                        "dispatch_retry_ring_full",
                                    );
                                    if !accepted {
                                        iroha_logger::warn!(
                                            queue_cap,
                                            pending = pending.len(),
                                            retry_depth = retry_ring.depth(),
                                            workers,
                                            "zk_lane: dropped important task after dispatch saturation"
                                        );
                                    }
                                } else {
                                    record_lane_drop("dispatch_enqueue_timeout");
                                    iroha_logger::warn!(
                                        queue_cap,
                                        pending = pending.len(),
                                        workers,
                                        "zk_lane: dropping diagnostic trace-check task due to saturated dispatch backlog"
                                    );
                                }
                                break;
                            }
                            if enqueue_poll > Duration::ZERO {
                                tokio::time::sleep(enqueue_poll).await;
                            } else {
                                tokio::task::yield_now().await;
                            }
                        }
                        if pending.len() >= max_batch {
                            dispatch_pending(&mut worker_pool, &mut pending);
                        }
                    } else {
                        dispatch_pending(&mut worker_pool, &mut pending);
                        break;
                    }
                }
                // Periodically drain small batches to avoid unbounded latency
                () = tokio::time::sleep(retry_tick) => {
                    dispatch_pending(&mut worker_pool, &mut pending);
                }
            }
            let retry_stats = retry_ring.drain_into_pending(&mut pending, queue_cap);
            if retry_stats.replayed > 0 {
                with_metrics(|metrics| {
                    metrics
                        .zk_lane_retry_replayed_total
                        .inc_by(retry_stats.replayed);
                });
                set_pending_depth(pending.len());
            }
            if retry_stats.exhausted > 0 {
                with_metrics(|metrics| {
                    metrics
                        .zk_lane_retry_exhausted_total
                        .inc_by(retry_stats.exhausted);
                });
                record_lane_drop_by("retry_exhausted", retry_stats.exhausted);
                iroha_logger::warn!(
                    exhausted = retry_stats.exhausted,
                    "zk_lane: dropping retry-ring tasks after exhausting retry rounds"
                );
            }
            set_retry_ring_depth(retry_stats.depth);
            if pending.len() >= max_batch {
                dispatch_pending(&mut worker_pool, &mut pending);
            }
        }
        if !pending.is_empty() {
            for task in &pending {
                clear_inflight_digest(task.digest());
            }
            record_lane_drop_by("shutdown_flush_drop", pending.len() as u64);
            iroha_logger::warn!(
                dropped = pending.len(),
                "zk_lane: dropping pending diagnostic trace-check tasks during shutdown"
            );
        }
        let retry_dropped = retry_ring.clear();
        if retry_dropped > 0 {
            record_lane_drop_by("shutdown_flush_drop", retry_dropped as u64);
            iroha_logger::warn!(
                dropped = retry_dropped,
                "zk_lane: dropping retry-ring tasks during shutdown"
            );
            set_retry_ring_depth(0);
        }
        let WorkerPool {
            work_txs,
            join_handles: joins,
            ..
        } = worker_pool;
        drop(work_txs);
        let _ = tokio::task::spawn_blocking(move || {
            for join in joins {
                if let Err(err) = join.join() {
                    iroha_logger::warn!(?err, "zk lane verifier thread exited with panic");
                }
            }
        })
        .await;
    });
    Some((handle, task))
}
#[cfg(test)]
mod tests {
    //! Minimal unit tests for `ZkLane` helpers.
    use super::*;
    fn root(byte: u8) -> HashOf<iroha_crypto::MerkleTree<[u8; 32]>> {
        HashOf::from_untyped_unchecked(Hash::prehashed([byte; 32]))
    }
    struct TraceFixture {
        trace: Vec<RegisterState>,
        constraints: Vec<Constraint>,
        mem_log: Vec<MemEvent>,
        reg_log: Vec<RegEvent>,
        step_log: Vec<StepEntry>,
    }
    impl TraceFixture {
        fn new() -> Self {
            let mut gpr = [0; 256];
            gpr[128] = 7;
            let mut tags = [false; 256];
            tags[128] = true;
            Self {
                trace: vec![RegisterState { pc: 11, gpr, tags }],
                constraints: vec![Constraint::Range {
                    reg: 128,
                    bits: 8,
                    cycle: 0,
                }],
                mem_log: vec![MemEvent::Load {
                    addr: 64,
                    value: 7,
                    size: 1,
                    path: vec![[0x31; 32]],
                    root: root(0x41),
                }],
                reg_log: vec![RegEvent::Read {
                    index: 128,
                    value: 7,
                    tag: true,
                    path: [[0x51; 32]; ivm::REGISTER_MERKLE_PATH_DEPTH],
                    root: root(0x61),
                }],
                step_log: (0..3)
                    .map(|i| StepEntry {
                        pc: 10 + u64::from(i),
                        reg_root: root(1 + 2 * i),
                        mem_root: root(2 + 2 * i),
                    })
                    .collect(),
            }
        }
        fn snapshot(&self, budget: &iroha_allocation::AllocationBudget) -> DiagnosticTraceSnapshot {
            ivm::zk::DiagnosticTraceSource {
                registers: ivm::zk::DiagnosticRegisterSource::States(&self.trace),
                constraints: &self.constraints,
                memory_events: &self.mem_log,
                register_events: &self.reg_log,
                steps: &self.step_log,
            }
            .try_snapshot(budget)
            .expect("fund lane trace fixture")
        }
        fn task(&self, budget: &iroha_allocation::AllocationBudget) -> ZkTask {
            ZkTask {
                tx_hash: Some(Hash::prehashed([0xCD; 32])),
                code_hash: [0xAB; 32],
                program: vec![0x55; 96].into(),
                header: None,
                snapshot: self.snapshot(budget),
                transport_capabilities: None,
                negotiated_capabilities: None,
            }
        }
    }
    fn digest_task() -> ZkTask {
        TraceFixture::new().task(&iroha_allocation::AllocationBudget::new(64 * 1024))
    }
    fn empty_snapshot() -> DiagnosticTraceSnapshot {
        ivm::zk::DiagnosticTraceSource {
            registers: ivm::zk::DiagnosticRegisterSource::States(&[]),
            constraints: &[],
            memory_events: &[],
            register_events: &[],
            steps: &[],
        }
        .try_snapshot(&iroha_allocation::AllocationBudget::new(0))
        .expect("empty capture needs no payload credit")
    }
    #[test]
    fn digest_binds_program_trace_and_constraints() {
        let digest = digest_task().digest();
        let mut changed = digest_task();
        let mut program = changed.program.as_ref().to_vec();
        program[95] ^= 1;
        changed.program = program.into();
        assert_ne!(
            digest,
            changed.digest(),
            "the complete program must be bound"
        );
        let budget = iroha_allocation::AllocationBudget::new(64 * 1024);
        let mut fixture = TraceFixture::new();
        fixture.trace[0].gpr[128] ^= 1;
        assert_ne!(
            digest,
            fixture.task(&budget).digest(),
            "register values must be bound"
        );
        let mut fixture = TraceFixture::new();
        fixture.constraints[0] = Constraint::Zero { reg: 128, cycle: 0 };
        assert_ne!(
            digest,
            fixture.task(&budget).digest(),
            "constraints must be bound"
        );
    }
    #[test]
    fn digest_binds_access_logs_and_intermediate_steps() {
        let digest = digest_task().digest();
        let budget = iroha_allocation::AllocationBudget::new(64 * 1024);
        let mut fixture = TraceFixture::new();
        if let MemEvent::Load { value, .. } = &mut fixture.mem_log[0] {
            *value ^= 1;
        }
        assert_ne!(
            digest,
            fixture.task(&budget).digest(),
            "memory events must be bound"
        );
        let mut fixture = TraceFixture::new();
        if let RegEvent::Read { value, .. } = &mut fixture.reg_log[0] {
            *value ^= 1;
        }
        assert_ne!(
            digest,
            fixture.task(&budget).digest(),
            "register events must be bound"
        );
        let mut fixture = TraceFixture::new();
        fixture.step_log[1].pc ^= 1;
        assert_ne!(
            digest,
            fixture.task(&budget).digest(),
            "intermediate steps must be bound"
        );
    }
    #[test]
    fn queue_cap_defaults_scale_with_workers() {
        assert_eq!(resolve_queue_cap(0, 1), 128);
        assert_eq!(resolve_queue_cap(0, 32), 128);
        assert_eq!(resolve_queue_cap(0, 64), 256);
        assert_eq!(resolve_queue_cap(17, 4), 17);
    }
    #[test]
    fn worker_threads_auto_is_bounded() {
        let expected = std::thread::available_parallelism()
            .map(|count| count.get())
            .unwrap_or(1)
            .clamp(AUTO_WORKER_MIN, AUTO_WORKER_MAX);
        assert_eq!(resolve_worker_threads(0), expected);
        assert!(resolve_worker_threads(0) <= AUTO_WORKER_MAX);
    }
    #[test]
    fn worker_threads_preserves_explicit_count() {
        assert_eq!(resolve_worker_threads(32), 32);
    }
    #[test]
    fn retry_ring_replays_when_pending_has_capacity() {
        let ring = RetryRing::new(8, 3);
        let task = ZkTask {
            tx_hash: Some(Hash::prehashed([0x11; 32])),
            code_hash: [0x22; 32],
            program: vec![0x01, 0x02].into(),
            header: None,
            snapshot: empty_snapshot(),
            transport_capabilities: None,
            negotiated_capabilities: None,
        };
        assert!(ring.enqueue(task).is_ok(), "ring accepts first task");
        let mut pending = Vec::new();
        let stats = ring.drain_into_pending(&mut pending, 1);
        assert_eq!(stats.replayed, 1);
        assert_eq!(stats.exhausted, 0);
        assert_eq!(stats.depth, 0);
        assert_eq!(pending.len(), 1);
    }
    #[test]
    fn retry_ring_exhausts_when_pending_stays_full() {
        let ring = RetryRing::new(4, 2);
        for idx in 0..2 {
            let task = ZkTask {
                tx_hash: Some(Hash::prehashed([idx as u8; 32])),
                code_hash: [0xAA; 32],
                program: vec![idx as u8].into(),
                header: None,
                snapshot: empty_snapshot(),
                transport_capabilities: None,
                negotiated_capabilities: None,
            };
            assert!(ring.enqueue(task).is_ok(), "ring enqueue should succeed");
        }
        let mut pending = vec![ZkTask {
            tx_hash: None,
            code_hash: [0xFF; 32],
            program: vec![0xFF].into(),
            header: None,
            snapshot: empty_snapshot(),
            transport_capabilities: None,
            negotiated_capabilities: None,
        }];
        let first = ring.drain_into_pending(&mut pending, 1);
        assert_eq!(first.exhausted, 0);
        assert_eq!(first.depth, 2);
        let second = ring.drain_into_pending(&mut pending, 1);
        assert_eq!(second.exhausted, 2);
        assert_eq!(second.depth, 0);
    }
    #[test]
    fn result_cache_dedupes_inflight_and_reuses_recent_result() {
        let cache = ZkResultCache::new(8, Duration::from_millis(100));
        let now = Instant::now();
        let key = [0x5A; 32];
        assert_eq!(cache.admit(key, now), CacheAdmission::Accepted);
        assert_eq!(
            cache.admit(key, now + Duration::from_millis(10)),
            CacheAdmission::Inflight
        );
        cache.record(key, now + Duration::from_millis(15));
        assert_eq!(
            cache.admit(key, now + Duration::from_millis(20)),
            CacheAdmission::Cached
        );
        assert_eq!(
            cache.admit(key, now + Duration::from_millis(130)),
            CacheAdmission::Accepted
        );
    }
    #[test]
    fn result_cache_evicts_oldest_entries_when_capacity_reached() {
        let cache = ZkResultCache::new(2, Duration::from_secs(1));
        let now = Instant::now();
        let a = [0x01; 32];
        let b = [0x02; 32];
        let c = [0x03; 32];
        assert_eq!(cache.admit(a, now), CacheAdmission::Accepted);
        cache.record(a, now);
        assert_eq!(cache.admit(b, now), CacheAdmission::Accepted);
        cache.record(b, now + Duration::from_millis(1));
        assert_eq!(cache.admit(c, now), CacheAdmission::Accepted);
        cache.record(c, now + Duration::from_millis(2));
        assert_eq!(
            cache.admit(a, now + Duration::from_millis(3)),
            CacheAdmission::Accepted
        );
        assert_eq!(
            cache.admit(c, now + Duration::from_millis(3)),
            CacheAdmission::Cached
        );
    }
}

#[cfg(test)]
mod snapshot_custody_tests;
