//! Async DA spool batching for Torii ingest persistence.
use super::ReceiptInsertOutcome;
use crate::{panic_recovery, routing::MaybeTelemetry};
use iroha_futures::supervisor::ShutdownSignal;
use iroha_logger::warn;
use iroha_panic_hook::catch_unwind_suppressed;
use std::{
    any::Any,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot};
const OUTCOME_OK: &str = "ok";
const OUTCOME_PARTIAL_ERROR: &str = "partial_error";
const OUTCOME_ERROR: &str = "error";
const KIND_WORKER: &str = "worker";
/// Result payload emitted by a DA spool action.
#[derive(Debug)]
pub enum DaSpoolActionOutput {
    /// The action has no handler-visible output.
    None,
    /// The action appended to the durable receipt log.
    ReceiptOutcome(ReceiptInsertOutcome),
}
/// One synchronous persistence action executed by the DA spool worker.
pub struct DaSpoolAction {
    kind: &'static str,
    run: Box<dyn FnOnce() -> Result<DaSpoolActionOutput, String> + Send + 'static>,
}
impl DaSpoolAction {
    /// Build a spool action with an operator-facing artifact kind label.
    pub(crate) fn new<F>(kind: &'static str, run: F) -> Self
    where
        F: FnOnce() -> Result<DaSpoolActionOutput, String> + Send + 'static,
    {
        Self {
            kind,
            run: Box::new(run),
        }
    }
    fn execute(self) -> DaSpoolActionReport {
        let kind = self.kind;
        let run = self.run;
        match catch_unwind_suppressed(run) {
            Ok(Ok(output)) => DaSpoolActionReport {
                kind,
                outcome: DaSpoolActionOutcome::Ok,
                error: None,
                output: Some(output),
            },
            Ok(Err(error)) => DaSpoolActionReport {
                kind,
                outcome: DaSpoolActionOutcome::Error,
                error: Some(error),
                output: None,
            },
            Err(payload) => DaSpoolActionReport {
                kind,
                outcome: DaSpoolActionOutcome::Error,
                error: Some(format!(
                    "DA spool action `{kind}` panicked: {}",
                    panic_payload_message(payload.as_ref())
                )),
                output: None,
            },
        }
    }
}
fn panic_payload_message(payload: &(dyn Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|message| (*message).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic payload".to_owned())
}
/// A handler-visible report for one spool action.
#[derive(Debug)]
pub struct DaSpoolActionReport {
    kind: &'static str,
    outcome: DaSpoolActionOutcome,
    error: Option<String>,
    output: Option<DaSpoolActionOutput>,
}
impl DaSpoolActionReport {
    /// Artifact kind label for logs and metrics.
    pub(crate) fn kind(&self) -> &'static str {
        self.kind
    }
    /// Outcome label for logs and metrics.
    pub(crate) fn outcome_label(&self) -> &'static str {
        self.outcome.label()
    }
    /// Error text when the action failed.
    pub(crate) fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
    /// Handler-visible action output.
    pub(crate) fn output(&self) -> Option<&DaSpoolActionOutput> {
        self.output.as_ref()
    }
}
#[derive(Clone, Copy, Debug)]
enum DaSpoolActionOutcome {
    Ok,
    Error,
}
impl DaSpoolActionOutcome {
    const fn label(self) -> &'static str {
        match self {
            Self::Ok => OUTCOME_OK,
            Self::Error => OUTCOME_ERROR,
        }
    }
}
/// A batch of DA persistence actions that should complete before the ingest response is returned.
#[derive(Default)]
pub struct DaSpoolBatch {
    actions: Vec<DaSpoolAction>,
    commit_actions: Vec<DaSpoolAction>,
}
impl DaSpoolBatch {
    /// Create an empty batch.
    pub(crate) fn new() -> Self {
        Self::default()
    }
    /// Append one persistence action.
    pub(crate) fn push(&mut self, action: DaSpoolAction) {
        self.actions.push(action);
    }
    /// Append a durability marker that may run only after all artifact actions succeed.
    pub(crate) fn push_commit(&mut self, action: DaSpoolAction) {
        self.commit_actions.push(action);
    }
    /// Whether the batch has no actions.
    pub(crate) fn is_empty(&self) -> bool {
        self.actions.is_empty() && self.commit_actions.is_empty()
    }
    /// Execute the batch synchronously on the current thread.
    pub(crate) fn execute_sync(self) -> DaSpoolBatchReport {
        let started_at = Instant::now();
        let mut action_reports: Vec<_> = self
            .actions
            .into_iter()
            .map(DaSpoolAction::execute)
            .collect();
        if action_reports
            .iter()
            .all(|report| matches!(report.outcome, DaSpoolActionOutcome::Ok))
        {
            action_reports.extend(self.commit_actions.into_iter().map(DaSpoolAction::execute));
        }
        DaSpoolBatchReport {
            action_reports,
            write_duration: started_at.elapsed(),
        }
    }
}
/// Handler-visible result of a DA spool batch.
#[derive(Debug)]
pub struct DaSpoolBatchReport {
    action_reports: Vec<DaSpoolActionReport>,
    write_duration: Duration,
}
impl DaSpoolBatchReport {
    fn worker_error(error: String) -> Self {
        Self {
            action_reports: vec![DaSpoolActionReport {
                kind: KIND_WORKER,
                outcome: DaSpoolActionOutcome::Error,
                error: Some(error),
                output: None,
            }],
            write_duration: Duration::ZERO,
        }
    }
    /// Action reports in execution order.
    pub(crate) fn actions(&self) -> &[DaSpoolActionReport] {
        &self.action_reports
    }
    fn batch_outcome_label(&self) -> &'static str {
        if self
            .action_reports
            .iter()
            .any(|report| matches!(report.outcome, DaSpoolActionOutcome::Error))
        {
            OUTCOME_PARTIAL_ERROR
        } else {
            OUTCOME_OK
        }
    }
    fn write_ms(&self) -> f64 {
        self.write_duration.as_secs_f64() * 1_000.0
    }
}
struct DaSpoolJob {
    batch: DaSpoolBatch,
    ack: oneshot::Sender<DaSpoolBatchReport>,
}
/// Bounded async worker that batches DA spool writes onto blocking threads.
pub struct DaSpooler {
    tx: mpsc::Sender<DaSpoolJob>,
    depth: Arc<AtomicUsize>,
    telemetry: MaybeTelemetry,
    worker: std::sync::Mutex<DaSpoolWorkerRegistration>,
}
struct DaSpoolWorkerRegistration {
    receiver: Option<mpsc::Receiver<DaSpoolJob>>,
    batch_max: usize,
    task: Option<tokio::task::JoinHandle<crate::ToriiCriticalWorkerExit>>,
}
struct PendingDepthGuard<'a> {
    spooler: &'a DaSpooler,
    armed: bool,
}
impl PendingDepthGuard<'_> {
    fn disarm(&mut self) {
        self.armed = false;
    }
}
impl Drop for PendingDepthGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            let restored_depth = DaSpooler::decrement_depth(&self.spooler.depth, 1);
            self.spooler.record_queue_depth(restored_depth);
        }
    }
}
impl DaSpooler {
    /// Prepare a DA spooler without starting background work.
    pub(crate) fn prepare(
        queue_capacity: std::num::NonZeroUsize,
        batch_max: std::num::NonZeroUsize,
        telemetry: MaybeTelemetry,
    ) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(queue_capacity.get());
        let depth = Arc::new(AtomicUsize::new(0));
        Arc::new(Self {
            tx,
            depth,
            telemetry,
            worker: std::sync::Mutex::new(DaSpoolWorkerRegistration {
                receiver: Some(rx),
                batch_max: batch_max.get().max(1),
                task: None,
            }),
        })
    }
    /// Start the prepared worker and retain its join handle until Torii takes ownership.
    pub(crate) fn start(&self, shutdown: ShutdownSignal) -> Result<(), &'static str> {
        let mut worker = self
            .worker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if worker.task.is_some() {
            return Err("DA spool worker was started more than once");
        }
        let receiver = worker
            .receiver
            .take()
            .ok_or("DA spool worker receiver is unavailable")?;
        let batch_max = worker.batch_max;
        let depth = Arc::clone(&self.depth);
        let telemetry = self.telemetry.clone();
        worker.task = Some(tokio::spawn(Self::run(
            receiver, batch_max, depth, telemetry, shutdown,
        )));
        Ok(())
    }
    /// Transfer the started worker handle to Torii's critical-worker supervisor.
    pub(crate) fn take_worker(
        &self,
    ) -> Option<tokio::task::JoinHandle<crate::ToriiCriticalWorkerExit>> {
        self.worker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .task
            .take()
    }
    #[cfg(test)]
    pub(crate) fn spawn(
        queue_capacity: std::num::NonZeroUsize,
        batch_max: std::num::NonZeroUsize,
        telemetry: MaybeTelemetry,
    ) -> Arc<Self> {
        let spooler = Self::prepare(queue_capacity, batch_max, telemetry);
        spooler
            .start(ShutdownSignal::new())
            .expect("fresh test DA spooler must start");
        spooler
    }
    /// Submit a batch and wait for the worker acknowledgement.
    pub(crate) async fn submit(&self, batch: DaSpoolBatch) -> DaSpoolBatchReport {
        if batch.is_empty() {
            let report = batch.execute_sync();
            Self::record_report(&self.telemetry, &report);
            return report;
        }
        let Some(queued_depth) = Self::try_increment_depth(&self.depth) else {
            self.record_queue_depth(usize::MAX);
            let report = DaSpoolBatchReport::worker_error(
                "DA spool queue depth counter is exhausted".to_owned(),
            );
            Self::record_report(&self.telemetry, &report);
            return report;
        };
        self.record_queue_depth(queued_depth);
        let mut depth_guard = PendingDepthGuard {
            spooler: self,
            armed: true,
        };
        let (ack, ack_rx) = oneshot::channel();
        match self.tx.send(DaSpoolJob { batch, ack }).await {
            Ok(()) => {
                depth_guard.disarm();
                match ack_rx.await {
                    Ok(report) => report,
                    Err(err) => {
                        let report = DaSpoolBatchReport::worker_error(format!(
                            "DA spool worker dropped acknowledgement: {err}"
                        ));
                        Self::record_report(&self.telemetry, &report);
                        report
                    }
                }
            }
            Err(_err) => {
                drop(depth_guard);
                let report =
                    DaSpoolBatchReport::worker_error("DA spool worker is unavailable".to_owned());
                Self::record_report(&self.telemetry, &report);
                report
            }
        }
    }
    async fn run(
        mut rx: mpsc::Receiver<DaSpoolJob>,
        batch_max: usize,
        depth: Arc<AtomicUsize>,
        telemetry: MaybeTelemetry,
        shutdown: ShutdownSignal,
    ) -> crate::ToriiCriticalWorkerExit {
        loop {
            let first = tokio::select! {
                biased;
                () = shutdown.receive() => {
                    // Reject new queued work, then durably drain every job
                    // accepted before shutdown before reporting completion.
                    rx.close();
                    rx.recv().await
                }
                first = rx.recv() => first,
            };
            let Some(first) = first else {
                break;
            };
            let mut jobs = Vec::with_capacity(batch_max);
            jobs.push(first);
            while jobs.len() < batch_max {
                match rx.try_recv() {
                    Ok(job) => jobs.push(job),
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => break,
                }
            }
            let drained = jobs.len();
            let depth_after = Self::decrement_depth(&depth, drained);
            Self::record_queue_depth_for(&telemetry, depth_after);
            let reports = panic_recovery::join_recoverable(
                panic_recovery::spawn_blocking_recoverable(move || {
                    jobs.into_iter()
                        .map(|job| (job.ack, job.batch.execute_sync()))
                        .collect::<Vec<_>>()
                }),
            )
            .await;
            match reports {
                Ok(reports) => {
                    for (ack, report) in reports {
                        Self::record_report(&telemetry, &report);
                        let _ = ack.send(report);
                    }
                }
                Err(err) => {
                    warn!(?err, "DA spool worker join failed");
                }
            }
        }
        Self::record_queue_depth_for(&telemetry, 0);
        if shutdown.is_sent() {
            crate::ToriiCriticalWorkerExit::StoppedByShutdown
        } else {
            crate::ToriiCriticalWorkerExit::UnexpectedExit
        }
    }
    fn record_queue_depth(&self, depth: usize) {
        Self::record_queue_depth_for(&self.telemetry, depth);
    }
    /// Return the currently reserved queue depth for cancellation regressions.
    #[cfg(test)]
    pub(crate) fn queued_depth(&self) -> usize {
        self.depth.load(Ordering::Acquire)
    }
    fn try_increment_depth(depth: &AtomicUsize) -> Option<usize> {
        depth
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .ok()
            .and_then(|previous| previous.checked_add(1))
    }
    fn decrement_depth(depth: &AtomicUsize, amount: usize) -> usize {
        let mut current = depth.load(Ordering::Acquire);
        loop {
            let next = current.saturating_sub(amount);
            match depth.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return next,
                Err(actual) => current = actual,
            }
        }
    }
    fn record_queue_depth_for(telemetry: &MaybeTelemetry, depth: usize) {
        if !telemetry.is_enabled() {
            return;
        }
        telemetry.with_metrics(|handle| {
            handle.set_torii_da_spool_queue_depth(u64::try_from(depth).unwrap_or(u64::MAX));
        });
    }
    fn record_report(telemetry: &MaybeTelemetry, report: &DaSpoolBatchReport) {
        if !telemetry.is_enabled() {
            return;
        }
        telemetry.with_metrics(|handle| {
            handle.record_torii_da_spool_batch(report.batch_outcome_label(), report.write_ms());
            for action in report.actions() {
                handle.record_torii_da_spool_artifact(action.kind(), action.outcome_label(), 1);
            }
        });
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        num::NonZeroUsize,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };
    #[test]
    fn queue_depth_increment_rejects_overflow_without_wrapping() {
        let depth = AtomicUsize::new(usize::MAX);
        assert_eq!(DaSpooler::try_increment_depth(&depth), None);
        assert_eq!(depth.load(Ordering::SeqCst), usize::MAX);
    }
    #[test]
    fn queue_depth_decrement_clamps_underflow_without_wrapping() {
        let depth = AtomicUsize::new(1);
        assert_eq!(DaSpooler::decrement_depth(&depth, 4), 0);
        assert_eq!(depth.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn da_spooler_rejects_when_queue_depth_counter_is_exhausted() {
        let marker = Arc::new(AtomicUsize::new(0));
        let spooler = DaSpooler::spawn(
            NonZeroUsize::new(1).expect("non-zero queue"),
            NonZeroUsize::new(1).expect("non-zero batch"),
            MaybeTelemetry::disabled(),
        );
        spooler.depth.store(usize::MAX, Ordering::SeqCst);
        let mut batch = DaSpoolBatch::new();
        let marker_for_action = Arc::clone(&marker);
        batch.push(DaSpoolAction::new("test_artifact", move || {
            marker_for_action.fetch_add(1, Ordering::SeqCst);
            Ok(DaSpoolActionOutput::None)
        }));
        let report = spooler.submit(batch).await;
        assert_eq!(marker.load(Ordering::SeqCst), 0);
        assert_eq!(spooler.depth.load(Ordering::SeqCst), usize::MAX);
        assert_eq!(report.actions().len(), 1);
        assert_eq!(report.actions()[0].kind(), KIND_WORKER);
        assert_eq!(
            report.actions()[0].error(),
            Some("DA spool queue depth counter is exhausted")
        );
    }
    #[tokio::test]
    async fn da_spooler_rejects_when_worker_receiver_is_closed() {
        let marker = Arc::new(AtomicUsize::new(0));
        let spooler = DaSpooler::prepare(
            NonZeroUsize::new(1).expect("non-zero queue"),
            NonZeroUsize::new(1).expect("non-zero batch"),
            MaybeTelemetry::disabled(),
        );
        drop(
            spooler
                .worker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .receiver
                .take()
                .expect("prepared spooler retains its receiver"),
        );
        let mut batch = DaSpoolBatch::new();
        let marker_for_action = Arc::clone(&marker);
        batch.push(DaSpoolAction::new("test_artifact", move || {
            marker_for_action.fetch_add(1, Ordering::SeqCst);
            Ok(DaSpoolActionOutput::None)
        }));

        let report = spooler.submit(batch).await;

        assert_eq!(marker.load(Ordering::SeqCst), 0);
        assert_eq!(spooler.queued_depth(), 0);
        assert_eq!(report.actions().len(), 1);
        assert_eq!(report.actions()[0].kind(), KIND_WORKER);
        assert_eq!(
            report.actions()[0].error(),
            Some("DA spool worker is unavailable")
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn da_spooler_shutdown_drains_physically_started_batch() {
        let spooler = DaSpooler::prepare(
            NonZeroUsize::new(1).expect("non-zero queue"),
            NonZeroUsize::new(1).expect("non-zero batch"),
            MaybeTelemetry::disabled(),
        );
        let shutdown = ShutdownSignal::new();
        spooler
            .start(shutdown.clone())
            .expect("prepared spooler starts once");
        let worker = spooler
            .take_worker()
            .expect("started spooler retains its worker");
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let mut batch = DaSpoolBatch::new();
        batch.push(DaSpoolAction::new("blocked_artifact", move || {
            started_tx.send(()).expect("signal physical spool work");
            release_rx.recv().expect("release physical spool work");
            Ok(DaSpoolActionOutput::None)
        }));
        let submitter = Arc::clone(&spooler);
        let submission = tokio::spawn(async move { submitter.submit(batch).await });
        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("spool batch must start");

        shutdown.send();
        tokio::task::yield_now().await;
        assert!(
            !worker.is_finished(),
            "shutdown must not detach physically running spool work"
        );
        release_tx.send(()).expect("release physical spool work");
        let report = submission.await.expect("submission task must join");
        assert!(report.actions()[0].error().is_none());
        assert_eq!(
            worker.await.expect("spool worker must join"),
            crate::ToriiCriticalWorkerExit::StoppedByShutdown
        );
    }
}
