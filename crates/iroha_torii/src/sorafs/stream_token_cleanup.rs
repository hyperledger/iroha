//! Bounded, cancellation-safe release of authenticated external stream leases.
//!
//! One queue slot is reserved before Accepted admission. A body owns that reservation until
//! cancellation or completion; its destructor only enqueues the exact accepted record. The
//! retained critical worker runs one physical release at a time, independently of query gates.
//! Queue/reservations are bounded by the configured admission pending limit, plus one physical
//! work item. This does not promise a finite shutdown if an injected synchronous provider hangs.
use super::StreamTokenAdmissionCaptureV1;
use crate::ToriiCriticalWorkerExit;
use iroha_data_model::sorafs::stream_token_gateway::StreamTokenGatewayAdmissionRecordV1;
use iroha_futures::supervisor::ShutdownSignal;
use std::{
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
    },
};
use tokio::{sync::mpsc, task::JoinHandle};

/// Prepare only the exactly configured capture/cleanup pair, before the HTTP service starts.
pub fn prepare(
    capture: Option<&Arc<StreamTokenAdmissionCaptureV1>>,
    capacity: Option<u32>,
    shutdown: ShutdownSignal,
) -> Result<Option<Arc<StreamTokenCleanupV1>>, crate::ToriiBuildError> {
    match (capture, capacity) {
        (None, None) => Ok(None),
        (Some(_), Some(capacity)) => StreamTokenCleanupV1::new(capacity, shutdown)
            .map(Arc::new)
            .map(Some)
            .map_err(|error| {
                crate::ToriiBuildError::invalid_configuration("stream_token_cleanup", error)
            }),
        _ => Err(crate::ToriiBuildError::invalid_configuration(
            "stream_token_cleanup",
            "stream-token admission capture and cleanup capacity must be configured together",
        )),
    }
}

/// Register exactly one cleanup worker in the existing Torii startup/rollback lifecycle.
pub fn register_worker(
    app: &crate::AppState,
    workers: &mut Vec<crate::ToriiCriticalWorker>,
) -> Result<(), &'static str> {
    match (
        app.stream_token_admission_capture.as_ref(),
        app.stream_token_cleanup.as_ref(),
    ) {
        (None, None) => Ok(()),
        (Some(_), Some(cleanup)) => {
            workers.push(crate::ToriiCriticalWorker {
                name: "sorafs_stream_token_cleanup",
                task: cleanup.start()?,
            });
            Ok(())
        }
        _ => Err("stream-token admission requires its retained cleanup worker"),
    }
}

struct CleanupState {
    started: AtomicBool,
    receiver_alive: AtomicBool,
    receiver_failed: AtomicBool,
    unsettled: AtomicUsize,
    fenced: AtomicBool,
    unresolved: AtomicUsize,
    physical: AtomicUsize,
    shutdown: ShutdownSignal,
}
impl CleanupState {
    fn fail_closed(&self) {
        self.unresolved.fetch_add(1, Ordering::AcqRel);
        self.fenced.store(true, Ordering::Release);
        self.shutdown.send();
    }
}

/// Local resource owner; neither this queue nor a ticket authenticates a provider record.
pub struct StreamTokenCleanupV1 {
    sender: mpsc::Sender<LeaseCleanupWork>,
    receiver: Mutex<Option<mpsc::Receiver<LeaseCleanupWork>>>,
    state: Arc<CleanupState>,
}
impl fmt::Debug for StreamTokenCleanupV1 {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("StreamTokenCleanupV1")
            .field("fenced", &self.state.fenced.load(Ordering::Acquire))
            .field("unresolved", &self.state.unresolved.load(Ordering::Acquire))
            .field("unsettled", &self.state.unsettled.load(Ordering::Acquire))
            .field(
                "receiver_failed",
                &self.state.receiver_failed.load(Ordering::Acquire),
            )
            .finish_non_exhaustive()
    }
}
impl StreamTokenCleanupV1 {
    /// Allocate the configured local ticket ceiling, without starting a detached task.
    pub(crate) fn new(capacity: u32, shutdown: ShutdownSignal) -> Result<Self, &'static str> {
        if capacity == 0 || capacity > 1_000_000 {
            return Err("stream-token cleanup capacity must be within 1..=1000000");
        }
        let capacity = usize::try_from(capacity)
            .map_err(|_| "stream-token cleanup capacity is not representable")?;
        let (sender, receiver) = mpsc::channel(capacity);
        Ok(Self {
            sender,
            receiver: Mutex::new(Some(receiver)),
            state: Arc::new(CleanupState {
                started: AtomicBool::new(false),
                receiver_alive: AtomicBool::new(false),
                receiver_failed: AtomicBool::new(false),
                unsettled: AtomicUsize::new(0),
                fenced: AtomicBool::new(false),
                unresolved: AtomicUsize::new(0),
                physical: AtomicUsize::new(0),
                shutdown,
            }),
        })
    }

    /// Start the sole receiver and return its handle to the existing critical-worker supervisor.
    pub(crate) fn start(&self) -> Result<JoinHandle<ToriiCriticalWorkerExit>, &'static str> {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| "stream-token cleanup requires the existing async runtime")?;
        let mut receiver = self
            .receiver
            .lock()
            .map_err(|_| "stream-token cleanup receiver state is poisoned")?;
        let receiver = receiver
            .take()
            .ok_or("stream-token cleanup worker was already started")?;
        // Construct before spawn: cancellation before the first poll must fence the receiver too.
        let owner = CleanupReceiver {
            receiver,
            state: Arc::clone(&self.state),
            clean: false,
        };
        self.state.receiver_alive.store(true, Ordering::Release);
        self.state.started.store(true, Ordering::Release);
        Ok(runtime.spawn(run(owner)))
    }

    /// Reserve before the external Accepted side effect; no waiting queue is created here.
    pub(crate) fn try_reserve(&self) -> Result<StreamTokenCleanupTicketV1, &'static str> {
        if !self.state.started.load(Ordering::Acquire)
            || !self.state.receiver_alive.load(Ordering::Acquire)
            || self.state.fenced.load(Ordering::Acquire)
            || self.state.shutdown.is_sent()
        {
            return Err("stream-token cleanup is unavailable");
        }
        let permit = self
            .sender
            .clone()
            .try_reserve_owned()
            .map_err(|_| "stream-token cleanup capacity is unavailable")?;
        // Close a race with shutdown/failure during reservation, before the external side effect.
        if !self.state.receiver_alive.load(Ordering::Acquire)
            || self.state.fenced.load(Ordering::Acquire)
            || self.state.shutdown.is_sent()
        {
            return Err("stream-token cleanup is unavailable");
        }
        Ok(StreamTokenCleanupTicketV1 {
            permit,
            // Allocate settlement before Accepted admission; arming only transfers ownership.
            settlement: Arc::new(LeaseSettlement {
                state: Arc::clone(&self.state),
                disposition: AtomicU8::new(0),
            }),
        })
    }
}
impl Drop for StreamTokenCleanupV1 {
    fn drop(&mut self) {
        self.state.fenced.store(true, Ordering::Release);
        self.state.shutdown.send();
    }
}

/// Reserved capacity, held before admission and consumed only by an already validated lease.
pub struct StreamTokenCleanupTicketV1 {
    permit: mpsc::OwnedPermit<LeaseCleanupWork>,
    settlement: Arc<LeaseSettlement>,
}
impl StreamTokenCleanupTicketV1 {
    /// Arm immediately after capture returns an authenticated Accepted record, before other work.
    /// This private ownership transfer does not replace capture's exact record validation.
    #[expect(
        clippy::large_types_passed_by_value,
        reason = "The authenticated record moves into cancellation-safe lease cleanup ownership."
    )]
    pub(crate) fn arm(
        self,
        capture: Arc<StreamTokenAdmissionCaptureV1>,
        record: StreamTokenGatewayAdmissionRecordV1,
    ) -> ExternalStreamTokenLeaseV1 {
        self.settlement
            .state
            .unsettled
            .fetch_add(1, Ordering::AcqRel);
        ExternalStreamTokenLeaseV1 {
            permit: Some(self.permit),
            work: Some(LeaseCleanupWork {
                capture,
                record,
                settlement: self.settlement,
            }),
        }
    }
}

/// Cancellation-safe ownership of exactly one accepted public lease record.
pub struct ExternalStreamTokenLeaseV1 {
    permit: Option<mpsc::OwnedPermit<LeaseCleanupWork>>,
    work: Option<LeaseCleanupWork>,
}
impl fmt::Debug for ExternalStreamTokenLeaseV1 {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("ExternalStreamTokenLeaseV1")
            .finish_non_exhaustive()
    }
}
impl Drop for ExternalStreamTokenLeaseV1 {
    fn drop(&mut self) {
        if let (Some(permit), Some(work)) = (self.permit.take(), self.work.take()) {
            // Receiver::close is graceful and keeps alive=true. Unexpected receiver loss must
            // account the known record even if Tokio retains a racing send until Sender drop.
            let settlement = Arc::clone(&work.settlement);
            if !settlement.state.receiver_alive.load(Ordering::Acquire) {
                settlement.unresolved_if_pending();
                return;
            }
            // No provider I/O, blocking mutex, task creation or telemetry callback runs here.
            drop(permit.send(work));
            if !settlement.state.receiver_alive.load(Ordering::Acquire) {
                settlement.unresolved_if_pending();
            }
        }
    }
}

struct LeaseCleanupWork {
    capture: Arc<StreamTokenAdmissionCaptureV1>,
    record: StreamTokenGatewayAdmissionRecordV1,
    settlement: Arc<LeaseSettlement>,
}
impl LeaseCleanupWork {
    fn claim_physical(&self) -> Option<PhysicalRelease> {
        self.settlement
            .disposition
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| PhysicalRelease::new(Arc::clone(&self.settlement.state)))
    }
    fn release(self) {
        match self.capture.release_lease(&self.record) {
            Ok(_) => self.settlement.acknowledged(),
            Err(error) => {
                iroha_logger::error!(
                    ?error,
                    gateway_sequence = self.record.outcome.binding.gateway_sequence,
                    "external stream-token lease release is unresolved; admission is fenced"
                );
            }
        }
        // An error or panic leaves this work armed. Drop fences and signals shutdown without
        // claiming successful release; the provider's authenticated expiry remains the bound.
    }
}
impl Drop for LeaseCleanupWork {
    fn drop(&mut self) {
        self.settlement.unresolved();
    }
}

// Zero is pending, one is claimed for physical work, two is acknowledged, three is unresolved.
// Sender-side receiver loss may settle only Pending; a claimed physical worker owns its actual
// completion even if the supervising receiver disappears while the call is still running.
struct LeaseSettlement {
    state: Arc<CleanupState>,
    disposition: AtomicU8,
}
impl LeaseSettlement {
    fn acknowledged(&self) {
        if self
            .disposition
            .compare_exchange(1, 2, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.state.unsettled.fetch_sub(1, Ordering::AcqRel);
        }
    }
    fn unresolved_if_pending(&self) {
        if self
            .disposition
            .compare_exchange(0, 3, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.state.unsettled.fetch_sub(1, Ordering::AcqRel);
            self.state.fail_closed();
        }
    }
    fn unresolved(&self) {
        let mut current = self.disposition.load(Ordering::Acquire);
        while current < 2 {
            match self
                .disposition
                .compare_exchange(current, 3, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    self.state.unsettled.fetch_sub(1, Ordering::AcqRel);
                    self.state.fail_closed();
                    return;
                }
                Err(observed) => current = observed,
            }
        }
    }
}
// Drop publishes receiver loss before the Receiver field drains. This order is structural,
// including cancellation before the first poll, not dependent on async argument destruction.
struct CleanupReceiver {
    receiver: mpsc::Receiver<LeaseCleanupWork>,
    state: Arc<CleanupState>,
    clean: bool,
}
impl Drop for CleanupReceiver {
    fn drop(&mut self) {
        self.state.receiver_alive.store(false, Ordering::Release);
        if !self.clean {
            self.state.receiver_failed.store(true, Ordering::Release);
            self.state.fenced.store(true, Ordering::Release);
            self.state.shutdown.send();
        }
    }
}

struct PhysicalRelease(Arc<CleanupState>);
impl PhysicalRelease {
    fn new(state: Arc<CleanupState>) -> Self {
        state.physical.fetch_add(1, Ordering::AcqRel);
        Self(state)
    }
}
impl Drop for PhysicalRelease {
    fn drop(&mut self) {
        self.0.physical.fetch_sub(1, Ordering::AcqRel);
    }
}

async fn run(mut owner: CleanupReceiver) -> ToriiCriticalWorkerExit {
    let state = Arc::clone(&owner.state);
    let mut closing = false;
    loop {
        if state.shutdown.is_sent() && !closing {
            state.fenced.store(true, Ordering::Release);
            owner.receiver.close();
            closing = true;
        }
        let work = if closing {
            owner.receiver.recv().await
        } else {
            tokio::select! {
                biased;
                () = state.shutdown.receive() => continue,
                work = owner.receiver.recv() => work,
            }
        };
        let Some(work) = work else { break };
        let Some(physical) = work.claim_physical() else {
            continue;
        };
        // The join is deliberately not selected against shutdown or a request deadline. There
        // is at most one physical release, and cancellation does not free its occupied capacity.
        if crate::panic_recovery::join_recoverable(
            crate::panic_recovery::spawn_blocking_recoverable(move || {
                let _physical = physical;
                work.release();
            }),
        )
        .await
        .is_err()
        {
            iroha_logger::error!(
                "stream-token cleanup physical worker failed; admission is fenced"
            );
            state.fenced.store(true, Ordering::Release);
            state.shutdown.send();
        }
    }
    owner.clean = true;
    if state.unresolved.load(Ordering::Acquire) != 0 {
        iroha_logger::error!(
            unresolved = state.unresolved.load(Ordering::Acquire),
            "stream-token cleanup stopped with unresolved leases bounded by external expiry"
        );
        ToriiCriticalWorkerExit::UnexpectedExit
    } else {
        ToriiCriticalWorkerExit::StoppedByShutdown
    }
}

#[cfg(test)]
pub mod test_support;
#[cfg(test)]
mod tests;
