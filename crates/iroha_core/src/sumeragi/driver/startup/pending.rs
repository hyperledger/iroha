//! Prepaid preparation and activation on one instance's original joining thread.
//!
//! This owner has no lane-registry dependency. Preparation retains its own exact
//! typed refusal and recovery; the context supplies only cancellation and waits
//! on the original borrowed capacity source or configured local backoff.

use std::{
    sync::{
        OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Waker},
    time::Duration,
};

use iroha_allocation::{
    AllocationBudget, AllocationRefusal, ChargedShared, release::ReleaseRegistration,
};
use iroha_sumeragi::types::Hash32;
use parking_lot::Mutex;

use super::{
    DriverError, DriverJoiner, DriverPreparation, OriginalJoiner, OriginalWorkerPanic,
    PreparedWorkers, RetirementControl, RetirementJob, RunningDriver, Worker, WorkerAdmission,
    WorkerStart, discard_join_result,
};
use crate::execution_attempt::ExecutionAttemptError as Attempt;
use crate::sumeragi::driver::{
    persist::Backoff,
    traits::{BlockStore, BodyStore, Clock, Executor, Net, RecordStore, SystemClock},
    wake::ThreadWake,
};

/// An owned completed startup refusal, retaining its original typed storage source.
#[derive(Debug, thiserror::Error)]
pub enum StartupPreparationError {
    /// Original native I/O error, including its OS code or exact custom source.
    #[error("{0}")]
    Io(#[from] std::io::Error),
    /// Original committed-prefix failure, including height and native read source.
    #[error("{0}")]
    History(#[from] crate::sumeragi::driver::StartupHistoryError),
    /// Existing configuration or key-admission diagnostic.
    #[error("{0}")]
    Message(String),
}

enum Phase {
    Preparing,
    AwaitingActivation,
    StartingWorkers,
    Ready(PreparedWorkers),
    Refused(DriverError),
    PreparationRefused(Attempt<StartupPreparationError>),
    Transferred,
    Closed,
}

enum TransferDecision {
    Pending,
    Transferred,
    Abandoned(Phase),
}

struct Control {
    phase: Mutex<Phase>,
    cancelled: AtomicBool,
    shutdown: AtomicBool,
    retirement: OnceLock<RetirementControl>,
    join_failure: Mutex<Option<OriginalWorkerPanic>>,
    wake: ThreadWake,
    workers: [OnceLock<std::thread::ThreadId>; Worker::COUNT],
    #[cfg(test)]
    joining: AtomicBool,
}

/// Exact original worker membership, published before any backend callback.
#[derive(Clone)]
pub(super) struct WorkerOrigin(ChargedShared<Control>);

impl WorkerOrigin {
    pub(super) fn retain_join_failure(&self, failure: Option<OriginalWorkerPanic>) {
        if let Some(error) = failure {
            self.0.retain_join_failure(error);
        }
    }

    pub(super) fn bind(self, worker: Worker) {
        let index = worker.index();
        self.0.workers[index]
            .set(std::thread::current().id())
            .expect("one original thread per startup worker role");
    }
}

impl Control {
    fn retire(&self) {
        let retirement = {
            let _phase = self.phase.lock();
            self.cancelled.store(true, Ordering::Release);
            self.retirement.get().cloned()
        };
        if let Some(retirement) = retirement {
            retirement.retire();
        }
        self.wake.notify();
    }

    fn cancel(&self) {
        // Installation and final stop share the phase mutex. A stop cannot miss
        // a concurrently admitted original publication control. Never call it
        // or destroy its shared custody while holding this mutex.
        let retirement = {
            let _phase = self.phase.lock();
            self.shutdown.store(true, Ordering::Release);
            self.cancelled.store(true, Ordering::Release);
            self.retirement.get().cloned()
        };
        if let Some(retirement) = retirement
            && !cfg!(all(test, sumeragi_core_mutation = "HC420"))
        {
            retirement.stop();
        }
        self.wake.notify();
    }

    fn install_retirement(&self, retirement: Option<&RetirementControl>) {
        let Some(retirement) = retirement else { return };
        let (stopped, retired) = {
            let _phase = self.phase.lock();
            assert!(self.retirement.set(retirement.clone()).is_ok());
            (self.shutdown.load(Ordering::Acquire), self.cancelled())
        };
        if stopped {
            retirement.stop();
        } else if retired {
            retirement.retire();
        }
    }

    fn retain_join_failure(&self, error: OriginalWorkerPanic) {
        let mut original = Some(error);
        {
            let mut failure = self.join_failure.lock();
            if failure.is_none() {
                *failure = original.take();
            }
        }
        drop(original);
    }

    fn retirement_complete(&self) -> bool {
        self.join_failure.lock().is_none()
            && self
                .retirement
                .get()
                .is_none_or(RetirementControl::complete)
    }

    fn finish_untransferred(&self, mut retirement: Option<RetirementJob>) {
        // Even a normal worker creation/readiness refusal retains this prepaid
        // job until the coordinator retires the generation or finally stops it.
        while !self.cancelled() {
            if !self.wake.take_pending() {
                std::thread::park();
            }
        }
        if self.join_failure.lock().is_some() {
            return;
        }
        if cfg!(all(test, sumeragi_core_mutation = "HC419")) {
            return;
        }
        if let Some(job) = retirement.as_mut() {
            job.bind_current();
        }
        if let Some(job) = retirement {
            job.run();
        }
    }

    fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    fn refuse(&self, error: DriverError) {
        let previous = {
            let mut phase = self.phase.lock();
            std::mem::replace(&mut *phase, Phase::Refused(error))
        };
        // Only this thread writes a refusal, before publishing any worker owner.
        debug_assert!(matches!(
            previous,
            Phase::Preparing | Phase::StartingWorkers
        ));
        drop(previous);
    }

    // Transfer and cancellation select the sole worker owner under the same lock.
    // Once a transfer wins, the original joiner must receive those exact handles;
    // cancellation cannot close that receiver before the handoff completes.
    fn await_transfer(&self) -> bool {
        loop {
            let decision = if cfg!(all(test, sumeragi_core_mutation = "HC416")) {
                let transferred = matches!(*self.phase.lock(), Phase::Transferred);
                #[cfg(test)]
                super::tests::after_transfer_observation();
                if transferred {
                    TransferDecision::Transferred
                } else if self.cancelled() {
                    // Deliberately omit the atomic claim of untransferred Ready.
                    // CompletionOwner may now observe a concurrent Transferred.
                    return false;
                } else {
                    TransferDecision::Pending
                }
            } else {
                let decision = {
                    let mut phase = self.phase.lock();
                    if matches!(*phase, Phase::Transferred) {
                        TransferDecision::Transferred
                    } else if self.cancelled() {
                        TransferDecision::Abandoned(std::mem::replace(&mut *phase, Phase::Closed))
                    } else {
                        TransferDecision::Pending
                    }
                };
                #[cfg(test)]
                super::tests::after_transfer_observation();
                decision
            };
            match decision {
                TransferDecision::Transferred => return true,
                TransferDecision::Abandoned(original) => {
                    // Native stop, physical joins and refunds never hold the phase mutex.
                    drop(original);
                    return false;
                }
                TransferDecision::Pending => {
                    if !self.wake.take_pending() {
                        std::thread::park();
                    }
                }
            }
        }
    }

    fn reject_preparation(&self, error: Attempt<StartupPreparationError>) {
        let previous = {
            let mut phase = self.phase.lock();
            std::mem::replace(&mut *phase, Phase::PreparationRefused(error))
        };
        debug_assert!(matches!(previous, Phase::Preparing));
        drop(previous);
    }
}

/// A worker-local wait owner, funded before the original joining thread starts.
/// The registration is destroyed before its shared wake on every unwind path.
pub struct StartupContext {
    registration: ReleaseRegistration,
    control: ChargedShared<Control>,
    backoff: Backoff,
    failures: u32,
}

/// Unregister inside the wait frame before its caller's borrowed refusal can drop.
struct WaitRegistration<'a>(&'a mut ReleaseRegistration);
impl Drop for WaitRegistration<'_> {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

impl StartupContext {
    /// Whether final shutdown or generation retirement has cancelled this job.
    #[must_use]
    pub fn cancelled(&self) -> bool {
        self.control.cancelled()
    }

    /// Wait for the borrowed original capacity source, or configured local retry.
    ///
    /// The caller retains its full typed error/recovery through this wait and the
    /// next actual attempt. This function neither clones a refusal nor authorizes
    /// publication. `None` is for a refusal with no capacity release observation.
    /// Returns false when cancellation wins; no callback runs beneath a control lock.
    #[must_use]
    pub fn wait_retry(&mut self, original: Option<&AllocationRefusal>) -> bool {
        self.failures = self.failures.saturating_add(1);
        let clock = SystemClock::new();
        let due = clock
            .now()
            .saturating_add(self.backoff.delay(self.failures));
        let release = match original {
            Some(AllocationRefusal::Capacity { release, .. }) => Some(release),
            _ => None,
        };
        let registration = WaitRegistration(&mut self.registration);
        let ready = loop {
            if self.control.cancelled() {
                break false;
            }
            if let Some(release) = release {
                if registration
                    .0
                    .poll_wait(release, &mut Context::from_waker(Waker::noop()))
                    .is_ready()
                {
                    break true;
                }
            } else if clock.now() >= due {
                break true;
            }
            if self.control.wake.take_pending() {
                continue;
            }
            if release.is_some() {
                std::thread::park();
            } else {
                let remaining = due.saturating_sub(clock.now());
                if remaining != 0 {
                    std::thread::park_timeout(Duration::from_millis(remaining));
                }
            }
        };
        drop(registration);
        ready
    }

    fn await_activation(&self) -> bool {
        {
            let mut phase = self.control.phase.lock();
            debug_assert!(matches!(*phase, Phase::Preparing));
            *phase = Phase::AwaitingActivation;
        }
        loop {
            if self.cancelled() {
                return false;
            }
            let approved = matches!(*self.control.phase.lock(), Phase::StartingWorkers);
            if approved {
                return true;
            }
            if !self.control.wake.take_pending() {
                std::thread::park();
            }
        }
    }
}

/// The coordinator's observation of its one original generation-local startup.
pub enum StartupPoll {
    /// Preparation, worker readiness or cancellation cleanup is still owned.
    Pending,
    /// The prepared original inputs await the coordinator's fresh eligibility check.
    AwaitingActivation,
    /// Exact workers and their original joining thread transferred together.
    Ready(RunningDriver),
    /// The original typed driver refusal, moved out of the slot without projection.
    Refused(DriverError),
    /// The original typed preparation refusal; its generation remains retained.
    PreparationRefused(Attempt<StartupPreparationError>),
    /// Original cleanup and any admitted retirement publication have completed.
    Closed,
    /// The original joiner unwound; retain this generation until final shutdown.
    Failed,
}

/// Nonblocking retirement of an already-refused, explicitly cancelled generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartupRetirement {
    /// Original cleanup or its joining thread is still in progress.
    Pending,
    /// Original joins succeeded and every admitted publication completed.
    Joined,
    /// A missing, failed or Ready-owning joiner cannot certify retirement.
    Failed,
}

/// A startup's original join handle and fixed prepaid completion/control storage.
///
/// Callers must remove this owner from shared maps before polling or destroying
/// it. Polling never waits for a running thread. Final Drop cancels and joins the
/// original thread, except when invoked by that same thread's callback.
pub struct PendingDriver {
    control: ChargedShared<Control>,
    joiner: Option<OriginalJoiner>,
    failed: bool,
}

impl PendingDriver {
    pub(super) fn owns_worker(&self, current: std::thread::ThreadId) -> bool {
        self.control
            .workers
            .iter()
            .any(|worker| worker.get() == Some(&current))
    }

    pub(super) fn admission_bytes() -> Result<usize, AllocationRefusal> {
        ChargedShared::<Control>::allocation_layout()
            .size()
            .checked_add(ReleaseRegistration::allocation_layout().size())
            .ok_or(AllocationRefusal::DemandOverflow)
    }

    /// Admit preparation before starting this lane's intended original joiner.
    ///
    /// Preparation must preserve its original error and recovery owners until a
    /// retry returns. It creates admitted inputs, not protocol workers. Only this
    /// control's activation acknowledgement permits the common worker constructor.
    ///
    /// # Errors
    /// Returns original resource, physical-allocation or joiner-spawn refusal.
    pub fn spawn<N, R, B, K, C, E, F>(
        instance: Hash32,
        budget: &AllocationBudget,
        backoff: Backoff,
        prepare: F,
    ) -> Result<Self, DriverError>
    where
        N: Net + 'static,
        R: RecordStore + 'static,
        B: BodyStore + 'static,
        K: BlockStore + 'static,
        C: Clock + 'static,
        E: Executor + 'static,
        F: FnOnce(
                &mut StartupContext,
            ) -> Result<
                Option<DriverPreparation<N, R, B, K, C, E>>,
                Attempt<StartupPreparationError>,
            > + Send
            + 'static,
    {
        let mut reservation = budget.try_reserve_bytes(Self::admission_bytes()?)?;
        let registration = ReleaseRegistration::from_reservation(&mut reservation)?;
        let control = ChargedShared::from_reservation(
            Control {
                phase: Mutex::new(Phase::Preparing),
                cancelled: AtomicBool::new(false),
                shutdown: AtomicBool::new(false),
                retirement: OnceLock::new(),
                join_failure: Mutex::new(None),
                wake: ThreadWake::new(),
                workers: [const { OnceLock::new() }; Worker::COUNT],
                #[cfg(test)]
                joining: AtomicBool::new(false),
            },
            &mut reservation,
        )
        .map_err(|(_, error)| DriverError::Allocation(error))?;
        let mut context = StartupContext {
            registration,
            control: control.clone(),
            backoff,
            failures: 0,
        };
        let original_budget = budget.clone();
        let joiner = OriginalJoiner::start_preparing(move |receive| {
            let _completion = CompletionOwner(context.control.clone());
            context.control.wake.bind_current();
            context
                .registration
                .bind_thread(context.control.wake.original_thread());
            if context.cancelled() {
                return;
            }
            let DriverPreparation {
                driver,
                config,
                start,
            } = match prepare(&mut context) {
                Ok(Some(prepared)) => prepared,
                Ok(None) => return,
                Err(error) => {
                    context.control.reject_preparation(error);
                    return;
                }
            };
            if start.init.instance != instance
                || !start.allocation_budget.same_pool(&original_budget)
            {
                context.control.refuse(DriverError::StartupIdentity);
                return;
            }
            // Admission only borrows these original prepared inputs. A capacity
            // retry never recreates or drops the already recovered executor.
            let mut previous = None;
            let (admitted, mut retirement) = loop {
                if context.cancelled() {
                    return;
                }
                let result = WorkerAdmission::new(&driver, &config, &start);
                match result {
                    Ok(admitted) => break admitted,
                    Err(
                        error @ (DriverError::Admission(_)
                        | DriverError::Allocation(_)
                        | DriverError::Buffer(_)),
                    ) => {
                        // The original previous error lives through the attempt.
                        // wait_retry cancelled its registration before replacement.
                        previous = Some(error);
                        let original = match previous.as_ref() {
                            Some(DriverError::Admission(original)) => Some(original),
                            _ => None,
                        };
                        if !context.wait_retry(original) {
                            return;
                        }
                    }
                    Err(error) => {
                        context.control.refuse(error);
                        return;
                    }
                }
            };
            drop(previous);
            context
                .control
                .install_retirement(admitted.retirement.as_ref());
            if let Some(job) = retirement.as_mut() {
                job.bind_current();
            }
            if let Some(control) = admitted.retirement.as_ref()
                && let Err(error) = control.wait_bound()
            {
                context.control.refuse(error);
                return;
            }
            let mut workers = WorkerStart::from_admission(driver, config, start, admitted);
            workers.origin = Some(WorkerOrigin(context.control.clone()));
            if !context.await_activation() {
                drop(workers);
                context.control.finish_untransferred(retirement);
                return;
            }
            // The actual worker constructor also checks the original node gate;
            // cancellation after approval retains every acquired prefix here.
            let prepared = match workers.spawn_workers() {
                Ok(prepared) => prepared,
                Err(error) => {
                    context.control.refuse(error);
                    context.control.finish_untransferred(retirement);
                    return;
                }
            };
            if context.cancelled() {
                drop(prepared);
                context.control.finish_untransferred(retirement);
                return;
            }
            {
                let mut phase = context.control.phase.lock();
                debug_assert!(matches!(*phase, Phase::StartingWorkers));
                *phase = Phase::Ready(prepared);
            }
            // Wait for this same completion's transfer before relinquishing the
            // startup control. The same original joiner claims and cleans any
            // cancelled untransferred owner outside the completion mutex.
            if !context.control.await_transfer() {
                context.control.finish_untransferred(retirement);
                return;
            }
            #[cfg(test)]
            let handoff_observation = context.control.clone();
            // Keep the already-paid startup owners through the ordinary join
            // loop. Releasing them can invoke original allocation callbacks;
            // those callbacks must not unwind before worker handoff is received.
            #[cfg(all(test, sumeragi_core_mutation = "HC407"))]
            {
                drop(_completion);
                drop(context);
            }
            #[cfg(test)]
            handoff_observation.joining.store(true, Ordering::Release);
            DriverJoiner::join_workers(receive, retirement);
            #[cfg(not(all(test, sumeragi_core_mutation = "HC407")))]
            {
                drop(_completion);
                drop(context);
            }
        })?;
        #[cfg(all(test, sumeragi_core_mutation = "HC404"))]
        while matches!(*control.phase.lock(), Phase::Preparing)
            && joiner
                .0
                .as_ref()
                .is_some_and(|owner| !owner.thread.is_finished())
        {
            std::thread::park_timeout(Duration::from_millis(1));
        }
        Ok(Self {
            control,
            joiner: Some(joiner),
            failed: false,
        })
    }

    /// Approve only these prepared inputs after a fresh generation eligibility check.
    /// Returns false if preparation is not ready or this original owner was cancelled.
    #[must_use]
    pub fn activate(&self) -> bool {
        let activated = {
            let mut phase = self.control.phase.lock();
            if self.control.cancelled() || !matches!(*phase, Phase::AwaitingActivation) {
                false
            } else {
                *phase = Phase::StartingWorkers;
                true
            }
        };
        if activated {
            self.control.wake.notify();
        }
        activated
    }

    /// Retire this generation while preserving its original publication job.
    /// Its admitted job runs only after every acquired worker joins successfully.
    pub fn retire(&self) {
        self.control.retire();
    }

    /// Finally stop this startup and its original retry job without waiting for I/O.
    /// An already-running native call completes on its original joining thread.
    pub fn cancel(&self) {
        self.control.cancel();
    }

    /// Whether this original generation has been cancelled.
    #[must_use]
    pub fn cancelled(&self) -> bool {
        self.control.cancelled()
    }

    /// Reap an explicitly retired refusal only after its original physical cleanup.
    /// A known-ended Ready owner or a failed joining thread never becomes success.
    /// The caller retains the original terminal error until Joined is observed.
    #[must_use]
    pub fn poll_cancelled_failure(&mut self) -> StartupRetirement {
        if !self.cancelled() || !self.failed {
            return StartupRetirement::Pending;
        }
        if matches!(*self.control.phase.lock(), Phase::Ready(_)) {
            return if cfg!(all(test, sumeragi_core_mutation = "HC413")) {
                StartupRetirement::Joined
            } else {
                StartupRetirement::Failed
            };
        }
        let Some(original) = self.joiner.as_ref().and_then(|joiner| joiner.0.as_ref()) else {
            return if cfg!(all(test, sumeragi_core_mutation = "HC413")) {
                StartupRetirement::Joined
            } else {
                StartupRetirement::Failed
            };
        };
        if !original.thread.is_finished() {
            return StartupRetirement::Pending;
        }
        let DriverJoiner { workers, thread } = self
            .joiner
            .take()
            .expect("observed original failure joiner")
            .take();
        drop(workers);
        if let Err(error) = thread.join() {
            self.control
                .retain_join_failure(OriginalWorkerPanic::new(error));
            return if cfg!(all(test, sumeragi_core_mutation = "HC413")) {
                StartupRetirement::Joined
            } else {
                StartupRetirement::Failed
            };
        }
        if !self.control.retirement_complete() {
            return StartupRetirement::Failed;
        }
        StartupRetirement::Joined
    }

    fn take_result(&self) -> Option<Phase> {
        let result = {
            let mut phase = self.control.phase.lock();
            if matches!(
                *phase,
                Phase::Ready(_) | Phase::Refused(_) | Phase::PreparationRefused(_)
            ) {
                Some(std::mem::replace(&mut *phase, Phase::Transferred))
            } else {
                None
            }
        };
        if result.is_some() {
            self.control.wake.notify();
        }
        result
    }

    /// Observe or transfer without waiting; physical joins and result destruction
    /// occur only after the completion mutex is released.
    #[must_use]
    pub fn poll(&mut self) -> StartupPoll {
        if self.failed {
            return StartupPoll::Failed;
        }
        let ended_ready = {
            let phase = self.control.phase.lock();
            matches!(*phase, Phase::Ready(_))
                && self.joiner.as_ref().is_none_or(|joiner| {
                    joiner
                        .0
                        .as_ref()
                        .is_none_or(|owner| owner.thread.is_finished())
                })
        };
        if ended_ready && !cfg!(all(test, sumeragi_core_mutation = "HC406")) {
            // An already-ended original joiner cannot authorize live exposure.
            // Keep the exact Ready worker owner and join handle for final Drop.
            self.failed = true;
            return StartupPoll::Failed;
        }
        if let Some(result) = self.take_result() {
            return match result {
                Phase::Ready(prepared) => {
                    let joiner = self
                        .joiner
                        .take()
                        .expect("original startup joiner transfers once");
                    StartupPoll::Ready(prepared.attach(joiner))
                }
                Phase::Refused(error) => {
                    // Worker creation/readiness consumed the original prepared
                    // inputs. The current generation remains excluded. Explicit
                    // ineligible retirement may reap it only after the original
                    // joiner successfully finishes; consumed owners never restart.
                    self.failed = true;
                    StartupPoll::Refused(error)
                }
                Phase::PreparationRefused(error) => {
                    self.failed = true;
                    StartupPoll::PreparationRefused(error)
                }
                _ => unreachable!("only an owned result was taken"),
            };
        }
        if self.joiner.as_ref().is_some_and(|joiner| {
            joiner
                .0
                .as_ref()
                .is_some_and(|owner| owner.thread.is_finished())
        }) {
            let DriverJoiner { workers, thread } =
                self.joiner.take().expect("observed original joiner").take();
            drop(workers);
            if let Err(error) = thread.join() {
                self.control
                    .retain_join_failure(OriginalWorkerPanic::new(error));
                self.failed = true;
                return StartupPoll::Failed;
            }
            if !self.control.retirement_complete() {
                self.failed = true;
                return StartupPoll::Failed;
            }
            return StartupPoll::Closed;
        }
        if self.joiner.is_none() {
            return StartupPoll::Closed;
        }
        if matches!(*self.control.phase.lock(), Phase::AwaitingActivation) && !self.cancelled() {
            StartupPoll::AwaitingActivation
        } else {
            StartupPoll::Pending
        }
    }
}

impl Drop for PendingDriver {
    fn drop(&mut self) {
        // Ready transferred its original joiner and publication control together.
        // Destroying the now-empty startup observer must not stop that live owner.
        if self.joiner.is_none() {
            return;
        }
        let current = std::thread::current().id();
        let on_worker = self.owns_worker(current);
        self.cancel();
        if let Some(Phase::Ready(prepared)) = self.take_result() {
            if let Some(joiner) = self.joiner.take() {
                prepared.attach(joiner).shutdown();
                return;
            }
            drop(prepared);
        }
        if let Some(joiner) = self.joiner.take() {
            let DriverJoiner { workers, thread } = joiner.take();
            drop(workers);
            if !on_worker && thread.thread().id() != current {
                discard_join_result(thread.join());
            }
        }
    }
}

/// Reclaim an untransferred Ready owner on its original non-protocol joiner.
struct CompletionOwner(ChargedShared<Control>);
impl Drop for CompletionOwner {
    fn drop(&mut self) {
        let abandoned = {
            let mut phase = self.0.phase.lock();
            if matches!(
                *phase,
                Phase::Refused(_) | Phase::PreparationRefused(_) | Phase::Transferred
            ) {
                None
            } else {
                Some(std::mem::replace(&mut *phase, Phase::Closed))
            }
        };
        drop(abandoned);
    }
}

#[cfg(test)]
impl PendingDriver {
    /// Construct a complete original Ready owner to test an already-ended joiner.
    pub(super) fn ready_with_joiner_for_test(
        prepared: PreparedWorkers,
        joiner: OriginalJoiner,
        budget: &AllocationBudget,
    ) -> Self {
        let mut reservation = budget
            .try_reserve_bytes(ChargedShared::<Control>::allocation_layout().size())
            .unwrap();
        let control = ChargedShared::from_reservation(
            Control {
                phase: Mutex::new(Phase::Ready(prepared)),
                cancelled: AtomicBool::new(false),
                shutdown: AtomicBool::new(false),
                retirement: OnceLock::new(),
                join_failure: Mutex::new(None),
                wake: ThreadWake::new(),
                workers: [const { OnceLock::new() }; Worker::COUNT],
                joining: AtomicBool::new(false),
            },
            &mut reservation,
        )
        .map_err(|(_, error)| error)
        .unwrap();
        Self {
            control,
            joiner: Some(joiner),
            failed: false,
        }
    }

    /// Whether the exact unexposed workers and original joining thread are retained.
    pub(super) fn retains_ready_for_test(&self) -> bool {
        matches!(*self.control.phase.lock(), Phase::Ready(_)) && self.joiner.is_some()
    }
}

#[cfg(test)]
impl PendingDriver {
    /// Observe the same Ready handle without transferring its worker/joiner owners.
    pub(in crate::sumeragi) fn ready_handle_for_test(
        &self,
    ) -> Option<crate::sumeragi::driver::DriverHandle> {
        match &*self.control.phase.lock() {
            Phase::Ready(prepared) => Some(prepared.handle.clone()),
            _ => None,
        }
    }
}

#[cfg(test)]
impl PendingDriver {
    /// Observe the original joiner's entry into its ordinary worker handoff loop.
    pub(super) fn original_join_wait_entered_for_test(&self) -> bool {
        self.control.joining.load(Ordering::Acquire)
    }
}

#[cfg(test)]
impl PendingDriver {
    /// Observe the actual refused phase without consuming its original typed error.
    pub(in crate::sumeragi) fn refusal_ready_for_test(&self) -> bool {
        matches!(*self.control.phase.lock(), Phase::Refused(_))
    }

    /// Identify the original physical owner before the completion transfers.
    pub(in crate::sumeragi) fn original_joiner_for_test(&self) -> std::thread::ThreadId {
        self.joiner
            .as_ref()
            .unwrap()
            .0
            .as_ref()
            .unwrap()
            .thread
            .thread()
            .id()
    }
}

#[cfg(test)]
impl PendingDriver {
    /// Whether the retained original physical joiner has ended, without consuming it.
    pub(in crate::sumeragi::driver) fn original_joiner_finished_for_test(&self) -> bool {
        self.joiner
            .as_ref()
            .unwrap()
            .0
            .as_ref()
            .unwrap()
            .thread
            .is_finished()
    }

    /// Match the original worker panic while its exact carrier is still retained.
    pub(super) fn original_join_failure_for_test(&self, expected: &str) -> bool {
        self.control
            .join_failure
            .lock()
            .as_ref()
            .is_some_and(|error| {
                error
                    .downcast_ref::<&str>()
                    .is_some_and(|original| *original == expected)
            })
    }
}

#[cfg(test)]
impl PendingDriver {
    /// Independent cleanup after observing a missing final-stop notification.
    pub(in crate::sumeragi) fn stop_original_publication_for_test(&self) {
        if let Some(retirement) = self.control.retirement.get() {
            retirement.stop();
        }
    }
}

#[cfg(test)]
mod panic_cleanup_tests {
    use super::*;
    use std::sync::{Arc, Weak, atomic::AtomicUsize};

    struct Replacement(Arc<AtomicUsize>);
    impl Drop for Replacement {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    struct Secondary {
        control: Weak<Control>,
        charge: Option<iroha_allocation::AllocationReservation>,
        unlocked: Arc<AtomicBool>,
        released: Arc<AtomicUsize>,
    }
    impl Drop for Secondary {
        fn drop(&mut self) {
            let unlocked = self
                .control
                .upgrade()
                .is_some_and(|control| control.join_failure.try_lock().is_some());
            self.unlocked.store(unlocked, Ordering::SeqCst);
            drop(self.charge.take());
            std::panic::panic_any(Replacement(self.released.clone()));
        }
    }

    #[test]
    fn secondary_startup_panic_disposal_leaves_failure_mutex_free_and_primary_unchanged() {
        let control = Arc::new(Control {
            phase: Mutex::new(Phase::Preparing),
            cancelled: AtomicBool::new(false),
            shutdown: AtomicBool::new(false),
            retirement: OnceLock::new(),
            join_failure: Mutex::new(None),
            wake: ThreadWake::new(),
            workers: [const { OnceLock::new() }; Worker::COUNT],
            joining: AtomicBool::new(false),
        });
        let primary = Arc::new(());
        control.retain_join_failure(OriginalWorkerPanic::new(Box::new(primary.clone())));
        let budget = AllocationBudget::new(1);
        let unlocked = Arc::new(AtomicBool::new(false));
        let released = Arc::new(AtomicUsize::new(0));
        control.retain_join_failure(OriginalWorkerPanic::new(Box::new(Secondary {
            control: Arc::downgrade(&control),
            charge: Some(budget.try_reserve_bytes(1).unwrap()),
            unlocked: unlocked.clone(),
            released: released.clone(),
        })));
        let exact = control
            .join_failure
            .lock()
            .as_ref()
            .unwrap()
            .downcast_ref::<Arc<()>>()
            .is_some_and(|error| Arc::ptr_eq(error, &primary));
        assert!(exact && unlocked.load(Ordering::SeqCst));
        assert!(!control.retirement_complete());
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(released.load(Ordering::SeqCst), 1);
        drop(control);
        assert_eq!(Arc::strong_count(&primary), 1);
    }
}
