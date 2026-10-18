//! Original driver joiner ownership of its already-admitted retired publication.
//!
//! One fixed control and one release registration are funded before the existing
//! joiner starts. After physically joining the original workers, that same thread
//! retries only the original store capability. No lifecycle map owns an I/O call.

use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Waker},
    time::Duration,
};

use iroha_allocation::{
    AllocationBudget, AllocationRefusal, ChargedShared,
    release::{ReleaseRegistration, ReleaseWait},
};
use iroha_sumeragi::types::{Hash32, Millis};

use super::{
    DriverError,
    persist::Backoff,
    traits::{Clock, RetiredPublication, SystemClock},
    wake::ThreadWake,
};
use crate::execution_attempt::ExecutionAttemptError as Attempt;

/// The store retains only this funded notification state, never a store reference.
/// The job and its coordinator separately retain the original store, avoiding a cycle.
struct Control {
    instance: Hash32,
    wake: ThreadWake,
    stop: AtomicBool,
    complete: AtomicBool,
    phase: parking_lot::Mutex<Phase>,
    ready: parking_lot::Condvar,
}

enum Binding {
    Pending,
    Ready,
    Failed(Option<io::Error>),
}

struct Phase {
    binding: Binding,
    retiring: bool,
    failed: bool,
    appends: usize,
}

/// Unforgeable original joiner admission retained by exactly one native store.
/// Its constructor is private to funded driver admission; cloning preserves the
/// same original pool, instance and physical joining thread without new admission.
#[derive(Clone)]
pub struct OriginalPublicationOwner(ChargedShared<Control>);

impl OriginalPublicationOwner {
    pub(in crate::sumeragi) fn belongs_to(
        &self,
        instance: Hash32,
        budget: &AllocationBudget,
    ) -> bool {
        self.0.instance == instance && self.0.belongs_to(budget)
    }

    pub(in crate::sumeragi) fn same_owner(&self, other: &Self) -> bool {
        ChargedShared::ptr_eq(&self.0, &other.0)
    }

    pub(in crate::sumeragi) fn require_binding_thread(&self) -> io::Result<()> {
        if self.0.wake.original_thread().id() != std::thread::current().id()
            || !matches!(self.0.phase.lock().binding, Binding::Pending)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "publication owner can only bind once on its original joining thread",
            ));
        }
        Ok(())
    }

    pub(in crate::sumeragi) fn admit_append(&self) -> io::Result<AppendPermit<'_>> {
        let mut phase = self.0.phase.lock();
        if (!matches!(phase.binding, Binding::Ready)
            || phase.failed
            || phase.retiring
            || self.0.stop.load(Ordering::Acquire))
            && !cfg!(all(test, sumeragi_core_mutation = "HC425"))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "original publication owner is not live",
            ));
        }
        phase.appends = phase.appends.checked_add(1).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "original append count overflow")
        })?;
        Ok(AppendPermit(self))
    }

    /// Signal only the original funded joiner. This performs no native I/O.
    pub(in crate::sumeragi) fn retire(&self) {
        {
            let mut phase = self.0.phase.lock();
            phase.retiring = true;
        }
        self.0.wake.notify();
    }

    pub(in crate::sumeragi) fn require_resume(&self) -> io::Result<()> {
        let phase = self.0.phase.lock();
        if self.0.wake.original_thread().id() != std::thread::current().id()
            || !matches!(phase.binding, Binding::Ready)
            || !phase.retiring
            || phase.failed
            || (phase.appends != 0 && !cfg!(all(test, sumeragi_core_mutation = "HC426")))
            || self.0.stop.load(Ordering::Acquire)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "only the retired original joiner may continue its publication",
            ));
        }
        Ok(())
    }
}

/// Inline admission lasts through the actual append and all original I/O guards.
/// Its release wakes the original joiner after releasing the short phase mutex.
pub(in crate::sumeragi) struct AppendPermit<'a>(&'a OriginalPublicationOwner);
impl Drop for AppendPermit<'_> {
    fn drop(&mut self) {
        {
            let mut phase = self.0.0.phase.lock();
            phase.appends = phase
                .appends
                .checked_sub(1)
                .expect("original append permit");
        }
        self.0.0.wake.notify();
    }
}

/// Coordinator custody and final-shutdown signal; no callback runs under a map.
#[derive(Clone)]
pub(super) struct RetirementControl {
    owner: OriginalPublicationOwner,
    _publication: Arc<dyn RetiredPublication>,
}

impl RetirementControl {
    pub(super) fn stop(&self) {
        {
            let _phase = self.owner.0.phase.lock();
            self.owner.0.stop.store(true, Ordering::Release);
        }
        self.owner.0.wake.notify();
    }

    pub(super) fn retire(&self) {
        self.owner.retire();
    }

    pub(super) fn wait_bound(&self) -> Result<(), DriverError> {
        let mut phase = self.owner.0.phase.lock();
        loop {
            match &mut phase.binding {
                Binding::Pending => {
                    self.owner.0.ready.wait(&mut phase);
                }
                Binding::Ready => {
                    return if phase.failed || self.owner.0.stop.load(Ordering::Acquire) {
                        Err(DriverError::RetirementBinding(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "original publication owner stopped during binding",
                        )))
                    } else {
                        Ok(())
                    };
                }
                Binding::Failed(original) => {
                    return Err(DriverError::RetirementBinding(
                        original.take().unwrap_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "original publication binding has already failed",
                            )
                        }),
                    ));
                }
            }
        }
    }

    pub(super) fn complete(&self) -> bool {
        self.owner.0.complete.load(Ordering::Acquire)
    }
}

/// Cancellation precedes destruction of the exact move-only refusal, including unwind.
struct Retry {
    registration: ReleaseRegistration,
    error: Option<Attempt<io::Error>>,
    failures: u32,
    due: Millis,
}

impl Retry {
    fn source(&self) -> Option<&ReleaseWait> {
        let Some(Attempt::Deferred(reason)) = &self.error else {
            return None;
        };
        match reason.allocation_refusal() {
            Some(AllocationRefusal::Capacity { release, .. }) => Some(release),
            _ => None,
        }
    }

    fn ready(&mut self, now: Millis) -> bool {
        let Some(Attempt::Deferred(reason)) = &self.error else {
            return now >= self.due;
        };
        let Some(AllocationRefusal::Capacity { release, .. }) = reason.allocation_refusal() else {
            return now >= self.due;
        };
        // Only the exact refused pool's release makes a capacity retry eligible.
        // bind_thread uses the original joiner; this Context is never retained.
        if self
            .registration
            .poll_wait(release, &mut Context::from_waker(Waker::noop()))
            .is_pending()
        {
            return false;
        }
        self.registration.cancel();
        true
    }

    fn refuse(&mut self, error: Attempt<io::Error>, now: Millis, backoff: Backoff) {
        self.registration.cancel();
        // The old refusal survives the actual retry and retires after its result arrives.
        self.error = Some(error);
        self.failures = self.failures.saturating_add(1);
        self.due = now.saturating_add(backoff.delay(self.failures));
    }

    fn clear(&mut self) {
        self.registration.cancel();
        self.error = None;
    }
}

/// Entire retry state stays on the existing joiner; no Result crosses a shared slot.
pub(super) struct RetirementJob {
    // Refusal/registration retirement precedes the last original store reference.
    retry: Retry,
    control: ChargedShared<Control>,
    publication: Arc<dyn RetiredPublication>,
    bound: bool,
    backoff: Backoff,
}

impl RetirementJob {
    fn admission_bytes() -> Result<usize, AllocationRefusal> {
        ChargedShared::<Control>::allocation_layout()
            .size()
            .checked_add(ReleaseRegistration::allocation_layout().size())
            .ok_or(AllocationRefusal::DemandOverflow)
    }

    pub(super) fn admit(
        publication: Arc<dyn RetiredPublication>,
        instance: Hash32,
        budget: &AllocationBudget,
        backoff: Backoff,
    ) -> Result<(RetirementControl, Self), DriverError> {
        if publication.instance() != instance || !publication.belongs_to(budget) {
            return Err(DriverError::RetirementIdentity);
        }
        let mut reservation = budget.try_reserve_bytes(Self::admission_bytes()?)?;
        let registration = ReleaseRegistration::from_reservation(&mut reservation)?;
        let control = ChargedShared::from_reservation(
            Control {
                instance,
                phase: parking_lot::Mutex::new(Phase {
                    binding: Binding::Pending,
                    retiring: false,
                    failed: false,
                    appends: 0,
                }),
                ready: parking_lot::Condvar::new(),
                wake: ThreadWake::new(),
                stop: AtomicBool::new(false),
                complete: AtomicBool::new(false),
            },
            &mut reservation,
        )
        .map_err(|(_, error)| DriverError::Allocation(error))?;
        let observer = RetirementControl {
            owner: OriginalPublicationOwner(control.clone()),
            _publication: Arc::clone(&publication),
        };
        Ok((
            observer,
            Self {
                control,
                publication,
                bound: false,
                retry: Retry {
                    registration,
                    error: None,
                    failures: 0,
                    due: 0,
                },
                backoff,
            },
        ))
    }

    /// Bind the original store before acknowledging admission to any worker.
    pub(super) fn bind_current(&mut self) {
        if self.bound {
            return;
        }
        self.bound = true;
        self.control.wake.bind_current();
        self.retry
            .registration
            .bind_thread(self.control.wake.original_thread());
        let result = self
            .publication
            .bind_owner(OriginalPublicationOwner(self.control.clone()));
        {
            let mut phase = self.control.phase.lock();
            phase.binding = match result {
                Ok(()) => Binding::Ready,
                Err(error) => {
                    phase.failed = true;
                    Binding::Failed(Some(error))
                }
            };
        }
        self.control.ready.notify_all();
    }

    /// Called only after the original driver workers have all been physically joined.
    pub(super) fn run(mut self) {
        let clock = SystemClock::new();
        while !self.control.stop.load(Ordering::Acquire) {
            let eligible = {
                let phase = self.control.phase.lock();
                if phase.failed {
                    return;
                }
                phase.retiring
                    && (phase.appends == 0 || cfg!(all(test, sumeragi_core_mutation = "HC426")))
            };
            if !eligible {
                if !self.control.wake.take_pending() {
                    std::thread::park();
                }
                continue;
            }
            let now = clock.now();
            if self.retry.ready(now) {
                match self
                    .publication
                    .resume(&OriginalPublicationOwner(self.control.clone()))
                {
                    Ok(()) => {
                        self.retry.clear();
                        self.control.complete.store(true, Ordering::Release);
                        return;
                    }
                    Err(error) => self.retry.refuse(error, clock.now(), self.backoff),
                }
            }
            if self.control.stop.load(Ordering::Acquire) || self.control.wake.take_pending() {
                continue;
            }
            if self.retry.source().is_some() {
                // poll_wait is run before parking, including immediately after refusal.
                // Actual release and final stop both unpark the same original thread.
                if !self.retry.ready(clock.now()) {
                    std::thread::park();
                }
            } else {
                let wait = self.retry.due.saturating_sub(clock.now());
                if wait != 0 {
                    std::thread::park_timeout(Duration::from_millis(wait));
                }
            }
        }
        // Final stop closes new permit admission under the same phase mutex.
        // Drain only already-admitted native appends; never start another retry.
        loop {
            let unfinished = { self.control.phase.lock().appends != 0 };
            if !unfinished || cfg!(all(test, sumeragi_core_mutation = "HC426")) {
                break;
            }
            if !self.control.wake.take_pending() {
                std::thread::park();
            }
        }
        self.retry.clear();
    }
}

impl Drop for RetirementJob {
    fn drop(&mut self) {
        // A failed/missing handoff or panic cannot leave append admission live.
        // This shared tombstone outlives the job in its exact original store.
        {
            let mut phase = self.control.phase.lock();
            if !self.control.complete.load(Ordering::Acquire) {
                phase.failed = true;
            }
            if matches!(phase.binding, Binding::Pending) {
                phase.binding = Binding::Failed(Some(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "original publication joiner ended before binding",
                )));
            }
        }
        self.control.ready.notify_all();
        self.control.wake.notify();
    }
}

#[cfg(test)]
mod tests;

/// Test harness owning the same admitted physical joiner used by real drivers.
/// Direct native append controls use this explicit owner; no append bypass exists.
#[cfg(any(test, feature = "iroha-core-tests"))]
pub(in crate::sumeragi) struct PublicationSession {
    control: RetirementControl,
    thread: Option<std::thread::JoinHandle<()>>,
}
#[cfg(any(test, feature = "iroha-core-tests"))]
impl PublicationSession {
    #[cfg(test)]
    pub(in crate::sumeragi) fn start(
        publication: Arc<dyn RetiredPublication>,
        budget: &AllocationBudget,
    ) -> Self {
        Self::try_start(publication, budget).unwrap()
    }
    pub(in crate::sumeragi) fn try_start(
        publication: Arc<dyn RetiredPublication>,
        budget: &AllocationBudget,
    ) -> Result<Self, DriverError> {
        let instance = publication.instance();
        let (control, job) =
            RetirementJob::admit(publication, instance, budget, Backoff::default())?;
        let joiner = super::DriverJoiner::start(Some(job))?;
        let binding = control.wait_bound();
        if binding.is_err() {
            control.stop();
        }
        let thread = joiner
            .handoff(Vec::new())
            .ok()
            .expect("original publication joiner handoff");
        let session = Self {
            control,
            thread: Some(thread),
        };
        binding?;
        Ok(session)
    }
    #[cfg(test)]
    pub(in crate::sumeragi) fn admitted_bytes() -> usize {
        RetirementJob::admission_bytes().unwrap()
    }
    #[cfg(test)]
    pub(in crate::sumeragi) fn retire(&self) {
        self.control.retire();
    }
    #[cfg(test)]
    pub(in crate::sumeragi) fn complete(&self) -> bool {
        self.control.complete()
    }
    #[cfg(test)]
    pub(in crate::sumeragi) fn original_thread(&self) -> std::thread::ThreadId {
        self.thread
            .as_ref()
            .expect("original publication joiner")
            .thread()
            .id()
    }
    #[cfg(test)]
    pub(in crate::sumeragi) fn finished(&self) -> bool {
        self.thread
            .as_ref()
            .is_none_or(std::thread::JoinHandle::is_finished)
    }
    #[cfg(test)]
    pub(in crate::sumeragi) fn join(mut self) -> std::thread::Result<()> {
        self.thread
            .take()
            .expect("original publication joiner")
            .join()
    }
    #[cfg(test)]
    pub(in crate::sumeragi) fn retained_bytes() -> usize {
        ChargedShared::<Control>::allocation_layout().size()
    }
}
#[cfg(any(test, feature = "iroha-core-tests"))]
impl Drop for PublicationSession {
    fn drop(&mut self) {
        self.control.stop();
        if let Some(thread) = self.thread.take() {
            super::discard_join_result(thread.join());
        }
    }
}
