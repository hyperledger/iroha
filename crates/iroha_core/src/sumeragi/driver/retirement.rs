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

/// The original capability outlives the worker even if its callback unwinds.
/// Completion only means the exact store returned success, never materialized bytes.
struct Control {
    publication: Arc<dyn RetiredPublication>,
    wake: ThreadWake,
    stop: AtomicBool,
    complete: AtomicBool,
}

/// Coordinator observation and final-shutdown signal; no callback runs under a map.
pub(super) struct RetirementControl(ChargedShared<Control>);

impl RetirementControl {
    pub(super) fn stop(&self) {
        self.0.stop.store(true, Ordering::Release);
        self.0.wake.notify();
    }

    pub(super) fn complete(&self) -> bool {
        self.0.complete.load(Ordering::Acquire)
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
                publication,
                wake: ThreadWake::new(),
                stop: AtomicBool::new(false),
                complete: AtomicBool::new(false),
            },
            &mut reservation,
        )
        .map_err(|(_, error)| DriverError::Allocation(error))?;
        let observer = RetirementControl(control.clone());
        Ok((
            observer,
            Self {
                control,
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

    /// Bind before receiving workers, while the original joiner is being started.
    pub(super) fn bind_current(&mut self) {
        self.control.wake.bind_current();
        self.retry
            .registration
            .bind_thread(self.control.wake.original_thread());
    }

    /// Called only after the original driver workers have all been physically joined.
    pub(super) fn run(mut self) {
        let clock = SystemClock::new();
        while !self.control.stop.load(Ordering::Acquire) {
            let now = clock.now();
            if self.retry.ready(now) {
                match self.control.publication.resume() {
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
        self.retry.clear();
    }
}

#[cfg(test)]
mod tests;
