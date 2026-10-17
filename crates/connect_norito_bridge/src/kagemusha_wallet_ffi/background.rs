//! One bounded native fold worker per opaque wallet, with cooperative payment priority.
//!
//! Each turn prepares one sub-proof under the wallet owner, proves it without the owner and
//! publishes it under the owner again. While it proves, ingests and status reads take the
//! owner; a payment cancels the proof through the scheduler before it takes the owner. The
//! backlog comes from each turn's own result, never from a snapshot: it is a scheduling hint
//! that only decides whether an activity update wakes the worker.

use super::*;
use std::sync::{Condvar, Weak};
use std::thread::{self, JoinHandle};

#[derive(Default)]
struct Control {
    enabled: bool,
    stopped: bool,
    started: bool,
    running: bool,
    wake: bool,
    payments: usize,
    // Backlog of the last finished turn; `None` when unknown. A hint, never readiness.
    backlog: Option<u128>,
    // A terminal error cannot be overwritten by a later wake before a caller observes it.
    error: Option<(Failure, bool)>,
    // Observation-only fold telemetry of this owner; no scheduling or error path reads it.
    fold: state::FoldMetricsV1,
}
#[derive(Default)]
struct Inner {
    control: Mutex<Control>,
    ready: Condvar,
}
impl Inner {
    fn lock(&self) -> std::sync::MutexGuard<'_, Control> {
        self.control
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn wake(&self) {
        let mut state = self.lock();
        if state.error.is_some_and(|(_, observed)| observed) {
            state.error = None;
        }
        state.wake = true;
        self.ready.notify_all();
    }
}
impl state::FoldObserverV1 for Inner {
    fn sub_proof(&self, mut record: state::FoldSubProofV1) {
        record.peak_rss_bytes = peak_rss_bytes();
        self.lock().fold.record(record);
    }
}
/// Process lifetime peak resident set size, read at the end of each fold sub-proof.
#[cfg(unix)]
fn peak_rss_bytes() -> Option<u64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: `usage` is writable memory for one `rusage`; RUSAGE_SELF reads this process.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: zero-initialized and then filled by the successful call above.
    let peak = u64::try_from(unsafe { usage.assume_init() }.ru_maxrss).ok()?;
    // Apple platforms report bytes; Linux and Android report kibibytes.
    Some(if cfg!(target_vendor = "apple") {
        peak
    } else {
        peak.saturating_mul(1024)
    })
}
#[cfg(not(unix))]
fn peak_rss_bytes() -> Option<u64> {
    None
}
#[derive(Default)]
pub(super) struct Background {
    inner: Arc<Inner>,
    join: Mutex<Option<JoinHandle<()>>>,
}
impl Background {
    /// A background that keeps the fold telemetry its owner's scheduler reports.
    pub(super) fn observing(scheduler: &state::Scheduler) -> Self {
        let background = Self::default();
        scheduler.observe(background.inner.clone());
        background
    }
    pub(super) fn activity(&self, owner: &Arc<Owner>, enabled: bool) -> Result<()> {
        self.activity_with(owner, enabled, |task| {
            thread::Builder::new()
                .name("kagemusha-fold".into())
                .spawn(task)
        })
    }
    fn activity_with(
        &self,
        owner: &Arc<Owner>,
        enabled: bool,
        spawn: impl FnOnce(Box<dyn FnOnce() + Send>) -> std::io::Result<JoinHandle<()>>,
    ) -> Result<()> {
        // Serialize spawn with close, but never hold this mutex during a join.
        let mut join = self.join.lock().map_err(|_| Failure::code(INTERNAL))?;
        let wake = {
            let mut state = self.inner.lock();
            if state.stopped {
                return Err(Failure::code(CLOSED));
            }
            // Wake only when a turn can find work: a new worker, eligibility appearing, an
            // unknown or non-zero backlog, or an error a retry may clear. Leaving activity
            // needs no wake; the scheduler has already cancelled any running sub-proof.
            let wake = enabled
                && (join.is_none()
                    || !state.enabled
                    || state.backlog != Some(0)
                    || state.error.is_some());
            state.enabled = enabled;
            if enabled && join.is_none() {
                state.started = true;
            }
            wake
        };
        if enabled && join.is_none() {
            let weak = Arc::downgrade(owner);
            let inner = self.inner.clone();
            match spawn(Box::new(move || worker(weak, inner))) {
                Ok(handle) => *join = Some(handle),
                Err(_) => {
                    let mut state = self.inner.lock();
                    state.started = false;
                    state.enabled = false;
                    return Err(Failure::code(RESOURCE));
                }
            }
        }
        if wake {
            self.inner.wake();
        }
        Ok(())
    }
    pub(super) fn stop(&self) {
        let mut state = self.inner.lock();
        state.stopped = true;
        state.enabled = false;
        self.inner.ready.notify_all();
    }
    pub(super) fn join(&self) -> Result<()> {
        let thread = self
            .join
            .lock()
            .map_err(|_| Failure::code(INTERNAL))?
            .take();
        if let Some(thread) = thread {
            thread.join().map_err(|_| Failure::code(INTERNAL))?;
        }
        Ok(())
    }
    pub(super) fn payment<'a>(
        &'a self,
        scheduler: &state::Scheduler,
        class: state::FoldCallClassV1,
    ) -> Payment<'a> {
        self.inner.lock().payments += 1;
        self.inner.ready.notify_all();
        Payment {
            priority: Some(scheduler.payment_for(class)),
            background: self,
        }
    }
    /// Take an explicit fold call's result as this owner's latest turn. A background turn
    /// that started while that call held the scheduler slot ended idle without reading the
    /// manifest and nothing else wakes it, so a checkpoint, a folded head or a failure
    /// resumes the worker; a caught-up or idle result only keeps its backlog.
    pub(super) fn after_explicit_fold(&self, result: &Result<Response>) {
        let resume = if let Some(Ok((kind, backlog))) = result.as_ref().ok().map(finished) {
            if let Some(backlog) = backlog {
                self.inner.lock().backlog = Some(backlog);
            }
            matches!(kind, 8 | 9)
        } else {
            self.inner.lock().backlog = None;
            true
        };
        if resume {
            self.inner.wake();
        }
    }
    /// Observation-only fold telemetry: the last 64 sub-proofs and cumulative counts.
    pub(super) fn fold_metrics(&self) -> state::FoldMetricsV1 {
        self.inner.lock().fold.clone()
    }
    pub(super) fn status(&self) -> Result<Response> {
        let mut state = self.inner.lock();
        if state.stopped {
            return Err(Failure::code(CLOSED));
        }
        if let Some((error, observed)) = &mut state.error {
            *observed = true;
            return Err(*error);
        }
        Ok(Response {
            kind: 29,
            sequence: state.backlog.unwrap_or(0),
            detail: (if state.running {
                2
            } else {
                u32::from(state.started)
            }) | (u32::from(state.enabled) << 2)
                | (u32::from(state.backlog.is_some()) << 3),
            ..Response::default()
        })
    }
}
pub(super) struct Payment<'a> {
    priority: Option<state::PaymentGuard>,
    background: &'a Background,
}
impl Drop for Payment<'_> {
    fn drop(&mut self) {
        // Release core payment priority before notifying the parked runner.
        drop(self.priority.take());
        self.background.inner.lock().payments -= 1;
        self.background.inner.wake();
    }
}
impl Drop for Background {
    fn drop(&mut self) {
        self.stop();
        // Explicit close joins. Defensive destruction cannot join its own worker when
        // its temporary upgrade happens to be the final owner reference.
        let handle = self
            .join
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(handle) = handle
            && handle.thread().id() != thread::current().id()
        {
            let _ = handle.join();
        }
    }
}
fn worker(owner: Weak<Owner>, inner: Arc<Inner>) {
    loop {
        {
            let mut state = inner.lock();
            while !(state.stopped
                || state.enabled && state.wake && state.payments == 0 && state.error.is_none())
            {
                state = inner
                    .ready
                    .wait(state)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
            if state.stopped {
                return;
            }
            state.wake = false;
            state.running = true;
        }
        let Some(owner) = owner.upgrade() else {
            return;
        };
        let result = run(|| {
            let proof = {
                let mut wallet = owner.wallet.lock().map_err(|_| Failure::code(INTERNAL))?;
                let wallet = wallet.as_deref_mut().ok_or(Failure::code(CLOSED))?;
                // A payment can arrive while this worker waits for the wallet mutex.
                // The core prepare also checks its own payment guard and exact cancellation token.
                {
                    let state = inner.lock();
                    if state.stopped || !state.enabled || state.payments != 0 {
                        return Ok((6, None));
                    }
                }
                match wallet.fold()? {
                    ControlFlow::Break(response) => return finished(&response),
                    ControlFlow::Continue(proof) => proof,
                }
            };
            // The owner is free while this sub-proof proves. The proof releases its scheduler
            // slot before this worker takes the owner again to publish.
            let publication = proof()?;
            let mut wallet = owner.wallet.lock().map_err(|_| Failure::code(INTERNAL))?;
            let wallet = wallet.as_deref_mut().ok_or(Failure::code(CLOSED))?;
            finished(&publication(wallet)?)
        });
        drop(owner); // Never keep custody alive while parked on the condition variable.
        let mut state = inner.lock();
        state.running = false;
        match result {
            Ok((kind, backlog)) => {
                if let Some(backlog) = backlog {
                    state.backlog = Some(backlog);
                }
                if matches!(kind, 8 | 9) {
                    state.wake = true;
                }
            }
            Err(error) => {
                // A turn that did not finish leaves the backlog unknown, so the next activity
                // update wakes the worker again.
                state.backlog = None;
                if error.status == CANCELLED {
                    // A cancelled sub-proof waits for its eligibility and payment gates as
                    // before. A proof discarded at publication has no other waker: resume
                    // from durable state.
                    state.wake = true;
                } else {
                    state.error = Some((error, false));
                }
            }
        }
        inner.ready.notify_all();
    }
}

/// Check one fold response and take the backlog of the manifest its turn ended on: none for
/// an idle turn, none or zero when caught up (none before Bootstrap), at least one after a
/// checkpoint and any count after a folded head.
fn finished(response: &Response) -> Result<(i32, Option<u128>)> {
    let shaped = matches!(
        (response.kind, response.backlog),
        (6, None) | (7, None | Some(0)) | (8, Some(1..)) | (9, Some(_))
    );
    if !shaped || !response.bytes.is_empty() {
        return Err(Failure::code(INTERNAL));
    }
    Ok((response.kind, response.backlog))
}

#[cfg(test)]
mod tests;
