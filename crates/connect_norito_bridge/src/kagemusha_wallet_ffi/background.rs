//! One bounded native fold worker per opaque wallet, with cooperative payment priority.

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
    backlog: Option<u128>,
    // A terminal error cannot be overwritten by a later wake before a caller observes it.
    error: Option<(Failure, bool)>,
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
#[derive(Default)]
pub(super) struct Background {
    inner: Arc<Inner>,
    join: Mutex<Option<JoinHandle<()>>>,
}
impl Background {
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
        {
            let mut state = self.inner.lock();
            if state.stopped {
                return Err(Failure::code(CLOSED));
            }
            state.enabled = enabled;
            if enabled && join.is_none() {
                state.started = true;
            }
        }
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
        self.inner.wake();
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
    pub(super) fn payment<'a>(&'a self, scheduler: &state::Scheduler) -> Payment<'a> {
        self.inner.lock().payments += 1;
        self.inner.ready.notify_all();
        Payment {
            priority: Some(scheduler.payment()),
            background: self,
        }
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
            let mut wallet = owner.wallet.lock().map_err(|_| Failure::code(INTERNAL))?;
            let wallet = wallet.as_deref_mut().ok_or(Failure::code(CLOSED))?;
            // A payment can arrive while this worker waits for the wallet mutex.
            // Core fold_once also checks its own payment guard and exact cancellation token.
            {
                let state = inner.lock();
                if state.stopped || !state.enabled || state.payments != 0 {
                    return Ok((6, None));
                }
            }
            let response = wallet.fold()?;
            if !(6..=9).contains(&response.kind) || !response.bytes.is_empty() {
                return Err(Failure::code(INTERNAL));
            }
            let backlog = wallet.snapshot()?.fold_backlog;
            Ok((response.kind, Some(backlog)))
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
            Err(error) if error.status == CANCELLED => {}
            Err(error) => state.error = Some((error, false)),
        }
        inner.ready.notify_all();
    }
}

#[cfg(test)]
mod tests;
