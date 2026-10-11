//! Closing retains the existing Native identity until genuine custody join succeeds.

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

/// One shared state transferred from the runtime into its admitted owner.
/// Failed cleanup retains the same registered identity and cannot reopen ordinary calls.
#[derive(Default)]
pub(super) struct CloseState {
    started: AtomicBool,
    joined: Mutex<bool>,
}
impl CloseState {
    pub(super) fn begin(&self) {
        self.started.store(true, Ordering::Release);
    }
    pub(super) fn require_open(&self) -> Result<()> {
        if self.started.load(Ordering::Acquire) {
            Err(Failure::code(CLOSED))
        } else {
            Ok(())
        }
    }
    /// A normal refusal is retryable; a panic poisons the join and grants no release.
    pub(super) fn join(&self, action: impl FnOnce() -> Result<()>) -> Result<()> {
        let mut joined = self.joined.lock().map_err(|_| Failure::code(INTERNAL))?;
        if !*joined {
            action()?;
            *joined = true;
        }
        Ok(())
    }
}

enum Target {
    Wallet(Arc<Owner>),
    Runtime(Arc<open::RuntimeOwner>),
}
impl Target {
    fn begin(&self) {
        match self {
            Self::Wallet(owner) => owner.closing.begin(),
            Self::Runtime(owner) => owner.closing.begin(),
        }
    }
    fn join(&self) -> Result<()> {
        match self {
            Self::Wallet(owner) => owner.closing.join(|| {
                owner.background.stop();
                owner.scheduler.set_activity(false, false);
                // Join any accepted proof before taking the exclusive wallet owner.
                let _priority = owner.scheduler.payment();
                owner.background.join()?;
                let mut wallet = owner.wallet.lock().map_err(|_| Failure::code(INTERNAL))?;
                drop(wallet.take());
                Ok(())
            }),
            Self::Runtime(owner) => open::close(Arc::clone(owner)),
        }
    }
    fn remove_joined(&self, selected: &mut Registry, id: u64) -> Result<()> {
        // A concurrent close may have removed this same genuinely joined entry.
        // No missing-ID lookup is reinterpreted as success: each caller owns this Target.
        match self {
            Self::Wallet(owner) => match selected.owners.get(&id) {
                Some(active) if Arc::ptr_eq(active, owner) => {
                    selected.owners.remove(&id);
                }
                None if !selected.runtimes.contains_key(&id) => {}
                _ => return Err(Failure::code(CONFLICT)),
            },
            Self::Runtime(owner) => match selected.runtimes.get(&id) {
                Some(active) if Arc::ptr_eq(active, owner) => {
                    selected.runtimes.remove(&id);
                }
                None if !selected.owners.contains_key(&id) => {}
                _ => return Err(Failure::code(CONFLICT)),
            },
        }
        Ok(())
    }
}

pub(super) fn close_with(registry: &Mutex<Registry>, id: u64) -> Result<()> {
    let target = {
        let selected = registry.lock().map_err(|_| Failure::code(INTERNAL))?;
        let target = if let Some(owner) = selected.owners.get(&id) {
            Target::Wallet(Arc::clone(owner))
        } else if let Some(owner) = selected.runtimes.get(&id) {
            Target::Runtime(Arc::clone(owner))
        } else {
            return Err(Failure::code(CLOSED));
        };
        // Promotion and activity are ordered by this same registry lock.
        target.begin();
        target
    };
    target.join()?;
    let mut selected = registry.lock().map_err(|_| Failure::code(INTERNAL))?;
    target.remove_joined(&mut selected, id)
}

#[cfg(test)]
mod tests;
