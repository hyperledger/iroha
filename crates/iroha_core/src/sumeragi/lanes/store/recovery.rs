//! A startup owner retains its lock, validated prefix and every original recovery allocation.

use super::*;
use crate::execution_attempt::ExecutionAttemptError as Attempt;

/// Exclusive initialization in progress; no not-ready store or unvalidated tip is exposed.
pub struct LaneStoreOpen {
    pub(super) store: FileLaneBlockStore,
    target: u64,
    pub(super) validated: u64,
    refusal: Option<crate::execution_attempt::ExecutionDeferred>,
}
impl LaneStoreOpen {
    pub(super) fn new(store: FileLaneBlockStore, target: u64) -> Self {
        Self {
            store,
            target,
            validated: 0,
            refusal: None,
        }
    }
    /// Complete recovery, returning this exact owner on every refusal or error.
    /// A caller may retry WouldBlock after resources/authority become available; semantic or I/O
    /// failures remain errors. No retry spins or alternate proof/source replacement occur here.
    ///
    /// # Errors
    /// Full certificate/availability validation, original-pool resource refusal or durability.
    #[allow(
        clippy::result_large_err,
        reason = "return original startup ownership without allocating"
    )]
    pub fn complete(mut self) -> Result<FileLaneBlockStore, (Self, Attempt<io::Error>)> {
        if let Err(error) = self.progress() {
            self.refusal = match &error {
                Attempt::Deferred(original) => Some(original.clone()),
                Attempt::Rejected(_) => None,
            };
            return Err((self, error));
        }
        self.refusal = None;
        *self.store.state.lock() = StoreState {
            tip: self.target,
            read: None,
            write: None,
        };
        Ok(self.store)
    }
    fn progress(&mut self) -> Result<(), Attempt<io::Error>> {
        self.store.revalidate_custody()?;
        while self.validated < self.target {
            let height = self.validated + 1;
            let mut state = self.store.state.lock();
            let prepared = self.store.read_prepared(&mut state, height)?;
            let bytes = prepared.prepare(&self.store.budget).map_err(record_error)?;
            self.store.publish_frame(height, bytes)?;
            state.read = None;
            self.validated = height;
        }
        self.store.revalidate_custody()?;
        Ok(())
    }
}
