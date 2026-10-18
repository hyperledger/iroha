//! A startup owner retains its lock, validated prefix and every original recovery allocation.

use super::*;
use crate::execution_attempt::ExecutionAttemptError as Attempt;

/// Exclusive initialization in progress; no not-ready store or unvalidated tip is exposed.
pub struct LaneStoreOpen {
    pub(super) store: FileLaneBlockStore,
    target: u64,
    pub(super) validated: u64,
}
impl LaneStoreOpen {
    pub(super) fn new(store: FileLaneBlockStore, target: u64) -> Self {
        Self {
            store,
            target,
            validated: 0,
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
        let budget = self.store.budget.clone();
        // Borrow the original startup owner through cleanup; the scope returns only the
        // small attempt result before this function moves the complete owner once.
        let outcome = FileLaneBlockStore::with_original_refunds(&budget, || {
            self.progress()?;
            *self.store.state.lock() = StoreState {
                read: None,
                write: None,
            };
            *self.store.tip.lock() = self.target;
            Ok(())
        });
        match outcome {
            Ok(()) => Ok(self.store),
            Err(error) => Err((self, error)),
        }
    }
    fn progress(&mut self) -> Result<(), Attempt<io::Error>> {
        self.store.revalidate_custody()?;
        while self.validated < self.target {
            let height = self.validated + 1;
            let mut state = self.store.state.lock();
            let prepared =
                self.store
                    .read_prepared(&mut state, height, &super::ReadInterest::Historical)?;
            let bytes = prepared.prepare(&self.store.budget).map_err(record_error)?;
            self.store.publish_frame(height, bytes)?;
            state.read = None;
            self.validated = height;
        }
        self.store.revalidate_custody()?;
        Ok(())
    }
}
