//! Original-pool refund custody across retained physical writer lifetimes.

use super::{AllocationBudget, AllocationScope};
use std::cell::Cell;

/// Coalesced original-pool wakes retained until enclosing writers have retired.
///
/// Freed credits remain immediately reusable, including callback-free native
/// thread parking. Only arbitrary task callbacks for refunds performed inside
/// `with_scope` are captured; other pools and concurrent threads retain their
/// normal behavior. This owner allocates no storage and is not a reservation.
/// It may move across threads after a synchronous scope has ended. Its scopes
/// remain thread-bound and cannot escape through an async future.
#[must_use = "retain original refund notifications until all enclosing writers release"]
pub struct AllocationRefundBatch {
    budget: AllocationBudget,
    pending: Cell<bool>,
}

impl AllocationRefundBatch {
    pub(super) fn new(budget: AllocationBudget) -> Self {
        Self {
            budget,
            pending: Cell::new(false),
        }
    }

    /// Run synchronous work while retaining this exact pool's refund wakes.
    ///
    /// Notifications survive success and unwind in this owner. The caller must
    /// release enclosing physical writers before dropping it. Nested ordinary
    /// scopes coalesce into this batch; separate retained batches keep their own
    /// custody. Scope entry/exit and recording a refund allocate nothing.
    ///
    /// ```compile_fail
    /// let budget = iroha_allocation::AllocationBudget::new(1);
    /// let mut batch = budget.deferred_refund_batch();
    /// let escaped = batch.with_scope(|scope| scope);
    /// drop(escaped);
    /// ```
    pub fn with_scope<R>(
        &mut self,
        operation: impl for<'scope> FnOnce(&'scope AllocationScope<'scope>) -> R,
    ) -> R {
        self.budget
            .with_refund_scope(Some(&self.pending), operation)
    }
}

impl Drop for AllocationRefundBatch {
    fn drop(&mut self) {
        if self.pending.get() {
            // Preserve exact pool identity and any still-enclosing synchronous
            // scope. No batch/TLS borrow remains when user callbacks execute.
            self.budget.pool.notify_refund();
        }
    }
}
