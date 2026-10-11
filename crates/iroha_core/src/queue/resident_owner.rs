//! Original Queue policy residence and physically funded shared transaction controls.
//!
//! The encoded-size expansion is a resident admission estimate, not a ledger for
//! nested decoded allocations. Only the actual ledger/control layouts below are
//! physically prepaid from the admitting State's original finite execution pool.
//! TODO: Carry the full canonical owned proof/decoder ledger through accepted,
//! block and gossip successors; this resident estimate does not fund their graph.

use super::*;
use iroha_allocation::shared::{Reserved, Shared};
use iroha_allocation::{AllocationBudget, AllocationCharge, ChargedShared};

/// The original Queue pressure counters, retained by every original transaction owner.
pub(super) struct QueueResidentLedger {
    pub(super) retained_bytes: AtomicU64,
    pub(super) active_count: AtomicUsize,
    pub(super) queued_count: AtomicUsize,
    /// Latched original admission health, refreshed at the existing publication boundary.
    pub(super) faulted: AtomicBool,
    mutations: AtomicUsize,
    budget: AllocationBudget,
    capacity: NonZeroUsize,
    max_retained_bytes: NonZeroU64,
    backpressure: watch::Sender<BackpressureState>,
}

impl QueueResidentLedger {
    fn backpressure_state(&self) -> BackpressureState {
        let queued = self.queued_count.load(Ordering::Relaxed);
        // Match QueuePressureSnapshot::into_backpressure: age remains in the
        // rich Queue snapshot/telemetry and does not gate coarse admission.
        let saturated = self.faulted.load(Ordering::Acquire)
            || self.active_count.load(Ordering::Relaxed) >= self.capacity.get()
            || self
                .retained_bytes
                .load(Ordering::Relaxed)
                .saturating_add(TX_RETAINED_OVERHEAD_BYTES)
                > self.max_retained_bytes.get();
        if saturated {
            BackpressureState::Saturated {
                queued,
                capacity: self.capacity,
            }
        } else {
            BackpressureState::Healthy {
                queued,
                capacity: self.capacity,
            }
        }
    }

    /// Sample the actual counters inside the original watch publication fence.
    pub(super) fn publish_backpressure(&self) -> BackpressureState {
        self.backpressure.send_if_modified(|current| {
            let state = self.backpressure_state();
            if *current == state {
                false
            } else {
                *current = state;
                true
            }
        });
        self.backpressure_state()
    }

    /// Defer watch wakes until all enclosing original Queue mutation guards release.
    pub(super) fn mutation(&self) -> ResidentMutation<'_> {
        self.mutations.fetch_add(1, Ordering::AcqRel);
        ResidentMutation { ledger: self }
    }

    fn refund_estimate(&self, cost: u64) {
        let mut current = self.retained_bytes.load(Ordering::Relaxed);
        loop {
            match self.retained_bytes.compare_exchange_weak(
                current,
                current.saturating_sub(cost),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(next) => current = next,
            }
        }
        if self.mutations.load(Ordering::Acquire) == 0 {
            self.publish_backpressure();
        }
    }
}

/// Borrowed fence lifetime; it owns no graph and allocates no replacement control.
pub(super) struct ResidentMutation<'queue> {
    ledger: &'queue QueueResidentLedger,
}

impl Drop for ResidentMutation<'_> {
    fn drop(&mut self) {
        if self.ledger.mutations.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.ledger.publish_backpressure();
        }
    }
}

/// Custody of one exact shared shell and its original Queue resident estimate.
/// Shared destroys the checked input and frees its shell before dropping this charge.
pub(super) struct QueueResidentCharge {
    _physical: AllocationCharge,
    ledger: ChargedShared<QueueResidentLedger>,
    estimated_bytes: u64,
}

impl Drop for QueueResidentCharge {
    fn drop(&mut self) {
        self.ledger.refund_estimate(self.estimated_bytes);
    }
}

/// The production Queue's sole shared accepted owner; cloning retains the original graph.
pub(super) struct QueuedTransaction {
    original: Shared<CheckedTransaction<'static>, QueueResidentCharge>,
}

impl QueuedTransaction {
    /// Reserve the concrete shell before moving or publishing the checked transaction.
    pub(super) fn reserve(
        ledger: &ChargedShared<QueueResidentLedger>,
        encoded_len: usize,
    ) -> Result<Reserved<CheckedTransaction<'static>, QueueResidentCharge>, Error> {
        let layout = Shared::<CheckedTransaction<'static>, QueueResidentCharge>::layout();
        let mut reservation = ledger
            .budget
            .try_reserve(layout)
            .map_err(|original| Error::Deferred(original.into()))?;
        let physical = reservation
            .try_split(layout)
            .expect("exact admitted original Queue shell");
        let cost = Queue::retained_byte_cost(encoded_len);
        ledger.retained_bytes.fetch_add(cost, Ordering::Relaxed);
        let charge = QueueResidentCharge {
            _physical: physical,
            ledger: ledger.clone(),
            estimated_bytes: cost,
        };
        Reserved::try_new(charge).map_err(|(charge, _refusal)| {
            drop(charge);
            Error::Deferred(ivm::error::ExecutionDeferral::AllocationUnavailable.into())
        })
    }

    pub(super) fn initialize(
        shell: Reserved<CheckedTransaction<'static>, QueueResidentCharge>,
        checked: CheckedTransaction<'static>,
    ) -> Self {
        Self {
            original: shell.initialize(checked),
        }
    }

    #[cfg(test)]
    pub(super) fn ptr_eq(first: &Self, second: &Self) -> bool {
        Shared::ptr_eq(&first.original, &second.original)
    }
}

impl Clone for QueuedTransaction {
    fn clone(&self) -> Self {
        Self {
            original: self.original.clone(),
        }
    }
}

impl std::ops::Deref for QueuedTransaction {
    type Target = CheckedTransaction<'static>;
    fn deref(&self) -> &Self::Target {
        &self.original
    }
}

impl AsRef<CheckedTransaction<'static>> for QueuedTransaction {
    fn as_ref(&self) -> &CheckedTransaction<'static> {
        self
    }
}

impl Queue {
    /// Initialize only under the original admission mutation fence, from its State pool.
    pub(super) fn resident_ledger(
        &self,
        budget: &AllocationBudget,
    ) -> Result<&ChargedShared<QueueResidentLedger>, Error> {
        if let Some(ledger) = self.resident_accounting.get() {
            if !ledger.belongs_to(budget) {
                return Err(Error::AdmissionInvariant {
                    reason: "Queue resident custody belongs to a different original State pool"
                        .to_owned(),
                });
            }
            return Ok(ledger);
        }
        {
            // Startup can reserve before the first actual admission initializes custody.
            // Borrow the inline pool binding only; no charged owner drops under this lock.
            let binding = self.sumeragi_wake.lock();
            #[cfg(all(test, sumeragi_core_mutation = "HC192"))]
            let _ = &binding;
            #[cfg(not(all(test, sumeragi_core_mutation = "HC192")))]
            if binding
                .as_ref()
                .is_some_and(|original| !original.belongs_to(budget))
            {
                return Err(Error::AdmissionInvariant {
                    reason: "Queue resident custody belongs to a different original State pool"
                        .to_owned(),
                });
            }
        }
        let layout = ChargedShared::<QueueResidentLedger>::allocation_layout();
        let mut reservation = budget
            .try_reserve(layout)
            .map_err(|original| Error::Deferred(original.into()))?;
        let shell = ChargedShared::<QueueResidentLedger>::reserve_from(&mut reservation).map_err(
            |error| {
                Error::Deferred(match error {
                    iroha_allocation::PrepaidSharedError::Allocator { .. } => {
                        ivm::error::ExecutionDeferral::AllocationUnavailable.into()
                    }
                    iroha_allocation::PrepaidSharedError::Reservation(_) => {
                        ivm::error::ExecutionDeferral::LocalInvariantViolation.into()
                    }
                })
            },
        )?;
        #[cfg(test)]
        let retained_bytes = self.retained_bytes_before_admission.load(Ordering::Relaxed);
        #[cfg(not(test))]
        let retained_bytes = 0;
        let ledger = shell.initialize(QueueResidentLedger {
            retained_bytes: AtomicU64::new(retained_bytes),
            active_count: AtomicUsize::new(0),
            queued_count: AtomicUsize::new(0),
            faulted: AtomicBool::new(self.admission_faulted()),
            mutations: AtomicUsize::new(0),
            budget: budget.clone(),
            capacity: self.capacity,
            max_retained_bytes: self.max_retained_bytes,
            backpressure: self.backpressure_tx.clone(),
        });
        // The original Queue mutation fence serializes this one initialization.
        assert!(self.resident_accounting.set(ledger).is_ok());
        Ok(self
            .resident_accounting
            .get()
            .expect("published original Queue resident ledger"))
    }

    /// Inspect original custody under the actual Queue mutation fence, including cold startup.
    /// The locked callback must not reacquire that fence. The second callback runs after
    /// its original guard drops, but before mutation/watch and original-pool refunds.
    pub(super) fn with_resident_refunds<T, R>(
        &self,
        locked: impl FnOnce() -> T,
        after_unlock: impl FnOnce(T) -> R,
    ) -> R {
        #[cfg(not(all(test, sumeragi_core_mutation = "HC138")))]
        let guard = self.push_remove_lock.lock();
        #[cfg(all(test, sumeragi_core_mutation = "HC138"))]
        let guard: Option<parking_lot::MutexGuard<'_, ()>> = None;
        if let Some(ledger) = self.resident_accounting.get() {
            ledger.budget.with_deferred_refund_notifications(|_| {
                let _mutation = ledger.mutation();
                // Declare this owned original guard after the mutation owner so
                // unwind also releases the writer before any refund/watch callback.
                let guard = guard;
                let completed = locked();
                drop(guard);
                after_unlock(completed)
            })
        } else {
            // Admission cannot initialize the ledger while this cold writer is held.
            let completed = locked();
            drop(guard);
            after_unlock(completed)
        }
    }
}
