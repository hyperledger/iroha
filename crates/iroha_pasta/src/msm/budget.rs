//! Explicit memory budgets for kernel scratch space.
//!
//! [`MemoryBudget`] limits one kernel. [`SharedMemoryBudget`] additionally
//! admits its scratch against the process-wide ceiling and an optional caller
//! ceiling. Admission never waits: nested Rayon jobs cannot hold a reservation
//! while blocking workers needed by its owner. Contended kernels instead use
//! smaller plans or an allocation-free multiplication path.
//!
//! TODO: charge these budgets to the workspace allocation accounting
//! (`iroha_allocation`) once the native prover links it; today the budget is a
//! plain byte count chosen by the caller.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

/// Maximum simultaneously reserved MSM scratch in this process: 64 MiB.
pub const PROCESS_MSM_SCRATCH_BYTES: usize = 64 << 20;

#[derive(Debug)]
struct SharedState {
    limit: usize,
    used: AtomicUsize,
    peak: AtomicUsize,
}

impl SharedState {
    const fn new(limit: usize) -> Self {
        Self {
            limit,
            used: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        }
    }

    fn acquire(&self, bytes: usize) -> bool {
        let previous = self
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|&next| next <= self.limit)
            });
        previous.is_ok_and(|previous| {
            self.peak.fetch_max(previous + bytes, Ordering::Relaxed);
            true
        })
    }

    fn release(&self, bytes: usize) {
        self.used.fetch_sub(bytes, Ordering::Release);
    }

    fn available(&self) -> usize {
        self.limit - self.used.load(Ordering::Acquire)
    }
}

static PROCESS_SCRATCH: SharedState = SharedState::new(PROCESS_MSM_SCRATCH_BYTES);

/// Shared admission for concurrent MSM kernels, always bounded by the process cap.
///
/// Clones share the same caller ceiling. Independently constructed budgets still
/// charge the same process-wide 64 MiB limit. The budget covers kernel-owned heap
/// scratch, not input slices, retained commitment tables, allocator bookkeeping
/// or Rayon worker stacks. It is configured explicitly, never by the environment.
#[derive(Clone, Debug, Default)]
pub struct SharedMemoryBudget {
    local: Option<Arc<SharedState>>,
}

impl SharedMemoryBudget {
    /// Share the process-wide cap without an additional caller ceiling.
    pub const fn process_default() -> Self {
        Self { local: None }
    }

    /// Add a caller ceiling of `bytes`, shared by clones of this budget.
    pub fn new(bytes: usize) -> Self {
        Self {
            local: Some(Arc::new(SharedState::new(
                bytes.min(PROCESS_MSM_SCRATCH_BYTES),
            ))),
        }
    }

    /// The effective ceiling, independent of current reservations.
    pub fn limit_bytes(&self) -> usize {
        self.local.as_deref().unwrap_or(&PROCESS_SCRATCH).limit
    }

    /// Scratch presently charged to this budget (to the process for the default).
    pub fn in_use_bytes(&self) -> usize {
        self.local
            .as_deref()
            .unwrap_or(&PROCESS_SCRATCH)
            .used
            .load(Ordering::Acquire)
    }

    /// Highest simultaneously reserved byte count observed by this budget.
    pub fn peak_bytes(&self) -> usize {
        self.local
            .as_deref()
            .unwrap_or(&PROCESS_SCRATCH)
            .peak
            .load(Ordering::Acquire)
    }

    /// Currently available bytes; another kernel can reserve them immediately.
    pub fn available_bytes(&self) -> usize {
        self.local.as_deref().map_or_else(
            || PROCESS_SCRATCH.available(),
            |local| local.available().min(PROCESS_SCRATCH.available()),
        )
    }

    /// Reserve scratch before allocation, returning `None` immediately if full.
    ///
    /// Keep the returned guard alive until every charged allocation is dropped,
    /// including during unwinding. Never wait for admission while holding one.
    pub fn try_reserve(&self, bytes: usize) -> Option<ScratchReservation<'_>> {
        if !PROCESS_SCRATCH.acquire(bytes) {
            return None;
        }
        if let Some(local) = &self.local
            && !local.acquire(bytes)
        {
            PROCESS_SCRATCH.release(bytes);
            return None;
        }
        Some(ScratchReservation { owner: self, bytes })
    }
}

/// An admitted scratch allocation, released on drop, including unwinding.
#[derive(Debug)]
pub struct ScratchReservation<'a> {
    owner: &'a SharedMemoryBudget,
    bytes: usize,
}

impl ScratchReservation<'_> {
    /// Number of bytes admitted by this reservation.
    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

impl Drop for ScratchReservation<'_> {
    fn drop(&mut self) {
        if let Some(local) = &self.owner.local {
            local.release(self.bytes);
        }
        PROCESS_SCRATCH.release(self.bytes);
    }
}

/// A limit on the scratch bytes a kernel may hold at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MemoryBudget {
    bytes: usize,
}

impl MemoryBudget {
    /// The default budget: 256 MiB.
    pub const DEFAULT: Self = Self::new(256 << 20);

    /// A budget of `bytes` bytes.
    pub const fn new(bytes: usize) -> Self {
        Self { bytes }
    }

    /// The budget in bytes.
    pub const fn bytes(self) -> usize {
        self.bytes
    }

    /// Returns `Ok(())` when `required` bytes fit the budget.
    ///
    /// # Errors
    ///
    /// [`BudgetExceeded`] when they do not.
    pub const fn check(self, required: usize) -> Result<(), BudgetExceeded> {
        if required <= self.bytes {
            Ok(())
        } else {
            Err(BudgetExceeded {
                required,
                budget: self.bytes,
            })
        }
    }
}

impl Default for MemoryBudget {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// A kernel could not plan its work within the memory budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetExceeded {
    /// Bytes the smallest feasible plan needs.
    pub required: usize,
    /// Bytes the budget allows.
    pub budget: usize,
}

impl core::fmt::Display for BudgetExceeded {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "kernel needs {} bytes of scratch, budget is {}",
            self.required, self.budget
        )
    }
}

impl std::error::Error for BudgetExceeded {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloned_caller_budget_admits_and_releases_exactly() {
        let budget = SharedMemoryBudget::new(1024);
        let clone = budget.clone();
        assert_eq!(budget.limit_bytes(), 1024);
        assert_eq!(budget.in_use_bytes(), 0);
        assert_eq!(budget.peak_bytes(), 0);
        let first = budget.try_reserve(700).expect("small reservation");
        assert_eq!(first.bytes(), 700);
        assert_eq!(clone.in_use_bytes(), 700);
        assert!(clone.available_bytes() <= 324);
        assert!(clone.try_reserve(325).is_none());
        let second = clone.try_reserve(324).expect("remaining bytes");
        assert_eq!(budget.in_use_bytes(), 1024);
        assert_eq!(budget.peak_bytes(), 1024);
        drop(first);
        assert_eq!(budget.in_use_bytes(), 324);
        drop(second);
        assert_eq!(budget.in_use_bytes(), 0);
        assert_eq!(budget.peak_bytes(), 1024);
        assert_eq!(
            SharedMemoryBudget::default().limit_bytes(),
            PROCESS_MSM_SCRATCH_BYTES
        );
        assert_eq!(
            SharedMemoryBudget::new(usize::MAX).limit_bytes(),
            PROCESS_MSM_SCRATCH_BYTES
        );
        assert!(SharedMemoryBudget::new(0).try_reserve(1).is_none());
    }

    #[test]
    fn check_and_default() {
        let b = MemoryBudget::new(100);
        assert_eq!(b.bytes(), 100);
        assert!(b.check(100).is_ok());
        assert_eq!(
            b.check(101),
            Err(BudgetExceeded {
                required: 101,
                budget: 100
            })
        );
        assert_eq!(MemoryBudget::default(), MemoryBudget::DEFAULT);
        assert_eq!(
            BudgetExceeded {
                required: 2,
                budget: 1
            }
            .to_string(),
            "kernel needs 2 bytes of scratch, budget is 1"
        );
    }
}
