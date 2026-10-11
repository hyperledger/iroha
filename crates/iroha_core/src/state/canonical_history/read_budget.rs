//! Original physical source custody for one off-chain canonical-history operation.
//!
//! The caller supplies its already admitted frame pool and original native codec context.
//! This owner neither derives credits from wire lengths nor grants HTTP admission. Clones
//! share cumulative counters and physical frame/shell charges across every ancestry read.
//! The integrating request retains its real permit through the worker and returned graph.

use iroha_allocation::AllocationBudget;
use norito::core::DecodeBudgetContext;

/// Explicit source and decoder custody retained across one off-chain history walk.
///
/// On-chain execution keeps its independent deterministic execution owner. An off-chain
/// caller must provide the allocation pool belonging to its actual request admission;
/// creating equal limits in a fresh pool cannot replace that custody.
#[derive(Clone)]
pub struct CanonicalHistoryReadBudget {
    frames: AllocationBudget,
    allocations: DecodeBudgetContext,
}

impl CanonicalHistoryReadBudget {
    /// Retain existing physical and cumulative decoder owners without granting new credit.
    pub fn new(frames: AllocationBudget, allocations: DecodeBudgetContext) -> Self {
        Self {
            frames,
            allocations,
        }
    }

    /// Install only a synchronous scope on the physical thread doing the work.
    ///
    /// The native context restores prior thread state during normal return and unwinding.
    /// No guard is returned, so an asynchronous caller cannot retain it across an await.
    pub fn with<R>(&self, work: impl FnOnce() -> R) -> R {
        self.allocations.with(work)
    }

    /// Exact original pool used by the canonical source, never the node execution cache.
    pub(crate) fn frames(&self) -> &AllocationBudget {
        &self.frames
    }

    /// Test original physical ownership without creating a reservation or allocation.
    pub fn same_frame_pool(&self, other: &Self) -> bool {
        self.frames.same_pool(&other.frames)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use norito::DecodeLimits;

    fn budget() -> CanonicalHistoryReadBudget {
        CanonicalHistoryReadBudget::new(
            AllocationBudget::new(4096),
            DecodeBudgetContext::new(DecodeLimits::new(4096, 4096, 4096, 4096, 16)),
        )
    }

    #[test]
    fn clones_retain_original_source_and_cumulative_decoder_credit() {
        let owner = budget();
        let clone = owner.clone();
        assert!(owner.same_frame_pool(&clone));
        assert!(!owner.same_frame_pool(&budget()));
        owner
            .with(|| norito::core::reserve_decode_allocation(3072))
            .unwrap();
        assert!(
            clone
                .with(|| norito::core::reserve_decode_allocation(1025))
                .is_err()
        );
        assert_eq!(owner.allocations.consumed_allocated_bytes(), 3072);
        clone
            .with(|| norito::core::reserve_decode_allocation(1024))
            .unwrap();
        assert_eq!(owner.allocations.consumed_allocated_bytes(), 4096);
    }

    #[test]
    fn nested_same_owner_does_not_duplicate_native_charges_or_leak_scope() {
        let owner = budget();
        assert!(!norito::core::decode_limits_active());
        owner
            .with(|| owner.with(|| norito::core::reserve_decode_allocation(64)))
            .unwrap();
        assert_eq!(owner.allocations.consumed_allocated_bytes(), 64);
        assert!(!norito::core::decode_limits_active());
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            owner.with(|| {
                norito::core::reserve_decode_allocation(128).unwrap();
                panic!("interrupted physical history reader");
            })
        }));
        assert!(!norito::core::decode_limits_active());
        assert_eq!(owner.allocations.consumed_allocated_bytes(), 192);
    }
}
