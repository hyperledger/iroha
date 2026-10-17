//! One request's prepaid, finite live native-verifier working set.

use iroha_allocation::{AllocationBudget, AllocationCharge};
use norito::{
    DecodeLimits,
    core::{DecodeBudgetContext, PreparedDecodeWorkspace},
};
use std::{alloc::Layout, cell::RefCell};

use crate::execution_attempt::ExecutionAttemptError;
use crate::sumeragi::certified_chain::ChainReadError;

/// Original physical corridors supplied by the integrating request admission.
///
/// These pools must be disjoint parts of the same retained request reservation.
/// The source/output pool remains charged by actual native destinations. The graph
/// pool prepays the complete verifier working set before any source is decoded.
#[derive(Clone)]
pub struct NativeFinalityProofBudget {
    frames: AllocationBudget,
    graphs: AllocationBudget,
    limits: DecodeLimits,
}

impl NativeFinalityProofBudget {
    /// Retain the caller's already admitted source and graph corridors.
    pub fn new(frames: AllocationBudget, graphs: AllocationBudget, limits: DecodeLimits) -> Self {
        Self {
            frames,
            graphs,
            limits,
        }
    }

    pub(crate) fn frames(&self) -> &AllocationBudget {
        &self.frames
    }

    pub(crate) fn workspace(
        &self,
    ) -> Result<FinalityDecodeWorkspace, ExecutionAttemptError<ChainReadError>> {
        FinalityDecodeWorkspace::new(&self.graphs, self.limits)
    }
}

/// The closed pinned reader retains at most these eight graph generations:
/// constructor genesis/epoch, prefix tip, prefix schedule, prefix authority,
/// two validation-cache entries, a held target, and current transient work.
/// Every new owned graph (including clone and crypto backing) is admitted in
/// one bounded stage. Old and new prefix fields overlap only inside that last
/// transient group. Proof destinations have their independent exact frame ledger.
const LIVE_GRAPH_GROUPS: usize = 8;

// Norito's JSON unknown-field error owns one key outside decoder accounting.
// Signed genesis metadata is capped by MAX_JSON_BYTES; that error is projected
// directly without formatting. Other native diagnostics can format a bounded
// peer/public key (at most 8,258 payload bytes), with overlapping text and growth
// covered by 128 KiB. These diagnostics are dropped before this workspace; no
// dynamic reason escapes the interval's heapless native-refusal projection.
const DIAGNOSTIC_BYTES: usize = iroha_primitives::json::MAX_JSON_BYTES + 128 * 1024;

fn capacity() -> ExecutionAttemptError<ChainReadError> {
    ExecutionAttemptError::Deferred(ivm::error::ExecutionDeferral::ActiveMemoryCapacity.into())
}

pub(crate) struct FinalityDecodeWorkspace {
    counters: RefCell<PreparedDecodeWorkspace>,
    budget: AllocationBudget,
    limits: DecodeLimits,
    // All caller-owned cursor/receipt graphs must die before this original charge.
    _graphs: AllocationCharge,
}

impl FinalityDecodeWorkspace {
    fn new(
        budget: &AllocationBudget,
        original: DecodeLimits,
    ) -> Result<Self, ExecutionAttemptError<ChainReadError>> {
        let controls = PreparedDecodeWorkspace::allocation_layouts()
            .iter()
            .map(Layout::size)
            .sum::<usize>()
            .checked_add(DecodeBudgetContext::allocation_layout().size())
            .ok_or_else(capacity)?;
        let stage = budget
            .limit_bytes()
            .checked_sub(controls)
            .and_then(|bytes| bytes.checked_sub(DIAGNOSTIC_BYTES))
            .and_then(|bytes| bytes.checked_div(LIVE_GRAPH_GROUPS))
            .filter(|bytes| *bytes > 0)
            .ok_or_else(capacity)?;
        let graph_bytes = stage
            .checked_mul(LIVE_GRAPH_GROUPS)
            .and_then(|bytes| bytes.checked_add(DIAGNOSTIC_BYTES))
            .ok_or_else(capacity)?;
        let layout = Layout::array::<u8>(
            graph_bytes
                .checked_add(controls)
                .and_then(|bytes| {
                    bytes.checked_sub(DecodeBudgetContext::allocation_layout().size())
                })
                .ok_or_else(capacity)?,
        )
        .map_err(|_| capacity())?;
        let mut reservation = budget.try_reserve(layout).map_err(|_| capacity())?;
        let counters = PreparedDecodeWorkspace::from_reservation(budget, &mut reservation)
            .map_err(|_| capacity())?;
        let charge = reservation
            .try_split(Layout::array::<u8>(graph_bytes).map_err(|_| capacity())?)
            .map_err(|_| capacity())?;
        Ok(Self {
            counters: RefCell::new(counters),
            budget: budget.clone(),
            limits: DecodeLimits::new(
                original.max_sequence_elements(),
                original.max_field_bytes(),
                stage.min(original.max_total_elements()),
                stage.min(original.max_total_allocated_bytes()),
                original.max_nesting_depth(),
            ),
            _graphs: charge,
        })
    }

    pub(crate) fn target_context(
        &self,
    ) -> Result<DecodeBudgetContext, ExecutionAttemptError<ChainReadError>> {
        DecodeBudgetContext::try_new_owned(self.limits, &self.budget).map_err(|_| capacity())
    }

    /// Reuse only this workspace's prepaid stage controls. Any truly inherited
    /// caller limit still composes normally; no original outer counter is reset.
    pub(crate) fn stage<R, E>(&self, work: impl FnOnce() -> Result<R, E>) -> Result<R, E>
    where
        E: From<ExecutionAttemptError<ChainReadError>>,
    {
        self.counters
            .borrow_mut()
            .with_limits(self.limits, self.limits, work)
            .map_err(|_| E::from(capacity()))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> (AllocationBudget, FinalityDecodeWorkspace) {
        let pool = AllocationBudget::new(DIAGNOSTIC_BYTES + 16_384);
        let workspace = FinalityDecodeWorkspace::new(
            &pool,
            DecodeLimits::new(16_384, 16_384, 16_384, 16_384, 32),
        )
        .unwrap();
        (pool, workspace)
    }

    #[test]
    fn finality_workspace_retains_funding_across_bounded_repeated_phases() {
        let (pool, workspace) = owner();
        let held = pool.reserved_bytes();
        assert!(held > pool.limit_bytes() / 2);
        for _ in 0..100 {
            workspace
                .stage(|| {
                    norito::core::reserve_decode_allocation(
                        workspace.limits.max_total_allocated_bytes(),
                    )
                    .map_err(|error| {
                        let _ = error;
                        capacity()
                    })
                })
                .unwrap();
            assert_eq!(pool.reserved_bytes(), held);
        }
        assert!(
            workspace
                .stage(|| norito::core::reserve_decode_allocation(
                    workspace.limits.max_total_allocated_bytes() + 1
                )
                .map_err(|_| capacity()))
                .is_err()
        );
        assert_eq!(pool.reserved_bytes(), held);
        drop(workspace);
        assert_eq!(pool.reserved_bytes(), 0);
    }

    #[test]
    fn finality_workspace_never_resets_target_or_inherited_counter() {
        let (pool, workspace) = owner();
        let target = workspace.target_context().unwrap();
        let maximum = workspace.limits.max_total_allocated_bytes();
        target
            .with(|| norito::core::reserve_decode_allocation(maximum))
            .unwrap();
        workspace
            .stage(|| Ok::<_, ExecutionAttemptError<ChainReadError>>(()))
            .unwrap();
        assert!(
            target
                .with(|| norito::core::reserve_decode_allocation(1))
                .is_err()
        );
        let inherited = DecodeBudgetContext::new(DecodeLimits::new(16, 16, 16, 16, 16));
        inherited
            .with(|| {
                workspace
                    .stage(|| norito::core::reserve_decode_allocation(16).map_err(|_| capacity()))
            })
            .unwrap();
        assert!(
            inherited
                .with(|| workspace
                    .stage(|| norito::core::reserve_decode_allocation(1).map_err(|_| capacity())))
                .is_err()
        );
        assert_eq!(inherited.consumed_allocated_bytes(), 16);
        drop(target);
        drop(workspace);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}
