//! Independent census of the empty World's funded owners and epoch-retained cells.

use iroha_allocation::{AllocationBudget, AllocationCharge};
use mv::cell::{Cell, CellInitialization};

use super::{
    AnchorStorage, CommitteeStorage, LightClientSetStorage, RetainedSccpAnchors,
    sccp_forgery_custody, sccp_reconciliation_store,
};
use crate::sumeragi::amx::RetainedNativeAmx;

/// All live empty-World owners, excluding generations retired during construction.
pub(super) fn world_live_bytes() -> usize {
    let maps = [
        sccp_reconciliation_store::Records::initial_allocation_demand(),
        sccp_reconciliation_store::Proofs::initial_allocation_demand(),
        sccp_reconciliation_store::Refunds::initial_allocation_demand(),
        sccp_reconciliation_store::Due::initial_allocation_demand(),
        sccp_forgery_custody::OffenceStorage::initial_allocation_demand(),
        LightClientSetStorage::initial_allocation_demand(),
        CommitteeStorage::initial_allocation_demand(),
        AnchorStorage::initial_allocation_demand(),
    ]
    .into_iter()
    .map(|demand| demand.unwrap().bytes())
    .sum::<usize>();
    // Current committee, liability clock and Musubi shortfall each own a u64 cell.
    maps + 3 * initialized_cell_bytes::<u64>()
        + initialized_cell_bytes::<u32>()
        + initialized_cell_bytes::<Option<u64>>()
        + initialized_cell_bytes::<RetainedSccpAnchors>()
        + initialized_cell_bytes::<RetainedNativeAmx>()
}

fn initialized_cell_bytes<T: mv::Value>() -> usize {
    CellInitialization::<T>::allocation_layouts()
        .into_iter()
        .map(|layout| layout.size())
        .sum()
}

/// Empty-World cell generations retained by an epoch pin after World drops.
pub(super) fn world_retired_bytes() -> usize {
    3 * retired_cell_bytes::<u64>()
        + retired_cell_bytes::<u32>()
        + retired_cell_bytes::<Option<u64>>()
        + retired_cell_bytes::<RetainedSccpAnchors>()
        + retired_cell_bytes::<RetainedNativeAmx>()
}

fn retired_cell_bytes<T: mv::Value>() -> usize {
    Cell::<T, AllocationCharge>::allocation_layouts()
        .into_iter()
        .map(|layout| layout.size())
        .sum()
}

/// Drain constructor/replacement generations before asserting exact live custody.
pub(super) fn reclaim_to(budget: &AllocationBudget, expected: usize) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while budget.reserved_bytes() != expected {
        assert!(
            budget.reserved_bytes() >= expected && std::time::Instant::now() < deadline,
            "original custody {} != {expected}",
            budget.reserved_bytes(),
        );
        crossbeam_epoch::pin().flush();
        std::thread::yield_now();
    }
}
