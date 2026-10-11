//! Original execution-pool custody for the production Musubi shortfall scalar.
//!
//! The value has no nested allocations. Initial seven controls and each writer's
//! two physically preallocated EBR generations plus successor use actual retained
//! charges. TODO: account platform mutex and epoch bookkeeping before claiming
//! complete production admission.

#[path = "scalar_cell_custody_snapshot.rs"]
mod snapshot;
pub(super) use snapshot::decode_snapshot;

use iroha_allocation::{AllocationBudget, AllocationCharge};
use mv::{
    cell::{Cell, CellInitialization, CellInitializationError},
    storage::AdmittedStorageError,
};

pub(super) fn admission_error(error: CellInitializationError) -> AdmittedStorageError {
    match error {
        CellInitializationError::Admission(error) => AdmittedStorageError::Allocation(error),
        CellInitializationError::Allocator { layout } => AdmittedStorageError::Allocator { layout },
    }
}

pub(super) fn initialize(
    value: u64,
    budget: &AllocationBudget,
) -> Result<Cell<u64, AllocationCharge>, AdmittedStorageError> {
    CellInitialization::try_reserve(budget)
        .map(|initial| initial.initialize(value, None))
        .map_err(admission_error)
}

pub(super) fn default_budget() -> AllocationBudget {
    AllocationBudget::new(iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES)
}

#[cfg(test)]
pub(crate) fn fixture(value: u64) -> Cell<u64, AllocationCharge> {
    initialize(value, &default_budget()).expect("fixture scalar original initial capacity")
}

#[cfg(test)]
pub(super) trait ScalarCellFixtureBlock {
    fn block(&self) -> mv::cell::Block<'_, u64, AllocationCharge>;
}
#[cfg(test)]
impl ScalarCellFixtureBlock for Cell<u64, AllocationCharge> {
    fn block(&self) -> mv::cell::Block<'_, u64, AllocationCharge> {
        use super::world_acquisition::{OriginalControlSource, WorldFieldAcquisition};
        let budget = default_budget();
        let layouts = self
            .generation_layouts()
            .into_iter()
            .chain([self.successor_layout()])
            .flatten();
        let mut original = budget
            .try_reserve_layouts(layouts)
            .expect("fixture scalar writer capacity");
        let mut slot = self
            .original_acquisition(&budget, &mut original)
            .expect("fixture scalar original pool");
        slot.try_initialize(mv::BlockMode::Ordinary)
            .expect("fixture scalar writer");
        slot.into_block()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_scalar_initialization_refuses_exact_pool_before_movement() {
        let demand = CellInitialization::<u64>::allocation_layouts()
            .into_iter()
            .map(|layout| layout.size())
            .sum::<usize>();
        let source = AllocationBudget::new(demand - 1);
        assert!(matches!(
            initialize(7, &source),
            Err(AdmittedStorageError::Allocation(_))
        ));
        assert_eq!(source.reserved_bytes(), 0);
        source.set_limit_bytes(demand);
        let cell = initialize(7, &source).unwrap();
        assert_eq!(*cell.view().get(), 7);
        assert_eq!(source.reserved_bytes(), demand);
        let foreign = AllocationBudget::new(demand);
        assert_eq!(foreign.reserved_bytes(), 0);
    }

    #[test]
    fn actual_world_scalar_keeps_original_charges_through_rollback_capture_and_publication() {
        let world = super::super::World::default();
        let original = AllocationBudget::new(16 * 1024 * 1024);
        let mut block = world.try_block(&original).unwrap();
        *block.musubi_replication_shortfall_releases.get_mut() = 9;
        {
            let mut rejected = block.musubi_replication_shortfall_releases.transaction();
            *rejected.get_mut() = 22;
            // An unapplied child must restore the funded original block value.
        }
        assert_eq!(*block.musubi_replication_shortfall_releases.get(), 9);
        let reserved = original.reserved_bytes();
        let journal = block
            .try_detach_journals(
                super::super::world_journals::resources::WorldJournalShellReservation::for_test(),
                |_| Ok::<_, ()>(()),
            )
            .unwrap();
        assert_eq!(*world.musubi_replication_shortfall_releases.view().get(), 0);
        assert_eq!(
            journal
                .field("musubi_replication_shortfall_releases")
                .unwrap()
                .touched_values,
            1
        );
        assert!(
            original.reserved_bytes() < reserved,
            "original World shell frees after detachment"
        );
        let detached_bytes = original.reserved_bytes();
        assert!(
            detached_bytes > 0,
            "same source retains actual generations and identities"
        );
        original.set_limit_bytes(0);
        let prepared = journal
            .try_prepare_publication(&world, |_, _| Ok::<_, ()>(()))
            .unwrap_or_else(|(_, error, _)| panic!("original funded publication: {error:?}"));
        assert_eq!(original.reserved_bytes(), detached_bytes);
        drop(prepared.publish());
        assert_eq!(*world.musubi_replication_shortfall_releases.view().get(), 9);
        assert_eq!(
            *world
                .musubi_replication_shortfall_releases
                .predecessor_view()
                .get(),
            Some(0)
        );
        assert!(
            original.reserved_bytes() > 0,
            "published scalar remains charged to its actual execution source"
        );
        drop(world);
        // Exact delayed EBR reclamation and notification retention are covered
        // by MV initial_tests against the original collector.
    }
}
