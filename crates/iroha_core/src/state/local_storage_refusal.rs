//! First-refusal custody outside deterministic instruction and receipt encodings.

use super::{StateBlock, StateStorageAdmissionError, StateTransaction};

impl StateTransaction<'_, '_> {
    /// Retain the first original local refusal even if contract code handles its inner error.
    pub(crate) fn arm_local_storage_refusal(&mut self, error: StateStorageAdmissionError) {
        if self.local_storage_refusal.is_none() {
            *self.local_storage_refusal = Some(error);
        }
    }

    /// Abort local processing before accounting, receipts, callbacks or successful apply.
    pub(crate) fn require_storage_admission(&self) -> Result<(), StateStorageAdmissionError> {
        match self.local_storage_refusal.as_ref() {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }
}

impl StateBlock<'_> {
    /// Borrow the original refusal through child discard, without taking or clearing it.
    pub(crate) fn require_storage_admission(&self) -> Result<(), StateStorageAdmissionError> {
        match self.local_storage_refusal.as_ref() {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        kura::Kura,
        query::store::LiveQueryStore,
        state::{State, TransactionsBlockError, World},
    };
    use iroha_allocation::{AllocationBudget, AllocationRefusal};
    use iroha_data_model::block::BlockHeader;
    use iroha_model_base::state_path::StatePath;
    use std::num::NonZeroU64;

    #[test]
    fn caught_storage_allocation_refusal_cannot_commit_a_world_overlay() {
        let state = State::new_for_testing(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let path: StatePath = "refusal/value".parse().unwrap();
        let header = BlockHeader::new(NonZeroU64::MIN, None, None, 1, 0);
        let mut block = state.try_block(header).unwrap();
        let mut transaction = block.try_transaction().unwrap();
        // A full original pool refuses with a release observation.
        let pool = AllocationBudget::new(1);
        let occupied = pool.try_reserve_bytes(1).unwrap();
        let refusal = pool.try_reserve_bytes(1).unwrap_err();
        assert!(matches!(&refusal, AllocationRefusal::Capacity { .. }));
        transaction
            .world
            .smart_contract_state
            .insert(path.clone(), vec![8]);
        let expected = StateStorageAdmissionError::World(
            mv::storage::AdmittedStorageError::Allocation(refusal),
        );
        transaction.arm_local_storage_refusal(expected.clone());
        assert_eq!(
            transaction.require_storage_admission(),
            Err(expected.clone())
        );
        transaction.apply();
        drop(occupied);
        assert_eq!(block.require_storage_admission(), Err(expected));
        assert!(matches!(
            block.commit_world_overlay_for_testing(),
            Err(TransactionsBlockError::LocalStateStorage(
                StateStorageAdmissionError::World(_)
            ))
        ));
        assert!(state.world.smart_contract_state.view().get(&path).is_none());
    }
}
