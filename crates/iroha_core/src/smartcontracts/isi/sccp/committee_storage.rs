//! Original-pool map custody for immutable native SCCP generation owners.
//!
//! Current and undo map nodes use the same finite pool. The closed copy policy
//! shares already admitted payload graphs; it never allocates replacement keys,
//! member identities or generation records while a map is copied.

use super::generation_record::RetainedSccpGeneration;
use concread::bptree::{
    AllocationDemand, ClonePlanning, NodeCloning, NodeFunding, PlanningError, Prepaid,
};
use iroha_allocation::{AllocationCharge, AllocationReservation};
use mv::storage::AdmittedStoragePolicy;
use std::alloc::Layout;

/// Closed prepaid node/copy policy for current and undo native generation rows.
pub struct CommitteeStoragePolicy(AllocationReservation);

impl NodeFunding for CommitteeStoragePolicy {
    type Charge = AllocationCharge;
    fn take_node_charge(&mut self, layout: Layout) -> Self::Charge {
        self.0
            .try_split(layout)
            .expect("admitted committee map node layout")
    }
}

macro_rules! retained_copy {
    ($value:ty) => {
        impl NodeCloning<u64, $value> for CommitteeStoragePolicy {
            fn clone_key(&mut self, key: &u64) -> u64 {
                *key
            }
            fn clone_value(&mut self, value: &$value) -> $value {
                value.clone()
            }
        }
        impl ClonePlanning<u64, $value> for CommitteeStoragePolicy {
            fn plan_key(_: &u64, _: &mut AllocationDemand) -> Result<(), PlanningError> {
                Ok(())
            }
            fn plan_value(_: &$value, _: &mut AllocationDemand) -> Result<(), PlanningError> {
                // Only immutable references are duplicated; payload custody stays original.
                Ok(())
            }
        }
    };
}
retained_copy!(RetainedSccpGeneration);
retained_copy!(Option<RetainedSccpGeneration>);

impl AdmittedStoragePolicy for CommitteeStoragePolicy {
    fn from_admission(admission: AllocationReservation) -> Self {
        Self(admission)
    }
    fn admission(&self) -> &AllocationReservation {
        &self.0
    }
}

/// Native current/undo map mode; no untracked generation-table variant exists.
pub type CommitteeStorageMode = Prepaid<CommitteeStoragePolicy>;
/// Original current and exact undo maps of structurally validated generation claims.
pub type CommitteeStorage = mv::storage::Storage<u64, RetainedSccpGeneration, CommitteeStorageMode>;

#[cfg(test)]
#[path = "committee_storage/tests.rs"]
mod tests;

#[cfg(test)]
use iroha_allocation::AllocationBudget;
#[cfg(test)]
use iroha_data_model::sccp::generation::SccpCommitteeGenerationV1;

/// Fixture-only malformed record construction preserves snapshot rejection tests.
/// It uses the actual map's pool and is absent from production builds.
#[cfg(test)]
pub(crate) trait CommitteeFixtureStorage {
    fn insert(
        &mut self,
        key: u64,
        record: SccpCommitteeGenerationV1,
    ) -> Option<RetainedSccpGeneration>;
    fn remove(&mut self, key: u64) -> Option<RetainedSccpGeneration>;
}
#[cfg(test)]
fn fixture(
    record: &SccpCommitteeGenerationV1,
    budget: &AllocationBudget,
) -> RetainedSccpGeneration {
    use norito::codec::Encode as _;
    RetainedSccpGeneration::decode_snapshot_hex_for_fixture(&hex::encode(record.encode()), budget)
        .unwrap()
}
#[cfg(test)]
impl CommitteeFixtureStorage for CommitteeStorage {
    fn insert(
        &mut self,
        key: u64,
        record: SccpCommitteeGenerationV1,
    ) -> Option<RetainedSccpGeneration> {
        let owner = fixture(&record, self.allocation_budget());
        self.try_with_admitted_block(|block| {
            block.try_insert_admitted(key, owner).map_err(|(_, e)| e)
        })
        .unwrap()
    }
    fn remove(&mut self, key: u64) -> Option<RetainedSccpGeneration> {
        self.try_with_admitted_block(|block| block.try_remove_admitted(key).map_err(|(_, e)| e))
            .unwrap()
    }
}
#[cfg(test)]
impl CommitteeFixtureStorage
    for mv::storage::Block<'_, u64, RetainedSccpGeneration, CommitteeStorageMode>
{
    fn insert(
        &mut self,
        key: u64,
        record: SccpCommitteeGenerationV1,
    ) -> Option<RetainedSccpGeneration> {
        let owner = fixture(&record, self.allocation_budget());
        self.try_insert_admitted(key, owner)
            .map_err(|(_, e)| e)
            .unwrap()
    }
    fn remove(&mut self, key: u64) -> Option<RetainedSccpGeneration> {
        self.try_remove_admitted(key).map_err(|(_, e)| e).unwrap()
    }
}

/// Test-only acquisition of this exact generation map's admitted writer pair.
/// The returned block retains the original pool's refund scope until both locks release.
#[cfg(test)]
pub(crate) trait CommitteeFixtureBlock {
    /// Acquire the ordinary current/undo writers without acquiring other World fields.
    fn block(&self) -> mv::storage::Block<'_, u64, RetainedSccpGeneration, CommitteeStorageMode>;
}
#[cfg(test)]
impl CommitteeFixtureBlock for CommitteeStorage {
    fn block(&self) -> mv::storage::Block<'_, u64, RetainedSccpGeneration, CommitteeStorageMode> {
        let scope = self
            .allocation_budget()
            .try_owned_refund_scope()
            .expect("fixture generation original refund scope");
        let mut slot = self
            .try_block_acquisition_owned(&scope)
            .expect("fixture generation original pool");
        slot.try_initialize(mv::BlockMode::Ordinary)
            .expect("fixture generation original current/undo writers");
        slot.into_block()
    }
}

/// Test-only ordinary publication of this exact admitted generation writer pair.
#[cfg(test)]
pub(crate) trait CommitteeFixtureCommit {
    /// Prepare and install the original pair before releasing its refund scope.
    fn commit(self);
}
#[cfg(test)]
impl CommitteeFixtureCommit
    for mv::storage::Block<'_, u64, RetainedSccpGeneration, CommitteeStorageMode>
{
    fn commit(self) {
        use mv::BlockPublication as _;

        let mut publication = self.publication_slot();
        publication.prepare_publication();
        publication.publish_prepared();
    }
}

#[cfg(test)]
impl CommitteeFixtureStorage
    for mv::storage::Transaction<'_, u64, RetainedSccpGeneration, CommitteeStorageMode>
{
    fn insert(
        &mut self,
        key: u64,
        record: SccpCommitteeGenerationV1,
    ) -> Option<RetainedSccpGeneration> {
        let owner = fixture(&record, self.allocation_budget());
        self.try_insert_admitted(key, owner)
            .map_err(|(_, e)| e)
            .unwrap()
    }
    fn remove(&mut self, key: u64) -> Option<RetainedSccpGeneration> {
        self.try_remove_admitted(key).map_err(|(_, e)| e).unwrap()
    }
}

#[cfg(test)]
#[test]
fn fixture_transaction_keeps_original_pool_and_ordinary_apply_rollback() {
    use crate::smartcontracts::isi::sccp::test_support::sample_generation;

    let budget = AllocationBudget::new(1 << 20);
    let storage = CommitteeStorage::try_new_admitted(budget.clone()).unwrap();
    let record = sample_generation(1);
    let mut block = storage.block();
    {
        let mut transaction = block.try_transaction_admitted().unwrap();
        assert!(transaction.insert(1, record.clone()).is_none());
        let retained = transaction.get(&1).unwrap();
        assert!(retained.belongs_to(&budget));
        assert_eq!(&**retained, &record);
        transaction.apply();
    }
    {
        let mut transaction = block.try_transaction_admitted().unwrap();
        let removed = transaction.remove(1).unwrap();
        assert!(removed.belongs_to(&budget));
        assert_eq!(&*removed, &record);
        assert!(transaction.get(&1).is_none());
        // Abandon the child: its original parent roots must survive unchanged.
    }
    assert_eq!(block.get(&1).map(|retained| &**retained), Some(&record));
    block.commit();
    assert_eq!(
        storage.view().get(&1).map(|retained| &**retained),
        Some(&record)
    );
}
