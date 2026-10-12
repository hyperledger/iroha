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
