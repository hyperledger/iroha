//! Original-pool map nodes for immutable completed native anchor chunk roots.

use concread::bptree::{
    AllocationDemand, ClonePlanning, NodeCloning, NodeFunding, PlanningError, Prepaid,
};
use iroha_allocation::{AllocationCharge, AllocationReservation};
use mv::storage::AdmittedStoragePolicy;
use std::alloc::Layout;

/// Closed fixed-value node policy; every current and undo node retains original funding.
pub struct AnchorStoragePolicy(AllocationReservation);
impl NodeFunding for AnchorStoragePolicy {
    type Charge = AllocationCharge;
    fn take_node_charge(&mut self, layout: Layout) -> Self::Charge {
        self.0
            .try_split(layout)
            .expect("admitted anchor node layout")
    }
}
macro_rules! fixed_copy {
    ($value:ty) => {
        impl NodeCloning<u64, $value> for AnchorStoragePolicy {
            fn clone_key(&mut self, key: &u64) -> u64 {
                *key
            }
            fn clone_value(&mut self, value: &$value) -> $value {
                *value
            }
        }
        impl ClonePlanning<u64, $value> for AnchorStoragePolicy {
            fn plan_key(_: &u64, _: &mut AllocationDemand) -> Result<(), PlanningError> {
                Ok(())
            }
            fn plan_value(_: &$value, _: &mut AllocationDemand) -> Result<(), PlanningError> {
                Ok(())
            }
        }
    };
}
fixed_copy!([u8; 32]);
fixed_copy!(Option<[u8; 32]>);
impl AdmittedStoragePolicy for AnchorStoragePolicy {
    fn from_admission(admission: AllocationReservation) -> Self {
        Self(admission)
    }
    fn admission(&self) -> &AllocationReservation {
        &self.0
    }
}
/// The sole completed-chunk map mode.
pub type AnchorStorageMode = Prepaid<AnchorStoragePolicy>;
/// Complete current/undo chunk root map, charged to its original execution pool.
pub type AnchorStorage = mv::storage::Storage<u64, [u8; 32], AnchorStorageMode>;

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_allocation::AllocationBudget;
    #[test]
    fn original_pool_retains_current_undo_and_refused_child_without_partial_root() {
        let budget = AllocationBudget::new(1 << 20);
        let table = AnchorStorage::try_new_admitted(budget.clone()).unwrap();
        for root in [[1; 32], [2; 32]] {
            table
                .try_with_admitted_block(|block| {
                    block
                        .try_insert_admitted(0, root)
                        .map_err(|(_, error)| error)?;
                    Ok::<_, mv::storage::AdmittedStorageError>(())
                })
                .unwrap();
        }
        let snapshot = table.snapshot();
        assert_eq!(snapshot.current().get(&0), Some(&[2; 32]));
        assert_eq!(snapshot.revert_map().get(&0), Some(&Some([1; 32])));
        drop(snapshot);
        let before = budget.reserved_bytes();
        let result = table.try_with_admitted_block(|block| {
            let mut child = block.try_transaction_admitted()?;
            budget.set_limit_bytes(budget.reserved_bytes());
            let (_, original) = child.try_insert_admitted(1, [3; 32]).unwrap_err();
            drop(child);
            Err::<(), _>(original)
        });
        assert!(result.is_err());
        assert_eq!(budget.reserved_bytes(), before);
        let snapshot = table.snapshot();
        assert!(snapshot.current().get(&1).is_none());
        assert_eq!(snapshot.current().get(&0), Some(&[2; 32]));
        assert_eq!(snapshot.revert_map().get(&0), Some(&Some([1; 32])));
        drop(snapshot);
        drop(table);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}
