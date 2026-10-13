//! Exercise the exact prepaid mode adapter and unchanged original journal custody.

use super::*;
use concread::bptree::{AllocationDemand, NodeCloning, NodeFunding, PlanningError};
use iroha_allocation::{AllocationBudget, AllocationCharge, AllocationReservation};
use mv::BlockMode;
use std::alloc::Layout;

struct Policy(AllocationReservation);
impl NodeFunding for Policy {
    type Charge = AllocationCharge;
    fn take_node_charge(&mut self, layout: Layout) -> Self::Charge {
        self.0.try_split(layout).unwrap()
    }
}
macro_rules! inline_value {
    ($value:ty) => {
        impl NodeCloning<u64, $value> for Policy {
            fn clone_key(&mut self, key: &u64) -> u64 {
                *key
            }
            fn clone_value(&mut self, value: &$value) -> $value {
                *value
            }
        }
        impl ClonePlanning<u64, $value> for Policy {
            fn plan_key(_: &u64, _: &mut AllocationDemand) -> Result<(), PlanningError> {
                Ok(())
            }
            fn plan_value(_: &$value, _: &mut AllocationDemand) -> Result<(), PlanningError> {
                Ok(())
            }
        }
    };
}
inline_value!(u64);
inline_value!(Option<u64>);
impl AdmittedStoragePolicy for Policy {
    fn from_admission(admission: AllocationReservation) -> Self {
        Self(admission)
    }
    fn admission(&self) -> &AllocationReservation {
        &self.0
    }
}
type Mode = Prepaid<Policy>;
type Table = Storage<u64, u64, Mode>;

fn journal(table: &Table) -> mv::storage::Detached<u64, u64, (), Mode> {
    table
        .try_capture_admitted_block(BlockMode::Ordinary, |block| {
            block.try_insert_admitted(7, 79).unwrap();
            Ok::<_, ()>(())
        })
        .unwrap()
}

#[test]
fn prepaid_adapter_preserves_exact_original_through_abort_and_publish() {
    let budget = AllocationBudget::new(1 << 20);
    let table = Table::try_new_admitted(budget.clone()).unwrap();
    let original = journal(&table);
    let before = budget.reserved_bytes();
    let scope = budget.try_owned_refund_scope().unwrap();
    let scoped = budget.reserved_bytes();
    let mut slot = Mode::publication_slot(original, &table, &scope);
    Mode::try_prepare(&mut slot).unwrap();
    assert_eq!(budget.reserved_bytes(), scoped);
    let (original, cleanup) = Mode::abort(Mode::into_prepared(slot));
    assert!(original.matches_current(&table));
    assert_eq!(table.view().get(&7), None);
    drop(scope);
    assert_eq!(
        budget.reserved_bytes(),
        scoped,
        "retirement keeps the original scope"
    );
    drop(cleanup);
    assert_eq!(budget.reserved_bytes(), before);
    let scope = budget.try_owned_refund_scope().unwrap();
    let mut slot = Mode::publication_slot(original, &table, &scope);
    Mode::try_prepare(&mut slot).unwrap();
    let published = Mode::publish(Mode::into_prepared(slot));
    assert_eq!(table.view().get(&7), Some(&79));
    drop((published, scope));
    drop(table);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn prepaid_adapter_retains_foreign_scope_refusal_for_normal_original_recovery() {
    let budget = AllocationBudget::new(1 << 20);
    let table = Table::try_new_admitted(budget.clone()).unwrap();
    let original = journal(&table);
    let bytes = budget.reserved_bytes();
    let other = AllocationBudget::new(1 << 20);
    let foreign = other.try_owned_refund_scope().unwrap();
    let mut slot = Mode::publication_slot(original, &table, &foreign);
    assert_eq!(
        Mode::try_prepare(&mut slot),
        Err(PublicationPreparationError::Admission(
            AdmittedStorageError::ScopeIdentity
        ))
    );
    let original = Mode::recover_original(&mut slot);
    assert!(original.matches_current(&table));
    assert_eq!(budget.reserved_bytes(), bytes);
    let scope = budget.try_owned_refund_scope().unwrap();
    let mut retry = Mode::publication_slot(original, &table, &scope);
    Mode::try_prepare(&mut retry).unwrap();
    drop(Mode::publish(Mode::into_prepared(retry)));
    assert_eq!(table.view().get(&7), Some(&79));
    drop((slot, scope, foreign));
    drop(table);
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(other.reserved_bytes(), 0);
}

#[test]
fn prepaid_adapter_recovers_busy_writer_without_losing_retry_authority() {
    let budget = AllocationBudget::new(1 << 20);
    let table = Table::try_new_admitted(budget.clone()).unwrap();
    let original = journal(&table);
    let competitor = journal(&table);
    let scope = budget.try_owned_refund_scope().unwrap();
    let mut first = Mode::publication_slot(original, &table, &scope);
    Mode::try_prepare(&mut first).unwrap();
    let mut blocked = Mode::publication_slot(competitor, &table, &scope);
    assert!(matches!(
        Mode::try_prepare(&mut blocked),
        Err(PublicationPreparationError::Busy(_))
    ));
    let competitor = Mode::recover_original(&mut blocked);
    let (original, cleanup) = Mode::abort(Mode::into_prepared(first));
    drop((blocked, cleanup, original));
    let mut retry = Mode::publication_slot(competitor, &table, &scope);
    Mode::try_prepare(&mut retry).unwrap();
    Mode::release_writers(&mut retry);
    drop((retry, scope));
    drop(table);
    assert_eq!(budget.reserved_bytes(), 0);
}
