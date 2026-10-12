//! Actual prepaid native-generation table current/undo and aborted transaction custody.

use super::*;
use iroha_allocation::AllocationBudget;
use iroha_data_model::sccp::generation::SccpGenerationEndV1;
use std::ops::Deref;

fn original(pool: &AllocationBudget) -> RetainedSccpGeneration {
    RetainedSccpGeneration::admit(&super::super::test_support::sample_generation(1), pool).unwrap()
}

#[test]
fn actual_table_shares_original_current_undo_and_abandons_refused_child() {
    let pool = AllocationBudget::new(1 << 20);
    let original = original(&pool);
    let mut ended = original.clone();
    ended.end = Some(SccpGenerationEndV1 {
        end_height: 10,
        end_timestamp_ms: 2_000,
        next_committee_root: original.committee_root,
        successor_validity_ms: original.validity_ms,
    });
    let retained_bytes = pool.reserved_bytes();
    let table = CommitteeStorage::try_new_admitted(pool.clone()).unwrap();
    table
        .try_with_admitted_block(|block| {
            block
                .try_insert_admitted(1, original.clone())
                .map_err(|(_, error)| error)?;
            Ok::<_, mv::storage::AdmittedStorageError>(())
        })
        .unwrap();
    assert!(std::ptr::eq(
        table.view().get(&1).unwrap().deref(),
        original.deref()
    ));
    table
        .try_with_admitted_block(|block| {
            let mut transaction = block.try_transaction_admitted()?;
            transaction
                .try_insert_admitted(1, ended.clone())
                .map_err(|(_, error)| error)?;
            transaction.apply();
            Ok::<_, mv::storage::AdmittedStorageError>(())
        })
        .unwrap();
    let snapshot = table.snapshot();
    assert!(std::ptr::eq(
        snapshot.current().get(&1).unwrap().deref(),
        ended.deref()
    ));
    assert!(std::ptr::eq(
        snapshot
            .revert_map()
            .get(&1)
            .unwrap()
            .as_ref()
            .unwrap()
            .deref(),
        original.deref()
    ));
    drop(snapshot);
    let before = pool.reserved_bytes();
    let refused = table.try_with_admitted_block(|block| {
        let mut transaction = block.try_transaction_admitted()?;
        pool.set_limit_bytes(pool.reserved_bytes());
        let (_, refusal) = transaction
            .try_insert_admitted(2, original.clone())
            .expect_err("the same original pool is full");
        assert!(matches!(
            &refusal,
            mv::storage::AdmittedStorageError::Allocation(
                iroha_allocation::AllocationRefusal::Capacity { .. }
            )
        ));
        // Even a handled refusal followed by dropping this child cannot publish its prefix.
        drop(transaction);
        Err::<(), _>(refusal)
    });
    assert!(refused.is_err());
    assert_eq!(pool.reserved_bytes(), before);
    assert!(table.view().get(&2).is_none());
    let snapshot = table.snapshot();
    assert!(std::ptr::eq(
        snapshot.current().get(&1).unwrap().deref(),
        ended.deref()
    ));
    assert!(std::ptr::eq(
        snapshot
            .revert_map()
            .get(&1)
            .unwrap()
            .as_ref()
            .unwrap()
            .deref(),
        original.deref()
    ));
    drop(snapshot);
    drop(table);
    assert_eq!(pool.reserved_bytes(), retained_bytes);
    drop((original, ended));
    assert_eq!(pool.reserved_bytes(), 0);
}
