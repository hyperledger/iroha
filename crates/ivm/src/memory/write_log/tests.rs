//! Refusal, snapshot, scrub and final-owner accounting for write logs.

use super::*;
use crate::cache_memory::{
    TestMemoryBudget, refuse_next_owned_allocation_for_test, refuse_next_owned_vec_growth_for_test,
};
use std::sync::{Arc, Barrier};

fn log(budget: &TestMemoryBudget) -> WriteLog {
    WriteLog::with_test_budget(budget)
}
fn append(log: &mut WriteLog, addr: u64, bytes: &[u8]) {
    let entry = log.prepare(addr, bytes).unwrap();
    log.record_prepared(entry);
}
fn bytes(log: &WriteLog) -> usize {
    log.rows.capacity() * std::mem::size_of::<WriteLogEntry>()
        + log
            .rows
            .iter()
            .map(|entry| entry.bytes.len())
            .sum::<usize>()
}

#[test]
fn prepared_entry_carries_payload_charge_until_recorded_or_dropped() {
    let budget = TestMemoryBudget::new(4096);
    let mut log = log(&budget);
    let entry = log.prepare(7, &[1, 2, 3]).unwrap();
    assert!(log.is_empty());
    let rows = bytes(&log);
    assert_eq!(budget.stats().active_bytes, rows + 3);
    assert_eq!(entry.address(), 7);
    assert_eq!(entry.bytes(), &[1, 2, 3]);
    log.record_prepared(entry);
    assert_eq!(budget.stats().active_bytes, bytes(&log));
    let before = SCRUBBED_ENTRIES.get();
    let abandoned = log.prepare(8, &[4, 5]).unwrap();
    drop(abandoned);
    assert_eq!(SCRUBBED_ENTRIES.get(), before + 1);
    assert_eq!(budget.stats().active_bytes, bytes(&log));
    assert_eq!(log.rows.len(), 1);
    drop(log);
    assert_eq!(budget.stats().measured_resident_bytes(), 0);
}

#[test]
fn row_and_payload_refusal_preserve_nonempty_contents_and_retry() {
    let budget = TestMemoryBudget::new(4096);
    let mut log = log(&budget);
    for index in 0..4 {
        append(&mut log, index, &[index as u8]);
    }
    let snapshot = log.try_snapshot().unwrap();
    let before = budget.stats().active_bytes;
    refuse_next_owned_vec_growth_for_test();
    assert!(matches!(
        log.prepare(9, &[9]).unwrap_err(),
        VMError::ExecutionDeferred(ExecutionDeferral::AllocationUnavailable)
    ));
    assert!(matches!(
        allocation_error(OwnedVecGrowthError::AllocationUnavailable),
        VMError::ExecutionDeferred(ExecutionDeferral::AllocationUnavailable)
    ));
    assert_eq!(budget.stats().active_bytes, before);
    assert_eq!(&log.rows[..], &*snapshot);
    refuse_next_owned_allocation_for_test();
    assert!(log.prepare(9, &[9]).is_err());
    // Successful row-capacity growth remains owned after payload refusal.
    assert_eq!(
        budget.stats().active_bytes,
        bytes(&log) + bytes(&snapshot.log)
    );
    assert_eq!(&log.rows[..], &*snapshot);
    append(&mut log, 9, &[9]);
    assert_eq!(log.rows.len(), 5);
    assert_eq!(snapshot.len(), 4);
    drop(log);
    assert_eq!(budget.stats().active_bytes, bytes(&snapshot.log));
    drop(snapshot);
    assert_eq!(budget.stats().measured_resident_bytes(), 0);
}

#[test]
fn clear_scrubs_payloads_but_keeps_row_capacity_owned() {
    let budget = TestMemoryBudget::new(4096);
    let mut log = log(&budget);
    append(&mut log, 1, &[0xa5; 32]);
    append(&mut log, 2, &[0x5a; 17]);
    let rows = log.rows.capacity() * std::mem::size_of::<WriteLogEntry>();
    assert!(log.try_retain());
    let before = SCRUBBED_ENTRIES.get();
    log.clear();
    assert_eq!(SCRUBBED_ENTRIES.get(), before + 2);
    assert!(log.is_empty());
    assert_eq!(budget.stats().retained_bytes, rows);
    assert_eq!(budget.stats().active_bytes, 0);
    log.make_active();
    assert_eq!(budget.stats().active_bytes, rows);
    assert_eq!(budget.stats().retained_bytes, 0);
    drop(log);
    assert_eq!(budget.stats().measured_resident_bytes(), 0);
}

#[test]
fn snapshots_copy_exact_rows_and_keep_before_images_without_locks() {
    let budget = TestMemoryBudget::new(4096);
    let mut log = log(&budget);
    append(&mut log, 1, &[7, 8]);
    let snapshot = log.try_snapshot().unwrap();
    assert_eq!(snapshot.log.rows.capacity(), 1);
    assert_eq!(
        snapshot.log.memory_plan().unwrap().requested_bytes(),
        bytes(&snapshot.log)
    );
    assert_ne!(snapshot[0].bytes().as_ptr(), log.rows[0].bytes().as_ptr());
    append(&mut log, 2, &[9]);
    log.clear();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].bytes(), &[7, 8]);
    let copied = snapshot.try_clone().unwrap();
    assert_eq!(snapshot, copied);
    assert_ne!(snapshot[0].bytes().as_ptr(), copied[0].bytes().as_ptr());
    drop(log);
    drop(snapshot);
    assert_eq!(budget.stats().active_bytes, bytes(&copied.log));
    drop(copied);
    assert_eq!(budget.stats().measured_resident_bytes(), 0);
}

#[test]
fn snapshot_refusals_drop_partial_owners_without_changing_source() {
    let budget = TestMemoryBudget::new(4096);
    let mut log = log(&budget);
    append(&mut log, 1, &[0xa5; 32]);
    let before = bytes(&log);
    refuse_next_owned_vec_growth_for_test();
    assert!(log.try_snapshot().is_err());
    assert_eq!(budget.stats().active_bytes, before);
    refuse_next_owned_allocation_for_test();
    assert!(log.try_snapshot().is_err());
    assert_eq!(budget.stats().active_bytes, before);
    assert_eq!(log.rows[0].bytes(), &[0xa5; 32]);
    append(&mut log, 2, &[0x5a; 7]);
    let before = bytes(&log);
    let scrubbed = SCRUBBED_ENTRIES.get();
    crate::cache_memory::refuse_owned_allocation_after_for_test(1);
    assert!(log.try_snapshot().is_err());
    assert_eq!(SCRUBBED_ENTRIES.get(), scrubbed + 1);
    assert_eq!(budget.stats().active_bytes, before);
    assert_eq!(log.rows[0].bytes(), &[0xa5; 32]);
    assert_eq!(log.rows[1].bytes(), &[0x5a; 7]);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _copy = log.try_snapshot().unwrap();
        panic!("exercise snapshot unwind");
    }));
    assert!(result.is_err());
    assert_eq!(budget.stats().active_bytes, before);
    drop(log);
    assert_eq!(budget.stats().measured_resident_bytes(), 0);
}

#[test]
fn retention_shrink_and_concurrent_final_borrowers_keep_original_charges() {
    let budget = TestMemoryBudget::new(4096);
    let mut log = log(&budget);
    append(&mut log, 1, &[0xa5; 32]);
    let owner = Arc::new(log.try_snapshot().unwrap());
    drop(log);
    let resident = bytes(&owner.log);
    assert!(owner.log.try_retain());
    budget.set_limit(0);
    let barrier = Arc::new(Barrier::new(3));
    std::thread::scope(|scope| {
        for _ in 0..2 {
            let borrower = Arc::clone(&owner);
            let barrier = Arc::clone(&barrier);
            scope.spawn(move || {
                barrier.wait();
                assert_eq!(borrower[0].bytes(), &[0xa5; 32]);
                barrier.wait();
            });
        }
        drop(owner); // Simulate eviction while both borrowers retain storage.
        assert_eq!(budget.stats().retained_bytes, resident);
        barrier.wait();
        assert_eq!(budget.stats().retained_bytes, resident);
        barrier.wait();
    });
    assert_eq!(budget.stats().measured_resident_bytes(), 0);
}

#[test]
fn disabled_or_partial_retention_keeps_uncached_writes_and_all_charges() {
    let budget = TestMemoryBudget::new(0);
    let mut log = log(&budget);
    append(&mut log, 5, &[9; 32]);
    let resident = bytes(&log);
    assert!(!log.try_retain());
    assert_eq!(log.rows[0].bytes(), &[9; 32]);
    assert_eq!(budget.stats().active_bytes, resident);
    let row_bytes = log.rows.capacity() * std::mem::size_of::<WriteLogEntry>();
    budget.set_limit(row_bytes);
    assert!(!log.try_retain());
    assert_eq!(budget.stats().retained_bytes, row_bytes);
    assert_eq!(budget.stats().active_bytes, 32);
    log.make_active();
    assert_eq!(budget.stats().retained_bytes, 0);
    assert_eq!(budget.stats().active_bytes, resident);
    append(&mut log, 6, &[8]);
    assert_eq!(log.rows[0].bytes(), &[9; 32]);
    assert_eq!(log.rows[1].bytes(), &[8]);
    drop(log);
    assert_eq!(budget.stats().measured_resident_bytes(), 0);
}
