//! Public-span invariance, exact trace bytes, refusal and private backing custody.

use super::super::trace_storage::{PANIC_AFTER_COPY, REFUSE_ALLOCATION};
use super::*;
use iroha_allocation::AllocationRefusal;
use sha2::{Digest, Sha256};
use std::{alloc::Layout, mem::size_of};

const LIMIT: usize = 1 << 20;
fn prepare(
    log: &mut DeltaTraceLog,
    rows: usize,
    first: usize,
    repeated: usize,
    original: &AllocationBudget,
) -> Result<(), VMError> {
    original.with_deferred_refund_notifications(|scope| {
        log.prepare_batch(rows, first, repeated, Some(scope))
    })
}
fn first(log: &mut DeltaTraceLog, original: &AllocationBudget) {
    prepare(log, 1, 0, 0, original).unwrap();
    log.record_reserved(12, [0; 256], [false; 256]);
}

#[test]
fn private_changes_do_not_select_physical_span_or_growth_geometry() {
    let mut outputs = Vec::new();
    for value in [0u64, 0xfedc_ba98_7654_3210] {
        let original = AllocationBudget::new(LIMIT);
        let mut log = DeltaTraceLog::new(Some(&original));
        first(&mut log, &original);
        let mut values = [0; 256];
        let mut tags = [false; 256];
        let mut geometry = Vec::new();
        for step in 1..=20 {
            prepare(&mut log, 3, 2, 0, &original).unwrap();
            values[7] = value.wrapping_mul(step);
            tags[8] = value != 0 && step % 2 == 0;
            for offset in 0..3 {
                log.record_reserved(12 + 4 * step + offset, values, tags);
            }
            geometry.push((
                log.len(),
                log.rows.capacity(),
                log.changes.capacity(),
                log.changes.as_slice().len(),
                original.reserved_bytes(),
                original.peak_reserved_bytes(),
            ));
        }
        outputs.push(geometry);
        assert_eq!(log.changes.as_slice().len(), 256 + 20 * 2);
        for index in 1..log.len() {
            if (index - 1) % 3 != 0 {
                assert!(log.entry(index).unwrap().changes.is_empty());
            }
        }
        drop(log);
        assert_eq!(original.reserved_bytes(), 0);
    }
    assert_eq!(outputs[0], outputs[1]);
}

#[test]
fn borrowed_logical_rows_preserve_the_exact_previous_trace_hash_input() {
    // Test-only old algorithm is an independent collecting reference, not a
    // production owner or compatibility decoder.
    let original = AllocationBudget::new(LIMIT);
    let mut log = DeltaTraceLog::new(Some(&original));
    let mut previous: Option<RegisterState> = None;
    let mut reference = Vec::new();
    let mut values = [0; 256];
    let mut tags = [false; 256];
    for pc in 0u64..12 {
        prepare(&mut log, 1, 256, 0, &original).unwrap();
        values[7] = pc.wrapping_mul(19);
        tags[255] = pc % 2 == 1;
        let changes: Vec<_> = (0..256)
            .filter(|&index| {
                previous.as_ref().is_none_or(|last| {
                    last.gpr[index] != values[index] || last.tags[index] != tags[index]
                })
            })
            .map(|index| (index, values[index], tags[index]))
            .collect();
        reference.push((pc, changes));
        log.record_reserved(pc, values, tags);
        previous = Some(RegisterState {
            pc,
            gpr: values,
            tags,
        });
    }
    assert_eq!(log.len(), reference.len());
    for (actual, (pc, changes)) in log.entries().zip(&reference) {
        assert_eq!(actual, DeltaEntry { pc: *pc, changes });
    }
    // Compare the existing domain-separated byte sequence without leaking
    // fixture ownership merely to obtain an iterator with a static lifetime.
    fn digest<'a>(entries: impl ExactSizeIterator<Item = DeltaEntry<'a>>) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"ivm-summary:delta-trace:v1");
        h.update((entries.len() as u64).to_le_bytes());
        for entry in entries {
            h.update(entry.pc.to_le_bytes());
            h.update((entry.changes.len() as u64).to_le_bytes());
            for &(index, value, tag) in entry.changes {
                h.update((index as u64).to_le_bytes());
                h.update(value.to_le_bytes());
                h.update([u8::from(tag)]);
            }
        }
        h.finalize().into()
    }
    assert_eq!(
        digest(log.entries()),
        digest(
            reference
                .iter()
                .map(|(pc, changes)| DeltaEntry { pc: *pc, changes })
        )
    );
}

#[test]
fn complete_dual_backing_growth_refuses_atomically_with_original_release_source() {
    let original = AllocationBudget::new(LIMIT);
    let mut log = DeltaTraceLog::new(Some(&original));
    first(&mut log, &original);
    // Both descriptor and public change backing must grow in this batch.
    let old = original.reserved_bytes();
    let demand = 8 * size_of::<Row>() + 512 * size_of::<(usize, u64, bool)>();
    let row_ptr = log.rows.as_slice().as_ptr();
    let change_ptr = log.changes.as_slice().as_ptr();
    original.set_limit_bytes(old + demand - 1);
    let Err(VMError::AllocationDeferred(AllocationRefusal::Capacity {
        requested_bytes,
        release,
        ..
    })) = prepare(&mut log, 7, 256, 0, &original)
    else {
        panic!("combined growth refusal");
    };
    assert_eq!(requested_bytes, demand);
    let Err(AllocationRefusal::Capacity {
        release: expected, ..
    }) = original.try_reserve_bytes(demand)
    else {
        panic!("original owner");
    };
    assert_eq!(release, expected);
    assert_eq!(log.rows.as_slice().as_ptr(), row_ptr);
    assert_eq!(log.changes.as_slice().as_ptr(), change_ptr);
    assert!(log.pending.is_none());
    original.set_limit_bytes(old + demand);
    prepare(&mut log, 7, 256, 0, &original).unwrap();
    assert_eq!(original.peak_reserved_bytes(), old + demand);
    assert_eq!(original.reserved_bytes(), demand);
    for pc in 0..7 {
        log.record_reserved(pc, [0; 256], [false; 256]);
    }
    assert_eq!(log.len(), 8);
}

#[test]
fn second_allocation_refusal_and_partial_copy_unwind_keep_live_rows() {
    let original = AllocationBudget::new(LIMIT);
    let mut log = DeltaTraceLog::new(Some(&original));
    first(&mut log, &original);
    let before = original.reserved_bytes();
    let row_ptr = log.rows.as_slice().as_ptr();
    let change_ptr = log.changes.as_slice().as_ptr();
    for panic in [false, true] {
        if panic {
            PANIC_AFTER_COPY.set(true);
        } else {
            REFUSE_ALLOCATION.set(2);
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prepare(&mut log, 7, 256, 0, &original)
        }));
        if panic {
            assert!(result.is_err());
        } else {
            assert!(matches!(
                result.unwrap(),
                Err(VMError::ExecutionDeferred(
                    crate::error::ExecutionDeferral::AllocationUnavailable
                ))
            ));
        }
        assert_eq!(original.reserved_bytes(), before);
        assert_eq!(log.rows.as_slice().as_ptr(), row_ptr);
        assert_eq!(log.changes.as_slice().as_ptr(), change_ptr);
        assert_eq!(log.entry(0).unwrap().changes.len(), 256);
        assert!(log.pending.is_none());
    }
    prepare(&mut log, 7, 256, 0, &original).unwrap();
}

#[test]
fn foreign_scope_pending_overlap_and_overflow_do_not_change_credit() {
    let original = AllocationBudget::new(LIMIT);
    let foreign = AllocationBudget::new(LIMIT);
    let mut log = DeltaTraceLog::new(Some(&original));
    assert!(
        matches!(log.prepare_batch(1, 256, 0, None), Err(VMError::ExecutionDeferred(__actual_error_field)) if __actual_error_field == (
            crate::error::ExecutionDeferral::TraceOwnerUnavailable
        ))
    );
    foreign.with_deferred_refund_notifications(|scope| {
        assert!(matches!(log.prepare_batch(1, 256, 0, Some(scope)), Err(VMError::ExecutionDeferred(__actual_error_field)) if __actual_error_field == (
                crate::error::ExecutionDeferral::TraceOwnerUnavailable
            )));
        assert!(matches!(log.reset(Some(scope)), Err(VMError::ExecutionDeferred(__actual_error_field)) if __actual_error_field == (
                crate::error::ExecutionDeferral::TraceOwnerUnavailable
            )));
    });
    assert!(matches!(
        prepare(&mut log, usize::MAX, 256, 256, &original),
        Err(VMError::AllocationDeferred(
            AllocationRefusal::DemandOverflow
        ))
    ));
    assert_eq!(original.reserved_bytes(), 0);
    prepare(&mut log, 2, 0, 0, &original).unwrap();
    let before = original.reserved_bytes();
    assert!(
        matches!(prepare(&mut log, 1, 0, 0, &original), Err(VMError::ExecutionDeferred(__actual_error_field)) if __actual_error_field == (
            crate::error::ExecutionDeferral::TraceOwnerUnavailable
        ))
    );
    log.record_reserved(4, [0; 256], [false; 256]);
    log.record_reserved(8, [0; 256], [false; 256]);
    original.set_limit_bytes(0);
    log.scrub();
    prepare(&mut log, 2, 0, 0, &original).unwrap();
    log.record_reserved(12, [7; 256], [true; 256]);
    log.record_reserved(16, [7; 256], [true; 256]);
    assert_eq!(original.reserved_bytes(), before);
    original
        .with_deferred_refund_notifications(|scope| log.reset(Some(scope)))
        .unwrap();
    assert_eq!(original.reserved_bytes(), 0);
    assert!(matches!(
        prepare(&mut log, 1, 256, 0, &original),
        Err(VMError::AllocationDeferred(
            AllocationRefusal::ExceedsLimit { .. }
        ))
    ));
}

#[test]
fn snapshot_preserves_prepaid_public_spans_and_independent_final_owner() {
    let original = AllocationBudget::new(LIMIT);
    let mut log = DeltaTraceLog::new(Some(&original));
    first(&mut log, &original);
    prepare(&mut log, 3, 256, 0, &original).unwrap();
    let before = original.reserved_bytes();
    let mut copied = original
        .with_deferred_refund_notifications(|scope| log.try_clone_allocation(Some(scope)))
        .unwrap();
    assert_eq!(original.reserved_bytes(), 2 * before);
    assert_ne!(
        log.changes.as_slice().as_ptr(),
        copied.changes.as_slice().as_ptr()
    );
    original.set_limit_bytes(0);
    for pc in 0..3 {
        log.record_reserved(pc, [3; 256], [true; 256]);
        copied.record_reserved(pc, [9; 256], [false; 256]);
    }
    assert_ne!(log.entry(1), copied.entry(1));
    assert_eq!(log.entry(2).unwrap().changes, &[]);
    assert_eq!(copied.entry(2).unwrap().changes, &[]);
    drop(log);
    assert_eq!(original.reserved_bytes(), before);
    let owner = std::sync::Arc::new(copied);
    let borrowed = owner.clone();
    drop(owner);
    assert_eq!(original.reserved_bytes(), before);
    drop(borrowed);
    assert_eq!(original.reserved_bytes(), 0);
}

#[test]
fn discarded_unobserved_credit_preserves_partial_history_and_allows_caught_retry() {
    let original = AllocationBudget::new(LIMIT);
    let mut log = DeltaTraceLog::new(Some(&original));
    prepare(&mut log, 3, 2, 0, &original).unwrap();
    let initial_credit = original.reserved_bytes();
    log.discard_unobserved();
    assert!(log.is_empty());
    assert!(log.last.is_none());
    assert_eq!(original.reserved_bytes(), initial_credit);
    // A refused root/first instruction has not consumed the first full image.
    original.set_limit_bytes(0);
    prepare(&mut log, 3, 0, 0, &original).unwrap();
    log.record_reserved(12, [41; 256], [true; 256]);
    log.record_reserved(16, [41; 256], [true; 256]);
    let rows = log.rows.as_slice().as_ptr();
    let changes = log.changes.as_slice().as_ptr();
    log.discard_unobserved();
    log.discard_unobserved();
    assert_eq!(log.len(), 2);
    assert_eq!(log.entry(0).unwrap().changes[255], (255, 41, true));
    assert!(log.entry(1).unwrap().changes.is_empty());
    assert_eq!(log.changes.as_slice().len(), 256);
    // A retry with no new register changes uses the original pending capacity;
    // canceling did not erase `last` and cannot force another 256-word image.
    prepare(&mut log, 1, 0, 0, &original).unwrap();
    log.record_reserved(20, [41; 256], [true; 256]);
    assert!(log.entry(2).unwrap().changes.is_empty());
    assert_eq!(log.rows.as_slice().as_ptr(), rows);
    assert_eq!(log.changes.as_slice().as_ptr(), changes);
    assert_eq!(original.reserved_bytes(), initial_credit);
    drop(log);
    assert_eq!(original.reserved_bytes(), 0);
}

#[test]
fn discarding_snapshot_pending_credit_does_not_cancel_the_original_batch() {
    let original = AllocationBudget::new(LIMIT);
    let mut log = DeltaTraceLog::new(Some(&original));
    first(&mut log, &original);
    prepare(&mut log, 2, 1, 0, &original).unwrap();
    let credit = original.reserved_bytes();
    let mut copied = original
        .with_deferred_refund_notifications(|scope| log.try_clone_allocation(Some(scope)))
        .unwrap();
    assert_eq!(original.reserved_bytes(), 2 * credit);
    original.set_limit_bytes(0);
    copied.discard_unobserved();
    let mut values = [0; 256];
    values[7] = 19;
    log.record_reserved(16, values, [false; 256]);
    log.record_reserved(20, values, [false; 256]);
    prepare(&mut copied, 1, 0, 0, &original).unwrap();
    copied.record_reserved(24, [0; 256], [false; 256]);
    assert_eq!(log.entry(1).unwrap().changes, &[(7, 19, false)]);
    assert!(copied.entry(1).unwrap().changes.is_empty());
    assert_eq!(log.len(), 3);
    assert_eq!(copied.len(), 2);
    assert_eq!(original.reserved_bytes(), 2 * credit);
    drop(log);
    assert_eq!(original.reserved_bytes(), credit);
    drop(copied);
    assert_eq!(original.reserved_bytes(), 0);
}

#[test]
fn actual_delta_change_destructor_erases_fields_before_original_refund() {
    use crate::memory::private_disposal::tests as observer;
    let _serial = observer::serial();
    let original = observer::budget();
    for field in 0..3 {
        let mut log = DeltaTraceLog::new(Some(original));
        prepare(&mut log, 1, 256, 0, original).unwrap();
        log.record_reserved(19, [u64::MAX; 256], [true; 256]);
        let base = log.changes.as_slice().as_ptr().cast::<u8>();
        let change = &log.changes.as_slice()[255];
        let spans = [
            (
                std::ptr::from_ref(&change.0).cast::<u8>(),
                size_of::<usize>(),
            ),
            (std::ptr::from_ref(&change.1).cast::<u8>(), size_of::<u64>()),
            (
                std::ptr::from_ref(&change.2).cast::<u8>(),
                size_of::<bool>(),
            ),
        ];
        let credit = log.changes.capacity() * size_of::<(usize, u64, bool)>();
        let _watch = observer::watch(
            base,
            Layout::array::<(usize, u64, bool)>(log.changes.capacity()).unwrap(),
            spans[field].0 as usize - base as usize,
            spans[field].1,
        );
        drop(log);
        observer::assert_erased_and_freed();
        // Descriptors drop first; change backing retains its exact own charge.
        assert_eq!(observer::original_credit_at_free(), credit);
        assert_eq!(original.reserved_bytes(), 0);
    }
}

#[test]
fn partial_private_change_copy_unwind_scrubs_new_backing_and_keeps_original_credit() {
    let original = AllocationBudget::new(LIMIT);
    let mut log = DeltaTraceLog::new(Some(&original));
    prepare(&mut log, 1, 256, 0, &original).unwrap();
    log.record_reserved(41, [0xfedc_ba98_7654_3210; 256], [true; 256]);
    let before = original.reserved_bytes();
    let rows = log.rows.as_slice().as_ptr();
    let changes = log.changes.as_slice().as_ptr();
    // Row capacity is four; only change backing grows. The injected unwind
    // therefore follows an actual copied private tuple, not a descriptor.
    PANIC_AFTER_COPY.set(true);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        prepare(&mut log, 1, 256, 0, &original).unwrap();
    }));
    assert!(result.is_err());
    assert_eq!(original.reserved_bytes(), before);
    assert_eq!(log.rows.as_slice().as_ptr(), rows);
    assert_eq!(log.changes.as_slice().as_ptr(), changes);
    assert_eq!(
        log.entry(0).unwrap().changes[255],
        (255, 0xfedc_ba98_7654_3210, true)
    );
    assert!(log.pending.is_none());
    prepare(&mut log, 1, 256, 0, &original).unwrap();
    log.record_reserved(45, [0; 256], [false; 256]);
    assert_eq!(log.entry(1).unwrap().changes.len(), 256);
    drop(log);
    assert_eq!(original.reserved_bytes(), 0);
}

#[test]
fn diagnostic_capture_rejects_corrupt_indices_without_a_raw_row_constructor() {
    let original = AllocationBudget::new(LIMIT);
    let mut log = DeltaTraceLog::new(Some(&original));
    first(&mut log, &original);
    let before = original.reserved_bytes();
    // Corruption is confined to the canonical owner's private test module;
    // consumers cannot construct or mutate live owned delta rows.
    log.changes.as_mut_slice()[7].0 = 256;
    let source = crate::zk::DiagnosticTraceSource {
        registers: crate::zk::DiagnosticRegisterSource::Deltas(&log),
        constraints: &[],
        memory_events: &[],
        register_events: &[],
        steps: &[],
    };
    assert!(matches!(
        source.try_snapshot(&original),
        Err(VMError::DecodeError)
    ));
    assert_eq!(original.reserved_bytes(), before);
    assert_eq!(log.changes.as_slice()[7].0, 256);
    drop(log);
    assert_eq!(original.reserved_bytes(), 0);
}
