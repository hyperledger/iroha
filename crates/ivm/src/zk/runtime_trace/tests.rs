//! Original capture admission, immutable checkpoint and final-owner regressions.

use super::*;
use crate::zk::trace_storage::{PANIC_AFTER_COPY, REFUSE_ALLOCATION};
use iroha_allocation::AllocationRefusal;
use std::{
    alloc::Layout,
    mem::size_of,
    panic::{AssertUnwindSafe, catch_unwind},
};

const LIMIT: usize = 16 * 1024 * 1024;

fn logs(
    original: Option<&AllocationBudget>,
    pc: u64,
    changed: bool,
) -> (PcTraceLog, DeltaTraceLog) {
    let mut pcs = PcTraceLog::new(original);
    let mut deltas = DeltaTraceLog::new(original);
    fn prepare(
        pcs: &mut PcTraceLog,
        deltas: &mut DeltaTraceLog,
        scope: Option<&iroha_allocation::AllocationScope<'_>>,
    ) {
        pcs.prepare(8, scope).unwrap();
        deltas.prepare_batch(2, 256, 255, scope).unwrap();
    }
    match original {
        Some(original) => original.with_deferred_refund_notifications(|scope| {
            prepare(&mut pcs, &mut deltas, Some(scope));
        }),
        None => prepare(&mut pcs, &mut deltas, None),
    }
    let mut registers = [pc; 256];
    registers[0] = 0;
    let mut tags = [true; 256];
    tags[0] = false;
    pcs.record_reserved(pc);
    deltas.record_reserved(pc, registers, tags);
    if changed {
        registers[1..].fill(pc + 1);
        tags[1..].fill(false);
    }
    pcs.record_reserved(pc + 4);
    deltas.record_reserved(pc + 4, registers, tags);
    (pcs, deltas)
}

fn demand(capture: &RuntimeTraceCapture) -> usize {
    Geometry::of(capture.0.source())
        .plan()
        .unwrap()
        .requested_bytes()
}

#[test]
fn public_capacities_ignore_private_logical_change_counts() {
    let original = AllocationBudget::new(LIMIT);
    let (same_pc, same_delta) = logs(Some(&original), 4, false);
    let (changed_pc, changed_delta) = logs(Some(&original), 4, true);
    let before = original.reserved_bytes();
    let same = RuntimeTraceCapture::try_capture(&same_pc, &same_delta).unwrap();
    let same_bytes = original.reserved_bytes() - before;
    let changed = RuntimeTraceCapture::try_capture(&changed_pc, &changed_delta).unwrap();
    assert_eq!(original.reserved_bytes() - before, 2 * same_bytes);
    assert_eq!(demand(&same), same_bytes);
    assert_eq!(demand(&changed), same_bytes);
    assert_eq!(same.0.pcs.capacity(), 8);
    assert_eq!(same.0.rows.capacity(), 4);
    assert_eq!(same.0.changes.capacity(), 511);
    assert!(same.delta(1).unwrap().changes.is_empty());
    assert_eq!(changed.delta(1).unwrap().changes.len(), 255);
    assert_eq!(same.delta(0), same_delta.entry(0));
    assert_eq!(changed.delta(1), changed_delta.entry(1));
    assert_ne!(same.pcs().as_ptr(), same_pc.as_slice().as_ptr());
    assert_ne!(
        same.delta(0).unwrap().changes.as_ptr(),
        same_delta.entry(0).unwrap().changes.as_ptr()
    );
    assert!(same.belongs_to(&original));
    assert!(!same.belongs_to(&AllocationBudget::new(LIMIT)));
    drop((
        same_pc,
        same_delta,
        changed_pc,
        changed_delta,
        same,
        changed,
    ));
    assert_eq!(original.reserved_bytes(), 0);
}

#[test]
fn immutable_checkpoint_clones_outlive_sources_without_new_credit() {
    let original = AllocationBudget::new(LIMIT);
    let (pcs, delta) = logs(Some(&original), 40, true);
    let capture = RuntimeTraceCapture::try_capture(&pcs, &delta).unwrap();
    let bytes = demand(&capture);
    drop((pcs, delta));
    assert_eq!(original.reserved_bytes(), bytes);
    original.set_limit_bytes(0);
    let checkpoint = capture.clone();
    let restored = checkpoint.clone();
    assert!(Owner::ptr_eq(&capture.0, &checkpoint.0));
    assert_eq!(original.reserved_bytes(), bytes);
    drop(capture);
    assert_eq!(checkpoint.pcs(), &[40, 44]);
    assert_eq!(checkpoint.delta(1).unwrap().changes[6], (7, 41, false));
    assert_eq!(checkpoint.deltas().len(), 2);
    assert_eq!(checkpoint.deltas().next_back().unwrap().pc, 44);
    assert_eq!(checkpoint.delta(2), None);
    drop(checkpoint);
    assert_eq!(original.reserved_bytes(), bytes);
    drop(restored);
    assert_eq!(original.reserved_bytes(), 0);
}

#[test]
fn combine_prepays_old_and_new_peak_and_keeps_refused_checkpoints() {
    let original = AllocationBudget::new(LIMIT);
    let (pc_a, delta_a) = logs(Some(&original), 4, false);
    let (pc_b, delta_b) = logs(Some(&original), 40, true);
    let a = RuntimeTraceCapture::try_capture(&pc_a, &delta_a).unwrap();
    let b = RuntimeTraceCapture::try_capture(&pc_b, &delta_b).unwrap();
    drop((pc_a, delta_a, pc_b, delta_b));
    let checkpoint = a.clone();
    let before = original.reserved_bytes();
    let wanted = Geometry::of(a.0.source())
        .with_next(b.0.source())
        .unwrap()
        .plan()
        .unwrap()
        .requested_bytes();
    original.set_limit_bytes(before + wanted - 1);
    let expected = original.try_reserve_bytes(wanted).unwrap_err();
    let refusal = a.try_combine(&b).unwrap_err();
    assert!(
        matches!(refusal, VMError::AllocationDeferred(__actual_error_field) if __actual_error_field == (expected))
    );
    assert_eq!(original.reserved_bytes(), before);
    assert!(Owner::ptr_eq(&a.0, &checkpoint.0));
    assert_eq!(a.pcs(), &[4, 8]);
    assert_eq!(b.pcs(), &[40, 44]);
    original.set_limit_bytes(before + wanted);
    let combined = a.try_combine(&b).unwrap();
    assert_eq!(original.reserved_bytes(), before + wanted);
    assert_eq!(combined.pcs(), &[4, 8, 40, 44]);
    assert_eq!(
        combined.deltas().map(|row| row.pc).collect::<Vec<_>>(),
        vec![4, 8, 40, 44]
    );
    assert!(combined.delta(1).unwrap().changes.is_empty());
    assert_eq!(combined.delta(2).unwrap().changes[7], (7, 40, true));
    assert_eq!(combined.delta(3).unwrap().changes[6], (7, 41, false));
    assert_eq!(combined.0.changes.capacity(), 1022);
    drop((a, b));
    assert_eq!(original.reserved_bytes(), wanted + demand(&checkpoint));
    assert_eq!(checkpoint.delta_len(), 2);
    drop(checkpoint);
    assert_eq!(original.reserved_bytes(), wanted);
    drop(combined);
    assert_eq!(original.reserved_bytes(), 0);
}

#[test]
fn foreign_empty_and_standalone_owners_never_substitute_for_original_credit() {
    let original = AllocationBudget::new(LIMIT);
    let foreign = AllocationBudget::new(LIMIT);
    let pcs = PcTraceLog::new(Some(&original));
    let delta = DeltaTraceLog::new(Some(&original));
    let foreign_delta = DeltaTraceLog::new(Some(&foreign));
    assert!(matches!(
        RuntimeTraceCapture::try_capture(&pcs, &foreign_delta).unwrap_err(),
        VMError::ExecutionDeferred(ExecutionDeferral::TraceOwnerUnavailable)
    ));
    assert_eq!(
        (original.reserved_bytes(), foreign.reserved_bytes()),
        (0, 0)
    );
    let a = RuntimeTraceCapture::try_capture(&pcs, &delta).unwrap();
    let b =
        RuntimeTraceCapture::try_capture(&PcTraceLog::new(Some(&foreign)), &foreign_delta).unwrap();
    let local = RuntimeTraceCapture::try_capture(&PcTraceLog::new(None), &DeltaTraceLog::new(None))
        .unwrap();
    let before = (original.reserved_bytes(), foreign.reserved_bytes());
    assert!(matches!(
        a.try_combine(&b).unwrap_err(),
        VMError::ExecutionDeferred(ExecutionDeferral::TraceOwnerUnavailable)
    ));
    assert!(matches!(
        a.try_combine(&local).unwrap_err(),
        VMError::ExecutionDeferred(ExecutionDeferral::TraceOwnerUnavailable)
    ));
    assert!(matches!(
        local.try_combine(&a).unwrap_err(),
        VMError::ExecutionDeferred(ExecutionDeferral::TraceOwnerUnavailable)
    ));
    assert_eq!(
        (original.reserved_bytes(), foreign.reserved_bytes()),
        before
    );
    original.set_limit_bytes(0);
    assert!(matches!(
        a.try_combine(&a),
        Err(VMError::AllocationDeferred(
            AllocationRefusal::ExceedsLimit { .. }
        ))
    ));
    assert_eq!(original.reserved_bytes(), before.0);
    drop((a, b, local));
    assert_eq!(
        (original.reserved_bytes(), foreign.reserved_bytes()),
        (0, 0)
    );
}

#[test]
fn partial_allocator_refusal_and_private_copy_unwind_keep_sources_and_credit() {
    let original = AllocationBudget::new(LIMIT);
    let (pcs, delta) = logs(Some(&original), 12, true);
    let before = original.reserved_bytes();
    REFUSE_SHELL.set(true);
    assert!(matches!(
        RuntimeTraceCapture::try_capture(&pcs, &delta).unwrap_err(),
        VMError::ExecutionDeferred(ExecutionDeferral::AllocationUnavailable)
    ));
    assert_eq!(original.reserved_bytes(), before);
    for stage in 1..=3 {
        REFUSE_ALLOCATION.set(stage);
        assert!(matches!(
            RuntimeTraceCapture::try_capture(&pcs, &delta).unwrap_err(),
            VMError::ExecutionDeferred(ExecutionDeferral::AllocationUnavailable)
        ));
        assert_eq!(original.reserved_bytes(), before);
    }
    // The complete shell and all three backing allocations exist before this
    // hook panics immediately after copying the first real private tuple.
    PANIC_AFTER_COPY.set(true);
    assert!(
        catch_unwind(AssertUnwindSafe(|| RuntimeTraceCapture::try_capture(
            &pcs, &delta
        )))
        .is_err()
    );
    assert_eq!(original.reserved_bytes(), before);
    assert_eq!(delta.entry(0).unwrap().changes[7], (7, 12, true));
    let capture = RuntimeTraceCapture::try_capture(&pcs, &delta).unwrap();
    let retained = original.reserved_bytes();
    REFUSE_ALLOCATION.set(3);
    assert!(matches!(
        capture.try_combine(&capture),
        Err(VMError::ExecutionDeferred(
            ExecutionDeferral::AllocationUnavailable
        ))
    ));
    assert_eq!(original.reserved_bytes(), retained);
    assert_eq!(capture.delta(1).unwrap().changes[6], (7, 13, false));
    drop((capture, pcs, delta));
    assert_eq!(original.reserved_bytes(), 0);
}

#[test]
fn capture_retains_unobserved_capacity_without_consuming_source_batch() {
    let original = AllocationBudget::new(LIMIT);
    let mut pcs = PcTraceLog::new(Some(&original));
    let mut delta = DeltaTraceLog::new(Some(&original));
    original.with_deferred_refund_notifications(|scope| {
        pcs.prepare(19, Some(scope)).unwrap();
        delta.prepare_batch(3, 256, 1, Some(scope)).unwrap();
    });
    let capture = RuntimeTraceCapture::try_capture(&pcs, &delta).unwrap();
    assert!(capture.pcs().is_empty());
    assert_eq!(capture.delta_len(), 0);
    assert_eq!(capture.0.pcs.capacity(), 19);
    assert_eq!(capture.0.rows.capacity(), 4);
    assert_eq!(capture.0.changes.capacity(), 258);
    original.set_limit_bytes(0);
    let mut registers = [0; 256];
    for pc in [4, 8, 12] {
        registers[7] = pc;
        pcs.record_reserved(pc);
        delta.record_reserved(pc, registers, [false; 256]);
    }
    assert_eq!(delta.len(), 3);
    assert_eq!(capture.delta_len(), 0);
    drop((capture, pcs, delta));
    assert_eq!(original.reserved_bytes(), 0);
}

#[test]
fn standalone_capture_combines_without_inventing_an_execution_pool() {
    let (pcs, delta) = logs(None, 20, true);
    let capture = RuntimeTraceCapture::try_capture(&pcs, &delta).unwrap();
    let combined = capture.try_combine(&capture).unwrap();
    assert!(combined.0.original.is_none());
    assert_eq!(combined.pcs(), &[20, 24, 20, 24]);
    assert_eq!(combined.delta_len(), 4);
    assert_eq!(combined.delta(3), delta.entry(1));
    assert!(!combined.belongs_to(&AllocationBudget::new(LIMIT)));
    drop((pcs, delta, capture));
    assert_eq!(combined.delta(0).unwrap().changes[7], (7, 20, true));
}

#[test]
fn checked_public_layout_overflow_is_not_allocator_fallback() {
    for geometry in [
        Geometry {
            pcs: usize::MAX,
            rows: 0,
            changes: 0,
        },
        Geometry {
            pcs: 0,
            rows: usize::MAX,
            changes: 0,
        },
        Geometry {
            pcs: 0,
            rows: 0,
            changes: usize::MAX,
        },
    ] {
        assert!(matches!(
            geometry.plan(),
            Err(VMError::AllocationDeferred(
                AllocationRefusal::DemandOverflow
            ))
        ));
    }
}

#[test]
fn actual_capture_destructor_erases_private_fields_before_original_refund() {
    use crate::memory::private_disposal::tests as observer;
    let _serial = observer::serial();
    let original = observer::budget();
    for field in 0..3 {
        assert_eq!(original.reserved_bytes(), 0);
        let (pcs, delta) = logs(Some(original), 0xdead_beef, true);
        let capture = RuntimeTraceCapture::try_capture(&pcs, &delta).unwrap();
        drop((pcs, delta));
        let entries = capture.0.changes.as_slice();
        let base = entries.as_ptr().cast::<u8>();
        let entry = &entries[7];
        let spans = [
            ((&entry.0 as *const usize).cast::<u8>(), size_of::<usize>()),
            ((&entry.1 as *const u64).cast::<u8>(), size_of::<u64>()),
            ((&entry.2 as *const bool).cast::<u8>(), size_of::<bool>()),
        ];
        let changes_bytes = capture.0.changes.capacity() * size_of::<Change>();
        let _watch = observer::watch(
            base,
            Layout::array::<Change>(capture.0.changes.capacity()).unwrap(),
            spans[field].0 as usize - base as usize,
            spans[field].1,
        );
        drop(capture);
        observer::assert_erased_and_freed();
        // Shared releases its shell charge after the moved payload's backing.
        assert_eq!(
            observer::original_credit_at_free(),
            changes_bytes + Owner::layout().size()
        );
        assert_eq!(original.reserved_bytes(), 0);
    }
}

#[test]
fn actual_capture_destructor_erases_logical_descriptor_fields() {
    use crate::memory::private_disposal::tests as observer;
    let _serial = observer::serial();
    let original = observer::budget();
    for field in 0..3 {
        assert_eq!(original.reserved_bytes(), 0);
        let (pcs, delta) = logs(Some(original), 0xbeef, true);
        let capture = RuntimeTraceCapture::try_capture(&pcs, &delta).unwrap();
        drop((pcs, delta));
        let entries = capture.0.rows.as_slice();
        let base = entries.as_ptr().cast::<u8>();
        // All selected fields are nonzero: observed PC, physical start 256,
        // and the private logical count 255.
        let entry = &entries[1];
        let spans = [
            ((&entry.pc as *const u64).cast::<u8>(), size_of::<u64>()),
            (
                (&entry.start as *const usize).cast::<u8>(),
                size_of::<usize>(),
            ),
            (
                (&entry.count as *const usize).cast::<u8>(),
                size_of::<usize>(),
            ),
        ];
        let retained_at_row_free = capture.0.rows.capacity() * size_of::<Row>()
            + capture.0.changes.capacity() * size_of::<Change>()
            + Owner::layout().size();
        let _watch = observer::watch(
            base,
            Layout::array::<Row>(capture.0.rows.capacity()).unwrap(),
            spans[field].0 as usize - base as usize,
            spans[field].1,
        );
        drop(capture);
        observer::assert_erased_and_freed();
        assert_eq!(observer::original_credit_at_free(), retained_at_row_free);
        assert_eq!(original.reserved_bytes(), 0);
    }
}
