//! PC ownership, before-effects growth and original-pool erasure tests.

use super::*;
use std::{alloc::Layout, mem::size_of};

fn prepare(log: &mut PcTraceLog, rows: usize, original: &AllocationBudget) -> Result<(), VMError> {
    original.with_deferred_refund_notifications(|scope| log.prepare(rows, Some(scope)))
}

#[test]
fn pc_growth_keeps_old_and_new_charges_and_preserves_refused_observations() {
    let bytes = size_of::<u64>();
    let original = AllocationBudget::new(4 * bytes);
    let mut log = PcTraceLog::new(Some(&original));
    prepare(&mut log, 4, &original).unwrap();
    for pc in [4, 8, 12, 16] {
        log.record_reserved(pc);
    }
    let ptr = log.as_slice().as_ptr();
    original.set_limit_bytes(12 * bytes - 1);
    assert!(
        matches!(prepare(&mut log, 1, &original), Err(VMError::AllocationDeferred(AllocationRefusal::Capacity { requested_bytes, .. })) if requested_bytes == 8 * bytes)
    );
    assert_eq!(log.as_slice(), &[4, 8, 12, 16]);
    assert_eq!(log.as_slice().as_ptr(), ptr);
    original.set_limit_bytes(12 * bytes);
    prepare(&mut log, 1, &original).unwrap();
    log.record_reserved(20);
    assert_eq!(original.peak_reserved_bytes(), 12 * bytes);
    assert_eq!(original.reserved_bytes(), 8 * bytes);
    original.set_limit_bytes(0);
    log.clear();
    prepare(&mut log, 8, &original).unwrap();
    for pc in 0..8 {
        log.record_reserved(pc);
    }
    assert_eq!(log.allocated_bytes().unwrap(), 8 * bytes);
    original
        .with_deferred_refund_notifications(|scope| log.reset(Some(scope)))
        .unwrap();
    assert_eq!(original.reserved_bytes(), 0);
    assert!(matches!(
        prepare(&mut log, 1, &original),
        Err(VMError::AllocationDeferred(
            AllocationRefusal::ExceedsLimit { .. }
        ))
    ));
}

#[test]
fn pc_copy_scope_refusal_and_unwind_preserve_the_original() {
    let original = AllocationBudget::new(1024);
    let foreign = AllocationBudget::new(1024);
    let mut log = PcTraceLog::new(Some(&original));
    prepare(&mut log, 4, &original).unwrap();
    for pc in 1..=4 {
        log.record_reserved(pc);
    }
    assert_eq!(
        log.prepare(0, None),
        Err(VMError::ExecutionDeferred(
            crate::error::ExecutionDeferral::TraceOwnerUnavailable
        ))
    );
    foreign.with_deferred_refund_notifications(|scope| {
        assert_eq!(
            log.reset(Some(scope)),
            Err(VMError::ExecutionDeferred(
                crate::error::ExecutionDeferral::TraceOwnerUnavailable
            ))
        );
        assert!(matches!(
            log.try_clone_allocation(Some(scope)),
            Err(VMError::ExecutionDeferred(
                crate::error::ExecutionDeferral::TraceOwnerUnavailable
            ))
        ));
    });
    let before = original.reserved_bytes();
    for panic in [false, true] {
        if panic {
            PANIC_AFTER_COPY.set(true);
        } else {
            REFUSE_ALLOCATION.set(1);
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prepare(&mut log, 1, &original)
        }));
        if panic {
            assert!(result.is_err());
        } else {
            assert!(matches!(
                result.unwrap(),
                Err(VMError::ExecutionDeferred(
                    ExecutionDeferral::AllocationUnavailable
                ))
            ));
        }
        assert_eq!(original.reserved_bytes(), before);
        assert_eq!(log.as_slice(), &[1, 2, 3, 4]);
    }
    let copy = original
        .with_deferred_refund_notifications(|scope| log.try_clone_allocation(Some(scope)))
        .unwrap();
    assert_eq!(copy.as_slice(), log.as_slice());
    assert_ne!(copy.as_slice().as_ptr(), log.as_slice().as_ptr());
    assert_eq!(original.reserved_bytes(), 2 * before);
    drop(log);
    assert_eq!(original.reserved_bytes(), before);
    drop(copy);
    assert_eq!(original.reserved_bytes(), 0);
}

#[test]
fn actual_pc_destructor_scrubs_before_original_credit_refund() {
    use crate::memory::private_disposal::tests as observer;
    let _serial = observer::serial();
    let original = observer::budget();
    assert_eq!(original.reserved_bytes(), 0);
    let mut log = PcTraceLog::new(Some(original));
    prepare(&mut log, 4, original).unwrap();
    log.record_reserved(0xffff_ffff_ffff_abcd);
    let credit = original.reserved_bytes();
    let _watch = observer::watch(
        log.as_slice().as_ptr().cast(),
        Layout::array::<u64>(4).unwrap(),
        0,
        size_of::<u64>(),
    );
    drop(log);
    observer::assert_erased_and_freed();
    assert_eq!(observer::original_credit_at_free(), credit);
    assert_eq!(original.reserved_bytes(), 0);
}

#[test]
fn empty_pc_snapshot_retains_already_admitted_future_observations() {
    let original = AllocationBudget::new(size_of::<[u64; 8]>());
    let mut log = PcTraceLog::new(Some(&original));
    prepare(&mut log, 1, &original).unwrap();
    assert!(log.as_slice().is_empty());
    let mut copy = original
        .with_deferred_refund_notifications(|scope| log.try_clone_allocation(Some(scope)))
        .unwrap();
    assert_eq!(original.reserved_bytes(), size_of::<[u64; 8]>());
    original.set_limit_bytes(0);
    log.record_reserved(11);
    copy.record_reserved(19);
    assert_eq!(log.as_slice(), &[11]);
    assert_eq!(copy.as_slice(), &[19]);
    drop(log);
    assert_eq!(original.reserved_bytes(), 4 * size_of::<u64>());
    drop(copy);
    assert_eq!(original.reserved_bytes(), 0);
}
