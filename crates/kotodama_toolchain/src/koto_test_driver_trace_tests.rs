//! Actual VM trace/report ownership and checkpoint regressions.

use super::*;
use crate::koto_test_driver::{
    HashMap, IVMHost, MockWorldStateView, WsvHost, default_caller_account,
};
use iroha_allocation::AllocationBudget;

const LIMIT: usize = 128 * 1024 * 1024;

fn traced_vm(budget: &AllocationBudget, mode: TraceMode, value: u64) -> IVM {
    let mut vm = IVM::try_new_with_memory_budget(u64::MAX, budget).unwrap();
    let mut code = ivm::ProgramMetadata::default().encode();
    code.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
    vm.load_program(&code).unwrap();
    vm.set_max_cycles(0);
    vm.set_register(5, value);
    vm.set_trace_mode(mode);
    vm.run().unwrap();
    vm
}

fn host() -> KotoTestHost {
    KotoTestHost::new(
        WsvHost::new_with_subject(
            MockWorldStateView::default(),
            default_caller_account().unwrap(),
        ),
        None,
        HashMap::new(),
        std::sync::Arc::new(crate::koto_test_driver::SourceContext::empty("Trace")),
    )
}

fn values(trace: &RuntimeTraceCapture) -> Vec<u64> {
    trace
        .deltas()
        .map(|entry| entry.changes.iter().find(|change| change.0 == 5).unwrap().1)
        .collect()
}

#[test]
fn checkpoints_share_original_trace_and_restore_reclaims_only_replacement() {
    let budget = AllocationBudget::new(LIMIT);
    let first = traced_vm(&budget, TraceMode::DeltaRegisters, 11);
    let second = traced_vm(&budget, TraceMode::DeltaRegisters, 22);
    let mut host = host();
    host.record_nested_trace(&first).unwrap();
    let retained = budget.reserved_bytes();
    let original_rows = host
        .supplemental_trace
        .as_ref()
        .unwrap()
        .delta(0)
        .unwrap()
        .changes
        .as_ptr();
    let checkpoint = host.checkpoint().unwrap();
    assert_eq!(
        budget.reserved_bytes(),
        retained,
        "checkpoint must share trace backing"
    );
    host.record_nested_trace(&second).unwrap();
    assert_eq!(
        values(host.supplemental_trace.as_ref().unwrap()),
        vec![11, 22]
    );
    assert!(budget.reserved_bytes() > retained);
    host.restore(checkpoint.as_ref()).unwrap();
    let restored = host.supplemental_trace.as_ref().unwrap();
    assert_eq!(values(restored), vec![11]);
    assert_eq!(restored.delta(0).unwrap().changes.as_ptr(), original_rows);
    assert_eq!(budget.reserved_bytes(), retained);
    drop((first, second, host));
    assert!(
        budget.reserved_bytes() > 0,
        "checkpoint still owns original trace"
    );
    drop(checkpoint);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn refused_nested_capture_keeps_original_report_and_retries_in_same_pool() {
    let budget = AllocationBudget::new(LIMIT);
    let first = traced_vm(&budget, TraceMode::DeltaRegisters, 11);
    let second = traced_vm(&budget, TraceMode::DeltaRegisters, 22);
    let mut host = host();
    host.record_nested_trace(&first).unwrap();
    let retained = budget.reserved_bytes();
    let original_rows = host
        .supplemental_trace
        .as_ref()
        .unwrap()
        .delta(0)
        .unwrap()
        .changes
        .as_ptr();
    budget.set_limit_bytes(retained);
    assert!(matches!(
        host.record_nested_trace(&second),
        Err(VMError::AllocationDeferred(_))
    ));
    assert_eq!(budget.reserved_bytes(), retained);
    let preserved = host.supplemental_trace.as_ref().unwrap();
    assert_eq!(values(preserved), vec![11]);
    assert_eq!(preserved.delta(0).unwrap().changes.as_ptr(), original_rows);
    budget.set_limit_bytes(LIMIT);
    host.record_nested_trace(&second).unwrap();
    assert_eq!(
        values(host.supplemental_trace.as_ref().unwrap()),
        vec![11, 22]
    );
    drop((first, second, host));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn report_keeps_root_and_nested_rows_apart_and_outlives_both_vms() {
    for mode in [TraceMode::PcOnly, TraceMode::DeltaRegisters] {
        let budget = AllocationBudget::new(LIMIT);
        let root = traced_vm(&budget, mode, 11);
        let nested = traced_vm(&budget, mode, 22);
        let mut host = host();
        host.record_nested_trace(&nested).unwrap();
        let report = capture_report(&root, host.supplemental_trace.as_ref()).unwrap();
        let harness = report.harness.as_ref().unwrap();
        let runtime = report.runtime.as_ref().unwrap();
        if mode == TraceMode::PcOnly {
            assert_eq!(harness.pcs(), root.trace_pcs());
            assert_eq!(runtime.pcs(), nested.trace_pcs());
            assert_eq!(harness.delta_len() + runtime.delta_len(), 0);
        } else {
            assert_eq!(values(harness), vec![11]);
            assert_eq!(values(runtime), vec![22]);
            assert!(harness.pcs().is_empty());
        }
        drop((root, nested, host));
        assert!(budget.reserved_bytes() > 0);
        drop(report);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn trace_off_needs_no_capture_allocation_under_exhausted_pool() {
    let budget = AllocationBudget::new(LIMIT);
    let vm = traced_vm(&budget, TraceMode::Off, 11);
    let mut host = host();
    let retained = budget.reserved_bytes();
    budget.set_limit_bytes(retained);
    host.record_nested_trace(&vm).unwrap();
    assert!(host.supplemental_trace.is_none());
    let report = capture_report(&vm, None).unwrap();
    assert!(report.harness.is_none() && report.runtime.is_none());
    assert_eq!(budget.reserved_bytes(), retained);
    drop((vm, host));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn foreign_pool_report_composition_refuses_without_replacing_nested_owner() {
    let first = AllocationBudget::new(LIMIT);
    let second = AllocationBudget::new(LIMIT);
    let root = traced_vm(&first, TraceMode::DeltaRegisters, 11);
    let nested = traced_vm(&second, TraceMode::DeltaRegisters, 22);
    let mut host = host();
    host.record_nested_trace(&nested).unwrap();
    let reserved = (first.reserved_bytes(), second.reserved_bytes());
    assert!(matches!(
        capture_report(&root, host.supplemental_trace.as_ref()),
        Err(VMError::ExecutionDeferred(
            ivm::error::ExecutionDeferral::TraceOwnerUnavailable
        ))
    ));
    assert_eq!((first.reserved_bytes(), second.reserved_bytes()), reserved);
    assert_eq!(values(host.supplemental_trace.as_ref().unwrap()), vec![22]);
    drop((root, nested, host));
    assert_eq!(first.reserved_bytes(), 0);
    assert_eq!(second.reserved_bytes(), 0);
}
