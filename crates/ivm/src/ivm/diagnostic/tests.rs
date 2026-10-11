//! Borrowed source identity, inline snapshot lifetime and fresh-attempt clearing.

use super::*;
use crate::{
    encoding::wide::encode_halt,
    metadata::{EmbeddedContractDebugInfoV1, EmbeddedSourceLocation, EmbeddedSourceMapEntryV1},
};
use iroha_allocation::AllocationBudget;

fn debug() -> EmbeddedContractDebugInfoV1 {
    EmbeddedContractDebugInfoV1 {
        source_map: vec![EmbeddedSourceMapEntryV1 {
            function_name: "transfer".into(),
            pc_start: 0,
            pc_end: 4,
            source: EmbeddedSourceLocation {
                source_path: Some("contracts/wallet.ko".into()),
                source_id: 3,
                byte_start: 11,
                byte_end: 23,
                line: 12,
                column: 4,
            },
        }],
        budget_report: Vec::new(),
    }
}

#[test]
fn source_views_borrow_the_original_and_snapshot_resolves_its_own_owner() {
    let mut vm = IVM::try_new(100).unwrap();
    vm.load_code(&encode_halt().to_le_bytes()).unwrap();
    vm.contract_debug = Some(debug());
    vm.capture_trap(&VMError::UnknownSyscall(0x7fff));
    let diagnostic = vm.last_diagnostic().unwrap();
    let source = diagnostic.source.unwrap();
    let original = &vm.contract_debug.as_ref().unwrap().source_map[0];
    assert_eq!(
        source.function.unwrap().as_ptr(),
        original.function_name.as_ptr()
    );
    assert_eq!(
        source.path.unwrap().as_ptr(),
        original.source.source_path.as_ref().unwrap().as_ptr()
    );
    assert_eq!(diagnostic.context.current_function, source.function);
    assert_eq!(diagnostic.context.syscall, Some(0x7fff));
    let copied = vm.try_clone_snapshot().unwrap();
    assert_eq!(copied.last_diagnostic(), vm.last_diagnostic());
    assert_eq!(copied.last_diagnostic, vm.last_diagnostic);
    vm.contract_debug.as_mut().unwrap().source_map[0]
        .function_name
        .push('X');
    assert_eq!(
        vm.last_diagnostic().unwrap().context.current_function,
        Some("transferX")
    );
    drop(vm);
    assert_eq!(
        copied.last_diagnostic().unwrap().context.current_function,
        Some("transfer")
    );
    assert_eq!(
        copied.last_diagnostic().unwrap().source.unwrap().path,
        Some("contracts/wallet.ko")
    );
}

#[test]
fn failed_run_load_and_reset_clear_stale_context_before_local_preflight() {
    let original = AllocationBudget::new(128 * 1024 * 1024);
    let mut vm = IVM::try_new_with_memory_budget(100, &original).unwrap();
    vm.load_code(&encode_halt().to_le_bytes()).unwrap();
    vm.capture_trap(&VMError::OutOfGas);
    let gas = vm.remaining_gas();
    original.set_limit_bytes(0);
    assert!(matches!(vm.run(), Err(VMError::AllocationDeferred(_))));
    assert_eq!(vm.remaining_gas(), gas);
    assert!(vm.last_diagnostic().is_none());
    vm.capture_trap(&VMError::InvalidMetadata);
    assert!(vm.load_program(&[]).is_err());
    assert!(vm.last_diagnostic().is_none());
    original.set_limit_bytes(128 * 1024 * 1024);
    vm.capture_trap(&VMError::OutOfGas);
    vm.reset().unwrap();
    assert!(vm.last_diagnostic().is_none());
    vm.run().unwrap();
    assert!(vm.last_diagnostic().is_none());
}

#[test]
fn inline_capture_keeps_exact_budget_and_omits_local_error_graphs() {
    let mut vm = IVM::try_new(100).unwrap();
    vm.load_code(&encode_halt().to_le_bytes()).unwrap();
    vm.gas_remaining = 41;
    vm.cycles = 7;
    vm.capture_trap(&VMError::Metered {
        gas: 5,
        source: Box::new(VMError::OutOfGas),
    });
    let diagnostic = vm.last_diagnostic().unwrap();
    assert_eq!(diagnostic.trap_kind, VmTrapKind::OutOfGas);
    assert_eq!(diagnostic.budget.gas_used, 59);
    assert_eq!(diagnostic.budget.cycles, 7);
    let error = VMError::Metered {
        gas: 5,
        source: Box::new(VMError::ExecutionDeferred(
            crate::error::ExecutionDeferral::TraceOwnerUnavailable,
        )),
    };
    vm.capture_trap(&error);
    assert!(vm.last_diagnostic().is_none());
    assert!(error.execution_deferral().is_some());
}

#[test]
fn nested_fault_keeps_deepest_hash_selector_and_relative_position() {
    use iroha_data_model::executor::fault::{
        IvmFaultKindV1, IvmFaultPositionV1, IvmInvocationSelectorV1,
    };
    let mut child = IVM::try_new(0).unwrap();
    child
        .load_code(
            &crate::encoding::wide::encode_ri(crate::instruction::wide::arithmetic::ADDI, 10, 0, 1)
                .to_le_bytes(),
        )
        .unwrap();
    let error = child.run().unwrap_err();
    let fault = child.last_diagnostic().unwrap().fault.unwrap();
    assert_eq!(fault.kind, IvmFaultKindV1::OutOfGas);
    assert_eq!(fault.site.selector, IvmInvocationSelectorV1::Generic);
    assert_eq!(
        fault.site.position,
        IvmFaultPositionV1::Execute { pc_offset: 0 }
    );
    let mut parent = IVM::try_new(100).unwrap();
    parent.load_code(&encode_halt().to_le_bytes()).unwrap();
    assert_ne!(parent.code_hash(), child.code_hash());
    parent.inherit_execution_fault(&child, &error, IvmFaultPositionV1::Initialization);
    parent.capture_trap(&VMError::metered(31, error.clone()));
    assert_eq!(parent.last_diagnostic().unwrap().fault, Some(fault));
    assert!(parent.last_diagnostic().unwrap().source.is_none());
    let mut root = IVM::try_new(100).unwrap();
    root.load_code(&encode_halt().to_le_bytes()).unwrap();
    root.inherit_execution_fault(&parent, &error, IvmFaultPositionV1::Initialization);
    root.capture_trap(&VMError::metered(43, error));
    assert_eq!(root.last_diagnostic().unwrap().fault, Some(fault));
    root.run().unwrap();
    assert!(root.last_diagnostic().is_none());
}

#[test]
fn local_invariants_never_capture_a_canonical_fault() {
    let mut vm = IVM::try_new(100).unwrap();
    vm.load_code(&encode_halt().to_le_bytes()).unwrap();
    for error in [
        VMError::HostUnavailable,
        VMError::SyscallGasQuoteExceeded {
            quoted: 1,
            actual: 2,
        },
        VMError::SyscallMeteringModeMismatch { syscall: 1 },
    ] {
        vm.capture_trap(&error);
        assert!(vm.last_diagnostic().is_none());
        assert!(
            vm.execution_fault(&error, IvmFaultPositionV1::Initialization)
                .is_none()
        );
    }
}

#[test]
fn boundary_fault_preserves_initialization_and_local_custody_never_becomes_a_fault() {
    let mut vm = IVM::try_new(100).unwrap();
    vm.load_code(&encode_halt().to_le_bytes()).unwrap();
    vm.record_boundary_fault(&VMError::OutOfGas, IvmFaultPositionV1::Initialization);
    let fault = vm
        .execution_fault(&VMError::OutOfGas, IvmFaultPositionV1::ReturnValidation)
        .unwrap();
    assert_eq!(fault.site.position, IvmFaultPositionV1::Initialization);
    assert!(vm.last_diagnostic().unwrap().source.is_none());
    vm.registers.set_tag(10, true);
    let gas = vm.remaining_gas();
    let error = vm.run().unwrap_err();
    assert_eq!(
        error.execution_deferral(),
        Some(crate::error::ExecutionDeferral::LocalInvariantViolation)
    );
    assert!(vm.last_diagnostic().is_none());
    assert!(
        vm.execution_fault(&error, IvmFaultPositionV1::Initialization)
            .is_none()
    );
    assert_eq!(vm.remaining_gas(), gas);
}
