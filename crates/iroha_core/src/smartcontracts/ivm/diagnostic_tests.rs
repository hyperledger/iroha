//! Lazy local-refusal mapping and exact completed semantic diagnostic rendering.

use super::*;
use crate::{
    execution_attempt::{ExecutionAttemptError, expect_completed_rejection},
    test_allocations::allocations_during,
};
use iroha_allocation::AllocationBudget;
use iroha_data_model::executor::fault::{
    IvmFaultKindV1, IvmFaultPositionV1, IvmInvocationSelectorV1,
};
use ivm::{VMError, encoding::wide::encode_ri, instruction::wide::arithmetic};

#[test]
fn direct_local_mapper_keeps_original_nested_owner_without_physical_allocation() {
    let original = AllocationBudget::new(128 * 1024 * 1024);
    let vm = ivm::IVM::try_new_with_memory_budget(100, &original).unwrap();
    original.set_limit_bytes(original.reserved_bytes());
    let capacity = original.try_reserve_bytes(1).unwrap_err();
    for source in [
        VMError::AllocationDeferred(capacity),
        VMError::ExecutionDeferred(ivm::error::ExecutionDeferral::TraceOwnerUnavailable),
    ] {
        let expected = source.clone();
        let error = VMError::Metered {
            gas: 31,
            source: Box::new(VMError::Metered {
                gas: 17,
                source: Box::new(source),
            }),
        };
        let mut attempt = None;
        let allocations = allocations_during(|| {
            attempt = Some(map_vm_error_with_context_to_validation(&vm, error));
        });
        assert_eq!(allocations, 0);
        let ExecutionAttemptError::Deferred(owner) = attempt.unwrap() else {
            panic!("a local refusal cannot become a completed validation diagnostic");
        };
        assert_eq!(owner.into_vm_error(), expected);
        assert!(vm.last_diagnostic().is_none());
    }
    drop(vm);
    assert_eq!(original.reserved_bytes(), 0);
}

#[test]
fn actual_semantic_trap_retains_bounded_fault_without_formatting() {
    let mut vm = ivm::IVM::try_new(0).unwrap();
    vm.load_code(&encode_ri(arithmetic::ADDI, 10, 0, 1).to_le_bytes())
        .unwrap();
    let error = vm.run().unwrap_err();
    let mut outcome = None;
    let allocations = allocations_during(|| {
        outcome = Some(map_vm_error_with_context_to_validation(&vm, error));
    });
    assert_eq!(allocations, 0);
    let ValidationFail::IvmFault(fault) = expect_completed_rejection(outcome.unwrap()) else {
        panic!("VM traps must retain a structured fault");
    };
    assert_eq!(fault.kind, IvmFaultKindV1::OutOfGas);
    assert_eq!(fault.site.code_hash.as_ref(), &vm.code_hash());
    assert_eq!(fault.site.selector, IvmInvocationSelectorV1::Generic);
    assert_eq!(
        fault.site.position,
        IvmFaultPositionV1::Execute { pc_offset: 0 }
    );
}

#[test]
fn host_invariants_remain_unfinished_local_attempts() {
    let vm = ivm::IVM::try_new(100).unwrap();
    for error in [
        VMError::HostUnavailable,
        VMError::SyscallGasQuoteExceeded {
            quoted: 1,
            actual: 2,
        },
        VMError::SyscallMeteringModeMismatch { syscall: 3 },
    ] {
        let outcome = map_vm_error_with_context_to_validation(&vm, error);
        assert!(
            matches!(outcome, ExecutionAttemptError::Deferred(owner) if owner.reason() == ivm::error::ExecutionDeferral::LocalInvariantViolation)
        );
    }
}

#[test]
fn argument_precharge_fault_retains_selected_entrypoint_and_initialization() {
    let artifact = kotodama_lang::compiler::Compiler::new()
        .compile_source(
            "seiyaku Precharge { kotoage fn run(int value) authorize(anyone) { let _v = value; } }",
        )
        .unwrap();
    let parsed = ivm::ProgramMetadata::parse(&artifact).unwrap();
    let descriptor = &parsed.contract_interface.as_ref().unwrap().entrypoints[0];
    let schema = descriptor.argument_schema.as_ref().unwrap();
    let bytes = ivm_abi::arguments::encode_argument_record_from_json(
        schema,
        &iroha_primitives::json::Json::from(norito::json!({"value": "7"})),
    )
    .unwrap();
    let record =
        ivm::prepare_argument_record_with_gas_limit(schema, std::sync::Arc::from(bytes), u64::MAX)
            .unwrap();
    let mut vm = ivm::IVM::try_new(0).unwrap();
    vm.load_program(&artifact).unwrap();
    vm.set_program_counter((parsed.code_offset - parsed.header_len) as u64 + descriptor.entry_pc)
        .unwrap();
    let error = record.precharge_vm(&mut vm).unwrap_err();
    vm.record_boundary_fault(&error, IvmFaultPositionV1::Initialization);
    let ValidationFail::IvmFault(fault) =
        expect_completed_rejection(map_vm_error_with_context_to_validation(&vm, error))
    else {
        panic!("precharge gas exhaustion must retain a deterministic fault");
    };
    assert_eq!(fault.kind, IvmFaultKindV1::OutOfGas);
    assert_eq!(fault.site.code_hash.as_ref(), &vm.code_hash());
    assert_eq!(fault.site.selector, IvmInvocationSelectorV1::Entrypoint(0));
    assert_eq!(fault.site.position, IvmFaultPositionV1::Initialization);
}

#[test]
fn declared_rejection_moves_original_backing_without_physical_allocation() {
    let vm = ivm::IVM::try_new(100).unwrap();
    for depth in 0..=2 {
        for presentation in [None, Some("authenticated explanation")] {
            let contract: Box<str> = "LiquidityPolicy".into();
            let mut name = String::with_capacity(80);
            name.push_str("BelowMinimum");
            let mut error_type = String::with_capacity(120);
            error_type.push_str("LiquidityPolicy::LiquidityError");
            let message: Option<Box<str>> = presentation.map(Into::into);
            let contract_backing = contract.as_ptr();
            let name_backing = (name.as_ptr(), name.capacity());
            let type_backing = (error_type.as_ptr(), error_type.capacity());
            let message_backing = message.as_deref().map(str::as_ptr);
            let mut error = VMError::ContractAbort {
                contract,
                name,
                error_type,
                schema_hash: [7; 32],
                code: 18,
                message,
            };
            for gas in 0..depth {
                error = VMError::Metered {
                    gas: gas + 13,
                    source: Box::new(error),
                };
            }
            let mut outcome = None;
            let allocations = allocations_during(|| {
                outcome = Some(map_vm_error_with_context_to_validation(&vm, error));
            });
            assert_eq!(
                allocations, 0,
                "depth={depth}, presentation={presentation:?}"
            );
            let ValidationFail::ContractRejected(rejection) =
                expect_completed_rejection(outcome.unwrap())
            else {
                panic!("declared rejection must retain its authenticated structure");
            };
            assert_eq!(rejection.contract.as_ptr(), contract_backing);
            assert_eq!(
                (rejection.name.as_ptr(), rejection.name.capacity()),
                name_backing
            );
            assert_eq!(
                (
                    rejection.error_type.as_ptr(),
                    rejection.error_type.capacity()
                ),
                type_backing,
            );
            assert_eq!(
                rejection.message.as_deref().map(str::as_ptr),
                message_backing
            );
            assert_eq!(&*rejection.contract, "LiquidityPolicy");
            assert_eq!(rejection.name, "BelowMinimum");
            assert_eq!(rejection.error_type, "LiquidityPolicy::LiquidityError");
            assert_eq!(rejection.schema_hash, [7; 32]);
            assert_eq!(rejection.code, 18);
            assert_eq!(rejection.message.as_deref(), presentation);
        }
    }
}

#[test]
fn metered_fault_keeps_kind_and_exact_phase() {
    for with_context in [false, true] {
        let mut vm = ivm::IVM::try_new(0).unwrap();
        let source = if with_context {
            vm.load_code(&encode_ri(arithmetic::ADDI, 10, 0, 1).to_le_bytes())
                .unwrap();
            vm.run().unwrap_err()
        } else {
            VMError::OutOfGas
        };
        let error = VMError::Metered {
            gas: 31,
            source: Box::new(VMError::Metered {
                gas: 17,
                source: Box::new(source),
            }),
        };
        let ValidationFail::IvmFault(fault) =
            expect_completed_rejection(map_vm_error_with_context_to_validation(&vm, error))
        else {
            panic!("missing fault")
        };
        assert_eq!(fault.kind, IvmFaultKindV1::OutOfGas);
        assert_eq!(
            fault.site.position,
            if with_context {
                IvmFaultPositionV1::Execute { pc_offset: 0 }
            } else {
                IvmFaultPositionV1::ReturnValidation
            }
        );
    }
}
