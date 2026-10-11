//! Local refusal identity and ordinary contract-debug outcome regressions.

use std::any::Any;

use iroha_core::smartcontracts::ivm::{
    cache::PreparedContractCache, return_value::EntrypointReturnDecodeError,
};
use ivm::{
    TraceMode,
    encoding::wide::{encode_halt, encode_syscallx},
    error::ExecutionDeferral,
};

use super::*;

fn vm() -> IVM {
    let mut vm = IVM::try_new(100).unwrap();
    let words = [encode_syscallx(ivm::syscalls::SYSCALL_ABORT), encode_halt()];
    let code: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    vm.load_code(&code).unwrap();
    vm.set_zk_mode(false).unwrap();
    vm.set_max_cycles(0);
    vm
}

struct Host {
    change_mode: bool,
    error: Option<VMError>,
    calls: usize,
}
impl IVMHost for Host {
    fn prepare_syscall(&self, _: u32, _: &IVM) -> Result<u64, VMError> {
        Ok(0)
    }
    fn syscall(&mut self, _: u32, vm: &mut IVM) -> Result<u64, VMError> {
        self.calls += 1;
        if self.change_mode {
            vm.set_trace_mode(TraceMode::PcOnly);
        }
        self.error.take().map_or(Ok(0), Err)
    }
    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

#[test]
fn actual_trace_policy_change_cannot_reach_completed_report() {
    let mut vm = vm();
    vm.set_trace_mode(TraceMode::DeltaRegisters);
    let mut host = Host {
        change_mode: true,
        error: None,
        calls: 0,
    };
    let mut report_built = false;
    let report = (|| -> eyre::Result<()> {
        let _outcome = run(&mut vm, &mut host)?;
        report_built = true;
        Ok(())
    })()
    .unwrap_err();
    assert_eq!(host.calls, 1);
    assert!(!report_built);
    assert_eq!(
        report.downcast_ref::<VMError>(),
        Some(&VMError::ExecutionDeferred(
            ExecutionDeferral::TraceOwnerUnavailable
        ))
    );
}

#[test]
fn nested_metered_local_errors_retain_their_original_type_without_gas() {
    for reason in [
        ExecutionDeferral::LocalInvariantViolation,
        ExecutionDeferral::TraceOwnerUnavailable,
        ExecutionDeferral::ActiveMemoryCapacity,
        ExecutionDeferral::AllocationUnavailable,
        ExecutionDeferral::VerifierArtifactsUnavailable,
        ExecutionDeferral::CanonicalHistoryUnavailable,
        ExecutionDeferral::CanonicalHistoryCapacity,
    ] {
        let error = VMError::Metered {
            gas: 31,
            source: Box::new(VMError::Metered {
                gas: 17,
                source: Box::new(VMError::ExecutionDeferred(reason)),
            }),
        };
        let expected = error.clone();
        let report = completed(Err(error)).unwrap_err();
        let retained = report.downcast_ref::<VMError>().unwrap();
        assert_eq!(retained, &expected);
        assert_eq!(retained.execution_deferral(), Some(reason));
        assert_eq!(retained.metered_gas(), None);
    }
}

#[test]
fn allocation_refusal_retains_the_original_pool_release_observation() {
    let cache = iroha_core::smartcontracts::ivm::cache::PreparedContractCache::with_capacity(0);
    let original = cache.execution_budget();
    let baseline = original.reserved_bytes();
    let retained = original
        .try_reserve_bytes(original.limit_bytes() - baseline)
        .unwrap();
    let refusal = original.try_reserve_bytes(1).unwrap_err();
    let expected = VMError::AllocationDeferred(refusal);
    let mut host = Host {
        change_mode: false,
        error: Some(expected.clone()),
        calls: 0,
    };
    let mut vm = vm();
    let report = run(&mut vm, &mut host).unwrap_err();
    assert_eq!(host.calls, 1);
    assert_eq!(report.downcast_ref::<VMError>(), Some(&expected));
    assert_eq!(original.reserved_bytes(), original.limit_bytes());
    drop(retained);
    assert_eq!(original.reserved_bytes(), baseline);
    assert_eq!(report.downcast_ref::<VMError>(), Some(&expected));
}

#[test]
fn ordinary_success_and_semantic_faults_remain_completed_outcomes() {
    for error in [
        None,
        Some(VMError::OutOfGas),
        Some(VMError::PrivacyViolation),
    ] {
        let mut vm = vm();
        let mut host = Host {
            change_mode: false,
            error: error.clone(),
            calls: 0,
        };
        assert_eq!(run(&mut vm, &mut host).unwrap(), error.map_or(Ok(()), Err));
        assert_eq!(host.calls, 1);
    }
    let semantic = VMError::Metered {
        gas: 13,
        source: Box::new(VMError::OutOfGas),
    };
    assert_eq!(completed(Err(semantic.clone())).unwrap(), Err(semantic));
}

fn completed_return() -> (IVM, PreparedContractCache, EntrypointValueTypeV1) {
    let cache = PreparedContractCache::with_capacity(0);
    let mut vm = IVM::try_new_with_memory_budget(100_000, cache.execution_budget()).unwrap();
    let program = kotodama_lang::compiler::Compiler::new()
        .compile_source(
            "seiyaku DebugReturnAttempt { view fn main() authorize(anyone) -> bool { true } }",
        )
        .unwrap();
    vm.load_program(&program).unwrap();
    vm.select_entrypoint("main").unwrap();
    let schema = vm
        .contract_interface()
        .unwrap()
        .entrypoints
        .iter()
        .find(|entry| entry.name == "main")
        .unwrap()
        .return_schema
        .clone()
        .unwrap();
    vm.run().unwrap();
    (vm, cache, schema)
}

#[test]
fn actual_return_refusal_keeps_typed_original_owner_and_retries() {
    let (vm, cache, schema) = completed_return();
    let original = cache.execution_budget();
    let original_limit = original.limit_bytes();
    assert_eq!(
        decode_return(&vm, &schema, "return value").unwrap(),
        norito::json::Value::Bool(true)
    );
    let gas = vm.remaining_gas();
    vm.memory.clear_tracking();
    original.set_limit_bytes(original.reserved_bytes());
    let expected = (0..65_536)
        .find_map(|_| match vm.memory.load_u64(vm.register(10)) {
            Ok(_) => None,
            Err(error @ VMError::AllocationDeferred(_)) => Some(error),
            Err(error) => panic!("unexpected tracked return-read failure: {error:?}"),
        })
        .expect("tiny fixture exhausts its original read backing");
    let retained = original.reserved_bytes();
    for context in [
        "failed to decode contract debug view return value",
        "failed to decode contract debug call return value",
    ] {
        let report = decode_return(&vm, &schema, context).unwrap_err();
        let Some(EntrypointReturnDecodeError::ExecutionDeferred { word_index, reason }) =
            report.downcast_ref::<EntrypointReturnDecodeError>()
        else {
            panic!("return refusal must retain its typed owner");
        };
        assert_eq!(*word_index, 0);
        assert_eq!(reason, &expected);
        assert_eq!(reason.metered_gas(), None);
        assert_eq!(report.to_string(), context);
        assert_eq!(vm.remaining_gas(), gas);
        assert_eq!(vm.call_result_word_count().unwrap(), 1);
        assert_eq!(original.reserved_bytes(), retained);
    }
    original.set_limit_bytes(original_limit);
    assert_eq!(
        decode_return(&vm, &schema, "return value").unwrap(),
        norito::json::Value::Bool(true)
    );
    assert_eq!(vm.remaining_gas(), gas);
    drop(vm);
    assert_eq!(original.reserved_bytes(), 0);
}

#[test]
fn actual_semantic_return_error_keeps_type_and_full_display_chain() {
    let (mut vm, cache, schema) = completed_return();
    vm.store_u64(vm.register(10), 2).unwrap();
    let gas = vm.remaining_gas();
    let context = "failed to decode contract debug call return value";
    let report = decode_return(&vm, &schema, context).unwrap_err();
    let typed = report
        .downcast_ref::<EntrypointReturnDecodeError>()
        .unwrap();
    assert!(matches!(
        typed,
        EntrypointReturnDecodeError::NonCanonicalBit {
            word_index: 0,
            role: "bool",
            value: 2,
        }
    ));
    assert_eq!(format!("{report:#}"), format!("{context}: {typed}"));
    assert_eq!(vm.remaining_gas(), gas);
    drop(vm);
    assert_eq!(cache.execution_budget().reserved_bytes(), 0);
}

#[test]
fn borrowed_trap_rendering_uses_exact_original_error_and_success_has_no_trap() {
    let mut vm = vm();
    let original = VMError::UnknownSyscall(0x7fff);
    let mut host = Host {
        change_mode: false,
        error: Some(original.clone()),
        calls: 0,
    };
    let error = run(&mut vm, &mut host).unwrap().unwrap_err();
    assert_eq!(error, original);
    let diagnostic = super::super::map_local_vm_diagnostic(vm.last_diagnostic().unwrap(), &error);
    assert_eq!(diagnostic.message, error.to_string());
    assert_eq!(diagnostic.syscall, Some(0x7fff));
    let (vm, _, _) = completed_return();
    assert!(
        vm.last_diagnostic().is_none(),
        "post-success return errors have no VM trap"
    );
}
