//! Physical allocation census across actual native failure and diagnostic capture.

use super::{ObserveLog, SERIAL, observe_log_requests, stop_log_requests};
use iroha_allocation::AllocationBudget;
use ivm::{
    IVM, VMError, VmTrapKind,
    encoding::wide::{encode_halt, encode_syscallx},
    host::IVMHost,
};
use std::any::Any;

struct ExhaustAtTrap {
    original: AllocationBudget,
    error: Option<VMError>,
}
impl IVMHost for ExhaustAtTrap {
    fn prepare_syscall(&self, _: u32, _: &IVM) -> Result<u64, VMError> {
        Ok(0)
    }
    fn syscall(&mut self, _: u32, _: &mut IVM) -> Result<u64, VMError> {
        self.original.set_limit_bytes(0);
        // The real interpreter has completed its public instruction admission.
        // Observe the trap unwinding and capture, not unrelated VM construction.
        observe_log_requests();
        Err(self.error.take().unwrap())
    }
    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

#[test]
fn actual_trap_and_local_refusal_capture_make_no_heap_request_at_exhausted_original_pool() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for local in [false, true] {
        let original = AllocationBudget::new(128 * 1024 * 1024);
        let mut vm = IVM::try_new_with_memory_budget(100, &original).unwrap();
        let code: Vec<_> = [encode_syscallx(ivm::syscalls::SYSCALL_ABORT), encode_halt()]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        vm.load_code(&code).unwrap();
        original.set_limit_bytes(original.reserved_bytes());
        let refusal = original.try_reserve_bytes(1).unwrap_err();
        original.set_limit_bytes(128 * 1024 * 1024);
        let expected = if local {
            VMError::AllocationDeferred(refusal.clone())
        } else {
            VMError::UnknownSyscall(0x7fff)
        };
        let mut host = ExhaustAtTrap {
            original: original.clone(),
            error: Some(expected),
        };
        let _observe = ObserveLog;
        let result = vm.run_with_host(&mut host);
        let requests = stop_log_requests();
        match result {
            Err(VMError::AllocationDeferred(actual)) if local => assert_eq!(actual, refusal),
            Err(VMError::UnknownSyscall(0x7fff)) if !local => {}
            other => panic!("actual trap changed: {other:?}"),
        }
        assert_eq!(requests, 0, "trap capture and local unwind cannot allocate");
        if local {
            assert!(vm.last_diagnostic().is_none());
        } else {
            let diagnostic = vm.last_diagnostic().unwrap();
            assert_eq!(diagnostic.trap_kind, VmTrapKind::UnknownSyscall);
            assert_eq!(diagnostic.context.syscall, Some(0x7fff));
            assert_eq!(diagnostic.budget.gas_remaining, vm.remaining_gas());
        }
        let gas = vm.remaining_gas();
        observe_log_requests();
        let refusal = vm.run_with_host(&mut host);
        let requests = stop_log_requests();
        assert!(matches!(refusal, Err(VMError::AllocationDeferred(_))));
        assert_eq!(
            requests, 0,
            "local preflight refusal cannot allocate a diagnostic"
        );
        assert_eq!(vm.remaining_gas(), gas);
        assert!(
            vm.last_diagnostic().is_none(),
            "early refusal clears the preceding trap"
        );
        drop(vm);
        assert_eq!(original.reserved_bytes(), 0);
    }
}
