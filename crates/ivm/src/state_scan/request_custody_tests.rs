//! Scan input custody, refusal, and continuation lifetime regressions.

use super::*;
use iroha_allocation::AllocationBudget;

const POOL_BYTES: usize = 256 * 1024 * 1024;

fn fixture() -> (IVM, AllocationBudget) {
    let code = kotodama_lang::compiler::Compiler::new()
        .compile_source("seiyaku Scan { state StateMap<string, int> orders; view fn main() authorize(anyone) { () } }")
        .expect("compile admitted map");
    let pool = AllocationBudget::new(POOL_BYTES);
    let mut vm = IVM::try_new_with_memory_budget(u64::MAX, &pool).unwrap();
    vm.load_program(&code).unwrap();
    tests::arguments(&mut vm, "orders", None, 16);
    (vm, pool)
}

#[test]
fn request_refusals_retry_original_pool_and_retain_only_input_custody() {
    let (vm, pool) = fixture();
    // Host TLV reads have their own retained diagnostic backing. Warm that
    // exact path, then isolate request custody from read-log capacity growth.
    drop(StateScanRequest::decode(&vm, "instance-a").unwrap());
    vm.memory.clear_tracking();
    let baseline = pool.reserved_bytes();
    let input = vm.register(10);
    // Reject both the initial input owner and the later schema scratch owner.
    // Neither may leave a charge behind or publish a partially decoded request.
    for allowance in [0, 200_000] {
        vm.memory.clear_tracking();
        pool.set_limit_bytes(baseline + allowance);
        let error = match StateScanRequest::decode(&vm, "instance-a") {
            Ok(_) => panic!("request unexpectedly fit insufficient allocation budget"),
            Err(error) => error,
        };
        assert!(matches!(error, VMError::AllocationDeferred(_)), "{error:?}");
        assert_eq!(pool.reserved_bytes(), baseline);
        assert_eq!(vm.register(10), input);
        assert_eq!(vm.register(11), 0);
    }
    pool.set_limit_bytes(POOL_BYTES);
    vm.memory.clear_tracking();
    let request = StateScanRequest::decode(&vm, "instance-a").unwrap();
    assert_eq!(request.map.as_ref(), "orders");
    assert_eq!(request.instance, "instance-a");
    assert!(request.after.is_none());
    let retained = request._reservation.as_ref().unwrap().remaining_bytes();
    assert!(retained > 0);
    assert_eq!(
        pool.reserved_bytes(),
        baseline + retained,
        "schema scratch and decode context shells must already have released"
    );
    pool.set_limit_bytes(baseline);
    assert_eq!(pool.reserved_bytes(), baseline + retained);
    drop(request);
    assert_eq!(pool.reserved_bytes(), baseline);
    drop(vm);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn resumed_cursor_key_remains_funded_and_invalid_cursor_refunds_inputs() {
    let (mut vm, pool) = fixture();
    let first = StateScanRequest::decode(&vm, "instance-a").unwrap();
    let expected = tests::key(17);
    let cursor = first.cursor(expected.clone());
    let encoded = cursor.encode_frame().unwrap();
    drop(first);
    tests::arguments(&mut vm, "orders", Some(&encoded), 16);
    drop(StateScanRequest::decode(&vm, "instance-a").unwrap());
    vm.memory.clear_tracking();
    let baseline = pool.reserved_bytes();
    let inputs = (vm.register(10), vm.register(11));
    let request = StateScanRequest::decode(&vm, "instance-a").unwrap();
    assert_eq!(request.after.as_ref(), Some(&expected));
    let retained = request._reservation.as_ref().unwrap().remaining_bytes();
    assert_eq!(pool.reserved_bytes(), baseline + retained);
    drop(request);
    assert_eq!(pool.reserved_bytes(), baseline);
    vm.memory.clear_tracking();
    let error = match StateScanRequest::decode(&vm, "another-instance") {
        Ok(_) => panic!("cursor accepted a different instance"),
        Err(error) => error,
    };
    assert_eq!(error, VMError::NoritoInvalid);
    assert_eq!((vm.register(10), vm.register(11)), inputs);
    assert_eq!(pool.reserved_bytes(), baseline);
    drop(vm);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn input_decoder_preserves_local_allocator_failures_and_releases_context() {
    let pool = AllocationBudget::new(1024 * 1024);
    let limits = norito::canonical_decode_limits(64);
    for error in [
        norito::Error::AllocationFailed { bytes: 64 },
        norito::Error::NonCanonicalEncoding,
    ] {
        let expected = match error {
            norito::Error::AllocationFailed { .. } => unavailable(),
            _ => VMError::NoritoInvalid,
        };
        let mut owner = Some(
            pool.try_reserve_bytes(
                limits.max_total_allocated_bytes()
                    + norito::core::DecodeBudgetContext::allocation_layout().size(),
            )
            .unwrap(),
        );
        let result: Result<(), _> = decode_request_value(&mut owner, limits, || Err(error));
        assert_eq!(result.unwrap_err(), expected);
        assert_eq!(
            pool.reserved_bytes(),
            owner.as_ref().unwrap().remaining_bytes()
        );
        drop(owner);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn dispatched_local_refusal_preserves_inputs_and_does_not_refund_unmetered_work() {
    use crate::{CoreHost, host::IVMHost};
    struct RefusingHost {
        pool: AllocationBudget,
        core: CoreHost,
        entered: bool,
    }
    impl IVMHost for RefusingHost {
        fn as_any(&mut self) -> &mut dyn std::any::Any {
            self
        }
        fn prepare_syscall(&self, number: u32, vm: &IVM) -> Result<u64, VMError> {
            self.core.prepare_syscall(number, vm)
        }
        fn syscall(&mut self, number: u32, vm: &mut IVM) -> Result<u64, VMError> {
            self.entered = true;
            self.pool.set_limit_bytes(self.pool.reserved_bytes());
            let result = self.core.syscall(number, vm);
            self.pool.set_limit_bytes(POOL_BYTES);
            result
        }
    }
    let (mut vm, pool) = fixture();
    let inputs = (vm.register(10), vm.register(11), vm.register(12));
    let baseline = pool.reserved_bytes();
    let mut host = RefusingHost {
        pool: pool.clone(),
        core: CoreHost::new(),
        entered: false,
    };
    let error = vm
        .execute_syscall(&mut host, syscalls::SYSCALL_STATE_SCAN)
        .unwrap_err();
    assert!(
        host.entered,
        "exercise the request refusal after dispatch admission"
    );
    assert!(matches!(error, VMError::AllocationDeferred(_)), "{error:?}");
    assert_eq!(
        vm.remaining_gas(),
        0,
        "unmetered errors retain the full reserved quote"
    );
    assert_eq!((vm.register(10), vm.register(11), vm.register(12)), inputs);
    assert_eq!(pool.reserved_bytes(), baseline);
}
