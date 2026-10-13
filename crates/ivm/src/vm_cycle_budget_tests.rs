//! Actual dispatch, nested-run, failure and reuse controls for shared VM cycles.

use super::*;
use std::{any::Any, num::NonZeroU64};

fn budget(limit: u64) -> VmCycleBudget {
    VmCycleBudget::new(NonZeroU64::new(limit).unwrap())
}
fn vm(words: &[u32]) -> IVM {
    let mut bytes = ProgramMetadata::default().encode();
    for word in words {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&bytes).unwrap();
    vm
}
fn add() -> u32 {
    crate::encoding::wide::encode_rr(instruction::wide::arithmetic::ADD, 4, 2, 3)
}
fn halt() -> u32 {
    crate::encoding::wide::encode_halt()
}

#[test]
fn actual_costly_opcodes_match_completed_counter_and_refuse_before_dispatch() {
    for (opcode, cost) in [
        (instruction::wide::arithmetic::ADD, 1),
        (instruction::wide::arithmetic::ISQRT, 6),
        (instruction::wide::arithmetic::DIV_CEIL, 12),
        (instruction::wide::arithmetic::GCD, 12),
        (instruction::wide::arithmetic::MEAN, 3),
    ] {
        let words = [crate::encoding::wide::encode_rr(opcode, 4, 2, 3), halt()];
        for limit in [cost + 1, cost] {
            let allowance = budget(limit);
            let mut runtime = vm(&words);
            runtime.set_register(2, 49);
            runtime.set_register(3, 7);
            let result =
                runtime.run_with_host_and_cycle_budget(&mut DefaultHost::new(), &allowance);
            assert_eq!(result.is_ok(), limit == cost + 1);
            assert_eq!(allowance.consumed(), runtime.get_cycle_count());
            assert_eq!(allowance.consumed(), limit);
            assert_eq!(allowance.remaining(), 0);
            assert_eq!(allowance.exhausted(), limit == cost);
        }
        if cost > 1 {
            let allowance = budget(cost - 1);
            let mut runtime = vm(&words);
            runtime.set_register(2, 49);
            runtime.set_register(3, 7);
            runtime.set_register(4, 99);
            let gas_before = runtime.remaining_gas();
            assert!(matches!(
                runtime.run_with_host_and_cycle_budget(&mut DefaultHost::new(), &allowance),
                Err(VMError::ExceededMaxCycles)
            ));
            assert_eq!(runtime.register(4), 99);
            assert_eq!(runtime.get_cycle_count(), 0);
            assert_eq!(allowance.consumed(), 0);
            assert_eq!(runtime.remaining_gas(), gas_before);
            assert!(allowance.exhausted());
        }
    }
}

#[test]
fn actual_runs_and_warm_template_reuse_share_one_allowance() {
    let allowance = budget(6);
    let mut runtime = vm(&[add(), halt()]);
    let template = runtime
        .try_runtime_template()
        .expect("runtime template allocation fits test host");
    for expected in [2, 4] {
        runtime.reset_from_runtime_template(&template).unwrap();
        runtime
            .run_with_host_and_cycle_budget(&mut DefaultHost::new(), &allowance)
            .unwrap();
        assert_eq!(allowance.consumed(), expected);
        assert!(runtime.active_cycle_budget.is_none());
    }
    vm(&[add(), halt()])
        .run_with_host_and_cycle_budget(&mut DefaultHost::new(), &allowance)
        .unwrap();
    assert_eq!(allowance.limit(), 6);
    assert_eq!(allowance.remaining(), 0);
    assert!(!allowance.exhausted());
    assert!(matches!(
        vm(&[halt()]).run_with_host_and_cycle_budget(&mut DefaultHost::new(), &allowance),
        Err(VMError::ExceededMaxCycles)
    ));
    assert_eq!(allowance.consumed(), 6);
    assert!(allowance.exhausted());
    // An independently owned ordinary run (the callback API) does not borrow this allowance.
    vm(&[add(), halt()])
        .run_with_host(&mut DefaultHost::new())
        .unwrap();
    assert_eq!(allowance.consumed(), 6);
}

#[test]
fn actual_trap_retains_prior_cycles_and_refunds_only_uncompleted_instruction() {
    let allowance = budget(20);
    let divide = crate::encoding::wide::encode_rr(instruction::wide::arithmetic::DIV_CEIL, 4, 2, 3);
    let mut runtime = vm(&[add(), divide, halt()]);
    runtime.set_register(2, 12);
    runtime.set_register(3, 0);
    assert!(
        runtime
            .run_with_host_and_cycle_budget(&mut DefaultHost::new(), &allowance)
            .is_err()
    );
    assert_eq!(runtime.get_cycle_count(), 1);
    assert_eq!(allowance.consumed(), 1);
    assert_eq!(allowance.remaining(), 19);
    assert!(!allowance.exhausted());
    vm(&[halt()])
        .run_with_host_and_cycle_budget(&mut DefaultHost::new(), &allowance)
        .unwrap();
    assert_eq!(allowance.consumed(), 2);
}

#[test]
fn actual_program_cycle_refusal_does_not_claim_shared_exhaustion() {
    let allowance = budget(10);
    let mut runtime = vm(&[add(), halt()]);
    runtime.set_max_cycles(1);
    assert!(matches!(
        runtime.run_with_host_and_cycle_budget(&mut DefaultHost::new(), &allowance),
        Err(VMError::ExceededMaxCycles)
    ));
    assert_eq!(allowance.consumed(), 1);
    assert!(!allowance.exhausted());
}

#[test]
fn actual_zk_padding_is_reserved_and_retained_on_padding_gas_failure() {
    for (limit, gas, success, cycles, refused) in [
        (8, 100, true, 8, false),
        (7, 100, false, 1, true),
        (8, 1, false, 8, false),
    ] {
        let allowance = budget(limit);
        let mut runtime = vm(&[halt()]);
        runtime
            .set_zk_mode(true)
            .expect("private lifecycle cleanup succeeds");
        runtime.set_max_cycles(8);
        runtime.set_gas_limit(gas);
        let result = runtime.run_with_host_and_cycle_budget(&mut DefaultHost::new(), &allowance);
        assert_eq!(result.is_ok(), success);
        assert_eq!(runtime.get_cycle_count(), cycles);
        assert_eq!(allowance.consumed(), cycles);
        assert_eq!(allowance.exhausted(), refused);
    }
}

// A canonical no-argument syscall passes real program admission before the
// test host uses its callback to exercise nested VM ownership.
const NEST: u32 = crate::syscalls::SYSCALL_SYSVAR_BLOCK_HEIGHT;
fn nested_words() -> [u32; 2] {
    [crate::encoding::wide::encode_syscallx(NEST), halt()]
}
struct NestedHost {
    depth: usize,
    swallow_and_exit: bool,
    panic_after_child: bool,
    retained: Option<IVM>,
}
impl IVMHost for NestedHost {
    fn prepare_syscall(&self, number: u32, _vm: &IVM) -> Result<u64, VMError> {
        assert_eq!(number, NEST);
        Ok(0)
    }
    fn allows_syscall(&self, policy: SyscallPolicy, number: u32) -> bool {
        number == NEST || crate::syscalls::is_syscall_allowed(policy, number)
    }
    fn syscall(&mut self, number: u32, parent: &mut IVM) -> Result<u64, VMError> {
        assert_eq!(number, NEST);
        self.retained = Some(parent.try_clone_snapshot()?);
        let mut child = if self.depth == 0 {
            vm(&nested_words())
        } else {
            vm(&[add(), halt()])
        };
        self.depth += 1;
        let result = child.run_with_host_and_parent_cycle_budget(self, parent);
        self.depth -= 1;
        if self.panic_after_child && self.depth == 0 {
            panic!("actual child completed before parent host unwinds");
        }
        if self.swallow_and_exit {
            parent.request_exit();
            return Ok(0);
        }
        result.map(|()| 0)
    }
    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}
fn host() -> NestedHost {
    NestedHost {
        depth: 0,
        swallow_and_exit: false,
        panic_after_child: false,
        retained: None,
    }
}

#[test]
fn actual_recursive_vm_runs_reserve_parent_cycles_and_share_refusal() {
    for (limit, success, consumed) in [(6, true, 6), (5, false, 5), (1, false, 0)] {
        let allowance = budget(limit);
        let mut runtime = vm(&nested_words());
        let result = runtime.run_with_host_and_cycle_budget(&mut host(), &allowance);
        assert_eq!(result.is_ok(), success);
        assert_eq!(allowance.consumed(), consumed);
        assert_eq!(allowance.exhausted(), !success);
        assert_eq!(allowance.remaining(), limit - consumed);
        assert!(runtime.active_cycle_budget.is_none());
    }
}

#[test]
fn swallowed_child_refusal_cannot_succeed_after_host_requests_immediate_exit() {
    let allowance = budget(1);
    let mut runtime = vm(&nested_words());
    let mut host = host();
    host.swallow_and_exit = true;
    assert!(matches!(
        runtime.run_with_host_and_cycle_budget(&mut host, &allowance),
        Err(VMError::ExceededMaxCycles)
    ));
    assert_eq!(runtime.get_cycle_count(), 1);
    assert_eq!(allowance.consumed(), 1);
    assert!(allowance.exhausted());
    assert!(runtime.active_cycle_budget.is_none());
}

#[test]
fn parent_unwind_keeps_completed_child_work_and_closes_retained_copies_on_owner_drop() {
    let allowance = budget(20);
    let mut runtime = vm(&nested_words());
    let mut host = host();
    host.panic_after_child = true;
    assert!(
        std::panic::catch_unwind(AssertUnwindSafe(
            || runtime.run_with_host_and_cycle_budget(&mut host, &allowance)
        ))
        .is_err()
    );
    assert_eq!(allowance.consumed(), 4);
    assert_eq!(allowance.remaining(), 16);
    assert!(!allowance.exhausted());
    assert!(runtime.active_cycle_budget.is_none());
    let mut retained = host.retained.take().unwrap();
    drop(allowance);
    retained
        .reset()
        .expect("private lifecycle cleanup succeeds");
    assert!(matches!(
        retained.run_with_host(&mut DefaultHost::new()),
        Err(VMError::HostUnavailable)
    ));
}

#[test]
fn retained_runtime_cannot_rebind_a_foreign_allowance_after_an_actual_nested_run() {
    let original = budget(20);
    let mut runtime = vm(&nested_words());
    let mut host = host();
    runtime
        .run_with_host_and_cycle_budget(&mut host, &original)
        .unwrap();
    let mut retained = host.retained.take().unwrap();
    retained
        .reset()
        .expect("private lifecycle cleanup succeeds");
    let foreign = budget(10);
    assert!(matches!(
        retained.run_with_host_and_cycle_budget(&mut DefaultHost::new(), &foreign),
        Err(VMError::HostUnavailable)
    ));
    assert!(!original.is_open());
    assert!(!foreign.is_open());
    assert!(!original.exhausted());
    assert!(!foreign.exhausted());
    assert_eq!(original.consumed(), 6);
    assert_eq!(foreign.consumed(), 0);
    assert!(matches!(
        vm(&[halt()]).run_with_host_and_cycle_budget(&mut DefaultHost::new(), &original),
        Err(VMError::HostUnavailable)
    ));
}
