use crate::common;
use common::{assemble, assemble_zk};
use ivm::{IVM, VMError, encoding, instruction};
const HALT: [u8; 4] = encoding::wide::encode_halt().to_le_bytes();
#[test]
fn test_out_of_gas() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(1, 1);
    vm.set_register(2, 2);
    let mut prog = Vec::new();
    prog.extend_from_slice(
        &encoding::wide::encode_rr(instruction::wide::arithmetic::ADD, 3, 1, 2).to_le_bytes(),
    );
    prog.extend_from_slice(&HALT);
    let prog = assemble(&prog);
    vm.load_program(&prog).unwrap();
    vm.set_gas_limit(0); // not enough for even the first instruction
    let res = vm.run();
    assert!(
        matches!(res, Err(VMError::OutOfGas)),
        "Expected OutOfGas error"
    );
}
#[test]
fn test_exact_gas_limit() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(1, 1);
    vm.set_register(2, 2);
    let mut prog = Vec::new();
    prog.extend_from_slice(
        &encoding::wide::encode_rr(instruction::wide::arithmetic::ADD, 3, 1, 2).to_le_bytes(),
    );
    prog.extend_from_slice(&HALT);
    let prog = assemble(&prog);
    vm.load_program(&prog).unwrap();
    vm.set_gas_limit(2); // enough for ADD and NOP padding if any
    vm.run().expect("VM should succeed with exact gas limit");
    assert_eq!(vm.register(3), 3);
}
#[test]
fn test_gas_accounting_multiple_ops() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(1, 1);
    vm.set_register(2, 2);
    let mut prog = Vec::new();
    prog.extend_from_slice(
        &encoding::wide::encode_rr(instruction::wide::arithmetic::ADD, 3, 1, 2).to_le_bytes(),
    );
    prog.extend_from_slice(
        &encoding::wide::encode_rr(instruction::wide::arithmetic::ADD, 3, 1, 2).to_le_bytes(),
    );
    prog.extend_from_slice(&HALT);
    let prog = assemble(&prog);
    vm.load_program(&prog).unwrap();
    vm.set_gas_limit(5);
    vm.run().expect("execution failed");
    assert_eq!(vm.remaining_gas(), 3);
}
#[test]
fn test_getgas_instruction() {
    let mut vm = IVM::new(u64::MAX);
    let mut prog = Vec::new();
    prog.extend_from_slice(
        &encoding::wide::encode_rr(instruction::wide::system::GETGAS, 1, 0, 0).to_le_bytes(),
    );
    prog.extend_from_slice(&HALT);
    let prog = assemble(&prog);
    vm.load_program(&prog).unwrap();
    vm.set_gas_limit(10);
    vm.run().expect("execution failed");
    assert_eq!(vm.register(1), 10);
    assert_eq!(vm.remaining_gas(), 10); // HALT no longer consumes gas
}
#[test]
fn test_getgas_progress() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(1, 1);
    vm.set_register(2, 2);
    let mut prog = Vec::new();
    // add r3 = r1 + r2
    prog.extend_from_slice(
        &encoding::wide::encode_rr(instruction::wide::arithmetic::ADD, 3, 1, 2).to_le_bytes(),
    );
    // GETGAS r4
    prog.extend_from_slice(
        &encoding::wide::encode_rr(instruction::wide::system::GETGAS, 4, 0, 0).to_le_bytes(),
    );
    // add r5 = r1 + r2
    prog.extend_from_slice(
        &encoding::wide::encode_rr(instruction::wide::arithmetic::ADD, 5, 1, 2).to_le_bytes(),
    );
    // GETGAS r6
    prog.extend_from_slice(
        &encoding::wide::encode_rr(instruction::wide::system::GETGAS, 6, 0, 0).to_le_bytes(),
    );
    prog.extend_from_slice(&HALT);
    let prog = assemble(&prog);
    vm.load_program(&prog).unwrap();
    vm.set_gas_limit(100);
    vm.run().expect("execution failed");
    assert_eq!(vm.register(4), 99);
    assert_eq!(vm.register(6), 98);
    assert_eq!(vm.remaining_gas(), 98);
}
#[test]
fn test_getgas_zero_remaining() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(1, 1);
    vm.set_register(2, 2);
    let mut prog = Vec::new();
    prog.extend_from_slice(
        &encoding::wide::encode_rr(instruction::wide::arithmetic::ADD, 3, 1, 2).to_le_bytes(),
    );
    prog.extend_from_slice(
        &encoding::wide::encode_rr(instruction::wide::arithmetic::ADD, 3, 1, 2).to_le_bytes(),
    );
    prog.extend_from_slice(
        &encoding::wide::encode_rr(instruction::wide::system::GETGAS, 3, 0, 0).to_le_bytes(),
    );
    prog.extend_from_slice(&HALT);
    let prog = assemble(&prog);
    vm.load_program(&prog).unwrap();
    vm.set_gas_limit(2);
    vm.run().expect("execution failed");
    assert_eq!(vm.register(3), 0);
    assert_eq!(vm.remaining_gas(), 0);
}
struct ExtraCostHost;
impl ivm::IVMHost for ExtraCostHost {
    fn prepare_syscall(&self, number: u32, _vm: &IVM) -> Result<u64, VMError> {
        assert_eq!(number, 1);
        Ok(2)
    }
    fn syscall(&mut self, number: u32, vm: &mut IVM) -> Result<u64, VMError> {
        assert_eq!(number, 1);
        let a0 = vm.register(10);
        vm.set_register(10, a0.wrapping_add(1));
        Ok(2) // additional gas cost
    }
    fn as_any(&mut self) -> &mut dyn std::any::Any {
        self
    }
}
struct MeteredErrorHost;
impl ivm::IVMHost for MeteredErrorHost {
    fn prepare_syscall(&self, number: u32, _vm: &IVM) -> Result<u64, VMError> {
        assert_eq!(number, ivm::syscalls::SYSCALL_EXIT);
        Ok(7)
    }
    fn syscall(&mut self, number: u32, _vm: &mut IVM) -> Result<u64, VMError> {
        assert_eq!(number, ivm::syscalls::SYSCALL_EXIT);
        Err(VMError::metered(7, VMError::PermissionDenied))
    }
    fn as_any(&mut self) -> &mut dyn std::any::Any {
        self
    }
}
struct UnmeteredErrorHost {
    calls: usize,
}
impl ivm::IVMHost for UnmeteredErrorHost {
    fn prepare_syscall(&self, number: u32, _vm: &IVM) -> Result<u64, VMError> {
        assert_eq!(number, 1);
        Ok(7)
    }
    fn syscall(&mut self, number: u32, _vm: &mut IVM) -> Result<u64, VMError> {
        assert_eq!(number, 1);
        self.calls += 1;
        Err(VMError::PermissionDenied)
    }
    fn as_any(&mut self) -> &mut dyn std::any::Any {
        self
    }
}
struct SideEffectHost {
    calls: usize,
}
impl ivm::IVMHost for SideEffectHost {
    fn prepare_syscall(&self, number: u32, _vm: &IVM) -> Result<u64, VMError> {
        assert_eq!(number, 1);
        Ok(2)
    }
    fn syscall(&mut self, number: u32, _vm: &mut IVM) -> Result<u64, VMError> {
        assert_eq!(number, 1);
        self.calls += 1;
        Ok(2)
    }
    fn as_any(&mut self) -> &mut dyn std::any::Any {
        self
    }
}
struct RefundingHost {
    observed_remaining: u64,
}
impl ivm::IVMHost for RefundingHost {
    fn prepare_syscall(&self, number: u32, _vm: &IVM) -> Result<u64, VMError> {
        assert_eq!(number, 1);
        Ok(7)
    }
    fn syscall(&mut self, number: u32, vm: &mut IVM) -> Result<u64, VMError> {
        assert_eq!(number, 1);
        self.observed_remaining = vm.remaining_gas();
        Ok(2)
    }
    fn as_any(&mut self) -> &mut dyn std::any::Any {
        self
    }
}
struct UnderquotingHost;
impl ivm::IVMHost for UnderquotingHost {
    fn prepare_syscall(&self, number: u32, _vm: &IVM) -> Result<u64, VMError> {
        assert_eq!(number, 1);
        Ok(1)
    }
    fn syscall(&mut self, number: u32, _vm: &mut IVM) -> Result<u64, VMError> {
        assert_eq!(number, 1);
        Ok(2)
    }
    fn as_any(&mut self) -> &mut dyn std::any::Any {
        self
    }
}
struct CompactProofHost {
    calls: usize,
}
impl ivm::IVMHost for CompactProofHost {
    fn prepare_syscall(&self, number: u32, _vm: &IVM) -> Result<u64, VMError> {
        assert!(matches!(
            number,
            ivm::syscalls::SYSCALL_GET_MERKLE_COMPACT
                | ivm::syscalls::SYSCALL_GET_REGISTER_MERKLE_COMPACT
        ));
        Ok(2)
    }
    fn syscall(&mut self, _number: u32, _vm: &mut IVM) -> Result<u64, VMError> {
        self.calls += 1;
        Ok(2)
    }
    fn as_any(&mut self) -> &mut dyn std::any::Any {
        self
    }
}
#[test]
fn downcast_extra_cost_host() {
    let mut host: Box<dyn ivm::IVMHost> = Box::new(ExtraCostHost);
    assert!(host.as_any().downcast_mut::<ExtraCostHost>().is_some());
}
#[test]
fn test_syscall_additional_gas() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(ExtraCostHost);
    vm.set_register(10, 5);
    let mut prog = Vec::new();
    prog.extend_from_slice(
        &encoding::wide::encode_sys(instruction::wide::system::SCALL, 1).to_le_bytes(),
    );
    prog.extend_from_slice(&HALT);
    let prog = assemble(&prog);
    vm.load_program(&prog).unwrap();
    vm.set_gas_limit(7); // 5 base + 2 extra
    vm.run().expect("syscall should succeed");
    assert_eq!(vm.register(10), 6);
    assert_eq!(vm.remaining_gas(), 0);
}
#[test]
fn syscall_quote_is_debited_before_host_side_effects() {
    let mut vm = IVM::new(u64::MAX);
    let mut host = SideEffectHost { calls: 0 };
    let mut prog = Vec::new();
    prog.extend_from_slice(
        &encoding::wide::encode_sys(instruction::wide::system::SCALL, 1).to_le_bytes(),
    );
    prog.extend_from_slice(&HALT);
    let prog = assemble(&prog);
    vm.load_program(&prog).unwrap();
    vm.set_gas_limit(6); // five for SCALL, but only one of the quoted two remains
    let result = vm.run_with_host(&mut host);
    assert!(matches!(result, Err(VMError::OutOfGas)));
    assert_eq!(
        host.calls, 0,
        "host must not run when its quote cannot be paid"
    );
}
#[test]
fn compact_proof_helpers_debit_quotes_and_restore_the_host_on_failure() {
    let mut vm = IVM::new(1);
    vm.set_host(CompactProofHost { calls: 0 });
    assert!(matches!(
        vm.get_memory_compact_bundle(0, None),
        Err(VMError::OutOfGas)
    ));
    assert!(matches!(
        vm.get_registers_compact_bundle(0, None),
        Err(VMError::OutOfGas)
    ));
    let host = vm
        .host_mut_any()
        .expect("host must be restored after metering failure")
        .downcast_mut::<CompactProofHost>()
        .expect("compact proof host");
    assert_eq!(
        host.calls, 0,
        "unaffordable helper calls must never reach the host"
    );
}
#[test]
fn syscall_refunds_unused_quote_and_preserves_host_budget_view() {
    let mut vm = IVM::new(u64::MAX);
    let mut host = RefundingHost {
        observed_remaining: 0,
    };
    let mut prog = Vec::new();
    prog.extend_from_slice(
        &encoding::wide::encode_sys(instruction::wide::system::SCALL, 1).to_le_bytes(),
    );
    prog.extend_from_slice(&HALT);
    let prog = assemble(&prog);
    vm.load_program(&prog).unwrap();
    vm.set_gas_limit(12); // five for SCALL plus the seven-gas quote
    vm.run_with_host(&mut host).expect("syscall should succeed");
    assert_eq!(host.observed_remaining, 7);
    assert_eq!(vm.remaining_gas(), 5); // only the two-gas actual cost remains charged
}
#[test]
fn syscall_rejects_a_host_cost_above_its_quote() {
    let mut vm = IVM::new(u64::MAX);
    let mut host = UnderquotingHost;
    let mut prog = Vec::new();
    prog.extend_from_slice(
        &encoding::wide::encode_sys(instruction::wide::system::SCALL, 1).to_le_bytes(),
    );
    prog.extend_from_slice(&HALT);
    let prog = assemble(&prog);
    vm.load_program(&prog).unwrap();
    vm.set_gas_limit(6);
    let result = vm.run_with_host(&mut host);
    assert!(matches!(
        result,
        Err(VMError::SyscallGasQuoteExceeded {
            quoted: 1,
            actual: 2
        })
    ));
    assert_eq!(vm.remaining_gas(), 0);
    assert_eq!(
        result.unwrap_err().execution_deferral(),
        Some(ivm::error::ExecutionDeferral::LocalInvariantViolation)
    );
    assert!(
        vm.last_diagnostic().is_none(),
        "a host quote violation is a local refusal, not a guest semantic trap"
    );
}
#[test]
fn metered_syscall_error_debits_gas_and_preserves_error() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(MeteredErrorHost);
    let mut prog = Vec::new();
    prog.extend_from_slice(
        &encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            ivm::syscalls::SYSCALL_EXIT as u8,
        )
        .to_le_bytes(),
    );
    prog.extend_from_slice(&HALT);
    let prog = assemble(&prog);
    vm.load_program(&prog).unwrap();
    vm.set_gas_limit(20);
    let res = vm.run();
    assert!(matches!(res, Err(VMError::PermissionDenied)));
    assert_eq!(vm.remaining_gas(), 8);
}
#[test]
fn metered_syscall_error_returns_out_of_gas_when_debit_cannot_be_paid() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(MeteredErrorHost);
    let mut prog = Vec::new();
    prog.extend_from_slice(
        &encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            ivm::syscalls::SYSCALL_EXIT as u8,
        )
        .to_le_bytes(),
    );
    prog.extend_from_slice(&HALT);
    let prog = assemble(&prog);
    vm.load_program(&prog).unwrap();
    vm.set_gas_limit(10);
    let res = vm.run();
    assert!(matches!(res, Err(VMError::OutOfGas)));
    assert_eq!(vm.remaining_gas(), 5);
}
#[test]
fn unmetered_syscall_error_consumes_the_fail_closed_quote() {
    let mut vm = IVM::new(u64::MAX);
    let mut host = UnmeteredErrorHost { calls: 0 };
    let mut prog = Vec::new();
    prog.extend_from_slice(
        &encoding::wide::encode_sys(instruction::wide::system::SCALL, 1).to_le_bytes(),
    );
    prog.extend_from_slice(&HALT);
    let prog = assemble(&prog);
    vm.load_program(&prog).unwrap();
    vm.set_gas_limit(20);
    let result = vm.run_with_host(&mut host);
    assert!(matches!(result, Err(VMError::PermissionDenied)));
    assert_eq!(host.calls, 1, "the host executes only after quote debit");
    assert_eq!(
        vm.remaining_gas(),
        8,
        "an unmetered failure must not refund potentially expensive host work"
    );
}
#[test]
fn test_zk_padding_consumes_gas() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_max_cycles(5);
    let halt_prog: [u8; 4] = HALT;
    let prog = assemble_zk(&halt_prog, 5);
    vm.load_program(&prog).unwrap();
    vm.set_gas_limit(10);
    vm.run().expect("execution failed");
    // One HALT (0 gas) plus four padding cycles at cost 1 each
    assert_eq!(vm.remaining_gas(), 6);
}
#[test]
fn test_zk_padding_out_of_gas() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_max_cycles(5);
    let halt_prog: [u8; 4] = HALT;
    let prog = assemble_zk(&halt_prog, 5);
    vm.load_program(&prog).unwrap();
    vm.set_gas_limit(3); // less than 4 padding cycles
    let res = vm.run();
    assert!(matches!(res, Err(VMError::OutOfGas)));
    // Padding attempts set the cycle count to MAX_CYCLES even on failure
    assert_eq!(vm.get_cycle_count(), 5);
}
