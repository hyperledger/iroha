use crate::common;
use common::{assemble, assemble_zk};
use ivm::{IVM, VMError, encoding, zk::MAX_CYCLES};
#[test]
fn test_zk_mode_padding_and_assert() {
    // Program that triggers an assertion failure via the ZK ASSERT instruction.
    let assert_instr = encoding::wide::encode_rr(ivm::instruction::wide::zk::ASSERT, 0, 1, 0);
    let halt = encoding::wide::encode_halt().to_le_bytes();
    let mut assert_prog = Vec::with_capacity(8);
    assert_prog.extend_from_slice(&assert_instr.to_le_bytes());
    assert_prog.extend_from_slice(&halt);
    // Case 1: Normal mode (zk_mode = false) -> ZK op is rejected immediately.
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(1, 1);
    let prog = assemble(&assert_prog);
    vm.load_program(&prog).unwrap();
    let res = vm.run();
    assert!(
        matches!(res, Err(VMError::ZkExtensionDisabled)),
        "ZK ASSERT should be gated by header mode bit"
    );
    // Execution is rejected before the instruction is applied.
    assert_eq!(vm.get_cycle_count(), 0);
    // Case 2: ZK mode (zk_mode = true) -> should pad to MAX_CYCLES and then error
    let mut vm2 = IVM::new(u64::MAX);
    vm2.set_register(1, 1);
    let prog = assemble_zk(&assert_prog, MAX_CYCLES);
    vm2.load_program(&prog).unwrap();
    let res2 = vm2.run();
    assert!(
        matches!(res2, Err(VMError::AssertionFailed)),
        "Assert should still produce error in ZK mode"
    );
    // Execution should be padded to MAX_CYCLES cycles
    assert_eq!(vm2.get_cycle_count(), MAX_CYCLES);
    // Case 3: ZK mode with no assertion (normal halt) -> should still pad cycles and return Ok
    let mut vm3 = IVM::new(u64::MAX);
    let halt_prog: [u8; 4] = encoding::wide::encode_halt().to_le_bytes();
    let prog = assemble_zk(&halt_prog, MAX_CYCLES);
    vm3.load_program(&prog).unwrap();
    let res3 = vm3.run();
    assert!(res3.is_ok(), "Normal halt should succeed in ZK mode");
    assert_eq!(
        vm3.get_cycle_count(),
        MAX_CYCLES,
        "Cycles should be padded to MAX_CYCLES on normal halt in ZK mode"
    );
}
#[test]
fn test_exceed_max_cycles_error() {
    // Infinite loop using JMP with zero offset
    let prog: [u8; 4] =
        encoding::wide::encode_offset24(ivm::instruction::wide::control::JMP, 0).to_le_bytes();
    let mut vm = IVM::new(u64::MAX);
    vm.set_max_cycles(10);
    let prog = assemble_zk(&prog, 10);
    vm.load_program(&prog).unwrap();
    // Provide ample gas for the configured cycle limit and any padding
    vm.set_gas_limit(MAX_CYCLES + 10);
    let res = vm.run();
    assert!(matches!(res, Err(VMError::ExceededMaxCycles)));
    assert_eq!(vm.get_cycle_count(), 10);
}
#[test]
fn test_assert_continues_execution_in_zk_mode() {
    // Program: ASSERT r1; ADDI r2,r2,1; HALT
    let assert_inst = encoding::wide::encode_rr(ivm::instruction::wide::zk::ASSERT, 0, 1, 0);
    let addi_inst = encoding::wide::encode_ri(ivm::instruction::wide::arithmetic::ADDI, 2, 2, 1);
    let halt_inst = encoding::wide::encode_halt();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&assert_inst.to_le_bytes());
    bytes.extend_from_slice(&addi_inst.to_le_bytes());
    bytes.extend_from_slice(&halt_inst.to_le_bytes());
    // Normal mode: ZK ASSERT is rejected, so ADDI does not execute.
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(1, 1);
    vm.set_register(2, 0);
    let prog = assemble(&bytes);
    vm.load_program(&prog).unwrap();
    let res = vm.run();
    assert!(matches!(res, Err(VMError::ZkExtensionDisabled)));
    assert_eq!(
        vm.register(2),
        0,
        "addi executed unexpectedly when ZK mode bit is unset"
    );
    // ZK mode: execution continues so ADDI runs
    let mut vm2 = IVM::new(u64::MAX);
    vm2.set_register(1, 1);
    vm2.set_register(2, 0);
    let prog = assemble_zk(&bytes, 10);
    vm2.load_program(&prog).unwrap();
    let res2 = vm2.run();
    assert!(matches!(res2, Err(VMError::AssertionFailed)));
    assert_eq!(vm2.register(2), 1, "addi should execute in zk mode");
    assert_eq!(vm2.get_cycle_count(), 10);
}
#[test]
fn test_zero_max_cycles_means_no_padding() {
    // Program header sets max_cycles=0 which disables ZK padding.
    let halt_prog: [u8; 4] = encoding::wide::encode_halt().to_le_bytes();
    let prog = assemble(&halt_prog);
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&prog).unwrap();
    vm.set_gas_limit(10);
    vm.run().expect("execution failed");
    // Without a cycle limit there should be no padding.
    assert_eq!(vm.get_cycle_count(), 1);
}
#[test]
fn test_program_exceeding_old_cycle_limit() {
    // Loop for >65k cycles but <MAX_CYCLES to confirm higher limit works.
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(1, 0);
    let iterations: u64 = 35_000; // ~70k cycles with two instructions per loop
    vm.set_register(2, iterations);
    let addi =
        encoding::wide::encode_ri(ivm::instruction::wide::arithmetic::ADDI, 1, 1, 1).to_le_bytes();
    let blt =
        encoding::wide::encode_branch(ivm::instruction::wide::control::BLT, 1, 2, -1).to_le_bytes();
    let mut code = Vec::new();
    code.extend_from_slice(&addi);
    code.extend_from_slice(&blt);
    code.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let prog = assemble_zk(&code, MAX_CYCLES);
    vm.load_program(&prog).unwrap();
    vm.set_gas_limit(MAX_CYCLES + 10);
    vm.run().expect("execution failed");
    assert_eq!(vm.register(1), iterations);
    assert_eq!(vm.get_cycle_count(), MAX_CYCLES);
}
