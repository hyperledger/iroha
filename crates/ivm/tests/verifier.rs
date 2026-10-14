//! Retained diagnostic trace and execution behavior controls.
use crate::common;
use common::assemble_zk;
use ivm::{IVM, encoding, instruction, zk::check_diagnostic_trace};
#[test]
fn test_diagnostic_trace_check_passes() {
    // Program: ASSERT x1==0; HALT
    let assert_inst = encoding::wide::encode_rr(instruction::wide::zk::ASSERT, 0, 1, 0);
    let halt_inst = encoding::wide::encode_halt();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&assert_inst.to_le_bytes());
    bytes.extend_from_slice(&halt_inst.to_le_bytes());
    let prog = assemble_zk(&bytes, 8);
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(1, 0);
    vm.load_program(&prog).unwrap();
    vm.set_zk_trace_enabled(true);
    let res = vm.run();
    assert!(res.is_ok());
    let snapshot = common::diagnostic_snapshot(&vm);
    check_diagnostic_trace(&snapshot).unwrap();
}
#[test]
fn test_diagnostic_trace_check_rejects_failed_constraint() {
    // ASSERT on non-zero register should fail verification
    let assert_inst = encoding::wide::encode_rr(instruction::wide::zk::ASSERT, 0, 1, 0);
    let halt_inst = encoding::wide::encode_halt();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&assert_inst.to_le_bytes());
    bytes.extend_from_slice(&halt_inst.to_le_bytes());
    let prog = assemble_zk(&bytes, 8);
    let mut vm = IVM::new(u64::MAX);
    vm.set_register(1, 1); // will trigger assertion
    vm.load_program(&prog).unwrap();
    vm.set_zk_trace_enabled(true);
    let res = vm.run();
    assert!(res.is_err());
    let snapshot = common::diagnostic_snapshot(&vm);
    let check = check_diagnostic_trace(&snapshot);
    assert!(check.is_err());
}
