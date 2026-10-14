//! Retained diagnostic trace and execution behavior controls.
use crate::common;
use common::assemble_zk;
use ivm::{IVM, encoding};
#[test]
fn zk_padding_extends_trace_to_max_cycles() {
    // Program: HALT
    let halt_inst = encoding::wide::encode_halt();
    let mut code = Vec::new();
    code.extend_from_slice(&halt_inst.to_le_bytes());
    // Set max_cycles to 8 to force padding after HALT
    let prog = assemble_zk(&code, 8);
    let start_gas = 1_000;
    let mut vm = IVM::new(start_gas);
    vm.load_program(&prog).unwrap();
    vm.set_zk_trace_enabled(true);
    vm.run().unwrap();
    let snapshot = common::diagnostic_snapshot(&vm);
    let trace = snapshot.states();
    assert_eq!(
        trace.len() as u64,
        vm.get_cycle_count(),
        "trace must be padded to max_cycles"
    );
    assert_eq!(
        vm.step_log().len() as u64,
        vm.get_cycle_count(),
        "step log must align with trace length"
    );
    // Padded cycles consume gas as NOPs (1 each); HALT itself is free.
    let gas_used = start_gas - vm.remaining_gas();
    let padded_cycles = vm.get_cycle_count().saturating_sub(1);
    assert!(
        gas_used >= padded_cycles,
        "expected at least {padded_cycles} units of gas used, got {gas_used}"
    );
}
#[test]
fn disabling_zk_trace_keeps_zk_semantics_without_formal_logs() {
    let assert_zero = encoding::wide::encode_rr(ivm::instruction::wide::zk::ASSERT, 0, 0, 0);
    let halt = encoding::wide::encode_halt();
    let mut code = Vec::new();
    code.extend_from_slice(&assert_zero.to_le_bytes());
    code.extend_from_slice(&halt.to_le_bytes());
    let prog = assemble_zk(&code, 32);
    let mut vm = IVM::new(1_000);
    vm.load_program(&prog).unwrap();
    assert!(vm.zk_mode_enabled());
    vm.set_zk_trace_enabled(false);
    vm.run().unwrap();
    assert!(vm.zk_mode_enabled());
    assert!(!vm.zk_trace_enabled());
    assert_eq!(vm.get_cycle_count(), 32);
    assert!(common::diagnostic_snapshot(&vm).states().is_empty());
    assert!(vm.step_log().is_empty());
    assert!(vm.memory_log().is_empty());
    assert!(common::diagnostic_snapshot(&vm).register_event_count() == 0);
    assert!(vm.constraints().is_empty());
}
