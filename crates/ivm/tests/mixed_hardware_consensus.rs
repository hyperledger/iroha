//! Consensus surface must remain stable across mixed hardware configurations.
use crate::common;
use common::assemble_with_mode;
use ivm::{ExecutionSummary, IVM, encoding, instruction, runtime};
#[derive(Debug, PartialEq, Eq)]
struct RunOutcome {
    register_value: u64,
    gas_used: u64,
    execution_summary: ExecutionSummary,
}
fn build_add_program() -> Vec<u8> {
    let mut code = Vec::new();
    let mut push = |word: u32| code.extend_from_slice(&word.to_le_bytes());
    // r5 = r1 + r2
    push(encoding::wide::encode_rr(
        instruction::wide::arithmetic::ADD,
        5,
        1,
        2,
    ));
    push(encoding::wide::encode_halt());
    assemble_with_mode(&code, 0)
}
fn run_with(
    policy: runtime::AccelerationPolicy,
    caps: runtime::HardwareCapabilities,
) -> RunOutcome {
    let gas_limit = 10_000;
    let mut vm = IVM::new(gas_limit);
    vm.set_acceleration_policy(policy);
    vm.set_hardware_capabilities(caps);
    vm.set_register(1, 123);
    vm.set_register(2, 456);
    let prog = build_add_program();
    vm.load_program(&prog).expect("load program");
    vm.run().expect("vm run");
    RunOutcome {
        register_value: vm.register(5),
        gas_used: gas_limit.saturating_sub(vm.remaining_gas()),
        execution_summary: vm.execution_summary(),
    }
}
#[test]
fn consensus_across_mixed_hardware_configs() {
    // Simulate a node with all accelerators enabled vs. a deterministic fallback node.
    let hw_enabled = run_with(
        runtime::AccelerationPolicy::adaptive(),
        runtime::HardwareCapabilities::new(true, true),
    );
    let hw_disabled = run_with(
        runtime::AccelerationPolicy::deterministic(),
        runtime::HardwareCapabilities::none(),
    );
    // Results must not diverge across hardware configurations.
    assert_eq!(hw_enabled, hw_disabled);
    assert_eq!(hw_enabled.register_value, 579);
    assert_eq!(hw_enabled.gas_used, hw_enabled.execution_summary.gas_used);
}
