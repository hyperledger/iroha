//! Cycle-root admission before ordinary instruction and padding effects.

use super::*;
use crate::{
    ProgramMetadata,
    encoding::wide::{encode_halt, encode_ri, encode_rr},
    host::DefaultHost,
    instruction::wide::arithmetic,
    ivm::VmCycleBudget,
    zk,
};
use iroha_allocation::{AllocationBudget, AllocationRefusal};
use std::{mem::size_of, num::NonZeroU64};

const LIMIT: usize = 128 * 1024 * 1024;
const GAS: u64 = 10_000;

fn program(words: &[u32], max_cycles: u64) -> Vec<u8> {
    let metadata = ProgramMetadata {
        mode: crate::ivm_mode::ZK,
        max_cycles,
        ..ProgramMetadata::default()
    };
    let mut image = metadata.encode();
    image.extend(words.iter().flat_map(|word| word.to_le_bytes()));
    image
}
fn loaded(original: Option<&AllocationBudget>, words: &[u32], max_cycles: u64) -> IVM {
    let mut vm = original
        .map_or_else(
            || IVM::try_new(GAS),
            |budget| IVM::try_new_with_memory_budget(GAS, budget),
        )
        .unwrap();
    vm.load_program(&program(words, max_cycles)).unwrap();
    vm.set_zk_trace_enabled(true);
    vm
}
// Query the canonical standalone owner so pressure assertions use its exact
// public row/change layouts, not a guessed tuple or allocator capacity.
fn delta_bytes(cycles: usize) -> usize {
    let mut delta = zk::DeltaTraceLog::new(None);
    delta.prepare_batch(cycles, 256, 0, None).unwrap();
    delta.allocated_bytes().unwrap()
}
fn allowance(cycles: u64) -> VmCycleBudget {
    VmCycleBudget::new(NonZeroU64::new(cycles).unwrap())
}

#[test]
fn refused_first_root_backing_preserves_instruction_gas_state_and_shared_allowance() {
    let original = AllocationBudget::new(LIMIT);
    let words = [encode_ri(arithmetic::ADDI, 7, 7, 1), encode_halt()];
    let mut vm = loaded(Some(&original), &words, 2);
    vm.registers.set(7, 41);
    vm.preload_input(0, &[1, 2, 3, 4]).unwrap();
    let input_cursor = vm.input_bump_next;
    let pc = vm.pc;
    let previous_logger = vm.proof_register_log_handle().unwrap();
    let baseline = original.reserved_bytes();
    let shell = zk::SharedRegLog::allocation_layout().size();
    let rows = 4 * size_of::<zk::StepEntry>();
    // The previous shell is genuinely borrowed: the next invocation needs its
    // replacement plus a complete root buffer, one byte beyond this limit.
    original.set_limit_bytes(baseline + shell + rows - 1);
    let cycles = allowance(2);
    assert!(matches!(
        vm.run_with_host_and_cycle_budget(&mut DefaultHost::default(), &cycles),
        Err(VMError::AllocationDeferred(AllocationRefusal::Capacity { requested_bytes, .. }))
        if requested_bytes == rows
    ));
    assert_eq!(vm.pc, pc);
    assert_eq!(vm.cycles, 0);
    assert_eq!(vm.gas_remaining, GAS);
    assert_eq!(vm.register(7), 41);
    assert_eq!(vm.input_bump_next, input_cursor);
    assert_eq!(
        vm.memory
            .inspect_region(crate::Memory::INPUT_START, 4)
            .unwrap(),
        &[1, 2, 3, 4]
    );
    assert!(vm.step_log().is_empty());
    assert_eq!(cycles.consumed(), 0);
    assert_eq!(cycles.remaining(), 2);
    assert_eq!(original.reserved_bytes(), baseline + shell);
    let event_rows = 4 * size_of::<zk::RegEvent>();
    original.set_limit_bytes(baseline + shell + rows + event_rows + delta_bytes(2));
    vm.run_with_host_and_cycle_budget(&mut DefaultHost::default(), &cycles)
        .unwrap();
    assert_eq!(vm.register(7), 42);
    assert_eq!(vm.step_log().len(), 2);
    assert_eq!(cycles.consumed(), 2);
    assert_eq!(
        original.reserved_bytes(),
        baseline + shell + rows + event_rows + delta_bytes(2)
    );
    drop(vm);
    assert_eq!(original.reserved_bytes(), shell);
    drop(previous_logger);
    assert_eq!(original.reserved_bytes(), 0);
}

#[test]
fn twelve_cycle_instruction_admits_all_rows_before_overshooting_one_cycle_limit() {
    for opcode in [arithmetic::DIV_CEIL, arithmetic::GCD] {
        let original = AllocationBudget::new(LIMIT);
        let words = [encode_rr(opcode, 7, 5, 6), encode_halt()];
        let mut vm = loaded(Some(&original), &words, 1);
        vm.registers.set(5, 19);
        vm.registers.set(6, 3);
        let baseline = original.reserved_bytes();
        let start = vm.pc;
        let cycles = allowance(12);
        assert!(matches!(
            vm.run_with_host_and_cycle_budget(&mut DefaultHost::default(), &cycles),
            Err(VMError::ExceededMaxCycles)
        ));
        assert_eq!(vm.pc, start + 4);
        assert_eq!(vm.cycles, 12);
        assert_eq!(cycles.consumed(), 12);
        assert_eq!(vm.step_log().len(), 12);
        assert!(vm.step_log().iter().all(|row| row.pc == start + 4));
        assert_eq!(
            original.reserved_bytes(),
            baseline
                + 12 * size_of::<zk::StepEntry>()
                + 4 * size_of::<zk::RegEvent>()
                + delta_bytes(12)
        );
        assert_eq!(
            vm.register(7),
            if opcode == arithmetic::DIV_CEIL { 7 } else { 1 }
        );
        drop(vm);
        assert_eq!(original.reserved_bytes(), 0);
    }
}

#[test]
fn padding_refusal_precedes_cycle_gas_and_shared_allowance_then_exact_retry_matches() {
    let original = AllocationBudget::new(LIMIT);
    let words = [encode_halt()];
    let mut vm = loaded(Some(&original), &words, 9);
    let pc = vm.pc;
    let previous_logger = vm.proof_register_log_handle().unwrap();
    let baseline = original.reserved_bytes();
    let shell = zk::SharedRegLog::allocation_layout().size();
    let row = size_of::<zk::StepEntry>();
    let limit = baseline + shell + (4 + 9) * row + delta_bytes(1);
    original.set_limit_bytes(limit - 1);
    let cycles = allowance(9);
    assert!(matches!(
        vm.run_with_host_and_cycle_budget(&mut DefaultHost::default(), &cycles),
        Err(VMError::AllocationDeferred(AllocationRefusal::Capacity { requested_bytes, .. }))
        if requested_bytes == 9 * row
    ));
    assert!(vm.halted);
    assert_eq!(vm.pc, pc + 4);
    assert_eq!(vm.cycles, 1);
    assert_eq!(vm.gas_remaining, GAS);
    assert_eq!(vm.step_log().len(), 1);
    assert_eq!(cycles.consumed(), 1);
    assert_eq!(cycles.remaining(), 8);
    assert_eq!(
        original.reserved_bytes(),
        baseline + shell + 4 * row + delta_bytes(1)
    );
    original.set_limit_bytes(limit);
    vm.pc = pc;
    let retry_cycles = allowance(9);
    vm.run_with_host_and_cycle_budget(&mut DefaultHost::default(), &retry_cycles)
        .unwrap();
    assert_eq!(
        original.reserved_bytes(),
        baseline + shell + 9 * row + delta_bytes(9)
    );
    assert_eq!(retry_cycles.consumed(), 9);
    let mut standalone = loaded(None, &words, 9);
    standalone
        .run_with_host(&mut DefaultHost::default())
        .unwrap();
    assert_eq!(vm.execution_summary(), standalone.execution_summary());
    assert_eq!(vm.step_log(), standalone.step_log());
    assert_eq!(vm.gas_remaining, GAS - 8);
    drop((vm, previous_logger));
    assert_eq!(original.reserved_bytes(), 0);
}

#[test]
fn known_padding_out_of_gas_keeps_its_existing_outcome_without_root_growth() {
    let original = AllocationBudget::new(LIMIT);
    let mut vm = loaded(Some(&original), &[encode_halt()], 9);
    vm.set_gas_limit(3);
    let previous_logger = vm.proof_register_log_handle().unwrap();
    let baseline = original.reserved_bytes();
    let shell = zk::SharedRegLog::allocation_layout().size();
    let rows = 4 * size_of::<zk::StepEntry>();
    original.set_limit_bytes(baseline + shell + rows + delta_bytes(1));
    let cycles = allowance(9);
    assert!(matches!(
        vm.run_with_host_and_cycle_budget(&mut DefaultHost::default(), &cycles),
        Err(VMError::OutOfGas)
    ));
    assert_eq!(vm.cycles, 9);
    assert_eq!(vm.gas_remaining, 3);
    assert_eq!(cycles.consumed(), 9);
    assert_eq!(vm.step_log().len(), 1);
    assert_eq!(
        original.reserved_bytes(),
        baseline + shell + rows + delta_bytes(1)
    );
    drop((vm, previous_logger));
    assert_eq!(original.reserved_bytes(), 0);
}

#[test]
fn warm_reset_retires_cycle_backing_but_keeps_original_pool_binding() {
    let original = AllocationBudget::new(LIMIT);
    let mut vm = loaded(Some(&original), &[encode_halt()], 3);
    let template = vm.try_runtime_template().unwrap();
    let baseline = original.reserved_bytes();
    vm.run_with_host(&mut DefaultHost::default()).unwrap();
    assert_eq!(
        original.reserved_bytes(),
        baseline + 4 * size_of::<zk::StepEntry>() + delta_bytes(3)
    );
    original.set_limit_bytes(0);
    vm.reset_from_runtime_template(&template).unwrap();
    assert_eq!(original.reserved_bytes(), baseline);
    assert_eq!(vm.step_log.allocated_bytes().unwrap(), 0);
    let invocation = vm.begin_trace_invocation().unwrap();
    assert!(matches!(
        vm.prepare_trace_instruction(&invocation, encode_halt(), |_| Ok(())),
        Err(VMError::AllocationDeferred(_))
    ));
    assert_eq!(original.reserved_bytes(), baseline);
    original.set_limit_bytes(baseline + 4 * size_of::<zk::StepEntry>() + delta_bytes(3));
    vm.prepare_trace_instruction(&invocation, encode_halt(), |_| Ok(()))
        .unwrap();
    vm.finish_trace_invocation(invocation);
    assert_eq!(
        original.reserved_bytes(),
        baseline + 4 * size_of::<zk::StepEntry>() + delta_bytes(3)
    );
    drop((vm, template));
    assert_eq!(original.reserved_bytes(), 0);
}

#[test]
fn test_snapshot_cycle_rows_have_independent_credit_without_aggregate_double_count() {
    let original = AllocationBudget::new(LIMIT);
    let mut vm = loaded(Some(&original), &[encode_halt()], 1);
    vm.step_log.prepare_cycles(1).unwrap();
    let root = vm.registers.merkle_root();
    vm.step_log.record_reserved(vm.pc, root, root);
    let copy = vm.try_clone_snapshot().unwrap();
    assert_eq!(copy.step_log(), vm.step_log());
    assert_ne!(copy.step_log().as_ptr(), vm.step_log().as_ptr());
    assert_eq!(
        copy.step_log.allocated_bytes().unwrap(),
        4 * size_of::<zk::StepEntry>()
    );
    assert_eq!(
        copy.cache_reservation.bytes(),
        0,
        "the fixed owner already accounts for the cycle rows"
    );
    drop(vm);
    assert_eq!(copy.step_log().len(), 1);
    assert!(original.reserved_bytes() >= copy.step_log.allocated_bytes().unwrap());
    drop(copy);
    assert_eq!(original.reserved_bytes(), 0);
}
