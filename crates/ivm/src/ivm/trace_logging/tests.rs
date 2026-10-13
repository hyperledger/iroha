//! Exact trace preparation, cleanup and original-owner boundary regressions.

use super::*;
use crate::{
    ProgramMetadata,
    encoding::wide::{encode_halt, encode_ri, encode_rr},
    instruction::wide::{arithmetic as a, crypto as v},
};
use std::panic::{AssertUnwindSafe, catch_unwind};

pub(super) const LIMIT: usize = 128 * 1024 * 1024;
pub(super) const GAS: u64 = 10_000;

fn loaded(original: &AllocationBudget, mode: TraceMode, cycle_trace: bool) -> IVM {
    let mut image = ProgramMetadata {
        mode: if cycle_trace { crate::ivm_mode::ZK } else { 0 },
        max_cycles: if cycle_trace { 64 } else { 0 },
        ..ProgramMetadata::default()
    }
    .encode();
    image.extend(encode_halt().to_le_bytes());
    let mut vm = IVM::try_new_with_memory_budget(GAS, original).unwrap();
    vm.load_program(&image).unwrap();
    vm.set_zk_trace_enabled(cycle_trace);
    vm.set_trace_mode(mode);
    vm
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct GuestState {
    pc: u64,
    gas: u64,
    cycles: u64,
    registers: [u64; 256],
    tags: [bool; 256],
    heap: u64,
    input: u64,
    halted: bool,
}
pub(super) fn state(vm: &IVM) -> GuestState {
    GuestState {
        pc: vm.pc,
        gas: vm.gas_remaining,
        cycles: vm.cycles,
        registers: vm.registers.snapshot(),
        tags: vm.registers.snapshot_tags(),
        heap: vm.memory.heap_allocated_len(),
        input: vm.input_bump_next,
        halted: vm.halted,
    }
}

#[test]
fn initial_pc_and_full_delta_refusal_precedes_all_guest_changes() {
    for mode in [TraceMode::PcOnly, TraceMode::DeltaRegisters] {
        let original = AllocationBudget::new(LIMIT);
        let mut vm = loaded(&original, mode, false);
        vm.registers.set(7, 41);
        vm.cycles = 17;
        vm.halted = true;
        let before = state(&vm);
        let bytes = original.reserved_bytes();
        original.set_limit_bytes(0);
        assert!(matches!(
            vm.begin_trace_invocation(),
            Err(VMError::AllocationDeferred(
                AllocationRefusal::ExceedsLimit { .. }
            ))
        ));
        assert_eq!(state(&vm), before);
        assert!(vm.pc_trace.as_slice().is_empty());
        assert!(vm.delta_trace.is_empty());
        assert_eq!(original.reserved_bytes(), bytes);
        original.set_limit_bytes(LIMIT);
        let invocation = vm.begin_trace_invocation().unwrap();
        vm.record_trace_prefetch(&invocation).unwrap();
        vm.finish_trace_invocation(invocation);
        assert_eq!(state(&vm), before);
        drop(vm);
        assert_eq!(original.reserved_bytes(), 0);
    }
}

#[test]
fn tail_refusal_and_unwind_cancel_only_unobserved_credit_and_keep_original_error() {
    let original = AllocationBudget::new(LIMIT);
    let mut vm = loaded(&original, TraceMode::DeltaRegisters, true);
    let invocation = vm.begin_trace_invocation().unwrap();
    vm.record_trace_prefetch(&invocation).unwrap();
    let word = encode_ri(a::ADDI, 7, 7, 1);
    let before = state(&vm);
    let outcome = vm.prepare_trace_instruction(&invocation, word, |_| {
        original.set_limit_bytes(original.reserved_bytes());
        let Err(refusal) = original.try_reserve_bytes(1) else {
            panic!("original pool must refuse after limit shrinks to live credit");
        };
        Err::<(), _>(VMError::AllocationDeferred(refusal))
    });
    let Err(VMError::AllocationDeferred(AllocationRefusal::Capacity { release, .. })) = outcome
    else {
        panic!("original tail refusal");
    };
    let Err(AllocationRefusal::Capacity {
        release: expected, ..
    }) = original.try_reserve_bytes(1)
    else {
        panic!("original release source");
    };
    assert_eq!(release, expected);
    assert_eq!(state(&vm), before);
    assert_eq!(vm.delta_trace.len(), 1);
    assert!(vm.trace_log.is_empty());
    let retained = original.reserved_bytes();
    original.set_limit_bytes(0);
    let unwound = catch_unwind(AssertUnwindSafe(|| {
        let _ = vm.prepare_trace_instruction(&invocation, word, |_| -> Result<(), VMError> {
            panic!("later preflight unwind");
        });
    }));
    assert!(unwound.is_err());
    assert_eq!(state(&vm), before);
    assert_eq!(original.reserved_bytes(), retained);
    // Both retries use the original admitted backing at a zero admission limit.
    vm.prepare_trace_instruction(&invocation, word, |_| Ok(()))
        .unwrap();
    vm.registers.set(7, 1);
    vm.pc += 4;
    vm.cycles = 1;
    let mut last = 0;
    vm.publish_trace_cycles(&invocation, &mut last).unwrap();
    vm.record_trace_prefetch(&invocation).unwrap();
    assert_eq!(vm.delta_trace.entry(1).unwrap().changes, &[(7, 1, false)]);
    assert_eq!(last, 1);
    vm.finish_trace_invocation(invocation);
}

#[test]
fn previous_instruction_span_covers_wide_changes_before_a_narrow_next_opcode() {
    let original = AllocationBudget::new(LIMIT);
    let mut vm = loaded(&original, TraceMode::DeltaRegisters, true);
    vm.vector_length = 64;
    let invocation = vm.begin_trace_invocation().unwrap();
    vm.record_trace_prefetch(&invocation).unwrap();
    vm.prepare_trace_instruction(&invocation, encode_rr(v::VADD32, 2, 0, 1), |_| Ok(()))
        .unwrap();
    // Mimic only the public destination window here; the classifier's separate
    // tests compare the bound with actual ordinary interpreter transitions.
    for register in 160..224 {
        vm.registers.set(register, 41);
        vm.registers.set_tag(register, true);
    }
    vm.pc += 4;
    vm.cycles += 1;
    let mut last = 0;
    vm.publish_trace_cycles(&invocation, &mut last).unwrap();
    vm.record_trace_prefetch(&invocation).unwrap();
    assert_eq!(vm.delta_trace.entry(1).unwrap().changes.len(), 64);
    vm.prepare_trace_instruction(&invocation, encode_ri(a::ADDI, 0, 0, 0), |_| Ok(()))
        .unwrap();
    vm.pc += 4;
    vm.cycles += 1;
    vm.publish_trace_cycles(&invocation, &mut last).unwrap();
    vm.record_trace_prefetch(&invocation).unwrap();
    assert!(vm.delta_trace.entry(2).unwrap().changes.is_empty());
    vm.finish_trace_invocation(invocation);
}

#[test]
fn completed_cycle_batch_records_changes_once_then_padding_uses_no_change_span() {
    for (opcode, cycles) in [(a::GCD, 12), (a::DIV_CEIL, 12), (a::ISQRT, 6), (a::MEAN, 3)] {
        let original = AllocationBudget::new(LIMIT);
        let mut vm = loaded(&original, TraceMode::DeltaRegisters, true);
        let invocation = vm.begin_trace_invocation().unwrap();
        vm.record_trace_prefetch(&invocation).unwrap();
        vm.prepare_trace_instruction(&invocation, encode_rr(opcode, 7, 5, 6), |_| Ok(()))
            .unwrap();
        vm.registers.set(7, 17);
        vm.pc += 4;
        vm.cycles = cycles;
        let mut last = 0;
        vm.publish_trace_cycles(&invocation, &mut last).unwrap();
        assert_eq!(vm.trace_log.len(), cycles as usize);
        assert_eq!(vm.trace_log.entry(0).unwrap().changes.len(), 256);
        assert!(
            vm.trace_log
                .entries()
                .skip(1)
                .all(|row| row.changes.is_empty())
        );
        vm.record_trace_prefetch(&invocation).unwrap();
        assert_eq!(vm.delta_trace.entry(1).unwrap().changes, &[(7, 17, false)]);
        // Terminal instruction's unused future runtime row stays unused.
        vm.prepare_trace_instruction(&invocation, encode_halt(), |_| Ok(()))
            .unwrap();
        vm.pc += 4;
        vm.cycles += 1;
        vm.publish_trace_cycles(&invocation, &mut last).unwrap();
        vm.prepare_trace_padding(&invocation, 64 - vm.cycles)
            .unwrap();
        original.set_limit_bytes(0);
        vm.cycles = 64;
        vm.publish_trace_cycles(&invocation, &mut last).unwrap();
        assert_eq!(vm.trace_log.len(), 64);
        assert!(
            vm.trace_log
                .entries()
                .skip(1)
                .all(|row| row.changes.is_empty())
        );
        vm.finish_trace_invocation(invocation);
        assert_eq!(vm.delta_trace.len(), 2);
    }
}

#[test]
fn non_zk_mode_mutation_cannot_append_or_repair_a_foreign_pending_batch() {
    let original = AllocationBudget::new(LIMIT);
    let mut vm = loaded(&original, TraceMode::DeltaRegisters, false);
    let original_invocation = vm.begin_trace_invocation().unwrap();
    vm.record_trace_prefetch(&original_invocation).unwrap();
    vm.prepare_trace_instruction(&original_invocation, encode_halt(), |_| Ok(()))
        .unwrap();
    vm.set_trace_mode(TraceMode::PcOnly);
    let newer = vm.begin_trace_invocation().unwrap();
    let retained = original.reserved_bytes();
    original.set_limit_bytes(0);
    assert!(
        matches!(vm.record_trace_prefetch(&original_invocation), Err(VMError::ExecutionDeferred(__actual_error_field)) if __actual_error_field == (
            crate::error::ExecutionDeferral::TraceOwnerUnavailable
        ))
    );
    assert!(
        matches!(vm.prepare_trace_instruction(&original_invocation, encode_halt(), |_| Ok(())), Err(VMError::ExecutionDeferred(__actual_error_field)) if __actual_error_field == (
            crate::error::ExecutionDeferral::TraceOwnerUnavailable
        ))
    );
    vm.finish_trace_invocation(original_invocation);
    vm.record_trace_prefetch(&newer).unwrap();
    assert_eq!(vm.pc_trace.as_slice(), &[vm.pc]);
    assert_eq!(original.reserved_bytes(), retained);
    vm.finish_trace_invocation(newer);
}

#[test]
fn snapshot_preserves_independent_pending_capacity_and_reset_keeps_pool_identity() {
    let original = AllocationBudget::new(LIMIT);
    let mut vm = loaded(&original, TraceMode::DeltaRegisters, true);
    let invocation = vm.begin_trace_invocation().unwrap();
    vm.record_trace_prefetch(&invocation).unwrap();
    vm.prepare_trace_instruction(&invocation, encode_ri(a::ADDI, 7, 7, 1), |_| Ok(()))
        .unwrap();
    vm.with_trace_scope(|vm, scope| vm.pc_trace.prepare(4, scope))
        .unwrap();
    let demand = vm.trace_log.allocated_bytes().unwrap()
        + vm.delta_trace.allocated_bytes().unwrap()
        + vm.pc_trace.allocated_bytes().unwrap();
    let before = original.reserved_bytes();
    let mut copies = original
        .with_deferred_refund_notifications(|scope| vm.try_clone_trace_storage(Some(scope)))
        .unwrap();
    assert_eq!(original.reserved_bytes(), before + demand);
    original.set_limit_bytes(0);
    copies.cycles.record_reserved(vm.pc, [9; 256], [true; 256]);
    let mut copied_registers = vm.registers.snapshot();
    copied_registers[7] = 23;
    copies
        .runtime
        .record_reserved(vm.pc, copied_registers, vm.registers.snapshot_tags());
    copies.pcs.record_reserved(99);
    vm.finish_trace_invocation(invocation);
    vm.reset_trace_storage().unwrap();
    assert_eq!(original.reserved_bytes(), before);
    assert_eq!(copies.runtime.entry(1).unwrap().changes, &[(7, 23, false)]);
    assert_eq!(copies.pcs.as_slice(), &[99]);
    assert!(matches!(
        vm.begin_trace_invocation(),
        Err(VMError::AllocationDeferred(_))
    ));
    drop(copies);
    assert_eq!(original.reserved_bytes(), before - demand);
    drop(vm);
    assert_eq!(original.reserved_bytes(), 0);
}

#[test]
fn original_scope_validation_precedes_clone_and_partial_copy_keeps_original_credit() {
    let original = AllocationBudget::new(LIMIT);
    let foreign = AllocationBudget::new(LIMIT);
    let mut vm = loaded(&original, TraceMode::DeltaRegisters, true);
    let invocation = vm.begin_trace_invocation().unwrap();
    vm.record_trace_prefetch(&invocation).unwrap();
    vm.prepare_trace_instruction(&invocation, encode_ri(a::ADDI, 7, 7, 1), |_| Ok(()))
        .unwrap();
    vm.registers.set(7, 41);
    vm.cycles = 1;
    vm.pc += 4;
    let mut last = 0;
    vm.publish_trace_cycles(&invocation, &mut last).unwrap();
    vm.record_trace_prefetch(&invocation).unwrap();
    vm.prepare_trace_instruction(&invocation, encode_halt(), |_| Ok(()))
        .unwrap();
    let before = original.reserved_bytes();
    foreign.with_deferred_refund_notifications(|scope| {
        assert!(matches!(
            vm.try_clone_trace_storage(Some(scope)),
            Err(VMError::ExecutionDeferred(
                crate::error::ExecutionDeferral::TraceOwnerUnavailable
            ))
        ));
    });
    assert_eq!(foreign.reserved_bytes(), 0);
    assert_eq!(original.reserved_bytes(), before);
    assert_eq!(vm.delta_trace.len(), 2);
    // The independent cycle delta copy fits; the subsequent runtime delta copy
    // refuses its full combined backing after that first owner has allocated.
    let cycle_bytes = vm.trace_log.allocated_bytes().unwrap();
    let runtime_bytes = vm.delta_trace.allocated_bytes().unwrap();
    original.set_limit_bytes(before + cycle_bytes + runtime_bytes - 1);
    let outcome = original
        .with_deferred_refund_notifications(|scope| vm.try_clone_trace_storage(Some(scope)));
    assert!(
        matches!(outcome, Err(VMError::AllocationDeferred(AllocationRefusal::Capacity { requested_bytes, .. })) if requested_bytes == runtime_bytes)
    );
    assert_eq!(original.reserved_bytes(), before);
    assert_eq!(vm.delta_trace.len(), 2);
    assert_eq!(vm.trace_log.entry(0).unwrap().changes[7], (7, 41, false));
    vm.finish_trace_invocation(invocation);
}

#[test]
fn no_observation_preflight_skips_destination_geometry_and_retains_no_backing() {
    let original = AllocationBudget::new(LIMIT);
    let mut vm = loaded(&original, TraceMode::Off, false);
    let invocation = vm.begin_trace_invocation().unwrap();
    let before = state(&vm);
    let retained = original.reserved_bytes();
    original.set_limit_bytes(0);
    let mut calls = 0;
    // Opcode validation is the ordinary caller's earlier responsibility. This
    // helper-only sentinel proves absent observations do not invoke the delta
    // classifier, which would reject it. No invalid instruction is executed.
    assert!(matches!(
        vm.prepare_trace_instruction(&invocation, 0, |_| {
            calls += 1;
            Ok(41)
        }),
        Ok(41)
    ));
    assert_eq!(calls, 1);
    assert_eq!(state(&vm), before);
    assert_eq!(original.reserved_bytes(), retained);
    assert_eq!(vm.trace_log.allocated_bytes().unwrap(), 0);
    assert_eq!(vm.delta_trace.allocated_bytes().unwrap(), 0);
    assert_eq!(vm.pc_trace.allocated_bytes().unwrap(), 0);
    vm.finish_trace_invocation(invocation);
}

#[test]
fn no_observation_tail_refusal_panic_and_policy_checks_preserve_their_precedence() {
    let original = AllocationBudget::new(LIMIT);
    let mut vm = loaded(&original, TraceMode::Off, false);
    let invocation = vm.begin_trace_invocation().unwrap();
    let before = state(&vm);
    original.set_limit_bytes(original.reserved_bytes());
    let refusal = original.try_reserve_bytes(1).unwrap_err();
    assert!(
        matches!(vm.prepare_trace_instruction(&invocation, encode_halt(), |_| {
            Err::<(), _>(VMError::AllocationDeferred(refusal.clone()))
        }), Err(VMError::AllocationDeferred(__actual_error_field)) if __actual_error_field == (refusal))
    );
    let panic = catch_unwind(AssertUnwindSafe(|| {
        let _ =
            vm.prepare_trace_instruction(&invocation, encode_halt(), |_| -> Result<(), VMError> {
                std::panic::panic_any("original no-observation tail panic");
            });
    }))
    .unwrap_err();
    assert_eq!(
        panic.downcast_ref::<&str>(),
        Some(&"original no-observation tail panic")
    );
    assert_eq!(state(&vm), before);
    vm.prepare_trace_instruction(&invocation, encode_halt(), |_| Ok(()))
        .unwrap();
    assert!(matches!(
        vm.prepare_trace_instruction(&invocation, encode_halt(), |vm| {
            vm.set_trace_mode(TraceMode::PcOnly);
            Err::<(), _>(VMError::PrivacyViolation)
        }),
        Err(VMError::PrivacyViolation)
    ));
    let mut called = false;
    assert!(
        matches!(vm.prepare_trace_instruction(&invocation, encode_halt(), |_| {
            called = true;
            Ok(())
        }), Err(VMError::ExecutionDeferred(__actual_error_field)) if __actual_error_field == (
            crate::error::ExecutionDeferral::TraceOwnerUnavailable
        ))
    );
    assert!(!called);
    vm.finish_trace_invocation(invocation);
}

#[test]
fn no_observation_successful_tail_cannot_authorize_a_replaced_policy() {
    let original = AllocationBudget::new(LIMIT);
    let mut vm = loaded(&original, TraceMode::Off, false);
    let invocation = vm.begin_trace_invocation().unwrap();
    let retained = original.reserved_bytes();
    assert!(
        matches!(vm.prepare_trace_instruction(&invocation, encode_halt(), |vm| {
            vm.set_trace_mode(TraceMode::DeltaRegisters);
            Ok(())
        }), Err(VMError::ExecutionDeferred(__actual_error_field)) if __actual_error_field == (
            crate::error::ExecutionDeferral::TraceOwnerUnavailable
        ))
    );
    assert_eq!(original.reserved_bytes(), retained);
    assert!(vm.delta_trace.is_empty());
    vm.finish_trace_invocation(invocation);
}

#[test]
fn pc_only_admission_does_not_classify_delta_destinations() {
    let original = AllocationBudget::new(LIMIT);
    let mut vm = loaded(&original, TraceMode::PcOnly, false);
    let invocation = vm.begin_trace_invocation().unwrap();
    vm.record_trace_prefetch(&invocation).unwrap();
    // The public opcode is already checked by the run loop. As above, the
    // helper-only sentinel must never reach the unused delta classifier.
    vm.prepare_trace_instruction(&invocation, 0, |_| Ok(()))
        .unwrap();
    vm.record_trace_prefetch(&invocation).unwrap();
    assert_eq!(vm.pc_trace.as_slice(), &[vm.pc, vm.pc]);
    assert_eq!(vm.trace_log.allocated_bytes().unwrap(), 0);
    assert_eq!(vm.delta_trace.allocated_bytes().unwrap(), 0);
    vm.finish_trace_invocation(invocation);
}

#[test]
fn fresh_child_uses_original_pool_and_refuses_before_parent_effects() {
    let original = AllocationBudget::new(LIMIT);
    let mut parent = loaded(&original, TraceMode::DeltaRegisters, false);
    parent.registers.set(17, 0xace);
    parent.registers.set_tag(17, true);
    parent.cycles = 71;
    parent.gas_remaining = 19;
    parent.halted = true;
    let before = state(&parent);
    let retained = original.reserved_bytes();
    original.set_limit_bytes(retained);
    let refusal = parent.try_new_in_same_memory_pool(GAS / 2).err().unwrap();
    let Err(AllocationRefusal::Capacity {
        release: expected, ..
    }) = original.try_reserve_bytes(1)
    else {
        panic!("original pool must be exhausted");
    };
    let VMError::AllocationDeferred(AllocationRefusal::Capacity { release, .. }) = refusal else {
        panic!("fresh child must preserve original capacity refusal");
    };
    assert_eq!(release, expected);
    assert_eq!(state(&parent), before);
    assert_eq!(original.reserved_bytes(), retained);

    original.set_limit_bytes(LIMIT);
    let child = parent.try_new_in_same_memory_pool(GAS / 2).unwrap();
    assert!(
        child
            .memory
            .allocation_budget()
            .unwrap()
            .same_pool(&original)
    );
    assert_eq!(child.registers.get(17), 0);
    assert!(!child.registers.tag(17));
    assert_eq!(child.trace_mode(), TraceMode::Off);
    assert_eq!(child.pc, 0);
    assert_eq!(child.cycles, 0);
    assert_eq!(child.gas_remaining, GAS / 2);
    assert!(!child.halted);
    assert_eq!(state(&parent), before);
    let captured = child.try_runtime_trace_capture().unwrap();
    assert!(captured.is_empty());
    assert!(captured.belongs_to(&original));
    drop((child, captured));
    assert_eq!(original.reserved_bytes(), retained);
    drop(parent);
    assert_eq!(original.reserved_bytes(), 0);
}

#[test]
fn fresh_standalone_child_stays_unfunded_and_capture_checks_vm_owner() {
    let mut parent = IVM::try_new(GAS).unwrap();
    parent.registers.set(17, 42);
    let child = parent.try_new_in_same_memory_pool(GAS / 2).unwrap();
    assert!(parent.memory.allocation_budget().is_none());
    assert!(child.memory.allocation_budget().is_none());
    assert_eq!(child.registers.get(17), 0);
    assert_eq!(parent.registers.get(17), 42);
    let capture = child.try_runtime_trace_capture().unwrap();
    assert!(capture.is_empty());
    assert!(
        capture
            .try_combine(&parent.try_runtime_trace_capture().unwrap())
            .is_ok()
    );

    // Matching substituted logs are still not the original VM allocation owner.
    let foreign = AllocationBudget::new(LIMIT);
    parent.pc_trace = zk::PcTraceLog::new(Some(&foreign));
    parent.delta_trace = zk::DeltaTraceLog::new(Some(&foreign));
    assert!(matches!(
        parent.try_runtime_trace_capture(),
        Err(VMError::ExecutionDeferred(
            crate::error::ExecutionDeferral::TraceOwnerUnavailable
        ))
    ));
    assert_eq!(foreign.reserved_bytes(), 0);
}
