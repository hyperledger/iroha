//! Allocation ownership, VM baselines, and independent snapshot regressions.

use super::*;
use crate::{
    error::VmBudgetSnapshot,
    ivm::snapshot::{checked_allocation_bytes, contract_debug_allocation_bytes},
    metadata::{EmbeddedFunctionBudgetReportV1, EmbeddedSourceLocation, EmbeddedSourceMapEntryV1},
};

/// A run replaces its logger before guest effects. Keep this separate from
/// the exact read/write-owner budgets exercised by the callers below.
fn allow_exact_invocation_shell(vm: &mut IVM, budget: &AllocationBudget) {
    let occupied = budget.reserved_bytes();
    let shell = zk::SharedRegLog::allocation_layout().size();
    let before = vm.execution_summary();
    budget.set_limit_bytes(occupied + shell - 1);
    assert!(matches!(
        vm.run(),
        Err(VMError::AllocationDeferred(iroha_allocation::AllocationRefusal::Capacity {
            requested_bytes, ..
        })) if requested_bytes == shell
    ));
    assert_eq!(vm.execution_summary(), before);
    assert_eq!(budget.reserved_bytes(), occupied);
    budget.set_limit_bytes(occupied + shell);
}

#[test]
fn load_program_reuses_cached_prepared_ops() {
    set_banner_enabled(false);
    ivm_cache::init_global_with_capacity(64);
    let program = program_with_imm(7);
    let mut first_vm = IVM::new(u64::MAX);
    first_vm
        .load_program(&program)
        .expect("first load succeeds");
    let first_ops = first_vm.prepared.as_ref().expect("prepared").ops.clone();
    let mut second_vm = IVM::new(u64::MAX);
    second_vm
        .load_program(&program)
        .expect("second load succeeds");
    let second_ops = second_vm.prepared.as_ref().expect("prepared").ops.clone();
    assert!(crate::cache_memory::SharedAllocation::ptr_eq(
        &first_ops,
        &second_ops
    ));
}
#[test]
fn warm_runtime_template_reset_does_not_clone_reload_or_reparse() {
    set_banner_enabled(false);
    let program = program_with_imm(7);
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&program).expect("program loads");
    let code_allocation = vm
        .memory
        .load_region(0, 1)
        .expect("loaded code is readable")
        .as_ptr();
    let parse_attempts = vm.program_parse_attempts();
    let prepared_loads = vm.prepared_loads();
    // Building the immutable template makes one fallible full-memory copy.
    let template = vm
        .try_runtime_template()
        .expect("runtime template allocation fits test host");
    vm.set_register(7, 99);
    vm.preload_input(0, &[0xA5])
        .expect("invocation input is writable before execution");
    vm.reset_from_runtime_template(&template)
        .expect("warm VM retains its runtime-template geometry");
    assert!(
        std::ptr::eq(
            vm.memory
                .load_region(0, 1)
                .expect("loaded code remains readable")
                .as_ptr(),
            code_allocation,
        ),
        "warm reset must preserve the VM memory allocation"
    );
    assert_eq!(vm.program_parse_attempts(), parse_attempts);
    assert_eq!(vm.prepared_loads(), prepared_loads);
    assert_eq!(vm.register(7), 0);
    assert_eq!(
        vm.memory
            .load_region(Memory::INPUT_START, 1)
            .expect("input baseline is readable"),
        [0]
    );
}
fn funded_template_demand(vm: &IVM) -> usize {
    norito::core::owned_arc_allocation_bytes::<RuntimeTemplateData>().unwrap()
        + norito::core::owned_arc_allocation_bytes::<RuntimeTemplateBacking>().unwrap()
        + vm.memory
            .runtime_template_memory_plan()
            .unwrap()
            .requested_bytes()
        + vm.registers
            .runtime_template_memory_plan()
            .unwrap()
            .requested_bytes()
        + vm.private_memory_bytes
            .runtime_template_memory_plan()
            .unwrap()
            .requested_bytes()
}

#[test]
fn funded_runtime_template_refusal_retry_and_final_owner_use_original_pool() {
    use iroha_allocation::{AllocationBudget, AllocationRefusal};

    let budget = AllocationBudget::new(64 * 1024 * 1024);
    let mut vm = IVM::try_new_with_memory_budget(1_000, &budget).unwrap();
    vm.load_program(&program_with_imm(7)).unwrap();
    vm.memory.store_u64(Memory::STACK_START, 0x1234).unwrap();
    vm.memory.load_u64(Memory::STACK_START).unwrap();
    vm.private_memory_bytes
        .try_insert(Memory::STACK_START..Memory::STACK_START + 8)
        .unwrap();
    // Refresh both retained node arrays before planning their clone.
    vm.memory.commit();
    let expected_root = vm.memory.current_root();
    let _ = vm.registers.merkle_root();
    let original_bytes = budget.reserved_bytes();
    let template_bytes = funded_template_demand(&vm);
    let gas = vm.remaining_gas();
    let pc = vm.pc;
    let source_ranges = vm.private_memory_bytes.pairs_for_testing().to_vec();

    budget.set_limit_bytes(0);
    assert!(matches!(
        vm.try_runtime_template(),
        Err(VMError::AllocationDeferred(
            AllocationRefusal::ExceedsLimit { .. }
        ))
    ));
    assert_eq!(budget.reserved_bytes(), original_bytes);
    budget.set_limit_bytes(original_bytes + template_bytes - 1);
    assert!(matches!(
        vm.try_runtime_template(),
        Err(VMError::AllocationDeferred(
            AllocationRefusal::Capacity { .. }
        ))
    ));
    assert_eq!(budget.reserved_bytes(), original_bytes);
    assert_eq!(vm.remaining_gas(), gas);
    assert_eq!(vm.pc, pc);
    assert_eq!(vm.private_memory_bytes.pairs_for_testing(), source_ranges);

    budget.set_limit_bytes(original_bytes + template_bytes);
    let template = vm.try_runtime_template().unwrap();
    assert_eq!(budget.reserved_bytes(), original_bytes + template_bytes);
    // Existing row capacity is prepaid; the new write owns eight additional bytes.
    budget.set_limit_bytes(original_bytes + template_bytes + 8);
    vm.memory.store_u64(Memory::STACK_START, 0x5678).unwrap();
    vm.reset_from_runtime_template(&template).unwrap();
    assert_eq!(vm.memory.current_root(), expected_root);
    assert_eq!(
        template.data().private_memory_bytes,
        vm.private_memory_bytes
    );
    let borrower = template.clone();
    drop(vm);
    assert_eq!(budget.reserved_bytes(), template_bytes);
    budget.set_limit_bytes(0);
    drop(template);
    assert_eq!(budget.reserved_bytes(), template_bytes);
    drop(borrower);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn funded_runtime_template_partial_copy_refusal_refunds_original_lease() {
    let budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
    let mut vm = IVM::try_new_with_memory_budget(1_000, &budget).unwrap();
    vm.private_memory_bytes
        .try_insert(Memory::STACK_START..Memory::STACK_START + 8)
        .unwrap();
    let original_bytes = budget.reserved_bytes();
    let template_bytes = funded_template_demand(&vm);
    budget.set_limit_bytes(original_bytes + template_bytes);
    // This failure happens after memory, leaf, and register copies exist.
    PrivateMemoryRanges::refuse_next_copy_for_testing();
    assert!(matches!(
        vm.try_runtime_template(),
        Err(VMError::ExecutionDeferred(
            crate::error::ExecutionDeferral::AllocationUnavailable
        ))
    ));
    assert_eq!(budget.reserved_bytes(), original_bytes);
    let template = vm.try_runtime_template().unwrap();
    assert_eq!(budget.reserved_bytes(), original_bytes + template_bytes);
    drop(template);
    assert_eq!(budget.reserved_bytes(), original_bytes);
}

#[test]
fn funded_runtime_template_unwind_refunds_only_abandoned_snapshot() {
    let budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
    let mut vm = IVM::try_new_with_memory_budget(1_000, &budget).unwrap();
    let original_bytes = budget.reserved_bytes();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _template = vm.try_runtime_template().unwrap();
        assert!(budget.reserved_bytes() > original_bytes);
        panic!("abandon funded runtime template");
    }));
    assert!(panic.is_err());
    assert_eq!(budget.reserved_bytes(), original_bytes);
    drop(vm);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn runtime_template_copies_private_ranges_without_changing_the_source() {
    let mut vm = quiet_vm(1_000);
    vm.private_memory_bytes
        .try_insert(Memory::STACK_START..Memory::STACK_START + 8)
        .unwrap();
    let template = vm
        .try_runtime_template()
        .expect("bounded private-range baseline");
    assert_eq!(
        template.data().private_memory_bytes,
        vm.private_memory_bytes
    );
    vm.private_memory_bytes.clear();
    assert!(!template.data().private_memory_bytes.is_empty());
}
#[test]
fn private_range_template_reset_growth_refuses_before_memory_mutation() {
    let program = program_with_imm(7);
    let mut vm = quiet_vm(1_000);
    vm.load_program(&program).unwrap();
    let start = Memory::STACK_START;
    vm.private_memory_bytes
        .try_insert(start..start + 8)
        .unwrap();
    let template = vm.try_runtime_template().unwrap();
    vm.memory.store_u64(start, 0x1234).unwrap();
    let before = vm.memory.load_u64(start).unwrap();
    // Exercise a reset destination with no retained interval capacity.
    vm.private_memory_bytes = PrivateMemoryRanges::default();
    crate::cache_memory::refuse_next_owned_vec_growth_for_test();
    let gas = vm.remaining_gas();
    let pc = vm.pc;
    let refused = vm.reset_from_runtime_template(&template).unwrap_err();
    assert_eq!(
        refused.kind,
        RuntimeTemplateResetErrorKind::AllocationUnavailable
    );
    assert_eq!(vm.memory.load_u64(start).unwrap(), before);
    assert!(vm.private_memory_bytes.is_empty());
    assert_eq!(vm.remaining_gas(), gas);
    assert_eq!(vm.pc, pc);
    vm.reset_from_runtime_template(&template).unwrap();
    assert_eq!(vm.memory.load_u64(start).unwrap(), 0);
    assert_eq!(
        vm.private_memory_bytes,
        template.data().private_memory_bytes
    );
}

#[test]
fn funded_private_interval_reset_reuses_capacity_after_original_pool_shrinks() {
    let budget = AllocationBudget::new(64 * 1024 * 1024);
    let mut vm = IVM::try_new_with_memory_budget(1_000, &budget).unwrap();
    vm.load_program(&program_with_imm(7)).unwrap();
    let start = Memory::STACK_START;
    vm.private_memory_bytes
        .try_insert(start..start + 8)
        .unwrap();
    let template = vm.try_runtime_template().unwrap();
    vm.memory.store_u64(start, 0x1234).unwrap();
    vm.private_memory_bytes.clear();
    let ranges = vm.private_memory_bytes.pairs_for_testing().as_ptr();
    budget.set_limit_bytes(0);
    vm.reset_from_runtime_template(&template).unwrap();
    assert_eq!(vm.private_memory_bytes.pairs_for_testing().as_ptr(), ranges);
    assert_eq!(
        vm.private_memory_bytes,
        template.data().private_memory_bytes
    );
    assert_eq!(vm.memory.inspect_region(start, 8).unwrap(), &[0; 8]);
    assert_eq!(vm.remaining_gas(), 1_000);
    drop(vm);
    drop(template);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn funded_private_tlv_interval_refusal_preserves_heap_and_guest_state() {
    let budget = AllocationBudget::new(64 * 1024 * 1024);
    let mut vm = IVM::try_new_with_memory_budget(1_000, &budget).unwrap();
    vm.set_zk_mode(true).unwrap();
    let heap = vm.memory.heap_allocated_len();
    let gas = vm.remaining_gas();
    let pc = vm.pc;
    let reserved = budget.reserved_bytes();
    budget.set_limit_bytes(0);
    assert!(matches!(
        vm.alloc_host_private_tlv(&[1, 2, 3]),
        Err(VMError::AllocationDeferred(_))
    ));
    assert_eq!(vm.memory.heap_allocated_len(), heap);
    assert_eq!(vm.remaining_gas(), gas);
    assert_eq!(vm.pc, pc);
    assert!(vm.private_memory_bytes.is_empty());
    assert_eq!(budget.reserved_bytes(), reserved);
    budget.set_limit_bytes(64 * 1024 * 1024);
    let address = vm.alloc_host_private_tlv(&[1, 2, 3]).unwrap();
    assert_eq!(address, Memory::HEAP_START + heap);
    assert_eq!(
        vm.private_memory_bytes.pairs_for_testing(),
        &[(address, address + 3)]
    );
    assert_eq!(vm.remaining_gas(), gas);
}
#[test]
fn prepaid_dirty_tracking_resets_warm_vm_after_budget_shrink_with_identical_gas() {
    let program = program_with_imm(7);
    let budget = AllocationBudget::new(64 * 1024 * 1024);
    let mut vm = IVM::try_new_with_memory_budget(1_000, &budget).unwrap();
    vm.load_program(&program).unwrap();
    let template = vm.try_runtime_template().unwrap();
    let mut ordinary = quiet_vm(1_000);
    ordinary.load_program(&program).unwrap();
    let ordinary_template = ordinary.try_runtime_template().unwrap();
    let before_gas = vm.remaining_gas();
    let before_pc = vm.pc;
    // Tracked probes reuse this prepaid read array throughout zero-limit resets.
    assert_eq!(vm.memory.load_u64(Memory::STACK_START), Ok(0));
    let reserved = budget.reserved_bytes();
    let row_bytes = 4 * std::mem::size_of::<crate::WriteLogEntry>();
    budget.set_limit_bytes(0);
    for iteration in 0..2 {
        // Fund only the new log payload and, once, its row capacity. Bitmaps
        // and canonical nodes remain prepaid through the zero-limit reset.
        let additional = if iteration == 0 { row_bytes + 8 } else { 8 };
        budget.set_limit_bytes(budget.reserved_bytes() + additional);
        vm.memory.store_u64(Memory::STACK_START, 0x1234).unwrap();
        budget.set_limit_bytes(0);
        ordinary
            .memory
            .store_u64(Memory::STACK_START, 0x1234)
            .unwrap();
        assert_eq!(vm.remaining_gas(), before_gas);
        assert_eq!(vm.pc, before_pc);
        assert_eq!(vm.memory.load_u64(Memory::STACK_START), Ok(0x1234));
        vm.reset_from_runtime_template(&template).unwrap();
        ordinary
            .reset_from_runtime_template(&ordinary_template)
            .unwrap();
        assert_eq!(vm.memory.load_u64(Memory::STACK_START), Ok(0));
        assert_eq!(vm.remaining_gas(), ordinary.remaining_gas());
        assert_eq!(vm.pc, ordinary.pc);
        assert_eq!(budget.reserved_bytes(), reserved + row_bytes);
        assert!(matches!(vm.run(), Err(VMError::AllocationDeferred(_))));
        assert_eq!(budget.reserved_bytes(), reserved + row_bytes);
        allow_exact_invocation_shell(&mut vm, &budget);
        vm.run().unwrap();
        ordinary.run().unwrap();
        assert_eq!(vm.remaining_gas(), ordinary.remaining_gas());
        assert_eq!(vm.memory.current_root(), ordinary.memory.current_root());
        assert_eq!(vm.registers.merkle_root(), ordinary.registers.merkle_root());
        budget.set_limit_bytes(0);
        vm.reset_from_runtime_template(&template).unwrap();
        ordinary
            .reset_from_runtime_template(&ordinary_template)
            .unwrap();
    }
    drop(vm);
    let template_credit = budget.reserved_bytes();
    assert!(template_credit > 0);
    let borrower = template.clone();
    drop(template);
    assert_eq!(budget.reserved_bytes(), template_credit);
    drop(borrower);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn funded_write_log_refusal_preserves_guest_bytes_privacy_gas_and_retry_result() {
    let budget = AllocationBudget::new(64 * 1024 * 1024);
    let mut vm = IVM::try_new_with_memory_budget(1_000, &budget).unwrap();
    let mut local = quiet_vm(1_000);
    let program = program_with_imm(7);
    vm.load_program(&program).unwrap();
    local.load_program(&program).unwrap();
    // Probe reads below must not borrow write-log or bitmap observation credit.
    assert_eq!(vm.memory.load_u64(Memory::STACK_START), Ok(0));
    let base = budget.reserved_bytes();
    let gas = vm.remaining_gas();
    let pc = vm.pc;
    let root = vm.memory.current_root();
    let privacy = vm.private_memory_bytes.pairs_for_testing().to_vec();
    budget.set_limit_bytes(0);
    assert!(matches!(
        vm.store_u64(Memory::STACK_START, 0x1234),
        Err(VMError::AllocationDeferred(_))
    ));
    assert_eq!(vm.remaining_gas(), gas);
    assert_eq!(vm.pc, pc);
    assert_eq!(vm.memory.load_u64(Memory::STACK_START), Ok(0));
    assert_eq!(vm.memory.current_root(), root);
    assert_eq!(vm.private_memory_bytes.pairs_for_testing(), privacy);
    assert_eq!(budget.reserved_bytes(), base);
    let append_bytes = 4 * std::mem::size_of::<crate::WriteLogEntry>() + 8;
    budget.set_limit_bytes(base + append_bytes);
    vm.store_u64(Memory::STACK_START, 0x1234).unwrap();
    local.store_u64(Memory::STACK_START, 0x1234).unwrap();
    assert_eq!(budget.reserved_bytes(), base + append_bytes);
    allow_exact_invocation_shell(&mut vm, &budget);
    vm.run().unwrap();
    local.run().unwrap();
    assert_eq!(vm.remaining_gas(), local.remaining_gas());
    assert_eq!(vm.memory.current_root(), local.memory.current_root());
    assert_eq!(vm.registers.merkle_root(), local.registers.merkle_root());
    drop(vm);
    assert_eq!(budget.reserved_bytes(), 0);
}
#[test]
fn runtime_template_rejects_same_program_reloaded_after_memory_writes() {
    let program = program_with_imm(7);
    let mut vm = quiet_vm(u64::MAX);
    vm.load_program(&program).expect("template program loads");
    let template = vm
        .try_runtime_template()
        .expect("runtime template allocation fits test host");
    vm.memory
        .store_u64(Memory::STACK_START, 0xDEAD_BEEF)
        .expect("write invocation stack");
    vm.load_program(&program)
        .expect("same program can be reloaded by lifecycle API");
    assert_eq!(vm.code_hash(), template.data().code_hash);

    let error = vm
        .reset_from_runtime_template(&template)
        .expect_err("same-hash lifecycle change must reject warm reset");

    assert!(error.to_string().contains("lifecycle mismatch"));
    assert_eq!(
        vm.memory.load_u64(Memory::STACK_START),
        Ok(0xDEAD_BEEF),
        "failed reset must leave the VM unchanged for pool discard"
    );
}
#[test]
fn runtime_template_rejects_independent_same_generation_memory_image() {
    let program = program_with_imm(7);
    let mut target = quiet_vm(u64::MAX);
    target.load_program(&program).expect("target program loads");
    let template = target
        .try_runtime_template()
        .expect("runtime template allocation fits test host");

    let mut replacement = quiet_vm(u64::MAX);
    replacement
        .preload_input(0, &[0xA5])
        .expect("replacement input is writable");
    replacement
        .load_program(&program)
        .expect("same program loads into replacement memory");
    assert_eq!(
        replacement.memory.template_generation(),
        target.memory.template_generation()
    );
    target.memory = replacement.memory;

    let error = target
        .reset_from_runtime_template(&template)
        .expect_err("independent same-generation memory must not match the template");

    assert!(error.to_string().contains("baseline identity mismatch"));
    assert_eq!(
        target
            .memory
            .load_region(Memory::INPUT_START, 1)
            .expect("replacement input remains readable"),
        [0xA5],
        "a rejected reset must leave the replacement memory unchanged"
    );
}
#[test]
fn loading_a_program_clears_prior_heap_and_allocator_state() {
    let first = program_with_imm(7);
    let second = program_with_imm(8);
    let mut vm = quiet_vm(u64::MAX);
    vm.load_program(&first).expect("first program loads");
    vm.memory
        .store_u64(Memory::HEAP_START, 0xDEAD_BEEF)
        .expect("dirty first program heap");
    assert_eq!(vm.alloc_heap(16), Ok(Memory::HEAP_START));

    vm.load_program(&second).expect("replacement program loads");

    assert_eq!(vm.memory.load_u64(Memory::HEAP_START), Ok(0));
    assert_eq!(vm.alloc_heap(8), Ok(Memory::HEAP_START));
}
#[test]
fn runtime_template_geometry_mismatch_never_replaces_the_memory_image() {
    let mut vm = quiet_vm(u64::MAX);
    vm.load_code(&crate::encoding::wide::encode_halt().to_le_bytes())
        .expect("template program loads");
    let template = vm
        .try_runtime_template()
        .expect("runtime template allocation fits test host");
    vm.memory = Memory::new_with_stack_limit(Memory::MIN_STACK_SIZE).unwrap();
    vm.set_register(7, 99);
    let mismatched_allocation = vm
        .memory
        .load_region(Memory::HEAP_START, 1)
        .expect("mismatched memory is readable")
        .as_ptr();
    let error = vm
        .reset_from_runtime_template(&template)
        .expect_err("different memory geometry must reject warm reset");
    assert!(error.to_string().contains("memory geometry mismatch"));
    assert_eq!(vm.register(7), 99, "failed reset must not touch VM state");
    assert_eq!(vm.memory.stack_limit(), Memory::MIN_STACK_SIZE);
    assert!(std::ptr::eq(
        vm.memory
            .load_region(Memory::HEAP_START, 1)
            .expect("mismatched memory remains readable")
            .as_ptr(),
        mismatched_allocation
    ));
}
#[test]
fn runtime_template_rejects_a_different_program_before_mutating_the_vm() {
    let mut template_vm = quiet_vm(u64::MAX);
    template_vm
        .load_program(&program_with_imm(7))
        .expect("template program loads");
    let template = template_vm
        .try_runtime_template()
        .expect("runtime template allocation fits test host");

    let mut vm = quiet_vm(u64::MAX);
    vm.load_program(&program_with_imm(8))
        .expect("worker program loads");
    vm.set_register(7, 99);
    let code_hash = vm.code_hash();

    let error = vm
        .reset_from_runtime_template(&template)
        .expect_err("a template for another program must be rejected");

    assert!(error.to_string().contains("program mismatch"));
    assert_eq!(vm.code_hash(), code_hash);
    assert_eq!(vm.register(7), 99, "failed reset must not touch VM state");
}
#[test]
fn runtime_template_rejects_a_different_heap_authority() {
    let mut vm = quiet_vm(u64::MAX);
    vm.load_code(&crate::encoding::wide::encode_halt().to_le_bytes())
        .expect("template program loads");
    let template = vm
        .try_runtime_template()
        .expect("runtime template allocation fits test host");
    vm.memory
        .set_heap_max_limit(Memory::HEAP_MAX_SIZE - Memory::STACK_ALIGNMENT)
        .expect("smaller heap authority is valid");
    vm.set_register(7, 99);
    let error = vm
        .reset_from_runtime_template(&template)
        .expect_err("different heap authority must reject warm reset");
    assert!(error.to_string().contains("heap-ceiling bytes"));
    assert_eq!(vm.register(7), 99, "failed reset must not touch VM state");
    assert_eq!(
        vm.memory.heap_max_limit(),
        Memory::HEAP_MAX_SIZE - Memory::STACK_ALIGNMENT,
    );
}
#[test]
fn load_program_runs_unaligned_contract_prefix_from_prepared_ops() {
    set_banner_enabled(false);
    let (program, prefix_len) = program_with_unaligned_contract_prefix();
    assert_ne!(prefix_len as u64 & 0b11, 0);
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&program).expect("program loads");
    assert_eq!(vm.pc(), prefix_len as u64);
    assert!(vm.prepared_contains_pc(vm.pc()));
    vm.reset_predecode_misses();
    vm.run().expect("unaligned prefix program runs");
    assert_eq!(vm.predecode_misses(), 0);
}
#[test]
fn contract_return_integrity_is_cloned_and_cleared_at_reuse_boundaries() {
    set_banner_enabled(false);
    let (program, _) = program_with_unaligned_contract_prefix();
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&program).expect("contract program loads");
    assert!(vm.strict_return_integrity);
    vm.contract_return_stack.try_push(4).unwrap();
    vm.contract_return_stack.try_push(8).unwrap();
    vm.contract_outer_return_pc = Some(12);
    let cloned = vm.try_clone_snapshot().expect("fund VM snapshot");
    assert!(cloned.strict_return_integrity);
    assert_eq!(&cloned.contract_return_stack[..], &[4, 8]);
    assert_eq!(cloned.contract_outer_return_pc, Some(12));
    vm.reset().expect("private lifecycle cleanup succeeds");
    assert!(vm.contract_return_stack.is_empty());
    assert_eq!(vm.contract_outer_return_pc, None);
    vm.contract_return_stack.try_push(12).unwrap();
    vm.contract_outer_return_pc = Some(16);
    let template = vm
        .try_runtime_template()
        .expect("runtime template allocation fits test host");
    vm.reset_from_runtime_template(&template)
        .expect("warm VM retains its runtime-template geometry");
    assert!(vm.strict_return_integrity);
    assert!(vm.contract_return_stack.is_empty());
    assert_eq!(vm.contract_outer_return_pc, None);
    vm.contract_return_stack.try_push(16).unwrap();
    vm.contract_outer_return_pc = Some(20);
    vm.load_code(&crate::encoding::wide::encode_halt().to_le_bytes())
        .expect("raw code loads");
    assert!(!vm.strict_return_integrity);
    assert!(vm.contract_return_stack.is_empty());
    assert_eq!(vm.contract_outer_return_pc, None);
}
#[test]
fn child_call_return_slot_refusal_precedes_frame_and_gas_mutation() {
    let (program, prefix_len) = program_with_unaligned_contract_prefix();
    let mut vm = quiet_vm(100_000);
    vm.load_program(&program).unwrap();
    let gas = vm.remaining_gas();
    REFUSE_CALL_RETURN_RESERVATION_FOR_TEST.with(|refuse| refuse.set(true));
    assert!(matches!(
        vm.begin_child_call(prefix_len as u64),
        Err(VMError::ExecutionDeferred(
            crate::error::ExecutionDeferral::AllocationUnavailable
        ))
    ));
    assert_eq!(vm.remaining_gas(), gas);
    assert!(vm.memory.call_frames.is_empty());
    assert!(vm.contract_return_stack.is_empty());
    vm.preflight_contract_return().unwrap();
    vm.push_contract_return(12);
    assert_eq!(&vm.contract_return_stack[..], &[12]);
}
#[test]
fn funded_child_return_backing_defers_before_gas_and_keeps_its_charge() {
    let (program, prefix_len) = program_with_unaligned_contract_prefix();
    let budget = AllocationBudget::new(64 * 1024 * 1024);
    let mut vm = IVM::try_new_with_memory_budget(100_000, &budget).unwrap();
    vm.load_program(&program).unwrap();
    let occupied = budget.reserved_bytes();
    budget.set_limit_bytes(occupied);
    let gas = vm.remaining_gas();
    assert!(matches!(
        vm.begin_child_call(prefix_len as u64),
        Err(VMError::AllocationDeferred(_))
    ));
    assert_eq!(vm.remaining_gas(), gas);
    assert!(vm.memory.call_frames.is_empty());
    assert!(vm.contract_return_stack.is_empty());
    assert_eq!(budget.reserved_bytes(), occupied);

    budget.set_limit_bytes(occupied + MAX_CONTRACT_CALL_DEPTH * std::mem::size_of::<u64>());
    vm.preflight_contract_return().unwrap();
    vm.push_contract_return(12);
    assert_eq!(&vm.contract_return_stack[..], &[12]);
    assert_eq!(
        budget.reserved_bytes(),
        occupied + MAX_CONTRACT_CALL_DEPTH * std::mem::size_of::<u64>()
    );
    vm.reset().expect("private lifecycle cleanup succeeds");
    assert!(vm.contract_return_stack.is_empty());
    assert_eq!(
        budget.reserved_bytes(),
        occupied + MAX_CONTRACT_CALL_DEPTH * std::mem::size_of::<u64>()
    );
    drop(vm);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn fallible_worker_trace_copy_preserves_proof_logs_and_independent_buffers() {
    let mut vm = quiet_vm(1_000_000);
    let mut gpr = [0; 256];
    gpr[7] = 91;
    vm.constraints.record(Constraint::Zero { reg: 8, cycle: 1 });
    vm.trace_log.prepare_batch(1, 256, 0, None).unwrap();
    vm.trace_log.record_reserved(4, gpr, [false; 256]);
    vm.delta_trace.prepare_batch(1, 256, 0, None).unwrap();
    vm.delta_trace.record_reserved(4, gpr, [false; 256]);
    let reg_root = vm.registers.merkle_root();
    let mem_root = vm.memory.root();
    vm.step_log.prepare_cycles(1).expect("prepaid cycle row");
    vm.step_log.record_reserved(4, reg_root, mem_root);
    vm.pc_trace.prepare(1, None).unwrap();
    vm.pc_trace.record_reserved(4);
    vm.contract_return_stack.try_push(8).unwrap();

    let copied = vm
        .try_clone_snapshot()
        .expect("bounded diagnostic and proof logs");
    assert_eq!(copied.constraints.list, vm.constraints.list);
    assert!(copied.trace_log.entries().eq(vm.trace_log.entries()));
    assert!(copied.delta_trace.entries().eq(vm.delta_trace.entries()));
    assert_eq!(copied.step_log.as_slice(), vm.step_log.as_slice());
    assert_eq!(copied.pc_trace.as_slice(), vm.pc_trace.as_slice());
    assert_eq!(
        &copied.contract_return_stack[..],
        &vm.contract_return_stack[..]
    );
    vm.pc_trace.clear();
    vm.pc_trace.prepare(1, None).unwrap();
    vm.pc_trace.record_reserved(12);
    vm.trace_log.scrub();
    vm.trace_log.prepare_batch(1, 256, 0, None).unwrap();
    gpr[7] = 0;
    vm.trace_log.record_reserved(4, gpr, [false; 256]);
    assert_ne!(copied.pc_trace.as_slice(), vm.pc_trace.as_slice());
    assert!(!copied.trace_log.entries().eq(vm.trace_log.entries()));
}
fn sample_worker_diagnostic() -> super::super::diagnostic::TrapSnapshot {
    super::super::diagnostic::TrapSnapshot {
        fault: None,
        propagated: false,
        trap_kind: VmTrapKind::MemoryFault,
        pc: 32,
        source_index: Some(0),
        budget: VmBudgetSnapshot {
            gas_limit: 100,
            gas_remaining: 40,
            gas_used: 60,
            cycles: 10,
            max_cycles: 100,
            stack_limit_bytes: 4096,
            stack_bytes_used: 64,
        },
        entrypoint_pc: Some(8),
        opcode: Some(7),
        syscall: None,
        predecoded_loaded: true,
        predecoded_hit: Some(true),
    }
}
#[test]
fn fallible_worker_metadata_copy_preserves_nested_fields_and_ownership() {
    let mut vm = quiet_vm(1_000_000);
    let source = EmbeddedSourceLocation {
        source_path: Some("contracts/wallet.ko".to_owned()),
        source_id: 3,
        byte_start: 11,
        byte_end: 23,
        line: 12,
        column: 4,
    };
    vm.contract_debug = Some(EmbeddedContractDebugInfoV1 {
        source_map: vec![EmbeddedSourceMapEntryV1 {
            function_name: "transfer".to_owned(),
            pc_start: 8,
            pc_end: 40,
            source: source.clone(),
        }],
        budget_report: vec![EmbeddedFunctionBudgetReportV1 {
            function_name: "transfer".to_owned(),
            pc_start: 8,
            pc_end: 40,
            bytecode_bytes: 32,
            bytecode_words: 8,
            frame_bytes: 64,
            jump_span_words: 0,
            jump_range_risk: false,
            source: Some(source),
        }],
    });
    vm.last_diagnostic = Some(sample_worker_diagnostic());
    let copied = vm
        .try_clone_snapshot()
        .expect("bounded debug and diagnostic snapshot");
    assert_eq!(copied.contract_debug, vm.contract_debug);
    assert_eq!(copied.last_diagnostic, vm.last_diagnostic);
    assert!(contract_debug_allocation_bytes(vm.contract_debug.as_ref().unwrap()).unwrap() > 0);
    assert_eq!(copied.last_diagnostic(), vm.last_diagnostic());
    vm.contract_debug.as_mut().unwrap().source_map[0]
        .function_name
        .push('X');
    assert_ne!(copied.contract_debug, vm.contract_debug);
    assert_eq!(copied.last_diagnostic, vm.last_diagnostic);
    assert_ne!(copied.last_diagnostic(), vm.last_diagnostic());
    drop(vm);
    assert_eq!(
        copied.last_diagnostic().unwrap().context.current_function,
        Some("transfer")
    );
    let mut bytes = isize::MAX as usize;
    assert!(checked_allocation_bytes(&mut bytes, 1).is_err());
}
#[test]
fn worker_nested_private_range_snapshots_refuse_and_retry_without_mutation() {
    let mut vm = quiet_vm(1_000_000);
    vm.private_memory_bytes.try_insert(10..20).unwrap();
    vm.private_memory_bytes.try_insert(30..40).unwrap();
    let original = vm.private_memory_bytes.try_clone().unwrap();
    REFUSE_DIAGNOSTIC_SNAPSHOT_FOR_TEST.with(|refuse| refuse.set(true));
    let refused = vm.try_clone_snapshot();
    REFUSE_DIAGNOSTIC_SNAPSHOT_FOR_TEST.with(|refuse| refuse.set(false));
    assert!(matches!(
        refused,
        Err(VMError::ExecutionDeferred(
            crate::error::ExecutionDeferral::AllocationUnavailable
        ))
    ));
    assert_eq!(vm.private_memory_bytes, original);
    let worker = vm
        .try_clone_snapshot()
        .expect("nested worker copies fit test host");
    assert_eq!(worker.private_memory_bytes, original);
    vm.private_memory_bytes.try_remove(15..35).unwrap();
    assert_eq!(worker.private_memory_bytes, original);
}
#[test]
fn worker_private_range_copy_refusal_leaves_source_intact() {
    let mut vm = quiet_vm(1_000);
    vm.private_memory_bytes.try_insert(10..20).unwrap();
    let before = vm.private_memory_bytes.try_clone().unwrap();
    PrivateMemoryRanges::refuse_next_copy_for_testing();
    assert!(matches!(
        vm.try_clone_snapshot(),
        Err(VMError::ExecutionDeferred(
            crate::error::ExecutionDeferral::AllocationUnavailable
        ))
    ));
    assert_eq!(vm.private_memory_bytes, before);
    assert_eq!(
        vm.try_clone_snapshot().unwrap().private_memory_bytes,
        before
    );
}
#[test]
fn idle_retention_rejects_live_trace_allocations_without_discarding_them() {
    let mut vm = quiet_vm(1_000_000);
    vm.constraints.record(Constraint::Zero { reg: 7, cycle: 1 });
    vm.trace_log.prepare_batch(1, 256, 0, None).unwrap();
    vm.trace_log.record_reserved(4, [0; 256], [false; 256]);
    let retained_trace = vm.trace_log.try_clone_allocation(None).unwrap();
    assert!(!vm.try_retain_cache_allocations());
    assert!(vm.trace_log.entries().eq(retained_trace.entries()));
    assert_eq!(vm.constraints.list.len(), 1);
}
#[test]
fn try_new_preserves_public_gas_limit_with_charged_memory() {
    let vm = IVM::try_new(257).expect("the default VM memory fits the test host");
    assert_eq!(vm.remaining_gas(), 257);
    assert!(vm.memory.stack_limit() > 0);
    assert!(vm.registers.merkle_path(255).is_ok());
}
#[test]
fn funded_vm_image_leaves_bitmaps_and_register_tree_reserve_before_construction_and_refund() {
    let gas_limit = 257;
    let stack_limit = IvmConfig::adaptive(gas_limit).stack_limit_for_gas();
    let image_bytes = Memory::image_bytes_for_stack_limit(stack_limit).unwrap();
    let leaf_bytes = image_bytes.div_ceil(32) * 32;
    let node_bytes = iroha_crypto::MerkleTree::<[u8; 32]>::repeated_sha256_node_allocation_bytes(
        image_bytes.div_ceil(32),
    )
    .unwrap();
    let bitmap_bytes = 2 * image_bytes.div_ceil(32).div_ceil(64) * 8;
    let register_bytes = Registers::initial_tree_allocation_bytes().unwrap();
    let insufficient =
        AllocationBudget::new(image_bytes + leaf_bytes + node_bytes + bitmap_bytes - 1);
    assert!(matches!(
        IVM::try_new_with_memory_budget(gas_limit, &insufficient),
        Err(VMError::AllocationDeferred(
            iroha_allocation::AllocationRefusal::ExceedsLimit { .. }
        ))
    ));
    assert_eq!(insufficient.reserved_bytes(), 0);

    let tree_insufficient = AllocationBudget::new(
        image_bytes + leaf_bytes + node_bytes + bitmap_bytes + register_bytes - 1,
    );
    assert!(matches!(
        IVM::try_new_with_memory_budget(gas_limit, &tree_insufficient),
        Err(VMError::AllocationDeferred(
            iroha_allocation::AllocationRefusal::Capacity { .. }
        ))
    ));
    assert_eq!(tree_insufficient.reserved_bytes(), 0);

    let shell_bytes = zk::SharedRegLog::allocation_layout().size();
    let total_bytes =
        image_bytes + leaf_bytes + node_bytes + bitmap_bytes + register_bytes + shell_bytes;
    let shell_insufficient = AllocationBudget::new(total_bytes - 1);
    assert!(matches!(
        IVM::try_new_with_memory_budget(gas_limit, &shell_insufficient),
        Err(VMError::AllocationDeferred(iroha_allocation::AllocationRefusal::Capacity {
            requested_bytes, ..
        })) if requested_bytes == shell_bytes
    ));
    assert_eq!(shell_insufficient.reserved_bytes(), 0);
    let budget = AllocationBudget::new(total_bytes);
    let mut vm = IVM::try_new_with_memory_budget(gas_limit, &budget).unwrap();
    assert_eq!(budget.reserved_bytes(), total_bytes);
    assert_eq!(vm.remaining_gas(), gas_limit);
    assert_eq!(vm.memory.stack_limit(), stack_limit);
    assert!(matches!(
        IVM::try_new_with_memory_budget(gas_limit, &budget),
        Err(VMError::AllocationDeferred(
            iroha_allocation::AllocationRefusal::Capacity { .. }
        ))
    ));
    let code = crate::encoding::wide::encode_halt().to_le_bytes();
    vm.load_code(&code).unwrap();
    assert_eq!(budget.reserved_bytes(), total_bytes);
    let mut ordinary = IVM::try_new(gas_limit).unwrap();
    ordinary.load_code(&code).unwrap();
    // The replacement shell overlaps the old one, then retires it before
    // unprepared fetch allocates separate read rows. Admit the exact peak of
    // these sequential stages without changing the construction charge.
    let read_bytes = 4 * std::mem::size_of::<crate::AccessRange>();
    allow_exact_invocation_shell(&mut vm, &budget);
    budget.set_limit_bytes(total_bytes + shell_bytes.max(read_bytes));
    vm.run().unwrap();
    ordinary.run().unwrap();
    assert_eq!(vm.remaining_gas(), ordinary.remaining_gas());
    assert_eq!(vm.memory.current_root(), ordinary.memory.current_root());
    assert_eq!(vm.registers.merkle_root(), ordinary.registers.merkle_root());
    vm.reset().expect("private lifecycle cleanup succeeds");
    ordinary
        .reset()
        .expect("private lifecycle cleanup succeeds");
    assert_eq!(vm.registers.merkle_root(), ordinary.registers.merkle_root());
    assert_eq!(budget.reserved_bytes(), total_bytes + read_bytes);
    drop(vm);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn snapshot_refusal_preserves_original_vm() {
    let mut vm = quiet_vm(1_000_000);
    vm.set_register(7, 91);
    let before_gas = vm.remaining_gas();
    REFUSE_WORKER_SNAPSHOT_FOR_TEST.with(|refuse| refuse.set(true));
    let refused = vm.try_clone_snapshot();
    REFUSE_WORKER_SNAPSHOT_FOR_TEST.with(|refuse| refuse.set(false));
    assert!(matches!(
        refused,
        Err(VMError::ExecutionDeferred(
            crate::error::ExecutionDeferral::AllocationUnavailable
        ))
    ));
    assert_eq!(vm.remaining_gas(), before_gas);
    assert_eq!(vm.register(7), 91);
    vm.try_clone_snapshot().expect("snapshot fits retry");
}

#[test]
fn diagnostic_snapshot_refusal_preserves_original_diagnostic() {
    let mut vm = quiet_vm(1_000_000);
    vm.last_diagnostic = Some(sample_worker_diagnostic());
    let before_gas = vm.remaining_gas();
    REFUSE_DIAGNOSTIC_SNAPSHOT_FOR_TEST.with(|refuse| refuse.set(true));
    let refused = vm.try_clone_snapshot();
    REFUSE_DIAGNOSTIC_SNAPSHOT_FOR_TEST.with(|refuse| refuse.set(false));
    assert!(matches!(
        refused,
        Err(VMError::ExecutionDeferred(
            crate::error::ExecutionDeferral::AllocationUnavailable
        ))
    ));
    assert_eq!(vm.remaining_gas(), before_gas);
    assert_eq!(vm.last_diagnostic, Some(sample_worker_diagnostic()));
    vm.try_clone_snapshot().expect("snapshot fits retry");
}

#[test]
fn trace_snapshot_refusal_preserves_original_trace() {
    let mut vm = quiet_vm(1_000_000);
    vm.pc_trace.prepare(1, None).unwrap();
    vm.pc_trace.record_reserved(4);
    let before_gas = vm.remaining_gas();
    REFUSE_TRACE_SNAPSHOT_FOR_TEST.with(|refuse| refuse.set(true));
    let refused = vm.try_clone_snapshot();
    REFUSE_TRACE_SNAPSHOT_FOR_TEST.with(|refuse| refuse.set(false));
    assert!(matches!(
        refused,
        Err(VMError::ExecutionDeferred(
            crate::error::ExecutionDeferral::AllocationUnavailable
        ))
    ));
    assert_eq!(vm.remaining_gas(), before_gas);
    assert_eq!(vm.pc_trace.as_slice(), &[4]);
    vm.try_clone_snapshot().expect("snapshot fits retry");
}

#[test]
fn snapshot_refusal_keeps_the_host_and_allows_retry() {
    let mut vm = quiet_vm(1_000_000);
    vm.set_host(DefaultHost::default());
    let before_gas = vm.remaining_gas();
    REFUSE_WORKER_SNAPSHOT_FOR_TEST.with(|refuse| refuse.set(true));
    let refused = vm.try_clone_snapshot();
    REFUSE_WORKER_SNAPSHOT_FOR_TEST.with(|refuse| refuse.set(false));
    assert!(matches!(
        refused,
        Err(VMError::ExecutionDeferred(
            crate::error::ExecutionDeferral::AllocationUnavailable
        ))
    ));
    assert_eq!(vm.remaining_gas(), before_gas);
    assert!(vm.host_mut_any().is_some());
    vm.try_clone_snapshot().expect("snapshot fits retry");
}

#[test]
fn funded_read_refusal_preserves_output_privacy_gas_and_exact_credit_retry() {
    let budget = AllocationBudget::new(64 * 1024 * 1024);
    let mut vm = IVM::try_new_with_memory_budget(1_000, &budget).unwrap();
    let mut local = quiet_vm(1_000);
    let program = program_with_imm(7);
    vm.load_program(&program).unwrap();
    local.load_program(&program).unwrap();
    vm.memory
        .preload_input(0, &[1, 2, 3, 4, 5, 6, 7, 8])
        .unwrap();
    local
        .memory
        .preload_input(0, &[1, 2, 3, 4, 5, 6, 7, 8])
        .unwrap();
    vm.memory.commit();
    local.memory.commit();
    for _ in 0..4 {
        vm.memory.load_u8(Memory::OUTPUT_START).unwrap();
    }
    let occupied = budget.reserved_bytes();
    let gas = vm.remaining_gas();
    let pc = vm.pc;
    let root = vm.memory.current_root();
    let privacy = vm.private_memory_bytes.pairs_for_testing().to_vec();
    let mut output = [0xa5; 8];
    budget.set_limit_bytes(0);
    assert!(matches!(
        vm.memory.load_bytes(Memory::INPUT_START, &mut output),
        Err(VMError::AllocationDeferred(_))
    ));
    assert_eq!(output, [0xa5; 8]);
    // Existing history is observed without a new funded snapshot under refusal.
    assert_eq!(
        vm.memory.inspect_region(Memory::INPUT_START, 8).unwrap(),
        &[1, 2, 3, 4, 5, 6, 7, 8]
    );
    // Address/alignment errors still precede local allocation admission.
    assert!(matches!(
        vm.memory.load_u8(u64::MAX),
        Err(VMError::MemoryAccessViolation { .. })
    ));
    assert!(matches!(
        vm.memory.load_u64(Memory::INPUT_START + 1),
        Err(VMError::MisalignedAccess { .. })
    ));
    assert_eq!(vm.remaining_gas(), gas);
    assert_eq!(vm.pc, pc);
    assert_eq!(vm.memory.current_root(), root);
    assert_eq!(vm.private_memory_bytes.pairs_for_testing(), privacy);
    assert_eq!(budget.reserved_bytes(), occupied);
    let read_bytes = 8 * std::mem::size_of::<crate::AccessRange>();
    budget.set_limit_bytes(occupied + read_bytes);
    vm.memory
        .load_bytes(Memory::INPUT_START, &mut output)
        .unwrap();
    assert_eq!(output, [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(
        vm.memory.load_u64(Memory::INPUT_START),
        local.memory.load_u64(Memory::INPUT_START)
    );
    assert_eq!(budget.reserved_bytes(), occupied + read_bytes / 2);
    allow_exact_invocation_shell(&mut vm, &budget);
    vm.run().unwrap();
    local.run().unwrap();
    assert_eq!(vm.remaining_gas(), local.remaining_gas());
    assert_eq!(vm.memory.current_root(), local.memory.current_root());
    assert_eq!(vm.registers.merkle_root(), local.registers.merkle_root());
    drop(vm);
    assert_eq!(budget.reserved_bytes(), 0);
}
#[test]
fn executed_runtime_is_retainable_after_template_reset() {
    set_banner_enabled(false);
    let program = program_with_imm(7);
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&program).expect("program loads");
    let template = vm
        .try_runtime_template()
        .expect("runtime template allocation fits test host");
    vm.memory.store_u64(Memory::STACK_START, 0x5678).unwrap();
    vm.run().expect("program runs to halt");
    vm.reset_from_runtime_template(&template)
        .expect("warm VM retains its runtime-template geometry");
    // Execution marks the fixed memory image unmeasured; the reset runtime
    // must still be admissible to an idle runtime pool.
    assert!(template.try_retain_cache_allocations());
    assert!(vm.try_retain_cache_allocations());
    vm.activate_cached_runtime();
    vm.run().expect("reactivated runtime runs again");
    vm.reset_from_runtime_template(&template).unwrap();
    assert!(vm.try_retain_cache_allocations());
}
