//! Actual lifecycle owners under exhausted ordinary credit and bounded diagnostics.

use super::*;
use crate::{
    Memory,
    encoding::wide,
    error::ExecutionDeferral,
    execution_memory_recorder::{
        DiagnosticMemoryAccess, DiagnosticMemoryAccessKind, DiagnosticMemoryAccessRecorder,
        DiagnosticMemoryPrivacyTag,
    },
    metadata::ProgramMetadata,
};
use iroha_allocation::AllocationBudget;

const SECRET: u64 = 0x1122_3344_5566_7788;
const PUBLIC: u64 = 0xAABB_CCDD;

#[derive(Clone, Copy, Debug)]
enum Transition {
    Reset,
    Disable,
    RawLoad,
    ArtifactLoad,
    PreparedLoad,
}

fn transition(vm: &mut IVM, action: Transition) -> Result<(), VMError> {
    match action {
        Transition::Reset => vm.reset(),
        Transition::Disable => vm.set_zk_mode(false),
        Transition::RawLoad => vm.load_code(&wide::encode_halt().to_le_bytes()),
        Transition::PreparedLoad => {
            let (code, _) = kotodama_lang::compiler::Compiler::new()
                .compile_source_with_manifest(
                    "seiyaku Cleanup { view fn main() authorize(anyone) -> bool { true } }",
                )
                .unwrap();
            let prepared = crate::PreparedContract::prepare(std::sync::Arc::from(code)).unwrap();
            vm.load_prepared(&prepared)
        }
        Transition::ArtifactLoad => {
            let mut code = ProgramMetadata::default().encode();
            code.extend_from_slice(&wide::encode_halt().to_le_bytes());
            vm.load_program(&code)
        }
    }
}

fn seed(vm: &mut IVM) {
    vm.load_code(&wide::encode_halt().to_le_bytes()).unwrap();
    vm.set_zk_mode(true).unwrap();
    vm.set_register(2, SECRET);
    vm.registers.set_tag(2, true);
    vm.set_register(7, PUBLIC);
    for start in [Memory::STACK_START, Memory::STACK_START + 32] {
        vm.memory.store_u64(start, SECRET).unwrap();
        vm.private_memory_bytes
            .try_insert(start..start + 8)
            .unwrap();
    }
    vm.memory
        .store_u64(Memory::STACK_START + 16, PUBLIC)
        .unwrap();
    vm.memory.clear_tracking();
}

fn local_vm() -> IVM {
    let mut vm = IVM::new(10_000);
    seed(&mut vm);
    vm
}

fn recorder(rows: usize) -> DiagnosticMemoryAccessRecorder {
    let budget = AllocationBudget::new(rows * std::mem::size_of::<DiagnosticMemoryAccess>());
    let recorder = DiagnosticMemoryAccessRecorder::try_new(rows, &budget).unwrap();
    recorder.begin_run(true).unwrap();
    recorder
}

fn assert_secret_bytes(vm: &IVM) {
    for start in [Memory::STACK_START, Memory::STACK_START + 32] {
        assert_eq!(
            vm.memory.inspect_region(start, 8).unwrap(),
            SECRET.to_le_bytes()
        );
    }
}

#[test]
fn exhausted_write_credit_does_not_block_private_reset_or_mode_transition() {
    for action in [Transition::Reset, Transition::Disable] {
        let budget = AllocationBudget::new(64 * 1024 * 1024);
        let mut funded = IVM::try_new_with_memory_budget(10_000, &budget).unwrap();
        seed(&mut funded);
        let mut ordinary = local_vm();
        let occupied = budget.reserved_bytes();
        budget.set_limit_bytes(0);
        let gas = funded.remaining_gas();
        transition(&mut funded, action).unwrap();
        transition(&mut ordinary, action).unwrap();
        assert_eq!(funded.memory.root(), ordinary.memory.root());
        assert_eq!(funded.registers.snapshot(), ordinary.registers.snapshot());
        assert_eq!(
            funded.registers.snapshot_tags(),
            ordinary.registers.snapshot_tags()
        );
        assert_eq!(funded.remaining_gas(), gas);
        assert_eq!(budget.reserved_bytes(), occupied);
        assert!(funded.private_memory_bytes.is_empty());
        assert!(!funded.registers.has_private());
        assert_eq!(
            funded
                .memory
                .inspect_region(Memory::STACK_START, 8)
                .unwrap(),
            [0; 8]
        );
        assert_eq!(
            funded
                .memory
                .inspect_region(Memory::STACK_START + 16, 8)
                .unwrap(),
            PUBLIC.to_le_bytes()
        );
        drop(funded);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn diagnostic_refusal_precedes_every_lifecycle_mutation_and_retry() {
    for action in [
        Transition::Reset,
        Transition::Disable,
        Transition::RawLoad,
        Transition::ArtifactLoad,
        Transition::PreparedLoad,
    ] {
        let mut vm = local_vm();
        let ranges = vm.private_memory_bytes.try_clone().unwrap();
        let root = vm.memory.root();
        let registers = vm.registers.snapshot();
        let tags = vm.registers.snapshot_tags();
        let gas = vm.remaining_gas();
        let epoch = vm.proof_state_epoch;
        let pc = vm.pc;
        let max_cycles = vm.max_cycles;
        let diagnostic = recorder(15);
        vm.memory
            .install_diagnostic_access_recorder(diagnostic.shared())
            .unwrap();
        assert_eq!(
            transition(&mut vm, action),
            Err(VMError::ExecutionDeferred(
                ExecutionDeferral::ActiveMemoryCapacity
            )),
            "{action:?}"
        );
        assert_eq!(diagnostic.len(), 0);
        assert_eq!(vm.private_memory_bytes, ranges);
        assert_eq!(vm.memory.root(), root);
        assert_eq!(vm.registers.snapshot(), registers);
        assert_eq!(vm.registers.snapshot_tags(), tags);
        assert_eq!(vm.remaining_gas(), gas);
        assert_eq!(vm.proof_state_epoch, epoch);
        assert_eq!(vm.pc, pc);
        assert_eq!(vm.max_cycles, max_cycles);
        assert!(vm.zk_mode_enabled());
        assert_secret_bytes(&vm);
        vm.memory.clear_diagnostic_access_recorder();
        transition(&mut vm, action).unwrap();
        assert!(vm.private_memory_bytes.is_empty());
        assert!(!vm.registers.has_private());
    }
}

#[test]
fn invalid_range_rejects_before_zeroing_an_earlier_valid_range() {
    for action in [
        Transition::Reset,
        Transition::Disable,
        Transition::RawLoad,
        Transition::ArtifactLoad,
        Transition::PreparedLoad,
    ] {
        let mut vm = local_vm();
        let invalid = vm.memory.stack_top();
        vm.private_memory_bytes
            .try_insert(invalid..invalid + 1)
            .unwrap();
        let ranges = vm.private_memory_bytes.try_clone().unwrap();
        let registers = vm.registers.snapshot();
        let tags = vm.registers.snapshot_tags();
        let root = vm.memory.root();
        assert_eq!(
            transition(&mut vm, action),
            Err(VMError::ExecutionDeferred(
                ExecutionDeferral::LocalInvariantViolation,
            ))
        );
        assert_secret_bytes(&vm);
        assert_eq!(vm.private_memory_bytes, ranges);
        assert_eq!(vm.registers.snapshot(), registers);
        assert_eq!(vm.registers.snapshot_tags(), tags);
        assert_eq!(vm.memory.root(), root);
        assert!(vm.zk_mode_enabled());
    }
}

#[test]
fn successful_scrub_records_complete_zero_rows_and_preserves_commitment() {
    let mut vm = local_vm();
    let mut ordinary = local_vm();
    let diagnostic = recorder(16);
    vm.memory
        .install_diagnostic_access_recorder(diagnostic.shared())
        .unwrap();
    vm.set_zk_mode(false).unwrap();
    ordinary.set_zk_mode(false).unwrap();
    assert_eq!(vm.memory.root(), ordinary.memory.root());
    diagnostic.with_records(|rows| {
        assert_eq!(rows.len(), 16);
        for (index, row) in rows.iter().enumerate() {
            let offset = index % 8;
            assert_eq!(
                row.address,
                Memory::STACK_START + (index / 8) as u64 * 32 + offset as u64
            );
            assert_eq!(row.access_ordinal, (index / 8) as u64);
            assert_eq!(row.byte_offset, offset as u32);
            assert_eq!(row.before, SECRET.to_le_bytes()[offset]);
            assert_eq!(row.after, 0);
            assert_eq!(row.kind, DiagnosticMemoryAccessKind::PrivateReset);
            assert_eq!(row.privacy_tag, DiagnosticMemoryPrivacyTag::Public);
        }
    });
    assert!(vm.memory.try_write_log_snapshot().unwrap().is_empty());
    vm.memory.clear_diagnostic_access_recorder();
    assert_eq!(vm.register(2), 0);
    assert_eq!(vm.register(7), PUBLIC);
    assert_eq!(vm.registers.merkle_root(), ordinary.registers.merkle_root());
}

#[test]
fn private_heap_envelope_and_stack_are_both_erased_without_log_growth() {
    let mut vm = local_vm();
    let heap = vm.alloc_host_private_tlv(&[0x91, 0x92, 0x93]).unwrap();
    vm.set_zk_mode(false).unwrap();
    assert_eq!(vm.memory.inspect_region(heap, 3).unwrap(), &[0; 3]);
    assert_eq!(
        vm.memory.inspect_region(Memory::STACK_START, 8).unwrap(),
        &[0; 8]
    );
    assert!(vm.memory.try_write_log_snapshot().unwrap().is_empty());
}

#[test]
fn owner_cleanup_keeps_shared_private_template_and_restores_dirty_chunks() {
    let mut vm = local_vm();
    let template = vm.try_runtime_template().unwrap();
    let borrower = template.clone();
    let initial_root = vm.memory.root();
    vm.set_zk_mode(false).unwrap();
    assert_ne!(vm.memory.root(), initial_root);
    assert_eq!(
        borrower
            .data()
            .memory
            .inspect_region(Memory::STACK_START, 8)
            .unwrap(),
        SECRET.to_le_bytes()
    );
    vm.reset_from_runtime_template(&borrower).unwrap();
    assert_eq!(vm.memory.root(), initial_root);
    assert_secret_bytes(&vm);
    assert!(vm.registers.tag(2));
    assert_eq!(vm.register(2), SECRET);
}
