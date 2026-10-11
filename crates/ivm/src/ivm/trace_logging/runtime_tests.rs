//! Ordinary execution boundaries for prepaid runtime and completed-cycle traces.
//!
//! These tests exercise the production interpreter and its original allocation owner.

use super::{
    tests::{GAS, LIMIT, state},
    *,
};
use crate::{
    PreparedArgumentRecord, ProgramMetadata,
    encoding::wide::{encode_halt, encode_ri, encode_rr, encode_syscallx},
    host::{DefaultHost, IVMHost},
    instruction::wide::{arithmetic as a, crypto as v},
};
use kotodama_lang::compiler::{Compiler, CompilerOptions};
use std::{any::Any, cell::Cell, sync::Arc};

fn generic(original: &AllocationBudget, words: &[u32], mode: TraceMode, cycles: u64) -> IVM {
    let mut image = ProgramMetadata {
        mode: crate::ivm_mode::ZK | crate::ivm_mode::VECTOR,
        vector_length: 64,
        max_cycles: cycles,
        ..ProgramMetadata::default()
    }
    .encode();
    image.extend(words.iter().flat_map(|word| word.to_le_bytes()));
    let mut vm = IVM::try_new_with_memory_budget(GAS, original).unwrap();
    vm.load_program(&image).unwrap();
    vm.set_zk_trace_enabled(cycles != 0);
    vm.set_trace_mode(mode);
    vm
}

struct UnreachedRootHost {
    metadata: Cell<usize>,
    quotes: Cell<usize>,
    calls: usize,
}
impl IVMHost for UnreachedRootHost {
    fn prepared_entrypoint_arguments(&self) -> Option<PreparedArgumentRecord> {
        self.metadata.set(self.metadata.get() + 1);
        None
    }
    fn prepare_syscall(&self, _: u32, _: &IVM) -> Result<u64, VMError> {
        self.quotes.set(self.quotes.get() + 1);
        Err(VMError::AssertionFailed)
    }
    fn syscall(&mut self, _: u32, _: &mut IVM) -> Result<u64, VMError> {
        self.calls += 1;
        Err(VMError::AssertionFailed)
    }
    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

#[test]
fn first_runtime_row_refuses_before_strict_default_argument_metadata_or_effects() {
    let bytes = Compiler::new_with_options(CompilerOptions {
        force_zk: true,
        max_cycles: 64,
        ..CompilerOptions::default()
    })
    .compile_source("seiyaku TraceRoot { view fn main(bool ready) authorize(anyone) -> bool { return ready; } }")
    .unwrap();
    let contract = crate::prepare_contract(Arc::<[u8]>::from(bytes)).unwrap();
    for mode in [TraceMode::PcOnly, TraceMode::DeltaRegisters] {
        let original = AllocationBudget::new(LIMIT);
        let mut vm = IVM::try_new_with_memory_budget(GAS, &original).unwrap();
        vm.load_prepared(&contract).unwrap();
        vm.select_entrypoint("main").unwrap();
        vm.set_zk_trace_enabled(false);
        vm.set_trace_mode(mode);
        vm.registers.set(7, 41);
        vm.cycles = 17;
        vm.halted = true;
        let before = state(&vm);
        let borrowed_logger = vm.proof_register_log_handle().unwrap();
        let baseline = original.reserved_bytes();
        let shell = zk::SharedRegLog::allocation_layout().size();
        original.set_limit_bytes(baseline + shell);
        let mut host = UnreachedRootHost {
            metadata: Cell::new(0),
            quotes: Cell::new(0),
            calls: 0,
        };
        assert!(matches!(
            vm.run_with_host(&mut host),
            Err(VMError::AllocationDeferred(
                AllocationRefusal::Capacity { .. }
            ))
        ));
        assert_eq!(state(&vm), before);
        assert_eq!(
            (host.metadata.get(), host.quotes.get(), host.calls),
            (0, 0, 0)
        );
        assert!(vm.trace_pcs().is_empty());
        assert!(vm.delta_register_trace().is_empty());
        assert_eq!(original.reserved_bytes(), baseline + shell);
        drop(vm);
        assert_eq!(original.reserved_bytes(), shell);
        drop(borrowed_logger);
        assert_eq!(original.reserved_bytes(), 0);
    }
}

#[test]
fn strict_root_keeps_the_post_clear_epoch_and_initial_argument_observation() {
    let bytes = Compiler::new_with_options(CompilerOptions {
        force_zk: true,
        max_cycles: 64,
        ..CompilerOptions::default()
    })
    .compile_source("seiyaku TraceRoot { view fn main() authorize(anyone) {} }")
    .unwrap();
    let contract = crate::prepare_contract(Arc::<[u8]>::from(bytes)).unwrap();
    let original = AllocationBudget::new(LIMIT);
    let mut vm = IVM::try_new_with_memory_budget(GAS, &original).unwrap();
    vm.load_prepared(&contract).unwrap();
    vm.select_entrypoint("main").unwrap();
    vm.set_zk_trace_enabled(false);
    vm.set_trace_mode(TraceMode::DeltaRegisters);
    let epoch = vm.proof_state_epoch;
    let entry_pc = vm.pc;
    let code_end = vm.memory.code_len();
    let stack_top = vm.memory.stack_top();
    vm.run_with_host(&mut DefaultHost::default()).unwrap();
    // Exactly the invocation clear advances custody; root argument installation
    // is observed by the first already funded row under that same epoch.
    assert_eq!(vm.proof_state_epoch, epoch.wrapping_add(1));
    let first = vm.delta_register_trace().entry(0).unwrap();
    assert_eq!(first.pc, entry_pc);
    assert_eq!(first.changes.len(), 256);
    assert_eq!(first.changes[1], (1, code_end, false));
    assert_eq!(first.changes[31], (31, stack_top, false));
    drop(vm);
    assert_eq!(original.reserved_bytes(), 0);
}

#[test]
fn original_vector_changes_precede_narrow_zero_destination_and_terminal_observations() {
    let original = AllocationBudget::new(LIMIT);
    let mut vm = generic(
        &original,
        &[
            encode_rr(v::VADD32, 2, 0, 1),
            encode_ri(a::ADDI, 0, 0, 0),
            encode_halt(),
        ],
        TraceMode::DeltaRegisters,
        8,
    );
    for register in 32..160 {
        vm.registers.set(register, register as u64);
    }
    let initial = vm.pc;
    vm.run_with_host(&mut DefaultHost::default()).unwrap();
    let trace = vm.delta_register_trace();
    assert_eq!(trace.len(), 3);
    assert_eq!(trace.entry(0).unwrap().pc, initial);
    assert_eq!(trace.entry(0).unwrap().changes.len(), 256);
    assert_eq!(trace.entry(1).unwrap().changes.len(), 64);
    assert!(
        trace
            .entry(1)
            .unwrap()
            .changes
            .iter()
            .all(|(r, _, _)| (160..224).contains(r))
    );
    assert!(trace.entry(2).unwrap().changes.is_empty());
    assert_eq!(vm.trace_log.len(), 8);
    assert!(
        vm.trace_log
            .entries()
            .skip(1)
            .all(|row| row.changes.is_empty())
    );
    drop(vm);
    assert_eq!(original.reserved_bytes(), 0);
}

#[test]
fn ordinary_multicycle_overshoot_is_fully_admitted_before_the_first_effect() {
    for (opcode, cycles) in [(a::DIV_CEIL, 12), (a::GCD, 12), (a::ISQRT, 6), (a::MEAN, 3)] {
        let original = AllocationBudget::new(LIMIT);
        let mut vm = generic(
            &original,
            &[encode_rr(opcode, 7, 5, 6), encode_halt()],
            TraceMode::DeltaRegisters,
            1,
        );
        vm.registers.set(5, 19);
        vm.registers.set(6, 3);
        let initial = vm.pc;
        assert_eq!(
            vm.run_with_host(&mut DefaultHost::default()),
            Err(VMError::ExceededMaxCycles)
        );
        assert_eq!(vm.cycles, cycles);
        assert_eq!(vm.pc, initial + 4);
        assert_eq!(vm.trace_log.len(), cycles as usize);
        assert!(vm.trace_log.entries().all(|row| row.pc == initial + 4));
        assert_eq!(vm.trace_log.entry(0).unwrap().changes.len(), 256);
        assert!(
            vm.trace_log
                .entries()
                .skip(1)
                .all(|row| row.changes.is_empty())
        );
        // The next instruction was never attempted, so its pre-fetch row stays unused.
        assert_eq!(vm.delta_register_trace().len(), 1);
        drop(vm);
        assert_eq!(original.reserved_bytes(), 0);
    }
}

struct NetChangesHost;
impl IVMHost for NetChangesHost {
    fn prepare_syscall(&self, _: u32, _: &IVM) -> Result<u64, VMError> {
        Ok(0)
    }
    fn syscall(&mut self, _: u32, vm: &mut IVM) -> Result<u64, VMError> {
        for register in 1..256 {
            if register % 2 == 0 && register != 10 {
                if vm.zk_mode_enabled() {
                    vm.registers.set_tag(register, true);
                }
            } else {
                vm.registers.set(register, 41);
            }
        }
        // ABORT declares public r10. Change its value, preserving that required
        // tag; all other even registers exercise tag-only net changes. This
        // test host does not request abort.
        Ok(0)
    }
    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

#[test]
fn actual_syscall_value_and_tag_only_net_changes_use_one_public_full_span() {
    let original = AllocationBudget::new(LIMIT);
    let mut vm = generic(
        &original,
        &[
            encode_syscallx(crate::syscalls::SYSCALL_ABORT),
            encode_ri(a::ADDI, 0, 0, 0),
            encode_halt(),
        ],
        TraceMode::DeltaRegisters,
        8,
    );
    vm.run_with_host(&mut NetChangesHost).unwrap();
    assert_eq!(
        vm.delta_register_trace().entry(1).unwrap().changes.len(),
        255
    );
    assert!(
        vm.delta_register_trace()
            .entry(2)
            .unwrap()
            .changes
            .is_empty()
    );
    assert_eq!(vm.registers.snapshot()[0], 0);
    assert!(!vm.registers.snapshot_tags()[0]);
    assert_eq!(vm.registers.snapshot()[10], 41);
    assert!(!vm.registers.snapshot_tags()[10]);
    assert!(
        vm.delta_register_trace()
            .entry(1)
            .unwrap()
            .changes
            .contains(&(2, 0, true))
    );
}

struct TraceMutatingHost;
impl IVMHost for TraceMutatingHost {
    fn prepare_syscall(&self, _: u32, _: &IVM) -> Result<u64, VMError> {
        Ok(0)
    }
    fn syscall(&mut self, _: u32, vm: &mut IVM) -> Result<u64, VMError> {
        vm.set_trace_mode(TraceMode::PcOnly);
        Ok(0)
    }
    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

#[test]
fn actual_non_zk_host_mode_replacement_is_local_refusal_not_unfunded_append() {
    let original = AllocationBudget::new(LIMIT);
    let mut vm = generic(
        &original,
        &[
            encode_syscallx(crate::syscalls::SYSCALL_ABORT),
            encode_halt(),
        ],
        TraceMode::DeltaRegisters,
        0,
    );
    vm.set_zk_mode(false).unwrap();
    let start = vm.pc;
    assert_eq!(
        vm.run_with_host(&mut TraceMutatingHost),
        Err(VMError::ExecutionDeferred(
            crate::error::ExecutionDeferral::TraceOwnerUnavailable
        ))
    );
    assert!(vm.trace_pcs().is_empty());
    assert!(vm.delta_register_trace().is_empty());
    // The next ordinary invocation can admit its independently selected mode.
    vm.set_program_counter(start).unwrap();
    vm.run_with_host(&mut NetChangesHost).unwrap();
    assert!(!vm.trace_pcs().is_empty());
}

#[test]
fn actual_zk_host_custody_violation_is_a_local_invariant_deferral() {
    let original = AllocationBudget::new(LIMIT);
    let mut vm = generic(
        &original,
        &[
            encode_syscallx(crate::syscalls::SYSCALL_ABORT),
            encode_halt(),
        ],
        TraceMode::DeltaRegisters,
        64,
    );
    let error = vm.run_with_host(&mut TraceMutatingHost).unwrap_err();
    assert_eq!(
        error,
        VMError::ExecutionDeferred(crate::error::ExecutionDeferral::LocalInvariantViolation,)
    );
    assert_eq!(
        error.execution_deferral(),
        Some(crate::error::ExecutionDeferral::LocalInvariantViolation,)
    );
    assert!(vm.trace_pcs().is_empty());
    assert!(vm.delta_register_trace().is_empty());
    assert!(vm.step_log().is_empty());
    drop(vm);
    assert_eq!(original.reserved_bytes(), 0);
}

struct ShrinkOriginalHost {
    original: AllocationBudget,
    exit: bool,
    calls: usize,
}
impl IVMHost for ShrinkOriginalHost {
    fn prepare_syscall(&self, _: u32, _: &IVM) -> Result<u64, VMError> {
        Ok(0)
    }
    fn syscall(&mut self, _: u32, vm: &mut IVM) -> Result<u64, VMError> {
        self.calls += 1;
        self.original.set_limit_bytes(0);
        if self.exit {
            vm.request_exit();
        }
        Ok(0)
    }
    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

#[test]
fn pc_growth_refusal_keeps_the_preceding_observations_and_prevents_next_effect() {
    let original = AllocationBudget::new(LIMIT);
    let syscall = encode_syscallx(crate::syscalls::SYSCALL_ABORT);
    let add = encode_ri(a::ADDI, 7, 7, 1);
    let mut vm = generic(
        &original,
        &[syscall, add, add, add, encode_halt()],
        TraceMode::PcOnly,
        0,
    );
    let start = vm.pc;
    let mut host = ShrinkOriginalHost {
        original: original.clone(),
        exit: false,
        calls: 0,
    };
    let shared_cycles = crate::ivm::VmCycleBudget::new(std::num::NonZeroU64::new(5).unwrap());
    assert!(
        matches!(vm.run_with_host_and_cycle_budget(&mut host, &shared_cycles),
        Err(VMError::AllocationDeferred(AllocationRefusal::ExceedsLimit { requested_bytes, limit_bytes: 0 }))
        if requested_bytes == 8 * std::mem::size_of::<u64>())
    );
    assert_eq!(host.calls, 1);
    assert_eq!(vm.trace_pcs(), &[start, start + 4, start + 8, start + 12]);
    assert_eq!(vm.pc, start + 12);
    assert_eq!(vm.registers.snapshot()[7], 2);
    assert_eq!(vm.cycles, 3);
    assert_eq!(shared_cycles.consumed(), 3);
    assert_eq!(
        vm.gas_remaining,
        GAS - crate::gas::cost_of(syscall).unwrap() - 2 * crate::gas::cost_of(add).unwrap()
    );
    drop(vm);
    assert_eq!(original.reserved_bytes(), 0);
}

#[test]
fn payable_padding_refuses_before_effects_but_unpayable_padding_preserves_oog() {
    let syscall = encode_syscallx(crate::syscalls::SYSCALL_ABORT);
    for payable in [false, true] {
        let original = AllocationBudget::new(LIMIT);
        let mut vm = generic(&original, &[syscall, encode_halt()], TraceMode::Off, 64);
        let initial_gas = crate::gas::cost_of(syscall).unwrap() + if payable { 63 } else { 62 };
        vm.set_gas_limit(initial_gas);
        let initial_registers = vm.registers.snapshot();
        let start = vm.pc;
        let mut host = ShrinkOriginalHost {
            original: original.clone(),
            exit: true,
            calls: 0,
        };
        let shared_cycles = crate::ivm::VmCycleBudget::new(std::num::NonZeroU64::new(64).unwrap());
        let outcome = vm.run_with_host_and_cycle_budget(&mut host, &shared_cycles);
        if payable {
            assert!(matches!(
                outcome,
                Err(VMError::AllocationDeferred(
                    AllocationRefusal::ExceedsLimit { .. }
                ))
            ));
            assert_eq!(
                (vm.cycles, shared_cycles.consumed(), vm.gas_remaining),
                (1, 1, 63)
            );
        } else {
            assert_eq!(outcome, Err(VMError::OutOfGas));
            assert_eq!(
                (vm.cycles, shared_cycles.consumed(), vm.gas_remaining),
                (64, 64, 62)
            );
        }
        assert_eq!(host.calls, 1);
        assert_eq!(vm.pc, start + 4);
        assert_eq!(vm.registers.snapshot(), initial_registers);
        assert_eq!(vm.trace_log.len(), 1);
        assert_eq!(vm.step_log().len(), 1);
        assert!(vm.delta_register_trace().is_empty());
        drop(vm);
        assert_eq!(original.reserved_bytes(), 0);
    }
}
