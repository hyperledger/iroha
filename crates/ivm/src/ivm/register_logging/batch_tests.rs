//! Real execution-boundary admission, nested calls and native finish observations.

use super::*;
use crate::{
    PreparedArgumentRecord, PreparedContract, ProgramMetadata, Registers,
    argument_record::prepare_argument_record_with_gas_limit,
    encoding::wide::{encode_halt, encode_ri, encode_sys, encode_syscallx},
    execution_memory::ExecutionMemoryLease,
    execution_packets::{INSTRUCTION_WINDOWS, NativeInvocation, instruction_clocks},
    host::{DefaultHost, IVMHost},
    instruction::wide::{arithmetic, system},
    pointer_abi::PointerType,
    syscalls,
};
use iroha_allocation::{AllocationBudget, AllocationRefusal};
use iroha_primitives::json::Json;
use ivm_abi::arguments::encode_argument_record_from_json;
use kotodama_lang::compiler::{Compiler, CompilerOptions};
use std::{
    any::Any,
    cell::{Cell, RefCell},
    collections::BTreeMap,
    mem::size_of,
    sync::Arc,
};

const LIMIT: usize = 128 * 1024 * 1024;
const GAS: u64 = 1_000_000;
const ROW: usize = size_of::<zk::RegEvent>();

fn artifact(source: &str, cycles: u64) -> PreparedContract {
    let bytes = Compiler::new_with_options(CompilerOptions {
        force_zk: true,
        max_cycles: cycles,
        ..CompilerOptions::default()
    })
    .compile_source(source)
    .unwrap();
    crate::prepare_contract(Arc::<[u8]>::from(bytes)).unwrap()
}
fn loaded(contract: &PreparedContract, original: &AllocationBudget) -> IVM {
    let mut vm = IVM::try_new_with_memory_budget(GAS, original).unwrap();
    vm.load_prepared(contract).unwrap();
    vm.select_entrypoint("main").unwrap();
    vm.set_zk_trace_enabled(true);
    vm
}
fn generic(original: &AllocationBudget, words: &[u32], cycles: u64) -> IVM {
    let mut bytes = ProgramMetadata {
        mode: crate::ivm_mode::ZK,
        max_cycles: cycles,
        ..ProgramMetadata::default()
    }
    .encode();
    bytes.extend(words.iter().flat_map(|word| word.to_le_bytes()));
    let mut vm = IVM::try_new_with_memory_budget(GAS, original).unwrap();
    vm.load_program(&bytes).unwrap();
    vm.set_zk_trace_enabled(true);
    vm
}

struct InputHost {
    prepared: Option<PreparedArgumentRecord>,
    inner: DefaultHost,
    foreign: Registers,
    probes: Cell<usize>,
}
impl IVMHost for InputHost {
    fn prepared_entrypoint_arguments(&self) -> Option<PreparedArgumentRecord> {
        // This unrelated metadata observation must be masked. Actual ordinary
        // default/prepared argument installation must remain traced.
        assert_eq!(self.foreign.get(199), 987);
        self.probes.set(self.probes.get() + 1);
        self.prepared.clone()
    }
    fn prepare_syscall(&self, number: u32, vm: &IVM) -> Result<u64, VMError> {
        self.inner.prepare_syscall(number, vm)
    }
    fn syscall(&mut self, number: u32, vm: &mut IVM) -> Result<u64, VMError> {
        self.inner.syscall(number, vm)
    }
    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}
fn input_host(contract: &PreparedContract, prepared: bool) -> InputHost {
    let schema = contract
        .contract_interface()
        .entrypoints
        .iter()
        .find(|entry| entry.name == "main")
        .unwrap()
        .argument_schema
        .as_ref()
        .unwrap();
    let record =
        encode_argument_record_from_json(schema, &Json::new(norito::json!({"ready": true})))
            .unwrap();
    let owner =
        prepare_argument_record_with_gas_limit(schema, Arc::from(record.clone()), GAS).unwrap();
    let mut tlv = Vec::new();
    tlv.extend_from_slice(&(PointerType::NoritoBytes as u16).to_be_bytes());
    tlv.push(1);
    tlv.extend_from_slice(&(record.len() as u32).to_be_bytes());
    tlv.extend_from_slice(&record);
    tlv.extend_from_slice(iroha_crypto::Hash::new(&record).as_ref());
    crate::pointer_abi::validate_tlv_bytes(&tlv).unwrap();
    let mut foreign = Registers::new();
    foreign.set(199, 987);
    InputHost {
        prepared: prepared.then_some(owner),
        inner: DefaultHost::default().with_public_inputs(BTreeMap::from([(
            ivm_abi::arguments::ENTRYPOINT_ARGUMENT_RECORD_PUBLIC_INPUT_KEY
                .parse()
                .unwrap(),
            tlv,
        )])),
        foreign,
        probes: Cell::new(0),
    }
}

#[test]
fn actual_empty_prepared_and_default_roots_refuse_before_gas_heap_or_register_effects() {
    for route in [
        RootArguments::Empty,
        RootArguments::Prepared,
        RootArguments::DefaultHost,
    ] {
        let empty = matches!(route, RootArguments::Empty);
        let contract = artifact(
            if empty {
                "seiyaku RootRows { view fn main() authorize(anyone) { } }"
            } else {
                "seiyaku RootRows { view fn main(bool ready) authorize(anyone) -> bool { ready } }"
            },
            128,
        );
        let original = AllocationBudget::new(LIMIT);
        let mut vm = loaded(&contract, &original);
        let mut host: Box<dyn IVMHost> = if empty {
            Box::new(DefaultHost::default())
        } else {
            let host = input_host(&contract, matches!(route, RootArguments::Prepared));
            if let Some(prepared) = &host.prepared {
                prepared.precharge_vm(&mut vm).unwrap();
            }
            Box::new(host)
        };
        let log = vm.proof_register_log_handle().unwrap();
        let scope = zk::RegLoggerGuard::install(Some(log.clone()));
        let before = (
            vm.remaining_gas(),
            vm.memory.heap_allocated_len(),
            vm.registers.snapshot(),
            vm.registers.snapshot_tags(),
        );
        let baseline = original.reserved_bytes();
        let rows = event_counts::root(route, false);
        original.set_limit_bytes(baseline + rows * ROW - 1);
        let Err(VMError::AllocationDeferred(AllocationRefusal::Capacity {
            requested_bytes,
            release,
            ..
        })) = vm.begin_root_call(host.as_mut())
        else {
            panic!("entire root subtree must be admitted before argument effects");
        };
        assert_eq!(requested_bytes, rows * ROW);
        let Err(AllocationRefusal::Capacity {
            release: original_release,
            ..
        }) = original.try_reserve_bytes(rows * ROW)
        else {
            panic!("same original refusal");
        };
        assert_eq!(release, original_release);
        assert_eq!(
            (
                vm.remaining_gas(),
                vm.memory.heap_allocated_len(),
                vm.registers.snapshot(),
                vm.registers.snapshot_tags()
            ),
            before
        );
        assert_eq!(original.reserved_bytes(), baseline);
        assert!(log.lock().as_slice().is_empty());
        original.set_limit_bytes(LIMIT);
        vm.begin_root_call(host.as_mut()).unwrap();
        assert_eq!(log.lock().capacity(), rows);
        assert!(log.lock().as_slice().len() >= 16);
        assert!(!log.lock().as_slice().iter().any(|event| matches!(
            event,
            zk::RegEvent::Read {
                index: 199,
                value: 987,
                ..
            }
        )));
        if !empty {
            assert_eq!(
                host.as_any()
                    .downcast_mut::<InputHost>()
                    .unwrap()
                    .probes
                    .get(),
                2
            );
        }
        drop(scope);
        drop(vm);
        assert_eq!(
            original.reserved_bytes(),
            zk::SharedRegLog::allocation_layout().size() + rows * ROW
        );
        drop(log);
        assert_eq!(original.reserved_bytes(), 0);
    }
}

// Admit the earlier cycle-delta owner so these tests pressure the intended
// register-row/shell boundary, using its canonical public layout exactly.
fn initial_cycle_delta_bytes() -> usize {
    let mut deltas = zk::DeltaTraceLog::new(None);
    deltas.prepare_batch(1, 256, 0, None).unwrap();
    deltas.allocated_bytes().unwrap()
}

#[test]
fn ordinary_instruction_shortage_precedes_gas_cycles_registers_and_shared_allowance() {
    let original = AllocationBudget::new(LIMIT);
    let word = encode_ri(arithmetic::ADDI, 7, 7, 1);
    let mut vm = generic(&original, &[word, encode_halt()], 2);
    vm.set_register(7, 41);
    let old_log = vm.proof_register_log_handle().unwrap();
    let baseline = original.reserved_bytes();
    let shell = zk::SharedRegLog::allocation_layout().size();
    let steps = 4 * size_of::<zk::StepEntry>();
    let deltas = initial_cycle_delta_bytes();
    original.set_limit_bytes(baseline + shell + steps + deltas + 4 * ROW - 1);
    let start = vm.pc;
    let allowance = crate::ivm::VmCycleBudget::new(std::num::NonZeroU64::new(2).unwrap());
    assert!(
        matches!(vm.run_with_host_and_cycle_budget(&mut DefaultHost::default(), &allowance), Err(VMError::AllocationDeferred(AllocationRefusal::Capacity { requested_bytes, .. })) if requested_bytes == 4 * ROW)
    );
    assert_eq!(
        (vm.pc, vm.cycles, vm.remaining_gas(), vm.register(7)),
        (start, 0, GAS, 41)
    );
    assert_eq!(allowance.consumed(), 0);
    assert!(
        vm.proof_register_log_handle()
            .unwrap()
            .lock()
            .as_slice()
            .is_empty()
    );
    original.set_limit_bytes(LIMIT);
    vm.run_with_host_and_cycle_budget(&mut DefaultHost::default(), &allowance)
        .unwrap();
    assert_eq!(vm.register(7), 42);
    assert_eq!(
        vm.proof_register_log_handle()
            .unwrap()
            .lock()
            .as_slice()
            .len(),
        3
    );
    drop(vm);
    drop(old_log);
    assert_eq!(original.reserved_bytes(), 0);
}

#[test]
fn compiled_strict_children_and_returns_share_prepaid_rows_and_snapshot_custody() {
    let contract = artifact(
        "seiyaku NestedRows { fn inner(bool value) -> bool { value } fn outer(bool value) -> bool { inner(value: value) } view fn main(bool ready) authorize(anyone) -> bool { outer(value: ready) } }",
        512,
    );
    for prepared in [false, true] {
        let original = AllocationBudget::new(LIMIT);
        let mut vm = loaded(&contract, &original);
        let mut host = input_host(&contract, prepared);
        if let Some(input) = &host.prepared {
            input.precharge_vm(&mut vm).unwrap();
        }
        vm.run_with_host(&mut host).unwrap();
        assert_eq!(vm.call_result_word_count(), Ok(1));
        assert_eq!(vm.public_call_result_word(0), Ok(1));
        assert!(vm.contract_return_stack.is_empty());
        let log = vm.proof_register_log_handle().unwrap();
        assert!(log.lock().as_slice().len() > event_counts::root(RootArguments::Prepared, false));
        let before = original.reserved_bytes();
        let copy = vm.try_clone_snapshot().unwrap();
        let copied = copy.proof_register_log_handle().unwrap();
        assert!(copied.belongs_to(&original));
        assert!(!zk::SharedRegLog::ptr_eq(&log, &copied));
        assert_eq!(log.lock().as_slice(), copied.lock().as_slice());
        assert_ne!(
            log.lock().as_slice().as_ptr(),
            copied.lock().as_slice().as_ptr()
        );
        assert!(
            original.reserved_bytes()
                >= before
                    + copied.lock().capacity() * ROW
                    + zk::SharedRegLog::allocation_layout().size()
        );
        drop(copy);
        drop(copied);
        assert_eq!(original.reserved_bytes(), before);
        let retained = zk::SharedRegLog::allocation_layout().size() + log.lock().capacity() * ROW;
        drop(vm);
        assert_eq!(original.reserved_bytes(), retained);
        drop(log);
        assert_eq!(original.reserved_bytes(), 0);
    }
}

struct AllRegisters {
    reject_prepare: bool,
    calls: usize,
}
impl IVMHost for AllRegisters {
    fn prepare_syscall(&self, _: u32, _: &IVM) -> Result<u64, VMError> {
        if self.reject_prepare {
            Err(VMError::AssertionFailed)
        } else {
            Ok(0)
        }
    }
    fn syscall(&mut self, _: u32, vm: &mut IVM) -> Result<u64, VMError> {
        self.calls += 1;
        for index in 1..256 {
            vm.set_register(index, index as u64 + 100);
            vm.registers.set_tag(index, false);
        }
        Ok(0)
    }
    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

#[test]
fn actual_reserved_syscalls_prepay_restore_and_all_255_host_net_writes() {
    for reject_prepare in [false, true] {
        let original = AllocationBudget::new(LIMIT);
        let mut vm = generic(&original, &[encode_halt()], 1);
        vm.set_register(10, 7);
        vm.registers.set_tag(10, true);
        let log = vm.proof_register_log_handle().unwrap();
        let _scope = zk::RegLoggerGuard::install(Some(log.clone()));
        let mut host = AllRegisters {
            reject_prepare,
            calls: 0,
        };
        let rows = event_counts::syscall(syscalls::SYSCALL_ABORT);
        let baseline = original.reserved_bytes();
        let before = (
            vm.remaining_gas(),
            vm.memory.heap_allocated_len(),
            vm.registers.snapshot(),
            vm.registers.snapshot_tags(),
        );
        original.set_limit_bytes(baseline + rows * ROW - 1);
        assert!(matches!(
            vm.execute_syscall(&mut host, syscalls::SYSCALL_ABORT),
            Err(VMError::AllocationDeferred(_))
        ));
        assert_eq!(
            (
                vm.remaining_gas(),
                vm.memory.heap_allocated_len(),
                vm.registers.snapshot(),
                vm.registers.snapshot_tags()
            ),
            before
        );
        assert_eq!(host.calls, 0);
        original.set_limit_bytes(LIMIT);
        // Exercise the actual syscall as a nested subtree of its public opcode batch.
        let _instruction = vm
            .prepare_instruction_register_events(encode_sys(
                system::SCALL,
                syscalls::SYSCALL_ABORT as u8,
            ))
            .unwrap();
        let result = vm.execute_syscall(&mut host, syscalls::SYSCALL_ABORT);
        if reject_prepare {
            assert_eq!(result, Err(VMError::AssertionFailed));
            assert_eq!(vm.registers.snapshot()[10], 7);
            assert!(vm.registers.tag(10));
            assert_eq!(log.lock().as_slice().len(), 5);
        } else {
            result.unwrap();
            assert_eq!(host.calls, 1);
            assert_eq!(log.lock().as_slice().len(), 258);
            for (index, event) in log.lock().as_slice()[3..].iter().enumerate() {
                assert!(
                    matches!(event, zk::RegEvent::Write { index: observed, value, tag: false, .. } if *observed == index + 1 && *value == index as u64 + 101)
                );
            }
        }
    }
}

#[test]
fn native_delayed_finish_uses_original_batch_and_preserves_every_original_packet() {
    let contract = artifact(
        "seiyaku NativeEventRows { view fn main() authorize(anyone) { } }",
        64,
    );
    let original = AllocationBudget::new(LIMIT);
    let run = || {
        let mut parent =
            ExecutionMemoryLease::reserve(&original, NativeInvocation::allocation_plan().unwrap())
                .unwrap();
        NativeInvocation::run_public_leaf_root(
            contract.clone(),
            "main",
            GAS,
            &mut parent,
            &original,
        )
        .unwrap()
    };
    let plain = run();
    assert!(!IVM::native_register_trace_enabled_for_test());
    let (traced, count) = IVM::with_native_register_trace_for_test(&run);
    assert!(!IVM::native_register_trace_enabled_for_test());
    assert_eq!(
        (
            traced.remaining_gas(),
            traced.cycles(),
            traced.instructions()
        ),
        (plain.remaining_gas(), plain.cycles(), plain.instructions())
    );
    for (left, right) in traced.packets().iter().zip(plain.packets()) {
        assert_eq!(
            (
                left.space(),
                left.generation(),
                left.index(),
                left.clock(),
                left.is_write(),
                left.before(),
                left.after(),
                left.before_private(),
                left.after_private()
            ),
            (
                right.space(),
                right.generation(),
                right.index(),
                right.clock(),
                right.is_write(),
                right.before(),
                right.after(),
                right.before_private(),
                right.after_private()
            )
        );
    }
    let mut expected = event_counts::root(RootArguments::Empty, true);
    for window in 0..INSTRUCTION_WINDOWS {
        let clocks = instruction_clocks(window).unwrap();
        let packet = &traced.packets()[clocks[0] as usize];
        if !packet.enabled() {
            continue;
        }
        assert_eq!(
            packet.space(),
            Some(crate::execution_packets::PacketSpace::Owner)
        );
        assert_eq!(packet.index(), 32);
        assert!(!packet.is_write());
        let pc = u64::from_le_bytes(packet.before()[..8].try_into().unwrap()) as usize;
        // Native PC addresses IVM code memory: the deployable file additionally
        // prefixes that entire region with its fixed metadata header.
        let offset = contract.header_len().checked_add(pc).unwrap();
        assert!(offset >= contract.code_offset());
        let word = u32::from_le_bytes(contract.artifact()[offset..offset + 4].try_into().unwrap());
        expected += event_counts::instruction(word, 1, true, true).unwrap();
    }
    assert_eq!(count, Some(expected));
    let panic = std::panic::catch_unwind(|| {
        IVM::with_native_register_trace_for_test(|| panic!("trace observation unwind"))
    });
    assert!(panic.is_err());
    assert!(!IVM::native_register_trace_enabled_for_test());
    let after = run();
    assert_eq!(
        (after.remaining_gas(), after.cycles()),
        (plain.remaining_gas(), plain.cycles())
    );
}

#[test]
fn syscall_shell_refusal_precedes_reserved_output_and_staged_entry_effects() {
    let contract = artifact(
        "seiyaku ShellRows { view fn main() authorize(anyone) { } }",
        64,
    );
    for number in [syscalls::SYSCALL_ABORT, syscalls::SYSCALL_INT_ADD] {
        let original = AllocationBudget::new(LIMIT);
        let mut vm = loaded(&contract, &original);
        vm.set_register(10, 71);
        vm.registers.set_tag(10, true);
        let log = vm.proof_register_log_handle().unwrap();
        log.prepare_events(event_counts::syscall(number)).unwrap();
        let scope = zk::RegLoggerGuard::install(Some(log.clone()));
        let before = (
            vm.remaining_gas(),
            vm.memory.heap_allocated_len(),
            vm.registers.snapshot(),
            vm.registers.snapshot_tags(),
        );
        let baseline = original.reserved_bytes();
        let shell = zk::SharedRegLog::allocation_layout().size();
        original.set_limit_bytes(baseline + shell - 1);
        let mut host = AllRegisters {
            reject_prepare: false,
            calls: 0,
        };
        let Err(VMError::AllocationDeferred(AllocationRefusal::Capacity {
            requested_bytes,
            release,
            ..
        })) = vm.execute_syscall(&mut host, number)
        else {
            panic!("detached shell must precede output clearing and staged entry gas");
        };
        assert_eq!(requested_bytes, shell);
        let Err(AllocationRefusal::Capacity {
            release: expected, ..
        }) = original.try_reserve_bytes(shell)
        else {
            panic!("original release source");
        };
        assert_eq!(release, expected);
        assert_eq!(
            (
                vm.remaining_gas(),
                vm.memory.heap_allocated_len(),
                vm.registers.snapshot(),
                vm.registers.snapshot_tags()
            ),
            before
        );
        assert!(vm.staged_syscall.is_none());
        assert!(vm.last_staged_syscall.is_none());
        assert_eq!(vm.syscall_gas_reserve, 0);
        assert_eq!(host.calls, 0);
        assert!(log.lock().as_slice().is_empty());
        assert_eq!(original.reserved_bytes(), baseline);
        drop(scope);
        drop((vm, log));
        assert_eq!(original.reserved_bytes(), 0);
    }
}

#[test]
fn syscall_instruction_shell_refusal_precedes_base_gas_and_cycle_allowance() {
    for word in [
        encode_sys(system::SCALL, syscalls::SYSCALL_ABORT as u8),
        encode_syscallx(syscalls::SYSCALL_ABORT),
    ] {
        let original = AllocationBudget::new(LIMIT);
        let mut vm = generic(&original, &[word, encode_halt()], 2);
        vm.set_register(10, 71);
        vm.registers.set_tag(10, true);
        let previous = vm.proof_register_log_handle().unwrap();
        let before = (
            vm.pc,
            vm.remaining_gas(),
            vm.registers.snapshot(),
            vm.registers.snapshot_tags(),
        );
        let baseline = original.reserved_bytes();
        let shell = zk::SharedRegLog::allocation_layout().size();
        let rows = event_counts::instruction(word, 1, false, false).unwrap() * ROW;
        let steps = 4 * size_of::<zk::StepEntry>();
        let deltas = initial_cycle_delta_bytes();
        original.set_limit_bytes(baseline + shell + steps + deltas + rows + shell - 1);
        let allowance = crate::ivm::VmCycleBudget::new(std::num::NonZeroU64::new(2).unwrap());
        let mut host = AllRegisters {
            reject_prepare: false,
            calls: 0,
        };
        assert!(
            matches!(vm.run_with_host_and_cycle_budget(&mut host, &allowance),
            Err(VMError::AllocationDeferred(AllocationRefusal::Capacity { requested_bytes, .. }))
            if requested_bytes == shell)
        );
        assert_eq!(
            (
                vm.pc,
                vm.remaining_gas(),
                vm.registers.snapshot(),
                vm.registers.snapshot_tags()
            ),
            before
        );
        assert_eq!(vm.cycles, 0);
        assert_eq!(allowance.consumed(), 0);
        assert_eq!(host.calls, 0);
        assert!(
            vm.proof_register_log_handle()
                .unwrap()
                .lock()
                .as_slice()
                .is_empty()
        );
        assert_eq!(
            original.reserved_bytes(),
            baseline + shell + steps + deltas + rows
        );
        drop((vm, previous));
        assert_eq!(original.reserved_bytes(), 0);
    }
}

#[test]
fn default_root_shell_refusal_precedes_argument_gas_heap_and_descriptors() {
    let contract = artifact(
        "seiyaku RootShell { view fn main(bool ready) authorize(anyone) -> bool { ready } }",
        128,
    );
    let original = AllocationBudget::new(LIMIT);
    let mut vm = loaded(&contract, &original);
    let mut host = input_host(&contract, false);
    let log = vm.proof_register_log_handle().unwrap();
    log.prepare_events(event_counts::root(RootArguments::DefaultHost, false))
        .unwrap();
    let scope = zk::RegLoggerGuard::install(Some(log.clone()));
    let before = (
        vm.remaining_gas(),
        vm.memory.heap_allocated_len(),
        vm.input_bump_next,
        vm.registers.snapshot(),
        vm.registers.snapshot_tags(),
    );
    let baseline = original.reserved_bytes();
    let shell = zk::SharedRegLog::allocation_layout().size();
    original.set_limit_bytes(baseline + shell - 1);
    assert!(matches!(vm.begin_root_call(&mut host),
        Err(VMError::AllocationDeferred(AllocationRefusal::Capacity { requested_bytes, .. }))
        if requested_bytes == shell));
    assert_eq!(
        (
            vm.remaining_gas(),
            vm.memory.heap_allocated_len(),
            vm.input_bump_next,
            vm.registers.snapshot(),
            vm.registers.snapshot_tags()
        ),
        before
    );
    assert_eq!(host.probes.get(), 1);
    assert!(log.lock().as_slice().is_empty());
    assert_eq!(original.reserved_bytes(), baseline);
    drop(scope);
    drop((vm, log));
    assert_eq!(original.reserved_bytes(), 0);
}

struct ShrinkingShellHost {
    original: AllocationBudget,
    shell: RefCell<Option<zk::SharedRegLog>>,
    calls: usize,
    panic_in_body: bool,
    expected_peak: usize,
}
impl IVMHost for ShrinkingShellHost {
    fn prepare_syscall(&self, _: u32, vm: &IVM) -> Result<u64, VMError> {
        let detached = vm.reg_log.as_ref().unwrap();
        assert!(detached.belongs_to(&self.original));
        assert!(vm.host_trace_log_detached);
        assert_eq!(self.original.reserved_bytes(), self.expected_peak);
        *self.shell.borrow_mut() = Some(detached.clone());
        self.original.set_limit_bytes(0);
        assert!(matches!(
            self.original
                .try_reserve_bytes(zk::SharedRegLog::allocation_layout().size()),
            Err(AllocationRefusal::ExceedsLimit { requested_bytes, limit_bytes: 0 })
                if requested_bytes == zk::SharedRegLog::allocation_layout().size()
        ));
        Ok(7)
    }
    fn syscall(&mut self, _: u32, vm: &mut IVM) -> Result<u64, VMError> {
        assert!(zk::SharedRegLog::ptr_eq(
            vm.reg_log.as_ref().unwrap(),
            self.shell.borrow().as_ref().unwrap()
        ));
        assert!(vm.host_trace_log_detached);
        self.calls += 1;
        for index in 1..256 {
            vm.set_register(index, index as u64 + 100);
            vm.registers.set_tag(index, false);
        }
        if self.panic_in_body {
            panic!("host body after original pool shrink");
        }
        Ok(7)
    }
    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

#[test]
fn reserved_callbacks_reuse_one_shell_after_pool_shrink_and_release_on_unwind() {
    for panic_in_body in [false, true] {
        let original = AllocationBudget::new(LIMIT);
        let mut vm = generic(&original, &[encode_halt()], 1);
        vm.set_register(10, 71);
        vm.registers.set_tag(10, true);
        let log = vm.proof_register_log_handle().unwrap();
        log.prepare_events(event_counts::syscall(syscalls::SYSCALL_ABORT))
            .unwrap();
        let baseline = original.reserved_bytes();
        let scope = zk::RegLoggerGuard::install(Some(log.clone()));
        let mut host = ShrinkingShellHost {
            original: original.clone(),
            shell: RefCell::new(None),
            calls: 0,
            panic_in_body,
            expected_peak: baseline + zk::SharedRegLog::allocation_layout().size(),
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            vm.execute_syscall(&mut host, syscalls::SYSCALL_ABORT)
        }));
        if panic_in_body {
            assert!(result.is_err());
            assert!(log.lock().as_slice().is_empty());
            assert_eq!(vm.registers.snapshot()[10], 71);
            assert!(vm.registers.tag(10));
        } else {
            result.unwrap().unwrap();
            assert_eq!(log.lock().as_slice().len(), 258);
            for (index, event) in log.lock().as_slice()[3..].iter().enumerate() {
                assert!(
                    matches!(event, zk::RegEvent::Write { index: observed, value, tag: false, .. }
                    if *observed == index + 1 && *value == index as u64 + 101)
                );
            }
        }
        assert_eq!(host.calls, 1);
        assert_eq!(vm.remaining_gas(), GAS - 7);
        assert_eq!(vm.syscall_gas_reserve, 0);
        assert!(!vm.host_trace_log_detached);
        assert!(vm.host_trace_invocation_log.is_none());
        assert!(zk::SharedRegLog::ptr_eq(&log, vm.reg_log.as_ref().unwrap()));
        assert_eq!(
            original.reserved_bytes(),
            baseline + zk::SharedRegLog::allocation_layout().size()
        );
        let shell = host.shell.get_mut().take().unwrap();
        assert!(shell.lock().as_slice().is_empty());
        drop(shell);
        assert_eq!(original.reserved_bytes(), baseline);
        if panic_in_body {
            original.set_limit_bytes(LIMIT);
            let mut retry = AllRegisters {
                reject_prepare: false,
                calls: 0,
            };
            vm.execute_syscall(&mut retry, syscalls::SYSCALL_ABORT)
                .unwrap();
            assert_eq!(retry.calls, 1);
            // Host panic restored its declared output, but other guest writes
            // remain ordinary VM state. Retry emits three sanitation events
            // and exactly one changed output, not 255 duplicate net writes.
            let events = log.lock();
            assert_eq!(events.as_slice().len(), 4);
            assert!(matches!(
                events.as_slice().last(),
                Some(zk::RegEvent::Write {
                    index: 10,
                    value: 110,
                    tag: false,
                    ..
                })
            ));
            for index in 1..256 {
                assert_eq!(vm.registers.snapshot()[index], index as u64 + 100);
                assert!(!vm.registers.tag(index));
            }
            drop(events);
            assert_eq!(original.reserved_bytes(), baseline);
        }
        drop(scope);
        drop((vm, log));
        assert_eq!(original.reserved_bytes(), 0);
    }
}
