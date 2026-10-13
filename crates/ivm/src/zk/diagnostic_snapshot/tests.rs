//! Exact original-pool capture, rejection, borrowed verification and real disposal controls.

use super::*;
use crate::memory::private_disposal::tests as observer;
use iroha_crypto::{Hash, HashOf};
use std::{
    alloc::Layout,
    mem::{offset_of, size_of},
    sync::Arc,
};

struct Fixture {
    states: Vec<RegisterState>,
    constraints: Vec<Constraint>,
    memory: Vec<MemEvent>,
    registers: Vec<RegEvent>,
    steps: Vec<StepEntry>,
}
impl Fixture {
    fn new() -> Self {
        let root = HashOf::from_untyped_unchecked(Hash::prehashed([9; 32]));
        Self {
            states: vec![RegisterState {
                pc: 4,
                gpr: [0xA5A5; 256],
                tags: [true; 256],
            }],
            constraints: vec![Constraint::Range {
                reg: 7,
                bits: 64,
                cycle: 0,
            }],
            memory: vec![
                MemEvent::Load {
                    addr: 16,
                    value: 0xBABA,
                    size: 8,
                    path: vec![[3; 32]; 2],
                    root,
                },
                MemEvent::Store {
                    addr: 24,
                    value: 0xCCCC,
                    size: 8,
                    path: vec![[4; 32]; 3],
                    root,
                },
            ],
            registers: vec![
                RegEvent::Read {
                    index: 7,
                    value: 0xDDDD,
                    tag: true,
                    path: [[5; 32]; crate::REGISTER_MERKLE_PATH_DEPTH],
                    root,
                },
                RegEvent::Write {
                    index: 8,
                    value: 0xEEEE,
                    tag: true,
                    path: [[6; 32]; crate::REGISTER_MERKLE_PATH_DEPTH],
                    root,
                },
            ],
            steps: vec![StepEntry {
                pc: 4,
                reg_root: root,
                mem_root: root,
            }],
        }
    }
    fn source(&self) -> DiagnosticTraceSource<'_> {
        DiagnosticTraceSource {
            registers: DiagnosticRegisterSource::States(&self.states),
            constraints: &self.constraints,
            memory_events: &self.memory,
            register_events: &self.registers,
            steps: &self.steps,
        }
    }
}

#[test]
fn complete_nested_demand_refuses_one_byte_short_before_copy_and_retries_exactly() {
    let fixture = Fixture::new();
    let source = fixture.source();
    let expected = size_of::<RegisterState>()
        + size_of::<Constraint>()
        + 2 * size_of::<MemoryRow>()
        + 2 * size_of::<RegisterRow>()
        + 21 * size_of::<[u8; 32]>()
        + size_of::<StepEntry>();
    assert_eq!(
        source.allocation_plan().unwrap().requested_bytes(),
        expected
    );
    let budget = AllocationBudget::new(expected - 1);
    assert!(matches!(
        source.try_snapshot(&budget),
        Err(VMError::AllocationDeferred(_))
    ));
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(fixture.states[0].gpr, [0xA5A5; 256]);
    assert_eq!(memory_parts(&fixture.memory[1]).4, &[[4; 32]; 3]);
    budget.set_limit_bytes(expected);
    let snapshot = source.try_snapshot(&budget).unwrap();
    assert_eq!(budget.reserved_bytes(), expected);
    assert_eq!(snapshot.states(), fixture.states);
    assert_eq!(snapshot.memory_events().nth(1).unwrap().path, &[[4; 32]; 3]);
    assert_eq!(snapshot.register_event(1).unwrap().value, 0xEEEE);
    assert!(snapshot.register_event(2).is_none());
    drop(snapshot);
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(fixture.states[0].gpr[7], 0xA5A5);
}

#[test]
fn reserved_parent_survives_shrink_and_shared_snapshot_final_owner() {
    let fixture = Fixture::new();
    let source = fixture.source();
    let demand = source.allocation_plan().unwrap();
    let budget = AllocationBudget::new(demand.requested_bytes());
    let short = ExecutionMemoryPlan::array::<u8>(demand.requested_bytes() - 1).unwrap();
    let mut insufficient = ExecutionMemoryLease::reserve(&budget, short).unwrap();
    assert!(matches!(
        source.try_snapshot_from_parent(&mut insufficient),
        Err(VMError::ExecutionDeferred(_))
    ));
    assert_eq!(insufficient.remaining_bytes(), short.requested_bytes());
    drop(insufficient);
    assert_eq!(budget.reserved_bytes(), 0);
    let mut parent = ExecutionMemoryLease::reserve(&budget, demand).unwrap();
    budget.set_limit_bytes(0);
    let owner = Arc::new(source.try_snapshot_from_parent(&mut parent).unwrap());
    assert_eq!(parent.remaining_bytes(), 0);
    drop(parent);
    let borrower = Arc::clone(&owner);
    drop(owner);
    assert_eq!(budget.reserved_bytes(), demand.requested_bytes());
    assert_eq!(borrower.states()[0].gpr[0], 0xA5A5);
    drop(borrower);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn delta_capture_expands_without_changing_source() {
    let budget = AllocationBudget::new(64 * 1024);
    let mut rows = super::DeltaTraceLog::new(Some(&budget));
    budget.with_deferred_refund_notifications(|scope| {
        rows.prepare_batch(2, 256, 1, Some(scope)).unwrap();
    });
    let mut gpr = [0; 256];
    let mut tags = [false; 256];
    gpr[7] = 21;
    tags[7] = true;
    rows.record_reserved(4, gpr, tags);
    gpr[8] = 22;
    rows.record_reserved(8, gpr, tags);
    let retained = budget.reserved_bytes();
    let snapshot = DiagnosticTraceSource {
        registers: DiagnosticRegisterSource::Deltas(&rows),
        constraints: &[],
        memory_events: &[],
        register_events: &[],
        steps: &[],
    }
    .try_snapshot(&budget)
    .unwrap();
    assert_eq!(snapshot.states()[1].gpr[7], 21);
    assert!(snapshot.states()[1].tags[7]);
    assert_eq!(snapshot.states()[1].gpr[8], 22);
    drop(snapshot);
    assert_eq!(rows.entry(0).unwrap().changes[7], (7, 21, true));
    assert_eq!(budget.reserved_bytes(), retained);
    drop(rows);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn original_state_backing_erases_registers_and_tags_before_credit_refund() {
    let _serial = observer::serial();
    let budget = observer::budget();
    assert_eq!(budget.reserved_bytes(), 0);
    let fixture = Fixture::new();
    let snapshot = fixture.source().try_snapshot(budget).unwrap();
    let total = budget.reserved_bytes();
    let _watch = observer::watch(
        snapshot.states.as_slice().as_ptr().cast(),
        Layout::array::<RegisterState>(1).unwrap(),
        offset_of!(RegisterState, gpr),
        size_of::<[u64; 256]>(),
    );
    observer::watch_second_span(offset_of!(RegisterState, tags), size_of::<[bool; 256]>());
    drop(snapshot);
    observer::assert_erased_and_freed();
    assert_eq!(observer::original_credit_at_free(), total);
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(fixture.states[0].gpr[7], 0xA5A5);
}

#[test]
fn original_event_backing_erases_each_private_row_before_deallocation() {
    let _serial = observer::serial();
    let budget = observer::budget();
    let fixture = Fixture::new();
    let path_start = offset_of!(Range<usize>, start);
    let path_end = offset_of!(Range<usize>, end);
    for index in 0..2 {
        for (field, bytes) in [
            (offset_of!(MemoryRow, written), size_of::<bool>()),
            (offset_of!(MemoryRow, address), size_of::<u64>()),
            (offset_of!(MemoryRow, value), size_of::<u128>()),
            (offset_of!(MemoryRow, size), size_of::<u8>()),
            (offset_of!(MemoryRow, path) + path_start, size_of::<usize>()),
            (offset_of!(MemoryRow, path) + path_end, size_of::<usize>()),
            (offset_of!(MemoryRow, root), 32),
        ] {
            assert_eq!(budget.reserved_bytes(), 0);
            let snapshot = fixture.source().try_snapshot(budget).unwrap();
            let _watch = observer::watch(
                snapshot.memory_events.as_slice().as_ptr().cast(),
                Layout::array::<MemoryRow>(2).unwrap(),
                index * size_of::<MemoryRow>() + field,
                bytes,
            );
            drop(snapshot);
            observer::assert_erased_and_freed();
            assert!(observer::original_credit_at_free() >= 2 * size_of::<MemoryRow>());
            assert_eq!(budget.reserved_bytes(), 0);
        }
        for (field, bytes) in [
            (offset_of!(RegisterRow, written), size_of::<bool>()),
            (offset_of!(RegisterRow, index), size_of::<usize>()),
            (offset_of!(RegisterRow, value), size_of::<u64>()),
            (offset_of!(RegisterRow, tag), size_of::<bool>()),
            (
                offset_of!(RegisterRow, path) + path_start,
                size_of::<usize>(),
            ),
            (offset_of!(RegisterRow, path) + path_end, size_of::<usize>()),
            (offset_of!(RegisterRow, root), 32),
        ] {
            let snapshot = fixture.source().try_snapshot(budget).unwrap();
            let _watch = observer::watch(
                snapshot.register_events.as_slice().as_ptr().cast(),
                Layout::array::<RegisterRow>(2).unwrap(),
                index * size_of::<RegisterRow>() + field,
                bytes,
            );
            drop(snapshot);
            observer::assert_erased_and_freed();
            assert!(observer::original_credit_at_free() >= 2 * size_of::<RegisterRow>());
            assert_eq!(budget.reserved_bytes(), 0);
        }
    }
}

#[test]
fn flattened_path_backing_erases_every_initialized_sibling_on_unwind() {
    let _serial = observer::serial();
    let budget = observer::budget();
    assert_eq!(budget.reserved_bytes(), 0);
    let fixture = Fixture::new();
    let snapshot = fixture.source().try_snapshot(budget).unwrap();
    let bytes = snapshot.paths.as_slice().len() * 32;
    let _watch = observer::watch(
        snapshot.paths.as_slice().as_ptr().cast(),
        Layout::array::<[u8; 32]>(21).unwrap(),
        0,
        bytes,
    );
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _retained = snapshot;
        panic!("exercise detached owner unwind");
    }));
    assert!(result.is_err());
    observer::assert_erased_and_freed();
    assert!(observer::original_credit_at_free() >= bytes);
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(register_parts(&fixture.registers[1]).4, &[[6; 32]; 8]);
}

#[test]
fn checker_rejects_extra_missing_and_out_of_range_register_paths() {
    let mut vm = crate::IVM::new(1_000_000);
    vm.set_zk_mode(true).unwrap();
    vm.set_zk_trace_enabled(true);
    let code = [
        crate::encoding::wide::encode_ri(crate::instruction::wide::arithmetic::ADDI, 1, 0, 7),
        crate::encoding::wide::encode_halt(),
    ];
    vm.load_code(
        &code
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    vm.set_zk_mode(true).unwrap();
    vm.set_zk_trace_enabled(true);
    vm.set_max_cycles(8);
    vm.run().unwrap();
    let budget = AllocationBudget::new(1024 * 1024);
    let snapshot = vm.try_diagnostic_snapshot(&budget).unwrap();
    assert!(super::super::check_diagnostic_trace(&snapshot).is_ok());
    let event = snapshot
        .register_events()
        .next()
        .expect("real authenticated register event");
    assert_eq!(event.path.len(), 8);
    for (index, path) in [
        (event.index, event.path[..7].to_vec()),
        (event.index, [event.path, &[[8; 32]]].concat()),
        (256, event.path.to_vec()),
    ] {
        let altered = DiagnosticRegisterEvent {
            index,
            path: &path,
            ..event
        };
        assert!(matches!(
            super::super::register_authentication::check(altered),
            Err(VMError::AssertionFailed)
        ));
    }
}

#[test]
fn funded_vm_capture_requires_original_pool_and_refusal_preserves_execution() {
    let budget = AllocationBudget::new(128 * 1024 * 1024);
    let mut vm = crate::IVM::try_new_with_memory_budget(1_000_000, &budget).unwrap();
    let code = [
        crate::encoding::wide::encode_ri(crate::instruction::wide::arithmetic::ADDI, 1, 0, 7),
        crate::encoding::wide::encode_halt(),
    ];
    vm.load_code(
        &code
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    vm.set_zk_mode(true).unwrap();
    vm.set_zk_trace_enabled(true);
    vm.set_max_cycles(8);
    vm.run().unwrap();
    let before = vm.execution_summary();
    let resident = budget.reserved_bytes();
    let foreign = AllocationBudget::new(0);
    assert!(matches!(
        vm.try_diagnostic_snapshot(&foreign),
        Err(VMError::HostUnavailable)
    ));
    assert_eq!(foreign.reserved_bytes(), 0);
    budget.set_limit_bytes(resident);
    assert!(matches!(
        vm.try_diagnostic_snapshot(&budget),
        Err(VMError::AllocationDeferred(_))
    ));
    assert_eq!(budget.reserved_bytes(), resident);
    assert_eq!(vm.execution_summary(), before);
    budget.set_limit_bytes(128 * 1024 * 1024);
    let snapshot = vm.try_diagnostic_snapshot(&budget).unwrap();
    assert!(!snapshot.states().is_empty());
    assert!(super::super::check_diagnostic_trace(&snapshot).is_ok());
    assert!(budget.reserved_bytes() > resident);
    drop(vm);
    assert!(budget.reserved_bytes() > 0);
    assert_eq!(snapshot.states().last().unwrap().gpr[1], 7);
    drop(snapshot);
    assert_eq!(budget.reserved_bytes(), 0);
}
