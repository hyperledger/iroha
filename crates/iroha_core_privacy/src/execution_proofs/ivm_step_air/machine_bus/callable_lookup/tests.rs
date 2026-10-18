//! Original artifact, descriptor, active-generation and column adversaries.

use super::*;
use packet::{CLOCK, ENABLED, GENERATION, KEY, Space};
use private_dispatch::Program;

mod history;

fn program() -> Program {
    use ivm::encoding::wide as enc;
    use ivm_abi::{call::CallSchemaV1, call::CallTypeNodeV1, entrypoint::EntrypointValueKindV1};
    let original = private_dispatch::tests::callable_lookup_contract(&[
        enc::encode_jump(wide::control::JAL, 1, 4),
        enc::encode_offset24(wide::control::JALS, 4),
        enc::encode_ri(wide::control::JALR, 0, 1, 0),
        enc::encode_ri(wide::arithmetic::ADDI, 0, 0, 0),
        enc::encode_ri(wide::control::JALR, 0, 1, 0),
        enc::encode_ri(wide::control::JALR, 0, 1, 0),
    ]);
    let mut interface = original.contract_interface().clone();
    for callable in interface.callables.iter_mut().skip(1) {
        callable.frame_bytes = 128;
        callable.arguments = CallSchemaV1 {
            nodes: vec![CallTypeNodeV1::Leaf(EntrypointValueKindV1::Bool); 2],
        };
        callable.results = CallSchemaV1 {
            nodes: vec![
                CallTypeNodeV1::Tuple(2),
                CallTypeNodeV1::Leaf(EntrypointValueKindV1::Bool),
                CallTypeNodeV1::Leaf(EntrypointValueKindV1::Bool),
            ],
        };
    }
    let mut bytes = original.metadata().encode();
    bytes.extend(interface.encode_section());
    bytes.extend_from_slice(&original.artifact()[original.code_offset()..]);
    Program::new(ivm::prepare_contract(bytes.into()).unwrap()).unwrap()
}

fn read(space: Space, generation: u16, index: u32, value: u64) -> [F; packet::WIDTH] {
    packet::Event {
        space,
        vm: 7,
        generation,
        index,
        write: false,
        before: u128::from(value).to_le_bytes(),
        after: u128::from(value).to_le_bytes(),
        before_private: 0,
        after_private: 0,
    }
    .fields(0)
}

struct Fixture {
    schedule: Schedule,
    dispatch: [F; private_dispatch::WIDTH],
    descriptor: [F; frame_descriptor::WIDTH],
    returning: [F; SELECTORS],
    packets: OriginalPackets,
}
impl Fixture {
    fn new(program: &Program, slot: Option<usize>, root: bool) -> Self {
        Self::at(program, slot, root, 100, ivm::Memory::STACK_START)
    }
    fn at(program: &Program, slot: Option<usize>, root: bool, first: u32, start: u64) -> Self {
        Self::at_vm(program, slot, root, first, start, 7)
    }
    fn at_vm(
        program: &Program,
        slot: Option<usize>,
        root: bool,
        first: u32,
        start: u64,
        vm: u8,
    ) -> Self {
        fn place_in_vm(packet: &mut [F; packet::WIDTH], vm: u8) {
            if packet[ENABLED] == F::ONE {
                packet[packet::VM] = F(u64::from(vm));
                packet[KEY] = F((packet[KEY].0 & !(0xff << 48)) | (u64::from(vm) << 48));
            }
        }
        let schedule = Schedule::new(vm, first).unwrap();
        let (dispatch, mut original) =
            private_dispatch::tests::callable_lookup_witness(program, slot, root);
        let child = slot.is_some_and(|index| index < 2);
        let returns = slot.is_some_and(|index| matches!(index, 2 | 4 | 5));
        let callable = if child {
            slot.unwrap() + 1
        } else if returns && !root {
            slot.unwrap() - 3
        } else {
            0
        };
        let selected = program.callables().entries[callable];
        let (descriptor, descriptor_ports) = frame_descriptor::tests::callable_lookup_witness(
            selected.entry,
            u64::from(selected.frame),
            selected.arguments as u64,
            selected.results as u64,
            child,
        );
        let mut extra = [[F::ZERO; packet::WIDTH]; EXTRA_PORTS];
        extra[..frame_descriptor::PORTS].copy_from_slice(&descriptor_ports);
        let mut returning = [F::ZERO; SELECTORS];
        if returns {
            returning[callable] = F::ONE;
            let saved_sp = ivm::Memory::STACK_START + 1024;
            for (slot, space, generation, index, value) in [
                (0, Space::Register, 0, 10, start),
                (1, Space::Register, 0, 11, selected.results as u64),
                (2, Space::Register, 0, 31, saved_sp),
                (3, Space::Owner, 3, 10, saved_sp),
                (4, Space::Owner, 3, 11, selected.entry),
            ] {
                extra[OPERANDS + slot] = read(space, generation, index, value);
            }
        }
        let budget = iroha_allocation::AllocationBudget::new(Scan::BYTES);
        let scan = Scan::candidate(
            &budget,
            (0..return_copyback::CELLS).map(|index| {
                let (row, mut cells) = return_copyback::tests::callable_lookup_witness(
                    returns,
                    selected.results as u64,
                    if root { 0 } else { 2 },
                    start,
                    index,
                    u16::MAX,
                    0,
                );
                for cell in &mut cells {
                    place_in_vm(cell, vm);
                }
                if index == 0 && returns {
                    extra[RESULT_START] = cells[2];
                    extra[RESULT_END] = cells[3];
                }
                for (port, offset) in [(4, SCAN_START + 2 * index), (5, SCAN_START + 2 * index + 1)]
                {
                    if cells[port][ENABLED] == F::ONE {
                        cells[port][CLOCK] = F(u64::from(first) + offset as u64);
                    }
                }
                scan_storage::Cell {
                    row,
                    child: cells[4],
                    copyback: cells[5],
                }
            }),
        )
        .unwrap();
        for (index, packet) in original.iter_mut().chain(extra.iter_mut()).enumerate() {
            place_in_vm(packet, vm);
            if packet[ENABLED] == F::ONE {
                packet[CLOCK] = F(u64::from(schedule.clocks[index]));
            }
        }
        Self {
            schedule,
            dispatch,
            descriptor,
            returning,
            packets: OriginalPackets::candidate(
                private_dispatch::OriginalPackets::candidate(original),
                extra,
                scan,
            ),
        }
    }
    fn witness(&self) -> Witness<'_> {
        Witness {
            dispatch: &self.dispatch,
            descriptor: &self.descriptor,
            returning: &self.returning,
        }
    }
    fn control_accepts(&self, program: &Program) -> bool {
        let mut scratch = Scratch::new();
        let mut check = |values: &[F]| {
            if values.iter().all(|value| *value == F::ZERO) {
                Ok(())
            } else {
                Err(())
            }
        };
        let mut out = Stream::new(&mut scratch, &mut check);
        append_control_residues(
            &mut out,
            program,
            &self.schedule,
            self.witness(),
            &self.packets,
        );
        out.finish().is_ok()
    }
    fn accepts(&self, program: &Program) -> bool {
        let mut scratch = Scratch::new();
        let mut check = |values: &[F]| {
            if values.iter().all(|value| *value == F::ZERO) {
                Ok(())
            } else {
                Err(())
            }
        };
        let mut out = Stream::new(&mut scratch, &mut check);
        let decoded = append_control_residues(
            &mut out,
            program,
            &self.schedule,
            self.witness(),
            &self.packets,
        );
        if out.finish().is_err() {
            return false;
        }
        evaluate_scan(
            &self.schedule,
            &decoded,
            &self.packets,
            &mut scratch,
            &mut |_, values| check(values),
        )
        .is_ok()
    }
    fn replace_packet(&mut self, index: usize, packet: [F; packet::WIDTH]) {
        if index < private_dispatch::PORTS {
            // Test-only reconstruction of one small fixed packet owner.
            let mut original =
                core::array::from_fn(|slot| *self.packets.dispatch.producer(slot).unwrap());
            original[index] = packet;
            self.packets.dispatch = private_dispatch::OriginalPackets::candidate(original);
        } else if index < FIXED_PORTS {
            self.packets.extra[index - private_dispatch::PORTS] = packet;
        } else {
            let index = index - FIXED_PORTS;
            let cell = self.packets.scan.get_mut(index / 2);
            if index % 2 == 0 {
                cell.child = packet;
            } else {
                cell.copyback = packet;
            }
        }
    }
}

#[test]
fn derived_original_schemas_join_all_scan_cells_child_and_root_returns() {
    let program = program();
    assert_eq!(program.callables().len, 3);
    assert_eq!(program.callables().entries[0].arguments, 0);
    assert_eq!(program.callables().entries[1].arguments, 2);
    assert_eq!(program.callables().entries[1].results, 2);
    assert_eq!(program.callables().entries[1].entry, 16);
    assert!(program.callables().entries[1].absolute > 16);
    for (slot, root) in [
        (Some(0), false),
        (Some(1), false),
        (Some(2), true),
        (Some(4), false),
        (Some(5), false),
        (None, false),
    ] {
        assert!(
            Fixture::new(&program, slot, root).accepts(&program),
            "slot={slot:?}, root={root}"
        );
    }
}

#[test]
fn coherent_forged_descriptor_fields_cannot_replace_original_metadata() {
    let program = program();
    let mut fixture = Fixture::new(&program, Some(0), false);
    for (entry, frame, arguments, results) in [
        (16, 144, 2, 2),
        (16, 128, 3, 2),
        (16, 128, 2, 3),
        (20, 128, 2, 2),
        (0, 128, 2, 2),
        (program.callables().entries[1].absolute, 128, 2, 2),
    ] {
        let (row, mut packets) = frame_descriptor::tests::callable_lookup_witness(
            entry, frame, arguments, results, true,
        );
        for (index, packet) in packets.iter_mut().enumerate() {
            if packet[ENABLED] == F::ONE {
                packet[CLOCK] = F(u64::from(
                    fixture.schedule.clocks[private_dispatch::PORTS + index],
                ));
            }
        }
        fixture.descriptor = row;
        fixture.packets.extra[..frame_descriptor::PORTS].copy_from_slice(&packets);
        assert!(
            !fixture.control_accepts(&program),
            "entry={entry}, frame={frame}, arguments={arguments}, results={results}"
        );
    }
}

#[test]
fn return_lookup_uses_active_relative_entry_not_continuation_or_another_generation() {
    let program = program();
    let mut valid = Fixture::new(&program, Some(4), false);
    assert!(valid.accepts(&program));
    for selector in [0, 2] {
        valid.returning[1] = F::ZERO;
        valid.returning[selector] = F::ONE;
        assert!(!valid.control_accepts(&program));
        valid.returning[selector] = F::ZERO;
        valid.returning[1] = F::ONE;
    }
    let original = valid.packets.extra[OPERANDS + 4];
    for replacement in [
        program.callables().entries[1].absolute,
        program.callables().entries[0].absolute + 4,
    ] {
        valid.packets.extra[OPERANDS + 4] = read(Space::Owner, 3, 11, replacement);
        valid.packets.extra[OPERANDS + 4][CLOCK] = original[CLOCK];
        assert!(!valid.control_accepts(&program));
    }
    valid.packets.extra[OPERANDS + 4] = original;
    valid.packets.extra[OPERANDS + 4][GENERATION] = F(2);
    valid.packets.extra[OPERANDS + 4][KEY] = original[KEY].sub(F(1 << 32));
    assert!(!valid.control_accepts(&program));
    valid.packets.extra[OPERANDS + 4] = original;
    valid.packets.extra[OPERANDS + 4][packet::BEFORE_TAG] = F::ONE;
    valid.packets.extra[OPERANDS + 4][packet::AFTER_TAG] = F::ONE;
    assert!(!valid.control_accepts(&program));
}

#[test]
fn every_fixed_packet_and_lookup_selector_remains_constrained() {
    let program = program();
    for (slot, root) in [
        (Some(0), false),
        (Some(2), true),
        (Some(4), false),
        (None, false),
    ] {
        let mut fixture = Fixture::new(&program, slot, root);
        assert!(fixture.accepts(&program));
        for index in 0..FIXED_PORTS {
            let original = *fixture.packets.producer(index).unwrap();
            for column in 0..packet::WIDTH {
                let mut changed = original;
                changed[column] = changed[column].add(F::ONE);
                fixture.replace_packet(index, changed);
                let prior_link = index == 13
                    && slot.is_some_and(|slot| slot < 2)
                    && ((BEFORE..BEFORE + 4).contains(&column) || column == packet::BEFORE_TAG);
                // Endpoint headers bind in the scan; all other fixed roles bind in control.
                if !prior_link {
                    let accepts = if index < private_dispatch::PORTS + RESULT_START {
                        fixture.control_accepts(&program)
                    } else {
                        fixture.accepts(&program)
                    };
                    assert!(!accepts, "slot={slot:?}, packet={index}, column={column}");
                }
                fixture.replace_packet(index, original);
            }
        }
        for index in FIXED_PORTS..FIXED_PORTS + 2 {
            let original = *fixture.packets.producer(index).unwrap();
            for column in 0..packet::WIDTH {
                let mut changed = original;
                changed[column] = changed[column].add(F::ONE);
                fixture.replace_packet(index, changed);
                assert!(
                    !fixture.accepts(&program),
                    "first-cell packet={index}, column={column}"
                );
                fixture.replace_packet(index, original);
            }
        }
        for selector in 0..SELECTORS {
            fixture.returning[selector] = fixture.returning[selector].add(F::ONE);
            assert!(!fixture.control_accepts(&program));
            fixture.returning[selector] = fixture.returning[selector].sub(F::ONE);
        }
        assert!(fixture.packets.producer(PORTS).is_none());
    }
}

#[test]
fn changed_artifact_absolute_prefix_and_private_metadata_do_not_authorize_root() {
    let program = program();
    let valid = Fixture::new(&program, Some(0), false);
    let mut interface = program.artifact().contract_interface().clone();
    interface.compiler_fingerprint.push_str("-different-prefix");
    interface.callables[1].frame_bytes += 16;
    let mut bytes = program.artifact().metadata().encode();
    bytes.extend(interface.encode_section());
    bytes.extend_from_slice(&program.artifact().artifact()[program.artifact().code_offset()..]);
    let changed = Program::new(ivm::prepare_contract(bytes.into()).unwrap()).unwrap();
    assert!(!valid.control_accepts(&changed));
    assert!(Fixture::new(&changed, Some(0), false).accepts(&changed));
    let mut padded = Fixture::new(&program, None, false);
    padded.packets.extra[9] = read(Space::Owner, 1, 4, ivm::Memory::STACK_START);
    assert!(!padded.control_accepts(&program));
    assert!(Schedule::new(7, u32::MAX).is_none());
}

#[test]
fn exact_window_has_every_original_once_and_only_the_54_reserved_zero_gaps() {
    let program = program();
    let fixture = Fixture::new(&program, Some(4), false);
    let mut hits = vec![0; PORTS];
    let mut gaps = 0;
    for offset in 0..CLOCK_SLOTS {
        let actual = fixture.schedule.producer_at_clock(&fixture.packets, offset);
        if let Some(index) = (0..PORTS)
            .find(|index| core::ptr::eq(actual, fixture.packets.producer(*index).unwrap()))
        {
            hits[index] += 1;
        } else {
            assert!((22..30).contains(&offset) || (54..100).contains(&offset));
            assert_eq!(actual, &[F::ZERO; packet::WIDTH]);
            gaps += 1;
        }
    }
    assert_eq!(CLOCK_SLOTS, 8297);
    assert_eq!(PORTS, 8243);
    assert_eq!(gaps, 54);
    assert!(hits.iter().all(|count| *count == 1));
}

#[test]
fn complete_scan_checks_last_cell_and_inactive_cells_without_large_stack_banks() {
    let program = program();
    for slot in [Some(4), None] {
        let mut fixture = Fixture::new(&program, slot, false);
        for index in [0, return_copyback::CELLS / 2, return_copyback::CELLS - 1] {
            let original = fixture.packets.scan.get(index).row[0];
            fixture.packets.scan.get_mut(index).row[0] = original.add(F::ONE);
            assert!(!fixture.accepts(&program), "slot={slot:?}, cell={index}");
            fixture.packets.scan.get_mut(index).row[0] = original;
            for port in [0, 1] {
                let packet_index = FIXED_PORTS + index * 2 + port;
                let original = *fixture.packets.producer(packet_index).unwrap();
                let mut changed = original;
                changed[CLOCK] = changed[CLOCK].add(F::ONE);
                fixture.replace_packet(packet_index, changed);
                assert!(!fixture.accepts(&program));
                fixture.replace_packet(packet_index, original);
            }
        }
    }
}

#[test]
fn composed_callable_relations_retain_exact_degree_four_and_lookup_three() {
    use crate::execution_proofs::stark::proof_managed_note_stark::degree_audit::measured_maximum_affine_degree_v1;
    let program = program();
    let descriptor = private_dispatch::WIDTH;
    let returning = descriptor + frame_descriptor::WIDTH;
    let first_cell = returning + SELECTORS;
    let packet_start = first_cell + return_copyback::WIDTH;
    let mut fixture = Fixture::new(&program, Some(4), false);
    for (suffix, declared) in [(false, MAXIMUM_DEGREE), (true, 3)] {
        let degree = measured_maximum_affine_degree_v1(
            [0xcb; 32],
            [packet_start + FIXED_PORTS * packet::WIDTH, 0, 0, 0, 0],
            8,
            declared,
            |row, _, _, _, _| {
                for index in 0..FIXED_PORTS {
                    fixture.replace_packet(
                        index,
                        row[packet_start + index * packet::WIDTH
                            ..packet_start + (index + 1) * packet::WIDTH]
                            .try_into()
                            .unwrap(),
                    );
                }
                fixture
                    .packets
                    .scan
                    .get_mut(0)
                    .row
                    .copy_from_slice(&row[first_cell..packet_start]);
                let witness = Witness {
                    dispatch: row[..descriptor].try_into().unwrap(),
                    descriptor: row[descriptor..returning].try_into().unwrap(),
                    returning: row[returning..first_cell].try_into().unwrap(),
                };
                let mut residues = Vec::new();
                append_control_residues(
                    &mut residues,
                    &program,
                    &fixture.schedule,
                    witness,
                    &fixture.packets,
                );
                if suffix {
                    let mut dispatcher = Vec::new();
                    private_dispatch::append_residues(
                        &mut dispatcher,
                        &program,
                        fixture.schedule.dispatch,
                        witness.dispatch,
                        &fixture.packets.dispatch,
                    );
                    assert_eq!(&residues[..dispatcher.len()], dispatcher.as_slice());
                    residues.drain(..dispatcher.len());
                }
                Ok::<_, core::convert::Infallible>(residues)
            },
        );
        assert_eq!(degree, usize::from(declared));
    }
}

fn maximum_result_program() -> Program {
    use ivm_abi::{
        call::{CallSchemaV1, CallTypeNodeV1},
        entrypoint::EntrypointValueKindV1,
    };
    let program = program();
    let mut interface = program.artifact().contract_interface().clone();
    interface.callables[1].results = CallSchemaV1 {
        nodes: core::iter::once(CallTypeNodeV1::Tuple(8192))
            .chain((0..8192).map(|_| CallTypeNodeV1::Leaf(EntrypointValueKindV1::Bool)))
            .collect(),
    };
    let mut bytes = program.artifact().metadata().encode();
    bytes.extend(interface.encode_section());
    bytes.extend_from_slice(&program.artifact().artifact()[program.artifact().code_offset()..]);
    Program::new(ivm::prepare_contract(bytes.into()).unwrap()).unwrap()
}

#[test]
fn maximum_shifted_interval_checks_every_cell_and_preserves_parent_mask() {
    let program = maximum_result_program();
    let start = ivm::Memory::STACK_START + 8;
    let mut fixture = Fixture::at(&program, Some(4), false, 5000, start);
    assert!(fixture.accepts(&program));
    for (index, missing) in [(0, 8), (2048, 0), (4096, 0)] {
        let (row, mut packets) = return_copyback::tests::callable_lookup_witness(
            true,
            8192,
            2,
            start,
            index,
            u16::MAX ^ (1 << missing),
            0,
        );
        packets[4][CLOCK] = fixture.packets.scan.get(index).child[CLOCK];
        packets[5][CLOCK] = fixture.packets.scan.get(index).copyback[CLOCK];
        let mut original = scan_storage::Cell {
            row,
            child: packets[4],
            copyback: packets[5],
        };
        core::mem::swap(fixture.packets.scan.get_mut(index), &mut original);
        assert!(
            !fixture.accepts(&program),
            "missing initialization cell={index}"
        );
        core::mem::swap(fixture.packets.scan.get_mut(index), &mut original);
    }
    let index = 4096;
    let (row, mut packets) = return_copyback::tests::callable_lookup_witness(
        true,
        8192,
        2,
        start,
        index,
        u16::MAX,
        0xa55a,
    );
    packets[4][CLOCK] = fixture.packets.scan.get(index).child[CLOCK];
    packets[5][CLOCK] = fixture.packets.scan.get(index).copyback[CLOCK];
    *fixture.packets.scan.get_mut(index) = scan_storage::Cell {
        row,
        child: packets[4],
        copyback: packets[5],
    };
    assert!(fixture.accepts(&program));
    fixture.packets.scan.get_mut(index).copyback[packet::AFTER] = F(255);
    assert!(!fixture.accepts(&program));
}

#[test]
fn compiled_artifacts_reject_zero_result_schemas_including_empty_forests() {
    let original = program();
    let mut interface = original.artifact().contract_interface().clone();
    interface.callables[1].results = ivm_abi::call::CallSchemaV1 { nodes: Vec::new() };
    let mut bytes = original.artifact().metadata().encode();
    bytes.extend(interface.encode_section());
    bytes.extend_from_slice(&original.artifact().artifact()[original.artifact().code_offset()..]);
    assert!(ivm::prepare_contract(bytes.into()).is_err());
}

#[test]
fn swapping_inactive_cells_cannot_replace_the_fixed_scan_schedule() {
    let program = program();
    let mut fixture = Fixture::new(&program, None, false);
    assert!(fixture.accepts(&program));
    fixture.packets.scan.swap(1, return_copyback::CELLS - 1);
    assert!(!fixture.accepts(&program));
    fixture.packets.scan.swap(1, return_copyback::CELLS - 1);
    assert!(fixture.accepts(&program));
}

#[test]
fn shared_child_selection_derives_every_field_from_original_fetch_and_schemas() {
    let program = program();
    for slot in 0..private_dispatch::MAX_WORDS {
        let mut fetch = [F::ZERO; CAPACITY];
        fetch[slot] = F::ONE;
        let (child, selected, absolute) = program.callables().select_child(&fetch);
        if let Some(index) = program.callables().children[slot] {
            let original = &program.artifact().contract_interface().callables[index];
            let limbs = |value: u64| core::array::from_fn(|i| F((value >> (16 * i)) & 0xffff));
            assert_eq!(selected, F::ONE);
            assert_eq!(*child.entry_pc(), limbs(original.entry_pc));
            assert_eq!(child.frame_bytes(), F(u64::from(original.frame_bytes)));
            assert_eq!(
                child.argument_words(),
                F(original.argument_word_count().unwrap() as u64)
            );
            assert_eq!(
                child.result_words(),
                F(original.result_word_count().unwrap() as u64)
            );
            assert_eq!(
                absolute,
                limbs(
                    (program.artifact().code_offset() - program.artifact().header_len()) as u64
                        + original.entry_pc
                )
            );
        } else {
            assert_eq!(selected, F::ZERO);
            assert_eq!(*child.entry_pc(), [F::ZERO; 4]);
            assert_eq!(child.frame_bytes(), F::ZERO);
            assert_eq!(child.argument_words(), F::ZERO);
            assert_eq!(child.result_words(), F::ZERO);
            assert_eq!(absolute, [F::ZERO; 4]);
        }
    }
    let (child, selected, absolute) = program.callables().select_child(&[F::ZERO; CAPACITY]);
    assert_eq!(selected, F::ZERO);
    assert_eq!(*child.entry_pc(), [F::ZERO; 4]);
    assert_eq!(child.frame_bytes(), F::ZERO);
    assert_eq!(child.argument_words(), F::ZERO);
    assert_eq!(child.result_words(), F::ZERO);
    assert_eq!(absolute, [F::ZERO; 4]);
}
