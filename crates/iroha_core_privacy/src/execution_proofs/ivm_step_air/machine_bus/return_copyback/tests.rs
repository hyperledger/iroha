//! Byte-interval oracle, complete scan, and original packet mutation controls.

use super::*;
use packet::{Event, Space};

fn bytes(value: u64) -> [u8; 16] {
    let mut result = [0; 16];
    result[..8].copy_from_slice(&value.to_le_bytes());
    result
}
fn event(
    space: Space,
    generation: u16,
    index: u32,
    before: u64,
    after: u64,
    write: bool,
    clock: u32,
) -> [F; packet::WIDTH] {
    Event {
        space,
        vm: 7,
        generation,
        index,
        before: bytes(before),
        after: bytes(after),
        before_private: 0,
        after_private: 0,
        write,
    }
    .fields(clock as usize)
}
fn set_bits(target: &mut [F], value: u64) {
    for (i, bit) in target.iter_mut().enumerate() {
        *bit = F((value >> i) & 1);
    }
}
fn schedule(offset: usize) -> Schedule {
    schedules(7, [10, 11, 12, 13], 100)
        .unwrap()
        .nth(offset)
        .unwrap()
}

#[derive(Clone)]
struct Fixture {
    schedule: Schedule,
    row: [F; WIDTH],
    packets: [[F; packet::WIDTH]; 6],
    required: u16,
}
impl Fixture {
    fn new(start: u64, end: u64, parent: u16, offset: usize) -> Self {
        Self::build(true, start, end, parent, offset, u16::MAX, 0xa55a)
    }
    fn build(
        selected: bool,
        start: u64,
        end: u64,
        parent: u16,
        offset: usize,
        child_mask: u16,
        parent_mask: u16,
    ) -> Self {
        let schedule = schedule(offset);
        let (start, end, active, parent) = if selected {
            (start, end, 7, parent)
        } else {
            (0, 0, 0, 0)
        };
        let cell = (start >> 4) + offset as u64;
        // Independent byte-interval oracle; no AIR mask or comparison helper.
        let required = (0..16).fold(0_u16, |mask, byte| {
            let address = cell * 16 + byte;
            mask | if selected && start <= address && address < end {
                1 << byte
            } else {
                0
            }
        });
        let child_enabled = required != 0;
        let parent_enabled = child_enabled && parent != 0;
        let child_mask = if child_enabled { child_mask } else { 0 };
        let parent_mask = if parent_enabled { parent_mask } else { 0 };
        let mut row = [F::ZERO; WIDTH];
        set_bits(&mut row[START..END], start);
        set_bits(&mut row[END..CELL], end);
        set_bits(&mut row[CELL..COMPARE], cell);
        set_bits(&mut row[ACTIVE..PARENT], active);
        set_bits(&mut row[PARENT..LENGTH], u64::from(parent));
        set_bits(&mut row[LENGTH..LENGTH_INVERSE], end.wrapping_sub(start));
        row[LENGTH_INVERSE] = pack(&row[LENGTH..LENGTH_INVERSE]).inv().unwrap_or(F::ZERO);
        row[ACTIVE_INVERSE] = F(active).inv().unwrap_or(F::ZERO);
        row[HAS_PARENT] = F(u64::from(parent != 0));
        row[PARENT_INVERSE] = F(u64::from(parent)).inv().unwrap_or(F::ZERO);
        set_bits(&mut row[CHILD_MASK..PARENT_MASK], u64::from(child_mask));
        set_bits(&mut row[PARENT_MASK..LOWER], u64::from(parent_mask));
        row[LOWER] = F(u64::from(required & 0xff != 0));
        row[UPPER] = F(u64::from(required & 0xff00 != 0));
        row[CHILD_ENABLED] = F(u64::from(child_enabled));
        row[PARENT_ENABLED] = F(u64::from(parent_enabled));
        for half in 0..2 {
            let bank =
                &mut row[COMPARE + half * COMPARE_WIDTH..COMPARE + (half + 1) * COMPARE_WIDTH];
            let left = cell * 16 + half as u64 * 8;
            let mut borrow = 0_i64;
            for limb in 0..5 {
                let difference = u64::cast_signed((left >> (limb * 8)) & 255)
                    - u64::cast_signed((end >> (limb * 8)) & 255)
                    - borrow;
                borrow = i64::from(difference < 0);
                set_bits(
                    &mut bank[limb * 8..(limb + 1) * 8],
                    difference.rem_euclid(256) as u64,
                );
                bank[40 + limb] = F(i64::cast_unsigned(borrow));
            }
        }
        let mut packets = [[F::ZERO; packet::WIDTH]; 6];
        if selected {
            packets[0] = event(
                Space::Owner,
                0,
                0,
                active,
                u64::from(parent),
                true,
                schedule.owner_clocks[0],
            );
            packets[1] = event(
                Space::Owner,
                active as u16,
                2,
                u64::from(parent),
                u64::from(parent),
                false,
                schedule.owner_clocks[1],
            );
            packets[2] = event(
                Space::Owner,
                active as u16,
                8,
                start,
                start,
                false,
                schedule.owner_clocks[2],
            );
            packets[3] = event(
                Space::Owner,
                active as u16,
                9,
                end,
                end,
                false,
                schedule.owner_clocks[3],
            );
        }
        if child_enabled {
            packets[4] = event(
                Space::Initialization,
                active as u16,
                cell as u32,
                u64::from(child_mask),
                u64::from(child_mask),
                false,
                schedule.child_clock,
            );
        }
        if parent_enabled {
            packets[5] = event(
                Space::Initialization,
                parent,
                cell as u32,
                u64::from(parent_mask),
                u64::from(parent_mask | required),
                true,
                schedule.parent_clock,
            );
        }
        Self {
            schedule,
            row,
            packets,
            required,
        }
    }
    fn residues(&self) -> Vec<F> {
        let mut out = Vec::new();
        append_residues(
            &mut out,
            self.schedule,
            &self.row,
            Ports {
                active: &self.packets[0],
                parent: &self.packets[1],
                result_start: &self.packets[2],
                result_end: &self.packets[3],
                child: &self.packets[4],
                copyback: &self.packets[5],
            },
        );
        assert_eq!(out.len(), CONSTRAINTS);
        out
    }
    fn accepts(&self) -> bool {
        self.residues().iter().all(|value| *value == F::ZERO)
    }
}

#[test]
fn all_4097_slots_cover_maximum_shifted_results_and_copy_back_only_to_immediate_parent() {
    let start = ivm::Memory::STACK_START + 8;
    let end = start + 65536;
    for parent in [0, 3] {
        let mut total = 0;
        for offset in 0..CELLS {
            let fixture = Fixture::new(start, end, parent, offset);
            assert!(fixture.accepts(), "parent={parent} offset={offset}");
            total += fixture.required.count_ones();
            assert_eq!(fixture.packets[4][packet::GENERATION], F(7));
            if parent == 0 {
                assert_eq!(fixture.packets[5], [F::ZERO; packet::WIDTH]);
            } else {
                assert_eq!(fixture.packets[5][packet::GENERATION], F(3));
                assert_eq!(
                    fixture.packets[5][packet::AFTER],
                    F(u64::from(0xa55a | fixture.required))
                );
            }
            assert_eq!(
                fixture.required,
                if offset == 0 {
                    0xff00
                } else if offset == CELLS - 1 {
                    0xff
                } else {
                    0xffff
                }
            );
        }
        assert_eq!(total, 65536);
    }
}

#[test]
fn aligned_half_tables_derive_exact_masks_and_padding_is_canonical() {
    for (start, end, expected) in [
        (0, 8, 0xff),
        (8, 16, 0xff00),
        (0, 16, 0xffff),
        (8, 24, 0xff00),
    ] {
        let first = Fixture::new(start, end, 3, 0);
        assert!(first.accepts());
        assert_eq!(first.required, expected);
        let second = Fixture::new(start, end, 3, 1);
        assert!(second.accepts());
        assert_eq!(second.required, if end == 24 { 0xff } else { 0 });
        let padding = Fixture::new(start, end, 3, CELLS - 1);
        assert!(padding.accepts());
        assert_eq!(padding.packets[4..], [[F::ZERO; packet::WIDTH]; 2]);
    }
    for offset in [0, 1, CELLS - 1] {
        let inactive = Fixture::build(false, 99, 999, 4, offset, u16::MAX, u16::MAX);
        assert!(inactive.accepts());
        assert_eq!(inactive.packets, [[F::ZERO; packet::WIDTH]; 6]);
        let mut leaked = inactive.clone();
        leaked.packets[5][packet::BEFORE] = F::ONE;
        assert!(!leaked.accepts());
    }
}

#[test]
fn every_required_child_byte_must_be_initialized_and_parent_outside_bits_are_preserved() {
    for byte in 0..16 {
        let fixture = Fixture::build(true, 16, 32, 3, 0, u16::MAX ^ (1 << byte), 0);
        assert!(!fixture.accepts(), "uninitialized byte={byte}");
    }
    for parent_mask in [0, 1, 0x00ff, 0xff00, 0xa55a, u16::MAX] {
        for (start, end, child_mask) in [(8, 16, 0xff00), (0, 8, 0x00ff)] {
            let fixture = Fixture::build(true, start, end, 3, 0, child_mask, parent_mask);
            assert!(fixture.accepts());
            assert_eq!(
                fixture.packets[5][packet::AFTER],
                F(u64::from(parent_mask | fixture.required))
            );
            let mut discarded = fixture.clone();
            discarded.packets[5][packet::AFTER] = F(u64::from(fixture.required));
            assert_eq!(discarded.accepts(), parent_mask & !fixture.required == 0);
        }
    }
}

#[test]
fn successful_return_rejects_empty_unaligned_reversed_oversized_and_unbounded_intervals() {
    for (start, end) in [
        (8, 8),
        (1, 16),
        (8, 17),
        (16, 8),
        (0, 65544),
        (1 << 36, (1 << 36) + 8),
        ((1 << 36) - 8, 1 << 36),
    ] {
        assert!(
            !Fixture::new(start, end, 3, 0).accepts(),
            "start={start} end={end}"
        );
    }
    assert!(Fixture::new((1 << 36) - 16, (1 << 36) - 8, 3, 0).accepts());
    assert!(Fixture::new((1 << 36) - 16, (1 << 36) - 8, 3, CELLS - 1).accepts());
}

#[test]
fn every_original_packet_and_private_witness_column_is_bound() {
    let fixture = Fixture::new(
        ivm::Memory::STACK_START,
        ivm::Memory::STACK_START + 16,
        3,
        0,
    );
    assert!(fixture.accepts());
    for packet in 0..6 {
        for column in 0..packet::WIDTH {
            let mut changed = fixture.clone();
            changed.packets[packet][column] = changed.packets[packet][column].add(F::ONE);
            assert!(!changed.accepts(), "packet={packet} column={column}");
        }
    }
    for column in 0..WIDTH {
        let mut changed = fixture.clone();
        changed.row[column] = changed.row[column].add(F::ONE);
        assert!(!changed.accepts(), "column={column}");
    }
}

#[test]
fn complete_public_schedule_has_disjoint_clocks_and_rejects_aliases_and_overflow() {
    let schedule = schedules(7, [10, 11, 12, 13], 100)
        .unwrap()
        .collect::<Vec<_>>();
    assert_eq!(schedule.len(), CELLS);
    for (offset, slot) in schedule.iter().enumerate() {
        assert_eq!(slot.offset, offset);
        assert_eq!(slot.child_clock, 100 + 2 * offset as u32);
        assert_eq!(slot.parent_clock, 101 + 2 * offset as u32);
        assert_eq!(slot.owner_clocks, [10, 11, 12, 13]);
    }
    assert!(schedules(7, [10, 10, 12, 13], 100).is_none());
    assert!(schedules(7, [10, 11, 12, 100], 100).is_none());
    assert!(schedules(7, [10, 11, 12, 100 + 2 * CELLS as u32 - 1], 100).is_none());
    assert!(schedules(7, [10, 11, 12, 13], u32::MAX - 100).is_none());
    assert!(schedules(7, [10, 11, 12, 13], u32::MAX - (2 * CELLS - 1) as u32).is_some());
}

#[test]
fn original_return_scan_and_copyback_residues_have_degree_three() {
    use crate::execution_proofs::stark::proof_managed_note_stark::degree_audit::measured_maximum_affine_degree_v1;
    for offset in [0, 1, CELLS - 1] {
        let degree = measured_maximum_affine_degree_v1(
            [142; 32],
            [WIDTH + 6 * packet::WIDTH, 0, 0, 0, 0],
            8,
            3,
            |row, _, _, _, _| {
                let packet = |i: usize| {
                    row[WIDTH + i * packet::WIDTH..WIDTH + (i + 1) * packet::WIDTH]
                        .try_into()
                        .unwrap()
                };
                let mut output = Vec::new();
                append_residues(
                    &mut output,
                    schedule(offset),
                    row[..WIDTH].try_into().unwrap(),
                    Ports {
                        active: packet(0),
                        parent: packet(1),
                        result_start: packet(2),
                        result_end: packet(3),
                        child: packet(4),
                        copyback: packet(5),
                    },
                );
                Ok::<_, core::convert::Infallible>(output)
            },
        );
        assert_eq!(degree, 3);
    }
}

#[derive(Clone)]
struct OperandFixture {
    scan: Fixture,
    schedule: OperandSchedule,
    packets: [[F; packet::WIDTH]; OPERAND_PORTS],
    entry: [F; 4],
    count: F,
}
impl OperandFixture {
    fn new(selected: bool) -> Self {
        let scan = Fixture::build(
            selected,
            ivm::Memory::STACK_START,
            ivm::Memory::STACK_START + 16,
            3,
            0,
            u16::MAX,
            0,
        );
        let schedule = OperandSchedule::new(7, [20, 21, 22, 23, 24]).unwrap();
        let mut packets = [[F::ZERO; packet::WIDTH]; OPERAND_PORTS];
        let (entry, count) = if selected {
            let saved_sp = ivm::Memory::STACK_START + 1024;
            for (slot, space, generation, index, value) in [
                (0, Space::Register, 0, 10, ivm::Memory::STACK_START),
                (1, Space::Register, 0, 11, 2),
                (2, Space::Register, 0, 31, saved_sp),
                (3, Space::Owner, 7, 10, saved_sp),
                (4, Space::Owner, 7, 11, 4),
            ] {
                packets[slot] = event(
                    space,
                    generation,
                    index,
                    value,
                    value,
                    false,
                    schedule.clocks[slot],
                );
            }
            ([F(4), F::ZERO, F::ZERO, F::ZERO], F(2))
        } else {
            ([F::ZERO; 4], F::ZERO)
        };
        Self {
            scan,
            schedule,
            packets,
            entry,
            count,
        }
    }
    fn accepts(&self) -> bool {
        let mut output = Vec::new();
        append_operand_residues(
            &mut output,
            self.schedule,
            &self.scan.row,
            &super::super::callable_lookup::SelectedCallable::unbound_diagnostic(
                self.entry,
                F::ZERO,
                F::ZERO,
                self.count,
            ),
            OperandPorts {
                active: &self.scan.packets[0],
                packets: core::array::from_fn(|i| &self.packets[i]),
            },
        );
        assert_eq!(output.len(), OPERAND_CONSTRAINTS);
        self.scan.accepts() && output.iter().all(|value| *value == F::ZERO)
    }
}

#[test]
fn return_operands_bind_exact_saved_sp_result_interval_and_authenticated_callable_fields() {
    let fixture = OperandFixture::new(true);
    assert!(fixture.accepts());
    for packet in 0..OPERAND_PORTS {
        for column in 0..packet::WIDTH {
            let mut changed = fixture.clone();
            changed.packets[packet][column] = changed.packets[packet][column].add(F::ONE);
            assert!(!changed.accepts(), "packet={packet} column={column}");
        }
    }
    for packet in 0..3 {
        let mut changed = fixture.clone();
        // Preserve the original read pair; changing the actual source still fails.
        changed.packets[packet][packet::BEFORE] = changed.packets[packet][packet::BEFORE].add(F(8));
        changed.packets[packet][packet::AFTER] = changed.packets[packet][packet::AFTER].add(F(8));
        assert!(!changed.accepts());
        let mut private = fixture.clone();
        private.packets[packet][packet::BEFORE_TAG] = F::ONE;
        private.packets[packet][packet::AFTER_TAG] = F::ONE;
        assert!(!private.accepts());
    }
    for limb in 0..4 {
        let mut wrong_callable = fixture.clone();
        wrong_callable.entry[limb] = wrong_callable.entry[limb].add(F::ONE);
        assert!(!wrong_callable.accepts());
    }
    let mut wrong_count = fixture;
    wrong_count.count = F(3);
    assert!(!wrong_count.accepts());
}

#[test]
fn inactive_return_operand_ports_are_zero_and_clock_order_is_strict() {
    let inactive = OperandFixture::new(false);
    assert!(inactive.accepts());
    assert_eq!(inactive.packets, [[F::ZERO; packet::WIDTH]; OPERAND_PORTS]);
    for packet in 0..OPERAND_PORTS {
        let mut leaked = inactive.clone();
        leaked.packets[packet][packet::BEFORE] = F::ONE;
        assert!(!leaked.accepts());
    }
    assert!(OperandSchedule::new(7, [20, 21, 21, 23, 24]).is_none());
    assert!(OperandSchedule::new(7, [21, 20, 22, 23, 24]).is_none());
}

#[test]
fn return_operand_join_has_degree_two_over_all_original_columns() {
    use crate::execution_proofs::stark::proof_managed_note_stark::degree_audit::measured_maximum_affine_degree_v1;
    let degree = measured_maximum_affine_degree_v1(
        [143; 32],
        [WIDTH + 5 + (OPERAND_PORTS + 1) * packet::WIDTH, 0, 0, 0, 0],
        8,
        3,
        |row, _, _, _, _| {
            let first = WIDTH + 5;
            let packet = |i: usize| {
                row[first + i * packet::WIDTH..first + (i + 1) * packet::WIDTH]
                    .try_into()
                    .unwrap()
            };
            let mut output = Vec::new();
            append_operand_residues(
                &mut output,
                OperandSchedule::new(7, [20, 21, 22, 23, 24]).unwrap(),
                row[..WIDTH].try_into().unwrap(),
                &super::super::callable_lookup::SelectedCallable::unbound_diagnostic(
                    row[WIDTH..WIDTH + 4].try_into().unwrap(),
                    F::ZERO,
                    F::ZERO,
                    row[WIDTH + 4],
                ),
                OperandPorts {
                    active: packet(0),
                    packets: core::array::from_fn(|i| packet(i + 1)),
                },
            );
            Ok::<_, core::convert::Infallible>(output)
        },
    );
    assert_eq!(degree, 2);
}

#[test]
#[ignore = "requires the actual ivm native frame-owner producer capture from this candidate"]
fn genuine_native_initialization_and_copyback_match_every_mandatory_cell() {
    let path = std::env::var_os("IROHA_IVM_NATIVE_FRAME_OWNER_CAPTURE")
        .expect("genuine native capture required");
    let bytes = std::fs::read(path).unwrap();
    assert!(bytes.len() < 16 * 1024 * 1024);
    let capture: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
    assert_eq!(
        capture["schema"].as_str(),
        Some("ivm.native-frame-owner-equations.v1")
    );
    assert_eq!(capture["cells"].as_u64(), Some(CELLS as u64));
    let cases = capture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 12);
    for case in cases {
        let root = case["root_return"].as_bool().unwrap();
        let descriptor = case["selected_descriptor"].as_array().unwrap();
        let start = descriptor[4].as_u64().unwrap();
        let end = descriptor[5].as_u64().unwrap();
        let before = case["before_return"]["initialization"].as_array().unwrap();
        let after = case["after_return"]["initialization"].as_array().unwrap();
        let failed = case["before_failed_return"]["initialization"]
            .as_array()
            .unwrap();
        assert_eq!(before.len(), if root { 1 } else { 2 });
        assert_eq!(after.len(), if root { 0 } else { 1 });
        assert_eq!(failed.len(), before.len());
        let child = before.last().unwrap().as_array().unwrap();
        let missing = failed.last().unwrap().as_array().unwrap();
        assert_eq!(child.len(), CELLS);
        assert_eq!(missing.len(), CELLS);
        let parent_before = (!root).then(|| before[0].as_array().unwrap());
        let parent_after = (!root).then(|| after[0].as_array().unwrap());
        if !root {
            assert_eq!(parent_before.unwrap().len(), CELLS);
            assert_eq!(parent_after.unwrap().len(), CELLS);
        }
        let mut missing_refused = false;
        for offset in 0..CELLS {
            let child_mask = u16::try_from(child[offset].as_u64().unwrap()).unwrap();
            let parent_mask = parent_before.map_or(0, |masks| {
                u16::try_from(masks[offset].as_u64().unwrap()).unwrap()
            });
            let fixture = Fixture::build(
                true,
                start,
                end,
                if root { 0 } else { 1 },
                offset,
                child_mask,
                parent_mask,
            );
            assert!(
                fixture.accepts(),
                "root={root} start={start} end={end} offset={offset}"
            );
            if let Some(after) = parent_after {
                let observed = after[offset].as_u64().unwrap();
                if fixture.required == 0 {
                    assert_eq!(observed, u64::from(parent_mask));
                } else {
                    assert_eq!(fixture.packets[5][packet::AFTER].0, observed);
                }
            }
            let missing_mask = u16::try_from(missing[offset].as_u64().unwrap()).unwrap();
            let rejected = Fixture::build(
                true,
                start,
                end,
                if root { 0 } else { 1 },
                offset,
                missing_mask,
                parent_mask,
            );
            missing_refused |= !rejected.accepts();
        }
        assert!(
            missing_refused,
            "native missing-byte return must be unsatisfied"
        );
        if root {
            assert_eq!(case["after_return"]["completed"][0].as_u64(), Some(start));
            assert_eq!(case["after_return"]["completed"][1].as_u64(), Some(end));
        }
    }
}

#[test]
#[ignore = "requires the actual ivm compiler-image call-runtime capture from this candidate"]
fn genuine_native_call_runtime_return_operands_bind_protected_state_and_program_metadata() {
    let path = std::env::var_os("IROHA_IVM_NATIVE_CALL_RUNTIME_CAPTURE")
        .expect("genuine native runtime capture required");
    let bytes = std::fs::read(path).unwrap();
    assert!(bytes.len() < 4 * 1024 * 1024);
    let capture: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
    assert_eq!(
        capture["schema"].as_str(),
        Some("ivm.native-call-runtime-equations.v1")
    );
    assert!(
        capture["failed_sp_gas_after"].as_u64().unwrap()
            < capture["failed_sp_gas_before"].as_u64().unwrap()
    );
    for (entry, key, root) in [
        ("root_entry", "root_return", true),
        ("child_entry", "child_return", false),
    ] {
        let returned = &capture[key];
        let source = returned["before_owner"]["descriptors"]
            .as_array()
            .unwrap()
            .last()
            .unwrap();
        let registers = returned["operands"]["values"].as_array().unwrap();
        let tags = returned["operands"]["tags"].as_array().unwrap();
        assert_eq!(registers.len(), 5);
        assert_eq!(tags.len(), 5);
        let start = source[4].as_u64().unwrap();
        let end = source[5].as_u64().unwrap();
        let initial = returned["before_owner"]["initialization"]
            .as_array()
            .unwrap();
        let child_mask = u16::try_from(initial.last().unwrap()[0].as_u64().unwrap()).unwrap();
        let parent_mask = if root {
            0
        } else {
            u16::try_from(initial[0][0].as_u64().unwrap()).unwrap()
        };
        let scan = Fixture::build(
            true,
            start,
            end,
            if root { 0 } else { 1 },
            0,
            child_mask,
            parent_mask,
        );
        let schedule = OperandSchedule::new(7, [20, 21, 22, 23, 24]).unwrap();
        let mut packets = [[F::ZERO; packet::WIDTH]; OPERAND_PORTS];
        for (slot, index, register) in [(0, 0, 10), (1, 1, 11), (2, 4, 31)] {
            let value = registers[index].as_u64().unwrap();
            packets[slot] = event(
                Space::Register,
                0,
                register,
                value,
                value,
                false,
                schedule.clocks[slot],
            );
            let tag = F(u64::from(tags[index].as_bool().unwrap()));
            packets[slot][packet::BEFORE_TAG] = tag;
            packets[slot][packet::AFTER_TAG] = tag;
        }
        for (slot, index, source_index) in [(3, 10, 6), (4, 11, 7)] {
            let value = source[source_index].as_u64().unwrap();
            packets[slot] = event(
                Space::Owner,
                7,
                index,
                value,
                value,
                false,
                schedule.clocks[slot],
            );
        }
        let pc = capture[entry]["entry_pc"].as_u64().unwrap();
        let fixture = OperandFixture {
            scan,
            schedule,
            packets,
            entry: core::array::from_fn(|limb| F((pc >> (limb * 16)) & 0xffff)),
            count: F(capture[entry]["result_words"].as_u64().unwrap()),
        };
        assert!(fixture.accepts());
    }
}

#[test]
fn copyback_witness_tail_uses_its_own_width_and_constrains_all_four_activity_bits() {
    for offset in [0, CELLS - 1] {
        let start = ivm::Memory::STACK_START + 8;
        let fixture = Fixture::new(start, start + 65536, 3, offset);
        assert_eq!(fixture.row.get(LOWER..WIDTH).unwrap().len(), 4);
        const { assert!(LOWER > packet::WIDTH) };
        assert_eq!(fixture.residues().len(), CONSTRAINTS);
        assert!(fixture.accepts());
        for index in LOWER..WIDTH {
            let mut invalid = fixture.clone();
            invalid.row[index] = F(2);
            assert!(!invalid.accepts(), "tail column {index}");
        }
    }
}

/// One fixed scan-cell witness; this helper provides no invocation authority.
pub(in crate::execution_proofs::ivm_step_air::machine_bus) fn callable_lookup_witness(
    selected: bool,
    words: u64,
    parent: u16,
    start: u64,
    offset: usize,
    child_mask: u16,
    parent_mask: u16,
) -> ([F; WIDTH], [[F; packet::WIDTH]; 6]) {
    let mut fixture = Fixture::build(
        selected,
        start,
        start + words * 8,
        parent,
        offset,
        child_mask,
        parent_mask,
    );
    if selected {
        set_bits(&mut fixture.row[ACTIVE..PARENT], 3);
        fixture.row[ACTIVE_INVERSE] = F(3).inv().unwrap();
        fixture.packets[0][packet::BEFORE] = F(3);
        for packet in &mut fixture.packets {
            if packet[packet::GENERATION] == F(7) {
                packet[packet::GENERATION] = F(3);
                packet[packet::KEY] = packet[packet::KEY].sub(F(4 << 32));
            }
        }
    }
    (fixture.row, fixture.packets)
}
