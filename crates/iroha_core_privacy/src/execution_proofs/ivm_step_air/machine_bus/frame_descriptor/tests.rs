//! Successful descriptor bounds, original packet joins, and mutation controls.

use super::*;
use packet::{Event, Space};

#[derive(Clone)]
struct Shape {
    root: bool,
    selected: bool,
    parent: u16,
    generation: u16,
    sp: u64,
    stack_top: u64,
    heap_end: u64,
    argument: u64,
    argument_words: u64,
    result: u64,
    result_words: u64,
    frame: u64,
    entry: u64,
    parent_bounds: [u64; 2],
}
impl Shape {
    fn root() -> Self {
        Self {
            root: true,
            selected: true,
            parent: 0,
            generation: 1,
            sp: 0xdead_beef, // The old root r31 is not the entry SP.
            stack_top: ivm::Memory::STACK_START + 1024,
            heap_end: ivm::Memory::HEAP_START + 1024,
            argument: ivm::Memory::HEAP_START,
            argument_words: 2,
            result: ivm::Memory::HEAP_START + 32,
            result_words: 2,
            frame: 128,
            entry: 4,
            parent_bounds: [0, 0],
        }
    }
    fn child() -> Self {
        let mut shape = Self::root();
        shape.root = false;
        shape.parent = 3;
        shape.generation = 7;
        shape.parent_bounds = [
            ivm::Memory::STACK_START + 512,
            ivm::Memory::STACK_START + 1024,
        ];
        shape.sp = shape.parent_bounds[0];
        shape.argument = shape.parent_bounds[0];
        shape.result = shape.parent_bounds[0] + 32;
        shape
    }
}
fn bytes(value: u64) -> [u8; 16] {
    let mut output = [0; 16];
    output[..8].copy_from_slice(&value.to_le_bytes());
    output
}
fn event(
    space: Space,
    generation: u16,
    index: u32,
    before: u64,
    after: u64,
    write: bool,
    clock: usize,
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
    .fields(clock)
}
fn set_bits(target: &mut [F], value: u64) {
    for (i, target) in target.iter_mut().enumerate() {
        *target = F((value >> i) & 1);
    }
}

#[derive(Clone)]
struct Fixture {
    schedule: Schedule,
    selected: F,
    entry: [F; 4],
    frame: F,
    argument_words: F,
    result_words: F,
    active: [F; packet::WIDTH],
    packets: [[F; packet::WIDTH]; PORTS],
    row: [F; WIDTH],
}
impl Fixture {
    fn new(shape: Shape) -> Self {
        let schedule =
            Schedule::new(7, shape.root, core::array::from_fn(|i| (20 + i) as u32)).unwrap();
        let mut values = [0_u64; WORDS];
        if shape.selected {
            values[SP] = if shape.root {
                shape.stack_top
            } else {
                shape.sp
            };
            values[ARGUMENT] = shape.argument;
            values[ARGUMENT_COUNT] = shape.argument_words;
            values[RESULT] = shape.result;
            values[RESULT_COUNT] = shape.result_words;
            values[FRAME] = shape.frame;
            values[ENTRY] = shape.entry;
            values[STACK_TOP] = shape.stack_top;
            values[STACK_START] = values[SP].wrapping_sub(values[FRAME]);
            values[ARGUMENT_END] =
                values[ARGUMENT].wrapping_add(values[ARGUMENT_COUNT].wrapping_mul(8));
            values[RESULT_END] = values[RESULT].wrapping_add(values[RESULT_COUNT].wrapping_mul(8));
            if shape.root {
                values[HEAP_END] = shape.heap_end;
            } else {
                values[PARENT_START] = shape.parent_bounds[0];
                values[PARENT_END] = shape.parent_bounds[1];
            }
        }
        let mut row = [F::ZERO; WIDTH];
        for (word, &value) in values.iter().enumerate() {
            set_bits(&mut row[word * 64..(word + 1) * 64], value);
        }
        for operation in 0..3 {
            let mut carry = 0_i64;
            for limb_index in 0..4 {
                let value = if operation == 0 {
                    u64::cast_signed(limb(&row, SP, limb_index).0)
                        - u64::cast_signed(limb(&row, FRAME, limb_index).0)
                        - carry
                } else {
                    let (base, count) = if operation == 1 {
                        (ARGUMENT, ARGUMENT_COUNT)
                    } else {
                        (RESULT, RESULT_COUNT)
                    };
                    let addend = values[count].wrapping_mul(8);
                    u64::cast_signed(limb(&row, base, limb_index).0)
                        + u64::cast_signed((addend >> (16 * limb_index)) & 0xffff)
                        + carry
                };
                carry = if operation == 0 {
                    i64::from(value < 0)
                } else {
                    value >> 16
                };
                row[CARRIES + operation * 4 + limb_index] = F(i64::cast_unsigned(carry));
            }
        }
        for index in 0..16 {
            let (left, right) = comparison_operands(&row, index);
            let bank = &mut row
                [COMPARISONS + index * COMPARE_WIDTH..COMPARISONS + (index + 1) * COMPARE_WIDTH];
            let mut borrow = 0_i64;
            for limb_index in 0..4 {
                let difference =
                    u64::cast_signed(pack(&left[limb_index * 16..(limb_index + 1) * 16]).0)
                        - u64::cast_signed(pack(&right[limb_index * 16..(limb_index + 1) * 16]).0)
                        - borrow;
                borrow = i64::from(difference < 0);
                set_bits(
                    &mut bank[limb_index * 16..(limb_index + 1) * 16],
                    difference.rem_euclid(1 << 16) as u64,
                );
                bank[64 + limb_index] = F(i64::cast_unsigned(borrow));
            }
        }
        row[ARGUMENT_NONZERO] = F(u64::from(values[ARGUMENT_COUNT] != 0));
        row[ARGUMENT_INVERSE] = F(values[ARGUMENT_COUNT]).inv().unwrap_or(F::ZERO);
        row[RESULT_INVERSE] = F(values[RESULT_COUNT]).inv().unwrap_or(F::ZERO);
        let mut packets = [[F::ZERO; packet::WIDTH]; PORTS];
        let mut active = [F::ZERO; packet::WIDTH];
        if shape.selected {
            active = event(
                Space::Owner,
                0,
                0,
                u64::from(shape.parent),
                u64::from(shape.generation),
                true,
                10,
            );
            for (i, register) in [10, 11, 12, 13].into_iter().enumerate() {
                let word = [ARGUMENT, ARGUMENT_COUNT, RESULT, RESULT_COUNT][i];
                packets[i] = event(
                    Space::Register,
                    0,
                    register,
                    values[word],
                    values[word],
                    false,
                    20 + i,
                );
            }
            if !shape.root {
                packets[4] = event(Space::Register, 0, 31, values[SP], values[SP], false, 24);
            }
            packets[5] = event(
                Space::Owner,
                0,
                20,
                values[STACK_TOP],
                values[STACK_TOP],
                false,
                25,
            );
            if shape.root {
                packets[6] = event(
                    Space::Owner,
                    0,
                    21,
                    values[HEAP_END],
                    values[HEAP_END],
                    false,
                    26,
                );
            } else {
                for (i, word) in [PARENT_START, PARENT_END].into_iter().enumerate() {
                    packets[7 + i] = event(
                        Space::Owner,
                        shape.parent,
                        4 + i as u32,
                        values[word],
                        values[word],
                        false,
                        27 + i,
                    );
                }
            }
            for (i, word) in [
                STACK_START,
                SP,
                ARGUMENT,
                ARGUMENT_END,
                RESULT,
                RESULT_END,
                SP,
                ENTRY,
            ]
            .into_iter()
            .enumerate()
            {
                packets[9 + i] = event(
                    Space::Owner,
                    shape.generation,
                    DESCRIPTOR_INDEXES[i],
                    0,
                    values[word],
                    true,
                    29 + i,
                );
            }
            if shape.root {
                for (i, word) in [ARGUMENT, ARGUMENT_END, RESULT, RESULT_END]
                    .into_iter()
                    .enumerate()
                {
                    packets[17 + i] = event(
                        Space::Owner,
                        0,
                        16 + i as u32,
                        0,
                        values[word],
                        true,
                        37 + i,
                    );
                }
            }
        }
        Self {
            schedule,
            selected: F(u64::from(shape.selected)),
            entry: core::array::from_fn(|i| F((values[ENTRY] >> (16 * i)) & 0xffff)),
            frame: F(values[FRAME]),
            argument_words: F(values[ARGUMENT_COUNT]),
            result_words: F(values[RESULT_COUNT]),
            active,
            packets,
            row,
        }
    }
    fn residues(&self) -> Vec<F> {
        let mut output = Vec::new();
        append_residues(
            &mut output,
            self.schedule,
            &self.row,
            self.selected,
            &super::super::callable_lookup::SelectedCallable::unbound_diagnostic(
                self.entry,
                self.frame,
                self.argument_words,
                self.result_words,
            ),
            Ports {
                active: &self.active,
                packets: core::array::from_fn(|i| &self.packets[i]),
            },
        );
        assert_eq!(output.len(), CONSTRAINTS);
        output
    }
    fn accepts(&self) -> bool {
        self.residues().into_iter().all(|value| value == F::ZERO)
    }
}

#[test]
fn root_uses_memory_stack_top_and_child_uses_original_public_r31() {
    let root = Fixture::new(Shape::root());
    assert!(root.accepts());
    assert_eq!(root.packets[4], [F::ZERO; packet::WIDTH]);
    assert_eq!(
        limb(&root.row, SP, 0),
        F((ivm::Memory::STACK_START + 1024) & 0xffff)
    );
    let child = Fixture::new(Shape::child());
    assert!(child.accepts());
    assert!(
        child.packets[17..]
            .iter()
            .all(|p| *p == [F::ZERO; packet::WIDTH])
    );
    let mut wrong_sp = Shape::child();
    wrong_sp.sp += 8;
    assert!(!Fixture::new(wrong_sp).accepts());
    for index in 0..5 {
        let mut private = child.clone();
        private.packets[index][packet::BEFORE_TAG] = F::ONE;
        private.packets[index][packet::AFTER_TAG] = F::ONE;
        assert!(!private.accepts());
    }
}

#[test]
fn successful_entry_checks_exact_alignment_counts_caps_and_canonical_empty_arguments() {
    let mut empty = Shape::child();
    empty.argument = 0;
    empty.argument_words = 0;
    assert!(Fixture::new(empty.clone()).accepts());
    empty.argument = ivm::Memory::STACK_START;
    assert!(!Fixture::new(empty).accepts());
    for mutation in 0..8 {
        let mut shape = Shape::root();
        match mutation {
            0 => shape.frame += 8,
            1 => shape.entry += 2,
            2 => shape.argument += 1,
            3 => shape.result += 1,
            4 => shape.stack_top += 1,
            5 => shape.result_words = 0,
            6 => shape.argument_words = 8193,
            7 => shape.frame = 4 * 1024 * 1024 + 16,
            _ => unreachable!(),
        }
        assert!(!Fixture::new(shape).accepts(), "mutation={mutation}");
    }
    let mut maximum = Shape::root();
    maximum.stack_top = ivm::Memory::STACK_START + 4 * 1024 * 1024;
    maximum.frame = 4 * 1024 * 1024;
    maximum.argument_words = 8192;
    maximum.result_words = 8192;
    maximum.result = maximum.argument + 65536;
    maximum.heap_end = maximum.result + 65536;
    assert!(Fixture::new(maximum).accepts());
}

#[test]
fn checked_arithmetic_table_overlap_heap_allocation_and_immediate_parent_bounds_refuse() {
    for mutation in 0..10 {
        let mut shape = if mutation < 5 {
            Shape::root()
        } else {
            Shape::child()
        };
        match mutation {
            0 => shape.result = u64::MAX - 7,
            1 => shape.frame = 4 * 1024 * 1024,
            2 => shape.result = shape.argument + 8,
            3 => shape.argument = ivm::Memory::INPUT_START,
            4 => shape.heap_end = shape.result + 8,
            5 => shape.argument = shape.parent_bounds[0] - 8,
            6 => shape.result = shape.parent_bounds[1] - 8,
            7 => shape.sp = shape.stack_top + 8,
            8 => shape.parent_bounds[1] = shape.result + 8,
            9 => shape.result = shape.argument,
            _ => unreachable!(),
        }
        assert!(!Fixture::new(shape).accepts(), "mutation={mutation}");
    }
}

#[test]
fn original_operand_metadata_and_fresh_descriptor_packets_cannot_be_substituted() {
    let fixture = Fixture::new(Shape::child());
    assert!(fixture.accepts());
    for packet in 0..PORTS {
        for column in 0..packet::WIDTH {
            let mut changed = fixture.clone();
            changed.packets[packet][column] = changed.packets[packet][column].add(F::ONE);
            assert!(!changed.accepts(), "packet={packet} column={column}");
        }
    }
    for column in 0..WIDTH {
        let mut changed = fixture.clone();
        changed.row[column] = changed.row[column].add(F::ONE);
        assert!(!changed.accepts(), "private column={column}");
    }
    for mutation in 0..7 {
        let mut changed = fixture.clone();
        match mutation {
            0..=3 => changed.entry[mutation] = changed.entry[mutation].add(F::ONE),
            4 => changed.frame = changed.frame.add(F::ONE),
            5 => changed.argument_words = changed.argument_words.add(F::ONE),
            6 => changed.result_words = changed.result_words.add(F::ONE),
            _ => unreachable!(),
        }
        assert!(!changed.accepts());
    }
    let mut changed = fixture;
    changed.active[packet::AFTER] = changed.active[packet::AFTER].add(F::ONE);
    assert!(!changed.accepts());
}

#[test]
fn inactive_entry_slots_are_zero_and_completed_root_globals_can_be_replaced() {
    for mut shape in [Shape::root(), Shape::child()] {
        shape.selected = false;
        let inactive = Fixture::new(shape);
        assert!(inactive.accepts());
        assert_eq!(inactive.packets, [[F::ZERO; packet::WIDTH]; PORTS]);
        for packet in 0..PORTS {
            let mut leaked = inactive.clone();
            leaked.packets[packet][packet::BEFORE] = F::ONE;
            assert!(!leaked.accepts());
        }
    }
    let mut reentry = Fixture::new(Shape::root());
    for packet in 17..PORTS {
        reentry.packets[packet][packet::BEFORE] = F(123);
    }
    assert!(
        reentry.accepts(),
        "the same typed history owns previous root-global values"
    );
    reentry.packets[9][packet::BEFORE] = F(123);
    assert!(
        !reentry.accepts(),
        "fresh generation descriptors never inherit old values"
    );
}

#[test]
fn original_descriptor_publication_residues_have_degree_three() {
    use crate::execution_proofs::stark::proof_managed_note_stark::degree_audit::measured_maximum_affine_degree_v1;
    let total = WIDTH + 8 + (PORTS + 1) * packet::WIDTH;
    for root in [false, true] {
        let schedule = Schedule::new(7, root, core::array::from_fn(|i| (20 + i) as u32)).unwrap();
        let degree = measured_maximum_affine_degree_v1(
            [141; 32],
            [total, 0, 0, 0, 0],
            8,
            4,
            |row, _, _, _, _| {
                let first = WIDTH + 8;
                let packet = |i: usize| {
                    row[first + i * packet::WIDTH..first + (i + 1) * packet::WIDTH]
                        .try_into()
                        .unwrap()
                };
                let mut output = Vec::new();
                append_residues(
                    &mut output,
                    schedule,
                    row[..WIDTH].try_into().unwrap(),
                    row[WIDTH],
                    &super::super::callable_lookup::SelectedCallable::unbound_diagnostic(
                        row[WIDTH + 1..WIDTH + 5].try_into().unwrap(),
                        row[WIDTH + 5],
                        row[WIDTH + 6],
                        row[WIDTH + 7],
                    ),
                    Ports {
                        active: packet(0),
                        packets: core::array::from_fn(|i| packet(i + 1)),
                    },
                );
                Ok::<_, core::convert::Infallible>(output)
            },
        );
        assert_eq!(degree, 3);
    }
}

#[test]
#[ignore = "requires the actual ivm native frame-owner producer capture from this candidate"]
fn genuine_native_frame_owner_entries_match_all_original_descriptor_fields() {
    let path = std::env::var_os("IROHA_IVM_NATIVE_FRAME_OWNER_CAPTURE")
        .expect("genuine native capture required");
    let bytes = std::fs::read(path).unwrap();
    assert!(bytes.len() < 16 * 1024 * 1024);
    let capture: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
    assert_eq!(
        capture["schema"].as_str(),
        Some("ivm.native-frame-owner-equations.v1")
    );
    let cases = capture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 12);
    let mut checked = 0;
    for case in cases {
        for entry in case["entries"].as_array().unwrap() {
            let value = |key: &str| entry[key].as_u64().unwrap();
            let root = entry["root"].as_bool().unwrap();
            let fixture = Fixture::new(Shape {
                root,
                selected: true,
                parent: if root { 0 } else { 1 },
                generation: if root { 1 } else { 2 },
                sp: value("sp"),
                stack_top: value("stack_top"),
                heap_end: value("heap_end"),
                argument: value("argument"),
                argument_words: value("argument_words"),
                result: value("result"),
                result_words: value("result_words"),
                frame: value("frame_bytes"),
                entry: value("entry_pc"),
                parent_bounds: [value("parent_start"), value("parent_end")],
            });
            assert!(fixture.accepts());
            let actual = entry["descriptor"].as_array().unwrap();
            assert_eq!(actual.len(), 8);
            for (index, value) in actual.iter().enumerate() {
                assert_eq!(
                    packet::half(&fixture.packets[9 + index], packet::AFTER, 0),
                    value.as_u64().unwrap()
                );
            }
            checked += 1;
        }
    }
    assert_eq!(checked, 18);
}

#[test]
#[ignore = "requires the actual ivm compiler-image call-runtime capture from this candidate"]
fn genuine_native_call_runtime_entries_match_original_operands_and_installed_descriptors() {
    let path = std::env::var_os("IROHA_IVM_NATIVE_CALL_RUNTIME_CAPTURE")
        .expect("genuine native runtime capture required");
    let bytes = std::fs::read(path).unwrap();
    assert!(bytes.len() < 4 * 1024 * 1024);
    let capture: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
    assert_eq!(
        capture["schema"].as_str(),
        Some("ivm.native-call-runtime-equations.v1")
    );
    for (key, root) in [("root_entry", true), ("child_entry", false)] {
        let entry = &capture[key];
        let registers = entry["operands"]["values"].as_array().unwrap();
        let tags = entry["operands"]["tags"].as_array().unwrap();
        assert_eq!(registers.len(), 5);
        assert_eq!(tags.len(), 5);
        assert!(tags.iter().all(|tag| tag.as_bool() == Some(false)));
        let descriptors = entry["owner"]["descriptors"].as_array().unwrap();
        assert_eq!(descriptors.len(), if root { 1 } else { 2 });
        let descriptor = descriptors.last().unwrap().as_array().unwrap();
        let value = |index: usize| registers[index].as_u64().unwrap();
        let fixture = Fixture::new(Shape {
            root,
            selected: true,
            parent: if root { 0 } else { 1 },
            generation: if root { 1 } else { 2 },
            sp: value(4),
            stack_top: entry["owner"]["stack_top"].as_u64().unwrap(),
            heap_end: entry["owner"]["heap_end"].as_u64().unwrap(),
            argument: value(0),
            argument_words: value(1),
            result: value(2),
            result_words: value(3),
            frame: entry["frame_bytes"].as_u64().unwrap(),
            entry: entry["entry_pc"].as_u64().unwrap(),
            parent_bounds: if root {
                [0, 0]
            } else {
                [
                    descriptors[0][0].as_u64().unwrap(),
                    descriptors[0][1].as_u64().unwrap(),
                ]
            },
        });
        assert!(fixture.accepts());
        for (index, value) in descriptor.iter().enumerate() {
            assert_eq!(
                packet::half(&fixture.packets[9 + index], packet::AFTER, 0),
                value.as_u64().unwrap()
            );
        }
    }
}

/// Local descriptor candidate, including deliberately invalid adversarial shapes.
pub(in crate::execution_proofs::ivm_step_air::machine_bus) fn callable_lookup_witness(
    entry: u64,
    frame: u64,
    arguments: u64,
    results: u64,
    selected: bool,
) -> ([F; WIDTH], [[F; packet::WIDTH]; PORTS]) {
    let mut shape = Shape::child();
    shape.generation = 11;
    shape.entry = entry;
    shape.frame = frame;
    shape.argument_words = arguments;
    if arguments == 0 {
        shape.argument = 0;
    }
    shape.result_words = results;
    shape.selected = selected;
    let fixture = Fixture::new(shape);
    (fixture.row, fixture.packets)
}

/// Reuse the descriptor equations with actual prepared-CALL stack/table observations.
pub(in super::super) fn child_for_original_tables(
    selected: (u64, u64, u64, u64),
    stack_top: u64,
    parent_bounds: [u64; 2],
    argument: u64,
    result: u64,
) -> ([F; WIDTH], [[F; packet::WIDTH]; PORTS]) {
    let mut shape = Shape::child();
    shape.generation = 11;
    shape.stack_top = stack_top;
    shape.parent_bounds = parent_bounds;
    shape.sp = parent_bounds[0];
    shape.argument = argument;
    shape.result = result;
    (
        shape.entry,
        shape.frame,
        shape.argument_words,
        shape.result_words,
    ) = selected;
    let fixture = Fixture::new(shape);
    assert!(fixture.accepts());
    (fixture.row, fixture.packets)
}
