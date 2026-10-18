//! Full native products and bit counts over the sole original packet owner.

use super::{tests::*, *};
use ivm::{encoding::wide as enc, instruction::wide};

const PRODUCTS: [u8; 4] = [
    wide::arithmetic::MUL,
    wide::arithmetic::MULH,
    wide::arithmetic::MULHU,
    wide::arithmetic::MULHSU,
];
const COUNTS: [u8; 3] = [
    wide::arithmetic::POPCNT,
    wide::arithmetic::CLZ,
    wide::arithmetic::CTZ,
];

// Independent test oracle: shared product limbs, corrections and count-prefix
// witnesses are deliberately not consulted. Nothing passes this expected value
// into Source, Instructions or the native interpreter.
fn expected(opcode: u8, left: u64, right: u64) -> u64 {
    match opcode {
        wide::arithmetic::MUL => (u128::from(left) * u128::from(right)) as u64,
        wide::arithmetic::MULH => {
            ((i128::from(u64::cast_signed(left)) * i128::from(u64::cast_signed(right))) >> 64)
                as u64
        }
        wide::arithmetic::MULHU => ((u128::from(left) * u128::from(right)) >> 64) as u64,
        wide::arithmetic::MULHSU => {
            ((i128::from(u64::cast_signed(left)) * i128::from(right)) >> 64) as u64
        }
        wide::arithmetic::POPCNT => u64::from(left.count_ones()),
        wide::arithmetic::CLZ => u64::from(left.leading_zeros()),
        wide::arithmetic::CTZ => u64::from(left.trailing_zeros()),
        _ => unreachable!("closed multiply/count test opcode list"),
    }
}

fn value(packet: &ivm::execution_packets::NativePacket, after: bool) -> u64 {
    let bytes = if after {
        packet.after()
    } else {
        packet.before()
    };
    u64::from_le_bytes(bytes[..8].try_into().unwrap())
}

fn check_expression(native: &NativeInvocation, window: usize, word: u32, left: u64, right: u64) {
    let start = instruction_clocks(window).unwrap()[0] as usize;
    let first = &native.packets()[start + 17];
    let second = &native.packets()[start + 18];
    let output = &native.packets()[start + 19];
    assert!(first.enabled());
    assert_eq!(first.index(), wide::rs1(word) as u32);
    assert_eq!(value(first, false), left);
    assert_eq!(first.before(), first.after());
    assert_eq!(first.before_private(), 0);
    assert_eq!(first.after_private(), 0);
    let product = PRODUCTS.contains(&wide::opcode(word));
    assert_eq!(second.enabled(), product);
    if product {
        assert_eq!(second.index(), wide::rs2(word) as u32);
        assert_eq!(value(second, false), right);
        assert_eq!(second.before(), second.after());
        assert_eq!(second.before_private(), 0);
        assert_eq!(second.after_private(), 0);
    } else {
        assert_eq!(Fields::native(second).0, [F::ZERO; packet::WIDTH]);
    }
    let destination = wide::rd(word);
    assert_eq!(output.enabled(), destination != 0);
    if destination != 0 {
        assert_eq!(output.index(), destination as u32);
        assert_eq!(
            value(output, true),
            expected(wide::opcode(word), left, right)
        );
        assert_eq!(output.after_private(), 0);
        if destination == wide::rs1(word) {
            assert_eq!(value(output, false), left);
        } else if product && destination == wide::rs2(word) {
            assert_eq!(value(output, false), right);
        }
    } else {
        assert_eq!(Fields::native(output).0, [F::ZERO; packet::WIDTH]);
    }
    for offset in [4, 5, 6, 7, 20, 21, 22, 23, 27, 28, 29, 30, 31] {
        assert_eq!(
            Fields::native(&native.packets()[start + offset]).0,
            [F::ZERO; packet::WIDTH]
        );
    }
    let gas = &native.packets()[start + 1];
    assert_eq!(
        value(gas, false) - value(gas, true),
        if product { 3 } else { 6 }
    );
    let cycles = &native.packets()[start + 25];
    assert_eq!(value(cycles, true) - value(cycles, false), 1);
}

#[test]
fn native_products_match_independent_full_width_signed_and_unsigned_arithmetic() {
    let pairs = [
        (0, 0),
        (1, u64::MAX),
        (u64::MAX, u64::MAX),
        (i64::cast_unsigned(i64::MIN), i64::cast_unsigned(i64::MIN)),
        (i64::MAX as u64, i64::MAX as u64),
        (i64::cast_unsigned(i64::MIN), u64::MAX),
        (u64::MAX, i64::cast_unsigned(i64::MIN)),
        (0xffff_ffff_0000_0001, 0x8000_ffff_0000_0001),
        (0x5555_5555_5555_5555, 0xaaaa_aaaa_aaaa_aaaa),
    ];
    for (left, right) in pairs {
        for (destination, first, second) in [
            (6, 4, 5),
            (4, 4, 5),
            (5, 4, 5),
            (0, 4, 5),
            (4, 4, 4),
            (6, 0, 5),
            (0, 255, 0),
        ] {
            let mut body = Vec::new();
            for opcode in PRODUCTS {
                body.push(enc::encode_literal(wide::memory::LDI64, first.max(4), 0));
                body.push(enc::encode_literal(wide::memory::LDI64, 5, 1));
                body.push(enc::encode_rr(opcode, destination, first, second));
            }
            let (native, budget) = native(artifact_with_literals(&body, 0, &[left, right]));
            let instructions = Instructions::new(&native, &root(&native), &budget).unwrap();
            for window in 0..INSTRUCTION_WINDOWS {
                assert!(check(&instructions, &native, window), "window {window}");
            }
            for index in 0..PRODUCTS.len() {
                check_expression(
                    &native,
                    index * 3 + 2,
                    body[index * 3 + 2],
                    if first == 0 { 0 } else { left },
                    match second {
                        0 => 0,
                        4 => left,
                        _ => right,
                    },
                );
            }
            drop(instructions);
            drop(native);
            assert_eq!(budget.reserved_bytes(), 0);
        }
    }
    assert_ne!(
        expected(
            wide::arithmetic::MULHSU,
            i64::cast_unsigned(i64::MIN),
            u64::MAX
        ),
        expected(
            wide::arithmetic::MULHSU,
            u64::MAX,
            i64::cast_unsigned(i64::MIN)
        ),
        "the signed operand is the original first source",
    );
}

#[test]
fn native_counts_cover_every_bit_and_zero_with_full_sixty_four_results() {
    let inputs: Vec<u64> = [0, u64::MAX, 0xffff_ffff_0000_0001]
        .into_iter()
        .chain((0..64).flat_map(|bit| [1_u64 << bit, !(1_u64 << bit)]))
        .collect();
    for inputs in inputs.chunks(14) {
        let mut body = Vec::new();
        for (index, _) in inputs.iter().enumerate() {
            body.push(enc::encode_literal(wide::memory::LDI64, 4, index as u16));
            body.extend(COUNTS.map(|opcode| enc::encode_rr(opcode, 6, 4, 255)));
        }
        let (native, budget) = native(artifact_with_literals(&body, 0, inputs));
        let instructions = Instructions::new(&native, &root(&native), &budget).unwrap();
        for window in 0..INSTRUCTION_WINDOWS {
            assert!(check(&instructions, &native, window), "window {window}");
        }
        for (index, input) in inputs.iter().copied().enumerate() {
            for (offset, opcode) in COUNTS.into_iter().enumerate() {
                check_expression(
                    &native,
                    index * 4 + offset + 1,
                    enc::encode_rr(opcode, 6, 4, 255),
                    input,
                    0,
                );
            }
        }
        drop(instructions);
        drop(native);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn ignored_count_rs2_bytes_preserve_actual_packet_history_and_atomic_aliases() {
    for opcode in COUNTS {
        for (destination, first) in [(6, 4), (4, 4), (0, 4), (6, 0), (0, 255)] {
            let left = if first == 0 { 0 } else { 0x8000_1234_0000_0000 };
            let make = |unused| {
                let words = [
                    enc::encode_literal(wide::memory::LDI64, first.max(4), 0),
                    enc::encode_rr(opcode, destination, first, unused),
                ];
                native(artifact_with_literals(&words, 0, &[left]))
            };
            let (reference, reference_budget) = make(0);
            let reference_instructions =
                Instructions::new(&reference, &root(&reference), &reference_budget).unwrap();
            assert!(check(&reference_instructions, &reference, 1));
            for unused in [4, 5, 127, 128, 255] {
                let (candidate, budget) = make(unused);
                let instructions =
                    Instructions::new(&candidate, &root(&candidate), &budget).unwrap();
                for window in 0..INSTRUCTION_WINDOWS {
                    assert!(check(&instructions, &candidate, window), "window {window}");
                }
                check_expression(
                    &candidate,
                    1,
                    enc::encode_rr(opcode, destination, first, unused),
                    left,
                    0,
                );
                // Same ordinal and code prefix mean identical actual clocks.
                // Compare original cells directly; no normalization/reclocking
                // or replacement packet owner is constructed.
                for clock in instruction_clocks(1).unwrap() {
                    assert_eq!(
                        Fields::native(&reference.packets()[clock as usize]).0,
                        Fields::native(&candidate.packets()[clock as usize]).0
                    );
                }
                assert_eq!(
                    reference_instructions.rows.as_slice()[1].0,
                    instructions.rows.as_slice()[1].0
                );
                drop(instructions);
                drop(candidate);
                assert_eq!(budget.reserved_bytes(), 0);
            }
            drop(reference_instructions);
            drop(reference);
            assert_eq!(reference_budget.reserved_bytes(), 0);
        }
    }
}

#[test]
fn every_product_count_workspace_and_original_operand_cell_is_constrained() {
    use crate::execution_proofs::ivm_step_air::residues::{Scratch, Stream};
    for opcode in PRODUCTS.into_iter().chain(COUNTS) {
        let word = enc::encode_rr(opcode, 4, 4, 5);
        let body = [
            enc::encode_literal(wide::memory::LDI64, 4, 0),
            enc::encode_literal(wide::memory::LDI64, 5, 1),
            word,
        ];
        let (native, budget) = native(artifact_with_literals(
            &body,
            0,
            &[0xffff_ffff_ffff_fffd, 0x8000_0000_0000_0001],
        ));
        let instructions = Instructions::new(&native, &root(&native), &budget).unwrap();
        let schedule = private_dispatch::Schedule::new(0, instruction_clocks(2).unwrap()).unwrap();
        let packets = original(&native, 2);
        let row = &instructions.rows.as_slice()[2].0;
        let accepts = |row: &[F; private_dispatch::WIDTH],
                       packets: &private_dispatch::OriginalPackets| {
            let mut scratch = Scratch::new();
            let mut consume = |values: &[F]| {
                values
                    .iter()
                    .all(|value| *value == F::ZERO)
                    .then_some(())
                    .ok_or(())
            };
            let mut out = Stream::new(&mut scratch, &mut consume);
            private_dispatch::native_witness::append_subset_residues(
                &mut out,
                &instructions.program,
                row,
                packets,
            );
            private_dispatch::append_residues(
                &mut out,
                &instructions.program,
                schedule,
                row,
                packets,
            );
            out.finish().is_ok()
        };
        assert!(accepts(row, &packets));
        // rd=rs1 binds its original before-word locally as well as through
        // full history, so no unconstrained prior-write field is counted here.
        for port in [1, 15, 16, 17, 18, 19] {
            for column in 0..packet::WIDTH {
                let mut fields = core::array::from_fn(|slot| *packets.producer(slot).unwrap());
                fields[port][column] = fields[port][column].add(F::ONE);
                assert!(
                    !accepts(row, &private_dispatch::OriginalPackets::candidate(fields)),
                    "opcode {opcode:#x}, port {port}, column {column}"
                );
            }
        }
        // Includes product radix4 digits, bounded carries, both signed-high
        // corrections, every prefix and all otherwise inactive canonical banks.
        for column in 0..private_dispatch::WIDTH {
            let mut changed = Witness(*row);
            changed.0[column] = changed.0[column].add(F::ONE);
            assert!(
                !accepts(&changed.0, &packets),
                "opcode {opcode:#x}, workspace {column}"
            );
        }
        for alternative in PRODUCTS.into_iter().chain(COUNTS) {
            let correct = expected(opcode, 0xffff_ffff_ffff_fffd, 0x8000_0000_0000_0001);
            let wrong = expected(alternative, 0xffff_ffff_ffff_fffd, 0x8000_0000_0000_0001);
            if wrong == correct {
                continue;
            }
            let mut fields = core::array::from_fn(|slot| *packets.producer(slot).unwrap());
            for limb in 0..4 {
                fields[19][packet::AFTER + limb] = F((wrong >> (16 * limb)) & 0xffff);
            }
            assert!(
                !accepts(row, &private_dispatch::OriginalPackets::candidate(fields)),
                "opcode {opcode:#x}, wrong output from {alternative:#x}"
            );
        }
        drop(instructions);
        drop(native);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn three_and_six_gas_operations_still_retire_exactly_one_cycle() {
    use ivm::{VMError, execution_memory::ExecutionMemoryLease, execution_packets::CaptureError};
    let mut body = vec![
        enc::encode_literal(wide::memory::LDI64, 4, 0),
        enc::encode_literal(wide::memory::LDI64, 5, 1),
    ];
    body.extend(
        PRODUCTS
            .into_iter()
            .chain(COUNTS)
            .map(|opcode| enc::encode_rr(opcode, 6, 4, 5)),
    );
    // Nine body instructions cost32 gas. Initializer/Unit cost25, and the
    // thirteen actual instructions leave51 padding cycles:108 gas exactly.
    for gas in [107, 108] {
        let budget = AllocationBudget::new(128 * 1024 * 1024);
        let mut parent =
            ExecutionMemoryLease::reserve(&budget, NativeInvocation::allocation_plan().unwrap())
                .unwrap();
        let result = NativeInvocation::run_public_leaf_root(
            artifact_with_literals(&body, 0, &[i64::cast_unsigned(i64::MIN), u64::MAX]),
            "main",
            gas,
            &mut parent,
            &budget,
        );
        if gas == 107 {
            assert!(matches!(
                result,
                Err(CaptureError::Execution(VMError::OutOfGas))
            ));
        } else {
            let native = result.unwrap();
            assert_eq!(native.instructions(), 13);
            assert_eq!(native.cycles(), 64);
            assert_eq!(native.remaining_gas(), 0);
            let exact = AllocationBudget::new(Instructions::BYTES);
            let instructions = Instructions::new(&native, &root(&native), &exact).unwrap();
            for window in 0..INSTRUCTION_WINDOWS {
                assert!(check(&instructions, &native, window));
            }
            drop(instructions);
            assert_eq!(exact.reserved_bytes(), 0);
            let short = AllocationBudget::new(Instructions::BYTES - 1);
            assert!(matches!(
                Instructions::new(&native, &root(&native), &short),
                Err(Error::Allocation(_))
            ));
            assert_eq!(short.reserved_bytes(), 0);
            drop(native);
        }
        drop(parent);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn maximum_product_count_profile_retains_fixed_workspace_on_small_stack() {
    let mut body = vec![
        enc::encode_literal(wide::memory::LDI64, 4, 0),
        enc::encode_literal(wide::memory::LDI64, 5, 1),
    ];
    body.extend(
        PRODUCTS
            .into_iter()
            .chain(COUNTS)
            .cycle()
            .take(58)
            .map(|opcode| enc::encode_rr(opcode, 6, 4, 5)),
    );
    let (native, budget) = native(artifact_with_literals(
        &body,
        0,
        &[i64::cast_unsigned(i64::MIN), u64::MAX],
    ));
    assert_eq!(native.instructions(), 64);
    std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(move || {
            let held = budget.reserved_bytes();
            let instructions = Instructions::new(&native, &root(&native), &budget).unwrap();
            assert_eq!(budget.reserved_bytes(), held + Instructions::BYTES);
            for window in 0..INSTRUCTION_WINDOWS {
                assert!(check(&instructions, &native, window), "window {window}");
            }
            drop(instructions);
            assert_eq!(budget.reserved_bytes(), held);
            drop(native);
            assert_eq!(budget.reserved_bytes(), 0);
        })
        .unwrap()
        .join()
        .unwrap();
}
