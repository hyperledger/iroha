//! Native shifts and rotates over original full-width sources and atomic writes.

use super::{tests::*, *};
use ivm::{encoding::wide as enc, instruction::wide};

const REGISTER: [u8; 5] = [
    wide::arithmetic::SLL,
    wide::arithmetic::SRL,
    wide::arithmetic::SRA,
    wide::arithmetic::ROTL,
    wide::arithmetic::ROTR,
];
const IMMEDIATE: [u8; 2] = [wide::arithmetic::ROTL_IMM, wide::arithmetic::ROTR_IMM];

// This expression oracle is used only after native execution. No Source,
// instruction workspace or original packet constructor accepts its output.
fn expected(opcode: u8, value: u64, amount: u64) -> u64 {
    let amount = (amount & 63) as u32;
    match opcode {
        wide::arithmetic::SLL => value << amount,
        wide::arithmetic::SRL => value >> amount,
        wide::arithmetic::SRA => i64::cast_unsigned(u64::cast_signed(value) >> amount),
        wide::arithmetic::ROTL | wide::arithmetic::ROTL_IMM => value.rotate_left(amount),
        wide::arithmetic::ROTR | wide::arithmetic::ROTR_IMM => value.rotate_right(amount),
        _ => unreachable!("closed shift test opcode list"),
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

fn instruction(opcode: u8, destination: u8, left: u8, amount: u8) -> u32 {
    if IMMEDIATE.contains(&opcode) {
        enc::encode_ri(opcode, destination, left, u8::cast_signed(amount))
    } else {
        enc::encode_rr(opcode, destination, left, amount)
    }
}

fn check_expression(native: &NativeInvocation, window: usize, word: u32, left: u64, amount: u64) {
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
    assert_eq!(second.enabled(), REGISTER.contains(&wide::opcode(word)));
    if second.enabled() {
        assert_eq!(second.index(), wide::rs2(word) as u32);
        assert_eq!(
            value(second, false),
            amount,
            "full original count, not low six bits"
        );
        assert_eq!(second.before(), second.after());
        assert_eq!(second.before_private(), 0);
        assert_eq!(second.after_private(), 0);
    } else {
        assert_eq!(Fields::native(second).0, [F::ZERO; packet::WIDTH]);
        assert_eq!(amount, u64::from(i8::cast_unsigned(wide::imm8(word))));
    }
    let destination = wide::rd(word);
    assert_eq!(output.enabled(), destination != 0);
    if destination != 0 {
        assert_eq!(output.index(), destination as u32);
        assert_eq!(
            value(output, true),
            expected(wide::opcode(word), left, amount)
        );
        assert_eq!(output.after_private(), 0);
        if destination == wide::rs1(word) {
            assert_eq!(value(output, false), left);
        } else if second.enabled() && destination == wide::rs2(word) {
            assert_eq!(value(output, false), amount);
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
        ivm::gas::cost_of(word).unwrap()
    );
    let cycles = &native.packets()[start + 25];
    assert_eq!(value(cycles, true) - value(cycles, false), 1);
}

#[test]
fn every_register_count_keeps_full_original_bits_and_signed_shift_semantics() {
    let amounts: Vec<u64> = (0..64)
        .chain([64, 65, 127, 128, 1 << 63, u64::MAX])
        .collect();
    for left in [
        0,
        i64::cast_unsigned(i64::MIN),
        i64::MAX as u64,
        0xfedc_ba98_7654_3210,
    ] {
        for amounts in amounts.chunks(9) {
            let mut literals = vec![left];
            literals.extend_from_slice(amounts);
            let mut body = vec![enc::encode_literal(wide::memory::LDI64, 4, 0)];
            for (index, _) in amounts.iter().enumerate() {
                body.push(enc::encode_literal(
                    wide::memory::LDI64,
                    5,
                    (index + 1) as u16,
                ));
                body.extend(REGISTER.map(|opcode| instruction(opcode, 6, 4, 5)));
            }
            let (native, budget) = native(artifact_with_literals(&body, 0, &literals));
            let instructions = Instructions::new(&native, &root(&native), &budget).unwrap();
            for window in 0..INSTRUCTION_WINDOWS {
                assert!(check(&instructions, &native, window), "window {window}");
            }
            for (index, amount) in amounts.iter().copied().enumerate() {
                for (offset, opcode) in REGISTER.into_iter().enumerate() {
                    check_expression(
                        &native,
                        2 + index * 6 + offset,
                        instruction(opcode, 6, 4, 5),
                        left,
                        amount,
                    );
                }
            }
            drop(instructions);
            drop(native);
            assert_eq!(budget.reserved_bytes(), 0);
        }
    }
}

#[test]
fn every_rotate_immediate_is_unsigned_without_a_fabricated_count_read() {
    let amounts: Vec<u8> = (0..=u8::MAX).collect();
    for left in [i64::cast_unsigned(i64::MIN), 0xfedc_ba98_7654_3210] {
        for amounts in amounts.chunks(29) {
            let mut body = vec![enc::encode_literal(wide::memory::LDI64, 4, 0)];
            for amount in amounts {
                body.extend(IMMEDIATE.map(|opcode| instruction(opcode, 6, 4, *amount)));
            }
            let (native, budget) = native(artifact_with_literals(&body, 0, &[left]));
            let instructions = Instructions::new(&native, &root(&native), &budget).unwrap();
            for window in 0..INSTRUCTION_WINDOWS {
                assert!(check(&instructions, &native, window), "window {window}");
            }
            for (index, amount) in amounts.iter().copied().enumerate() {
                for (offset, opcode) in IMMEDIATE.into_iter().enumerate() {
                    check_expression(
                        &native,
                        1 + index * 2 + offset,
                        instruction(opcode, 6, 4, amount),
                        left,
                        u64::from(amount),
                    );
                }
            }
            drop(instructions);
            drop(native);
            assert_eq!(budget.reserved_bytes(), 0);
        }
    }
}

#[test]
fn shifts_preserve_read_order_atomic_aliases_and_r0_reads_without_writes() {
    for left in [i64::cast_unsigned(i64::MIN), u64::MAX] {
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
            for opcode in REGISTER.into_iter().chain(IMMEDIATE) {
                body.push(enc::encode_literal(wide::memory::LDI64, first.max(4), 0));
                body.push(enc::encode_literal(wide::memory::LDI64, 5, 1));
                body.push(instruction(
                    opcode,
                    destination,
                    first,
                    if IMMEDIATE.contains(&opcode) {
                        255
                    } else {
                        second
                    },
                ));
            }
            let (native, budget) = native(artifact_with_literals(&body, 0, &[left, 65]));
            let instructions = Instructions::new(&native, &root(&native), &budget).unwrap();
            for window in 0..INSTRUCTION_WINDOWS {
                assert!(check(&instructions, &native, window), "window {window}");
            }
            for (index, opcode) in REGISTER.into_iter().chain(IMMEDIATE).enumerate() {
                let word = body[index * 3 + 2];
                let amount = if IMMEDIATE.contains(&opcode) {
                    255
                } else {
                    match second {
                        0 => 0,
                        4 => left,
                        _ => 65,
                    }
                };
                check_expression(
                    &native,
                    index * 3 + 2,
                    word,
                    if first == 0 { 0 } else { left },
                    amount,
                );
            }
            drop(instructions);
            drop(native);
            assert_eq!(budget.reserved_bytes(), 0);
        }
    }
}

#[test]
fn all_shift_original_ports_and_barrel_stage_cells_reject_mutations() {
    use crate::execution_proofs::ivm_step_air::{
        residues::{Scratch, Stream},
        shift,
    };
    for opcode in REGISTER.into_iter().chain(IMMEDIATE) {
        let word = instruction(
            opcode,
            4,
            4,
            if IMMEDIATE.contains(&opcode) { 255 } else { 5 },
        );
        let body = [
            enc::encode_literal(wide::memory::LDI64, 4, 0),
            enc::encode_literal(wide::memory::LDI64, 5, 1),
            word,
        ];
        let (native, budget) = native(artifact_with_literals(
            &body,
            0,
            &[0xfedc_ba98_7654_3210, u64::MAX],
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
        for port in [1, 15, 16, 17, 18, 19] {
            for column in 0..packet::WIDTH {
                let mut fields = core::array::from_fn(|slot| *packets.producer(slot).unwrap());
                fields[port][column] = fields[port][column].add(F::ONE);
                let changed = private_dispatch::OriginalPackets::candidate(fields);
                assert!(
                    !accepts(row, &changed),
                    "opcode {opcode:#x}, port {port}, column {column}"
                );
            }
        }
        let start = if opcode == wide::arithmetic::SRA {
            0
        } else {
            private_dispatch::WIDTH - shift::BANK_WIDTH
        };
        for column in start..private_dispatch::WIDTH {
            let mut changed = Witness(*row);
            changed.0[column] = changed.0[column].add(F::ONE);
            assert!(
                !accepts(&changed.0, &packets),
                "opcode {opcode:#x}, workspace {column}"
            );
        }
        drop(instructions);
        drop(native);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn exact_shift_gas_and_cycles_preserve_the_fixed_funding_boundary() {
    use ivm::{VMError, execution_memory::ExecutionMemoryLease, execution_packets::CaptureError};
    let mut body = vec![
        enc::encode_literal(wide::memory::LDI64, 4, 0),
        enc::encode_literal(wide::memory::LDI64, 5, 1),
    ];
    body.extend(
        REGISTER
            .into_iter()
            .chain(IMMEDIATE)
            .map(|opcode| instruction(opcode, 6, 4, 5)),
    );
    // Nine body instructions cost13 gas. Initializer and Unit return cost25;
    // thirteen actual instructions leave51 one-gas padding cycles:89 total.
    for gas in [88, 89] {
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
        if gas == 88 {
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
fn maximum_shift_profile_keeps_all_windows_and_small_stack_evaluation() {
    let mut body = vec![
        enc::encode_literal(wide::memory::LDI64, 4, 0),
        enc::encode_literal(wide::memory::LDI64, 5, 1),
    ];
    body.extend(
        REGISTER
            .into_iter()
            .chain(IMMEDIATE)
            .cycle()
            .take(58)
            .map(|opcode| instruction(opcode, 6, 4, 5)),
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
