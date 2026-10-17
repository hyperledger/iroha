//! Original public scalar expressions, operand order and one atomic destination.

use super::{tests::*, *};
use ivm::{encoding::wide as enc, instruction::wide};

const OPCODES: [u8; 17] = [
    wide::arithmetic::ADD,
    wide::arithmetic::SUB,
    wide::arithmetic::AND,
    wide::arithmetic::OR,
    wide::arithmetic::XOR,
    wide::arithmetic::ADDI,
    wide::arithmetic::ANDI,
    wide::arithmetic::ORI,
    wide::arithmetic::XORI,
    wide::arithmetic::NEG,
    wide::arithmetic::NOT,
    wide::arithmetic::SLT,
    wide::arithmetic::SLTU,
    wide::arithmetic::SEQ,
    wide::arithmetic::SNE,
    wide::arithmetic::MIN,
    wide::arithmetic::MAX,
];

fn instruction(opcode: u8, destination: u8, right: u8, immediate: i8) -> u32 {
    match opcode {
        wide::arithmetic::ADDI
        | wide::arithmetic::ANDI
        | wide::arithmetic::ORI
        | wide::arithmetic::XORI => enc::encode_ri(opcode, destination, 4, immediate),
        wide::arithmetic::NEG | wide::arithmetic::NOT => {
            enc::encode_rr(opcode, destination, 4, 255)
        }
        _ => enc::encode_rr(opcode, destination, 4, right),
    }
}

// Expected expression values are a test oracle only. Neither Source nor witness
// construction receives this function or any expected native result.
fn expected(instruction: u32, left: u64, right: u64) -> u64 {
    let immediate = i64::cast_unsigned(i64::from(wide::imm8(instruction)));
    match wide::opcode(instruction) {
        wide::arithmetic::ADD => left.wrapping_add(right),
        wide::arithmetic::SUB => left.wrapping_sub(right),
        wide::arithmetic::AND => left & right,
        wide::arithmetic::OR => left | right,
        wide::arithmetic::XOR => left ^ right,
        wide::arithmetic::ADDI => left.wrapping_add(immediate),
        wide::arithmetic::ANDI => left & immediate,
        wide::arithmetic::ORI => left | immediate,
        wide::arithmetic::XORI => left ^ immediate,
        wide::arithmetic::NEG => left.wrapping_neg(),
        wide::arithmetic::NOT => !left,
        wide::arithmetic::SLT => u64::from(u64::cast_signed(left) < u64::cast_signed(right)),
        wide::arithmetic::SLTU => u64::from(left < right),
        wide::arithmetic::SEQ => u64::from(left == right),
        wide::arithmetic::SNE => u64::from(left != right),
        wide::arithmetic::MIN => {
            i64::cast_unsigned(u64::cast_signed(left).min(u64::cast_signed(right)))
        }
        wide::arithmetic::MAX => {
            i64::cast_unsigned(u64::cast_signed(left).max(u64::cast_signed(right)))
        }
        _ => unreachable!("closed test opcode list"),
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

#[test]
fn every_public_expression_uses_full_words_original_sources_and_atomic_alias_writes() {
    let inputs = [
        (0, u64::MAX, i8::MIN),
        (u64::MAX, 1, -1),
        (i64::cast_unsigned(i64::MIN), i64::MAX as u64, 0),
        (0xffff_ffff_0000_0001, 0, i8::MAX),
    ];
    for (left, right, immediate) in inputs {
        for (destination, second) in [(6, 5), (4, 5), (5, 5), (0, 5), (4, 4), (6, 0)] {
            let mut body = Vec::new();
            for opcode in OPCODES {
                body.push(enc::encode_literal(wide::memory::LDI64, 4, 0));
                body.push(enc::encode_literal(wide::memory::LDI64, 5, 1));
                body.push(instruction(opcode, destination, second, immediate));
            }
            let (native, budget) = native(artifact_with_literals(&body, 0, &[left, right]));
            let instructions = Instructions::new(&native, &root(&native), &budget).unwrap();
            for window in 0..INSTRUCTION_WINDOWS {
                assert!(check(&instructions, &native, window), "window {window}");
            }
            for (index, opcode) in OPCODES.into_iter().enumerate() {
                let word = instruction(opcode, destination, second, immediate);
                let operands = ivm::execution_packets::public_scalar_operands(word).unwrap();
                let start = instruction_clocks(index * 3 + 2).unwrap()[0] as usize;
                let left_packet = &native.packets()[start + 17];
                let right_packet = &native.packets()[start + 18];
                let output = &native.packets()[start + 19];
                assert_eq!(left_packet.index(), operands.0 as u32);
                assert_eq!(value(left_packet, false), left);
                assert_eq!(left_packet.before(), left_packet.after());
                assert_eq!(left_packet.before_private(), 0);
                assert_eq!(left_packet.after_private(), 0);
                let right_value = match second {
                    0 => 0,
                    4 => left,
                    _ => right,
                };
                assert_eq!(right_packet.enabled(), operands.1.is_some());
                if let Some(register) = operands.1 {
                    assert_eq!(right_packet.index(), register as u32);
                    assert_eq!(value(right_packet, false), right_value);
                    assert_eq!(right_packet.before(), right_packet.after());
                    assert_eq!(right_packet.before_private(), 0);
                    assert_eq!(right_packet.after_private(), 0);
                }
                assert_eq!(output.enabled(), destination != 0);
                if destination != 0 {
                    assert_eq!(output.index(), u32::from(destination));
                    assert_eq!(value(output, true), expected(word, left, right_value));
                    assert_eq!(output.after_private(), 0);
                    if destination == 4 {
                        assert_eq!(value(output, false), left);
                    } else if destination == 5 {
                        assert_eq!(value(output, false), right);
                    }
                }
                for offset in [4, 5, 6, 7, 20, 21, 22, 23, 27, 28, 29, 30, 31] {
                    assert!(!native.packets()[start + offset].enabled());
                }
                let debit = &native.packets()[start + 1];
                assert_eq!(
                    value(debit, false) - value(debit, true),
                    ivm::gas::cost_of(word).unwrap(),
                );
                let cycles = &native.packets()[start + 25];
                assert_eq!(value(cycles, true) - value(cycles, false), 1);
            }
            drop(instructions);
            drop(native);
            assert_eq!(budget.reserved_bytes(), 0);
        }
    }
}

#[test]
fn zero_and_maximum_register_sources_do_not_disappear_when_destination_is_r0() {
    let mut body = vec![enc::encode_literal(wide::memory::LDI64, 255, 0)];
    for opcode in OPCODES {
        let word = match opcode {
            wide::arithmetic::ADDI
            | wide::arithmetic::ANDI
            | wide::arithmetic::ORI
            | wide::arithmetic::XORI => enc::encode_ri(opcode, 0, 0, -1),
            wide::arithmetic::NEG | wide::arithmetic::NOT => enc::encode_rr(opcode, 0, 255, 255),
            _ => enc::encode_rr(opcode, 0, 0, 255),
        };
        body.push(word);
    }
    let (native, budget) = native(artifact_with_literals(&body, 0, &[u64::MAX]));
    let instructions = Instructions::new(&native, &root(&native), &budget).unwrap();
    for window in 0..INSTRUCTION_WINDOWS {
        assert!(check(&instructions, &native, window), "window {window}");
    }
    for (index, word) in body[1..].iter().copied().enumerate() {
        let start = instruction_clocks(index + 1).unwrap()[0] as usize;
        let (left, right) = ivm::execution_packets::public_scalar_operands(word).unwrap();
        assert!(native.packets()[start + 17].enabled());
        assert_eq!(native.packets()[start + 17].index(), left as u32);
        assert_eq!(native.packets()[start + 18].enabled(), right.is_some());
        assert!(!native.packets()[start + 19].enabled());
        assert!(native.packets()[start + 1].enabled());
    }
    drop(instructions);
    drop(native);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn native_scalar_workspace_original_operands_and_exact_debit_reject_mutations() {
    use crate::execution_proofs::ivm_step_air::residues::{Scratch, Stream};
    let body = [
        enc::encode_literal(wide::memory::LDI64, 4, 0),
        enc::encode_literal(wide::memory::LDI64, 5, 1),
        enc::encode_rr(wide::arithmetic::SLT, 4, 4, 5),
        enc::encode_ri(wide::arithmetic::XORI, 4, 4, -128),
    ];
    let (native, budget) = native(artifact_with_literals(
        &body,
        0,
        &[i64::cast_unsigned(i64::MIN), u64::MAX],
    ));
    let instructions = Instructions::new(&native, &root(&native), &budget).unwrap();
    for window in [2, 3] {
        let schedule =
            private_dispatch::Schedule::new(0, instruction_clocks(window).unwrap()).unwrap();
        let packets = original(&native, window);
        let row = &instructions.rows.as_slice()[window].0;
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
        // Original operand/destination, gas and control ports are copied only
        // into test candidates; no NativeInvocation accepts a replacement bank.
        for port in [1, 15, 16, 17, 18, 19] {
            for column in 0..packet::WIDTH {
                let mut fields = core::array::from_fn(|slot| *packets.producer(slot).unwrap());
                fields[port][column] = fields[port][column].add(F::ONE);
                let changed = private_dispatch::OriginalPackets::candidate(fields);
                assert!(
                    !accepts(row, &changed),
                    "window {window}, port {port}, column {column}"
                );
            }
        }
        if window == 2 {
            for column in 0..private_dispatch::WIDTH {
                let mut changed = Witness(*row);
                changed.0[column] = changed.0[column].add(F::ONE);
                assert!(!accepts(&changed.0, &packets), "workspace column {column}");
            }
        }
    }
    drop(instructions);
    drop(native);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn exact_scalar_gas_and_cycle_costs_leave_no_extra_padding_or_uncharged_comparisons() {
    use ivm::{VMError, execution_memory::ExecutionMemoryLease, execution_packets::CaptureError};
    let mut body = vec![
        enc::encode_literal(wide::memory::LDI64, 4, 0),
        enc::encode_literal(wide::memory::LDI64, 5, 1),
    ];
    for opcode in OPCODES {
        body.push(instruction(opcode, 6, 5, -1));
    }
    // With no stack frame, initializer + typed Unit return consume 25 gas.
    // These 19 body instructions cost 23 gas; all 23 native instructions leave
    // 41 padding cycles. Comparison instructions consume 2 gas but one cycle.
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
            assert_eq!(native.instructions(), 23);
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
fn maximum_public_scalar_profile_retains_fixed_funding_and_small_stack_evaluation() {
    let mut body = vec![
        enc::encode_literal(wide::memory::LDI64, 4, 0),
        enc::encode_literal(wide::memory::LDI64, 5, 1),
    ];
    body.extend(
        OPCODES
            .into_iter()
            .cycle()
            .take(58)
            .map(|opcode| instruction(opcode, 6, 5, -128)),
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

#[test]
fn broader_valid_scalar_operations_remain_local_refusals_without_published_packets() {
    use ivm::{IVM, execution_memory::ExecutionMemoryLease, execution_packets::CaptureError};
    for opcode in [
        wide::arithmetic::DIV,
        wide::arithmetic::REM,
        wide::arithmetic::CMOV,
    ] {
        let artifact = artifact_with_literals(
            &[
                enc::encode_literal(wide::memory::LDI64, 4, 0),
                enc::encode_rr(opcode, 6, 4, 4),
            ],
            0,
            &[3],
        );
        let mut ordinary = IVM::new(10_000);
        ordinary.load_prepared(&artifact).unwrap();
        ordinary.select_entrypoint("main").unwrap();
        ordinary.run().unwrap();
        let budget = AllocationBudget::new(128 * 1024 * 1024);
        let mut parent =
            ExecutionMemoryLease::reserve(&budget, NativeInvocation::allocation_plan().unwrap())
                .unwrap();
        assert!(matches!(
            NativeInvocation::run_public_leaf_root(artifact, "main", 10_000, &mut parent, &budget),
            Err(CaptureError::Unsupported),
        ));
        drop(parent);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}
