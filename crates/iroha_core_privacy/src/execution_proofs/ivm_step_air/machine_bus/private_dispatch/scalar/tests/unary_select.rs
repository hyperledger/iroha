//! Native total unary/selection operations and coherent private-column forgeries.

use super::*;

const UNARY_OPS: [u8; 2] = [wide::arithmetic::NOT, wide::arithmetic::NEG];
const SELECTION_OPS: [u8; 2] = [wide::arithmetic::MIN, wide::arithmetic::MAX];

fn expected(opcode: u8, left: u64, right: u64) -> u64 {
    match opcode {
        wide::arithmetic::NOT => !left,
        wide::arithmetic::NEG => left.wrapping_neg(),
        wide::arithmetic::MIN => {
            i64::cast_unsigned(u64::cast_signed(left).min(u64::cast_signed(right)))
        }
        wide::arithmetic::MAX => {
            i64::cast_unsigned(u64::cast_signed(left).max(u64::cast_signed(right)))
        }
        _ => panic!("total unary/selection fixture opcode"),
    }
}

fn checked_native(instruction: u32, inputs: &[(usize, u64, bool)]) -> (Program, ScalarFixture) {
    let (program, fixture) = native(instruction, inputs);
    let packets = &fixture.0.packets.fields;
    let left = packet::half(&packets[SCALAR_LEFT], BEFORE, 0);
    let right = packet::half(&packets[SCALAR_RIGHT], BEFORE, 0);
    assert_eq!(ivm::gas::cost_of(instruction), Some(1));
    assert_eq!(
        packet::half(&packets[SCALAR_DESTINATION], AFTER, 0),
        if wide::rd(instruction) == 0 {
            0
        } else {
            expected(wide::opcode(instruction), left, right)
        }
    );
    assert_eq!(
        packets[SCALAR_DESTINATION][AFTER_TAG],
        if wide::rd(instruction) == 0 {
            F::ZERO
        } else {
            packets[SCALAR_LEFT][BEFORE_TAG]
        }
    );
    assert_eq!(
        packet::half(&packets[GAS_DEBIT], BEFORE, 0) - packet::half(&packets[GAS_DEBIT], AFTER, 0),
        1
    );
    assert_eq!(
        packet::half(&packets[PC_WRITE], AFTER, 0),
        packet::half(&packets[PC_READ], BEFORE, 0) + 4
    );
    assert_eq!(
        packet::half(&packets[CYCLE_WRITE], AFTER, 0),
        packet::half(&packets[CYCLE_WRITE], BEFORE, 0) + 1
    );
    assert_eq!(packets[RUNNING_WRITE][AFTER], F::ONE);
    if UNARY_OPS.contains(&wide::opcode(instruction)) {
        assert!(packets[SCALAR_RIGHT].iter().all(|cell| *cell == F::ZERO));
        let sources = word::Sources::new(&fixture.0.row[SCALAR..SCALAR + ALU]);
        let operands = if wide::opcode(instruction) == wide::arithmetic::NEG {
            [0, left]
        } else {
            [left, u64::MAX]
        };
        for (operand, value) in operands.into_iter().enumerate() {
            for limb in 0..4 {
                assert_eq!(sources.limb(operand, limb), constant_limb(value, limb));
            }
        }
    }
    (program, fixture)
}

/// Replace every arithmetic workspace consistently, retaining original packets.
fn replace_sources(fixture: &mut ScalarFixture, instruction: u32, left: u64, right: u64) {
    fixture.0.row[SCALAR..SCALAR + ALU].copy_from_slice(&word::witness(left, right));
    fill_product(&mut fixture.0, left, right);
    fixture.0.row[SCALAR + ALU..SCALAR + COMPARE].copy_from_slice(&alu::witness(
        if UNARY_OPS.contains(&wide::opcode(instruction)) {
            alu_opcode(instruction)
        } else {
            wide::arithmetic::ADD
        },
        left,
        right,
    ));
    fixture.0.row[SCALAR + COMPARE..SCALAR + PRODUCT_DIGITS].copy_from_slice(
        &branch::bank_witness(
            if SELECTION_OPS.contains(&wide::opcode(instruction)) {
                wide::control::BLT
            } else {
                0
            },
            left,
            right,
        ),
    );
    fixture.0.row[SCALAR + SHIFT..super::super::super::WIDTH]
        .copy_from_slice(&shift::bank_witness(wide::arithmetic::SLL, left, right));
}

fn replace_destination(fixture: &mut ScalarFixture, value: u64) {
    for limb in 0..4 {
        fixture.0.packets.fields[SCALAR_DESTINATION][AFTER + limb] = constant_limb(value, limb);
    }
}

#[test]
fn native_unary_full_words_tags_zero_and_read_before_write_aliases_match() {
    let values = [
        0,
        1,
        u64::MAX,
        i64::cast_unsigned(i64::MIN),
        i64::MAX as u64,
        0xffff_ffff_0000_0001,
    ];
    for opcode in UNARY_OPS {
        for tag in [false, true] {
            for value in values {
                for rd in [0, 2, 4] {
                    checked_native(
                        enc::encode_rr(opcode, rd, 2, 255),
                        &[(2, value, tag), (4, 19, !tag), (255, 17, !tag)],
                    );
                }
            }
        }
        for rd in [0, 4] {
            checked_native(
                enc::encode_rr(opcode, rd, 0, 255),
                &[(4, 19, true), (255, u64::MAX, true)],
            );
        }
    }
    // ABS has separate public-tag and overflow checks; it must not enter the
    // total-unary destination path even though its shared ALU performs SUB.
    let absolute = enc::encode_rr(wide::arithmetic::ABS, 4, 2, 255);
    assert!(is_supported(absolute));
    assert!(!is_alu(absolute));
}

#[test]
fn native_unary_ignores_every_rs2_byte_and_its_value_and_tag() {
    for opcode in UNARY_OPS {
        for raw in 0..=u8::MAX {
            checked_native(
                enc::encode_rr(opcode, 4, 2, raw),
                &[(2, 0x8000_1234_5678_9abc, true), (255, 17, false)],
            );
        }
        let instruction = enc::encode_rr(opcode, 4, 2, 255);
        let (program, first) = checked_native(instruction, &[(2, 17, true), (255, 0, false)]);
        let (_, second) = checked_native(instruction, &[(2, 17, true), (255, u64::MAX, true)]);
        assert_eq!(first.0.row, second.0.row);
        assert_eq!(first.0.packets.fields, second.0.packets.fields);
        let mut extra = first.clone();
        extra.0.packets.fields[SCALAR_RIGHT] = event(
            Space::Register,
            0,
            255,
            0,
            0,
            false,
            extra.0.schedule.clocks[SCALAR_RIGHT],
            false,
            false,
        );
        assert!(!extra.accepts(&program));
        let mut wrong_tag = first.clone();
        wrong_tag.0.packets.fields[SCALAR_DESTINATION][AFTER_TAG] = F::ZERO;
        assert!(!wrong_tag.accepts(&program));
    }
}

#[test]
fn native_signed_min_max_full_words_ties_tags_aliases_and_zero_match() {
    let pairs = [
        (0, 0),
        (0, 1),
        (1, 0),
        (u64::MAX, 1),
        (1, u64::MAX),
        (i64::cast_unsigned(i64::MIN), i64::MAX as u64),
        (i64::MAX as u64, i64::cast_unsigned(i64::MIN)),
        (i64::cast_unsigned(i64::MIN), i64::cast_unsigned(i64::MIN)),
        (u64::MAX, u64::MAX),
        (0xffff_ffff_0000_0001, 0),
        (0, 0xffff_ffff_0000_0001),
    ];
    for opcode in SELECTION_OPS {
        for tag in [false, true] {
            for (left, right) in pairs {
                checked_native(
                    enc::encode_rr(opcode, 4, 2, 3),
                    &[(2, left, tag), (3, right, tag)],
                );
            }
            for (rd, left, right) in [(0, 2, 3), (2, 2, 3), (3, 2, 3), (4, 2, 2), (2, 2, 2)] {
                checked_native(
                    enc::encode_rr(opcode, rd, left, right),
                    &[(2, u64::MAX, tag), (3, 1, tag)],
                );
            }
        }
        for (rd, left, right) in [(4, 0, 0), (0, 0, 0), (4, 0, 3), (4, 2, 0)] {
            checked_native(
                enc::encode_rr(opcode, rd, left, right),
                &[(2, u64::MAX, false), (3, 1, false), (4, 19, true)],
            );
        }
    }
}

#[test]
fn native_selection_mixed_tag_orders_trap_after_one_gas_without_commit() {
    for opcode in SELECTION_OPS {
        for rd in [0, 4] {
            for left_tag in [false, true] {
                let instruction = enc::encode_rr(opcode, rd, 2, 3);
                let (_, recorder, outcome) = shifts::capture(
                    &[instruction],
                    &[(2, 17, left_tag), (3, 23, !left_tag)],
                    100,
                    32,
                );
                assert!(matches!(outcome, Err(ivm::VMError::PrivacyViolation)));
                assert_eq!(recorder.records().len(), 1);
                let record = &recorder.records()[0];
                assert_eq!(record.instruction, Some(instruction));
                assert_eq!(record.opcode_gas, Some(1));
                assert!(matches!(record.outcome, DiagnosticStepOutcome::Trapped(_)));
                assert_eq!(record.before.registers, record.after.registers);
                assert_eq!(record.before.tags, record.after.tags);
                assert_eq!(record.before.pc, record.after.pc);
                assert_eq!(record.before.cycles, record.after.cycles);
                assert_eq!(record.after.gas_remaining + 1, record.before.gas_remaining);
                assert!(!record.after.halted);
                let (program, mut forged) =
                    checked_native(instruction, &[(2, 17, false), (3, 23, false)]);
                for (slot, tag) in [(SCALAR_LEFT, left_tag), (SCALAR_RIGHT, !left_tag)] {
                    forged.0.packets.fields[slot][BEFORE_TAG] = F(u64::from(tag));
                    forged.0.packets.fields[slot][AFTER_TAG] = F(u64::from(tag));
                }
                if rd != 0 {
                    forged.0.packets.fields[SCALAR_DESTINATION][AFTER_TAG] = F(u64::from(left_tag));
                }
                assert!(!forged.accepts(&program));
            }
        }
    }
}

#[test]
fn unary_routing_and_signed_selection_reject_coherent_arithmetic_forgeries() {
    for opcode in UNARY_OPS {
        let instruction = enc::encode_rr(opcode, 4, 2, 255);
        let (program, fixture) = checked_native(instruction, &[(2, 17, true)]);
        let mut wrong = fixture.clone();
        replace_sources(&mut wrong, instruction, 17, 0);
        // Both alternative ALUs return 17: SUB(17, 0) or XOR(17, 0).
        replace_destination(&mut wrong, 17);
        assert!(!wrong.accepts(&program));
        let replacement = if opcode == wide::arithmetic::NEG {
            wide::arithmetic::NOT
        } else {
            wide::arithmetic::NEG
        };
        let changed = Program::new(contract(
            &[enc::encode_rr(replacement, 4, 2, 255)],
            1_000,
            ivm::ivm_mode::ZK,
        ))
        .unwrap();
        assert!(!fixture.accepts(&changed));
    }
    for opcode in SELECTION_OPS {
        let instruction = enc::encode_rr(opcode, 4, 2, 3);
        let (program, fixture) = checked_native(instruction, &[(2, u64::MAX, true), (3, 1, true)]);
        let wrong_result = if opcode == wide::arithmetic::MIN {
            1
        } else {
            u64::MAX
        };
        let mut flipped = fixture.clone();
        flipped.0.row[SCALAR + COMPARE + branch::TAKEN_BANK_OFFSET] = F::ZERO;
        replace_destination(&mut flipped, wrong_result);
        assert!(!flipped.accepts(&program));
        let mut unsigned = fixture.clone();
        unsigned.0.row[SCALAR + COMPARE..SCALAR + PRODUCT_DIGITS]
            .copy_from_slice(&branch::bank_witness(wide::control::BLTU, u64::MAX, 1));
        replace_destination(&mut unsigned, wrong_result);
        assert!(!unsigned.accepts(&program));
        let (program, mut boolean) = checked_native(instruction, &[(2, 17, true), (3, 23, true)]);
        replace_destination(&mut boolean, 1);
        assert!(!boolean.accepts(&program));
    }
    for opcode in UNARY_OPS.into_iter().chain(SELECTION_OPS) {
        let instruction = enc::encode_rr(opcode, 4, 2, 3);
        let (program, mut reduced) = checked_native(
            instruction,
            &[(2, 0xffff_ffff_0000_0001, true), (3, 0, true)],
        );
        let (left, right) = if opcode == wide::arithmetic::NOT {
            (0, u64::MAX)
        } else {
            (0, 0)
        };
        replace_sources(&mut reduced, instruction, left, right);
        replace_destination(&mut reduced, expected(opcode, 0, 0));
        assert!(!reduced.accepts(&program));
        let instruction = enc::encode_rr(opcode, 4, 0, 0);
        let (program, mut zero) = checked_native(instruction, &[]);
        zero.0.packets.fields[SCALAR_LEFT][BEFORE] = F::ONE;
        zero.0.packets.fields[SCALAR_LEFT][AFTER] = F::ONE;
        let (left, right) = match opcode {
            wide::arithmetic::NEG => (0, 1),
            wide::arithmetic::NOT => (1, u64::MAX),
            _ => {
                zero.0.packets.fields[SCALAR_RIGHT][BEFORE] = F::ONE;
                zero.0.packets.fields[SCALAR_RIGHT][AFTER] = F::ONE;
                (1, 1)
            }
        };
        replace_sources(&mut zero, instruction, left, right);
        replace_destination(&mut zero, expected(opcode, 1, 1));
        assert!(!zero.accepts(&program));
        let instruction = enc::encode_rr(opcode, 2, 2, 3);
        let (program, mut alias) = checked_native(instruction, &[(2, 17, true), (3, 23, true)]);
        for limb in 0..4 {
            alias.0.packets.fields[SCALAR_DESTINATION][BEFORE + limb] = constant_limb(23, limb);
        }
        assert!(!alias.accepts(&program));
    }
}

#[test]
fn total_unary_selection_one_gas_boundaries_cycles_pc_and_false_halt_reject() {
    for opcode in UNARY_OPS.into_iter().chain(SELECTION_OPS) {
        let instruction = enc::encode_rr(opcode, 4, 2, 3);
        let inputs = [(2, i64::cast_unsigned(i64::MIN), true), (3, 1, true)];
        let root_gas = root_setup_gas();
        for gas in [0, root_result_table_gas()] {
            let (program, recorder, outcome) = shifts::capture(&[instruction], &inputs, gas, 32);
            assert!(matches!(outcome, Err(ivm::VMError::OutOfGas)));
            assert_root_preflight_out_of_gas(&program, &recorder, gas);
        }
        let (_, recorder, outcome) = shifts::capture(&[instruction], &inputs, root_gas, 32);
        assert!(matches!(outcome, Err(ivm::VMError::OutOfGas)));
        assert_eq!(recorder.records().len(), 1);
        let record = &recorder.records()[0];
        assert_eq!(record.instruction, Some(instruction));
        assert_eq!(record.opcode_gas, Some(1));
        assert_eq!(record.before.gas_remaining, 0);
        assert!(matches!(record.outcome, DiagnosticStepOutcome::Trapped(_)));
        assert_eq!(record.before, record.after);
        for gas in [root_gas + 1, 0xffff, 0x10000, u64::MAX] {
            let (program, recorder, _later_outcome) =
                shifts::capture(&[instruction], &inputs, gas, 32);
            let record = &recorder.records()[0];
            assert_eq!(record.outcome, DiagnosticStepOutcome::Completed);
            assert_eq!(record.before.gas_remaining, gas - root_gas);
            assert_eq!(record.after.gas_remaining, gas - root_gas - 1);
            assert!(ScalarFixture::from_record(&program, record).accepts(&program));
        }
        let (program, fixture) = checked_native(instruction, &inputs);
        let before = packet::half(&fixture.0.packets.fields[GAS_DEBIT], BEFORE, 0);
        for cost in [0, 2, 3] {
            let mut wrong = fixture.clone();
            bits(&mut wrong.0.row[WORDS + 128..WORDS + 192], before - cost);
            carries(&mut wrong.0.row[CARRIES..CARRIES + 4], before, cost, true);
            for limb in 0..4 {
                wrong.0.packets.fields[GAS_DEBIT][AFTER + limb] =
                    constant_limb(before - cost, limb);
            }
            assert!(!wrong.accepts(&program));
        }
        let mut underflow = fixture.clone();
        for (word, offset, value) in [(1, BEFORE, 0), (2, AFTER, u64::MAX)] {
            bits(
                &mut underflow.0.row[WORDS + 64 * word..WORDS + 64 * (word + 1)],
                value,
            );
            for limb in 0..4 {
                underflow.0.packets.fields[GAS_DEBIT][offset + limb] = constant_limb(value, limb);
            }
        }
        carries(&mut underflow.0.row[CARRIES..CARRIES + 4], 0, 1, true);
        assert!(!underflow.accepts(&program));
        let (limited, recorder, outcome) = shifts::capture(&[instruction], &inputs, 16, 1);
        assert!(matches!(outcome, Err(ivm::VMError::ExceededMaxCycles)));
        assert_eq!(recorder.records().len(), 1);
        let mut exhausted = ScalarFixture::from_record(&limited, &recorder.records()[0]);
        assert!(exhausted.accepts(&limited));
        for (word, value) in [(3, 1), (4, 2), (9, u64::MAX)] {
            bits(
                &mut exhausted.0.row[WORDS + 64 * word..WORDS + 64 * (word + 1)],
                value,
            );
        }
        exhausted.0.packets.fields[CYCLE_WRITE][BEFORE] = F::ONE;
        exhausted.0.packets.fields[CYCLE_WRITE][AFTER] = F(2);
        carries(&mut exhausted.0.row[CARRIES + 4..CARRIES + 8], 1, 1, false);
        carries(&mut exhausted.0.row[CARRIES + 16..CARRIES + 20], 0, 1, true);
        assert!(!exhausted.accepts(&limited));
        let mut wrong_pc = fixture.clone();
        let pc = packet::half(&wrong_pc.0.packets.fields[PC_WRITE], AFTER, 0) + 4;
        for limb in 0..4 {
            wrong_pc.0.packets.fields[PC_WRITE][AFTER + limb] = constant_limb(pc, limb);
        }
        assert!(!wrong_pc.accepts(&program));
        let mut halt = fixture.clone();
        halt.0.row[HALT] = F::ONE;
        halt.0.packets.fields[RUNNING_WRITE][AFTER] = F::ZERO;
        assert!(!halt.accepts(&program));
    }
}

#[test]
fn consecutive_native_unary_selection_preserves_private_boundaries_and_protected_return() {
    let body = [
        enc::encode_rr(wide::arithmetic::NEG, 4, 2, 255),
        enc::encode_rr(wide::arithmetic::NOT, 4, 4, 255),
        enc::encode_rr(wide::arithmetic::MIN, 5, 4, 3),
        enc::encode_rr(wide::arithmetic::MAX, 4, 5, 2),
    ];
    let (program, recorder, outcome) = shifts::capture(
        &body,
        &[(2, 17, true), (3, 23, true), (255, 0, false)],
        100,
        64,
    );
    assert!(outcome.is_ok());
    let records = &recorder.records()[..body.len()];
    for (instruction, record) in body.into_iter().zip(records) {
        assert_eq!(record.instruction, Some(instruction));
        assert_eq!(record.opcode_gas, Some(1));
        assert_eq!(record.after.pc, record.before.pc + 4);
        assert_eq!(record.after.cycles, record.before.cycles + 1);
        assert_eq!(record.after.gas_remaining + 1, record.before.gas_remaining);
        assert!(!record.after.halted);
        assert!(ScalarFixture::from_record(&program, record).accepts(&program));
    }
    for pair in records.windows(2) {
        assert_eq!(pair[0].after, pair[1].before);
    }
    let final_step = records.last().unwrap();
    assert_eq!(final_step.after.registers[4], 17);
    assert!(final_step.after.tags[4]);
    assert_eq!(final_step.after.registers[5], 16);
    assert!(final_step.after.tags[5]);
    assert!(final_step.after.pc < program.code_end());
    let end = recorder.end().unwrap();
    assert_eq!(end.outcome, Ok(()));
    assert!(end.state.halted);
    assert_eq!(end.state.pc, program.code_end());
}
