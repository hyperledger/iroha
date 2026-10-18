//! Native private MEAN, exact signed rounding, original costs and coherent attacks.

use super::*;

fn checked(instruction: u32, inputs: &[(usize, u64, bool)]) -> (Program, ScalarFixture) {
    let (program, fixture) = native(instruction, inputs);
    let p = &fixture.0.packets.fields;
    let left = u64::cast_signed(packet::half(&p[SCALAR_LEFT], BEFORE, 0));
    let right = u64::cast_signed(packet::half(&p[SCALAR_RIGHT], BEFORE, 0));
    let expected = ((i128::from(left) + i128::from(right)) / 2) as u64;
    assert_eq!(ivm::gas::cost_of(instruction), Some(2));
    assert_eq!(
        packet::half(&p[SCALAR_DESTINATION], AFTER, 0),
        if has_destination(instruction) {
            expected
        } else {
            0
        }
    );
    assert_eq!(
        p[SCALAR_DESTINATION][AFTER_TAG],
        if has_destination(instruction) {
            p[SCALAR_LEFT][BEFORE_TAG]
        } else {
            F::ZERO
        }
    );
    assert_eq!(
        packet::half(&p[GAS_DEBIT], BEFORE, 0) - packet::half(&p[GAS_DEBIT], AFTER, 0),
        2
    );
    assert_eq!(
        packet::half(&p[CYCLE_WRITE], AFTER, 0) - packet::half(&p[CYCLE_WRITE], BEFORE, 0),
        3
    );
    assert_eq!(
        packet::half(&p[PC_WRITE], AFTER, 0),
        packet::half(&p[PC_READ], BEFORE, 0) + 4
    );
    (program, fixture)
}

#[test]
fn native_private_mean_signed_extremes_rounding_tags_aliases_and_zero_match() {
    for (a, b) in [
        (0_i64, 0_i64),
        (0, -1),
        (0, -3),
        (1, 0),
        (3, 0),
        (-1, -2),
        (i64::MIN, i64::MIN),
        (i64::MAX, i64::MAX),
        (i64::MIN, i64::MAX),
        (i64::MIN, -1),
        (i64::MIN, 1),
        (i64::MAX, -1),
        (i64::MAX, 1),
        (-65536, 65535),
        (65535, 65536),
        (-(1 << 32), (1 << 32) - 1),
        (
            0x5555_5555_5555_5555,
            u64::cast_signed(0xaaaa_aaaa_aaaa_aaaa_u64),
        ),
    ] {
        for (a, b) in [(a, b), (b, a)] {
            for tag in [false, true] {
                for (rd, rs1, rs2) in [(4, 2, 3), (2, 2, 3), (3, 2, 3), (2, 2, 2), (0, 2, 3)] {
                    checked(
                        enc::encode_rr(wide::arithmetic::MEAN, rd, rs1, rs2),
                        &[
                            (2, i64::cast_unsigned(a), tag),
                            (3, i64::cast_unsigned(b), tag),
                            (4, 91, !tag),
                        ],
                    );
                }
            }
            for (rd, rs1, rs2) in [(4, 0, 3), (4, 2, 0), (0, 0, 0)] {
                checked(
                    enc::encode_rr(wide::arithmetic::MEAN, rd, rs1, rs2),
                    &[
                        (2, i64::cast_unsigned(a), false),
                        (3, i64::cast_unsigned(b), false),
                    ],
                );
            }
        }
    }
}

fn set_destination(fixture: &mut ScalarFixture, value: u64) {
    for limb in 0..4 {
        fixture.0.packets.fields[SCALAR_DESTINATION][AFTER + limb] = constant_limb(value, limb);
    }
}

#[test]
fn private_mean_rejects_wrapped_sum_floor_unsigned_and_false_original_sources() {
    let opcode = enc::encode_rr(wide::arithmetic::MEAN, 4, 2, 3);
    for (a, b) in [
        (i64::MIN, i64::MIN),
        (i64::MAX, i64::MAX),
        (-1, 0),
        (-3, 0),
        (i64::MIN, i64::MAX),
    ] {
        let (program, fixture) = checked(
            opcode,
            &[
                (2, i64::cast_unsigned(a), true),
                (3, i64::cast_unsigned(b), true),
            ],
        );
        let sum = i128::from(a) + i128::from(b);
        let correct = (sum / 2) as u64;
        for wrong in [
            correct.wrapping_add(1),
            (sum >> 1) as u64,
            i64::cast_unsigned(a.wrapping_add(b) / 2),
            ((u128::from(i64::cast_unsigned(a)) + u128::from(i64::cast_unsigned(b))) / 2) as u64,
        ] {
            if wrong == correct {
                continue;
            }
            // Rebuild the result's digits and carries coherently for a different
            // legitimate signed sum. The original ADD/source bits remain fixed.
            let signed = u64::cast_signed(wrong);
            let mut forged = fixture.clone();
            forged.0.row[SCALAR + MEAN..SCALAR + SHIFT].copy_from_slice(&mean::result_witness(
                i64::cast_unsigned(signed),
                i64::cast_unsigned(signed),
            ));
            set_destination(&mut forged, wrong);
            assert!(!forged.accepts(&program));
        }
        let (left, right) = (17, 23);
        let mut forged = fixture.clone();
        forged.0.row[SCALAR..SCALAR + ALU].copy_from_slice(&word::witness(left, right));
        fill_product(&mut forged.0, left, right);
        forged.0.row[SCALAR + ALU..SCALAR + COMPARE].copy_from_slice(&alu::witness(
            wide::arithmetic::ADD,
            left,
            right,
        ));
        forged.0.row[SCALAR + COMPARE..SCALAR + PRODUCT_DIGITS]
            .copy_from_slice(&branch::bank_witness(0, left, right));
        forged.0.row[SCALAR + SHIFT..super::super::super::WIDTH]
            .copy_from_slice(&shift::bank_witness(wide::arithmetic::SLL, left, right));
        forged.0.row[SCALAR + MEAN..SCALAR + SHIFT]
            .copy_from_slice(&mean::result_witness(left, right));
        set_destination(&mut forged, 20);
        assert!(!forged.accepts(&program));
        assert!(Fixture::padding().accepts(&program));
    }
}

#[test]
fn private_mean_binds_two_gas_three_cycles_and_native_last_attempt_boundary() {
    let instruction = enc::encode_rr(wide::arithmetic::MEAN, 4, 2, 3);
    let inputs = [
        (2, i64::cast_unsigned(i64::MIN), true),
        (3, i64::MAX as u64, true),
    ];
    let (program, fixture) = checked(instruction, &inputs);
    let p = &fixture.0.packets.fields;
    let gas = packet::half(&p[GAS_DEBIT], BEFORE, 0);
    let cycles = packet::half(&p[CYCLE_WRITE], BEFORE, 0);
    for wrong_cost in [0, 1, 3, 12] {
        let mut forged = fixture.clone();
        let after = gas - wrong_cost;
        bits(&mut forged.0.row[WORDS + 128..WORDS + 192], after);
        carries(
            &mut forged.0.row[CARRIES..CARRIES + 4],
            gas,
            wrong_cost,
            true,
        );
        for limb in 0..4 {
            forged.0.packets.fields[GAS_DEBIT][AFTER + limb] = constant_limb(after, limb);
        }
        assert!(!forged.accepts(&program));
    }
    for wrong_cost in [0, 1, 2, 4, 12] {
        let mut forged = fixture.clone();
        let after = cycles + wrong_cost;
        bits(&mut forged.0.row[WORDS + 256..WORDS + 320], after);
        carries(
            &mut forged.0.row[CARRIES + 4..CARRIES + 8],
            cycles,
            wrong_cost,
            false,
        );
        for limb in 0..4 {
            forged.0.packets.fields[CYCLE_WRITE][AFTER + limb] = constant_limb(after, limb);
        }
        assert!(!forged.accepts(&program));
    }
    for gas in 0..2 {
        let (_, recorder, outcome) =
            shifts::capture(&[instruction], &inputs, root_setup_gas() + gas, 32);
        assert!(matches!(outcome, Err(ivm::VMError::OutOfGas)));
        assert_eq!(recorder.records().len(), 1);
        let record = &recorder.records()[0];
        assert_eq!(record.opcode_gas, Some(2));
        assert_eq!(record.before.gas_remaining, gas);
        assert_eq!(record.before, record.after);
        assert!(matches!(record.outcome, DiagnosticStepOutcome::Trapped(_)));
    }
    for total_gas in [root_setup_gas() + 2, 0xffff, 0x10000, u64::MAX] {
        let (program, recorder, _) = shifts::capture(&[instruction], &inputs, total_gas, 32);
        let record = &recorder.records()[0];
        assert_eq!(record.outcome, DiagnosticStepOutcome::Completed);
        assert_eq!(record.before.gas_remaining, total_gas - root_setup_gas());
        assert_eq!(record.after.gas_remaining, total_gas - root_setup_gas() - 2);
        assert_eq!(record.after.cycles - record.before.cycles, 3);
        assert!(ScalarFixture::from_record(&program, record).accepts(&program));
    }
    for limit in [1, 2, 3] {
        let (limited, recorder, outcome) = shifts::capture(&[instruction], &inputs, 100, limit);
        assert!(matches!(outcome, Err(ivm::VMError::ExceededMaxCycles)));
        assert_eq!(recorder.records().len(), 1);
        let record = &recorder.records()[0];
        assert_eq!(record.outcome, DiagnosticStepOutcome::Completed);
        assert_eq!(record.before.cycles, 0);
        assert_eq!(record.after.cycles, 3);
        assert!(ScalarFixture::from_record(&limited, record).accepts(&limited));
    }
}

#[test]
fn private_mean_preserves_mixed_instruction_continuity_and_inactive_bank() {
    let instructions = [
        enc::encode_rr(wide::arithmetic::MEAN, 4, 2, 3),
        enc::encode_rr(wide::system::GETGAS, 5, 0, 0),
        enc::encode_rr(wide::arithmetic::ADD, 4, 4, 3),
        enc::encode_rr(wide::arithmetic::MEAN, 4, 4, 3),
    ];
    let (program, recorder, _) = shifts::capture(
        &instructions,
        &[(2, i64::cast_unsigned(-3_i64), true), (3, 0, true)],
        100,
        32,
    );
    assert!(recorder.records().len() >= instructions.len());
    for (instruction, record) in instructions.into_iter().zip(recorder.records()) {
        assert_eq!(record.instruction, Some(instruction));
        let fixture = ScalarFixture::from_record(&program, record);
        assert!(fixture.accepts(&program));
        if !is_mean(instruction) {
            assert!(
                fixture.0.row[SCALAR + MEAN..SCALAR + SHIFT]
                    .iter()
                    .all(|cell| *cell == F::ZERO)
            );
            for column in SCALAR + MEAN..SCALAR + SHIFT {
                let mut forged = fixture.clone();
                forged.0.row[column] = F::ONE;
                assert!(!forged.accepts(&program));
            }
        }
    }
    for pair in recorder.records()[..instructions.len()].windows(2) {
        assert_eq!(pair[0].after, pair[1].before);
    }
}
