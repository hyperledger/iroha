//! Native ceiling division, exact rounding, shared-cell roles and original ports.

use super::*;

fn expected(left: u64, right: u64) -> Option<u64> {
    let (left, right) = (u64::cast_signed(left), u64::cast_signed(right));
    let quotient = left.checked_div(right)?;
    let remainder = left.checked_rem(right)?;
    quotient
        .checked_add(i64::from(remainder != 0 && (left < 0) == (right < 0)))
        .map(|v| i64::cast_unsigned(v))
}

fn set_destination(fixture: &mut ScalarFixture, value: u64) {
    for limb in 0..4 {
        fixture.0.packets.fields[SCALAR_DESTINATION][AFTER + limb] = constant_limb(value, limb);
    }
}

fn fill_ceiling(fixture: &mut Fixture) {
    let result = ceiling::witness(&fixture.row[SCALAR + SHIFT..super::super::super::WIDTH]);
    fixture.row[SCALAR + MEAN..SCALAR + SHIFT].copy_from_slice(&result);
}

fn checked(instruction: u32, inputs: &[(usize, u64, bool)]) -> (Program, ScalarFixture) {
    let (program, fixture) = native(instruction, inputs);
    let p = &fixture.0.packets.fields;
    let result = expected(
        packet::half(&p[SCALAR_LEFT], BEFORE, 0),
        packet::half(&p[SCALAR_RIGHT], BEFORE, 0),
    )
    .unwrap();
    assert_eq!(ivm::gas::cost_of(instruction), Some(12));
    assert_eq!(
        packet::half(&p[SCALAR_DESTINATION], AFTER, 0),
        if has_destination(instruction) {
            result
        } else {
            0
        }
    );
    for slot in [SCALAR_LEFT, SCALAR_RIGHT, SCALAR_DESTINATION] {
        assert_eq!(p[slot][AFTER_TAG], F::ZERO);
    }
    assert_eq!(
        packet::half(&p[GAS_DEBIT], BEFORE, 0) - packet::half(&p[GAS_DEBIT], AFTER, 0),
        12
    );
    assert_eq!(
        packet::half(&p[CYCLE_WRITE], AFTER, 0) - packet::half(&p[CYCLE_WRITE], BEFORE, 0),
        12
    );
    assert_eq!(
        packet::half(&p[PC_WRITE], AFTER, 0),
        packet::half(&p[PC_READ], BEFORE, 0) + 4
    );
    (program, fixture)
}

#[test]
fn private_divceil_native_signed_extremes_rounding_aliases_and_r0_match() {
    for (left, right) in [
        (0_i64, 1_i64),
        (0, -1),
        (1, 2),
        (17, 3),
        (17, -3),
        (-17, 3),
        (-17, -3),
        (18, 3),
        (18, -3),
        (-18, 3),
        (-18, -3),
        (i64::MIN, 1),
        (i64::MIN, 2),
        (i64::MIN, -3),
        (i64::MIN, i64::MIN),
        (i64::MAX, 1),
        (i64::MAX, 2),
        (i64::MAX, -3),
        (i64::MAX, i64::MIN),
        (-1, i64::MIN),
        (65535, 65536),
        (-65537, -65536),
    ] {
        for rd in [0, 2, 3, 4] {
            checked(
                enc::encode_rr(wide::arithmetic::DIV_CEIL, rd, 2, 3),
                &[
                    (2, i64::cast_unsigned(left), false),
                    (3, i64::cast_unsigned(right), false),
                    (4, 91, true),
                ],
            );
        }
        checked(
            enc::encode_rr(wide::arithmetic::DIV_CEIL, 4, 0, 3),
            &[(3, i64::cast_unsigned(right), false)],
        );
        if left != 0 {
            checked(
                enc::encode_rr(wide::arithmetic::DIV_CEIL, 2, 2, 2),
                &[(2, i64::cast_unsigned(left), false)],
            );
        }
    }
    for bit in 0..64 {
        checked(
            enc::encode_rr(wide::arithmetic::DIV_CEIL, 4, 2, 3),
            &[(2, 0xfedc_ba98_7654_3210, false), (3, 1_u64 << bit, false)],
        );
    }
}

#[test]
fn private_divceil_exact_nonzero_inverse_and_false_signed_rounding_reject() {
    let instruction = enc::encode_rr(wide::arithmetic::DIV_CEIL, 4, 2, 3);
    for (left, right) in [(17_i64, 3_i64), (-17, -3), (17, -3), (-17, 3), (18, 3)] {
        let (program, fixture) = checked(
            instruction,
            &[
                (2, i64::cast_unsigned(left), false),
                (3, i64::cast_unsigned(right), false),
            ],
        );
        let shifts = &fixture.0.row[SCALAR + SHIFT..super::super::super::WIDTH];
        let bank = &fixture.0.row[SCALAR + MEAN..SCALAR + SHIFT];
        if left == 17 && right == 3 {
            assert_ne!(bank[ceiling::INVERSE], F::ZERO);
            assert_ne!(bank[ceiling::INVERSE], F::ONE);
        }
        // Keep the exact original division bank, but rebuild a coherent result
        // that claims zero remainder or the opposite truncating quotient sign.
        for change in [0, 1] {
            let mut alternative: [F; shift::BANK_WIDTH] = shifts.try_into().unwrap();
            if change == 0 {
                alternative[division::REMAINDER..division::REMAINDER + 36].fill(F::ZERO);
            } else {
                alternative[division::QUOTIENT_NEGATIVE] =
                    F::ONE.sub(alternative[division::QUOTIENT_NEGATIVE]);
            }
            let candidate = ceiling::witness(&alternative);
            if candidate.as_slice() == bank {
                continue;
            }
            let wrong = candidate[..4]
                .iter()
                .enumerate()
                .fold(0_u64, |v, (i, limb)| v | (limb.0 << (16 * i)));
            let mut forged = fixture.clone();
            forged.0.row[SCALAR + MEAN..SCALAR + SHIFT].copy_from_slice(&candidate);
            set_destination(&mut forged, wrong);
            assert!(!forged.accepts(&program));
        }
        for cell in 0..mean::WIDTH {
            let mut forged = fixture.clone();
            forged.0.row[SCALAR + MEAN + cell] = forged.0.row[SCALAR + MEAN + cell].add(F::ONE);
            assert!(!forged.accepts(&program), "ceiling result cell {cell}");
        }
    }
}

#[test]
fn private_divceil_same_integer_sum_with_noncanonical_remainder_rejects() {
    // 17 = 3*5+2 = 3*4+5; only the former remainder is strictly below 3.
    let (program, mut forged) = checked(
        enc::encode_rr(wide::arithmetic::DIV_CEIL, 4, 2, 3),
        &[(2, 17, false), (3, 3, false)],
    );
    let digits = multiply::product_digits(3, 4);
    let product = multiply::witness(3, 4, &digits, true);
    forged.0.row[SCALAR + PRODUCT_DIGITS..SCALAR + MULTIPLY].copy_from_slice(&digits);
    forged.0.row[SCALAR + MULTIPLY..SCALAR + MULTIPLY + multiply::SIGNED_UNSIGNED]
        .copy_from_slice(&product[..multiply::SIGNED_UNSIGNED]);
    for (offset, result, borrows, value) in [
        (
            division::QUOTIENT,
            division::QUOTIENT_RESULT,
            division::QUOTIENT_BORROWS,
            4,
        ),
        (
            division::REMAINDER,
            division::REMAINDER_RESULT,
            division::REMAINDER_BORROWS,
            5,
        ),
    ] {
        let correction = multiply::correction_witness(value, 0);
        for start in [offset, result] {
            forged.0.row[SCALAR + SHIFT + start..SCALAR + SHIFT + start + 36]
                .copy_from_slice(&correction[..36]);
        }
        forged.0.row[SCALAR + SHIFT + borrows..SCALAR + SHIFT + borrows + 4]
            .copy_from_slice(&correction[36..]);
    }
    forged.0.row[SCALAR + COMPARE..SCALAR + PRODUCT_DIGITS]
        .copy_from_slice(&branch::bank_witness(0, 5, 3));
    fill_ceiling(&mut forged.0);
    set_destination(&mut forged, 5);
    let mut residues = Vec::new();
    super::super::super::append_residues(
        &mut residues,
        &program,
        forged.0.schedule,
        &forged.0.row,
        &forged.0.packets,
    );
    assert_eq!(
        residues
            .into_iter()
            .filter(|v| *v != F::ZERO)
            .collect::<Vec<_>>(),
        vec![F::ZERO.sub(F::ONE)]
    );
}

#[test]
fn private_divceil_native_private_arithmetic_and_gas_traps_refuse_completed_rows() {
    for rd in [0, 4] {
        let instruction = enc::encode_rr(wide::arithmetic::DIV_CEIL, rd, 2, 3);
        for (left, right, tags, gas) in [
            (17, 3, [true, false], 12),
            (17, 3, [false, true], 12),
            (17, 3, [true, true], 12),
            (17, 0, [false, false], 12),
            (i64::cast_unsigned(i64::MIN), u64::MAX, [false, false], 12),
            (17, 3, [false, false], 0),
            (17, 3, [false, false], 11),
        ] {
            let (_, recorder, outcome) = shifts::capture(
                &[instruction],
                &[(2, left, tags[0]), (3, right, tags[1])],
                root_setup_gas() + gas,
                32,
            );
            if gas < 12 {
                assert!(matches!(outcome, Err(ivm::VMError::OutOfGas)));
            } else if tags != [false, false] {
                assert!(matches!(outcome, Err(ivm::VMError::PrivacyViolation)));
            } else {
                assert!(matches!(outcome, Err(ivm::VMError::AssertionFailed)));
            }
            let record = &recorder.records()[0];
            assert!(matches!(record.outcome, DiagnosticStepOutcome::Trapped(_)));
            assert_eq!(record.before.registers, record.after.registers);
            assert_eq!(record.before.tags, record.after.tags);
            assert_eq!(record.before.pc, record.after.pc);
            assert_eq!(record.before.cycles, record.after.cycles);
            assert_eq!(record.after.gas_remaining, if gas < 12 { gas } else { 0 });
            let (program, mut forged) = checked(instruction, &[(2, 17, false), (3, 3, false)]);
            for (slot, value, tag) in [(SCALAR_LEFT, left, tags[0]), (SCALAR_RIGHT, right, tags[1])]
            {
                for limb in 0..4 {
                    forged.0.packets.fields[slot][BEFORE + limb] = constant_limb(value, limb);
                    forged.0.packets.fields[slot][AFTER + limb] = constant_limb(value, limb);
                }
                forged.0.packets.fields[slot][BEFORE_TAG] = F(u64::from(tag));
                forged.0.packets.fields[slot][AFTER_TAG] = F(u64::from(tag));
            }
            forged.0.row[SCALAR..SCALAR + ALU].copy_from_slice(&word::witness(left, right));
            forged.0.row[SCALAR + ALU..SCALAR + COMPARE].copy_from_slice(&alu::witness(
                wide::arithmetic::ADD,
                left,
                right,
            ));
            fill_count(&mut forged.0, left, false);
            fill_division(&mut forged.0, left, right, gas, 4);
            fill_ceiling(&mut forged.0);
            set_destination(&mut forged, 0);
            bits(&mut forged.0.row[WORDS + 64..WORDS + 128], gas);
            let after = gas.wrapping_sub(12);
            bits(&mut forged.0.row[WORDS + 128..WORDS + 192], after);
            carries(&mut forged.0.row[CARRIES..CARRIES + 4], gas, 12, true);
            for limb in 0..4 {
                forged.0.packets.fields[GAS_DEBIT][BEFORE + limb] = constant_limb(gas, limb);
                forged.0.packets.fields[GAS_DEBIT][AFTER + limb] = constant_limb(after, limb);
            }
            assert!(!forged.accepts(&program));
        }
    }
}

#[test]
fn private_divceil_twelve_gas_cycles_and_last_attempt_boundary_are_bound() {
    let instruction = enc::encode_rr(wide::arithmetic::DIV_CEIL, 4, 2, 3);
    let inputs = [(2, 17, false), (3, 3, false)];
    let (program, fixture) = checked(instruction, &inputs);
    for (slot, word, carry, before, is_gas) in [
        (
            GAS_DEBIT,
            2,
            0,
            packet::half(&fixture.0.packets.fields[GAS_DEBIT], BEFORE, 0),
            true,
        ),
        (
            CYCLE_WRITE,
            4,
            4,
            packet::half(&fixture.0.packets.fields[CYCLE_WRITE], BEFORE, 0),
            false,
        ),
    ] {
        for wrong in [0, 1, 6, 10, 11, 13] {
            let mut forged = fixture.clone();
            let after = if is_gas {
                before - wrong
            } else {
                before + wrong
            };
            bits(
                &mut forged.0.row[WORDS + 64 * word..WORDS + 64 * (word + 1)],
                after,
            );
            carries(
                &mut forged.0.row[CARRIES + carry..CARRIES + carry + 4],
                before,
                wrong,
                is_gas,
            );
            for limb in 0..4 {
                forged.0.packets.fields[slot][AFTER + limb] = constant_limb(after, limb);
            }
            assert!(!forged.accepts(&program));
        }
    }
    for limit in 1..=12 {
        let (program, recorder, outcome) = shifts::capture(&[instruction], &inputs, 100, limit);
        assert!(matches!(outcome, Err(ivm::VMError::ExceededMaxCycles)));
        assert_eq!(recorder.records().len(), 1);
        let record = &recorder.records()[0];
        assert_eq!(record.outcome, DiagnosticStepOutcome::Completed);
        assert_eq!(record.before.cycles, 0);
        assert_eq!(record.after.cycles, 12);
        assert!(ScalarFixture::from_record(&program, record).accepts(&program));
    }
}

#[test]
fn private_divceil_mean_square_multiply_and_padding_keep_distinct_original_cell_roles() {
    let instructions = [
        enc::encode_rr(wide::arithmetic::DIV_CEIL, 4, 2, 3),
        enc::encode_rr(wide::arithmetic::MEAN, 4, 4, 3),
        enc::encode_rr(wide::arithmetic::ISQRT, 4, 4, 255),
        enc::encode_rr(wide::arithmetic::MUL, 4, 4, 3),
        enc::encode_rr(wide::arithmetic::DIV, 4, 4, 3),
        enc::encode_rr(wide::arithmetic::DIV_CEIL, 4, 4, 3),
        enc::encode_rr(wide::system::GETGAS, 5, 4, 5),
    ];
    let (program, recorder, _) =
        shifts::capture(&instructions, &[(2, 17, false), (3, 3, false)], 100, 100);
    assert!(recorder.records().len() >= instructions.len());
    for (instruction, record) in instructions.into_iter().zip(recorder.records()) {
        let fixture = ScalarFixture::from_record(&program, record);
        assert!(fixture.accepts(&program));
        if !is_mean(instruction) && !is_division_ceiling(instruction) {
            assert!(
                fixture.0.row[SCALAR + MEAN..SCALAR + SHIFT]
                    .iter()
                    .all(|v| *v == F::ZERO)
            );
            for offset in 0..mean::WIDTH {
                let mut forged = fixture.clone();
                forged.0.row[SCALAR + MEAN + offset] = F::ONE;
                assert!(!forged.accepts(&program));
            }
        }
        if is_mean(instruction) {
            let mut forged = fixture.clone();
            forged.0.row[SCALAR + MEAN + ceiling::INVERSE] = F(2);
            assert!(!forged.accepts(&program));
        }
    }
    for pair in recorder.records()[..instructions.len()].windows(2) {
        assert_eq!(pair[0].after, pair[1].before);
    }
    assert!(Fixture::padding().accepts(&program));
    for offset in 0..mean::WIDTH {
        let mut forged = ScalarFixture(Fixture::padding());
        forged.0.row[SCALAR + MEAN + offset] = F::ONE;
        assert!(!forged.accepts(&program));
    }
}
