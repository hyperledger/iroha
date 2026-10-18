//! Coherent quotient/remainder, outcome, carry and full-column attacks.

use super::*;

fn replace_word(bank: &mut [F], offset: usize, value: u64) {
    for limb in 0..4 {
        bank[offset + limb] = F((value >> (16 * limb)) & 0xffff);
    }
    word::fill_digits(&mut bank[offset + 4..offset + 36], value);
}

fn forged_destination(
    segment: &ScalarSegment,
    records: &[DiagnosticStepRecord],
    value: u64,
) -> (ScalarSegment, Vec<Vec<F>>) {
    let mut records = records.to_vec();
    records[0].after.registers[8] = value;
    let changed = from_records(segment, &records, segment.outcome);
    let mut rows = changed.witness_rows(&records).unwrap();
    rows[0][RESULT..RESULT + 2].copy_from_slice(&halves(value));
    (changed, rows)
}

#[test]
fn division_interior_rows_and_all_shared_columns_are_bound_for_success_and_both_traps() {
    for kind in 0..4 {
        for (a, b, gas) in [
            (0xffff_ffff_0000_0001, 7, 1_000),
            (17, 0, 11),
            (17, 0, 10),
            (i64::cast_unsigned(i64::MIN), u64::MAX, 1_000),
        ] {
            let body = [
                enc::encode_ri(wide::arithmetic::ADDI, 24, 24, 0),
                enc::encode_rr(DIVISION_OPS[kind], 8, 6, 7),
            ];
            let (segment, records) = attempted(&body, 2, &[(6, a), (7, b), (8, 91)], gas);
            let rows = segment.witness_rows(&records).unwrap();
            assert_rows(&segment, &rows);
            for column in 0..ROW_WIDTH {
                let mut forged = rows[1].clone();
                forged[column] = forged[column].add(F::ONE);
                let incoming =
                    residues(&segment, &rows[0], &forged, &segment.fixed_row(0)).unwrap();
                let outgoing =
                    residues(&segment, &forged, &rows[2], &segment.fixed_row(1)).unwrap();
                assert!(
                    incoming
                        .iter()
                        .chain(&outgoing)
                        .any(|value| *value != F::ZERO),
                    "kind {kind}, outcome {:?}, unbound {column}",
                    segment.outcome
                );
            }
            for column in 0..ROW_WIDTH {
                let mut forged = rows[2].clone();
                forged[column] = forged[column].add(F::ONE);
                assert!(
                    residues(
                        &segment,
                        &forged,
                        &forged,
                        &segment.fixed_row(segment.steps)
                    )
                    .unwrap()
                    .iter()
                    .any(|value| *value != F::ZERO)
                        || residues(&segment, &rows[1], &forged, &segment.fixed_row(1))
                            .unwrap()
                            .iter()
                            .any(|value| *value != F::ZERO),
                    "unbound padding column {column}"
                );
            }
        }
    }
}

#[test]
fn adjusted_quotient_and_remainder_cannot_bypass_strict_remainder_bound() {
    for kind in [1, 3] {
        let (segment, records) = single(kind, 17, 5, 1_000);
        // Q=2,R=7 preserves A=B*Q+R exactly, but R is not below B.
        let value = if kind == 1 { 2 } else { 7 };
        let (changed, mut rows) = forged_destination(&segment, &records, value);
        let bank = &mut rows[0][SHIFT..RESULT];
        for (offset, value) in [
            (division::QUOTIENT, 2),
            (division::REMAINDER, 7),
            (division::QUOTIENT_RESULT, 2),
            (division::REMAINDER_RESULT, 7),
        ] {
            replace_word(bank, offset, value);
        }
        let digits = multiply::product_digits(5, 2);
        let mut product = multiply::witness(5, 2, &digits, true);
        product[multiply::SIGNED_UNSIGNED..multiply::SIGNED_SIGNED]
            .copy_from_slice(&multiply::correction_witness(17, 0));
        product[multiply::SIGNED_SIGNED..].copy_from_slice(&multiply::correction_witness(5, 0));
        rows[0][BIT_COUNT..MULTIPLY].copy_from_slice(&digits);
        rows[0][MULTIPLY..ABSOLUTE].copy_from_slice(&product);
        rows[0][BRANCH..SHIFT].copy_from_slice(&branch::bank_witness(wide::control::BEQ, 7, 5));
        assert!(rejects(&changed, &rows));
    }
}

#[test]
fn coherent_signed_results_false_sources_high_products_and_carries_fail_division_air() {
    for kind in [0, 2] {
        let (segment, records) = single(kind, i64::cast_unsigned(-17_i64), 5, 1_000);
        let result = segment.after.registers[8].wrapping_neg();
        let (changed, mut rows) = forged_destination(&segment, &records, result);
        let (offset, borrows, sign) = if kind == 0 {
            (
                division::QUOTIENT_RESULT,
                division::QUOTIENT_BORROWS,
                division::QUOTIENT_NEGATIVE,
            )
        } else {
            (
                division::REMAINDER_RESULT,
                division::REMAINDER_BORROWS,
                division::REMAINDER_NEGATIVE,
            )
        };
        replace_word(&mut rows[0][SHIFT..RESULT], offset, result);
        rows[0][SHIFT + sign] = F::ZERO;
        rows[0][SHIFT + borrows..SHIFT + borrows + 4].fill(F::ZERO);
        assert!(rejects(&changed, &rows));
        let false_witness = division::witness(17, 5, 1_000, kind);
        rows[0][SOURCES..ALU].copy_from_slice(&word::witness(17, 5));
        rows[0][ALU..BRANCH].copy_from_slice(&alu_bank_witness(wide::arithmetic::ADD, 17, 5));
        rows[0][BRANCH..SHIFT].copy_from_slice(&branch::bank_witness(
            wide::control::BEQ,
            false_witness.remainder,
            false_witness.denominator,
        ));
        rows[0][SHIFT..RESULT].copy_from_slice(&false_witness.bank);
        rows[0][BIT_COUNT..MULTIPLY].copy_from_slice(&false_witness.digits);
        rows[0][MULTIPLY..ABSOLUTE].copy_from_slice(&false_witness.product);
        assert!(rejects(&changed, &rows));
    }
    let (segment, records) = single(1, u64::MAX, 1, 1_000);
    let rows = segment.witness_rows(&records).unwrap();
    for carry in 0..7 {
        let mut forged = rows.clone();
        let value = forged[0][MULTIPLY + multiply::CARRY + carry].0 + 1;
        forged[0][MULTIPLY + multiply::CARRY + carry] = F(value);
        word::fill_digits(
            &mut forged[0][MULTIPLY + multiply::CARRY_DIGITS + 9 * carry
                ..MULTIPLY + multiply::CARRY_DIGITS + 9 * (carry + 1)],
            value,
        );
        assert!(rejects(&segment, &forged));
    }
    let mut forged = rows.clone();
    forged[0][MULTIPLY + multiply::PRODUCT + 7] = F::ONE;
    forged[0][BIT_COUNT + 56] = F::ONE;
    assert!(
        rejects(&segment, &forged),
        "nonzero high product cannot be omitted from sum"
    );
    let mut forged = rows;
    forged[0][SHIFT + division::SUM_CARRIES + 7] = F::ONE;
    assert!(rejects(&segment, &forged), "final sum carry is zero");
}

#[test]
fn false_zero_overflow_gas_predicates_and_trap_workspaces_fail_even_with_changed_outcomes() {
    for (kind, a, b, gas) in [
        (0, 17, 0, 10),
        (2, i64::cast_unsigned(i64::MIN), u64::MAX, 10),
        (1, 17, 5, 9),
        (1, 17, 0xffff_ffff_0000_0001, 10),
    ] {
        let (segment, records) = single(kind, a, b, gas);
        let rows = segment.witness_rows(&records).unwrap();
        for offset in [
            division::ZERO_DENOMINATOR,
            division::ZERO_INVERSE,
            division::OVERFLOW,
            division::OVERFLOW_INVERSE,
            division::ARITHMETIC_ERROR,
            division::LOCAL_TRAP,
        ] {
            let mut forged = rows.clone();
            forged[0][SHIFT + offset] = forged[0][SHIFT + offset].add(F::ONE);
            assert!(rejects(&segment, &forged));
        }
        if segment.outcome.trapped() {
            let other = if segment.outcome == SegmentOutcome::OutOfGas {
                SegmentOutcome::AssertionFailed
            } else {
                SegmentOutcome::OutOfGas
            };
            let mut changed_records = records.clone();
            changed_records[0].outcome = other.diagnostic();
            let changed = from_records(&segment, &changed_records, other);
            let candidate = changed.witness_rows(&changed_records).unwrap();
            assert!(rejects(&changed, &candidate));
            assert_ne!(segment.digest().unwrap(), changed.digest().unwrap());
            for offset in [
                division::QUOTIENT,
                division::REMAINDER,
                division::QUOTIENT_RESULT,
                division::REMAINDER_RESULT,
            ] {
                let mut forged = rows.clone();
                replace_word(&mut forged[0][SHIFT..RESULT], offset, 1);
                assert!(rejects(&segment, &forged));
            }
        }
    }
}

#[test]
fn trap_transition_forgery_cannot_write_advance_debit_or_continue_after_failure() {
    for (a, b, gas) in [(17, 0, 10), (17, 5, 9)] {
        let (segment, records) = single(0, a, b, gas);
        for change in 0..4 {
            let mut forged = records.clone();
            match change {
                0 => forged[0].after.registers[8] ^= 1,
                1 => forged[0].after.pc += 4,
                2 => forged[0].after.gas_remaining = forged[0].after.gas_remaining.wrapping_add(10),
                _ => forged[0].after.cycles += 1,
            }
            let changed = ScalarSegment::new(
                segment.contract.clone(),
                1,
                forged[0].before,
                forged[0].after,
                segment.outcome,
            );
            if let Ok(changed) = changed {
                let rows = changed.witness_rows(&forged).unwrap();
                assert!(rejects(&changed, &rows));
            }
        }
        let mut extra = records[0];
        extra.before = extra.after;
        extra.after.cycles += 1;
        extra.after.pc += 4;
        extra.outcome = DiagnosticStepOutcome::Completed;
        let extended = [records[0], extra];
        let changed = ScalarSegment::new(
            segment.contract.clone(),
            2,
            segment.before,
            extra.after,
            SegmentOutcome::OutOfGas,
        )
        .unwrap();
        assert!(changed.witness_rows(&extended).is_err());
        let mut success = records.clone();
        success[0].outcome = DiagnosticStepOutcome::Completed;
        success[0].after.cycles += 1;
        success[0].after.pc += 4;
        let changed = from_records(&segment, &success, SegmentOutcome::Continue);
        assert!(rejects(&changed, &changed.witness_rows(&success).unwrap()));
    }
}
