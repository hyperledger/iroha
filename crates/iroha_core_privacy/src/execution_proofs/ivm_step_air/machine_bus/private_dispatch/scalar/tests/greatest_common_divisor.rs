//! Native signed GCD, original port custody and complete shared-cell ownership.

use super::*;

fn expected(left: u64, right: u64) -> u64 {
    let (mut a, mut b) = ((left as i64).unsigned_abs(), (right as i64).unsigned_abs());
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

fn checked(instruction: u32, inputs: &[(usize, u64, bool)]) -> (Program, ScalarFixture) {
    let (program, fixture) = native(instruction, inputs);
    let p = &fixture.0.packets.fields;
    assert_eq!(ivm::gas::cost_of(instruction), Some(12));
    let result = expected(
        packet::half(&p[SCALAR_LEFT], BEFORE, 0),
        packet::half(&p[SCALAR_RIGHT], BEFORE, 0),
    );
    assert_eq!(
        packet::half(&p[SCALAR_DESTINATION], AFTER, 0),
        if has_destination(instruction) {
            result
        } else {
            0
        }
    );
    if has_destination(instruction) {
        assert_eq!(p[SCALAR_DESTINATION][AFTER_TAG], p[SCALAR_LEFT][BEFORE_TAG]);
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
    assert_eq!(
        (PORTS, super::super::WIDTH, super::super::super::WIDTH),
        (21, 758, 1512)
    );
    (program, fixture)
}

#[test]
fn private_gcd_native_zero_signed_extremes_common_factors_tags_and_aliases_match() {
    for (left, right) in [
        (0_i64, 0_i64),
        (0, 1),
        (0, -17),
        (17, 0),
        (-17, 0),
        (i64::MIN, 0),
        (0, i64::MIN),
        (i64::MIN, i64::MIN),
        (i64::MIN, i64::MAX),
        (i64::MIN, -1),
        (i64::MAX, 1),
        (12, 18),
        (-12, 18),
        (12, -18),
        (-12, -18),
        (17, 17),
        (65536, 65535),
        (1 << 48, 1 << 40),
        (7_540_113_804_746_346_429, 4_660_046_610_375_530_309),
    ] {
        for tag in [false, true] {
            for rd in [0, 2, 3, 4] {
                checked(
                    enc::encode_rr(wide::arithmetic::GCD, rd, 2, 3),
                    &[(2, left as u64, tag), (3, right as u64, tag), (4, 97, !tag)],
                );
            }
            checked(
                enc::encode_rr(wide::arithmetic::GCD, 2, 2, 2),
                &[(2, left as u64, tag)],
            );
        }
        for (rs1, rs2) in [(0, 3), (2, 0), (0, 0)] {
            checked(
                enc::encode_rr(wide::arithmetic::GCD, 4, rs1, rs2),
                &[(2, left as u64, false), (3, right as u64, false)],
            );
        }
    }
    let mut random = 0xc341_79a5_563c_b912_u64;
    for _ in 0..64 {
        random = random
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let left = random;
        random = random.rotate_left(17).wrapping_add(0xd341_e6c9_417d_c765);
        checked(
            enc::encode_rr(wide::arithmetic::GCD, 4, 2, 3),
            &[(2, left, true), (3, random, true)],
        );
    }
}

#[test]
fn private_gcd_total_zero_branches_and_nonzero_bank_reject_every_cell_change() {
    for (left, right) in [
        (0, 0),
        (i64::MIN as u64, 0),
        (0, i64::MIN as u64),
        (12, 18),
        (u64::MAX, 65537),
    ] {
        let (program, fixture) = checked(
            enc::encode_rr(wide::arithmetic::GCD, 4, 2, 3),
            &[(2, left, true), (3, right, true)],
        );
        for column in 0..super::super::super::WIDTH {
            let mut forged = fixture.clone();
            forged.0.row[column] = forged.0.row[column].add(F::ONE);
            assert!(
                !forged.accepts(&program),
                "left={left} right={right} physical={column}"
            );
        }
        for slot in [SCALAR_LEFT, SCALAR_RIGHT, GAS_DEBIT, CYCLE_WRITE, PC_WRITE] {
            for column in 0..packet::WIDTH {
                let mut forged = fixture.clone();
                forged.0.packets.fields[slot][column] =
                    forged.0.packets.fields[slot][column].add(F::ONE);
                assert!(!forged.accepts(&program), "slot={slot} column={column}");
            }
        }
        for column in (AFTER..AFTER + 4).chain([AFTER_TAG]) {
            let mut forged = fixture.clone();
            forged.0.packets.fields[SCALAR_DESTINATION][column] =
                forged.0.packets.fields[SCALAR_DESTINATION][column].add(F::ONE);
            assert!(!forged.accepts(&program));
        }
    }
}

#[test]
fn private_gcd_rejects_coherent_foreign_sources_and_mismatched_original_tags() {
    let instruction = enc::encode_rr(wide::arithmetic::GCD, 4, 2, 3);
    let (program, fixture) = checked(instruction, &[(2, 12, true), (3, 18, true)]);
    for (left, right) in [(0, 0), (12, 0), (0, 18), (24, 18), (u64::MAX, 65537)] {
        let mut forged = fixture.clone();
        gcd::fill(&mut forged.0.row[SCALAR..], left, right);
        for limb in 0..4 {
            forged.0.packets.fields[SCALAR_DESTINATION][AFTER + limb] =
                constant_limb(expected(left, right), limb);
        }
        assert!(
            !forged.accepts(&program),
            "coherent foreign GCD cannot replace original source reads"
        );
    }
    for rd in [0, 4] {
        let instruction = enc::encode_rr(wide::arithmetic::GCD, rd, 2, 3);
        for tags in [[false, true], [true, false]] {
            let (_, recorder, outcome) = shifts::capture(
                &[instruction],
                &[(2, 12, tags[0]), (3, 18, tags[1])],
                100,
                64,
            );
            assert!(matches!(outcome, Err(ivm::VMError::PrivacyViolation)));
            let record = &recorder.records()[0];
            assert!(matches!(record.outcome, DiagnosticStepOutcome::Trapped(_)));
            assert_eq!(record.before.registers, record.after.registers);
            assert_eq!(record.before.pc, record.after.pc);
            assert_eq!(record.before.cycles, record.after.cycles);
            let (program, mut forged) = checked(instruction, &[(2, 12, false), (3, 18, false)]);
            for (slot, tag) in [(SCALAR_LEFT, tags[0]), (SCALAR_RIGHT, tags[1])] {
                forged.0.packets.fields[slot][BEFORE_TAG] = F(u64::from(tag));
                forged.0.packets.fields[slot][AFTER_TAG] = F(u64::from(tag));
            }
            if rd != 0 {
                forged.0.packets.fields[SCALAR_DESTINATION][AFTER_TAG] = F(u64::from(tags[0]));
            }
            assert!(!forged.accepts(&program));
        }
    }
}

#[test]
fn private_gcd_binds_twelve_gas_cycles_and_native_last_attempt_boundary() {
    let instruction = enc::encode_rr(wide::arithmetic::GCD, 4, 2, 3);
    let inputs = [(2, i64::MIN as u64, true), (3, 0, true)];
    let (program, fixture) = checked(instruction, &inputs);
    for (slot, word, carry, is_gas) in [(GAS_DEBIT, 2, 0, true), (CYCLE_WRITE, 4, 4, false)] {
        let before = packet::half(&fixture.0.packets.fields[slot], BEFORE, 0);
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
    for gas in 0..12 {
        let (_, recorder, outcome) =
            shifts::capture(&[instruction], &inputs, root_setup_gas() + gas, 32);
        assert!(matches!(outcome, Err(ivm::VMError::OutOfGas)));
        assert_eq!(recorder.records().len(), 1);
        assert_eq!(recorder.records()[0].before, recorder.records()[0].after);
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
fn private_gcd_all_six_shared_workspace_modes_keep_original_record_continuity() {
    let instructions = [
        enc::encode_rr(wide::arithmetic::GCD, 4, 2, 3),
        enc::encode_rr(wide::arithmetic::DIV_CEIL, 4, 4, 3),
        enc::encode_rr(wide::arithmetic::MEAN, 4, 4, 3),
        enc::encode_rr(wide::arithmetic::ISQRT, 4, 4, 255),
        enc::encode_rr(wide::arithmetic::MUL, 4, 4, 3),
        enc::encode_rr(wide::arithmetic::DIV, 4, 4, 3),
        enc::encode_rr(wide::arithmetic::GCD, 4, 4, 3),
    ];
    let (program, recorder, _) =
        shifts::capture(&instructions, &[(2, 12, false), (3, 18, false)], 200, 100);
    assert!(recorder.records().len() >= instructions.len());
    for (instruction, record) in instructions.into_iter().zip(recorder.records()) {
        assert_eq!(record.instruction, Some(instruction));
        assert!(ScalarFixture::from_record(&program, record).accepts(&program));
    }
    for pair in recorder.records()[..instructions.len()].windows(2) {
        assert_eq!(pair[0].after, pair[1].before);
    }
    assert!(Fixture::padding().accepts(&program));
}
