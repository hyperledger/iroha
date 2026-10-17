//! Native ABS through the original private ports, including trap-sensitive input.

use super::*;

fn checked(instruction: u32, inputs: &[(usize, u64, bool)]) -> (Program, ScalarFixture) {
    let (program, fixture) = native(instruction, inputs);
    let p = &fixture.0.packets.fields;
    let source = packet::half(&p[SCALAR_LEFT], BEFORE, 0);
    let expected = u64::cast_signed(source).checked_abs().unwrap() as u64;
    assert_eq!(ivm::gas::cost_of(instruction), Some(1));
    assert_eq!(
        packet::half(&p[SCALAR_DESTINATION], AFTER, 0),
        if has_destination(instruction) {
            expected
        } else {
            0
        }
    );
    assert_eq!(p[SCALAR_LEFT][BEFORE_TAG], F::ZERO);
    assert_eq!(p[SCALAR_DESTINATION][AFTER_TAG], F::ZERO);
    assert!(p[SCALAR_RIGHT].iter().all(|v| *v == F::ZERO));
    assert_eq!(
        packet::half(&p[GAS_DEBIT], BEFORE, 0) - packet::half(&p[GAS_DEBIT], AFTER, 0),
        1
    );
    assert_eq!(
        packet::half(&p[PC_WRITE], AFTER, 0),
        packet::half(&p[PC_READ], BEFORE, 0) + 4
    );
    assert_eq!(
        packet::half(&p[CYCLE_WRITE], AFTER, 0),
        packet::half(&p[CYCLE_WRITE], BEFORE, 0) + 1
    );
    assert_eq!(fixture.0.row[SCALAR + MOVE_ZERO], F::ZERO);
    (program, fixture)
}

fn destination(fixture: &mut ScalarFixture, value: u64) {
    for limb in 0..4 {
        fixture.0.packets.fields[SCALAR_DESTINATION][AFTER + limb] = constant_limb(value, limb);
    }
}

// Rebuild every reused bank coherently for the candidate source; callers choose
// whether to retain or replace the original architectural read packet.
fn arithmetic(fixture: &mut ScalarFixture, value: u64) {
    fixture.0.row[SCALAR..SCALAR + ALU].copy_from_slice(&word::witness(0, value));
    fill_product(&mut fixture.0, 0, value);
    fixture.0.row[SCALAR + ALU..SCALAR + COMPARE].copy_from_slice(&alu::witness(
        wide::arithmetic::SUB,
        0,
        value,
    ));
    fixture.0.row[SCALAR + COMPARE..SCALAR + PRODUCT_DIGITS]
        .copy_from_slice(&branch::bank_witness(0, 0, value));
    fixture.0.row[SCALAR + SHIFT..super::super::super::WIDTH]
        .copy_from_slice(&shift::bank_witness(wide::arithmetic::SLL, 0, value));
    fill_absolute_zero_test(&mut fixture.0, value);
}

#[test]
fn native_absolute_full_words_zero_aliases_and_unused_operand_match() {
    for value in [
        0,
        1,
        u64::MAX,
        i64::MAX as u64,
        i64::cast_unsigned(i64::MIN + 1),
        1 << 32,
        0xffff_ffff_0000_0001,
    ] {
        for rd in [0, 2, 4] {
            checked(
                enc::encode_rr(wide::arithmetic::ABS, rd, 2, 255),
                &[(2, value, false), (4, 19, true), (255, u64::MAX, true)],
            );
        }
    }
    for rs2 in 0..=u8::MAX {
        checked(
            enc::encode_rr(wide::arithmetic::ABS, 4, 2, rs2),
            &[
                (2, i64::cast_unsigned(-17i64), false),
                (4, 91, true),
                (255, 17, true),
            ],
        );
    }
    for rd in [0, 4] {
        checked(
            enc::encode_rr(wide::arithmetic::ABS, rd, 0, 255),
            &[(4, 91, true), (255, u64::MAX, true)],
        );
    }
}

#[test]
fn native_absolute_overflow_private_tag_and_gas_first_traps_cannot_commit() {
    for rd in [0, 4] {
        for (value, tag, funded) in [
            (i64::cast_unsigned(i64::MIN), false, true),
            (i64::cast_unsigned(i64::MIN), true, true),
            (17, true, true),
            (i64::cast_unsigned(-17i64), true, true),
            (i64::cast_unsigned(i64::MIN), true, false),
            (17, false, false),
        ] {
            let instruction = enc::encode_rr(wide::arithmetic::ABS, rd, 2, 255);
            let (_, recorder, outcome) = shifts::capture(
                &[instruction],
                &[(2, value, tag), (4, 91, true)],
                root_setup_gas() + u64::from(funded),
                32,
            );
            if !funded {
                assert!(matches!(outcome, Err(ivm::VMError::OutOfGas)));
            } else if tag {
                assert!(matches!(outcome, Err(ivm::VMError::PrivacyViolation)));
            } else {
                assert!(matches!(outcome, Err(ivm::VMError::AssertionFailed)));
            }
            let record = &recorder.records()[0];
            assert_eq!(recorder.records().len(), 1);
            assert_eq!(record.opcode_gas, Some(1));
            assert!(matches!(record.outcome, DiagnosticStepOutcome::Trapped(_)));
            assert_eq!(record.before.registers, record.after.registers);
            assert_eq!(record.before.tags, record.after.tags);
            assert_eq!(record.before.pc, record.after.pc);
            assert_eq!(record.before.cycles, record.after.cycles);
            assert_eq!(record.after.gas_remaining, 0);
            assert_eq!(record.before.gas_remaining, u64::from(funded));
            assert!(!record.after.halted);
        }
        let instruction = enc::encode_rr(wide::arithmetic::ABS, rd, 2, 255);
        let (program, fixture) = checked(instruction, &[(2, 17, false), (4, 91, true)]);
        let mut secret = fixture.clone();
        secret.0.packets.fields[SCALAR_LEFT][BEFORE_TAG] = F::ONE;
        secret.0.packets.fields[SCALAR_LEFT][AFTER_TAG] = F::ONE;
        if rd != 0 {
            secret.0.packets.fields[SCALAR_DESTINATION][AFTER_TAG] = F::ONE;
        }
        assert!(!secret.accepts(&program));
        let mut overflow = fixture.clone();
        arithmetic(&mut overflow, i64::cast_unsigned(i64::MIN));
        for limb in 0..4 {
            for offset in [BEFORE, AFTER] {
                overflow.0.packets.fields[SCALAR_LEFT][offset + limb] =
                    constant_limb(i64::cast_unsigned(i64::MIN), limb);
            }
        }
        if rd != 0 {
            destination(&mut overflow, i64::cast_unsigned(i64::MIN));
        }
        assert!(!overflow.accepts(&program));
        // Pretending overflow is nonzero cannot satisfy the canonical inverse.
        overflow.0.row[SCALAR + MOVE_ZERO] = F::ZERO;
        overflow.0.row[SCALAR + MOVE_INVERSE] = F::ONE;
        assert!(!overflow.accepts(&program));
    }
}

#[test]
fn absolute_rejects_coherent_wrong_magnitude_original_source_and_tariff() {
    for value in [17, i64::cast_unsigned(-17i64), 0xffff_ffff_0000_0001] {
        let instruction = enc::encode_rr(wide::arithmetic::ABS, 4, 2, 255);
        let (program, fixture) = checked(instruction, &[(2, value, false), (4, 91, true)]);
        let correct = u64::cast_signed(value).checked_abs().unwrap() as u64;
        for wrong in [correct + 1, correct.wrapping_neg()] {
            let mut forged = fixture.clone();
            destination(&mut forged, wrong);
            assert!(!forged.accepts(&program));
        }
        let mut forged = fixture.clone();
        arithmetic(&mut forged, 29);
        destination(&mut forged, 29);
        assert!(!forged.accepts(&program));
        let before = packet::half(&fixture.0.packets.fields[GAS_DEBIT], BEFORE, 0);
        for cost in [0, 2, 10] {
            let mut forged = fixture.clone();
            let after = before - cost;
            bits(&mut forged.0.row[WORDS + 128..WORDS + 192], after);
            carries(&mut forged.0.row[CARRIES..CARRIES + 4], before, cost, true);
            for limb in 0..4 {
                forged.0.packets.fields[GAS_DEBIT][AFTER + limb] = constant_limb(after, limb);
            }
            assert!(!forged.accepts(&program));
        }
        assert!(Fixture::padding().accepts(&program));
    }
}

#[test]
fn absolute_binds_every_original_workspace_and_used_port_cell() {
    // rd=rs1 binds the prior destination through the same original read.
    let (program, fixture) = checked(
        enc::encode_rr(wide::arithmetic::ABS, 2, 2, 255),
        &[(2, i64::cast_unsigned(-17i64), false), (255, 17, true)],
    );
    for index in 0..super::super::super::WIDTH {
        let mut forged = fixture.clone();
        forged.0.row[index] = forged.0.row[index].add(F::ONE);
        assert!(!forged.accepts(&program), "workspace {index}");
    }
    for slot in 0..PORTS {
        for column in 0..packet::WIDTH {
            let mut forged = fixture.clone();
            forged.0.packets.fields[slot][column] =
                forged.0.packets.fields[slot][column].add(F::ONE);
            assert!(!forged.accepts(&program), "port {slot} column {column}");
        }
    }
}
