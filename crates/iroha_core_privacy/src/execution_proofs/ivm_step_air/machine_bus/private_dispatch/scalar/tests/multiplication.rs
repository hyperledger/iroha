//! Original private multiplication, signed corrections, tariffs and coherent attacks.

use super::*;

const OPS: [u8; 4] = [
    wide::arithmetic::MUL,
    wide::arithmetic::MULHU,
    wide::arithmetic::MULHSU,
    wide::arithmetic::MULH,
];

fn expected(opcode: u8, left: u64, right: u64) -> u64 {
    match opcode {
        wide::arithmetic::MUL => left.wrapping_mul(right),
        wide::arithmetic::MULHU => ((u128::from(left) * u128::from(right)) >> 64) as u64,
        wide::arithmetic::MULHSU => {
            ((i128::from(u64::cast_signed(left)) * i128::from(right)) >> 64) as u64
        }
        wide::arithmetic::MULH => {
            ((i128::from(u64::cast_signed(left)) * i128::from(u64::cast_signed(right))) >> 64)
                as u64
        }
        _ => panic!("multiplication fixture opcode"),
    }
}

fn set_destination(fixture: &mut ScalarFixture, value: u64) {
    for limb in 0..4 {
        fixture.0.packets.fields[SCALAR_DESTINATION][AFTER + limb] = constant_limb(value, limb);
    }
}

fn checked(instruction: u32, inputs: &[(usize, u64, bool)]) -> (Program, ScalarFixture) {
    let (program, fixture) = native(instruction, inputs);
    let p = &fixture.0.packets.fields;
    let left = packet::half(&p[SCALAR_LEFT], BEFORE, 0);
    let right = packet::half(&p[SCALAR_RIGHT], BEFORE, 0);
    assert_eq!(ivm::gas::cost_of(instruction), Some(3));
    assert_eq!(
        packet::half(&p[SCALAR_DESTINATION], AFTER, 0),
        if has_destination(instruction) {
            expected(wide::opcode(instruction), left, right)
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
        3
    );
    assert_eq!(
        packet::half(&p[PC_WRITE], AFTER, 0),
        packet::half(&p[PC_READ], BEFORE, 0) + 4
    );
    assert_eq!(
        packet::half(&p[CYCLE_WRITE], AFTER, 0),
        packet::half(&p[CYCLE_WRITE], BEFORE, 0) + 1
    );
    assert!(
        fixture.0.row
            [SCALAR + MULTIPLY + multiply::CARRY..SCALAR + MULTIPLY + multiply::CARRY_DIGITS]
            .iter()
            .all(|carry| carry.0 < 1 << 18)
    );
    (program, fixture)
}

#[test]
fn private_multiply_native_words_signs_tags_aliases_and_zero_match() {
    let pairs = [
        (0, 0),
        (0, u64::MAX),
        (1, u64::MAX),
        (u64::MAX, u64::MAX),
        (i64::cast_unsigned(i64::MIN), i64::cast_unsigned(i64::MIN)),
        (i64::MAX as u64, i64::MAX as u64),
        (i64::cast_unsigned(i64::MIN), u64::MAX),
        (u64::MAX, i64::cast_unsigned(i64::MIN)),
        (0xffff_ffff_0000_0001, 0x8000_ffff_0000_0001),
        (0x5555_5555_5555_5555, 0xaaaa_aaaa_aaaa_aaaa),
    ];
    for opcode in OPS {
        for (left, right) in pairs {
            for tag in [false, true] {
                for (rd, rs1, rs2) in [(4, 2, 3), (2, 2, 3), (3, 2, 3), (2, 2, 2), (0, 2, 3)] {
                    checked(
                        enc::encode_rr(opcode, rd, rs1, rs2),
                        &[(2, left, tag), (3, right, tag), (4, 91, !tag)],
                    );
                }
            }
            for (rd, rs1, rs2) in [(4, 0, 3), (4, 2, 0), (0, 0, 0)] {
                checked(
                    enc::encode_rr(opcode, rd, rs1, rs2),
                    &[(2, left, false), (3, right, false)],
                );
            }
        }
    }
    assert_ne!(
        expected(OPS[2], i64::cast_unsigned(i64::MIN), u64::MAX),
        expected(OPS[2], u64::MAX, i64::cast_unsigned(i64::MIN))
    );
}

#[test]
fn private_multiply_coherent_wrong_products_halves_and_sign_corrections_fail() {
    let (left, right) = (0xffff_ffff_ffff_fffd, 0x8000_0000_0000_0001);
    for (kind, opcode) in OPS.into_iter().enumerate() {
        let (program, fixture) = checked(
            enc::encode_rr(opcode, 4, 2, 3),
            &[(2, left, true), (3, right, true)],
        );
        let result = expected(opcode, left, right);
        for alternative in OPS {
            let value = expected(alternative, left, right);
            if value != result {
                let mut forged = fixture.clone();
                set_destination(&mut forged, value);
                assert!(!forged.accepts(&program));
            }
        }
        // Replace the entire product and corrections consistently, including
        // the final destination, while keeping the authentic original sources.
        let digits = multiply::product_digits(left ^ 1, right);
        let bank = multiply::witness(left, right, &digits, true);
        let false_result = multiply::result_half(&bank, kind, 0).0
            | (multiply::result_half(&bank, kind, 1).0 << 32);
        assert_ne!(false_result, result);
        let mut forged = fixture.clone();
        forged.0.row[SCALAR + PRODUCT_DIGITS..SCALAR + MULTIPLY].copy_from_slice(&digits);
        forged.0.row[SCALAR + MULTIPLY..SCALAR + COUNT].copy_from_slice(&bank);
        set_destination(&mut forged, false_result);
        assert!(!forged.accepts(&program));
        if kind >= 2 {
            let digits = multiply::product_digits(left, right);
            let unsigned = multiply::witness(left & !(1 << 63), right & !(1 << 63), &digits, true);
            let mut forged = fixture.clone();
            forged.0.row[SCALAR + MULTIPLY + multiply::SIGNED_UNSIGNED..SCALAR + COUNT]
                .copy_from_slice(&unsigned[multiply::SIGNED_UNSIGNED..]);
            let value = multiply::result_half(&unsigned, kind, 0).0
                | (multiply::result_half(&unsigned, kind, 1).0 << 32);
            assert_ne!(value, result);
            set_destination(&mut forged, value);
            assert!(!forged.accepts(&program));
        }
    }
}

#[test]
fn private_multiply_bounded_carries_and_false_original_sources_fail() {
    for opcode in OPS {
        let (program, fixture) = checked(
            enc::encode_rr(opcode, 4, 2, 3),
            &[(2, u64::MAX, true), (3, u64::MAX, true)],
        );
        for carry in 0..7 {
            let mut forged = fixture.clone();
            let offset = SCALAR + MULTIPLY + multiply::CARRY + carry;
            forged.0.row[offset] = forged.0.row[offset].add(F::ONE);
            let value = forged.0.row[offset].0;
            word::fill_digits(
                &mut forged.0.row[SCALAR + MULTIPLY + multiply::CARRY_DIGITS + 9 * carry
                    ..SCALAR + MULTIPLY + multiply::CARRY_DIGITS + 9 * (carry + 1)],
                value,
            );
            assert!(!forged.accepts(&program));
        }
        let mut forged = fixture.clone();
        let start = SCALAR + MULTIPLY + multiply::CARRY_DIGITS;
        forged.0.row[SCALAR + MULTIPLY + multiply::CARRY] = F(1 << 18);
        forged.0.row[start..start + 9].fill(F::ZERO);
        forged.0.row[start + 8] = F(4);
        assert!(!forged.accepts(&program));
        // Rebuild every arithmetic bank from false operands, retaining the
        // original register packets. This must fail source ownership itself.
        let (left, right) = (17, 23);
        let mut forged = fixture.clone();
        forged.0.row[SCALAR..SCALAR + ALU].copy_from_slice(&word::witness(left, right));
        forged.0.row[SCALAR + ALU..SCALAR + COMPARE].copy_from_slice(&alu::witness(
            wide::arithmetic::ADD,
            left,
            right,
        ));
        forged.0.row[SCALAR + COMPARE..SCALAR + PRODUCT_DIGITS]
            .copy_from_slice(&branch::bank_witness(0, left, right));
        fill_product(&mut forged.0, left, right);
        forged.0.row[SCALAR + SHIFT..super::super::super::WIDTH]
            .copy_from_slice(&shift::bank_witness(wide::arithmetic::SLL, left, right));
        set_destination(&mut forged, expected(opcode, left, right));
        assert!(!forged.accepts(&program));
    }
}

#[test]
fn private_multiply_exact_three_gas_and_unavailable_extended_arithmetic_are_bound() {
    for opcode in OPS {
        let (program, fixture) = checked(
            enc::encode_rr(opcode, 4, 2, 3),
            &[(2, 17, true), (3, 23, true)],
        );
        let before = packet::half(&fixture.0.packets.fields[GAS_DEBIT], BEFORE, 0);
        for cost in [0, 1, 2, 4] {
            let mut forged = fixture.clone();
            let after = before - cost;
            bits(&mut forged.0.row[WORDS + 128..WORDS + 192], after);
            carries(&mut forged.0.row[CARRIES..CARRIES + 4], before, cost, true);
            for limb in 0..4 {
                forged.0.packets.fields[GAS_DEBIT][AFTER + limb] = constant_limb(after, limb);
            }
            assert!(!forged.accepts(&program));
        }
    }
    assert!(is_supported(enc::encode_rr(
        wide::arithmetic::DIV_CEIL,
        4,
        2,
        3
    )));
    assert!(is_supported(enc::encode_rr(wide::arithmetic::GCD, 4, 2, 3)));
    // Vector arithmetic still needs its original vector-state relation.
    assert!(!is_supported(enc::encode_rr(wide::crypto::VADD64, 4, 2, 3)));
}
