//! Native division, original public operands, exact quotient and remainder bounds.

use super::*;

const OPS: [u8; 4] = [
    wide::arithmetic::DIV,
    wide::arithmetic::DIVU,
    wide::arithmetic::REM,
    wide::arithmetic::REMU,
];

fn expected(kind: usize, left: u64, right: u64) -> Option<u64> {
    match kind {
        0 => u64::cast_signed(left)
            .checked_div(u64::cast_signed(right))
            .map(|value| i64::cast_unsigned(value)),
        1 => left.checked_div(right),
        2 => u64::cast_signed(left)
            .checked_rem(u64::cast_signed(right))
            .map(|value| i64::cast_unsigned(value)),
        3 => left.checked_rem(right),
        _ => panic!("division fixture opcode"),
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
    let result = expected(division_kind(instruction).unwrap(), left, right).unwrap();
    assert_eq!(ivm::gas::cost_of(instruction), Some(10));
    assert_eq!(
        packet::half(&p[SCALAR_DESTINATION], AFTER, 0),
        if has_destination(instruction) {
            result
        } else {
            0
        }
    );
    assert_eq!(p[SCALAR_DESTINATION][AFTER_TAG], F::ZERO);
    assert_eq!(p[SCALAR_LEFT][BEFORE_TAG], F::ZERO);
    assert_eq!(p[SCALAR_RIGHT][BEFORE_TAG], F::ZERO);
    assert_eq!(
        packet::half(&p[GAS_DEBIT], BEFORE, 0) - packet::half(&p[GAS_DEBIT], AFTER, 0),
        10
    );
    assert_eq!(
        packet::half(&p[PC_WRITE], AFTER, 0),
        packet::half(&p[PC_READ], BEFORE, 0) + 4
    );
    assert_eq!(
        packet::half(&p[CYCLE_WRITE], AFTER, 0),
        packet::half(&p[CYCLE_WRITE], BEFORE, 0) + 1
    );
    assert_eq!(
        fixture.0.row[SCALAR + SHIFT + division::LOCAL_TRAP],
        F::ZERO
    );
    (program, fixture)
}

#[test]
fn private_division_native_full_words_signs_aliases_and_r0_match() {
    let pairs = [
        (0, 1),
        (0, u64::MAX),
        (1, 1),
        (1, u64::MAX),
        (u64::MAX, 1),
        (u64::MAX, u64::MAX),
        (i64::cast_unsigned(i64::MIN), 1),
        (i64::cast_unsigned(i64::MIN), 2),
        (i64::cast_unsigned(i64::MIN), u64::MAX),
        (i64::cast_unsigned(i64::MIN), i64::cast_unsigned(i64::MIN)),
        (i64::MAX as u64, i64::cast_unsigned(i64::MIN)),
        (17, 3),
        (17, i64::cast_unsigned(-3i64)),
        (i64::cast_unsigned(-17i64), 3),
        (i64::cast_unsigned(-17i64), i64::cast_unsigned(-3i64)),
        (0xffff_ffff_0000_0001, 0x8000_ffff_0000_0001),
    ];
    for (kind, opcode) in OPS.into_iter().enumerate() {
        for (left, right) in pairs {
            if expected(kind, left, right).is_none() {
                continue;
            }
            for rd in [0, 2, 3, 4] {
                checked(
                    enc::encode_rr(opcode, rd, 2, 3),
                    &[(2, left, false), (3, right, false), (4, 91, true)],
                );
            }
            checked(
                enc::encode_rr(opcode, 4, 0, 3),
                &[(3, right, false), (4, 91, true)],
            );
            if left != 0 {
                checked(enc::encode_rr(opcode, 2, 2, 2), &[(2, left, false)]);
            }
        }
        for bit in 0..64 {
            let right = 1u64 << bit;
            checked(
                enc::encode_rr(opcode, 4, 2, 3),
                &[(2, 0xfedc_ba98_7654_3210, false), (3, right, false)],
            );
        }
    }
}

#[test]
fn private_division_coherent_false_quotients_remainders_and_signs_reject() {
    for (kind, opcode) in OPS.into_iter().enumerate() {
        let (left, right) = if division::signed_kind(kind) {
            (i64::cast_unsigned(-17i64), 3)
        } else {
            (17, 3)
        };
        let (program, fixture) = checked(
            enc::encode_rr(opcode, 4, 2, 3),
            &[(2, left, false), (3, right, false)],
        );
        let actual = expected(kind, left, right).unwrap();
        for value in [
            actual.wrapping_add(1),
            expected(kind ^ 2, left, right).unwrap(),
            actual.wrapping_neg(),
        ] {
            if value == actual {
                continue;
            }
            let mut forged = fixture.clone();
            set_destination(&mut forged, value);
            assert!(!forged.accepts(&program));
        }
        // A complete arithmetic bank from another dividend cannot be joined
        // to the original public register packets, even with its matching result.
        let mut forged = fixture.clone();
        let gas = packet::half(&fixture.0.packets.fields[GAS_DEBIT], BEFORE, 0);
        fill_division(&mut forged.0, left.wrapping_add(1), right, gas, kind);
        set_destination(
            &mut forged,
            expected(kind, left.wrapping_add(1), right).unwrap(),
        );
        assert!(!forged.accepts(&program));
        // Reinterpret both signed magnitudes/results as unsigned, consistently.
        if division::signed_kind(kind) {
            let mut forged = fixture.clone();
            fill_division(&mut forged.0, left, right, gas, kind + 1);
            set_destination(&mut forged, expected(kind + 1, left, right).unwrap());
            assert!(!forged.accepts(&program));
        }
        for offset in [
            division::QUOTIENT,
            division::REMAINDER,
            division::QUOTIENT_NEGATIVE,
            division::REMAINDER_NEGATIVE,
            division::SUM_CARRIES,
            division::SUM_CARRIES + 7,
            division::ZERO_DENOMINATOR,
            division::ZERO_INVERSE,
            division::OVERFLOW,
            division::OVERFLOW_INVERSE,
            division::ARITHMETIC_ERROR,
            division::LOCAL_TRAP,
        ] {
            let mut forged = fixture.clone();
            forged.0.row[SCALAR + SHIFT + offset] =
                forged.0.row[SCALAR + SHIFT + offset].add(F::ONE);
            assert!(!forged.accepts(&program), "kind{kind} offset{offset}");
        }
    }
}

#[test]
fn private_division_noncanonical_remainder_with_same_integer_sum_rejects() {
    // 17 = 3*5+2 = 3*4+5. Only the first quotient/remainder is canonical.
    // Rebuild every affected product, result, carry and comparison cell, so
    // the strict remainder bound alone must reject the alternative identity.
    for opcode in OPS {
        let (program, mut forged) = checked(
            enc::encode_rr(opcode, 4, 2, 3),
            &[(2, 17, false), (3, 3, false)],
        );
        let digits = multiply::product_digits(3, 4);
        let product = multiply::witness(3, 4, &digits, true);
        forged.0.row[SCALAR + PRODUCT_DIGITS..SCALAR + MULTIPLY].copy_from_slice(&digits);
        forged.0.row[SCALAR + MULTIPLY..SCALAR + MULTIPLY + multiply::SIGNED_UNSIGNED]
            .copy_from_slice(&product[..multiply::SIGNED_UNSIGNED]);
        for (offset, borrows, value) in [
            (division::QUOTIENT, division::QUOTIENT_BORROWS, 4),
            (division::REMAINDER, division::REMAINDER_BORROWS, 5),
        ] {
            let result = if offset == division::QUOTIENT {
                division::QUOTIENT_RESULT
            } else {
                division::REMAINDER_RESULT
            };
            let correction = multiply::correction_witness(value, 0);
            forged.0.row[SCALAR + SHIFT + offset..SCALAR + SHIFT + offset + 36]
                .copy_from_slice(&correction[..36]);
            forged.0.row[SCALAR + SHIFT + result..SCALAR + SHIFT + result + 36]
                .copy_from_slice(&correction[..36]);
            forged.0.row[SCALAR + SHIFT + borrows..SCALAR + SHIFT + borrows + 4]
                .copy_from_slice(&correction[36..]);
        }
        forged.0.row[SCALAR + COMPARE..SCALAR + PRODUCT_DIGITS]
            .copy_from_slice(&branch::bank_witness(0, 5, 3));
        set_destination(
            &mut forged,
            if division_kind(enc::encode_rr(opcode, 4, 2, 3)).unwrap() < 2 {
                4
            } else {
                5
            },
        );
        assert_eq!(forged.0.row[SCALAR + COMPARE + branch::BORROW + 3], F::ZERO);
        let mut residues = Vec::new();
        super::super::super::append_residues(
            &mut residues,
            &program,
            forged.0.schedule,
            &forged.0.row,
            &forged.0.packets,
        );
        let failures = residues
            .into_iter()
            .filter(|value| *value != F::ZERO)
            .collect::<Vec<_>>();
        assert_eq!(failures, vec![F::ZERO.sub(F::ONE)]);
    }
}

#[test]
fn private_division_exact_gas_source_history_and_canonical_padding_are_bound() {
    for opcode in OPS {
        let (program, fixture) = checked(
            enc::encode_rr(opcode, 4, 2, 3),
            &[(2, 17, false), (3, 3, false)],
        );
        let before = packet::half(&fixture.0.packets.fields[GAS_DEBIT], BEFORE, 0);
        for cost in [0, 1, 9, 11] {
            let mut forged = fixture.clone();
            let after = before - cost;
            bits(&mut forged.0.row[WORDS + 128..WORDS + 192], after);
            carries(&mut forged.0.row[CARRIES..CARRIES + 4], before, cost, true);
            for limb in 0..4 {
                forged.0.packets.fields[GAS_DEBIT][AFTER + limb] = constant_limb(after, limb);
            }
            assert!(!forged.accepts(&program));
        }
        for slot in [SCALAR_LEFT, SCALAR_RIGHT, SCALAR_DESTINATION] {
            let mut omitted = fixture.clone();
            omitted.0.packets.fields[slot].fill(F::ZERO);
            assert!(!omitted.accepts(&program));
            let mut changed = fixture.clone();
            changed.0.packets.fields[slot][AFTER] = F(29);
            if slot != SCALAR_DESTINATION {
                changed.0.packets.fields[slot][BEFORE] = F(29);
            }
            assert!(!changed.accepts(&program));
        }
        assert!(Fixture::padding().accepts(&program));
    }
}

#[test]
fn private_division_native_private_operands_refuse_even_matching_tags_and_rd0() {
    for opcode in OPS {
        for tags in [[true, false], [false, true], [true, true]] {
            for rd in [0, 4] {
                let instruction = enc::encode_rr(opcode, rd, 2, 3);
                let artifact = contract(&[instruction], 1_000, ivm::ivm_mode::ZK);
                let mut vm = IVM::new(100);
                vm.load_prepared(&artifact).unwrap();
                for (register, value, tag) in [(2, 17, tags[0]), (3, 3, tags[1])] {
                    vm.set_register(register, value);
                    vm.registers.set_tag(register, tag);
                }
                let budget = AllocationBudget::new(8 * std::mem::size_of::<DiagnosticStepRecord>());
                let mut recorder = DiagnosticStepRecorder::try_new(8, &budget).unwrap();
                assert!(matches!(
                    vm.run_with_host_diagnostic_steps(&mut DefaultHost::default(), &mut recorder),
                    Err(ivm::VMError::PrivacyViolation)
                ));
                let record = &recorder.records()[0];
                assert!(matches!(record.outcome, DiagnosticStepOutcome::Trapped(_)));
                assert_eq!(record.before.registers, record.after.registers);
                assert_eq!(record.before.tags, record.after.tags);
                assert_eq!(record.before.pc, record.after.pc);
                assert_eq!(record.before.cycles, record.after.cycles);
                assert_eq!(record.before.gas_remaining, record.after.gas_remaining + 10);
                let (program, mut forged) = checked(instruction, &[(2, 17, false), (3, 3, false)]);
                for (slot, tag) in [SCALAR_LEFT, SCALAR_RIGHT].into_iter().zip(tags) {
                    forged.0.packets.fields[slot][BEFORE_TAG] = F(u64::from(tag));
                    forged.0.packets.fields[slot][AFTER_TAG] = F(u64::from(tag));
                }
                assert!(!forged.accepts(&program));
            }
        }
    }
}

#[test]
fn private_division_native_arithmetic_and_gas_traps_cannot_claim_completion() {
    for (kind, opcode) in OPS.into_iter().enumerate() {
        for (left, right) in [(17, 0), (i64::cast_unsigned(i64::MIN), u64::MAX), (17, 3)] {
            for opcode_gas in [0, 9, 10] {
                let arithmetic = expected(kind, left, right).is_none();
                if opcode_gas == 10 && !arithmetic {
                    continue;
                }
                let instruction = enc::encode_rr(opcode, 4, 2, 3);
                let artifact = contract(&[instruction], 1_000, ivm::ivm_mode::ZK);
                let mut vm = IVM::new(root_setup_gas() + opcode_gas);
                vm.load_prepared(&artifact).unwrap();
                vm.set_register(2, left);
                vm.set_register(3, right);
                vm.set_register(4, 29);
                let budget = AllocationBudget::new(8 * std::mem::size_of::<DiagnosticStepRecord>());
                let mut recorder = DiagnosticStepRecorder::try_new(8, &budget).unwrap();
                let outcome =
                    vm.run_with_host_diagnostic_steps(&mut DefaultHost::default(), &mut recorder);
                if opcode_gas < 10 {
                    assert!(matches!(outcome, Err(ivm::VMError::OutOfGas)));
                } else {
                    assert!(matches!(outcome, Err(ivm::VMError::AssertionFailed)));
                }
                let record = &recorder.records()[0];
                assert!(matches!(record.outcome, DiagnosticStepOutcome::Trapped(_)));
                assert_eq!(record.before.registers, record.after.registers);
                assert_eq!(record.before.tags, record.after.tags);
                assert_eq!(record.before.pc, record.after.pc);
                assert_eq!(record.before.cycles, record.after.cycles);
                assert_eq!(
                    record.after.gas_remaining,
                    if opcode_gas < 10 { opcode_gas } else { 0 }
                );
                // Attempt a fully rebuilt completed row for those trapped inputs.
                let (program, mut forged) = checked(instruction, &[(2, 17, false), (3, 3, false)]);
                for (slot, value) in [(SCALAR_LEFT, left), (SCALAR_RIGHT, right)] {
                    for limb in 0..4 {
                        forged.0.packets.fields[slot][BEFORE + limb] = constant_limb(value, limb);
                        forged.0.packets.fields[slot][AFTER + limb] = constant_limb(value, limb);
                    }
                }
                forged.0.row[SCALAR..SCALAR + ALU].copy_from_slice(&word::witness(left, right));
                forged.0.row[SCALAR + ALU..SCALAR + COMPARE].copy_from_slice(&alu::witness(
                    wide::arithmetic::ADD,
                    left,
                    right,
                ));
                fill_count(&mut forged.0, left, false);
                fill_division(&mut forged.0, left, right, opcode_gas, kind);
                set_destination(&mut forged, 0);
                bits(&mut forged.0.row[WORDS + 64..WORDS + 128], opcode_gas);
                let after = opcode_gas.wrapping_sub(10);
                bits(&mut forged.0.row[WORDS + 128..WORDS + 192], after);
                carries(
                    &mut forged.0.row[CARRIES..CARRIES + 4],
                    opcode_gas,
                    10,
                    true,
                );
                for limb in 0..4 {
                    forged.0.packets.fields[GAS_DEBIT][BEFORE + limb] =
                        constant_limb(opcode_gas, limb);
                    forged.0.packets.fields[GAS_DEBIT][AFTER + limb] = constant_limb(after, limb);
                }
                assert!(!forged.accepts(&program));
            }
        }
    }
}
