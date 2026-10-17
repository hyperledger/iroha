//! Native conditional reads/writes, public condition policy and coherent forgeries.

use super::*;

fn checked(instruction: u32, inputs: &[(usize, u64, bool)]) -> (Program, ScalarFixture) {
    let (program, fixture) = native(instruction, inputs);
    let p = &fixture.0.packets.fields;
    let condition = packet::half(&p[SCALAR_LEFT], BEFORE, 0);
    let taken = condition != 0;
    assert_eq!(p[SCALAR_LEFT][BEFORE_TAG], F::ZERO);
    let register_move = wide::opcode(instruction) == wide::arithmetic::CMOV;
    assert_eq!(
        p[SCALAR_RIGHT][ENABLED],
        F(u64::from(register_move && taken))
    );
    let destination = taken && wide::rd(instruction) != 0;
    assert_eq!(p[SCALAR_DESTINATION][ENABLED], F(u64::from(destination)));
    assert_eq!(p[SCALAR_DESTINATION][WRITE], F(u64::from(destination)));
    if !taken {
        assert!(
            p[SCALAR_RIGHT]
                .iter()
                .chain(p[SCALAR_DESTINATION].iter())
                .all(|x| *x == F::ZERO)
        );
    }
    let value = if register_move {
        packet::half(&p[SCALAR_RIGHT], BEFORE, 0)
    } else {
        i64::cast_unsigned(i64::from(wide::imm8(instruction)))
    };
    assert_eq!(
        packet::half(&p[SCALAR_DESTINATION], AFTER, 0),
        if destination { value } else { 0 }
    );
    assert_eq!(
        p[SCALAR_DESTINATION][AFTER_TAG],
        if destination && register_move {
            p[SCALAR_RIGHT][BEFORE_TAG]
        } else {
            F::ZERO
        }
    );
    assert_eq!(ivm::gas::cost_of(instruction), Some(3));
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
    (program, fixture)
}

#[test]
fn native_conditional_moves_bind_all_condition_bits_values_tags_aliases_and_r0() {
    let mut conditions = vec![0, u64::MAX, 0xffff_ffff_0000_0001];
    conditions.extend((0..64).map(|bit| 1u64 << bit));
    for condition in conditions {
        for tag in [false, true] {
            for rd in [0, 2, 3, 4] {
                checked(
                    enc::encode_rr(wide::arithmetic::CMOV, rd, 2, 3),
                    &[
                        (2, 0x8123_4567_89ab_cdef, tag),
                        (3, condition, false),
                        (4, 27, !tag),
                    ],
                );
            }
        }
    }
    for (rd, src, cond) in [
        (4, 2, 2),
        (2, 2, 2),
        (4, 0, 3),
        (4, 2, 0),
        (4, 0, 0),
        (0, 0, 0),
    ] {
        checked(
            enc::encode_rr(wide::arithmetic::CMOV, rd, src, cond),
            &[(2, u64::MAX, false), (3, 1, false), (4, 19, true)],
        );
    }
}

#[test]
fn native_conditional_immediates_cover_all_signed_bytes_and_preserve_untaken_destination() {
    for raw in 0..=u8::MAX {
        for condition in [0, 1, 0xffff_ffff_0000_0001] {
            for rd in [0, 2, 4] {
                checked(
                    enc::encode_ri(wide::arithmetic::CMOVI, rd, 2, u8::cast_signed(raw)),
                    &[
                        (2, condition, false),
                        (4, 0x8000_ffff_0000_0001, true),
                        (255, 17, true),
                    ],
                );
            }
        }
    }
    checked(
        enc::encode_ri(wide::arithmetic::CMOVI, 4, 0, -1),
        &[(4, 29, true)],
    );
}

#[test]
fn conditional_moves_do_not_read_unused_source_or_destination_and_reject_invented_effects() {
    let instruction = enc::encode_rr(wide::arithmetic::CMOV, 4, 2, 3);
    let (program, first) = checked(instruction, &[(2, 0, false), (3, 0, false), (4, 19, false)]);
    let (_, second) = checked(
        instruction,
        &[(2, u64::MAX, true), (3, 0, false), (4, 99, true)],
    );
    assert_eq!(first.0.row, second.0.row);
    assert_eq!(first.0.packets.fields, second.0.packets.fields);
    let (_, taken) = checked(
        instruction,
        &[(2, u64::MAX, true), (3, 1, false), (4, 99, true)],
    );
    for slot in [SCALAR_RIGHT, SCALAR_DESTINATION] {
        let mut extra = first.clone();
        extra.0.packets.fields[slot] = taken.0.packets.fields[slot];
        assert!(!extra.accepts(&program));
        let mut omitted = taken.clone();
        omitted.0.packets.fields[slot].fill(F::ZERO);
        assert!(!omitted.accepts(&program));
    }
    for (offset, replacement) in [(MOVE_ZERO, F::ONE), (MOVE_INVERSE, F::ZERO)] {
        let mut changed = taken.clone();
        changed.0.row[SCALAR + offset] = replacement;
        assert!(!changed.accepts(&program));
    }
    // A coherent zero-test for the field-reduced word cannot replace the
    // original full 64-bit condition or suppress its actual private effects.
    let (_, mut modular) = checked(
        instruction,
        &[
            (2, 17, true),
            (3, 0xffff_ffff_0000_0001, false),
            (4, 19, false),
        ],
    );
    modular.0.row[SCALAR + MOVE_ZERO] = F::ONE;
    modular.0.row[SCALAR + MOVE_INVERSE] = F::ZERO;
    modular.0.packets.fields[SCALAR_RIGHT].fill(F::ZERO);
    modular.0.packets.fields[SCALAR_DESTINATION].fill(F::ZERO);
    assert!(!modular.accepts(&program));
    let mut altered = taken.clone();
    altered.0.packets.fields[SCALAR_DESTINATION][AFTER_TAG] = F::ZERO;
    assert!(!altered.accepts(&program));
    let mut altered = taken.clone();
    altered.0.packets.fields[SCALAR_DESTINATION][AFTER] = F(18);
    assert!(!altered.accepts(&program));
}

#[test]
fn conditional_moves_native_private_condition_refuses_even_false_and_rd0() {
    for immediate in [false, true] {
        for condition in [0, 1, u64::MAX] {
            for rd in [0, 4] {
                let instruction = if immediate {
                    enc::encode_ri(wide::arithmetic::CMOVI, rd, 3, -1)
                } else {
                    enc::encode_rr(wide::arithmetic::CMOV, rd, 2, 3)
                };
                let artifact = contract(&[instruction], 1_000, ivm::ivm_mode::ZK);
                let mut vm = IVM::new(100);
                vm.load_prepared(&artifact).unwrap();
                vm.set_register(2, 17);
                vm.set_register(3, condition);
                vm.registers.set_tag(3, true);
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
                assert_eq!(record.before.cycles, record.after.cycles);
                assert_eq!(record.before.pc, record.after.pc);
                assert_eq!(record.before.gas_remaining, record.after.gas_remaining + 3);
                let (program, mut changed) =
                    checked(instruction, &[(2, 17, true), (3, condition, false)]);
                changed.0.packets.fields[SCALAR_LEFT][BEFORE_TAG] = F::ONE;
                changed.0.packets.fields[SCALAR_LEFT][AFTER_TAG] = F::ONE;
                assert!(!changed.accepts(&program));
            }
        }
    }
}

#[test]
fn conditional_move_zero_test_is_canonical_on_unused_and_padding_rows() {
    let (program, fixture) = native(
        enc::encode_rr(wide::arithmetic::ADD, 4, 2, 3),
        &[(2, 17, false), (3, 19, false)],
    );
    let padding = ScalarFixture(Fixture::padding());
    assert!(padding.accepts(&program));
    for original in [&fixture, &padding] {
        for offset in [MOVE_ZERO, MOVE_INVERSE] {
            let mut changed = original.clone();
            changed.0.row[SCALAR + offset] = changed.0.row[SCALAR + offset].add(F::ONE);
            assert!(!changed.accepts(&program));
        }
    }
}
