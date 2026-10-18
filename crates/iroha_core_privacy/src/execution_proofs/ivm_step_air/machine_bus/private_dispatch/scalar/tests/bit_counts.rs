//! Original private bit-count operands, tags, exact tariffs and prefix forgeries.

use super::*;

const OPS: [u8; 3] = [
    wide::arithmetic::POPCNT,
    wide::arithmetic::CLZ,
    wide::arithmetic::CTZ,
];

fn expected(opcode: u8, value: u64) -> u64 {
    u64::from(match opcode {
        wide::arithmetic::POPCNT => value.count_ones(),
        wide::arithmetic::CLZ => value.leading_zeros(),
        wide::arithmetic::CTZ => value.trailing_zeros(),
        _ => panic!("bit-count fixture opcode"),
    })
}

fn checked(instruction: u32, inputs: &[(usize, u64, bool)]) -> (Program, ScalarFixture) {
    let (program, fixture) = native(instruction, inputs);
    let p = &fixture.0.packets.fields;
    let value = packet::half(&p[SCALAR_LEFT], BEFORE, 0);
    assert_eq!(ivm::gas::cost_of(instruction), Some(6));
    assert_eq!(
        packet::half(&p[SCALAR_DESTINATION], AFTER, 0),
        if has_destination(instruction) {
            expected(wide::opcode(instruction), value)
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
    assert!(p[SCALAR_RIGHT].iter().all(|v| *v == F::ZERO));
    assert_eq!(
        packet::half(&p[GAS_DEBIT], BEFORE, 0) - packet::half(&p[GAS_DEBIT], AFTER, 0),
        6
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

fn set_result(fixture: &mut ScalarFixture, value: u64) {
    for limb in 0..4 {
        fixture.0.packets.fields[SCALAR_DESTINATION][AFTER + limb] = constant_limb(value, limb);
    }
}

#[test]
fn private_bit_counts_match_native_every_bit_zero_tags_aliases_and_r0() {
    for opcode in OPS {
        for value in [0, u64::MAX, 0xffff_ffff_0000_0001]
            .into_iter()
            .chain((0..64).flat_map(|bit| [1_u64 << bit, !(1_u64 << bit)]))
        {
            for tag in [false, true] {
                for rd in [0, 2, 4] {
                    checked(
                        enc::encode_rr(opcode, rd, 2, 255),
                        &[(2, value, tag), (4, 91, !tag), (255, 17, !tag)],
                    );
                }
            }
        }
        for rd in [0, 4] {
            checked(
                enc::encode_rr(opcode, rd, 0, 255),
                &[(4, 99, true), (255, 1, true)],
            );
        }
    }
}

#[test]
fn private_bit_counts_ignore_all_encoded_rs2_bytes_but_keep_original_source_tag() {
    for opcode in OPS {
        for raw in 0..=u8::MAX {
            checked(
                enc::encode_rr(opcode, 4, 2, raw),
                &[(2, 0x8000_1234_0000_0000, true), (255, 17, false)],
            );
        }
        let instruction = enc::encode_rr(opcode, 4, 2, 255);
        let (program, fixture) = checked(instruction, &[(2, 16, true), (255, 0, false)]);
        let (_, changed_unused) = checked(instruction, &[(2, 16, true), (255, u64::MAX, true)]);
        assert_eq!(fixture.0.row, changed_unused.0.row);
        assert_eq!(fixture.0.packets.fields, changed_unused.0.packets.fields);
        let mut wrong_tag = fixture.clone();
        wrong_tag.0.packets.fields[SCALAR_DESTINATION][AFTER_TAG] = F::ZERO;
        assert!(!wrong_tag.accepts(&program));
        let mut extra = fixture.clone();
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
    }
}

#[test]
fn private_bit_count_coherent_wrong_prefix_direction_source_and_result_reject() {
    let value = 0x0000_1234_0000_0000;
    for opcode in OPS {
        let instruction = enc::encode_rr(opcode, 4, 2, 255);
        let (program, fixture) = checked(instruction, &[(2, value, true)]);
        for i in 0..64 {
            let mut changed = fixture.clone();
            changed.0.row[SCALAR + COUNT + i] = changed.0.row[SCALAR + COUNT + i].add(F::ONE);
            set_result(&mut changed, expected(opcode, value) + 1);
            assert!(!changed.accepts(&program));
        }
        for replacement in OPS {
            if expected(replacement, value) != expected(opcode, value) {
                let mut changed = fixture.clone();
                fill_count(&mut changed.0, value, replacement == wide::arithmetic::CLZ);
                set_result(&mut changed, expected(replacement, value));
                assert!(!changed.accepts(&program));
            }
        }
        let (_, wrong_source) = checked(instruction, &[(2, value ^ 1, true)]);
        let mut changed = fixture.clone();
        changed.0.row[SCALAR..].copy_from_slice(&wrong_source.0.row[SCALAR..]);
        changed.0.packets.fields[SCALAR_DESTINATION][AFTER..AFTER + 4]
            .copy_from_slice(&wrong_source.0.packets.fields[SCALAR_DESTINATION][AFTER..AFTER + 4]);
        assert!(!changed.accepts(&program));
        for limb in 1..4 {
            let mut changed = fixture.clone();
            changed.0.packets.fields[SCALAR_DESTINATION][AFTER + limb] = F::ONE;
            assert!(!changed.accepts(&program));
        }
    }
}

#[test]
fn private_bit_count_six_gas_one_cycle_and_unconditional_prefixes_are_bound() {
    for opcode in OPS {
        let (program, fixture) = checked(enc::encode_rr(opcode, 4, 2, 255), &[(2, 17, true)]);
        let before = packet::half(&fixture.0.packets.fields[GAS_DEBIT], BEFORE, 0);
        for cost in [0, 1, 3, 5, 7] {
            let mut changed = fixture.clone();
            let after = before - cost;
            bits(&mut changed.0.row[WORDS + 128..WORDS + 192], after);
            carries(&mut changed.0.row[CARRIES..CARRIES + 4], before, cost, true);
            for limb in 0..4 {
                changed.0.packets.fields[GAS_DEBIT][AFTER + limb] = constant_limb(after, limb);
            }
            assert!(!changed.accepts(&program));
        }
        let mut changed = fixture.clone();
        let before = packet::half(&changed.0.packets.fields[CYCLE_WRITE], BEFORE, 0);
        bits(&mut changed.0.row[WORDS + 256..WORDS + 320], before + 6);
        carries(
            &mut changed.0.row[CARRIES + 4..CARRIES + 8],
            before,
            6,
            false,
        );
        for limb in 0..4 {
            changed.0.packets.fields[CYCLE_WRITE][AFTER + limb] = constant_limb(before + 6, limb);
        }
        assert!(!changed.accepts(&program));
    }
    let (program, fixture) = native(
        enc::encode_rr(wide::arithmetic::ADD, 4, 2, 3),
        &[(2, 16, true), (3, 19, true)],
    );
    let padding = ScalarFixture(Fixture::padding());
    assert!(padding.accepts(&program));
    for original in [&fixture, &padding] {
        for i in 0..64 {
            let mut changed = original.clone();
            changed.0.row[SCALAR + COUNT + i] = changed.0.row[SCALAR + COUNT + i].add(F::ONE);
            assert!(!changed.accepts(&program));
        }
    }
}
