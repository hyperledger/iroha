//! Canonical zero-safe inverse semantics, exact call geometry and scoped costs.

use super::*;
use crate::privacy_engines::transparent_stark::GOLDILOCKS_MODULUS_V1;

fn checked_reference(gate: F, denominator: F) -> (F, F) {
    if gate == F::ZERO {
        (F::ZERO, F::ZERO)
    } else if denominator == F::ZERO {
        (F::ONE, F::ZERO)
    } else {
        (
            F::ZERO,
            denominator
                .inv()
                .expect("nonzero canonical Goldilocks value is invertible"),
        )
    }
}

fn integer_inverse(value: u64) -> u64 {
    let modulus = u128::from(GOLDILOCKS_MODULUS_V1);
    let mut exponent = GOLDILOCKS_MODULUS_V1 - 2;
    let mut power = u128::from(value);
    let mut result = 1_u128;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = result * power % modulus;
        }
        power = power * power % modulus;
        exponent >>= 1;
    }
    result as u64
}

#[test]
fn zero_safe_fixed_work_matches_integer_arithmetic_for_every_gate_class() {
    let gates = [
        0,
        1,
        2,
        255,
        GOLDILOCKS_MODULUS_V1 - 1,
        GOLDILOCKS_MODULUS_V1,
        u64::MAX,
    ];
    let mut words = vec![0, 1, 2, 255, 256, 65535, 65536, GOLDILOCKS_MODULUS_V1 - 1];
    let mut random = 0x689f_123c_a755_7291_u64;
    for _ in 0..256 {
        random = random
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        words.push(random % GOLDILOCKS_MODULUS_V1);
    }
    for gate in gates {
        for &denominator in &words {
            let expected = if gate == 0 {
                (F::ZERO, F::ZERO)
            } else if denominator == 0 {
                (F::ONE, F::ZERO)
            } else {
                (F::ZERO, F(integer_inverse(denominator)))
            };
            assert_eq!(zero_safe_inverse_v1(F(gate), F(denominator)), expected);
            assert_eq!(checked_reference(F(gate), F(denominator)), expected);
        }
    }
}

#[test]
fn zero_safe_fixed_work_preserves_invalid_active_and_ignored_inactive_inputs() {
    for denominator in [GOLDILOCKS_MODULUS_V1, GOLDILOCKS_MODULUS_V1 + 1, u64::MAX] {
        assert_eq!(
            zero_safe_inverse_v1(F::ZERO, F(denominator)),
            (F::ZERO, F::ZERO)
        );
        assert_eq!(
            checked_reference(F::ZERO, F(denominator)),
            (F::ZERO, F::ZERO)
        );
        for gate in [1, 2, GOLDILOCKS_MODULUS_V1 - 1, u64::MAX] {
            assert!(
                std::panic::catch_unwind(|| checked_reference(F(gate), F(denominator))).is_err()
            );
            assert!(
                std::panic::catch_unwind(|| zero_safe_inverse_v1(F(gate), F(denominator))).is_err()
            );
        }
    }
}

#[test]
fn zero_safe_fixed_work_full_registered_call_budget_is_explicit() {
    let mut by_kind = [0_usize; 4];
    for column in 0..ZK_X509_RFC5280_STARK_AUX_WIDTH_V1 {
        if (AUX_NUMERIC_INVERSE..AUX_NUMERIC_ZERO_SUM + numeric::LOOKUP_LANES_V1).contains(&column)
        {
            by_kind[0] += 1;
        } else if profile_lookup_aux_column_descriptor_v1(column).is_some() {
            by_kind[1] += 3;
        } else if lookup_aux_column_descriptor_v1(column).is_some() {
            by_kind[2] += 2;
        } else if grammar_lookup_aux_column_descriptor_v1(column).is_some() {
            by_kind[3] += 2;
        }
    }
    assert_eq!(by_kind, [16, 96, 96, 96]);
    assert_eq!(by_kind.iter().sum::<usize>(), 304);
    let full_calls = by_kind.iter().sum::<usize>() * ZK_X509_RFC5280_STARK_TRACE_SIZE_V1;
    assert_eq!(full_calls, 159_383_552);
    // Each valid call executes the existing chain, including inactive rows.
    assert_eq!(
        u64::try_from(full_calls).unwrap() * (64 + 10),
        11_794_382_848
    );
}

#[test]
#[ignore = "scoped interleaved per-gate inverse costs; full replay/proof qualification is separate"]
fn zero_safe_fixed_work_interleaved_per_gate_costs() {
    use std::hint::black_box;
    const CALLS: usize = 1 << 16;
    println!(
        "zero_safe_fixed_header calls={CALLS} cases=6 rounds=3 expected_records=36 full_replay_calls=159383552 fixed_chain_field_multiplications_per_call=74 whole_replay_timing=false"
    );
    let mut records = 0;
    for case in 0..6 {
        for round in 0..3 {
            let mut checksums = [(F::ZERO, F::ZERO); 2];
            for fixed in if round % 2 == 0 {
                [false, true]
            } else {
                [true, false]
            } {
                let mut checksum = (F::ZERO, F::ZERO);
                let started = std::time::Instant::now();
                for index in 0..CALLS {
                    let denominator = F(17 + (index % 65521) as u64);
                    let (gate, denominator) = match case {
                        0 => (F::ZERO, F::ZERO),
                        1 => (F::ZERO, denominator),
                        2 => (F::ONE, F::ZERO),
                        3 => (F::ONE, denominator),
                        4 => (F(2), denominator),
                        _ => (F(u64::from(index % 16 == 0)), denominator),
                    };
                    let (gate, denominator) = black_box((gate, denominator));
                    let result = if fixed {
                        zero_safe_inverse_v1(gate, denominator)
                    } else {
                        checked_reference(gate, denominator)
                    };
                    let result = black_box(result);
                    checksum.0 = checksum.0.add(result.0);
                    checksum.1 = checksum.1.add(result.1);
                }
                let elapsed_ns = started.elapsed().as_nanos();
                checksums[usize::from(fixed)] = black_box(checksum);
                println!(
                    "zero_safe_fixed_cost case={case} round={round} fixed={fixed} calls={CALLS} elapsed_ns={elapsed_ns}"
                );
                records += 1;
            }
            assert_eq!(checksums[0], checksums[1]);
        }
    }
    assert_eq!(records, 36);
}
