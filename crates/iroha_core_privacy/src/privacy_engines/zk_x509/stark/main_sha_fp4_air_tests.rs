//! Complete SHA registration Fp4 arithmetic, degree and public-context checks.

use super::super::super::{
    sha_call_bus_stark::ZkX509ShaCallBusLaneChallengesV1,
    sha256_word_air::{ZkX509WordMemoryChallengesV1, ZkX509WordMemoryLaneChallengesV1},
};
use super::*;
use crate::privacy_engines::transparent_stark::GOLDILOCKS_MODULUS_V1;

fn challenges() -> (
    ZkX509ShaWordStarkChallengesV1,
    ZkX509ShaCallBusChallengesV1,
    ZkX509Rfc5280StarkChallengesV1,
) {
    let word = ZkX509ShaWordStarkChallengesV1 {
        memory: ZkX509WordMemoryChallengesV1 {
            lanes: core::array::from_fn(|lane| {
                let start = 3 + 8 * lane as u64;
                ZkX509WordMemoryLaneChallengesV1 {
                    beta: F(start),
                    address: F(start + 2),
                    value: F(start + 4),
                    is_write: F(start + 6),
                }
            }),
        },
        base_folding: [F(101), F(103), F(107), F(109)],
    };
    let call = ZkX509ShaCallBusChallengesV1 {
        lanes: core::array::from_fn(|lane| ZkX509ShaCallBusLaneChallengesV1 {
            terms: core::array::from_fn(|term| F(211 + (lane * 7 + term) as u64)),
        }),
    };
    let rfc = ZkX509Rfc5280StarkChallengesV1 {
        tuple: core::array::from_fn(|lane| {
            core::array::from_fn(|term| F(503 + (lane * 12 + term) as u64))
        }),
    };
    (word, call, rfc)
}

fn terminal(segment: u16) -> u8 {
    segment as u8
}

fn context(terminal: u8) -> ShaMainFp4AirContextV1 {
    let (word, call, rfc) = challenges();
    ShaMainFp4AirContextV1 {
        word,
        call,
        rfc,
        segment: terminal,
    }
}

fn row<A>(mut field: impl FnMut(usize) -> A) -> ZkX509ShaBatchRowV1<A> {
    ZkX509ShaBatchRowV1 {
        base: core::array::from_fn(&mut field),
        aux: core::array::from_fn(|index| field(index + 101)),
        fixed: core::array::from_fn(|index| field(index + 203)),
    }
}

fn map_row<A: Copy, B>(
    row: &ZkX509ShaBatchRowV1<A>,
    mut field: impl FnMut(A) -> B,
) -> ZkX509ShaBatchRowV1<B> {
    ZkX509ShaBatchRowV1 {
        base: row.base.map(&mut field),
        aux: row.aux.map(&mut field),
        fixed: row.fixed.map(&mut field),
    }
}

#[test]
fn four_complete_sha_fp4_registrations_match_independent_base_polynomial_lifting() {
    let (word, call, rfc) = challenges();
    let w = E::canonical([0, 1, 0, 0]).unwrap();
    let mut instances = Vec::new();
    for registration in AggregateProofLayoutV1::for_full_profile_v1()
        .unwrap()
        .registered_segments
    {
        let Some(MainFp4AirEvaluatorV1::Sha(evaluator)) =
            MainFp4AirEvaluatorV1::for_registration_v1(registration).unwrap()
        else {
            continue;
        };
        instances.push(registration.segment.instance);
        let terminal = terminal(registration.segment.instance);
        let current = row(|index| {
            let i = index as u64;
            E::canonical([i + 1, i + 3, i + 5, i + 7]).unwrap()
        });
        let next = row(|index| {
            let i = index as u64;
            E::canonical([i + 11, i + 13, i + 17, i + 19]).unwrap()
        });
        let actual = evaluator
            .evaluate_residues_v1(&current, &next, context(terminal))
            .unwrap();
        assert_eq!(actual.len(), 564);
        let mut expected = vec![E::ZERO; actual.len()];
        // Total degree six includes fixed columns. Cubic cell substitution
        // therefore needs nineteen independent base-field samples.
        for sample in 0..19 {
            let t = F(sample);
            let scalar = |value: E| {
                value
                    .coefficients()
                    .iter()
                    .rev()
                    .fold(F::ZERO, |sum, &coefficient| sum.mul(t).add(coefficient))
            };
            let current_base = map_row(&current, scalar);
            let next_base = map_row(&next, scalar);
            let base = evaluate_zk_x509_sha_batch_local_residues_over_field_v1(
                &current_base,
                &next_base,
                word,
                call,
                &rfc,
                terminal,
            )
            .unwrap();
            let mut numerator = E::ONE;
            let mut denominator = F::ONE;
            for other in 0..19 {
                if other != sample {
                    numerator = numerator.mul(w.sub(E::from_base(F(other))));
                    denominator = denominator.mul(t.sub(F(other)));
                }
            }
            let weight = numerator.mul_base(denominator.inv().unwrap());
            for (sum, &value) in expected.iter_mut().zip(&base) {
                *sum = sum.add(weight.mul_base(value));
            }
            if sample == 0 {
                let embedded_current = map_row(&current_base, E::from_base);
                let embedded_next = map_row(&next_base, E::from_base);
                assert_eq!(
                    evaluator
                        .evaluate_residues_v1(&embedded_current, &embedded_next, context(terminal))
                        .unwrap(),
                    base.into_iter().map(E::from_base).collect::<Vec<_>>()
                );
            }
        }
        assert_eq!(actual, expected);
        assert!(
            actual
                .iter()
                .any(|value| value.coefficients()[1] != F::ZERO)
        );
    }
    assert_eq!(instances, vec![0, 1, 2, 3]);
}

#[test]
fn complete_sha_call_bus_total_degree_fits_six() {
    let (word, call, rfc) = challenges();
    let mut samples = (0..9)
        .map(|sample| {
            let t = F(sample);
            let current = row(|index| F(index as u64 + 1).add(t.mul(F(index as u64 + 3))));
            let next = row(|index| F(index as u64 + 11).add(t.mul(F(index as u64 + 13))));
            evaluate_zk_x509_sha_batch_local_residues_over_field_v1(
                &current,
                &next,
                word,
                call,
                &rfc,
                terminal(0),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    for _ in 0..7 {
        samples = samples
            .windows(2)
            .map(|pair| {
                pair[1]
                    .iter()
                    .zip(&pair[0])
                    .map(|(&right, &left)| right.sub(left))
                    .collect()
            })
            .collect();
    }
    assert!(samples.iter().flatten().all(|&value| value == F::ZERO));
}

#[test]
fn sha_fp4_rejects_wrong_instance_noncanonical_rows_and_binds_local_recurrences() {
    let registration = AggregateProofLayoutV1::for_full_profile_v1()
        .unwrap()
        .registered_segments
        .into_iter()
        .find(|registration| registration.segment.adapter == SegmentAdapterIdV1::Sha256CallBus)
        .unwrap();
    let Some(MainFp4AirEvaluatorV1::Sha(evaluator)) =
        MainFp4AirEvaluatorV1::for_registration_v1(registration).unwrap()
    else {
        panic!("SHA evaluator")
    };
    let current = row(|index| E::from_base(F(index as u64 + 1)));
    let next = row(|index| E::from_base(F(index as u64 + 11)));
    let terminal = terminal(registration.segment.instance);
    let original = evaluator
        .evaluate_residues_v1(&current, &next, context(terminal))
        .unwrap();
    let mut wrong_instance = terminal;
    wrong_instance = (wrong_instance + 1) % 4;
    assert!(
        evaluator
            .evaluate_residues_v1(&current, &next, context(wrong_instance))
            .is_err()
    );
    // Private RFC endpoints remain locally bound by all16 stream recurrences.
    // The20 new joined quotient controls bind them across registrations.
    for product in 0..16 {
        let mut changed = next;
        changed.aux[62 + product] = changed.aux[62 + product].add(E::ONE);
        assert_ne!(
            evaluator
                .evaluate_residues_v1(&current, &changed, context(terminal))
                .unwrap(),
            original
        );
    }
    // CA products have no public slots. The local running products remain
    // constrained; the MAIN108 quotient mutation tests cover their cross joins.
    for lane in 0..4 {
        for column in [54 + lane, 58 + lane] {
            let mut changed = next;
            changed.aux[column] = changed.aux[column].add(E::ONE);
            assert_ne!(
                evaluator
                    .evaluate_residues_v1(&current, &changed, context(terminal))
                    .unwrap(),
                original
            );
        }
    }
    let (word, call, rfc) = challenges();
    let mut noncanonical = map_row(&current, |value| value.coefficients()[0]);
    noncanonical.base[88] = F(GOLDILOCKS_MODULUS_V1);
    assert!(
        evaluate_zk_x509_sha_batch_local_residues_over_field_v1(
            &noncanonical,
            &map_row(&next, |value| value.coefficients()[0]),
            word,
            call,
            &rfc,
            terminal,
        )
        .is_err()
    );
    assert!(
        evaluator
            .evaluate_residues_v1(&current, &next, context(u8::MAX))
            .is_err()
    );
}
