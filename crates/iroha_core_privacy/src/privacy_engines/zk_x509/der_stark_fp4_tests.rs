//! Independent extension-field, terminal-binding and DER tuple checks.

use super::*;
use crate::privacy_engines::transparent_stark::GoldilocksFp4V1 as E;

fn challenges() -> ZkX509DerStarkChallengesV1 {
    ZkX509DerStarkChallengesV1 {
        tuple: core::array::from_fn(|lane| {
            core::array::from_fn(|column| F((1_000 + lane * 100 + column) as u64))
        }),
        byte_lookup: [F(9_001), F(9_002), F(9_003), F(9_004)],
    }
}

fn claims() -> ZkX509DerStarkTerminalClaimsV1 {
    ZkX509DerStarkTerminalClaimsV1 {
        input_byte: [F(13), F(17), F(19), F(23)],
        node: [F(29), F(31), F(37), F(41)],
    }
}

fn rows() -> [Vec<E>; 6] {
    let mut index = 1;
    [
        ZK_X509_DER_STARK_BASE_WIDTH_V1,
        ZK_X509_DER_STARK_BASE_WIDTH_V1,
        ZK_X509_DER_STARK_AUX_WIDTH_V1,
        ZK_X509_DER_STARK_AUX_WIDTH_V1,
        ZK_X509_DER_STARK_FIXED_WIDTH_V1,
        ZK_X509_DER_STARK_FIXED_WIDTH_V1,
    ]
    .map(|width| {
        (0..width)
            .map(|_| {
                index += 1;
                E::canonical([index, index + 3, index + 5, index + 7]).unwrap()
            })
            .collect()
    })
}

fn evaluate<A: PolynomialAirFieldV1>(
    rows: &[Vec<A>; 6],
    challenges: ZkX509DerStarkChallengesV1,
    claims: ZkX509DerStarkTerminalClaimsV1,
) -> Result<Vec<A>, ZkX509DerStarkErrorV1> {
    evaluate_zk_x509_der_stark_residues_v1(
        rows[0].as_slice().try_into().unwrap(),
        rows[1].as_slice().try_into().unwrap(),
        rows[2].as_slice().try_into().unwrap(),
        rows[3].as_slice().try_into().unwrap(),
        rows[4].as_slice().try_into().unwrap(),
        rows[5].as_slice().try_into().unwrap(),
        challenges,
        ZkX509DerStarkPublicTerminalsV1,
        claims,
    )
}

#[test]
fn der_fp4_matches_independent_base_polynomial_interpolation() {
    let rows = rows();
    let actual = evaluate(&rows, challenges(), claims()).unwrap();
    assert_eq!(actual.len(), ZK_X509_DER_STARK_CONSTRAINT_COUNT_V1);
    let w = E::canonical([0, 1, 0, 0]).unwrap();
    let mut expected = vec![E::ZERO; actual.len()];
    // Cubic input polynomials and the registered degree-seven AIR require
    // twenty-two independent base-field samples, including both fixed rows.
    for sample in 0..22 {
        let t = F(sample);
        let base = rows.each_ref().map(|row| {
            row.iter()
                .map(|value| {
                    value
                        .coefficients()
                        .iter()
                        .rev()
                        .fold(F::ZERO, |sum, c| sum.mul(t).add(*c))
                })
                .collect::<Vec<_>>()
        });
        let evaluated = evaluate(&base, challenges(), claims()).unwrap();
        let mut numerator = E::ONE;
        let mut denominator = F::ONE;
        for other in 0..22 {
            if other != sample {
                numerator = numerator.mul(w.sub(E::from_base(F(other))));
                denominator = denominator.mul(t.sub(F(other)));
            }
        }
        let weight = numerator.mul_base(denominator.inv().unwrap());
        for (sum, value) in expected.iter_mut().zip(&evaluated) {
            *sum = sum.add(weight.mul_base(*value));
        }
        if sample == 0 {
            let embedded = base
                .each_ref()
                .map(|row| row.iter().copied().map(E::from_base).collect());
            assert_eq!(
                evaluate(&embedded, challenges(), claims()).unwrap(),
                evaluated.into_iter().map(E::from_base).collect::<Vec<_>>()
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

#[test]
fn der_fp4_binds_all_terminal_lanes_and_rejects_malformed_inputs() {
    let canonical = claims();
    let mut aux = [E::ZERO; ZK_X509_DER_STARK_AUX_WIDTH_V1];
    for lane in 0..ZK_X509_DER_STARK_BUS_LANES_V1 {
        aux[AUX_INPUT_BYTE_AFTER + lane] = E::from_base(canonical.input_byte[lane]);
        aux[AUX_NODE_AFTER + lane] = E::from_base(canonical.node[lane]);
    }
    let gate = E::canonical([2, 3, 5, 7]).unwrap();
    assert_eq!(
        evaluate_zk_x509_der_stark_terminal_claim_residues_v1(gate, &aux, canonical),
        [E::ZERO; 8]
    );
    for index in 0..8 {
        let mut changed = canonical;
        if index < 4 {
            changed.input_byte[index] = changed.input_byte[index].add(F::ONE);
        } else {
            changed.node[index - 4] = changed.node[index - 4].add(F::ONE);
        }
        let residues = evaluate_zk_x509_der_stark_terminal_claim_residues_v1(gate, &aux, changed);
        for (slot, residue) in residues.into_iter().enumerate() {
            assert_eq!(
                residue,
                if slot == index {
                    E::ZERO.sub(gate)
                } else {
                    E::ZERO
                }
            );
        }
        assert_eq!(
            evaluate_zk_x509_der_stark_terminal_claim_residues_v1(E::ZERO, &aux, changed),
            [E::ZERO; 8]
        );
    }
    let rows = rows();
    let base = rows.each_ref().map(|row| {
        row.iter()
            .map(|value| value.coefficients()[0])
            .collect::<Vec<_>>()
    });
    for row in 0..6 {
        let mut malformed = base.clone();
        malformed[row][0] = F(GOLDILOCKS_MODULUS_V1);
        assert_eq!(
            evaluate(&malformed, challenges(), canonical),
            Err(ZkX509DerStarkErrorV1::Row)
        );
    }
    let mut malformed_claims = canonical;
    malformed_claims.node[2] = F(GOLDILOCKS_MODULUS_V1);
    assert_eq!(
        evaluate(&rows, challenges(), malformed_claims),
        Err(ZkX509DerStarkErrorV1::Row)
    );
    let mut malformed_challenges = challenges();
    malformed_challenges.tuple[1] = malformed_challenges.tuple[0];
    assert_eq!(
        evaluate(&rows, malformed_challenges, canonical),
        Err(ZkX509DerStarkErrorV1::Challenge)
    );
}

#[test]
fn der_fp4_downstream_factors_preserve_exact_tuple_order() {
    let values: [E; 11] = core::array::from_fn(|index| {
        let i = index as u64 + 1;
        E::canonical([i, i + 11, i + 23, i + 47]).unwrap()
    });
    let event = ZkX509DerStarkNodeEventV1 {
        document: values[0],
        ordinal: values[1],
        parent_frame: values[2],
        tag_class: values[3],
        tag_number: values[4],
        constructed: values[5],
        start: values[6],
        content_start: values[7],
        content_end: values[8],
        depth: values[9],
        content_len: values[10],
    };
    let challenges = challenges();
    for lane in 0..4 {
        let c = challenges.tuple[lane];
        let expected = values
            .iter()
            .zip(&c[1..])
            .fold(E::from_base(F(3).mul(c[0])), |sum, (value, coefficient)| {
                sum.add(value.mul_base(*coefficient))
            });
        assert_eq!(
            zk_x509_der_stark_node_factor_v1(event, lane, &challenges).unwrap(),
            expected
        );
        let expected_byte = E::from_base(F(6).mul(c[0]))
            .add(values[0].mul_base(c[1]))
            .add(values[1].mul_base(c[2]))
            .add(values[2].mul_base(c[3]));
        assert_eq!(
            zk_x509_der_stark_input_byte_factor_v1(
                values[0],
                values[1],
                values[2],
                lane,
                &challenges
            )
            .unwrap(),
            expected_byte
        );
    }
    assert_eq!(
        zk_x509_der_stark_node_factor_v1(event, 4, &challenges),
        Err(ZkX509DerStarkErrorV1::Challenge)
    );
    assert_eq!(
        zk_x509_der_stark_input_byte_factor_v1(values[0], values[1], values[2], 4, &challenges),
        Err(ZkX509DerStarkErrorV1::Challenge)
    );
}
