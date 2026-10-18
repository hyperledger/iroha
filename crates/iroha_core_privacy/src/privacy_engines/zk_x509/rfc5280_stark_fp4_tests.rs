//! Independent polynomial lifting and terminal binding for certificate policy.

use super::*;
use crate::privacy_engines::transparent_stark::GoldilocksFp4V1 as E;

fn challenges() -> ZkX509Rfc5280StarkChallengesV1 {
    ZkX509Rfc5280StarkChallengesV1 {
        tuple: core::array::from_fn(|lane| {
            core::array::from_fn(|slot| F((10_000 + lane * 100 + slot) as u64))
        }),
    }
}

fn der_challenges() -> ZkX509DerStarkChallengesV1 {
    ZkX509DerStarkChallengesV1 {
        tuple: core::array::from_fn(|lane| {
            core::array::from_fn(|slot| F((20_000 + lane * 100 + slot) as u64))
        }),
        byte_lookup: [F(30_000), F(30_001), F(30_002), F(30_003)],
    }
}

fn rows() -> [Vec<E>; 5] {
    let mut index = 1;
    [
        ZK_X509_RFC5280_STARK_BASE_WIDTH_V1,
        ZK_X509_RFC5280_STARK_BASE_WIDTH_V1,
        ZK_X509_RFC5280_STARK_AUX_WIDTH_V1,
        ZK_X509_RFC5280_STARK_AUX_WIDTH_V1,
        ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1,
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

fn evaluate<A: PolynomialAirFieldV1>(rows: &[Vec<A>; 5]) -> Vec<A> {
    evaluate_zk_x509_rfc5280_stark_residues_v1(
        rows[0].as_slice().try_into().unwrap(),
        rows[1].as_slice().try_into().unwrap(),
        rows[2].as_slice().try_into().unwrap(),
        rows[3].as_slice().try_into().unwrap(),
        rows[4].as_slice().try_into().unwrap(),
        der_challenges(),
        &challenges(),
        ZkX509Rfc5280StarkTerminalClaimsV1::canonical_identity_v1(),
    )
    .unwrap()
}

#[test]
fn rfc5280_fp4_matches_independent_base_polynomial_interpolation() {
    let rows = rows();
    let actual = evaluate(&rows);
    assert_eq!(actual.len(), ZK_X509_RFC5280_STARK_CONSTRAINT_COUNT_V1);
    let w = E::canonical([0, 1, 0, 0]).unwrap();
    let mut expected = vec![E::ZERO; actual.len()];
    // Cubic input polynomials and degree-four AIR require thirteen samples.
    // Base-only evaluation followed by Lagrange interpolation avoids using the
    // extension AIR's multiplication as the reference calculation.
    for sample in 0..13 {
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
        let evaluated = evaluate(&base);
        let mut numerator = E::ONE;
        let mut denominator = F::ONE;
        for other in 0..13 {
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
                evaluate(&embedded),
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
fn rfc5280_total_degree_is_exactly_four_including_fixed_selectors() {
    let rows = rows();
    let mut samples = (0..6)
        .map(|sample| {
            let t = F(sample);
            let base = rows.each_ref().map(|row| {
                row.iter()
                    .map(|value| {
                        let c = value.coefficients();
                        c[0].add(c[1].mul(t))
                    })
                    .collect::<Vec<_>>()
            });
            evaluate(&base)
        })
        .collect::<Vec<_>>();
    for order in 1..=5 {
        samples = samples
            .windows(2)
            .map(|pair| {
                pair[0]
                    .iter()
                    .zip(&pair[1])
                    .map(|(left, right)| right.sub(*left))
                    .collect()
            })
            .collect();
        if order == 4 {
            assert!(samples.iter().flatten().any(|value| *value != F::ZERO));
        }
    }
    assert!(samples[0].iter().all(|value| *value == F::ZERO));
    assert_eq!(ZK_X509_RFC5280_STARK_CONSTRAINT_DEGREE_V1, 4);
}

#[test]
fn rfc5280_fp4_binds_every_committed_terminal() {
    let claims = ZkX509Rfc5280StarkTerminalClaimsV1::canonical_identity_v1();
    let aux = [E::ONE; ZK_X509_RFC5280_STARK_AUX_WIDTH_V1];
    let gate = E::canonical([2, 3, 5, 7]).unwrap();
    assert_eq!(
        evaluate_zk_x509_rfc5280_terminal_claim_residues_v1(gate, &aux, claims).unwrap(),
        [E::ZERO; RFC5280_TERMINAL_RESIDUES_V1]
    );
    // Discover the binding by perturbing every committed auxiliary cell. The
    // reference is the base-field result, scaled by a genuinely quartic gate.
    let mut observed = [false; RFC5280_TERMINAL_RESIDUES_V1];
    for column in 0..aux.len() {
        let mut changed = aux;
        changed[column] = changed[column].add(E::ONE);
        let mut base = [F::ONE; ZK_X509_RFC5280_STARK_AUX_WIDTH_V1];
        base[column] = F(2);
        let expected =
            evaluate_zk_x509_rfc5280_terminal_claim_residues_v1(F::ONE, &base, claims).unwrap();
        let actual =
            evaluate_zk_x509_rfc5280_terminal_claim_residues_v1(gate, &changed, claims).unwrap();
        for (slot, (got, expected)) in actual.into_iter().zip(expected).enumerate() {
            assert_eq!(got, gate.mul_base(expected));
            observed[slot] |= got != E::ZERO;
        }
        assert_eq!(
            evaluate_zk_x509_rfc5280_terminal_claim_residues_v1(E::ZERO, &changed, claims).unwrap(),
            [E::ZERO; RFC5280_TERMINAL_RESIDUES_V1]
        );
    }
    assert!(observed.into_iter().all(|bound| bound));
    assert_eq!(claims.output_roles.len(), 1);
    for role in OUTPUT_ROLES_V1 {
        if role == ZkX509Rfc5280OutputRoleV1::GovernedTrustAnchor {
            continue;
        }
        let mut wrong_role = claims;
        wrong_role.output_roles[0].role = role;
        assert_eq!(
            evaluate_zk_x509_rfc5280_terminal_claim_residues_v1(gate, &aux, wrong_role),
            Err(ZkX509Rfc5280StarkErrorV1::TerminalClaim),
            "a private role cannot replace the sole public governed-root role: {role:?}"
        );
    }
    let mut wrong_product = claims;
    wrong_product.output_roles[0].consumer_products[1] = F(GOLDILOCKS_MODULUS_V1);
    assert_eq!(
        evaluate_zk_x509_rfc5280_terminal_claim_residues_v1(gate, &aux, wrong_product),
        Err(ZkX509Rfc5280StarkErrorV1::TerminalClaim)
    );
}

#[test]
fn rfc5280_opened_air_rejects_malformed_fields_challenges_and_claims() {
    let extension = rows();
    let rows = extension.each_ref().map(|row| {
        row.iter()
            .map(|value| value.coefficients()[0])
            .collect::<Vec<_>>()
    });
    let evaluate = |rows: &[Vec<F>; 5], der, local, claims| {
        evaluate_zk_x509_rfc5280_stark_residues_v1(
            rows[0].as_slice().try_into().unwrap(),
            rows[1].as_slice().try_into().unwrap(),
            rows[2].as_slice().try_into().unwrap(),
            rows[3].as_slice().try_into().unwrap(),
            rows[4].as_slice().try_into().unwrap(),
            der,
            &local,
            claims,
        )
    };
    let claims = ZkX509Rfc5280StarkTerminalClaimsV1::canonical_identity_v1();
    for row in 0..5 {
        let mut malformed = rows.clone();
        malformed[row][0] = F(GOLDILOCKS_MODULUS_V1);
        assert_eq!(
            evaluate(&malformed, der_challenges(), challenges(), claims),
            Err(ZkX509Rfc5280StarkErrorV1::Semantic)
        );
    }
    let mut local = challenges();
    local.tuple[1] = local.tuple[0];
    assert!(evaluate(&rows, der_challenges(), local, claims).is_err());
    let mut der = der_challenges();
    der.tuple[1] = der.tuple[0];
    assert!(evaluate(&rows, der, challenges(), claims).is_err());
    let mut malformed_claims = claims;
    malformed_claims.output_roles[0].consumer_products[1] = F(GOLDILOCKS_MODULUS_V1);
    assert_eq!(
        evaluate(&rows, der_challenges(), challenges(), malformed_claims),
        Err(ZkX509Rfc5280StarkErrorV1::TerminalClaim)
    );
}
