//! Differential and adversarial checks for the complete compact-CA Fp4 AIR.

use super::super::sha_call_bus_stark::ZkX509ShaCallBusLaneChallengesV1;
use super::*;

fn challenges() -> (ZkX509ShaCallBusChallengesV1, ZkX509Rfc5280StarkChallengesV1) {
    (
        ZkX509ShaCallBusChallengesV1 {
            lanes: core::array::from_fn(|lane| ZkX509ShaCallBusLaneChallengesV1 {
                terms: core::array::from_fn(|term| F((lane * 7 + term + 2) as u64)),
            }),
        },
        ZkX509Rfc5280StarkChallengesV1 {
            tuple: core::array::from_fn(|lane| {
                core::array::from_fn(|term| F((lane * 13 + term + 101) as u64))
            }),
        },
    )
}
fn public_and_claims() -> (
    ZkX509CaAccumulatorStarkPublicV1,
    ZkX509CaAccumulatorStarkTerminalClaimsV1,
) {
    (
        ZkX509CaAccumulatorStarkPublicV1 {
            governed_root: [F(7); 32],
            root_spki_channel: F(19),
        },
        ZkX509CaAccumulatorStarkTerminalClaimsV1 {
            source_products: [[F(23); ZK_X509_SHA_BUS_LANES_V1];
                ZK_X509_CA_ACCUMULATOR_ACTIVE_ROWS_V1],
            digest_products: [[F(29); ZK_X509_SHA_BUS_LANES_V1];
                ZK_X509_CA_ACCUMULATOR_ACTIVE_ROWS_V1],
            root_spki_consumer_products: [F(31); ZK_X509_RFC5280_STARK_BUS_LANES_V1],
        },
    )
}
fn rows() -> [Vec<E>; 5] {
    let mut index = 1_u64;
    [
        ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1,
        ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1,
        ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1,
        ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1,
        ZK_X509_CA_ACCUMULATOR_FIXED_WIDTH_V1,
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
#[test]
fn ca_fp4_residues_match_independent_base_polynomial_lifting() {
    let (public, claims) = public_and_claims();
    let (sha, io) = challenges();
    let rows = rows();
    let extension = evaluate_ca_accumulator_stark_residues_v1(
        public, &rows[0], &rows[1], &rows[2], &rows[3], &rows[4], sha, &io, claims,
    )
    .unwrap();
    // Every input is a cubic polynomial in the formal extension generator.
    // The largest full degree INCLUDING fixed selectors is five: the source
    // recurrence multiplies an auxiliary value by two quadratic factors.
    // Thus sixteen base evaluations independently reconstruct each residue
    // before reducing modulo w^4-7; no Fp4 multiplication is used by the AIR
    // in this reference path.
    let w = E::canonical([0, 1, 0, 0]).unwrap();
    let mut expected = vec![E::ZERO; ZK_X509_CA_ACCUMULATOR_CONSTRAINT_COUNT_V1];
    for sample in 0..16 {
        let t = F(sample);
        let lifted = rows.each_ref().map(|row| {
            row.iter()
                .map(|value| {
                    value
                        .coefficients()
                        .iter()
                        .rev()
                        .fold(F::ZERO, |sum, coefficient| sum.mul(t).add(*coefficient))
                })
                .collect::<Vec<_>>()
        });
        let evaluated = evaluate_ca_accumulator_stark_residues_v1(
            public, &lifted[0], &lifted[1], &lifted[2], &lifted[3], &lifted[4], sha, &io, claims,
        )
        .unwrap();
        let mut numerator = E::ONE;
        let mut denominator = F::ONE;
        for other in 0..16 {
            if other != sample {
                numerator = numerator.mul(w.sub(E::from_base(F(other))));
                denominator = denominator.mul(t.sub(F(other)));
            }
        }
        let weight = numerator.mul_base(denominator.inv().unwrap());
        for (sum, value) in expected.iter_mut().zip(evaluated) {
            *sum = sum.add(weight.mul_base(value));
        }
        // Base-field embedding is a second independent invariant.
        if sample == 0 {
            let embedded = lifted
                .each_ref()
                .map(|row| row.iter().copied().map(E::from_base).collect::<Vec<_>>());
            let actual = evaluate_ca_accumulator_stark_residues_v1(
                public,
                &embedded[0],
                &embedded[1],
                &embedded[2],
                &embedded[3],
                &embedded[4],
                sha,
                &io,
                claims,
            )
            .unwrap();
            let base = evaluate_ca_accumulator_stark_residues_v1(
                public, &lifted[0], &lifted[1], &lifted[2], &lifted[3], &lifted[4], sha, &io,
                claims,
            )
            .unwrap();
            assert_eq!(
                actual,
                base.into_iter().map(E::from_base).collect::<Vec<_>>()
            );
        }
    }
    assert_eq!(extension, expected);
    assert!(
        extension
            .iter()
            .any(|value| value.coefficients()[1] != F::ZERO)
    );
}

#[test]
fn ca_fixed_deep_evaluation_matches_known_polynomials_and_rejects_shape() {
    let root = goldilocks_primitive_root_v1(ZK_X509_CA_ACCUMULATOR_TRACE_LOG2_V1).unwrap();
    let mut x = F::ONE;
    let native = (0..ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1)
        .map(|_| {
            let value = x.add(x.mul(x)).add(x.pow(3));
            x = x.mul(root);
            value
        })
        .collect::<Vec<_>>();
    let columns = (0..ZK_X509_CA_ACCUMULATOR_FIXED_WIDTH_V1)
        .map(|index| {
            native
                .iter()
                .map(|value| value.add(F(index as u64)))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let point = E::canonical([7, 11, 13, 17]).unwrap();
    let actual = ca_fixed_columns_at_deep_v1(&columns, point).unwrap();
    for (index, value) in actual.into_iter().enumerate() {
        assert_eq!(
            value,
            point
                .add(point.mul(point))
                .add(point.pow(3))
                .add(E::from_base(F(index as u64)))
        );
    }
    assert!(ca_fixed_columns_at_deep_v1(&columns[..79], point).is_err());
    let mut changed = columns;
    changed[0][0] = F(u64::MAX);
    assert!(ca_fixed_columns_at_deep_v1(&changed, point).is_err());
}

#[test]
fn ca_complete_deep_constraint_check_rejects_trace_and_composition_substitution() {
    let (public, _) = public_and_claims();
    let (sha, io) = challenges();
    let layout = ca_aggregate_layout_v1().unwrap();
    let point = E::canonical([7, 11, 13, 17]).unwrap();
    let fixed_columns = compile_ca_accumulator_fixed_columns_v1().unwrap();
    let fixed = ca_fixed_columns_at_deep_v1(&fixed_columns, point).unwrap();
    let rows = rows();
    let residues = evaluate_ca_accumulator_local_residues_v1(
        public, &rows[0], &rows[1], &rows[2], &rows[3], &fixed, sha, &io,
    )
    .unwrap();
    let alphas = (0..ZK_X509_CA_ACCUMULATOR_LOCAL_CONSTRAINT_COUNT_V1)
        .map(|index| E::canonical([index as u64 + 2, 3, 5, 7]).unwrap())
        .collect::<Vec<_>>();
    let quotient = residues
        .iter()
        .zip(&alphas)
        .fold(E::ZERO, |sum, (value, alpha)| sum.add(value.mul(*alpha)))
        .mul(
            point
                .pow(ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1 as u128)
                .sub(E::ONE)
                .inv()
                .unwrap(),
        );
    let wire = |row: &[E]| {
        row.iter()
            .map(|value| value.coefficients().map(F::value))
            .collect()
    };
    let mut chunks = vec![[0; 4]; CA_COMPOSITION_DEGREE_CHUNKS_V1];
    // Use two nonzero chunks to exercise extension-field recomposition.
    chunks[1] = [2, 3, 5, 7];
    chunks[0] = quotient
        .sub(
            E::canonical(chunks[1]).unwrap().mul(
                point.pow(
                    super::super::composition_masking::QuotientChunkGeometryV1::new_v1(
                        &layout,
                        CA_AGGREGATE_PARAMETERS_V1,
                    )
                    .unwrap()
                    .stride_v1() as u128,
                ),
            ),
        )
        .coefficients()
        .map(F::value);
    let deep = aggregate::AggregateDeepProofV1 {
        trace_groups: vec![aggregate::AggregateDeepTraceGroupOpeningV1 {
            base_current: wire(&rows[0]),
            base_next: wire(&rows[1]),
            aux_current: wire(&rows[2]),
            aux_next: wire(&rows[3]),
        }],
        composition_values: vec![chunks],
    };
    let check = |deep: &aggregate::AggregateDeepProofV1| {
        verify_ca_deep_constraints_v1(
            public,
            deep,
            point,
            &layout,
            &fixed_columns,
            sha,
            &io,
            &alphas,
        )
    };
    // This tests only the relation equation; authentication and degree checks
    // remain separately mandatory and would reject these arbitrary rows.
    check(&deep).unwrap();
    for mutation in 0..5 {
        let mut changed = deep.clone();
        let group = &mut changed.trace_groups[0];
        let value = match mutation {
            0 => &mut group.base_current[CA_DIGEST_BYTE_BITS_START],
            1 => &mut group.base_next[CA_INDEX_BITS_START],
            2 => &mut group.aux_current[source_aux_cell_v1(0, 0)],
            3 => &mut group.aux_next[serialized_sha_product_cell_v1(0)],
            _ => &mut changed.composition_values[0][1],
        };
        *value = E::canonical(*value)
            .unwrap()
            .add(E::ONE)
            .coefficients()
            .map(F::value);
        assert!(check(&changed).is_err(), "mutation {mutation}");
    }
    assert!(
        verify_ca_deep_constraints_v1(
            public,
            &deep,
            E::ONE,
            &layout,
            &fixed_columns,
            sha,
            &io,
            &alphas
        )
        .is_err()
    );
    let mut changed = deep;
    changed.trace_groups[0].base_current.pop();
    assert!(check(&changed).is_err());
}
