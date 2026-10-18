//! Authenticated ordinal, `KeyUsage` role and exact extension cardinality controls.
use super::*;
use crate::privacy_engines::transparent_stark::GoldilocksFp4V1 as E;
fn fixed(family: ZkX509Rfc5280StarkFamilyV1) -> ZkX509Rfc5280StarkFixedRowV1 {
    let mut fixed = [F::ZERO; ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1];
    fixed[family as usize] = F::ONE;
    fixed
}
fn valid(row: &ZkX509Rfc5280StarkBaseRowV1, fixed: &ZkX509Rfc5280StarkFixedRowV1) -> bool {
    residues(row, fixed).iter().all(|r| *r == F::ZERO)
}

#[test]
fn oid_variant_is_the_original_extension_ordinal_and_ku_is_the_original_leaf_role() {
    let fixed = fixed(ZkX509Rfc5280StarkFamilyV1::FixedByte);
    for purpose in [6, 7] {
        for ordinal in 0..if purpose == 6 { 5 } else { 2 } {
            let mut row = active_zero_row_v1();
            row[BASE_ROLE] = F(purpose);
            row[BASE_H] = F(ordinal);
            row[BASE_ENDPOINT_ROLE] = F(ordinal);
            populate_fixed_byte(&mut row, F::ZERO);
            assert!(valid(&row, &fixed));
            for variant in 0..5 {
                if variant == ordinal {
                    continue;
                }
                let mut changed = row;
                changed[BASE_ENDPOINT_ROLE] = F(variant);
                populate_fixed_byte(&mut changed, F::ZERO);
                assert!(!valid(&changed, &fixed));
            }
        }
    }
    for certificate_two in [F::ZERO, F::ONE] {
        for (document, variant) in [
            (5 + certificate_two.0, 0),
            (10 + certificate_two.0, 1),
            (15, 1),
        ] {
            if document == 15 && certificate_two == F::ZERO {
                continue;
            }
            let mut row = active_zero_row_v1();
            row[BASE_ROLE] = F(10);
            row[BASE_DOCUMENT] = F(document);
            row[BASE_CERT2_ACTIVE] = certificate_two;
            row[BASE_ENDPOINT_ROLE] = F(variant);
            populate_fixed_byte(&mut row, certificate_two);
            assert!(valid(&row, &fixed));
            let mut changed = row;
            changed[BASE_ENDPOINT_ROLE] = F::ONE.sub(changed[BASE_ENDPOINT_ROLE]);
            populate_fixed_byte(&mut changed, certificate_two);
            assert!(!valid(&changed, &fixed));
            for column in FIXED_FLAGS..KU_LEAF + 2 {
                let mut changed = row;
                changed[column] = changed[column].add(F::ONE);
                assert!(!valid(&changed, &fixed), "{document}:{column}");
            }
        }
    }
}

#[test]
fn exact_original_extension_counts_force_leaf_eku_and_critical_boolean_positions() {
    let fixed = fixed(ZkX509Rfc5280StarkFamilyV1::SourceNode);
    for document in 0..3 {
        for role in [
            ZkX509Rfc5280GrammarRoleV1::CertificateExtensions,
            ZkX509Rfc5280GrammarRoleV1::CertificateExtension,
        ] {
            for ordinal in 0..5 {
                let count = if role == ZkX509Rfc5280GrammarRoleV1::CertificateExtensions {
                    4 + u64::from(document == 0)
                } else {
                    if ordinal < 2 { 2 } else { 3 }
                };
                let mut row = active_zero_row_v1();
                row[BASE_DOCUMENT] = F(document);
                row[BASE_ROLE] = F(role as u64);
                row[BASE_INSTANCE] = F(ordinal);
                row[BASE_D] = F(count);
                populate_source_node(&mut row);
                assert!(valid(&row, &fixed));
                for wrong in 0..7 {
                    if wrong == count {
                        continue;
                    }
                    let mut changed = row;
                    changed[BASE_D] = F(wrong);
                    populate_source_node(&mut changed);
                    assert!(
                        !valid(&changed, &fixed),
                        "{document}:{role:?}:{ordinal}:{wrong}"
                    );
                }
                for column in NODE_FLAGS..NODE_PREFIX_END {
                    let mut changed = row;
                    changed[column] = changed[column].add(F::ONE);
                    assert!(!valid(&changed, &fixed), "{document}:{role:?}:{column}");
                }
            }
        }
    }
    let mut inactive = [F::ZERO; ZK_X509_RFC5280_STARK_BASE_WIDTH_V1];
    populate_source_node(&mut inactive);
    assert!(valid(&inactive, &fixed));
    assert!(
        inactive[NODE_FLAGS..NODE_PREFIX_END]
            .iter()
            .all(|v| *v == F::ZERO)
    );
}

#[test]
fn genuine_source_and_profile_rows_satisfy_both_field_evaluators_and_clear_unused_aliases() {
    use crate::privacy_engines::zk_x509::{
        der_air::build_zk_x509_rfc5280_trace_v1,
        relation::release_fixture::{
            build_zk_x509_copy_capacity_fixture_v1, build_zk_x509_release_fixture_v1,
            reference_statement_context_v1,
        },
        verifier_profile::rfc_statement_with_crl_number_v1,
    };
    for (maximum, capacity) in [(false, false), (true, false), (false, true), (true, true)] {
        let fixture = if capacity {
            build_zk_x509_copy_capacity_fixture_v1(maximum)
        } else {
            build_zk_x509_release_fixture_v1(reference_statement_context_v1(), maximum)
        }
        .unwrap();
        let trace = build_zk_x509_rfc5280_trace_v1(
            &fixture.witness.certificate_chain_der,
            &fixture.witness.crl_der,
            rfc_statement_with_crl_number_v1(
                &fixture.statement,
                fixture.authoritative_state.crl_record().crl_number,
            ),
        )
        .unwrap();
        let material = build_zk_x509_rfc5280_stark_base_material_v1(&trace).unwrap();
        let mut counts = [0; 3];
        for family in [
            ZkX509Rfc5280StarkFamilyV1::SourceNode,
            ZkX509Rfc5280StarkFamilyV1::FixedByte,
        ] {
            for ordinal in 0..material.family_rows[family as usize].len() {
                let index = material.schedule.starts[family as usize] + ordinal;
                let row = material.base_row(index).unwrap();
                let fixed = material.fixed_row(index).unwrap();
                assert!(valid(&row, &fixed), "{family:?}:{ordinal}");
                assert_eq!(
                    residues(&row.map(E::from_base), &fixed.map(E::from_base)),
                    [E::ZERO; RESIDUES]
                );
                if family == ZkX509Rfc5280StarkFamilyV1::SourceNode {
                    counts[0] += usize::from(row[NODE_FLAGS] == F::ONE);
                    counts[1] += usize::from(row[NODE_FLAGS + 2] == F::ONE);
                } else {
                    counts[2] +=
                        usize::from(row[FIXED_FLAGS + 4] == F::ONE && row[BASE_IS_WRITE] == F::ONE);
                }
            }
        }
        let depth = if maximum { 3 } else { 2 };
        assert_eq!(counts, [depth, 4 * depth + 1, depth]);
    }
}

#[test]
fn identity_equations_are_fp4_generic_with_degree_at_most_three() {
    for seed in [1_u64, 7, 19] {
        let samples = (0..6)
            .map(|point| {
                let affine = |kind: u64, i: usize| {
                    F((seed + kind * 13 + i as u64 * 17) % 1009 + 1)
                        .add(F((seed * 7 + kind * 19 + i as u64 * 29) % 997 + 1).mul(F(point)))
                };
                let row = core::array::from_fn(|i| affine(1, i));
                let fixed = core::array::from_fn(|i| affine(2, i));
                let result = residues(&row, &fixed);
                assert_eq!(
                    residues(&row.map(E::from_base), &fixed.map(E::from_base)),
                    result.map(E::from_base)
                );
                result
            })
            .collect::<Vec<_>>();
        for column in 0..RESIDUES {
            let mut values = samples.iter().map(|r| r[column]).collect::<Vec<_>>();
            for _ in 0..4 {
                values = values.windows(2).map(|p| p[1].sub(p[0])).collect();
            }
            assert!(values.iter().all(|v| *v == F::ZERO), "{seed}:{column}");
        }
    }
    assert_eq!(NODE_PREFIX_END, 144);
    assert_eq!(ZK_X509_RFC5280_STARK_BASE_WIDTH_V1, 285);
    assert_eq!(ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1, 147);
}
