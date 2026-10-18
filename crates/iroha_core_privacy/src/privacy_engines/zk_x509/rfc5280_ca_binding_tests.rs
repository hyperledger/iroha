//! Independent RFC topology and compact-CA terminal parity controls.

use super::*;
use crate::privacy_engines::zk_x509::{
    accumulator_air::{
        ZkX509CaAccumulatorStatementV1, ZkX509CaAccumulatorWitnessV1, build_ca_accumulator_trace_v1,
    },
    accumulator_stark::{
        build_ca_accumulator_stark_material_v1, ca_accumulator_root_spki_channel_v1,
    },
    der_air::build_zk_x509_rfc5280_trace_v1,
    relation::release_fixture::{build_zk_x509_release_fixture_v1, reference_statement_context_v1},
    sha_call_bus_stark::{
        ZkX509ShaCallBusChallengesV1, ZkX509ShaCallBusLaneChallengesV1, ZkX509ShaCallPublicShapeV1,
        ZkX509ShaCallScheduleV1,
    },
    verifier_profile::compile_zk_x509_rfc_statement_from_authoritative_state_v1,
};

#[test]
fn compact_ca_channel_matches_actual_rfc_fixed_topology_for_every_disclosure_count() {
    for (disclosures, expected_channel) in [30_u32, 32, 34, 36, 38].into_iter().enumerate() {
        let mut shape = ZkX509Rfc5280StarkShapeV1::default();
        shape.disclosed_attribute_count = u8::try_from(disclosures).unwrap();
        for index in 0..disclosures {
            shape.disclosed_attribute_indices[index] = u8::try_from(index).unwrap();
        }
        let fixed = compile_zk_x509_rfc5280_stark_fixed_schedule_v1(shape).unwrap();
        let root_rows = fixed
            .output_topology
            .iter()
            .filter(|entry| entry.role == ZkX509Rfc5280OutputRoleV1::GovernedTrustAnchor)
            .collect::<Vec<_>>();
        assert_eq!(root_rows.len(), 91);
        let sha_schedule = ZkX509ShaCallScheduleV1::new(ZkX509ShaCallPublicShapeV1 {
            disclosed_attributes: disclosures,
        })
        .unwrap();
        let ca_channel = ca_accumulator_root_spki_channel_v1(&sha_schedule).unwrap();
        for (offset, entry) in root_rows.into_iter().enumerate() {
            assert_eq!(entry.channel, expected_channel);
            assert_eq!(entry.channel, ca_channel);
            assert_eq!(entry.consumer_endpoint_role, 4);
            assert_eq!(entry.endpoint_instance, 0);
            assert_eq!(usize::try_from(entry.offset).unwrap(), offset);
        }
    }
}

#[test]
fn actual_root_spki_products_match_rfc_and_ca_and_reject_retired_channel() {
    let fixture = build_zk_x509_release_fixture_v1(reference_statement_context_v1(), true)
        .expect("maximum real certificate and occupied-CA-path fixture");
    let statement = compile_zk_x509_rfc_statement_from_authoritative_state_v1(
        &fixture.statement,
        &fixture.authoritative_state,
    );
    let mut rfc_trace = build_zk_x509_rfc5280_trace_v1(
        &fixture.witness.certificate_chain_der,
        &fixture.witness.crl_der,
        statement,
    )
    .unwrap();
    assert_eq!(rfc_trace.certificates.len(), 3);
    assert_eq!(
        rfc_trace.statement.disclosed_attribute_indices,
        [0, 1, 2, 3]
    );
    let root_spki_der = rfc_trace
        .certificates
        .last()
        .unwrap()
        .spki_der
        .as_slice()
        .try_into()
        .expect("exact 91-byte DER root SPKI");
    let ca_trace = build_ca_accumulator_trace_v1(
        ZkX509CaAccumulatorStatementV1 {
            governed_root: *fixture.statement.ca_membership_root.as_bytes(),
        },
        ZkX509CaAccumulatorWitnessV1 {
            root_spki_der,
            path: fixture.witness.ca_membership_path,
        },
    )
    .unwrap();
    let io_challenges = ZkX509Rfc5280StarkChallengesV1 {
        tuple: core::array::from_fn(|lane| {
            core::array::from_fn(|term| F(u64::try_from(1_001 + 100 * lane + 2 * term).unwrap()))
        }),
    };
    let sha_challenges = ZkX509ShaCallBusChallengesV1 {
        lanes: core::array::from_fn(|lane| ZkX509ShaCallBusLaneChallengesV1 {
            terms: core::array::from_fn(|term| {
                F(u64::try_from(11 + 100 * lane + 2 * term).unwrap())
            }),
        }),
    };
    for disclosures in 0..=4 {
        rfc_trace.statement.disclosed_attribute_indices = (0..disclosures)
            .map(|index| u8::try_from(index).unwrap())
            .collect();
        let sha_schedule = ZkX509ShaCallScheduleV1::new(ZkX509ShaCallPublicShapeV1 {
            disclosed_attributes: disclosures,
        })
        .unwrap();
        let ca = build_ca_accumulator_stark_material_v1(
            &ca_trace,
            &sha_schedule,
            sha_challenges,
            &io_challenges,
        )
        .unwrap();
        let rfc = zk_x509_rfc5280_output_terminals_v1(&rfc_trace, &io_challenges).unwrap();
        let role = ZkX509Rfc5280OutputRoleV1::GovernedTrustAnchor;
        let role_index = output_role_index_v1(role);
        let witnesses = rfc5280_io_witnesses_v1(&rfc_trace, 0).unwrap();
        let roles = output_roles_v1(&rfc_trace).unwrap();
        let root = witnesses
            .iter()
            .zip(roles)
            .find(|(_, candidate)| *candidate == role)
            .map(|(witness, _)| witness)
            .unwrap();
        assert_eq!(root.declaration.channel, ca.root_spki_terminal.channel);
        assert_eq!(
            root.producer_value.as_slice(),
            ca_trace.witness.root_spki_der
        );
        assert_eq!(root.declaration.consumers.len(), 1);
        assert_eq!(rfc.consumer_events[role_index], 91);
        assert_eq!(ca.root_spki_terminal.event_count, 91);
        assert_eq!(
            ca.root_spki_terminal.consumer_products,
            rfc.consumer[role_index]
        );
        // The pre-repair CA channel must produce a different binding in every lane.
        // This recomputes real bytes through RFC's own tuple expression, not CA's helper.
        for lane in 0..ZK_X509_RFC5280_STARK_BUS_LANES_V1 {
            let retired = root.producer_value.iter().copied().enumerate().fold(
                F::ONE,
                |product, (offset, byte)| {
                    product.mul(
                        output_factor_v1(
                            role,
                            root.declaration.channel - 2,
                            root.declaration.consumers[0],
                            offset,
                            byte,
                            false,
                            lane,
                            &io_challenges,
                        )
                        .unwrap(),
                    )
                },
            );
            assert_ne!(retired, rfc.consumer[role_index][lane]);
        }
    }
}
