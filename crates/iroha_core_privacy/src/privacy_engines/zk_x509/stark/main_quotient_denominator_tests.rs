//! Direct-field oracles, shape rejection and complete-profile work accounting.

use super::*;
use rand::{RngCore, SeedableRng, rngs::StdRng};

#[test]
fn every_profile_stripe_matches_direct_boundary_and_random_denominators() {
    let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
    let mut rng = StdRng::from_seed([0xD3; 32]);
    let mut quotient_rows = 0;
    let mut inverse_calls = 0;
    let mut stripes = 0;
    let mut maximum_period = 0;
    for registration in &layout.registered_segments {
        let segment = registration.segment;
        let plan = registered_retained_prover_plan_v1(segment, layout.common_lde_log2).unwrap();
        let first = main_quotient_stripes::MainQuotientStripeV1::new_v1(
            segment.trace_log2,
            plan.quotient_coset_log2,
            0,
        )
        .unwrap();
        for ordinal in 0..first.count {
            let stripe = main_quotient_stripes::MainQuotientStripeV1::new_v1(
                segment.trace_log2,
                plan.quotient_coset_log2,
                ordinal,
            )
            .unwrap();
            let table = MainQuotientDenominatorsV1::new_v1(segment.trace_log2, stripe).unwrap();
            let period = stripe.rows / segment.trace_size();
            assert_eq!(table.inverses.len(), period);
            assert_eq!(stripe.root.pow(stripe.rows as u128), F::ONE);
            assert_ne!(stripe.root.pow((stripe.rows / 2) as u128), F::ONE);
            let step = stripe.root.pow(segment.trace_size() as u128);
            assert_eq!(step.pow(period as u128), F::ONE);
            if period > 1 {
                assert_ne!(step.pow((period / 2) as u128), F::ONE);
            }
            let indices = [
                0,
                1,
                period - 1,
                period,
                stripe.rows / 2,
                stripe.rows - 2,
                stripe.rows - 1,
            ];
            for row in indices
                .into_iter()
                .chain((0..64).map(|_| rng.next_u64() as usize % stripe.rows))
            {
                let x = stripe.shift.mul(stripe.root.pow(row as u128));
                let direct = x
                    .pow(segment.trace_size() as u128)
                    .sub(F::ONE)
                    .inv()
                    .unwrap();
                assert_eq!(table.at_v1(segment.trace_log2, row).unwrap(), direct);
            }
            // Exhaust small, padded quotient domains; this includes N != S.
            if stripe.rows <= 8192 {
                for row in 0..stripe.rows {
                    let x = stripe.shift.mul(stripe.root.pow(row as u128));
                    assert_eq!(
                        table.at_v1(segment.trace_log2, row).unwrap(),
                        x.pow(segment.trace_size() as u128)
                            .sub(F::ONE)
                            .inv()
                            .unwrap()
                    );
                }
            }
            assert!(table.at_v1(segment.trace_log2, stripe.rows).is_err());
            assert!(table.at_v1(segment.trace_log2 + 1, 0).is_err());
            assert_eq!(
                MainQuotientDenominatorsV1::payload_bound_v1(segment.trace_log2, stripe).unwrap(),
                core::mem::size_of::<MainQuotientDenominatorsV1>()
                    + period * core::mem::size_of::<F>()
            );
            quotient_rows += stripe.rows;
            inverse_calls += period;
            stripes += 1;
            maximum_period = maximum_period.max(period);
        }
    }
    assert_eq!(layout.registered_segments.len(), 49);
    assert_eq!(quotient_rows, 53_215_232);
    assert_eq!(stripes, 123);
    assert_eq!(inverse_calls, 3_118);
    assert_eq!(quotient_rows - inverse_calls, 53_212_114);
    assert_eq!(maximum_period, 256);
}

#[test]
fn malformed_denominator_stripes_fail_before_allocation_or_indexing() {
    let stripe = main_quotient_stripes::MainQuotientStripeV1::new_v1(18, 21, 1).unwrap();
    let mut malformed = Vec::new();
    for change in 0..9 {
        let mut value = stripe;
        match change {
            0 => value.rows = 0,
            1 => value.rows += 1,
            2 => value.count = 0,
            3 => value.count += 1,
            4 => value.ordinal = value.count,
            5 => value.next_stride += 1,
            6 => value.root = F::ONE,
            7 => value.shift = F::ZERO,
            _ => value.shift = F::ONE,
        }
        malformed.push(value);
    }
    for value in malformed {
        assert!(MainQuotientDenominatorsV1::payload_bound_v1(18, value).is_err());
        assert!(MainQuotientDenominatorsV1::new_v1(18, value).is_err());
    }
    for native_log in [0, MIN_TRACE_LOG2 - 1, 20, u8::MAX] {
        assert!(MainQuotientDenominatorsV1::new_v1(native_log, stripe).is_err());
    }
    let oversized = main_quotient_stripes::MainQuotientStripeV1::new_v1(19, 23, 0).unwrap();
    assert!(MainQuotientDenominatorsV1::new_v1(19, oversized).is_err());
}

#[test]
#[ignore = "constructs the maximum bound credential to compare all49 prover dispatches"]
fn cached_composition_matches_direct_oracle_for_every_registration() {
    use crate::privacy_engines::zk_x509::{
        main_assembly::build_zk_x509_main_trace_assembly_v1,
        relation::{
            ZkX509GovernanceV1,
            release_fixture::{build_zk_x509_release_fixture_v1, reference_statement_context_v1},
        },
    };
    let fixture = build_zk_x509_release_fixture_v1(reference_statement_context_v1(), true)
        .expect("maximum signed credential");
    let trust_anchor = fixture.authoritative_state.trust_anchor();
    let crl = fixture.authoritative_state.crl_record();
    let assembly = build_zk_x509_main_trace_assembly_v1(
        &fixture.statement,
        ZkX509GovernanceV1 {
            trust_anchor: &trust_anchor,
            certificate_policy: fixture.authoritative_state.certificate_policy(),
            crl: &crl,
        },
        &fixture.witness,
    )
    .expect("actual maximum MAIN assembly");
    let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
    assert_eq!(layout.registered_segments.len(), 49);
    let digest = |seed| PrivacyOuterDigestV1::from_bytes([seed; 48]);
    let pre_aux = ZkX509CredentialMainPreAuxV1::fixture_for_test_v1(
        [0x81; 32],
        assembly.verifier_profile.compiled_profile_digest,
        core::array::from_fn(|index| digest(index as u8 + 1)),
    );
    let binding = derive_zk_x509_credential_pre_aux_binding_v1(
        pre_aux,
        digest(0x91),
        digest(0xA1),
        digest(0xB1),
    )
    .unwrap();
    let sha = core::array::from_fn(|segment| {
        ZkX509ShaBatchSegmentBaseSourceV1::new_v1(
            &assembly.sha_schedule,
            &assembly.sha_witnesses,
            segment,
        )
        .unwrap()
    });
    let p256 = P256MainBaseSourceV1::new_v1(&assembly).unwrap();
    let source = MainLog19BoundTraceGroupSourceV1::bind_from_phase_v1(
        &layout, &assembly, sha, p256, binding,
    )
    .unwrap();

    let post_base = binding.main_post_base();
    let providers = [
        MainProverConstraintProviderV1::Log5(
            MainP256Log5ProverConstraintSourceV1::for_main_v1(&layout, &source.p256).unwrap(),
        ),
        MainProverConstraintProviderV1::P256Scalar(
            MainP256ScalarProverConstraintSourceV1::for_main_v1(&layout, &source.p256).unwrap(),
        ),
        MainProverConstraintProviderV1::Projection(
            MainProjectionProverConstraintSourceV1::for_main_v1(
                &layout,
                &fixture.statement,
                post_base,
            )
            .unwrap(),
        ),
        MainProverConstraintProviderV1::Log16(
            MainP256Log16ProverConstraintSourceV1::for_main_v1(&layout, &source.p256).unwrap(),
        ),
        MainProverConstraintProviderV1::Io(
            MainIoProverConstraintSourceV1::for_main_v1(
                &layout,
                &fixture.statement,
                &assembly.io,
                post_base,
            )
            .unwrap(),
        ),
        MainProverConstraintProviderV1::Log19(
            MainLog19ProverConstraintSourceV1::for_main_v1(&layout, &source).unwrap(),
        ),
    ];
    let mut rng = StdRng::from_seed([0x73; 32]);
    let mut checked = 0;
    for registration in layout.registered_segments.iter().copied() {
        let segment = registration.segment;
        let provider = &providers[registration.trace_group];
        let plan = registered_retained_prover_plan_v1(segment, layout.common_lde_log2).unwrap();
        let first = main_quotient_stripes::MainQuotientStripeV1::new_v1(
            segment.trace_log2,
            plan.quotient_coset_log2,
            0,
        )
        .unwrap();
        // These rows are synthetic public field data, not retained witness cells.
        let mut fields = |width| {
            (0..width)
                .map(|_| F::reduce(u128::from(rng.next_u64())))
                .collect::<Vec<_>>()
        };
        let rows = [
            segment.base_width,
            segment.base_width,
            segment.aux_width,
            segment.aux_width,
            segment.fixed_width,
            segment.fixed_width,
        ]
        .map(&mut fields);
        let opening = RegisteredOpenedRowsV1 {
            base_current: &rows[0],
            base_next: &rows[1],
            aux_current: &rows[2],
            aux_next: &rows[3],
        };
        let alphas = (0..segment.constraint_count)
            .map(|_| {
                E::from_coefficients(core::array::from_fn(|_| {
                    F::reduce(u128::from(rng.next_u64()))
                }))
                .unwrap()
            })
            .collect::<Vec<_>>();
        for ordinal in [0, first.count - 1] {
            let stripe = main_quotient_stripes::MainQuotientStripeV1::new_v1(
                segment.trace_log2,
                plan.quotient_coset_log2,
                ordinal,
            )
            .unwrap();
            let table = MainQuotientDenominatorsV1::new_v1(segment.trace_log2, stripe).unwrap();
            for row in [0, 1, stripe.rows / 2, stripe.rows - 1] {
                let x = stripe.shift.mul(stripe.root.pow(row as u128));
                let direct = provider
                    .composition_value_v1(registration, x, opening, &rows[4], &rows[5], &alphas)
                    .unwrap();
                let cached = provider
                    .composition_value_on_stripe_v1(
                        registration,
                        &table,
                        row,
                        opening,
                        &rows[4],
                        &rows[5],
                        &alphas,
                    )
                    .unwrap();
                assert_eq!(
                    cached, direct,
                    "{:?}/{} stripe {ordinal} row {row}",
                    segment.adapter, segment.instance
                );
            }
            assert!(
                provider
                    .composition_value_on_stripe_v1(
                        registration,
                        &table,
                        stripe.rows,
                        opening,
                        &rows[4],
                        &rows[5],
                        &alphas
                    )
                    .is_err()
            );
            assert!(
                provider
                    .composition_value_on_stripe_v1(
                        registration,
                        &table,
                        0,
                        opening,
                        &rows[4],
                        &rows[5],
                        &alphas[1..]
                    )
                    .is_err()
            );
        }
        checked += 1;
    }
    assert_eq!(checked, 49);
}
