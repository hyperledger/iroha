// Native bridge custody and exact constant-column AIR controls.

#[test]
fn private_sha_union_centers_validate_every_segment_and_preserve_zero_factors() {
    let mut centers = ZkX509ShaUnionCentersV1::empty_v1();
    assert!(centers.validate_v1().is_err());
    let streams: [[F; 4]; 4] = core::array::from_fn(|stream| {
        core::array::from_fn(|lane| F(2 + (stream * 4 + lane) as u64))
    });
    for segment in 0..4 {
        centers.install_segment_v1(segment, &streams).unwrap();
        for lane in 0..4 {
            assert_eq!(
                centers.products_v1()[segment][lane],
                streams
                    .iter()
                    .fold(F::ONE, |product, stream| product.mul(stream[lane]))
            );
        }
        assert!(centers.install_segment_v1(segment, &streams).is_err());
        assert_eq!(centers.validate_v1().is_ok(), segment == 3);
    }
    assert!(centers.install_segment_v1(4, &streams).is_err());
    let mut invalid = ZkX509ShaUnionCentersV1::empty_v1();
    let mut malformed = streams;
    malformed[3][3] = F(u64::MAX);
    assert!(invalid.install_segment_v1(0, &malformed).is_err());
    assert_eq!(invalid.products, [[F::ZERO; 4]; 4]);
    assert_eq!(invalid.present, 0);
    for segment in 0..4 {
        let mut zero = streams;
        zero[segment][segment] = F::ZERO;
        invalid.install_segment_v1(segment, &zero).unwrap();
        assert_eq!(invalid.products[segment][segment], F::ZERO);
    }
    invalid.validate_v1().unwrap();
    assert!(core::mem::needs_drop::<ZkX509ShaUnionCentersV1>());
    assert_eq!(
        format!("{centers:?}"),
        "ZkX509ShaUnionCentersV1 { <private products redacted> }"
    );
}

#[test]
fn private_sha_union_centers_clear_owned_cells_on_success_error_and_unwind() {
    use super::super::private_table::inspection;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    for outcome in 0..3 {
        let (result, observations) = inspection::observe_v1(|| {
            catch_unwind(AssertUnwindSafe(
                || -> Result<(), ZkX509Rfc5280StarkErrorV1> {
                    let owner = ZkX509ShaUnionCentersV1::identity_fixture_v1();
                    assert_eq!(owner.products_v1(), &[[F::ONE; 4]; 4]);
                    match outcome {
                        0 => Ok(()),
                        1 => Err(ZkX509Rfc5280StarkErrorV1::Source),
                        _ => panic!("deliberate bridge-owner unwind"),
                    }
                },
            ))
        });
        match outcome {
            0 => assert!(matches!(result, Ok(Ok(())))),
            1 => assert!(matches!(result, Ok(Err(ZkX509Rfc5280StarkErrorV1::Source)))),
            _ => assert!(result.is_err()),
        }
        assert_eq!(
            observations.iter().map(|item| item.cells).sum::<usize>(),
            16
        );
        assert_eq!(
            observations
                .iter()
                .map(|item| item.nonzero_before)
                .sum::<usize>(),
            16
        );
        assert!(observations.iter().all(|item| item.nonzero_after == 0));
    }
}

#[test]
fn all_sixteen_native_bridge_columns_are_constant_and_air_rejects_coordinated_drift() {
    let trace = canonical_trace_v1();
    let material = build_zk_x509_rfc5280_stark_base_material_v1(&trace).unwrap();
    let mut centers = ZkX509ShaUnionCentersV1::empty_v1();
    for segment in 0..4 {
        let streams = core::array::from_fn(|stream| {
            core::array::from_fn(|lane| F(2 + (segment * 100 + stream * 4 + lane) as u64))
        });
        centers.install_segment_v1(segment, &streams).unwrap();
    }
    let provider = ZkX509Rfc5280StarkColumnProviderV1::with_centers_v1(
        &material,
        der_challenges_v1(),
        challenges_v1(),
        centers,
    )
    .unwrap();
    let claims = provider
        .terminal_claims_v1()
        .expect("valid RFC union fixture private products");
    let offset = RFC5280_RESIDUE_SECTIONS_V1[..12]
        .iter()
        .map(|(_, count)| count)
        .sum::<usize>()
        + 24;
    for segment in 0..4 {
        for lane in 0..4 {
            let local = 4 * segment + lane;
            let column = provider
                .build_aux_column_v1(AUX_SHA_UNION_CENTERS + local)
                .unwrap();
            assert_eq!(column.len(), ZK_X509_RFC5280_STARK_TRACE_SIZE_V1);
            assert!(
                column
                    .iter()
                    .all(|value| *value == provider.sha_union_centers_v1()[segment][lane])
            );
            for row in [
                0,
                1,
                480_287,
                521_951,
                ZK_X509_RFC5280_STARK_TRACE_SIZE_V1 - 2,
                ZK_X509_RFC5280_STARK_TRACE_SIZE_V1 - 1,
            ] {
                let current = provider.base_row_v1(row).unwrap();
                let next = provider
                    .base_row_v1((row + 1) % ZK_X509_RFC5280_STARK_TRACE_SIZE_V1)
                    .unwrap();
                let fixed = provider.fixed_row_v1(row).unwrap();
                let continue_gate = F(u64::from(row + 1 != ZK_X509_RFC5280_STARK_TRACE_SIZE_V1));
                assert_eq!(fixed[FIX_CONTINUE], continue_gate);
                let mut aux = neutral_aux_v1();
                for (segment, values) in provider.sha_union_centers_v1().iter().enumerate() {
                    aux[AUX_SHA_UNION_CENTERS + 4 * segment
                        ..AUX_SHA_UNION_CENTERS + 4 * segment + 4]
                        .copy_from_slice(values);
                }
                let evaluate = |next_aux: &ZkX509Rfc5280StarkAuxRowV1| {
                    evaluate_zk_x509_rfc5280_stark_residues_v1(
                        &current,
                        &next,
                        &aux,
                        next_aux,
                        &fixed,
                        der_challenges_v1(),
                        challenges_v1(),
                        claims,
                    )
                    .unwrap()[offset + local]
                };
                assert_eq!(evaluate(&aux), F::ZERO);
                let mut changed = aux;
                changed[AUX_SHA_UNION_CENTERS + local] =
                    changed[AUX_SHA_UNION_CENTERS + local].add(F::ONE);
                assert_eq!(evaluate(&changed), continue_gate);
            }
        }
    }
    // A final-row-only mutation can satisfy a selected endpoint equation with
    // a coordinated consumer change, but the preceding row still rejects it.
    // The complete joined-plan tests independently bind each endpoint factor.
    let last = ZK_X509_RFC5280_STARK_TRACE_SIZE_V1 - 1;
    assert_eq!(provider.fixed_row_v1(last).unwrap()[FIX_CONTINUE], F::ZERO);
}
