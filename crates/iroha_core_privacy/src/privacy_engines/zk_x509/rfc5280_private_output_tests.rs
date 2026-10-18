// Private RFC endpoint controls, included inside the RFC test module.

#[test]
fn output_normalization_matches_each_fixed_role_channel_offset_and_direction() {
    let challenges = challenges_v1();
    for count in 0..=4_u8 {
        let mut shape = ZkX509Rfc5280StarkShapeV1::default();
        shape.disclosed_attribute_count = count;
        for index in 0..usize::from(count) {
            shape.disclosed_attribute_indices[index] = index as u8;
        }
        let schedule = compile_zk_x509_rfc5280_stark_fixed_schedule_v1(shape).unwrap();
        let mut census = [[0_usize; OUTPUT_ROLE_COUNT_V1]; 2];
        for (ordinal, entry) in schedule.output_topology.iter().enumerate() {
            let role = output_role_index_v1(entry.role);
            assert_eq!(entry.endpoint_instance, 0);
            assert_eq!(
                u64::from(entry.consumer_endpoint_role),
                OUTPUT_CONSUMER_ENDPOINTS_V1[role]
            );
            let mut endpoints = [[F::ZERO; ZK_X509_RFC5280_STARK_BASE_WIDTH_V1]; 2];
            for (side, consumer) in [false, true].into_iter().enumerate() {
                let family = if consumer {
                    ZkX509Rfc5280StarkFamilyV1::OutputConsumer
                } else {
                    ZkX509Rfc5280StarkFamilyV1::OutputProducer
                };
                let fixed = schedule
                    .fixed_row(schedule.starts[family as usize] + ordinal)
                    .unwrap();
                assert_eq!(fixed[FIX_REQUIRED_ACTIVE], F::ONE);
                assert_eq!(
                    fixed[output_role_fixed_selector_column_v1(role, consumer)],
                    F::ONE
                );
                assert_eq!(
                    fixed[FIX_OUTPUT_ROLE_PRODUCTS..FIX_OUTPUT_ROLE_PRODUCTS + 18]
                        .iter()
                        .filter(|value| **value == F::ONE)
                        .count(),
                    1
                );
                let row = &mut endpoints[side];
                row[BASE_ACTIVE] = F::ONE;
                row[BASE_VALUE] = F((u64::from(entry.channel) + u64::from(entry.offset)) % 256);
                for (column, value) in metadata_columns_v1()
                    .into_iter()
                    .zip(&fixed[FIX_EXPECTED..FIX_EXPECTED + 6])
                {
                    row[column] = *value;
                }
                assert_eq!(output_metadata_residues_v1(row, &fixed), [F::ZERO; 6]);
                let mut omitted = *row;
                omitted[BASE_ACTIVE] = F::ZERO;
                assert!(
                    private_geometry_residues_v1(&omitted, &omitted, &fixed)
                        .iter()
                        .any(|value| *value != F::ZERO)
                );
                census[side][role] += 1;
            }
            for lane in 0..4 {
                assert_eq!(
                    output_role_product_factor_v1(&endpoints[0], role, false, lane, &challenges),
                    output_role_product_factor_v1(&endpoints[1], role, true, lane, &challenges)
                );
                // Raw endpoint factors differ, explaining why raw equality was invalid.
                assert_ne!(
                    output_row_factor_v1(&endpoints[0], lane, &challenges),
                    output_row_factor_v1(&endpoints[1], lane, &challenges)
                );
                for column in [BASE_ROLE, BASE_INSTANCE, BASE_OFFSET, BASE_VALUE] {
                    let mut wrong = endpoints[0];
                    wrong[column] = wrong[column].add(F::ONE);
                    assert_ne!(
                        output_role_product_factor_v1(&wrong, role, false, lane, &challenges),
                        output_role_product_factor_v1(&endpoints[1], role, true, lane, &challenges)
                    );
                }
            }
        }
        assert_eq!(census[0], census[1]);
        assert!(census[0].iter().all(|count| *count > 0));
    }
}

#[test]
fn actual_rfc_output_witnesses_have_exact_normalized_receiver_products() {
    let trace = canonical_trace_v1();
    let shape = build_zk_x509_rfc5280_stark_shape_v1(&trace).unwrap();
    let schedule = compile_zk_x509_rfc5280_stark_fixed_schedule_v1(shape).unwrap();
    let roles = output_roles_v1(&trace).unwrap();
    let witnesses = rfc5280_io_witnesses_v1(&trace, 0).unwrap();
    let challenges = challenges_v1();
    let mut producer = [[F::ONE; 4]; OUTPUT_ROLE_COUNT_V1];
    let mut consumer = producer;
    let mut ordinal = 0;
    for (role, witness) in roles.into_iter().zip(witnesses) {
        assert_eq!(witness.declaration.consumers.len(), 1);
        assert_eq!(witness.consumer_values.len(), 1);
        assert_eq!(
            witness.producer_value.len(),
            witness.consumer_values[0].len()
        );
        let role_index = output_role_index_v1(role);
        for (offset, (left, right)) in witness
            .producer_value
            .iter()
            .zip(&witness.consumer_values[0])
            .enumerate()
        {
            let entry = schedule.output_topology[ordinal];
            assert_eq!(entry.role, role);
            assert_eq!(entry.channel, witness.declaration.channel);
            assert_eq!(entry.offset as usize, offset);
            let source = output_base_row_v1(
                role,
                entry.channel,
                witness.declaration.producer,
                offset,
                *left,
                true,
            )
            .unwrap();
            let sink = output_base_row_v1(
                role,
                entry.channel,
                witness.declaration.consumers[0],
                offset,
                *right,
                false,
            )
            .unwrap();
            for lane in 0..4 {
                producer[role_index][lane] = producer[role_index][lane].mul(
                    output_role_product_factor_v1(&source, role_index, false, lane, &challenges),
                );
                consumer[role_index][lane] =
                    consumer[role_index][lane].mul(output_row_factor_v1(&sink, lane, &challenges));
            }
            ordinal += 1;
        }
    }
    assert_eq!(ordinal, schedule.output_topology.len());
    assert_eq!(producer, consumer);
    assert_eq!(
        consumer,
        zk_x509_rfc5280_output_terminals_v1(&trace, &challenges)
            .unwrap()
            .consumer
    );
}

#[test]
fn normalized_output_products_and_private_endpoints_support_zero_factors() {
    let mut challenges = challenges_v1();
    let mut row = [F::ZERO; ZK_X509_RFC5280_STARK_BASE_WIDTH_V1];
    row[BASE_ROLE] = F(1);
    row[BASE_INSTANCE] = F(2);
    row[BASE_OFFSET] = F(3);
    row[BASE_VALUE] = F(7);
    for lane in 0..4 {
        let partial = output_role_product_factor_v1(&row, 0, false, lane, &challenges)
            .sub(F(80).mul(challenges.tuple[lane][0]));
        challenges.tuple[lane][0] = F::ZERO.sub(partial).mul(F(80).inv().unwrap());
        assert_eq!(
            output_role_product_factor_v1(&row, 0, false, lane, &challenges),
            F::ZERO
        );
    }
    challenges.validate().unwrap();
    let mut product = [F::ONE; 4];
    for value in [7, 9, 11] {
        row[BASE_VALUE] = F(value);
        for lane in 0..4 {
            product[lane] = product[lane].mul(output_role_product_factor_v1(
                &row, 0, false, lane, &challenges,
            ));
        }
    }
    assert_eq!(product, [F::ZERO; 4]);
    let claims = terminal_claims_v1();
    let mut aux = terminal_aux_v1(claims);
    for consumer in [false, true] {
        for lane in 0..4 {
            aux[output_role_aux_column_v1(0, consumer, lane)] = F::ZERO;
        }
    }
    assert!(
        evaluate_zk_x509_rfc5280_terminal_claim_residues_v1(F::ONE, &aux, claims)
            .unwrap()
            .iter()
            .all(|v| *v == F::ZERO)
    );
}

#[test]
fn normalized_output_factor_is_affine_in_arbitrary_fp4_openings() {
    use crate::privacy_engines::transparent_stark::GoldilocksFp4V1 as E;
    let challenges = challenges_v1();
    let row = core::array::from_fn(|i| E::canonical([i as u64 + 1, 3, 5, 7]).unwrap());
    for role in 0..OUTPUT_ROLE_COUNT_V1 {
        for lane in 0..4 {
            let c = challenges.tuple[lane];
            let expected = E::from_base(
                F(80)
                    .mul(c[0])
                    .add(F(OUTPUT_CONSUMER_ENDPOINTS_V1[role]).mul(c[3])),
            )
            .add(row[BASE_ROLE].mul_base(c[1]))
            .add(row[BASE_INSTANCE].mul_base(c[2]))
            .add(row[BASE_OFFSET].mul_base(c[5]))
            .add(row[BASE_VALUE].mul_base(c[6]));
            assert_eq!(
                output_role_product_factor_v1(&row, role, false, lane, &challenges),
                expected
            );
            assert_eq!(
                output_role_product_factor_v1(&row, role, true, lane, &challenges),
                output_row_factor_v1(&row, lane, &challenges)
            );
        }
    }
}
