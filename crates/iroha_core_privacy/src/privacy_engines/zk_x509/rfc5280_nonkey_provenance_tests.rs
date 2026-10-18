// Post-repair regression for the original non-key coherent-shadow diagnostic.
// The earlier accepted shadow and native logs remain in the remediation artifacts.
// Complete Name census and string policy have separate controls; this rejects an
// unbound output replacement, not every malformed RFC 5280 document.

#[test]
fn nonkey_output_shadow_bytes_reject_without_changing_authenticated_byte_endpoint() {
    for trace in [canonical_trace_v1(), spki_maximum_release_trace_v1()] {
        let material = build_zk_x509_rfc5280_stark_base_material_v1(&trace).unwrap();
        let role = ZkX509Rfc5280OutputRoleV1::Projection;
        for slot in 0..usize::from(material.schedule.shape.disclosed_attribute_count) {
            let ordinal = material
                .schedule
                .output_topology
                .iter()
                .position(|entry| entry.channel == 6 + 2 * slot as u32 && entry.offset == 0)
                .unwrap();
            let index = material.schedule.starts
                [ZkX509Rfc5280StarkFamilyV1::OutputProducer as usize]
                + ordinal;
            let row = material.base_row(index).unwrap();
            let next = material.base_row(index + 1).unwrap();
            let fixed = material.fixed_row(index).unwrap();
            let (aux, after) = spki_output_aux_fixture_v1(&row, &fixed, role);
            let evaluate = |row: &ZkX509Rfc5280StarkBaseRowV1,
                            aux: &ZkX509Rfc5280StarkAuxRowV1,
                            after: &ZkX509Rfc5280StarkAuxRowV1| {
                evaluate_zk_x509_rfc5280_local_residues_v1(
                    row,
                    &next,
                    aux,
                    after,
                    &fixed,
                    der_challenges_v1(),
                    &challenges_v1(),
                )
                .unwrap()
            };
            assert!(evaluate(&row, &aux, &after).iter().all(|v| *v == F::ZERO));
            assert_eq!(row[BASE_SERIAL_BYTE_QUERY_ACTIVE], F::ONE);
            let mut changed = row;
            let value = row[BASE_VALUE].0 as u8 ^ 1;
            changed[BASE_VALUE] = F(u64::from(value));
            write_u8_bits_v1(&mut changed, BASE_BYTE_BITS, value);
            populate_degree_normalization_helpers_v1(&mut changed, &fixed);
            let (repaired_aux, repaired_after) = spki_output_aux_fixture_v1(&changed, &fixed, role);
            let mut products_only = after;
            for lane in 0..4 {
                let column = output_role_aux_column_v1(output_role_index_v1(role), false, lane);
                products_only[column] = repaired_after[column];
            }
            assert!(
                evaluate(&changed, &aux, &products_only)
                    .iter()
                    .any(|v| *v != F::ZERO)
            );
            assert!(
                evaluate(&changed, &repaired_aux, &repaired_after)
                    .iter()
                    .all(|v| *v == F::ZERO)
            );
            let consumer_index = material.schedule.starts
                [ZkX509Rfc5280StarkFamilyV1::OutputConsumer as usize]
                + ordinal;
            let mut consumer = material.base_row(consumer_index).unwrap();
            consumer[BASE_VALUE] = changed[BASE_VALUE];
            for lane in 0..4 {
                assert_ne!(
                    (
                        after[AUX_SERIAL_BYTE_LOOKUP_ACCUMULATOR + lane],
                        after[AUX_SERIAL_BYTE_ZERO_ACCUMULATOR + lane]
                    ),
                    (
                        repaired_after[AUX_SERIAL_BYTE_LOOKUP_ACCUMULATOR + lane],
                        repaired_after[AUX_SERIAL_BYTE_ZERO_ACCUMULATOR + lane]
                    )
                );
                assert_eq!(
                    output_role_product_factor_v1(
                        &changed,
                        output_role_index_v1(role),
                        false,
                        lane,
                        &challenges_v1()
                    ),
                    output_role_product_factor_v1(
                        &consumer,
                        output_role_index_v1(role),
                        true,
                        lane,
                        &challenges_v1()
                    )
                );
            }
        }
    }
}
