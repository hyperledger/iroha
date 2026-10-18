//! Real-cell cleanup at the assembly's private ownership transfers.

use super::*;
use crate::privacy_engines::zk_x509::{io_air::ZkX509IoEndpointV1, private_table::inspection};

fn witness() -> ZkX509IoChannelWitnessV1 {
    let endpoint = ZkX509IoEndpointV1 {
        role: ZkX509IoSegmentRoleV1::Projection,
        instance: 0,
    };
    ZkX509IoChannelWitnessV1 {
        declaration: ZkX509IoChannelDeclarationV1 {
            channel: 3,
            producer: endpoint,
            consumers: vec![endpoint; 2],
            byte_len: 3,
            public_value: None,
        },
        producer_value: vec![11; 3],
        consumer_values: vec![vec![13; 3]; 2],
    }
}

#[test]
fn owned_io_material_clears_actual_cells_on_success_error_unwind_and_dedup() {
    for mode in 0..3 {
        let witness = witness();
        let access = IoAccessV1 {
            channel: F(3),
            offset: F(7),
            value: F(9),
            is_write: F::ONE,
            endpoint: witness.declaration.producer,
        };
        let material = ZkX509MainIoBaseMaterialV1 {
            declarations: vec![witness.declaration.clone()],
            witnesses: vec![witness],
            logical_active_rows: 2,
            execution: vec![access; 2],
            sorted: vec![access; 2],
        };
        let (result, observed) = inspection::observe_v1(|| {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut material = material;
                if mode == 0 {
                    material.zeroize_private_v1();
                    assert_eq!(material.logical_active_rows, 2);
                    assert!(material.witnesses.is_empty());
                    assert!(material.execution.is_empty() && material.sorted.is_empty());
                    Ok(())
                } else if mode == 1 {
                    Err(())
                } else {
                    panic!("injected assembly ownership unwind")
                }
            }))
        });
        assert_eq!(result.is_err(), mode == 2);
        assert_eq!(
            observed
                .iter()
                .map(|item| item.nonzero_before)
                .sum::<usize>(),
            25
        );
        assert!(observed.iter().all(|item| item.nonzero_after == 0));
    }
    let ((), observed) = inspection::observe_v1(|| {
        // The actual shared-prefix deduplication drops skipped witnesses and
        // any unconsumed iterator tail before a complete IO material exists.
        let mut deduplicated = vec![witness(), witness(), witness()].into_iter().skip(1);
        drop(deduplicated.next());
        drop(deduplicated);
    });
    assert_eq!(
        observed
            .iter()
            .map(|item| item.nonzero_before)
            .sum::<usize>(),
        27
    );
    assert!(observed.iter().all(|item| item.nonzero_after == 0));
}

#[test]
fn owned_sha_message_clears_when_schedule_rejects_before_transfer() {
    let schedule = ZkX509ShaCallScheduleV1::new(ZkX509ShaCallPublicShapeV1 {
        disclosed_attributes: 2,
    })
    .unwrap();
    let (result, observed) =
        inspection::observe_v1(|| sha_witness_v1(&schedule, usize::MAX, vec![0xa5; 33]));
    assert!(result.is_err());
    assert_eq!(
        observed
            .iter()
            .map(|item| item.nonzero_before)
            .sum::<usize>(),
        33
    );
    assert!(observed.iter().all(|item| item.nonzero_after == 0));
}

#[test]
fn owned_projection_message_list_clears_late_hash_error_and_unwind() {
    let (statement, witness) = super::super::projection_air::tests::fixture();
    let mut trace = build_zk_x509_projection_trace_v1(&statement, &witness).unwrap();
    let disclosed = statement.disclosed_attributes.len();
    let expected = projection_sha_messages_v1(disclosed, &trace).unwrap();
    let private_bytes = expected.iter().map(Vec::len).sum::<usize>();
    assert!(private_bytes > 0);
    let (result, observed) = inspection::observe_v1(|| {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _messages = expected;
            panic!("injected message-list unwind");
        }))
    });
    assert!(result.is_err());
    assert_eq!(
        observed.iter().map(|item| item.cells).sum::<usize>(),
        private_bytes
    );
    assert!(observed.iter().any(|item| item.nonzero_before > 0));
    assert!(observed.iter().all(|item| item.nonzero_after == 0));
    trace.io_channels.last_mut().unwrap().value[0] ^= 1;
    let (result, observed) =
        inspection::observe_v1(|| projection_sha_messages_v1(disclosed, &trace));
    assert!(result.is_err());
    assert_eq!(
        observed.iter().map(|item| item.cells).sum::<usize>(),
        private_bytes
    );
    assert!(observed.iter().all(|item| item.nonzero_after == 0));
}

#[test]
fn extracted_projection_witness_clears_partial_disclosures_and_owned_success() {
    let mut fixture = super::super::relation::tests::fixture();
    let trace = build_zk_x509_rfc5280_trace_v1(
        &fixture.witness.certificate_chain_der,
        &fixture.witness.crl_der,
        rfc_statement_with_crl_number_v1(&fixture.statement, fixture.crl.crl_number),
    )
    .unwrap();
    let expected = projection_witness_v1(&fixture.statement, &trace, &fixture.witness).unwrap();
    assert_eq!(expected.chain_spki_der.len(), trace.certificates.len());
    assert_eq!(expected.leaf_serial, trace.certificates[0].serial);
    assert_eq!(
        expected.attribute_salts[0],
        fixture.witness.attribute_openings[0].salt
    );
    let private_cells = expected.chain_spki_der.iter().map(Vec::len).sum::<usize>()
        + expected.leaf_serial.len()
        + expected
            .disclosed_attribute_values
            .iter()
            .map(Vec::len)
            .sum::<usize>()
        + expected.attribute_salts.len();
    for unwind in [false, true] {
        let owned = expected.clone();
        let (result, observed) = inspection::observe_v1(|| {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _owned = owned;
                if unwind {
                    panic!("injected projection-witness transfer unwind");
                }
            }))
        });
        assert_eq!(result.is_err(), unwind);
        assert_eq!(
            observed.iter().map(|item| item.cells).sum::<usize>(),
            private_cells
        );
        assert!(observed.iter().any(|item| item.nonzero_before > 0));
        assert!(observed.iter().all(|item| item.nonzero_after == 0));
    }
    let mut second = fixture.statement.disclosed_attributes[0];
    second.index = 1;
    fixture.statement.disclosed_attributes.push(second);
    fixture
        .witness
        .attribute_openings
        .push(fixture.witness.attribute_openings[0]);
    let first_cells = expected.disclosed_attribute_values[0].len() + 1;
    let (result, observed) = inspection::observe_v1(|| {
        projection_witness_v1(&fixture.statement, &trace, &fixture.witness)
    });
    assert!(matches!(result, Err(ZkX509MainAssemblyErrorV1::Source)));
    assert_eq!(
        observed.iter().map(|item| item.cells).sum::<usize>(),
        first_cells
    );
    assert!(observed.iter().any(|item| item.nonzero_before > 0));
    assert!(observed.iter().all(|item| item.nonzero_after == 0));
}

#[test]
fn p256_assembly_inputs_clear_partial_signature_error_and_later_owner_unwind() {
    let fixture = super::super::relation::tests::fixture();
    let mut trace = build_zk_x509_rfc5280_trace_v1(
        &fixture.witness.certificate_chain_der,
        &fixture.witness.crl_der,
        rfc_statement_with_crl_number_v1(&fixture.statement, fixture.crl.crl_number),
    )
    .unwrap();
    let schedule = ZkX509ShaCallScheduleV1::new(ZkX509ShaCallPublicShapeV1 {
        disclosed_attributes: fixture.statement.disclosed_attributes.len(),
    })
    .unwrap();
    let calls = core::array::from_fn(|index| ZkX509ShaCallWitnessV1 {
        role: schedule.call(index).unwrap().role,
        message: Vec::new(),
        digest: [0x35; 32],
    });
    zeroize_words_v1(&mut trace.certificates[1].signature.encoded);
    trace.certificates[1].signature.encoded = vec![0];
    let (result, observed) =
        inspection::observe_v1(|| build_p256_material_v1(&fixture.witness, &trace, &calls));
    assert!(matches!(result, Err(ZkX509MainAssemblyErrorV1::Source)));
    // Exactly the first retained five-word tuple was written before the
    // second signature failed parsing; the raw temporary Vec must clear it.
    assert_eq!(observed.iter().map(|item| item.cells).sum::<usize>(), 160);
    assert!(observed.iter().any(|item| item.nonzero_before > 0));
    assert!(observed.iter().all(|item| item.nonzero_after == 0));

    let input = P256EcdsaWitnessV1 {
        public_key_x_be: [11; 32],
        public_key_y_be: [13; 32],
        r_be: [17; 32],
        s_be: [19; 32],
        digest_be: [23; 32],
    };
    for mode in 0..3 {
        let (result, observed) = inspection::observe_v1(|| {
            std::panic::catch_unwind(|| {
                let owned = MainP256WitnessesV1 {
                    selected: [input; P256_SIGNATURES_V1],
                    optional: MainOptionalP256SelectionV1(P256OptionalCertificateSelectionV1 {
                        active: F::ONE,
                        real: input,
                        selected: input,
                    }),
                };
                assert_eq!(owned.selected[4], input);
                if mode == 0 {
                    Ok(())
                } else if mode == 1 {
                    Err(())
                } else {
                    panic!("injected after P-256 inputs and before IO transfer");
                }
            })
        });
        assert_eq!(result.is_err(), mode == 2);
        assert_eq!(
            observed
                .iter()
                .map(|item| item.nonzero_before)
                .sum::<usize>(),
            1121
        );
        assert!(observed.iter().all(|item| item.nonzero_after == 0));
    }
}
