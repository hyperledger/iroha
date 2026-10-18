// Explicit private SHA segment and recurrence scratch ownership.

#[test]
fn private_sha_product_owners_clear_explicit_storage_on_success_error_and_unwind() {
    use super::super::private_table::inspection;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    for outcome in 0..3 {
        let (result, observations) = inspection::observe_v1(|| {
            catch_unwind(AssertUnwindSafe(
                || -> Result<(), ZkX509ShaCallBusStarkErrorV1> {
                    let original = ZkX509ShaSegmentProductStateV1::one_v1();
                    let mut retained = original.clone();
                    retained.source_products[0] = F(79);
                    retained.copy_from_v1(&original);
                    assert_eq!(retained, original);
                    assert_eq!(
                        format!("{retained:?}"),
                        "ZkX509ShaSegmentProductStateV1 { <private products redacted> }"
                    );
                    let mut scratch = ShaCallBindingScratchV1::zero_v1();
                    scratch.base.fill(F(17));
                    assert!(scratch.set_factor_v1(Some(F(79))));
                    assert_eq!(scratch.factor, F(79));
                    assert!(!scratch.set_factor_v1(None));
                    assert_eq!(
                        format!("{scratch:?}"),
                        "ShaCallBindingScratchV1 { <private row redacted> }"
                    );
                    match outcome {
                        0 => Ok(()),
                        1 => Err(ZkX509ShaCallBusStarkErrorV1::Resource),
                        2 => panic!("deliberate private-owner unwind"),
                        _ => unreachable!(),
                    }
                },
            ))
        });
        match outcome {
            0 => assert!(matches!(result, Ok(Ok(())))),
            1 => assert!(matches!(
                result,
                Ok(Err(ZkX509ShaCallBusStarkErrorV1::Resource))
            )),
            2 => assert!(result.is_err()),
            _ => unreachable!(),
        }
        assert_eq!(
            observations.iter().map(|item| item.cells).sum::<usize>(),
            138
        );
        assert_eq!(
            observations
                .iter()
                .map(|item| item.nonzero_before)
                .sum::<usize>(),
            138
        );
        assert!(observations.iter().all(|item| item.nonzero_after == 0));
    }
}

#[test]
fn actual_sha_binding_error_clears_private_recurrence_owners_and_keeps_borrowed_input() {
    use super::super::private_table::inspection;

    let schedule = ZkX509ShaCallScheduleV1::new(ZkX509ShaCallPublicShapeV1 {
        disclosed_attributes: 4,
    })
    .unwrap();
    let manifest = schedule.calls[CRL_ISSUER_SPKI_CALL_V1];
    let witness = witness_for(manifest);
    let source = build_zk_x509_sha_batch_call_base_source_v1(manifest, &witness, 4).unwrap();
    let mut consumer = source.rfc_consumer.unwrap();
    // The real fixed-row builder fails at its checked raw-message end once
    // input rows are reached; no production fault injection is introduced.
    assert!(consumer.message_prefix_bytes > 0);
    consumer.message_capacity_bytes = usize::MAX;
    let word = source
        .word
        .bind_challenges_for_test_v1(word_challenges())
        .unwrap();
    let initial = ZkX509ShaSegmentProductStateV1::one_v1();
    let (result, observations) = inspection::observe_v1(|| {
        finish_zk_x509_sha_batch_call_binding_v1(
            manifest,
            word,
            Some(consumer),
            challenges(),
            &rfc_challenges(),
            &initial,
        )
    });
    assert!(matches!(
        result,
        Err(ZkX509ShaCallBusStarkErrorV1::Resource)
    ));
    assert_eq!(initial, ZkX509ShaSegmentProductStateV1::one_v1());
    assert!(observations.iter().all(|item| item.nonzero_after == 0));
    assert!(
        observations
            .iter()
            .any(|item| item.cells == 89 && item.nonzero_before != 0)
    );
    assert!(observations.iter().filter(|item| item.cells == 16).count() >= 2);
    assert!(observations.iter().filter(|item| item.cells == 4).count() >= 4);
}

#[test]
fn invalid_sha_raw_length_is_rejected_before_reading_private_word_rows() {
    struct NoPrivateRead;
    impl ShaWordCapacityBaseRowsV1 for NoPrivateRead {
        fn message_len_v1(&self) -> usize {
            10
        }
        fn logical_rows_v1(&self) -> usize {
            1
        }
        fn base_row_v1(
            &self,
            _: usize,
        ) -> Result<&[F; SHA_WORD_CAPACITY_BASE_WIDTH_V1], ZkX509ShaWordStarkErrorV1> {
            panic!("private row must not be read on an invalid public shape")
        }
        fn fixed_row_v1(
            &self,
            _: usize,
        ) -> Result<&[F; SHA_WORD_CAPACITY_FIXED_WIDTH_V1], ZkX509ShaWordStarkErrorV1> {
            panic!("fixed row is unused by base widening")
        }
    }
    let consumer = ZkX509ShaRfcConsumerChannelsV1 {
        role: ZkX509Rfc5280OutputRoleV1::IssuerSpkiSha,
        message_channel: 24,
        length_channel: None,
        message_prefix_bytes: usize::MAX,
        message_capacity_bytes: 91,
    };
    assert!(matches!(
        widened_sha_batch_base_row_v1(&NoPrivateRead, Some(consumer), 0),
        Err(ZkX509ShaCallBusStarkErrorV1::LengthOrPadding)
    ));
}

#[test]
fn private_sha_endpoint_clones_clear_storage_without_exposing_debug_products() {
    use super::super::private_table::inspection;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    let state = ZkX509ShaSegmentProductStateV1::one_v1();
    let endpoint = state.terminal_v1(3).unwrap();
    assert!(core::mem::needs_drop::<ZkX509ShaSegmentPrivateEndpointV1>());
    assert_eq!(
        format!("{endpoint:?}"),
        "ZkX509ShaSegmentPrivateEndpointV1 { <private products redacted> }"
    );
    for outcome in 0..3 {
        let (result, observations) = inspection::observe_v1(|| {
            catch_unwind(AssertUnwindSafe(
                || -> Result<(), ZkX509ShaCallBusStarkErrorV1> {
                    let copy = endpoint.clone();
                    let second = copy.clone();
                    assert_eq!(copy, second);
                    match outcome {
                        0 => Ok(()),
                        1 => Err(ZkX509ShaCallBusStarkErrorV1::Resource),
                        _ => panic!("deliberate private endpoint unwind"),
                    }
                },
            ))
        });
        assert_eq!(
            observations.iter().map(|item| item.cells).sum::<usize>(),
            32
        );
        assert_eq!(
            observations
                .iter()
                .map(|item| item.nonzero_before)
                .sum::<usize>(),
            32
        );
        assert!(observations.iter().all(|item| item.nonzero_after == 0));
        match outcome {
            0 => assert!(matches!(result, Ok(Ok(())))),
            1 => assert!(matches!(
                result,
                Ok(Err(ZkX509ShaCallBusStarkErrorV1::Resource))
            )),
            _ => assert!(result.is_err()),
        }
    }
    assert_eq!(endpoint.rfc_stream_products, [[F::ONE; 4]; 4]);
    let (result, observations) = inspection::observe_v1(|| state.terminal_v1(4));
    assert!(matches!(
        result,
        Err(ZkX509ShaCallBusStarkErrorV1::Topology)
    ));
    assert!(
        observations.is_empty(),
        "reject a bad public segment before copying private products"
    );
}
