#[cfg(test)]
mod validation_fee_policy_proof_bridge_tests {
    use super::*;
    use std::ptr;

    fn native_checkpoint(height: u64) -> &'static [u8] {
        match height {
            1 => include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../fixtures/sumeragi/native-finality/genesis-checkpoint.nrt"
            )),
            2 => include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../fixtures/sumeragi/native-finality/height-2-checkpoint.nrt"
            )),
            _ => panic!("fixture checkpoint height"),
        }
    }
    #[test]
    fn request_encoder_derives_height_from_complete_native_checkpoint() {
        for height in 1..=2 {
            let checkpoint = native_checkpoint(height);
            let decoded_checkpoint =
                iroha_data_model::sumeragi_finality::SumeragiFinalityCheckpoint::decode_canonical(
                    checkpoint,
                )
                .unwrap();
            assert_eq!(decoded_checkpoint.height(), height);
            assert_eq!(decoded_checkpoint.encode_canonical().unwrap(), checkpoint);
            let request = validation_fee_current_policy_proof_request_v1(checkpoint).unwrap();
            let decoded: ValidationFeeCurrentPolicyProofRequestV1 =
                decode_from_bytes(&request).unwrap();
            assert_eq!(
                decoded,
                ValidationFeeCurrentPolicyProofRequestV1 {
                    version: VALIDATION_FEE_POLICY_PROOF_VERSION_V1,
                    trusted_checkpoint_height: height,
                }
            );
            let mut output = ptr::null_mut();
            let mut length = 0;
            let code = unsafe {
                connect_norito_validation_fee_current_policy_proof_request_v1(
                    checkpoint.as_ptr(),
                    checkpoint.len() as c_ulong,
                    &mut output,
                    &mut length,
                )
            };
            assert_eq!(code, 0);
            assert_eq!(
                unsafe { slice::from_raw_parts(output, length as usize) },
                request
            );
            connect_norito_free(output);
            let mut suffix = checkpoint.to_vec();
            suffix.push(0);
            assert!(validation_fee_current_policy_proof_request_v1(&suffix).is_err());
        }
        for malformed in [
            &[][..],
            &[0; 32],
            &[1; 32],
            &[2; 32],
            &native_checkpoint(1)[..32],
        ] {
            assert!(validation_fee_current_policy_proof_request_v1(malformed).is_err());
        }
    }
    #[test]
    fn proof_verifier_rejects_malformed_archive_and_scalar_checkpoint() {
        let checkpoint =
            iroha_data_model::sumeragi_finality::SumeragiFinalityCheckpoint::decode_canonical(
                native_checkpoint(1),
            )
            .unwrap();
        for archive in [&[][..], b"not norito"] {
            for trust in [native_checkpoint(1), &[5; 32][..]] {
                assert!(
                    validation_fee_current_policy_proof_verify_v1(
                        archive,
                        checkpoint.network_id(),
                        [3; 32],
                        trust,
                    )
                    .is_err()
                );
            }
        }
    }
    #[test]
    fn fee_checkpoint_c_boundaries_clear_every_output_on_refusal() {
        let checkpoint = native_checkpoint(1);
        let network =
            iroha_data_model::sumeragi_finality::SumeragiFinalityCheckpoint::decode_canonical(
                checkpoint,
            )
            .unwrap()
            .network_id();
        for (input, length) in [
            (ptr::null(), checkpoint.len() as c_ulong),
            (checkpoint.as_ptr(), 0),
            (
                checkpoint.as_ptr(),
                (iroha_data_model::sumeragi_finality::MAX_FINALITY_CHECKPOINT_BYTES + 1) as c_ulong,
            ),
        ] {
            let mut output = ptr::dangling_mut();
            let mut output_len = 99;
            let code = unsafe {
                connect_norito_validation_fee_current_policy_proof_request_v1(
                    input,
                    length,
                    &mut output,
                    &mut output_len,
                )
            };
            assert_ne!(code, 0);
            assert!(output.is_null());
            assert_eq!(output_len, 0);
        }
        let mut projection = ptr::dangling_mut();
        let mut projection_len = 99;
        let mut promoted = ptr::dangling_mut();
        let mut promoted_len = 99;
        let code = unsafe {
            connect_norito_validation_fee_current_policy_proof_verify_v1(
                b"not norito".as_ptr(),
                10,
                network.as_bytes().as_ptr(),
                32,
                [3_u8; 32].as_ptr(),
                32,
                checkpoint.as_ptr(),
                checkpoint.len() as c_ulong,
                &mut projection,
                &mut projection_len,
                &mut promoted,
                &mut promoted_len,
            )
        };
        assert_ne!(code, 0);
        assert!(projection.is_null());
        assert!(promoted.is_null());
        assert_eq!((projection_len, promoted_len), (0, 0));
    }

    fn retail_fixture() -> JsonValue {
        norito::json::from_str(include_str!(
            "../../../javascript/iroha_js/test/fixtures/retail_fee_codec_v1.json"
        ))
        .unwrap()
    }
    #[test]
    fn retail_bridge_matches_native_and_javascript_fixture() {
        let fixture = retail_fixture();
        let request = norito::json::to_vec(&fixture["request"]).unwrap();
        let assessment = norito::json::to_vec(&fixture["assessment"]).unwrap();
        assert_eq!(
            hex::encode(retail_fee_intent_hash_v1(&request).unwrap()),
            fixture["intent_hash_hex"].as_str().unwrap()
        );
        let marker = retail_fee_assessment_marker_v1(&assessment).unwrap();
        assert_eq!(
            std::str::from_utf8(&marker).unwrap(),
            fixture["marker"].as_str().unwrap()
        );
        let decoded: RetailFeeAssessmentV1 =
            norito::json::from_slice(&retail_fee_assessment_decode_v1(&marker).unwrap()).unwrap();
        let expected: RetailFeeAssessmentV1 = norito::json::from_slice(&assessment).unwrap();
        assert_eq!(decoded, expected);
        let mut trailing = marker.clone();
        trailing.extend_from_slice(b"00");
        assert!(retail_fee_assessment_decode_v1(&trailing).is_err());
        assert!(retail_fee_assessment_decode_v1(marker.to_ascii_uppercase().as_slice()).is_err());
    }
    #[test]
    fn retail_bridge_rejects_unknown_fields_and_invalid_payment_shape() {
        let mut fixture = retail_fixture();
        fixture
            .as_object_mut()
            .unwrap()
            .get_mut("request")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("exempt".into(), JsonValue::Bool(true));
        assert!(
            retail_fee_intent_hash_v1(&norito::json::to_vec(&fixture["request"]).unwrap()).is_err()
        );
        let mut request: RetailFeeQuoteRequestV1 =
            norito::json::from_value(retail_fixture()["request"].clone()).unwrap();
        request.transfers[0].amount_minor_units = 0;
        assert!(retail_fee_intent_hash_v1(&norito::json::to_vec(&request).unwrap()).is_err());
        let mut assessment: RetailFeeAssessmentV1 =
            norito::json::from_value(retail_fixture()["assessment"].clone()).unwrap();
        assessment.fee_minor = 1;
        assert!(
            retail_fee_assessment_marker_v1(&norito::json::to_vec(&assessment).unwrap()).is_err()
        );
    }
    #[test]
    fn retail_bridge_accepts_exact_byte_limits_and_rejects_one_more() {
        let fixture = retail_fixture();
        let request = norito::json::to_vec(&fixture["request"]).unwrap();
        let expected = retail_fee_intent_hash_v1(&request).unwrap();
        let mut padded = request;
        assert!(padded.len() < RETAIL_FEE_BRIDGE_MAX_INPUT_BYTES);
        padded.resize(RETAIL_FEE_BRIDGE_MAX_INPUT_BYTES, b' ');
        assert_eq!(retail_fee_intent_hash_v1(&padded).unwrap(), expected);
        padded.push(b' ');
        assert!(retail_fee_intent_hash_v1(&padded).is_err());

        let assessment = norito::json::to_vec(&fixture["assessment"]).unwrap();
        let expected = retail_fee_assessment_marker_v1(&assessment).unwrap();
        let mut padded = assessment;
        assert!(padded.len() < RETAIL_FEE_ASSESSMENT_MAX_BYTES);
        padded.resize(RETAIL_FEE_ASSESSMENT_MAX_BYTES, b' ');
        assert_eq!(retail_fee_assessment_marker_v1(&padded).unwrap(), expected);
        padded.push(b' ');
        assert!(retail_fee_assessment_marker_v1(&padded).is_err());
        assert!(expected.len() <= RETAIL_FEE_MARKER_MAX_BYTES);
        assert!(
            retail_fee_assessment_decode_v1(&expected).unwrap().len()
                <= RETAIL_FEE_ASSESSMENT_MAX_BYTES
        );
        let oversized = vec![b'0'; RETAIL_FEE_MARKER_MAX_BYTES + 1];
        assert!(retail_fee_assessment_decode_v1(&oversized).is_err());
    }
    #[test]
    fn retail_bridge_binds_order_and_amount_at_the_payment_count_limit() {
        let mut request: RetailFeeQuoteRequestV1 =
            norito::json::from_value(retail_fixture()["request"].clone()).unwrap();
        let leg = request.transfers[0].clone();
        request.transfers = vec![leg; 1_000];
        request.transfers[1].amount_minor_units += 1;
        let bytes = norito::json::to_vec(&request).unwrap();
        assert!(bytes.len() <= RETAIL_FEE_BRIDGE_MAX_INPUT_BYTES);
        let original = retail_fee_intent_hash_v1(&bytes).unwrap();
        request.transfers.swap(0, 1);
        let reordered =
            retail_fee_intent_hash_v1(&norito::json::to_vec(&request).unwrap()).unwrap();
        assert_ne!(original, reordered);
        request.transfers[0].amount_minor_units += 1;
        assert_ne!(
            reordered,
            retail_fee_intent_hash_v1(&norito::json::to_vec(&request).unwrap()).unwrap()
        );
        request.transfers.push(request.transfers[0].clone());
        assert!(retail_fee_intent_hash_v1(&norito::json::to_vec(&request).unwrap()).is_err());
    }
    #[test]
    fn retail_c_abi_refuses_oversized_inputs_before_reading_and_clears_outputs() {
        let single_byte = [0_u8];
        let operations: [(
            unsafe extern "C" fn(*const c_uchar, c_ulong, *mut *mut c_uchar, *mut c_ulong) -> c_int,
            usize,
        ); 3] = [
            (
                connect_norito_retail_fee_intent_hash_v1,
                RETAIL_FEE_BRIDGE_MAX_INPUT_BYTES,
            ),
            (
                connect_norito_retail_fee_assessment_marker_v1,
                RETAIL_FEE_ASSESSMENT_MAX_BYTES,
            ),
            (
                connect_norito_retail_fee_assessment_decode_v1,
                RETAIL_FEE_MARKER_MAX_BYTES,
            ),
        ];
        for (operation, limit) in operations {
            let mut output = ptr::dangling_mut::<c_uchar>();
            let mut length = c_ulong::MAX;
            // Only one byte is readable: the operation must inspect the length first.
            let status = unsafe {
                operation(
                    single_byte.as_ptr(),
                    (limit + 1) as c_ulong,
                    &mut output,
                    &mut length,
                )
            };
            assert_eq!(status, ERR_RETAIL_FEE_ASSESSMENT);
            assert!(output.is_null());
            assert_eq!(length, 0);
        }
    }
    #[test]
    fn retail_c_abi_refuses_controller_output_that_cannot_roundtrip() {
        use iroha_data_model::account::controller::{MultisigMember, MultisigPolicy};
        let mut assessment: RetailFeeAssessmentV1 =
            norito::json::from_value(retail_fixture()["assessment"].clone()).unwrap();
        let mut found = false;
        // General Model accounts allow large controllers. This finite control finds
        // a legitimate input within the JSON cap whose marker exceeds its own cap.
        for count in 2..=128_u8 {
            let members = (1..=count)
                .map(|seed| {
                    let pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).unwrap();
                    MultisigMember::new(pair.public_key().clone(), 1).unwrap()
                })
                .collect();
            assessment.account_id =
                AccountId::new_multisig(MultisigPolicy::new(1, members).unwrap());
            let input = norito::json::to_vec(&assessment).unwrap();
            if input.len() > RETAIL_FEE_ASSESSMENT_MAX_BYTES {
                break;
            }
            let encoded = norito::encode_canonical(&assessment).unwrap();
            if encoded.len() <= (RETAIL_FEE_MARKER_MAX_BYTES - RETAIL_FEE_MARKER_PREFIX.len()) / 2 {
                continue;
            }
            found = true;
            let mut output = ptr::dangling_mut::<c_uchar>();
            let mut length = c_ulong::MAX;
            let status = unsafe {
                connect_norito_retail_fee_assessment_marker_v1(
                    input.as_ptr(),
                    input.len() as c_ulong,
                    &mut output,
                    &mut length,
                )
            };
            assert_eq!(status, ERR_RETAIL_FEE_ASSESSMENT);
            assert!(output.is_null());
            assert_eq!(length, 0);
            break;
        }
        assert!(
            found,
            "the bounded controller output refusal must be exercised"
        );
    }
    #[test]
    fn retail_c_abi_clears_outputs_and_roundtrips() {
        let mut output = ptr::dangling_mut::<c_uchar>();
        let mut length = c_ulong::MAX;
        let status = unsafe {
            connect_norito_retail_fee_intent_hash_v1(ptr::null(), 1, &mut output, &mut length)
        };
        assert_eq!(status, ERR_RETAIL_FEE_ASSESSMENT);
        assert!(output.is_null());
        assert_eq!(length, 0);
        let input = norito::json::to_vec(&retail_fixture()["assessment"]).unwrap();
        let status = unsafe {
            connect_norito_retail_fee_assessment_marker_v1(
                input.as_ptr(),
                input.len() as c_ulong,
                &mut output,
                &mut length,
            )
        };
        assert_eq!(status, 0);
        assert!(!output.is_null());
        let actual = unsafe { slice::from_raw_parts(output, length as usize).to_vec() };
        connect_norito_free(output);
        assert_eq!(actual, retail_fee_assessment_marker_v1(&input).unwrap());
        length = c_ulong::MAX;
        let status = unsafe {
            connect_norito_retail_fee_assessment_marker_v1(
                input.as_ptr(),
                input.len() as c_ulong,
                ptr::null_mut(),
                &mut length,
            )
        };
        assert_eq!(status, ERR_NULL_PTR);
        assert_eq!(length, 0);
    }
}
