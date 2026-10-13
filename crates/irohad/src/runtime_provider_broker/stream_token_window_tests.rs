// Broker claims remain untrusted: body-derived times must match before observer admission.
#[test]
fn stream_token_broker_rejects_either_substituted_window_claim_and_scrubs_signatures() {
    let binding = token_signer_binding();
    let request = make_operation_request(
        TEST_SESSION_ID,
        1,
        binding.clone(),
        observation(&binding).metadata_digest,
        OPERATION_STREAM_TOKEN_SIGN_V1,
        signing_payload(),
    )
    .unwrap();
    let expected = expected();
    let positive = stream_token_signer_test_support::receipt(&request.payload);
    validate_stream_token_receipt_result(&request, &positive.encode_canonical().unwrap()).unwrap();
    for change_issue in [true, false] {
        let mut receipt = stream_token_signer_test_support::receipt(&request.payload);
        if change_issue {
            receipt.request.issued_at_unix_ms += 1;
        } else {
            receipt.request.expires_at_unix_ms += 1;
        }
        // All previous explicit request comparisons and the genuine role signature still pass.
        assert_eq!(receipt.request.operation_id, expected.operation_id());
        assert_eq!(receipt.request.binding_digest, expected.binding_digest());
        assert_eq!(
            receipt.request.signing_payload_digest,
            expected.signing_payload_digest()
        );
        assert_eq!(
            receipt.request.signing_payload_size,
            expected.signing_payload_size()
        );
        receipt.intent.request_digest = receipt.request.digest().unwrap();
        Signature::try_from_bytes(&receipt.signatures[0].signature)
            .unwrap()
            .verify(
                &stream_token_signer_test_support::signer_binding()
                    .custody()
                    .public_key,
                &request.payload,
            )
            .unwrap();
        let bytes = receipt.encode_canonical().unwrap();
        assert_eq!(
            validate_stream_token_receipt_result(&request, &bytes),
            Err(BrokerError::Protocol)
        );
        let audit = Arc::new(Mutex::new(None));
        let claims = StreamTokenBrokerReceiptClaimsV1::new(receipt).with_drop_audit(audit.clone());
        assert_eq!(
            claims.validate(&request, &expected),
            Err(BrokerError::Protocol)
        );
        let result = audit.lock().unwrap();
        let result = result.as_ref().expect("real claim guard dropped");
        assert_eq!(result.signature_bytes, 4 * 64);
        assert!(result.receipt_signatures_zero);
        assert!(result.role_signature_zero);
        assert!(result.parsed_signature_zero.is_none_or(|zero| zero));
        assert!(
            result.parsed_signature_zero.is_none(),
            "window rejected before role crypto allocation"
        );
    }
}
