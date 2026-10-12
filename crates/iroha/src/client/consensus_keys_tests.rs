// HTTP observations exercise request custody and bounded decoding, not finality.
#[test]
fn consensus_keys_reader_requires_operator_auth_and_bounded_canonical_records() {
    use iroha_data_model::consensus::{
        ConsensusKeyId, ConsensusKeyRecord, ConsensusKeyRole, ConsensusKeyStatus,
    };
    let client = client_with_base_url(base_url());
    let record = ConsensusKeyRecord {
        id: ConsensusKeyId::new(ConsensusKeyRole::Committee, "committee-test"),
        public_key: client.key_pair.public_key().clone(),
        pop: None,
        activation_height: 10,
        expiry_height: None,
        replaces: None,
        status: ConsensusKeyStatus::Pending,
    };
    let records = vec![record.clone()];
    let (result, request) =
        capture_request(norito_response(StatusCode::OK, &records), |transport| {
            client
                .clone()
                .with_test_http_transport(transport)
                .get_sumeragi_consensus_keys()
        });
    assert_eq!(result.unwrap(), records);
    assert_eq!(request.url.path(), "/v1/sumeragi/consensus-keys");
    assert_eq!(request.method, HttpMethod::GET);
    assert_eq!(request.max_response_bytes, 1024 * 1024);
    assert_single_accept_header(&request, APPLICATION_NORITO);
    super::tests::assert_operator_signature_headers(&request);

    let mut trailing = norito::encode_canonical(&records).unwrap();
    trailing.push(0);
    for (case, response) in [
        norito_response(StatusCode::OK, &vec![record.clone(), record.clone()]),
        norito_response(StatusCode::OK, &vec![record; 129]),
        mk_response(StatusCode::OK, trailing, Some(APPLICATION_NORITO)),
        json_response(StatusCode::OK, "[]"),
        empty_response(StatusCode::FORBIDDEN),
    ]
    .into_iter()
    .enumerate()
    {
        let (result, _) = capture_request(response, |transport| {
            client
                .clone()
                .with_test_http_transport(transport)
                .get_sumeragi_consensus_keys()
        });
        let error = result.expect_err("invalid observation must fail");
        if case == 2 {
            assert!(matches!(error.downcast_ref::<crate::Error>(),
                Some(crate::Error::CanonicalDecode(failure))
                    if failure.operation == "sumeragi.consensus_keys.read"
                        && failure.source.kind() == norito::core::DecodeAttemptErrorKind::Invalid));
        }
    }
    let (result, requests) = capture_requests(empty_response(StatusCode::OK), |transport| {
        client
            .clone()
            .with_test_http_transport(transport)
            .with_request_deadline(std::time::Instant::now())
            .get_sumeragi_consensus_keys()
    });
    assert!(result.is_err());
    assert!(requests.is_empty());
    let mut missing = client;
    missing.operator_key_pair = None;
    let (result, requests) = capture_requests(empty_response(StatusCode::OK), |transport| {
        missing
            .with_test_http_transport(transport)
            .get_sumeragi_consensus_keys()
    });
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("operator signing key")
    );
    assert!(requests.is_empty());
}
