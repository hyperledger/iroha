// Included within stream_token_mutation_tests to reuse the exact real socket-pair fixture.
fn accept_read_session(fixture: &Fixture) -> UnixStream {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut peer = loop {
        match fixture.reconnect_listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "explicit read connects"
                );
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("isolated read accept failed: {error}"),
        }
    };
    // Accepted sockets may inherit the nonblocking listener mode on BSD.
    peer.set_nonblocking(false).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    peer.set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let frame = read_length_prefixed(&mut peer, MAX_HANDSHAKE_FRAME_BYTES_V1).unwrap();
    let request = decode_frame::<HandshakeRequestV1>(
        &frame,
        FRAME_KIND_HANDSHAKE_REQUEST_V1,
        MAX_HANDSHAKE_FRAME_BYTES_V1,
    )
    .unwrap();
    validate_handshake_request(&request).unwrap();
    assert_eq!(request.chain_id, fixture.signer.session.chain_id);
    assert_eq!(request.network_id, network_id());
    assert_eq!(
        request.requested_catalog,
        vec![fixture.signer.binding.clone()]
    );
    let response = make_handshake_response(
        &request,
        [0xb8; 32],
        vec![observation(&fixture.signer.binding)],
    )
    .unwrap();
    let frame = encode_frame(
        FRAME_KIND_HANDSHAKE_RESPONSE_V1,
        &response,
        MAX_HANDSHAKE_FRAME_BYTES_V1,
    )
    .unwrap();
    write_length_prefixed(&mut peer, &frame, MAX_HANDSHAKE_FRAME_BYTES_V1).unwrap();
    peer
}

fn lose_one_sign(fixture: &mut Fixture) -> Vec<u8> {
    let client = fixture.signer.clone();
    let signing = thread::spawn(move || client.sign(&expected(), &token_body()));
    qualify(&mut fixture.peer, 1);
    let (_, receipt) = admit_sign(&mut fixture.peer);
    fixture.peer.shutdown(std::net::Shutdown::Write).unwrap();
    assert_eq!(
        signing.join().unwrap().err(),
        Some(StreamTokenSignerCallErrorV1::AmbiguousCompletion)
    );
    assert_fenced(&fixture.signer, &fixture.reconnect_listener, 3);
    receipt
}

#[test]
fn ambiguous_sign_allows_only_explicit_exact_recovery_and_never_clears_sign_latch() {
    let mut fixture = fixture();
    let receipt = lose_one_sign(&mut fixture);
    let mut other_body = token_body();
    other_body.token_id = "1123456789abcdef0123456789abcdef".to_owned();
    let other_expected = stream_token_signer_test_support::expected(&other_body);
    assert_eq!(
        fixture.signer.recover(&expected(), &other_body).err(),
        Some(StreamTokenSignerCallErrorV1::Refused)
    );
    assert_eq!(
        fixture.signer.recover(&other_expected, &other_body).err(),
        Some(StreamTokenSignerCallErrorV1::Refused)
    );
    assert_fenced(&fixture.signer, &fixture.reconnect_listener, 3);
    let client = fixture.signer.clone();
    let recovering = thread::spawn(move || client.recover(&expected(), &token_body()));
    let mut peer = accept_read_session(&fixture);
    let request = read_request(&mut peer, 1, OPERATION_STREAM_TOKEN_RECOVER_V1);
    assert_eq!(request.payload, signing_payload());
    write_response(&mut peer, &request, receipt.clone());
    assert_eq!(recovering.join().unwrap().unwrap().bytes(), receipt);
    assert_fenced(&fixture.signer, &fixture.reconnect_listener, 3);
    assert_no_request_bytes(&mut fixture.peer);
    // The one-purpose read connection has closed; it cannot retain a signing session.
    let mut byte = [0; 1];
    assert_eq!(peer.read(&mut byte).unwrap(), 0);
}

#[test]
fn reconstructed_client_without_retained_owner_cannot_recover_ambiguous_sign() {
    let mut fixture = fixture();
    lose_one_sign(&mut fixture);
    // A new process would lose this latch. Its exact body and operation ID alone cannot
    // authorize a read or another Sign until a finalized native owner can be authenticated.
    let reconstructed = StreamTokenSignerBrokerClient {
        session: Arc::clone(&fixture.signer.session),
        binding: fixture.signer.binding.clone(),
        metadata_digest: fixture.signer.metadata_digest,
        latch: Arc::new(Mutex::new(StreamTokenSignLatchV1::Idle)),
    };
    assert_eq!(
        reconstructed.recover(&expected(), &token_body()).err(),
        Some(StreamTokenSignerCallErrorV1::Refused)
    );
    assert_eq!(
        fixture
            .reconnect_listener
            .accept()
            .expect_err("unretained owner cannot open a recovery connection")
            .kind(),
        io::ErrorKind::WouldBlock
    );
    assert_no_request_bytes(&mut fixture.peer);
}

#[test]
fn recovery_failure_and_substituted_receipt_cannot_reopen_signing() {
    for substituted in [false, true] {
        let mut fixture = fixture();
        lose_one_sign(&mut fixture);
        let client = fixture.signer.clone();
        let recovering = thread::spawn(move || client.recover(&expected(), &token_body()));
        let mut peer = accept_read_session(&fixture);
        let request = read_request(&mut peer, 1, OPERATION_STREAM_TOKEN_RECOVER_V1);
        if substituted {
            let mut other_body = token_body();
            other_body.token_id = "2123456789abcdef0123456789abcdef".to_owned();
            let other = make_operation_request(
                request.session_id,
                request.request_id,
                request.binding.clone(),
                request.provider_metadata_digest,
                request.operation,
                other_body.signing_payload_bytes().unwrap(),
            )
            .unwrap();
            let receipt = stream_token_signer_test_support::receipt(&other.payload)
                .encode_canonical()
                .unwrap();
            write_response(&mut peer, &other, receipt);
        } else {
            peer.shutdown(std::net::Shutdown::Write).unwrap();
        }
        assert_eq!(
            recovering.join().unwrap().err(),
            Some(if substituted {
                StreamTokenSignerCallErrorV1::InvalidResponse
            } else {
                StreamTokenSignerCallErrorV1::Unavailable
            })
        );
        assert_fenced(&fixture.signer, &fixture.reconnect_listener, 3);
        assert_no_request_bytes(&mut fixture.peer);
    }
}

#[test]
fn observer_remains_a_separate_exact_read_after_sign_is_ambiguous() {
    let mut fixture = fixture();
    lose_one_sign(&mut fixture);
    let observer = StreamTokenObserverBrokerClient {
        session: Arc::clone(&fixture.signer.session),
        binding: fixture.signer.binding.clone(),
        metadata_digest: fixture.signer.metadata_digest,
        observer_handle: fixture
            .signer
            .binding
            .stream_token_signer_binding
            .as_ref()
            .unwrap()
            .observer_handle()
            .to_owned(),
    };
    assert_ne!(observer.handle(), fixture.signer.handle());
    let query = stream_token_signer_test_support::query();
    let expected_query = query.encode_canonical().unwrap();
    let observation = stream_token_signer_test_support::state_claim(&query)
        .encode_canonical()
        .unwrap();
    let raw = StreamTokenObserverReplyV1::current(
        vec![0xa1; SIGNER_CUSTODY_MAX_BYTES_V1],
        observation.clone(),
    )
    .unwrap();
    let encoded = encode_stream_token_observer_reply(&query, &raw).unwrap();
    assert!(
        encoded.len() > MAX_STREAM_TOKEN_FRAME_BYTES_V1,
        "valid full custody leaf exceeds retired bare-signature frame ceiling"
    );
    let observing = thread::spawn(move || observer.observe(&query));
    let mut peer = accept_read_session(&fixture);
    let request = read_request(&mut peer, 1, OPERATION_STREAM_TOKEN_OBSERVE_V1);
    assert_eq!(
        request.payload, expected_query,
        "caller phase/challenge/finality floor preserved byte-for-byte"
    );
    write_response(&mut peer, &request, encoded);
    let reply = observing.join().unwrap().unwrap();
    let (record, actual) = reply.current_evidence().unwrap();
    assert_eq!(record, vec![0xa1; SIGNER_CUSTODY_MAX_BYTES_V1]);
    assert_eq!(actual, observation);
    assert!(reply.completed_observation().is_none());
    assert_fenced(&fixture.signer, &fixture.reconnect_listener, 3);
    assert_no_request_bytes(&mut fixture.peer);
}

#[test]
fn observer_closed_forms_and_query_network_challenge_are_exact() {
    let binding = token_signer_binding();
    let query = stream_token_signer_test_support::query();
    let payload = query.encode_canonical().unwrap();
    let claim = stream_token_signer_test_support::state_claim(&query);
    let bytes = claim.encode_canonical().unwrap();
    let completed = StreamTokenObserverReplyV1::completed(bytes.clone()).unwrap();
    assert_eq!(
        encode_stream_token_observer_reply(&query, &completed).err(),
        Some(BrokerError::Protocol)
    );
    let wire = StreamTokenObserverReplyWireV1::Completed { observation: bytes };
    let wrong_form = encode_canonical(&wire, MAX_STREAM_TOKEN_HARDWARE_FRAME_BYTES_V1).unwrap();
    assert_eq!(
        decode_stream_token_observer_reply(&binding, &payload, &wrong_form).err(),
        Some(BrokerError::Protocol)
    );
    for mutation in 0..4 {
        let mut changed = claim.clone();
        match mutation {
            0 => changed.body.request_digest = [0xa2; 32],
            1 => changed.body.chain_id = "other-stream-chain".to_owned(),
            2 => changed.body.network_id = [0xa3; 32],
            3 => changed.body.phase = sorafs_manifest::signer::stream_token_evidence::SignerStreamTokenObservationPhaseV1::BeforeProvider,
            _ => unreachable!(),
        }
        let reply = StreamTokenObserverReplyV1::current(
            vec![0xa4; 32],
            changed.encode_canonical().unwrap(),
        )
        .unwrap();
        let encoded = encode_stream_token_observer_reply(&query, &reply).unwrap();
        assert_eq!(
            decode_stream_token_observer_reply(&binding, &payload, &encoded).err(),
            Some(BrokerError::Protocol)
        );
    }
    let mut wrong_query = query.clone();
    wrong_query.subject = SignerStreamTokenObservationRequestSubjectV1::CurrentCustody {
        binding_digest: [0xa5; 32],
    };
    assert_eq!(
        decode_stream_token_observer_request(&binding, &wrong_query.encode_canonical().unwrap())
            .err(),
        Some(BrokerError::BindingMismatch)
    );
}

#[test]
fn stream_token_full_binding_network_is_checked_at_handshake_and_operation_admission() {
    let binding = token_signer_binding();
    let chain = binding
        .stream_token_signer_binding
        .as_ref()
        .unwrap()
        .custody()
        .chain_id
        .clone();
    assert!(
        make_handshake_request(&chain, network_id(), vec![binding.clone()], [0xaa; 32]).is_ok()
    );
    assert!(
        make_handshake_request(
            "another-chain",
            network_id(),
            vec![binding.clone()],
            [0xaa; 32]
        )
        .is_err()
    );
    let wrong_network = network_id_from(0xa6);
    assert!(
        make_handshake_request(&chain, wrong_network, vec![binding.clone()], [0xaa; 32]).is_err()
    );
    let request = make_operation_request(
        TEST_SESSION_ID,
        1,
        binding,
        observation(&token_signer_binding()).metadata_digest,
        OPERATION_STREAM_TOKEN_SIGN_V1,
        signing_payload(),
    )
    .unwrap();
    assert!(validate_operation_request_with_session(&request, Some(&chain), &network_id()).is_ok());
    assert!(
        validate_operation_request_with_session(&request, Some("another-chain"), &network_id())
            .is_err()
    );
    assert!(
        validate_operation_request_with_session(&request, Some(&chain), &wrong_network).is_err()
    );
}

#[test]
fn stream_token_wire_leaf_ceilings_fit_finite_operation_admission() {
    // Maximal bounded raw transport leaves are not asserted to be valid signed state evidence.
    let wire = StreamTokenObserverReplyWireV1::Current {
        record: vec![0xa7; SIGNER_CUSTODY_MAX_BYTES_V1],
        observation: vec![0xa8; SIGNER_STREAM_TOKEN_EVIDENCE_MAX_BYTES_V1],
    };
    let result = encode_canonical(&wire, MAX_STREAM_TOKEN_HARDWARE_FRAME_BYTES_V1).unwrap();
    let decoded = decode_canonical_with_policy::<StreamTokenObserverReplyWireV1>(
        &result,
        MAX_STREAM_TOKEN_HARDWARE_FRAME_BYTES_V1,
        STREAM_TOKEN_HARDWARE_DECODE_POLICY_V1,
    )
    .unwrap();
    assert!(
        matches!(&decoded, StreamTokenObserverReplyWireV1::Current { record, observation }
        if record.len() == SIGNER_CUSTODY_MAX_BYTES_V1 && observation.len() == SIGNER_STREAM_TOKEN_EVIDENCE_MAX_BYTES_V1)
    );
    let binding = token_signer_binding();
    let query = stream_token_signer_test_support::query();
    let request = make_operation_request(
        TEST_SESSION_ID,
        1,
        binding.clone(),
        observation(&binding).metadata_digest,
        OPERATION_STREAM_TOKEN_OBSERVE_V1,
        query.encode_canonical().unwrap(),
    )
    .unwrap();
    // A schema-valid small observation supplies the envelope shape; maximal raw leaves then
    // measure transport admission independently of the caller's authenticated evidence verifier.
    let small = StreamTokenObserverReplyV1::current(
        vec![0xa9; 32],
        stream_token_signer_test_support::state_claim(&query)
            .encode_canonical()
            .unwrap(),
    )
    .unwrap();
    let mut response = make_operation_response(
        &request,
        STATUS_OK_V1,
        encode_stream_token_observer_reply(&query, &small).unwrap(),
        &network_id(),
    )
    .unwrap();
    response.result = result;
    response.result_digest = operation_result_digest(&response.result);
    response.response_digest = operation_response_digest(&OperationResponseFieldsV1 {
        session_id: response.session_id,
        request_id: response.request_id,
        request_digest: response.request_digest,
        observed_binding: response.observed_binding.clone(),
        provider_metadata_digest: response.provider_metadata_digest,
        operation: response.operation,
        payload_digest: response.payload_digest,
        status: response.status,
        result_digest: response.result_digest,
        result_len: response.result.len().try_into().unwrap(),
    })
    .unwrap();
    validate_operation_response_envelope(&request, &response).unwrap();
    let frame = encode_frame(
        FRAME_KIND_OPERATION_RESPONSE_V1,
        &response,
        MAX_STREAM_TOKEN_HARDWARE_FRAME_BYTES_V1,
    )
    .unwrap();
    assert!(frame.len() < MAX_STREAM_TOKEN_HARDWARE_FRAME_BYTES_V1);
    let policy = STREAM_TOKEN_HARDWARE_DECODE_POLICY_V1;
    assert_eq!(policy.max_total_allocated_bytes, 2 * 1024 * 1024);
    let pool = Arc::new(DecodeResourcePoolV1::new(policy.max_composed_bytes));
    let admission = DecodeResourceAdmissionV1::acquire_operation_from(
        pool.clone(),
        OPERATION_STREAM_TOKEN_OBSERVE_V1,
    )
    .unwrap();
    assert_eq!(pool.allocation.reserved_bytes(), policy.max_composed_bytes);
    let mut transport = Cursor::new(Vec::new());
    write_length_prefixed(
        &mut transport,
        &frame,
        MAX_STREAM_TOKEN_HARDWARE_FRAME_BYTES_V1,
    )
    .unwrap();
    transport.set_position(0);
    let inbound = read_length_prefixed_with_decode_admission(
        &mut transport,
        MAX_STREAM_TOKEN_HARDWARE_FRAME_BYTES_V1,
        &admission,
    )
    .unwrap();
    let scope = admission.enter();
    let mut outer = decode_operation_frame::<OperationResponseV1>(
        &inbound,
        FRAME_KIND_OPERATION_RESPONSE_V1,
        OPERATION_STREAM_TOKEN_OBSERVE_V1,
    )
    .unwrap();
    validate_operation_response_envelope(&request, &outer).unwrap();
    assert_eq!(outer.result_digest, operation_result_digest(&outer.result));
    let result_len = outer.result.len();
    let owned_result =
        ScrubbedBytes::with_decode_admission(std::mem::take(&mut outer.result), admission.clone());
    drop(scope);
    let before_inner = admission.usage.lock().unwrap().consumed_bytes;
    let scope = owned_result
        .enter_decode_admission()
        .expect("result retains original operation admission");
    let decoded = decode_canonical_with_policy::<StreamTokenObserverReplyWireV1>(
        &owned_result,
        MAX_STREAM_TOKEN_HARDWARE_FRAME_BYTES_V1,
        policy,
    )
    .unwrap();
    assert!(
        matches!(&decoded, StreamTokenObserverReplyWireV1::Current { record, observation }
        if record.len() == SIGNER_CUSTODY_MAX_BYTES_V1 && observation.len() == SIGNER_STREAM_TOKEN_EVIDENCE_MAX_BYTES_V1)
    );
    // The maximum opaque observation is deliberately not signed canonical state evidence. The
    // real inner decoder must still charge and reject it under this same result-owned budget.
    assert_eq!(
        decode_stream_token_observer_reply(&binding, &request.payload, &owned_result).err(),
        Some(BrokerError::Protocol)
    );
    let consumed = admission.usage.lock().unwrap().consumed_bytes;
    assert!(
        consumed > before_inner,
        "actual inner decoders charge the retained admission"
    );
    assert!(consumed <= policy.max_cumulative_bytes);
    for length in [
        frame.len(),
        result_len,
        SIGNER_STREAM_TOKEN_EVIDENCE_MAX_BYTES_V1,
    ] {
        let budget =
            decode_resource_budget(length, MAX_STREAM_TOKEN_HARDWARE_FRAME_BYTES_V1, policy)
                .unwrap();
        assert!(
            budget.max_total_allocated_bytes <= 2 * 1024 * 1024,
            "finite per-decode allocation cap"
        );
    }
    eprintln!(
        "stream-token bounded decode: outer={} result={} per_decode_allocation={} composed_reservation={} cumulative_consumed={} cumulative_cap={}",
        frame.len(),
        result_len,
        policy.max_total_allocated_bytes,
        policy.max_composed_bytes,
        consumed,
        policy.max_cumulative_bytes
    );
    drop(scope);
    drop(owned_result);
    drop(admission);
    assert_eq!(
        pool.allocation.reserved_bytes(),
        0,
        "result-owned reservation released after final decode"
    );
    assert_eq!(
        operation_frame_limit(OPERATION_APPEAL_FINANCE_CHECKPOINT_SIGN_V1),
        MAX_STREAM_TOKEN_FRAME_BYTES_V1
    );
    assert_eq!(
        StreamTokenObserverReplyV1::current(vec![0; SIGNER_CUSTODY_MAX_BYTES_V1 + 1], vec![1])
            .err(),
        Some(StreamTokenSignerCallErrorV1::InvalidResponse)
    );
    assert_eq!(
        StreamTokenObserverReplyV1::completed(vec![
            0;
            SIGNER_STREAM_TOKEN_EVIDENCE_MAX_BYTES_V1 + 1
        ])
        .err(),
        Some(StreamTokenSignerCallErrorV1::InvalidResponse)
    );
    assert_eq!(
        StreamTokenSignerReceiptV1::new(vec![0; SIGNER_STREAM_TOKEN_RECEIPT_MAX_BYTES_V1 + 1])
            .err(),
        Some(StreamTokenSignerCallErrorV1::InvalidResponse)
    );
    let (mut sender, mut receiver) = UnixStream::pair().unwrap();
    sender
        .write_all(
            &u32::try_from(MAX_STREAM_TOKEN_HARDWARE_FRAME_BYTES_V1 + 1)
                .unwrap()
                .to_be_bytes(),
        )
        .unwrap();
    assert_eq!(
        read_length_prefixed(&mut receiver, MAX_STREAM_TOKEN_HARDWARE_FRAME_BYTES_V1).err(),
        Some(BrokerError::Protocol)
    );
}

#[test]
fn stream_token_server_dispatch_routes_sign_recovery_and_observer_to_separate_backends() {
    struct Hardware {
        signs: AtomicU64,
        recoveries: AtomicU64,
        original: Mutex<Option<([u8; 32], Vec<u8>)>>,
    }
    impl StreamTokenSignerClientV1 for Hardware {
        fn handle(&self) -> &'static str {
            "hsm://sorafs/stream-token/primary-a"
        }
        fn sign(
            &self,
            expected: &SignerStreamTokenExpectedV1,
            body: &sorafs_manifest::StreamTokenBodyV1,
        ) -> Result<StreamTokenSignerReceiptV1, StreamTokenSignerCallErrorV1> {
            assert_eq!(expected, &stream_token_signer_test_support::expected(body));
            self.signs.fetch_add(1, Ordering::SeqCst);
            let bytes =
                stream_token_signer_test_support::receipt(&body.signing_payload_bytes().unwrap())
                    .encode_canonical()
                    .unwrap();
            let mut original = self.original.lock().unwrap();
            assert!(original.is_none(), "the fixture signs only once");
            *original = Some((expected.operation_id(), bytes.clone()));
            StreamTokenSignerReceiptV1::new(bytes)
        }

        fn recover(
            &self,
            expected: &SignerStreamTokenExpectedV1,
            body: &sorafs_manifest::StreamTokenBodyV1,
        ) -> Result<StreamTokenSignerReceiptV1, StreamTokenSignerCallErrorV1> {
            assert_eq!(expected, &stream_token_signer_test_support::expected(body));
            self.recoveries.fetch_add(1, Ordering::SeqCst);
            let original = self.original.lock().unwrap();
            let (operation, bytes) = original
                .as_ref()
                .expect("read only a previously stored receipt");
            assert_eq!(*operation, expected.operation_id());
            StreamTokenSignerReceiptV1::new(bytes.clone())
        }
    }

    struct Observer {
        reads: AtomicU64,
    }
    impl StreamTokenStateObserverClientV1 for Observer {
        fn finalize_check(
            &self,
            _instruction: &iroha_data_model::isi::sorafs::MutateSorafsStreamTokenAuthority,
        ) -> Result<iroha_data_model::transaction::SignedTransaction, StreamTokenSignerCallErrorV1>
        {
            Err(StreamTokenSignerCallErrorV1::Unavailable)
        }

        fn handle(&self) -> &'static str {
            "state://sorafs/stream-token/observer-primary"
        }
        fn observe(
            &self,
            query: &SignerStreamTokenObservationRequestV1,
        ) -> Result<StreamTokenObserverReplyV1, StreamTokenSignerCallErrorV1> {
            assert_eq!(query, &stream_token_signer_test_support::query());
            self.reads.fetch_add(1, Ordering::SeqCst);
            StreamTokenObserverReplyV1::current(
                vec![0xab; 32],
                stream_token_signer_test_support::state_claim(query)
                    .encode_canonical()
                    .unwrap(),
            )
        }
    }
    let signer_backend = Arc::new(Hardware {
        signs: AtomicU64::new(0),
        recoveries: AtomicU64::new(0),
        original: Mutex::new(None),
    });
    let observer = Arc::new(Observer {
        reads: AtomicU64::new(0),
    });
    let binding = token_signer_binding();
    for backends in [
        RuntimeProviderBrokerBackendsV1::new(),
        RuntimeProviderBrokerBackendsV1::new()
            .with_stream_token_signer_client(signer_backend.clone()),
        RuntimeProviderBrokerBackendsV1::new().with_stream_token_state_observer(observer.clone()),
    ] {
        assert!(
            make_server_observation(network_id(), &binding, &backends).is_err(),
            "one slot needs both separate clients"
        );
    }
    let backends = RuntimeProviderBrokerBackendsV1::new()
        .with_stream_token_signer_client(signer_backend.clone())
        .with_stream_token_state_observer(observer.clone());
    let initial_observation = make_server_observation(network_id(), &binding, &backends).unwrap();
    let state = singleton_state(
        "stream-token-mutation-test-chain",
        binding.clone(),
        initial_observation.clone(),
        backends,
    );
    let mut returned = Vec::new();
    for (id, operation) in [
        (1, OPERATION_STREAM_TOKEN_SIGN_V1),
        (2, OPERATION_STREAM_TOKEN_RECOVER_V1),
    ] {
        let request = make_operation_request(
            TEST_SESSION_ID,
            id,
            binding.clone(),
            initial_observation.metadata_digest,
            operation,
            signing_payload(),
        )
        .unwrap();
        validate_operation_request_with_session(&request, Some(&state.chain_id), &state.network_id)
            .unwrap();
        returned.push(
            dispatch_server_operation(&state, &request)
                .unwrap()
                .to_vec(),
        );
    }
    assert_eq!(
        returned[0], returned[1],
        "read-only recovery returns the same sole raw canonical receipt"
    );
    let query = stream_token_signer_test_support::query();
    let payload = query.encode_canonical().unwrap();
    let request = make_operation_request(
        TEST_SESSION_ID,
        3,
        binding.clone(),
        initial_observation.metadata_digest,
        OPERATION_STREAM_TOKEN_OBSERVE_V1,
        payload.clone(),
    )
    .unwrap();
    let result = dispatch_server_operation(&state, &request).unwrap();
    assert!(
        decode_stream_token_observer_reply(&binding, &payload, &result)
            .unwrap()
            .current_evidence()
            .is_some()
    );
    let request = make_operation_request(
        TEST_SESSION_ID,
        4,
        binding.clone(),
        initial_observation.metadata_digest,
        OPERATION_QUALIFY_V1,
        encode_canonical(&(), MAX_STREAM_TOKEN_METADATA_BYTES_V1).unwrap(),
    )
    .unwrap();
    let result = dispatch_server_operation(&state, &request).unwrap();
    validate_stream_token_metadata_result(&binding, &result).unwrap();
    assert_eq!(signer_backend.signs.load(Ordering::SeqCst), 1);
    assert_eq!(signer_backend.recoveries.load(Ordering::SeqCst), 1);
    assert_eq!(
        observer.reads.load(Ordering::SeqCst),
        1,
        "metadata checks never mint observer evidence"
    );
}

#[test]
fn completed_observer_reply_preserves_only_raw_exact_phase_evidence() {
    use sorafs_manifest::signer::{
        receipt::{SignerCompletedOperationV1, SignerOperationFinalizedAnchorV1},
        stream_token_evidence::{
            SignerStreamTokenObservationPhaseV1, SignerStreamTokenStateSubjectV1,
        },
    };
    let binding = token_signer_binding();
    let expected = expected();
    let mut query = stream_token_signer_test_support::query();
    query.phase = SignerStreamTokenObservationPhaseV1::BeforeRelease;
    query.subject = SignerStreamTokenObservationRequestSubjectV1::CompletedOperation {
        binding_digest: expected.binding_digest(),
        operation_id: expected.operation_id(),
        signing_payload_digest: expected.signing_payload_digest(),
        signing_payload_size: expected.signing_payload_size(),
        receipt_digest: [0xac; 32],
        signatures_digest: [0xad; 32],
    };
    let receipt = stream_token_signer_test_support::receipt(&signing_payload());
    let mut observation = stream_token_signer_test_support::state_claim(&query);
    observation.body.subject = SignerStreamTokenStateSubjectV1::CompletedOperation {
        binding_digest: expected.binding_digest(),
        operation_id: expected.operation_id(),
        signing_payload_digest: expected.signing_payload_digest(),
        signing_payload_size: expected.signing_payload_size(),
        completed_operation: Box::new(SignerCompletedOperationV1 {
            operation_id: expected.operation_id(),
            intent_digest: receipt.intent.digest().unwrap(),
            original_custody: receipt.request.original_custody,
            reservation: receipt.reservation,
            commitment: receipt.commitment,
            signatures_digest: [0xad; 32],
            completed_at_unix_ms: query.not_before_unix_ms,
            anchor: SignerOperationFinalizedAnchorV1 {
                height: 11,
                block_hash: [0xae; 32],
                operation_state_digest: [0xaf; 32],
            },
        }),
    };
    let bytes = observation.encode_canonical().unwrap();
    let reply = StreamTokenObserverReplyV1::completed(bytes.clone()).unwrap();
    let encoded = encode_stream_token_observer_reply(&query, &reply).unwrap();
    let payload = query.encode_canonical().unwrap();
    let decoded = decode_stream_token_observer_reply(&binding, &payload, &encoded).unwrap();
    assert_eq!(decoded.completed_observation(), Some(bytes.as_slice()));
    assert!(decoded.current_evidence().is_none());
    let current = StreamTokenObserverReplyV1::current(vec![0xb1; 32], bytes).unwrap();
    assert_eq!(
        encode_stream_token_observer_reply(&query, &current).err(),
        Some(BrokerError::Protocol)
    );
    // A decoded untrusted completed row still has no authenticated finality or release capability.
}

#[test]
fn stream_token_decoded_receipt_signatures_are_scrubbed_on_success_and_every_rejection_stage() {
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
    for fault in 0..4 {
        let mut receipt = stream_token_signer_test_support::receipt(&request.payload);
        match fault {
            0 => {}
            1 => {
                receipt.signatures[1].purpose =
                    sorafs_manifest::signer::protocol::SignerKeyOperationPurposeV1::RolePayload
            }
            2 => receipt.request.operation_id[0] ^= 1,
            3 => receipt.signatures[0].signature[0] ^= 1,
            _ => unreachable!(),
        }
        let audit = Arc::new(Mutex::new(None));
        let claims = StreamTokenBrokerReceiptClaimsV1::new(receipt).with_drop_audit(audit.clone());
        assert!(
            audit.lock().unwrap().is_none(),
            "guard owns unreleased signature copies"
        );
        let result = claims.validate(&request, &expected);
        assert_eq!(
            result,
            if fault == 0 {
                Ok(())
            } else {
                Err(BrokerError::Protocol)
            }
        );
        let audit = audit.lock().unwrap();
        let observed = audit
            .as_ref()
            .expect("actual guard Drop audited after validation exit");
        assert_eq!(observed.signature_bytes, 4 * 64);
        assert!(observed.receipt_signatures_zero);
        assert!(observed.role_signature_zero);
        assert!(observed.parsed_signature_zero.is_none_or(|zero| zero));
        assert_eq!(
            observed.parsed_signature_zero.is_some(),
            fault == 0 || fault == 3
        );
    }
}

include!("stream_token_window_tests.rs");
include!("stream_token_check_tests.rs");

include!("stream_token_blocking_worker_tests.rs");

#[test]
fn observer_evidence_codec_refusal_remains_local_after_exact_prefix() {
    use norito::core::{with_decode_limits_measured, with_decode_limits_scope};

    let binding = token_signer_binding();
    let query = stream_token_signer_test_support::query();
    let payload = query.encode_canonical().unwrap();
    let claim = stream_token_signer_test_support::state_claim(&query);
    let observation_bytes = claim.encode_canonical().unwrap();
    let reply =
        StreamTokenObserverReplyV1::current(vec![0xa4; 32], observation_bytes.clone()).unwrap();
    let encoded = encode_stream_token_observer_reply(&query, &reply).unwrap();
    let limits = |bytes| DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX);

    assert_eq!(
        with_decode_limits_scope(limits(0), || {
            decode_stream_token_observer_request(&binding, &payload)
        })
        .err(),
        Some(BrokerError::Unavailable),
        "the real manifest request decoder preserves enclosing admission refusal"
    );
    // The reply path first decodes the original request and the broker envelope.
    // Measure that exact prefix, so the next actual refusal occurs at the newly
    // typed manifest observation decoder, not the separately owned broker codec.
    let ((), prefix) = with_decode_limits_measured(limits(usize::MAX), || {
        decode_stream_token_observer_request(&binding, &payload).unwrap();
        decode_canonical_with_policy::<StreamTokenObserverReplyWireV1>(
            &encoded,
            MAX_STREAM_TOKEN_HARDWARE_FRAME_BYTES_V1,
            STREAM_TOKEN_HARDWARE_DECODE_POLICY_V1,
        )
        .unwrap();
    });
    assert!(prefix.total_allocated_bytes() > 0);
    assert_eq!(
        with_decode_limits_scope(limits(prefix.total_allocated_bytes()), || {
            decode_stream_token_observer_reply(&binding, &payload, &encoded)
        })
        .err(),
        Some(BrokerError::Unavailable),
        "a post-envelope evidence decoder refusal is operational"
    );
    assert_eq!(
        stream_token_transport_error(BrokerError::Unavailable),
        StreamTokenSignerCallErrorV1::Unavailable
    );
    let recovered = decode_stream_token_observer_reply(&binding, &payload, &encoded)
        .expect("the exact same bytes decode after the enclosing scope retires");
    assert_eq!(
        recovered.current_evidence(),
        Some((&[0xa4; 32][..], observation_bytes.as_slice()))
    );
    assert_eq!(query.encode_canonical().unwrap(), payload);
    assert_eq!(
        encode_stream_token_observer_reply(&query, &reply).unwrap(),
        encoded
    );
}

#[test]
fn observer_evidence_semantic_rejections_keep_each_service_category() {
    use norito::core::with_decode_limits_scope;

    let binding = token_signer_binding();
    let query = stream_token_signer_test_support::query();
    let payload = query.encode_canonical().unwrap();
    let mut malformed = payload.clone();
    *malformed.last_mut().unwrap() ^= 1;
    assert_eq!(
        with_decode_limits_scope(
            DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
            || decode_stream_token_observer_request(&binding, &malformed),
        )
        .err(),
        Some(BrokerError::Rejected),
        "malformed canonical input is semantic even inside a zero allowance"
    );
    let mut invalid = query.clone();
    invalid.challenge = [0; 32];
    let original = invalid.encode_canonical().unwrap_err();
    assert!(!original.is_retryable());
    assert_eq!(
        stream_token_transport_error(stream_token_evidence_error(
            &original,
            BrokerError::Rejected
        )),
        StreamTokenSignerCallErrorV1::Refused,
        "client request encoding retains its original semantic category"
    );
    let invalid_payload = norito::encode_canonical(&invalid).unwrap();
    assert_eq!(
        decode_stream_token_observer_request(&binding, &invalid_payload).err(),
        Some(BrokerError::Rejected)
    );
    let mut claim = stream_token_signer_test_support::state_claim(&query);
    claim.body.request_digest = [0xa2; 32];
    let reply =
        StreamTokenObserverReplyV1::current(vec![0xa4; 32], claim.encode_canonical().unwrap())
            .unwrap();
    let encoded = encode_stream_token_observer_reply(&query, &reply).unwrap();
    assert_eq!(
        decode_stream_token_observer_reply(&binding, &payload, &encoded).err(),
        Some(BrokerError::Protocol),
        "substituted signed request claim is not a local capacity failure"
    );
    assert_eq!(
        stream_token_transport_error(BrokerError::Protocol),
        StreamTokenSignerCallErrorV1::InvalidResponse
    );
}
