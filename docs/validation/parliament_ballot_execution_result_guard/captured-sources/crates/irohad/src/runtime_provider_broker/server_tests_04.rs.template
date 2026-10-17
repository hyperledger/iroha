use crate::external_software_signer::{
    consensus_threshold_beacon_broker_max_committee_test_fixture_v1,
    consensus_threshold_beacon_broker_test_fixture_v1,
    consensus_threshold_tle_broker_max_committee_test_fixture_v1,
    consensus_threshold_tle_broker_test_fixture_v1,
};
use crate::runtime_provider_broker::api::{
    ConsensusSignerProviderQualificationV1, GlobalBeaconPartialSignerBrokerBackendErrorV1,
    GlobalBeaconPartialSignerBrokerBackendV1,
    ParliamentTlePartialReleaseSignerBrokerBackendErrorV1,
    ParliamentTlePartialReleaseSignerBrokerBackendV1,
};

fn read_consensus_signer_operation(
    stream: &mut BrokerTestStream,
    session_network_id: &NetworkId,
) -> OperationRequestV1 {
    // The fake broker represents a separate process, so its decode admission
    // must not compete with the in-process client for one process-local pool.
    let decode_pool = Arc::clone(&stream.decode_pool);
    let (announced_slot, announced_operation, frame, admission) =
        read_operation_request_frame_inner(stream, None, Some(decode_pool))
            .expect("read fake consensus-signer operation");
    let _scope = admission.enter();
    let request = decode_operation_frame::<OperationRequestV1>(
        &frame,
        FRAME_KIND_OPERATION_REQUEST_V1,
        announced_operation,
    )
    .expect("decode fake consensus-signer operation");
    validate_operation_request_with_session(&request, None, session_network_id)
        .expect("validate network-bound fake consensus-signer operation");
    assert_eq!(request.binding.slot, announced_slot);
    assert_eq!(request.operation, announced_operation);
    request
}

fn expect_and_answer_consensus_signer_qualification(
    stream: &mut BrokerTestStream,
    expected_request_id: u64,
    revision: u64,
    policy_digest: [u8; 32],
) {
    let qualify = read_operation(stream);
    assert_eq!(qualify.request_id, expected_request_id);
    assert_eq!(qualify.operation, OPERATION_QUALIFY_V1);
    let qualification = encode_canonical(
        &QualificationResultWireV1 {
            revision,
            policy_digest,
        },
        MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
    )
    .expect("encode exact consensus-signer qualification");
    send_operation(
        stream,
        &operation_response(&qualify, STATUS_OK_V1, qualification),
    );
}

#[test]
fn fenced_privacy_head_reader_binding_is_exact_and_drift_checked() {
    let binding = privacy_reader_binding();
    let publisher_binding = privacy_publisher_binding();
    assert_ne!(binding.slot, publisher_binding.slot);
    assert_eq!(binding.handle, publisher_binding.handle);
    assert_eq!(binding.revision, publisher_binding.revision);
    assert_eq!(binding.policy_digest, publisher_binding.policy_digest);
    assert_eq!(validate_wire_binding(&binding), Ok(()));
    assert_eq!(
        validate_observation(&binding, &observation(&binding)),
        Ok(())
    );
    let backends = RuntimeProviderBrokerBackendsV1::new()
        .with_fenced_privacy_head_reader(Arc::new(ServerTestFencedPrivacyHeadReader::exact()));
    assert_backend_fixture(
        &binding,
        &backends,
        "stable exact fenced privacy head reader qualifies twice",
    );
    let substituted = RuntimeProviderBrokerBackendsV1::new().with_fenced_privacy_head_reader(
        Arc::new(ServerTestFencedPrivacyHeadReader::substituted()),
    );
    assert_eq!(
        make_server_observation(network_id(), &binding, &substituted),
        Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch)
    );
    let drifted = RuntimeProviderBrokerBackendsV1::new()
        .with_fenced_privacy_head_reader(Arc::new(ServerTestFencedPrivacyHeadReader::drifting()));
    assert_eq!(
        make_server_observation(network_id(), &binding, &drifted),
        Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch)
    );
}
#[test]
fn fenced_privacy_head_reader_operation_is_canonical_bounded_and_exact() {
    assert!(operation_is_known(
        OPERATION_FENCED_PRIVACY_READ_HEAD_WITH_ANCESTRY_V1
    ));
    assert_eq!(
        operation_frame_limit(OPERATION_FENCED_PRIVACY_READ_HEAD_WITH_ANCESTRY_V1),
        MAX_FENCED_PRIVACY_HEAD_FRAME_BYTES_V1
    );
    let binding = privacy_reader_binding();
    let reader = Arc::new(ServerTestFencedPrivacyHeadReader::exact());
    let backends =
        RuntimeProviderBrokerBackendsV1::new().with_fenced_privacy_head_reader(reader.clone());
    let observed = make_server_observation(network_id(), &binding, &backends)
        .expect("qualify stable fenced privacy head reader");
    let state = singleton_state(
        "fenced-privacy-head-reader-test-chain",
        binding.clone(),
        observed.clone(),
        backends,
    );
    let (head, publication) = sample_fenced_privacy_head_evidence();
    let required_ancestors = vec![head];
    let required_publications = vec![publication];
    let wire = FencedPrivacyHeadReadRequestWireV1::from_required_evidence(
        &required_ancestors,
        &required_publications,
    );
    assert_eq!(
        wire.to_required_evidence()
            .expect("reconstruct exact fenced head evidence"),
        (required_ancestors.clone(), required_publications.clone())
    );
    let request = make_operation_request(
        [0xE1; 32],
        1,
        binding.clone(),
        observed.metadata_digest,
        OPERATION_FENCED_PRIVACY_READ_HEAD_WITH_ANCESTRY_V1,
        encode_canonical(&wire, MAX_FENCED_PRIVACY_HEAD_FRAME_BYTES_V1)
            .expect("encode fenced head read"),
    )
    .expect("construct fenced head read operation");
    validate_operation_request(&request).expect("validate fenced head read");
    let result = dispatch_server_operation(&state, &request).expect("dispatch fenced head read");
    let proof = decode_canonical::<FencedTransparencyHeadAncestryProofWireV1>(
        &result,
        MAX_FENCED_PRIVACY_HEAD_FRAME_BYTES_V1,
    )
    .and_then(|wire| wire.to_proof(&required_ancestors, &required_publications))
    .expect("decode exact authenticated ancestry proof");
    assert_eq!(proof.authoritative_head(), Some(head));
    assert_eq!(proof.verified_ancestors(), required_ancestors);
    assert_eq!(proof.verified_publications(), required_publications);
    assert_eq!(reader.read_calls.load(Ordering::SeqCst), 1);
    let genesis_wire = FencedPrivacyHeadReadRequestWireV1::from_required_evidence(&[], &[]);
    let genesis_request = make_operation_request(
        [0xE2; 32],
        2,
        binding.clone(),
        observed.metadata_digest,
        OPERATION_FENCED_PRIVACY_READ_HEAD_WITH_ANCESTRY_V1,
        encode_canonical(&genesis_wire, MAX_FENCED_PRIVACY_HEAD_FRAME_BYTES_V1)
            .expect("encode authenticated genesis read"),
    )
    .expect("construct authenticated genesis operation");
    let genesis_result = dispatch_server_operation(&state, &genesis_request)
        .expect("dispatch authenticated genesis read");
    let genesis_proof = decode_canonical::<FencedTransparencyHeadAncestryProofWireV1>(
        &genesis_result,
        MAX_FENCED_PRIVACY_HEAD_FRAME_BYTES_V1,
    )
    .and_then(|wire| wire.to_proof(&[], &[]))
    .expect("decode authenticated genesis proof");
    assert_eq!(genesis_proof.authoritative_head(), None);
    assert_eq!(reader.read_calls.load(Ordering::SeqCst), 2);
    let mut malformed = wire.clone();
    malformed.version = node::FENCED_TRANSPARENCY_PUBLICATION_VERSION_V1.wrapping_add(1);
    let malformed_request = make_operation_request(
        [0xE3; 32],
        3,
        binding.clone(),
        observed.metadata_digest,
        OPERATION_FENCED_PRIVACY_READ_HEAD_WITH_ANCESTRY_V1,
        encode_canonical(&malformed, MAX_FENCED_PRIVACY_HEAD_FRAME_BYTES_V1)
            .expect("encode malformed fenced head read"),
    )
    .expect("construct malformed fenced head read operation");
    assert_eq!(
        validate_operation_request(&malformed_request),
        Err(BrokerError::Rejected)
    );
    assert_eq!(reader.read_calls.load(Ordering::SeqCst), 2);
    let excessive = FencedPrivacyHeadReadRequestWireV1 {
        version: node::FENCED_TRANSPARENCY_PUBLICATION_VERSION_V1,
        required_ancestors: vec![
            FencedTransparencyTargetHeadWireV1::from_head(head);
            MAX_FENCED_PRIVACY_HEAD_EVIDENCE_ITEMS_V1 + 1
        ],
        required_publications: Vec::new(),
    };
    let excessive_request = make_operation_request(
        [0xE4; 32],
        4,
        binding.clone(),
        observed.metadata_digest,
        OPERATION_FENCED_PRIVACY_READ_HEAD_WITH_ANCESTRY_V1,
        encode_canonical(&excessive, MAX_FENCED_PRIVACY_HEAD_FRAME_BYTES_V1)
            .expect("encode excessive fenced head evidence"),
    )
    .expect("construct excessive fenced head operation");
    assert_eq!(
        validate_operation_request(&excessive_request),
        Err(BrokerError::Rejected)
    );
    assert_eq!(reader.read_calls.load(Ordering::SeqCst), 2);
    let substituted_reader = Arc::new(ServerTestFencedPrivacyHeadReader::substituted_proof());
    let proof_backends = RuntimeProviderBrokerBackendsV1::new()
        .with_fenced_privacy_head_reader(substituted_reader.clone());
    let substituted_observed = make_server_observation(network_id(), &binding, &proof_backends)
        .expect("qualify head reader that substitutes proof evidence");
    let substituted_state = singleton_state(
        "fenced-privacy-substituted-head-proof-test-chain",
        binding.clone(),
        substituted_observed,
        proof_backends,
    );
    assert_eq!(
        dispatch_server_operation(&substituted_state, &request),
        Err(BrokerError::Rejected)
    );
    assert_eq!(substituted_reader.read_calls.load(Ordering::SeqCst), 1);
    let drift_reader = Arc::new(ServerTestFencedPrivacyHeadReader::drifting_after_read());
    let drift_backends = RuntimeProviderBrokerBackendsV1::new()
        .with_fenced_privacy_head_reader(drift_reader.clone());
    let drift_observed = make_server_observation(network_id(), &binding, &drift_backends)
        .expect("head reader is stable before its authenticated read");
    let drift_state = singleton_state(
        "fenced-privacy-head-read-drift-test-chain",
        binding,
        drift_observed,
        drift_backends,
    );
    assert_eq!(
        dispatch_server_operation(&drift_state, &request),
        Err(BrokerError::StaleOrRevoked)
    );
    assert_eq!(drift_reader.read_calls.load(Ordering::SeqCst), 1);
    let unit = encode_canonical(&(), MAX_FENCED_PRIVACY_HEAD_FRAME_BYTES_V1)
        .expect("encode payload-free head-read failure");
    assert_eq!(
        make_operation_response(
            &request,
            STATUS_CONFLICT_V1,
            unit.clone(),
            &state.network_id,
        ),
        Err(BrokerError::Protocol)
    );
    assert_eq!(
        make_operation_response(
            &request,
            STATUS_AMBIGUOUS_V1,
            unit.clone(),
            &state.network_id,
        ),
        Err(BrokerError::Protocol)
    );
    assert!(
        make_operation_response(&request, STATUS_UNAVAILABLE_V1, unit, &state.network_id,).is_ok()
    );
}
#[test]
fn por_replay_archive_binding_is_exact_bounded_and_drift_checked() {
    let binding = replay_archive_binding();
    let exact = por_replay_archive_exact_binding(&binding).expect("exact replay-archive binding");
    let (limits, bounds) = por_replay_archive_configured_proof_bounds(&binding)
        .expect("bounded replay-archive proof policy");
    assert_eq!(limits.max_successor_receipts, 1_024);
    assert_eq!(limits.max_successor_proof_bytes, 1_048_576);
    assert_eq!(bounds.max_successor_receipts(), 1_024);
    assert_eq!(bounds.max_successor_proof_bytes(), 1_048_576);
    assert_eq!(validate_wire_binding(&binding), Ok(()));
    assert_eq!(
        validate_observation(&binding, &observation(&binding)),
        Ok(())
    );
    let backends = RuntimeProviderBrokerBackendsV1::new()
        .with_por_finalized_replay_archive(Arc::new(ServerTestPorReplayArchive::exact(exact)));
    assert_eq!(
        validate_exact_backend_set(std::slice::from_ref(&binding), &backends),
        Ok(())
    );
    make_server_observation(network_id(), &binding, &backends)
        .expect("stable exact replay archive qualifies twice");
    assert_eq!(
        validate_exact_backend_set(&[], &backends),
        Err(RuntimeProviderBrokerServerErrorV1::BackendSetMismatch)
    );
    let mut confused = binding.clone();
    confused.pop_credential_runtime_binding = pop_runtime_binding().pop_credential_runtime_binding;
    assert!(validate_wire_binding(&confused).is_err());
    let mut missing_limits = binding.clone();
    missing_limits.por_replay_archive_proof_limits = None;
    assert!(validate_wire_binding(&missing_limits).is_err());
    let mut zero_limits = binding.clone();
    zero_limits
        .por_replay_archive_proof_limits
        .as_mut()
        .expect("proof limits")
        .max_successor_receipts = 0;
    assert!(validate_wire_binding(&zero_limits).is_err());
    let mut excessive_limits = binding.clone();
    excessive_limits
        .por_replay_archive_proof_limits
        .as_mut()
        .expect("proof limits")
        .max_successor_proof_bytes = u64::try_from(MAX_POR_REPLAY_ARCHIVE_SUCCESSOR_PROOF_BYTES_V1)
        .expect("proof ceiling fits u64")
        + 1;
    assert!(validate_wire_binding(&excessive_limits).is_err());
    let later = node::PorFinalizedReplayArchiveBindingV1::try_new(
        exact.archive_id,
        exact.revision + 1,
        exact.policy_digest,
        exact.signing_public_key,
    )
    .expect("valid drifted replay-archive binding");
    let drifted = RuntimeProviderBrokerBackendsV1::new().with_por_finalized_replay_archive(
        Arc::new(ServerTestPorReplayArchive::drifting(exact, later)),
    );
    assert_eq!(
        make_server_observation(network_id(), &binding, &drifted),
        Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch)
    );
}
#[test]
fn por_replay_archive_lookup_results_round_trip_found_and_absent() {
    let binding = replay_archive_binding();
    let exact = por_replay_archive_exact_binding(&binding).expect("exact replay-archive binding");
    let (limits, bounds) = por_replay_archive_configured_proof_bounds(&binding)
        .expect("bounded replay-archive proof policy");
    let record = por_replay_archive_record_fixture();
    let receipt_digest =
        node::PorFinalizedReplayArchiveReceiptV1::signing_digest(exact, &record, None)
            .expect("derive replay-archive receipt digest");
    let receipt = node::PorFinalizedReplayArchiveReceiptV1::try_new(
        exact,
        &record,
        None,
        test_signature(&receipt_digest),
    )
    .expect("authenticate replay-archive receipt");
    let found_request = PorReplayArchiveLookupRequestWireV1 {
        challenge_id: record.challenge_id(),
        expected_checkpoint_head: receipt,
        max_successor_receipts: limits.max_successor_receipts,
        max_successor_proof_bytes: limits.max_successor_proof_bytes,
    };
    let found = node::PorFinalizedReplayArchiveLookupV1::Found(Box::new(
        node::PorFinalizedReplayArchiveReadbackV1 {
            record: record.clone(),
            receipt,
            successor_receipts: Vec::new(),
        },
    ));
    let found_wire =
        por_replay_archive_lookup_to_wire(found.clone(), &found_request, exact, bounds)
            .expect("validate and encode found lookup");
    let found_bytes = encode_canonical(&found_wire, MAX_POR_REPLAY_ARCHIVE_FRAME_BYTES_V1)
        .expect("encode found lookup wire");
    let found_decoded = decode_canonical::<PorReplayArchiveLookupOutcomeWireV1>(
        &found_bytes,
        MAX_POR_REPLAY_ARCHIVE_FRAME_BYTES_V1,
    )
    .expect("decode found lookup wire");
    assert_eq!(found_decoded, found_wire);
    assert_eq!(
        por_replay_archive_lookup_from_wire(&found_decoded, &found_request, &binding,),
        Ok(found)
    );
    let absent_challenge_id = [0xFA; 32];
    let absence_digest = node::PorFinalizedReplayArchiveAbsenceProofV1::signing_digest(
        exact,
        absent_challenge_id,
        receipt,
    )
    .expect("derive replay-archive absence digest");
    let absence = node::PorFinalizedReplayArchiveAbsenceProofV1::try_new(
        exact,
        absent_challenge_id,
        receipt,
        test_signature(&absence_digest),
    )
    .expect("authenticate replay-archive absence proof");
    let absent_request = PorReplayArchiveLookupRequestWireV1 {
        challenge_id: absent_challenge_id,
        expected_checkpoint_head: receipt,
        max_successor_receipts: limits.max_successor_receipts,
        max_successor_proof_bytes: limits.max_successor_proof_bytes,
    };
    let absent = node::PorFinalizedReplayArchiveLookupV1::Absent(Box::new(absence));
    let absent_wire =
        por_replay_archive_lookup_to_wire(absent.clone(), &absent_request, exact, bounds)
            .expect("validate and encode absent lookup");
    let absent_bytes = encode_canonical(&absent_wire, MAX_POR_REPLAY_ARCHIVE_FRAME_BYTES_V1)
        .expect("encode absent lookup wire");
    let absent_decoded = decode_canonical::<PorReplayArchiveLookupOutcomeWireV1>(
        &absent_bytes,
        MAX_POR_REPLAY_ARCHIVE_FRAME_BYTES_V1,
    )
    .expect("decode absent lookup wire");
    assert_eq!(absent_decoded, absent_wire);
    assert_eq!(
        por_replay_archive_lookup_from_wire(&absent_decoded, &absent_request, &binding,),
        Ok(absent)
    );
    let mut substituted_request = absent_request;
    substituted_request.challenge_id = [0xFB; 32];
    assert_eq!(
        por_replay_archive_lookup_from_wire(&absent_decoded, &substituted_request, &binding,),
        Err(BrokerError::Rejected)
    );
}
#[test]
fn por_replay_archive_operations_are_bounded_and_append_is_ambiguous() {
    for operation in [
        OPERATION_POR_REPLAY_ARCHIVE_READINESS_V1,
        OPERATION_POR_REPLAY_ARCHIVE_CURRENT_HEAD_V1,
        OPERATION_POR_REPLAY_ARCHIVE_APPEND_V1,
        OPERATION_POR_REPLAY_ARCHIVE_LOOKUP_V1,
    ] {
        assert!(operation_is_known(operation));
    }
    assert_eq!(
        operation_frame_limit(OPERATION_POR_REPLAY_ARCHIVE_READINESS_V1),
        MAX_POR_REPLAY_ARCHIVE_CONTROL_FRAME_BYTES_V1
    );
    assert_eq!(
        operation_frame_limit(OPERATION_POR_REPLAY_ARCHIVE_CURRENT_HEAD_V1),
        MAX_POR_REPLAY_ARCHIVE_CONTROL_FRAME_BYTES_V1
    );
    assert_eq!(
        operation_frame_limit(OPERATION_POR_REPLAY_ARCHIVE_APPEND_V1),
        MAX_POR_REPLAY_ARCHIVE_FRAME_BYTES_V1
    );
    assert_eq!(
        operation_frame_limit(OPERATION_POR_REPLAY_ARCHIVE_LOOKUP_V1),
        MAX_POR_REPLAY_ARCHIVE_FRAME_BYTES_V1
    );
    let binding = replay_archive_binding();
    let exact = por_replay_archive_exact_binding(&binding).expect("exact replay-archive binding");
    let backends = RuntimeProviderBrokerBackendsV1::new()
        .with_por_finalized_replay_archive(Arc::new(ServerTestPorReplayArchive::exact(exact)));
    let observed = make_server_observation(network_id(), &binding, &backends)
        .expect("qualify stable replay archive");
    let state = singleton_state(
        "por-replay-archive-test-chain",
        binding.clone(),
        observed.clone(),
        backends,
    );
    for (request_id, operation) in [
        (1, OPERATION_POR_REPLAY_ARCHIVE_READINESS_V1),
        (2, OPERATION_POR_REPLAY_ARCHIVE_CURRENT_HEAD_V1),
    ] {
        let request = make_operation_request(
            [0xA1; 32],
            request_id,
            binding.clone(),
            observed.metadata_digest,
            operation,
            encode_canonical(&(), MAX_POR_REPLAY_ARCHIVE_CONTROL_FRAME_BYTES_V1)
                .expect("encode replay-archive control request"),
        )
        .expect("construct replay-archive request");
        validate_operation_request(&request).expect("validate replay-archive control request");
        let result = dispatch_server_operation(&state, &request)
            .expect("dispatch replay-archive control request");
        if operation == OPERATION_POR_REPLAY_ARCHIVE_READINESS_V1 {
            decode_canonical::<()>(&result, MAX_POR_REPLAY_ARCHIVE_CONTROL_FRAME_BYTES_V1)
                .expect("decode readiness");
        } else {
            assert_eq!(
                decode_canonical::<Option<node::PorFinalizedReplayArchiveReceiptV1>>(
                    &result,
                    MAX_POR_REPLAY_ARCHIVE_CONTROL_FRAME_BYTES_V1
                )
                .expect("decode current head"),
                None
            );
        }
    }
    let invalid_append = PorReplayArchiveAppendRequestWireV1 {
        canonical_record: Vec::new(),
        expected_previous_head: None,
    };
    let append_request = make_operation_request(
        [0xA2; 32],
        3,
        binding.clone(),
        observed.metadata_digest,
        OPERATION_POR_REPLAY_ARCHIVE_APPEND_V1,
        encode_canonical(&invalid_append, MAX_POR_REPLAY_ARCHIVE_FRAME_BYTES_V1)
            .expect("encode malformed append request"),
    )
    .expect("construct malformed append request");
    assert_eq!(
        validate_operation_request(&append_request),
        Err(BrokerError::Rejected)
    );
    let unit =
        encode_canonical(&(), MAX_OPERATION_FRAME_BYTES_V1).expect("encode payload-free failure");
    assert!(
        make_operation_response(
            &append_request,
            STATUS_AMBIGUOUS_V1,
            unit.clone(),
            &state.network_id,
        )
        .is_ok(),
        "append is the only replay-archive operation allowed to be ambiguous"
    );
    let lookup_request = make_operation_request(
        [0xA3; 32],
        4,
        binding,
        observed.metadata_digest,
        OPERATION_POR_REPLAY_ARCHIVE_LOOKUP_V1,
        unit.clone(),
    )
    .expect("construct lookup envelope");
    assert_eq!(
        make_operation_response(
            &lookup_request,
            STATUS_AMBIGUOUS_V1,
            unit,
            &state.network_id,
        ),
        Err(BrokerError::Protocol)
    );
}
#[test]
fn gateway_and_pop_wires_enforce_bounds_and_mutation_ambiguity() {
    let acme_binding = runtime_binding(
        IrohaRuntimeProviderSlotV1::GatewayAcmeClient,
        SERVER_TEST_ACME_HANDLE,
    );
    let acme_order = GatewayAcmeOrderRequestWireV1 {
        hostnames: vec!["gateway.example.com".to_owned()],
        account_email: Some("ops@example.com".to_owned()),
        directory_url: "https://acme.example.com/directory".to_owned(),
        dns_provider_id: Some("route53:production".to_owned()),
        dns01: true,
        tls_alpn_01: true,
    };
    assert_eq!(validate_gateway_acme_order(&acme_order), Ok(()));
    let oversized_wildcard = format!(
        "*.{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(60),
    );
    let mut invalid_acme_order = acme_order.clone();
    invalid_acme_order.hostnames = vec![oversized_wildcard];
    assert_eq!(
        validate_gateway_acme_order(&invalid_acme_order),
        Err(BrokerError::Rejected)
    );
    let acme_request = validated_operation(
        acme_binding,
        OPERATION_GATEWAY_ACME_ORDER_CERTIFICATE_V1,
        encode_canonical(&acme_order, MAX_GATEWAY_ACME_FRAME_BYTES_V1)
            .expect("encode valid ACME order"),
    );
    let ambiguous = make_operation_response(
        &acme_request,
        STATUS_AMBIGUOUS_V1,
        encode_canonical(&(), MAX_OPERATION_FRAME_BYTES_V1).expect("encode empty ambiguous result"),
        &network_id(),
    )
    .expect("construct ACME ambiguous response");
    assert_eq!(
        validate_operation_response(&acme_request, &ambiguous, &network_id(),),
        Ok(())
    );
    let compliance_binding = runtime_binding(
        IrohaRuntimeProviderSlotV1::GatewayComplianceFeedTransport,
        SERVER_TEST_COMPLIANCE_HANDLE,
    );
    let compliance_request_wire = GatewayComplianceFetchRequestWireV1 {
        url: "https://feeds.example.com/catalog".to_owned(),
        pinned_addresses: vec![
            IpAddressWireV1::from("8.8.8.8".parse::<std::net::IpAddr>().expect("public IPv4")),
            IpAddressWireV1::from("9.9.9.9".parse::<std::net::IpAddr>().expect("public IPv4")),
        ],
        connect_timeout: DurationWireV1::from_duration(Duration::from_secs(5)),
        total_timeout: DurationWireV1::from_duration(Duration::from_secs(10)),
        max_encoded_bytes: 1024,
    };
    validate_gateway_compliance_fetch_request(&compliance_request_wire)
        .expect("canonical pinned public compliance request");
    let mut private_address = compliance_request_wire.clone();
    private_address.pinned_addresses = vec![IpAddressWireV1::from(
        "127.0.0.1".parse::<std::net::IpAddr>().expect("loopback"),
    )];
    assert_eq!(
        validate_gateway_compliance_fetch_request(&private_address),
        Err(BrokerError::Rejected)
    );
    let compliance_request = validated_operation(
        compliance_binding,
        OPERATION_GATEWAY_COMPLIANCE_FETCH_V1,
        encode_canonical(
            &compliance_request_wire,
            MAX_GATEWAY_COMPLIANCE_FRAME_BYTES_V1,
        )
        .expect("encode valid compliance request"),
    );
    let invalid_ambiguity = operation_response(
        &compliance_request,
        STATUS_AMBIGUOUS_V1,
        encode_canonical(&(), MAX_OPERATION_FRAME_BYTES_V1).expect("encode empty ambiguous result"),
    );
    let invalid_frame = encode_frame(
        FRAME_KIND_OPERATION_RESPONSE_V1,
        &invalid_ambiguity,
        MAX_GATEWAY_COMPLIANCE_FRAME_BYTES_V1,
    );
    assert!(
        invalid_frame.is_ok(),
        "the canonical invalid-status fixture is within the compliance wire cap"
    );
    assert_eq!(
        validate_operation_response(&compliance_request, &invalid_ambiguity, &network_id(),),
        Err(BrokerError::Protocol)
    );
    let pop_binding = pop_runtime_binding();
    let exact = pop_binding
        .pop_credential_runtime_binding
        .as_ref()
        .expect("PoP exact metadata");
    let pop_resolve = validated_operation(
        pop_binding.clone(),
        OPERATION_POP_RUNTIME_OPEN_V1,
        encode_canonical(exact, MAX_POP_RUNTIME_FRAME_BYTES_V1).expect("encode exact PoP binding"),
    );
    let ambiguous_resolve = make_operation_response(
        &pop_resolve,
        STATUS_AMBIGUOUS_V1,
        encode_canonical(&(), MAX_OPERATION_FRAME_BYTES_V1).expect("encode empty ambiguous result"),
        &network_id(),
    )
    .expect("construct PoP resolve ambiguity");
    assert_eq!(
        validate_operation_response(&pop_resolve, &ambiguous_resolve, &network_id(),),
        Ok(())
    );
    let pop_wrap = validated_operation(
        pop_binding,
        OPERATION_POP_WALLET_WRAP_DEK_V1,
        encode_canonical(
            &PopWalletWrapDekRequestWireV1 {
                context: [0x91; 32],
                dek: [0x92; 32],
            },
            MAX_POP_RUNTIME_FRAME_BYTES_V1,
        )
        .expect("encode PoP KMS wrap request"),
    );
    let ambiguous_wrap = make_operation_response(
        &pop_wrap,
        STATUS_AMBIGUOUS_V1,
        encode_canonical(&(), MAX_OPERATION_FRAME_BYTES_V1).expect("encode empty ambiguous result"),
        &network_id(),
    )
    .expect("construct PoP wrap ambiguity");
    assert_eq!(
        validate_operation_response(&pop_wrap, &ambiguous_wrap, &network_id(),),
        Ok(())
    );
}
#[test]
fn reputation_runtime_bindings_and_observations_are_exactly_slot_shaped() {
    let slots = [
        (
            IrohaRuntimeProviderSlotV1::ReputationJournalTransactionSubmitter,
            32,
        ),
        (IrohaRuntimeProviderSlotV1::ReputationThresholdSigner, 33),
        (IrohaRuntimeProviderSlotV1::ReputationGovernanceDag, 34),
        (IrohaRuntimeProviderSlotV1::ReputationJournalCheckpoint, 50),
    ];
    for (slot, wire_id) in slots {
        assert_eq!(slot.wire_id(), wire_id);
        let catalog = reputation_catalog(slot);
        let binding = reputation_binding(slot);
        assert_eq!(validate_wire_binding(&binding), Ok(()), "{slot:?}");
        let observed = observation(&binding);
        assert_eq!(
            validate_observation(&binding, &observed),
            Ok(()),
            "{slot:?}"
        );
        assert!(matches!(
            prepare_test_server_state(&catalog, RuntimeProviderBrokerBackendsV1::new()),
            Err(RuntimeProviderBrokerServerErrorV1::BackendSetMismatch)
        ));
        prepare_test_server_state(&catalog, reputation_backends(slot))
            .unwrap_or_else(|error| panic!("accept exact {slot:?} backend: {error:?}"));
        assert!(matches!(
            prepare_test_server_state(&catalog, reputation_runtime_substituted_backends(slot),),
            Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch)
        ));
        let mut zero_revision = binding.clone();
        zero_revision.revision = Some(0);
        assert_eq!(
            validate_wire_binding(&zero_revision),
            Err(BrokerError::BindingMismatch),
            "{slot:?}"
        );
        let mut zero_digest = binding.clone();
        zero_digest.policy_digest = Some([0; 32]);
        assert_eq!(
            validate_wire_binding(&zero_digest),
            Err(BrokerError::BindingMismatch),
            "{slot:?}"
        );
        let mut role_confused = binding;
        role_confused.stream_token_signer_binding =
            token_signer_binding().stream_token_signer_binding;
        assert_eq!(
            validate_wire_binding(&role_confused),
            Err(BrokerError::BindingMismatch),
            "{slot:?}"
        );
    }
}
#[test]
fn reputation_checkpoint_load_is_bounded_and_slot_exact() {
    assert_eq!(OPERATION_REPUTATION_JOURNAL_CHECKPOINT_LOAD_V1, 101);
    assert_eq!(
        OPERATION_REPUTATION_JOURNAL_CHECKPOINT_COMPARE_AND_SWAP_V1,
        102
    );
    for operation in [
        OPERATION_REPUTATION_JOURNAL_CHECKPOINT_LOAD_V1,
        OPERATION_REPUTATION_JOURNAL_CHECKPOINT_COMPARE_AND_SWAP_V1,
    ] {
        assert!(operation_is_known(operation));
        assert_eq!(
            operation_frame_limit(operation),
            MAX_REPUTATION_JOURNAL_CHECKPOINT_FRAME_BYTES_V1
        );
        assert_eq!(
            operation_decode_policy(operation),
            REPUTATION_DECODE_POLICY_V1
        );
    }
    let slot = IrohaRuntimeProviderSlotV1::ReputationJournalCheckpoint;
    let catalog = reputation_catalog(slot);
    let state = prepare_test_server_state(&catalog, reputation_backends(slot))
        .expect("prepare exact reputation checkpoint backend");
    let binding = state.catalog[0].clone();
    let mut wrong_profile = binding.clone();
    wrong_profile.revision = Some(2);
    assert_eq!(
        validate_wire_binding(&wrong_profile),
        Err(BrokerError::BindingMismatch)
    );
    let payload = encode_canonical(
        &CHECKPOINT_LOAD_REQUEST_VERSION_V1,
        MAX_REPUTATION_JOURNAL_CHECKPOINT_FRAME_BYTES_V1,
    )
    .expect("encode checkpoint load request");
    assert_eq!(
        payload.len(),
        norito::core::Header::SIZE + core::mem::size_of::<u8>()
    );
    let request = make_operation_request(
        TEST_SESSION_ID,
        1,
        binding.clone(),
        state.observations[0].metadata_digest,
        OPERATION_REPUTATION_JOURNAL_CHECKPOINT_LOAD_V1,
        payload,
    )
    .expect("seal checkpoint load request");
    assert_ne!(request.session_id, [0; 32]);
    assert_ne!(request.request_id, 0);
    assert_ne!(request.provider_metadata_digest, [0; 32]);
    assert_eq!(
        operation_payload_digest(&request.payload),
        request.payload_digest,
        "checkpoint load payload digest"
    );
    validate_wire_binding(&request.binding).expect("validate checkpoint load request binding");
    let request_fields = OperationRequestFieldsV1 {
        session_id: request.session_id,
        request_id: request.request_id,
        binding: request.binding.clone(),
        provider_metadata_digest: request.provider_metadata_digest,
        operation: request.operation,
        payload_digest: request.payload_digest,
        payload_len: u64::try_from(request.payload.len())
            .expect("checkpoint load payload length fits u64"),
    };
    assert_eq!(
        operation_request_digest(&request_fields).expect("digest checkpoint load request fields"),
        request.request_digest,
        "checkpoint load request digest"
    );
    assert_eq!(
        decode_canonical::<u8>(
            &request.payload,
            MAX_REPUTATION_JOURNAL_CHECKPOINT_FRAME_BYTES_V1,
        )
        .expect("decode checkpoint load payload"),
        CHECKPOINT_LOAD_REQUEST_VERSION_V1
    );
    validate_operation_payload(&request, None, &network_id())
        .expect("validate checkpoint load operation payload");
    validate_operation_request(&request).expect("validate checkpoint load request");
    let result = dispatch_server_operation(&state, &request).expect("dispatch checkpoint load");
    assert_eq!(
        decode_canonical::<Option<Vec<u8>>>(
            &result,
            MAX_REPUTATION_JOURNAL_CHECKPOINT_FRAME_BYTES_V1,
        )
        .expect("decode empty checkpoint head"),
        None
    );
    validate_operation_result(&request, STATUS_OK_V1, &result, &state.network_id)
        .expect("validate checkpoint load result");
    let unsupported_version = CHECKPOINT_LOAD_REQUEST_VERSION_V1 ^ u8::MAX;
    let alternate_version = make_operation_request(
        TEST_SESSION_ID,
        2,
        binding.clone(),
        state.observations[0].metadata_digest,
        OPERATION_REPUTATION_JOURNAL_CHECKPOINT_LOAD_V1,
        encode_canonical(
            &unsupported_version,
            MAX_REPUTATION_JOURNAL_CHECKPOINT_FRAME_BYTES_V1,
        )
        .expect("encode alternate checkpoint load version"),
    )
    .expect("seal alternate checkpoint load version");
    assert_eq!(
        validate_operation_request(&alternate_version),
        Err(BrokerError::Rejected)
    );
    let mut trailing_payload = request.payload.clone();
    trailing_payload.push(0);
    let trailing = make_operation_request(
        TEST_SESSION_ID,
        3,
        binding.clone(),
        state.observations[0].metadata_digest,
        OPERATION_REPUTATION_JOURNAL_CHECKPOINT_LOAD_V1,
        trailing_payload,
    )
    .expect("seal trailing checkpoint load payload");
    assert_eq!(
        validate_operation_request(&trailing),
        Err(BrokerError::Protocol)
    );
    let malformed_compare = encode_canonical(
        &ReputationJournalCheckpointCompareAndSwapRequestWireV1 {
            expected_revision: Some([0; 32]),
            next_record: vec![0],
        },
        MAX_REPUTATION_JOURNAL_CHECKPOINT_FRAME_BYTES_V1,
    )
    .expect("encode malformed checkpoint CAS");
    let malformed_compare = make_operation_request(
        TEST_SESSION_ID,
        4,
        binding,
        state.observations[0].metadata_digest,
        OPERATION_REPUTATION_JOURNAL_CHECKPOINT_COMPARE_AND_SWAP_V1,
        malformed_compare,
    )
    .expect("seal malformed checkpoint CAS");
    assert_eq!(
        validate_operation_request(&malformed_compare),
        Err(BrokerError::Rejected)
    );
    let ambiguous_compare = make_operation_response(
        &malformed_compare,
        STATUS_AMBIGUOUS_V1,
        encode_canonical(&(), MAX_OPERATION_FRAME_BYTES_V1)
            .expect("encode empty ambiguous checkpoint result"),
        &state.network_id,
    )
    .expect("construct checkpoint CAS ambiguity");
    assert_eq!(
        validate_operation_response(&malformed_compare, &ambiguous_compare, &state.network_id,),
        Ok(())
    );
    let journal_binding =
        reputation_binding(IrohaRuntimeProviderSlotV1::ReputationJournalTransactionSubmitter);
    let cross_slot = make_operation_request(
        TEST_SESSION_ID,
        5,
        journal_binding.clone(),
        observation(&journal_binding).metadata_digest,
        OPERATION_REPUTATION_JOURNAL_CHECKPOINT_LOAD_V1,
        encode_canonical(
            &CHECKPOINT_LOAD_REQUEST_VERSION_V1,
            MAX_REPUTATION_JOURNAL_CHECKPOINT_FRAME_BYTES_V1,
        )
        .expect("encode cross-slot checkpoint load"),
    )
    .expect("seal cross-slot checkpoint load");
    assert_eq!(
        validate_operation_request(&cross_slot),
        Err(BrokerError::BindingMismatch)
    );
}
#[test]
fn reputation_runtime_operations_are_strict_and_reconcile_exact_keys() {
    use test_reputation::ReputationJournalTransactionSubmitOutcomeV1;

    assert_eq!(OPERATION_REPUTATION_JOURNAL_SUPPORTS_AUTHORITY_V1, 16);
    assert_eq!(OPERATION_REPUTATION_JOURNAL_SUBMIT_V1, 17);
    assert_eq!(OPERATION_REPUTATION_THRESHOLD_RECONCILE_V1, 18);
    assert_eq!(OPERATION_REPUTATION_GOVERNANCE_RECONCILE_V1, 19);
    for operation in 16..=19 {
        assert!(operation_is_known(operation));
        assert_eq!(
            operation_frame_limit(operation),
            MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1
        );
    }
    let authority_keypair = KeyPair::try_from_seed(vec![0x88; 32], Algorithm::Ed25519)
        .expect("derive reputation broker authority");
    let authority = AccountId::new(authority_keypair.public_key().clone());
    let supports_payload = encode_canonical(
        &ReputationJournalSupportsAuthorityRequestWireV1 {
            authority: authority.clone(),
        },
        MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1,
    )
    .expect("encode supports-authority request");
    let journal_state = prepare_test_server_state(
        &reputation_catalog(IrohaRuntimeProviderSlotV1::ReputationJournalTransactionSubmitter),
        reputation_backends(IrohaRuntimeProviderSlotV1::ReputationJournalTransactionSubmitter),
    )
    .expect("prepare exact reputation journal backend");
    assert_eq!(
        ensure_reputation_session_network(&network_id_from(0x16), &journal_state.network_id,),
        Err(BrokerError::BindingMismatch),
        "the journal submitter cannot be used as a cross-network deputy"
    );
    let supports = reputation_request(
        &journal_state,
        1,
        OPERATION_REPUTATION_JOURNAL_SUPPORTS_AUTHORITY_V1,
        supports_payload.clone(),
    );
    validate_operation_request(&supports).expect("validate supports-authority request");
    let supports_result = dispatch_server_operation(&journal_state, &supports)
        .expect("dispatch supports-authority request");
    validate_operation_result(
        &supports,
        STATUS_OK_V1,
        &supports_result,
        &journal_state.network_id,
    )
    .expect("validate supports-authority result");
    assert!(
        decode_canonical::<bool>(&supports_result, MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1,)
            .expect("decode supports-authority result")
    );
    let drifting_journal_state = prepare_test_server_state(
        &reputation_catalog(IrohaRuntimeProviderSlotV1::ReputationJournalTransactionSubmitter),
        RuntimeProviderBrokerBackendsV1::new().with_reputation_journal_transaction_submitter(
            Arc::new(ServerTestReputationJournalSubmitter::drifting_after_operation()),
        ),
    )
    .expect("prepare drifting reputation journal backend");
    let drifting_supports = reputation_request(
        &drifting_journal_state,
        1,
        OPERATION_REPUTATION_JOURNAL_SUPPORTS_AUTHORITY_V1,
        supports_payload.clone(),
    );
    validate_operation_request(&drifting_supports)
        .expect("validate drifting supports-authority request");
    assert_eq!(
        dispatch_server_operation(&drifting_journal_state, &drifting_supports),
        Err(BrokerError::StaleOrRevoked),
        "read-only post-operation qualification drift is definitive"
    );
    let mut trailing_supports = supports_payload.clone();
    trailing_supports.push(0);
    let trailing = reputation_request(
        &journal_state,
        2,
        OPERATION_REPUTATION_JOURNAL_SUPPORTS_AUTHORITY_V1,
        trailing_supports,
    );
    assert!(validate_operation_request(&trailing).is_err());
    let malformed_submit = ReputationJournalTransactionRequestWireV1 {
        sequence: 0,
        network_id: network_id(),
        authority: authority.clone(),
        event_id: iroha_data_model::sorafs::reputation::ReputationJournalEventIdV1::ZERO,
        source_id: iroha_data_model::sorafs::reputation::ReputationJournalSourceIdV1::ZERO,
        attempt: 0,
        idempotency_key: [0; 32],
        canonical_instruction: Vec::new(),
    };
    let malformed_submit = reputation_request(
        &journal_state,
        3,
        OPERATION_REPUTATION_JOURNAL_SUBMIT_V1,
        encode_canonical(&malformed_submit, MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1)
            .expect("encode malformed reputation journal submit"),
    );
    assert_eq!(
        validate_operation_request(&malformed_submit),
        Err(BrokerError::Protocol),
        "the missing mandatory typed instruction fails canonical decoding before request validation"
    );
    for outcome in [
        ReputationJournalTransactionSubmitOutcomeV1::Queued {
            receipt: [0x71; 32],
        },
        ReputationJournalTransactionSubmitOutcomeV1::NotQueued {
            receipt: [0x72; 32],
        },
        ReputationJournalTransactionSubmitOutcomeV1::Ambiguous {
            receipt: [0x73; 32],
        },
    ] {
        let wire = reputation_journal_submit_result_to_wire(outcome)
            .expect("encode reputation journal result");
        assert_eq!(
            reputation_journal_submit_result_from_wire(wire),
            Ok(outcome)
        );
    }
    assert_eq!(
        reputation_journal_submit_result_from_wire(
            ReputationJournalTransactionSubmitResultWireV1 {
                outcome: 1,
                receipt: [0; 32],
            },
        ),
        Err(BrokerError::Rejected)
    );
    let threshold_backend = Arc::new(ServerTestReputationThresholdSigner::exact());
    let threshold_state = prepare_test_server_state(
        &reputation_catalog(IrohaRuntimeProviderSlotV1::ReputationThresholdSigner),
        RuntimeProviderBrokerBackendsV1::new()
            .with_reputation_threshold_signer(threshold_backend.clone()),
    )
    .expect("prepare exact reputation threshold signer");
    let threshold_request = threshold_request();
    let threshold_payload = encode_canonical(
        &reputation_threshold_request_to_wire(&threshold_request)
            .expect("project reputation threshold request"),
        MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1,
    )
    .expect("encode reputation threshold request");
    let mut cross_network_threshold_request = threshold_request.clone();
    cross_network_threshold_request.material.network_id = network_id_from(0x16);
    cross_network_threshold_request.material_digest = reputation_hash_canonical(
        b"sorafs-reputation-unsigned-material-delivery-v1",
        &cross_network_threshold_request.material,
    )
    .expect("digest cross-network reputation threshold material");
    cross_network_threshold_request.idempotency_key = reputation_publication_idempotency_key(
        b"sorafs-reputation-threshold-signing-operation-v1",
        cross_network_threshold_request.sequence,
        cross_network_threshold_request.material_digest,
        None,
    )
    .expect("derive cross-network threshold idempotency key");
    let cross_network_threshold = reputation_request(
        &threshold_state,
        3,
        OPERATION_REPUTATION_THRESHOLD_RECONCILE_V1,
        encode_canonical(
            &reputation_threshold_request_to_wire(&cross_network_threshold_request)
                .expect("project cross-network reputation threshold request"),
            MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1,
        )
        .expect("encode cross-network reputation threshold request"),
    );
    validate_operation_request(&cross_network_threshold)
        .expect("cross-network threshold request is otherwise canonical");
    assert_eq!(
        dispatch_server_operation(&threshold_state, &cross_network_threshold),
        Err(BrokerError::BindingMismatch),
        "the threshold signer cannot be used as a cross-network deputy"
    );
    for request_id in [1, 2] {
        let operation = reputation_request(
            &threshold_state,
            request_id,
            OPERATION_REPUTATION_THRESHOLD_RECONCILE_V1,
            threshold_payload.clone(),
        );
        validate_operation_request(&operation).expect("validate reputation threshold request");
        let result = dispatch_server_operation(&threshold_state, &operation)
            .expect("reconcile reputation threshold request");
        validate_operation_result(
            &operation,
            STATUS_OK_V1,
            &result,
            &threshold_state.network_id,
        )
        .expect("validate pending threshold result");
        assert_eq!(
            decode_canonical::<ReputationReconcileResultWireV1>(
                &result,
                MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1,
            )
            .expect("decode pending threshold result"),
            ReputationReconcileResultWireV1 {
                outcome: 0,
                canonical_result: Vec::new(),
                failure_receipt: [0; 32],
            }
        );
    }
    assert_eq!(
        threshold_backend
            .reconciled_keys
            .lock()
            .expect("threshold reconciliation keys")
            .as_slice(),
        &[
            threshold_request.idempotency_key,
            threshold_request.idempotency_key,
        ],
        "reconciliation retries preserve the exact operation key"
    );
    let drifting_threshold_state = prepare_test_server_state(
        &reputation_catalog(IrohaRuntimeProviderSlotV1::ReputationThresholdSigner),
        RuntimeProviderBrokerBackendsV1::new().with_reputation_threshold_signer(Arc::new(
            ServerTestReputationThresholdSigner::drifting_after_operation(),
        )),
    )
    .expect("prepare drifting reputation threshold signer");
    let drifting_threshold = reputation_request(
        &drifting_threshold_state,
        1,
        OPERATION_REPUTATION_THRESHOLD_RECONCILE_V1,
        threshold_payload.clone(),
    );
    validate_operation_request(&drifting_threshold).expect("validate drifting threshold request");
    assert_eq!(
        dispatch_server_operation(&drifting_threshold_state, &drifting_threshold),
        Err(BrokerError::Ambiguous),
        "post-dispatch qualification drift is an ambiguous mutation"
    );
    let governance_backend = Arc::new(ServerTestReputationGovernanceDag::exact());
    let governance_state = prepare_test_server_state(
        &reputation_catalog(IrohaRuntimeProviderSlotV1::ReputationGovernanceDag),
        RuntimeProviderBrokerBackendsV1::new()
            .with_reputation_governance_dag(governance_backend.clone()),
    )
    .expect("prepare exact reputation Governance DAG");
    let governance_request = governance_request();
    let governance_payload = encode_canonical(
        &reputation_governance_request_to_wire(&governance_request)
            .expect("project reputation governance request"),
        MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1,
    )
    .expect("encode reputation governance request");
    for request_id in [1, 2] {
        let operation = reputation_request(
            &governance_state,
            request_id,
            OPERATION_REPUTATION_GOVERNANCE_RECONCILE_V1,
            governance_payload.clone(),
        );
        validate_operation_request(&operation).expect("validate reputation governance request");
        let result = dispatch_server_operation(&governance_state, &operation)
            .expect("reconcile reputation governance request");
        validate_operation_result(
            &operation,
            STATUS_OK_V1,
            &result,
            &governance_state.network_id,
        )
        .expect("validate pending governance result");
    }
    assert_eq!(
        governance_backend
            .reconciled_keys
            .lock()
            .expect("governance reconciliation keys")
            .as_slice(),
        &[
            governance_request.idempotency_key,
            governance_request.idempotency_key,
        ],
        "publication reconciliation preserves the exact operation key"
    );
    let drifting_governance_state = prepare_test_server_state(
        &reputation_catalog(IrohaRuntimeProviderSlotV1::ReputationGovernanceDag),
        RuntimeProviderBrokerBackendsV1::new().with_reputation_governance_dag(Arc::new(
            ServerTestReputationGovernanceDag::drifting_after_operation(),
        )),
    )
    .expect("prepare drifting reputation Governance DAG");
    let drifting_governance = reputation_request(
        &drifting_governance_state,
        1,
        OPERATION_REPUTATION_GOVERNANCE_RECONCILE_V1,
        governance_payload.clone(),
    );
    validate_operation_request(&drifting_governance).expect("validate drifting governance request");
    assert_eq!(
        dispatch_server_operation(&drifting_governance_state, &drifting_governance),
        Err(BrokerError::Ambiguous),
        "post-publication qualification drift is ambiguous"
    );
    let threshold_binding =
        reputation_binding(IrohaRuntimeProviderSlotV1::ReputationThresholdSigner);
    let cross_slot = make_operation_request(
        TEST_SESSION_ID,
        9,
        threshold_binding.clone(),
        observation(&threshold_binding).metadata_digest,
        OPERATION_REPUTATION_GOVERNANCE_RECONCILE_V1,
        governance_payload,
    )
    .expect("seal cross-slot reputation request");
    assert_eq!(
        validate_operation_request(&cross_slot),
        Err(BrokerError::BindingMismatch)
    );
    let mut trailing_threshold = threshold_payload;
    trailing_threshold.push(0);
    let trailing_threshold = make_operation_request(
        TEST_SESSION_ID,
        10,
        threshold_binding.clone(),
        observation(&threshold_binding).metadata_digest,
        OPERATION_REPUTATION_THRESHOLD_RECONCILE_V1,
        trailing_threshold,
    )
    .expect("seal trailing threshold request");
    assert!(validate_operation_request(&trailing_threshold).is_err());
}
#[test]
fn reputation_qualification_results_are_exactly_bound() {
    for (slot, request_id) in [
        (
            IrohaRuntimeProviderSlotV1::ReputationJournalTransactionSubmitter,
            1,
        ),
        (IrohaRuntimeProviderSlotV1::ReputationThresholdSigner, 2),
        (IrohaRuntimeProviderSlotV1::ReputationGovernanceDag, 3),
        (IrohaRuntimeProviderSlotV1::ReputationJournalCheckpoint, 4),
    ] {
        let binding = reputation_binding(slot);
        let operation = make_operation_request(
            TEST_SESSION_ID,
            request_id,
            binding.clone(),
            observation(&binding).metadata_digest,
            OPERATION_QUALIFY_V1,
            encode_canonical(&(), MAX_OPERATION_FRAME_BYTES_V1)
                .expect("encode qualification request"),
        )
        .expect("seal reputation qualification operation");
        validate_operation_request(&operation)
            .expect("validate reputation qualification operation");
        let exact = QualificationResultWireV1 {
            revision: binding.revision.expect("qualification revision"),
            policy_digest: binding.policy_digest.expect("qualification policy digest"),
        };
        let exact = encode_canonical(&exact, MAX_OPERATION_FRAME_BYTES_V1)
            .expect("encode exact reputation qualification");
        assert_eq!(
            validate_operation_result(&operation, STATUS_OK_V1, &exact, &network_id(),),
            Ok(()),
            "{slot:?}"
        );
        let stale = QualificationResultWireV1 {
            revision: binding
                .revision
                .expect("qualification revision")
                .saturating_add(1),
            policy_digest: binding.policy_digest.expect("qualification policy digest"),
        };
        let stale = encode_canonical(&stale, MAX_OPERATION_FRAME_BYTES_V1)
            .expect("encode stale reputation qualification");
        assert_eq!(
            validate_operation_result(&operation, STATUS_OK_V1, &stale, &network_id(),),
            Err(BrokerError::Protocol),
            "{slot:?}"
        );
        let mut trailing = exact;
        trailing.push(0);
        assert_eq!(
            validate_operation_result(&operation, STATUS_OK_V1, &trailing, &network_id(),),
            Err(BrokerError::Protocol),
            "{slot:?}"
        );
    }
}
#[test]
fn reputation_runtime_result_shapes_and_ambiguity_are_exact() {
    let threshold_request = threshold_request();
    let threshold_binding =
        reputation_binding(IrohaRuntimeProviderSlotV1::ReputationThresholdSigner);
    let threshold_operation = make_operation_request(
        TEST_SESSION_ID,
        1,
        threshold_binding.clone(),
        observation(&threshold_binding).metadata_digest,
        OPERATION_REPUTATION_THRESHOLD_RECONCILE_V1,
        encode_canonical(
            &reputation_threshold_request_to_wire(&threshold_request)
                .expect("project threshold request"),
            MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1,
        )
        .expect("encode threshold request"),
    )
    .expect("seal threshold operation");
    validate_operation_request(&threshold_operation).expect("validate threshold operation");
    let pending = ReputationReconcileResultWireV1 {
        outcome: 0,
        canonical_result: Vec::new(),
        failure_receipt: [0; 32],
    };
    let pending = encode_canonical(&pending, MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1)
        .expect("encode pending reconciliation");
    validate_operation_result(&threshold_operation, STATUS_OK_V1, &pending, &network_id())
        .expect("accept canonical pending result");
    for invalid in [
        ReputationReconcileResultWireV1 {
            outcome: 0,
            canonical_result: Vec::new(),
            failure_receipt: [0x61; 32],
        },
        ReputationReconcileResultWireV1 {
            outcome: 1,
            canonical_result: Vec::new(),
            failure_receipt: [0; 32],
        },
        ReputationReconcileResultWireV1 {
            outcome: 2,
            canonical_result: Vec::new(),
            failure_receipt: [0; 32],
        },
    ] {
        let invalid = encode_canonical(&invalid, MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1)
            .expect("encode invalid reconciliation result");
        assert_eq!(
            validate_operation_result(&threshold_operation, STATUS_OK_V1, &invalid, &network_id(),),
            Err(BrokerError::Protocol)
        );
    }
    let unit = encode_canonical(&(), MAX_OPERATION_FRAME_BYTES_V1)
        .expect("encode payload-free broker status");
    assert_eq!(
        validate_operation_result(
            &threshold_operation,
            STATUS_AMBIGUOUS_V1,
            &unit,
            &network_id(),
        ),
        Ok(())
    );
    let governance_request = governance_request();
    let governance_binding =
        reputation_binding(IrohaRuntimeProviderSlotV1::ReputationGovernanceDag);
    let governance_operation = make_operation_request(
        TEST_SESSION_ID,
        2,
        governance_binding.clone(),
        observation(&governance_binding).metadata_digest,
        OPERATION_REPUTATION_GOVERNANCE_RECONCILE_V1,
        encode_canonical(
            &reputation_governance_request_to_wire(&governance_request)
                .expect("project governance request"),
            MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1,
        )
        .expect("encode governance request"),
    )
    .expect("seal governance operation");
    validate_operation_request(&governance_operation).expect("validate governance operation");
    assert_eq!(
        validate_operation_result(
            &governance_operation,
            STATUS_AMBIGUOUS_V1,
            &unit,
            &network_id(),
        ),
        Ok(())
    );
    let journal_binding =
        reputation_binding(IrohaRuntimeProviderSlotV1::ReputationJournalTransactionSubmitter);
    let authority_keypair = KeyPair::try_from_seed(vec![0x89; 32], Algorithm::Ed25519)
        .expect("derive result-shape authority");
    let mut journal_operation = make_operation_request(
        TEST_SESSION_ID,
        3,
        journal_binding.clone(),
        observation(&journal_binding).metadata_digest,
        OPERATION_REPUTATION_JOURNAL_SUPPORTS_AUTHORITY_V1,
        encode_canonical(
            &ReputationJournalSupportsAuthorityRequestWireV1 {
                authority: AccountId::new(authority_keypair.public_key().clone()),
            },
            MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1,
        )
        .expect("encode supports-authority request"),
    )
    .expect("seal supports-authority operation");
    validate_operation_request(&journal_operation).expect("validate supports-authority operation");
    assert_eq!(
        validate_operation_result(
            &journal_operation,
            STATUS_AMBIGUOUS_V1,
            &unit,
            &network_id(),
        ),
        Err(BrokerError::Protocol),
        "read-only authority probing cannot be ambiguous"
    );
    journal_operation.operation = OPERATION_REPUTATION_JOURNAL_SUBMIT_V1;
    assert_eq!(
        validate_operation_result(
            &journal_operation,
            STATUS_AMBIGUOUS_V1,
            &unit,
            &network_id(),
        ),
        Ok(()),
        "journal submission is mutation-ambiguous"
    );
}
#[test]
fn evidence_viewer_and_moderation_archive_wire_shapes_are_exact() {
    assert_eq!(
        validate_exact_backend_set(&[], &RuntimeProviderBrokerBackendsV1::new()),
        Ok(())
    );
    for slot in [
        IrohaRuntimeProviderSlotV1::EvidenceViewerWebAuthn,
        IrohaRuntimeProviderSlotV1::EvidenceViewerGrantAuthority,
        IrohaRuntimeProviderSlotV1::EvidenceViewerReceiptSigner,
        IrohaRuntimeProviderSlotV1::EvidenceViewerErasure,
        IrohaRuntimeProviderSlotV1::EvidenceViewerCheckpointStore,
        IrohaRuntimeProviderSlotV1::EvidenceViewerCompactionArchive,
        IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive,
        IrohaRuntimeProviderSlotV1::EvidenceViewerTransparencyPublisher,
    ] {
        let binding = evidence_viewer_binding(slot);
        assert_eq!(validate_wire_binding(&binding), Ok(()), "{slot:?}");
        let observed = observation(&binding);
        assert_eq!(
            validate_observation(&binding, &observed),
            Ok(()),
            "{slot:?}"
        );
        assert_eq!(
            validate_exact_backend_set(
                std::slice::from_ref(&binding),
                &RuntimeProviderBrokerBackendsV1::new(),
            ),
            Err(RuntimeProviderBrokerServerErrorV1::BackendSetMismatch),
            "{slot:?}"
        );
        let mut confused = binding.clone();
        confused.slot = if slot == IrohaRuntimeProviderSlotV1::EvidenceViewerErasure {
            IrohaRuntimeProviderSlotV1::EvidenceViewerWebAuthn.wire_id()
        } else {
            IrohaRuntimeProviderSlotV1::EvidenceViewerErasure.wire_id()
        };
        assert_eq!(
            validate_wire_binding(&confused),
            Err(BrokerError::BindingMismatch),
            "{slot:?}"
        );
    }
    let receipt = evidence_viewer_binding(IrohaRuntimeProviderSlotV1::EvidenceViewerReceiptSigner);
    let mut substituted_receipt = observation(&receipt);
    substituted_receipt.evidence_viewer_receipt_signer_public_key = Some([0xEE; 32]);
    metadata_digest(&mut substituted_receipt);
    assert_eq!(
        validate_observation(&receipt, &substituted_receipt),
        Err(BrokerError::BindingMismatch)
    );
    let archive =
        evidence_viewer_binding(IrohaRuntimeProviderSlotV1::EvidenceViewerCompactionArchive);
    let mut substituted_archive = observation(&archive);
    substituted_archive.evidence_viewer_archive_id = Some([0xEF; 32]);
    metadata_digest(&mut substituted_archive);
    assert_eq!(
        validate_observation(&archive, &substituted_archive),
        Err(BrokerError::BindingMismatch)
    );
}
#[test]
fn moderation_archive_pre_dispatch_validation_is_slot_exact_and_body_bounded() {
    let moderation_archive =
        evidence_viewer_binding(IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive);
    let unit = encode_canonical(
        &ModerationPanelNotificationArchiveQualifyRequestWireV1 {
            version: MODERATION_PANEL_NOTIFICATION_ARCHIVE_BROKER_WIRE_VERSION_V1,
            slot: IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive.wire_id(),
            network_id: network_id(),
        },
        MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1,
    )
    .expect("encode archive qualification");
    let qualify = validated_operation(
        moderation_archive.clone(),
        OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_QUALIFY_V1,
        unit,
    );
    assert_eq!(
        validate_operation_request_for_session(&qualify, "server-test-chain", &network_id()),
        Ok(())
    );
    let install_payload = encode_canonical(
        &ModerationPanelNotificationArchiveInstallRequestWireV1 {
            version: MODERATION_PANEL_NOTIFICATION_ARCHIVE_BROKER_WIRE_VERSION_V1,
            slot: IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive.wire_id(),
            network_id: network_id(),
            operation_id: [0xA1; 32],
            receipt_message: [0xA2; 32],
            canonical_artifact: vec![0xA3],
        },
        MAX_EVIDENCE_VIEWER_BULK_FRAME_BYTES_V1,
    )
    .expect("encode moderation archive install");
    let install = validated_operation(
        moderation_archive.clone(),
        OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_INSTALL_V1,
        install_payload.clone(),
    );
    assert_eq!(
        validate_operation_request_for_session(&install, "server-test-chain", &network_id()),
        Ok(())
    );
    let read_payload = encode_canonical(
        &ModerationPanelNotificationArchiveReadRequestWireV1 {
            version: MODERATION_PANEL_NOTIFICATION_ARCHIVE_BROKER_WIRE_VERSION_V1,
            slot: IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive.wire_id(),
            network_id: network_id(),
            operation_id: [0xA1; 32],
        },
        MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1,
    )
    .expect("encode moderation archive read");
    let read = validated_operation(
        moderation_archive.clone(),
        OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_READ_V1,
        read_payload,
    );
    assert_eq!(
        validate_operation_request_for_session(&read, "server-test-chain", &network_id()),
        Ok(())
    );
    let evidence_archive =
        evidence_viewer_binding(IrohaRuntimeProviderSlotV1::EvidenceViewerCompactionArchive);
    let cross_slot = make_operation_request(
        TEST_SESSION_ID,
        91,
        evidence_archive.clone(),
        observation(&evidence_archive).metadata_digest,
        OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_INSTALL_V1,
        install_payload.clone(),
    )
    .expect("seal cross-slot archive operation");
    assert_eq!(
        validate_operation_request_for_session(&cross_slot, "server-test-chain", &network_id()),
        Err(BrokerError::BindingMismatch)
    );
    for (request_id, operation, payload) in [
        (
            93,
            OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_QUALIFY_V1,
            encode_canonical(
                &ModerationPanelNotificationArchiveQualifyRequestWireV1 {
                    version: MODERATION_PANEL_NOTIFICATION_ARCHIVE_BROKER_WIRE_VERSION_V1,
                    slot: IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive.wire_id(),
                    network_id: network_id(),
                },
                MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1,
            )
            .expect("encode cross-slot moderation qualification"),
        ),
        (
            94,
            OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_INSTALL_V1,
            install_payload.clone(),
        ),
        (
            95,
            OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_READ_V1,
            encode_canonical(
                &ModerationPanelNotificationArchiveReadRequestWireV1 {
                    version: MODERATION_PANEL_NOTIFICATION_ARCHIVE_BROKER_WIRE_VERSION_V1,
                    slot: IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive.wire_id(),
                    network_id: network_id(),
                    operation_id: [0xA1; 32],
                },
                MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1,
            )
            .expect("encode cross-slot moderation read"),
        ),
    ] {
        let request = make_operation_request(
            TEST_SESSION_ID,
            request_id,
            evidence_archive.clone(),
            observation(&evidence_archive).metadata_digest,
            operation,
            payload,
        )
        .expect("seal moderation operation on evidence slot");
        assert_eq!(
            validate_operation_request_for_session(&request, "server-test-chain", &network_id()),
            Err(BrokerError::BindingMismatch)
        );
    }
    for (request_id, operation, payload) in [
        (
            96,
            OPERATION_EVIDENCE_VIEWER_ARCHIVE_INSTALL_V1,
            encode_canonical(
                &EvidenceViewerArchiveInstallRequestWireV1 {
                    operation_id: [0xD1; 32],
                    receipt_message: [0xD2; 32],
                    canonical_artifact: vec![0xD3],
                },
                MAX_EVIDENCE_VIEWER_BULK_FRAME_BYTES_V1,
            )
            .expect("encode evidence archive install"),
        ),
        (
            97,
            OPERATION_EVIDENCE_VIEWER_ARCHIVE_READ_V1,
            encode_canonical(
                &EvidenceViewerArchiveReadRequestWireV1 {
                    operation_id: [0xD1; 32],
                },
                MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1,
            )
            .expect("encode evidence archive read"),
        ),
    ] {
        let request = make_operation_request(
            TEST_SESSION_ID,
            request_id,
            moderation_archive.clone(),
            observation(&moderation_archive).metadata_digest,
            operation,
            payload,
        )
        .expect("seal evidence operation on moderation slot");
        assert_eq!(
            validate_operation_request_for_session(&request, "server-test-chain", &network_id()),
            Err(BrokerError::BindingMismatch)
        );
    }
    let mut one_byte_archive = moderation_archive;
    one_byte_archive
        .moderation_panel_notification_archive_binding
        .as_mut()
        .expect("moderation archive binding")
        .max_bytes = 1;
    assert_eq!(validate_wire_binding(&one_byte_archive), Ok(()));
    let oversized_payload = encode_canonical(
        &ModerationPanelNotificationArchiveInstallRequestWireV1 {
            version: MODERATION_PANEL_NOTIFICATION_ARCHIVE_BROKER_WIRE_VERSION_V1,
            slot: IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive.wire_id(),
            network_id: network_id(),
            operation_id: [0xB1; 32],
            receipt_message: [0xB2; 32],
            canonical_artifact: vec![0xB3, 0xB4],
        },
        MAX_EVIDENCE_VIEWER_BULK_FRAME_BYTES_V1,
    )
    .expect("encode over-bound moderation archive install");
    let oversized = make_operation_request(
        TEST_SESSION_ID,
        92,
        one_byte_archive.clone(),
        observation(&one_byte_archive).metadata_digest,
        OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_INSTALL_V1,
        oversized_payload,
    )
    .expect("seal over-bound archive operation");
    assert_eq!(
        validate_operation_request_for_session(&oversized, "server-test-chain", &network_id()),
        Err(BrokerError::Rejected)
    );
}
include!("moderation_source_attestation_tests.rs");
#[test]
fn moderation_archive_fixture_is_preflighted_before_every_mutating_backend() {
    let fixture = test_moderation::moderation_panel_notification_archive_broker_fixture_v1()
        .expect("build genuine signed moderation archive fixture");
    let catalog =
        IrohaRuntimeProviderBindingsV1::qualified_moderation_panel_notification_archive_for_test(
            &fixture,
            SERVER_TEST_MODERATION_PUBLICATION_HANDLE,
            7,
            TEST_POLICY_DIGEST,
        );
    let checkpoint = Arc::new(ServerTestModerationCheckpointStore::from_fixture(&fixture));
    let archive = Arc::new(ServerTestModerationPanelNotificationArchive::from_fixture(
        &fixture,
    ));
    let publication = Arc::new(ServerTestModerationHandoffBoundary::exact(
        test_moderation::ModerationTerminalHandoffKindV1::Publication,
    ));
    let state = prepare_test_server_state(
        &catalog,
        RuntimeProviderBrokerBackendsV1::new()
            .with_moderation_publication_handoff(publication.clone())
            .with_moderation_checkpoint_store(checkpoint.clone())
            .with_moderation_panel_notification_archive(archive.clone()),
    )
    .expect("prepare exact moderation archive broker state");
    let operation_for_slot =
        |request_id: u64, slot: IrohaRuntimeProviderSlotV1, operation, payload| {
            let index = state
                .catalog
                .iter()
                .position(|binding| binding.slot == slot.wire_id())
                .expect("fixture provider binding");
            make_operation_request(
                TEST_SESSION_ID,
                request_id,
                state.catalog[index].clone(),
                state.observations[index].metadata_digest,
                operation,
                payload,
            )
            .expect("seal fixture operation request")
        };
    let mut substituted_receipt = fixture.validation.receipt_message;
    substituted_receipt[0] ^= 1;
    let substituted_install = operation_for_slot(
        1,
        IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive,
        OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_INSTALL_V1,
        encode_canonical(
            &ModerationPanelNotificationArchiveInstallRequestWireV1 {
                version: MODERATION_PANEL_NOTIFICATION_ARCHIVE_BROKER_WIRE_VERSION_V1,
                slot: IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive.wire_id(),
                network_id: fixture.network_id,
                operation_id: fixture.validation.operation_id,
                receipt_message: substituted_receipt,
                canonical_artifact: fixture.canonical_artifact.clone(),
            },
            MAX_EVIDENCE_VIEWER_BULK_FRAME_BYTES_V1,
        )
        .expect("encode substituted archive install"),
    );
    validate_operation_request_for_session(
        &substituted_install,
        "server-test-chain",
        &fixture.network_id,
    )
    .expect("substituted receipt is structurally canonical");
    assert_eq!(
        dispatch_server_operation(&state, &substituted_install),
        Err(BrokerError::Rejected)
    );
    assert_eq!(
        archive.install_calls.load(Ordering::Acquire),
        0,
        "derived receipt substitution must be rejected before archive installation"
    );
    let install = operation_for_slot(
        2,
        IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive,
        OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_INSTALL_V1,
        encode_canonical(
            &ModerationPanelNotificationArchiveInstallRequestWireV1 {
                version: MODERATION_PANEL_NOTIFICATION_ARCHIVE_BROKER_WIRE_VERSION_V1,
                slot: IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive.wire_id(),
                network_id: fixture.network_id,
                operation_id: fixture.validation.operation_id,
                receipt_message: fixture.validation.receipt_message,
                canonical_artifact: fixture.canonical_artifact.clone(),
            },
            MAX_EVIDENCE_VIEWER_BULK_FRAME_BYTES_V1,
        )
        .expect("encode exact archive install"),
    );
    validate_operation_request_for_session(&install, "server-test-chain", &fixture.network_id)
        .expect("validate exact archive install");
    let install_result = {
        let install_result =
            dispatch_server_operation(&state, &install).expect("install genuine archive fixture");
        let _scope = install_result.enter_decode_admission();
        validate_operation_result(&install, STATUS_OK_V1, &install_result, &state.network_id)
            .expect("validate exact archive install result");
        decode_canonical::<ModerationPanelNotificationArchiveInstallResultWireV1>(
            &install_result,
            MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1,
        )
        .expect("decode archive install result")
    };
    assert_eq!(state.decode_pool.allocation.reserved_bytes(), 0);
    assert_eq!(install_result.signature, fixture.archive_signature);
    assert_eq!(archive.install_calls.load(Ordering::Acquire), 1);
    let read = operation_for_slot(
        3,
        IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive,
        OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_READ_V1,
        encode_canonical(
            &ModerationPanelNotificationArchiveReadRequestWireV1 {
                version: MODERATION_PANEL_NOTIFICATION_ARCHIVE_BROKER_WIRE_VERSION_V1,
                slot: IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive.wire_id(),
                network_id: fixture.network_id,
                operation_id: fixture.validation.operation_id,
            },
            MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1,
        )
        .expect("encode exact archive read"),
    );
    let readback = {
        let readback =
            dispatch_server_operation(&state, &read).expect("read genuine archive fixture");
        let _scope = readback.enter_decode_admission();
        decode_canonical::<Option<ModerationPanelNotificationArchiveReadbackWireV1>>(
            &readback,
            MAX_EVIDENCE_VIEWER_BULK_FRAME_BYTES_V1,
        )
        .expect("decode exact archive readback")
        .expect("installed fixture must be readable")
    };
    assert_eq!(state.decode_pool.allocation.reserved_bytes(), 0);
    assert_eq!(
        readback.canonical_artifact.as_slice(),
        fixture.canonical_artifact.as_slice()
    );
    assert_eq!(readback.signature, fixture.archive_signature);
    let mut substituted_statement = fixture.source_attestation.clone();
    substituted_statement.terminal_set_digest[0] ^= 1;
    let substituted_attestation = operation_for_slot(
        4,
        IrohaRuntimeProviderSlotV1::ModerationCheckpointStore,
        OPERATION_MODERATION_PANEL_NOTIFICATION_SOURCE_ATTEST_V1,
        encode_canonical(
            &ModerationPanelNotificationSourceAttestRequestWireV1 {
                version: MODERATION_PANEL_NOTIFICATION_ARCHIVE_BROKER_WIRE_VERSION_V1,
                slot: IrohaRuntimeProviderSlotV1::ModerationCheckpointStore.wire_id(),
                network_id: fixture.network_id,
                statement: substituted_statement,
            },
            MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1,
        )
        .expect("encode substituted source attestation"),
    );
    validate_operation_request_for_session(
        &substituted_attestation,
        "server-test-chain",
        &fixture.network_id,
    )
    .expect("substituted source digest is structurally canonical");
    assert_eq!(
        dispatch_server_operation(&state, &substituted_attestation),
        Err(BrokerError::Rejected)
    );
    assert_eq!(
        checkpoint.attest_calls.load(Ordering::Acquire),
        0,
        "source substitution must be rejected before checkpoint attestation signing"
    );
    let attest = operation_for_slot(
        5,
        IrohaRuntimeProviderSlotV1::ModerationCheckpointStore,
        OPERATION_MODERATION_PANEL_NOTIFICATION_SOURCE_ATTEST_V1,
        encode_canonical(
            &ModerationPanelNotificationSourceAttestRequestWireV1 {
                version: MODERATION_PANEL_NOTIFICATION_ARCHIVE_BROKER_WIRE_VERSION_V1,
                slot: IrohaRuntimeProviderSlotV1::ModerationCheckpointStore.wire_id(),
                network_id: fixture.network_id,
                statement: fixture.source_attestation.clone(),
            },
            MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1,
        )
        .expect("encode exact source attestation"),
    );
    let attest_result = {
        let attest_result =
            dispatch_server_operation(&state, &attest).expect("attest genuine terminal set");
        let _scope = attest_result.enter_decode_admission();
        decode_canonical::<ModerationPanelNotificationSourceAttestResultWireV1>(
            &attest_result,
            MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1,
        )
        .expect("decode exact source attestation result")
    };
    assert_eq!(state.decode_pool.allocation.reserved_bytes(), 0);
    assert_eq!(
        attest_result.statement_digest,
        fixture.validation.source_attestation_digest
    );
    fixture
        .source_attestation
        .verify(attest_result.signature)
        .expect("verify independently signed source attestation");
    assert_eq!(checkpoint.attest_calls.load(Ordering::Acquire), 1);
    let head = decode_canonical::<test_moderation::ModerationPanelNotificationArchiveHeadV1>(
        &fixture.canonical_signed_head,
        MAX_MODERATION_HANDOFF_CANONICAL_BYTES_V1,
    )
    .expect("decode genuine signed archive head");
    let archive_head_read_payload = encode_canonical(&(), MAX_MODERATION_HANDOFF_FRAME_BYTES_V1)
        .expect("encode archive-head read request");
    let cross_slot_read = operation_for_slot(
        60,
        IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive,
        OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_HEAD_READ_V1,
        archive_head_read_payload.clone(),
    );
    assert_eq!(
        validate_operation_request_for_session(
            &cross_slot_read,
            "server-test-chain",
            &fixture.network_id,
        ),
        Err(BrokerError::BindingMismatch)
    );
    assert_eq!(
        dispatch_server_operation(&state, &cross_slot_read),
        Err(BrokerError::BindingMismatch)
    );
    let mut trailing_read_payload = archive_head_read_payload.clone();
    trailing_read_payload.push(0);
    let trailing_read = operation_for_slot(
        61,
        IrohaRuntimeProviderSlotV1::ModerationPublicationHandoff,
        OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_HEAD_READ_V1,
        trailing_read_payload,
    );
    assert_eq!(
        validate_operation_request_for_session(
            &trailing_read,
            "server-test-chain",
            &fixture.network_id,
        ),
        Err(BrokerError::Protocol)
    );
    assert_eq!(
        dispatch_server_operation(&state, &trailing_read),
        Err(BrokerError::Protocol)
    );
    let empty_head_read = operation_for_slot(
        62,
        IrohaRuntimeProviderSlotV1::ModerationPublicationHandoff,
        OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_HEAD_READ_V1,
        archive_head_read_payload.clone(),
    );
    validate_operation_request_for_session(
        &empty_head_read,
        "server-test-chain",
        &fixture.network_id,
    )
    .expect("validate empty archive-head readback request");
    let empty_head_read_result = {
        let empty_head_read_result = dispatch_server_operation(&state, &empty_head_read)
            .expect("read empty public archive head");
        let _scope = empty_head_read_result.enter_decode_admission();
        validate_operation_result(
            &empty_head_read,
            STATUS_OK_V1,
            &empty_head_read_result,
            &state.network_id,
        )
        .expect("validate empty archive-head readback result");
        decode_canonical::<ModerationPanelNotificationArchiveHeadReadResultWireV1>(
            &empty_head_read_result,
            MAX_MODERATION_HANDOFF_FRAME_BYTES_V1,
        )
        .expect("decode empty archive-head readback")
    };
    assert_eq!(state.decode_pool.allocation.reserved_bytes(), 0);
    assert_eq!(
        empty_head_read_result.version,
        MODERATION_PANEL_NOTIFICATION_ARCHIVE_BROKER_WIRE_VERSION_V1
    );
    assert_eq!(
        empty_head_read_result.slot,
        IrohaRuntimeProviderSlotV1::ModerationPublicationHandoff.wire_id()
    );
    assert!(empty_head_read_result.canonical_head.is_none());
    let publish_wire = ModerationPanelNotificationArchiveHeadPublishRequestWireV1 {
        version: MODERATION_PANEL_NOTIFICATION_ARCHIVE_BROKER_WIRE_VERSION_V1,
        slot: IrohaRuntimeProviderSlotV1::ModerationPublicationHandoff.wire_id(),
        network_id: fixture.network_id,
        head: head.clone(),
        canonical_head: fixture.canonical_signed_head.clone(),
    };
    let publish_payload = encode_canonical(&publish_wire, MAX_MODERATION_HANDOFF_FRAME_BYTES_V1)
        .expect("encode exact archive-head publication");
    let cross_slot_publish = operation_for_slot(
        6,
        IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive,
        OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_HEAD_PUBLISH_V1,
        publish_payload.clone(),
    );
    assert_eq!(
        validate_operation_request_for_session(
            &cross_slot_publish,
            "server-test-chain",
            &fixture.network_id,
        ),
        Err(BrokerError::BindingMismatch)
    );
    assert_eq!(
        dispatch_server_operation(&state, &cross_slot_publish),
        Err(BrokerError::BindingMismatch)
    );
    let mut substituted_head = head;
    substituted_head.source_checkpoint_revision[0] ^= 1;
    let substituted_head_bytes =
        norito::to_bytes(&substituted_head).expect("encode substituted archive head");
    let substituted_publish = operation_for_slot(
        7,
        IrohaRuntimeProviderSlotV1::ModerationPublicationHandoff,
        OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_HEAD_PUBLISH_V1,
        encode_canonical(
            &ModerationPanelNotificationArchiveHeadPublishRequestWireV1 {
                version: MODERATION_PANEL_NOTIFICATION_ARCHIVE_BROKER_WIRE_VERSION_V1,
                slot: IrohaRuntimeProviderSlotV1::ModerationPublicationHandoff.wire_id(),
                network_id: fixture.network_id,
                head: substituted_head,
                canonical_head: substituted_head_bytes,
            },
            MAX_MODERATION_HANDOFF_FRAME_BYTES_V1,
        )
        .expect("encode substituted archive-head publication"),
    );
    assert_eq!(
        validate_operation_request_for_session(
            &substituted_publish,
            "server-test-chain",
            &fixture.network_id,
        ),
        Err(BrokerError::Rejected)
    );
    assert_eq!(
        dispatch_server_operation(&state, &substituted_publish),
        Err(BrokerError::Rejected)
    );
    let mut substituted_source_catalog = state.catalog.clone();
    substituted_source_catalog
        .iter_mut()
        .find(|binding| {
            binding.slot == IrohaRuntimeProviderSlotV1::ModerationCheckpointStore.wire_id()
        })
        .expect("checkpoint fixture binding")
        .moderation_checkpoint_attestation_public_key = Some(TEST_SIGNER_KEY);
    assert_eq!(
        validate_moderation_panel_notification_archive_head_at_broker_boundary(
            &fixture.canonical_signed_head,
            &fixture.network_id,
            &substituted_source_catalog,
        ),
        Err(BrokerError::Rejected),
        "the independently administered checkpoint key is part of the head boundary"
    );
    let mut substituted_signer_catalog = state.catalog.clone();
    substituted_signer_catalog
        .iter_mut()
        .find(|binding| {
            binding.slot == IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive.wire_id()
        })
        .expect("archive fixture binding")
        .moderation_panel_notification_archive_binding
        .as_mut()
        .expect("exact archive fixture binding")
        .public_key = TEST_SIGNER_KEY;
    assert_eq!(
        validate_moderation_panel_notification_archive_head_at_broker_boundary(
            &fixture.canonical_signed_head,
            &fixture.network_id,
            &substituted_signer_catalog,
        ),
        Err(BrokerError::Rejected),
        "the sealed current signer epoch is part of the head boundary"
    );
    assert_eq!(
        publication.delivery_calls.load(Ordering::Acquire),
        0,
        "cross-slot and signed-head substitution must precede publication"
    );
    let publish = operation_for_slot(
        8,
        IrohaRuntimeProviderSlotV1::ModerationPublicationHandoff,
        OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_HEAD_PUBLISH_V1,
        publish_payload,
    );
    validate_operation_request_for_session(&publish, "server-test-chain", &fixture.network_id)
        .expect("validate genuine archive-head publication");
    let publish_result = {
        let publish_result = dispatch_server_operation(&state, &publish)
            .expect("publish genuine signed archive head");
        let _scope = publish_result.enter_decode_admission();
        validate_operation_result(&publish, STATUS_OK_V1, &publish_result, &state.network_id)
            .expect("validate dedicated archive-head result");
        decode_canonical::<ModerationPanelNotificationArchiveHeadPublishResultWireV1>(
            &publish_result,
            MAX_MODERATION_HANDOFF_FRAME_BYTES_V1,
        )
        .expect("decode archive-head publication result")
    };
    assert_eq!(state.decode_pool.allocation.reserved_bytes(), 0);
    assert_eq!(publish_result.operation_id, fixture.validation.operation_id);
    assert_eq!(publish_result.head_digest, fixture.validation.head_digest);
    assert_eq!(
        publish_result.chain_commitment,
        fixture.validation.chain_commitment
    );
    assert_eq!(publish_result.outcome, 1);
    assert_eq!(publication.delivery_calls.load(Ordering::Acquire), 1);
    let published_head_read = operation_for_slot(
        63,
        IrohaRuntimeProviderSlotV1::ModerationPublicationHandoff,
        OPERATION_MODERATION_PANEL_NOTIFICATION_ARCHIVE_HEAD_READ_V1,
        archive_head_read_payload,
    );
    validate_operation_request_for_session(
        &published_head_read,
        "server-test-chain",
        &fixture.network_id,
    )
    .expect("validate published archive-head readback request");
    let published_head_read_result = {
        let published_head_read_result = dispatch_server_operation(&state, &published_head_read)
            .expect("read exact public archive head");
        let _scope = published_head_read_result.enter_decode_admission();
        validate_operation_result(
            &published_head_read,
            STATUS_OK_V1,
            &published_head_read_result,
            &state.network_id,
        )
        .expect("validate published archive-head readback result");
        decode_canonical::<ModerationPanelNotificationArchiveHeadReadResultWireV1>(
            &published_head_read_result,
            MAX_MODERATION_HANDOFF_FRAME_BYTES_V1,
        )
        .expect("decode published archive-head readback")
    };
    assert_eq!(state.decode_pool.allocation.reserved_bytes(), 0);
    assert_eq!(
        published_head_read_result.canonical_head.as_deref(),
        Some(fixture.canonical_signed_head.as_slice())
    );
    assert_eq!(
        publication.delivery_calls.load(Ordering::Acquire),
        1,
        "public head reads must never replay publication"
    );
}
#[test]
fn evidence_transparency_ambiguity_reconnects_for_readback_without_replay() {
    let catalog = evidence_transparency_publisher_test_catalog();
    let backend = Arc::new(ServerTestEvidenceTransparencyPublisher::default());
    let (_directory, policy, shutdown, server) = start_signer(
        catalog.clone(),
        RuntimeProviderBrokerBackendsV1::new()
            .with_evidence_viewer_transparency_publisher(backend.clone()),
    );
    let dependencies =
        resolve_test_process(&catalog, &policy).expect("resolve transparency-publisher proxy");
    let publisher = dependencies
        .sorafs_evidence_viewer_transparency_publisher
        .as_ref()
        .expect("resolved transparency publisher");
    assert_eq!(
        publisher.compare_and_publish(&evidence_transparency_test_body()),
        Err(
            test_evidence_transparency::
                EvidenceViewerTransparencyPublisherExternalErrorV1::Ambiguous,
        )
    );
    assert_eq!(
        backend.compare_calls.load(Ordering::Acquire),
        1,
        "an ambiguous mutation must never be replayed"
    );
    assert_eq!(
        publisher
            .qualification()
            .expect("requalify over the fresh broker session"),
        node::evidence_viewer::EvidenceViewerRuntimeProviderQualificationV1::new(
            7,
            TEST_POLICY_DIGEST
        ),
    );
    assert_eq!(
        publisher.load_head(),
        Ok(None),
        "fresh authoritative readback must remain available"
    );
    assert_eq!(
        backend.compare_calls.load(Ordering::Acquire),
        1,
        "qualification and readback must not replay the mutation"
    );
    drop(dependencies);
    shutdown.request_shutdown();
    server
        .join()
        .expect("join transparency-publisher broker")
        .expect("transparency-publisher broker exits cleanly");
}
struct TestGlobalBeaconBrokerBackendV1 {
    handle: &'static str,
    qualification: ConsensusSignerProviderQualificationV1,
}

impl GlobalBeaconPartialSignerBrokerBackendV1 for TestGlobalBeaconBrokerBackendV1 {
    fn handle(&self) -> &str {
        self.handle
    }

    fn qualification(
        &self,
    ) -> Result<ConsensusSignerProviderQualificationV1, GlobalBeaconPartialSignerBrokerBackendErrorV1>
    {
        Ok(self.qualification)
    }

    fn attest_partial_signing_capability(
        &self,
        _session: &iroha_core::beacon::ValidatedGlobalThresholdBeaconSessionV1,
        _expected_signer_index: u16,
    ) -> Result<
        iroha_core::beacon::GlobalThresholdBeaconPartialSigningCapabilityV1,
        GlobalBeaconPartialSignerBrokerBackendErrorV1,
    > {
        Err(GlobalBeaconPartialSignerBrokerBackendErrorV1::Rejected)
    }

    fn sign_partial(
        &self,
        _session: &iroha_core::beacon::ValidatedGlobalThresholdBeaconSessionV1,
        _payload: &[u8],
    ) -> Result<
        iroha_data_model::consensus::GlobalThresholdBeaconPartialSignatureV1,
        GlobalBeaconPartialSignerBrokerBackendErrorV1,
    > {
        Err(GlobalBeaconPartialSignerBrokerBackendErrorV1::Rejected)
    }
}

struct TransientQualificationGlobalBeaconBrokerBackendV1 {
    inner: Arc<dyn GlobalBeaconPartialSignerBrokerBackendV1>,
    qualification_calls: AtomicU64,
    fail_on_qualification_call: AtomicU64,
    sign_calls: AtomicU64,
}

impl TransientQualificationGlobalBeaconBrokerBackendV1 {
    fn fail_after_additional_qualification_calls(&self, additional_calls: u64) {
        let current = self.qualification_calls.load(Ordering::Acquire);
        self.fail_on_qualification_call.store(
            current
                .checked_add(additional_calls)
                .expect("qualification test counter remains bounded"),
            Ordering::Release,
        );
    }
}

impl GlobalBeaconPartialSignerBrokerBackendV1
    for TransientQualificationGlobalBeaconBrokerBackendV1
{
    fn handle(&self) -> &str {
        self.inner.handle()
    }

    fn qualification(
        &self,
    ) -> Result<ConsensusSignerProviderQualificationV1, GlobalBeaconPartialSignerBrokerBackendErrorV1>
    {
        let call = self.qualification_calls.fetch_add(1, Ordering::AcqRel) + 1;
        if self.fail_on_qualification_call.load(Ordering::Acquire) == call {
            return Err(GlobalBeaconPartialSignerBrokerBackendErrorV1::Unavailable);
        }
        self.inner.qualification()
    }

    fn attest_partial_signing_capability(
        &self,
        session: &iroha_core::beacon::ValidatedGlobalThresholdBeaconSessionV1,
        expected_signer_index: u16,
    ) -> Result<
        iroha_core::beacon::GlobalThresholdBeaconPartialSigningCapabilityV1,
        GlobalBeaconPartialSignerBrokerBackendErrorV1,
    > {
        self.inner
            .attest_partial_signing_capability(session, expected_signer_index)
    }

    fn sign_partial(
        &self,
        session: &iroha_core::beacon::ValidatedGlobalThresholdBeaconSessionV1,
        payload: &[u8],
    ) -> Result<
        iroha_data_model::consensus::GlobalThresholdBeaconPartialSignatureV1,
        GlobalBeaconPartialSignerBrokerBackendErrorV1,
    > {
        self.sign_calls.fetch_add(1, Ordering::AcqRel);
        self.inner.sign_partial(session, payload)
    }
}

struct InvalidGlobalBeaconBrokerBackendV1 {
    handle: String,
    qualification: ConsensusSignerProviderQualificationV1,
    sign_calls: Arc<AtomicU64>,
}

impl GlobalBeaconPartialSignerBrokerBackendV1 for InvalidGlobalBeaconBrokerBackendV1 {
    fn handle(&self) -> &str {
        &self.handle
    }

    fn qualification(
        &self,
    ) -> Result<ConsensusSignerProviderQualificationV1, GlobalBeaconPartialSignerBrokerBackendErrorV1>
    {
        Ok(self.qualification)
    }

    fn attest_partial_signing_capability(
        &self,
        session: &iroha_core::beacon::ValidatedGlobalThresholdBeaconSessionV1,
        _expected_signer_index: u16,
    ) -> Result<
        iroha_core::beacon::GlobalThresholdBeaconPartialSigningCapabilityV1,
        GlobalBeaconPartialSignerBrokerBackendErrorV1,
    > {
        iroha_core::beacon::GlobalThresholdBeaconPartialSigningCapabilityV1::for_validated_session(
            session, 2,
        )
        .map_err(|_| GlobalBeaconPartialSignerBrokerBackendErrorV1::Rejected)
    }

    fn sign_partial(
        &self,
        session: &iroha_core::beacon::ValidatedGlobalThresholdBeaconSessionV1,
        _payload: &[u8],
    ) -> Result<
        iroha_data_model::consensus::GlobalThresholdBeaconPartialSignatureV1,
        GlobalBeaconPartialSignerBrokerBackendErrorV1,
    > {
        self.sign_calls.fetch_add(1, Ordering::AcqRel);
        Ok(
            iroha_data_model::consensus::GlobalThresholdBeaconPartialSignatureV1 {
                session_id: session.record().session_id,
                signer_index: 1,
                signature_share: [0; 48],
                proof: iroha_data_model::consensus::GlobalThresholdBeaconPartialSignatureProofV1 {
                    x: [0; 96],
                    y: [0; 48],
                    z_s: [0; 32],
                    z_r: [0; 32],
                    z_u: [0; 32],
                },
            },
        )
    }
}

struct TestParliamentTleBrokerBackendV1 {
    handle: &'static str,
    qualification: ConsensusSignerProviderQualificationV1,
}

impl ParliamentTlePartialReleaseSignerBrokerBackendV1 for TestParliamentTleBrokerBackendV1 {
    fn handle(&self) -> &str {
        self.handle
    }

    fn qualification(
        &self,
    ) -> Result<
        ConsensusSignerProviderQualificationV1,
        ParliamentTlePartialReleaseSignerBrokerBackendErrorV1,
    > {
        Ok(self.qualification)
    }

    fn attest_partial_release_capability(
        &self,
        _session: &iroha_core_timed_ovn::tle::ValidatedTleKeySessionV1,
        _expected_participant_index: u16,
    ) -> Result<
        iroha_core::tle_release::TlePartialReleaseCapabilityAttestationV1,
        ParliamentTlePartialReleaseSignerBrokerBackendErrorV1,
    > {
        Err(ParliamentTlePartialReleaseSignerBrokerBackendErrorV1::Rejected)
    }

    fn sign_projected_partial_release(
        &self,
        _projection: &iroha_core_timed_ovn::tle::ValidatedTleReleaseProjectionV1,
    ) -> Result<
        iroha_core_timed_ovn::tle::TlePartialReleaseShareV1,
        ParliamentTlePartialReleaseSignerBrokerBackendErrorV1,
    > {
        Err(ParliamentTlePartialReleaseSignerBrokerBackendErrorV1::Rejected)
    }
}

#[test]
fn consensus_signer_broker_startup_is_exact_and_fail_closed() {
    let handle = "provider://iroha/consensus-signers/primary";
    let revision = 7;
    let digest = [0xA7; 32];
    let qualification = ConsensusSignerProviderQualificationV1::new(revision, digest, false);

    let beacon_catalog = IrohaRuntimeProviderBindingsV1::qualified_for_test(
        "broker-consensus-test",
        IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner,
        handle,
        revision,
        digest,
    );
    let beacon_binding = ProviderBindingWireV1::try_from_binding(
        beacon_catalog.iter().next().expect("beacon catalog entry"),
    )
    .expect("project beacon signer binding");
    validate_wire_binding(&beacon_binding).expect("accept exact beacon signer binding");
    validate_observation(&beacon_binding, &observation(&beacon_binding))
        .expect("accept metadata-free beacon signer observation");
    assert!(matches!(
        prepare_test_server_state(&beacon_catalog, RuntimeProviderBrokerBackendsV1::new()),
        Err(RuntimeProviderBrokerServerErrorV1::BackendSetMismatch)
    ));
    prepare_test_server_state(
        &beacon_catalog,
        RuntimeProviderBrokerBackendsV1::new().with_global_beacon_partial_signer(Arc::new(
            TestGlobalBeaconBrokerBackendV1 {
                handle,
                qualification,
            },
        )),
    )
    .expect("exact beacon signer backend qualifies");
    for backend in [
        TestGlobalBeaconBrokerBackendV1 {
            handle: "provider://iroha/consensus-signers/substituted",
            qualification,
        },
        TestGlobalBeaconBrokerBackendV1 {
            handle,
            qualification: ConsensusSignerProviderQualificationV1::new(revision + 1, digest, false),
        },
        TestGlobalBeaconBrokerBackendV1 {
            handle,
            qualification: ConsensusSignerProviderQualificationV1::new(revision, [0xA8; 32], false),
        },
        TestGlobalBeaconBrokerBackendV1 {
            handle,
            qualification: ConsensusSignerProviderQualificationV1::new(revision, digest, true),
        },
    ] {
        assert!(matches!(
            prepare_test_server_state(
                &beacon_catalog,
                RuntimeProviderBrokerBackendsV1::new()
                    .with_global_beacon_partial_signer(Arc::new(backend)),
            ),
            Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch)
        ));
    }

    let tle_catalog = IrohaRuntimeProviderBindingsV1::qualified_for_test(
        "broker-consensus-test",
        IrohaRuntimeProviderSlotV1::ParliamentTlePartialReleaseSigner,
        handle,
        revision,
        digest,
    );
    let tle_binding = ProviderBindingWireV1::try_from_binding(
        tle_catalog.iter().next().expect("TLE catalog entry"),
    )
    .expect("project TLE signer binding");
    validate_wire_binding(&tle_binding).expect("accept exact TLE signer binding");
    validate_observation(&tle_binding, &observation(&tle_binding))
        .expect("accept metadata-free TLE signer observation");
    for binding in [&beacon_binding, &tle_binding] {
        let mut checkpoint_confused = observation(binding);
        checkpoint_confused.moderation_checkpoint_attestation_public_key = Some(TEST_SIGNER_KEY);
        metadata_digest(&mut checkpoint_confused);
        assert_eq!(
            validate_observation(binding, &checkpoint_confused),
            Err(BrokerError::BindingMismatch)
        );

        let mut archive_confused = observation(binding);
        archive_confused.moderation_panel_notification_archive_binding =
            evidence_viewer_binding(IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive)
                .moderation_panel_notification_archive_binding;
        metadata_digest(&mut archive_confused);
        assert_eq!(
            validate_observation(binding, &archive_confused),
            Err(BrokerError::BindingMismatch)
        );
    }
    assert!(matches!(
        prepare_test_server_state(
            &tle_catalog,
            RuntimeProviderBrokerBackendsV1::new().with_global_beacon_partial_signer(Arc::new(
                TestGlobalBeaconBrokerBackendV1 {
                    handle,
                    qualification,
                },
            )),
        ),
        Err(RuntimeProviderBrokerServerErrorV1::BackendSetMismatch)
    ));
    prepare_test_server_state(
        &tle_catalog,
        RuntimeProviderBrokerBackendsV1::new().with_parliament_tle_partial_release_signer(
            Arc::new(TestParliamentTleBrokerBackendV1 {
                handle,
                qualification,
            }),
        ),
    )
    .expect("exact Parliament TLE signer backend qualifies");
    for qualification in [
        ConsensusSignerProviderQualificationV1::new(revision + 1, digest, false),
        ConsensusSignerProviderQualificationV1::new(revision, [0xA8; 32], false),
        ConsensusSignerProviderQualificationV1::new(revision, digest, true),
    ] {
        assert!(matches!(
            prepare_test_server_state(
                &tle_catalog,
                RuntimeProviderBrokerBackendsV1::new().with_parliament_tle_partial_release_signer(
                    Arc::new(TestParliamentTleBrokerBackendV1 {
                        handle,
                        qualification,
                    },)
                ),
            ),
            Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch)
        ));
    }
}

#[test]
fn threshold_client_shallow_validation_is_exact_to_ok_typed_slot_pairs() {
    let catalog = IrohaRuntimeProviderBindingsV1::qualified_for_test(
        "threshold-client-response-test",
        IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner,
        "software://iroha/consensus-threshold/primary",
        7,
        [0xA7; 32],
    );
    let beacon_binding = ProviderBindingWireV1::try_from_binding(
        catalog.iter().next().expect("one beacon response binding"),
    )
    .expect("project beacon response binding");
    let request = make_operation_request(
        TEST_SESSION_ID,
        1,
        beacon_binding.clone(),
        observation(&beacon_binding).metadata_digest,
        OPERATION_GLOBAL_BEACON_PARTIAL_SIGN_V1,
        vec![0xA5],
    )
    .expect("seal shallow beacon response request");
    let malformed_result = vec![0x5A];
    let correlated_ok = operation_response(&request, STATUS_OK_V1, malformed_result.clone());
    assert_eq!(
        validate_operation_response_for_client(&request, &correlated_ok, catalog.network_id()),
        Ok(()),
        "the exact typed proxy owns semantic validation for a correlated OK result"
    );
    let correlated_rejection =
        operation_response(&request, STATUS_REJECTED_V1, malformed_result.clone());
    assert_eq!(
        validate_operation_response_for_client(
            &request,
            &correlated_rejection,
            catalog.network_id(),
        ),
        Err(BrokerError::Protocol),
        "error statuses must retain the exact payload-free result matrix"
    );

    let tle_catalog = IrohaRuntimeProviderBindingsV1::qualified_for_test(
        "threshold-client-response-test",
        IrohaRuntimeProviderSlotV1::ParliamentTlePartialReleaseSigner,
        "software://iroha/consensus-threshold/primary",
        7,
        [0xA7; 32],
    );
    let tle_binding = ProviderBindingWireV1::try_from_binding(
        tle_catalog.iter().next().expect("one TLE response binding"),
    )
    .expect("project TLE response binding");
    let cross_slot = make_operation_request(
        TEST_SESSION_ID,
        2,
        tle_binding.clone(),
        observation(&tle_binding).metadata_digest,
        OPERATION_GLOBAL_BEACON_PARTIAL_SIGN_V1,
        vec![0xA5],
    )
    .expect("seal cross-slot threshold response request");
    let cross_slot_ok = operation_response(&cross_slot, STATUS_OK_V1, malformed_result);
    assert_eq!(
        validate_operation_response_for_client(
            &cross_slot,
            &cross_slot_ok,
            tle_catalog.network_id(),
        ),
        Err(BrokerError::BindingMismatch),
        "an operation number alone must never enter the shallow typed-proxy path"
    );
}

#[test]
fn global_beacon_partial_signer_round_trips_over_authenticated_broker() {
    let fixture = consensus_threshold_beacon_broker_test_fixture_v1();
    let (_directory, policy, shutdown, server) =
        start_signer(fixture.catalog.clone(), fixture.backends);
    let dependencies = resolve_test_process(&fixture.catalog, &policy)
        .expect("resolve global-beacon broker proxy");
    let signer = dependencies
        .sumeragi_global_beacon_partial_signer
        .as_ref()
        .expect("resolved global-beacon partial signer");
    let anchor = iroha_data_model::consensus::GlobalThresholdBeaconChainAnchorV1 {
        height: 50,
        block_hash:
            iroha_crypto::HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
                iroha_crypto::Hash::prehashed([0xB1; 32]),
            ),
    };
    let mut verifier = iroha_core::beacon::GlobalThresholdBeaconPulseAggregatorV1::new(
        fixture.session.clone(),
        51,
        anchor,
        iroha_core::beacon::pulse_context_fixture_v1(),
    )
    .expect("construct canonical brokered beacon pulse");
    let partial = iroha_core::beacon::GlobalThresholdBeaconPartialSignerV1::sign_partial(
        signer.as_ref(),
        &fixture.session,
        verifier.payload(),
    )
    .expect("round-trip global-beacon partial through authenticated broker");
    assert!(
        verifier
            .accept_partial(partial)
            .expect("independently verify brokered beacon partial")
    );
    let context = iroha_core::beacon::pulse_context_fixture_v1();
    let slot = iroha_core::beacon::global_threshold_beacon_pulse_signing_slot_v1(
        &fixture.session,
        verifier.payload(),
    )
    .expect("parse original caller signing context");
    assert_eq!(slot.context, context);
    for field in 0..5 {
        let mut changed = context;
        match field {
            0 => changed.instance[0] ^= 1,
            1 => changed.epoch += 1,
            2 => changed.epoch_context_id[0] ^= 1,
            3 => changed.parent_consensus_hash[0] ^= 1,
            _ => changed.parent_result[0] ^= 1,
        }
        let mut other = iroha_core::beacon::GlobalThresholdBeaconPulseAggregatorV1::new(
            fixture.session.clone(),
            51,
            anchor,
            changed,
        )
        .expect("different explicit native signing context");
        assert!(
            other.accept_partial(partial).is_err(),
            "brokered signature must retain context field {field}"
        );
    }
    drop(dependencies);
    shutdown.request_shutdown();
    server
        .join()
        .expect("join global-beacon broker")
        .expect("global-beacon broker exits cleanly");
}

#[test]
fn maximum_committee_global_beacon_proxy_round_trips_on_ordinary_stack() {
    let fixture_started = std::time::Instant::now();
    let fixture = consensus_threshold_beacon_broker_max_committee_test_fixture_v1();
    eprintln!(
        "max31 fixture construction: {:?}",
        fixture_started.elapsed()
    );
    let connection_started = std::time::Instant::now();
    assert_eq!(fixture.session.record().committee_size, 31);
    assert_eq!(fixture.session.record().threshold, 11);
    let (_directory, policy, shutdown, server) =
        start_signer(fixture.catalog.clone(), fixture.backends);
    let dependencies = resolve_test_process(&fixture.catalog, &policy)
        .expect("resolve maximum-committee beacon proxy");
    eprintln!(
        "max31 authenticated connection: {:?}",
        connection_started.elapsed()
    );
    let signer = dependencies
        .sumeragi_global_beacon_partial_signer
        .as_ref()
        .expect("resolved maximum-committee beacon signer");
    let anchor = iroha_data_model::consensus::GlobalThresholdBeaconChainAnchorV1 {
        height: 50,
        block_hash:
            iroha_crypto::HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
                iroha_crypto::Hash::prehashed([0xB6; 32]),
            ),
    };
    let mut verifier = iroha_core::beacon::GlobalThresholdBeaconPulseAggregatorV1::new(
        fixture.session.clone(),
        51,
        anchor,
        iroha_core::beacon::pulse_context_fixture_v1(),
    )
    .expect("construct maximum-committee brokered beacon pulse");
    let signing_started = std::time::Instant::now();
    let partial = iroha_core::beacon::GlobalThresholdBeaconPartialSignerV1::sign_partial(
        signer.as_ref(),
        &fixture.session,
        verifier.payload(),
    );
    eprintln!(
        "max31 authenticated partial-sign exchange: {:?}",
        signing_started.elapsed()
    );
    let partial =
        partial.expect("sign maximum-committee beacon partial on the ordinary client stack");
    assert!(
        verifier
            .accept_partial(partial)
            .expect("independently verify maximum-committee beacon partial")
    );

    drop(dependencies);
    shutdown.request_shutdown();
    server
        .join()
        .expect("join maximum-committee beacon broker")
        .expect("maximum-committee beacon broker exits cleanly");
}

#[test]
fn transient_beacon_qualification_reconnects_without_signer_replay() {
    for (failure_offset, block_hash_byte) in [(1_u64, 0xB4_u8), (3_u64, 0xB5_u8)] {
        let fixture = consensus_threshold_beacon_broker_test_fixture_v1();
        let inner = fixture
            .backends
            .global_beacon_partial_signer
            .as_ref()
            .expect("fixture has one global-beacon signer")
            .clone();
        let backend = Arc::new(TransientQualificationGlobalBeaconBrokerBackendV1 {
            inner,
            qualification_calls: AtomicU64::new(0),
            fail_on_qualification_call: AtomicU64::new(0),
            sign_calls: AtomicU64::new(0),
        });
        let backends = fixture
            .backends
            .with_global_beacon_partial_signer(backend.clone());
        let (_directory, policy, shutdown, server) =
            start_signer(fixture.catalog.clone(), backends);
        let dependencies = resolve_test_process(&fixture.catalog, &policy)
            .expect("resolve transient beacon broker proxy");
        let signer = dependencies
            .sumeragi_global_beacon_partial_signer
            .as_ref()
            .expect("resolved transient global-beacon partial signer");
        backend.fail_after_additional_qualification_calls(failure_offset);

        let anchor = iroha_data_model::consensus::GlobalThresholdBeaconChainAnchorV1 {
            height: 50,
            block_hash:
                iroha_crypto::HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
                    iroha_crypto::Hash::prehashed([block_hash_byte; 32]),
                ),
        };
        let mut verifier = iroha_core::beacon::GlobalThresholdBeaconPulseAggregatorV1::new(
            fixture.session.clone(),
            51,
            anchor,
            iroha_core::beacon::pulse_context_fixture_v1(),
        )
        .expect("construct transient-qualification beacon pulse");
        let partial = iroha_core::beacon::GlobalThresholdBeaconPartialSignerV1::sign_partial(
            signer.as_ref(),
            &fixture.session,
            verifier.payload(),
        )
        .expect("transient qualification outage reconnects and retries once");
        assert!(
            verifier
                .accept_partial(partial)
                .expect("verify partial after qualification reconnect")
        );
        assert_eq!(
            backend.sign_calls.load(Ordering::Acquire),
            1,
            "qualification failure at offset {failure_offset} must not replay signing"
        );

        drop(dependencies);
        shutdown.request_shutdown();
        server
            .join()
            .expect("join transient-qualification beacon broker")
            .expect("transient-qualification beacon broker exits cleanly");
    }
}

#[test]
fn global_beacon_partial_signer_reconnects_after_broker_restart() {
    let fixture = consensus_threshold_beacon_broker_test_fixture_v1();
    let catalog = fixture.catalog.clone();
    let session = fixture.session.clone();
    let (_directory, policy, shutdown, server) = start_signer(fixture.catalog, fixture.backends);
    let dependencies =
        resolve_test_process(&catalog, &policy).expect("resolve retained beacon broker proxy");
    let signer = dependencies
        .sumeragi_global_beacon_partial_signer
        .as_ref()
        .expect("resolved retained global-beacon partial signer");

    shutdown.request_shutdown();
    server
        .join()
        .expect("join predecessor global-beacon broker")
        .expect("predecessor global-beacon broker exits cleanly");

    let replacement = consensus_threshold_beacon_broker_test_fixture_v1();
    let replacement_policy = policy.clone();
    let replacement_lifecycle = Arc::new(RuntimeProviderBrokerLifecycleV1::new());
    let server_lifecycle = Arc::clone(&replacement_lifecycle);
    let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
    let replacement_server = thread::spawn(move || {
        serve_test_process_with_lifecycle(
            &replacement.catalog,
            replacement.backends,
            &replacement_policy,
            server_lifecycle,
            move || {
                ready_sender
                    .send(())
                    .expect("publish replacement beacon broker readiness");
            },
        )
    });
    ready_receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("replacement beacon broker becomes ready");

    let anchor = iroha_data_model::consensus::GlobalThresholdBeaconChainAnchorV1 {
        height: 50,
        block_hash:
            iroha_crypto::HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
                iroha_crypto::Hash::prehashed([0xB2; 32]),
            ),
    };
    let mut verifier = iroha_core::beacon::GlobalThresholdBeaconPulseAggregatorV1::new(
        session.clone(),
        51,
        anchor,
        iroha_core::beacon::pulse_context_fixture_v1(),
    )
    .expect("construct post-restart beacon pulse");
    let partial = iroha_core::beacon::GlobalThresholdBeaconPartialSignerV1::sign_partial(
        signer.as_ref(),
        &session,
        verifier.payload(),
    )
    .expect("retained beacon proxy reconnects after broker restart");
    assert!(
        verifier
            .accept_partial(partial)
            .expect("verify post-restart brokered beacon partial")
    );

    drop(dependencies);
    replacement_lifecycle.request_shutdown();
    replacement_server
        .join()
        .expect("join replacement global-beacon broker")
        .expect("replacement global-beacon broker exits cleanly");
}

#[test]
fn invalid_beacon_partial_permanently_poisons_without_reconnect_or_replay() {
    let fixture = consensus_threshold_beacon_broker_test_fixture_v1();
    let catalog = fixture.catalog;
    let session = fixture.session;
    drop(fixture.backends);
    let configured = catalog.iter().next().expect("one beacon signer binding");
    let sign_calls = Arc::new(AtomicU64::new(0));
    let backends = RuntimeProviderBrokerBackendsV1::new().with_global_beacon_partial_signer(
        Arc::new(InvalidGlobalBeaconBrokerBackendV1 {
            handle: configured.handle().to_owned(),
            qualification: ConsensusSignerProviderQualificationV1::new(
                configured.revision().expect("beacon signer revision"),
                configured
                    .policy_digest()
                    .expect("beacon signer policy digest"),
                false,
            ),
            sign_calls: Arc::clone(&sign_calls),
        }),
    );
    let (_directory, policy, shutdown, server) = start_signer(catalog.clone(), backends);
    let dependencies =
        resolve_test_process(&catalog, &policy).expect("resolve invalid beacon broker proxy");
    let signer = dependencies
        .sumeragi_global_beacon_partial_signer
        .as_ref()
        .expect("resolved invalid beacon partial signer");
    let anchor = iroha_data_model::consensus::GlobalThresholdBeaconChainAnchorV1 {
        height: 50,
        block_hash:
            iroha_crypto::HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
                iroha_crypto::Hash::prehashed([0xB3; 32]),
            ),
    };
    let verifier = iroha_core::beacon::GlobalThresholdBeaconPulseAggregatorV1::new(
        session.clone(),
        51,
        anchor,
        iroha_core::beacon::pulse_context_fixture_v1(),
    )
    .expect("construct invalid-provider beacon pulse");
    for attempt in 0..2 {
        assert!(
            iroha_core::beacon::GlobalThresholdBeaconPartialSignerV1::sign_partial(
                signer.as_ref(),
                &session,
                verifier.payload(),
            )
            .is_err(),
            "invalid provider output must fail on attempt {attempt}"
        );
    }
    assert_eq!(
        sign_calls.load(Ordering::Acquire),
        1,
        "the latched stale signer failure must reject locally without reconnect or replay"
    );

    drop(dependencies);
    shutdown.request_shutdown();
    server
        .join()
        .expect("join invalid beacon broker")
        .expect("invalid beacon broker exits cleanly");
}

#[test]
fn correlated_malformed_beacon_response_is_rejected_by_typed_proxy() {
    let fixture = consensus_threshold_beacon_broker_test_fixture_v1();
    let catalog = fixture.catalog;
    let session = fixture.session;
    drop(fixture.backends);
    let binding = ProviderBindingWireV1::try_from_binding(
        catalog.iter().next().expect("one beacon signer binding"),
    )
    .expect("project malformed-response beacon binding");
    let revision = binding.revision.expect("beacon signer revision");
    let policy_digest = binding.policy_digest.expect("beacon signer policy digest");
    let invalid_session_id = session.record().session_id;
    let server_network_id = *catalog.network_id();
    let (_directory, _path, policy, listener) = bind_fake_broker();
    let server_binding = binding.clone();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept malformed beacon client");
        let handshake = read_handshake(&mut stream);
        assert_eq!(handshake.requested_catalog, vec![server_binding]);
        send_handshake(&mut stream, &handshake_response(&handshake));
        for expected_request_id in 1_u64..=3 {
            let qualify = read_operation(&mut stream);
            assert_eq!(qualify.request_id, expected_request_id);
            assert_eq!(qualify.operation, OPERATION_QUALIFY_V1);
            let qualification = encode_canonical(
                &QualificationResultWireV1 {
                    revision,
                    policy_digest,
                },
                MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
            )
            .expect("encode malformed-response beacon qualification");
            send_operation(
                &mut stream,
                &operation_response(&qualify, STATUS_OK_V1, qualification),
            );
        }
        let sign = read_consensus_signer_operation(&mut stream, &server_network_id);
        assert_eq!(sign.request_id, 4);
        assert_eq!(sign.operation, OPERATION_GLOBAL_BEACON_PARTIAL_SIGN_V1);
        let malformed = encode_canonical(
            &GlobalBeaconPartialSignResultWireV1 {
                partial: iroha_data_model::consensus::GlobalThresholdBeaconPartialSignatureV1 {
                    session_id: invalid_session_id,
                    signer_index: 1,
                    signature_share: [0; 48],
                    proof:
                        iroha_data_model::consensus::GlobalThresholdBeaconPartialSignatureProofV1 {
                            x: [0; 96],
                            y: [0; 48],
                            z_s: [0; 32],
                            z_r: [0; 32],
                            z_u: [0; 32],
                        },
                },
            },
            MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
        )
        .expect("encode correlated malformed beacon result");
        send_operation(
            &mut stream,
            &operation_response(&sign, STATUS_OK_V1, malformed),
        );
    });
    let dependencies = resolve_test_process(&catalog, &policy)
        .expect("resolve proxy through correlated fake beacon broker");
    let signer = dependencies
        .sumeragi_global_beacon_partial_signer
        .as_ref()
        .expect("resolved malformed-response beacon signer");
    let anchor = iroha_data_model::consensus::GlobalThresholdBeaconChainAnchorV1 {
        height: 50,
        block_hash:
            iroha_crypto::HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
                iroha_crypto::Hash::prehashed([0xB7; 32]),
            ),
    };
    let verifier = iroha_core::beacon::GlobalThresholdBeaconPulseAggregatorV1::new(
        session.clone(),
        51,
        anchor,
        iroha_core::beacon::pulse_context_fixture_v1(),
    )
    .expect("construct malformed-response beacon pulse");
    assert_eq!(
        iroha_core::beacon::GlobalThresholdBeaconPartialSignerV1::sign_partial(
            signer.as_ref(),
            &session,
            verifier.payload(),
        ),
        Err(ERROR_REJECTED.to_owned()),
        "an envelope-correlated OK response cannot bypass typed proof verification"
    );
    assert_eq!(
        iroha_core::beacon::GlobalThresholdBeaconPartialSignerV1::sign_partial(
            signer.as_ref(),
            &session,
            verifier.payload(),
        ),
        Err(ERROR_UNAVAILABLE.to_owned()),
        "semantic rejection must permanently poison the session without replay"
    );
    server
        .join()
        .expect("join malformed-response beacon broker");
}

#[test]
fn parliament_tle_capability_attestation_round_trips_over_authenticated_broker() {
    let fixture = consensus_threshold_tle_broker_test_fixture_v1();
    let (_directory, policy, shutdown, server) =
        start_signer(fixture.catalog.clone(), fixture.backends);
    let requested_catalog = fixture
        .catalog
        .iter()
        .map(ProviderBindingWireV1::try_from_binding)
        .collect::<Result<Vec<_>, _>>()
        .expect("project exact TLE broker catalog");
    let (client, observations) = connect_test_process(
        &policy,
        fixture.catalog.chain_id(),
        *fixture.catalog.network_id(),
        requested_catalog.clone(),
    )
    .expect("authenticate TLE capability broker client session");
    let payload = encode_canonical(
        &ParliamentTleCapabilityAttestRequestWireV1 {
            key_session: fixture.session.public_state().clone(),
            participant_index: 1,
        },
        MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
    )
    .expect("encode exact TLE capability operation");
    let result = client
        .call(
            &requested_catalog[0],
            observations[0].metadata_digest,
            OPERATION_PARLIAMENT_TLE_CAPABILITY_ATTEST_V1,
            payload,
            false,
        )
        .expect("round-trip Parliament TLE capability through authenticated broker");
    let attested = client
        .decode_operation_result::<ParliamentTleCapabilityAttestResultWireV1>(
            &result,
            OPERATION_PARLIAMENT_TLE_CAPABILITY_ATTEST_V1,
        )
        .expect("decode brokered Parliament TLE capability");
    assert_eq!(
        attested.key_session_id,
        fixture.session.public_state().key_session_id
    );
    assert_eq!(
        attested.transcript_hash,
        fixture.session.public_state().transcript_hash
    );
    assert_eq!(attested.participant_index, 1);
    let wrong_seat_payload = encode_canonical(
        &ParliamentTleCapabilityAttestRequestWireV1 {
            key_session: fixture.session.public_state().clone(),
            participant_index: 2,
        },
        MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
    )
    .expect("encode wrong-seat TLE capability operation");
    assert!(matches!(
        client.call(
            &requested_catalog[0],
            observations[0].metadata_digest,
            OPERATION_PARLIAMENT_TLE_CAPABILITY_ATTEST_V1,
            wrong_seat_payload,
            false,
        ),
        Err(BrokerError::Rejected)
    ));
    drop(client);
    shutdown.request_shutdown();
    server
        .join()
        .expect("join Parliament TLE capability broker")
        .expect("Parliament TLE capability broker exits cleanly");
}

#[test]
fn parliament_tle_capability_typed_proxy_requalifies_before_and_after_lookup() {
    let fixture = consensus_threshold_tle_broker_test_fixture_v1();
    let catalog = fixture.catalog;
    let session = fixture.session;
    drop(fixture.backends);
    let binding = ProviderBindingWireV1::try_from_binding(
        catalog.iter().next().expect("one TLE signer binding"),
    )
    .expect("project exact-capability TLE binding");
    let revision = binding.revision.expect("TLE signer revision");
    let policy_digest = binding.policy_digest.expect("TLE signer policy digest");
    let expected_public_state = session.public_state().clone();
    let expected_key_session_id = expected_public_state.key_session_id;
    let expected_transcript_hash = expected_public_state.transcript_hash;
    let server_network_id = *catalog.network_id();
    let (_directory, _path, policy, listener) = bind_fake_broker();
    let server_binding = binding.clone();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener
            .accept()
            .expect("accept exact-capability TLE client");
        let handshake = read_handshake(&mut stream);
        assert_eq!(handshake.requested_catalog, vec![server_binding]);
        send_handshake(&mut stream, &handshake_response(&handshake));

        expect_and_answer_consensus_signer_qualification(&mut stream, 1, revision, policy_digest);
        let attest = read_consensus_signer_operation(&mut stream, &server_network_id);
        assert_eq!(attest.request_id, 2);
        assert_eq!(
            attest.operation,
            OPERATION_PARLIAMENT_TLE_CAPABILITY_ATTEST_V1
        );
        let request = decode_canonical::<ParliamentTleCapabilityAttestRequestWireV1>(
            &attest.payload,
            MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
        )
        .expect("decode exact typed-proxy TLE capability request");
        assert_eq!(request.key_session, expected_public_state);
        assert_eq!(request.participant_index, 1);
        let exact = encode_canonical(
            &ParliamentTleCapabilityAttestResultWireV1 {
                key_session_id: expected_key_session_id,
                transcript_hash: expected_transcript_hash,
                participant_index: 1,
            },
            MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
        )
        .expect("encode exact typed-proxy TLE capability result");
        send_operation(
            &mut stream,
            &operation_response(&attest, STATUS_OK_V1, exact),
        );
        expect_and_answer_consensus_signer_qualification(&mut stream, 3, revision, policy_digest);
    });
    let requested_catalog = catalog
        .iter()
        .map(ProviderBindingWireV1::try_from_binding)
        .collect::<Result<Vec<_>, _>>()
        .expect("project exact-capability TLE catalog");
    let (broker_session, observations) = connect_test_process(
        &policy,
        catalog.chain_id(),
        *catalog.network_id(),
        requested_catalog.clone(),
    )
    .expect("authenticate exact-capability TLE broker session");
    let signer = ParliamentTleBrokerPartialReleaseSigner {
        session: broker_session,
        binding: requested_catalog[0].clone(),
        metadata_digest: observations[0].metadata_digest,
    };
    let attestation = signer
        .attest_projected_capability(&session, 1)
        .expect("typed proxy accepts the exact capability result");
    assert!(attestation.matches(&session, 1));
    server.join().expect("join exact-capability TLE broker");
}

#[test]
fn parliament_tle_partial_release_round_trips_over_authenticated_broker() {
    let fixture = consensus_threshold_tle_broker_test_fixture_v1();
    let (_directory, policy, shutdown, server) =
        start_signer(fixture.catalog.clone(), fixture.backends);
    let requested_catalog = fixture
        .catalog
        .iter()
        .map(ProviderBindingWireV1::try_from_binding)
        .collect::<Result<Vec<_>, _>>()
        .expect("project exact TLE broker catalog");
    let (client, observations) = connect_test_process(
        &policy,
        fixture.catalog.chain_id(),
        *fixture.catalog.network_id(),
        requested_catalog.clone(),
    )
    .expect("authenticate TLE broker client session");
    let payload = encode_canonical(
        &ParliamentTlePartialReleaseSignRequestWireV1 {
            projection: fixture.projection,
        },
        MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
    )
    .expect("encode exact TLE broker operation");
    let result = client
        .call(
            &requested_catalog[0],
            observations[0].metadata_digest,
            OPERATION_PARLIAMENT_TLE_PARTIAL_RELEASE_SIGN_V1,
            payload,
            false,
        )
        .expect("round-trip Parliament TLE partial through authenticated broker");
    let signed = client
        .decode_operation_result::<ParliamentTlePartialReleaseSignResultWireV1>(
            &result,
            OPERATION_PARLIAMENT_TLE_PARTIAL_RELEASE_SIGN_V1,
        )
        .expect("decode brokered Parliament TLE partial");
    fixture
        .session
        .verify_partial_release(&fixture.identity, 100, &signed.partial)
        .expect("independently verify brokered Parliament TLE partial");
    drop(client);
    shutdown.request_shutdown();
    server
        .join()
        .expect("join Parliament TLE broker")
        .expect("Parliament TLE broker exits cleanly");
}

#[test]
fn maximum_committee_parliament_tle_proxy_round_trips_on_ordinary_stack() {
    let fixture = consensus_threshold_tle_broker_max_committee_test_fixture_v1();
    assert_eq!(fixture.session.public_state().committee_size, 31);
    assert_eq!(fixture.session.public_state().threshold, 11);
    let (_directory, policy, shutdown, server) =
        start_signer(fixture.catalog.clone(), fixture.backends);
    let requested_catalog = fixture
        .catalog
        .iter()
        .map(ProviderBindingWireV1::try_from_binding)
        .collect::<Result<Vec<_>, _>>()
        .expect("project maximum-committee TLE broker catalog");
    let (session, observations) = connect_test_process(
        &policy,
        fixture.catalog.chain_id(),
        *fixture.catalog.network_id(),
        requested_catalog.clone(),
    )
    .expect("authenticate maximum-committee TLE broker client session");
    let signer = ParliamentTleBrokerPartialReleaseSigner {
        session,
        binding: requested_catalog[0].clone(),
        metadata_digest: observations[0].metadata_digest,
    };
    let first = live_exact_qualification(
        signer.session.as_ref(),
        &signer.binding,
        signer.metadata_digest,
    )
    .expect("first maximum-committee TLE proxy qualification");
    let second = live_exact_qualification(
        signer.session.as_ref(),
        &signer.binding,
        signer.metadata_digest,
    )
    .expect("second maximum-committee TLE proxy qualification");
    assert_eq!(first, second);
    let partial = signer
        .sign_projected_partial_release(
            &fixture.projection,
            &fixture.session,
            &fixture.identity,
            fixture.projection.finalized_height,
        )
        .expect("sign maximum-committee TLE partial on the ordinary client stack");
    fixture
        .session
        .verify_partial_release(
            &fixture.identity,
            fixture.projection.finalized_height,
            &partial,
        )
        .expect("independently verify maximum-committee TLE partial");

    drop(signer);
    shutdown.request_shutdown();
    server
        .join()
        .expect("join maximum-committee TLE broker")
        .expect("maximum-committee TLE broker exits cleanly");
}

#[test]
fn correlated_malformed_tle_response_is_rejected_by_typed_proxy() {
    let fixture = consensus_threshold_tle_broker_test_fixture_v1();
    let catalog = fixture.catalog;
    let projection = fixture.projection;
    let session = fixture.session;
    let identity = fixture.identity;
    drop(fixture.backends);
    let binding = ProviderBindingWireV1::try_from_binding(
        catalog.iter().next().expect("one TLE signer binding"),
    )
    .expect("project malformed-response TLE binding");
    let revision = binding.revision.expect("TLE signer revision");
    let policy_digest = binding.policy_digest.expect("TLE signer policy digest");
    let key_session_id = session.public_state().key_session_id;
    let server_network_id = *catalog.network_id();
    let (_directory, _path, policy, listener) = bind_fake_broker();
    let server_binding = binding.clone();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept malformed TLE client");
        let handshake = read_handshake(&mut stream);
        assert_eq!(handshake.requested_catalog, vec![server_binding]);
        send_handshake(&mut stream, &handshake_response(&handshake));
        for expected_request_id in 1_u64..=3 {
            let qualify = read_operation(&mut stream);
            assert_eq!(qualify.request_id, expected_request_id);
            assert_eq!(qualify.operation, OPERATION_QUALIFY_V1);
            let qualification = encode_canonical(
                &QualificationResultWireV1 {
                    revision,
                    policy_digest,
                },
                MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
            )
            .expect("encode malformed-response TLE qualification");
            send_operation(
                &mut stream,
                &operation_response(&qualify, STATUS_OK_V1, qualification),
            );
        }
        let sign = read_consensus_signer_operation(&mut stream, &server_network_id);
        assert_eq!(sign.request_id, 4);
        assert_eq!(
            sign.operation,
            OPERATION_PARLIAMENT_TLE_PARTIAL_RELEASE_SIGN_V1
        );
        let malformed = encode_canonical(
            &ParliamentTlePartialReleaseSignResultWireV1 {
                partial: iroha_core_timed_ovn::tle::TlePartialReleaseShareV1 {
                    key_session_id,
                    identity_digest: [0; 32],
                    participant_index: 1,
                    sigma: [0; 48],
                    proof_x: [0; 96],
                    proof_y: [0; 48],
                    z_s: [0; 32],
                    z_r: [0; 32],
                    z_u: [0; 32],
                },
            },
            MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
        )
        .expect("encode correlated malformed TLE result");
        send_operation(
            &mut stream,
            &operation_response(&sign, STATUS_OK_V1, malformed),
        );
    });
    let requested_catalog = catalog
        .iter()
        .map(ProviderBindingWireV1::try_from_binding)
        .collect::<Result<Vec<_>, _>>()
        .expect("project malformed-response TLE catalog");
    let (broker_session, observations) = connect_test_process(
        &policy,
        catalog.chain_id(),
        *catalog.network_id(),
        requested_catalog.clone(),
    )
    .expect("authenticate malformed-response TLE broker session");
    let signer = ParliamentTleBrokerPartialReleaseSigner {
        session: broker_session,
        binding: requested_catalog[0].clone(),
        metadata_digest: observations[0].metadata_digest,
    };
    let first = live_exact_qualification(
        signer.session.as_ref(),
        &signer.binding,
        signer.metadata_digest,
    )
    .expect("first malformed-response TLE qualification");
    let second = live_exact_qualification(
        signer.session.as_ref(),
        &signer.binding,
        signer.metadata_digest,
    )
    .expect("second malformed-response TLE qualification");
    assert_eq!(first, second);
    assert_eq!(
        signer.sign_projected_partial_release(
            &projection,
            &session,
            &identity,
            projection.finalized_height,
        ),
        Err(BrokerError::Rejected),
        "an envelope-correlated OK response cannot bypass typed TLE proof verification"
    );
    assert_eq!(
        signer.sign_projected_partial_release(
            &projection,
            &session,
            &identity,
            projection.finalized_height,
        ),
        Err(BrokerError::Protocol),
        "semantic rejection must permanently poison the TLE session without replay"
    );
    server.join().expect("join malformed-response TLE broker");
}

#[derive(Clone, Copy)]
enum ParliamentTleCapabilityResultFault {
    WrongKeySessionId,
    WrongTranscriptHash,
    WrongParticipantIndex,
    Truncated,
}

fn assert_invalid_tle_capability_result_is_rejected(fault: ParliamentTleCapabilityResultFault) {
    let fixture = consensus_threshold_tle_broker_test_fixture_v1();
    let catalog = fixture.catalog;
    let session = fixture.session;
    drop(fixture.backends);
    let binding = ProviderBindingWireV1::try_from_binding(
        catalog.iter().next().expect("one TLE signer binding"),
    )
    .expect("project mismatched-capability TLE binding");
    let revision = binding.revision.expect("TLE signer revision");
    let policy_digest = binding.policy_digest.expect("TLE signer policy digest");
    let key_session_id = session.public_state().key_session_id;
    let transcript_hash = session.public_state().transcript_hash;
    let server_network_id = *catalog.network_id();
    let (_directory, _path, policy, listener) = bind_fake_broker();
    let server_binding = binding.clone();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener
            .accept()
            .expect("accept mismatched-capability TLE client");
        let handshake = read_handshake(&mut stream);
        assert_eq!(handshake.requested_catalog, vec![server_binding]);
        send_handshake(&mut stream, &handshake_response(&handshake));
        expect_and_answer_consensus_signer_qualification(&mut stream, 1, revision, policy_digest);
        let attest = read_consensus_signer_operation(&mut stream, &server_network_id);
        assert_eq!(attest.request_id, 2);
        assert_eq!(
            attest.operation,
            OPERATION_PARLIAMENT_TLE_CAPABILITY_ATTEST_V1
        );
        let mut result = ParliamentTleCapabilityAttestResultWireV1 {
            key_session_id,
            transcript_hash,
            participant_index: 1,
        };
        match fault {
            ParliamentTleCapabilityResultFault::WrongKeySessionId => {
                let candidate =
                    iroha_data_model::governance::types::TleKeySessionId::new([0xC7; 32]);
                result.key_session_id = if candidate == result.key_session_id {
                    iroha_data_model::governance::types::TleKeySessionId::new([0xC8; 32])
                } else {
                    candidate
                };
            }
            ParliamentTleCapabilityResultFault::WrongTranscriptHash => {
                result.transcript_hash[0] ^= 1;
            }
            ParliamentTleCapabilityResultFault::WrongParticipantIndex => {
                result.participant_index = 2;
            }
            ParliamentTleCapabilityResultFault::Truncated => {}
        }
        let mut invalid = encode_canonical(&result, MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1)
            .expect("encode correlated invalid TLE capability result");
        if matches!(fault, ParliamentTleCapabilityResultFault::Truncated) {
            invalid
                .pop()
                .expect("canonical TLE capability result is nonempty");
        }
        send_operation(
            &mut stream,
            &operation_response(&attest, STATUS_OK_V1, invalid),
        );
    });
    let requested_catalog = catalog
        .iter()
        .map(ProviderBindingWireV1::try_from_binding)
        .collect::<Result<Vec<_>, _>>()
        .expect("project mismatched-capability TLE catalog");
    let (broker_session, observations) = connect_test_process(
        &policy,
        catalog.chain_id(),
        *catalog.network_id(),
        requested_catalog.clone(),
    )
    .expect("authenticate mismatched-capability TLE broker session");
    let signer = ParliamentTleBrokerPartialReleaseSigner {
        session: broker_session,
        binding: requested_catalog[0].clone(),
        metadata_digest: observations[0].metadata_digest,
    };
    let expected_error = if matches!(fault, ParliamentTleCapabilityResultFault::Truncated) {
        BrokerError::Protocol
    } else {
        BrokerError::Rejected
    };
    assert_eq!(
        signer.attest_projected_capability(&session, 1),
        Err(expected_error),
        "an envelope-correlated response cannot substitute or truncate a public TLE capability"
    );
    assert_eq!(
        signer.attest_projected_capability(&session, 1),
        Err(BrokerError::Protocol),
        "an invalid capability must permanently poison the TLE session without replay"
    );
    server.join().expect("join invalid-capability TLE broker");
}

#[test]
fn correlated_wrong_tle_key_session_id_is_rejected_by_typed_proxy() {
    assert_invalid_tle_capability_result_is_rejected(
        ParliamentTleCapabilityResultFault::WrongKeySessionId,
    );
}

#[test]
fn correlated_wrong_tle_transcript_hash_is_rejected_by_typed_proxy() {
    assert_invalid_tle_capability_result_is_rejected(
        ParliamentTleCapabilityResultFault::WrongTranscriptHash,
    );
}

#[test]
fn correlated_wrong_tle_participant_index_is_rejected_by_typed_proxy() {
    assert_invalid_tle_capability_result_is_rejected(
        ParliamentTleCapabilityResultFault::WrongParticipantIndex,
    );
}

#[test]
fn correlated_truncated_tle_capability_is_rejected_by_typed_proxy() {
    assert_invalid_tle_capability_result_is_rejected(ParliamentTleCapabilityResultFault::Truncated);
}

#[test]
fn parliament_tle_partial_release_reconnects_after_broker_restart() {
    let fixture = consensus_threshold_tle_broker_test_fixture_v1();
    let catalog = fixture.catalog.clone();
    let projection = fixture.projection.clone();
    let session = fixture.session.clone();
    let identity = fixture.identity;
    let (_directory, policy, shutdown, server) = start_signer(fixture.catalog, fixture.backends);
    let requested_catalog = catalog
        .iter()
        .map(ProviderBindingWireV1::try_from_binding)
        .collect::<Result<Vec<_>, _>>()
        .expect("project exact retained TLE broker catalog");
    let (client, observations) = connect_test_process(
        &policy,
        catalog.chain_id(),
        *catalog.network_id(),
        requested_catalog.clone(),
    )
    .expect("authenticate retained TLE broker client session");

    shutdown.request_shutdown();
    server
        .join()
        .expect("join predecessor TLE broker")
        .expect("predecessor TLE broker exits cleanly");

    let replacement = consensus_threshold_tle_broker_test_fixture_v1();
    let replacement_policy = policy.clone();
    let replacement_lifecycle = Arc::new(RuntimeProviderBrokerLifecycleV1::new());
    let server_lifecycle = Arc::clone(&replacement_lifecycle);
    let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
    let replacement_server = thread::spawn(move || {
        serve_test_process_with_lifecycle(
            &replacement.catalog,
            replacement.backends,
            &replacement_policy,
            server_lifecycle,
            move || {
                ready_sender
                    .send(())
                    .expect("publish replacement TLE broker readiness");
            },
        )
    });
    ready_receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("replacement TLE broker becomes ready");

    let signed = retry_consensus_signer_once_after_unavailable(client.as_ref(), || {
        let payload = encode_canonical(
            &ParliamentTlePartialReleaseSignRequestWireV1 {
                projection: projection.clone(),
            },
            MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
        )?;
        let result = client.call(
            &requested_catalog[0],
            observations[0].metadata_digest,
            OPERATION_PARLIAMENT_TLE_PARTIAL_RELEASE_SIGN_V1,
            payload,
            false,
        )?;
        client
            .decode_operation_result::<ParliamentTlePartialReleaseSignResultWireV1>(
                &result,
                OPERATION_PARLIAMENT_TLE_PARTIAL_RELEASE_SIGN_V1,
            )
            .map(|result| result.partial)
    })
    .expect("retained TLE proxy reconnects after broker restart");
    session
        .verify_partial_release(&identity, 100, &signed)
        .expect("verify post-restart brokered TLE partial");

    drop(client);
    replacement_lifecycle.request_shutdown();
    replacement_server
        .join()
        .expect("join replacement TLE broker")
        .expect("replacement TLE broker exits cleanly");
}

#[test]
fn global_beacon_capability_attestation_round_trips_over_authenticated_broker() {
    let fixture = consensus_threshold_beacon_broker_test_fixture_v1();
    let counted = Arc::new(TransientQualificationGlobalBeaconBrokerBackendV1 {
        inner: fixture
            .backends
            .global_beacon_partial_signer
            .as_ref()
            .expect("real custody backend")
            .clone(),
        qualification_calls: AtomicU64::new(0),
        fail_on_qualification_call: AtomicU64::new(0),
        sign_calls: AtomicU64::new(0),
    });
    let backends = fixture
        .backends
        .with_global_beacon_partial_signer(counted.clone());
    let (_directory, policy, shutdown, server) = start_signer(fixture.catalog.clone(), backends);
    let requested_catalog = fixture
        .catalog
        .iter()
        .map(ProviderBindingWireV1::try_from_binding)
        .collect::<Result<Vec<_>, _>>()
        .expect("project exact beacon broker catalog");
    let (client, observations) = connect_test_process(
        &policy,
        fixture.catalog.chain_id(),
        *fixture.catalog.network_id(),
        requested_catalog.clone(),
    )
    .expect("authenticate beacon capability broker client session");
    let payload = encode_canonical(
        &GlobalBeaconCapabilityAttestRequestWireV1 {
            session: fixture.session.record().clone(),
            signer_index: 1,
        },
        MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
    )
    .expect("encode exact beacon capability operation");
    let result = client
        .call(
            &requested_catalog[0],
            observations[0].metadata_digest,
            OPERATION_GLOBAL_BEACON_CAPABILITY_ATTEST_V1,
            payload,
            false,
        )
        .expect("round-trip global beacon capability through authenticated broker");
    let attested = client
        .decode_operation_result::<GlobalBeaconCapabilityAttestResultWireV1>(
            &result,
            OPERATION_GLOBAL_BEACON_CAPABILITY_ATTEST_V1,
        )
        .expect("decode brokered global beacon capability");
    assert_eq!(attested.session_id, fixture.session.record().session_id);
    assert_eq!(
        attested.transcript_hash,
        fixture.session.record().transcript_hash
    );
    assert_eq!(attested.signer_index, 1);
    let wrong_seat_payload = encode_canonical(
        &GlobalBeaconCapabilityAttestRequestWireV1 {
            session: fixture.session.record().clone(),
            signer_index: 2,
        },
        MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
    )
    .expect("encode wrong-seat beacon capability operation");
    assert!(matches!(
        client.call(
            &requested_catalog[0],
            observations[0].metadata_digest,
            OPERATION_GLOBAL_BEACON_CAPABILITY_ATTEST_V1,
            wrong_seat_payload,
            false,
        ),
        Err(BrokerError::Rejected)
    ));
    assert_eq!(
        counted.sign_calls.load(Ordering::Acquire),
        0,
        "capability lookup must never sign a pulse"
    );
    drop(client);
    shutdown.request_shutdown();
    server
        .join()
        .expect("join global beacon capability broker")
        .expect("global beacon capability broker exits cleanly");
}

#[test]
fn global_beacon_capability_typed_proxy_requalifies_before_and_after_lookup() {
    let fixture = consensus_threshold_beacon_broker_test_fixture_v1();
    let catalog = fixture.catalog;
    let session = fixture.session;
    drop(fixture.backends);
    let binding = ProviderBindingWireV1::try_from_binding(
        catalog.iter().next().expect("one beacon signer binding"),
    )
    .expect("project exact-capability beacon binding");
    let revision = binding.revision.expect("beacon signer revision");
    let policy_digest = binding.policy_digest.expect("beacon signer policy digest");
    let expected_public_state = session.record().clone();
    let expected_session_id = expected_public_state.session_id;
    let expected_transcript_hash = expected_public_state.transcript_hash;
    let server_network_id = *catalog.network_id();
    let (_directory, _path, policy, listener) = bind_fake_broker();
    let server_binding = binding.clone();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener
            .accept()
            .expect("accept exact-capability beacon client");
        let handshake = read_handshake(&mut stream);
        assert_eq!(handshake.requested_catalog, vec![server_binding]);
        send_handshake(&mut stream, &handshake_response(&handshake));

        expect_and_answer_consensus_signer_qualification(&mut stream, 1, revision, policy_digest);
        let attest = read_consensus_signer_operation(&mut stream, &server_network_id);
        assert_eq!(attest.request_id, 2);
        assert_eq!(
            attest.operation,
            OPERATION_GLOBAL_BEACON_CAPABILITY_ATTEST_V1
        );
        let request = decode_canonical::<GlobalBeaconCapabilityAttestRequestWireV1>(
            &attest.payload,
            MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
        )
        .expect("decode exact typed-proxy beacon capability request");
        assert_eq!(request.session, expected_public_state);
        assert_eq!(request.signer_index, 1);
        let exact = encode_canonical(
            &GlobalBeaconCapabilityAttestResultWireV1 {
                session_id: expected_session_id,
                transcript_hash: expected_transcript_hash,
                signer_index: 1,
            },
            MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
        )
        .expect("encode exact typed-proxy beacon capability result");
        send_operation(
            &mut stream,
            &operation_response(&attest, STATUS_OK_V1, exact),
        );
        expect_and_answer_consensus_signer_qualification(&mut stream, 3, revision, policy_digest);
    });
    let requested_catalog = catalog
        .iter()
        .map(ProviderBindingWireV1::try_from_binding)
        .collect::<Result<Vec<_>, _>>()
        .expect("project exact-capability beacon catalog");
    let (broker_session, observations) = connect_test_process(
        &policy,
        catalog.chain_id(),
        *catalog.network_id(),
        requested_catalog.clone(),
    )
    .expect("authenticate exact-capability beacon broker session");
    let signer = GlobalBeaconBrokerPartialSigner {
        session: broker_session,
        binding: requested_catalog[0].clone(),
        metadata_digest: observations[0].metadata_digest,
    };
    assert_eq!(
        iroha_core::beacon::GlobalThresholdBeaconPartialSignerV1::attest_partial_signing_capability(
            &signer, &session, 0
        ),
        Err(iroha_core::beacon::GlobalThresholdBeaconCapabilityErrorV1::InvalidRequest),
        "invalid seats fail before any broker operation",
    );
    let attestation = iroha_core::beacon::GlobalThresholdBeaconPartialSignerV1::attest_partial_signing_capability(&signer, &session, 1)
        .expect("typed proxy accepts the exact capability result");
    assert!(attestation.matches(&session, 1));
    server.join().expect("join exact-capability beacon broker");
}

#[derive(Clone, Copy)]
enum GlobalBeaconCapabilityResultFault {
    WrongSessionId,
    WrongTranscriptHash,
    WrongSignerIndex,
    Truncated,
}

fn assert_invalid_beacon_capability_result_is_rejected(fault: GlobalBeaconCapabilityResultFault) {
    let fixture = consensus_threshold_beacon_broker_test_fixture_v1();
    let catalog = fixture.catalog;
    let session = fixture.session;
    drop(fixture.backends);
    let binding = ProviderBindingWireV1::try_from_binding(
        catalog.iter().next().expect("one beacon signer binding"),
    )
    .expect("project mismatched-capability beacon binding");
    let revision = binding.revision.expect("beacon signer revision");
    let policy_digest = binding.policy_digest.expect("beacon signer policy digest");
    let session_id = session.record().session_id;
    let transcript_hash = session.record().transcript_hash;
    let server_network_id = *catalog.network_id();
    let (_directory, _path, policy, listener) = bind_fake_broker();
    let server_binding = binding.clone();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener
            .accept()
            .expect("accept mismatched-capability beacon client");
        let handshake = read_handshake(&mut stream);
        assert_eq!(handshake.requested_catalog, vec![server_binding]);
        send_handshake(&mut stream, &handshake_response(&handshake));
        expect_and_answer_consensus_signer_qualification(&mut stream, 1, revision, policy_digest);
        let attest = read_consensus_signer_operation(&mut stream, &server_network_id);
        assert_eq!(attest.request_id, 2);
        assert_eq!(
            attest.operation,
            OPERATION_GLOBAL_BEACON_CAPABILITY_ATTEST_V1
        );
        let mut result = GlobalBeaconCapabilityAttestResultWireV1 {
            session_id,
            transcript_hash,
            signer_index: 1,
        };
        match fault {
            GlobalBeaconCapabilityResultFault::WrongSessionId => {
                let candidate = [0xC7; 32];
                result.session_id = if candidate == result.session_id {
                    [0xC8; 32]
                } else {
                    candidate
                };
            }
            GlobalBeaconCapabilityResultFault::WrongTranscriptHash => {
                result.transcript_hash[0] ^= 1;
            }
            GlobalBeaconCapabilityResultFault::WrongSignerIndex => {
                result.signer_index = 2;
            }
            GlobalBeaconCapabilityResultFault::Truncated => {}
        }
        let mut invalid = encode_canonical(&result, MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1)
            .expect("encode correlated invalid beacon capability result");
        if matches!(fault, GlobalBeaconCapabilityResultFault::Truncated) {
            invalid
                .pop()
                .expect("canonical beacon capability result is nonempty");
        }
        send_operation(
            &mut stream,
            &operation_response(&attest, STATUS_OK_V1, invalid),
        );
    });
    let requested_catalog = catalog
        .iter()
        .map(ProviderBindingWireV1::try_from_binding)
        .collect::<Result<Vec<_>, _>>()
        .expect("project mismatched-capability beacon catalog");
    let (broker_session, observations) = connect_test_process(
        &policy,
        catalog.chain_id(),
        *catalog.network_id(),
        requested_catalog.clone(),
    )
    .expect("authenticate mismatched-capability beacon broker session");
    let signer = GlobalBeaconBrokerPartialSigner {
        session: broker_session,
        binding: requested_catalog[0].clone(),
        metadata_digest: observations[0].metadata_digest,
    };
    let expected_error = if matches!(fault, GlobalBeaconCapabilityResultFault::Truncated) {
        BrokerError::Protocol
    } else {
        BrokerError::Rejected
    };
    assert_eq!(
        signer.attest_projected_capability(&session, 1),
        Err(expected_error),
        "an envelope-correlated response cannot substitute or truncate a public beacon capability"
    );
    assert_eq!(
        signer.attest_projected_capability(&session, 1),
        Err(BrokerError::Protocol),
        "an invalid capability must permanently poison the beacon session without replay"
    );
    server
        .join()
        .expect("join invalid-capability beacon broker");
}

#[test]
fn correlated_wrong_beacon_session_id_is_rejected_by_typed_proxy() {
    assert_invalid_beacon_capability_result_is_rejected(
        GlobalBeaconCapabilityResultFault::WrongSessionId,
    );
}

#[test]
fn correlated_wrong_beacon_transcript_hash_is_rejected_by_typed_proxy() {
    assert_invalid_beacon_capability_result_is_rejected(
        GlobalBeaconCapabilityResultFault::WrongTranscriptHash,
    );
}

#[test]
fn correlated_wrong_beacon_signer_index_is_rejected_by_typed_proxy() {
    assert_invalid_beacon_capability_result_is_rejected(
        GlobalBeaconCapabilityResultFault::WrongSignerIndex,
    );
}

#[test]
fn correlated_truncated_beacon_capability_is_rejected_by_typed_proxy() {
    assert_invalid_beacon_capability_result_is_rejected(
        GlobalBeaconCapabilityResultFault::Truncated,
    );
}

#[test]
fn global_beacon_capability_request_rejects_foreign_network_transcript_and_invalid_seat() {
    let pool = Arc::new(DecodeResourcePoolV1::new(MAX_BROKER_SHARED_DECODE_BYTES_V1));
    let admission = DecodeResourceAdmissionV1::acquire_operation_from(
        pool,
        OPERATION_GLOBAL_BEACON_CAPABILITY_ATTEST_V1,
    )
    .unwrap();
    let _scope = admission.enter();
    let fixture = consensus_threshold_beacon_broker_test_fixture_v1();
    let encode = |session, signer_index| {
        encode_canonical(
            &GlobalBeaconCapabilityAttestRequestWireV1 {
                session,
                signer_index,
            },
            MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
        )
        .expect("canonical public capability request")
    };
    let public = fixture.session.record();
    for signer_index in [0, public.committee_size + 1] {
        assert!(matches!(
            decode_global_beacon_capability_attest_request(
                &encode(public.clone(), signer_index),
                fixture.catalog.network_id(),
            ),
            Err(BrokerError::Rejected)
        ));
    }
    let mut foreign = public.clone();
    foreign.network_id = NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::prehashed([0xD9; 32])),
    );
    assert_ne!(foreign.network_id, *fixture.catalog.network_id());
    assert!(matches!(
        decode_global_beacon_capability_attest_request(
            &encode(foreign, 1),
            fixture.catalog.network_id(),
        ),
        Err(BrokerError::BindingMismatch)
    ));
    let mut corrupt = public.clone();
    corrupt.transcript_hash[0] ^= 1;
    assert!(matches!(
        decode_global_beacon_capability_attest_request(
            &encode(corrupt, 1),
            fixture.catalog.network_id(),
        ),
        Err(BrokerError::Rejected)
    ));
}

#[test]
fn global_beacon_capability_server_rejects_a_qualified_backend_claiming_the_wrong_seat() {
    let fixture = consensus_threshold_beacon_broker_test_fixture_v1();
    let original = fixture
        .backends
        .global_beacon_partial_signer
        .as_ref()
        .expect("real backend");
    let sign_calls = Arc::new(AtomicU64::new(0));
    let backend = Arc::new(InvalidGlobalBeaconBrokerBackendV1 {
        handle: original.handle().to_owned(),
        qualification: original
            .qualification()
            .expect("exact provider qualification"),
        sign_calls: sign_calls.clone(),
    });
    let (_directory, policy, shutdown, server) = start_signer(
        fixture.catalog.clone(),
        fixture.backends.with_global_beacon_partial_signer(backend),
    );
    let dependencies =
        resolve_test_process(&fixture.catalog, &policy).expect("resolve qualified provider");
    let signer = dependencies
        .sumeragi_global_beacon_partial_signer
        .as_ref()
        .expect("typed proxy");
    assert_eq!(
        iroha_core::beacon::GlobalThresholdBeaconPartialSignerV1::attest_partial_signing_capability(
            signer.as_ref(),
            &fixture.session,
            1,
        ),
        Err(iroha_core::beacon::GlobalThresholdBeaconCapabilityErrorV1::NotOwned)
    );
    assert_eq!(sign_calls.load(Ordering::Acquire), 0);
    drop(dependencies);
    shutdown.request_shutdown();
    server
        .join()
        .expect("join capability broker")
        .expect("clean shutdown");
}

#[test]
fn prepared_beacon_readiness_round_trips_over_its_typed_broker_domain() {
    use iroha_core::beacon::seat_readiness::{
        prove_global_threshold_beacon_seat_readiness_v1,
        verify_global_threshold_beacon_seat_readiness_v1,
    };
    let (fixture, authority, context) = crate::external_software_signer::consensus_threshold_beacon_readiness_broker_test_fixture_v1();
    let (_directory, policy, shutdown, server) =
        start_signer(fixture.catalog.clone(), fixture.backends);
    let dependencies = resolve_test_process(&fixture.catalog, &policy).unwrap();
    let signer = dependencies
        .sumeragi_global_beacon_partial_signer
        .as_ref()
        .unwrap();
    let proof = prove_global_threshold_beacon_seat_readiness_v1(
        signer.as_ref(),
        &fixture.session,
        &authority,
        &context,
    )
    .unwrap();
    verify_global_threshold_beacon_seat_readiness_v1(
        &fixture.session,
        &authority,
        &context,
        &proof,
    )
    .unwrap();
    let mut replay = context;
    replay.transition_id[0] ^= 1;
    assert!(
        verify_global_threshold_beacon_seat_readiness_v1(
            &fixture.session,
            &authority,
            &replay,
            &proof
        )
        .is_err()
    );
    let other_attempt = prove_global_threshold_beacon_seat_readiness_v1(
        signer.as_ref(),
        &fixture.session,
        &authority,
        &replay,
    )
    .unwrap();
    assert_ne!(proof.signature_share, other_attempt.signature_share);
    let mut wrong_seat = context;
    wrong_seat.validator_index = 1;
    assert!(
        prove_global_threshold_beacon_seat_readiness_v1(
            signer.as_ref(),
            &fixture.session,
            &authority,
            &wrong_seat
        )
        .is_err()
    );
    let (challenge, _) =
        iroha_core::beacon::seat_readiness::global_threshold_beacon_seat_readiness_challenge_v1(
            &fixture.session,
            &authority,
            &context,
        )
        .unwrap();
    assert!(
        signer
            .sign_partial(&fixture.session, challenge.as_ref())
            .is_err(),
        "the pulse operation never accepts readiness payloads"
    );
    let anchor = iroha_data_model::consensus::GlobalThresholdBeaconChainAnchorV1 {
        height: 50,
        block_hash:
            iroha_crypto::HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
                iroha_crypto::Hash::new(b"post-readiness ordinary pulse"),
            ),
    };
    let mut pulse = iroha_core::beacon::GlobalThresholdBeaconPulseAggregatorV1::new(
        fixture.session.clone(),
        51,
        anchor,
        iroha_core::beacon::pulse_context_fixture_v1(),
    )
    .unwrap();
    assert!(
        pulse.accept_partial(proof).is_err(),
        "readiness cannot be relabeled as a pulse"
    );
    let ordinary = signer
        .sign_partial(&fixture.session, pulse.payload())
        .unwrap();
    pulse.accept_partial(ordinary).unwrap();
    drop(dependencies);
    shutdown.request_shutdown();
    server.join().unwrap().unwrap();
}

#[test]
fn beacon_request_borrowed_views_emit_the_exact_canonical_owned_frames() {
    let (fixture, authority, context) = crate::external_software_signer::consensus_threshold_beacon_readiness_broker_test_fixture_v1();
    let public = fixture.session.record();
    let anchor = iroha_data_model::consensus::GlobalThresholdBeaconChainAnchorV1 {
        height: 50,
        block_hash: iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::prehashed(
            [0xB1; 32],
        )),
    };
    let pulse_context = iroha_core::beacon::pulse_context_fixture_v1();
    let owned = GlobalBeaconPartialSignRequestWireV1 {
        session: public.clone(),
        height: 51,
        finalized_chain_anchor: anchor,
        context: pulse_context,
    };
    let borrowed = GlobalBeaconPartialSignRequestRefV1 {
        session: norito::core::PayloadRef(public),
        height: 51,
        finalized_chain_anchor: anchor,
        context: pulse_context,
    };
    assert_eq!(
        norito::encode_canonical(&owned).unwrap(),
        norito::encode_canonical(&borrowed).unwrap()
    );
    let owned = GlobalBeaconSeatReadinessRequestWireV1 {
        session: public.clone(),
        authority: authority.clone(),
        context,
    };
    let borrowed = GlobalBeaconSeatReadinessRequestRefV1 {
        session: norito::core::PayloadRef(public),
        authority: norito::core::PayloadRef(&authority),
        context,
    };
    assert_eq!(
        norito::encode_canonical(&owned).unwrap(),
        norito::encode_canonical(&borrowed).unwrap()
    );
    let owned = GlobalBeaconCapabilityAttestRequestWireV1 {
        session: public.clone(),
        signer_index: 1,
    };
    let borrowed = GlobalBeaconCapabilityAttestRequestRefV1 {
        session: norito::core::PayloadRef(public),
        signer_index: 1,
    };
    assert_eq!(
        norito::encode_canonical(&owned).unwrap(),
        norito::encode_canonical(&borrowed).unwrap()
    );
}

#[test]
fn beacon_operation_graph_uses_the_original_process_pool_and_outlives_its_decode_permit() {
    let fixture = consensus_threshold_beacon_broker_test_fixture_v1();
    let public = fixture.session.record();
    let binding = iroha_core::beacon::GlobalThresholdBeaconSessionBindingV1 {
        network_id: public.network_id,
        session_id: public.session_id,
        roster_hash: public.roster_hash,
        transcript_hash: public.transcript_hash,
    };
    let demand =
        iroha_core::beacon::global_threshold_beacon_session_allocation_bytes_v1(public, &binding)
            .unwrap();
    let policy = operation_decode_policy(OPERATION_GLOBAL_BEACON_CAPABILITY_ATTEST_V1);
    let pool = Arc::new(DecodeResourcePoolV1::new(
        policy.max_composed_bytes + demand + 1,
    ));
    let admission = DecodeResourceAdmissionV1::acquire_operation_from(
        pool.clone(),
        OPERATION_GLOBAL_BEACON_CAPABILITY_ATTEST_V1,
    )
    .unwrap();
    let blocker = pool.try_acquire(2).unwrap();
    assert!(matches!(
        admission.retain_beacon_session(public, &binding),
        Err(BrokerError::Unavailable)
    ));
    assert_eq!(
        pool.allocation.reserved_bytes(),
        policy.max_composed_bytes + 2
    );
    assert!(admission.beacon_session.lock().unwrap().is_none());
    assert!(matches!(
        admission.retain_beacon_session(public, &binding),
        Err(BrokerError::Unavailable)
    ));
    assert!(admission.beacon_session.lock().unwrap().is_none());
    assert_eq!(
        pool.allocation.reserved_bytes(),
        policy.max_composed_bytes + 2
    );
    drop(blocker);
    let session = admission.retain_beacon_session(public, &binding).unwrap();
    assert!(session.belongs_to(&pool.allocation));
    assert_eq!(session.record(), public);
    assert!(
        admission
            .beacon_session
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .ptr_eq(&session)
    );
    let retained = session.retained_allocation_bytes();
    assert_eq!(
        pool.allocation.reserved_bytes(),
        policy.max_composed_bytes + retained
    );
    let shared = session.clone();
    assert!(shared.ptr_eq(&session));
    drop(admission);
    assert_eq!(pool.allocation.reserved_bytes(), retained);
    drop(session);
    assert_eq!(pool.allocation.reserved_bytes(), retained);
    drop(shared);
    assert_eq!(pool.allocation.reserved_bytes(), 0);
    assert!(
        matches!(
            retain_operation_beacon_session(public, &binding),
            Err(BrokerError::Unavailable)
        ),
        "an absent original operation never creates another pool"
    );
}

#[test]
fn beacon_operation_reuses_original_graph_across_ingress_dispatch_and_response() {
    for committee in [4, 31] {
        let fixture = if committee == 4 {
            consensus_threshold_beacon_broker_test_fixture_v1()
        } else {
            consensus_threshold_beacon_broker_max_committee_test_fixture_v1()
        };
        let public = fixture.session.record();
        let binding = iroha_core::beacon::GlobalThresholdBeaconSessionBindingV1 {
            network_id: public.network_id,
            session_id: public.session_id,
            roster_hash: public.roster_hash,
            transcript_hash: public.transcript_hash,
        };
        let graph_demand = iroha_core::beacon::global_threshold_beacon_session_allocation_bytes_v1(
            public, &binding,
        )
        .unwrap();
        let policy = operation_decode_policy(OPERATION_GLOBAL_BEACON_PARTIAL_SIGN_V1);
        let pool = Arc::new(DecodeResourcePoolV1::new(
            policy.max_composed_bytes + graph_demand,
        ));
        let state =
            prepare_server_state(&fixture.catalog, fixture.backends, Arc::clone(&pool)).unwrap();
        let wire_binding =
            ProviderBindingWireV1::try_from_binding(fixture.catalog.iter().next().unwrap())
                .unwrap();
        let metadata = configured_observation(&state, &wire_binding)
            .unwrap()
            .metadata_digest;
        let anchor = iroha_data_model::consensus::GlobalThresholdBeaconChainAnchorV1 {
            height: 50,
            block_hash: iroha_crypto::HashOf::from_untyped_unchecked(
                iroha_crypto::Hash::prehashed([0xB6; 32]),
            ),
        };
        let payload = encode_canonical(
            &GlobalBeaconPartialSignRequestRefV1 {
                session: norito::core::PayloadRef(public),
                height: 51,
                finalized_chain_anchor: anchor,
                context: iroha_core::beacon::pulse_context_fixture_v1(),
            },
            MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
        )
        .unwrap();
        // Exercise the exact authoritative decode policy before the transport
        // boundary maps its original Norito cause to BrokerError::Protocol.
        // Drop this independent probe before entering the real operation below.
        {
            let budget =
                decode_resource_budget(payload.len(), MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1, policy)
                    .expect("current global beacon operation decode geometry");
            let limits = DecodeLimits::new(
                budget.max_sequence_elements,
                budget.max_blob_bytes,
                budget.max_total_elements,
                budget.max_total_allocated_bytes,
                budget.max_nesting_depth,
            );
            let source_identity = (
                payload.as_ptr(),
                payload.len(),
                iroha_crypto::Hash::new(&payload),
            );
            let (decoded, actual_work) = norito::core::with_decode_limits_measured(limits, || {
                norito::decode_canonical_with_limits::<GlobalBeaconPartialSignRequestWireV1>(
                    &payload, limits,
                )
            });
            let decoded = decoded.unwrap_or_else(|original| {
                panic!(
                    "n{committee} exact broker policy canonical decode failed for {} bytes with {budget:?}: {original:?}",
                    payload.len(),
                )
            });
            // The measurement is actual cumulative codec work. It neither
            // represents allocator residency nor replaces the retained graph
            // charged to the original process pool below.
            assert!(actual_work.total_allocated_bytes() > 0);
            assert!(actual_work.total_allocated_bytes() <= budget.max_total_allocated_bytes);
            assert!(actual_work.total_elements() <= budget.max_total_elements);
            let retired_generic_budget = decode_resource_budget(
                payload.len(),
                MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
                STANDARD_DECODE_POLICY_V1,
            )
            .unwrap();
            if committee == 31 {
                assert!(
                    actual_work.total_allocated_bytes()
                        > retired_generic_budget.max_total_allocated_bytes,
                    "the real maximum graph exceeds generic fixed headroom"
                );
                let retired_limits = DecodeLimits::new(
                    retired_generic_budget.max_sequence_elements,
                    retired_generic_budget.max_blob_bytes,
                    retired_generic_budget.max_total_elements,
                    retired_generic_budget.max_total_allocated_bytes,
                    retired_generic_budget.max_nesting_depth,
                );
                let refusal = norito::decode_canonical_with_limits::<
                    GlobalBeaconPartialSignRequestWireV1,
                >(&payload, retired_limits)
                .expect_err("same maximum graph reproduces the original generic resource refusal");
                assert!(refusal.is_decode_resource_limit());
            } else {
                assert!(
                    budget.max_total_allocated_bytes
                        < retired_generic_budget.max_total_allocated_bytes,
                    "actual small wire geometry reduces the four-seat quota"
                );
            }
            let probe_pool = Arc::new(DecodeResourcePoolV1::new(policy.max_composed_bytes));
            let narrow = DecodeLimits::new(
                limits.max_sequence_elements(),
                limits.max_field_bytes(),
                limits.max_total_elements(),
                actual_work.total_allocated_bytes() - 1,
                limits.max_nesting_depth(),
            );
            assert_eq!(
                norito::core::with_decode_limits_scope(narrow, || {
                    decode_canonical_with_policy_from::<GlobalBeaconPartialSignRequestWireV1>(
                        &payload,
                        MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
                        policy,
                        Arc::clone(&probe_pool),
                    )
                })
                .err(),
                Some(BrokerError::Unavailable),
                "the actual final-prefix caller refusal stays local under the same protocol budget"
            );
            assert_eq!(probe_pool.allocation.reserved_bytes(), 0);
            let retry = decode_canonical_with_policy_from::<GlobalBeaconPartialSignRequestWireV1>(
                &payload,
                MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
                policy,
                Arc::clone(&probe_pool),
            )
            .expect("original full source retries after its enclosing quota retires");
            assert_eq!(&retry.session, public);
            assert_eq!(norito::encode_canonical(&retry).unwrap(), payload);
            drop(retry);
            assert_eq!(probe_pool.allocation.reserved_bytes(), 0);
            let mut corrupted = payload.clone();
            *corrupted.last_mut().unwrap() ^= 1;
            assert_eq!(
                decode_canonical_with_policy_from::<GlobalBeaconPartialSignRequestWireV1>(
                    &corrupted,
                    MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
                    policy,
                    Arc::clone(&probe_pool),
                )
                .err(),
                Some(BrokerError::Protocol),
                "a completed canonical mismatch is still invalid"
            );
            assert_eq!(probe_pool.allocation.reserved_bytes(), 0);
            assert_eq!(
                (
                    payload.as_ptr(),
                    payload.len(),
                    iroha_crypto::Hash::new(&payload)
                ),
                source_identity
            );
            assert_eq!(&decoded.session, public);
            assert_eq!(decoded.height, 51);
            assert_eq!(decoded.finalized_chain_anchor, anchor);
            assert_eq!(
                decoded.context,
                iroha_core::beacon::pulse_context_fixture_v1()
            );
            assert_eq!(
                norito::encode_canonical(&decoded).expect("sole canonical request layout"),
                payload
            );
        }
        let request = make_operation_request(
            TEST_SESSION_ID,
            1,
            wire_binding,
            metadata,
            OPERATION_GLOBAL_BEACON_PARTIAL_SIGN_V1,
            payload,
        )
        .unwrap();
        let admission = DecodeResourceAdmissionV1::acquire_operation_from(
            Arc::clone(&pool),
            OPERATION_GLOBAL_BEACON_PARTIAL_SIGN_V1,
        )
        .unwrap();
        let scope = admission.enter();
        let ingress_started = std::time::Instant::now();
        validate_operation_request_with_session(&request, None, fixture.catalog.network_id())
            .expect("actual ingress authenticates and retains the complete session");
        eprintln!(
            "n{committee} original broker ingress validation: {:?}",
            ingress_started.elapsed()
        );
        let original = admission
            .beacon_session
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .clone();
        assert!(original.belongs_to(&pool.allocation));
        let retained = original.retained_allocation_bytes();
        assert_eq!(
            pool.allocation.reserved_bytes(),
            policy.max_composed_bytes + retained
        );
        let blocker = pool
            .try_acquire(pool.max_bytes - pool.allocation.reserved_bytes())
            .unwrap();
        assert_eq!(pool.allocation.reserved_bytes(), pool.max_bytes);

        let dispatch_started = std::time::Instant::now();
        let result = dispatch_server_operation(&state, &request)
            .expect("the real signer dispatch shares the ingress graph under saturation");
        eprintln!(
            "n{committee} retained broker sign dispatch: {:?}",
            dispatch_started.elapsed()
        );
        let response_started = std::time::Instant::now();
        let response = make_operation_response_scrubbed(
            &request,
            STATUS_OK_V1,
            result,
            fixture.catalog.network_id(),
        )
        .expect("the real response verifier shares that identical authenticated graph");
        validate_operation_response(&request, &response, fixture.catalog.network_id()).unwrap();
        eprintln!(
            "n{committee} retained broker response validation: {:?}",
            response_started.elapsed()
        );
        let final_owner = admission
            .beacon_session
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .clone();
        assert!(final_owner.ptr_eq(&original));
        assert_eq!(pool.allocation.reserved_bytes(), pool.max_bytes);
        let signed = decode_canonical::<GlobalBeaconPartialSignResultWireV1>(
            &response.result,
            MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
        )
        .unwrap();
        let mut verifier = iroha_core::beacon::GlobalThresholdBeaconPulseAggregatorV1::new(
            fixture.session.clone(),
            51,
            anchor,
            iroha_core::beacon::pulse_context_fixture_v1(),
        )
        .unwrap();
        assert!(verifier.accept_partial(signed.partial).unwrap());
        drop(response);
        drop(blocker);
        drop(scope);
        drop(admission);
        assert_eq!(pool.allocation.reserved_bytes(), retained);
        drop(original);
        assert_eq!(pool.allocation.reserved_bytes(), retained);
        drop(final_owner);
        assert_eq!(pool.allocation.reserved_bytes(), 0);
    }
}

#[test]
fn beacon_operation_rejects_rebound_record_and_binding_without_replacing_original() {
    let fixture = consensus_threshold_beacon_broker_test_fixture_v1();
    let public = fixture.session.record();
    let binding = iroha_core::beacon::GlobalThresholdBeaconSessionBindingV1 {
        network_id: public.network_id,
        session_id: public.session_id,
        roster_hash: public.roster_hash,
        transcript_hash: public.transcript_hash,
    };
    let pool = new_test_process_pool();
    let admission = DecodeResourceAdmissionV1::acquire_operation_from(
        Arc::clone(&pool),
        OPERATION_GLOBAL_BEACON_CAPABILITY_ATTEST_V1,
    )
    .unwrap();
    let original = admission.retain_beacon_session(public, &binding).unwrap();
    let retained_total = pool.allocation.reserved_bytes();
    let mut changed = public.clone();
    changed.adaptive_dkg.event_hash[0] ^= 1;
    assert_eq!(changed.session_id, public.session_id);
    assert_eq!(changed.roster_hash, public.roster_hash);
    assert_eq!(changed.transcript_hash, public.transcript_hash);
    assert!(matches!(
        admission.retain_beacon_session(&changed, &binding),
        Err(BrokerError::Rejected)
    ));
    let mut foreign_binding = binding;
    foreign_binding.transcript_hash[0] ^= 1;
    assert!(matches!(
        admission.retain_beacon_session(public, &foreign_binding),
        Err(BrokerError::Rejected)
    ));
    assert_eq!(pool.allocation.reserved_bytes(), retained_total);
    let same = admission
        .retain_beacon_session(&public.clone(), &binding)
        .unwrap();
    assert!(same.ptr_eq(&original));
    assert_eq!(pool.allocation.reserved_bytes(), retained_total);
    drop(same);
    drop(admission);
    assert_eq!(
        pool.allocation.reserved_bytes(),
        original.retained_allocation_bytes()
    );
    drop(original);
    assert_eq!(pool.allocation.reserved_bytes(), 0);
}

#[test]
fn beacon_operation_does_not_retain_failed_authentication_before_exact_retry() {
    let fixture = consensus_threshold_beacon_broker_test_fixture_v1();
    let public = fixture.session.record();
    let binding = iroha_core::beacon::GlobalThresholdBeaconSessionBindingV1 {
        network_id: public.network_id,
        session_id: public.session_id,
        roster_hash: public.roster_hash,
        transcript_hash: public.transcript_hash,
    };
    let pool = new_test_process_pool();
    let admission = DecodeResourceAdmissionV1::acquire_operation_from(
        Arc::clone(&pool),
        OPERATION_GLOBAL_BEACON_CAPABILITY_ATTEST_V1,
    )
    .unwrap();
    let before = pool.allocation.reserved_bytes();
    let mut changed = public.clone();
    changed.adaptive_dkg.event_hash[0] ^= 1;
    assert!(matches!(
        admission.retain_beacon_session(&changed, &binding),
        Err(BrokerError::Rejected)
    ));
    assert!(admission.beacon_session.lock().unwrap().is_none());
    assert_eq!(pool.allocation.reserved_bytes(), before);
    let exact = admission.retain_beacon_session(public, &binding).unwrap();
    assert!(exact.belongs_to(&pool.allocation));
    assert_eq!(exact.record(), public);
    drop(admission);
    assert_eq!(
        pool.allocation.reserved_bytes(),
        exact.retained_allocation_bytes()
    );
    drop(exact);
    assert_eq!(pool.allocation.reserved_bytes(), 0);
}

#[test]
fn global_beacon_schema_work_quota_scales_wire_and_preserves_every_absolute_and_original_pool_cap()
{
    let policy = GLOBAL_BEACON_DECODE_POLICY_V1;
    assert_eq!(policy.allocation_wire_passes, 5 + 6 + 2);
    assert!(policy.allocation_headroom_bytes > 0);
    assert!(policy.allocation_headroom_bytes < STANDARD_DECODE_POLICY_V1.allocation_headroom_bytes);
    assert_eq!(
        policy.max_sequence_elements,
        STANDARD_DECODE_POLICY_V1.max_sequence_elements
    );
    assert_eq!(
        policy.max_blob_bytes,
        STANDARD_DECODE_POLICY_V1.max_blob_bytes
    );
    assert_eq!(
        policy.max_total_elements,
        STANDARD_DECODE_POLICY_V1.max_total_elements
    );
    assert_eq!(
        policy.max_total_allocated_bytes,
        STANDARD_DECODE_POLICY_V1.max_total_allocated_bytes
    );
    assert_eq!(
        policy.max_nesting_depth,
        STANDARD_DECODE_POLICY_V1.max_nesting_depth
    );
    assert_eq!(
        policy.max_composed_bytes,
        STANDARD_DECODE_POLICY_V1.max_composed_bytes
    );
    assert_eq!(
        policy.max_cumulative_bytes,
        STANDARD_DECODE_POLICY_V1.max_cumulative_bytes
    );
    for operation in 0..=u16::MAX {
        if !operation_is_known(operation) {
            continue;
        }
        if matches!(
            operation,
            OPERATION_GLOBAL_BEACON_PARTIAL_SIGN_V1
                | OPERATION_GLOBAL_BEACON_CAPABILITY_ATTEST_V1
                | OPERATION_GLOBAL_BEACON_SEAT_READINESS_V1
        ) {
            assert_eq!(operation_decode_policy(operation), policy);
            assert_eq!(
                operation_semantic_frame_limit(operation),
                MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1
            );
        } else {
            assert_eq!(
                operation_decode_policy(operation).allocation_wire_passes,
                1,
                "other existing operation profiles retain their original single wire pass"
            );
        }
    }
    for bytes in [1, 1024, MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1] {
        let budget =
            decode_resource_budget(bytes, MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1, policy).unwrap();
        assert_eq!(
            budget.max_total_allocated_bytes,
            (bytes * GLOBAL_BEACON_DECODE_PROFILE_V1.allocation_wire_passes
                + GLOBAL_BEACON_DECODE_PROFILE_V1.allocation_intrinsic_bytes)
                .min(STANDARD_MAX_DECODE_ALLOCATION_BYTES_V1)
        );
        assert!(budget.max_total_allocated_bytes <= STANDARD_MAX_DECODE_ALLOCATION_BYTES_V1);
        assert_eq!(
            budget.composed_charge_bytes,
            bytes + budget.max_total_allocated_bytes
        );
    }
    assert_eq!(
        decode_resource_budget(
            MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1 + 1,
            MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
            policy
        ),
        Err(BrokerError::Protocol)
    );
    let pool = Arc::new(DecodeResourcePoolV1::new(policy.max_composed_bytes));
    let occupied = pool.try_acquire(1).unwrap();
    assert_eq!(
        DecodeResourceAdmissionV1::acquire_operation_from(
            Arc::clone(&pool),
            OPERATION_GLOBAL_BEACON_PARTIAL_SIGN_V1,
        )
        .err(),
        Some(BrokerError::Unavailable),
        "genuine original pool saturation remains retryable"
    );
    assert_eq!(pool.allocation.reserved_bytes(), 1);
    drop(occupied);
    let admitted = DecodeResourceAdmissionV1::acquire_operation_from(
        Arc::clone(&pool),
        OPERATION_GLOBAL_BEACON_PARTIAL_SIGN_V1,
    )
    .unwrap();
    assert_eq!(pool.allocation.reserved_bytes(), policy.max_composed_bytes);
    drop(admitted);
    assert_eq!(pool.allocation.reserved_bytes(), 0);
}
