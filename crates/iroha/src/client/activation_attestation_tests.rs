// HTTP transport fixtures use a current result-only genesis plus real BLS node signatures.
// Full current quorum, ancestry and transaction checks live in the model and real-node tests.
fn current_finality_fixture() -> (
    iroha_data_model::sumeragi_finality::SumeragiFinalityProof,
    iroha_data_model::sumeragi_finality::SumeragiFinalityVerifier,
    KeyPair,
) {
    use iroha_data_model::{
        sumeragi_finality::SumeragiFinalityVerifier,
        testing::native_finality::NativeFinalityFixture,
    };
    let native = NativeFinalityFixture::start("sdk-current-finality");
    let proof = native.genesis_proof().clone();
    let verifier =
        SumeragiFinalityVerifier::new(native.genesis(), native.chain_id(), proof.committee.clone())
            .unwrap();
    let node = (1..=4)
        .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
        .find(|key| key.public_key() == &proof.committee[0].public_key)
        .unwrap();
    (proof, verifier, node)
}
fn current_finality_client() -> Client {
    let mut client = client_with_base_url(base_url());
    client.network_id =
        NetworkId::from_genesis_hash(current_finality_fixture().0.block_header.hash());
    client
}

#[test]
fn provider_discovery_reader_uses_exact_bounded_norito_request_and_never_trusts_a_response_root() {
    use iroha_data_model::{
        sorafs::{
            capacity::ProviderId, provider_admission::discovery::MAX_PROVIDER_DISCOVERY_BYTES_V1,
        },
        testing::native_finality::NativeFinalityFixture,
    };
    let mut native = NativeFinalityFixture::start("sdk-provider-discovery");
    let block = native.block_with_submitted_work(native.next_header());
    let proof = native.certify(block);
    let verified = native.verifier().verify_retained_decision(&proof).unwrap();
    let mut client = client_with_base_url(base_url());
    client.network_id = native.network_id();
    client.headers.insert(
        "x-api-token".into(),
        "provider-discovery-token-fixture".into(),
    );
    let provider = ProviderId::new([0xab; 32]);
    let (result, request) = capture_request(
        mk_response(StatusCode::OK, vec![1, 2, 3], Some(APPLICATION_NORITO)),
        |transport| {
            let client = client.clone().with_test_http_transport(transport);
            mark_data_model_compatible(&client);
            client.get_provider_discovery(
                provider,
                Hash::new(b"independently qualified schema"),
                &verified,
                1,
            )
        },
    );
    assert!(result.is_err());
    assert_eq!(
        request.url.path(),
        format!(
            "/v1/sorafs/providers/{}/discovery/2",
            hex::encode(provider.as_bytes())
        )
    );
    assert_eq!(request.max_response_bytes, MAX_PROVIDER_DISCOVERY_BYTES_V1);
    assert_eq!(
        request
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("accept"))
            .map(|(_, value)| value.as_str()),
        Some(APPLICATION_NORITO)
    );
    assert_eq!(
        request
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("x-api-token"))
            .map(|(_, value)| value.as_str()),
        Some("provider-discovery-token-fixture")
    );
    assert!(
        client
            .get_provider_discovery(ProviderId::new([0; 32]), Hash::new(b"schema"), &verified, 1)
            .is_err()
    );
    client.network_id = NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
        Hash::new(b"foreign provider network genesis"),
    ));
    assert!(
        client
            .get_provider_discovery(provider, Hash::new(b"schema"), &verified, 1)
            .is_err()
    );
}
#[test]
fn account_read_discovery_uses_bounded_parent_transport_and_rejects_unverified_data() {
    use iroha_data_model::{
        sorafs::{
            capacity::ProviderId, provider_admission::discovery::MAX_PROVIDER_DISCOVERY_BYTES_V1,
        },
        testing::native_finality::NativeFinalityFixture,
    };
    let mut native = NativeFinalityFixture::start("sdk-account-read-discovery");
    let block = native.block_with_submitted_work(native.next_header());
    let proof = native.certify(block);
    let verified = native.verifier().verify_retained_decision(&proof).unwrap();
    let mut client = client_with_base_url(base_url());
    client.network_id = native.network_id();
    let provider = ProviderId::new([0xbc; 32]);
    for status in [StatusCode::OK, StatusCode::SERVICE_UNAVAILABLE] {
        let (result, request) = capture_request(
            mk_response(status, vec![1, 2, 3], Some(APPLICATION_NORITO)),
            |transport| {
                let client = client.clone().with_test_http_transport(transport);
                mark_data_model_compatible(&client);
                client.get_account_read_provider_discovery(
                    provider,
                    Hash::new(b"qualified schema"),
                    &verified,
                    1,
                )
            },
        );
        assert!(result.is_err());
        assert_eq!(
            request.url.path(),
            format!(
                "/v1/sorafs/providers/{}/discovery/2",
                hex::encode(provider.as_bytes())
            )
        );
        assert_eq!(request.max_response_bytes, MAX_PROVIDER_DISCOVERY_BYTES_V1);
    }
    assert!(
        client
            .get_account_read_provider_discovery(
                ProviderId::new([0; 32]),
                Hash::new(b"schema"),
                &verified,
                1
            )
            .is_err()
    );
    client.network_id = NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
        Hash::new(b"foreign registry"),
    ));
    assert!(
        client
            .get_account_read_provider_discovery(provider, Hash::new(b"schema"), &verified, 1)
            .is_err()
    );
}

fn stream_token_custody_control_fixture() -> (
    Client,
    iroha_data_model::sorafs::capacity::ProviderId,
    sorafs_manifest::signer::custody::SignerCustodyBindingV1,
    iroha_data_model::sumeragi_finality::VerifiedSumeragiBlock,
) {
    use iroha_data_model::{
        sorafs::capacity::ProviderId, testing::native_finality::NativeFinalityFixture,
    };
    use sorafs_manifest::signer::{
        custody::SignerCustodyBindingV1,
        protocol::{SignerKeyAlgorithmV1, SignerPurposeBindingV1, SignerRoleV1},
    };
    let mut native = NativeFinalityFixture::start("sdk-stream-token-control");
    let block = native.block_with_submitted_work(native.next_header());
    let proof = native.certify(block);
    let verified = native.verifier().verify_retained_decision(&proof).unwrap();
    let mut client = client_with_base_url(base_url());
    client.chain = native.chain_id().parse().unwrap();
    client.network_id = native.network_id();
    let provider = ProviderId::new([0xbd; 32]);
    let key = KeyPair::from_seed(vec![0x65; 32], Algorithm::Ed25519);
    let binding = SignerCustodyBindingV1 {
        chain_id: client.chain.to_string(),
        network_id: *client.network_id.as_bytes(),
        runtime_handle: "software://storage/token".into(),
        key_handle: "software://storage/token/key".into(),
        service_id: "storage-token-signer".into(),
        administrator_id: "storage-token-admin".into(),
        role: SignerRoleV1::StreamToken,
        purpose: SignerPurposeBindingV1::StreamToken {
            provider_id: *provider.as_bytes(),
        },
        algorithm: SignerKeyAlgorithmV1::Ed25519,
        public_key: key.public_key().clone(),
        key_revision: 1,
        policy_revision: 1,
        policy_digest: [9; 32],
    };
    binding.validate().unwrap();
    (client, provider, binding, verified)
}

#[test]
fn stream_token_custody_control_uses_bounded_discovery_and_rejects_unverified_responses() {
    use iroha_data_model::sorafs::provider_admission::discovery::MAX_PROVIDER_DISCOVERY_BYTES_V1;
    let (client, provider, binding, verified) = stream_token_custody_control_fixture();
    for response in [
        mk_response(StatusCode::OK, vec![1, 2, 3], Some(APPLICATION_NORITO)),
        mk_response(
            StatusCode::SERVICE_UNAVAILABLE,
            vec![1, 2, 3],
            Some(APPLICATION_NORITO),
        ),
        mk_response(StatusCode::OK, b"{}".to_vec(), Some(APPLICATION_JSON)),
        mk_response(
            StatusCode::OK,
            vec![0; MAX_PROVIDER_DISCOVERY_BYTES_V1 + 1],
            Some(APPLICATION_NORITO),
        ),
    ] {
        let (result, request) = capture_request(response, |transport| {
            let client = client.clone().with_test_http_transport(transport);
            mark_data_model_compatible(&client);
            client.get_stream_token_custody_control(
                provider,
                &binding,
                Hash::new(b"independently qualified schema"),
                &verified,
                1,
            )
        });
        assert!(result.is_err());
        assert_eq!(
            request.url.path(),
            format!(
                "/v1/sorafs/providers/{}/discovery/2",
                hex::encode(provider.as_bytes())
            )
        );
        assert_eq!(request.max_response_bytes, MAX_PROVIDER_DISCOVERY_BYTES_V1);
        assert_eq!(
            request
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("accept"))
                .map(|(_, value)| value.as_str()),
            Some(APPLICATION_NORITO)
        );
    }
}

#[test]
fn stream_token_custody_control_rejects_independent_scope_mismatch_before_dispatch() {
    use iroha_data_model::sorafs::capacity::ProviderId;
    use sorafs_manifest::signer::protocol::{SignerPurposeBindingV1, SignerRoleV1};
    let (client, provider, binding, verified) = stream_token_custody_control_fixture();
    let mut mutants = Vec::new();
    let mut changed = binding.clone();
    changed.chain_id = "another-chain".into();
    mutants.push(changed);
    let mut changed = binding.clone();
    changed.network_id = [0x42; 32];
    mutants.push(changed);
    let mut changed = binding.clone();
    changed.purpose = SignerPurposeBindingV1::StreamToken {
        provider_id: [0x43; 32],
    };
    mutants.push(changed);
    let mut changed = binding.clone();
    changed.role = SignerRoleV1::ProofOutcome;
    mutants.push(changed);
    let mut changed = binding.clone();
    changed.key_revision = 0;
    mutants.push(changed);
    with_mock_http(
        |_| panic!("invalid independent custody binding must not dispatch"),
        |transport| {
            let client = client.with_test_http_transport(transport);
            mark_data_model_compatible(&client);
            for changed in &mutants {
                assert!(
                    client
                        .get_stream_token_custody_control(
                            provider,
                            changed,
                            Hash::new(b"schema"),
                            &verified,
                            1,
                        )
                        .is_err()
                );
            }
            assert!(
                client
                    .get_stream_token_custody_control(
                        ProviderId::new([0; 32]),
                        &binding,
                        Hash::new(b"schema"),
                        &verified,
                        1,
                    )
                    .is_err()
            );
            let mut foreign = client.clone();
            foreign.network_id = NetworkId::from_genesis_hash(
                iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"other genesis")),
            );
            let mut foreign_binding = binding.clone();
            foreign_binding.network_id = *foreign.network_id.as_bytes();
            assert!(
                foreign
                    .get_stream_token_custody_control(
                        provider,
                        &foreign_binding,
                        Hash::new(b"schema"),
                        &verified,
                        1,
                    )
                    .is_err()
            );
        },
    );
}

#[test]
fn stream_token_custody_control_expired_deadline_does_not_dispatch() {
    let (client, provider, binding, verified) = stream_token_custody_control_fixture();
    with_mock_http(
        |_| panic!("expired custody-control read must not dispatch"),
        |transport| {
            let client = client
                .with_test_http_transport(transport)
                .with_request_deadline(std::time::Instant::now());
            mark_data_model_compatible(&client);
            assert!(
                client
                    .get_stream_token_custody_control(
                        provider,
                        &binding,
                        Hash::new(b"schema"),
                        &verified,
                        1,
                    )
                    .is_err()
            );
        },
    );
}

fn client_attestation_fixture() -> iroha_data_model::sumeragi_finality::SumeragiFinalityAttestation
{
    use iroha_data_model::sumeragi_finality::*;
    let (proof, verifier, signer) = current_finality_fixture();
    let node_id = iroha_model_base::peer::PeerId::new(signer.public_key().clone());
    let body = SumeragiFinalityAttestationBody {
        observed_at_unix_ms: 1_000_000,
        challenge: [17; 32],
        network_id: NetworkId::from_genesis_hash(proof.block_header.hash()),
        node_fingerprint: Hash::new(norito::codec::Encode::encode(&node_id)),
        node_id,
        build_fingerprint: Hash::new(b"build"),
        config_fingerprint: Hash::new(b"config"),
        genesis_block_hash: proof.block_header.hash(),
        genesis_finality_proof: proof.clone(),
        status: iroha_data_model::sumeragi::SumeragiStatus {
            protocol_version: iroha_data_model::sumeragi::PROTOCOL_VERSION,
            config_fingerprint: Hash::new(b"config"),
            beacon_horizon: None,
            instance: verifier.instance().0,
            height: 2,
            view: 0,
            stage: 0,
            leader: None,
            proxy_tail: None,
            high_qc_view: None,
            level: 0,
            start_level: 0,
            t_retx_ms: 100,
            committed_height: 1,
            applied_height: 1,
            awaiting: false,
            signer: Some(signer.public_key().clone()),
            unanchored: false,
            abstaining: false,
            halted: None,
            footprint: iroha_data_model::sumeragi::SumeragiFootprint::default(),
        },
        finality_proof: proof,
    };
    let signature =
        iroha_crypto::SignatureOf::try_from_hash(signer.private_key(), body.signing_hash())
            .unwrap();
    let value = SumeragiFinalityAttestation { body, signature };
    value.verify().unwrap();
    value
}

#[test]
fn bridge_finality_attestation_reader_binds_exact_request_headers_and_signed_body() {
    let attestation = client_attestation_fixture();
    let mut client = current_finality_client();
    client
        .headers
        .insert("Accept".to_owned(), APPLICATION_JSON.to_owned());
    client
        .headers
        .insert("Content-Type".to_owned(), APPLICATION_JSON.to_owned());
    client
        .headers
        .insert("x-iroha-finality-challenge".to_owned(), "stale".to_owned());
    let response = mk_response(
        StatusCode::OK,
        norito::to_bytes(&attestation).expect("wire"),
        Some(APPLICATION_NORITO),
    );
    let (actual, request) = capture_request(response, |transport| {
        let client = client.with_test_http_transport(transport);
        mark_data_model_compatible(&client);
        client.get_sumeragi_finality_attestation(
            NonZeroU64::new(1).unwrap(),
            attestation.body.challenge,
            &attestation.body.node_id,
        )
    });
    let actual = actual.expect("authenticated attestation");
    assert_eq!(actual.attestation(), &attestation);
    assert_eq!(actual.into_attestation(), attestation);
    assert_eq!(request.method, HttpMethod::GET);
    assert_eq!(request.url.path(), "/v1/bridge/finality/attestation/1");
    assert!(request.url.query().is_none());
    assert!(request.body.is_empty());
    assert_eq!(
        request.max_response_bytes,
        SUMERAGI_FINALITY_RESPONSE_MAX_BYTES
    );
    assert_single_accept_header(&request, APPLICATION_NORITO);
    let challenges = request
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("x-iroha-finality-challenge"))
        .map(|(_, value)| value.as_str())
        .collect::<Vec<_>>();
    assert_eq!(challenges, vec![hex::encode(attestation.body.challenge)]);
    assert!(
        request
            .headers
            .iter()
            .all(|(name, _)| !name.eq_ignore_ascii_case("content-type"))
    );
}

#[test]
fn bridge_finality_attestation_reader_rejects_wrong_bindings_and_invalid_http_body() {
    let attestation = client_attestation_fixture();
    let client = current_finality_client();
    let wire = norito::to_bytes(&attestation).expect("wire");
    let (zero, requests) = capture_requests(
        mk_response(StatusCode::OK, wire.clone(), Some(APPLICATION_NORITO)),
        |transport| {
            client
                .clone()
                .with_test_http_transport(transport)
                .get_sumeragi_finality_attestation(
                    NonZeroU64::new(1).unwrap(),
                    [0; 32],
                    &attestation.body.node_id,
                )
        },
    );
    assert!(zero.is_err());
    assert!(
        requests.is_empty(),
        "zero challenge must fail before compatibility or HTTP"
    );
    let wrong_key =
        KeyPair::try_from_seed(vec![94; 32], Algorithm::BlsNormal).expect("other reporter");
    let wrong_node = iroha_model_base::peer::PeerId::new(wrong_key.public_key().clone());
    for (height, challenge, node) in [
        (
            2,
            attestation.body.challenge,
            attestation.body.node_id.clone(),
        ),
        (1, [18; 32], attestation.body.node_id.clone()),
        (1, attestation.body.challenge, wrong_node),
    ] {
        let (result, _) = capture_request(
            mk_response(StatusCode::OK, wire.clone(), Some(APPLICATION_NORITO)),
            |transport| {
                let client = client.clone().with_test_http_transport(transport);
                mark_data_model_compatible(&client);
                client.get_sumeragi_finality_attestation(
                    NonZeroU64::new(height).unwrap(),
                    challenge,
                    &node,
                )
            },
        );
        assert!(result.is_err(), "wrong request binding must fail");
    }
    let mut altered = attestation.clone();
    altered.body.build_fingerprint = Hash::new(b"tampered unsigned status");
    let mut trailing = wire.clone();
    trailing.push(0);
    let mut wrong_network_client = client.clone();
    wrong_network_client.network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
        Hash::new(b"foreign network"),
    ));
    let (result, _) = capture_request(
        mk_response(StatusCode::OK, wire.clone(), Some(APPLICATION_NORITO)),
        |transport| {
            let client = wrong_network_client.with_test_http_transport(transport);
            mark_data_model_compatible(&client);
            client.get_sumeragi_finality_attestation(
                NonZeroU64::new(1).unwrap(),
                attestation.body.challenge,
                &attestation.body.node_id,
            )
        },
    );
    assert!(result.is_err());
    for response in [
        mk_response(
            StatusCode::NOT_FOUND,
            wire.clone(),
            Some(APPLICATION_NORITO),
        ),
        mk_response(StatusCode::OK, wire, Some(APPLICATION_JSON)),
        mk_response(StatusCode::OK, trailing, Some(APPLICATION_NORITO)),
        mk_response(StatusCode::OK, Vec::new(), Some(APPLICATION_NORITO)),
        mk_response(
            StatusCode::OK,
            norito::to_bytes(&altered).expect("tampered wire"),
            Some(APPLICATION_NORITO),
        ),
    ] {
        let (result, _) = capture_request(response, |transport| {
            let client = client.clone().with_test_http_transport(transport);
            mark_data_model_compatible(&client);
            client.get_sumeragi_finality_attestation(
                NonZeroU64::new(1).unwrap(),
                attestation.body.challenge,
                &attestation.body.node_id,
            )
        });
        assert!(result.is_err(), "invalid response must fail");
    }
}

fn client_tip_progress_fixture()
-> iroha_torii_shared::bridge_finality::BridgeFinalityAttestationTipMismatchV1 {
    let key = KeyPair::try_from_seed(vec![96; 32], Algorithm::BlsNormal).expect("reporter key");
    iroha_torii_shared::bridge_finality::BridgeFinalityAttestationTipMismatchV1 {
        requested_height: 10,
        applied_height: 9,
        status_height: 10,
        challenge: [17; 32],
        node_id: iroha_model_base::peer::PeerId::new(key.public_key().clone()),
        network_id: current_finality_client().network_id,
    }
}

fn client_tip_progress_envelope(
    progress: iroha_torii_shared::bridge_finality::BridgeFinalityAttestationTipMismatchV1,
) -> iroha_torii_shared::ErrorEnvelope {
    iroha_torii_shared::bridge_attestation::FinalityAttestationFailure {
        height: progress.requested_height,
        challenge: progress.challenge,
        reason:
            iroha_torii_shared::bridge_attestation::FinalityAttestationFailureReason::TipChanged,
        tip_mismatch: Some(progress),
    }
    .into_error_envelope()
}

#[test]
fn bridge_finality_attestation_reader_preserves_only_bound_typed_tip_progress() {
    for (requested, applied, status) in [(10, 9, 10), (9, 10, 10), (10, 10, 9)] {
        let mut progress = client_tip_progress_fixture();
        progress.requested_height = requested;
        progress.applied_height = applied;
        progress.status_height = status;
        let response = mk_response(
            StatusCode::CONFLICT,
            norito::to_bytes(&client_tip_progress_envelope(progress.clone())).expect("wire"),
            Some(APPLICATION_NORITO),
        );
        let (result, requests) = capture_requests(response, |transport| {
            let client = current_finality_client().with_test_http_transport(transport);
            mark_data_model_compatible(&client);
            client.get_sumeragi_finality_attestation(
                NonZeroU64::new(requested).unwrap(),
                progress.challenge,
                &progress.node_id,
            )
        });
        assert_eq!(requests.len(), 1, "one-shot reader does not poll");
        assert_eq!(
            requests[0].url.path(),
            format!("/v1/bridge/finality/attestation/{requested}")
        );
        let error = result.expect_err("a changing tip is not finality evidence");
        let typed = error
            .downcast_ref::<BridgeFinalityAttestationTipMismatch>()
            .expect("exact typed progress");
        assert_eq!(typed.response(), &progress);
        assert!(typed.to_string().contains("finality tip is changing"));
    }
}

#[test]
fn bridge_finality_attestation_reader_rejects_malformed_or_unbound_tip_progress() {
    let valid = client_tip_progress_fixture();
    let mut cases = Vec::new();
    let mut changed = valid.clone();
    changed.requested_height = 11;
    cases.push(changed);
    let mut changed = valid.clone();
    changed.challenge = [18; 32];
    cases.push(changed);
    let mut changed = valid.clone();
    changed.challenge = [0; 32];
    cases.push(changed);
    let mut changed = valid.clone();
    changed.node_id = iroha_model_base::peer::PeerId::new(
        KeyPair::try_from_seed(vec![97; 32], Algorithm::BlsNormal)
            .expect("other reporter")
            .public_key()
            .clone(),
    );
    cases.push(changed);
    let mut changed = valid.clone();
    changed.network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"foreign finality progress network",
    )));
    cases.push(changed);
    for (requested, applied, status) in [(0, 9, 10), (10, 0, 10), (10, 9, 0), (10, 10, 10)] {
        let mut changed = valid.clone();
        changed.requested_height = requested;
        changed.applied_height = applied;
        changed.status_height = status;
        cases.push(changed);
    }
    for progress in cases {
        let response = mk_response(
            StatusCode::CONFLICT,
            norito::to_bytes(&client_tip_progress_envelope(progress)).expect("wire"),
            Some(APPLICATION_NORITO),
        );
        let (result, _) = capture_request(response, |transport| {
            let client = current_finality_client().with_test_http_transport(transport);
            mark_data_model_compatible(&client);
            client.get_sumeragi_finality_attestation(
                NonZeroU64::new(valid.requested_height).unwrap(),
                valid.challenge,
                &valid.node_id,
            )
        });
        let error = result.expect_err("malformed or foreign progress must fail");
        assert!(
            error
                .downcast_ref::<BridgeFinalityAttestationTipMismatch>()
                .is_none()
        );
    }
}

#[test]
fn bridge_finality_attestation_reader_rejects_untyped_or_noncanonical_progress_http() {
    use iroha_torii_shared::bridge_attestation::{
        FINALITY_ATTESTATION_FAILURE_MAX_BYTES, FinalityAttestationFailureReason as Reason,
    };
    let progress = client_tip_progress_fixture();
    let envelope = client_tip_progress_envelope(progress.clone());
    let wire = norito::to_bytes(&envelope).expect("wire");
    let mut wrong_code = envelope.clone();
    wrong_code.code = "query_validation_failed".into();
    let mut missing_details = envelope.clone();
    missing_details.details = None;
    let mut wrong_details = envelope.clone();
    wrong_details
        .details
        .as_mut()
        .unwrap()
        .finality_attestation_failure
        .as_mut()
        .unwrap()
        .reason = Reason::ConflictingState;
    let mut mixed_details = envelope.clone();
    mixed_details.details.as_mut().unwrap().reject_code = Some("invalid_finality_proof".into());
    let mut trailing = wire.clone();
    trailing.push(0);
    let mut duplicate_type =
        mk_response(StatusCode::CONFLICT, wire.clone(), Some(APPLICATION_NORITO));
    duplicate_type.headers_mut().append(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static(APPLICATION_NORITO),
    );
    let mut responses = vec![duplicate_type];
    for status in [
        StatusCode::NOT_FOUND,
        StatusCode::SERVICE_UNAVAILABLE,
        StatusCode::OK,
    ] {
        responses.push(mk_response(status, wire.clone(), Some(APPLICATION_NORITO)));
    }
    for body in [
        Vec::new(),
        trailing,
        vec![0; FINALITY_ATTESTATION_FAILURE_MAX_BYTES + 1],
        norito::to_bytes(&wrong_code).expect("wire"),
        norito::to_bytes(&missing_details).expect("wire"),
        norito::to_bytes(&wrong_details).expect("wire"),
        norito::to_bytes(&mixed_details).expect("wire"),
        b"query_validation_failed: Query not found in the live query store.".to_vec(),
        norito::to_bytes(&iroha_torii_shared::ErrorEnvelope::new(
            "bridge_finality_attestation_tip_mismatch",
            "retired envelope",
        ))
        .expect("obsolete envelope is negative data"),
    ] {
        responses.push(mk_response(
            StatusCode::CONFLICT,
            body,
            Some(APPLICATION_NORITO),
        ));
    }
    for content_type in [
        None,
        Some(APPLICATION_JSON),
        Some("application/x-norito; arbitrary=1"),
    ] {
        responses.push(mk_response(
            StatusCode::CONFLICT,
            wire.clone(),
            content_type,
        ));
    }
    responses.push(mk_response(
        StatusCode::CONFLICT,
        norito::json::to_json(&envelope).expect("json").into_bytes(),
        Some(APPLICATION_JSON),
    ));
    for response in responses {
        let (result, _) = capture_request(response, |transport| {
            let client = current_finality_client().with_test_http_transport(transport);
            mark_data_model_compatible(&client);
            client.get_sumeragi_finality_attestation(
                NonZeroU64::new(progress.requested_height).unwrap(),
                progress.challenge,
                &progress.node_id,
            )
        });
        let error = result.expect_err("only canonical bound HTTP409 is progress");
        assert!(
            error
                .downcast_ref::<BridgeFinalityAttestationTipMismatch>()
                .is_none()
        );
    }
}

fn rejected_next_bridge_finality_response(
    client: &Client,
    height: NonZeroU64,
    verifier: &mut iroha_data_model::sumeragi_finality::SumeragiFinalityVerifier,
    response: HttpResponse<Vec<u8>>,
) -> eyre::Report {
    capture_request(response, |mock_transport| {
        let client = client
            .clone()
            .with_test_http_transport(mock_transport.clone());
        mark_data_model_compatible(&client);

        client.get_next_sumeragi_finality_proof(height, verifier)
    })
    .0
    .expect_err("bridge finality response must fail")
}

#[test]
fn bridge_finality_reader_retries_only_backpressure_within_original_deadline() {
    let (successor, mut verifier, _) = current_finality_fixture();
    let expected = successor.clone();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let observations = Arc::clone(&calls);
    let started = std::time::Instant::now();
    let deadline = started + Duration::from_secs(10);
    let result = with_mock_http(
        move |request| {
            let mut observations = observations.lock().expect("observations");
            observations.push((std::time::Instant::now(), request));
            if observations.len() == 1 {
                let mut response = empty_response(StatusCode::TOO_MANY_REQUESTS);
                response
                    .headers_mut()
                    .insert("retry-after", "1".parse().unwrap());
                Ok(response)
            } else {
                Ok(norito_response(StatusCode::OK, &expected))
            }
        },
        |transport| {
            let client = current_finality_client()
                .with_test_http_transport(transport)
                .with_request_deadline(deadline);
            mark_data_model_compatible(&client);
            client.get_next_sumeragi_finality_proof(successor.block_header.height(), &mut verifier)
        },
    )
    .expect("bounded retry accepts exact successor");
    assert_eq!(result, successor);
    let calls = calls.lock().expect("observations");
    assert_eq!(calls.len(), 2);
    assert!(calls[1].0.duration_since(calls[0].0) >= Duration::from_secs(1));
    for (_, request) in calls.iter() {
        assert_eq!(request.method, HttpMethod::GET);
        assert_eq!(request.url.path(), "/v1/bridge/finality/1");
        assert!(request.timeout.unwrap() <= deadline.duration_since(started));
    }
    assert!(calls[1].1.timeout.unwrap() < calls[0].1.timeout.unwrap());
}

#[test]
fn bridge_finality_reader_rejects_unbounded_or_invalid_backpressure_without_advancing() {
    let (successor, mut verifier, _) = current_finality_fixture();
    let height = successor.block_header.height();
    // A missing operation deadline, malformed/duplicate hints, an excessive delay,
    // and non-429 errors must all make exactly one dispatch without changing trust.
    for (status, hints, budget) in [
        (StatusCode::TOO_MANY_REQUESTS, vec!["0"], None),
        (
            StatusCode::TOO_MANY_REQUESTS,
            vec!["-1"],
            Some(Duration::from_secs(5)),
        ),
        (
            StatusCode::TOO_MANY_REQUESTS,
            vec!["0", "1"],
            Some(Duration::from_secs(5)),
        ),
        (
            StatusCode::TOO_MANY_REQUESTS,
            vec!["18446744073709551615"],
            Some(Duration::from_secs(5)),
        ),
        (
            StatusCode::TOO_MANY_REQUESTS,
            vec!["1"],
            Some(Duration::from_millis(500)),
        ),
        (
            StatusCode::UNAUTHORIZED,
            vec!["0"],
            Some(Duration::from_secs(5)),
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            vec!["0"],
            Some(Duration::from_secs(5)),
        ),
    ] {
        let mut response = empty_response(status);
        for hint in hints {
            response
                .headers_mut()
                .append("retry-after", hint.parse().unwrap());
        }
        let (result, _) = capture_request(response, |transport| {
            let client = current_finality_client().with_test_http_transport(transport);
            let client = budget.map_or_else(
                || client.clone(),
                |budget| client.with_request_deadline(std::time::Instant::now() + budget),
            );
            mark_data_model_compatible(&client);
            client.get_next_sumeragi_finality_proof(height, &mut verifier)
        });
        assert!(result.is_err(), "{status} must fail");
    }
    let actual = capture_request(norito_response(StatusCode::OK, &successor), |transport| {
        let client = current_finality_client().with_test_http_transport(transport);
        mark_data_model_compatible(&client);
        client.get_next_sumeragi_finality_proof(height, &mut verifier)
    })
    .0
    .expect("all failed reads retained the original chain anchor");
    assert_eq!(actual, successor);
}

#[test]
fn activation_evidence_backpressure_preserves_challenge_and_response_bounds() {
    for hint in [None, Some("0")] {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let observations = Arc::clone(&calls);
        let challenge = [0x73; 32];
        with_mock_http(
            move |request| {
                let mut observations = observations.lock().unwrap();
                observations.push(request);
                if observations.len() == 1 {
                    let mut response = empty_response(StatusCode::TOO_MANY_REQUESTS);
                    if let Some(hint) = hint {
                        response
                            .headers_mut()
                            .insert("retry-after", hint.parse().unwrap());
                    }
                    Ok(response)
                } else {
                    Ok(empty_response(StatusCode::CONFLICT))
                }
            },
            |transport| {
                let client = current_finality_client()
                    .with_test_http_transport(transport)
                    .with_request_deadline(std::time::Instant::now() + Duration::from_secs(5));
                let result = client
                    .send_activation_evidence_read(
                        "/v1/bridge/finality/2/attestation",
                        2048,
                        Some(challenge),
                        ActivationEvidenceReadAuth::Public,
                    )
                    .expect("read-only retry");
                assert_eq!(result.status(), StatusCode::CONFLICT);
            },
        );
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        for request in calls.iter() {
            assert_eq!(request.method, HttpMethod::GET);
            assert_eq!(request.max_response_bytes, 2048);
            let challenges: Vec<_> = request
                .headers
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("x-iroha-finality-challenge"))
                .collect();
            assert_eq!(challenges.len(), 1);
            assert_eq!(challenges[0].1, hex::encode(challenge));
        }
    }
}

#[test]
fn bridge_finality_next_reader_response_contract_failures_do_not_advance() {
    let client = current_finality_client();

    let (successor, mut verifier, _) = current_finality_fixture();
    let height = successor.block_header.height();
    let body = norito::to_bytes(&successor).expect("encode canonical successor proof");

    let error = rejected_next_bridge_finality_response(
        &client,
        height,
        &mut verifier,
        mk_response(
            StatusCode::BAD_GATEWAY,
            b"upstream failure".to_vec(),
            Some(APPLICATION_NORITO),
        ),
    );
    assert!(error.to_string().contains("sumeragi.finality_proof.read"));

    let error = rejected_next_bridge_finality_response(
        &client,
        height,
        &mut verifier,
        mk_response(StatusCode::OK, body.clone(), Some(APPLICATION_JSON)),
    );
    assert!(error.to_string().contains("invalid content-type"));

    let mut duplicate_content_type =
        mk_response(StatusCode::OK, body.clone(), Some(APPLICATION_NORITO));
    duplicate_content_type.headers_mut().append(
        "content-type",
        APPLICATION_NORITO.parse().expect("Norito media type"),
    );
    let error = rejected_next_bridge_finality_response(
        &client,
        height,
        &mut verifier,
        duplicate_content_type,
    );
    assert!(error.to_string().contains("multiple Content-Type"));

    let error = rejected_next_bridge_finality_response(
        &client,
        height,
        &mut verifier,
        mk_response(
            StatusCode::OK,
            vec![0; SUMERAGI_FINALITY_RESPONSE_MAX_BYTES + 1],
            Some(APPLICATION_NORITO),
        ),
    );
    assert!(error.to_string().contains("response exceeds"));

    let mut trailing = body.clone();
    trailing.push(0);
    let error = rejected_next_bridge_finality_response(
        &client,
        height,
        &mut verifier,
        mk_response(StatusCode::OK, trailing, Some(APPLICATION_NORITO)),
    );
    assert!(matches!(
        error.downcast_ref::<crate::Error>(),
        Some(crate::Error::CanonicalDecode { operation: "sumeragi.finality_proof.read", source })
            if source.kind() == norito::core::DecodeAttemptErrorKind::Invalid
    ));

    let actual = capture_request(
        mk_response(StatusCode::OK, body, Some(APPLICATION_NORITO)),
        |mock_transport| {
            let client = client
                .clone()
                .with_test_http_transport(mock_transport.clone());
            mark_data_model_compatible(&client);
            client.get_next_sumeragi_finality_proof(height, &mut verifier)
        },
    )
    .0
    .expect("valid successor must verify after rejected responses");
    assert_eq!(actual, successor);
}

#[test]
fn bridge_finality_next_reader_verification_failure_does_not_advance() {
    let client = current_finality_client();

    let (successor, mut verifier, _) = current_finality_fixture();
    let height = successor.block_header.height();
    let mut invalid = successor.clone();
    invalid.committee[0].proof_of_possession[0] ^= 0x40;
    let invalid_body = norito::to_bytes(&invalid).expect("encode invalid successor finality proof");
    let error = rejected_next_bridge_finality_response(
        &client,
        height,
        &mut verifier,
        mk_response(StatusCode::OK, invalid_body, Some(APPLICATION_NORITO)),
    );
    assert!(!error.to_string().is_empty());

    let body = norito::to_bytes(&successor).expect("encode canonical successor proof");
    let actual = capture_request(
        mk_response(StatusCode::OK, body, Some(APPLICATION_NORITO)),
        |mock_transport| {
            let client = client
                .clone()
                .with_test_http_transport(mock_transport.clone());
            mark_data_model_compatible(&client);
            client.get_next_sumeragi_finality_proof(height, &mut verifier)
        },
    )
    .0
    .expect("valid successor must verify after a rejected invalid signature");
    assert_eq!(actual, successor);
}

#[test]
fn bridge_finality_reader_expired_deadline_does_not_dispatch_or_advance() {
    let (successor, mut verifier, _) = current_finality_fixture();
    with_mock_http(
        |_| panic!("expired deadline must not dispatch"),
        |transport| {
            let client = current_finality_client()
                .with_test_http_transport(transport)
                .with_request_deadline(std::time::Instant::now());
            mark_data_model_compatible(&client);
            assert!(
                client
                    .get_next_sumeragi_finality_proof(
                        successor.block_header.height(),
                        &mut verifier
                    )
                    .is_err()
            );
        },
    );
    verifier
        .verify(&successor)
        .expect("deadline retained original anchor");
}

#[test]
fn bridge_finality_next_reader_rejects_height_mismatch_before_advancing() {
    let (proof, mut verifier, _) = current_finality_fixture();
    let (result, request) = capture_request(norito_response(StatusCode::OK, &proof), |transport| {
        let client = current_finality_client().with_test_http_transport(transport);
        mark_data_model_compatible(&client);
        client.get_next_sumeragi_finality_proof(NonZeroU64::new(2).unwrap(), &mut verifier)
    });
    assert!(result.unwrap_err().to_string().contains("requested height"));
    assert_eq!(request.url.path(), "/v1/bridge/finality/2");
    verifier
        .verify(&proof)
        .expect("mismatched height retained original prefix");
}
#[test]
fn current_genesis_readiness_authenticates_selected_root_and_instance() {
    let attestation = client_attestation_fixture();
    let (_, verifier, _) = current_finality_fixture();
    let (result, _) = capture_request(norito_response(StatusCode::OK, &attestation), |transport| {
        let client = current_finality_client().with_test_http_transport(transport);
        mark_data_model_compatible(&client);
        client.poll_sumeragi_genesis_readiness(
            attestation.body.challenge,
            &attestation.body.node_id,
            &verifier,
            std::time::Instant::now() + Duration::from_secs(5),
        )
    });
    assert!(matches!(
        result.unwrap(),
        GenesisFinalityReadiness::Ready(_)
    ));
    let mut wrong = attestation.clone();
    wrong.body.status.instance[0] ^= 1;
    let (_, _, signer) = current_finality_fixture();
    wrong.signature =
        iroha_crypto::SignatureOf::try_from_hash(signer.private_key(), wrong.body.signing_hash())
            .unwrap();
    let (result, _) = capture_request(norito_response(StatusCode::OK, &wrong), |transport| {
        let client = current_finality_client().with_test_http_transport(transport);
        mark_data_model_compatible(&client);
        client.poll_sumeragi_genesis_readiness(
            wrong.body.challenge,
            &wrong.body.node_id,
            &verifier,
            std::time::Instant::now() + Duration::from_secs(5),
        )
    });
    assert!(
        result.is_err(),
        "valid node signature cannot substitute the selected consensus instance"
    );
}

#[test]
fn native_client_continues_real_h2_quorum_and_keeps_checkpoint_on_rejection() {
    use iroha_data_model::{
        block::CommitCertificate, sumeragi_finality::SumeragiFinalityVerifier,
        testing::native_finality::NativeFinalityFixture,
    };
    // Real BLS certificates over protocol fixture outputs; no World execution claim.
    let native = NativeFinalityFixture::new();
    let first = native.genesis_proof().clone();
    let second = native.latest().clone();
    let mut verifier =
        SumeragiFinalityVerifier::new(native.genesis(), native.chain_id(), first.committee.clone())
            .unwrap();
    let mut client = client_with_base_url(base_url());
    client.network_id = native.network_id();
    let returned = capture_request(norito_response(StatusCode::OK, &first), |transport| {
        let client = client.clone().with_test_http_transport(transport);
        mark_data_model_compatible(&client);
        client.get_next_sumeragi_finality_proof(first.block_header.height(), &mut verifier)
    })
    .0
    .unwrap();
    assert_eq!(returned, first);
    let pinned = verifier
        .export_checkpoint(&first)
        .unwrap()
        .encode_canonical()
        .unwrap();
    let mut altered = second.clone();
    let mut block = decode_framed_signed_block(&altered.block_wire).unwrap();
    let certificate = block.commit_certificate().unwrap();
    let mut qc: iroha_sumeragi::message::Qc =
        norito::decode_canonical(certificate.commit_qc()).unwrap();
    qc.agg_sig.0[0] ^= 1;
    block.set_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
        certificate.consensus_header().to_vec(),
        norito::encode_canonical(&qc).unwrap(),
        certificate.result_preimage().to_vec(),
        certificate.availability().to_vec(),
    )));
    altered.block_wire = block.encode_wire().unwrap();
    assert!(
        capture_request(norito_response(StatusCode::OK, &altered), |transport| {
            let client = client.clone().with_test_http_transport(transport);
            mark_data_model_compatible(&client);
            client.get_next_sumeragi_finality_proof(second.block_header.height(), &mut verifier)
        })
        .0
        .is_err()
    );
    assert_eq!(
        verifier
            .export_checkpoint(&first)
            .unwrap()
            .encode_canonical()
            .unwrap(),
        pinned
    );
    let returned = capture_request(norito_response(StatusCode::OK, &second), |transport| {
        let client = client.clone().with_test_http_transport(transport);
        mark_data_model_compatible(&client);
        client.get_next_sumeragi_finality_proof(second.block_header.height(), &mut verifier)
    })
    .0
    .unwrap();
    assert_eq!(returned, second);
    assert_eq!(verifier.export_checkpoint(&second).unwrap().height(), 2);
}

#[test]
fn private_dataspace_record_read_is_bounded_exact_and_does_not_select_parent_trust() {
    use iroha_data_model::{
        block::consensus::SumeragiRootScope,
        private_dataspace::{
            MAX_PRIVATE_DATASPACE_RECORD_PROOF_BYTES, PrivateDataspaceAnchorState,
            PrivateDataspaceRecord, PrivateDataspaceRecordProof, PrivateDataspaceRegistration,
        },
        sumeragi_finality::authenticated_genesis,
        testing::native_finality::NativeFinalityFixture,
    };
    let client = current_finality_client();
    let dataspace_id = DataSpaceId::new(u64::MAX);
    let scope = SumeragiRootScope::Dataspace {
        parent_network_id: client.network_id,
        dataspace_id,
    };
    let child = NativeFinalityFixture::start_with_scope("sdk-private-record", scope);
    let result = child
        .verifier()
        .verify_retained_decision(child.genesis_proof())
        .unwrap()
        .result()
        .0;
    let registration = PrivateDataspaceRegistration::new(
        scope,
        child.chain_id().parse().unwrap(),
        child.network_id(),
        result,
        authenticated_genesis(child.genesis())
            .map(|genesis| genesis.into_parts().0)
            .unwrap(),
    )
    .unwrap();
    let record = PrivateDataspaceRecord {
        dataspace_id,
        alias: "acme".into(),
        owner: client.account.clone(),
        ownership_generation: 1,
        anchor: PrivateDataspaceAnchorState::from_authorized_registration(registration).unwrap(),
    };
    let key = record.witness_key();
    let value = norito::encode_canonical(&record).unwrap();
    // This structurally valid response deliberately carries no authenticated parent decision.
    let proof = PrivateDataspaceRecordProof::from_writes(
        client.network_id,
        2,
        *Hash::new(b"untrusted claimed parent result").as_ref(),
        [(key.as_slice(), value.as_slice())],
        record,
    )
    .unwrap();
    let wire = norito::encode_canonical(&proof).unwrap();
    let response = mk_response(StatusCode::OK, wire.clone(), Some(APPLICATION_NORITO));
    let (received, request) = capture_request(response, |transport| {
        let client = client.clone().with_test_http_transport(transport);
        mark_data_model_compatible(&client);
        client.get_private_dataspace_record_proof(dataspace_id, NonZeroU64::new(2).unwrap())
    });
    let received = received.unwrap();
    assert_eq!(received, proof);
    assert_eq!(
        request.url.path(),
        format!("/v1/private-dataspaces/{}/records/2/proof", u64::MAX)
    );
    assert_eq!(
        request.max_response_bytes,
        MAX_PRIVATE_DATASPACE_RECORD_PROOF_BYTES
    );
    let (parent_genesis, mut parent_verifier, _) = current_finality_fixture();
    parent_verifier.verify(&parent_genesis).unwrap();
    let parent = parent_verifier
        .verify_retained_decision(&parent_genesis)
        .unwrap();
    assert!(
        received.verify(dataspace_id, &parent).is_err(),
        "transport cannot authenticate the claimed parent decision"
    );
    for (requested_dataspace, requested_height, wrong_network) in [
        (DataSpaceId::new(1), 2, false),
        (dataspace_id, 3, false),
        (dataspace_id, 2, true),
    ] {
        let response = mk_response(StatusCode::OK, wire.clone(), Some(APPLICATION_NORITO));
        let (result, _) = capture_request(response, |transport| {
            let mut client = client.clone().with_test_http_transport(transport);
            if wrong_network {
                client.network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
                    Hash::new(b"another parent"),
                ));
            }
            mark_data_model_compatible(&client);
            client.get_private_dataspace_record_proof(
                requested_dataspace,
                NonZeroU64::new(requested_height).unwrap(),
            )
        });
        assert!(result.is_err());
    }
    for response in [
        mk_response(StatusCode::OK, wire.clone(), Some(APPLICATION_JSON)),
        mk_response(
            StatusCode::OK,
            vec![0; MAX_PRIVATE_DATASPACE_RECORD_PROOF_BYTES + 1],
            Some(APPLICATION_NORITO),
        ),
        mk_response(StatusCode::OK, Vec::new(), Some(APPLICATION_NORITO)),
        mk_response(
            StatusCode::OK,
            [wire.as_slice(), &[0]].concat(),
            Some(APPLICATION_NORITO),
        ),
    ] {
        let (result, _) = capture_request(response, |transport| {
            let client = client.clone().with_test_http_transport(transport);
            mark_data_model_compatible(&client);
            client.get_private_dataspace_record_proof(dataspace_id, NonZeroU64::new(2).unwrap())
        });
        assert!(result.is_err());
    }
    assert!(
        client
            .get_private_dataspace_record_proof(DataSpaceId::UNIVERSAL, NonZeroU64::new(2).unwrap())
            .is_err()
    );
    assert!(
        client
            .get_private_dataspace_record_proof(dataspace_id, NonZeroU64::new(1).unwrap())
            .is_err()
    );
}

fn private_root_export_fixture() -> (
    Client,
    iroha_data_model::testing::native_finality::NativeFinalityFixture,
    iroha_data_model::private_dataspace::PrivateDataspaceRegistration,
) {
    use iroha_data_model::{
        block::consensus::SumeragiRootScope, private_dataspace::PrivateDataspaceRegistration,
        sumeragi_finality::authenticated_genesis, testing::native_finality::NativeFinalityFixture,
    };
    let parent = current_finality_client();
    let scope = SumeragiRootScope::Dataspace {
        parent_network_id: parent.network_id,
        dataspace_id: DataSpaceId::new(u64::MAX),
    };
    let child = NativeFinalityFixture::start_with_scope("sdk-private-export", scope);
    let result = child
        .verifier()
        .verify_retained_decision(child.genesis_proof())
        .unwrap()
        .result()
        .0;
    let registration = PrivateDataspaceRegistration::new(
        scope,
        child.chain_id().parse().unwrap(),
        child.network_id(),
        result,
        authenticated_genesis(child.genesis())
            .map(|genesis| genesis.into_parts().0)
            .unwrap(),
    )
    .unwrap();
    let mut client = client_with_base_url(base_url());
    client.chain = registration.child_chain_id.clone();
    client.network_id = child.network_id();
    client
        .headers
        .insert("x-api-token".into(), "private-export-owner-fixture".into());
    (client, child, registration)
}

#[test]
fn private_root_registration_read_retains_owner_token_and_exact_independent_scope() {
    use iroha_data_model::{
        block::consensus::SumeragiRootScope,
        private_dataspace::MAX_PRIVATE_DATASPACE_REGISTRATION_BYTES,
    };
    let (client, _, registration) = private_root_export_fixture();
    let scope = registration.scope;
    let wire = norito::encode_canonical(&registration).unwrap();
    let (received, request) = capture_request(
        norito_response(StatusCode::OK, &registration),
        |transport| {
            let client = client.clone().with_test_http_transport(transport);
            mark_data_model_compatible(&client);
            client.get_private_root_registration(scope)
        },
    );
    assert_eq!(received.unwrap(), registration);
    assert_eq!(request.url.path(), "/v1/private-root/registration");
    assert_eq!(
        request.max_response_bytes,
        MAX_PRIVATE_DATASPACE_REGISTRATION_BYTES
    );
    assert_eq!(
        request
            .headers
            .iter()
            .filter(|(name, value)| name.eq_ignore_ascii_case("x-api-token")
                && value == "private-export-owner-fixture")
            .count(),
        1
    );
    assert!(
        !request
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("x-iroha-signature"))
    );
    let SumeragiRootScope::Dataspace {
        parent_network_id, ..
    } = scope
    else {
        unreachable!()
    };
    for changed in 0..4 {
        let (result, _) = capture_request(
            mk_response(StatusCode::OK, wire.clone(), Some(APPLICATION_NORITO)),
            |transport| {
                let mut client = client.clone().with_test_http_transport(transport);
                let selected_scope = match changed {
                    0 => SumeragiRootScope::Dataspace {
                        parent_network_id,
                        dataspace_id: DataSpaceId::new(1),
                    },
                    1 => SumeragiRootScope::Dataspace {
                        parent_network_id: client.network_id,
                        dataspace_id: DataSpaceId::new(u64::MAX),
                    },
                    2 => {
                        client.network_id = parent_network_id;
                        scope
                    }
                    _ => {
                        client.chain = "another-child-chain".parse().unwrap();
                        scope
                    }
                };
                mark_data_model_compatible(&client);
                client.get_private_root_registration(selected_scope)
            },
        );
        assert!(result.is_err(), "substitution {changed}");
    }
    for response in [
        mk_response(StatusCode::OK, wire.clone(), Some(APPLICATION_JSON)),
        mk_response(
            StatusCode::OK,
            [wire.as_slice(), &[0]].concat(),
            Some(APPLICATION_NORITO),
        ),
        mk_response(
            StatusCode::OK,
            vec![0; MAX_PRIVATE_DATASPACE_REGISTRATION_BYTES + 1],
            Some(APPLICATION_NORITO),
        ),
        mk_response(StatusCode::FORBIDDEN, wire, Some(APPLICATION_NORITO)),
    ] {
        let (result, _) = capture_request(response, |transport| {
            let client = client.clone().with_test_http_transport(transport);
            mark_data_model_compatible(&client);
            client.get_private_root_registration(scope)
        });
        assert!(result.is_err());
    }
    assert!(
        client
            .get_private_root_registration(SumeragiRootScope::Global)
            .is_err()
    );
    assert!(
        client
            .get_private_root_registration(SumeragiRootScope::Dataspace {
                parent_network_id,
                dataspace_id: DataSpaceId::UNIVERSAL
            })
            .is_err()
    );
}

#[test]
fn private_root_anchor_read_is_bounded_exact_and_does_not_authenticate_the_quorum() {
    use iroha_data_model::{
        block::consensus::SumeragiRootScope,
        private_dataspace::{
            MAX_PRIVATE_DATASPACE_ANCHOR_BYTES, PrivateDataspaceAnchor, PrivateDataspaceAnchorState,
        },
    };
    let (client, mut child, registration) = private_root_export_fixture();
    let scope = registration.scope;
    let block = child.block_with_submitted_work(child.next_header());
    let proof = child.certify(block);
    let verified = child.verifier().verify_retained_decision(&proof).unwrap();
    let anchor = PrivateDataspaceAnchor::from_certificate(
        &registration,
        verified.block().commit_certificate().unwrap(),
    )
    .unwrap();
    let height = NonZeroU64::new(2).unwrap();
    let wire = norito::encode_canonical(&anchor).unwrap();
    let (received, request) =
        capture_request(norito_response(StatusCode::OK, &anchor), |transport| {
            let client = client.clone().with_test_http_transport(transport);
            mark_data_model_compatible(&client);
            client.get_private_root_anchor(scope, height)
        });
    assert_eq!(received.unwrap(), anchor);
    assert_eq!(request.url.path(), "/v1/private-root/anchors/2");
    assert_eq!(
        request.max_response_bytes,
        MAX_PRIVATE_DATASPACE_ANCHOR_BYTES
    );
    assert_eq!(
        request
            .headers
            .iter()
            .filter(|(name, value)| name.eq_ignore_ascii_case("x-api-token")
                && value == "private-export-owner-fixture")
            .count(),
        1
    );
    let SumeragiRootScope::Dataspace {
        parent_network_id, ..
    } = scope
    else {
        unreachable!()
    };
    for changed in 0..4 {
        let (result, _) = capture_request(
            mk_response(StatusCode::OK, wire.clone(), Some(APPLICATION_NORITO)),
            |transport| {
                let mut client = client.clone().with_test_http_transport(transport);
                let selected_scope = match changed {
                    0 => SumeragiRootScope::Dataspace {
                        parent_network_id,
                        dataspace_id: DataSpaceId::new(1),
                    },
                    1 => SumeragiRootScope::Dataspace {
                        parent_network_id: client.network_id,
                        dataspace_id: DataSpaceId::new(u64::MAX),
                    },
                    2 => {
                        client.network_id = parent_network_id;
                        scope
                    }
                    _ => scope,
                };
                mark_data_model_compatible(&client);
                client.get_private_root_anchor(
                    selected_scope,
                    if changed == 3 {
                        NonZeroU64::new(3).unwrap()
                    } else {
                        height
                    },
                )
            },
        );
        assert!(result.is_err(), "substitution {changed}");
    }
    let mut forged = anchor.clone();
    let mut qc: iroha_sumeragi::message::Qc =
        norito::decode_canonical(&forged.certificate.commit_qc).unwrap();
    qc.agg_sig.0[0] ^= 1;
    forged.certificate.commit_qc = norito::encode_canonical(&qc).unwrap();
    let (received, _) = capture_request(norito_response(StatusCode::OK, &forged), |transport| {
        let client = client.clone().with_test_http_transport(transport);
        mark_data_model_compatible(&client);
        client.get_private_root_anchor(scope, height)
    });
    let mut tracker =
        PrivateDataspaceAnchorState::from_authorized_registration(registration).unwrap();
    assert!(
        tracker.apply(&received.unwrap()).is_err(),
        "transport never confers quorum trust"
    );
    tracker.apply(&anchor).unwrap();
    for response in [
        mk_response(StatusCode::OK, wire.clone(), Some(APPLICATION_JSON)),
        mk_response(
            StatusCode::OK,
            [wire.as_slice(), &[0]].concat(),
            Some(APPLICATION_NORITO),
        ),
        mk_response(
            StatusCode::OK,
            vec![0; MAX_PRIVATE_DATASPACE_ANCHOR_BYTES + 1],
            Some(APPLICATION_NORITO),
        ),
        mk_response(StatusCode::FORBIDDEN, wire, Some(APPLICATION_NORITO)),
    ] {
        let (result, _) = capture_request(response, |transport| {
            let client = client.clone().with_test_http_transport(transport);
            mark_data_model_compatible(&client);
            client.get_private_root_anchor(scope, height)
        });
        assert!(result.is_err());
    }
    assert!(
        client
            .get_private_root_anchor(SumeragiRootScope::Global, height)
            .is_err()
    );
    assert!(
        client
            .get_private_root_anchor(scope, NonZeroU64::new(1).unwrap())
            .is_err()
    );
    assert!(
        client
            .get_private_root_anchor(
                SumeragiRootScope::Dataspace {
                    parent_network_id,
                    dataspace_id: DataSpaceId::UNIVERSAL
                },
                height
            )
            .is_err()
    );
}

#[test]
fn independent_custody_state_uses_exact_bounded_route_and_never_treats_http_absence_as_state() {
    use iroha_data_model::sorafs::stream_token_custody::proof::MAX_STREAM_TOKEN_CUSTODY_PROOF_BYTES_V1;
    let (client, provider, binding, verified) = stream_token_custody_control_fixture();
    let owner = AccountId::new(
        KeyPair::from_seed(vec![0x66; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    for response in [
        mk_response(StatusCode::OK, vec![1, 2, 3], Some(APPLICATION_NORITO)),
        mk_response(StatusCode::NOT_FOUND, Vec::new(), Some(APPLICATION_NORITO)),
        mk_response(
            StatusCode::SERVICE_UNAVAILABLE,
            Vec::new(),
            Some(APPLICATION_NORITO),
        ),
        mk_response(StatusCode::OK, b"{}".to_vec(), Some(APPLICATION_JSON)),
        mk_response(
            StatusCode::OK,
            vec![0; MAX_STREAM_TOKEN_CUSTODY_PROOF_BYTES_V1 + 1],
            Some(APPLICATION_NORITO),
        ),
    ] {
        let (result, request) = capture_request(response, |transport| {
            let client = client.clone().with_test_http_transport(transport);
            mark_data_model_compatible(&client);
            client.get_stream_token_custody_state(
                provider,
                &owner,
                &binding,
                Hash::new(b"independently selected schema"),
                &verified,
            )
        });
        assert!(result.is_err());
        assert_eq!(
            request.url.path(),
            format!(
                "/v1/sorafs/providers/{}/custody/2",
                hex::encode(provider.as_bytes())
            )
        );
        assert_eq!(
            request.max_response_bytes,
            MAX_STREAM_TOKEN_CUSTODY_PROOF_BYTES_V1
        );
        assert_eq!(
            request
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("accept"))
                .map(|(_, value)| value.as_str()),
            Some(APPLICATION_NORITO)
        );
    }
}

#[test]
fn independent_custody_state_decodes_authenticated_absence_on_the_selected_global_root() {
    use iroha_data_model::{
        sorafs::stream_token_custody::proof::StreamTokenCustodyProofV1,
        sumeragi_finality::{
            WorldStateElementKindV1, WorldStateSnapshotEntryV1, WorldStateSnapshotV1,
            world_state_value_hash_v1,
        },
        testing::native_finality::NativeFinalityFixture,
    };
    let (mut client, provider, mut binding, _) = stream_token_custody_control_fixture();
    let mut native = NativeFinalityFixture::start("sdk-native-custody-absence");
    client.chain = native.chain_id().parse().unwrap();
    client.network_id = native.network_id();
    binding.chain_id = client.chain.to_string();
    binding.network_id = *client.network_id.as_bytes();
    let owner = AccountId::new(
        KeyPair::from_seed(vec![0x66; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    let schema = Hash::new(b"independently qualified sdk custody schema");
    let proof = StreamTokenCustodyProofV1 {
        world: WorldStateSnapshotV1 {
            schema_hash: schema,
            entries: vec![WorldStateSnapshotEntryV1 {
                field_id: "world.provider_owners".into(),
                kind: WorldStateElementKindV1::Table,
                key_hash: Some(world_state_value_hash_v1(&provider).unwrap()),
                value_hash: world_state_value_hash_v1(&owner).unwrap(),
            }],
        },
        owner: owner.clone(),
        current: None,
    };
    let block = native.block_with_submitted_work(native.next_header());
    let certificate = native.certify_with_world_root(block, proof.world.root().unwrap());
    let verified = native
        .verifier()
        .verify_retained_decision(&certificate)
        .unwrap();
    let response = mk_response(
        StatusCode::OK,
        norito::encode_canonical(&proof).unwrap(),
        Some(APPLICATION_NORITO),
    );
    let (result, _) = capture_request(response, |transport| {
        let client = client.with_test_http_transport(transport);
        mark_data_model_compatible(&client);
        client.get_stream_token_custody_state(provider, &owner, &binding, schema, &verified)
    });
    let state = result.unwrap();
    assert!(state.current().is_none());
    assert_eq!(state.owner(), &owner);
    assert_eq!(state.context_id(), verified.context_id());
}

#[test]
fn independent_custody_state_refuses_foreign_private_or_expired_selection_before_dispatch() {
    use iroha_data_model::{
        block::consensus::SumeragiRootScope, testing::native_finality::NativeFinalityFixture,
    };
    let (client, provider, binding, verified) = stream_token_custody_control_fixture();
    let owner = AccountId::new(
        KeyPair::from_seed(vec![0x66; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    let mut private = NativeFinalityFixture::start_with_scope(
        "private-custody-root",
        SumeragiRootScope::Dataspace {
            parent_network_id: client.network_id,
            dataspace_id: iroha_model_base::topology::DataSpaceId::new(u64::MAX),
        },
    );
    let block = private.block_with_submitted_work(private.next_header());
    let certificate = private.certify(block);
    let private_block = private
        .verifier()
        .verify_retained_decision(&certificate)
        .unwrap();
    with_mock_http(
        |_| panic!("invalid or expired custody selection must not dispatch"),
        |transport| {
            let client = client.with_test_http_transport(transport);
            mark_data_model_compatible(&client);
            let schema = Hash::new(b"selected schema");
            let mut changed = binding.clone();
            changed.chain_id = "other-chain".into();
            assert!(
                client
                    .get_stream_token_custody_state(provider, &owner, &changed, schema, &verified)
                    .is_err()
            );
            let mut foreign = client.clone();
            foreign.chain = "another-root-label".parse().unwrap();
            changed.chain_id = foreign.chain.to_string();
            assert!(
                foreign
                    .get_stream_token_custody_state(provider, &owner, &changed, schema, &verified)
                    .is_err()
            );
            let mut private_client = client.clone();
            private_client.chain = private.chain_id().parse().unwrap();
            private_client.network_id = private.network_id();
            changed.chain_id = private_client.chain.to_string();
            changed.network_id = *private_client.network_id.as_bytes();
            assert!(
                private_client
                    .get_stream_token_custody_state(
                        provider,
                        &owner,
                        &changed,
                        schema,
                        &private_block
                    )
                    .is_err()
            );
            let expired = client.with_request_deadline(std::time::Instant::now());
            assert!(
                expired
                    .get_stream_token_custody_state(provider, &owner, &binding, schema, &verified)
                    .is_err()
            );
        },
    );
}

fn current_finality_interval_fixture() -> (
    Client,
    Vec<iroha_data_model::sumeragi_finality::SumeragiFinalityProof>,
) {
    use iroha_data_model::testing::native_finality::NativeFinalityFixture;
    let mut native = NativeFinalityFixture::start("sdk-original-interval");
    let mut proofs = vec![native.genesis_proof().clone()];
    while proofs.len() < 4 {
        let block = native.block_with_submitted_work(native.next_header());
        proofs.push(native.certify(block));
    }
    let mut client = client_with_base_url(base_url());
    client.network_id = native.network_id();
    (client, proofs)
}
#[test]
fn finality_interval_reader_uses_one_exact_bounded_request_and_original_deadline() {
    let (client, expected) = current_finality_interval_fixture();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let (result, request) =
        capture_request(norito_response(StatusCode::OK, &expected), |transport| {
            let client = client
                .with_test_http_transport(transport)
                .with_request_deadline(deadline);
            mark_data_model_compatible(&client);
            client.get_sumeragi_finality_interval(
                NonZeroU64::new(1).unwrap(),
                NonZeroU64::new(4).unwrap(),
            )
        });
    assert_eq!(result.unwrap(), expected);
    assert_eq!(request.method, HttpMethod::GET);
    assert_eq!(request.url.path(), "/v1/bridge/finality/interval/1/4");
    assert_eq!(
        request.max_response_bytes,
        SUMERAGI_FINALITY_RESPONSE_MAX_BYTES
    );
    assert!(request.timeout.unwrap() <= Duration::from_secs(10));
    assert_eq!(
        request
            .headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case("accept"))
            .map(|(_, value)| value.as_str()),
        Some(APPLICATION_NORITO)
    );
}
#[test]
fn finality_interval_reader_refuses_missing_reordered_and_noncanonical_rows_without_fallback() {
    let (client, expected) = current_finality_interval_fixture();
    let mut reordered = expected.clone();
    reordered.swap(1, 2);
    let mut duplicated = expected.clone();
    duplicated[2] = duplicated[1].clone();
    let mut trailing = norito::to_bytes(&expected).unwrap();
    trailing.push(0);
    for response in [
        norito_response(StatusCode::OK, &expected[..3].to_vec()),
        norito_response(StatusCode::OK, &reordered),
        norito_response(StatusCode::OK, &duplicated),
        mk_response(StatusCode::OK, trailing, Some(APPLICATION_NORITO)),
    ] {
        let (result, request) = capture_request(response, |transport| {
            let client = client.clone().with_test_http_transport(transport);
            mark_data_model_compatible(&client);
            client.get_sumeragi_finality_interval(
                NonZeroU64::new(1).unwrap(),
                NonZeroU64::new(4).unwrap(),
            )
        });
        assert!(
            result.is_err(),
            "interval shape/framing failure cannot select a per-height fallback"
        );
        assert_eq!(request.url.path(), "/v1/bridge/finality/interval/1/4");
    }
}
#[test]
fn finality_interval_reader_rejects_invalid_range_and_expired_original_deadline_before_dispatch() {
    let (client, _) = current_finality_interval_fixture();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let observations = Arc::clone(&calls);
    with_mock_http(
        move |request| {
            observations.lock().unwrap().push(request);
            Ok(empty_response(StatusCode::OK))
        },
        |transport| {
            let client = client.with_test_http_transport(transport);
            mark_data_model_compatible(&client);
            for (from, to) in [(4, 3), (1, 65)] {
                assert!(
                    client
                        .get_sumeragi_finality_interval(
                            NonZeroU64::new(from).unwrap(),
                            NonZeroU64::new(to).unwrap()
                        )
                        .is_err()
                );
            }
            assert!(
                client
                    .with_request_deadline(std::time::Instant::now())
                    .get_sumeragi_finality_interval(
                        NonZeroU64::new(1).unwrap(),
                        NonZeroU64::new(4).unwrap()
                    )
                    .is_err()
            );
        },
    );
    assert!(calls.lock().unwrap().is_empty());
}
