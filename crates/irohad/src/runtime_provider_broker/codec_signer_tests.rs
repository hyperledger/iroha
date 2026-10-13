// Broker fixtures may carry signing material: assertions never print values,
// and every temporary encoding remains guarded by the broker's scrub-on-drop buffer.
fn assert_broker_frame_owner<T>(value: &T, owner: &str, limit: usize)
where
    T: NoritoSerialize + for<'de> NoritoDeserialize<'de>,
{
    assert!(T::nominal_name() == owner);
    assert!(T::frame_name() == owner);
    let encoded = encode_sensitive_canonical(value, limit).expect("encode current broker owner");
    let view = norito::core::from_bytes_view(&encoded).expect("valid broker frame header");
    assert!(view.schema() == norito::schema::identity::frame_hash::<T>());
    let decoded: T = decode_canonical(&encoded, limit).expect("decode current broker owner");
    let roundtrip = encode_sensitive_canonical(&decoded, limit).expect("re-encode broker owner");
    assert!(encoded.as_slice() == roundtrip.as_slice());
    let mut substituted = ScrubbedBytes::new(encoded.to_vec());
    substituted[6] ^= 1;
    assert!(matches!(
        norito::decode_canonical::<T>(&substituted),
        Err(norito::Error::SchemaMismatch)
    ));
    assert!(matches!(
        decode_canonical::<T>(&substituted, limit),
        Err(BrokerError::Protocol)
    ));
    assert!(matches!(
        decode_canonical::<T>(&encoded[..encoded.len() - 1], limit),
        Err(BrokerError::Protocol)
    ));
    let mut trailing = ScrubbedBytes::new(encoded.to_vec());
    trailing.push(0);
    assert!(matches!(
        decode_canonical::<T>(&trailing, limit + 1),
        Err(BrokerError::Protocol)
    ));
}

#[test]
fn broker_same_payload_request_and_result_owners_reject_substitution() {
    let sign = BillingSignDigestRequestWireV1 { digest: [0x31; 32] };
    let lookup = BillingLookupRequestWireV1 {
        record_id: [0x31; 32],
    };
    let signature = SignResultWireV1 {
        signature: [0x42; 64],
    };
    let issuer = PopIssuerSignResultWireV1 {
        signature: [0x42; 64],
    };
    assert_broker_frame_owner(
        &sign,
        "irohad::runtime_provider_broker::protocol::BillingSignDigestRequestWireV1",
        MAX_BILLING_CONTROL_FRAME_BYTES_V1,
    );
    assert_broker_frame_owner(
        &lookup,
        "irohad::runtime_provider_broker::protocol::BillingLookupRequestWireV1",
        MAX_BILLING_CONTROL_FRAME_BYTES_V1,
    );
    assert_broker_frame_owner(
        &signature,
        "irohad::runtime_provider_broker::protocol::primitives::SignResultWireV1",
        MAX_GOVERNANCE_SIGNING_FRAME_BYTES_V1,
    );
    assert_broker_frame_owner(
        &issuer,
        "irohad::runtime_provider_broker::protocol::primitives::PopIssuerSignResultWireV1",
        MAX_GOVERNANCE_SIGNING_FRAME_BYTES_V1,
    );
    let sign_bytes = encode_sensitive_canonical(&sign, MAX_BILLING_CONTROL_FRAME_BYTES_V1)
        .expect("encode sign request");
    let lookup_bytes = encode_sensitive_canonical(&lookup, MAX_BILLING_CONTROL_FRAME_BYTES_V1)
        .expect("encode lookup request");
    let signature_bytes =
        encode_sensitive_canonical(&signature, MAX_GOVERNANCE_SIGNING_FRAME_BYTES_V1)
            .expect("encode sign result");
    let issuer_bytes = encode_sensitive_canonical(&issuer, MAX_GOVERNANCE_SIGNING_FRAME_BYTES_V1)
        .expect("encode issuer result");
    assert!(
        norito::core::from_bytes_view(&sign_bytes)
            .expect("sign payload")
            .as_bytes()
            == norito::core::from_bytes_view(&lookup_bytes)
                .expect("lookup payload")
                .as_bytes()
    );
    assert!(
        norito::core::from_bytes_view(&signature_bytes)
            .expect("signature payload")
            .as_bytes()
            == norito::core::from_bytes_view(&issuer_bytes)
                .expect("issuer payload")
                .as_bytes()
    );
    assert!(matches!(
        decode_canonical::<BillingSignDigestRequestWireV1>(
            &lookup_bytes,
            MAX_BILLING_CONTROL_FRAME_BYTES_V1
        ),
        Err(BrokerError::Protocol)
    ));
    assert!(matches!(
        decode_canonical::<BillingLookupRequestWireV1>(
            &sign_bytes,
            MAX_BILLING_CONTROL_FRAME_BYTES_V1
        ),
        Err(BrokerError::Protocol)
    ));
    assert!(matches!(
        decode_canonical::<SignResultWireV1>(&issuer_bytes, MAX_GOVERNANCE_SIGNING_FRAME_BYTES_V1),
        Err(BrokerError::Protocol)
    ));
    assert!(matches!(
        decode_canonical::<PopIssuerSignResultWireV1>(
            &signature_bytes,
            MAX_GOVERNANCE_SIGNING_FRAME_BYTES_V1
        ),
        Err(BrokerError::Protocol)
    ));
}

#[derive(Encode)]
struct HandshakeRequestWithoutNetworkV1 {
    chain_id: String,
    requested_catalog: Vec<ProviderBindingWireV1>,
    client_nonce: [u8; 32],
    catalog_digest: [u8; 32],
    client_transcript_digest: [u8; 32],
}
#[test]
fn canonical_framing_rejects_magic_version_kind_trailing_and_oversize() {
    fn frame_payload<T: norito::SerializePayload>(value: &T) -> ScrubbedBytes {
        let _layout = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        let (payload, flags) = norito::codec::encode_with_header_flags(value);
        let payload = ScrubbedBytes::new(payload);
        ScrubbedBytes::new(
            norito::core::frame_bare_with_header_flags::<HandshakeRequestV1>(&payload, flags)
                .expect("frame handshake payload under current owner"),
        )
    }
    let request = make_handshake_request(
        "test-chain",
        server_test_network_id(),
        vec![signer_binding()],
        [0x42; 32],
    )
    .expect("build handshake");
    let frame = encode_frame(
        FRAME_KIND_HANDSHAKE_REQUEST_V1,
        &request,
        MAX_HANDSHAKE_FRAME_BYTES_V1,
    )
    .expect("encode handshake frame");
    let envelope_header = norito::core::Header::read(&frame[..]).expect("read broker header");
    assert_eq!(
        envelope_header.schema,
        norito::core::schema_hash_for_name(
            "irohad::runtime_provider_broker::protocol::primitives::BrokerFrameV1",
        ),
        "broker envelopes advertise their declared protocol identity",
    );
    let envelope = decode_canonical::<BrokerFrameV1>(&frame, MAX_HANDSHAKE_FRAME_BYTES_V1)
        .expect("decode canonical envelope");
    let request_header =
        norito::core::Header::read(&envelope.body[..]).expect("read handshake header");
    assert_eq!(
        request_header.schema,
        norito::core::schema_hash_for_name(
            "irohad::runtime_provider_broker::protocol::HandshakeRequestV1",
        ),
        "nested requests advertise their own declared protocol identity",
    );
    assert_eq!(
        decode_frame::<HandshakeRequestV1>(
            &frame,
            FRAME_KIND_HANDSHAKE_REQUEST_V1,
            MAX_HANDSHAKE_FRAME_BYTES_V1,
        )
        .expect("decode canonical frame"),
        request
    );
    let retired = HandshakeRequestWithoutNetworkV1 {
        chain_id: request.chain_id.clone(),
        requested_catalog: request.requested_catalog.clone(),
        client_nonce: request.client_nonce,
        catalog_digest: request.catalog_digest,
        client_transcript_digest: request.client_transcript_digest,
    };
    assert_broker_frame_owner(
        &request,
        "irohad::runtime_provider_broker::protocol::HandshakeRequestV1",
        MAX_HANDSHAKE_FRAME_BYTES_V1,
    );
    // The unsupported shape stays payload-only and is placed under the real
    // request owner, so rejection must inspect its missing network field.
    let current_body = frame_payload(&request);
    assert!(
        decode_canonical::<HandshakeRequestV1>(&current_body, MAX_HANDSHAKE_FRAME_BYTES_V1).is_ok()
    );
    let retired_body = frame_payload(&retired);
    let error = norito::decode_canonical::<HandshakeRequestV1>(&retired_body)
        .expect_err("networkless shape must fail under the current owner");
    assert!(!matches!(error, norito::Error::SchemaMismatch));
    let retired_envelope = BrokerFrameV1 {
        magic: BROKER_MAGIC_V1,
        version: BROKER_VERSION_V1,
        kind: FRAME_KIND_HANDSHAKE_REQUEST_V1,
        body: retired_body.to_vec(),
    };
    assert_broker_frame_owner(
        &retired_envelope,
        "irohad::runtime_provider_broker::protocol::primitives::BrokerFrameV1",
        MAX_HANDSHAKE_FRAME_BYTES_V1,
    );
    let retired_frame = encode_sensitive_canonical(&retired_envelope, MAX_HANDSHAKE_FRAME_BYTES_V1)
        .expect("encode current envelope containing unsupported handshake payload");
    assert_eq!(
        decode_frame::<HandshakeRequestV1>(
            &retired_frame,
            FRAME_KIND_HANDSHAKE_REQUEST_V1,
            MAX_HANDSHAKE_FRAME_BYTES_V1,
        ),
        Err(BrokerError::Protocol),
        "the retired networkless request schema must fail closed",
    );
    for mutation in 0..3 {
        let mut envelope = decode_canonical::<BrokerFrameV1>(&frame, MAX_HANDSHAKE_FRAME_BYTES_V1)
            .expect("decode frame envelope");
        match mutation {
            0 => envelope.magic[0] ^= 1,
            1 => envelope.version += 1,
            2 => envelope.kind += 1,
            _ => unreachable!(),
        }
        let confused = encode_canonical(&envelope, MAX_HANDSHAKE_FRAME_BYTES_V1)
            .expect("encode confused frame");
        assert_eq!(
            decode_frame::<HandshakeRequestV1>(
                &confused,
                FRAME_KIND_HANDSHAKE_REQUEST_V1,
                MAX_HANDSHAKE_FRAME_BYTES_V1,
            ),
            Err(BrokerError::Protocol)
        );
    }
    let mut trailing = ScrubbedBytes::new(frame.to_vec());
    trailing.push(0);
    assert_eq!(
        decode_frame::<HandshakeRequestV1>(
            &trailing,
            FRAME_KIND_HANDSHAKE_REQUEST_V1,
            MAX_HANDSHAKE_FRAME_BYTES_V1,
        ),
        Err(BrokerError::Protocol)
    );
    let oversized = u32::try_from(MAX_HANDSHAKE_FRAME_BYTES_V1 + 1)
        .expect("handshake bound fits u32")
        .to_be_bytes();
    assert_eq!(
        read_length_prefixed(&mut Cursor::new(oversized), MAX_HANDSHAKE_FRAME_BYTES_V1),
        Err(BrokerError::Protocol)
    );
    assert_eq!(
        read_length_prefixed(
            &mut Cursor::new(0_u32.to_be_bytes()),
            MAX_HANDSHAKE_FRAME_BYTES_V1
        ),
        Err(BrokerError::Protocol)
    );
}
#[test]
fn operation_request_prelude_enforces_role_limit_and_global_inbound_budget() {
    let slot = IrohaRuntimeProviderSlotV1::ModerationQuarantineKeyWrapper.wire_id();
    let operation = OPERATION_MODERATION_QUARANTINE_WRAP_DEK_V1;
    let mut oversized_moderation = Vec::new();
    oversized_moderation.extend_from_slice(&slot.to_be_bytes());
    oversized_moderation.extend_from_slice(&operation.to_be_bytes());
    oversized_moderation.extend_from_slice(
        &u32::try_from(MAX_MODERATION_QUARANTINE_FRAME_BYTES_V1 + 1)
            .expect("moderation frame limit fits u32")
            .to_be_bytes(),
    );
    assert_eq!(
        read_operation_request_frame(&mut Cursor::new(oversized_moderation)),
        Err(BrokerError::Protocol),
        "the server applies the announced moderation operation limit before allocation"
    );
    let mut oversized_request_auth = Vec::new();
    oversized_request_auth.extend_from_slice(
        &IrohaRuntimeProviderSlotV1::GovernanceDagIpfsAuthenticator
            .wire_id()
            .to_be_bytes(),
    );
    oversized_request_auth
        .extend_from_slice(&OPERATION_GOVERNANCE_REQUEST_AUTHENTICATE_V1.to_be_bytes());
    oversized_request_auth.extend_from_slice(
        &u32::try_from(MAX_GOVERNANCE_REQUEST_AUTH_FRAME_BYTES_V1 + 1)
            .expect("request-auth frame limit fits u32")
            .to_be_bytes(),
    );
    assert_eq!(
        read_operation_request_frame(&mut Cursor::new(oversized_request_auth)),
        Err(BrokerError::Protocol),
        "the request-auth bound is enforced before allocation"
    );
    let mut oversized_native_signer = Vec::new();
    oversized_native_signer.extend_from_slice(
        &IrohaRuntimeProviderSlotV1::ProofOutcomeTransactionSigner
            .wire_id()
            .to_be_bytes(),
    );
    oversized_native_signer.extend_from_slice(&OPERATION_NATIVE_TRANSACTION_SIGN_V1.to_be_bytes());
    oversized_native_signer.extend_from_slice(
        &u32::try_from(MAX_NATIVE_TRANSACTION_FRAME_BYTES_V1 + 1)
            .expect("native transaction frame limit fits u32")
            .to_be_bytes(),
    );
    assert_eq!(
        read_operation_request_frame(&mut Cursor::new(oversized_native_signer)),
        Err(BrokerError::Protocol),
        "the native transaction bound is enforced before allocation"
    );
    let mut unknown_operation = Vec::new();
    unknown_operation.extend_from_slice(&slot.to_be_bytes());
    unknown_operation.extend_from_slice(&u16::MAX.to_be_bytes());
    assert_eq!(
        read_operation_request_frame(&mut Cursor::new(unknown_operation)),
        Err(BrokerError::Protocol)
    );
    let mut budget_exhaustion = Vec::new();
    budget_exhaustion.extend_from_slice(&slot.to_be_bytes());
    budget_exhaustion.extend_from_slice(&operation.to_be_bytes());
    budget_exhaustion.extend_from_slice(&9_u32.to_be_bytes());
    budget_exhaustion.extend_from_slice(&[0xAA; 9]);
    let decode_pool = new_test_process_pool();
    assert!(
        matches!(
            read_operation_request_frame_with_budget(
                &mut Cursor::new(budget_exhaustion),
                Arc::new(tokio::sync::Semaphore::new(8)),
                Arc::clone(&decode_pool),
            ),
            Err(BrokerError::Unavailable)
        ),
        "declared inbound bytes must fit the single shared operation budget"
    );
    assert_eq!(
        decode_pool.allocation.reserved_bytes(),
        0,
        "raw ingress rejection happens before composed process admission"
    );
}
#[test]
fn stalled_operation_body_does_not_reserve_composed_decode_pool() {
    struct StalledBodyReader {
        prefix: Cursor<Vec<u8>>,
        decode_pool: Arc<DecodeResourcePoolV1>,
        observed_body_read: Arc<AtomicBool>,
    }
    impl std::io::Read for StalledBodyReader {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            if usize::try_from(self.prefix.position()).unwrap_or(usize::MAX)
                < self.prefix.get_ref().len()
            {
                return std::io::Read::read(&mut self.prefix, output);
            }
            assert_eq!(
                self.decode_pool.allocation.reserved_bytes(),
                0,
                "the composed pool is acquired only after the full raw frame"
            );
            self.observed_body_read.store(true, Ordering::Release);
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "simulated stalled operation body",
            ))
        }
    }
    let operation = OPERATION_PROVIDER_INGEST_CHECKPOINT_COMPARE_AND_SWAP_V1;
    let policy = operation_decode_policy(operation);
    let decode_pool = Arc::new(DecodeResourcePoolV1::new(policy.max_composed_bytes));
    let observed_body_read = Arc::new(AtomicBool::new(false));
    let mut prefix = Vec::new();
    prefix.extend_from_slice(
        &IrohaRuntimeProviderSlotV1::ProviderIngestCheckpointStore
            .wire_id()
            .to_be_bytes(),
    );
    prefix.extend_from_slice(&operation.to_be_bytes());
    prefix.extend_from_slice(&16_u32.to_be_bytes());
    let mut reader = StalledBodyReader {
        prefix: Cursor::new(prefix),
        decode_pool: Arc::clone(&decode_pool),
        observed_body_read: Arc::clone(&observed_body_read),
    };
    let raw_budget = Arc::new(tokio::sync::Semaphore::new(16));
    assert!(matches!(
        read_operation_request_frame_inner(
            &mut reader,
            Some(Arc::clone(&raw_budget)),
            Some(Arc::clone(&decode_pool)),
        ),
        Err(BrokerError::Unavailable)
    ));
    assert!(observed_body_read.load(Ordering::Acquire));
    assert_eq!(decode_pool.allocation.reserved_bytes(), 0);
    assert_eq!(
        raw_budget.available_permits(),
        16,
        "failed body reads release the declared-byte reservation"
    );
}
#[test]
fn length_prefixed_reader_preallocates_large_frame_once_and_reads_in_chunks() {
    struct CountingReader {
        inner: Cursor<Vec<u8>>,
        body_reads: usize,
    }
    impl std::io::Read for CountingReader {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            let body = self.inner.position() >= 4;
            let read = std::io::Read::read(&mut self.inner, output)?;
            if body && read != 0 {
                self.body_reads += 1;
            }
            Ok(read)
        }
    }
    let frame_len = 2 * 1024 * 1024 + 17;
    let payload = vec![0xA5; frame_len];
    let mut framed = Vec::with_capacity(frame_len + 4);
    framed.extend_from_slice(
        &u32::try_from(frame_len)
            .expect("test frame length fits u32")
            .to_be_bytes(),
    );
    framed.extend_from_slice(&payload);
    let mut reader = CountingReader {
        inner: Cursor::new(framed),
        body_reads: 0,
    };
    let frame = read_length_prefixed(&mut reader, frame_len).expect("read bounded large frame");
    assert_eq!(frame.as_slice(), payload);
    assert!(frame.bytes.capacity() >= frame_len);
    assert_eq!(reader.body_reads, frame_len.div_ceil(64 * 1024));
}
#[test]
fn configured_catalog_slots_roundtrip_through_the_canonical_inverse() {
    for slot in IrohaRuntimeProviderSlotV1::ALL {
        let catalog = IrohaRuntimeProviderBindingsV1::qualified_for_test(
            "catalog-inverse-chain",
            slot,
            format!("runtime://production/runtime-slot-{}", slot.wire_id()),
            1,
            TEST_POLICY_DIGEST,
        );
        let configured = catalog.iter().next().expect("one configured binding");
        let wire = ProviderBindingWireV1::try_from_binding(configured)
            .expect("project configured binding");
        assert_eq!(wire.runtime_slot(), Ok(slot));
    }
    let configured_ids = IrohaRuntimeProviderSlotV1::ALL
        .into_iter()
        .map(IrohaRuntimeProviderSlotV1::wire_id)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(configured_ids.len(), IrohaRuntimeProviderSlotV1::ALL.len());
    let mut unknown = signer_binding();
    for wire_id in (0..=u16::MAX).filter(|wire_id| !configured_ids.contains(wire_id)) {
        unknown.slot = wire_id;
        assert_eq!(unknown.runtime_slot(), Err(BrokerError::BindingMismatch));
    }
}
#[test]
fn evidence_viewer_webauthn_wire_is_canonical_and_binding_exact() {
    let valid = evidence_viewer_binding(IrohaRuntimeProviderSlotV1::EvidenceViewerWebAuthn);
    validate_wire_binding(&valid).expect("canonical WebAuthn binding");
    let configured = valid
        .evidence_viewer_webauthn_binding
        .as_ref()
        .expect("WebAuthn metadata");
    let request = EvidenceViewerVerifyAndConsumeRequestWireV1 {
        challenge: b"canonical-challenge".to_vec(),
        assertion: vec![0xA5],
        binding_digest: [0xB6; 32],
        rp_id: configured.rp_id.clone(),
        allowed_origins: configured.allowed_origins.clone(),
        now_unix_ms: 1_000,
    };
    validate_evidence_viewer_verify_and_consume_wire(&request, configured)
        .expect("exact WebAuthn operation wire");
    for rp_id in ["Review.example", "localhost", "127.0.0.1"] {
        let mut binding = valid.clone();
        binding
            .evidence_viewer_webauthn_binding
            .as_mut()
            .expect("WebAuthn metadata")
            .rp_id = rp_id.to_owned();
        assert_eq!(
            validate_wire_binding(&binding),
            Err(BrokerError::BindingMismatch),
            "{rp_id:?} must fail closed"
        );
    }
    for origin in [
        "http://review.example",
        "https://operator:secret@review.example",
        "https://review.example/path",
        "https://review.example?challenge=1",
        "https://review.example#fragment",
        "https://review.example:443",
        "https://foreign.example",
    ] {
        let mut binding = valid.clone();
        binding
            .evidence_viewer_webauthn_binding
            .as_mut()
            .expect("WebAuthn metadata")
            .allowed_origins = vec![origin.to_owned()];
        assert_eq!(
            validate_wire_binding(&binding),
            Err(BrokerError::BindingMismatch),
            "{origin:?} must fail closed"
        );
    }
    let substituted = EvidenceViewerVerifyAndConsumeRequestWireV1 {
        challenge: b"canonical-challenge".to_vec(),
        assertion: vec![0xA5],
        binding_digest: [0xB6; 32],
        rp_id: "other.example".to_owned(),
        allowed_origins: vec!["https://other.example".to_owned()],
        now_unix_ms: 1_000,
    };
    assert_eq!(
        validate_evidence_viewer_verify_and_consume_wire(&substituted, configured),
        Err(BrokerError::BindingMismatch)
    );
}
#[test]
fn signer_observation_requires_governance_peer_and_strong_ed25519_key() {
    let binding = signer_binding();
    assert_eq!(
        binding.governance_dag_publisher_peer_id.as_deref(),
        Some(b"12D3KooWRuntimeBrokerPrimary".as_slice())
    );
    assert_eq!(
        binding.governance_dag_publisher_public_key,
        Some(TEST_SIGNER_KEY)
    );
    validate_wire_binding(&binding).expect("accept pinned signer identity");
    let valid = observation(&binding);
    validate_observation(&binding, &valid).expect("accept canonical signer metadata");
    let mut missing_peer = binding.clone();
    missing_peer.governance_dag_publisher_peer_id = None;
    assert_eq!(
        validate_wire_binding(&missing_peer),
        Err(BrokerError::BindingMismatch)
    );
    let mut missing_key = binding.clone();
    missing_key.governance_dag_publisher_public_key = None;
    assert_eq!(
        validate_wire_binding(&missing_key),
        Err(BrokerError::BindingMismatch)
    );
    let mut substituted_peer = valid.clone();
    substituted_peer
        .signer_metadata
        .as_mut()
        .expect("signer metadata")
        .publisher_peer_id = b"12D3KooWRuntimeBrokerSecondary".to_vec();
    refresh_metadata_digest(&mut substituted_peer);
    assert_eq!(
        validate_observation(&binding, &substituted_peer),
        Err(BrokerError::BindingMismatch)
    );
    let mut substituted_key = valid.clone();
    substituted_key
        .signer_metadata
        .as_mut()
        .expect("signer metadata")
        .public_key = server_test_request_auth_public_key();
    refresh_metadata_digest(&mut substituted_key);
    assert_eq!(
        validate_observation(&binding, &substituted_key),
        Err(BrokerError::BindingMismatch)
    );
    let mut oversized_peer = valid.clone();
    oversized_peer
        .signer_metadata
        .as_mut()
        .expect("signer metadata")
        .publisher_peer_id = vec![b'A'; GOVERNANCE_DAG_PUBLISHER_PEER_ID_MAX_BYTES_V1 + 1];
    refresh_metadata_digest(&mut oversized_peer);
    assert_eq!(
        validate_observation(&binding, &oversized_peer),
        Err(BrokerError::BindingMismatch)
    );
    for peer_id in [b"peer id".to_vec(), vec![0x7F], vec![0x80]] {
        let mut nonvisible_peer = valid.clone();
        nonvisible_peer
            .signer_metadata
            .as_mut()
            .expect("signer metadata")
            .publisher_peer_id = peer_id;
        refresh_metadata_digest(&mut nonvisible_peer);
        assert_eq!(
            validate_observation(&binding, &nonvisible_peer),
            Err(BrokerError::BindingMismatch)
        );
    }
    let mut identity_key = [0; 32];
    identity_key[0] = 1;
    for public_key in [[0; 32], identity_key, [0xFF; 32]] {
        let mut invalid_key = valid.clone();
        invalid_key
            .signer_metadata
            .as_mut()
            .expect("signer metadata")
            .public_key = public_key;
        refresh_metadata_digest(&mut invalid_key);
        assert_eq!(
            validate_observation(&binding, &invalid_key),
            Err(BrokerError::BindingMismatch)
        );
    }
}
#[test]
fn server_governance_signer_must_match_the_configured_publisher_identity() {
    let catalog = server_test_catalog();
    let configured = catalog.iter().next().expect("configured signer");
    let binding = ProviderBindingWireV1::try_from_binding(configured)
        .expect("project configured Governance signer");
    assert_eq!(binding, signer_binding_for_server());
    make_server_observation(network_id(), &binding, &server_test_backends())
        .expect("accept exact configured signer identity");
    let mut substituted_peer = binding.clone();
    substituted_peer.governance_dag_publisher_peer_id =
        Some(b"12D3KooWRuntimeBrokerServerSecondary".to_vec());
    validate_wire_binding(&substituted_peer).expect("substituted peer remains structurally valid");
    assert!(matches!(
        make_server_observation(network_id(), &substituted_peer, &server_test_backends()),
        Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch)
    ));
    let mut substituted_key = binding;
    substituted_key.governance_dag_publisher_public_key =
        Some(server_test_request_auth_public_key());
    validate_wire_binding(&substituted_key).expect("substituted key remains structurally valid");
    assert!(matches!(
        make_server_observation(network_id(), &substituted_key, &server_test_backends()),
        Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch)
    ));
}
#[test]
fn governance_request_auth_binds_scope_key_signature_and_body_bound() {
    let catalog = request_auth_server_test_catalog();
    assert!(matches!(
        prepare_test_server_state(&catalog, RuntimeProviderBrokerBackendsV1::new()),
        Err(RuntimeProviderBrokerServerErrorV1::BackendSetMismatch)
    ));
    assert!(matches!(
        prepare_test_server_state(
            &catalog,
            RuntimeProviderBrokerBackendsV1::new().with_governance_dag_ipfs_authenticator(
                Arc::new(ServerTestGovernanceRequestAuthenticator::with_public_key(
                    TEST_SIGNER_KEY,
                ),)
            ),
        ),
        Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch)
    ));
    assert!(matches!(
        prepare_test_server_state(
            &catalog,
            request_auth_server_test_backends().with_governance_dag_head_authenticator(Arc::new(
                ServerTestGovernanceRequestAuthenticator::exact()
            )),
        ),
        Err(RuntimeProviderBrokerServerErrorV1::BackendSetMismatch)
    ));
    let state = request_auth_server_test_state();
    let binding = &state.catalog[0];
    let ingress_wire = binding
        .governance_request_ingress_binding
        .expect("request-auth ingress binding");
    assert_eq!(
        governance_request_ingress_binding_from_wire(ingress_wire),
        Ok(server_test_request_ingress_binding(
            server_test_request_auth_public_key()
        ))
    );
    let mut missing_key = binding.clone();
    missing_key.governance_request_ingress_binding = None;
    assert_eq!(
        validate_wire_binding(&missing_key),
        Err(BrokerError::BindingMismatch)
    );
    let mut zero_bound = binding.clone();
    zero_bound
        .governance_request_ingress_binding
        .as_mut()
        .expect("request-auth ingress binding")
        .max_body_bytes = 0;
    assert_eq!(
        validate_wire_binding(&zero_bound),
        Err(BrokerError::BindingMismatch)
    );
    let qualification = sorafs_node::GovernanceDagRequestAuthenticator::ingress_qualification(
        &ServerTestGovernanceRequestAuthenticator::exact(),
    )
    .expect("qualify exact request ingress");
    let qualification_wire = governance_request_ingress_qualification_to_wire(qualification);
    assert_eq!(
        governance_request_ingress_qualification_from_wire(qualification_wire),
        Ok(qualification)
    );
    let mut zero_replay = qualification_wire;
    zero_replay.replay_namespace_digest = [0; 32];
    assert_eq!(
        governance_request_ingress_qualification_from_wire(zero_replay),
        Err(BrokerError::Protocol)
    );
    let request =
        canonical_request_auth_test_request(sorafs_node::GovernanceDagAuthenticationScope::Ipfs);
    let wire = governance_request_auth_to_wire(&request);
    assert_eq!(
        governance_request_auth_from_wire(&wire, 1024),
        Ok(request.clone())
    );
    let authenticator = ServerTestGovernanceRequestAuthenticator::exact();
    let envelope =
        sorafs_node::GovernanceDagRequestAuthenticator::authenticate(&authenticator, &request)
            .expect("sign canonical broker request");
    let result = governance_request_auth_result_to_wire(&envelope);
    assert_eq!(
        validate_governance_request_auth_envelope(
            &request,
            result,
            server_test_request_auth_public_key(),
        ),
        Ok(envelope)
    );
    let mut bad_signature = result;
    bad_signature.signature[0] ^= 1;
    assert_eq!(
        validate_governance_request_auth_envelope(
            &request,
            bad_signature,
            server_test_request_auth_public_key(),
        ),
        Err(BrokerError::Rejected)
    );
    let mut substituted_key = result;
    substituted_key.public_key[0] ^= 1;
    assert_eq!(
        validate_governance_request_auth_envelope(
            &request,
            substituted_key,
            server_test_request_auth_public_key(),
        ),
        Err(BrokerError::BindingMismatch)
    );
    let mut oversized_body = wire.clone();
    oversized_body.body_length = 1025;
    assert_eq!(
        governance_request_auth_from_wire(&oversized_body, 1024),
        Err(BrokerError::Rejected)
    );
    let mut percent_alias = wire.clone();
    percent_alias.canonical_url = "https://kubo.example/api/%41".to_owned();
    assert_eq!(
        governance_request_auth_from_wire(&percent_alias, 1024),
        Err(BrokerError::Rejected)
    );
    let mut noncanonical_url = wire;
    noncanonical_url.canonical_url = "https://kubo.example/api/v0/dag/put?z=1&a=2".to_owned();
    assert_eq!(
        governance_request_auth_from_wire(&noncanonical_url, 1024),
        Err(BrokerError::Rejected)
    );
    let wrong_scope = canonical_request_auth_test_request(
        sorafs_node::GovernanceDagAuthenticationScope::SignedHead,
    );
    let payload = encode_canonical(
        &governance_request_auth_to_wire(&wrong_scope),
        MAX_GOVERNANCE_REQUEST_AUTH_FRAME_BYTES_V1,
    )
    .expect("encode wrong-scope request-auth operation");
    let operation = make_operation_request(
        TEST_SESSION_ID,
        1,
        binding.clone(),
        state.observations[0].metadata_digest,
        OPERATION_GOVERNANCE_REQUEST_AUTHENTICATE_V1,
        payload,
    )
    .expect("seal wrong-scope request-auth operation");
    assert_eq!(
        validate_operation_request(&operation),
        Err(BrokerError::BindingMismatch)
    );
}
#[test]
fn governance_request_auth_round_trips_over_the_stock_broker() {
    let (_directory, policy, shutdown, server) = start_request_auth_test_server();
    let dependencies = resolve_test_process(&request_auth_server_test_catalog(), &policy)
        .expect("resolve request-auth broker dependency");
    let authenticator = dependencies
        .sorafs_governance_dag_ipfs_authenticator
        .as_ref()
        .expect("resolved IPFS request authenticator");
    let ingress_qualification = authenticator
        .ingress_qualification()
        .expect("qualify resolved IPFS request ingress");
    assert_eq!(
        ingress_qualification.binding().public_key(),
        server_test_request_auth_public_key()
    );
    assert_eq!(
        ingress_qualification,
        server_test_request_ingress_qualification(server_test_request_auth_public_key())
    );
    let request =
        canonical_request_auth_test_request(sorafs_node::GovernanceDagAuthenticationScope::Ipfs);
    let envelope = authenticator
        .authenticate(&request)
        .expect("broker signs the exact canonical request");
    assert_eq!(envelope.scope(), request.scope());
    assert_eq!(envelope.request_digest(), request.request_digest());
    assert_eq!(envelope.public_key(), server_test_request_auth_public_key());
    drop(dependencies);
    shutdown.request_shutdown();
    server
        .join()
        .expect("join request-auth broker")
        .expect("request-auth broker exits cleanly");
}
#[test]
fn native_signer_catalog_backend_set_and_identity_are_exact() {
    use iroha_torii::SorafsNativeTransactionSignerRoleV1 as Role;
    let catalog = native_signer_test_catalog();
    let wire = catalog
        .iter()
        .map(ProviderBindingWireV1::try_from_binding)
        .collect::<Result<Vec<_>, _>>()
        .expect("project native signer catalog");
    assert_eq!(wire.len(), 4);
    for (projected, configured) in wire.iter().zip(catalog.iter()) {
        validate_wire_binding(projected).expect("accept exact native signer binding");
        assert_eq!(
            native_transaction_signer_binding_from_wire(projected)
                .expect("reconstruct native signer binding"),
            configured
                .native_signer_binding()
                .expect("configured native signer binding")
                .clone()
        );
    }
    let mut role_confused_wire = wire[0].clone();
    role_confused_wire
        .native_signer_binding
        .as_mut()
        .expect("native signer metadata")
        .role = native_transaction_signer_role_to_wire(Role::Repair);
    assert_eq!(
        validate_wire_binding(&role_confused_wire),
        Err(BrokerError::BindingMismatch)
    );
    let mut missing_native_identity = wire[0].clone();
    missing_native_identity.native_signer_binding = None;
    assert_eq!(
        validate_wire_binding(&missing_native_identity),
        Err(BrokerError::BindingMismatch)
    );
    assert!(matches!(
        prepare_test_server_state(&catalog, RuntimeProviderBrokerBackendsV1::new()),
        Err(RuntimeProviderBrokerServerErrorV1::BackendSetMismatch)
    ));
    assert!(matches!(
        prepare_test_server_state(
            &proof_native_signer_test_catalog(),
            native_signer_test_backends(),
        ),
        Err(RuntimeProviderBrokerServerErrorV1::BackendSetMismatch)
    ));
    assert!(matches!(
        prepare_test_server_state(
            &proof_native_signer_test_catalog(),
            RuntimeProviderBrokerBackendsV1::new().with_proof_outcome_transaction_signer(Arc::new(
                ServerTestNativeSigner::exact(Role::ProofOutcome).with_seed(0xE1),
            )),
        ),
        Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch)
    ));
    assert!(matches!(
        prepare_test_server_state(
            &proof_native_signer_test_catalog(),
            RuntimeProviderBrokerBackendsV1::new().with_proof_outcome_transaction_signer(Arc::new(
                ServerTestNativeSigner::exact(Role::ProofOutcome).with_role(Role::Repair),
            )),
        ),
        Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch)
    ));
    prepare_test_server_state(&catalog, native_signer_test_backends())
        .expect("accept all four independently injected native signer roles");
}
#[test]
fn broker_server_accepts_exact_subset_and_confines_session_to_it() {
    let (_directory, policy, shutdown, server) = start_native_signer_test_server();
    let proof_catalog = proof_native_signer_test_catalog();
    let proof_binding = ProviderBindingWireV1::try_from_binding(
        proof_catalog.iter().next().expect("proof signer binding"),
    )
    .expect("project proof signer binding");
    assert!(
        connect_test_process(
            &policy,
            proof_catalog.chain_id(),
            test_network_id(0x16),
            vec![proof_binding.clone()],
        )
        .is_err(),
        "the same display chain on another genesis lineage must not authenticate",
    );
    let (session, observations) = connect_test_process(
        &policy,
        proof_catalog.chain_id(),
        *proof_catalog.network_id(),
        vec![proof_binding.clone()],
    )
    .expect("connect with an exact subset of the server catalog");
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].binding, proof_binding);
    let full_state =
        prepare_test_server_state(&native_signer_test_catalog(), native_signer_test_backends())
            .expect("prepare full native signer state");
    let repair_slot = IrohaRuntimeProviderSlotV1::RepairTransactionSigner.wire_id();
    let repair_index = full_state
        .catalog
        .iter()
        .position(|binding| binding.slot == repair_slot)
        .expect("repair signer in full server catalog");
    let repair_binding = &full_state.catalog[repair_index];
    let repair_metadata_digest = full_state.observations[repair_index].metadata_digest;
    let unit =
        encode_canonical(&(), MAX_OPERATION_FRAME_BYTES_V1).expect("encode qualification payload");
    assert!(
        matches!(
            session.call(
                repair_binding,
                repair_metadata_digest,
                OPERATION_QUALIFY_V1,
                unit,
                false,
            ),
            Err(BrokerError::Unavailable)
        ),
        "a session cannot invoke a configured role omitted from its handshake"
    );
    drop(session);
    shutdown.request_shutdown();
    server
        .join()
        .expect("join native signer broker")
        .expect("native signer broker exits cleanly");
}
#[test]
fn canonical_broker_codec_accounts_for_variable_payload_frame_header() {
    use norito::SerializePayload as _;

    let value = SoracloudProvenanceSignRequestWireV1 {
        purpose: iroha_data_model::soracloud::SoracloudRuntimeProvenancePurposeV1::InrouHostAdvert
            .wire_id(),
        preimage: vec![0xA5; 257],
    };
    assert_broker_frame_owner(
        &value,
        "irohad::runtime_provider_broker::protocol::SoracloudProvenanceSignRequestWireV1",
        MAX_GOVERNANCE_SIGNING_FRAME_BYTES_V1,
    );
    let bare_payload_len = value
        .encoded_len_exact()
        .expect("variable request has an exact bare payload length");
    let framed_len =
        norito::canonical_frame_len(&value).expect("compute exact canonical framed length");
    assert!(
        framed_len > bare_payload_len,
        "the outer Norito frame must be included in broker limits"
    );
    let pool = Arc::new(DecodeResourcePoolV1::new(
        CONTROL_DECODE_POLICY_V1.max_composed_bytes,
    ));
    let admission = DecodeResourceAdmissionV1::acquire_from(pool, None, CONTROL_DECODE_POLICY_V1)
        .expect("acquire isolated broker admission");
    let framed = {
        let _scope = admission.enter();
        encode_canonical(&value, framed_len).expect("encode at the exact canonical frame limit")
    };
    assert_eq!(framed.len(), framed_len);
    assert_eq!(
        admission
            .usage
            .lock()
            .expect("read isolated broker admission")
            .consumed_bytes,
        framed_len,
        "encoder admission must charge the full canonical frame"
    );
    assert_eq!(
        encode_canonical(&value, framed_len - 1),
        Err(BrokerError::Rejected),
        "a limit that excludes one frame byte must fail closed"
    );
    assert_eq!(
        decode_canonical::<SoracloudProvenanceSignRequestWireV1>(&framed, framed_len)
            .expect("decode the exact canonical variable request"),
        value
    );
}
#[test]
fn soracloud_broker_admission_rejects_explicit_purpose_mismatch() {
    let native = proof_native_signer_test_catalog();
    let mut binding = ProviderBindingWireV1::try_from_binding(
        native.iter().next().expect("proof signer binding"),
    )
    .expect("project signer binding");
    binding.slot = IrohaRuntimeProviderSlotV1::SoracloudRuntimeMutationSigner.wire_id();
    binding.handle = "software://sorafs/ai/runtime-broker-primary".to_owned();
    binding
        .native_signer_binding
        .as_mut()
        .expect("signer identity")
        .role = SORACLOUD_RUNTIME_SIGNER_ROLE_WIRE_V1;
    validate_wire_binding(&binding).expect("accept Soracloud signer binding");
    let preimage = iroha_data_model::soracloud::encode_soracloud_runtime_provenance_preimage_v1(
        iroha_data_model::soracloud::SoracloudRuntimeProvenancePurposeV1::InrouHostAdvert,
        b"canonical semantic payload",
    )
    .expect("encode purpose-bound preimage");
    let valid_payload = encode_canonical(
        &SoracloudProvenanceSignRequestWireV1 {
            purpose:
                iroha_data_model::soracloud::SoracloudRuntimeProvenancePurposeV1::InrouHostAdvert
                    .wire_id(),
            preimage: preimage.clone(),
        },
        MAX_NATIVE_TRANSACTION_FRAME_BYTES_V1,
    )
    .expect("encode valid request");
    let valid = make_operation_request(
        TEST_SESSION_ID,
        1,
        binding.clone(),
        [0xC1; 32],
        OPERATION_SORACLOUD_PROVENANCE_SIGN_V1,
        valid_payload,
    )
    .expect("seal valid request");
    validate_operation_request(&valid).expect("accept matching purpose");
    let mismatched_payload = encode_canonical(
        &SoracloudProvenanceSignRequestWireV1 {
            purpose:
                iroha_data_model::soracloud::SoracloudRuntimeProvenancePurposeV1::InrouHostWithdraw
                    .wire_id(),
            preimage,
        },
        MAX_NATIVE_TRANSACTION_FRAME_BYTES_V1,
    )
    .expect("encode mismatched request");
    let mismatched = make_operation_request(
        TEST_SESSION_ID,
        2,
        binding,
        [0xC1; 32],
        OPERATION_SORACLOUD_PROVENANCE_SIGN_V1,
        mismatched_payload,
    )
    .expect("seal mismatched request");
    assert_eq!(
        validate_operation_request(&mismatched),
        Err(BrokerError::Rejected)
    );
}
#[test]
fn native_signer_payload_hard_cut_precedes_provider_use() {
    use iroha_torii::SorafsNativeTransactionSignerRoleV1 as Role;
    let signer = Arc::new(ServerTestNativeSigner::exact(Role::ProofOutcome));
    let state = proof_native_signer_test_state(signer.clone());
    let exact = native_transaction_signer_binding_from_wire(&state.catalog[0])
        .expect("native signer binding");
    let payload = native_signer_test_payload(exact.role(), exact.authority().clone());
    let canonical = encode_native_transaction_payload(&payload).expect("canonical payload");
    assert_eq!(
        decode_native_transaction_payload(&canonical),
        Ok(payload.clone())
    );
    assert_eq!(
        decode_native_transaction_payload(&[]),
        Err(BrokerError::Rejected)
    );
    assert_eq!(
        decode_native_transaction_payload(&[0xFF]),
        Err(BrokerError::Rejected)
    );
    assert!(
        canonical[0] < 0x80,
        "the fixture starts with a canonical compact field length"
    );
    let mut noncanonical = Vec::with_capacity(canonical.len() + 1);
    noncanonical.push(canonical[0] | 0x80);
    noncanonical.push(0);
    noncanonical.extend_from_slice(&canonical[1..]);
    assert_eq!(
        decode_native_transaction_payload(&noncanonical),
        Err(BrokerError::Rejected)
    );
    let mut trailing = canonical.clone();
    trailing.push(0);
    assert_eq!(
        decode_native_transaction_payload(&trailing),
        Err(BrokerError::Rejected)
    );
    assert_eq!(
        decode_native_transaction_payload(&vec![0; MAX_NATIVE_TRANSACTION_PAYLOAD_BYTES_V1 + 1]),
        Err(BrokerError::Rejected)
    );
    let other =
        iroha_crypto::KeyPair::try_from_seed(vec![0xD1; 32], iroha_crypto::Algorithm::Ed25519)
            .expect("derive wrong native signer authority");
    let wrong_authority = native_signer_test_payload(
        Role::ProofOutcome,
        iroha_data_model::account::AccountId::new(other.public_key().clone()),
    );
    let wrong_request = make_operation_request(
        TEST_SESSION_ID,
        1,
        state.catalog[0].clone(),
        state.observations[0].metadata_digest,
        OPERATION_NATIVE_TRANSACTION_SIGN_V1,
        encode_native_transaction_payload(&wrong_authority)
            .expect("encode wrong-authority payload"),
    )
    .expect("seal wrong-authority request");
    assert_eq!(
        validate_operation_request(&wrong_request),
        Err(BrokerError::Rejected)
    );
    assert_eq!(signer.sign_calls.load(Ordering::Relaxed), 0);
    let cross_network = native_signer_test_payload_for_network(
        exact.role(),
        test_network_id(0x16),
        exact.authority().clone(),
    );
    let cross_network_request = make_operation_request(
        TEST_SESSION_ID,
        2,
        state.catalog[0].clone(),
        state.observations[0].metadata_digest,
        OPERATION_NATIVE_TRANSACTION_SIGN_V1,
        encode_native_transaction_payload(&cross_network)
            .expect("encode cross-network native signer payload"),
    )
    .expect("seal cross-network native signer request");
    validate_operation_request(&cross_network_request)
        .expect("cross-network payload is structurally canonical");
    assert_eq!(
        dispatch_server_operation(&state, &cross_network_request),
        Err(BrokerError::BindingMismatch)
    );
    assert_eq!(
        signer.sign_calls.load(Ordering::Relaxed),
        0,
        "the external signer boundary must not see a foreign-network transaction"
    );
    let request = make_operation_request(
        TEST_SESSION_ID,
        3,
        state.catalog[0].clone(),
        state.observations[0].metadata_digest,
        OPERATION_NATIVE_TRANSACTION_SIGN_V1,
        canonical,
    )
    .expect("seal exact native signer request");
    validate_operation_request(&request).expect("validate exact native signer request");
    let signed_transaction = dispatch_server_operation(&state, &request)
        .and_then(|bytes| {
            decode_canonical::<iroha_data_model::transaction::SignedTransaction>(
                &bytes,
                MAX_NATIVE_SIGNED_TRANSACTION_BYTES_V1,
            )
        })
        .expect("sign exact canonical payload");
    assert_eq!(signed_transaction.payload(), &payload);
    signed_transaction
        .verify_signature()
        .expect("verify exact signed payload");
    assert_eq!(signer.sign_calls.load(Ordering::Relaxed), 1);
}
#[test]
fn native_signer_rejects_tampered_and_drifting_provider_outputs() {
    use iroha_torii::SorafsNativeTransactionSignerRoleV1 as Role;
    for (mode, expected) in [
        (
            ServerTestNativeSignerMode::InvalidSignature,
            BrokerError::Ambiguous,
        ),
        (
            ServerTestNativeSignerMode::DriftAfterSign,
            BrokerError::StaleOrRevoked,
        ),
    ] {
        let signer = Arc::new(ServerTestNativeSigner::exact(Role::ProofOutcome).with_mode(mode));
        let state = proof_native_signer_test_state(signer.clone());
        let exact = native_transaction_signer_binding_from_wire(&state.catalog[0])
            .expect("native signer binding");
        let payload = native_signer_test_payload(exact.role(), exact.authority().clone());
        let request = make_operation_request(
            TEST_SESSION_ID,
            1,
            state.catalog[0].clone(),
            state.observations[0].metadata_digest,
            OPERATION_NATIVE_TRANSACTION_SIGN_V1,
            encode_native_transaction_payload(&payload).expect("encode native signer payload"),
        )
        .expect("seal native signer request");
        validate_operation_request(&request).expect("validate canonical native signer request");
        assert_eq!(dispatch_server_operation(&state, &request), Err(expected));
        assert_eq!(signer.sign_calls.load(Ordering::Relaxed), 1);
    }
}
#[test]
fn appeal_finance_signer_rejects_cross_network_before_provider_use() {
    let signer = Arc::new(ServerTestAppealFinanceSigner::exact());
    let state = appeal_finance_signer_test_state(signer.clone());
    let exact = state.catalog[0]
        .appeal_finance_signer_binding
        .as_ref()
        .expect("exact appeal-finance signer binding");
    let cross_network =
        transaction_signer_test_payload_for_network(test_network_id(0x16), exact.authority.clone());
    let cross_network_request = make_operation_request(
        TEST_SESSION_ID,
        1,
        state.catalog[0].clone(),
        state.observations[0].metadata_digest,
        OPERATION_APPEAL_FINANCE_TRANSACTION_SIGN_V1,
        encode_transaction_payload_bounded(&cross_network, MAX_APPEAL_FINANCE_TRANSACTION_BYTES_V1)
            .expect("encode cross-network appeal-finance payload"),
    )
    .expect("seal cross-network appeal-finance signer request");
    validate_operation_request(&cross_network_request)
        .expect("cross-network appeal-finance payload is structurally canonical");
    assert_eq!(
        dispatch_server_operation(&state, &cross_network_request),
        Err(BrokerError::BindingMismatch)
    );
    assert_eq!(
        signer.sign_calls.load(Ordering::Relaxed),
        0,
        "the appeal-finance external signer must not see a foreign-network transaction"
    );
    let exact_payload =
        transaction_signer_test_payload_for_network(network_id(), exact.authority.clone());
    let exact_request = make_operation_request(
        TEST_SESSION_ID,
        2,
        state.catalog[0].clone(),
        state.observations[0].metadata_digest,
        OPERATION_APPEAL_FINANCE_TRANSACTION_SIGN_V1,
        encode_transaction_payload_bounded(&exact_payload, MAX_APPEAL_FINANCE_TRANSACTION_BYTES_V1)
            .expect("encode exact appeal-finance payload"),
    )
    .expect("seal exact appeal-finance signer request");
    validate_operation_request(&exact_request)
        .expect("validate exact appeal-finance signer request");
    let signed_transaction = dispatch_server_operation(&state, &exact_request)
        .and_then(|bytes| {
            decode_canonical::<iroha_data_model::transaction::SignedTransaction>(
                &bytes,
                MAX_APPEAL_FINANCE_TRANSACTION_FRAME_BYTES_V1,
            )
        })
        .expect("sign exact appeal-finance payload");
    assert_eq!(signed_transaction.payload(), &exact_payload);
    signed_transaction
        .verify_signature()
        .expect("verify appeal-finance transaction signature");
    assert_eq!(signer.sign_calls.load(Ordering::Relaxed), 1);
}
#[test]
fn native_signer_proxy_poisons_the_session_after_tamper_or_drift() {
    use iroha_torii::{
        SoraFsProofOutcomeSigningError as SigningError,
        SorafsNativeTransactionSignerProbeErrorV1 as ProbeError,
        SorafsNativeTransactionSignerRoleV1 as Role,
    };
    for mode in [
        ServerTestNativeSignerMode::InvalidSignature,
        ServerTestNativeSignerMode::DriftAfterSign,
    ] {
        let catalog = proof_native_signer_test_catalog();
        let backend = Arc::new(ServerTestNativeSigner::exact(Role::ProofOutcome).with_mode(mode));
        let (_directory, policy, shutdown, server) = start_native_signer_server(
            catalog.clone(),
            RuntimeProviderBrokerBackendsV1::new().with_proof_outcome_transaction_signer(backend),
        );
        let dependencies =
            resolve_test_process(&catalog, &policy).expect("resolve proof-outcome signer proxy");
        let binding = catalog
            .iter()
            .next()
            .and_then(IrohaRuntimeProviderBindingV1::native_signer_binding)
            .expect("proof-outcome signer binding");
        let signer = dependencies
            .sorafs_proof_outcome_signer
            .as_ref()
            .expect("resolved proof-outcome signer");
        let payload = native_signer_test_payload(binding.role(), binding.authority().clone());
        assert_eq!(
            signer.sign(payload),
            Err(SigningError::QualificationChanged),
            "a substituted or drifting response poisons the qualified proxy"
        );
        assert_eq!(
            signer.public_key(),
            Err(ProbeError::Unavailable),
            "a poisoned signer session cannot be reused"
        );
        drop(dependencies);
        shutdown.request_shutdown();
        server
            .join()
            .expect("join adversarial native signer broker")
            .expect("adversarial native signer broker exits cleanly");
    }
}
#[test]
fn all_native_signer_roles_round_trip_over_the_stock_broker() {
    let catalog = native_signer_test_catalog();
    let (_directory, policy, shutdown, server) = start_native_signer_test_server();
    let dependencies =
        resolve_test_process(&catalog, &policy).expect("resolve all native signer broker roles");
    macro_rules! assert_role_round_trip {
        ($field:ident, $slot:ident, $qualifier:ident, $error:ident) => {{
            let binding = catalog
                .iter()
                .find(|binding| binding.slot() == IrohaRuntimeProviderSlotV1::$slot)
                .and_then(IrohaRuntimeProviderBindingV1::native_signer_binding)
                .expect("native signer catalog binding")
                .clone();
            let proxy = dependencies
                .$field
                .as_ref()
                .expect("resolved native signer proxy")
                .clone();
            let signer = iroha_torii::$qualifier(network_id(), binding.clone(), proxy)
                .expect("outer registry re-qualifies native signer proxy");
            let payload = native_signer_test_payload(binding.role(), binding.authority().clone());
            let mut foreign = payload.clone();
            foreign.domain =
                iroha_data_model::transaction::TransactionDomain::Network(test_network_id(0x16));
            assert_eq!(signer.sign(foreign), Err(iroha_torii::$error::Refused));
            let mut absent = payload.clone();
            absent.domain = iroha_data_model::transaction::TransactionDomain::Genesis;
            assert_eq!(signer.sign(absent), Err(iroha_torii::$error::Refused));
            let signed = signer
                .sign(payload.clone())
                .expect("native signer broker signs exact payload");
            assert_eq!(signed.payload(), &payload);
            assert_eq!(signed.authority(), binding.authority());
            signed
                .verify_signature()
                .expect("native signer output signature verifies");
        }};
    }
    assert_role_round_trip!(
        sorafs_proof_outcome_signer,
        ProofOutcomeTransactionSigner,
        qualify_sorafs_proof_outcome_transaction_signer_v1,
        SoraFsProofOutcomeSigningError
    );
    assert_role_round_trip!(
        sorafs_repair_transaction_signer,
        RepairTransactionSigner,
        qualify_sorafs_repair_transaction_signer_v1,
        SoraFsRepairTransactionSigningError
    );
    assert_role_round_trip!(
        sorafs_reserve_transaction_signer,
        ReserveTransactionSigner,
        qualify_sorafs_reserve_transaction_signer_v1,
        SoraFsReserveTransactionSigningError
    );
    assert_role_round_trip!(
        sorafs_orderbook_transaction_signer,
        OrderbookTransactionSigner,
        qualify_sorafs_orderbook_transaction_signer_v1,
        SoraFsOrderbookTransactionSigningError
    );
    drop(dependencies);
    shutdown.request_shutdown();
    server
        .join()
        .expect("join native signer broker")
        .expect("native signer broker exits cleanly");
}
#[test]
fn moderation_transaction_signer_binding_backend_and_identity_are_exact() {
    let catalog = moderation_transaction_signer_test_catalog();
    let binding = catalog
        .iter()
        .next()
        .map(ProviderBindingWireV1::try_from_binding)
        .transpose()
        .expect("project moderation transaction signer binding")
        .expect("moderation transaction signer binding");
    validate_wire_binding(&binding).expect("accept exact moderation transaction signer binding");
    assert!(
        binding.native_signer_binding.is_none(),
        "slot 18 uses only its exact outer provider binding"
    );
    let mut role_confused = binding.clone();
    role_confused.native_signer_binding = proof_native_signer_test_catalog()
        .iter()
        .next()
        .and_then(IrohaRuntimeProviderBindingV1::native_signer_binding)
        .map(NativeTransactionSignerBindingWireV1::from_binding);
    assert_eq!(
        validate_wire_binding(&role_confused),
        Err(BrokerError::BindingMismatch),
        "slot 18 must reject the authority-pinned native-role discriminator"
    );
    assert!(matches!(
        prepare_test_server_state(&catalog, RuntimeProviderBrokerBackendsV1::new()),
        Err(RuntimeProviderBrokerServerErrorV1::BackendSetMismatch)
    ));
    assert_eq!(
        validate_exact_backend_set(
            &[],
            &RuntimeProviderBrokerBackendsV1::new().with_moderation_transaction_signer(Arc::new(
                ServerTestModerationTransactionSigner::exact()
            )),
        ),
        Err(RuntimeProviderBrokerServerErrorV1::BackendSetMismatch)
    );
    for signer in [
        ServerTestModerationTransactionSigner::exact()
            .with_handle("software://sorafs/moderation/substituted"),
        ServerTestModerationTransactionSigner::exact().with_revision(8),
        ServerTestModerationTransactionSigner::exact()
            .with_mode(ServerTestModerationTransactionSignerMode::DriftOnSecondQualification),
    ] {
        assert!(matches!(
            prepare_test_server_state(
                &catalog,
                RuntimeProviderBrokerBackendsV1::new()
                    .with_moderation_transaction_signer(Arc::new(signer)),
            ),
            Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch)
        ));
    }
    prepare_test_server_state(
        &catalog,
        RuntimeProviderBrokerBackendsV1::new().with_moderation_transaction_signer(Arc::new(
            ServerTestModerationTransactionSigner::exact(),
        )),
    )
    .expect("accept the exact moderation transaction signer");
}
#[test]
fn moderation_transaction_signer_payload_and_result_are_exact() {
    let signer = Arc::new(ServerTestModerationTransactionSigner::exact());
    let state = moderation_transaction_signer_test_state(signer.clone());
    let payload = moderation_transaction_signer_test_payload();
    let canonical = encode_native_transaction_payload(&payload).expect("encode moderation payload");
    for malformed in [
        Vec::new(),
        vec![0xFF],
        {
            let mut trailing = canonical.clone();
            trailing.push(0);
            trailing
        },
        vec![0; MAX_NATIVE_TRANSACTION_PAYLOAD_BYTES_V1 + 1],
    ] {
        let request = make_operation_request(
            TEST_SESSION_ID,
            1,
            state.catalog[0].clone(),
            state.observations[0].metadata_digest,
            OPERATION_NATIVE_TRANSACTION_SIGN_V1,
            malformed,
        )
        .expect("seal malformed moderation signer request");
        assert!(
            validate_operation_request(&request).is_err(),
            "malformed payload must fail before provider use"
        );
    }
    assert_eq!(signer.sign_calls.load(Ordering::Relaxed), 0);
    let cross_network = transaction_signer_test_payload_for_network(
        test_network_id(0x16),
        payload.authority().clone(),
    );
    let cross_network_request = make_operation_request(
        TEST_SESSION_ID,
        2,
        state.catalog[0].clone(),
        state.observations[0].metadata_digest,
        OPERATION_NATIVE_TRANSACTION_SIGN_V1,
        encode_native_transaction_payload(&cross_network)
            .expect("encode cross-network moderation payload"),
    )
    .expect("seal cross-network moderation signer request");
    validate_operation_request(&cross_network_request)
        .expect("cross-network moderation payload is structurally canonical");
    assert_eq!(
        dispatch_server_operation(&state, &cross_network_request),
        Err(BrokerError::BindingMismatch)
    );
    assert_eq!(
        signer.sign_calls.load(Ordering::Relaxed),
        0,
        "the moderation external signer must not see a foreign-network transaction"
    );
    let request = make_operation_request(
        TEST_SESSION_ID,
        3,
        state.catalog[0].clone(),
        state.observations[0].metadata_digest,
        OPERATION_NATIVE_TRANSACTION_SIGN_V1,
        canonical,
    )
    .expect("seal exact moderation signer request");
    validate_operation_request(&request).expect("validate exact moderation signer request");
    let result =
        dispatch_server_operation(&state, &request).expect("sign exact moderation payload");
    validate_operation_result(&request, STATUS_OK_V1, &result, &state.network_id)
        .expect("accept exact signed moderation result");
    let signed_transaction = decode_canonical::<iroha_data_model::transaction::SignedTransaction>(
        &result,
        MAX_NATIVE_SIGNED_TRANSACTION_BYTES_V1,
    )
    .expect("decode exact signed moderation transaction");
    assert_eq!(signed_transaction.payload(), &payload);
    signed_transaction
        .verify_signature()
        .expect("verify moderation transaction signature");
    assert_eq!(signer.sign_calls.load(Ordering::Relaxed), 1);
    for mode in [
        ServerTestModerationTransactionSignerMode::InvalidSignature,
        ServerTestModerationTransactionSignerMode::SubstitutedPayload,
    ] {
        let fake = ServerTestModerationTransactionSigner::exact().with_mode(mode);
        let substituted =
            iroha_torii::sorafs::moderation_runtime::ModerationSignedTransactionSignerV1::sign(
                &fake,
                payload.clone(),
            )
            .expect("construct adversarial moderation signer result");
        let substituted = encode_canonical(&substituted, MAX_NATIVE_SIGNED_TRANSACTION_BYTES_V1)
            .expect("encode adversarial moderation signer result");
        assert_eq!(
            validate_operation_result(&request, STATUS_OK_V1, &substituted, &state.network_id,),
            Err(BrokerError::Protocol)
        );
    }
}
#[test]
fn moderation_transaction_signer_rejects_substitution_and_post_sign_drift() {
    for mode in [
        ServerTestModerationTransactionSignerMode::InvalidSignature,
        ServerTestModerationTransactionSignerMode::SubstitutedPayload,
        ServerTestModerationTransactionSignerMode::DriftAfterSign,
    ] {
        let signer = Arc::new(ServerTestModerationTransactionSigner::exact().with_mode(mode));
        let state = moderation_transaction_signer_test_state(signer.clone());
        let request = make_operation_request(
            TEST_SESSION_ID,
            1,
            state.catalog[0].clone(),
            state.observations[0].metadata_digest,
            OPERATION_NATIVE_TRANSACTION_SIGN_V1,
            encode_native_transaction_payload(&moderation_transaction_signer_test_payload())
                .expect("encode moderation transaction signer payload"),
        )
        .expect("seal moderation transaction signer request");
        validate_operation_request(&request)
            .expect("validate canonical moderation transaction signer request");
        assert_eq!(
            dispatch_server_operation(&state, &request),
            Err(BrokerError::StaleOrRevoked)
        );
        assert_eq!(signer.sign_calls.load(Ordering::Relaxed), 1);
    }
}
#[test]
fn moderation_transaction_signer_round_trips_and_poisons_on_substitution() {
    let catalog = moderation_transaction_signer_test_catalog();
    let (_directory, policy, shutdown, server) = start_native_signer_server(
        catalog.clone(),
        RuntimeProviderBrokerBackendsV1::new().with_moderation_transaction_signer(Arc::new(
            ServerTestModerationTransactionSigner::exact(),
        )),
    );
    let dependencies =
        resolve_test_process(&catalog, &policy).expect("resolve moderation transaction signer");
    let signer = dependencies
        .sorafs_moderation_transaction_signer
        .as_ref()
        .expect("resolved moderation transaction signer");
    let qualification =
        sorafs_node::moderation_orchestrator::ModerationRuntimeProviderV1::qualification(
            signer.as_ref(),
        )
        .expect("qualify moderation transaction signer proxy");
    assert_eq!(qualification.revision(), 7);
    assert_eq!(qualification.policy_digest(), TEST_POLICY_DIGEST);
    let payload = moderation_transaction_signer_test_payload();
    let signed_transaction =
        iroha_torii::sorafs::moderation_runtime::ModerationSignedTransactionSignerV1::sign(
            signer.as_ref(),
            payload.clone(),
        )
        .expect("moderation transaction signer proxy signs exact payload");
    assert_eq!(signed_transaction.payload(), &payload);
    signed_transaction
        .verify_signature()
        .expect("verify brokered moderation signature");
    drop(dependencies);
    shutdown.request_shutdown();
    server
        .join()
        .expect("join moderation transaction signer broker")
        .expect("moderation transaction signer broker exits cleanly");
    for mode in [
        ServerTestModerationTransactionSignerMode::InvalidSignature,
        ServerTestModerationTransactionSignerMode::DriftAfterSign,
    ] {
        let backend = Arc::new(ServerTestModerationTransactionSigner::exact().with_mode(mode));
        let (_directory, policy, shutdown, server) = start_native_signer_server(
            catalog.clone(),
            RuntimeProviderBrokerBackendsV1::new()
                .with_moderation_transaction_signer(backend.clone()),
        );
        let dependencies = resolve_test_process(&catalog, &policy)
            .expect("resolve adversarial moderation transaction signer");
        let signer = dependencies
            .sorafs_moderation_transaction_signer
            .as_ref()
            .expect("resolved adversarial moderation transaction signer");
        assert_eq!(
            iroha_torii::sorafs::moderation_runtime::ModerationSignedTransactionSignerV1::sign(
                signer.as_ref(),
                moderation_transaction_signer_test_payload(),
            ),
            Err(iroha_torii::sorafs::moderation_runtime::ModerationSigningFailureV1::Refused,)
        );
        let qualification_calls = backend.qualification_calls.load(Ordering::Relaxed);
        assert_eq!(backend.sign_calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            sorafs_node::moderation_orchestrator::ModerationRuntimeProviderV1::qualification(
                signer.as_ref()
            ),
            Err(
                sorafs_node::moderation_orchestrator::ModerationRuntimeProviderReadinessErrorV1::Rejected
            ),
            "a substituted or drifting signer poisons its broker session"
        );
        assert_eq!(
            iroha_torii::sorafs::moderation_runtime::ModerationSignedTransactionSignerV1::sign(
                signer.as_ref(),
                moderation_transaction_signer_test_payload(),
            ),
            Err(iroha_torii::sorafs::moderation_runtime::ModerationSigningFailureV1::Refused)
        );
        assert_eq!(backend.sign_calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            backend.qualification_calls.load(Ordering::Relaxed),
            qualification_calls,
            "the rejected session never requalifies or signs through the provider"
        );
        drop(dependencies);
        shutdown.request_shutdown();
        server
            .join()
            .expect("join adversarial moderation signer broker")
            .expect("adversarial moderation signer broker exits cleanly");
    }
}
#[test]
fn catalog_digest_binds_protocol_and_exact_network_identity() {
    let catalog = vec![signer_binding()];
    let network_id = server_test_network_id();
    let canonical_catalog = encode_canonical(&catalog, MAX_HANDSHAKE_FRAME_BYTES_V1)
        .expect("encode canonical test catalog");
    let digest = catalog_digest("test-chain", &network_id, &catalog)
        .expect("digest chain-bound test catalog");
    assert_eq!(
        digest,
        digest_parts(
            CATALOG_DIGEST_DOMAIN_V1,
            &[
                &BROKER_MAGIC_V1,
                &BROKER_VERSION_V1.to_be_bytes(),
                b"test-chain",
                network_id.as_bytes(),
                &canonical_catalog,
            ],
        )
    );
    assert_ne!(
        digest,
        catalog_digest("other-chain", &network_id, &catalog)
            .expect("digest catalog for a different chain")
    );
    assert_ne!(
        digest,
        catalog_digest("test-chain", &test_network_id(0x16), &catalog)
            .expect("digest catalog for a different exact network")
    );
    let mut substituted_peer = catalog.clone();
    substituted_peer[0].governance_dag_publisher_peer_id =
        Some(b"12D3KooWRuntimeBrokerSecondary".to_vec());
    assert_ne!(
        digest,
        catalog_digest("test-chain", &network_id, &substituted_peer)
            .expect("digest catalog with a substituted publisher peer ID")
    );
    let mut substituted_key = catalog.clone();
    substituted_key[0].governance_dag_publisher_public_key =
        Some(server_test_request_auth_public_key());
    assert_ne!(
        digest,
        catalog_digest("test-chain", &network_id, &substituted_key)
            .expect("digest catalog with a substituted publisher key")
    );
    let mut other_magic = BROKER_MAGIC_V1;
    other_magic[0] ^= 1;
    assert_ne!(
        digest,
        digest_parts(
            CATALOG_DIGEST_DOMAIN_V1,
            &[
                &other_magic,
                &BROKER_VERSION_V1.to_be_bytes(),
                b"test-chain",
                network_id.as_bytes(),
                &canonical_catalog,
            ],
        )
    );
    assert_ne!(
        digest,
        digest_parts(
            CATALOG_DIGEST_DOMAIN_V1,
            &[
                &BROKER_MAGIC_V1,
                &(BROKER_VERSION_V1 + 1).to_be_bytes(),
                b"test-chain",
                network_id.as_bytes(),
                &canonical_catalog,
            ],
        )
    );
}
#[test]
fn handshake_rejects_catalog_nonce_session_binding_metadata_and_transcript_confusion() {
    assert_eq!(
        make_handshake_request(
            "test-chain",
            server_test_network_id(),
            vec![checkpoint_binding(), signer_binding()],
            [0x42; 32],
        ),
        Err(BrokerError::BindingMismatch),
        "the requested catalog order is canonical"
    );
    assert_eq!(
        make_handshake_request(
            "test-chain",
            server_test_network_id(),
            vec![signer_binding()],
            [0; 32],
        ),
        Err(BrokerError::BindingMismatch),
        "a zero nonce cannot bind a fresh session"
    );
    let request = make_handshake_request(
        "test-chain",
        server_test_network_id(),
        vec![signer_binding(), checkpoint_binding()],
        [0x42; 32],
    )
    .expect("build handshake");
    let response = handshake_response(&request);
    validate_handshake_response(&request, &response).expect("validate exact handshake");
    for mutation in 0..9 {
        let mut confused = response.clone();
        match mutation {
            0 => confused.chain_id.push('x'),
            1 => confused.network_id = test_network_id(0x16),
            2 => confused.requested_catalog.swap(0, 1),
            3 => confused.client_nonce[0] ^= 1,
            4 => confused.session_id = [0; 32],
            5 => confused.observations.swap(0, 1),
            6 => confused.observations[0].binding.handle.push('x'),
            7 => confused.observations[0].metadata_digest[0] ^= 1,
            8 => confused.server_transcript_digest[0] ^= 1,
            _ => unreachable!(),
        }
        assert!(
            validate_handshake_response(&request, &confused).is_err(),
            "mutation {mutation} must fail"
        );
    }
}

#[test]
fn canonical_broker_encoding_counts_exact_output_and_limit_under_both_layouts() {
    let value = SoracloudProvenanceSignRequestWireV1 {
        purpose: iroha_data_model::soracloud::SoracloudRuntimeProvenancePurposeV1::InrouHostAdvert
            .wire_id(),
        preimage: vec![0xc1; 257],
    };
    let canonical = norito::encode_canonical(&value).unwrap();
    let mut different_ambient_length = false;
    for flags in [0, norito::core::header_flags::COMPACT_LEN] {
        let _ambient = norito::core::DecodeFlagsGuard::enter(flags);
        let ambient_before = norito::core::to_bytes(&value).unwrap();
        different_ambient_length |= ambient_before.len() != canonical.len();
        assert_eq!(
            norito::canonical_frame_len(&value).unwrap(),
            canonical.len()
        );
        let pool = Arc::new(DecodeResourcePoolV1::new(
            CONTROL_DECODE_POLICY_V1.max_composed_bytes,
        ));
        let admission =
            DecodeResourceAdmissionV1::acquire_from(pool, None, CONTROL_DECODE_POLICY_V1).unwrap();
        let scope = admission.enter();
        assert_eq!(
            encode_canonical(&value, canonical.len()).unwrap(),
            canonical,
            "layout {flags:#04x}"
        );
        let charged = admission.usage.lock().unwrap().consumed_bytes;
        assert_eq!(
            charged,
            canonical.len(),
            "only the complete canonical frame is charged"
        );
        assert_eq!(
            encode_canonical(&value, canonical.len() - 1),
            Err(BrokerError::Rejected)
        );
        assert_eq!(
            admission.usage.lock().unwrap().consumed_bytes,
            charged,
            "over-limit counting rejects before allocation/admission"
        );
        assert_eq!(
            decode_canonical::<SoracloudProvenanceSignRequestWireV1>(&canonical, canonical.len())
                .unwrap(),
            value
        );
        drop(scope);
        assert_eq!(
            norito::core::to_bytes(&value).unwrap(),
            ambient_before,
            "canonical broker encoding/decoding restores ambient layout"
        );
    }
    assert!(
        different_ambient_length,
        "the fixture exposes the former ambient count mismatch"
    );
}

#[test]
fn stream_token_discriminator_rejects_foreign_bulk_operations_before_reading_length() {
    let slot = IrohaRuntimeProviderSlotV1::StreamTokenSigner.wire_id();
    let allowed = [
        OPERATION_QUALIFY_V1,
        OPERATION_STREAM_TOKEN_SIGN_V1,
        OPERATION_STREAM_TOKEN_RECOVER_V1,
        OPERATION_STREAM_TOKEN_OBSERVE_V1,
        OPERATION_STREAM_TOKEN_CHECK_V1,
    ];
    let mut rejected = 0;
    for operation in 0..=u16::MAX {
        if !operation_is_known(operation) || allowed.contains(&operation) {
            continue;
        }
        let mut wire = slot.to_be_bytes().to_vec();
        wire.extend_from_slice(&operation.to_be_bytes());
        wire.extend_from_slice(&u32::MAX.to_be_bytes());
        let mut reader = Cursor::new(wire);
        let inbound = Arc::new(tokio::sync::Semaphore::new(1));
        let pool = Arc::new(DecodeResourcePoolV1::new(1));
        assert_eq!(
            read_operation_request_frame_inner(&mut reader, Some(inbound.clone()), Some(pool))
                .err(),
            Some(BrokerError::Protocol)
        );
        assert_eq!(
            reader.position(),
            4,
            "known foreign operation {operation} must not read even its length"
        );
        assert_eq!(
            inbound.available_permits(),
            1,
            "foreign bulk reservation cannot consume raw capacity"
        );
        rejected += 1;
    }
    assert!(
        rejected > 100,
        "cover every known unrelated operation, including all bulk paths"
    );
    for (slot, operation) in allowed
        .into_iter()
        .map(|operation| (slot, operation))
        .chain([
            (
                IrohaRuntimeProviderSlotV1::GovernanceDagSigner.wire_id(),
                OPERATION_SIGN_V1,
            ),
            (
                IrohaRuntimeProviderSlotV1::ProviderIngestAuthenticatedSource.wire_id(),
                OPERATION_PROVIDER_INGEST_SOURCE_FETCH_V1,
            ),
        ])
    {
        // This layer reads only discriminator and bounded raw frame; typed canonical validation follows.
        let body = [0xc2; 32];
        let mut wire = slot.to_be_bytes().to_vec();
        wire.extend_from_slice(&operation.to_be_bytes());
        wire.extend_from_slice(
            &(u32::try_from(body.len()).expect("fixture body length fits u32")).to_be_bytes(),
        );
        wire.extend_from_slice(&body);
        let mut reader = Cursor::new(wire);
        let (actual_slot, actual_operation, frame, _) =
            read_operation_request_frame_inner(&mut reader, None, None).unwrap();
        assert_eq!((actual_slot, actual_operation), (slot, operation));
        assert_eq!(&frame[..], &body);
        assert_eq!(
            reader.position(),
            40,
            "valid slot-11 and unrelated role admission remains intact"
        );
    }
}
