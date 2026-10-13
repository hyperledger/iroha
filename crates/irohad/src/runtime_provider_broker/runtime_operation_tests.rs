// Runtime-provider operation, endpoint, ambiguity, and billing regressions.
fn valid_governance_sign_request_payload() -> Vec<u8> {
    encode_canonical(
        &PurposeSignRequestWireV1 {
            purpose: sorafs_node::GovernanceDagSigningPurposeV1::KeyTransition.wire_id(),
            payload: sorafs_node::governance_dag_key_transition_signing_payload_v1(
                1, 2, [0x41; 32],
            )
            .expect("governance key-transition signing payload"),
        },
        MAX_OPERATION_FRAME_BYTES_V1,
    )
    .expect("encode governance sign request")
}
#[test]
#[expect(
    clippy::vec_init_then_push,
    reason = "sequential fixtures document the ordered mutating-operation inventory"
)]
fn evidence_viewer_operations_are_bounded_canonical_and_ambiguity_typed() {
    let webauthn = evidence_viewer_binding(IrohaRuntimeProviderSlotV1::EvidenceViewerWebAuthn);
    let grants = evidence_viewer_binding(IrohaRuntimeProviderSlotV1::EvidenceViewerGrantAuthority);
    let receipt = evidence_viewer_binding(IrohaRuntimeProviderSlotV1::EvidenceViewerReceiptSigner);
    let erasure = evidence_viewer_binding(IrohaRuntimeProviderSlotV1::EvidenceViewerErasure);
    let checkpoint =
        evidence_viewer_binding(IrohaRuntimeProviderSlotV1::EvidenceViewerCheckpointStore);
    let archive =
        evidence_viewer_binding(IrohaRuntimeProviderSlotV1::EvidenceViewerCompactionArchive);
    let publisher =
        evidence_viewer_binding(IrohaRuntimeProviderSlotV1::EvidenceViewerTransparencyPublisher);
    for operation in 40..=50 {
        assert!(operation_is_known(operation));
        assert!(operation_frame_limit(operation) <= MAX_EVIDENCE_VIEWER_BULK_FRAME_BYTES_V1);
    }
    for operation in [
        OPERATION_EVIDENCE_VIEWER_TRANSPARENCY_LOAD_V1,
        OPERATION_EVIDENCE_VIEWER_TRANSPARENCY_COMPARE_AND_PUBLISH_V1,
    ] {
        assert!(operation_is_known(operation));
        assert_eq!(
            operation_frame_limit(operation),
            MAX_EVIDENCE_VIEWER_BULK_FRAME_BYTES_V1
        );
    }
    assert_eq!(
        broker_error_status(BrokerError::Ambiguous),
        Some((STATUS_AMBIGUOUS_V1, true)),
        "mutation ambiguity must retire the authenticated session"
    );
    let qualify_publisher = validated_test_operation(
        publisher,
        OPERATION_QUALIFY_V1,
        encode_canonical(&(), MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1)
            .expect("encode transparency-publisher qualification"),
    );
    validate_operation_request(&qualify_publisher)
        .expect("transparency publisher supports only its qualified slot");
    let now_unix_ms = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_millis(),
    )
    .expect("timestamp fits u64");
    let claims = sorafs_node::evidence_viewer::EvidenceViewerGrantClaimsV1 {
        session_id: [0x11; 16],
        case_id: "case-1".to_owned(),
        round_id: "round-1".to_owned(),
        quarantine_id: [0x12; 16],
        viewer_account: "viewer".to_owned(),
        role: sorafs_node::evidence_viewer::EvidenceViewerRoleV1::Juror,
        purpose_digest: [0x13; 32],
        issuance_nonce: [0x14; 32],
        generation: 1,
        issued_at_unix_ms: now_unix_ms,
        expires_at_unix_ms: now_unix_ms + 60_000,
    };
    let checkpoint_record = sorafs_node::evidence_viewer::EvidenceViewerCheckpointStoreRecordV1 {
        version: sorafs_node::evidence_viewer::EVIDENCE_VIEWER_CHECKPOINT_STORE_RECORD_VERSION_V1,
        generation: 1,
        predecessor_revision: None,
        predecessor_checkpoint_digest: None,
        checkpoint_digest: [0x21; 32],
        checkpoint_bytes: vec![0x22],
        checkpoint_store_handle: checkpoint.handle.clone(),
        checkpoint_store_revision: checkpoint.revision.expect("revision"),
        checkpoint_store_policy_digest: checkpoint.policy_digest.expect("policy digest"),
        signer_handle: "software://sorafs/evidence-viewer/primary".to_owned(),
        signer_public_key: TEST_SIGNER_KEY,
        signature: [0x23; 64],
        revision: [0x24; 32],
    };
    let checkpoint_record_bytes = encode_canonical(
        &checkpoint_record,
        evidence_viewer_checkpoint_record_limit(&checkpoint).expect("checkpoint record limit"),
    )
    .expect("encode checkpoint record");
    let mut mutating = Vec::new();
    mutating.push(validated_test_operation(
        webauthn.clone(),
        OPERATION_EVIDENCE_VIEWER_ISSUE_CHALLENGE_V1,
        encode_canonical(
            &EvidenceViewerIssueChallengeRequestWireV1 {
                binding_digest: [0x31; 32],
                issued_at_unix_ms: now_unix_ms,
                expires_at_unix_ms: now_unix_ms + 60_000,
            },
            MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1,
        )
        .expect("encode challenge issue"),
    ));
    mutating.push(validated_test_operation(
        webauthn,
        OPERATION_EVIDENCE_VIEWER_VERIFY_AND_CONSUME_V1,
        encode_canonical(
            &EvidenceViewerVerifyAndConsumeRequestWireV1 {
                challenge: b"challenge-secret".to_vec(),
                assertion: vec![0x32],
                binding_digest: [0x33; 32],
                rp_id: "review.example".to_owned(),
                allowed_origins: vec!["https://review.example".to_owned()],
                now_unix_ms,
            },
            MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1,
        )
        .expect("encode WebAuthn verification"),
    ));
    mutating.push(validated_test_operation(
        grants.clone(),
        OPERATION_EVIDENCE_VIEWER_GRANT_ISSUE_V1,
        encode_canonical(
            &EvidenceViewerGrantIssueRequestWireV1 {
                claims: claims.clone(),
            },
            MAX_EVIDENCE_VIEWER_CLAIMS_BYTES_V1,
        )
        .expect("encode grant issue"),
    ));
    mutating.push(validated_test_operation(
        grants.clone(),
        OPERATION_EVIDENCE_VIEWER_GRANT_REVOKE_V1,
        encode_canonical(
            &EvidenceViewerGrantRevokeRequestWireV1 {
                token_digest: [0x34; 32],
            },
            MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1,
        )
        .expect("encode grant revocation"),
    ));
    mutating.push(validated_test_operation(
        erasure,
        OPERATION_EVIDENCE_VIEWER_ERASE_V1,
        encode_canonical(
            &EvidenceViewerEraseRequestWireV1 {
                operation_id: [0x35; 32],
                quarantine_id: [0x36; 16],
                object_id: [0x37; 16],
                evidence_digest: [0x38; 32],
            },
            MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1,
        )
        .expect("encode erasure"),
    ));
    mutating.push(validated_test_operation(
        checkpoint.clone(),
        OPERATION_EVIDENCE_VIEWER_CHECKPOINT_COMPARE_AND_SWAP_V1,
        encode_canonical(
            &EvidenceViewerCheckpointCompareAndSwapRequestWireV1 {
                expected_revision: None,
                next_record: checkpoint_record_bytes,
            },
            MAX_EVIDENCE_VIEWER_BULK_FRAME_BYTES_V1,
        )
        .expect("encode checkpoint CAS"),
    ));
    mutating.push(validated_test_operation(
        archive.clone(),
        OPERATION_EVIDENCE_VIEWER_ARCHIVE_INSTALL_V1,
        encode_canonical(
            &EvidenceViewerArchiveInstallRequestWireV1 {
                operation_id: [0x39; 32],
                receipt_message: [0x3A; 32],
                canonical_artifact: vec![0x3B],
            },
            MAX_EVIDENCE_VIEWER_BULK_FRAME_BYTES_V1,
        )
        .expect("encode archive install"),
    ));
    let unit = encode_canonical(&(), MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1).expect("encode unit");
    for request in &mutating {
        assert_eq!(
            validate_operation_result(
                request,
                STATUS_AMBIGUOUS_V1,
                &unit,
                &server_test_network_id(),
            ),
            Ok(()),
            "operation {}",
            request.operation
        );
    }
    let readonly = [
        validated_test_operation(
            grants,
            OPERATION_EVIDENCE_VIEWER_GRANT_VERIFY_V1,
            encode_canonical(
                &EvidenceViewerGrantVerifyRequestWireV1 {
                    token: b"grant-secret".to_vec(),
                    claims,
                    now_unix_ms: now_unix_ms + 1,
                },
                MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1,
            )
            .expect("encode grant verification"),
        ),
        validated_test_operation(
            receipt,
            OPERATION_EVIDENCE_VIEWER_RECEIPT_SIGN_V1,
            encode_canonical(
                &PurposeSignRequestWireV1 {
                    purpose: sorafs_node::evidence_viewer::EvidenceViewerSigningPurposeV1::Receipt
                        .wire_id(),
                    payload: [
                        b"sorafs.evidence-viewer.receipt-signature.v1".as_slice(),
                        &[0x41; 32],
                    ]
                    .concat(),
                },
                MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1,
            )
            .expect("encode receipt sign"),
        ),
        validated_test_operation(
            checkpoint,
            OPERATION_EVIDENCE_VIEWER_CHECKPOINT_LOAD_V1,
            unit.clone(),
        ),
        validated_test_operation(
            archive,
            OPERATION_EVIDENCE_VIEWER_ARCHIVE_READ_V1,
            encode_canonical(
                &EvidenceViewerArchiveReadRequestWireV1 {
                    operation_id: [0x42; 32],
                },
                MAX_EVIDENCE_VIEWER_CONTROL_BYTES_V1,
            )
            .expect("encode archive read"),
        ),
    ];
    for request in readonly {
        assert_eq!(
            validate_operation_result(
                &request,
                STATUS_AMBIGUOUS_V1,
                &unit,
                &server_test_network_id(),
            ),
            Err(BrokerError::Protocol),
            "operation {}",
            request.operation
        );
    }
    let redacted = format!(
        "{:?}",
        EvidenceViewerVerifyAndConsumeRequestWireV1 {
            challenge: b"challenge-secret".to_vec(),
            assertion: b"assertion-secret".to_vec(),
            binding_digest: [0x43; 32],
            rp_id: "review.example".to_owned(),
            allowed_origins: vec!["https://review.example".to_owned()],
            now_unix_ms,
        }
    );
    assert!(!redacted.contains("challenge-secret"));
    assert!(!redacted.contains("assertion-secret"));
}
#[test]
fn provider_ingest_wire_roles_bind_exact_public_policy() {
    let source = ProviderBindingWireV1 {
        slot: IrohaRuntimeProviderSlotV1::ProviderIngestAuthenticatedSource.wire_id(),
        handle: SERVER_TEST_SOURCE_HANDLE.to_owned(),
        revision: Some(5),
        policy_digest: Some([0xB1; 32]),
        bootle_lantern_issuance_bindings: None,
        stream_token_signer_binding: None,
        appeal_finance_signer_binding: None,
        appeal_finance_checkpoint_binding: None,
        appeal_finance_checkpoint_max_bytes: None,
        pop_credential_runtime_binding: None,
        por_replay_archive_binding: None,
        por_replay_archive_proof_limits: None,
        potr_runtime_binding: None,
        native_signer_binding: None,
        governance_dag_publisher_peer_id: None,
        governance_dag_publisher_public_key: None,
        governance_request_ingress_binding: None,
        provider_ingest_signer_binding: None,
        provider_ingest_source_limits: Some(ProviderIngestSourceLimitsWireV1 {
            operation_timeout_ms: 30_000,
            max_content_bytes: 64 * 1024 * 1024,
            max_source_providers: 8,
            max_concurrent_streams: 2,
        }),
        provider_ingest_checkpoint_max_bytes: None,
        provider_ingest_max_signed_transaction_bytes: None,
        evidence_viewer_webauthn_binding: None,
        evidence_viewer_grant_ttl_ms: None,
        evidence_viewer_receipt_signer_public_key: None,
        evidence_viewer_transparency_publisher_public_key: None,
        evidence_viewer_checkpoint_max_bytes: None,
        moderation_checkpoint_max_bytes: None,
        moderation_checkpoint_attestation_public_key: None,
        evidence_viewer_archive_id: None,
        evidence_viewer_archive_public_key: None,
        evidence_viewer_archive_max_bytes: None,
        moderation_panel_notification_archive_binding: None,
    };
    assert_eq!(validate_wire_binding(&source), Ok(()));
    let mut source_observation = ProviderObservationWireV1 {
        binding: source.clone(),
        signer_metadata: None,
        governance_request_ingress_qualification: None,
        moderation_quarantine_active_key_id: None,
        provider_ingest_signer_binding: None,
        provider_ingest_source_provider_ids: SERVER_TEST_SOURCE_PROVIDER_IDS.to_vec(),
        potr_signer_public_key: Vec::new(),
        evidence_viewer_receipt_signer_public_key: None,
        evidence_viewer_archive_id: None,
        evidence_viewer_archive_public_key: None,
        moderation_checkpoint_attestation_public_key: None,
        moderation_panel_notification_archive_binding: None,
        metadata_digest: [0; 32],
    };
    refresh_metadata_digest(&mut source_observation);
    assert_eq!(validate_observation(&source, &source_observation), Ok(()));
    source_observation
        .provider_ingest_source_provider_ids
        .swap(0, 1);
    refresh_metadata_digest(&mut source_observation);
    assert_eq!(
        validate_observation(&source, &source_observation),
        Err(BrokerError::BindingMismatch)
    );
    let exact_signer = ProviderIngestSignerBindingWireV1 {
        runtime_handle: "software://sorafs/provider-ingest/signer-primary".to_owned(),
        adapter_revision: 3,
        signer_policy_id: [0xA1; 32],
        signer_policy_revision: 1,
        signer_policy_predecessor_digest: None,
        signer_policy_digest: [0xA2; 32],
        algorithm: 1,
        public_key: TEST_SIGNER_KEY.to_vec(),
    };
    let resolver = ProviderBindingWireV1 {
        slot: IrohaRuntimeProviderSlotV1::ProviderIngestCompletionSignerResolver.wire_id(),
        handle: "resolver://sorafs/provider-ingest/primary".to_owned(),
        revision: Some(6),
        policy_digest: Some([0xB2; 32]),
        bootle_lantern_issuance_bindings: None,
        stream_token_signer_binding: None,
        appeal_finance_signer_binding: None,
        appeal_finance_checkpoint_binding: None,
        appeal_finance_checkpoint_max_bytes: None,
        pop_credential_runtime_binding: None,
        por_replay_archive_binding: None,
        por_replay_archive_proof_limits: None,
        potr_runtime_binding: None,
        native_signer_binding: None,
        governance_dag_publisher_peer_id: None,
        governance_dag_publisher_public_key: None,
        governance_request_ingress_binding: None,
        provider_ingest_signer_binding: Some(exact_signer.clone()),
        provider_ingest_source_limits: None,
        provider_ingest_checkpoint_max_bytes: None,
        provider_ingest_max_signed_transaction_bytes: Some(1024 * 1024),
        evidence_viewer_webauthn_binding: None,
        evidence_viewer_grant_ttl_ms: None,
        evidence_viewer_receipt_signer_public_key: None,
        evidence_viewer_transparency_publisher_public_key: None,
        evidence_viewer_checkpoint_max_bytes: None,
        moderation_checkpoint_max_bytes: None,
        moderation_checkpoint_attestation_public_key: None,
        evidence_viewer_archive_id: None,
        evidence_viewer_archive_public_key: None,
        evidence_viewer_archive_max_bytes: None,
        moderation_panel_notification_archive_binding: None,
    };
    assert_eq!(validate_wire_binding(&resolver), Ok(()));
    let mut exact_minimum = resolver.clone();
    exact_minimum.provider_ingest_max_signed_transaction_bytes =
        Some(provider_ingest_outbox_defaults::MAX_SIGNED_TRANSACTION_BYTES_MIN);
    assert_eq!(validate_wire_binding(&exact_minimum), Ok(()));
    let mut below_minimum = resolver.clone();
    below_minimum.provider_ingest_max_signed_transaction_bytes =
        Some(provider_ingest_outbox_defaults::MAX_SIGNED_TRANSACTION_BYTES_MIN - 1);
    assert_eq!(
        validate_wire_binding(&below_minimum),
        Err(BrokerError::BindingMismatch)
    );
    let mut leaf = resolver.clone();
    leaf.slot = IrohaRuntimeProviderSlotV1::ProviderIngestCompletionSigner.wire_id();
    leaf.handle = exact_signer.runtime_handle.clone();
    leaf.revision = Some(exact_signer.adapter_revision);
    leaf.policy_digest = Some(exact_signer.signer_policy_digest);
    assert_eq!(validate_wire_binding(&leaf), Ok(()));
    let mut substituted = leaf.clone();
    substituted
        .provider_ingest_signer_binding
        .as_mut()
        .expect("detailed signer binding")
        .algorithm = 99;
    assert_eq!(
        validate_wire_binding(&substituted),
        Err(BrokerError::Protocol)
    );
    let checkpoint = ProviderBindingWireV1 {
        slot: IrohaRuntimeProviderSlotV1::ProviderIngestCheckpointStore.wire_id(),
        handle: "sealed://sorafs/provider-ingest/checkpoint-primary".to_owned(),
        revision: Some(7),
        policy_digest: Some([0xA7; 32]),
        bootle_lantern_issuance_bindings: None,
        stream_token_signer_binding: None,
        appeal_finance_signer_binding: None,
        appeal_finance_checkpoint_binding: None,
        appeal_finance_checkpoint_max_bytes: None,
        pop_credential_runtime_binding: None,
        por_replay_archive_binding: None,
        por_replay_archive_proof_limits: None,
        potr_runtime_binding: None,
        native_signer_binding: None,
        governance_dag_publisher_peer_id: None,
        governance_dag_publisher_public_key: None,
        governance_request_ingress_binding: None,
        provider_ingest_signer_binding: None,
        provider_ingest_source_limits: None,
        provider_ingest_checkpoint_max_bytes: Some(64 * 1024 * 1024),
        provider_ingest_max_signed_transaction_bytes: None,
        evidence_viewer_webauthn_binding: None,
        evidence_viewer_grant_ttl_ms: None,
        evidence_viewer_receipt_signer_public_key: None,
        evidence_viewer_transparency_publisher_public_key: None,
        evidence_viewer_checkpoint_max_bytes: None,
        moderation_checkpoint_max_bytes: None,
        moderation_checkpoint_attestation_public_key: None,
        evidence_viewer_archive_id: None,
        evidence_viewer_archive_public_key: None,
        evidence_viewer_archive_max_bytes: None,
        moderation_panel_notification_archive_binding: None,
    };
    assert_eq!(validate_wire_binding(&checkpoint), Ok(()));
    let checkpoint_load_payload = encode_canonical(
        &CHECKPOINT_LOAD_REQUEST_VERSION_V1,
        MAX_PROVIDER_INGEST_CHECKPOINT_FRAME_BYTES_V1,
    )
    .expect("encode provider-ingest checkpoint load");
    assert_eq!(
        checkpoint_load_payload.len(),
        norito::core::Header::SIZE + core::mem::size_of::<u8>()
    );
    assert_eq!(
        decode_canonical::<u8>(
            &checkpoint_load_payload,
            MAX_PROVIDER_INGEST_CHECKPOINT_FRAME_BYTES_V1,
        )
        .expect("decode provider-ingest checkpoint load"),
        CHECKPOINT_LOAD_REQUEST_VERSION_V1
    );
    let checkpoint_load = make_operation_request(
        TEST_SESSION_ID,
        3,
        checkpoint.clone(),
        [0xC7; 32],
        OPERATION_PROVIDER_INGEST_CHECKPOINT_LOAD_V1,
        checkpoint_load_payload.clone(),
    )
    .expect("seal provider-ingest checkpoint load");
    assert_eq!(validate_operation_request(&checkpoint_load), Ok(()));
    let unsupported_version = CHECKPOINT_LOAD_REQUEST_VERSION_V1 ^ u8::MAX;
    let alternate_checkpoint_load = make_operation_request(
        TEST_SESSION_ID,
        4,
        checkpoint.clone(),
        [0xC7; 32],
        OPERATION_PROVIDER_INGEST_CHECKPOINT_LOAD_V1,
        encode_canonical(
            &unsupported_version,
            MAX_PROVIDER_INGEST_CHECKPOINT_FRAME_BYTES_V1,
        )
        .expect("encode alternate provider-ingest checkpoint load version"),
    )
    .expect("seal alternate provider-ingest checkpoint load version");
    assert_eq!(
        validate_operation_request(&alternate_checkpoint_load),
        Err(BrokerError::Rejected)
    );
    let mut trailing_checkpoint_load_payload = checkpoint_load_payload.clone();
    trailing_checkpoint_load_payload.push(0);
    let trailing_checkpoint_load = make_operation_request(
        TEST_SESSION_ID,
        5,
        checkpoint.clone(),
        [0xC7; 32],
        OPERATION_PROVIDER_INGEST_CHECKPOINT_LOAD_V1,
        trailing_checkpoint_load_payload,
    )
    .expect("seal trailing provider-ingest checkpoint load payload");
    assert_eq!(
        validate_operation_request(&trailing_checkpoint_load),
        Err(BrokerError::Protocol)
    );
    let cross_slot_checkpoint_load = make_operation_request(
        TEST_SESSION_ID,
        6,
        source.clone(),
        [0xC8; 32],
        OPERATION_PROVIDER_INGEST_CHECKPOINT_LOAD_V1,
        checkpoint_load_payload,
    )
    .expect("seal cross-slot provider-ingest checkpoint load");
    assert_eq!(
        validate_operation_request(&cross_slot_checkpoint_load),
        Err(BrokerError::BindingMismatch)
    );
    let retention = ProviderBindingWireV1 {
        slot: IrohaRuntimeProviderSlotV1::ProviderIngestRetentionAuthority.wire_id(),
        handle: "sealed://sorafs/provider-ingest/retention-primary".to_owned(),
        revision: Some(9),
        policy_digest: Some([0xC9; 32]),
        bootle_lantern_issuance_bindings: None,
        stream_token_signer_binding: None,
        appeal_finance_signer_binding: None,
        appeal_finance_checkpoint_binding: None,
        appeal_finance_checkpoint_max_bytes: None,
        pop_credential_runtime_binding: None,
        por_replay_archive_binding: None,
        por_replay_archive_proof_limits: None,
        potr_runtime_binding: None,
        native_signer_binding: None,
        governance_dag_publisher_peer_id: None,
        governance_dag_publisher_public_key: None,
        governance_request_ingress_binding: None,
        provider_ingest_signer_binding: None,
        provider_ingest_source_limits: None,
        provider_ingest_checkpoint_max_bytes: None,
        provider_ingest_max_signed_transaction_bytes: None,
        evidence_viewer_webauthn_binding: None,
        evidence_viewer_grant_ttl_ms: None,
        evidence_viewer_receipt_signer_public_key: None,
        evidence_viewer_transparency_publisher_public_key: None,
        evidence_viewer_checkpoint_max_bytes: None,
        moderation_checkpoint_max_bytes: None,
        moderation_checkpoint_attestation_public_key: None,
        evidence_viewer_archive_id: None,
        evidence_viewer_archive_public_key: None,
        evidence_viewer_archive_max_bytes: None,
        moderation_panel_notification_archive_binding: None,
    };
    assert_eq!(validate_wire_binding(&retention), Ok(()));
    for operation in [
        OPERATION_PROVIDER_INGEST_RESOLVER_READINESS_V1,
        OPERATION_PROVIDER_INGEST_RESOLVE_SIGNER_V1,
        OPERATION_PROVIDER_INGEST_SOURCE_READINESS_V1,
    ] {
        assert_eq!(
            operation_frame_limit(operation),
            MAX_PROVIDER_INGEST_CONTROL_FRAME_BYTES_V1
        );
    }
    assert_eq!(
        operation_frame_limit(OPERATION_PROVIDER_INGEST_SIGN_V1),
        MAX_PROVIDER_INGEST_SIGNER_FRAME_BYTES_V1
    );
    for operation in [
        OPERATION_PROVIDER_INGEST_CHECKPOINT_LOAD_V1,
        OPERATION_PROVIDER_INGEST_CHECKPOINT_COMPARE_AND_SWAP_V1,
    ] {
        assert_eq!(
            operation_frame_limit(operation),
            MAX_PROVIDER_INGEST_CHECKPOINT_FRAME_BYTES_V1
        );
    }
    for operation in [
        OPERATION_PROVIDER_INGEST_RETENTION_LOAD_V1,
        OPERATION_PROVIDER_INGEST_RETENTION_COMPARE_AND_SWAP_V1,
    ] {
        assert_eq!(
            operation_frame_limit(operation),
            MAX_PROVIDER_INGEST_RETENTION_FRAME_BYTES_V1
        );
    }
    assert_eq!(
        operation_frame_limit(OPERATION_PROVIDER_INGEST_SOURCE_FETCH_V1),
        MAX_PROVIDER_INGEST_SOURCE_INITIAL_FRAME_BYTES_V1
    );
    for operation in [
        OPERATION_PROVIDER_INGEST_RESOLVER_READINESS_V1,
        OPERATION_PROVIDER_INGEST_RESOLVE_SIGNER_V1,
        OPERATION_PROVIDER_INGEST_SIGN_V1,
        OPERATION_PROVIDER_INGEST_CHECKPOINT_LOAD_V1,
        OPERATION_PROVIDER_INGEST_CHECKPOINT_COMPARE_AND_SWAP_V1,
        OPERATION_PROVIDER_INGEST_RETENTION_LOAD_V1,
        OPERATION_PROVIDER_INGEST_RETENTION_COMPARE_AND_SWAP_V1,
        OPERATION_PROVIDER_INGEST_SOURCE_READINESS_V1,
        OPERATION_PROVIDER_INGEST_SOURCE_FETCH_V1,
    ] {
        assert!(operation_is_known(operation));
        assert!(
            operation_frame_limit(operation) <= MAX_OPERATION_FRAME_BYTES_V1,
            "provider-ingest operation {operation} must stay within the process raw-frame ceiling"
        );
    }
    let signer_owner = iroha_data_model::account::AccountId::new(
        iroha_crypto::PublicKey::from_bytes(iroha_crypto::Algorithm::Ed25519, &TEST_SIGNER_KEY)
            .expect("provider-ingest signer public key"),
    );
    let signer_context = provider_ingest_completion_test_context(signer_owner.clone());
    let admitted_payload = provider_ingest_completion_test_payload(signer_owner.clone());
    let admitted_payload = encode_canonical(
        &admitted_payload,
        usize::try_from(
            leaf.provider_ingest_max_signed_transaction_bytes
                .expect("provider-ingest signed transaction ceiling"),
        )
        .expect("provider-ingest signed transaction ceiling fits usize"),
    )
    .expect("encode provider-ingest completion payload");
    let admitted_request = make_operation_request(
        TEST_SESSION_ID,
        1,
        leaf.clone(),
        [0xB3; 32],
        OPERATION_PROVIDER_INGEST_SIGN_V1,
        encode_canonical(
            &ProviderIngestSignRequestWireV1 {
                context: provider_ingest_signer_context_to_wire(&signer_context)
                    .expect("encode provider-ingest signer context"),
                transaction_payload: admitted_payload,
            },
            MAX_OPERATION_FRAME_BYTES_V1,
        )
        .expect("encode provider-ingest sign request"),
    )
    .expect("build provider-ingest sign operation");
    assert_eq!(validate_operation_request(&admitted_request), Ok(()));
    assert_eq!(
        validate_operation_request_for_session(
            &admitted_request,
            "server-test-chain",
            &server_test_network_id(),
        ),
        Ok(())
    );
    assert_eq!(
        validate_operation_request_for_session(
            &admitted_request,
            "server-test-chain",
            &test_network_id(0x16),
        ),
        Err(BrokerError::BindingMismatch)
    );
    let mut substituted_instruction =
        provider_ingest_completion_test_instruction(signer_owner.clone());
    substituted_instruction.expected_assignment_revision += 1;
    let substituted_payload = provider_ingest_completion_test_payload_with_executable(
        server_test_network_id(),
        signer_owner,
        iroha_data_model::transaction::Executable::Instructions(
            vec![iroha_data_model::isi::InstructionBox::from(
                substituted_instruction,
            )]
            .into(),
        ),
    );
    let substituted_payload = encode_canonical(
        &substituted_payload,
        usize::try_from(
            leaf.provider_ingest_max_signed_transaction_bytes
                .expect("provider-ingest signed transaction ceiling"),
        )
        .expect("provider-ingest signed transaction ceiling fits usize"),
    )
    .expect("encode substituted provider-ingest completion payload");
    let substituted_request = make_operation_request(
        TEST_SESSION_ID,
        2,
        leaf,
        [0xB3; 32],
        OPERATION_PROVIDER_INGEST_SIGN_V1,
        encode_canonical(
            &ProviderIngestSignRequestWireV1 {
                context: provider_ingest_signer_context_to_wire(&signer_context)
                    .expect("encode provider-ingest signer context"),
                transaction_payload: substituted_payload,
            },
            MAX_OPERATION_FRAME_BYTES_V1,
        )
        .expect("encode substituted provider-ingest sign request"),
    )
    .expect("build substituted provider-ingest sign operation");
    assert_eq!(
        validate_operation_request(&substituted_request),
        Err(BrokerError::BindingMismatch)
    );
    assert_eq!(
        validate_operation_request_for_session(
            &substituted_request,
            "server-test-chain",
            &server_test_network_id(),
        ),
        Err(BrokerError::BindingMismatch)
    );
    let owner = iroha_data_model::account::AccountId::new(
        provider_ingest_completion_test_keypair()
            .public_key()
            .clone(),
    );
    let context = provider_ingest_completion_test_context(owner.clone());
    let exact_payload = provider_ingest_completion_test_payload(owner.clone());
    assert_eq!(
        ensure_provider_ingest_completion_payload(
            &exact_payload,
            &context,
            &server_test_network_id(),
        ),
        Ok(())
    );
    let cross_network_payload = iroha_data_model::transaction::TransactionBuilder::new(
        test_network_id(0x16),
        owner.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .into_payload()
    .expect("build cross-network provider-ingest payload");
    assert_eq!(
        ensure_provider_ingest_completion_payload(
            &cross_network_payload,
            &context,
            &server_test_network_id(),
        ),
        Err(BrokerError::BindingMismatch)
    );
    let genesis_payload = iroha_data_model::transaction::TransactionBuilder::new_genesis(
        owner,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .into_payload()
    .expect("build genesis-domain provider-ingest payload");
    assert_eq!(
        ensure_provider_ingest_completion_payload(
            &genesis_payload,
            &context,
            &server_test_network_id(),
        ),
        Err(BrokerError::BindingMismatch)
    );
}
#[test]
fn provider_ingest_signer_wire_pins_exact_assignment_revision() {
    let owner = iroha_data_model::account::AccountId::new(
        provider_ingest_completion_test_keypair()
            .public_key()
            .clone(),
    );
    let context = provider_ingest_completion_test_context(owner.clone());
    let wire = provider_ingest_signer_context_to_wire(&context)
        .expect("encode exact provider-ingest signer context");
    assert_eq!(
        provider_ingest_signer_context_from_wire(&wire),
        Ok(context.clone())
    );
    let payload = provider_ingest_completion_test_payload(owner);
    assert_eq!(
        ensure_provider_ingest_completion_payload(&payload, &context, &server_test_network_id(),),
        Ok(())
    );
    let mut substituted = wire;
    substituted.expected_assignment_revision += 1;
    let substituted = provider_ingest_signer_context_from_wire(&substituted)
        .expect("decode production-shaped substituted context");
    assert_eq!(
        ensure_provider_ingest_completion_payload(
            &payload,
            &substituted,
            &server_test_network_id(),
        ),
        Err(BrokerError::BindingMismatch)
    );
    let mut zero = provider_ingest_signer_context_to_wire(&context)
        .expect("encode exact provider-ingest signer context");
    zero.expected_assignment_revision = 0;
    assert_eq!(
        provider_ingest_signer_context_from_wire(&zero),
        Err(BrokerError::Rejected)
    );
}
#[test]
fn provider_ingest_completion_signer_accepts_only_exact_completion_schema() {
    let owner = iroha_data_model::account::AccountId::new(
        provider_ingest_completion_test_keypair()
            .public_key()
            .clone(),
    );
    let context = provider_ingest_completion_test_context(owner.clone());
    let exact = provider_ingest_completion_test_payload(owner.clone());
    assert_eq!(
        ensure_provider_ingest_completion_payload(&exact, &context, &server_test_network_id(),),
        Ok(())
    );
    let other_executable = provider_ingest_completion_test_payload_with_executable(
        server_test_network_id(),
        owner.clone(),
        iroha_data_model::transaction::Executable::Ivm(
            iroha_data_model::transaction::IvmBytecode::from_compiled(vec![1]),
        ),
    );
    assert_eq!(
        ensure_provider_ingest_completion_payload(
            &other_executable,
            &context,
            &server_test_network_id(),
        ),
        Err(BrokerError::Rejected)
    );
    let wrong_instruction = provider_ingest_completion_test_payload_with_executable(
        server_test_network_id(),
        owner.clone(),
        iroha_data_model::transaction::Executable::Instructions(
            vec![iroha_data_model::isi::InstructionBox::from(
                iroha_data_model::isi::Log::new(
                    iroha_data_model::Level::INFO,
                    "not a provider-ingest completion".into(),
                ),
            )]
            .into(),
        ),
    );
    assert_eq!(
        ensure_provider_ingest_completion_payload(
            &wrong_instruction,
            &context,
            &server_test_network_id(),
        ),
        Err(BrokerError::Rejected)
    );
    let completion = provider_ingest_completion_test_instruction(owner.clone());
    let batch = provider_ingest_completion_test_payload_with_executable(
        server_test_network_id(),
        owner.clone(),
        iroha_data_model::transaction::Executable::Batch(
            vec![
                iroha_data_model::transaction::ExecutableBatchItem::Instruction(
                    iroha_data_model::isi::InstructionBox::from(completion.clone()),
                ),
            ]
            .into(),
        ),
    );
    assert_eq!(
        ensure_provider_ingest_completion_payload(&batch, &context, &server_test_network_id(),),
        Err(BrokerError::Rejected)
    );
    let extra_instruction = provider_ingest_completion_test_payload_with_executable(
        server_test_network_id(),
        owner.clone(),
        iroha_data_model::transaction::Executable::Instructions(
            vec![
                iroha_data_model::isi::InstructionBox::from(completion.clone()),
                iroha_data_model::isi::InstructionBox::from(iroha_data_model::isi::Log::new(
                    iroha_data_model::Level::INFO,
                    "extra instruction".into(),
                )),
            ]
            .into(),
        ),
    );
    assert_eq!(
        ensure_provider_ingest_completion_payload(
            &extra_instruction,
            &context,
            &server_test_network_id(),
        ),
        Err(BrokerError::Rejected)
    );
    let other_owner = iroha_data_model::account::AccountId::new(
        iroha_crypto::KeyPair::try_from_seed(vec![0x43; 32], iroha_crypto::Algorithm::Ed25519)
            .expect("other provider-ingest owner key")
            .public_key()
            .clone(),
    );
    let wrong_payload_owner = provider_ingest_completion_test_payload_with_executable(
        server_test_network_id(),
        other_owner.clone(),
        iroha_data_model::transaction::Executable::Instructions(
            vec![iroha_data_model::isi::InstructionBox::from(
                completion.clone(),
            )]
            .into(),
        ),
    );
    assert_eq!(
        ensure_provider_ingest_completion_payload(
            &wrong_payload_owner,
            &context,
            &server_test_network_id(),
        ),
        Err(BrokerError::BindingMismatch)
    );
    let mut wrong_authority = completion.clone();
    wrong_authority.expected_authority.provider_owner = other_owner;
    let wrong_authority = provider_ingest_completion_test_payload_with_executable(
        server_test_network_id(),
        owner.clone(),
        iroha_data_model::transaction::Executable::Instructions(
            vec![iroha_data_model::isi::InstructionBox::from(wrong_authority)].into(),
        ),
    );
    assert_eq!(
        ensure_provider_ingest_completion_payload(
            &wrong_authority,
            &context,
            &server_test_network_id(),
        ),
        Err(BrokerError::BindingMismatch)
    );
    let mut wrong_policy = completion.clone();
    wrong_policy.expected_authority.signer_policy.policy_digest[0] ^= 1;
    let wrong_policy = provider_ingest_completion_test_payload_with_executable(
        server_test_network_id(),
        owner.clone(),
        iroha_data_model::transaction::Executable::Instructions(
            vec![iroha_data_model::isi::InstructionBox::from(wrong_policy)].into(),
        ),
    );
    assert_eq!(
        ensure_provider_ingest_completion_payload(
            &wrong_policy,
            &context,
            &server_test_network_id(),
        ),
        Err(BrokerError::BindingMismatch)
    );
    let mut wrong_anchor = completion.clone();
    wrong_anchor.finalized_anchor.block_hash[0] ^= 1;
    let wrong_anchor = provider_ingest_completion_test_payload_with_executable(
        server_test_network_id(),
        owner.clone(),
        iroha_data_model::transaction::Executable::Instructions(
            vec![iroha_data_model::isi::InstructionBox::from(wrong_anchor)].into(),
        ),
    );
    assert_eq!(
        ensure_provider_ingest_completion_payload(
            &wrong_anchor,
            &context,
            &server_test_network_id(),
        ),
        Err(BrokerError::BindingMismatch)
    );
    let mut wrong_assignment_revision = completion.clone();
    wrong_assignment_revision.expected_assignment_revision =
        context.expected_assignment_revision + 1;
    let wrong_assignment_revision = provider_ingest_completion_test_payload_with_executable(
        server_test_network_id(),
        owner.clone(),
        iroha_data_model::transaction::Executable::Instructions(
            vec![iroha_data_model::isi::InstructionBox::from(
                wrong_assignment_revision,
            )]
            .into(),
        ),
    );
    assert_eq!(
        ensure_provider_ingest_completion_payload(
            &wrong_assignment_revision,
            &context,
            &server_test_network_id(),
        ),
        Err(BrokerError::BindingMismatch)
    );
    let mut zero_order = completion.clone();
    zero_order.order_id = iroha_data_model::sorafs::pin_registry::ReplicationOrderId::new([0; 32]);
    let mut zero_provider = completion.clone();
    zero_provider.provider_id = iroha_data_model::sorafs::capacity::ProviderId::new([0; 32]);
    let mut zero_epoch = completion.clone();
    zero_epoch.completion_epoch = 0;
    let mut zero_revision = completion.clone();
    zero_revision.expected_assignment_revision = 0;
    let mut zero_anchor_height = completion.clone();
    zero_anchor_height.finalized_anchor.height = 0;
    let mut zero_anchor_hash = completion;
    zero_anchor_hash.finalized_anchor.block_hash = [0; 32];
    for malformed in [
        zero_order,
        zero_provider,
        zero_epoch,
        zero_revision,
        zero_anchor_height,
        zero_anchor_hash,
    ] {
        let payload = provider_ingest_completion_test_payload_with_executable(
            server_test_network_id(),
            owner.clone(),
            iroha_data_model::transaction::Executable::Instructions(
                vec![iroha_data_model::isi::InstructionBox::from(malformed)].into(),
            ),
        );
        assert_eq!(
            ensure_provider_ingest_completion_payload(
                &payload,
                &context,
                &server_test_network_id(),
            ),
            Err(BrokerError::Rejected)
        );
    }
}
#[test]
fn provider_ingest_completion_signer_rejects_signed_envelope_sidecars() {
    let keypair = provider_ingest_completion_test_keypair();
    let owner = iroha_data_model::account::AccountId::new(keypair.public_key().clone());
    let context = provider_ingest_completion_test_context(owner.clone());
    let payload = provider_ingest_completion_test_payload(owner.clone());
    let exact = iroha_data_model::transaction::TransactionBuilder::from_payload(payload.clone())
        .expect("rebuild exact provider-ingest payload")
        .try_sign(keypair.private_key())
        .expect("sign exact provider-ingest completion");
    assert_eq!(
        ensure_provider_ingest_completion_transaction(&exact, &context, &server_test_network_id(),),
        Ok(())
    );
    let attachments = vec![iroha_data_model::proof::ProofAttachment::new_ref(
        "halo2/ipa".into(),
        iroha_data_model::proof::ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]),
        iroha_data_model::proof::VerifyingKeyId::new("halo2/ipa", "vk_1"),
    )];
    let attached = iroha_data_model::transaction::TransactionBuilder::from_payload(payload)
        .expect("rebuild attached provider-ingest payload")
        .with_proof_attachments(attachments)
        .expect("valid proof carriers")
        .try_sign(keypair.private_key())
        .expect("sign attached provider-ingest completion");
    assert_eq!(
        ensure_provider_ingest_completion_transaction(
            &attached,
            &context,
            &server_test_network_id(),
        ),
        Err(BrokerError::Rejected)
    );
    let mut multisig = exact;
    multisig.set_multisig_signatures(
        iroha_data_model::transaction::signed::MultisigSignatures::new(Vec::new()),
    );
    assert_eq!(
        ensure_provider_ingest_completion_transaction(
            &multisig,
            &context,
            &server_test_network_id(),
        ),
        Err(BrokerError::Rejected)
    );
}
#[test]
fn operation_response_rejects_session_order_slot_binding_and_digest_confusion() {
    let unit = encode_canonical(&(), MAX_OPERATION_FRAME_BYTES_V1).expect("encode canonical unit");
    decode_canonical::<()>(&unit, MAX_OPERATION_FRAME_BYTES_V1).expect("decode canonical unit");
    let binding = signer_binding();
    let metadata_digest = observation(&binding).metadata_digest;
    let payload = valid_governance_sign_request_payload();
    let request = make_operation_request(
        TEST_SESSION_ID,
        9,
        binding,
        metadata_digest,
        OPERATION_SIGN_V1,
        payload,
    )
    .expect("build operation request");
    validate_operation_request(&request).expect("validate operation request");
    let result = encode_canonical(
        &SignResultWireV1 {
            signature: test_governance_operation_signature(&request),
        },
        MAX_OPERATION_FRAME_BYTES_V1,
    )
    .expect("encode operation result");
    let response = operation_response(&request, STATUS_OK_V1, result);
    validate_operation_response(&request, &response, &server_test_network_id())
        .expect("validate exact operation response");
    for mutation in 0..11 {
        let mut confused = response.clone();
        match mutation {
            0 => confused.session_id[0] ^= 1,
            1 => confused.request_id -= 1,
            2 => confused.request_id += 1,
            3 => confused.request_digest[0] ^= 1,
            4 => confused.observed_binding.slot += 1,
            5 => confused.observed_binding.handle.push('x'),
            6 => confused.observed_binding.revision = Some(8),
            7 => confused.provider_metadata_digest[0] ^= 1,
            8 => confused.operation += 1,
            9 => confused.payload_digest[0] ^= 1,
            10 => confused.observed_binding.policy_digest = Some([0x72; 32]),
            _ => unreachable!(),
        }
        reseal_response(&mut confused);
        assert_eq!(
            validate_operation_response(&request, &confused, &server_test_network_id()),
            Err(BrokerError::Protocol),
            "mutation {mutation} must fail"
        );
    }
    let mut wrong_result_digest = response.clone();
    wrong_result_digest.result_digest[0] ^= 1;
    reseal_response(&mut wrong_result_digest);
    assert_eq!(
        validate_operation_response(&request, &wrong_result_digest, &server_test_network_id(),),
        Err(BrokerError::Protocol)
    );
    let mut wrong_response_digest = response;
    wrong_response_digest.response_digest[0] ^= 1;
    assert_eq!(
        validate_operation_response(&request, &wrong_response_digest, &server_test_network_id(),),
        Err(BrokerError::Protocol)
    );
    let diagnostic_leak =
        operation_response(&request, STATUS_REJECTED_V1, b"provider secret".to_vec());
    assert_eq!(
        validate_operation_response(&request, &diagnostic_leak, &server_test_network_id()),
        Err(BrokerError::Protocol),
        "provider diagnostics must never cross the broker boundary"
    );
    let mut corrupt_request = request;
    corrupt_request.payload.push(4);
    assert_eq!(
        validate_operation_request(&corrupt_request),
        Err(BrokerError::Protocol)
    );
    let load_payload = encode_canonical(
        &SealedLoadRequestWireV1 { slot: 1 },
        MAX_OPERATION_FRAME_BYTES_V1,
    )
    .expect("encode mismatched load payload");
    let mismatched = make_operation_request(
        TEST_SESSION_ID,
        10,
        signer_binding(),
        metadata_digest,
        OPERATION_SEALED_LOAD_V1,
        load_payload,
    )
    .expect("build structurally bound mismatched request");
    assert_eq!(
        validate_operation_request(&mismatched),
        Err(BrokerError::BindingMismatch)
    );
}
#[test]
fn production_endpoint_policy_pins_non_root_service_uid() {
    let policy = EndpointPolicy::for_service_uid(
        iroha_config::parameters::defaults::runtime_provider_broker::endpoint_path(),
        42_424,
        true,
    );
    assert_eq!(policy.expected_service_uid, 42_424);
    assert_eq!(verify_peer_uid(42_424, 42_424), Ok(()));
    assert_eq!(
        verify_peer_uid(42_425, 42_424),
        Err(BrokerError::Unavailable),
        "supplementary-group access never substitutes for the pinned service UID"
    );
}
#[test]
fn configured_production_endpoint_keeps_exact_custody_checks() {
    let endpoint_path = "/var/iroha-seat-7/runtime-provider-broker-v1.sock"
        .parse::<iroha_config::parameters::actual::RuntimeProviderBrokerEndpointPath>()
        .expect("valid public broker endpoint");
    let policy = EndpointPolicy::production(&endpoint_path);
    assert_eq!(policy.path.as_path(), endpoint_path.as_path());
    assert_eq!(
        policy.expected_service_uid,
        rustix::process::geteuid().as_raw()
    );
    assert_eq!(policy.socket_mode, STOCK_BROKER_SOCKET_MODE_V1);
    assert!(policy.verify_all_ancestors);
}
#[test]
fn endpoint_policy_rejects_outage_mode_owner_symlink_and_path_substitution() {
    let production = EndpointPolicy::production(&validated_production_endpoint());
    assert_eq!(
        production.path,
        iroha_config::parameters::defaults::runtime_provider_broker::endpoint_path()
    );
    assert_eq!(
        production.expected_service_uid,
        rustix::process::geteuid().as_raw()
    );
    assert_eq!(production.socket_mode, STOCK_BROKER_SOCKET_MODE_V1);
    assert!(production.verify_all_ancestors);
    let (_directory, path, policy, listener) = bind_fake_broker();
    let first = endpoint_identity(&policy).expect("accept hardened socket");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).expect("loosen test socket");
    assert_eq!(endpoint_identity(&policy), Err(BrokerError::Unavailable));
    set_socket_mode(&path).expect("restore test socket mode");
    let mut wrong_owner = policy.clone();
    wrong_owner.expected_service_uid = wrong_owner.expected_service_uid.wrapping_add(1);
    assert_eq!(
        endpoint_identity(&wrong_owner),
        Err(BrokerError::Unavailable)
    );
    assert_eq!(
        verify_peer_uid(
            policy.expected_service_uid.wrapping_add(1),
            policy.expected_service_uid
        ),
        Err(BrokerError::Unavailable),
        "a substituted peer credential must fail closed"
    );
    let symlink_path = path.with_extension("link");
    symlink(&path, &symlink_path).expect("create test socket symlink");
    assert_eq!(
        endpoint_identity(&EndpointPolicy::for_test(symlink_path)),
        Err(BrokerError::Unavailable)
    );
    fs::remove_file(&path).expect("remove first test socket");
    let replacement = UnixListener::bind(&path).expect("bind replacement test socket");
    set_socket_mode(&path).expect("harden replacement test socket");
    let second = endpoint_identity(&policy).expect("inspect replacement socket");
    assert_ne!(first, second, "device/inode substitution must be visible");
    drop(listener);
    drop(replacement);
    let missing = EndpointPolicy::for_test(path.with_extension("missing"));
    assert!(matches!(
        connect_verified(&missing),
        Err(BrokerError::Unavailable)
    ));
}
#[test]
fn fake_broker_qualifies_signs_and_enforces_monotonic_request_ids() {
    let (_directory, _path, policy, listener) = bind_fake_broker();
    let governance_payload =
        sorafs_node::governance_dag_key_transition_signing_payload_v1(1, 2, [0x47; 32])
            .expect("governance key-transition payload");
    let expected_governance_payload = governance_payload.clone();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept fake broker client");
        let handshake = read_handshake(&mut stream);
        send_handshake(&mut stream, &handshake_response(&handshake));
        let qualify = read_operation(&mut stream);
        assert_eq!(qualify.request_id, 1);
        assert_eq!(qualify.operation, OPERATION_QUALIFY_V1);
        let qualification = encode_canonical(
            &QualificationResultWireV1 {
                revision: 7,
                policy_digest: TEST_POLICY_DIGEST,
            },
            MAX_OPERATION_FRAME_BYTES_V1,
        )
        .expect("encode qualification result");
        send_operation(
            &mut stream,
            &operation_response(&qualify, STATUS_OK_V1, qualification),
        );
        let sign = read_operation(&mut stream);
        assert_eq!(sign.request_id, 2);
        assert_eq!(sign.operation, OPERATION_SIGN_V1);
        let decoded = decode_canonical::<PurposeSignRequestWireV1>(
            &sign.payload,
            MAX_OPERATION_FRAME_BYTES_V1,
        )
        .expect("decode purpose-separated sign request");
        assert_eq!(
            decoded.purpose,
            sorafs_node::GovernanceDagSigningPurposeV1::KeyTransition.wire_id()
        );
        assert_eq!(decoded.payload, expected_governance_payload);
        let signature = encode_canonical(
            &SignResultWireV1 {
                signature: test_governance_operation_signature(&sign),
            },
            MAX_OPERATION_FRAME_BYTES_V1,
        )
        .expect("encode signature result");
        send_operation(
            &mut stream,
            &operation_response(&sign, STATUS_OK_V1, signature),
        );
        let requalify = read_operation(&mut stream);
        assert_eq!(requalify.request_id, 3);
        assert_eq!(requalify.operation, OPERATION_QUALIFY_V1);
        let qualification = encode_canonical(
            &QualificationResultWireV1 {
                revision: 7,
                policy_digest: TEST_POLICY_DIGEST,
            },
            MAX_OPERATION_FRAME_BYTES_V1,
        )
        .expect("encode second qualification result");
        send_operation(
            &mut stream,
            &operation_response(&requalify, STATUS_OK_V1, qualification),
        );
    });
    let binding = signer_binding();
    let (session, observations) = connect_test_process(
        &policy,
        "test-chain",
        server_test_network_id(),
        vec![binding.clone()],
    )
    .expect("connect broker session");
    let publisher_peer_id = binding
        .governance_dag_publisher_peer_id
        .clone()
        .expect("configured signer peer ID");
    let public_key = binding
        .governance_dag_publisher_public_key
        .expect("configured signer key");
    let signer = GovernanceDagBrokerSigner {
        session,
        binding,
        metadata_digest: observations[0].metadata_digest,
        publisher_peer_id,
        public_key,
    };
    assert_eq!(
        signer.live_qualification().expect("qualify signer"),
        sorafs_node::GovernanceDagRuntimeProviderQualificationV1::new(7, TEST_POLICY_DIGEST)
    );
    assert_eq!(
        sorafs_node::GovernanceDagRuntimeSigner::sign(
            &signer,
            sorafs_node::GovernanceDagSigningPurposeV1::KeyTransition,
            &governance_payload,
        )
        .expect("sign through broker"),
        test_governance_signature(&governance_payload)
    );
    sorafs_node::GovernanceDagRuntimeSigner::qualification(&signer).expect("requalify signer");
    server.join().expect("join fake broker");
}
#[test]
fn fake_broker_resolves_and_operates_moderation_quarantine_wrapper() {
    let (_directory, _path, policy, listener) = bind_fake_broker();
    let context_digest = [0x31; 32];
    let dek = [0x52; 32];
    let wrapped_dek = vec![0xA7; MAX_MODERATION_QUARANTINE_WRAPPED_DEK_BYTES_V1];
    let expected_wrapped_dek = wrapped_dek.clone();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept fake broker client");
        let handshake = read_handshake(&mut stream);
        assert_eq!(handshake.requested_catalog, vec![moderation_binding()]);
        send_handshake(&mut stream, &handshake_response(&handshake));
        for request_id in 1..=2 {
            let qualify = read_operation(&mut stream);
            assert_eq!(qualify.request_id, request_id);
            assert_eq!(qualify.operation, OPERATION_QUALIFY_V1);
            decode_canonical::<()>(&qualify.payload, MAX_OPERATION_FRAME_BYTES_V1)
                .expect("decode moderation qualification request");
            let qualification = encode_canonical(
                &QualificationResultWireV1 {
                    revision: 7,
                    policy_digest: TEST_POLICY_DIGEST,
                },
                MAX_OPERATION_FRAME_BYTES_V1,
            )
            .expect("encode moderation qualification result");
            send_operation(
                &mut stream,
                &operation_response(&qualify, STATUS_OK_V1, qualification),
            );
        }
        let wrap = read_operation(&mut stream);
        assert_eq!(wrap.request_id, 3);
        assert_eq!(wrap.operation, OPERATION_MODERATION_QUARANTINE_WRAP_DEK_V1);
        assert_eq!(
            decode_canonical::<ModerationQuarantineWrapDekRequestWireV1>(
                &wrap.payload,
                MAX_MODERATION_QUARANTINE_OPERATION_BYTES_V1,
            )
            .expect("decode moderation wrap request"),
            ModerationQuarantineWrapDekRequestWireV1 {
                context_digest,
                dek,
            }
        );
        let wrapped = encode_canonical(
            &ModerationQuarantineWrapDekResultWireV1 {
                wrapped_dek: wrapped_dek.clone(),
            },
            MAX_MODERATION_QUARANTINE_OPERATION_BYTES_V1,
        )
        .expect("encode moderation wrapped DEK");
        send_operation(
            &mut stream,
            &operation_response(&wrap, STATUS_OK_V1, wrapped),
        );
        let unwrap = read_operation(&mut stream);
        assert_eq!(unwrap.request_id, 4);
        assert_eq!(
            unwrap.operation,
            OPERATION_MODERATION_QUARANTINE_UNWRAP_DEK_V1
        );
        assert_eq!(
            decode_nested_canonical::<ModerationQuarantineUnwrapDekRequestWireV1>(
                &unwrap.payload,
                MAX_MODERATION_QUARANTINE_OPERATION_BYTES_V1,
            )
            .expect("decode moderation unwrap request"),
            ModerationQuarantineUnwrapDekRequestWireV1 {
                key_id: SERVER_TEST_MODERATION_KEY_ID.to_owned(),
                context_digest,
                wrapped_dek,
            }
        );
        let unwrapped = encode_canonical(
            &ModerationQuarantineUnwrapDekResultWireV1 { dek },
            MAX_MODERATION_QUARANTINE_OPERATION_BYTES_V1,
        )
        .expect("encode moderation unwrapped DEK");
        send_operation(
            &mut stream,
            &operation_response(&unwrap, STATUS_OK_V1, unwrapped),
        );
    });
    let dependencies = resolve_test_process(&moderation_server_test_catalog(), &policy)
        .expect("resolve moderation quarantine broker wrapper");
    let key_wrapper = dependencies
        .moderation_quarantine_key_wrapper
        .expect("moderation wrapper dependency");
    assert_eq!(
        key_wrapper
            .qualification()
            .expect("requalify moderation wrapper"),
        sorafs_node::ModerationQuarantineKeyProviderQualificationV1::new(7, TEST_POLICY_DIGEST,)
    );
    assert_eq!(key_wrapper.active_key_id(), SERVER_TEST_MODERATION_KEY_ID);
    assert_eq!(
        key_wrapper
            .wrap_dek(context_digest, &dek)
            .expect("wrap DEK through broker"),
        expected_wrapped_dek
    );
    assert_eq!(
        key_wrapper
            .unwrap_dek(
                SERVER_TEST_MODERATION_KEY_ID,
                context_digest,
                &expected_wrapped_dek,
            )
            .expect("unwrap DEK through broker"),
        dek
    );
    server.join().expect("join fake moderation broker");
}
#[test]
fn moderation_wrap_disconnect_is_ambiguous_and_never_replayed() {
    let (_directory, _path, policy, listener) = bind_fake_broker();
    let seen_operations = Arc::new(AtomicU64::new(0));
    let server_seen = Arc::clone(&seen_operations);
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept fake broker client");
        let handshake = read_handshake(&mut stream);
        assert_eq!(handshake.requested_catalog, vec![moderation_binding()]);
        send_handshake(&mut stream, &handshake_response(&handshake));
        let qualify = read_operation(&mut stream);
        server_seen.fetch_add(1, Ordering::SeqCst);
        let qualification = encode_canonical(
            &QualificationResultWireV1 {
                revision: 7,
                policy_digest: TEST_POLICY_DIGEST,
            },
            MAX_OPERATION_FRAME_BYTES_V1,
        )
        .expect("encode moderation qualification");
        send_operation(
            &mut stream,
            &operation_response(&qualify, STATUS_OK_V1, qualification),
        );
        let wrap = read_operation(&mut stream);
        server_seen.fetch_add(1, Ordering::SeqCst);
        assert_eq!(wrap.operation, OPERATION_MODERATION_QUARANTINE_WRAP_DEK_V1);
        stream
            .shutdown(std::net::Shutdown::Both)
            .expect("drop wrap response after dispatch");
    });
    let dependencies = resolve_test_process(&moderation_server_test_catalog(), &policy)
        .expect("resolve moderation wrapper");
    let key_wrapper = dependencies
        .moderation_quarantine_key_wrapper
        .expect("moderation wrapper dependency");
    let context_digest = [0x31; 32];
    let dek = [0x52; 32];
    assert_eq!(
        key_wrapper.wrap_dek(context_digest, &dek),
        Err(sorafs_node::ModerationQuarantineKeyOperationErrorV1::Ambiguous)
    );
    assert_eq!(
        key_wrapper.wrap_dek(context_digest, &dek),
        Err(sorafs_node::ModerationQuarantineKeyOperationErrorV1::Ambiguous),
        "the poisoned session preserves uncertainty and rejects locally without replay"
    );
    server.join().expect("join disconnecting broker");
    assert_eq!(
        seen_operations.load(Ordering::SeqCst),
        2,
        "only qualification and the single dispatched wrap reach the provider"
    );
}
#[test]
fn moderation_provider_unavailable_status_remains_definitive() {
    let (_directory, _path, policy, listener) = bind_fake_broker();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept fake broker client");
        let handshake = read_handshake(&mut stream);
        send_handshake(&mut stream, &handshake_response(&handshake));
        let qualify = read_operation(&mut stream);
        let qualification = encode_canonical(
            &QualificationResultWireV1 {
                revision: 7,
                policy_digest: TEST_POLICY_DIGEST,
            },
            MAX_OPERATION_FRAME_BYTES_V1,
        )
        .expect("encode moderation qualification");
        send_operation(
            &mut stream,
            &operation_response(&qualify, STATUS_OK_V1, qualification),
        );
        let wrap = read_operation(&mut stream);
        let redacted = encode_canonical(&(), MAX_OPERATION_FRAME_BYTES_V1)
            .expect("encode payload-free unavailable result");
        send_operation(
            &mut stream,
            &operation_response(&wrap, STATUS_UNAVAILABLE_V1, redacted),
        );
    });
    let dependencies = resolve_test_process(&moderation_server_test_catalog(), &policy)
        .expect("resolve moderation wrapper");
    let key_wrapper = dependencies
        .moderation_quarantine_key_wrapper
        .expect("moderation wrapper dependency");
    assert_eq!(
        key_wrapper.wrap_dek([0x31; 32], &[0x52; 32]),
        Err(sorafs_node::ModerationQuarantineKeyOperationErrorV1::Unavailable),
        "an authenticated provider-unavailable response proves no wrap completed"
    );
    server.join().expect("join unavailable broker");
}
#[test]
fn reputation_threshold_disconnect_is_ambiguous_and_never_replayed() {
    let (_directory, _path, policy, listener) = bind_fake_broker();
    let seen = Arc::new(AtomicU64::new(0));
    let server_seen = Arc::clone(&seen);
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept fake broker client");
        let handshake = read_handshake(&mut stream);
        send_handshake(&mut stream, &handshake_response(&handshake));
        let qualify = read_operation(&mut stream);
        server_seen.fetch_add(1, Ordering::SeqCst);
        assert_eq!(qualify.operation, OPERATION_QUALIFY_V1);
        assert_eq!(
            qualify.binding.slot,
            IrohaRuntimeProviderSlotV1::ReputationThresholdSigner.wire_id()
        );
        let qualification = encode_canonical(
            &QualificationResultWireV1 {
                revision: 7,
                policy_digest: TEST_POLICY_DIGEST,
            },
            MAX_OPERATION_FRAME_BYTES_V1,
        )
        .expect("encode reputation threshold qualification");
        send_operation(
            &mut stream,
            &operation_response(&qualify, STATUS_OK_V1, qualification),
        );
        let reconcile = read_operation(&mut stream);
        server_seen.fetch_add(1, Ordering::SeqCst);
        assert_eq!(
            reconcile.operation,
            OPERATION_REPUTATION_THRESHOLD_RECONCILE_V1
        );
        stream
            .shutdown(std::net::Shutdown::Both)
            .expect("drop reputation threshold response after dispatch");
    });
    let dependencies = resolve_test_process(
        &reputation_runtime_test_catalog(IrohaRuntimeProviderSlotV1::ReputationThresholdSigner),
        &policy,
    )
    .expect("resolve reputation threshold signer");
    let signer = dependencies
        .sorafs_reputation_threshold_signer
        .as_ref()
        .expect("reputation threshold dependency");
    let request = reputation_test_threshold_request();
    let first =
        sorafs_node::reputation::runtime::ReputationThresholdSignerClientV1::reconcile_signature(
            signer.as_ref(),
            &request,
        )
        .expect_err("disconnect after dispatch is ambiguous");
    let second =
        sorafs_node::reputation::runtime::ReputationThresholdSignerClientV1::reconcile_signature(
            signer.as_ref(),
            &request,
        )
        .expect_err("poisoned session rejects locally");
    assert_eq!(first.receipt(), request.idempotency_key);
    assert_eq!(second.receipt(), request.idempotency_key);
    server.join().expect("join disconnecting reputation broker");
    assert_eq!(
        seen.load(Ordering::SeqCst),
        2,
        "only qualification and one reconcile reach the provider"
    );
}
#[test]
fn fake_broker_rejects_drift_and_poisoned_session_without_replay() {
    let (_directory, _path, policy, listener) = bind_fake_broker();
    let seen = Arc::new(AtomicU64::new(0));
    let server_seen = Arc::clone(&seen);
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept fake broker client");
        let handshake = read_handshake(&mut stream);
        send_handshake(&mut stream, &handshake_response(&handshake));
        let qualify = read_operation(&mut stream);
        server_seen.fetch_add(1, Ordering::SeqCst);
        let redacted = encode_canonical(&(), MAX_OPERATION_FRAME_BYTES_V1)
            .expect("encode redacted provider error");
        send_operation(
            &mut stream,
            &operation_response(&qualify, STATUS_STALE_OR_REVOKED_V1, redacted),
        );
    });
    let binding = signer_binding();
    let (session, observations) = connect_test_process(
        &policy,
        "test-chain",
        server_test_network_id(),
        vec![binding.clone()],
    )
    .expect("connect broker session");
    let publisher_peer_id = binding
        .governance_dag_publisher_peer_id
        .clone()
        .expect("configured signer peer ID");
    let public_key = binding
        .governance_dag_publisher_public_key
        .expect("configured signer key");
    let signer = GovernanceDagBrokerSigner {
        session,
        binding,
        metadata_digest: observations[0].metadata_digest,
        publisher_peer_id,
        public_key,
    };
    assert_eq!(
        sorafs_node::GovernanceDagRuntimeSigner::qualification(&signer),
        Err(ERROR_STALE_OR_REVOKED.to_owned())
    );
    assert_eq!(
        sorafs_node::GovernanceDagRuntimeSigner::qualification(&signer),
        Err(ERROR_STALE_OR_REVOKED.to_owned()),
        "revocation remains a permanent failure without another provider call"
    );
    server.join().expect("join fake broker");
    assert_eq!(seen.load(Ordering::SeqCst), 1);
}
#[test]
fn fake_broker_reports_cas_ambiguity_and_never_retries() {
    let (_directory, _path, policy, listener) = bind_fake_broker();
    let seen = Arc::new(AtomicU64::new(0));
    let server_seen = Arc::clone(&seen);
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept fake broker client");
        let handshake = read_handshake(&mut stream);
        send_handshake(&mut stream, &handshake_response(&handshake));
        let qualify = read_operation(&mut stream);
        server_seen.fetch_add(1, Ordering::SeqCst);
        let qualification = encode_canonical(
            &QualificationResultWireV1 {
                revision: 7,
                policy_digest: TEST_POLICY_DIGEST,
            },
            MAX_OPERATION_FRAME_BYTES_V1,
        )
        .expect("encode qualification result");
        send_operation(
            &mut stream,
            &operation_response(&qualify, STATUS_OK_V1, qualification),
        );
        let compare_and_swap = read_operation(&mut stream);
        server_seen.fetch_add(1, Ordering::SeqCst);
        assert_eq!(compare_and_swap.request_id, 2);
        assert_eq!(
            compare_and_swap.operation,
            OPERATION_SEALED_COMPARE_AND_SWAP_V1
        );
        drop(stream);
    });
    let binding = checkpoint_binding();
    let (session, observations) = connect_test_process(
        &policy,
        "test-chain",
        server_test_network_id(),
        vec![binding.clone()],
    )
    .expect("connect broker session");
    let store = GovernanceDagBrokerCheckpointStore {
        session,
        binding,
        metadata_digest: observations[0].metadata_digest,
    };
    store.live_qualification().expect("qualify store");
    let slot = sorafs_node::GovernanceDagSealedStateSlot::PublishIntent;
    let next = sorafs_node::GovernanceDagSealedStateRecord::new(slot, 1, vec![1, 2, 3]);
    assert_eq!(
        sorafs_node::GovernanceDagSealedCheckpointStore::compare_and_swap(
            &store,
            slot,
            None,
            next.clone(),
        ),
        Err(ERROR_AMBIGUOUS.to_owned())
    );
    assert_eq!(
        sorafs_node::GovernanceDagSealedCheckpointStore::compare_and_swap(&store, slot, None, next,),
        Err(ERROR_AMBIGUOUS.to_owned()),
        "the unresolved mutation remains ambiguous without another provider call"
    );
    server.join().expect("join fake broker");
    assert_eq!(
        seen.load(Ordering::SeqCst),
        2,
        "the ambiguous mutation must not be replayed"
    );
}
#[test]
fn fake_broker_rejects_substituted_handshake_catalog() {
    let (_directory, _path, policy, listener) = bind_fake_broker();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept fake broker client");
        let handshake = read_handshake(&mut stream);
        let mut response = handshake_response(&handshake);
        response.requested_catalog[0]
            .handle
            .push_str("-substituted");
        response.observations[0].binding = response.requested_catalog[0].clone();
        let transcript = ServerTranscriptFieldsV1 {
            chain_id: response.chain_id.clone(),
            network_id: response.network_id,
            requested_catalog: response.requested_catalog.clone(),
            client_nonce: response.client_nonce,
            catalog_digest: response.catalog_digest,
            client_transcript_digest: response.client_transcript_digest,
            session_id: response.session_id,
            observations: response.observations.clone(),
        };
        response.server_transcript_digest =
            server_transcript_digest(&transcript).expect("seal substituted server transcript");
        send_handshake(&mut stream, &response);
    });
    assert!(matches!(
        connect_test_process(
            &policy,
            "test-chain",
            server_test_network_id(),
            vec![signer_binding()],
        ),
        Err(BrokerError::BindingMismatch)
    ));
    server.join().expect("join fake broker");
}
#[test]
fn billing_catalog_requires_all_six_exact_backends() {
    use IrohaRuntimeProviderSlotV1 as Slot;
    let billing_slots = [
        Slot::BillingFinalizedQuery,
        Slot::BillingJournalVerifier,
        Slot::BillingStatementSigner,
        Slot::BillingStatementPublisher,
        Slot::BillingAcknowledgementAuthority,
        Slot::BillingEpochWitnessStore,
    ];
    for slot in billing_slots {
        let catalog = IrohaRuntimeProviderBindingsV1::qualified_for_test(
            "server-test-chain",
            slot,
            billing_runtime_test_handle(slot),
            7,
            TEST_POLICY_DIGEST,
        );
        prepare_test_server_state(&catalog, billing_runtime_backends(slot, false))
            .unwrap_or_else(|error| panic!("accept exact {slot:?} billing backend: {error:?}"));
        assert!(matches!(
            prepare_test_server_state(&catalog, RuntimeProviderBrokerBackendsV1::new(),),
            Err(RuntimeProviderBrokerServerErrorV1::BackendSetMismatch)
        ));
        assert!(matches!(
            prepare_test_server_state(&catalog, billing_runtime_backends(slot, true),),
            Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch)
        ));
    }
}
#[test]
fn billing_runtime_operation_matrix_is_strict_and_bounded() {
    use IrohaRuntimeProviderSlotV1 as Slot;
    let billing_slots = [
        Slot::BillingFinalizedQuery,
        Slot::BillingJournalVerifier,
        Slot::BillingStatementSigner,
        Slot::BillingStatementPublisher,
        Slot::BillingAcknowledgementAuthority,
        Slot::BillingEpochWitnessStore,
    ];
    let unit = encode_canonical(&(), MAX_BILLING_CONTROL_FRAME_BYTES_V1)
        .expect("encode billing control request");
    for (index, slot) in billing_slots.into_iter().enumerate() {
        validate_wire_binding(&billing_runtime_test_binding(slot))
            .expect("accept exact payload-free billing binding");
        let qualify = billing_operation_request(
            slot,
            u64::try_from(index + 1).expect("request id"),
            OPERATION_QUALIFY_V1,
            unit.clone(),
        );
        validate_operation_request(&qualify).expect("accept billing qualification request");
        let readiness = billing_operation_request(
            slot,
            u64::try_from(index + 10).expect("request id"),
            OPERATION_BILLING_READINESS_V1,
            unit.clone(),
        );
        validate_operation_request(&readiness)
            .expect("accept role-matched billing readiness request");
    }
    for operation in OPERATION_BILLING_IDENTITY_V1..=OPERATION_BILLING_COMPARE_AND_SWAP_EPOCH_V1 {
        assert!(operation_is_known(operation));
        assert!(operation_frame_limit(operation) <= MAX_OPERATION_FRAME_BYTES_V1);
    }
    assert!(
        std::hint::black_box(MAX_BILLING_RUNTIME_FRAME_BYTES_V1) < MAX_OPERATION_FRAME_BYTES_V1,
        "billing frames must not inherit the 512 MiB appeal-finance ceiling"
    );
    assert_eq!(
        operation_frame_limit(OPERATION_BILLING_QUERY_PAGE_V1),
        MAX_BILLING_RUNTIME_FRAME_BYTES_V1
    );
    assert_eq!(
        operation_frame_limit(OPERATION_BILLING_LOOKUP_PUBLICATION_V1),
        MAX_BILLING_RUNTIME_FRAME_BYTES_V1
    );
    assert_eq!(
        operation_frame_limit(OPERATION_BILLING_IDENTITY_V1),
        MAX_BILLING_CONTROL_FRAME_BYTES_V1
    );
    let epoch_identity = billing_operation_request(
        Slot::BillingEpochWitnessStore,
        30,
        OPERATION_BILLING_IDENTITY_V1,
        unit.clone(),
    );
    assert_eq!(
        validate_operation_request(&epoch_identity),
        Err(BrokerError::BindingMismatch),
        "the witness store rejects another slot's fabricated identity operation"
    );
    let zero_digest = billing_operation_request(
        Slot::BillingStatementSigner,
        31,
        OPERATION_BILLING_SIGN_STATEMENT_DIGEST_V1,
        encode_canonical(
            &BillingSignDigestRequestWireV1 { digest: [0; 32] },
            MAX_BILLING_CONTROL_FRAME_BYTES_V1,
        )
        .expect("encode zero billing digest"),
    );
    assert_eq!(
        validate_operation_request(&zero_digest),
        Err(BrokerError::Rejected)
    );
    let valid_digest = billing_operation_request(
        Slot::BillingStatementSigner,
        32,
        OPERATION_BILLING_SIGN_STATEMENT_DIGEST_V1,
        encode_canonical(
            &BillingSignDigestRequestWireV1 { digest: [0xB2; 32] },
            MAX_BILLING_CONTROL_FRAME_BYTES_V1,
        )
        .expect("encode billing digest"),
    );
    validate_operation_request(&valid_digest).expect("accept nonzero statement-signing digest");
    let substituted_role = billing_operation_request(
        Slot::BillingFinalizedQuery,
        33,
        OPERATION_BILLING_SIGN_STATEMENT_DIGEST_V1,
        valid_digest.payload.clone(),
    );
    assert_eq!(
        validate_operation_request(&substituted_role),
        Err(BrokerError::BindingMismatch)
    );
    let mut publication = billing_operation_request(
        Slot::BillingStatementPublisher,
        34,
        OPERATION_BILLING_PUBLISH_STATEMENT_V1,
        unit.clone(),
    );
    assert_eq!(
        validate_operation_result(
            &publication,
            STATUS_AMBIGUOUS_V1,
            &unit,
            &server_test_network_id(),
        ),
        Ok(()),
        "uncertain immutable publication is reconciled by lookup"
    );
    publication.operation = OPERATION_BILLING_LOOKUP_PUBLICATION_V1;
    assert_eq!(
        validate_operation_result(
            &publication,
            STATUS_AMBIGUOUS_V1,
            &unit,
            &server_test_network_id(),
        ),
        Err(BrokerError::Protocol),
        "read-only publication lookup cannot be ambiguous"
    );
    let mut witness = billing_operation_request(
        Slot::BillingEpochWitnessStore,
        35,
        OPERATION_BILLING_COMPARE_AND_SWAP_EPOCH_V1,
        unit.clone(),
    );
    assert_eq!(
        validate_operation_result(
            &witness,
            STATUS_CONFLICT_V1,
            &unit,
            &server_test_network_id(),
        ),
        Ok(())
    );
    witness.operation = OPERATION_BILLING_LOAD_LATEST_EPOCH_V1;
    assert_eq!(
        validate_operation_result(
            &witness,
            STATUS_CONFLICT_V1,
            &unit,
            &server_test_network_id(),
        ),
        Err(BrokerError::Protocol)
    );
}

#[test]
fn evidence_viewer_grant_nonce_is_required_by_canonical_broker_requests() {
    let binding = evidence_viewer_binding(IrohaRuntimeProviderSlotV1::EvidenceViewerGrantAuthority);
    let now_unix_ms = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    let claims = sorafs_node::evidence_viewer::EvidenceViewerGrantClaimsV1 {
        session_id: [0x11; 16],
        case_id: "case-1".to_owned(),
        round_id: "round-1".to_owned(),
        quarantine_id: [0x12; 16],
        viewer_account: "viewer".to_owned(),
        role: sorafs_node::evidence_viewer::EvidenceViewerRoleV1::Juror,
        purpose_digest: [0x13; 32],
        issuance_nonce: [0x14; 32],
        generation: 1,
        issued_at_unix_ms: now_unix_ms,
        expires_at_unix_ms: now_unix_ms + 60_000,
    };
    let request = EvidenceViewerGrantIssueRequestWireV1 {
        claims: claims.clone(),
    };
    let canonical = encode_canonical(&request, MAX_EVIDENCE_VIEWER_CLAIMS_BYTES_V1).unwrap();
    for flags in [0, norito::core::header_flags::COMPACT_LEN] {
        let _layout = norito::core::DecodeFlagsGuard::enter(flags);
        assert_eq!(
            encode_canonical(&request, MAX_EVIDENCE_VIEWER_CLAIMS_BYTES_V1).unwrap(),
            canonical
        );
        let valid = validated_test_operation(
            binding.clone(),
            OPERATION_EVIDENCE_VIEWER_GRANT_ISSUE_V1,
            canonical.clone(),
        );
        validate_operation_request(&valid).expect("complete nonce-bearing request");
    }
    let mut zero = claims;
    zero.issuance_nonce = [0; 32];
    let mut invalid =
        validated_test_operation(binding, OPERATION_EVIDENCE_VIEWER_GRANT_ISSUE_V1, canonical);
    invalid.payload = encode_canonical(
        &EvidenceViewerGrantIssueRequestWireV1 { claims: zero },
        MAX_EVIDENCE_VIEWER_CLAIMS_BYTES_V1,
    )
    .unwrap();
    invalid.payload_digest = operation_payload_digest(&invalid.payload);
    assert_eq!(
        validate_operation_request(&invalid),
        Err(BrokerError::Protocol),
        "the stale envelope digest is rejected before nonce validation"
    );
    let invalid = make_operation_request(
        invalid.session_id,
        invalid.request_id,
        invalid.binding.clone(),
        invalid.provider_metadata_digest,
        invalid.operation,
        std::mem::take(&mut invalid.payload),
    )
    .expect("bind the zero-nonce payload into a canonical request envelope");
    assert_eq!(
        validate_operation_request(&invalid),
        Err(BrokerError::Rejected)
    );
}

#[test]
fn provider_ingest_signer_wire_binds_both_accounts_and_refuses_missing_authority() {
    let signer = AccountId::new(
        provider_ingest_completion_test_keypair()
            .public_key()
            .clone(),
    );
    let owner_key =
        iroha_crypto::KeyPair::try_from_seed(vec![0x7B; 32], iroha_crypto::Algorithm::Ed25519)
            .unwrap();
    let owner = AccountId::new(owner_key.public_key().clone());
    let mut context = provider_ingest_completion_test_context(signer.clone());
    context.expected_authority.provider_owner = owner.clone();
    let wire = provider_ingest_signer_context_to_wire(&context).unwrap();
    assert_eq!(
        provider_ingest_signer_context_from_wire(&wire).unwrap(),
        context
    );
    let mut instruction = provider_ingest_completion_test_instruction(signer.clone());
    instruction.expected_authority = context.expected_authority.clone();
    let payload = provider_ingest_completion_test_payload_with_executable(
        server_test_network_id(),
        signer,
        Executable::Instructions(
            vec![iroha_data_model::isi::InstructionBox::from(
                instruction.clone(),
            )]
            .into(),
        ),
    );
    assert_eq!(
        ensure_provider_ingest_completion_payload(&payload, &context, &server_test_network_id()),
        Ok(())
    );
    let owner_signed = provider_ingest_completion_test_payload_with_executable(
        server_test_network_id(),
        owner.clone(),
        Executable::Instructions(
            vec![iroha_data_model::isi::InstructionBox::from(instruction)].into(),
        ),
    );
    assert_eq!(
        ensure_provider_ingest_completion_payload(
            &owner_signed,
            &context,
            &server_test_network_id()
        ),
        Err(BrokerError::BindingMismatch)
    );
    let mut changed = context.clone();
    changed.expected_authority.completion_signer = owner;
    let changed = provider_ingest_signer_context_from_wire(
        &provider_ingest_signer_context_to_wire(&changed).unwrap(),
    )
    .unwrap();
    assert_eq!(
        ensure_provider_ingest_completion_payload(&payload, &changed, &server_test_network_id()),
        Err(BrokerError::BindingMismatch)
    );
    let mut missing = wire.clone();
    missing.expected_authority.clear();
    assert!(provider_ingest_signer_context_from_wire(&missing).is_err());
    let mut trailing = wire;
    trailing.expected_authority.push(0);
    assert!(provider_ingest_signer_context_from_wire(&trailing).is_err());
}

#[test]
fn server_endpoint_policy_preserves_and_rejects_programmatic_observer_deadlines() {
    let mut config = iroha_config::parameters::actual::RuntimeProviderBroker {
        endpoint_path: validated_production_endpoint(),
        credential_max_memory_bytes:
            iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES,
        observer_operation_timeout: Duration::from_millis(500),
    };
    let policy = EndpointPolicy::from_server_policy(&config).unwrap();
    assert_eq!(
        policy.observer_operation_timeout,
        Duration::from_millis(500)
    );
    assert_eq!(policy.path.as_path(), config.endpoint_path.as_path());
    for invalid in [
        Duration::ZERO,
        BROKER_IO_TIMEOUT_V1 + Duration::from_millis(1),
    ] {
        config.observer_operation_timeout = invalid;
        assert_eq!(
            EndpointPolicy::from_server_policy(&config).unwrap_err(),
            RuntimeProviderBrokerServerErrorV1::Protocol
        );
    }
}
