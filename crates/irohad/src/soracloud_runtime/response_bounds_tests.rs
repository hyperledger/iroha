// Canonical Soracloud response-frame bounds and VM gas admission controls.
// Included by the existing tests module to preserve its exact test namespace.
fn encoded_soracloud_response_len(
    operation: SoracloudHostOperationV1,
    payload: SoracloudHostResponsePayloadV1,
) -> usize {
    norito::to_bytes(&SoracloudHostResponseEnvelopeV1 {
        schema_version: SORACLOUD_HOST_RESPONSE_VERSION_V1,
        operation,
        payload,
    })
    .expect("encode Soracloud response fixture")
    .len()
}
fn assert_soracloud_response_bound_matches(
    operation: SoracloudHostOperationV1,
    payload: SoracloudHostResponsePayloadV1,
    shape: SoracloudResponseShape<'_>,
) {
    assert_eq!(
        soracloud_response_encoded_len_bound(operation, shape),
        Some(encoded_soracloud_response_len(operation, payload))
    );
}
#[test]
fn soracloud_response_preflight_is_independent_of_ambient_decode_flags() {
    let canonical = {
        let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        encoded_soracloud_response_len(
            SoracloudHostOperationV1::ReadConfig,
            SoracloudHostResponsePayloadV1::ReadConfig(SoracloudReadConfigResponseV1 {
                found: false,
                payload_bytes: Vec::new(),
            }),
        )
    };
    for flags in [0, norito::core::header_flags::COMPACT_LEN] {
        let _flags = norito::core::DecodeFlagsGuard::enter(flags);
        assert_eq!(
            soracloud_response_encoded_len_bound(
                SoracloudHostOperationV1::ReadConfig,
                SoracloudResponseShape::FoundPayload { payload_bytes: 0 },
            ),
            Some(canonical)
        );
    }
}

#[test]
fn soracloud_response_bounds_match_empty_response_shapes() {
    let hash = Hash::new(b"empty-response-shape");
    for (operation, payload, shape) in [
        (
            SoracloudHostOperationV1::ReadCommittedState,
            SoracloudHostResponsePayloadV1::ReadCommittedState(
                SoracloudReadCommittedStateResponseV1 { entry: None },
            ),
            SoracloudResponseShape::ReadCommittedState(None),
        ),
        (
            SoracloudHostOperationV1::EmitStateMutation,
            SoracloudHostResponsePayloadV1::EmitStateMutation(
                SoracloudEmitStateMutationResponseV1 {
                    mutation_commitment: hash,
                },
            ),
            SoracloudResponseShape::SingleHash,
        ),
        (
            SoracloudHostOperationV1::EmitMailboxMessage,
            SoracloudHostResponsePayloadV1::EmitMailboxMessage(
                SoracloudEmitMailboxMessageResponseV1 {
                    message_id: hash,
                    payload_commitment: hash,
                },
            ),
            SoracloudResponseShape::HashPair,
        ),
        (
            SoracloudHostOperationV1::AppendJournal,
            SoracloudHostResponsePayloadV1::AppendJournal(SoracloudAppendJournalResponseV1 {
                artifact_hash: hash,
            }),
            SoracloudResponseShape::SingleHash,
        ),
        (
            SoracloudHostOperationV1::PublishCheckpoint,
            SoracloudHostResponsePayloadV1::PublishCheckpoint(
                SoracloudPublishCheckpointResponseV1 {
                    artifact_hash: hash,
                },
            ),
            SoracloudResponseShape::SingleHash,
        ),
        (
            SoracloudHostOperationV1::ReadConfig,
            SoracloudHostResponsePayloadV1::ReadConfig(SoracloudReadConfigResponseV1 {
                found: false,
                payload_bytes: Vec::new(),
            }),
            SoracloudResponseShape::FoundPayload { payload_bytes: 0 },
        ),
        (
            SoracloudHostOperationV1::ReadSecretEnvelope,
            SoracloudHostResponsePayloadV1::ReadSecretEnvelope(
                SoracloudReadSecretEnvelopeResponseV1 { envelope: None },
            ),
            SoracloudResponseShape::SecretEnvelope(None),
        ),
    ] {
        assert_soracloud_response_bound_matches(operation, payload, shape);
    }
}
#[test]
fn soracloud_response_bounds_match_maximal_host_response_shapes() {
    let payload_bytes = vec![
        0xA5;
        usize::try_from(SORACLOUD_HOST_VARIABLE_RESPONSE_MAX_BYTES)
            .expect("response bound fits host usize")
    ];
    assert_soracloud_response_bound_matches(
        SoracloudHostOperationV1::ReadConfig,
        SoracloudHostResponsePayloadV1::ReadConfig(SoracloudReadConfigResponseV1 {
            found: true,
            payload_bytes: payload_bytes.clone(),
        }),
        SoracloudResponseShape::FoundPayload {
            payload_bytes: payload_bytes.len(),
        },
    );
}
#[test]
fn soracloud_response_bounds_match_adversarial_framing_boundaries() {
    let payload = vec![0x5A; 16_384];
    let entry = SoraServiceStateEntryV1 {
        schema_version: iroha_data_model::soracloud::SORA_SERVICE_STATE_ENTRY_VERSION_V1,
        service_name: "s".repeat(127).parse().expect("valid service name"),
        // Keep Name fields within their actual byte limit while the String
        // and payload fields cross the larger Norito framing boundary.
        service_version: "v".repeat(16_383),
        binding_name: "b"
            .repeat(iroha_model_base::name::MAX_NAME_BYTES)
            .parse()
            .expect("valid maximal binding name"),
        state_key: format!("/{}", "k".repeat(16_383)),
        encryption: iroha_data_model::soracloud::SoraStateEncryptionV1::FheCiphertext,
        payload: payload.clone(),
        payload_bytes: NonZeroU64::new(
            u64::try_from(payload.len()).expect("payload length fits u64"),
        )
        .expect("non-zero payload"),
        payload_commitment: Hash::new(&payload),
        fhe_public_key_digest: Some(Hash::new(b"public-key")),
        fhe_residual_multiple_bound: Some(u128::MAX),
        fhe_bound_mode: Some(iroha_data_model::soracloud::BfvCiphertextBoundModeV1::BoundedNoise),
        last_update_sequence: u64::MAX,
        governance_tx_hash: Hash::new(b"governance"),
        source_action: SoraServiceLifecycleActionV1::FheJobRun,
    };
    assert_soracloud_response_bound_matches(
        SoracloudHostOperationV1::ReadCommittedState,
        SoracloudHostResponsePayloadV1::ReadCommittedState(SoracloudReadCommittedStateResponseV1 {
            entry: Some(entry.clone()),
        }),
        SoracloudResponseShape::ReadCommittedState(Some(&entry)),
    );
    let envelope = SecretEnvelopeV1 {
        schema_version: SECRET_ENVELOPE_VERSION_V1,
        encryption: SecretEnvelopeEncryptionV1::ClientCiphertext,
        key_id: "k".repeat(128),
        key_version: std::num::NonZeroU32::new(u32::MAX).expect("non-zero key version"),
        nonce: vec![0x11; 127],
        ciphertext: vec![0x22; 128],
        commitment: Hash::new(vec![0x22; 128]),
        aad_digest: Some(Hash::new(b"aad")),
    };
    assert_soracloud_response_bound_matches(
        SoracloudHostOperationV1::ReadSecretEnvelope,
        SoracloudHostResponsePayloadV1::ReadSecretEnvelope(SoracloudReadSecretEnvelopeResponseV1 {
            envelope: Some(envelope.clone()),
        }),
        SoracloudResponseShape::SecretEnvelope(Some(&envelope)),
    );
}
#[test]
fn soracloud_response_frame_gas_boundary_precedes_state_observation() -> Result<()> {
    let bundle = load_deployment_bundle_fixture()?;
    let temp_dir = tempfile::tempdir()?;
    let entry = SoraServiceStateEntryV1 {
        schema_version: iroha_data_model::soracloud::SORA_SERVICE_STATE_ENTRY_VERSION_V1,
        service_name: bundle.service.service_name.clone(),
        service_version: bundle.service.service_version.clone(),
        binding_name: "session_store".parse().expect("valid binding"),
        state_key: "/state/session/alice".to_owned(),
        encryption: iroha_data_model::soracloud::SoraStateEncryptionV1::ClientCiphertext,
        payload: b"alice-session".to_vec(),
        payload_bytes: std::num::NonZeroU64::new(13).expect("non-zero"),
        payload_commitment: Hash::new(b"alice-session"),
        fhe_public_key_digest: None,
        fhe_residual_multiple_bound: None,
        fhe_bound_mode: None,
        last_update_sequence: 4,
        governance_tx_hash: Hash::new(b"gov-session"),
        source_action: SoraServiceLifecycleActionV1::StateMutation,
    };
    let mut committed_entries = BTreeMap::new();
    committed_entries.insert(
        (
            "session_store".to_owned(),
            "/state/session/alice".to_owned(),
        ),
        entry.clone(),
    );
    let request_envelope = SoracloudHostRequestEnvelopeV1 {
        schema_version: iroha_data_model::soracloud::SORACLOUD_HOST_REQUEST_VERSION_V1,
        operation: SoracloudHostOperationV1::ReadCommittedState,
        payload: SoracloudHostRequestPayloadV1::ReadCommittedState(
            iroha_data_model::soracloud::SoracloudReadCommittedStateRequestV1 {
                binding_name: "session_store".parse().expect("valid binding"),
                state_key: "/state/session/alice".to_owned(),
            },
        ),
    };
    let request_payload = norito::to_bytes(&request_envelope)?;
    let request_tlv = make_pointer_tlv(PointerType::SoracloudRequest, &request_payload);
    let response_bytes = encoded_soracloud_response_len(
        SoracloudHostOperationV1::ReadCommittedState,
        SoracloudHostResponsePayloadV1::ReadCommittedState(SoracloudReadCommittedStateResponseV1 {
            entry: Some(entry.clone()),
        }),
    );
    let response_gas =
        ivm::gas::syscall_byte_gas(ivm::gas::G_SORACLOUD, request_payload.len(), response_bytes);
    let mut code = Vec::new();
    code.extend_from_slice(
        &ivm::encoding::wide::encode_syscallx(SYSCALL_SORACLOUD_READ_COMMITTED_STATE).to_le_bytes(),
    );
    code.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
    for reserve in [response_gas - 1, response_gas] {
        let query_request = sample_ordered_mailbox_request(
            &bundle,
            "query",
            sample_mailbox_message(&bundle, "query", b"frame-gas-boundary".to_vec()),
        );
        let mut host = SoracloudIvmHost::new(
            query_request,
            temp_dir.path().to_path_buf(),
            committed_entries.clone(),
        );
        // SCALLX uses five gas; HALT has zero cost.
        let mut vm = IVM::new(5 + reserve);
        vm.load_code(&code)?;
        let request_ptr = vm.alloc_input_tlv(&request_tlv)?;
        vm.set_register(10, request_ptr);
        let result = vm.run_with_host(&mut host);
        assert_eq!(host.metering_query_count(), 1);
        if reserve < response_gas {
            assert_eq!(result, Err(VMError::OutOfGas));
            assert_eq!(vm.register(10), request_ptr);
            assert_eq!(host.metering_allocation_count(), 0);
            assert!(
                host.local_read_bindings().is_empty(),
                "framing gas must be admitted before recording a state observation"
            );
            assert!(!host.has_local_read_side_effects());
        } else {
            result?;
            assert_eq!(
                host.local_read_bindings(),
                vec![state_entry_binding(&entry)]
            );
            assert_eq!(host.metering_allocation_count(), 1);
            let response = vm.validate_tlv(vm.register(10))?;
            assert_eq!(response.type_id, PointerType::SoracloudResponse);
            assert_eq!(response.payload.len(), response_bytes);
            assert_eq!(vm.remaining_gas(), 0);
        }
    }
    Ok(())
}
#[test]
fn soracloud_response_bound_overflow_fails_closed() {
    assert_eq!(norito_byte_vec_encoded_len(usize::MAX), None);
    assert_eq!(norito_struct_encoded_len([usize::MAX]), None);
    assert_eq!(
        soracloud_response_encoded_len_bound(
            SoracloudHostOperationV1::ReadConfig,
            SoracloudResponseShape::FoundPayload {
                payload_bytes: usize::MAX,
            },
        ),
        None
    );
}
