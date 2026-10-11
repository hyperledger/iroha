// KAGEMUSHA V1 payer-signed top-up admission regressions.
pub(crate) mod kagemusha_top_up_admission_tests {
    use super::*;
    use crate::state::StateBlock;
    use iroha_data_model::{
        isi::KAGEMUSHA_CHAIN_VERSION_V1,
        kagemusha::{
            KAGEMUSHA_HISTORY_ACCUMULATOR_BYTES_V1, KAGEMUSHA_WIRE_VERSION_V1,
            KAGEMUSHA_XCHACHA20POLY1305_NONCE_BYTES_V1, KAGEMUSHA_XCHACHA20POLY1305_TAG_BYTES_V1,
            KagemushaDevicePublicKeyV1, KagemushaDeviceSignatureV1,
            KagemushaEncryptedCreditEnvelopeV1, KagemushaHardwareCredentialV1,
            KagemushaMintAuthorizationV1, KagemushaPairedProofV1,
            kagemusha_credit_opening_canonical_len_v1, kagemusha_device_key_reference_v1,
            kagemusha_liability_pool_id_v1,
        },
        nexus::AxtAssetIncarnationV1,
    };
    use p256::ecdsa::{Signature as P256Signature, SigningKey, signature::Signer as _};

    fn fixture_account(seed: u8) -> (AccountId, KeyPair) {
        let keypair = KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519);
        (AccountId::new(keypair.public_key().clone()), keypair)
    }

    fn fixture_device_signature(key: &SigningKey, message: &[u8]) -> KagemushaDeviceSignatureV1 {
        let signature: P256Signature = key.sign(message);
        let signature = signature.normalize_s().unwrap_or(signature);
        KagemushaDeviceSignatureV1::from_raw_bytes(signature.to_bytes().as_ref())
            .expect("canonical device signature")
    }

    /// Shape-valid negative fixture with opaque proofs; never a valid monetary authorization.
    pub(crate) fn fixture_top_up_request(
        payer: AccountId,
        network_id: iroha_data_model::NetworkId,
    ) -> KagemushaTopUpRequestV1 {
        let asset = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").expect("fixture domain"),
            "xor".parse().expect("fixture asset name"),
        );
        let asset_incarnation =
            AxtAssetIncarnationV1::try_from_bytes(*Hash::new(b"queue-top-up-asset").as_ref())
                .expect("canonical asset incarnation");
        let device_key =
            SigningKey::from_bytes((&[0x31; 32]).into()).expect("deterministic P-256 device key");
        let device_public_key = KagemushaDevicePublicKeyV1::from_sec1_bytes(
            device_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        )
        .expect("canonical device public key");
        let device_key_reference = kagemusha_device_key_reference_v1(&device_public_key);
        let suite_id = [0x10; 32];
        let hardware_credential = KagemushaHardwareCredentialV1 {
            app_policy_binding_digest: [0xA6; 32],
            version: KAGEMUSHA_WIRE_VERSION_V1,
            credential_id: [0; 32],
            network_id,
            hardware_profile_id: [0x71; 32],
            suite_id,
            firmware_policy_digest: [0x72; 32],
            policy_epoch: 1,
            lane_commitment: [0x23; 32],
            hardware_epoch_id: [0x73; 32],
            hardware_epoch_generation: 1,
            device_public_key,
            device_key_reference,
            issued_at_ms: 500,
            expires_at_ms: 90_000,
            governance_signature: fixture_device_signature(
                &device_key,
                b"queue KAGEMUSHA top-up credential",
            ),
        }
        .seal_credential_id()
        .expect("seal hardware credential identity");
        let mut recipient_one_time_key = [0; 32];
        recipient_one_time_key[0] = 0x29;
        let mut ephemeral_x25519_public_key = [0; 32];
        ephemeral_x25519_public_key[0] = 0x28;
        let encrypted_credit = KagemushaEncryptedCreditEnvelopeV1 {
            version: KAGEMUSHA_WIRE_VERSION_V1,
            ephemeral_x25519_public_key,
            nonce: [0x27; KAGEMUSHA_XCHACHA20POLY1305_NONCE_BYTES_V1],
            ciphertext_and_tag: vec![
                0x27;
                kagemusha_credit_opening_canonical_len_v1()
                    .expect("credit opening length")
                    + KAGEMUSHA_XCHACHA20POLY1305_TAG_BYTES_V1
            ],
        }
        .canonical_bytes_against_recipient_key(recipient_one_time_key)
        .expect("canonical encrypted credit");
        let request = KagemushaTopUpRequestV1 {
            version: KAGEMUSHA_CHAIN_VERSION_V1,
            operation_id: [0x21; 32],
            issuance_commitment: [0; 32],
            credit_id: [0; 32],
            release_id: [0x22; 32],
            suite_id,
            vk_digest: [0x24; 32],
            network_id,
            asset: asset.clone(),
            asset_incarnation,
            scale: 4,
            amount: 25_000,
            liability_pool_id: kagemusha_liability_pool_id_v1(
                &network_id,
                &asset,
                asset_incarnation,
            )
            .expect("liability pool"),
            payer,
            recipient: fixture_account(0x32).0,
            hardware_credential,
            recipient_credential_commitment: [0x25; 32],
            credit_commitment: [0x26; 32],
            recipient_one_time_key,
            encrypted_credit,
            artifact_manifest_digest: [0x28; 32],
            mint_authorization: None,
        }
        .seal_identifiers()
        .expect("seal top-up identifiers");
        let statement = request
            .mint_authorization_statement()
            .expect("mint authorization statement");
        let semantic_digest = statement
            .canonical_digest()
            .expect("mint authorization semantic digest");
        request
            .attach_mint_authorization(KagemushaMintAuthorizationV1 {
                version: KAGEMUSHA_WIRE_VERSION_V1,
                statement,
                proof: KagemushaPairedProofV1 {
                    version: KAGEMUSHA_WIRE_VERSION_V1,
                    eq_protocol_digest: [0x81; 32],
                    ep_protocol_digest: [0x82; 32],
                    semantic_digest,
                    guard_eq_credential_audit: [0x83; 32],
                    guard_ep_credential_audit: [0x84; 32],
                    eq_deferred_audit: [0x85; 32],
                    ep_deferred_audit: [0x86; 32],
                    eq_proof: vec![0x87; 128],
                    ep_proof: vec![0x88; 128],
                    eq_history: vec![0x89; KAGEMUSHA_HISTORY_ACCUMULATOR_BYTES_V1],
                    ep_history: vec![0x8A; KAGEMUSHA_HISTORY_ACCUMULATOR_BYTES_V1],
                },
            })
            .expect("attach mint authorization")
    }

    fn accepted_top_up(
        authority: AccountId,
        keypair: &KeyPair,
        request: KagemushaTopUpRequestV1,

        time_source: &TimeSource,
    ) -> AcceptedTransaction<'static> {
        request
            .validate_shape()
            .expect("fixture must be a structurally valid top-up request");
        accepted_tx_with_attachments(
            authority,
            keypair,
            time_source,
            vec![InstructionBox::from(
                TopUpKagemushaV1::new(request).expect("valid top-up instruction"),
            )],
            Metadata::default(),
            None,
        )
    }

    fn signed_top_up_carrier(
        authority: AccountId,
        keypair: &KeyPair,
        executable: Executable,

        time_source: &TimeSource,
    ) -> SignedTransaction {
        let gas_limit = executable
            .requires_transaction_gas_limit()
            .then(|| NonZeroU64::new(1).expect("non-zero gas limit"));
        TransactionBuilder::new_with_time_source(
            queue_test_network_id(),
            authority,
            time_source,
            FeePaymentIntent::authority(Vec::new(), gas_limit),
        )
        .with_executable(executable)
        .sign(keypair.private_key())
    }

    fn assert_stateful_top_up_rejection(transaction: &SignedTransaction, expected_reason: &str) {
        let state = State::new(
            world_with_test_domains(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let mut state_block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
        let mut state_transaction = state_block.transaction();
        let route = RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL);
        let accepted = AcceptedTransaction::new_unchecked(std::borrow::Cow::Borrowed(transaction));
        let policy_route =
            crate::state::network_policy_routes::CapturedNetworkPolicyRoute::for_component(
                &accepted,
                &state_transaction,
                route,
            )
            .expect("completed original physical policy capture");
        let error = StateBlock::validate_stateful_admission(
            transaction,
            &mut state_transaction,
            route,
            policy_route,
            None,
        )
        .expect_err("stateful admission must repeat the KAGEMUSHA top-up invariant");
        assert!(matches!(
            error,
            TransactionRejectionReason::Validation(ValidationFail::NotPermitted(reason))
                if reason == expected_reason
        ));
    }

    fn assert_queue_top_up_rejection(transaction: SignedTransaction, expected_reason: &str) {
        let accepted = AcceptedTransaction::new_unchecked(std::borrow::Cow::Owned(transaction));
        let checked = CheckedTransaction::new_unchecked(accepted);
        let error = Queue::classify_pending_kagemusha_operation(&checked)
            .expect_err("queue admission must reject a non-canonical KAGEMUSHA top-up carrier");
        assert!(matches!(
            error,
            Error::KagemushaV1OperationCarrierRejected { reason }
                if reason == expected_reason
        ));
    }

    #[test]
    fn queue_rejects_copied_top_up_request_under_foreign_authority() {
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let (payer, _payer_keypair) = fixture_account(0x41);
        let (foreign_authority, foreign_keypair) = fixture_account(0x42);
        let transaction = accepted_top_up(
            foreign_authority,
            &foreign_keypair,
            fixture_top_up_request(payer, queue_test_network_id()),
            &time_source,
        );

        let error = Queue::classify_pending_kagemusha_operation(
            &CheckedTransaction::new_unchecked(transaction),
        )
        .expect_err("a copied request cannot claim its payer's operation id");

        assert!(matches!(
            error,
            Error::KagemushaV1OperationCarrierRejected { reason }
                if reason == "KAGEMUSHA V1 top-up authority must equal the embedded payer"
        ));
    }

    #[test]
    fn queue_classifies_exact_native_payer_signed_top_up() {
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let (payer, payer_keypair) = fixture_account(0x44);
        let transaction = accepted_top_up(
            payer.clone(),
            &payer_keypair,
            fixture_top_up_request(payer.clone(), queue_test_network_id()),
            &time_source,
        );

        let binding = Queue::classify_pending_kagemusha_operation(
            &CheckedTransaction::new_unchecked(transaction),
        )
        .expect("canonical payer-signed top-up must classify")
        .expect("top-up must produce a pending operation binding");

        assert_eq!(binding.authority, payer);
        assert_eq!(binding.operation_id, [0x21; 32]);
        assert_eq!(binding.kind, KagemushaOperationKindV1::TopUp);
    }

    #[test]
    fn stateful_block_admission_rechecks_top_up_payer() {
        let (_, time_source) = TimeSource::new_mock(Duration::default());
        let (payer, _) = fixture_account(0x45);
        let (foreign_authority, foreign_keypair) = fixture_account(0x46);
        let foreign = accepted_top_up(
            foreign_authority,
            &foreign_keypair,
            fixture_top_up_request(payer, queue_test_network_id()),
            &time_source,
        );
        assert_stateful_top_up_rejection(
            foreign.external().expect("direct signed transaction"),
            "KAGEMUSHA V1 top-up authority must equal the embedded payer",
        );
    }

    #[test]
    fn queue_and_stateful_block_admission_reject_mixed_top_up_instruction_carrier() {
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let (payer, payer_keypair) = fixture_account(0x47);
        let top_up = InstructionBox::from(
            TopUpKagemushaV1::new(fixture_top_up_request(
                payer.clone(),
                queue_test_network_id(),
            ))
            .expect("valid top-up instruction"),
        );
        let transaction = signed_top_up_carrier(
            payer,
            &payer_keypair,
            Executable::Instructions(
                vec![
                    top_up,
                    InstructionBox::from(Log::new(Level::INFO, "mixed carrier".into())),
                ]
                .into(),
            ),
            &time_source,
        );

        let expected_reason =
            "a KAGEMUSHA V1 top-up must be the only instruction in its signed transaction";
        assert_queue_top_up_rejection(transaction.clone(), expected_reason);
        assert_stateful_top_up_rejection(&transaction, expected_reason);
    }

    #[test]
    fn queue_and_stateful_block_admission_reject_mixed_batch_top_up_carrier() {
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let (payer, payer_keypair) = fixture_account(0x49);
        let top_up = InstructionBox::from(
            TopUpKagemushaV1::new(fixture_top_up_request(
                payer.clone(),
                queue_test_network_id(),
            ))
            .expect("valid top-up instruction"),
        );
        let transaction = signed_top_up_carrier(
            payer,
            &payer_keypair,
            Executable::Batch(
                vec![
                    ExecutableBatchItem::Instruction(top_up),
                    ExecutableBatchItem::Instruction(InstructionBox::from(Log::new(
                        Level::INFO,
                        "mixed batch carrier".into(),
                    ))),
                ]
                .into(),
            ),
            &time_source,
        );

        let expected_reason =
            "KAGEMUSHA V1 top-up cannot be carried by batch, proved, overlay, or opaque execution";
        assert_queue_top_up_rejection(transaction.clone(), expected_reason);
        assert_stateful_top_up_rejection(&transaction, expected_reason);
    }

    #[test]
    fn queue_and_stateful_block_admission_reject_proved_overlay_top_up_carrier() {
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
        let (payer, payer_keypair) = fixture_account(0x48);
        let top_up = InstructionBox::from(
            TopUpKagemushaV1::new(fixture_top_up_request(
                payer.clone(),
                queue_test_network_id(),
            ))
            .expect("valid top-up instruction"),
        );
        let transaction = signed_top_up_carrier(
            payer,
            &payer_keypair,
            Executable::IvmProved(iroha_data_model::transaction::IvmProved {
                bytecode: iroha_data_model::transaction::executable::IvmBytecode::from_compiled(
                    vec![0],
                ),
                overlay: vec![top_up].into(),
                events_commitment: Hash::new(b"KAGEMUSHA top-up carrier events"),
                gas_policy_commitment: Hash::new(b"KAGEMUSHA top-up carrier gas policy"),
            }),
            &time_source,
        );

        let expected_reason =
            "KAGEMUSHA V1 top-up cannot be carried by batch, proved, overlay, or opaque execution";
        assert_queue_top_up_rejection(transaction.clone(), expected_reason);
        assert_stateful_top_up_rejection(&transaction, expected_reason);
    }
    #[test]
    fn native_top_up_requires_original_commit_attestation() {
        let (_, time) = TimeSource::new_mock(Duration::default());
        let (payer, key) = fixture_account(0x51);
        let top_up = TopUpKagemushaV1::new(fixture_top_up_request(
            payer.clone(),
            queue_test_network_id(),
        ))
        .unwrap();
        let signed = signed_top_up_carrier(
            payer,
            &key,
            Executable::Instructions(vec![InstructionBox::from(top_up)].into()),
            &time,
        );
        let mut builder = iroha_data_model::block::builder::BlockBuilder::new(BlockHeader::new(
            nonzero!(2_u64),
            None,
            None,
            1,
            0,
        ));
        builder.push_transaction(signed);
        let block = builder.build(iroha_data_model::block::BlockSignatures::default());
        assert!(crate::sumeragi::executor::proposal_requires_attestation(&block, u64::MAX));
    }
}
