/// Native proof construction and the real signed executor's qualification refusal boundary.
/// This is not a qualified privacy-success or post-proof rollback test.
mod privacy_occurrence_executor {
    use super::*;
    use crate::{
        privacy_engines::orchard::{
            OrchardChangeProverInputV1, Scope, SpendingKey, authorize_orchard_bundle_v1,
            orchard_empty_root_v1, prepare_orchard_bundle_v1_with_rng,
        },
        privacy_profiles::compiled_privacy_profile_v1,
        privacy_state::PrivacyActivationKeyV1,
        state::seed_committed_transaction_context,
    };
    use iroha_data_model::{
        isi::{error::InvalidParameterError, privacy::SubmitPrivacyProofV1},
        privacy::{
            OrchardHalo2ActionsStatementV1, PrivacyActiveLifecycleV1, PrivacyConsensusLimitsV1,
            PrivacyNativeConsensusBindingV1, PrivacyOrchardActionV1, PrivacyPoolIdV1,
            PrivacyProofBytesV1, PrivacyProofEnvelopeV1, PrivacyProofV1, PrivacyProtocolIdV1,
            PrivacyProtocolLifecycleV1, PrivacyRootV1, PrivacyStatementContextV1,
            PrivacyStatementV1, PrivacyTransactionIntentDigestV1, PrivacyValueBalanceDirectionV1,
            PrivacyValueBalanceV1,
        },
        transaction::{TransactionEntrypoint, TransactionPayload},
    };
    use rand::{SeedableRng as _, rngs::StdRng};
    use std::time::Duration;

    const GAS: u64 = 50_000_000;
    const BEFORE: &str = "privacy_occurrence_before";
    const AFTER: &str = "privacy_occurrence_after";

    fn contract_fixture() -> (State, ContractInvocation, ContractInvocation) {
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        let (program, manifest) = kotodama_lang::compiler::Compiler::new()
            .compile_source_with_manifest(
                r#"
seiyaku PrivacyOccurrenceGuard { permission CanInvokeContractEntrypoint;
  kotoage fn open() authorize(CanInvokeContractEntrypoint) {
    ledger::account::set_metadata(
      account: context::authority(),
      key: Name::parse("privacy_occurrence_before"),
      value: Json::parse("true")
    );
  }
  kotoage fn close() authorize(CanInvokeContractEntrypoint) {
    ledger::account::set_metadata(
      account: context::authority(),
      key: Name::parse("privacy_occurrence_after"),
      value: Json::parse("true")
    );
  }
}
"#,
            )
            .expect("compile real privacy occurrence guard");
        let authority = ALICE_ID.clone();
        let domain =
            Domain::new(DomainId::try_new("wonderland", "universal").unwrap()).build(&authority);
        let state = state_after_genesis(World::with(
            [domain],
            [Account::new(authority.clone()).build(&authority)],
            [],
        ));
        let code_hash = ivm::contract_code_hash(&program);
        let contract_address =
            ContractAddress::derive(&state.network_id, &authority, 94, DataSpaceId::UNIVERSAL)
                .expect("derive contract address");
        let artifact = iroha_data_model::smart_contract::ContractArtifactId::new(
            DataSpaceId::UNIVERSAL,
            code_hash,
        );
        let mut world = state.world.block();
        world.contract_code.insert(artifact.clone(), program);
        world.contract_manifests.insert(
            artifact,
            manifest
                .try_signed(
                    manifest_signing.context(),
                    manifest_signing.max_frame_bytes(),
                    &ALICE_KEYPAIR,
                )
                .expect("sign bounded guard manifest"),
        );
        world.account_permissions.insert(
            contract_address.subject_id(),
            BTreeSet::from([executor_permission::account::CanModifyAccountMetadata {
                account: authority.clone(),
            }
            .into()]),
        );
        world.account_permissions.insert(
            authority.clone(),
            BTreeSet::from([
                iroha_executor_data_model::permission::smart_contract::CanUseContractPermission {
                    contract: contract_address.clone(),
                    permission: "CanInvokeContractEntrypoint".parse().unwrap(),
                }
                .into(),
            ]),
        );
        let profile = compiled_privacy_profile_v1(PrivacyProtocolIdV1::OrchardHalo2ActionsV1)
            .expect("compiled production Orchard profile");
        world.privacy_activations.insert(
            PrivacyActivationKeyV1::new(profile.protocol_id),
            profile.activation_record(PrivacyProtocolLifecycleV1::Active(
                PrivacyActiveLifecycleV1 {
                    proposed_at_height: 1,
                    activated_at_height: 1,
                    state_since_height: 1,
                },
            )),
        );
        assert!(world.privacy_exact12_qualification.get().is_none());
        world.commit();
        bind_executor_test_contract_after_genesis(&state, &contract_address, &authority, code_hash);
        let call = |entrypoint: &str| ContractInvocation {
            contract_address: contract_address.clone(),
            expected_code_hash: code_hash,
            entrypoint: entrypoint.to_owned(),
            arguments: None,
        };
        (state, call("open"), call("close"))
    }

    fn mixed_payload(
        state: &State,
        open: &ContractInvocation,
        close: &ContractInvocation,
        envelope: PrivacyProofEnvelopeV1,
    ) -> TransactionPayload {
        let mut builder = TransactionBuilder::new(
            state.network_id,
            ALICE_ID.clone(),
            FeePaymentIntent::authority(Vec::new(), core::num::NonZeroU64::new(GAS)),
        )
        .with_executable(Executable::Batch(
            vec![
                ExecutableBatchItem::ContractCall(open.clone()),
                ExecutableBatchItem::Instruction(SubmitPrivacyProofV1::new(envelope).into()),
                ExecutableBatchItem::ContractCall(close.clone()),
            ]
            .into(),
        ));
        // Both phases use exactly this time, fee intent, metadata and complete call sequence.
        builder.set_creation_time(Duration::from_millis(1));
        builder.into_payload().expect("canonical mixed payload")
    }

    fn real_orchard_mixed_transaction(
        state: &State,
        open: &ContractInvocation,
        close: &ContractInvocation,
    ) -> SignedTransaction {
        let profile = compiled_privacy_profile_v1(PrivacyProtocolIdV1::OrchardHalo2ActionsV1)
            .expect("compiled production Orchard profile");
        // Deterministic native witness/entropy belong only to this test; neither is exported.
        let spending_key = (1_u8..=u8::MAX)
            .find_map(|counter| {
                let mut bytes = [0x61; 32];
                bytes[0] = counter;
                Option::<SpendingKey>::from(SpendingKey::from_bytes(bytes))
            })
            .expect("fixture spending key");
        let mut rng = StdRng::from_seed([0x67; 32]);
        let prepared = prepare_orchard_bundle_v1_with_rng(
            orchard_empty_root_v1(),
            Vec::new(),
            vec![OrchardChangeProverInputV1::new(
                spending_key,
                Scope::External,
                1,
                17,
                [0x63; 512],
            )],
            1,
            &mut rng,
        )
        .expect("produce a real Post-NU6.3 Halo2 proof");
        let draft = prepared.public_draft();
        assert_eq!(draft.value_balance, -17);
        let mut statement = OrchardHalo2ActionsStatementV1 {
            context: PrivacyStatementContextV1 {
                network_id: state.network_id,
                action_index: 0,
                transaction_intent_digest: PrivacyTransactionIntentDigestV1::new([0; 32]),
                parameter_id: profile.parameter_id,
                parameter_digest: profile.parameter_digest,
                verifier_digest: profile.verifier_digest,
                statement_schema_digest: profile.statement_schema_digest,
                engine_manifest_digest: profile.engine_manifest_digest,
            },
            asset_definition_id: AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "privacy_occurrence".parse().unwrap(),
            ),
            public_balance_scope: iroha_data_model::asset::AssetBalanceScope::Global,
            pool_id: PrivacyPoolIdV1::new([0x64; 32]),
            anchor: PrivacyRootV1::new(draft.anchor),
            anchor_epoch: 1,
            actions: draft
                .actions
                .iter()
                .map(|action| PrivacyOrchardActionV1 {
                    nullifier: action.nullifier,
                    randomized_key: action.randomized_key,
                    note_commitment: action.note_commitment,
                    ephemeral_key: action.ephemeral_key,
                    encrypted_note: action.encrypted_note.to_vec(),
                    outgoing_ciphertext: action.outgoing_ciphertext.to_vec(),
                    value_commitment: action.value_commitment,
                })
                .collect(),
            value_balance: PrivacyValueBalanceV1 {
                direction: PrivacyValueBalanceDirectionV1::IntoPool,
                amount: 17,
            },
            expiry_height: 100,
        };
        // Empty proof bytes are only the native builder's unsigned draft. They are replaced
        // before signing or execution and are never submitted to any accepting verifier.
        let draft_envelope = PrivacyProofEnvelopeV1::bind_v1(
            PrivacyStatementV1::OrchardHalo2ActionsV1(statement.clone()),
            PrivacyProofV1::OrchardHalo2ActionsV1(PrivacyProofBytesV1::new(Vec::new())),
        )
        .expect("bind draft statement");
        let intent = mixed_payload(state, open, close, draft_envelope)
            .privacy_transaction_intent_digest_v1()
            .expect("derive complete signed batch intent");
        assert!(!intent.is_zero());
        statement.context.transaction_intent_digest = intent;
        let limits = PrivacyConsensusLimitsV1::taira_default();
        let binding = PrivacyNativeConsensusBindingV1::new(
            &statement.context,
            *state.network_id.as_bytes(),
            &limits,
        )
        .expect("bind actual genesis security domain and complete batch");
        // Authorization consumes the prepared witness and independently invokes the production
        // Orchard verifier before returning. No qualification or verifier gate is replaced.
        let proved = authorize_orchard_bundle_v1(prepared, binding, &limits)
            .expect("authorize and independently verify the real native Orchard bundle");
        assert!(!proved.authorization.is_empty());
        assert_eq!(proved.public.anchor, *statement.anchor.as_bytes());
        assert_eq!(proved.public.actions.len(), statement.actions.len());
        let envelope = PrivacyProofEnvelopeV1::bind_v1(
            PrivacyStatementV1::OrchardHalo2ActionsV1(statement),
            PrivacyProofV1::OrchardHalo2ActionsV1(PrivacyProofBytesV1::new(proved.authorization)),
        )
        .expect("bind final real proof");
        assert!(profile.matches_envelope_v1(&envelope));
        let payload = mixed_payload(state, open, close, envelope);
        assert_eq!(
            payload
                .validate_privacy_transaction_intent_binding_v1()
                .unwrap(),
            intent
        );
        let signed = TransactionBuilder::from_payload(payload)
            .expect("final fixed batch payload")
            .try_sign(ALICE_KEYPAIR.private_key())
            .expect("sign complete batch");
        signed.verify_signature().expect("verify actual signature");
        assert_eq!(
            signed
                .privacy_transaction_intent_binding_if_present_v1()
                .unwrap()
                .unwrap()
                .0,
            intent,
        );
        signed
    }

    #[test]
    fn signed_privacy_mixed_batch_reaches_production_qualification_and_rolls_back_open() {
        let (state, open, close) = contract_fixture();
        let signed = real_orchard_mixed_transaction(&state, &open, &close);
        let entrypoint = TransactionEntrypoint::External(signed.clone());
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            state.view().latest_block_hash(),
            None,
            1,
            0,
        ));
        let before: Name = BEFORE.parse().unwrap();
        let after: Name = AFTER.parse().unwrap();
        let mut transaction =
            block.transaction_for_fastpq_testing(Hash::from(signed.hash_as_entrypoint()));
        // Replay source context is the same immutable owner required by the production wrapper;
        // the wrapper itself derives, arms, consumes and clears the privacy binding.
        seed_committed_transaction_context(&mut transaction, &entrypoint, 0);
        transaction.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        transaction.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        assert!(
            transaction
                .world
                .privacy_exact12_qualification
                .get()
                .is_none()
        );
        assert!(
            transaction
                .world
                .account(&ALICE_ID)
                .unwrap()
                .metadata()
                .get(&before)
                .is_none()
        );
        let error = crate::executor::Executor::Initial
            .execute_transaction(&mut transaction, &ALICE_ID, &signed, &mut IvmCache::new())
            .map_err(crate::execution_attempt::expect_completed_rejection)
            .expect_err("the real executor must enforce missing production qualification");
        assert!(
            matches!(error,
                ValidationFail::InstructionFailed(
                    iroha_data_model::isi::error::InstructionExecutionError::InvalidParameter(
                        InvalidParameterError::SmartContract(ref message)
                    )
                ) if message == "privacy Exact12 production qualification is not registered"),
            "unexpected refusal, before the intended qualification boundary: {error:?}"
        );
        assert_eq!(
            transaction
                .world
                .account(&ALICE_ID)
                .unwrap()
                .metadata()
                .get(&before),
            Some(&Json::new(true)),
            "the actual first contract call must have written before native admission refused"
        );
        assert!(
            transaction
                .world
                .account(&ALICE_ID)
                .unwrap()
                .metadata()
                .get(&after)
                .is_none()
        );
        assert!(transaction.privacy_transaction_intent_binding.is_none());
        assert_eq!(transaction.current_direct_privacy_instruction_index, None);
        assert_eq!(
            transaction.current_network_entrypoint_hash,
            Some(entrypoint.hash())
        );
        assert_eq!(transaction.privacy_budget_for_testing(), (0, 0, 0, 0));
        assert_eq!(transaction.world.privacy_roots.iter().count(), 0);
        assert_eq!(transaction.world.privacy_root_heads.iter().count(), 0);
        assert_eq!(transaction.world.privacy_nullifiers.iter().count(), 0);
        assert_eq!(transaction.world.privacy_commitments.iter().count(), 0);
        // The owning transaction overlay, not a test-specific privacy handler, rolls back.
        drop(transaction);
        let verification = block.transaction();
        let account = verification.world.account(&ALICE_ID).unwrap();
        assert!(account.metadata().get(&before).is_none());
        assert!(account.metadata().get(&after).is_none());
        assert!(verification.privacy_transaction_intent_binding.is_none());
        assert_eq!(verification.current_direct_privacy_instruction_index, None);
        assert_eq!(verification.privacy_budget_for_testing(), (0, 0, 0, 0));
        assert_eq!(verification.world.privacy_roots.iter().count(), 0);
        assert_eq!(verification.world.privacy_root_heads.iter().count(), 0);
        assert_eq!(verification.world.privacy_nullifiers.iter().count(), 0);
        assert_eq!(verification.world.privacy_commitments.iter().count(), 0);
    }
}
