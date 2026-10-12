mod public_artifact_tests {
    //! Public immutable artifact creation with separate privileged and owner-scoped mutations.
    use super::*;
    world_test!(artifact_registry_and_pending_uploads_are_dataspace_scoped {
        blank_test_state_transaction!(state, block, stx);
        bootstrap_alice_account(&mut stx);
        let (code, manifest) = minimal_contract_artifact();
        let hash = manifest.code_hash.expect("artifact hash");
        let private = ContractArtifactId::new(DataSpaceId::new(u64::MAX), hash);
        let public = ContractArtifactId::new(DataSpaceId::UNIVERSAL, hash);
        scode::RegisterSmartContractBytes { artifact_id: private, code: code.clone() }
            .expect_execute(&ALICE_ID, &mut stx, "register private artifact");
        assert_eq!(stx.world.contract_code.get(&private), Some(&code));
        assert!(stx.world.contract_code.get(&public).is_none());
        scode::RegisterSmartContractBytes { artifact_id: public, code: code.clone() }
            .expect_execute(&ALICE_ID, &mut stx, "same bytes have an independent public registration");
        assert_eq!(stx.world.contract_code.get(&public), Some(&code));
        let upload_hash = Hash::new(b"scoped pending upload");
        let private_upload = ContractArtifactId::new(DataSpaceId::new(u64::MAX), upload_hash);
        let public_upload = ContractArtifactId::new(DataSpaceId::UNIVERSAL, upload_hash);
        for artifact_id in [private_upload, public_upload] {
            scode::UploadSmartContractCodeChunk { artifact_id, total_size: 3, chunk_index: 0, chunk_count: 1, chunk: vec![1, 2, 3] }
                .expect_execute(&ALICE_ID, &mut stx, "stage independently scoped upload");
        }
        scode::CancelSmartContractCodeUpload { artifact_id: public_upload }
            .expect_execute(&ALICE_ID, &mut stx, "cancel only public staging");
        assert!(stx.world.contract_code_uploads.get(&SmartContractCodeUploadKey::new(ALICE_ID.clone(), public_upload)).is_none());
        assert!(stx.world.contract_code_uploads.get(&SmartContractCodeUploadKey::new(ALICE_ID.clone(), private_upload)).is_some());
    });
    world_test!(contract_manifest_is_immutable_for_registered_code_hash {
        let manifest_signing =
            crate::manifest_signing_test_support::ManifestSigningFixture::new();
        blank_test_state_transaction!(state, block, stx);
        bootstrap_alice_account(&mut stx);
        let signer_one = checked_keypair_with_algorithm(Algorithm::Ed25519);
        let signer_two = checked_keypair_with_algorithm(Algorithm::Ed25519);
        let members = vec![
            MultisigMember::new(signer_one.public_key().clone(), 1)
                .expect("first manifest signer"),
            MultisigMember::new(signer_two.public_key().clone(), 1)
                .expect("second manifest signer"),
        ];
        let authority = AccountId::new_multisig(
            MultisigPolicy::new(1, members).expect("manifest publisher multisig policy"),
        );
        Register::account(Account::new(authority.clone()))
            .expect_execute(&ALICE_ID, &mut stx, "register manifest authority");
        let (artifact, unsigned_manifest) = minimal_contract_artifact();
        let code_hash = unsigned_manifest.code_hash.expect("manifest code hash");
        stx.world.contract_code.insert(iroha_data_model::smart_contract::ContractArtifactId::new(iroha_model_base::topology::DataSpaceId::UNIVERSAL, code_hash), artifact);
        let first_manifest = unsigned_manifest
            .clone()
            .try_signed(manifest_signing.context(), manifest_signing.max_frame_bytes(), &signer_one)
            .expect("first signed manifest");
        { let scoped_manifest = first_manifest.clone(); smart_contract_code::RegisterSmartContractCode { artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(iroha_model_base::topology::DataSpaceId::UNIVERSAL, scoped_manifest.code_hash.unwrap_or_else(|| iroha_crypto::Hash::new(b"missing test manifest hash"))), manifest: scoped_manifest } }
        .expect_execute(&authority, &mut stx, "first manifest registration");
        { let scoped_manifest = first_manifest.clone(); smart_contract_code::RegisterSmartContractCode { artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(iroha_model_base::topology::DataSpaceId::UNIVERSAL, scoped_manifest.code_hash.unwrap_or_else(|| iroha_crypto::Hash::new(b"missing test manifest hash"))), manifest: scoped_manifest } }
        .expect_execute(&authority, &mut stx, "identical manifest registration is idempotent");
        let differently_signed_manifest = unsigned_manifest.clone()
            .try_signed(manifest_signing.context(), manifest_signing.max_frame_bytes(), &signer_two)
            .expect("second signed manifest");
        { let scoped_manifest = differently_signed_manifest; smart_contract_code::RegisterSmartContractCode { artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(iroha_model_base::topology::DataSpaceId::UNIVERSAL, scoped_manifest.code_hash.unwrap_or_else(|| iroha_crypto::Hash::new(b"missing test manifest hash"))), manifest: scoped_manifest } }
        .expect_execute(&authority, &mut stx, "another authorized signer reuses the immutable manifest");
        let developer_key = checked_keypair_with_algorithm(Algorithm::Ed25519);
        let developer = AccountId::new(developer_key.public_key().clone());
        Register::account(Account::new(developer.clone()))
            .expect_execute(&ALICE_ID, &mut stx, "register independent ordinary developer");
        { let scoped_manifest = unsigned_manifest.clone().try_signed(manifest_signing.context(), manifest_signing.max_frame_bytes(), &developer_key).expect("developer provenance"); smart_contract_code::RegisterSmartContractCode { artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(iroha_model_base::topology::DataSpaceId::UNIVERSAL, scoped_manifest.code_hash.unwrap_or_else(|| iroha_crypto::Hash::new(b"missing test manifest hash"))), manifest: scoped_manifest } }
        .expect_execute(&developer, &mut stx, "an independent developer shares identical content");
        let error = { let scoped_manifest = first_manifest.clone(); smart_contract_code::RegisterSmartContractCode { artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(iroha_model_base::topology::DataSpaceId::UNIVERSAL, scoped_manifest.code_hash.unwrap_or_else(|| iroha_crypto::Hash::new(b"missing test manifest hash"))), manifest: scoped_manifest } }
        .expect_execute_err(&developer, &mut stx, "existing content never bypasses submitter signature ownership");
        assert!(matches!(&error, InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(message)) if message.contains("manifest signer is not authorised")), "unexpected artifact failure: {error:?}");
        let mut changed = unsigned_manifest;
        changed.abi_hash = Some(Hash::new(b"substituted ABI"));
        let error = { let scoped_manifest = changed.try_signed(manifest_signing.context(), manifest_signing.max_frame_bytes(), &developer_key).expect("changed content signature"); smart_contract_code::RegisterSmartContractCode { artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(iroha_model_base::topology::DataSpaceId::UNIVERSAL, scoped_manifest.code_hash.unwrap_or_else(|| iroha_crypto::Hash::new(b"missing test manifest hash"))), manifest: scoped_manifest } }
        .expect_execute_err(&developer, &mut stx, "valid signatures cannot replace immutable artifact semantics");
        assert!(matches!(&error, InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(message)) if message.contains("manifest payload does not match")), "unexpected artifact failure: {error:?}");
        assert_eq!(
            stx.world.contract_manifests.get(&iroha_data_model::smart_contract::ContractArtifactId::new(iroha_model_base::topology::DataSpaceId::UNIVERSAL, code_hash)),
            Some(&first_manifest),
        );
    });
    world_test!(contract_binding_mutations_require_runtime_lifecycle_authority {
        let manifest_signing =
            crate::manifest_signing_test_support::ManifestSigningFixture::new();
        blank_test_state_transaction!(state, block, stx);
        Register::account(Account::new(ALICE_ID.clone()))
            .expect_execute(&ALICE_ID, &mut stx, "seed authority");
        let attacker = AccountId::new(checked_keypair().public_key().clone());
        Register::account(Account::new(attacker.clone()))
            .expect_execute(&ALICE_ID, &mut stx, "seed unprivileged attacker");
        let protected = iroha_data_model::parameter::custom::CustomParameter::new(
            iroha_data_model::parameter::custom::CustomParameterId(
                "gov_protected_namespaces".parse().expect("parameter id"),
            ),
            Json::new(vec!["dataspace:1".to_owned()]),
        );
        stx.world
            .parameters
            .get_mut()
            .set_parameter(Parameter::Custom(protected)).expect("valid fixture parameters");
        let (program, manifest) = minimal_contract_artifact();
        let code_hash = manifest.code_hash.expect("manifest code hash");
        let register_bytes = scode::RegisterSmartContractBytes { artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(iroha_model_base::topology::DataSpaceId::UNIVERSAL, code_hash),
            code: program,
        };
        let unregistered = AccountId::new(checked_keypair().public_key().clone());
        register_bytes.clone().expect_execute_err(
            &unregistered, &mut stx, "unregistered authority cannot create an artifact");
        assert!(stx.world.contract_code.get(&iroha_data_model::smart_contract::ContractArtifactId::new(iroha_model_base::topology::DataSpaceId::UNIVERSAL, code_hash)).is_none());
        register_bytes.clone().expect_execute(
            &attacker, &mut stx, "ordinary registered developer may create verified code");
        assert!(stx.world.contract_code.get(&iroha_data_model::smart_contract::ContractArtifactId::new(iroha_model_base::topology::DataSpaceId::UNIVERSAL, code_hash)).is_some());
        Grant::account_permission(
            Permission::new(
                "CanManageSmartContractCode".to_owned(),
                Json::from(norito::json!({ "scope": "wrong" })),
            ),
            attacker.clone(),
        )
        .expect_execute(&attacker, &mut stx, "store adversarial same-name permission payload");
        let error = scode::RemoveSmartContractBytes { artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(iroha_model_base::topology::DataSpaceId::UNIVERSAL, code_hash), reason: None }
            .expect_execute_err(&attacker, &mut stx, "creation does not grant global removal authority");
        assert_contains!(error.to_string(), "CanManageSmartContractCode");
        assert!(stx.world.contract_code.get(&iroha_data_model::smart_contract::ContractArtifactId::new(iroha_model_base::topology::DataSpaceId::UNIVERSAL, code_hash)).is_some());
        let upload_hash = Hash::new(b"ordinary owner pending upload");
        let upload = scode::UploadSmartContractCodeChunk { artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(iroha_model_base::topology::DataSpaceId::UNIVERSAL, upload_hash),
            total_size: 3,
            chunk_index: 0,
            chunk_count: 1,
            chunk: vec![1, 2, 3],
        };
        upload.clone().expect_execute_err(&unregistered, &mut stx, "missing accounts cannot stage uploads");
        upload.expect_execute(&attacker, &mut stx, "registered developer stages only their own upload");
        let attacker_upload_key = SmartContractCodeUploadKey::new(attacker.clone(),iroha_data_model::smart_contract::ContractArtifactId::new(iroha_model_base::topology::DataSpaceId::UNIVERSAL, upload_hash));
        assert!(stx.world.contract_code_uploads.get(&attacker_upload_key).is_some());
        assert!(stx.world.contract_code_upload_chunks.get(
            &SmartContractCodeUploadChunkKey::new(attacker_upload_key.clone(), 0)).is_some());
        let finalize = scode::FinalizeSmartContractCodeUpload { artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(iroha_model_base::topology::DataSpaceId::UNIVERSAL, upload_hash), total_size: 3, chunk_count: 1,
        };
        finalize.clone().expect_execute_err(&unregistered, &mut stx, "missing accounts cannot finalize uploads");
        let error = finalize.clone().expect_execute_err(&ALICE_ID, &mut stx, "another account cannot finalize the owner's staging");
        assert!(matches!(&error, InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(message)) if message.contains("pending contract upload descriptor not found")), "unexpected artifact failure: {error:?}");
        finalize.expect_execute_err(&attacker, &mut stx, "public upload still verifies complete IVM artifacts");
        assert!(stx.world.contract_code.get(&iroha_data_model::smart_contract::ContractArtifactId::new(iroha_model_base::topology::DataSpaceId::UNIVERSAL, upload_hash)).is_none());
        assert!(stx.world.contract_code_uploads.get(&attacker_upload_key).is_some());
        scode::CancelSmartContractCodeUpload { artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(iroha_model_base::topology::DataSpaceId::UNIVERSAL, upload_hash)}
            .expect_execute(&ALICE_ID, &mut stx, "another account cancels only its own nonexistent staging");
        assert!(stx.world.contract_code_uploads.get(&attacker_upload_key).is_some());
        assert!(stx.world.contract_code_upload_chunks.get(
            &SmartContractCodeUploadChunkKey::new(attacker_upload_key.clone(), 0)).is_some());
        scode::CancelSmartContractCodeUpload { artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(iroha_model_base::topology::DataSpaceId::UNIVERSAL, upload_hash)}
            .expect_execute(&attacker, &mut stx, "owner cancels its own staging without privileged grant");
        assert!(stx.world.contract_code_uploads.get(&attacker_upload_key).is_none());
        assert!(stx.world.contract_code_upload_chunks.iter().all(|(key,_)| key.upload != attacker_upload_key));
        grant_contract_lifecycle_authority(&mut stx, &ALICE_ID);
        register_bytes
            .clone()
            .expect_execute(&ALICE_ID, &mut stx, "authorized bytecode registration");
        let remove_bytes = scode::RemoveSmartContractBytes { artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(iroha_model_base::topology::DataSpaceId::UNIVERSAL, code_hash),
            reason: Some("permission regression fixture".to_owned()),
        };
        let error = remove_bytes
            .clone()
            .expect_execute_err(&attacker, &mut stx, "raw bytecode removal requires runtime lifecycle authority");
        assert_contains!(format!("{error:?}"), "CanManageSmartContractCode");
        assert!(stx.world.contract_code.get(&iroha_data_model::smart_contract::ContractArtifactId::new(iroha_model_base::topology::DataSpaceId::UNIVERSAL, code_hash)).is_some());
        remove_bytes
            .expect_execute(&ALICE_ID, &mut stx, "authorized bytecode removal");
        assert!(stx.world.contract_code.get(&iroha_data_model::smart_contract::ContractArtifactId::new(iroha_model_base::topology::DataSpaceId::UNIVERSAL, code_hash)).is_none());
        register_bytes
            .expect_execute(&ALICE_ID, &mut stx, "authorized bytecode re-registration");
        let register_manifest = { let scoped_manifest = manifest.try_signed(manifest_signing.context(), manifest_signing.max_frame_bytes(), &ALICE_KEYPAIR).expect("sign bounded fixture manifest"); scode::RegisterSmartContractCode { artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(iroha_model_base::topology::DataSpaceId::UNIVERSAL, scoped_manifest.code_hash.unwrap_or_else(|| iroha_crypto::Hash::new(b"missing test manifest hash"))), manifest: scoped_manifest } };
        let error = register_manifest
            .clone()
            .expect_execute_err(&attacker, &mut stx, "manifest registration requires the submitting account signature");
        assert_contains!(format!("{error:?}"), "manifest signer is not authorised");
        assert!(stx.world.contract_manifests.get(&iroha_data_model::smart_contract::ContractArtifactId::new(iroha_model_base::topology::DataSpaceId::UNIVERSAL, code_hash)).is_none());
        register_manifest
            .expect_execute(&ALICE_ID, &mut stx, "authorized manifest registration");
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &ALICE_ID,
            0,
            DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        let contract_subject = contract_address.subject_id();
        Register::account(Account::new(contract_subject.clone()))
            .expect_execute(&ALICE_ID, &mut stx, "seed contract subject");
        stx.world.contract_subject_bindings.insert(
            contract_address.clone(),
            crate::smartcontracts::code::ContractSubjectBinding::new_direct(
                &contract_address,
                ALICE_ID.clone(),
            ),
        );
        stx.world
            .contract_subject_addresses
            .insert(contract_subject.clone(), contract_address.clone());
        let activate = scode::ActivateContractInstance {
            contract_address: contract_address.clone(),
            expected_revision: 1,
            code_hash,
        };
        let removed_subject = stx
            .world
            .accounts
            .remove(contract_subject.clone())
            .expect("remove contract subject for corruption regression");
        let missing_subject_activation = activate
            .clone()
            .expect_execute_err(&ALICE_ID, &mut stx, "activation must reject a missing contract subject");
        assert_contains!(
            missing_subject_activation.to_string(),
            &format!(
                "contract subject account `{contract_subject}` for `{contract_address}` does not exist"
            )
        );
        assert!(
            stx.world
                .contract_instances
                .get(&contract_address)
                .is_none(),
            "missing-subject activation rejection must not mutate the instance registry"
        );
        stx.world
            .accounts
            .insert(contract_subject.clone(), removed_subject);
        let error = activate
            .clone()
            .expect_execute_err(&attacker, &mut stx, "an unprivileged account must not pre-bind another account's address");
        assert_contains!(format!("{error:?}"), "current account owner");
        assert!(
            stx.world
                .contract_instances
                .get(&contract_address)
                .is_none(),
            "rejected first binding must not mutate the instance registry"
        );
        activate
            .clone()
            .expect_execute(&ALICE_ID, &mut stx, "runtime lifecycle authority may activate verified code");
        assert_eq!(
            stx.world.contract_instances.get(&contract_address),
            Some(&code_hash)
        );
        assert_eq!(
            stx.world
                .contract_subject_bindings
                .get(&contract_address)
                .expect("active lifecycle")
                .lifecycle
                .active_code_hash,
            Some(code_hash)
        );
        assert!(
            stx.world.account(&contract_subject).is_ok(),
            "contract subject account remains available",
        );
        let deactivate = scode::DeactivateContractInstance {
            contract_address: contract_address.clone(),
            expected_revision: 2,
            reason: Some("adversarial ABA attempt".to_owned()),
        };
        let lifecycle_before_missing_subject = stx
            .world
            .contract_subject_bindings
            .get(&contract_address)
            .expect("active lifecycle")
            .lifecycle
            .clone();
        let removed_subject = stx
            .world
            .accounts
            .remove(contract_subject.clone())
            .expect("remove active contract subject for corruption regression");
        let missing_subject_deactivation = deactivate
            .clone()
            .expect_execute_err(&ALICE_ID, &mut stx, "deactivation must reject a missing contract subject");
        assert_contains!(
            missing_subject_deactivation.to_string(),
            &format!(
                "contract subject account `{contract_subject}` for `{contract_address}` does not exist"
            )
        );
        assert_eq!(
            stx.world.contract_instances.get(&contract_address),
            Some(&code_hash),
            "missing-subject deactivation rejection must preserve the active instance"
        );
        assert_eq!(
            stx.world
                .contract_subject_bindings
                .get(&contract_address)
                .expect("retained lifecycle")
                .lifecycle,
            lifecycle_before_missing_subject,
            "missing-subject deactivation rejection must preserve lifecycle state"
        );
        stx.world
            .accounts
            .insert(contract_subject.clone(), removed_subject);
        let error = deactivate
            .clone()
            .expect_execute_err(&attacker, &mut stx, "an unprivileged account must not begin an ABA rebind");
        assert_contains!(format!("{error:?}"), "current account owner");
        assert_eq!(
            stx.world.contract_instances.get(&contract_address),
            Some(&code_hash),
            "rejected deactivation must preserve the live binding"
        );
        let active_activate = scode::ActivateContractInstance {
            contract_address: contract_address.clone(),
            expected_revision: 2,
            code_hash,
        };
        let error = active_activate
            .clone()
            .expect_execute_err(&attacker, &mut stx, "even an idempotent binding request requires lifecycle authority");
        assert_contains!(format!("{error:?}"), "current account owner");
        deactivate
            .expect_execute(&ALICE_ID, &mut stx, "runtime lifecycle authority may deactivate an instance");
        assert!(
            stx.world
                .contract_instances
                .get(&contract_address)
                .is_none()
        );
        let deactivated_lifecycle = &stx
            .world
            .contract_subject_bindings
            .get(&contract_address)
            .expect("retained inactive lifecycle")
            .lifecycle;
        assert!(deactivated_lifecycle.active_code_hash.is_none());
        assert_eq!(deactivated_lifecycle.revision, 3);
        let reactivate = scode::ActivateContractInstance {
            contract_address: contract_address.clone(),
            expected_revision: 3,
            code_hash,
        };
        let error = reactivate
            .clone()
            .expect_execute_err(&attacker, &mut stx, "an unprivileged account must not complete an ABA rebind");
        assert_contains!(format!("{error:?}"), "current account owner");
        assert!(
            stx.world
                .contract_instances
                .get(&contract_address)
                .is_none()
        );
        reactivate
            .expect_execute(&ALICE_ID, &mut stx, "runtime lifecycle authority may reactivate verified code");
        assert_eq!(
            stx.world.contract_instances.get(&contract_address),
            Some(&code_hash)
        );
        let reactivated_lifecycle = &stx
            .world
            .contract_subject_bindings
            .get(&contract_address)
            .expect("reactivated lifecycle")
            .lifecycle;
        assert_eq!(reactivated_lifecycle.active_code_hash, Some(code_hash));
        assert_eq!(reactivated_lifecycle.revision, 4);
    });
}
