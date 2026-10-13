use iroha_data_model::isi::smart_contract_code::UploadSmartContractCodeChunk;
fn contract_deployment_permission() -> Permission {
    executor_permission::smart_contract::CanManageSmartContractCode.into()
}
fn bundled_default_user_provided_executor() -> super::Executor {
    let raw_executor = data_model_executor::Executor::new(IvmBytecode::from_compiled(
        include_bytes!("../../../defaults/executor.to").to_vec(),
    ));
    super::Executor::UserProvided(
        super::LoadedExecutor::load(raw_executor).expect("load bundled default executor"),
    )
}
fn contract_upload_instruction(code_hash: Hash, chunk_index: u32) -> InstructionBox {
    UploadSmartContractCodeChunk {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            DataSpaceId::UNIVERSAL,
            code_hash,
        ),
        total_size: if chunk_index == 0 { 1 } else { 65_537 },
        chunk_index,
        chunk_count: if chunk_index == 0 { 1 } else { 2 },
        chunk: vec![0xA5],
    }
    .into()
}
fn contract_deployment_bootstrap_instructions(
    authority: &AccountId,
    account: iroha_data_model::account::NewAccount,
    permission: Permission,
    deployment: InstructionBox,
) -> Vec<InstructionBox> {
    vec![
        Register::account(account).into(),
        Grant::account_permission(permission, authority.clone()).into(),
        deployment,
    ]
}
#[test]
fn contract_code_management_manager_sponsors_registration_and_meters_every_instruction() {
    for executor in [
        super::Executor::Initial,
        bundled_default_user_provided_executor(),
    ] {
        let keypair = checked_keypair();
        let manager = AccountId::new(keypair.public_key().clone());
        let builder = checked_account_id();
        let mut world = World::with([], [Account::new(manager.clone()).build(&manager)], []);
        world.account_permissions.insert(
            manager.clone(),
            BTreeSet::from([
                executor_permission::smart_contract::CanGrantSmartContractCodeManagement.into(),
            ]),
        );
        let state = State::new_for_testing(
            component_world_for_testing(world),
            Kura::blank_kura_for_testing(),
            query::store::LiveQueryStore::start_test(),
        );
        let instructions: Vec<InstructionBox> = vec![
            Register::account(Account::new(builder.clone())).into(),
            Grant::account_permission(contract_deployment_permission(), builder.clone()).into(),
        ];
        let expected_gas =
            crate::gas::meter_instructions(&instructions, &crate::gas::DEFAULT_ZK_GAS)
                .expect("gas quote must complete for this fixture");
        let transaction = TransactionBuilder::new(
            state.network_id,
            manager.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions(instructions)
        .sign(keypair.private_key());
        let mut block = state.block(BlockHeader::new(nonzero!(2_u64), None, None, 0, 0));
        let mut state_transaction = block.transaction_for_fastpq_testing(iroha_crypto::Hash::from(
            transaction.hash_as_entrypoint(),
        ));
        state_transaction.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        state_transaction.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        executor
            .execute_transaction(
                &mut state_transaction,
                &manager,
                transaction,
                &mut IvmCache::new(),
            )
            .map_err(crate::execution_attempt::expect_completed_rejection)
            .expect(
                "an admitted code-management grant authority may register and authorize a builder",
            );
        assert_eq!(state_transaction.last_tx_gas_used, expected_gas);
        assert!(
            authority_has_permission(
                &state_transaction.world,
                &builder,
                &contract_deployment_permission()
            )
            .expect("builder permissions")
        );
        assert!(
            !authority_has_permission(
                &state_transaction.world,
                &manager,
                &contract_deployment_permission()
            )
            .expect("manager permissions")
        );
        let code_hash = Hash::new(b"authorized builder upload");
        executor
            .execute_instruction(
                &mut state_transaction,
                &builder,
                contract_upload_instruction(code_hash, 0),
            )
            .expect("the newly authorized builder may upload code");
        assert!(
            state_transaction
                .world
                .contract_code_upload_progress(
                    &builder,
                    &iroha_data_model::smart_contract::ContractArtifactId::new(
                        DataSpaceId::UNIVERSAL,
                        code_hash
                    )
                )
                .is_some()
        );
        state_transaction.apply();
        assert!(block.world.account(&builder).is_ok());
        assert!(
            block
                .world
                .contract_code_upload_progress(
                    &builder,
                    &iroha_data_model::smart_contract::ContractArtifactId::new(
                        DataSpaceId::UNIVERSAL,
                        code_hash
                    )
                )
                .is_some()
        );
    }
}
#[test]
fn contract_code_management_management_uses_exact_effective_role_and_borrowed_gate() {
    for executor in [
        super::Executor::Initial,
        bundled_default_user_provided_executor(),
    ] {
        for assigned in [false, true] {
            let manager = checked_account_id();
            let builder = checked_account_id();
            let mut world = World::with(
                [],
                [
                    Account::new(manager.clone()).build(&manager),
                    Account::new(builder.clone()).build(&manager),
                ],
                [],
            );
            let role_id: RoleId = "contract_code_management_managers"
                .parse()
                .expect("role id");
            let manager_permission: Permission =
                executor_permission::smart_contract::CanGrantSmartContractCodeManagement.into();
            let role = Role::new(role_id.clone(), manager.clone())
                .add_permission(manager_permission.clone())
                .build(&manager);
            world.roles.insert(role_id.clone(), role);
            if assigned {
                world.account_roles.insert(
                    crate::role::RoleIdWithOwner::new(manager.clone(), role_id.clone()),
                    (),
                );
            }
            let state = State::new_for_testing(
                component_world_for_testing(world),
                Kura::blank_kura_for_testing(),
                query::store::LiveQueryStore::start_test(),
            );
            let mut block = state.block(BlockHeader::new(nonzero!(2_u64), None, None, 0, 0));
            let mut state_transaction = block.transaction();
            let grant: InstructionBox =
                Grant::account_permission(contract_deployment_permission(), builder.clone()).into();
            let result = executor.execute_borrowed_overlay_instruction(
                &mut state_transaction,
                &manager,
                &grant,
                None,
            );
            assert_eq!(
                result.is_ok(),
                assigned,
                "manager role assignment is required: {result:?}"
            );
            if assigned {
                assert!(
                    authority_has_permission(
                        &state_transaction.world,
                        &builder,
                        &contract_deployment_permission()
                    )
                    .expect("granted permission")
                );
                let revoke: InstructionBox =
                    Revoke::account_permission(contract_deployment_permission(), builder.clone())
                        .into();
                executor
                    .execute_borrowed_overlay_instruction(
                        &mut state_transaction,
                        &manager,
                        &revoke,
                        None,
                    )
                    .expect("manager may revoke a code manager");
                assert!(
                    !authority_has_permission(
                        &state_transaction.world,
                        &builder,
                        &contract_deployment_permission()
                    )
                    .expect("revoked permission")
                );
            }
            for instruction in [
                Grant::account_permission(manager_permission.clone(), builder.clone()).into(),
                Revoke::account_permission(manager_permission.clone(), manager.clone()).into(),
                Grant::account_role(role_id.clone(), builder.clone()).into(),
                Revoke::account_role(role_id.clone(), manager.clone()).into(),
                Grant::role_permission(manager_permission.clone(), role_id.clone()).into(),
                Unregister::role(role_id.clone()).into(),
                Register::role(
                    Role::new("new_managers".parse().expect("role id"), builder.clone())
                        .add_permission(manager_permission.clone()),
                )
                .into(),
            ] {
                let error = executor
                    .execute_instruction(&mut state_transaction, &manager, instruction)
                    .expect_err("manager roots cannot be propagated or removed after genesis");
                assert!(
                    matches!(error, ValidationFail::NotPermitted(message) if message.contains("CanGrantSmartContractCodeManagement") && message.contains("genesis"))
                );
            }
            for permission in [contract_deployment_permission(), manager_permission] {
                let malformed = Permission::new(permission.name().to_owned(), Json::new(true));
                let grant: InstructionBox =
                    Grant::account_permission(malformed, builder.clone()).into();
                let error = executor
                    .execute_borrowed_overlay_instruction(
                        &mut state_transaction,
                        &manager,
                        &grant,
                        None,
                    )
                    .expect_err("non-unit code-management capabilities always reject");
                assert!(
                    matches!(error, ValidationFail::NotPermitted(message) if message.contains("Invalid permission payload"))
                );
            }
        }
    }
}
#[test]
fn default_user_provided_executor_rejects_existing_bootstrap_before_grant_dispatch() {
    let keypair = checked_keypair();
    let authority = AccountId::new(keypair.public_key().clone());
    let chain = ChainId::from("contract-deployment-bootstrap-user-provided-replay");
    let code_hash = Hash::new(b"default user-provided deployment bootstrap replay");
    let account = Account::new(authority.clone()).build(&authority);
    let state = State::new_with_chain(
        component_world_for_testing(World::with([], [account], [])),
        Kura::blank_kura_for_testing(),
        query::store::LiveQueryStore::start_test(),
        chain,
    );
    let transaction = TransactionBuilder::new(
        state.network_id,
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_executable(Executable::Instructions(
        contract_deployment_bootstrap_instructions(
            &authority,
            Account::new(authority.clone()),
            contract_deployment_permission(),
            contract_upload_instruction(code_hash, 0),
        )
        .into(),
    ))
    .sign(keypair.private_key());
    let mut block = state.block(BlockHeader::new(nonzero!(2_u64), None, None, 0, 0));
    let executor = bundled_default_user_provided_executor();
    let super::Executor::UserProvided(loaded_executor) = &executor else {
        unreachable!("test constructs a user-provided executor")
    };
    let (runtime_stats_before, _) = loaded_executor.runtime_pool_snapshot();
    let error = {
        let mut state_transaction = block.transaction_for_fastpq_testing(iroha_crypto::Hash::from(
            transaction.hash_as_entrypoint(),
        ));
        state_transaction.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        state_transaction.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        let mut ivm_cache = IvmCache::new();
        executor
            .execute_transaction(
                &mut state_transaction,
                &authority,
                transaction,
                &mut ivm_cache,
            )
            .map_err(crate::execution_attempt::expect_completed_rejection)
            .expect_err("an existing authority cannot replay the bootstrap prefix")
    };
    assert!(
        matches!(&error, ValidationFail::InstructionFailed(
            iroha_data_model::isi::error::InstructionExecutionError::Repetition(detail)
        ) if detail.instruction == iroha_data_model::isi::InstructionType::Register
            && detail.id == iroha_data_model::IdBox::AccountId(authority.clone())),
        "duplicate bootstrap registration must reject the exact existing account: {error:?}"
    );
    let (runtime_stats_after, _) = loaded_executor.runtime_pool_snapshot();
    assert_eq!(
        runtime_stats_after.hits + runtime_stats_after.misses,
        runtime_stats_before.hits + runtime_stats_before.misses + 1,
        "only the rejected duplicate account registration may reach the runtime"
    );
    block
        .world
        .account(&authority)
        .expect("pre-existing account must remain present");
    assert!(
        !block
            .world
            .account_permissions_iter(&authority)
            .expect("pre-existing account permissions")
            .any(|permission| permission.name() == "CanManageSmartContractCode")
    );
    assert!(
        block
            .world
            .contract_code_upload_progress(
                &authority,
                &iroha_data_model::smart_contract::ContractArtifactId::new(
                    DataSpaceId::UNIVERSAL,
                    code_hash
                )
            )
            .is_none()
    );
}
#[test]
#[allow(clippy::too_many_lines)]
fn default_user_provided_executor_rejects_noncanonical_bootstrap_without_committing_state() {
    let keypair = checked_keypair();
    let authority = AccountId::new(keypair.public_key().clone());
    let chain = ChainId::from("contract-deployment-bootstrap-user-provided-adversarial");
    let code_hash = Hash::new(b"default user-provided adversarial deployment bootstrap");
    let mut metadata = Metadata::default();
    metadata.insert(
        "bootstrap-note".parse().expect("metadata key"),
        Json::new("decorated"),
    );
    let plain = contract_deployment_bootstrap_instructions(
        &authority,
        Account::new(authority.clone()),
        contract_deployment_permission(),
        contract_upload_instruction(code_hash, 0),
    );
    let decorated = contract_deployment_bootstrap_instructions(
        &authority,
        Account::new(authority.clone()).with_metadata(metadata),
        contract_deployment_permission(),
        contract_upload_instruction(code_hash, 0),
    );
    let malformed = contract_deployment_bootstrap_instructions(
        &authority,
        Account::new(authority.clone()),
        Permission::new(
            "CanManageSmartContractCode".to_owned(),
            Json::from(norito::json!({ "scope": "malformed" })),
        ),
        contract_upload_instruction(code_hash, 0),
    );
    let reordered = vec![
        Register::account(Account::new(authority.clone())).into(),
        contract_upload_instruction(code_hash, 0),
        Grant::account_permission(contract_deployment_permission(), authority.clone()).into(),
    ];
    for (label, instructions, expected_runtime_checkouts) in [
        ("plain self-grant", plain, 1),
        ("decorated registration", decorated, 1),
        ("malformed same-name grant", malformed, 1),
        ("reordered prefix", reordered, 2),
    ] {
        let state = State::new_with_chain(
            component_world_for_testing(World::new()),
            Kura::blank_kura_for_testing(),
            query::store::LiveQueryStore::start_test(),
            chain.clone(),
        );
        let transaction = TransactionBuilder::new(
            state.network_id,
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_executable(Executable::Instructions(instructions.into()))
        .sign(keypair.private_key());
        let mut block = state.block(BlockHeader::new(nonzero!(2_u64), None, None, 0, 0));
        let executor = bundled_default_user_provided_executor();
        let super::Executor::UserProvided(loaded_executor) = &executor else {
            unreachable!("test constructs a user-provided executor")
        };
        let (runtime_stats_before, _) = loaded_executor.runtime_pool_snapshot();
        let error = {
            let mut state_transaction = block.transaction_for_fastpq_testing(
                iroha_crypto::Hash::from(transaction.hash_as_entrypoint()),
            );
            state_transaction.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            state_transaction.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            let mut ivm_cache = IvmCache::new();
            executor
                .execute_transaction(
                    &mut state_transaction,
                    &authority,
                    transaction,
                    &mut ivm_cache,
                )
                .map_err(crate::execution_attempt::expect_completed_rejection)
                .expect_err("noncanonical bootstrap must be rejected")
        };
        let error_debug = format!("{error:?}");
        assert!(
            error_debug.contains("CanManageSmartContractCode"),
            "unexpected {label} rejection: {error_debug}"
        );
        let (runtime_stats_after, _) = loaded_executor.runtime_pool_snapshot();
        assert_eq!(
            runtime_stats_after.hits + runtime_stats_after.misses,
            runtime_stats_before.hits + runtime_stats_before.misses + expected_runtime_checkouts,
            "unexpected user-provided runtime dispatch count for {label}"
        );
        assert!(
            block.world.account(&authority).is_err(),
            "rejected {label} must not commit its provisional account"
        );
        assert!(
            block.world.account_permissions.get(&authority).is_none(),
            "rejected {label} must not commit a permission"
        );
        assert!(
            block
                .world
                .contract_code_upload_progress(
                    &authority,
                    &iroha_data_model::smart_contract::ContractArtifactId::new(
                        DataSpaceId::UNIVERSAL,
                        code_hash
                    )
                )
                .is_none(),
            "rejected {label} must not commit upload staging"
        );
    }
}
#[test]
fn user_provided_borrowed_overlay_rejects_deployment_permission_before_runtime_dispatch() {
    let authority = checked_account_id();
    let account = Account::new(authority.clone()).build(&authority);
    let state = State::new_for_testing(
        component_world_for_testing(World::with([], [account], [])),
        Kura::blank_kura_for_testing(),
        query::store::LiveQueryStore::start_test(),
    );
    let mut block = state.block(BlockHeader::new(nonzero!(2_u64), None, None, 0, 0));
    let mut state_transaction = block.transaction();
    let instruction: InstructionBox =
        Grant::account_permission(contract_deployment_permission(), authority.clone()).into();
    let executor = bundled_default_user_provided_executor();
    let super::Executor::UserProvided(loaded_executor) = &executor else {
        unreachable!("test constructs a user-provided executor")
    };
    let (runtime_stats_before, _) = loaded_executor.runtime_pool_snapshot();
    let error = executor
        .execute_borrowed_overlay_instruction(
            &mut state_transaction,
            &authority,
            &instruction,
            None,
        )
        .expect_err("borrowed overlay permission mutation must be consensus-gated");
    assert!(
        matches!(&error, ValidationFail::NotPermitted(message) if
        message.contains("CanManageSmartContractCode")
            && message.contains("CanGrantSmartContractCodeManagement")),
        "unexpected bootstrap rejection: {error:?}"
    );
    let (runtime_stats_after, _) = loaded_executor.runtime_pool_snapshot();
    assert_eq!(runtime_stats_after, runtime_stats_before);
    assert!(
        !state_transaction
            .world
            .account_permissions_iter(&authority)
            .expect("account permissions")
            .any(|permission| permission.name() == "CanManageSmartContractCode")
    );
}
#[test]
fn initial_executor_denies_preexisting_deployment_self_grant_without_state_change() {
    let keypair = checked_keypair();
    let authority = AccountId::new(keypair.public_key().clone());
    let chain = ChainId::from("contract-deployment-bootstrap-existing");
    let code_hash = Hash::new(b"contract deployment bootstrap existing authority");
    let account = Account::new(authority.clone()).build(&authority);
    let state = State::new_with_chain(
        component_world_for_testing(World::with([], [account], [])),
        Kura::blank_kura_for_testing(),
        query::store::LiveQueryStore::start_test(),
        chain,
    );
    let transaction = TransactionBuilder::new(
        state.network_id,
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_executable(Executable::Instructions(
        contract_deployment_bootstrap_instructions(
            &authority,
            Account::new(authority.clone()),
            contract_deployment_permission(),
            contract_upload_instruction(code_hash, 0),
        )
        .into(),
    ))
    .sign(keypair.private_key());
    let mut block = state.block(BlockHeader::new(nonzero!(2_u64), None, None, 0, 0));
    let mut state_transaction = block
        .transaction_for_fastpq_testing(iroha_crypto::Hash::from(transaction.hash_as_entrypoint()));
    state_transaction.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
    state_transaction.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
    let mut ivm_cache = IvmCache::new();
    assert!(
        !(state_transaction._curr_block.is_genesis() && state_transaction.block_hashes.is_empty()),
        "bootstrap replay must be exercised outside genesis"
    );
    let error = super::Executor::Initial
        .execute_transaction(
            &mut state_transaction,
            &authority,
            transaction,
            &mut ivm_cache,
        )
        .map_err(crate::execution_attempt::expect_completed_rejection)
        .expect_err("an existing authority cannot replay the bootstrap prefix");
    assert!(
        matches!(&error, ValidationFail::InstructionFailed(
            iroha_data_model::isi::error::InstructionExecutionError::Repetition(detail)
        ) if detail.instruction == iroha_data_model::isi::InstructionType::Register
            && detail.id == iroha_data_model::IdBox::AccountId(authority.clone())),
        "duplicate bootstrap registration must reject the exact existing account: {error:?}"
    );
    assert!(
        !state_transaction
            .world
            .account_permissions_iter(&authority)
            .expect("existing account permissions")
            .any(|permission| permission.name() == "CanManageSmartContractCode")
    );
    assert!(
        state_transaction
            .world
            .contract_code_upload_progress(
                &authority,
                &iroha_data_model::smart_contract::ContractArtifactId::new(
                    DataSpaceId::UNIVERSAL,
                    code_hash
                )
            )
            .is_none()
    );
}
#[test]
fn initial_executor_denies_deployment_permission_grant_revoke_and_malformed_payload() {
    let authority = checked_account_id();
    let canonical = contract_deployment_permission();
    let account = Account::new(authority.clone()).build(&authority);
    let mut world = World::with([], [account], []);
    world
        .account_permissions
        .insert(authority.clone(), BTreeSet::from([canonical.clone()]));
    let state = State::new_for_testing(
        component_world_for_testing(world),
        Kura::blank_kura_for_testing(),
        query::store::LiveQueryStore::start_test(),
    );
    let mut block = state.block(BlockHeader::new(nonzero!(2_u64), None, None, 0, 0));
    let mut state_transaction = block.transaction();
    assert!(
        !(state_transaction._curr_block.is_genesis() && state_transaction.block_hashes.is_empty()),
        "permission parity must be exercised outside genesis"
    );
    let malformed = Permission::new(
        "CanManageSmartContractCode".to_owned(),
        Json::from(norito::json!({ "scope": "not-canonical" })),
    );
    let role_id: RoleId = "deployment_bootstrap_role".parse().expect("role id");
    for instruction in [
        Grant::account_permission(canonical.clone(), authority.clone()).into(),
        Grant::account_permission(malformed, authority.clone()).into(),
        Revoke::account_permission(canonical.clone(), authority.clone()).into(),
        Grant::role_permission(canonical.clone(), role_id.clone()).into(),
        Revoke::role_permission(canonical.clone(), role_id.clone()).into(),
        concrete_instruction_box!(
            Grant<Permission, Account>,
            Grant::account_permission(canonical.clone(), authority.clone())
        ),
        concrete_instruction_box!(
            Revoke<Permission, Role>,
            Revoke::role_permission(canonical.clone(), role_id)
        ),
    ] {
        let error = super::Executor::Initial
            .execute_instruction(&mut state_transaction, &authority, instruction)
            .expect_err("deployment permission mutation requires code-management grant authority");
        assert!(matches!(error, ValidationFail::NotPermitted(message) if
            message.contains("CanManageSmartContractCode")));
    }
    let stored: BTreeSet<_> = state_transaction
        .world
        .account_permissions_iter(&authority)
        .expect("account permissions")
        .cloned()
        .collect();
    assert_eq!(stored, BTreeSet::from([canonical]));
}
