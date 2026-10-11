fn owner_entrypoint_permission(address: &ContractAddress, selector: &str) -> Permission {
    executor_permission::smart_contract::CanUseContractPermission {
        contract: address.clone(),
        permission: selector.parse().expect("declared permission name"),
    }
    .into()
}
fn seed_owner_permission_contract(
    transaction: &mut crate::state::StateTransaction<'_, '_>,
    address: &ContractAddress,
    owner: &AccountId,
    code_hash: Hash,
) {
    let artifact =
        iroha_data_model::smart_contract::ContractArtifactId::for_address(address, code_hash)
            .unwrap();
    if transaction
        .world
        .contract_manifests
        .get(&artifact)
        .is_none()
    {
        let (_, mut manifest) = kotodama_lang::compiler::Compiler::new()
            .compile_source_with_manifest(
                r#"
seiyaku OwnerGrantFixture {
  hajimari() {}
  permission read;
  permission touch_caller;
  permission unused;
  permission write;
  kotoage fn write_value() authorize(write) {}
  view fn read_value() authorize(read) -> int { return 1; }
}
"#,
            )
            .expect("compile declared permission fixture");
        manifest.code_hash = Some(code_hash);
        transaction
            .world
            .contract_manifests
            .insert(artifact, manifest);
    }
    transaction.world.accounts.insert(
        address.subject_id(),
        iroha_data_model::account::AccountValue::new(
            iroha_data_model::account::AccountDetails::default(),
        ),
    );
    transaction
        .world
        .contract_instances
        .insert(address.clone(), code_hash);
    transaction
        .world
        .contract_subject_addresses
        .insert(address.subject_id(), address.clone());
    transaction.world.contract_subject_bindings.insert(
        address.clone(),
        crate::smartcontracts::code::ContractSubjectBinding::new_direct(address, owner.clone())
            .with_active_code_hash(code_hash),
    );
}
fn owner_permission_state(owner: &AccountId, recipient: &AccountId) -> (State, ContractAddress) {
    let state = state_after_genesis(World::with(
        [],
        [
            Account::new(owner.clone()).build(owner),
            Account::new(recipient.clone()).build(recipient),
        ],
        [],
    ));
    let address = ContractAddress::derive(&state.network_id, owner, 41, DataSpaceId::UNIVERSAL)
        .expect("contract address from original genesis network");
    {
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            state.view().latest_block_hash(),
            None,
            0,
            0,
        ));
        let mut setup = block.transaction();
        seed_owner_permission_contract(
            &mut setup,
            &address,
            owner,
            Hash::new(b"owner delegation code"),
        );
        setup.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("contract owner fixture World setup");
    }
    (state, address)
}

#[test]
fn current_contract_owner_originates_and_revokes_exact_tokens_without_code_management() {
    for executor in [
        super::Executor::Initial,
        bundled_default_user_provided_executor(),
    ] {
        let owner = checked_account_id();
        let recipient = checked_account_id();
        let (state, address) = owner_permission_state(&owner, &recipient);
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            state.view().latest_block_hash(),
            None,
            0,
            0,
        ));
        let mut tx = block.transaction();
        let permission = owner_entrypoint_permission(&address, "write");
        assert!(
            !authority_has_permission(&tx.world, &owner, &contract_deployment_permission())
                .unwrap()
        );
        assert!(!authority_has_permission(&tx.world, &owner, &permission).unwrap());
        executor
            .execute_instruction(
                &mut tx,
                &owner,
                Grant::account_permission(permission.clone(), recipient.clone()).into(),
            )
            .expect("current lifecycle owner originates exact grant");
        assert!(authority_has_permission(&tx.world, &recipient, &permission).unwrap());
        executor
            .execute_instruction(
                &mut tx,
                &owner,
                Revoke::account_permission(permission.clone(), recipient.clone()).into(),
            )
            .expect("current lifecycle owner revokes exact grant without possessing it");
        assert!(!authority_has_permission(&tx.world, &recipient, &permission).unwrap());
        assert!(
            !authority_has_permission(&tx.world, &owner, &contract_deployment_permission())
                .unwrap()
        );
    }
}

#[test]
fn suspended_contract_permissions_can_be_repaired_without_authorizing_invocation() {
    for executor in [
        super::Executor::Initial,
        bundled_default_user_provided_executor(),
    ] {
        let owner = checked_account_id();
        let holder = checked_account_id();
        let (state, address) = owner_permission_state(&owner, &holder);
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            state.view().latest_block_hash(),
            None,
            0,
            0,
        ));
        let mut tx = block.transaction();
        let retained = tx.world.contract_instances.get(&address).copied().unwrap();
        let revision = tx
            .world
            .contract_subject_bindings
            .get(&address)
            .unwrap()
            .lifecycle
            .revision;
        iroha_data_model::isi::smart_contract_code::DeactivateContractInstance {
            contract_address: address.clone(),
            expected_revision: revision,
            reason: None,
        }
        .execute(&owner, &mut tx)
        .expect("owner suspends the contract before repairing its grants");
        assert!(tx.world.contract_instances.get(&address).is_none());
        assert_eq!(
            tx.world
                .contract_subject_bindings
                .get(&address)
                .unwrap()
                .lifecycle
                .retained_code_hash,
            Some(retained)
        );
        let permission = owner_entrypoint_permission(&address, "write");
        executor
            .execute_instruction(
                &mut tx,
                &owner,
                Grant::account_permission(permission.clone(), holder.clone()).into(),
            )
            .expect("owner grants a retained declaration while suspended");
        executor
            .execute_instruction(
                &mut tx,
                &holder,
                Grant::account_permission(permission.clone(), owner.clone()).into(),
            )
            .expect("exact holder delegates a retained declaration while suspended");
        for authority in [&owner, &holder] {
            let denied = enforce_named_contract_entrypoint_authorization(
                &tx.world,
                authority,
                &address,
                "write_value",
                &iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Permission(
                    "write".parse().unwrap(),
                ),
            )
            .expect_err("even an exact grant cannot invoke a suspended instance");
            assert!(denied.to_string().contains("live instance"));
        }
        executor
            .execute_instruction(
                &mut tx,
                &holder,
                Revoke::account_permission(permission.clone(), owner.clone()).into(),
            )
            .expect("exact holder revokes a retained declaration while suspended");
        executor
            .execute_instruction(
                &mut tx,
                &owner,
                Revoke::account_permission(permission.clone(), holder.clone()).into(),
            )
            .expect("owner revokes a retained declaration while suspended");
        assert!(!authority_has_permission(&tx.world, &owner, &permission).unwrap());
        assert!(!authority_has_permission(&tx.world, &holder, &permission).unwrap());
        let typo = owner_entrypoint_permission(&address, "writeTypo");
        for instruction in [
            Grant::account_permission(typo.clone(), holder.clone()).into(),
            Revoke::account_permission(typo, holder.clone()).into(),
        ] {
            assert!(
                executor
                    .execute_instruction(&mut tx, &owner, instruction)
                    .unwrap_err()
                    .to_string()
                    .contains("Instance permission declared by the current code")
            );
        }
    }
}

#[test]
fn contract_owner_delegation_rejects_foreign_transferred_pending_and_parliament_authority() {
    use iroha_data_model::smart_contract::ContractLifecycleOwnerV1;
    for scenario in 0..8 {
        let owner = checked_account_id();
        let foreign = checked_account_id();
        let (state, address) = owner_permission_state(&owner, &foreign);
        let authority = match scenario {
            0 | 2 | 6 | 7 => foreign.clone(),
            _ => owner.clone(),
        };
        let mut block = state.block(BlockHeader::new(
            nonzero!(2_u64),
            state.view().latest_block_hash(),
            None,
            0,
            0,
        ));
        let mut tx = block.transaction();
        assert!(
            super::root_scope::execution_root_scope(&mut tx).is_ok(),
            "owner refusal scenarios must reach the authenticated permission boundary"
        );
        let mut binding = tx
            .world
            .contract_subject_bindings
            .get(&address)
            .cloned()
            .unwrap();
        match scenario {
            1 => binding.lifecycle.owner = ContractLifecycleOwnerV1::Account(foreign.clone()),
            2 => {
                binding.lifecycle.pending_owner =
                    Some(ContractLifecycleOwnerV1::Account(foreign.clone()))
            }
            3 => binding.lifecycle.owner = ContractLifecycleOwnerV1::Parliament,
            _ => {}
        }
        tx.world
            .contract_subject_bindings
            .insert(address.clone(), binding);
        let selector = if scenario == 5 { "writeTypo" } else { "write" };
        let permission = owner_entrypoint_permission(&address, selector);
        if scenario == 6 {
            tx.world.account_permissions.insert(
                foreign.clone(),
                BTreeSet::from([owner_entrypoint_permission(&address, "read")]),
            );
        }
        if scenario == 7 {
            tx.world.account_permissions.insert(
                foreign.clone(),
                BTreeSet::from([
                    executor_permission::smart_contract::CanManageSmartContractCode.into(),
                ]),
            );
        }
        let role_id: RoleId = "owner_scope_test".parse().unwrap();
        tx.world.roles.insert(
            role_id.clone(),
            Role::new(role_id.clone(), owner.clone())
                .add_permission(permission.clone())
                .build(&owner),
        );
        if scenario == 4 {
            // Construct a valid State, then exercise the delegation boundary against a
            // corrupted transactional view. State startup correctly rejects this binding.
            tx.world
                .contract_subject_bindings
                .get_mut(&address)
                .unwrap()
                .lifecycle
                .active_code_hash = Some(Hash::new(b"unmatched active index"));
        }
        let instructions: Vec<InstructionBox> = vec![
            Grant::account_permission(permission.clone(), foreign.clone()).into(),
            Revoke::account_permission(permission.clone(), foreign.clone()).into(),
            Grant::role_permission(permission.clone(), role_id.clone()).into(),
            Revoke::role_permission(permission.clone(), role_id.clone()).into(),
            Grant::account_role(role_id.clone(), foreign.clone()).into(),
            Revoke::account_role(role_id.clone(), foreign.clone()).into(),
            Register::role(
                Role::new("new_owner_scope_test".parse().unwrap(), authority.clone())
                    .add_permission(permission.clone()),
            )
            .into(),
            Unregister::role(role_id.clone()).into(),
        ];
        // Even an executor that approves everything cannot bypass this native invariant.
        let permissive = super::Executor::UserProvided(
            super::LoadedExecutor::load(data_model_executor::Executor::new(
                IvmBytecode::from_compiled(generate_ok_program()),
            ))
            .expect("permissive test executor"),
        );
        for executor in [&super::Executor::Initial, &permissive] {
            for instruction in &instructions {
                assert!(
                    executor
                        .execute_instruction(&mut tx, &authority, instruction.clone())
                        .is_err(),
                    "scenario {scenario} accepted an owned permission mutation: {instruction:?}"
                );
                assert!(
                    executor
                        .execute_borrowed_overlay_instruction(
                            &mut tx,
                            &authority,
                            instruction,
                            None
                        )
                        .is_err(),
                    "scenario {scenario} accepted a borrowed permission mutation: {instruction:?}"
                );
            }
        }
        assert!(!authority_has_permission(&tx.world, &foreign, &permission).unwrap());
    }
}

#[test]
fn ordinary_owner_self_grant_enables_guarded_call_and_revocation_closes_it() {
    let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
    let authority = ALICE_ID.clone();
    let (program, manifest) = kotodama_lang::compiler::Compiler::new()
        .compile_source_with_manifest(
            r#"
seiyaku OwnerPermission { permission write; permission touch_caller;
  state int owner_authorized;
  hajimari() { owner_authorized = 0; }
  kotoage fn write_value() authorize(write) {
    owner_authorized = 1;
  }
  kotoage fn touch_account() authorize(anyone) {
    ledger::account::set_metadata(
      account: context::authority(),
      key: Name::parse("owner_authorized"),
      value: Json::parse("{\"written\":true}")
    );
  }
}
"#,
        )
        .expect("compile guarded mutable entrypoint");
    let code_hash = ivm::contract_code_hash(&program);
    let state = state_after_genesis(World::with(
        [],
        [Account::new(authority.clone()).build(&authority)],
        [],
    ));
    let address =
        ContractAddress::derive(&state.network_id, &authority, 73, DataSpaceId::UNIVERSAL).unwrap();
    let mut block = state.block(BlockHeader::new(
        nonzero!(2_u64),
        state.view().latest_block_hash(),
        None,
        0,
        0,
    ));
    let mut setup = block.transaction();
    setup.world.contract_code.insert(
        iroha_data_model::smart_contract::ContractArtifactId::new(
            address.dataspace_id().unwrap(),
            code_hash,
        ),
        program,
    );
    setup.world.contract_manifests.insert(
        iroha_data_model::smart_contract::ContractArtifactId::new(
            address.dataspace_id().unwrap(),
            code_hash,
        ),
        manifest
            .try_signed(
                manifest_signing.context(),
                manifest_signing.max_frame_bytes(),
                &ALICE_KEYPAIR,
            )
            .expect("sign bounded fixture manifest"),
    );
    seed_owner_permission_contract(&mut setup, &address, &authority, code_hash);
    setup.apply();
    let permission = owner_entrypoint_permission(&address, "write");
    let call = TransactionBuilder::new(
        state.network_id,
        authority.clone(),
        FeePaymentIntent::authority(Vec::new(), core::num::NonZeroU64::new(50_000_000)),
    )
    .with_executable(Executable::ContractCall(ContractInvocation {
        contract_address: address.clone(),
        expected_code_hash: code_hash,
        entrypoint: "write_value".to_owned(),
        arguments: None,
    }))
    .sign(ALICE_KEYPAIR.private_key());
    let mut cache = IvmCache::new();
    let mut tx = block.transaction_for_fastpq_testing(Hash::from(call.hash_as_entrypoint()));
    tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
    tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
    assert!(
        !authority_has_permission(&tx.world, &authority, &contract_deployment_permission())
            .unwrap()
    );
    let denied = super::Executor::Initial
        .execute_transaction(&mut tx, &authority, call.clone(), &mut cache)
        .expect_err("ownership alone must not authorize invocation");
    assert!(
        denied
            .to_string()
            .contains("requires its declared exact authorization")
    );
    drop(tx);
    let grant = TransactionBuilder::new(
        state.network_id,
        authority.clone(),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Grant::account_permission(
        permission.clone(),
        authority.clone(),
    )])
    .sign(ALICE_KEYPAIR.private_key());
    let mut tx = block.transaction_for_fastpq_testing(Hash::from(grant.hash_as_entrypoint()));
    tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
    tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
    super::Executor::Initial
        .execute_transaction(&mut tx, &authority, grant, &mut cache)
        .expect("ordinary owner self-grant executes without global permission");
    tx.apply();
    let mut tx = block.transaction_for_fastpq_testing(Hash::from(call.hash_as_entrypoint()));
    tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
    tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
    super::Executor::Initial
        .execute_transaction(&mut tx, &authority, call.clone(), &mut cache)
        .expect("exact self-grant authorizes guarded mutable call");
    let state_key: StatePath = format!(
        "sc/{}/owner_authorized",
        hex::encode(Hash::new(address.to_string().as_bytes()).as_ref())
    )
    .parse()
    .unwrap();
    assert!(
        tx.world.smart_contract_state.get(&state_key).is_some(),
        "the guarded call must persist its own address-scoped state"
    );
    assert!(
        tx.world
            .account(&authority)
            .unwrap()
            .metadata()
            .get(&"owner_authorized".parse::<Name>().unwrap())
            .is_none()
    );
    tx.apply();
    // Invocation permission does not authorize a contract subject to mutate its caller's
    // account metadata. Keep this negative body unchanged from the original failure.
    let mut tx = block.transaction();
    super::Executor::Initial
        .execute_instruction(
            &mut tx,
            &authority,
            Grant::account_permission(
                owner_entrypoint_permission(&address, "touch_caller"),
                authority.clone(),
            )
            .into(),
        )
        .expect("owner may grant a second exact selector");
    tx.apply();
    let forbidden_body = TransactionBuilder::from_payload(call.payload().clone())
        .unwrap()
        .with_executable(Executable::ContractCall(ContractInvocation {
            contract_address: address.clone(),
            expected_code_hash: code_hash,
            entrypoint: "touch_account".to_owned(),
            arguments: None,
        }))
        .sign(ALICE_KEYPAIR.private_key());
    let mut tx =
        block.transaction_for_fastpq_testing(Hash::from(forbidden_body.hash_as_entrypoint()));
    tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
    tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
    let denied = super::Executor::Initial
        .execute_transaction(&mut tx, &authority, forbidden_body, &mut cache)
        .expect_err("scoped invocation does not grant caller metadata authority");
    assert!(
        denied
            .to_string()
            .contains("authority cannot modify this metadata")
    );
    drop(tx);
    let mut tx = block.transaction();
    super::Executor::Initial
        .execute_instruction(
            &mut tx,
            &authority,
            Revoke::account_permission(permission.clone(), authority.clone()).into(),
        )
        .expect("owner revokes exact invocation grant");
    tx.apply();
    let mut tx = block.transaction_for_fastpq_testing(Hash::from(call.hash_as_entrypoint()));
    tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
    tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
    assert!(
        super::Executor::Initial
            .execute_transaction(&mut tx, &authority, call, &mut cache)
            .is_err()
    );
    assert!(
        !authority_has_permission(&tx.world, &authority, &contract_deployment_permission())
            .unwrap()
    );
}

#[test]
fn scoped_permission_delegation_requires_current_declaration_and_exact_instance() {
    let owner = checked_account_id();
    let holder = checked_account_id();
    let (state, address) = owner_permission_state(&owner, &holder);
    let mut block = state.block(BlockHeader::new(
        nonzero!(2_u64),
        state.view().latest_block_hash(),
        None,
        0,
        0,
    ));
    let mut tx = block.transaction();
    let unused = owner_entrypoint_permission(&address, "unused");
    assert!(
        contract_permission_delegation_allowed(&tx, &owner, &unused).unwrap(),
        "declared but unused permissions are legitimate capabilities"
    );
    tx.world.add_account_permission(&holder, unused.clone());
    assert!(
        contract_permission_delegation_allowed(&tx, &holder, &unused).unwrap(),
        "an exact holder may delegate a live declared permission"
    );
    let second =
        ContractAddress::derive(&state.network_id, &owner, 42, DataSpaceId::UNIVERSAL).unwrap();
    seed_owner_permission_contract(
        &mut tx,
        &second,
        &owner,
        Hash::new(b"second permission declaration"),
    );
    assert!(
        !contract_permission_delegation_allowed(
            &tx,
            &holder,
            &owner_entrypoint_permission(&second, "unused")
        )
        .unwrap(),
        "a holder cannot cross instances with the same declaration name"
    );
    let artifact = iroha_data_model::smart_contract::ContractArtifactId::for_address(
        &address,
        *tx.world.contract_instances.get(&address).unwrap(),
    )
    .unwrap();
    tx.world
        .contract_manifests
        .get_mut(&artifact)
        .unwrap()
        .permissions
        .retain(|declaration| declaration.name.as_ref() != "unused");
    assert!(
        contract_permission_delegation_allowed(&tx, &holder, &unused).is_err(),
        "a retained token does not revive a declaration removed by current code"
    );
    assert!(
        contract_permission_delegation_allowed(&tx, &owner, &unused).is_err(),
        "ownership does not permit misspelled or retired declarations"
    );
}
