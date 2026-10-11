#[test]
fn contract_dispatch_context_rejects_no_selector_self_describing_artifact_without_main() {
    let (program, expected_entrypoint_pc) =
        contract_program_with_entrypoint("run", Some("RunPermission"));
    let metadata = Metadata::default();
    let err = parse_contract_call_execution_context(&metadata, &program)
        .expect_err("self-describing default dispatch without main should reject");
    assert!(matches!(
        err,
        ValidationFail::NotPermitted(message)
            if message.contains("require explicit contract_entrypoint")
    ));
    let mut metadata = Metadata::default();
    metadata.insert(
        Name::from_str("contract_entrypoint").expect("static name"),
        Json::new("run".to_owned()),
    );
    let context = parse_contract_call_execution_context(&metadata, &program)
        .expect("explicit run dispatch parses")
        .expect("explicit run context");
    assert_eq!(context.entrypoint.as_deref(), Some("run"));
    assert_eq!(context.entrypoint_pc(), Some(expected_entrypoint_pc));
    assert_eq!(
        context.entrypoint_authorization(),
        &EntrypointAuthorizationV1::Permission("RunPermission".parse().unwrap())
    );
}
#[test]
fn trigger_dispatch_encodes_event_args_as_one_canonical_record() {
    let contract = prepared_parameterized_trigger_contract();
    let mut metadata = Metadata::default();
    metadata.insert(
        Name::from_str("contract_entrypoint").expect("static name"),
        Json::new("run".to_owned()),
    );
    let event_args = Json::from(norito::json!({"val": "1.25"}));
    validate_trigger_call_execution_context(&metadata, contract.artifact())
        .expect("registration validates the typed callback without a fabricated payload");
    let context =
        parse_prepared_trigger_call_execution_context(&metadata, &contract, &event_args, u64::MAX)
            .expect("bind typed trigger arguments");
    let descriptor = contract
        .entrypoint_descriptor("run")
        .expect("run descriptor");
    let schema = descriptor
        .argument_schema
        .as_ref()
        .expect("run argument schema");
    let expected = ivm_abi::arguments::encode_argument_record_from_json(schema, &event_args)
        .expect("encode expected canonical record");
    assert_eq!(context.argument_record(), Some(expected.as_slice()));
    ivm::validate_argument_record(
        schema,
        context.argument_record().expect("trigger argument record"),
    )
    .expect("roundtrip canonical trigger argument record");
}
#[test]
#[cfg(debug_assertions)]
fn malformed_invocation_arguments_fail_during_context_preparation() {
    let contract = prepared_parameterized_trigger_contract();
    let schema = contract
        .entrypoint_descriptor("run")
        .and_then(|descriptor| descriptor.argument_schema.as_ref())
        .expect("run argument schema");
    let mut malformed = ivm_abi::arguments::encode_argument_record_from_json(
        schema,
        &Json::from(norito::json!({"val": "1.25"})),
    )
    .expect("encode valid argument fixture");
    *malformed.last_mut().expect("record hash byte") ^= 0x80;
    let contract_address = ContractAddress::derive(
        &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
            .parse()
            .expect("canonical test network id"),
        &ALICE_ID,
        19,
        DataSpaceId::UNIVERSAL,
    )
    .expect("derive contract address");
    let invocation = ContractInvocation {
        contract_address,
        expected_code_hash: iroha_crypto::Hash::new(b"malformed-argument-contract-code"),
        entrypoint: "run".to_owned(),
        arguments: Some(
            iroha_data_model::transaction::executable::ContractArgumentRecord::try_new(malformed)
                .expect("bounded malformed fixture"),
        ),
    };
    ivm::reset_argument_record_decode_count();
    let error = parse_prepared_contract_invocation_execution_context(
        &invocation,
        &contract,
        None,
        invocation.contract_address.subject_id(),
        u64::MAX,
    )
    .expect_err("malformed arguments must fail before a VM is constructed or entered");
    assert!(matches!(
        error,
        ValidationFail::NotPermitted(message)
            if message.contains("invalid contract argument record")
    ));
    assert_eq!(ivm::argument_record_decode_count(), 1);
}
#[test]
fn trigger_dispatch_rejects_static_payload_and_implicit_entrypoint() {
    let contract = prepared_parameterized_trigger_contract();
    let event_args = Json::from(norito::json!({"val": "7"}));
    let err = parse_prepared_trigger_call_execution_context(
        &Metadata::default(),
        &contract,
        &event_args,
        u64::MAX,
    )
    .expect_err("trigger callback selection must be explicit");
    assert!(matches!(
        err,
        ValidationFail::NotPermitted(message)
            if message.contains("explicit contract_entrypoint")
    ));
    let mut metadata = Metadata::default();
    metadata.insert(
        Name::from_str("contract_entrypoint").expect("static name"),
        Json::new("run".to_owned()),
    );
    metadata.insert(
        Name::from_str("contract_payload").expect("static name"),
        Json::from(norito::json!({"val": "99"})),
    );
    let err =
        parse_prepared_trigger_call_execution_context(&metadata, &contract, &event_args, u64::MAX)
            .expect_err("fixed metadata payload must not shadow event arguments");
    assert!(matches!(
        err,
        ValidationFail::NotPermitted(message)
            if message.contains("triggering event")
    ));
}
#[test]
fn contract_entrypoint_authorization_accepts_direct_and_role_grants() {
    let authority = ALICE_ID.clone();
    let account = Account::new(authority.clone()).build(&authority);
    let world = World::with([], [account], []);
    let kura = Kura::blank_kura_for_testing();
    let query_handle = query::store::LiveQueryStore::start_test();
    let state = State::new(world, kura, query_handle);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut tx = block.transaction();
    let contract_address = ContractAddress::derive(
        &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
            .parse()
            .expect("canonical test network id"),
        &authority,
        91,
        DataSpaceId::UNIVERSAL,
    )
    .expect("derive contract address");
    let (artifact, manifest) = kotodama_lang::compiler::Compiler::new()
        .compile_source_with_manifest(
            r#"
seiyaku DispatchRoles {
  permission Admin;
  permission RoleAdmin;
  permission MalformedOnly;
  import permission "ContractOperations" as ContractOperations;
  import permission "CanTransferAsset" as AssetTransfer;
  kotoage fn admin() authorize(Admin) {}
  kotoage fn role_admin() authorize(RoleAdmin) {}
  kotoage fn malformed_only() authorize(MalformedOnly) {}
  kotoage fn custom_admin() authorize(ContractOperations) {}
  kotoage fn typed_import() authorize(AssetTransfer) {}
}
"#,
        )
        .expect("compile declared dispatch roles");
    let code_hash = ivm::contract_code_hash(&artifact);
    tx.world
        .contract_instances
        .insert(contract_address.clone(), code_hash);
    tx.world.contract_manifests.insert(
        iroha_data_model::smart_contract::ContractArtifactId::for_address(
            &contract_address,
            code_hash,
        )
        .unwrap(),
        manifest,
    );
    seed_owner_permission_contract(&mut tx, &contract_address, &authority, code_hash);
    let direct_context = contract_permission_context(contract_address.clone(), "admin", "Admin");
    let err = enforce_contract_entrypoint_authorization(&tx.world, &authority, &direct_context)
        .map_err(crate::execution_attempt::expect_completed_rejection)
        .expect_err("missing permission should reject contract entrypoint");
    assert!(
        matches!(
            err,
            ValidationFail::NotPermitted(ref message)
                if message.contains("requires its declared exact authorization")
        ),
        "unexpected authorization rejection: {err:?}"
    );
    let direct_permission: Permission =
        iroha_executor_data_model::permission::smart_contract::CanUseContractPermission {
            contract: contract_address.clone(),
            permission: "Admin".parse().unwrap(),
        }
        .into();
    Grant::account_permission(direct_permission, authority.clone())
        .execute(&authority, &mut tx)
        .expect("grant direct contract permission");
    enforce_contract_entrypoint_authorization(&tx.world, &authority, &direct_context)
        .expect("direct permission should allow contract entrypoint");
    let role_context =
        contract_permission_context(contract_address.clone(), "role_admin", "RoleAdmin");
    let role_id: RoleId = "contract_admin_role".parse().expect("role id");
    let role: iroha_data_model::role::NewRole = Role::new(role_id.clone(), authority.clone())
        .add_permission(Permission::from(
            iroha_executor_data_model::permission::smart_contract::CanUseContractPermission {
                contract: contract_address.clone(),
                permission: "RoleAdmin".parse().unwrap(),
            },
        ));
    Register::role(role)
        .execute(&authority, &mut tx)
        .expect("register contract role");
    enforce_contract_entrypoint_authorization(&tx.world, &authority, &role_context)
        .expect("role permission should allow contract entrypoint");
    for denied_context in [
        contract_permission_context(contract_address.clone(), "wrong_entrypoint", "Admin"),
        contract_permission_context(
            ContractAddress::derive(
                &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                    .parse()
                    .expect("canonical test network id"),
                &authority,
                92,
                DataSpaceId::UNIVERSAL,
            )
            .expect("derive distinct contract address"),
            "admin",
            "Admin",
        ),
    ] {
        enforce_contract_entrypoint_authorization(&tx.world, &authority, &denied_context)
            .expect_err("a grant for another contract or selector must fail closed");
    }
    let malformed_permission =
        Permission::new("CanUseContractPermission".to_owned(), Json::new(()));
    let staged_before = norito::to_bytes(
        &tx.world
            .account_permissions
            .iter()
            .map(|(account, permissions)| (account.clone(), permissions.clone()))
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let published = state
        .world
        .account_permissions
        .try_committed_view()
        .unwrap();
    let published_before = norito::to_bytes(&(
        published
            .current()
            .iter()
            .map(|(account, permissions)| (account.clone(), permissions.clone()))
            .collect::<Vec<_>>(),
        published
            .undo()
            .iter()
            .map(|(account, permissions)| (account.clone(), permissions.clone()))
            .collect::<Vec<_>>(),
    ))
    .unwrap();
    tx.world.take_external_events();
    let malformed_grant = super::Executor::Initial
        .execute_instruction(
            &mut tx,
            &authority,
            Grant::account_permission(malformed_permission.clone(), authority.clone()).into(),
        )
        .expect_err("native Grant rejects the recognized malformed permission before mutation");
    assert!(matches!(
        malformed_grant,
        ValidationFail::NotPermitted(message)
            if message.contains("Invalid permission payload")
    ));
    assert_eq!(
        norito::to_bytes(
            &tx.world
                .account_permissions
                .iter()
                .map(|(account, permissions)| (account.clone(), permissions.clone()))
                .collect::<Vec<_>>()
        )
        .unwrap(),
        staged_before
    );
    assert!(tx.world.take_external_events().is_empty());
    let after = state
        .world
        .account_permissions
        .try_committed_view()
        .unwrap();
    assert!(published.same_publication(&after));
    assert_eq!(
        norito::to_bytes(&(
            after
                .current()
                .iter()
                .map(|(account, permissions)| (account.clone(), permissions.clone()))
                .collect::<Vec<_>>(),
            after
                .undo()
                .iter()
                .map(|(account, permissions)| (account.clone(), permissions.clone()))
                .collect::<Vec<_>>(),
        ))
        .unwrap(),
        published_before
    );
    // Seed adversarial retained DATA to test the executor's independent authority boundary.
    tx.world
        .add_account_permission(&authority, malformed_permission);
    let malformed_only =
        contract_permission_context(contract_address.clone(), "malformed_only", "MalformedOnly");
    enforce_contract_entrypoint_authorization(&tx.world, &authority, &malformed_only)
        .expect_err("a name-only permission must never bypass exact payload matching");
    let custom_name = "ContractOperations";
    let noncanonical_custom = Permission::new(
        custom_name.to_owned(),
        Json::from(norito::json!({ "scope": "different-contract" })),
    );
    Grant::account_permission(noncanonical_custom.clone(), authority.clone())
        .execute(&authority, &mut tx)
        .expect("store same-name custom permission with a noncanonical payload");
    enforce_named_contract_entrypoint_authorization(
        &tx.world,
        &authority,
        &contract_address,
        "custom_admin",
        &EntrypointAuthorizationV1::Permission(custom_name.parse().unwrap()),
    )
    .expect_err("a same-name custom payload must not authorize an entrypoint");
    Revoke::account_permission(noncanonical_custom, authority.clone())
        .execute(&authority, &mut tx)
        .expect("remove noncanonical custom permission");
    Grant::account_permission(
        Permission::new(custom_name.to_owned(), Json::new(())),
        authority.clone(),
    )
    .execute(&authority, &mut tx)
    .expect("grant canonical custom entrypoint permission");
    enforce_named_contract_entrypoint_authorization(
        &tx.world,
        &authority,
        &contract_address,
        "custom_admin",
        &EntrypointAuthorizationV1::Permission(custom_name.parse().unwrap()),
    )
    .expect("the exact empty-payload custom permission must authorize its marker");
    let imported_asset = AssetId::of(
        AssetDefinitionId::derive_from_components(
            DomainId::try_new("sharedrole", "universal").unwrap(),
            "coin".parse().unwrap(),
        ),
        authority.clone(),
    );
    let typed_transfer: Permission = executor_permission::asset::CanTransferAsset {
        asset: imported_asset,
    }
    .into();
    tx.world.add_account_permission(&authority, typed_transfer);
    enforce_named_contract_entrypoint_authorization(
        &tx.world,
        &authority,
        &contract_address,
        "typed_import",
        &EntrypointAuthorizationV1::Permission("AssetTransfer".parse().unwrap()),
    )
    .expect_err("an imported marker never consumes a typed ledger permission payload");
}
fn generate_denied_program(message: &str) -> Vec<u8> {
    let verdict = Err(iroha_data_model::ValidationFail::NotPermitted(
        message.to_owned(),
    ));
    generate_verdict_program(&verdict)
}
#[test]
fn execute_instruction_with_ivm() {
    fn read_default_bytecode() -> Option<Vec<u8>> {
        std::env::var_os("IROHA_TEST_USE_DEFAULT_EXECUTOR")?;
        let path1 =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../defaults/executor.to");
        if let Ok(b) = std::fs::read(&path1) {
            return Some(b);
        }
        if let Ok(b) = std::fs::read("defaults/executor.to") {
            return Some(b);
        }
        None
    }
    let bytecode = read_default_bytecode().unwrap_or_else(generate_ok_program);
    let raw = data_model_executor::Executor::new(IvmBytecode::from_compiled(bytecode));
    let executor = super::Executor::UserProvided(super::LoadedExecutor::load(raw).expect("load"));
    let wonderland_domain_id: DomainId =
        DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain: Domain = Domain::new(wonderland_domain_id.clone()).build(&ALICE_ID);
    let alice_account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
    let world = World::with([domain], [alice_account], []);
    let kura = Kura::blank_kura_for_testing();
    let query_handle = query::store::LiveQueryStore::start_test();
    let state = State::new_with_chain(
        component_world_for_testing(world),
        kura,
        query_handle,
        ChainId::from("test-chain"),
    );
    let block_header = BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    let mut block = state.block(block_header);
    let mut state_tx = block.transaction();
    let domain_id: DomainId = DomainId::try_new("test", "universal").expect("domain id");
    let instruction = Register::domain(Domain::new(domain_id.clone())).into();
    executor
        .execute_instruction(&mut state_tx, &ALICE_ID.clone(), instruction)
        .expect("execution");
    assert!(state_tx.world.domains.get(&domain_id).is_some());
}
#[test]
fn loaded_executor_stack_limit_tracks_gas_limit() {
    let bytecode = generate_ok_program();
    let raw = data_model_executor::Executor::new(IvmBytecode::from_compiled(bytecode));
    let loaded = super::LoadedExecutor::load(raw).expect("load");
    let small_limit = 10_000;
    let large_limit = 50_000;
    {
        let vm_small = loaded
            .checkout_runtime_for_gas_limit(
                small_limit,
                Memory::HEAP_MAX_SIZE,
                &executor_test_budget(),
            )
            .expect("checkout small");
        assert_eq!(
            vm_small.memory.stack_limit(),
            super::stack_limit_for_gas(small_limit)
        );
        assert_eq!(vm_small.remaining_gas(), small_limit);
    }
    {
        let vm_large = loaded
            .checkout_runtime_for_gas_limit(
                large_limit,
                Memory::HEAP_MAX_SIZE,
                &executor_test_budget(),
            )
            .expect("checkout large");
        assert_eq!(
            vm_large.memory.stack_limit(),
            super::stack_limit_for_gas(large_limit)
        );
        assert_eq!(vm_large.remaining_gas(), large_limit);
    }
}
#[test]
fn loaded_executor_runtime_tracks_governed_heap_limit() {
    if executor_cache_test_in_child("loaded_executor_runtime_tracks_governed_heap_limit") {
        return;
    }
    const GAS_LIMIT: u64 = 10_000;
    const SMALL_HEAP_LIMIT: u64 = 64;
    const LARGE_HEAP_LIMIT: u64 = 128;
    let raw = data_model_executor::Executor::new(IvmBytecode::from_compiled(generate_ok_program()));
    let loaded = super::LoadedExecutor::load(raw).expect("load");
    // Static admission creates no eager default VM; both governed variants are funded below.
    {
        let mut runtime = loaded
            .checkout_runtime_for_gas_limit(GAS_LIMIT, SMALL_HEAP_LIMIT, &executor_test_budget())
            .expect("small heap runtime");
        assert_eq!(runtime.memory.heap_max_limit(), SMALL_HEAP_LIMIT);
        assert_eq!(
            runtime.memory.alloc(SMALL_HEAP_LIMIT + 8),
            Err(VMError::OutOfMemory)
        );
    }
    {
        let runtime = loaded
            .checkout_runtime_for_gas_limit(GAS_LIMIT, LARGE_HEAP_LIMIT, &executor_test_budget())
            .expect("large heap runtime");
        assert_eq!(runtime.memory.heap_max_limit(), LARGE_HEAP_LIMIT);
    }
    let (after_distinct_limits, _) = loaded.runtime_pool_snapshot();
    let runtime = loaded
        .checkout_runtime_for_gas_limit(GAS_LIMIT, SMALL_HEAP_LIMIT, &executor_test_budget())
        .expect("warm small heap runtime");
    assert_eq!(runtime.memory.heap_max_limit(), SMALL_HEAP_LIMIT);
    drop(runtime);
    let (after_reuse, _) = loaded.runtime_pool_snapshot();
    assert_eq!(after_reuse.hits, after_distinct_limits.hits + 1);
}
#[test]
fn loaded_executor_reuses_and_resets_runtime_after_error_return() {
    if executor_cache_test_in_child("loaded_executor_reuses_and_resets_runtime_after_error_return")
    {
        return;
    }
    const GAS_LIMIT: u64 = 10_000;
    // Retention assertions own the default cache configuration for this scope;
    // concurrent State fixtures may otherwise legitimately disable retention.
    let _cache_limits = ivm::ivm_cache::CacheLimitsGuard::new(ivm::ivm_cache::CacheLimits {
        capacity: iroha_config::parameters::defaults::pipeline::CACHE_SIZE,
        max_bytes: iroha_config::parameters::defaults::pipeline::IVM_CACHE_MAX_BYTES,
        max_decoded_ops: iroha_config::parameters::defaults::pipeline::IVM_CACHE_MAX_DECODED_OPS,
    });
    fn dirty_then_fail(loaded: &super::LoadedExecutor) -> Result<(), *const u8> {
        let mut runtime = loaded
            .checkout_runtime_for_gas_limit(
                GAS_LIMIT,
                Memory::HEAP_MAX_SIZE,
                &executor_test_budget(),
            )
            .expect("checkout runtime");
        let allocation = runtime
            .memory
            .load_region(0, 1)
            .expect("code memory")
            .as_ptr();
        runtime.set_register(7, 99);
        runtime
            .memory
            .preload_input(0, &[0xA5])
            .expect("dirty input memory");
        Err(allocation)
    }
    let raw = data_model_executor::Executor::new(IvmBytecode::from_compiled(generate_ok_program()));
    let loaded = super::LoadedExecutor::load(raw).expect("load");
    drop(
        loaded
            .checkout_runtime_for_gas_limit(
                GAS_LIMIT,
                Memory::HEAP_MAX_SIZE,
                &executor_test_budget(),
            )
            .expect("warm bounded-stack executor runtime"),
    );
    let (before, _) = loaded.runtime_pool_snapshot();
    let allocation = dirty_then_fail(&loaded).expect_err("synthetic validation failure");
    let (after_error, variants) = loaded.runtime_pool_snapshot();
    assert_eq!(
        variants, 1,
        "only the measured runtime geometry is retained"
    );
    assert_eq!(
        after_error.dirty_resets,
        before.dirty_resets + 1,
        "runtime retention: {:?}",
        ivm::cache_memory::memory_stats()
    );
    let runtime = loaded
        .checkout_runtime_for_gas_limit(GAS_LIMIT, Memory::HEAP_MAX_SIZE, &executor_test_budget())
        .expect("warm checkout");
    assert_eq!(runtime.register(7), 0);
    assert_eq!(runtime.remaining_gas(), GAS_LIMIT);
    assert_eq!(
        runtime
            .memory
            .load_region(0, 1)
            .expect("code memory")
            .as_ptr(),
        allocation,
        "warm executor validation must reuse the same memory allocation"
    );
    assert_eq!(
        runtime
            .memory
            .load_region(Memory::INPUT_START, 1)
            .expect("input memory"),
        &[0],
        "dirty input must be restored before reuse"
    );
    let (after_reuse, _) = loaded.runtime_pool_snapshot();
    assert_eq!(after_reuse.hits, after_error.hits + 1);
    assert_eq!(after_reuse.program_loads, after_error.program_loads);
    assert_eq!(after_reuse.template_builds, after_error.template_builds);
}
#[test]
fn loaded_executor_runtime_variants_are_bounded() {
    let raw = data_model_executor::Executor::new(IvmBytecode::from_compiled(generate_ok_program()));
    let loaded = super::LoadedExecutor::load(raw).expect("load");
    let capacity = loaded.runtime_variant_capacity();
    let (before, _) = loaded.runtime_pool_snapshot();
    let policy = ivm::IvmStackPolicy::V1;
    let multiplier = policy.bytes_per_gas();
    let mut observed_keys = BTreeSet::new();
    for index in 0..capacity.saturating_add(3) {
        let target_stack = policy
            .minimum_stack_bytes()
            .saturating_mul(u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1));
        let gas_limit = target_stack.saturating_add(multiplier.saturating_sub(1)) / multiplier;
        let key = super::ExecutorRuntimeKey::for_limits(gas_limit, Memory::HEAP_MAX_SIZE);
        assert!(
            observed_keys.insert(key),
            "test gas limits must resolve to distinct stack variants"
        );
        let runtime = loaded
            .checkout_runtime_for_gas_limit(
                gas_limit,
                Memory::HEAP_MAX_SIZE,
                &executor_test_budget(),
            )
            .expect("checkout gas/stack variant");
        assert_eq!(runtime.memory.stack_limit(), key.stack_limit);
    }
    let (after, variant_count) = loaded.runtime_pool_snapshot();
    assert_eq!(variant_count, capacity);
    assert!(after.evictions > before.evictions);
}
#[test]
fn execute_transaction_rejects_authority_argument_mismatch() {
    let domain_id = DomainId::try_new("wonderland", "universal").expect("valid fixture domain");
    let world = World::with(
        [Domain::new(domain_id).build(&ALICE_ID)],
        [Account::new(ALICE_ID.clone()).build(&ALICE_ID)],
        [],
    );
    let state = State::new_with_chain(
        component_world_for_testing(world),
        Kura::blank_kura_for_testing(),
        query::store::LiveQueryStore::start_test(),
        ChainId::from("authority-binding"),
    );
    let mut block = state.block(BlockHeader::new(nonzero!(2_u64), None, None, 0, 0));
    let transaction = TransactionBuilder::new(
        state.network_id,
        ALICE_ID.clone(),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "authority binding".to_owned())])
    .sign(ALICE_KEYPAIR.private_key());
    let mut state_transaction = block
        .transaction_for_fastpq_testing(iroha_crypto::Hash::from(transaction.hash_as_entrypoint()));
    state_transaction.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
    state_transaction.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
    let mut ivm_cache = IvmCache::new();
    let error = super::Executor::Initial
        .execute_transaction(&mut state_transaction, &BOB_ID, transaction, &mut ivm_cache)
        .map_err(crate::execution_attempt::expect_completed_rejection)
        .expect_err("the call-site authority must match the signed transaction");
    assert!(matches!(error, ValidationFail::InternalError(message) if
        message == "signed authority mismatch"));
    assert_eq!(
        state_transaction.last_tx_gas_used, 0,
        "a mismatched authority must fail before execution or fee accounting"
    );
}
#[test]
fn transaction_metadata_cannot_change_governed_executor_fuel_budget() {
    let bytecode = generate_ok_program();
    let raw = data_model_executor::Executor::new(IvmBytecode::from_compiled(bytecode));
    let user_executor =
        super::Executor::UserProvided(super::LoadedExecutor::load(raw).expect("load"));
    for (executor_name, executor) in [
        ("initial", super::Executor::Initial),
        ("user-provided", user_executor),
    ] {
        let wonderland_domain_id: DomainId =
            DomainId::try_new("wonderland", "universal").expect("domain id");
        let domain: Domain = Domain::new(wonderland_domain_id).build(&ALICE_ID);
        let alice_account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
        let world = World::with([domain], [alice_account], []);
        let kura = Kura::blank_kura_for_testing();
        let query_handle = query::store::LiveQueryStore::start_test();
        let state = State::new_with_chain(
            component_world_for_testing(world),
            kura,
            query_handle,
            ChainId::from("test-chain"),
        );
        let block_header = BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
        let mut block = state.block(block_header);
        let mut metadata = Metadata::default();
        metadata.insert(
            Name::from_str("additional_fuel").expect("static name"),
            Json::new(u64::MAX),
        );
        let tx = TransactionBuilder::new(
            state.network_id,
            ALICE_ID.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_metadata(metadata)
        .with_executable(Executable::Instructions(Vec::new().into()))
        .sign(ALICE_KEYPAIR.private_key());
        let mut state_tx =
            block.transaction_for_fastpq_testing(iroha_crypto::Hash::from(tx.hash_as_entrypoint()));
        state_tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        state_tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        *state_tx.world.executor.get_mut() = executor;
        let governed_fuel = state_tx.world.parameters.get().executor().fuel.get();
        assert_eq!(
            state_tx.executor_fuel_remaining, governed_fuel,
            "{executor_name} transaction must start with the governed fuel budget"
        );
        let mut ivm_cache = crate::smartcontracts::ivm::cache::IvmCache::new();
        let executor = state_tx.world.executor.clone();
        executor
            .execute_transaction(&mut state_tx, &ALICE_ID, tx, &mut ivm_cache)
            .map_err(crate::execution_attempt::expect_completed_rejection)
            .expect("ordinary metadata must not reject execution");
        assert_eq!(
            state_tx.executor_fuel_remaining, governed_fuel,
            "{executor_name} transaction metadata must not alter the governed fuel budget"
        );
    }
}
#[test]
fn executor_validation_consumes_fuel_budget() {
    let bytecode = generate_ok_program();
    let raw = data_model_executor::Executor::new(IvmBytecode::from_compiled(bytecode));
    let executor = super::Executor::UserProvided(super::LoadedExecutor::load(raw).expect("load"));
    let wonderland_domain_id: DomainId =
        DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain: Domain = Domain::new(wonderland_domain_id.clone()).build(&ALICE_ID);
    let alice_account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
    let world = World::with([domain], [alice_account], []);
    let kura = Kura::blank_kura_for_testing();
    let query_handle = query::store::LiveQueryStore::start_test();
    let state = State::new_with_chain(
        component_world_for_testing(world),
        kura,
        query_handle,
        ChainId::from("test-chain"),
    );
    let block_header = BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    let mut block = state.block(block_header);
    let mut state_tx = block.transaction();
    let base_fuel = state_tx.world.parameters.get().executor().fuel.get();
    let instruction: InstructionBox = Log::new(Level::INFO, "executor fuel".to_owned()).into();
    executor
        .execute_instruction(&mut state_tx, &ALICE_ID.clone(), instruction)
        .expect("execution");
    let remaining = state_tx.executor_fuel_remaining;
    assert!(
        remaining < base_fuel,
        "expected executor fuel budget to decrease"
    );
}
#[test]
fn executor_validation_rejects_when_budget_exhausted() {
    let bytecode = generate_ok_program();
    let raw = data_model_executor::Executor::new(IvmBytecode::from_compiled(bytecode));
    let executor = super::Executor::UserProvided(super::LoadedExecutor::load(raw).expect("load"));
    let world = World::new();
    let kura = Kura::blank_kura_for_testing();
    let query_handle = query::store::LiveQueryStore::start_test();
    let state = State::new_with_chain(
        component_world_for_testing(world),
        kura,
        query_handle,
        ChainId::from("test-chain"),
    );
    let block_header = BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    let mut block = state.block(block_header);
    let mut state_tx = block.transaction();
    state_tx.executor_fuel_remaining = 0;
    let instruction: InstructionBox = Log::new(Level::INFO, "executor fuel".to_owned()).into();
    let err = executor
        .execute_instruction(&mut state_tx, &ALICE_ID.clone(), instruction)
        .expect_err("expected fuel exhaustion");
    assert!(
        matches!(err, ValidationFail::TooComplex),
        "unexpected error: {err:?}"
    );
}
fn native_find_accounts_request() -> QueryRequest {
    use iroha_data_model::query::{
        QueryBox, QueryWithParams,
        account::prelude::FindAccounts,
        dsl::{CompoundPredicate, SelectorTuple},
        parameters::QueryParams,
    };
    let query: QueryBox<_> = Box::new(iroha_data_model::query::ErasedIterQuery::<Account>::new(
        CompoundPredicate::PASS,
        SelectorTuple::default(),
        norito::codec::Encode::encode(&FindAccounts),
    ));
    let query = QueryWithParams::new(&query, QueryParams::default())
        .expect("account query type has a canonical mapping");
    QueryRequest::Start(query)
}
fn native_find_permissions_request_with_payload(payload: Vec<u8>) -> QueryRequest {
    use iroha_data_model::query::{
        QueryBox, QueryWithParams,
        dsl::{CompoundPredicate, SelectorTuple},
        parameters::QueryParams,
    };
    let query: QueryBox<_> = Box::new(iroha_data_model::query::ErasedIterQuery::<Permission>::new(
        CompoundPredicate::PASS,
        SelectorTuple::default(),
        payload,
    ));
    let query = QueryWithParams::new(&query, QueryParams::default())
        .expect("permission query type has a canonical mapping");
    QueryRequest::Start(query)
}
fn native_find_permissions_request(account: AccountId) -> QueryRequest {
    native_find_permissions_request_with_payload(norito::codec::Encode::encode(
        &iroha_data_model::query::permission::prelude::FindPermissionsByAccountId::new(account),
    ))
}
fn validate_native_query_with_world(
    executor: &super::Executor,
    world: &World,
    authority: &AccountId,
    query: &QueryRequest,
) -> Result<(), ValidationFail> {
    let world_view = world.view();
    executor
        .validate_query_with_world_parts(
            &world_view,
            None,
            authority,
            query,
            &executor_test_budget(),
        )
        .map_err(|error| match error {
            crate::execution_attempt::ExecutionAttemptError::Rejected(error) => error,
            crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                panic!("query fixture unexpectedly deferred: {reason}")
            }
        })
}
fn remove_committed_storage_entry<K: mv::Key, V: mv::Value>(
    storage: &mv::storage::Storage<K, V>,
    key: K,
) -> Option<V> {
    let mut block = storage.block();
    let removed = block.remove(key);
    block.commit();
    removed
}
#[test]
fn native_query_boundary_requires_registered_authority_for_every_executor() {
    let public_query = QueryRequest::Singular(SingularQueryBox::FindParameters(FindParameters));
    let initial = super::Executor::Initial;
    let allow_all = super::Executor::UserProvided(
        super::LoadedExecutor::load(data_model_executor::Executor::new(
            IvmBytecode::from_compiled(generate_ok_program()),
        ))
        .expect("load allow-all executor"),
    );
    let empty_world = World::new();
    for executor in [&initial, &allow_all] {
        let error =
            validate_native_query_with_world(executor, &empty_world, &ALICE_ID, &public_query)
                .expect_err("an unregistered query authority must fail closed");
        assert!(matches!(error, ValidationFail::NotPermitted(message)
            if message.contains("not a registered account")));
    }
    let registered_world = World::with([], [Account::new(ALICE_ID.clone()).build(&ALICE_ID)], []);
    validate_native_query_with_world(&initial, &registered_world, &ALICE_ID, &public_query)
        .expect("registered accounts may use public queries");
    validate_native_query_with_world(&allow_all, &registered_world, &ALICE_ID, &public_query)
        .expect("the shared native boundary must also admit a registered IVM caller");
    let error = validate_native_query_with_world(
        &allow_all,
        &registered_world,
        &ALICE_ID,
        &native_find_accounts_request(),
    )
    .expect_err("an allow-all custom executor must not widen native ledger access");
    assert!(matches!(error, ValidationFail::NotPermitted(message)
        if message.contains("CanReadAllLedgerData")));
}
#[test]
fn native_global_query_requires_exact_direct_or_assigned_role_grant() {
    let mut world = World::with(
        [],
        [
            Account::new(ALICE_ID.clone()).build(&ALICE_ID),
            Account::new(BOB_ID.clone()).build(&BOB_ID),
        ],
        [],
    );
    let query = native_find_accounts_request();
    let executor = super::Executor::Initial;
    let exact: Permission = executor_permission::query::CanReadAllLedgerData.into();
    validate_native_query_with_world(&executor, &world, &ALICE_ID, &query)
        .expect_err("the account roster must not be public");
    world.account_permissions.insert(
        ALICE_ID.clone(),
        BTreeSet::from([Permission::new(
            "CanReadAllLedgerData".to_owned(),
            Json::new("wrong-payload"),
        )]),
    );
    validate_native_query_with_world(&executor, &world, &ALICE_ID, &query)
        .expect_err("same-name malformed grants must fail closed");
    world
        .account_permissions
        .insert(ALICE_ID.clone(), BTreeSet::from([exact.clone()]));
    validate_native_query_with_world(&executor, &world, &ALICE_ID, &query)
        .expect("the exact direct root must authorize a global query");
    assert!(
        remove_committed_storage_entry(&world.account_permissions, ALICE_ID.clone()).is_some(),
        "the direct global-read grant must exist before revocation"
    );
    validate_native_query_with_world(&executor, &world, &ALICE_ID, &query)
        .expect_err("revoking the direct root must revoke access");
    let role_id: RoleId = "native_global_reader".parse().expect("role id");
    world.roles.insert(
        role_id.clone(),
        Role {
            id: role_id.clone(),
            permissions: BTreeSet::from([exact]),
            permission_epochs: BTreeMap::new(),
        },
    );
    world.grant_role_for_tests(ALICE_ID.clone(), role_id.clone());
    validate_native_query_with_world(&executor, &world, &ALICE_ID, &query)
        .expect("an assigned role carrying the exact root must authorize the query");
    assert!(
        remove_committed_storage_entry(
            &world.account_roles,
            crate::role::RoleIdWithOwner::new(ALICE_ID.clone(), role_id),
        )
        .is_some(),
        "the global-reader role assignment must exist before revocation"
    );
    validate_native_query_with_world(&executor, &world, &ALICE_ID, &query)
        .expect_err("revoking role membership must revoke global access");
}
#[test]
fn native_account_query_is_self_scoped_and_exact_payload_bound() {
    let mut world = World::with(
        [],
        [
            Account::new(ALICE_ID.clone()).build(&ALICE_ID),
            Account::new(BOB_ID.clone()).build(&BOB_ID),
        ],
        [],
    );
    let executor = super::Executor::Initial;
    let self_query = QueryRequest::Singular(
        iroha_data_model::query::account::prelude::FindAccountById::new(ALICE_ID.clone()).into(),
    );
    let bob_query = native_find_permissions_request(BOB_ID.clone());
    let exact: Permission = executor_permission::query::CanReadAccountData {
        account: BOB_ID.clone(),
    }
    .into();
    validate_native_query_with_world(&executor, &world, &ALICE_ID, &self_query)
        .expect("an account may read its own private data");
    validate_native_query_with_world(&executor, &world, &ALICE_ID, &bob_query)
        .expect_err("foreign account data requires an exact grant");
    world.account_permissions.insert(
        ALICE_ID.clone(),
        BTreeSet::from([
            executor_permission::query::CanReadAccountData {
                account: ALICE_ID.clone(),
            }
            .into(),
            Permission::new("CanReadAccountData".to_owned(), Json::new(())),
        ]),
    );
    validate_native_query_with_world(&executor, &world, &ALICE_ID, &bob_query)
        .expect_err("wrong-target and malformed grants must not authorize Bob's data");
    world
        .account_permissions
        .insert(ALICE_ID.clone(), BTreeSet::from([exact.clone()]));
    validate_native_query_with_world(&executor, &world, &ALICE_ID, &bob_query)
        .expect("the exact direct grant must authorize Bob's data");
    assert!(
        remove_committed_storage_entry(&world.account_permissions, ALICE_ID.clone()).is_some(),
        "the direct account-read grant must exist before revocation"
    );
    validate_native_query_with_world(&executor, &world, &ALICE_ID, &bob_query)
        .expect_err("revoking the exact grant must revoke account access");
    let role_id: RoleId = "native_account_reader".parse().expect("role id");
    world.roles.insert(
        role_id.clone(),
        Role {
            id: role_id.clone(),
            permissions: BTreeSet::from([exact]),
            permission_epochs: BTreeMap::new(),
        },
    );
    world.grant_role_for_tests(ALICE_ID.clone(), role_id.clone());
    validate_native_query_with_world(&executor, &world, &ALICE_ID, &bob_query)
        .expect("an assigned exact role grant must authorize Bob's data");
    assert!(
        remove_committed_storage_entry(
            &world.account_roles,
            crate::role::RoleIdWithOwner::new(ALICE_ID.clone(), role_id),
        )
        .is_some(),
        "the account-reader role assignment must exist before revocation"
    );
    let mut malformed_payload = norito::codec::Encode::encode(
        &iroha_data_model::query::permission::prelude::FindPermissionsByAccountId::new(
            BOB_ID.clone(),
        ),
    );
    malformed_payload.push(0xA5);
    let malformed_query = native_find_permissions_request_with_payload(malformed_payload);
    world.account_permissions.insert(
        ALICE_ID.clone(),
        BTreeSet::from([executor_permission::query::CanReadAllLedgerData.into()]),
    );
    let error = validate_native_query_with_world(&executor, &world, &ALICE_ID, &malformed_query)
        .expect_err("a malformed iterable carrier must fail before permission lookup");
    assert!(matches!(error, ValidationFail::NotPermitted(message)
        if message.contains("malformed") || message.contains("authorization matrix")));
    validate_native_query_with_world(&executor, &world, &ALICE_ID, &bob_query)
        .expect("the global read root must override an account-scoped grant");
}
#[test]
fn validate_query_with_ivm() {
    let bytecode = read_default_bytecode().unwrap_or_else(generate_ok_program);
    let raw = data_model_executor::Executor::new(IvmBytecode::from_compiled(bytecode));
    let executor = super::Executor::UserProvided(super::LoadedExecutor::load(raw).expect("load"));
    let world = World::with([], [Account::new(ALICE_ID.clone()).build(&ALICE_ID)], []);
    let kura = Kura::blank_kura_for_testing();
    let query_handle = query::store::LiveQueryStore::start_test();
    let state = State::new_with_chain(world, kura, query_handle, ChainId::from("test-chain"));
    let block_header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(block_header);
    let state_tx = block.transaction();
    let query = QueryRequest::Singular(SingularQueryBox::FindParameters(FindParameters));
    executor
        .validate_query(&state_tx, &ALICE_ID.clone(), &query)
        .expect("validation");
}
#[test]
fn initial_executor_mirrors_default_private_query_permissions() {
    use iroha_data_model::query::sorafs::prelude::{
        FindSorafsModerationEvents, FindSorafsModerationJurorEligibility,
        FindSorafsModerationSnapshot, FindSorafsOrderbookPolicy,
        FindSorafsReputationJournalAuthorityPolicy, FindSorafsReputationJournalEventBySourceId,
        FindSorafsReserveEvents,
    };
    let alice_account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
    let bob_account = Account::new(BOB_ID.clone()).build(&BOB_ID);
    let world = World::with([], [alice_account, bob_account], []);
    let latest_block = BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    let state = State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        query::store::LiveQueryStore::start_test(),
    );
    let mut block = state.block(latest_block.clone());
    let mut state_transaction = block.transaction();
    let executor = super::Executor::Initial;
    let orderbook = QueryRequest::Singular(FindSorafsOrderbookPolicy.into());
    let reserve_events =
        QueryRequest::Singular(FindSorafsReserveEvents::new(None, None, 16).into());
    let reputation_policy =
        QueryRequest::Singular(FindSorafsReputationJournalAuthorityPolicy.into());
    let reputation_event = QueryRequest::Singular(
        FindSorafsReputationJournalEventBySourceId::new(
            iroha_data_model::sorafs::reputation::ReputationJournalSourceIdV1([0x43; 32]),
            None,
        )
        .into(),
    );
    let own_eligibility = QueryRequest::Singular(
        FindSorafsModerationJurorEligibility::new(
            "case-1".to_owned(),
            "round-1".to_owned(),
            ALICE_ID.clone(),
        )
        .into(),
    );
    let foreign_eligibility = QueryRequest::Singular(
        FindSorafsModerationJurorEligibility::new(
            "case-1".to_owned(),
            "round-1".to_owned(),
            BOB_ID.clone(),
        )
        .into(),
    );
    let moderation_snapshot =
        QueryRequest::Singular(FindSorafsModerationSnapshot::new(8, 16).into());
    let moderation_events = QueryRequest::Singular(
        FindSorafsModerationEvents::new(
            iroha_data_model::sorafs::moderation_ledger::ModerationFinalizedCursorV1 {
                height: 1,
                block_hash: [0x42; 32],
            },
            None,
            16,
        )
        .into(),
    );
    let orderbook_error = executor
        .validate_query_with_world_parts(
            &state_transaction.world,
            Some(latest_block.clone()),
            &ALICE_ID,
            &orderbook,
            &executor_test_budget(),
        )
        .expect_err("orderbook state must not be public under the Initial executor");
    assert!(matches!(
        orderbook_error,
        crate::execution_attempt::ExecutionAttemptError::Rejected(ValidationFail::NotPermitted(_))
    ));
    let reserve_error = executor
        .validate_query_with_world_parts(
            &state_transaction.world,
            Some(latest_block.clone()),
            &ALICE_ID,
            &reserve_events,
            &executor_test_budget(),
        )
        .expect_err("reserve committed events must remain governance-readable");
    assert!(matches!(
        reserve_error,
        crate::execution_attempt::ExecutionAttemptError::Rejected(ValidationFail::NotPermitted(_))
    ));
    let reputation_policy_error = executor
        .validate_query_with_world_parts(
            &state_transaction.world,
            Some(latest_block.clone()),
            &ALICE_ID,
            &reputation_policy,
            &executor_test_budget(),
        )
        .expect_err("reputation authority policy must remain operator-readable");
    assert!(matches!(
        reputation_policy_error,
        crate::execution_attempt::ExecutionAttemptError::Rejected(ValidationFail::NotPermitted(_))
    ));
    executor
        .validate_query_with_world_parts(
            &state_transaction.world,
            Some(latest_block.clone()),
            &ALICE_ID,
            &reputation_event,
            &executor_test_budget(),
        )
        .expect("payload-free finalized reputation events must remain public");
    executor
        .validate_query_with_world_parts(
            &state_transaction.world,
            Some(latest_block.clone()),
            &ALICE_ID,
            &own_eligibility,
            &executor_test_budget(),
        )
        .expect("a juror must be able to read their own eligibility");
    let eligibility_error = executor
        .validate_query_with_world_parts(
            &state_transaction.world,
            Some(latest_block.clone()),
            &ALICE_ID,
            &foreign_eligibility,
            &executor_test_budget(),
        )
        .expect_err("another juror's eligibility must remain private");
    assert!(matches!(
        eligibility_error,
        crate::execution_attempt::ExecutionAttemptError::Rejected(ValidationFail::NotPermitted(_))
    ));
    let snapshot_error = executor
        .validate_query_with_world_parts(
            &state_transaction.world,
            Some(latest_block.clone()),
            &ALICE_ID,
            &moderation_snapshot,
            &executor_test_budget(),
        )
        .expect_err("complete moderation snapshots must remain private");
    assert!(matches!(
        snapshot_error,
        crate::execution_attempt::ExecutionAttemptError::Rejected(ValidationFail::NotPermitted(_))
    ));
    executor
        .validate_query_with_world_parts(
            &state_transaction.world,
            Some(latest_block.clone()),
            &ALICE_ID,
            &moderation_events,
            &executor_test_budget(),
        )
        .expect("payload-free committed moderation events must remain public");
    state_transaction.world.account_permissions.insert(
        ALICE_ID.clone(),
        BTreeSet::from([
            Permission::from(executor_permission::sorafs::CanSetSorafsPricing),
            Permission::from(executor_permission::sorafs::CanSetSorafsReservePolicy),
            Permission::from(executor_permission::sorafs::CanManageSorafsReputationJournalPolicy),
            Permission::from(executor_permission::sorafs::CanRecordSorafsReputationJournal),
            Permission::from(executor_permission::sorafs::CanResolveSorafsCapacityDispute),
            Permission::from(executor_permission::sorafs::CanManageSorafsModeration),
        ]),
    );
    executor
        .validate_query_with_world_parts(
            &state_transaction.world,
            Some(latest_block.clone()),
            &ALICE_ID,
            &orderbook,
            &executor_test_budget(),
        )
        .expect("pricing operators must be able to read orderbook state");
    executor
        .validate_query_with_world_parts(
            &state_transaction.world,
            Some(latest_block.clone()),
            &ALICE_ID,
            &reserve_events,
            &executor_test_budget(),
        )
        .expect("reserve governors must be able to read committed reserve events");
    executor
        .validate_query_with_world_parts(
            &state_transaction.world,
            Some(latest_block.clone()),
            &ALICE_ID,
            &reputation_policy,
            &executor_test_budget(),
        )
        .expect("reputation policy managers must be able to read the active authority policy");
    executor
        .validate_query_with_world_parts(
            &state_transaction.world,
            Some(latest_block.clone()),
            &ALICE_ID,
            &foreign_eligibility,
            &executor_test_budget(),
        )
        .expect("moderation managers must be able to read juror eligibility");
    executor
        .validate_query_with_world_parts(
            &state_transaction.world,
            Some(latest_block),
            &ALICE_ID,
            &moderation_snapshot,
            &executor_test_budget(),
        )
        .expect("moderation managers must be able to read complete snapshots");
    let public_query = QueryRequest::Singular(SingularQueryBox::FindParameters(FindParameters));
    executor
        .validate_query_with_world_parts(
            &state_transaction.world,
            None,
            &ALICE_ID,
            &public_query,
            &executor_test_budget(),
        )
        .expect("standard public queries must remain available");
}
#[test]
fn validate_start_query_with_ivm() {
    use iroha_data_model::query::{
        QueryItemKind, QueryWithParams,
        dsl::{CompoundPredicate, SelectorTuple},
        parameters::QueryParams,
    };
    let bytecode = read_default_bytecode().unwrap_or_else(generate_ok_program);
    let raw = data_model_executor::Executor::new(IvmBytecode::from_compiled(bytecode));
    let executor = super::Executor::UserProvided(super::LoadedExecutor::load(raw).expect("load"));
    let world = World::with([], [Account::new(ALICE_ID.clone()).build(&ALICE_ID)], []);
    let kura = Kura::blank_kura_for_testing();
    let query_handle = query::store::LiveQueryStore::start_test();
    let state = State::new_with_chain(world, kura, query_handle, ChainId::from("test-chain"));
    let block_header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(block_header);
    let state_tx = block.transaction();
    let iter_query = QueryWithParams {
        query: (),
        query_payload: norito::codec::Encode::encode(
            &iroha_data_model::query::domain::prelude::FindDomains,
        ),
        item: QueryItemKind::Domain,
        predicate_bytes: norito::codec::Encode::encode(&CompoundPredicate::<Domain>::PASS),
        selector_bytes: norito::codec::Encode::encode(&SelectorTuple::<Domain>::default()),
        params: QueryParams::default(),
    };
    let query = QueryRequest::Start(iter_query);
    executor
        .validate_query(&state_tx, &ALICE_ID.clone(), &query)
        .expect("validation");
}
#[test]
fn validate_query_rejected_by_executor() {
    let bytecode = generate_denied_program("queries disabled");
    let raw = data_model_executor::Executor::new(IvmBytecode::from_compiled(bytecode));
    let executor = super::Executor::UserProvided(super::LoadedExecutor::load(raw).expect("load"));
    let world = World::with([], [Account::new(ALICE_ID.clone()).build(&ALICE_ID)], []);
    let kura = Kura::blank_kura_for_testing();
    let query_handle = query::store::LiveQueryStore::start_test();
    let state = State::new_with_chain(world, kura, query_handle, ChainId::from("test-chain"));
    let block_header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(block_header);
    let state_tx = block.transaction();
    let query = QueryRequest::Singular(SingularQueryBox::FindParameters(FindParameters));
    let err = executor
        .validate_query(&state_tx, &ALICE_ID.clone(), &query)
        .expect_err("executor should deny the query");
    assert!(
        matches!(
            err,
            crate::execution_attempt::ExecutionAttemptError::Rejected(iroha_data_model::ValidationFail::NotPermitted(ref msg)) if msg == "queries disabled"
        ),
        "unexpected validation failure: {err:?}"
    );
}
#[test]
fn migrate_invokes_entrypoint_and_swaps_executor() {
    // A loadable validation executor is not necessarily a migration
    // executor: migration must return the canonical migration payload.
    // Build that exact entrypoint contract instead of depending on the
    // independently generated bundled validation fixture.
    let bytecode = generate_migration_program(&Ok(initial_executor_data_model_fallback()));
    let raw = data_model_executor::Executor::new(IvmBytecode::from_compiled(bytecode));
    // Start with the initial executor
    let mut executor = super::Executor::Initial;
    // Minimal state scaffolding
    let world = World::new();
    let kura = Kura::blank_kura_for_testing();
    let query_handle = query::store::LiveQueryStore::start_test();
    let state = State::new_with_chain(world, kura, query_handle, ChainId::from("test-chain"));
    let block_header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(block_header);
    let mut state_tx = block.transaction();
    // Perform migration
    executor
        .migrate(raw, &mut state_tx, &ALICE_ID.clone())
        .expect("migration should succeed");
    // Ensure executor has been swapped
    match executor {
        super::Executor::UserProvided(_) => {}
        _ => panic!("expected UserProvided executor after migration"),
    }
}
#[test]
fn migrate_rejects_unauthorized_non_genesis_callers_before_loading_bytecode() {
    let raw = data_model_executor::Executor::new(IvmBytecode::from_compiled(Vec::new()));
    let mut executor = super::Executor::Initial;
    let state = State::new_with_chain(
        World::new(),
        Kura::blank_kura_for_testing(),
        query::store::LiveQueryStore::start_test(),
        ChainId::from("executor-mutation-boundary"),
    );
    let block_header = BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    let mut block = state.block(block_header);
    let mut state_transaction = block.transaction();
    let error = executor
        .migrate(raw, &mut state_transaction, &ALICE_ID)
        .expect_err("direct migration must enforce executor-upgrade authority");
    assert_eq!(error, VMError::PermissionDenied);
    assert!(matches!(executor, super::Executor::Initial));
}
#[test]
fn migrate_applies_data_model_from_entrypoint() {
    let retained_permission = Permission::new(
        "permission.can_control_domain_lives".to_owned(),
        Json::new(()),
    );
    let declared_permission_names = [
        "CanMintAsset",
        "CanInvokeContractEntrypoint",
        "CanPublishSpaceDirectoryManifest",
        "CanPublishSpaceDirectoryManifestForUaid",
        "CanPublishSpaceDirectoryManifestForAccountDomain",
    ];
    let declared_permissions = declared_permission_names
        .into_iter()
        .map(|name| Permission::new(name.to_owned(), Json::new(())))
        .collect::<BTreeSet<_>>();
    let permissions = core::iter::once(retained_permission.name().to_owned())
        .chain(
            declared_permissions
                .iter()
                .map(|permission| permission.name().to_owned()),
        )
        .collect();
    let custom_parameters: BTreeMap<CustomParameterId, CustomParameter> = BTreeMap::new();
    let data_model = ExecutorDataModel::new(
        custom_parameters,
        BTreeSet::new(),
        permissions,
        Json::new(()),
    );
    let verdict = Ok(data_model.clone());
    let bytecode = generate_migration_program(&verdict);
    let raw = data_model_executor::Executor::new(IvmBytecode::from_compiled(bytecode));
    let mut executor = super::Executor::Initial;
    let role_id: RoleId = "declared_permission_role".parse().expect("role id");
    let stored_permissions = core::iter::once(retained_permission.clone())
        .chain(declared_permissions.iter().cloned())
        .collect::<BTreeSet<_>>();
    let mut permission_epochs = BTreeMap::from([(retained_permission.clone(), 8)]);
    permission_epochs.extend(declared_permissions.iter().cloned().enumerate().map(
        |(index, permission)| {
            (
                permission,
                9 + u64::try_from(index).expect("declared permission count fits u64"),
            )
        },
    ));
    let role = Role {
        id: role_id.clone(),
        permissions: stored_permissions.clone(),
        permission_epochs,
    };
    let mut world = World::with_assets_and_roles(
        [],
        [Account::new(ALICE_ID.clone()).build(&ALICE_ID)],
        [],
        [],
        [],
        [role],
    );
    world
        .account_permissions
        .insert(ALICE_ID.clone(), stored_permissions.clone());
    let kura = Kura::blank_kura_for_testing();
    let query_handle = query::store::LiveQueryStore::start_test();
    let state = State::new_with_chain(world, kura, query_handle, ChainId::from("test-chain"));
    let block_header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(block_header);
    let mut state_tx = block.transaction();
    executor
        .migrate(raw, &mut state_tx, &ALICE_ID.clone())
        .expect("migration should succeed");
    assert_eq!(*state_tx.world.executor_data_model.get(), data_model);
    assert_eq!(
        state_tx
            .world
            .account_permissions
            .get(&ALICE_ID)
            .expect("retained account permission entry"),
        &stored_permissions,
    );
    let role = state_tx.world.roles.get(&role_id).expect("retained role");
    assert_eq!(
        role.permissions().cloned().collect::<BTreeSet<_>>(),
        stored_permissions,
    );
    assert_eq!(role.permission_epochs().get(&retained_permission), Some(&8),);
    assert!(
        declared_permissions
            .iter()
            .all(|permission| role.permission_epochs().contains_key(permission)),
    );
    match executor {
        super::Executor::UserProvided(_) => {}
        _ => panic!("expected UserProvided executor after migration"),
    }
}
#[test]
fn migrate_fails_on_invalid_bytecode() {
    // Construct an invalid program (oversized code section) to trigger a VM error
    let mut prog = Vec::new();
    // Start with a fully valid authenticated header so rejection exercises the
    // oversized code section rather than an earlier metadata failure.
    prog.extend_from_slice(&ivm::ProgramMetadata::default_for(1, 1, 1).encode());
    // Oversized code
    let heap_start =
        usize::try_from(ivm::Memory::HEAP_START).expect("HEAP_START fits within usize");
    prog.extend(std::iter::repeat_n(0u8, heap_start + 8));
    let raw = data_model_executor::Executor::new(IvmBytecode::from_compiled(prog));
    let mut executor = super::Executor::Initial;
    let world = World::new();
    let kura = Kura::blank_kura_for_testing();
    let query_handle = query::store::LiveQueryStore::start_test();
    let state = State::new_with_chain(world, kura, query_handle, ChainId::from("test-chain"));
    let block_header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(block_header);
    let mut state_tx = block.transaction();
    let res = executor.migrate(raw, &mut state_tx, &ALICE_ID.clone());
    assert!(res.is_err(), "migration with invalid bytecode must fail");
    // Ensure executor remains unchanged
    matches!(executor, super::Executor::Initial);
}

#[test]
fn native_exact_transaction_read_requires_source_account_grant_and_revalidates_revocation() {
    use iroha_data_model::query::{
        CommittedTransaction, CommittedTxFilters, Query,
        dsl::{CommittedTxPredicate as P, CompoundPredicate, SelectorTuple},
        parameters::QueryParams,
        transaction::prelude::FindTransactions,
    };
    let transaction_hash = HashOf::from_untyped_unchecked(Hash::new(b"exact-read-auth-fixture"));
    let exact = CompoundPredicate::from_filters(CommittedTxFilters {
        authority_eq: Some(BOB_ID.clone()),
        entry_eq: Some(transaction_hash),
        ..CommittedTxFilters::default()
    });
    let query = |predicate: CompoundPredicate<CommittedTransaction>| {
        let query = FindTransactions::new();
        QueryRequest::Start(QueryWithParams {
            query: (),
            query_payload: query.dyn_encode(),
            item: query.query_item_kind(),
            predicate_bytes: predicate.encode(),
            selector_bytes: SelectorTuple::<CommittedTransaction>::default().encode(),
            params: QueryParams::default(),
        })
    };
    let request = query(exact.clone());
    let mut world = World::with(
        [],
        [
            Account::new(ALICE_ID.clone()).build(&ALICE_ID),
            Account::new(BOB_ID.clone()).build(&BOB_ID),
        ],
        [],
    );
    let executor = super::Executor::Initial;
    validate_native_query_with_world(&executor, &world, &BOB_ID, &request)
        .expect("source may read its own exact transaction");
    validate_native_query_with_world(&executor, &world, &ALICE_ID, &request)
        .expect_err("hash possession does not grant foreign transaction access");
    world.account_permissions.insert(
        ALICE_ID.clone(),
        BTreeSet::from([
            executor_permission::query::CanReadAccountData {
                account: ALICE_ID.clone(),
            }
            .into(),
            Permission::new("CanReadAccountData".to_owned(), Json::new(())),
        ]),
    );
    validate_native_query_with_world(&executor, &world, &ALICE_ID, &request)
        .expect_err("wrong target and malformed grants do not authorize recovery");
    let exact_grant: Permission = executor_permission::query::CanReadAccountData {
        account: BOB_ID.clone(),
    }
    .into();
    world
        .account_permissions
        .insert(ALICE_ID.clone(), BTreeSet::from([exact_grant.clone()]));
    validate_native_query_with_world(&executor, &world, &ALICE_ID, &request)
        .expect("exact source-account delegation authorizes recovery");
    for predicate in [
        CompoundPredicate::PASS,
        CompoundPredicate::from_filters(CommittedTxFilters {
            entry_eq: Some(transaction_hash),
            ..CommittedTxFilters::default()
        }),
        CompoundPredicate::from_committed_tx_predicate(P::Or(vec![
            P::AuthorityEq(BOB_ID.clone()),
            P::EntryEq(transaction_hash),
        ])),
        CompoundPredicate::from_committed_tx_predicate(P::Not(Box::new(P::AuthorityEq(
            BOB_ID.clone(),
        )))),
    ] {
        validate_native_query_with_world(&executor, &world, &ALICE_ID, &query(predicate))
            .expect_err("account delegation does not authorize inventory, hash-only, OR or NOT");
    }
    assert!(remove_committed_storage_entry(&world.account_permissions, ALICE_ID.clone()).is_some());
    validate_native_query_with_world(&executor, &world, &ALICE_ID, &request)
        .expect_err("revocation is effective before another signed recovery query");
    let role_id: RoleId = "exact_transaction_reader".parse().expect("role id");
    world.roles.insert(
        role_id.clone(),
        Role {
            id: role_id.clone(),
            permissions: BTreeSet::from([exact_grant]),
            permission_epochs: BTreeMap::new(),
        },
    );
    world.grant_role_for_tests(ALICE_ID.clone(), role_id.clone());
    validate_native_query_with_world(&executor, &world, &ALICE_ID, &request)
        .expect("assigned exact account-read role authorizes recovery");
    assert!(
        remove_committed_storage_entry(
            &world.account_roles,
            crate::role::RoleIdWithOwner::new(ALICE_ID.clone(), role_id)
        )
        .is_some()
    );
    validate_native_query_with_world(&executor, &world, &ALICE_ID, &request)
        .expect_err("role revocation is effective");
}
/// Every authoritative SoraFS orderbook and reserve query is gated by its operator permission,
/// while PoP-registry, moderation and reputation transparency reads stay public.
#[test]
#[allow(clippy::too_many_lines)]
fn initial_executor_gates_every_authoritative_sorafs_query_variant() {
    use iroha_data_model::{
        query::sorafs::prelude::*,
        sorafs::{
            capacity::ProviderId, moderation_ledger::ModerationFinalizedCursorV1,
            reputation::ReputationJournalFinalizedCursorV1,
        },
    };
    let world = World::with(
        [],
        [
            Account::new(ALICE_ID.clone()).build(&ALICE_ID),
            Account::new(BOB_ID.clone()).build(&BOB_ID),
        ],
        [],
    );
    let latest_block = BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    let state = State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        query::store::LiveQueryStore::start_test(),
    );
    let mut block = state.block(latest_block.clone());
    let mut state_transaction = block.transaction();
    let executor = super::Executor::Initial;
    let singular = |query: SingularQueryBox| QueryRequest::Singular(query);
    let orderbook_queries: Vec<QueryRequest> = vec![
        singular(FindSorafsOrderbookPolicy.into()),
        singular(FindSorafsOrderbookOrderById::new([0x11; 32]).into()),
        singular(FindSorafsOrderbookCancellationByOrderId::new([0x12; 32]).into()),
        singular(FindSorafsOrderbookReceiptById::new([0x13; 32]).into()),
        singular(FindSorafsOrderbookTradeById::new([0x14; 32]).into()),
        singular(FindSorafsOrderbookChannelById::new([0x15; 32]).into()),
        singular(FindSorafsOrderbookStatus.into()),
        singular(FindSorafsOrderbookOrders::new(None, None, None, 10).into()),
        singular(FindSorafsOrderbookReceipts::new(None, None, None, 10).into()),
        singular(FindSorafsOrderbookTrades::new(None, None, 10).into()),
        singular(FindSorafsOrderbookChannels::new(None, None, None, 10).into()),
        singular(FindSorafsOrderbookEvents::new(None, None, 10).into()),
    ];
    let reserve_queries: Vec<QueryRequest> = vec![
        singular(FindSorafsReservePolicy::new().into()),
        singular(FindSorafsReserveProviderById::new(ProviderId::new([0x51; 32])).into()),
        singular(FindSorafsReserveMovementById::new([0x61; 32]).into()),
        singular(FindSorafsReserveAppealById::new([0x71; 32]).into()),
        singular(FindSorafsReserveProviders::new(None, None, 10).into()),
        singular(FindSorafsReserveMovements::new(None, None, 10).into()),
        singular(FindSorafsReserveAppeals::new(None, None, 10).into()),
        singular(FindSorafsReserveEvents::new(None, None, 10).into()),
    ];
    let reputation_policy = singular(FindSorafsReputationJournalAuthorityPolicy.into());
    let reputation_cursor = ReputationJournalFinalizedCursorV1 {
        height: 7,
        block_hash: [0x45; 32],
        finalized_at_unix_ms: 1_700_000_000_000,
    };
    let public_queries: Vec<QueryRequest> = vec![
        singular(FindSorafsPopIssuerPolicy.into()),
        singular(FindSorafsPopCredentialCommitmentByDigest::new([1; 32]).into()),
        singular(FindSorafsPopCommitmentRootByVersion::new(1).into()),
        singular(FindSorafsPopRevocationPublicationByVersion::new(1).into()),
        singular(FindSorafsPopRevocationByNonceCommitment::new([2; 32]).into()),
        singular(FindSorafsPopAuditDigestBySequence::new(1).into()),
        singular(FindSorafsPopRegistryStatus.into()),
        singular(FindSorafsModerationPolicy.into()),
        singular(FindSorafsModerationStatus.into()),
        singular(
            FindSorafsModerationAppeal::new("appeal-case".to_owned(), "round-1".to_owned()).into(),
        ),
        singular(
            FindSorafsModerationEvents::new(
                ModerationFinalizedCursorV1 {
                    height: 7,
                    block_hash: [0x44; 32],
                },
                None,
                16,
            )
            .into(),
        ),
        singular(FindSorafsReputationJournalEvents::new(Some(reputation_cursor), None, 16).into()),
    ];
    macro_rules! validate {
        ($query:expr) => {
            executor.validate_query_with_world_parts(
                &state_transaction.world,
                Some(latest_block.clone()),
                &ALICE_ID,
                $query,
                &executor_test_budget(),
            )
        };
    }
    macro_rules! hold_only {
        ($permission:expr) => {
            state_transaction.world.account_permissions.insert(
                ALICE_ID.clone(),
                BTreeSet::from([Permission::from($permission)]),
            );
        };
    }
    for query in &public_queries {
        validate!(query)
            .unwrap_or_else(|error| panic!("transparency query must stay public: {error:?}"));
    }
    // An unrelated SoraFS operator permission must not open any gated family.
    hold_only!(executor_permission::sorafs::CanBindSorafsAlias);
    for query in orderbook_queries
        .iter()
        .chain(&reserve_queries)
        .chain(std::iter::once(&reputation_policy))
    {
        let error = validate!(query)
            .expect_err("gated SoraFS state must not be readable without its permission");
        assert!(
            matches!(
                error,
                crate::execution_attempt::ExecutionAttemptError::Rejected(
                    ValidationFail::NotPermitted(_)
                )
            ),
            "{error:?}"
        );
    }
    // A provider-scoped completion token authorizes completion work, never global inventory.
    hold_only!(
        executor_permission::sorafs::CanCompleteSorafsReplicationOrder {
            provider_id: iroha_data_model::sorafs::capacity::ProviderId::new([0x71; 32]),
        }
    );
    for query in &orderbook_queries {
        validate!(query)
            .expect_err("provider-scoped completion must not expose the global orderbook");
    }
    for permission in [Permission::from(
        executor_permission::sorafs::CanSetSorafsPricing,
    )] {
        hold_only!(permission.clone());
        for query in &orderbook_queries {
            validate!(query).unwrap_or_else(|error| {
                panic!("{} must read orderbook state: {error:?}", permission.name())
            });
        }
        for query in &reserve_queries {
            validate!(query).expect_err("orderbook operators must not read reserve state");
        }
    }
    hold_only!(executor_permission::sorafs::CanSetSorafsReservePolicy);
    for query in &reserve_queries {
        validate!(query)
            .unwrap_or_else(|error| panic!("reserve governors must read reserve state: {error:?}"));
    }
    for query in &orderbook_queries {
        validate!(query).expect_err("reserve governors must not read orderbook state");
    }
    for permission in [
        Permission::from(executor_permission::sorafs::CanManageSorafsReputationJournalPolicy),
        Permission::from(executor_permission::sorafs::CanRecordSorafsReputationJournal),
        Permission::from(executor_permission::sorafs::CanResolveSorafsCapacityDispute),
    ] {
        hold_only!(permission.clone());
        validate!(&reputation_policy).unwrap_or_else(|error| {
            panic!(
                "{} must read the reputation authority policy: {error:?}",
                permission.name()
            )
        });
    }
}
/// SCCP proposal authority admits Parliament proposals without applying their parameter
/// changes. Generic parameter authority is separate, and validation-fee governance parameters
/// remain reserved for Parliament enactment even during genesis.
#[test]
fn initial_executor_separates_sccp_proposal_authority_from_parameter_governance() {
    let generic_admin = checked_account_id();
    let sccp_proposer = checked_account_id();
    let genesis_authority = checked_account_id();
    let mut world = World::with(
        [],
        [
            Account::new(generic_admin.clone()).build(&generic_admin),
            Account::new(sccp_proposer.clone()).build(&sccp_proposer),
            Account::new(genesis_authority.clone()).build(&genesis_authority),
        ],
        [],
    );
    world.account_permissions.insert(
        generic_admin.clone(),
        BTreeSet::from([executor_permission::parameter::CanSetParameters.into()]),
    );
    world.account_permissions.insert(
        sccp_proposer.clone(),
        BTreeSet::from([executor_permission::sccp::CanProposeSccpRouteGovernance.into()]),
    );
    let set_custom = |id: &str| -> InstructionBox {
        iroha_data_model::isi::SetParameter::new(iroha_data_model::parameter::Parameter::Custom(
            CustomParameter::new(
                CustomParameterId::new(id.parse().expect("test custom parameter id")),
                Json::new(()),
            ),
        ))
        .into()
    };
    let reserved = [
        iroha_data_model::validation_fee::RETIRED_VALIDATION_FEE_GOVERNANCE_KEYSET_PARAMETER_ID,
        iroha_data_model::validation_fee::ValidationFeePolicyRegistryV1::PARAMETER_ID_STR,
        iroha_data_model::validation_fee::RETIRED_VALIDATION_FEE_POLICY_PARAMETER_ID,
    ];
    let state = component_state_for_testing(world);
    {
        // Check the genesis permission predicate directly; this component overlay
        // intentionally cannot authenticate or execute a genesis source.
        let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
        let genesis = block.transaction();
        assert!(is_initial_genesis_context(&genesis));
        for id in reserved {
            let error = validate_initial_native_instruction_authority(
                &genesis,
                &genesis_authority,
                &set_custom(id),
                true,
            )
            .map_err(crate::execution_attempt::expect_completed_rejection)
            .expect_err("reserved governance remains closed in the genesis permission predicate");
            assert!(
                matches!(&error, ValidationFail::NotPermitted(reason)
                    if reason.contains("only be changed by an enacted SORA Parliament proposal")),
                "{id}: {error:?}",
            );
        }
    }
    {
        let chain = crate::sumeragi::test_chain::CertifiedTestChain::start(
            crate::sumeragi::test_chain::TestChainConfig::new(World::new(), 1_000),
        )
        .expect("the unmodified signed genesis must execute and publish");
        assert_eq!(chain.height(), 1);
    }
    for id in reserved {
        // Exercise the signed pipeline as well: the only change from the positive
        // control is one forbidden parameter. Startup retains the original typed
        // validation reason, which must match the direct policy predicate.
        let mut config = crate::sumeragi::test_chain::TestChainConfig::new(World::new(), 1_000);
        config
            .genesis_parameters
            .push(iroha_data_model::parameter::Parameter::Custom(
                CustomParameter::new(id.parse().unwrap(), Json::new(())),
            ));
        let error = crate::sumeragi::test_chain::CertifiedTestChain::start(config)
            .err()
            .expect("reserved parameters must stay closed during authenticated genesis");
        assert!(
            matches!(&error.error,
                crate::sumeragi::test_chain::TestChainError::OriginalGenesisExecution(error)
                if matches!(error.as_ref(),
                    crate::block::BlockValidationError::InvalidGenesis(
                        crate::block::InvalidGenesisError::RejectedOutput(output)
                    ) if matches!(output.reason.as_ref(),
                        iroha_data_model::transaction::error::TransactionRejectionReason::Validation(
                            ValidationFail::NotPermitted(reason)
                        ) if reason.contains("only be changed by an enacted SORA Parliament proposal")
                    )
                )
            ),
            "{id}: {error:?}",
        );
        assert_eq!(
            crate::state::StateReadOnly::height(&error.state.view()),
            0,
            "rejected genesis must not publish a block"
        );
    }
    let mut block = state.block(BlockHeader::new(nonzero!(2_u64), None, None, 0, 0));
    let mut state_transaction = block.transaction();
    for id in reserved {
        for authority in [&generic_admin, &sccp_proposer] {
            let error = super::Executor::Initial
                .execute_instruction(&mut state_transaction, authority, set_custom(id))
                .expect_err("reserved parameters must not be set through SetParameter");
            assert!(
                matches!(error, ValidationFail::NotPermitted(_)),
                "{id}: {error:?}"
            );
        }
    }
    let error = super::Executor::Initial
        .execute_instruction(
            &mut state_transaction,
            &sccp_proposer,
            set_custom("unrelated_parameter"),
        )
        .expect_err("the SCCP route proposal permission must not authorize generic parameters");
    assert!(
        matches!(&error, ValidationFail::NotPermitted(message) if message.contains("CanSetParameters")),
        "{error:?}"
    );
    validate_initial_native_instruction_authority(
        &state_transaction,
        &generic_admin,
        &set_custom("unrelated_parameter"),
        false,
    )
    .expect("CanSetParameters must authorize an unreserved custom parameter");
    super::Executor::Initial
        .execute_instruction(
            &mut state_transaction,
            &generic_admin,
            set_custom("unrelated_parameter"),
        )
        .expect("a generic parameter administrator can set an unrelated custom parameter");
    assert!(state_transaction.world.sccp_parameters().is_none());

    let proposal = crate::smartcontracts::isi::sccp::test_support::sample_proposal(
        state_transaction.network_id,
    );
    let propose = || {
        InstructionBox::from(
            iroha_data_model::isi::governance::ProposeSccpRouteGovernance {
                proposal: proposal.clone(),
            },
        )
    };
    let error = super::Executor::Initial
        .execute_instruction(&mut state_transaction, &generic_admin, propose())
        .expect_err("generic parameter authority must not authorize SCCP proposals");
    assert!(
        matches!(
            &error,
            ValidationFail::InstructionFailed(InstructionExecutionError::InvariantViolation(reason))
                if reason.contains("CanProposeSccpRouteGovernance required")
        ),
        "unexpected SCCP proposer rejection: {error:?}"
    );
    assert_eq!(
        state_transaction
            .world
            .governance_proposals()
            .iter()
            .count(),
        0
    );
    super::Executor::Initial
        .execute_instruction(&mut state_transaction, &sccp_proposer, propose())
        .expect("the SCCP proposer permission admits a canonical Parliament proposal");
    let proposals = state_transaction.world.governance_proposals();
    assert_eq!(proposals.iter().count(), 1);
    let (_, record) = proposals.iter().next().expect("the admitted SCCP proposal");
    assert_eq!(record.proposer, sccp_proposer);
    assert_eq!(
        record.status,
        crate::state::GovernanceProposalStatus::Proposed
    );
    assert_eq!(
        record
            .as_sccp_route_governance()
            .expect("the canonical SCCP proposal body")
            .proposal
            .as_ref(),
        &proposal
    );
    assert!(
        state_transaction.world.sccp_parameters().is_none(),
        "proposing SetParameters must not enact the SCCP parameter change"
    );
}
/// DPN markers are exact unit payloads: malformed payloads fail closed before storage, even when
/// genesis grants them.
#[test]
fn initial_executor_rejects_malformed_dpn_payloads_even_at_genesis() {
    let key = checked_keypair();
    let bootstrap = AccountId::new(key.public_key().clone());
    let destination = checked_account_id();
    let config = || {
        let world = World::with(
            [],
            [Account::new(destination.clone()).build(&destination)],
            [],
        );
        let mut config = crate::sumeragi::test_chain::TestChainConfig::new(world, 1_000);
        config.genesis_key = key.clone();
        config
    };
    let names = [
        "DpnAdmin",
        "DpnUser",
        "DpnInori",
        "DpnSettlement",
        "DpnEprGuard",
    ];
    let mut positive = config();
    for name in names {
        positive.genesis_instructions.push(
            Grant::account_permission(
                Permission::new(name.to_owned(), Json::new(())),
                destination.clone(),
            )
            .into(),
        );
    }
    let chain = crate::sumeragi::test_chain::CertifiedTestChain::start(positive)
        .expect("signed genesis grants all exact DPN markers");
    assert_eq!(chain.height(), 1);
    crate::block::authenticate_genesis_block_intents(chain.genesis(), &bootstrap).unwrap();
    for name in names {
        let exact = Permission::new(name.to_owned(), Json::new(()));
        assert!(
            authority_has_permission(&chain.state().view().world, &destination, &exact).unwrap()
        );
    }
    drop(chain);
    for name in names {
        for payload in ["{}", "[]", "true", "\"unexpected\""] {
            let malformed = Permission::new(
                name.to_owned(),
                Json::from_raw_json(payload.to_owned()).expect("JSON fixture"),
            );
            let error = {
                let state = component_state_for_testing(World::with(
                    [],
                    [
                        Account::new(bootstrap.clone()).build(&bootstrap),
                        Account::new(destination.clone()).build(&destination),
                    ],
                    [],
                ));
                let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
                let tx = block.transaction();
                validate_initial_permission_or_role_mutation(
                    &tx,
                    &bootstrap,
                    &Grant::account_permission(malformed.clone(), destination.clone()).into(),
                    true,
                )
                .map_err(crate::execution_attempt::expect_completed_rejection)
                .expect_err("the genesis permission predicate rejects malformed marker")
            };
            assert!(
                matches!(&error, ValidationFail::NotPermitted(reason)
                if reason.contains(name) && reason.contains("Invalid permission payload")),
                "{error:?}"
            );
            let mut negative = config();
            negative
                .genesis_instructions
                .push(Grant::account_permission(malformed.clone(), destination.clone()).into());
            let error = crate::sumeragi::test_chain::CertifiedTestChain::start(negative)
                .err()
                .expect("malformed DPN signed genesis rejects");
            assert!(
                matches!(&error.error,
                    crate::sumeragi::test_chain::TestChainError::OriginalGenesisExecution(error)
                    if matches!(error.as_ref(),
                        crate::block::BlockValidationError::InvalidGenesis(
                            crate::block::InvalidGenesisError::RejectedOutput(output)
                        ) if matches!(output.reason.as_ref(),
                            iroha_data_model::transaction::error::TransactionRejectionReason::Validation(
                                ValidationFail::NotPermitted(reason)
                            ) if reason.contains(name) && reason.contains("Invalid permission payload")
                        )
                    )
                ),
                "{name} {payload}: {error:?}"
            );
            let view = error.state.view();
            assert_eq!(crate::state::StateReadOnly::height(&view), 0);
            assert!(
                !authority_has_permission(&view.world, &destination, &malformed).unwrap(),
                "malformed {name} reached storage"
            );
        }
    }
}

// Cache residency is process-global. Run only the selected test in a fresh copy of
// this same harness so unrelated parallel tests cannot change its original budget.
fn executor_cache_test_in_child(name: &str) -> bool {
    const CHILD: &str = "IROHA_CORE_EXECUTOR_CACHE_TEST_CHILD";
    let exact_name = format!("executor::tests::{name}");
    if std::env::var_os(CHILD).as_deref() == Some(std::ffi::OsStr::new(&exact_name)) {
        return false;
    }
    let output = std::process::Command::new(
        std::env::current_exe().expect("resolve Core cache-test executable"),
    )
    .arg(&exact_name)
    .args(["--exact", "--nocapture", "--test-threads=1"])
    .env(CHILD, &exact_name)
    .output()
    .expect("execute exact cache-test child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "{exact_name} failed in its isolated harness\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains(&format!("test {exact_name} ... ok"))
            && stdout.contains("test result: ok. 1 passed; 0 failed;"),
        "{exact_name} did not complete exactly once\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    true
}

#[test]
fn loaded_executor_materializes_only_governed_runtime() {
    if executor_cache_test_in_child("loaded_executor_materializes_only_governed_runtime") {
        return;
    }
    const GAS_LIMIT: u64 = 10_000;
    let raw = data_model_executor::Executor::new(IvmBytecode::from_compiled(generate_ok_program()));
    let loaded = super::LoadedExecutor::load(raw).expect("validate executor without a runtime");
    assert_eq!(
        loaded.runtime_pool_snapshot(),
        (super::ExecutorRuntimePoolStats::default(), 0)
    );
    let limit_before = ivm::cache_memory::memory_stats().limit_bytes;
    let mut runtime = loaded
        .checkout_runtime_for_gas_limit(GAS_LIMIT, Memory::HEAP_MAX_SIZE, &executor_test_budget())
        .unwrap();
    let allocation = runtime.memory.load_region(0, 1).unwrap().as_ptr();
    runtime.set_register(7, 99);
    runtime.memory.preload_input(0, &[0xA5]).unwrap();
    drop(runtime);
    let (before_reuse, _) = loaded.runtime_pool_snapshot();
    let runtime = loaded
        .checkout_runtime_for_gas_limit(GAS_LIMIT, Memory::HEAP_MAX_SIZE, &executor_test_budget())
        .unwrap();
    let (after_reuse, _) = loaded.runtime_pool_snapshot();
    assert_eq!(
        after_reuse.hits,
        before_reuse.hits + 1,
        "governed checkout must reuse its original funded runtime"
    );
    assert_eq!(after_reuse.program_loads, before_reuse.program_loads);
    assert_eq!(after_reuse.template_builds, before_reuse.template_builds);
    assert_eq!(
        runtime.memory.load_region(0, 1).unwrap().as_ptr(),
        allocation
    );
    assert_eq!(runtime.register(7), 0);
    assert_eq!(
        runtime.memory.load_region(Memory::INPUT_START, 1).unwrap(),
        &[0]
    );
    assert_eq!(runtime.remaining_gas(), GAS_LIMIT);
    assert_eq!(ivm::cache_memory::memory_stats().limit_bytes, limit_before);
}

#[test]
fn executor_idle_retention_reclamation_preserves_lru_identity_and_original_owners() {
    if executor_cache_test_in_child(
        "executor_idle_retention_reclamation_preserves_lru_identity_and_original_owners",
    ) {
        return;
    }
    const GAS: u64 = 10_000;
    let loaded = super::LoadedExecutor::load(data_model_executor::Executor::new(
        IvmBytecode::from_compiled(generate_ok_program()),
    ))
    .unwrap();
    loaded.runtime_pool.lock().unwrap().clear_storage();
    for heap in [64, 128] {
        drop(
            loaded
                .checkout_runtime_for_gas_limit(GAS, heap, &executor_test_budget())
                .unwrap(),
        );
    }
    let first = super::ExecutorRuntimeKey::for_limits(GAS, 64);
    let second = super::ExecutorRuntimeKey::for_limits(GAS, 128);
    let active = super::ExecutorRuntimeKey::for_limits(GAS, 256);
    let returning = super::ExecutorRuntimeKey::for_limits(GAS, 512);
    let (identity, idle, retained_index, rows, evictions_before) = {
        let mut pool = loaded.runtime_pool.lock().unwrap();
        assert!(pool.variants.get(&first).unwrap().available.is_some());
        assert!(pool.variants.get(&second).unwrap().available.is_some());
        // These empty rows stand for an active borrower and the returning owner.
        pool.insert_variant(active);
        let identity = pool.insert_variant(returning);
        pool.touch(first);
        let expected = pool
            .variants
            .get(&second)
            .unwrap()
            .available
            .as_ref()
            .unwrap()
            .1
            .memory
            .load_region(0, 1)
            .unwrap()
            .as_ptr();
        let retained_index = pool.index_memory.bytes();
        let rows = pool.variants.len();
        let evictions_before = pool.stats.evictions;
        let resident = ivm::cache_memory::memory_stats().measured_resident_bytes();
        let idle = pool
            .take_idle_runtime_for_retention(returning, &identity)
            .unwrap();
        assert_eq!(idle.1.memory.load_region(0, 1).unwrap().as_ptr(), expected);
        assert_eq!(
            ivm::cache_memory::memory_stats().measured_resident_bytes(),
            resident,
            "moving the original owner must not refund live storage"
        );
        assert_eq!(pool.index_memory.bytes(), retained_index);
        assert_eq!(pool.variants.len(), rows);
        assert!(pool.variants.get(&first).unwrap().available.is_some());
        assert!(pool.variants.get(&second).unwrap().available.is_none());
        assert!(pool.variants.get(&active).unwrap().available.is_none());
        assert!(pool.variants.get(&returning).unwrap().available.is_none());
        (identity, idle, retained_index, rows, evictions_before)
    };
    assert!(
        loaded.runtime_pool.try_lock().is_ok(),
        "destruction runs outside the pool lock"
    );
    let resident = ivm::cache_memory::memory_stats().measured_resident_bytes();
    let original_baseline = idle.0.clone();
    assert_eq!(
        ivm::cache_memory::memory_stats().measured_resident_bytes(),
        resident,
        "a borrower shares the original allocation charges"
    );
    drop(idle);
    let while_borrowed = ivm::cache_memory::memory_stats().measured_resident_bytes();
    assert!(
        while_borrowed < resident,
        "the original idle VM refunds when destroyed"
    );
    drop(original_baseline);
    assert!(
        ivm::cache_memory::memory_stats().measured_resident_bytes() < while_borrowed,
        "the shared baseline refunds only after its final borrower drops"
    );
    let last_idle = {
        let mut pool = loaded.runtime_pool.lock().unwrap();
        let idle = pool
            .take_idle_runtime_for_retention(returning, &identity)
            .unwrap();
        assert!(
            pool.take_idle_runtime_for_retention(returning, &identity)
                .is_none()
        );
        assert_eq!(pool.stats.evictions, evictions_before + 2);
        assert_eq!(pool.index_memory.bytes(), retained_index);
        assert_eq!(pool.variants.len(), rows);
        idle
    };
    drop(last_idle);
}

#[test]
fn executor_idle_retention_reclamation_rejects_replaced_or_filled_returning_slot() {
    if executor_cache_test_in_child(
        "executor_idle_retention_reclamation_rejects_replaced_or_filled_returning_slot",
    ) {
        return;
    }
    const GAS: u64 = 10_000;
    let loaded = super::LoadedExecutor::load(data_model_executor::Executor::new(
        IvmBytecode::from_compiled(generate_ok_program()),
    ))
    .unwrap();
    loaded.runtime_pool.lock().unwrap().clear_storage();
    for heap in [64, 256] {
        drop(
            loaded
                .checkout_runtime_for_gas_limit(GAS, heap, &executor_test_budget())
                .unwrap(),
        );
    }
    let idle_key = super::ExecutorRuntimeKey::for_limits(GAS, 64);
    let competing_idle = super::ExecutorRuntimeKey::for_limits(GAS, 256);
    let returning = super::ExecutorRuntimeKey::for_limits(GAS, 128);
    let mut pool = loaded.runtime_pool.lock().unwrap();
    let old_identity = pool.insert_variant(returning);
    let new_identity = ivm::cache_memory::SharedValue::new((), Some(0));
    pool.variants.get_mut(&returning).unwrap().identity = new_identity.clone();
    let evictions = pool.stats.evictions;
    assert!(
        pool.take_idle_runtime_for_retention(returning, &old_identity)
            .is_none()
    );
    assert!(pool.variants.get(&idle_key).unwrap().available.is_some());
    assert_eq!(pool.stats.evictions, evictions);
    let original = pool
        .variants
        .get_mut(&idle_key)
        .unwrap()
        .available
        .take()
        .unwrap();
    pool.variants.get_mut(&returning).unwrap().available = Some(original);
    assert!(
        pool.take_idle_runtime_for_retention(returning, &new_identity)
            .is_none()
    );
    assert!(pool.variants.get(&returning).unwrap().available.is_some());
    assert!(
        pool.variants
            .get(&competing_idle)
            .unwrap()
            .available
            .is_some()
    );
    assert_eq!(pool.stats.evictions, evictions);
}

#[test]
fn native_account_grant_reader_preserves_refusal_and_exact_token_shape() {
    let mut world = World::with(
        [],
        [
            Account::new(ALICE_ID.clone()).build(&ALICE_ID),
            Account::new(BOB_ID.clone()).build(&BOB_ID),
        ],
        [],
    );
    let exact: Permission = executor_permission::query::CanReadAccountData {
        account: BOB_ID.clone(),
    }
    .into();
    let read = |world: &World| {
        super::authority_has_native_account_read_permission(&world.view(), &ALICE_ID, &BOB_ID)
    };
    world
        .account_permissions
        .insert(ALICE_ID.clone(), BTreeSet::from([exact.clone()]));
    assert_eq!(read(&world), Ok(true));
    let refused = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(96, usize::MAX, usize::MAX, 0, 32),
        || read(&world),
    );
    assert!(
        matches!(refused, Err(crate::execution_attempt::ExecutionAttemptError::Deferred(ref reason))
        if reason.reason() == ivm::error::ExecutionDeferral::ActiveMemoryCapacity)
    );
    assert_eq!(read(&world), Ok(true));
    for invalid in [
        Permission::new("CanReadAccountData".into(), Json::new(())),
        Permission::new("CanReadAccountData".into(), Json::new(false)),
        Permission::new(
            "CanReadAccountData".into(),
            format!(r#"{{"account":"{}","unrecognized_field":null}}"#, *BOB_ID)
                .parse::<Json>()
                .unwrap(),
        ),
        executor_permission::query::CanReadAccountData {
            account: ALICE_ID.clone(),
        }
        .into(),
    ] {
        world
            .account_permissions
            .insert(ALICE_ID.clone(), BTreeSet::from([invalid]));
        assert_eq!(
            read(&world),
            Ok(false),
            "only the exact canonical target grant authorizes"
        );
    }
    assert!(remove_committed_storage_entry(&world.account_permissions, ALICE_ID.clone()).is_some());
    assert_eq!(read(&world), Ok(false));
    let role_id: RoleId = "original_account_reader".parse().unwrap();
    world.roles.insert(
        role_id.clone(),
        Role {
            id: role_id.clone(),
            permissions: BTreeSet::from([exact]),
            permission_epochs: BTreeMap::new(),
        },
    );
    world.grant_role_for_tests(ALICE_ID.clone(), role_id.clone());
    assert_eq!(read(&world), Ok(true));
    let refused = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(96, usize::MAX, usize::MAX, 0, 32),
        || read(&world),
    );
    assert!(matches!(
        refused,
        Err(crate::execution_attempt::ExecutionAttemptError::Deferred(_))
    ));
    assert!(
        remove_committed_storage_entry(
            &world.account_roles,
            crate::role::RoleIdWithOwner::new(ALICE_ID.clone(), role_id)
        )
        .is_some()
    );
    assert_eq!(
        read(&world),
        Ok(false),
        "revoking the original role revokes its exact grant"
    );
}

#[test]
fn completion_permission_payload_requires_exact_nonzero_provider_scope() {
    use iroha_data_model::sorafs::capacity::ProviderId;
    use iroha_executor_data_model::permission::sorafs::CanCompleteSorafsReplicationOrder;
    let token = CanCompleteSorafsReplicationOrder {
        provider_id: ProviderId::new([1; 32]),
    };
    let exact: Permission = token.into();
    validate_initial_permission_payload_constraints(&exact).unwrap();
    let bytes = norito::to_bytes(&exact).unwrap();
    let decoded = norito::decode_from_bytes::<Permission>(&bytes).unwrap();
    assert_eq!(decoded, exact);
    assert_eq!(
        CanCompleteSorafsReplicationOrder::try_from(&decoded).unwrap(),
        token
    );
    let mut extra = norito::json::to_value(&token).unwrap();
    extra
        .as_object_mut()
        .unwrap()
        .insert("unrelated".into(), norito::json::Value::Bool(true));
    for malformed in [
        Permission::new(exact.name().to_owned(), Json::new(())),
        Permission::new(exact.name().to_owned(), Json::new(norito::json!({}))),
        Permission::new(exact.name().to_owned(), Json::new(extra)),
        Permission::from(CanCompleteSorafsReplicationOrder {
            provider_id: ProviderId::new([0; 32]),
        }),
    ] {
        assert!(validate_initial_permission_payload_constraints(&malformed).is_err());
    }
}
