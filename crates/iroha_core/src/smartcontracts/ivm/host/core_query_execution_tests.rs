fn ledger_reader_world_for_core_query_tests(mut world: World, authority: &AccountId) -> World {
    if world.accounts.view().get(authority).is_none() {
        let (id, account) = iroha_data_model::IntoKeyValue::into_key_value(
            Account::new(authority.clone()).build(authority),
        );
        world.accounts.insert(id, account);
    }
    world.account_permissions.insert(
        authority.clone(),
        [Permission::from(
            iroha_executor_data_model::permission::query::CanReadAllLedgerData,
        )]
        .into_iter()
        .collect(),
    );
    world
}

#[test]
fn execute_query_syscall_returns_norito_response_and_gas() {
    let authority: AccountId = fixture_account("alice");
    let world = ledger_reader_world_for_core_query_tests(World::new(), &authority);
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = State::new_for_testing(world, kura, query);
    let view = state.view();
    let mut host = CoreHostImpl::new(authority.clone());
    host.set_query_state(&view);
    let mut vm = IVM::new(1_000_000);
    let request = QueryRequest::Singular(SingularQueryBox::FindParameters(FindParameters));
    let gas_ctx = QueryGasContext::from_request(&request);
    let request_bytes = norito::to_bytes(&request).expect("encode query request");
    let expected_execution = execute_query_on_state_with_budget(
        &view,
        &authority,
        request,
        Some(
            CoreHost::query_execution_budget(&gas_ctx, 1_000_000).expect("query execution budget"),
        ),
    )
    .expect("measure query execution");
    let ptr = store_tlv(&mut vm, PointerType::NoritoBytes, &request_bytes);
    vm.set_register(10, ptr);
    let gas = host
        .syscall(ivm_sys::SYSCALL_SMARTCONTRACT_EXECUTE_QUERY, &mut vm)
        .expect("query syscall");
    let out_ptr = vm.register(10);
    let tlv = vm.memory.validate_tlv(out_ptr).expect("output tlv");
    assert_eq!(tlv.type_id, PointerType::NoritoBytes);
    let response: QueryResponse = norito::decode_from_bytes(tlv.payload).expect("decode response");
    assert!(matches!(response, QueryResponse::Singular(_)));
    let expected = CoreHost::query_gas_cost(
        &gas_ctx,
        expected_execution.processed_items,
        expected_execution.processed_bytes,
    );
    assert_eq!(gas, expected);
}
#[test]
fn execute_query_rejects_oversized_singular_response_before_output_allocation() {
    let authority: AccountId = fixture_account("alice");
    let mut metadata = Metadata::default();
    metadata.insert(
        "oversized".parse().expect("metadata key"),
        Json::new("x".repeat(128 * 1024)),
    );
    let account = Account::new(authority.clone())
        .with_metadata(metadata)
        .build(&authority);
    let state = State::new_for_testing(
        World::with([], [account], []),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let view = state.view();
    let mut host = CoreHostImpl::new(authority.clone());
    host.set_query_state(&view);
    let mut vm = IVM::new(
        CoreHost::QUERY_GAS_BASE_SINGULAR
            .saturating_add(CoreHost::QUERY_GAS_PER_ITEM)
            .saturating_add(512),
    );
    let request = QueryRequest::Singular(SingularQueryBox::FindAccountById(FindAccountById {
        id: authority.clone(),
    }));
    let request_bytes = norito::to_bytes(&request).expect("encode query request");
    let request_ptr = store_tlv(&mut vm, PointerType::NoritoBytes, &request_bytes);
    vm.set_register(10, request_ptr);
    let error = host
        .syscall(ivm_sys::SYSCALL_SMARTCONTRACT_EXECUTE_QUERY, &mut vm)
        .expect_err("oversized singular query must exhaust its byte budget");
    assert_eq!(error, ivm::VMError::OutOfGas);
    assert_eq!(
        vm.register(10),
        request_ptr,
        "the host must not publish an output pointer after admission fails"
    );
}
#[test]
fn get_account_balance_syscall_returns_canonical_quantity_pointer() {
    let authority: AccountId = fixture_account("alice");
    let domain =
        Domain::new(DomainId::try_new("wonderland", "universal").unwrap()).build(&authority);
    let account = build_fixture_account(&authority, &authority);
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
    let asset_def = AssetDefinition::numeric(
        asset_def_id.clone(),
        "rose".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&authority);
    let asset_id = AssetId::of(asset_def_id.clone(), authority.clone());
    let asset = Asset::new(asset_id.clone(), Quantity::from(42_u32));
    let world = World::with_assets([domain], [account], [asset_def], [asset], []);
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = State::new_for_testing(world, kura, query);
    let view = state.view();
    let mut host: CoreHostImpl<QueryStateSlot<_>> = CoreHostImpl::new(authority.clone());
    host.set_query_state(&view);
    let mut vm = IVM::new(10_000);
    let balance_request = QueryRequest::Singular(SingularQueryBox::FindAssetById(FindAssetById {
        id: asset_id,
    }));
    let gas_ctx = QueryGasContext::from_request(&balance_request);
    let expected_execution = execute_query_on_state_with_budget(
        &view,
        &authority,
        balance_request,
        Some(
            CoreHost::query_execution_budget(&gas_ctx, vm.remaining_gas())
                .expect("balance query execution budget"),
        ),
    )
    .expect("measure balance query execution");
    let account_ptr = store_tlv(&mut vm, PointerType::AccountId, &norito_blob(&authority));
    let asset_def_ptr = store_tlv(
        &mut vm,
        PointerType::AssetDefinitionId,
        &norito_blob(&asset_def_id),
    );
    vm.set_register(10, account_ptr);
    vm.set_register(11, asset_def_ptr);
    let balance_payload = quantity_frame(&Quantity::from(42_u32));
    let gas = host
        .syscall(ivm_sys::SYSCALL_GET_ACCOUNT_BALANCE, &mut vm)
        .expect("get balance");
    assert_eq!(
        gas,
        CoreHost::query_gas_cost(
            &gas_ctx,
            expected_execution.processed_items,
            expected_execution.processed_bytes.saturating_add(
                u64::try_from(balance_payload.len()).expect("balance payload length")
            ),
        )
    );
    let tlv = vm
        .memory
        .validate_tlv(vm.register(10))
        .expect("balance tlv");
    assert_eq!(tlv.type_id, PointerType::Quantity);
    let value = QuantityValueV1::decode_frame(tlv.payload)
        .expect("decode quantity balance")
        .into_quantity();
    assert_eq!(value, Quantity::from(42_u32));
}
#[test]
fn core_queries_return_typed_handles_and_specialists_remain_norito() {
    let authority: AccountId = fixture_account("alice");
    let domain_id = DomainId::try_new("wonderland", "universal").unwrap();
    let domain = Domain::new(domain_id.clone()).build(&authority);
    let account = build_fixture_account(&authority, &authority);
    let asset_def_id = AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        "rose".parse().expect("asset name"),
    );
    let asset_def = AssetDefinition::numeric(
        asset_def_id.clone(),
        "rose".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&authority);
    let full_asset_definition_bytes =
        norito::to_bytes(&asset_def).expect("encode full asset definition");
    let projected_asset_definition_bytes = norito::to_bytes(&Some(
        CoreHost::project_asset_definition(asset_def.clone()).expect("project definition"),
    ))
    .expect("encode projected asset definition");
    assert!(
        projected_asset_definition_bytes.len() < full_asset_definition_bytes.len(),
        "typed projection must be smaller than the full asset definition"
    );
    let asset_id = AssetId::of(asset_def_id.clone(), authority.clone());
    let asset = Asset::new(asset_id.clone(), Quantity::from(7_u32));
    let nft_id: NftId = "ticket$wonderland.universal".parse().expect("nft id");
    let nft = Nft::new(nft_id.clone(), Metadata::default()).build(&authority);
    let world = World::with_assets([domain], [account], [asset_def], [asset], [nft]);
    let state = contract_test_state_with_world(&authority, world);
    let contract_address = install_contract(
        &state,
        &authority,
        r#"
seiyaku DedicatedQueryContract {
  view fn main() authorize(anyone) -> int { return 0; }
}
"#,
        0,
    );
    let code_hash = *state
        .view()
        .world()
        .contract_instances()
        .get(&contract_address)
        .expect("installed query contract binding");
    let alias: ContractAlias = "router::universal".parse().expect("contract alias");
    let next_height = u64::try_from(state.view().height() + 1)
        .ok()
        .and_then(core::num::NonZeroU64::new)
        .expect("next block height");
    let mut block = state.block(BlockHeader::new(next_height, None, None, 0, 0));
    let mut tx = block.transaction();
    tx.world_mut_for_testing().add_account_permission(
        &authority,
        Permission::from(CanManageAccountAlias {
            scope: AccountAliasPermissionScope::Dataspace(DataSpaceId::UNIVERSAL),
        }),
    );
    // This positive fixture reads NFTs and an unrelated missing account through the
    // production native query gate, which requires the ledger-wide read permission.
    tx.world_mut_for_testing().add_account_permission(
        &authority,
        Permission::from(iroha_executor_data_model::permission::query::CanReadAllLedgerData),
    );
    iroha_data_model::isi::SetContractAlias::bind(contract_address.clone(), alias.clone(), None)
        .execute(&authority, &mut tx)
        .expect("bind contract alias");
    tx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit contract alias block");
    let view = state.view();
    let mut host = CoreHostImpl::new(authority.clone());
    host.set_query_state(&view);
    host.enable_core_query_page_metrics();
    let mut vm = IVM::new(1_000_000);
    macro_rules! assert_single_projection {
        ($tag:expr) => {{
            let metrics = host
                .core_query_page_metrics()
                .expect("typed query metrics enabled");
            assert_eq!(metrics.host_queries, 1, "{:?}", $tag);
            assert_eq!(metrics.projection_decodes, 1, "{:?}", $tag);
            assert!(
                metrics.projection_payload_bytes > 0 && metrics.leaf_tlv_bytes > 0,
                "{:?} must execute one host query and decode one non-empty typed projection",
                $tag
            );
        }};
    }
    let account_ptr = store_tlv(&mut vm, PointerType::AccountId, &norito_blob(&authority));
    host.reset_core_query_page_metrics();
    vm.set_register(10, CoreQueryEntityTagV1::Account.as_u64());
    vm.set_register(11, account_ptr);
    host.syscall(ivm_sys::SYSCALL_CORE_QUERY_GET, &mut vm)
        .expect("get account");
    assert_single_projection!(CoreQueryEntityTagV1::Account);
    let (is_some, account_words) =
        read_option_words(&vm, vm.register(10), CoreHost::ACCOUNT_VIEW_WORDS);
    assert!(is_some);
    assert_eq!(account_words.len(), 2);
    let account_out: AccountId = decode_typed_leaf(&vm, account_words[0], PointerType::AccountId);
    assert_eq!(account_out, authority);
    let _: Json = decode_typed_leaf(&vm, account_words[1], PointerType::Json);
    let asset_ptr = store_tlv(&mut vm, PointerType::AssetId, &norito_blob(&asset_id));
    host.reset_core_query_page_metrics();
    vm.set_register(10, CoreQueryEntityTagV1::Asset.as_u64());
    vm.set_register(11, asset_ptr);
    host.syscall(ivm_sys::SYSCALL_CORE_QUERY_GET, &mut vm)
        .expect("get asset");
    assert_single_projection!(CoreQueryEntityTagV1::Asset);
    let (is_some, asset_words) =
        read_option_words(&vm, vm.register(10), CoreHost::ASSET_VIEW_WORDS);
    assert!(is_some);
    let asset_out: AssetId = decode_typed_leaf(&vm, asset_words[0], PointerType::AssetId);
    assert_eq!(asset_out, asset_id);
    let asset_amount = decode_quantity_leaf(&vm, asset_words[1]);
    assert_eq!(asset_amount, Quantity::from(7_u32));
    let asset_def_ptr = store_tlv(
        &mut vm,
        PointerType::AssetDefinitionId,
        &norito_blob(&asset_def_id),
    );
    host.reset_core_query_page_metrics();
    vm.set_register(10, CoreQueryEntityTagV1::AssetDefinition.as_u64());
    vm.set_register(11, asset_def_ptr);
    host.syscall(ivm_sys::SYSCALL_CORE_QUERY_GET, &mut vm)
        .expect("get asset definition");
    assert_single_projection!(CoreQueryEntityTagV1::AssetDefinition);
    let (is_some, definition_words) =
        read_option_words(&vm, vm.register(10), CoreHost::ASSET_DEFINITION_VIEW_WORDS);
    assert!(is_some);
    assert_eq!(definition_words.len(), 7);
    let asset_def_out: AssetDefinitionId =
        decode_typed_leaf(&vm, definition_words[0], PointerType::AssetDefinitionId);
    assert_eq!(asset_def_out, asset_def_id);
    assert_eq!(
        vm.memory
            .validate_tlv(definition_words[1])
            .expect("name blob")
            .type_id,
        PointerType::Blob
    );
    assert_eq!(
        read_option_words(&vm, definition_words[2], 1),
        (false, vec![])
    );
    let _: AccountId = decode_typed_leaf(&vm, definition_words[3], PointerType::AccountId);
    let _ = decode_quantity_leaf(&vm, definition_words[4]);
    let _: Json = decode_typed_leaf(&vm, definition_words[6], PointerType::Json);
    let domain_ptr = store_tlv(&mut vm, PointerType::DomainId, &norito_blob(&domain_id));
    host.reset_core_query_page_metrics();
    vm.set_register(10, CoreQueryEntityTagV1::Domain.as_u64());
    vm.set_register(11, domain_ptr);
    host.syscall(ivm_sys::SYSCALL_CORE_QUERY_GET, &mut vm)
        .expect("get domain");
    assert_single_projection!(CoreQueryEntityTagV1::Domain);
    let (is_some, domain_words) =
        read_option_words(&vm, vm.register(10), CoreHost::DOMAIN_VIEW_WORDS);
    assert!(is_some);
    let domain_out: DomainId = decode_typed_leaf(&vm, domain_words[0], PointerType::DomainId);
    assert_eq!(domain_out, domain_id);
    let _: AccountId = decode_typed_leaf(&vm, domain_words[1], PointerType::AccountId);
    let _: Json = decode_typed_leaf(&vm, domain_words[2], PointerType::Json);
    let nft_ptr = store_tlv(&mut vm, PointerType::NftId, &norito_blob(&nft_id));
    host.reset_core_query_page_metrics();
    vm.set_register(10, CoreQueryEntityTagV1::Nft.as_u64());
    vm.set_register(11, nft_ptr);
    host.syscall(ivm_sys::SYSCALL_CORE_QUERY_GET, &mut vm)
        .expect("get nft");
    assert_single_projection!(CoreQueryEntityTagV1::Nft);
    let (is_some, nft_words) = read_option_words(&vm, vm.register(10), CoreHost::NFT_VIEW_WORDS);
    assert!(is_some);
    let nft_out: NftId = decode_typed_leaf(&vm, nft_words[0], PointerType::NftId);
    assert_eq!(nft_out, nft_id);
    let nft_owner: AccountId = decode_typed_leaf(&vm, nft_words[1], PointerType::AccountId);
    assert_eq!(nft_owner, authority);
    let _: Json = decode_typed_leaf(&vm, nft_words[2], PointerType::Json);
    let missing = fixture_account("bob");
    let missing_ptr = store_tlv(&mut vm, PointerType::AccountId, &norito_blob(&missing));
    vm.set_register(10, CoreQueryEntityTagV1::Account.as_u64());
    vm.set_register(11, missing_ptr);
    host.syscall(ivm_sys::SYSCALL_CORE_QUERY_GET, &mut vm)
        .expect("missing account is an Option::none result");
    assert_eq!(
        read_option_words(&vm, vm.register(10), CoreHost::ACCOUNT_VIEW_WORDS),
        (false, vec![])
    );
    let missing_nft: NftId = "missing$wonderland.universal".parse().expect("NFT id");
    let missing_nft_ptr = store_tlv(&mut vm, PointerType::NftId, &norito_blob(&missing_nft));
    vm.set_register(10, CoreQueryEntityTagV1::Nft.as_u64());
    vm.set_register(11, missing_nft_ptr);
    host.syscall(ivm_sys::SYSCALL_CORE_QUERY_GET, &mut vm)
        .expect("missing NFT is an Option::none result");
    assert_eq!(
        read_option_words(&vm, vm.register(10), CoreHost::NFT_VIEW_WORDS),
        (false, vec![])
    );
    vm.set_register(10, CoreQueryEntityTagV1::Account.as_u64());
    vm.set_register(11, domain_ptr);
    assert!(matches!(
        host.syscall(ivm_sys::SYSCALL_CORE_QUERY_GET, &mut vm),
        Err(ivm::VMError::NoritoInvalid)
    ));
    vm.set_register(10, 0);
    vm.set_register(11, account_ptr);
    assert!(matches!(
        host.syscall(ivm_sys::SYSCALL_CORE_QUERY_GET, &mut vm),
        Err(ivm::VMError::DecodeError)
    ));
    let parameter_name: Name = "block.max_transactions".parse().expect("parameter name");
    let parameter_ptr = store_tlv(&mut vm, PointerType::Name, &norito_blob(&parameter_name));
    vm.set_register(10, parameter_ptr);
    host.syscall(ivm_sys::SYSCALL_QUERY_GET_PARAMETER, &mut vm)
        .expect("get parameter");
    let parameter_tlv = vm
        .memory
        .validate_tlv(vm.register(10))
        .expect("parameter output");
    let parameter_out: Parameter =
        norito::decode_from_bytes(parameter_tlv.payload).expect("decode parameter");
    assert!(matches!(parameter_out, Parameter::Block(_)));
    let output_limit_name: Name = "smart_contract.max_output_items"
        .parse()
        .expect("parameter name");
    let output_limit_ptr = store_tlv(&mut vm, PointerType::Name, &norito_blob(&output_limit_name));
    vm.set_register(10, output_limit_ptr);
    host.syscall(ivm_sys::SYSCALL_QUERY_GET_PARAMETER, &mut vm)
        .expect("get smart-contract output limit");
    let output_limit_tlv = vm
        .memory
        .validate_tlv(vm.register(10))
        .expect("output-limit parameter");
    let output_limit: Parameter =
        norito::decode_from_bytes(output_limit_tlv.payload).expect("decode output limit");
    assert!(matches!(
        output_limit,
        Parameter::SmartContract(SmartContractParameter::MaxOutputItems(_))
    ));
    let retired_untyped_parameter_ptr = store_tlv(
        &mut vm,
        PointerType::NoritoBytes,
        &norito_blob(&parameter_name),
    );
    vm.set_register(10, retired_untyped_parameter_ptr);
    assert!(matches!(
        host.syscall(ivm_sys::SYSCALL_QUERY_GET_PARAMETER, &mut vm),
        Err(ivm::VMError::NoritoInvalid)
    ));
    assert_eq!(vm.register(10), retired_untyped_parameter_ptr);
    let contract_ptr = store_tlv(
        &mut vm,
        PointerType::NoritoBytes,
        &norito_blob(&contract_address),
    );
    vm.set_register(10, contract_ptr);
    host.syscall(ivm_sys::SYSCALL_QUERY_GET_CONTRACT_INSTANCE, &mut vm)
        .expect("get contract instance");
    let contract_tlv = vm
        .memory
        .validate_tlv(vm.register(10))
        .expect("contract instance output");
    let instance_out: ContractInstance =
        norito::decode_from_bytes(contract_tlv.payload).expect("decode contract instance");
    assert_eq!(instance_out.contract_address, contract_address);
    assert_eq!(instance_out.code_hash, code_hash);
    assert_eq!(instance_out.contract_alias, Some(alias.clone()));
    crate::private_settlement::global_state::tests::assert_private_settlement_frame_v1(
        &instance_out,
        "iroha_data_model::smart_contract::model::ContractInstance",
    );
    assert_eq!(
        contract_tlv.payload,
        norito::encode_canonical(&instance_out).expect("shared instance owner frame"),
    );
    let mut wrong_owner = contract_tlv.payload.to_vec();
    wrong_owner[6..22].copy_from_slice(&norito::schema::identity::frame_hash::<ContractAddress>());
    assert!(matches!(
        norito::decode_from_bytes::<ContractInstance>(&wrong_owner),
        Err(norito::Error::SchemaMismatch),
    ));
    let alias_name: Name = alias.as_ref().parse().expect("alias name pointer");
    let alias_ptr = store_tlv(&mut vm, PointerType::Name, &norito_blob(&alias_name));
    vm.set_register(10, alias_ptr);
    host.syscall(ivm_sys::SYSCALL_QUERY_GET_CONTRACT_INSTANCE, &mut vm)
        .expect("get contract instance by alias");
    let alias_contract_tlv = vm
        .memory
        .validate_tlv(vm.register(10))
        .expect("contract alias output");
    let alias_instance_out: ContractInstance =
        norito::decode_from_bytes(alias_contract_tlv.payload)
            .expect("decode contract alias instance");
    assert_eq!(alias_instance_out.contract_address, contract_address);
    assert_eq!(alias_instance_out.code_hash, code_hash);
    assert_eq!(alias_instance_out.contract_alias, Some(alias));
    let retired_untyped_alias_ptr =
        store_tlv(&mut vm, PointerType::NoritoBytes, &norito_blob(&alias_name));
    vm.set_register(10, retired_untyped_alias_ptr);
    assert!(matches!(
        host.syscall(ivm_sys::SYSCALL_QUERY_GET_CONTRACT_INSTANCE, &mut vm),
        Err(ivm::VMError::NoritoInvalid)
    ));
    assert_eq!(vm.register(10), retired_untyped_alias_ptr);
}
#[test]
fn core_query_get_respects_user_executor_denial_for_every_entity() {
    let authority: AccountId = fixture_account("alice");
    let domain_id = DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain = Domain::new(domain_id.clone()).build(&authority);
    let account = build_fixture_account(&authority, &authority);
    let asset_definition_id = AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        "rose".parse().expect("asset name"),
    );
    let asset_definition = AssetDefinition::numeric(
        asset_definition_id.clone(),
        "rose".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&authority);
    let asset_id = AssetId::of(asset_definition_id.clone(), authority.clone());
    let asset = Asset::new(asset_id.clone(), Quantity::from(7_u32));
    let nft_id: NftId = "ticket$wonderland.universal".parse().expect("NFT id");
    let nft = Nft::new(nft_id.clone(), Metadata::default()).build(&authority);
    let missing_account = fixture_account("bob");
    let missing_asset_id = AssetId::of(asset_definition_id.clone(), missing_account.clone());
    let missing_asset_definition_id = AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        "missing".parse().expect("asset name"),
    );
    let missing_domain_id = DomainId::try_new("missing", "universal").expect("missing domain id");
    let missing_nft_id: NftId = "missing$wonderland.universal".parse().expect("NFT id");
    let world = World::with_assets([domain], [account], [asset_definition], [asset], [nft]);
    {
        let mut executor_block = world.executor.block();
        *executor_block.get_mut() =
            crate::executor::denying_executor_for_testing("queries disabled");
        executor_block.commit();
    }
    let state = State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let view = state.view();
    let mut host = CoreHostImpl::new(authority.clone());
    host.set_query_state(&view);
    let cases = [
        (
            CoreQueryEntityTagV1::Account,
            PointerType::AccountId,
            [norito_blob(&authority), norito_blob(&missing_account)],
        ),
        (
            CoreQueryEntityTagV1::Asset,
            PointerType::AssetId,
            [norito_blob(&asset_id), norito_blob(&missing_asset_id)],
        ),
        (
            CoreQueryEntityTagV1::AssetDefinition,
            PointerType::AssetDefinitionId,
            [
                norito_blob(&asset_definition_id),
                norito_blob(&missing_asset_definition_id),
            ],
        ),
        (
            CoreQueryEntityTagV1::Domain,
            PointerType::DomainId,
            [norito_blob(&domain_id), norito_blob(&missing_domain_id)],
        ),
        (
            CoreQueryEntityTagV1::Nft,
            PointerType::NftId,
            [norito_blob(&nft_id), norito_blob(&missing_nft_id)],
        ),
    ];
    for (tag, pointer_type, payloads) in cases {
        for (presence, payload) in ["present", "missing"].into_iter().zip(payloads) {
            let mut vm = IVM::new(1_000_000);
            let id_pointer = store_tlv(&mut vm, pointer_type, &payload);
            vm.set_register(10, tag.as_u64());
            vm.set_register(11, id_pointer);
            let error = host
                .syscall(ivm_sys::SYSCALL_CORE_QUERY_GET, &mut vm)
                .expect_err("deny-all executor must reject typed entity reads");
            assert_eq!(
                error,
                ivm::VMError::PermissionDenied,
                "{presence} entity {tag:?}",
            );
            assert_eq!(
                vm.register(10),
                tag.as_u64(),
                "denied {presence} {tag:?} query must not publish an output handle",
            );
            assert_eq!(
                vm.register(11),
                id_pointer,
                "denied {presence} {tag:?} query must preserve its input pointer",
            );
        }
    }
}
#[test]
fn core_query_page_request_encodes_canonical_account_components() {
    let QueryRequest::Start(query) =
        CoreHost::core_query_page_request(CoreQueryEntityTagV1::Account, 3, 2, None)
            .expect("build account page request")
    else {
        panic!("typed account page must use an iterable start request");
    };
    assert_eq!(query.item, QueryItemKind::Account);
    assert_eq!(
        query.query_payload,
        norito::codec::Encode::encode(&FindAccounts)
    );
    assert_eq!(
        query.predicate_bytes,
        norito::codec::Encode::encode(&CompoundPredicate::<Account>::PASS)
    );
    assert_eq!(
        query.selector_bytes,
        norito::codec::Encode::encode(&SelectorTuple::<Account>::default())
    );
    assert_eq!(query.params.pagination.offset_value(), 3);
    assert_eq!(
        query.params.fetch_size.fetch_size.map(NonZeroU64::get),
        Some(2)
    );
}
#[test]
fn core_query_page_respects_user_executor_denial_for_every_entity() {
    let authority: AccountId = fixture_account("alice");
    let account = build_fixture_account(&authority, &authority);
    let world = World::with([], [account], []);
    {
        let mut executor_block = world.executor.block();
        *executor_block.get_mut() =
            crate::executor::denying_executor_for_testing("queries disabled");
        executor_block.commit();
    }
    let state = State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let view = state.view();
    let mut host = CoreHostImpl::new(authority.clone());
    host.set_query_state(&view);
    for tag in [
        CoreQueryEntityTagV1::Account,
        CoreQueryEntityTagV1::Asset,
        CoreQueryEntityTagV1::AssetDefinition,
        CoreQueryEntityTagV1::Domain,
        CoreQueryEntityTagV1::Nft,
    ] {
        let mut vm = IVM::new(1_000_000);
        vm.set_register(10, tag.as_u64());
        vm.set_register(11, 0);
        vm.set_register(12, 1);
        let error = host
            .syscall(ivm_sys::SYSCALL_CORE_QUERY_PAGE, &mut vm)
            .expect_err("deny-all executor must reject typed page reads");
        assert_eq!(error, ivm::VMError::PermissionDenied, "entity {tag:?}");
        assert_eq!(
            vm.register(10),
            tag.as_u64(),
            "denied {tag:?} page must not publish a list handle",
        );
        assert_eq!(
            vm.register(11),
            0,
            "denied {tag:?} page must preserve its offset input",
        );
        assert_eq!(
            vm.register(12),
            1,
            "denied {tag:?} page must preserve its limit input",
        );
    }
}
#[test]
fn core_query_page_is_bounded_ordered_and_validates_arguments() {
    let authority = fixture_account("alice");
    let ids = [
        authority.clone(),
        fixture_account("bob"),
        fixture_account("carol"),
    ];
    let mut expected_ids = ids.to_vec();
    expected_ids.sort();
    let accounts = ids
        .iter()
        .map(|id| build_fixture_account(id, &authority))
        .collect::<Vec<_>>();
    let world = ledger_reader_world_for_core_query_tests(World::with([], accounts, []), &authority);
    let state = State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let view = state.view();
    let mut host = CoreHostImpl::new(authority.clone());
    host.set_query_state(&view);
    host.enable_core_query_page_metrics();
    let mut vm = IVM::new(1_000_000);
    vm.set_register(10, CoreQueryEntityTagV1::Account.as_u64());
    vm.set_register(11, 0);
    vm.set_register(12, 1);
    let gas = host
        .syscall(ivm_sys::SYSCALL_CORE_QUERY_PAGE, &mut vm)
        .expect("first account page");
    let list_layout = ivm::list::ListLayoutV1::try_new(
        QUERY_PAGE_CAPACITY_V1 as u64,
        CoreHost::ACCOUNT_VIEW_WORDS,
    )
    .expect("account page layout");
    let first = ivm::list::read_words(&vm, vm.register(10), list_layout).expect("read first page");
    assert_eq!(first.len(), 1);
    let first_id: AccountId = decode_typed_leaf(&vm, first[0][0], PointerType::AccountId);
    assert_eq!(first_id, expected_ids[0]);
    assert_eq!(read_option_int(&vm, vm.register(11)), Some(1));
    let request = CoreHost::core_query_page_request(CoreQueryEntityTagV1::Account, 0, 1, None)
        .expect("page request");
    let gas_ctx = QueryGasContext::from_request(&request);
    let expected_execution = execute_bounded_query_on_state_with_budget(
        &view,
        &authority,
        request,
        Some(
            CoreHost::query_execution_budget(&gas_ctx, 1_000_000).expect("query execution budget"),
        ),
    )
    .expect("measure bounded query execution");
    let metrics = host
        .core_query_page_metrics()
        .expect("typed page metrics enabled");
    assert_eq!(
        gas,
        CoreHost::query_gas_cost(
            &gas_ctx,
            expected_execution.processed_items,
            expected_execution
                .processed_bytes
                .saturating_add(metrics.projection_payload_bytes)
                .saturating_add(metrics.leaf_tlv_bytes),
        ),
        "one-item pages must charge the returned item, one lookahead, and every encoded leaf"
    );
    vm.set_register(10, CoreQueryEntityTagV1::Account.as_u64());
    vm.set_register(11, 1);
    vm.set_register(12, 1);
    host.syscall(ivm_sys::SYSCALL_CORE_QUERY_PAGE, &mut vm)
        .expect("second account page");
    let second =
        ivm::list::read_words(&vm, vm.register(10), list_layout).expect("read second page");
    let second_id: AccountId = decode_typed_leaf(&vm, second[0][0], PointerType::AccountId);
    assert_eq!(second_id, expected_ids[1]);
    assert_eq!(read_option_int(&vm, vm.register(11)), Some(2));
    vm.set_register(10, CoreQueryEntityTagV1::Account.as_u64());
    vm.set_register(11, 2);
    vm.set_register(12, 1);
    host.syscall(ivm_sys::SYSCALL_CORE_QUERY_PAGE, &mut vm)
        .expect("final account page");
    let final_page =
        ivm::list::read_words(&vm, vm.register(10), list_layout).expect("read final page");
    let final_id: AccountId = decode_typed_leaf(&vm, final_page[0][0], PointerType::AccountId);
    assert_eq!(final_id, expected_ids[2]);
    assert_eq!(read_option_int(&vm, vm.register(11)), None);
    vm.set_register(10, CoreQueryEntityTagV1::Account.as_u64());
    vm.set_register(11, 0);
    vm.set_register(12, QUERY_PAGE_CAPACITY_V1 as u64);
    host.syscall(ivm_sys::SYSCALL_CORE_QUERY_PAGE, &mut vm)
        .expect("maximum-capacity account page");
    let maximum_page = ivm::list::read_words(&vm, vm.register(10), list_layout)
        .expect("read maximum-capacity page");
    assert_eq!(maximum_page.len(), expected_ids.len());
    assert_eq!(read_option_int(&vm, vm.register(11)), None);
    for (tag, offset_bits, limit) in [
        (0, 0, 1),
        (CoreQueryEntityTagV1::Account.as_u64(), (-1_i64) as u64, 1),
        (
            CoreQueryEntityTagV1::Account.as_u64(),
            (i64::MAX - 1) as u64,
            2,
        ),
        (CoreQueryEntityTagV1::Account.as_u64(), 0, 0),
        (CoreQueryEntityTagV1::Account.as_u64(), 0, 65),
    ] {
        vm.set_register(10, tag);
        vm.set_register(11, offset_bits);
        vm.set_register(12, limit);
        assert!(matches!(
            host.syscall(ivm_sys::SYSCALL_CORE_QUERY_PAGE, &mut vm),
            Err(ivm::VMError::DecodeError)
        ));
    }
}

#[test]
fn typed_asset_definition_query_returns_native_constrained_and_unconstrained_scale() {
    for (spec, expected) in [
        (iroha_primitives::numeric::NumericSpec::integer(), Some(0)),
        (
            iroha_primitives::numeric::NumericSpec::fractional(2),
            Some(2),
        ),
        (
            iroha_primitives::numeric::NumericSpec::fractional(18),
            Some(18),
        ),
        (
            iroha_primitives::numeric::NumericSpec::unconstrained(),
            None,
        ),
    ] {
        let authority = fixture_account("alice");
        let domain_id = DomainId::try_new("precision", "universal").unwrap();
        let id =
            AssetDefinitionId::derive_from_components(domain_id.clone(), "unit".parse().unwrap());
        let definition = AssetDefinition::new(
            id.clone(),
            "unit",
            spec,
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&authority);
        let world = World::with(
            [Domain::new(domain_id).build(&authority)],
            [Account::new(authority.clone()).build(&authority)],
            [definition],
        );
        let state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let view = state.view();
        let mut host = CoreHostImpl::new(authority);
        host.set_query_state(&view);
        let mut vm = IVM::new(1_000_000);
        let pointer = store_tlv(&mut vm, PointerType::AssetDefinitionId, &norito_blob(&id));
        vm.set_register(10, CoreQueryEntityTagV1::AssetDefinition.as_u64());
        vm.set_register(11, pointer);
        host.syscall(ivm_sys::SYSCALL_CORE_QUERY_GET, &mut vm)
            .expect("native typed definition query");
        let (some, words) = ivm::sum::read_words(
            &vm,
            vm.register(10),
            ivm::sum::SumLayoutV1::option(CoreHost::ASSET_DEFINITION_VIEW_WORDS).unwrap(),
        )
        .unwrap();
        assert!(some);
        let (has_scale, scale_words) =
            ivm::sum::read_words(&vm, words[5], ivm::sum::SumLayoutV1::option(1).unwrap()).unwrap();
        assert_eq!(has_scale, expected.is_some());
        if let Some(scale) = expected {
            let value = vm.memory.validate_tlv(scale_words[0]).unwrap();
            assert_eq!(value.type_id, PointerType::Int);
            assert_eq!(
                IntValueV1::decode_frame(value.payload).unwrap().into_int(),
                BigInt::from(scale)
            );
        }
    }
}

#[test]
fn account_asset_pages_filter_before_pagination_and_enforce_account_access() {
    let alice = fixture_account("alice");
    let bob = fixture_account("bob");
    let domain_id = DomainId::try_new("wonderland", "universal").expect("domain");
    let domain = Domain::new(domain_id.clone()).build(&alice);
    let mut definitions = Vec::new();
    let mut assets = Vec::new();
    let mut expected = Vec::new();
    for name in ["rose", "tulip", "lily"] {
        let id = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            name.parse().expect("asset name"),
        );
        definitions.push(
            AssetDefinition::numeric(
                id.clone(),
                name.to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
            .build(&alice),
        );
        for owner in [&alice, &bob] {
            let asset_id = AssetId::of(id.clone(), owner.clone());
            if owner == &alice {
                expected.push(asset_id.clone());
            }
            assets.push(Asset::new(asset_id, Quantity::from(7_u32)));
        }
    }
    expected.sort();
    let world = World::with_assets(
        [domain],
        [
            build_fixture_account(&alice, &alice),
            build_fixture_account(&bob, &alice),
        ],
        definitions,
        assets,
        [],
    );
    let state = State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let view = state.view();
    let mut host = CoreHostImpl::new(alice.clone());
    host.set_query_state(&view);
    let mut vm = IVM::new(1_000_000);
    let alice_pointer = store_tlv(&mut vm, PointerType::AccountId, &norito_blob(&alice));
    let bob_pointer = store_tlv(&mut vm, PointerType::AccountId, &norito_blob(&bob));
    let layout =
        ivm::list::ListLayoutV1::try_new(QUERY_PAGE_CAPACITY_V1 as u64, CoreHost::ASSET_VIEW_WORDS)
            .expect("asset page layout");
    for (offset, expected_id) in expected.iter().enumerate() {
        vm.set_register(10, CoreQueryEntityTagV1::Asset.as_u64());
        vm.set_register(11, offset as u64);
        vm.set_register(12, 1);
        vm.set_register(13, alice_pointer);
        host.syscall(ivm_sys::SYSCALL_CORE_QUERY_PAGE, &mut vm)
            .expect("an account can read its own asset page without all-ledger permission");
        let rows = ivm::list::read_words(&vm, vm.register(10), layout).expect("asset rows");
        assert_eq!(rows.len(), 1);
        let id: AssetId = decode_typed_leaf(&vm, rows[0][0], PointerType::AssetId);
        assert_eq!(&id, expected_id);
        assert_eq!(
            read_option_int(&vm, vm.register(11)),
            (offset + 1 < expected.len()).then_some((offset + 1) as i64)
        );
    }
    for owner in [0, bob_pointer] {
        vm.set_register(10, CoreQueryEntityTagV1::Asset.as_u64());
        vm.set_register(11, 0);
        vm.set_register(12, 1);
        vm.set_register(13, owner);
        assert_eq!(
            host.syscall(ivm_sys::SYSCALL_CORE_QUERY_PAGE, &mut vm),
            Err(ivm::VMError::PermissionDenied)
        );
        assert_eq!(vm.register(10), CoreQueryEntityTagV1::Asset.as_u64());
    }
    vm.set_register(10, CoreQueryEntityTagV1::Account.as_u64());
    vm.set_register(13, alice_pointer);
    assert_eq!(
        host.syscall(ivm_sys::SYSCALL_CORE_QUERY_PAGE, &mut vm),
        Err(ivm::VMError::DecodeError)
    );
}

#[test]
fn account_asset_page_request_uses_native_scoped_query_and_rejects_other_entities() {
    let account = fixture_account("alice");
    let QueryRequest::Start(request) =
        CoreHost::core_query_page_request(CoreQueryEntityTagV1::Asset, 2, 1, Some(account.clone()))
            .expect("scoped request")
    else {
        panic!("iterable request");
    };
    assert_eq!(
        request.query_payload,
        norito::codec::Encode::encode(
            &iroha_data_model::query::asset::prelude::FindAssetsByAccountId::new(account.clone()),
        )
    );
    assert_eq!(request.params.pagination.offset_value(), 2);
    for tag in [
        CoreQueryEntityTagV1::Account,
        CoreQueryEntityTagV1::AssetDefinition,
        CoreQueryEntityTagV1::Domain,
        CoreQueryEntityTagV1::Nft,
    ] {
        assert!(matches!(
            CoreHost::core_query_page_request(tag, 0, 1, Some(account.clone())),
            Err(ivm::VMError::DecodeError)
        ));
    }
}
