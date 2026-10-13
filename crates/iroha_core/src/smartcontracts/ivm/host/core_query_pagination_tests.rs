#[test]
fn every_core_query_page_family_uses_canonical_id_order_and_next_offset() {
    let authority = fixture_account("alice");
    let second_account = fixture_account("bob");
    let domain_ids = [
        DomainId::try_new("alpha", "universal").expect("alpha domain"),
        DomainId::try_new("beta", "universal").expect("beta domain"),
    ];
    let domains = domain_ids
        .iter()
        .rev()
        .cloned()
        .map(|id| Domain::new(id).build(&authority))
        .collect::<Vec<_>>();
    let asset_definition_ids = [
        AssetDefinitionId::derive_from_components(
            domain_ids[0].clone(),
            "coin".parse().expect("asset name"),
        ),
        AssetDefinitionId::derive_from_components(
            domain_ids[1].clone(),
            "coin".parse().expect("asset name"),
        ),
    ];
    let asset_definitions = asset_definition_ids
        .iter()
        .rev()
        .cloned()
        .map(|id| {
            AssetDefinition::numeric(
                id,
                "coin".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
            .build(&authority)
        })
        .collect::<Vec<_>>();
    let asset_ids = asset_definition_ids
        .iter()
        .cloned()
        .map(|definition| AssetId::of(definition, authority.clone()))
        .collect::<Vec<_>>();
    let assets = asset_ids
        .iter()
        .rev()
        .cloned()
        .enumerate()
        .map(|(index, id)| {
            let amount = u32::try_from(index)
                .expect("two-asset fixture index")
                .saturating_add(1);
            Asset::new(id, Quantity::from(amount))
        })
        .collect::<Vec<_>>();
    let nft_ids = [
        "ticket$alpha.universal"
            .parse::<NftId>()
            .expect("alpha NFT"),
        "ticket$beta.universal".parse::<NftId>().expect("beta NFT"),
    ];
    let nfts = nft_ids
        .iter()
        .rev()
        .cloned()
        .map(|id| Nft::new(id, Metadata::default()).build(&authority))
        .collect::<Vec<_>>();
    let accounts = [
        build_fixture_account(&second_account, &authority),
        build_fixture_account(&authority, &authority),
    ];
    let world = ledger_reader_world_for_core_query_tests(
        World::with_assets(domains, accounts, asset_definitions, assets, nfts),
        &authority,
    );
    let state = State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let view = state.view();
    let mut host = CoreHostImpl::new(authority.clone());
    host.set_query_state(&view);
    host.enable_core_query_page_metrics();
    let mut vm = IVM::new(2_000_000);
    let mut account_ids = vec![authority, second_account];
    account_ids.sort();
    let mut sorted_domain_ids = domain_ids.to_vec();
    sorted_domain_ids.sort();
    let mut sorted_definition_ids = asset_definition_ids.to_vec();
    sorted_definition_ids.sort();
    let mut sorted_asset_ids = asset_ids;
    sorted_asset_ids.sort();
    let mut sorted_nft_ids = nft_ids.to_vec();
    sorted_nft_ids.sort();
    let families = [
        (
            CoreQueryEntityTagV1::Account,
            CoreHost::ACCOUNT_VIEW_WORDS,
            PointerType::AccountId,
            account_ids.iter().map(norito_blob).collect::<Vec<_>>(),
        ),
        (
            CoreQueryEntityTagV1::Asset,
            CoreHost::ASSET_VIEW_WORDS,
            PointerType::AssetId,
            sorted_asset_ids.iter().map(norito_blob).collect::<Vec<_>>(),
        ),
        (
            CoreQueryEntityTagV1::AssetDefinition,
            CoreHost::ASSET_DEFINITION_VIEW_WORDS,
            PointerType::AssetDefinitionId,
            sorted_definition_ids
                .iter()
                .map(norito_blob)
                .collect::<Vec<_>>(),
        ),
        (
            CoreQueryEntityTagV1::Domain,
            CoreHost::DOMAIN_VIEW_WORDS,
            PointerType::DomainId,
            sorted_domain_ids
                .iter()
                .map(norito_blob)
                .collect::<Vec<_>>(),
        ),
        (
            CoreQueryEntityTagV1::Nft,
            CoreHost::NFT_VIEW_WORDS,
            PointerType::NftId,
            sorted_nft_ids.iter().map(norito_blob).collect::<Vec<_>>(),
        ),
    ];
    for (tag, words_per_item, id_type, expected_ids) in families {
        assert_eq!(expected_ids.len(), 2, "two-item {tag:?} fixture");
        let layout =
            ivm::list::ListLayoutV1::try_new(QUERY_PAGE_CAPACITY_V1 as u64, words_per_item)
                .expect("typed page list layout");
        for (offset, expected) in expected_ids.iter().enumerate() {
            host.reset_core_query_page_metrics();
            vm.set_register(10, tag.as_u64());
            vm.set_register(11, u64::try_from(offset).expect("offset"));
            vm.set_register(12, 1);
            let gas = host
                .syscall(ivm_sys::SYSCALL_CORE_QUERY_PAGE, &mut vm)
                .unwrap_or_else(|error| panic!("{tag:?} page {offset}: {error:?}"));
            let page =
                ivm::list::read_words(&vm, vm.register(10), layout).expect("read typed page");
            assert_eq!(page.len(), 1, "{tag:?} page {offset}");
            let id = vm
                .memory
                .validate_tlv(page[0][0])
                .expect("typed page ID leaf");
            assert_eq!(id.type_id, id_type, "{tag:?} page {offset}");
            assert_eq!(id.payload, expected, "{tag:?} page {offset}");
            let metrics = host
                .core_query_page_metrics()
                .expect("typed page metrics enabled");
            assert_eq!(metrics.host_queries, 1, "{tag:?} page {offset}");
            assert_eq!(metrics.projection_decodes, 1, "{tag:?} page {offset}");
            assert!(
                metrics.projection_payload_bytes > 0 && metrics.leaf_tlv_bytes > 0,
                "{tag:?} page {offset} must encode one projection and its typed leaves once"
            );
            assert_eq!(
                read_option_int(&vm, vm.register(11)),
                if offset == 0 { Some(1) } else { None },
                "{tag:?} next_offset at page {offset}"
            );
            host.reset_core_query_page_metrics();
            let mut repeated_vm = IVM::new(2_000_000);
            repeated_vm.set_register(10, tag.as_u64());
            repeated_vm.set_register(11, u64::try_from(offset).expect("offset"));
            repeated_vm.set_register(12, 1);
            let repeated_gas = host
                .syscall(ivm_sys::SYSCALL_CORE_QUERY_PAGE, &mut repeated_vm)
                .unwrap_or_else(|error| panic!("repeated {tag:?} page {offset}: {error:?}"));
            let repeated_metrics = host
                .core_query_page_metrics()
                .expect("typed page metrics enabled");
            assert_eq!(
                repeated_gas, gas,
                "{tag:?} page {offset} gas must be deterministic"
            );
            assert_eq!(
                repeated_metrics, metrics,
                "{tag:?} page {offset} must repeat exactly one query, one projection decode, and the same projected byte counts"
            );
        }
    }
}
#[test]
fn v1_core_query_gas_schedule_golden() {
    let context = QueryGasContext {
        base: CoreHost::QUERY_GAS_BASE_ITERABLE,
        per_item: CoreHost::QUERY_GAS_PER_ITEM,
        offset_items: 3,
    };
    assert_eq!(
        CoreHost::query_gas_cost(&context, 2, 100),
        3_950,
        "V1 core-query gas charges base, processed and offset items, then encoded bytes"
    );
}
#[test]
fn block_height_sysvar_uses_attached_transaction_context() {
    let authority: AccountId = fixture_account("alice");
    let world = World::new();
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = State::new_for_testing(world, kura, query);
    let header = BlockHeader::new(nonzero!(9_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let tx = block.transaction();
    let mut host = CoreHostImpl::new(authority);
    host.set_query_state(&tx);
    let mut vm = IVM::new(10_000);
    assert_eq!(
        (host.syscall(ivm_sys::SYSCALL_SYSVAR_BLOCK_HEIGHT, &mut vm))
            .expect("expected successful VM operation"),
        CoreHost::sysvar_gas(0)
    );
    assert_eq!(vm.register(10), 9);
}
#[test]
fn execute_query_syscall_charges_sorted_queries_by_scanned_items() {
    let authority: AccountId = fixture_account("alice");
    let domain: Domain =
        Domain::new(DomainId::try_new("wonderland", "universal").unwrap()).build(&authority);
    let accounts = vec![
        build_fixture_account(&authority, &authority),
        build_fixture_account(&fixture_account("bob"), &authority),
        build_fixture_account(&fixture_account("carol"), &authority),
    ];
    let world =
        ledger_reader_world_for_core_query_tests(World::with([domain], accounts, []), &authority);
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = State::new_for_testing(world, kura, query);
    let view = state.view();
    let mut host = CoreHostImpl::new(authority.clone());
    host.set_query_state(&view);
    let mut vm = IVM::new(1_000_000);
    let sort_key: Name = "rank".parse().unwrap();
    let params = QueryParams {
        pagination: Pagination::new(Some(nonzero!(1_u64)), 0),
        sorting: Sorting::by_metadata_key(sort_key),
        fetch_size: FetchSize::new(Some(nonzero!(1_u64))),
    };
    let request = QueryRequest::Start(QueryWithParams {
        query: (),
        query_payload: norito::codec::Encode::encode(&FindAccounts),
        item: QueryItemKind::Account,
        predicate_bytes: norito::codec::Encode::encode(&CompoundPredicate::<Account>::PASS),
        selector_bytes: norito::codec::Encode::encode(&SelectorTuple::<Account>::default()),
        params,
    });
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
    .expect("measure sorted query execution");
    let ptr = store_tlv(&mut vm, PointerType::NoritoBytes, &request_bytes);
    vm.set_register(10, ptr);
    let gas = host
        .syscall(ivm_sys::SYSCALL_SMARTCONTRACT_EXECUTE_QUERY, &mut vm)
        .expect("query syscall");
    let out_ptr = vm.register(10);
    let tlv = vm.memory.validate_tlv(out_ptr).expect("output tlv");
    let response: QueryResponse = norito::decode_from_bytes(tlv.payload).expect("decode response");
    let QueryResponse::Iterable(output) = response else {
        panic!("expected iterable query response");
    };
    assert_eq!(output.batch.len(), 1);
    assert_eq!(output.remaining_items, Some(0));
    let expected = CoreHost::query_gas_cost(
        &gas_ctx,
        expected_execution.processed_items,
        expected_execution.processed_bytes,
    );
    assert_eq!(gas, expected);
}
#[test]
fn execute_query_syscall_sorted_offset_ignores_offset_penalty() {
    let authority: AccountId = fixture_account("alice");
    let domain: Domain =
        Domain::new(DomainId::try_new("wonderland", "universal").unwrap()).build(&authority);
    let accounts = vec![
        build_fixture_account(&authority, &authority),
        build_fixture_account(&fixture_account("bob"), &authority),
        build_fixture_account(&fixture_account("carol"), &authority),
    ];
    let world =
        ledger_reader_world_for_core_query_tests(World::with([domain], accounts, []), &authority);
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = State::new_for_testing(world, kura, query);
    let view = state.view();
    let mut host = CoreHostImpl::new(authority.clone());
    host.set_query_state(&view);
    let mut vm = IVM::new(1_000_000);
    let sort_key: Name = "rank".parse().unwrap();
    let params = QueryParams {
        pagination: Pagination::new(Some(nonzero!(1_u64)), 2),
        sorting: Sorting::by_metadata_key(sort_key),
        fetch_size: FetchSize::new(Some(nonzero!(1_u64))),
    };
    let request = QueryRequest::Start(QueryWithParams {
        query: (),
        query_payload: norito::codec::Encode::encode(&FindAccounts),
        item: QueryItemKind::Account,
        predicate_bytes: norito::codec::Encode::encode(&CompoundPredicate::<Account>::PASS),
        selector_bytes: norito::codec::Encode::encode(&SelectorTuple::<Account>::default()),
        params,
    });
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
    .expect("measure sorted-offset query execution");
    let ptr = store_tlv(&mut vm, PointerType::NoritoBytes, &request_bytes);
    vm.set_register(10, ptr);
    let gas = host
        .syscall(ivm_sys::SYSCALL_SMARTCONTRACT_EXECUTE_QUERY, &mut vm)
        .expect("query syscall");
    let out_ptr = vm.register(10);
    let tlv = vm.memory.validate_tlv(out_ptr).expect("output tlv");
    assert_eq!(tlv.type_id, PointerType::NoritoBytes);
    let response: QueryResponse = norito::decode_from_bytes(tlv.payload).expect("decode response");
    let QueryResponse::Iterable(output) = response else {
        panic!("expected iterable query response");
    };
    assert_eq!(output.batch.len(), 1);
    assert_eq!(output.remaining_items, Some(0));
    let expected = CoreHost::query_gas_cost(
        &gas_ctx,
        expected_execution.processed_items,
        expected_execution.processed_bytes,
    );
    assert_eq!(gas, expected);
}
#[test]
fn execute_query_syscall_out_of_gas_when_budget_exhausted() {
    let world = World::new();
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = State::new_for_testing(world, kura, query);
    let authority: AccountId = fixture_account("alice");
    let view = state.view();
    let mut host = CoreHostImpl::new(authority);
    host.set_query_state(&view);
    let mut vm = IVM::new(CoreHost::QUERY_GAS_BASE_SINGULAR - 1);
    let request = QueryRequest::Singular(SingularQueryBox::FindParameters(FindParameters));
    let request_bytes = norito::to_bytes(&request).expect("encode query request");
    let ptr = store_tlv(&mut vm, PointerType::NoritoBytes, &request_bytes);
    vm.set_register(10, ptr);
    let err = host
        .syscall(ivm_sys::SYSCALL_SMARTCONTRACT_EXECUTE_QUERY, &mut vm)
        .expect_err("query should run out of gas");
    assert!(matches!(err, ivm::VMError::OutOfGas));
}
#[test]
fn execute_query_syscall_out_of_gas_when_response_bytes_exceed_budget() {
    let authority: AccountId = fixture_account("alice");
    let world = ledger_reader_world_for_core_query_tests(World::new(), &authority);
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = State::new_for_testing(world, kura, query);
    let view = state.view();
    let mut host = CoreHostImpl::new(authority);
    host.set_query_state(&view);
    let mut vm = IVM::new(CoreHost::QUERY_GAS_BASE_SINGULAR + CoreHost::QUERY_GAS_PER_ITEM);
    let request = QueryRequest::Singular(SingularQueryBox::FindParameters(FindParameters));
    let request_bytes = norito::to_bytes(&request).expect("encode query request");
    let ptr = store_tlv(&mut vm, PointerType::NoritoBytes, &request_bytes);
    vm.set_register(10, ptr);
    let err = host
        .syscall(ivm_sys::SYSCALL_SMARTCONTRACT_EXECUTE_QUERY, &mut vm)
        .expect_err("query should run out of gas on response bytes");
    assert!(matches!(err, ivm::VMError::OutOfGas));
}
#[test]
fn execute_query_syscall_rejects_continue_request() {
    let world = World::new();
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = State::new_for_testing(world, kura, query);
    let authority: AccountId = fixture_account("alice");
    let view = state.view();
    let mut host = CoreHostImpl::new(authority);
    host.set_query_state(&view);
    let mut vm = IVM::new(1_000_000);
    let cursor = ForwardCursor {
        query: "ivm-cursor".to_string(),
        cursor: nonzero!(1_u64),
        gas_budget: None,
    };
    let request = QueryRequest::Continue(cursor);
    let request_bytes = norito::to_bytes(&request).expect("encode query request");
    let ptr = store_tlv(&mut vm, PointerType::NoritoBytes, &request_bytes);
    vm.set_register(10, ptr);
    let err = host
        .syscall(ivm_sys::SYSCALL_SMARTCONTRACT_EXECUTE_QUERY, &mut vm)
        .expect_err("continue should be rejected");
    assert!(matches!(err, ivm::VMError::PermissionDenied));
}

#[test]
fn dispatched_failed_query_consumes_its_fail_closed_reserve() {
    let state = State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let view = state.view();
    let mut host = CoreHostImpl::new(fixture_account("alice"));
    host.set_query_state(&view);
    let code = [
        ivm::encoding::wide::encode_sys(
            ivm::instruction::wide::system::SCALL,
            u8::try_from(ivm_sys::SYSCALL_SMARTCONTRACT_EXECUTE_QUERY).expect("syscall fits"),
        )
        .to_le_bytes(),
        ivm::encoding::wide::encode_halt().to_le_bytes(),
    ]
    .concat();
    let mut vm = IVM::new(10_000);
    vm.load_program(&build_program(&code, 0))
        .expect("load query program");
    let request = QueryRequest::Continue(ForwardCursor {
        query: "ivm-cursor".to_owned(),
        cursor: nonzero!(1_u64),
        gas_budget: None,
    });
    let request_bytes = norito::to_bytes(&request).expect("encode query request");
    let request_ptr = store_tlv(&mut vm, PointerType::NoritoBytes, &request_bytes);
    vm.set_register(10, request_ptr);
    let error = vm
        .run_with_host(&mut host)
        .expect_err("continuation queries are rejected");
    assert!(matches!(
        (&(error), &(ivm::VMError::PermissionDenied)),
        (
            ivm::VMError::PermissionDenied,
            ivm::VMError::PermissionDenied
        )
    ));
    assert_eq!(
        vm.remaining_gas(),
        0,
        "an unmetered query failure must not refund host work"
    );
    assert_eq!(vm.register(10), request_ptr, "no output may be published");
}
