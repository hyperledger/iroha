#[test]
fn pointer_abi_holding_limit_preserves_some_and_none() {
    let account = fixture_account("alice");
    let asset_definition = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonder", "universal").unwrap(),
        "coin".parse().unwrap(),
    );
    for expected in [Some(Quantity::from(2_500_u64)), None] {
        let mut vm = IVM::new(10_000);
        let account_ptr = store_tlv(&mut vm, PointerType::AccountId, &norito_blob(&account));
        let asset_ptr = store_tlv(
            &mut vm,
            PointerType::AssetDefinitionId,
            &norito_blob(&asset_definition),
        );
        let layout = ivm::sum::SumLayoutV1::option(1).expect("quantity option layout");
        let limit_ptr = match &expected {
            Some(amount) => {
                let amount_ptr = store_tlv(&mut vm, PointerType::Quantity, &quantity_frame(amount));
                ivm::sum::allocate_words(&mut vm, layout, 1, &[amount_ptr])
                    .expect("Option::some quantity")
            }
            None => {
                ivm::sum::allocate_words(&mut vm, layout, 0, &[]).expect("Option::none quantity")
            }
        };
        vm.set_register(10, account_ptr);
        vm.set_register(11, asset_ptr);
        vm.set_register(12, limit_ptr);
        let mut host = CoreHost::new(account.clone());
        host.syscall(ivm_sys::SYSCALL_SET_ASSET_HOLDING_LIMIT, &mut vm)
            .expect("queue holding-limit instruction");
        let queued = host.drain_instructions();
        assert_eq!(queued.len(), 1);
        let instruction = queued[0]
            .as_any()
            .downcast_ref::<iroha_data_model::isi::SetAssetHoldingLimit>()
            .expect("typed holding-limit instruction");
        assert_eq!(instruction.account_id, account);
        assert_eq!(instruction.asset_definition_id, asset_definition);
        assert_eq!(instruction.holding_limit, expected);
    }
}
#[test]
fn pointer_abi_daily_limit_rejects_noncanonical_options() {
    let mut vm = IVM::new(10_000);
    let layout = ivm::sum::SumLayoutV1::option(1).expect("quantity option layout");
    let invalid_tag = vm.alloc_heap(layout.allocation_bytes().unwrap()).unwrap();
    vm.store_u64(invalid_tag, 2).unwrap();
    assert!(matches!(
        (
            &(CoreHost::decode_optional_amount(&vm, invalid_tag)),
            &(ivm::VMError::DecodeError)
        ),
        (Err(ivm::VMError::DecodeError), ivm::VMError::DecodeError)
    ));
    let noncanonical_none = vm.alloc_heap(layout.allocation_bytes().unwrap()).unwrap();
    vm.store_u64(noncanonical_none, 0).unwrap();
    vm.store_u64(noncanonical_none + 8, 1).unwrap();
    assert!(matches!(
        (
            &(CoreHost::decode_optional_amount(&vm, noncanonical_none)),
            &(ivm::VMError::DecodeError)
        ),
        (Err(ivm::VMError::DecodeError), ivm::VMError::DecodeError)
    ));
    let wrong_payload = store_tlv(
        &mut vm,
        PointerType::Name,
        &norito_blob(&"not_a_quantity".parse::<Name>().unwrap()),
    );
    let wrong_some = ivm::sum::allocate_words(&mut vm, layout, 1, &[wrong_payload])
        .expect("well-formed option with wrong payload type");
    assert!(CoreHost::decode_optional_amount(&vm, wrong_some).is_err());
    assert!(CoreHost::decode_optional_amount(&vm, invalid_tag + 1).is_err());
}
#[test]
#[allow(clippy::too_many_lines)]
fn pointer_abi_transfer_asset_enqueues_isi() {
    // Prepare Norito-encoded inputs in INPUT region
    let from: AccountId = fixture_account("alice");
    let to: AccountId = fixture_account("bob");
    let asset_def: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonder", "universal").unwrap(),
            "coin".parse().unwrap(),
        );
    let amount = Quantity::from(1234_u64);
    let dataspace = DataSpaceId::UNIVERSAL;
    let from_bytes = norito_blob(&from);
    let to_bytes = norito_blob(&to);
    let asset_bytes = norito_blob(&asset_def);
    let dataspace_bytes = norito_blob(&dataspace);
    let from_tlv = pointer_abi_tests::make_tlv(ivm::PointerType::AccountId as u16, &from_bytes);
    let to_tlv = pointer_abi_tests::make_tlv(ivm::PointerType::AccountId as u16, &to_bytes);
    let asset_tlv =
        pointer_abi_tests::make_tlv(ivm::PointerType::AssetDefinitionId as u16, &asset_bytes);
    let dataspace_tlv =
        pointer_abi_tests::make_tlv(ivm::PointerType::DataSpaceId as u16, &dataspace_bytes);
    let amount_tlv =
        pointer_abi_tests::make_tlv(ivm::PointerType::Quantity as u16, &quantity_frame(&amount));
    // Offsets in INPUT region
    let off_from = 0u64;
    let off_to = 256u64;
    let off_asset = 512u64;
    let off_amount = 768u64;
    let off_dataspace = 1024u64;
    let ptr_from = ivm::Memory::INPUT_START + off_from;
    let ptr_to = ivm::Memory::INPUT_START + off_to;
    let ptr_asset = ivm::Memory::INPUT_START + off_asset;
    let ptr_amount = ivm::Memory::INPUT_START + off_amount;
    let ptr_dataspace = ivm::Memory::INPUT_START + off_dataspace;
    let mut vm = IVM::new(10_000);
    // Preload the INPUT region
    vm.memory
        .preload_input(off_from, &from_tlv)
        .expect("preload input");
    vm.memory
        .preload_input(off_to, &to_tlv)
        .expect("preload input");
    vm.memory
        .preload_input(off_asset, &asset_tlv)
        .expect("preload input");
    vm.memory
        .preload_input(off_amount, &amount_tlv)
        .expect("preload input");
    vm.memory
        .preload_input(off_dataspace, &dataspace_tlv)
        .expect("preload input");
    let state = scoped_transfer_state(
        &from,
        &to,
        asset_def.clone(),
        "coin",
        AssetBalancePolicy::Global,
        None,
    );
    let view = state.view();
    let mut host: CoreHostImpl<QueryStateSlot<_>> = CoreHostImpl::new(from.clone());
    host.set_query_state(&view);
    // Set arg registers to pointers and amount
    vm.set_register(10, ptr_from);
    vm.set_register(11, ptr_to);
    vm.set_register(12, ptr_asset);
    vm.set_register(13, ptr_amount);
    vm.set_register(14, ptr_dataspace);
    host.syscall(ivm_sys::SYSCALL_TRANSFER_ASSET_SCOPED, &mut vm)
        .unwrap();
    let queued = host.drain_instructions();
    assert_eq!(queued.len(), 1);
    let instr = &queued[0];
    let any = instr.as_any();
    if let Some(tb) = any.downcast_ref::<TransferBox>() {
        match tb {
            TransferBox::Asset(inner) => {
                assert_eq!(inner.destination, to);
                assert_eq!(inner.source.account, from);
                assert_eq!(inner.source.definition, asset_def);
                assert_eq!(inner.object, amount);
            }
            _ => panic!("expected asset transfer"),
        }
    } else {
        panic!("expected TransferBox instruction");
    }
}
// NOTE: Additional CoreHost tests for NFT syscalls can be added once the VM instruction
// builder helpers stabilize across metadata header formats.
#[test]
fn nft_mint_enqueues_register_and_transfer() {
    let authority: AccountId = fixture_account("alice");
    let authority_clone = authority.clone();
    let owner: AccountId = fixture_account("bob");
    let nft_id: NftId = "gold$wonderland.universal".parse().unwrap();
    let nft_tlv = make_tlv(PointerType::NftId as u16, &norito_blob(&nft_id));
    let owner_tlv = make_tlv(PointerType::AccountId as u16, &norito_blob(&owner));
    let mut code = Vec::new();
    code.extend_from_slice(
        &encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            u8::try_from(ivm_sys::SYSCALL_NFT_MINT_ASSET).expect("syscall id fits in u8"),
        )
        .to_le_bytes(),
    );
    code.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let program = build_program(&code, 4);
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new(authority_clone));
    vm.load_program(&program).unwrap();
    vm.memory
        .preload_input(0, &nft_tlv)
        .expect("preload nft tlv");
    vm.memory
        .preload_input(256, &owner_tlv)
        .expect("preload owner tlv");
    vm.set_register(10, ivm::Memory::INPUT_START);
    vm.set_register(11, ivm::Memory::INPUT_START + 256);
    vm.run().unwrap();
    let host_any = vm.host_mut_any().unwrap();
    let host = host_any.downcast_mut::<CoreHost>().unwrap();
    let queued = host.drain_instructions();
    assert_eq!(queued.len(), 2);
    let reg = queued[0]
        .as_any()
        .downcast_ref::<RegisterBox>()
        .expect("register instruction");
    match reg {
        RegisterBox::Nft(inner) => assert_eq!(&inner.object.id, &nft_id),
        _ => panic!("expected NFT register"),
    }
    let xfer = queued[1]
        .as_any()
        .downcast_ref::<TransferBox>()
        .expect("transfer instruction");
    match xfer {
        TransferBox::Nft(inner) => {
            assert_eq!(&inner.source, &authority);
            assert_eq!(&inner.destination, &owner);
            assert_eq!(&inner.object, &nft_id);
        }
        _ => panic!("expected NFT transfer"),
    }
}
#[cfg(all(feature = "telemetry", feature = "sm"))]
#[test]
fn sm3_syscall_records_success_metric() {
    let authority: AccountId = fixture_account("alice");
    let message = b"telemetry";
    let tlv = pointer_abi_tests::make_tlv(ivm::PointerType::Blob as u16, message);
    let mut vm = IVM::new(10_000);
    vm.memory
        .preload_input(0, &tlv)
        .expect("preload SM3 input TLV");
    let mut code = Vec::new();
    code.extend_from_slice(
        &encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            u8::try_from(ivm_sys::SYSCALL_SM3_HASH).expect("syscall id fits in u8"),
        )
        .to_le_bytes(),
    );
    code.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let program = build_program(&code, 4);
    let accounts = Arc::new(vec![authority.clone()]);
    let mut host = CoreHost::with_accounts(authority, accounts);
    host.force_sm_enabled_for_tests(true);
    let metrics = Arc::new(iroha_telemetry::metrics::Metrics::default());
    host.set_telemetry(StateTelemetry::new(Arc::clone(&metrics), true));
    vm.set_host(host);
    vm.load_program(&program).expect("load SM3 program");
    vm.set_register(10, ivm::Memory::INPUT_START);
    vm.run().expect("SM3 syscall must succeed");
    assert_eq!(
        metrics
            .sm_syscall_total
            .with_label_values(&["hash", "-"])
            .get(),
        1
    );
}
#[cfg(all(feature = "telemetry", feature = "sm"))]
#[test]
fn sm3_syscall_failure_records_failure_metric() {
    let authority: AccountId = fixture_account("alice");
    let message = b"not-a-blob";
    // Encode a TLV with the wrong pointer type to trigger a Norito validation error.
    let tlv = pointer_abi_tests::make_tlv(ivm::PointerType::AccountId as u16, message);
    let mut vm = IVM::new(10_000);
    vm.memory
        .preload_input(0, &tlv)
        .expect("preload SM3 input TLV");
    let mut code = Vec::new();
    code.extend_from_slice(
        &encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            u8::try_from(ivm_sys::SYSCALL_SM3_HASH).expect("syscall id fits in u8"),
        )
        .to_le_bytes(),
    );
    code.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let program = build_program(&code, 4);
    let accounts = Arc::new(vec![authority.clone()]);
    let mut host = CoreHost::with_accounts(authority, accounts);
    host.force_sm_enabled_for_tests(true);
    let metrics = Arc::new(iroha_telemetry::metrics::Metrics::default());
    host.set_telemetry(StateTelemetry::new(Arc::clone(&metrics), true));
    vm.set_host(host);
    vm.load_program(&program).expect("load SM3 program");
    vm.set_register(10, ivm::Memory::INPUT_START);
    let err = vm
        .run()
        .expect_err("SM3 must be rejected when TLV carries the wrong type");
    assert!(matches!(err, ivm::VMError::NoritoInvalid));
    assert_eq!(
        metrics
            .sm_syscall_failures_total
            .with_label_values(&["hash", "-", "norito_invalid"])
            .get(),
        1
    );
}
