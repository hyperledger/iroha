// Pointer-ABI boundary tests for CoreHost decoding and instruction construction.
#[test]
fn get_public_input_rejects_registry_type_mismatch() {
    let authority: AccountId = fixture_account("alice");
    let name: Name = "pub_key".parse().unwrap();
    let payload = b"hello".to_vec();
    let tlv = make_tlv(PointerType::Blob as u16, &payload);
    let entry = norito::json::object([
        ("name", norito::json::Value::from(name.as_ref())),
        (
            "type_id",
            norito::json::Value::from(u64::from(PointerType::Name as u16)),
        ),
        ("tlv_hex", norito::json::Value::from(hex::encode(&tlv))),
    ])
    .expect("registry entry");
    let registry = norito::json::Value::Array(vec![entry]);
    let custom = CustomParameter::new(ivm_metadata::public_inputs_id(), Json::from(registry));
    let mut params = Parameters::default();
    params.set_parameter(Parameter::Custom(custom));
    let mut host = CoreHost::new(authority);
    host.set_public_inputs_from_parameters(&params);
    assert!(host.public_inputs.is_empty());
    let mut vm = IVM::new(10_000);
    let name_ptr = store_tlv(&mut vm, PointerType::Name, &norito_blob(&name));
    vm.set_register(10, name_ptr);
    let err = host
        .syscall(ivm_sys::SYSCALL_GET_PUBLIC_INPUT, &mut vm)
        .expect_err("mismatched registry entry should error");
    assert!(matches!(err, VMError::PermissionDenied));
}
#[test]
fn set_account_detail_rejects_tlv_with_bad_hash() {
    let authority: AccountId = fixture_account("alice");
    let key: Name = "cursor".parse().unwrap();
    let account_tlv = make_tlv(PointerType::AccountId as u16, &norito_blob(&authority));
    let key_tlv = make_tlv(PointerType::Name as u16, &norito_blob(&key));
    // Tamper with the trailing hash so TLV validation fails before decoding JSON.
    let mut value_tlv = make_tlv(PointerType::Json as u16, br#"{"note":"tampered"}"#);
    let last = value_tlv
        .last_mut()
        .expect("TLV must include a trailing hash");
    *last ^= 0xFF;
    let mut vm = IVM::new(u64::MAX);
    vm.memory
        .preload_input(0, &account_tlv)
        .expect("preload account TLV");
    vm.memory
        .preload_input(256, &key_tlv)
        .expect("preload key TLV");
    vm.memory
        .preload_input(512, &value_tlv)
        .expect("preload value TLV");
    // SCALL SET_ACCOUNT_DETAIL; HALT
    let mut code = Vec::new();
    code.extend_from_slice(
        &encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            u8::try_from(ivm_sys::SYSCALL_SET_ACCOUNT_DETAIL).expect("syscall id fits in u8"),
        )
        .to_le_bytes(),
    );
    code.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let program = build_program(&code, 4);
    vm.set_host(CoreHost::with_accounts(
        authority.clone(),
        Arc::new(vec![authority]),
    ));
    vm.load_program(&program).expect("load program");
    vm.set_register(10, ivm::Memory::INPUT_START);
    vm.set_register(11, ivm::Memory::INPUT_START + 256);
    vm.set_register(12, ivm::Memory::INPUT_START + 512);
    let err = vm
        .run()
        .expect_err("invalid TLV hash should reject the syscall");
    assert!(
        matches!(err, ivm::VMError::NoritoInvalid),
        "expected NoritoInvalid when TLV hash is tampered, got {err:?}"
    );
}
#[test]
fn decode_tlv_typed_respects_pointer_policy_guard() {
    // Install a non-v1 ABI annotation so pointer validation fails closed.
    let _guard = ivm::pointer_abi::PointerPolicyGuard::install(ivm::SyscallPolicy::AbiV1, 9);
    let mut vm = ivm::IVM::new(1_000_000);
    let did: DomainId = DomainId::try_new("wonder", "universal").unwrap();
    let payload = norito::to_bytes(&did).expect("encode domain id");
    let tlv = make_tlv(PointerType::DomainId as u16, &payload);
    vm.memory.preload_input(0, &tlv).expect("preload input");
    let err = CoreHost::decode_tlv_typed::<DomainId>(
        &vm,
        ivm::Memory::INPUT_START,
        PointerType::DomainId,
    )
    .expect_err("pointer policy guard should forbid DomainId");
    assert!(
        matches!(
            err,
            ivm::VMError::AbiTypeNotAllowed { abi, type_id }
                if abi == 9 && type_id == PointerType::DomainId as u16
        ),
        "expected AbiTypeNotAllowed with annotated abi/type, got {err:?}"
    );
}
#[test]
fn decode_tlv_blob_accepts_code_region_literal() {
    let payload = b"risk".to_vec();
    let tlv = make_tlv(PointerType::Blob as u16, &payload);
    let literal_data_offset = 16 + core::mem::size_of::<u64>();
    let post_pad = (4 - ((literal_data_offset + tlv.len()) % 4)) % 4;
    let mut program = ivm::ProgramMetadata::default().encode();
    program.extend_from_slice(b"LTLB");
    program.extend_from_slice(&1_u32.to_le_bytes());
    program.extend_from_slice(
        &u32::try_from(post_pad)
            .expect("literal padding fits u32")
            .to_le_bytes(),
    );
    program.extend_from_slice(
        &u32::try_from(tlv.len())
            .expect("literal length fits u32")
            .to_le_bytes(),
    );
    let descriptor = ivm::encode_literal_descriptor(
        ivm::LiteralKindV1::PointerTlv,
        u64::try_from(literal_data_offset).expect("literal offset fits u64"),
    )
    .expect("encode pointer literal descriptor");
    program.extend_from_slice(&descriptor.to_le_bytes());
    program.extend_from_slice(&tlv);
    program.extend(std::iter::repeat_n(0_u8, post_pad));
    program.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let mut vm = ivm::IVM::new(1_000_000);
    vm.load_program(&program).expect("load abi v1 program");
    let decoded = CoreHost::decode_tlv_blob(
        &vm,
        u64::try_from(literal_data_offset).expect("literal pointer fits u64"),
    )
    .expect("decode code literal");
    assert_eq!(decoded, payload);
}
#[test]
fn pointer_abi_transfer_availability_packs_flags_and_preserves_reason() {
    use iroha_data_model::asset::AssetTransferAvailability::{Disabled, Enabled};
    let account = fixture_account("alice");
    let asset_definition = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonder", "universal").unwrap(),
        "coin".parse().unwrap(),
    );
    for (flags, incoming, outgoing, reason) in [
        (0b00, Disabled, Disabled, None),
        (0b01, Enabled, Disabled, Some("incoming only".to_owned())),
        (0b10, Disabled, Enabled, Some("outgoing only".to_owned())),
        (0b11, Enabled, Enabled, None),
    ] {
        let mut vm = IVM::new(10_000);
        let account_ptr = store_tlv(&mut vm, PointerType::AccountId, &norito_blob(&account));
        let asset_ptr = store_tlv(
            &mut vm,
            PointerType::AssetDefinitionId,
            &norito_blob(&asset_definition),
        );
        let layout = ivm::sum::SumLayoutV1::option(1).expect("reason option layout");
        let reason_ptr = match &reason {
            Some(reason) => {
                let string_ptr = store_tlv(&mut vm, PointerType::Blob, reason.as_bytes());
                ivm::sum::allocate_words(&mut vm, layout, 1, &[string_ptr])
                    .expect("Option::some reason")
            }
            None => ivm::sum::allocate_words(&mut vm, layout, 0, &[]).expect("Option::none reason"),
        };
        vm.set_register(10, account_ptr);
        vm.set_register(11, asset_ptr);
        vm.set_register(12, 7);
        vm.set_register(13, flags);
        vm.set_register(14, reason_ptr);
        let mut host = CoreHost::new(account.clone());
        host.syscall(ivm_sys::SYSCALL_SET_ASSET_TRANSFER_AVAILABILITY, &mut vm)
            .expect("queue transfer-availability instruction");
        let queued = host.drain_instructions();
        assert_eq!(queued.len(), 1);
        let instruction = queued[0]
            .as_any()
            .downcast_ref::<iroha_data_model::isi::SetAssetTransferAvailability>()
            .expect("typed transfer-availability instruction");
        assert_eq!(instruction.account_id, account);
        assert_eq!(instruction.asset_definition_id, asset_definition);
        assert_eq!(instruction.expected_revision, 7);
        assert_eq!(instruction.incoming, incoming);
        assert_eq!(instruction.outgoing, outgoing);
        assert_eq!(instruction.reason, reason);
    }
    let mut invalid_vm = IVM::new(10_000);
    let account_ptr = store_tlv(
        &mut invalid_vm,
        PointerType::AccountId,
        &norito_blob(&account),
    );
    let asset_ptr = store_tlv(
        &mut invalid_vm,
        PointerType::AssetDefinitionId,
        &norito_blob(&asset_definition),
    );
    let layout = ivm::sum::SumLayoutV1::option(1).expect("reason option layout");
    let reason_ptr =
        ivm::sum::allocate_words(&mut invalid_vm, layout, 0, &[]).expect("absent reason");
    invalid_vm.set_register(10, account_ptr);
    invalid_vm.set_register(11, asset_ptr);
    invalid_vm.set_register(12, 0);
    invalid_vm.set_register(13, 0b100);
    invalid_vm.set_register(14, reason_ptr);
    let mut host = CoreHost::new(account);
    assert!(matches!(
        (
            &(host.syscall(
                ivm_sys::SYSCALL_SET_ASSET_TRANSFER_AVAILABILITY,
                &mut invalid_vm,
            )),
            &(ivm::VMError::DecodeError)
        ),
        (Err(ivm::VMError::DecodeError), ivm::VMError::DecodeError)
    ));
}
#[test]
fn pointer_abi_daily_limit_preserves_some_and_none() {
    let account = fixture_account("alice");
    let asset_definition = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonder", "universal").unwrap(),
        "coin".parse().unwrap(),
    );
    for expected in [Some(Quantity::from(125_u64)), None] {
        let mut vm = IVM::new(10_000);
        let account_ptr = store_tlv(&mut vm, PointerType::AccountId, &norito_blob(&account));
        let asset_ptr = store_tlv(
            &mut vm,
            PointerType::AssetDefinitionId,
            &norito_blob(&asset_definition),
        );
        let layout = ivm::sum::SumLayoutV1::option(1).expect("quantity option layout");
        let cap_ptr = match &expected {
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
        vm.set_register(12, cap_ptr);
        let mut host = CoreHost::new(account.clone());
        host.syscall(ivm_sys::SYSCALL_SET_ASSET_TRANSFER_DAILY_LIMIT, &mut vm)
            .expect("queue daily-limit instruction");
        let queued = host.drain_instructions();
        assert_eq!(queued.len(), 1);
        let instruction = queued[0]
            .as_any()
            .downcast_ref::<iroha_data_model::isi::SetAssetTransferControl>()
            .expect("typed transfer-control instruction");
        assert_eq!(instruction.account_id, account);
        assert_eq!(instruction.asset_definition_id, asset_definition);
        assert_eq!(instruction.limits.len(), 1);
        assert_eq!(
            instruction.limits[0].window,
            iroha_data_model::asset::AssetTransferControlWindow::Day
        );
        assert_eq!(instruction.limits[0].cap_amount, expected);
    }
}
