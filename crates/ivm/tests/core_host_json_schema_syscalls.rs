//! CoreHost JSON encode/decode and schema encode/decode helpers.
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    prelude::{AccountId, AssetDefinitionId},
    smart_contract::ContractAddress,
};
use iroha_model_base::state_path::StatePath;
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::{numeric::Quantity, numeric_abi::QuantityValueV1};
use ivm::{
    CoreHost, EmbeddedContractInterfaceV1, EmbeddedEntrypointDescriptor, EmbeddedStateDescriptor,
    EmbeddedStateType, IVM, IVMHost, PointerType, ProgramMetadata, encoding, instruction::wide,
    syscalls,
};
mod common;
fn tlv(pty: PointerType, payload: &[u8]) -> Vec<u8> {
    let payload = common::payload_for_type(pty, payload);
    let mut v = Vec::with_capacity(7 + payload.len() + 32);
    v.extend_from_slice(&(pty as u16).to_be_bytes());
    v.push(1);
    v.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    v.extend_from_slice(payload.as_ref());
    let h: [u8; 32] = iroha_crypto::Hash::new(payload).into();
    v.extend_from_slice(&h);
    v
}
fn alloc_heap_tlv(vm: &mut IVM, bytes: &[u8]) -> u64 {
    let addr = vm.memory.alloc(bytes.len() as u64).expect("alloc heap tlv");
    vm.memory
        .store_bytes(addr, bytes)
        .expect("store heap direct tlv");
    addr
}
fn state_map_interface(name: &str, key: EmbeddedStateType) -> EmbeddedContractInterfaceV1 {
    EmbeddedContractInterfaceV1 {
        permissions: Vec::new(),
        events: Vec::new(),
        callables: vec![common::unit_callable(0)],
        seiyaku_name: "DirectMapKeyFixture".to_owned(),
        compiler_fingerprint: "ivm-integration-tests".to_owned(),
        abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
        features_bitmap: 0,
        access_set_hints: None,
        kotoba: Vec::new(),
        entrypoints: vec![EmbeddedEntrypointDescriptor {
            name: "inspect".to_owned(),
            kind: iroha_data_model::smart_contract::manifest::EntryPointKind::View,
            params: Vec::new(),
            argument_schema: None,
            return_type: Some("()".to_owned()),
            return_schema: Some(ivm_abi::entrypoint::EntrypointValueTypeV1 {
                nodes: vec![ivm_abi::entrypoint::EntrypointValueTypeNodeV1::Unit],
            }),
            authorization:
                iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Anyone,
            read_keys: Vec::new(),
            write_keys: Vec::new(),
            access_hints_complete: Some(true),
            access_hints_skipped: Vec::new(),
            triggers: Vec::new(),
            entry_pc: 0,
        }],
        states: vec![EmbeddedStateDescriptor {
            name: name.to_owned(),
            ty: EmbeddedStateType::StateMap {
                key: Box::new(key),
                value: Box::new(EmbeddedStateType::Bytes),
            },
        }],
        error_messages: Vec::new(),
        error_types: Vec::new(),
        enum_types: Vec::new(),
    }
}
fn assemble_state_map_schema(name: &str, key: EmbeddedStateType) -> Vec<u8> {
    let mut program = ProgramMetadata::default().encode();
    program.extend_from_slice(&state_map_interface(name, key).encode_section());
    for word in common::unit_return_words() {
        program.extend_from_slice(&word.to_le_bytes());
    }
    program
}
fn assemble_state_map_schema_with_literals(
    name: &str,
    key: EmbeddedStateType,
    literals: &[&[u8]],
) -> (Vec<u8>, Vec<u64>) {
    let section = state_map_interface(name, key).encode_section();
    let offsets_len = literals.len() * core::mem::size_of::<u64>();
    // Literal descriptors are relative to the start of the LTLB section, even
    // when a CNTR section precedes it in the artifact.
    let data_start = 16 + offsets_len;
    let mut offsets = Vec::with_capacity(literals.len());
    let mut data = Vec::new();
    let mut cursor = u64::try_from(data_start).expect("literal offset fits u64");
    for literal in literals {
        offsets.push(cursor);
        data.extend_from_slice(literal);
        cursor = cursor
            .checked_add(u64::try_from(literal.len()).expect("literal length fits u64"))
            .expect("literal offset remains bounded");
    }
    let post_pad = (4 - ((section.len() + 16 + offsets_len + data.len()) % 4)) % 4;
    let mut program = ProgramMetadata::default().encode();
    program.extend_from_slice(&section);
    program.extend_from_slice(&ivm_abi::metadata::LITERAL_SECTION_MAGIC);
    program.extend_from_slice(
        &u32::try_from(literals.len())
            .expect("literal count fits u32")
            .to_le_bytes(),
    );
    program.extend_from_slice(
        &u32::try_from(post_pad)
            .expect("literal padding fits u32")
            .to_le_bytes(),
    );
    program.extend_from_slice(
        &u32::try_from(data.len())
            .expect("literal data fits u32")
            .to_le_bytes(),
    );
    for offset in &offsets {
        program.extend_from_slice(&offset.to_le_bytes());
    }
    program.extend_from_slice(&data);
    program.extend(std::iter::repeat_n(0, post_pad));
    for word in common::unit_return_words() {
        program.extend_from_slice(&word.to_le_bytes());
    }
    let literal_ptrs = offsets
        .into_iter()
        .map(|offset| {
            u64::try_from(section.len())
                .expect("CNTR section length fits u64")
                .checked_add(offset)
                .expect("literal pointer remains bounded")
        })
        .collect();
    (program, literal_ptrs)
}
fn unwrap_some_word(vm: &IVM) -> u64 {
    let layout = ivm::sum::SumLayoutV1::option(1).expect("Option layout");
    let (is_some, words) =
        ivm::sum::read_words(vm, vm.register(10), layout).expect("read typed JSON getter Option");
    assert!(is_some, "typed JSON getter must return Option::some");
    assert_eq!(words.len(), 1);
    words[0]
}
fn checked_contract_authority_fixture() -> AccountId {
    AccountId::new(
        KeyPair::try_random()
            .expect("generate checked JSON contract-authority fixture keypair")
            .public_key()
            .clone(),
    )
}
#[test]
fn contract_authority_fixture_uses_checked_ed25519_key_generation() {
    let authority = checked_contract_authority_fixture();
    let algorithm = authority
        .expect_single_signatory()
        .try_algorithm()
        .expect("fixture authority public key has a valid algorithm");
    assert_eq!(algorithm, Algorithm::Ed25519);
}
#[test]
fn json_encode_decode_roundtrip() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    let json = br#"{"a":1,"b":[2,3]}"#;
    let p_json = vm.alloc_input_tlv(&tlv(PointerType::Json, json)).unwrap();
    // ENCODE
    let enc_prog = common::assemble(
        &[
            encoding::wide::encode_sys(
                wide::system::SCALL,
                syscalls::SYSCALL_INPUT_PUBLISH_TLV as u8,
            )
            .to_le_bytes(),
            encoding::wide::encode_sys(wide::system::SCALL, syscalls::SYSCALL_JSON_ENCODE as u8)
                .to_le_bytes(),
            encoding::wide::encode_halt().to_le_bytes(),
        ]
        .concat(),
    );
    vm.set_register(10, p_json);
    vm.load_program(&enc_prog).unwrap();
    vm.run().unwrap();
    let p_blob = vm.register(10);
    let tlv_b = vm.memory.validate_tlv(p_blob).unwrap();
    assert_eq!(tlv_b.type_id, PointerType::NoritoBytes);
    // DECODE
    let dec_prog = common::assemble(
        &[
            encoding::wide::encode_sys(
                wide::system::SCALL,
                syscalls::SYSCALL_INPUT_PUBLISH_TLV as u8,
            )
            .to_le_bytes(),
            encoding::wide::encode_sys(wide::system::SCALL, syscalls::SYSCALL_JSON_DECODE as u8)
                .to_le_bytes(),
            encoding::wide::encode_halt().to_le_bytes(),
        ]
        .concat(),
    );
    vm.set_register(10, p_blob);
    vm.load_program(&dec_prog).unwrap();
    vm.run().unwrap();
    let p_out = vm.register(10);
    let tlv_j = vm.memory.validate_tlv(p_out).unwrap();
    assert_eq!(tlv_j.type_id, PointerType::Json);
}
#[test]
fn json_decode_rejects_retired_blob_carrier() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    let json = br#"{"a":1,"b":[2,3]}"#;
    let p_blob = vm.alloc_input_tlv(&tlv(PointerType::Blob, json)).unwrap();
    let dec_prog = common::assemble(
        &[
            encoding::wide::encode_sys(
                wide::system::SCALL,
                syscalls::SYSCALL_INPUT_PUBLISH_TLV as u8,
            )
            .to_le_bytes(),
            encoding::wide::encode_sys(wide::system::SCALL, syscalls::SYSCALL_JSON_DECODE as u8)
                .to_le_bytes(),
            encoding::wide::encode_halt().to_le_bytes(),
        ]
        .concat(),
    );
    vm.set_register(10, p_blob);
    vm.load_program(&dec_prog).unwrap();
    assert_eq!(vm.run(), Err(ivm::VMError::NoritoInvalid));
    assert_eq!(vm.register(10), p_blob);
}
#[test]
fn json_get_blob_hex_accepts_canonical_lowercase_hex() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    let hash = iroha_crypto::Hash::new(b"settlement");
    let hash_hex = hex::encode(hash.as_ref());
    let json = format!(r#"{{"settlement_hash":"0x{hash_hex}"}}"#);
    let p_json = vm
        .alloc_input_tlv(&tlv(PointerType::Json, json.as_bytes()))
        .unwrap();
    let p_key = vm
        .alloc_input_tlv(&tlv(PointerType::Name, b"settlement_hash"))
        .unwrap();
    let prog = common::assemble_syscalls(&[syscalls::SYSCALL_JSON_GET_BLOB_HEX as u8]);
    vm.set_register(10, p_json);
    vm.set_register(11, p_key);
    vm.load_program(&prog).unwrap();
    vm.run().unwrap();
    let out_ptr = unwrap_some_word(&vm);
    let tlv_out = vm.memory.validate_tlv(out_ptr).unwrap();
    assert_eq!(tlv_out.type_id, PointerType::Blob);
    assert_eq!(tlv_out.payload, hash.as_ref());
}
#[test]
fn json_get_blob_hex_rejects_noncanonical_and_malformed_spellings() {
    for invalid in ["deadbeef", "hash:deadbeef", "0xDEADBEEF", "0xabc", "0xzz"] {
        let mut vm = IVM::new(u64::MAX);
        vm.set_host(CoreHost::new());
        let json = format!(r#"{{"value":"{invalid}"}}"#);
        let p_json = vm
            .alloc_input_tlv(&tlv(PointerType::Json, json.as_bytes()))
            .expect("allocate JSON input");
        let p_key = vm
            .alloc_input_tlv(&tlv(PointerType::Name, b"value"))
            .expect("allocate JSON key");
        let program = common::assemble_syscalls(&[syscalls::SYSCALL_JSON_GET_BLOB_HEX as u8]);
        vm.set_register(10, p_json);
        vm.set_register(11, p_key);
        vm.load_program(&program).expect("load blob getter");
        assert_eq!(
            vm.run(),
            Err(ivm::VMError::DecodeError),
            "`{invalid}` must not decode as canonical bytes or read as absent"
        );
    }
}
#[test]
fn json_get_asset_definition_id_reads_address_literals() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    let json = br#"{"asset_definition_id":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM"}"#;
    let p_json = vm.alloc_input_tlv(&tlv(PointerType::Json, json)).unwrap();
    let p_key = vm
        .alloc_input_tlv(&tlv(PointerType::Name, b"asset_definition_id"))
        .unwrap();
    let prog = common::assemble_syscalls(&[syscalls::SYSCALL_JSON_GET_ASSET_DEFINITION_ID as u8]);
    vm.set_register(10, p_json);
    vm.set_register(11, p_key);
    vm.load_program(&prog).unwrap();
    vm.run().unwrap();
    let out_ptr = unwrap_some_word(&vm);
    let tlv_out = vm.memory.validate_tlv(out_ptr).unwrap();
    assert_eq!(tlv_out.type_id, PointerType::AssetDefinitionId);
    let asset: AssetDefinitionId = norito::decode_from_bytes(tlv_out.payload).unwrap();
    assert_eq!(
        asset,
        AssetDefinitionId::parse_address_literal("62Fk4FPcMuLvW5QjDGNF2a4jAmjM").unwrap()
    );
}
#[test]
fn schema_encode_decode_roundtrip() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    let schema = b"Order";
    let json = br#"{"qty":10,"side":"buy"}"#;
    let p_schema = vm.alloc_input_tlv(&tlv(PointerType::Name, schema)).unwrap();
    let p_json = vm.alloc_input_tlv(&tlv(PointerType::Json, json)).unwrap();
    // ENCODE (inputs are already in INPUT via alloc_input_tlv)
    let enc = common::assemble(
        &[
            encoding::wide::encode_sys(wide::system::SCALL, syscalls::SYSCALL_SCHEMA_ENCODE as u8)
                .to_le_bytes(),
            encoding::wide::encode_halt().to_le_bytes(),
        ]
        .concat(),
    );
    vm.set_register(10, p_schema);
    vm.set_register(11, p_json);
    vm.load_program(&enc).unwrap();
    vm.run().unwrap();
    let p_blob = vm.register(10);
    let tlv_b = vm.memory.validate_tlv(p_blob).unwrap();
    assert_eq!(tlv_b.type_id, PointerType::NoritoBytes);
    // DECODE (inputs are already in INPUT via alloc_input_tlv)
    let dec = common::assemble(
        &[
            encoding::wide::encode_sys(wide::system::SCALL, syscalls::SYSCALL_SCHEMA_DECODE as u8)
                .to_le_bytes(),
            encoding::wide::encode_halt().to_le_bytes(),
        ]
        .concat(),
    );
    vm.set_register(10, p_schema);
    vm.set_register(11, p_blob);
    vm.load_program(&dec).unwrap();
    vm.run().unwrap();
    let p_out = vm.register(10);
    let tlv_j = vm.memory.validate_tlv(p_out).unwrap();
    assert_eq!(tlv_j.type_id, PointerType::Json);
}
#[test]
fn schema_decode_rejects_blob() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    let schema = b"Order";
    let json = br#"{"qty":10,"side":"buy"}"#;
    let p_schema = vm.alloc_input_tlv(&tlv(PointerType::Name, schema)).unwrap();
    let p_json = vm.alloc_input_tlv(&tlv(PointerType::Json, json)).unwrap();
    let enc = common::assemble(
        &[
            encoding::wide::encode_sys(wide::system::SCALL, syscalls::SYSCALL_SCHEMA_ENCODE as u8)
                .to_le_bytes(),
            encoding::wide::encode_halt().to_le_bytes(),
        ]
        .concat(),
    );
    vm.set_register(10, p_schema);
    vm.set_register(11, p_json);
    vm.load_program(&enc).unwrap();
    vm.run().unwrap();
    let p_blob = vm.register(10);
    let encoded = vm.memory.validate_tlv(p_blob).unwrap();
    let p_blob_alt = vm
        .alloc_input_tlv(&tlv(PointerType::Blob, encoded.payload))
        .unwrap();
    let dec = common::assemble(
        &[
            encoding::wide::encode_sys(wide::system::SCALL, syscalls::SYSCALL_SCHEMA_DECODE as u8)
                .to_le_bytes(),
            encoding::wide::encode_halt().to_le_bytes(),
        ]
        .concat(),
    );
    vm.set_register(10, p_schema);
    vm.set_register(11, p_blob_alt);
    vm.load_program(&dec).unwrap();
    let err = vm.run().unwrap_err();
    assert!(matches!(err, ivm::VMError::NoritoInvalid));
}
#[test]
fn schema_unknown_and_malformed_inputs_fail_closed() {
    let generic_json = iroha_primitives::json::Json::from_str_norito(r#"{"value":1}"#)
        .expect("parse adversarial generic JSON");
    let generic_json_bytes =
        norito::to_bytes(&generic_json).expect("encode adversarial generic JSON");
    for (schema, payload) in [
        (&b"UnknownSchema"[..], generic_json_bytes.as_slice()),
        (&b"Order"[..], generic_json_bytes.as_slice()),
    ] {
        let mut vm = IVM::new(u64::MAX);
        vm.set_host(CoreHost::new());
        let p_schema = vm.alloc_input_tlv(&tlv(PointerType::Name, schema)).unwrap();
        let p_bytes = vm
            .alloc_input_tlv(&tlv(PointerType::NoritoBytes, payload))
            .unwrap();
        let dec = common::assemble(
            &[
                encoding::wide::encode_sys(
                    wide::system::SCALL,
                    syscalls::SYSCALL_SCHEMA_DECODE as u8,
                )
                .to_le_bytes(),
                encoding::wide::encode_halt().to_le_bytes(),
            ]
            .concat(),
        );
        vm.set_register(10, p_schema);
        vm.set_register(11, p_bytes);
        vm.load_program(&dec).unwrap();
        assert_eq!(vm.run(), Err(ivm::VMError::NoritoInvalid));
        assert_eq!(vm.register(10), p_schema);
        assert_eq!(vm.register(11), p_bytes);
    }
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    let p_schema = vm
        .alloc_input_tlv(&tlv(PointerType::Name, b"UnknownSchema"))
        .unwrap();
    let p_json = vm
        .alloc_input_tlv(&tlv(PointerType::Json, br#"{"value":1}"#))
        .unwrap();
    let enc = common::assemble(
        &[
            encoding::wide::encode_sys(wide::system::SCALL, syscalls::SYSCALL_SCHEMA_ENCODE as u8)
                .to_le_bytes(),
            encoding::wide::encode_halt().to_le_bytes(),
        ]
        .concat(),
    );
    vm.set_register(10, p_schema);
    vm.set_register(11, p_json);
    vm.load_program(&enc).unwrap();
    assert_eq!(vm.run(), Err(ivm::VMError::NoritoInvalid));
    assert_eq!(vm.register(10), p_schema);
    assert_eq!(vm.register(11), p_json);
}
#[test]
fn schema_info_resolves_only_explicit_families() {
    let known = [
        ("Order", "OrderByTime", 2usize),
        ("OrderByTime", "OrderByTime", 2usize),
        ("Trade", "TradeV2", 2usize),
        ("TradeV1", "TradeV2", 2usize),
        ("TradeV2", "TradeV2", 2usize),
        ("QueryRequest", "QueryRequest", 1usize),
        ("QueryResponse", "QueryResponse", 1usize),
    ];
    for (schema, expected_current, expected_versions) in known {
        let mut vm = IVM::new(u64::MAX);
        vm.set_host(CoreHost::new());
        let p_schema = vm
            .alloc_input_tlv(&tlv(PointerType::Name, schema.as_bytes()))
            .expect("allocate schema name");
        let program = common::assemble_syscalls(&[syscalls::SYSCALL_SCHEMA_INFO]);
        vm.set_register(10, p_schema);
        vm.load_program(&program).expect("load schema info program");
        vm.run().expect("known schema info succeeds");
        let output = vm
            .memory
            .validate_tlv(vm.register(10))
            .expect("schema info output");
        assert_eq!(output.type_id, PointerType::Json);
        let value = common::json_from_payload(output.payload);
        assert_eq!(
            value["current"]["name"].as_str(),
            Some(expected_current),
            "current schema for {schema}"
        );
        assert_eq!(
            value["versions"].as_array().map(Vec::len),
            Some(expected_versions),
            "version count for {schema}"
        );
    }
    for schema in ["UnknownSchema", "OrderV2", "TradeV3", "Query"] {
        let mut vm = IVM::new(u64::MAX);
        vm.set_host(CoreHost::new());
        let p_schema = vm
            .alloc_input_tlv(&tlv(PointerType::Name, schema.as_bytes()))
            .expect("allocate adversarial schema name");
        let program = common::assemble_syscalls(&[syscalls::SYSCALL_SCHEMA_INFO]);
        vm.set_register(10, p_schema);
        vm.load_program(&program).expect("load schema info program");
        assert_eq!(vm.run(), Err(ivm::VMError::NoritoInvalid));
        assert_eq!(vm.register(10), p_schema);
    }
}
#[test]
fn json_get_quantity_reads_canonical_decimal_strings() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    let json = br#"{"amount":"0.00001"}"#;
    let p_json = vm.alloc_input_tlv(&tlv(PointerType::Json, json)).unwrap();
    let p_key = vm
        .alloc_input_tlv(&tlv(PointerType::Name, b"amount"))
        .unwrap();
    let prog = common::assemble_syscalls(&[syscalls::SYSCALL_JSON_GET_QUANTITY]);
    vm.set_register(10, p_json);
    vm.set_register(11, p_key);
    vm.load_program(&prog).unwrap();
    vm.run().unwrap();
    let tlv = vm.memory.validate_tlv(unwrap_some_word(&vm)).unwrap();
    assert_eq!(tlv.type_id, PointerType::Quantity);
    let value = QuantityValueV1::decode_frame(tlv.payload)
        .expect("decode quantity")
        .into_quantity();
    assert_eq!(value, "0.00001".parse::<Quantity>().expect("quantity"));
}
#[test]
fn json_get_quantity_accepts_input_heap_and_literal_pointers() {
    let json_tlv = tlv(PointerType::Json, br#"{"amount":"0.00001"}"#);
    let key_tlv = tlv(PointerType::Name, b"amount");
    let canonical_prog = common::assemble_syscalls(&[syscalls::SYSCALL_JSON_GET_QUANTITY]);
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    let p_json = vm.alloc_input_tlv(&json_tlv).expect("alloc input json");
    let p_key = vm.alloc_input_tlv(&key_tlv).expect("alloc input key");
    vm.set_register(10, p_json);
    vm.set_register(11, p_key);
    vm.load_program(&canonical_prog).unwrap();
    vm.run().unwrap();
    let tlv = vm.memory.validate_tlv(unwrap_some_word(&vm)).unwrap();
    assert_eq!(tlv.type_id, PointerType::Quantity);
    let value = QuantityValueV1::decode_frame(tlv.payload)
        .expect("decode input quantity")
        .into_quantity();
    assert_eq!(value, "0.00001".parse::<Quantity>().expect("quantity"));
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    vm.load_program(&canonical_prog).unwrap();
    let p_json = alloc_heap_tlv(&mut vm, &json_tlv);
    let p_key = alloc_heap_tlv(&mut vm, &key_tlv);
    vm.set_register(10, p_json);
    vm.set_register(11, p_key);
    vm.run().unwrap();
    let tlv = vm.memory.validate_tlv(unwrap_some_word(&vm)).unwrap();
    assert_eq!(tlv.type_id, PointerType::Quantity);
    let value = QuantityValueV1::decode_frame(tlv.payload)
        .expect("decode heap quantity")
        .into_quantity();
    assert_eq!(value, "0.00001".parse::<Quantity>().expect("quantity"));
    let (literal_prog, literal_ptrs) = common::assemble_syscalls_with_literal_section(
        &[syscalls::SYSCALL_JSON_GET_QUANTITY],
        &[json_tlv.as_slice(), key_tlv.as_slice()],
    );
    let json_addr = literal_ptrs[0];
    let key_addr = literal_ptrs[1];
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    vm.load_program(&literal_prog).unwrap();
    vm.set_register(10, json_addr);
    vm.set_register(11, key_addr);
    vm.run().unwrap();
    let tlv = vm.memory.validate_tlv(unwrap_some_word(&vm)).unwrap();
    assert_eq!(tlv.type_id, PointerType::Quantity);
    let value = QuantityValueV1::decode_frame(tlv.payload)
        .expect("decode literal quantity")
        .into_quantity();
    assert_eq!(value, "0.00001".parse::<Quantity>().expect("quantity"));
}
#[test]
fn schema_info_accepts_input_heap_and_literal_pointers() {
    let schema_tlv = tlv(PointerType::Name, b"Order");
    let canonical_prog = common::assemble_syscalls(&[syscalls::SYSCALL_SCHEMA_INFO as u8]);
    let decode_schema_info = |vm: &IVM| {
        let tlv = vm
            .memory
            .validate_tlv(vm.register(10))
            .expect("schema info tlv");
        assert_eq!(tlv.type_id, PointerType::Json);
        let json: iroha_primitives::json::Json =
            norito::decode_from_bytes(tlv.payload).expect("decode schema info json");
        let value: norito::json::Value =
            norito::json::from_str(json.get()).expect("parse schema info json");
        assert!(value.get("current").is_some());
        assert!(value.get("versions").is_some());
    };
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    let p_schema = vm.alloc_input_tlv(&schema_tlv).expect("alloc input schema");
    vm.set_register(10, p_schema);
    vm.load_program(&canonical_prog).unwrap();
    vm.run().unwrap();
    decode_schema_info(&vm);
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    vm.load_program(&canonical_prog).unwrap();
    let p_schema = alloc_heap_tlv(&mut vm, &schema_tlv);
    vm.set_register(10, p_schema);
    vm.run().unwrap();
    decode_schema_info(&vm);
    let (literal_prog, literal_ptrs) = common::assemble_syscalls_with_literal_section(
        &[syscalls::SYSCALL_SCHEMA_INFO as u8],
        &[schema_tlv.as_slice()],
    );
    let schema_addr = literal_ptrs[0];
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    vm.load_program(&literal_prog).unwrap();
    vm.set_register(10, schema_addr);
    vm.run().unwrap();
    decode_schema_info(&vm);
}
#[test]
fn json_set_i64_accepts_input_heap_and_literal_pointers() {
    let json_tlv = tlv(PointerType::Json, br#"{}"#);
    let key_tlv = tlv(PointerType::Name, b"bucket_id");
    let canonical_prog = common::assemble_syscalls(&[syscalls::SYSCALL_JSON_SET_I64 as u8]);
    let decode_bucket_id = |vm: &IVM| {
        let tlv = vm
            .memory
            .validate_tlv(vm.register(10))
            .expect("json output tlv");
        assert_eq!(tlv.type_id, PointerType::Json);
        let value = common::json_from_payload(tlv.payload);
        let object = value.as_object().expect("json object");
        assert_eq!(
            object.get("bucket_id").and_then(|value| value.as_i64()),
            Some(2)
        );
    };
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    let p_json = vm.alloc_input_tlv(&json_tlv).expect("alloc input json");
    let p_key = vm.alloc_input_tlv(&key_tlv).expect("alloc input key");
    vm.set_register(10, p_json);
    vm.set_register(11, p_key);
    vm.set_register(12, 2);
    vm.load_program(&canonical_prog).unwrap();
    vm.run().unwrap();
    decode_bucket_id(&vm);
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    vm.load_program(&canonical_prog).unwrap();
    let p_json = alloc_heap_tlv(&mut vm, &json_tlv);
    let p_key = alloc_heap_tlv(&mut vm, &key_tlv);
    vm.set_register(10, p_json);
    vm.set_register(11, p_key);
    vm.set_register(12, 2);
    vm.run().unwrap();
    decode_bucket_id(&vm);
    let (literal_prog, literal_ptrs) = common::assemble_syscalls_with_literal_section(
        &[syscalls::SYSCALL_JSON_SET_I64 as u8],
        &[json_tlv.as_slice(), key_tlv.as_slice()],
    );
    let json_addr = literal_ptrs[0];
    let key_addr = literal_ptrs[1];
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    vm.load_program(&literal_prog).unwrap();
    vm.set_register(10, json_addr);
    vm.set_register(11, key_addr);
    vm.set_register(12, 2);
    vm.run().unwrap();
    decode_bucket_id(&vm);
}
#[test]
fn json_set_account_id_accepts_input_heap_and_literal_pointers() {
    let owner_literal = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV";
    let expected_owner = AccountId::parse_encoded(owner_literal)
        .expect("valid canonical account id")
        .to_string();
    let json_tlv = tlv(PointerType::Json, br#"{}"#);
    let key_tlv = tlv(PointerType::Name, b"owner");
    let owner_tlv = tlv(PointerType::AccountId, owner_literal.as_bytes());
    let canonical_prog = common::assemble_syscalls(&[syscalls::SYSCALL_JSON_SET_ACCOUNT_ID as u8]);
    let decode_owner = |vm: &IVM| {
        let tlv = vm
            .memory
            .validate_tlv(vm.register(10))
            .expect("json output tlv");
        assert_eq!(tlv.type_id, PointerType::Json);
        let value = common::json_from_payload(tlv.payload);
        let object = value.as_object().expect("json object");
        assert_eq!(
            object.get("owner").and_then(|value| value.as_str()),
            Some(expected_owner.as_str())
        );
    };
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    let p_json = vm.alloc_input_tlv(&json_tlv).expect("alloc input json");
    let p_key = vm.alloc_input_tlv(&key_tlv).expect("alloc input key");
    let p_owner = vm.alloc_input_tlv(&owner_tlv).expect("alloc input owner");
    vm.set_register(10, p_json);
    vm.set_register(11, p_key);
    vm.set_register(12, p_owner);
    vm.load_program(&canonical_prog).unwrap();
    vm.run().unwrap();
    decode_owner(&vm);
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    vm.load_program(&canonical_prog).unwrap();
    let p_json = alloc_heap_tlv(&mut vm, &json_tlv);
    let p_key = alloc_heap_tlv(&mut vm, &key_tlv);
    let p_owner = alloc_heap_tlv(&mut vm, &owner_tlv);
    vm.set_register(10, p_json);
    vm.set_register(11, p_key);
    vm.set_register(12, p_owner);
    vm.run().unwrap();
    decode_owner(&vm);
    let (literal_prog, literal_ptrs) = common::assemble_syscalls_with_literal_section(
        &[syscalls::SYSCALL_JSON_SET_ACCOUNT_ID as u8],
        &[
            json_tlv.as_slice(),
            key_tlv.as_slice(),
            owner_tlv.as_slice(),
        ],
    );
    let json_addr = literal_ptrs[0];
    let key_addr = literal_ptrs[1];
    let owner_addr = literal_ptrs[2];
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    vm.load_program(&literal_prog).unwrap();
    vm.set_register(10, json_addr);
    vm.set_register(11, key_addr);
    vm.set_register(12, owner_addr);
    vm.run().unwrap();
    decode_owner(&vm);
}
#[test]
fn build_path_key_norito_accepts_input_heap_and_literal_pointers() {
    let base_tlv = tlv(PointerType::Name, b"entries");
    let key_payload = tlv(PointerType::Blob, b"canonical key bytes");
    let key_tlv = tlv(PointerType::NoritoBytes, &key_payload);
    let canonical_prog = assemble_state_map_schema("entries", EmbeddedStateType::Bytes);
    let expected_path = format!("entries/{}", hex::encode(&key_payload));
    let decode_path = |vm: &IVM| {
        let tlv = vm
            .memory
            .validate_tlv(vm.register(10))
            .expect("StatePath output tlv");
        assert_eq!(tlv.type_id, PointerType::NoritoBytes);
        let path: StatePath =
            norito::decode_from_bytes(tlv.payload).expect("decode canonical StatePath");
        assert_eq!(path.as_ref(), expected_path);
    };
    let mut vm = IVM::new(u64::MAX);
    let mut host = CoreHost::new();
    let p_base = vm.alloc_input_tlv(&base_tlv).expect("alloc input base");
    let p_key = vm.alloc_input_tlv(&key_tlv).expect("alloc input key");
    vm.set_register(10, p_base);
    vm.set_register(11, p_key);
    vm.load_program(&canonical_prog).unwrap();
    host.syscall(syscalls::SYSCALL_BUILD_PATH_KEY_NORITO, &mut vm)
        .unwrap();
    decode_path(&vm);
    let mut vm = IVM::new(u64::MAX);
    let mut host = CoreHost::new();
    vm.load_program(&canonical_prog).unwrap();
    let p_base = alloc_heap_tlv(&mut vm, &base_tlv);
    let p_key = alloc_heap_tlv(&mut vm, &key_tlv);
    vm.set_register(10, p_base);
    vm.set_register(11, p_key);
    host.syscall(syscalls::SYSCALL_BUILD_PATH_KEY_NORITO, &mut vm)
        .unwrap();
    decode_path(&vm);
    let (literal_prog, literal_ptrs) = assemble_state_map_schema_with_literals(
        "entries",
        EmbeddedStateType::Bytes,
        &[base_tlv.as_slice(), key_tlv.as_slice()],
    );
    let base_addr = literal_ptrs[0];
    let key_addr = literal_ptrs[1];
    let mut vm = IVM::new(u64::MAX);
    let mut host = CoreHost::new();
    vm.load_program(&literal_prog).unwrap();
    vm.set_register(10, base_addr);
    vm.set_register(11, key_addr);
    host.syscall(syscalls::SYSCALL_BUILD_PATH_KEY_NORITO, &mut vm)
        .unwrap();
    decode_path(&vm);
}
#[test]
fn json_object_builders_roundtrip_i64_and_account_id() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    let p_bucket_key = vm
        .alloc_input_tlv(&tlv(PointerType::Name, b"bucket_id"))
        .unwrap();
    let p_owner_key = vm
        .alloc_input_tlv(&tlv(PointerType::Name, b"owner"))
        .unwrap();
    let owner_literal = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV";
    let p_owner = vm
        .alloc_input_tlv(&tlv(PointerType::AccountId, owner_literal.as_bytes()))
        .unwrap();
    vm.load_program(&common::assemble_syscalls(&[
        syscalls::SYSCALL_JSON_OBJECT as u8
    ]))
    .unwrap();
    vm.run().unwrap();
    let p_payload = vm.register(10);
    vm.set_register(10, p_payload);
    vm.set_register(11, p_bucket_key);
    vm.set_register(12, 2);
    vm.load_program(&common::assemble_syscalls(&[
        syscalls::SYSCALL_JSON_SET_I64 as u8,
    ]))
    .unwrap();
    vm.run().unwrap();
    let p_payload = vm.register(10);
    vm.set_register(10, p_payload);
    vm.set_register(11, p_owner_key);
    vm.set_register(12, p_owner);
    vm.load_program(&common::assemble_syscalls(&[
        syscalls::SYSCALL_JSON_SET_ACCOUNT_ID as u8,
    ]))
    .unwrap();
    vm.run().unwrap();
    let p_payload = vm.register(10);
    vm.set_register(10, p_payload);
    vm.set_register(11, p_owner_key);
    vm.load_program(&common::assemble_syscalls(&[
        syscalls::SYSCALL_JSON_GET_ACCOUNT_ID as u8,
    ]))
    .unwrap();
    vm.run().unwrap();
    let tlv_out = vm.memory.validate_tlv(unwrap_some_word(&vm)).unwrap();
    assert_eq!(tlv_out.type_id, PointerType::AccountId);
    let owner: AccountId = norito::decode_from_bytes(tlv_out.payload).expect("decode account");
    assert_eq!(
        owner,
        AccountId::parse_encoded(owner_literal).expect("valid canonical account id")
    );
}
#[test]
fn json_get_account_id_rejects_noncanonical_contract_address_literal() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    let authority = checked_contract_authority_fixture();
    let contract_address = ContractAddress::derive(
        &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
            .parse()
            .expect("canonical test network id"),
        &authority,
        3,
        DataSpaceId::UNIVERSAL,
    )
    .expect("derive contract address");
    let json = format!(r#"{{"controller":"{}"}}"#, contract_address);
    let p_json = vm
        .alloc_input_tlv(&tlv(PointerType::Json, json.as_bytes()))
        .unwrap();
    let p_key = vm
        .alloc_input_tlv(&tlv(PointerType::Name, b"controller"))
        .unwrap();
    let prog = common::assemble_syscalls(&[syscalls::SYSCALL_JSON_GET_ACCOUNT_ID as u8]);
    vm.set_register(10, p_json);
    vm.set_register(11, p_key);
    vm.load_program(&prog).unwrap();
    // A present field that is not a canonical AccountId literal traps instead
    // of reading as an absent field.
    assert_eq!(vm.run(), Err(ivm::VMError::DecodeError));
}
