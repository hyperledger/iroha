//! `CoreHost` Norito serialization helper syscall coverage.
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
use iroha_core::smartcontracts::ivm::host::CoreHost;
use iroha_crypto::Hash;
use iroha_model_base::{name::Name, state_path::StatePath};
use iroha_primitives::json::Json;
use iroha_test_samples::ALICE_ID;
use ivm::{
    EmbeddedContractInterfaceV1, EmbeddedEntrypointDescriptor, EmbeddedStateDescriptor,
    EmbeddedStateType, IVM, IVMHost, PointerType, ProgramMetadata, VMError, syscalls,
};
use std::convert::TryFrom;
fn make_tlv(pty: PointerType, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(7 + payload.len() + 32);
    v.extend_from_slice(&(pty as u16).to_be_bytes());
    v.push(1);
    let payload_len = u32::try_from(payload.len()).expect("payload length fits in u32");
    v.extend_from_slice(&payload_len.to_be_bytes());
    v.extend_from_slice(payload);
    let h: [u8; 32] = Hash::new(payload).into();
    v.extend_from_slice(&h);
    v
}
fn preload_input(vm: &mut IVM, _offset: u64, blob: &[u8]) -> u64 {
    vm.alloc_input_tlv(blob).expect("allocate input TLV")
}
fn load_metadata(vm: &mut IVM) {
    vm.load_program(&ProgramMetadata::default().encode())
        .expect("load metadata");
    assert_eq!(vm.abi_version(), 1, "default metadata should set ABI v1");
    assert!(
        ivm::syscalls::is_syscall_allowed(vm.syscall_policy(), syscalls::SYSCALL_JSON_ENCODE),
        "ABI policy must allow JSON helpers in tests"
    );
}
fn load_state_map_metadata(vm: &mut IVM, name: &str, key: EmbeddedStateType) {
    let interface = EmbeddedContractInterfaceV1 {
        events: Vec::new(),
        enum_types: Vec::new(),
        permissions: Vec::new(),
        callables: vec![ivm::call::EmbeddedCallableV1 {
                entry_pc: 0,
                frame_bytes: 0,
                arguments: ivm::call::CallSchemaV1::empty(),
                results: ivm::call::CallSchemaV1::unit(),
            }],
        seiyaku_name: "CodecHelperFixture".to_owned(),
        compiler_fingerprint: "iroha-core-tests".to_owned(),
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
            return_schema: Some(iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
                nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Unit],
            }),
            authorization: iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Anyone,
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
    };
    let mut artifact = ProgramMetadata::default().encode();
    artifact.extend_from_slice(&interface.encode_section());
    for instruction in [
        ivm::encoding::wide::encode_store(ivm::instruction::wide::memory::STORE64, 12, 0, 0),
        ivm::encoding::wide::encode_ri(ivm::instruction::wide::arithmetic::ADDI, 10, 12, 0),
        ivm::encoding::wide::encode_ri(ivm::instruction::wide::arithmetic::ADDI, 11, 0, 1),
        ivm::encoding::wide::encode_rr(ivm::instruction::wide::control::JALR, 0, 1, 0),
    ] {
        artifact.extend_from_slice(&instruction.to_le_bytes());
    }
    vm.load_program(&artifact)
        .expect("load schema-bound StateMap metadata");
}
#[test]
fn json_encode_decode_roundtrip() {
    let mut host = CoreHost::new(ALICE_ID.clone());
    let mut vm = IVM::new(0);
    load_metadata(&mut vm);
    let json_value = norito::json::to_string(&norito::json!({
        "a": 1u64,
        "b": [2u64, 3u64]
    }))
    .expect("serialize json value");
    let json = Json::from_str_norito(&json_value).expect("parse json");
    let json_body = norito::to_bytes(&json).expect("encode json payload");
    let json_ptr = preload_input(&mut vm, 0, &make_tlv(PointerType::Json, &json_body));
    vm.set_register(10, json_ptr);
    host.syscall(syscalls::SYSCALL_JSON_ENCODE, &mut vm)
        .expect("json encode syscall succeeds");
    let encoded_ptr = vm.register(10);
    let encoded_tlv = vm
        .memory
        .validate_tlv(encoded_ptr)
        .expect("validate NoritoBytes TLV");
    assert_eq!(encoded_tlv.type_id, PointerType::NoritoBytes);
    host.syscall(syscalls::SYSCALL_JSON_DECODE, &mut vm)
        .expect("json decode syscall succeeds");
    let decoded_ptr = vm.register(10);
    let decoded_tlv = vm
        .memory
        .validate_tlv(decoded_ptr)
        .expect("validate Json TLV");
    assert_eq!(decoded_tlv.type_id, PointerType::Json);
    let decoded_json: Json =
        norito::decode_from_bytes(decoded_tlv.payload).expect("decode json payload");
    let roundtrip: norito::json::Value =
        norito::json::from_str(decoded_json.get()).expect("parse decoded json");
    let original: norito::json::Value =
        norito::json::from_str(json.get()).expect("parse original json");
    assert_eq!(roundtrip, original);
}
#[test]
fn schema_encode_decode_roundtrip() {
    let mut host = CoreHost::new(ALICE_ID.clone());
    let mut vm = IVM::new(0);
    load_metadata(&mut vm);
    let schema_name: Name = "Order".parse().unwrap();
    let schema_body = norito::to_bytes(&schema_name).expect("encode schema name");
    let schema_ptr = preload_input(&mut vm, 0, &make_tlv(PointerType::Name, &schema_body));
    let json_value = norito::json::to_string(&norito::json!({
        "qty": 10i64,
        "side": "buy"
    }))
    .expect("serialize schema json");
    let json = Json::from_str_norito(&json_value).expect("parse schema json");
    let json_body = norito::to_bytes(&json).expect("encode schema json");
    let json_ptr = preload_input(&mut vm, 256, &make_tlv(PointerType::Json, &json_body));
    vm.set_register(10, schema_ptr);
    vm.set_register(11, json_ptr);
    host.syscall(syscalls::SYSCALL_SCHEMA_ENCODE, &mut vm)
        .expect("schema encode succeeds");
    let encoded_ptr = vm.register(10);
    let encoded_tlv = vm
        .memory
        .validate_tlv(encoded_ptr)
        .expect("validate NoritoBytes output");
    assert_eq!(encoded_tlv.type_id, PointerType::NoritoBytes);
    vm.set_register(10, schema_ptr);
    vm.set_register(11, encoded_ptr);
    host.syscall(syscalls::SYSCALL_SCHEMA_DECODE, &mut vm)
        .expect("schema decode succeeds");
    let decoded_ptr = vm.register(10);
    let decoded_tlv = vm
        .memory
        .validate_tlv(decoded_ptr)
        .expect("validate decoded Json TLV");
    assert_eq!(decoded_tlv.type_id, PointerType::Json);
    let decoded_json: Json =
        norito::decode_from_bytes(decoded_tlv.payload).expect("decode schema json");
    let roundtrip: norito::json::Value =
        norito::json::from_str(decoded_json.get()).expect("parse decoded schema json");
    let original: norito::json::Value =
        norito::json::from_str(json.get()).expect("parse original schema json");
    assert_eq!(roundtrip, original);
}
#[test]
fn production_schema_host_rejects_unknown_and_malformed_inputs_for_canonical_syscalls() {
    let unknown_name: Name = "UnknownSchema".parse().expect("unknown schema name");
    let unknown_name_body = norito::to_bytes(&unknown_name).expect("encode unknown schema name");
    let unknown_json =
        Json::from_str_norito(r#"{"value":1}"#).expect("parse adversarial generic JSON");
    let unknown_json_body = norito::to_bytes(&unknown_json).expect("encode generic JSON");
    let mut host = CoreHost::new(ALICE_ID.clone());
    let mut vm = IVM::new(0);
    load_metadata(&mut vm);
    let schema_ptr = preload_input(&mut vm, 0, &make_tlv(PointerType::Name, &unknown_name_body));
    let json_ptr = preload_input(
        &mut vm,
        256,
        &make_tlv(PointerType::Json, &unknown_json_body),
    );
    vm.set_register(10, schema_ptr);
    vm.set_register(11, json_ptr);
    assert_eq!(
        host.syscall(syscalls::SYSCALL_SCHEMA_ENCODE, &mut vm),
        Err(VMError::NoritoInvalid)
    );
    assert_eq!(vm.register(10), schema_ptr);
    assert_eq!(vm.register(11), json_ptr);
    let order_name: Name = "Order".parse().expect("known schema name");
    let order_name_body = norito::to_bytes(&order_name).expect("encode known schema name");
    for (schema_body, payload) in [
        (unknown_name_body.as_slice(), unknown_json_body.as_slice()),
        (order_name_body.as_slice(), unknown_json_body.as_slice()),
    ] {
        let mut host = CoreHost::new(ALICE_ID.clone());
        let mut vm = IVM::new(0);
        load_metadata(&mut vm);
        let schema_ptr = preload_input(&mut vm, 0, &make_tlv(PointerType::Name, schema_body));
        let bytes_ptr = preload_input(&mut vm, 256, &make_tlv(PointerType::NoritoBytes, payload));
        vm.set_register(10, schema_ptr);
        vm.set_register(11, bytes_ptr);
        assert_eq!(
            host.syscall(syscalls::SYSCALL_SCHEMA_DECODE, &mut vm),
            Err(VMError::NoritoInvalid)
        );
        assert_eq!(vm.register(10), schema_ptr);
        assert_eq!(vm.register(11), bytes_ptr);
    }
}
#[test]
fn name_decode_from_norito_bytes() {
    let mut host = CoreHost::new(ALICE_ID.clone());
    let mut vm = IVM::new(0);
    load_metadata(&mut vm);
    let name: Name = "cursor".parse().expect("name");
    let raw = norito::to_bytes(&name).expect("encode name");
    let key_ptr = preload_input(&mut vm, 0, &make_tlv(PointerType::NoritoBytes, &raw));
    vm.set_register(10, key_ptr);
    host.syscall(syscalls::SYSCALL_NAME_DECODE, &mut vm)
        .expect("name decode succeeds");
    let name_ptr = vm.register(10);
    let tlv = vm.memory.validate_tlv(name_ptr).expect("validate name TLV");
    assert_eq!(tlv.type_id, PointerType::Name);
    let decoded: Name = norito::decode_from_bytes(tlv.payload).expect("decode name");
    assert_eq!(decoded.as_ref(), "cursor");
}
#[test]
fn build_path_key_norito_appends_canonical_key_bytes() {
    // Composite paths have their own nominal type and can exceed the Name bound.
    for payload in [b"opaque bytes payload".to_vec(), vec![0xAB; 512]] {
        let mut host = CoreHost::new(ALICE_ID.clone());
        let mut vm = IVM::new(0);
        load_state_map_metadata(&mut vm, "kv", EmbeddedStateType::Bytes);
        let base: Name = "kv".parse().unwrap();
        let base_bytes = norito::to_bytes(&base).expect("encode base name");
        let base_ptr = preload_input(&mut vm, 0, &make_tlv(PointerType::Name, &base_bytes));
        let key = make_tlv(PointerType::Blob, &payload);
        let key_ptr = preload_input(&mut vm, 256, &make_tlv(PointerType::NoritoBytes, &key));
        vm.set_register(10, base_ptr);
        vm.set_register(11, key_ptr);
        host.syscall(syscalls::SYSCALL_BUILD_PATH_KEY_NORITO, &mut vm)
            .expect("path key builder succeeds");
        let out_ptr = vm.register(10);
        let out_tlv = vm
            .memory
            .validate_tlv(out_ptr)
            .expect("validate output StatePath TLV");
        assert_eq!(out_tlv.type_id, PointerType::NoritoBytes);
        let out_path: StatePath =
            norito::decode_from_bytes(out_tlv.payload).expect("decode output StatePath");
        assert_eq!(out_path.as_ref(), format!("kv/{}", hex::encode(key)));
        assert_eq!(
            out_tlv.payload,
            norito::encode_canonical(&out_path).expect("canonical StatePath frame")
        );
    }
}
#[test]
fn schema_info_returns_registry_snapshot() {
    let mut host = CoreHost::new(ALICE_ID.clone());
    let mut vm = IVM::new(0);
    load_metadata(&mut vm);
    let schema: Name = "Order".parse().unwrap();
    let schema_bytes = norito::to_bytes(&schema).expect("encode schema name");
    let schema_ptr = preload_input(&mut vm, 0, &make_tlv(PointerType::Name, &schema_bytes));
    vm.set_register(10, schema_ptr);
    host.syscall(syscalls::SYSCALL_SCHEMA_INFO, &mut vm)
        .expect("schema info succeeds");
    let info_ptr = vm.register(10);
    let info_tlv = vm
        .memory
        .validate_tlv(info_ptr)
        .expect("validate schema info json");
    assert_eq!(info_tlv.type_id, PointerType::Json);
    let info_json: Json =
        norito::decode_from_bytes(info_tlv.payload).expect("decode schema info json");
    let info: norito::json::Value =
        norito::json::from_str(info_json.get()).expect("parse schema info json");
    let current_name = info["current"]["name"].as_str().unwrap();
    assert_eq!(current_name, "OrderByTime");
    let versions = info["versions"].as_array().unwrap();
    assert!(versions.len() >= 2);
}
