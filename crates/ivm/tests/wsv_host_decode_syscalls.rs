//! WsvHost JSON/Name/Schema decode syscalls coverage.
use iroha_crypto::PublicKey;
use iroha_data_model::prelude::AssetDefinitionId;
use iroha_model_base::name::Name;
use iroha_primitives::json::Json;
use ivm::{
    IVM, PointerType, VMError,
    mock_wsv::{AccountId, MockWorldStateView, WsvHost},
    syscalls,
};
use std::str::FromStr;
mod common;
fn make_tlv(pty: PointerType, payload: &[u8]) -> Vec<u8> {
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
fn unwrap_some_word(vm: &IVM) -> u64 {
    let layout = ivm::sum::SumLayoutV1::option(1).expect("Option layout");
    let (is_some, words) =
        ivm::sum::read_words(vm, vm.register(10), layout).expect("read typed JSON getter Option");
    assert!(is_some, "typed JSON getter must return Option::some");
    assert_eq!(words.len(), 1);
    words[0]
}
fn account(_domain: &str, public_key: &str) -> AccountId {
    let public_key: PublicKey = public_key.parse().expect("public key");
    AccountId::new(public_key)
}
fn wsv_host() -> WsvHost {
    let wsv = MockWorldStateView::new();
    let caller = account(
        "wonderland",
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
    );
    WsvHost::new_with_subject(wsv, caller.clone())
}
#[test]
fn wsv_host_name_decode_roundtrip() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(wsv_host());
    let name = "wonderland";
    let name_payload =
        norito::to_bytes(&Name::from_str(name).expect("name parse")).expect("encode name");
    let p_name = vm
        .alloc_input_tlv(&make_tlv(PointerType::NoritoBytes, &name_payload))
        .expect("alloc name");
    let prog = common::assemble_syscalls(&[syscalls::SYSCALL_NAME_DECODE as u8]);
    vm.set_register(10, p_name);
    vm.load_program(&prog).expect("load program");
    vm.run().expect("name decode");
    let out_ptr = vm.register(10);
    let tlv = vm.memory.validate_tlv(out_ptr).expect("output tlv");
    assert_eq!(tlv.type_id, PointerType::Name);
    let parsed: Name = norito::decode_from_bytes(tlv.payload).expect("decode name");
    assert_eq!(parsed.as_ref(), name);
}
#[test]
fn wsv_host_json_decode_rejects_retired_blob_carrier() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(wsv_host());
    let json = br#"{"a":1,"b":[2,3]}"#;
    let p_blob = vm
        .alloc_input_tlv(&make_tlv(PointerType::Blob, json))
        .expect("alloc blob");
    let prog = common::assemble_syscalls(&[syscalls::SYSCALL_JSON_DECODE as u8]);
    vm.set_register(10, p_blob);
    vm.load_program(&prog).expect("load program");
    assert!(matches!(vm.run(), Err(VMError::NoritoInvalid)));
    assert_eq!(vm.register(10), p_blob);
}
#[test]
fn wsv_host_json_get_asset_definition_id_reads_address_literals() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(wsv_host());
    let json = br#"{"asset_definition_id":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM"}"#;
    let p_json = vm
        .alloc_input_tlv(&make_tlv(PointerType::Json, json))
        .expect("alloc json");
    let p_key = vm
        .alloc_input_tlv(&make_tlv(PointerType::Name, b"asset_definition_id"))
        .expect("alloc key");
    let prog = common::assemble_syscalls(&[syscalls::SYSCALL_JSON_GET_ASSET_DEFINITION_ID as u8]);
    vm.set_register(10, p_json);
    vm.set_register(11, p_key);
    vm.load_program(&prog).expect("load program");
    vm.run().expect("json get asset definition id");
    let out_ptr = unwrap_some_word(&vm);
    let tlv = vm.memory.validate_tlv(out_ptr).expect("output tlv");
    assert_eq!(tlv.type_id, PointerType::AssetDefinitionId);
    let asset: AssetDefinitionId = norito::decode_from_bytes(tlv.payload).expect("decode asset");
    assert_eq!(
        asset,
        AssetDefinitionId::parse_address_literal("62Fk4FPcMuLvW5QjDGNF2a4jAmjM").unwrap()
    );
}
#[test]
fn wsv_host_schema_decode_roundtrip() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(wsv_host());
    let schema = b"Order";
    let json = br#"{"qty":10,"side":"buy"}"#;
    let p_schema = vm
        .alloc_input_tlv(&make_tlv(PointerType::Name, schema))
        .expect("alloc schema");
    let p_json = vm
        .alloc_input_tlv(&make_tlv(PointerType::Json, json))
        .expect("alloc order json");
    let enc_prog = common::assemble_syscalls(&[syscalls::SYSCALL_SCHEMA_ENCODE as u8]);
    vm.set_register(10, p_schema);
    vm.set_register(11, p_json);
    vm.load_program(&enc_prog).expect("load program");
    vm.run().expect("schema encode");
    let p_bytes = vm.register(10);
    let encoded = vm.memory.validate_tlv(p_bytes).expect("encoded tlv");
    assert_eq!(encoded.type_id, PointerType::NoritoBytes);
    let p_bytes_in = vm
        .alloc_input_tlv(&make_tlv(PointerType::NoritoBytes, encoded.payload))
        .expect("alloc encoded order bytes");
    let prog = common::assemble_syscalls(&[syscalls::SYSCALL_SCHEMA_DECODE as u8]);
    vm.set_register(10, p_schema);
    vm.set_register(11, p_bytes_in);
    vm.load_program(&prog).expect("load program");
    vm.run().expect("schema decode");
    let out_ptr = vm.register(10);
    let tlv = vm.memory.validate_tlv(out_ptr).expect("output tlv");
    assert_eq!(tlv.type_id, PointerType::Json);
    let value: norito::json::Value = common::json_from_payload(tlv.payload);
    let obj = value.as_object().expect("json object");
    assert_eq!(obj.get("qty").and_then(|v| v.as_i64()), Some(10));
    assert_eq!(obj.get("side").and_then(|v| v.as_str()), Some("buy"));
}
#[test]
fn wsv_host_schema_unknown_and_malformed_inputs_fail_closed() {
    let json = br#"{"hello":"world","n":1}"#;
    let expected =
        Json::from_str_norito(std::str::from_utf8(json).expect("json utf8")).expect("parse json");
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(wsv_host());
    let p_schema = vm
        .alloc_input_tlv(&make_tlv(PointerType::Name, b"UnknownSchema"))
        .expect("alloc schema");
    let p_json = vm
        .alloc_input_tlv(&make_tlv(PointerType::Json, json))
        .expect("alloc json");
    let enc_prog = common::assemble_syscalls(&[syscalls::SYSCALL_SCHEMA_ENCODE as u8]);
    vm.set_register(10, p_schema);
    vm.set_register(11, p_json);
    vm.load_program(&enc_prog).expect("load program");
    assert!(matches!(vm.run(), Err(VMError::NoritoInvalid)));
    assert_eq!(vm.register(10), p_schema);
    assert_eq!(vm.register(11), p_json);
    let encoded = norito::to_bytes(&expected).expect("encode adversarial generic JSON");
    for (schema, payload) in [
        (&b"UnknownSchema"[..], encoded.as_slice()),
        (&b"Order"[..], encoded.as_slice()),
    ] {
        let mut vm = IVM::new(u64::MAX);
        vm.set_host(wsv_host());
        let p_schema = vm
            .alloc_input_tlv(&make_tlv(PointerType::Name, schema))
            .expect("alloc schema");
        let p_blob_in = vm
            .alloc_input_tlv(&make_tlv(PointerType::NoritoBytes, payload))
            .expect("alloc blob");
        let dec_prog = common::assemble_syscalls(&[syscalls::SYSCALL_SCHEMA_DECODE as u8]);
        vm.set_register(10, p_schema);
        vm.set_register(11, p_blob_in);
        vm.load_program(&dec_prog).expect("load program");
        assert!(matches!(vm.run(), Err(VMError::NoritoInvalid)));
        assert_eq!(vm.register(10), p_schema);
        assert_eq!(vm.register(11), p_blob_in);
    }
}
