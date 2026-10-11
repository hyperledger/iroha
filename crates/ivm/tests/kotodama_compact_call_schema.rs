//! Genuine eager numeric argument and durable getter execution through complete CS1 metadata.

use iroha_crypto::Hash;
use iroha_data_model::smart_contract::entrypoint::{
    EntrypointArgumentRecordV1, EntrypointValueAtomV1,
};
use iroha_model_base::name::Name;
use iroha_primitives::{
    json::Json,
    numeric_abi::{IntValueV1, QuantityValueV1},
};
use ivm::{CoreHost, IVM, PointerType, ProgramMetadata, VMError, host::DefaultHost};
use std::collections::BTreeMap;
mod common;

fn tlv(kind: PointerType, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(kind as u16).to_be_bytes());
    bytes.push(1);
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes.extend_from_slice(Hash::new(payload).as_ref());
    bytes
}
fn quantity_result(vm: &IVM) -> String {
    let value = vm
        .validate_tlv(vm.public_call_result_word(0).unwrap())
        .unwrap();
    assert_eq!(value.type_id, PointerType::Quantity);
    QuantityValueV1::decode_frame(value.payload)
        .unwrap()
        .as_quantity()
        .to_string()
}
#[test]
fn compact_schema_validates_an_unused_numeric_root_argument_before_its_constant_body() {
    let source = "seiyaku UnusedRoot { view fn main(quantity value) authorize(anyone) -> quantity { let quantity constant=7; return constant; } }";
    let program = kotodama_lang::compiler::Compiler::new()
        .compile_source(source)
        .unwrap();
    let parsed = ProgramMetadata::parse(&program).unwrap();
    let entry = &parsed.contract_interface.as_ref().unwrap().entrypoints[0];
    assert_eq!(entry.name, "main");
    let schema = entry.argument_schema.as_ref().unwrap();
    let input = Json::from_str_norito(r#"{"value":"9"}"#).unwrap();
    let original = ivm_abi::arguments::encode_argument_record_from_json(schema, &input).unwrap();
    // Keep the genuine schema hash, record shape, outer TLV type and envelope
    // hash. Only the canonical numeric body is substituted with an Int frame.
    let mut record: EntrypointArgumentRecordV1 = norito::decode_from_bytes(&original).unwrap();
    assert!(matches!(
        record.atoms.as_slice(),
        [EntrypointValueAtomV1::Pointer(_)]
    ));
    record.atoms[0] = EntrypointValueAtomV1::Pointer(tlv(
        PointerType::Quantity,
        &IntValueV1::try_new(9.into())
            .unwrap()
            .encode_frame()
            .unwrap(),
    ));
    let invalid = norito::encode_canonical(&record).unwrap();
    for (payload, valid) in [(original, true), (invalid, false)] {
        let key: Name = ivm_abi::arguments::ENTRYPOINT_ARGUMENT_RECORD_PUBLIC_INPUT_KEY
            .parse()
            .unwrap();
        let mut host = DefaultHost::new().with_public_inputs(BTreeMap::from([(
            key,
            tlv(PointerType::NoritoBytes, &payload),
        )]));
        let mut vm = IVM::new(4_000_000);
        vm.load_program(&program).unwrap();
        common::select_kotodama_entrypoint(&mut vm, &program, "main");
        let result = vm.run_with_host(&mut host);
        assert!(vm.remaining_gas() < 4_000_000);
        if valid {
            assert_eq!(result, Ok(()));
            assert_eq!(quantity_result(&vm), "7");
        } else {
            assert_eq!(result, Err(VMError::DecodeError));
            assert!(vm.call_result_word_count().is_err());
        }
    }
}
#[test]
fn compact_schema_rejects_a_genuine_invalid_durable_quantity_before_an_unused_private_body() {
    let source = "seiyaku UnusedDurable { state quantity source; hajimari(){ source=9; } fn unused(quantity value)->quantity { let quantity constant=7; return constant; } view fn main() authorize(anyone) ->quantity { let first=unused(value:source); return unused(value:first); } }";
    let program = kotodama_lang::compiler::Compiler::new()
        .compile_source(source)
        .unwrap();
    let mut host = CoreHost::new();
    let mut initialize = IVM::new(4_000_000);
    initialize.load_program(&program).unwrap();
    common::select_kotodama_entrypoint(&mut initialize, &program, "hajimari");
    assert_eq!(initialize.run_with_host(&mut host), Ok(()));
    let original = host.state_bytes("source").unwrap();
    let mut valid = IVM::new(4_000_000);
    valid.load_program(&program).unwrap();
    common::select_kotodama_entrypoint(&mut valid, &program, "main");
    assert_eq!(valid.run_with_host(&mut host), Ok(()));
    assert_eq!(quantity_result(&valid), "7");
    assert_eq!(host.state_bytes("source").unwrap(), original);
    let invalid = common::encode_pointer_state_value(
        ivm_abi::state_value::StateValueKindV1::Quantity,
        PointerType::Quantity,
        &IntValueV1::try_new(9.into())
            .unwrap()
            .encode_frame()
            .unwrap(),
    );
    host.insert_state_value("source", invalid.clone());
    let mut vm = IVM::new(4_000_000);
    vm.load_program(&program).unwrap();
    common::select_kotodama_entrypoint(&mut vm, &program, "main");
    assert_eq!(vm.run_with_host(&mut host), Err(VMError::DecodeError));
    assert!(vm.call_result_word_count().is_err());
    assert!(vm.remaining_gas() < 4_000_000);
    assert_eq!(
        host.state_bytes("source").unwrap(),
        invalid,
        "failed getter cannot rewrite the original durable record"
    );
    host.insert_state_value("source", original);
    let mut retry = IVM::new(4_000_000);
    retry.load_program(&program).unwrap();
    common::select_kotodama_entrypoint(&mut retry, &program, "main");
    assert_eq!(retry.run_with_host(&mut host), Ok(()));
    assert_eq!(quantity_result(&retry), "7");
}
