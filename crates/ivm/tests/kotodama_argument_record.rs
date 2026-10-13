//! End-to-end coverage for one-shot public entrypoint argument decoding.
use iroha_crypto::Hash;
use iroha_model_base::name::Name;
use iroha_primitives::json::Json;
use ivm::{
    IVM, ProgramMetadata,
    mock_wsv::{AccountId, MockWorldStateView, WsvHost},
    pointer_abi::PointerType,
};
use std::{collections::BTreeMap, fs};
mod common;
fn tlv(pointer_type: PointerType, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(7 + payload.len() + Hash::LENGTH);
    out.extend_from_slice(&(pointer_type as u16).to_be_bytes());
    out.push(1);
    out.extend_from_slice(
        &u32::try_from(payload.len())
            .expect("test payload fits u32")
            .to_be_bytes(),
    );
    out.extend_from_slice(payload);
    out.extend_from_slice(Hash::new(payload).as_ref());
    out
}
fn argument_record_tlv(entrypoint: &ivm::EmbeddedEntrypointDescriptor, payload: &Json) -> Vec<u8> {
    let schema = entrypoint
        .argument_schema
        .as_ref()
        .expect("parameterized entrypoint argument schema");
    let record = ivm_abi::arguments::encode_argument_record_from_json(schema, payload)
        .expect("encode argument record");
    tlv(PointerType::NoritoBytes, &record)
}
fn host_with_arguments(inputs: BTreeMap<Name, Vec<u8>>) -> WsvHost {
    let caller = AccountId::new(
        "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774"
            .parse()
            .expect("sample public key"),
    );
    WsvHost::new_with_subject(MockWorldStateView::new(), caller).with_public_inputs(inputs)
}
#[test]
fn shared_sdk_fixture_is_generated_and_validated_by_rust() {
    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/kotodama/entrypoint_argument_record_v1.json");
    let fixture_text = fs::read_to_string(&fixture_path).expect("read shared argument fixture");
    let fixture: norito::json::Value =
        norito::json::from_str(&fixture_text).expect("parse shared argument fixture");
    let root = fixture.as_object().expect("fixture root object");
    assert_eq!(
        root.get("codec").and_then(norito::json::Value::as_str),
        Some("EntrypointArgumentRecordV1")
    );
    assert_eq!(
        root.get("generator").and_then(norito::json::Value::as_str),
        Some("ivm_abi::arguments::encode_argument_record_from_json")
    );
    let contract = root
        .get("contract")
        .and_then(norito::json::Value::as_object)
        .expect("fixture contract object");
    let source = contract
        .get("source")
        .and_then(norito::json::Value::as_str)
        .expect("fixture contract source");
    let entrypoint_name = contract
        .get("entrypoint")
        .and_then(norito::json::Value::as_str)
        .expect("fixture entrypoint name");
    let code = kotodama_lang::compiler::Compiler::new()
        .compile_source(source)
        .expect("compile shared fixture contract");
    let parsed = ProgramMetadata::parse(&code).expect("parse shared fixture contract");
    let entrypoint = parsed
        .contract_interface
        .as_ref()
        .expect("fixture contract interface")
        .entrypoints
        .iter()
        .find(|entrypoint| entrypoint.name == entrypoint_name)
        .expect("fixture entrypoint descriptor");
    let schema = entrypoint
        .argument_schema
        .as_ref()
        .expect("fixture entrypoint schema");
    let boundary = root
        .get("torii_boundary")
        .and_then(norito::json::Value::as_object)
        .expect("fixture Torii boundary");
    let payload = Json::from(
        boundary
            .get("payload")
            .expect("fixture boundary payload")
            .clone(),
    );
    let generated = ivm_abi::arguments::encode_argument_record_from_json(schema, &payload)
        .expect("generate fixture record");
    let expected_schema = root
        .get("entrypoint_argument_schema_v1")
        .and_then(norito::json::Value::as_object)
        .expect("fixture schema evidence");
    let expected_schema_bytes = hex::decode(
        expected_schema
            .get("norito_hex")
            .and_then(norito::json::Value::as_str)
            .expect("fixture schema bytes"),
    )
    .expect("decode fixture schema bytes");
    assert_eq!(
        norito::to_bytes(schema).expect("encode fixture schema"),
        expected_schema_bytes
    );
    let expected_record = root
        .get("entrypoint_argument_record_v1")
        .and_then(norito::json::Value::as_object)
        .expect("fixture record evidence");
    let expected_record_bytes = hex::decode(
        expected_record
            .get("norito_hex")
            .and_then(norito::json::Value::as_str)
            .expect("fixture record bytes"),
    )
    .expect("decode fixture record bytes");
    assert_eq!(generated, expected_record_bytes);
    let validated = ivm::validate_argument_record(schema, &generated)
        .expect("validate Rust-generated fixture record");
    assert_eq!(
        hex::encode(validated.schema_hash),
        expected_schema
            .get("schema_hash_hex")
            .and_then(norito::json::Value::as_str)
            .expect("fixture schema hash")
    );
    let payload_object = boundary
        .get("payload")
        .and_then(norito::json::Value::as_object)
        .expect("fixture boundary payload object");
    for (field, expected) in [
        ("count", "-7"),
        (
            "exact_int",
            "1606938044258990275541962092341162602522202993782792835301376",
        ),
        ("exact_decimal", "-12345678901234567890.125"),
        (
            "exact_quantity",
            "12345678901234567890.0000000000000000000000000001",
        ),
    ] {
        assert_eq!(
            payload_object
                .get(field)
                .and_then(norito::json::Value::as_str),
            Some(expected),
            "{field} must remain a canonical JSON string",
        );
    }
    let entry_pc =
        u64::try_from(parsed.prefix_len()).expect("prefix fits u64") + entrypoint.entry_pc;
    let key: Name = ivm_abi::arguments::ENTRYPOINT_ARGUMENT_RECORD_PUBLIC_INPUT_KEY
        .parse()
        .expect("public input key");
    let host = host_with_arguments(BTreeMap::from([(
        key,
        tlv(PointerType::NoritoBytes, &generated),
    )]));
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&code)
        .expect("load shared fixture contract");
    vm.set_program_counter(entry_pc)
        .expect("select shared quote wrapper");
    vm.set_host(host);
    vm.run()
        .expect("execute shared exact-number argument fixture");
    assert_eq!(common::decode_i64_return_word(&vm, 0), -7);
}
#[test]
fn compiled_wrapper_decodes_record_and_loads_aligned_words() {
    let source = r#"
seiyaku ArgumentRecordRuntime {
  view fn run(int count, Name label) authorize(anyone) -> int {
    let _label = label;
    return count;
  }
}
"#;
    let code = kotodama_lang::compiler::Compiler::new()
        .compile_source(source)
        .expect("compile parameterized view");
    let parsed = ProgramMetadata::parse(&code).expect("parse compiled metadata");
    let interface = parsed
        .contract_interface
        .as_ref()
        .expect("embedded contract interface");
    let run = interface
        .entrypoints
        .iter()
        .find(|entrypoint| entrypoint.name == "run")
        .expect("run entrypoint descriptor");
    let entry_pc = u64::try_from(parsed.prefix_len()).expect("prefix fits u64") + run.entry_pc;
    let payload =
        Json::from_str_norito(r#"{"count":"41","label":"ready"}"#).expect("valid boundary JSON");
    let key: Name = ivm_abi::arguments::ENTRYPOINT_ARGUMENT_RECORD_PUBLIC_INPUT_KEY
        .parse()
        .expect("public input key");
    let host = host_with_arguments(BTreeMap::from([(key, argument_record_tlv(run, &payload))]));
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&code).expect("load compiled program");
    vm.set_program_counter(entry_pc)
        .expect("select run wrapper");
    vm.set_host(host);
    vm.run().expect("execute parameterized wrapper");
    assert_eq!(common::decode_i64_return_word(&vm, 0), 41);
}
#[test]
fn single_json_parameter_is_a_named_record_field_not_the_transport_object() {
    let source = r#"
seiyaku JsonArgumentRecordRuntime {
  view fn run(Json firing_event) authorize(anyone) -> Option<int> {
    firing_event.get_int(Name::parse("value"))
  }
}
"#;
    let code = kotodama_lang::compiler::Compiler::new()
        .compile_source(source)
        .expect("compile Json parameter view");
    let parsed = ProgramMetadata::parse(&code).expect("parse compiled metadata");
    let run = parsed
        .contract_interface
        .as_ref()
        .expect("embedded contract interface")
        .entrypoints
        .iter()
        .find(|entrypoint| entrypoint.name == "run")
        .expect("run entrypoint descriptor");
    let entry_pc = u64::try_from(parsed.prefix_len()).expect("prefix fits u64") + run.entry_pc;
    let payload = Json::from_str_norito(r#"{"firing_event":{"value":"29"}}"#)
        .expect("valid named Json boundary field");
    let key: Name = ivm_abi::arguments::ENTRYPOINT_ARGUMENT_RECORD_PUBLIC_INPUT_KEY
        .parse()
        .expect("public input key");
    let host = host_with_arguments(BTreeMap::from([(key, argument_record_tlv(run, &payload))]));
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&code).expect("load compiled program");
    vm.set_program_counter(entry_pc)
        .expect("select run wrapper");
    vm.set_host(host);
    vm.run().expect("execute Json argument wrapper");
    let layout = ivm::sum::SumLayoutV1::option(1).expect("Option<int> layout");
    let (present, payload) = ivm::sum::read_words(
        &vm,
        vm.public_call_result_word(0)
            .expect("completed return word"),
        layout,
    )
    .expect("read Option<int>");
    assert!(present);
    assert_eq!(payload.len(), 1);
    assert_eq!(common::decode_i64_word(&vm, payload[0]), 29);

    let numeric_token =
        Json::from_str_norito(r#"{"firing_event":{"value":29}}"#).expect("number-token JSON field");
    let key: Name = ivm_abi::arguments::ENTRYPOINT_ARGUMENT_RECORD_PUBLIC_INPUT_KEY
        .parse()
        .expect("public input key");
    let host = host_with_arguments(BTreeMap::from([(
        key,
        argument_record_tlv(run, &numeric_token),
    )]));
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&code).expect("load compiled program");
    vm.set_program_counter(entry_pc)
        .expect("select run wrapper");
    vm.set_host(host);
    // A present JSON number token is malformed input for the exact int getter:
    // the call aborts instead of reading the field as absent.
    assert!(
        matches!(vm.run(), Err(ivm::VMError::DecodeError)),
        "typed int getter must reject a JSON number token"
    );
}
#[test]
fn compiled_wrapper_rebuilds_recursive_public_types_from_one_record() {
    let source = r#"
seiyaku RecursiveArgumentRecordRuntime {
  struct Request { int count, bool ready }

  view fn run(
    Request request,
    (int, bool) pair,
    Option<int> maybe,
    Result<int, bool> outcome
  ) authorize(anyone) -> int {
    let optional = match maybe { Option::some(value) => value, Option::none => 0 };
    let result = match outcome { Result::ok(value) => value, Result::err(_) => 0 };
    if (!request.ready || !pair.1) { return 0; }
    return request.count + pair.0 + optional + result;
  }
}
"#;
    let code = kotodama_lang::compiler::Compiler::new()
        .compile_source(source)
        .expect("compile recursive public arguments");
    let parsed = ProgramMetadata::parse(&code).expect("parse compiled metadata");
    let run = parsed
        .contract_interface
        .as_ref()
        .expect("embedded contract interface")
        .entrypoints
        .iter()
        .find(|entrypoint| entrypoint.name == "run")
        .expect("run entrypoint descriptor");
    let entry_pc = u64::try_from(parsed.prefix_len()).expect("prefix fits u64") + run.entry_pc;
    let payload = Json::from_str_norito(
        r#"{"maybe":{"some":"13"},"outcome":{"ok":"17"},"pair":["11",true],"request":{"count":"7","ready":true}}"#,
    )
    .expect("valid recursive boundary JSON");
    let key: Name = ivm_abi::arguments::ENTRYPOINT_ARGUMENT_RECORD_PUBLIC_INPUT_KEY
        .parse()
        .expect("public input key");
    let host = host_with_arguments(BTreeMap::from([(key, argument_record_tlv(run, &payload))]));
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&code).expect("load compiled program");
    vm.set_program_counter(entry_pc)
        .expect("select run wrapper");
    vm.set_host(host);
    vm.run().expect("execute recursive wrapper");
    assert_eq!(common::decode_i64_return_word(&vm, 0), 48);
}
