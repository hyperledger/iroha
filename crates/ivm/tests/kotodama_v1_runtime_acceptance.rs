//! End-to-end acceptance coverage for Kotodama V1 runtime semantics.
use crate::common;
use iroha_crypto::Hash;
use iroha_model_base::name::Name;
use iroha_primitives::json::Json;
use ivm::{CoreHost, IVM, ProgramMetadata, host::DefaultHost, pointer_abi::PointerType};
use kotodama_lang::compiler::Compiler;
use norito::json as njson;
use std::{collections::BTreeMap, fmt::Write as _};
const MAX_INT: &str = "6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042047";
const MAX_INT_MINUS_ONE: &str = "6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042046";
const MIN_INT: &str = "-6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042048";
const MIN_INT_PLUS_ONE: &str = "-6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042047";
fn compile_and_run(source: &str) -> IVM {
    let code = Compiler::new()
        .compile_source(source)
        .expect("compile V1 contract");
    let parsed = ProgramMetadata::parse(&code).expect("parse V1 contract metadata");
    let run = parsed
        .contract_interface
        .as_ref()
        .expect("embedded contract interface")
        .entrypoints
        .iter()
        .find(|entrypoint| entrypoint.name == "run")
        .expect("run entrypoint descriptor");
    let entry_pc = u64::try_from(parsed.prefix_len()).expect("prefix fits u64") + run.entry_pc;
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    vm.load_program(&code).expect("load V1 contract");
    vm.set_program_counter(entry_pc)
        .expect("select run entrypoint");
    vm.run().expect("run V1 contract");
    vm
}
fn compile_and_run_with_default_host(source: &str) -> IVM {
    let code = Compiler::new()
        .compile_source(source)
        .expect("compile V1 contract for the standalone host");
    let parsed = ProgramMetadata::parse(&code).expect("parse V1 contract metadata");
    let run = parsed
        .contract_interface
        .as_ref()
        .expect("embedded contract interface")
        .entrypoints
        .iter()
        .find(|entrypoint| entrypoint.name == "run")
        .expect("run entrypoint descriptor");
    let entry_pc = u64::try_from(parsed.prefix_len()).expect("prefix fits u64") + run.entry_pc;
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&code).expect("load V1 contract");
    vm.set_program_counter(entry_pc)
        .expect("select run entrypoint");
    vm.run().expect("run V1 contract with DefaultHost");
    vm
}
fn compile_init_and_run(source: &str) -> IVM {
    let code = Compiler::new()
        .compile_source(source)
        .expect("compile initialized V1 contract");
    let parsed = ProgramMetadata::parse(&code).expect("parse initialized V1 contract metadata");
    let interface = parsed
        .contract_interface
        .as_ref()
        .expect("embedded contract interface");
    let entry_pc = |name: &str| {
        let entry = interface
            .entrypoints
            .iter()
            .find(|entrypoint| entrypoint.name == name)
            .unwrap_or_else(|| panic!("missing {name} entrypoint"));
        u64::try_from(parsed.prefix_len()).expect("prefix fits u64") + entry.entry_pc
    };
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    vm.load_program(&code)
        .expect("load initialized V1 contract");
    vm.set_program_counter(entry_pc("hajimari"))
        .expect("select hajimari entrypoint");
    vm.run().expect("initialize V1 contract");
    vm.reset().expect("private lifecycle cleanup succeeds");
    vm.set_gas_limit(u64::MAX);
    vm.set_program_counter(entry_pc("run"))
        .expect("select run entrypoint");
    vm.run().expect("run initialized V1 contract");
    vm
}
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
fn argument_host(
    schema: &ivm_abi::entrypoint::EntrypointArgumentSchemaV1,
    left: &str,
    right: &str,
) -> DefaultHost {
    let payload = Json::from_str_norito(&format!(r#"{{"left":"{left}","right":"{right}"}}"#))
        .expect("valid comparison arguments");
    let payload = ivm_abi::arguments::encode_argument_record_from_json(schema, &payload)
        .expect("encode comparison argument record");
    let key: Name = ivm_abi::arguments::ENTRYPOINT_ARGUMENT_RECORD_PUBLIC_INPUT_KEY
        .parse()
        .expect("public input key");
    DefaultHost::new().with_public_inputs(BTreeMap::from([(
        key,
        tlv(PointerType::NoritoBytes, &payload),
    )]))
}
#[test]
fn call_aware_allocation_preserves_internal_call_and_tuple_results() {
    let source = include_str!("../fixtures/koto_v1/kotodama_v1_runtime_acceptance/001.ko");
    let vm = compile_and_run(source);
    assert_eq!(
        vm.public_call_result_word(0)
            .expect("completed return word"),
        1
    );
}
#[test]
fn mixed_value_and_divergent_tails_execute_both_paths_without_unit_fallthrough() {
    let source = include_str!("../fixtures/koto_v1/kotodama_v1_runtime_acceptance/002.ko");
    let vm = compile_and_run(source);
    assert_eq!(common::decode_i64_return_word(&vm, 0), 25);
}
#[test]
fn result_if_let_executes_both_tags_and_binds_only_the_selected_payload() {
    let source = include_str!("../fixtures/koto_v1/kotodama_v1_runtime_acceptance/003.ko");
    let vm = compile_and_run(source);
    assert_eq!(common::decode_i64_return_word(&vm, 0), 4978);
}
#[test]
fn state_map_get_distinguishes_absent_present_zero_and_removal() {
    let source = include_str!("../fixtures/koto_v1/kotodama_v1_runtime_acceptance/004.ko");
    let vm = compile_and_run(source);
    assert_eq!(common::decode_i64_return_word(&vm, 0), 1);
}
#[test]
fn aggregate_state_map_value_roundtrips_as_one_record() {
    let source = include_str!("../fixtures/koto_v1/kotodama_v1_runtime_acceptance/005.ko");
    let vm = compile_and_run(source);
    assert_eq!(common::decode_i64_return_word(&vm, 0), 9);
}
#[test]
fn aggregate_option_and_result_unwrap_merge_each_payload_word() {
    let source = include_str!("../fixtures/koto_v1/kotodama_v1_runtime_acceptance/006.ko");
    let vm = compile_and_run(source);
    assert_eq!(common::decode_i64_return_word(&vm, 0), 67);
}
#[test]
fn propagation_materializes_the_enclosing_sum_layout_on_failure() {
    let result_source = include_str!("../fixtures/koto_v1/kotodama_v1_runtime_acceptance/007.ko");
    let result_vm = compile_and_run(result_source);
    let result_layout = ivm::sum::SumLayoutV1::try_new(1, 2).expect("Result layout");
    assert_eq!(
        (ivm::sum::read_words(
            &result_vm,
            result_vm
                .public_call_result_word(0)
                .expect("completed return word"),
            result_layout
        ))
        .expect("expected successful fixture result"),
        (false, vec![1]),
        "the returned error must occupy the wider enclosing Result allocation"
    );
    let option_source = include_str!("../fixtures/koto_v1/kotodama_v1_runtime_acceptance/008.ko");
    let option_vm = compile_and_run(option_source);
    let option_layout = ivm::sum::SumLayoutV1::option(2).expect("Option layout");
    assert_eq!(
        (ivm::sum::read_words(
            &option_vm,
            option_vm
                .public_call_result_word(0)
                .expect("completed return word"),
            option_layout
        ))
        .expect("expected successful fixture result"),
        (false, vec![]),
        "the returned none must occupy the wider enclosing Option allocation"
    );
}
#[test]
fn native_json_executes_once_and_returns_canonical_recursive_values() {
    let source = include_str!("../fixtures/koto_v1/kotodama_v1_runtime_acceptance/009.ko");
    let vm = compile_and_run(source);
    let output = vm
        .validate_tlv(
            vm.public_call_result_word(0)
                .expect("completed return word"),
        )
        .expect("native JSON result TLV");
    assert_eq!(output.type_id, PointerType::Json);
    let json: Json = norito::decode_from_bytes(output.payload).expect("decode native JSON result");
    let value: njson::Value = json
        .clone()
        .try_into_any_norito()
        .expect("convert native JSON result");
    assert_eq!(
        value,
        norito::json!({
            "amount": "1.25",
            "blobs": ["0xaa", "0xbb"],
            "labels": ["primary", "secondary"],
            "maybe": { "some": "1.25" },
            "z_bytes": "0xab01",
        })
    );
    let rendered = njson::to_string(&json).expect("render native JSON result");
    let key_positions = ["amount", "blobs", "labels", "maybe", "z_bytes"].map(|key| {
        rendered
            .find(&format!("\"{key}\""))
            .unwrap_or_else(|| panic!("missing canonical key `{key}` in {rendered}"))
    });
    assert!(
        key_positions.windows(2).all(|pair| pair[0] < pair[1]),
        "object keys must be encoded in canonical lexical order: {rendered}"
    );
}
#[test]
fn native_json_literal_and_dynamic_options_preserve_identical_tags() {
    let vm = compile_and_run(
        r#"
        seiyaku TaggedJson {
            fn pass(Option<()> _ value) -> Option<()> { value }
            fn increment(int _ value) -> int { value + 1 }
            view fn run() authorize(anyone) -> Json {
                let Option<()> absent = Option::none;
                let present = pass(Option::some(()));
                let dynamic_absent = pass(absent);
                json {
                    literal: json {
                        present: Option::some(()),
                        absent: absent,
                        nested: Option::some(Option::some(())),
                        present_absent: Option::some(absent),
                        items: [Option::some(()), absent],
                        folded: Option::some(1 + 2),
                    },
                    dynamic: json {
                        present: present,
                        absent: dynamic_absent,
                        nested: Option::some(present),
                        present_absent: Option::some(dynamic_absent),
                        items: [present, dynamic_absent],
                        folded: Option::some(increment(2)),
                    },
                }
            }
        }
    "#,
    );
    let json: Json = norito::decode_from_bytes(
        vm.validate_tlv(
            vm.public_call_result_word(0)
                .expect("completed return word"),
        )
        .unwrap()
        .payload,
    )
    .expect("canonical native JSON result");
    let value: njson::Value = json.try_into_any_norito().unwrap();
    let expected = norito::json!({
        "present": { "some": null },
        "absent": { "none": true },
        "nested": { "some": { "some": null } },
        "present_absent": { "some": { "none": true } },
        "items": [{ "some": null }, { "none": true }],
        "folded": { "some": "3" },
    });
    assert_eq!(value.get("literal"), Some(&expected));
    assert_eq!(value.get("dynamic"), Some(&expected));
}
#[test]
fn native_json_and_typed_getters_execute_with_default_host() {
    let source = include_str!("../fixtures/koto_v1/kotodama_v1_runtime_acceptance/010.ko");
    let vm = compile_and_run_with_default_host(source);
    assert_eq!(common::decode_i64_return_word(&vm, 0), 7);
}
#[test]
fn scalar_and_aggregate_state_roots_roundtrip_as_schema_bound_records() {
    let source = include_str!("../fixtures/koto_v1/kotodama_v1_runtime_acceptance/011.ko");
    let vm = compile_init_and_run(source);
    assert_eq!(common::decode_i64_return_word(&vm, 0), 27);
}

#[test]
fn exact_numeric_state_survives_a_fresh_host_snapshot_roundtrip() {
    let source = r#"
        seiyaku DurableNumericState { permission WriteState;
            state int Whole;
            state decimal Rate;
            state quantity Supply;

            hajimari() {
                let int zero_whole = 0;
                let decimal zero_rate = 0;
                let quantity zero_supply = 0;
                Whole = zero_whole;
                Rate = zero_rate;
                Supply = zero_supply;
            }

            kotoage fn store() authorize(WriteState) -> int {
                Whole = 1606938044258990275541962092341162602522202993782792835301376;
                Rate = -12345678901234567890.125;
                Supply = 12345678901234567890.0000000000000000000000000001;
                return 1;
            }

            view fn inspect() authorize(anyone) -> bool {
                return Whole == 1606938044258990275541962092341162602522202993782792835301376
                    && Rate == -12345678901234567890.125
                    && Supply == 12345678901234567890.0000000000000000000000000001;
            }
        }
    "#;
    let program = Compiler::new()
        .compile_source(source)
        .expect("compile exact durable numeric-state contract");
    let parsed = ProgramMetadata::parse(&program).expect("parse durable numeric-state metadata");
    let interface = parsed
        .contract_interface
        .as_ref()
        .expect("durable numeric-state contract carries CNTR");
    let entry_pc = |name: &str| {
        u64::try_from(parsed.prefix_len()).expect("program prefix fits u64")
            + interface
                .entrypoints
                .iter()
                .find(|entrypoint| entrypoint.name == name)
                .unwrap_or_else(|| panic!("missing `{name}` entrypoint"))
                .entry_pc
    };

    let mut writer = CoreHost::new();
    let mut write_vm = IVM::new(u64::MAX);
    write_vm
        .load_program(&program)
        .expect("load durable numeric-state contract for writing");
    write_vm
        .set_program_counter(entry_pc("store"))
        .expect("select numeric-state writer");
    write_vm
        .run_with_host(&mut writer)
        .expect("persist all exact numeric state values");
    assert_eq!(writer.state_paths(), ["Rate", "Supply", "Whole"]);

    let persisted = writer
        .state_paths()
        .into_iter()
        .map(|path| {
            let value = writer
                .state_bytes(&path)
                .unwrap_or_else(|| panic!("missing persisted state `{path}`"));
            (path, value)
        })
        .collect::<Vec<_>>();
    let mut reader = CoreHost::new();
    for (path, value) in persisted {
        reader.insert_state_value(path, value);
    }

    let mut read_vm = IVM::new(u64::MAX);
    read_vm
        .load_program(&program)
        .expect("load durable numeric-state contract after restart");
    read_vm
        .set_program_counter(entry_pc("inspect"))
        .expect("select numeric-state reader");
    read_vm
        .run_with_host(&mut reader)
        .expect("read all exact numeric values after restart");
    assert_eq!(
        read_vm
            .public_call_result_word(0)
            .expect("completed return word"),
        1,
        "schema-bound int, decimal, and quantity state must retain exact values"
    );
}

#[test]
fn pointer_literal_state_is_materialized_before_record_encoding() {
    let source = include_str!("../fixtures/koto_v1/kotodama_v1_runtime_acceptance/012.ko");
    let vm = compile_init_and_run(source);
    assert_eq!(common::decode_i64_return_word(&vm, 0), 1);
}
#[test]
fn logical_operators_short_circuit_state_side_effects() {
    let source = include_str!("../fixtures/koto_v1/kotodama_v1_runtime_acceptance/013.ko");
    let vm = compile_and_run(source);
    assert_eq!(common::decode_i64_return_word(&vm, 0), 2);
}
#[test]
fn state_map_iteration_uses_canonical_norito_byte_order_for_sixty_four_items() {
    let mut source = String::from(include_str!(
        "../fixtures/koto_v1/kotodama_v1_runtime_acceptance/014.ko"
    ));
    let inserted = (-32_i64..32).rev().collect::<Vec<_>>();
    for key in &inserted {
        writeln!(source, "    Values[{key}] = {};", key * 2).expect("write generated assignment");
    }
    source.push_str(
        r#"
    var int seen = 0;
    for (key, value) in Values.take(64) {
"#,
    );
    // The durable key is the complete schema-bound StateValueRecordV1, not
    // its inner numeric pointer. The shared fixture owner emits that same record.
    let mut expected = inserted;
    expected.sort_by_key(|key| common::encode_int_state_value(*key));
    for (index, key) in expected.into_iter().enumerate() {
        writeln!(
            source,
            "      if (seen == {index}) {{ require(key == {key}, IterationError::OutOfOrder); }}"
        )
        .expect("write canonical-order assertion");
    }
    source.push_str(
        r#"
      require(value == key * 2, IterationError::WrongValue);
      seen = seen + 1;
    }
    require(seen == 64, IterationError::WrongItemCount);
    return seen;
  }
}
"#,
    );
    let vm = compile_and_run(&source);
    assert_eq!(common::decode_i64_return_word(&vm, 0), 64);
}
#[test]
fn signed_comparisons_match_all_boundary_pairs_in_values_and_branches() {
    let source = include_str!("../fixtures/koto_v1/kotodama_v1_runtime_acceptance/015.ko");
    let code = Compiler::new()
        .compile_source(source)
        .expect("compile signed comparison contract");
    let parsed = ProgramMetadata::parse(&code).expect("parse comparison metadata");
    let interface = parsed
        .contract_interface
        .as_ref()
        .expect("embedded contract interface");
    let compare = interface
        .entrypoints
        .iter()
        .find(|entrypoint| entrypoint.name == "compare")
        .expect("compare entrypoint descriptor");
    let entry_pc = u64::try_from(parsed.prefix_len()).expect("prefix fits u64") + compare.entry_pc;
    let argument_schema = compare
        .argument_schema
        .as_ref()
        .expect("comparison argument schema");
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&code).expect("load comparison contract");
    vm.set_program_counter(entry_pc)
        .expect("select comparison wrapper");
    let template = vm
        .try_runtime_template()
        .expect("runtime template allocation fits test host");
    let code_len = vm.memory.code_len();
    let loaded_code = vm
        .memory
        .load_region(0, code_len)
        .expect("loaded code region")
        .to_vec();
    let values = [
        MIN_INT,
        MIN_INT_PLUS_ONE,
        "-1",
        "0",
        "1",
        MAX_INT_MINUS_ONE,
        MAX_INT,
    ];
    for (left_index, left) in values.into_iter().enumerate() {
        for (right_index, right) in values.into_iter().enumerate() {
            vm.reset_from_runtime_template(&template)
                .expect("acceptance VM retains its template geometry");
            vm.set_host(argument_host(argument_schema, left, right));
            vm.run().expect("execute signed comparison pair");
            let expected = [
                left_index == right_index,
                left_index != right_index,
                left_index < right_index,
                left_index <= right_index,
                left_index > right_index,
                left_index >= right_index,
            ];
            for (index, expected) in expected.into_iter().enumerate() {
                assert_eq!(
                    vm.public_call_result_word(index)
                        .expect("completed tuple word"),
                    u64::from(expected),
                    "value comparison {index} failed for {left} and {right}"
                );
                assert_eq!(
                    common::decode_i64_return_word(&vm, 6 + index),
                    i64::from(expected),
                    "branch comparison {index} failed for {left} and {right}"
                );
            }
            assert_eq!(vm.memory.code_len(), code_len);
            assert_eq!(
                vm.memory
                    .load_region(0, code_len)
                    .expect("warm code region"),
                loaded_code.as_slice(),
                "warm invocation must retain the loaded bytecode"
            );
        }
    }
}
