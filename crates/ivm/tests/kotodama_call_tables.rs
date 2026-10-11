//! Runtime coverage for the single bounded table ABI across wide products and loop calls.

use ivm::{IVM, ProgramMetadata};
use kotodama_lang::compiler::Compiler as KotodamaCompiler;

fn run_table_function(source: &str) -> IVM {
    let artifact = KotodamaCompiler::new()
        .compile_source(source)
        .expect("compile table program");
    let metadata = ProgramMetadata::parse(&artifact).expect("metadata");
    let main = metadata
        .contract_interface
        .as_ref()
        .expect("CNTR")
        .entrypoints
        .iter()
        .find(|entry| entry.name == "main")
        .expect("main entrypoint");
    let mut vm = IVM::new(5_000_000);
    vm.load_program(&artifact).expect("admit table contract");
    vm.set_program_counter(metadata.prefix_len() as u64 + main.entry_pc)
        .unwrap();
    vm.run().expect("execute authenticated table calls");
    assert_eq!(vm.call_result_word_count().unwrap(), 1);
    vm
}

#[test]
fn wide_arguments_results_and_nested_loop_calls_reuse_caller_tables() {
    let fields = (0..32)
        .map(|index| format!("bool f{index};"))
        .collect::<Vec<_>>()
        .join(" ");
    let values = (0..32)
        .map(|index| format!("f{index}: {}", index % 2 == 0))
        .collect::<Vec<_>>()
        .join(", ");
    let source = format!(
        "seiyaku Wide {{\n        struct Record {{ {fields} }}\n        fn echo(Record value) -> Record {{ value }}\n        fn relay(Record value) -> Record {{ echo(value: value) }}\n        view fn main() authorize(anyone) -> bool {{\n            let expected = Record {{ {values} }};\n            var value = expected;\n            for index in range(4) {{ value = relay(value: value); }}\n            value == expected && value.f0 && !value.f31\n        }}\n    }}"
    );
    let vm = run_table_function(&source);
    assert_eq!(vm.public_call_result_word(0).unwrap(), 1);
}

#[test]
fn unit_calls_initialize_exactly_one_result_slot() {
    let source = "seiyaku UnitCalls { fn unit() { () } fn pair(bool value) -> ((), bool, ()) { (unit(), value, unit()) } view fn main() authorize(anyone) -> bool { pair(value: true) == ((), true, ()) } }";
    let vm = run_table_function(source);
    assert_eq!(vm.public_call_result_word(0).unwrap(), 1);
}

#[test]
fn empty_products_use_unit_slots_in_calls_sums_and_lists() {
    let vm = run_table_function(
        r#"
seiyaku EmptyProducts {
    struct Empty {}
    struct Pair { Empty first; Empty second; }
    fn echo(Empty value) -> Empty { value }
    fn pair(Pair value) -> Pair { value }
    view fn main() authorize(anyone) -> bool {
        let value = echo(value: Empty {});
        let expected = Pair { first: Empty {}, second: Empty {} };
        let List<Empty, 2> items = [value, Empty {}];
        let Option<Empty> wrapped = Option::some(value);
        value == Empty {} && pair(value: expected) == expected
            && items == [Empty {}, Empty {}] && wrapped == Option::some(Empty {})
    }
}
"#,
    );
    assert_eq!(vm.public_call_result_word(0), Ok(1));
    let vm = run_table_function(
        "seiyaku EmptyRoot { struct Empty {} view fn main() authorize(anyone) -> Empty { Empty {} } }",
    );
    assert_eq!(vm.public_call_result_word(0), Ok(0));
}

#[test]
fn wide_sum_payloads_cross_the_signed_immediate_boundary() {
    // The last payload word sits at byte 32,768, beyond the signed IR immediate.
    // Keep the public boundary Boolean: the existing public schema node limit is
    // independent of the wider private function table and its active sum payload.
    let width = 4096;
    let fields = (0..width)
        .map(|index| format!("bool f{index};"))
        .collect::<Vec<_>>()
        .join(" ");
    let values = (0..width)
        .map(|index| {
            if index == width - 1 {
                format!("f{index}: last")
            } else {
                format!("f{index}: {}", index % 2 == 0)
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    // Keep separate artifacts beneath the unchanged 1 MiB image limit. The
    // constructors return sum handles, avoiding repeated wide table marshals.
    let option_source = format!(
        r#"seiyaku WideOption {{
            struct Wide {{ {fields} }}
            fn option(bool last, List<int, 1> trace, int digit) -> Option<Wide> {{
                var log = trace;
                log.set(index: 0, value: log.get(0).unwrap_or(0) * 10 + digit);
                Option::some(Wide {{ {values} }})
            }}
            fn equal(bool last, List<int, 1> trace) -> bool {{
                option(last: true, trace: trace, digit: 1) ==
                    option(last: last, trace: trace, digit: 2)
            }}
            view fn main() authorize(anyone) -> bool {{
                let List<int, 1> trace = [0];
                let same = equal(last: true, trace: trace);
                let different = !equal(last: false, trace: trace);
                let ordered_once = trace.get(0).unwrap_or(0) == 1212;
                let present = option(last: true, trace: trace, digit: 0);
                let selected = match present {{
                    Option::some(value) => value.f0 && !value.f4093 && value.f4094 && value.f4095,
                    Option::none => false,
                }};
                same && different && ordered_once && selected
            }}
        }}"#,
    );
    let result_source = format!(
        r#"seiyaku WideResult {{
            struct Wide {{ {fields} }}
            fn result(bool last, bool success) -> Result<Wide, Wide> {{
                let value = Wide {{ {values} }};
                if success {{ Result::ok(value) }} else {{ Result::err(value) }}
            }}
            view fn main() authorize(anyone) -> bool {{
                let success = result(last: true, success: true);
                let failure = result(last: false, success: false);
                let success_selected = match success {{
                    Result::ok(value) => value.f4095,
                    Result::err(value) => false,
                }};
                let failure_selected = match failure {{
                    Result::ok(value) => false,
                    Result::err(value) => !value.f4095,
                }};
                success_selected && failure_selected
            }}
        }}"#,
    );
    for source in [option_source, result_source] {
        let vm = run_table_function(&source);
        assert_eq!(vm.public_call_result_word(0), Ok(1));
    }
}

fn repeated_boolean_tuple(width: usize, word: &str) -> String {
    let words = std::iter::repeat_n(word, width)
        .collect::<Vec<_>>()
        .join(", ");
    format!("({words})")
}

fn maximum_table_sample_checks(value: &str, expected: bool) -> String {
    // Include both sides of the 32-word transfer window and the signed byte
    // immediate boundary, plus the final physical table slot. Content checks
    // sample these words; runtime admission checks every initialized Bool slot.
    let width = ivm_abi::call::MAX_CALL_WORDS_V1;
    [0, 1, 15, 16, 31, 32, 4095, 4096, width - 2, width - 1]
        .into_iter()
        .map(|index| {
            if expected {
                format!("{value}.{index}")
            } else {
                format!("!{value}.{index}")
            }
        })
        .collect::<Vec<_>>()
        .join(" && ")
}

fn run_maximum_table_function(source: &str, argument_words: usize, result_words: usize) -> IVM {
    use ivm_abi::{
        call::{CallTypeNodeV1, MAX_CALL_WORDS_V1},
        entrypoint::EntrypointValueKindV1,
    };

    assert_eq!(MAX_CALL_WORDS_V1, 8192);
    assert!(source.len() <= kotodama_lang::source::MAX_SOURCE_BYTES);
    let artifact = KotodamaCompiler::new()
        .compile_source(source)
        .expect("compile maximum-width table program within existing limits");
    assert!(
        artifact.len()
            <= ivm_abi::metadata::HEADER_SIZE + ivm_abi::metadata::MAX_PROGRAM_IMAGE_BYTES_V1
    );
    let metadata = ProgramMetadata::parse(&artifact).expect("canonical maximum-table metadata");
    assert_eq!(metadata.metadata.version_major, 1);
    assert_eq!(metadata.metadata.version_minor, 1);
    assert_eq!(metadata.metadata.abi_version, 1);
    let interface = metadata.contract_interface.as_ref().expect("CNTR");
    // The two private functions must survive optimization. A missing wide or
    // nested callable would turn this into a different boundary regression.
    assert_eq!(interface.callables.len(), 3);
    assert!(
        interface
            .callables
            .iter()
            .all(|callable| callable.validate())
    );
    let main = interface
        .entrypoints
        .iter()
        .find(|entry| entry.name == "main")
        .expect("Boolean public main");
    let root = interface
        .callables
        .iter()
        .find(|callable| callable.entry_pc == main.entry_pc)
        .expect("authenticated root callable");
    assert!(root.arguments.nodes.is_empty());
    assert_eq!(root.result_word_count(), Some(1));
    assert_eq!(
        root.results.nodes,
        [CallTypeNodeV1::Leaf(EntrypointValueKindV1::Bool)]
    );
    assert_eq!(
        interface
            .callables
            .iter()
            .filter(|callable| {
                callable.argument_word_count() == Some(argument_words)
                    && callable.result_word_count() == Some(result_words)
            })
            .count(),
        1
    );
    let wide = interface
        .callables
        .iter()
        .find(|callable| {
            callable.argument_word_count() == Some(argument_words)
                && callable.result_word_count() == Some(result_words)
        })
        .unwrap();
    let (wide_schema, narrow_schema) = if argument_words == MAX_CALL_WORDS_V1 {
        (&wide.arguments, &wide.results)
    } else {
        assert_eq!(result_words, MAX_CALL_WORDS_V1);
        (&wide.results, &wide.arguments)
    };
    assert_eq!(wide_schema.nodes.len(), MAX_CALL_WORDS_V1 + 1);
    assert_eq!(
        wide_schema.nodes[0],
        CallTypeNodeV1::Tuple(MAX_CALL_WORDS_V1 as u32)
    );
    assert!(
        wide_schema.nodes[1..]
            .iter()
            .all(|node| { matches!(node, CallTypeNodeV1::Leaf(EntrypointValueKindV1::Bool)) })
    );
    assert_eq!(
        narrow_schema.nodes,
        [CallTypeNodeV1::Leaf(EntrypointValueKindV1::Bool)]
    );
    assert_eq!(
        interface
            .callables
            .iter()
            .filter(|callable| {
                callable.argument_word_count() == Some(1) && callable.result_word_count() == Some(1)
            })
            .count(),
        1
    );

    let mut vm = IVM::new(5_000_000);
    vm.load_program(&artifact)
        .expect("admit original maximum-table artifact");
    vm.select_entrypoint("main").unwrap();
    let original_stack_top = vm.memory.stack_top();
    assert!(vm.call_result_word_count().is_err());
    assert!(vm.public_call_result_word(0).is_err());
    vm.run()
        .expect("execute all maximum-table initialization and nested returns");
    assert_eq!(vm.register(31), original_stack_top);
    assert_eq!(vm.call_result_word_count(), Ok(1));
    assert_eq!(vm.public_call_result_word(0), Ok(1));
    assert!(vm.public_call_result_word(1).is_err());
    // A completed private table's large width cannot replace the original root
    // result owner, even if guest descriptor registers claim another address.
    vm.set_register(10, u64::MAX);
    vm.set_register(11, MAX_CALL_WORDS_V1 as u64);
    assert_eq!(vm.call_result_word_count(), Ok(1));
    assert_eq!(vm.public_call_result_word(0), Ok(1));
    assert!(vm.public_call_result_word(1).is_err());
    vm
}

#[test]
fn maximum_argument_table_initializes_every_word_across_nested_calls() {
    let width = ivm_abi::call::MAX_CALL_WORDS_V1;
    let ty = repeated_boolean_tuple(width, "bool");
    let values = repeated_boolean_tuple(width, "value");
    let checks = maximum_table_sample_checks("value", true);
    let source = format!(
        r#"seiyaku MaximumArguments {{
            fn consume({ty} value) -> bool {{ {checks} }}
            fn relay(bool value) -> bool {{ consume(value: {values}) }}
            view fn main() authorize(anyone) -> bool {{
                let populated = relay(value: true);
                let cleared = relay(value: false);
                populated && !cleared
            }}
        }}"#
    );
    // The nested relay stages all 8192 runtime words in its own immediate
    // caller frame. Both invocations run the complete typed/initialized scan;
    // the true invocation also reads every selected content sentinel.
    let vm = run_maximum_table_function(&source, width, 1);
    assert_eq!(vm.public_call_result_word(0), Ok(1));
}

#[test]
fn maximum_result_table_initializes_every_word_across_nested_returns() {
    let width = ivm_abi::call::MAX_CALL_WORDS_V1;
    let ty = repeated_boolean_tuple(width, "bool");
    let values = repeated_boolean_tuple(width, "second");
    let populated_checks = maximum_table_sample_checks("populated", true);
    let cleared_checks = maximum_table_sample_checks("cleared", false);
    let source = format!(
        r#"seiyaku MaximumResults {{
            fn relay(bool value) -> bool {{ value }}
            fn produce(bool value) -> {ty} {{
                let first = relay(value: value);
                let second = relay(value: first);
                {values}
            }}
            view fn main() authorize(anyone) -> bool {{
                let populated = produce(value: true);
                let populated_ok = {populated_checks};
                let cleared = produce(value: false);
                let cleared_ok = {cleared_checks};
                populated_ok && cleared_ok
            }}
        }}"#
    );
    // Both scalar child returns precede the maximum-width protected copyback.
    // The two producer returns initialize every slot with opposite values in
    // the original caller-owned table before the root may publish its Boolean.
    let vm = run_maximum_table_function(&source, 1, width);
    assert_eq!(vm.public_call_result_word(0), Ok(1));
}

#[test]
fn one_word_beyond_maximum_call_tables_is_rejected_before_lowering() {
    let width = ivm_abi::call::MAX_CALL_WORDS_V1 + 1;
    let ty = repeated_boolean_tuple(width, "bool");
    let values = repeated_boolean_tuple(width, "false");
    for (name, source) in [
        (
            "argument-bound.ko",
            format!(
                "seiyaku ArgumentBound {{ fn too_wide({ty} value) -> bool {{ false }} view fn main() authorize(anyone) -> bool {{ true }} }}"
            ),
        ),
        (
            "result-bound.ko",
            format!(
                "seiyaku ResultBound {{ fn too_wide() -> {ty} {{ {values} }} view fn main() authorize(anyone) -> bool {{ true }} }}"
            ),
        ),
    ] {
        assert!(source.len() <= kotodama_lang::source::MAX_SOURCE_BYTES);
        let error = kotodama_lang::session::CompilerSession::default()
            .check(kotodama_lang::session::CompileRequest {
                source: &source,
                source_name: Some(name),
            })
            .expect_err("8193 words must fail original semantic validation before lowering");
        assert!(error.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "K2007" && diagnostic.message.contains("8192")
        }));
    }
}
