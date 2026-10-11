//! Benchmarks for phase-separated Kotodama compilation and execution in IVM.
use criterion::{BatchSize, Criterion};
use iroha_crypto::Hash;
use iroha_model_base::name::Name;
use iroha_primitives::{
    json::Json,
    numeric::{Numeric, Quantity, RoundingMode},
    numeric_abi::IntValueV1,
};
use ivm::{IVM, ProgramMetadata, encoding, host::DefaultHost, pointer_abi::PointerType};
use kotodama_lang::compiler::{Compiler, benchmark::SourcePhase, encode_add};
use kotodama_lang::{parser, semantic::SemanticContext};
use std::{collections::BTreeMap, sync::Arc};
const LITERAL_BENCH_SIZE: usize = 512;
fn kotodama_program() -> Vec<u8> {
    let src =
        "seiyaku Add { view fn add(int a, int b) authorize(anyone) -> int { return a + b; } }";
    Compiler::new().compile_source(src).expect("compile failed")
}
fn entrypoint_pc(program: &[u8], name: &str) -> u64 {
    let parsed = ProgramMetadata::parse(program).expect("parse Kotodama metadata");
    let entrypoint = parsed
        .contract_interface
        .as_ref()
        .expect("Kotodama artifact has CNTR")
        .entrypoints
        .iter()
        .find(|entrypoint| entrypoint.name == name)
        .expect("benchmark entrypoint exists");
    u64::try_from(parsed.prefix_len()).expect("prefix fits u64") + entrypoint.entry_pc
}
fn tlv(pointer_type: PointerType, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(7 + payload.len() + Hash::LENGTH);
    out.extend_from_slice(&(pointer_type as u16).to_be_bytes());
    out.push(1);
    out.extend_from_slice(
        &u32::try_from(payload.len())
            .expect("benchmark payload fits u32")
            .to_be_bytes(),
    );
    out.extend_from_slice(payload);
    out.extend_from_slice(Hash::new(payload).as_ref());
    out
}
fn int_result_i64(vm: &IVM) -> i64 {
    let tlv = vm
        .validate_tlv(
            vm.public_call_result_word(0)
                .expect("benchmark completed with an int result"),
        )
        .expect("benchmark returned an int TLV");
    assert_eq!(tlv.type_id, PointerType::Int);
    IntValueV1::decode_frame(tlv.payload)
        .expect("benchmark returned a canonical int frame")
        .into_int()
        .try_to_i64()
        .expect("benchmark int result fits i64")
}
fn add_argument_host(program: &[u8]) -> DefaultHost {
    let parsed = ProgramMetadata::parse(program).expect("parse Kotodama metadata");
    let schema = parsed
        .contract_interface
        .as_ref()
        .expect("Kotodama artifact has CNTR")
        .entrypoints
        .iter()
        .find(|entrypoint| entrypoint.name == "add")
        .and_then(|entrypoint| entrypoint.argument_schema.as_ref())
        .expect("benchmark entrypoint has an argument schema");
    let payload = Json::from(norito::json!({"a": "4", "b": "7"}));
    let payload = ivm_abi::arguments::encode_argument_record_from_json(schema, &payload)
        .expect("encode canonical benchmark argument record");
    let key: Name = ivm_abi::arguments::ENTRYPOINT_ARGUMENT_RECORD_PUBLIC_INPUT_KEY
        .parse()
        .expect("public input key is a Name");
    DefaultHost::new().with_public_inputs(BTreeMap::from([(
        key,
        tlv(PointerType::NoritoBytes, &payload),
    )]))
}
fn asm_program() -> Vec<u8> {
    let mut prog = ProgramMetadata::default().encode();
    let add = encode_add(3, 10, 11).to_le_bytes();
    prog.extend_from_slice(&add);
    prog.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    prog
}
// The measured reset statement is byte-for-byte the predecessor workload.
// Exercise and check the dirty reset immediately before sampling instead.
#[allow(unused_must_use)]
fn bench_kotodama(c: &mut Criterion) {
    let code = kotodama_program();
    let pc = entrypoint_pc(&code, "add");
    let host = add_argument_host(&code);
    let parsed = ProgramMetadata::parse(&code).expect("parse Kotodama metadata");
    let argument_schema = parsed
        .contract_interface
        .as_ref()
        .expect("Kotodama artifact has CNTR")
        .entrypoints
        .iter()
        .find(|entrypoint| entrypoint.name == "add")
        .and_then(|entrypoint| entrypoint.argument_schema.as_ref())
        .expect("benchmark entrypoint has an argument schema")
        .clone();
    let argument_json = Json::from(norito::json!({"a": "4", "b": "7"}));
    let argument_record =
        ivm_abi::arguments::encode_argument_record_from_json(&argument_schema, &argument_json)
            .expect("encode canonical benchmark argument record");
    let prepared =
        ivm::prepare_contract(Arc::from(code.clone())).expect("prepare benchmark contract once");
    assert_eq!(prepared.entrypoint_pc("add"), Some(pc));
    // Keep the benchmark honest: CNTR artifacts deliberately halt until an
    // entrypoint is selected, so validate the measured path before sampling.
    let mut verification_vm = IVM::new(u64::MAX);
    verification_vm
        .load_prepared(&prepared)
        .expect("load prepared benchmark artifact");
    verification_vm
        .set_program_counter(pc)
        .expect("select benchmark entrypoint");
    verification_vm.set_host(host.clone());
    verification_vm.run().expect("execute benchmark add");
    assert_eq!(int_result_i64(&verification_vm), 11);
    c.bench_function("kotodama_runtime_phase_prepare_validate_predecode", |b| {
        b.iter_batched(
            || Arc::<[u8]>::from(code.clone()),
            |artifact| {
                std::hint::black_box(
                    ivm::prepare_contract(artifact)
                        .expect("prepare and predecode benchmark contract"),
                )
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("kotodama_runtime_phase_argument_decode", |b| {
        b.iter_batched(
            || Arc::<[u8]>::from(argument_record.clone()),
            |record| {
                std::hint::black_box(
                    ivm::prepare_argument_record_with_gas_limit(&argument_schema, record, u64::MAX)
                        .expect("decode canonical benchmark argument record"),
                )
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("kotodama_runtime_phase_load_prepared", |b| {
        b.iter_batched(
            || IVM::new(u64::MAX),
            |mut vm| {
                vm.load_prepared(&prepared)
                    .expect("load prepared benchmark artifact");
                std::hint::black_box(vm);
            },
            BatchSize::SmallInput,
        )
    });
    let mut vm = IVM::new(u64::MAX);
    vm.load_prepared(&prepared)
        .expect("load warm prepared benchmark artifact");
    vm.set_program_counter(pc)
        .expect("select warm benchmark entrypoint");
    let template = vm
        .try_runtime_template()
        .expect("runtime template allocation fits test host");
    vm.set_host(host.clone());
    vm.run().expect("preflight warm benchmark invocation");
    assert_eq!(int_result_i64(&vm), 11);
    vm.reset_from_runtime_template(&template)
        .expect("preflight dirty warm runtime benchmark geometry");
    c.bench_function("kotodama_runtime_phase_dirty_reset", |b| {
        b.iter_batched(
            || {
                // A template restores only the VM whose memory baseline it
                // captured, so each dirty runtime carries its own template.
                let mut dirty = IVM::new(u64::MAX);
                dirty
                    .load_prepared(&prepared)
                    .expect("load dirty-reset benchmark artifact");
                dirty
                    .set_program_counter(pc)
                    .expect("select dirty-reset benchmark entrypoint");
                let dirty_template = dirty
                    .try_runtime_template()
                    .expect("dirty-reset template allocation fits test host");
                dirty.set_host(host.clone());
                dirty.run().expect("dirty benchmark runtime state");
                (dirty, dirty_template)
            },
            |(mut dirty, template)| {
                dirty
                    .reset_from_runtime_template(&template)
                    .expect("dirty-reset benchmark geometry must match");
                std::hint::black_box(dirty.register(10));
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("kotodama_runtime_phase_execute_prepared", |b| {
        b.iter_batched(
            || {
                let mut ready = IVM::new(u64::MAX);
                ready
                    .load_prepared(&prepared)
                    .expect("load execution benchmark artifact");
                ready
                    .set_program_counter(pc)
                    .expect("select execution benchmark entrypoint");
                ready.set_host(host.clone());
                ready
            },
            |mut ready| {
                ready.run().expect("execute prepared benchmark contract");
                std::hint::black_box(ready.register(10));
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("kotodama_runtime_cold_add", |b| {
        b.iter(|| {
            let mut vm = IVM::new(u64::MAX);
            vm.load_program(&code).unwrap();
            vm.set_program_counter(pc).unwrap();
            vm.set_host(host.clone());
            vm.run().unwrap();
            std::hint::black_box(vm.register(10));
        })
    });
    c.bench_function("kotodama_runtime_warm_add", |b| {
        b.iter(|| {
            vm.reset_from_runtime_template(&template);
            vm.set_host(host.clone());
            vm.run().unwrap();
            std::hint::black_box(vm.register(10));
        })
    });
}
fn bench_asm(c: &mut Criterion) {
    let code = asm_program();
    c.bench_function("asm_add", |b| {
        b.iter(|| {
            let mut vm = IVM::new(u64::MAX);
            vm.set_register(10, 4);
            vm.set_register(11, 7);
            vm.load_program(&code).unwrap();
            vm.run().unwrap();
            std::hint::black_box(vm.register(3));
        })
    });
}
fn literal_heavy_source(count: usize) -> String {
    let mut src = String::from(
        "seiyaku Literals { permission Bench; \n  kotoage fn main() authorize(Bench) {\n",
    );
    for i in 0..count {
        src.push_str(&format!(
            "    ledger::account::set_metadata(account: context::authority(), key: Name::parse(\"literal{i}\"), value: Json::parse(\"{{\\\"value\\\":{i}}}\"));\n"
        ));
    }
    src.push_str("  }\n}\n");
    src
}
fn bench_compiler_phases(c: &mut Criterion) {
    let source = literal_heavy_source(64);
    let source_phase = SourcePhase::new(
        Default::default(),
        source.clone(),
        Some("bench/literal_heavy.ko".to_owned()),
    );
    c.bench_function("kotodama_phase_parse", |b| {
        b.iter_batched(
            || source_phase.clone(),
            |source_phase| {
                std::hint::black_box(
                    source_phase
                        .parse()
                        .expect("parse canonical benchmark source"),
                )
            },
            BatchSize::SmallInput,
        )
    });
    let parsed = source_phase
        .parse()
        .expect("prepare parsed benchmark source");
    c.bench_function("kotodama_phase_resolved_hir", |b| {
        b.iter_batched(
            || parsed.clone(),
            |parsed| {
                std::hint::black_box(
                    parsed
                        .resolve()
                        .expect("resolve canonical benchmark source"),
                )
            },
            BatchSize::SmallInput,
        )
    });
    let resolved = parsed
        .resolve()
        .expect("prepare resolved-HIR benchmark source");
    c.bench_function("kotodama_phase_semantic", |b| {
        b.iter_batched(
            || resolved.clone(),
            |resolved| {
                std::hint::black_box(
                    resolved
                        .type_effect()
                        .expect("type/effect-check canonical benchmark source"),
                )
            },
            BatchSize::SmallInput,
        )
    });
    let interface_program = parser::parse(&source).expect("prepare interface benchmark source");
    c.bench_function("kotodama_phase_interface_summary", |b| {
        b.iter_batched(
            || (SemanticContext::new(), interface_program.clone()),
            |(semantic, program)| {
                std::hint::black_box(
                    semantic
                        .resolve_function_signatures(&program)
                        .expect("summarize canonical benchmark interfaces and effects"),
                )
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("kotodama_phase_typed_effect_hir", |b| {
        b.iter_batched(
            || resolved.clone(),
            |resolved| {
                std::hint::black_box(
                    resolved
                        .type_effect()
                        .expect("type/effect-check canonical benchmark source"),
                )
            },
            BatchSize::SmallInput,
        )
    });
    let typed = resolved
        .type_effect()
        .expect("prepare typed/effect-HIR benchmark source");
    c.bench_function("kotodama_phase_ir_lower", |b| {
        b.iter_batched(
            || typed.clone(),
            |typed| {
                std::hint::black_box(typed.lower_ir().expect("lower canonical benchmark source"))
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("kotodama_phase_ssa_construct", |b| {
        b.iter_batched(
            || {
                typed
                    .clone()
                    .lower_ir()
                    .expect("prepare lowering IR for SSA construction")
            },
            |lowered| {
                std::hint::black_box(
                    lowered
                        .construct_ssa()
                        .expect("construct canonical SSA MIR"),
                )
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("kotodama_phase_ssa_optimize", |b| {
        b.iter_batched(
            || {
                typed
                    .clone()
                    .lower_ir()
                    .expect("prepare lowering IR for SSA optimization")
                    .construct_ssa()
                    .expect("prepare SSA MIR for optimization")
            },
            |ssa| std::hint::black_box(ssa.optimize().expect("optimize canonical SSA MIR")),
            BatchSize::SmallInput,
        )
    });
    c.bench_function("kotodama_phase_de_ssa", |b| {
        b.iter_batched(
            || {
                typed
                    .clone()
                    .lower_ir()
                    .expect("prepare lowering IR for de-SSA")
                    .construct_ssa()
                    .expect("prepare SSA MIR for de-SSA")
                    .optimize()
                    .expect("prepare optimized SSA MIR for de-SSA")
            },
            |optimized| {
                std::hint::black_box(optimized.destroy_ssa().expect("destroy canonical SSA MIR"))
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("kotodama_phase_codegen", |b| {
        b.iter_batched(
            || {
                typed
                    .clone()
                    .lower_ir()
                    .expect("prepare lowering IR for codegen")
                    .construct_ssa()
                    .expect("prepare SSA MIR for codegen")
                    .optimize()
                    .expect("prepare optimized SSA MIR for codegen")
                    .destroy_ssa()
                    .expect("prepare de-SSA IR for codegen")
            },
            |codegen| {
                std::hint::black_box(codegen.emit().expect("emit canonical benchmark artifact"))
            },
            BatchSize::SmallInput,
        )
    });
}
fn bounded_list_source() -> String {
    let values = (0..64)
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "seiyaku BoundedLists {{ fn main() -> int {{ \
            let List<int, 64> source = [{values}]; \
            let List<int, 64> mapped = [value + 1 for value in source if value >= 0]; \
            mapped.len() \
        }} }}"
    )
}
fn bounded_list_runtime_source(manual: bool) -> String {
    let values = (0..64)
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let body = if manual {
        "var List<int, 64> mapped = []; \
         for index in range(64) { \
             let value = match source.get(index) { Option::some(value) => value, Option::none => 0 }; \
             let pushed = match mapped.try_push(value + 1) { Result::ok(_) => true, Result::err(_) => false }; \
             if !pushed { return -1; } \
         }"
    } else {
        "let List<int, 64> mapped = [value + 1 for value in source];"
    };
    format!(
        "seiyaku BoundedListRuntime {{ view fn main() authorize(anyone) -> int {{ let List<int, 64> source = [{values}]; {body} match mapped.get(63) {{ Option::some(value) => value, Option::none => -1 }} }} }}"
    )
}
fn warm_list_runtime(source: &str) -> (IVM, ivm::RuntimeTemplate) {
    let code = Compiler::new()
        .compile_source(source)
        .expect("compile bounded List runtime benchmark");
    let pc = entrypoint_pc(&code, "main");
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&code)
        .expect("load bounded List runtime benchmark");
    vm.set_program_counter(pc)
        .expect("select bounded List runtime benchmark entrypoint");
    let template = vm
        .try_runtime_template()
        .expect("runtime template allocation fits test host");
    vm.run().expect("verify bounded List runtime benchmark");
    assert_eq!(int_result_i64(&vm), 64);
    vm.reset_from_runtime_template(&template)
        .expect("bounded List benchmark geometry must match");
    (vm, template)
}
// `warm_list_runtime` checks the dirty reset and result before Criterion starts;
// retain the predecessor's exact measured reset statement in both workloads.
#[allow(unused_must_use)]
fn bench_compiled_bounded_list_runtime(c: &mut Criterion) {
    let (mut sugar_vm, sugar_template) = warm_list_runtime(&bounded_list_runtime_source(false));
    c.bench_function("kotodama_list_comprehension_runtime_64", |b| {
        b.iter(|| {
            sugar_vm.reset_from_runtime_template(&sugar_template);
            sugar_vm
                .run()
                .expect("execute List comprehension benchmark");
            std::hint::black_box(sugar_vm.register(10));
        })
    });
    let (mut manual_vm, manual_template) = warm_list_runtime(&bounded_list_runtime_source(true));
    c.bench_function("kotodama_list_manual_runtime_64", |b| {
        b.iter(|| {
            manual_vm.reset_from_runtime_template(&manual_template);
            manual_vm.run().expect("execute manual List benchmark");
            std::hint::black_box(manual_vm.register(10));
        })
    });
}
fn bench_bounded_lists(c: &mut Criterion) {
    let source = bounded_list_source();
    let parsed = SourcePhase::new(
        Default::default(),
        source,
        Some("bench/bounded_list.ko".to_owned()),
    )
    .parse()
    .expect("parse bounded List benchmark");
    let resolved = parsed.resolve().expect("resolve bounded List benchmark");
    c.bench_function("kotodama_list_semantic_64", |b| {
        b.iter_batched(
            || resolved.clone(),
            |resolved| {
                std::hint::black_box(
                    resolved
                        .type_effect()
                        .expect("analyze bounded List benchmark"),
                )
            },
            BatchSize::SmallInput,
        )
    });
    let typed = resolved
        .type_effect()
        .expect("analyze bounded List benchmark");
    c.bench_function("kotodama_list_lower_64", |b| {
        b.iter_batched(
            || typed.clone(),
            |typed| std::hint::black_box(typed.lower_ir().expect("lower bounded List benchmark")),
            BatchSize::SmallInput,
        )
    });
    let layout = ivm::list::ListLayoutV1::try_new(64, 1).expect("bounded List layout");
    let elements = (0..63).map(|value| vec![value]).collect::<Vec<_>>();
    let mut vm = IVM::new(u64::MAX);
    let handle = ivm::list::allocate_words(&mut vm, layout, &elements)
        .expect("allocate contiguous bounded List");
    c.bench_function("kotodama_list_get_64", |b| {
        b.iter(|| {
            std::hint::black_box(
                ivm::list::get_words(&vm, handle, layout, 62).expect("read List element"),
            )
        })
    });
    c.bench_function("kotodama_list_try_set_64", |b| {
        b.iter(|| {
            std::hint::black_box(
                ivm::list::try_set_words(&mut vm, handle, layout, 62, &[62])
                    .expect("replace List element"),
            )
        })
    });
    c.bench_function("kotodama_list_try_push_pop_64", |b| {
        b.iter(|| {
            let pushed = ivm::list::try_push_words(&mut vm, handle, layout, &[63])
                .expect("append List element");
            let popped = ivm::list::pop_words(&mut vm, handle, layout).expect("pop List element");
            std::hint::black_box((pushed, popped));
        })
    });
    c.bench_function("kotodama_list_contains_64", |b| {
        b.iter(|| {
            std::hint::black_box(
                ivm::list::contains_words(&vm, handle, layout, &[62])
                    .expect("search List elements"),
            )
        })
    });
}
fn quantity(value: &str) -> Quantity {
    value.parse().expect("benchmark quantity literal parses")
}
fn decimal(value: &str) -> Numeric {
    value.parse().expect("benchmark decimal literal parses")
}
fn bench_decimal_arithmetic(c: &mut Criterion) {
    let add_lhs = decimal("-1234567890123456789012345678901234567890.1234567890123456789012345678");
    let add_rhs = decimal("0.8765432109876543210987654321");
    let sub_rhs = decimal("-0.1234567890123456789012345678");
    let mul_lhs = decimal("-1234567890123456789012345678901234567890.12345678901234");
    let mul_rhs = decimal("98765432109876543210.87654321098765");
    let exact_lhs = decimal("-123456789012345678901234567890.125");
    let exact_divisor = decimal("8");
    let rounded_divisor = decimal("7");
    c.bench_function("kotodama_decimal_add", |b| {
        b.iter(|| {
            std::hint::black_box(
                add_lhs
                    .try_decimal_add(&add_rhs)
                    .expect("benchmark decimal addition"),
            )
        })
    });
    c.bench_function("kotodama_decimal_sub", |b| {
        b.iter(|| {
            std::hint::black_box(
                add_lhs
                    .try_decimal_sub(&sub_rhs)
                    .expect("benchmark decimal subtraction"),
            )
        })
    });
    c.bench_function("kotodama_decimal_mul", |b| {
        b.iter(|| {
            std::hint::black_box(
                mul_lhs
                    .try_decimal_mul(&mul_rhs)
                    .expect("benchmark decimal multiplication"),
            )
        })
    });
    c.bench_function("kotodama_decimal_div_exact", |b| {
        b.iter(|| {
            std::hint::black_box(
                exact_lhs
                    .try_decimal_div_exact(&exact_divisor)
                    .expect("benchmark exact decimal division"),
            )
        })
    });
    for (name, mode) in [
        ("kotodama_decimal_div_round_floor", RoundingMode::Floor),
        ("kotodama_decimal_div_round_ceil", RoundingMode::Ceil),
        (
            "kotodama_decimal_div_round_nearest_even",
            RoundingMode::NearestEven,
        ),
    ] {
        c.bench_function(name, |b| {
            b.iter(|| {
                std::hint::black_box(
                    exact_lhs
                        .try_decimal_div_round(&rounded_divisor, 28, mode)
                        .expect("benchmark rounded decimal division"),
                )
            })
        });
    }
}
fn bench_quantity_arithmetic(c: &mut Criterion) {
    let add_lhs = quantity("1234567890123456789012345678901234567890.1234567890123456789012345678");
    let add_rhs = quantity("0.8765432109876543210987654321");
    let sub_rhs = quantity("0.1234567890123456789012345678");
    let mul_lhs = quantity("1234567890123456789012345678901234567890.12345678901234");
    let mul_rhs = quantity("98765432109876543210.87654321098765");
    let exact_lhs = quantity("123456789012345678901234567890.125");
    let exact_divisor = quantity("8");
    let rounded_divisor = quantity("7");
    c.bench_function("kotodama_quantity_add", |b| {
        b.iter(|| {
            std::hint::black_box(
                add_lhs
                    .checked_add(&add_rhs)
                    .expect("benchmark quantity addition"),
            )
        })
    });
    c.bench_function("kotodama_quantity_sub", |b| {
        b.iter(|| {
            std::hint::black_box(
                add_lhs
                    .checked_sub(&sub_rhs)
                    .expect("benchmark quantity subtraction"),
            )
        })
    });
    c.bench_function("kotodama_quantity_mul_decimal", |b| {
        b.iter(|| {
            std::hint::black_box(
                mul_lhs
                    .try_mul_decimal(mul_rhs.as_numeric())
                    .expect("benchmark quantity multiplication"),
            )
        })
    });
    c.bench_function("kotodama_quantity_div_decimal_exact", |b| {
        b.iter(|| {
            std::hint::black_box(
                exact_lhs
                    .try_div_decimal_exact(exact_divisor.as_numeric())
                    .expect("benchmark exact quantity division"),
            )
        })
    });
    for (name, mode) in [
        ("kotodama_quantity_div_round_floor", RoundingMode::Floor),
        ("kotodama_quantity_div_round_ceil", RoundingMode::Ceil),
        (
            "kotodama_quantity_div_round_nearest_even",
            RoundingMode::NearestEven,
        ),
    ] {
        c.bench_function(name, |b| {
            b.iter(|| {
                std::hint::black_box(
                    exact_lhs
                        .try_div_decimal_round(rounded_divisor.as_numeric(), 28, mode)
                        .expect("benchmark rounded quantity division"),
                )
            })
        });
    }
}
fn bench_literal_heavy_compile(c: &mut Criterion) {
    let src = literal_heavy_source(LITERAL_BENCH_SIZE);
    let compiler = Compiler::new();
    c.bench_function("kotodama_phase_codegen_end_to_end", |b| {
        b.iter(|| {
            let bytes = compiler
                .compile_source(&src)
                .expect("literal heavy program compiles");
            std::hint::black_box(bytes);
        })
    });
}
/// Entry point for the benchmark binary.
fn main() {
    // Silence ASCII banner and feature selection in benches.
    ivm::set_banner_enabled(false);
    let mut c = Criterion::default().configure_from_args();
    bench_kotodama(&mut c);
    bench_asm(&mut c);
    bench_compiler_phases(&mut c);
    bench_bounded_lists(&mut c);
    bench_compiled_bounded_list_runtime(&mut c);
    bench_decimal_arithmetic(&mut c);
    bench_quantity_arithmetic(&mut c);
    bench_literal_heavy_compile(&mut c);
    c.final_summary();
}
