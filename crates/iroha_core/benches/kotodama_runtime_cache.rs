//! Benchmarks the production Kotodama prepared-contract and warm-runtime cache path.
use criterion::Criterion;
use iroha_core::smartcontracts::ivm::cache::IvmCache;
use iroha_crypto::Hash;
use iroha_model_base::name::Name;
use iroha_primitives::{json::Json, numeric_abi::IntValueV1};
use ivm::{ProgramMetadata, host::DefaultHost, pointer_abi::PointerType};
use kotodama_lang::compiler::Compiler;
use std::collections::BTreeMap;
// Timing the cache path must not be coupled to the evolving deterministic
// instruction/syscall schedule; gas behavior has separate golden tests.
const GAS_LIMIT: u64 = u64::MAX;
fn benchmark_program() -> Vec<u8> {
    Compiler::new()
        .compile_source(
            "seiyaku Add { view fn add(int a, int b) authorize(anyone) -> int { return a + b; } }",
        )
        .expect("compile benchmark contract")
}
fn entrypoint_pc(program: &[u8], name: &str) -> u64 {
    let metadata = ProgramMetadata::parse(program).expect("parse benchmark metadata");
    let entrypoint = metadata
        .contract_interface
        .as_ref()
        .expect("benchmark artifact has CNTR metadata")
        .entrypoints
        .iter()
        .find(|entrypoint| entrypoint.name == name)
        .expect("benchmark entrypoint exists");
    u64::try_from(metadata.prefix_len()).expect("metadata prefix fits u64") + entrypoint.entry_pc
}
fn pointer_tlv(pointer_type: PointerType, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(7 + payload.len() + Hash::LENGTH);
    bytes.extend_from_slice(&(pointer_type as u16).to_be_bytes());
    bytes.push(1);
    bytes.extend_from_slice(
        &u32::try_from(payload.len())
            .expect("benchmark payload fits u32")
            .to_be_bytes(),
    );
    bytes.extend_from_slice(payload);
    bytes.extend_from_slice(Hash::new(payload).as_ref());
    bytes
}
fn argument_host(program: &[u8]) -> DefaultHost {
    let metadata = ProgramMetadata::parse(program).expect("parse benchmark metadata");
    let schema = metadata
        .contract_interface
        .as_ref()
        .expect("benchmark artifact has CNTR metadata")
        .entrypoints
        .iter()
        .find(|entrypoint| entrypoint.name == "add")
        .and_then(|entrypoint| entrypoint.argument_schema.as_ref())
        .expect("benchmark entrypoint has an argument schema");
    let json = Json::from(norito::json!({"a": "4", "b": "7"}));
    let record = ivm_abi::arguments::encode_argument_record_from_json(schema, &json)
        .expect("encode canonical benchmark argument record");
    let key: Name = ivm_abi::arguments::ENTRYPOINT_ARGUMENT_RECORD_PUBLIC_INPUT_KEY
        .parse()
        .expect("public input key is a Name");
    DefaultHost::new().with_public_inputs(BTreeMap::from([(
        key,
        pointer_tlv(PointerType::NoritoBytes, &record),
    )]))
}
fn bench_production_runtime_cache(c: &mut Criterion) {
    let program = benchmark_program();
    let code_hash = ivm::contract_code_hash(&program);
    let pc = entrypoint_pc(&program, "add");
    let host = argument_host(&program);
    let mut cache = IvmCache::with_capacity(4);
    let summary = cache
        .summarize_program_with_hash(code_hash, &program)
        .expect("prepare benchmark contract");
    // Seed the same shared prepared-runtime pool used by production contract
    // execution. Subsequent samples must hit the content-addressed summary and
    // restore the owned VM with dirty-page reset.
    {
        let mut runtime = summary
            .checkout_runtime(GAS_LIMIT, ivm::Memory::HEAP_MAX_SIZE)
            .expect("checkout cold benchmark runtime");
        runtime
            .set_program_counter(pc)
            .expect("select benchmark entrypoint");
        runtime.set_host(host.clone());
        runtime.run().expect("execute cold benchmark invocation");
        let result = runtime
            .validate_tlv(
                runtime
                    .public_call_result_word(0)
                    .expect("benchmark completed with an int result"),
            )
            .expect("validate benchmark int result");
        assert_eq!(result.type_id, PointerType::Int);
        assert_eq!(
            IntValueV1::decode_frame(result.payload)
                .expect("decode benchmark int result")
                .into_int()
                .try_to_i64(),
            Some(11)
        );
    }
    c.bench_function("kotodama_core_runtime_warm_add", |b| {
        b.iter(|| {
            let summary = cache
                .summarize_program_with_hash(code_hash, &[])
                .expect("content-addressed summary hit");
            let mut runtime = summary
                .checkout_runtime(GAS_LIMIT, ivm::Memory::HEAP_MAX_SIZE)
                .expect("checkout warm benchmark runtime");
            runtime
                .set_program_counter(pc)
                .expect("select benchmark entrypoint");
            runtime.set_host(host.clone());
            runtime.run().expect("execute warm benchmark invocation");
            std::hint::black_box(runtime.register(10));
        })
    });
    let stats = summary.prepared_contract_cache().stats();
    assert!(stats.runtime_hits > 0, "benchmark must exercise warm hits");
    assert!(
        stats.runtime_dirty_resets > 0,
        "warm samples must restore pooled runtimes with dirty-page reset"
    );
    assert_eq!(
        stats.runtime_prepared_loads, 1,
        "warm samples must not reload the prepared program"
    );
    assert_eq!(
        stats.runtime_template_builds, 1,
        "warm samples must not rebuild the runtime template"
    );
}
fn main() {
    ivm::set_banner_enabled(false);
    let mut criterion = Criterion::default().configure_from_args();
    bench_production_runtime_cache(&mut criterion);
    criterion.final_summary();
}
