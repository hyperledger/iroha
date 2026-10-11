//! Genuine full compiler output and actual ABI producer for the sole CS1 codec.

use crate::session::{CompileOutput, CompileRequest, CompilerSession};
use ivm_abi::{call::CallSchemaV1, metadata::ProgramMetadata};
use norito::core::{DecodeFlagsGuard, Encoder, SerializePayload};

fn compile(source: &str) -> CompileOutput {
    crate::session::run_with_compiler_stack(|| {
        CompilerSession::default()
            .build(CompileRequest {
                source,
                source_name: Some("compact_call_schema.ko"),
            })
            .expect("canonical production compilation and admission")
    })
    .unwrap()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|value| format!("{value:02x}")).collect()
}
fn assert_complete(output: &CompileOutput) {
    let parsed = ProgramMetadata::parse(&output.artifact).unwrap();
    let interface = parsed.contract_interface.as_ref().unwrap();
    assert_eq!(interface, &output.contract_interface);
    assert_eq!(parsed.metadata.abi_version, 1);
    let _flags = DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    for callable in &interface.callables {
        assert!(callable.validate());
        for schema in [&callable.arguments, &callable.results] {
            let mut bytes = Vec::new();
            schema.serialize(&mut Encoder::new(&mut bytes)).unwrap();
            assert_eq!(&bytes[..4], b"CS1\0");
            assert_eq!(
                u64::from_le_bytes(bytes[4..12].try_into().unwrap()) as usize,
                schema.nodes.len()
            );
            let framed = norito::encode_canonical(schema).unwrap();
            assert_eq!(
                norito::decode_from_bytes::<CallSchemaV1>(&framed).unwrap(),
                *schema
            );
        }
    }
    let section = interface.encode_section();
    assert_eq!(
        &output.artifact[parsed.header_len..parsed.header_len + section.len()],
        section.as_slice()
    );
}
#[test]
fn canonical_dlmm_compact_schema_retains_every_full_callable_and_exact_emitted_cntr() {
    let source = include_str!("../../../iroha_core/src/validation_fee/fixtures/dlmm_pool.ko");
    let output = compile(source);
    assert_complete(&output);
    let parsed = ProgramMetadata::parse(&output.artifact).unwrap();
    eprintln!(
        "DLMM_CS1 artifact_bytes={} cntr_bytes={} code_bytes={} callables={} source_hash={} artifact_hash={} abi_hash={}",
        output.artifact.len(),
        output.contract_interface.encode_section().len(),
        output.artifact.len() - parsed.code_offset,
        output.contract_interface.callables.len(),
        hex(iroha_crypto::Hash::new(source.as_bytes()).as_ref()),
        hex(iroha_crypto::Hash::new(&output.artifact).as_ref()),
        hex(&ivm_abi::syscalls::compute_abi_hash(
            ivm_abi::SyscallPolicy::AbiV1
        ))
    );
}
#[test]
fn compact_schema_keeps_unused_numeric_private_call_arguments_authenticated() {
    let source = "seiyaku Eager { fn unused(quantity value) -> quantity { let quantity constant=7; return constant; } view fn main() authorize(anyone) -> quantity { let quantity value=9; let a=unused(value:value); return unused(value:a); } }";
    let output = compile(source);
    assert_complete(&output);
    let report = output
        .report
        .budget_report
        .iter()
        .find(|report| report.function_name == "unused")
        .expect("two original calls retain the authenticated private callee");
    let descriptor = output
        .contract_interface
        .callables
        .iter()
        .find(|callable| callable.entry_pc == report.pc_start)
        .unwrap();
    let quantity =
        ivm_abi::call::CallTypeNodeV1::Leaf(ivm_abi::entrypoint::EntrypointValueKindV1::Quantity);
    assert_eq!(descriptor.arguments.nodes, vec![quantity.clone()]);
    assert_eq!(descriptor.results.nodes, vec![quantity]);
    assert_eq!(descriptor.argument_word_count(), Some(1));
    assert_eq!(descriptor.result_word_count(), Some(1));
}
#[test]
#[ignore = "genuine current native output; root must publish exact stdout and regenerate all ABI/capture consumers"]
fn capture_actual_compact_schema_abi_and_complete_dlmm_artifact() {
    let source = include_str!("../../../iroha_core/src/validation_fee/fixtures/dlmm_pool.ko");
    let output = compile(source);
    assert_complete(&output);
    println!(
        "CS1_ABI_HASH\t{}",
        hex(&ivm_abi::syscalls::compute_abi_hash(
            ivm_abi::SyscallPolicy::AbiV1
        ))
    );
    println!(
        "CS1_ABI_TABLE\t{}",
        ivm_abi::syscalls::render_abi_hashes_markdown_table().replace('\n', "\\n")
    );
    println!(
        "CS1_DLMM_NATIVE\t{}\t{}\t{}",
        hex(iroha_crypto::Hash::new(source.as_bytes()).as_ref()),
        hex(iroha_crypto::Hash::new(&output.artifact).as_ref()),
        hex(&output.artifact)
    );
}
