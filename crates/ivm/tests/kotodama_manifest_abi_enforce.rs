//! Kotodama compiler-owned first-release metadata tests.
#[test]
fn compiler_emits_fixed_v1_abi_and_inferred_vector_metadata() {
    use ivm::ProgramMetadata;
    use kotodama_lang::compiler::Compiler;
    let src = "seiyaku FixedHeader { view fn f() authorize(anyone) -> int { return 3; } }";
    let (artifact, manifest) = Compiler::new()
        .compile_source_with_manifest(src)
        .expect("compile first-release artifact");
    let parsed = ProgramMetadata::parse(&artifact).expect("parse compiler artifact");
    assert_eq!(parsed.metadata.abi_version, 1);
    assert_eq!(parsed.metadata.vector_length, 0);
    assert!(manifest.abi_hash.is_some());
}
