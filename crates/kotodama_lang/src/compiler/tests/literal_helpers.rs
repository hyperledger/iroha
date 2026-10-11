//! Artifact-level proof that private literal folding uses the ordinary typed ABI.

use super::{Compiler, CompilerOptions};

#[test]
fn private_literal_helpers_emit_the_exact_direct_literal_artifact() {
    for (kind, value) in [("int", "-19"), ("decimal", "12.5"), ("quantity", "0")] {
        let helper = format!(
            "seiyaku LiteralFold {{ fn literal() -> {kind} {{ let {kind} value = {value}; return value; }} view fn read() authorize(anyone) -> {kind} {{ return literal(); }} }}"
        );
        let direct = format!(
            "seiyaku LiteralFold {{ view fn read() authorize(anyone) -> {kind} {{ let {kind} value = {value}; return value; }} }}"
        );
        let (artifact, manifest, report) = Compiler::new()
            .compile_source_with_manifest_and_report(&helper)
            .expect("compile private typed helper");
        let (direct_artifact, direct_manifest, _) = Compiler::new()
            .compile_source_with_manifest_and_report(&direct)
            .expect("compile direct typed literal");
        assert_eq!(
            artifact, direct_artifact,
            "the same literal TLV, LDLIT, public callable/schema and complete artifact imply identical charged bytecode; no alternate call ABI or gas price is introduced for {kind}"
        );
        assert_eq!(manifest, direct_manifest);
        assert!(
            report
                .budget_report
                .iter()
                .all(|function| function.function_name != "literal")
        );
        assert!(
            report
                .budget_report
                .iter()
                .any(|function| function.function_name == "read")
        );
    }
}

#[test]
fn literal_folding_retains_public_roots_and_context_reading_helpers() {
    let source = r#"
seiyaku LiteralRoots {
    view fn public_zero() authorize(anyone) -> quantity { let quantity zero = 0; return zero; }
    fn private_authority() -> AccountId { return context::authority(); }
    view fn owner() authorize(anyone) -> AccountId { return private_authority(); }
}
"#;
    // Compare the exact same source through both forms of the current compiler.
    // Private-body movement may retire this helper's callable, while literal
    // folding must never turn its authority read into a constant.
    let before = super::super::single_use_private::compile(source, true);
    let after = super::super::single_use_private::compile(source, false);
    super::super::single_use_private::assert_public_metadata(&before, &after);
    for retained in ["public_zero", "owner"] {
        assert!(
            after
                .report
                .budget_report
                .iter()
                .any(|function| function.function_name == retained)
        );
    }
    assert!(
        before
            .report
            .budget_report
            .iter()
            .any(|function| function.function_name == "private_authority")
    );
    assert!(
        !after
            .report
            .budget_report
            .iter()
            .any(|function| function.function_name == "private_authority")
    );
    let authority_word = crate::encoding::wide::encode_sys(
        crate::instruction::wide::system::SCALL,
        crate::syscalls::SYSCALL_GET_AUTHORITY as u8,
    );
    for output in [&before, &after] {
        let parsed = crate::metadata::ProgramMetadata::parse(&output.artifact).unwrap();
        assert_eq!(
            output.artifact[parsed.code_offset..]
                .chunks_exact(4)
                .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
                .filter(|word| *word == authority_word)
                .count(),
            1,
            "the original host authority read remains executable exactly once"
        );
    }
    let repeated = super::super::single_use_private::compile(source, false);
    assert_eq!(after.artifact, repeated.artifact);
    assert_eq!(after.manifest, repeated.manifest);
}

#[test]
fn literal_candidates_exclude_attributes_parameters_and_secret_types() {
    use crate::{
        ast::FunctionKind,
        ir::DataRefKind,
        semantic::{Type, TypedItem},
    };
    let parsed = crate::parser::parse("seiyaku Candidates { fn literal() -> quantity { let quantity value = 0; return value; } view fn read() authorize(anyone) -> quantity { return literal(); } }").expect("parse");
    let typed = crate::semantic::analyze(&parsed).expect("analyze");
    let expected =
        std::collections::BTreeMap::from([("literal".to_owned(), DataRefKind::Quantity)]);
    assert_eq!(super::super::private_literal_candidates(&typed), expected);
    for exclude in 0..9 {
        let mut changed = typed.clone();
        let function = changed
            .items
            .iter_mut()
            .map(|item| {
                let TypedItem::Function(function) = item;
                function
            })
            .find(|function| function.name == "literal")
            .unwrap();
        match exclude {
            0 => function.modifiers.kind = FunctionKind::View,
            1 => function.modifiers.authorization = Some("CanInspect".to_owned()),
            2 => function.modifiers.is_test = true,
            3 => function.modifiers.test_fixture = Some("fixture".to_owned()),
            4 => function.params.push("argument".to_owned()),
            5 => function.ret_ty = Some(Type::Secret(Box::new(Type::Quantity))),
            6 => function.ret_ty = Some(Type::Name),
            7 => function.ret_ty = None,
            8 => function.param_types.push(crate::semantic::TypedParam {
                name: "argument".to_owned(),
                ty: Type::Quantity,
                call_mode: crate::ast::ParameterCallMode::Named,
                is_state: false,
            }),
            _ => unreachable!(),
        }
        assert!(
            super::super::private_literal_candidates(&changed).is_empty(),
            "attribute/type exclusion {exclude} must survive the SSA metadata boundary"
        );
    }
    // Source validation is still authoritative; the conservative metadata guard
    // is not a new way to admit private authorization or public direct calls.
    let error = Compiler::new().compile_source("seiyaku Invalid { permission CanInspect;  fn value() -> int authorize(CanInspect) { return 0; } view fn read() authorize(anyone) -> int { return value(); } }").expect_err("private authorization rejected before optimization");
    assert!(error.contains("only valid on"), "{error}");
}

#[test]
fn literal_folding_preserves_forced_zk_and_cycle_metadata() {
    let helper = "seiyaku Forced { fn zero() -> quantity { let quantity value = 0; return value; } view fn read() authorize(anyone) -> quantity { return zero(); } }";
    let direct = "seiyaku Forced { view fn read() authorize(anyone) -> quantity { let quantity value = 0; return value; } }";
    let compiler = Compiler::new_with_options(CompilerOptions {
        force_zk: true,
        max_cycles: 100_000,
        ..CompilerOptions::default()
    });
    let helper = compiler
        .compile_source(helper)
        .expect("compile forced-zk helper");
    let direct = compiler
        .compile_source(direct)
        .expect("compile forced-zk direct literal");
    assert_eq!(
        helper, direct,
        "literal substitution leaves the same global ZK and cycle policy"
    );
}

#[test]
fn unused_folded_numeric_literal_preserves_the_codegen_rejection() {
    use crate::{ir::DataRefKind, semantic::TypedItem};
    let source = "seiyaku Malformed { fn literal() -> quantity { let quantity value = 0; return value; } view fn read() authorize(anyone) -> quantity { let quantity ignored = literal(); return 1; } }";
    let compile_invalid = |fold| {
        let parsed = crate::parser::parse(source).expect("parse");
        let typed = crate::semantic::analyze(&parsed).expect("analyze");
        assert!(typed.items.iter().any(|item| {
            let TypedItem::Function(function) = item;
            function.name == "literal"
        }));
        let compiler = Compiler::new();
        let mut lowered = compiler
            .lower_typed_program(typed, None)
            .expect("validated typed source");
        let literal = lowered
            .ir_program
            .functions
            .iter_mut()
            .find(|function| function.name == "literal")
            .unwrap();
        let mut changed = false;
        for instruction in literal
            .blocks
            .iter_mut()
            .flat_map(|block| &mut block.instrs)
        {
            if let crate::ir::Instr::DataRef {
                kind: DataRefKind::Quantity,
                value,
                ..
            } = instruction
            {
                *value = "not-a-quantity".to_owned();
                changed = true;
            }
        }
        assert!(
            changed,
            "corruption must reach the original typed literal payload"
        );
        let mut ssa = compiler
            .construct_ssa_program(lowered)
            .expect("SSA structure remains valid");
        let prepared = if fold {
            compiler
                .optimize_ssa_program(ssa)
                .expect("ordinary optimizer")
        } else {
            ssa.ssa_program
                .optimize_and_retain(&ssa.executable_roots, &std::collections::BTreeMap::new())
                .expect("same SSA optimizer without eligible literals");
            super::super::PreparedCompilation {
                typed: ssa.typed,
                state_descriptors: ssa.state_descriptors,
                ssa_program: ssa.ssa_program,
                source_name: ssa.source_name,
            }
        };
        let codegen = compiler
            .destroy_ssa_program(prepared)
            .expect("destroy verified SSA");
        compiler
            .compile_codegen(codegen)
            .err()
            .expect("the canonical literal validator must still reject")
    };
    let original = compile_invalid(false);
    assert!(
        original.contains("invalid quantity literal `not-a-quantity`"),
        "{original}"
    );
    assert_eq!(compile_invalid(true), original);
}

#[test]
fn canonical_dlmm_literal_folding_measures_same_compiler_artifacts_and_public_metadata() {
    use crate::{
        metadata::ProgramMetadata,
        session::{CompileOutput, CompileRequest, CompilerSession},
    };
    const SOURCE: &str =
        include_str!("../../../../iroha_core/src/validation_fee/fixtures/dlmm_pool.ko");
    let compile = |fold| {
        crate::session::run_with_compiler_stack(|| {
            let options = CompilerOptions::default();
            let session = CompilerSession::new(options.clone());
            let parsed = session
                .parse_compilation_unit(CompileRequest {
                    source: SOURCE,
                    source_name: Some("canonical_dlmm_pool.ko"),
                })
                .expect("parse canonical pool");
            let resolved = session
                .resolve_compilation_unit(parsed)
                .expect("resolve canonical pool");
            let typed = session
                .type_effect_compilation_unit(resolved)
                .expect("validate canonical pool types and effects");
            let compiler = Compiler::new_with_options(options);
            let lowered = compiler
                .lower_typed_program(typed, Some("canonical_dlmm_pool.ko"))
                .expect("validate codegen and lower canonical pool");
            let mut ssa = compiler
                .construct_ssa_program(lowered)
                .expect("construct canonical SSA");
            let prepared = if fold {
                compiler
                    .optimize_ssa_program(ssa)
                    .expect("production optimizer")
            } else {
                // The diagnostic varies only the eligible literal map. Both arms
                // use the same compiler, SSA passes, validation and gas policy.
                ssa.ssa_program
                    .optimize_and_retain(&ssa.executable_roots, &std::collections::BTreeMap::new())
                    .expect("same optimizer without eligible literals");
                ssa.ssa_program
                    .inline_single_use_private_calls(
                        &ssa.executable_roots,
                        &super::super::private_inline_candidates(&ssa.typed),
                    )
                    .expect("same whole-program private-body pass in both diagnostic arms");
                super::super::PreparedCompilation {
                    typed: ssa.typed,
                    state_descriptors: ssa.state_descriptors,
                    ssa_program: ssa.ssa_program,
                    source_name: ssa.source_name,
                }
            };
            let codegen = compiler
                .destroy_ssa_program(prepared)
                .expect("destroy verified SSA");
            let artifact = compiler
                .compile_codegen(codegen)
                .expect("emit validated artifact");
            compiler
                .manifest_from_artifacts(artifact)
                .expect("parse and validate complete embedded metadata")
        })
        .expect("use the existing canonical compiler worker")
    };
    let original = compile(false);
    let folded = compile(true);
    let mut original_manifest = original.manifest.clone();
    let mut folded_manifest = folded.manifest.clone();
    assert_ne!(original_manifest.code_hash, folded_manifest.code_hash);
    original_manifest.code_hash = None;
    folded_manifest.code_hash = None;
    assert_eq!(
        folded_manifest, original_manifest,
        "all public exports, authorization, schemas, state, errors, hints and ABI identity must remain exact"
    );

    let callable_schemas = |output: &CompileOutput| {
        output
            .report
            .budget_report
            .iter()
            .map(|function| {
                let callable = output
                    .contract_interface
                    .callables
                    .iter()
                    .find(|callable| callable.entry_pc == function.pc_start)
                    .expect("every retained function has its authenticated callable");
                assert!(callable.validate());
                assert_eq!(callable.frame_bytes, function.frame_bytes);
                (
                    function.function_name.clone(),
                    (callable.arguments.clone(), callable.results.clone()),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    let mut original_schemas = callable_schemas(&original);
    for name in ["zero_decimal", "zero_quantity"] {
        assert!(
            original_schemas.remove(name).is_some(),
            "the diagnostic baseline must retain {name}"
        );
    }
    assert_eq!(
        callable_schemas(&folded),
        original_schemas,
        "only exact private literal helpers disappear; every remaining callable's typed schema is unchanged"
    );
    let mut original_interface = original.contract_interface.clone();
    let mut folded_interface = folded.contract_interface.clone();
    for interface in [&mut original_interface, &mut folded_interface] {
        for entrypoint in &mut interface.entrypoints {
            entrypoint.entry_pc = 0;
        }
        // Frame sizes and entry PCs are code-layout facts. All callable schemas
        // were compared above, rather than silently discarding that authority.
        interface.callables.clear();
    }
    assert_eq!(folded_interface, original_interface);
    let original_metadata = ProgramMetadata::parse(&original.artifact).expect("baseline header");
    let folded_metadata = ProgramMetadata::parse(&folded.artifact).expect("optimized header");
    let header = |metadata: &ProgramMetadata| {
        (
            metadata.version_major,
            metadata.version_minor,
            metadata.mode,
            metadata.vector_length,
            metadata.max_cycles,
            metadata.abi_version,
        )
    };
    assert_eq!(
        header(&folded_metadata.metadata),
        header(&original_metadata.metadata)
    );
    assert!(
        folded.artifact.len() < original.artifact.len(),
        "the canonical pool must actually shrink"
    );
    let delta = original.artifact.len() - folded.artifact.len();
    eprintln!(
        "canonical DLMM same-compiler literal folding: original_bytes={} folded_bytes={} saved_bytes={delta} original_code_bytes={} folded_code_bytes={} original_functions={} folded_functions={} original_hash={} folded_hash={}",
        original.artifact.len(),
        folded.artifact.len(),
        original.artifact.len() - original_metadata.code_offset,
        folded.artifact.len() - folded_metadata.code_offset,
        original.report.budget_report.len(),
        folded.report.budget_report.len(),
        original.report.artifact_hash,
        folded.report.artifact_hash
    );
    // Metadata equality is not execution-effect qualification. Actual payout,
    // asset-precision rounding and default-policy runtime gates remain separate.
}
