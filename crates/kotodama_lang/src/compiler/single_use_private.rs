//! Same-compiler publication and declaration controls for private body movement.

use crate::{
    compiler::CompilerOptions,
    metadata::ProgramMetadata,
    session::{CompileOutput, CompileRequest, CompilerSession},
    ssa::with_private_calls_retained,
};
use std::collections::BTreeMap;

pub(super) fn compile(source: &str, retain_calls: bool) -> CompileOutput {
    crate::session::run_with_compiler_stack(|| {
        let build = || {
            CompilerSession::new(CompilerOptions::default())
                .build(CompileRequest {
                    source,
                    source_name: Some("single_use_private.ko"),
                })
                .expect("canonical source, SSA, schema and artifact validation")
        };
        if retain_calls {
            with_private_calls_retained(build)
        } else {
            build()
        }
    })
    .expect("canonical compiler worker")
}

pub(super) fn assert_public_metadata(before: &CompileOutput, after: &CompileOutput) {
    let mut before_manifest = before.manifest.clone();
    let mut after_manifest = after.manifest.clone();
    before_manifest.code_hash = None;
    after_manifest.code_hash = None;
    assert_eq!(
        before_manifest, after_manifest,
        "public permissions, schemas, triggers, state and access claims remain exact"
    );
    let normalize = |output: &CompileOutput| {
        let mut interface = output.contract_interface.clone();
        interface.callables.clear();
        for entrypoint in &mut interface.entrypoints {
            entrypoint.entry_pc = 0;
        }
        interface
    };
    assert_eq!(
        normalize(before),
        normalize(after),
        "only private callable ownership and executable geometry can change"
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
                    .unwrap();
                assert!(callable.validate());
                assert_eq!(callable.frame_bytes, function.frame_bytes);
                (
                    function.function_name.clone(),
                    (callable.arguments.clone(), callable.results.clone()),
                )
            })
            .collect::<BTreeMap<_, _>>()
    };
    let old = callable_schemas(before);
    for (name, schema) in callable_schemas(after) {
        assert_eq!(
            old.get(&name),
            Some(&schema),
            "every surviving callable preserves its exact ABI schema"
        );
    }
    for output in [before, after] {
        let parsed = ProgramMetadata::parse(&output.artifact).unwrap();
        assert_eq!(
            parsed.contract_interface.as_ref().unwrap(),
            &output.contract_interface
        );
        assert_eq!(
            output.manifest.code_hash,
            Some(crate::metadata::contract_code_hash(&output.artifact))
        );
        assert_eq!(
            output.report.artifact_hash,
            crate::metadata::contract_code_hash(&output.artifact)
        );
    }
    let old = ProgramMetadata::parse(&before.artifact).unwrap();
    let new = ProgramMetadata::parse(&after.artifact).unwrap();
    assert_eq!(
        &before.artifact[..old.header_len],
        &after.artifact[..new.header_len],
        "unchanged ABI, mode, maximum cycles and cost policy"
    );
}

#[test]
fn exact_private_body_movement_keeps_public_schema_effects_and_access_completeness() {
    let source = r#"seiyaku SingleUsePrivate { permission Entry;
        state int counter;
        hajimari() { counter = 0; }
        fn touch(int _ key) -> int { counter = counter + key; return counter; }
        kotoage fn update(int key) authorize(Entry) -> int { return touch(key); }
        view fn read() authorize(anyone) -> int { return counter; }
    }"#;
    let before = compile(source, true);
    let after = compile(source, false);
    assert_public_metadata(&before, &after);
    assert_eq!(
        before.report.budget_report.len(),
        after.report.budget_report.len() + 1
    );
    assert!(
        !after
            .report
            .budget_report
            .iter()
            .any(|function| function.function_name == "touch")
    );
    assert!(after.artifact.len() < before.artifact.len());
    let update = after
        .contract_interface
        .entrypoints
        .iter()
        .find(|entry| entry.name == "update")
        .unwrap();
    assert_eq!(update.read_keys, vec!["state:counter"]);
    assert_eq!(update.write_keys, vec!["state:counter"]);
}

#[test]
fn declaration_authority_roots_and_repeated_helpers_remain_separate_callables() {
    let source = r#"seiyaku PrivateExclusions {
        fn shared(int _ value) -> int { return value + 1; }
        view fn public_helper(int value) authorize(anyone) -> int { return value + 2; }
        view fn first(int value) authorize(anyone) -> int { return shared(value); }
        view fn second(int value) authorize(anyone) -> int { return shared(value); }
    }"#;
    let before = compile(source, true);
    let after = compile(source, false);
    assert_public_metadata(&before, &after);
    assert_eq!(before.artifact, after.artifact);
    assert!(
        after
            .report
            .budget_report
            .iter()
            .any(|function| function.function_name == "shared")
    );
    assert!(
        after
            .report
            .budget_report
            .iter()
            .any(|function| function.function_name == "public_helper")
    );
}

#[test]
fn conservative_private_call_comparison_scope_retires_after_unwind() {
    let source = "seiyaku Scope { fn leaf(int _ value) -> int { return value + 1; } view fn main(int value) authorize(anyone) -> int { return leaf(value); } }";
    let failure =
        std::panic::catch_unwind(|| with_private_calls_retained(|| panic!("comparison unwind")));
    assert!(failure.is_err());
    let after = compile(source, false);
    assert!(
        !after
            .report
            .budget_report
            .iter()
            .any(|function| function.function_name == "leaf")
    );
}

#[test]
fn canonical_dlmm_single_use_private_inlining_measures_exact_artifact_sections() {
    let source = include_str!("../../../iroha_core/src/validation_fee/fixtures/dlmm_pool.ko");
    let before = compile(source, true);
    let after = compile(source, false);
    assert_public_metadata(&before, &after);
    let old = ProgramMetadata::parse(&before.artifact).unwrap();
    let new = ProgramMetadata::parse(&after.artifact).unwrap();
    let old_code = before.artifact.len() - old.code_offset;
    let new_code = after.artifact.len() - new.code_offset;
    let old_cntr = before.contract_interface.encode_section().len();
    let new_cntr = after.contract_interface.encode_section().len();
    assert!(after.artifact.len() < before.artifact.len());
    assert!(after.report.budget_report.len() < before.report.budget_report.len());
    let surviving = after
        .report
        .budget_report
        .iter()
        .map(|function| function.function_name.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let removed = before
        .report
        .budget_report
        .iter()
        .filter(|function| !surviving.contains(function.function_name.as_str()))
        .map(|function| function.function_name.as_str())
        .collect::<Vec<_>>();
    eprintln!(
        "dlmm_single_use baseline_bytes={} optimized_bytes={} saved_bytes={} baseline_code={} optimized_code={} baseline_cntr={} optimized_cntr={} removed_private={removed:?} artifact_hash={}",
        before.artifact.len(),
        after.artifact.len(),
        before.artifact.len() - after.artifact.len(),
        old_code,
        new_code,
        old_cntr,
        new_cntr,
        after.report.artifact_hash
    );
}

#[test]
fn typed_private_candidates_exclude_attributes_secrets_and_state_or_aggregate_handles() {
    use crate::{
        ast::FunctionKind,
        semantic::{Type, TypedItem},
    };
    let source = "seiyaku Candidates { fn helper(int _ value) -> int { return value + 1; } view fn main(int value) authorize(anyone) -> int { return helper(value); } }";
    let typed = crate::semantic::analyze(&crate::parser::parse(source).unwrap()).unwrap();
    assert_eq!(
        super::private_inline_candidates(&typed),
        BTreeMap::from([("helper".to_owned(), false)])
    );
    for exclusion in 0..11 {
        let mut changed = typed.clone();
        let function = changed
            .items
            .iter_mut()
            .map(|item| {
                let TypedItem::Function(function) = item;
                function
            })
            .find(|function| function.name == "helper")
            .unwrap();
        match exclusion {
            0 => function.modifiers.kind = FunctionKind::View,
            1 => function.modifiers.authorization = Some("Entry".to_owned()),
            2 => function.modifiers.is_test = true,
            3 => function.modifiers.test_fixture = Some("fixture".to_owned()),
            4 => function.ret_ty = Some(Type::Secret(Box::new(Type::Int))),
            5 => function.param_types[0].ty = Type::Secret(Box::new(Type::Int)),
            6 => function.param_types[0].is_state = true,
            7 => function.ret_ty = Some(Type::Option(Box::new(Type::Int))),
            8 => function.param_types[0].ty = Type::Tuple(vec![Type::Int, Type::Int]),
            9 => {
                function.param_types[0].ty =
                    Type::StateMap(Box::new(Type::Int), Box::new(Type::Int))
            }
            10 => function.ret_ty = Some(Type::StateCursor(Box::new(Type::Int))),
            _ => unreachable!(),
        }
        assert!(
            super::private_inline_candidates(&changed).is_empty(),
            "typed exclusion {exclusion}"
        );
    }
}
