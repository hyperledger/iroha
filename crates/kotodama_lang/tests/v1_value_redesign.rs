//! Acceptance coverage for composable values, nominal errors, and explicit mutation.
use kotodama_lang::{
    compiler::Compiler,
    parser,
    semantic::{self, Type, TypedItem},
};

fn checked(body: &str) -> Result<semantic::TypedProgram, semantic::SemanticError> {
    let source = format!("seiyaku Values {{ {body} }}");
    semantic::analyze(&parser::parse(&source).expect("parse final V1 syntax"))
}
fn rejected(body: &str, code: &str) {
    let error = checked(body).expect_err("source must be rejected");
    assert_eq!(error.code(), code, "{error}");
}
#[test]
fn unit_is_a_value_in_aggregates_state_and_public_schemas() {
    let source = r#"seiyaku Units {
        struct Receipt { () marker; List<(), 2> markers; }
        state () marker;
        hajimari() { marker = (); }
        view fn main() authorize(anyone) -> Receipt { Receipt { marker: (), markers: [(), ()] } }
        fn omitted() { return (); }
        fn some_unit() -> Option<()> { Option::some(()) }
        fn result_unit() -> Result<(), ListError> { Result::ok(()) }
    }"#;
    let bytes = Compiler::new()
        .compile_source(source)
        .expect("compile composable Unit");
    let metadata = kotodama_lang::metadata::ProgramMetadata::parse(&bytes).unwrap();
    let interface = metadata.contract_interface.unwrap();
    assert!(matches!(
        interface.states[0].ty,
        kotodama_lang::metadata::EmbeddedStateType::Unit
    ));
    let main = interface
        .entrypoints
        .iter()
        .find(|entry| entry.name == "main")
        .unwrap();
    assert!(
        main.return_schema
            .as_ref()
            .unwrap()
            .nodes
            .iter()
            .any(|node| matches!(node, ivm_abi::entrypoint::EntrypointValueTypeNodeV1::Unit))
    );
}
#[test]
fn error_codes_are_enum_local_and_nominal_values_support_exhaustive_match() {
    let typed = checked(
        r#"
        error enum Left { Failed = 1 }
        error enum Right { Failed = 1 }
        fn convert(Left value) -> Right {
            match value { Left::Failed => { Right::Failed } }
        }
        view fn main() authorize(anyone) -> bool { Left::Failed == Left::Failed }
    "#,
    )
    .unwrap();
    let left = typed
        .error_types
        .iter()
        .find(|item| item.identity.ends_with("::Left"))
        .unwrap();
    let right = typed
        .error_types
        .iter()
        .find(|item| item.identity.ends_with("::Right"))
        .unwrap();
    assert_ne!(left.identity, right.identity);
    assert_eq!(left.schema_hash(), right.schema_hash());
    rejected(
        "error enum Left { Failed = 1 } error enum Right { Failed = 1 } fn f() -> bool { Left::Failed == Right::Failed }",
        "K2003",
    );
    rejected(
        "error enum E { One = 1; Two = 2 } fn f(E value) -> int { match value { E::One => { 1 } } }",
        "E_MATCH_NON_EXHAUSTIVE",
    );
    rejected(
        "error enum E { One = 1; Two = 2 } fn f(E value) -> int { match value { E::One => { 1 }, E::One => { 2 } } }",
        "E_MATCH_DUPLICATE_PATTERN",
    );
}
#[test]
fn nominal_errors_work_with_japanese_branding_and_source_text() {
    let source = "誓約 Values { /* 不足は明示的な失敗です */ error enum Failure { Missing = 1 } view fn convert(Failure value) authorize(anyone) -> Failure { match value { Failure::Missing => { Failure::Missing } } } }";
    semantic::analyze(&parser::parse(source).unwrap()).unwrap();
}
#[test]
fn list_mutations_have_exact_results_and_mutable_receivers() {
    let typed = checked(
        r#"
        fn f() -> Result<(), ListError> {
            var List<int, 2> values = [1];
            values.set(index: 0, value: 2);
            values.push(3);
            values.try_set(index: 0, value: 4)?;
            values.try_push(5)
        }
    "#,
    )
    .unwrap();
    let TypedItem::Function(function) = &typed.items[0];
    assert!(
        matches!(function.ret_ty.as_ref(), Some(Type::Result(ok, err)) if **ok == Type::Unit && matches!(**err, Type::ErrorEnum(_)))
    );
    for method in [
        "set(index: 0, value: 2)",
        "push(2)",
        "try_set(index: 0, value: 2)",
        "try_push(2)",
    ] {
        rejected(
            &format!("fn f() {{ let List<int,2> values = [1]; let _ = values.{method}; }}"),
            "E_LIST_MUTABLE_RECEIVER",
        );
    }
}
#[test]
fn results_cannot_be_lost_implicitly_or_by_overwrite() {
    for source in [
        "fn f() { quantity::try_from_int(-1); }",
        "fn f() { let result = quantity::try_from_int(-1); }",
        "fn f() { var result = quantity::try_from_int(1); result = quantity::try_from_int(2); let _ = result; }",
        "fn f(bool flag) { let result = quantity::try_from_int(1); if flag { let _ = result; } }",
        "fn f() { for i in range(2) { let result = quantity::try_from_int(i); break; let _ = result; } }",
    ] {
        rejected(source, "E_RESULT_MUST_USE");
    }
    checked("fn f() { let _ = quantity::try_from_int(-1); }").unwrap();
    checked("fn f(bool flag) { let result = quantity::try_from_int(1); if flag { let _ = result; } else { let _ = result; } }").unwrap();
    checked("state Result<quantity, NumericError> stored; hajimari() { let result = quantity::try_from_int(1); stored = result; stored = quantity::try_from_int(2); }").unwrap();
}
#[test]
fn propagation_requires_identical_nominal_error_types() {
    rejected(
        "error enum E { Failed = 1 } fn f() -> Result<quantity, E> { let value = quantity::try_from_int(1)?; Result::ok(value) }",
        "E_PROPAGATE_ERROR_TYPE",
    );
}
#[test]
fn fused_rounding_folds_once_and_lowers_to_one_fused_instruction() {
    let typed = checked(r#"
        fn dynamic(decimal value, decimal multiplier, decimal divisor) -> decimal {
            value.mul_div_round(multiplier: multiplier, divisor: divisor, scale: 2, mode: Rounding::floor)
        }
        fn folded() -> decimal {
            7.13.mul_div_round(multiplier: 1.17, divisor: 3.0, scale: 2, mode: Rounding::floor)
        }
    "#).unwrap();
    let TypedItem::Function(folded) = &typed.items[1];
    assert!(
        matches!(&folded.body.tail.as_ref().unwrap().expr, semantic::ExprKind::DecimalLiteral { value, .. } if value.to_string() == "2.78")
    );
    let lowered = kotodama_lang::ir::lower(&typed).unwrap();
    let fused = lowered
        .functions
        .iter()
        .flat_map(|function| &function.blocks)
        .flat_map(|block| &block.instrs)
        .filter(|instruction| {
            matches!(
                instruction,
                kotodama_lang::ir::Instr::NumericRound {
                    multiplier: Some(_),
                    op: kotodama_lang::ir::NumericRoundOp::DecimalMulDiv,
                    ..
                }
            )
        })
        .count();
    assert_eq!(fused, 1);
}

#[test]
fn exact_rejection_requires_expected_while_catch_all_stays_explicit() {
    let program = |call: &str| {
        parser::parse(&format!(
            "seiyaku Demo {{ permission Run;  kotoage fn run(int count) authorize(Run) -> int {{ return count; }} #[test] fn rejection() {{ {call}; }} }}"
        ))
        .expect("rejection helper source must parse before semantic validation")
    };
    let missing_expected = program(
        r#"test::expect_reject_as(actor: "issuer", kotoage: "run", arguments:  { count: 7 })"#,
    );
    let error = semantic::SemanticContext::with_capabilities(false, true)
        .analyze(&missing_expected)
        .expect_err("exact rejection must never imply a catch-all expectation");
    assert_eq!(error.code(), "E_MISSING_NAMED_ARGUMENT");
    assert_eq!(
        error.message(),
        "call `test::expect_reject_as` is missing required argument `expected`"
    );

    let positional = program(r#"test::expect_reject_as("issuer", "run", json { count: 7 })"#);
    let error = semantic::SemanticContext::with_capabilities(false, true)
        .analyze(&positional)
        .expect_err("the retired positional form must not restore implicit rejection matching");
    assert_eq!(error.code(), "E_NAMED_ARGUMENTS_REQUIRED");
    assert_eq!(
        error.message(),
        "parameter `actor` of `test::expect_reject_as` requires its label; write `actor: ...` or pass a variable named `actor`"
    );

    let catch_all = program(
        r#"test::expect_any_reject_as(actor: "issuer", kotoage: "run", arguments:  { count: 7 })"#,
    );
    semantic::SemanticContext::with_capabilities(false, true)
        .analyze(&catch_all)
        .expect("the explicitly named catch-all helper accepts three labeled arguments");
}

#[test]
fn structural_equality_accepts_nested_values_and_consumes_results() {
    let source = r#"seiyaku Equality {
        error enum Failure { Missing = 1; Denied = 2 }
        struct Record { () marker; (int, bool) pair; Option<List<Result<quantity, Failure>, 2>> values; }
        fn compare(Record left, Record right) -> bool { left == right }
        fn different(Record left, Record right) -> bool { left != right }
        view fn main() authorize(anyone) -> bool {
            let Record first = Record { marker: (), pair: (3, true), values: Option::some([Result::ok(4)]) };
            let Record second = Record { marker: (), pair: (3, true), values: Option::some([Result::ok(4)]) };
            compare(left: first, right: second)
        }
    }"#;
    Compiler::new()
        .compile_source(source)
        .expect("compile recursive value equality");
    checked("fn f() { let left = [quantity::try_from_int(1)]; let right = [quantity::try_from_int(1)]; let equal = left == right; }")
        .expect("whole-value comparison consumes both Result collections");
    checked("fn f() { let left = Option::some(quantity::try_from_int(1)); let right = Option::some(quantity::try_from_int(1)); let different = left != right; }")
        .expect("whole-value inequality consumes nested Result payloads");
    checked("fn f(List<StateCursor<int>, 2> values, StateCursor<int> cursor) -> bool { values.contains(cursor) }")
        .expect("contains and equality share the same canonical cursor comparison");
}

#[test]
fn structural_equality_preserves_nominal_types_and_resource_rejections() {
    for source in [
        "struct Left { int value; } struct Right { int value; } fn f(Left left, Right right) -> bool { left == right }",
        "error enum Left { Failed = 1 } error enum Right { Failed = 1 } fn f(Option<Left> left, Option<Right> right) -> bool { left != right }",
        "fn f(List<int, 2> left, List<int, 3> right) -> bool { left == right }",
        "fn f((int, bool) left, (decimal, bool) right) -> bool { left == right }",
        "fn f(StateMap<int, int> left, StateMap<int, int> right) -> bool { left == right }",
    ] {
        rejected(source, "K2003");
    }
}

#[test]
fn structural_equality_handles_only_results_on_executed_paths() {
    rejected(
        "fn f(bool compare) { let left = Option::some(quantity::try_from_int(1)); let right = Option::some(quantity::try_from_int(1)); if compare { let equal = left == right; } }",
        "E_RESULT_MUST_USE",
    );
    checked("fn f(bool compare) { let left = Option::some(quantity::try_from_int(1)); let right = Option::some(quantity::try_from_int(1)); if compare { let equal = left == right; } else { let _ = left; let _ = right; } }")
        .expect("both branches handle the complete compared values");
}

#[test]
fn call_tables_flatten_large_products_and_bind_all_callable_signatures() {
    use ivm_abi::{call::CallTypeNodeV1, entrypoint::EntrypointValueKindV1};
    let fields = (0..32)
        .map(|index| format!("bool f{index}"))
        .collect::<Vec<_>>()
        .join("; ");
    let source = format!(
        "seiyaku Wide {{ struct Record {{ {fields}; }} fn echo(Record value) -> Record {{ value }} view fn main(Record value) authorize(anyone) -> Record {{ echo(value: value) }} }}"
    );
    let bytes = Compiler::new()
        .compile_source(&source)
        .expect("compile 32-word arguments and results");
    let parsed = ivm_abi::metadata::ProgramMetadata::parse(&bytes).expect("parse artifact");
    let interface = parsed.contract_interface.expect("CNTR");
    assert_eq!(interface.callables.len(), 2);
    assert!(
        interface
            .callables
            .windows(2)
            .all(|pair| pair[0].entry_pc < pair[1].entry_pc)
    );
    for callable in &interface.callables {
        assert_eq!(callable.argument_word_count(), Some(32));
        assert_eq!(callable.result_word_count(), Some(32));
        assert_eq!(callable.arguments, callable.results);
        assert!(
            matches!(&callable.arguments.nodes[0], CallTypeNodeV1::Struct { fields, .. } if fields.len() == 32)
        );
        assert_eq!(
            callable.arguments.nodes[1..],
            vec![CallTypeNodeV1::Leaf(EntrypointValueKindV1::Bool); 32]
        );
        assert!(callable.validate());
        assert!(callable.frame_bytes >= 16);
    }
    let main = &interface.entrypoints[0];
    assert!(
        interface
            .callables
            .iter()
            .any(|callable| callable.entry_pc == main.entry_pc)
    );
    assert_eq!(
        main.argument_schema.as_ref().unwrap().word_count(),
        Some(32)
    );
    assert_eq!(main.return_schema.as_ref().unwrap().word_count(), Some(32));
}

#[test]
fn call_tables_preserve_8192_word_bound_without_a_register_fast_path() {
    let limit = ivm_abi::call::MAX_CALL_WORDS_V1;
    let parameters = (0..=limit)
        .map(|index| format!("bool p{index}"))
        .collect::<Vec<_>>()
        .join(", ");
    let source = format!(
        "seiyaku Bound {{ fn too_wide({parameters}) -> bool {{ p0 }} view fn main() authorize(anyone) -> bool {{ true }} }}"
    );
    let error = kotodama_lang::session::CompilerSession::default()
        .check(kotodama_lang::session::CompileRequest {
            source: &source,
            source_name: Some("bound.ko"),
        })
        .expect_err("one word beyond the table bound is rejected before lowering");
    assert!(
        error
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "K2007" && diagnostic.message.contains("8192"))
    );
    let inclusive = source.replace(&format!(", bool p{limit}"), "");
    kotodama_lang::session::CompilerSession::default()
        .check(kotodama_lang::session::CompileRequest {
            source: &inclusive,
            source_name: Some("inclusive.ko"),
        })
        .expect("exactly 8192 argument words remain valid");
    // Two call sites keep `echo` out of single-use private-call inlining, so
    // the artifact really contains a small call through the call table.
    let source = "seiyaku Small { fn echo(bool value) -> bool { value } view fn main() authorize(anyone) -> bool { echo(value: true) || echo(value: false) } }";
    let bytes = Compiler::new()
        .compile_source(source)
        .expect("small calls use the same descriptor");
    let interface = ivm_abi::metadata::ProgramMetadata::parse(&bytes)
        .unwrap()
        .contract_interface
        .unwrap();
    assert_eq!(interface.callables.len(), 2);
    assert!(
        interface
            .callables
            .iter()
            .all(|callable| callable.frame_bytes >= 16)
    );
    assert!(
        interface
            .callables
            .iter()
            .any(|callable| callable.arguments.nodes.is_empty())
    );
    assert!(
        interface
            .callables
            .iter()
            .any(|callable| callable.argument_word_count() == Some(1))
    );
}

#[test]
fn call_tables_reject_oversized_shared_product_returns_before_lowering() {
    let mut declarations = "struct B0 { bool bit; }".to_owned();
    for level in 1..=14 {
        declarations.push_str(&format!(
            " struct B{level} {{ B{} left; B{} right; }}",
            level - 1,
            level - 1
        ));
    }
    let source = format!(
        "seiyaku Bound {{ {declarations} fn too_wide(B13 value) -> B14 {{ B14 {{ left: value, right: value }} }} view fn main() authorize(anyone) -> bool {{ true }} }}"
    );
    let error = kotodama_lang::session::CompilerSession::default()
        .check(kotodama_lang::session::CompileRequest {
            source: &source,
            source_name: Some("return-bound.ko"),
        })
        .expect_err("16384-word product result is rejected without expanding shared type storage");
    assert!(
        error
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "K2007"
                && diagnostic.message.contains("returns more than 8192"))
    );
}
