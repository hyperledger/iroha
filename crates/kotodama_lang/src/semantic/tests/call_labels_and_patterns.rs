// Source-call labels and order-independent named struct binding regressions.

#[test]
fn test_functions_accept_explicit_unit_and_reject_non_unit_results() {
    let unit = parse("#[test] fn smoke() -> () { () }").expect("explicit Unit test parses");
    analyze_test(&unit).expect("explicit and omitted Unit returns agree");
    let non_unit = parse("#[test] fn invalid() -> int { 1 }").expect("non-Unit test parses");
    let error = analyze_test(&non_unit).expect_err("test runner has no result channel");
    assert_eq!(error.code, "K2003");
    assert!(error.message.contains("must return Unit"));
}

#[test]
fn builtin_labels_follow_fixed_signatures_including_keyword_labels() {
    let source = "fn inspect(Json payload) -> int { let Option<int> number = payload.get_int(Name::parse(\"n\")); bytes::len(b\"text\") } fn update() { ledger::trigger::set_enabled(trigger: Name::parse(\"wake\"), enabled: true); } #[test] fn check() { test::assert_eq(expected: 2, actual: 2); }";
    analyze_test(&parse(source).expect("keyword labels parse"))
        .expect("fixed builtin policies type check");
    // Single-argument calls accept a positional argument or the declared label.
    for source in [
        "fn valid() { ledger::trigger::unregister(Name::parse(\"wake\")); }",
        "fn valid() -> int { bytes::len(value: b\"text\") }",
    ] {
        analyze(&parse(source).expect("single-argument call parses"))
            .expect("single-argument builtins accept either form");
    }
    let error =
        analyze_error("fn invalid(Name wake) { ledger::trigger::set_enabled(wake, true); }");
    assert_eq!(error.code, "E_NAMED_ARGUMENTS_REQUIRED");
}

#[test]
fn state_pages_accept_constant_expressions_and_exact_cursor_types() {
    let program = parse("const int PAGE_SIZE = 2; state StateMap<int, int> Values; fn page(Option<StateCursor<int>> after) -> StatePage<int, int, PAGE_SIZE * 2> { Values.page(limit: PAGE_SIZE * 2, after: after) }")
        .expect("constant bounded page parses");
    let typed = analyze(&program).expect("constant expression fixes page capacity");
    let TypedItem::Function(function) = &typed.items[0];
    assert_eq!(
        type_name(function.ret_ty.as_ref().expect("page type")),
        "StatePage<int, int, 4>"
    );
    let source = "state StateMap<int, int> Values; fn scan(Option<StateCursor<Name>> after) { let page = Values.page(after: after, limit: 2); }";
    analyze(&parse(source).expect("cursor mismatch parses")).expect_err("cursor key type is exact");
}

#[test]
fn all_static_bounds_share_constant_arithmetic_and_source_provenance() {
    let file = crate::source::SourceFile::new(
        crate::source::SourceId(8),
        "capacities.ko",
        "module M { struct Rows { List<int, WIDTH * 2> values; } const int WIDTH = 2; fn select(List<int, WIDTH + 2> values) -> List<int, WIDTH> { values.take(WIDTH) } fn total() -> int { var int sum = 0; for index in range(WIDTH * 2) { sum += index; } sum } }",
    );
    let (spanned, _) =
        crate::parser::parse_source_spanned(&file, crate::source::FrontendBudget::v1())
            .expect("capacity expressions parse");
    let resolved = crate::resolved::resolve(spanned, &file)
        .expect("capacity identifiers resolve as constants");
    SemanticContext::new()
        .analyze_resolved(&resolved)
        .expect("constant type capacities and operation bounds agree");
}

#[test]
fn finite_list_loops_accept_tuple_and_named_patterns() {
    let source = "struct Row { int first; int second; } fn inspect() -> int { let List<(int, int), 2> pairs = [(1, 2), (3, 4)]; let List<Row, 1> rows = [Row { first: 5, second: 6 }]; var int total = 0; for (left, right) in pairs { total += left + right; } for Row { second: selected, first: _ } in rows { total += selected; } total }";
    let program = parse(source).expect("loop binding patterns parse");
    analyze(&program).expect("bounded tuple and struct items bind fields");
}

#[test]
fn page_snapshots_allow_direct_and_saved_iteration_with_state_writes() {
    for iterator in ["Values.take(2)", "items"] {
        let source = format!(
            "state StateMap<int, int> Values; fn mutate() {{ let items = Values.take(2); for (key, value) in {iterator} {{ Values[key] = value + 1; }} }}"
        );
        analyze(&parse(&source).expect("snapshot mutation parses"))
            .expect("writes cannot alter a materialized List");
    }
}

#[test]
fn state_page_limits_reject_dynamic_zero_and_over_limit_values() {
    for (limit, code) in [
        ("n", "E_UNBOUNDED_ITERATION"),
        ("0", "E_ITERATION_LIMIT"),
        ("65", "E_ITERATION_LIMIT"),
    ] {
        let source = format!(
            "state StateMap<int, int> Values; fn scan(int n) {{ let page = Values.page(after: Option::none, limit: {limit}); }}"
        );
        assert_eq!(analyze_error(&source).code, code);
    }
}

#[test]
fn explicit_positional_prefix_ignores_repeated_types() {
    let program = parse(
        "fn add(int _ left, int _ right) -> int { left + right } fn main() -> int { add(1, 2) }",
    )
    .expect("explicit positional parameters");
    analyze(&program).expect("repeated types do not change declared call spelling");
}

#[test]
fn explicit_struct_discards_do_not_bind_or_shadow_underscore() {
    let file = crate::source::SourceFile::new(
        crate::source::SourceId(7),
        "discard.ko",
        "module M { struct Pair { int left; int right; } fn inspect(Pair value) { let Pair { left: _, right: _ } = value; let _ = 1; let _ = 2; } }",
    );
    let (spanned, _) =
        crate::parser::parse_source_spanned(&file, crate::source::FrontendBudget::v1())
            .expect("discard patterns parse");
    let resolved =
        crate::resolved::resolve(spanned, &file).expect("discards never shadow one another");
    SemanticContext::new()
        .analyze_resolved(&resolved)
        .expect("discards type check");
}

#[test]
fn mixed_source_call_evaluates_in_source_order() {
    let program = parse("fn target(int _ value, int lower, int upper) -> int { value + lower + upper } fn main() -> int { target(5, upper: 10, lower: 0) }")
        .expect("mixed call");
    let typed = analyze(&program).expect("mixed call type checks");
    let function = typed
        .items
        .iter()
        .find_map(|item| {
            let TypedItem::Function(function) = item;
            (function.name == "main").then_some(function)
        })
        .expect("main");
    let ExprKind::NamedCall {
        evaluation_order, ..
    } = function.body.tail.as_ref().expect("tail").kind()
    else {
        panic!("named call preserves source permutation");
    };
    assert_eq!(evaluation_order, &[0, 2, 1]);
}

#[test]
fn positional_only_call_modes_reject_names() {
    let error = analyze_error(
        "fn target(int _ value) -> int { value } fn main() -> int { target(value: 1) }",
    );
    assert_eq!(error.code, "E_POSITIONAL_ARGUMENT_REQUIRED");
}

#[test]
fn named_struct_bindings_select_fields_and_capture_initializer_once() {
    let program = parse("struct Pair { int right; int left; } fn make() -> Pair { Pair { left: 7, right: 9 } } fn main() -> int { let Pair { left: selected, right: _ } = make(); selected }")
        .expect("named struct pattern");
    let typed = analyze(&program).expect("named fields type check");
    let function = typed
        .items
        .iter()
        .find_map(|item| {
            let TypedItem::Function(function) = item;
            (function.name == "main").then_some(function)
        })
        .expect("main");
    assert_eq!(function.body.statements.iter().filter(|statement| matches!(statement, TypedStatement::Let { value, .. } if matches!(value.kind(), ExprKind::Call { target: name, .. } if name.user_name() == Some("make")))).count(), 1);
    let selected = function
        .body
        .statements
        .iter()
        .find_map(|statement| match statement {
            TypedStatement::Let { name, value } if name == "selected" => Some(value),
            _ => None,
        })
        .expect("selected field");
    assert!(matches!(selected.kind(), ExprKind::Member { field, .. } if field == "1"));
}

#[test]
fn named_struct_patterns_check_completeness_and_nominality() {
    for (pattern, code) in [
        ("Pair { left }", "E_MISSING_STRUCT_PATTERN_FIELD"),
        ("Pair { missing, .. }", "E_UNKNOWN_STRUCT_FIELD"),
        ("Pair { left: same, right: same }", "K2001"),
        ("(left, right)", "E_POSITIONAL_STRUCT_PATTERN"),
    ] {
        let source = format!(
            "struct Pair {{ int left; int right; }} fn main() {{ let {pattern} = Pair {{ left: 1, right: 2 }}; }}"
        );
        let error = analyze_error(&source);
        assert_eq!(error.code, code, "{source}: {}", error.message);
    }
    let program = parse("struct Pair { int left; int right; } fn main() -> int { var Pair { left, .. } = Pair { right: 2, left: 1 }; left += 3; left }")
        .expect("mutable named pattern with explicit rest");
    analyze(&program).expect("var applies to named pattern bindings");
}

#[test]
fn result_obligations_follow_named_argument_source_order_on_propagation() {
    let source = |arguments: &str| {
        format!(
            "fn collect(Result<int, ListError> pending, int value) -> int {{ let _ = pending; value }} \
         fn next() -> Result<int, ListError> {{ Result::err(ListError::CapacityExceeded) }} \
         fn run() -> Result<int, ListError> {{ let pending = next(); \
         let value = collect({arguments}); Result::ok(value) }}"
        )
    };
    let accepted = source("pending: pending, value: next()?");
    analyze(&parse(&accepted).expect("source order fixture parses"))
        .expect("the pending result is consumed before the possible early return");
    let rejected = source("value: next()?, pending: pending");
    assert_eq!(analyze_error(&rejected).code, "E_RESULT_MUST_USE");
}

#[test]
fn interspersed_unit_parameters_match_public_and_internal_word_layouts() {
    let source = "seiyaku Units { struct Receipt { () marker; int value; } view fn echo(() leading, Receipt receipt, () trailing) authorize(anyone) -> Receipt { let _ = leading; let _ = trailing; receipt } }";
    let typed = analyze(&parse(source).expect("Unit product parameters parse"))
        .expect("Unit composes in public parameters and products");
    let TypedItem::Function(function) = &typed.items[0];
    let arguments = crate::ir::entrypoint_argument_schema(&function.param_types)
        .expect("public argument schema")
        .expect("parameter record");
    assert_eq!(arguments.word_count(), Some(4));
    let returns = crate::ir::entrypoint_return_schema("echo", function.ret_ty.as_ref())
        .expect("public return schema")
        .expect("return record");
    assert_eq!(returns.word_count(), Some(2));
    let lowered = crate::ir::lower(&typed).expect("parameter wrapper and implementation lower");
    assert!(
        lowered
            .functions
            .iter()
            .any(|function| function.params.len() == 4)
    );
    assert_eq!(
        lowered
            .functions
            .iter()
            .flat_map(|function| &function.blocks)
            .flat_map(|block| &block.instrs)
            .filter(|instruction| matches!(instruction, crate::ir::Instr::LoadVar { .. }))
            .count(),
        4
    );
}
