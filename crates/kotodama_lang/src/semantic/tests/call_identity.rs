#[test]
fn user_builtin_and_method_calls_retain_distinct_identities() {
    let source = r#"seiyaku CallNames {
        error enum Failure { Missing = 1 }
        fn min(int value) -> int { value + 100 }
        fn authority() -> int { 7 }
        fn mint_asset(int value) -> int { value + 10 }
        fn is_some(int value) -> int { value + 1 }
        fn expect(int value) -> int { value + 2 }
        fn account_id(string value) -> int { 3 }
        fn local_min() -> int { min(value: 9) }
        fn builtin_min(int left, int right) -> int { math::min(left, right) }
        fn local_expect() -> int { expect(value: 4) }
        fn method_expect(Option<int> value) -> int { value.expect(error: Failure::Missing) }
        fn local_predicate() -> int { is_some(4) }
        fn method_predicate(Option<int> value) -> bool { value.is_some() }
        view fn pure() authorize(anyone) -> int { mint_asset(authority()) }
        view fn caller() authorize(anyone) -> AccountId { context::authority() }
    }"#;
    let typed = analyze(&parse(source).expect("parse independent call names"))
        .expect("lowering spellings do not reserve private helpers or add builtin effects");
    for (function, expected) in [
        ("local_min", CallTarget::User("min".into())),
        ("builtin_min", CallTarget::Builtin(Builtin::Min)),
        ("local_expect", CallTarget::User("expect".into())),
        (
            "method_expect",
            CallTarget::Intrinsic(CompilerIntrinsic::Expect),
        ),
        ("local_predicate", CallTarget::User("is_some".into())),
        (
            "method_predicate",
            CallTarget::Intrinsic(CompilerIntrinsic::IsSome),
        ),
        ("pure", CallTarget::User("mint_asset".into())),
        ("caller", CallTarget::Builtin(Builtin::Authority)),
    ] {
        let tail = typed
            .items
            .iter()
            .find_map(|item| {
                let TypedItem::Function(item) = item;
                (item.name == function).then(|| item.body.tail.as_ref().unwrap())
            })
            .unwrap();
        let (ExprKind::Call { target, .. } | ExprKind::NamedCall { target, .. }) = tail.kind()
        else {
            panic!("{function} must retain a typed call, found {tail:?}");
        };
        assert_eq!(target, &expected, "{function}");
        assert_eq!(tail.clone(), *tail, "cloning preserves call identity");
    }
}

#[test]
fn bare_retired_helpers_resolve_declarations_before_guidance() {
    for name in [
        "get_int",
        "contains",
        "path",
        "is_some",
        "expect",
        "unwrap_or",
    ] {
        let source = format!(
            "module Helpers {{ fn {name}(int value) -> int {{ value }} fn use_helper() -> int {{ {name}(3) }} }}"
        );
        analyze(&parse(&source).expect("bare source name parses"))
            .unwrap_or_else(|error| panic!("declared {name}: {error:?}"));
        let error = analyze_error(&format!("fn missing() {{ {name}(3); }}"));
        assert_eq!(error.code, "K2002");
        assert_eq!(
            error.message,
            crate::parser::removed_free_helper_message(name).unwrap()
        );
    }
}

#[test]
fn user_lowering_names_do_not_bypass_effect_analysis() {
    let error = analyze_error(
        r#"seiyaku Effects {
        state int count;
        hajimari() { count = 0; }
        fn min() -> int { count = count + 1; count }
        view fn read() authorize(anyone) -> int { min() }
    }"#,
    );
    assert!(
        error.message.contains("view") && error.message.contains("min"),
        "{error:?}"
    );
}

#[test]
fn lazy_error_helpers_do_not_definitely_initialize_state() {
    for operation in ["ok_or", "expect"] {
        let source = format!(
            r#"seiyaku Init {{
            state int count;
            error enum Failure {{ Missing = 1 }}
            fn initialize() -> Failure {{ count = 1; Failure::Missing }}
            hajimari() {{
                let Option<int> value = Option::some(1);
                let outcome = value.{operation}(initialize());
                let _ = outcome;
            }}
        }}"#
        );
        let error = analyze_error(&source);
        assert!(
            error.message.contains("count") && error.message.contains("initializ"),
            "{operation}: {error:?}"
        );
    }
}
