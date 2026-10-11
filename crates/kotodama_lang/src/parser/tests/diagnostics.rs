// Structured parse and lex diagnostics: source spellings, site help, exact
// fixes that repair the source, and no recovery cascades.
fn syntax_diagnostics(text: &str) -> Vec<Diagnostic> {
    let source = SourceFile::new(SourceId(0), "case.ko", text);
    crate::syntax::parse_program(&source, FrontendBudget::v1())
        .diagnostics
        .diagnostics
}
fn only_diagnostic(text: &str) -> Diagnostic {
    let mut diagnostics = syntax_diagnostics(text);
    assert_eq!(
        diagnostics.len(),
        1,
        "expected exactly one diagnostic for {text:?}: {}",
        summarize(&diagnostics)
    );
    diagnostics.remove(0)
}
fn summarize(diagnostics: &[Diagnostic]) -> String {
    diagnostics
        .iter()
        .map(|diagnostic| format!("[{}] {}", diagnostic.code, diagnostic.message))
        .collect::<Vec<_>>()
        .join(" | ")
}
fn replacements(diagnostic: &Diagnostic) -> Vec<String> {
    diagnostic
        .fixes()
        .map(|fix| fix.replacement.clone())
        .collect()
}
fn apply(text: &str, fix: &DiagnosticFix) -> String {
    let range = fix.span.byte_range.expect("fix has an exact range");
    let mut patched = text.to_owned();
    patched.replace_range(range.start as usize..range.end as usize, &fix.replacement);
    patched
}
/// Every offered fix, applied on its own, must leave a source that parses.
fn assert_fixes_repair(text: &str, diagnostic: &Diagnostic) {
    assert!(
        diagnostic.fix.is_some(),
        "{} has no fix: {diagnostic:#?}",
        diagnostic.code
    );
    for fix in diagnostic.fixes() {
        let patched = apply(text, fix);
        let remaining = syntax_diagnostics(&patched);
        assert!(
            remaining.is_empty(),
            "fix {:?} for {} did not repair {text:?}; patched {patched:?}: {}",
            fix.replacement,
            diagnostic.code,
            summarize(&remaining)
        );
    }
}
fn assert_site_help(diagnostic: &Diagnostic) {
    let fallback = crate::diagnostic::diagnostic_explanation(&diagnostic.code)
        .map(|entry| entry.help.to_owned());
    assert!(diagnostic.help.is_some(), "{diagnostic:#?}");
    assert_ne!(
        diagnostic.help, fallback,
        "{} used the registry fallback help",
        diagnostic.code
    );
}
#[test]
fn expected_token_errors_use_source_spellings_and_insertion_points() {
    let text = "seiyaku S {\n    fn f() {\n        let x = 1\n    }\n}\n";
    let diagnostic = only_diagnostic(text);
    assert_eq!(diagnostic.code, "K1001");
    assert_eq!(diagnostic.message, "expected `;`, found `}`");
    let span = diagnostic.primary_span.as_ref().expect("span");
    assert_eq!((span.start.line, span.start.column), (3, 18));
    assert_eq!(span.byte_range.map(|range| range.len()), Some(0));
    assert_eq!(replacements(&diagnostic), [";"]);
    assert_site_help(&diagnostic);
    assert_fixes_repair(text, &diagnostic);
    for (text, expected) in [
        ("seiyaku S { fn f(int a { } }", "expected `)`, found `{`"),
        (
            "seiyaku S { permission A;  kotoage fn run() authorize(A) ok {} }",
            "expected `authorize(Admin)`, a return type, or the function body `{`, found identifier `ok`",
        ),
        (
            "seiyaku S { fn f() { let x = 1 as int; } }",
            "expected `;`, found keyword `as`",
        ),
        (
            "seiyaku S { fn f() { fn(); } }",
            "expected `}` to close the block, found keyword `fn`",
        ),
        (
            "seiyaku S { fn match() {} }",
            "expected identifier, found keyword `match`",
        ),
    ] {
        let diagnostics = syntax_diagnostics(text);
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message == expected),
            "{text}: {}",
            summarize(&diagnostics)
        );
    }
}
#[test]
fn casts_are_explained_as_named_conversions() {
    let diagnostic = only_diagnostic("seiyaku S { fn f() { let x = 1 as decimal; } }");
    assert_eq!(diagnostic.message, "expected `;`, found keyword `as`");
    assert!(
        diagnostic.help.as_deref().is_some_and(
            |help| help.contains("no `as` casts") && help.contains("decimal::from_int")
        )
    );
}
#[test]
fn parse_messages_never_leak_token_debug_names_or_templates() {
    for text in [
        "seiyaku S { fn f() { let x = 1 } }",
        "seiyaku S { #[message(\"x\")] view fn f() authorize(anyone) {} }",
        "seiyaku S { #[authorize] view fn f() authorize(anyone) {} }",
        "module M { kotoage fn run() authorize(anyone) {} }",
        "seiyaku S { error enum E { A = 1, B = 1 } }",
        "seiyaku S { kotoage fn run() authorize(\"\") {} }",
        "seiyaku S { fn f() { while true {} } }",
        "seiyaku S { fn f() { let id = account!(\"a\"); } }",
        "seiyaku S { fn f(Option<int> v) -> int { match v { Option::some(x) => x, true => 0 } } }",
        "seiyaku S { fn f() { range(1, 10); } }",
        "誓約 S { 言挙げ bump() {} }",
    ] {
        for diagnostic in syntax_diagnostics(text) {
            for leaked in [
                "Ident(",
                "String(",
                "RParen",
                "LBrace",
                "RBrace",
                "Semicolon",
                "ColonColon",
                "FatArrow",
                "Kotoage",
                "Authorize",
                "but found",
                "expected expected",
            ] {
                assert!(
                    !diagnostic.message.contains(leaked),
                    "{text}: leaked `{leaked}` in {:?}",
                    diagnostic.message
                );
            }
            assert!(
                diagnostic.notes.is_empty(),
                "parse diagnostics must not repeat source text as notes: {diagnostic:#?}"
            );
        }
    }
}
#[test]
fn english_declaration_words_suggest_both_branded_spellings() {
    let text = "contract Counter {\n}\n";
    let diagnostic = only_diagnostic(text);
    assert_eq!(diagnostic.code, "E_ENGLISH_DECLARATION_WORD");
    assert_eq!(
        diagnostic.message,
        "`contract` is not a Kotodama keyword; a deployable unit is declared with `seiyaku` or `誓約`"
    );
    assert_eq!(replacements(&diagnostic), ["seiyaku", "誓約"]);
    assert_site_help(&diagnostic);
    assert_fixes_repair(text, &diagnostic);
    for (text, expected) in [
        (
            "seiyaku S { state int v; init() { v = 0; } }",
            vec!["hajimari", "始まり"],
        ),
        (
            "seiyaku S { state int v; constructor() { v = 0; } }",
            vec!["hajimari", "始まり"],
        ),
        ("seiyaku S { upgrade() {} }", vec!["kaizen", "改善"]),
        ("seiyaku S { migrate() {} }", vec!["kaizen", "改善"]),
        (
            // Without `authorize(...)` the read-only `view` is preferred.
            "seiyaku S { pub fn one() -> int { return 1; } }",
            vec!["view", "kotoage", "言挙げ"],
        ),
        (
            "seiyaku S { entry fn one() authorize(anyone) {} }",
            vec!["kotoage", "言挙げ", "view"],
        ),
    ] {
        let diagnostic = only_diagnostic(text);
        assert_eq!(diagnostic.code, "E_ENGLISH_DECLARATION_WORD", "{text}");
        assert_eq!(replacements(&diagnostic), expected, "{text}");
        assert_site_help(&diagnostic);
    }
    // The preferred fixes repair the source outright.
    for text in [
        "seiyaku S { state int v; init() { v = 0; } }",
        "seiyaku S { upgrade() {} }",
        "seiyaku S { entry fn one() authorize(anyone) {} }",
    ] {
        let diagnostic = only_diagnostic(text);
        assert!(syntax_diagnostics(&apply(text, diagnostic.fix.as_ref().expect("fix"))).is_empty());
    }
}
#[test]
fn keyword_typos_get_bounded_deterministic_suggestions() {
    for (text, message, expected) in [
        (
            "seiyaku S { kaizan() {} }",
            "unknown keyword `kaizan`; did you mean `kaizen`/`改善`?",
            vec!["kaizen", "改善"],
        ),
        (
            "seiyak S {\n}\n",
            "unknown keyword `seiyak`; did you mean `seiyaku`/`誓約`?",
            vec!["seiyaku", "誓約"],
        ),
        (
            "Seiyaku S {\n}\n",
            "unknown keyword `Seiyaku`; did you mean `seiyaku`/`誓約`?",
            vec!["seiyaku", "誓約"],
        ),
        (
            "seiyaku S { kotoge fn run() authorize(anyone) {} }",
            "unknown keyword `kotoge`; did you mean `kotoage`/`言挙げ`?",
            vec!["kotoage", "言挙げ"],
        ),
        (
            "seiyaku S { state int v; hajimai() { v = 0; } }",
            "unknown keyword `hajimai`; did you mean `hajimari`/`始まり`?",
            vec!["hajimari", "始まり"],
        ),
        (
            "seiyaku S { kotoage fn run() autorize(anyone) {} }",
            "unknown keyword `autorize`; did you mean `authorize`?",
            vec!["authorize"],
        ),
    ] {
        let diagnostic = only_diagnostic(text);
        assert_eq!(diagnostic.code, "E_KEYWORD_TYPO", "{text}");
        assert_eq!(diagnostic.message, message);
        assert_eq!(replacements(&diagnostic), expected);
        assert_fixes_repair(text, &diagnostic);
    }
    let text = "seiyaku S { view fn f() authorize(anyone) -> int { retrun 1; } }";
    let diagnostic = only_diagnostic(text);
    assert_eq!(diagnostic.code, "E_KEYWORD_TYPO");
    assert_eq!(replacements(&diagnostic), ["return"]);
    assert_fixes_repair(text, &diagnostic);
    // Distant words are not guessed at.
    let diagnostic = only_diagnostic("seiyaku S { helper() {} }");
    assert_eq!(diagnostic.code, "K1001");
    assert!(diagnostic.fix.is_none());
}
#[test]
fn branded_declaration_shapes_get_one_token_fixes_that_echo_the_spelling() {
    for (text, message) in [
        (
            "seiyaku S { state int v; fn hajimari() { v = 0; } }",
            "`hajimari` is a lifecycle hook, not a function name: write `hajimari() { ... }` without `fn`",
        ),
        (
            "seiyaku S { state int v; hajimari fn init() { v = 0; } }",
            "`hajimari` is itself the declaration: write `hajimari() { ... }` without `fn` or a name",
        ),
        (
            "seiyaku S { 改善 fn() {} }",
            "`改善` is itself the declaration: write `改善() { ... }` without `fn` or a name",
        ),
        (
            "seiyaku S { kotoage bump() authorize(anyone) {} }",
            "`kotoage` modifies a function declaration: write `kotoage fn bump(...)`",
        ),
        (
            "誓約 S { 言挙げ bump() authorize(anyone) {} }",
            "`言挙げ` modifies a function declaration: write `言挙げ fn bump(...)`",
        ),
        (
            "seiyaku S { view one() authorize(anyone) -> int { return 1; } }",
            "`view` modifies a function declaration: write `view fn one(...)`",
        ),
    ] {
        let diagnostic = only_diagnostic(text);
        assert_eq!(diagnostic.code, "E_DECLARATION_SHAPE", "{text}");
        assert_eq!(diagnostic.message, message);
        assert_site_help(&diagnostic);
        assert_fixes_repair(text, &diagnostic);
    }
    let text = "seiyaku S { kotoage view fn one() authorize(anyone) -> int { return 1; } }";
    let diagnostic = only_diagnostic(text);
    assert_eq!(diagnostic.code, "E_DECLARATION_SHAPE");
    assert_eq!(diagnostic.fixes().count(), 2);
    let kotoage = apply(text, diagnostic.fix.as_ref().expect("fix"));
    assert!(kotoage.contains("kotoage fn one"), "{kotoage}");
    let view = apply(text, &diagnostic.alternative_fixes[0]);
    assert!(view.contains("{ view fn one"), "{view}");
    assert!(syntax_diagnostics(&view).is_empty());
}
#[test]
fn authorize_position_and_requirements_are_targeted() {
    let text = "seiyaku S { permission CanBump;  kotoage fn bump(int d) -> int authorize(CanBump) { return d; } }";
    let diagnostic = only_diagnostic(text);
    assert_eq!(diagnostic.code, "E_AUTHORIZE_POSITION");
    assert_eq!(
        diagnostic.message,
        "`authorize(...)` comes before the return type"
    );
    assert_fixes_repair(text, &diagnostic);

    let commented = "seiyaku S { permission Admin; kotoage fn run() -> int /* result policy */ authorize(Admin) { 1 } }";
    let diagnostic = only_diagnostic(commented);
    assert_eq!(diagnostic.code, "E_AUTHORIZE_POSITION");
    let repaired = apply(commented, diagnostic.fix.as_ref().expect("order fix"));
    assert!(repaired.contains("authorize(Admin) /* result policy */ -> int"));
    assert_fixes_repair(commented, &diagnostic);

    let diagnostic = only_diagnostic("誓約 S { 言挙げ fn run() {} }");
    assert_eq!(diagnostic.code, "E_KOTOAGE_AUTHORIZATION_MISSING");
    assert_eq!(
        diagnostic.message,
        "言挙げ function `run` requires an explicit `authorize(...)` policy"
    );
    assert!(
        diagnostic.fix.is_none(),
        "a permission name cannot be guessed"
    );
    assert!(diagnostic.help.as_deref().is_some_and(
        |help| help.contains("`authorize(Admin)`") && help.contains("`authorize(anyone)`")
    ));

    for text in [
        "seiyaku S { 改善() authorize(\"Admin\") {} }",
        "seiyaku S { state int v; hajimari() authorize(\"Admin\") { v = 0; } }",
    ] {
        let diagnostic = only_diagnostic(text);
        assert_eq!(diagnostic.code, "E_LIFECYCLE_AUTHORIZATION", "{text}");
        assert_eq!(diagnostic.phase, DiagnosticPhase::Parse);
        assert_fixes_repair(text, &diagnostic);
    }
    assert!(
        only_diagnostic("seiyaku S { 改善() authorize(\"Admin\") {} }")
            .message
            .starts_with("`改善` cannot declare")
    );
}
#[test]
fn reflexes_from_other_languages_get_exact_fixes() {
    for (text, code) in [
        (
            "seiyaku S { view fn f() authorize(anyone) -> int { let mut total = 0; total += 1; return total; } }",
            "E_LET_MUT",
        ),
        (
            "seiyaku S { view fn f() authorize(anyone) -> int { var total = 0; for i in 0..10 { total += i; } return total; } }",
            "E_RANGE_SYNTAX",
        ),
        (
            "seiyaku S { view fn f() authorize(anyone) -> Option<int> { return Some(1); } }",
            "E_LEGACY_SUM_CONSTRUCTOR",
        ),
        (
            "seiyaku S { view fn f() authorize(anyone) -> Option<int> { return None; } }",
            "E_LEGACY_SUM_CONSTRUCTOR",
        ),
        (
            "seiyaku S { view fn f() authorize(anyone) -> Result<int, string> { return Err(\"no\"); } }",
            "E_LEGACY_SUM_CONSTRUCTOR",
        ),
        (
            "seiyaku S { view fn f() authorize(anyone) -> Option<int> { return Option::Some(1); } }",
            "E_LEGACY_SUM_CONSTRUCTOR",
        ),
        (
            "seiyaku S { view fn f(Option<int> v) authorize(anyone) -> int { match v { Option::Some(x) => x, Option::none => 0 } } }",
            "E_LEGACY_SUM_CONSTRUCTOR",
        ),
        (
            "seiyaku S { view fn f(Option<int> v) authorize(anyone) -> int { match v { Some(x) => x, Option::none => 0 } } }",
            "E_LEGACY_SUM_CONSTRUCTOR",
        ),
        (
            "seiyaku S { view fn f() authorize(anyone) -> int { var t = 0; for (i in range(3)) { t += i; } return t; } }",
            "K1001",
        ),
        (
            "seiyaku S { view fn f(Option<int> v) authorize(anyone) -> int { match v { Option::some(x) => { x } Option::none => { 0 } } } }",
            "K1001",
        ),
    ] {
        let diagnostic = only_diagnostic(text);
        assert_eq!(diagnostic.code, code, "{text}");
        assert_site_help(&diagnostic);
        assert_fixes_repair(text, &diagnostic);
    }
    let diagnostic = only_diagnostic(
        "seiyaku S { view fn f() authorize(anyone) -> int { var t = 0; for i in 1..10 { t += i; } return t; } }",
    );
    assert_eq!(diagnostic.code, "E_RANGE_SYNTAX");
    assert!(diagnostic.fix.is_none(), "range(N) counts from zero only");
    assert!(
        diagnostic
            .help
            .as_deref()
            .is_some_and(|help| help.contains("range(10 - 1)"))
    );
    for text in [
        "seiyaku S { view fn f() authorize(anyone) -> int { var i = 0; while i < 3 { i += 1; } return i; } }",
        "seiyaku S { view fn f() authorize(anyone) -> int { loop { break; } return 1; } }",
    ] {
        let diagnostic = only_diagnostic(text);
        assert_eq!(diagnostic.code, "E_UNSUPPORTED_LOOP", "{text}");
        assert_site_help(&diagnostic);
    }
    // Lowercase helpers named `some`/`ok` remain ordinary functions.
    assert!(
        syntax_diagnostics(
            "seiyaku S { fn some(int v) -> Option<int> { Option::some(v) } view fn f() authorize(anyone) -> Option<int> { some(1) } }"
        )
        .is_empty()
    );
}
#[test]
fn name_colon_type_reports_once_with_the_users_names() {
    for (text, message, replacement) in [
        (
            "seiyaku V { permission A;  kotoage fn add(amount: int) authorize(A) {} }",
            "parameters are type-first: write `int amount`, not `amount: int`",
            "int amount",
        ),
        (
            "seiyaku V { struct Entry { amount: quantity } }",
            "struct fields are type-first: write `quantity amount;`, not `amount: quantity`",
            "quantity amount",
        ),
        (
            "seiyaku V { state total: Map<AccountId, int>; }",
            "state declarations are type-first: write `state Map<AccountId, int> total;`, not `total: Map<AccountId, int>`",
            "Map<AccountId, int> total",
        ),
        (
            "seiyaku V { const limit: int = 1; }",
            "constants are type-first: write `const int limit = ...;`, not `limit: int`",
            "int limit",
        ),
        (
            "seiyaku V { fn f() { let y: int = 6; } }",
            "typed locals are type-first: write `let int y = ...;`, not `y: int`",
            "int y",
        ),
    ] {
        let diagnostic = only_diagnostic(text);
        assert_eq!(diagnostic.code, "E_RETIRED_DECLARATION_ORDER", "{text}");
        assert_eq!(diagnostic.message, message);
        assert_eq!(replacements(&diagnostic), [replacement]);
    }
    let text = "seiyaku V { permission A;  kotoage fn add(amount: int) authorize(A) {} }";
    assert_fixes_repair(text, &only_diagnostic(text));
    for (text, message) in [
        (
            "seiyaku V { view fn run(value) authorize(anyone) {} }",
            "parameter `value` needs a type before its name, for example `int value`",
        ),
        (
            "seiyaku V { state count; }",
            "state declaration `count` needs a type before its name, for example `state int count;`",
        ),
    ] {
        let diagnostic = only_diagnostic(text);
        assert_eq!(diagnostic.code, "E_MISSING_DECLARATION_TYPE");
        assert_eq!(diagnostic.message, message);
    }
}
#[test]
fn recovery_does_not_cascade_after_match_loop_or_brace_errors() {
    for text in [
        "seiyaku S {\n    view fn f(Option<int> v) authorize(anyone) -> int {\n        match v {\n            Option::some(x) => x,\n            _ => 0,\n        }\n    }\n}\n",
        "seiyaku S {\n    view fn f(Option<Option<int>> v) authorize(anyone) -> int {\n        match v {\n            Option::some(Option::some(x)) => x,\n            Option::some(inner) => 0,\n            Option::none => 0,\n        }\n    }\n}\n",
        "seiyaku S {\n    view fn f(bool b) authorize(anyone) -> int {\n        match b {\n            true => 1,\n            false => 0,\n        }\n    }\n}\n",
        "seiyaku S {\n    view fn f() authorize(anyone) -> int {\n        let f = x;\n        while x { }\n        return 1;\n    }\n}\n",
    ] {
        // Every reported error is the arm's own mistake, never a cascade.
        let diagnostics = syntax_diagnostics(text);
        assert!(!diagnostics.is_empty(), "{text}");
        assert!(
            diagnostics.iter().all(|diagnostic| {
                diagnostic.code == diagnostics[0].code && diagnostic.help == diagnostics[0].help
            }),
            "{text}: {}",
            summarize(&diagnostics)
        );
    }
    let text = "seiyaku S { permission B; \n    state int count;\n    hajimari() {\n        count = 0;\n\n    kotoage fn bump() authorize(B) {\n        count += 1;\n    }\n}\n";
    let diagnostic = only_diagnostic(text);
    assert_eq!(
        diagnostic.message,
        "expected `}` to close the block, found keyword `kotoage`"
    );
    assert_eq!(diagnostic.labels.len(), 1);
    assert_eq!(diagnostic.labels[0].message, "this `{` is not closed");
    assert_eq!(diagnostic.labels[0].span.start.line, 3);
    assert_fixes_repair(text, &diagnostic);
    // An identifier named `json` before a loop body is an ordinary local.
    assert!(
        syntax_diagnostics(
            "seiyaku S { view fn f(List<int, 4> json) authorize(anyone) -> int { var t = 0; for x in json { t += x; } return t; } }"
        )
        .is_empty()
    );
}
#[test]
fn trailing_text_after_the_unit_is_reported_once() {
    let diagnostic = only_diagnostic("seiyaku S {\n}\n}\n");
    assert_eq!(diagnostic.message, "unmatched `}` after the end of `S`");
    let diagnostic = only_diagnostic("seiyaku S {\n}\nmodule M {\n}\n");
    assert!(diagnostic.message.starts_with(
        "a source file contains exactly one seiyaku or module, but `module` starts a second one"
    ));
}
#[test]
fn every_name_colon_type_declaration_is_reported_and_parsing_continues() {
    for (text, count) in [
        (
            "seiyaku V { permission A;  kotoage fn send(to: AccountId, amount: int) authorize(A) {} }",
            2,
        ),
        (
            "seiyaku V { struct P { owner: AccountId; amount: Map<Name, int>; } }",
            2,
        ),
        (
            "seiyaku V { state total: int; const limit: int = 1; fn f() { let y: int = 6; } }",
            3,
        ),
    ] {
        let diagnostics = syntax_diagnostics(text);
        assert_eq!(
            diagnostics.len(),
            count,
            "{text}: {}",
            summarize(&diagnostics)
        );
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| diagnostic.code == "E_RETIRED_DECLARATION_ORDER"),
            "{text}: {}",
            summarize(&diagnostics)
        );
        // Applying every fix, last first, repairs the whole source.
        let mut patched = text.to_owned();
        for diagnostic in diagnostics.iter().rev() {
            patched = apply(&patched, diagnostic.fix.as_ref().expect("swap fix"));
        }
        assert!(
            syntax_diagnostics(&patched).is_empty(),
            "{patched}: {}",
            summarize(&syntax_diagnostics(&patched))
        );
    }
    // A later, unrelated error in the same function is still found.
    let diagnostics = syntax_diagnostics(
        "seiyaku V { view fn f(amount: int) authorize(anyone) -> int { let x = 1 return x; } }",
    );
    assert_eq!(
        diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect::<Vec<_>>(),
        ["E_RETIRED_DECLARATION_ORDER", "K1001"],
        "{}",
        summarize(&diagnostics)
    );
}
#[test]
fn english_words_in_modules_and_nested_units_get_context_aware_fixes() {
    // A module's public surface is `export`, not kotoage or view.
    let text = "module M {\n    pub fn one() -> int {\n        return 1;\n    }\n}\n";
    let diagnostic = only_diagnostic(text);
    assert_eq!(diagnostic.code, "E_ENGLISH_DECLARATION_WORD");
    assert_eq!(
        diagnostic.message,
        "`pub` is not a Kotodama keyword; a module makes a function public with `export`"
    );
    assert_eq!(replacements(&diagnostic), ["export"]);
    assert_site_help(&diagnostic);
    assert_fixes_repair(text, &diagnostic);
    // Modules have no lifecycle hooks, so no hook spelling is offered.
    let diagnostic = only_diagnostic("module M { init() {} }");
    assert_eq!(diagnostic.code, "E_ENGLISH_DECLARATION_WORD");
    assert!(diagnostic.fix.is_none(), "{diagnostic:#?}");
    // Renaming a nested `contract` would still nest a unit.
    let diagnostic = only_diagnostic("seiyaku S { contract Inner { } }");
    assert_eq!(diagnostic.code, "E_ENGLISH_DECLARATION_WORD");
    assert!(diagnostic.fix.is_none(), "{diagnostic:#?}");
    assert!(
        diagnostic
            .help
            .as_deref()
            .is_some_and(|help| help.contains("its own `.ko` file"))
    );
}
#[test]
fn ranges_none_calls_and_same_line_statements_get_targeted_errors() {
    for text in [
        "seiyaku S { view fn f() authorize(anyone) -> int { let r = 0..10; return 1; } }",
        "seiyaku S { view fn f(List<int, 4> xs) authorize(anyone) -> int { return xs[1..3]; } }",
    ] {
        let diagnostic = only_diagnostic(text);
        assert_eq!(diagnostic.code, "E_RANGE_SYNTAX", "{text}");
        assert_eq!(diagnostic.message, "Kotodama has no `..` range operator");
        assert_site_help(&diagnostic);
    }
    assert_eq!(
        only_diagnostic(
            "seiyaku S { view fn f() authorize(anyone) -> int { let r = 0..=9; return 1; } }"
        )
        .message,
        "Kotodama has no `..=` range operator"
    );
    let text = "seiyaku S { view fn f() authorize(anyone) -> Option<int> { return None(); } }";
    let diagnostic = only_diagnostic(text);
    assert_eq!(diagnostic.code, "E_LEGACY_SUM_CONSTRUCTOR");
    assert_eq!(replacements(&diagnostic), ["Option::none"]);
    assert_fixes_repair(text, &diagnostic);
    // `None(x)` has no exact repair.
    assert!(
        only_diagnostic(
            "seiyaku S { view fn f() authorize(anyone) -> Option<int> { return None(1); } }"
        )
        .fix
        .is_none()
    );
    // A `;` omitted before a statement keyword on the same line is inserted
    // right after the previous token.
    let text =
        "seiyaku S { view fn f() authorize(anyone) -> int { let x = 1 let y = 2; return x + y; } }";
    let diagnostic = only_diagnostic(text);
    assert_eq!(diagnostic.message, "expected `;`, found keyword `let`");
    let span = diagnostic.primary_span.as_ref().expect("span");
    assert_eq!(span.byte_range.map(|range| range.len()), Some(0));
    assert_eq!(
        span.byte_range.map(|range| range.start as usize),
        text.find(" let y")
    );
    assert_fixes_repair(text, &diagnostic);
}
#[test]
fn item_recovery_still_reports_a_later_misspelled_declaration_head() {
    let text = "seiyaku S {\n    strcut A { int a; }\n    kaizan() { }\n    view fn f() authorize(anyone) -> int { return 1; }\n}\n";
    let diagnostics = syntax_diagnostics(text);
    assert_eq!(
        diagnostics
            .iter()
            .map(|diagnostic| diagnostic.message.as_str())
            .collect::<Vec<_>>(),
        [
            "unknown keyword `strcut`; did you mean `struct`?",
            "unknown keyword `kaizan`; did you mean `kaizen`/`改善`?",
        ],
        "{}",
        summarize(&diagnostics)
    );
}
#[test]
fn missing_closing_brace_fix_keeps_the_opener_indentation() {
    let text = "seiyaku S {\n    state int v;\n    hajimari() {\n        v = 0;\n\n    view fn get() authorize(anyone) -> int {\n        return v;\n    }\n}\n";
    let diagnostic = only_diagnostic(text);
    assert_eq!(replacements(&diagnostic), ["\n    }"]);
    assert_fixes_repair(text, &diagnostic);
}
#[test]
fn unambiguous_same_line_omissions_get_insertion_fixes() {
    // `;` cannot appear inside parentheses, so the `)` was omitted.
    let text = "seiyaku S { view fn f() authorize(anyone) -> int { let total = g(1, 2; return total; } fn g(int a, int b) -> int { a + b } }";
    let diagnostic = only_diagnostic(text);
    assert_eq!(diagnostic.message, "expected `)`, found `;`");
    assert_eq!(replacements(&diagnostic), [")"]);
    assert_fixes_repair(text, &diagnostic);
    // A namespaced pattern after an expression body starts the next arm.
    let text = "seiyaku S { view fn f(Option<int> v) authorize(anyone) -> int { match v { Option::some(x) => x Option::none => 0 } } }";
    let diagnostic = only_diagnostic(text);
    assert_eq!(replacements(&diagnostic), [","]);
    assert_fixes_repair(text, &diagnostic);
}
#[test]
fn three_clause_for_loops_get_a_counted_range_fix() {
    for (header, replacement) in [
        ("(i = 0; i < 10; i += 1)", "i in range(10)"),
        (
            "(var i = 0; i <= LIMIT; i = i + 1)",
            "i in range(LIMIT + 1)",
        ),
        ("(int i = 0; i < 2 * 3; i += 1)", "i in range(2 * 3)"),
    ] {
        let text = format!(
            "seiyaku S {{ const int LIMIT = 3; view fn f() authorize(anyone) -> int {{ var t = 0; for {header} {{ t += i; }} return t; }} }}"
        );
        let diagnostic = only_diagnostic(&text);
        assert_eq!(diagnostic.code, "E_UNSUPPORTED_LOOP", "{text}");
        assert_eq!(replacements(&diagnostic), [replacement], "{text}");
        assert_site_help(&diagnostic);
        assert_fixes_repair(&text, &diagnostic);
    }
    // Other shapes are explained without a guessed rewrite.
    for header in [
        "(i = 1; i < 10; i += 1)",
        "(i = 0; i < n && ok; i += 1)",
        "(i = 0; i < 10; i += 2)",
    ] {
        let text = format!(
            "seiyaku S {{ view fn f() authorize(anyone) -> int {{ for {header} {{ }} return 0; }} }}"
        );
        let diagnostic = only_diagnostic(&text);
        assert_eq!(diagnostic.code, "E_UNSUPPORTED_LOOP", "{text}");
        assert!(diagnostic.fix.is_none(), "{text}");
    }
}
