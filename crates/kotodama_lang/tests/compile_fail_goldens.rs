//! Public compiler-session compile-fail diagnostic goldens for Kotodama V1.
use kotodama_lang::{
    diagnostic::DiagnosticPhase,
    semantic::MAX_EXPANDED_TYPE_NODES,
    session::{CompileRequest, CompilerSession},
    source::MAX_NESTING_DEPTH,
};
#[derive(Clone, Copy)]
struct CompileFailCase {
    name: &'static str,
    source: &'static str,
    phase: DiagnosticPhase,
    code: &'static str,
    message: &'static str,
    line: usize,
}
include!(concat!(env!("OUT_DIR"), "/kotodama_compile_fail_cases.rs"));
#[test]
fn public_session_compile_fail_diagnostics_are_stable() {
    let session = CompilerSession::default();
    let mut failures = Vec::new();
    for case in CASES {
        let source_name = format!("{}.ko", case.name);
        let diagnostics = match session.build(CompileRequest {
            source: case.source,
            source_name: Some(&source_name),
        }) {
            Ok(_) => {
                failures.push(format!("{} unexpectedly compiled", case.name));
                continue;
            }
            Err(diagnostics) => diagnostics,
        };
        let Some(diagnostic) = diagnostics.diagnostics.iter().find(|diagnostic| {
            diagnostic.phase == case.phase
                && diagnostic.code == case.code
                && diagnostic.message.contains(case.message)
        }) else {
            failures.push(format!(
                "{} omitted {} {} containing {:?}: {:#?}",
                case.name,
                case.phase.as_str(),
                case.code,
                case.message,
                diagnostics.diagnostics
            ));
            continue;
        };
        let Some(span) = diagnostic.primary_span.as_ref() else {
            failures.push(format!("{} diagnostic has no primary span", case.name));
            continue;
        };
        if span.source.as_deref() != Some(source_name.as_str()) {
            failures.push(format!(
                "{} source name drifted: {diagnostic:#?}",
                case.name
            ));
        }
        if span.start.line != case.line {
            failures.push(format!(
                "{} source line drifted: {diagnostic:#?}",
                case.name
            ));
        }
        if span.start.column < 1 {
            failures.push(format!(
                "{} span must use one-based columns: {diagnostic:#?}",
                case.name
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}
/// Full rendered human output for targeted syntax diagnostics: message,
/// location, source excerpt, labels, help and fixes. Invisible characters are
/// written as Rust escapes so this file stays free of them.
const RENDERED_SYNTAX_SNAPSHOTS: &[(&str, &str, &str)] = &[
    (
        "missing-semicolon",
        "seiyaku Counter {\n    state int count;\n    hajimari() {\n        count = 0\n    }\n}\n",
        concat!(
            "error[K1001] parse: expected `;`, found `}`\n",
            "  --> missing-semicolon.ko:4:18\n",
            "    4 |         count = 0\n",
            "      |                  ^\n",
            "  = help: every statement and `state`/`const` declaration ends with `;`; block-valued `if`, `match` and `for` statements do not\n",
            "  = fix: insert `;`",
        ),
    ),
    (
        "english-contract",
        "contract Counter {\n}\n",
        concat!(
            "error[E_ENGLISH_DECLARATION_WORD] parse: `contract` is not a Kotodama keyword; a deployable unit is declared with `seiyaku` or `誓約`\n",
            "  --> english-contract.ko:1:1\n",
            "    1 | contract Counter {\n",
            "      | ^^^^^^^^\n",
            "  = help: a source file contains exactly one `seiyaku Name { ... }` (deployable; also spelled `誓約`) or one `module Name { ... }` (reusable library)\n",
            "  = fix: replace `contract` with `seiyaku` or `誓約`",
        ),
    ),
    (
        "english-pub-fn",
        "seiyaku Counter {\n    pub fn one() -> int {\n        return 1;\n    }\n}\n",
        concat!(
            "error[E_ENGLISH_DECLARATION_WORD] parse: `pub` is not a Kotodama keyword; a public state-changing function is declared with `kotoage` or `言挙げ`\n",
            "  --> english-pub-fn.ko:2:5\n",
            "    2 |     pub fn one() -> int {\n",
            "      |     ^^^\n",
            "  = help: public functions are `kotoage fn` (also `言挙げ fn`; submitted in a transaction, may write state, requires an explicit `authorize(...)`) or `view fn` (read-only); plain `fn` is private to the unit\n",
            "  = fix: replace `pub` with `view`, `kotoage` or `言挙げ`",
        ),
    ),
    (
        "keyword-typo",
        "seiyaku Counter {\n    kaizan() {\n    }\n}\n",
        concat!(
            "error[E_KEYWORD_TYPO] parse: unknown keyword `kaizan`; did you mean `kaizen`/`改善`?\n",
            "  --> keyword-typo.ko:2:5\n",
            "    2 |     kaizan() {\n",
            "      |     ^^^^^^\n",
            "  = help: keywords are case-sensitive and spelled exactly as in the V1 keyword table\n",
            "  = fix: replace `kaizan` with `kaizen` or `改善`",
        ),
    ),
    (
        "lifecycle-hook-as-function",
        "seiyaku Counter {\n    state int count;\n    fn hajimari() {\n        count = 0;\n    }\n}\n",
        concat!(
            "error[E_DECLARATION_SHAPE] parse: `hajimari` is a lifecycle hook, not a function name: write `hajimari() { ... }` without `fn`\n",
            "  --> lifecycle-hook-as-function.ko:3:5\n",
            "    3 |     fn hajimari() {\n",
            "      |     ^^\n",
            "  = help: `hajimari`/`始まり` declares the one-shot activation hook that initializes durable state; it is written `hajimari() { ... }` with no `fn`, no name and no `authorize(...)`\n",
            "  = fix: delete `fn `",
        ),
    ),
    (
        "kanji-kotoage-without-fn",
        "誓約 Counter {\n    言挙げ bump() authorize(anyone) {\n    }\n}\n",
        concat!(
            "error[E_DECLARATION_SHAPE] parse: `言挙げ` modifies a function declaration: write `言挙げ fn bump(...)`\n",
            "  --> kanji-kotoage-without-fn.ko:2:5\n",
            "    2 |     言挙げ bump() authorize(anyone) {\n",
            "      |     ^^^^^^\n",
            "  = help: public functions are declared `kotoage fn name(...)` (also `言挙げ fn`) or `view fn name(...)`; only the lifecycle hooks `hajimari` and `kaizen` omit `fn`\n",
            "  = fix: insert ` fn`",
        ),
    ),
    (
        "authorize-after-return-type",
        "seiyaku Counter {\n    kotoage fn bump(int delta) -> int authorize(anyone) {\n        return delta;\n    }\n}\n",
        concat!(
            "error[E_AUTHORIZE_POSITION] parse: `authorize(...)` comes before the return type\n",
            "  --> authorize-after-return-type.ko:2:32\n",
            "    2 |     kotoage fn bump(int delta) -> int authorize(anyone) {\n",
            "      |                                ^^^^^^^^^^^^^^^^^^^^^^^^\n",
            "  = help: write `kotoage fn name(params) authorize(Admin) -> Type { ... }`\n",
            "  = fix: replace `-> int authorize(anyone)` with `authorize(anyone) -> int`",
        ),
    ),
    (
        "kanji-kotoage-without-authorize",
        "誓約 Counter {\n    言挙げ fn run() {\n    }\n}\n",
        concat!(
            "error[E_KOTOAGE_AUTHORIZATION_MISSING] parse: 言挙げ function `run` requires an explicit `authorize(...)` policy\n",
            "  --> kanji-kotoage-without-authorize.ko:2:17\n",
            "    2 |     言挙げ fn run() {\n",
            "      |                    ^\n",
            "  = help: use a declared permission such as `authorize(Admin)`, or explicitly allow every caller with `authorize(anyone)`",
        ),
    ),
    (
        "lifecycle-authorization",
        "seiyaku Counter {\n    改善() authorize(\"Admin\") {\n    }\n}\n",
        concat!(
            "error[E_LIFECYCLE_AUTHORIZATION] parse: `改善` cannot declare `authorize(...)`: lifecycle hooks are authorized by the runtime\n",
            "  --> lifecycle-authorization.ko:2:10\n",
            "    2 |     改善() authorize(\"Admin\") {\n",
            "      |            ^^^^^^^^^^^^^^^^^^\n",
            "  = help: remove the clause; lifecycle authority is checked by the runtime\n",
            "  = fix: delete ` authorize(\"Admin\")`",
        ),
    ),
    (
        "let-mut",
        "seiyaku Counter {\n    view fn sum() authorize(anyone) -> int {\n        let mut total = 0;\n        return total;\n    }\n}\n",
        concat!(
            "error[E_LET_MUT] parse: a mutable local is declared with `var`, not `let mut`\n",
            "  --> let-mut.ko:3:9\n",
            "    3 |         let mut total = 0;\n",
            "      |         ^^^^^^^\n",
            "  = help: `let` binds an immutable local and `var` a mutable one: `var total = 0;` or `var int total = 0;`\n",
            "  = fix: replace `let mut` with `var`",
        ),
    ),
    (
        "range-operator",
        "seiyaku Counter {\n    view fn sum() authorize(anyone) -> int {\n        var total = 0;\n        for i in 0..10 {\n            total += i;\n        }\n        return total;\n    }\n}\n",
        concat!(
            "error[E_RANGE_SYNTAX] parse: Kotodama has no `..` range operator; counted loops use `range(N)`, which counts from 0 up to N - 1\n",
            "  --> range-operator.ko:4:18\n",
            "    4 |         for i in 0..10 {\n",
            "      |                  ^^^^^\n",
            "  = help: the loop bound must be a compile-time integer expression\n",
            "  = fix: replace `0..10` with `range(10)`",
        ),
    ),
    (
        "while-loop",
        "seiyaku Counter {\n    view fn sum() authorize(anyone) -> int {\n        var i = 0;\n        while i < 10 {\n            i += 1;\n        }\n        return i;\n    }\n}\n",
        concat!(
            "error[E_UNSUPPORTED_LOOP] parse: `while` loops are not part of Kotodama; every loop is a `for` loop with a compiler-proven bound\n",
            "  --> while-loop.ko:4:9\n",
            "    4 |         while i < 10 {\n",
            "      |         ^^^^^\n",
            "  = help: execution is metered and must be bounded: iterate `for i in range(N)` with a compile-time `N`, or a collection with a proven capacity, and exit early with `break`",
        ),
    ),
    (
        "three-clause-for",
        "seiyaku Counter {\n    view fn sum() authorize(anyone) -> int {\n        var total = 0;\n        for (i = 0; i < 10; i += 1) {\n            total += i;\n        }\n        return total;\n    }\n}\n",
        concat!(
            "error[E_UNSUPPORTED_LOOP] parse: `for (init; condition; step)` loops are not part of Kotodama; every loop is a `for` loop with a compiler-proven bound\n",
            "  --> three-clause-for.ko:4:13\n",
            "    4 |         for (i = 0; i < 10; i += 1) {\n",
            "      |             ^^^^^^^^^^^^^^^^^^^^^^^\n",
            "  = help: count with `for i in range(N) { ... }`, which runs i = 0 up to N - 1; `N` must be a compile-time integer expression\n",
            "  = fix: replace `(i = 0; i < 10; i += 1)` with `i in range(10)`",
        ),
    ),
    (
        "match-wildcard",
        "seiyaku Counter {\n    view fn read(Option<int> maybe) authorize(anyone) -> int {\n        match maybe {\n            Option::some(v) => v,\n            _ => 0,\n        }\n    }\n}\n",
        concat!(
            "error[E_MATCH_WILDCARD] parse: `match` has no wildcard arm; name every variant\n",
            "  --> match-wildcard.ko:5:13\n",
            "    5 |             _ => 0,\n",
            "      |             ^\n",
            "  = help: a match over `Option` lists `Option::some(value)` and `Option::none`; over `Result`, `Result::ok(value)` and `Result::err(error)`; payloads you do not use bind `_`",
        ),
    ),
    (
        "some-constructor",
        "seiyaku Counter {\n    view fn wrap(int value) authorize(anyone) -> Option<int> {\n        return Some(value);\n    }\n}\n",
        concat!(
            "error[E_LEGACY_SUM_CONSTRUCTOR] parse: `Some` is spelled `Option::some` in Kotodama\n",
            "  --> some-constructor.ko:3:16\n",
            "    3 |         return Some(value);\n",
            "      |                ^^^^\n",
            "  = help: optional and fallible values are built and matched as `Option::some(value)`, `Option::none`, `Result::ok(value)` and `Result::err(error)`\n",
            "  = fix: replace `Some` with `Option::some`",
        ),
    ),
    (
        "none-call",
        "seiyaku Counter {\n    view fn empty() authorize(anyone) -> Option<int> {\n        return None();\n    }\n}\n",
        concat!(
            "error[E_LEGACY_SUM_CONSTRUCTOR] parse: `None` is spelled `Option::none` in Kotodama, and it is a value, not a call\n",
            "  --> none-call.ko:3:16\n",
            "    3 |         return None();\n",
            "      |                ^^^^\n",
            "  = help: optional and fallible values are built and matched as `Option::some(value)`, `Option::none`, `Result::ok(value)` and `Result::err(error)`\n",
            "  = fix: replace `None()` with `Option::none`",
        ),
    ),
    (
        "range-value",
        "seiyaku Counter {\n    view fn first() authorize(anyone) -> int {\n        let window = 0..10;\n        return 0;\n    }\n}\n",
        concat!(
            "error[E_RANGE_SYNTAX] parse: Kotodama has no `..` range operator\n",
            "  --> range-value.ko:3:23\n",
            "    3 |         let window = 0..10;\n",
            "      |                       ^^\n",
            "  = help: counted loops iterate `for i in range(N)`, which counts from 0 up to N - 1 with a compile-time `N`; there are no range values or list slices",
        ),
    ),
    (
        "english-pub-fn-in-module",
        "module Math {\n    pub fn double(int value) -> int {\n        return value * 2;\n    }\n}\n",
        concat!(
            "error[E_ENGLISH_DECLARATION_WORD] parse: `pub` is not a Kotodama keyword; a module makes a function public with `export`\n",
            "  --> english-pub-fn-in-module.ko:2:5\n",
            "    2 |     pub fn double(int value) -> int {\n",
            "      |     ^^^\n",
            "  = help: a module shares functions, structs, error enums and constants with `export`; public `kotoage fn` (also `言挙げ fn`) and `view fn` functions belong to a seiyaku\n",
            "  = fix: replace `pub` with `export`",
        ),
    ),
    (
        "missing-parameter-type",
        "seiyaku Counter {\n    view fn run(value) authorize(anyone) -> int {\n        return 1;\n    }\n}\n",
        concat!(
            "error[E_MISSING_DECLARATION_TYPE] parse: parameter `value` needs a type before its name, for example `int value`\n",
            "  --> missing-parameter-type.ko:2:17\n",
            "    2 |     view fn run(value) authorize(anyone) -> int {\n",
            "      |                 ^^^^^\n",
            "  = help: declarations name the type first; the type is never inferred for parameters, fields, state or constants",
        ),
    ),
    (
        "name-colon-type",
        "seiyaku Vault { permission CanAdd; \n    kotoage fn add(amount: int) authorize(CanAdd) {\n    }\n}\n",
        concat!(
            "error[E_RETIRED_DECLARATION_ORDER] parse: parameters are type-first: write `int amount`, not `amount: int`\n",
            "  --> name-colon-type.ko:2:20\n",
            "    2 |     kotoage fn add(amount: int) authorize(CanAdd) {\n",
            "      |                    ^^^^^^^^^^^\n",
            "  = help: Kotodama declarations name the type first: `fn add(int lhs)`, `state int total;`, `const int limit = 1;`, `let int count = 0;`, struct field `quantity balance;`\n",
            "  = fix: replace `amount: int` with `int amount`",
        ),
    ),
    (
        "missing-closing-brace",
        "seiyaku Counter { permission CanBump; \n    state int count;\n    hajimari() {\n        count = 0;\n\n    kotoage fn bump() authorize(CanBump) {\n        count += 1;\n    }\n}\n",
        concat!(
            "error[K1001] parse: expected `}` to close the block, found keyword `kotoage`\n",
            "  --> missing-closing-brace.ko:4:19\n",
            "    4 |         count = 0;\n",
            "      |                   ^\n",
            "  = label: missing-closing-brace.ko:3:16: this `{` is not closed\n",
            "    3 |     hajimari() {\n",
            "      |                ^\n",
            "  = help: declarations cannot appear inside a function body; close the body with `}` before the next declaration\n",
            "  = fix: insert `}` on a new line",
        ),
    ),
    (
        "fullwidth-parentheses",
        "seiyaku Counter {\n    始まり（） {\n    }\n}\n",
        concat!(
            "error[E_FULLWIDTH_ASCII] lex: full-width `（）` (U+FF08) is not Kotodama syntax; write `()`\n",
            "  --> fullwidth-parentheses.ko:2:8\n",
            "    2 |     始まり（） {\n",
            "      |           ^^^^\n",
            "  = help: punctuation, letters and digits outside string literals are ASCII; switch the input method to half-width (direct input) for code\n",
            "  = fix: replace `（）` with `()`",
        ),
    ),
    (
        "glued-kanji-keyword",
        "seiyaku Counter {\n    言挙げfn bump() authorize(anyone) {\n    }\n}\n",
        concat!(
            "error[E_KEYWORD_SPACING] lex: `言挙げ` and `fn` need a space between them\n",
            "  --> glued-kanji-keyword.ko:2:5\n",
            "    2 |     言挙げfn bump() authorize(anyone) {\n",
            "      |     ^^^^^^^^\n",
            "  = help: `言挙げ` is a keyword (also spelled `kotoage`); separate it from the next word with a space\n",
            "  = fix: insert ` `",
        ),
    ),
    (
        "confusable-keyword",
        "契約 Counter {\n}\n",
        concat!(
            "error[E_CONFUSABLE_KEYWORD] lex: `契約` is not a Kotodama keyword; did you mean `誓約`/`seiyaku`?\n",
            "  --> confusable-keyword.ko:1:1\n",
            "    1 | 契約 Counter {\n",
            "      | ^^^^\n",
            "  = help: `誓約` (せいやく, “solemn pledge”) is spelled exactly `誓約` or `seiyaku`; both spellings are the same keyword\n",
            "  = fix: replace `契約` with `誓約` or `seiyaku`",
        ),
    ),
    (
        "bidi-control-in-comment",
        "seiyaku Counter {\n    // owner check \u{202e} disabled\n}\n",
        concat!(
            "error[E_BIDI_CONTROL_CHARACTER] lex: source contains the invisible bidirectional control character U+202E (RIGHT-TO-LEFT OVERRIDE)\n",
            "  --> bidi-control-in-comment.ko:2:20\n",
            "    2 |     // owner check \\u{202e} disabled\n",
            "      |                    ^^^^^^^^\n",
            "  = help: it can make reviewed code read differently from what compiles; delete it (inside a string literal, write it as a `\\u{...}` escape)\n",
            "  = fix: delete `<U+202E>`",
        ),
    ),
    (
        "bidi-control-in-string",
        "seiyaku Counter {\n    view fn label() authorize(anyone) -> string {\n        return \"admin\\u{202e} user\";\n    }\n}\n",
        concat!(
            "error[E_BIDI_CONTROL_CHARACTER] lex: source contains the invisible bidirectional control character U+202E (RIGHT-TO-LEFT OVERRIDE)\n",
            "  --> bidi-control-in-string.ko:3:22\n",
            "    3 |         return \"admin\\u{202e} user\";\n",
            "      |                      ^^^^^^^^\n",
            "  = help: it can make reviewed code read differently from what compiles; write it as the escape `\\u{202e}` if the string really needs it\n",
            "  = fix: replace `<U+202E>` with `\\u{202e}`",
        ),
    ),
    (
        "line-separator-in-comment",
        "seiyaku Counter {\n    state int count;\n    hajimari() {\n        count = 0; // reset\u{2028}count = 1;\n    }\n}\n",
        concat!(
            "error[E_UNICODE_LINE_SEPARATOR] lex: source contains the invisible line separator U+2028 (LINE SEPARATOR)\n",
            "  --> line-separator-in-comment.ko:4:28\n",
            "    4 |         count = 0; // reset\\u{2028}count = 1;\n",
            "      |                            ^^^^^^^^\n",
            "  = help: it can make reviewed code read differently from what compiles; delete it (inside a string literal, write it as a `\\u{...}` escape)\n",
            "  = fix: delete `<U+2028>`",
        ),
    ),
    (
        "non-ascii-space",
        "seiyaku\u{a0}Counter {\n}\n",
        concat!(
            "error[E_NON_ASCII_WHITESPACE] lex: U+00A0 is not a token separator; use an ASCII space\n",
            "  --> non-ascii-space.ko:1:8\n",
            "    1 | seiyaku\\u{a0}Counter {\n",
            "      |        ^^^^^^\n",
            "  = help: tokens are separated by ASCII spaces, tabs and line breaks, or the ideographic space U+3000; other Unicode spaces look identical but are rejected\n",
            "  = fix: replace `<U+00A0>` with ` `",
        ),
    ),
    (
        "single-ampersand",
        "seiyaku Counter {\n    view fn both(bool a, bool b) authorize(anyone) -> bool {\n        return a & b;\n    }\n}\n",
        concat!(
            "error[E_UNSUPPORTED_OPERATOR] lex: `&` is not a Kotodama operator; boolean AND is `&&`\n",
            "  --> single-ampersand.ko:3:18\n",
            "    3 |         return a & b;\n",
            "      |                  ^\n",
            "  = help: Kotodama has no bitwise operators or closures; combine `bool` conditions with `&&` and `||`\n",
            "  = fix: replace `&` with `&&`",
        ),
    ),
    (
        "japanese-identifier",
        "seiyaku Counter {\n    view fn 合計() authorize(anyone) -> int {\n        return 1;\n    }\n}\n",
        concat!(
            "error[K0100] lex: non-ASCII identifier `合計`: identifiers are ASCII\n",
            "  --> japanese-identifier.ko:2:13\n",
            "    2 |     view fn 合計() authorize(anyone) -> int {\n",
            "      |             ^^^^\n",
            "  = help: the only Japanese words in Kotodama source are the keywords 誓約, 言挙げ, 始まり and 改善 (also spelled seiyaku, kotoage, hajimari and kaizen); name declarations with ASCII letters, digits and `_`, and keep Japanese text in strings and comments",
        ),
    ),
];
#[test]
fn targeted_syntax_diagnostics_render_exactly() {
    let session = CompilerSession::default();
    let mut failures = Vec::new();
    for (name, source, expected) in RENDERED_SYNTAX_SNAPSHOTS {
        let source_name = format!("{name}.ko");
        let rendered = match session.check(CompileRequest {
            source,
            source_name: Some(&source_name),
        }) {
            Ok(_) => {
                failures.push(format!("{name} unexpectedly checked"));
                continue;
            }
            Err(diagnostics) => diagnostics.render_human(),
        };
        if rendered != *expected {
            failures.push(format!("{name}: rendered {rendered:?}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
#[test]
fn tail_type_mismatch_points_at_the_exact_tail_expression() {
    let source = "seiyaku TailMismatch {\nfn value() -> bool { 1 }\n}";
    let diagnostics = CompilerSession::default()
        .build(CompileRequest {
            source,
            source_name: Some("tail-type-mismatch-exact.ko"),
        })
        .expect_err("the int tail must not satisfy the declared bool result");
    let diagnostic = diagnostics
        .diagnostics
        .iter()
        .find(|diagnostic| {
            diagnostic.phase == DiagnosticPhase::Semantic
                && diagnostic.code == "E_TAIL_TYPE_MISMATCH"
        })
        .expect("exact tail mismatch diagnostic");
    assert_eq!(
        diagnostic.message,
        "block tail type mismatch: expected `bool`, found `int`"
    );
    let span = diagnostic
        .primary_span
        .as_ref()
        .expect("tail mismatch must retain the tail expression span");
    assert_eq!(span.source.as_deref(), Some("tail-type-mismatch-exact.ko"));
    assert_eq!((span.start.line, span.start.column), (2, 22));
    assert_eq!((span.end.line, span.end.column), (2, 23));
    let range = span
        .byte_range
        .expect("tail mismatch must retain the exact byte range");
    let literal = source.rfind('1').expect("tail literal");
    assert_eq!(
        (range.start, range.end),
        (
            u32::try_from(literal).expect("source offset fits u32"),
            u32::try_from(literal + 1).expect("source offset fits u32"),
        )
    );
    assert_eq!(
        &source[range.start as usize..range.end as usize],
        "1",
        "the diagnostic must select only the incompatible tail expression"
    );
}
fn trigger_metadata_contract(value: &str) -> String {
    format!(
        r#"
        seiyaku TriggerMetadata {{ permission RunTrigger;
            const string dynamic = "{{}}";
            kotoage fn run() authorize(RunTrigger) {{}}
            trigger wake -> run {{
                on time pre_commit;
                metadata {{ payload: {value}; }}
            }}
        }}
        "#,
    )
}
#[test]
fn public_session_enforces_json_parse_arguments_in_trigger_metadata() {
    let session = CompilerSession::default();
    for value in [r#"Json::parse("{}")"#, r#"Json::parse(value: "{}")"#] {
        let source = trigger_metadata_contract(value);
        session
            .build(CompileRequest {
                source: &source,
                source_name: Some("trigger-json-canonical.ko"),
            })
            .expect("positional and labelled Json::parse trigger metadata must compile");
    }
    for (value, phase, code, message) in [
        (
            r#"Json::parse(raw: "{}")"#,
            DiagnosticPhase::Semantic,
            "E_UNKNOWN_NAMED_ARGUMENT",
            "call `Json::parse` has no parameter named `raw`",
        ),
        (
            r#"Json::parse(value: "{}", value: "{}")"#,
            DiagnosticPhase::Parse,
            "E_DUPLICATE_NAMED_ARGUMENT",
            "named argument `value` is supplied more than once",
        ),
        (
            "Json::parse()",
            DiagnosticPhase::Semantic,
            "E_MISSING_NAMED_ARGUMENT",
            "call `Json::parse` is missing required argument `value`",
        ),
        (
            r#"Json::parse("{}", "{}")"#,
            DiagnosticPhase::Semantic,
            "K2003",
            "call `Json::parse` expects at most 1 arguments, got 2",
        ),
        (
            "Json::parse(dynamic)",
            DiagnosticPhase::Semantic,
            "E_JSON_LITERAL_REQUIRED",
            "Json::parse requires a direct string literal so native JSON is validated at compile time",
        ),
        (
            r#"json("{}")"#,
            DiagnosticPhase::Resolve,
            "K2002",
            "unknown function or builtin `json`",
        ),
    ] {
        let source = trigger_metadata_contract(value);
        let diagnostics = match session.build(CompileRequest {
            source: &source,
            source_name: Some("trigger-json-invalid.ko"),
        }) {
            Ok(_) => panic!("invalid trigger metadata `{value}` compiled"),
            Err(diagnostics) => diagnostics,
        };
        let diagnostic = diagnostics
            .diagnostics
            .iter()
            .find(|diagnostic| {
                diagnostic.phase == phase
                    && diagnostic.code == code
                    && diagnostic.message == message
            })
            .unwrap_or_else(|| {
                panic!(
                    "trigger metadata `{value}` omitted {phase:?} {code} {message:?}: {:#?}",
                    diagnostics.diagnostics
                )
            });
        assert!(
            diagnostic.primary_span.is_some(),
            "trigger metadata `{value}` must retain a source span"
        );
    }
}
fn named_type_chain_source(contract: &str, struct_count: usize) -> String {
    assert!(struct_count != 0, "a named-type chain has a product root");
    let mut source = format!("seiyaku {contract} {{\n");
    for index in 0..struct_count {
        if index + 1 == struct_count {
            source.push_str(&format!("struct S{index:03} {{ int value; }}\n"));
        } else {
            source.push_str(&format!(
                "struct S{index:03} {{ S{:03} next; }}\n",
                index + 1
            ));
        }
    }
    source.push_str("view fn run() authorize(anyone) {}\n}\n");
    source
}
fn with_private_parameter(source: String, declaration: &str) -> String {
    source.replacen(
        "view fn run() authorize(anyone) {}\n}",
        &format!("{declaration}\nview fn run() authorize(anyone) {{}}\n}}"),
        1,
    )
}
fn branching_named_type_use_source(contract: &str, repeated_roots: usize) -> String {
    let mut source = format!("seiyaku {contract} {{\n");
    for index in 0..14 {
        source.push_str(&format!(
            "struct S{index:03} {{ S{:03} left; S{:03} right; }}\n",
            index + 1,
            index + 1
        ));
    }
    source.push_str("struct S014 { int value; }\n");
    let repeated = std::iter::repeat_n("S000", repeated_roots)
        .collect::<Vec<_>>()
        .join(", ");
    source.push_str(&format!(
        "fn keep(Option<({repeated})> value) {{}}\nview fn run() authorize(anyone) {{}}\n}}\n"
    ));
    source
}
fn branching_named_type_expression_source(contract: &str, repeated_roots: usize) -> String {
    let mut source = format!("seiyaku {contract} {{\n");
    for index in 0..14 {
        source.push_str(&format!(
            "struct S{index:03} {{ S{:03} left; S{:03} right; }}\n",
            index + 1,
            index + 1
        ));
    }
    source.push_str("struct S014 { int value; }\nstate StateMap<int, S000> records;\n");
    let repeated = std::iter::repeat_n("records.get(0)", repeated_roots)
        .collect::<Vec<_>>()
        .join(", ");
    source.push_str(&format!(
        "fn infer() {{ let values = ({repeated}); }}\nview fn run() authorize(anyone) {{}}\n}}\n"
    ));
    source
}
#[test]
fn acyclic_named_type_chain_preserves_the_exact_v1_resolution_boundary() {
    // Expanded depth counts every product wrapper and the terminal scalar. A
    // chain of 255 structs plus `int` is therefore exactly 256 levels.
    let boundary = with_private_parameter(
        named_type_chain_source("DepthBoundary", MAX_NESTING_DEPTH - 1),
        "fn keep(S000 value) {}",
    );
    CompilerSession::default()
        .build(CompileRequest {
            source: &boundary,
            source_name: Some("depth-boundary.ko"),
        })
        .expect("a named type exactly 256 expanded levels deep must compile");
    // Adding one product wrapper produces the required hostile 257-level
    // acyclic chain without relying on syntactic generic nesting.
    let source = named_type_chain_source("DeepAcyclic", MAX_NESTING_DEPTH);
    let diagnostics = CompilerSession::default()
        .build(CompileRequest {
            source: &source,
            source_name: Some("deep-acyclic.ko"),
        })
        .expect_err("a 257-level expanded acyclic named type must fail within the fixed budget");
    let diagnostic = diagnostics
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "K2008")
        .expect("named-type depth diagnostic");
    assert_eq!(diagnostic.phase, DiagnosticPhase::Semantic);
    assert_eq!(
        diagnostic.message,
        format!(
            "expanded value type `S000` exceeds the V1 nesting limit of {MAX_NESTING_DEPTH} levels"
        )
    );
    let span = diagnostic.primary_span.as_ref().expect("exact type span");
    assert_eq!(span.source.as_deref(), Some("deep-acyclic.ko"));
    assert_eq!(span.start.line, 2);
}
#[test]
fn use_site_wrapper_cannot_hide_an_over_depth_named_type() {
    let source = with_private_parameter(
        named_type_chain_source("WrappedDepth", MAX_NESTING_DEPTH - 1),
        "fn keep(Option<S000> value) {}",
    );
    let diagnostics = CompilerSession::default()
        .build(CompileRequest {
            source: &source,
            source_name: Some("wrapped-depth.ko"),
        })
        .expect_err("a wrapper around a 256-level named type reaches 257 expanded levels");
    let diagnostic = diagnostics
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "K2008")
        .expect("use-site named-type depth diagnostic");
    assert_eq!(diagnostic.phase, DiagnosticPhase::Semantic);
    assert_eq!(
        diagnostic.message,
        format!(
            "expanded use-site value type exceeds the V1 nesting limit of {MAX_NESTING_DEPTH} levels"
        )
    );
    let span = diagnostic
        .primary_span
        .as_ref()
        .expect("exact use-site span");
    assert_eq!(span.source.as_deref(), Some("wrapped-depth.ko"));
    let range = span.byte_range.expect("exact use-site byte range");
    assert_eq!(
        &source[range.start as usize..range.end as usize],
        "Option<S000>"
    );
}
#[test]
fn repeated_shared_named_type_uses_obey_the_same_expanded_node_budget() {
    // Fourteen branching definitions produce a canonical S000 DAG with 49,151
    // conceptual expanded nodes. Five references plus the Option/tuple wrappers
    // remain below 250,000; a sixth reference exceeds it. Both sources stay
    // tiny, so the test specifically exercises semantic expansion accounting.
    let legitimate = branching_named_type_use_source("SharedUseBoundary", 5);
    CompilerSession::default()
        .build(CompileRequest {
            source: &legitimate,
            source_name: Some("shared-use-boundary.ko"),
        })
        .expect("repeated shared named-type references below the node budget must compile");
    let hostile = branching_named_type_use_source("SharedUseOverflow", 6);
    let diagnostics = CompilerSession::default()
        .build(CompileRequest {
            source: &hostile,
            source_name: Some("shared-use-overflow.ko"),
        })
        .expect_err("repeated shared named-type references must not multiply past the budget");
    let diagnostic = diagnostics
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "K2008")
        .expect("use-site named-type node diagnostic");
    assert_eq!(diagnostic.phase, DiagnosticPhase::Semantic);
    assert_eq!(
        diagnostic.message,
        format!(
            "expanded use-site value type exceeds the V1 resource limit of {MAX_EXPANDED_TYPE_NODES} type nodes"
        )
    );
    let span = diagnostic
        .primary_span
        .as_ref()
        .expect("exact use-site span");
    assert_eq!(span.source.as_deref(), Some("shared-use-overflow.ko"));
    let range = span.byte_range.expect("exact use-site byte range");
    assert_eq!(
        &hostile[range.start as usize..range.end as usize],
        "Option<(S000, S000, S000, S000, S000, S000)>"
    );
}
#[test]
fn inferred_aggregate_types_cannot_bypass_the_shared_node_budget() {
    let legitimate = branching_named_type_expression_source("InferredSharedBoundary", 5);
    CompilerSession::default()
        .check(CompileRequest {
            source: &legitimate,
            source_name: Some("inferred-shared-boundary.ko"),
        })
        .expect("an inferred shared aggregate below the semantic node budget must check");
    let hostile = branching_named_type_expression_source("InferredSharedOverflow", 6);
    let diagnostics = CompilerSession::default()
        .check(CompileRequest {
            source: &hostile,
            source_name: Some("inferred-shared-overflow.ko"),
        })
        .expect_err("inferred aggregates must use the same expanded-shape budget");
    let diagnostic = diagnostics
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "K2008")
        .expect("inferred use-site named-type node diagnostic");
    assert_eq!(diagnostic.phase, DiagnosticPhase::Semantic);
    assert_eq!(
        diagnostic.message,
        format!(
            "expanded use-site value type exceeds the V1 resource limit of {MAX_EXPANDED_TYPE_NODES} type nodes"
        )
    );
    let span = diagnostic
        .primary_span
        .as_ref()
        .expect("exact inferred expression span");
    assert_eq!(span.source.as_deref(), Some("inferred-shared-overflow.ko"));
    let range = span.byte_range.expect("exact inferred byte range");
    assert_eq!(
        &hostile[range.start as usize..range.end as usize],
        "(records.get(0), records.get(0), records.get(0), records.get(0), records.get(0), records.get(0))"
    );
}
#[test]
fn modest_shared_named_type_dag_compiles_below_the_node_budget() {
    let mut source = String::from("seiyaku ModestDag {\n");
    for index in 0..8 {
        source.push_str(&format!(
            "struct S{index:03} {{ S{:03} left; S{:03} right; }}\n",
            index + 1,
            index + 1
        ));
    }
    source.push_str("struct S008 { int value; }\nview fn run() authorize(anyone) {}\n}\n");
    CompilerSession::default()
        .build(CompileRequest {
            source: &source,
            source_name: Some("modest-dag.ko"),
        })
        .expect("a shared DAG whose expanded form is below the node budget must compile");
}
#[test]
fn branching_named_type_dag_is_measured_without_exponential_expansion() {
    let mut source = String::from("seiyaku BranchingDag {\n");
    for index in 0..17 {
        source.push_str(&format!(
            "struct S{index:03} {{ S{:03} left; S{:03} right; }}\n",
            index + 1,
            index + 1
        ));
    }
    source.push_str("struct S017 { int value; }\n}\n");
    let diagnostics = CompilerSession::default()
        .build(CompileRequest {
            source: &source,
            source_name: Some("branching-dag.ko"),
        })
        .expect_err("an exponentially expanding named-type DAG must fail before materialization");
    let diagnostic = diagnostics
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "K2008")
        .expect("named-type resource diagnostic");
    assert_eq!(diagnostic.phase, DiagnosticPhase::Semantic);
    assert_eq!(
        diagnostic.message,
        format!(
            "expanded value type `S000` exceeds the V1 resource limit of {MAX_EXPANDED_TYPE_NODES} type nodes"
        )
    );
    let span = diagnostic.primary_span.as_ref().expect("exact type span");
    assert_eq!(span.source.as_deref(), Some("branching-dag.ko"));
    assert_eq!(span.start.line, 2);
}
#[test]
fn over_budget_named_types_point_at_parameter_and_return_references() {
    for (source_name, declaration) in [
        (
            "oversized-param.ko",
            "view fn inspect(S000 value) authorize(anyone) {}",
        ),
        (
            "oversized-return.ko",
            "view fn inspect() authorize(anyone) -> S000 {}",
        ),
    ] {
        let mut source = String::from("seiyaku LocatedBudget {\n");
        for index in 0..17 {
            source.push_str(&format!(
                "struct S{index:03} {{ S{:03} left; S{:03} right; }}\n",
                index + 1,
                index + 1
            ));
        }
        source.push_str("struct S017 { int value; }\n");
        source.push_str(declaration);
        source.push_str("\n}\n");
        let diagnostics = CompilerSession::default()
            .build(CompileRequest {
                source: &source,
                source_name: Some(source_name),
            })
            .expect_err("the conceptual expanded shape exceeds the fixed V1 node budget");
        let diagnostic = diagnostics
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "K2008")
            .expect("located named-type resource diagnostic");
        let span = diagnostic.primary_span.as_ref().expect("exact use span");
        assert_eq!(span.source.as_deref(), Some(source_name));
        assert_eq!(span.start.line, 20);
        let range = span.byte_range.expect("exact type byte range");
        let start = usize::try_from(range.start).expect("source offset fits usize");
        let end = usize::try_from(range.end).expect("source offset fits usize");
        assert_eq!(&source[start..end], "S000");
    }
}
#[test]
fn multi_error_renderers_preserve_identical_semantic_records_and_exact_spans() {
    let source = r#"seiyaku Broken {
  fn first() { let quantity total = true; }
  fn second() { let value = 1; value = 2; }
}"#;
    let source_name = "multi-error-renderers.ko";
    let diagnostics = CompilerSession::default()
        .build(CompileRequest {
            source,
            source_name: Some(source_name),
        })
        .expect_err("independent semantic errors must fail compilation");
    for code in ["E_TYPE_ANNOTATION_MISMATCH", "E_IMMUTABLE_ASSIGNMENT"] {
        assert!(
            diagnostics
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == code),
            "missing {code}: {diagnostics:#?}"
        );
    }
    assert!(
        diagnostics.diagnostics.len() >= 2,
        "all independent errors must be retained: {diagnostics:#?}"
    );
    let human = diagnostics.render_human();
    for diagnostic in &diagnostics.diagnostics {
        assert!(
            human.contains(&format!(
                "{}[{}] {}: {}",
                diagnostic.severity.as_str(),
                diagnostic.code,
                diagnostic.phase.as_str(),
                diagnostic.message
            )),
            "human output omitted the canonical header for {}: {human}",
            diagnostic.code,
        );
        let span = diagnostic
            .primary_span
            .as_ref()
            .unwrap_or_else(|| panic!("{} has no primary span", diagnostic.code));
        assert_eq!(span.source.as_deref(), Some(source_name));
        let range = span
            .byte_range
            .unwrap_or_else(|| panic!("{} has no exact byte range", diagnostic.code));
        let start = usize::try_from(range.start).expect("byte offset fits usize");
        let end = usize::try_from(range.end).expect("byte offset fits usize");
        assert!(
            start < end && end <= source.len(),
            "{} has invalid byte range {start}..{end}",
            diagnostic.code
        );
        assert!(
            human.contains(&format!(
                "{source_name}:{}:{}-{}:{}",
                span.start.line, span.start.column, span.end.line, span.end.column
            )),
            "human output omitted the exact span for {}: {human}",
            diagnostic.code
        );
        for label in &diagnostic.labels {
            assert!(
                human.contains(&label.message),
                "human output omitted a label for {}: {human}",
                diagnostic.code
            );
        }
        for note in &diagnostic.notes {
            assert!(
                human.contains(note),
                "human output omitted a note for {}: {human}",
                diagnostic.code
            );
        }
        if let Some(help) = &diagnostic.help {
            assert!(
                human.contains(help),
                "human output omitted help for {}: {human}",
                diagnostic.code
            );
        }
        if let Some(fix) = &diagnostic.fix {
            assert!(
                human.contains(&fix.replacement),
                "human output omitted the fix for {}: {human}",
                diagnostic.code
            );
        }
    }
    let canonical: norito::json::Value = norito::json::from_str(
        &diagnostics
            .render_json()
            .expect("render canonical JSON diagnostics"),
    )
    .expect("decode canonical JSON diagnostics");
    let sarif: norito::json::Value = norito::json::from_str(
        &diagnostics
            .render_sarif()
            .expect("render canonical SARIF diagnostics"),
    )
    .expect("decode canonical SARIF diagnostics");
    let canonical_records = canonical.as_array().expect("canonical diagnostic array");
    let sarif_results = sarif
        .pointer("/runs/0/results")
        .and_then(norito::json::Value::as_array)
        .expect("SARIF result array");
    assert_eq!(canonical_records.len(), sarif_results.len());
    for (canonical_record, sarif_result) in canonical_records.iter().zip(sarif_results) {
        assert_eq!(
            sarif_result
                .pointer("/properties/kotodama")
                .expect("SARIF embeds the canonical Kotodama record"),
            canonical_record,
            "JSON and SARIF semantic fields diverged"
        );
    }
}
