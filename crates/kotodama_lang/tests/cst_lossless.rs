//! Lossless CST coverage for trivia, Unicode, and recovery tokens.
use kotodama_lang::{
    source::{FrontendBudget, SourceFile, SourceId},
    syntax::{SyntaxKind, parse},
};
#[test]
fn valid_source_round_trips_with_unicode_in_trivia_and_strings() {
    let text = r##"/* leading comment */
seiyaku Words {
    // 言葉 and spacing must survive
    view fn cafe(int value) authorize(anyone) -> string {
        let message = r#"こんにちは // not a comment"#;
        return message;
    }
}
"##;
    let source = SourceFile::new(SourceId(7), "unicode.ko", text);
    let output = parse(&source, FrontendBudget::v1());
    assert_eq!(output.tree.text(&source), text);
    assert!(output.is_ok(), "{:?}", output.diagnostics.diagnostics);
    let kinds = output
        .tree
        .tokens()
        .into_iter()
        .map(|token| token.kind)
        .collect::<Vec<_>>();
    assert!(kinds.contains(&SyntaxKind::Whitespace));
    assert!(kinds.contains(&SyntaxKind::LineComment));
    assert!(kinds.contains(&SyntaxKind::BlockComment));
}
#[test]
fn non_ascii_identifier_characters_are_lossless_errors() {
    let text = "seiyaku Café { view fn ping() authorize(anyone) { return; } }";
    let source = SourceFile::new(SourceId(8), "non-ascii-ident.ko", text);
    let output = parse(&source, FrontendBudget::v1());
    assert_eq!(output.tree.text(&source), text);
    assert!(!output.is_ok());
    assert!(output.tree.tokens().into_iter().any(|token| {
        token.kind == SyntaxKind::ErrorToken && source.slice(token.range) == Some("Café")
    }));
    assert!(output.diagnostics.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "K0100"
            && diagnostic.message == "non-ASCII identifier `Café`: identifiers are ASCII"
            // Japanese keyword guidance is reserved for Japanese text.
            && !diagnostic.help.as_deref().unwrap_or("").contains("誓約")
    }));
}
#[test]
fn malformed_text_remains_lossless_as_error_tokens() {
    let text = "seiyaku Demo { fn f() { let x = 1; @ let y = 2; } }";
    let source = SourceFile::new(SourceId(1), "error-token.ko", text);
    let output = parse(&source, FrontendBudget::v1());
    assert_eq!(output.tree.text(&source), text);
    assert!(output.tree.tokens().into_iter().any(|token| {
        token.kind == SyntaxKind::ErrorToken && source.slice(token.range) == Some("@")
    }));
    assert!(
        output
            .diagnostics
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.phase.as_str() == "lex")
    );
}
#[test]
fn unsuffixed_decimal_fraction_is_preserved_by_v1_lexer() {
    let text = "seiyaku Demo { fn f() { let value = 1_234.50_0; } }";
    let source = SourceFile::new(SourceId(9), "decimal-fraction.ko", text);
    let output = parse(&source, FrontendBudget::v1());
    assert_eq!(output.tree.text(&source), text);
    assert!(output.is_ok(), "{:#?}", output.diagnostics.diagnostics);
    assert!(output.tree.tokens().into_iter().any(|token| {
        token.kind == SyntaxKind::Decimal && source.slice(token.range) == Some("1_234.50_0")
    }));
}
#[test]
fn parser_inserts_zero_width_missing_tokens_without_changing_text() {
    let text = "seiyaku Demo { fn f() { let int value = ; return; } }";
    let source = SourceFile::new(SourceId(2), "missing.ko", text);
    let output = parse(&source, FrontendBudget::v1());
    assert_eq!(output.tree.text(&source), text);
    let missing = output
        .tree
        .tokens()
        .into_iter()
        .filter(|token| token.kind == SyntaxKind::Missing)
        .collect::<Vec<_>>();
    assert!(!missing.is_empty());
    assert!(missing.iter().all(|token| token.range.is_empty()));
    assert!(missing.iter().all(|token| token.expected.is_some()));
}
#[test]
fn local_test_units_are_accepted_without_rewriting() {
    let text = r#"module Tests {
        koto_test { target: "contract.ko" }
        fixture actors { caller("alice"); }
        #[test(fixture="actors")]
        fn smoke() { test::assert(true); }
    }"#;
    let source = SourceFile::new(SourceId(3), "contract.test.ko", text);
    let output = parse(&source, FrontendBudget::v1());
    assert_eq!(output.tree.text(&source), text);
    assert!(output.is_ok(), "{:?}", output.diagnostics.diagnostics);
}
