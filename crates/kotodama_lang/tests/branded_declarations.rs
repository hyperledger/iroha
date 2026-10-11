//! Kotodama V1 branded declaration syntax invariants.
use kotodama_lang::{
    formatter::format_source,
    lexer::V1_KEYWORD_EDITOR_PATTERN,
    session::{CompileRequest, CompilerSession},
    source::{FrontendBudget, SourceFile, SourceId},
    syntax::parse,
};
fn parse_source(text: &str) -> kotodama_lang::syntax::ParseOutput {
    let source = SourceFile::new(SourceId(0), "branding.ko", text);
    parse(&source, FrontendBudget::v1())
}
#[test]
fn romanized_and_japanese_declaration_sets_are_first_class() {
    for source in [
        r#"seiyaku Branding { permission Set;
            state int value;
            hajimari() { value = 0; }
            kotoage fn set(int next) authorize(Set) { value = next; }
            kaizen() {}
            view fn read() authorize(anyone) -> int { return value; }
            trigger tick -> set { on time pre_commit; }
        }"#,
        r#"誓約 Branding { permission Set;
            state int value;
            始まり() { value = 0; }
            言挙げ fn set(int next) authorize(Set) { value = next; }
            改善() {}
            view fn read() authorize(anyone) -> int { return value; }
            trigger tick -> set { on time pre_commit; }
        }"#,
    ] {
        let output = parse_source(source);
        assert!(output.is_ok(), "{:?}", output.diagnostics.diagnostics);
    }
}
#[test]
fn formatting_preserves_the_selected_japanese_declaration_script() {
    let source = SourceFile::new(
        SourceId(1),
        "japanese-branding.ko",
        "誓約 Branding{ permission Set; 始まり(){}言挙げ fn set() authorize(Set) {}改善(){}}",
    );
    let formatted = format_source(&source, FrontendBudget::v1())
        .expect("Japanese branded declarations must format");
    for spelling in ["誓約", "始まり", "言挙げ", "改善"] {
        assert!(
            formatted.contains(spelling),
            "formatter omitted `{spelling}`: {formatted}"
        );
    }
    for spelling in ["seiyaku", "hajimari", "kotoage", "kaizen"] {
        assert!(
            !formatted.contains(spelling),
            "formatter rewrote Japanese `{spelling}` feature syntax: {formatted}"
        );
    }
}
#[test]
fn editor_keyword_boundaries_cover_unicode_identifier_continuations() {
    for property in [r"\p{L}", r"\p{N}"] {
        assert!(
            V1_KEYWORD_EDITOR_PATTERN.contains(property),
            "editor keyword matcher omitted Unicode boundary `{property}`"
        );
    }
    for alias in ["contract", "entry", "init", "upgrade"] {
        assert!(
            !V1_KEYWORD_EDITOR_PATTERN.contains(alias),
            "editor keyword matcher advertised English feature alias `{alias}`"
        );
    }
}
#[test]
fn english_feature_aliases_are_rejected_by_the_lossless_frontend() {
    for (alias, source) in [
        ("contract", "contract Branding {}"),
        (
            "entry",
            "seiyaku Branding { entry fn set() authorize(anyone) {} }",
        ),
        ("init", "seiyaku Branding { init() {} }"),
        ("upgrade", "seiyaku Branding { upgrade() {} }"),
    ] {
        let output = parse_source(source);
        assert!(
            !output.is_ok(),
            "English feature alias `{alias}` was accepted"
        );
        assert_eq!(
            output
                .tree
                .text(&SourceFile::new(SourceId(0), "branding.ko", source)),
            source,
            "alias rejection must remain lossless"
        );
    }
}
#[test]
fn english_words_remain_available_as_ordinary_identifiers() {
    let source = r#"module OrdinaryWords {
        fn combine(int contract, int entry, int init, int upgrade) -> int {
            return contract + entry + init + upgrade;
        }
    }"#;
    let output = parse_source(source);
    assert!(output.is_ok(), "{:?}", output.diagnostics.diagnostics);
    CompilerSession::default()
        .check(CompileRequest {
            source,
            source_name: Some("ordinary-words.ko"),
        })
        .expect("English words that are not feature syntax must resolve as ordinary identifiers");
}
