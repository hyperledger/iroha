//! Source directives, bare fragments, explicit exports, and static rejection text.
use kotodama_lang::{
    ast::{Item, SourceDirectiveKind, SourceUnitKind},
    formatter::format_source,
    parser::{parse, parse_fragment_source, parse_source},
    source::{FrontendBudget, SourceFile, SourceId},
    syntax::parse_fragment_program,
};

#[test]
fn directives_retain_declaration_order_and_original_ranges() {
    let text =
        "seiyaku Wallet { include \"./state.ko\"; fn helper() {} import \"./math.ko\" as math; }";
    let file = SourceFile::new(SourceId(19), "wallet.ko", text);
    let program = parse_source(&file, FrontendBudget::v1()).expect("source directives");
    assert_eq!(program.directives.len(), 2);
    assert_eq!(program.directives[0].item_index, 0);
    assert_eq!(program.directives[1].item_index, 1);
    assert_eq!(program.directives[0].source.source, SourceId(19));
    assert_eq!(
        file.slice(program.directives[0].source.range),
        Some("include \"./state.ko\";")
    );
    assert!(
        matches!(&program.directives[1].kind, SourceDirectiveKind::Import { path, alias } if path == "./math.ko" && alias == "math")
    );
}

#[test]
fn bare_fragments_have_no_synthetic_wrapper_offsets() {
    let text = "permission CanCredit; // shared declarations\nstate int balance;\ninclude \"./errors.ko\";\nkotoage fn credit() authorize(CanCredit) {}";
    let file = SourceFile::new(SourceId(23), "state.ko", text);
    let parsed = parse_fragment_program(&file, FrontendBudget::v1());
    assert!(parsed.is_ok(), "{}", parsed.diagnostics.render_human());
    assert_eq!(parsed.tree.text(&file), text);
    let program = parsed.program.expect("fragment AST");
    assert_eq!(program.unit.kind, SourceUnitKind::Fragment);
    assert!(program.unit.name.is_empty());
    assert_eq!(program.items.len(), 2);
    assert_eq!(
        file.slice(program.directives[0].source.range),
        Some("include \"./errors.ko\";")
    );
    assert!(
        parse(text).is_err(),
        "standalone compilation still requires a named source unit"
    );
    let named = SourceFile::new(SourceId(24), "module.ko", "module Math {}");
    assert!(parse_fragment_source(&named, FrontendBudget::v1()).is_err());
}

#[test]
fn exports_are_explicit_and_independent_of_function_kind() {
    let program = parse("module Math { export const int SCALE = 10; export struct Quote { int amount; } export error enum Fault { Invalid = 1; } export fn double(int value) -> int { value * 2 } fn hidden() {} }").expect("explicit exports");
    assert_eq!(
        program
            .exports
            .iter()
            .map(|export| export.name.as_str())
            .collect::<Vec<_>>(),
        ["SCALE", "Quote", "Fault", "double"]
    );
    let Item::Function(function) = &program.items[3] else {
        panic!("function")
    };
    assert_eq!(
        function.modifiers.kind,
        kotodama_lang::ast::FunctionKind::Private
    );
    for text in [
        "seiyaku Wallet { export fn hidden() {} }",
        "module Math { export state int balance; }",
        "module Math { export import \"./value.ko\" as value; }",
        "module Math { export view fn read() authorize(anyone) {} }",
    ] {
        assert!(parse(text).is_err(), "invalid exported declaration: {text}");
    }
}

#[test]
fn error_messages_accept_static_utf8_and_enforce_the_byte_limit() {
    let program = parse("module Errors { error enum Fault { #[message(\"残高が不足しています\")] Insufficient = 7; Plain = 8; } }").expect("static message");
    let Item::Enum(errors) = &program.items[0] else {
        panic!("error enum")
    };
    assert_eq!(
        errors.variants[0].message.as_deref(),
        Some("残高が不足しています")
    );
    assert_eq!(errors.variants[1].message, None);
    let exact = "é".repeat(2048);
    parse(&format!(
        "module E {{ error enum F {{ #[message(\"{exact}\")] Bad = 1; }} }}"
    ))
    .expect("4096 UTF-8 bytes");
    for attribute in [
        "#[message(\"\")]".to_owned(),
        "#[message(\" \\n \")]".to_owned(),
        "#[message(value)]".to_owned(),
        "#[message(\"a\" + \"b\")]".to_owned(),
        "#[message(\"a\")] #[message(\"b\")]".to_owned(),
        format!("#[message(\"{exact}x\")]"),
    ] {
        assert!(
            parse(&format!(
                "module E {{ error enum F {{ {attribute} Bad = 1; }} }}"
            ))
            .is_err(),
            "invalid message: {attribute}"
        );
    }
}

#[test]
fn formatting_fragments_and_dependencies_is_lossless_and_idempotent() {
    for text in [
        "seiyaku Wallet{include\"./state.ko\";import\"./math.ko\"as math;}",
        "// shared\ninclude\"./types.ko\";export const int SCALE=10;error enum Fault{#[message(\"Keep this text\")] Bad=1;}",
    ] {
        let source = SourceFile::new(SourceId(0), "format.ko", text);
        let formatted = format_source(&source, FrontendBudget::v1()).expect("format source");
        let source = SourceFile::new(SourceId(0), "format.ko", &formatted);
        assert_eq!(
            format_source(&source, FrontendBudget::v1()).expect("format twice"),
            formatted
        );
        assert!(formatted.contains("include \"./"));
        if text.contains("import") {
            assert!(formatted.contains("import \"./math.ko\" as math;"));
        } else {
            assert!(formatted.contains("#[message(\"Keep this text\")]"));
        }
    }
}

#[test]
fn directives_require_literal_paths_and_declaration_scope() {
    for text in [
        "module M { include path; }",
        "module M { include \"\"; }",
        "module M { import \"./x.ko\"; }",
        "module M { import \"./x.ko\" as \"x\"; }",
        "module M { fn f() { include \"./x.ko\"; } }",
        "module M { fn f() { import \"./x.ko\" as x; } }",
    ] {
        assert!(parse(text).is_err(), "invalid directive: {text}");
    }
}
