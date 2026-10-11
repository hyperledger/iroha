//! Structural CST coverage for declarations, statements, and hostile recovery.
use kotodama_lang::{
    source::{FrontendBudget, SourceFile, SourceId},
    syntax::{GreenElement, GreenNode, SyntaxKind, lex, parse},
};
use std::collections::HashMap;
fn collect_kinds(node: &GreenNode, counts: &mut HashMap<SyntaxKind, usize>) {
    *counts.entry(node.kind).or_default() += 1;
    for child in &node.children {
        if let GreenElement::Node(child) = child {
            collect_kinds(child, counts);
        }
    }
}
fn collect_nodes<'tree>(node: &'tree GreenNode, nodes: &mut Vec<&'tree GreenNode>) {
    nodes.push(node);
    for child in &node.children {
        if let GreenElement::Node(child) = child {
            collect_nodes(child, nodes);
        }
    }
}
#[test]
fn valid_contract_has_declaration_and_statement_structure() {
    let text = r#"seiyaku Shape { permission Run;
        struct Pair { int left, int right }
        error enum Failure { Bad = 1 }
        const int LIMIT = 4;
        state int count;
        trigger tick -> run { on time pre_commit; }

        hajimari() {
            var int sum = 0;
            for i in range(4) {
                if i < 2 { sum += i; } else { continue; }
            }
        }

        kotoage fn run(int value) authorize(Run) {
            let int copy = value;
            return;
        }

        view fn read() authorize(anyone) -> int { return 1; }
    }
"#;
    let source = SourceFile::new(SourceId(11), "shape.ko", text);
    let output = parse(&source, FrontendBudget::v1());
    assert!(output.is_ok(), "{:?}", output.diagnostics.diagnostics);
    assert_eq!(output.tree.text(&source), text);
    let mut counts = HashMap::new();
    collect_kinds(output.tree.root(), &mut counts);
    for required in [
        SyntaxKind::Root,
        SyntaxKind::SourceUnit,
        SyntaxKind::ItemList,
        SyntaxKind::StructItem,
        SyntaxKind::EnumItem,
        SyntaxKind::ConstItem,
        SyntaxKind::StateItem,
        SyntaxKind::TriggerItem,
        SyntaxKind::FunctionItem,
        SyntaxKind::ParamList,
        SyntaxKind::Block,
        SyntaxKind::StatementList,
        SyntaxKind::LetStmt,
        SyntaxKind::ExprStmt,
        SyntaxKind::ReturnStmt,
        SyntaxKind::ContinueStmt,
        SyntaxKind::IfExpr,
        SyntaxKind::ForStmt,
    ] {
        assert!(
            counts.contains_key(&required),
            "missing {required:?}: {counts:?}"
        );
    }
    assert_eq!(counts.get(&SyntaxKind::SourceUnit), Some(&1));
    assert_eq!(counts.get(&SyntaxKind::ItemList), Some(&1));
    assert_eq!(counts.get(&SyntaxKind::FunctionItem), Some(&3));
    assert_eq!(counts.get(&SyntaxKind::ParamList), Some(&3));
}
#[test]
fn local_test_declarations_and_attributes_are_structural_nodes() {
    let text = r#"module Tests {
        koto_test { target: "contract.ko" }
        fixture actors { caller("alice"); }
        #[test(fixture="actors")]
        fn smoke() { test::assert(true); }
    }"#;
    let source = SourceFile::new(SourceId(12), "contract.test.ko", text);
    let output = parse(&source, FrontendBudget::v1());
    assert!(output.is_ok(), "{:?}", output.diagnostics.diagnostics);
    let mut counts = HashMap::new();
    collect_kinds(output.tree.root(), &mut counts);
    assert_eq!(counts.get(&SyntaxKind::TestTargetItem), Some(&1));
    assert_eq!(counts.get(&SyntaxKind::FixtureItem), Some(&1));
    assert_eq!(counts.get(&SyntaxKind::Attribute), Some(&1));
    assert_eq!(counts.get(&SyntaxKind::FunctionItem), Some(&1));
}
#[test]
fn hostile_recovery_is_lossless_and_inserts_specific_missing_tokens() {
    let text = r#"seiyaku Broken {
        #[test(fixture="actors")
        fn bad(int value {
            let int first = @
            if true { return }
            for i in range(2) { continue; }
        }
    }"#;
    let source = SourceFile::new(SourceId(13), "hostile.ko", text);
    let output = parse(&source, FrontendBudget::v1());
    assert_eq!(output.tree.text(&source), text);
    assert!(!output.is_ok());
    let mut counts = HashMap::new();
    collect_kinds(output.tree.root(), &mut counts);
    assert!(
        counts
            .get(&SyntaxKind::ErrorNode)
            .copied()
            .unwrap_or_default()
            >= 1
    );
    assert_eq!(counts.get(&SyntaxKind::FunctionItem), Some(&1));
    assert_eq!(counts.get(&SyntaxKind::Attribute), Some(&1));
    let expected = output
        .tree
        .tokens()
        .into_iter()
        .filter_map(|token| token.is_missing().then_some(token.expected))
        .flatten()
        .collect::<Vec<_>>();
    assert!(expected.contains(&SyntaxKind::RBracket), "{expected:?}");
    assert!(expected.contains(&SyntaxKind::RParen), "{expected:?}");
    assert!(expected.contains(&SyntaxKind::Semicolon), "{expected:?}");
}
#[test]
fn tree_uses_the_one_lossless_token_stream_exactly_once() {
    let text = "/* 前 */\n誓約 Demo { // 言葉\n 始まり() { let string s = \"雪\"; }\n}\n";
    let source = SourceFile::new(SourceId(14), "branded.ko", text);
    let lexed = lex(&source, FrontendBudget::v1());
    let output = parse(&source, FrontendBudget::v1());
    assert_eq!(output.tree.text(&source), text);
    let tree_tokens = output
        .tree
        .tokens()
        .into_iter()
        .filter(|token| !token.is_missing())
        .copied()
        .collect::<Vec<_>>();
    assert_eq!(tree_tokens, lexed.tokens);
    let mut nodes = Vec::new();
    collect_nodes(output.tree.root(), &mut nodes);
    for node in nodes {
        assert!(
            source.slice(node.range).is_some(),
            "{:?} has a non-UTF-8 range {:?}",
            node.kind,
            node.range
        );
        for child in &node.children {
            let range = match child {
                GreenElement::Node(child) => child.range,
                GreenElement::Token(token) => token.range,
            };
            if !range.is_empty() {
                assert!(
                    node.range.contains(range),
                    "{:?} {:?} does not contain {:?}",
                    node.kind,
                    node.range,
                    range
                );
            }
        }
    }
}
#[test]
fn excessive_nested_recovery_remains_bounded_and_lossless() {
    let mut text = String::from("seiyaku Deep { fn run() {");
    for _ in 0..300 {
        text.push_str("if true {");
    }
    text.push_str("return;");
    for _ in 0..300 {
        text.push('}');
    }
    text.push_str("} }");
    let source = SourceFile::new(SourceId(15), "deep.ko", &text);
    let output = parse(&source, FrontendBudget::v1());
    assert_eq!(output.tree.text(&source), text);
    assert!(
        output
            .diagnostics
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "K0003")
    );
    assert_eq!(
        output
            .tree
            .tokens()
            .into_iter()
            .filter(|token| token.kind == SyntaxKind::Eof)
            .count(),
        1
    );
}
