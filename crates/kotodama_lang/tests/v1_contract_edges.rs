//! Adversarial edge coverage for the final Kotodama V1 frontend contract.
use kotodama_lang::{
    ast::{BinaryOp, Expr, Item, Program, UnaryOp},
    parser::parse,
    session::{CompileRequest, CompilerSession},
};
fn function_tail<'program>(program: &'program Program, name: &str) -> &'program Expr {
    program
        .items
        .iter()
        .find_map(|item| match item {
            Item::Function(function) if function.name == name => function.body.tail.as_deref(),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing tail expression for `{name}`"))
}
fn assert_ident(expression: &Expr, expected: &str) {
    assert!(
        matches!(expression.kind(), Expr::Ident(actual) if actual == expected),
        "expected identifier `{expected}`, found {expression:?}"
    );
}
#[test]
fn operator_precedence_and_left_associativity_are_structural() {
    let program = parse(
        r#"
        module Precedence {
            fn arithmetic(int a, int b, int c, int d, int e, int f) -> int {
                a - b + c * d / e % f
            }

            fn logic(bool a, bool b, bool c, int x, int y, int z, int w) -> bool {
                a || b && x + y * z < w == c
            }

            fn prefix(bool fallback, Option<bool> maybe) -> bool {
                !maybe? && fallback
            }
        }
        "#,
    )
    .expect("parse the complete V1 precedence ladder");
    let Expr::Binary {
        op: BinaryOp::Add,
        left,
        right,
    } = function_tail(&program, "arithmetic").kind()
    else {
        panic!("addition must be the arithmetic root");
    };
    let Expr::Binary {
        op: BinaryOp::Sub,
        left: a,
        right: b,
    } = left.kind()
    else {
        panic!("addition and subtraction must associate left");
    };
    assert_ident(a, "a");
    assert_ident(b, "b");
    let Expr::Binary {
        op: BinaryOp::Mod,
        left,
        right: f,
    } = right.kind()
    else {
        panic!("multiplication, division, and remainder must associate left");
    };
    let Expr::Binary {
        op: BinaryOp::Div,
        left,
        right: e,
    } = left.kind()
    else {
        panic!("division must remain inside the remainder left operand");
    };
    let Expr::Binary {
        op: BinaryOp::Mul,
        left: c,
        right: d,
    } = left.kind()
    else {
        panic!("multiplication must bind before addition");
    };
    assert_ident(c, "c");
    assert_ident(d, "d");
    assert_ident(e, "e");
    assert_ident(f, "f");
    let Expr::Binary {
        op: BinaryOp::Or,
        left: a,
        right,
    } = function_tail(&program, "logic").kind()
    else {
        panic!("logical or must be the boolean root");
    };
    assert_ident(a, "a");
    let Expr::Binary {
        op: BinaryOp::And,
        left: b,
        right,
    } = right.kind()
    else {
        panic!("logical and must bind before logical or");
    };
    assert_ident(b, "b");
    let Expr::Binary {
        op: BinaryOp::Eq,
        left,
        right: c,
    } = right.kind()
    else {
        panic!("comparison operators must bind before logical and");
    };
    let Expr::Binary {
        op: BinaryOp::Lt,
        left,
        right: w,
    } = left.kind()
    else {
        panic!("comparison chains must associate left");
    };
    let Expr::Binary {
        op: BinaryOp::Add,
        left: x,
        right,
    } = left.kind()
    else {
        panic!("addition must bind before comparison");
    };
    let Expr::Binary {
        op: BinaryOp::Mul,
        left: y,
        right: z,
    } = right.kind()
    else {
        panic!("multiplication must bind before addition");
    };
    assert_ident(x, "x");
    assert_ident(y, "y");
    assert_ident(z, "z");
    assert_ident(w, "w");
    assert_ident(c, "c");
    let Expr::Binary {
        op: BinaryOp::And,
        left,
        right: fallback,
    } = function_tail(&program, "prefix").kind()
    else {
        panic!("logical and must remain outside prefix/postfix operators");
    };
    let Expr::Unary {
        op: UnaryOp::Not,
        expr,
    } = left.kind()
    else {
        panic!("prefix not must wrap its complete postfix operand");
    };
    let Expr::Propagate(maybe) = expr.kind() else {
        panic!("postfix propagation must bind before prefix not");
    };
    assert_ident(maybe, "maybe");
    assert_ident(fallback, "fallback");
}
#[test]
fn native_json_rejects_keys_that_collide_only_after_escape_decoding() {
    let source = r#"
        seiyaku DuplicateDecodedKey {
            fn build() -> Json {
                json { owner: 1, "own\u{65}r": 2 }
            }
        }
    "#;
    let diagnostics = CompilerSession::default()
        .check(CompileRequest {
            source,
            source_name: Some("duplicate-decoded-key.ko"),
        })
        .expect_err("decoded duplicate JSON keys must fail closed");
    let diagnostic = diagnostics
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "E_JSON_DUPLICATE_KEY")
        .unwrap_or_else(|| panic!("missing duplicate-key diagnostic: {diagnostics:#?}"));
    assert!(
        diagnostic.message.contains("after string decoding"),
        "{}",
        diagnostic.message
    );
}
#[test]
fn json_parse_rejects_duplicate_object_keys_before_artifact_emission() {
    let source = r#"
        seiyaku DuplicateParsedJsonKey {
            view fn build() authorize(anyone) -> Json {
                Json::parse("{\"owner\":1,\"owner\":2}")
            }
        }
    "#;
    let diagnostics = CompilerSession::default()
        .build(CompileRequest {
            source,
            source_name: Some("duplicate-parsed-json-key.ko"),
        })
        .expect_err("Json::parse duplicate object keys must fail closed");
    let diagnostic = diagnostics
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "E_JSON_DUPLICATE_KEY")
        .unwrap_or_else(|| panic!("missing parsed duplicate-key diagnostic: {diagnostics:#?}"));
    assert!(
        !diagnostic.message.contains("{error}"),
        "translated diagnostic leaked an unresolved placeholder: {}",
        diagnostic.message
    );
    assert_eq!(
        diagnostic
            .primary_span
            .as_ref()
            .and_then(|span| span.source.as_deref()),
        Some("duplicate-parsed-json-key.ko")
    );
}
#[test]
fn json_parse_rejects_malformed_literals_before_artifact_emission() {
    let source = r#"
        seiyaku MalformedParsedJson {
            view fn build() authorize(anyone) -> Json {
                Json::parse("{\"owner\":")
            }
        }
    "#;
    let diagnostics = CompilerSession::default()
        .build(CompileRequest {
            source,
            source_name: Some("malformed-parsed-json.ko"),
        })
        .expect_err("malformed Json::parse literals must fail closed");
    let diagnostic = diagnostics
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "E_JSON_LITERAL_INVALID")
        .unwrap_or_else(|| panic!("missing malformed JSON diagnostic: {diagnostics:#?}"));
    assert!(
        diagnostic.message.contains("Json::parse"),
        "{}",
        diagnostic.message
    );
    assert!(
        !diagnostic.message.contains("{error}"),
        "translated diagnostic leaked an unresolved placeholder: {}",
        diagnostic.message
    );
    assert_eq!(
        diagnostic
            .primary_span
            .as_ref()
            .and_then(|span| span.source.as_deref()),
        Some("malformed-parsed-json.ko")
    );
}
