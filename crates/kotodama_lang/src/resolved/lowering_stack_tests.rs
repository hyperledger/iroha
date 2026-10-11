//! Deep resolver ownership crosses type capacities, expressions and statement blocks.

use super::*;
use crate::{session, source::SourceId};

const MIXED_DEPTH: usize = 32_768;

fn empty_targets() -> GlobalTargets {
    GlobalTargets {
        all: BTreeMap::new(),
        structs: BTreeMap::new(),
        enums: BTreeMap::new(),
        functions: BTreeMap::new(),
        states: BTreeMap::new(),
        consts: BTreeMap::new(),
        permissions: BTreeSet::new(),
        variant_codes: BTreeMap::new(),
        resolve_import_calls: false,
        external_functions: BTreeSet::new(),
        external_states: BTreeSet::new(),
        external_structs: BTreeSet::new(),
        external_consts: BTreeSet::new(),
        external_variant_codes: BTreeMap::new(),
        declarations: BTreeMap::new(),
    }
}

fn range(map: &AstSourceMap) -> SourceRange {
    SourceRange::new(map.source(), TextRange::new(0, 1))
}

fn source_type(map: &mut AstSourceMap, ty: TypeExpr) -> TypeExpr {
    TypeExpr::Source {
        node: map.allocate_owned(AstNodeKind::Type, TextRange::new(0, 1), None),
        source: range(map),
        ty: Box::new(ty),
    }
}

fn source_expression(map: &mut AstSourceMap, expression: Expr) -> Expr {
    Expr::Source {
        node: map.allocate_owned(AstNodeKind::Expression, TextRange::new(0, 1), None),
        source: range(map),
        expression: Box::new(expression),
    }
}

fn mixed_source_type(map: &mut AstSourceMap, bindings: &mut Vec<BindingFact>) -> TypeExpr {
    let mut ty = source_type(map, TypeExpr::Const(0));
    for _ in 0..MIXED_DEPTH {
        let owner = map.allocate_owned(AstNodeKind::Statement, TextRange::new(0, 1), None);
        let name_node = map.allocate_owned(AstNodeKind::Name, TextRange::new(0, 1), None);
        bindings.push(BindingFact {
            owner,
            ordinal: 0,
            name_node,
            name: "x".to_owned(),
            kind: BindingFactKind::Local,
        });
        let statement = Statement::Source {
            node: owner,
            source: range(map),
            statement: Box::new(Statement::Let {
                mutable: false,
                pat: Pattern::Name("x".to_owned()),
                ty: Some(ty),
                value: source_expression(map, Expr::Bool(false)),
            }),
        };
        let condition = source_expression(map, Expr::Bool(true));
        let tail = source_expression(map, Expr::Ident("x".to_owned()));
        let expression = source_expression(
            map,
            Expr::If {
                condition: Box::new(condition),
                then_branch: Block {
                    statements: vec![statement],
                    tail: Some(Box::new(tail)),
                },
                else_branch: None,
            },
        );
        ty = source_type(map, TypeExpr::ConstExpression(Box::new(expression)));
    }
    ty
}

fn mixed_binding_identity(mut ty: &TypeExpr, arena: &ResolvedArena) -> bool {
    let mut depth = 0;
    while let TypeExpr::ConstExpression(expression) = ty.kind() {
        let Expr::If { then_branch, .. } = expression.kind() else {
            return false;
        };
        let statement = &then_branch.statements[0];
        let Statement::Let {
            ty: Some(child), ..
        } = statement.kind()
        else {
            return false;
        };
        let node = &arena.nodes[statement.hir_id().expect("resolved statement").0 as usize];
        let [binding] = node.bindings.as_slice() else {
            return false;
        };
        let tail = then_branch.tail.as_ref().expect("bound tail");
        let tail_node = &arena.nodes[tail.hir_id().expect("resolved tail").0 as usize];
        if tail_node.target
            != Some(ResolvedTarget::Value(ResolvedValueTarget::Binding(
                *binding,
            )))
            || tail_node.scope != node.scope
            || ty.source().is_none()
        {
            return false;
        }
        depth += 1;
        ty = child;
    }
    depth == MIXED_DEPTH && matches!(ty.kind(), TypeExpr::Const(0))
}

#[test]
fn mixed_lowering_preserves_bindings_on_the_ordinary_caller_stack() {
    let source = SourceFile::new(SourceId(91), "mixed-lowering.ko", "x");
    let mut map = AstSourceMap::new(source.id());
    let mut bindings = Vec::new();
    let ty = mixed_source_type(&mut map, &mut bindings);
    let mut lowerer = HirLowerer::new(&source, &map, empty_targets(), BTreeMap::new(), &bindings);
    session::reset_compiler_worker_spawn_count();
    let resolved = lowerer.wrap_type(ty, ScopeId(0));
    let exact_binding_identity = mixed_binding_identity(&resolved, &lowerer.arena);
    let all_source_bound = lowerer
        .arena
        .nodes
        .iter()
        .all(|node| node.source == Some(range(&map)));
    crate::ast::drop_type_iterative(resolved);
    assert!(
        exact_binding_identity,
        "each tail resolves its own completed declaration"
    );
    assert!(all_source_bound);
    assert!(lowerer.diagnostics.is_empty());
    assert_eq!(lowerer.arena.nodes.len(), 6 * MIXED_DEPTH + 1);
    assert_eq!(lowerer.arena.scopes.len(), MIXED_DEPTH + 1);
    assert_eq!(lowerer.arena.bindings.len(), MIXED_DEPTH);
    assert_eq!(lowerer.consumed_binding_facts.len(), MIXED_DEPTH);
    assert_eq!(session::compiler_worker_spawn_count(), 0);
}

fn deep_untrusted_type() -> TypeExpr {
    let mut ty = TypeExpr::Const(0);
    for _ in 0..MIXED_DEPTH {
        ty = TypeExpr::ConstExpression(Box::new(Expr::If {
            condition: Box::new(Expr::Bool(true)),
            then_branch: Block {
                statements: vec![Statement::Let {
                    mutable: false,
                    pat: Pattern::Name("x".to_owned()),
                    ty: Some(ty),
                    value: Expr::Bool(false),
                }],
                tail: None,
            },
            else_branch: None,
        }));
    }
    ty
}

#[test]
fn malformed_resolved_type_discards_a_deep_mixed_remainder_iteratively() {
    let source = SourceFile::new(SourceId(92), "untrusted-type.ko", "x");
    let map = AstSourceMap::new(source.id());
    let mut lowerer = HirLowerer::new(&source, &map, empty_targets(), BTreeMap::new(), &[]);
    let result = lowerer.wrap_type(
        TypeExpr::Resolved {
            id: HirId(900),
            source: Some(range(&map)),
            ty: Box::new(deep_untrusted_type()),
        },
        ScopeId(0),
    );
    assert_eq!(result, TypeExpr::Const(0));
    assert_eq!(lowerer.diagnostics.len(), 1);
    assert_eq!(
        lowerer.diagnostics[0].message,
        "resolved-HIR type wrapper was supplied as spanned AST input"
    );
    assert!(lowerer.arena.nodes.is_empty());
}

#[test]
fn malformed_resolved_expression_discards_a_deep_mixed_remainder_iteratively() {
    let source = SourceFile::new(SourceId(93), "untrusted-expression.ko", "x");
    let map = AstSourceMap::new(source.id());
    let mut lowerer = HirLowerer::new(&source, &map, empty_targets(), BTreeMap::new(), &[]);
    let TypeExpr::ConstExpression(expression) = deep_untrusted_type() else {
        panic!("mixed root")
    };
    let result = lowerer.wrap_expr(
        Expr::Resolved {
            id: HirId(901),
            source: Some(range(&map)),
            expression,
        },
        ScopeId(0),
        &BTreeMap::new(),
    );
    assert_eq!(result, Expr::IntLiteral(BigInt::zero()));
    assert_eq!(lowerer.diagnostics.len(), 1);
    assert_eq!(
        lowerer.diagnostics[0].message,
        "resolved-HIR expression wrapper was supplied as spanned AST input"
    );
    assert!(lowerer.arena.nodes.is_empty());
}

#[test]
fn malformed_resolved_statement_discards_a_deep_mixed_remainder_iteratively() {
    let source = SourceFile::new(SourceId(94), "untrusted-statement.ko", "x");
    let map = AstSourceMap::new(source.id());
    let mut lowerer = HirLowerer::new(&source, &map, empty_targets(), BTreeMap::new(), &[]);
    let mut block = Block {
        statements: vec![Statement::Resolved {
            id: HirId(902),
            source: Some(range(&map)),
            statement: Box::new(Statement::Let {
                mutable: false,
                pat: Pattern::Name("x".to_owned()),
                ty: Some(deep_untrusted_type()),
                value: Expr::Bool(false),
            }),
        }],
        tail: None,
    };
    let mut visible = BTreeMap::new();
    lowerer.wrap_block(&mut block, ScopeId(0), &mut visible);
    assert_eq!(block.statements, vec![Statement::Break]);
    assert!(visible.is_empty());
    assert_eq!(lowerer.diagnostics.len(), 1);
    assert_eq!(
        lowerer.diagnostics[0].message,
        "resolved-HIR statement wrapper was supplied as spanned AST input"
    );
    assert!(lowerer.arena.nodes.is_empty());
}
