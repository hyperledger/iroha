//! Source sites for function effects and calls, used by view-purity diagnostics.
//!
//! Typed function summaries record which effects a function performs and which
//! functions it calls. This module records *where*: the first statement that
//! performs a forbidden-in-view effect and the first statement that calls each
//! callee. Sites come from diagnostic-only typed-block provenance and never
//! affect typing, lowering, or artifacts.
use super::{
    ExprKind, FunctionEffects, FunctionKind, FunctionSummary, SemanticContext, SemanticError,
    SemanticFailure, SemanticFailures, TypedBlock, TypedExpr, TypedItem, TypedStatement,
    collect_calls_in_expr, collect_calls_in_statement, compute_transitive_effects,
    describe_view_violation, expr_effects, statement_effects,
};
use crate::semantic_diagnostics::SemanticDiagnostic;
use crate::source::SourceRange;
use indexmap::IndexSet;
use std::collections::{BTreeMap, HashMap, HashSet};

/// Where one function performs effects and calls other functions.
#[derive(Clone, Debug, Default)]
pub(super) struct EffectSites {
    /// First statement that performs a direct effect forbidden in a view.
    pub(super) effect: Option<SourceRange>,
    /// First statement that calls each user function.
    pub(super) calls: BTreeMap<String, SourceRange>,
}

/// Record effect and call sites for one typed function body.
pub(super) fn effect_sites(context: &SemanticContext, body: &TypedBlock) -> EffectSites {
    let mut sites = EffectSites {
        effect: first_effect_site(context, body),
        calls: BTreeMap::new(),
    };
    collect_call_sites(context, body, &mut sites.calls);
    sites
}

/// Find the innermost source-backed statement that performs a direct effect.
fn first_effect_site(context: &SemanticContext, block: &TypedBlock) -> Option<SourceRange> {
    for (index, statement) in block.statements.iter().enumerate() {
        if !statement_effects(context, statement).forbids_view() {
            continue;
        }
        return nested_effect_site(context, statement).or(block.statement_source(index));
    }
    block
        .tail
        .as_deref()
        .filter(|tail| expr_effects(context, tail).forbids_view())
        .and_then(|tail| nested_expression_effect_site(context, tail).or(block.tail_source()))
}

/// Descend into control-flow bodies when the guard itself is effect-free.
fn nested_effect_site(
    context: &SemanticContext,
    statement: &TypedStatement,
) -> Option<SourceRange> {
    let guarded = |guard: Option<&TypedExpr>, blocks: &[Option<&TypedBlock>]| {
        if guard.is_some_and(|guard| expr_effects(context, guard).forbids_view()) {
            return None;
        }
        blocks
            .iter()
            .flatten()
            .find_map(|block| first_effect_site(context, block))
    };
    match statement {
        TypedStatement::If {
            cond,
            then_branch,
            else_branch,
        } => guarded(Some(cond), &[Some(then_branch), else_branch.as_ref()]),
        TypedStatement::IfLet {
            value,
            then_branch,
            else_branch,
            ..
        } => guarded(Some(value), &[Some(then_branch), else_branch.as_ref()]),
        TypedStatement::While { cond, body } => guarded(Some(cond), &[Some(body)]),
        TypedStatement::For { cond, body, .. } => guarded(cond.as_ref(), &[Some(body)]),
        TypedStatement::ForEachMap { map, body, .. } => guarded(Some(map), &[Some(body)]),
        TypedStatement::Expr(expression) | TypedStatement::Return(Some(expression)) => {
            nested_expression_effect_site(context, expression)
        }
        _ => None,
    }
}

fn nested_expression_effect_site(
    context: &SemanticContext,
    expression: &TypedExpr,
) -> Option<SourceRange> {
    match expression.kind() {
        ExprKind::If {
            condition,
            then_branch,
            else_branch,
        } if !expr_effects(context, condition).forbids_view() => {
            first_effect_site(context, then_branch)
                .or_else(|| first_effect_site(context, else_branch))
        }
        ExprKind::Match { value, arms } if !expr_effects(context, value).forbids_view() => arms
            .iter()
            .find_map(|arm| first_effect_site(context, &arm.body)),
        _ => None,
    }
}

/// Record the first source-backed statement that calls each user function.
fn collect_call_sites(
    context: &SemanticContext,
    block: &TypedBlock,
    sites: &mut BTreeMap<String, SourceRange>,
) {
    fn record(
        sites: &mut BTreeMap<String, SourceRange>,
        calls: IndexSet<String>,
        source: Option<SourceRange>,
    ) {
        if let Some(source) = source {
            for callee in calls {
                sites.entry(callee).or_insert(source);
            }
        }
    }
    for (index, statement) in block.statements.iter().enumerate() {
        let source = block.statement_source(index);
        let mut guards = IndexSet::new();
        let nested: Vec<&TypedBlock> = match statement {
            TypedStatement::If {
                cond,
                then_branch,
                else_branch,
            } => {
                collect_calls_in_expr(context, cond, &mut guards);
                std::iter::once(then_branch).chain(else_branch).collect()
            }
            TypedStatement::IfLet {
                value,
                then_branch,
                else_branch,
                ..
            } => {
                collect_calls_in_expr(context, value, &mut guards);
                std::iter::once(then_branch).chain(else_branch).collect()
            }
            TypedStatement::While { cond, body } => {
                collect_calls_in_expr(context, cond, &mut guards);
                vec![body]
            }
            TypedStatement::ForEachMap { map, body, .. } => {
                collect_calls_in_expr(context, map, &mut guards);
                vec![body]
            }
            other => {
                collect_calls_in_statement(context, other, &mut guards);
                Vec::new()
            }
        };
        record(sites, guards, source);
        for nested in nested {
            collect_call_sites(context, nested, sites);
            // Calls inside nested blocks without provenance still map to the
            // enclosing statement.
            let mut unsited = IndexSet::new();
            super::collect_called_functions_into(context, nested, &mut unsited);
            unsited.retain(|callee| !sites.contains_key(callee));
            record(sites, unsited, source);
        }
    }
    if let Some(tail) = &block.tail {
        let mut calls = IndexSet::new();
        collect_calls_in_expr(context, tail, &mut calls);
        record(sites, calls, block.tail_source());
    }
}

/// Upper bound on view-policy findings reported for one program.
const MAX_VIEW_POLICY_FAILURES: usize = 32;

/// Shortest-first, deterministic call chain from a view to a function that
/// performs a forbidden effect directly.
fn view_violation_chain(
    root: &str,
    summaries: &HashMap<String, FunctionSummary>,
    effects: &HashMap<String, FunctionEffects>,
) -> Option<Vec<String>> {
    let mut visited = HashSet::new();
    let mut queue = std::collections::VecDeque::from([vec![root.to_owned()]]);
    while let Some(path) = queue.pop_front() {
        let name = path.last().expect("chains are never empty");
        if !visited.insert(name.clone()) {
            continue;
        }
        let summary = summaries.get(name)?;
        if summary.direct_effects.forbids_view() {
            return Some(path);
        }
        for callee in &summary.calls {
            if effects
                .get(callee)
                .copied()
                .is_some_and(FunctionEffects::forbids_view)
            {
                let mut next = path.clone();
                next.push(callee.clone());
                queue.push_back(next);
            }
        }
    }
    None
}

fn view_policy_help(view: &str, effect: &str) -> String {
    let kotoage = crate::glossary::by_spelling("kotoage").map_or_else(
        || "kotoage".to_owned(),
        crate::glossary::BrandedKeyword::label,
    );
    let what = match effect {
        "durable state mutation" => "writes durable state",
        "instruction emission" => "submits ledger instructions",
        _ => "performs host side effects",
    };
    format!(
        "A `view fn` is answered by a read-only query and cannot run code that {what}. \
         Declare `{view}` as a {kotoage} function with an explicit `authorize(...)` policy so it runs in an \
         authorized transaction, or move the effect out of the view's call graph."
    )
}

/// Collect every view-purity and kotoage-authorization violation, in item order.
pub(super) fn permission_failures(
    context: &SemanticContext,
    items: &[TypedItem],
) -> Vec<SemanticFailure> {
    let summaries = context.function_summaries.borrow().clone();
    let effects = compute_transitive_effects(&summaries);
    let mut failures = Vec::new();
    for func in items.iter().map(|item| match item {
        TypedItem::Function(func) => func,
    }) {
        if failures.len() >= MAX_VIEW_POLICY_FAILURES {
            break;
        }
        if func.modifiers.kind == FunctionKind::View
            && let Some(chain) = view_violation_chain(&func.name, &summaries, &effects)
        {
            let offender = chain.last().expect("chains are never empty");
            let effect_kind = summaries
                .get(offender)
                .map_or("host side effects", |summary| {
                    describe_view_violation(summary.direct_effects)
                });
            let message = if chain.len() == 1 {
                format!("view function `{}` cannot perform {effect_kind}", func.name)
            } else {
                format!(
                    "view function `{}` cannot call `{}` because `{offender}` performs {effect_kind}",
                    func.name, chain[1]
                )
            };
            let site_of = |name: &str| summaries.get(name).map(|summary| &summary.sites);
            let effect_site = site_of(offender).and_then(|sites| sites.effect);
            let primary = if chain.len() == 1 {
                effect_site
            } else {
                site_of(&func.name).and_then(|sites| sites.calls.get(&chain[1]).copied())
            };
            let name_source = func.name_source.or_else(|| {
                context
                    .declaration_diagnostic(&func.name)
                    .map(|d| d.primary)
            });
            let diagnostic = primary.or(name_source).map(|primary| {
                let mut diagnostic = SemanticDiagnostic::at(primary, None)
                    .with_help(view_policy_help(&func.name, effect_kind));
                if primary != name_source.unwrap_or(primary) {
                    diagnostic = diagnostic.with_label(
                        name_source,
                        format!("`{}` is declared as a view here", func.name),
                    );
                }
                for pair in chain.windows(2).skip(1) {
                    diagnostic = diagnostic.with_label(
                        site_of(&pair[0]).and_then(|sites| sites.calls.get(&pair[1]).copied()),
                        format!("`{}` calls `{}` here", pair[0], pair[1]),
                    );
                }
                if chain.len() > 1 {
                    diagnostic = diagnostic.with_label(
                        effect_site,
                        format!("`{offender}` performs {effect_kind} here"),
                    );
                }
                diagnostic
            });
            failures.push(SemanticFailure {
                error: SemanticError {
                    code: "K2004",
                    message,
                },
                location: Some(func.location),
                diagnostic,
            });
        }
        if matches!(
            func.modifiers.kind,
            FunctionKind::Kotoage | FunctionKind::View
        ) && func.modifiers.authorization.is_none()
        {
            failures.push(SemanticFailure {
                error: SemanticError {
                    code: "K2004",
                    message: format!(
                        "public function `{}` requires an explicit `authorize(...)` policy",
                        func.name
                    ),
                },
                location: Some(func.location),
                diagnostic: func
                    .name_source
                    .or_else(|| {
                        context
                            .declaration_diagnostic(&func.name)
                            .map(|d| d.primary)
                    })
                    .map(|primary| SemanticDiagnostic::at(primary, None)),
            });
        }
    }
    failures
}

/// Return every permission failure as one fail-closed collection.
pub(super) fn enforce_permission_requirements(
    context: &SemanticContext,
    items: &[TypedItem],
) -> Result<(), SemanticFailures> {
    let failures = permission_failures(context, items);
    if failures.is_empty() {
        Ok(())
    } else {
        Err(SemanticFailures { failures })
    }
}
