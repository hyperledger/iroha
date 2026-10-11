//! Caller-stack lowering with one work list across every recursive AST owner.

use std::borrow::Cow;

use super::*;

/// A lexical environment is independent of the stable scope identity in HIR.
#[derive(Clone, Copy)]
struct LexicalContext {
    scope: ScopeId,
    environment: usize,
}

#[derive(Clone, Copy)]
struct NodeContext {
    id: HirId,
    source_node: Option<NodeId>,
    source: Option<SourceRange>,
}

type VisibleBindings = BTreeMap<String, BindingId>;

struct Environments<'a> {
    visible: Vec<Cow<'a, VisibleBindings>>,
}

impl Environments<'_> {
    fn get(&self, context: LexicalContext) -> &VisibleBindings {
        &self.visible[context.environment]
    }

    fn get_mut(&mut self, context: LexicalContext) -> &mut VisibleBindings {
        self.visible[context.environment].to_mut()
    }

    fn child(&mut self, lowerer: &mut HirLowerer<'_>, parent: LexicalContext) -> LexicalContext {
        let scope = lowerer.new_scope(parent.scope);
        let visible = self.get(parent).clone();
        self.push(scope, visible)
    }

    fn push(&mut self, scope: ScopeId, visible: VisibleBindings) -> LexicalContext {
        let environment = self.visible.len();
        self.visible.push(Cow::Owned(visible));
        LexicalContext { scope, environment }
    }

    fn release(&mut self, context: LexicalContext) {
        assert_eq!(context.environment + 1, self.visible.len());
        self.visible.pop();
    }
}

/// Children borrow disjoint AST slots; deferred effects never retain a parent
/// AST borrow. Installing its resolved shell on entry avoids a recursive
/// postorder reconstruction or an unsafe pointer to the parent.
enum Work<'tree> {
    Type(&'tree mut TypeExpr, ScopeId),
    Expression(&'tree mut Expr, LexicalContext),
    Statement(&'tree mut Statement, LexicalContext),
    Block(&'tree mut Block, LexicalContext),
    ChildBlock(&'tree mut Block, LexicalContext),
    EmptyExpression(&'tree mut Expr, ScopeId),
    Release(LexicalContext),
    DeclareLocal {
        pattern: &'tree Pattern,
        mutable: bool,
        lexical: LexicalContext,
        node: NodeContext,
    },
    Assignment {
        name: &'tree str,
        lexical: LexicalContext,
        node: NodeContext,
    },
    PatternBlock {
        pattern: &'tree SumPattern,
        block: &'tree mut Block,
        lexical: LexicalContext,
        node: NodeContext,
        ordinal: usize,
    },
    IteratorBlock {
        pattern: &'tree Pattern,
        block: &'tree mut Block,
        lexical: LexicalContext,
        node: NodeContext,
    },
}

impl HirLowerer<'_> {
    pub(super) fn wrap_type(&mut self, mut ty: TypeExpr, scope: ScopeId) -> TypeExpr {
        let mut environments = Environments {
            visible: Vec::new(),
        };
        self.lower_work(&mut environments, vec![Work::Type(&mut ty, scope)]);
        ty
    }

    pub(super) fn wrap_expr(
        &mut self,
        mut expression: Expr,
        scope: ScopeId,
        visible: &VisibleBindings,
    ) -> Expr {
        let mut environments = Environments {
            visible: vec![Cow::Borrowed(visible)],
        };
        self.lower_work(
            &mut environments,
            vec![Work::Expression(
                &mut expression,
                LexicalContext {
                    scope,
                    environment: 0,
                },
            )],
        );
        expression
    }

    pub(super) fn wrap_block(
        &mut self,
        block: &mut Block,
        scope: ScopeId,
        visible: &mut VisibleBindings,
    ) {
        let mut environments = Environments {
            visible: vec![Cow::Owned(std::mem::take(visible))],
        };
        self.lower_work(
            &mut environments,
            vec![Work::Block(
                block,
                LexicalContext {
                    scope,
                    environment: 0,
                },
            )],
        );
        *visible = environments
            .visible
            .pop()
            .expect("root lexical environment")
            .into_owned();
    }

    fn lower_work(&mut self, environments: &mut Environments<'_>, mut work: Vec<Work<'_>>) {
        while let Some(next) = work.pop() {
            match next {
                Work::Type(ty, scope) => self.lower_type(ty, scope, &mut work),
                Work::Expression(expression, lexical) => {
                    self.lower_expression(expression, lexical, environments, &mut work);
                }
                Work::Statement(statement, lexical) => {
                    self.lower_statement(statement, lexical, environments, &mut work);
                }
                Work::Block(block, lexical) => schedule_block(block, lexical, &mut work),
                Work::ChildBlock(block, parent) => {
                    let lexical = environments.child(self, parent);
                    work.push(Work::Release(lexical));
                    work.push(Work::Block(block, lexical));
                }
                Work::EmptyExpression(expression, scope) => {
                    let lexical = environments.push(scope, BTreeMap::new());
                    work.push(Work::Release(lexical));
                    work.push(Work::Expression(expression, lexical));
                }
                Work::Release(lexical) => environments.release(lexical),
                Work::DeclareLocal {
                    pattern,
                    mutable,
                    lexical,
                    node,
                } => {
                    self.node_mut(node.id).bindings = self.declare_pattern(
                        pattern,
                        lexical.scope,
                        environments.get_mut(lexical),
                        BindingProperties {
                            kind: ResolvedBindingKind::Local,
                            mutable,
                        },
                        node.source_node,
                        node.source,
                    );
                }
                Work::Assignment {
                    name,
                    lexical,
                    node,
                } => {
                    self.node_mut(node.id).target = self
                        .value_target(name, environments.get(lexical), node.source)
                        .map(ResolvedTarget::Assignment);
                }
                Work::PatternBlock {
                    pattern,
                    block,
                    lexical,
                    node,
                    ordinal,
                } => {
                    let child = environments.child(self, lexical);
                    let bindings = self.declare_sum_pattern(
                        pattern,
                        child.scope,
                        environments.get_mut(child),
                        node.source_node,
                        ordinal,
                        node.source,
                    );
                    self.node_mut(node.id).bindings.extend(bindings);
                    work.push(Work::Release(child));
                    work.push(Work::Block(block, child));
                }
                Work::IteratorBlock {
                    pattern,
                    block,
                    lexical,
                    node,
                } => {
                    let child = environments.child(self, lexical);
                    self.node_mut(node.id).bindings = self.declare_pattern(
                        pattern,
                        child.scope,
                        environments.get_mut(child),
                        BindingProperties {
                            kind: ResolvedBindingKind::Iterator,
                            mutable: false,
                        },
                        node.source_node,
                        node.source,
                    );
                    work.push(Work::Release(child));
                    work.push(Work::Block(block, child));
                }
            }
        }
    }

    fn lower_type<'tree>(
        &mut self,
        slot: &'tree mut TypeExpr,
        scope: ScopeId,
        work: &mut Vec<Work<'tree>>,
    ) {
        let current = std::mem::replace(slot, TypeExpr::Const(0));
        let Some((ty, node)) = self.enter_type(current, scope) else {
            return;
        };
        *slot = TypeExpr::Resolved {
            id: node.id,
            source: node.source,
            ty: Box::new(ty),
        };
        let TypeExpr::Resolved { ty, .. } = slot else {
            unreachable!("installed type shell")
        };
        match ty.as_mut() {
            TypeExpr::Path(name) => {
                self.node_mut(node.id).target = self
                    .type_target(name, node.source)
                    .map(ResolvedTarget::Type);
            }
            TypeExpr::Generic { base, args } => {
                self.node_mut(node.id).target = self
                    .type_target(base, node.source)
                    .map(ResolvedTarget::Type);
                work.extend(args.iter_mut().rev().map(|ty| Work::Type(ty, scope)));
            }
            TypeExpr::Tuple(elements) => {
                work.extend(elements.iter_mut().rev().map(|ty| Work::Type(ty, scope)));
            }
            TypeExpr::ConstExpression(expression) => {
                work.push(Work::EmptyExpression(expression, scope))
            }
            TypeExpr::Const(_) => {}
            TypeExpr::Source { .. } | TypeExpr::Resolved { .. } => {
                unreachable!("validated type shell")
            }
        }
    }

    fn lower_statement<'tree>(
        &mut self,
        slot: &'tree mut Statement,
        lexical: LexicalContext,
        environments: &mut Environments<'_>,
        work: &mut Vec<Work<'tree>>,
    ) {
        let current = std::mem::replace(slot, Statement::Break);
        let Some((statement, node)) = self.enter_statement(current, lexical.scope) else {
            return;
        };
        *slot = Statement::Resolved {
            id: node.id,
            source: node.source,
            statement: Box::new(statement),
        };
        let Statement::Resolved { statement, .. } = slot else {
            unreachable!("installed statement shell")
        };
        self.schedule_statement(statement, lexical, node, environments, work);
    }

    fn schedule_statement<'tree>(
        &mut self,
        statement: &'tree mut Statement,
        lexical: LexicalContext,
        node: NodeContext,
        environments: &mut Environments<'_>,
        work: &mut Vec<Work<'tree>>,
    ) {
        match statement {
            Statement::Let {
                mutable,
                pat,
                ty,
                value,
            } => {
                work.push(Work::DeclareLocal {
                    pattern: pat,
                    mutable: *mutable,
                    lexical,
                    node,
                });
                work.push(Work::Expression(value, lexical));
                if let Some(ty) = ty {
                    work.push(Work::Type(ty, lexical.scope));
                }
            }
            Statement::Assign { name, value } => {
                work.push(Work::Assignment {
                    name,
                    lexical,
                    node,
                });
                work.push(Work::Expression(value, lexical));
            }
            Statement::AssignExpr { target, value, .. } => {
                work.push(Work::Expression(value, lexical));
                work.push(Work::Expression(target, lexical));
            }
            Statement::Expr(expression)
            | Statement::Emit(expression)
            | Statement::Return(Some(expression)) => {
                work.push(Work::Expression(expression, lexical));
            }
            Statement::If {
                cond,
                then_branch,
                else_branch,
            } => {
                schedule_if(cond, then_branch, else_branch, lexical, work);
            }
            Statement::IfLet {
                pattern,
                value,
                then_branch,
                else_branch,
            } => {
                schedule_if_let(
                    pattern,
                    value,
                    then_branch,
                    else_branch,
                    lexical,
                    node,
                    work,
                );
            }
            Statement::While { cond, body } => {
                work.push(Work::ChildBlock(body, lexical));
                work.push(Work::Expression(cond, lexical));
            }
            Statement::For {
                init,
                cond,
                step,
                body,
                ..
            } => {
                let child = environments.child(self, lexical);
                work.push(Work::Release(child));
                work.push(Work::Block(body, child));
                if let Some(step) = step {
                    work.push(Work::Statement(step, child));
                }
                if let Some(cond) = cond {
                    work.push(Work::Expression(cond, child));
                }
                if let Some(init) = init {
                    work.push(Work::Statement(init, child));
                }
            }
            Statement::ForEachMap { pat, map, body } => {
                work.push(Work::IteratorBlock {
                    pattern: pat,
                    block: body,
                    lexical,
                    node,
                });
                work.push(Work::Expression(map, lexical));
            }
            Statement::Break | Statement::Continue | Statement::Return(None) => {}
            Statement::Source { .. } | Statement::Resolved { .. } => {
                unreachable!("validated statement shell")
            }
        }
    }

    fn lower_expression<'tree>(
        &mut self,
        slot: &'tree mut Expr,
        lexical: LexicalContext,
        environments: &mut Environments<'_>,
        work: &mut Vec<Work<'tree>>,
    ) {
        let current = std::mem::replace(slot, Expr::IntLiteral(BigInt::zero()));
        let Some((expression, node)) = self.enter_expression(current, lexical.scope) else {
            return;
        };
        *slot = Expr::Resolved {
            id: node.id,
            source: node.source,
            expression: Box::new(expression),
        };
        let Expr::Resolved { expression, .. } = slot else {
            unreachable!("installed expression shell")
        };
        let expression = expression.as_mut();
        self.resolve_expression_target(expression, lexical, node, environments);
        match expression {
            Expr::If {
                condition,
                then_branch,
                else_branch,
            } => {
                schedule_if(condition, then_branch, else_branch, lexical, work);
            }
            Expr::IfLet {
                pattern,
                value,
                then_branch,
                else_branch,
            } => {
                schedule_if_let(
                    pattern,
                    value,
                    then_branch,
                    else_branch,
                    lexical,
                    node,
                    work,
                );
            }
            Expr::Match { value, arms } => {
                let mut ordinal = arms
                    .iter()
                    .filter(|arm| matches!(&arm.pattern.binding, Some(PatternBinding::Name(_))))
                    .count();
                for arm in arms.iter_mut().rev() {
                    if matches!(&arm.pattern.binding, Some(PatternBinding::Name(_))) {
                        ordinal -= 1;
                    }
                    work.push(Work::PatternBlock {
                        pattern: &arm.pattern,
                        block: &mut arm.body,
                        lexical,
                        node,
                        ordinal,
                    });
                }
                work.push(Work::Expression(value, lexical));
            }
            Expr::ListComprehension {
                expression,
                item,
                source,
                condition,
            } => {
                let child = self.comprehension_context(item, lexical, node, environments);
                work.push(Work::Release(child));
                if let Some(condition) = condition {
                    work.push(Work::Expression(condition, child));
                }
                work.push(Work::Expression(source, lexical));
                work.push(Work::Expression(expression, child));
            }
            _ => schedule_expression_children(expression, lexical, work),
        }
    }

    fn comprehension_context(
        &mut self,
        item: &str,
        lexical: LexicalContext,
        node: NodeContext,
        environments: &mut Environments<'_>,
    ) -> LexicalContext {
        let child = environments.child(self, lexical);
        let (item_node, item_source) = self.consume_binding_fact(
            node.source_node,
            0,
            item,
            ResolvedBindingKind::Comprehension,
        );
        self.node_mut(node.id).bindings = vec![self.declare_binding(
            child.scope,
            environments.get_mut(child),
            item,
            BindingProperties {
                kind: ResolvedBindingKind::Comprehension,
                mutable: false,
            },
            item_node,
            item_source.or(node.source),
        )];
        child
    }

    fn resolve_expression_target(
        &mut self,
        expression: &Expr,
        lexical: LexicalContext,
        node: NodeContext,
        environments: &Environments<'_>,
    ) {
        match expression {
            Expr::Ident(name) => {
                self.node_mut(node.id).target = self
                    .value_target(name, environments.get(lexical), node.source)
                    .map(ResolvedTarget::Value);
            }
            Expr::Call {
                name,
                implicit_receiver,
                ..
            } => {
                self.node_mut(node.id).target = self
                    .call_target(name, *implicit_receiver, node.source)
                    .map(ResolvedTarget::Call);
            }
            Expr::StructLiteral { name, .. } => {
                self.node_mut(node.id).target = if let Some(symbol) = self.globals.structs.get(name)
                {
                    Some(ResolvedTarget::StructLiteral(*symbol))
                } else if self.globals.external_structs.contains(name)
                    || (self.globals.resolve_import_calls && explicit_import_call(name))
                {
                    Some(ResolvedTarget::ExternalStructLiteral)
                } else {
                    None
                };
                if self.node_mut(node.id).target.is_none() {
                    self.diagnostics.push(Diagnostic::error(
                        "K2002",
                        DiagnosticPhase::Resolve,
                        format!("unknown struct `{name}`"),
                        self.source_span(node.source),
                    ));
                }
            }
            _ => {}
        }
    }
}

fn schedule_block<'tree>(
    block: &'tree mut Block,
    lexical: LexicalContext,
    work: &mut Vec<Work<'tree>>,
) {
    if let Some(tail) = &mut block.tail {
        work.push(Work::Expression(tail, lexical));
    }
    work.extend(
        block
            .statements
            .iter_mut()
            .rev()
            .map(|statement| Work::Statement(statement, lexical)),
    );
}

fn schedule_if<'tree>(
    condition: &'tree mut Expr,
    then_branch: &'tree mut Block,
    else_branch: &'tree mut Option<Block>,
    lexical: LexicalContext,
    work: &mut Vec<Work<'tree>>,
) {
    if let Some(block) = else_branch {
        work.push(Work::ChildBlock(block, lexical));
    }
    work.push(Work::ChildBlock(then_branch, lexical));
    work.push(Work::Expression(condition, lexical));
}

fn schedule_if_let<'tree>(
    pattern: &'tree SumPattern,
    value: &'tree mut Expr,
    then_branch: &'tree mut Block,
    else_branch: &'tree mut Option<Block>,
    lexical: LexicalContext,
    node: NodeContext,
    work: &mut Vec<Work<'tree>>,
) {
    if let Some(block) = else_branch {
        work.push(Work::ChildBlock(block, lexical));
    }
    work.push(Work::PatternBlock {
        pattern,
        block: then_branch,
        lexical,
        node,
        ordinal: 0,
    });
    work.push(Work::Expression(value, lexical));
}

fn schedule_expression_children<'tree>(
    expression: &'tree mut Expr,
    lexical: LexicalContext,
    work: &mut Vec<Work<'tree>>,
) {
    match expression {
        Expr::Call { args, .. } | Expr::Tuple(args) | Expr::List(args) | Expr::JsonArray(args) => {
            work.extend(
                args.iter_mut()
                    .rev()
                    .map(|arg| Work::Expression(arg, lexical)),
            );
        }
        Expr::StructLiteral { fields, .. } | Expr::ArgumentRecord { fields } => {
            work.extend(
                fields
                    .iter_mut()
                    .rev()
                    .map(|field| Work::Expression(&mut field.value, lexical)),
            );
        }
        Expr::JsonObject(entries) => {
            work.extend(
                entries
                    .iter_mut()
                    .rev()
                    .map(|entry| Work::Expression(&mut entry.value, lexical)),
            );
        }
        Expr::Binary { left, right, .. }
        | Expr::Index {
            target: left,
            index: right,
        } => {
            work.push(Work::Expression(right, lexical));
            work.push(Work::Expression(left, lexical));
        }
        Expr::Unary { expr, .. }
        | Expr::Member { object: expr, .. }
        | Expr::OptionSome(expr)
        | Expr::ResultOk(expr)
        | Expr::ResultErr(expr)
        | Expr::Propagate(expr) => {
            work.push(Work::Expression(expr, lexical));
        }
        Expr::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            work.push(Work::Expression(else_expr, lexical));
            work.push(Work::Expression(then_expr, lexical));
            work.push(Work::Expression(cond, lexical));
        }
        Expr::Ident(_)
        | Expr::IntLiteral(_)
        | Expr::DecimalLiteral(_)
        | Expr::OptionNone
        | Expr::Bool(_)
        | Expr::String(_)
        | Expr::Bytes(_) => {}
        Expr::If { .. }
        | Expr::IfLet { .. }
        | Expr::Match { .. }
        | Expr::ListComprehension { .. }
        | Expr::Source { .. }
        | Expr::Resolved { .. } => unreachable!("expression has a dedicated scheduling owner"),
    }
}

impl HirLowerer<'_> {
    fn enter_type(&mut self, ty: TypeExpr, scope: ScopeId) -> Option<(TypeExpr, NodeContext)> {
        let mut ty = ty;
        let mut source_node = None;
        let mut source = None;
        while let TypeExpr::Source {
            node,
            source: range,
            ty: inner,
        } = ty
        {
            source = self.validate_source_node(node, range, &[AstNodeKind::Type]);
            source_node = Some(node);
            ty = *inner;
        }
        if let TypeExpr::Resolved { source, .. } = ty {
            self.diagnostics.push(Diagnostic::error(
                "K2099",
                DiagnosticPhase::Resolve,
                "resolved-HIR type wrapper was supplied as spanned AST input",
                self.source_span(source),
            ));
            crate::ast::drop_type_iterative(ty);
            return None;
        }
        if source_node.is_none() {
            self.diagnostics.push(Diagnostic::error(
                "K2099",
                DiagnosticPhase::Resolve,
                "spanned AST contains a type node without explicit Source(NodeId, range) provenance",
                None,
            ));
        }

        let id = self.alloc_node(ResolvedNodeKind::Type, scope, source_node, source);
        Some((
            ty,
            NodeContext {
                id,
                source_node,
                source,
            },
        ))
    }
    fn enter_statement(
        &mut self,
        statement: Statement,
        scope: ScopeId,
    ) -> Option<(Statement, NodeContext)> {
        let mut statement = statement;
        let mut source_node = None;
        let mut source = None;
        while let Statement::Source {
            node,
            source: range,
            statement: inner,
        } = statement
        {
            source = self.validate_source_node(node, range, &[AstNodeKind::Statement]);
            source_node = Some(node);
            statement = *inner;
        }
        if let Statement::Resolved { source, .. } = statement {
            self.diagnostics.push(Diagnostic::error(
                "K2099",
                DiagnosticPhase::Resolve,
                "resolved-HIR statement wrapper was supplied as spanned AST input",
                self.source_span(source),
            ));
            crate::ast::drop_block_iterative(Block {
                statements: vec![statement],
                tail: None,
            });
            return None;
        }
        if source_node.is_none() {
            self.diagnostics.push(Diagnostic::error(
                "K2099",
                DiagnosticPhase::Resolve,
                "spanned AST contains a statement without explicit Source(NodeId, range) provenance",
                None,
            ));
        }

        let id = self.alloc_node(ResolvedNodeKind::Statement, scope, source_node, source);
        Some((
            statement,
            NodeContext {
                id,
                source_node,
                source,
            },
        ))
    }
    fn enter_expression(
        &mut self,
        expression: Expr,
        scope: ScopeId,
    ) -> Option<(Expr, NodeContext)> {
        let mut expression = expression;
        let mut source_node = None;
        let mut source = None;
        while let Expr::Source {
            node,
            source: range,
            expression: inner,
        } = expression
        {
            source = self.validate_source_node(
                node,
                range,
                &[
                    AstNodeKind::Expression,
                    AstNodeKind::Call,
                    AstNodeKind::IndexExpression,
                    AstNodeKind::ListComprehension,
                    AstNodeKind::DecimalLiteral,
                ],
            );
            source_node = Some(node);
            expression = *inner;
        }
        if let Expr::Resolved { source, .. } = expression {
            self.diagnostics.push(Diagnostic::error(
                "K2099",
                DiagnosticPhase::Resolve,
                "resolved-HIR expression wrapper was supplied as spanned AST input",
                self.source_span(source),
            ));
            crate::ast::drop_expression_iterative(expression);
            return None;
        }
        if source_node.is_none() {
            self.diagnostics.push(Diagnostic::error(
                "K2099",
                DiagnosticPhase::Resolve,
                "spanned AST contains an expression without explicit Source(NodeId, range) provenance",
                None,
            ));
        }

        let id = self.alloc_node(ResolvedNodeKind::Expression, scope, source_node, source);
        Some((
            expression,
            NodeContext {
                id,
                source_node,
                source,
            },
        ))
    }
}
