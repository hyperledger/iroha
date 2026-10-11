//! Exact shallow lowering parity against the frozen recursive implementation.
// The old traversal exists only in this test module. Production lowering must
// use its iterative owner; deep-stack tests never call this recursive oracle.
use super::*;
use crate::source::{FrontendBudget, SourceId};

struct RecursiveLowerer<'a> {
    source: &'a SourceFile,
    source_map: &'a AstSourceMap,
    globals: GlobalTargets,
    parameter_sources: BTreeMap<(String, usize), (NodeId, SourceRange)>,
    binding_facts: BTreeMap<NodeId, Vec<BindingFact>>,
    consumed_binding_facts: BTreeSet<(NodeId, u16)>,
    consumed_binding_name_nodes: BTreeSet<NodeId>,
    arena: ResolvedArena,
    diagnostics: Vec<Diagnostic>,
}
#[derive(Clone, Copy)]
struct BindingProperties {
    kind: ResolvedBindingKind,
    mutable: bool,
}
impl<'a> RecursiveLowerer<'a> {
    fn new(
        source: &'a SourceFile,
        source_map: &'a AstSourceMap,
        globals: GlobalTargets,
        parameter_sources: BTreeMap<(String, usize), (NodeId, SourceRange)>,
        binding_facts: &[BindingFact],
    ) -> Self {
        let mut facts_by_owner = BTreeMap::<NodeId, Vec<BindingFact>>::new();
        for fact in binding_facts {
            facts_by_owner
                .entry(fact.owner)
                .or_default()
                .push(fact.clone());
        }
        for facts in facts_by_owner.values_mut() {
            facts.sort_by_key(|fact| fact.ordinal);
        }
        Self {
            source,
            source_map,
            globals,
            parameter_sources,
            binding_facts: facts_by_owner,
            consumed_binding_facts: BTreeSet::new(),
            consumed_binding_name_nodes: BTreeSet::new(),
            arena: ResolvedArena {
                source: source.id(),
                nodes: Vec::new(),
                scopes: vec![ResolvedScope {
                    id: ScopeId(0),
                    parent: None,
                }],
                bindings: Vec::new(),
                symbols: Vec::new(),
            },
            diagnostics: Vec::new(),
        }
    }
    fn source_span(&self, source: Option<SourceRange>) -> Option<SourceSpan> {
        source
            .filter(|range| range.source == self.source.id())
            .map(|range| SourceSpan::from_range(self.source, range.range))
    }
    fn validate_source_node(
        &mut self,
        node: NodeId,
        source: SourceRange,
        kinds: &[AstNodeKind],
    ) -> Option<SourceRange> {
        let valid = source.source == self.source.id()
            && self
                .source_map
                .node(node)
                .is_some_and(|mapped| mapped.range == source.range && kinds.contains(&mapped.kind));
        if valid {
            Some(source)
        } else {
            self.diagnostics.push(Diagnostic::error(
                "K2099",
                DiagnosticPhase::Resolve,
                "source provenance NodeId/range/kind does not match the stable source arena",
                self.source_span(Some(source)),
            ));
            None
        }
    }
    fn new_scope(&mut self, parent: ScopeId) -> ScopeId {
        let id = ScopeId(u32::try_from(self.arena.scopes.len()).expect("scope budget fits u32"));
        self.arena.scopes.push(ResolvedScope {
            id,
            parent: Some(parent),
        });
        id
    }
    fn alloc_node(
        &mut self,
        kind: ResolvedNodeKind,
        scope: ScopeId,
        source_node: Option<NodeId>,
        source: Option<SourceRange>,
    ) -> HirId {
        let id = HirId(u32::try_from(self.arena.nodes.len()).expect("HIR node budget fits u32"));
        self.arena.nodes.push(ResolvedNode {
            id,
            scope,
            source,
            source_node,
            kind,
            target: None,
            bindings: Vec::new(),
        });
        id
    }
    fn node_mut(&mut self, id: HirId) -> &mut ResolvedNode {
        self.arena
            .nodes
            .get_mut(usize::try_from(id.0).expect("HIR id fits usize"))
            .expect("newly allocated HIR node exists")
    }
    fn binding_source_label(&self, binding: BindingId) -> Option<DiagnosticLabel> {
        self.arena
            .binding(binding)
            .and_then(|binding| binding.source)
            .and_then(|source| self.source_span(Some(source)))
            .map(|span| DiagnosticLabel {
                span,
                message: "previous binding is declared here".to_owned(),
            })
    }
    fn binding_fact_kind(kind: ResolvedBindingKind) -> Option<BindingFactKind> {
        match kind {
            ResolvedBindingKind::Parameter => None,
            ResolvedBindingKind::Local => Some(BindingFactKind::Local),
            ResolvedBindingKind::Pattern => Some(BindingFactKind::Pattern),
            ResolvedBindingKind::Iterator => Some(BindingFactKind::Iterator),
            ResolvedBindingKind::Comprehension => Some(BindingFactKind::Comprehension),
        }
    }
    fn consume_binding_fact(
        &mut self,
        owner: Option<NodeId>,
        ordinal: usize,
        name: &str,
        kind: ResolvedBindingKind,
    ) -> (Option<NodeId>, Option<SourceRange>) {
        let Some(owner) = owner else {
            self.diagnostics.push(Diagnostic::error(
                "K2099",
                DiagnosticPhase::Resolve,
                format!("binding `{name}` has no direct parser-owned source node"),
                None,
            ));
            return (None, None);
        };
        let ordinal = u16::try_from(ordinal).expect("one node's binding budget fits u16");
        let expected_kind = Self::binding_fact_kind(kind)
            .expect("only non-parameter bindings use parser binding facts");
        let matches = self
            .binding_facts
            .get(&owner)
            .into_iter()
            .flatten()
            .filter(|fact| fact.ordinal == ordinal)
            .cloned()
            .collect::<Vec<_>>();
        let owner_source = self.source_map.source_range(owner);
        let [fact] = matches.as_slice() else {
            self.diagnostics.push(Diagnostic::error(
                "K2099",
                DiagnosticPhase::Resolve,
                format!(
                    "binding `{name}` does not have exactly one parser fact for owner {:?} ordinal {ordinal}",
                    owner
                ),
                self.source_span(owner_source),
            ));
            return (None, None);
        };
        let owner_node = self.source_map.node(owner);
        let name_source = self.source_map.source_range(fact.name_node);
        let name_node = self.source_map.node(fact.name_node);
        let valid_owner_kind = owner_node.is_some_and(|node| match expected_kind {
            BindingFactKind::Local | BindingFactKind::Iterator => {
                node.kind == AstNodeKind::Statement
            }
            BindingFactKind::Pattern => {
                matches!(node.kind, AstNodeKind::Statement | AstNodeKind::Expression)
            }
            BindingFactKind::Comprehension => node.kind == AstNodeKind::ListComprehension,
        });
        let valid_name_node = name_node.is_some_and(|node| {
            node.kind == AstNodeKind::Name
                && !node.range.is_empty()
                && owner_node.is_some_and(|owner| owner.range.contains(node.range))
                && self.source.slice(node.range) == Some(fact.name.as_str())
        });
        if fact.owner != owner
            || fact.name != name
            || fact.kind != expected_kind
            || !valid_owner_kind
            || !valid_name_node
            || name_source.is_none()
        {
            self.diagnostics.push(Diagnostic::error(
                "K2099",
                DiagnosticPhase::Resolve,
                format!(
                    "binding fact for `{name}` has mismatched owner, ordinal, role, spelling, or name token"
                ),
                self.source_span(name_source.or(owner_source)),
            ));
            return (None, None);
        }
        if !self.consumed_binding_name_nodes.insert(fact.name_node) {
            self.diagnostics.push(Diagnostic::error(
                "K2099",
                DiagnosticPhase::Resolve,
                format!("binding fact for `{name}` reuses another binding's name token"),
                self.source_span(name_source),
            ));
            return (None, None);
        }
        if !self.consumed_binding_facts.insert((owner, ordinal)) {
            self.diagnostics.push(Diagnostic::error(
                "K2099",
                DiagnosticPhase::Resolve,
                format!("binding fact for `{name}` was consumed more than once"),
                self.source_span(name_source),
            ));
            return (None, None);
        }
        (Some(fact.name_node), name_source)
    }
    fn diagnose_unconsumed_binding_facts(&mut self) {
        for facts in self.binding_facts.values() {
            for fact in facts {
                if !self
                    .consumed_binding_facts
                    .contains(&(fact.owner, fact.ordinal))
                {
                    self.diagnostics.push(Diagnostic::error(
                        "K2099",
                        DiagnosticPhase::Resolve,
                        format!(
                            "parser binding fact for `{}` was not consumed by its direct HIR owner",
                            fact.name
                        ),
                        self.source_map.source_span(self.source, fact.name_node),
                    ));
                }
            }
        }
    }
    fn declare_binding(
        &mut self,
        scope: ScopeId,
        visible: &mut BTreeMap<String, BindingId>,
        name: &str,
        properties: BindingProperties,
        source_node: Option<NodeId>,
        source: Option<SourceRange>,
    ) -> BindingId {
        let id =
            BindingId(u32::try_from(self.arena.bindings.len()).expect("binding budget fits u32"));
        let reserved = kotodama_surface::source_policy::is_reserved_source_declaration(name, false);
        let previous = visible.get(name).copied();
        let global = self.globals.all.contains_key(name);
        if name == "_" {
            // A discard owns provenance but never enters the value namespace.
        } else {
            if reserved || previous.is_some() || global {
                let diagnostic = local_collision_diagnostic(
                    &self.globals,
                    self.source,
                    name,
                    properties.kind,
                    reserved,
                    previous.and_then(|previous| self.binding_source_label(previous)),
                    self.source_span(source),
                );
                self.diagnostics.push(diagnostic);
            }
            visible.insert(name.to_owned(), id);
        }
        self.arena.bindings.push(ResolvedBinding {
            id,
            scope,
            name: name.to_owned(),
            kind: properties.kind,
            source,
            source_node,
            mutable: properties.mutable,
        });
        id
    }
    fn value_target(
        &mut self,
        name: &str,
        visible: &BTreeMap<String, BindingId>,
        source: Option<SourceRange>,
    ) -> Option<ResolvedValueTarget> {
        let target = if let Some(binding) = visible.get(name) {
            Some(ResolvedValueTarget::Binding(*binding))
        } else if let Some(symbol) = self.globals.states.get(name) {
            Some(ResolvedValueTarget::State(*symbol))
        } else if let Some(symbol) = self.globals.consts.get(name) {
            Some(ResolvedValueTarget::Const(*symbol))
        } else if let Some(code) = self.globals.variant_codes.get(name) {
            Some(ResolvedValueTarget::VariantCode(*code))
        } else if kotodama_surface::source_policy::V1_ROUNDING_PATHS.contains(&name)
            || kotodama_surface::builtins::Builtin::nominal_value(name)
                .is_some_and(kotodama_surface::builtins::Builtin::is_nominal_path)
            || name == "null"
            || crate::testing::REJECTION_SELECTORS.contains(&name)
        {
            Some(ResolvedValueTarget::Intrinsic)
        } else if self.globals.external_states.contains(name) {
            Some(ResolvedValueTarget::ExternalState)
        } else if self.globals.external_consts.contains(name) {
            Some(ResolvedValueTarget::ExternalConst)
        } else if self.globals.resolve_import_calls
            && name.rsplit_once("::").is_some_and(|(namespace, variant)| {
                explicit_import_call(namespace) && !variant.is_empty()
            })
        {
            Some(ResolvedValueTarget::ImportedVariant)
        } else {
            self.globals
                .external_variant_codes
                .get(name)
                .map(|code| ResolvedValueTarget::VariantCode(*code))
        };
        if target.is_none() {
            let diagnostic =
                unknown_value_diagnostic(&self.globals, name, visible, self.source_span(source));
            self.diagnostics.push(diagnostic);
        }
        target
    }
    fn type_target(
        &mut self,
        name: &str,
        _source: Option<SourceRange>,
    ) -> Option<ResolvedTypeTarget> {
        if builtin_type(name) {
            Some(ResolvedTypeTarget::Builtin)
        } else if let Some(symbol) = self.globals.enums.get(name) {
            Some(ResolvedTypeTarget::Enum(*symbol))
        } else if self.globals.external_structs.contains(name) {
            Some(ResolvedTypeTarget::ExternalStruct)
        } else if self.globals.resolve_import_calls && explicit_import_call(name) {
            Some(ResolvedTypeTarget::ExternalType)
        } else {
            self.globals
                .structs
                .get(name)
                .copied()
                .map(ResolvedTypeTarget::Struct)
        }
    }
    fn call_target(
        &mut self,
        name: &str,
        implicit_receiver: bool,
        _source: Option<SourceRange>,
    ) -> Option<ResolvedCallTarget> {
        if implicit_receiver {
            Some(ResolvedCallTarget::Method)
        } else if let Some(symbol) = self.globals.functions.get(name) {
            Some(ResolvedCallTarget::Function(*symbol))
        } else if let Some(builtin) = Builtin::from_source_name(name) {
            Some(ResolvedCallTarget::Builtin(builtin))
        } else if let Some(symbol) = self.globals.structs.get(name) {
            Some(ResolvedCallTarget::Struct(*symbol))
        } else if intrinsic_call(name) {
            Some(ResolvedCallTarget::Intrinsic)
        } else if self.globals.external_functions.contains(name)
            || (self.globals.resolve_import_calls && explicit_import_call(name))
        {
            Some(ResolvedCallTarget::External)
        } else {
            None
        }
    }
    fn wrap_type(&mut self, ty: TypeExpr, scope: ScopeId) -> TypeExpr {
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
            return TypeExpr::Const(0);
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
        match &mut ty {
            TypeExpr::Path(name) => {
                self.node_mut(id).target = self.type_target(name, source).map(ResolvedTarget::Type);
            }
            TypeExpr::Generic { base, args } => {
                self.node_mut(id).target = self.type_target(base, source).map(ResolvedTarget::Type);
                for argument in args {
                    let current = std::mem::replace(argument, TypeExpr::Const(0));
                    *argument = self.wrap_type(current, scope);
                }
            }
            TypeExpr::Tuple(elements) => {
                for element in elements {
                    let current = std::mem::replace(element, TypeExpr::Const(0));
                    *element = self.wrap_type(current, scope);
                }
            }
            TypeExpr::Const(_) => {}
            TypeExpr::ConstExpression(expression) => {
                let current = std::mem::replace(expression.as_mut(), Expr::IntLiteral(0.into()));
                **expression = self.wrap_expr(current, scope, &BTreeMap::new());
            }
            TypeExpr::Source { .. } | TypeExpr::Resolved { .. } => {
                self.diagnostics.push(Diagnostic::error(
                    "K2099",
                    DiagnosticPhase::Resolve,
                    "source or resolved wrapper escaped the AST/HIR stage boundary",
                    self.source_span(source),
                ));
            }
        }
        TypeExpr::Resolved {
            id,
            source,
            ty: Box::new(ty),
        }
    }
    fn declare_pattern(
        &mut self,
        pattern: &Pattern,
        scope: ScopeId,
        visible: &mut BTreeMap<String, BindingId>,
        properties: BindingProperties,
        owner: Option<NodeId>,
        source: Option<SourceRange>,
    ) -> Vec<BindingId> {
        let names: Vec<&String> = match pattern {
            Pattern::Name(name) => vec![name],
            Pattern::Tuple(names) => names.iter().collect(),
            Pattern::Struct { fields, .. } => fields.iter().map(|field| &field.binding).collect(),
        };
        names
            .iter()
            .enumerate()
            .map(|(ordinal, name)| {
                let (name_node, name_source) =
                    self.consume_binding_fact(owner, ordinal, name, properties.kind);
                self.declare_binding(
                    scope,
                    visible,
                    name,
                    properties,
                    name_node,
                    name_source.or(source),
                )
            })
            .collect()
    }
    fn declare_sum_pattern(
        &mut self,
        pattern: &SumPattern,
        scope: ScopeId,
        visible: &mut BTreeMap<String, BindingId>,
        owner: Option<NodeId>,
        ordinal: usize,
        source: Option<SourceRange>,
    ) -> Vec<BindingId> {
        match &pattern.binding {
            Some(PatternBinding::Name(name)) => {
                let (name_node, name_source) =
                    self.consume_binding_fact(owner, ordinal, name, ResolvedBindingKind::Pattern);
                vec![self.declare_binding(
                    scope,
                    visible,
                    name,
                    BindingProperties {
                        kind: ResolvedBindingKind::Pattern,
                        mutable: false,
                    },
                    name_node,
                    name_source.or(source),
                )]
            }
            Some(PatternBinding::Wildcard) | None => Vec::new(),
        }
    }
    fn wrap_block(
        &mut self,
        block: &mut Block,
        scope: ScopeId,
        visible: &mut BTreeMap<String, BindingId>,
    ) {
        for statement in &mut block.statements {
            let current = std::mem::replace(statement, Statement::Break);
            *statement = self.wrap_statement(current, scope, visible);
        }
        if let Some(tail) = block.tail.take() {
            block.tail = Some(Box::new(self.wrap_expr(*tail, scope, visible)));
        }
    }
    fn wrap_child_block(
        &mut self,
        block: &mut Block,
        parent: ScopeId,
        visible: &BTreeMap<String, BindingId>,
    ) {
        let scope = self.new_scope(parent);
        let mut child_visible = visible.clone();
        self.wrap_block(block, scope, &mut child_visible);
    }
    fn wrap_statement(
        &mut self,
        statement: Statement,
        scope: ScopeId,
        visible: &mut BTreeMap<String, BindingId>,
    ) -> Statement {
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
            return Statement::Break;
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
        match &mut statement {
            Statement::Let {
                mutable,
                pat,
                ty,
                value,
            } => {
                if let Some(current) = ty.take() {
                    *ty = Some(self.wrap_type(current, scope));
                }
                let current = std::mem::replace(value, Expr::IntLiteral(BigInt::zero()));
                *value = self.wrap_expr(current, scope, visible);
                self.node_mut(id).bindings = self.declare_pattern(
                    pat,
                    scope,
                    visible,
                    BindingProperties {
                        kind: ResolvedBindingKind::Local,
                        mutable: *mutable,
                    },
                    source_node,
                    source,
                );
            }
            Statement::Assign { name, value } => {
                let current = std::mem::replace(value, Expr::IntLiteral(BigInt::zero()));
                *value = self.wrap_expr(current, scope, visible);
                self.node_mut(id).target = self
                    .value_target(name, visible, source)
                    .map(ResolvedTarget::Assignment);
            }
            Statement::AssignExpr { target, value, .. } => {
                let current = std::mem::replace(target, Expr::IntLiteral(BigInt::zero()));
                *target = self.wrap_expr(current, scope, visible);
                let current = std::mem::replace(value, Expr::IntLiteral(BigInt::zero()));
                *value = self.wrap_expr(current, scope, visible);
            }
            Statement::Expr(expression) | Statement::Emit(expression) => {
                let current = std::mem::replace(expression, Expr::IntLiteral(BigInt::zero()));
                *expression = self.wrap_expr(current, scope, visible);
            }
            Statement::Return(expression) => {
                if let Some(current) = expression.take() {
                    *expression = Some(self.wrap_expr(current, scope, visible));
                }
            }
            Statement::If {
                cond,
                then_branch,
                else_branch,
            } => {
                let current = std::mem::replace(cond, Expr::Bool(false));
                *cond = self.wrap_expr(current, scope, visible);
                self.wrap_child_block(then_branch, scope, visible);
                if let Some(block) = else_branch {
                    self.wrap_child_block(block, scope, visible);
                }
            }
            Statement::IfLet {
                pattern,
                value,
                then_branch,
                else_branch,
            } => {
                let current = std::mem::replace(value, Expr::Bool(false));
                *value = self.wrap_expr(current, scope, visible);
                let then_scope = self.new_scope(scope);
                let mut then_visible = visible.clone();
                self.node_mut(id).bindings = self.declare_sum_pattern(
                    pattern,
                    then_scope,
                    &mut then_visible,
                    source_node,
                    0,
                    source,
                );
                self.wrap_block(then_branch, then_scope, &mut then_visible);
                if let Some(block) = else_branch {
                    self.wrap_child_block(block, scope, visible);
                }
            }
            Statement::While { cond, body } => {
                let current = std::mem::replace(cond, Expr::Bool(false));
                *cond = self.wrap_expr(current, scope, visible);
                self.wrap_child_block(body, scope, visible);
            }
            Statement::For {
                init,
                cond,
                step,
                body,
                ..
            } => {
                let loop_scope = self.new_scope(scope);
                let mut loop_visible = visible.clone();
                if let Some(current) = init.take() {
                    *init = Some(Box::new(self.wrap_statement(
                        *current,
                        loop_scope,
                        &mut loop_visible,
                    )));
                }
                if let Some(current) = cond.take() {
                    *cond = Some(self.wrap_expr(current, loop_scope, &loop_visible));
                }
                if let Some(current) = step.take() {
                    *step = Some(Box::new(self.wrap_statement(
                        *current,
                        loop_scope,
                        &mut loop_visible,
                    )));
                }
                self.wrap_block(body, loop_scope, &mut loop_visible);
            }
            Statement::ForEachMap { pat, map, body } => {
                let current = std::mem::replace(map, Expr::Bool(false));
                *map = self.wrap_expr(current, scope, visible);
                let loop_scope = self.new_scope(scope);
                let mut loop_visible = visible.clone();
                let bindings = self.declare_pattern(
                    pat,
                    loop_scope,
                    &mut loop_visible,
                    BindingProperties {
                        kind: ResolvedBindingKind::Iterator,
                        mutable: false,
                    },
                    source_node,
                    source,
                );
                self.node_mut(id).bindings = bindings;
                self.wrap_block(body, loop_scope, &mut loop_visible);
            }
            Statement::Break | Statement::Continue => {}
            Statement::Source { .. } | Statement::Resolved { .. } => {
                self.diagnostics.push(Diagnostic::error(
                    "K2099",
                    DiagnosticPhase::Resolve,
                    "source or resolved wrapper escaped the AST/HIR stage boundary",
                    self.source_span(source),
                ));
            }
        }
        Statement::Resolved {
            id,
            source,
            statement: Box::new(statement),
        }
    }
    fn wrap_expr(
        &mut self,
        expression: Expr,
        scope: ScopeId,
        visible: &BTreeMap<String, BindingId>,
    ) -> Expr {
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
            return Expr::IntLiteral(BigInt::zero());
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
        match &mut expression {
            Expr::Ident(name) => {
                self.node_mut(id).target = self
                    .value_target(name, visible, source)
                    .map(ResolvedTarget::Value);
            }
            Expr::Call {
                name,
                args,
                implicit_receiver,
                ..
            } => {
                self.node_mut(id).target = self
                    .call_target(name, *implicit_receiver, source)
                    .map(ResolvedTarget::Call);
                for argument in args {
                    let current = std::mem::replace(argument, Expr::IntLiteral(BigInt::zero()));
                    *argument = self.wrap_expr(current, scope, visible);
                }
            }
            Expr::ArgumentRecord { fields } => {
                for field in fields {
                    let current =
                        std::mem::replace(&mut field.value, Expr::IntLiteral(BigInt::zero()));
                    field.value = self.wrap_expr(current, scope, visible);
                }
            }
            Expr::StructLiteral { name, fields } => {
                self.node_mut(id).target = if let Some(symbol) = self.globals.structs.get(name) {
                    Some(ResolvedTarget::StructLiteral(*symbol))
                } else if self.globals.external_structs.contains(name)
                    || (self.globals.resolve_import_calls && explicit_import_call(name))
                {
                    Some(ResolvedTarget::ExternalStructLiteral)
                } else {
                    None
                };
                if self.node_mut(id).target.is_none() {
                    self.diagnostics.push(Diagnostic::error(
                        "K2002",
                        DiagnosticPhase::Resolve,
                        format!("unknown struct `{name}`"),
                        self.source_span(source),
                    ));
                }
                for field in fields {
                    let current =
                        std::mem::replace(&mut field.value, Expr::IntLiteral(BigInt::zero()));
                    field.value = self.wrap_expr(current, scope, visible);
                }
            }
            Expr::Binary { left, right, .. }
            | Expr::Index {
                target: left,
                index: right,
            } => {
                let current = std::mem::replace(&mut **left, Expr::IntLiteral(BigInt::zero()));
                **left = self.wrap_expr(current, scope, visible);
                let current = std::mem::replace(&mut **right, Expr::IntLiteral(BigInt::zero()));
                **right = self.wrap_expr(current, scope, visible);
            }
            Expr::Unary { expr, .. }
            | Expr::Member { object: expr, .. }
            | Expr::OptionSome(expr)
            | Expr::ResultOk(expr)
            | Expr::ResultErr(expr)
            | Expr::Propagate(expr) => {
                let current = std::mem::replace(&mut **expr, Expr::IntLiteral(BigInt::zero()));
                **expr = self.wrap_expr(current, scope, visible);
            }
            Expr::Conditional {
                cond,
                then_expr,
                else_expr,
            } => {
                for child in [cond, then_expr, else_expr] {
                    let current = std::mem::replace(&mut **child, Expr::IntLiteral(BigInt::zero()));
                    **child = self.wrap_expr(current, scope, visible);
                }
            }
            Expr::If {
                condition,
                then_branch,
                else_branch,
            } => {
                let current = std::mem::replace(&mut **condition, Expr::Bool(false));
                **condition = self.wrap_expr(current, scope, visible);
                self.wrap_child_block(then_branch, scope, visible);
                if let Some(block) = else_branch {
                    self.wrap_child_block(block, scope, visible);
                }
            }
            Expr::IfLet {
                pattern,
                value,
                then_branch,
                else_branch,
            } => {
                let current = std::mem::replace(&mut **value, Expr::Bool(false));
                **value = self.wrap_expr(current, scope, visible);
                let then_scope = self.new_scope(scope);
                let mut then_visible = visible.clone();
                self.node_mut(id).bindings = self.declare_sum_pattern(
                    pattern,
                    then_scope,
                    &mut then_visible,
                    source_node,
                    0,
                    source,
                );
                self.wrap_block(then_branch, then_scope, &mut then_visible);
                if let Some(block) = else_branch {
                    self.wrap_child_block(block, scope, visible);
                }
            }
            Expr::Match { value, arms } => {
                let current = std::mem::replace(&mut **value, Expr::Bool(false));
                **value = self.wrap_expr(current, scope, visible);
                let mut bindings = Vec::new();
                let mut binding_ordinal = 0;
                for arm in arms {
                    let arm_scope = self.new_scope(scope);
                    let mut arm_visible = visible.clone();
                    let ordinal = binding_ordinal;
                    if matches!(&arm.pattern.binding, Some(PatternBinding::Name(_))) {
                        binding_ordinal += 1;
                    }
                    bindings.extend(self.declare_sum_pattern(
                        &arm.pattern,
                        arm_scope,
                        &mut arm_visible,
                        source_node,
                        ordinal,
                        source,
                    ));
                    self.wrap_block(&mut arm.body, arm_scope, &mut arm_visible);
                }
                self.node_mut(id).bindings = bindings;
            }
            Expr::Tuple(elements) | Expr::List(elements) | Expr::JsonArray(elements) => {
                for element in elements {
                    let current = std::mem::replace(element, Expr::IntLiteral(BigInt::zero()));
                    *element = self.wrap_expr(current, scope, visible);
                }
            }
            Expr::ListComprehension {
                expression: item_expression,
                item,
                source: list_source,
                condition,
            } => {
                let comprehension_scope = self.new_scope(scope);
                let mut comprehension_visible = visible.clone();
                let (item_node, item_source) = self.consume_binding_fact(
                    source_node,
                    0,
                    item,
                    ResolvedBindingKind::Comprehension,
                );
                self.node_mut(id).bindings = vec![self.declare_binding(
                    comprehension_scope,
                    &mut comprehension_visible,
                    item,
                    BindingProperties {
                        kind: ResolvedBindingKind::Comprehension,
                        mutable: false,
                    },
                    item_node,
                    item_source.or(source),
                )];
                let current =
                    std::mem::replace(&mut **item_expression, Expr::IntLiteral(BigInt::zero()));
                **item_expression =
                    self.wrap_expr(current, comprehension_scope, &comprehension_visible);
                let current =
                    std::mem::replace(&mut **list_source, Expr::IntLiteral(BigInt::zero()));
                **list_source = self.wrap_expr(current, scope, visible);
                if let Some(current) = condition.take() {
                    *condition = Some(Box::new(self.wrap_expr(
                        *current,
                        comprehension_scope,
                        &comprehension_visible,
                    )));
                }
            }
            Expr::JsonObject(entries) => {
                for entry in entries {
                    let current =
                        std::mem::replace(&mut entry.value, Expr::IntLiteral(BigInt::zero()));
                    entry.value = self.wrap_expr(current, scope, visible);
                }
            }
            Expr::IntLiteral(_)
            | Expr::DecimalLiteral(_)
            | Expr::OptionNone
            | Expr::Bool(_)
            | Expr::String(_)
            | Expr::Bytes(_) => {}
            Expr::Source { .. } | Expr::Resolved { .. } => {
                self.diagnostics.push(Diagnostic::error(
                    "K2099",
                    DiagnosticPhase::Resolve,
                    "source or resolved wrapper escaped the AST/HIR stage boundary",
                    self.source_span(source),
                ));
            }
        }
        Expr::Resolved {
            id,
            source,
            expression: Box::new(expression),
        }
    }
    fn lower_program(mut self, mut program: Program) -> (Program, ResolvedArena, Vec<Diagnostic>) {
        let root = ScopeId(0);
        let root_visible = BTreeMap::new();
        for item in &mut program.items {
            match item {
                Item::Function(function) => {
                    let scope = self.new_scope(root);
                    let mut visible = BTreeMap::new();
                    for (index, parameter) in function.params.iter().enumerate() {
                        let source = self
                            .parameter_sources
                            .get(&(function.name.clone(), index))
                            .copied();
                        let (source_node, source) = source
                            .map(|(node, range)| (Some(node), Some(range)))
                            .unwrap_or((None, None));
                        self.declare_binding(
                            scope,
                            &mut visible,
                            &parameter.name,
                            BindingProperties {
                                kind: ResolvedBindingKind::Parameter,
                                mutable: false,
                            },
                            source_node,
                            source,
                        );
                    }
                    for parameter in &mut function.params {
                        if let Some(current) = parameter.ty.take() {
                            parameter.ty = Some(self.wrap_type(current, scope));
                        }
                    }
                    if let Some(current) = function.ret_ty.take() {
                        function.ret_ty = Some(self.wrap_type(current, scope));
                    }
                    self.wrap_block(&mut function.body, scope, &mut visible);
                }
                Item::Struct(definition) | Item::Event(definition) => {
                    for (_, ty) in &mut definition.fields {
                        let current = std::mem::replace(ty, TypeExpr::Const(0));
                        *ty = self.wrap_type(current, root);
                    }
                }
                Item::Const(declaration) => {
                    if let Some(current) = declaration.ty.take() {
                        declaration.ty = Some(self.wrap_type(current, root));
                    }
                    let current =
                        std::mem::replace(&mut declaration.value, Expr::IntLiteral(BigInt::zero()));
                    declaration.value = self.wrap_expr(current, root, &root_visible);
                }
                Item::State(declaration) => {
                    let current = std::mem::replace(&mut declaration.ty, TypeExpr::Const(0));
                    declaration.ty = self.wrap_type(current, root);
                }
                Item::Trigger(declaration) => {
                    if let crate::ast::TriggerFilter::Time(
                        crate::ast::TriggerTimeFilter::Schedule {
                            start_ms,
                            period_ms,
                        },
                    ) = &mut declaration.filter
                    {
                        for expression in std::iter::once(start_ms).chain(period_ms) {
                            let expression = expression.as_mut();
                            let current =
                                std::mem::replace(expression, Expr::IntLiteral(BigInt::zero()));
                            *expression = self.wrap_expr(current, root, &root_visible);
                        }
                    }
                    for entry in &mut declaration.metadata {
                        let current =
                            std::mem::replace(&mut entry.value, Expr::IntLiteral(BigInt::zero()));
                        entry.value = self.wrap_expr(current, root, &root_visible);
                    }
                }
                Item::Enum(_) => {}
            }
        }
        for fixture in &mut program.fixtures {
            for action in &mut fixture.actions {
                for argument in &mut action.args {
                    let current = std::mem::replace(argument, Expr::IntLiteral(BigInt::zero()));
                    *argument = self.wrap_expr(current, root, &root_visible);
                }
            }
        }
        self.diagnose_unconsumed_binding_facts();
        (program, self.arena, self.diagnostics)
    }
}

fn targets(ast: &SpannedProgram) -> GlobalTargets {
    let mut targets = GlobalTargets {
        all: BTreeMap::new(),
        structs: BTreeMap::new(),
        enums: BTreeMap::new(),
        functions: BTreeMap::new(),
        states: BTreeMap::new(),
        consts: BTreeMap::new(),
        permissions: BTreeSet::new(),
        variant_codes: BTreeMap::new(),
        resolve_import_calls: true,
        external_functions: BTreeSet::from(["external_fn".to_owned()]),
        external_states: BTreeSet::from(["external_state".to_owned()]),
        external_structs: BTreeSet::from(["External".to_owned()]),
        external_consts: BTreeSet::from(["EXTERNAL_CONST".to_owned()]),
        external_variant_codes: BTreeMap::from([("ExternalError::No".to_owned(), 7)]),
        declarations: BTreeMap::new(),
    };
    for fact in &ast.facts.declarations {
        if fact.kind == DeclarationKind::Parameter {
            continue;
        }
        let id = symbol_id(targets.all.len());
        targets.all.insert(fact.name.clone(), id);
        let owner = match fact.kind {
            DeclarationKind::Function => Some(&mut targets.functions),
            DeclarationKind::Struct | DeclarationKind::Event => Some(&mut targets.structs),
            DeclarationKind::Enum => Some(&mut targets.enums),
            DeclarationKind::State => Some(&mut targets.states),
            DeclarationKind::Const => Some(&mut targets.consts),
            _ => None,
        };
        if let Some(owner) = owner {
            owner.insert(fact.name.clone(), id);
        }
    }
    targets
}

fn compare_lowering(name: &str, source: &SourceFile, ast: SpannedProgram) {
    let globals = targets(&ast);
    let mut parameters = BTreeMap::new();
    for function in ast
        .facts
        .declarations
        .iter()
        .filter(|f| f.kind == DeclarationKind::Function)
    {
        for (index, parameter) in ast
            .facts
            .declarations
            .iter()
            .filter(|f| f.kind == DeclarationKind::Parameter && f.owner == Some(function.node))
            .enumerate()
        {
            if let Some(range) = ast.facts.source_map.source_range(parameter.name_node) {
                parameters.insert((function.name.clone(), index), (parameter.name_node, range));
            }
        }
    }
    let expected = RecursiveLowerer::new(
        source,
        &ast.facts.source_map,
        globals.clone(),
        parameters.clone(),
        &ast.facts.bindings,
    )
    .lower_program(ast.program.clone());
    let actual = HirLowerer::new(
        source,
        &ast.facts.source_map,
        globals,
        parameters,
        &ast.facts.bindings,
    )
    .lower_program(ast.program);
    assert!(
        !actual.1.nodes.is_empty(),
        "{name}: fixture must exercise lowering"
    );
    assert_eq!(
        actual.0, expected.0,
        "{name}: exact AST/provenance/child order"
    );
    assert_eq!(
        actual.1, expected.1,
        "{name}: exact HIR IDs/scopes/bindings/targets"
    );
    assert_eq!(
        actual.2, expected.2,
        "{name}: exact diagnostic order and ranges"
    );
    crate::ast::drop_program_iterative(actual.0);
    crate::ast::drop_program_iterative(expected.0);
}

#[test]
fn parsed_fixtures_preserve_every_lowered_identity_and_scope_order() {
    let fixtures = [
        (
            "resolved/001.ko",
            include_str!("../../fixtures/koto_v1/resolved/001.ko"),
        ),
        (
            "resolved/002.ko",
            include_str!("../../fixtures/koto_v1/resolved/002.ko"),
        ),
        (
            "resolved/003.ko",
            include_str!("../../fixtures/koto_v1/resolved/003.ko"),
        ),
        (
            "resolved/004.ko",
            include_str!("../../fixtures/koto_v1/resolved/004.ko"),
        ),
        (
            "resolved/005.ko",
            include_str!("../../fixtures/koto_v1/resolved/005.ko"),
        ),
        (
            "resolved/006.ko",
            include_str!("../../fixtures/koto_v1/resolved/006.ko"),
        ),
        (
            "resolved/007.ko",
            include_str!("../../fixtures/koto_v1/resolved/007.ko"),
        ),
        (
            "resolved/008.ko",
            include_str!("../../fixtures/koto_v1/resolved/008.ko"),
        ),
        (
            "resolved/009.ko",
            include_str!("../../fixtures/koto_v1/resolved/009.ko"),
        ),
        (
            "resolved/010.ko",
            include_str!("../../fixtures/koto_v1/resolved/010.ko"),
        ),
        (
            "sugar_zero_cost/001.ko",
            include_str!("../../fixtures/koto_v1/sugar_zero_cost/001.ko"),
        ),
        (
            "sugar_zero_cost/002.ko",
            include_str!("../../fixtures/koto_v1/sugar_zero_cost/002.ko"),
        ),
        (
            "sugar_zero_cost/003.ko",
            include_str!("../../fixtures/koto_v1/sugar_zero_cost/003.ko"),
        ),
        (
            "sugar_zero_cost/004.ko",
            include_str!("../../fixtures/koto_v1/sugar_zero_cost/004.ko"),
        ),
        (
            "sugar_zero_cost/005.ko",
            include_str!("../../fixtures/koto_v1/sugar_zero_cost/005.ko"),
        ),
        (
            "sugar_zero_cost/006.ko",
            include_str!("../../fixtures/koto_v1/sugar_zero_cost/006.ko"),
        ),
        (
            "sugar_zero_cost/007.ko",
            include_str!("../../fixtures/koto_v1/sugar_zero_cost/007.ko"),
        ),
        (
            "sugar_zero_cost/008.ko",
            include_str!("../../fixtures/koto_v1/sugar_zero_cost/008.ko"),
        ),
        (
            "sugar_zero_cost/009.ko",
            include_str!("../../fixtures/koto_v1/sugar_zero_cost/009.ko"),
        ),
        (
            "sugar_zero_cost/010.ko",
            include_str!("../../fixtures/koto_v1/sugar_zero_cost/010.ko"),
        ),
        (
            "sugar_zero_cost/011.ko",
            include_str!("../../fixtures/koto_v1/sugar_zero_cost/011.ko"),
        ),
        (
            "sugar_zero_cost/012.ko",
            include_str!("../../fixtures/koto_v1/sugar_zero_cost/012.ko"),
        ),
        (
            "sugar_zero_cost/013.ko",
            include_str!("../../fixtures/koto_v1/sugar_zero_cost/013.ko"),
        ),
        (
            "sugar_zero_cost/014.ko",
            include_str!("../../fixtures/koto_v1/sugar_zero_cost/014.ko"),
        ),
        (
            "sugar_zero_cost/015.ko",
            include_str!("../../fixtures/koto_v1/sugar_zero_cost/015.ko"),
        ),
        (
            "sugar_zero_cost/016.ko",
            include_str!("../../fixtures/koto_v1/sugar_zero_cost/016.ko"),
        ),
        (
            "sugar_zero_cost/017.ko",
            include_str!("../../fixtures/koto_v1/sugar_zero_cost/017.ko"),
        ),
        (
            "sugar_zero_cost/018.ko",
            include_str!("../../fixtures/koto_v1/sugar_zero_cost/018.ko"),
        ),
    ];
    for (name, text) in fixtures {
        let source = SourceFile::new(SourceId(73), name, text);
        let (ast, _) =
            crate::parser::parse_source_spanned(&source, FrontendBudget::v1()).expect(name);
        compare_lowering(name, &source, ast);
    }
}

#[test]
fn mixed_type_capacities_and_local_binding_timing_match_the_oracle() {
    let source = SourceFile::new(
        SourceId(74),
        "mixed-lowering.ko",
        r#"
        seiyaku Mixed {
            fn helper(int argument) -> int {
                let int local = argument;
                let List<int, if true { let List<int, 2> inner = []; 3 } else { 4 }> nested = [];
                let int branch = if true { let int local = local; local } else { argument };
                for index in range(3) { local = local + index; }
                for step in range(1) { continue; break; }
                return local + branch;
            }
        }
    "#,
    );
    let (mut ast, _) = crate::parser::parse_source_spanned(&source, FrontendBudget::v1())
        .expect("mixed source parses");
    // While is an internal AST owner, not accepted V1 source syntax. Exercise
    // its exact fail-closed provenance diagnostics without inventing syntax.
    let Item::Function(function) = &mut ast.program.items[0] else {
        panic!("mixed helper function");
    };
    function.body.statements.push(Statement::While {
        cond: Expr::Bool(false),
        body: Block {
            statements: vec![Statement::Continue, Statement::Break],
            tail: None,
        },
    });
    compare_lowering("mixed capacities and declaration timing", &source, ast);
}

#[test]
fn corrupted_binding_facts_and_provenance_keep_diagnostic_identity() {
    let text = include_str!("../../fixtures/koto_v1/resolved/004.ko");
    let source = SourceFile::new(SourceId(75), "corrupted-lowering.ko", text);
    let (ast, _) = crate::parser::parse_source_spanned(&source, FrontendBudget::v1())
        .expect("corruption source parses");
    assert!(!ast.facts.bindings.is_empty());
    let mut duplicate = ast.clone();
    duplicate
        .facts
        .bindings
        .push(duplicate.facts.bindings[0].clone());
    compare_lowering("duplicate binding fact", &source, duplicate);
    let mut missing = ast.clone();
    missing.facts.bindings.remove(0);
    compare_lowering("missing binding fact", &source, missing);
    let mut renamed = ast.clone();
    renamed.facts.bindings[0].name.push_str("_forged");
    compare_lowering("wrong binding name", &source, renamed);
    let wrong_source = SourceFile::new(SourceId(76), "wrong-source.ko", text);
    compare_lowering("wrong source identity", &wrong_source, ast);
}
