//! Fail-closed declaration, type, and call resolution for spanned Kotodama AST.
use crate::{
    ast::{
        Block, Expr, FunctionKind, HirId, Item, Pattern, PatternBinding, Program, Statement,
        SumPattern, TypeExpr,
    },
    diagnostic::{Diagnostic, DiagnosticBundle, DiagnosticLabel, DiagnosticPhase, SourceSpan},
    source::{SourceFile, SourceRange, TextRange},
    spanned_ast::{
        AstFacts, AstNodeKind, AstSourceMap, BindingFact, BindingFactKind, DeclarationFact,
        DeclarationKind, NodeId, SpannedProgram, TypeUseFact,
    },
};
use iroha_primitives::bigint::BigInt;
use kotodama_surface::builtins::Builtin;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
/// Stable identity of one resolved source declaration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymbolId(u32);
/// Stable identity of a lexical scope in resolved HIR.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScopeId(u32);
/// Stable identity of a parameter or local binding in resolved HIR.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BindingId(u32);
/// Declaration role retained by the resolved symbol arena.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolvedSymbolKind {
    /// The single source unit.
    SourceUnit,
    /// A function or lifecycle declaration.
    Function,
    /// A user-defined struct.
    Struct,
    /// Contract-owned native event payload declaration.
    Event,
    /// A declared nominal enum namespace.
    Enum,
    /// A durable state declaration.
    State,
    /// A typed constant declaration.
    Const,
    /// A trigger declaration.
    Trigger,
    /// An explicitly declared authorization permission.
    Permission,
}
/// Resolved declaration retained before semantic typing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedSymbol {
    /// Stable symbol identity.
    pub id: SymbolId,
    /// Source node declaring the symbol.
    pub node: NodeId,
    /// Exact source range of the declared name.
    pub source: crate::source::SourceRange,
    /// Declared spelling.
    pub name: String,
    /// Declaration role.
    pub kind: ResolvedSymbolKind,
}
/// Lexical binding role retained before type checking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolvedBindingKind {
    /// Function parameter.
    Parameter,
    /// `let` or `var` declaration.
    Local,
    /// Sum-pattern payload declaration.
    Pattern,
    /// Bounded-loop iterator declaration.
    Iterator,
    /// List-comprehension item declaration.
    Comprehension,
}
/// One parameter or local declaration with a stable lexical identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedBinding {
    /// Stable binding identity.
    pub id: BindingId,
    /// Scope that owns the binding.
    pub scope: ScopeId,
    /// Source spelling.
    pub name: String,
    /// Binding role.
    pub kind: ResolvedBindingKind,
    /// Exact declaration range when source-backed.
    pub source: Option<SourceRange>,
    /// Exact parser-owned name token when source-backed.
    pub source_node: Option<NodeId>,
    /// Whether assignment is permitted.
    pub mutable: bool,
}
/// Target selected for one value-name use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolvedValueTarget {
    /// Parameter or local binding.
    Binding(BindingId),
    /// Durable state declaration.
    State(SymbolId),
    /// Source constant declaration.
    Const(SymbolId),
    /// Stable declared nominal variant code.
    VariantCode(u32),
    /// Three-segment variant path authenticated by the locked type import graph.
    ImportedVariant,
    /// Compiler-owned value such as a rounding mode or JSON null.
    Intrinsic,
    /// State supplied by an explicitly typed standalone-test target.
    ExternalState,
    /// Constant supplied by an explicitly typed standalone-test target.
    ExternalConst,
}
/// Target selected for one source type reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolvedTypeTarget {
    /// Compiler-owned scalar, aggregate, or Iroha boundary type.
    Builtin,
    /// User-defined struct declaration.
    Struct(SymbolId),
    /// Nominal payloadless enum declaration.
    Enum(SymbolId),
    /// Struct supplied by an explicitly typed standalone-test target.
    ExternalStruct,
    /// Two-segment type path authenticated by the locked package export graph.
    ExternalType,
}
/// One resolved named type use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedTypeUse {
    /// Exact source node of the type name.
    pub node: NodeId,
    /// Exact source range of the named type use.
    pub source: crate::source::SourceRange,
    /// Owning function declaration, when the use occurs in a function.
    pub owner: Option<NodeId>,
    /// Source spelling.
    pub name: String,
    /// Bound type declaration.
    pub target: ResolvedTypeTarget,
}
/// Target selected for one source call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolvedCallTarget {
    /// User-defined function declaration.
    Function(SymbolId),
    /// Canonical builtin registry entry.
    Builtin(Builtin),
    /// Receiver-typed method resolved during semantic typing.
    Method,
    /// Explicit compiler-owned numeric/sum intrinsic.
    Intrinsic,
    /// User-defined struct referenced with retired positional syntax.
    Struct(SymbolId),
    /// Explicit import-alias call whose export is bound by the typed linker.
    External,
}
/// Authoritative target attached to one resolved-HIR node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolvedTarget {
    /// Named type reference.
    Type(ResolvedTypeTarget),
    /// Function, builtin, intrinsic, or method call.
    Call(ResolvedCallTarget),
    /// Value-name use.
    Value(ResolvedValueTarget),
    /// Named struct literal.
    StructLiteral(SymbolId),
    /// Named struct literal supplied by an explicitly typed standalone-test target.
    ExternalStructLiteral,
    /// Simple named assignment target.
    Assignment(ResolvedValueTarget),
}
/// Coarse resolved-HIR node category.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolvedNodeKind {
    /// Type expression.
    Type,
    /// Statement.
    Statement,
    /// Expression.
    Expression,
}
/// One stable node in the native resolved-HIR arena.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedNode {
    /// Stable identity embedded in the resolved tree.
    pub id: HirId,
    /// Lexical scope containing the node.
    pub scope: ScopeId,
    /// Exact source range when source-backed.
    pub source: Option<SourceRange>,
    /// Stable CST/AST source identity when source-backed.
    pub source_node: Option<NodeId>,
    /// Node category.
    pub kind: ResolvedNodeKind,
    /// Named target, if this node performs name resolution.
    pub target: Option<ResolvedTarget>,
    /// Bindings declared by this node, in source order.
    pub bindings: Vec<BindingId>,
}
/// One lexical scope in resolved HIR.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedScope {
    /// Stable scope identity.
    pub id: ScopeId,
    /// Enclosing scope, absent for the source-unit root.
    pub parent: Option<ScopeId>,
}
/// Immutable resolver output consulted by semantic typing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedArena {
    source: crate::source::SourceId,
    nodes: Vec<ResolvedNode>,
    scopes: Vec<ResolvedScope>,
    bindings: Vec<ResolvedBinding>,
    symbols: Vec<ResolvedSymbol>,
}
impl ResolvedArena {
    pub(crate) const fn source(&self) -> crate::source::SourceId {
        self.source
    }
    pub(crate) fn node(&self, id: HirId) -> Option<&ResolvedNode> {
        self.nodes
            .get(usize::try_from(id.0).ok()?)
            .filter(|node| node.id == id)
    }
    pub(crate) fn binding(&self, id: BindingId) -> Option<&ResolvedBinding> {
        self.bindings
            .get(usize::try_from(id.0).ok()?)
            .filter(|binding| binding.id == id)
    }
    pub(crate) fn nodes(&self) -> impl ExactSizeIterator<Item = &ResolvedNode> {
        self.nodes.iter()
    }
    pub(crate) fn bindings(&self) -> impl ExactSizeIterator<Item = &ResolvedBinding> {
        self.bindings.iter()
    }
    pub(crate) fn symbol(&self, id: SymbolId) -> Option<&ResolvedSymbol> {
        self.symbols
            .get(usize::try_from(id.0).ok()?)
            .filter(|symbol| symbol.id == id)
    }
    pub(crate) fn binding_visible_at(&self, binding: BindingId, node: HirId) -> bool {
        let Some(binding) = self.binding(binding) else {
            return false;
        };
        let Some(node) = self.node(node) else {
            return false;
        };
        let mut scope = Some(node.scope);
        while let Some(current) = scope {
            if current == binding.scope {
                return true;
            }
            let Some(index) = usize::try_from(current.0).ok() else {
                return false;
            };
            scope = self
                .scopes
                .get(index)
                .filter(|entry| entry.id == current)
                .and_then(|entry| entry.parent);
        }
        false
    }
}
/// One resolved source call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedCall {
    /// Exact complete call node.
    pub node: NodeId,
    /// Exact call-name node.
    pub name_node: NodeId,
    /// Exact source range of the complete call expression.
    pub source: crate::source::SourceRange,
    /// Exact source range of the called name.
    pub name_source: crate::source::SourceRange,
    /// Exact source-order argument labels; positional arguments have no label range.
    pub argument_name_sources: Vec<Option<crate::source::SourceRange>>,
    /// Owning function declaration, when the call occurs in a function.
    pub owner: Option<NodeId>,
    /// Source spelling.
    pub name: String,
    /// Bound call target.
    pub target: ResolvedCallTarget,
}
/// Distinct resolved HIR consumed by canonical semantic typing.
#[derive(Clone, Debug, PartialEq)]
pub struct ResolvedProgram {
    program: Program,
    facts: AstFacts,
    source_file: SourceFile,
    symbols: Vec<ResolvedSymbol>,
    types: Vec<ResolvedTypeUse>,
    calls: Vec<ResolvedCall>,
    arena: Arc<ResolvedArena>,
    /// Independently resolved include files sharing this unit's declarations.
    included: Vec<ResolvedProgram>,
    /// Native root view before include assembly.
    original: Option<Box<ResolvedProgram>>,
}
impl ResolvedProgram {
    /// Return the source AST after fail-closed resolution.
    #[must_use]
    pub const fn program(&self) -> &Program {
        &self.program
    }
    /// Return the stable source-node arena.
    #[must_use]
    pub const fn source_map(&self) -> &AstSourceMap {
        &self.facts.source_map
    }
    /// Retain parser-owned source identities for compiler lint diagnostics.
    pub(crate) const fn lint_facts(&self) -> &AstFacts {
        &self.facts
    }
    /// Return the immutable target/scope/binding arena required by typing.
    pub(crate) fn arena(&self) -> Arc<ResolvedArena> {
        Arc::clone(&self.arena)
    }
    /// Original per-file resolver arenas of this complete source unit.
    pub(crate) fn arenas(&self) -> impl Iterator<Item = Arc<ResolvedArena>> {
        std::iter::once(Arc::clone(&self.arena))
            .chain(self.included.iter().map(|file| Arc::clone(&file.arena)))
    }
    /// Original immutable files of this complete source unit.
    pub(crate) fn source_files(&self) -> impl Iterator<Item = &SourceFile> {
        std::iter::once(&self.source_file).chain(self.included.iter().map(|file| &file.source_file))
    }
    /// Per-file resolver authorities, retaining each original fact and binding arena.
    pub(crate) fn source_programs(&self) -> impl Iterator<Item = &ResolvedProgram> {
        std::iter::once(self.original.as_deref().unwrap_or(self)).chain(self.included.iter())
    }
    /// Original per-file program, without declarations assembled from other files.
    pub(crate) fn source_program(
        &self,
        source: crate::source::SourceId,
    ) -> Option<&ResolvedProgram> {
        self.source_programs()
            .find(|file| file.source_file.id() == source)
    }
    /// Assemble resolved declarations without rewriting source text or local HIR identities.
    pub(crate) fn with_included_sources(
        mut self,
        included: Vec<ResolvedProgram>,
        order: &[(crate::source::SourceId, usize)],
    ) -> Self {
        self.original = Some(Box::new(self.clone()));
        let originals = std::iter::once(&self)
            .chain(included.iter())
            .map(|file| (file.source_file.id(), &file.program))
            .collect::<BTreeMap<_, _>>();
        self.program.items = order
            .iter()
            .map(|(source, index)| originals[source].items[*index].clone())
            .collect();
        for file in &included {
            self.program
                .permissions
                .extend(file.program.permissions.iter().cloned());
            self.program
                .exports
                .extend(file.program.exports.iter().cloned());
            self.program
                .directives
                .extend(file.program.directives.iter().cloned());
            self.program
                .fixtures
                .extend(file.program.fixtures.iter().cloned());
            self.symbols.extend(file.symbols.iter().cloned());
            self.types.extend(file.types.iter().cloned());
            self.calls.extend(file.calls.iter().cloned());
        }
        self.included = included;
        self
    }
    /// Return resolved declarations.
    pub fn symbols(&self) -> impl ExactSizeIterator<Item = &ResolvedSymbol> {
        self.symbols.iter()
    }
    /// Return resolved named type uses.
    pub fn types(&self) -> impl ExactSizeIterator<Item = &ResolvedTypeUse> {
        self.types.iter()
    }
    /// Return resolved source calls.
    pub fn calls(&self) -> impl ExactSizeIterator<Item = &ResolvedCall> {
        self.calls.iter()
    }
    /// Return the immutable source file that owns every resolver-produced range.
    pub(crate) const fn source_file(&self) -> &SourceFile {
        &self.source_file
    }
    /// Convert one resolver-owned source range into the canonical diagnostic span.
    pub(crate) fn source_span(&self, range: SourceRange) -> Option<SourceSpan> {
        self.source_files()
            .find(|file| file.id() == range.source)
            .map(|file| SourceSpan::from_range(file, range.range))
    }
    /// Return stable parameter/local bindings in resolver allocation order.
    pub fn bindings(&self) -> impl ExactSizeIterator<Item = &ResolvedBinding> {
        self.arena.bindings()
    }
    /// Return the exact declared parameter-name range for one source function.
    pub(crate) fn parameter_name_source(
        &self,
        function_name: &str,
        parameter_name: &str,
    ) -> Option<SourceRange> {
        let file = std::iter::once(self).chain(&self.included).find(|file| {
            file.facts
                .declarations
                .iter()
                .any(|fact| fact.kind == DeclarationKind::Function && fact.name == function_name)
        })?;
        let owner = file
            .facts
            .declarations
            .iter()
            .find(|fact| fact.kind == DeclarationKind::Function && fact.name == function_name)?
            .node;
        file.facts
            .declarations
            .iter()
            .find(|fact| {
                fact.kind == DeclarationKind::Parameter
                    && fact.owner == Some(owner)
                    && fact.name == parameter_name
            })
            .and_then(|fact| file.facts.source_map.source_range(fact.name_node))
    }
    /// Return the exact lifecycle-name range for the source `hajimari` declaration.
    pub(crate) fn hajimari_name_source(&self) -> Option<SourceRange> {
        let name = self.program.items.iter().find_map(|item| {
            let Item::Function(function) = item else {
                return None;
            };
            (function.modifiers.kind == FunctionKind::Hajimari).then_some(&function.name)
        })?;
        std::iter::once(self)
            .chain(&self.included)
            .find_map(|file| {
                file.facts
                    .declarations
                    .iter()
                    .find(|fact| fact.kind == DeclarationKind::Function && &fact.name == name)
                    .and_then(|fact| file.facts.source_map.source_range(fact.name_node))
            })
    }
    /// Return the exact `state` keyword range of the first scalar state declaration.
    pub(crate) fn first_scalar_state_keyword_source(&self) -> Option<SourceRange> {
        let name = self.program.items.iter().find_map(|item| {
            let Item::State(state) = item else {
                return None;
            };
            (!matches!(
                state.ty.kind(),
                TypeExpr::Generic { base, .. } if base == "StateMap"
            ))
            .then_some(&state.name)
        })?;
        let file = std::iter::once(self).chain(&self.included).find(|file| {
            file.facts
                .declarations
                .iter()
                .any(|fact| fact.kind == DeclarationKind::State && &fact.name == name)
        })?;
        let declaration = file
            .facts
            .declarations
            .iter()
            .find(|fact| fact.kind == DeclarationKind::State && &fact.name == name)?;
        let declaration = file.facts.source_map.source_range(declaration.node)?;
        let keyword_end = declaration.range.start.checked_add(5)?;
        let keyword = TextRange::new(declaration.range.start, keyword_end);
        (keyword.end <= declaration.range.end && file.source_file.slice(keyword) == Some("state"))
            .then_some(SourceRange::new(declaration.source, keyword))
    }
    pub(crate) fn into_program(self) -> Program {
        let mut program = self.program;
        crate::ast::strip_program_provenance(&mut program);
        program
    }
    pub(crate) fn attach_sources(&self, typed: &mut crate::semantic::TypedProgram) {
        for file in &self.included {
            file.attach_sources(typed);
        }
        typed
            .source_files
            .insert(self.source_map().source(), self.source_file.clone());
        for item in &mut typed.items {
            let crate::semantic::TypedItem::Function(function) = item;
            let Some(declaration) =
                self.facts.declarations.iter().find(|fact| {
                    fact.kind == DeclarationKind::Function && fact.name == function.name
                })
            else {
                continue;
            };
            let source_map = &self.facts.source_map;
            let Some(declaration_range) = source_map.source_range(declaration.node) else {
                continue;
            };
            let Some(name_range) = source_map.source_range(declaration.name_node) else {
                continue;
            };
            function.source = Some(declaration_range);
            function.name_source = Some(name_range);
        }
        for state in &mut typed.states {
            if let Some(source) = self
                .facts
                .declarations
                .iter()
                .find(|fact| fact.kind == DeclarationKind::State && fact.name == state.name)
                .and_then(|fact| self.facts.source_map.source_range(fact.node))
            {
                state.source = Some(source);
            }
        }
    }
    pub(crate) fn span_for_location(
        &self,
        source: &SourceFile,
        line: usize,
        column: usize,
    ) -> Option<SourceSpan> {
        self.facts
            .declarations
            .iter()
            .filter(|fact| {
                matches!(
                    fact.kind,
                    DeclarationKind::Function | DeclarationKind::Trigger
                )
            })
            .find_map(|fact| {
                let span = self.facts.source_map.source_span(source, fact.name_node)?;
                (span.start.line == line && span.start.column == column).then_some(span)
            })
    }
}
fn symbol_id(index: usize) -> SymbolId {
    SymbolId(u32::try_from(index).expect("symbol budget fits u32"))
}
fn symbol_kind(kind: DeclarationKind) -> Option<ResolvedSymbolKind> {
    Some(match kind {
        DeclarationKind::SourceUnit => ResolvedSymbolKind::SourceUnit,
        DeclarationKind::Function => ResolvedSymbolKind::Function,
        DeclarationKind::Struct => ResolvedSymbolKind::Struct,
        DeclarationKind::Event => ResolvedSymbolKind::Event,
        DeclarationKind::Enum => ResolvedSymbolKind::Enum,
        DeclarationKind::State => ResolvedSymbolKind::State,
        DeclarationKind::Const => ResolvedSymbolKind::Const,
        DeclarationKind::Trigger => ResolvedSymbolKind::Trigger,
        DeclarationKind::Permission => ResolvedSymbolKind::Permission,
        DeclarationKind::Parameter => return None,
    })
}
fn declaration_span(
    ast: &SpannedProgram,
    source: &SourceFile,
    fact: &DeclarationFact,
) -> Option<SourceSpan> {
    ast.facts.source_map.source_span(source, fact.name_node)
}
fn duplicate_diagnostic(
    ast: &SpannedProgram,
    source: &SourceFile,
    current: &DeclarationFact,
    previous: &DeclarationFact,
) -> Diagnostic {
    let mut diagnostic = Diagnostic::error(
        "E_DUPLICATE_DECLARATION",
        DiagnosticPhase::Resolve,
        format!(
            "declaration name `{}` is already used by a {}",
            current.name,
            previous.kind.description()
        ),
        declaration_span(ast, source, current),
    );
    if let Some(span) = declaration_span(ast, source, previous) {
        diagnostic.labels.push(DiagnosticLabel {
            span,
            message: "first declaration is here".to_owned(),
        });
    }
    diagnostic
}
fn builtin_type(name: &str) -> bool {
    kotodama_surface::source_policy::V1_SOURCE_TYPE_NAMES.contains(&name)
}
fn explicit_import_call(name: &str) -> bool {
    name.split_once("::").is_some_and(|(alias, symbol)| {
        !alias.is_empty() && symbol.split("::").all(|part| !part.is_empty())
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ast::{Expr, Item, Statement},
        source::{FrontendBudget, SourceId},
        spanned_ast::AstNodeKind,
    };
    #[test]
    fn declared_helper_names_resolve_before_retired_builtin_guidance() {
        for name in ["get_int", "expect", "is_some", "min", "authority"] {
            let text = format!(
                "module Calls {{ fn {name}(int value) -> int {{ value }} fn use_name() -> int {{ {name}(3) }} }}"
            );
            let source = SourceFile::new(SourceId(90), "calls.ko", text);
            let (ast, _) = crate::parser::parse_source_spanned(&source, FrontendBudget::v1())
                .expect("declared helper source parses");
            resolve(ast, &source).unwrap_or_else(|diagnostics| panic!("{name}: {diagnostics:?}"));
        }
        let (source, diagnostics) = resolve_text(
            "missing.ko",
            "module Missing { fn call() { get_int(1); } }",
            false,
        );
        assert_eq!(diagnostics.diagnostics.len(), 1, "{diagnostics:?}");
        assert_eq!(diagnostics.diagnostics[0].code, "K2002");
        assert_eq!(diagnostics.diagnostics[0].phase, DiagnosticPhase::Resolve);
        assert!(
            diagnostics.diagnostics[0]
                .message
                .contains("json.get_int(key)")
        );
        assert_eq!(primary_spellings(&source, &diagnostics), ["get_int"]);
    }
    fn primary_spellings(source: &SourceFile, diagnostics: &DiagnosticBundle) -> Vec<String> {
        diagnostics
            .diagnostics
            .iter()
            .filter_map(|diagnostic| diagnostic.primary_span.as_ref())
            .filter_map(|span| span.byte_range)
            .map(|range| {
                assert!(
                    !range.is_empty(),
                    "resolver spans must never be fabricated empties"
                );
                source
                    .slice(range)
                    .expect("diagnostic range belongs to its source")
                    .to_owned()
            })
            .collect()
    }
    fn resolve_text(name: &str, text: &str, imports: bool) -> (SourceFile, DiagnosticBundle) {
        let source = SourceFile::new(SourceId(91), name, text);
        let (ast, _) = crate::parser::parse_source_spanned(&source, FrontendBudget::v1())
            .expect("probe parses");
        let diagnostics = if imports {
            resolve_with_imports(ast, &source, &BTreeMap::new())
        } else {
            resolve(ast, &source)
        }
        .expect_err("probe must fail resolution");
        (source, diagnostics)
    }
    #[test]
    fn builtin_roots_resolve_before_import_aliases() {
        for imports in [false, true] {
            let (source, diagnostics) = resolve_text(
                "builtin.ko",
                "seiyaku B { view fn who() authorize(anyone) -> AccountId { return context::caller(); } }",
                imports,
            );
            let diagnostic = &diagnostics.diagnostics[0];
            assert_eq!(diagnostic.code, "E_UNKNOWN_BUILTIN");
            assert_eq!(diagnostic.message, "unknown builtin `context::caller`");
            assert_eq!(
                diagnostic.help.as_deref(),
                Some("did you mean `context::authority`?")
            );
            assert_eq!(
                diagnostic.fix.as_ref().map(|fix| fix.replacement.as_str()),
                Some("context::authority")
            );
            assert_eq!(
                primary_spellings(&source, &diagnostics),
                ["context::caller"]
            );
        }
        let (_, retired) = resolve_text(
            "retired.ko",
            "seiyaku R { view fn which() authorize(anyone) -> Name { return context::entrypoint(); } }",
            true,
        );
        let help = retired.diagnostics[0]
            .help
            .as_deref()
            .expect("retired help");
        assert!(help.contains("context::kotoage"), "{help}");
        assert!(help.contains("言挙げ"), "{help}");
    }
    #[test]
    fn unknown_names_suggest_the_closest_declared_spelling() {
        let (_, local) = resolve_text(
            "local.ko",
            "seiyaku L { fn f(int total) -> int { return totl; } }",
            false,
        );
        assert_eq!(local.diagnostics[0].code, "K2002");
        assert_eq!(
            local.diagnostics[0].help.as_deref(),
            Some("did you mean `total`?")
        );
        let (_, variant) = resolve_text(
            "variant.ko",
            "seiyaku V { error enum VaultError { ZeroDeposit = 1 } fn f() { require(true, VaultError::ZeroDepsit); } }",
            false,
        );
        assert_eq!(variant.diagnostics[0].code, "E_UNKNOWN_ENUM_VARIANT");
        assert_eq!(
            variant.diagnostics[0].message,
            "enum `VaultError` has no variant `ZeroDepsit`"
        );
        assert_eq!(
            variant.diagnostics[0]
                .fix
                .as_ref()
                .map(|fix| fix.replacement.as_str()),
            Some("VaultError::ZeroDeposit")
        );
        let (_, ty) = resolve_text(
            "type.ko",
            "seiyaku T { struct Position { int x } fn f() { let Positon p = Position { x: 1 }; } }",
            false,
        );
        assert_eq!(
            ty.diagnostics[0].help.as_deref(),
            Some("did you mean `Position`?")
        );
    }
    #[test]
    fn shadowing_names_the_declaration_as_spelled_without_cascading() {
        let text = "誓約 Stake { permission Staker; \n    言挙げ fn stake(quantity value) authorize(Staker) {\n        let _ = value;\n    }\n    view fn quote(quantity stake) authorize(anyone) -> quantity {\n        return stake + stake;\n    }\n}";
        let (source, diagnostics) = resolve_text("stake.ko", text, false);
        assert_eq!(diagnostics.diagnostics.len(), 1, "{diagnostics:?}");
        let diagnostic = &diagnostics.diagnostics[0];
        assert_eq!(diagnostic.code, "E_LOCAL_SHADOWING");
        assert_eq!(
            diagnostic.message,
            "local binding `stake` shadows 言挙げ `stake`"
        );
        assert_eq!(primary_spellings(&source, &diagnostics), ["stake"]);
        assert_eq!(diagnostic.labels.len(), 1);
        assert_eq!(
            diagnostic.labels[0].message,
            "言挙げ `stake` is declared here"
        );
        assert_eq!(diagnostic.labels[0].span.start.line, 2);
    }
    #[test]
    fn declaration_keywords_echo_the_written_spelling() {
        assert_eq!(
            declaration_keyword(
                DeclarationKind::Function,
                Some("kotoage fn f() authorize(anyone) {}")
            ),
            "kotoage"
        );
        assert_eq!(
            declaration_keyword(
                DeclarationKind::Function,
                Some("言挙げ fn f() authorize(anyone) {}")
            ),
            "言挙げ"
        );
        assert_eq!(
            declaration_keyword(
                DeclarationKind::Function,
                Some("view fn f() authorize(anyone) {}")
            ),
            "view fn"
        );
        assert_eq!(
            declaration_keyword(DeclarationKind::Function, Some("改善() {}")),
            "改善"
        );
        assert_eq!(declaration_keyword(DeclarationKind::Const, None), "const");
    }
    #[test]
    fn recovering_resolution_empties_only_failing_bodies() {
        let recover = |text: &str| {
            let source = SourceFile::new(SourceId(92), "recover.ko", text);
            let (ast, _) = crate::parser::parse_source_spanned(&source, FrontendBudget::v1())
                .expect("probe parses");
            *resolve_recovering(ast, &source)
                .map(|_| ())
                .expect_err("probe must fail resolution")
        };
        let inside = recover(
            "seiyaku R { fn bad() -> int { return missing; } fn good() -> int { return 1; } }",
        );
        assert_eq!(inside.diagnostics.diagnostics[0].code, "K2002");
        assert!(inside.reduced.is_some());
        assert_eq!(inside.emptied, BTreeSet::from(["bad".to_owned()]));
        // A failure outside every body (here a state type) leaves nothing to
        // recover; the original diagnostics are still returned.
        let outside = recover("seiyaku R { state Missing value; fn good() -> int { return 1; } }");
        assert_eq!(outside.diagnostics.diagnostics[0].code, "K2002");
        assert!(outside.reduced.is_none());
        assert!(outside.emptied.is_empty());
    }
    #[test]
    fn import_call_shape_accepts_nonempty_qualified_identifier_paths() {
        for accepted in ["math::add", "math_v1::add_2", "math::nested::add"] {
            assert!(explicit_import_call(accepted), "{accepted}");
        }
        for rejected in ["add", "math::", "::add", "math::::add", "math::nested::"] {
            assert!(!explicit_import_call(rejected), "{rejected}");
        }
    }
    #[test]
    fn identical_spellings_keep_distinct_cst_ranges() {
        let text = include_str!("../fixtures/koto_v1/resolved/001.ko");
        let source = SourceFile::new(SourceId(37), "same_tokens.ko", text);
        let (ast, _) = crate::parser::parse_source_spanned(&source, FrontendBudget::v1())
            .expect("the adversarial source is syntactically valid");
        assert_eq!(ast.facts.source_map.source(), SourceId(37));
        let diagnostics = resolve(ast, &source).expect_err("resolution must fail closed");
        assert_eq!(
            primary_spellings(&source, &diagnostics),
            [
                "Missing", "Missing", "Missing", "first", "absent", "absent", "repeated"
            ]
        );
        let missing_ranges = diagnostics
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.message == "unknown type `Missing`")
            .map(|diagnostic| {
                diagnostic
                    .primary_span
                    .as_ref()
                    .and_then(|span| span.byte_range)
                    .expect("unknown type has an exact range")
            })
            .collect::<Vec<_>>();
        assert_eq!(missing_ranges.len(), 3);
        assert!(
            missing_ranges
                .windows(2)
                .all(|ranges| ranges[0] < ranges[1])
        );
        let absent_ranges = diagnostics
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.message.contains("`absent`"))
            .map(|diagnostic| {
                diagnostic
                    .primary_span
                    .as_ref()
                    .and_then(|span| span.byte_range)
                    .expect("unknown call has an exact range")
            })
            .collect::<Vec<_>>();
        assert_eq!(absent_ranges.len(), 2);
        assert_ne!(absent_ranges[0], absent_ranges[1]);
    }
    #[test]
    fn diagnostic_targets_bind_to_exact_nested_source_nodes() {
        let text = include_str!("../fixtures/koto_v1/resolved/002.ko");
        let source = SourceFile::new(SourceId(41), "origins.ko", text);
        let (ast, _) = crate::parser::parse_source_spanned(&source, FrontendBudget::v1())
            .expect("diagnostic-target source parses");
        let Item::Function(function) = &ast.program.items[0] else {
            panic!("function item")
        };
        let Statement::AssignExpr { target, .. } = function.body.statements[0].kind() else {
            panic!("indexed assignment")
        };
        let outer_id = target.source_node().expect("outer index source identity");
        let outer_node = ast
            .facts
            .source_map
            .node(outer_id)
            .expect("outer index node");
        assert_eq!(outer_node.kind, AstNodeKind::IndexExpression);
        assert_eq!(source.slice(outer_node.range), Some("values[outer][inner]"));
        let Expr::Index {
            target: inner_target,
            ..
        } = target.kind()
        else {
            panic!("outer index expression")
        };
        let inner_id = inner_target
            .source_node()
            .expect("inner lvalue index source identity");
        let inner_node = ast
            .facts
            .source_map
            .node(inner_id)
            .expect("inner index node");
        assert_eq!(inner_node.kind, AstNodeKind::IndexExpression);
        assert_eq!(source.slice(inner_node.range), Some("values[outer]"));
        let Expr::Index {
            target: receiver, ..
        } = inner_target.kind()
        else {
            panic!("inner index expression")
        };
        let receiver_id = receiver
            .source_node()
            .expect("exact lvalue receiver source identity");
        let receiver_node = ast
            .facts
            .source_map
            .node(receiver_id)
            .expect("lvalue receiver node");
        assert_eq!(source.slice(receiver_node.range), Some("values"));
        let Statement::Let {
            value: read_index, ..
        } = function.body.statements[1].kind()
        else {
            panic!("read index binding")
        };
        let Expr::Index {
            target: read_receiver,
            ..
        } = read_index.kind()
        else {
            panic!("read index expression")
        };
        let read_index_node = ast
            .facts
            .source_map
            .node(
                read_index
                    .source_node()
                    .expect("read index source identity"),
            )
            .expect("read index node");
        assert_eq!(source.slice(read_index_node.range), Some("values[inner]"));
        let read_receiver_node = ast
            .facts
            .source_map
            .node(
                read_receiver
                    .source_node()
                    .expect("read receiver source identity"),
            )
            .expect("read receiver node");
        assert_eq!(source.slice(read_receiver_node.range), Some("values"));
        let Statement::Let { value: amount, .. } = function.body.statements[2].kind() else {
            panic!("quantity binding")
        };
        let amount_id = amount
            .source_node()
            .expect("quantity literal source identity");
        let amount_node = ast.facts.source_map.node(amount_id).expect("quantity node");
        assert_eq!(amount_node.kind, AstNodeKind::DecimalLiteral);
        assert_eq!(source.slice(amount_node.range), Some("1.250_0"));
        let Statement::Let {
            value: comprehension,
            ..
        } = function.body.statements[3].kind()
        else {
            panic!("comprehension binding")
        };
        let comprehension_id = comprehension
            .source_node()
            .expect("comprehension source identity");
        let comprehension_node = ast
            .facts
            .source_map
            .node(comprehension_id)
            .expect("comprehension node");
        assert_eq!(comprehension_node.kind, AstNodeKind::ListComprehension);
        assert_eq!(
            source.slice(comprehension_node.range),
            Some("[item for item in values if true]")
        );
    }
    #[test]
    fn successful_resolution_retains_declarations_types_and_calls() {
        let text = include_str!("../fixtures/koto_v1/resolved/003.ko");
        let source = SourceFile::new(SourceId(9), "japanese.ko", text);
        let (ast, _) = crate::parser::parse_source_spanned(&source, FrontendBudget::v1())
            .expect("Japanese declaration spellings parse");
        let resolved = resolve(ast, &source).expect("all named references resolve");
        assert_eq!(resolved.source_map().source(), SourceId(9));
        assert!(resolved.symbols().any(|symbol| symbol.name == "helper"));
        assert!(resolved.types().all(|ty| ty.name == "int"));
        assert!(resolved.calls().any(|call| {
            call.name == "helper" && matches!(call.target, ResolvedCallTarget::Function(_))
        }));
        let parameter = resolved
            .parameter_name_source("helper", "value")
            .expect("parameter name source");
        assert_eq!(source.slice(parameter.range), Some("value"));
    }
    #[test]
    fn parser_binding_facts_have_direct_owners_and_exact_utf8_ranges() {
        let text = include_str!("../fixtures/koto_v1/resolved/004.ko");
        let source = SourceFile::new(SourceId(75), "utf8-binding-facts.ko", text);
        let (ast, _) = crate::parser::parse_source_spanned(&source, FrontendBudget::v1())
            .expect("adversarial repeated-name source parses");
        let mut owner_ordinals = BTreeSet::new();
        let mut name_nodes = BTreeSet::new();
        let mut repeated_ranges = Vec::new();
        for fact in &ast.facts.bindings {
            assert!(
                owner_ordinals.insert((fact.owner, fact.ordinal)),
                "binding owner/ordinal pairs must be unique"
            );
            assert!(
                name_nodes.insert(fact.name_node),
                "each binding must own a distinct exact name token"
            );
            let owner = ast
                .facts
                .source_map
                .node(fact.owner)
                .expect("direct binding owner");
            let name = ast
                .facts
                .source_map
                .node(fact.name_node)
                .expect("binding name token");
            assert_eq!(name.kind, AstNodeKind::Name);
            assert!(owner.range.contains(name.range));
            assert_eq!(source.slice(name.range), Some(fact.name.as_str()));
            if fact.name == "repeated" {
                repeated_ranges.push(name.range);
            }
            match fact.kind {
                BindingFactKind::Local | BindingFactKind::Iterator => {
                    assert_eq!(owner.kind, AstNodeKind::Statement)
                }
                BindingFactKind::Pattern => assert!(matches!(
                    owner.kind,
                    AstNodeKind::Statement | AstNodeKind::Expression
                )),
                BindingFactKind::Comprehension => {
                    assert_eq!(owner.kind, AstNodeKind::ListComprehension)
                }
            }
        }
        assert_eq!(repeated_ranges.len(), 5);
        repeated_ranges.sort_unstable();
        assert!(
            repeated_ranges.windows(2).all(|pair| pair[0] < pair[1]),
            "identical spellings must retain distinct source-token ranges"
        );
        let first = repeated_ranges[0];
        assert_eq!(source.slice(first), Some("repeated"));
        assert_ne!(
            usize::try_from(first.start).expect("source budget"),
            text[..usize::try_from(first.start).expect("source budget")]
                .chars()
                .count(),
            "the fixture must exercise UTF-8 byte offsets, not ASCII-only offsets"
        );
    }
    #[test]
    fn parenthesized_if_let_keeps_its_direct_binding_owner_when_becoming_a_statement() {
        let text = include_str!("../fixtures/koto_v1/resolved/005.ko");
        let source = SourceFile::new(SourceId(81), "parenthesized-if-let.ko", text);
        let (ast, _) = crate::parser::parse_source_spanned(&source, FrontendBudget::v1())
            .expect("parenthesized if-let statement parses");
        let fact = ast
            .facts
            .bindings
            .iter()
            .find(|fact| fact.name == "payload")
            .expect("payload binding fact");
        assert_eq!(
            ast.facts
                .source_map
                .node(fact.owner)
                .map(|owner| owner.kind),
            Some(AstNodeKind::Statement)
        );
        let name = ast
            .facts
            .source_map
            .node(fact.name_node)
            .expect("payload name token");
        assert_eq!(source.slice(name.range), Some("payload"));
        resolve(ast, &source).expect("direct binding owner survives statement conversion");
    }
    fn binding_fact_fixture() -> (SourceFile, SpannedProgram) {
        let text = include_str!("../fixtures/koto_v1/resolved/006.ko");
        let source = SourceFile::new(SourceId(76), "binding-integrity.ko", text);
        let (ast, _) = crate::parser::parse_source_spanned(&source, FrontendBudget::v1())
            .expect("binding-integrity fixture parses");
        (source, ast)
    }
    fn assert_binding_fact_corruption_fails(source: &SourceFile, ast: SpannedProgram) {
        let diagnostics = resolve(ast, source).expect_err("corrupt binding facts must fail closed");
        assert!(
            diagnostics
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "K2099"),
            "unexpected diagnostics: {diagnostics:?}"
        );
    }
    #[test]
    fn resolver_rejects_missing_duplicate_and_mismatched_binding_facts() {
        let (source, original) = binding_fact_fixture();
        resolve(original.clone(), &source).expect("uncorrupted binding facts resolve");
        assert!(original.facts.bindings.len() >= 5);
        let mut missing = original.clone();
        missing.facts.bindings.remove(0);
        assert_binding_fact_corruption_fails(&source, missing);
        let mut duplicate = original.clone();
        duplicate
            .facts
            .bindings
            .push(duplicate.facts.bindings[0].clone());
        assert_binding_fact_corruption_fails(&source, duplicate);
        let mut wrong_owner = original.clone();
        wrong_owner.facts.bindings[0].owner = wrong_owner.facts.declarations[0].node;
        assert_binding_fact_corruption_fails(&source, wrong_owner);
        let mut wrong_ordinal = original.clone();
        wrong_ordinal.facts.bindings[0].ordinal = u16::MAX;
        assert_binding_fact_corruption_fails(&source, wrong_ordinal);
        let mut wrong_role = original.clone();
        wrong_role.facts.bindings[0].kind = BindingFactKind::Iterator;
        assert_binding_fact_corruption_fails(&source, wrong_role);
        let mut wrong_spelling = original.clone();
        wrong_spelling.facts.bindings[0].name = "forged".to_owned();
        assert_binding_fact_corruption_fails(&source, wrong_spelling);
        let mut wrong_name_node = original.clone();
        wrong_name_node.facts.bindings[0].name_node = wrong_name_node.facts.bindings[0].owner;
        assert_binding_fact_corruption_fails(&source, wrong_name_node);
        let mut reused_name_node = original;
        let payload_indices = reused_name_node
            .facts
            .bindings
            .iter()
            .enumerate()
            .filter_map(|(index, fact)| (fact.name == "payload").then_some(index))
            .collect::<Vec<_>>();
        assert_eq!(payload_indices.len(), 2);
        reused_name_node.facts.bindings[payload_indices[1]].name_node =
            reused_name_node.facts.bindings[payload_indices[0]].name_node;
        assert_binding_fact_corruption_fails(&source, reused_name_node);
    }
    #[test]
    fn resolver_rejects_mismatched_source_identity_even_for_an_empty_module() {
        let parsed_source = SourceFile::new(SourceId(78), "empty.ko", "module Empty {}");
        let (ast, _) = crate::parser::parse_source_spanned(&parsed_source, FrontendBudget::v1())
            .expect("empty module parses");
        let different_identity = SourceFile::new(SourceId(79), "empty.ko", "module Empty {}");
        let diagnostics =
            resolve(ast, &different_identity).expect_err("source identity mismatch must fail");
        assert_eq!(diagnostics.diagnostics.len(), 1);
        assert_eq!(diagnostics.diagnostics[0].code, "K2099");
    }
    #[test]
    fn shadowing_diagnostic_labels_both_exact_names_after_utf8_prefix() {
        let text = "誓約 Shadow { fn run(int value) { /* 雪 */ let int value = 1; } }";
        let source = SourceFile::new(SourceId(77), "utf8-shadow.ko", text);
        let (ast, _) = crate::parser::parse_source_spanned(&source, FrontendBudget::v1())
            .expect("shadowing source parses");
        let diagnostics = resolve(ast, &source).expect_err("shadowing must be rejected");
        let diagnostic = diagnostics
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "E_LOCAL_SHADOWING")
            .expect("shadowing diagnostic");
        let primary = diagnostic
            .primary_span
            .as_ref()
            .and_then(|span| span.byte_range)
            .expect("exact shadowing name range");
        let previous = diagnostic.labels[0]
            .span
            .byte_range
            .expect("exact previous name range");
        assert_eq!(source.slice(primary), Some("value"));
        assert_eq!(source.slice(previous), Some("value"));
        assert_ne!(primary, previous);
        assert_eq!(
            usize::try_from(primary.start).expect("source budget"),
            text.rfind("value").expect("local name byte offset")
        );
        assert_eq!(
            usize::try_from(previous.start).expect("source budget"),
            text.find("value").expect("parameter name byte offset")
        );
    }
    #[test]
    fn state_and_lifecycle_diagnostic_ranges_come_from_resolved_nodes() {
        let text = include_str!("../fixtures/koto_v1/resolved/007.ko");
        let source = SourceFile::new(SourceId(11), "state.ko", text);
        let (ast, _) = crate::parser::parse_source_spanned(&source, FrontendBudget::v1())
            .expect("state source parses");
        let resolved = resolve(ast, &source).expect("state source resolves");
        let state = resolved
            .first_scalar_state_keyword_source()
            .expect("scalar state keyword source");
        assert_eq!(source.slice(state.range), Some("state"));
        let lifecycle = resolved
            .hajimari_name_source()
            .expect("hajimari name source");
        assert_eq!(source.slice(lifecycle.range), Some("始まり"));
    }
    fn resolved_local_program() -> (SourceFile, ResolvedProgram) {
        let text = include_str!("../fixtures/koto_v1/resolved/008.ko");
        let source = SourceFile::new(SourceId(73), "stable.ko", text);
        let (ast, _) = crate::parser::parse_source_spanned(&source, FrontendBudget::v1())
            .expect("stable local source parses");
        let resolved = resolve(ast, &source).expect("stable local source resolves");
        (source, resolved)
    }
    fn helper_return(program: &mut ResolvedProgram) -> &mut Expr {
        let Item::Function(function) = &mut program.program.items[0] else {
            panic!("helper function")
        };
        let Statement::Resolved { statement, .. } = &mut function.body.statements[1] else {
            panic!("resolved return statement")
        };
        let Statement::Return(Some(expression)) = statement.as_mut() else {
            panic!("return expression")
        };
        expression
    }
    fn helper_statement(program: &mut ResolvedProgram, index: usize) -> &mut Statement {
        let Item::Function(function) = &mut program.program.items[0] else {
            panic!("helper function")
        };
        function
            .body
            .statements
            .get_mut(index)
            .expect("helper statement index")
    }
    fn assert_internal_resolution_failure(program: &ResolvedProgram) {
        let failures = crate::semantic::SemanticContext::new()
            .analyze_resolved(program)
            .expect_err("corrupted resolved HIR must fail closed");
        assert!(
            failures
                .failures
                .iter()
                .any(|failure| failure.error.code == "E_INTERNAL_RESOLUTION"),
            "unexpected failures: {failures:?}"
        );
    }
    #[test]
    fn resolved_bindings_and_targets_survive_clone_and_move() {
        let (_source, resolved) = resolved_local_program();
        let cloned = resolved.clone();
        let moved = std::hint::black_box(cloned);
        assert_eq!(resolved.arena, moved.arena);
        assert!(moved.bindings().count() >= 3);
        assert!(moved.arena.nodes().any(|node| {
            matches!(
                node.target,
                Some(ResolvedTarget::Value(ResolvedValueTarget::Binding(_)))
            )
        }));
        let typed = crate::semantic::SemanticContext::new()
            .analyze_resolved(&moved)
            .expect("moved resolved HIR types without pointer rebinding");
        assert!(!typed.hir_nodes.is_empty());
    }
    #[test]
    fn semantic_rejects_corrupted_hir_id_kind_source_and_target() {
        let (_source, resolved) = resolved_local_program();
        let original_id = helper_return(&mut resolved.clone())
            .hir_id()
            .expect("return value HIR id");
        let mut missing_id = resolved.clone();
        let Expr::Resolved { id, .. } = helper_return(&mut missing_id) else {
            panic!("resolved expression")
        };
        *id = HirId(u32::MAX);
        assert_internal_resolution_failure(&missing_id);
        let mut wrong_kind = resolved.clone();
        Arc::make_mut(&mut wrong_kind.arena)
            .nodes
            .get_mut(original_id.0 as usize)
            .expect("return node")
            .kind = ResolvedNodeKind::Statement;
        assert_internal_resolution_failure(&wrong_kind);
        let mut wrong_source = resolved.clone();
        let Expr::Resolved { source, .. } = helper_return(&mut wrong_source) else {
            panic!("resolved expression")
        };
        let range = source.as_mut().expect("source-backed return value");
        range.range.end = range.range.end.saturating_sub(1);
        assert_internal_resolution_failure(&wrong_source);
        let mut missing_target = resolved.clone();
        Arc::make_mut(&mut missing_target.arena)
            .nodes
            .get_mut(original_id.0 as usize)
            .expect("return node")
            .target = None;
        assert_internal_resolution_failure(&missing_target);
        let mut wrong_target = resolved;
        Arc::make_mut(&mut wrong_target.arena)
            .nodes
            .get_mut(original_id.0 as usize)
            .expect("return node")
            .target = Some(ResolvedTarget::Call(ResolvedCallTarget::Intrinsic));
        assert_internal_resolution_failure(&wrong_target);
    }
    #[test]
    fn semantic_rejects_missing_or_corrupted_statement_hir_wrappers() {
        let (_source, resolved) = resolved_local_program();
        let mut missing_return = resolved.clone();
        let current = std::mem::replace(helper_statement(&mut missing_return, 1), Statement::Break);
        let Statement::Resolved { statement, .. } = current else {
            panic!("resolved return statement")
        };
        *helper_statement(&mut missing_return, 1) = *statement;
        assert_internal_resolution_failure(&missing_return);
        let mut missing_let = resolved.clone();
        let current = std::mem::replace(helper_statement(&mut missing_let, 0), Statement::Break);
        let Statement::Resolved { statement, .. } = current else {
            panic!("resolved let statement")
        };
        *helper_statement(&mut missing_let, 0) = *statement;
        assert_internal_resolution_failure(&missing_let);
        let mut wrong_id = resolved.clone();
        let Statement::Resolved { id, .. } = helper_statement(&mut wrong_id, 0) else {
            panic!("resolved let statement")
        };
        *id = HirId(u32::MAX);
        assert_internal_resolution_failure(&wrong_id);
        let let_id = helper_statement(&mut resolved.clone(), 0)
            .hir_id()
            .expect("let HIR id");
        let mut wrong_kind = resolved.clone();
        Arc::make_mut(&mut wrong_kind.arena)
            .nodes
            .get_mut(let_id.0 as usize)
            .expect("let arena node")
            .kind = ResolvedNodeKind::Expression;
        assert_internal_resolution_failure(&wrong_kind);
        let mut wrong_source = resolved;
        let Statement::Resolved { source, .. } = helper_statement(&mut wrong_source, 0) else {
            panic!("resolved let statement")
        };
        let range = source.as_mut().expect("source-backed let statement");
        range.range.end = range.range.end.saturating_sub(1);
        assert_internal_resolution_failure(&wrong_source);
    }
    fn resolved_type_program() -> (SourceFile, ResolvedProgram) {
        let text = include_str!("../fixtures/koto_v1/resolved/009.ko");
        let source = SourceFile::new(SourceId(80), "resolved-types.ko", text);
        let (ast, _) = crate::parser::parse_source_spanned(&source, FrontendBudget::v1())
            .expect("resolved type fixture parses");
        let resolved = resolve(ast, &source).expect("resolved type fixture resolves");
        (source, resolved)
    }
    fn parameter_type(program: &mut ResolvedProgram, index: usize) -> &mut TypeExpr {
        let Item::Function(function) = &mut program.program.items[0] else {
            panic!("type fixture function")
        };
        function.params[index]
            .ty
            .as_mut()
            .expect("typed parameter annotation")
    }
    fn list_capacity_type(program: &mut ResolvedProgram) -> &mut TypeExpr {
        let TypeExpr::Resolved { ty, .. } = parameter_type(program, 1) else {
            panic!("resolved List type")
        };
        let TypeExpr::Generic { args, .. } = ty.as_mut() else {
            panic!("List generic type")
        };
        &mut args[1]
    }
    #[test]
    fn semantic_rejects_missing_or_corrupted_tuple_and_const_type_wrappers() {
        let (_source, resolved) = resolved_type_program();
        let mut missing_tuple = resolved.clone();
        let current = std::mem::replace(parameter_type(&mut missing_tuple, 0), TypeExpr::Const(0));
        let TypeExpr::Resolved { ty, .. } = current else {
            panic!("resolved tuple type")
        };
        *parameter_type(&mut missing_tuple, 0) = *ty;
        assert_internal_resolution_failure(&missing_tuple);
        let mut wrong_tuple_id = resolved.clone();
        let TypeExpr::Resolved { id, .. } = parameter_type(&mut wrong_tuple_id, 0) else {
            panic!("resolved tuple type")
        };
        *id = HirId(u32::MAX);
        assert_internal_resolution_failure(&wrong_tuple_id);
        let tuple_id = parameter_type(&mut resolved.clone(), 0)
            .hir_id()
            .expect("tuple HIR id");
        let mut wrong_tuple_kind = resolved.clone();
        Arc::make_mut(&mut wrong_tuple_kind.arena)
            .nodes
            .get_mut(tuple_id.0 as usize)
            .expect("tuple arena node")
            .kind = ResolvedNodeKind::Expression;
        assert_internal_resolution_failure(&wrong_tuple_kind);
        let mut wrong_tuple_source = resolved.clone();
        let TypeExpr::Resolved { source, .. } = parameter_type(&mut wrong_tuple_source, 0) else {
            panic!("resolved tuple type")
        };
        let range = source.as_mut().expect("source-backed tuple type");
        range.range.end = range.range.end.saturating_sub(1);
        assert_internal_resolution_failure(&wrong_tuple_source);
        let mut missing_const = resolved.clone();
        let current = std::mem::replace(list_capacity_type(&mut missing_const), TypeExpr::Const(0));
        let TypeExpr::Resolved { ty, .. } = current else {
            panic!("resolved List capacity")
        };
        *list_capacity_type(&mut missing_const) = *ty;
        assert_internal_resolution_failure(&missing_const);
        let mut wrong_const_id = resolved.clone();
        let TypeExpr::Resolved { id, .. } = list_capacity_type(&mut wrong_const_id) else {
            panic!("resolved List capacity")
        };
        *id = HirId(u32::MAX);
        assert_internal_resolution_failure(&wrong_const_id);
        let const_id = list_capacity_type(&mut resolved.clone())
            .hir_id()
            .expect("capacity HIR id");
        let mut wrong_const_kind = resolved.clone();
        Arc::make_mut(&mut wrong_const_kind.arena)
            .nodes
            .get_mut(const_id.0 as usize)
            .expect("capacity arena node")
            .kind = ResolvedNodeKind::Statement;
        assert_internal_resolution_failure(&wrong_const_kind);
        let mut wrong_const_source = resolved;
        let TypeExpr::Resolved { source, .. } = list_capacity_type(&mut wrong_const_source) else {
            panic!("resolved List capacity")
        };
        let range = source.as_mut().expect("source-backed List capacity");
        range.range.end = range.range.end.saturating_sub(1);
        assert_internal_resolution_failure(&wrong_const_source);
    }
    #[test]
    fn resolver_reports_shadowing_and_multiple_unknown_values_with_locations() {
        let text = include_str!("../fixtures/koto_v1/resolved/010.ko");
        let source = SourceFile::new(SourceId(74), "bad-locals.ko", text);
        let (ast, _) = crate::parser::parse_source_spanned(&source, FrontendBudget::v1())
            .expect("adversarial local source parses");
        let diagnostics = resolve(ast, &source).expect_err("resolution must reject every error");
        assert!(diagnostics.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "E_LOCAL_SHADOWING" && diagnostic.primary_span.is_some()
        }));
        let unknowns = diagnostics
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.message.starts_with("unknown value"))
            .collect::<Vec<_>>();
        assert_eq!(unknowns.len(), 2);
        assert!(unknowns.iter().all(|diagnostic| {
            diagnostic
                .primary_span
                .as_ref()
                .and_then(|span| span.byte_range)
                .is_some()
        }));
    }
    #[test]
    fn only_canonical_numeric_conversions_are_resolver_intrinsics() {
        for canonical in [
            "decimal::from_int",
            "decimal::to_int_exact",
            "decimal::to_int_trunc",
            "decimal::to_int_round",
            "quantity::try_from_int",
            "quantity::try_from_decimal",
            "decimal::from_quantity",
        ] {
            assert!(intrinsic_call(canonical), "missing intrinsic `{canonical}`");
        }
        for retired in ["int::from_i64", "quantity::from_i64", "quantity::from_u128"] {
            assert!(
                !intrinsic_call(retired),
                "retired intrinsic `{retired}` leaked into V1"
            );
        }
    }
}
/// Compiler-owned numeric conversion calls resolved without a registry builtin.
const INTRINSIC_CALLS: &[&str] = &[
    "decimal::from_int",
    "decimal::to_int_exact",
    "decimal::to_int_trunc",
    "decimal::to_int_round",
    "quantity::try_from_int",
    "quantity::try_from_decimal",
    "decimal::from_quantity",
];
fn intrinsic_call(name: &str) -> bool {
    INTRINSIC_CALLS.contains(&name)
}
/// Whether `name` is a compiler-owned numeric conversion call.
pub(crate) fn is_intrinsic_call(name: &str) -> bool {
    intrinsic_call(name)
}
/// Explain an unresolved value and suggest the closest visible spelling.
fn unknown_value_diagnostic(
    globals: &GlobalTargets,
    name: &str,
    visible: &BTreeMap<String, BindingId>,
    span: Option<SourceSpan>,
) -> Diagnostic {
    if let Some((namespace, variant)) = name.rsplit_once("::")
        && globals.enums.contains_key(namespace)
    {
        let prefix = format!("{namespace}::");
        let suggestion = suggestions::closest_name(
            variant,
            globals
                .variant_codes
                .keys()
                .filter_map(|code| code.strip_prefix(prefix.as_str())),
        )
        .map(|suggestion| suggestions::NameSuggestion {
            help: format!("did you mean `{namespace}::{}`?", suggestion.replacement),
            replacement: format!("{namespace}::{}", suggestion.replacement),
        });
        return with_suggestion(
            Diagnostic::error(
                "E_UNKNOWN_ENUM_VARIANT",
                DiagnosticPhase::Resolve,
                format!("enum `{namespace}` has no variant `{variant}`"),
                span,
            ),
            suggestion,
            None,
        );
    }
    let suggestion = if suggestions::builtin_root(name).is_some() {
        suggestions::intrinsic_value(name)
    } else {
        suggestions::closest_name(
            name,
            visible
                .keys()
                .chain(globals.states.keys())
                .chain(globals.consts.keys())
                .chain(globals.variant_codes.keys())
                .chain(globals.external_states.iter())
                .chain(globals.external_consts.iter())
                .map(String::as_str),
        )
    };
    with_suggestion(
        Diagnostic::error(
            "K2002",
            DiagnosticPhase::Resolve,
            format!("unknown value `{name}`"),
            span,
        ),
        suggestion,
        None,
    )
}
/// Attach a did-you-mean help line, a replacement fix and an optional note.
fn with_suggestion(
    mut diagnostic: Diagnostic,
    suggestion: Option<suggestions::NameSuggestion>,
    note: Option<String>,
) -> Diagnostic {
    if let Some(suggestion) = suggestion {
        if let Some(span) = diagnostic.primary_span.clone() {
            diagnostic.fix = Some(crate::diagnostic::DiagnosticFix {
                span,
                replacement: suggestion.replacement,
            });
        }
        diagnostic.help = Some(suggestion.help);
    }
    diagnostic.notes.extend(note);
    diagnostic
}
/// Report a call through a compiler-owned namespace that names no builtin.
fn unknown_builtin_diagnostic(name: &str, span: Option<SourceSpan>) -> Diagnostic {
    let (suggestion, note) = if matches!(name.split("::").next(), Some("Option" | "Result")) {
        (suggestions::intrinsic_value(name), None)
    } else {
        suggestions::unknown_builtin(name)
    };
    with_suggestion(
        Diagnostic::error(
            "E_UNKNOWN_BUILTIN",
            DiagnosticPhase::Resolve,
            format!("unknown builtin `{name}`"),
            span,
        ),
        suggestion,
        note,
    )
}
fn resolve_type(
    ast: &SpannedProgram,
    source: &SourceFile,
    fact: &TypeUseFact,
    structs: &BTreeMap<String, SymbolId>,
    enums: &BTreeMap<String, SymbolId>,
    external_structs: &BTreeSet<String>,
    resolve_imports: bool,
) -> Result<ResolvedTypeUse, Box<Diagnostic>> {
    let target = if builtin_type(&fact.name) {
        ResolvedTypeTarget::Builtin
    } else if let Some(symbol) = structs.get(&fact.name) {
        ResolvedTypeTarget::Struct(*symbol)
    } else if let Some(symbol) = enums.get(&fact.name) {
        ResolvedTypeTarget::Enum(*symbol)
    } else if external_structs.contains(&fact.name) {
        ResolvedTypeTarget::ExternalStruct
    } else if resolve_imports && explicit_import_call(&fact.name) {
        ResolvedTypeTarget::ExternalType
    } else {
        let suggestion = suggestions::closest_name(
            &fact.name,
            kotodama_surface::source_policy::V1_SOURCE_TYPE_NAMES
                .iter()
                .copied()
                .chain(structs.keys().map(String::as_str))
                .chain(enums.keys().map(String::as_str))
                .chain(external_structs.iter().map(String::as_str)),
        );
        return Err(Box::new(with_suggestion(
            Diagnostic::error(
                "K2002",
                DiagnosticPhase::Resolve,
                format!("unknown type `{}`", fact.name),
                ast.facts.source_map.source_span(source, fact.node),
            ),
            suggestion,
            None,
        )));
    };
    Ok(ResolvedTypeUse {
        node: fact.node,
        source: ast
            .facts
            .source_map
            .source_range(fact.node)
            .expect("resolver facts always reference their source arena"),
        owner: fact.owner,
        name: fact.name.clone(),
        target,
    })
}
#[derive(Clone)]
struct GlobalTargets {
    all: BTreeMap<String, SymbolId>,
    structs: BTreeMap<String, SymbolId>,
    enums: BTreeMap<String, SymbolId>,
    functions: BTreeMap<String, SymbolId>,
    states: BTreeMap<String, SymbolId>,
    consts: BTreeMap<String, SymbolId>,
    permissions: BTreeSet<String>,
    variant_codes: BTreeMap<String, u32>,
    resolve_import_calls: bool,
    external_functions: BTreeSet<String>,
    external_states: BTreeSet<String>,
    external_structs: BTreeSet<String>,
    external_consts: BTreeSet<String>,
    external_variant_codes: BTreeMap<String, u32>,
    /// Declared spelling and name range of each source-unit declaration.
    declarations: BTreeMap<String, GlobalDeclaration>,
}
/// One source-unit declaration retained for collision diagnostics.
#[derive(Clone, Debug)]
struct GlobalDeclaration {
    /// Declaration keyword as written, such as `kotoage`, `言挙げ`, `view fn` or `const`.
    keyword: String,
    /// Exact declared-name range.
    source: Option<SourceRange>,
}
/// Read the declaration keyword exactly as the source spells it.
///
/// Both spellings of a branded keyword are the same token; diagnostics echo
/// whichever one this declaration used.
fn declaration_keyword(kind: DeclarationKind, text: Option<&str>) -> String {
    let fixed = match kind {
        DeclarationKind::Struct => Some("struct"),
        DeclarationKind::Event => Some("event"),
        DeclarationKind::Enum => None,
        DeclarationKind::State => Some("state"),
        DeclarationKind::Const => Some("const"),
        DeclarationKind::Trigger => Some("trigger"),
        DeclarationKind::Permission => Some("permission"),
        DeclarationKind::Parameter => Some("parameter"),
        DeclarationKind::Function | DeclarationKind::SourceUnit => None,
    };
    if let Some(fixed) = fixed {
        return fixed.to_owned();
    }
    let words = text
        .unwrap_or_default()
        .split(|character: char| character.is_whitespace() || "({".contains(character))
        .filter(|word| !word.is_empty());
    for word in words {
        match word {
            "error" => return "error enum".to_owned(),
            "enum" => return "enum".to_owned(),
            "view" => return "view fn".to_owned(),
            "fn" | "module" => return word.to_owned(),
            word if crate::glossary::by_spelling(word).is_some() => return word.to_owned(),
            _ => {}
        }
    }
    kind.description().to_owned()
}
/// Diagnose a local binding that reuses a reserved name, a visible binding, or a
/// source-unit declaration.
fn local_collision_diagnostic(
    globals: &GlobalTargets,
    source: &SourceFile,
    name: &str,
    kind: ResolvedBindingKind,
    reserved: bool,
    previous: Option<DiagnosticLabel>,
    span: Option<SourceSpan>,
) -> Diagnostic {
    let binding = match kind {
        ResolvedBindingKind::Parameter => "parameter",
        ResolvedBindingKind::Local => "local binding",
        ResolvedBindingKind::Pattern => "pattern binding",
        ResolvedBindingKind::Iterator => "loop binding",
        ResolvedBindingKind::Comprehension => "comprehension binding",
    };
    if reserved {
        return Diagnostic::error(
            "E_RESERVED_DECLARATION",
            DiagnosticPhase::Resolve,
            format!("local binding `{name}` uses a compiler-reserved name"),
            span,
        );
    }
    let declaration = globals.declarations.get(name);
    let message = if previous.is_some() {
        format!("local binding `{name}` duplicates or shadows an existing binding")
    } else if globals.consts.contains_key(name) {
        format!("local binding `{name}` shadows a const declaration")
    } else if globals.states.contains_key(name) {
        format!("local binding `{name}` shadows a state declaration")
    } else if globals.functions.contains_key(name) {
        let keyword = declaration.map_or("fn", |declaration| declaration.keyword.as_str());
        format!("local binding `{name}` shadows {keyword} `{name}`")
    } else if globals.structs.contains_key(name) {
        format!("local binding `{name}` shadows a struct declaration")
    } else {
        format!("local binding `{name}` shadows a source declaration")
    };
    let mut diagnostic =
        Diagnostic::error("E_LOCAL_SHADOWING", DiagnosticPhase::Resolve, message, span);
    if let Some(previous) = previous {
        diagnostic.labels.push(previous);
        diagnostic.help = Some(format!(
            "Rename this {binding}; Kotodama never lets one local hide another."
        ));
    } else {
        if let Some(declaration) = declaration
            && let Some(range) = declaration
                .source
                .filter(|range| range.source == source.id())
        {
            diagnostic.labels.push(DiagnosticLabel {
                span: SourceSpan::from_range(source, range.range),
                message: format!("{} `{name}` is declared here", declaration.keyword),
            });
        }
        diagnostic.help = Some(format!(
            "Rename this {binding}; parameters, locals, and seiyaku-level declarations share one namespace, so `{name}` cannot name both."
        ));
    }
    diagnostic
}
struct HirLowerer<'a> {
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
impl<'a> HirLowerer<'a> {
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
            // A rejected binding still resolves its own later uses, so one
            // collision does not cascade into "unknown value" diagnostics.
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
            || self.globals.permissions.contains(name)
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
/// Resolve one CST-derived spanned AST into named HIR.
pub(crate) fn resolve(
    ast: SpannedProgram,
    source: &SourceFile,
) -> Result<ResolvedProgram, DiagnosticBundle> {
    let external = ExternalResolutionEnvironment::default();
    resolve_with_imports_and_externals(ast, source, false, &external)
}
/// Resolve a module source while retaining import-shaped calls for the typed linker.
pub(crate) fn resolve_with_imports(
    ast: SpannedProgram,
    source: &SourceFile,
    _imports: &BTreeMap<String, ()>,
) -> Result<ResolvedProgram, DiagnosticBundle> {
    let external = ExternalResolutionEnvironment::default();
    // Alias/export validation belongs to the typed linker. Preserve every
    // syntactically explicit two-segment import call in resolved HIR, including
    // calls through an undeclared alias, so diagnostics retain the name span.
    resolve_with_imports_and_externals(ast, source, true, &external)
}
/// Outcome of resolution that keeps going past failures inside function bodies.
pub(crate) struct RecoveredResolution {
    /// Every resolution diagnostic of the original source.
    pub(crate) diagnostics: DiagnosticBundle,
    /// The source resolved again with each failing function body emptied, when
    /// every failure lies inside a function body and the reduced source
    /// resolves cleanly.
    pub(crate) reduced: Option<ResolvedProgram>,
    /// Functions whose bodies were emptied; their semantic results are void.
    pub(crate) emptied: BTreeSet<String>,
}
/// Resolve `ast`; on failure, also resolve a reduced copy whose failing
/// function bodies are empty, so independent functions can still be type
/// checked. Signatures, declarations, and every other body are unchanged.
///
/// `ast` must be the canonical V1 parse of `source`. The reduced copy is built
/// from a fresh parse of `source` only when resolution fails, so successful
/// compilations never pay for a second program tree.
pub(crate) fn resolve_recovering(
    ast: SpannedProgram,
    source: &SourceFile,
) -> Result<ResolvedProgram, Box<RecoveredResolution>> {
    let diagnostics = match resolve(ast, source) {
        Ok(program) => return Ok(program),
        Err(diagnostics) => diagnostics,
    };
    let reparsed = crate::parser::parse_source_spanned(source, crate::source::FrontendBudget::v1())
        .ok()
        .map(|(program, _)| program);
    let (reduced, emptied) =
        match reparsed.map(|reparsed| empty_failing_bodies(reparsed, &diagnostics)) {
            Some(Ok((reduced, emptied))) => (resolve(reduced, source).ok(), emptied),
            Some(Err(unchanged)) => {
                crate::ast::drop_program_iterative(unchanged.program);
                (None, BTreeSet::new())
            }
            None => (None, BTreeSet::new()),
        };
    Err(Box::new(RecoveredResolution {
        diagnostics,
        emptied: if reduced.is_some() {
            emptied
        } else {
            BTreeSet::new()
        },
        reduced,
    }))
}
/// Recover a project unit with the exact include/import declaration environment.
/// This is used only after strict project resolution has already failed.
pub(crate) fn resolve_with_imports_recovering(
    ast: SpannedProgram,
    source: &SourceFile,
    external: &ExternalResolutionEnvironment,
) -> Result<ResolvedProgram, Box<RecoveredResolution>> {
    let diagnostics =
        match resolve_with_imports_and_external_environment(ast.clone(), source, external) {
            Ok(program) => return Ok(program),
            Err(diagnostics) => diagnostics,
        };
    let (reduced, emptied) = match empty_failing_bodies(ast, &diagnostics) {
        Ok((reduced, emptied)) => (
            resolve_with_imports_and_external_environment(reduced, source, external).ok(),
            emptied,
        ),
        Err(unchanged) => {
            crate::ast::drop_program_iterative(unchanged.program);
            (None, BTreeSet::new())
        }
    };
    Err(Box::new(RecoveredResolution {
        diagnostics,
        emptied: if reduced.is_some() {
            emptied
        } else {
            BTreeSet::new()
        },
        reduced,
    }))
}

/// Empty the bodies of functions that contain resolution failures and drop the
/// parser facts that belonged to those bodies. Returns the program unchanged
/// when a failure lies outside every function body, so the caller can release
/// it without recursion.
fn empty_failing_bodies(
    mut ast: SpannedProgram,
    diagnostics: &DiagnosticBundle,
) -> Result<(SpannedProgram, BTreeSet<String>), Box<SpannedProgram>> {
    let body_ranges = |function: &crate::ast::Function| {
        function
            .body
            .statements
            .iter()
            .filter_map(Statement::source)
            .chain(function.body.tail.as_deref().and_then(Expr::source))
            .map(|range| range.range)
            .collect::<Vec<_>>()
    };
    let mut emptied = BTreeSet::new();
    let mut removed = Vec::new();
    let mut outside_bodies = false;
    for diagnostic in &diagnostics.diagnostics {
        let owner = diagnostic
            .primary_span
            .as_ref()
            .and_then(|span| span.byte_range)
            .and_then(|range| {
                ast.program.items.iter().find_map(|item| {
                    let Item::Function(function) = item else {
                        return None;
                    };
                    body_ranges(function)
                        .iter()
                        .any(|body| body.contains(range))
                        .then_some(function)
                })
            });
        let Some(owner) = owner else {
            outside_bodies = true;
            break;
        };
        if emptied.insert(owner.name.clone()) {
            removed.extend(body_ranges(owner));
        }
    }
    if outside_bodies {
        return Err(Box::new(ast));
    }
    let inside = |node: NodeId| {
        ast.facts
            .source_map
            .source_range(node)
            .is_some_and(|range| removed.iter().any(|body| body.contains(range.range)))
    };
    let bindings = ast
        .facts
        .bindings
        .iter()
        .filter(|fact| !inside(fact.name_node))
        .cloned()
        .collect();
    let calls = ast
        .facts
        .calls
        .iter()
        .filter(|fact| !inside(fact.node))
        .cloned()
        .collect();
    let type_uses = ast
        .facts
        .type_uses
        .iter()
        .filter(|fact| !inside(fact.node))
        .cloned()
        .collect();
    ast.facts.bindings = bindings;
    ast.facts.calls = calls;
    ast.facts.type_uses = type_uses;
    for item in &mut ast.program.items {
        if let Item::Function(function) = item
            && emptied.contains(&function.name)
        {
            let body = std::mem::replace(
                &mut function.body,
                crate::ast::Block {
                    statements: Vec::new(),
                    tail: None,
                },
            );
            crate::ast::drop_block_iterative(body);
        }
    }
    Ok((ast, emptied))
}
/// Names exported by one typed standalone-test target for fail-closed resolution.
#[derive(Clone, Debug, Default)]
pub(crate) struct ExternalResolutionEnvironment {
    pub(crate) contracts: BTreeMap<String, crate::semantic::ImportedContractInterface>,
    pub(crate) functions: BTreeSet<String>,
    pub(crate) states: BTreeSet<String>,
    pub(crate) structs: BTreeSet<String>,
    pub(crate) consts: BTreeSet<String>,
    pub(crate) permissions: BTreeSet<String>,
    pub(crate) variant_codes: BTreeMap<String, u32>,
}
/// Resolve a standalone test source against its target's typed interface.
pub(crate) fn resolve_with_external_environment(
    ast: SpannedProgram,
    source: &SourceFile,
    external: &ExternalResolutionEnvironment,
) -> Result<ResolvedProgram, DiagnosticBundle> {
    resolve_with_imports_and_externals(ast, source, false, external)
}
/// Resolve immutable standalone tests with their target interface and explicit import calls.
pub(crate) fn resolve_with_imports_and_external_environment(
    ast: SpannedProgram,
    source: &SourceFile,
    external: &ExternalResolutionEnvironment,
) -> Result<ResolvedProgram, DiagnosticBundle> {
    resolve_with_imports_and_externals(ast, source, true, external)
}
fn resolve_with_imports_and_externals(
    ast: SpannedProgram,
    source: &SourceFile,
    resolve_import_calls: bool,
    external: &ExternalResolutionEnvironment,
) -> Result<ResolvedProgram, DiagnosticBundle> {
    resolve_with_imports_and_externals_inner(ast, source, resolve_import_calls, external).map_err(
        |mut diagnostics| {
            diagnostics.capture_source(source);
            diagnostics
        },
    )
}
fn resolve_with_imports_and_externals_inner(
    ast: SpannedProgram,
    source: &SourceFile,
    resolve_import_calls: bool,
    external: &ExternalResolutionEnvironment,
) -> Result<ResolvedProgram, DiagnosticBundle> {
    if ast.facts.source_map.source() != source.id() {
        return Err(DiagnosticBundle::single(Diagnostic::error(
            "K2099",
            DiagnosticPhase::Resolve,
            "spanned AST and resolver source identities do not match",
            None,
        )));
    }
    let mut diagnostics = Vec::new();
    let mut symbols = Vec::new();
    let mut globals = BTreeMap::<String, (SymbolId, &DeclarationFact)>::new();
    let mut structs = BTreeMap::<String, SymbolId>::new();
    let mut enums = BTreeMap::<String, SymbolId>::new();
    let mut functions = BTreeMap::<String, SymbolId>::new();
    let mut states = BTreeMap::<String, SymbolId>::new();
    let mut consts = BTreeMap::<String, SymbolId>::new();
    for fact in &ast.facts.declarations {
        if fact.kind == DeclarationKind::Parameter {
            if fact.owner.is_none() {
                diagnostics.push(Diagnostic::error(
                    "K2099",
                    DiagnosticPhase::Resolve,
                    format!("parameter `{}` has no owning function", fact.name),
                    declaration_span(&ast, source, fact),
                ));
            }
            // Parameter collisions are diagnosed while constructing the native
            // lexical binding arena below. Reporting them here as declarations
            // as well would emit two diagnostics for the same exact name token.
            continue;
        }
        let id = symbol_id(symbols.len());
        let reserved = if fact.kind.is_type_declaration() {
            kotodama_surface::source_policy::is_reserved_source_type_declaration(&fact.name)
        } else {
            kotodama_surface::source_policy::is_reserved_source_declaration(
                &fact.name,
                fact.kind.is_function(),
            )
        };
        if reserved {
            diagnostics.push(Diagnostic::error(
                "E_RESERVED_DECLARATION",
                DiagnosticPhase::Resolve,
                format!(
                    "{} `{}` uses a compiler-reserved name",
                    fact.kind.description(),
                    fact.name
                ),
                declaration_span(&ast, source, fact),
            ));
            continue;
        }
        if let Some((_, previous)) = globals.get(&fact.name) {
            diagnostics.push(duplicate_diagnostic(&ast, source, fact, previous));
            continue;
        }
        globals.insert(fact.name.clone(), (id, fact));
        match fact.kind {
            DeclarationKind::Function => {
                functions.insert(fact.name.clone(), id);
            }
            DeclarationKind::Struct | DeclarationKind::Event => {
                structs.insert(fact.name.clone(), id);
            }
            DeclarationKind::Enum => {
                enums.insert(fact.name.clone(), id);
            }
            DeclarationKind::State => {
                states.insert(fact.name.clone(), id);
            }
            DeclarationKind::Const => {
                consts.insert(fact.name.clone(), id);
            }
            DeclarationKind::SourceUnit
            | DeclarationKind::Trigger
            | DeclarationKind::Permission => {}
            DeclarationKind::Parameter => unreachable!("parameters were handled above"),
        }
        symbols.push(ResolvedSymbol {
            id,
            node: fact.node,
            source: ast
                .facts
                .source_map
                .source_range(fact.name_node)
                .expect("declaration facts always reference their source arena"),
            name: fact.name.clone(),
            kind: symbol_kind(fact.kind).expect("global declaration has a symbol kind"),
        });
    }
    let declaration_source = |name: &str, kind: DeclarationKind| {
        ast.facts
            .declarations
            .iter()
            .find(|fact| fact.kind == kind && fact.name == name)
            .and_then(|fact| ast.facts.source_map.source_range(fact.node))
    };
    let mut variant_codes = BTreeMap::new();
    for descriptor in [
        ivm_abi::error_types::list_error_type(),
        ivm_abi::error_types::numeric_error_type(),
    ] {
        let name = descriptor
            .identity
            .rsplit("::")
            .next()
            .expect("builtin error name");
        for variant in &descriptor.variants {
            variant_codes.insert(format!("{name}::{}", variant.name), variant.code);
        }
    }
    for item in &ast.program.items {
        match item {
            Item::Struct(definition) | Item::Event(definition) => {
                let mut fields = BTreeSet::new();
                for (field, _) in &definition.fields {
                    if !fields.insert(field.as_str()) {
                        diagnostics.push(Diagnostic::error(
                            "E_DUPLICATE_DECLARATION",
                            DiagnosticPhase::Resolve,
                            format!(
                                "field `{field}` is declared more than once in struct `{}`",
                                definition.name
                            ),
                            declaration_source(&definition.name, DeclarationKind::Struct)
                                .map(|range| SourceSpan::from_range(source, range.range)),
                        ));
                    }
                }
            }
            Item::Enum(definition) => {
                let mut variants = BTreeSet::new();
                for variant in &definition.variants {
                    if !variants.insert(variant.name.as_str()) {
                        diagnostics.push(Diagnostic::error(
                            "E_DUPLICATE_DECLARATION",
                            DiagnosticPhase::Resolve,
                            format!(
                                "enum variant `{}` is declared more than once in `{}`",
                                variant.name, definition.name
                            ),
                            declaration_source(&definition.name, DeclarationKind::Enum)
                                .map(|range| SourceSpan::from_range(source, range.range)),
                        ));
                    }
                    variant_codes.insert(
                        format!("{}::{}", definition.name, variant.name),
                        variant.code,
                    );
                }
            }
            Item::Function(_) | Item::Const(_) | Item::State(_) | Item::Trigger(_) => {}
        }
    }
    let mut types = Vec::with_capacity(ast.facts.type_uses.len());
    for fact in &ast.facts.type_uses {
        match resolve_type(
            &ast,
            source,
            fact,
            &structs,
            &enums,
            &external.structs,
            resolve_import_calls,
        ) {
            Ok(resolved) => types.push(resolved),
            Err(diagnostic) => diagnostics.push(*diagnostic),
        }
    }
    let mut calls = Vec::with_capacity(ast.facts.calls.len());
    for fact in &ast.facts.calls {
        let target = if fact.implicit_receiver {
            Some(ResolvedCallTarget::Method)
        } else if let Some(symbol) = functions.get(&fact.name) {
            Some(ResolvedCallTarget::Function(*symbol))
        } else if let Some(builtin) = Builtin::from_source_name(&fact.name) {
            Some(ResolvedCallTarget::Builtin(builtin))
        } else if let Some(symbol) = structs.get(&fact.name) {
            Some(ResolvedCallTarget::Struct(*symbol))
        } else if intrinsic_call(&fact.name) {
            Some(ResolvedCallTarget::Intrinsic)
        } else if external.functions.contains(&fact.name) {
            Some(ResolvedCallTarget::External)
        } else if suggestions::builtin_root(&fact.name).is_some() {
            // Compiler-owned roots can never be import aliases, so an unknown
            // member is an unknown builtin rather than a missing import.
            diagnostics.push(unknown_builtin_diagnostic(
                &fact.name,
                ast.facts.source_map.source_span(source, fact.name_node),
            ));
            continue;
        } else if resolve_import_calls && explicit_import_call(&fact.name) {
            Some(ResolvedCallTarget::External)
        } else {
            None
        };
        if let Some(target) = target {
            calls.push(ResolvedCall {
                node: fact.node,
                name_node: fact.name_node,
                argument_name_sources: fact
                    .argument_name_nodes
                    .iter()
                    .map(|node| node.and_then(|node| ast.facts.source_map.source_range(node)))
                    .collect(),
                source: ast
                    .facts
                    .source_map
                    .source_range(fact.node)
                    .expect("call facts always reference their source arena"),
                name_source: ast
                    .facts
                    .source_map
                    .source_range(fact.name_node)
                    .expect("call names always reference their source arena"),
                owner: fact.owner,
                name: fact.name.clone(),
                target,
            });
        } else {
            if let Some(message) = crate::parser::removed_free_helper_message(&fact.name) {
                diagnostics.push(Diagnostic::error(
                    "K2002",
                    DiagnosticPhase::Resolve,
                    message,
                    ast.facts.source_map.source_span(source, fact.name_node),
                ));
                continue;
            }
            let suggestion = suggestions::closest_name(
                &fact.name,
                functions
                    .keys()
                    .chain(structs.keys())
                    .map(String::as_str)
                    .chain(
                        INTRINSIC_CALLS
                            .iter()
                            .copied()
                            .filter(|name| !name.contains("::")),
                    ),
            );
            diagnostics.push(with_suggestion(
                Diagnostic::error(
                    "K2002",
                    DiagnosticPhase::Resolve,
                    format!("unknown function or builtin `{}`", fact.name),
                    ast.facts.source_map.source_span(source, fact.name_node),
                ),
                suggestion,
                None,
            ));
        }
    }
    let permission_names = ast
        .program
        .permissions
        .iter()
        .map(|declaration| declaration.name.as_str())
        .chain(external.permissions.iter().map(String::as_str))
        .collect::<BTreeSet<_>>();
    for authorization in &ast.facts.authorizations {
        let name = authorization.name.as_str();
        if name != "anyone" && !permission_names.contains(name) {
            let suggestion =
                crate::diagnostic::suggest::closest(name, permission_names.iter().copied());
            let mut diagnostic = Diagnostic::error(
                "E_UNKNOWN_PERMISSION",
                DiagnosticPhase::Resolve,
                format!("authorization references undeclared permission `{name}`"),
                ast.facts
                    .source_map
                    .source_span(source, authorization.name_node),
            );
            diagnostic.help = Some(match suggestion {
                Some(candidate) => format!(
                    "did you mean `{candidate}`? Permission names must be explicitly declared by this seiyaku"
                ),
                None => format!(
                    "declare `permission {name};` or explicitly import a chain permission; use `authorize(anyone)` for open access"
                ),
            });
            diagnostics.push(diagnostic);
        }
    }
    let mut parameter_sources = BTreeMap::new();
    for item in &ast.program.items {
        let Item::Function(function) = item else {
            continue;
        };
        let Some(owner) = ast
            .facts
            .declarations
            .iter()
            .find(|fact| fact.kind == DeclarationKind::Function && fact.name == function.name)
            .map(|fact| fact.node)
        else {
            continue;
        };
        for (index, fact) in ast
            .facts
            .declarations
            .iter()
            .filter(|fact| fact.kind == DeclarationKind::Parameter && fact.owner == Some(owner))
            .enumerate()
        {
            if let Some(range) = ast.facts.source_map.source_range(fact.name_node) {
                parameter_sources.insert((function.name.clone(), index), (fact.name_node, range));
            }
        }
    }
    let declarations = globals
        .iter()
        .map(|(name, (_, fact))| {
            let text = ast
                .facts
                .source_map
                .source_range(fact.node)
                .and_then(|range| source.slice(range.range));
            (
                name.clone(),
                GlobalDeclaration {
                    keyword: declaration_keyword(fact.kind, text),
                    source: ast.facts.source_map.source_range(fact.name_node),
                },
            )
        })
        .collect();
    let global_targets = GlobalTargets {
        declarations,
        all: globals
            .iter()
            .map(|(name, (id, _))| (name.clone(), *id))
            .collect(),
        structs,
        enums,
        functions,
        states,
        consts,
        permissions: ast
            .program
            .permissions
            .iter()
            .map(|permission| permission.name.clone())
            .chain(external.permissions.iter().cloned())
            .collect(),
        variant_codes,
        resolve_import_calls,
        external_functions: external.functions.clone(),
        external_states: external.states.clone(),
        external_structs: external.structs.clone(),
        external_consts: external.consts.clone(),
        external_variant_codes: external.variant_codes.clone(),
    };
    let SpannedProgram { program, facts } = ast;
    let (program, mut arena, lower_diagnostics) = HirLowerer::new(
        source,
        &facts.source_map,
        global_targets,
        parameter_sources,
        &facts.bindings,
    )
    .lower_program(program);
    arena.symbols = symbols.clone();
    diagnostics.extend(lower_diagnostics);
    for call in &calls {
        let matching = arena.nodes().filter(|node| {
            node.source == Some(call.source)
                && node.target == Some(ResolvedTarget::Call(call.target))
        });
        if matching.count() != 1 {
            diagnostics.push(Diagnostic::error(
                "K2099",
                DiagnosticPhase::Resolve,
                format!(
                    "resolved call `{}` did not bind exactly once into native HIR",
                    call.name
                ),
                Some(SourceSpan::from_range(source, call.name_source.range)),
            ));
        }
    }
    if diagnostics.is_empty() {
        Ok(ResolvedProgram {
            program,
            facts,
            source_file: source.clone(),
            symbols,
            types,
            calls,
            arena: Arc::new(arena),
            included: Vec::new(),
            original: None,
        })
    } else {
        Err(DiagnosticBundle::new(diagnostics))
    }
}

#[path = "resolved/lowering.rs"]
mod lowering;
#[cfg(test)]
#[path = "resolved/lowering_equivalence_tests.rs"]
mod lowering_equivalence_tests;
#[cfg(test)]
#[path = "resolved/lowering_stack_tests.rs"]
mod lowering_stack_tests;
#[path = "resolved/suggestions.rs"]
pub(crate) mod suggestions;
