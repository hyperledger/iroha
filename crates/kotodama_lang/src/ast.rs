//! Abstract syntax tree definitions for KOTODAMA.
//!
//! These structures represent the parsed Kotodama source surface accepted by the compiler.
use crate::source::{SourceRange, TextRange};
use iroha_primitives::bigint::BigInt;
/// Stable identity assigned when a spanned AST node enters resolved HIR.
///
/// The identity is local to one source unit. It is embedded in resolver-only
/// provenance wrappers, so moving or cloning a resolved program cannot detach
/// semantic analysis from the name-resolution result it is required to use.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct HirId(pub(crate) u32);
/// Stable identity assigned by the CST/AST parser to one source-backed node.
///
/// Unlike an address-derived lookup key, this identity is stored directly in
/// source provenance and therefore survives moves, clones, and parser caches.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct NodeId(pub(crate) u32);
impl NodeId {
    pub(crate) fn index(self) -> usize {
        usize::try_from(self.0).expect("u32 source-node identity fits usize")
    }
}
/// Compiler-owned call name used after parsing the canonical `StateMap.get(key)` method form.
///
/// Source code cannot call this name directly. Keeping the marker distinct from the source spelling
/// preserves enough call-form information for name resolution to distinguish a user function named
/// `get` from the StateMap intrinsic.
pub(crate) const STATE_MAP_GET_INTRINSIC: &str = "state_map_get";
#[derive(Debug, PartialEq, Clone)]
pub struct Program {
    /// The single named source unit declared by this file.
    pub unit: SourceUnit,
    pub items: Vec<Item>,
    /// Explicit instance permissions and named chain-permission imports.
    pub permissions: Vec<PermissionDecl>,
    /// Explicit source dependencies in declaration order.
    pub directives: Vec<SourceDirective>,
    /// Declarations explicitly exposed to module consumers.
    pub exports: Vec<ExportDecl>,
    /// Optional standalone test-file target declaration.
    pub test_target: Option<TestTargetDecl>,
    /// Optional local test fixtures available to `#[test(...)]` functions.
    pub fixtures: Vec<FixtureDecl>,
}
/// A permission name bound explicitly by this seiyaku's source.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PermissionDecl {
    /// Local source identifier referenced by authorization and grant operations.
    pub name: String,
    /// Explicit chain-global token import; absent for an instance permission.
    pub chain_permission: Option<String>,
}
/// Whether a source file declares a deployable `seiyaku` or a library module.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SourceUnitKind {
    /// A deployable `seiyaku`/`誓約` unit.
    Seiyaku,
    /// A non-deployable library unit.
    Module,
    /// Bare declarations included into an enclosing seiyaku or module.
    Fragment,
}
/// One source dependency at a declaration boundary.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SourceDirective {
    /// Include or namespaced local-module import.
    pub kind: SourceDirectiveKind,
    /// Number of ordinary declarations preceding this directive.
    pub item_index: usize,
    /// Exact directive range in its original source file.
    pub source: SourceRange,
}
/// Source-level dependency syntax; resolution is owned by the compiler graph.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SourceDirectiveKind {
    /// Include bare declarations into the enclosing unit's shared scope.
    Include {
        /// Literal path relative to the file containing the directive.
        path: String,
    },
    /// Bind a namespace to an authenticated compiled contract interface.
    ContractImport {
        /// Literal artifact path resolved only from the owning source inventory.
        path: String,
        /// Explicit source namespace for this contract interface.
        alias: String,
    },
    /// Bind one exact public nominal identity from an authenticated contract namespace.
    ContractTypeImport {
        /// Complete immutable identity, including package/revision when present.
        identity: String,
        /// Previously declared contract namespace.
        contract: String,
        /// Local source spelling of this exact type.
        alias: String,
    },
    /// Import an independently scoped local module.
    Import {
        /// Literal path relative to the file containing the directive.
        path: String,
        /// Explicit source namespace for exported declarations.
        alias: String,
    },
}
/// Explicit visibility of one module declaration.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ExportDecl {
    /// Source declaration name, independent of its runtime function role.
    pub name: String,
    /// Exact `export` modifier range in its original source file.
    pub source: SourceRange,
}
/// Identity of the single top-level source unit.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SourceUnit {
    /// Unit category.
    pub kind: SourceUnitKind,
    /// Source-level seiyaku or module name.
    pub name: String,
}
#[derive(Debug, PartialEq, Clone, Copy, Eq)]
pub struct SourceLocation {
    pub line: usize,
    pub column: usize,
}
/// Exact declaration role of a function inside a seiyaku or module.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub enum FunctionKind {
    /// Private `fn`, including module-private and compiler-created helpers.
    #[default]
    Private,
    /// Mutating public `kotoage fn`/`言挙げ fn` declaration.
    Kotoage,
    /// Seiyaku lifecycle declaration (`hajimari` / `始まり`).
    Hajimari,
    /// Seiyaku lifecycle declaration (`kaizen` / `改善`).
    Kaizen,
    /// Read-only public query entrypoint (`view fn`).
    View,
}
/// Parsed modifiers associated with a function.
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct FunctionModifiers {
    pub kind: FunctionKind,
    /// Caller authorization identifier, or the explicit open policy `anyone`.
    pub authorization: Option<String>,
    /// Marks a function as a local-only Kotodama test.
    pub is_test: bool,
    /// Optional fixture bound to a Kotodama test function.
    pub test_fixture: Option<String>,
}
#[derive(Debug, PartialEq, Clone)]
pub enum Item {
    Function(Function),
    /// User-defined product type with named fields.
    Struct(StructDef),
    /// Contract-owned typed native event payload declaration.
    Event(StructDef),
    /// An ordinary data enum or a raisable error enum.
    Enum(EnumDef),
    /// Seiyaku-level constant declaration.
    Const(ConstDecl),
    /// Seiyaku-level durable state declaration lowered to host-backed state
    /// paths, including flattened singleton struct/tuple children.
    State(StateDecl),
    /// Seiyaku-level trigger declaration (manifest-only metadata).
    Trigger(TriggerDecl),
}
/// A syntactic type expression as written by the user.
pub enum TypeExpr {
    /// Parser-internal provenance carrier removed before any canonical public
    /// parse/session output is returned. This is not a Kotodama type variant.
    #[doc(hidden)]
    Source {
        node: NodeId,
        source: SourceRange,
        ty: Box<TypeExpr>,
    },
    /// Resolver-owned provenance carrier. This variant never appears in parser
    /// output and is removed before an AST is returned to source tooling.
    #[doc(hidden)]
    Resolved {
        id: HirId,
        source: Option<SourceRange>,
        ty: Box<TypeExpr>,
    },
    /// A path or simple identifier, e.g. `int`, `AccountId`.
    Path(String),
    /// A generic type, such as `StateMap<K, V>`.
    Generic { base: String, args: Vec<TypeExpr> },
    /// A tuple type, e.g. `(int, bool)`.
    Tuple(Vec<TypeExpr>),
    /// A non-negative compile-time integer argument, used by `List<T, N>`.
    Const(u64),
    /// An integer constant expression in a generic capacity position.
    ConstExpression(Box<Expr>),
}
impl std::fmt::Debug for TypeExpr {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Source { node, source, .. } => formatter
                .debug_struct("Source")
                .field("node", node)
                .field("source", source)
                .field("ty", &"..")
                .finish(),
            Self::Resolved { id, source, .. } => formatter
                .debug_struct("Resolved")
                .field("id", id)
                .field("source", source)
                .field("ty", &"..")
                .finish(),
            Self::Path(path) => formatter.debug_tuple("Path").field(path).finish(),
            Self::Generic { base, args } => formatter
                .debug_struct("Generic")
                .field("base", base)
                .field("args", &args.len())
                .finish(),
            Self::Tuple(items) => formatter
                .debug_tuple("Tuple")
                .field(&format_args!("{} item(s)", items.len()))
                .finish(),
            Self::Const(value) => formatter.debug_tuple("Const").field(value).finish(),
            Self::ConstExpression(value) => formatter
                .debug_tuple("ConstExpression")
                .field(value)
                .finish(),
        }
    }
}
impl PartialEq for TypeExpr {
    fn eq(&self, other: &Self) -> bool {
        ast_nodes_equal(CompareNode::Type(self, other))
    }
}
impl Clone for TypeExpr {
    fn clone(&self) -> Self {
        clone_ast_node(CloneNode::Type(self)).into_type()
    }
}
/// Explicit source-call spelling of a parameter.
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum ParameterCallMode {
    /// `Type name`: callers may use the parameter name or its positional slot.
    #[default]
    Named,
    /// `Type _ name`: callers supply an unlabeled positional argument.
    Positional,
}
#[derive(Debug, PartialEq, Clone)]
pub struct Param {
    pub ty: Option<TypeExpr>,
    pub name: String,
    /// Declaration-owned source argument mode.
    pub call_mode: ParameterCallMode,
    /// Internal state-handle marker; canonical V1 source parameters always set this to `false`.
    pub is_state: bool,
}
#[derive(Debug, PartialEq, Clone)]
pub struct Function {
    pub name: String,
    pub params: Vec<Param>,
    pub ret_ty: Option<TypeExpr>,
    pub body: Block,
    pub modifiers: FunctionModifiers,
    pub location: SourceLocation,
}
#[derive(Debug, PartialEq, Clone)]
pub struct Block {
    pub statements: Vec<Statement>,
    /// Final expression without a semicolon, evaluated as the block value.
    pub tail: Option<Box<Expr>>,
}

/// A user-defined struct with named fields.
#[derive(Debug, PartialEq, Clone)]
pub struct StructDef {
    pub name: String,
    pub fields: Vec<(String, TypeExpr)>,
}
/// One closed, explicitly numbered nominal enum.
#[derive(Debug, PartialEq, Clone)]
pub struct EnumDef {
    pub name: String,
    /// Whether the variants are data values or raisable failures.
    pub kind: EnumKind,
    pub variants: Vec<EnumVariant>,
}
/// The semantic purpose of a nominal enum declaration.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EnumKind {
    /// An ordinary data value; never a raisable rejection.
    Data,
    /// A raisable failure with optional human-readable variant messages.
    Error,
}
/// One explicitly numbered nominal variant.
#[derive(Debug, PartialEq, Clone)]
pub struct EnumVariant {
    pub name: String,
    pub code: u32,
    /// Optional bounded static text displayed for this nominal rejection.
    pub message: Option<String>,
}
/// A seiyaku-level type-first `const` declaration: `const Type name = expr;`.
#[derive(Debug, PartialEq, Clone)]
pub struct ConstDecl {
    pub name: String,
    pub ty: Option<TypeExpr>,
    pub value: Expr,
}

/// A seiyaku-level `state` declaration: `state Type name;`.
#[derive(Debug, PartialEq, Clone)]
pub struct StateDecl {
    pub name: String,
    pub ty: TypeExpr,
}
/// Standalone Kotodama test-file declaration identifying the seiyaku under test.
#[derive(Debug, PartialEq, Clone)]
pub struct TestTargetDecl {
    pub target: String,
}
/// Declarative local fixture used by `koto_test`.
#[derive(Debug, PartialEq, Clone)]
pub struct FixtureDecl {
    pub name: String,
    pub actions: Vec<FixtureAction>,
}

/// One fixture action expressed as a function-style command, for example
/// `caller(account("alice@wonderland"))`.
#[derive(Debug, PartialEq, Clone)]
pub struct FixtureAction {
    pub name: String,
    pub args: Vec<Expr>,
}

/// Seiyaku-level trigger declaration.
#[derive(Debug, PartialEq, Clone)]
pub struct TriggerDecl {
    pub name: String,
    /// Source location of the trigger name used for stable diagnostics.
    pub location: SourceLocation,
    pub call: TriggerCall,
    pub filter: TriggerFilter,
    pub repeats: Option<TriggerRepeats>,
    pub authority: Option<String>,
    pub metadata: Vec<TriggerMetadataEntry>,
}

/// Trigger callback target.
#[derive(Debug, PartialEq, Clone)]
pub struct TriggerCall {
    pub entrypoint: String,
}
/// Trigger filter definition.
#[derive(Debug, PartialEq, Clone)]
pub enum TriggerFilter {
    Time(TriggerTimeFilter),
    Execute { trigger_id: String },
    Data(TriggerDataFilter),
    Pipeline(TriggerPipelineFilter),
}
/// Data trigger filter variants.
#[derive(Debug, PartialEq, Clone)]
pub enum TriggerDataFilter {
    Any,
    Structured(TriggerStructuredDataFilter),
}
/// Structured data trigger filter block.
#[derive(Debug, PartialEq, Clone)]
pub struct TriggerStructuredDataFilter {
    pub family: TriggerDataFamily,
    pub event: TriggerDataEventKind,
    pub matchers: Vec<TriggerDataMatcher>,
}
/// Supported data-event families for contract trigger declarations.
#[derive(Debug, PartialEq, Clone, Copy, Eq)]
pub enum TriggerDataFamily {
    Peer,
    Domain,
    Account,
    Asset,
    AssetDefinition,
    Nft,
    Rwa,
    Trigger,
    Role,
    Configuration,
    Executor,
}
/// Event kind selector inside a structured data trigger.
#[derive(Debug, PartialEq, Clone)]
pub enum TriggerDataEventKind {
    Any,
    Named(String),
}
/// Matcher entry inside a structured data trigger block.
#[derive(Debug, PartialEq, Clone)]
pub struct TriggerDataMatcher {
    pub key: String,
    pub value: String,
}
/// Pipeline trigger filter variants.
#[derive(Debug, PartialEq, Clone)]
pub enum TriggerPipelineFilter {
    TransactionApproved,
    BlockApproved,
}
/// Time trigger filter variants.
#[derive(Debug, PartialEq, Clone)]
pub enum TriggerTimeFilter {
    PreCommit,
    Schedule {
        start_ms: Box<Expr>,
        period_ms: Option<Box<Expr>>,
    },
}
/// Trigger repeat policy.
#[derive(Debug, PartialEq, Clone)]
pub enum TriggerRepeats {
    Indefinitely,
    Exactly(u32),
}
/// Trigger metadata entry (literal JSON values only).
#[derive(Debug, PartialEq, Clone)]
pub struct TriggerMetadataEntry {
    pub key: String,
    pub value: Expr,
}

/// Localized message entry keyed by a stable message id.
#[derive(Debug, PartialEq, Clone)]
pub struct MessageEntry {
    pub msg_id: String,
    pub translations: Vec<MessageTranslation>,
}
/// Localization entry for a specific language tag.
#[derive(Debug, PartialEq, Clone)]
pub struct MessageTranslation {
    pub lang: String,
    pub text: String,
}
#[derive(Debug, PartialEq, Clone)]
pub enum Pattern {
    Name(String),
    Tuple(Vec<String>),
    /// A named, order-independent destructure of one declared struct.
    Struct {
        /// Nominal struct type selected by the pattern.
        name: String,
        /// Named fields and their local binding names.
        fields: Vec<StructPatternField>,
        /// Whether a trailing `..` explicitly discards unspecified fields.
        rest: bool,
    },
}
/// One field in a named struct binding pattern.
#[derive(Debug, PartialEq, Clone)]
pub struct StructPatternField {
    /// Field selected from the declared struct.
    pub name: String,
    /// Local binding name, or `_` for an explicit discard.
    pub binding: String,
    /// Exact source range of the selected field name.
    pub source: Option<SourceRange>,
}
/// Canonical namespaced variant admitted in `match` and `if let` patterns.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub enum SumVariant {
    OptionSome,
    OptionNone,
    ResultOk,
    ResultErr,
    /// A payloadless variant in a nominal data or error enum.
    Nominal {
        namespace: String,
        variant: String,
    },
}
/// Payload handling for an active sum variant pattern.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PatternBinding {
    /// Bind the active payload to a new local.
    Name(String),
    /// Explicitly ignore the active payload.
    Wildcard,
}
/// One namespaced `Option`, `Result`, or nominal error pattern.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SumPattern {
    pub variant: SumVariant,
    /// `None` is valid only for the inactive `Option::none` pattern.
    pub binding: Option<PatternBinding>,
}
/// One source `match` arm.
#[derive(Debug, PartialEq, Clone)]
pub struct MatchArm {
    pub pattern: SumPattern,
    pub body: Block,
}

/// One native JSON object entry with its decoded key and exact source spelling.
#[derive(Debug, PartialEq, Clone)]
pub struct JsonObjectEntry {
    /// Decoded object key used for duplicate detection and canonical encoding.
    pub key: String,
    /// Exact identifier or quoted-string token spelling retained for tooling.
    pub key_spelling: String,
    /// Exact source range of the key token.
    pub key_range: TextRange,
    /// Dynamically converted JSON value expression.
    pub value: Expr,
}
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum AssignOp {
    /// Simple assignment: `=`.
    Set,
    /// Compound assignment: `+=`.
    Add,
    /// Compound assignment: `-=`.
    Sub,
    /// Compound assignment: `*=`.
    Mul,
    /// Compound assignment: `/=`.
    Div,
    /// Compound assignment: `%=`.
    Mod,
}
pub enum Statement {
    /// Parser-internal provenance carrier removed before any canonical public
    /// parse/session output is returned. This is not a Kotodama statement.
    #[doc(hidden)]
    Source {
        node: NodeId,
        source: SourceRange,
        statement: Box<Statement>,
    },
    /// Resolver-owned provenance carrier. This variant never appears in parser
    /// output and is removed before an AST is returned to source tooling.
    #[doc(hidden)]
    Resolved {
        id: HirId,
        source: Option<SourceRange>,
        statement: Box<Statement>,
    },
    /// Local binding declared with `let` (immutable) or `var` (mutable).
    Let {
        /// Whether the source declaration used `var`.
        mutable: bool,
        pat: Pattern,
        ty: Option<TypeExpr>,
        value: Expr,
    },
    /// Assignment to a mutable local, parameter/state handle, or state binding.
    Assign {
        name: String,
        value: Expr,
    },
    /// Assignment to a general lvalue (field/indexed), e.g. `a[i].f = v` or `obj.x += 1`.
    AssignExpr {
        target: Expr,
        op: AssignOp,
        value: Expr,
    },
    Expr(Expr),
    /// Emit exactly one declared event payload.
    Emit(Expr),
    Return(Option<Expr>),
    Break,
    Continue,
    If {
        cond: Expr,
        then_branch: Block,
        else_branch: Option<Block>,
    },
    /// Pattern-guarded statement form. Unlike the expression form, `else` may be absent.
    IfLet {
        pattern: SumPattern,
        value: Expr,
        then_branch: Block,
        else_branch: Option<Block>,
    },
    While {
        cond: Expr,
        body: Block,
    },
    For {
        line: usize,
        init: Option<Box<Statement>>,
        cond: Option<Expr>,
        step: Option<Box<Statement>>,
        body: Block,
    },
    /// Iteration over a bounded list, with the same flat binding patterns as `let`.
    ForEachMap {
        pat: Pattern,
        map: Expr,
        body: Block,
    },
}
impl std::fmt::Debug for Statement {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Source { .. } => "Source(..)",
            Self::Resolved { .. } => "Resolved(..)",
            Self::Let { .. } => "Let(..)",
            Self::Assign { .. } => "Assign(..)",
            Self::AssignExpr { .. } => "AssignExpr(..)",
            Self::Expr(_) => "Expr(..)",
            Self::Emit(_) => "Emit(..)",
            Self::Return(_) => "Return(..)",
            Self::Break => "Break",
            Self::Continue => "Continue",
            Self::If { .. } => "If(..)",
            Self::IfLet { .. } => "IfLet(..)",
            Self::While { .. } => "While(..)",
            Self::For { .. } => "For(..)",
            Self::ForEachMap { .. } => "ForEachMap(..)",
        })
    }
}
impl PartialEq for Statement {
    fn eq(&self, other: &Self) -> bool {
        ast_nodes_equal(CompareNode::Statement(self, other))
    }
}
impl Clone for Statement {
    fn clone(&self) -> Self {
        clone_statement_iterative(self)
    }
}
pub enum Expr {
    /// Parser-internal provenance carrier removed before any canonical public
    /// parse/session output is returned. This is not a Kotodama expression.
    #[doc(hidden)]
    Source {
        node: NodeId,
        source: SourceRange,
        expression: Box<Expr>,
    },
    /// Resolver-owned provenance carrier. This variant never appears in parser
    /// output and is removed before an AST is returned to source tooling.
    #[doc(hidden)]
    Resolved {
        id: HirId,
        source: Option<SourceRange>,
        expression: Box<Expr>,
    },
    Binary {
        op: BinaryOp,
        left: Box<Expr>,
        right: Box<Expr>,
    },
    Unary {
        op: UnaryOp,
        expr: Box<Expr>,
    },
    /// Ternary conditional expression: `cond ? then : else`.
    Conditional {
        cond: Box<Expr>,
        then_expr: Box<Expr>,
        else_expr: Box<Expr>,
    },
    /// Expression-valued conditional whose branches are blocks.
    If {
        condition: Box<Expr>,
        then_branch: Block,
        else_branch: Option<Block>,
    },
    /// Expression-valued sum pattern test.
    IfLet {
        pattern: SumPattern,
        value: Box<Expr>,
        then_branch: Block,
        else_branch: Option<Block>,
    },
    /// Exhaustive expression-valued `Option` or `Result` match.
    Match {
        value: Box<Expr>,
        arms: Vec<MatchArm>,
    },
    /// Active `Option` constructor; no inactive payload is materialized.
    OptionSome(Box<Expr>),
    /// Contextual inactive `Option` constructor.
    OptionNone,
    /// Active success constructor; the error type is supplied by context.
    ResultOk(Box<Expr>),
    /// Active error constructor; the success type is supplied by context.
    ResultErr(Box<Expr>),
    /// Postfix propagation expression.
    Propagate(Box<Expr>),
    /// Call to a builtin function like `crypto::iroha_hash(payload)`.
    Call {
        name: String,
        args: Vec<Expr>,
        /// Source labels in source order. The outer `None` denotes an all-positional call;
        /// inner `None` slots are the positional prefix of a mixed call.
        ///
        /// Method receivers are stored as `args[0]` and are deliberately excluded from this list
        /// because they are compiler-inserted rather than source arguments.
        argument_names: Option<Vec<Option<String>>>,
        /// Whether `args[0]` is the implicit receiver from source method syntax.
        implicit_receiver: bool,
    },
    /// Named source construction for a declared struct.
    StructLiteral {
        name: String,
        fields: Vec<StructLiteralField>,
    },
    /// Closed typed argument record accepted only by test invocation helpers.
    ArgumentRecord {
        fields: Vec<StructLiteralField>,
    },
    /// Field access: `expr.field`
    Member {
        object: Box<Expr>,
        field: String,
    },
    /// Indexing: `expr[index]`
    Index {
        target: Box<Expr>,
        index: Box<Expr>,
    },
    /// Tuple literal: `(a, b, c)`
    Tuple(Vec<Expr>),
    /// Bounded list literal. Its capacity is inferred from context or the exact number of elements.
    List(Vec<Expr>),
    /// Capacity-proven list comprehension:
    /// `[expression for item in source if condition]`.
    ListComprehension {
        expression: Box<Expr>,
        item: String,
        source: Box<Expr>,
        condition: Option<Box<Expr>>,
    },
    /// Native canonical JSON object construction.
    JsonObject(Vec<JsonObjectEntry>),
    /// Native canonical JSON array construction.
    JsonArray(Vec<Expr>),
    Bool(bool),
    /// A source `int` literal after one signed-domain range check.
    IntLiteral(BigInt),
    /// Exact source spelling of an exact base-10 `decimal` literal.
    DecimalLiteral(String),
    String(String),
    Bytes(Vec<u8>),
    Ident(String),
}
impl std::fmt::Debug for Expr {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bool(value) => formatter.debug_tuple("Bool").field(value).finish(),
            Self::IntLiteral(value) => formatter.debug_tuple("IntLiteral").field(value).finish(),
            Self::DecimalLiteral(value) => formatter
                .debug_tuple("DecimalLiteral")
                .field(value)
                .finish(),
            Self::String(value) => formatter.debug_tuple("String").field(value).finish(),
            Self::Bytes(value) => formatter.debug_tuple("Bytes").field(value).finish(),
            Self::Ident(value) => formatter.debug_tuple("Ident").field(value).finish(),
            other => formatter.write_str(match other {
                Self::Source { .. } => "Source(..)",
                Self::Resolved { .. } => "Resolved(..)",
                Self::Binary { .. } => "Binary(..)",
                Self::Unary { .. } => "Unary(..)",
                Self::Conditional { .. } => "Conditional(..)",
                Self::If { .. } => "If(..)",
                Self::IfLet { .. } => "IfLet(..)",
                Self::Match { .. } => "Match(..)",
                Self::OptionSome(_) => "OptionSome(..)",
                Self::OptionNone => "OptionNone",
                Self::ResultOk(_) => "ResultOk(..)",
                Self::ResultErr(_) => "ResultErr(..)",
                Self::Propagate(_) => "Propagate(..)",
                Self::Call { .. } => "Call(..)",
                Self::ArgumentRecord { .. } => "ArgumentRecord(..)",
                Self::StructLiteral { .. } => "StructLiteral(..)",
                Self::Member { .. } => "Member(..)",
                Self::Index { .. } => "Index(..)",
                Self::Tuple(_) => "Tuple(..)",
                Self::List(_) => "List(..)",
                Self::ListComprehension { .. } => "ListComprehension(..)",
                Self::JsonObject(_) => "JsonObject(..)",
                Self::JsonArray(_) => "JsonArray(..)",
                Self::Bool(_)
                | Self::IntLiteral(_)
                | Self::DecimalLiteral(_)
                | Self::String(_)
                | Self::Bytes(_)
                | Self::Ident(_) => unreachable!("scalar expressions were rendered above"),
            }),
        }
    }
}
impl PartialEq for Expr {
    fn eq(&self, other: &Self) -> bool {
        ast_nodes_equal(CompareNode::Expr(self, other))
    }
}
impl Clone for Expr {
    fn clone(&self) -> Self {
        clone_expr_iterative(self)
    }
}
/// One source field in a named struct literal.
#[derive(Debug, PartialEq, Clone)]
pub struct StructLiteralField {
    /// Declared field name supplied by the source.
    pub name: String,
    /// Field value; shorthand fields contain `Expr::Ident(name)`.
    pub value: Expr,
    /// Whether the source used shorthand spelling without `: value`.
    pub shorthand: bool,
}

enum CloneNode<'a> {
    Type(&'a TypeExpr),
    Expr(&'a Expr),
    Statement(&'a Statement),
    Block(&'a Block),
}

enum CloneTask<'a> {
    Visit(CloneNode<'a>),
    BuildType(CloneType<'a>),
    BuildExpr(CloneExpr<'a>),
    BuildStatement(CloneStatement<'a>),
    BuildBlock {
        statement_count: usize,
        has_tail: bool,
    },
}

#[derive(Clone, Copy)]
enum WrappedExpr {
    OptionSome,
    ResultOk,
    ResultErr,
    Propagate,
}

#[derive(Clone, Copy)]
enum SequenceExpr {
    Tuple,
    List,
    JsonArray,
}

enum CloneType<'a> {
    Source(NodeId, SourceRange),
    Resolved(HirId, Option<SourceRange>),
    Generic(&'a str, usize),
    Tuple(usize),
    ConstExpression,
}

enum CloneExpr<'a> {
    Source(NodeId, SourceRange),
    Resolved(HirId, Option<SourceRange>),
    Binary(BinaryOp),
    Unary(UnaryOp),
    Conditional,
    If {
        has_else: bool,
    },
    IfLet {
        pattern: &'a SumPattern,
        has_else: bool,
    },
    Match(&'a [MatchArm]),
    Wrapped(WrappedExpr),
    Call {
        name: &'a str,
        argument_names: &'a Option<Vec<Option<String>>>,
        implicit_receiver: bool,
        argument_count: usize,
    },
    StructLiteral {
        name: Option<&'a str>,
        fields: &'a [StructLiteralField],
    },
    Member(&'a str),
    Index,
    Sequence(SequenceExpr, usize),
    ListComprehension {
        item: &'a str,
        has_condition: bool,
    },
    JsonObject(&'a [JsonObjectEntry]),
}

enum CloneStatement<'a> {
    Source(NodeId, SourceRange),
    Resolved(HirId, Option<SourceRange>),
    Let {
        mutable: bool,
        pat: &'a Pattern,
        has_type: bool,
    },
    Assign(&'a str),
    AssignExpr(AssignOp),
    Expr,
    Emit,
    Return,
    If {
        has_else: bool,
    },
    IfLet {
        pattern: &'a SumPattern,
        has_else: bool,
    },
    While,
    For {
        line: usize,
        has_init: bool,
        has_cond: bool,
        has_step: bool,
    },
    ForEachMap {
        pat: &'a Pattern,
    },
}

enum CloneValue {
    Type(TypeExpr),
    Expr(Expr),
    Statement(Statement),
    Block(Block),
}

impl CloneValue {
    fn into_type(self) -> TypeExpr {
        let Self::Type(ty) = self else {
            panic!("AST clone traversal produced a non-type child")
        };
        ty
    }

    fn into_expr(self) -> Expr {
        let Self::Expr(expression) = self else {
            panic!("AST clone traversal produced a non-expression child")
        };
        expression
    }

    fn into_statement(self) -> Statement {
        let Self::Statement(statement) = self else {
            panic!("AST clone traversal produced a non-statement child")
        };
        statement
    }

    fn into_block(self) -> Block {
        let Self::Block(block) = self else {
            panic!("AST clone traversal produced a non-block child")
        };
        block
    }
}

fn take_clone_children(values: &mut Vec<CloneValue>, count: usize) -> Vec<CloneValue> {
    let start = values
        .len()
        .checked_sub(count)
        .expect("AST clone traversal visited every child before its parent");
    values.split_off(start)
}

// Type capacities contain expressions and typed lets contain annotations. Both
// directions must remain on this same work list, including provenance wrappers.
fn visit_type_clone<'a>(
    ty: &'a TypeExpr,
    tasks: &mut Vec<CloneTask<'a>>,
    values: &mut Vec<CloneValue>,
) {
    match ty {
        TypeExpr::Source { node, source, ty } => {
            tasks.push(CloneTask::BuildType(CloneType::Source(*node, *source)));
            tasks.push(CloneTask::Visit(CloneNode::Type(ty)));
        }
        TypeExpr::Resolved { id, source, ty } => {
            tasks.push(CloneTask::BuildType(CloneType::Resolved(*id, *source)));
            tasks.push(CloneTask::Visit(CloneNode::Type(ty)));
        }
        TypeExpr::Path(path) => values.push(CloneValue::Type(TypeExpr::Path(path.clone()))),
        TypeExpr::Generic { base, args } => {
            tasks.push(CloneTask::BuildType(CloneType::Generic(base, args.len())));
            tasks.extend(
                args.iter()
                    .rev()
                    .map(|ty| CloneTask::Visit(CloneNode::Type(ty))),
            );
        }
        TypeExpr::Tuple(items) => {
            tasks.push(CloneTask::BuildType(CloneType::Tuple(items.len())));
            tasks.extend(
                items
                    .iter()
                    .rev()
                    .map(|ty| CloneTask::Visit(CloneNode::Type(ty))),
            );
        }
        TypeExpr::Const(value) => values.push(CloneValue::Type(TypeExpr::Const(*value))),
        TypeExpr::ConstExpression(expression) => {
            tasks.push(CloneTask::BuildType(CloneType::ConstExpression));
            tasks.push(CloneTask::Visit(CloneNode::Expr(expression)));
        }
    }
}

fn build_type_clone(builder: CloneType<'_>, values: &mut Vec<CloneValue>) {
    let count = match builder {
        CloneType::Generic(_, count) | CloneType::Tuple(count) => count,
        CloneType::Source(..) | CloneType::Resolved(..) | CloneType::ConstExpression => 1,
    };
    let mut children = take_clone_children(values, count).into_iter();
    let ty = match builder {
        CloneType::Source(node, source) => TypeExpr::Source {
            node,
            source,
            ty: Box::new(children.next().unwrap().into_type()),
        },
        CloneType::Resolved(id, source) => TypeExpr::Resolved {
            id,
            source,
            ty: Box::new(children.next().unwrap().into_type()),
        },
        CloneType::Generic(base, _) => TypeExpr::Generic {
            base: base.to_owned(),
            args: children.by_ref().map(CloneValue::into_type).collect(),
        },
        CloneType::Tuple(_) => {
            TypeExpr::Tuple(children.by_ref().map(CloneValue::into_type).collect())
        }
        CloneType::ConstExpression => {
            TypeExpr::ConstExpression(Box::new(children.next().unwrap().into_expr()))
        }
    };
    debug_assert!(children.next().is_none());
    values.push(CloneValue::Type(ty));
}

fn clone_ast_node(root: CloneNode<'_>) -> CloneValue {
    let mut tasks = vec![CloneTask::Visit(root)];
    let mut values = Vec::new();
    while let Some(task) = tasks.pop() {
        match task {
            CloneTask::Visit(CloneNode::Type(ty)) => visit_type_clone(ty, &mut tasks, &mut values),
            CloneTask::BuildType(builder) => build_type_clone(builder, &mut values),
            CloneTask::Visit(CloneNode::Expr(expression)) => match expression {
                Expr::Source {
                    node,
                    source,
                    expression,
                } => {
                    tasks.push(CloneTask::BuildExpr(CloneExpr::Source(*node, *source)));
                    tasks.push(CloneTask::Visit(CloneNode::Expr(expression)));
                }
                Expr::Resolved {
                    id,
                    source,
                    expression,
                } => {
                    tasks.push(CloneTask::BuildExpr(CloneExpr::Resolved(*id, *source)));
                    tasks.push(CloneTask::Visit(CloneNode::Expr(expression)));
                }
                Expr::Binary { op, left, right } => {
                    tasks.push(CloneTask::BuildExpr(CloneExpr::Binary(*op)));
                    tasks.push(CloneTask::Visit(CloneNode::Expr(right)));
                    tasks.push(CloneTask::Visit(CloneNode::Expr(left)));
                }
                Expr::Unary { op, expr } => {
                    tasks.push(CloneTask::BuildExpr(CloneExpr::Unary(*op)));
                    tasks.push(CloneTask::Visit(CloneNode::Expr(expr)));
                }
                Expr::Conditional {
                    cond,
                    then_expr,
                    else_expr,
                } => {
                    tasks.push(CloneTask::BuildExpr(CloneExpr::Conditional));
                    tasks.push(CloneTask::Visit(CloneNode::Expr(else_expr)));
                    tasks.push(CloneTask::Visit(CloneNode::Expr(then_expr)));
                    tasks.push(CloneTask::Visit(CloneNode::Expr(cond)));
                }
                Expr::If {
                    condition,
                    then_branch,
                    else_branch,
                } => {
                    tasks.push(CloneTask::BuildExpr(CloneExpr::If {
                        has_else: else_branch.is_some(),
                    }));
                    if let Some(else_branch) = else_branch {
                        tasks.push(CloneTask::Visit(CloneNode::Block(else_branch)));
                    }
                    tasks.push(CloneTask::Visit(CloneNode::Block(then_branch)));
                    tasks.push(CloneTask::Visit(CloneNode::Expr(condition)));
                }
                Expr::IfLet {
                    pattern,
                    value,
                    then_branch,
                    else_branch,
                } => {
                    tasks.push(CloneTask::BuildExpr(CloneExpr::IfLet {
                        pattern,
                        has_else: else_branch.is_some(),
                    }));
                    if let Some(else_branch) = else_branch {
                        tasks.push(CloneTask::Visit(CloneNode::Block(else_branch)));
                    }
                    tasks.push(CloneTask::Visit(CloneNode::Block(then_branch)));
                    tasks.push(CloneTask::Visit(CloneNode::Expr(value)));
                }
                Expr::Match { value, arms } => {
                    tasks.push(CloneTask::BuildExpr(CloneExpr::Match(arms)));
                    for arm in arms.iter().rev() {
                        tasks.push(CloneTask::Visit(CloneNode::Block(&arm.body)));
                    }
                    tasks.push(CloneTask::Visit(CloneNode::Expr(value)));
                }
                Expr::OptionSome(value) => {
                    tasks.push(CloneTask::BuildExpr(CloneExpr::Wrapped(
                        WrappedExpr::OptionSome,
                    )));
                    tasks.push(CloneTask::Visit(CloneNode::Expr(value)));
                }
                Expr::ResultOk(value) => {
                    tasks.push(CloneTask::BuildExpr(CloneExpr::Wrapped(
                        WrappedExpr::ResultOk,
                    )));
                    tasks.push(CloneTask::Visit(CloneNode::Expr(value)));
                }
                Expr::ResultErr(value) => {
                    tasks.push(CloneTask::BuildExpr(CloneExpr::Wrapped(
                        WrappedExpr::ResultErr,
                    )));
                    tasks.push(CloneTask::Visit(CloneNode::Expr(value)));
                }
                Expr::Propagate(value) => {
                    tasks.push(CloneTask::BuildExpr(CloneExpr::Wrapped(
                        WrappedExpr::Propagate,
                    )));
                    tasks.push(CloneTask::Visit(CloneNode::Expr(value)));
                }
                Expr::Call {
                    name,
                    args,
                    argument_names,
                    implicit_receiver,
                } => {
                    tasks.push(CloneTask::BuildExpr(CloneExpr::Call {
                        name,
                        argument_names,
                        implicit_receiver: *implicit_receiver,
                        argument_count: args.len(),
                    }));
                    tasks.extend(
                        args.iter()
                            .rev()
                            .map(|argument| CloneTask::Visit(CloneNode::Expr(argument))),
                    );
                }
                Expr::StructLiteral { name, fields } => {
                    tasks.push(CloneTask::BuildExpr(CloneExpr::StructLiteral {
                        name: Some(name),
                        fields,
                    }));
                    tasks.extend(
                        fields
                            .iter()
                            .rev()
                            .map(|field| CloneTask::Visit(CloneNode::Expr(&field.value))),
                    );
                }
                Expr::ArgumentRecord { fields } => {
                    tasks.push(CloneTask::BuildExpr(CloneExpr::StructLiteral {
                        name: None,
                        fields,
                    }));
                    tasks.extend(
                        fields
                            .iter()
                            .rev()
                            .map(|field| CloneTask::Visit(CloneNode::Expr(&field.value))),
                    );
                }
                Expr::Member { object, field } => {
                    tasks.push(CloneTask::BuildExpr(CloneExpr::Member(field)));
                    tasks.push(CloneTask::Visit(CloneNode::Expr(object)));
                }
                Expr::Index { target, index } => {
                    tasks.push(CloneTask::BuildExpr(CloneExpr::Index));
                    tasks.push(CloneTask::Visit(CloneNode::Expr(index)));
                    tasks.push(CloneTask::Visit(CloneNode::Expr(target)));
                }
                Expr::Tuple(items) | Expr::List(items) | Expr::JsonArray(items) => {
                    let kind = match expression {
                        Expr::Tuple(_) => SequenceExpr::Tuple,
                        Expr::List(_) => SequenceExpr::List,
                        Expr::JsonArray(_) => SequenceExpr::JsonArray,
                        _ => unreachable!("matched an expression sequence"),
                    };
                    tasks.push(CloneTask::BuildExpr(CloneExpr::Sequence(kind, items.len())));
                    tasks.extend(
                        items
                            .iter()
                            .rev()
                            .map(|item| CloneTask::Visit(CloneNode::Expr(item))),
                    );
                }
                Expr::ListComprehension {
                    expression,
                    item,
                    source,
                    condition,
                } => {
                    tasks.push(CloneTask::BuildExpr(CloneExpr::ListComprehension {
                        item,
                        has_condition: condition.is_some(),
                    }));
                    if let Some(condition) = condition {
                        tasks.push(CloneTask::Visit(CloneNode::Expr(condition)));
                    }
                    tasks.push(CloneTask::Visit(CloneNode::Expr(source)));
                    tasks.push(CloneTask::Visit(CloneNode::Expr(expression)));
                }
                Expr::JsonObject(entries) => {
                    tasks.push(CloneTask::BuildExpr(CloneExpr::JsonObject(entries)));
                    tasks.extend(
                        entries
                            .iter()
                            .rev()
                            .map(|entry| CloneTask::Visit(CloneNode::Expr(&entry.value))),
                    );
                }
                Expr::OptionNone => values.push(CloneValue::Expr(Expr::OptionNone)),
                Expr::Bool(value) => values.push(CloneValue::Expr(Expr::Bool(*value))),
                Expr::IntLiteral(value) => {
                    values.push(CloneValue::Expr(Expr::IntLiteral(value.clone())));
                }
                Expr::DecimalLiteral(value) => {
                    values.push(CloneValue::Expr(Expr::DecimalLiteral(value.clone())));
                }
                Expr::String(value) => {
                    values.push(CloneValue::Expr(Expr::String(value.clone())));
                }
                Expr::Bytes(value) => {
                    values.push(CloneValue::Expr(Expr::Bytes(value.clone())));
                }
                Expr::Ident(value) => {
                    values.push(CloneValue::Expr(Expr::Ident(value.clone())));
                }
            },
            CloneTask::Visit(CloneNode::Statement(statement)) => match statement {
                Statement::Source {
                    node,
                    source,
                    statement,
                } => {
                    tasks.push(CloneTask::BuildStatement(CloneStatement::Source(
                        *node, *source,
                    )));
                    tasks.push(CloneTask::Visit(CloneNode::Statement(statement)));
                }
                Statement::Resolved {
                    id,
                    source,
                    statement,
                } => {
                    tasks.push(CloneTask::BuildStatement(CloneStatement::Resolved(
                        *id, *source,
                    )));
                    tasks.push(CloneTask::Visit(CloneNode::Statement(statement)));
                }
                Statement::Let {
                    mutable,
                    pat,
                    ty,
                    value,
                } => {
                    tasks.push(CloneTask::BuildStatement(CloneStatement::Let {
                        mutable: *mutable,
                        pat,
                        has_type: ty.is_some(),
                    }));
                    tasks.push(CloneTask::Visit(CloneNode::Expr(value)));
                    if let Some(ty) = ty {
                        tasks.push(CloneTask::Visit(CloneNode::Type(ty)));
                    }
                }
                Statement::Assign { name, value } => {
                    tasks.push(CloneTask::BuildStatement(CloneStatement::Assign(name)));
                    tasks.push(CloneTask::Visit(CloneNode::Expr(value)));
                }
                Statement::AssignExpr { target, op, value } => {
                    tasks.push(CloneTask::BuildStatement(CloneStatement::AssignExpr(*op)));
                    tasks.push(CloneTask::Visit(CloneNode::Expr(value)));
                    tasks.push(CloneTask::Visit(CloneNode::Expr(target)));
                }
                Statement::Emit(expression) => {
                    tasks.push(CloneTask::BuildStatement(CloneStatement::Emit));
                    tasks.push(CloneTask::Visit(CloneNode::Expr(expression)));
                }
                Statement::Expr(expression) => {
                    tasks.push(CloneTask::BuildStatement(CloneStatement::Expr));
                    tasks.push(CloneTask::Visit(CloneNode::Expr(expression)));
                }
                Statement::Return(Some(expression)) => {
                    tasks.push(CloneTask::BuildStatement(CloneStatement::Return));
                    tasks.push(CloneTask::Visit(CloneNode::Expr(expression)));
                }
                Statement::Return(None) => {
                    values.push(CloneValue::Statement(Statement::Return(None)));
                }
                Statement::Break => values.push(CloneValue::Statement(Statement::Break)),
                Statement::Continue => values.push(CloneValue::Statement(Statement::Continue)),
                Statement::If {
                    cond,
                    then_branch,
                    else_branch,
                } => {
                    tasks.push(CloneTask::BuildStatement(CloneStatement::If {
                        has_else: else_branch.is_some(),
                    }));
                    if let Some(else_branch) = else_branch {
                        tasks.push(CloneTask::Visit(CloneNode::Block(else_branch)));
                    }
                    tasks.push(CloneTask::Visit(CloneNode::Block(then_branch)));
                    tasks.push(CloneTask::Visit(CloneNode::Expr(cond)));
                }
                Statement::IfLet {
                    pattern,
                    value,
                    then_branch,
                    else_branch,
                } => {
                    tasks.push(CloneTask::BuildStatement(CloneStatement::IfLet {
                        pattern,
                        has_else: else_branch.is_some(),
                    }));
                    if let Some(else_branch) = else_branch {
                        tasks.push(CloneTask::Visit(CloneNode::Block(else_branch)));
                    }
                    tasks.push(CloneTask::Visit(CloneNode::Block(then_branch)));
                    tasks.push(CloneTask::Visit(CloneNode::Expr(value)));
                }
                Statement::While { cond, body } => {
                    tasks.push(CloneTask::BuildStatement(CloneStatement::While));
                    tasks.push(CloneTask::Visit(CloneNode::Block(body)));
                    tasks.push(CloneTask::Visit(CloneNode::Expr(cond)));
                }
                Statement::For {
                    line,
                    init,
                    cond,
                    step,
                    body,
                } => {
                    tasks.push(CloneTask::BuildStatement(CloneStatement::For {
                        line: *line,
                        has_init: init.is_some(),
                        has_cond: cond.is_some(),
                        has_step: step.is_some(),
                    }));
                    tasks.push(CloneTask::Visit(CloneNode::Block(body)));
                    if let Some(step) = step {
                        tasks.push(CloneTask::Visit(CloneNode::Statement(step)));
                    }
                    if let Some(cond) = cond {
                        tasks.push(CloneTask::Visit(CloneNode::Expr(cond)));
                    }
                    if let Some(init) = init {
                        tasks.push(CloneTask::Visit(CloneNode::Statement(init)));
                    }
                }
                Statement::ForEachMap { pat, map, body } => {
                    tasks.push(CloneTask::BuildStatement(CloneStatement::ForEachMap {
                        pat,
                    }));
                    tasks.push(CloneTask::Visit(CloneNode::Block(body)));
                    tasks.push(CloneTask::Visit(CloneNode::Expr(map)));
                }
            },
            CloneTask::Visit(CloneNode::Block(block)) => {
                tasks.push(CloneTask::BuildBlock {
                    statement_count: block.statements.len(),
                    has_tail: block.tail.is_some(),
                });
                if let Some(tail) = &block.tail {
                    tasks.push(CloneTask::Visit(CloneNode::Expr(tail)));
                }
                tasks.extend(
                    block
                        .statements
                        .iter()
                        .rev()
                        .map(|statement| CloneTask::Visit(CloneNode::Statement(statement))),
                );
            }
            CloneTask::BuildExpr(builder) => {
                let child_count = match &builder {
                    CloneExpr::Source(..)
                    | CloneExpr::Resolved(..)
                    | CloneExpr::Unary(..)
                    | CloneExpr::Wrapped(..)
                    | CloneExpr::Member(..) => 1,
                    CloneExpr::Binary(..) | CloneExpr::Index => 2,
                    CloneExpr::Conditional => 3,
                    CloneExpr::If { has_else } | CloneExpr::IfLet { has_else, .. } => {
                        2 + usize::from(*has_else)
                    }
                    CloneExpr::Match(arms) => 1 + arms.len(),
                    CloneExpr::Call { argument_count, .. } => *argument_count,
                    CloneExpr::StructLiteral { fields, .. } => fields.len(),
                    CloneExpr::Sequence(_, count) => *count,
                    CloneExpr::ListComprehension { has_condition, .. } => {
                        2 + usize::from(*has_condition)
                    }
                    CloneExpr::JsonObject(entries) => entries.len(),
                };
                let mut children = take_clone_children(&mut values, child_count).into_iter();
                let expression = match builder {
                    CloneExpr::Source(node, source) => Expr::Source {
                        node,
                        source,
                        expression: Box::new(children.next().unwrap().into_expr()),
                    },
                    CloneExpr::Resolved(id, source) => Expr::Resolved {
                        id,
                        source,
                        expression: Box::new(children.next().unwrap().into_expr()),
                    },
                    CloneExpr::Binary(op) => Expr::Binary {
                        op,
                        left: Box::new(children.next().unwrap().into_expr()),
                        right: Box::new(children.next().unwrap().into_expr()),
                    },
                    CloneExpr::Unary(op) => Expr::Unary {
                        op,
                        expr: Box::new(children.next().unwrap().into_expr()),
                    },
                    CloneExpr::Conditional => Expr::Conditional {
                        cond: Box::new(children.next().unwrap().into_expr()),
                        then_expr: Box::new(children.next().unwrap().into_expr()),
                        else_expr: Box::new(children.next().unwrap().into_expr()),
                    },
                    CloneExpr::If { has_else } => Expr::If {
                        condition: Box::new(children.next().unwrap().into_expr()),
                        then_branch: children.next().unwrap().into_block(),
                        else_branch: has_else.then(|| children.next().unwrap().into_block()),
                    },
                    CloneExpr::IfLet { pattern, has_else } => Expr::IfLet {
                        pattern: pattern.clone(),
                        value: Box::new(children.next().unwrap().into_expr()),
                        then_branch: children.next().unwrap().into_block(),
                        else_branch: has_else.then(|| children.next().unwrap().into_block()),
                    },
                    CloneExpr::Match(arms) => Expr::Match {
                        value: Box::new(children.next().unwrap().into_expr()),
                        arms: arms
                            .iter()
                            .map(|arm| MatchArm {
                                pattern: arm.pattern.clone(),
                                body: children.next().unwrap().into_block(),
                            })
                            .collect(),
                    },
                    CloneExpr::Wrapped(kind) => {
                        let child = Box::new(children.next().unwrap().into_expr());
                        match kind {
                            WrappedExpr::OptionSome => Expr::OptionSome(child),
                            WrappedExpr::ResultOk => Expr::ResultOk(child),
                            WrappedExpr::ResultErr => Expr::ResultErr(child),
                            WrappedExpr::Propagate => Expr::Propagate(child),
                        }
                    }
                    CloneExpr::Call {
                        name,
                        argument_names,
                        implicit_receiver,
                        ..
                    } => Expr::Call {
                        name: name.to_owned(),
                        args: children.by_ref().map(CloneValue::into_expr).collect(),
                        argument_names: argument_names.clone(),
                        implicit_receiver,
                    },
                    CloneExpr::StructLiteral { name, fields } => {
                        let fields = fields
                            .iter()
                            .map(|field| StructLiteralField {
                                name: field.name.clone(),
                                value: children.next().unwrap().into_expr(),
                                shorthand: field.shorthand,
                            })
                            .collect();
                        match name {
                            Some(name) => Expr::StructLiteral {
                                name: name.to_owned(),
                                fields,
                            },
                            None => Expr::ArgumentRecord { fields },
                        }
                    }
                    CloneExpr::Member(field) => Expr::Member {
                        object: Box::new(children.next().unwrap().into_expr()),
                        field: field.to_owned(),
                    },
                    CloneExpr::Index => Expr::Index {
                        target: Box::new(children.next().unwrap().into_expr()),
                        index: Box::new(children.next().unwrap().into_expr()),
                    },
                    CloneExpr::Sequence(kind, _) => {
                        let items = children.by_ref().map(CloneValue::into_expr).collect();
                        match kind {
                            SequenceExpr::Tuple => Expr::Tuple(items),
                            SequenceExpr::List => Expr::List(items),
                            SequenceExpr::JsonArray => Expr::JsonArray(items),
                        }
                    }
                    CloneExpr::ListComprehension {
                        item,
                        has_condition,
                    } => Expr::ListComprehension {
                        expression: Box::new(children.next().unwrap().into_expr()),
                        item: item.to_owned(),
                        source: Box::new(children.next().unwrap().into_expr()),
                        condition: has_condition
                            .then(|| Box::new(children.next().unwrap().into_expr())),
                    },
                    CloneExpr::JsonObject(entries) => Expr::JsonObject(
                        entries
                            .iter()
                            .map(|entry| JsonObjectEntry {
                                key: entry.key.clone(),
                                key_spelling: entry.key_spelling.clone(),
                                key_range: entry.key_range,
                                value: children.next().unwrap().into_expr(),
                            })
                            .collect(),
                    ),
                };
                debug_assert!(children.next().is_none());
                values.push(CloneValue::Expr(expression));
            }
            CloneTask::BuildStatement(builder) => {
                let child_count = match &builder {
                    CloneStatement::Source(..)
                    | CloneStatement::Resolved(..)
                    | CloneStatement::Assign(..)
                    | CloneStatement::Expr
                    | CloneStatement::Emit
                    | CloneStatement::Return => 1,
                    CloneStatement::Let { has_type, .. } => 1 + usize::from(*has_type),
                    CloneStatement::AssignExpr(..) | CloneStatement::While => 2,
                    CloneStatement::If { has_else } | CloneStatement::IfLet { has_else, .. } => {
                        2 + usize::from(*has_else)
                    }
                    CloneStatement::For {
                        has_init,
                        has_cond,
                        has_step,
                        ..
                    } => {
                        usize::from(*has_init) + usize::from(*has_cond) + usize::from(*has_step) + 1
                    }
                    CloneStatement::ForEachMap { .. } => 2,
                };
                let mut children = take_clone_children(&mut values, child_count).into_iter();
                let statement = match builder {
                    CloneStatement::Source(node, source) => Statement::Source {
                        node,
                        source,
                        statement: Box::new(children.next().unwrap().into_statement()),
                    },
                    CloneStatement::Resolved(id, source) => Statement::Resolved {
                        id,
                        source,
                        statement: Box::new(children.next().unwrap().into_statement()),
                    },
                    CloneStatement::Let {
                        mutable,
                        pat,
                        has_type,
                    } => Statement::Let {
                        mutable,
                        pat: pat.clone(),
                        ty: has_type.then(|| children.next().unwrap().into_type()),
                        value: children.next().unwrap().into_expr(),
                    },
                    CloneStatement::Assign(name) => Statement::Assign {
                        name: name.to_owned(),
                        value: children.next().unwrap().into_expr(),
                    },
                    CloneStatement::AssignExpr(op) => Statement::AssignExpr {
                        target: children.next().unwrap().into_expr(),
                        op,
                        value: children.next().unwrap().into_expr(),
                    },
                    CloneStatement::Expr => Statement::Expr(children.next().unwrap().into_expr()),
                    CloneStatement::Emit => Statement::Emit(children.next().unwrap().into_expr()),
                    CloneStatement::Return => {
                        Statement::Return(Some(children.next().unwrap().into_expr()))
                    }
                    CloneStatement::If { has_else } => Statement::If {
                        cond: children.next().unwrap().into_expr(),
                        then_branch: children.next().unwrap().into_block(),
                        else_branch: has_else.then(|| children.next().unwrap().into_block()),
                    },
                    CloneStatement::IfLet { pattern, has_else } => Statement::IfLet {
                        pattern: pattern.clone(),
                        value: children.next().unwrap().into_expr(),
                        then_branch: children.next().unwrap().into_block(),
                        else_branch: has_else.then(|| children.next().unwrap().into_block()),
                    },
                    CloneStatement::While => Statement::While {
                        cond: children.next().unwrap().into_expr(),
                        body: children.next().unwrap().into_block(),
                    },
                    CloneStatement::For {
                        line,
                        has_init,
                        has_cond,
                        has_step,
                    } => Statement::For {
                        line,
                        init: has_init.then(|| Box::new(children.next().unwrap().into_statement())),
                        cond: has_cond.then(|| children.next().unwrap().into_expr()),
                        step: has_step.then(|| Box::new(children.next().unwrap().into_statement())),
                        body: children.next().unwrap().into_block(),
                    },
                    CloneStatement::ForEachMap { pat } => Statement::ForEachMap {
                        pat: pat.clone(),
                        map: children.next().unwrap().into_expr(),
                        body: children.next().unwrap().into_block(),
                    },
                };
                debug_assert!(children.next().is_none());
                values.push(CloneValue::Statement(statement));
            }
            CloneTask::BuildBlock {
                statement_count,
                has_tail,
            } => {
                let mut children =
                    take_clone_children(&mut values, statement_count + usize::from(has_tail))
                        .into_iter();
                let statements = children
                    .by_ref()
                    .take(statement_count)
                    .map(CloneValue::into_statement)
                    .collect();
                let tail = has_tail.then(|| Box::new(children.next().unwrap().into_expr()));
                debug_assert!(children.next().is_none());
                values.push(CloneValue::Block(Block { statements, tail }));
            }
        }
    }
    assert_eq!(values.len(), 1, "AST clone traversal produced one root");
    values.pop().unwrap()
}

fn clone_expr_iterative(expression: &Expr) -> Expr {
    clone_ast_node(CloneNode::Expr(expression)).into_expr()
}

fn clone_statement_iterative(statement: &Statement) -> Statement {
    clone_ast_node(CloneNode::Statement(statement)).into_statement()
}

enum CompareNode<'a> {
    Type(&'a TypeExpr, &'a TypeExpr),
    Expr(&'a Expr, &'a Expr),
    Statement(&'a Statement, &'a Statement),
    Block(&'a Block, &'a Block),
}

fn compare_type_nodes<'a>(
    left: &'a TypeExpr,
    right: &'a TypeExpr,
    pending: &mut Vec<CompareNode<'a>>,
) -> bool {
    match (left, right) {
        (
            TypeExpr::Source {
                node: left_node,
                source: left_source,
                ty: left_ty,
            },
            TypeExpr::Source {
                node: right_node,
                source: right_source,
                ty: right_ty,
            },
        ) => {
            if left_node != right_node || left_source != right_source {
                return false;
            }
            pending.push(CompareNode::Type(left_ty, right_ty));
        }
        (
            TypeExpr::Resolved {
                id: left_id,
                source: left_source,
                ty: left_ty,
            },
            TypeExpr::Resolved {
                id: right_id,
                source: right_source,
                ty: right_ty,
            },
        ) => {
            if left_id != right_id || left_source != right_source {
                return false;
            }
            pending.push(CompareNode::Type(left_ty, right_ty));
        }
        (TypeExpr::Path(left), TypeExpr::Path(right)) => {
            if left != right {
                return false;
            }
        }
        (
            TypeExpr::Generic {
                base: left_base,
                args: left_args,
            },
            TypeExpr::Generic {
                base: right_base,
                args: right_args,
            },
        ) => {
            if left_base != right_base || left_args.len() != right_args.len() {
                return false;
            }
            pending.extend(
                left_args
                    .iter()
                    .zip(right_args)
                    .rev()
                    .map(|(left, right)| CompareNode::Type(left, right)),
            );
        }
        (TypeExpr::Tuple(left), TypeExpr::Tuple(right)) => {
            if left.len() != right.len() {
                return false;
            }
            pending.extend(
                left.iter()
                    .zip(right)
                    .rev()
                    .map(|(left, right)| CompareNode::Type(left, right)),
            );
        }
        (TypeExpr::Const(left), TypeExpr::Const(right)) => {
            if left != right {
                return false;
            }
        }
        (TypeExpr::ConstExpression(left), TypeExpr::ConstExpression(right)) => {
            pending.push(CompareNode::Expr(left, right));
        }
        _ => return false,
    }
    true
}

fn ast_nodes_equal(root: CompareNode<'_>) -> bool {
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        match node {
            CompareNode::Type(left, right) => {
                if !compare_type_nodes(left, right, &mut pending) {
                    return false;
                }
            }
            CompareNode::Block(left, right) => {
                if left.statements.len() != right.statements.len()
                    || left.tail.is_some() != right.tail.is_some()
                {
                    return false;
                }
                if let (Some(left), Some(right)) = (&left.tail, &right.tail) {
                    pending.push(CompareNode::Expr(left, right));
                }
                pending.extend(
                    left.statements
                        .iter()
                        .zip(&right.statements)
                        .rev()
                        .map(|(left, right)| CompareNode::Statement(left, right)),
                );
            }
            CompareNode::Statement(left, right) => match (left, right) {
                (
                    Statement::Source {
                        node: left_node,
                        source: left_source,
                        statement: left_statement,
                    },
                    Statement::Source {
                        node: right_node,
                        source: right_source,
                        statement: right_statement,
                    },
                ) => {
                    if left_node != right_node || left_source != right_source {
                        return false;
                    }
                    pending.push(CompareNode::Statement(left_statement, right_statement));
                }
                (
                    Statement::Resolved {
                        id: left_id,
                        source: left_source,
                        statement: left_statement,
                    },
                    Statement::Resolved {
                        id: right_id,
                        source: right_source,
                        statement: right_statement,
                    },
                ) => {
                    if left_id != right_id || left_source != right_source {
                        return false;
                    }
                    pending.push(CompareNode::Statement(left_statement, right_statement));
                }
                (
                    Statement::Let {
                        mutable: left_mutable,
                        pat: left_pattern,
                        ty: left_ty,
                        value: left_value,
                    },
                    Statement::Let {
                        mutable: right_mutable,
                        pat: right_pattern,
                        ty: right_ty,
                        value: right_value,
                    },
                ) => {
                    if left_mutable != right_mutable
                        || left_pattern != right_pattern
                        || left_ty.is_some() != right_ty.is_some()
                    {
                        return false;
                    }
                    pending.push(CompareNode::Expr(left_value, right_value));
                    if let (Some(left), Some(right)) = (left_ty, right_ty) {
                        pending.push(CompareNode::Type(left, right));
                    }
                }
                (
                    Statement::Assign {
                        name: left_name,
                        value: left_value,
                    },
                    Statement::Assign {
                        name: right_name,
                        value: right_value,
                    },
                ) => {
                    if left_name != right_name {
                        return false;
                    }
                    pending.push(CompareNode::Expr(left_value, right_value));
                }
                (
                    Statement::AssignExpr {
                        target: left_target,
                        op: left_op,
                        value: left_value,
                    },
                    Statement::AssignExpr {
                        target: right_target,
                        op: right_op,
                        value: right_value,
                    },
                ) => {
                    if left_op != right_op {
                        return false;
                    }
                    pending.push(CompareNode::Expr(left_value, right_value));
                    pending.push(CompareNode::Expr(left_target, right_target));
                }
                (Statement::Expr(left), Statement::Expr(right))
                | (Statement::Emit(left), Statement::Emit(right)) => {
                    pending.push(CompareNode::Expr(left, right));
                }
                (Statement::Return(left), Statement::Return(right)) => match (left, right) {
                    (Some(left), Some(right)) => pending.push(CompareNode::Expr(left, right)),
                    (None, None) => {}
                    _ => return false,
                },
                (Statement::Break, Statement::Break)
                | (Statement::Continue, Statement::Continue) => {}
                (
                    Statement::If {
                        cond: left_cond,
                        then_branch: left_then,
                        else_branch: left_else,
                    },
                    Statement::If {
                        cond: right_cond,
                        then_branch: right_then,
                        else_branch: right_else,
                    },
                ) => {
                    if left_else.is_some() != right_else.is_some() {
                        return false;
                    }
                    if let (Some(left), Some(right)) = (left_else, right_else) {
                        pending.push(CompareNode::Block(left, right));
                    }
                    pending.push(CompareNode::Block(left_then, right_then));
                    pending.push(CompareNode::Expr(left_cond, right_cond));
                }
                (
                    Statement::IfLet {
                        pattern: left_pattern,
                        value: left_value,
                        then_branch: left_then,
                        else_branch: left_else,
                    },
                    Statement::IfLet {
                        pattern: right_pattern,
                        value: right_value,
                        then_branch: right_then,
                        else_branch: right_else,
                    },
                ) => {
                    if left_pattern != right_pattern || left_else.is_some() != right_else.is_some()
                    {
                        return false;
                    }
                    if let (Some(left), Some(right)) = (left_else, right_else) {
                        pending.push(CompareNode::Block(left, right));
                    }
                    pending.push(CompareNode::Block(left_then, right_then));
                    pending.push(CompareNode::Expr(left_value, right_value));
                }
                (
                    Statement::While {
                        cond: left_cond,
                        body: left_body,
                    },
                    Statement::While {
                        cond: right_cond,
                        body: right_body,
                    },
                ) => {
                    pending.push(CompareNode::Block(left_body, right_body));
                    pending.push(CompareNode::Expr(left_cond, right_cond));
                }
                (
                    Statement::For {
                        line: left_line,
                        init: left_init,
                        cond: left_cond,
                        step: left_step,
                        body: left_body,
                    },
                    Statement::For {
                        line: right_line,
                        init: right_init,
                        cond: right_cond,
                        step: right_step,
                        body: right_body,
                    },
                ) => {
                    if left_line != right_line
                        || left_init.is_some() != right_init.is_some()
                        || left_cond.is_some() != right_cond.is_some()
                        || left_step.is_some() != right_step.is_some()
                    {
                        return false;
                    }
                    pending.push(CompareNode::Block(left_body, right_body));
                    if let (Some(left), Some(right)) = (left_step, right_step) {
                        pending.push(CompareNode::Statement(left, right));
                    }
                    if let (Some(left), Some(right)) = (left_cond, right_cond) {
                        pending.push(CompareNode::Expr(left, right));
                    }
                    if let (Some(left), Some(right)) = (left_init, right_init) {
                        pending.push(CompareNode::Statement(left, right));
                    }
                }
                (
                    Statement::ForEachMap {
                        pat: left_pat,
                        map: left_map,
                        body: left_body,
                    },
                    Statement::ForEachMap {
                        pat: right_pat,
                        map: right_map,
                        body: right_body,
                    },
                ) => {
                    if left_pat != right_pat {
                        return false;
                    }
                    pending.push(CompareNode::Block(left_body, right_body));
                    pending.push(CompareNode::Expr(left_map, right_map));
                }
                _ => return false,
            },
            CompareNode::Expr(left, right) => match (left, right) {
                (
                    Expr::Source {
                        node: left_node,
                        source: left_source,
                        expression: left_expression,
                    },
                    Expr::Source {
                        node: right_node,
                        source: right_source,
                        expression: right_expression,
                    },
                ) => {
                    if left_node != right_node || left_source != right_source {
                        return false;
                    }
                    pending.push(CompareNode::Expr(left_expression, right_expression));
                }
                (
                    Expr::Resolved {
                        id: left_id,
                        source: left_source,
                        expression: left_expression,
                    },
                    Expr::Resolved {
                        id: right_id,
                        source: right_source,
                        expression: right_expression,
                    },
                ) => {
                    if left_id != right_id || left_source != right_source {
                        return false;
                    }
                    pending.push(CompareNode::Expr(left_expression, right_expression));
                }
                (
                    Expr::Binary {
                        op: left_op,
                        left: left_left,
                        right: left_right,
                    },
                    Expr::Binary {
                        op: right_op,
                        left: right_left,
                        right: right_right,
                    },
                ) => {
                    if left_op != right_op {
                        return false;
                    }
                    pending.push(CompareNode::Expr(left_right, right_right));
                    pending.push(CompareNode::Expr(left_left, right_left));
                }
                (
                    Expr::Unary {
                        op: left_op,
                        expr: left_expression,
                    },
                    Expr::Unary {
                        op: right_op,
                        expr: right_expression,
                    },
                ) => {
                    if left_op != right_op {
                        return false;
                    }
                    pending.push(CompareNode::Expr(left_expression, right_expression));
                }
                (
                    Expr::Conditional {
                        cond: left_cond,
                        then_expr: left_then,
                        else_expr: left_else,
                    },
                    Expr::Conditional {
                        cond: right_cond,
                        then_expr: right_then,
                        else_expr: right_else,
                    },
                ) => {
                    pending.push(CompareNode::Expr(left_else, right_else));
                    pending.push(CompareNode::Expr(left_then, right_then));
                    pending.push(CompareNode::Expr(left_cond, right_cond));
                }
                (
                    Expr::If {
                        condition: left_condition,
                        then_branch: left_then,
                        else_branch: left_else,
                    },
                    Expr::If {
                        condition: right_condition,
                        then_branch: right_then,
                        else_branch: right_else,
                    },
                ) => {
                    if left_else.is_some() != right_else.is_some() {
                        return false;
                    }
                    if let (Some(left), Some(right)) = (left_else, right_else) {
                        pending.push(CompareNode::Block(left, right));
                    }
                    pending.push(CompareNode::Block(left_then, right_then));
                    pending.push(CompareNode::Expr(left_condition, right_condition));
                }
                (
                    Expr::IfLet {
                        pattern: left_pattern,
                        value: left_value,
                        then_branch: left_then,
                        else_branch: left_else,
                    },
                    Expr::IfLet {
                        pattern: right_pattern,
                        value: right_value,
                        then_branch: right_then,
                        else_branch: right_else,
                    },
                ) => {
                    if left_pattern != right_pattern || left_else.is_some() != right_else.is_some()
                    {
                        return false;
                    }
                    if let (Some(left), Some(right)) = (left_else, right_else) {
                        pending.push(CompareNode::Block(left, right));
                    }
                    pending.push(CompareNode::Block(left_then, right_then));
                    pending.push(CompareNode::Expr(left_value, right_value));
                }
                (
                    Expr::Match {
                        value: left_value,
                        arms: left_arms,
                    },
                    Expr::Match {
                        value: right_value,
                        arms: right_arms,
                    },
                ) => {
                    if left_arms.len() != right_arms.len()
                        || left_arms
                            .iter()
                            .zip(right_arms)
                            .any(|(left, right)| left.pattern != right.pattern)
                    {
                        return false;
                    }
                    pending.extend(
                        left_arms
                            .iter()
                            .zip(right_arms)
                            .rev()
                            .map(|(left, right)| CompareNode::Block(&left.body, &right.body)),
                    );
                    pending.push(CompareNode::Expr(left_value, right_value));
                }
                (Expr::OptionSome(left), Expr::OptionSome(right))
                | (Expr::ResultOk(left), Expr::ResultOk(right))
                | (Expr::ResultErr(left), Expr::ResultErr(right))
                | (Expr::Propagate(left), Expr::Propagate(right)) => {
                    pending.push(CompareNode::Expr(left, right));
                }
                (Expr::OptionNone, Expr::OptionNone) => {}
                (
                    Expr::Call {
                        name: left_name,
                        args: left_args,
                        argument_names: left_names,
                        implicit_receiver: left_receiver,
                    },
                    Expr::Call {
                        name: right_name,
                        args: right_args,
                        argument_names: right_names,
                        implicit_receiver: right_receiver,
                    },
                ) => {
                    if left_name != right_name
                        || left_names != right_names
                        || left_receiver != right_receiver
                        || left_args.len() != right_args.len()
                    {
                        return false;
                    }
                    pending.extend(
                        left_args
                            .iter()
                            .zip(right_args)
                            .rev()
                            .map(|(left, right)| CompareNode::Expr(left, right)),
                    );
                }
                (
                    Expr::StructLiteral {
                        name: left_name,
                        fields: left_fields,
                    },
                    Expr::StructLiteral {
                        name: right_name,
                        fields: right_fields,
                    },
                ) => {
                    if left_name != right_name
                        || left_fields.len() != right_fields.len()
                        || left_fields.iter().zip(right_fields).any(|(left, right)| {
                            left.name != right.name || left.shorthand != right.shorthand
                        })
                    {
                        return false;
                    }
                    pending.extend(
                        left_fields
                            .iter()
                            .zip(right_fields)
                            .rev()
                            .map(|(left, right)| CompareNode::Expr(&left.value, &right.value)),
                    );
                }
                (
                    Expr::ArgumentRecord {
                        fields: left_fields,
                    },
                    Expr::ArgumentRecord {
                        fields: right_fields,
                    },
                ) => {
                    if left_fields.len() != right_fields.len()
                        || left_fields.iter().zip(right_fields).any(|(left, right)| {
                            left.name != right.name || left.shorthand != right.shorthand
                        })
                    {
                        return false;
                    }
                    pending.extend(
                        left_fields
                            .iter()
                            .zip(right_fields)
                            .rev()
                            .map(|(left, right)| CompareNode::Expr(&left.value, &right.value)),
                    );
                }
                (
                    Expr::Member {
                        object: left_object,
                        field: left_field,
                    },
                    Expr::Member {
                        object: right_object,
                        field: right_field,
                    },
                ) => {
                    if left_field != right_field {
                        return false;
                    }
                    pending.push(CompareNode::Expr(left_object, right_object));
                }
                (
                    Expr::Index {
                        target: left_target,
                        index: left_index,
                    },
                    Expr::Index {
                        target: right_target,
                        index: right_index,
                    },
                ) => {
                    pending.push(CompareNode::Expr(left_index, right_index));
                    pending.push(CompareNode::Expr(left_target, right_target));
                }
                (Expr::Tuple(left), Expr::Tuple(right))
                | (Expr::List(left), Expr::List(right))
                | (Expr::JsonArray(left), Expr::JsonArray(right)) => {
                    if left.len() != right.len() {
                        return false;
                    }
                    pending.extend(
                        left.iter()
                            .zip(right)
                            .rev()
                            .map(|(left, right)| CompareNode::Expr(left, right)),
                    );
                }
                (
                    Expr::ListComprehension {
                        expression: left_expression,
                        item: left_item,
                        source: left_source,
                        condition: left_condition,
                    },
                    Expr::ListComprehension {
                        expression: right_expression,
                        item: right_item,
                        source: right_source,
                        condition: right_condition,
                    },
                ) => {
                    if left_item != right_item
                        || left_condition.is_some() != right_condition.is_some()
                    {
                        return false;
                    }
                    if let (Some(left), Some(right)) = (left_condition, right_condition) {
                        pending.push(CompareNode::Expr(left, right));
                    }
                    pending.push(CompareNode::Expr(left_source, right_source));
                    pending.push(CompareNode::Expr(left_expression, right_expression));
                }
                (Expr::JsonObject(left), Expr::JsonObject(right)) => {
                    if left.len() != right.len()
                        || left.iter().zip(right).any(|(left, right)| {
                            left.key != right.key
                                || left.key_spelling != right.key_spelling
                                || left.key_range != right.key_range
                        })
                    {
                        return false;
                    }
                    pending.extend(
                        left.iter()
                            .zip(right)
                            .rev()
                            .map(|(left, right)| CompareNode::Expr(&left.value, &right.value)),
                    );
                }
                (Expr::Bool(left), Expr::Bool(right)) => {
                    if left != right {
                        return false;
                    }
                }
                (Expr::IntLiteral(left), Expr::IntLiteral(right)) => {
                    if left != right {
                        return false;
                    }
                }
                (Expr::DecimalLiteral(left), Expr::DecimalLiteral(right))
                | (Expr::String(left), Expr::String(right))
                | (Expr::Ident(left), Expr::Ident(right)) => {
                    if left != right {
                        return false;
                    }
                }
                (Expr::Bytes(left), Expr::Bytes(right)) => {
                    if left != right {
                        return false;
                    }
                }
                _ => return false,
            },
        }
    }
    true
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
    /// Integer modulo (remainder) operator: `a % b`.
    Mod,
    And,
    Or,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UnaryOp {
    Neg,
    Not,
}
impl TypeExpr {
    /// Return this type's exact source range when it came from source text.
    #[must_use]
    pub const fn source(&self) -> Option<SourceRange> {
        let mut current = self;
        loop {
            match current {
                Self::Source { source, .. }
                | Self::Resolved {
                    source: Some(source),
                    ..
                } => return Some(*source),
                Self::Resolved {
                    ty, source: None, ..
                } => current = ty,
                _ => return None,
            }
        }
    }
    /// Return the stable resolved-HIR identity, when name resolution has run.
    #[must_use]
    pub const fn hir_id(&self) -> Option<HirId> {
        let mut current = self;
        loop {
            match current {
                Self::Resolved { id, .. } => return Some(*id),
                Self::Source { ty, .. } => current = ty,
                _ => return None,
            }
        }
    }
    /// Return the parser-owned source identity before resolved-HIR lowering.
    #[must_use]
    pub const fn source_node(&self) -> Option<NodeId> {
        let mut current = self;
        loop {
            match current {
                Self::Source { node, .. } => return Some(*node),
                Self::Resolved { ty, .. } => current = ty,
                _ => return None,
            }
        }
    }
    /// View the semantic type form without its source wrapper.
    #[must_use]
    pub fn kind(&self) -> &Self {
        let mut current = self;
        loop {
            match current {
                Self::Source { ty, .. } | Self::Resolved { ty, .. } => current = ty,
                _ => return current,
            }
        }
    }
    /// Consume the source wrapper and return the semantic type form.
    #[must_use]
    pub fn into_kind(mut self) -> Self {
        loop {
            self = match self {
                Self::Source { ty, .. } | Self::Resolved { ty, .. } => *ty,
                leaf => return leaf,
            };
        }
    }
}
impl Statement {
    /// Return this statement's exact source range when it came from source text.
    #[must_use]
    pub const fn source(&self) -> Option<SourceRange> {
        let mut current = self;
        loop {
            match current {
                Self::Source { source, .. }
                | Self::Resolved {
                    source: Some(source),
                    ..
                } => return Some(*source),
                Self::Resolved {
                    statement,
                    source: None,
                    ..
                } => current = statement,
                _ => return None,
            }
        }
    }
    /// Return the stable resolved-HIR identity, when name resolution has run.
    #[must_use]
    pub const fn hir_id(&self) -> Option<HirId> {
        let mut current = self;
        loop {
            match current {
                Self::Resolved { id, .. } => return Some(*id),
                Self::Source { statement, .. } => current = statement,
                _ => return None,
            }
        }
    }
    /// Return the parser-owned source identity before resolved-HIR lowering.
    #[must_use]
    pub const fn source_node(&self) -> Option<NodeId> {
        let mut current = self;
        loop {
            match current {
                Self::Source { node, .. } => return Some(*node),
                Self::Resolved { statement, .. } => current = statement,
                _ => return None,
            }
        }
    }
    /// View the semantic statement form without its source wrapper.
    #[must_use]
    pub fn kind(&self) -> &Self {
        let mut current = self;
        loop {
            match current {
                Self::Source { statement, .. } | Self::Resolved { statement, .. } => {
                    current = statement
                }
                _ => return current,
            }
        }
    }
    /// Consume the source wrapper and return the semantic statement form.
    #[must_use]
    pub fn into_kind(mut self) -> Self {
        loop {
            self = match self {
                Self::Source { statement, .. } | Self::Resolved { statement, .. } => *statement,
                leaf => return leaf,
            };
        }
    }
}
impl Expr {
    /// Return this expression's exact source range when it came from source text.
    #[must_use]
    pub const fn source(&self) -> Option<SourceRange> {
        let mut current = self;
        loop {
            match current {
                Self::Source { source, .. }
                | Self::Resolved {
                    source: Some(source),
                    ..
                } => return Some(*source),
                Self::Resolved {
                    expression,
                    source: None,
                    ..
                } => current = expression,
                _ => return None,
            }
        }
    }
    /// Return the stable resolved-HIR identity, when name resolution has run.
    #[must_use]
    pub const fn hir_id(&self) -> Option<HirId> {
        let mut current = self;
        loop {
            match current {
                Self::Resolved { id, .. } => return Some(*id),
                Self::Source { expression, .. } => current = expression,
                _ => return None,
            }
        }
    }
    /// Return the parser-owned source identity before resolved-HIR lowering.
    #[must_use]
    pub const fn source_node(&self) -> Option<NodeId> {
        let mut current = self;
        loop {
            match current {
                Self::Source { node, .. } => return Some(*node),
                Self::Resolved { expression, .. } => current = expression,
                _ => return None,
            }
        }
    }
    /// View the semantic expression form without its source wrapper.
    #[must_use]
    pub fn kind(&self) -> &Self {
        let mut current = self;
        loop {
            match current {
                Self::Source { expression, .. } | Self::Resolved { expression, .. } => {
                    current = expression
                }
                _ => return current,
            }
        }
    }
    /// Consume the source wrapper and return the semantic expression form.
    #[must_use]
    pub fn into_kind(mut self) -> Self {
        loop {
            self = match self {
                Self::Source { expression, .. } | Self::Resolved { expression, .. } => *expression,
                leaf => return leaf,
            };
        }
    }
}
#[derive(Clone, Copy)]
enum ProvenanceAction {
    Rebase(crate::source::SourceId),
    Strip,
}
fn normalize_type_provenance(ty: &mut TypeExpr, action: ProvenanceAction) -> &mut TypeExpr {
    match action {
        ProvenanceAction::Rebase(source_id) => {
            let mut current = ty;
            loop {
                match current {
                    TypeExpr::Source { source, ty, .. } => {
                        source.source = source_id;
                        current = ty;
                    }
                    TypeExpr::Resolved { source, ty, .. } => {
                        if let Some(source) = source {
                            source.source = source_id;
                        }
                        current = ty;
                    }
                    _ => return current,
                }
            }
        }
        ProvenanceAction::Strip => loop {
            let current = std::mem::replace(ty, TypeExpr::Const(0));
            match current {
                TypeExpr::Source { ty: inner, .. } | TypeExpr::Resolved { ty: inner, .. } => {
                    *ty = *inner;
                }
                current => {
                    *ty = current;
                    return ty;
                }
            }
        },
    }
}
fn normalize_statement_provenance(
    statement: &mut Statement,
    action: ProvenanceAction,
) -> &mut Statement {
    match action {
        ProvenanceAction::Rebase(source_id) => {
            let mut current = statement;
            loop {
                match current {
                    Statement::Source {
                        source, statement, ..
                    } => {
                        source.source = source_id;
                        current = statement;
                    }
                    Statement::Resolved {
                        source, statement, ..
                    } => {
                        if let Some(source) = source {
                            source.source = source_id;
                        }
                        current = statement;
                    }
                    _ => return current,
                }
            }
        }
        ProvenanceAction::Strip => loop {
            let current = std::mem::replace(statement, Statement::Break);
            match current {
                Statement::Source {
                    statement: inner, ..
                }
                | Statement::Resolved {
                    statement: inner, ..
                } => {
                    *statement = *inner;
                }
                current => {
                    *statement = current;
                    return statement;
                }
            }
        },
    }
}
fn normalize_expr_provenance(expression: &mut Expr, action: ProvenanceAction) -> &mut Expr {
    match action {
        ProvenanceAction::Rebase(source_id) => {
            let mut current = expression;
            loop {
                match current {
                    Expr::Source {
                        source, expression, ..
                    } => {
                        source.source = source_id;
                        current = expression;
                    }
                    Expr::Resolved {
                        source, expression, ..
                    } => {
                        if let Some(source) = source {
                            source.source = source_id;
                        }
                        current = expression;
                    }
                    _ => return current,
                }
            }
        }
        ProvenanceAction::Strip => loop {
            let current = std::mem::replace(expression, Expr::IntLiteral(BigInt::zero()));
            match current {
                Expr::Source {
                    expression: inner, ..
                }
                | Expr::Resolved {
                    expression: inner, ..
                } => {
                    *expression = *inner;
                }
                current => {
                    *expression = current;
                    return expression;
                }
            }
        },
    }
}
fn transform_program_provenance(program: &mut Program, action: ProvenanceAction) {
    enum Pending<'a> {
        Type(&'a mut TypeExpr),
        Statement(&'a mut Statement),
        Expr(&'a mut Expr),
    }
    fn push_block<'a>(block: &'a mut Block, pending: &mut Vec<Pending<'a>>) {
        pending.extend(block.statements.iter_mut().map(Pending::Statement));
        if let Some(tail) = &mut block.tail {
            pending.push(Pending::Expr(tail));
        }
    }
    let mut pending = Vec::new();
    for item in &mut program.items {
        match item {
            Item::Function(function) => {
                pending.extend(
                    function
                        .params
                        .iter_mut()
                        .filter_map(|parameter| parameter.ty.as_mut())
                        .map(Pending::Type),
                );
                if let Some(ret_ty) = &mut function.ret_ty {
                    pending.push(Pending::Type(ret_ty));
                }
                push_block(&mut function.body, &mut pending);
            }
            Item::Struct(definition) | Item::Event(definition) => {
                pending.extend(
                    definition
                        .fields
                        .iter_mut()
                        .map(|(_, ty)| Pending::Type(ty)),
                );
            }
            Item::Const(declaration) => {
                if let Some(ty) = &mut declaration.ty {
                    pending.push(Pending::Type(ty));
                }
                pending.push(Pending::Expr(&mut declaration.value));
            }
            Item::State(declaration) => pending.push(Pending::Type(&mut declaration.ty)),
            Item::Trigger(declaration) => {
                pending.extend(
                    declaration
                        .metadata
                        .iter_mut()
                        .map(|entry| Pending::Expr(&mut entry.value)),
                );
                if let TriggerFilter::Time(TriggerTimeFilter::Schedule {
                    start_ms,
                    period_ms,
                }) = &mut declaration.filter
                {
                    pending.push(Pending::Expr(start_ms));
                    pending.extend(period_ms.iter_mut().map(|value| Pending::Expr(value)));
                }
            }
            Item::Enum(_) => {}
        }
    }
    for fixture in &mut program.fixtures {
        for fixture_action in &mut fixture.actions {
            pending.extend(fixture_action.args.iter_mut().map(Pending::Expr));
        }
    }
    while let Some(node) = pending.pop() {
        match node {
            Pending::Type(ty) => match normalize_type_provenance(ty, action) {
                TypeExpr::Generic { args, .. } | TypeExpr::Tuple(args) => {
                    pending.extend(args.iter_mut().map(Pending::Type));
                }
                TypeExpr::Path(_) | TypeExpr::Const(_) => {}
                TypeExpr::ConstExpression(value) => pending.push(Pending::Expr(value)),
                TypeExpr::Source { .. } | TypeExpr::Resolved { .. } => {
                    unreachable!("provenance normalization returns the semantic node")
                }
            },
            Pending::Statement(statement) => {
                match normalize_statement_provenance(statement, action) {
                    Statement::Let { ty, value, pat, .. } => {
                        if let Pattern::Struct { fields, .. } = pat {
                            for field in fields {
                                match action {
                                    ProvenanceAction::Rebase(source) => {
                                        if let Some(range) = &mut field.source {
                                            range.source = source;
                                        }
                                    }
                                    ProvenanceAction::Strip => field.source = None,
                                }
                            }
                        }
                        if let Some(ty) = ty {
                            pending.push(Pending::Type(ty));
                        }
                        pending.push(Pending::Expr(value));
                    }
                    Statement::Assign { value, .. }
                    | Statement::Expr(value)
                    | Statement::Emit(value) => {
                        pending.push(Pending::Expr(value));
                    }
                    Statement::AssignExpr { target, value, .. } => {
                        pending.push(Pending::Expr(target));
                        pending.push(Pending::Expr(value));
                    }
                    Statement::Return(value) => {
                        if let Some(value) = value {
                            pending.push(Pending::Expr(value));
                        }
                    }
                    Statement::If {
                        cond,
                        then_branch,
                        else_branch,
                    }
                    | Statement::IfLet {
                        value: cond,
                        then_branch,
                        else_branch,
                        ..
                    } => {
                        pending.push(Pending::Expr(cond));
                        push_block(then_branch, &mut pending);
                        if let Some(block) = else_branch {
                            push_block(block, &mut pending);
                        }
                    }
                    Statement::While { cond, body } => {
                        pending.push(Pending::Expr(cond));
                        push_block(body, &mut pending);
                    }
                    Statement::For {
                        init,
                        cond,
                        step,
                        body,
                        ..
                    } => {
                        if let Some(init) = init {
                            pending.push(Pending::Statement(init));
                        }
                        if let Some(cond) = cond {
                            pending.push(Pending::Expr(cond));
                        }
                        if let Some(step) = step {
                            pending.push(Pending::Statement(step));
                        }
                        push_block(body, &mut pending);
                    }
                    Statement::ForEachMap { pat, map, body } => {
                        if let Pattern::Struct { fields, .. } = pat {
                            for field in fields {
                                match action {
                                    ProvenanceAction::Rebase(source) => {
                                        if let Some(range) = &mut field.source {
                                            range.source = source;
                                        }
                                    }
                                    ProvenanceAction::Strip => field.source = None,
                                }
                            }
                        }
                        pending.push(Pending::Expr(map));
                        push_block(body, &mut pending);
                    }
                    Statement::Break | Statement::Continue => {}
                    Statement::Source { .. } | Statement::Resolved { .. } => {
                        unreachable!("provenance normalization returns the semantic node")
                    }
                }
            }
            Pending::Expr(expression) => match normalize_expr_provenance(expression, action) {
                Expr::Binary { left, right, .. }
                | Expr::Index {
                    target: left,
                    index: right,
                } => {
                    pending.push(Pending::Expr(left));
                    pending.push(Pending::Expr(right));
                }
                Expr::Unary { expr, .. }
                | Expr::Member { object: expr, .. }
                | Expr::OptionSome(expr)
                | Expr::ResultOk(expr)
                | Expr::ResultErr(expr)
                | Expr::Propagate(expr) => pending.push(Pending::Expr(expr)),
                Expr::Conditional {
                    cond,
                    then_expr,
                    else_expr,
                } => {
                    pending.push(Pending::Expr(cond));
                    pending.push(Pending::Expr(then_expr));
                    pending.push(Pending::Expr(else_expr));
                }
                Expr::If {
                    condition,
                    then_branch,
                    else_branch,
                }
                | Expr::IfLet {
                    value: condition,
                    then_branch,
                    else_branch,
                    ..
                } => {
                    pending.push(Pending::Expr(condition));
                    push_block(then_branch, &mut pending);
                    if let Some(block) = else_branch {
                        push_block(block, &mut pending);
                    }
                }
                Expr::Match { value, arms } => {
                    pending.push(Pending::Expr(value));
                    for arm in arms {
                        push_block(&mut arm.body, &mut pending);
                    }
                }
                Expr::Call { args, .. }
                | Expr::Tuple(args)
                | Expr::List(args)
                | Expr::JsonArray(args) => {
                    pending.extend(args.iter_mut().map(Pending::Expr));
                }
                Expr::ListComprehension {
                    expression,
                    source,
                    condition,
                    ..
                } => {
                    pending.push(Pending::Expr(expression));
                    pending.push(Pending::Expr(source));
                    if let Some(condition) = condition {
                        pending.push(Pending::Expr(condition));
                    }
                }
                Expr::StructLiteral { fields, .. } | Expr::ArgumentRecord { fields } => pending
                    .extend(
                        fields
                            .iter_mut()
                            .map(|field| Pending::Expr(&mut field.value)),
                    ),
                Expr::JsonObject(entries) => pending.extend(
                    entries
                        .iter_mut()
                        .map(|entry| Pending::Expr(&mut entry.value)),
                ),
                Expr::IntLiteral(_)
                | Expr::DecimalLiteral(_)
                | Expr::OptionNone
                | Expr::Bool(_)
                | Expr::String(_)
                | Expr::Bytes(_)
                | Expr::Ident(_) => {}
                Expr::Source { .. } | Expr::Resolved { .. } => {
                    unreachable!("provenance normalization returns the semantic node")
                }
            },
        }
    }
}
/// Rebase every embedded source range while preserving local NodeId/HirId identities.
pub(crate) fn rebase_program_source(program: &mut Program, source: crate::source::SourceId) {
    transform_program_provenance(program, ProvenanceAction::Rebase(source));
    for directive in &mut program.directives {
        directive.source.source = source;
    }
    for export in &mut program.exports {
        export.source.source = source;
    }
}
/// Remove compiler provenance wrappers for public syntax/tooling AST consumers.
pub(crate) fn strip_program_provenance(program: &mut Program) {
    transform_program_provenance(program, ProvenanceAction::Strip);
}
/// Return the first source range whose expression path exceeds `max_depth`.
///
/// The traversal is iterative so an adversarially deep parser result cannot
/// exhaust the caller's stack while it is being validated. Source and resolved
/// provenance wrappers do not consume depth. The enclosing source-unit and
/// block braces do consume depth, matching the combined V1 nesting budget used
/// by the token preflight.
fn expression_depth_violation_impl(
    program: Option<&Program>,
    expression_root: Option<(&Expr, usize)>,
    max_depth: usize,
    expression_syntax_depths: &[usize],
) -> Option<TextRange> {
    enum Pending<'a> {
        Block {
            block: &'a Block,
            depth: usize,
        },
        Statement {
            statement: &'a Statement,
            block_depth: usize,
        },
        Expr {
            expression: &'a Expr,
            depth: usize,
            range: Option<TextRange>,
        },
    }

    fn push_block<'a>(block: &'a Block, depth: usize, pending: &mut Vec<Pending<'a>>) {
        pending.push(Pending::Block { block, depth });
    }

    fn push_expression<'a>(expression: &'a Expr, depth: usize, pending: &mut Vec<Pending<'a>>) {
        pending.push(Pending::Expr {
            expression,
            depth,
            range: None,
        });
    }

    let mut pending = Vec::new();
    if let Some(program) = program {
        // Bare fragments have no synthetic enclosing brace in their source.
        let source_unit_depth = usize::from(program.unit.kind != SourceUnitKind::Fragment);
        for item in &program.items {
            match item {
                Item::Function(function) => push_block(
                    &function.body,
                    source_unit_depth.saturating_add(1),
                    &mut pending,
                ),
                Item::Const(declaration) => {
                    push_expression(&declaration.value, source_unit_depth, &mut pending)
                }
                Item::Trigger(declaration) => {
                    if let TriggerFilter::Time(TriggerTimeFilter::Schedule {
                        start_ms,
                        period_ms,
                    }) = &declaration.filter
                    {
                        for value in std::iter::once(start_ms).chain(period_ms) {
                            push_expression(
                                value,
                                source_unit_depth.saturating_add(2),
                                &mut pending,
                            );
                        }
                    }
                    // Metadata values sit inside both the trigger and metadata braces.
                    let metadata_depth = source_unit_depth.saturating_add(2);
                    for entry in &declaration.metadata {
                        push_expression(&entry.value, metadata_depth, &mut pending);
                    }
                }
                Item::Struct(_) | Item::Event(_) | Item::Enum(_) | Item::State(_) => {}
            }
        }
        // Fixture arguments sit inside the fixture braces and action parentheses.
        let fixture_depth = source_unit_depth.saturating_add(2);
        for fixture in &program.fixtures {
            for action in &fixture.actions {
                for argument in &action.args {
                    push_expression(argument, fixture_depth, &mut pending);
                }
            }
        }
    }
    if let Some((expression, depth)) = expression_root {
        push_expression(expression, depth, &mut pending);
    }

    while let Some(node) = pending.pop() {
        match node {
            Pending::Block { block, depth } => {
                for statement in &block.statements {
                    pending.push(Pending::Statement {
                        statement,
                        block_depth: depth,
                    });
                }
                if let Some(tail) = &block.tail {
                    push_expression(tail, depth, &mut pending);
                }
            }
            Pending::Statement {
                statement,
                block_depth,
            } => match statement {
                Statement::Source {
                    node, statement, ..
                } => {
                    pending.push(Pending::Statement {
                        statement,
                        block_depth: block_depth.saturating_add(
                            expression_syntax_depths
                                .get(node.index())
                                .copied()
                                .unwrap_or(0),
                        ),
                    });
                }
                Statement::Resolved { statement, .. } => {
                    pending.push(Pending::Statement {
                        statement,
                        block_depth,
                    });
                }
                Statement::Let { value, .. }
                | Statement::Assign { value, .. }
                | Statement::Expr(value)
                | Statement::Emit(value) => {
                    push_expression(value, block_depth, &mut pending);
                }
                Statement::AssignExpr { target, value, .. } => {
                    push_expression(target, block_depth, &mut pending);
                    push_expression(value, block_depth, &mut pending);
                }
                Statement::Return(value) => {
                    if let Some(value) = value {
                        push_expression(value, block_depth, &mut pending);
                    }
                }
                Statement::If {
                    cond,
                    then_branch,
                    else_branch,
                } => {
                    push_expression(cond, block_depth, &mut pending);
                    let nested_depth = block_depth.saturating_add(1);
                    push_block(then_branch, nested_depth, &mut pending);
                    if let Some(block) = else_branch {
                        push_block(block, nested_depth, &mut pending);
                    }
                }
                Statement::IfLet {
                    value,
                    then_branch,
                    else_branch,
                    ..
                } => {
                    push_expression(value, block_depth, &mut pending);
                    let nested_depth = block_depth.saturating_add(1);
                    push_block(then_branch, nested_depth, &mut pending);
                    if let Some(block) = else_branch {
                        push_block(block, nested_depth, &mut pending);
                    }
                }
                Statement::While { cond, body } => {
                    push_expression(cond, block_depth, &mut pending);
                    push_block(body, block_depth.saturating_add(1), &mut pending);
                }
                Statement::For {
                    init,
                    cond,
                    step,
                    body,
                    ..
                } => {
                    if let Some(init) = init {
                        pending.push(Pending::Statement {
                            statement: init,
                            block_depth,
                        });
                    }
                    if let Some(cond) = cond {
                        push_expression(cond, block_depth, &mut pending);
                    }
                    if let Some(step) = step {
                        pending.push(Pending::Statement {
                            statement: step,
                            block_depth,
                        });
                    }
                    push_block(body, block_depth.saturating_add(1), &mut pending);
                }
                Statement::ForEachMap { map, body, .. } => {
                    push_expression(map, block_depth, &mut pending);
                    push_block(body, block_depth.saturating_add(1), &mut pending);
                }
                Statement::Break | Statement::Continue => {}
            },
            Pending::Expr {
                expression,
                depth,
                range,
            } => match expression {
                Expr::Source {
                    node,
                    source,
                    expression,
                } => pending.push(Pending::Expr {
                    expression,
                    depth: depth.saturating_add(
                        expression_syntax_depths
                            .get(node.index())
                            .copied()
                            .unwrap_or(0),
                    ),
                    range: Some(source.range),
                }),
                Expr::Resolved {
                    source, expression, ..
                } => pending.push(Pending::Expr {
                    expression,
                    depth,
                    range: source.map(|source| source.range).or(range),
                }),
                _ if depth > max_depth => {
                    return Some(range.unwrap_or(TextRange::new(0, 0)));
                }
                Expr::Binary { left, right, .. }
                | Expr::Index {
                    target: left,
                    index: right,
                } => {
                    let child_depth = depth.saturating_add(1);
                    push_expression(left, child_depth, &mut pending);
                    push_expression(right, child_depth, &mut pending);
                }
                Expr::Unary { expr, .. }
                | Expr::Member { object: expr, .. }
                | Expr::OptionSome(expr)
                | Expr::ResultOk(expr)
                | Expr::ResultErr(expr)
                | Expr::Propagate(expr) => {
                    push_expression(expr, depth.saturating_add(1), &mut pending);
                }
                Expr::Conditional {
                    cond,
                    then_expr,
                    else_expr,
                } => {
                    let child_depth = depth.saturating_add(1);
                    push_expression(cond, child_depth, &mut pending);
                    push_expression(then_expr, child_depth, &mut pending);
                    push_expression(else_expr, child_depth, &mut pending);
                }
                Expr::If {
                    condition,
                    then_branch,
                    else_branch,
                } => {
                    let child_depth = depth.saturating_add(1);
                    push_expression(condition, child_depth, &mut pending);
                    push_block(then_branch, child_depth, &mut pending);
                    if let Some(block) = else_branch {
                        push_block(block, child_depth, &mut pending);
                    }
                }
                Expr::IfLet {
                    value,
                    then_branch,
                    else_branch,
                    ..
                } => {
                    let child_depth = depth.saturating_add(1);
                    push_expression(value, child_depth, &mut pending);
                    push_block(then_branch, child_depth, &mut pending);
                    if let Some(block) = else_branch {
                        push_block(block, child_depth, &mut pending);
                    }
                }
                Expr::Match { value, arms } => {
                    let child_depth = depth.saturating_add(1);
                    push_expression(value, child_depth, &mut pending);
                    for arm in arms {
                        push_block(&arm.body, child_depth, &mut pending);
                    }
                }
                Expr::Call { args, .. } | Expr::Tuple(args) | Expr::List(args) => {
                    let child_depth = depth.saturating_add(1);
                    for argument in args {
                        push_expression(argument, child_depth, &mut pending);
                    }
                }
                Expr::JsonObject(entries) => {
                    let child_depth = depth.saturating_add(1);
                    for entry in entries {
                        push_expression(&entry.value, child_depth, &mut pending);
                    }
                }
                Expr::JsonArray(elements) => {
                    let child_depth = depth.saturating_add(1);
                    for element in elements {
                        push_expression(element, child_depth, &mut pending);
                    }
                }
                Expr::ListComprehension {
                    expression,
                    source,
                    condition,
                    ..
                } => {
                    let child_depth = depth.saturating_add(1);
                    push_expression(expression, child_depth, &mut pending);
                    push_expression(source, child_depth, &mut pending);
                    if let Some(condition) = condition {
                        push_expression(condition, child_depth, &mut pending);
                    }
                }
                Expr::StructLiteral { fields, .. } | Expr::ArgumentRecord { fields } => {
                    let child_depth = depth.saturating_add(1);
                    for field in fields {
                        push_expression(&field.value, child_depth, &mut pending);
                    }
                }
                Expr::IntLiteral(_)
                | Expr::DecimalLiteral(_)
                | Expr::OptionNone
                | Expr::Bool(_)
                | Expr::String(_)
                | Expr::Bytes(_)
                | Expr::Ident(_) => {}
            },
        }
    }
    None
}
/// Return the first parsed-program expression path that exceeds `max_depth`.
pub(crate) fn expression_depth_violation(
    program: &Program,
    max_depth: usize,
    expression_syntax_depths: &[usize],
) -> Option<TextRange> {
    expression_depth_violation_impl(Some(program), None, max_depth, expression_syntax_depths)
}
/// Return the first path in one parser-owned expression that exceeds `max_depth`.
pub(crate) fn expression_depth_violation_in_expression(
    expression: &Expr,
    root_depth: usize,
    max_depth: usize,
    expression_syntax_depths: &[usize],
) -> Option<TextRange> {
    expression_depth_violation_impl(
        None,
        Some((expression, root_depth)),
        max_depth,
        expression_syntax_depths,
    )
}
/// Destroy a parsed program without recursively dropping adversarially deep
/// expression, statement, or type trees.
///
/// V1 accepts nesting up to the fixed frontend limit. Rust's derived drop glue walks recursive
/// enums on the caller's stack, which can overflow the smaller stacks used by editor workers and
/// test executors even though parsing itself stayed within that limit. Tooling that consumes an AST
/// only for validation uses this explicit work list instead.
pub(crate) fn drop_program_iterative(program: Program) {
    enum Pending {
        Statement(Statement),
        Expr(Expr),
        Type(TypeExpr),
    }
    fn push_block(block: Block, pending: &mut Vec<Pending>) {
        pending.extend(block.statements.into_iter().map(Pending::Statement));
        pending.extend(
            block
                .tail
                .into_iter()
                .map(|expression| Pending::Expr(*expression)),
        );
    }
    let Program {
        unit: _,
        items,
        permissions: _,
        test_target: _,
        fixtures,
        directives: _,
        exports: _,
    } = program;
    let mut pending = Vec::new();
    for item in items {
        match item {
            Item::Function(function) => {
                pending.extend(
                    function
                        .params
                        .into_iter()
                        .filter_map(|parameter| parameter.ty)
                        .map(Pending::Type),
                );
                pending.extend(function.ret_ty.into_iter().map(Pending::Type));
                push_block(function.body, &mut pending);
            }
            Item::Struct(definition) | Item::Event(definition) => pending.extend(
                definition
                    .fields
                    .into_iter()
                    .map(|(_, ty)| Pending::Type(ty)),
            ),
            Item::Const(declaration) => {
                pending.extend(declaration.ty.into_iter().map(Pending::Type));
                pending.push(Pending::Expr(declaration.value));
            }
            Item::State(declaration) => pending.push(Pending::Type(declaration.ty)),
            Item::Trigger(declaration) => {
                pending.extend(
                    declaration
                        .metadata
                        .into_iter()
                        .map(|entry| Pending::Expr(entry.value)),
                );
                if let TriggerFilter::Time(TriggerTimeFilter::Schedule {
                    start_ms,
                    period_ms,
                }) = declaration.filter
                {
                    pending.push(Pending::Expr(*start_ms));
                    pending.extend(period_ms.into_iter().map(|value| Pending::Expr(*value)));
                }
            }
            Item::Enum(_) => {}
        }
    }
    for fixture in fixtures {
        for action in fixture.actions {
            pending.extend(action.args.into_iter().map(Pending::Expr));
        }
    }
    while let Some(node) = pending.pop() {
        match node {
            Pending::Type(TypeExpr::Source { ty, .. } | TypeExpr::Resolved { ty, .. }) => {
                pending.push(Pending::Type(*ty));
            }
            Pending::Type(TypeExpr::Generic { args, .. })
            | Pending::Type(TypeExpr::Tuple(args)) => {
                pending.extend(args.into_iter().map(Pending::Type));
            }
            Pending::Type(TypeExpr::Path(_) | TypeExpr::Const(_)) => {}
            Pending::Type(TypeExpr::ConstExpression(value)) => pending.push(Pending::Expr(*value)),
            Pending::Statement(statement) => match statement {
                Statement::Source { statement, .. } | Statement::Resolved { statement, .. } => {
                    pending.push(Pending::Statement(*statement));
                }
                Statement::Let { ty, value, .. } => {
                    pending.extend(ty.into_iter().map(Pending::Type));
                    pending.push(Pending::Expr(value));
                }
                Statement::Assign { value, .. }
                | Statement::Expr(value)
                | Statement::Emit(value) => {
                    pending.push(Pending::Expr(value));
                }
                Statement::AssignExpr { target, value, .. } => {
                    pending.push(Pending::Expr(target));
                    pending.push(Pending::Expr(value));
                }
                Statement::Return(value) => {
                    pending.extend(value.into_iter().map(Pending::Expr));
                }
                Statement::If {
                    cond,
                    then_branch,
                    else_branch,
                } => {
                    pending.push(Pending::Expr(cond));
                    push_block(then_branch, &mut pending);
                    if let Some(block) = else_branch {
                        push_block(block, &mut pending);
                    }
                }
                Statement::IfLet {
                    value,
                    then_branch,
                    else_branch,
                    ..
                } => {
                    pending.push(Pending::Expr(value));
                    push_block(then_branch, &mut pending);
                    if let Some(block) = else_branch {
                        push_block(block, &mut pending);
                    }
                }
                Statement::While { cond, body } => {
                    pending.push(Pending::Expr(cond));
                    push_block(body, &mut pending);
                }
                Statement::For {
                    init,
                    cond,
                    step,
                    body,
                    ..
                } => {
                    pending.extend(
                        init.into_iter()
                            .map(|statement| Pending::Statement(*statement)),
                    );
                    pending.extend(cond.into_iter().map(Pending::Expr));
                    pending.extend(
                        step.into_iter()
                            .map(|statement| Pending::Statement(*statement)),
                    );
                    push_block(body, &mut pending);
                }
                Statement::ForEachMap { map, body, .. } => {
                    pending.push(Pending::Expr(map));
                    push_block(body, &mut pending);
                }
                Statement::Break | Statement::Continue => {}
            },
            Pending::Expr(expression) => match expression {
                Expr::Source { expression, .. } | Expr::Resolved { expression, .. } => {
                    pending.push(Pending::Expr(*expression));
                }
                Expr::Binary { left, right, .. }
                | Expr::Index {
                    target: left,
                    index: right,
                } => {
                    pending.push(Pending::Expr(*left));
                    pending.push(Pending::Expr(*right));
                }
                Expr::Unary { expr, .. }
                | Expr::Member { object: expr, .. }
                | Expr::OptionSome(expr)
                | Expr::ResultOk(expr)
                | Expr::ResultErr(expr)
                | Expr::Propagate(expr) => {
                    pending.push(Pending::Expr(*expr));
                }
                Expr::Conditional {
                    cond,
                    then_expr,
                    else_expr,
                } => {
                    pending.push(Pending::Expr(*cond));
                    pending.push(Pending::Expr(*then_expr));
                    pending.push(Pending::Expr(*else_expr));
                }
                Expr::If {
                    condition,
                    then_branch,
                    else_branch,
                } => {
                    pending.push(Pending::Expr(*condition));
                    push_block(then_branch, &mut pending);
                    if let Some(block) = else_branch {
                        push_block(block, &mut pending);
                    }
                }
                Expr::IfLet {
                    value,
                    then_branch,
                    else_branch,
                    ..
                } => {
                    pending.push(Pending::Expr(*value));
                    push_block(then_branch, &mut pending);
                    if let Some(block) = else_branch {
                        push_block(block, &mut pending);
                    }
                }
                Expr::Match { value, arms } => {
                    pending.push(Pending::Expr(*value));
                    for arm in arms {
                        push_block(arm.body, &mut pending);
                    }
                }
                Expr::Call { args, .. } | Expr::Tuple(args) | Expr::List(args) => {
                    pending.extend(args.into_iter().map(Pending::Expr));
                }
                Expr::JsonObject(entries) => {
                    pending.extend(entries.into_iter().map(|entry| Pending::Expr(entry.value)))
                }
                Expr::JsonArray(elements) => {
                    pending.extend(elements.into_iter().map(Pending::Expr));
                }
                Expr::ListComprehension {
                    expression,
                    source,
                    condition,
                    ..
                } => {
                    pending.push(Pending::Expr(*expression));
                    pending.push(Pending::Expr(*source));
                    pending.extend(condition.map(|condition| Pending::Expr(*condition)));
                }
                Expr::StructLiteral { fields, .. } | Expr::ArgumentRecord { fields } => {
                    pending.extend(fields.into_iter().map(|field| Pending::Expr(field.value)))
                }
                Expr::Bool(_)
                | Expr::IntLiteral(_)
                | Expr::DecimalLiteral(_)
                | Expr::OptionNone
                | Expr::String(_)
                | Expr::Bytes(_)
                | Expr::Ident(_) => {}
            },
        }
    }
}
/// Destroy one parser-owned expression through the program's iterative drain.
///
/// This is used on syntax-error and resource-limit paths before an expression
/// has been committed to a complete [`Program`].
pub(crate) fn drop_expression_iterative(expression: Expr) {
    drop_program_iterative(Program {
        unit: SourceUnit {
            kind: SourceUnitKind::Module,
            name: String::new(),
        },
        items: vec![Item::Const(ConstDecl {
            name: String::new(),
            ty: None,
            value: expression,
        })],
        directives: Vec::new(),
        exports: Vec::new(),
        permissions: Vec::new(),
        test_target: None,
        fixtures: Vec::new(),
    });
}
/// Destroy one parser-owned type through an explicit work list.
///
/// Syntax recovery can retain a complete boundary-depth type before a later
/// token fails. Draining it here avoids recursive derived drop glue while the
/// type has not yet been committed to a complete [`Program`].
pub(crate) fn drop_type_iterative(ty: TypeExpr) {
    let mut pending = vec![ty];
    while let Some(ty) = pending.pop() {
        match ty {
            TypeExpr::Source { ty, .. } | TypeExpr::Resolved { ty, .. } => {
                pending.push(*ty);
            }
            TypeExpr::Generic { args, .. } | TypeExpr::Tuple(args) => {
                pending.extend(args);
            }
            TypeExpr::Path(_) | TypeExpr::Const(_) => {}
            TypeExpr::ConstExpression(value) => drop_expression_iterative(*value),
        }
    }
}
/// Destroy one parser-owned block through the program's iterative drain.
///
/// Parser recovery uses this while a function body is still incomplete, so a
/// missing closing brace cannot recursively drop already-accepted expressions.
pub(crate) fn drop_block_iterative(block: Block) {
    drop_program_iterative(Program {
        unit: SourceUnit {
            kind: SourceUnitKind::Module,
            name: String::new(),
        },
        items: vec![Item::Function(Function {
            name: String::new(),
            params: Vec::new(),
            ret_ty: None,
            body: block,
            modifiers: FunctionModifiers::default(),
            location: SourceLocation { line: 0, column: 0 },
        })],
        directives: Vec::new(),
        exports: Vec::new(),
        permissions: Vec::new(),
        test_target: None,
        fixtures: Vec::new(),
    });
}
#[cfg(test)]
mod provenance_tests {
    use super::*;
    use crate::source::{SourceId, TextRange};

    #[test]
    fn recursive_traits_are_spawn_free_for_flat_width_and_aggregates() {
        let expressions: Vec<_> = (0..16_384)
            .map(|_| Expr::IntLiteral(BigInt::one()))
            .collect();
        crate::session::reset_compiler_worker_spawn_count();
        let cloned_expressions = expressions.clone();
        assert_eq!(crate::session::compiler_worker_spawn_count(), 0);
        crate::session::reset_compiler_worker_spawn_count();
        assert_eq!(expressions, cloned_expressions);
        assert_eq!(crate::session::compiler_worker_spawn_count(), 0);

        let statements: Vec<_> = (0..16_384)
            .map(|_| Statement::Expr(Expr::IntLiteral(BigInt::one())))
            .collect();
        crate::session::reset_compiler_worker_spawn_count();
        let cloned_statements = statements.clone();
        assert_eq!(crate::session::compiler_worker_spawn_count(), 0);
        crate::session::reset_compiler_worker_spawn_count();
        assert_eq!(statements, cloned_statements);
        assert_eq!(crate::session::compiler_worker_spawn_count(), 0);

        let items: Vec<_> = (0..16_384)
            .map(|index| {
                Item::Const(ConstDecl {
                    name: format!("VALUE_{index}"),
                    ty: None,
                    value: Expr::IntLiteral(BigInt::one()),
                })
            })
            .collect();
        crate::session::reset_compiler_worker_spawn_count();
        let cloned_items = items.clone();
        assert_eq!(crate::session::compiler_worker_spawn_count(), 0);
        crate::session::reset_compiler_worker_spawn_count();
        assert_eq!(items, cloned_items);
        assert_eq!(crate::session::compiler_worker_spawn_count(), 0);

        let function = Function {
            name: "wide".to_owned(),
            params: Vec::new(),
            ret_ty: None,
            body: Block {
                statements,
                tail: None,
            },
            modifiers: FunctionModifiers::default(),
            location: SourceLocation { line: 1, column: 1 },
        };

        crate::session::reset_compiler_worker_spawn_count();
        let cloned = function.clone();
        assert_eq!(crate::session::compiler_worker_spawn_count(), 0);

        crate::session::reset_compiler_worker_spawn_count();
        assert_eq!(function, cloned);
        assert_eq!(crate::session::compiler_worker_spawn_count(), 0);

        crate::session::reset_compiler_worker_spawn_count();
        assert!(format!("{function:?}").contains("Function"));
        assert_eq!(crate::session::compiler_worker_spawn_count(), 0);

        let program = Program {
            unit: SourceUnit {
                kind: SourceUnitKind::Module,
                name: "Wide".to_owned(),
            },
            items,
            directives: Vec::new(),
            exports: Vec::new(),
            permissions: Vec::new(),
            test_target: None,
            fixtures: Vec::new(),
        };
        crate::session::reset_compiler_worker_spawn_count();
        let cloned = program.clone();
        assert_eq!(crate::session::compiler_worker_spawn_count(), 0);
        crate::session::reset_compiler_worker_spawn_count();
        assert_eq!(program, cloned);
        assert_eq!(crate::session::compiler_worker_spawn_count(), 0);
    }

    #[test]
    fn recursive_traits_fit_an_exact_depth_tree_on_a_small_stack() {
        std::thread::Builder::new()
            .name("kotodama-ast-trait-boundary".to_owned())
            .stack_size(128 * 1024)
            .spawn(|| {
                let mut expression = Expr::Ident("value".to_owned());
                for depth in 0..crate::source::MAX_NESTING_DEPTH {
                    expression = match depth % 4 {
                        0 => Expr::StructLiteral {
                            name: "Wrapper".to_owned(),
                            fields: vec![StructLiteralField {
                                name: "value".to_owned(),
                                value: expression,
                                shorthand: false,
                            }],
                        },
                        1 => Expr::JsonObject(vec![JsonObjectEntry {
                            key: "value".to_owned(),
                            key_spelling: "value".to_owned(),
                            key_range: TextRange::new(depth as u32, depth as u32 + 1),
                            value: expression,
                        }]),
                        2 => Expr::Match {
                            value: Box::new(Expr::OptionNone),
                            arms: vec![MatchArm {
                                pattern: SumPattern {
                                    variant: SumVariant::OptionNone,
                                    binding: None,
                                },
                                body: Block {
                                    statements: Vec::new(),
                                    tail: Some(Box::new(expression)),
                                },
                            }],
                        },
                        _ => Expr::If {
                            condition: Box::new(Expr::Bool(true)),
                            then_branch: Block {
                                statements: vec![Statement::Expr(expression)],
                                tail: None,
                            },
                            else_branch: None,
                        },
                    };
                }

                let mut statement = Statement::Expr(Expr::Ident("item".to_owned()));
                for line in 0..crate::source::MAX_NESTING_DEPTH {
                    statement = Statement::For {
                        line,
                        init: Some(Box::new(statement)),
                        cond: Some(Expr::Bool(true)),
                        step: None,
                        body: Block {
                            statements: Vec::new(),
                            tail: None,
                        },
                    };
                }

                crate::session::reset_compiler_worker_spawn_count();
                let cloned_expression = expression.clone();
                let cloned_statement = statement.clone();
                assert_eq!(expression, cloned_expression);
                assert_eq!(statement, cloned_statement);
                assert_eq!(crate::session::compiler_worker_spawn_count(), 0);

                for (expression, statement) in [
                    (expression, statement),
                    (cloned_expression, cloned_statement),
                ] {
                    drop_program_iterative(Program {
                        unit: SourceUnit {
                            kind: SourceUnitKind::Module,
                            name: "Boundary".to_owned(),
                        },
                        items: vec![
                            Item::Const(ConstDecl {
                                name: "VALUE".to_owned(),
                                ty: None,
                                value: expression,
                            }),
                            Item::Function(Function {
                                name: "boundary".to_owned(),
                                params: Vec::new(),
                                ret_ty: None,
                                body: Block {
                                    statements: vec![statement],
                                    tail: None,
                                },
                                modifiers: FunctionModifiers::default(),
                                location: SourceLocation { line: 1, column: 1 },
                            }),
                        ],
                        directives: Vec::new(),
                        exports: Vec::new(),
                        permissions: Vec::new(),
                        test_target: None,
                        fixtures: Vec::new(),
                    });
                }
            })
            .expect("small-stack AST trait worker must spawn")
            .join()
            .expect("small-stack AST trait worker must complete");
    }

    #[test]
    fn type_traits_are_iterative_at_the_depth_boundary() {
        let mut ty = TypeExpr::Path("int".to_owned());
        for _ in 0..crate::source::MAX_NESTING_DEPTH {
            ty = TypeExpr::Generic {
                base: "Option".to_owned(),
                args: vec![ty],
            };
        }

        crate::session::reset_compiler_worker_spawn_count();
        let cloned = ty.clone();
        assert_eq!(ty, cloned);
        assert!(!format!("{ty:?}").is_empty());
        assert_eq!(crate::session::compiler_worker_spawn_count(), 0);
        drop_type_iterative(ty);
        drop_type_iterative(cloned);
    }

    fn deeply_sourced_program(depth: u32) -> Program {
        let old_source = SourceId(11);
        let mut expression = Expr::IntLiteral(BigInt::one());
        for index in (0..depth).rev() {
            expression = Expr::Source {
                node: NodeId(index),
                source: SourceRange::new(old_source, TextRange::new(index, index + 1)),
                expression: Box::new(Expr::Unary {
                    op: UnaryOp::Neg,
                    expr: Box::new(expression),
                }),
            };
        }
        Program {
            unit: SourceUnit {
                kind: SourceUnitKind::Module,
                name: "Provenance".to_owned(),
            },
            items: vec![Item::Const(ConstDecl {
                name: "VALUE".to_owned(),
                ty: None,
                value: expression,
            })],
            directives: Vec::new(),
            exports: Vec::new(),
            permissions: Vec::new(),
            test_target: None,
            fixtures: Vec::new(),
        }
    }
    #[test]
    fn full_depth_provenance_rebases_and_strips_iteratively() {
        let mut program = deeply_sourced_program(256);
        let new_source = SourceId(99);
        rebase_program_source(&mut program, new_source);
        let Item::Const(declaration) = &program.items[0] else {
            panic!("const declaration")
        };
        let mut current = &declaration.value;
        let mut wrappers = 0_u32;
        loop {
            match current {
                Expr::Source {
                    source, expression, ..
                } => {
                    assert_eq!(source.source, new_source);
                    wrappers += 1;
                    let Expr::Unary { expr, .. } = expression.as_ref() else {
                        panic!("nested unary")
                    };
                    current = expr;
                }
                Expr::IntLiteral(value) if value == &BigInt::one() => break,
                other => panic!("unexpected nested expression: {other:?}"),
            }
        }
        assert_eq!(wrappers, 256);
        strip_program_provenance(&mut program);
        let Item::Const(declaration) = &program.items[0] else {
            panic!("const declaration")
        };
        let mut current = &declaration.value;
        for _ in 0..256 {
            let Expr::Unary { expr, .. } = current else {
                panic!("stripped unary")
            };
            current = expr;
        }
        assert!(matches!(current, Expr::IntLiteral(value) if value == &BigInt::one()));
        drop_program_iterative(program);
    }
}

#[cfg(test)]
#[path = "ast/provenance_tests.rs"]
mod provenance_iteration_tests;

#[cfg(test)]
#[path = "ast/mixed_ownership_tests.rs"]
mod mixed_ownership_tests;
