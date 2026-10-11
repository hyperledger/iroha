//! Stable source identities for the CST-lowered Kotodama AST.
pub(crate) use crate::ast::NodeId;
use crate::{
    ast::Program,
    source::{SourceFile, SourceId, TextRange},
};
/// Coarse source node category retained independently of AST enum layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AstNodeKind {
    /// A declared authorization name.
    Permission,
    /// Top-level `seiyaku`/`誓約` or module declaration.
    SourceUnit,
    /// Function, lifecycle, or view declaration.
    Function,
    /// Struct declaration.
    Struct,
    /// Contract-owned native event declaration.
    Event,
    /// Ordinary or raisable-error enum declaration.
    Enum,
    /// Durable state declaration.
    State,
    /// Constant declaration.
    Const,
    /// Trigger declaration.
    Trigger,
    /// Function parameter declaration.
    Parameter,
    /// Named type reference.
    Type,
    /// Statement.
    Statement,
    /// Expression.
    Expression,
    /// Function or builtin call expression.
    Call,
    /// Checked-index diagnostic target (`value[index]`).
    IndexExpression,
    /// Capacity-proven bounded-list comprehension.
    ListComprehension,
    /// Unsuffixed exact decimal literal token.
    DecimalLiteral,
    /// Declaration or reference name.
    Name,
}
/// Exact source location of one AST node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AstNode {
    /// Stable arena identifier.
    pub id: NodeId,
    /// Syntactic node category.
    pub kind: AstNodeKind,
    /// Exact half-open UTF-8 byte range.
    pub range: TextRange,
    /// Owning function declaration for function-local nodes.
    pub owner: Option<NodeId>,
}
/// Per-source AST node arena keyed by stable [`NodeId`] values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AstSourceMap {
    source: SourceId,
    nodes: Vec<AstNode>,
}
impl AstSourceMap {
    pub(crate) fn new(source: SourceId) -> Self {
        Self {
            source,
            nodes: Vec::new(),
        }
    }
    /// Return the source identity shared by every node in this map.
    #[must_use]
    pub const fn source(&self) -> SourceId {
        self.source
    }
    /// Return one source node by stable identity.
    #[must_use]
    pub fn node(&self, id: NodeId) -> Option<&AstNode> {
        self.nodes.get(id.index()).filter(|node| node.id == id)
    }
    /// Iterate over source nodes in stable allocation order.
    pub fn nodes(&self) -> impl ExactSizeIterator<Item = &AstNode> {
        self.nodes.iter()
    }
    pub(crate) fn allocate_owned(
        &mut self,
        kind: AstNodeKind,
        range: TextRange,
        owner: Option<NodeId>,
    ) -> NodeId {
        let id = NodeId(u32::try_from(self.nodes.len()).expect("AST node budget fits u32"));
        self.nodes.push(AstNode {
            id,
            kind,
            range,
            owner,
        });
        id
    }
    pub(crate) fn begin_owned(
        &mut self,
        kind: AstNodeKind,
        start: u32,
        owner: Option<NodeId>,
    ) -> NodeId {
        self.allocate_owned(kind, TextRange::empty(start), owner)
    }
    pub(crate) fn finish(&mut self, id: NodeId, end: u32) {
        if let Some(node) = self.nodes.get_mut(id.index()) {
            node.range = TextRange::new(node.range.start, end.max(node.range.start));
        }
    }
    /// Reclassify a parser-reserved block expression as the statement form
    /// selected after its trailing syntax is known.
    ///
    /// The stable identity is deliberately preserved so binding facts remain attached to their
    /// direct owner without a spelling-, address-, or traversal-order-based rebind.
    pub(crate) fn set_kind(&mut self, id: NodeId, kind: AstNodeKind) {
        if let Some(node) = self.nodes.get_mut(id.index()) {
            node.kind = kind;
        }
    }
    pub(crate) fn source_span(
        &self,
        source: &SourceFile,
        id: NodeId,
    ) -> Option<crate::diagnostic::SourceSpan> {
        (source.id() == self.source)
            .then(|| self.node(id))
            .flatten()
            .map(|node| crate::diagnostic::SourceSpan::from_range(source, node.range))
    }
    pub(crate) fn source_range(&self, id: NodeId) -> Option<crate::source::SourceRange> {
        self.node(id)
            .map(|node| crate::source::SourceRange::new(self.source, node.range))
    }
    pub(crate) fn rebase(&mut self, source: SourceId) {
        self.source = source;
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeclarationKind {
    Permission,
    SourceUnit,
    Function,
    Struct,
    /// Contract-owned native event declaration.
    Event,
    Enum,
    State,
    Const,
    Trigger,
    Parameter,
}
impl DeclarationKind {
    pub(crate) const fn description(self) -> &'static str {
        match self {
            Self::SourceUnit => "source unit",
            Self::Function => "function",
            Self::Struct => "type",
            Self::Event => "event",
            Self::Enum => "type",
            Self::State => "state declaration",
            Self::Const => "const declaration",
            Self::Permission => "permission declaration",
            Self::Trigger => "trigger declaration",
            Self::Parameter => "parameter",
        }
    }
    pub(crate) const fn is_function(self) -> bool {
        matches!(self, Self::Function)
    }
    pub(crate) const fn is_type_declaration(self) -> bool {
        matches!(
            self,
            Self::SourceUnit | Self::Struct | Self::Enum | Self::Event
        )
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DeclarationFact {
    pub(crate) node: NodeId,
    pub(crate) name_node: NodeId,
    pub(crate) owner: Option<NodeId>,
    pub(crate) name: String,
    pub(crate) kind: DeclarationKind,
    /// Authored documentation from the adjacent CST doc-comment block.
    pub(crate) documentation: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TypeUseFact {
    pub(crate) node: NodeId,
    pub(crate) owner: Option<NodeId>,
    pub(crate) name: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CallFact {
    pub(crate) node: NodeId,
    pub(crate) name_node: NodeId,
    pub(crate) owner: Option<NodeId>,
    pub(crate) name: String,
    pub(crate) implicit_receiver: bool,
    /// Source-order argument labels; positional arguments have no name node.
    pub(crate) argument_name_nodes: Vec<Option<NodeId>>,
}
/// Lexical binding role recorded directly by the parser.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum BindingFactKind {
    Local,
    Pattern,
    Iterator,
    Comprehension,
}
/// Exact source fact for one non-parameter lexical binding declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BindingFact {
    pub(crate) owner: NodeId,
    pub(crate) ordinal: u16,
    pub(crate) name_node: NodeId,
    pub(crate) name: String,
    pub(crate) kind: BindingFactKind,
}
/// Exact identifier used by a public function caller policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AuthorizationFact {
    pub(crate) name_node: NodeId,
    pub(crate) name: String,
}
/// CST-lowerer-owned source facts used to construct resolved HIR without rescanning text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AstFacts {
    pub(crate) source_map: AstSourceMap,
    pub(crate) declarations: Vec<DeclarationFact>,
    pub(crate) type_uses: Vec<TypeUseFact>,
    pub(crate) calls: Vec<CallFact>,
    pub(crate) bindings: Vec<BindingFact>,
    pub(crate) authorizations: Vec<AuthorizationFact>,
}
impl AstFacts {
    pub(crate) fn new(source: SourceId) -> Self {
        Self {
            source_map: AstSourceMap::new(source),
            declarations: Vec::new(),
            type_uses: Vec::new(),
            calls: Vec::new(),
            bindings: Vec::new(),
            authorizations: Vec::new(),
        }
    }
}
/// Compiler AST paired with its stable source-node arena and resolver facts.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct SpannedProgram {
    pub(crate) program: Program,
    pub(crate) facts: AstFacts,
}
impl SpannedProgram {
    /// Rebase a cached source unit while preserving every stable local NodeId.
    pub(crate) fn rebase_source(&mut self, source: SourceId) {
        self.facts.source_map.rebase(source);
        crate::ast::rebase_program_source(&mut self.program, source);
    }
    pub(crate) fn with_source(mut self, source: SourceId) -> Self {
        self.rebase_source(source);
        self
    }
}
