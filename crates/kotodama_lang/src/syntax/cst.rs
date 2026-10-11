//! Immutable lossless concrete syntax tree nodes.
use super::kind::SyntaxKind;
use crate::source::{SourceFile, SourceId, TextRange};
/// One lossless token in a concrete syntax tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GreenToken {
    /// Token kind.
    pub kind: SyntaxKind,
    /// Exact UTF-8 byte range in the source file.
    pub range: TextRange,
    /// Expected token kind for a zero-width recovery token.
    pub expected: Option<SyntaxKind>,
}
impl GreenToken {
    /// Construct a source-backed token.
    #[must_use]
    pub const fn source(kind: SyntaxKind, range: TextRange) -> Self {
        Self {
            kind,
            range,
            expected: None,
        }
    }
    /// Construct a zero-width missing token.
    #[must_use]
    pub const fn missing(offset: u32, expected: SyntaxKind) -> Self {
        Self {
            kind: SyntaxKind::Missing,
            range: TextRange::empty(offset),
            expected: Some(expected),
        }
    }
    /// Return whether this is a parser-inserted missing token.
    #[must_use]
    pub const fn is_missing(&self) -> bool {
        matches!(self.kind, SyntaxKind::Missing)
    }
}
/// A child of a concrete syntax node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GreenElement {
    /// Nested syntax node.
    Node(Box<GreenNode>),
    /// Leaf token.
    Token(GreenToken),
}
impl GreenElement {
    fn range(&self) -> TextRange {
        match self {
            Self::Node(node) => node.range,
            Self::Token(token) => token.range,
        }
    }
}
/// Immutable concrete syntax node.
pub struct GreenNode {
    /// Node kind.
    pub kind: SyntaxKind,
    /// Range spanning all source-backed descendants.
    pub range: TextRange,
    /// Lossless children in source order.
    pub children: Vec<GreenElement>,
}
impl Clone for GreenNode {
    fn clone(&self) -> Self {
        enum Pending<'a> {
            Element(&'a GreenElement),
            Node(&'a GreenNode),
            Finish {
                kind: SyntaxKind,
                range: TextRange,
                children: usize,
            },
        }

        let mut pending = vec![Pending::Node(self)];
        let mut values = Vec::new();
        while let Some(operation) = pending.pop() {
            match operation {
                Pending::Element(GreenElement::Token(token)) => {
                    values.push(GreenElement::Token(*token));
                }
                Pending::Element(GreenElement::Node(node)) => {
                    let node = node.as_ref();
                    pending.push(Pending::Finish {
                        kind: node.kind,
                        range: node.range,
                        children: node.children.len(),
                    });
                    pending.extend(node.children.iter().rev().map(Pending::Element));
                }
                Pending::Node(node) => {
                    pending.push(Pending::Finish {
                        kind: node.kind,
                        range: node.range,
                        children: node.children.len(),
                    });
                    pending.extend(node.children.iter().rev().map(Pending::Element));
                }
                Pending::Finish {
                    kind,
                    range,
                    children,
                } => {
                    let start = values.len().saturating_sub(children);
                    let children = values.split_off(start);
                    values.push(GreenElement::Node(Box::new(Self {
                        kind,
                        range,
                        children,
                    })));
                }
            }
        }
        let GreenElement::Node(root) = values.pop().expect("syntax traversal produces one root")
        else {
            unreachable!("syntax root is always a node")
        };
        *root
    }
}
impl std::fmt::Debug for GreenNode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut node_count = 1_usize;
        let mut token_count = 0_usize;
        let mut pending = self.children.iter().collect::<Vec<_>>();
        while let Some(element) = pending.pop() {
            match element {
                GreenElement::Node(node) => {
                    node_count = node_count.saturating_add(1);
                    pending.extend(node.children.iter());
                }
                GreenElement::Token(_) => token_count = token_count.saturating_add(1),
            }
        }
        formatter
            .debug_struct("GreenNode")
            .field("kind", &self.kind)
            .field("range", &self.range)
            .field("children", &self.children.len())
            .field("descendant_nodes", &node_count)
            .field("descendant_tokens", &token_count)
            .finish()
    }
}
impl PartialEq for GreenNode {
    fn eq(&self, other: &Self) -> bool {
        let mut pending = vec![(self, other)];
        while let Some((left, right)) = pending.pop() {
            if left.kind != right.kind
                || left.range != right.range
                || left.children.len() != right.children.len()
            {
                return false;
            }
            for (left, right) in left.children.iter().zip(&right.children) {
                match (left, right) {
                    (GreenElement::Token(left), GreenElement::Token(right)) if left == right => {}
                    (GreenElement::Node(left), GreenElement::Node(right)) => {
                        pending.push((left, right));
                    }
                    _ => return false,
                }
            }
        }
        true
    }
}
impl Eq for GreenNode {}
impl GreenNode {
    pub(crate) fn new(kind: SyntaxKind, fallback: u32, children: Vec<GreenElement>) -> Self {
        let first = children
            .iter()
            .map(GreenElement::range)
            .find(|range| !range.is_empty());
        let last = children
            .iter()
            .rev()
            .map(GreenElement::range)
            .find(|range| !range.is_empty());
        let range = match (first, last) {
            (Some(first), Some(last)) => TextRange::new(first.start, last.end),
            _ => TextRange::empty(fallback),
        };
        Self {
            kind,
            range,
            children,
        }
    }
}
fn drop_green_elements_iterative(elements: Vec<GreenElement>) {
    let mut pending = elements;
    while let Some(element) = pending.pop() {
        if let GreenElement::Node(node) = element {
            let GreenNode { children, .. } = *node;
            pending.extend(children);
        }
    }
}
/// Complete lossless concrete syntax tree for one source file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyntaxTree {
    source: SourceId,
    root: GreenNode,
}
impl SyntaxTree {
    pub(crate) fn new(source: SourceId, root: GreenNode) -> Self {
        Self { source, root }
    }
    /// Return the source identifier.
    #[must_use]
    pub const fn source(&self) -> SourceId {
        self.source
    }
    /// Return the root node.
    #[must_use]
    pub const fn root(&self) -> &GreenNode {
        &self.root
    }
    /// Reconstruct the exact source text represented by the tree.
    #[must_use]
    pub fn text(&self, source: &SourceFile) -> String {
        if source.id() != self.source {
            return String::new();
        }
        let mut output = String::with_capacity(source.text().len());
        let mut pending = self.root.children.iter().rev().collect::<Vec<_>>();
        while let Some(element) = pending.pop() {
            match element {
                GreenElement::Node(node) => pending.extend(node.children.iter().rev()),
                GreenElement::Token(token)
                    if !token.is_missing() && token.kind != SyntaxKind::Eof =>
                {
                    if let Some(text) = source.slice(token.range) {
                        output.push_str(text);
                    }
                }
                GreenElement::Token(_) => {}
            }
        }
        output
    }
    /// Return every leaf token in source order, including trivia, missing tokens, and end-of-file.
    #[must_use]
    pub fn tokens(&self) -> Vec<&GreenToken> {
        self.token_iter().collect()
    }
    pub(crate) fn token_iter(&self) -> GreenTokenIter<'_> {
        GreenTokenIter {
            pending: self.root.children.iter().rev().collect(),
        }
    }
    /// Consume the tree and return its tokens without recursively dropping nested green nodes.
    pub(crate) fn into_tokens(mut self) -> Vec<GreenToken> {
        let mut pending = std::mem::take(&mut self.root.children)
            .into_iter()
            .rev()
            .collect::<Vec<_>>();
        let mut tokens = Vec::new();
        while let Some(element) = pending.pop() {
            match element {
                GreenElement::Node(node) => {
                    let GreenNode { children, .. } = *node;
                    pending.extend(children.into_iter().rev());
                }
                GreenElement::Token(token) => tokens.push(token),
            }
        }
        tokens
    }
}
impl Drop for SyntaxTree {
    fn drop(&mut self) {
        drop_green_elements_iterative(std::mem::take(&mut self.root.children));
    }
}
pub(crate) struct GreenTokenIter<'tree> {
    pending: Vec<&'tree GreenElement>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deeply_nested_tree(depth: usize) -> SyntaxTree {
        let mut node = GreenNode::new(
            SyntaxKind::Ident,
            0,
            vec![GreenElement::Token(GreenToken::source(
                SyntaxKind::Ident,
                TextRange::new(0, 1),
            ))],
        );
        for _ in 0..depth {
            node = GreenNode::new(
                SyntaxKind::IfExpr,
                0,
                vec![GreenElement::Node(Box::new(node))],
            );
        }
        SyntaxTree::new(SourceId(1), node)
    }

    #[test]
    fn deep_tree_consumption_and_drop_are_iterative() {
        std::thread::Builder::new()
            .name("kotodama-cst-drop-depth".into())
            .stack_size(128 * 1024)
            .spawn(|| {
                let tokens = deeply_nested_tree(4_096).into_tokens();
                assert_eq!(tokens.len(), 1);
                drop(deeply_nested_tree(4_096));
            })
            .expect("spawn small-stack CST worker")
            .join()
            .expect("small-stack CST worker");
    }

    #[test]
    fn public_child_collection_clone_is_spawn_free() {
        let leaf = || {
            GreenElement::Node(Box::new(GreenNode::new(
                SyntaxKind::Ident,
                0,
                vec![GreenElement::Token(GreenToken::source(
                    SyntaxKind::Ident,
                    TextRange::new(0, 1),
                ))],
            )))
        };
        let children = std::iter::repeat_with(leaf)
            .take(16_384)
            .collect::<Vec<_>>();
        crate::session::reset_compiler_worker_spawn_count();
        let cloned = children.clone();
        assert_eq!(children, cloned);
        assert_eq!(crate::session::compiler_worker_spawn_count(), 0);
    }

    #[test]
    fn missing_token_owner_sweep_matches_the_exhaustive_search() {
        // Deterministic linear congruential generator: small ranges collide
        // often, which exercises every tie-breaking rule.
        let mut seed = 0x9e37_79b9_u32;
        let mut next = |bound: u32| {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (seed >> 8) % bound
        };
        for _ in 0..128 {
            let count = 1 + next(40) as usize;
            let nodes = (0..count)
                .map(|_| {
                    let start = next(100);
                    SyntaxOutlineNode {
                        kind: SyntaxKind::Block,
                        range: TextRange::new(start, start + next(30)),
                        parent: None,
                        children: Vec::new(),
                    }
                })
                .collect::<Vec<_>>();
            let depths = (0..count).map(|_| next(5) as usize).collect::<Vec<_>>();
            let outline = SyntaxOutline { nodes };
            let missing = (0..24)
                .map(|_| MissingSyntax {
                    offset: next(140),
                    expected: SyntaxKind::Semicolon,
                    owner: (next(3) == 0).then(|| next(count as u32 + 2) as usize),
                })
                .collect::<Vec<_>>();
            let exhaustive = missing
                .iter()
                .map(|missing| {
                    let contains = |node: &SyntaxOutlineNode| {
                        node.range.start <= missing.offset && missing.offset <= node.range.end
                    };
                    missing
                        .owner
                        .filter(|owner| outline.nodes.get(*owner).is_some_and(contains))
                        .or_else(|| {
                            outline
                                .nodes
                                .iter()
                                .enumerate()
                                .filter(|(_, node)| contains(node))
                                .max_by_key(|(id, node)| {
                                    (depths[*id], node.range.start, u32::MAX - node.range.end)
                                })
                                .map(|(id, _)| id)
                        })
                        .unwrap_or(0)
                })
                .collect::<Vec<_>>();
            assert_eq!(
                missing_token_owners(&outline, &depths, &missing),
                exhaustive
            );
        }
    }
}
impl<'tree> Iterator for GreenTokenIter<'tree> {
    type Item = &'tree GreenToken;
    fn next(&mut self) -> Option<Self::Item> {
        while let Some(element) = self.pending.pop() {
            match element {
                GreenElement::Node(node) => self.pending.extend(node.children.iter().rev()),
                GreenElement::Token(token) => return Some(token),
            }
        }
        None
    }
}
#[derive(Clone, Debug)]
pub(crate) struct SyntaxOutlineNode {
    pub(crate) kind: SyntaxKind,
    pub(crate) range: TextRange,
    parent: Option<usize>,
    children: Vec<usize>,
}
#[derive(Clone, Debug, Default)]
pub(crate) struct SyntaxOutline {
    nodes: Vec<SyntaxOutlineNode>,
}
/// One parser-inserted token with the syntax node that owned the failed
/// expectation. Retaining the owner avoids guessing at equal child/parent
/// recovery boundaries after the outline has been completed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MissingSyntax {
    pub(crate) offset: u32,
    pub(crate) expected: SyntaxKind,
    pub(crate) owner: Option<usize>,
}
#[derive(Clone, Debug, Default)]
pub(crate) struct SyntaxOutlineBuilder {
    outline: SyntaxOutline,
    stack: Vec<usize>,
}
#[derive(Clone, Debug)]
pub(crate) struct SyntaxOutlineCheckpoint {
    node_len: usize,
    stack: Vec<usize>,
    child_lengths: Vec<(usize, usize)>,
}
impl SyntaxOutlineBuilder {
    pub(crate) fn start(&mut self, kind: SyntaxKind, start: u32) -> usize {
        let parent = self.stack.last().copied();
        let id = self.outline.nodes.len();
        self.outline.nodes.push(SyntaxOutlineNode {
            kind,
            range: TextRange::empty(start),
            parent,
            children: Vec::new(),
        });
        if let Some(parent) = parent {
            self.outline.nodes[parent].children.push(id);
        }
        self.stack.push(id);
        id
    }
    /// Complete `id` and any still-open descendants at the same recovery
    /// boundary. Successful parses finish in strict stack order; unwinding
    /// descendants here keeps malformed input structurally balanced.
    pub(crate) fn finish(&mut self, id: usize, end: u32) {
        while let Some(current) = self.stack.pop() {
            if let Some(node) = self.outline.nodes.get_mut(current) {
                node.range.end = end.max(node.range.start);
            }
            if current == id {
                return;
            }
        }
    }
    pub(crate) fn set_kind(&mut self, id: usize, kind: SyntaxKind) {
        if let Some(node) = self.outline.nodes.get_mut(id) {
            node.kind = kind;
        }
    }
    pub(crate) fn current(&self) -> Option<usize> {
        self.stack.last().copied()
    }
    pub(crate) fn checkpoint(&self) -> SyntaxOutlineCheckpoint {
        SyntaxOutlineCheckpoint {
            node_len: self.outline.nodes.len(),
            stack: self.stack.clone(),
            child_lengths: self
                .stack
                .iter()
                .map(|id| (*id, self.outline.nodes[*id].children.len()))
                .collect(),
        }
    }
    pub(crate) fn rollback(&mut self, checkpoint: SyntaxOutlineCheckpoint) {
        self.outline.nodes.truncate(checkpoint.node_len);
        for (id, child_len) in checkpoint.child_lengths {
            if let Some(node) = self.outline.nodes.get_mut(id) {
                node.children.truncate(child_len);
            }
        }
        self.stack = checkpoint.stack;
    }
    pub(crate) fn finish_open_nodes(&mut self, end: u32) {
        while let Some(id) = self.stack.pop() {
            if let Some(node) = self.outline.nodes.get_mut(id) {
                node.range.end = end.max(node.range.start);
            }
        }
    }
    pub(crate) fn into_outline(self) -> SyntaxOutline {
        self.outline
    }
}
/// Build one lossless tree from the structural decisions recorded by the
/// canonical AST parser and the original trivia-bearing lexer tape.
/// The outline node that owns each missing token.
///
/// A recorded owner is kept when its range contains the missing offset.
/// Otherwise the owner is the deepest node containing the offset, ties broken
/// by the latest start, then the earliest end, then the highest node id. That
/// fallback is answered by one sweep over the offsets in increasing order with
/// an ordered active set, so recovery-heavy sources stay `O((n + m) log n)`
/// instead of scanning every node for every missing token.
fn missing_token_owners(
    outline: &SyntaxOutline,
    depths: &[usize],
    missing: &[MissingSyntax],
) -> Vec<usize> {
    use std::{
        cmp::Reverse,
        collections::{BTreeSet, BinaryHeap},
    };
    let contains = |node: &SyntaxOutlineNode, offset: u32| {
        node.range.start <= offset && offset <= node.range.end
    };
    let mut owners = missing
        .iter()
        .map(|missing| {
            missing.owner.filter(|owner| {
                outline
                    .nodes
                    .get(*owner)
                    .is_some_and(|node| contains(node, missing.offset))
            })
        })
        .collect::<Vec<_>>();
    let mut pending = (0..missing.len())
        .filter(|index| owners[*index].is_none())
        .collect::<Vec<_>>();
    if pending.is_empty() {
        return owners.into_iter().map(|owner| owner.unwrap_or(0)).collect();
    }
    pending.sort_by_key(|index| missing[*index].offset);
    let mut by_start = (0..outline.nodes.len()).collect::<Vec<_>>();
    by_start.sort_by_key(|id| outline.nodes[*id].range.start);
    let key = |id: usize| {
        let node = &outline.nodes[id];
        (depths[id], node.range.start, u32::MAX - node.range.end, id)
    };
    let mut active = BTreeSet::new();
    let mut expiry = BinaryHeap::new();
    let mut next = 0_usize;
    for index in pending {
        let offset = missing[index].offset;
        while let Some(&id) = by_start.get(next)
            && outline.nodes[id].range.start <= offset
        {
            active.insert(key(id));
            expiry.push(Reverse((outline.nodes[id].range.end, id)));
            next += 1;
        }
        while let Some(&Reverse((end, id))) = expiry.peek()
            && end < offset
        {
            expiry.pop();
            active.remove(&key(id));
        }
        owners[index] = active.last().map(|(_, _, _, id)| *id);
    }
    owners.into_iter().map(|owner| owner.unwrap_or(0)).collect()
}
pub(crate) fn build_tree_from_outline(
    source: SourceId,
    tokens: &[GreenToken],
    outline: &SyntaxOutline,
    missing: &[MissingSyntax],
) -> SyntaxTree {
    let Some(root) = outline.nodes.first() else {
        return SyntaxTree::new(
            source,
            GreenNode::new(
                SyntaxKind::Root,
                0,
                tokens.iter().copied().map(GreenElement::Token).collect(),
            ),
        );
    };
    let mut depths = vec![0_usize; outline.nodes.len()];
    for (id, node) in outline.nodes.iter().enumerate() {
        depths[id] = node
            .parent
            .and_then(|parent| depths.get(parent).copied())
            .unwrap_or_default()
            .saturating_add(usize::from(node.parent.is_some()));
    }
    let owners = missing_token_owners(outline, &depths, missing);
    let mut direct_missing = vec![Vec::<(u32, SyntaxKind)>::new(); outline.nodes.len()];
    for (missing, owner) in missing.iter().zip(owners) {
        direct_missing[owner].push((missing.offset, missing.expected));
    }
    for insertions in &mut direct_missing {
        insertions.sort_unstable_by_key(|(offset, _)| *offset);
    }
    struct Frame {
        node: usize,
        child: usize,
        missing: usize,
    }
    struct DirectEmissionBoundary {
        offset: u32,
        include_missing: bool,
        include_eof: bool,
    }
    fn emit_direct(
        events: &mut Vec<Event>,
        tokens: &[GreenToken],
        token: &mut usize,
        missing: &[(u32, SyntaxKind)],
        missing_index: &mut usize,
        boundary: DirectEmissionBoundary,
    ) {
        loop {
            let next_token = tokens.get(*token).filter(|token| {
                (token.kind == SyntaxKind::Eof && boundary.include_eof)
                    || token.range.start < boundary.offset
            });
            let next_missing = missing.get(*missing_index).filter(|(offset, _)| {
                *offset < boundary.offset
                    || (boundary.include_missing && *offset == boundary.offset)
            });
            match (next_token, next_missing) {
                (Some(token_value), Some((offset, expected)))
                    if *offset <= token_value.range.start =>
                {
                    events.push(Event::Missing {
                        expected: *expected,
                        offset: *offset,
                    });
                    *missing_index = missing_index.saturating_add(1);
                }
                (Some(_), _) => {
                    events.push(Event::Token(*token));
                    *token = token.saturating_add(1);
                }
                (None, Some((offset, expected))) => {
                    events.push(Event::Missing {
                        expected: *expected,
                        offset: *offset,
                    });
                    *missing_index = missing_index.saturating_add(1);
                }
                (None, None) => break,
            }
        }
    }
    let mut events = Vec::with_capacity(tokens.len().saturating_add(outline.nodes.len() * 2));
    events.push(Event::Start {
        kind: root.kind,
        offset: root.range.start,
    });
    let mut frames = vec![Frame {
        node: 0,
        child: 0,
        missing: 0,
    }];
    let mut token = 0_usize;
    while let Some(frame) = frames.last_mut() {
        let node = &outline.nodes[frame.node];
        if let Some(child_id) = node.children.get(frame.child).copied() {
            let child = &outline.nodes[child_id];
            emit_direct(
                &mut events,
                tokens,
                &mut token,
                &direct_missing[frame.node],
                &mut frame.missing,
                DirectEmissionBoundary {
                    offset: child.range.start,
                    include_missing: false,
                    include_eof: false,
                },
            );
            frame.child = frame.child.saturating_add(1);
            events.push(Event::Start {
                kind: child.kind,
                offset: child.range.start,
            });
            frames.push(Frame {
                node: child_id,
                child: 0,
                missing: 0,
            });
            continue;
        }
        let include_eof = frame.node == 0;
        emit_direct(
            &mut events,
            tokens,
            &mut token,
            &direct_missing[frame.node],
            &mut frame.missing,
            DirectEmissionBoundary {
                offset: node.range.end,
                include_missing: true,
                include_eof,
            },
        );
        events.push(Event::Finish {
            offset: node.range.end,
        });
        frames.pop();
    }
    while token < tokens.len() {
        events.insert(events.len().saturating_sub(1), Event::Token(token));
        token = token.saturating_add(1);
    }
    build_tree(source, tokens, events)
}
#[derive(Debug)]
pub(crate) enum Event {
    Start { kind: SyntaxKind, offset: u32 },
    Token(usize),
    Missing { expected: SyntaxKind, offset: u32 },
    Finish { offset: u32 },
}
struct NodeBuilder {
    kind: SyntaxKind,
    offset: u32,
    children: Vec<GreenElement>,
}
pub(crate) fn build_tree(
    source: SourceId,
    tokens: &[GreenToken],
    events: Vec<Event>,
) -> SyntaxTree {
    let mut stack = Vec::<NodeBuilder>::new();
    let mut root = None;
    for event in events {
        match event {
            Event::Start { kind, offset } => stack.push(NodeBuilder {
                kind,
                offset,
                children: Vec::new(),
            }),
            Event::Token(index) => {
                if let (Some(parent), Some(token)) = (stack.last_mut(), tokens.get(index)) {
                    parent.children.push(GreenElement::Token(*token));
                }
            }
            Event::Missing { expected, offset } => {
                if let Some(parent) = stack.last_mut() {
                    parent
                        .children
                        .push(GreenElement::Token(GreenToken::missing(offset, expected)));
                }
            }
            Event::Finish { offset } => {
                let Some(builder) = stack.pop() else {
                    continue;
                };
                let fallback = builder.offset.min(offset);
                let node = GreenNode::new(builder.kind, fallback, builder.children);
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(GreenElement::Node(Box::new(node)));
                } else {
                    root = Some(node);
                }
            }
        }
    }
    let root = root.unwrap_or_else(|| GreenNode::new(SyntaxKind::Root, 0, Vec::new()));
    SyntaxTree::new(source, root)
}
