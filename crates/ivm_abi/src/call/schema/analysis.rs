//! Allocation-free shape validation and caller-funded traversal layouts.

use super::{CallSchemaV1, CallTypeNodeV1};
use crate::{
    call::{MAX_CALL_SCHEMA_DEPTH_V1, MAX_CALL_SCHEMA_NODES_V1},
    entrypoint::{
        is_canonical_kotodama_identifier, is_canonical_kotodama_struct_name,
        state_key_schema_depth_v1,
    },
    list::ListLayoutV1,
    pointer_abi::PointerType,
    sum::SumLayoutV1,
};

/// Derived traversal layout for one node of the authenticated schema.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CallNodeLayoutV1 {
    /// First node after this complete subtree.
    pub subtree_end: usize,
    /// Flattened width of the value; a Sum or List handle always occupies one word.
    pub words: usize,
}

/// Allocation-free summary of a validated callable forest.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CallSchemaSummaryV1 {
    roots: usize,
    words: usize,
}
impl CallSchemaSummaryV1 {
    /// Number of complete type trees in the forest.
    #[must_use]
    pub const fn root_count(self) -> usize {
        self.roots
    }
    /// Exact flattened width of all forest roots.
    #[must_use]
    pub const fn word_count(self) -> usize {
        self.words
    }
}

#[derive(Clone, Copy, Default)]
struct Frame {
    node: usize,
    remaining: usize,
    children: usize,
    words: usize,
    first_words: usize,
    last_words: usize,
    resource: bool,
}

fn valid_node(node: &CallTypeNodeV1) -> bool {
    match node {
        CallTypeNodeV1::Struct { name, fields } => {
            is_canonical_kotodama_struct_name(name)
                && fields
                    .iter()
                    .all(|name| is_canonical_kotodama_identifier(name))
                && unique_fields(fields)
        }
        CallTypeNodeV1::Tuple(arity) => *arity >= 2,
        CallTypeNodeV1::List { capacity } => (1..=64).contains(capacity),
        CallTypeNodeV1::Error(error) => error.validate(),
        CallTypeNodeV1::Enum(enumeration) => enumeration.validate(),
        CallTypeNodeV1::StateCursor(key) => crate::entrypoint::validate_state_key_schema_v1(key),
        CallTypeNodeV1::Pointer(id) => matches!(
            PointerType::from_u16(*id),
            Some(
                PointerType::AxtDescriptor
                    | PointerType::AxtAnchoredSpendV1
                    | PointerType::ProofBlob
                    | PointerType::SoracloudRequest
                    | PointerType::SoracloudResponse
            )
        ),
        CallTypeNodeV1::SecretNumeric(id) => matches!(
            PointerType::from_u16(*id),
            Some(PointerType::Int | PointerType::Decimal | PointerType::Quantity)
        ),
        _ => true,
    }
}

fn unique_fields(fields: &[String]) -> bool {
    // Sort bounded index batches, never the authenticated declaration order.
    // No allocation or attacker-controlled hash buckets are needed.
    let mut indexes = [0_usize; 1024];
    for start in (0..fields.len()).step_by(indexes.len()) {
        let end = start.saturating_add(indexes.len()).min(fields.len());
        let batch = &mut indexes[..end - start];
        for (index, slot) in batch.iter_mut().enumerate() {
            *slot = start + index;
        }
        batch.sort_unstable_by(|left, right| fields[*left].cmp(&fields[*right]));
        if batch
            .windows(2)
            .any(|pair| fields[pair[0]] == fields[pair[1]])
        {
            return false;
        }
        if fields[end..].iter().any(|name| {
            batch
                .binary_search_by(|index| fields[*index].cmp(name))
                .is_ok()
        }) {
            return false;
        }
    }
    true
}

impl CallSchemaV1 {
    /// Exact backing bytes required for a layout slice, before any allocation.
    #[must_use]
    pub fn analysis_reservation_bytes(&self) -> Option<usize> {
        (self.nodes.len() <= MAX_CALL_SCHEMA_NODES_V1)
            .then_some(self.nodes.len())?
            .checked_mul(core::mem::size_of::<CallNodeLayoutV1>())
    }
    /// Validate the full forest and derive table counts without allocating.
    #[must_use]
    pub fn analyze(&self) -> Option<CallSchemaSummaryV1> {
        self.scan(None)
    }
    /// Validate and fill a caller-funded layout slice of exactly `nodes.len()` entries.
    ///
    /// Failure may leave a partially filled slice; it must never be published or used.
    #[must_use]
    pub fn analyze_into(&self, layouts: &mut [CallNodeLayoutV1]) -> Option<CallSchemaSummaryV1> {
        if layouts.len() != self.nodes.len() {
            return None;
        }
        self.scan(Some(layouts))
    }
    fn scan(&self, mut layouts: Option<&mut [CallNodeLayoutV1]>) -> Option<CallSchemaSummaryV1> {
        self.analysis_reservation_bytes()?;
        let mut stack = [Frame::default(); MAX_CALL_SCHEMA_DEPTH_V1];
        let mut depth = 0_usize;
        let mut node_count = self.nodes.len();
        let mut summary = CallSchemaSummaryV1::default();
        for (index, node) in self.nodes.iter().enumerate() {
            if let CallTypeNodeV1::StateCursor(key) = node {
                node_count = node_count.checked_add(key.nodes.len())?;
                if node_count > MAX_CALL_SCHEMA_NODES_V1
                    || depth
                        .checked_add(1)?
                        .checked_add(state_key_schema_depth_v1(key)?)?
                        > MAX_CALL_SCHEMA_DEPTH_V1
                {
                    return None;
                }
            }
            let children = node.child_count();
            if depth.checked_add(1)? > MAX_CALL_SCHEMA_DEPTH_V1
                || children > self.nodes.len().checked_sub(index + 1)?
                || !valid_node(node)
            {
                return None;
            }
            if children != 0 {
                stack[depth] = Frame {
                    node: index,
                    remaining: children,
                    children,
                    ..Frame::default()
                };
                depth += 1;
                continue;
            }
            let mut finished = index;
            let mut words = 1;
            let mut resource = matches!(
                node,
                CallTypeNodeV1::StateRoot | CallTypeNodeV1::SecretNumeric(_)
            ) || matches!(node, CallTypeNodeV1::Pointer(id) if *id == PointerType::AxtAnchoredSpendV1 as u16);
            loop {
                if let Some(layouts) = layouts.as_deref_mut() {
                    layouts[finished] = CallNodeLayoutV1 {
                        subtree_end: index + 1,
                        words,
                    };
                }
                if depth == 0 {
                    summary.roots = summary.roots.checked_add(1)?;
                    summary.words = summary.words.checked_add(words)?;
                    break;
                }
                let parent = &mut stack[depth - 1];
                if parent.remaining == parent.children {
                    parent.first_words = words;
                }
                parent.last_words = words;
                parent.words = parent.words.checked_add(words)?;
                parent.resource |= resource;
                parent.remaining = parent.remaining.checked_sub(1)?;
                if parent.remaining != 0 {
                    break;
                }
                finished = parent.node;
                resource = parent.resource;
                words = match &self.nodes[finished] {
                    CallTypeNodeV1::Option => {
                        SumLayoutV1::option(u64::try_from(parent.first_words).ok()?).ok()?;
                        1
                    }
                    CallTypeNodeV1::Result => {
                        SumLayoutV1::try_new(
                            u64::try_from(parent.last_words).ok()?,
                            u64::try_from(parent.first_words).ok()?,
                        )
                        .ok()?;
                        1
                    }
                    CallTypeNodeV1::List { capacity } => {
                        if resource {
                            return None;
                        }
                        ListLayoutV1::try_new(
                            u64::from(*capacity),
                            u64::try_from(parent.first_words).ok()?,
                        )
                        .ok()?;
                        1
                    }
                    CallTypeNodeV1::Struct { .. } | CallTypeNodeV1::Tuple(_) => parent.words,
                    _ => return None,
                };
                depth -= 1;
            }
        }
        (depth == 0
            && crate::entrypoint::type_structure::validate_reserved_nominal_shapes_v1(&self.nodes))
        .then_some(summary)
    }
}
