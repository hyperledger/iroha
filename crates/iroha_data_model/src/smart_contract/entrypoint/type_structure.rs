//! Allocation-free structure and reserved nominal shapes shared by boundary and callable schemas.
//!
//! These borrowed views have no wire representation. Each owner enforces its own node/depth
//! budget before checking nominal shapes; private callable types do not inherit public limits.

use super::{
    EntrypointValueKindV1 as Kind, EntrypointValueTypeNodeV1, EntrypointValueTypeV1,
    MAX_ENTRYPOINT_LIST_CAPACITY_V1,
};

/// Borrowed structural information needed to validate a flat type tape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TypeNodeViewV1<'a> {
    /// Named product with ordered inline child subtrees.
    Struct {
        /// Exact nominal source identity.
        name: &'a str,
        /// Ordered field names.
        fields: &'a [String],
    },
    /// Positional product with this number of inline child subtrees.
    Tuple(usize),
    /// One optional payload subtree.
    Option,
    /// Ok and Err payload subtrees, in that order.
    Result,
    /// One element subtree and the exact capacity.
    List(u8),
    /// Exact public scalar kind.
    Leaf(Kind),
    /// Exact scalar or tuple cursor key schema.
    StateCursor(&'a EntrypointValueTypeV1),
    /// Another leaf with no children (Unit, nominal enum/error, or internal/private leaf).
    Other,
}
impl TypeNodeViewV1<'_> {
    /// Number of inline child subtrees.
    #[must_use]
    pub fn child_count(self) -> usize {
        match self {
            Self::Struct { fields, .. } => fields.len(),
            Self::Tuple(arity) => arity,
            Self::Option | Self::List(_) => 1,
            Self::Result => 2,
            _ => 0,
        }
    }
}

/// A flat schema node exposing its structure without cloning or allocating.
pub trait FlatTypeNodeV1 {
    /// Borrow the node's shape; children are always inline in preorder.
    fn type_node_view(&self) -> TypeNodeViewV1<'_>;
}
impl FlatTypeNodeV1 for EntrypointValueTypeNodeV1 {
    fn type_node_view(&self) -> TypeNodeViewV1<'_> {
        match self {
            Self::Struct(product) => TypeNodeViewV1::Struct {
                name: &product.name,
                fields: &product.fields,
            },
            Self::Tuple(arity) => TypeNodeViewV1::Tuple(usize::from(*arity)),
            Self::Option => TypeNodeViewV1::Option,
            Self::Result => TypeNodeViewV1::Result,
            Self::List(list) => TypeNodeViewV1::List(list.capacity),
            Self::Leaf(kind) => TypeNodeViewV1::Leaf(*kind),
            Self::StateCursor(key) => TypeNodeViewV1::StateCursor(key),
            Self::Unit | Self::Error(_) | Self::Enum(_) => TypeNodeViewV1::Other,
        }
    }
}

/// Return one structurally complete subtree range without applying an owner's size budget.
#[must_use]
pub fn subtree_range_v1<N: FlatTypeNodeV1>(
    nodes: &[N],
    start: usize,
) -> Option<std::ops::Range<usize>> {
    let mut index = start;
    let mut pending = 1_usize;
    while pending != 0 {
        let node = nodes.get(index)?;
        index = index.checked_add(1)?;
        pending = pending
            .checked_sub(1)?
            .checked_add(node.type_node_view().child_count())?;
    }
    Some(start..index)
}

pub(super) fn is_core_query_view_name(name: &str) -> bool {
    matches!(
        name,
        "kotodama::AccountView"
            | "kotodama::AssetView"
            | "kotodama::AssetDefinitionView"
            | "kotodama::DomainView"
            | "kotodama::NftView"
    )
}

fn core_query_view_nodes_name<N: FlatTypeNodeV1>(nodes: &[N]) -> Option<(&str, usize)> {
    use TypeNodeViewV1::{Leaf, Option as Optional};
    let TypeNodeViewV1::Struct { name, fields } = nodes.first()?.type_node_view() else {
        return None;
    };
    let (names, shape): (&[&str], &[TypeNodeViewV1<'_>]) = match name {
        "kotodama::AccountView" => (
            &["id", "metadata"],
            &[Leaf(Kind::AccountId), Leaf(Kind::Json)],
        ),
        "kotodama::AssetView" => (
            &["id", "amount"],
            &[Leaf(Kind::AssetId), Leaf(Kind::Quantity)],
        ),
        "kotodama::AssetDefinitionView" => (
            &[
                "id",
                "name",
                "description",
                "owned_by",
                "total_quantity",
                "numeric_scale",
                "metadata",
            ],
            &[
                Leaf(Kind::AssetDefinitionId),
                Leaf(Kind::String),
                Optional,
                Leaf(Kind::String),
                Leaf(Kind::AccountId),
                Leaf(Kind::Quantity),
                Optional,
                Leaf(Kind::Int),
                Leaf(Kind::Json),
            ],
        ),
        "kotodama::DomainView" => (
            &["id", "owned_by", "metadata"],
            &[
                Leaf(Kind::DomainId),
                Leaf(Kind::AccountId),
                Leaf(Kind::Json),
            ],
        ),
        "kotodama::NftView" => (
            &["id", "owned_by", "content"],
            &[Leaf(Kind::NftId), Leaf(Kind::AccountId), Leaf(Kind::Json)],
        ),
        _ => return None,
    };
    if !fields.iter().map(String::as_str).eq(names.iter().copied())
        || !nodes
            .iter()
            .skip(1)
            .take(shape.len())
            .map(FlatTypeNodeV1::type_node_view)
            .eq(shape.iter().copied())
    {
        return None;
    }
    Some((name, shape.len() + 1))
}

fn core_query_view_range<N: FlatTypeNodeV1>(
    nodes: &[N],
    start: usize,
) -> Option<std::ops::Range<usize>> {
    let (_, consumed) = core_query_view_nodes_name(nodes.get(start..)?)?;
    let expected_end = start.checked_add(consumed)?;
    let range = subtree_range_v1(nodes, start)?;
    (range.end == expected_end).then_some(range)
}

fn valid_state_page_shape<N: FlatTypeNodeV1>(nodes: &[N], start: usize) -> Option<()> {
    let TypeNodeViewV1::Struct { fields, .. } = nodes.get(start)?.type_node_view() else {
        return None;
    };
    if fields != ["items", "next"] {
        return None;
    }
    let TypeNodeViewV1::List(capacity) = nodes.get(start.checked_add(1)?)?.type_node_view() else {
        return None;
    };
    if !(1..=64).contains(&capacity)
        || nodes.get(start.checked_add(2)?)?.type_node_view() != TypeNodeViewV1::Tuple(2)
    {
        return None;
    }
    let key_range = subtree_range_v1(nodes, start.checked_add(3)?)?;
    let value_end = subtree_range_v1(nodes, key_range.end)?.end;
    let TypeNodeViewV1::StateCursor(key) = nodes.get(value_end.checked_add(1)?)?.type_node_view()
    else {
        return None;
    };
    (super::validate_state_key_schema_v1(key)
        && nodes
            .get(key_range)?
            .iter()
            .map(FlatTypeNodeV1::type_node_view)
            .eq(key.nodes.iter().map(FlatTypeNodeV1::type_node_view))
        && nodes.get(value_end)?.type_node_view() == TypeNodeViewV1::Option
        && subtree_range_v1(nodes, start)?.end == value_end.checked_add(2)?)
    .then_some(())
}

/// Validate every reserved nominal shape in an already structurally validated type forest.
///
/// This checks the exact core view, `QueryPage`, and `StatePage` field/type identities. The caller
/// retains its own node/depth limits and leaf privacy/resource policy; no allocation occurs.
#[must_use]
pub fn validate_reserved_nominal_shapes_v1<N: FlatTypeNodeV1>(nodes: &[N]) -> bool {
    for (start, node) in nodes.iter().enumerate() {
        let TypeNodeViewV1::Struct { name, fields } = node.type_node_view() else {
            continue;
        };
        if is_core_query_view_name(name) {
            if core_query_view_range(nodes, start).is_none() {
                return false;
            }
            continue;
        }
        if name == "kotodama::StatePage" {
            if valid_state_page_shape(nodes, start).is_none() {
                return false;
            }
            continue;
        }
        if name != "kotodama::QueryPage" {
            continue;
        }
        if fields != ["items", "next_offset"] {
            return false;
        }
        let Some(root_range) = subtree_range_v1(nodes, start) else {
            return false;
        };
        let Some(list_start) = start.checked_add(1) else {
            return false;
        };
        if nodes.get(list_start).map(FlatTypeNodeV1::type_node_view)
            != Some(TypeNodeViewV1::List(MAX_ENTRYPOINT_LIST_CAPACITY_V1))
        {
            return false;
        }
        let Some(element_start) = list_start.checked_add(1) else {
            return false;
        };
        let Some(element_range) = core_query_view_range(nodes, element_start) else {
            return false;
        };
        let Some(list_range) = subtree_range_v1(nodes, list_start) else {
            return false;
        };
        let next_offset_start = element_range.end;
        let Some(next_offset_leaf) = next_offset_start.checked_add(1) else {
            return false;
        };
        let Some(next_offset_end) = next_offset_leaf.checked_add(1) else {
            return false;
        };
        if list_range.end != element_range.end
            || nodes
                .get(next_offset_start)
                .map(FlatTypeNodeV1::type_node_view)
                != Some(TypeNodeViewV1::Option)
            || nodes
                .get(next_offset_leaf)
                .map(FlatTypeNodeV1::type_node_view)
                != Some(TypeNodeViewV1::Leaf(Kind::Int))
            || subtree_range_v1(nodes, next_offset_start)
                != Some(next_offset_start..next_offset_end)
            || root_range.end != next_offset_end
        {
            return false;
        }
    }
    true
}
