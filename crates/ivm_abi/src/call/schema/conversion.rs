//! Lossless conversion of already validated public type records into callable tapes.

use super::{CallSchemaV1, CallTypeNodeV1};
use crate::entrypoint::{
    EntrypointArgumentSchemaV1, EntrypointValueTypeNodeV1, EntrypointValueTypeV1,
};

impl CallSchemaV1 {
    /// Compare one public schema without allocating a converted copy.
    #[must_use]
    pub fn matches_entrypoint_type(&self, schema: &EntrypointValueTypeV1) -> bool {
        schema.validate() && self.matches_public_nodes(&schema.nodes)
    }
    /// Compare the full public parameter forest without allocating a converted copy.
    #[must_use]
    pub fn matches_entrypoint_arguments(&self, schema: &EntrypointArgumentSchemaV1) -> bool {
        if !schema.validate() {
            return false;
        }
        let mut offset = 0_usize;
        for field in &schema.fields {
            let Some(end) = offset.checked_add(field.ty.nodes.len()) else {
                return false;
            };
            let Some(nodes) = self.nodes.get(offset..end) else {
                return false;
            };
            if !matches_public_nodes(nodes, &field.ty.nodes) {
                return false;
            }
            offset = end;
        }
        offset == self.nodes.len()
    }
    fn matches_public_nodes(&self, nodes: &[EntrypointValueTypeNodeV1]) -> bool {
        matches_public_nodes(&self.nodes, nodes)
    }
    /// Convert one valid public type without erasing nominal or nested information.
    #[must_use]
    pub fn from_entrypoint_type(schema: &EntrypointValueTypeV1) -> Option<Self> {
        if !schema.validate() {
            return None;
        }
        let mut result = Self::empty();
        result.append_public_nodes(&schema.nodes);
        Some(result)
    }
    /// Convert all valid public parameters in their declared order.
    #[must_use]
    pub fn from_entrypoint_arguments(schema: &EntrypointArgumentSchemaV1) -> Option<Self> {
        if !schema.validate() {
            return None;
        }
        let count = schema.fields.iter().try_fold(0_usize, |count, field| {
            count.checked_add(field.ty.nodes.len())
        })?;
        if count > crate::call::MAX_CALL_SCHEMA_NODES_V1 {
            return None;
        }
        let mut result = Self {
            nodes: Vec::with_capacity(count),
        };
        for field in &schema.fields {
            result.append_public_nodes(&field.ty.nodes);
        }
        Some(result)
    }
    fn append_public_nodes(&mut self, nodes: &[EntrypointValueTypeNodeV1]) {
        self.nodes.extend(nodes.iter().map(|node| match node {
            EntrypointValueTypeNodeV1::Struct(product) => CallTypeNodeV1::Struct {
                name: product.name.clone(),
                fields: product.fields.clone(),
            },
            EntrypointValueTypeNodeV1::Tuple(arity) => CallTypeNodeV1::Tuple(u32::from(*arity)),
            EntrypointValueTypeNodeV1::Option => CallTypeNodeV1::Option,
            EntrypointValueTypeNodeV1::Result => CallTypeNodeV1::Result,
            EntrypointValueTypeNodeV1::List(list) => CallTypeNodeV1::List {
                capacity: list.capacity,
            },
            EntrypointValueTypeNodeV1::Leaf(kind) => CallTypeNodeV1::Leaf(*kind),
            EntrypointValueTypeNodeV1::Unit => CallTypeNodeV1::Unit,
            EntrypointValueTypeNodeV1::Error(error) => CallTypeNodeV1::Error(error.clone()),
            EntrypointValueTypeNodeV1::Enum(enumeration) => {
                CallTypeNodeV1::Enum(enumeration.clone())
            }
            EntrypointValueTypeNodeV1::StateCursor(key) => CallTypeNodeV1::StateCursor(key.clone()),
        }));
    }
}

fn matches_public_nodes(nodes: &[CallTypeNodeV1], public: &[EntrypointValueTypeNodeV1]) -> bool {
    nodes.len() == public.len()
        && nodes
            .iter()
            .zip(public)
            .all(|(node, public)| match (node, public) {
                (
                    CallTypeNodeV1::Struct { name, fields },
                    EntrypointValueTypeNodeV1::Struct(product),
                ) => name == &product.name && fields == &product.fields,
                (CallTypeNodeV1::Tuple(arity), EntrypointValueTypeNodeV1::Tuple(expected)) => {
                    *arity == u32::from(*expected)
                }
                (CallTypeNodeV1::Option, EntrypointValueTypeNodeV1::Option)
                | (CallTypeNodeV1::Result, EntrypointValueTypeNodeV1::Result)
                | (CallTypeNodeV1::Unit, EntrypointValueTypeNodeV1::Unit) => true,
                (CallTypeNodeV1::List { capacity }, EntrypointValueTypeNodeV1::List(list)) => {
                    *capacity == list.capacity
                }
                (CallTypeNodeV1::Leaf(kind), EntrypointValueTypeNodeV1::Leaf(expected)) => {
                    kind == expected
                }
                (
                    CallTypeNodeV1::StateCursor(kind),
                    EntrypointValueTypeNodeV1::StateCursor(expected),
                ) => kind == expected,
                (CallTypeNodeV1::Error(error), EntrypointValueTypeNodeV1::Error(expected)) => {
                    error == expected
                }
                (CallTypeNodeV1::Enum(enumeration), EntrypointValueTypeNodeV1::Enum(expected)) => {
                    enumeration == expected
                }
                _ => false,
            })
}
