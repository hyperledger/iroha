//! Complete flat callable type tapes, without recursive wire containers or references.

use iroha_data_model::smart_contract::manifest::{
    ContractEnumTypeDescriptorV1, ContractErrorTypeDescriptor,
};

use crate::entrypoint::type_structure::{FlatTypeNodeV1, TypeNodeViewV1};
use crate::{
    entrypoint::{EntrypointValueKindV1, EntrypointValueTypeV1},
    pointer_abi::PointerType,
};

mod analysis;
mod codec;
mod conversion;
pub use analysis::{CallNodeLayoutV1, CallSchemaSummaryV1};

/// One node in the sole V1 callable schema's preorder tape.
#[derive(Clone, Debug, PartialEq, Eq, norito::NoritoSchema)]
#[norito_schema(name = "ivm_abi::call::CallTypeNodeV1")]
pub enum CallTypeNodeV1 {
    /// Nominal product; field subtrees immediately follow in declaration order.
    Struct {
        /// Canonical nominal source identity.
        name: String,
        /// Ordered canonical field names.
        fields: Vec<String>,
    },
    /// Positional product with this number of inline child subtrees.
    Tuple(u32),
    /// Optional handle; one inline Some payload subtree follows.
    Option,
    /// Result handle; the Ok subtree precedes the Err subtree.
    Result,
    /// List handle; one inline element subtree follows.
    List {
        /// Exact source capacity, in 1 through 64.
        capacity: u8,
    },
    /// Exact public scalar/pointer kind, preserving String versus Blob identity.
    Leaf(EntrypointValueKindV1),
    /// Canonical zero scalar.
    Unit,
    /// Exact nominal error identity and permitted enum-local codes.
    Error(ContractErrorTypeDescriptor),
    /// Canonical cursor bound to one complete scalar-or-tuple map-key schema.
    StateCursor(EntrypointValueTypeV1),
    /// Compiler-owned durable-state root handle.
    StateRoot,
    /// Internal pointer type with no public boundary leaf representation.
    Pointer(u16),
    /// Private numeric handle for Int, Decimal, or Quantity.
    SecretNumeric(u16),
    /// Exact ordinary enum identity and permitted enum-local codes.
    Enum(ContractEnumTypeDescriptorV1),
}
impl CallTypeNodeV1 {
    /// Number of inline child subtrees immediately following this node.
    #[must_use]
    pub fn child_count(&self) -> usize {
        self.type_node_view().child_count()
    }
    /// Whether the leaf's complete storage word carries a private memory tag.
    #[must_use]
    pub const fn is_private(&self) -> bool {
        matches!(self, Self::SecretNumeric(_))
    }
    /// Pointer envelope type for a leaf, if it is represented by a pointer.
    #[must_use]
    pub fn pointer_type(&self) -> Option<PointerType> {
        use EntrypointValueKindV1 as Kind;
        Some(match self {
            Self::Pointer(id) | Self::SecretNumeric(id) => return PointerType::from_u16(*id),
            Self::StateCursor(_) => PointerType::NoritoBytes,
            Self::Leaf(kind) => match kind {
                Kind::Bool => return None,
                Kind::Int => PointerType::Int,
                Kind::Decimal => PointerType::Decimal,
                Kind::Quantity => PointerType::Quantity,
                Kind::String | Kind::Blob => PointerType::Blob,
                Kind::Json => PointerType::Json,
                Kind::Name => PointerType::Name,
                Kind::AccountId => PointerType::AccountId,
                Kind::AssetDefinitionId => PointerType::AssetDefinitionId,
                Kind::AssetId => PointerType::AssetId,
                Kind::DomainId => PointerType::DomainId,
                Kind::NftId => PointerType::NftId,
                Kind::DataSpaceId => PointerType::DataSpaceId,
            },
            _ => return None,
        })
    }
}

impl FlatTypeNodeV1 for CallTypeNodeV1 {
    fn type_node_view(&self) -> TypeNodeViewV1<'_> {
        match self {
            Self::Struct { name, fields } => TypeNodeViewV1::Struct { name, fields },
            Self::Tuple(arity) => TypeNodeViewV1::Tuple(*arity as usize),
            Self::Option => TypeNodeViewV1::Option,
            Self::Result => TypeNodeViewV1::Result,
            Self::List { capacity } => TypeNodeViewV1::List(*capacity),
            Self::Leaf(kind) => TypeNodeViewV1::Leaf(*kind),
            Self::StateCursor(key) => TypeNodeViewV1::StateCursor(key),
            Self::Unit
            | Self::Error(_)
            | Self::Enum(_)
            | Self::StateRoot
            | Self::Pointer(_)
            | Self::SecretNumeric(_) => TypeNodeViewV1::Other,
        }
    }
}

/// A bounded forest of exact callable types with inline children and no references.
#[repr(transparent)]
#[derive(Clone, Debug, PartialEq, Eq, norito::NoritoSchema)]
#[norito_schema(name = "ivm_abi::call::CallSchemaV1")]
pub struct CallSchemaV1 {
    /// Complete preorder nodes; empty only for a function without arguments.
    pub nodes: Vec<CallTypeNodeV1>,
}

impl CallSchemaV1 {
    /// Empty argument forest.
    #[must_use]
    pub const fn empty() -> Self {
        Self { nodes: Vec::new() }
    }
    /// Complete Unit result tree.
    #[must_use]
    pub fn unit() -> Self {
        Self {
            nodes: vec![CallTypeNodeV1::Unit],
        }
    }
    /// Whether any descendant requires private numeric storage.
    #[must_use]
    pub fn contains_private(&self) -> bool {
        self.nodes.iter().any(CallTypeNodeV1::is_private)
    }
    /// Exact flattened table width derived from all root trees.
    #[must_use]
    pub fn word_count(&self) -> Option<usize> {
        Some(self.analyze()?.word_count())
    }
}
