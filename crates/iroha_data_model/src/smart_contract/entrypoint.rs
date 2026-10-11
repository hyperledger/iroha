//! Exact recursive boundary schemas for Kotodama entrypoints.
//!
//! JSON is accepted only at client-facing boundaries. The compiler embeds these
//! schemas in the signed contract interface so hosts can bind argument records
//! and return registers to one canonical, recursively typed ABI description.

use crate::{
    DeriveFastJson as DeriveFast, DeriveJsonDeserialize as DeriveJsonDe,
    DeriveJsonSerialize as DeriveJsonSer,
};
use iroha_crypto::Hash;
use iroha_schema::IntoSchema;
use norito::{Decode, DeserializePayload, Encode};
// BEGIN GENERATED: kotodama-v1-source-identifier-policy
/// Exact identifier spellings forbidden in every Kotodama V1 source position.
const KOTODAMA_V1_FORBIDDEN_SOURCE_IDENTIFIERS: &[&str] = &["Amount"];
/// Compiler-owned names forbidden for source-unit and struct declarations.
const KOTODAMA_V1_RESERVED_TYPE_DECLARATIONS: &[&str] = &[
    "int",
    "decimal",
    "quantity",
    "bool",
    "string",
    "bytes",
    "Json",
    "AccountId",
    "AssetDefinitionId",
    "AssetId",
    "DomainId",
    "Name",
    "NftId",
    "DataSpaceId",
    "Option",
    "Result",
    "List",
    "ListError",
    "NumericError",
    "StateMap",
    "StateCursor",
    "StatePage",
    "Secret",
    "AccountView",
    "AssetView",
    "AssetDefinitionView",
    "DomainView",
    "NftView",
    "QueryPage",
    "AxtDescriptor",
    "AxtAnchoredSpendV1",
    "ProofBlob",
    "SoracloudRequest",
    "SoracloudResponse",
    "state_map_get",
    "__kotodama_state_page",
    "__kotodama_state_take",
    "__kotodama_list_len",
    "__kotodama_list_get",
    "__kotodama_list_set",
    "__kotodama_list_push",
    "__kotodama_list_try_set",
    "__kotodama_list_try_push",
    "__kotodama_list_pop",
    "__kotodama_list_contains",
    "__kotodama_list_take",
    "__kotodama_list_enumerate",
    "__kotodama_decimal_div_round",
    "__kotodama_decimal_mul_div_round",
    "__kotodama_quantity_mul_div_round",
    "__kotodama_quantity_div_round",
    "__kotodama_quantity_ratio_round",
    "__kotodama_decimal_to_int_trunc",
    "__kotodama_decimal_to_int_round",
    "__kotodama_option_ok_or",
    "__kotodama_result_or_err",
    "i8",
    "i16",
    "i32",
    "i64",
    "i128",
    "isize",
    "u8",
    "u16",
    "u32",
    "u64",
    "u128",
    "usize",
    "num",
    "Int",
    "Integer",
    "float",
    "f32",
    "f64",
    "Decimal",
    "Fixed",
    "FixedPoint",
    "Amount",
    "amount",
    "money",
    "Quantity",
    "number",
];
// END GENERATED: kotodama-v1-source-identifier-policy
/// Domain separator for hashes binding public argument records to exact schemas.
pub const ENTRYPOINT_ARGUMENT_SCHEMA_HASH_DOMAIN_V1: &[u8] =
    b"KOTODAMA_ENTRYPOINT_ARGUMENT_SCHEMA_V1\0";
/// Domain separator for hashes binding return records to exact value schemas.
pub const ENTRYPOINT_RETURN_SCHEMA_HASH_DOMAIN_V1: &[u8] =
    b"KOTODAMA_ENTRYPOINT_RETURN_SCHEMA_V1\0";
/// Hash an exact encoded V1 argument schema with its dedicated domain separator.
#[must_use]
pub fn entrypoint_argument_schema_hash_v1(schema_payload: &[u8]) -> [u8; 32] {
    let mut material =
        Vec::with_capacity(ENTRYPOINT_ARGUMENT_SCHEMA_HASH_DOMAIN_V1.len() + schema_payload.len());
    material.extend_from_slice(ENTRYPOINT_ARGUMENT_SCHEMA_HASH_DOMAIN_V1);
    material.extend_from_slice(schema_payload);
    Hash::new(&material).into()
}
/// Hash an exact encoded V1 return schema with its dedicated domain separator.
#[must_use]
pub fn entrypoint_return_schema_hash_v1(schema_payload: &[u8]) -> [u8; 32] {
    let mut material =
        Vec::with_capacity(ENTRYPOINT_RETURN_SCHEMA_HASH_DOMAIN_V1.len() + schema_payload.len());
    material.extend_from_slice(ENTRYPOINT_RETURN_SCHEMA_HASH_DOMAIN_V1);
    material.extend_from_slice(schema_payload);
    Hash::new(&material).into()
}
/// Maximum number of public source parameters carried by ABI V1.
pub const MAX_ENTRYPOINT_ARGUMENTS: usize = 8192;
/// Maximum flattened public argument words in the 64 KiB V1 call table.
pub const MAX_ENTRYPOINT_ARGUMENT_WORDS: usize = 8192;
/// Maximum flattened public result words in the 64 KiB V1 call table.
pub const MAX_ENTRYPOINT_RETURN_WORDS: usize = 8192;
/// Maximum recursive type nodes in one V1 boundary schema.
pub const MAX_ENTRYPOINT_ARGUMENT_TYPE_NODES: usize = 256;
/// Maximum recursive aggregate depth in one V1 boundary schema.
pub const MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH: usize = 256;
/// Minimum capacity accepted for a boundary `List<T, N>`.
pub const MIN_ENTRYPOINT_LIST_CAPACITY_V1: u8 = 1;
/// Maximum capacity accepted for a boundary `List<T, N>`.
pub const MAX_ENTRYPOINT_LIST_CAPACITY_V1: u8 = 64;
/// Maximum encoded compiler schema accepted by the V1 argument decoder.
pub const MAX_ENTRYPOINT_ARGUMENT_SCHEMA_BYTES: usize = 64 * 1024;
/// Maximum complete encoded payload envelope at one public V1 contract boundary.
pub const MAX_ENTRYPOINT_BOUNDARY_BYTES: usize =
    crate::transaction::executable::MAX_CONTRACT_ARGUMENT_RECORD_BYTES;
/// Maximum canonical Norito argument record accepted by one public V1 invocation.
pub const MAX_ENTRYPOINT_ARGUMENT_RECORD_BYTES: usize = MAX_ENTRYPOINT_BOUNDARY_BYTES;
/// Fixed V1 pointer-ABI envelope around a `NoritoBytes` return payload.
///
/// The layout is `type: u16`, `version: u8`, `length: u32`, and a 32-byte
/// payload hash, for seven header bytes plus [`Hash::LENGTH`].
pub const ENTRYPOINT_RETURN_TLV_ENVELOPE_BYTES_V1: usize = 7 + Hash::LENGTH;
/// Maximum canonical Norito return record accepted from one public V1 invocation.
///
/// The complete `NoritoBytes` TLV published by `CALL_CONTRACT`, not merely its
/// payload, must fit the existing one-mebibyte contract-boundary allocation.
/// Return collectors enforce this payload limit before cloning pointed VM data
/// and check the exact framed Norito length before publishing the record.
pub const MAX_ENTRYPOINT_RETURN_RECORD_BYTES: usize =
    MAX_ENTRYPOINT_BOUNDARY_BYTES - ENTRYPOINT_RETURN_TLV_ENVELOPE_BYTES_V1;
/// Leaf representation used at a public Kotodama boundary.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveFast,
    DeriveJsonSer,
    DeriveJsonDe,
)]
#[norito(no_fast_from_json)]
#[norito(tag = "kind", content = "value", deny_unknown_fields)]
#[norito(decode_from_slice)]
pub enum EntrypointValueKindV1 {
    /// Canonical signed 512-bit integer pointer.
    Int,
    /// Canonical exact decimal pointer.
    Decimal,
    /// Canonical non-negative nominal asset-quantity pointer.
    Quantity,
    /// Boolean scalar carried as exactly zero or one.
    Bool,
    /// UTF-8 string carried as a `Blob` pointer.
    String,
    /// Nested JSON value carried as a `Json` pointer.
    Json,
    /// Validated [`iroha_model_base::name::Name`] pointer.
    Name,
    /// Validated universal account identifier pointer.
    AccountId,
    /// Validated asset-definition identifier pointer.
    AssetDefinitionId,
    /// Validated full asset identifier pointer.
    AssetId,
    /// Validated domain identifier pointer.
    DomainId,
    /// Validated NFT identifier pointer.
    NftId,
    /// Validated dataspace identifier pointer.
    DataSpaceId,
    /// Raw bytes carried as a `Blob` pointer.
    Blob,
}
impl EntrypointValueKindV1 {
    /// Return whether the value occupies a validated pointer word.
    #[must_use]
    pub const fn is_pointer(self) -> bool {
        !matches!(self, Self::Bool)
    }
    /// Canonical V1 spelling shared by leaf schemas and borrowed durable-state projections.
    pub const fn canonical_type_name(self) -> &'static str {
        match self {
            Self::Int => "int",
            Self::Decimal => "decimal",
            Self::Quantity => "quantity",
            Self::Bool => "bool",
            Self::String => "string",
            Self::Json => "Json",
            Self::Name => "Name",
            Self::AccountId => "AccountId",
            Self::AssetDefinitionId => "AssetDefinitionId",
            Self::AssetId => "AssetId",
            Self::DomainId => "DomainId",
            Self::NftId => "NftId",
            Self::DataSpaceId => "DataSpaceId",
            Self::Blob => "bytes",
        }
    }

    /// Whether this scalar kind is a canonical V1 durable cursor key.
    ///
    /// JSON is not a stable scalar key. This is the same rule used by recursive schema validation.
    #[must_use]
    pub const fn is_state_cursor_key(self) -> bool {
        !matches!(self, Self::Json)
    }
}
/// Named product metadata carried by a [`EntrypointValueTypeNodeV1::Struct`] node.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveFast,
    DeriveJsonSer,
    DeriveJsonDe,
)]
#[norito(no_fast_from_json)]
#[norito(deny_unknown_fields)]
pub struct EntrypointStructTypeNodeV1 {
    /// Exact qualified source identity, including its declaring contract or module owner.
    pub name: String,
    /// Ordered source field names. Child nodes immediately follow.
    pub fields: Vec<String>,
}
/// Metadata carried by an [`EntrypointValueTypeNodeV1::List`] node.
///
/// The exact element subtree immediately follows this node in the enclosing preorder tape. Keeping
/// every aggregate in one flat tape makes decoding, validation, cloning, comparison, and
/// destruction bounded by the explicit V1 node budget rather than the native call stack.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveFast,
    DeriveJsonSer,
    DeriveJsonDe,
)]
#[norito(no_fast_from_json)]
#[norito(deny_unknown_fields)]
pub struct EntrypointListTypeNodeV1 {
    /// Compile-time capacity in the inclusive range 1 through 64.
    pub capacity: u8,
}
/// One preorder node in an exact public boundary type.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveFast,
    DeriveJsonSer,
    DeriveJsonDe,
)]
#[norito(no_fast_from_json)]
#[norito(tag = "kind", content = "value", deny_unknown_fields)]
pub enum EntrypointValueTypeNodeV1 {
    /// Named product represented by an exact JSON object.
    Struct(EntrypointStructTypeNodeV1),
    /// Positional product represented by an exact JSON array.
    Tuple(
        /// Number of child nodes which immediately follow.
        u16,
    ),
    /// Tagged optional payload represented by one active-only compiler-owned sum handle.
    Option,
    /// Tagged result payload represented by one active-only compiler-owned sum handle.
    Result,
    /// Bounded contiguous list represented by one schema-bound sequence pointer.
    List(EntrypointListTypeNodeV1),
    /// Scalar or pointer leaf consuming one ABI word.
    Leaf(EntrypointValueKindV1),
    /// Unit value, carried by exactly one canonical zero scalar word.
    Unit,
    /// Nominal finite error value, carried by its validated enum-local code.
    Error(super::manifest::ContractErrorTypeDescriptor),
    /// Opaque canonical cursor for one exact scalar or tuple map-key schema.
    StateCursor(EntrypointValueTypeV1),
    /// Ordinary nominal enum carried by its validated enum-local code.
    Enum(super::manifest::ContractEnumTypeDescriptorV1),
}
/// Flat, compiler-emitted recursive value type schema.
#[repr(transparent)]
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, IntoSchema, crate :: DeriveJsonSerialize,
)]
#[norito(no_fast_from_json)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1")]
pub struct EntrypointValueTypeV1 {
    /// Preorder aggregate layout.
    pub nodes: Vec<EntrypointValueTypeNodeV1>,
}
/// Decode-only wire twin retaining the derive-generated V1 layout while the
/// public type validates the decoded schema before returning it.
#[repr(transparent)]
#[derive(Decode, IntoSchema, crate :: DeriveJsonDeserialize)]
#[norito(no_fast_from_json)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::smart_contract::entrypoint::DecodedEntrypointValueTypeV1"
)]
struct DecodedEntrypointValueTypeV1 {
    nodes: Vec<EntrypointValueTypeNodeV1>,
}

impl<'de> DeserializePayload<'de> for EntrypointValueTypeV1 {
    fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived)
            .unwrap_or_else(|error| panic!("invalid V1 entrypoint value schema: {error}"))
    }
    fn try_deserialize(archived: &'de norito::core::Archived<Self>) -> Result<Self, norito::Error> {
        // Both transparent types wrap the exact same `nodes` field, so their
        // archived layouts are identical. The private twin exists solely to
        // reuse the derive-generated wire decoder.
        let decoded =
            <DecodedEntrypointValueTypeV1 as DeserializePayload>::try_deserialize(archived.cast())?;
        let value = Self {
            nodes: decoded.nodes,
        };
        if !value.validate() {
            return Err(norito::Error::Message(
                "invalid V1 entrypoint value schema".to_owned(),
            ));
        }
        Ok(value)
    }
}

impl norito::json::JsonDeserialize for EntrypointValueTypeV1 {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let decoded =
            <DecodedEntrypointValueTypeV1 as norito::json::JsonDeserialize>::json_deserialize(
                parser,
            )?;
        Self::from_decoded_json(decoded)
    }
    fn json_from_value(value: &norito::json::Value) -> Result<Self, norito::json::Error> {
        let decoded =
            <DecodedEntrypointValueTypeV1 as norito::json::JsonDeserialize>::json_from_value(
                value,
            )?;
        Self::from_decoded_json(decoded)
    }
}

impl<'a> norito::json::FastFromJson<'a> for EntrypointValueTypeV1 {
    fn parse(
        walker: &mut norito::json::TapeWalker<'a>,
        _arena: &mut norito::json::Arena,
    ) -> Result<Self, norito::Error> {
        walker.ensure_document_depth()?;
        let input = walker.input();
        let mut parser = norito::json::Parser::new_at(input, walker.raw_pos());
        let value = <Self as norito::json::JsonDeserialize>::json_deserialize(&mut parser)
            .map_err(norito::Error::from)?;
        walker.sync_to_raw(parser.position());
        Ok(value)
    }
}
// These nominal names are compiler-reserved. Matching their complete subtree
// here keeps artifact admission from trusting a forged name with different
// fields or pointer kinds.
mod state_key;
/// Shared allocation-free flat-tree and reserved nominal shape validation.
pub mod type_structure;
pub use state_key::{
    STATE_KEY_SCHEMA_HASH_DOMAIN_V1, state_key_schema_depth_v1, state_key_schema_hash_v1,
    validate_state_key_schema_v1, visit_state_key_type_v1,
};
use type_structure::{is_core_query_view_name, validate_reserved_nominal_shapes_v1};

fn entrypoint_node_child_count(node: &EntrypointValueTypeNodeV1) -> usize {
    match node {
        EntrypointValueTypeNodeV1::Struct(node) => node.fields.len(),
        EntrypointValueTypeNodeV1::Tuple(arity) => usize::from(*arity),
        EntrypointValueTypeNodeV1::Option | EntrypointValueTypeNodeV1::List(_) => 1,
        EntrypointValueTypeNodeV1::Result => 2,
        EntrypointValueTypeNodeV1::Leaf(_)
        | EntrypointValueTypeNodeV1::Unit
        | EntrypointValueTypeNodeV1::StateCursor(_)
        | EntrypointValueTypeNodeV1::Error(_)
        | EntrypointValueTypeNodeV1::Enum(_) => 0,
    }
}
/// Return the exact preorder range occupied by one structurally complete boundary-type subtree.
///
/// This cursor helper deliberately checks only flat-tree structure. Callers accepting an entire
/// untrusted schema must still use [`EntrypointValueTypeV1::validate`] to enforce identifiers,
/// capacities, reserved nominal shapes, and the V1 node/depth budgets.
#[must_use]
pub fn entrypoint_value_subtree_range_v1(
    nodes: &[EntrypointValueTypeNodeV1],
    start: usize,
) -> Option<std::ops::Range<usize>> {
    type_structure::subtree_range_v1(nodes, start)
}

fn entrypoint_subtree_end(nodes: &[EntrypointValueTypeNodeV1], start: usize) -> Option<usize> {
    entrypoint_value_subtree_range_v1(nodes, start).map(|range| range.end)
}
struct RenderedEntrypointType {
    text: String,
    core_view: Option<String>,
    list_element_core_view: Option<String>,
}
fn take_rendered_entrypoint_children(
    rendered: &mut Vec<RenderedEntrypointType>,
    count: usize,
) -> Option<Vec<RenderedEntrypointType>> {
    if rendered.len() < count {
        return None;
    }
    let split = rendered.len() - count;
    let mut children = rendered.split_off(split);
    children.reverse();
    Some(children)
}
impl EntrypointValueTypeV1 {
    fn from_decoded_json(
        decoded: DecodedEntrypointValueTypeV1,
    ) -> Result<Self, norito::json::Error> {
        let value = Self {
            nodes: decoded.nodes,
        };
        if !value.validate() {
            return Err(norito::json::Error::Message(
                "invalid V1 entrypoint value schema".to_owned(),
            ));
        }
        Ok(value)
    }
    fn analyze(&self) -> Option<EntrypointTypeAnalysisV1> {
        #[derive(Clone, Copy)]
        struct Frame {
            remaining: usize,
            suppress_words: bool,
        }
        if self.nodes.is_empty() || self.nodes.len() > MAX_ENTRYPOINT_ARGUMENT_TYPE_NODES {
            return None;
        }
        let mut stack = [Frame {
            remaining: 0,
            suppress_words: false,
        }; MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH];
        let mut stack_len = 0_usize;
        let mut max_words = 0_usize;
        let mut total_nodes = self.nodes.len();
        for (index, node) in self.nodes.iter().enumerate() {
            while stack_len != 0 && stack[stack_len - 1].remaining == 0 {
                stack_len -= 1;
            }
            let suppress_words = if index == 0 {
                false
            } else {
                let parent = stack.get_mut(stack_len.checked_sub(1)?)?;
                parent.remaining = parent.remaining.checked_sub(1)?;
                parent.suppress_words
            };
            let depth = stack_len.checked_add(1)?;
            if depth > MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH {
                return None;
            }
            match node {
                EntrypointValueTypeNodeV1::StateCursor(key) => {
                    let key_depth = state_key_schema_depth_v1(key)?;
                    total_nodes = total_nodes.checked_add(key.nodes.len())?;
                    if total_nodes > MAX_ENTRYPOINT_ARGUMENT_TYPE_NODES
                        || depth.checked_add(key_depth)? > MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH
                    {
                        return None;
                    }
                }
                EntrypointValueTypeNodeV1::Error(error) if !error.validate() => return None,
                EntrypointValueTypeNodeV1::Enum(descriptor) if !descriptor.validate() => {
                    return None;
                }
                EntrypointValueTypeNodeV1::Struct(node) => {
                    if !is_canonical_kotodama_struct_name(&node.name)
                        || node
                            .fields
                            .iter()
                            .any(|field| !is_canonical_kotodama_identifier(field))
                        || node.fields.len() > MAX_ENTRYPOINT_ARGUMENT_TYPE_NODES
                    {
                        return None;
                    }
                    let mut names = [""; MAX_ENTRYPOINT_ARGUMENT_TYPE_NODES];
                    for (index, field) in node.fields.iter().enumerate() {
                        names[index] = field.as_str();
                    }
                    let names = &mut names[..node.fields.len()];
                    names.sort_unstable();
                    if names.windows(2).any(|pair| pair[0] == pair[1]) {
                        return None;
                    }
                }
                EntrypointValueTypeNodeV1::Tuple(arity) if *arity < 2 => return None,
                EntrypointValueTypeNodeV1::List(list)
                    if !(MIN_ENTRYPOINT_LIST_CAPACITY_V1..=MAX_ENTRYPOINT_LIST_CAPACITY_V1)
                        .contains(&list.capacity) =>
                {
                    return None;
                }
                _ => {}
            }
            let is_handle = matches!(
                node,
                EntrypointValueTypeNodeV1::Option
                    | EntrypointValueTypeNodeV1::Result
                    | EntrypointValueTypeNodeV1::List(_)
            );
            if !suppress_words
                && (is_handle
                    || matches!(node, EntrypointValueTypeNodeV1::Struct(product) if product.fields.is_empty())
                    || matches!(
                        node,
                        EntrypointValueTypeNodeV1::Leaf(_)
                            | EntrypointValueTypeNodeV1::Unit
                            | EntrypointValueTypeNodeV1::StateCursor(_)
                            | EntrypointValueTypeNodeV1::Error(_)
                            | EntrypointValueTypeNodeV1::Enum(_)
                    ))
            {
                max_words = max_words.checked_add(1)?;
            }
            let children = entrypoint_node_child_count(node);
            if children != 0 {
                *stack.get_mut(stack_len)? = Frame {
                    remaining: children,
                    suppress_words: suppress_words || is_handle,
                };
                stack_len += 1;
            }
        }
        while stack_len != 0 && stack[stack_len - 1].remaining == 0 {
            stack_len -= 1;
        }
        if stack_len != 0 || !validate_reserved_nominal_shapes_v1(&self.nodes) {
            return None;
        }
        Some(EntrypointTypeAnalysisV1 { max_words })
    }
    /// Validate tree shape, identifiers, list capacities, and recursive limits.
    #[must_use]
    pub fn validate(&self) -> bool {
        self.analyze().is_some()
    }
    /// Borrow the exact flat node slice for the subtree beginning at `start`.
    ///
    /// The full enclosing schema is validated first, so a returned slice is
    /// guaranteed to be inside one admissible V1 preorder tape.
    #[must_use]
    pub fn subtree_nodes(&self, start: usize) -> Option<&[EntrypointValueTypeNodeV1]> {
        if !self.validate() {
            return None;
        }
        let range = entrypoint_value_subtree_range_v1(&self.nodes, start)?;
        self.nodes.get(range)
    }
    /// Return the fixed ABI words emitted for this type.
    ///
    /// Every `Option`, `Result`, and `List` consumes one compiler-owned handle
    /// word; products flatten their children in declaration order. Empty named
    /// products occupy one initialized zero word while keeping an empty atom tape.
    #[must_use]
    pub fn word_count(&self) -> Option<usize> {
        self.analyze().map(|analysis| analysis.max_words)
    }
    /// Return flattened ABI word roles in deterministic preorder.
    pub fn word_kinds(&self) -> Option<Vec<EntrypointValueWordKindV1>> {
        if !self.validate() {
            return None;
        }
        let mut node_index = 0;
        let words = max_entrypoint_word_kinds(&self.nodes, &mut node_index)?;
        (node_index == self.nodes.len()).then_some(words)
    }
    /// Validate one active-only flat atom tape against this exact type.
    #[must_use]
    pub fn validate_atoms(&self, atoms: &[EntrypointValueAtomV1]) -> bool {
        if !self.validate() {
            return false;
        }
        let mut node_index = 0;
        let mut atom_index = 0;
        walk_entrypoint_value_atoms(&self.nodes, atoms, &mut node_index, &mut atom_index, None)
            && node_index == self.nodes.len()
            && atom_index == atoms.len()
    }
    /// Return the actual flattened VM word roles selected by an active-only value.
    pub fn word_kinds_for_atoms(
        &self,
        atoms: &[EntrypointValueAtomV1],
    ) -> Option<Vec<EntrypointValueWordKindV1>> {
        if !self.validate() {
            return None;
        }
        let mut node_index = 0;
        let mut atom_index = 0;
        let mut kinds = Vec::new();
        if !walk_entrypoint_value_atoms(
            &self.nodes,
            atoms,
            &mut node_index,
            &mut atom_index,
            Some(&mut kinds),
        ) || node_index != self.nodes.len()
            || atom_index != atoms.len()
        {
            return None;
        }
        Some(kinds)
    }
    /// Render the canonical public Kotodama type name represented by this schema.
    pub fn canonical_type_name(&self) -> Option<String> {
        if !self.validate() {
            return None;
        }
        let mut rendered = Vec::<RenderedEntrypointType>::new();
        for node in self.nodes.iter().rev() {
            let value = match node {
                EntrypointValueTypeNodeV1::StateCursor(key) => RenderedEntrypointType {
                    text: format!("StateCursor<{}>", key.canonical_type_name()?),
                    core_view: None,
                    list_element_core_view: None,
                },
                EntrypointValueTypeNodeV1::Unit => RenderedEntrypointType {
                    text: "()".to_owned(),
                    core_view: None,
                    list_element_core_view: None,
                },
                EntrypointValueTypeNodeV1::Error(error) => RenderedEntrypointType {
                    text: error.identity.clone(),
                    core_view: None,
                    list_element_core_view: None,
                },
                EntrypointValueTypeNodeV1::Enum(descriptor) => RenderedEntrypointType {
                    text: descriptor.identity.clone(),
                    core_view: None,
                    list_element_core_view: None,
                },
                EntrypointValueTypeNodeV1::Struct(node) => {
                    let children =
                        take_rendered_entrypoint_children(&mut rendered, node.fields.len())?;
                    let (text, core_view) = if node.name == "kotodama::StatePage" {
                        let list = &children.first()?.text;
                        let body = list.strip_prefix("List<(")?;
                        let (types, capacity) = body.rsplit_once("), ")?;
                        (
                            format!("StatePage<{types}, {}>", capacity.strip_suffix('>')?),
                            None,
                        )
                    } else if node.name == "kotodama::QueryPage" {
                        let view_name = children.first()?.list_element_core_view.clone()?;
                        (format!("QueryPage<{view_name}>"), None)
                    } else if is_core_query_view_name(&node.name) {
                        let name = node.name.strip_prefix("kotodama::")?.to_owned();
                        (name.clone(), Some(name))
                    } else {
                        (format!("struct {}", node.name), None)
                    };
                    RenderedEntrypointType {
                        text,
                        core_view,
                        list_element_core_view: None,
                    }
                }
                EntrypointValueTypeNodeV1::Tuple(arity) => {
                    let children =
                        take_rendered_entrypoint_children(&mut rendered, usize::from(*arity))?;
                    RenderedEntrypointType {
                        text: format!(
                            "({})",
                            children
                                .iter()
                                .map(|child| child.text.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                        core_view: None,
                        list_element_core_view: None,
                    }
                }
                EntrypointValueTypeNodeV1::Option => {
                    let child = take_rendered_entrypoint_children(&mut rendered, 1)?.pop()?;
                    RenderedEntrypointType {
                        text: format!("Option<{}>", child.text),
                        core_view: None,
                        list_element_core_view: None,
                    }
                }
                EntrypointValueTypeNodeV1::Result => {
                    let mut children =
                        take_rendered_entrypoint_children(&mut rendered, 2)?.into_iter();
                    let ok = children.next()?;
                    let err = children.next()?;
                    RenderedEntrypointType {
                        text: format!("Result<{}, {}>", ok.text, err.text),
                        core_view: None,
                        list_element_core_view: None,
                    }
                }
                EntrypointValueTypeNodeV1::List(list) => {
                    let child = take_rendered_entrypoint_children(&mut rendered, 1)?.pop()?;
                    RenderedEntrypointType {
                        text: format!("List<{}, {}>", child.text, list.capacity),
                        core_view: None,
                        list_element_core_view: child.core_view,
                    }
                }
                EntrypointValueTypeNodeV1::Leaf(kind) => RenderedEntrypointType {
                    text: kind.canonical_type_name().to_owned(),
                    core_view: None,
                    list_element_core_view: None,
                },
            };
            rendered.push(value);
        }
        (rendered.len() == 1).then(|| rendered.pop().expect("length checked").text)
    }
}
#[derive(Clone, Copy)]
struct EntrypointTypeAnalysisV1 {
    max_words: usize,
}
/// Flattened word role derived from a validated boundary schema.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::smart_contract::entrypoint::EntrypointValueWordKindV1")]
#[expect(
    variant_size_differences,
    reason = "A cursor's fixed schema digest keeps word descriptors Copy and allocation-free"
)]
pub enum EntrypointValueWordKindV1 {
    /// One active-only compiler-owned Option/Result handle.
    Sum,
    /// One schema-bound canonical list-sequence pointer.
    List,
    /// Scalar or pointer leaf.
    Leaf(EntrypointValueKindV1),
    /// Canonical zero scalar for a unit value.
    Unit,
    /// Validated enum-local u32 code for a nominal error type.
    Error,
    /// Canonical cursor-frame pointer bound to its complete key-schema hash.
    StateCursor([u8; 32]),
    /// Validated enum-local u32 code for an ordinary nominal enum.
    Enum,
}
/// Canonical wire atom in a public entrypoint value record.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    norito::NoritoSchema,
    DeriveFast,
    DeriveJsonSer,
    DeriveJsonDe,
)]
#[norito_schema(name = "iroha_data_model::smart_contract::entrypoint::EntrypointValueAtomV1")]
#[norito(
    no_fast_from_json,
    tag = "kind",
    content = "value",
    deny_unknown_fields
)]
pub enum EntrypointValueAtomV1 {
    /// Option/Result tag.
    Tag(bool),
    /// Boolean scalar.
    Bool(bool),
    /// Complete pointer-ABI TLV envelope for a typed leaf.
    Pointer(Vec<u8>),
    /// Canonical bounded sequence marker carrying the number of following items.
    ///
    /// The items immediately follow this marker in the enclosing record's one
    /// preorder atom tape. Each item is delimited by the list element schema,
    /// so no recursive atom ownership or end marker is needed.
    List(
        /// Number of schema-delimited item streams which immediately follow.
        u8,
    ),
    /// Unique unit value, with no variable payload.
    Unit,
    /// Enum-local code validated against the exact nominal error schema.
    ErrorCode(u32),
    /// Enum-local code validated against the exact ordinary enum schema.
    EnumCode(u32),
}
/// Schema-bound canonical Norito payload supplied to a public entrypoint wrapper.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::smart_contract::entrypoint::EntrypointArgumentRecordV1")]
pub struct EntrypointArgumentRecordV1 {
    /// Domain-separated hash of the exact encoded schema.
    pub schema_hash: [u8; 32],
    /// Flattened atoms in declaration and schema preorder.
    pub atoms: Vec<EntrypointValueAtomV1>,
}
/// Schema-bound canonical Norito payload returned by a nested contract call.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    norito::NoritoSchema,
    DeriveFast,
    DeriveJsonSer,
    DeriveJsonDe,
)]
#[norito_schema(name = "iroha_data_model::smart_contract::entrypoint::EntrypointReturnRecordV1")]
#[norito(no_fast_from_json, deny_unknown_fields)]
pub struct EntrypointReturnRecordV1 {
    /// Domain-separated hash of the exact encoded return value schema.
    pub schema_hash: [u8; 32],
    /// Flattened canonical atoms in schema preorder.
    pub atoms: Vec<EntrypointValueAtomV1>,
}
/// One named field in a public entrypoint argument record.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveFast,
    DeriveJsonSer,
    DeriveJsonDe,
)]
#[norito(no_fast_from_json)]
#[norito(deny_unknown_fields)]
pub struct EntrypointArgumentFieldV1 {
    /// Source-level parameter name used as the boundary object key.
    pub name: String,
    /// Canonical representation expected by the compiled implementation.
    pub ty: EntrypointValueTypeV1,
}
/// Compiler-emitted schema for one public entrypoint invocation.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveFast,
    DeriveJsonSer,
    DeriveJsonDe,
)]
#[norito(no_fast_from_json)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::smart_contract::entrypoint::EntrypointArgumentSchemaV1")]
pub struct EntrypointArgumentSchemaV1 {
    /// Fields in source declaration and ABI argument-table order.
    pub fields: Vec<EntrypointArgumentFieldV1>,
}
impl EntrypointArgumentSchemaV1 {
    /// Validate source-field uniqueness and the argument ABI bounds.
    #[must_use]
    pub fn validate(&self) -> bool {
        if self.fields.is_empty() || self.fields.len() > MAX_ENTRYPOINT_ARGUMENTS {
            return false;
        }
        // Sort compact indices into the borrowed names: the full ABI bound needs
        // 16 KiB instead of 128 KiB of string references on a 64-bit host. This
        // keeps validation allocation-free and leaves declaration order intact.
        let mut indices = [0_u16; MAX_ENTRYPOINT_ARGUMENTS];
        for (index, field) in self.fields.iter().enumerate() {
            if !is_canonical_kotodama_identifier(&field.name) || !field.ty.validate() {
                return false;
            }
            let Ok(compact_index) = u16::try_from(index) else {
                return false;
            };
            indices[index] = compact_index;
        }
        let indices = &mut indices[..self.fields.len()];
        indices.sort_unstable_by(|left, right| {
            self.fields[usize::from(*left)]
                .name
                .cmp(&self.fields[usize::from(*right)].name)
        });
        !indices.windows(2).any(|pair| {
            self.fields[usize::from(pair[0])].name == self.fields[usize::from(pair[1])].name
        }) && self.word_count_unchecked() <= MAX_ENTRYPOINT_ARGUMENT_WORDS
    }
    /// Return the total fixed-width table word count for this schema.
    #[must_use]
    pub fn word_count(&self) -> Option<usize> {
        if !self.validate() {
            return None;
        }
        Some(self.word_count_unchecked())
    }
    fn word_count_unchecked(&self) -> usize {
        self.fields
            .iter()
            .map(|field| field.ty.word_count().unwrap_or(usize::MAX))
            .fold(0_usize, usize::saturating_add)
    }
    /// Return flattened ABI word roles across fields in declaration order.
    pub fn word_kinds(&self) -> Option<Vec<EntrypointValueWordKindV1>> {
        if !self.validate() {
            return None;
        }
        let mut words = Vec::with_capacity(self.word_count_unchecked());
        for field in &self.fields {
            words.extend(field.ty.word_kinds()?);
        }
        Some(words)
    }
    /// Validate active-only atom variants for every declared field.
    #[must_use]
    pub fn validate_atoms(&self, atoms: &[EntrypointValueAtomV1]) -> bool {
        if !self.validate() {
            return false;
        }
        let mut atom_index = 0;
        for field in &self.fields {
            let mut node_index = 0;
            if !walk_entrypoint_value_atoms(
                &field.ty.nodes,
                atoms,
                &mut node_index,
                &mut atom_index,
                None,
            ) || node_index != field.ty.nodes.len()
            {
                return false;
            }
        }
        atom_index == atoms.len()
    }
    /// Return actual flattened VM word roles selected by this argument record.
    pub fn word_kinds_for_atoms(
        &self,
        atoms: &[EntrypointValueAtomV1],
    ) -> Option<Vec<EntrypointValueWordKindV1>> {
        if !self.validate() {
            return None;
        }
        let mut atom_index = 0;
        let mut kinds = Vec::new();
        for field in &self.fields {
            let mut node_index = 0;
            if !walk_entrypoint_value_atoms(
                &field.ty.nodes,
                atoms,
                &mut node_index,
                &mut atom_index,
                Some(&mut kinds),
            ) || node_index != field.ty.nodes.len()
            {
                return None;
            }
        }
        (atom_index == atoms.len() && kinds.len() <= MAX_ENTRYPOINT_ARGUMENT_WORDS).then_some(kinds)
    }
}
fn max_entrypoint_word_kinds(
    nodes: &[EntrypointValueTypeNodeV1],
    node_index: &mut usize,
) -> Option<Vec<EntrypointValueWordKindV1>> {
    let start = *node_index;
    let end = entrypoint_subtree_end(nodes, start)?;
    let mut rendered = Vec::<Vec<EntrypointValueWordKindV1>>::new();
    for node in nodes[start..end].iter().rev() {
        let child_count = entrypoint_node_child_count(node);
        if rendered.len() < child_count {
            return None;
        }
        let split = rendered.len() - child_count;
        let mut children = rendered.split_off(split);
        children.reverse();
        let words = match node {
            EntrypointValueTypeNodeV1::StateCursor(key) => {
                vec![EntrypointValueWordKindV1::StateCursor(
                    state_key_schema_hash_v1(key)?,
                )]
            }
            EntrypointValueTypeNodeV1::Unit => vec![EntrypointValueWordKindV1::Unit],
            EntrypointValueTypeNodeV1::Error(_) => vec![EntrypointValueWordKindV1::Error],
            EntrypointValueTypeNodeV1::Enum(_) => vec![EntrypointValueWordKindV1::Enum],
            EntrypointValueTypeNodeV1::Struct(product) if product.fields.is_empty() => {
                vec![EntrypointValueWordKindV1::Unit]
            }
            EntrypointValueTypeNodeV1::Struct(_) | EntrypointValueTypeNodeV1::Tuple(_) => {
                children.into_iter().flatten().collect()
            }
            EntrypointValueTypeNodeV1::Option | EntrypointValueTypeNodeV1::Result => {
                vec![EntrypointValueWordKindV1::Sum]
            }
            EntrypointValueTypeNodeV1::List(_) => {
                vec![EntrypointValueWordKindV1::List]
            }
            EntrypointValueTypeNodeV1::Leaf(kind) => {
                vec![EntrypointValueWordKindV1::Leaf(*kind)]
            }
        };
        rendered.push(words);
    }
    *node_index = end;
    (rendered.len() == 1).then(|| rendered.pop().expect("length checked"))
}
// Terminal atoms consume exactly one word; aggregate scheduling stays in the iterative walker.
fn entrypoint_atom_word_kind(
    node: &EntrypointValueTypeNodeV1,
    atom: &EntrypointValueAtomV1,
) -> Option<EntrypointValueWordKindV1> {
    use EntrypointValueAtomV1 as Atom;
    use EntrypointValueTypeNodeV1 as Node;
    use EntrypointValueWordKindV1 as Word;
    match (node, atom) {
        (Node::StateCursor(key), Atom::Pointer(_)) => {
            Some(Word::StateCursor(state_key_schema_hash_v1(key)?))
        }
        (Node::Unit, Atom::Unit) => Some(Word::Unit),
        (Node::Error(error), Atom::ErrorCode(code)) if error.variant(*code).is_some() => {
            Some(Word::Error)
        }
        (Node::Enum(descriptor), Atom::EnumCode(code)) if descriptor.variant(*code).is_some() => {
            Some(Word::Enum)
        }
        (Node::Leaf(EntrypointValueKindV1::Bool), Atom::Bool(_)) => {
            Some(Word::Leaf(EntrypointValueKindV1::Bool))
        }
        (Node::Leaf(kind), Atom::Pointer(_)) if kind.is_pointer() => Some(Word::Leaf(*kind)),
        _ => None,
    }
}
fn walk_entrypoint_value_atoms(
    nodes: &[EntrypointValueTypeNodeV1],
    atoms: &[EntrypointValueAtomV1],
    node_index: &mut usize,
    atom_index: &mut usize,
    mut kinds: Option<&mut Vec<EntrypointValueWordKindV1>>,
) -> bool {
    let start = *node_index;
    let Some(end) = entrypoint_subtree_end(nodes, start) else {
        return false;
    };
    // `(node start, emit one top-level ABI word)` actions are deliberately
    // iterative. Repeated list elements reuse the same schema subtree while
    // advancing one shared atom cursor, so neither schema nor value nesting
    // consumes the native call stack.
    let mut actions = vec![(start, true)];
    let mut cursor = *atom_index;
    while let Some((node_start, emit_kind)) = actions.pop() {
        let Some(node) = nodes.get(node_start) else {
            return false;
        };
        match node {
            EntrypointValueTypeNodeV1::StateCursor(_)
            | EntrypointValueTypeNodeV1::Unit
            | EntrypointValueTypeNodeV1::Error(_)
            | EntrypointValueTypeNodeV1::Enum(_)
            | EntrypointValueTypeNodeV1::Leaf(_) => {
                let Some(word_kind) = atoms
                    .get(cursor)
                    .and_then(|atom| entrypoint_atom_word_kind(node, atom))
                else {
                    return false;
                };
                cursor += 1;
                if emit_kind && let Some(kinds) = kinds.as_deref_mut() {
                    kinds.push(word_kind);
                }
            }
            EntrypointValueTypeNodeV1::Struct(node) => {
                if node.fields.is_empty()
                    && emit_kind
                    && let Some(kinds) = kinds.as_deref_mut()
                {
                    kinds.push(EntrypointValueWordKindV1::Unit);
                }
                let mut child = node_start + 1;
                let mut starts = Vec::with_capacity(node.fields.len());
                for _ in &node.fields {
                    starts.push(child);
                    let Some(next) = entrypoint_subtree_end(nodes, child) else {
                        return false;
                    };
                    child = next;
                }
                actions.extend(starts.into_iter().rev().map(|start| (start, emit_kind)));
            }
            EntrypointValueTypeNodeV1::Tuple(arity) => {
                let mut child = node_start + 1;
                let mut starts = Vec::with_capacity(usize::from(*arity));
                for _ in 0..*arity {
                    starts.push(child);
                    let Some(next) = entrypoint_subtree_end(nodes, child) else {
                        return false;
                    };
                    child = next;
                }
                actions.extend(starts.into_iter().rev().map(|start| (start, emit_kind)));
            }
            EntrypointValueTypeNodeV1::Option => {
                let Some(EntrypointValueAtomV1::Tag(active)) = atoms.get(cursor) else {
                    return false;
                };
                cursor += 1;
                if emit_kind && let Some(kinds) = kinds.as_deref_mut() {
                    kinds.push(EntrypointValueWordKindV1::Sum);
                }
                if *active {
                    actions.push((node_start + 1, false));
                }
            }
            EntrypointValueTypeNodeV1::Result => {
                let Some(EntrypointValueAtomV1::Tag(ok_active)) = atoms.get(cursor) else {
                    return false;
                };
                cursor += 1;
                if emit_kind && let Some(kinds) = kinds.as_deref_mut() {
                    kinds.push(EntrypointValueWordKindV1::Sum);
                }
                let ok_start = node_start + 1;
                let Some(err_start) = entrypoint_subtree_end(nodes, ok_start) else {
                    return false;
                };
                actions.push((if *ok_active { ok_start } else { err_start }, false));
            }
            EntrypointValueTypeNodeV1::List(list) => {
                let Some(EntrypointValueAtomV1::List(item_count)) = atoms.get(cursor) else {
                    return false;
                };
                cursor += 1;
                if *item_count > list.capacity {
                    return false;
                }
                if emit_kind && let Some(kinds) = kinds.as_deref_mut() {
                    kinds.push(EntrypointValueWordKindV1::List);
                }
                let element_start = node_start + 1;
                actions.extend(std::iter::repeat_n(
                    (element_start, false),
                    usize::from(*item_count),
                ));
            }
        }
    }
    *node_index = end;
    *atom_index = cursor;
    true
}
/// Return whether a locked package identity has the canonical V1 path/revision grammar.
///
/// Components are ASCII letters, digits or `_`, followed by those characters, `.` or `-`.
/// Paths use `/`; an optional single `@revision` is literal and is never version-normalized.
#[must_use]
pub fn is_canonical_kotodama_package_identity(value: &str) -> bool {
    fn component(value: &str) -> bool {
        let mut bytes = value.bytes();
        bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            && bytes.all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
    }
    if value.is_empty() || value.len() > 1024 || value.contains("__kotodama_link_") {
        return false;
    }
    let mut parts = value.split('@');
    let path = parts.next().unwrap_or_default();
    path.split('/').all(component) && parts.next().is_none_or(component) && parts.next().is_none()
}
/// Validate a contract-qualified, locked-package, or root-local module struct identity.
///
/// Package identities retain their locked spelling. Unit and type names use the same
/// declaration vocabulary as source; qualified compiler-owned names are never aliases.
/// Root-local modules use `local::<64 lowercase hex owner digest>::Unit::Struct`.
#[must_use]
pub fn is_canonical_kotodama_struct_name(value: &str) -> bool {
    fn declaration(value: &str) -> bool {
        is_canonical_kotodama_identifier(value)
            && !value.starts_with("__kotodama_link_")
            && !KOTODAMA_V1_RESERVED_TYPE_DECLARATIONS.contains(&value)
    }
    if value.len() > 1024 {
        return false;
    }
    if is_core_query_view_name(value)
        || matches!(value, "kotodama::QueryPage" | "kotodama::StatePage")
    {
        return true;
    }
    if !value.contains("::") {
        return false;
    }
    if value.contains("__kotodama_link_") {
        return false;
    }
    let mut parts = value.split("::");
    match (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) {
        (Some(unit), Some(name), None, None, None) => {
            unit != "kotodama" && declaration(unit) && declaration(name)
        }
        (Some("local"), Some(digest), Some(unit), Some(name), None) => {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                && declaration(unit)
                && declaration(name)
        }
        (Some(package), Some(unit), Some(name), None, None) => {
            is_canonical_kotodama_package_identity(package)
                && declaration(unit)
                && declaration(name)
        }
        _ => false,
    }
}
/// Return whether `value` is an ASCII Kotodama identifier that does not collide
/// with a canonical V1 keyword or first-release forbidden source identifier.
///
/// Manifest and SDK boundary-schema validators use this predicate so schema
/// field names cannot reinterpret a language keyword as an ordinary binding.
#[must_use]
pub fn is_canonical_kotodama_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && !KOTODAMA_V1_FORBIDDEN_SOURCE_IDENTIFIERS.contains(&value)
        && !matches!(
            value,
            "as" | "authorize"
                | "break"
                | "const"
                | "continue"
                | "decimal"
                | "else"
                | "enum"
                | "emit"
                | "event"
                | "error"
                | "export"
                | "false"
                | "fn"
                | "for"
                | "hajimari"
                | "if"
                | "import"
                | "include"
                | "in"
                | "int"
                | "kaizen"
                | "kotoage"
                | "let"
                | "match"
                | "module"
                | "permission"
                | "quantity"
                | "return"
                | "seiyaku"
                | "state"
                | "struct"
                | "trigger"
                | "true"
                | "var"
                | "view"
        )
}
#[cfg(test)]
mod tests {
    #[test]
    fn exported_struct_names_use_shared_locked_identity_vectors() {
        use super::*;
        let vectors: norito::json::Value = norito::json::from_str(include_str!(
            "../../../../fixtures/kotodama/exported_struct_names_v1.json"
        ))
        .unwrap();
        for (group, expected) in [("valid", true), ("invalid", false)] {
            for value in vectors[group].as_array().unwrap() {
                let name = value.as_str().unwrap();
                assert_eq!(is_canonical_kotodama_struct_name(name), expected, "{name}");
                let schema = EntrypointValueTypeV1 {
                    nodes: vec![
                        EntrypointValueTypeNodeV1::Struct(EntrypointStructTypeNodeV1 {
                            name: name.to_owned(),
                            fields: vec!["amount".to_owned()],
                        }),
                        EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
                    ],
                };
                assert_eq!(schema.validate(), expected, "{name}");
                if expected {
                    let frame = norito::to_bytes(&schema).unwrap();
                    assert_eq!(
                        norito::decode_from_bytes::<EntrypointValueTypeV1>(&frame).unwrap(),
                        schema
                    );
                }
            }
        }
        for package in ["std/math@1.0.0", "local", "org/sub_pkg@rev-1"] {
            assert!(is_canonical_kotodama_package_identity(package));
        }
        for package in ["", "a::b", "a//b", "a@", "a@@1", "../a"] {
            assert!(!is_canonical_kotodama_package_identity(package));
        }
    }

    #[test]
    fn struct_nominality_requires_an_owner_and_reserves_builtin_identities() {
        use super::*;
        for name in [
            "Receipt",
            "AccountView",
            "kotodama::Receipt",
            "Main::AccountView",
        ] {
            assert!(!is_canonical_kotodama_struct_name(name), "{name}");
        }
        for name in [
            "Payments::Receipt",
            "Other::Receipt",
            "kotodama::AccountView",
        ] {
            assert!(is_canonical_kotodama_struct_name(name), "{name}");
        }
        let make = |name: &str| EntrypointValueTypeV1 {
            nodes: vec![EntrypointValueTypeNodeV1::Struct(
                EntrypointStructTypeNodeV1 {
                    name: name.to_owned(),
                    fields: vec![],
                },
            )],
        };
        let left = make("Payments::Receipt");
        let right = make("Other::Receipt");
        assert!(left.validate() && right.validate());
        assert_ne!(
            entrypoint_return_schema_hash_v1(&norito::encode_canonical(&left).unwrap()),
            entrypoint_return_schema_hash_v1(&norito::encode_canonical(&right).unwrap()),
        );
        assert!(
            !make("kotodama::AccountView").validate(),
            "reserved identities keep their complete shape"
        );
    }
    #[test]
    fn nominal_errors_and_unit_roundtrip_with_exact_sum_validation() {
        use super::*;
        use crate::smart_contract::manifest::{
            ContractErrorTypeDescriptor, ContractErrorVariantDescriptor,
        };
        let error = ContractErrorTypeDescriptor {
            identity: "example/vault@1::Vault::VaultError".to_owned(),
            variants: vec![ContractErrorVariantDescriptor {
                name: "InvalidQuantity".to_owned(),
                code: 1,
            }],
        };
        let schema = EntrypointValueTypeV1 {
            nodes: vec![
                EntrypointValueTypeNodeV1::Result,
                EntrypointValueTypeNodeV1::Unit,
                EntrypointValueTypeNodeV1::Error(error.clone()),
            ],
        };
        assert!(schema.validate());
        assert_eq!(schema.word_count(), Some(1));
        assert!(schema.validate_atoms(&[
            EntrypointValueAtomV1::Tag(true),
            EntrypointValueAtomV1::Unit
        ]));
        assert!(schema.validate_atoms(&[
            EntrypointValueAtomV1::Tag(false),
            EntrypointValueAtomV1::ErrorCode(1)
        ]));
        assert!(!schema.validate_atoms(&[
            EntrypointValueAtomV1::Tag(false),
            EntrypointValueAtomV1::ErrorCode(2)
        ]));
        assert!(!schema.validate_atoms(&[
            EntrypointValueAtomV1::Tag(true),
            EntrypointValueAtomV1::Bool(false)
        ]));
        let encoded = norito::to_bytes(&schema).expect("encode nominal schema");
        assert_eq!(
            norito::decode_from_bytes::<EntrypointValueTypeV1>(&encoded)
                .expect("decode nominal schema"),
            schema
        );
        let mut other = error.clone();
        other.identity = "example/other@1::Other::VaultError".to_owned();
        assert_eq!(error.schema_hash(), other.schema_hash());
        assert_ne!(error.identity, other.identity);
        other.variants.push(other.variants[0].clone());
        assert!(!other.validate());
    }
    use super::*;
    #[test]
    fn ordinary_enum_schema_preserves_nominality_and_nested_active_atoms() {
        use crate::smart_contract::manifest::{
            ContractEnumTypeDescriptorV1, ContractEnumVariantDescriptorV1,
        };
        let descriptor = ContractEnumTypeDescriptorV1 {
            identity: "example/vault@1::Vault::Phase".into(),
            variants: vec![ContractEnumVariantDescriptorV1 {
                name: "Open".into(),
                code: 7,
            }],
        };
        let enum_type = EntrypointValueTypeV1 {
            nodes: vec![EntrypointValueTypeNodeV1::Enum(descriptor.clone())],
        };
        assert_eq!(enum_type.word_count(), Some(1));
        assert_eq!(
            enum_type.word_kinds(),
            Some(vec![EntrypointValueWordKindV1::Enum])
        );
        assert_eq!(
            enum_type.canonical_type_name(),
            Some(descriptor.identity.clone())
        );
        assert!(enum_type.validate_atoms(&[EntrypointValueAtomV1::EnumCode(7)]));
        for atom in [
            EntrypointValueAtomV1::EnumCode(0),
            EntrypointValueAtomV1::EnumCode(1),
            EntrypointValueAtomV1::ErrorCode(7),
        ] {
            assert!(!enum_type.validate_atoms(&[atom]));
        }
        let nested = EntrypointValueTypeV1 {
            nodes: vec![
                EntrypointValueTypeNodeV1::Option,
                EntrypointValueTypeNodeV1::List(EntrypointListTypeNodeV1 { capacity: 2 }),
                EntrypointValueTypeNodeV1::Enum(descriptor.clone()),
            ],
        };
        let atoms = vec![
            EntrypointValueAtomV1::Tag(true),
            EntrypointValueAtomV1::List(2),
            EntrypointValueAtomV1::EnumCode(7),
            EntrypointValueAtomV1::EnumCode(7),
        ];
        assert!(nested.validate_atoms(&atoms));
        assert_eq!(
            nested.word_kinds_for_atoms(&atoms),
            Some(vec![EntrypointValueWordKindV1::Sum])
        );
        let frame = norito::to_bytes(&nested).unwrap();
        assert_eq!(
            norito::decode_canonical::<EntrypointValueTypeV1>(&frame).unwrap(),
            nested
        );
        let json = norito::json::to_json(&nested).unwrap();
        assert_eq!(
            norito::json::from_str::<EntrypointValueTypeV1>(&json).unwrap(),
            nested
        );
        let record = EntrypointReturnRecordV1 {
            schema_hash: entrypoint_return_schema_hash_v1(&norito::codec::Encode::encode(&nested)),
            atoms,
        };
        let json = norito::json::to_json(&record).unwrap();
        assert_eq!(
            norito::json::from_str::<EntrypointReturnRecordV1>(&json).unwrap(),
            record
        );
        assert!(
            norito::json::from_str::<EntrypointReturnRecordV1>(&json.replacen(
                '{',
                "{\"unknown\":true,",
                1
            ))
            .is_err()
        );
        let mut other = enum_type.clone();
        let EntrypointValueTypeNodeV1::Enum(other_descriptor) = &mut other.nodes[0] else {
            unreachable!()
        };
        other_descriptor.identity = "example/other@1::Other::Phase".into();
        assert_ne!(
            entrypoint_return_schema_hash_v1(&norito::codec::Encode::encode(&enum_type)),
            entrypoint_return_schema_hash_v1(&norito::codec::Encode::encode(&other))
        );
        let EntrypointValueTypeNodeV1::Enum(other_descriptor) = &mut other.nodes[0] else {
            unreachable!()
        };
        other_descriptor.variants[0].code = 0;
        assert!(!other.validate());
        assert!(
            norito::decode_canonical::<EntrypointValueTypeV1>(&norito::to_bytes(&other).unwrap())
                .is_err()
        );
        let tag = norito::codec::Encode::encode(&enum_type.nodes[0]);
        assert_eq!(&tag[..4], &9_u32.to_le_bytes());
        let tag = norito::codec::Encode::encode(&EntrypointValueAtomV1::EnumCode(7));
        assert_eq!(&tag[..4], &6_u32.to_le_bytes());
        let tag = norito::codec::Encode::encode(&EntrypointValueWordKindV1::Enum);
        assert_eq!(&tag[..4], &6_u32.to_le_bytes());
    }
    #[test]
    fn nominal_public_schema_and_atom_tags_are_pinned() {
        let descriptor = super::super::manifest::ContractErrorTypeDescriptor {
            identity: "example::Error".into(),
            variants: vec![super::super::manifest::ContractErrorVariantDescriptor {
                name: "Rejected".into(),
                code: 1,
            }],
        };
        for (node, expected) in [
            (EntrypointValueTypeNodeV1::Unit, 6_u32),
            (EntrypointValueTypeNodeV1::Error(descriptor), 7),
            (
                EntrypointValueTypeNodeV1::StateCursor(leaf(EntrypointValueKindV1::Int)),
                8,
            ),
        ] {
            let encoded = norito::codec::Encode::encode(&node);
            assert_eq!(&encoded[..4], &expected.to_le_bytes());
        }
        for (atom, expected) in [
            (EntrypointValueAtomV1::Unit, 4_u32),
            (EntrypointValueAtomV1::ErrorCode(1), 5),
        ] {
            let encoded = norito::codec::Encode::encode(&atom);
            assert_eq!(&encoded[..4], &expected.to_le_bytes());
        }
    }
    #[test]
    fn state_page_schema_requires_matching_cursor_and_bounded_pair_items() {
        let mut schema = EntrypointValueTypeV1 {
            nodes: vec![
                EntrypointValueTypeNodeV1::Struct(EntrypointStructTypeNodeV1 {
                    name: "kotodama::StatePage".into(),
                    fields: vec!["items".into(), "next".into()],
                }),
                EntrypointValueTypeNodeV1::List(EntrypointListTypeNodeV1 { capacity: 8 }),
                EntrypointValueTypeNodeV1::Tuple(2),
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Bool),
                EntrypointValueTypeNodeV1::Option,
                EntrypointValueTypeNodeV1::StateCursor(leaf(EntrypointValueKindV1::Int)),
            ],
        };
        assert_eq!(
            schema.canonical_type_name().as_deref(),
            Some("StatePage<int, bool, 8>")
        );
        assert_eq!(schema.word_count(), Some(2));
        schema.nodes[6] = EntrypointValueTypeNodeV1::StateCursor(leaf(EntrypointValueKindV1::Bool));
        assert!(!schema.validate());
        schema.nodes[6] = EntrypointValueTypeNodeV1::StateCursor(leaf(EntrypointValueKindV1::Int));
        schema.nodes[1] =
            EntrypointValueTypeNodeV1::List(EntrypointListTypeNodeV1 { capacity: 65 });
        assert!(!schema.validate());
    }
    #[test]
    fn cursor_schema_is_a_nominal_one_word_pointer_and_rejects_json_keys() {
        let schema = EntrypointValueTypeV1 {
            nodes: vec![EntrypointValueTypeNodeV1::StateCursor(leaf(
                EntrypointValueKindV1::Int,
            ))],
        };
        assert_eq!(
            schema.canonical_type_name().as_deref(),
            Some("StateCursor<int>")
        );
        assert_eq!(
            schema.word_kinds(),
            Some(vec![EntrypointValueWordKindV1::StateCursor(
                state_key_schema_hash_v1(&leaf(EntrypointValueKindV1::Int)).unwrap()
            )])
        );
        let frame = norito::encode_canonical(&schema).unwrap();
        assert_eq!(
            norito::decode_canonical::<EntrypointValueTypeV1>(&frame).unwrap(),
            schema
        );
        assert!(
            !EntrypointValueTypeV1 {
                nodes: vec![EntrypointValueTypeNodeV1::StateCursor(leaf(
                    EntrypointValueKindV1::Json
                ))]
            }
            .validate()
        );
    }
    fn leaf(kind: EntrypointValueKindV1) -> EntrypointValueTypeV1 {
        EntrypointValueTypeV1 {
            nodes: vec![EntrypointValueTypeNodeV1::Leaf(kind)],
        }
    }
    fn int_atom(value: u8) -> EntrypointValueAtomV1 {
        EntrypointValueAtomV1::Pointer(vec![value])
    }
    fn nested_list_schema(list_count: usize) -> EntrypointValueTypeV1 {
        let mut nodes = Vec::with_capacity(list_count.saturating_add(1));
        nodes.extend((0..list_count).map(|_| {
            EntrypointValueTypeNodeV1::List(EntrypointListTypeNodeV1 {
                capacity: MIN_ENTRYPOINT_LIST_CAPACITY_V1,
            })
        }));
        nodes.push(EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int));
        EntrypointValueTypeV1 { nodes }
    }
    fn wide_tuple_schema(child_count: usize) -> EntrypointValueTypeV1 {
        let arity = u16::try_from(child_count).expect("test tuple arity fits u16");
        let mut nodes = Vec::with_capacity(child_count.saturating_add(1));
        nodes.push(EntrypointValueTypeNodeV1::Tuple(arity));
        nodes.extend(
            (0..child_count).map(|_| EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int)),
        );
        EntrypointValueTypeV1 { nodes }
    }
    fn account_view_schema() -> EntrypointValueTypeV1 {
        EntrypointValueTypeV1 {
            nodes: vec![
                EntrypointValueTypeNodeV1::Struct(EntrypointStructTypeNodeV1 {
                    name: "kotodama::AccountView".into(),
                    fields: vec!["id".into(), "metadata".into()],
                }),
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::AccountId),
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Json),
            ],
        }
    }
    fn asset_definition_view_schema() -> EntrypointValueTypeV1 {
        use EntrypointValueKindV1 as Kind;
        use EntrypointValueTypeNodeV1 as Node;
        EntrypointValueTypeV1 {
            nodes: vec![
                Node::Struct(EntrypointStructTypeNodeV1 {
                    name: "kotodama::AssetDefinitionView".into(),
                    fields: [
                        "id",
                        "name",
                        "description",
                        "owned_by",
                        "total_quantity",
                        "numeric_scale",
                        "metadata",
                    ]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                }),
                Node::Leaf(Kind::AssetDefinitionId),
                Node::Leaf(Kind::String),
                Node::Option,
                Node::Leaf(Kind::String),
                Node::Leaf(Kind::AccountId),
                Node::Leaf(Kind::Quantity),
                Node::Option,
                Node::Leaf(Kind::Int),
                Node::Leaf(Kind::Json),
            ],
        }
    }
    fn query_page_schema(view: &EntrypointValueTypeV1) -> EntrypointValueTypeV1 {
        let mut nodes = vec![
            EntrypointValueTypeNodeV1::Struct(EntrypointStructTypeNodeV1 {
                name: "kotodama::QueryPage".into(),
                fields: vec!["items".into(), "next_offset".into()],
            }),
            EntrypointValueTypeNodeV1::List(EntrypointListTypeNodeV1 {
                capacity: MAX_ENTRYPOINT_LIST_CAPACITY_V1,
            }),
        ];
        nodes.extend(view.nodes.iter().cloned());
        nodes.extend([
            EntrypointValueTypeNodeV1::Option,
            EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
        ]);
        EntrypointValueTypeV1 { nodes }
    }
    #[test]
    fn exact_nested_type_roundtrips_and_counts_register_words() {
        let ty = EntrypointValueTypeV1 {
            nodes: vec![
                EntrypointValueTypeNodeV1::Struct(EntrypointStructTypeNodeV1 {
                    name: "Fixture::Receipt".into(),
                    fields: vec!["status".into(), "detail".into()],
                }),
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Bool),
                EntrypointValueTypeNodeV1::Result,
                EntrypointValueTypeNodeV1::Option,
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::String),
                EntrypointValueTypeNodeV1::Tuple(2),
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Bool),
            ],
        };
        let encoded = norito::to_bytes(&ty).expect("encode exact boundary type");
        let decoded: EntrypointValueTypeV1 =
            norito::decode_from_bytes(&encoded).expect("decode exact boundary type");
        assert_eq!(decoded, ty);
        assert_eq!(decoded.word_count(), Some(2));
        assert_eq!(
            decoded.canonical_type_name().as_deref(),
            Some("struct Fixture::Receipt")
        );
    }
    #[test]
    fn numeric_boundary_leaves_are_distinct_pointer_types() {
        for (kind, name) in [
            (EntrypointValueKindV1::Int, "int"),
            (EntrypointValueKindV1::Decimal, "decimal"),
            (EntrypointValueKindV1::Quantity, "quantity"),
        ] {
            assert!(kind.is_pointer());
            let schema = leaf(kind);
            assert_eq!(schema.canonical_type_name().as_deref(), Some(name));
            assert!(schema.validate_atoms(&[EntrypointValueAtomV1::Pointer(vec![1])]));
            assert!(!schema.validate_atoms(&[EntrypointValueAtomV1::Bool(true)]));
        }
        assert!(!EntrypointValueKindV1::Bool.is_pointer());
    }
    #[test]
    fn inactive_sum_payloads_are_absent_from_the_wire() {
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "value".into(),
                ty: EntrypointValueTypeV1 {
                    nodes: vec![
                        EntrypointValueTypeNodeV1::Option,
                        EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::String),
                    ],
                },
            }],
        };
        assert_eq!(schema.word_count(), Some(1));
        assert_eq!(
            schema.word_kinds(),
            Some(vec![EntrypointValueWordKindV1::Sum])
        );
        assert!(schema.validate_atoms(&[EntrypointValueAtomV1::Tag(false)]));
        assert_eq!(
            schema.word_kinds_for_atoms(&[EntrypointValueAtomV1::Tag(false)]),
            Some(vec![EntrypointValueWordKindV1::Sum])
        );
        assert!(!schema.validate_atoms(&[
            EntrypointValueAtomV1::Tag(false),
            EntrypointValueAtomV1::Pointer(vec![1]),
        ]));
    }
    #[test]
    fn recursive_lists_roundtrip_and_enforce_capacity() {
        let nested = EntrypointValueTypeV1 {
            nodes: vec![
                EntrypointValueTypeNodeV1::List(EntrypointListTypeNodeV1 { capacity: 3 }),
                EntrypointValueTypeNodeV1::List(EntrypointListTypeNodeV1 { capacity: 2 }),
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Quantity),
            ],
        };
        assert!(nested.validate());
        assert_eq!(nested.word_count(), Some(1));
        assert_eq!(
            nested.canonical_type_name().as_deref(),
            Some("List<List<quantity, 2>, 3>")
        );
        assert_eq!(
            entrypoint_value_subtree_range_v1(&nested.nodes, 0),
            Some(0..3)
        );
        assert_eq!(
            entrypoint_value_subtree_range_v1(&nested.nodes, 1),
            Some(1..3)
        );
        assert_eq!(
            entrypoint_value_subtree_range_v1(&nested.nodes, 2),
            Some(2..3)
        );
        assert_eq!(entrypoint_value_subtree_range_v1(&nested.nodes, 3), None);
        assert_eq!(nested.subtree_nodes(1), Some(&nested.nodes[1..3]));
        let encoded = norito::to_bytes(&nested).expect("encode nested list schema");
        assert_eq!(
            norito::decode_from_bytes::<EntrypointValueTypeV1>(&encoded)
                .expect("decode nested list schema"),
            nested
        );
        for capacity in [0, 65] {
            let invalid = EntrypointValueTypeV1 {
                nodes: vec![
                    EntrypointValueTypeNodeV1::List(EntrypointListTypeNodeV1 { capacity }),
                    EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
                ],
            };
            assert!(!invalid.validate());
            assert_eq!(invalid.subtree_nodes(0), None);
        }

        {
            let json = norito::json::to_string(&nested).expect("encode flat list schema JSON");
            assert!(json.contains("capacity"));
            assert!(
                !json.contains("element"),
                "the flat V1 wire schema must not retain recursive list ownership"
            );
            assert_eq!(
                norito::json::from_str::<EntrypointValueTypeV1>(&json)
                    .expect("decode flat list schema JSON"),
                nested
            );
        }
    }
    #[test]
    fn flat_schema_rejects_missing_children_and_trailing_roots() {
        let list = EntrypointValueTypeNodeV1::List(EntrypointListTypeNodeV1 { capacity: 1 });
        let int = EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int);
        for nodes in [
            Vec::new(),
            vec![list.clone()],
            vec![list.clone(), int.clone(), int.clone()],
            vec![EntrypointValueTypeNodeV1::Option],
            vec![EntrypointValueTypeNodeV1::Result, int.clone()],
            vec![EntrypointValueTypeNodeV1::Tuple(2), int.clone()],
            vec![int.clone(), int.clone()],
        ] {
            let schema = EntrypointValueTypeV1 { nodes };
            assert!(!schema.validate());
            assert_eq!(schema.word_count(), None);
            assert_eq!(schema.word_kinds(), None);
            assert_eq!(schema.canonical_type_name(), None);
            assert!(!schema.validate_atoms(&[]));
            let encoded = norito::to_bytes(&schema).expect("encode malformed flat schema fixture");
            assert!(matches!(
                norito::decode_from_bytes::<EntrypointValueTypeV1>(&encoded),
                Err(norito::Error::Message(message))
                    if message == "invalid V1 entrypoint value schema"
            ));

            {
                let json =
                    norito::json::to_string(&schema).expect("encode malformed flat schema JSON");
                assert!(norito::json::from_str::<EntrypointValueTypeV1>(&json).is_err());
                assert!(norito::json::from_json_auto::<EntrypointValueTypeV1>(&json).is_err());
            }
        }
    }
    #[test]
    fn list_items_use_the_exact_following_subtree_and_advance_once() {
        let schema = EntrypointValueTypeV1 {
            nodes: vec![
                EntrypointValueTypeNodeV1::Tuple(2),
                EntrypointValueTypeNodeV1::List(EntrypointListTypeNodeV1 { capacity: 2 }),
                EntrypointValueTypeNodeV1::Tuple(2),
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Bool),
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::String),
            ],
        };
        assert!(schema.validate());
        assert_eq!(schema.word_count(), Some(2));
        assert_eq!(
            schema.word_kinds(),
            Some(vec![
                EntrypointValueWordKindV1::List,
                EntrypointValueWordKindV1::Leaf(EntrypointValueKindV1::String),
            ])
        );
        let atoms = vec![
            EntrypointValueAtomV1::List(2),
            int_atom(1),
            EntrypointValueAtomV1::Bool(true),
            int_atom(2),
            EntrypointValueAtomV1::Bool(false),
            EntrypointValueAtomV1::Pointer(vec![0x10]),
        ];
        assert!(schema.validate_atoms(&atoms));
        assert_eq!(schema.word_kinds_for_atoms(&atoms), schema.word_kinds());
        let empty = vec![
            EntrypointValueAtomV1::List(0),
            EntrypointValueAtomV1::Pointer(Vec::new()),
        ];
        assert!(schema.validate_atoms(&empty));
        let invalid = [
            vec![
                EntrypointValueAtomV1::List(3),
                int_atom(1),
                EntrypointValueAtomV1::Bool(true),
                int_atom(2),
                EntrypointValueAtomV1::Bool(false),
                int_atom(3),
                EntrypointValueAtomV1::Bool(true),
                EntrypointValueAtomV1::Pointer(Vec::new()),
            ],
            vec![
                EntrypointValueAtomV1::List(1),
                int_atom(1),
                EntrypointValueAtomV1::Pointer(Vec::new()),
            ],
            vec![
                EntrypointValueAtomV1::List(1),
                int_atom(1),
                EntrypointValueAtomV1::Bool(true),
                EntrypointValueAtomV1::Bool(false),
                EntrypointValueAtomV1::Pointer(Vec::new()),
            ],
            vec![
                EntrypointValueAtomV1::List(1),
                EntrypointValueAtomV1::Bool(true),
                int_atom(1),
                EntrypointValueAtomV1::Pointer(Vec::new()),
            ],
            vec![
                EntrypointValueAtomV1::List(1),
                int_atom(1),
                EntrypointValueAtomV1::Bool(true),
            ],
            vec![
                EntrypointValueAtomV1::List(2),
                int_atom(1),
                EntrypointValueAtomV1::Bool(true),
                EntrypointValueAtomV1::Pointer(Vec::new()),
            ],
            vec![
                EntrypointValueAtomV1::List(1),
                int_atom(2),
                EntrypointValueAtomV1::Bool(false),
                EntrypointValueAtomV1::Pointer(Vec::new()),
                EntrypointValueAtomV1::Bool(false),
            ],
        ];
        for atoms in invalid {
            assert!(
                !schema.validate_atoms(&atoms),
                "malformed list record {atoms:?}"
            );
            assert_eq!(schema.word_kinds_for_atoms(&atoms), None);
        }
    }
    #[test]
    fn nested_list_items_are_checked_without_recursive_schema_ownership() {
        let schema = EntrypointValueTypeV1 {
            nodes: vec![
                EntrypointValueTypeNodeV1::List(EntrypointListTypeNodeV1 { capacity: 1 }),
                EntrypointValueTypeNodeV1::List(EntrypointListTypeNodeV1 { capacity: 1 }),
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
            ],
        };
        let valid = vec![
            EntrypointValueAtomV1::List(1),
            EntrypointValueAtomV1::List(1),
            int_atom(7),
        ];
        assert!(schema.validate_atoms(&valid));
        assert_eq!(
            schema.word_kinds_for_atoms(&valid),
            Some(vec![EntrypointValueWordKindV1::List])
        );
        for invalid in [
            vec![
                EntrypointValueAtomV1::List(1),
                EntrypointValueAtomV1::List(1),
            ],
            vec![
                EntrypointValueAtomV1::List(1),
                EntrypointValueAtomV1::List(2),
                int_atom(1),
                int_atom(2),
            ],
            vec![EntrypointValueAtomV1::List(1), int_atom(7)],
            vec![
                EntrypointValueAtomV1::List(0),
                EntrypointValueAtomV1::List(0),
            ],
        ] {
            assert!(!schema.validate_atoms(&invalid));
        }
    }
    #[test]
    fn flat_list_marker_rejects_truncation_trailing_atoms_and_count_mismatches() {
        let schema = EntrypointValueTypeV1 {
            nodes: vec![
                EntrypointValueTypeNodeV1::List(EntrypointListTypeNodeV1 { capacity: 2 }),
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
            ],
        };
        assert!(schema.validate_atoms(&[EntrypointValueAtomV1::List(0)]));
        assert!(
            schema.validate_atoms(&[EntrypointValueAtomV1::List(2), int_atom(1), int_atom(2),])
        );
        for malformed in [
            vec![EntrypointValueAtomV1::List(1)],
            vec![EntrypointValueAtomV1::List(0), int_atom(1)],
            vec![EntrypointValueAtomV1::List(1), int_atom(1), int_atom(2)],
            vec![EntrypointValueAtomV1::List(2), int_atom(1)],
            vec![
                EntrypointValueAtomV1::List(3),
                int_atom(1),
                int_atom(2),
                int_atom(3),
            ],
            vec![
                EntrypointValueAtomV1::List(1),
                EntrypointValueAtomV1::Bool(true),
            ],
        ] {
            assert!(!schema.validate_atoms(&malformed), "{malformed:?}");
            assert_eq!(schema.word_kinds_for_atoms(&malformed), None);
        }
    }
    #[test]
    fn flat_atom_tape_is_stack_safe_at_the_depth_limit() {
        let schema = nested_list_schema(MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH - 1);
        let mut atoms = Vec::with_capacity(MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH);
        atoms.extend(
            (0..MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH - 1).map(|_| EntrypointValueAtomV1::List(1)),
        );
        atoms.push(int_atom(7));
        assert!(schema.validate_atoms(&atoms));
        assert_eq!(
            schema.word_kinds_for_atoms(&atoms),
            Some(vec![EntrypointValueWordKindV1::List])
        );
        let record = EntrypointArgumentRecordV1 {
            schema_hash: [0x5a; 32],
            atoms,
        };
        let encoded = norito::to_bytes(&record).expect("encode flat atom tape at depth limit");
        let decoded = norito::decode_from_bytes::<EntrypointArgumentRecordV1>(&encoded)
            .expect("decode flat atom tape at depth limit");
        assert_eq!(decoded, record);
        assert!(schema.validate_atoms(&decoded.atoms));
        assert_eq!(
            norito::to_bytes(&decoded).expect("re-encode flat atom tape at depth limit"),
            encoded
        );
    }
    #[test]
    fn argument_schema_preserves_order_at_full_abi_bound_and_rejects_distant_duplicates() {
        let mut schema = EntrypointArgumentSchemaV1 {
            fields: (0..MAX_ENTRYPOINT_ARGUMENTS)
                .rev()
                .map(|index| EntrypointArgumentFieldV1 {
                    name: format!("arg{index:04}"),
                    ty: EntrypointValueTypeV1 {
                        nodes: vec![EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int)],
                    },
                })
                .collect(),
        };
        let names: Vec<_> = schema
            .fields
            .iter()
            .map(|field| field.name.clone())
            .collect();
        assert!(schema.validate());
        assert_eq!(schema.word_count(), Some(MAX_ENTRYPOINT_ARGUMENT_WORDS));
        assert!(schema.fields.iter().map(|field| &field.name).eq(&names));
        for duplicate in [
            1,
            MAX_ENTRYPOINT_ARGUMENTS / 2,
            MAX_ENTRYPOINT_ARGUMENTS - 1,
        ] {
            let original = core::mem::replace(&mut schema.fields[duplicate].name, names[0].clone());
            assert!(!schema.validate(), "duplicate argument index {duplicate}");
            schema.fields[duplicate].name = original;
            assert!(schema.validate());
        }
        schema.fields.push(EntrypointArgumentFieldV1 {
            name: "one_too_many".into(),
            ty: EntrypointValueTypeV1 {
                nodes: vec![EntrypointValueTypeNodeV1::Unit],
            },
        });
        assert!(
            !schema.validate(),
            "argument count bound applies even to a unit field"
        );
        schema.fields.pop();
        schema.fields[0].name = "invalid-name".into();
        assert!(!schema.validate());
        schema.fields[0].name = names[0].clone();
        schema.fields[0].ty.nodes.clear();
        assert!(!schema.validate());
    }
    #[test]
    fn fixed_stack_schema_analysis_requires_unique_fields_and_exact_children() {
        let mut schema = EntrypointValueTypeV1 {
            nodes: vec![
                EntrypointValueTypeNodeV1::Struct(EntrypointStructTypeNodeV1 {
                    name: "Fixture::Pair".into(),
                    fields: vec!["z".into(), "a".into()],
                }),
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Bool),
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Bool),
            ],
        };
        assert_eq!(schema.word_count(), Some(2));
        let EntrypointValueTypeNodeV1::Struct(product) = &mut schema.nodes[0] else {
            unreachable!()
        };
        product.fields[1] = "z".into();
        assert!(!schema.validate());
        let EntrypointValueTypeNodeV1::Struct(product) = &mut schema.nodes[0] else {
            unreachable!()
        };
        product.fields[1] = "a".into();
        schema.nodes.pop();
        assert!(!schema.validate());
        schema
            .nodes
            .push(EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Bool));
        schema.nodes.push(EntrypointValueTypeNodeV1::Unit);
        assert!(!schema.validate());
    }
    #[test]
    fn flat_schema_accepts_exact_node_budget_and_rejects_one_more() {
        let at_limit = wide_tuple_schema(MAX_ENTRYPOINT_ARGUMENT_TYPE_NODES - 1);
        assert_eq!(at_limit.nodes.len(), MAX_ENTRYPOINT_ARGUMENT_TYPE_NODES);
        assert!(at_limit.validate());
        assert_eq!(
            entrypoint_value_subtree_range_v1(&at_limit.nodes, 0),
            Some(0..MAX_ENTRYPOINT_ARGUMENT_TYPE_NODES)
        );
        let encoded = norito::to_bytes(&at_limit).expect("encode max-node flat schema");
        assert_eq!(
            norito::decode_from_bytes::<EntrypointValueTypeV1>(&encoded)
                .expect("decode max-node flat schema"),
            at_limit
        );
        let over_limit = wide_tuple_schema(MAX_ENTRYPOINT_ARGUMENT_TYPE_NODES);
        assert_eq!(
            over_limit.nodes.len(),
            MAX_ENTRYPOINT_ARGUMENT_TYPE_NODES + 1
        );
        assert!(!over_limit.validate());
        let encoded = norito::to_bytes(&over_limit).expect("encode over-node-budget fixture");
        assert!(matches!(
            norito::decode_from_bytes::<EntrypointValueTypeV1>(&encoded),
            Err(norito::Error::Message(message))
                if message == "invalid V1 entrypoint value schema"
        ));

        {
            let json = norito::json::to_string(&over_limit).expect("encode over-node-budget JSON");
            assert!(norito::json::from_str::<EntrypointValueTypeV1>(&json).is_err());
            assert!(norito::json::from_json_auto::<EntrypointValueTypeV1>(&json).is_err());
        }
    }
    #[test]
    fn binary_schema_decode_accepts_the_flat_depth_limit_and_rejects_the_next_level() {
        let at_limit = nested_list_schema(MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH - 1);
        assert_eq!(at_limit.nodes.len(), MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH);
        assert!(at_limit.validate());
        let encoded = norito::to_bytes(&at_limit).expect("encode schema at flat depth limit");
        let decoded = norito::decode_from_bytes::<EntrypointValueTypeV1>(&encoded)
            .expect("decode schema at flat depth limit");
        assert_eq!(decoded, at_limit);
        assert_eq!(
            norito::to_bytes(&decoded).expect("re-encode schema at flat depth limit"),
            encoded,
            "custom validation must not change the canonical wire format"
        );
        let over_limit = nested_list_schema(MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH);
        assert_eq!(
            over_limit.nodes.len(),
            MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH + 1
        );
        assert!(!over_limit.validate());
        let encoded = norito::to_bytes(&over_limit).expect("encode over-limit schema fixture");
        assert!(matches!(
            norito::decode_from_bytes::<EntrypointValueTypeV1>(&encoded),
            Err(norito::Error::Message(message))
                if message == "invalid V1 entrypoint value schema"
        ));
    }
    #[test]
    fn binary_schema_decode_rejects_deep_flat_input_without_native_recursion() {
        let deep = nested_list_schema(MAX_ENTRYPOINT_ARGUMENT_TYPE_NODES + 64);
        let encoded = norito::to_bytes(&deep).expect("encode adversarial flat schema");
        assert!(matches!(
            norito::decode_from_bytes::<EntrypointValueTypeV1>(&encoded),
            Err(norito::Error::Message(message))
                if message == "invalid V1 entrypoint value schema"
        ));
        let leaf_bytes =
            norito::to_bytes(&leaf(EntrypointValueKindV1::Bool)).expect("encode recovery fixture");
        norito::decode_from_bytes::<EntrypointValueTypeV1>(&leaf_bytes)
            .expect("failed flat-schema validation must not poison later decodes");
    }

    #[test]
    fn json_schema_decode_enforces_recursive_and_structural_limits() {
        let at_limit = nested_list_schema(MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH - 1);
        let json = norito::json::to_string(&at_limit).expect("encode schema JSON at limit");
        let decoded = norito::json::from_str::<EntrypointValueTypeV1>(&json)
            .expect("decode schema JSON at limit");
        assert_eq!(decoded, at_limit);
        assert_eq!(
            norito::json::from_json_auto::<EntrypointValueTypeV1>(&json)
                .expect("fast decode schema JSON at limit"),
            at_limit
        );
        let over_limit = nested_list_schema(MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH);
        let json = norito::json::to_string(&over_limit).expect("encode over-limit schema JSON");
        assert!(matches!(
            norito::json::from_str::<EntrypointValueTypeV1>(&json),
            Err(norito::json::Error::Message(message))
                if message == "invalid V1 entrypoint value schema"
        ));
        assert!(norito::json::from_json_auto::<EntrypointValueTypeV1>(&json).is_err());
        let deep = nested_list_schema(MAX_ENTRYPOINT_ARGUMENT_TYPE_NODES + 64);
        let deep_json = norito::json::to_string(&deep).expect("encode adversarial flat JSON");
        assert!(matches!(
            norito::json::from_json::<EntrypointValueTypeV1>(&deep_json),
            Err(norito::json::Error::Message(message))
                if message == "invalid V1 entrypoint value schema"
        ));
        assert!(norito::json::from_json_auto::<EntrypointValueTypeV1>(&deep_json).is_err());
        assert!(matches!(
            norito::json::from_str::<EntrypointValueTypeV1>(&deep_json),
            Err(norito::json::Error::Message(message))
                if message == "invalid V1 entrypoint value schema"
        ));
        let value = norito::json::to_value(&deep).expect("convert adversarial flat schema");
        assert!(norito::json::from_value::<EntrypointValueTypeV1>(value).is_err());
        let leaf_value = norito::json::to_value(&leaf(EntrypointValueKindV1::Bool))
            .expect("convert recovery schema to JSON value");
        norito::json::from_value::<EntrypointValueTypeV1>(leaf_value)
            .expect("failed from_value validation must not poison later decodes");
    }

    #[test]
    fn manual_fast_json_schema_decode_enforces_complete_document_depth() {
        let wrappers = norito::json::MAX_JSON_VALUE_NESTING_DEPTH - 1;
        let nested = format!("{}null{}", "[".repeat(wrappers), "]".repeat(wrappers));
        let input = format!(r#"{{"nodes":[],"unknown":{nested}}}"#);
        let mut walker = norito::json::TapeWalker::new(&input);
        let mut arena = norito::json::Arena::new();
        assert!(matches!(
            <EntrypointValueTypeV1 as norito::json::FastFromJson>::parse(
                &mut walker,
                &mut arena
            ),
            Err(norito::Error::Json(
                norito::json::Error::NestingDepthExceeded {
                    depth,
                    limit: norito::json::MAX_JSON_VALUE_NESTING_DEPTH,
                    context: "JSON value",
                }
            )) if depth == norito::json::MAX_JSON_VALUE_NESTING_DEPTH + 1
        ));
    }
    #[test]
    fn asset_definition_precision_schema_roundtrips_and_rejects_old_or_forged_shapes() {
        use EntrypointValueKindV1 as Kind;
        use EntrypointValueTypeNodeV1 as Node;
        let view = asset_definition_view_schema();
        assert_eq!(view.word_count(), Some(7));
        assert_eq!(
            view.canonical_type_name().as_deref(),
            Some("AssetDefinitionView")
        );
        for schema in [view.clone(), query_page_schema(&view)] {
            assert!(schema.validate());
            let bytes = norito::to_bytes(&schema).expect("encode native precision schema");
            assert_eq!(
                norito::decode_from_bytes::<EntrypointValueTypeV1>(&bytes).unwrap(),
                schema
            );
            let json = norito::json::to_string(&schema).unwrap();
            assert_eq!(
                norito::json::from_str::<EntrypointValueTypeV1>(&json).unwrap(),
                schema
            );
        }
        let assert_rejected = |label: &str, malformed: EntrypointValueTypeV1| {
            assert!(!malformed.validate(), "{label}");
            assert_eq!(malformed.word_count(), None, "{label}");
            assert_eq!(malformed.canonical_type_name(), None, "{label}");
            assert!(!query_page_schema(&malformed).validate(), "paged {label}");
            let json = norito::json::to_string(&malformed).unwrap();
            assert!(
                norito::json::from_str::<EntrypointValueTypeV1>(&json).is_err(),
                "JSON {label}"
            );
        };
        let mut retired = view.clone();
        let Node::Struct(root) = &mut retired.nodes[0] else {
            unreachable!()
        };
        root.fields.remove(5);
        retired.nodes.drain(7..9);
        assert_rejected("retired six-field definition", retired);
        for kind in [Kind::Decimal, Kind::Quantity, Kind::String] {
            let mut forged = view.clone();
            forged.nodes[8] = Node::Leaf(kind);
            assert_rejected("non-int precision", forged);
        }
        let mut required_scale = view.clone();
        required_scale.nodes.remove(7);
        assert_rejected("missing precision option", required_scale);
        let mut reordered = view;
        let Node::Struct(root) = &mut reordered.nodes[0] else {
            unreachable!()
        };
        root.fields.swap(5, 6);
        assert_rejected("reordered precision field", reordered);
    }
    #[test]
    fn every_reserved_query_projection_has_one_exact_flat_shape() {
        use EntrypointValueKindV1 as Kind;
        use EntrypointValueTypeNodeV1 as Node;
        let views = vec![
            account_view_schema(),
            EntrypointValueTypeV1 {
                nodes: vec![
                    Node::Struct(EntrypointStructTypeNodeV1 {
                        name: "kotodama::AssetView".into(),
                        fields: vec!["id".into(), "amount".into()],
                    }),
                    Node::Leaf(Kind::AssetId),
                    Node::Leaf(Kind::Quantity),
                ],
            },
            asset_definition_view_schema(),
            EntrypointValueTypeV1 {
                nodes: vec![
                    Node::Struct(EntrypointStructTypeNodeV1 {
                        name: "kotodama::DomainView".into(),
                        fields: vec!["id".into(), "owned_by".into(), "metadata".into()],
                    }),
                    Node::Leaf(Kind::DomainId),
                    Node::Leaf(Kind::AccountId),
                    Node::Leaf(Kind::Json),
                ],
            },
            EntrypointValueTypeV1 {
                nodes: vec![
                    Node::Struct(EntrypointStructTypeNodeV1 {
                        name: "kotodama::NftView".into(),
                        fields: vec!["id".into(), "owned_by".into(), "content".into()],
                    }),
                    Node::Leaf(Kind::NftId),
                    Node::Leaf(Kind::AccountId),
                    Node::Leaf(Kind::Json),
                ],
            },
        ];
        for view in views {
            let Node::Struct(root) = &view.nodes[0] else {
                unreachable!("projection fixture starts with a struct")
            };
            let name = root.name.strip_prefix("kotodama::").unwrap().to_owned();
            assert!(view.validate(), "valid reserved projection {name}");
            assert_eq!(view.canonical_type_name().as_deref(), Some(name.as_str()));
            let page = query_page_schema(&view);
            assert!(page.validate(), "valid reserved page {name}");
            let expected_page_name = format!("QueryPage<{name}>");
            assert_eq!(
                page.canonical_type_name().as_deref(),
                Some(expected_page_name.as_str())
            );
            let mut wrong_leaf = view.clone();
            let last = wrong_leaf.nodes.len() - 1;
            wrong_leaf.nodes[last] = Node::Leaf(Kind::Blob);
            assert!(!wrong_leaf.validate(), "forged reserved projection {name}");
            let mut wrong_page = page;
            let last = wrong_page.nodes.len() - 1;
            wrong_page.nodes[last] = Node::Leaf(Kind::String);
            assert!(!wrong_page.validate(), "forged next_offset for {name}");
        }
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn query_page_type_name_is_derived_from_its_structural_specialization() {
        let account_view = account_view_schema();
        assert!(account_view.validate());
        assert_eq!(
            account_view.canonical_type_name().as_deref(),
            Some("AccountView")
        );
        let account_option = EntrypointValueTypeV1 {
            nodes: std::iter::once(EntrypointValueTypeNodeV1::Option)
                .chain(account_view.nodes.iter().cloned())
                .collect(),
        };
        assert!(account_option.validate());
        assert_eq!(
            account_option.canonical_type_name().as_deref(),
            Some("Option<AccountView>")
        );
        let page = query_page_schema(&account_view);
        assert!(page.validate());
        assert_eq!(
            page.canonical_type_name().as_deref(),
            Some("QueryPage<AccountView>")
        );
        let encoded = norito::to_bytes(&page).expect("encode structural query-page schema");
        let decoded: EntrypointValueTypeV1 =
            norito::decode_from_bytes(&encoded).expect("decode structural query-page schema");
        assert_eq!(decoded, page);
        assert_eq!(
            decoded.canonical_type_name().as_deref(),
            Some("QueryPage<AccountView>")
        );
        let assert_reserved_rejected = |label: &str, schema: &EntrypointValueTypeV1| {
            assert!(!schema.validate(), "{label} must fail schema validation");
            assert_eq!(schema.word_count(), None, "{label} must have no ABI width");
            assert_eq!(
                schema.canonical_type_name(),
                None,
                "{label} must have no admissible public type name"
            );
        };
        let mut wrong_capacity = page.clone();
        let EntrypointValueTypeNodeV1::List(items) = &mut wrong_capacity.nodes[1] else {
            unreachable!("query-page fixture has an items list")
        };
        items.capacity = 32;
        assert_reserved_rejected("wrong QueryPage list capacity", &wrong_capacity);
        let mut unknown_view = page.clone();
        let EntrypointValueTypeNodeV1::Struct(view) = &mut unknown_view.nodes[2] else {
            unreachable!("query-page fixture has a projected struct")
        };
        view.name = "Fixture::UnknownView".into();
        assert_reserved_rejected("unknown QueryPage projection", &unknown_view);
        let mut wrong_fields = page.clone();
        let EntrypointValueTypeNodeV1::Struct(view) = &mut wrong_fields.nodes[2] else {
            unreachable!("query-page fixture has a projected struct")
        };
        view.fields[1] = "content".into();
        assert_reserved_rejected("reserved view with wrong fields", &wrong_fields);
        let mut wrong_kind = page.clone();
        wrong_kind.nodes[3] = EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::DomainId);
        assert_reserved_rejected("reserved view with wrong leaf kind", &wrong_kind);
        let mut wrong_next_offset = page.clone();
        wrong_next_offset.nodes[6] = EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::String);
        assert_reserved_rejected("QueryPage with non-i64 next_offset", &wrong_next_offset);
        let mut ordinary_struct = unknown_view;
        let EntrypointValueTypeNodeV1::Struct(page_node) = &mut ordinary_struct.nodes[0] else {
            unreachable!("query-page fixture starts with a struct")
        };
        page_node.name = "Fixture::Page".into();
        assert!(ordinary_struct.validate());
        assert_eq!(
            ordinary_struct.canonical_type_name().as_deref(),
            Some("struct Fixture::Page"),
            "non-reserved user structs retain ordinary nominal rendering"
        );
    }
    #[test]
    fn argument_and_return_words_share_the_v1_table_bound() {
        assert_eq!(MAX_ENTRYPOINT_RETURN_WORDS, 8_192);
        assert_eq!(MAX_ENTRYPOINT_ARGUMENT_WORDS, MAX_ENTRYPOINT_RETURN_WORDS);
        assert_eq!(ENTRYPOINT_RETURN_TLV_ENVELOPE_BYTES_V1, 39);
        assert_eq!(
            MAX_ENTRYPOINT_RETURN_RECORD_BYTES + ENTRYPOINT_RETURN_TLV_ENVELOPE_BYTES_V1,
            MAX_ENTRYPOINT_BOUNDARY_BYTES
        );
        assert_eq!(leaf(EntrypointValueKindV1::Bool).word_count(), Some(1));
    }
    #[test]
    fn argument_table_bound_counts_flattened_words() {
        let mut schema = EntrypointArgumentSchemaV1 {
            fields: (0..64)
                .map(|index| EntrypointArgumentFieldV1 {
                    name: format!("field_{index}"),
                    ty: wide_tuple_schema(128),
                })
                .collect(),
        };
        assert_eq!(schema.word_count(), Some(8_192));
        schema.fields.push(EntrypointArgumentFieldV1 {
            name: "overflow".into(),
            ty: leaf(EntrypointValueKindV1::Bool),
        });
        assert!(!schema.validate());
        assert_eq!(schema.word_count(), None);
    }
    #[test]
    fn canonical_boundary_identifiers_reject_keywords_and_forbidden_spellings() {
        assert_eq!(KOTODAMA_V1_FORBIDDEN_SOURCE_IDENTIFIERS, &["Amount"]);
        assert!(!is_canonical_kotodama_identifier("Amount"));
        assert!(is_canonical_kotodama_identifier("amount"));
        for keyword in [
            "authorize",
            "break",
            "const",
            "continue",
            "decimal",
            "else",
            "enum",
            "emit",
            "event",
            "error",
            "false",
            "fn",
            "for",
            "hajimari",
            "始まり",
            "if",
            "in",
            "int",
            "kaizen",
            "改善",
            "kotoage",
            "言挙げ",
            "let",
            "match",
            "module",
            "permission",
            "quantity",
            "return",
            "seiyaku",
            "誓約",
            "state",
            "struct",
            "trigger",
            "true",
            "var",
            "view",
        ] {
            assert!(
                !is_canonical_kotodama_identifier(keyword),
                "keyword `{keyword}` must not be a boundary identifier"
            );
        }
        for identifier in ["contract", "entry", "init", "upgrade", "_value2"] {
            assert!(
                is_canonical_kotodama_identifier(identifier),
                "retired declaration word `{identifier}` remains an ordinary identifier"
            );
        }
    }
    #[test]
    fn empty_named_products_use_one_zero_word_and_no_atoms() {
        let empty_struct = EntrypointValueTypeV1 {
            nodes: vec![EntrypointValueTypeNodeV1::Struct(
                EntrypointStructTypeNodeV1 {
                    name: "Fixture::Empty".to_owned(),
                    fields: Vec::new(),
                },
            )],
        };
        assert!(empty_struct.validate());
        assert_eq!(empty_struct.word_count(), Some(1));
        assert_eq!(
            empty_struct.word_kinds(),
            Some(vec![EntrypointValueWordKindV1::Unit])
        );
        assert_eq!(
            empty_struct.word_kinds_for_atoms(&[]),
            empty_struct.word_kinds()
        );
        assert!(empty_struct.validate_atoms(&[]));
        assert!(!empty_struct.validate_atoms(&[EntrypointValueAtomV1::Unit]));
        assert_eq!(
            empty_struct.canonical_type_name().as_deref(),
            Some("struct Fixture::Empty")
        );
        let encoded = norito::to_bytes(&empty_struct).expect("encode empty nominal schema");
        assert_eq!(
            norito::decode_from_bytes::<EntrypointValueTypeV1>(&encoded).unwrap(),
            empty_struct
        );

        let mut nested = vec![EntrypointValueTypeNodeV1::List(EntrypointListTypeNodeV1 {
            capacity: 2,
        })];
        nested.extend(empty_struct.nodes.clone());
        let list = EntrypointValueTypeV1 { nodes: nested };
        assert_eq!(list.word_count(), Some(1));
        assert!(list.validate_atoms(&[EntrypointValueAtomV1::List(2)]));
        assert_eq!(
            list.word_kinds_for_atoms(&[EntrypointValueAtomV1::List(2)]),
            Some(vec![EntrypointValueWordKindV1::List])
        );
    }
    #[test]
    fn schemas_reject_non_tuple_arities() {
        for arity in [0, 1] {
            let mut nodes = vec![EntrypointValueTypeNodeV1::Tuple(arity)];
            nodes.extend(
                (0..arity).map(|_| EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int)),
            );
            assert!(!EntrypointValueTypeV1 { nodes }.validate());
        }
    }
    #[test]
    fn schemas_reject_noncanonical_and_duplicate_identifiers() {
        for invalid in [
            "",
            "two words",
            "言挙げ",
            "with-dash",
            "9starts_with_digit",
            "seiyaku",
            "Amount",
        ] {
            let argument = EntrypointArgumentSchemaV1 {
                fields: vec![EntrypointArgumentFieldV1 {
                    name: invalid.to_owned(),
                    ty: leaf(EntrypointValueKindV1::Int),
                }],
            };
            assert!(!argument.validate(), "argument field `{invalid}` must fail");
            let structure = EntrypointValueTypeV1 {
                nodes: vec![
                    EntrypointValueTypeNodeV1::Struct(EntrypointStructTypeNodeV1 {
                        name: "Fixture::Valid".to_owned(),
                        fields: vec![invalid.to_owned()],
                    }),
                    EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
                ],
            };
            assert!(!structure.validate(), "struct field `{invalid}` must fail");
        }
        let invalid_struct_name = EntrypointValueTypeV1 {
            nodes: vec![
                EntrypointValueTypeNodeV1::Struct(EntrypointStructTypeNodeV1 {
                    name: "Bad.Name".to_owned(),
                    fields: vec!["field".to_owned()],
                }),
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
            ],
        };
        assert!(!invalid_struct_name.validate());
        let retired_struct_name = EntrypointValueTypeV1 {
            nodes: vec![
                EntrypointValueTypeNodeV1::Struct(EntrypointStructTypeNodeV1 {
                    name: "Amount".to_owned(),
                    fields: vec!["amount".to_owned()],
                }),
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Quantity),
            ],
        };
        assert!(!retired_struct_name.validate());
        let duplicate_fields = EntrypointValueTypeV1 {
            nodes: vec![
                EntrypointValueTypeNodeV1::Struct(EntrypointStructTypeNodeV1 {
                    name: "Fixture::Valid".to_owned(),
                    fields: vec!["same".to_owned(), "same".to_owned()],
                }),
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Bool),
            ],
        };
        assert!(!duplicate_fields.validate());
    }
    #[test]
    fn every_leaf_and_cursor_key_has_one_canonical_spelling() {
        for (kind, expected) in [
            (EntrypointValueKindV1::Int, "int"),
            (EntrypointValueKindV1::Decimal, "decimal"),
            (EntrypointValueKindV1::Quantity, "quantity"),
            (EntrypointValueKindV1::Bool, "bool"),
            (EntrypointValueKindV1::String, "string"),
            (EntrypointValueKindV1::Json, "Json"),
            (EntrypointValueKindV1::Name, "Name"),
            (EntrypointValueKindV1::AccountId, "AccountId"),
            (
                EntrypointValueKindV1::AssetDefinitionId,
                "AssetDefinitionId",
            ),
            (EntrypointValueKindV1::AssetId, "AssetId"),
            (EntrypointValueKindV1::DomainId, "DomainId"),
            (EntrypointValueKindV1::NftId, "NftId"),
            (EntrypointValueKindV1::DataSpaceId, "DataSpaceId"),
            (EntrypointValueKindV1::Blob, "bytes"),
        ] {
            assert_eq!(kind.canonical_type_name(), expected);
            assert_eq!(leaf(kind).canonical_type_name().as_deref(), Some(expected));
            let cursor = EntrypointValueTypeV1 {
                nodes: vec![EntrypointValueTypeNodeV1::StateCursor(leaf(kind))],
            };
            if kind == EntrypointValueKindV1::Json {
                assert_eq!(cursor.canonical_type_name(), None);
            } else {
                assert_eq!(
                    cursor.canonical_type_name(),
                    Some(format!("StateCursor<{expected}>"))
                );
            }
        }
    }

    #[test]
    fn terminal_atoms_match_only_their_exact_scalar_kind() {
        use crate::smart_contract::manifest::{
            ContractErrorTypeDescriptor, ContractErrorVariantDescriptor,
        };
        use EntrypointValueAtomV1 as Atom;
        use EntrypointValueTypeNodeV1 as Node;
        let error = ContractErrorTypeDescriptor {
            identity: "example/vault@1::Vault::VaultError".to_owned(),
            variants: vec![ContractErrorVariantDescriptor {
                name: "InvalidQuantity".to_owned(),
                code: 1,
            }],
        };
        let atoms = [
            Atom::Pointer(vec![1]),
            Atom::Bool(false),
            Atom::Unit,
            Atom::ErrorCode(1),
            Atom::ErrorCode(2),
            Atom::Tag(true),
            Atom::List(0),
        ];
        let mut nodes = vec![
            (Node::StateCursor(leaf(EntrypointValueKindV1::Int)), 0),
            (Node::Unit, 2),
            (Node::Error(error), 3),
        ];
        nodes.extend(
            [
                EntrypointValueKindV1::Int,
                EntrypointValueKindV1::Decimal,
                EntrypointValueKindV1::Quantity,
                EntrypointValueKindV1::Bool,
                EntrypointValueKindV1::String,
                EntrypointValueKindV1::Json,
                EntrypointValueKindV1::Name,
                EntrypointValueKindV1::AccountId,
                EntrypointValueKindV1::AssetDefinitionId,
                EntrypointValueKindV1::AssetId,
                EntrypointValueKindV1::DomainId,
                EntrypointValueKindV1::NftId,
                EntrypointValueKindV1::DataSpaceId,
                EntrypointValueKindV1::Blob,
            ]
            .into_iter()
            .map(|kind| (Node::Leaf(kind), usize::from(!kind.is_pointer()))),
        );
        for (node, accepted) in nodes {
            let schema = EntrypointValueTypeV1 {
                nodes: vec![node.clone()],
            };
            for (index, atom) in atoms.iter().enumerate() {
                let expected = index == accepted;
                assert_eq!(
                    entrypoint_atom_word_kind(&node, atom).is_some(),
                    expected,
                    "{node:?}: {atom:?}"
                );
                assert_eq!(schema.validate_atoms(std::slice::from_ref(atom)), expected);
                assert_eq!(
                    schema
                        .word_kinds_for_atoms(std::slice::from_ref(atom))
                        .is_some(),
                    expected
                );
            }
        }
        for node in [
            Node::Option,
            Node::Result,
            Node::Tuple(2),
            Node::List(EntrypointListTypeNodeV1 { capacity: 1 }),
        ] {
            for atom in &atoms {
                assert_eq!(entrypoint_atom_word_kind(&node, atom), None);
            }
        }
    }
}

#[cfg(test)]
mod captured_entrypoint_schema_tests;

#[cfg(test)]
mod frame_identity_tests;
