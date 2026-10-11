//! Borrowed manifest signing and durable-type projections over the original native graph.
//!
//! These views grant no validation or physical allocation authority. Callers retain their
//! original read/write owner while using them and supply its cumulative context for outputs.
#![allow(unsafe_code)]

use std::io::Write;

use norito::core::{BoundedEncodeError, DecodeBudgetContext, Encoder, Error, SerializePayload};

use super::{
    entrypoint::{
        EntrypointArgumentSchemaV1, EntrypointValueKindV1, EntrypointValueTypeV1,
        MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH,
    },
    manifest::{
        AccessSetHints, ContractEnumTypeDescriptorV1, ContractErrorMessage,
        ContractErrorTypeDescriptor, ContractEventDescriptorV1, ContractManifest,
        ContractManifestSignaturePayload, ContractPermissionDescriptorV1, EntryPointKind,
        EntrypointAuthorizationV1, EntrypointDescriptor, EntrypointParamDescriptor,
        KotobaTranslationEntry, StateDescriptor, TriggerDescriptor,
    },
};
use iroha_crypto::Hash;

/// Borrow an original native value without changing its payload codec.
pub struct BorrowedManifestValue<'a, T>(
    /// Original native value.
    pub &'a T,
);

impl<T: SerializePayload> SerializePayload for BorrowedManifestValue<'_, T> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        self.0.serialize(writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.0.encoded_len_hint()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.0.encoded_len_exact()
    }
}

/// Exact signing fields of one entrypoint, borrowing its original child allocations.
///
/// The executable PC is intentionally absent: it belongs to the CNTR execution interface.
#[derive(norito::derive::SerializePayload)]
pub struct EntrypointDescriptorView<'a> {
    /// Source symbol.
    pub name: &'a str,
    /// Logical entrypoint kind.
    pub kind: BorrowedManifestValue<'a, EntryPointKind>,
    /// Original ordered parameter descriptors.
    pub params: BorrowedManifestValue<'a, Vec<EntrypointParamDescriptor>>,
    /// Original argument schema, preserving absence.
    pub argument_schema: BorrowedManifestValue<'a, Option<EntrypointArgumentSchemaV1>>,
    /// Original return spelling, preserving absence.
    pub return_type: Option<&'a str>,
    /// Original return schema, preserving absence.
    pub return_schema: BorrowedManifestValue<'a, Option<EntrypointValueTypeV1>>,
    /// Original explicit dispatcher authorization.
    pub authorization: BorrowedManifestValue<'a, EntrypointAuthorizationV1>,
    /// Original ordered read hints.
    pub read_keys: BorrowedManifestValue<'a, Vec<String>>,
    /// Original ordered write hints.
    pub write_keys: BorrowedManifestValue<'a, Vec<String>>,
    /// Original completeness claim.
    pub access_hints_complete: Option<bool>,
    /// Original skipped-hint explanations.
    pub access_hints_skipped: BorrowedManifestValue<'a, Vec<String>>,
    /// Original trigger descriptors.
    pub triggers: BorrowedManifestValue<'a, Vec<TriggerDescriptor>>,
}

impl<'a> From<&'a EntrypointDescriptor> for EntrypointDescriptorView<'a> {
    fn from(entry: &'a EntrypointDescriptor) -> Self {
        let EntrypointDescriptor {
            name,
            kind,
            params,
            argument_schema,
            return_type,
            return_schema,
            authorization,
            read_keys,
            write_keys,
            access_hints_complete,
            access_hints_skipped,
            triggers,
        } = entry;
        Self {
            name,
            kind: BorrowedManifestValue(kind),
            params: BorrowedManifestValue(params),
            argument_schema: BorrowedManifestValue(argument_schema),
            return_type: return_type.as_deref(),
            return_schema: BorrowedManifestValue(return_schema),
            authorization: BorrowedManifestValue(authorization),
            read_keys: BorrowedManifestValue(read_keys),
            write_keys: BorrowedManifestValue(write_keys),
            access_hints_complete: *access_hints_complete,
            access_hints_skipped: BorrowedManifestValue(access_hints_skipped),
            triggers: BorrowedManifestValue(triggers),
        }
    }
}

impl EntrypointDescriptorView<'_> {
    /// Compare every signed entrypoint field without constructing an owned descriptor.
    pub fn same_content(&self, other: &EntrypointDescriptor) -> bool {
        self.name == other.name
            && self.kind.0 == &other.kind
            && self.params.0 == &other.params
            && self.argument_schema.0 == &other.argument_schema
            && self.return_type == other.return_type.as_deref()
            && self.return_schema.0 == &other.return_schema
            && self.authorization.0 == &other.authorization
            && self.read_keys.0 == &other.read_keys
            && self.write_keys.0 == &other.write_keys
            && self.access_hints_complete == other.access_hints_complete
            && self.access_hints_skipped.0 == &other.access_hints_skipped
            && self.triggers.0 == &other.triggers
    }
}

/// Borrow an indexed original entrypoint sequence, yielding only stack views.
pub trait ManifestEntrypointSequenceV1 {
    /// Number of entries in the original sequence.
    fn len(&self) -> usize;
    /// Whether the original sequence is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Borrow one descriptor; an inconsistent cardinality is a native encoding error.
    fn get(&self, index: usize) -> Option<EntrypointDescriptorView<'_>>;
}

impl ManifestEntrypointSequenceV1 for Vec<EntrypointDescriptor> {
    fn len(&self) -> usize {
        Vec::len(self)
    }
    fn get(&self, index: usize) -> Option<EntrypointDescriptorView<'_>> {
        self.as_slice()
            .get(index)
            .map(EntrypointDescriptorView::from)
    }
}

/// Native sequence adapter with no collected intermediate descriptors.
pub struct BorrowedEntrypoints<'a>(
    /// Original native sequence provider.
    pub &'a dyn ManifestEntrypointSequenceV1,
);
struct EntrypointIter<'a> {
    source: &'a dyn ManifestEntrypointSequenceV1,
    index: usize,
    len: usize,
}
impl<'a> Iterator for EntrypointIter<'a> {
    type Item = EntrypointDescriptorView<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.index == self.len {
            return None;
        }
        let item = self.source.get(self.index)?;
        self.index += 1;
        Some(item)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = self.len - self.index;
        (left, Some(left))
    }
}
impl ExactSizeIterator for EntrypointIter<'_> {}
impl SerializePayload for BorrowedEntrypoints<'_> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        norito::core::write_element_sequence::<EntrypointDescriptorView<'_>, _>(
            writer,
            EntrypointIter {
                source: self.0,
                index: 0,
                len: self.0.len(),
            },
        )
    }
}

/// One borrowed durable-state type node. Children remain owned by its original source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManifestStateTypeNodeV1<'a> {
    /// Unit state.
    Unit,
    /// Nominal error identity.
    Error(&'a str),
    /// Ordinary nominal enum identity, independent of the error catalog.
    Enum(&'a str),
    /// Canonical scalar state.
    Scalar(EntrypointValueKindV1),
    /// Ordered tuple children.
    Tuple(usize),
    /// Named product with this many ordered fields.
    Struct {
        /// Canonical source name.
        name: &'a str,
        /// Field count.
        fields: usize,
    },
    /// Key and value children, in that order.
    StateMap,
    /// One optional child.
    Option,
    /// Success and error children, in that order.
    Result,
    /// One element child and fixed V1 capacity.
    List(u8),
    /// Exact scalar or tuple cursor key schema.
    StateCursor(&'a super::entrypoint::EntrypointValueTypeV1),
}

/// Minimal borrowed adapter for a native durable-state type tree.
///
/// This is a projection interface, not an alternate schema decoder or validation capability.
pub trait ManifestStateTypeV1 {
    /// Borrow the current native node.
    fn node(&self) -> ManifestStateTypeNodeV1<'_>;
    /// Borrow an ordered child. Leaf nodes have no children.
    fn child(&self, index: usize) -> Option<&dyn ManifestStateTypeV1>;
    /// Borrow a named product's ordered field name.
    fn field_name(&self, index: usize) -> Option<&str>;
}

#[derive(Clone, Copy)]
struct TypeFrame<'a> {
    source: &'a dyn ManifestStateTypeV1,
    next: usize,
}

/// Allocation-free canonical state spelling, with one continuation per active depth.
#[derive(Clone, Copy)]
pub struct ManifestStateTypeNameV1<'a> {
    source: &'a dyn ManifestStateTypeV1,
}
impl<'a> ManifestStateTypeNameV1<'a> {
    /// Borrow an original native type. The source owner must remain alive for this view.
    pub const fn new(source: &'a dyn ManifestStateTypeV1) -> Self {
        Self { source }
    }
    /// Count exact UTF-8 bytes without allocating a name or schema vector.
    ///
    /// # Errors
    /// Returns length overflow, excessive depth, missing children or field names,
    /// or a non-canonical state cursor key from the original native tree.
    pub fn byte_len(&self) -> Result<usize, Error> {
        let mut size = 0usize;
        self.visit(|text| {
            size = size.checked_add(text.len()).ok_or(Error::LengthMismatch)?;
            Ok(())
        })?;
        Ok(size)
    }
    /// Stream the canonical spelling without constructing owned text.
    ///
    /// # Errors
    /// Returns the original destination error or refuses an excessive, incomplete
    /// or non-canonical native type tree. The destination may contain a prefix.
    pub fn write_raw(&self, writer: &mut dyn Write) -> Result<(), Error> {
        self.visit(|text| {
            writer.write_all(text.as_bytes())?;
            Ok(())
        })
    }
    /// Compare canonical spelling with an original manifest string without allocating.
    ///
    /// # Errors
    /// Rejects an excessive, incomplete or non-canonical native type tree.
    /// A different valid spelling is `Ok(false)`.
    pub fn same_text(&self, text: &str) -> Result<bool, Error> {
        let mut remaining = text.as_bytes();
        let mut same = true;
        self.visit(|part| {
            if let Some(tail) = remaining.strip_prefix(part.as_bytes()) {
                remaining = tail;
            } else {
                same = false;
            }
            Ok(())
        })?;
        Ok(same && remaining.is_empty())
    }
    /// Materialize exactly one charged string under the caller's original cumulative context.
    ///
    /// The context does not own the returned physical graph. The caller retains its original
    /// allocation owner through consumption or transfers that custody with the result.
    ///
    /// # Errors
    /// Returns the original decode-budget or physical-allocation refusal, length
    /// overflow, or an excessive, incomplete or non-canonical native type tree.
    pub fn materialize(&self, context: &DecodeBudgetContext) -> Result<String, Error> {
        context.with(|| {
            let len = self.byte_len()?;
            if len == 0 {
                return Ok(String::new());
            }
            let layout = std::alloc::Layout::array::<u8>(len).map_err(|_| Error::LengthMismatch)?;
            let bytes_u64 = u64::try_from(len).map_err(|_| Error::LengthMismatch)?;
            norito::core::reserve_decode_allocation(layout.size())?;
            // SAFETY: charge precedes the exact non-zero native allocation. Null is refused.
            let pointer = unsafe { std::alloc::alloc(layout) };
            if pointer.is_null() {
                return Err(Error::AllocationFailed { bytes: bytes_u64 });
            }
            // SAFETY: Vec owns the original exact byte allocation; no growth is permitted below.
            let mut bytes = unsafe { Vec::from_raw_parts(pointer, 0, len) };
            self.visit(|text| {
                if text.len() > len - bytes.len() {
                    return Err(Error::LengthMismatch);
                }
                bytes.extend_from_slice(text.as_bytes());
                Ok(())
            })?;
            if bytes.len() != len {
                return Err(Error::LengthMismatch);
            }
            // SAFETY: every initialized fragment is valid UTF-8, including stack decimal digits.
            Ok(unsafe { String::from_utf8_unchecked(bytes) })
        })
    }
    fn visit(&self, mut emit: impl FnMut(&str) -> Result<(), Error>) -> Result<(), Error> {
        let mut frames: [Option<TypeFrame<'_>>; MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH] =
            [None; MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH];
        let mut parents = 0usize;
        let mut current = self.source;
        loop {
            let node = current.node();
            let children = match node {
                ManifestStateTypeNodeV1::Unit => {
                    emit("()")?;
                    0
                }
                ManifestStateTypeNodeV1::Error(identity)
                | ManifestStateTypeNodeV1::Enum(identity) => {
                    emit(identity)?;
                    0
                }
                ManifestStateTypeNodeV1::Scalar(kind) => {
                    emit(kind.canonical_type_name())?;
                    0
                }
                ManifestStateTypeNodeV1::StateCursor(key) => {
                    emit("StateCursor<")?;
                    super::entrypoint::visit_state_key_type_v1(key, &mut emit)?;
                    emit(">")?;
                    0
                }
                ManifestStateTypeNodeV1::Tuple(len) => {
                    emit("(")?;
                    len
                }
                ManifestStateTypeNodeV1::Struct { name, fields } => {
                    emit(name)?;
                    emit("{")?;
                    fields
                }
                ManifestStateTypeNodeV1::StateMap => {
                    emit("StateMap<")?;
                    2
                }
                ManifestStateTypeNodeV1::Option => {
                    emit("Option<")?;
                    1
                }
                ManifestStateTypeNodeV1::Result => {
                    emit("Result<")?;
                    2
                }
                ManifestStateTypeNodeV1::List(_) => {
                    emit("List<")?;
                    1
                }
            };
            if children != 0 {
                if parents + 1 >= MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH {
                    return Err(Error::LengthMismatch);
                }
                before_child(current, node, 0, &mut emit)?;
                frames[parents] = Some(TypeFrame {
                    source: current,
                    next: 1,
                });
                parents += 1;
                current = current.child(0).ok_or(Error::LengthMismatch)?;
                continue;
            }
            close_node(node, &mut emit)?;
            loop {
                if parents == 0 {
                    return Ok(());
                }
                let frame = frames[parents - 1].as_mut().ok_or(Error::LengthMismatch)?;
                let node = frame.source.node();
                if frame.next < child_count(node) {
                    let index = frame.next;
                    frame.next += 1;
                    before_child(frame.source, node, index, &mut emit)?;
                    current = frame.source.child(index).ok_or(Error::LengthMismatch)?;
                    break;
                }
                close_node(node, &mut emit)?;
                parents -= 1;
                frames[parents] = None;
            }
        }
    }
}

fn child_count(node: ManifestStateTypeNodeV1<'_>) -> usize {
    match node {
        ManifestStateTypeNodeV1::Tuple(len) => len,
        ManifestStateTypeNodeV1::Struct { fields, .. } => fields,
        ManifestStateTypeNodeV1::StateMap | ManifestStateTypeNodeV1::Result => 2,
        ManifestStateTypeNodeV1::Option | ManifestStateTypeNodeV1::List(_) => 1,
        _ => 0,
    }
}
fn before_child(
    source: &dyn ManifestStateTypeV1,
    node: ManifestStateTypeNodeV1<'_>,
    index: usize,
    emit: &mut impl FnMut(&str) -> Result<(), Error>,
) -> Result<(), Error> {
    if index != 0 {
        emit(", ")?;
    }
    if matches!(node, ManifestStateTypeNodeV1::Struct { .. }) {
        emit(source.field_name(index).ok_or(Error::LengthMismatch)?)?;
        emit(": ")?;
    }
    Ok(())
}
fn close_node(
    node: ManifestStateTypeNodeV1<'_>,
    emit: &mut impl FnMut(&str) -> Result<(), Error>,
) -> Result<(), Error> {
    match node {
        ManifestStateTypeNodeV1::Tuple(_) => emit(")"),
        ManifestStateTypeNodeV1::Struct { .. } => emit("}"),
        ManifestStateTypeNodeV1::StateMap
        | ManifestStateTypeNodeV1::Option
        | ManifestStateTypeNodeV1::Result => emit(">"),
        ManifestStateTypeNodeV1::List(capacity) => {
            emit(", ")?;
            let digits = [
                b'0' + capacity / 100,
                b'0' + (capacity / 10) % 10,
                b'0' + capacity % 10,
            ];
            let start = if capacity >= 100 {
                0
            } else if capacity >= 10 {
                1
            } else {
                2
            };
            emit(std::str::from_utf8(&digits[start..]).map_err(|_| Error::NonCanonicalEncoding)?)?;
            emit(">")
        }
        _ => Ok(()),
    }
}

impl SerializePayload for ManifestStateTypeNameV1<'_> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        norito::core::write_len(
            writer,
            u64::try_from(self.byte_len()?).map_err(|_| Error::LengthMismatch)?,
        )?;
        self.write_raw(writer)
    }
}

/// Original stored spelling or a borrowed native type projection, with one String payload codec.
#[derive(Clone, Copy)]
pub enum ManifestTypeNameView<'a> {
    /// Borrow an already materialized canonical spelling.
    Text(&'a str),
    /// Stream a canonical spelling from the original native type tree.
    State(ManifestStateTypeNameV1<'a>),
}
impl ManifestTypeNameView<'_> {
    /// Compare this original spelling without constructing text.
    ///
    /// # Errors
    /// Rejects an excessive, incomplete or non-canonical projected state tree.
    /// A different valid spelling is `Ok(false)`.
    pub fn same_text(&self, text: &str) -> Result<bool, Error> {
        match self {
            Self::Text(original) => Ok(*original == text),
            Self::State(state) => state.same_text(text),
        }
    }
}
impl SerializePayload for ManifestTypeNameView<'_> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        match self {
            Self::Text(text) => text.serialize(writer),
            Self::State(state) => state.serialize(writer),
        }
    }
}

/// Borrow the exact two signed fields of one durable state descriptor.
#[derive(norito::derive::SerializePayload)]
pub struct StateDescriptorView<'a> {
    /// Original source symbol.
    pub name: &'a str,
    /// Original spelling or borrowed native type.
    pub type_name: ManifestTypeNameView<'a>,
}
impl<'a> From<&'a StateDescriptor> for StateDescriptorView<'a> {
    fn from(state: &'a StateDescriptor) -> Self {
        Self {
            name: &state.name,
            type_name: ManifestTypeNameView::Text(&state.type_name),
        }
    }
}
impl StateDescriptorView<'_> {
    /// Compare both signed fields without allocating a type name.
    ///
    /// # Errors
    /// Rejects an excessive, incomplete or non-canonical projected state tree
    /// when the source symbols match. Differing signed fields are `Ok(false)`.
    pub fn same_content(&self, state: &StateDescriptor) -> Result<bool, Error> {
        Ok(self.name == state.name && self.type_name.same_text(&state.type_name)?)
    }
}
/// Borrow an indexed original state sequence, yielding only stack views.
pub trait ManifestStateSequenceV1 {
    /// Number of entries in the original sequence.
    fn len(&self) -> usize;
    /// Whether the original sequence is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Borrow one descriptor; an inconsistent cardinality is a native encoding error.
    fn get(&self, index: usize) -> Option<StateDescriptorView<'_>>;
}
impl ManifestStateSequenceV1 for Vec<StateDescriptor> {
    fn len(&self) -> usize {
        Vec::len(self)
    }
    fn get(&self, index: usize) -> Option<StateDescriptorView<'_>> {
        self.as_slice().get(index).map(StateDescriptorView::from)
    }
}
/// Native state sequence adapter with no collected descriptors.
pub struct BorrowedStates<'a>(
    /// Original native sequence provider.
    pub &'a dyn ManifestStateSequenceV1,
);
struct StateIter<'a> {
    source: &'a dyn ManifestStateSequenceV1,
    index: usize,
    len: usize,
}
impl<'a> Iterator for StateIter<'a> {
    type Item = StateDescriptorView<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.index == self.len {
            return None;
        }
        let item = self.source.get(self.index)?;
        self.index += 1;
        Some(item)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = self.len - self.index;
        (left, Some(left))
    }
}
impl ExactSizeIterator for StateIter<'_> {}
impl SerializePayload for BorrowedStates<'_> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        norito::core::write_element_sequence::<StateDescriptorView<'_>, _>(
            writer,
            StateIter {
                source: self.0,
                index: 0,
                len: self.0.len(),
            },
        )
    }
}

/// Borrowed canonical signing fields with the original manifest-payload frame identity.
///
/// Only lifetimes parameterize this wire projection. It has no decoder and grants no admission.
#[derive(norito::derive::SerializePayload, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::smart_contract::manifest::ContractManifestSignaturePayloadView",
    frame = "iroha_data_model::smart_contract::manifest::ContractManifestSignaturePayload"
)]
pub struct ContractManifestSignaturePayloadView<'a> {
    /// Original seiyaku name and exact presence.
    pub seiyaku_name: Option<&'a str>,
    /// Complete native artifact identity.
    pub code_hash: Option<Hash>,
    /// Native ABI identity.
    pub abi_hash: Option<Hash>,
    /// Original compiler fingerprint and exact presence.
    pub compiler_fingerprint: Option<&'a str>,
    /// Original capability bits and exact presence.
    pub features_bitmap: Option<u64>,
    /// Original access hints and exact presence.
    pub access_set_hints: Option<BorrowedManifestValue<'a, AccessSetHints>>,
    /// Original authenticated permission declarations.
    pub permissions: BorrowedManifestValue<'a, Vec<ContractPermissionDescriptorV1>>,
    /// Original authenticated native event declarations.
    pub events: BorrowedManifestValue<'a, Vec<ContractEventDescriptorV1>>,
    /// Original projected entrypoints and exact presence.
    pub entrypoints: Option<BorrowedEntrypoints<'a>>,
    /// Original projected states and exact presence.
    pub states: Option<BorrowedStates<'a>>,
    /// Original nominal error types and exact presence.
    pub error_types: Option<BorrowedManifestValue<'a, Vec<ContractErrorTypeDescriptor>>>,
    /// Complete signed ordinary enum declaration inventory.
    pub enum_types: BorrowedManifestValue<'a, Vec<ContractEnumTypeDescriptorV1>>,
    /// Original static presentation messages and exact presence.
    pub error_messages: Option<BorrowedManifestValue<'a, Vec<ContractErrorMessage>>>,
    /// Original localization tables and exact presence.
    pub kotoba: Option<BorrowedManifestValue<'a, Vec<KotobaTranslationEntry>>>,
}

impl<'a> From<&'a ContractManifest> for ContractManifestSignaturePayloadView<'a> {
    fn from(manifest: &'a ContractManifest) -> Self {
        let ContractManifest {
            seiyaku_name,
            code_hash,
            abi_hash,
            compiler_fingerprint,
            features_bitmap,
            access_set_hints,
            permissions,
            events,
            entrypoints,
            states,
            error_types,
            enum_types,
            error_messages,
            kotoba,
            provenance: _,
        } = manifest;
        Self {
            seiyaku_name: seiyaku_name.as_deref(),
            code_hash: *code_hash,
            abi_hash: *abi_hash,
            compiler_fingerprint: compiler_fingerprint.as_deref(),
            features_bitmap: *features_bitmap,
            access_set_hints: access_set_hints.as_ref().map(BorrowedManifestValue),
            permissions: BorrowedManifestValue(permissions),
            events: BorrowedManifestValue(events),
            entrypoints: entrypoints.as_ref().map(|rows| BorrowedEntrypoints(rows)),
            states: states.as_ref().map(|rows| BorrowedStates(rows)),
            error_types: error_types.as_ref().map(BorrowedManifestValue),
            enum_types: BorrowedManifestValue(enum_types),
            error_messages: error_messages.as_ref().map(BorrowedManifestValue),
            kotoba: kotoba.as_ref().map(BorrowedManifestValue),
        }
    }
}

impl ContractManifestSignaturePayloadView<'_> {
    /// Stream the exact bounded canonical signing frame through the original native codec.
    ///
    /// No output buffer is allocated here. The caller owns the destination and retains source
    /// custody; discard that destination after any second-pass write or canonicality error.
    ///
    /// # Errors
    ///
    /// Returns the original native budget, serialization or destination error, or refuses an
    /// oversized complete frame before writing any destination bytes.
    pub fn write_canonical(
        &self,
        context: &DecodeBudgetContext,
        max_frame_bytes: usize,
        writer: &mut dyn Write,
    ) -> Result<(), BoundedEncodeError> {
        context.with(|| {
            if std::mem::align_of::<Self>()
                != std::mem::align_of::<ContractManifestSignaturePayload>()
            {
                return Err(Error::NonCanonicalEncoding.into());
            }
            let _canonical =
                norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
            let encoded_bytes = norito::canonical_frame_len(self)?;
            if encoded_bytes > max_frame_bytes {
                return Err(BoundedEncodeError::FrameTooLarge {
                    encoded_bytes,
                    max_bytes: max_frame_bytes,
                });
            }
            norito::core::write_canonical_to_writer(self, writer)?;
            Ok(())
        })
    }

    /// Encode one bounded, exact canonical signing frame under the original supplied context.
    ///
    /// Both passes borrow the same graph. The caller retains physical source/output custody;
    /// cumulative counters alone do not provide a release owner or capacity grant.
    ///
    /// # Errors
    /// Returns the original native budget, allocation or serialization refusal,
    /// rejects non-canonical alignment, or refuses a complete frame over the bound.
    pub fn to_bytes(
        &self,
        context: &DecodeBudgetContext,
        max_frame_bytes: usize,
    ) -> Result<Vec<u8>, BoundedEncodeError> {
        context.with(|| {
            // Framing padding belongs to the original owned wire type, including its alignment.
            if std::mem::align_of::<Self>()
                != std::mem::align_of::<ContractManifestSignaturePayload>()
            {
                return Err(Error::NonCanonicalEncoding.into());
            }
            let _canonical =
                norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
            norito::core::to_bytes_bounded(self, max_frame_bytes)
        })
    }
}

/// Signing refusal retaining the original native encoder or cryptographic error.
#[derive(Debug, thiserror::Error)]
pub enum ManifestSigningError {
    /// The supplied native encoding budget or canonical serializer refused the payload.
    #[error(transparent)]
    Encoding(#[from] BoundedEncodeError),
    /// The selected native cryptographic signer refused the payload.
    #[error(transparent)]
    Signing(#[from] iroha_crypto::Error),
}
