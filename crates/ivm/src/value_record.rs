//! Exact, privacy-safe decoding of completed public Kotodama result tables.
#![expect(
    clippy::result_large_err,
    reason = "Return decoding moves the original VM allocation refusal and retry owner by value; boxing this error would allocate on the memory-exhaustion path"
)]
use crate::{
    IVM, PointerType,
    codec::{decode_canonical_norito, encode_canonical_norito},
    list::ListLayoutV1,
    sum::SumLayoutV1,
};
use iroha_data_model::{
    account::AccountId,
    asset::{AssetDefinitionId, AssetId},
    nft::NftId,
    smart_contract::entrypoint::{
        ENTRYPOINT_RETURN_TLV_ENVELOPE_BYTES_V1, EntrypointReturnRecordV1, EntrypointValueAtomV1,
        EntrypointValueKindV1, EntrypointValueTypeNodeV1, EntrypointValueTypeV1,
        MAX_ENTRYPOINT_RETURN_RECORD_BYTES, MAX_ENTRYPOINT_RETURN_WORDS,
        entrypoint_return_schema_hash_v1, entrypoint_value_subtree_range_v1,
    },
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::{
    bigint::BigInt,
    json::Json,
    numeric_abi::{DecimalValueV1, IntValueV1, QuantityValueV1},
};
use norito::{
    codec::Encode,
    json::{self, Map, Value},
};
use std::str;
use thiserror::Error;
mod capture;
pub use capture::{
    CapturedArgumentRecord, CapturedValueRecord, ValueRecordCaptureQuote, capture_argument_record,
    capture_argument_record_funded, capture_completed_return_funded, capture_value_record,
    capture_value_record_funded, quote_argument_record, quote_completed_return_record,
    quote_value_record,
};
mod materialize;
pub use materialize::{
    install_captured_arguments, install_empty_captured_arguments, transfer_return_record_funded,
    validate_return_destination,
};
/// Failure to decode the exact public return value declared by an entrypoint.
#[derive(Debug, Error)]
pub enum EntrypointReturnDecodeError {
    /// The signed schema is malformed or exceeds the V1 result table boundary.
    #[error("invalid entrypoint return schema")]
    InvalidSchema,
    /// The root invocation has no successfully completed result table.
    #[error("contract root invocation did not complete a result table: {reason}")]
    IncompleteInvocation {
        /// VM completion-state failure, without exposing guest values.
        reason: crate::VMError,
    },
    /// The completed table does not have exactly the signed schema's width.
    #[error(
        "contract result table contains {actual_words} words; schema requires {expected_words}"
    )]
    WordCount {
        /// Width required by the signed schema.
        expected_words: usize,
        /// Initialized width recorded by the interpreter.
        actual_words: usize,
    },
    /// A nested return record is not bound to the exact signed return schema.
    #[error("nested contract return record does not match its exact schema")]
    SchemaBinding,
    /// The canonical record exceeds the single-call V1 boundary.
    #[error(
        "entrypoint return record requires at least {bytes} encoded bytes; maximum is {max_bytes}"
    )]
    RecordTooLarge {
        /// Exact encoded size, or a guaranteed lower bound detected before cloning.
        bytes: usize,
        /// Active encoded-record limit (the V1 cap or a lower caller-affordability bound).
        max_bytes: usize,
    },
    /// Canonical Norito encoding or decoding failed inside the bounded envelope.
    #[error("invalid canonical entrypoint return record: {reason}")]
    RecordEncoding {
        /// Stable codec failure detail.
        reason: String,
    },
    /// A return word or pointed TLV crosses the ZK privacy boundary.
    #[error("contract return violates the ZK privacy boundary at word {word_index}: {reason}")]
    Privacy {
        /// Result-table word which failed the public-boundary check.
        word_index: usize,
        /// Structured VM error rendered without exposing private data.
        reason: crate::VMError,
    },
    /// Local resource admission could not complete return collection.
    ///
    /// This is an unfinished local attempt, not malformed guest data. The
    /// original refusal retains its allocation pool and release observation.
    #[error("contract return collection deferred at word {word_index}: {reason}")]
    ExecutionDeferred {
        /// Result-table word whose access could not be admitted locally.
        word_index: usize,
        /// Original VM deferral, including its resource retry owner.
        reason: crate::VMError,
    },
    /// An Option/Result tag or boolean is not the canonical scalar zero or one.
    #[error(
        "contract return at word {word_index} has non-canonical {role} value {value}; expected 0 or 1"
    )]
    NonCanonicalBit {
        /// Result-table word containing the malformed bit.
        word_index: usize,
        /// Logical use of the bit.
        role: &'static str,
        /// Public malformed value.
        value: u64,
    },
    /// A public pointer has the wrong pointer-ABI type for the signed schema.
    #[error(
        "contract return at word {word_index} has pointer type {actual:?}; expected {expected:?}"
    )]
    PointerType {
        /// Result-table word containing the pointer.
        word_index: usize,
        /// Expected pointer-ABI type.
        expected: PointerType,
        /// Actual pointer-ABI type.
        actual: PointerType,
    },
    /// A typed public TLV payload is invalid or non-canonical.
    #[error("invalid {kind} contract return at word {word_index}: {reason}")]
    InvalidValue {
        /// Result-table word containing the value or pointer.
        word_index: usize,
        /// Human-readable signed schema kind.
        kind: &'static str,
        /// Stable failure detail.
        reason: String,
    },
}
struct ReturnRecordBudget {
    lower_bound_bytes: usize,
    max_bytes: usize,
    reservation: Option<iroha_allocation::AllocationReservation>,
    charges: Option<iroha_allocation::ChargedBuffer<iroha_allocation::AllocationCharge>>,
}
impl Default for ReturnRecordBudget {
    fn default() -> Self {
        Self::new(MAX_ENTRYPOINT_RETURN_RECORD_BYTES)
    }
}
impl ReturnRecordBudget {
    fn new(max_bytes: usize) -> Self {
        Self {
            // Every framed record necessarily contains the Norito header and
            // its 32-byte schema-binding hash before any atom payload.
            lower_bound_bytes: norito::core::Header::SIZE + iroha_crypto::Hash::LENGTH,
            max_bytes: max_bytes.min(MAX_ENTRYPOINT_RETURN_RECORD_BYTES),
            reservation: None,
            charges: None,
        }
    }
    fn copy_pointer(
        &mut self,
        bytes: &[u8],
        word_index: usize,
    ) -> Result<Vec<u8>, EntrypointReturnDecodeError> {
        if let Some(reservation) = self.reservation.as_mut() {
            let mut buffer =
                iroha_allocation::ChargedBuffer::from_reservation(bytes.len(), reservation)
                    .map_err(|error| {
                        handle_decode_error(
                            word_index,
                            "value capture",
                            capture::prepaid_error(error),
                        )
                    })?;
            for byte in bytes {
                buffer.push_reserved(*byte);
            }
            // SAFETY: the fixed exact pointer backing moves into one immutable record atom;
            // the same construction ledger follows that record until final destruction.
            #[allow(unsafe_code)]
            let (bytes, charge) = unsafe { buffer.into_allocation_parts() };
            if let Err(charge) = self
                .charges
                .as_mut()
                .expect("funded value capture ledger")
                .try_push(charge)
            {
                drop(bytes);
                drop(charge);
                return Err(handle_decode_error(
                    word_index,
                    "value capture",
                    crate::VMError::ExecutionDeferred(
                        crate::error::ExecutionDeferral::LocalInvariantViolation,
                    ),
                ));
            }
            Ok(bytes)
        } else {
            let mut owned = Vec::new();
            owned.try_reserve_exact(bytes.len()).map_err(|_| {
                handle_decode_error(
                    word_index,
                    "value capture",
                    crate::VMError::ExecutionDeferred(
                        crate::error::ExecutionDeferral::AllocationUnavailable,
                    ),
                )
            })?;
            owned.extend_from_slice(bytes);
            Ok(owned)
        }
    }
    fn reserve(&mut self, bytes: usize) -> Result<(), EntrypointReturnDecodeError> {
        let next = self.lower_bound_bytes.checked_add(bytes).ok_or(
            EntrypointReturnDecodeError::RecordTooLarge {
                bytes: usize::MAX,
                max_bytes: self.max_bytes,
            },
        )?;
        if next > self.max_bytes {
            return Err(EntrypointReturnDecodeError::RecordTooLarge {
                bytes: next,
                max_bytes: self.max_bytes,
            });
        }
        self.lower_bound_bytes = next;
        Ok(())
    }
    fn reserve_atom(&mut self) -> Result<(), EntrypointReturnDecodeError> {
        // Every encoded enum atom consumes at least one byte.
        self.reserve(1)
    }
    fn reserve_list_atom(&mut self) -> Result<(), EntrypointReturnDecodeError> {
        // The flat V1 list tape owns an enum discriminant and one encoded `u8`
        // item count before its schema-delimited items.
        self.reserve(2)
    }
    fn reserve_pointer(
        &mut self,
        payload_bytes: usize,
    ) -> Result<usize, EntrypointReturnDecodeError> {
        let envelope_bytes = ENTRYPOINT_RETURN_TLV_ENVELOPE_BYTES_V1
            .checked_add(payload_bytes)
            .ok_or(EntrypointReturnDecodeError::RecordTooLarge {
                bytes: usize::MAX,
                max_bytes: self.max_bytes,
            })?;
        // Charge the atom discriminant and the entire owned TLV before cloning.
        self.reserve(envelope_bytes.checked_add(1).ok_or(
            EntrypointReturnDecodeError::RecordTooLarge {
                bytes: usize::MAX,
                max_bytes: self.max_bytes,
            },
        )?)?;
        Ok(envelope_bytes)
    }
}
fn push_atom(
    atoms: &mut Vec<EntrypointValueAtomV1>,
    budget: &mut ReturnRecordBudget,
    atom: EntrypointValueAtomV1,
) -> Result<(), EntrypointReturnDecodeError> {
    budget.reserve_atom()?;
    atoms.push(atom);
    Ok(())
}
fn push_list_header(
    atoms: &mut Vec<EntrypointValueAtomV1>,
    budget: &mut ReturnRecordBudget,
    item_count: usize,
) -> Result<(), EntrypointReturnDecodeError> {
    let item_count =
        u8::try_from(item_count).map_err(|_| EntrypointReturnDecodeError::InvalidSchema)?;
    budget.reserve_list_atom()?;
    atoms.push(EntrypointValueAtomV1::List(item_count));
    Ok(())
}
struct ResultTableCursor<'vm, 'budget> {
    vm: &'vm IVM,
    live_base: Option<u64>,
    word_index: usize,
    budget: &'budget mut ReturnRecordBudget,
}
impl ResultTableCursor<'_, '_> {
    fn public_scalar(&mut self) -> Result<(usize, u64), EntrypointReturnDecodeError> {
        let word_index = self.word_index;
        let value = if let Some(base) = self.live_base {
            let offset = u64::try_from(word_index)
                .ok()
                .and_then(|index| index.checked_mul(8))
                .and_then(|offset| base.checked_add(offset))
                .ok_or(EntrypointReturnDecodeError::InvalidSchema)?;
            self.vm.load_u64(offset)
        } else {
            self.vm.public_call_result_word(word_index)
        }
        .map_err(|error| handle_decode_error(word_index, "value table", error))?;
        self.word_index = self.word_index.saturating_add(1);
        Ok((word_index, value))
    }
}
fn decode_canonical<T>(
    payload: &[u8],
    word_index: usize,
    kind: &'static str,
) -> Result<T, EntrypointReturnDecodeError>
where
    T: for<'__frame> norito::NoritoDeserialize<'__frame> + norito::NoritoSerialize,
{
    decode_canonical_norito(payload).map_err(|error| EntrypointReturnDecodeError::InvalidValue {
        word_index,
        kind,
        reason: error.to_string(),
    })
}
fn expected_pointer_type(kind: EntrypointValueKindV1) -> Option<PointerType> {
    Some(match kind {
        EntrypointValueKindV1::Int => PointerType::Int,
        EntrypointValueKindV1::Decimal => PointerType::Decimal,
        EntrypointValueKindV1::Quantity => PointerType::Quantity,
        EntrypointValueKindV1::Bool => return None,
        EntrypointValueKindV1::String | EntrypointValueKindV1::Blob => PointerType::Blob,
        EntrypointValueKindV1::Json => PointerType::Json,
        EntrypointValueKindV1::Name => PointerType::Name,
        EntrypointValueKindV1::AccountId => PointerType::AccountId,
        EntrypointValueKindV1::AssetDefinitionId => PointerType::AssetDefinitionId,
        EntrypointValueKindV1::AssetId => PointerType::AssetId,
        EntrypointValueKindV1::DomainId => PointerType::DomainId,
        EntrypointValueKindV1::NftId => PointerType::NftId,
        EntrypointValueKindV1::DataSpaceId => PointerType::DataSpaceId,
    })
}
fn kind_name(kind: EntrypointValueKindV1) -> &'static str {
    match kind {
        EntrypointValueKindV1::Int => "int",
        EntrypointValueKindV1::Decimal => "decimal",
        EntrypointValueKindV1::Quantity => "quantity",
        EntrypointValueKindV1::Bool => "bool",
        EntrypointValueKindV1::String => "string",
        EntrypointValueKindV1::Json => "Json",
        EntrypointValueKindV1::Name => "Name",
        EntrypointValueKindV1::AccountId => "AccountId",
        EntrypointValueKindV1::AssetDefinitionId => "AssetDefinitionId",
        EntrypointValueKindV1::AssetId => "AssetId",
        EntrypointValueKindV1::DomainId => "DomainId",
        EntrypointValueKindV1::NftId => "NftId",
        EntrypointValueKindV1::DataSpaceId => "DataSpaceId",
        EntrypointValueKindV1::Blob => "bytes",
    }
}
fn validate_pointer_payload(
    kind: EntrypointValueKindV1,
    payload: &[u8],
    word_index: usize,
) -> Result<(), EntrypointReturnDecodeError> {
    match kind {
        EntrypointValueKindV1::Bool => {
            return Err(EntrypointReturnDecodeError::InvalidSchema);
        }
        EntrypointValueKindV1::Int => {
            IntValueV1::decode_frame(payload)
                .map(drop)
                .map_err(|error| EntrypointReturnDecodeError::InvalidValue {
                    word_index,
                    kind: "int",
                    reason: error.to_string(),
                })?
        }
        EntrypointValueKindV1::Decimal => {
            DecimalValueV1::decode_frame(payload)
                .map(drop)
                .map_err(|error| EntrypointReturnDecodeError::InvalidValue {
                    word_index,
                    kind: "decimal",
                    reason: error.to_string(),
                })?
        }
        EntrypointValueKindV1::Quantity => QuantityValueV1::decode_frame(payload)
            .map(drop)
            .map_err(|error| EntrypointReturnDecodeError::InvalidValue {
                word_index,
                kind: "quantity",
                reason: error.to_string(),
            })?,
        EntrypointValueKindV1::String => {
            str::from_utf8(payload).map_err(|error| EntrypointReturnDecodeError::InvalidValue {
                word_index,
                kind: "string",
                reason: error.to_string(),
            })?;
        }
        EntrypointValueKindV1::Json => {
            let _: Json = decode_canonical(payload, word_index, "Json")?;
        }
        EntrypointValueKindV1::Name => {
            let _: Name = decode_canonical(payload, word_index, "Name")?;
        }
        EntrypointValueKindV1::AccountId => {
            let _: AccountId = decode_canonical(payload, word_index, "AccountId")?;
        }
        EntrypointValueKindV1::AssetDefinitionId => {
            let _: AssetDefinitionId = decode_canonical(payload, word_index, "AssetDefinitionId")?;
        }
        EntrypointValueKindV1::AssetId => {
            let _: AssetId = decode_canonical(payload, word_index, "AssetId")?;
        }
        EntrypointValueKindV1::DomainId => {
            let _: DomainId = decode_canonical(payload, word_index, "DomainId")?;
        }
        EntrypointValueKindV1::NftId => {
            let _: NftId = decode_canonical(payload, word_index, "NftId")?;
        }
        EntrypointValueKindV1::DataSpaceId => {
            let _: DataSpaceId = decode_canonical(payload, word_index, "DataSpaceId")?;
        }
        EntrypointValueKindV1::Blob => {}
    }
    Ok(())
}
fn handle_decode_error(
    word_index: usize,
    kind: &'static str,
    error: crate::VMError,
) -> EntrypointReturnDecodeError {
    if error.execution_deferral().is_some() {
        EntrypointReturnDecodeError::ExecutionDeferred {
            word_index,
            reason: error,
        }
    } else if error == crate::VMError::PrivacyViolation {
        EntrypointReturnDecodeError::Privacy {
            word_index,
            reason: error,
        }
    } else {
        EntrypointReturnDecodeError::InvalidValue {
            word_index,
            kind,
            reason: error.to_string(),
        }
    }
}
impl EntrypointReturnDecodeError {
    /// Preserve a VM privacy or local refusal while classifying a public table access.
    pub fn from_vm_error(word_index: usize, kind: &'static str, error: crate::VMError) -> Self {
        handle_decode_error(word_index, kind, error)
    }
    /// Recover the nested-call VM failure before local attempt classification.
    ///
    /// Local resource refusals and privacy failures retain their original VM
    /// reason. Only the caller's lower gas-affordability record bound becomes
    /// out-of-gas; malformed values and the protocol size cap remain decode errors.
    pub fn into_nested_vm_error(self) -> crate::VMError {
        match self {
            Self::ExecutionDeferred { reason, .. } | Self::Privacy { reason, .. } => reason,
            Self::RecordTooLarge { max_bytes, .. }
                if max_bytes < MAX_ENTRYPOINT_RETURN_RECORD_BYTES =>
            {
                crate::VMError::OutOfGas
            }
            _ => crate::VMError::DecodeError,
        }
    }
}

fn list_shape_error(word_index: usize, reason: impl Into<String>) -> EntrypointReturnDecodeError {
    EntrypointReturnDecodeError::InvalidValue {
        word_index,
        kind: "List",
        reason: reason.into(),
    }
}
fn return_node_child_count(node: &EntrypointValueTypeNodeV1) -> usize {
    match node {
        EntrypointValueTypeNodeV1::Struct(node) => node.fields.len(),
        EntrypointValueTypeNodeV1::Tuple(arity) => usize::from(*arity),
        EntrypointValueTypeNodeV1::Option | EntrypointValueTypeNodeV1::List(_) => 1,
        EntrypointValueTypeNodeV1::Result => 2,
        EntrypointValueTypeNodeV1::Leaf(_)
        | EntrypointValueTypeNodeV1::Unit
        | EntrypointValueTypeNodeV1::Error(_)
        | EntrypointValueTypeNodeV1::Enum(_)
        | EntrypointValueTypeNodeV1::StateCursor(_) => 0,
    }
}
/// Take exactly one checked preorder subtree and advance the shared cursor.
///
/// The schema has a hard V1 node bound, but this iterative walk also avoids
/// making native stack depth part of boundary validation. In particular, a
/// `List` owns the one element subtree immediately following its list node.
fn take_return_subtree<'a>(
    nodes: &'a [EntrypointValueTypeNodeV1],
    node_index: &mut usize,
) -> Result<&'a [EntrypointValueTypeNodeV1], EntrypointReturnDecodeError> {
    let start = *node_index;
    let range = entrypoint_value_subtree_range_v1(nodes, start)
        .ok_or(EntrypointReturnDecodeError::InvalidSchema)?;
    let end = range.end;
    let subtree = nodes
        .get(range)
        .ok_or(EntrypointReturnDecodeError::InvalidSchema)?;
    *node_index = end;
    Ok(subtree)
}
fn return_child_starts(
    nodes: &[EntrypointValueTypeNodeV1],
    node_start: usize,
    child_count: usize,
) -> Result<Vec<usize>, EntrypointReturnDecodeError> {
    let root = entrypoint_value_subtree_range_v1(nodes, node_start)
        .ok_or(EntrypointReturnDecodeError::InvalidSchema)?;
    let mut child = node_start
        .checked_add(1)
        .ok_or(EntrypointReturnDecodeError::InvalidSchema)?;
    let mut starts = Vec::with_capacity(child_count);
    for _ in 0..child_count {
        starts.push(child);
        child = entrypoint_value_subtree_range_v1(nodes, child)
            .ok_or(EntrypointReturnDecodeError::InvalidSchema)?
            .end;
    }
    if child != root.end {
        return Err(EntrypointReturnDecodeError::InvalidSchema);
    }
    Ok(starts)
}
fn return_node_word_count(
    nodes: &[EntrypointValueTypeNodeV1],
    node_index: &mut usize,
) -> Result<usize, EntrypointReturnDecodeError> {
    let subtree = take_return_subtree(nodes, node_index)?;
    let mut rendered = Vec::with_capacity(subtree.len());
    for node in subtree.iter().rev() {
        let child_count = return_node_child_count(node);
        if rendered.len() < child_count {
            return Err(EntrypointReturnDecodeError::InvalidSchema);
        }
        let children = rendered.split_off(rendered.len() - child_count);
        let words = match node {
            EntrypointValueTypeNodeV1::Struct(node) if node.fields.is_empty() => 1,
            EntrypointValueTypeNodeV1::Struct(_) | EntrypointValueTypeNodeV1::Tuple(_) => children
                .into_iter()
                .try_fold(0_usize, usize::checked_add)
                .ok_or(EntrypointReturnDecodeError::InvalidSchema)?,
            EntrypointValueTypeNodeV1::Option
            | EntrypointValueTypeNodeV1::Result
            | EntrypointValueTypeNodeV1::List(_)
            | EntrypointValueTypeNodeV1::Leaf(_)
            | EntrypointValueTypeNodeV1::Unit
            | EntrypointValueTypeNodeV1::Error(_)
            | EntrypointValueTypeNodeV1::Enum(_)
            | EntrypointValueTypeNodeV1::StateCursor(_) => 1,
        };
        rendered.push(words);
    }
    (rendered.len() == 1)
        .then(|| rendered[0])
        .ok_or(EntrypointReturnDecodeError::InvalidSchema)
}
fn nominal_scalar_atom(
    node: &EntrypointValueTypeNodeV1,
    word: u64,
) -> Result<EntrypointValueAtomV1, EntrypointReturnDecodeError> {
    match node {
        EntrypointValueTypeNodeV1::Unit if word == 0 => Ok(EntrypointValueAtomV1::Unit),
        EntrypointValueTypeNodeV1::Error(error) => {
            let code =
                u32::try_from(word).map_err(|_| EntrypointReturnDecodeError::InvalidSchema)?;
            error
                .variant(code)
                .ok_or(EntrypointReturnDecodeError::InvalidSchema)?;
            Ok(EntrypointValueAtomV1::ErrorCode(code))
        }
        EntrypointValueTypeNodeV1::Enum(descriptor) => {
            let code =
                u32::try_from(word).map_err(|_| EntrypointReturnDecodeError::InvalidSchema)?;
            descriptor
                .variant(code)
                .ok_or(EntrypointReturnDecodeError::InvalidSchema)?;
            Ok(EntrypointValueAtomV1::EnumCode(code))
        }
        _ => Err(EntrypointReturnDecodeError::InvalidSchema),
    }
}
fn collect_cursor_pointer(
    vm: &IVM,
    pointer: u64,
    word_index: usize,
    key: &iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1,
    atoms: &mut Vec<EntrypointValueAtomV1>,
    budget: &mut ReturnRecordBudget,
) -> Result<(), EntrypointReturnDecodeError> {
    let tlv = vm
        .validate_tlv(pointer)
        .map_err(|error| handle_decode_error(word_index, "StateCursor", error))?;
    if tlv.type_id != PointerType::NoritoBytes {
        return Err(EntrypointReturnDecodeError::PointerType {
            word_index,
            expected: PointerType::NoritoBytes,
            actual: tlv.type_id,
        });
    }
    // Reserve the entire owned envelope before cloning attacker-controlled bytes.
    let bytes = budget.reserve_pointer(tlv.payload.len())?;
    let envelope = vm
        .memory
        .load_region(
            pointer,
            u64::try_from(bytes).map_err(|_| EntrypointReturnDecodeError::InvalidSchema)?,
        )
        .map_err(|error| handle_decode_error(word_index, "StateCursor", error))?;
    crate::state_cursor::validate_cursor_envelope(
        iroha_data_model::smart_contract::entrypoint::state_key_schema_hash_v1(key)
            .ok_or(EntrypointReturnDecodeError::InvalidSchema)?,
        envelope,
    )
    .map_err(|error| handle_decode_error(word_index, "StateCursor", error))?;
    atoms.push(EntrypointValueAtomV1::Pointer(
        budget.copy_pointer(envelope, word_index)?,
    ));
    Ok(())
}
fn collect_leaf_from_words(
    vm: &IVM,
    words: &[u64],
    payload_word_index: &mut usize,
    word_index: usize,
    kind: EntrypointValueKindV1,
    atoms: &mut Vec<EntrypointValueAtomV1>,
    budget: &mut ReturnRecordBudget,
) -> Result<(), EntrypointReturnDecodeError> {
    let word = *words
        .get(*payload_word_index)
        .ok_or_else(|| list_shape_error(word_index, "list item is missing an active word"))?;
    *payload_word_index = payload_word_index.saturating_add(1);
    match kind {
        EntrypointValueKindV1::Bool => {
            let value = match word {
                0 => false,
                1 => true,
                value => {
                    return Err(EntrypointReturnDecodeError::NonCanonicalBit {
                        word_index,
                        role: "bool",
                        value,
                    });
                }
            };
            push_atom(atoms, budget, EntrypointValueAtomV1::Bool(value))?;
        }
        pointer_kind => {
            if word == 0 {
                return Err(list_shape_error(
                    word_index,
                    "list item contains a null typed pointer",
                ));
            }
            let expected = expected_pointer_type(pointer_kind)
                .ok_or(EntrypointReturnDecodeError::InvalidSchema)?;
            let tlv = vm
                .validate_tlv(word)
                .map_err(|error| handle_decode_error(word_index, "List", error))?;
            if tlv.type_id != expected {
                return Err(EntrypointReturnDecodeError::PointerType {
                    word_index,
                    expected,
                    actual: tlv.type_id,
                });
            }
            let expected_envelope_bytes = budget.reserve_pointer(tlv.payload.len())?;
            validate_pointer_payload(pointer_kind, tlv.payload, word_index)?;
            let envelope = vm
                .memory
                .load_region(
                    word,
                    u64::try_from(expected_envelope_bytes)
                        .map_err(|_| EntrypointReturnDecodeError::InvalidSchema)?,
                )
                .map_err(|error| handle_decode_error(word_index, "List", error))?;
            let envelope = budget.copy_pointer(envelope, word_index)?;
            if envelope.len() != expected_envelope_bytes {
                return Err(list_shape_error(
                    word_index,
                    "validated list-item TLV length changed while cloning",
                ));
            }
            atoms.push(EntrypointValueAtomV1::Pointer(envelope));
        }
    }
    Ok(())
}
fn collect_node(
    nodes: &[EntrypointValueTypeNodeV1],
    node_index: &mut usize,
    cursor: &mut ResultTableCursor<'_, '_>,
    atoms: &mut Vec<EntrypointValueAtomV1>,
) -> Result<(), EntrypointReturnDecodeError> {
    use iroha_data_model::smart_contract::entrypoint::MAX_ENTRYPOINT_ARGUMENT_TYPE_NODES;
    #[derive(Clone, Copy)]
    enum Source {
        Result,
        Memory { base: u64, word_index: usize },
    }
    #[derive(Clone, Copy)]
    struct Visit {
        node: usize,
        source: Source,
        remaining: u64,
        stride: u64,
    }
    fn next(
        source: Source,
        cursor: &mut ResultTableCursor<'_, '_>,
    ) -> Result<(usize, u64), EntrypointReturnDecodeError> {
        match source {
            Source::Result => cursor.public_scalar(),
            Source::Memory { base, word_index } => {
                cursor
                    .vm
                    .ensure_public_memory(base, 8)
                    .map_err(|error| handle_decode_error(word_index, "value", error))?;
                let value = cursor
                    .vm
                    .load_u64(base)
                    .map_err(|error| handle_decode_error(word_index, "value", error))?;
                Ok((word_index, value))
            }
        }
    }
    let root = *node_index;
    let root_end = entrypoint_value_subtree_range_v1(nodes, root)
        .ok_or(EntrypointReturnDecodeError::InvalidSchema)?
        .end;
    if nodes.len() > MAX_ENTRYPOINT_ARGUMENT_TYPE_NODES {
        return Err(EntrypointReturnDecodeError::InvalidSchema);
    }
    let mut widths = [0usize; MAX_ENTRYPOINT_ARGUMENT_TYPE_NODES];
    for index in (root..root_end).rev() {
        widths[index] = if matches!(
            &nodes[index],
            EntrypointValueTypeNodeV1::Struct(_) | EntrypointValueTypeNodeV1::Tuple(_)
        ) {
            let mut child = index + 1;
            let mut total = 0usize;
            for _ in 0..return_node_child_count(&nodes[index]) {
                total = total
                    .checked_add(widths[child])
                    .ok_or(EntrypointReturnDecodeError::InvalidSchema)?;
                child = entrypoint_value_subtree_range_v1(nodes, child)
                    .ok_or(EntrypointReturnDecodeError::InvalidSchema)?
                    .end;
            }
            total.max(1)
        } else {
            1
        };
    }
    let mut pending = [Visit {
        node: 0,
        source: Source::Result,
        remaining: 0,
        stride: 0,
    }; MAX_ENTRYPOINT_ARGUMENT_TYPE_NODES * 2];
    pending[0] = Visit {
        node: root,
        source: Source::Result,
        remaining: 1,
        stride: 0,
    };
    let mut len = 1usize;
    while len != 0 {
        len -= 1;
        let visit = pending[len];
        if visit.remaining > 1 {
            let Source::Memory { base, word_index } = visit.source else {
                return Err(EntrypointReturnDecodeError::InvalidSchema);
            };
            pending[len] = Visit {
                source: Source::Memory {
                    base: base
                        .checked_add(visit.stride)
                        .ok_or(EntrypointReturnDecodeError::InvalidSchema)?,
                    word_index,
                },
                remaining: visit.remaining - 1,
                ..visit
            };
            len += 1;
        }
        match &nodes[visit.node] {
            node @ (EntrypointValueTypeNodeV1::Struct(_) | EntrypointValueTypeNodeV1::Tuple(_)) => {
                let count = return_node_child_count(node);
                if count == 0 {
                    let (word_index, word) = next(visit.source, cursor)?;
                    if word != 0 {
                        return Err(EntrypointReturnDecodeError::InvalidValue {
                            word_index,
                            kind: "empty struct",
                            reason: "empty struct requires the canonical zero Unit word".into(),
                        });
                    }
                    continue;
                }
                let start = len;
                let mut child = visit.node + 1;
                let mut offset = 0u64;
                for _ in 0..count {
                    let source = match visit.source {
                        Source::Result => Source::Result,
                        Source::Memory { base, word_index } => Source::Memory {
                            base: base
                                .checked_add(offset)
                                .ok_or(EntrypointReturnDecodeError::InvalidSchema)?,
                            word_index,
                        },
                    };
                    *pending
                        .get_mut(len)
                        .ok_or(EntrypointReturnDecodeError::InvalidSchema)? = Visit {
                        node: child,
                        source,
                        remaining: 1,
                        stride: 0,
                    };
                    len += 1;
                    offset = offset
                        .checked_add(
                            (widths[child] as u64)
                                .checked_mul(8)
                                .ok_or(EntrypointReturnDecodeError::InvalidSchema)?,
                        )
                        .ok_or(EntrypointReturnDecodeError::InvalidSchema)?;
                    child = entrypoint_value_subtree_range_v1(nodes, child)
                        .ok_or(EntrypointReturnDecodeError::InvalidSchema)?
                        .end;
                }
                pending[start..len].reverse();
            }
            node @ (EntrypointValueTypeNodeV1::Option | EntrypointValueTypeNodeV1::Result) => {
                let (word_index, pointer) = next(visit.source, cursor)?;
                let first = visit.node + 1;
                let option = matches!(node, EntrypointValueTypeNodeV1::Option);
                let kind = if option { "Option" } else { "Result" };
                if pointer == 0 {
                    return Err(EntrypointReturnDecodeError::InvalidValue {
                        word_index,
                        kind,
                        reason: "sum handle is null".into(),
                    });
                }
                let second = entrypoint_value_subtree_range_v1(nodes, first)
                    .ok_or(EntrypointReturnDecodeError::InvalidSchema)?
                    .end;
                let layout = if option {
                    SumLayoutV1::option(widths[first] as u64)
                } else {
                    SumLayoutV1::try_new(widths[second] as u64, widths[first] as u64)
                }
                .map_err(|_| EntrypointReturnDecodeError::InvalidSchema)?;
                let (tag, _) = crate::sum::validate_active_words(cursor.vm, pointer, layout)
                    .map_err(|error| handle_decode_error(word_index, kind, error))?;
                cursor
                    .vm
                    .ensure_public_memory(
                        pointer,
                        layout
                            .allocation_bytes()
                            .map_err(|_| EntrypointReturnDecodeError::InvalidSchema)?,
                    )
                    .map_err(|error| handle_decode_error(word_index, kind, error))?;
                push_atom(atoms, cursor.budget, EntrypointValueAtomV1::Tag(tag))?;
                if !option || tag {
                    *pending
                        .get_mut(len)
                        .ok_or(EntrypointReturnDecodeError::InvalidSchema)? = Visit {
                        node: if tag { first } else { second },
                        source: Source::Memory {
                            base: pointer
                                .checked_add(8)
                                .ok_or(EntrypointReturnDecodeError::InvalidSchema)?,
                            word_index,
                        },
                        remaining: 1,
                        stride: 0,
                    };
                    len += 1;
                }
            }
            EntrypointValueTypeNodeV1::List(list) => {
                let (word_index, pointer) = next(visit.source, cursor)?;
                let element = visit.node + 1;
                let layout =
                    ListLayoutV1::try_new(u64::from(list.capacity), widths[element] as u64)
                        .map_err(|_| EntrypointReturnDecodeError::InvalidSchema)?;
                let count = crate::list::len(cursor.vm, pointer, layout)
                    .map_err(|error| handle_decode_error(word_index, "List", error))?;
                cursor
                    .vm
                    .ensure_public_memory(pointer, 16)
                    .map_err(|error| handle_decode_error(word_index, "List", error))?;
                push_list_header(atoms, cursor.budget, count as usize)?;
                if count != 0 {
                    let base = pointer
                        .checked_add(
                            layout
                                .slot_offset(0)
                                .map_err(|_| EntrypointReturnDecodeError::InvalidSchema)?,
                        )
                        .ok_or(EntrypointReturnDecodeError::InvalidSchema)?;
                    *pending
                        .get_mut(len)
                        .ok_or(EntrypointReturnDecodeError::InvalidSchema)? = Visit {
                        node: element,
                        source: Source::Memory { base, word_index },
                        remaining: count,
                        stride: (widths[element] as u64) * 8,
                    };
                    len += 1;
                }
            }
            EntrypointValueTypeNodeV1::StateCursor(key) => {
                let (word_index, pointer) = next(visit.source, cursor)?;
                collect_cursor_pointer(cursor.vm, pointer, word_index, key, atoms, cursor.budget)?;
            }
            node @ (EntrypointValueTypeNodeV1::Unit
            | EntrypointValueTypeNodeV1::Error(_)
            | EntrypointValueTypeNodeV1::Enum(_)) => {
                let (_, word) = next(visit.source, cursor)?;
                push_atom(atoms, cursor.budget, nominal_scalar_atom(node, word)?)?;
            }
            EntrypointValueTypeNodeV1::Leaf(kind) => {
                let (word_index, word) = next(visit.source, cursor)?;
                collect_leaf_from_words(
                    cursor.vm,
                    &[word],
                    &mut 0,
                    word_index,
                    *kind,
                    atoms,
                    cursor.budget,
                )?;
            }
        }
    }
    *node_index = root_end;
    Ok(())
}
fn schema_hash(schema: &EntrypointValueTypeV1) -> Result<[u8; 32], EntrypointReturnDecodeError> {
    let schema =
        encode_canonical_norito(schema).map_err(|_| EntrypointReturnDecodeError::InvalidSchema)?;
    Ok(entrypoint_return_schema_hash_v1(&schema))
}
fn exact_record_bytes(
    record: &EntrypointReturnRecordV1,
    max_bytes: usize,
) -> Result<Vec<u8>, EntrypointReturnDecodeError> {
    let max_bytes = max_bytes.min(MAX_ENTRYPOINT_RETURN_RECORD_BYTES);
    // The bare length walk allocates no output buffer. It prevents an already
    // materialized adversarial record from forcing an oversized framed encode.
    let bare_bytes = {
        let _canonical_flags =
            norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        record.encoded_len()
    };
    if bare_bytes > max_bytes {
        return Err(EntrypointReturnDecodeError::RecordTooLarge {
            bytes: bare_bytes,
            max_bytes,
        });
    }
    let encoded = encode_canonical_norito(record).map_err(|error| {
        EntrypointReturnDecodeError::RecordEncoding {
            reason: error.to_string(),
        }
    })?;
    if encoded.len() > max_bytes {
        return Err(EntrypointReturnDecodeError::RecordTooLarge {
            bytes: encoded.len(),
            max_bytes,
        });
    }
    Ok(encoded)
}
fn collect_entrypoint_return_record(
    vm: &IVM,
    schema: &EntrypointValueTypeV1,
    max_bytes: usize,
) -> Result<EntrypointReturnRecordV1, EntrypointReturnDecodeError> {
    let words = schema
        .word_count()
        .filter(|words| *words <= MAX_ENTRYPOINT_RETURN_WORDS)
        .ok_or(EntrypointReturnDecodeError::InvalidSchema)?;
    let actual_words = vm
        .call_result_word_count()
        .map_err(|reason| EntrypointReturnDecodeError::IncompleteInvocation { reason })?;
    if actual_words != words {
        return Err(EntrypointReturnDecodeError::WordCount {
            expected_words: words,
            actual_words,
        });
    }
    let mut budget = ReturnRecordBudget::new(max_bytes);
    let mut cursor = ResultTableCursor {
        vm,
        live_base: None,
        word_index: 0,
        budget: &mut budget,
    };
    let mut node_index = 0_usize;
    let mut atoms = Vec::with_capacity(words);
    collect_node(&schema.nodes, &mut node_index, &mut cursor, &mut atoms)?;
    let actual_words = cursor.word_index;
    let actual_kinds = schema
        .word_kinds_for_atoms(&atoms)
        .ok_or(EntrypointReturnDecodeError::InvalidSchema)?;
    if node_index != schema.nodes.len()
        || actual_words != words
        || actual_kinds.len() != actual_words
    {
        return Err(EntrypointReturnDecodeError::InvalidSchema);
    }
    let record = EntrypointReturnRecordV1 {
        schema_hash: schema_hash(schema)?,
        atoms,
    };
    Ok(record)
}
/// Validate all completed public result-table words and build the canonical typed record.
///
/// The full framed Norito length is validated even though this API returns the
/// structured record. Use [`encode_entrypoint_return_record_bytes`] when the
/// caller needs wire bytes and wants to avoid encoding the record twice.
///
/// # Errors
/// Returns an error for malformed schemas, private values, non-canonical
/// tags/booleans, malformed typed pointer payloads, or a record over 1 MiB.
/// Local memory admission failures retain the original execution deferral.
pub fn encode_entrypoint_return_record(
    vm: &IVM,
    schema: &EntrypointValueTypeV1,
) -> Result<EntrypointReturnRecordV1, EntrypointReturnDecodeError> {
    let record = collect_entrypoint_return_record(vm, schema, MAX_ENTRYPOINT_RETURN_RECORD_BYTES)?;
    let _ = exact_record_bytes(&record, MAX_ENTRYPOINT_RETURN_RECORD_BYTES)?;
    Ok(record)
}
/// Validate completed public result-table words and encode one bounded canonical record.
///
/// # Errors
/// Returns the same failures as [`encode_entrypoint_return_record`].
pub fn encode_entrypoint_return_record_bytes(
    vm: &IVM,
    schema: &EntrypointValueTypeV1,
) -> Result<Vec<u8>, EntrypointReturnDecodeError> {
    encode_entrypoint_return_record_bytes_bounded(vm, schema, MAX_ENTRYPOINT_RETURN_RECORD_BYTES)
}
/// Validate completed public result-table words and encode a canonical record without
/// cloning pointer payloads beyond `max_bytes`.
///
/// This is used by nested-call dispatch after converting the caller's gas
/// escrow into an affordable response-byte bound.
pub fn encode_entrypoint_return_record_bytes_bounded(
    vm: &IVM,
    schema: &EntrypointValueTypeV1,
    max_bytes: usize,
) -> Result<Vec<u8>, EntrypointReturnDecodeError> {
    let record = collect_entrypoint_return_record(vm, schema, max_bytes)?;
    exact_record_bytes(&record, max_bytes)
}
fn pointer_payload(
    atom: &EntrypointValueAtomV1,
    kind: EntrypointValueKindV1,
    word_index: usize,
) -> Result<&[u8], EntrypointReturnDecodeError> {
    let EntrypointValueAtomV1::Pointer(envelope) = atom else {
        return Err(EntrypointReturnDecodeError::InvalidValue {
            word_index,
            kind: kind_name(kind),
            reason: "expected a typed pointer atom".to_owned(),
        });
    };
    let tlv = crate::pointer_abi::validate_tlv_bytes(envelope).map_err(|error| {
        EntrypointReturnDecodeError::InvalidValue {
            word_index,
            kind: kind_name(kind),
            reason: error.to_string(),
        }
    })?;
    let expected = expected_pointer_type(kind).ok_or(EntrypointReturnDecodeError::InvalidSchema)?;
    if tlv.type_id != expected {
        return Err(EntrypointReturnDecodeError::PointerType {
            word_index,
            expected,
            actual: tlv.type_id,
        });
    }
    validate_pointer_payload(kind, tlv.payload, word_index)?;
    Ok(tlv.payload)
}
fn int_json_value(value: &BigInt) -> Value {
    Value::from(value.to_string())
}
fn render_leaf(
    atoms: &[EntrypointValueAtomV1],
    atom_index: &mut usize,
    kind: EntrypointValueKindV1,
    word_index: usize,
) -> Result<Value, EntrypointReturnDecodeError> {
    let atom = atoms
        .get(*atom_index)
        .ok_or(EntrypointReturnDecodeError::InvalidSchema)?;
    *atom_index = atom_index.saturating_add(1);
    match (kind, atom) {
        (EntrypointValueKindV1::Bool, EntrypointValueAtomV1::Bool(value)) => {
            Ok(Value::Bool(*value))
        }
        (pointer_kind, EntrypointValueAtomV1::Pointer(_)) if pointer_kind.is_pointer() => {
            let payload = pointer_payload(atom, pointer_kind, word_index)?;
            Ok(match pointer_kind {
                EntrypointValueKindV1::Int => {
                    let value = IntValueV1::decode_frame(payload)
                        .map(IntValueV1::into_int)
                        .map_err(|error| EntrypointReturnDecodeError::InvalidValue {
                            word_index,
                            kind: "int",
                            reason: error.to_string(),
                        })?;
                    int_json_value(&value)
                }
                EntrypointValueKindV1::Decimal => {
                    let value = DecimalValueV1::decode_frame(payload)
                        .map(DecimalValueV1::into_numeric)
                        .map_err(|error| EntrypointReturnDecodeError::InvalidValue {
                            word_index,
                            kind: "decimal",
                            reason: error.to_string(),
                        })?;
                    Value::from(value.to_string())
                }
                EntrypointValueKindV1::Quantity => {
                    let value = QuantityValueV1::decode_frame(payload)
                        .map(QuantityValueV1::into_quantity)
                        .map_err(|error| EntrypointReturnDecodeError::InvalidValue {
                            word_index,
                            kind: "quantity",
                            reason: error.to_string(),
                        })?;
                    Value::from(value.to_string())
                }
                EntrypointValueKindV1::String => Value::from(
                    str::from_utf8(payload)
                        .map_err(|error| EntrypointReturnDecodeError::InvalidValue {
                            word_index,
                            kind: "string",
                            reason: error.to_string(),
                        })?
                        .to_owned(),
                ),
                EntrypointValueKindV1::Json => {
                    let value: Json = decode_canonical(payload, word_index, "Json")?;
                    json::parse_value(value.get()).map_err(|error| {
                        EntrypointReturnDecodeError::InvalidValue {
                            word_index,
                            kind: "Json",
                            reason: error.to_string(),
                        }
                    })?
                }
                EntrypointValueKindV1::Name => {
                    Value::from(decode_canonical::<Name>(payload, word_index, "Name")?.to_string())
                }
                EntrypointValueKindV1::AccountId => Value::from(
                    decode_canonical::<AccountId>(payload, word_index, "AccountId")?.to_string(),
                ),
                EntrypointValueKindV1::AssetDefinitionId => Value::from(
                    decode_canonical::<AssetDefinitionId>(
                        payload,
                        word_index,
                        "AssetDefinitionId",
                    )?
                    .to_string(),
                ),
                EntrypointValueKindV1::AssetId => Value::from(
                    decode_canonical::<AssetId>(payload, word_index, "AssetId")?.to_string(),
                ),
                EntrypointValueKindV1::DomainId => Value::from(
                    decode_canonical::<DomainId>(payload, word_index, "DomainId")?.to_string(),
                ),
                EntrypointValueKindV1::NftId => Value::from(
                    decode_canonical::<NftId>(payload, word_index, "NftId")?.to_string(),
                ),
                EntrypointValueKindV1::DataSpaceId => Value::from(
                    decode_canonical::<DataSpaceId>(payload, word_index, "DataSpaceId")?.as_u64(),
                ),
                EntrypointValueKindV1::Blob => Value::from(format!("0x{}", hex::encode(payload))),
                EntrypointValueKindV1::Bool => {
                    return Err(EntrypointReturnDecodeError::InvalidSchema);
                }
            })
        }
        _ => Err(EntrypointReturnDecodeError::InvalidValue {
            word_index,
            kind: kind_name(kind),
            reason: "atom kind does not match the exact schema".to_owned(),
        }),
    }
}
fn render_node(
    nodes: &[EntrypointValueTypeNodeV1],
    atoms: &[EntrypointValueAtomV1],
    node_index: &mut usize,
    atom_index: &mut usize,
) -> Result<Value, EntrypointReturnDecodeError> {
    enum ProductKind<'a> {
        Struct(&'a [String]),
        Tuple,
    }
    enum Continuation<'a> {
        Product {
            kind: ProductKind<'a>,
            child_starts: Vec<usize>,
            next_child: usize,
            next_word_index: usize,
            nested: bool,
            values: Vec<Value>,
        },
        Wrap {
            key: &'static str,
        },
        List {
            element_start: usize,
            next_item: usize,
            item_count: usize,
            word_index: usize,
            values: Vec<Value>,
        },
    }
    #[derive(Clone, Copy)]
    struct Visit {
        node_start: usize,
        atom_start: usize,
        word_index: usize,
        nested: bool,
    }
    fn following_word_index(
        nodes: &[EntrypointValueTypeNodeV1],
        child: usize,
        word_index: usize,
        nested: bool,
    ) -> Result<usize, EntrypointReturnDecodeError> {
        if nested {
            return Ok(word_index);
        }
        let mut end = child;
        word_index
            .checked_add(return_node_word_count(nodes, &mut end)?)
            .ok_or(EntrypointReturnDecodeError::InvalidSchema)
    }
    let root_start = *node_index;
    let root_end = entrypoint_value_subtree_range_v1(nodes, root_start)
        .ok_or(EntrypointReturnDecodeError::InvalidSchema)?
        .end;
    let mut current = Some(Visit {
        node_start: root_start,
        atom_start: *atom_index,
        word_index: 0,
        nested: false,
    });
    let mut continuations = Vec::<Continuation<'_>>::new();
    let mut completed = None::<(Value, usize)>;
    loop {
        if let Some(visit) = current.take() {
            let node = nodes
                .get(visit.node_start)
                .ok_or(EntrypointReturnDecodeError::InvalidSchema)?;
            match node {
                EntrypointValueTypeNodeV1::Struct(node) => {
                    let starts = return_child_starts(nodes, visit.node_start, node.fields.len())?;
                    let Some(first) = starts.first().copied() else {
                        completed = Some((Value::Object(Map::new()), visit.atom_start));
                        continue;
                    };
                    continuations.push(Continuation::Product {
                        kind: ProductKind::Struct(&node.fields),
                        child_starts: starts,
                        next_child: 1,
                        next_word_index: following_word_index(
                            nodes,
                            first,
                            visit.word_index,
                            visit.nested,
                        )?,
                        nested: visit.nested,
                        values: Vec::with_capacity(node.fields.len()),
                    });
                    current = Some(Visit {
                        node_start: first,
                        atom_start: visit.atom_start,
                        word_index: visit.word_index,
                        nested: visit.nested,
                    });
                }
                EntrypointValueTypeNodeV1::Tuple(arity) => {
                    let count = usize::from(*arity);
                    let starts = return_child_starts(nodes, visit.node_start, count)?;
                    let Some(first) = starts.first().copied() else {
                        completed = Some((Value::Array(Vec::new()), visit.atom_start));
                        continue;
                    };
                    continuations.push(Continuation::Product {
                        kind: ProductKind::Tuple,
                        child_starts: starts,
                        next_child: 1,
                        next_word_index: following_word_index(
                            nodes,
                            first,
                            visit.word_index,
                            visit.nested,
                        )?,
                        nested: visit.nested,
                        values: Vec::with_capacity(count),
                    });
                    current = Some(Visit {
                        node_start: first,
                        atom_start: visit.atom_start,
                        word_index: visit.word_index,
                        nested: visit.nested,
                    });
                }
                EntrypointValueTypeNodeV1::Option => {
                    let word_index = visit.word_index;
                    let Some(EntrypointValueAtomV1::Tag(tag)) = atoms.get(visit.atom_start) else {
                        return Err(EntrypointReturnDecodeError::InvalidValue {
                            word_index,
                            kind: "Option",
                            reason: "expected a canonical tag atom".to_owned(),
                        });
                    };
                    let next_atom = visit
                        .atom_start
                        .checked_add(1)
                        .ok_or(EntrypointReturnDecodeError::InvalidSchema)?;
                    if *tag {
                        continuations.push(Continuation::Wrap { key: "some" });
                        current = Some(Visit {
                            node_start: visit
                                .node_start
                                .checked_add(1)
                                .ok_or(EntrypointReturnDecodeError::InvalidSchema)?,
                            atom_start: next_atom,
                            word_index: visit.word_index,
                            nested: true,
                        });
                    } else {
                        completed = Some((
                            Value::Object(Map::from_iter([("none".to_owned(), Value::Bool(true))])),
                            next_atom,
                        ));
                    }
                }
                EntrypointValueTypeNodeV1::Result => {
                    let word_index = visit.word_index;
                    let Some(EntrypointValueAtomV1::Tag(tag)) = atoms.get(visit.atom_start) else {
                        return Err(EntrypointReturnDecodeError::InvalidValue {
                            word_index,
                            kind: "Result",
                            reason: "expected a canonical tag atom".to_owned(),
                        });
                    };
                    let ok_start = visit
                        .node_start
                        .checked_add(1)
                        .ok_or(EntrypointReturnDecodeError::InvalidSchema)?;
                    let err_start = entrypoint_value_subtree_range_v1(nodes, ok_start)
                        .ok_or(EntrypointReturnDecodeError::InvalidSchema)?
                        .end;
                    continuations.push(Continuation::Wrap {
                        key: if *tag { "ok" } else { "err" },
                    });
                    current = Some(Visit {
                        node_start: if *tag { ok_start } else { err_start },
                        atom_start: visit
                            .atom_start
                            .checked_add(1)
                            .ok_or(EntrypointReturnDecodeError::InvalidSchema)?,
                        word_index: visit.word_index,
                        nested: true,
                    });
                }
                EntrypointValueTypeNodeV1::List(list) => {
                    let word_index = visit.word_index;
                    let Some(EntrypointValueAtomV1::List(item_count)) = atoms.get(visit.atom_start)
                    else {
                        return Err(EntrypointReturnDecodeError::InvalidValue {
                            word_index,
                            kind: "List",
                            reason: "expected a canonical list atom".to_owned(),
                        });
                    };
                    let item_count = usize::from(*item_count);
                    if item_count > usize::from(list.capacity) {
                        return Err(EntrypointReturnDecodeError::InvalidValue {
                            word_index,
                            kind: "List",
                            reason: "list payload exceeds its schema capacity".to_owned(),
                        });
                    }
                    let element_start = visit
                        .node_start
                        .checked_add(1)
                        .ok_or(EntrypointReturnDecodeError::InvalidSchema)?;
                    let _ = entrypoint_value_subtree_range_v1(nodes, element_start)
                        .ok_or(EntrypointReturnDecodeError::InvalidSchema)?;
                    let first_item_atom = visit
                        .atom_start
                        .checked_add(1)
                        .ok_or(EntrypointReturnDecodeError::InvalidSchema)?;
                    if item_count == 0 {
                        completed = Some((Value::Array(Vec::new()), first_item_atom));
                        continue;
                    }
                    continuations.push(Continuation::List {
                        element_start,
                        next_item: 1,
                        item_count,
                        word_index: visit.word_index,
                        values: Vec::with_capacity(item_count),
                    });
                    current = Some(Visit {
                        node_start: element_start,
                        atom_start: first_item_atom,
                        word_index: visit.word_index,
                        nested: true,
                    });
                }
                EntrypointValueTypeNodeV1::StateCursor(key) => {
                    let Some(EntrypointValueAtomV1::Pointer(envelope)) =
                        atoms.get(visit.atom_start)
                    else {
                        return Err(EntrypointReturnDecodeError::InvalidSchema);
                    };
                    let word_index = visit.word_index;
                    crate::state_cursor::validate_cursor_envelope(
                        iroha_data_model::smart_contract::entrypoint::state_key_schema_hash_v1(key)
                            .ok_or(EntrypointReturnDecodeError::InvalidSchema)?,
                        envelope,
                    )
                    .map_err(|error| handle_decode_error(word_index, "StateCursor", error))?;
                    let tlv = crate::pointer_abi::validate_tlv_bytes(envelope)
                        .map_err(|error| handle_decode_error(word_index, "StateCursor", error))?;
                    completed = Some((
                        Value::String(format!("0x{}", hex::encode(tlv.payload))),
                        visit.atom_start + 1,
                    ));
                }
                EntrypointValueTypeNodeV1::Unit => {
                    if !matches!(
                        atoms.get(visit.atom_start),
                        Some(EntrypointValueAtomV1::Unit)
                    ) {
                        return Err(EntrypointReturnDecodeError::InvalidSchema);
                    }
                    completed = Some((Value::Null, visit.atom_start + 1));
                }
                EntrypointValueTypeNodeV1::Error(error) => {
                    let Some(EntrypointValueAtomV1::ErrorCode(code)) = atoms.get(visit.atom_start)
                    else {
                        return Err(EntrypointReturnDecodeError::InvalidSchema);
                    };
                    let variant = error
                        .variant(*code)
                        .ok_or(EntrypointReturnDecodeError::InvalidSchema)?;
                    completed = Some((Value::String(variant.name.clone()), visit.atom_start + 1));
                }
                EntrypointValueTypeNodeV1::Enum(descriptor) => {
                    let Some(EntrypointValueAtomV1::EnumCode(code)) = atoms.get(visit.atom_start)
                    else {
                        return Err(EntrypointReturnDecodeError::InvalidSchema);
                    };
                    let variant = descriptor
                        .variant(*code)
                        .ok_or(EntrypointReturnDecodeError::InvalidSchema)?;
                    completed = Some((Value::String(variant.name.clone()), visit.atom_start + 1));
                }
                EntrypointValueTypeNodeV1::Leaf(kind) => {
                    let mut next_atom = visit.atom_start;
                    let value = render_leaf(atoms, &mut next_atom, *kind, visit.word_index)?;
                    completed = Some((value, next_atom));
                }
            }
            continue;
        }
        let (value, child_atom_end) = completed
            .take()
            .ok_or(EntrypointReturnDecodeError::InvalidSchema)?;
        let Some(continuation) = continuations.pop() else {
            *node_index = root_end;
            *atom_index = child_atom_end;
            return Ok(value);
        };
        match continuation {
            Continuation::Product {
                kind,
                child_starts,
                mut next_child,
                next_word_index,
                nested,
                mut values,
            } => {
                values.push(value);
                if let Some(next_start) = child_starts.get(next_child).copied() {
                    next_child = next_child
                        .checked_add(1)
                        .ok_or(EntrypointReturnDecodeError::InvalidSchema)?;
                    continuations.push(Continuation::Product {
                        kind,
                        child_starts,
                        next_child,
                        next_word_index: following_word_index(
                            nodes,
                            next_start,
                            next_word_index,
                            nested,
                        )?,
                        nested,
                        values,
                    });
                    current = Some(Visit {
                        node_start: next_start,
                        atom_start: child_atom_end,
                        word_index: next_word_index,
                        nested,
                    });
                } else {
                    completed = Some((
                        match kind {
                            ProductKind::Struct(fields) => {
                                if fields.len() != values.len() {
                                    return Err(EntrypointReturnDecodeError::InvalidSchema);
                                }
                                Value::Object(Map::from_iter(fields.iter().cloned().zip(values)))
                            }
                            ProductKind::Tuple => Value::Array(values),
                        },
                        child_atom_end,
                    ));
                }
            }
            Continuation::Wrap { key } => {
                completed = Some((
                    Value::Object(Map::from_iter([(key.to_owned(), value)])),
                    child_atom_end,
                ));
            }
            Continuation::List {
                element_start,
                mut next_item,
                item_count,
                word_index,
                mut values,
            } => {
                values.push(value);
                if next_item < item_count {
                    next_item = next_item
                        .checked_add(1)
                        .ok_or(EntrypointReturnDecodeError::InvalidSchema)?;
                    continuations.push(Continuation::List {
                        element_start,
                        next_item,
                        item_count,
                        word_index,
                        values,
                    });
                    current = Some(Visit {
                        node_start: element_start,
                        atom_start: child_atom_end,
                        word_index,
                        nested: true,
                    });
                } else {
                    completed = Some((Value::Array(values), child_atom_end));
                }
            }
        }
    }
}
fn render_entrypoint_return_record_validated(
    schema: &EntrypointValueTypeV1,
    record: &EntrypointReturnRecordV1,
) -> Result<Value, EntrypointReturnDecodeError> {
    let words = schema
        .word_count()
        .filter(|words| *words <= MAX_ENTRYPOINT_RETURN_WORDS)
        .ok_or(EntrypointReturnDecodeError::InvalidSchema)?;
    let actual_words = schema
        .word_kinds_for_atoms(&record.atoms)
        .ok_or(EntrypointReturnDecodeError::SchemaBinding)?;
    if actual_words.len() != words {
        return Err(EntrypointReturnDecodeError::SchemaBinding);
    }
    if record.schema_hash != schema_hash(schema)? {
        return Err(EntrypointReturnDecodeError::SchemaBinding);
    }
    let mut node_index = 0_usize;
    let mut atom_index = 0_usize;
    let value = render_node(
        &schema.nodes,
        &record.atoms,
        &mut node_index,
        &mut atom_index,
    )?;
    if node_index != schema.nodes.len() || atom_index != record.atoms.len() {
        return Err(EntrypointReturnDecodeError::InvalidSchema);
    }
    Ok(value)
}
/// Render a canonical nested return record for a client-facing JSON boundary.
///
/// # Errors
/// Returns an error when the record is oversized, not schema-bound, or atom kinds differ.
pub fn render_entrypoint_return_record(
    schema: &EntrypointValueTypeV1,
    record: &EntrypointReturnRecordV1,
) -> Result<Value, EntrypointReturnDecodeError> {
    let _ = exact_record_bytes(record, MAX_ENTRYPOINT_RETURN_RECORD_BYTES)?;
    render_entrypoint_return_record_validated(schema, record)
}
/// Decode and validate one canonical schema-bound nested return record.
///
/// The byte limit is enforced before Norito decoding. The decoded value is
/// re-encoded byte-for-byte so trailing data, alternate layouts, and malformed
/// inactive branches fail closed before any client-facing rendering.
///
/// # Errors
/// Returns an error for oversized or non-canonical bytes, schema mismatch, or invalid typed atoms.
pub fn decode_entrypoint_return_record(
    schema: &EntrypointValueTypeV1,
    payload: &[u8],
) -> Result<EntrypointReturnRecordV1, EntrypointReturnDecodeError> {
    if payload.len() > MAX_ENTRYPOINT_RETURN_RECORD_BYTES {
        return Err(EntrypointReturnDecodeError::RecordTooLarge {
            bytes: payload.len(),
            max_bytes: MAX_ENTRYPOINT_RETURN_RECORD_BYTES,
        });
    }
    let record: EntrypointReturnRecordV1 = decode_canonical_norito(payload).map_err(|error| {
        EntrypointReturnDecodeError::RecordEncoding {
            reason: error.to_string(),
        }
    })?;
    if exact_record_bytes(&record, MAX_ENTRYPOINT_RETURN_RECORD_BYTES)?.as_slice() != payload {
        return Err(EntrypointReturnDecodeError::RecordEncoding {
            reason: "record is not the byte-exact canonical Norito encoding".to_owned(),
        });
    }
    let _ = render_entrypoint_return_record_validated(schema, &record)?;
    Ok(record)
}
/// Decode a completed schema-bound result table for Torii/CLI JSON output.
///
/// Only the active `Option`/`Result` branch is read. Runtime-to-runtime calls should use
/// [`encode_entrypoint_return_record`] and keep the wire representation typed.
///
/// # Errors
/// Returns an error for malformed schemas, non-canonical words, private
/// values/TLVs, schema-binding failures, or typed decode failures. Local memory
/// admission failures retain the original execution deferral.
pub fn decode_entrypoint_return(
    vm: &IVM,
    schema: &EntrypointValueTypeV1,
) -> Result<Value, EntrypointReturnDecodeError> {
    let record = collect_entrypoint_return_record(vm, schema, MAX_ENTRYPOINT_RETURN_RECORD_BYTES)?;
    let _ = exact_record_bytes(&record, MAX_ENTRYPOINT_RETURN_RECORD_BYTES)?;
    render_entrypoint_return_record_validated(schema, &record)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::IVMHost;
    use iroha_crypto::Hash;
    use iroha_data_model::smart_contract::entrypoint::{
        EntrypointListTypeNodeV1, EntrypointStructTypeNodeV1, MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH,
    };
    use iroha_primitives::numeric::Quantity;

    fn return_program(words: usize) -> Vec<u8> {
        assert!(words > 0);
        let value = if words == 1 {
            "()".to_owned()
        } else {
            format!("({})", vec!["()"; words].join(", "))
        };
        let source = format!(
            "seiyaku ReturnTable {{ view fn main() authorize(anyone) -> {value} {{ {value} }} }}"
        );
        kotodama_lang::compiler::Compiler::new()
            .compile_source(&source)
            .expect("compile authenticated Unit result table")
    }

    fn load_return_program(vm: &mut IVM, words: usize) {
        let program = return_program(words);
        let metadata = crate::ProgramMetadata::parse(&program).expect("parse result-table fixture");
        let entry = metadata
            .contract_interface
            .as_ref()
            .unwrap()
            .entrypoints
            .iter()
            .find(|entry| entry.name == "main")
            .unwrap();
        let entry_pc = metadata.prefix_len() as u64 + entry.entry_pc;
        vm.load_program(&program)
            .expect("load result-table fixture");
        vm.set_program_counter(entry_pc)
            .expect("select authenticated root entrypoint");
    }

    fn completed_return_vm(words: usize) -> IVM {
        let mut vm = IVM::new(1_000_000);
        load_return_program(&mut vm, words);
        vm.run().expect("complete root result table");
        assert_eq!(vm.call_result_word_count().unwrap(), words);
        vm
    }

    fn set_result_word(vm: &mut IVM, word_index: usize, word: u64) {
        assert!(word_index < vm.call_result_word_count().unwrap());
        // Trusted host mutation after a real successful root call exercises
        // malformed decoder inputs without forging interpreter completion.
        vm.store_u64(vm.register(10) + 8 * word_index as u64, word)
            .expect("write completed result-table fixture");
    }

    #[test]
    fn result_collection_requires_successful_completion_and_exact_table_width() {
        let schema = leaf(EntrypointValueKindV1::Bool);
        let mut unstarted = IVM::new(1_000_000);
        load_return_program(&mut unstarted, 1);
        unstarted.set_register(10, 1);
        assert!(matches!(
            decode_entrypoint_return(&unstarted, &schema),
            Err(EntrypointReturnDecodeError::IncompleteInvocation { .. })
        ));
        let mut failed = IVM::new(0);
        load_return_program(&mut failed, 1);
        assert!(failed.run().is_err());
        assert!(matches!(
            decode_entrypoint_return(&failed, &schema),
            Err(EntrypointReturnDecodeError::IncompleteInvocation { .. })
        ));
        let wider = completed_return_vm(3);
        assert!(matches!(
            decode_entrypoint_return(&wider, &schema),
            Err(EntrypointReturnDecodeError::WordCount {
                expected_words: 1,
                actual_words: 3,
            })
        ));
        let narrow = completed_return_vm(1);
        assert!(matches!(
            decode_entrypoint_return(&narrow, &nested_schema()),
            Err(EntrypointReturnDecodeError::WordCount {
                expected_words: 3,
                actual_words: 1,
            })
        ));
    }

    #[test]
    fn completed_table_ignores_register_descriptors_and_reports_word_indices() {
        let mut vm = completed_return_vm(1);
        let schema = leaf(EntrypointValueKindV1::Bool);
        set_result_word(&mut vm, 0, 1);
        let table = vm.register(10);
        vm.set_register(10, u64::MAX);
        vm.set_register(11, 0);
        assert_eq!(
            decode_entrypoint_return(&vm, &schema).unwrap(),
            Value::Bool(true)
        );
        vm.store_u64(table, 2).unwrap();
        let error = decode_entrypoint_return(&vm, &schema).unwrap_err();
        assert!(matches!(
            error,
            EntrypointReturnDecodeError::NonCanonicalBit {
                word_index: 0,
                role: "bool",
                value: 2,
            }
        ));
        assert!(error.to_string().contains("at word 0"));
    }

    #[test]
    fn nested_record_diagnostics_keep_the_owning_result_word_index() {
        let schema = EntrypointValueTypeV1 {
            nodes: vec![
                EntrypointValueTypeNodeV1::Tuple(3),
                EntrypointValueTypeNodeV1::Option,
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::String),
                EntrypointValueTypeNodeV1::List(EntrypointListTypeNodeV1 { capacity: 2 }),
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::String),
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::String),
            ],
        };
        let text = EntrypointValueAtomV1::Pointer(test_tlv(PointerType::Blob, b"public"));
        let record = EntrypointReturnRecordV1 {
            schema_hash: schema_hash(&schema).unwrap(),
            atoms: vec![
                EntrypointValueAtomV1::Tag(true),
                text.clone(),
                EntrypointValueAtomV1::List(2),
                text.clone(),
                text.clone(),
                text,
            ],
        };
        for (atom_index, expected_word) in [(1, 0), (4, 1), (5, 2)] {
            let mut malformed = record.clone();
            malformed.atoms[atom_index] =
                EntrypointValueAtomV1::Pointer(test_tlv(PointerType::Blob, &[0xFF]));
            assert!(matches!(
                render_entrypoint_return_record(&schema, &malformed),
                Err(EntrypointReturnDecodeError::InvalidValue { word_index, kind: "string", .. })
                if word_index == expected_word
            ));
        }
    }

    #[test]
    fn public_result_table_can_exceed_the_retired_register_window() {
        let vm = completed_return_vm(64);
        let mut nodes = vec![EntrypointValueTypeNodeV1::Tuple(64)];
        nodes.extend(vec![EntrypointValueTypeNodeV1::Unit; 64]);
        let schema = EntrypointValueTypeV1 { nodes };
        let record = encode_entrypoint_return_record(&vm, &schema).unwrap();
        assert_eq!(record.atoms, vec![EntrypointValueAtomV1::Unit; 64]);
        assert_eq!(
            decode_entrypoint_return(&vm, &schema).unwrap(),
            Value::Array(vec![Value::Null; 64])
        );
    }
    fn empty_struct_node() -> EntrypointValueTypeNodeV1 {
        EntrypointValueTypeNodeV1::Struct(EntrypointStructTypeNodeV1 {
            name: "Fixture::Empty".to_owned(),
            fields: Vec::new(),
        })
    }

    #[test]
    fn empty_named_struct_consumes_a_canonical_unit_slot_without_record_atoms() {
        let schema = EntrypointValueTypeV1 {
            nodes: vec![empty_struct_node()],
        };
        assert_eq!(schema.word_count(), Some(1));
        let mut vm = completed_return_vm(1);
        let record = encode_entrypoint_return_record(&vm, &schema).unwrap();
        assert!(record.atoms.is_empty());
        assert_eq!(
            decode_entrypoint_return(&vm, &schema).unwrap(),
            norito::json!({})
        );
        set_result_word(&mut vm, 0, 1);
        assert!(matches!(
            decode_entrypoint_return(&vm, &schema),
            Err(EntrypointReturnDecodeError::InvalidValue {
                word_index: 0,
                kind: "empty struct",
                ..
            })
        ));

        let schema = EntrypointValueTypeV1 {
            nodes: vec![
                EntrypointValueTypeNodeV1::Tuple(2),
                empty_struct_node(),
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Bool),
            ],
        };
        let mut vm = completed_return_vm(2);
        set_result_word(&mut vm, 1, 1);
        assert_eq!(
            decode_entrypoint_return(&vm, &schema).unwrap(),
            norito::json!([{}, true])
        );
        set_result_word(&mut vm, 1, 2);
        assert!(matches!(
            decode_entrypoint_return(&vm, &schema),
            Err(EntrypointReturnDecodeError::NonCanonicalBit { word_index: 1, .. })
        ));
    }

    #[test]
    fn list_of_empty_named_structs_validates_each_unit_payload_word() {
        let schema = list(
            2,
            EntrypointValueTypeV1 {
                nodes: vec![empty_struct_node()],
            },
        );
        let mut vm = completed_return_vm(1);
        let layout = ListLayoutV1::try_new(2, 1).unwrap();
        let handle = crate::list::allocate_words(&mut vm, layout, &[vec![0], vec![0]]).unwrap();
        set_result_word(&mut vm, 0, handle);
        let record = encode_entrypoint_return_record(&vm, &schema).unwrap();
        assert_eq!(record.atoms, vec![EntrypointValueAtomV1::List(2)]);
        assert_eq!(
            decode_entrypoint_return(&vm, &schema).unwrap(),
            norito::json!([{}, {}])
        );
        let invalid = crate::list::allocate_words(&mut vm, layout, &[vec![0], vec![1]]).unwrap();
        set_result_word(&mut vm, 0, invalid);
        assert!(matches!(
            decode_entrypoint_return(&vm, &schema),
            Err(EntrypointReturnDecodeError::InvalidValue {
                word_index: 0,
                kind: "empty struct",
                ..
            })
        ));
    }

    fn leaf(kind: EntrypointValueKindV1) -> EntrypointValueTypeV1 {
        EntrypointValueTypeV1 {
            nodes: vec![EntrypointValueTypeNodeV1::Leaf(kind)],
        }
    }
    fn list(capacity: u8, element: EntrypointValueTypeV1) -> EntrypointValueTypeV1 {
        let mut nodes = Vec::with_capacity(1 + element.nodes.len());
        nodes.push(EntrypointValueTypeNodeV1::List(EntrypointListTypeNodeV1 {
            capacity,
        }));
        nodes.extend(element.nodes);
        EntrypointValueTypeV1 { nodes }
    }
    fn nested_list_schema(levels: usize) -> EntrypointValueTypeV1 {
        let mut nodes = Vec::with_capacity(levels.saturating_add(1));
        for _ in 0..levels {
            nodes.push(EntrypointValueTypeNodeV1::List(EntrypointListTypeNodeV1 {
                capacity: 1,
            }));
        }
        nodes.push(EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int));
        EntrypointValueTypeV1 { nodes }
    }
    fn nested_product_schema(levels: usize) -> EntrypointValueTypeV1 {
        let mut nodes = Vec::with_capacity(levels.saturating_add(1));
        nodes.extend((0..levels).map(|_| {
            EntrypointValueTypeNodeV1::Struct(EntrypointStructTypeNodeV1 {
                name: "Fixture::Layer".to_owned(),
                fields: vec!["value".to_owned()],
            })
        }));
        nodes.push(EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int));
        EntrypointValueTypeV1 { nodes }
    }
    fn nested_option_schema(levels: usize) -> EntrypointValueTypeV1 {
        let mut nodes = Vec::with_capacity(levels.saturating_add(1));
        nodes.extend((0..levels).map(|_| EntrypointValueTypeNodeV1::Option));
        nodes.push(EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int));
        EntrypointValueTypeV1 { nodes }
    }
    fn test_tlv(ty: PointerType, payload: &[u8]) -> Vec<u8> {
        let mut envelope = Vec::with_capacity(7 + payload.len() + Hash::LENGTH);
        envelope.extend_from_slice(&(ty as u16).to_be_bytes());
        envelope.push(1);
        envelope.extend_from_slice(
            &u32::try_from(payload.len())
                .expect("test payload fits u32")
                .to_be_bytes(),
        );
        envelope.extend_from_slice(payload);
        envelope.extend_from_slice(Hash::new(payload).as_ref());
        envelope
    }
    fn input_tlv(vm: &mut IVM, ty: PointerType, payload: &[u8]) -> u64 {
        let envelope = test_tlv(ty, payload);
        vm.alloc_input_tlv(&envelope).expect("allocate test TLV")
    }
    fn int_envelope(value: i64) -> Vec<u8> {
        ivm_abi::numeric_tlv::encode_int(&BigInt::from_i128(i128::from(value)))
            .expect("encode V1 int envelope")
    }
    fn int_atom(value: i64) -> EntrypointValueAtomV1 {
        EntrypointValueAtomV1::Pointer(int_envelope(value))
    }
    fn input_int(vm: &mut IVM, value: i64) -> u64 {
        let envelope = int_envelope(value);
        vm.alloc_input_tlv(&envelope).expect("allocate V1 int TLV")
    }
    fn input_quantity(vm: &mut IVM, value: &str) -> u64 {
        let quantity: Quantity = value.parse().expect("canonical quantity");
        let envelope =
            ivm_abi::numeric_tlv::encode_quantity(&quantity).expect("encode V1 quantity envelope");
        vm.alloc_input_tlv(&envelope)
            .expect("allocate V1 quantity TLV")
    }
    fn nested_schema() -> EntrypointValueTypeV1 {
        EntrypointValueTypeV1 {
            nodes: vec![
                EntrypointValueTypeNodeV1::Struct(EntrypointStructTypeNodeV1 {
                    name: "Fixture::Receipt".to_owned(),
                    fields: vec!["maybe".to_owned(), "outcome".to_owned(), "label".to_owned()],
                }),
                EntrypointValueTypeNodeV1::Option,
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::String),
                EntrypointValueTypeNodeV1::Result,
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Bool),
                EntrypointValueTypeNodeV1::Tuple(2),
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Bool),
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::String),
            ],
        }
    }
    #[test]
    fn return_record_codec_is_ambient_independent_and_rejects_alternate_layout() {
        let schema = leaf(EntrypointValueKindV1::Blob);
        let canonical_schema =
            encode_canonical_norito(&schema).expect("encode canonical return schema");
        let canonical_schema_hash = entrypoint_return_schema_hash_v1(&canonical_schema);
        let record = EntrypointReturnRecordV1 {
            schema_hash: canonical_schema_hash,
            atoms: vec![EntrypointValueAtomV1::Pointer(test_tlv(
                PointerType::Blob,
                b"canonical return payload",
            ))],
        };
        let canonical_record = exact_record_bytes(&record, MAX_ENTRYPOINT_RETURN_RECORD_BYTES)
            .expect("encode canonical return record");
        let canonical_record_hash = Hash::new(&canonical_record);
        let length_probe_record = EntrypointReturnRecordV1 {
            schema_hash: canonical_schema_hash,
            atoms: vec![
                EntrypointValueAtomV1::Pointer(test_tlv(
                    PointerType::Blob,
                    b"length-sensitive return payload",
                ));
                16
            ],
        };
        let canonical_length_probe =
            exact_record_bytes(&length_probe_record, MAX_ENTRYPOINT_RETURN_RECORD_BYTES)
                .expect("encode canonical return-record length probe");
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        let alternate_record =
            norito::to_bytes(&record).expect("encode alternate-layout return record");
        assert_ne!(alternate_record, canonical_record);
        let ambient_before = norito::to_bytes(&schema).expect("encode schema under ambient layout");
        assert_eq!(
            schema_hash(&schema).expect("hash schema canonically"),
            canonical_schema_hash
        );
        let encoded_under_ambient = exact_record_bytes(&record, MAX_ENTRYPOINT_RETURN_RECORD_BYTES)
            .expect("encode record canonically under ambient layout");
        assert_eq!(encoded_under_ambient, canonical_record);
        assert_eq!(Hash::new(&encoded_under_ambient), canonical_record_hash);
        assert_eq!(
            exact_record_bytes(&length_probe_record, canonical_length_probe.len())
                .expect("canonical length admission must ignore ambient layout"),
            canonical_length_probe
        );
        assert!(matches!(
            exact_record_bytes(&length_probe_record, canonical_length_probe.len() - 1),
            Err(EntrypointReturnDecodeError::RecordTooLarge { .. })
        ));
        assert_eq!(
            decode_entrypoint_return_record(&schema, &canonical_record)
                .expect("decode canonical record under ambient layout"),
            record
        );
        assert!(matches!(
            decode_entrypoint_return_record(&schema, &alternate_record),
            Err(EntrypointReturnDecodeError::RecordEncoding { .. })
        ));
        assert_eq!(
            norito::to_bytes(&schema).expect("re-encode schema under ambient layout"),
            ambient_before,
            "canonical helpers must restore the caller's ambient layout"
        );
        drop(ambient);
        assert_eq!(
            norito::to_bytes(&record).expect("encode record after ambient guard"),
            canonical_record
        );
    }
    #[test]
    fn entrypoint_int_json_is_a_canonical_string_at_every_width() {
        for value in [
            BigInt::from_i128(-7),
            BigInt::from_i128(0),
            BigInt::from_i128(i128::MAX),
            "1606938044258990275541962092341162602522202993782792835301376"
                .parse::<BigInt>()
                .expect("2^200 fits the int domain"),
        ] {
            assert_eq!(int_json_value(&value), Value::from(value.to_string()));
        }
    }
    #[test]
    fn flat_list_element_cursor_consumes_exactly_one_bounded_subtree() {
        let nodes = vec![
            EntrypointValueTypeNodeV1::List(EntrypointListTypeNodeV1 { capacity: 4 }),
            EntrypointValueTypeNodeV1::Struct(EntrypointStructTypeNodeV1 {
                name: "Fixture::Pair".to_owned(),
                fields: vec!["left".to_owned(), "right".to_owned()],
            }),
            EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
            EntrypointValueTypeNodeV1::Option,
            EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Quantity),
        ];
        let mut list_element = 1;
        let subtree = take_return_subtree(&nodes, &mut list_element)
            .expect("one exact element subtree follows the List node");
        assert_eq!(subtree, &nodes[1..]);
        assert_eq!(list_element, nodes.len());
        let mut list_root = 0;
        assert_eq!(
            return_node_word_count(&nodes, &mut list_root).expect("valid flat List schema"),
            1
        );
        assert_eq!(list_root, nodes.len());
        let mut malformed = 1;
        assert!(matches!(
            take_return_subtree(&nodes[..4], &mut malformed),
            Err(EntrypointReturnDecodeError::InvalidSchema)
        ));
        assert_eq!(malformed, 1, "a rejected cursor must not advance");
    }
    #[test]
    fn maximum_flat_list_depth_renders_without_native_stack_recursion() {
        let levels = MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH - 1;
        let schema = nested_list_schema(levels);
        assert!(schema.validate());
        let mut atoms = Vec::with_capacity(levels.saturating_add(1));
        atoms.extend((0..levels).map(|_| EntrypointValueAtomV1::List(1)));
        atoms.push(int_atom(7));
        let record = EntrypointReturnRecordV1 {
            schema_hash: schema_hash(&schema).expect("hash the exact boundary schema"),
            atoms,
        };
        let rendered = render_entrypoint_return_record(&schema, &record)
            .expect("render the exact V1 nesting boundary");
        let mut cursor = &rendered;
        for _ in 0..levels {
            let items = cursor.as_array().expect("nested list renders as an array");
            assert_eq!(items.len(), 1);
            cursor = &items[0];
        }
        assert_eq!(cursor, &Value::from("7"));
        let over_limit = nested_list_schema(MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH);
        assert!(!over_limit.validate());
        assert!(matches!(
            render_entrypoint_return_record(&over_limit, &record),
            Err(EntrypointReturnDecodeError::InvalidSchema)
                | Err(EntrypointReturnDecodeError::SchemaBinding)
        ));
    }
    #[test]
    fn maximum_depth_return_collectors_use_bounded_work_stacks() {
        let levels = MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH - 1;
        let mut vm = completed_return_vm(1);
        let product_schema = nested_product_schema(levels);
        assert!(product_schema.validate());
        let seven = input_int(&mut vm, 7);
        set_result_word(&mut vm, 0, seven);
        let product_record = collect_entrypoint_return_record(
            &vm,
            &product_schema,
            MAX_ENTRYPOINT_RETURN_RECORD_BYTES,
        )
        .expect("collect the maximum-depth product without native recursion");
        assert_eq!(product_record.atoms, vec![int_atom(7)]);
        let list_schema = nested_list_schema(levels);
        assert!(list_schema.validate());
        let list_layout = ListLayoutV1::try_new(1, 1).expect("one-word list layout");
        let mut list_word = input_int(&mut vm, 9);
        for _ in 0..levels {
            list_word = crate::list::allocate_words(&mut vm, list_layout, &[vec![list_word]])
                .expect("allocate one nested active list item");
        }
        set_result_word(&mut vm, 0, list_word);
        let list_record =
            collect_entrypoint_return_record(&vm, &list_schema, MAX_ENTRYPOINT_RETURN_RECORD_BYTES)
                .expect("collect the maximum-depth flat List tape without native recursion");
        assert_eq!(list_record.atoms.len(), levels + 1);
        assert!(
            list_record.atoms[..levels]
                .iter()
                .all(|atom| atom == &EntrypointValueAtomV1::List(1))
        );
        assert_eq!(list_record.atoms.last(), Some(&int_atom(9)));
        let option_schema = nested_option_schema(levels);
        assert!(option_schema.validate());
        let option_layout = SumLayoutV1::option(1).expect("one-word Option layout");
        let mut option_word = input_int(&mut vm, 11);
        for _ in 0..levels {
            option_word = crate::sum::allocate_words(&mut vm, option_layout, 1, &[option_word])
                .expect("allocate one nested active Option payload");
        }
        set_result_word(&mut vm, 0, option_word);
        let option_record = collect_entrypoint_return_record(
            &vm,
            &option_schema,
            MAX_ENTRYPOINT_RETURN_RECORD_BYTES,
        )
        .expect("collect the maximum-depth active Option chain without native recursion");
        assert_eq!(option_record.atoms.len(), levels + 1);
        assert!(
            option_record.atoms[..levels]
                .iter()
                .all(|atom| atom == &EntrypointValueAtomV1::Tag(true))
        );
        assert_eq!(option_record.atoms.last(), Some(&int_atom(11)));
    }
    #[test]
    fn maximum_depth_active_payload_rejects_a_null_nested_sum_handle() {
        let levels = MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH - 1;
        let schema = nested_option_schema(levels);
        assert!(schema.validate());
        let mut vm = completed_return_vm(1);
        let layout = SumLayoutV1::option(1).expect("one-word Option layout");
        let mut pointer = 0_u64;
        for _ in 0..levels.saturating_sub(1) {
            pointer = crate::sum::allocate_words(&mut vm, layout, 1, &[pointer])
                .expect("wrap the malformed active child in a valid outer handle");
        }
        set_result_word(&mut vm, 0, pointer);
        assert!(matches!(
            collect_entrypoint_return_record(
                &vm,
                &schema,
                MAX_ENTRYPOINT_RETURN_RECORD_BYTES,
            ),
            Err(EntrypointReturnDecodeError::InvalidValue {
                kind: "Option",
                reason,
                ..
            }) if reason == "sum handle is null"
        ));
    }
    #[test]
    fn nested_struct_option_and_result_render_exact_json() {
        let schema = nested_schema();
        let mut vm = completed_return_vm(3);
        let label = input_tlv(&mut vm, PointerType::Blob, "言挙げ".as_bytes());
        let maybe = crate::sum::allocate_words(
            &mut vm,
            SumLayoutV1::option(1).expect("Option layout"),
            0,
            &[],
        )
        .expect("Option::none");
        let outcome = crate::sum::allocate_words(
            &mut vm,
            SumLayoutV1::try_new(2, 1).expect("Result layout"),
            1,
            &[1],
        )
        .expect("Result::ok");
        for (offset, value) in [maybe, outcome, label].into_iter().enumerate() {
            set_result_word(&mut vm, offset, value);
        }
        let value = decode_entrypoint_return(&vm, &schema).expect("decode exact nested return");
        assert_eq!(
            value,
            norito::json!({
                "maybe": { "none": true },
                "outcome": { "ok": true },
                "label": "言挙げ",
            })
        );
    }
    #[test]
    fn unit_and_nominal_errors_roundtrip_in_tables_and_nested_values() {
        let error = crate::error_types::list_error_type();
        let schema = EntrypointValueTypeV1 {
            nodes: vec![
                EntrypointValueTypeNodeV1::Tuple(3),
                EntrypointValueTypeNodeV1::Unit,
                EntrypointValueTypeNodeV1::Error(error.clone()),
                EntrypointValueTypeNodeV1::List(EntrypointListTypeNodeV1 { capacity: 2 }),
                EntrypointValueTypeNodeV1::Result,
                EntrypointValueTypeNodeV1::Unit,
                EntrypointValueTypeNodeV1::Error(error),
            ],
        };
        let mut vm = completed_return_vm(3);
        let layout = SumLayoutV1::try_new(1, 1).unwrap();
        let ok = crate::sum::allocate_words(&mut vm, layout, 1, &[0]).unwrap();
        let err = crate::sum::allocate_words(&mut vm, layout, 0, &[2]).unwrap();
        let items = crate::list::allocate_words(
            &mut vm,
            ListLayoutV1::try_new(2, 1).unwrap(),
            &[vec![ok], vec![err]],
        )
        .unwrap();
        for (offset, word) in [0, 1, items].into_iter().enumerate() {
            set_result_word(&mut vm, offset, word);
        }
        let expected = norito::json!([
            null,
            "IndexOutOfBounds",
            [{ "ok": null }, { "err": "CapacityExceeded" }]
        ]);
        assert_eq!(decode_entrypoint_return(&vm, &schema).unwrap(), expected);
        let encoded = encode_entrypoint_return_record_bytes(&vm, &schema).unwrap();
        let record = decode_entrypoint_return_record(&schema, &encoded).unwrap();
        assert_eq!(
            render_entrypoint_return_record(&schema, &record).unwrap(),
            expected
        );

        let mut wrong_identity = schema.clone();
        let EntrypointValueTypeNodeV1::Error(error) = &mut wrong_identity.nodes[2] else {
            unreachable!();
        };
        error.identity = "different-package@1.0.0::unit::ListError".to_owned();
        assert!(decode_entrypoint_return_record(&wrong_identity, &encoded).is_err());
        let mut wrong_schema = schema.clone();
        let EntrypointValueTypeNodeV1::Error(error) = &mut wrong_schema.nodes[2] else {
            unreachable!();
        };
        error.variants[0].name = "DifferentVariant".to_owned();
        assert!(decode_entrypoint_return_record(&wrong_schema, &encoded).is_err());
        let mut wrong_code = record;
        wrong_code.atoms[1] = EntrypointValueAtomV1::ErrorCode(3);
        assert!(render_entrypoint_return_record(&schema, &wrong_code).is_err());

        set_result_word(&mut vm, 0, 1);
        assert!(
            decode_entrypoint_return(&vm, &schema).is_err(),
            "Unit is exactly zero"
        );
        set_result_word(&mut vm, 0, 0);
        set_result_word(&mut vm, 1, u64::from(u32::MAX) + 1);
        assert!(
            decode_entrypoint_return(&vm, &schema).is_err(),
            "codes cannot truncate"
        );
        set_result_word(&mut vm, 1, 1);
        let bad_ok = crate::sum::allocate_words(&mut vm, layout, 1, &[1]).unwrap();
        let bad_items = crate::list::allocate_words(
            &mut vm,
            ListLayoutV1::try_new(2, 1).unwrap(),
            &[vec![bad_ok]],
        )
        .unwrap();
        set_result_word(&mut vm, 2, bad_items);
        assert!(
            decode_entrypoint_return(&vm, &schema).is_err(),
            "nested Unit is exactly zero"
        );
    }
    #[test]
    fn opaque_cursors_roundtrip_directly_and_inside_lists_and_options() {
        let cursor = iroha_data_model::smart_contract::state_cursor::StateCursorV1 {
            instance: "local::counter".to_owned(),
            map: "balances".parse().unwrap(),
            schema_hash: [7; 32],
            key_schema_hash: iroha_data_model::smart_contract::entrypoint::state_key_schema_hash_v1(&iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 { nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int)] }).unwrap(),
            last_key: "balances/01".parse().unwrap(),
        };
        let payload = cursor.encode_frame().expect("canonical cursor frame");
        let scalar = EntrypointValueTypeV1 {
            nodes: vec![EntrypointValueTypeNodeV1::StateCursor(iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 { nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int)] })],
        };
        let mut vm = completed_return_vm(1);
        let pointer = input_tlv(&mut vm, PointerType::NoritoBytes, &payload);
        set_result_word(&mut vm, 0, pointer);
        let expected = Value::String(format!("0x{}", hex::encode(&payload)));
        assert_eq!(decode_entrypoint_return(&vm, &scalar).unwrap(), expected);
        let record = encode_entrypoint_return_record_bytes(&vm, &scalar).unwrap();
        let decoded = decode_entrypoint_return_record(&scalar, &record).unwrap();
        assert_eq!(
            render_entrypoint_return_record(&scalar, &decoded).unwrap(),
            expected
        );
        assert!(matches!(
            collect_entrypoint_return_record(&vm, &scalar, 64),
            Err(EntrypointReturnDecodeError::RecordTooLarge { .. })
        ));
        let wrong_key = EntrypointValueTypeV1 {
            nodes: vec![EntrypointValueTypeNodeV1::StateCursor(iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 { nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Name)] })],
        };
        assert!(decode_entrypoint_return(&vm, &wrong_key).is_err());
        let optional = EntrypointValueTypeV1 {
            nodes: vec![EntrypointValueTypeNodeV1::Option, scalar.nodes[0].clone()],
        };
        let schema = list(2, optional);
        let some =
            crate::sum::allocate_words(&mut vm, SumLayoutV1::option(1).unwrap(), 1, &[pointer])
                .unwrap();
        let none =
            crate::sum::allocate_words(&mut vm, SumLayoutV1::option(1).unwrap(), 0, &[]).unwrap();
        let handle = crate::list::allocate_words(
            &mut vm,
            ListLayoutV1::try_new(2, 1).unwrap(),
            &[vec![some], vec![none]],
        )
        .unwrap();
        set_result_word(&mut vm, 0, handle);
        assert_eq!(
            decode_entrypoint_return(&vm, &schema).unwrap(),
            norito::json!([{ "some": expected }, { "none": true }])
        );
        let malformed = input_tlv(&mut vm, PointerType::NoritoBytes, b"not a cursor frame");
        set_result_word(&mut vm, 0, malformed);
        assert!(decode_entrypoint_return(&vm, &scalar).is_err());
        let wrong_pointer = input_tlv(&mut vm, PointerType::Blob, &payload);
        set_result_word(&mut vm, 0, wrong_pointer);
        assert!(matches!(
            decode_entrypoint_return(&vm, &scalar),
            Err(EntrypointReturnDecodeError::PointerType { .. })
        ));
    }
    #[test]
    fn typed_return_record_roundtrips_and_binds_the_exact_schema() {
        let schema = nested_schema();
        let mut vm = completed_return_vm(3);
        let label = input_tlv(&mut vm, PointerType::Blob, b"label");
        let maybe = crate::sum::allocate_words(
            &mut vm,
            SumLayoutV1::option(1).expect("Option layout"),
            0,
            &[],
        )
        .expect("Option::none");
        let outcome = crate::sum::allocate_words(
            &mut vm,
            SumLayoutV1::try_new(2, 1).expect("Result layout"),
            1,
            &[1],
        )
        .expect("Result::ok");
        for (offset, value) in [maybe, outcome, label].into_iter().enumerate() {
            set_result_word(&mut vm, offset, value);
        }
        let record = encode_entrypoint_return_record(&vm, &schema).expect("encode typed record");
        let encoded = norito::to_bytes(&record).expect("encode record Norito");
        let decoded: EntrypointReturnRecordV1 =
            norito::decode_from_bytes(&encoded).expect("decode record Norito");
        assert_eq!(decoded, record);
        assert_eq!(
            decoded.schema_hash,
            schema_hash(&schema).expect("schema hash")
        );
        let mut mismatched = schema.clone();
        mismatched.nodes.pop();
        assert!(render_entrypoint_return_record(&mismatched, &decoded).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(matches!(
            decode_entrypoint_return_record(&schema, &trailing),
            Err(EntrypointReturnDecodeError::RecordEncoding { .. })
        ));
    }
    #[test]
    fn retired_recursive_list_record_encoding_is_rejected() {
        // This test-only encoder preserves the retired field shape solely to
        // prove that the first-release decoder does not accept it. Variant
        // order intentionally matches the canonical enum's discriminants.
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "ivm::value_record::tests::retired_recursive_list_record_encoding_is_rejected::LegacyEntrypointValueAtomV1"
        )]
        #[derive(Encode)]
        enum LegacyEntrypointValueAtomV1 {
            Tag(bool),
            Int(i64),
            Bool(bool),
            Pointer(Vec<u8>),
            List(Vec<Vec<Self>>),
        }
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "ivm::value_record::tests::retired_recursive_list_record_encoding_is_rejected::LegacyEntrypointReturnRecordV1"
        )]
        #[derive(Encode)]
        struct LegacyEntrypointReturnRecordV1 {
            schema_hash: [u8; 32],
            atoms: Vec<LegacyEntrypointValueAtomV1>,
        }
        let schema = list(1, leaf(EntrypointValueKindV1::Int));
        let schema_hash = schema_hash(&schema).expect("List schema hash");
        let legacy_items = vec![vec![LegacyEntrypointValueAtomV1::Int(7)]];
        let legacy = LegacyEntrypointReturnRecordV1 {
            schema_hash,
            atoms: vec![LegacyEntrypointValueAtomV1::List(legacy_items)],
        };
        // Construct every retired variant so the local encoder's order remains
        // an explicit part of the fixture rather than an accidental omission.
        let _variant_order_guard = (
            LegacyEntrypointValueAtomV1::Tag(false),
            LegacyEntrypointValueAtomV1::Bool(false),
            LegacyEntrypointValueAtomV1::Pointer(Vec::new()),
        );
        let current = EntrypointReturnRecordV1 {
            schema_hash,
            atoms: vec![EntrypointValueAtomV1::List(1), int_atom(7)],
        };
        let (current_payload, current_flags, payload, flags) = {
            let _canonical =
                norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
            let (current_payload, current_flags) =
                norito::codec::encode_with_header_flags(&current);
            let (payload, flags) = norito::codec::encode_with_header_flags(&legacy);
            (current_payload, current_flags, payload, flags)
        };
        let canonical_bytes =
            norito::core::frame_bare_with_header_flags::<EntrypointReturnRecordV1>(
                &current_payload,
                current_flags,
            )
            .unwrap();
        assert_eq!(canonical_bytes, norito::encode_canonical(&current).unwrap());
        assert_eq!(
            decode_entrypoint_return_record(&schema, &canonical_bytes).unwrap(),
            current
        );
        let legacy_bytes =
            norito::core::frame_bare_with_header_flags::<EntrypointReturnRecordV1>(&payload, flags)
                .unwrap();
        let view =
            norito::core::from_bytes_view(&legacy_bytes).expect("valid current-owner envelope");
        assert_eq!(
            view.schema(),
            norito::schema::identity::frame_hash::<EntrypointReturnRecordV1>()
        );
        assert_eq!(view.as_bytes(), payload.as_slice());
        assert!(
            !matches!(
                norito::decode_canonical::<EntrypointReturnRecordV1>(&legacy_bytes),
                Err(norito::Error::SchemaMismatch)
            ),
            "recursive payload must reach the current return-record decoder"
        );
        assert_ne!(legacy_bytes, canonical_bytes);
        assert!(decode_entrypoint_return_record(&schema, &legacy_bytes).is_err());
    }
    #[test]
    fn exact_return_record_byte_cap_is_inclusive_and_checked_before_encoding() {
        let schema = leaf(EntrypointValueKindV1::Blob);
        let schema_hash = schema_hash(&schema).expect("return schema hash");
        assert_eq!(
            test_tlv(PointerType::NoritoBytes, &[]).len(),
            ENTRYPOINT_RETURN_TLV_ENVELOPE_BYTES_V1,
            "the published overhead must match the canonical pointer-ABI encoder"
        );
        let mut payload_len = MAX_ENTRYPOINT_RETURN_RECORD_BYTES.saturating_sub(256);
        let mut record = EntrypointReturnRecordV1 {
            schema_hash,
            atoms: Vec::new(),
        };
        let mut encoded = Vec::new();
        for _ in 0..12 {
            record.atoms = vec![EntrypointValueAtomV1::Pointer(test_tlv(
                PointerType::Blob,
                &vec![0x5A; payload_len],
            ))];
            encoded = norito::to_bytes(&record).expect("encode boundary record");
            match encoded.len().cmp(&MAX_ENTRYPOINT_RETURN_RECORD_BYTES) {
                core::cmp::Ordering::Equal => break,
                core::cmp::Ordering::Less => {
                    payload_len = payload_len.saturating_add(
                        MAX_ENTRYPOINT_RETURN_RECORD_BYTES.saturating_sub(encoded.len()),
                    );
                }
                core::cmp::Ordering::Greater => {
                    payload_len = payload_len
                        .saturating_sub(encoded.len() - MAX_ENTRYPOINT_RETURN_RECORD_BYTES);
                }
            }
        }
        assert_eq!(
            encoded.len(),
            MAX_ENTRYPOINT_RETURN_RECORD_BYTES,
            "fixture must land exactly on the inclusive V1 return boundary"
        );
        assert_eq!(
            encoded.len() + ENTRYPOINT_RETURN_TLV_ENVELOPE_BYTES_V1,
            iroha_data_model::smart_contract::entrypoint::MAX_ENTRYPOINT_BOUNDARY_BYTES,
            "record plus its canonical NoritoBytes TLV must fill exactly one boundary envelope"
        );
        assert_eq!(
            exact_record_bytes(&record, MAX_ENTRYPOINT_RETURN_RECORD_BYTES)
                .expect("exact-cap record"),
            encoded
        );
        decode_entrypoint_return_record(&schema, &encoded)
            .expect("the exact canonical V1 cap must decode");
        let boundary_payload = vec![0x5A; payload_len];
        let boundary_envelope = test_tlv(PointerType::Blob, &boundary_payload);
        let mut vm = completed_return_vm(1);
        let pointer = vm
            .alloc_heap(u64::try_from(boundary_envelope.len()).expect("TLV length fits u64"))
            .expect("exact-cap leaf fits the clean child heap");
        vm.store_bytes(pointer, &boundary_envelope)
            .expect("store exact-cap leaf");
        set_result_word(&mut vm, 0, pointer);
        assert_eq!(
            encode_entrypoint_return_record_bytes(&vm, &schema)
                .expect("the cumulative clone budget must admit the exact cap"),
            encoded
        );
        let mut oversized = record;
        let EntrypointValueAtomV1::Pointer(envelope) = &mut oversized.atoms[0] else {
            panic!("fixture pointer atom");
        };
        let oversized_payload = vec![0x5A; payload_len + 1];
        *envelope = test_tlv(PointerType::Blob, &oversized_payload);
        assert!(matches!(
            exact_record_bytes(&oversized, MAX_ENTRYPOINT_RETURN_RECORD_BYTES),
            Err(EntrypointReturnDecodeError::RecordTooLarge {
                max_bytes: MAX_ENTRYPOINT_RETURN_RECORD_BYTES,
                ..
            })
        ));
        assert!(matches!(
            decode_entrypoint_return_record(
                &schema,
                &vec![0; MAX_ENTRYPOINT_RETURN_RECORD_BYTES + 1]
            ),
            Err(EntrypointReturnDecodeError::RecordTooLarge {
                bytes,
                max_bytes: MAX_ENTRYPOINT_RETURN_RECORD_BYTES,
            }) if bytes == MAX_ENTRYPOINT_RETURN_RECORD_BYTES + 1
        ));
    }
    #[test]
    fn repeated_large_pointer_is_rejected_before_the_second_clone() {
        let schema = list(2, leaf(EntrypointValueKindV1::Blob));
        let payload = vec![0xA5; MAX_ENTRYPOINT_RETURN_RECORD_BYTES / 2 + 1024];
        let envelope = test_tlv(PointerType::Blob, &payload);
        let mut vm = completed_return_vm(1);
        let pointer = vm
            .alloc_heap(u64::try_from(envelope.len()).expect("TLV length fits u64"))
            .expect("allocate one large public TLV");
        vm.store_bytes(pointer, &envelope)
            .expect("store one large public TLV");
        let layout = ListLayoutV1::try_new(2, 1).expect("list layout");
        let list = crate::list::allocate_words(&mut vm, layout, &[vec![pointer], vec![pointer]])
            .expect("list repeating one VM pointer");
        set_result_word(&mut vm, 0, list);
        assert!(matches!(
            encode_entrypoint_return_record(&vm, &schema),
            Err(EntrypointReturnDecodeError::RecordTooLarge {
                max_bytes: MAX_ENTRYPOINT_RETURN_RECORD_BYTES,
                ..
            })
        ));
        let mut budget = ReturnRecordBudget::default();
        budget
            .reserve_pointer(payload.len())
            .expect("first pointer fits the cumulative clone budget");
        let charged_after_first = budget.lower_bound_bytes;
        assert!(budget.reserve_pointer(payload.len()).is_err());
        assert_eq!(
            budget.lower_bound_bytes, charged_after_first,
            "a rejected pointer must not advance the clone budget"
        );
    }
    #[test]
    fn caller_affordability_bound_rejects_pointer_before_payload_clone() {
        let schema = leaf(EntrypointValueKindV1::Blob);
        let payload = vec![0xA5; 64 * 1024];
        let envelope = test_tlv(PointerType::Blob, &payload);
        let mut vm = completed_return_vm(1);
        let pointer = vm
            .alloc_heap(u64::try_from(envelope.len()).expect("TLV length fits u64"))
            .expect("allocate child return TLV");
        vm.store_bytes(pointer, &envelope)
            .expect("store child return TLV");
        set_result_word(&mut vm, 0, pointer);
        let affordable_record_bytes = 1024;
        assert!(matches!(
            encode_entrypoint_return_record_bytes_bounded(
                &vm,
                &schema,
                affordable_record_bytes,
            ),
            Err(EntrypointReturnDecodeError::RecordTooLarge {
                max_bytes,
                ..
            }) if max_bytes == affordable_record_bytes
        ));
    }
    #[test]
    fn inactive_return_record_branches_reject_hidden_atoms() {
        let option_schema = EntrypointValueTypeV1 {
            nodes: vec![
                EntrypointValueTypeNodeV1::Option,
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Blob),
            ],
        };
        let option_record = EntrypointReturnRecordV1 {
            schema_hash: schema_hash(&option_schema).expect("Option schema hash"),
            atoms: vec![
                EntrypointValueAtomV1::Tag(false),
                EntrypointValueAtomV1::Pointer(test_tlv(PointerType::Blob, b"private-placeholder")),
            ],
        };
        assert!(matches!(
            render_entrypoint_return_record(&option_schema, &option_record),
            Err(EntrypointReturnDecodeError::SchemaBinding)
        ));
        let result_schema = EntrypointValueTypeV1 {
            nodes: vec![
                EntrypointValueTypeNodeV1::Result,
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Blob),
            ],
        };
        let result_record = EntrypointReturnRecordV1 {
            schema_hash: schema_hash(&result_schema).expect("Result schema hash"),
            atoms: vec![
                EntrypointValueAtomV1::Tag(true),
                int_atom(7),
                EntrypointValueAtomV1::Pointer(test_tlv(PointerType::Blob, b"private-error")),
            ],
        };
        assert!(matches!(
            render_entrypoint_return_record(&result_schema, &result_record),
            Err(EntrypointReturnDecodeError::SchemaBinding)
        ));
    }
    #[test]
    fn flat_list_records_reject_malformed_truncated_trailing_and_count_mismatch_tapes() {
        let schema = list(2, leaf(EntrypointValueKindV1::Int));
        let valid = EntrypointReturnRecordV1 {
            schema_hash: schema_hash(&schema).expect("List schema hash"),
            atoms: vec![EntrypointValueAtomV1::List(2), int_atom(1), int_atom(2)],
        };
        assert_eq!(
            render_entrypoint_return_record(&schema, &valid).expect("canonical flat list tape"),
            norito::json!(["1", "2"])
        );
        for atoms in [
            vec![
                EntrypointValueAtomV1::List(1),
                EntrypointValueAtomV1::Bool(true),
            ],
            vec![EntrypointValueAtomV1::List(1), int_atom(1), int_atom(2)],
            vec![EntrypointValueAtomV1::List(1)],
            vec![EntrypointValueAtomV1::List(2), int_atom(1)],
            vec![EntrypointValueAtomV1::List(0), int_atom(1)],
            vec![
                EntrypointValueAtomV1::List(3),
                int_atom(1),
                int_atom(2),
                int_atom(3),
            ],
        ] {
            let record = EntrypointReturnRecordV1 {
                schema_hash: schema_hash(&schema).expect("List schema hash"),
                atoms,
            };
            assert!(render_entrypoint_return_record(&schema, &record).is_err());
            let encoded = norito::to_bytes(&record).expect("encode malformed tape fixture");
            assert!(decode_entrypoint_return_record(&schema, &encoded).is_err());
        }
    }
    #[test]
    fn malformed_tags_and_booleans_fail_closed_without_reading_inactive_words() {
        let mut vm = completed_return_vm(1);
        set_result_word(&mut vm, 0, 2);
        assert!(matches!(
            decode_entrypoint_return(&vm, &leaf(EntrypointValueKindV1::Bool)),
            Err(EntrypointReturnDecodeError::NonCanonicalBit { role: "bool", .. })
        ));
        let option_int = EntrypointValueTypeV1 {
            nodes: vec![
                EntrypointValueTypeNodeV1::Option,
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
            ],
        };
        let forged = crate::sum::allocate_words(
            &mut vm,
            SumLayoutV1::option(1).expect("Option layout"),
            0,
            &[],
        )
        .expect("Option::none to forge");
        vm.store_u64(forged, 2).expect("forge Option tag");
        set_result_word(&mut vm, 0, forged);
        assert!(matches!(
            decode_entrypoint_return(&vm, &option_int),
            Err(EntrypointReturnDecodeError::InvalidValue { kind: "Option", .. })
        ));
        let none = crate::sum::allocate_words(
            &mut vm,
            SumLayoutV1::option(1).expect("Option layout"),
            0,
            &[],
        )
        .expect("Option::none");
        set_result_word(&mut vm, 0, none);
        vm.store_u64(none + 8, 99)
            .expect("forge inactive Option storage");
        assert!(matches!(
            decode_entrypoint_return(&vm, &option_int),
            Err(EntrypointReturnDecodeError::InvalidValue { kind: "Option", .. })
        ));
        vm.store_u64(none + 8, 0)
            .expect("restore canonical inactive Option storage");
        vm.set_register(11, 7);
        assert_eq!(
            decode_entrypoint_return(&vm, &option_int).expect("decode active-only None"),
            norito::json!({ "none": true })
        );
    }
    #[test]
    fn private_registers_do_not_override_tables_but_private_active_payloads_are_rejected() {
        let option_int = EntrypointValueTypeV1 {
            nodes: vec![
                EntrypointValueTypeNodeV1::Option,
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
            ],
        };
        let mut vm = completed_return_vm(1);
        vm.set_zk_mode(true)
            .expect("private lifecycle cleanup succeeds");
        let none =
            crate::sum::allocate_words(&mut vm, SumLayoutV1::option(1).unwrap(), 0, &[]).unwrap();
        set_result_word(&mut vm, 0, none);
        let table = vm.register(10);
        vm.set_register(10, u64::MAX);
        vm.set_register(11, 0);
        vm.registers.set_tag(10, true);
        vm.registers.set_tag(11, true);
        assert_eq!(
            decode_entrypoint_return(&vm, &option_int)
                .expect("private descriptor registers are not result authority"),
            norito::json!({ "none": true })
        );

        let record = crate::private_input::int_record(42_u64.into()).unwrap();
        let kind = record.kind.tag();
        let mut host = crate::host::DefaultHost::with_private_inputs(vec![record]).unwrap();
        vm.set_register(10, 0);
        vm.set_register(11, kind);
        host.syscall(crate::syscalls::SYSCALL_GET_PRIVATE_INPUT, &mut vm)
            .unwrap();
        let private_pointer = vm.register(10);
        let some = crate::sum::allocate_words(
            &mut vm,
            SumLayoutV1::option(1).unwrap(),
            1,
            &[private_pointer],
        )
        .unwrap();
        vm.store_u64(table, some).unwrap();
        assert!(matches!(
            decode_entrypoint_return(&vm, &option_int),
            Err(EntrypointReturnDecodeError::Privacy { word_index: 0, .. })
        ));
        vm.store_u64(table, private_pointer).unwrap();
        assert!(matches!(
            decode_entrypoint_return(&vm, &leaf(EntrypointValueKindV1::Int)),
            Err(EntrypointReturnDecodeError::Privacy { word_index: 0, .. })
        ));
    }
    #[test]
    fn nested_quantity_list_roundtrips_as_one_return_word() {
        let schema = list(2, list(2, leaf(EntrypointValueKindV1::Quantity)));
        let mut vm = completed_return_vm(1);
        let amount_pointer = input_quantity(&mut vm, "1.25");
        let inner_layout = ListLayoutV1::try_new(2, 1).expect("inner layout");
        let first = crate::list::allocate_words(&mut vm, inner_layout, &[vec![amount_pointer]])
            .expect("first inner list");
        let second = crate::list::allocate_words(&mut vm, inner_layout, &[vec![amount_pointer]])
            .expect("second inner list");
        let outer_layout = ListLayoutV1::try_new(2, 1).expect("outer layout");
        let list = crate::list::allocate_words(&mut vm, outer_layout, &[vec![first], vec![second]])
            .expect("outer list");
        set_result_word(&mut vm, 0, list);
        assert_eq!(
            decode_entrypoint_return(&vm, &schema).expect("decode nested quantity list"),
            norito::json!([["1.25"], ["1.25"]])
        );
        let overflow =
            crate::list::allocate_words(&mut vm, outer_layout, &[vec![first], vec![second]])
                .expect("outer list to forge");
        vm.store_u64(overflow, 3)
            .expect("forge length past capacity");
        set_result_word(&mut vm, 0, overflow);
        assert!(matches!(
            encode_entrypoint_return_record(&vm, &schema),
            Err(EntrypointReturnDecodeError::InvalidValue { kind: "List", .. })
        ));
        let wrong = input_tlv(&mut vm, PointerType::Blob, b"not a quantity frame");
        let wrong_inner = crate::list::allocate_words(&mut vm, inner_layout, &[vec![wrong]])
            .expect("inner list with wrong pointer type");
        let wrong_outer = crate::list::allocate_words(&mut vm, outer_layout, &[vec![wrong_inner]])
            .expect("outer list with wrong pointer type");
        set_result_word(&mut vm, 0, wrong_outer);
        assert!(matches!(
            encode_entrypoint_return_record(&vm, &schema),
            Err(EntrypointReturnDecodeError::PointerType {
                expected: PointerType::Quantity,
                actual: PointerType::Blob,
                ..
            })
        ));
    }
    #[test]
    fn list_of_nested_option_results_decodes_active_only_sum_handles() {
        let element = EntrypointValueTypeV1 {
            nodes: vec![
                EntrypointValueTypeNodeV1::Option,
                EntrypointValueTypeNodeV1::Result,
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Quantity),
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Bool),
            ],
        };
        let schema = list(3, element);
        let mut vm = completed_return_vm(1);
        let amount = input_quantity(&mut vm, "1.25");
        let result_layout = SumLayoutV1::try_new(1, 1).expect("Result layout");
        let option_layout = SumLayoutV1::option(1).expect("Option layout");
        let ok =
            crate::sum::allocate_words(&mut vm, result_layout, 1, &[amount]).expect("Result::ok");
        let some_ok =
            crate::sum::allocate_words(&mut vm, option_layout, 1, &[ok]).expect("Option::some ok");
        let err = crate::sum::allocate_words(&mut vm, result_layout, 0, &[1]).expect("Result::err");
        let some_err = crate::sum::allocate_words(&mut vm, option_layout, 1, &[err])
            .expect("Option::some err");
        let none =
            crate::sum::allocate_words(&mut vm, option_layout, 0, &[]).expect("Option::none");
        let list_layout = ListLayoutV1::try_new(3, 1).expect("list layout");
        let list = crate::list::allocate_words(
            &mut vm,
            list_layout,
            &[vec![some_ok], vec![some_err], vec![none]],
        )
        .expect("allocate list");
        set_result_word(&mut vm, 0, list);
        assert_eq!(
            decode_entrypoint_return(&vm, &schema).expect("decode nested sums"),
            norito::json!([
                { "some": { "ok": "1.25" } },
                { "some": { "err": true } },
                { "none": true },
            ])
        );
        let forged =
            crate::sum::allocate_words(&mut vm, result_layout, 0, &[1]).expect("Result to forge");
        vm.store_u64(forged, 2).expect("forge Result tag");
        let some_forged = crate::sum::allocate_words(&mut vm, option_layout, 1, &[forged])
            .expect("Option with forged Result");
        let forged_list = crate::list::allocate_words(&mut vm, list_layout, &[vec![some_forged]])
            .expect("list with forged Result");
        set_result_word(&mut vm, 0, forged_list);
        assert!(matches!(
            encode_entrypoint_return_record(&vm, &schema),
            Err(EntrypointReturnDecodeError::InvalidValue { kind: "Result", .. })
        ));
    }
}

#[cfg(test)]
mod materialize_tests;
#[cfg(test)]
pub(crate) use materialize_tests::complete_test_result;
