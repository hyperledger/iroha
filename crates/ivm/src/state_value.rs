//! Compiler-internal canonical codec for aggregate durable-state values.
use crate::{
    VMError,
    host::preflight_reserved_syscall_gas,
    ivm::IVM,
    pointer_abi::{self, PointerType, Tlv},
};
use iroha_crypto::Hash;
use iroha_data_model::{
    account::AccountId,
    prelude::{AssetDefinitionId, AssetId, NftId},
    soracloud::{SoracloudHostRequestEnvelopeV1, SoracloudHostResponseEnvelopeV1},
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::{
    json::Json,
    numeric_abi::{DecimalValueV1, IntValueV1, QuantityValueV1},
};
use ivm_abi::state_value::{
    MAX_STATE_VALUE_RECORD_BYTES, MAX_STATE_VALUE_SCHEMA_BYTES, MAX_STATE_VALUE_WORDS,
    StateValueAtomV1, StateValueKindV1, StateValueNodeV1, StateValueRecordV1, StateValueSchemaV1,
    state_value_schema_for_embedded_type_v1, state_value_schema_hash_v1,
};
use ivm_abi::sum::SumLayoutV1;
use ivm_abi::{codec::encode_canonical_norito, list::ListLayoutV1};
#[cfg(test)]
use norito::{decode_from_bytes, to_bytes};
const STATE_VALUE_GAS_BASE: u64 = 32;
type AddressResolver = fn(&IVM, u64) -> u64;
fn gas(bytes: usize, words: usize) -> u64 {
    STATE_VALUE_GAS_BASE
        .saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX))
        .saturating_add(u64::try_from(words).unwrap_or(u64::MAX))
}
fn load_tlv<'a>(
    vm: &'a IVM,
    address: u64,
    resolver: AddressResolver,
) -> Result<(&'a [u8], Tlv<'a>), VMError> {
    let original_address = address;
    let address = resolver(vm, address);
    let tlv = vm.validate_tlv(address).inspect_err(|error| {
        if crate::dev_env::decode_trace_enabled() {
            eprintln!(
                "[state-value] invalid TLV pointer original=0x{original_address:016x} resolved=0x{address:016x}: {error:?}"
            );
        }
    })?;
    let total = 7usize
        .checked_add(tlv.payload.len())
        .and_then(|len| len.checked_add(Hash::LENGTH))
        .ok_or(VMError::NoritoInvalid)?;
    let envelope = vm.memory.load_region(
        address,
        u64::try_from(total).map_err(|_| VMError::NoritoInvalid)?,
    )?;
    Ok((envelope, tlv))
}
fn load_expected_tlv<'a>(
    vm: &'a IVM,
    address: u64,
    expected: PointerType,
    resolver: AddressResolver,
) -> Result<(&'a [u8], Tlv<'a>), VMError> {
    let (envelope, tlv) = load_tlv(vm, address, resolver)?;
    if tlv.type_id != expected {
        if crate::dev_env::decode_trace_enabled() {
            eprintln!(
                "[state-value] TLV type mismatch pointer=0x{address:016x} expected={expected:?} actual={:?}",
                tlv.type_id
            );
        }
        return Err(VMError::NoritoInvalid);
    }
    Ok((envelope, tlv))
}
fn decode_schema(
    vm: &IVM,
    address: u64,
    resolver: AddressResolver,
) -> Result<(StateValueSchemaV1, &[u8]), VMError> {
    let (_, tlv) = load_expected_tlv(vm, address, PointerType::NoritoBytes, resolver)?;
    if tlv.payload.len() > MAX_STATE_VALUE_SCHEMA_BYTES {
        return Err(VMError::NoritoInvalid);
    }
    let schema: StateValueSchemaV1 = decode_canonical_norito(tlv.payload)?;
    if !schema.validate() {
        return Err(VMError::DecodeError);
    }
    Ok((schema, tlv.payload))
}
fn decode_canonical_norito<T>(payload: &[u8]) -> Result<T, VMError>
where
    T: for<'__frame> norito::NoritoDeserialize<'__frame> + norito::NoritoSerialize,
{
    norito::decode_canonical(payload).map_err(|error| match error {
        norito::Error::AllocationFailed { .. } => {
            VMError::ExecutionDeferred(crate::ExecutionDeferral::AllocationUnavailable)
        }
        _ => VMError::DecodeError,
    })
}
fn validate_pointer_payload(kind: StateValueKindV1, payload: &[u8]) -> Result<(), VMError> {
    match kind {
        StateValueKindV1::Bool => return Err(VMError::DecodeError),
        StateValueKindV1::Int => {
            IntValueV1::decode_frame(payload).map_err(|_| VMError::DecodeError)?;
        }
        StateValueKindV1::Decimal => {
            DecimalValueV1::decode_frame(payload).map_err(|_| VMError::DecodeError)?;
        }
        StateValueKindV1::Quantity => {
            QuantityValueV1::decode_frame(payload).map_err(|_| VMError::DecodeError)?;
        }
        StateValueKindV1::String => {
            std::str::from_utf8(payload).map_err(|_| VMError::DecodeError)?;
        }
        StateValueKindV1::Json => {
            let _: Json = decode_canonical_norito(payload)?;
        }
        StateValueKindV1::Bytes => {}
        StateValueKindV1::AccountId => {
            let _: AccountId = decode_canonical_norito(payload)?;
        }
        StateValueKindV1::AssetDefinitionId => {
            let _: AssetDefinitionId = decode_canonical_norito(payload)?;
        }
        StateValueKindV1::AssetId => {
            let _: AssetId = decode_canonical_norito(payload)?;
        }
        StateValueKindV1::DomainId => {
            let _: DomainId = decode_canonical_norito(payload)?;
        }
        StateValueKindV1::NftId => {
            let _: NftId = decode_canonical_norito(payload)?;
        }
        StateValueKindV1::Name => {
            let _: Name = decode_canonical_norito(payload)?;
        }
        StateValueKindV1::DataSpaceId => {
            let _: DataSpaceId = decode_canonical_norito(payload)?;
        }
        StateValueKindV1::AxtDescriptor => {
            let value: crate::axt::AxtDescriptor = decode_canonical_norito(payload)?;
            crate::axt::validate_descriptor(&value).map_err(|_| VMError::DecodeError)?;
        }
        StateValueKindV1::ProofBlob => {
            let value: crate::axt::ProofBlob = decode_canonical_norito(payload)?;
            crate::axt::validate_proof_blob(&value).map_err(|_| VMError::DecodeError)?;
        }
        StateValueKindV1::SoracloudRequest => {
            let value: SoracloudHostRequestEnvelopeV1 = decode_canonical_norito(payload)?;
            value.validate().map_err(|_| VMError::DecodeError)?;
        }
        StateValueKindV1::SoracloudResponse => {
            let value: SoracloudHostResponseEnvelopeV1 = decode_canonical_norito(payload)?;
            value.validate().map_err(|_| VMError::DecodeError)?;
        }
    }
    Ok(())
}
fn encode_tlv(pointer_type: PointerType, payload: &[u8]) -> Result<Vec<u8>, VMError> {
    let payload_len = u32::try_from(payload.len()).map_err(|_| VMError::NoritoInvalid)?;
    let mut out = Vec::with_capacity(7 + payload.len() + Hash::LENGTH);
    out.extend_from_slice(&(pointer_type as u16).to_be_bytes());
    out.push(1);
    out.extend_from_slice(&payload_len.to_be_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(Hash::new(payload).as_ref());
    Ok(out)
}
fn table_words(vm: &IVM, address: u64, count: usize) -> Result<Vec<u64>, VMError> {
    if count > MAX_STATE_VALUE_WORDS || !address.is_multiple_of(8) {
        return Err(VMError::NoritoInvalid);
    }
    let byte_len = count.checked_mul(8).ok_or(VMError::NoritoInvalid)?;
    if byte_len == 0 {
        return Ok(Vec::new());
    }
    vm.ensure_public_memory(
        address,
        u64::try_from(byte_len).map_err(|_| VMError::NoritoInvalid)?,
    )?;
    let bytes = vm.memory.load_region(
        address,
        u64::try_from(byte_len).map_err(|_| VMError::NoritoInvalid)?,
    )?;
    Ok(bytes
        .chunks_exact(8)
        .map(|chunk| u64::from_le_bytes(chunk.try_into().expect("eight-byte chunk")))
        .collect())
}
fn skip_state_node(nodes: &[StateValueNodeV1], node_index: &mut usize) -> Result<(), VMError> {
    let mut pending = 1_usize;
    while pending != 0 {
        pending -= 1;
        let node = nodes.get(*node_index).ok_or(VMError::DecodeError)?;
        *node_index = node_index.checked_add(1).ok_or(VMError::DecodeError)?;
        let children = match node {
            StateValueNodeV1::Struct { fields, .. } => fields.len(),
            StateValueNodeV1::Tuple { arity } => usize::from(*arity),
            StateValueNodeV1::Option => 1,
            StateValueNodeV1::Result => 2,
            StateValueNodeV1::List { .. }
            | StateValueNodeV1::Leaf(_)
            | StateValueNodeV1::Unit
            | StateValueNodeV1::Error(_)
            | StateValueNodeV1::Enum(_)
            | StateValueNodeV1::StateCursor(_) => 0,
        };
        pending = pending.checked_add(children).ok_or(VMError::DecodeError)?;
    }
    Ok(())
}
fn state_node_word_count(
    nodes: &[StateValueNodeV1],
    node_index: &mut usize,
) -> Result<usize, VMError> {
    let mut pending = 1_usize;
    let mut words = 0_usize;
    while pending != 0 {
        pending -= 1;
        let node = nodes.get(*node_index).ok_or(VMError::DecodeError)?;
        *node_index = node_index.checked_add(1).ok_or(VMError::DecodeError)?;
        match node {
            StateValueNodeV1::Struct { fields, .. } => {
                words = words
                    .checked_add(usize::from(fields.is_empty()))
                    .ok_or(VMError::DecodeError)?;
                pending = pending
                    .checked_add(fields.len())
                    .ok_or(VMError::DecodeError)?;
            }
            StateValueNodeV1::Tuple { arity } => {
                pending = pending
                    .checked_add(usize::from(*arity))
                    .ok_or(VMError::DecodeError)?;
            }
            StateValueNodeV1::Option => {
                words = words.checked_add(1).ok_or(VMError::DecodeError)?;
                skip_state_node(nodes, node_index)?;
            }
            StateValueNodeV1::Result => {
                words = words.checked_add(1).ok_or(VMError::DecodeError)?;
                skip_state_node(nodes, node_index)?;
                skip_state_node(nodes, node_index)?;
            }
            StateValueNodeV1::List { .. }
            | StateValueNodeV1::Leaf(_)
            | StateValueNodeV1::Unit
            | StateValueNodeV1::Error(_)
            | StateValueNodeV1::Enum(_)
            | StateValueNodeV1::StateCursor(_) => {
                words = words.checked_add(1).ok_or(VMError::DecodeError)?;
            }
        }
    }
    Ok(words)
}
pub(crate) fn validate_state_pointer_atom(
    policy: ivm_abi::SyscallPolicy,
    kind: StateValueKindV1,
    envelope: &[u8],
) -> Result<(), VMError> {
    let expected = kind.pointer_type().ok_or(VMError::DecodeError)?;
    let tlv = pointer_abi::validate_tlv_bytes(envelope)?;
    if tlv.type_id != expected || !pointer_abi::is_type_allowed_for_policy(policy, tlv.type_id) {
        return Err(VMError::DecodeError);
    }
    // Exact envelope validation above has already authenticated these bytes;
    // rebuilding the same TLV would only repeat the payload hash.
    validate_pointer_payload(kind, tlv.payload)
}
fn validate_state_atoms_recursive(
    policy: ivm_abi::SyscallPolicy,
    nodes: &[StateValueNodeV1],
    atoms: &[StateValueAtomV1],
    node_index: &mut usize,
    atom_index: &mut usize,
) -> Result<(), VMError> {
    struct Cursor<'a> {
        nodes: &'a [StateValueNodeV1],
        atoms: &'a [StateValueAtomV1],
        node_index: usize,
        atom_index: usize,
    }
    enum Work {
        Validate(usize),
        Skip(usize),
        FinishStream(usize),
    }
    let mut cursors = vec![Cursor {
        nodes,
        atoms,
        node_index: *node_index,
        atom_index: *atom_index,
    }];
    let mut work = vec![Work::Validate(0)];
    while let Some(task) = work.pop() {
        match task {
            Work::Skip(cursor_id) => {
                let cursor = cursors.get_mut(cursor_id).ok_or(VMError::DecodeError)?;
                skip_state_node(cursor.nodes, &mut cursor.node_index)?;
            }
            Work::FinishStream(cursor_id) => {
                let cursor = cursors.get(cursor_id).ok_or(VMError::DecodeError)?;
                if cursor.node_index != cursor.nodes.len()
                    || cursor.atom_index != cursor.atoms.len()
                {
                    return Err(VMError::DecodeError);
                }
            }
            Work::Validate(cursor_id) => {
                let cursor = cursors.get_mut(cursor_id).ok_or(VMError::DecodeError)?;
                let cursor_nodes = cursor.nodes;
                let cursor_atoms = cursor.atoms;
                let node = cursor_nodes
                    .get(cursor.node_index)
                    .ok_or(VMError::DecodeError)?;
                cursor.node_index = cursor
                    .node_index
                    .checked_add(1)
                    .ok_or(VMError::DecodeError)?;
                match node {
                    StateValueNodeV1::Struct { fields, .. } => {
                        work.extend(
                            std::iter::repeat_with(|| Work::Validate(cursor_id)).take(fields.len()),
                        );
                    }
                    StateValueNodeV1::Tuple { arity } => {
                        work.extend(
                            std::iter::repeat_with(|| Work::Validate(cursor_id))
                                .take(usize::from(*arity)),
                        );
                    }
                    StateValueNodeV1::Option => {
                        let StateValueAtomV1::Tag(tag) = cursor_atoms
                            .get(cursor.atom_index)
                            .ok_or(VMError::DecodeError)?
                        else {
                            return Err(VMError::DecodeError);
                        };
                        cursor.atom_index = cursor
                            .atom_index
                            .checked_add(1)
                            .ok_or(VMError::DecodeError)?;
                        work.push(if *tag {
                            Work::Validate(cursor_id)
                        } else {
                            Work::Skip(cursor_id)
                        });
                    }
                    StateValueNodeV1::Result => {
                        let StateValueAtomV1::Tag(tag) = cursor_atoms
                            .get(cursor.atom_index)
                            .ok_or(VMError::DecodeError)?
                        else {
                            return Err(VMError::DecodeError);
                        };
                        cursor.atom_index = cursor
                            .atom_index
                            .checked_add(1)
                            .ok_or(VMError::DecodeError)?;
                        if *tag {
                            work.push(Work::Skip(cursor_id));
                            work.push(Work::Validate(cursor_id));
                        } else {
                            work.push(Work::Validate(cursor_id));
                            work.push(Work::Skip(cursor_id));
                        }
                    }
                    StateValueNodeV1::List { element, capacity } => {
                        let StateValueAtomV1::List(items) = cursor_atoms
                            .get(cursor.atom_index)
                            .ok_or(VMError::DecodeError)?
                        else {
                            return Err(VMError::DecodeError);
                        };
                        cursor.atom_index = cursor
                            .atom_index
                            .checked_add(1)
                            .ok_or(VMError::DecodeError)?;
                        if items.len() > usize::from(*capacity) {
                            return Err(VMError::DecodeError);
                        }
                        let first_cursor = cursors.len();
                        cursors.extend(items.iter().map(|item| Cursor {
                            nodes: &element.nodes,
                            atoms: item,
                            node_index: 0,
                            atom_index: 0,
                        }));
                        for item_cursor in (first_cursor..cursors.len()).rev() {
                            work.push(Work::FinishStream(item_cursor));
                            work.push(Work::Validate(item_cursor));
                        }
                    }
                    StateValueNodeV1::StateCursor(key) => {
                        let Some(StateValueAtomV1::Pointer(envelope)) =
                            cursor_atoms.get(cursor.atom_index)
                        else {
                            return Err(VMError::DecodeError);
                        };
                        ivm_abi::state_cursor::validate_cursor_envelope(
                            iroha_data_model::smart_contract::entrypoint::state_key_schema_hash_v1(
                                key,
                            )
                            .ok_or(VMError::DecodeError)?,
                            envelope,
                        )?;
                        cursor.atom_index = cursor
                            .atom_index
                            .checked_add(1)
                            .ok_or(VMError::DecodeError)?;
                    }
                    StateValueNodeV1::Unit
                    | StateValueNodeV1::Error(_)
                    | StateValueNodeV1::Enum(_) => {
                        match (node, cursor_atoms.get(cursor.atom_index)) {
                            (StateValueNodeV1::Unit, Some(StateValueAtomV1::Unit)) => {}
                            (
                                StateValueNodeV1::Error(error),
                                Some(StateValueAtomV1::ErrorCode(code)),
                            ) if error.variant(*code).is_some() => {}
                            (
                                StateValueNodeV1::Enum(descriptor),
                                Some(StateValueAtomV1::EnumCode(code)),
                            ) if descriptor.variant(*code).is_some() => {}
                            _ => return Err(VMError::DecodeError),
                        }
                        cursor.atom_index = cursor
                            .atom_index
                            .checked_add(1)
                            .ok_or(VMError::DecodeError)?;
                    }
                    StateValueNodeV1::Leaf(StateValueKindV1::Bool) => {
                        if !matches!(
                            cursor_atoms.get(cursor.atom_index),
                            Some(StateValueAtomV1::Bool(_))
                        ) {
                            return Err(VMError::DecodeError);
                        }
                        cursor.atom_index = cursor
                            .atom_index
                            .checked_add(1)
                            .ok_or(VMError::DecodeError)?;
                    }
                    StateValueNodeV1::Leaf(kind) => {
                        let StateValueAtomV1::Pointer(envelope) = cursor_atoms
                            .get(cursor.atom_index)
                            .ok_or(VMError::DecodeError)?
                        else {
                            return Err(VMError::DecodeError);
                        };
                        validate_state_pointer_atom(policy, *kind, envelope)?;
                        cursor.atom_index = cursor
                            .atom_index
                            .checked_add(1)
                            .ok_or(VMError::DecodeError)?;
                    }
                }
            }
        }
    }
    let root = cursors.first().ok_or(VMError::DecodeError)?;
    *node_index = root.node_index;
    *atom_index = root.atom_index;
    Ok(())
}
fn validate_state_atom_stream(
    policy: ivm_abi::SyscallPolicy,
    schema: &StateValueSchemaV1,
    atoms: &[StateValueAtomV1],
) -> Result<(), VMError> {
    let mut node_index = 0;
    let mut atom_index = 0;
    validate_state_atoms_recursive(
        policy,
        &schema.nodes,
        atoms,
        &mut node_index,
        &mut atom_index,
    )?;
    if node_index != schema.nodes.len() || atom_index != atoms.len() {
        return Err(VMError::DecodeError);
    }
    Ok(())
}
/// Reconstruct the exact compiler-owned durable-value schema embedded in CNTR.
pub(crate) fn schema_for_embedded_state_type(
    ty: &crate::metadata::EmbeddedStateType,
) -> Result<StateValueSchemaV1, VMError> {
    state_value_schema_for_embedded_type_v1(ty).ok_or(VMError::NoritoInvalid)
}
fn decode_validated_state_value_record(
    policy: ivm_abi::SyscallPolicy,
    schema: &StateValueSchemaV1,
    schema_payload: &[u8],
    payload: &[u8],
) -> Result<StateValueRecordV1, VMError> {
    if !schema.validate()
        || schema_payload.len() > MAX_STATE_VALUE_SCHEMA_BYTES
        || payload.len() > MAX_STATE_VALUE_RECORD_BYTES
    {
        return Err(VMError::NoritoInvalid);
    }
    let record: StateValueRecordV1 = decode_canonical_norito(payload)?;
    if record.schema_hash != state_value_schema_hash_v1(schema_payload) {
        return Err(VMError::DecodeError);
    }
    validate_state_atom_stream(policy, schema, &record.atoms)?;
    Ok(record)
}
/// Validate one persisted record against an exact CNTR-derived state schema.
pub(crate) fn validate_state_value_record(
    vm: &IVM,
    schema: &StateValueSchemaV1,
    payload: &[u8],
) -> Result<(), VMError> {
    validate_state_value_record_for_policy(vm.syscall_policy(), schema, payload)
}
pub(crate) fn validate_state_value_record_for_policy(
    policy: ivm_abi::SyscallPolicy,
    schema: &StateValueSchemaV1,
    payload: &[u8],
) -> Result<(), VMError> {
    let schema_payload = encode_canonical_norito(schema).map_err(|_| VMError::DecodeError)?;
    decode_validated_state_value_record(policy, schema, &schema_payload, payload).map(drop)
}
#[derive(Clone, Copy)]
struct StateEncodeContext<'a> {
    vm: &'a IVM,
    resolver: AddressResolver,
}
impl StateEncodeContext<'_> {
    fn resolve(self, pointer: u64) -> u64 {
        (self.resolver)(self.vm, pointer)
    }
}
struct StateAtomOutputArena {
    streams: Vec<Vec<StateValueAtomV1>>,
}
impl StateAtomOutputArena {
    fn new() -> Self {
        Self {
            streams: vec![Vec::new()],
        }
    }
}
impl Drop for StateAtomOutputArena {
    fn drop(&mut self) {
        let mut pending = std::mem::take(&mut self.streams);
        while let Some(mut stream) = pending.pop() {
            while let Some(atom) = stream.pop() {
                if let StateValueAtomV1::List(items) = atom {
                    pending.extend(items);
                }
            }
        }
    }
}
fn encode_state_node(
    nodes: &[StateValueNodeV1],
    node_index: &mut usize,
    words: &[u64],
    word_index: &mut usize,
    context: StateEncodeContext<'_>,
    atoms: &mut Vec<StateValueAtomV1>,
    pointer_bytes: &mut usize,
) -> Result<(), VMError> {
    enum WordStream<'a> {
        Borrowed(&'a [u64]),
        Owned(Vec<u64>),
    }
    impl WordStream<'_> {
        fn as_slice(&self) -> &[u64] {
            match self {
                Self::Borrowed(words) => words,
                Self::Owned(words) => words,
            }
        }
    }
    struct Cursor<'a> {
        nodes: &'a [StateValueNodeV1],
        node_index: usize,
        words: WordStream<'a>,
        word_index: usize,
        output: usize,
    }
    enum Work<'a> {
        Encode(usize),
        FinishCursor {
            cursor: usize,
            expected_node: usize,
            expected_word: usize,
        },
        FinishItem {
            cursor: usize,
            schema: &'a StateValueSchemaV1,
        },
        FinishList {
            parent_output: usize,
            item_outputs: Vec<usize>,
        },
    }
    let mut cursors = vec![Cursor {
        nodes,
        node_index: *node_index,
        words: WordStream::Borrowed(words),
        word_index: *word_index,
        output: 0,
    }];
    let mut outputs = StateAtomOutputArena::new();
    let mut work = vec![Work::Encode(0)];
    let mut encoded_pointer_bytes = 0_usize;
    while let Some(task) = work.pop() {
        match task {
            Work::FinishCursor {
                cursor,
                expected_node,
                expected_word,
            } => {
                let cursor = cursors.get(cursor).ok_or(VMError::DecodeError)?;
                if cursor.node_index != expected_node || cursor.word_index != expected_word {
                    return Err(VMError::DecodeError);
                }
            }
            Work::FinishItem { cursor, schema } => {
                let cursor = cursors.get(cursor).ok_or(VMError::DecodeError)?;
                if cursor.node_index != cursor.nodes.len()
                    || cursor.word_index != cursor.words.as_slice().len()
                {
                    return Err(VMError::DecodeError);
                }
                let item = outputs
                    .streams
                    .get(cursor.output)
                    .ok_or(VMError::DecodeError)?;
                validate_state_atom_stream(context.vm.syscall_policy(), schema, item)?;
            }
            Work::FinishList {
                parent_output,
                item_outputs,
            } => {
                let mut items = Vec::with_capacity(item_outputs.len());
                for output in item_outputs {
                    items.push(std::mem::take(
                        outputs
                            .streams
                            .get_mut(output)
                            .ok_or(VMError::DecodeError)?,
                    ));
                }
                outputs
                    .streams
                    .get_mut(parent_output)
                    .ok_or(VMError::DecodeError)?
                    .push(StateValueAtomV1::List(items));
            }
            Work::Encode(cursor_id) => {
                let cursor = cursors.get_mut(cursor_id).ok_or(VMError::DecodeError)?;
                let cursor_nodes = cursor.nodes;
                let cursor_output = cursor.output;
                let node = cursor_nodes
                    .get(cursor.node_index)
                    .ok_or(VMError::DecodeError)?;
                cursor.node_index = cursor
                    .node_index
                    .checked_add(1)
                    .ok_or(VMError::DecodeError)?;
                match node {
                    StateValueNodeV1::Struct { fields, .. } => {
                        if fields.is_empty() {
                            if cursor.words.as_slice().get(cursor.word_index) != Some(&0) {
                                return Err(VMError::DecodeError);
                            }
                            cursor.word_index = cursor
                                .word_index
                                .checked_add(1)
                                .ok_or(VMError::DecodeError)?;
                        }
                        work.extend(
                            std::iter::repeat_with(|| Work::Encode(cursor_id)).take(fields.len()),
                        );
                    }
                    StateValueNodeV1::Tuple { arity } => {
                        work.extend(
                            std::iter::repeat_with(|| Work::Encode(cursor_id))
                                .take(usize::from(*arity)),
                        );
                    }
                    StateValueNodeV1::Option => {
                        let pointer = *cursor
                            .words
                            .as_slice()
                            .get(cursor.word_index)
                            .ok_or(VMError::DecodeError)?;
                        cursor.word_index = cursor
                            .word_index
                            .checked_add(1)
                            .ok_or(VMError::DecodeError)?;
                        if pointer == 0 {
                            return Err(VMError::DecodeError);
                        }
                        let child_start = cursor.node_index;
                        let mut child_end = child_start;
                        let child_words = state_node_word_count(cursor_nodes, &mut child_end)?;
                        let layout = SumLayoutV1::option(
                            u64::try_from(child_words).map_err(|_| VMError::DecodeError)?,
                        )
                        .map_err(|_| VMError::DecodeError)?;
                        let (tag, payload) =
                            crate::sum::read_words(context.vm, context.resolve(pointer), layout)?;
                        outputs
                            .streams
                            .get_mut(cursor_output)
                            .ok_or(VMError::DecodeError)?
                            .push(StateValueAtomV1::Tag(tag));
                        cursor.node_index = child_end;
                        if tag {
                            let expected_word = payload.len();
                            let child_cursor = cursors.len();
                            cursors.push(Cursor {
                                nodes: cursor_nodes,
                                node_index: child_start,
                                words: WordStream::Owned(payload),
                                word_index: 0,
                                output: cursor_output,
                            });
                            work.push(Work::FinishCursor {
                                cursor: child_cursor,
                                expected_node: child_end,
                                expected_word,
                            });
                            work.push(Work::Encode(child_cursor));
                        } else if !payload.is_empty() {
                            return Err(VMError::DecodeError);
                        }
                        encoded_pointer_bytes = encoded_pointer_bytes.saturating_add(
                            usize::try_from(
                                layout
                                    .allocation_bytes()
                                    .map_err(|_| VMError::DecodeError)?,
                            )
                            .unwrap_or(usize::MAX),
                        );
                    }
                    StateValueNodeV1::Result => {
                        let pointer = *cursor
                            .words
                            .as_slice()
                            .get(cursor.word_index)
                            .ok_or(VMError::DecodeError)?;
                        cursor.word_index = cursor
                            .word_index
                            .checked_add(1)
                            .ok_or(VMError::DecodeError)?;
                        if pointer == 0 {
                            return Err(VMError::DecodeError);
                        }
                        let ok_start = cursor.node_index;
                        let mut ok_end = ok_start;
                        let ok_words = state_node_word_count(cursor_nodes, &mut ok_end)?;
                        let mut err_end = ok_end;
                        let err_words = state_node_word_count(cursor_nodes, &mut err_end)?;
                        let layout = SumLayoutV1::try_new(
                            u64::try_from(err_words).map_err(|_| VMError::DecodeError)?,
                            u64::try_from(ok_words).map_err(|_| VMError::DecodeError)?,
                        )
                        .map_err(|_| VMError::DecodeError)?;
                        let (tag, payload) =
                            crate::sum::read_words(context.vm, context.resolve(pointer), layout)?;
                        outputs
                            .streams
                            .get_mut(cursor_output)
                            .ok_or(VMError::DecodeError)?
                            .push(StateValueAtomV1::Tag(tag));
                        cursor.node_index = err_end;
                        let (active_start, active_end) = if tag {
                            (ok_start, ok_end)
                        } else {
                            (ok_end, err_end)
                        };
                        let expected_word = payload.len();
                        let child_cursor = cursors.len();
                        cursors.push(Cursor {
                            nodes: cursor_nodes,
                            node_index: active_start,
                            words: WordStream::Owned(payload),
                            word_index: 0,
                            output: cursor_output,
                        });
                        work.push(Work::FinishCursor {
                            cursor: child_cursor,
                            expected_node: active_end,
                            expected_word,
                        });
                        work.push(Work::Encode(child_cursor));
                        encoded_pointer_bytes = encoded_pointer_bytes.saturating_add(
                            usize::try_from(
                                layout
                                    .allocation_bytes()
                                    .map_err(|_| VMError::DecodeError)?,
                            )
                            .unwrap_or(usize::MAX),
                        );
                    }
                    StateValueNodeV1::List { element, capacity } => {
                        let pointer = *cursor
                            .words
                            .as_slice()
                            .get(cursor.word_index)
                            .ok_or(VMError::DecodeError)?;
                        cursor.word_index = cursor
                            .word_index
                            .checked_add(1)
                            .ok_or(VMError::DecodeError)?;
                        if pointer == 0 {
                            return Err(VMError::DecodeError);
                        }
                        let element_words = element.word_count().ok_or(VMError::DecodeError)?;
                        let layout = ListLayoutV1::try_new(
                            u64::from(*capacity),
                            u64::try_from(element_words).map_err(|_| VMError::DecodeError)?,
                        )
                        .map_err(|_| VMError::DecodeError)?;
                        let raw_items =
                            crate::list::read_words(context.vm, context.resolve(pointer), layout)?;
                        let parent_output = cursor_output;
                        let first_cursor = cursors.len();
                        let first_output = outputs.streams.len();
                        outputs
                            .streams
                            .extend((0..raw_items.len()).map(|_| Vec::new()));
                        cursors.extend(raw_items.into_iter().enumerate().map(
                            |(item_index, words)| Cursor {
                                nodes: &element.nodes,
                                node_index: 0,
                                words: WordStream::Owned(words),
                                word_index: 0,
                                output: first_output + item_index,
                            },
                        ));
                        let item_outputs =
                            (first_output..first_output + cursors.len() - first_cursor).collect();
                        work.push(Work::FinishList {
                            parent_output,
                            item_outputs,
                        });
                        for item_cursor in (first_cursor..cursors.len()).rev() {
                            work.push(Work::FinishItem {
                                cursor: item_cursor,
                                schema: element,
                            });
                            work.push(Work::Encode(item_cursor));
                        }
                        encoded_pointer_bytes = encoded_pointer_bytes.saturating_add(
                            usize::try_from(
                                layout
                                    .allocation_bytes()
                                    .map_err(|_| VMError::DecodeError)?,
                            )
                            .unwrap_or(usize::MAX),
                        );
                    }
                    StateValueNodeV1::Unit
                    | StateValueNodeV1::Error(_)
                    | StateValueNodeV1::Enum(_) => {
                        let word = *cursor
                            .words
                            .as_slice()
                            .get(cursor.word_index)
                            .ok_or(VMError::DecodeError)?;
                        cursor.word_index = cursor
                            .word_index
                            .checked_add(1)
                            .ok_or(VMError::DecodeError)?;
                        let atom = match node {
                            StateValueNodeV1::Unit if word == 0 => StateValueAtomV1::Unit,
                            StateValueNodeV1::Error(error) => {
                                let code = u32::try_from(word).map_err(|_| VMError::DecodeError)?;
                                error.variant(code).ok_or(VMError::DecodeError)?;
                                StateValueAtomV1::ErrorCode(code)
                            }
                            StateValueNodeV1::Enum(descriptor) => {
                                let code = u32::try_from(word).map_err(|_| VMError::DecodeError)?;
                                descriptor.variant(code).ok_or(VMError::DecodeError)?;
                                StateValueAtomV1::EnumCode(code)
                            }
                            _ => return Err(VMError::DecodeError),
                        };
                        outputs
                            .streams
                            .get_mut(cursor_output)
                            .ok_or(VMError::DecodeError)?
                            .push(atom);
                    }
                    StateValueNodeV1::Leaf(StateValueKindV1::Bool) => {
                        let word = *cursor
                            .words
                            .as_slice()
                            .get(cursor.word_index)
                            .ok_or(VMError::DecodeError)?;
                        cursor.word_index = cursor
                            .word_index
                            .checked_add(1)
                            .ok_or(VMError::DecodeError)?;
                        let value = match word {
                            0 => false,
                            1 => true,
                            _ => return Err(VMError::DecodeError),
                        };
                        outputs
                            .streams
                            .get_mut(cursor_output)
                            .ok_or(VMError::DecodeError)?
                            .push(StateValueAtomV1::Bool(value));
                    }
                    StateValueNodeV1::StateCursor(key) => {
                        let pointer = *cursor
                            .words
                            .as_slice()
                            .get(cursor.word_index)
                            .ok_or(VMError::DecodeError)?;
                        cursor.word_index = cursor
                            .word_index
                            .checked_add(1)
                            .ok_or(VMError::DecodeError)?;
                        let (envelope, _) = load_expected_tlv(
                            context.vm,
                            pointer,
                            PointerType::NoritoBytes,
                            context.resolver,
                        )?;
                        ivm_abi::state_cursor::validate_cursor_envelope(
                            iroha_data_model::smart_contract::entrypoint::state_key_schema_hash_v1(
                                key,
                            )
                            .ok_or(VMError::DecodeError)?,
                            envelope,
                        )?;
                        encoded_pointer_bytes =
                            encoded_pointer_bytes.saturating_add(envelope.len());
                        outputs
                            .streams
                            .get_mut(cursor_output)
                            .ok_or(VMError::DecodeError)?
                            .push(StateValueAtomV1::Pointer(envelope.to_vec()));
                    }
                    StateValueNodeV1::Leaf(StateValueKindV1::Bytes) => {
                        let pointer = *cursor
                            .words
                            .as_slice()
                            .get(cursor.word_index)
                            .ok_or(VMError::DecodeError)?;
                        cursor.word_index = cursor
                            .word_index
                            .checked_add(1)
                            .ok_or(VMError::DecodeError)?;
                        if pointer == 0 {
                            return Err(VMError::DecodeError);
                        }
                        let (envelope, tlv) = load_tlv(context.vm, pointer, context.resolver)?;
                        if !matches!(tlv.type_id, PointerType::Blob | PointerType::NoritoBytes) {
                            return Err(VMError::NoritoInvalid);
                        }
                        validate_pointer_payload(StateValueKindV1::Bytes, tlv.payload)?;
                        let canonical = encode_tlv(PointerType::Blob, tlv.payload)?;
                        encoded_pointer_bytes =
                            encoded_pointer_bytes.saturating_add(envelope.len());
                        outputs
                            .streams
                            .get_mut(cursor_output)
                            .ok_or(VMError::DecodeError)?
                            .push(StateValueAtomV1::Pointer(canonical));
                    }
                    StateValueNodeV1::Leaf(kind) => {
                        let pointer = *cursor
                            .words
                            .as_slice()
                            .get(cursor.word_index)
                            .ok_or(VMError::DecodeError)?;
                        cursor.word_index = cursor
                            .word_index
                            .checked_add(1)
                            .ok_or(VMError::DecodeError)?;
                        if pointer == 0 {
                            return Err(VMError::DecodeError);
                        }
                        let expected = kind.pointer_type().ok_or(VMError::DecodeError)?;
                        let (envelope, tlv) =
                            load_expected_tlv(context.vm, pointer, expected, context.resolver)?;
                        validate_pointer_payload(*kind, tlv.payload)?;
                        encoded_pointer_bytes =
                            encoded_pointer_bytes.saturating_add(envelope.len());
                        outputs
                            .streams
                            .get_mut(cursor_output)
                            .ok_or(VMError::DecodeError)?
                            .push(StateValueAtomV1::Pointer(envelope.to_vec()));
                    }
                }
            }
        }
    }
    let root = cursors.first().ok_or(VMError::DecodeError)?;
    *node_index = root.node_index;
    *word_index = root.word_index;
    atoms.extend(std::mem::take(
        outputs.streams.first_mut().ok_or(VMError::DecodeError)?,
    ));
    *pointer_bytes = pointer_bytes.saturating_add(encoded_pointer_bytes);
    Ok(())
}
/// Encode the compiler word table selected by `r11`/`r12` using the schema in `r10`.
pub(crate) fn encode_state_value(vm: &mut IVM, resolver: AddressResolver) -> Result<u64, VMError> {
    let (schema, schema_payload) = decode_schema(vm, vm.register(10), resolver)?;
    let count = usize::try_from(vm.register(12)).map_err(|_| VMError::NoritoInvalid)?;
    if count != schema.word_count().ok_or(VMError::DecodeError)? {
        return Err(VMError::DecodeError);
    }
    let words = table_words(vm, vm.register(11), count)?;
    let mut atoms = Vec::with_capacity(count);
    let mut pointer_bytes = 0_usize;
    let mut node_index = 0;
    let mut word_index = 0;
    encode_state_node(
        &schema.nodes,
        &mut node_index,
        &words,
        &mut word_index,
        StateEncodeContext { vm, resolver },
        &mut atoms,
        &mut pointer_bytes,
    )?;
    if node_index != schema.nodes.len()
        || word_index != words.len()
        || !schema.validate_atoms(&atoms)
    {
        return Err(VMError::DecodeError);
    }
    let record = StateValueRecordV1 {
        schema_hash: state_value_schema_hash_v1(schema_payload),
        atoms,
    };
    let payload = encode_canonical_norito(&record)?;
    if payload.len() > MAX_STATE_VALUE_RECORD_BYTES {
        return Err(VMError::NoritoInvalid);
    }
    let actual = gas(
        schema_payload
            .len()
            .saturating_add(count.saturating_mul(8))
            .saturating_add(pointer_bytes)
            .saturating_add(payload.len()),
        count,
    );
    preflight_reserved_syscall_gas(vm, actual)?;
    let out = encode_tlv(PointerType::NoritoBytes, &payload)?;
    let pointer = vm.alloc_host_tlv(&out)?;
    vm.set_register(10, pointer);
    Ok(actual)
}
enum PlannedStateWord {
    Scalar(u64),
    Pointer(Vec<u8>),
    Sum {
        layout: SumLayoutV1,
        tag: u64,
        active: Vec<usize>,
    },
    List {
        layout: ListLayoutV1,
        elements: Vec<Vec<usize>>,
    },
}
struct PlannedState {
    values: Vec<PlannedStateWord>,
    roots: Vec<usize>,
}
fn plan_state_atoms(
    nodes: &[StateValueNodeV1],
    atoms: &[StateValueAtomV1],
) -> Result<PlannedState, VMError> {
    struct Cursor<'a> {
        nodes: &'a [StateValueNodeV1],
        atoms: &'a [StateValueAtomV1],
        node_index: usize,
        atom_index: usize,
        output: usize,
    }
    enum Work {
        Plan(usize),
        FinishActive {
            parent_cursor: usize,
            child_cursor: usize,
            active_output: usize,
            expected_node: usize,
            expected_words: usize,
            layout: SumLayoutV1,
            tag: u64,
        },
        FinishItem {
            cursor: usize,
            output: usize,
            expected_words: usize,
        },
        FinishList {
            parent_output: usize,
            item_outputs: Vec<usize>,
            layout: ListLayoutV1,
        },
    }
    fn push_planned(
        values: &mut Vec<PlannedStateWord>,
        outputs: &mut [Vec<usize>],
        output: usize,
        value: PlannedStateWord,
    ) -> Result<(), VMError> {
        let value_id = values.len();
        values.push(value);
        outputs
            .get_mut(output)
            .ok_or(VMError::DecodeError)?
            .push(value_id);
        Ok(())
    }
    let mut cursors = vec![Cursor {
        nodes,
        atoms,
        node_index: 0,
        atom_index: 0,
        output: 0,
    }];
    let mut outputs = vec![Vec::new()];
    let mut values = Vec::new();
    let mut work = vec![Work::Plan(0)];
    while let Some(task) = work.pop() {
        match task {
            Work::FinishActive {
                parent_cursor,
                child_cursor,
                active_output,
                expected_node,
                expected_words,
                layout,
                tag,
            } => {
                let child = cursors.get(child_cursor).ok_or(VMError::DecodeError)?;
                if child.node_index != expected_node
                    || outputs
                        .get(active_output)
                        .ok_or(VMError::DecodeError)?
                        .len()
                        != expected_words
                {
                    return Err(VMError::DecodeError);
                }
                let child_atom_index = child.atom_index;
                cursors
                    .get_mut(parent_cursor)
                    .ok_or(VMError::DecodeError)?
                    .atom_index = child_atom_index;
                let active =
                    std::mem::take(outputs.get_mut(active_output).ok_or(VMError::DecodeError)?);
                let parent_output = cursors
                    .get(parent_cursor)
                    .ok_or(VMError::DecodeError)?
                    .output;
                push_planned(
                    &mut values,
                    &mut outputs,
                    parent_output,
                    PlannedStateWord::Sum {
                        layout,
                        tag,
                        active,
                    },
                )?;
            }
            Work::FinishItem {
                cursor,
                output,
                expected_words,
            } => {
                let cursor = cursors.get(cursor).ok_or(VMError::DecodeError)?;
                if cursor.node_index != cursor.nodes.len()
                    || cursor.atom_index != cursor.atoms.len()
                    || outputs.get(output).ok_or(VMError::DecodeError)?.len() != expected_words
                {
                    return Err(VMError::DecodeError);
                }
            }
            Work::FinishList {
                parent_output,
                item_outputs,
                layout,
                ..
            } => {
                let mut elements = Vec::with_capacity(item_outputs.len());
                for output in item_outputs {
                    elements.push(std::mem::take(
                        outputs.get_mut(output).ok_or(VMError::DecodeError)?,
                    ));
                }
                push_planned(
                    &mut values,
                    &mut outputs,
                    parent_output,
                    PlannedStateWord::List { layout, elements },
                )?;
            }
            Work::Plan(cursor_id) => {
                let cursor = cursors.get_mut(cursor_id).ok_or(VMError::DecodeError)?;
                let cursor_nodes = cursor.nodes;
                let cursor_atoms = cursor.atoms;
                let cursor_output = cursor.output;
                let node = cursor_nodes
                    .get(cursor.node_index)
                    .ok_or(VMError::DecodeError)?;
                cursor.node_index = cursor
                    .node_index
                    .checked_add(1)
                    .ok_or(VMError::DecodeError)?;
                match node {
                    StateValueNodeV1::Struct { fields, .. } => {
                        if fields.is_empty() {
                            push_planned(
                                &mut values,
                                &mut outputs,
                                cursor_output,
                                PlannedStateWord::Scalar(0),
                            )?;
                        }
                        work.extend(
                            std::iter::repeat_with(|| Work::Plan(cursor_id)).take(fields.len()),
                        );
                    }
                    StateValueNodeV1::Tuple { arity } => {
                        work.extend(
                            std::iter::repeat_with(|| Work::Plan(cursor_id))
                                .take(usize::from(*arity)),
                        );
                    }
                    StateValueNodeV1::Option => {
                        let StateValueAtomV1::Tag(tag) = cursor_atoms
                            .get(cursor.atom_index)
                            .ok_or(VMError::DecodeError)?
                        else {
                            return Err(VMError::DecodeError);
                        };
                        let tag = *tag;
                        cursor.atom_index = cursor
                            .atom_index
                            .checked_add(1)
                            .ok_or(VMError::DecodeError)?;
                        let child_start = cursor.node_index;
                        let mut child_end = child_start;
                        let child_words = state_node_word_count(cursor_nodes, &mut child_end)?;
                        cursor.node_index = child_end;
                        let layout = SumLayoutV1::option(
                            u64::try_from(child_words).map_err(|_| VMError::DecodeError)?,
                        )
                        .map_err(|_| VMError::DecodeError)?;
                        if tag {
                            let active_output = outputs.len();
                            outputs.push(Vec::with_capacity(child_words));
                            let child_atom_index = cursor.atom_index;
                            let child_cursor = cursors.len();
                            cursors.push(Cursor {
                                nodes: cursor_nodes,
                                atoms: cursor_atoms,
                                node_index: child_start,
                                atom_index: child_atom_index,
                                output: active_output,
                            });
                            work.push(Work::FinishActive {
                                parent_cursor: cursor_id,
                                child_cursor,
                                active_output,
                                expected_node: child_end,
                                expected_words: child_words,
                                layout,
                                tag: 1,
                            });
                            work.push(Work::Plan(child_cursor));
                        } else {
                            push_planned(
                                &mut values,
                                &mut outputs,
                                cursor_output,
                                PlannedStateWord::Sum {
                                    layout,
                                    tag: 0,
                                    active: Vec::new(),
                                },
                            )?;
                        }
                    }
                    StateValueNodeV1::Result => {
                        let StateValueAtomV1::Tag(tag) = cursor_atoms
                            .get(cursor.atom_index)
                            .ok_or(VMError::DecodeError)?
                        else {
                            return Err(VMError::DecodeError);
                        };
                        let tag = *tag;
                        cursor.atom_index = cursor
                            .atom_index
                            .checked_add(1)
                            .ok_or(VMError::DecodeError)?;
                        let ok_start = cursor.node_index;
                        let mut ok_end = ok_start;
                        let ok_words = state_node_word_count(cursor_nodes, &mut ok_end)?;
                        let mut err_end = ok_end;
                        let err_words = state_node_word_count(cursor_nodes, &mut err_end)?;
                        cursor.node_index = err_end;
                        let layout = SumLayoutV1::try_new(
                            u64::try_from(err_words).map_err(|_| VMError::DecodeError)?,
                            u64::try_from(ok_words).map_err(|_| VMError::DecodeError)?,
                        )
                        .map_err(|_| VMError::DecodeError)?;
                        let (active_start, active_end, active_words) = if tag {
                            (ok_start, ok_end, ok_words)
                        } else {
                            (ok_end, err_end, err_words)
                        };
                        let active_output = outputs.len();
                        outputs.push(Vec::with_capacity(active_words));
                        let child_atom_index = cursor.atom_index;
                        let child_cursor = cursors.len();
                        cursors.push(Cursor {
                            nodes: cursor_nodes,
                            atoms: cursor_atoms,
                            node_index: active_start,
                            atom_index: child_atom_index,
                            output: active_output,
                        });
                        work.push(Work::FinishActive {
                            parent_cursor: cursor_id,
                            child_cursor,
                            active_output,
                            expected_node: active_end,
                            expected_words: active_words,
                            layout,
                            tag: u64::from(tag),
                        });
                        work.push(Work::Plan(child_cursor));
                    }
                    StateValueNodeV1::List { element, capacity } => {
                        let StateValueAtomV1::List(items) = cursor_atoms
                            .get(cursor.atom_index)
                            .ok_or(VMError::DecodeError)?
                        else {
                            return Err(VMError::DecodeError);
                        };
                        cursor.atom_index = cursor
                            .atom_index
                            .checked_add(1)
                            .ok_or(VMError::DecodeError)?;
                        if items.len() > usize::from(*capacity) {
                            return Err(VMError::DecodeError);
                        }
                        let element_words = element.word_count().ok_or(VMError::DecodeError)?;
                        let layout = ListLayoutV1::try_new(
                            u64::from(*capacity),
                            u64::try_from(element_words).map_err(|_| VMError::DecodeError)?,
                        )
                        .map_err(|_| VMError::DecodeError)?;
                        let parent_output = cursor_output;
                        let first_cursor = cursors.len();
                        let first_output = outputs.len();
                        outputs.extend((0..items.len()).map(|_| Vec::with_capacity(element_words)));
                        cursors.extend(items.iter().enumerate().map(|(item_index, item)| Cursor {
                            nodes: &element.nodes,
                            atoms: item,
                            node_index: 0,
                            atom_index: 0,
                            output: first_output + item_index,
                        }));
                        let item_outputs =
                            (first_output..first_output + cursors.len() - first_cursor).collect();
                        work.push(Work::FinishList {
                            parent_output,
                            item_outputs,
                            layout,
                        });
                        for item_cursor in (first_cursor..cursors.len()).rev() {
                            work.push(Work::FinishItem {
                                cursor: item_cursor,
                                output: cursors[item_cursor].output,
                                expected_words: element_words,
                            });
                            work.push(Work::Plan(item_cursor));
                        }
                    }
                    StateValueNodeV1::Unit
                    | StateValueNodeV1::Error(_)
                    | StateValueNodeV1::Enum(_) => {
                        let scalar = match (node, cursor_atoms.get(cursor.atom_index)) {
                            (StateValueNodeV1::Unit, Some(StateValueAtomV1::Unit)) => 0,
                            (
                                StateValueNodeV1::Error(error),
                                Some(StateValueAtomV1::ErrorCode(code)),
                            ) if error.variant(*code).is_some() => u64::from(*code),
                            (
                                StateValueNodeV1::Enum(descriptor),
                                Some(StateValueAtomV1::EnumCode(code)),
                            ) if descriptor.variant(*code).is_some() => u64::from(*code),
                            _ => return Err(VMError::DecodeError),
                        };
                        cursor.atom_index = cursor
                            .atom_index
                            .checked_add(1)
                            .ok_or(VMError::DecodeError)?;
                        push_planned(
                            &mut values,
                            &mut outputs,
                            cursor_output,
                            PlannedStateWord::Scalar(scalar),
                        )?;
                    }
                    StateValueNodeV1::Leaf(StateValueKindV1::Bool) => {
                        let StateValueAtomV1::Bool(value) = cursor_atoms
                            .get(cursor.atom_index)
                            .ok_or(VMError::DecodeError)?
                        else {
                            return Err(VMError::DecodeError);
                        };
                        let value = *value;
                        cursor.atom_index = cursor
                            .atom_index
                            .checked_add(1)
                            .ok_or(VMError::DecodeError)?;
                        push_planned(
                            &mut values,
                            &mut outputs,
                            cursor_output,
                            PlannedStateWord::Scalar(u64::from(value)),
                        )?;
                    }
                    StateValueNodeV1::Leaf(_) | StateValueNodeV1::StateCursor(_) => {
                        let StateValueAtomV1::Pointer(envelope) = cursor_atoms
                            .get(cursor.atom_index)
                            .ok_or(VMError::DecodeError)?
                        else {
                            return Err(VMError::DecodeError);
                        };
                        cursor.atom_index = cursor
                            .atom_index
                            .checked_add(1)
                            .ok_or(VMError::DecodeError)?;
                        push_planned(
                            &mut values,
                            &mut outputs,
                            cursor_output,
                            PlannedStateWord::Pointer(envelope.clone()),
                        )?;
                    }
                }
            }
        }
    }
    let root = cursors.first().ok_or(VMError::DecodeError)?;
    if root.node_index != nodes.len() || root.atom_index != atoms.len() {
        return Err(VMError::DecodeError);
    }
    Ok(PlannedState {
        values,
        roots: std::mem::take(outputs.first_mut().ok_or(VMError::DecodeError)?),
    })
}
fn planned_state_bytes(planned: &PlannedState) -> usize {
    planned.values.iter().fold(0_usize, |bytes, value| {
        let value_bytes = match value {
            PlannedStateWord::Scalar(_) => 0,
            PlannedStateWord::Pointer(envelope) => envelope.len(),
            PlannedStateWord::Sum { layout, .. } => layout
                .allocation_bytes()
                .ok()
                .and_then(|bytes| usize::try_from(bytes).ok())
                .unwrap_or(usize::MAX),
            PlannedStateWord::List { layout, .. } => layout
                .allocation_bytes()
                .ok()
                .and_then(|bytes| usize::try_from(bytes).ok())
                .unwrap_or(usize::MAX),
        };
        bytes.saturating_add(value_bytes)
    })
}
fn planned_state_allocation_shape(planned: &PlannedState, tlv_lengths: &mut Vec<usize>) -> usize {
    planned.values.iter().fold(0_usize, |bytes, value| {
        let value_bytes = match value {
            PlannedStateWord::Scalar(_) => 0,
            PlannedStateWord::Pointer(envelope) => {
                tlv_lengths.push(envelope.len());
                0
            }
            PlannedStateWord::Sum { layout, .. } => layout
                .allocation_bytes()
                .ok()
                .and_then(|bytes| usize::try_from(bytes).ok())
                .unwrap_or(usize::MAX),
            PlannedStateWord::List { layout, .. } => layout
                .allocation_bytes()
                .ok()
                .and_then(|bytes| usize::try_from(bytes).ok())
                .unwrap_or(usize::MAX),
        };
        bytes.saturating_add(value_bytes)
    })
}
fn materialize_state_words(vm: &mut IVM, planned: &PlannedState) -> Result<Vec<u64>, VMError> {
    let mut materialized = Vec::with_capacity(planned.values.len());
    for value in &planned.values {
        let word = match value {
            PlannedStateWord::Scalar(value) => *value,
            PlannedStateWord::Pointer(envelope) => vm.alloc_host_tlv(envelope)?,
            PlannedStateWord::Sum {
                layout,
                tag,
                active,
            } => {
                let mut payload = Vec::with_capacity(active.len());
                for value in active {
                    payload.push(*materialized.get(*value).ok_or(VMError::DecodeError)?);
                }
                crate::sum::allocate_words(vm, *layout, *tag, &payload)?
            }
            PlannedStateWord::List { layout, elements } => {
                let width =
                    usize::try_from(layout.element_words()).map_err(|_| VMError::DecodeError)?;
                let mut words = Vec::with_capacity(elements.len());
                for element in elements {
                    let mut item = Vec::with_capacity(width);
                    for value in element {
                        item.push(*materialized.get(*value).ok_or(VMError::DecodeError)?);
                    }
                    if item.len() != width {
                        return Err(VMError::DecodeError);
                    }
                    words.push(item);
                }
                crate::list::allocate_words(vm, *layout, &words)?
            }
        };
        materialized.push(word);
    }
    planned
        .roots
        .iter()
        .map(|root| materialized.get(*root).copied().ok_or(VMError::DecodeError))
        .collect()
}
/// Decode the record in `r11`, returning an aligned Blob word table in `r10`.
pub(crate) fn decode_state_value(vm: &mut IVM, resolver: AddressResolver) -> Result<u64, VMError> {
    let (schema, schema_payload) = decode_schema(vm, vm.register(10), resolver)?;
    let record_pointer = vm.register(11);
    if record_pointer == 0 {
        // Missing durable values are not valid typed values. StateMap.get/remove
        // branch on presence before typed decoding; top-level Scalar/aggregate
        // state must have been initialized by `hajimari`/`始まり`.
        return Err(VMError::DecodeError);
    }
    let (_, tlv) = load_expected_tlv(vm, record_pointer, PointerType::NoritoBytes, resolver)?;
    if tlv.payload.len() > MAX_STATE_VALUE_RECORD_BYTES {
        return Err(VMError::NoritoInvalid);
    }
    let record = decode_validated_state_value_record(
        vm.syscall_policy(),
        &schema,
        schema_payload,
        tlv.payload,
    )?;
    let atoms = &record.atoms;
    let record_len = tlv.payload.len();
    let planned = plan_state_atoms(&schema.nodes, atoms)?;
    if planned.roots.len() != schema.word_count().ok_or(VMError::DecodeError)? {
        return Err(VMError::DecodeError);
    }
    let pointer_bytes = planned_state_bytes(&planned);
    let table_payload_len = 1usize.saturating_add(planned.roots.len().saturating_mul(8));
    let actual = gas(
        schema_payload
            .len()
            .saturating_add(record_len)
            .saturating_add(pointer_bytes)
            .saturating_add(table_payload_len),
        planned.roots.len(),
    );
    preflight_reserved_syscall_gas(vm, actual)?;
    let mut tlv_lengths = Vec::new();
    let raw_heap_bytes = planned_state_allocation_shape(&planned, &mut tlv_lengths);
    tlv_lengths.push(
        7_usize
            .saturating_add(table_payload_len)
            .saturating_add(Hash::LENGTH),
    );
    vm.preflight_host_tlv_allocations(&tlv_lengths)?;
    let raw_heap_bytes = u64::try_from(raw_heap_bytes).map_err(|_| VMError::OutOfMemory)?;
    if vm
        .memory
        .heap_allocated_len()
        .checked_add(raw_heap_bytes)
        .ok_or(VMError::OutOfMemory)?
        > vm.memory.heap_limit()
    {
        return Err(VMError::OutOfMemory);
    }
    let words = materialize_state_words(vm, &planned)?;
    let mut table = Vec::with_capacity(table_payload_len);
    table.push(0);
    for word in words {
        table.extend_from_slice(&word.to_le_bytes());
    }
    let out = encode_tlv(PointerType::Blob, &table)?;
    let pointer = vm.alloc_host_tlv(&out)?;
    vm.set_register(10, pointer);
    Ok(actual)
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_model_base::topology::DataSpaceId;
    use iroha_primitives::{bigint::BigInt, numeric::Quantity};
    use ivm_abi::state_value::{
        StateValueAtomV1, StateValueNodeV1, StateValueRecordV1, StateValueSchemaV1,
    };
    fn identity_address(_vm: &IVM, address: u64) -> u64 {
        address
    }
    fn install_schema(vm: &mut IVM, schema: &StateValueSchemaV1) -> u64 {
        let payload = to_bytes(schema).expect("schema bytes");
        let envelope = encode_tlv(PointerType::NoritoBytes, &payload).expect("schema TLV");
        vm.alloc_host_tlv(&envelope).expect("install schema")
    }
    fn install_int(vm: &mut IVM, value: i64) -> u64 {
        let frame = IntValueV1::try_new(BigInt::from_i128(i128::from(value)))
            .expect("test int is inside V1 domain")
            .encode_frame()
            .expect("canonical int frame");
        let envelope = encode_tlv(PointerType::Int, &frame).expect("int TLV");
        vm.alloc_host_tlv(&envelope).expect("install int")
    }
    fn install_quantity(vm: &mut IVM, value: &str) -> u64 {
        let quantity = value.parse().expect("canonical quantity");
        let frame = QuantityValueV1::new(quantity)
            .encode_frame()
            .expect("canonical quantity frame");
        let envelope = encode_tlv(PointerType::Quantity, &frame).expect("quantity TLV");
        vm.alloc_host_tlv(&envelope).expect("install quantity")
    }
    fn nested_singleton_list_schema(depth: usize) -> StateValueSchemaV1 {
        (0..depth).fold(
            StateValueSchemaV1 {
                nodes: vec![StateValueNodeV1::Leaf(StateValueKindV1::Bool)],
            },
            |element, _| StateValueSchemaV1 {
                nodes: vec![StateValueNodeV1::List {
                    element: Box::new(element),
                    capacity: 1,
                }],
            },
        )
    }
    fn nested_active_option_schema(depth: usize) -> StateValueSchemaV1 {
        let mut nodes = Vec::with_capacity(depth + 1);
        nodes.extend((0..depth).map(|_| StateValueNodeV1::Option));
        nodes.push(StateValueNodeV1::Leaf(StateValueKindV1::Bool));
        StateValueSchemaV1 { nodes }
    }
    fn nested_singleton_list_value(vm: &mut IVM, depth: usize, mut word: u64) -> u64 {
        let layout = ListLayoutV1::try_new(1, 1).expect("singleton List layout");
        for _ in 0..depth {
            word = crate::list::allocate_words(vm, layout, &[vec![word]])
                .expect("allocate nested singleton List");
        }
        word
    }
    fn read_singleton_lists(vm: &IVM, mut word: u64, depth: usize) -> u64 {
        let layout = ListLayoutV1::try_new(1, 1).expect("singleton List layout");
        for _ in 0..depth {
            let items = crate::list::read_words(vm, word, layout).expect("read singleton List");
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].len(), 1);
            word = items[0][0];
        }
        word
    }
    fn read_active_options(vm: &IVM, mut word: u64, depth: usize) -> u64 {
        let layout = SumLayoutV1::option(1).expect("Option layout");
        for _ in 0..depth {
            let (tag, payload) =
                crate::sum::read_words(vm, word, layout).expect("read active Option");
            assert!(tag);
            assert_eq!(payload.len(), 1);
            word = payload[0];
        }
        word
    }
    #[test]
    fn nested_list_runtime_walkers_are_stack_safe_at_the_v1_boundary() {
        const DEPTH: usize = 255;
        let worker = std::thread::Builder::new()
            .name("state-value-runtime-list-boundary".into())
            .stack_size(128 * 1024)
            .spawn(|| {
                let schema = nested_singleton_list_schema(DEPTH);
                assert!(schema.validate());
                assert_eq!(schema.word_count(), Some(1));
                let mut vm = IVM::new(u64::MAX);
                let schema_pointer = install_schema(&mut vm, &schema);
                let value = nested_singleton_list_value(&mut vm, DEPTH, 1);
                let table = vm.alloc_heap(8).expect("root word table");
                vm.store_u64(table, value).expect("store root List");
                vm.set_register(10, schema_pointer);
                vm.set_register(11, table);
                vm.set_register(12, 1);
                encode_state_value(&mut vm, identity_address).expect("encode nested Lists");
                let record_pointer = vm.register(10);
                let record_payload = vm
                    .validate_tlv(record_pointer)
                    .expect("nested List record")
                    .payload
                    .to_vec();
                validate_state_value_record(&vm, &schema, &record_payload)
                    .expect("validate nested List record");
                let record: StateValueRecordV1 =
                    decode_from_bytes(&record_payload).expect("decode nested List record");
                validate_state_atom_stream(vm.syscall_policy(), &schema, &record.atoms)
                    .expect("validate nested List atoms");
                let planned =
                    plan_state_atoms(&schema.nodes, &record.atoms).expect("plan nested Lists");
                assert_eq!(planned.roots.len(), 1);
                assert_eq!(planned.values.len(), DEPTH + 1);
                let mut planned_vm = IVM::new(u64::MAX);
                let planned_words = materialize_state_words(&mut planned_vm, &planned)
                    .expect("materialize nested Lists");
                assert_eq!(planned_words.len(), 1);
                assert_eq!(
                    read_singleton_lists(&planned_vm, planned_words[0], DEPTH),
                    1
                );
                vm.set_register(10, schema_pointer);
                vm.set_register(11, record_pointer);
                decode_state_value(&mut vm, identity_address).expect("decode nested Lists");
                let decoded_table = vm
                    .validate_tlv(vm.register(10))
                    .expect("decoded word table");
                let decoded_root = u64::from_le_bytes(
                    decoded_table.payload[1..9]
                        .try_into()
                        .expect("decoded root word"),
                );
                assert_eq!(read_singleton_lists(&vm, decoded_root, DEPTH), 1);
                let rejected_schema = nested_singleton_list_schema(DEPTH + 1);
                assert!(!rejected_schema.validate());
                assert!(
                    encode_canonical_norito(&rejected_schema).is_err(),
                    "256 nested Lists plus their leaf must exceed the 256-node V1 boundary"
                );
            })
            .expect("spawn small-stack nested List worker");
        worker.join().expect("small-stack nested List worker");
    }
    #[test]
    fn nested_list_encode_error_cleanup_is_stack_safe() {
        const INNER_DEPTH: usize = 254;
        let worker = std::thread::Builder::new()
            .name("state-value-runtime-list-error-cleanup".into())
            .stack_size(128 * 1024)
            .spawn(|| {
                let schema = StateValueSchemaV1 {
                    nodes: vec![StateValueNodeV1::List {
                        element: Box::new(nested_singleton_list_schema(INNER_DEPTH)),
                        capacity: 2,
                    }],
                };
                assert!(schema.validate());
                let mut vm = IVM::new(u64::MAX);
                let schema_pointer = install_schema(&mut vm, &schema);
                let valid = nested_singleton_list_value(&mut vm, INNER_DEPTH, 1);
                let invalid = nested_singleton_list_value(&mut vm, INNER_DEPTH, 2);
                let outer_layout = ListLayoutV1::try_new(2, 1).expect("outer List layout");
                let outer = crate::list::allocate_words(
                    &mut vm,
                    outer_layout,
                    &[vec![valid], vec![invalid]],
                )
                .expect("allocate mixed outer List");
                let table = vm.alloc_heap(8).expect("root word table");
                vm.store_u64(table, outer).expect("store outer List");
                let heap_before = vm.memory.heap_allocated_len();
                vm.set_register(10, schema_pointer);
                vm.set_register(11, table);
                vm.set_register(12, 1);
                assert_eq!(
                    encode_state_value(&mut vm, identity_address),
                    Err(VMError::DecodeError)
                );
                assert_eq!(vm.register(10), schema_pointer);
                assert_eq!(vm.memory.heap_allocated_len(), heap_before);
            })
            .expect("spawn small-stack List cleanup worker");
        worker.join().expect("small-stack List cleanup worker");
    }
    #[test]
    fn active_option_runtime_walkers_are_stack_safe_at_the_v1_boundary() {
        const DEPTH: usize = 255;
        let worker = std::thread::Builder::new()
            .name("state-value-runtime-option-boundary".into())
            .stack_size(128 * 1024)
            .spawn(|| {
                let schema = nested_active_option_schema(DEPTH);
                assert!(schema.validate());
                let mut skipped = 0;
                skip_state_node(&schema.nodes, &mut skipped).expect("skip nested Options");
                assert_eq!(skipped, DEPTH + 1);
                let mut counted = 0;
                assert_eq!(state_node_word_count(&schema.nodes, &mut counted), Ok(1));
                assert_eq!(counted, DEPTH + 1);
                let mut vm = IVM::new(u64::MAX);
                let schema_pointer = install_schema(&mut vm, &schema);
                let layout = SumLayoutV1::option(1).expect("Option layout");
                let mut value = 1_u64;
                for _ in 0..DEPTH {
                    value = crate::sum::allocate_words(&mut vm, layout, 1, &[value])
                        .expect("allocate active Option");
                }
                let table = vm.alloc_heap(8).expect("root word table");
                vm.store_u64(table, value).expect("store root Option");
                vm.set_register(10, schema_pointer);
                vm.set_register(11, table);
                vm.set_register(12, 1);
                encode_state_value(&mut vm, identity_address).expect("encode active Options");
                let record_pointer = vm.register(10);
                let record_payload = vm
                    .validate_tlv(record_pointer)
                    .expect("active Option record")
                    .payload
                    .to_vec();
                validate_state_value_record(&vm, &schema, &record_payload)
                    .expect("validate active Option record");
                let record: StateValueRecordV1 =
                    decode_from_bytes(&record_payload).expect("decode active Option record");
                let planned =
                    plan_state_atoms(&schema.nodes, &record.atoms).expect("plan active Options");
                assert_eq!(planned.roots.len(), 1);
                assert_eq!(planned.values.len(), DEPTH + 1);
                let mut planned_vm = IVM::new(u64::MAX);
                let planned_words = materialize_state_words(&mut planned_vm, &planned)
                    .expect("materialize active Options");
                assert_eq!(planned_words.len(), 1);
                assert_eq!(read_active_options(&planned_vm, planned_words[0], DEPTH), 1);
                validate_state_atom_stream(
                    vm.syscall_policy(),
                    &schema,
                    &[StateValueAtomV1::Tag(false)],
                )
                .expect("skip the inactive nested Option payload");
                vm.set_register(10, schema_pointer);
                vm.set_register(11, record_pointer);
                decode_state_value(&mut vm, identity_address).expect("decode active Options");
                let decoded_table = vm
                    .validate_tlv(vm.register(10))
                    .expect("decoded word table");
                let decoded_root = u64::from_le_bytes(
                    decoded_table.payload[1..9]
                        .try_into()
                        .expect("decoded root word"),
                );
                assert_eq!(read_active_options(&vm, decoded_root, DEPTH), 1);
                let rejected_schema = nested_active_option_schema(DEPTH + 1);
                assert!(!rejected_schema.validate());
                assert!(
                    encode_canonical_norito(&rejected_schema).is_err(),
                    "256 Options plus their leaf must exceed the 256-node V1 boundary"
                );
            })
            .expect("spawn small-stack active Option worker");
        worker.join().expect("small-stack active Option worker");
    }
    #[test]
    fn capability_payload_validation_is_canonical_and_uses_decode_errors() {
        use crate::axt::{AxtDescriptor, AxtTouchSpec, ProofBlob};
        let dsid = DataSpaceId::new(7);
        let descriptor = AxtDescriptor {
            dsids: vec![dsid],
            touches: vec![AxtTouchSpec {
                dsid,
                read: vec!["orders".to_owned()],
                write: vec!["ledger".to_owned()],
            }],
        };
        let canonical = encode_canonical_norito(&descriptor).expect("canonical descriptor");
        assert_eq!(
            validate_pointer_payload(StateValueKindV1::AxtDescriptor, &canonical),
            Ok(())
        );
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let alternate = {
            let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            to_bytes(&descriptor).expect("alternate descriptor")
        };
        assert_ne!(alternate, canonical);
        assert_eq!(
            validate_pointer_payload(StateValueKindV1::AxtDescriptor, &alternate),
            Err(VMError::DecodeError)
        );
        let invalid_descriptor = AxtDescriptor {
            dsids: Vec::new(),
            touches: Vec::new(),
        };
        assert_eq!(
            validate_pointer_payload(
                StateValueKindV1::AxtDescriptor,
                &encode_canonical_norito(&invalid_descriptor).expect("encode invalid descriptor"),
            ),
            Err(VMError::DecodeError)
        );
        let invalid_proof = ProofBlob {
            payload: Vec::new(),
            expiry_slot: Some(0),
        };
        assert_eq!(
            validate_pointer_payload(
                StateValueKindV1::ProofBlob,
                &encode_canonical_norito(&invalid_proof).expect("encode invalid proof"),
            ),
            Err(VMError::DecodeError)
        );
        let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        let ambient_before = to_bytes(&descriptor).expect("ambient descriptor");
        assert_eq!(
            validate_pointer_payload(StateValueKindV1::AxtDescriptor, &canonical),
            Ok(())
        );
        assert_eq!(
            to_bytes(&descriptor).expect("ambient descriptor after validation"),
            ambient_before
        );
    }
    fn mixed_pointer_scalar_schema() -> StateValueSchemaV1 {
        StateValueSchemaV1 {
            nodes: vec![
                StateValueNodeV1::Struct {
                    name: "Fixture::Mixed".into(),
                    fields: vec!["label".into(), "enabled".into(), "count".into()],
                },
                StateValueNodeV1::Leaf(StateValueKindV1::Name),
                StateValueNodeV1::Leaf(StateValueKindV1::Bool),
                StateValueNodeV1::Leaf(StateValueKindV1::Int),
            ],
        }
    }
    fn assert_mixed_name_pointer_rejected<F>(install_pointer: F, expected: VMError)
    where
        F: FnOnce(&mut IVM) -> u64,
    {
        let schema = mixed_pointer_scalar_schema();
        let mut vm = IVM::new(u64::MAX);
        let schema_pointer = install_schema(&mut vm, &schema);
        let count_pointer = install_int(&mut vm, 7);
        let name_pointer = install_pointer(&mut vm);
        let table = vm.alloc_heap(24).expect("mixed aggregate word table");
        vm.store_u64(table, name_pointer)
            .expect("store candidate Name pointer");
        vm.store_u64(table + 8, 1).expect("store valid bool scalar");
        vm.store_u64(table + 16, count_pointer)
            .expect("store valid int pointer");
        let heap_before = vm.memory.heap_allocated_len();
        vm.set_register(10, schema_pointer);
        vm.set_register(11, table);
        vm.set_register(12, 3);
        assert_eq!(encode_state_value(&mut vm, identity_address), Err(expected));
        assert_eq!(
            vm.register(10),
            schema_pointer,
            "a rejected input must not publish an output pointer"
        );
        assert_eq!(
            vm.memory.heap_allocated_len(),
            heap_before,
            "a rejected input must not allocate a partial output"
        );
    }
    fn install_pointer(vm: &mut IVM, pointer_type: PointerType, payload: &[u8]) -> u64 {
        let envelope = encode_tlv(pointer_type, payload).expect("pointer TLV");
        vm.alloc_host_tlv(&envelope).expect("install pointer")
    }
    #[test]
    fn schema_hash_is_domain_separated_and_stable() {
        let schema = StateValueSchemaV1 {
            nodes: vec![StateValueNodeV1::Leaf(StateValueKindV1::Int)],
        };
        let bytes = to_bytes(&schema).expect("schema bytes");
        assert_eq!(
            state_value_schema_hash_v1(&bytes),
            state_value_schema_hash_v1(&bytes)
        );
        assert_ne!(
            state_value_schema_hash_v1(&bytes),
            *Hash::new(&bytes).as_ref()
        );
    }
    #[test]
    fn cursor_state_roundtrip_preserves_frame_and_rejects_wrong_key_kind() {
        use iroha_data_model::smart_contract::{
            entrypoint::EntrypointValueKindV1, state_cursor::StateCursorV1,
        };
        let cursor = StateCursorV1 {
            instance: "local::金庫".into(),
            map: "balances".parse().unwrap(),
            schema_hash: [3; 32],
            key_schema_hash: iroha_data_model::smart_contract::entrypoint::state_key_schema_hash_v1(&iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 { nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int)] }).unwrap(),
            last_key: "balances/00".parse().unwrap(),
        };
        let frame = cursor.encode_frame().unwrap();
        let schema = StateValueSchemaV1 {
            nodes: vec![StateValueNodeV1::StateCursor(iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 { nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int)] })],
        };
        let mut vm = IVM::new(u64::MAX);
        let schema_pointer = install_schema(&mut vm, &schema);
        let pointer = install_pointer(&mut vm, PointerType::NoritoBytes, &frame);
        let table = vm.alloc_heap(8).unwrap();
        vm.store_u64(table, pointer).unwrap();
        vm.set_register(10, schema_pointer);
        vm.set_register(11, table);
        vm.set_register(12, 1);
        encode_state_value(&mut vm, identity_address).unwrap();
        let record = vm.register(10);
        vm.set_register(10, schema_pointer);
        vm.set_register(11, record);
        decode_state_value(&mut vm, identity_address).unwrap();
        let words = vm.validate_tlv(vm.register(10)).unwrap();
        let restored = u64::from_le_bytes(words.payload[1..9].try_into().unwrap());
        assert_eq!(vm.validate_tlv(restored).unwrap().payload, frame);
        let wrong = install_schema(
            &mut vm,
            &StateValueSchemaV1 {
                nodes: vec![StateValueNodeV1::StateCursor(iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 { nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Bool)] })],
            },
        );
        vm.set_register(10, wrong);
        vm.set_register(11, table);
        vm.set_register(12, 1);
        assert!(encode_state_value(&mut vm, identity_address).is_err());
    }
    #[test]
    fn empty_nominal_state_products_use_unit_slots_and_empty_atom_tapes() {
        let empty = StateValueSchemaV1 {
            nodes: vec![StateValueNodeV1::Struct {
                name: "Fixture::Empty".into(),
                fields: Vec::new(),
            }],
        };
        let schema = StateValueSchemaV1 {
            nodes: vec![
                StateValueNodeV1::Tuple { arity: 2 },
                empty.nodes[0].clone(),
                StateValueNodeV1::List {
                    element: Box::new(empty),
                    capacity: 2,
                },
            ],
        };
        assert_eq!(schema.word_count(), Some(2));
        let mut vm = IVM::new(u64::MAX);
        let schema_pointer = install_schema(&mut vm, &schema);
        let list = crate::list::allocate_words(
            &mut vm,
            ListLayoutV1::try_new(2, 1).unwrap(),
            &[vec![0], vec![0]],
        )
        .unwrap();
        let table = vm.alloc_heap(16).unwrap();
        vm.store_u64(table, 0).unwrap();
        vm.store_u64(table + 8, list).unwrap();
        vm.set_register(10, schema_pointer);
        vm.set_register(11, table);
        vm.set_register(12, 2);
        encode_state_value(&mut vm, identity_address).unwrap();
        let record_pointer = vm.register(10);
        let record: StateValueRecordV1 =
            decode_from_bytes(vm.validate_tlv(record_pointer).unwrap().payload).unwrap();
        assert_eq!(
            record.atoms,
            vec![StateValueAtomV1::List(vec![vec![], vec![]])]
        );
        vm.set_register(10, schema_pointer);
        vm.set_register(11, record_pointer);
        decode_state_value(&mut vm, identity_address).unwrap();
        let decoded = vm.validate_tlv(vm.register(10)).unwrap();
        assert_eq!(
            u64::from_le_bytes(decoded.payload[1..9].try_into().unwrap()),
            0
        );
        let copied_list = u64::from_le_bytes(decoded.payload[9..17].try_into().unwrap());
        assert_eq!(
            crate::list::read_words(&vm, copied_list, ListLayoutV1::try_new(2, 1).unwrap())
                .unwrap(),
            vec![vec![0], vec![0]]
        );
        vm.store_u64(table, 1).unwrap();
        vm.set_register(10, schema_pointer);
        vm.set_register(11, table);
        vm.set_register(12, 2);
        assert_eq!(
            encode_state_value(&mut vm, identity_address),
            Err(VMError::DecodeError)
        );
    }
    #[test]
    fn ordinary_enum_state_roundtrip_keeps_codes_out_of_error_domain() {
        let schema = StateValueSchemaV1 { nodes: vec![StateValueNodeV1::Enum(iroha_data_model::smart_contract::manifest::ContractEnumTypeDescriptorV1 {
                identity: "local::Status".into(),
                variants: vec![
                    iroha_data_model::smart_contract::manifest::ContractEnumVariantDescriptorV1 { name: "Open".into(), code: 1 },
                    iroha_data_model::smart_contract::manifest::ContractEnumVariantDescriptorV1 { name: "Closed".into(), code: 7 },
                ],
            })] };
        let mut vm = IVM::new(u64::MAX);
        let schema_pointer = install_schema(&mut vm, &schema);
        let table = vm.alloc_heap(8).unwrap();
        vm.store_u64(table, 7).unwrap();
        vm.set_register(10, schema_pointer);
        vm.set_register(11, table);
        vm.set_register(12, 1);
        encode_state_value(&mut vm, identity_address).unwrap();
        let record_pointer = vm.register(10);
        let record: StateValueRecordV1 =
            decode_from_bytes(vm.validate_tlv(record_pointer).unwrap().payload).unwrap();
        assert_eq!(record.atoms, vec![StateValueAtomV1::EnumCode(7)]);
        vm.set_register(10, schema_pointer);
        vm.set_register(11, record_pointer);
        decode_state_value(&mut vm, identity_address).unwrap();
        let decoded = vm.validate_tlv(vm.register(10)).unwrap();
        assert_eq!(&decoded.payload[1..], &7_u64.to_le_bytes());
        for word in [0, 2, u64::MAX] {
            vm.store_u64(table, word).unwrap();
            vm.set_register(10, schema_pointer);
            vm.set_register(11, table);
            vm.set_register(12, 1);
            assert_eq!(
                encode_state_value(&mut vm, identity_address),
                Err(VMError::DecodeError)
            );
        }
    }
    #[test]
    fn unit_and_nominal_error_state_roundtrip_rejects_invalid_words() {
        let schema = StateValueSchemaV1 {
            nodes: vec![
                StateValueNodeV1::Tuple { arity: 2 },
                StateValueNodeV1::Unit,
                StateValueNodeV1::Error(ivm_abi::error_types::list_error_type()),
            ],
        };
        let mut vm = IVM::new(u64::MAX);
        let schema_pointer = install_schema(&mut vm, &schema);
        let table = vm.alloc_heap(16).expect("scalar table");
        vm.store_u64(table, 0).expect("unit");
        vm.store_u64(table + 8, 2).expect("error code");
        vm.set_register(10, schema_pointer);
        vm.set_register(11, table);
        vm.set_register(12, 2);
        encode_state_value(&mut vm, identity_address).expect("encode nominal scalar state");
        let record_pointer = vm.register(10);
        let tlv = vm.validate_tlv(record_pointer).expect("record envelope");
        let record: StateValueRecordV1 = decode_from_bytes(tlv.payload).expect("record");
        assert_eq!(
            record.atoms,
            vec![StateValueAtomV1::Unit, StateValueAtomV1::ErrorCode(2)]
        );
        vm.set_register(10, schema_pointer);
        vm.set_register(11, record_pointer);
        decode_state_value(&mut vm, identity_address).expect("decode nominal scalar state");
        let decoded = vm.validate_tlv(vm.register(10)).expect("decoded table");
        assert_eq!(
            &decoded.payload[1..],
            &[0u64.to_le_bytes(), 2u64.to_le_bytes()].concat()
        );
        for (unit, error) in [(1, 2), (0, 0), (0, 3), (0, u64::MAX)] {
            vm.store_u64(table, unit).expect("unit candidate");
            vm.store_u64(table + 8, error).expect("error candidate");
            vm.set_register(10, schema_pointer);
            vm.set_register(11, table);
            vm.set_register(12, 2);
            assert!(encode_state_value(&mut vm, identity_address).is_err());
        }
    }
    #[test]
    fn aggregate_record_bytes_are_deterministic() {
        let schema = StateValueSchemaV1 {
            nodes: vec![
                StateValueNodeV1::Struct {
                    name: "Fixture::Pair".into(),
                    fields: vec!["count".into(), "ready".into()],
                },
                StateValueNodeV1::Leaf(StateValueKindV1::Int),
                StateValueNodeV1::Leaf(StateValueKindV1::Bool),
            ],
        };
        let mut vm = IVM::new(u64::MAX);
        let schema_pointer = install_schema(&mut vm, &schema);
        let table = vm.alloc_heap(16).expect("word table");
        let integer = install_int(&mut vm, 9);
        vm.store_u64(table, integer).expect("store integer pointer");
        vm.store_u64(table + 8, 1).expect("store boolean");
        let mut outputs = Vec::new();
        for _ in 0..2 {
            vm.set_register(10, schema_pointer);
            vm.set_register(11, table);
            vm.set_register(12, 2);
            encode_state_value(&mut vm, identity_address).expect("encode aggregate");
            let tlv = vm.validate_tlv(vm.register(10)).expect("encoded record");
            outputs.push(tlv.payload.to_vec());
        }
        assert_eq!(outputs[0], outputs[1]);
        let record: StateValueRecordV1 =
            decode_from_bytes(&outputs[0]).expect("decode stored record");
        assert!(matches!(
            record.atoms.as_slice(),
            [StateValueAtomV1::Pointer(_), StateValueAtomV1::Bool(true)]
        ));
    }
    #[test]
    fn nested_bytes_sources_encode_as_identical_canonical_blob_records() {
        let schema = StateValueSchemaV1 {
            nodes: vec![
                StateValueNodeV1::Struct {
                    name: "Fixture::Outer".into(),
                    fields: vec!["inner".into()],
                },
                StateValueNodeV1::Struct {
                    name: "Fixture::Inner".into(),
                    fields: vec!["value".into()],
                },
                StateValueNodeV1::Leaf(StateValueKindV1::Bytes),
            ],
        };
        let mut vm = IVM::new(u64::MAX);
        let schema_pointer = install_schema(&mut vm, &schema);
        let table = vm.alloc_heap(8).expect("word table");
        let payload = b"canonical bytes";
        let mut records = Vec::new();
        for pointer_type in [PointerType::Blob, PointerType::NoritoBytes] {
            let source = install_pointer(&mut vm, pointer_type, payload);
            vm.store_u64(table, source).expect("store bytes pointer");
            vm.set_register(10, schema_pointer);
            vm.set_register(11, table);
            vm.set_register(12, 1);
            encode_state_value(&mut vm, identity_address).expect("encode nested bytes");
            let record_pointer = vm.register(10);
            let record_tlv = vm.validate_tlv(record_pointer).expect("encoded record");
            records.push((record_pointer, record_tlv.payload.to_vec()));
        }
        assert_eq!(records[0].1, records[1].1);
        let record: StateValueRecordV1 =
            decode_from_bytes(&records[1].1).expect("decode stored record");
        let [StateValueAtomV1::Pointer(envelope)] = record.atoms.as_slice() else {
            panic!("nested bytes must encode as one pointer atom");
        };
        let atom = pointer_abi::validate_tlv_bytes(envelope).expect("canonical bytes atom");
        assert_eq!(atom.type_id, PointerType::Blob);
        assert_eq!(atom.payload, payload);
        vm.set_register(10, schema_pointer);
        vm.set_register(11, records[1].0);
        decode_state_value(&mut vm, identity_address).expect("decode nested bytes");
        let table = vm
            .validate_tlv(vm.register(10))
            .expect("decoded word table");
        assert_eq!(table.type_id, PointerType::Blob);
        let bytes_pointer =
            u64::from_le_bytes(table.payload[1..9].try_into().expect("bytes pointer word"));
        let bytes = vm.validate_tlv(bytes_pointer).expect("decoded bytes TLV");
        assert_eq!(bytes.type_id, PointerType::Blob);
        assert_eq!(bytes.payload, payload);
    }
    #[test]
    fn persisted_norito_bytes_atom_is_rejected_for_bytes_schema() {
        let schema = StateValueSchemaV1 {
            nodes: vec![StateValueNodeV1::Leaf(StateValueKindV1::Bytes)],
        };
        let schema_bytes = to_bytes(&schema).expect("schema bytes");
        let record = StateValueRecordV1 {
            schema_hash: state_value_schema_hash_v1(&schema_bytes),
            atoms: vec![StateValueAtomV1::Pointer(
                encode_tlv(PointerType::NoritoBytes, b"not canonical durable bytes")
                    .expect("NoritoBytes atom"),
            )],
        };
        let record = to_bytes(&record).expect("record bytes");
        let vm = IVM::new(u64::MAX);
        assert_eq!(
            validate_state_value_record(&vm, &schema, &record),
            Err(VMError::DecodeError)
        );
    }
    #[test]
    fn bytes_normalization_does_not_widen_other_pointer_types() {
        let bytes_schema = StateValueSchemaV1 {
            nodes: vec![StateValueNodeV1::Leaf(StateValueKindV1::Bytes)],
        };
        let string_schema = StateValueSchemaV1 {
            nodes: vec![StateValueNodeV1::Leaf(StateValueKindV1::String)],
        };
        let mut vm = IVM::new(u64::MAX);
        let table = vm.alloc_heap(8).expect("word table");
        let bytes_schema_pointer = install_schema(&mut vm, &bytes_schema);
        let unrelated = install_pointer(&mut vm, PointerType::Name, b"unrelated");
        vm.store_u64(table, unrelated)
            .expect("store unrelated pointer");
        vm.set_register(10, bytes_schema_pointer);
        vm.set_register(11, table);
        vm.set_register(12, 1);
        assert_eq!(
            encode_state_value(&mut vm, identity_address),
            Err(VMError::NoritoInvalid)
        );
        let string_schema_pointer = install_schema(&mut vm, &string_schema);
        let norito_bytes = install_pointer(&mut vm, PointerType::NoritoBytes, b"text");
        vm.store_u64(table, norito_bytes)
            .expect("store NoritoBytes pointer");
        vm.set_register(10, string_schema_pointer);
        vm.set_register(11, table);
        vm.set_register(12, 1);
        assert_eq!(
            encode_state_value(&mut vm, identity_address),
            Err(VMError::NoritoInvalid)
        );
    }
    #[test]
    fn decode_rejects_schema_mismatch() {
        let first = StateValueSchemaV1 {
            nodes: vec![
                StateValueNodeV1::Struct {
                    name: "Fixture::First".into(),
                    fields: vec!["value".into()],
                },
                StateValueNodeV1::Leaf(StateValueKindV1::Int),
            ],
        };
        let second = StateValueSchemaV1 {
            nodes: vec![
                StateValueNodeV1::Struct {
                    name: "Fixture::Second".into(),
                    fields: vec!["value".into()],
                },
                StateValueNodeV1::Leaf(StateValueKindV1::Int),
            ],
        };
        let mut vm = IVM::new(u64::MAX);
        let first_pointer = install_schema(&mut vm, &first);
        let table = vm.alloc_heap(8).expect("word table");
        let integer = install_int(&mut vm, 7);
        vm.store_u64(table, integer).expect("store integer pointer");
        vm.set_register(10, first_pointer);
        vm.set_register(11, table);
        vm.set_register(12, 1);
        encode_state_value(&mut vm, identity_address).expect("encode aggregate");
        let record_pointer = vm.register(10);
        let second_pointer = install_schema(&mut vm, &second);
        vm.set_register(10, second_pointer);
        vm.set_register(11, record_pointer);
        assert!(matches!(
            decode_state_value(&mut vm, identity_address),
            Err(VMError::DecodeError)
        ));
    }
    #[test]
    fn decode_rejects_noncanonical_inactive_sum_payload() {
        let schema = StateValueSchemaV1 {
            nodes: vec![
                StateValueNodeV1::Option,
                StateValueNodeV1::Leaf(StateValueKindV1::Int),
            ],
        };
        let schema_bytes = to_bytes(&schema).expect("schema bytes");
        let record = StateValueRecordV1 {
            schema_hash: state_value_schema_hash_v1(&schema_bytes),
            atoms: vec![
                StateValueAtomV1::Tag(false),
                StateValueAtomV1::Pointer(vec![99]),
            ],
        };
        let record = encode_tlv(
            PointerType::NoritoBytes,
            &to_bytes(&record).expect("record bytes"),
        )
        .expect("record TLV");
        let mut vm = IVM::new(u64::MAX);
        let schema_pointer = install_schema(&mut vm, &schema);
        let record_pointer = vm.alloc_host_tlv(&record).expect("install record");
        vm.set_register(10, schema_pointer);
        vm.set_register(11, record_pointer);
        assert_eq!(
            decode_state_value(&mut vm, identity_address),
            Err(VMError::DecodeError)
        );
    }
    #[test]
    fn missing_record_is_rejected_before_any_output_allocation() {
        let schema = StateValueSchemaV1 {
            nodes: vec![
                StateValueNodeV1::Option,
                StateValueNodeV1::Leaf(StateValueKindV1::Int),
            ],
        };
        let mut vm = IVM::new(u64::MAX);
        let schema_pointer = install_schema(&mut vm, &schema);
        vm.set_register(10, schema_pointer);
        vm.set_register(11, 0);
        assert_eq!(
            decode_state_value(&mut vm, identity_address),
            Err(VMError::DecodeError)
        );
        assert_eq!(vm.register(10), schema_pointer);
    }
    #[test]
    fn encode_rejects_inactive_payload_words_and_null_active_pointers() {
        let option = StateValueSchemaV1 {
            nodes: vec![
                StateValueNodeV1::Option,
                StateValueNodeV1::Leaf(StateValueKindV1::Int),
            ],
        };
        let mut vm = IVM::new(u64::MAX);
        let schema_pointer = install_schema(&mut vm, &option);
        let option_layout = SumLayoutV1::option(1).expect("Option layout");
        let forged = crate::sum::allocate_words(&mut vm, option_layout, 0, &[])
            .expect("Option::none to forge");
        vm.store_u64(forged + 8, 99)
            .expect("store hidden inactive payload");
        let table = vm.alloc_heap(8).expect("word table");
        vm.store_u64(table, forged).expect("store Option handle");
        vm.set_register(10, schema_pointer);
        vm.set_register(11, table);
        vm.set_register(12, 1);
        assert_eq!(
            encode_state_value(&mut vm, identity_address),
            Err(VMError::DecodeError),
            "an inactive payload word is not part of the V1 value"
        );
        let none = crate::sum::allocate_words(&mut vm, option_layout, 0, &[])
            .expect("canonical Option::none");
        vm.store_u64(table, none).expect("store canonical Option");
        vm.set_register(10, schema_pointer);
        vm.set_register(11, table);
        vm.set_register(12, 1);
        encode_state_value(&mut vm, identity_address).expect("encode active-only None");
        let encoded = vm.validate_tlv(vm.register(10)).expect("encoded record");
        let record: StateValueRecordV1 =
            decode_from_bytes(encoded.payload).expect("decode active-only record");
        assert_eq!(record.atoms, vec![StateValueAtomV1::Tag(false)]);
        let text = StateValueSchemaV1 {
            nodes: vec![StateValueNodeV1::Leaf(StateValueKindV1::String)],
        };
        let schema_pointer = install_schema(&mut vm, &text);
        vm.store_u64(table, 0).expect("store null pointer");
        vm.set_register(10, schema_pointer);
        vm.set_register(11, table);
        vm.set_register(12, 1);
        assert_eq!(
            encode_state_value(&mut vm, identity_address),
            Err(VMError::DecodeError)
        );
    }
    #[test]
    fn typed_pointer_leaf_rejects_a_hash_valid_but_malformed_payload() {
        let schema = StateValueSchemaV1 {
            nodes: vec![StateValueNodeV1::Leaf(StateValueKindV1::Name)],
        };
        let mut vm = IVM::new(u64::MAX);
        let schema_pointer = install_schema(&mut vm, &schema);
        let forged = encode_tlv(PointerType::Name, b"not canonical Norito")
            .expect("hash-valid malformed Name TLV");
        let forged_pointer = vm.alloc_host_tlv(&forged).expect("install forged Name");
        let table = vm.alloc_heap(8).expect("word table");
        vm.store_u64(table, forged_pointer)
            .expect("store forged pointer");
        vm.set_register(10, schema_pointer);
        vm.set_register(11, table);
        vm.set_register(12, 1);
        assert_eq!(
            encode_state_value(&mut vm, identity_address),
            Err(VMError::DecodeError)
        );
    }
    #[test]
    fn mixed_pointer_scalar_record_rejects_missing_stale_and_malformed_dynamic_pointers() {
        assert_mixed_name_pointer_rejected(|_| 0, VMError::DecodeError);
        assert_mixed_name_pointer_rejected(|_| 1, VMError::NoritoInvalid);
        assert_mixed_name_pointer_rejected(|vm| install_int(vm, 7), VMError::NoritoInvalid);
        assert_mixed_name_pointer_rejected(
            |vm| {
                let envelope = encode_tlv(PointerType::Name, b"not canonical Norito")
                    .expect("hash-valid malformed Name TLV");
                vm.alloc_host_tlv(&envelope)
                    .expect("install malformed dynamic Name")
            },
            VMError::DecodeError,
        );
        assert_mixed_name_pointer_rejected(
            |vm| {
                let name: Name = "valid-name".parse().expect("valid Name");
                let mut envelope = encode_tlv(
                    PointerType::Name,
                    &to_bytes(&name).expect("encode canonical Name"),
                )
                .expect("valid Name TLV");
                let last = envelope.last_mut().expect("TLV checksum byte");
                *last ^= 1;
                vm.alloc_host_tlv(&envelope)
                    .expect("install checksum-corrupted Name")
            },
            VMError::NoritoInvalid,
        );
    }
    #[test]
    fn quantity_list_roundtrips_as_one_canonical_sequence_handle() {
        let element = StateValueSchemaV1 {
            nodes: vec![StateValueNodeV1::Leaf(StateValueKindV1::Quantity)],
        };
        let schema = StateValueSchemaV1 {
            nodes: vec![StateValueNodeV1::List {
                element: Box::new(element),
                capacity: 2,
            }],
        };
        let mut vm = IVM::new(u64::MAX);
        let schema_pointer = install_schema(&mut vm, &schema);
        let first_amount = install_quantity(&mut vm, "1.25");
        let second_amount = install_quantity(&mut vm, "1.25");
        let layout = ListLayoutV1::try_new(2, 1).expect("quantity list layout");
        let list_pointer = crate::list::allocate_words(
            &mut vm,
            layout,
            &[vec![first_amount], vec![second_amount]],
        )
        .expect("allocate contiguous quantity list");
        let table = vm.alloc_heap(8).expect("word table");
        vm.store_u64(table, list_pointer)
            .expect("store list pointer");
        vm.set_register(10, schema_pointer);
        vm.set_register(11, table);
        vm.set_register(12, 1);
        encode_state_value(&mut vm, identity_address).expect("encode list state");
        let record_pointer = vm.register(10);
        vm.set_register(10, schema_pointer);
        vm.set_register(11, record_pointer);
        decode_state_value(&mut vm, identity_address).expect("decode list state");
        let table = vm.validate_tlv(vm.register(10)).expect("decoded table");
        let list_pointer = u64::from_le_bytes(table.payload[1..9].try_into().expect("list word"));
        let decoded =
            crate::list::read_words(&vm, list_pointer, layout).expect("read decoded list");
        assert_eq!(decoded.len(), 2);
        for item in &decoded {
            assert_eq!(item.len(), 1);
            let quantity = vm.validate_tlv(item[0]).expect("decoded quantity TLV");
            assert_eq!(quantity.type_id, PointerType::Quantity);
            let value = QuantityValueV1::decode_frame(quantity.payload)
                .expect("decode quantity")
                .into_quantity();
            assert_eq!(
                value,
                "1.25".parse::<Quantity>().expect("canonical quantity")
            );
        }
        let overflow = crate::list::allocate_words(
            &mut vm,
            layout,
            &[vec![first_amount], vec![second_amount]],
        )
        .expect("allocate list to forge");
        vm.store_u64(overflow, 3)
            .expect("forge length past capacity");
        let overflow_table = vm.alloc_heap(8).expect("overflow word table");
        vm.store_u64(overflow_table, overflow)
            .expect("store overflow list pointer");
        vm.set_register(10, schema_pointer);
        vm.set_register(11, overflow_table);
        vm.set_register(12, 1);
        assert_eq!(
            encode_state_value(&mut vm, identity_address),
            Err(VMError::DecodeError)
        );
    }
    #[test]
    fn list_of_nested_option_results_roundtrips_active_only_handles() {
        let element = StateValueSchemaV1 {
            nodes: vec![
                StateValueNodeV1::Option,
                StateValueNodeV1::Result,
                StateValueNodeV1::Leaf(StateValueKindV1::Quantity),
                StateValueNodeV1::Leaf(StateValueKindV1::Bool),
            ],
        };
        let schema = StateValueSchemaV1 {
            nodes: vec![StateValueNodeV1::List {
                element: Box::new(element),
                capacity: 3,
            }],
        };
        let mut vm = IVM::new(u64::MAX);
        let schema_pointer = install_schema(&mut vm, &schema);
        let amount = install_quantity(&mut vm, "1.25");
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
        let table = vm.alloc_heap(8).expect("word table");
        vm.store_u64(table, list).expect("store list handle");
        vm.set_register(10, schema_pointer);
        vm.set_register(11, table);
        vm.set_register(12, 1);
        encode_state_value(&mut vm, identity_address).expect("encode nested sums");
        let record_pointer = vm.register(10);
        vm.set_register(10, schema_pointer);
        vm.set_register(11, record_pointer);
        decode_state_value(&mut vm, identity_address).expect("decode nested sums");
        let table = vm.validate_tlv(vm.register(10)).expect("decoded table");
        let list = u64::from_le_bytes(table.payload[1..9].try_into().expect("list word"));
        let list = crate::list::read_words(&vm, list, list_layout).expect("read list");
        assert_eq!(list.len(), 3);
        let (some, first) =
            crate::sum::read_words(&vm, list[0][0], option_layout).expect("read first Option");
        assert!(some);
        let (ok, amount) =
            crate::sum::read_words(&vm, first[0], result_layout).expect("read first Result");
        assert!(ok);
        let amount = vm.validate_tlv(amount[0]).expect("quantity TLV");
        let amount = QuantityValueV1::decode_frame(amount.payload)
            .expect("decode quantity")
            .into_quantity();
        assert_eq!(
            amount,
            "1.25".parse::<Quantity>().expect("canonical quantity")
        );
        let (some, second) =
            crate::sum::read_words(&vm, list[1][0], option_layout).expect("read second Option");
        assert!(some);
        let (ok, error) =
            crate::sum::read_words(&vm, second[0], result_layout).expect("read second Result");
        assert!(!ok);
        assert_eq!(error, vec![1]);
        let (some, payload) =
            crate::sum::read_words(&vm, list[2][0], option_layout).expect("read Option::none");
        assert!(!some);
        assert!(payload.is_empty());
    }
}
