//! Native, schema-bound Kotodama JSON construction and typed getters.
//!
//! Integers, exact decimals, and quantities use canonical base-10 JSON strings so they never pass
//! through floating-point conversion or a host JSON integer-width limit.
//! Options use the public argument/return representation: `{"some": value}` or `{"none": true}`.
//! In particular, `Some(())` is `{"some": null}` and remains distinct from `None`.
use crate::{
    IVM, PointerType, VMError, host::preflight_reserved_syscall_gas, pointer_abi, syscalls,
};
use core::{fmt::Write as _, str::FromStr};
use iroha_crypto::Hash;
use iroha_data_model::{
    account::AccountId,
    prelude::{AssetDefinitionId, AssetId, NftId},
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::{
    bigint::BigInt,
    json::Json,
    numeric::{Numeric, Quantity},
    numeric_abi::{DecimalValueV1, IntValueV1, QuantityValueV1},
};
use ivm_abi::{
    codec::encode_canonical_norito,
    json::{
        JsonConstructionNodeV1, JsonConstructionSchemaV1, MAX_JSON_CONSTRUCTION_NODES_V1,
        MAX_JSON_CONSTRUCTION_SCHEMA_BYTES_V1, MAX_JSON_LITERAL_ITEMS_V1,
    },
    state_value::{
        MAX_STATE_VALUE_NODES, MAX_STATE_VALUE_WORDS, StateValueKindV1, StateValueNodeV1,
        StateValueSchemaV1,
    },
};
#[cfg(test)]
use norito::{decode_from_bytes, to_bytes};
use norito::{json as njson, json::native::Number as JsonNumber};
/// Base gas for a schema-bound native JSON construction.
pub const JSON_BUILD_GAS_BASE: u64 = 32;
/// Base gas for one typed JSON getter.
pub const JSON_TYPED_GETTER_GAS_BASE: u64 = 16;
/// Address translation used for compiler literal TLVs.
pub type AddressResolver = fn(&IVM, u64) -> u64;
/// Result metadata for one typed getter execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JsonGetterCost {
    /// Canonical input payload bytes inspected.
    pub input_bytes: usize,
    /// Typed payload and Option allocation bytes materialized.
    pub output_bytes: usize,
}
#[derive(Default)]
struct BuildStats {
    source_bytes: usize,
    collection_elements: usize,
}
fn drain_json_values_stack_safe(values: &mut Vec<njson::Value>) {
    let mut pending = core::mem::take(values);
    while let Some(value) = pending.pop() {
        match value {
            njson::Value::Array(mut children) => pending.append(&mut children),
            njson::Value::Object(object) => pending.extend(object.into_values()),
            njson::Value::Null
            | njson::Value::Bool(_)
            | njson::Value::Number(_)
            | njson::Value::String(_) => {}
        }
    }
}
// `norito::json::Value` has no custom destructor, so an owned deeply nested
// array/object must be dismantled iteratively on every early-return path.
#[derive(Debug)]
struct StackSafeJsonValue(Option<njson::Value>);
impl StackSafeJsonValue {
    fn new(value: njson::Value) -> Self {
        Self(Some(value))
    }
    fn value(&self) -> &njson::Value {
        self.0.as_ref().expect("stack-safe JSON value is present")
    }
    fn into_inner(mut self) -> njson::Value {
        self.0.take().expect("stack-safe JSON value is present")
    }
}
impl Drop for StackSafeJsonValue {
    fn drop(&mut self) {
        if let Some(value) = self.0.take() {
            let mut values = vec![value];
            drain_json_values_stack_safe(&mut values);
        }
    }
}
#[derive(Default)]
struct StackSafeJsonValues(Vec<njson::Value>);
impl StackSafeJsonValues {
    fn len(&self) -> usize {
        self.0.len()
    }
    fn push(&mut self, value: njson::Value) {
        self.0.push(value);
    }
    fn push_guarded(&mut self, value: StackSafeJsonValue) {
        self.push(value.into_inner());
    }
    fn split_off(&mut self, at: usize) -> Vec<njson::Value> {
        self.0.split_off(at)
    }
    fn into_only(mut self) -> Result<StackSafeJsonValue, VMError> {
        if self.0.len() != 1 {
            return Err(VMError::DecodeError);
        }
        Ok(StackSafeJsonValue::new(
            self.0.pop().ok_or(VMError::DecodeError)?,
        ))
    }
}
impl Drop for StackSafeJsonValues {
    fn drop(&mut self) {
        drain_json_values_stack_safe(&mut self.0);
    }
}
fn escape_json_string(value: &str, output: &mut String) {
    const HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if (character as u32) < 0x20 => {
                output.push_str("\\u00");
                output.push(HEX_DIGITS[((character as u32 >> 4) & 0xF) as usize] as char);
                output.push(HEX_DIGITS[(character as u32 & 0xF) as usize] as char);
            }
            _ => output.push(character),
        }
    }
    output.push('"');
}
fn json_from_value_ref(value: &njson::Value) -> Result<Json, VMError> {
    enum Task<'a> {
        Value {
            value: &'a njson::Value,
            depth: usize,
        },
        Escaped(&'a str),
        Byte(char),
    }
    let mut output = String::new();
    let mut pending = vec![Task::Value { value, depth: 1 }];
    while let Some(task) = pending.pop() {
        match task {
            Task::Escaped(value) => escape_json_string(value, &mut output),
            Task::Byte(value) => output.push(value),
            Task::Value { value, depth } => {
                if depth > njson::MAX_JSON_VALUE_NESTING_DEPTH {
                    return Err(VMError::DecodeError);
                }
                match value {
                    njson::Value::Null => output.push_str("null"),
                    njson::Value::Bool(value) => {
                        output.push_str(if *value { "true" } else { "false" });
                    }
                    njson::Value::Number(value) => match value {
                        JsonNumber::I64(value) => output.push_str(&value.to_string()),
                        JsonNumber::U64(value) => output.push_str(&value.to_string()),
                        JsonNumber::U128(value) => output.push_str(&value.to_string()),
                        JsonNumber::F64(value) => {
                            if !value.is_finite() {
                                return Err(VMError::DecodeError);
                            }
                            const F64_SAFE_INT: f64 = 9_007_199_254_740_992.0;
                            if value.fract() == 0.0 && value.abs() <= F64_SAFE_INT {
                                let _ = write!(output, "{value:.1}");
                            } else {
                                let _ = write!(output, "{value:?}");
                            }
                        }
                    },
                    njson::Value::String(value) => escape_json_string(value, &mut output),
                    njson::Value::Array(values) => {
                        let child_depth = depth.checked_add(1).ok_or(VMError::DecodeError)?;
                        output.push('[');
                        pending.push(Task::Byte(']'));
                        for (index, value) in values.iter().enumerate().rev() {
                            if index + 1 < values.len() {
                                pending.push(Task::Byte(','));
                            }
                            pending.push(Task::Value {
                                value,
                                depth: child_depth,
                            });
                        }
                    }
                    njson::Value::Object(object) => {
                        let child_depth = depth.checked_add(1).ok_or(VMError::DecodeError)?;
                        output.push('{');
                        pending.push(Task::Byte('}'));
                        for (index, (key, value)) in object.iter().enumerate().rev() {
                            if index + 1 < object.len() {
                                pending.push(Task::Byte(','));
                            }
                            pending.push(Task::Value {
                                value,
                                depth: child_depth,
                            });
                            pending.push(Task::Byte(':'));
                            pending.push(Task::Escaped(key));
                        }
                    }
                }
            }
        }
    }
    // Every structural token and string escape was emitted above from a
    // `Value`; the only otherwise-invalid payloads (non-finite numbers and
    // excessive depth) were rejected explicitly. Avoid reparsing into another
    // deeply nested owned `Value` merely to validate and recursively drop it.
    Json::from_raw_json(output).map_err(|_| VMError::DecodeError)
}
fn load_tlv<'a>(
    vm: &'a IVM,
    address: u64,
    expected: PointerType,
    resolver: AddressResolver,
) -> Result<pointer_abi::Tlv<'a>, VMError> {
    let resolved = resolver(vm, address);
    let tlv = vm.validate_tlv(resolved)?;
    if tlv.type_id != expected
        || !pointer_abi::is_type_allowed_for_policy(vm.syscall_policy(), tlv.type_id)
    {
        if crate::dev_env::decode_trace_enabled() {
            eprintln!(
                "[json] pointer type mismatch: raw=0x{address:x} resolved=0x{resolved:x} expected={expected:?} actual={:?}",
                tlv.type_id
            );
        }
        return Err(VMError::NoritoInvalid);
    }
    Ok(tlv)
}
fn decode_canonical<T>(payload: &[u8]) -> Result<T, VMError>
where
    T: for<'__frame> norito::NoritoDeserialize<'__frame> + norito::NoritoSerialize,
{
    ivm_abi::codec::decode_canonical_norito(payload).map_err(|_| VMError::DecodeError)
}
fn allocate_tlv(vm: &mut IVM, pointer_type: PointerType, payload: &[u8]) -> Result<u64, VMError> {
    let payload_len = u32::try_from(payload.len()).map_err(|_| VMError::NoritoInvalid)?;
    let mut envelope = Vec::with_capacity(7 + payload.len() + Hash::LENGTH);
    envelope.extend_from_slice(&(pointer_type as u16).to_be_bytes());
    envelope.push(1);
    envelope.extend_from_slice(&payload_len.to_be_bytes());
    envelope.extend_from_slice(payload);
    envelope.extend_from_slice(Hash::new(payload).as_ref());
    vm.alloc_host_tlv(&envelope)
}
fn decode_construction_schema(
    vm: &IVM,
    address: u64,
    resolver: AddressResolver,
) -> Result<(JsonConstructionSchemaV1, usize), VMError> {
    let tlv = load_tlv(vm, address, PointerType::NoritoBytes, resolver)?;
    if tlv.payload.len() > MAX_JSON_CONSTRUCTION_SCHEMA_BYTES_V1 {
        return Err(VMError::DecodeError);
    }
    let schema: JsonConstructionSchemaV1 = decode_canonical(tlv.payload)?;
    if !schema.validate() {
        return Err(VMError::DecodeError);
    }
    Ok((schema, tlv.payload.len()))
}
fn read_word_table(vm: &IVM, address: u64, count: usize) -> Result<Vec<u64>, VMError> {
    if count > MAX_STATE_VALUE_WORDS || !address.is_multiple_of(8) {
        return Err(VMError::DecodeError);
    }
    let byte_len = count.checked_mul(8).ok_or(VMError::DecodeError)?;
    if byte_len == 0 {
        return Ok(Vec::new());
    }
    vm.ensure_public_memory(
        address,
        u64::try_from(byte_len).map_err(|_| VMError::DecodeError)?,
    )?;
    let bytes = vm.memory.load_region(
        address,
        u64::try_from(byte_len).map_err(|_| VMError::DecodeError)?,
    )?;
    Ok(bytes
        .chunks_exact(8)
        .map(|chunk| u64::from_le_bytes(chunk.try_into().expect("eight-byte word")))
        .collect())
}
fn state_node_word_count(
    nodes: &[StateValueNodeV1],
    node_index: &mut usize,
) -> Result<usize, VMError> {
    let mut visited = 0usize;
    loop {
        visited = visited.checked_add(1).ok_or(VMError::DecodeError)?;
        if visited > MAX_STATE_VALUE_NODES {
            return Err(VMError::DecodeError);
        }
        let node = nodes.get(*node_index).ok_or(VMError::DecodeError)?;
        *node_index = node_index.checked_add(1).ok_or(VMError::DecodeError)?;
        match node {
            StateValueNodeV1::Option => {}
            StateValueNodeV1::List { .. }
            | StateValueNodeV1::Leaf(_)
            | StateValueNodeV1::Unit
            | StateValueNodeV1::Error(_)
            | StateValueNodeV1::Enum(_)
            | StateValueNodeV1::StateCursor(_) => return Ok(1),
            StateValueNodeV1::Struct { .. }
            | StateValueNodeV1::Tuple { .. }
            | StateValueNodeV1::Result => return Err(VMError::DecodeError),
        }
    }
}
fn pointer_leaf<'a>(
    vm: &'a IVM,
    word: u64,
    pointer_type: PointerType,
    resolver: AddressResolver,
    stats: &mut BuildStats,
) -> Result<&'a [u8], VMError> {
    let tlv = load_tlv(vm, word, pointer_type, resolver)?;
    stats.source_bytes = stats.source_bytes.saturating_add(tlv.payload.len());
    Ok(tlv.payload)
}
fn convert_leaf(
    vm: &IVM,
    kind: StateValueKindV1,
    word: u64,
    resolver: AddressResolver,
    stats: &mut BuildStats,
) -> Result<njson::Value, VMError> {
    if crate::dev_env::decode_trace_enabled() {
        eprintln!("[json] convert leaf: kind={kind:?} word=0x{word:x}");
    }
    Ok(match kind {
        StateValueKindV1::Int => {
            let payload = pointer_leaf(vm, word, PointerType::Int, resolver, stats)?;
            let value = IntValueV1::decode_frame(payload)
                .map_err(|_| VMError::DecodeError)?
                .into_int();
            njson::Value::from(value.to_string())
        }
        StateValueKindV1::Bool => match word {
            0 => njson::Value::Bool(false),
            1 => njson::Value::Bool(true),
            _ => return Err(VMError::DecodeError),
        },
        StateValueKindV1::Decimal => {
            let payload = pointer_leaf(vm, word, PointerType::Decimal, resolver, stats)?;
            let value = DecimalValueV1::decode_frame(payload)
                .map_err(|_| VMError::DecodeError)?
                .into_numeric();
            njson::Value::from(value.to_string())
        }
        StateValueKindV1::Quantity => {
            let payload = pointer_leaf(vm, word, PointerType::Quantity, resolver, stats)?;
            let quantity = QuantityValueV1::decode_frame(payload)
                .map_err(|_| VMError::DecodeError)?
                .into_quantity();
            njson::Value::from(quantity.to_string())
        }
        StateValueKindV1::String => {
            let payload = pointer_leaf(vm, word, PointerType::Blob, resolver, stats)?;
            njson::Value::from(
                core::str::from_utf8(payload)
                    .map_err(|_| VMError::DecodeError)?
                    .to_owned(),
            )
        }
        StateValueKindV1::Json => {
            let payload = pointer_leaf(vm, word, PointerType::Json, resolver, stats)?;
            let json: Json = decode_canonical(payload)?;
            json.try_into_any_norito()
                .map_err(|_| VMError::DecodeError)?
        }
        StateValueKindV1::Bytes => {
            let payload = pointer_leaf(vm, word, PointerType::Blob, resolver, stats)?;
            njson::Value::from(format!("0x{}", hex::encode(payload)))
        }
        StateValueKindV1::AccountId => {
            let payload = pointer_leaf(vm, word, PointerType::AccountId, resolver, stats)?;
            njson::Value::from(decode_canonical::<AccountId>(payload)?.to_string())
        }
        StateValueKindV1::AssetDefinitionId => {
            let payload = pointer_leaf(vm, word, PointerType::AssetDefinitionId, resolver, stats)?;
            njson::Value::from(decode_canonical::<AssetDefinitionId>(payload)?.to_string())
        }
        StateValueKindV1::AssetId => {
            let payload = pointer_leaf(vm, word, PointerType::AssetId, resolver, stats)?;
            njson::Value::from(decode_canonical::<AssetId>(payload)?.to_string())
        }
        StateValueKindV1::DomainId => {
            let payload = pointer_leaf(vm, word, PointerType::DomainId, resolver, stats)?;
            njson::Value::from(decode_canonical::<DomainId>(payload)?.to_string())
        }
        StateValueKindV1::NftId => {
            let payload = pointer_leaf(vm, word, PointerType::NftId, resolver, stats)?;
            njson::Value::from(decode_canonical::<NftId>(payload)?.to_string())
        }
        StateValueKindV1::Name => {
            let payload = pointer_leaf(vm, word, PointerType::Name, resolver, stats)?;
            njson::Value::from(decode_canonical::<Name>(payload)?.to_string())
        }
        StateValueKindV1::DataSpaceId => {
            let payload = pointer_leaf(vm, word, PointerType::DataSpaceId, resolver, stats)?;
            njson::Value::from(decode_canonical::<DataSpaceId>(payload)?.to_string())
        }
        StateValueKindV1::AxtDescriptor
        | StateValueKindV1::ProofBlob
        | StateValueKindV1::SoracloudRequest
        | StateValueKindV1::SoracloudResponse => return Err(VMError::DecodeError),
    })
}
fn convert_state_schema(
    vm: &IVM,
    schema: &StateValueSchemaV1,
    words: &[u64],
    resolver: AddressResolver,
    stats: &mut BuildStats,
) -> Result<StackSafeJsonValue, VMError> {
    enum Pending<'a> {
        Convert {
            nodes: &'a [StateValueNodeV1],
            node_start: usize,
            node_end: usize,
            words: Vec<u64>,
            depth: usize,
        },
        FinishList {
            value_start: usize,
            item_count: usize,
        },
        FinishSome {
            value_start: usize,
        },
    }
    let mut root_end = 0usize;
    state_node_word_count(&schema.nodes, &mut root_end)?;
    if root_end != schema.nodes.len() {
        return Err(VMError::DecodeError);
    }
    let mut pending = vec![Pending::Convert {
        nodes: &schema.nodes,
        node_start: 0,
        node_end: root_end,
        words: words.to_vec(),
        depth: 1,
    }];
    let mut completed = StackSafeJsonValues::default();
    while let Some(task) = pending.pop() {
        match task {
            Pending::Convert {
                nodes,
                mut node_start,
                node_end,
                mut words,
                mut depth,
            } => loop {
                if depth > MAX_STATE_VALUE_NODES || words.len() != 1 {
                    return Err(VMError::DecodeError);
                }
                let node = nodes.get(node_start).ok_or(VMError::DecodeError)?;
                let next_node = node_start.checked_add(1).ok_or(VMError::DecodeError)?;
                match node {
                    StateValueNodeV1::Option => {
                        let handle = words[0];
                        if crate::dev_env::decode_trace_enabled() {
                            eprintln!("[json] convert Option handle=0x{handle:x}");
                        }
                        let child_start = next_node;
                        let mut child_end = child_start;
                        let child_words = state_node_word_count(nodes, &mut child_end)?;
                        if child_end != node_end {
                            return Err(VMError::DecodeError);
                        }
                        let layout = crate::sum::SumLayoutV1::option(
                            u64::try_from(child_words).map_err(|_| VMError::DecodeError)?,
                        )
                        .map_err(|_| VMError::DecodeError)?;
                        let (some, payload) = crate::sum::read_words(vm, handle, layout)?;
                        // Each Option creates exactly one object member, including None.
                        // Its tag spelling and punctuation are charged in the encoded output.
                        stats.collection_elements = stats.collection_elements.saturating_add(1);
                        if !some {
                            let mut object = njson::Map::new();
                            object.insert("none".to_owned(), njson::Value::Bool(true));
                            completed.push(njson::Value::Object(object));
                            break;
                        }
                        pending.push(Pending::FinishSome {
                            value_start: completed.len(),
                        });
                        node_start = child_start;
                        words = payload;
                        depth = depth.checked_add(1).ok_or(VMError::DecodeError)?;
                    }
                    StateValueNodeV1::List { element, capacity } => {
                        if next_node != node_end {
                            return Err(VMError::DecodeError);
                        }
                        if crate::dev_env::decode_trace_enabled() {
                            eprintln!(
                                "[json] convert List handle=0x{:x} capacity={capacity} element_words={:?}",
                                words[0],
                                element.word_count()
                            );
                        }
                        let mut element_end = 0usize;
                        let element_words =
                            state_node_word_count(&element.nodes, &mut element_end)?;
                        if element_end != element.nodes.len() {
                            return Err(VMError::DecodeError);
                        }
                        let layout = crate::list::ListLayoutV1::try_new(
                            u64::from(*capacity),
                            u64::try_from(element_words).map_err(|_| VMError::DecodeError)?,
                        )
                        .map_err(|_| VMError::DecodeError)?;
                        let items = crate::list::read_words(vm, words[0], layout)?;
                        stats.collection_elements =
                            stats.collection_elements.saturating_add(items.len());
                        let value_start = completed.len();
                        let item_count = items.len();
                        let child_depth = depth.checked_add(1).ok_or(VMError::DecodeError)?;
                        pending.push(Pending::FinishList {
                            value_start,
                            item_count,
                        });
                        pending.extend(items.into_iter().rev().map(|words| Pending::Convert {
                            nodes: &element.nodes,
                            node_start: 0,
                            node_end: element_end,
                            words,
                            depth: child_depth,
                        }));
                        break;
                    }
                    StateValueNodeV1::StateCursor(key) => {
                        if next_node != node_end {
                            return Err(VMError::DecodeError);
                        }
                        let payload =
                            pointer_leaf(vm, words[0], PointerType::NoritoBytes, resolver, stats)?;
                        let cursor = iroha_data_model::smart_contract::state_cursor::StateCursorV1::decode_frame(payload).map_err(|_| VMError::DecodeError)?;
                        if Some(cursor.key_schema_hash) != iroha_data_model::smart_contract::entrypoint::state_key_schema_hash_v1(key) {
                            return Err(VMError::DecodeError);
                        }
                        completed.push(njson::Value::from(format!("0x{}", hex::encode(payload))));
                        break;
                    }
                    StateValueNodeV1::Unit => {
                        if next_node != node_end || words[0] != 0 {
                            return Err(VMError::DecodeError);
                        }
                        completed.push(njson::Value::Null);
                        break;
                    }
                    StateValueNodeV1::Error(error) => {
                        if next_node != node_end {
                            return Err(VMError::DecodeError);
                        }
                        let code = u32::try_from(words[0]).map_err(|_| VMError::DecodeError)?;
                        let variant = error.variant(code).ok_or(VMError::DecodeError)?;
                        completed.push(njson::Value::String(variant.name.clone()));
                        break;
                    }
                    StateValueNodeV1::Enum(descriptor) => {
                        if next_node != node_end {
                            return Err(VMError::DecodeError);
                        }
                        let code = u32::try_from(words[0]).map_err(|_| VMError::DecodeError)?;
                        let variant = descriptor.variant(code).ok_or(VMError::DecodeError)?;
                        completed.push(njson::Value::String(variant.name.clone()));
                        break;
                    }
                    StateValueNodeV1::Leaf(kind) => {
                        if next_node != node_end {
                            return Err(VMError::DecodeError);
                        }
                        completed.push(convert_leaf(vm, *kind, words[0], resolver, stats)?);
                        break;
                    }
                    StateValueNodeV1::Struct { .. }
                    | StateValueNodeV1::Tuple { .. }
                    | StateValueNodeV1::Result => return Err(VMError::DecodeError),
                }
            },
            Pending::FinishList {
                value_start,
                item_count,
            } => {
                if completed.len().checked_sub(value_start) != Some(item_count) {
                    return Err(VMError::DecodeError);
                }
                let values = completed.split_off(value_start);
                completed.push(njson::Value::Array(values));
            }
            Pending::FinishSome { value_start } => {
                if completed.len().checked_sub(value_start) != Some(1) {
                    return Err(VMError::DecodeError);
                }
                let value = completed.0.pop().ok_or(VMError::DecodeError)?;
                let mut object = njson::Map::new();
                object.insert("some".to_owned(), value);
                completed.push(njson::Value::Object(object));
            }
        }
    }
    completed.into_only()
}
fn convert_construction_schema(
    vm: &IVM,
    nodes: &[JsonConstructionNodeV1],
    node_index: &mut usize,
    words: &[u64],
    word_index: &mut usize,
    resolver: AddressResolver,
    stats: &mut BuildStats,
) -> Result<StackSafeJsonValue, VMError> {
    enum Pending<'a> {
        Convert {
            depth: usize,
        },
        FinishObject {
            keys: &'a [String],
            value_start: usize,
        },
        FinishArray {
            value_start: usize,
            item_count: usize,
        },
    }
    if nodes.is_empty() || nodes.len() > MAX_JSON_CONSTRUCTION_NODES_V1 {
        return Err(VMError::DecodeError);
    }
    let mut next_node = *node_index;
    let mut next_word = *word_index;
    let mut visited = 0usize;
    let mut pending = vec![Pending::Convert { depth: 1 }];
    let mut completed = StackSafeJsonValues::default();
    while let Some(task) = pending.pop() {
        match task {
            Pending::Convert { depth } => {
                visited = visited.checked_add(1).ok_or(VMError::DecodeError)?;
                if visited > MAX_JSON_CONSTRUCTION_NODES_V1
                    || depth > MAX_JSON_CONSTRUCTION_NODES_V1
                {
                    return Err(VMError::DecodeError);
                }
                let node = nodes.get(next_node).ok_or(VMError::DecodeError)?;
                next_node = next_node.checked_add(1).ok_or(VMError::DecodeError)?;
                match node {
                    JsonConstructionNodeV1::Object { keys } => {
                        if keys.len() > MAX_JSON_LITERAL_ITEMS_V1
                            || keys
                                .iter()
                                .enumerate()
                                .any(|(index, key)| keys[..index].contains(key))
                        {
                            return Err(VMError::DecodeError);
                        }
                        stats.collection_elements =
                            stats.collection_elements.saturating_add(keys.len());
                        let value_start = completed.len();
                        let child_depth = depth.checked_add(1).ok_or(VMError::DecodeError)?;
                        let required_tasks = pending
                            .len()
                            .checked_add(1)
                            .and_then(|count| count.checked_add(keys.len()))
                            .ok_or(VMError::DecodeError)?;
                        if required_tasks > MAX_JSON_CONSTRUCTION_NODES_V1 {
                            return Err(VMError::DecodeError);
                        }
                        pending.push(Pending::FinishObject { keys, value_start });
                        pending.extend(
                            (0..keys.len()).map(|_| Pending::Convert { depth: child_depth }),
                        );
                    }
                    JsonConstructionNodeV1::Array { arity } => {
                        let item_count = usize::from(*arity);
                        if item_count > MAX_JSON_LITERAL_ITEMS_V1 {
                            return Err(VMError::DecodeError);
                        }
                        stats.collection_elements =
                            stats.collection_elements.saturating_add(item_count);
                        let value_start = completed.len();
                        let child_depth = depth.checked_add(1).ok_or(VMError::DecodeError)?;
                        let required_tasks = pending
                            .len()
                            .checked_add(1)
                            .and_then(|count| count.checked_add(item_count))
                            .ok_or(VMError::DecodeError)?;
                        if required_tasks > MAX_JSON_CONSTRUCTION_NODES_V1 {
                            return Err(VMError::DecodeError);
                        }
                        pending.push(Pending::FinishArray {
                            value_start,
                            item_count,
                        });
                        pending.extend(
                            (0..item_count).map(|_| Pending::Convert { depth: child_depth }),
                        );
                    }
                    JsonConstructionNodeV1::Value { schema } => {
                        let count = schema.word_count().ok_or(VMError::DecodeError)?;
                        let end = next_word.checked_add(count).ok_or(VMError::DecodeError)?;
                        let value_words = words.get(next_word..end).ok_or(VMError::DecodeError)?;
                        next_word = end;
                        completed.push_guarded(convert_state_schema(
                            vm,
                            schema,
                            value_words,
                            resolver,
                            stats,
                        )?);
                    }
                }
            }
            Pending::FinishObject { keys, value_start } => {
                if completed.len().checked_sub(value_start) != Some(keys.len()) {
                    return Err(VMError::DecodeError);
                }
                let values = completed.split_off(value_start);
                let mut object = njson::Map::new();
                for (key, value) in keys.iter().cloned().zip(values) {
                    let replaced = object.insert(key, value);
                    debug_assert!(replaced.is_none(), "duplicate JSON keys were rejected");
                }
                completed.push(njson::Value::Object(object));
            }
            Pending::FinishArray {
                value_start,
                item_count,
            } => {
                if completed.len().checked_sub(value_start) != Some(item_count) {
                    return Err(VMError::DecodeError);
                }
                let values = completed.split_off(value_start);
                completed.push(njson::Value::Array(values));
            }
        }
    }
    let value = completed.into_only()?;
    *node_index = next_node;
    *word_index = next_word;
    Ok(value)
}
/// Deterministic gas charged by [`build_json`].
#[must_use]
pub fn build_json_gas(
    schema_bytes: usize,
    source_bytes: usize,
    words: usize,
    collection_elements: usize,
    output_bytes: usize,
) -> u64 {
    [
        schema_bytes,
        source_bytes,
        words,
        collection_elements,
        output_bytes,
    ]
    .into_iter()
    .fold(JSON_BUILD_GAS_BASE, |gas, value| {
        gas.saturating_add(u64::try_from(value).unwrap_or(u64::MAX))
    })
}
/// Deterministic gas for one typed JSON getter.
#[must_use]
pub fn typed_getter_gas(input_bytes: usize, output_bytes: usize) -> u64 {
    JSON_TYPED_GETTER_GAS_BASE
        .saturating_add(u64::try_from(input_bytes).unwrap_or(u64::MAX))
        .saturating_add(u64::try_from(output_bytes).unwrap_or(u64::MAX))
}
/// Execute `JSON_BUILD` using `r10=schema`, `r11=word table`, `r12=word count`.
///
/// # Errors
///
/// Returns a deterministic VM error for a malformed schema, word table, handle,
/// pointer payload, or unsupported source type.
pub fn build_json(vm: &mut IVM, resolver: AddressResolver) -> Result<u64, VMError> {
    let (schema, schema_bytes) = decode_construction_schema(vm, vm.register(10), resolver)?;
    if crate::dev_env::decode_trace_enabled() {
        eprintln!(
            "[json] decoded construction schema: nodes={} bytes={schema_bytes}",
            schema.nodes.len()
        );
    }
    let expected_words = schema.word_count().ok_or(VMError::DecodeError)?;
    let supplied_words = usize::try_from(vm.register(12)).map_err(|_| VMError::DecodeError)?;
    if supplied_words != expected_words {
        return Err(VMError::DecodeError);
    }
    let words = read_word_table(vm, vm.register(11), supplied_words)?;
    if crate::dev_env::decode_trace_enabled() {
        eprintln!(
            "[json] read construction word table: expected={expected_words} supplied={supplied_words} words={words:x?}"
        );
    }
    let mut stats = BuildStats::default();
    let mut node_index = 0;
    let mut word_index = 0;
    let value = convert_construction_schema(
        vm,
        &schema.nodes,
        &mut node_index,
        &words,
        &mut word_index,
        resolver,
        &mut stats,
    )?;
    if crate::dev_env::decode_trace_enabled() {
        eprintln!(
            "[json] converted construction tree: nodes={node_index}/{} words={word_index}/{}",
            schema.nodes.len(),
            words.len()
        );
    }
    if node_index != schema.nodes.len() || word_index != words.len() {
        return Err(VMError::DecodeError);
    }
    let json = json_from_value_ref(value.value());
    drop(value);
    let json = json?;
    let payload = encode_canonical_norito(&json)?;
    if crate::dev_env::decode_trace_enabled() {
        eprintln!("[json] encoded JSON payload: bytes={}", payload.len());
    }
    let gas = build_json_gas(
        schema_bytes,
        stats.source_bytes,
        supplied_words,
        stats.collection_elements,
        payload.len(),
    );
    preflight_reserved_syscall_gas(vm, gas)?;
    let pointer = allocate_tlv(vm, PointerType::Json, &payload)?;
    if crate::dev_env::decode_trace_enabled() {
        eprintln!("[json] allocated JSON result: pointer=0x{pointer:x}");
    }
    vm.set_register(10, pointer);
    Ok(gas)
}
fn canonical_account(raw: &str) -> Option<AccountId> {
    let value = AccountId::parse_encoded(raw).ok()?;
    (value.to_string() == raw).then_some(value)
}
fn canonical_asset_definition(raw: &str) -> Option<AssetDefinitionId> {
    let value = AssetDefinitionId::parse_address_literal(raw).ok()?;
    (value.to_string() == raw).then_some(value)
}
fn canonical_from_str<T>(raw: &str) -> Option<T>
where
    T: FromStr + ToString,
{
    let value = raw.parse::<T>().ok()?;
    (value.to_string() == raw).then_some(value)
}
fn canonical_hex_bytes(raw: &str) -> Option<Vec<u8>> {
    let hex = raw.strip_prefix("0x")?;
    if hex.len() % 2 != 0
        || !hex
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return None;
    }
    hex::decode(hex).ok()
}
fn canonical_numeric_string<T>(field: &njson::Value) -> Option<T>
where
    T: FromStr + ToString,
{
    let spelling = field.as_str()?;
    let value = spelling.parse::<T>().ok()?;
    (value.to_string() == spelling).then_some(value)
}
fn canonical_int_string(field: &njson::Value) -> Option<IntValueV1> {
    IntValueV1::try_new(canonical_numeric_string::<BigInt>(field)?).ok()
}
/// Active payload of one typed JSON getter.
enum GetterPayload {
    /// A host-allocated pointer-ABI value.
    Pointer(PointerType, Vec<u8>),
    /// One scalar ABI word, such as a `bool`.
    Word(u64),
}
/// Convert a present JSON field into the getter's active payload, or `None`
/// when the field's JSON value is not the getter's exact canonical type.
fn getter_value(number: u32, field: &njson::Value) -> Option<GetterPayload> {
    use GetterPayload::{Pointer, Word};
    Some(match number {
        syscalls::SYSCALL_JSON_GET_JSON => {
            let json = json_from_value_ref(field).ok()?;
            Pointer(PointerType::Json, encode_canonical_norito(&json).ok()?)
        }
        syscalls::SYSCALL_JSON_GET_NAME => {
            let raw = field.as_str()?;
            let value = Name::from_str(raw).ok()?;
            if value.as_ref() != raw {
                return None;
            }
            Pointer(PointerType::Name, encode_canonical_norito(&value).ok()?)
        }
        syscalls::SYSCALL_JSON_GET_ACCOUNT_ID => Pointer(
            PointerType::AccountId,
            encode_canonical_norito(&canonical_account(field.as_str()?)?).ok()?,
        ),
        syscalls::SYSCALL_JSON_GET_NFT_ID => Pointer(
            PointerType::NftId,
            encode_canonical_norito(&canonical_from_str::<NftId>(field.as_str()?)?).ok()?,
        ),
        syscalls::SYSCALL_JSON_GET_BLOB_HEX => {
            Pointer(PointerType::Blob, canonical_hex_bytes(field.as_str()?)?)
        }
        syscalls::SYSCALL_JSON_GET_ASSET_DEFINITION_ID => Pointer(
            PointerType::AssetDefinitionId,
            encode_canonical_norito(&canonical_asset_definition(field.as_str()?)?).ok()?,
        ),
        syscalls::SYSCALL_JSON_GET_INT => {
            let frame = canonical_int_string(field)?.encode_frame().ok()?;
            Pointer(PointerType::Int, frame)
        }
        syscalls::SYSCALL_JSON_GET_DECIMAL => {
            let value = canonical_numeric_string::<Numeric>(field)?;
            let frame = DecimalValueV1::from_canonical_numeric(value)
                .ok()?
                .encode_frame()
                .ok()?;
            Pointer(PointerType::Decimal, frame)
        }
        syscalls::SYSCALL_JSON_GET_QUANTITY => {
            let frame = QuantityValueV1::new(canonical_numeric_string::<Quantity>(field)?)
                .encode_frame()
                .ok()?;
            Pointer(PointerType::Quantity, frame)
        }
        syscalls::SYSCALL_JSON_GET_STRING => {
            Pointer(PointerType::Blob, field.as_str()?.as_bytes().to_vec())
        }
        syscalls::SYSCALL_JSON_GET_BOOL => Word(u64::from(field.as_bool()?)),
        _ => return None,
    })
}
/// Execute one typed JSON getter and materialize `Option<T>` as an active-only
/// compiler-owned sum handle in `r10`.
///
/// A key absent from the JSON object produces `Option::none`. A non-object
/// root, or a present field whose JSON value is not the getter's exact
/// canonical type, traps with [`VMError::DecodeError`]: malformed input never
/// reads as absent. Malformed pointer envelopes or noncanonical root/key
/// payloads remain deterministic VM errors.
pub fn typed_getter(
    vm: &mut IVM,
    number: u32,
    resolver: AddressResolver,
) -> Result<JsonGetterCost, VMError> {
    if !syscalls::is_json_getter_syscall(number) {
        return Err(VMError::UnknownSyscall(number));
    }
    let json_tlv = load_tlv(vm, vm.register(10), PointerType::Json, resolver)?;
    let key_tlv = load_tlv(vm, vm.register(11), PointerType::Name, resolver)?;
    let json: Json = decode_canonical(json_tlv.payload)?;
    let key: Name = decode_canonical(key_tlv.payload)?;
    let value = StackSafeJsonValue::new(
        json.try_into_any_norito()
            .map_err(|_| VMError::DecodeError)?,
    );
    let converted = match value.value().as_object() {
        None => Err(VMError::DecodeError),
        Some(object) => match object.get(key.as_ref()) {
            None => Ok(None),
            Some(field) => getter_value(number, field)
                .map(Some)
                .ok_or(VMError::DecodeError),
        },
    };
    drop(value);
    let converted = converted?;
    let input_bytes = json_tlv.payload.len().saturating_add(key_tlv.payload.len());
    let layout = crate::sum::SumLayoutV1::option(1).map_err(|_| VMError::DecodeError)?;
    let (handle, payload_bytes) = match converted {
        Some(GetterPayload::Pointer(pointer_type, payload)) => {
            let pointer = allocate_tlv(vm, pointer_type, &payload)?;
            (
                crate::sum::allocate_words(vm, layout, 1, &[pointer])?,
                payload.len(),
            )
        }
        Some(GetterPayload::Word(word)) => (
            crate::sum::allocate_words(vm, layout, 1, &[word])?,
            core::mem::size_of::<u64>(),
        ),
        None => (crate::sum::allocate_words(vm, layout, 0, &[])?, 0),
    };
    vm.set_register(10, handle);
    Ok(JsonGetterCost {
        input_bytes,
        output_bytes: payload_bytes.saturating_add(16),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{core_host::CoreHost, memory::Memory};
    use iroha_crypto::{Algorithm, KeyPair};
    use ivm_abi::{
        json::{JsonConstructionNodeV1, JsonConstructionSchemaV1},
        state_value::{StateValueKindV1, StateValueNodeV1, StateValueSchemaV1},
    };
    const TWO_POW_200: &str = "1606938044258990275541962092341162602522202993782792835301376";
    const MAX_INT_V1: &str = "6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042047";
    const MIN_INT_V1: &str = "-6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042048";
    const ABOVE_MAX_INT_V1: &str = "6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042048";
    const BELOW_MIN_INT_V1: &str = "-6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042049";
    fn tlv(pointer_type: PointerType, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(7 + payload.len() + Hash::LENGTH);
        bytes.extend_from_slice(&(pointer_type as u16).to_be_bytes());
        bytes.push(1);
        bytes.extend_from_slice(
            &u32::try_from(payload.len())
                .expect("test payload length")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(payload);
        bytes.extend_from_slice(Hash::new(payload).as_ref());
        bytes
    }
    fn leaf(kind: StateValueKindV1) -> StateValueSchemaV1 {
        StateValueSchemaV1 {
            nodes: vec![StateValueNodeV1::Leaf(kind)],
        }
    }
    fn quantity_frame(value: Quantity) -> Vec<u8> {
        QuantityValueV1::new(value)
            .encode_frame()
            .expect("quantity frame")
    }
    fn nested_list_fixture(
        vm: &mut IVM,
        wrappers: usize,
        kind: StateValueKindV1,
        mut word: u64,
    ) -> (StateValueSchemaV1, u64) {
        let mut schema = leaf(kind);
        let layout = crate::list::ListLayoutV1::try_new(1, 1).expect("unary list layout");
        for _ in 0..wrappers {
            word =
                crate::list::allocate_words(vm, layout, &[vec![word]]).expect("nested list value");
            schema = StateValueSchemaV1 {
                nodes: vec![StateValueNodeV1::List {
                    element: Box::new(schema),
                    capacity: 1,
                }],
            };
        }
        (schema, word)
    }
    fn nested_option_schema(wrappers: usize, kind: StateValueKindV1) -> StateValueSchemaV1 {
        let mut nodes = vec![StateValueNodeV1::Option; wrappers];
        nodes.push(StateValueNodeV1::Leaf(kind));
        StateValueSchemaV1 { nodes }
    }
    fn nested_some_options(vm: &mut IVM, wrappers: usize, mut word: u64) -> u64 {
        let layout = crate::sum::SumLayoutV1::option(1).expect("unary Option layout");
        for _ in 0..wrappers {
            word = crate::sum::allocate_words(vm, layout, 1, &[word]).expect("nested Option::some");
        }
        word
    }
    fn install_build_inputs(vm: &mut IVM, schema: &JsonConstructionSchemaV1, words: &[u64]) {
        assert!(schema.validate(), "test construction schema must be valid");
        let schema_payload =
            encode_canonical_norito(schema).expect("canonical construction schema");
        let schema_pointer = vm
            .alloc_input_tlv(&tlv(PointerType::NoritoBytes, &schema_payload))
            .expect("construction schema TLV");
        let byte_len = u64::try_from(words.len())
            .expect("test word count")
            .checked_mul(8)
            .expect("test word table length");
        let word_table = vm.alloc_heap(byte_len).expect("construction word table");
        for (index, word) in words.iter().copied().enumerate() {
            let offset = u64::try_from(index)
                .expect("test word index")
                .checked_mul(8)
                .expect("test word offset");
            vm.store_u64(word_table + offset, word)
                .expect("construction table word");
        }
        vm.set_register(10, schema_pointer);
        vm.set_register(11, word_table);
        vm.set_register(
            12,
            u64::try_from(words.len()).expect("test construction word count"),
        );
    }
    fn getter_payload(
        vm: &mut IVM,
        json_pointer: u64,
        key: &str,
        syscall: u32,
    ) -> (PointerType, Vec<u8>) {
        let key: Name = key.parse().expect("valid JSON key");
        let key_payload = encode_canonical_norito(&key).expect("canonical key payload");
        let key_pointer = vm
            .alloc_input_tlv(&tlv(PointerType::Name, &key_payload))
            .expect("key TLV");
        vm.set_register(10, json_pointer);
        vm.set_register(11, key_pointer);
        typed_getter(vm, syscall, CoreHost::resolve_code_tlv_addr).expect("typed JSON getter");
        let (some, words) = crate::sum::read_words(
            vm,
            vm.register(10),
            crate::sum::SumLayoutV1::option(1).expect("typed getter Option layout"),
        )
        .expect("read typed getter Option");
        assert!(some, "fixture field must produce Option::some");
        assert_eq!(words.len(), 1);
        let output = vm.validate_tlv(words[0]).expect("typed getter output TLV");
        (output.type_id, output.payload.to_vec())
    }
    #[test]
    fn construction_schema_decode_rejects_alternate_layouts_independently_of_ambient_flags() {
        let schema = JsonConstructionSchemaV1 {
            nodes: vec![
                JsonConstructionNodeV1::Object {
                    keys: vec!["value".to_owned()],
                },
                JsonConstructionNodeV1::Value {
                    schema: leaf(StateValueKindV1::Int),
                },
            ],
        };
        let canonical =
            ivm_abi::codec::encode_canonical_norito(&schema).expect("canonical JSON schema");
        assert_eq!(
            decode_canonical::<JsonConstructionSchemaV1>(&canonical),
            Ok(schema.clone())
        );
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let alternate = {
            let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            to_bytes(&schema).expect("alternate JSON schema")
        };
        assert_ne!(alternate, canonical);
        assert_eq!(
            decode_canonical::<JsonConstructionSchemaV1>(&alternate),
            Err(VMError::DecodeError)
        );
        let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        let ambient_before = to_bytes(&schema).expect("ambient JSON schema");
        assert_eq!(
            decode_canonical::<JsonConstructionSchemaV1>(&canonical),
            Ok(schema.clone())
        );
        assert_eq!(
            to_bytes(&schema).expect("ambient JSON schema after decode"),
            ambient_before
        );
    }
    #[test]
    fn native_json_cursor_uses_opaque_canonical_frame_hex() {
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
        let mut vm = IVM::new(u64::MAX);
        let pointer = allocate_tlv(&mut vm, PointerType::NoritoBytes, &frame).unwrap();
        let schema = StateValueSchemaV1 {
            nodes: vec![StateValueNodeV1::StateCursor(iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 { nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int)] })],
        };
        let value = convert_state_schema(
            &vm,
            &schema,
            &[pointer],
            CoreHost::resolve_code_tlv_addr,
            &mut BuildStats::default(),
        )
        .unwrap();
        assert_eq!(
            value.value(),
            &njson::Value::from(format!("0x{}", hex::encode(frame)))
        );
        let wrong = StateValueSchemaV1 {
            nodes: vec![StateValueNodeV1::StateCursor(iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 { nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Bool)] })],
        };
        assert!(
            convert_state_schema(
                &vm,
                &wrong,
                &[pointer],
                CoreHost::resolve_code_tlv_addr,
                &mut BuildStats::default()
            )
            .is_err()
        );
    }
    #[test]
    fn native_json_unit_and_errors_require_canonical_scalar_values() {
        let vm = IVM::new(u64::MAX);
        for (node, word, expected) in [
            (StateValueNodeV1::Unit, 0, njson::Value::Null),
            (StateValueNodeV1::Enum(iroha_data_model::smart_contract::manifest::ContractEnumTypeDescriptorV1 {
                identity: "local::Status".into(),
                variants: vec![
                    iroha_data_model::smart_contract::manifest::ContractEnumVariantDescriptorV1 { name: "Open".into(), code: 1 },
                    iroha_data_model::smart_contract::manifest::ContractEnumVariantDescriptorV1 { name: "Closed".into(), code: 7 },
                ],
            }), 7, njson::Value::String("Closed".into())),
            (
                StateValueNodeV1::Error(ivm_abi::error_types::list_error_type()),
                2,
                njson::Value::String("CapacityExceeded".into()),
            ),
        ] {
            let schema = StateValueSchemaV1 { nodes: vec![node] };
            assert!(ivm_abi::json::json_value_schema_is_supported(&schema));
            let value = convert_state_schema(
                &vm,
                &schema,
                &[word],
                CoreHost::resolve_code_tlv_addr,
                &mut BuildStats::default(),
            )
            .expect("canonical nominal scalar");
            assert_eq!(value.value(), &expected);
            assert!(
                convert_state_schema(
                    &vm,
                    &schema,
                    &[u64::MAX],
                    CoreHost::resolve_code_tlv_addr,
                    &mut BuildStats::default()
                )
                .is_err()
            );
        }
    }
    #[test]
    fn native_json_state_conversion_is_bounded_and_stack_safe_at_256_schema_nodes() {
        std::thread::Builder::new()
            .name("json-state-small-stack".to_owned())
            .stack_size(128 * 1024)
            .spawn(|| {
                let mut vm = IVM::new(u64::MAX);
                let (list_schema, list_handle) = nested_list_fixture(
                    &mut vm,
                    MAX_STATE_VALUE_NODES - 1,
                    StateValueKindV1::Bool,
                    1,
                );
                let mut stats = BuildStats::default();
                let value = convert_state_schema(
                    &vm,
                    &list_schema,
                    &[list_handle],
                    CoreHost::resolve_code_tlv_addr,
                    &mut stats,
                )
                .expect("convert 255 nested Lists");
                let mut current = value.value();
                for _ in 0..MAX_STATE_VALUE_NODES - 1 {
                    let njson::Value::Array(items) = current else {
                        panic!("each nested List must produce a JSON array");
                    };
                    assert_eq!(items.len(), 1);
                    current = &items[0];
                }
                assert_eq!(current, &njson::Value::Bool(true));
                assert_eq!(stats.collection_elements, MAX_STATE_VALUE_NODES - 1);
                drop(value);
                let option_schema =
                    nested_option_schema(MAX_STATE_VALUE_NODES - 1, StateValueKindV1::Bool);
                let option_handle = nested_some_options(&mut vm, MAX_STATE_VALUE_NODES - 1, 1);
                let mut stats = BuildStats::default();
                let option_value = convert_state_schema(
                    &vm,
                    &option_schema,
                    &[option_handle],
                    CoreHost::resolve_code_tlv_addr,
                    &mut stats,
                )
                .expect("convert 255 nested Options");
                let mut current = option_value.value();
                for _ in 0..MAX_STATE_VALUE_NODES - 1 {
                    let object = current.as_object().expect("each Option retains its tag");
                    assert_eq!(object.len(), 1);
                    current = object.get("some").expect("active Option tag");
                }
                assert_eq!(current, &njson::Value::Bool(true));
                assert_eq!(stats.collection_elements, MAX_STATE_VALUE_NODES - 1);
                drop(option_value);
                let (too_deep, too_deep_handle) =
                    nested_list_fixture(&mut vm, MAX_STATE_VALUE_NODES, StateValueKindV1::Bool, 1);
                assert!(matches!(
                    convert_state_schema(
                        &vm,
                        &too_deep,
                        &[too_deep_handle],
                        CoreHost::resolve_code_tlv_addr,
                        &mut BuildStats::default(),
                    ),
                    Err(VMError::DecodeError)
                ));
                let malformed_schema =
                    nested_option_schema(MAX_STATE_VALUE_NODES - 1, StateValueKindV1::Bool);
                let option_layout =
                    crate::sum::SumLayoutV1::option(1).expect("unary Option layout");
                let malformed_inner = crate::sum::allocate_words(&mut vm, option_layout, 0, &[])
                    .expect("innermost Option::none");
                vm.store_u64(malformed_inner + 8, 1)
                    .expect("forge inactive Option payload");
                let malformed_outer =
                    nested_some_options(&mut vm, MAX_STATE_VALUE_NODES - 2, malformed_inner);
                assert!(matches!(
                    convert_state_schema(
                        &vm,
                        &malformed_schema,
                        &[malformed_outer],
                        CoreHost::resolve_code_tlv_addr,
                        &mut BuildStats::default(),
                    ),
                    Err(VMError::DecodeError)
                ));
                let mut node_index = 0usize;
                assert_eq!(
                    state_node_word_count(&option_schema.nodes, &mut node_index),
                    Ok(1)
                );
                assert_eq!(node_index, MAX_STATE_VALUE_NODES);
                let too_many_options =
                    nested_option_schema(MAX_STATE_VALUE_NODES, StateValueKindV1::Bool);
                let mut too_many_index = 0usize;
                assert_eq!(
                    state_node_word_count(&too_many_options.nodes, &mut too_many_index),
                    Err(VMError::DecodeError)
                );
            })
            .expect("spawn small-stack JSON state test")
            .join()
            .expect("small-stack JSON state test");
    }
    #[test]
    fn build_json_deep_success_and_later_invalid_sibling_cleanup_are_stack_safe() {
        std::thread::Builder::new()
            .name("json-build-small-stack".to_owned())
            .stack_size(128 * 1024)
            .spawn(|| {
                let mut vm = IVM::new(u64::MAX);
                let nesting = njson::MAX_JSON_VALUE_NESTING_DEPTH - 1;
                let expected = Json::from_raw_json(format!(
                    "{}true{}",
                    "[".repeat(nesting),
                    "]".repeat(nesting)
                ))
                .expect("valid deep JSON fixture");
                let expected_payload =
                    encode_canonical_norito(&expected).expect("canonical deep JSON payload");

                {
                    let (state_schema, state_handle) = nested_list_fixture(
                        &mut vm,
                        nesting,
                        StateValueKindV1::Bool,
                        1,
                    );
                    let schema = JsonConstructionSchemaV1 {
                        nodes: vec![JsonConstructionNodeV1::Value {
                            schema: state_schema,
                        }],
                    };
                    install_build_inputs(&mut vm, &schema, &[state_handle]);
                    build_json(&mut vm, CoreHost::resolve_code_tlv_addr)
                        .expect("build and drop a state-list value at the JSON nesting limit");
                    let output = vm
                        .validate_tlv(vm.register(10))
                        .expect("deep state-list JSON output");
                    assert_eq!(output.type_id, PointerType::Json);
                    assert_eq!(output.payload, expected_payload);
                }

                {
                    let state_schema = nested_option_schema(nesting, StateValueKindV1::Bool);
                    let state_handle = nested_some_options(&mut vm, nesting, 1);
                    let expected = Json::from_raw_json(format!(
                        "{}true{}", "{\"some\":".repeat(nesting), "}".repeat(nesting)
                    )).expect("valid tagged deep Option JSON");
                    let schema = JsonConstructionSchemaV1 {
                        nodes: vec![JsonConstructionNodeV1::Value { schema: state_schema }],
                    };
                    install_build_inputs(&mut vm, &schema, &[state_handle]);
                    build_json(&mut vm, CoreHost::resolve_code_tlv_addr)
                        .expect("build and drop tagged Options at the JSON nesting limit");
                    assert_eq!(
                        vm.validate_tlv(vm.register(10)).unwrap().payload,
                        encode_canonical_norito(&expected).unwrap(),
                    );
                }

                {
                    let mut nodes = Vec::with_capacity(MAX_JSON_CONSTRUCTION_NODES_V1);
                    nodes.extend(
                        (0..nesting)
                            .map(|_| JsonConstructionNodeV1::Array { arity: 1 }),
                    );
                    nodes.push(JsonConstructionNodeV1::Value {
                        schema: leaf(StateValueKindV1::Bool),
                    });
                    let schema = JsonConstructionSchemaV1 { nodes };
                    install_build_inputs(&mut vm, &schema, &[1]);
                    build_json(&mut vm, CoreHost::resolve_code_tlv_addr)
                        .expect("walk and drop construction nodes at the JSON nesting limit");
                    let output = vm
                        .validate_tlv(vm.register(10))
                        .expect("deep construction JSON output");
                    assert_eq!(output.type_id, PointerType::Json);
                    assert_eq!(output.payload, expected_payload);
                }

                {
                    for wrappers in [njson::MAX_JSON_VALUE_NESTING_DEPTH, MAX_STATE_VALUE_NODES - 1] {
                        let schema = JsonConstructionSchemaV1 {
                            nodes: vec![JsonConstructionNodeV1::Value {
                                schema: nested_option_schema(wrappers, StateValueKindV1::Bool),
                            }],
                        };
                        let handle = nested_some_options(&mut vm, wrappers, 1);
                        install_build_inputs(&mut vm, &schema, &[handle]);
                        let before = vm.register(10);
                        assert_eq!(build_json(&mut vm, CoreHost::resolve_code_tlv_addr), Err(VMError::DecodeError));
                        assert_eq!(vm.register(10), before, "over-limit tagged JSON is never published");
                    }
                }

                {
                    let deep_schema = nested_option_schema(MAX_STATE_VALUE_NODES - 1, StateValueKindV1::Bool);
                    let deep_handle = nested_some_options(&mut vm, MAX_STATE_VALUE_NODES - 1, 1);
                    let schema = JsonConstructionSchemaV1 {
                        nodes: vec![
                            JsonConstructionNodeV1::Array { arity: 2 },
                            JsonConstructionNodeV1::Value {
                                schema: deep_schema,
                            },
                            JsonConstructionNodeV1::Value {
                                schema: leaf(StateValueKindV1::Bool),
                            },
                        ],
                    };
                    install_build_inputs(&mut vm, &schema, &[deep_handle, 2]);
                    assert_eq!(
                        build_json(&mut vm, CoreHost::resolve_code_tlv_addr),
                        Err(VMError::DecodeError),
                        "the valid deep first sibling must be cleaned up after the later invalid Bool"
                    );
                }
            })
            .expect("spawn small-stack JSON build test")
            .join()
            .expect("small-stack JSON build test");
    }
    #[test]
    fn build_json_emits_canonical_payload_accepted_by_getter_under_alternate_flags() {
        let schema = JsonConstructionSchemaV1 {
            nodes: vec![
                JsonConstructionNodeV1::Object {
                    keys: vec!["name".to_owned()],
                },
                JsonConstructionNodeV1::Value {
                    schema: leaf(StateValueKindV1::Name),
                },
            ],
        };
        let name: Name = "wonderland".parse().expect("canonical name");
        let schema_payload = encode_canonical_norito(&schema).expect("canonical JSON schema");
        let name_payload = encode_canonical_norito(&name).expect("canonical name payload");
        let mut vm = IVM::new(u64::MAX);
        let schema_pointer = vm
            .alloc_input_tlv(&tlv(PointerType::NoritoBytes, &schema_payload))
            .expect("schema TLV");
        let name_pointer = vm
            .alloc_input_tlv(&tlv(PointerType::Name, &name_payload))
            .expect("name TLV");
        let table = vm.alloc_heap(8).expect("word table");
        vm.store_u64(table, name_pointer).expect("name table word");
        vm.set_register(10, schema_pointer);
        vm.set_register(11, table);
        vm.set_register(12, 1);
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let ambient_probe = vec!["preserve".to_owned(), "ambient".to_owned()];
        let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        let ambient_before = to_bytes(&ambient_probe).expect("ambient probe");
        build_json(&mut vm, CoreHost::resolve_code_tlv_addr)
            .expect("build JSON under alternate ambient flags");
        let json_pointer = vm.register(10);
        let json_output = vm.validate_tlv(json_pointer).expect("JSON output TLV");
        assert_eq!(json_output.type_id, PointerType::Json);
        let json_payload = json_output.payload.to_vec();
        let decoded_json: Json =
            decode_canonical(&json_payload).expect("JSON output is canonically encoded");
        assert_eq!(
            decoded_json
                .clone()
                .try_into_any_norito::<njson::Value>()
                .expect("decode JSON value"),
            norito::json!({"name": "wonderland"})
        );
        assert_eq!(
            json_payload,
            encode_canonical_norito(&decoded_json).expect("re-encode canonical JSON")
        );
        let (pointer_type, getter_payload) = getter_payload(
            &mut vm,
            json_pointer,
            "name",
            syscalls::SYSCALL_JSON_GET_NAME,
        );
        assert_eq!(pointer_type, PointerType::Name);
        assert_eq!(
            decode_canonical::<Name>(&getter_payload),
            Ok(name.clone()),
            "the getter must accept JSON_BUILD output without an ambient-layout compatibility mode"
        );
        assert_eq!(
            getter_payload,
            encode_canonical_norito(&name).expect("re-encode canonical name")
        );
        assert_eq!(
            to_bytes(&ambient_probe).expect("ambient probe after JSON syscalls"),
            ambient_before,
            "canonical output encoding must restore the caller's ambient layout"
        );
    }
    #[test]
    fn typed_getters_emit_all_norito_outputs_canonically_under_alternate_flags() {
        let name: Name = "wonderland".parse().expect("canonical name");
        let account = AccountId::new(
            KeyPair::random_with_algorithm(Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let domain = DomainId::try_new("wonderland", "universal").expect("canonical domain");
        let nft = NftId::new(domain.clone(), "n0".parse().expect("NFT name"));
        let asset_definition =
            AssetDefinitionId::derive_from_components(domain, "rose".parse().expect("asset name"));
        let nested_value = norito::json!({"inner": true});
        let nested_json = Json::from(nested_value.clone());
        let mut object = njson::Map::new();
        object.insert("json".to_owned(), nested_value);
        object.insert("name".to_owned(), njson::Value::from(name.to_string()));
        object.insert(
            "account".to_owned(),
            njson::Value::from(account.to_string()),
        );
        object.insert("nft".to_owned(), njson::Value::from(nft.to_string()));
        object.insert(
            "asset_definition".to_owned(),
            njson::Value::from(asset_definition.to_string()),
        );
        let root = Json::from(njson::Value::Object(object));
        let root_payload = encode_canonical_norito(&root).expect("canonical root JSON");
        let mut vm = IVM::new(u64::MAX);
        let root_pointer = vm
            .alloc_input_tlv(&tlv(PointerType::Json, &root_payload))
            .expect("root JSON TLV");
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let ambient_probe = vec!["preserve".to_owned(), "ambient".to_owned()];
        let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        let ambient_before = to_bytes(&ambient_probe).expect("ambient probe");
        let (pointer_type, payload) = getter_payload(
            &mut vm,
            root_pointer,
            "json",
            syscalls::SYSCALL_JSON_GET_JSON,
        );
        assert_eq!(pointer_type, PointerType::Json);
        assert_eq!(decode_canonical::<Json>(&payload), Ok(nested_json.clone()));
        assert_eq!(
            payload,
            encode_canonical_norito(&nested_json).expect("canonical nested JSON")
        );
        let (pointer_type, payload) = getter_payload(
            &mut vm,
            root_pointer,
            "name",
            syscalls::SYSCALL_JSON_GET_NAME,
        );
        assert_eq!(pointer_type, PointerType::Name);
        assert_eq!(decode_canonical::<Name>(&payload), Ok(name.clone()));
        assert_eq!(
            payload,
            encode_canonical_norito(&name).expect("canonical name")
        );
        let (pointer_type, payload) = getter_payload(
            &mut vm,
            root_pointer,
            "account",
            syscalls::SYSCALL_JSON_GET_ACCOUNT_ID,
        );
        assert_eq!(pointer_type, PointerType::AccountId);
        assert_eq!(decode_canonical::<AccountId>(&payload), Ok(account.clone()));
        assert_eq!(
            payload,
            encode_canonical_norito(&account).expect("canonical account")
        );
        let (pointer_type, payload) = getter_payload(
            &mut vm,
            root_pointer,
            "nft",
            syscalls::SYSCALL_JSON_GET_NFT_ID,
        );
        assert_eq!(pointer_type, PointerType::NftId);
        assert_eq!(decode_canonical::<NftId>(&payload), Ok(nft.clone()));
        assert_eq!(
            payload,
            encode_canonical_norito(&nft).expect("canonical NFT")
        );
        let (pointer_type, payload) = getter_payload(
            &mut vm,
            root_pointer,
            "asset_definition",
            syscalls::SYSCALL_JSON_GET_ASSET_DEFINITION_ID,
        );
        assert_eq!(pointer_type, PointerType::AssetDefinitionId);
        assert_eq!(
            decode_canonical::<AssetDefinitionId>(&payload),
            Ok(asset_definition.clone())
        );
        assert_eq!(
            payload,
            encode_canonical_norito(&asset_definition).expect("canonical asset definition")
        );
        assert_eq!(
            to_bytes(&ambient_probe).expect("ambient probe after typed getters"),
            ambient_before,
            "canonical getter encoding must restore the caller's ambient layout"
        );
    }
    #[test]
    fn build_json_uses_canonical_strings_across_the_signed_512_bit_integer_domain() {
        let values = ["0", TWO_POW_200, MAX_INT_V1, MIN_INT_V1]
            .map(|value| value.parse::<BigInt>().expect("canonical V1 int"));
        let schema = JsonConstructionSchemaV1 {
            nodes: core::iter::once(JsonConstructionNodeV1::Array { arity: 4 })
                .chain(values.iter().map(|_| JsonConstructionNodeV1::Value {
                    schema: leaf(StateValueKindV1::Int),
                }))
                .collect(),
        };
        let mut vm = IVM::new(u64::MAX);
        let schema_ptr = vm
            .alloc_input_tlv(&tlv(
                PointerType::NoritoBytes,
                &to_bytes(&schema).expect("schema"),
            ))
            .expect("schema TLV");
        let table = vm.alloc_heap(32).expect("word table");
        for (index, value) in values.iter().enumerate() {
            let frame = IntValueV1::try_new(value.clone())
                .expect("int is inside V1 domain")
                .encode_frame()
                .expect("canonical int frame");
            let pointer = vm
                .alloc_input_tlv(&tlv(PointerType::Int, &frame))
                .expect("int TLV");
            vm.store_u64(table + u64::try_from(index).unwrap() * 8, pointer)
                .expect("table word");
        }
        vm.set_register(10, schema_ptr);
        vm.set_register(11, table);
        vm.set_register(12, 4);
        build_json(&mut vm, CoreHost::resolve_code_tlv_addr).expect("build exact JSON");
        let output = vm.validate_tlv(vm.register(10)).expect("JSON output");
        let json: Json = decode_from_bytes(output.payload).expect("decode JSON");
        let value: njson::Value = json.try_into_any_norito().expect("JSON value");
        assert_eq!(
            value,
            njson::Value::Array(
                values
                    .iter()
                    .map(|value| njson::Value::from(value.to_string()))
                    .collect()
            )
        );
    }
    #[test]
    fn build_json_and_typed_getter_roundtrip_an_int_beyond_64_bits() {
        let value = TWO_POW_200
            .parse::<BigInt>()
            .expect("2^200 fits the Kotodama int domain");
        let schema = JsonConstructionSchemaV1 {
            nodes: vec![
                JsonConstructionNodeV1::Object {
                    keys: vec!["value".to_owned()],
                },
                JsonConstructionNodeV1::Value {
                    schema: leaf(StateValueKindV1::Int),
                },
            ],
        };
        let mut vm = IVM::new(u64::MAX);
        let schema_ptr = vm
            .alloc_input_tlv(&tlv(
                PointerType::NoritoBytes,
                &to_bytes(&schema).expect("schema"),
            ))
            .expect("schema TLV");
        let frame = IntValueV1::try_new(value.clone())
            .expect("int is inside V1 domain")
            .encode_frame()
            .expect("canonical int frame");
        let pointer = vm
            .alloc_input_tlv(&tlv(PointerType::Int, &frame))
            .expect("int TLV");
        let table = vm.alloc_heap(8).expect("word table");
        vm.store_u64(table, pointer).expect("table word");
        vm.set_register(10, schema_ptr);
        vm.set_register(11, table);
        vm.set_register(12, 1);
        build_json(&mut vm, CoreHost::resolve_code_tlv_addr)
            .expect("build exact integer JSON object");
        let json_pointer = vm.register(10);
        let output = vm.validate_tlv(json_pointer).expect("JSON output");
        let json: Json = decode_from_bytes(output.payload).expect("decode JSON");
        assert_eq!(
            json.try_into_any_norito::<njson::Value>()
                .expect("decode JSON value"),
            norito::json!({"value": TWO_POW_200})
        );
        let (pointer_type, payload) = getter_payload(
            &mut vm,
            json_pointer,
            "value",
            syscalls::SYSCALL_JSON_GET_INT,
        );
        assert_eq!(pointer_type, PointerType::Int);
        assert_eq!(
            IntValueV1::decode_frame(&payload)
                .expect("round-tripped int frame")
                .into_int(),
            value
        );
    }
    #[test]
    fn build_json_orders_keys_and_converts_amount_and_bytes() {
        let account = AccountId::new(
            KeyPair::random_with_algorithm(Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let account_payload = to_bytes(&account).expect("encode account");
        let amount = "1.25".parse::<Quantity>().expect("canonical quantity");
        let amount_payload = quantity_frame(amount);
        let schema = JsonConstructionSchemaV1 {
            nodes: vec![
                JsonConstructionNodeV1::Object {
                    keys: vec!["z_owner".into(), "a_amount".into(), "bytes".into()],
                },
                JsonConstructionNodeV1::Value {
                    schema: leaf(StateValueKindV1::AccountId),
                },
                JsonConstructionNodeV1::Value {
                    schema: leaf(StateValueKindV1::Quantity),
                },
                JsonConstructionNodeV1::Value {
                    schema: leaf(StateValueKindV1::Bytes),
                },
            ],
        };
        let schema_payload = to_bytes(&schema).expect("encode construction schema");
        let mut vm = IVM::new(u64::MAX);
        let schema_ptr = vm
            .alloc_input_tlv(&tlv(PointerType::NoritoBytes, &schema_payload))
            .expect("schema TLV");
        let account_ptr = vm
            .alloc_input_tlv(&tlv(PointerType::AccountId, &account_payload))
            .expect("account TLV");
        let amount_ptr = vm
            .alloc_input_tlv(&tlv(PointerType::Quantity, &amount_payload))
            .expect("amount TLV");
        let bytes_ptr = vm
            .alloc_input_tlv(&tlv(PointerType::Blob, &[0xab, 0x01]))
            .expect("bytes TLV");
        let table = vm.alloc_heap(24).expect("word table");
        for (index, word) in [account_ptr, amount_ptr, bytes_ptr].into_iter().enumerate() {
            vm.store_u64(table + u64::try_from(index).unwrap() * 8, word)
                .expect("table word");
        }
        vm.set_register(10, schema_ptr);
        vm.set_register(11, table);
        vm.set_register(12, 3);
        let gas = build_json(&mut vm, CoreHost::resolve_code_tlv_addr).expect("build JSON");
        let output = vm.validate_tlv(vm.register(10)).expect("JSON output");
        assert_eq!(
            gas,
            build_json_gas(
                schema_payload.len(),
                account_payload.len() + amount_payload.len() + 2,
                3,
                3,
                output.payload.len(),
            )
        );
        let json: Json = decode_from_bytes(output.payload).expect("decode JSON");
        let text = njson::to_string(&json).expect("render JSON");
        assert!(text.find("a_amount").unwrap() < text.find("z_owner").unwrap());
        assert!(text.contains(r#""a_amount":"1.25""#));
        assert!(text.contains(r#""bytes":"0xab01""#));
        assert!(text.contains(&account.to_string()));
    }
    #[test]
    fn build_json_options_roundtrip_through_public_arguments_with_exact_gas() {
        use ivm_abi::entrypoint::{
            EntrypointArgumentFieldV1, EntrypointArgumentSchemaV1, EntrypointListTypeNodeV1,
            EntrypointValueAtomV1 as Atom, EntrypointValueTypeNodeV1 as Node,
            EntrypointValueTypeV1,
        };
        let mut vm = IVM::new(u64::MAX);
        let layout = crate::sum::SumLayoutV1::option(1).unwrap();
        let none = crate::sum::allocate_words(&mut vm, layout, 0, &[]).unwrap();
        let some = crate::sum::allocate_words(&mut vm, layout, 1, &[0]).unwrap();
        let some_none = crate::sum::allocate_words(&mut vm, layout, 1, &[none]).unwrap();
        let some_some = crate::sum::allocate_words(&mut vm, layout, 1, &[some]).unwrap();
        let option = StateValueSchemaV1 {
            nodes: vec![StateValueNodeV1::Option, StateValueNodeV1::Unit],
        };
        let nested = StateValueSchemaV1 {
            nodes: vec![
                StateValueNodeV1::Option,
                StateValueNodeV1::Option,
                StateValueNodeV1::Unit,
            ],
        };
        let list = StateValueSchemaV1 {
            nodes: vec![StateValueNodeV1::List {
                element: Box::new(option.clone()),
                capacity: 3,
            }],
        };
        let list_handle = crate::list::allocate_words(
            &mut vm,
            crate::list::ListLayoutV1::try_new(3, 1).unwrap(),
            &[vec![some], vec![none]],
        )
        .unwrap();
        let some_list = crate::sum::allocate_words(&mut vm, layout, 1, &[list_handle]).unwrap();
        let mut optional_list = list.clone();
        optional_list.nodes.insert(0, StateValueNodeV1::Option);
        let list_node = Node::List(EntrypointListTypeNodeV1 { capacity: 3 });
        for (state, nodes, word, expected, members, atoms) in [
            (
                option.clone(),
                vec![Node::Option, Node::Unit],
                some,
                r#"{"value":{"some":null}}"#,
                1,
                vec![Atom::Tag(true), Atom::Unit],
            ),
            (
                option,
                vec![Node::Option, Node::Unit],
                none,
                r#"{"value":{"none":true}}"#,
                1,
                vec![Atom::Tag(false)],
            ),
            (
                nested.clone(),
                vec![Node::Option, Node::Option, Node::Unit],
                some_some,
                r#"{"value":{"some":{"some":null}}}"#,
                2,
                vec![Atom::Tag(true), Atom::Tag(true), Atom::Unit],
            ),
            (
                nested.clone(),
                vec![Node::Option, Node::Option, Node::Unit],
                some_none,
                r#"{"value":{"some":{"none":true}}}"#,
                2,
                vec![Atom::Tag(true), Atom::Tag(false)],
            ),
            (
                nested,
                vec![Node::Option, Node::Option, Node::Unit],
                none,
                r#"{"value":{"none":true}}"#,
                1,
                vec![Atom::Tag(false)],
            ),
            (
                list,
                vec![list_node.clone(), Node::Option, Node::Unit],
                list_handle,
                r#"{"value":[{"some":null},{"none":true}]}"#,
                4,
                vec![Atom::List(2), Atom::Tag(true), Atom::Unit, Atom::Tag(false)],
            ),
            (
                optional_list,
                vec![Node::Option, list_node, Node::Option, Node::Unit],
                some_list,
                r#"{"value":{"some":[{"some":null},{"none":true}]}}"#,
                5,
                vec![
                    Atom::Tag(true),
                    Atom::List(2),
                    Atom::Tag(true),
                    Atom::Unit,
                    Atom::Tag(false),
                ],
            ),
        ] {
            let construction = JsonConstructionSchemaV1 {
                nodes: vec![
                    JsonConstructionNodeV1::Object {
                        keys: vec!["value".into()],
                    },
                    JsonConstructionNodeV1::Value { schema: state },
                ],
            };
            install_build_inputs(&mut vm, &construction, &[word]);
            let gas = build_json(&mut vm, CoreHost::resolve_code_tlv_addr).unwrap();
            let output = vm.validate_tlv(vm.register(10)).unwrap();
            let json: Json = decode_canonical(output.payload).unwrap();
            assert_eq!(json.get(), expected);
            assert_eq!(
                gas,
                build_json_gas(
                    encode_canonical_norito(&construction).unwrap().len(),
                    0,
                    1,
                    members + 1,
                    output.payload.len(),
                ),
                "charge the root member, every active Option tag, list items, and all encoded bytes"
            );
            let schema = EntrypointArgumentSchemaV1 {
                fields: vec![EntrypointArgumentFieldV1 {
                    name: "value".into(),
                    ty: EntrypointValueTypeV1 { nodes },
                }],
            };
            let record =
                ivm_abi::arguments::encode_argument_record_from_json(&schema, &json).unwrap();
            assert_eq!(
                crate::argument_record::validate_argument_record(&schema, &record)
                    .unwrap()
                    .atoms,
                atoms
            );
            let record_ptr = allocate_tlv(&mut vm, PointerType::NoritoBytes, &record).unwrap();
            let schema_ptr = allocate_tlv(
                &mut vm,
                PointerType::NoritoBytes,
                &encode_canonical_norito(&schema).unwrap(),
            )
            .unwrap();
            vm.set_register(10, record_ptr);
            vm.set_register(11, schema_ptr);
            crate::argument_record::decode_argument_record(&mut vm).unwrap();
            assert_eq!(vm.register(11), 1);
            let materialized = vm.memory.load_u64(vm.register(10)).unwrap();
            install_build_inputs(&mut vm, &construction, &[materialized]);
            assert_eq!(
                build_json(&mut vm, CoreHost::resolve_code_tlv_addr),
                Ok(gas)
            );
            let rebuilt: Json =
                decode_canonical(vm.validate_tlv(vm.register(10)).unwrap().payload).unwrap();
            assert_eq!(
                rebuilt, json,
                "public argument decoding must preserve every Option tag"
            );
        }
    }
    #[test]
    fn build_json_rejects_malformed_option_unit_handles_before_output() {
        let mut vm = IVM::new(u64::MAX);
        let schema = JsonConstructionSchemaV1 {
            nodes: vec![JsonConstructionNodeV1::Value {
                schema: StateValueSchemaV1 {
                    nodes: vec![StateValueNodeV1::Option, StateValueNodeV1::Unit],
                },
            }],
        };
        let layout = crate::sum::SumLayoutV1::option(1).unwrap();
        let hidden = crate::sum::allocate_words(&mut vm, layout, 0, &[]).unwrap();
        vm.store_u64(hidden + 8, 1).unwrap();
        let bad_unit = crate::sum::allocate_words(&mut vm, layout, 1, &[1]).unwrap();
        let bad_tag = crate::sum::allocate_words(&mut vm, layout, 1, &[0]).unwrap();
        vm.store_u64(bad_tag, 2).unwrap();
        for word in [0, hidden, hidden + 1, bad_unit, bad_tag, u64::MAX] {
            install_build_inputs(&mut vm, &schema, &[word]);
            let before = vm.register(10);
            assert!(
                build_json(&mut vm, CoreHost::resolve_code_tlv_addr).is_err(),
                "{word:x}"
            );
            assert_eq!(
                vm.register(10),
                before,
                "malformed handles publish no JSON result"
            );
        }
    }
    #[test]
    fn build_json_recurses_through_list_and_active_only_option() {
        let amount = "1.25".parse::<Quantity>().expect("canonical quantity");
        let amount_payload = quantity_frame(amount);
        let element_schema = StateValueSchemaV1 {
            nodes: vec![
                StateValueNodeV1::Option,
                StateValueNodeV1::Leaf(StateValueKindV1::Quantity),
            ],
        };
        let list_schema = StateValueSchemaV1 {
            nodes: vec![StateValueNodeV1::List {
                element: Box::new(element_schema),
                capacity: 2,
            }],
        };
        let schema = JsonConstructionSchemaV1 {
            nodes: vec![JsonConstructionNodeV1::Value {
                schema: list_schema,
            }],
        };
        let mut vm = IVM::new(u64::MAX);
        let schema_ptr = vm
            .alloc_input_tlv(&tlv(
                PointerType::NoritoBytes,
                &to_bytes(&schema).expect("schema"),
            ))
            .expect("schema TLV");
        let amount_ptr = vm
            .alloc_input_tlv(&tlv(PointerType::Quantity, &amount_payload))
            .expect("amount TLV");
        let option_layout = crate::sum::SumLayoutV1::option(1).expect("option layout");
        let some = crate::sum::allocate_words(&mut vm, option_layout, 1, &[amount_ptr])
            .expect("some amount");
        let none = crate::sum::allocate_words(&mut vm, option_layout, 0, &[]).expect("none amount");
        let list_layout = crate::list::ListLayoutV1::try_new(2, 1).expect("list layout");
        let list = crate::list::allocate_words(&mut vm, list_layout, &[vec![some], vec![none]])
            .expect("option list");
        let table = vm.alloc_heap(8).expect("word table");
        vm.store_u64(table, list).expect("list word");
        vm.set_register(10, schema_ptr);
        vm.set_register(11, table);
        vm.set_register(12, 1);
        build_json(&mut vm, CoreHost::resolve_code_tlv_addr).expect("build option list JSON");
        let output = vm.validate_tlv(vm.register(10)).expect("JSON output");
        let json: Json = decode_from_bytes(output.payload).expect("decode JSON");
        let value: njson::Value = json.try_into_any_norito().expect("JSON value");
        assert_eq!(value, norito::json!([{ "some": "1.25" }, { "none": true }]));
    }
    #[test]
    fn build_json_preserves_full_u64_and_scale_28_quantity_without_floats() {
        let maximum = Numeric::new(u64::MAX, 0);
        let precise = "0.0000000000000000000000000001"
            .parse::<Quantity>()
            .expect("canonical scale-28 quantity");
        let schema = JsonConstructionSchemaV1 {
            nodes: vec![
                JsonConstructionNodeV1::Array { arity: 2 },
                JsonConstructionNodeV1::Value {
                    schema: leaf(StateValueKindV1::Int),
                },
                JsonConstructionNodeV1::Value {
                    schema: leaf(StateValueKindV1::Quantity),
                },
            ],
        };
        let mut vm = IVM::new(u64::MAX);
        let schema_ptr = vm
            .alloc_input_tlv(&tlv(
                PointerType::NoritoBytes,
                &to_bytes(&schema).expect("schema"),
            ))
            .expect("schema TLV");
        let maximum_ptr = vm
            .alloc_input_tlv(&tlv(
                PointerType::Int,
                &IntValueV1::try_new(maximum.mantissa().clone())
                    .expect("maximum test int is inside V1 domain")
                    .encode_frame()
                    .expect("maximum int frame"),
            ))
            .expect("int TLV");
        let precise_ptr = vm
            .alloc_input_tlv(&tlv(PointerType::Quantity, &quantity_frame(precise)))
            .expect("quantity TLV");
        let table = vm.alloc_heap(16).expect("word table");
        vm.store_u64(table, maximum_ptr).expect("u128 word");
        vm.store_u64(table + 8, precise_ptr).expect("quantity word");
        vm.set_register(10, schema_ptr);
        vm.set_register(11, table);
        vm.set_register(12, 2);
        build_json(&mut vm, CoreHost::resolve_code_tlv_addr).expect("build exact JSON");
        let output = vm.validate_tlv(vm.register(10)).expect("JSON output");
        let json: Json = decode_from_bytes(output.payload).expect("decode JSON");
        let value: njson::Value = json.try_into_any_norito().expect("JSON value");
        assert_eq!(
            value,
            njson::Value::Array(vec![
                njson::Value::from(u64::MAX.to_string()),
                njson::Value::from("0.0000000000000000000000000001"),
            ])
        );
    }
    #[test]
    fn int_getter_accepts_only_canonical_signed_512_bit_strings() {
        for spelling in ["0", "-1", TWO_POW_200, MAX_INT_V1, MIN_INT_V1] {
            let value =
                canonical_int_string(&njson::Value::from(spelling)).expect("canonical int string");
            assert_eq!(value.as_int().to_string(), spelling);
        }
        for value in [
            njson::Value::from(-1_i64),
            njson::Value::from(u64::MAX),
            njson::Value::from(1.5_f64),
            njson::Value::from(""),
            njson::Value::from("+1"),
            njson::Value::from("01"),
            njson::Value::from("-0"),
            njson::Value::from("1.0"),
            njson::Value::from("1e0"),
            njson::Value::from(" 1"),
            njson::Value::from("1 "),
            njson::Value::from(ABOVE_MAX_INT_V1),
            njson::Value::from(BELOW_MIN_INT_V1),
            njson::Value::Bool(true),
            njson::Value::Null,
            njson::Value::Array(Vec::new()),
            njson::Value::Object(njson::Map::new()),
        ] {
            assert_eq!(canonical_int_string(&value), None, "value: {value:?}");
        }
    }
    #[test]
    fn unassigned_exact_json_getter_numbers_fail_before_vm_state_changes() {
        let mut vm = IVM::new(50_000);
        vm.set_register(10, 0x1111);
        vm.set_register(11, 0x2222);
        vm.set_register(12, 0x3333);
        for number in 0x01_0163..=0x01_0165 {
            let registers_before = [vm.register(10), vm.register(11), vm.register(12)];
            let heap_before = vm.memory.heap_allocated_len();
            let gas_before = vm.remaining_gas();
            assert_eq!(
                typed_getter(&mut vm, number, CoreHost::resolve_code_tlv_addr),
                Err(VMError::UnknownSyscall(number))
            );
            assert_eq!(
                [vm.register(10), vm.register(11), vm.register(12)],
                registers_before
            );
            assert_eq!(vm.memory.heap_allocated_len(), heap_before);
            assert_eq!(vm.remaining_gas(), gas_before);
        }
    }
    #[test]
    fn typed_getter_returns_active_only_some_and_none_handles() {
        let json = Json::from(norito::json!({
            "count": "7",
            "maximum": MAX_INT_V1,
            "number": 7,
            "wrong": true,
        }));
        let json_payload = to_bytes(&json).expect("encode JSON");
        let mut vm = IVM::new(u64::MAX);
        let json_ptr = vm
            .alloc_input_tlv(&tlv(PointerType::Json, &json_payload))
            .expect("JSON TLV");
        let key: Name = "count".parse().expect("key");
        let key_ptr = vm
            .alloc_input_tlv(&tlv(PointerType::Name, &to_bytes(&key).unwrap()))
            .expect("key TLV");
        vm.set_register(10, json_ptr);
        vm.set_register(11, key_ptr);
        typed_getter(
            &mut vm,
            syscalls::SYSCALL_JSON_GET_INT,
            CoreHost::resolve_code_tlv_addr,
        )
        .expect("get count");
        let (some, words) = crate::sum::read_words(
            &vm,
            vm.register(10),
            crate::sum::SumLayoutV1::option(1).unwrap(),
        )
        .expect("read int option");
        assert!(some);
        let int = vm.validate_tlv(words[0]).expect("int TLV");
        assert_eq!(int.type_id, PointerType::Int);
        assert_eq!(
            IntValueV1::decode_frame(int.payload)
                .expect("int frame")
                .into_int(),
            BigInt::from_i128(7)
        );
        let maximum: Name = "maximum".parse().expect("maximum key");
        let maximum_ptr = vm
            .alloc_input_tlv(&tlv(
                PointerType::Name,
                &to_bytes(&maximum).expect("maximum key"),
            ))
            .expect("maximum key TLV");
        vm.set_register(10, json_ptr);
        vm.set_register(11, maximum_ptr);
        typed_getter(
            &mut vm,
            syscalls::SYSCALL_JSON_GET_INT,
            CoreHost::resolve_code_tlv_addr,
        )
        .expect("get maximum");
        let (some, words) = crate::sum::read_words(
            &vm,
            vm.register(10),
            crate::sum::SumLayoutV1::option(1).unwrap(),
        )
        .expect("read maximum int option");
        assert!(some);
        let int = vm.validate_tlv(words[0]).expect("maximum int TLV");
        assert_eq!(int.type_id, PointerType::Int);
        assert_eq!(
            IntValueV1::decode_frame(int.payload)
                .expect("maximum int frame")
                .into_int(),
            MAX_INT_V1.parse::<BigInt>().expect("maximum V1 int")
        );
        let missing: Name = "missing".parse().expect("missing key");
        let missing_ptr = vm
            .alloc_input_tlv(&tlv(PointerType::Name, &to_bytes(&missing).unwrap()))
            .expect("missing key TLV");
        vm.set_register(10, json_ptr);
        vm.set_register(11, missing_ptr);
        typed_getter(
            &mut vm,
            syscalls::SYSCALL_JSON_GET_INT,
            CoreHost::resolve_code_tlv_addr,
        )
        .expect("missing is none");
        assert_eq!(
            crate::sum::read_words(
                &vm,
                vm.register(10),
                crate::sum::SumLayoutV1::option(1).unwrap()
            ),
            Ok((false, vec![]))
        );
        let number: Name = "number".parse().expect("number key");
        let number_ptr = vm
            .alloc_input_tlv(&tlv(PointerType::Name, &to_bytes(&number).unwrap()))
            .expect("number key TLV");
        vm.set_register(10, json_ptr);
        vm.set_register(11, number_ptr);
        // A JSON number token is present but not a canonical decimal string.
        assert_eq!(
            typed_getter(
                &mut vm,
                syscalls::SYSCALL_JSON_GET_INT,
                CoreHost::resolve_code_tlv_addr,
            )
            .err(),
            Some(VMError::DecodeError)
        );
        let wrong: Name = "wrong".parse().expect("wrong-type key");
        let wrong_ptr = vm
            .alloc_input_tlv(&tlv(PointerType::Name, &to_bytes(&wrong).unwrap()))
            .expect("wrong-type key TLV");
        vm.set_register(10, json_ptr);
        vm.set_register(11, wrong_ptr);
        assert_eq!(
            typed_getter(
                &mut vm,
                syscalls::SYSCALL_JSON_GET_INT,
                CoreHost::resolve_code_tlv_addr,
            )
            .err(),
            Some(VMError::DecodeError),
            "a present field of the wrong JSON type traps"
        );
        let array = Json::from(norito::json!(["7"]));
        let array_ptr = vm
            .alloc_input_tlv(&tlv(
                PointerType::Json,
                &to_bytes(&array).expect("encode array JSON"),
            ))
            .expect("array JSON TLV");
        vm.set_register(10, array_ptr);
        vm.set_register(11, key_ptr);
        assert_eq!(
            typed_getter(
                &mut vm,
                syscalls::SYSCALL_JSON_GET_INT,
                CoreHost::resolve_code_tlv_addr,
            )
            .err(),
            Some(VMError::DecodeError),
            "a non-object root traps"
        );
    }
    #[test]
    fn typed_string_and_bool_getters_read_exact_json_types() {
        let json = Json::from(norito::json!({
            "label": "rose garden",
            "empty": "",
            "flag": true,
            "off": false,
            "number": 5,
            "quoted_flag": "true",
        }));
        let json_payload = to_bytes(&json).expect("encode JSON");
        let mut vm = IVM::new(u64::MAX);
        let json_ptr = vm
            .alloc_input_tlv(&tlv(PointerType::Json, &json_payload))
            .expect("JSON TLV");
        let layout = crate::sum::SumLayoutV1::option(1).expect("Option layout");
        let get = |vm: &mut IVM, number: u32, key: &str| {
            let key: Name = key.parse().expect("valid key");
            let key_ptr = vm
                .alloc_input_tlv(&tlv(PointerType::Name, &to_bytes(&key).expect("key")))
                .expect("key TLV");
            vm.set_register(10, json_ptr);
            vm.set_register(11, key_ptr);
            typed_getter(vm, number, CoreHost::resolve_code_tlv_addr)
                .map(|_| crate::sum::read_words(vm, vm.register(10), layout).expect("option"))
        };
        for (key, expected) in [("label", "rose garden"), ("empty", "")] {
            let (some, words) =
                get(&mut vm, syscalls::SYSCALL_JSON_GET_STRING, key).expect("string field");
            assert!(some, "{key}");
            let text = vm.validate_tlv(words[0]).expect("string TLV");
            assert_eq!(text.type_id, PointerType::Blob);
            assert_eq!(text.payload, expected.as_bytes());
        }
        assert_eq!(
            get(&mut vm, syscalls::SYSCALL_JSON_GET_BOOL, "flag"),
            Ok((true, vec![1]))
        );
        assert_eq!(
            get(&mut vm, syscalls::SYSCALL_JSON_GET_BOOL, "off"),
            Ok((true, vec![0]))
        );
        for number in [
            syscalls::SYSCALL_JSON_GET_STRING,
            syscalls::SYSCALL_JSON_GET_BOOL,
        ] {
            assert_eq!(get(&mut vm, number, "missing"), Ok((false, vec![])));
        }
        for (number, key) in [
            (syscalls::SYSCALL_JSON_GET_STRING, "number"),
            (syscalls::SYSCALL_JSON_GET_STRING, "flag"),
            (syscalls::SYSCALL_JSON_GET_BOOL, "quoted_flag"),
            (syscalls::SYSCALL_JSON_GET_BOOL, "number"),
        ] {
            assert_eq!(
                get(&mut vm, number, key),
                Err(VMError::DecodeError),
                "{key} has the wrong JSON type"
            );
        }
    }
    #[test]
    fn typed_decimal_getter_accepts_only_canonical_string_values() {
        let oversized = "9".repeat(200);
        let json = Json::from(norito::json!({
            "canonical": "-12345678901234567890.125",
            "zero": "0",
            "trailing": "1.2500",
            "leading_zero": "01",
            "plus": "+1",
            "exponent": "1e0",
            "number": 1.25,
            "oversized": oversized,
            "wrong": true,
        }));
        let json_payload = to_bytes(&json).expect("encode JSON");
        let mut vm = IVM::new(u64::MAX);
        let json_ptr = vm
            .alloc_input_tlv(&tlv(PointerType::Json, &json_payload))
            .expect("JSON TLV");
        let option_layout = crate::sum::SumLayoutV1::option(1).expect("Option<decimal> layout");
        for (key, expected) in [
            (
                "canonical",
                Some(
                    "-12345678901234567890.125"
                        .parse::<Numeric>()
                        .expect("canonical decimal"),
                ),
            ),
            ("zero", Some(Numeric::zero())),
            ("trailing", None),
            ("leading_zero", None),
            ("plus", None),
            ("exponent", None),
            ("number", None),
            ("oversized", None),
            ("wrong", None),
            ("missing", None),
        ] {
            let key_name: Name = key.parse().expect("valid key");
            let key_ptr = vm
                .alloc_input_tlv(&tlv(
                    PointerType::Name,
                    &to_bytes(&key_name).expect("encode key"),
                ))
                .expect("key TLV");
            vm.set_register(10, json_ptr);
            vm.set_register(11, key_ptr);
            let result = typed_getter(
                &mut vm,
                syscalls::SYSCALL_JSON_GET_DECIMAL,
                CoreHost::resolve_code_tlv_addr,
            );
            if expected.is_none() && key != "missing" {
                // A present field that is not a canonical decimal string traps.
                assert_eq!(result.err(), Some(VMError::DecodeError), "{key}");
                continue;
            }
            result.expect("typed decimal getter");
            let (some, payload) = crate::sum::read_words(&vm, vm.register(10), option_layout)
                .expect("read Option<decimal>");
            match expected {
                Some(expected) => {
                    assert!(some, "{key} must produce Option::some");
                    let decimal = vm.validate_tlv(payload[0]).expect("decimal TLV");
                    assert_eq!(decimal.type_id, PointerType::Decimal);
                    let decimal = DecimalValueV1::decode_frame(decimal.payload)
                        .expect("decode canonical decimal")
                        .into_numeric();
                    assert_eq!(decimal, expected);
                }
                None => {
                    assert!(!some, "{key} must produce Option::none");
                    assert!(payload.is_empty(), "none has no placeholder payload");
                }
            }
        }
    }
    #[test]
    fn typed_quantity_getter_accepts_only_canonical_string_values() {
        let oversized = "9".repeat(200);
        let json = Json::from(norito::json!({
            "decimal": "1.25",
            "zero": "0",
            "trailing": "1.2500",
            "leading_zero": "01",
            "plus": "+1",
            "exponent": "1e0",
            "integer": 7,
            "negative": "-1",
            "oversized": oversized,
            "wrong": true,
        }));
        let json_payload = to_bytes(&json).expect("encode JSON");
        let mut vm = IVM::new(u64::MAX);
        let json_ptr = vm
            .alloc_input_tlv(&tlv(PointerType::Json, &json_payload))
            .expect("JSON TLV");
        let option_layout = crate::sum::SumLayoutV1::option(1).expect("Option<quantity> layout");
        for (key, expected) in [
            (
                "decimal",
                Some("1.25".parse::<Quantity>().expect("canonical quantity")),
            ),
            ("zero", Some(Quantity::zero())),
            ("trailing", None),
            ("leading_zero", None),
            ("plus", None),
            ("exponent", None),
            ("integer", None),
            ("negative", None),
            ("oversized", None),
            ("wrong", None),
            ("missing", None),
        ] {
            let key: Name = key.parse().expect("valid key");
            let key_ptr = vm
                .alloc_input_tlv(&tlv(
                    PointerType::Name,
                    &to_bytes(&key).expect("encode key"),
                ))
                .expect("key TLV");
            vm.set_register(10, json_ptr);
            vm.set_register(11, key_ptr);
            let result = typed_getter(
                &mut vm,
                syscalls::SYSCALL_JSON_GET_QUANTITY,
                CoreHost::resolve_code_tlv_addr,
            );
            if expected.is_none() && key.as_ref() != "missing" {
                // A present field that is not a canonical quantity string traps.
                assert_eq!(result.err(), Some(VMError::DecodeError), "{key}");
                continue;
            }
            result.expect("typed quantity getter");
            let (some, payload) = crate::sum::read_words(&vm, vm.register(10), option_layout)
                .expect("read Option<quantity>");
            match expected {
                Some(expected) => {
                    assert!(some, "{key} must produce Option::some");
                    let amount = vm.validate_tlv(payload[0]).expect("quantity TLV");
                    assert_eq!(amount.type_id, PointerType::Quantity);
                    let amount = QuantityValueV1::decode_frame(amount.payload)
                        .expect("decode canonical quantity")
                        .into_quantity();
                    assert_eq!(amount, expected);
                }
                None => {
                    assert!(!some, "{key} must produce Option::none");
                    assert!(payload.is_empty(), "none has no placeholder payload");
                }
            }
        }
    }
    #[test]
    fn build_json_rejects_duplicate_key_schema_before_reading_values() {
        let duplicate = JsonConstructionSchemaV1 {
            nodes: vec![
                JsonConstructionNodeV1::Object {
                    keys: vec!["same".into(), "same".into()],
                },
                JsonConstructionNodeV1::Value {
                    schema: leaf(StateValueKindV1::Int),
                },
                JsonConstructionNodeV1::Value {
                    schema: leaf(StateValueKindV1::Int),
                },
            ],
        };
        let mut vm = IVM::new(u64::MAX);
        let schema_ptr = vm
            .alloc_input_tlv(&tlv(
                PointerType::NoritoBytes,
                &to_bytes(&duplicate).expect("encode duplicate schema"),
            ))
            .expect("schema TLV");
        vm.set_register(10, schema_ptr);
        vm.set_register(11, 0);
        vm.set_register(12, 2);
        assert_eq!(
            build_json(&mut vm, CoreHost::resolve_code_tlv_addr),
            Err(VMError::DecodeError)
        );
    }
    #[test]
    fn build_json_rejects_noncanonical_quantities_and_hidden_option_payloads() {
        let quantity_schema = JsonConstructionSchemaV1 {
            nodes: vec![JsonConstructionNodeV1::Value {
                schema: leaf(StateValueKindV1::Quantity),
            }],
        };
        let mut vm = IVM::new(u64::MAX);
        let quantity_schema_ptr = vm
            .alloc_input_tlv(&tlv(
                PointerType::NoritoBytes,
                &to_bytes(&quantity_schema).expect("quantity schema"),
            ))
            .expect("quantity schema TLV");
        let noncanonical = vm
            .alloc_input_tlv(&tlv(
                PointerType::Quantity,
                &to_bytes(&Numeric::new(10_u32, 1)).expect("noncanonical quantity payload"),
            ))
            .expect("noncanonical quantity TLV");
        let quantity_table = vm.alloc_heap(8).expect("quantity word table");
        vm.store_u64(quantity_table, noncanonical)
            .expect("store quantity pointer");
        vm.set_register(10, quantity_schema_ptr);
        vm.set_register(11, quantity_table);
        vm.set_register(12, 1);
        assert_eq!(
            build_json(&mut vm, CoreHost::resolve_code_tlv_addr),
            Err(VMError::DecodeError),
            "quantity inputs must already use their unique canonical frame",
        );
        let option_schema = JsonConstructionSchemaV1 {
            nodes: vec![JsonConstructionNodeV1::Value {
                schema: StateValueSchemaV1 {
                    nodes: vec![
                        StateValueNodeV1::Option,
                        StateValueNodeV1::Leaf(StateValueKindV1::Quantity),
                    ],
                },
            }],
        };
        let option_schema_ptr = vm
            .alloc_input_tlv(&tlv(
                PointerType::NoritoBytes,
                &to_bytes(&option_schema).expect("Option schema"),
            ))
            .expect("Option schema TLV");
        let option_layout = crate::sum::SumLayoutV1::option(1).expect("Option<quantity> layout");
        let none = crate::sum::allocate_words(&mut vm, option_layout, 0, &[])
            .expect("canonical Option::none");
        vm.store_u64(none + 8, noncanonical)
            .expect("forge inactive placeholder payload");
        let option_table = vm.alloc_heap(8).expect("Option word table");
        vm.store_u64(option_table, none)
            .expect("store Option handle");
        vm.set_register(10, option_schema_ptr);
        vm.set_register(11, option_table);
        vm.set_register(12, 1);
        assert_eq!(
            build_json(&mut vm, CoreHost::resolve_code_tlv_addr),
            Err(VMError::DecodeError),
            "Option::none cannot smuggle an inactive placeholder into JSON",
        );
    }
    #[test]
    fn build_json_rejects_a_word_count_that_disagrees_with_the_schema() {
        let schema = JsonConstructionSchemaV1 {
            nodes: vec![JsonConstructionNodeV1::Value {
                schema: leaf(StateValueKindV1::Int),
            }],
        };
        let mut vm = IVM::new(u64::MAX);
        let schema_ptr = vm
            .alloc_input_tlv(&tlv(
                PointerType::NoritoBytes,
                &to_bytes(&schema).expect("encode schema"),
            ))
            .expect("schema TLV");
        vm.set_register(10, schema_ptr);
        vm.set_register(11, 0);
        vm.set_register(12, 0);
        assert_eq!(
            build_json(&mut vm, CoreHost::resolve_code_tlv_addr),
            Err(VMError::DecodeError)
        );
    }
    #[test]
    fn build_json_spills_large_canonical_output_to_owned_heap() {
        let schema = JsonConstructionSchemaV1 {
            nodes: vec![
                JsonConstructionNodeV1::Array { arity: 1 },
                JsonConstructionNodeV1::Value {
                    schema: leaf(StateValueKindV1::String),
                },
            ],
        };
        let mut vm = IVM::new(u64::MAX);
        let schema_ptr = vm
            .alloc_input_tlv(&tlv(
                PointerType::NoritoBytes,
                &to_bytes(&schema).expect("encode schema"),
            ))
            .expect("schema TLV");
        let source = "x".repeat(70 * 1024);
        let source_ptr = vm
            .alloc_host_tlv(&tlv(PointerType::Blob, source.as_bytes()))
            .expect("large string TLV");
        let table = vm.alloc_heap(8).expect("word table");
        vm.store_u64(table, source_ptr).expect("string word");
        vm.set_register(10, schema_ptr);
        vm.set_register(11, table);
        vm.set_register(12, 1);
        build_json(&mut vm, CoreHost::resolve_code_tlv_addr).expect("build large JSON");
        let output_ptr = vm.register(10);
        assert!(output_ptr >= Memory::HEAP_START);
        let output = vm.validate_tlv(output_ptr).expect("large JSON output");
        assert_eq!(output.type_id, PointerType::Json);
        let json: Json = decode_from_bytes(output.payload).expect("decode large JSON");
        let value: njson::Value = json.try_into_any_norito().expect("large JSON value");
        assert_eq!(
            value.as_array().and_then(|items| items[0].as_str()),
            Some(source.as_str())
        );
    }
    #[test]
    fn typed_getter_rejects_malformed_json_and_key_payloads() {
        let mut vm = IVM::new(u64::MAX);
        let malformed_json = vm
            .alloc_input_tlv(&tlv(PointerType::Json, br#"{"count":7}"#))
            .expect("malformed typed JSON TLV");
        let key: Name = "count".parse().expect("key");
        let key_ptr = vm
            .alloc_input_tlv(&tlv(PointerType::Name, &to_bytes(&key).unwrap()))
            .expect("key TLV");
        vm.set_register(10, malformed_json);
        vm.set_register(11, key_ptr);
        assert_eq!(
            typed_getter(
                &mut vm,
                syscalls::SYSCALL_JSON_GET_INT,
                CoreHost::resolve_code_tlv_addr,
            ),
            Err(VMError::DecodeError)
        );
        let json = Json::from(norito::json!({"count": 7}));
        let json_ptr = vm
            .alloc_input_tlv(&tlv(
                PointerType::Json,
                &to_bytes(&json).expect("encode JSON"),
            ))
            .expect("JSON TLV");
        let malformed_key = vm
            .alloc_input_tlv(&tlv(PointerType::Name, b"count"))
            .expect("malformed typed key TLV");
        vm.set_register(10, json_ptr);
        vm.set_register(11, malformed_key);
        assert_eq!(
            typed_getter(
                &mut vm,
                syscalls::SYSCALL_JSON_GET_INT,
                CoreHost::resolve_code_tlv_addr,
            ),
            Err(VMError::DecodeError)
        );
    }
}
