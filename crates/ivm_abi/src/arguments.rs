//! Canonical schema-bound JSON conversion for public Kotodama call arguments.
//!
//! Producers convert before signing. The VM owns metered decoding and materialization.
use crate::{
    VMError,
    codec::encode_canonical_norito as canonical_norito_frame,
    entrypoint::{
        EntrypointArgumentRecordV1, EntrypointArgumentSchemaV1, EntrypointValueAtomV1,
        EntrypointValueKindV1, EntrypointValueTypeNodeV1, EntrypointValueTypeV1,
        MAX_ENTRYPOINT_ARGUMENT_RECORD_BYTES, entrypoint_argument_schema_hash_v1,
        value_child_starts as argument_child_starts, value_subtree_end as argument_subtree_end,
    },
    pointer_abi::{PointerType, encode_tlv},
};
use iroha_data_model::{
    account::AccountId,
    prelude::{AssetDefinitionId, AssetId, NftId},
};
use iroha_model_base::{domain::DomainId, name::Name, topology::DataSpaceId};
use iroha_primitives::{
    bigint::BigInt,
    json::Json,
    numeric::{Numeric, Quantity},
    numeric_abi::DecimalValueV1,
};
use norito::json as njson;
use std::str::FromStr;
/// Public-input name for the canonical root entrypoint argument record.
///
/// Default root preparation requires a `NoritoBytes` TLV under this name.
/// The firing-event JSON uses its separate `trigger_event_json` input.
pub const ENTRYPOINT_ARGUMENT_RECORD_PUBLIC_INPUT_KEY: &str = "entrypoint_argument_record";
fn decode_int(value: &njson::Value) -> Result<BigInt, VMError> {
    let raw = value.as_str().ok_or(VMError::DecodeError)?;
    let parsed: BigInt = raw.parse().map_err(|_| VMError::DecodeError)?;
    if parsed.to_string() != raw {
        return Err(VMError::DecodeError);
    }
    Ok(parsed)
}
fn decode_u64(value: &njson::Value) -> Result<u64, VMError> {
    match value {
        njson::Value::Number(number) => number.as_u64().ok_or(VMError::DecodeError),
        _ => Err(VMError::DecodeError),
    }
}
fn decode_canonical_string<T>(
    value: &njson::Value,
    parse: impl FnOnce(&str) -> Result<T, VMError>,
    canonical: impl FnOnce(&T) -> String,
) -> Result<T, VMError> {
    let raw = value.as_str().ok_or(VMError::DecodeError)?;
    let parsed = parse(raw)?;
    if canonical(&parsed) != raw {
        return Err(VMError::DecodeError);
    }
    Ok(parsed)
}
fn decode_numeric(value: &njson::Value) -> Result<Numeric, VMError> {
    let raw = value.as_str().ok_or(VMError::DecodeError)?;
    let parsed: Numeric = raw.parse().map_err(|_| VMError::DecodeError)?;
    if parsed.to_string() != raw {
        return Err(VMError::DecodeError);
    }
    Ok(parsed)
}
fn decode_blob(value: &njson::Value) -> Result<Vec<u8>, VMError> {
    let raw = value.as_str().ok_or(VMError::DecodeError)?;
    let hex_body = raw.strip_prefix("0x").ok_or(VMError::DecodeError)?;
    if hex_body.len() % 2 != 0 {
        return Err(VMError::DecodeError);
    }
    if hex_body
        .bytes()
        .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(VMError::DecodeError);
    }
    hex::decode(hex_body).map_err(|_| VMError::DecodeError)
}
fn encode_leaf_atom(
    kind: &EntrypointValueKindV1,
    value: &njson::Value,
) -> Result<EntrypointValueAtomV1, VMError> {
    let encoded_pointer = |pointer_type, payload: Vec<u8>| {
        encode_tlv(pointer_type, &payload).map(EntrypointValueAtomV1::Pointer)
    };
    Ok(match kind {
        EntrypointValueKindV1::Int => {
            EntrypointValueAtomV1::Pointer(crate::numeric_tlv::encode_int(&decode_int(value)?)?)
        }
        EntrypointValueKindV1::Decimal => {
            let decimal = DecimalValueV1::try_from_numeric(decode_numeric(value)?)
                .map_err(|_| VMError::DecodeError)?;
            EntrypointValueAtomV1::Pointer(crate::numeric_tlv::encode_decimal(
                decimal.as_numeric(),
            )?)
        }
        EntrypointValueKindV1::Quantity => {
            let quantity = Quantity::try_from_numeric(decode_numeric(value)?)
                .map_err(|_| VMError::DecodeError)?;
            EntrypointValueAtomV1::Pointer(crate::numeric_tlv::encode_quantity(&quantity)?)
        }
        EntrypointValueKindV1::Bool => {
            EntrypointValueAtomV1::Bool(value.as_bool().ok_or(VMError::DecodeError)?)
        }
        EntrypointValueKindV1::String => encoded_pointer(
            PointerType::Blob,
            value
                .as_str()
                .ok_or(VMError::DecodeError)?
                .as_bytes()
                .to_vec(),
        )?,
        EntrypointValueKindV1::Json => encoded_pointer(
            PointerType::Json,
            canonical_norito_frame(
                &Json::from_norito_value_ref(value).map_err(|_| VMError::DecodeError)?,
            )
            .map_err(|_| VMError::NoritoInvalid)?,
        )?,
        EntrypointValueKindV1::Name => {
            let name = decode_canonical_string(
                value,
                |raw| Name::from_str(raw).map_err(|_| VMError::DecodeError),
                ToString::to_string,
            )?;
            encoded_pointer(
                PointerType::Name,
                canonical_norito_frame(&name).map_err(|_| VMError::NoritoInvalid)?,
            )?
        }
        EntrypointValueKindV1::AccountId => {
            let raw = value.as_str().ok_or(VMError::DecodeError)?;
            let parsed = AccountId::parse_encoded(raw).map_err(|_| VMError::DecodeError)?;
            if parsed.to_string() != raw {
                return Err(VMError::DecodeError);
            }
            let account_id = parsed;
            encoded_pointer(
                PointerType::AccountId,
                canonical_norito_frame(&account_id).map_err(|_| VMError::NoritoInvalid)?,
            )?
        }
        EntrypointValueKindV1::AssetDefinitionId => {
            let asset_definition_id = decode_canonical_string(
                value,
                |raw| {
                    AssetDefinitionId::parse_address_literal(raw).map_err(|_| VMError::DecodeError)
                },
                AssetDefinitionId::canonical_address,
            )?;
            encoded_pointer(
                PointerType::AssetDefinitionId,
                canonical_norito_frame(&asset_definition_id).map_err(|_| VMError::NoritoInvalid)?,
            )?
        }
        EntrypointValueKindV1::AssetId => {
            let asset_id = decode_canonical_string(
                value,
                |raw| AssetId::parse_literal(raw).map_err(|_| VMError::DecodeError),
                AssetId::canonical_literal,
            )?;
            encoded_pointer(
                PointerType::AssetId,
                canonical_norito_frame(&asset_id).map_err(|_| VMError::NoritoInvalid)?,
            )?
        }
        EntrypointValueKindV1::DomainId => {
            let domain_id = decode_canonical_string(
                value,
                |raw| DomainId::parse_fully_qualified(raw).map_err(|_| VMError::DecodeError),
                ToString::to_string,
            )?;
            encoded_pointer(
                PointerType::DomainId,
                canonical_norito_frame(&domain_id).map_err(|_| VMError::NoritoInvalid)?,
            )?
        }
        EntrypointValueKindV1::NftId => {
            let nft_id = decode_canonical_string(
                value,
                |raw| NftId::from_str(raw).map_err(|_| VMError::DecodeError),
                ToString::to_string,
            )?;
            encoded_pointer(
                PointerType::NftId,
                canonical_norito_frame(&nft_id).map_err(|_| VMError::NoritoInvalid)?,
            )?
        }
        EntrypointValueKindV1::DataSpaceId => {
            let dataspace_id = DataSpaceId::new(decode_u64(value)?);
            encoded_pointer(
                PointerType::DataSpaceId,
                canonical_norito_frame(&dataspace_id).map_err(|_| VMError::NoritoInvalid)?,
            )?
        }
        EntrypointValueKindV1::Blob => encoded_pointer(PointerType::Blob, decode_blob(value)?)?,
    })
}
/// Rejected public argument value with its JSON location and expected boundary type.
///
/// Producers and Torii surface this detail to callers; consensus execution only consumes the
/// mapped [`VMError`], so the extra text never affects VM behaviour.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArgumentDecodeError {
    /// Dotted JSON path of the rejected value, such as `amount`, `order.items[2]` or
    /// `limit.some`. Empty when the complete payload is rejected.
    pub path: String,
    /// Expected boundary type and JSON encoding at [`Self::path`].
    pub expected: String,
    /// Short description of the JSON value found at [`Self::path`].
    pub found: String,
    /// VM error reported by the non-detailed conversion functions.
    pub error: VMError,
}
impl ArgumentDecodeError {
    fn at(
        path: &str,
        expected: impl Into<String>,
        found: impl Into<String>,
        error: VMError,
    ) -> Box<Self> {
        Box::new(Self {
            path: path.to_owned(),
            expected: expected.into(),
            found: found.into(),
            error,
        })
    }
}
impl std::fmt::Display for ArgumentDecodeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.path.is_empty() {
            write!(formatter, "arguments")?;
        } else {
            write!(formatter, "argument `{}`", self.path)?;
        }
        write!(
            formatter,
            " expects {}, found {}",
            self.expected, self.found
        )
    }
}
impl std::error::Error for ArgumentDecodeError {}
impl From<Box<ArgumentDecodeError>> for VMError {
    fn from(error: Box<ArgumentDecodeError>) -> Self {
        error.error
    }
}
/// Describe the JSON encoding accepted for one leaf kind.
fn expected_leaf(kind: &EntrypointValueKindV1) -> String {
    let encoding = match kind {
        EntrypointValueKindV1::Int => "a canonical decimal integer string such as \"5\"",
        EntrypointValueKindV1::Decimal => "a canonical decimal string such as \"1.25\"",
        EntrypointValueKindV1::Quantity => "a canonical non-negative decimal string such as \"10\"",
        EntrypointValueKindV1::Bool => "true or false",
        EntrypointValueKindV1::String => "a JSON string",
        EntrypointValueKindV1::Json => "any JSON value",
        EntrypointValueKindV1::Name => "a canonical name string",
        EntrypointValueKindV1::AccountId => "a canonical account literal string",
        EntrypointValueKindV1::AssetDefinitionId => "a canonical asset-definition address string",
        EntrypointValueKindV1::AssetId => "a canonical asset literal string",
        EntrypointValueKindV1::DomainId => "a fully qualified domain string",
        EntrypointValueKindV1::NftId => "a canonical NFT identifier string",
        EntrypointValueKindV1::DataSpaceId => "a non-negative JSON integer",
        EntrypointValueKindV1::Blob => "a 0x-prefixed lowercase hexadecimal string",
    };
    format!("{} as {encoding}", kind.canonical_type_name())
}
/// Describe the JSON shape accepted for one schema node.
fn expected_node(node: &EntrypointValueTypeNodeV1) -> String {
    match node {
        EntrypointValueTypeNodeV1::Struct(node) => format!(
            "struct `{}` as an object with exactly the fields {}",
            node.name,
            node.fields
                .iter()
                .map(|field| format!("`{field}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        EntrypointValueTypeNodeV1::Tuple(arity) => {
            format!("a tuple as a JSON array of exactly {arity} element(s)")
        }
        EntrypointValueTypeNodeV1::Option => {
            "an option as {\"some\": value} or {\"none\": true}".to_owned()
        }
        EntrypointValueTypeNodeV1::Result => {
            "a result as {\"ok\": value} or {\"err\": value}".to_owned()
        }
        EntrypointValueTypeNodeV1::List(list) => format!(
            "a list as a JSON array of at most {} element(s)",
            list.capacity
        ),
        EntrypointValueTypeNodeV1::Leaf(kind) => expected_leaf(kind),
        EntrypointValueTypeNodeV1::Unit => "unit as null".to_owned(),
        EntrypointValueTypeNodeV1::Error(error) => format!(
            "an error variant name of `{}` (one of {})",
            error.identity,
            error
                .variants
                .iter()
                .map(|variant| format!("`{}`", variant.name))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        EntrypointValueTypeNodeV1::Enum(error) => format!(
            "an enum variant name of `{}` (one of {})",
            error.identity,
            error
                .variants
                .iter()
                .map(|variant| format!("`{}`", variant.name))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        EntrypointValueTypeNodeV1::StateCursor(_) => {
            "a state cursor as a 0x-prefixed lowercase hexadecimal string".to_owned()
        }
    }
}
/// Summarize a JSON value without echoing large or nested content.
fn describe_found(value: &njson::Value) -> String {
    const MAX_ECHO_CHARS: usize = 48;
    match value {
        njson::Value::Null => "null".to_owned(),
        njson::Value::Bool(value) => format!("boolean {value}"),
        njson::Value::Number(number) => {
            let rendered =
                njson::to_string(&njson::Value::Number(*number)).unwrap_or_else(|_| "?".to_owned());
            format!("JSON number {rendered}")
        }
        njson::Value::String(text) => {
            if text.chars().count() <= MAX_ECHO_CHARS {
                format!("string {text:?}")
            } else {
                let prefix = text.chars().take(MAX_ECHO_CHARS).collect::<String>();
                format!("string {prefix:?}...")
            }
        }
        njson::Value::Array(values) => format!("array of {} element(s)", values.len()),
        njson::Value::Object(object) => {
            let keys = object
                .keys()
                .take(8)
                .map(|key| format!("`{key}`"))
                .collect::<Vec<_>>();
            if keys.is_empty() {
                "empty object".to_owned()
            } else if object.len() > keys.len() {
                format!("object with fields {}, ...", keys.join(", "))
            } else {
                format!("object with fields {}", keys.join(", "))
            }
        }
    }
}
fn child_path(parent: &str, field: &str) -> String {
    if parent.is_empty() {
        field.to_owned()
    } else {
        format!("{parent}.{field}")
    }
}
fn index_path(parent: &str, index: usize) -> String {
    format!("{parent}[{index}]")
}
/// Report the first missing or unexpected key of an exact JSON object.
fn object_shape_error<'a>(
    path: &str,
    object: &njson::Map,
    fields: impl Iterator<Item = &'a str> + Clone,
    expected: &str,
) -> Box<ArgumentDecodeError> {
    if let Some(missing) = fields.clone().find(|field| object.get(*field).is_none()) {
        return ArgumentDecodeError::at(
            &child_path(path, missing),
            "a value for this declared field",
            "no value",
            VMError::DecodeError,
        );
    }
    if let Some(extra) = object
        .keys()
        .find(|key| !fields.clone().any(|field| field == key.as_str()))
    {
        return ArgumentDecodeError::at(
            &child_path(path, extra),
            "no value; the schema declares no field with this name",
            "an unexpected field",
            VMError::DecodeError,
        );
    }
    ArgumentDecodeError::at(path, expected, "an inexact object", VMError::DecodeError)
}
#[allow(
    clippy::too_many_lines,
    reason = "one explicit iterative walk keeps nested argument decoding off the native stack"
)]
fn decode_argument_node(
    nodes: &[EntrypointValueTypeNodeV1],
    node_index: &mut usize,
    value: &njson::Value,
    path: &str,
    out: &mut Vec<EntrypointValueAtomV1>,
) -> Result<(), Box<ArgumentDecodeError>> {
    enum Task<'a> {
        Visit {
            node_start: usize,
            value: &'a njson::Value,
            path: String,
        },
        FinishProduct {
            children: usize,
        },
        FinishSum {
            tag: bool,
        },
        FinishList {
            item_count_usize: usize,
        },
    }
    let schema_error = |path: &str| {
        ArgumentDecodeError::at(
            path,
            "a value described by a valid V1 argument schema",
            "an invalid schema node",
            VMError::DecodeError,
        )
    };
    let start = *node_index;
    let end = argument_subtree_end(nodes, start).map_err(|_| schema_error(path))?;
    let mut tasks = vec![Task::Visit {
        node_start: start,
        value,
        path: path.to_owned(),
    }];
    let mut results = Vec::<Vec<EntrypointValueAtomV1>>::new();
    while let Some(task) = tasks.pop() {
        match task {
            Task::Visit {
                node_start,
                value,
                path,
            } => {
                let node = nodes.get(node_start).ok_or_else(|| schema_error(&path))?;
                let mismatch = |error: VMError| {
                    ArgumentDecodeError::at(
                        &path,
                        expected_node(node),
                        describe_found(value),
                        error,
                    )
                };
                match node {
                    EntrypointValueTypeNodeV1::StateCursor(key) => {
                        let envelope = decode_blob(value)
                            .and_then(|bytes| encode_tlv(PointerType::NoritoBytes, &bytes))
                            .map_err(mismatch)?;
                        let key_hash = crate::entrypoint::state_key_schema_hash_v1(key)
                            .ok_or_else(|| mismatch(VMError::DecodeError))?;
                        crate::state_cursor::validate_cursor_envelope(key_hash, &envelope)
                            .map_err(mismatch)?;
                        results.push(vec![EntrypointValueAtomV1::Pointer(envelope)]);
                    }
                    EntrypointValueTypeNodeV1::Unit => {
                        if !matches!(value, njson::Value::Null) {
                            return Err(mismatch(VMError::DecodeError));
                        }
                        results.push(vec![EntrypointValueAtomV1::Unit]);
                    }
                    EntrypointValueTypeNodeV1::Error(error) => {
                        let variant = value
                            .as_str()
                            .and_then(|name| {
                                error.variants.iter().find(|variant| variant.name == name)
                            })
                            .ok_or_else(|| mismatch(VMError::DecodeError))?;
                        results.push(vec![EntrypointValueAtomV1::ErrorCode(variant.code)]);
                    }
                    EntrypointValueTypeNodeV1::Enum(error) => {
                        let variant = value
                            .as_str()
                            .and_then(|name| {
                                error.variants.iter().find(|variant| variant.name == name)
                            })
                            .ok_or_else(|| mismatch(VMError::DecodeError))?;
                        results.push(vec![EntrypointValueAtomV1::EnumCode(variant.code)]);
                    }
                    EntrypointValueTypeNodeV1::Struct(struct_node) => {
                        let object = value
                            .as_object()
                            .ok_or_else(|| mismatch(VMError::DecodeError))?;
                        let fields = struct_node.fields.iter().map(String::as_str);
                        if object.len() != struct_node.fields.len()
                            || fields.clone().any(|field| object.get(field).is_none())
                        {
                            return Err(object_shape_error(
                                &path,
                                object,
                                fields,
                                &expected_node(node),
                            ));
                        }
                        let starts =
                            argument_child_starts(nodes, node_start, struct_node.fields.len())
                                .map_err(|_| schema_error(&path))?;
                        tasks.push(Task::FinishProduct {
                            children: starts.len(),
                        });
                        for (child, field) in starts.iter().zip(&struct_node.fields).rev() {
                            tasks.push(Task::Visit {
                                node_start: *child,
                                value: object.get(field).ok_or_else(|| schema_error(&path))?,
                                path: child_path(&path, field),
                            });
                        }
                    }
                    EntrypointValueTypeNodeV1::Tuple(arity) => {
                        let values = value
                            .as_array()
                            .filter(|values| values.len() == usize::from(*arity))
                            .ok_or_else(|| mismatch(VMError::DecodeError))?;
                        let starts = argument_child_starts(nodes, node_start, values.len())
                            .map_err(|_| schema_error(&path))?;
                        tasks.push(Task::FinishProduct {
                            children: starts.len(),
                        });
                        for (index, (child, value)) in starts.iter().zip(values).enumerate().rev() {
                            tasks.push(Task::Visit {
                                node_start: *child,
                                value,
                                path: index_path(&path, index),
                            });
                        }
                    }
                    EntrypointValueTypeNodeV1::Option => {
                        let object = value
                            .as_object()
                            .filter(|object| object.len() == 1)
                            .ok_or_else(|| mismatch(VMError::DecodeError))?;
                        if let Some(value) = object.get("some") {
                            tasks.push(Task::FinishSum { tag: true });
                            tasks.push(Task::Visit {
                                node_start: node_start
                                    .checked_add(1)
                                    .ok_or_else(|| schema_error(&path))?,
                                value,
                                path: child_path(&path, "some"),
                            });
                        } else if object.get("none") == Some(&njson::Value::Bool(true)) {
                            results.push(vec![EntrypointValueAtomV1::Tag(false)]);
                        } else {
                            return Err(mismatch(VMError::DecodeError));
                        }
                    }
                    EntrypointValueTypeNodeV1::Result => {
                        let object = value
                            .as_object()
                            .filter(|object| object.len() == 1)
                            .ok_or_else(|| mismatch(VMError::DecodeError))?;
                        let ok_start = node_start
                            .checked_add(1)
                            .ok_or_else(|| schema_error(&path))?;
                        let err_start = argument_subtree_end(nodes, ok_start)
                            .map_err(|_| schema_error(&path))?;
                        if let Some(value) = object.get("ok") {
                            tasks.push(Task::FinishSum { tag: true });
                            tasks.push(Task::Visit {
                                node_start: ok_start,
                                value,
                                path: child_path(&path, "ok"),
                            });
                        } else if let Some(value) = object.get("err") {
                            tasks.push(Task::FinishSum { tag: false });
                            tasks.push(Task::Visit {
                                node_start: err_start,
                                value,
                                path: child_path(&path, "err"),
                            });
                        } else {
                            return Err(mismatch(VMError::DecodeError));
                        }
                    }
                    EntrypointValueTypeNodeV1::List(list) => {
                        let values = value
                            .as_array()
                            .filter(|values| values.len() <= usize::from(list.capacity))
                            .ok_or_else(|| mismatch(VMError::DecodeError))?;
                        let element_start = node_start
                            .checked_add(1)
                            .ok_or_else(|| schema_error(&path))?;
                        let _ = argument_subtree_end(nodes, element_start)
                            .map_err(|_| schema_error(&path))?;
                        tasks.push(Task::FinishList {
                            item_count_usize: values.len(),
                        });
                        for (index, value) in values.iter().enumerate().rev() {
                            tasks.push(Task::Visit {
                                node_start: element_start,
                                value,
                                path: index_path(&path, index),
                            });
                        }
                    }
                    EntrypointValueTypeNodeV1::Leaf(kind) => {
                        results.push(vec![encode_leaf_atom(kind, value).map_err(mismatch)?]);
                    }
                }
            }
            Task::FinishProduct { children } => {
                let split = results
                    .len()
                    .checked_sub(children)
                    .ok_or_else(|| schema_error(path))?;
                let child_results = results.split_off(split);
                let capacity = child_results
                    .iter()
                    .try_fold(0_usize, |total, child| total.checked_add(child.len()))
                    .ok_or_else(|| schema_error(path))?;
                let mut product = Vec::with_capacity(capacity);
                for child in child_results {
                    product.extend(child);
                }
                results.push(product);
            }
            Task::FinishSum { tag } => {
                let child = results.pop().ok_or_else(|| schema_error(path))?;
                let mut sum = Vec::with_capacity(child.len().saturating_add(1));
                sum.push(EntrypointValueAtomV1::Tag(tag));
                sum.extend(child);
                results.push(sum);
            }
            Task::FinishList { item_count_usize } => {
                let split = results
                    .len()
                    .checked_sub(item_count_usize)
                    .ok_or_else(|| schema_error(path))?;
                let item_results = results.split_off(split);
                let item_count =
                    u8::try_from(item_results.len()).map_err(|_| schema_error(path))?;
                let capacity = item_results
                    .iter()
                    .try_fold(1_usize, |total, item| total.checked_add(item.len()))
                    .ok_or_else(|| schema_error(path))?;
                let mut list = Vec::with_capacity(capacity);
                list.push(EntrypointValueAtomV1::List(item_count));
                for item in item_results {
                    list.extend(item);
                }
                results.push(list);
            }
        }
    }
    if results.len() != 1 {
        return Err(schema_error(path));
    }
    out.extend(results.pop().expect("length checked"));
    *node_index = end;
    Ok(())
}
fn decode_argument_value(
    ty: &EntrypointValueTypeV1,
    value: &njson::Value,
    path: &str,
    out: &mut Vec<EntrypointValueAtomV1>,
) -> Result<(), Box<ArgumentDecodeError>> {
    let invalid = || {
        ArgumentDecodeError::at(
            path,
            "a value described by a valid V1 argument schema",
            "an invalid schema",
            VMError::DecodeError,
        )
    };
    if !ty.validate() {
        return Err(invalid());
    }
    let mut node_index = 0;
    decode_argument_node(&ty.nodes, &mut node_index, value, path, out)?;
    if node_index != ty.nodes.len() {
        return Err(invalid());
    }
    Ok(())
}
/// Convert one Torii/CLI boundary JSON value into the canonical schema-bound
/// Norito record consumed by a Kotodama V1 entrypoint, reporting the exact
/// rejected location.
///
/// # Errors
/// Rejects invalid schemas, inexact fields, noncanonical leaf values and malformed active
/// aggregates with the JSON path, expected type and found value of the first rejection.
pub fn argument_record_from_json_detailed(
    schema: &EntrypointArgumentSchemaV1,
    payload: &Json,
) -> Result<EntrypointArgumentRecordV1, Box<ArgumentDecodeError>> {
    let invalid_schema = || {
        ArgumentDecodeError::at(
            "",
            "arguments described by a valid V1 argument schema",
            "an invalid schema",
            VMError::DecodeError,
        )
    };
    if !schema.validate() {
        return Err(invalid_schema());
    }
    let expected_object = || {
        format!(
            "an object with exactly the named arguments {}",
            schema
                .fields
                .iter()
                .map(|field| format!("`{}`", field.name))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let value: njson::Value = payload.try_into_any_norito().map_err(|_| {
        ArgumentDecodeError::at(
            "",
            expected_object(),
            "malformed JSON",
            VMError::DecodeError,
        )
    })?;
    let object = value.as_object().ok_or_else(|| {
        ArgumentDecodeError::at(
            "",
            expected_object(),
            describe_found(&value),
            VMError::DecodeError,
        )
    })?;
    let fields = schema.fields.iter().map(|field| field.name.as_str());
    if object.len() != schema.fields.len()
        || fields.clone().any(|field| object.get(field).is_none())
    {
        return Err(object_shape_error("", object, fields, &expected_object()));
    }
    let expected_words = schema.word_count().ok_or_else(invalid_schema)?;
    let mut atoms = Vec::with_capacity(expected_words);
    for field in &schema.fields {
        let field_value = object.get(&field.name).ok_or_else(invalid_schema)?;
        decode_argument_value(&field.ty, field_value, &field.name, &mut atoms)?;
    }
    if !schema.validate_atoms(&atoms) {
        return Err(invalid_schema());
    }
    let schema_bytes = canonical_norito_frame(schema).map_err(|_| {
        ArgumentDecodeError::at(
            "",
            "a canonically encodable argument schema",
            "an unencodable schema",
            VMError::NoritoInvalid,
        )
    })?;
    Ok(EntrypointArgumentRecordV1 {
        schema_hash: entrypoint_argument_schema_hash_v1(&schema_bytes),
        atoms,
    })
}
/// Convert one Torii/CLI boundary JSON value into the canonical schema-bound
/// Norito record consumed by a Kotodama V1 entrypoint.
///
/// # Errors
/// Rejects invalid schemas, inexact fields, noncanonical leaf values and malformed active aggregates.
pub fn argument_record_from_json(
    schema: &EntrypointArgumentSchemaV1,
    payload: &Json,
) -> Result<EntrypointArgumentRecordV1, VMError> {
    argument_record_from_json_detailed(schema, payload).map_err(VMError::from)
}
/// Encode a canonical public argument record for transport into the IVM host, reporting the
/// exact rejected location.
///
/// # Errors
/// Rejects invalid boundary values with their JSON path, or a complete record exceeding the
/// inclusive V1 byte limit.
pub fn encode_argument_record_from_json_detailed(
    schema: &EntrypointArgumentSchemaV1,
    payload: &Json,
) -> Result<Vec<u8>, Box<ArgumentDecodeError>> {
    let record = argument_record_from_json_detailed(schema, payload)?;
    let oversized = || {
        ArgumentDecodeError::at(
            "",
            format!(
                "arguments whose canonical record fits {MAX_ENTRYPOINT_ARGUMENT_RECORD_BYTES} bytes"
            ),
            "an oversized record",
            VMError::NoritoInvalid,
        )
    };
    let bytes = canonical_norito_frame(&record).map_err(|_| oversized())?;
    if bytes.len() > MAX_ENTRYPOINT_ARGUMENT_RECORD_BYTES {
        return Err(oversized());
    }
    Ok(bytes)
}
/// Encode a canonical public argument record for transport into the IVM host.
///
/// # Errors
/// Rejects invalid boundary values or a complete record exceeding the inclusive V1 byte limit.
pub fn encode_argument_record_from_json(
    schema: &EntrypointArgumentSchemaV1,
    payload: &Json,
) -> Result<Vec<u8>, VMError> {
    encode_argument_record_from_json_detailed(schema, payload).map_err(VMError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entrypoint::EntrypointArgumentFieldV1;
    #[test]
    fn numeric_argument_atoms_require_canonical_decimal_strings() {
        assert_eq!(decode_int(&norito::json!("-7")), Ok(BigInt::from_i128(-7)));
        assert_eq!(
            decode_numeric(&norito::json!("1.25")),
            Ok(Numeric::new(125, 2))
        );
        for value in [
            norito::json!(7),
            norito::json!(7_u64),
            norito::json!("+7"),
            norito::json!("07"),
            norito::json!("-0"),
        ] {
            assert_eq!(decode_int(&value), Err(VMError::DecodeError));
        }
        for value in [
            norito::json!(1.25),
            norito::json!("+1.25"),
            norito::json!("01.25"),
            norito::json!("1.250"),
            norito::json!("1e0"),
        ] {
            assert_eq!(decode_numeric(&value), Err(VMError::DecodeError));
        }
    }
    #[test]
    fn recursive_tags_reject_ambiguous_or_noncanonical_shapes() {
        let option_type = EntrypointValueTypeV1 {
            nodes: vec![
                EntrypointValueTypeNodeV1::Option,
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
            ],
        };
        let invalid = [
            norito::json!({ "some": "1", "none": true }),
            norito::json!({ "none": false }),
            norito::json!({ "None": true }),
            njson::Value::String("1".to_owned()),
            njson::Value::Null,
        ];
        for value in invalid {
            let schema = EntrypointArgumentSchemaV1 {
                fields: vec![EntrypointArgumentFieldV1 {
                    name: "value".into(),
                    ty: option_type.clone(),
                }],
            };
            let payload = Json::from(norito::json!({ "value": value }));
            assert_eq!(
                argument_record_from_json(&schema, &payload),
                Err(VMError::DecodeError)
            );
        }
    }

    #[test]
    fn shared_boundary_fixture_preserves_exact_canonical_record_bytes() {
        let fixture = njson::parse_value(include_str!(
            "../../../fixtures/kotodama/entrypoint_argument_record_v1.json"
        ))
        .expect("parse shared boundary fixture");
        assert_eq!(
            fixture.get("generator").and_then(njson::Value::as_str),
            Some("ivm_abi::arguments::encode_argument_record_from_json")
        );
        let schema_hex = fixture
            .pointer("/entrypoint_argument_schema_v1/norito_hex")
            .and_then(njson::Value::as_str)
            .expect("exact schema bytes");
        let schema: EntrypointArgumentSchemaV1 =
            crate::codec::decode_canonical_norito(&hex::decode(schema_hex).expect("schema hex"))
                .expect("canonical schema");
        let payload = Json::from(
            fixture
                .pointer("/torii_boundary/payload")
                .expect("shared payload")
                .clone(),
        );
        let expected = hex::decode(
            fixture
                .pointer("/entrypoint_argument_record_v1/norito_hex")
                .and_then(njson::Value::as_str)
                .expect("record hex"),
        )
        .expect("record bytes");
        assert_eq!(
            encode_argument_record_from_json(&schema, &payload),
            Ok(expected)
        );
        let mut extra: njson::Value = payload.try_into_any_norito().expect("boundary object");
        extra
            .as_object_mut()
            .expect("object")
            .insert("unknown".to_owned(), njson::Value::Bool(true));
        assert_eq!(
            argument_record_from_json(&schema, &Json::from(extra)),
            Err(VMError::DecodeError)
        );
        let mut noncanonical: njson::Value =
            payload.try_into_any_norito().expect("boundary object");
        noncanonical
            .as_object_mut()
            .expect("object")
            .insert("count".to_owned(), njson::Value::String("-0".to_owned()));
        assert_eq!(
            argument_record_from_json(&schema, &Json::from(noncanonical)),
            Err(VMError::DecodeError)
        );
    }
    fn leaf(kind: EntrypointValueKindV1) -> EntrypointValueTypeV1 {
        EntrypointValueTypeV1 {
            nodes: vec![EntrypointValueTypeNodeV1::Leaf(kind)],
        }
    }
    fn field(name: &str, ty: EntrypointValueTypeV1) -> EntrypointArgumentFieldV1 {
        EntrypointArgumentFieldV1 {
            name: name.to_owned(),
            ty,
        }
    }
    #[test]
    fn detailed_errors_name_the_rejected_field_path_and_expected_type() {
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![field("amount", leaf(EntrypointValueKindV1::Int))],
        };
        let error = argument_record_from_json_detailed(
            &schema,
            &Json::from(norito::json!({ "amount": 5 })),
        )
        .expect_err("JSON numbers are not int arguments");
        assert_eq!(error.path, "amount");
        assert_eq!(error.error, VMError::DecodeError);
        assert!(error.expected.starts_with("int as"), "{}", error.expected);
        assert_eq!(error.found, "JSON number 5");
        assert_eq!(
            error.to_string(),
            "argument `amount` expects int as a canonical decimal integer string such as \"5\", found JSON number 5"
        );
        assert_eq!(VMError::from(error), VMError::DecodeError);
        assert_eq!(
            argument_record_from_json(&schema, &Json::from(norito::json!({ "amount": 5 }))),
            Err(VMError::DecodeError)
        );
        assert!(
            argument_record_from_json_detailed(
                &schema,
                &Json::from(norito::json!({ "amount": "5" }))
            )
            .is_ok()
        );
    }
    #[test]
    fn detailed_errors_follow_nested_aggregates_and_object_shape() {
        let order = EntrypointValueTypeV1 {
            nodes: vec![
                EntrypointValueTypeNodeV1::Struct(
                    iroha_data_model::smart_contract::entrypoint::EntrypointStructTypeNodeV1 {
                        name: "Fixture::Order".to_owned(),
                        fields: vec!["lines".to_owned(), "memo".to_owned()],
                    },
                ),
                EntrypointValueTypeNodeV1::List(
                    iroha_data_model::smart_contract::entrypoint::EntrypointListTypeNodeV1 {
                        capacity: 4,
                    },
                ),
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Quantity),
                EntrypointValueTypeNodeV1::Option,
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::String),
            ],
        };
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![field("order", order)],
        };
        let reject = |payload: njson::Value| {
            argument_record_from_json_detailed(&schema, &Json::from(payload))
                .expect_err("invalid nested payload")
        };
        let list = reject(norito::json!({
            "order": { "lines": ["1", 2], "memo": { "none": true } }
        }));
        assert_eq!(list.path, "order.lines[1]");
        assert!(list.expected.starts_with("quantity"), "{}", list.expected);
        let option = reject(norito::json!({
            "order": { "lines": [], "memo": { "some": 7 } }
        }));
        assert_eq!(option.path, "order.memo.some");
        assert!(option.expected.starts_with("string"));
        let missing = reject(norito::json!({ "order": { "lines": [] } }));
        assert_eq!(missing.path, "order.memo");
        assert_eq!(missing.found, "no value");
        let extra = reject(norito::json!({
            "order": { "lines": [], "memo": { "none": true } },
            "unknown": true,
        }));
        assert_eq!(extra.path, "unknown");
        let root = reject(norito::json!(["order"]));
        assert_eq!(root.path, "");
        assert!(root.to_string().starts_with("arguments expects an object"));
        assert!(
            argument_record_from_json_detailed(
                &schema,
                &Json::from(norito::json!({
                    "order": { "lines": ["1", "2.5"], "memo": { "some": "thanks" } }
                }))
            )
            .is_ok()
        );
    }
    #[test]
    fn detailed_encoding_matches_the_vm_error_projection() {
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![field("space", leaf(EntrypointValueKindV1::DataSpaceId))],
        };
        let payload = Json::from(norito::json!({ "space": 7 }));
        assert_eq!(
            encode_argument_record_from_json_detailed(&schema, &payload).ok(),
            encode_argument_record_from_json(&schema, &payload).ok()
        );
        let wrong = Json::from(norito::json!({ "space": "7" }));
        let error = encode_argument_record_from_json_detailed(&schema, &wrong)
            .expect_err("dataspace ids are JSON integers");
        assert_eq!(error.path, "space");
        assert_eq!(error.found, "string \"7\"");
        assert_eq!(
            encode_argument_record_from_json(&schema, &wrong),
            Err(VMError::DecodeError)
        );
    }
    #[test]
    fn complete_public_record_limit_rejects_an_oversized_canonical_string() {
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "value".to_owned(),
                ty: EntrypointValueTypeV1 {
                    nodes: vec![EntrypointValueTypeNodeV1::Leaf(
                        EntrypointValueKindV1::String,
                    )],
                },
            }],
        };
        // The JSON object must fit its own inclusive limit before the complete
        // pointer and Norito record framing can exercise the public ABI limit.
        let string_bytes = iroha_primitives::json::MAX_JSON_BYTES - r#"{"value":""}"#.len();
        let oversized_string = "x".repeat(string_bytes);
        let value = norito::json!({"value": oversized_string});
        let payload = Json::from_norito_value_ref(&value).expect("valid bounded canonical JSON");
        assert_eq!(payload.get().len(), iroha_primitives::json::MAX_JSON_BYTES);
        let record = argument_record_from_json(&schema, &payload)
            .expect("valid canonical string and argument schema");
        let complete = canonical_norito_frame(&record).expect("encode complete argument record");
        assert!(complete.len() > MAX_ENTRYPOINT_ARGUMENT_RECORD_BYTES);
        assert_eq!(
            encode_argument_record_from_json(&schema, &payload),
            Err(VMError::NoritoInvalid)
        );
    }
}
