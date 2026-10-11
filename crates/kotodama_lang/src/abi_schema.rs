//! Pure schema construction shared by semantic checking and IR lowering.
//!
//! Keeping ABI-shape validation independent of instruction emission ensures
//! `check` and `build` reject the same oversized or unsupported typed values.
use crate::semantic::{ExprKind, Type, TypedExpr};
pub(crate) fn state_map_key_schema(
    ty: &Type,
) -> Option<ivm_abi::entrypoint::EntrypointValueTypeV1> {
    use ivm_abi::entrypoint::{EntrypointValueTypeNodeV1 as Node, EntrypointValueTypeV1};
    let mut nodes = Vec::new();
    let mut pending = vec![ty];
    while let Some(ty) = pending.pop() {
        if nodes.len()
            >= iroha_data_model::smart_contract::entrypoint::MAX_ENTRYPOINT_ARGUMENT_TYPE_NODES
        {
            return None;
        }
        let leaf = match ty {
            Type::Tuple(items) if items.len() >= 2 => {
                nodes.push(Node::Tuple(u16::try_from(items.len()).ok()?));
                pending.extend(items.iter().rev());
                continue;
            }
            leaf => public_value_kind(leaf)?,
        };
        nodes.push(Node::Leaf(leaf));
    }
    let schema = EntrypointValueTypeV1 { nodes };
    iroha_data_model::smart_contract::entrypoint::validate_state_key_schema_v1(&schema)
        .then_some(schema)
}
/// Exact public leaf kind, independent of container and durable-key policy.
pub(crate) fn public_value_kind(ty: &Type) -> Option<ivm_abi::entrypoint::EntrypointValueKindV1> {
    use ivm_abi::entrypoint::EntrypointValueKindV1 as Kind;
    Some(match ty {
        Type::Int => Kind::Int,
        Type::Decimal => Kind::Decimal,
        Type::Quantity => Kind::Quantity,
        Type::Bool => Kind::Bool,
        Type::String => Kind::String,
        Type::Bytes => Kind::Blob,
        Type::AccountId => Kind::AccountId,
        Type::AssetDefinitionId => Kind::AssetDefinitionId,
        Type::AssetId => Kind::AssetId,
        Type::DomainId => Kind::DomainId,
        Type::NftId => Kind::NftId,
        Type::Name => Kind::Name,
        Type::DataSpaceId => Kind::DataSpaceId,
        Type::Json => Kind::Json,
        _ => return None,
    })
}
pub(crate) fn state_value_kind_for_type(
    ty: &Type,
) -> Option<ivm_abi::state_value::StateValueKindV1> {
    use ivm_abi::state_value::StateValueKindV1 as Kind;
    Some(match ty {
        Type::Int => Kind::Int,
        Type::Decimal => Kind::Decimal,
        Type::Quantity => Kind::Quantity,
        Type::Bool => Kind::Bool,
        Type::String => Kind::String,
        Type::Json => Kind::Json,
        Type::Bytes => Kind::Bytes,
        Type::AccountId => Kind::AccountId,
        Type::AssetDefinitionId => Kind::AssetDefinitionId,
        Type::AssetId => Kind::AssetId,
        Type::DomainId => Kind::DomainId,
        Type::NftId => Kind::NftId,
        Type::Name => Kind::Name,
        Type::DataSpaceId => Kind::DataSpaceId,
        Type::AxtDescriptor => Kind::AxtDescriptor,
        Type::ProofBlob => Kind::ProofBlob,
        Type::SoracloudRequest => Kind::SoracloudRequest,
        Type::SoracloudResponse => Kind::SoracloudResponse,
        Type::Unit
        | Type::StateCursor(_)
        | Type::Enum(_)
        | Type::ErrorEnum(_)
        | Type::Secret(_)
        | Type::StateMap(_, _)
        | Type::AxtAnchoredSpendV1
        | Type::Option(_)
        | Type::Result(_, _)
        | Type::List(_, _)
        | Type::Tuple(_)
        | Type::Struct { .. }
        | Type::NamedStruct(_)
        | Type::ContractRef(_) => return None,
    })
}
fn state_value_schema_nodes(ty: &Type) -> Option<Vec<ivm_abi::state_value::StateValueNodeV1>> {
    use ivm_abi::state_value::StateValueNodeV1 as Node;
    enum Pending<'a> {
        Visit {
            ty: &'a Type,
            target: usize,
        },
        FinishList {
            target: usize,
            element_target: usize,
            capacity: u8,
        },
    }
    let mut node_streams = vec![Vec::new()];
    let mut pending = vec![Pending::Visit { ty, target: 0 }];
    while let Some(item) = pending.pop() {
        match item {
            Pending::FinishList {
                target,
                element_target,
                capacity,
            } => {
                let element_nodes = std::mem::take(node_streams.get_mut(element_target)?);
                let element = ivm_abi::state_value::StateValueSchemaV1 {
                    nodes: element_nodes,
                };
                if !element.validate() {
                    return None;
                }
                node_streams.get_mut(target)?.push(Node::List {
                    element: Box::new(element),
                    capacity,
                });
            }
            Pending::Visit { ty, target } => match ty {
                Type::StateCursor(key) => node_streams
                    .get_mut(target)?
                    .push(Node::StateCursor(state_map_key_schema(key)?)),
                Type::Unit => node_streams.get_mut(target)?.push(Node::Unit),
                Type::Enum(descriptor) => node_streams
                    .get_mut(target)?
                    .push(Node::Enum(descriptor.as_ref().clone())),
                Type::ErrorEnum(descriptor) => node_streams
                    .get_mut(target)?
                    .push(Node::Error(descriptor.as_ref().clone())),
                Type::Struct { name, fields } => {
                    node_streams.get_mut(target)?.push(Node::Struct {
                        name: name.clone(),
                        fields: fields.iter().map(|(name, _)| name.clone()).collect(),
                    });
                    pending.extend(fields.iter().rev().map(|(_, field_ty)| Pending::Visit {
                        ty: field_ty,
                        target,
                    }));
                }
                Type::Tuple(items) => {
                    let arity = u16::try_from(items.len()).ok()?;
                    node_streams.get_mut(target)?.push(Node::Tuple { arity });
                    pending.extend(
                        items
                            .iter()
                            .rev()
                            .map(|item| Pending::Visit { ty: item, target }),
                    );
                }
                Type::Option(inner) => {
                    node_streams.get_mut(target)?.push(Node::Option);
                    pending.push(Pending::Visit { ty: inner, target });
                }
                Type::Result(ok, err) => {
                    node_streams.get_mut(target)?.push(Node::Result);
                    pending.push(Pending::Visit { ty: err, target });
                    pending.push(Pending::Visit { ty: ok, target });
                }
                Type::List(element, capacity) => {
                    let element_target = node_streams.len();
                    node_streams.push(Vec::new());
                    pending.push(Pending::FinishList {
                        target,
                        element_target,
                        capacity: *capacity,
                    });
                    pending.push(Pending::Visit {
                        ty: element,
                        target: element_target,
                    });
                }
                leaf => {
                    node_streams
                        .get_mut(target)?
                        .push(Node::Leaf(state_value_kind_for_type(leaf)?));
                }
            },
        }
    }
    node_streams.into_iter().next()
}
pub(crate) fn state_value_schema(ty: &Type) -> Option<ivm_abi::state_value::StateValueSchemaV1> {
    let schema = ivm_abi::state_value::StateValueSchemaV1 {
        nodes: state_value_schema_nodes(ty)?,
    };
    schema.validate().then_some(schema)
}
fn append_json_construction_schema_nodes(
    expression: &TypedExpr,
    nodes: &mut Vec<ivm_abi::json::JsonConstructionNodeV1>,
) -> bool {
    use ivm_abi::json::JsonConstructionNodeV1 as Node;
    let mut pending = vec![expression];
    while let Some(expression) = pending.pop() {
        match expression.kind() {
            ExprKind::JsonObject(entries) => {
                nodes.push(Node::Object {
                    keys: entries.iter().map(|(key, _)| key.clone()).collect(),
                });
                pending.extend(entries.iter().rev().map(|(_, value)| value));
            }
            ExprKind::JsonArray(elements) => {
                let Ok(arity) = u16::try_from(elements.len()) else {
                    return false;
                };
                nodes.push(Node::Array { arity });
                pending.extend(elements.iter().rev());
            }
            _ => {
                let Some(schema) = state_value_schema(&expression.ty) else {
                    return false;
                };
                if !ivm_abi::json::json_value_schema_is_supported(&schema) {
                    return false;
                }
                nodes.push(Node::Value { schema });
            }
        }
    }
    true
}
/// A fully validated V1 native-JSON construction schema.
pub(crate) struct JsonConstructionSchema {
    pub(crate) encoded: Vec<u8>,
    pub(crate) word_count: usize,
}
/// Stable reason a typed native-JSON expression cannot cross the V1 ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum JsonConstructionSchemaError {
    UnsupportedValueType,
    InvalidShape,
    Encoding,
    EncodedSize,
}
impl core::fmt::Display for JsonConstructionSchemaError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedValueType => {
                "native JSON expression contains an unsupported value type"
            }
            Self::InvalidShape => "native JSON construction schema exceeds V1 shape limits",
            Self::Encoding => "native JSON construction schema cannot be canonically encoded",
            Self::EncodedSize => "native JSON construction schema exceeds the V1 byte limit",
        })
    }
}
pub(crate) fn json_construction_schema(
    expression: &TypedExpr,
) -> Result<JsonConstructionSchema, JsonConstructionSchemaError> {
    let mut nodes = Vec::new();
    if !append_json_construction_schema_nodes(expression, &mut nodes) {
        return Err(JsonConstructionSchemaError::UnsupportedValueType);
    }
    let schema = ivm_abi::json::JsonConstructionSchemaV1 { nodes };
    let word_count = schema
        .word_count()
        .ok_or(JsonConstructionSchemaError::InvalidShape)?;
    let encoded = ivm_abi::codec::encode_canonical_norito(&schema)
        .map_err(|_| JsonConstructionSchemaError::Encoding)?;
    if encoded.len() > ivm_abi::json::MAX_JSON_CONSTRUCTION_SCHEMA_BYTES_V1 {
        return Err(JsonConstructionSchemaError::EncodedSize);
    }
    Ok(JsonConstructionSchema {
        encoded,
        word_count,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn state_schema_construction_accepts_the_255_list_boundary_on_a_small_stack() {
        std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(|| {
                let mut accepted = Type::Bool;
                for _ in 0..255 {
                    accepted = Type::List(Box::new(accepted), 1);
                }
                assert!(state_value_schema(&accepted).is_some());
                let mut rejected = Type::Bool;
                for _ in 0..256 {
                    rejected = Type::List(Box::new(rejected), 1);
                }
                assert!(state_value_schema(&rejected).is_none());
                // These source-type fixtures intentionally exercise construction rather
                // than the recursive derived drop glue of the semantic-only test value.
                std::mem::forget(accepted);
                std::mem::forget(rejected);
            })
            .expect("spawn small-stack schema worker")
            .join()
            .expect("small-stack schema worker");
    }
}
