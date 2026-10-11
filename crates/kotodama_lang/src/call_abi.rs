//! Exact function signatures and checked stack layouts for the V1 call-table ABI.

use ivm_abi::call::{
    CallSchemaV1, CallTypeNodeV1, MAX_CALL_FRAME_BYTES_V1, MAX_CALL_SCHEMA_NODES_V1,
    MAX_CALL_WORDS_V1,
};

use crate::semantic::{Type, TypedFunction};

/// Complete schemas for one typed function.
pub(crate) struct CallSignature {
    pub(crate) arguments: CallSchemaV1,
    pub(crate) results: CallSchemaV1,
}
impl CallSignature {
    pub(crate) fn for_function(function: &TypedFunction) -> Result<Self, String> {
        let mut arguments = CallSchemaV1::empty();
        for parameter in &function.param_types {
            if parameter.is_state {
                arguments.nodes.push(CallTypeNodeV1::StateRoot);
            } else {
                append_nodes(&parameter.ty, &mut arguments.nodes)?;
            }
        }
        let mut results = CallSchemaV1::empty();
        append_nodes(
            function.ret_ty.as_ref().unwrap_or(&Type::Unit),
            &mut results.nodes,
        )?;
        let argument_words = arguments
            .word_count()
            .ok_or("invalid complete argument schema")?;
        let result_words = results
            .word_count()
            .ok_or("invalid complete result schema")?;
        if argument_words > MAX_CALL_WORDS_V1 || result_words > MAX_CALL_WORDS_V1 {
            return Err(format!(
                "function `{}` exceeds the V1 limit of {MAX_CALL_WORDS_V1} words per call table",
                function.name
            ));
        }
        Ok(Self { arguments, results })
    }
    pub(crate) fn argument_word_count(&self) -> usize {
        self.arguments
            .word_count()
            .expect("validated callable arguments")
    }
    pub(crate) fn result_word_count(&self) -> usize {
        self.results
            .word_count()
            .expect("validated callable result")
    }
}
fn append_nodes(ty: &Type, output: &mut Vec<CallTypeNodeV1>) -> Result<(), String> {
    use ivm_abi::{entrypoint::EntrypointValueKindV1 as Kind, pointer_abi::PointerType};
    let mut pending = vec![ty];
    while let Some(ty) = pending.pop() {
        if output.len() >= MAX_CALL_SCHEMA_NODES_V1 {
            return Err(format!(
                "callable type exceeds {MAX_CALL_SCHEMA_NODES_V1} nodes"
            ));
        }
        let node = match ty {
            Type::Struct { name, fields } => {
                pending.extend(fields.iter().rev().map(|(_, field)| field));
                CallTypeNodeV1::Struct {
                    name: name.clone(),
                    fields: fields.iter().map(|(name, _)| name.clone()).collect(),
                }
            }
            Type::Tuple(fields) if fields.is_empty() => CallTypeNodeV1::Unit,
            Type::Tuple(fields) => {
                pending.extend(fields.iter().rev());
                CallTypeNodeV1::Tuple(
                    u32::try_from(fields.len()).map_err(|_| "callable tuple arity overflow")?,
                )
            }
            Type::Option(inner) => {
                pending.push(inner);
                CallTypeNodeV1::Option
            }
            Type::Result(ok, err) => {
                pending.push(err);
                pending.push(ok);
                CallTypeNodeV1::Result
            }
            Type::List(element, capacity) => {
                pending.push(element);
                CallTypeNodeV1::List {
                    capacity: *capacity,
                }
            }
            Type::Unit => CallTypeNodeV1::Unit,
            Type::Enum(descriptor) => CallTypeNodeV1::Enum(descriptor.as_ref().clone()),
            Type::ErrorEnum(descriptor) => CallTypeNodeV1::Error(descriptor.as_ref().clone()),
            Type::StateCursor(key) => CallTypeNodeV1::StateCursor(
                crate::abi_schema::state_map_key_schema(key)
                    .ok_or("invalid callable state cursor key type")?,
            ),
            Type::StateMap(_, _) => CallTypeNodeV1::StateRoot,
            Type::Secret(inner) => {
                let kind = crate::abi_schema::state_value_kind_for_type(inner)
                    .and_then(|kind| kind.pointer_type())
                    .ok_or("invalid private callable numeric type")?;
                if !matches!(
                    kind,
                    PointerType::Int | PointerType::Decimal | PointerType::Quantity
                ) {
                    return Err("invalid private callable numeric type".into());
                }
                CallTypeNodeV1::SecretNumeric(kind as u16)
            }
            // References retain their nominal source type, but their private call-table
            // transport is the same public Blob leaf used for their canonical address.
            Type::ContractRef(_) => CallTypeNodeV1::Leaf(Kind::Blob),
            Type::Json => CallTypeNodeV1::Leaf(Kind::Json),
            Type::AxtDescriptor => CallTypeNodeV1::Pointer(PointerType::AxtDescriptor as u16),
            Type::AxtAnchoredSpendV1 => {
                CallTypeNodeV1::Pointer(PointerType::AxtAnchoredSpendV1 as u16)
            }
            Type::ProofBlob => CallTypeNodeV1::Pointer(PointerType::ProofBlob as u16),
            Type::SoracloudRequest => CallTypeNodeV1::Pointer(PointerType::SoracloudRequest as u16),
            Type::SoracloudResponse => {
                CallTypeNodeV1::Pointer(PointerType::SoracloudResponse as u16)
            }
            leaf => CallTypeNodeV1::Leaf(
                crate::abi_schema::public_value_kind(leaf)
                    .ok_or_else(|| format!("unresolved callable value type `{leaf:?}`"))?,
            ),
        };
        output.push(node);
    }
    Ok(())
}

pub(crate) fn checked_align_stack_frame_size(size: usize) -> Result<usize, String> {
    let padding = (16 - size % 16) % 16;
    size.checked_add(padding)
        .ok_or_else(|| "Kotodama stack frame alignment overflow".to_owned())
}

/// Disjoint scratch ranges, reserved once per invocation and reused across loop calls.
pub(crate) struct CallFrameLayout {
    pub(crate) argument_base_slot: usize,
    pub(crate) result_base_slot: usize,
    pub(crate) spill_base: usize,
    pub(crate) save_base: usize,
    pub(crate) state_table_base: usize,
    pub(crate) outgoing_argument_base: usize,
    pub(crate) outgoing_result_base: usize,
    pub(crate) bytes: usize,
}
impl CallFrameLayout {
    pub(crate) fn new(
        saves_return_address: bool,
        spill_bytes: usize,
        saved_registers: usize,
        state_words: usize,
        argument_words: usize,
        result_words: usize,
    ) -> Result<Self, String> {
        if argument_words > MAX_CALL_WORDS_V1 || result_words > MAX_CALL_WORDS_V1 {
            return Err("outgoing call table exceeds the V1 word limit".to_owned());
        }
        let mut cursor = usize::from(saves_return_address) * 8;
        let mut reserve = |bytes: usize| -> Result<usize, String> {
            let base = cursor;
            cursor = cursor
                .checked_add(bytes)
                .ok_or_else(|| "call frame size overflow".to_owned())?;
            Ok(base)
        };
        let argument_base_slot = reserve(8)?;
        let result_base_slot = reserve(8)?;
        let spill_base = reserve(spill_bytes)?;
        let save_base = reserve(
            saved_registers
                .checked_mul(8)
                .ok_or("saved register size overflow")?,
        )?;
        let state_table_base = reserve(
            state_words
                .checked_mul(8)
                .ok_or("state table size overflow")?,
        )?;
        let outgoing_argument_base = reserve(argument_words * 8)?;
        let outgoing_result_base = reserve(result_words * 8)?;
        let bytes = checked_align_stack_frame_size(cursor)?;
        if bytes > MAX_CALL_FRAME_BYTES_V1 as usize {
            return Err("function call frame exceeds the V1 stack limit".to_owned());
        }
        Ok(Self {
            argument_base_slot,
            result_base_slot,
            spill_base,
            save_base,
            state_table_base,
            outgoing_argument_base,
            outgoing_result_base,
            bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frame_reserves_disjoint_tables_and_rejects_overflow() {
        let layout = CallFrameLayout::new(true, 24, 2, 4, 8192, 8192).expect("bounded frame");
        assert_eq!(layout.argument_base_slot, 8);
        assert_eq!(layout.result_base_slot, 16);
        assert_eq!(layout.spill_base, 24);
        assert_eq!(layout.save_base, 48);
        assert_eq!(layout.state_table_base, 64);
        assert_eq!(layout.outgoing_argument_base, 96);
        assert_eq!(layout.outgoing_result_base, 96 + 65536);
        assert_eq!(layout.bytes, 96 + 131072);
        assert!(CallFrameLayout::new(false, usize::MAX, 0, 0, 0, 0).is_err());
        assert!(CallFrameLayout::new(false, 0, 0, 0, 8193, 1).is_err());
    }
    #[test]
    fn cursor_roles_keep_the_declared_key_kind_through_flattening() {
        use ivm_abi::entrypoint::EntrypointValueKindV1 as Kind;
        let kinds = [
            (Type::Int, Kind::Int),
            (Type::Decimal, Kind::Decimal),
            (Type::Quantity, Kind::Quantity),
            (Type::Bool, Kind::Bool),
            (Type::String, Kind::String),
            (Type::Bytes, Kind::Blob),
            (Type::AccountId, Kind::AccountId),
            (Type::AssetDefinitionId, Kind::AssetDefinitionId),
            (Type::AssetId, Kind::AssetId),
            (Type::DomainId, Kind::DomainId),
            (Type::NftId, Kind::NftId),
            (Type::Name, Kind::Name),
            (Type::DataSpaceId, Kind::DataSpaceId),
        ];
        for (ty, kind) in kinds {
            let mut roles = Vec::new();
            append_nodes(
                &Type::Tuple(vec![Type::Bool, Type::StateCursor(Box::new(ty))]),
                &mut roles,
            )
            .unwrap();
            assert_eq!(
                roles,
                [
                    CallTypeNodeV1::Tuple(2),
                    CallTypeNodeV1::Leaf(ivm_abi::entrypoint::EntrypointValueKindV1::Bool),
                    CallTypeNodeV1::StateCursor(ivm_abi::entrypoint::EntrypointValueTypeV1 {
                        nodes: vec![ivm_abi::entrypoint::EntrypointValueTypeNodeV1::Leaf(kind)]
                    })
                ]
            );
        }
        assert!(append_nodes(&Type::StateCursor(Box::new(Type::Json)), &mut Vec::new()).is_err());
    }
    #[test]
    fn signature_flattening_keeps_active_handles_and_secret_tags() {
        let mut roles = Vec::new();
        append_nodes(
            &Type::Tuple(vec![
                Type::Unit,
                Type::Bool,
                Type::Option(Box::new(Type::Int)),
                Type::Secret(Box::new(Type::Int)),
            ]),
            &mut roles,
        )
        .expect("roles");
        assert_eq!(
            roles,
            [
                CallTypeNodeV1::Tuple(4),
                CallTypeNodeV1::Unit,
                CallTypeNodeV1::Leaf(ivm_abi::entrypoint::EntrypointValueKindV1::Bool),
                CallTypeNodeV1::Option,
                CallTypeNodeV1::Leaf(ivm_abi::entrypoint::EntrypointValueKindV1::Int),
                CallTypeNodeV1::SecretNumeric(ivm_abi::pointer_abi::PointerType::Int as u16)
            ]
        );
        assert!(append_nodes(&Type::NamedStruct("Unresolved".into()), &mut Vec::new()).is_err());
    }
}
