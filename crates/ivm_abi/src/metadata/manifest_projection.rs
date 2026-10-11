//! Borrow the canonical manifest spelling from the admitted native durable-type graph.
//!
//! This adapter performs no validation, decoding, materialization, or allocation. The enclosing
//! native admission/VM owner retains every original child for the duration of the model view.

use iroha_data_model::smart_contract::{
    entrypoint::EntrypointValueKindV1 as Kind,
    manifest::{ManifestStateTypeNodeV1 as Node, ManifestStateTypeV1},
};

use super::EmbeddedStateType;

impl ManifestStateTypeV1 for EmbeddedStateType {
    fn node(&self) -> Node<'_> {
        match self {
            Self::Unit => Node::Unit,
            Self::Error(error) => Node::Error(&error.identity),
            Self::Enum(enumeration) => Node::Enum(&enumeration.identity),
            Self::StateCursor(key) => Node::StateCursor(key),
            Self::Int => Node::Scalar(Kind::Int),
            Self::Decimal => Node::Scalar(Kind::Decimal),
            Self::Quantity => Node::Scalar(Kind::Quantity),
            Self::Bool => Node::Scalar(Kind::Bool),
            Self::String => Node::Scalar(Kind::String),
            Self::Bytes => Node::Scalar(Kind::Blob),
            Self::DataSpaceId => Node::Scalar(Kind::DataSpaceId),
            Self::AccountId => Node::Scalar(Kind::AccountId),
            Self::AssetDefinitionId => Node::Scalar(Kind::AssetDefinitionId),
            Self::AssetId => Node::Scalar(Kind::AssetId),
            Self::NftId => Node::Scalar(Kind::NftId),
            Self::DomainId => Node::Scalar(Kind::DomainId),
            Self::Name => Node::Scalar(Kind::Name),
            Self::Json => Node::Scalar(Kind::Json),
            Self::Tuple(items) => Node::Tuple(items.len()),
            Self::Struct { name, fields } => Node::Struct {
                name,
                fields: fields.len(),
            },
            Self::StateMap { .. } => Node::StateMap,
            Self::Option(_) => Node::Option,
            Self::Result { .. } => Node::Result,
            Self::List { capacity, .. } => Node::List(*capacity),
        }
    }

    fn child(&self, index: usize) -> Option<&dyn ManifestStateTypeV1> {
        let child: &EmbeddedStateType = match self {
            Self::Tuple(items) => items.get(index)?,
            Self::Struct { fields, .. } => &fields.get(index)?.ty,
            Self::StateMap { key, value } => match index {
                0 => key,
                1 => value,
                _ => return None,
            },
            Self::Option(inner) if index == 0 => inner,
            Self::Result { ok, err } => match index {
                0 => ok,
                1 => err,
                _ => return None,
            },
            Self::List { element, .. } if index == 0 => element,
            _ => return None,
        };
        Some(child)
    }

    fn field_name(&self, index: usize) -> Option<&str> {
        match self {
            Self::Struct { fields, .. } => fields.get(index).map(|field| field.name.as_str()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::smart_contract::manifest::ManifestStateTypeNameV1;

    #[test]
    fn embedded_manifest_projection_preserves_native_cursor_and_child_identity() {
        let native = EmbeddedStateType::StateMap {
            key: Box::new(EmbeddedStateType::AccountId),
            value: Box::new(EmbeddedStateType::StateCursor(
                crate::entrypoint::EntrypointValueTypeV1 {
                    nodes: vec![crate::entrypoint::EntrypointValueTypeNodeV1::Leaf(
                        Kind::Quantity,
                    )],
                },
            )),
        };
        let EmbeddedStateType::StateMap { key, value } = &native else {
            unreachable!("genuine map fixture")
        };
        assert!(std::ptr::addr_eq(native.child(0).unwrap(), key.as_ref(),));
        assert!(std::ptr::addr_eq(native.child(1).unwrap(), value.as_ref(),));
        assert!(native.child(2).is_none());
        assert!(
            ManifestStateTypeNameV1::new(&native)
                .same_text("StateMap<AccountId, StateCursor<quantity>>")
                .unwrap()
        );
    }
}
