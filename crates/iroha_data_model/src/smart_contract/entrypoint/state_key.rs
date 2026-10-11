//! Allocation-free validation and projection of scalar and tuple durable-map key schemas.
use super::{
    EntrypointValueTypeNodeV1 as Node, EntrypointValueTypeV1, MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH,
    MAX_ENTRYPOINT_ARGUMENT_TYPE_NODES,
};

/// Domain separating exact scalar/tuple key-schema identities from value schemas.
pub const STATE_KEY_SCHEMA_HASH_DOMAIN_V1: &[u8] = b"KOTODAMA_STATE_KEY_SCHEMA_V1\0";

/// Check a canonical map-key schema using only existing scalar key leaves and tuples.
///
/// Empty/singleton tuples and all handles, named products, enums and Json are rejected.
/// Validation uses a fixed stack and never traverses an embedded cursor schema.
#[must_use]
pub fn validate_state_key_schema_v1(schema: &EntrypointValueTypeV1) -> bool {
    state_key_schema_depth_v1(schema).is_some()
}

/// Validate the complete key tree and return its maximum node depth.
#[must_use]
pub fn state_key_schema_depth_v1(schema: &EntrypointValueTypeV1) -> Option<usize> {
    if schema.nodes.is_empty() || schema.nodes.len() > MAX_ENTRYPOINT_ARGUMENT_TYPE_NODES {
        return None;
    }
    let mut stack = [0usize; MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH];
    let mut depth = 0usize;
    let mut maximum = 0usize;
    for (index, node) in schema.nodes.iter().enumerate() {
        while depth != 0 && stack[depth - 1] == 0 {
            depth -= 1;
        }
        if index != 0 {
            let remaining = stack.get_mut(depth.checked_sub(1)?)?;
            *remaining = remaining.checked_sub(1)?;
        }
        maximum = maximum.max(depth.checked_add(1)?);
        if maximum > MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH {
            return None;
        }
        match node {
            Node::Leaf(kind) if kind.is_state_cursor_key() => {}
            Node::Tuple(arity) if *arity >= 2 => {
                *stack.get_mut(depth)? = usize::from(*arity);
                depth += 1;
            }
            _ => return None,
        }
    }
    while depth != 0 && stack[depth - 1] == 0 {
        depth -= 1;
    }
    (depth == 0).then_some(maximum)
}

/// Hash a validated exact key schema using its canonical Norito frame and dedicated domain.
#[must_use]
pub fn state_key_schema_hash_v1(schema: &EntrypointValueTypeV1) -> Option<[u8; 32]> {
    if !validate_state_key_schema_v1(schema) {
        return None;
    }
    // Valid key schemas contain only a flat scalar/tuple node sequence. Its
    // serializer streams directly, so hashing a cursor word never allocates
    // schema-sized scratch before the VM's capture admission boundary.
    iroha_crypto::Hash::new_from_writer(|writer| {
        writer.write_all(STATE_KEY_SCHEMA_HASH_DOMAIN_V1)?;
        norito::core::write_canonical_to_writer(schema, writer).map_err(std::io::Error::other)
    })
    .ok()
    .map(Into::into)
}

/// Stream a validated canonical key type without allocating a rendered String.
///
/// # Errors
/// Returns invalid-schema or the destination's original error.
pub fn visit_state_key_type_v1(
    schema: &EntrypointValueTypeV1,
    mut emit: impl FnMut(&str) -> Result<(), norito::core::Error>,
) -> Result<(), norito::core::Error> {
    if !validate_state_key_schema_v1(schema) {
        return Err(norito::core::Error::NonCanonicalEncoding);
    }
    let mut remaining = [0usize; MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH];
    let mut totals = [0usize; MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH];
    let mut depth = 0usize;
    for (index, node) in schema.nodes.iter().enumerate() {
        if index != 0 {
            if remaining[depth - 1] != totals[depth - 1] {
                emit(", ")?;
            }
            remaining[depth - 1] -= 1;
        }
        match node {
            Node::Leaf(kind) => emit(kind.canonical_type_name())?,
            Node::Tuple(arity) => {
                emit("(")?;
                remaining[depth] = usize::from(*arity);
                totals[depth] = usize::from(*arity);
                depth += 1;
            }
            _ => unreachable!("validated scalar/tuple key schema"),
        }
        while depth != 0 && remaining[depth - 1] == 0 {
            emit(")")?;
            depth -= 1;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::EntrypointValueKindV1 as Kind;
    use super::*;
    #[test]
    fn nested_tuple_keys_have_exact_names_and_domain_separated_identity() {
        let key = EntrypointValueTypeV1 {
            nodes: vec![
                Node::Tuple(2),
                Node::Leaf(Kind::AccountId),
                Node::Tuple(2),
                Node::Leaf(Kind::Int),
                Node::Leaf(Kind::Name),
            ],
        };
        assert!(validate_state_key_schema_v1(&key));
        let mut text = String::new();
        visit_state_key_type_v1(&key, |part| {
            text.push_str(part);
            Ok(())
        })
        .unwrap();
        assert_eq!(text, "(AccountId, (int, Name))");
        let mut changed = key.clone();
        changed.nodes[3] = Node::Leaf(Kind::Bool);
        assert_ne!(
            state_key_schema_hash_v1(&key),
            state_key_schema_hash_v1(&changed)
        );
        assert_ne!(
            state_key_schema_hash_v1(&key).unwrap(),
            super::super::entrypoint_return_schema_hash_v1(
                &norito::encode_canonical(&key).unwrap()
            )
        );
    }
    #[test]
    fn streamed_key_hash_matches_canonical_bytes_at_the_schema_bound_and_under_ambient_flags() {
        let key = EntrypointValueTypeV1 {
            nodes: std::iter::once(Node::Tuple(255))
                .chain(std::iter::repeat_n(Node::Leaf(Kind::Name), 255))
                .collect(),
        };
        let mut material = STATE_KEY_SCHEMA_HASH_DOMAIN_V1.to_vec();
        material.extend_from_slice(&norito::encode_canonical(&key).unwrap());
        let expected: [u8; 32] = iroha_crypto::Hash::new(material).into();
        assert_eq!(state_key_schema_hash_v1(&key), Some(expected));
        let flags = norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let _ambient = norito::core::DecodeFlagsGuard::enter(flags);
        assert_eq!(state_key_schema_hash_v1(&key), Some(expected));
    }
    #[test]
    fn key_schema_rejects_handles_and_enforces_one_complete_bounded_tree() {
        for nodes in [
            vec![],
            vec![Node::Tuple(0)],
            vec![Node::Tuple(1), Node::Leaf(Kind::Int)],
            vec![Node::Leaf(Kind::Json)],
            vec![Node::Option, Node::Leaf(Kind::Int)],
            vec![Node::Leaf(Kind::Int), Node::Leaf(Kind::Int)],
            vec![Node::Tuple(2), Node::Leaf(Kind::Int)],
            vec![Node::Tuple(2), Node::Leaf(Kind::Int), Node::Unit],
        ] {
            assert!(!validate_state_key_schema_v1(&EntrypointValueTypeV1 {
                nodes
            }));
        }
        let excessive = EntrypointValueTypeV1 {
            nodes: std::iter::once(Node::Tuple(256))
                .chain(std::iter::repeat_n(Node::Leaf(Kind::Int), 256))
                .collect(),
        };
        assert!(!validate_state_key_schema_v1(&excessive));
    }
    #[test]
    fn cursor_key_nodes_share_the_enclosing_schema_budget_and_round_trip() {
        let key = EntrypointValueTypeV1 {
            nodes: vec![
                Node::Tuple(2),
                Node::Leaf(Kind::Int),
                Node::Leaf(Kind::Name),
            ],
        };
        let schema = EntrypointValueTypeV1 {
            nodes: vec![Node::StateCursor(key.clone())],
        };
        assert_eq!(
            schema.canonical_type_name().as_deref(),
            Some("StateCursor<(int, Name)>")
        );
        let frame = norito::encode_canonical(&schema).unwrap();
        assert_eq!(
            norito::decode_canonical::<EntrypointValueTypeV1>(&frame).unwrap(),
            schema
        );
        let json = norito::json::to_json(&schema).unwrap();
        assert_eq!(
            norito::json::from_str::<EntrypointValueTypeV1>(&json).unwrap(),
            schema
        );
        let excessive = EntrypointValueTypeV1 {
            nodes: std::iter::once(Node::Tuple(64))
                .chain(std::iter::repeat_n(Node::StateCursor(key), 64))
                .collect(),
        };
        assert!(
            !excessive.validate(),
            "embedded key nodes count toward the same 256-node budget"
        );
    }
}
