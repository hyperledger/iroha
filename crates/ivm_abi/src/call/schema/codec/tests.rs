//! Independent materialized-wire, malformed-input and active resource controls.

use super::*;
use norito::core::{DecodeFlagsGuard, DecodeLimits};

fn payload(schema: &CallSchemaV1) -> Vec<u8> {
    let _flags = DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let mut bytes = Vec::new();
    schema.serialize(&mut Encoder::new(&mut bytes)).unwrap();
    bytes
}
fn decode_payload(bytes: &[u8]) -> Result<CallSchemaV1, Error> {
    let _flags = DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let (schema, used) = decode(bytes)?;
    if used != bytes.len() {
        return Err(Error::LengthMismatch);
    }
    Ok(schema)
}
fn primitive<T: SerializePayload>(value: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    value.serialize(&mut Encoder::new(&mut bytes)).unwrap();
    bytes
}
// Independent materialized construction uses the original canonical primitive
// and descriptor encoders. It never calls the compact writer or node-tag helper.
fn materialized(schema: &CallSchemaV1) -> Vec<u8> {
    let _flags = DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let mut bytes = b"CS1\0".to_vec();
    bytes.extend_from_slice(&(schema.nodes.len() as u64).to_le_bytes());
    for node in &schema.nodes {
        use CallTypeNodeV1 as N;
        match node {
            N::Struct { name, fields } => {
                bytes.push(0);
                bytes.extend(primitive(name));
                bytes.extend(primitive(fields));
            }
            N::Tuple(n) => {
                bytes.push(1);
                bytes.extend_from_slice(&n.to_le_bytes());
            }
            N::Option => bytes.push(2),
            N::Result => bytes.push(3),
            N::List { capacity } => bytes.extend_from_slice(&[4, *capacity]),
            N::Leaf(kind) => {
                bytes.push(5);
                let encoded = primitive(kind);
                assert_eq!(encoded.len(), 4);
                bytes.push(
                    u32::from_le_bytes(encoded.try_into().unwrap())
                        .try_into()
                        .unwrap(),
                );
            }
            N::StateCursor(key) => {
                bytes.push(8);
                let encoded = primitive(key);
                norito::core::write_len(&mut bytes, encoded.len() as u64).unwrap();
                bytes.extend(encoded);
            }
            N::Unit => bytes.push(6),
            N::Error(error) => {
                bytes.push(7);
                let encoded = primitive(error);
                norito::core::write_len(&mut bytes, encoded.len() as u64).unwrap();
                bytes.extend(encoded);
            }
            N::Enum(enumeration) => {
                bytes.push(12);
                let encoded = primitive(enumeration);
                norito::core::write_len(&mut bytes, encoded.len() as u64).unwrap();
                bytes.extend(encoded);
            }
            N::StateRoot => bytes.push(9),
            N::Pointer(id) | N::SecretNumeric(id) => {
                bytes.push(if matches!(node, N::Pointer(_)) {
                    10
                } else {
                    11
                });
                bytes.extend_from_slice(&id.to_le_bytes());
            }
        }
    }
    bytes
}
fn all_nodes() -> CallSchemaV1 {
    use CallTypeNodeV1 as N;
    use EntrypointValueKindV1 as K;
    let mut nodes = vec![
        N::Struct {
            name: "Fixture::Point".into(),
            fields: vec!["first".into(), "second".into()],
        },
        N::Tuple(2),
        N::Leaf(K::String),
        N::Leaf(K::Blob),
        N::Option,
        N::Result,
        N::List { capacity: 64 },
        N::Leaf(K::Quantity),
        N::Error(crate::error_types::list_error_type()),
        N::Struct {
            name: "Fixture::Empty".into(),
            fields: vec![],
        },
        N::Unit,
        N::StateRoot,
        N::Enum(crate::enum_tests::descriptor()),
    ];
    for kind in [
        K::Int,
        K::Decimal,
        K::Quantity,
        K::Bool,
        K::String,
        K::Json,
        K::Name,
        K::AccountId,
        K::AssetDefinitionId,
        K::AssetId,
        K::DomainId,
        K::NftId,
        K::DataSpaceId,
        K::Blob,
    ] {
        nodes.push(N::Leaf(kind));
        if kind != K::Json {
            nodes.push(N::StateCursor(crate::entrypoint::EntrypointValueTypeV1 {
                nodes: vec![crate::entrypoint::EntrypointValueTypeNodeV1::Leaf(kind)],
            }));
        }
    }
    for pointer in [0x0b, 0x0d, 0x0e, 0x0f, 0x13] {
        nodes.push(N::Pointer(pointer));
    }
    for pointer in [0x10, 0x11, 0x12] {
        nodes.push(N::SecretNumeric(pointer));
    }
    CallSchemaV1 { nodes }
}
#[test]
fn compact_full_wire_matches_independent_materialized_primitives_and_all_logical_roles() {
    for schema in [CallSchemaV1::empty(), CallSchemaV1::unit(), all_nodes()] {
        let bytes = payload(&schema);
        assert_eq!(bytes, materialized(&schema));
        assert_eq!(decode_payload(&bytes).unwrap(), schema);
        let framed = norito::encode_canonical(&schema).unwrap();
        assert_eq!(
            norito::decode_from_bytes::<CallSchemaV1>(&framed).unwrap(),
            schema
        );
        assert_eq!(
            norito::core::encoded_payload_len(&schema).unwrap(),
            bytes.len()
        );
    }
    assert_eq!(
        payload(&CallSchemaV1::unit()),
        b"CS1\0\x01\0\0\0\0\0\0\0\x06"
    );
    assert_ne!(
        payload(&CallSchemaV1 {
            nodes: vec![CallTypeNodeV1::Leaf(EntrypointValueKindV1::String)]
        }),
        payload(&CallSchemaV1 {
            nodes: vec![CallTypeNodeV1::Leaf(EntrypointValueKindV1::Blob)]
        })
    );
}
#[test]
fn compact_decoder_rejects_every_truncated_prefix_unknown_tags_counts_and_trailing_bytes() {
    let full = payload(&all_nodes());
    for end in 0..full.len() {
        assert!(decode_payload(&full[..end]).is_err(), "prefix {end}");
    }
    let mut trailing = full.clone();
    trailing.push(6);
    assert!(decode_payload(&trailing).is_err());
    for magic in [b"CS0\0", b"CS2\0", b"NRT0"] {
        let mut bytes = full.clone();
        bytes[..4].copy_from_slice(magic);
        assert!(decode_payload(&bytes).is_err());
    }
    for count in [0, 1, u64::MAX, (MAX_CALL_SCHEMA_NODES_V1 + 1) as u64] {
        let mut bytes = full.clone();
        bytes[4..12].copy_from_slice(&count.to_le_bytes());
        assert!(decode_payload(&bytes).is_err());
    }
    for tag in [13, 127, 255] {
        let mut bytes = payload(&CallSchemaV1::unit());
        bytes[12] = tag;
        assert!(
            matches!(decode_payload(&bytes),Err(Error::InvalidTag { context:"CS1 callable node",tag:actual }) if actual==tag)
        );
    }
    let mut bytes = payload(&CallSchemaV1 {
        nodes: vec![CallTypeNodeV1::Leaf(EntrypointValueKindV1::Int)],
    });
    bytes[13] = 14;
    assert!(matches!(
        decode_payload(&bytes),
        Err(Error::InvalidTag {
            context: "CS1 scalar kind",
            tag: 14
        })
    ));
}
#[test]
fn compact_decoder_preserves_original_node_depth_nominal_resource_and_table_limits() {
    use CallTypeNodeV1 as N;
    let mut deep = CallSchemaV1 {
        nodes: vec![N::Option; crate::call::MAX_CALL_SCHEMA_DEPTH_V1 - 1],
    };
    deep.nodes.push(N::Unit);
    assert_eq!(decode_payload(&payload(&deep)).unwrap(), deep);
    deep.nodes.insert(0, N::Option);
    assert!(decode_payload(&payload(&deep)).is_err());
    let nodes = CallSchemaV1 {
        nodes: vec![N::Unit; MAX_CALL_SCHEMA_NODES_V1],
    };
    assert_eq!(decode_payload(&payload(&nodes)).unwrap(), nodes);
    let mut over = nodes;
    over.nodes.push(N::Unit);
    assert!(decode_payload(&payload(&over)).is_err());
    for invalid in [
        vec![N::List { capacity: 65 }, N::Unit],
        vec![N::List { capacity: 1 }, N::StateRoot],
        vec![
            N::Struct {
                name: "Fixture::Point".into(),
                fields: vec!["x".into(), "x".into()],
            },
            N::Unit,
            N::Unit,
        ],
        vec![
            N::Struct {
                name: "kotodama::AccountView".into(),
                fields: vec!["id".into(), "metadata".into()],
            },
            N::Leaf(EntrypointValueKindV1::Blob),
            N::Leaf(EntrypointValueKindV1::Json),
        ],
    ] {
        assert!(decode_payload(&payload(&CallSchemaV1 { nodes: invalid })).is_err());
    }
    let mut descriptor = crate::call::EmbeddedCallableV1 {
        entry_pc: 0,
        frame_bytes: 16,
        arguments: CallSchemaV1 {
            nodes: vec![N::Unit; crate::call::MAX_CALL_WORDS_V1],
        },
        results: CallSchemaV1::unit(),
    };
    let frame = norito::encode_canonical(&descriptor).unwrap();
    assert!(
        norito::decode_from_bytes::<crate::call::EmbeddedCallableV1>(&frame)
            .unwrap()
            .validate()
    );
    descriptor.arguments.nodes.push(N::Unit);
    assert!(
        !norito::decode_from_bytes::<crate::call::EmbeddedCallableV1>(
            &norito::encode_canonical(&descriptor).unwrap()
        )
        .unwrap()
        .validate()
    );
}
#[test]
fn compact_decode_charges_original_sequence_and_node_layout_before_allocation() {
    let bytes = payload(&CallSchemaV1 {
        nodes: vec![CallTypeNodeV1::Unit; 3],
    });
    let backing = 3 * std::mem::size_of::<CallTypeNodeV1>();
    let limited = |sequence, total, allocation| {
        norito::core::with_decode_limits(
            DecodeLimits::new(sequence, 1 << 20, total, allocation, 256),
            || decode_payload(&bytes),
        )
    };
    assert!(matches!(
        limited(2, 100, 1 << 20),
        Err(Error::SequenceLengthExceeded {
            length: 3,
            limit: 2
        })
    ));
    assert!(matches!(
        limited(100, 2, 1 << 20),
        Err(Error::TotalElementsExceeded {
            attempted: 3,
            limit: 2
        })
    ));
    assert!(
        matches!(limited(100,100,backing+2),Err(Error::TotalAllocationExceeded {attempted,limit}) if attempted==(backing+3) as u64&&limit==(backing+2) as u64)
    );
    assert_eq!(limited(100, 100, backing + 3).unwrap().nodes.len(), 3);
    assert_eq!(
        decode_payload(&bytes).unwrap().nodes.len(),
        3,
        "exact refusal does not poison a later original attempt"
    );
}
#[test]
fn compact_nested_strings_and_nominal_errors_keep_original_field_utf8_and_depth_refusals() {
    let schema = CallSchemaV1 {
        nodes: vec![CallTypeNodeV1::Struct {
            name: "Fixture::Point".into(),
            fields: vec![],
        }],
    };
    let mut bytes = payload(&schema);
    bytes[14] = 0xff;
    assert!(matches!(decode_payload(&bytes), Err(Error::InvalidUtf8)));
    let bytes = payload(&schema);
    let error =
        norito::core::with_decode_limits(DecodeLimits::new(100, 4, 100, 1 << 20, 256), || {
            decode_payload(&bytes)
        })
        .unwrap_err();
    assert!(matches!(
        error,
        Error::FieldLengthExceeded { length, limit: 4 } if length == "Fixture::Point".len() as u64
    ));
    let bytes = payload(&CallSchemaV1 {
        nodes: vec![CallTypeNodeV1::Error(crate::error_types::list_error_type())],
    });
    let error =
        norito::core::with_decode_limits(DecodeLimits::new(100, 1 << 20, 100, 1 << 20, 0), || {
            decode_payload(&bytes)
        })
        .unwrap_err();
    assert!(matches!(
        error.decode_resource_error(),
        Some(norito::core::DecodeResourceError::NestingDepthExceeded { .. })
    ));
}
#[test]
fn compact_schema_rejects_the_retired_original_generic_vector_body_without_decoder_fallback() {
    // Original Unit node was a u32 discriminant in a length-prefixed Vec
    // element, itself the single length-prefixed CallSchema field.
    let _flags = DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let mut vector = 1u64.to_le_bytes().to_vec();
    norito::core::write_len(&mut vector, 4).unwrap();
    vector.extend_from_slice(&6u32.to_le_bytes());
    let mut original = Vec::new();
    norito::core::write_len(&mut original, vector.len() as u64).unwrap();
    original.extend(vector);
    assert!(matches!(
        decode_payload(&original),
        Err(Error::InvalidMagic)
    ));
    let mut invented = b"CS1\0".to_vec();
    invented.extend(original);
    assert!(decode_payload(&invented).is_err());
}

// Encode-only historical oracle. It is test-private, has no decoder or schema
// alias, and uses the original complete enum payloads to measure retired framing.
#[derive(norito::Encode)]
enum OriginalNode {
    Struct { name: String, fields: Vec<String> },
    Tuple(u32),
    Option,
    Result,
    List { capacity: u8 },
    Leaf(EntrypointValueKindV1),
    Unit,
    Error(iroha_data_model::smart_contract::manifest::ContractErrorTypeDescriptor),
    StateCursor(crate::entrypoint::EntrypointValueTypeV1),
    StateRoot,
    Pointer(u16),
    SecretNumeric(u16),
    Enum(iroha_data_model::smart_contract::manifest::ContractEnumTypeDescriptorV1),
}
#[derive(norito::Encode)]
struct OriginalSchema {
    nodes: Vec<OriginalNode>,
}
fn original_materialized_payload(schema: &CallSchemaV1) -> Vec<u8> {
    let _flags = DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let nodes = schema
        .nodes
        .iter()
        .map(|node| {
            use CallTypeNodeV1 as N;
            match node {
                N::Struct { name, fields } => OriginalNode::Struct {
                    name: name.clone(),
                    fields: fields.clone(),
                },
                N::Tuple(n) => OriginalNode::Tuple(*n),
                N::Option => OriginalNode::Option,
                N::Result => OriginalNode::Result,
                N::List { capacity } => OriginalNode::List {
                    capacity: *capacity,
                },
                N::Leaf(kind) => OriginalNode::Leaf(*kind),
                N::Unit => OriginalNode::Unit,
                N::Error(error) => OriginalNode::Error(error.clone()),
                N::StateCursor(kind) => OriginalNode::StateCursor(kind.clone()),
                N::StateRoot => OriginalNode::StateRoot,
                N::Pointer(id) => OriginalNode::Pointer(*id),
                N::SecretNumeric(id) => OriginalNode::SecretNumeric(*id),
                N::Enum(enumeration) => OriginalNode::Enum(enumeration.clone()),
            }
        })
        .collect();
    primitive(&OriginalSchema { nodes })
}
#[test]
fn compact_full_schema_has_a_real_wire_reduction_against_original_complete_enum_framing() {
    let schema = CallSchemaV1 {
        nodes: vec![CallTypeNodeV1::Leaf(EntrypointValueKindV1::Quantity); 1000],
    };
    let original = original_materialized_payload(&schema);
    let compact = payload(&schema);
    assert_eq!(compact.len(), 12 + 2000);
    assert!(compact.len() < original.len());
    assert_eq!(decode_payload(&compact).unwrap(), schema);
    assert!(matches!(
        decode_payload(&original),
        Err(Error::InvalidMagic)
    ));
    let all = all_nodes();
    assert!(payload(&all).len() < original_materialized_payload(&all).len());
    assert!(matches!(
        decode_payload(&original_materialized_payload(&all)),
        Err(Error::InvalidMagic)
    ));
}
