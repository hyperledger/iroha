//! Boundary, conversion, and retired erased-payload rejection for callable schemas.
use super::*;
use crate::{entrypoint::*, pointer_abi::PointerType};
fn schema(nodes: Vec<CallTypeNodeV1>) -> CallSchemaV1 {
    CallSchemaV1 { nodes }
}
fn callable(arguments: CallSchemaV1, results: CallSchemaV1) -> EmbeddedCallableV1 {
    EmbeddedCallableV1 {
        entry_pc: 4,
        frame_bytes: 16,
        arguments,
        results,
    }
}
#[test]
fn flat_schema_layouts_derive_nested_widths_and_exact_subtree_ends() {
    use CallTypeNodeV1 as Node;
    let value = schema(vec![
        Node::Tuple(2),
        Node::Option,
        Node::Tuple(2),
        Node::Unit,
        Node::Leaf(EntrypointValueKindV1::Bool),
        Node::List { capacity: 3 },
        Node::Result,
        Node::Unit,
        Node::Error(crate::error_types::list_error_type()),
    ]);
    let summary = value.analyze().unwrap();
    assert_eq!((summary.root_count(), summary.word_count()), (1, 2));
    let mut layouts = vec![CallNodeLayoutV1::default(); value.nodes.len()];
    assert_eq!(value.analyze_into(&mut layouts), Some(summary));
    assert_eq!(
        layouts[0],
        CallNodeLayoutV1 {
            subtree_end: 9,
            words: 2
        }
    );
    assert_eq!(
        layouts[1],
        CallNodeLayoutV1 {
            subtree_end: 5,
            words: 1
        }
    );
    assert_eq!(
        layouts[2],
        CallNodeLayoutV1 {
            subtree_end: 5,
            words: 2
        }
    );
    assert_eq!(
        layouts[5],
        CallNodeLayoutV1 {
            subtree_end: 9,
            words: 1
        }
    );
    assert!(value.analyze_into(&mut layouts[..8]).is_none());
    assert_eq!(
        value.analysis_reservation_bytes(),
        Some(9 * size_of::<CallNodeLayoutV1>())
    );
}
#[test]
fn erased_missing_children_and_malformed_flat_shapes_reject_on_decode() {
    use CallTypeNodeV1 as Node;
    for nodes in [
        vec![Node::Option],
        vec![Node::Result, Node::Unit],
        vec![Node::List { capacity: 2 }],
        vec![Node::Tuple(u32::MAX)],
        vec![Node::Tuple(1), Node::Unit],
        vec![Node::List { capacity: 0 }, Node::Unit],
        vec![Node::StateCursor(
            crate::entrypoint::EntrypointValueTypeV1 {
                nodes: vec![crate::entrypoint::EntrypointValueTypeNodeV1::Leaf(
                    EntrypointValueKindV1::Json,
                )],
            },
        )],
        vec![Node::Pointer(PointerType::Int as u16)],
        vec![Node::SecretNumeric(PointerType::Blob as u16)],
        vec![
            Node::Struct {
                name: "Fixture::Point".into(),
                fields: vec!["x".into(), "x".into()],
            },
            Node::Unit,
            Node::Unit,
        ],
    ] {
        let invalid = schema(nodes);
        assert!(invalid.analyze().is_none());
        let bytes = norito::to_bytes(&invalid).unwrap();
        assert!(norito::decode_from_bytes::<CallSchemaV1>(&bytes).is_err());
    }
}
#[test]
fn private_limits_are_independent_of_public_limits_and_table_width() {
    use CallTypeNodeV1 as Node;
    let mut depth = schema(vec![Node::Option; MAX_CALL_SCHEMA_DEPTH_V1 - 1]);
    depth.nodes.push(Node::Unit);
    assert_eq!(depth.word_count(), Some(1));
    depth.nodes.insert(0, Node::Option);
    assert!(depth.analyze().is_none());
    let mut wide = schema(vec![
        Node::Option,
        Node::Tuple((MAX_CALL_WORDS_V1 + 1) as u32),
    ]);
    wide.nodes
        .extend(std::iter::repeat_n(Node::Unit, MAX_CALL_WORDS_V1 + 1));
    assert!(callable(CallSchemaV1::empty(), wide).validate());
    let mut arguments = schema(vec![Node::Unit; MAX_CALL_WORDS_V1]);
    assert!(callable(arguments.clone(), CallSchemaV1::unit()).validate());
    arguments.nodes.push(Node::Unit);
    assert!(!callable(arguments, CallSchemaV1::unit()).validate());
    let mut nodes = schema(vec![Node::Unit; MAX_CALL_SCHEMA_NODES_V1]);
    assert_eq!(
        nodes.analyze().unwrap().root_count(),
        MAX_CALL_SCHEMA_NODES_V1
    );
    nodes.nodes.push(Node::Unit);
    assert!(nodes.analyze().is_none());
    assert!(nodes.analysis_reservation_bytes().is_none());
    assert!(!callable(CallSchemaV1::empty(), CallSchemaV1::empty()).validate());
    assert!(!callable(CallSchemaV1::empty(), schema(vec![Node::Unit, Node::Unit])).validate());
}
#[test]
fn wide_nominal_products_reject_duplicate_fields_across_validation_batches() {
    let mut fields = (0..4096)
        .map(|index| format!("f{index}"))
        .collect::<Vec<_>>();
    let mut nodes = vec![CallTypeNodeV1::Struct {
        name: "Fixture::Wide".into(),
        fields: fields.clone(),
    }];
    nodes.extend(std::iter::repeat_n(CallTypeNodeV1::Unit, fields.len()));
    assert_eq!(schema(nodes.clone()).word_count(), Some(4096));
    fields[4095] = fields[0].clone();
    nodes[0] = CallTypeNodeV1::Struct {
        name: "Fixture::Wide".into(),
        fields,
    };
    assert!(schema(nodes).analyze().is_none());
}
#[test]
fn resource_and_privacy_roles_are_validated_inside_aggregate_types() {
    use CallTypeNodeV1 as Node;
    let secret = Node::SecretNumeric(PointerType::Int as u16);
    assert!(secret.is_private());
    assert_eq!(secret.pointer_type(), Some(PointerType::Int));
    let tuple = schema(vec![Node::Tuple(2), Node::Unit, secret.clone()]);
    assert!(tuple.contains_private() && tuple.analyze().is_some());
    for resource in [
        secret,
        Node::StateRoot,
        Node::Pointer(PointerType::AxtAnchoredSpendV1 as u16),
    ] {
        assert!(
            schema(vec![Node::List { capacity: 1 }, Node::Option, resource])
                .analyze()
                .is_none()
        );
    }
}
#[test]
fn public_conversion_preserves_complete_nominal_and_nested_schema() {
    use EntrypointValueTypeNodeV1 as Public;
    let public = EntrypointValueTypeV1 {
        nodes: vec![
            Public::Struct(EntrypointStructTypeNodeV1 {
                name: "Fixture::Payload".into(),
                fields: vec!["values".into(), "failure".into()],
            }),
            Public::List(EntrypointListTypeNodeV1 { capacity: 4 }),
            Public::Option,
            Public::StateCursor(crate::entrypoint::EntrypointValueTypeV1 {
                nodes: vec![crate::entrypoint::EntrypointValueTypeNodeV1::Leaf(
                    EntrypointValueKindV1::Int,
                )],
            }),
            Public::Error(crate::error_types::list_error_type()),
        ],
    };
    let converted = CallSchemaV1::from_entrypoint_type(&public).unwrap();
    assert!(converted.matches_entrypoint_type(&public));
    assert_eq!(converted.word_count(), public.word_count());
    let bytes = norito::to_bytes(&converted).unwrap();
    assert_eq!(
        norito::decode_from_bytes::<CallSchemaV1>(&bytes).unwrap(),
        converted
    );
    let arguments = EntrypointArgumentSchemaV1 {
        fields: vec![EntrypointArgumentFieldV1 {
            name: "payload".into(),
            ty: public.clone(),
        }],
    };
    assert_eq!(
        CallSchemaV1::from_entrypoint_arguments(&arguments).unwrap(),
        converted
    );
    assert!(converted.matches_entrypoint_arguments(&arguments));
    for index in [0, 1, 3, 4] {
        let mut changed = converted.clone();
        match &mut changed.nodes[index] {
            CallTypeNodeV1::Struct { name, .. } => *name = "Different".into(),
            CallTypeNodeV1::List { capacity } => *capacity = 5,
            CallTypeNodeV1::StateCursor(key) => {
                *key = EntrypointValueTypeV1 {
                    nodes: vec![EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Bool)],
                }
            }
            CallTypeNodeV1::Error(error) => error.identity = "kotodama::OtherError".into(),
            _ => unreachable!(),
        }
        assert!(!changed.matches_entrypoint_type(&public));
    }
    let too_wide_public = EntrypointValueTypeV1 {
        nodes: std::iter::once(Public::Tuple(256))
            .chain(std::iter::repeat_n(Public::Unit, 256))
            .collect(),
    };
    assert!(CallSchemaV1::from_entrypoint_type(&too_wide_public).is_none());
    assert!(!converted.matches_entrypoint_type(&too_wide_public));
}

#[test]
fn private_reserved_nominal_types_require_the_same_complete_shapes_as_public_types() {
    use CallTypeNodeV1 as Node;
    for name in [
        "kotodama::StatePage",
        "kotodama::QueryPage",
        "kotodama::AccountView",
        "kotodama::AssetView",
        "kotodama::AssetDefinitionView",
        "kotodama::DomainView",
        "kotodama::NftView",
    ] {
        let invalid = schema(vec![
            Node::Struct {
                name: name.into(),
                fields: vec!["bogus".into()],
            },
            Node::Unit,
        ]);
        assert!(invalid.analyze().is_none(), "forged {name}");
        assert!(
            norito::decode_from_bytes::<CallSchemaV1>(&norito::to_bytes(&invalid).unwrap())
                .is_err()
        );
    }
    let page = schema(vec![
        Node::Struct {
            name: "kotodama::QueryPage".into(),
            fields: vec!["items".into(), "next_offset".into()],
        },
        Node::List { capacity: 64 },
        Node::Struct {
            name: "kotodama::AccountView".into(),
            fields: vec!["id".into(), "metadata".into()],
        },
        Node::Leaf(EntrypointValueKindV1::AccountId),
        Node::Leaf(EntrypointValueKindV1::Json),
        Node::Option,
        Node::Leaf(EntrypointValueKindV1::Int),
    ]);
    assert!(page.analyze().is_some());
    let mut wrong_capacity = page.clone();
    wrong_capacity.nodes[1] = Node::List { capacity: 63 };
    assert!(wrong_capacity.analyze().is_none());
    let mut wrong_field = page.clone();
    wrong_field.nodes[4] = Node::Leaf(EntrypointValueKindV1::Blob);
    assert!(wrong_field.analyze().is_none());
    let mut wrong_tail = page;
    wrong_tail.nodes[6] = Node::Leaf(EntrypointValueKindV1::Quantity);
    assert!(wrong_tail.analyze().is_none());
}

#[test]
fn private_state_pages_allow_large_values_without_relaxing_public_schema_limits() {
    use CallTypeNodeV1 as Node;
    let mut nodes = vec![
        Node::Struct {
            name: "kotodama::StatePage".into(),
            fields: vec!["items".into(), "next".into()],
        },
        Node::List { capacity: 2 },
        Node::Tuple(2),
        Node::Leaf(EntrypointValueKindV1::Int),
        Node::Struct {
            name: "Fixture::Wide".into(),
            fields: (0..512).map(|index| format!("f{index}")).collect(),
        },
    ];
    nodes.extend(std::iter::repeat_n(
        Node::Leaf(EntrypointValueKindV1::Bool),
        512,
    ));
    nodes.push(Node::Option);
    nodes.push(Node::StateCursor(
        crate::entrypoint::EntrypointValueTypeV1 {
            nodes: vec![crate::entrypoint::EntrypointValueTypeNodeV1::Leaf(
                EntrypointValueKindV1::Int,
            )],
        },
    ));
    let page = schema(nodes);
    assert_eq!(page.word_count(), Some(2));
    let mut layouts = vec![CallNodeLayoutV1::default(); page.nodes.len()];
    assert!(page.analyze_into(&mut layouts).is_some());
    assert_eq!(layouts[2].words, 513);
    assert_eq!(
        norito::decode_from_bytes::<CallSchemaV1>(&norito::to_bytes(&page).unwrap()).unwrap(),
        page
    );
    let mut mismatched = page.clone();
    *mismatched.nodes.last_mut().unwrap() =
        Node::StateCursor(crate::entrypoint::EntrypointValueTypeV1 {
            nodes: vec![crate::entrypoint::EntrypointValueTypeNodeV1::Leaf(
                EntrypointValueKindV1::Bool,
            )],
        });
    assert!(mismatched.analyze().is_none());
    let mut wrong_key = page;
    wrong_key.nodes[3] = Node::Leaf(EntrypointValueKindV1::Json);
    assert!(wrong_key.analyze().is_none());
    let public = EntrypointValueTypeV1 {
        nodes: std::iter::once(EntrypointValueTypeNodeV1::Tuple(512))
            .chain(std::iter::repeat_n(EntrypointValueTypeNodeV1::Unit, 512))
            .collect(),
    };
    assert!(!public.validate());
}
