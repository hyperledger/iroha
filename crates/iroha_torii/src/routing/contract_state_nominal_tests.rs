// Exact nominal durable-state projection and public call-boundary roundtrips.

#[test]
fn contract_state_nominal_nested_options_preserve_none_and_some_unit() {
    use iroha_data_model::smart_contract::entrypoint::{
        EntrypointArgumentFieldV1, EntrypointArgumentSchemaV1, EntrypointValueAtomV1 as PublicAtom,
        EntrypointValueTypeNodeV1 as Node, EntrypointValueTypeV1,
    };
    use ivm::{EmbeddedStateType as Type, state_value::StateValueAtomV1 as Atom};
    let ty = Type::Option(Box::new(Type::Option(Box::new(Type::Unit))));
    let schema = EntrypointArgumentSchemaV1 {
        fields: vec![EntrypointArgumentFieldV1 {
            name: "value".to_owned(),
            ty: EntrypointValueTypeV1 {
                nodes: vec![Node::Option, Node::Option, Node::Unit],
            },
        }],
    };
    for (atoms, expected_json, expected_atoms) in [
        (
            vec![Atom::Tag(false)],
            "{\"none\":true}",
            vec![PublicAtom::Tag(false)],
        ),
        (
            vec![Atom::Tag(true), Atom::Tag(false)],
            "{\"some\":{\"none\":true}}",
            vec![PublicAtom::Tag(true), PublicAtom::Tag(false)],
        ),
        (
            vec![Atom::Tag(true), Atom::Tag(true), Atom::Unit],
            "{\"some\":{\"some\":null}}",
            vec![
                PublicAtom::Tag(true),
                PublicAtom::Tag(true),
                PublicAtom::Unit,
            ],
        ),
    ] {
        let record = make_state_record(&ty, atoms);
        let projected = decode_contract_state_scalar_json(&record, &ty).unwrap();
        assert_eq!(projected.get(), expected_json);
        let payload =
            IrohaJson::from_raw_json(format!("{{\"value\":{}}}", projected.get())).unwrap();
        assert_eq!(
            ivm_abi::arguments::argument_record_from_json(&schema, &payload)
                .unwrap()
                .atoms,
            expected_atoms
        );
    }
    for malformed in [
        "null",
        "{\"some\":null}",
        "{\"none\":false}",
        "{\"none\":true,\"some\":{\"none\":true}}",
    ] {
        let payload = IrohaJson::from_raw_json(format!("{{\"value\":{malformed}}}")).unwrap();
        assert!(ivm_abi::arguments::argument_record_from_json(&schema, &payload).is_err());
    }
}

fn nominal_state_key_schema(
    kind: iroha_data_model::smart_contract::entrypoint::EntrypointValueKindV1,
) -> iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
    use iroha_data_model::smart_contract::entrypoint::{
        EntrypointValueTypeNodeV1, EntrypointValueTypeV1,
    };
    EntrypointValueTypeV1 {
        nodes: vec![EntrypointValueTypeNodeV1::Leaf(kind)],
    }
}

fn nominal_state_key_hash(
    kind: iroha_data_model::smart_contract::entrypoint::EntrypointValueKindV1,
) -> [u8; 32] {
    iroha_data_model::smart_contract::entrypoint::state_key_schema_hash_v1(
        &nominal_state_key_schema(kind),
    )
    .unwrap()
}

fn nominal_state_cursor_fixture() -> iroha_data_model::smart_contract::state_cursor::StateCursorV1 {
    use iroha_data_model::smart_contract::{
        entrypoint::EntrypointValueKindV1 as Kind, state_cursor::StateCursorV1,
    };
    let suffix = contract_state_stored_map_key_suffix(&ivm::EmbeddedStateType::Bool, "true")
        .expect("canonical bool map key");
    StateCursorV1 {
        instance: "local::projection".to_owned(),
        map: "Balances".parse().unwrap(),
        schema_hash: [7; 32],
        key_schema_hash: nominal_state_key_hash(Kind::Bool),
        last_key: format!("Balances/{suffix}").parse().unwrap(),
    }
}

#[test]
fn contract_state_nominal_products_roundtrip_through_public_argument_json() {
    use iroha_data_model::smart_contract::entrypoint::{
        EntrypointArgumentFieldV1, EntrypointArgumentSchemaV1, EntrypointListTypeNodeV1,
        EntrypointStructTypeNodeV1, EntrypointValueAtomV1 as PublicAtom,
        EntrypointValueTypeNodeV1 as Node, EntrypointValueTypeV1,
    };
    use ivm::state_value::StateValueAtomV1 as Atom;
    use ivm::{EmbeddedStateFieldDescriptor as Field, EmbeddedStateType as Type};
    let error = ivm::error_types::list_error_type();
    let name = "std/math@1.0.0::Math::Receipt";
    let fields = vec!["completed".to_owned(), "attempts".to_owned()];
    let ty = Type::Struct {
        name: name.to_owned(),
        fields: vec![
            Field {
                name: fields[0].clone(),
                ty: Type::Unit,
            },
            Field {
                name: fields[1].clone(),
                ty: Type::List {
                    capacity: 4,
                    element: Box::new(Type::Result {
                        ok: Box::new(Type::Unit),
                        err: Box::new(Type::Error(error.clone())),
                    }),
                },
            },
        ],
    };
    let record = make_state_record(
        &ty,
        vec![
            Atom::Unit,
            Atom::List(vec![
                vec![Atom::Tag(true), Atom::Unit],
                vec![Atom::Tag(false), Atom::ErrorCode(1)],
                vec![Atom::Tag(false), Atom::ErrorCode(2)],
            ]),
        ],
    );
    let projected = decode_contract_state_scalar_json(&record, &ty).expect("project exact product");
    assert_eq!(
        projected.get(),
        "{\"attempts\":[{\"ok\":null},{\"err\":\"IndexOutOfBounds\"},{\"err\":\"CapacityExceeded\"}],\"completed\":null}"
    );
    let schema = EntrypointArgumentSchemaV1 {
        fields: vec![EntrypointArgumentFieldV1 {
            name: "receipt".to_owned(),
            ty: EntrypointValueTypeV1 {
                nodes: vec![
                    Node::Struct(EntrypointStructTypeNodeV1 {
                        name: name.to_owned(),
                        fields,
                    }),
                    Node::Unit,
                    Node::List(EntrypointListTypeNodeV1 { capacity: 4 }),
                    Node::Result,
                    Node::Unit,
                    Node::Error(error),
                ],
            },
        }],
    };
    let payload = IrohaJson::from_raw_json(format!("{{\"receipt\":{}}}", projected.get())).unwrap();
    let arguments = ivm_abi::arguments::argument_record_from_json(&schema, &payload)
        .expect("projected state is valid public call JSON");
    assert_eq!(
        arguments.atoms,
        vec![
            PublicAtom::Unit,
            PublicAtom::List(3),
            PublicAtom::Tag(true),
            PublicAtom::Unit,
            PublicAtom::Tag(false),
            PublicAtom::ErrorCode(1),
            PublicAtom::Tag(false),
            PublicAtom::ErrorCode(2),
        ]
    );
    for malformed in [
        "{\"receipt\":{\"attempts\":[],\"completed\":0}}",
        "{\"receipt\":{\"attempts\":[{\"err\":1}],\"completed\":null}}",
        "{\"receipt\":{\"attempts\":[{\"err\":\"Other::IndexOutOfBounds\"}],\"completed\":null}}",
    ] {
        let payload = IrohaJson::from_raw_json(malformed.to_owned()).unwrap();
        assert!(ivm_abi::arguments::argument_record_from_json(&schema, &payload).is_err());
    }
}

#[test]
fn contract_state_nominal_identity_schema_and_codes_are_exact() {
    use ivm::{EmbeddedStateType as Type, state_value::StateValueAtomV1 as Atom};
    let descriptor = ivm::error_types::list_error_type();
    let ty = Type::Error(descriptor.clone());
    let record = make_state_record(&ty, vec![Atom::ErrorCode(1)]);
    assert_eq!(
        decode_contract_state_scalar_json(&record, &ty)
            .unwrap()
            .get(),
        "\"IndexOutOfBounds\""
    );
    let mut wrong_identity = descriptor.clone();
    wrong_identity.identity = "other::ListError".to_owned();
    let mut wrong_schema = descriptor;
    wrong_schema.variants[0].name = "DifferentVariant".to_owned();
    for wrong in [
        Type::Error(wrong_identity),
        Type::Error(wrong_schema),
        Type::Unit,
    ] {
        assert!(decode_contract_state_scalar_json(&record, &wrong).is_err());
    }
    let zero_code = ivm::state_value::StateValueRecordV1 {
        schema_hash: [0; 32],
        atoms: vec![Atom::ErrorCode(0)],
    };
    assert!(
        norito::to_bytes(&zero_code).is_err(),
        "zero error codes have no canonical record"
    );
    for atom in [Atom::ErrorCode(99), Atom::Bool(true), Atom::Unit] {
        let record = make_unchecked_state_record(&ty, vec![atom]);
        assert!(decode_contract_state_scalar_json(&record, &ty).is_err());
    }
    for atom in [Atom::Bool(false), Atom::Bool(true), Atom::ErrorCode(1)] {
        let record = make_unchecked_state_record(&Type::Unit, vec![atom]);
        assert!(decode_contract_state_scalar_json(&record, &Type::Unit).is_err());
    }
    let unit = make_state_record(&Type::Unit, vec![Atom::Unit]);
    let flags = norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
    let _alternate = norito::core::DecodeFlagsGuard::enter(flags);
    assert_eq!(
        decode_contract_state_scalar_json(&unit, &Type::Unit)
            .unwrap()
            .get(),
        "null"
    );
    assert_eq!(
        decode_contract_state_scalar_json(&record, &ty)
            .unwrap()
            .get(),
        "\"IndexOutOfBounds\""
    );
}

#[test]
fn contract_state_nominal_page_cursor_roundtrips_without_erasing_key_schema() {
    use iroha_data_model::smart_contract::entrypoint::{
        EntrypointArgumentFieldV1, EntrypointArgumentSchemaV1, EntrypointListTypeNodeV1,
        EntrypointStructTypeNodeV1, EntrypointValueAtomV1 as PublicAtom,
        EntrypointValueKindV1 as Kind, EntrypointValueTypeNodeV1 as Node, EntrypointValueTypeV1,
    };
    use ivm::state_value::StateValueAtomV1 as Atom;
    use ivm::{EmbeddedStateFieldDescriptor as Field, EmbeddedStateType as Type};
    let frame = nominal_state_cursor_fixture().encode_frame().unwrap();
    let envelope = make_tlv(PointerType::NoritoBytes, &frame);
    let ty = Type::Struct {
        name: "kotodama::StatePage".to_owned(),
        fields: vec![
            Field {
                name: "items".to_owned(),
                ty: Type::List {
                    capacity: 2,
                    element: Box::new(Type::Tuple(vec![Type::Bool, Type::Unit])),
                },
            },
            Field {
                name: "next".to_owned(),
                ty: Type::Option(Box::new(Type::StateCursor(nominal_state_key_schema(
                    Kind::Bool,
                )))),
            },
        ],
    };
    let record = make_state_record(
        &ty,
        vec![
            Atom::List(vec![vec![Atom::Bool(true), Atom::Unit]]),
            Atom::Tag(true),
            Atom::Pointer(envelope.clone()),
        ],
    );
    let projected = decode_contract_state_scalar_json(&record, &ty).unwrap();
    assert_eq!(
        projected.get(),
        &format!(
            "{{\"items\":[[true,null]],\"next\":{{\"some\":\"0x{}\"}}}}",
            hex::encode(&frame)
        )
    );
    let schema = EntrypointArgumentSchemaV1 {
        fields: vec![EntrypointArgumentFieldV1 {
            name: "page".to_owned(),
            ty: EntrypointValueTypeV1 {
                nodes: vec![
                    Node::Struct(EntrypointStructTypeNodeV1 {
                        name: "kotodama::StatePage".to_owned(),
                        fields: vec!["items".to_owned(), "next".to_owned()],
                    }),
                    Node::List(EntrypointListTypeNodeV1 { capacity: 2 }),
                    Node::Tuple(2),
                    Node::Leaf(Kind::Bool),
                    Node::Unit,
                    Node::Option,
                    Node::StateCursor(nominal_state_key_schema(Kind::Bool)),
                ],
            },
        }],
    };
    let payload = IrohaJson::from_raw_json(format!("{{\"page\":{}}}", projected.get())).unwrap();
    let arguments = ivm_abi::arguments::argument_record_from_json(&schema, &payload).unwrap();
    assert_eq!(
        arguments.atoms,
        vec![
            PublicAtom::List(1),
            PublicAtom::Bool(true),
            PublicAtom::Unit,
            PublicAtom::Tag(true),
            PublicAtom::Pointer(envelope),
        ]
    );
    let mut malformed = nominal_state_cursor_fixture();
    malformed.key_schema_hash = nominal_state_key_hash(Kind::Int);
    let malformed = malformed.encode_frame().unwrap();
    let payload = IrohaJson::from_raw_json(format!(
        "{{\"page\":{{\"items\":[],\"next\":{{\"some\":\"0x{}\"}}}}}}",
        hex::encode(malformed)
    ))
    .unwrap();
    assert!(ivm_abi::arguments::argument_record_from_json(&schema, &payload).is_err());
}

#[test]
fn contract_state_nominal_cursor_rejects_wrong_pointer_key_and_malformed_frames() {
    use iroha_data_model::smart_contract::entrypoint::EntrypointValueKindV1 as Kind;
    use ivm::{EmbeddedStateType as Type, state_value::StateValueAtomV1 as Atom};
    let ty = Type::StateCursor(nominal_state_key_schema(Kind::Bool));
    let cursor = nominal_state_cursor_fixture();
    let frame = cursor.encode_frame().unwrap();
    let valid = make_state_record(
        &ty,
        vec![Atom::Pointer(make_tlv(PointerType::NoritoBytes, &frame))],
    );
    assert!(decode_contract_state_scalar_json(&valid, &ty).is_ok());
    let mut wrong_key = cursor.clone();
    wrong_key.key_schema_hash = nominal_state_key_hash(Kind::Int);
    let mut wrong_map = cursor.clone();
    wrong_map.last_key = "Other/00".parse().unwrap();
    let mut empty_instance = cursor;
    empty_instance.instance.clear();
    let mut trailing = frame.clone();
    trailing.push(0);
    for (pointer, malformed) in [
        (PointerType::Blob, frame),
        (PointerType::NoritoBytes, wrong_key.encode_frame().unwrap()),
        (
            PointerType::NoritoBytes,
            norito::encode_canonical(&wrong_map).unwrap(),
        ),
        (
            PointerType::NoritoBytes,
            norito::encode_canonical(&empty_instance).unwrap(),
        ),
        (PointerType::NoritoBytes, trailing),
    ] {
        let record =
            make_unchecked_state_record(&ty, vec![Atom::Pointer(make_tlv(pointer, &malformed))]);
        assert!(decode_contract_state_scalar_json(&record, &ty).is_err());
    }
}

#[test]
fn contract_state_nominal_tuple_cursor_binds_complete_key_schema() {
    use iroha_data_model::smart_contract::entrypoint::{
        EntrypointValueKindV1 as Kind, EntrypointValueTypeNodeV1 as Node, EntrypointValueTypeV1,
        state_key_schema_hash_v1,
    };
    use ivm::EmbeddedStateType as Type;
    let key = EntrypointValueTypeV1 {
        nodes: vec![
            Node::Tuple(2),
            Node::Leaf(Kind::Bool),
            Node::Leaf(Kind::Name),
        ],
    };
    let mut cursor = nominal_state_cursor_fixture();
    cursor.key_schema_hash = state_key_schema_hash_v1(&key).unwrap();
    let suffix = contract_state_stored_map_key_suffix(
        &Type::Tuple(vec![Type::Bool, Type::Name]),
        r#"[true,"buyer"]"#,
    )
    .unwrap();
    cursor.last_key = format!("Balances/{suffix}").parse().unwrap();
    let frame = cursor.encode_frame().unwrap();
    let envelope = make_tlv(PointerType::NoritoBytes, &frame);
    assert_eq!(
        decode_contract_state_pointer_json_fragment(&envelope, &Type::StateCursor(key.clone()))
            .unwrap(),
        format!("\"0x{}\"", hex::encode(frame))
    );
    let mut changed = key;
    changed.nodes.swap(1, 2);
    assert!(
        decode_contract_state_pointer_json_fragment(&envelope, &Type::StateCursor(changed))
            .is_err()
    );
    let invalid = Type::StateCursor(nominal_state_key_schema(Kind::Json));
    assert_eq!(
        decode_contract_state_pointer_json_fragment(&envelope, &invalid).unwrap_err(),
        "invalid state cursor key schema"
    );
}

#[test]
fn contract_state_nominal_enum_json_preserves_type_and_variant() {
    use iroha_data_model::smart_contract::{
        entrypoint::{
            EntrypointArgumentFieldV1, EntrypointArgumentSchemaV1,
            EntrypointValueAtomV1 as PublicAtom, EntrypointValueTypeNodeV1 as Node,
            EntrypointValueTypeV1,
        },
        manifest::{ContractEnumTypeDescriptorV1, ContractEnumVariantDescriptorV1},
    };
    use ivm::{EmbeddedStateType as Type, state_value::StateValueAtomV1 as Atom};
    let descriptor = ContractEnumTypeDescriptorV1 {
        identity: "Fixture::Phase".to_owned(),
        variants: vec![
            ContractEnumVariantDescriptorV1 {
                name: "Open".to_owned(),
                code: 1,
            },
            ContractEnumVariantDescriptorV1 {
                name: "Closed".to_owned(),
                code: 7,
            },
        ],
    };
    let ty = Type::Option(Box::new(Type::Enum(descriptor.clone())));
    let record = make_state_record(&ty, vec![Atom::Tag(true), Atom::EnumCode(7)]);
    let projected = decode_contract_state_scalar_json(&record, &ty).unwrap();
    assert_eq!(projected.get(), "{\"some\":\"Closed\"}");
    let schema = EntrypointArgumentSchemaV1 {
        fields: vec![EntrypointArgumentFieldV1 {
            name: "phase".to_owned(),
            ty: EntrypointValueTypeV1 {
                nodes: vec![Node::Option, Node::Enum(descriptor.clone())],
            },
        }],
    };
    let payload = IrohaJson::from_raw_json(format!("{{\"phase\":{}}}", projected.get())).unwrap();
    assert_eq!(
        ivm_abi::arguments::argument_record_from_json(&schema, &payload)
            .unwrap()
            .atoms,
        vec![PublicAtom::Tag(true), PublicAtom::EnumCode(7)]
    );
    let mut other = descriptor;
    other.identity = "Fixture::OtherPhase".to_owned();
    assert!(
        decode_contract_state_scalar_json(&record, &Type::Option(Box::new(Type::Enum(other))))
            .is_err()
    );
    for atom in [Atom::EnumCode(99), Atom::ErrorCode(7), Atom::Bool(true)] {
        let record = make_unchecked_state_record(&ty, vec![Atom::Tag(true), atom]);
        assert!(decode_contract_state_scalar_json(&record, &ty).is_err());
    }
}

#[test]
fn contract_state_tuple_keys_use_exact_records_and_shared_argument_json() {
    use ivm::{EmbeddedStateType as Type, state_value::StateValueAtomV1 as Atom};
    let ty = Type::Tuple(vec![Type::Int, Type::Tuple(vec![Type::Bool, Type::Name])]);
    let logical = r#"["7",[true,"buyer/first"]]"#;
    let suffix = contract_state_stored_map_key_suffix(&ty, logical).unwrap();
    let expected = make_state_record(
        &ty,
        vec![
            Atom::Pointer(encode_contract_state_pointer_tlv_bytes(&Type::Int, "7").unwrap()),
            Atom::Bool(true),
            Atom::Pointer(
                encode_contract_state_pointer_tlv_bytes(&Type::Name, "buyer/first").unwrap(),
            ),
        ],
    );
    assert_eq!(hex::decode(&suffix).unwrap(), expected);
    assert_eq!(
        contract_state_stored_map_key_suffix(&ty, &format!("json-{logical}")),
        Some(suffix.clone())
    );
    let (query_key, stored) =
        match_contract_state_map_key_suffix("Pairs", &ty, &format!("Pairs/{suffix}"))
            .unwrap()
            .unwrap();
    assert_eq!(query_key, format!("record-{suffix}"));
    assert_eq!(stored, suffix);
    assert_eq!(
        contract_state_stored_map_key_suffix(&ty, &query_key),
        Some(suffix.clone())
    );
    let wrong = Type::Tuple(vec![
        Type::Quantity,
        Type::Tuple(vec![Type::Bool, Type::Name]),
    ]);
    assert!(contract_state_stored_map_key_suffix(&wrong, &query_key).is_none());
    for invalid in [
        r#"[7,[true,"buyer/first"]]"#,
        r#"["7",[true]]"#,
        r#"["7",[true,"buyer/first"],false]"#,
    ] {
        assert!(contract_state_stored_map_key_suffix(&ty, invalid).is_none());
    }
    let value_ty = Type::Bool;
    let registry = BTreeMap::from([(
        "Pairs".to_owned(),
        Some(Type::StateMap {
            key: Box::new(ty),
            value: Box::new(value_ty.clone()),
        }),
    )]);
    let storage = BTreeMap::from([(
        format!("Pairs/{suffix}"),
        make_state_record(&value_ty, vec![Atom::Bool(true)]),
    )]);
    for key in [logical.to_owned(), query_key] {
        let path = format!("Pairs/{key}");
        assert!(contract_state_logical_path_exists(
            &registry,
            &path,
            &|path| storage.contains_key(path)
        ));
        assert_eq!(
            decode_contract_state_path_json(&registry, &path, &|path| storage.get(path).cloned())
                .unwrap()
                .get(),
            "true"
        );
    }
}

#[test]
fn contract_state_map_keys_reject_old_carriers_and_bound_producer_inputs() {
    use ivm::EmbeddedStateType as Type;
    for (ty, bytes) in [
        (Type::Bool, norito::encode_canonical(&0_i64).unwrap()),
        (Type::Bool, norito::encode_canonical(&1_i64).unwrap()),
        (
            Type::Int,
            encode_contract_state_pointer_tlv_bytes(&Type::Int, "7").unwrap(),
        ),
    ] {
        let suffix = hex::encode(bytes);
        assert!(validate_contract_state_stored_map_key_suffix(&ty, &suffix).is_err());
        assert!(contract_state_stored_map_key_suffix(&ty, &format!("record-{suffix}")).is_none());
        assert!(contract_state_stored_map_key_suffix(&ty, &format!("tlv-{suffix}")).is_none());
    }
    let max = ivm::syscalls::STATE_MAP_MAX_KEY_BYTES;
    assert!(contract_state_stored_map_key_suffix(&Type::String, &"a".repeat(max + 1)).is_none());
    assert!(
        contract_state_stored_map_key_suffix(&Type::String, &"a".repeat(max)).is_none(),
        "framing also fits the 4KiB physical limit"
    );
    assert!(
        validate_contract_state_stored_map_key_suffix(&Type::Bool, &"00".repeat(max + 1)).is_err()
    );
    let suffix = contract_state_stored_map_key_suffix(&Type::Int, "7").unwrap();
    let mut trailing = hex::decode(suffix).unwrap();
    trailing.push(0);
    assert!(
        validate_contract_state_stored_map_key_suffix(&Type::Int, &hex::encode(trailing)).is_err()
    );
    for ty in [
        Type::Tuple(vec![]),
        Type::Tuple(vec![Type::Bool]),
        Type::Tuple(vec![Type::Bool, Type::Json]),
    ] {
        assert!(contract_state_stored_map_key_suffix(&ty, "[true,false]").is_none());
    }
}

#[test]
fn contract_state_logical_json_keys_canonicalize_whitespace_and_escapes() {
    use ivm::EmbeddedStateType as Type;
    let tuple = Type::Tuple(vec![Type::Int, Type::String]);
    let compact =
        contract_state_stored_map_key_suffix(&tuple, r#"["7","hello @#$ / world, \"quoted\""]"#)
            .expect("canonical tuple key");
    for logical in [
        r#"[ "7" , "hello @#$ / world, \"quoted\"" ]"#,
        r#"json-["7", "hello @#$ \/ world, \u0022quoted\u0022"]"#,
    ] {
        assert_eq!(
            contract_state_stored_map_key_suffix(&tuple, logical),
            Some(compact.clone())
        );
    }
    let compact_string =
        contract_state_stored_map_key_suffix(&Type::String, r#"json-"hello / world""#)
            .expect("canonical string key");
    assert_eq!(
        contract_state_stored_map_key_suffix(&Type::String, r#"json- "hello \/ world" "#),
        Some(compact_string),
    );
    for invalid in [
        r#"[7,"hello"]"#,
        r#"["7","hello"] trailing"#,
        r#"["7","hello"],"extra":true"#,
    ] {
        assert!(contract_state_stored_map_key_suffix(&tuple, invalid).is_none());
    }
}

#[test]
fn contract_state_query_paths_preserve_json_key_commas_and_quotes() {
    let tuple = r#"Pairs/["7",[true,"buyer"]]"#;
    let string = r#"Names/json-"record-a,b\"c""#;
    assert_eq!(
        contract_state_query_paths(&format!("{tuple},{string},total")).unwrap(),
        vec![tuple, string, "total"]
    );
    assert_eq!(contract_state_query_paths("a,,b,").unwrap(), vec!["a", "b"]);
    for invalid in [
        "",
        "Pairs/[true,false",
        "Pairs/[true}",
        "Names/json-\"unterminated",
    ] {
        assert!(contract_state_query_paths(invalid).is_err());
    }
    assert!(contract_state_query_paths(&format!("Pairs/{}", "[".repeat(257))).is_err());
    let paths = std::iter::repeat_n("a", CONTRACT_STATE_MAX_EXPLICIT_PATHS_V1 + 1)
        .collect::<Vec<_>>()
        .join(",");
    assert!(contract_state_query_paths(&paths).is_err());
}

#[test]
fn contract_state_logical_query_validation_bounds_keys_without_weakening_paths() {
    let decode = Some(ContractStateDecodeMode::Json);
    for path in [
        r#"Pairs/["7", "hello @#$ / world"]"#,
        r#"Labels/json-"hello @#$ / world""#,
    ] {
        assert_eq!(parse_contract_state_query_path(path, decode).unwrap(), path);
        assert!(parse_contract_state_query_path(path, None).is_err());
        assert!(StatePath::from_str(path).is_err());
    }
    for path in [
        r#"bad base/json-"key""#,
        r#"bad@base/json-"key""#,
        r#"Labels/json-"unterminated"#,
        r#"Pairs/["7", "key"] trailing"#,
    ] {
        assert!(
            parse_contract_state_query_path(path, decode).is_err(),
            "{path}"
        );
    }
    let max = ivm::syscalls::STATE_MAP_MAX_KEY_BYTES;
    // The bound includes the explicit logical-key prefix and JSON quotes.
    let exact = format!("Labels/json-\"{}\"", "a".repeat(max - 7));
    assert!(parse_contract_state_query_path(&exact, decode).is_ok());
    let overflow = format!("Labels/json-\"{}\"", "a".repeat(max - 6));
    assert!(parse_contract_state_query_path(&overflow, decode).is_err());
}

routing_test! { async contract_state_endpoint_accepts_schema_bound_json_keys_with_reserved_text
    use iroha_data_model::{account::Account, block::BlockHeader, permission::Permission};
    use iroha_executor_data_model::permission::smart_contract::CanManageSmartContractCode;
    use iroha_model_base::topology::DataSpaceId;
    use ivm::{EmbeddedStateType as Type, state_value::StateValueAtomV1 as Atom};
    let key = checked_routing_fixture_keypair(
        0x71, iroha_crypto::Algorithm::Ed25519, "contract-state logical key fixture",
    );
    let authority = AccountId::new(key.public_key().clone());
    let mut world = World::with([], [Account::new(authority.clone()).build(&authority)], []);
    world.account_permissions_mut_for_testing().insert(
        authority.clone(),
        std::collections::BTreeSet::from([Permission::from(CanManageSmartContractCode)]),
    );
    let state = Arc::new(CoreState::new_for_testing(
        world, Kura::blank_kura_for_testing(), LiveQueryStore::start_test(),
    ));
    let address = iroha_data_model::smart_contract::ContractAddress::derive(
        state.network_id_ref(), &authority, 1, DataSpaceId::UNIVERSAL,
    ).unwrap();
    let code = kotodama_lang::compiler::Compiler::new().compile_source(
        r#"seiyaku QueryKeys {
            state StateMap<(int, string), bool> Pairs;
            state StateMap<string, bool> Labels;
            view fn ready() authorize(anyone) -> bool { return true; }
        }"#,
    ).expect("compile real schema-bearing artifact");
    let pair_key = r#"["7", "hello @#$ / world, \"quoted\""]"#;
    let label_key = r#"json-"hello @#$ / world, \"quoted\"""#;
    let pair_path = format!("Pairs/{pair_key}");
    let label_path = format!("Labels/{label_key}");
    {
        let mut block = state.block(BlockHeader::new(
            core::num::NonZeroU64::new(1).unwrap(), None, None, 0, 0,
        ));
        let mut transaction = block.transaction();
        let hash = iroha_core::smartcontracts::code::register_code_bytes(
            &authority, DataSpaceId::UNIVERSAL, code, &mut transaction,
        ).expect("register admitted artifact");
        transaction.world.bind_active_contract_subject_for_testing(address.clone(), hash);
        for (base, key_type, key) in [
            ("Pairs", Type::Tuple(vec![Type::Int, Type::String]), pair_key),
            ("Labels", Type::String, label_key),
        ] {
            let suffix = contract_state_stored_map_key_suffix(&key_type, key)
                .expect("canonical typed record key");
            transaction.world.smart_contract_state_mut_for_testing().insert(
                scoped_state_key(&address, &format!("{base}/{suffix}")),
                make_state_record(&Type::Bool, vec![Atom::Bool(true)]),
            );
        }
        transaction.apply();
        block.commit_world_overlay_for_testing().expect("commit query fixture");
    }
    for path in [&pair_path, &label_path] {
        let JsonBody(response) = handle_get_contract_state(state.clone(), NoritoQuery(
            ContractStateQuery {
                contract_address: Some(address.to_string()), path: Some(path.clone()),
                decode: Some("json".to_owned()), ..Default::default()
            },
        )).await.expect("typed logical JSON key is queryable");
        assert_eq!(response.entries.len(), 1);
        assert_eq!(&response.entries[0].path, path);
        assert!(response.entries[0].found);
        assert_eq!(response.entries[0].value_json.as_ref().unwrap().get(), "true");
    }
    let JsonBody(response) = handle_get_contract_state(state.clone(), NoritoQuery(
        ContractStateQuery {
            contract_address: Some(address.to_string()),
            paths: Some(format!("{pair_path}, {label_path}")),
            decode: Some("json".to_owned()), ..Default::default()
        },
    )).await.expect("commas inside JSON keys do not split paths");
    assert_eq!(response.entries.len(), 2);
    assert!(response.entries.iter().all(|entry| entry.found));
    for path in [
        r#"Pairs/["7", "unterminated]"#,
        r#"Pairs/[true, "wrong type"]"#,
        r#"Unknown/json-"unbound @#$ / key""#,
        r#"bad base/json-"key""#,
    ] {
        assert!(handle_get_contract_state(state.clone(), NoritoQuery(ContractStateQuery {
            contract_address: Some(address.to_string()), path: Some(path.to_owned()),
            decode: Some("json".to_owned()), ..Default::default()
        })).await.is_err(), "invalid or unbound logical query must reject: {path}");
    }
    for decode in [None, Some("json".to_owned())] {
        assert!(handle_get_contract_state(state.clone(), NoritoQuery(ContractStateQuery {
            contract_address: Some(address.to_string()), prefix: Some(label_path.clone()),
            decode, ..Default::default()
        })).await.is_err(), "prefix selection still requires a physical StatePath");
    }
}
