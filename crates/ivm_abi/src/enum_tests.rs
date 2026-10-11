//! Ordinary-enum schemas stay nominal and distinct across every ABI boundary.
use iroha_data_model::smart_contract::manifest::{
    ContractEnumTypeDescriptorV1, ContractEnumVariantDescriptorV1,
};

pub(crate) fn descriptor() -> ContractEnumTypeDescriptorV1 {
    ContractEnumTypeDescriptorV1 {
        identity: "Demo::Status".into(),
        variants: vec![
            ContractEnumVariantDescriptorV1 {
                name: "Pending".into(),
                code: 1,
            },
            ContractEnumVariantDescriptorV1 {
                name: "Done".into(),
                code: 7,
            },
        ],
    }
}

#[test]
fn ordinary_enum_public_arguments_accept_exact_names_only() {
    use crate::{arguments::argument_record_from_json_detailed, entrypoint::*};
    use iroha_primitives::json::Json;
    let schema = EntrypointArgumentSchemaV1 {
        fields: vec![EntrypointArgumentFieldV1 {
            name: "status".into(),
            ty: EntrypointValueTypeV1 {
                nodes: vec![EntrypointValueTypeNodeV1::Enum(descriptor())],
            },
        }],
    };
    let value = Json::from(norito::json!({"status": "Done"}));
    let record = argument_record_from_json_detailed(&schema, &value).unwrap();
    assert_eq!(record.atoms, vec![EntrypointValueAtomV1::EnumCode(7)]);
    assert!(schema.validate_atoms(&record.atoms));
    assert!(!schema.validate_atoms(&[EntrypointValueAtomV1::ErrorCode(7)]));
    for invalid in [
        norito::json!(7),
        norito::json!("7"),
        norito::json!("done"),
        norito::json!("Demo::Status::Done"),
        norito::json!("Missing"),
        norito::json!(null),
    ] {
        let payload = Json::from(norito::json::object([("status", invalid)]).unwrap());
        let error = argument_record_from_json_detailed(&schema, &payload).unwrap_err();
        assert_eq!(error.path, "status");
        assert!(error.expected.contains("enum variant name"), "{error}");
    }
}

#[test]
fn ordinary_enum_call_schema_roundtrips_without_error_equivalence() {
    use crate::{
        call::{CallSchemaV1, CallTypeNodeV1},
        entrypoint::*,
    };
    let public = EntrypointValueTypeV1 {
        nodes: vec![EntrypointValueTypeNodeV1::Enum(descriptor())],
    };
    let call = CallSchemaV1::from_entrypoint_type(&public).unwrap();
    assert_eq!(call.nodes, vec![CallTypeNodeV1::Enum(descriptor())]);
    assert_eq!(call.word_count(), Some(1));
    assert!(call.matches_entrypoint_type(&public));
    let encoded = norito::encode_canonical(&call).unwrap();
    assert_eq!(
        norito::decode_canonical::<CallSchemaV1>(&encoded).unwrap(),
        call
    );
    let other = CallSchemaV1 {
        nodes: vec![CallTypeNodeV1::Error(crate::error_types::list_error_type())],
    };
    assert!(!other.matches_entrypoint_type(&public));
    let mut invalid = descriptor();
    invalid.variants[0].code = 0;
    let invalid = CallSchemaV1 {
        nodes: vec![CallTypeNodeV1::Enum(invalid)],
    };
    assert!(invalid.analyze().is_none());
    let bytes = norito::encode_canonical(&invalid).unwrap();
    assert!(norito::decode_canonical::<CallSchemaV1>(&bytes).is_err());
}

#[test]
fn ordinary_enum_state_atoms_validate_codes_and_nominal_schema() {
    use crate::{metadata::EmbeddedStateType, state_value::*};
    let schema = StateValueSchemaV1 {
        nodes: vec![StateValueNodeV1::Enum(descriptor())],
    };
    assert!(schema.validate());
    assert_eq!(schema.word_kinds(), Some(vec![StateValueWordKindV1::Enum]));
    let frame = norito::encode_canonical(&schema).unwrap();
    assert_eq!(
        norito::decode_canonical::<StateValueSchemaV1>(&frame).unwrap(),
        schema
    );
    let atoms = vec![StateValueAtomV1::EnumCode(7)];
    assert!(schema.validate_atoms(&atoms));
    for invalid in [
        StateValueAtomV1::ErrorCode(7),
        StateValueAtomV1::EnumCode(0),
        StateValueAtomV1::EnumCode(2),
    ] {
        assert!(!schema.validate_atoms(&[invalid]));
    }
    let record = StateValueRecordV1 {
        schema_hash: state_value_schema_hash_v1(&frame),
        atoms,
    };
    let bytes = norito::encode_canonical(&record).unwrap();
    assert_eq!(
        norito::decode_canonical::<StateValueRecordV1>(&bytes).unwrap(),
        record
    );
    let native = EmbeddedStateType::Enum(descriptor());
    assert_eq!(native.wire_tag(), 23);
    let encoded = norito::encode_canonical(&native).unwrap();
    assert_eq!(
        norito::decode_canonical::<EmbeddedStateType>(&encoded).unwrap(),
        native
    );
    assert_ne!(
        native,
        EmbeddedStateType::Error(crate::error_types::list_error_type())
    );
    let nested = StateValueSchemaV1 {
        nodes: vec![
            StateValueNodeV1::Option,
            StateValueNodeV1::Enum(descriptor()),
        ],
    };
    assert!(nested.validate_atoms(&[StateValueAtomV1::Tag(false)]));
    assert!(nested.validate_atoms(&[StateValueAtomV1::Tag(true), StateValueAtomV1::EnumCode(1)]));
    assert!(!nested.validate_atoms(&[StateValueAtomV1::Tag(false), StateValueAtomV1::EnumCode(1)]));
}
