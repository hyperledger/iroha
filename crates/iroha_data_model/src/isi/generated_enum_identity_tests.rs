//! Complete captured frames and tag coverage for generated instruction enums.

use std::{collections::BTreeMap, fmt::Debug};

use norito::{
    NoritoDeserialize, NoritoSerialize,
    json::{self, JsonDeserialize, JsonSerialize, Value},
};

use super::{
    GrantType, InstructionType, RemoveKeyValueType, RevokeType, SetKeyValueType,
    mint_burn::{BurnType, MintType},
    register::{RegisterType, UnregisterType},
    settlement::{SettlementAtomicity, SettlementExecutionOrder},
    transfer::TransferType,
};

use crate::fixture_json;

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut encoded = String::new();
    for byte in bytes {
        write!(encoded, "{byte:02x}").expect("String formatting");
    }
    encoded
}

fn frame<T>(value: &T) -> String
where
    T: NoritoSerialize + for<'de> NoritoDeserialize<'de> + Debug + PartialEq,
{
    let bytes = norito::to_bytes(value).expect("encode generated instruction enum");
    let decoded: T = norito::decode_from_bytes(&bytes).expect("decode generated instruction enum");
    assert_eq!(&decoded, value);
    hex(&bytes)
}

fn record<T>(variant_count: usize) -> Value
where
    T: NoritoSerialize
        + for<'de> NoritoDeserialize<'de>
        + norito::NoritoSchema
        + JsonSerialize
        + JsonDeserialize
        + TryFrom<u8>
        + Copy
        + Debug
        + PartialEq,
{
    let identity_hash = norito::schema::identity::frame_hash::<T>();
    assert_eq!(norito::schema::identity::frame_hash::<T>(), identity_hash);
    assert_eq!(norito::schema::identity::frame_hash::<T>(), identity_hash);
    assert_eq!(T::frame_name(), T::nominal_name());
    let mut cases = Vec::new();
    for tag in 0..=u8::MAX {
        let result = T::try_from(tag);
        if usize::from(tag) >= variant_count {
            assert!(result.is_err(), "unexpected valid tag {tag}");
            continue;
        }
        let value = result.unwrap_or_else(|_| panic!("missing instruction tag {tag}"));
        let json = json::to_value(&value).expect("generated instruction JSON");
        let decoded: T = json::from_value(json.clone()).expect("decode generated instruction JSON");
        assert_eq!(decoded, value);
        cases.push(
            json::object([
                ("tag", Value::from(tag)),
                ("json", json),
                ("frame", Value::String(frame(&value))),
                ("vector_frame", Value::String(frame(&vec![value]))),
                ("option_frame", Value::String(frame(&Some(value)))),
                (
                    "map_frame",
                    Value::String(frame(&BTreeMap::from([(7_u8, value)]))),
                ),
            ])
            .expect("instruction enum case"),
        );
    }
    assert!(json::from_value::<T>(Value::String("UnknownInstructionVariant".into())).is_err());
    json::object([
        ("nominal", Value::String(T::nominal_name())),
        (
            "serialize_hash",
            Value::String(hex(&norito::schema::identity::frame_hash::<T>())),
        ),
        (
            "deserialize_hash",
            Value::String(hex(&norito::schema::identity::frame_hash::<T>())),
        ),
        ("cases", Value::Array(cases)),
    ])
    .expect("instruction enum type")
}

#[test]
fn generated_mint_burn_enums_preserve_captured_frames() {
    let rows = vec![record::<BurnType>(2), record::<MintType>(2)];
    let captured: Value = json::from_str(include_str!(
        "../../tests/fixtures/instruction_mint_burn_generated_identity_frames.json"
    ))
    .expect("immutable mint/burn enum capture");
    fixture_json::assert_json_matches(&captured, &Value::Array(rows), "mint/burn enum identities");
}

fn generated_instruction_enums() -> Vec<Value> {
    vec![
        record::<GrantType>(3),
        record::<InstructionType>(14),
        record::<RemoveKeyValueType>(5),
        record::<RevokeType>(3),
        record::<SetKeyValueType>(5),
        record::<RegisterType>(7),
        record::<UnregisterType>(7),
        record::<SettlementAtomicity>(1),
        record::<SettlementExecutionOrder>(2),
        record::<TransferType>(4),
    ]
}

#[test]
fn generated_instruction_enums_preserve_captured_frames() {
    let rows = generated_instruction_enums();
    assert_eq!(rows.len(), 10);
    assert_eq!(
        rows.iter()
            .map(|row| row.get("cases").unwrap().as_array().unwrap().len())
            .sum::<usize>(),
        51
    );
    let captured: Value = json::from_str(include_str!(
        "../../tests/fixtures/instruction_enum_generated_identity_frames.json"
    ))
    .expect("immutable generated instruction enum capture");
    fixture_json::assert_json_matches(
        &captured,
        &Value::Array(rows),
        "instruction enum identities",
    );
}
