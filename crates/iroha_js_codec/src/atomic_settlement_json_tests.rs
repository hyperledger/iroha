//! Shared JS settlement JSON preserves the complete atomic consent preimage.
use super::*;
use iroha_crypto::{Algorithm, HashOf, KeyPair};
use iroha_data_model::{
    NetworkId,
    asset::{AssetBalanceScope, AssetId},
    block::BlockHeader,
    isi::{AtomicSettlementMovement, AtomicSettlementMovements, SettleAtomic},
};
use iroha_model_base::{metadata::Metadata, topology::DataSpaceId};
use std::num::NonZeroU64;

fn settlement<const N: usize>(variants: [(&str, json::Value); N]) -> json::Value {
    let variants = variants
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect();
    json::Value::Object(
        [("Settlement".to_owned(), json::Value::Object(variants))]
            .into_iter()
            .collect(),
    )
}

fn atomic() -> SettleAtomic {
    let account = |seed| {
        AccountId::new(
            KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
                .expect("fixture key")
                .public_key()
                .clone(),
        )
    };
    let definition = AssetDefinitionId::from_uuid_bytes([
        1, 2, 3, 4, 5, 6, 0x47, 8, 0x89, 10, 11, 12, 13, 14, 15, 16,
    ])
    .expect("UUIDv4 fixture");
    let movements = (1..=3)
        .map(|id| AtomicSettlementMovement {
            source: AssetId::with_scope(
                definition.clone(),
                account(1),
                AssetBalanceScope::Dataspace(DataSpaceId::new(id)),
            ),
            recipient: account(2),
            quantity: Quantity::from(id + 42),
        })
        .collect::<Vec<_>>();
    SettleAtomic::new(
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
            b"atomic-js-fixture",
        ))),
        iroha_data_model::isi::SettlementId::new(
            account(1),
            "atomic_js".parse().expect("reference"),
        ),
        AtomicSettlementMovements::try_from(movements).expect("canonical"),
        NonZeroU64::new(500).expect("expiry"),
        Metadata::default(),
    )
}

#[test]
fn atomic_json_roundtrip_preserves_scope_intent_and_binary_instruction() {
    let value = atomic();
    let input = settlement([("Atomic", json::to_value(&value).expect("JSON"))]);
    let instruction = value_to_instruction(input.clone()).expect("parse atomic");
    assert_eq!(
        instruction_to_json_value(&instruction).expect("render atomic"),
        input
    );
    let bytes = norito::to_bytes(&instruction).expect("Norito instruction");
    let decoded = decode_instruction_aligned(&bytes).expect("decode instruction");
    let Some(SettlementInstructionBox::Atomic(decoded)) =
        decoded.as_any().downcast_ref::<SettlementInstructionBox>()
    else {
        panic!("atomic dispatch lost");
    };
    assert_eq!(decoded, &value);
    assert_eq!(
        decoded.intent_hash().expect("decoded intent"),
        value.intent_hash().expect("original intent")
    );
}

#[test]
fn atomic_json_rejects_missing_or_unknown_fields_and_variant_substitutions() {
    let payload = json::to_value(&atomic()).expect("JSON");
    let mut bare_id = payload.clone();
    bare_id.as_object_mut().expect("object").insert(
        "settlement_id".into(),
        json::Value::String("atomic_js".into()),
    );
    assert!(value_to_instruction(settlement([("Atomic", bare_id)])).is_err());
    for field in [
        "network_id",
        "settlement_id",
        "movements",
        "expires_at_height",
        "metadata",
    ] {
        let mut missing = payload.clone();
        assert!(
            missing
                .as_object_mut()
                .expect("object")
                .remove(field)
                .is_some()
        );
        assert!(value_to_instruction(settlement([("Atomic", missing)])).is_err());
    }
    let mut extra = payload.clone();
    extra
        .as_object_mut()
        .expect("object")
        .insert("unexpected".into(), json::Value::Bool(true));
    assert!(value_to_instruction(settlement([("Atomic", extra)])).is_err());
    assert!(
        value_to_instruction(settlement([
            ("Atomic", payload.clone()),
            ("Dvp", payload.clone())
        ]))
        .is_err()
    );
    assert!(value_to_instruction(settlement([("SettleAtomic", payload)])).is_err());
}

#[test]
fn atomic_json_rejects_noncanonical_quantities_and_reordered_movements() {
    let payload = json::to_value(&atomic()).expect("JSON");
    for amount in [
        json::Value::String("0".into()),
        json::Value::String("-1".into()),
        json::Value::String("043".into()),
        json::Value::Number(json::Number::from(43_u64)),
    ] {
        let mut changed = payload.clone();
        let movements = changed
            .as_object_mut()
            .expect("object")
            .get_mut("movements")
            .expect("movements")
            .as_array_mut()
            .expect("array");
        movements[1]
            .as_object_mut()
            .expect("movement")
            .insert("quantity".into(), amount);
        assert!(value_to_instruction(settlement([("Atomic", changed)])).is_err());
    }
    let mut changed = payload;
    changed
        .as_object_mut()
        .expect("object")
        .get_mut("movements")
        .expect("movements")
        .as_array_mut()
        .expect("array")
        .swap(0, 1);
    assert!(value_to_instruction(settlement([("Atomic", changed)])).is_err());
}
