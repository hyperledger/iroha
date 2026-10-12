//! Owner-qualified settlement identity and first-release codec controls.

use super::*;
use iroha_crypto::{Algorithm, KeyPair};

fn owner(seed: u8) -> AccountId {
    AccountId::new(
        KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    )
}

fn identity(seed: u8) -> SettlementId {
    SettlementId::new(owner(seed), "invoice_250000".parse().unwrap())
}

#[test]
fn settlement_id_binds_owner_and_reference_in_every_codec() {
    let id = identity(71);
    assert_eq!(id.owner(), &owner(71));
    assert_eq!(id.reference().as_ref(), "invoice_250000");
    let encoded = norito::encode_canonical(&id).unwrap();
    assert_eq!(
        norito::decode_canonical::<SettlementId>(&encoded).unwrap(),
        id
    );
    let json = norito::json::to_json(&id).unwrap();
    assert!(json.contains("\"owner\""));
    assert!(json.contains("\"reference\""));
    assert_eq!(norito::json::from_str::<SettlementId>(&json).unwrap(), id);
    assert_eq!(id.to_string(), format!("invoice_250000${}", owner(71)));
    assert_eq!(id.to_string().parse::<SettlementId>().unwrap(), id);
}

#[test]
fn equal_references_have_distinct_owner_namespaces() {
    let first = identity(71);
    let second = identity(72);
    assert_ne!(first, second);
    assert_eq!(first.reference(), second.reference());
    assert_ne!(
        norito::encode_canonical(&first).unwrap(),
        norito::encode_canonical(&second).unwrap(),
    );
    let receipts = BTreeMap::from([(first.clone(), 1_u64), (second.clone(), 2)]);
    assert_eq!(receipts.get(&first), Some(&1));
    assert_eq!(receipts.get(&second), Some(&2));
    let json = norito::json::to_json(&receipts).unwrap();
    assert_eq!(
        norito::json::from_str::<BTreeMap<SettlementId, u64>>(&json).unwrap(),
        receipts,
    );
}

#[test]
fn settlement_id_rejects_unqualified_and_ambiguous_text() {
    for text in [
        String::new(),
        "invoice_250000".to_owned(),
        format!("${}", owner(71)),
        "invoice_250000$".to_owned(),
        format!("invoice_250000${}$extra", owner(71)),
        "invoice_250000$not-an-account".to_owned(),
    ] {
        assert!(text.parse::<SettlementId>().is_err(), "{text}");
    }
}

#[test]
fn settlement_id_json_requires_one_complete_structured_identity() {
    let id = identity(71);
    for json in [
        "\"invoice_250000\"".to_owned(),
        norito::json::to_json(&id.to_string()).unwrap(),
        "{\"reference\":\"invoice_250000\"}".to_owned(),
        format!("{{\"owner\":\"{}\"}}", owner(71)),
        format!(
            "{{\"owner\":\"{}\",\"reference\":\"invoice_250000\",\"name\":\"invoice_250000\"}}",
            owner(71),
        ),
    ] {
        assert!(
            norito::json::from_str::<SettlementId>(&json).is_err(),
            "{json}"
        );
    }
}

#[test]
fn settlement_id_rejects_name_only_wire_with_claimed_identity_schema() {
    let id = identity(71);
    let mut frame = norito::encode_canonical(id.reference()).unwrap();
    frame[6..22].copy_from_slice(&norito::schema::identity::frame_hash::<SettlementId>());
    assert!(norito::decode_canonical::<SettlementId>(&frame).is_err());
}
