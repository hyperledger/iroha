//! Strict JSON coverage for native conditional escrow instructions.

use core::num::NonZeroU32;

use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::{
    account::AccountId,
    asset::AssetDefinitionId,
    escrow::{
        ConditionalEscrowCondition, ConditionalEscrowOracleCondition, ConditionalEscrowPredicate,
        ConditionalEscrowValue, EscrowId,
    },
    isi::{InstructionBox, instruction_wire_id},
};
use iroha_model_base::domain::DomainId;

use super::*;
use crate::{
    decode_instruction_frame, encode_instruction_frame, instruction_from_json,
    instruction_to_json_value,
};

const PREFIX: u16 = 753;

fn account(seed: u8) -> AccountId {
    AccountId::new(
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("escrow test-only key")
            .public_key()
            .clone(),
    )
}

fn fixtures() -> Vec<(&'static str, InstructionBox)> {
    let escrow_id = EscrowId::new(Hash::new(b"bond-retention"));
    let definition = AssetDefinitionId::derive_from_components(
        DomainId::try_new("bonds", "universal").expect("escrow test domain"),
        "cash".parse().expect("escrow test asset"),
    );
    vec![
        (
            "OpenConditionalEscrow",
            OpenConditionalEscrow::with_evidence_hashes(
                escrow_id,
                definition,
                account(0x42),
                100_u32,
                vec![ConditionalEscrowCondition::Oracle(
                    ConditionalEscrowOracleCondition {
                        id: "coupon_paid".parse().expect("condition id"),
                        attestor: account(0x43),
                        predicate: ConditionalEscrowPredicate::Equals(
                            ConditionalEscrowValue::Bool(true),
                        ),
                        sequence: NonZeroU32::new(1).expect("sequence"),
                    },
                )],
                1_800_000_000_000,
                vec![Hash::new(b"term-sheet")],
            )
            .into(),
        ),
        (
            "AttestEscrowCondition",
            AttestEscrowCondition::new(
                escrow_id,
                "coupon_paid".parse().expect("condition id"),
                ConditionalEscrowValue::Bool(true),
                Some(Hash::new(b"payment-evidence")),
            )
            .into(),
        ),
        (
            "ExpireConditionalEscrow",
            ExpireConditionalEscrow::new(escrow_id).into(),
        ),
    ]
}

fn source(value: &Value) -> String {
    json::to_json(value).expect("escrow test JSON")
}

#[test]
fn conditional_escrow_envelopes_roundtrip_through_json_and_frames() {
    for (name, native) in fixtures() {
        assert!(is_conditional_escrow_instruction(&native), "{name}");
        assert!(instruction_wire_id(&native).is_some(), "{name} wire ID");
        let value = instruction_to_json_value(&native).expect("canonical escrow JSON");
        assert!(value.get(name).is_some(), "{name} envelope");
        let text = source(&value);
        assert_eq!(instruction_from_json(&text).expect("parse"), native);
        let frame = encode_instruction_frame(&text, PREFIX).expect("frame");
        let decoded: Value =
            json::from_json(&decode_instruction_frame(&frame, PREFIX).expect("decode"))
                .expect("decoded JSON");
        assert_eq!(decoded, value);
    }
}

#[test]
fn conditional_escrow_json_rejects_missing_extra_and_alias_fields() {
    for (name, native) in fixtures() {
        let valid = instruction_to_json_value(&native).expect("render");
        let mut extra = valid.clone();
        extra
            .as_object_mut()
            .expect("envelope")
            .insert("legacy".to_owned(), Value::Null);
        assert!(instruction_from_json(&source(&extra)).is_err(), "{name}");
        let mut payload_extra = valid.clone();
        payload_extra
            .as_object_mut()
            .expect("envelope")
            .get_mut(name)
            .expect("payload")
            .as_object_mut()
            .expect("payload object")
            .insert("legacy".to_owned(), Value::Null);
        assert!(
            instruction_from_json(&source(&payload_extra)).is_err(),
            "{name}"
        );
        let mut missing = valid.clone();
        let payload = missing
            .as_object_mut()
            .expect("envelope")
            .get_mut(name)
            .expect("payload")
            .as_object_mut()
            .expect("payload object");
        let last = payload.keys().last().expect("field").clone();
        payload.remove(&last);
        assert!(instruction_from_json(&source(&missing)).is_err(), "{name}");
    }
}
