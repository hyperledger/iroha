//! Strict JSON coverage for the boxed repo lifecycle and its governance terms.

use base64::Engine as _;
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    account::AccountId,
    asset::AssetDefinitionId,
    isi::{InstructionBox, instruction_wire_id},
    repo::{RepoCashLeg, RepoCollateralLeg, RepoGovernance},
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
            .expect("repo test-only key")
            .public_key()
            .clone(),
    )
}

fn definition(name: &str) -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        DomainId::try_new("bonds", "universal").expect("repo test domain"),
        name.parse().expect("repo test asset name"),
    )
}

fn initiate(allow_early_repayment: bool) -> RepoIsi {
    RepoIsi::new(
        "bond_repo".parse().expect("agreement id"),
        account(0x31),
        account(0x32),
        None,
        RepoCashLeg::new(definition("cash"), 1_000_u32),
        RepoCollateralLeg::new(definition("bond"), 1_100_u32),
        250,
        1_735_086_400_000,
        RepoGovernance::new(1_500, 86_400, allow_early_repayment),
    )
}

fn fixtures() -> Vec<InstructionBox> {
    vec![
        RepoInstructionBox::from(initiate(true)).into(),
        RepoInstructionBox::Reverse(ReverseRepoIsi::new(
            "bond_repo".parse().expect("agreement id"),
        ))
        .into(),
        RepoInstructionBox::MarginCall(RepoMarginCallIsi::new(
            "bond_repo".parse().expect("agreement id"),
        ))
        .into(),
    ]
}

fn source(value: &Value) -> String {
    json::to_json(value).expect("repo test JSON")
}

#[test]
fn repo_envelopes_roundtrip_through_json_and_framed_wire() {
    for native in fixtures() {
        assert!(is_repo_instruction(&native));
        assert_eq!(
            instruction_wire_id(&native),
            Some(RepoInstructionBox::WIRE_ID)
        );
        let value = instruction_to_json_value(&native).expect("canonical repo JSON");
        let text = source(&value);
        let parsed = instruction_from_json(&text).expect("repo JSON parses");
        assert_eq!(parsed, native);
        let frame = encode_instruction_frame(&text, PREFIX).expect("repo frame");
        let decoded: Value =
            json::from_json(&decode_instruction_frame(&frame, PREFIX).expect("decode frame"))
                .expect("decoded JSON");
        assert_eq!(decoded, value);
    }
}

#[test]
fn repo_initiate_json_carries_explicit_governance_and_preserves_consent_hashes() {
    let instruction = initiate(true);
    let value = instruction_to_json_value(&RepoInstructionBox::from(instruction.clone()).into())
        .expect("render initiate");
    let governance = value
        .get("Repo")
        .and_then(|repo| repo.get("Initiate"))
        .and_then(|initiate| initiate.get("governance"))
        .expect("governance object");
    // Rendered JSON objects are key-sorted; field order is not significant.
    assert_eq!(
        source(governance),
        r#"{"allow_early_repayment":true,"haircut_bps":1500,"margin_frequency_secs":86400}"#
    );
    let parsed = instruction_from_json(&source(&value)).expect("parse initiate");
    let Some(RepoInstructionBox::Initiate(parsed)) =
        parsed.as_any().downcast_ref::<RepoInstructionBox>()
    else {
        panic!("repo initiate dispatch lost");
    };
    assert_eq!(
        parsed.initiation_intent_hash(),
        instruction.initiation_intent_hash()
    );
    assert_eq!(
        parsed.maturity_intent_hash(),
        instruction.maturity_intent_hash()
    );
    assert_ne!(
        initiate(false).initiation_intent_hash(),
        instruction.initiation_intent_hash()
    );
}

#[test]
fn repo_json_rejects_missing_terms_extra_fields_and_ambiguous_variants() {
    let valid = instruction_to_json_value(&RepoInstructionBox::from(initiate(false)).into())
        .expect("render initiate");
    fn initiate_fields(value: &mut Value) -> &mut json::Map {
        value
            .get_mut("Repo")
            .and_then(|repo| repo.get_mut("Initiate"))
            .and_then(Value::as_object_mut)
            .expect("initiate payload")
    }
    fn governance_fields(value: &mut Value) -> &mut json::Map {
        initiate_fields(value)
            .get_mut("governance")
            .and_then(Value::as_object_mut)
            .expect("governance payload")
    }
    let mut cases = Vec::new();
    let mut missing_term = valid.clone();
    assert!(
        governance_fields(&mut missing_term)
            .remove("allow_early_repayment")
            .is_some()
    );
    cases.push(missing_term);
    let mut stringly = valid.clone();
    governance_fields(&mut stringly).insert(
        "allow_early_repayment".to_owned(),
        Value::String("false".to_owned()),
    );
    cases.push(stringly);
    let mut governance_extra = valid.clone();
    governance_fields(&mut governance_extra).insert("legacy".to_owned(), Value::Null);
    cases.push(governance_extra);
    let mut payload_extra = valid.clone();
    initiate_fields(&mut payload_extra).insert("legacy".to_owned(), Value::Null);
    cases.push(payload_extra);
    let mut missing_rate = valid.clone();
    assert!(
        initiate_fields(&mut missing_rate)
            .remove("rate_bps")
            .is_some()
    );
    cases.push(missing_rate);
    let mut envelope_extra = valid.clone();
    envelope_extra
        .as_object_mut()
        .expect("envelope")
        .insert("legacy".to_owned(), Value::Null);
    cases.push(envelope_extra);
    let initiate_payload = valid
        .get("Repo")
        .and_then(|repo| repo.get("Initiate"))
        .cloned()
        .expect("initiate payload");
    let mut renamed = json::Map::new();
    renamed.insert("Settle".to_owned(), initiate_payload.clone());
    let mut two_variants = json::Map::new();
    two_variants.insert("Initiate".to_owned(), initiate_payload);
    two_variants.insert(
        "MarginCall".to_owned(),
        json::from_json(r#"{"agreement_id":"bond_repo"}"#).expect("margin payload"),
    );
    for variants in [renamed, two_variants, json::Map::new()] {
        let mut envelope = json::Map::new();
        envelope.insert("Repo".to_owned(), Value::Object(variants));
        cases.push(Value::Object(envelope));
    }
    cases.push(json::from_json(r#"{"Repo":[]}"#).expect("array payload"));
    for malformed in cases {
        assert_ne!(malformed, valid);
        let text = source(&malformed);
        assert!(
            instruction_from_json(&text).is_err(),
            "malformed repo JSON must be rejected: {text}"
        );
    }
}

#[test]
fn repo_requires_its_envelope_instead_of_generic_base64() {
    let native: InstructionBox = RepoInstructionBox::from(initiate(true)).into();
    let bytes = norito::encode_canonical(&native).expect("canonical instruction");
    let base64 = json::to_json(&Value::String(
        base64::engine::general_purpose::STANDARD.encode(bytes),
    ))
    .expect("base64 JSON");
    assert!(instruction_from_json(&base64).is_err());
}
