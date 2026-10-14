//! Verify durable map path hashing and pointer Norito encoding helpers align with CoreHost.
use crate::common;
use iroha_crypto::Hash as IrohaHash;
use iroha_data_model::prelude::*;
use iroha_model_base::name::Name;
use ivm::{CoreHost, PointerType, pointer_abi::validate_tlv_bytes};
use ivm_abi::state_value::StateValueKindV1;
use norito::to_bytes;
fn encode_pointer_tlv(ty: PointerType, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 1 + 4 + payload.len() + IrohaHash::LENGTH);
    out.extend_from_slice(&(ty as u16).to_be_bytes());
    out.push(1);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload.as_ref());
    let hash: [u8; 32] = IrohaHash::new(payload).into();
    out.extend_from_slice(&hash);
    out
}
fn parse_account_id_literal(id: &str) -> AccountId {
    AccountId::parse_encoded(id).expect("account literal must be canonical I105")
}
fn account_pointer_tlvs(id: &str) -> (Vec<u8>, Vec<u8>) {
    let account = parse_account_id_literal(id);
    let payload = to_bytes(&account).expect("encode account id");
    let raw = encode_pointer_tlv(PointerType::AccountId, &payload);
    let norito = encode_pointer_tlv(PointerType::NoritoBytes, &raw);
    (raw, norito)
}
fn map_path(base: &str, pointer_payload: &[u8]) -> String {
    format!("{base}/{}", hex::encode(pointer_payload))
}
#[test]
fn durable_map_account_id_path_is_reversible_canonical_hex() {
    const OWNER_ID: &str = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV";
    let (raw_ptr, _norito_ptr) = account_pointer_tlvs(OWNER_ID);
    let path = map_path("balances", &raw_ptr);
    assert!(path.starts_with("balances/"));
    assert_eq!(path, format!("balances/{}", hex::encode(raw_ptr)));
    let mut host = CoreHost::new();
    host.insert_state_value(&path, common::encode_int_state_value(5));
    let stored = host
        .state_bytes(&path)
        .expect("stored value should be present");
    assert_eq!(stored, common::encode_int_state_value(5));
}
#[test]
fn durable_map_name_value_roundtrip() {
    let mut host = CoreHost::new();
    let name: Name = "wonder".parse().expect("valid name");
    let payload = to_bytes(&name).expect("encode name");
    host.insert_state_value(
        "aliases/42",
        common::encode_pointer_state_value(StateValueKindV1::Name, PointerType::Name, &payload),
    );
    let stored = host.state_bytes("aliases/42").expect("name pointer stored");
    let envelope = common::decode_pointer_state_value(&stored, StateValueKindV1::Name);
    let decoded = validate_tlv_bytes(&envelope).expect("stored Name envelope");
    assert_eq!(decoded.type_id, PointerType::Name);
    assert_eq!(decoded.payload, payload);
}
#[test]
fn durable_map_account_id_value_roundtrip() {
    const OWNER_ID: &str = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV";
    let (raw_ptr, _norito_ptr) = account_pointer_tlvs(OWNER_ID);
    let raw = validate_tlv_bytes(&raw_ptr).expect("AccountId pointer envelope");
    let mut host = CoreHost::new();
    host.insert_state_value(
        "owners/7",
        common::encode_pointer_state_value(
            StateValueKindV1::AccountId,
            PointerType::AccountId,
            raw.payload,
        ),
    );
    let stored = host
        .state_bytes("owners/7")
        .expect("account pointer stored");
    let envelope = common::decode_pointer_state_value(&stored, StateValueKindV1::AccountId);
    assert_eq!(envelope, raw_ptr);
}
