use crate::common;
use ivm::{self, Memory, PointerType};
fn build_tlv_with_version(ty: PointerType, ver: u8, payload: &[u8]) -> Vec<u8> {
    let payload = common::payload_for_type(ty, payload);
    let mut tlv = Vec::with_capacity(7 + payload.len() + 32);
    tlv.extend_from_slice(&(ty as u16).to_be_bytes());
    tlv.push(ver);
    tlv.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    tlv.extend_from_slice(payload.as_ref());
    let h: [u8; 32] = iroha_crypto::Hash::new(&payload).into();
    tlv.extend_from_slice(&h);
    tlv
}
#[test]
fn validate_tlv_rejects_wrong_version() {
    // Prepare memory and preload a TLV with version != 1
    let mut mem = Memory::new();
    let payload = br#"{"k":"v"}"#;
    let tlv = build_tlv_with_version(PointerType::Json, 2, payload);
    mem.preload_input(0, &tlv).expect("preload input");
    let ptr = Memory::INPUT_START;
    let res = mem.validate_tlv(ptr);
    assert!(matches!(res, Err(ivm::VMError::NoritoInvalid)));
}
