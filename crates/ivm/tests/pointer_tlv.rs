use crate::common;
use iroha_crypto::{Hash, PublicKey};
use ivm::{Memory, PointerType};
fn valid_account_id_literal() -> Vec<u8> {
    let public_key: PublicKey =
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
            .parse()
            .expect("valid public key");
    ivm::mock_wsv::AccountId::new(public_key)
        .to_string()
        .into_bytes()
}
fn make_tlv(type_id: u16, version: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(7 + payload.len() + 32);
    out.extend_from_slice(&type_id.to_be_bytes());
    out.push(version);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload.as_ref());
    let h: [u8; 32] = Hash::new(payload).into();
    out.extend_from_slice(&h);
    out
}
#[test]
fn validate_known_types_ok() {
    let valid_account = valid_account_id_literal();
    let cases: Vec<(PointerType, &[u8])> = vec![
        (PointerType::AccountId, valid_account.as_slice()),
        (
            PointerType::AssetDefinitionId,
            b"62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
        ),
        (PointerType::Name, b"cursor"),
        (PointerType::Json, br#"{"q":1}"#),
        (PointerType::NftId, b"rose$wonderland"),
    ];
    for (pty, raw) in cases {
        let payload = common::payload_for_type(pty, raw);
        let tlv = make_tlv(pty as u16, 1, &payload);
        let mut mem = Memory::new();
        mem.preload_input(0, &tlv).expect("preload input");
        let v = mem.validate_tlv(Memory::INPUT_START).expect("valid tlv");
        assert_eq!(v.type_id as u16, pty as u16);
        assert_eq!(v.version, 1);
        assert_eq!(v.payload, payload.as_slice());
    }
}
#[test]
fn reject_hash_mismatch() {
    let valid_account = valid_account_id_literal();
    let payload = common::payload_for_type(PointerType::AccountId, &valid_account);
    let mut tlv = make_tlv(PointerType::AccountId as u16, 1, &payload);
    // Flip one byte in the stored hash
    let off = 7 + payload.len();
    tlv[off] ^= 0xFF;
    let mut mem = Memory::new();
    mem.preload_input(0, &tlv).expect("preload input");
    assert!(matches!(
        mem.validate_tlv(Memory::INPUT_START),
        Err(ivm::VMError::NoritoInvalid)
    ));
}
#[test]
fn reject_oob_length() {
    // Construct a TLV that claims a very large payload length
    let _payload = b"x";
    let mut hdr = Vec::new();
    hdr.extend_from_slice(&(PointerType::AccountId as u16).to_be_bytes());
    hdr.push(1);
    hdr.extend_from_slice(&(u32::MAX).to_be_bytes());
    // No payload/hash appended to keep it small in test; bounds check should fail first
    let mut mem = Memory::new();
    mem.preload_input(0, &hdr).expect("preload input");
    assert!(matches!(
        mem.validate_tlv(Memory::INPUT_START),
        Err(ivm::VMError::NoritoInvalid)
    ));
}
#[test]
fn reject_unknown_type() {
    let tlv = make_tlv(0xFFFF, 1, b"x");
    let mut mem = Memory::new();
    mem.preload_input(0, &tlv).expect("preload input");
    assert!(matches!(
        mem.validate_tlv(Memory::INPUT_START),
        Err(ivm::VMError::NoritoInvalid)
    ));
}
#[test]
fn reject_wrong_version() {
    let payload = common::payload_for_type(PointerType::Name, b"cursor");
    let tlv = make_tlv(PointerType::Name as u16, 2, &payload);
    let mut mem = Memory::new();
    mem.preload_input(0, &tlv).expect("preload input");
    assert!(matches!(
        mem.validate_tlv(Memory::INPUT_START),
        Err(ivm::VMError::NoritoInvalid)
    ));
}
#[test]
fn reject_wrong_region() {
    let payload = common::payload_for_type(PointerType::Name, b"cursor");
    let tlv = make_tlv(PointerType::Name as u16, 1, &payload);
    let mut mem = Memory::new();
    // Place TLV into HEAP region (writes allowed) but validator should enforce INPUT-only
    let heap_addr = Memory::HEAP_START;
    mem.store_bytes(heap_addr, &tlv).unwrap();
    assert!(matches!(
        mem.validate_tlv(heap_addr),
        Err(ivm::VMError::NoritoInvalid)
    ));
}
