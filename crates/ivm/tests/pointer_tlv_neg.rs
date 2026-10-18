//! Negative tests for Pointer‑ABI TLV validation.
use crate::common;
use iroha_crypto::PublicKey;
use ivm::{IVM, PointerType, ProgramMetadata};
fn valid_account_id_literal() -> Vec<u8> {
    let public_key: PublicKey =
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
            .parse()
            .expect("valid public key");
    ivm::mock_wsv::AccountId::new(public_key)
        .to_string()
        .into_bytes()
}
fn build_tlv(type_id: u16, version: u8, payload: &[u8], corrupt_hash: bool) -> Vec<u8> {
    use iroha_crypto::Hash;
    let mut v = Vec::with_capacity(2 + 1 + 4 + payload.len() + 32);
    v.extend_from_slice(&type_id.to_be_bytes());
    v.push(version);
    v.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    v.extend_from_slice(payload.as_ref());
    let h = Hash::new(payload);
    let mut hb = h.as_ref().to_vec();
    if corrupt_hash {
        hb[0] ^= 0xFF;
    }
    v.extend_from_slice(&hb);
    v
}
#[test]
fn tlv_wrong_hash_is_rejected() {
    let mut vm = IVM::new(0);
    // Load minimal header to init memory/code
    let meta = ProgramMetadata::default().encode();
    vm.load_program(&meta).unwrap();
    // Build a valid payload and a TLV with a corrupted hash
    let valid_account = valid_account_id_literal();
    let payload = common::payload_for_type(PointerType::AccountId, &valid_account);
    let tlv = build_tlv(PointerType::AccountId as u16, 1, &payload, true);
    vm.memory.preload_input(0, &tlv).expect("preload input");
    let addr = ivm::Memory::INPUT_START;
    let err = vm.memory.validate_tlv(addr).unwrap_err();
    assert!(matches!(err, ivm::VMError::NoritoInvalid));
}
#[test]
fn tlv_unknown_type_is_rejected() {
    let mut vm = IVM::new(0);
    let meta = ProgramMetadata::default().encode();
    vm.load_program(&meta).unwrap();
    let payload = b"62Fk4FPcMuLvW5QjDGNF2a4jAmjM";
    let tlv = build_tlv(0xDEAD, 1, payload, false);
    vm.memory.preload_input(0, &tlv).expect("preload input");
    let addr = ivm::Memory::INPUT_START;
    let err = vm.memory.validate_tlv(addr).unwrap_err();
    assert!(matches!(err, ivm::VMError::NoritoInvalid));
}
#[test]
fn tlv_wrong_version_is_rejected() {
    let mut vm = IVM::new(0);
    let meta = ProgramMetadata::default().encode();
    vm.load_program(&meta).unwrap();
    let payload = common::payload_for_type(PointerType::Name, b"cursor");
    let tlv = build_tlv(PointerType::Name as u16, 2, &payload, false);
    vm.memory.preload_input(0, &tlv).expect("preload input");
    let addr = ivm::Memory::INPUT_START;
    let err = vm.memory.validate_tlv(addr).unwrap_err();
    assert!(matches!(err, ivm::VMError::NoritoInvalid));
}
#[test]
fn tlv_out_of_bounds_is_rejected() {
    let mut vm = IVM::new(0);
    let meta = ProgramMetadata::default().encode();
    vm.load_program(&meta).unwrap();
    // Create a TLV that claims a payload larger than the INPUT region.
    let payload = vec![0u8; ivm::Memory::INPUT_SIZE as usize];
    let tlv = build_tlv(0x0004, 1, &payload, false);
    // Place it such that header fits but payload+hash exceed INPUT end.
    let hdr_len = 2 + 1 + 4;
    let pos = ivm::Memory::INPUT_SIZE - (hdr_len as u64);
    vm.memory
        .preload_input(pos, &tlv[..hdr_len])
        .expect("preload input");
    let addr = ivm::Memory::INPUT_START + pos;
    let err = vm.memory.validate_tlv(addr).unwrap_err();
    assert!(matches!(err, ivm::VMError::NoritoInvalid));
}
#[test]
fn tlv_pointer_overflow_is_rejected() {
    let mut vm = IVM::new(0);
    let meta = ProgramMetadata::default().encode();
    vm.load_program(&meta).unwrap();
    let err = vm.memory.validate_tlv(u64::MAX).unwrap_err();
    assert!(matches!(err, ivm::VMError::NoritoInvalid));
}
