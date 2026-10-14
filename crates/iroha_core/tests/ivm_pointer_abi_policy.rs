//! Node `CoreHost` pointer‑ABI policy tests: verify ABI‑keyed type acceptance.

use iroha_core::smartcontracts::ivm::host::CoreHost;
use iroha_data_model::prelude::*;
use iroha_model_base::domain::DomainId;
use ivm::{PointerType, ProgramMetadata};
use norito::to_bytes;
fn tlv_envelope(type_id: u16, payload: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(2 + 1 + 4 + payload.len() + 32);
    blob.extend_from_slice(&type_id.to_be_bytes());
    blob.push(1u8);
    blob.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    blob.extend_from_slice(payload);
    let hash: [u8; 32] = iroha_crypto::Hash::new(payload).into();
    blob.extend_from_slice(&hash);
    blob
}
#[test]
fn domainid_allowed_under_abi_current() {
    // Build minimal v1 header and load
    let meta = ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: 0,
        vector_length: 0,
        max_cycles: 1,
        abi_version: 1,
    };
    let mut vm = ivm::IVM::new(10_000);
    vm.load_program(&meta.encode()).expect("load v1 meta");
    // Prepare DomainId TLV
    let did: DomainId = DomainId::try_new("wonder", "universal").unwrap();
    let payload = to_bytes(&did).expect("encode DomainId");
    let tlv = tlv_envelope(PointerType::DomainId as u16, &payload);
    vm.memory.preload_input(0, &tlv).expect("preload input");
    // Node CoreHost decode should accept DomainId under abi v1
    let out: DomainId =
        CoreHost::decode_tlv_typed(&vm, ivm::Memory::INPUT_START, PointerType::DomainId)
            .expect("DomainId must be accepted under abi v1");
    assert_eq!(out, did);
}
#[test]
fn unknown_pointer_type_rejected_under_current() {
    // Build minimal v1 header and load
    let meta = ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: 0,
        vector_length: 0,
        max_cycles: 1,
        abi_version: 1, // v1
    };
    let mut vm = ivm::IVM::new(10_000);
    vm.load_program(&meta.encode()).expect("load v1 meta");
    // Construct a TLV with an unknown type id (0x00FF)
    let payload = b"deadbeef".to_vec();
    let tlv = tlv_envelope(0x00FF, &payload);
    vm.memory.preload_input(0, &tlv).expect("preload input");
    // validate_tlv should fail before type checking in decode_tlv_typed
    let err =
        CoreHost::decode_tlv_typed::<AccountId>(&vm, ivm::Memory::INPUT_START, PointerType::Blob)
            .expect_err("unknown pointer type id must be rejected");
    assert!(matches!(err, ivm::VMError::NoritoInvalid));
}
