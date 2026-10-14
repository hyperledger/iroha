//! Validate TLV hash verification for pointer-ABI values (single ABI).

use iroha_core::smartcontracts::ivm::host::CoreHost;
use iroha_model_base::name::Name;
use iroha_test_samples::ALICE_ID;
use ivm::{IVM, ProgramMetadata, encoding, instruction, syscalls as ivm_sys};
use norito::to_bytes;
fn build_program() -> Vec<u8> {
    // Program: SCALL SET_ACCOUNT_DETAIL; HALT
    let mut code = Vec::new();
    code.extend_from_slice(
        &encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            u8::try_from(ivm_sys::SYSCALL_SET_ACCOUNT_DETAIL).unwrap(),
        )
        .to_le_bytes(),
    );
    code.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let meta = ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: 0,
        vector_length: 0,
        max_cycles: 10_000,
        abi_version: 1,
    };
    let mut out = meta.encode();
    out.extend_from_slice(&code);
    out
}
fn tlv_envelope(type_id: u16, payload: &[u8], hash: Option<[u8; 32]>) -> Vec<u8> {
    let mut blob = Vec::with_capacity(2 + 1 + 4 + payload.len() + 32);
    blob.extend_from_slice(&type_id.to_be_bytes());
    blob.push(1u8); // version
    blob.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    blob.extend_from_slice(payload);
    match hash {
        Some(h) => blob.extend_from_slice(&h),
        None => blob.extend_from_slice(&[0u8; 32]),
    }
    blob
}
#[test]
fn tlv_zero_hash_rejected() {
    // Pointers point to TLV with zero hash; single ABI requires valid hash.
    let program = build_program();
    let mut vm = IVM::new(u64::MAX);
    // Build host with authority (used as fallback in tests only)
    let authority = ALICE_ID.clone();
    vm.set_host(CoreHost::new(authority.clone()));
    // Prepare TLV envelopes for (AccountId, Name, Json)
    let acc_payload = to_bytes(&authority).expect("encode account");
    let name: Name = "cursor".parse().unwrap();
    let name_payload = to_bytes(&name).expect("encode name");
    let json_value = norito::json::object([
        (
            "query",
            norito::json::to_value(&"sc_dummy").expect("serialize query"),
        ),
        (
            "cursor",
            norito::json::to_value(&1u64).expect("serialize cursor"),
        ),
    ])
    .expect("serialize query envelope");
    let json: iroha_primitives::json::Json = json_value.into();
    let json_payload = to_bytes(&json).expect("encode json");
    let acc_tlv = tlv_envelope(1, &acc_payload, None);
    let name_tlv = tlv_envelope(3, &name_payload, None);
    let json_tlv = tlv_envelope(4, &json_payload, None);
    // Place into INPUT region
    let off_acc = 0u64;
    let off_name = 256u64;
    let off_json = 512u64;
    vm.memory
        .preload_input(off_acc, &acc_tlv)
        .expect("preload input");
    vm.memory
        .preload_input(off_name, &name_tlv)
        .expect("preload input");
    vm.memory
        .preload_input(off_json, &json_tlv)
        .expect("preload input");
    // Set arg registers
    vm.set_register(10, ivm::Memory::INPUT_START + off_acc);
    vm.set_register(11, ivm::Memory::INPUT_START + off_name);
    vm.set_register(12, ivm::Memory::INPUT_START + off_json);
    vm.load_program(&program).unwrap();
    // Should fail under single ABI
    let err = vm.run().unwrap_err();
    assert!(matches!(err, ivm::VMError::NoritoInvalid));
}
#[test]
fn tlv_valid_hash_accepted() {
    // TLV with valid hash is accepted in single ABI
    let program = build_program();
    let mut vm = IVM::new(u64::MAX);
    let authority = ALICE_ID.clone();
    vm.set_host(CoreHost::new(authority.clone()));
    // TLVs with valid hashes
    let acc_payload = to_bytes(&authority).expect("encode account");
    let name: Name = "cursor".parse().unwrap();
    let name_payload = to_bytes(&name).expect("encode name");
    let json_value = norito::json::object([
        (
            "query",
            norito::json::to_value(&"sc_dummy").expect("serialize query"),
        ),
        (
            "cursor",
            norito::json::to_value(&1u64).expect("serialize cursor"),
        ),
    ])
    .expect("serialize query envelope");
    let json: iroha_primitives::json::Json = json_value.into();
    let json_payload = to_bytes(&json).expect("encode json");
    let acc_hash = iroha_crypto::Hash::new(&acc_payload);
    let name_hash = iroha_crypto::Hash::new(&name_payload);
    let json_hash = iroha_crypto::Hash::new(&json_payload);
    let acc_tlv = tlv_envelope(1, &acc_payload, Some(*acc_hash.as_ref()));
    let name_tlv = tlv_envelope(3, &name_payload, Some(*name_hash.as_ref()));
    let json_tlv = tlv_envelope(4, &json_payload, Some(*json_hash.as_ref()));
    let off_acc = 0u64;
    let off_name = 256u64;
    let off_json = 512u64;
    vm.memory
        .preload_input(off_acc, &acc_tlv)
        .expect("preload input");
    vm.memory
        .preload_input(off_name, &name_tlv)
        .expect("preload input");
    vm.memory
        .preload_input(off_json, &json_tlv)
        .expect("preload input");
    vm.set_register(10, ivm::Memory::INPUT_START + off_acc);
    vm.set_register(11, ivm::Memory::INPUT_START + off_name);
    vm.set_register(12, ivm::Memory::INPUT_START + off_json);
    vm.load_program(&program).unwrap();
    vm.run()
        .expect("execution should succeed with valid TLV digests");
}
