//! Durable struct state pointer fields should decode back into pointer-ABI TLVs.
use iroha_crypto::Hash as IrohaHash;
use iroha_data_model::prelude::*;
use ivm::{CoreHost, IVM, IVMHost, PointerType, VMError, pointer_abi, syscalls};
use norito::to_bytes;
fn encode_pointer_tlv(ty: PointerType, payload: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 1 + 4 + payload.len() + IrohaHash::LENGTH);
    out.extend_from_slice(&(ty as u16).to_be_bytes());
    out.push(1);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload.as_ref());
    let hash: [u8; 32] = IrohaHash::new(&payload).into();
    out.extend_from_slice(&hash);
    out
}
fn parse_account_id_literal(id: &str) -> AccountId {
    AccountId::parse_encoded(id).expect("account literal must be canonical I105")
}
fn encode_account_id_pointer(id: &str) -> Vec<u8> {
    let parsed = parse_account_id_literal(id);
    let raw = encode_pointer_tlv(
        PointerType::AccountId,
        to_bytes(&parsed).expect("encode id"),
    );
    encode_pointer_tlv(PointerType::NoritoBytes, raw)
}
fn encode_account_id_pointer_in_blob(id: &str) -> Vec<u8> {
    let parsed = parse_account_id_literal(id);
    let raw = encode_pointer_tlv(
        PointerType::AccountId,
        to_bytes(&parsed).expect("encode id"),
    );
    encode_pointer_tlv(PointerType::Blob, raw)
}
fn encode_account_id_pointer_without_inner_hash(id: &str) -> Vec<u8> {
    use iroha_crypto::Hash as IrohaHash;
    let parsed = parse_account_id_literal(id);
    let payload = to_bytes(&parsed).expect("encode id");
    // Build an inner TLV without the trailing hash (invalid layout).
    let mut inner = Vec::with_capacity(2 + 1 + 4 + payload.len());
    inner.extend_from_slice(&(PointerType::AccountId as u16).to_be_bytes());
    inner.push(1);
    inner.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    inner.extend_from_slice(payload.as_ref());
    // Wrap in NoritoBytes with a valid outer hash so only the missing inner hash is exercised.
    let mut outer = Vec::with_capacity(2 + 1 + 4 + inner.len() + IrohaHash::LENGTH);
    outer.extend_from_slice(&(PointerType::NoritoBytes as u16).to_be_bytes());
    outer.push(1);
    outer.extend_from_slice(&(inner.len() as u32).to_be_bytes());
    outer.extend_from_slice(&inner);
    let outer_hash: [u8; 32] = IrohaHash::new(&inner).into();
    outer.extend_from_slice(&outer_hash);
    outer
}
#[test]
fn pointer_from_norito_syscall_returns_pointer() {
    const OWNER_ID: &str = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV";
    let pointer_bytes = encode_account_id_pointer(OWNER_ID);
    let mut vm = IVM::new(u64::MAX);
    let ptr = vm
        .alloc_input_tlv(&pointer_bytes)
        .expect("write pointer into INPUT region");
    vm.set_register(10, ptr);
    vm.set_register(11, PointerType::AccountId as u64);
    let mut host = CoreHost::new();
    host.syscall(syscalls::SYSCALL_POINTER_FROM_NORITO, &mut vm)
        .expect("pointer_from_norito syscall succeeds");
    let out_ptr = vm.register(10);
    assert_ne!(
        out_ptr, 0,
        "pointer_from_norito should return non-null pointer"
    );
    let tlv = vm
        .memory
        .validate_tlv(out_ptr)
        .expect("returned pointer TLV");
    assert_eq!(tlv.type_id, PointerType::AccountId);
}
#[test]
fn pointer_from_norito_rejects_retired_blob_carrier() {
    const OWNER_ID: &str = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV";
    let pointer_bytes = encode_account_id_pointer_in_blob(OWNER_ID);
    let mut vm = IVM::new(u64::MAX);
    let ptr = vm
        .alloc_input_tlv(&pointer_bytes)
        .expect("write pointer into INPUT region");
    vm.set_register(10, ptr);
    vm.set_register(11, PointerType::AccountId as u64);
    let mut host = CoreHost::new();
    assert!(matches!(
        host.syscall(syscalls::SYSCALL_POINTER_FROM_NORITO, &mut vm),
        Err(VMError::NoritoInvalid)
    ));
    assert_eq!(vm.register(10), ptr);
}
#[test]
fn pointer_from_norito_rejects_inner_tlv_without_hash() {
    const OWNER_ID: &str = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV";
    let pointer_bytes = encode_account_id_pointer_without_inner_hash(OWNER_ID);
    let mut vm = IVM::new(u64::MAX);
    let ptr = vm
        .alloc_input_tlv(&pointer_bytes)
        .expect("write pointer into INPUT region");
    vm.set_register(10, ptr);
    vm.set_register(11, PointerType::AccountId as u64);
    let mut host = CoreHost::new();
    let err = host
        .syscall(syscalls::SYSCALL_POINTER_FROM_NORITO, &mut vm)
        .expect_err("invalid inner TLV without hash should fail");
    assert!(matches!(err, ivm::VMError::NoritoInvalid));
}
#[test]
fn pointer_from_norito_rejects_wrong_expected_type() {
    const OWNER_ID: &str = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV";
    let pointer_bytes = encode_account_id_pointer(OWNER_ID);
    let mut vm = IVM::new(u64::MAX);
    let ptr = vm
        .alloc_input_tlv(&pointer_bytes)
        .expect("write pointer into INPUT region");
    vm.set_register(10, ptr);
    // Expect a Blob TLV even though the inner payload encodes an AccountId.
    vm.set_register(11, PointerType::Blob as u64);
    let mut host = CoreHost::new();
    let err = host
        .syscall(syscalls::SYSCALL_POINTER_FROM_NORITO, &mut vm)
        .expect_err("mismatched expected pointer type should fail");
    assert!(matches!(err, VMError::NoritoInvalid));
}
#[test]
fn pointer_validate_rejects_unknown_type() {
    let payload = b"abc";
    let mut tlv = Vec::new();
    // Unknown pointer type id
    tlv.extend_from_slice(&0xFFFFu16.to_be_bytes());
    tlv.push(1);
    tlv.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    tlv.extend_from_slice(payload.as_ref());
    let hash: [u8; 32] = IrohaHash::new(payload).into();
    tlv.extend_from_slice(&hash);
    let err = pointer_abi::validate_tlv_bytes(&tlv).expect_err("unknown type must fail");
    assert!(matches!(err, VMError::NoritoInvalid));
}
