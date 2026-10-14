//! Pointer-ABI TLV guard regressions.
use crate::common;
use iroha_crypto::Hash;
use ivm::{CoreHost, IVM, PointerType, encoding, syscalls};
fn tlv(pty: PointerType, payload: &[u8]) -> Vec<u8> {
    let payload = common::payload_for_type(pty, payload);
    let mut v = Vec::with_capacity(7 + payload.len() + Hash::LENGTH);
    v.extend_from_slice(&(pty as u16).to_be_bytes());
    v.push(1);
    v.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    v.extend_from_slice(payload.as_ref());
    let h: [u8; Hash::LENGTH] = Hash::new(&payload).into();
    v.extend_from_slice(&h);
    v
}
#[test]
fn tlv_wrong_type_id_is_rejected() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    let inner = tlv(PointerType::Name, b"rose");
    let outer = tlv(PointerType::NoritoBytes, &inner);
    let ptr = vm.alloc_input_tlv(&outer).expect("allocate outer TLV");
    vm.set_register(10, ptr);
    vm.set_register(11, PointerType::AccountId as u16 as u64);
    let prog = common::assemble(
        &[
            encoding::wide::encode_sys(
                ivm::instruction::wide::system::SCALL,
                syscalls::SYSCALL_POINTER_FROM_NORITO as u8,
            )
            .to_le_bytes(),
            encoding::wide::encode_halt().to_le_bytes(),
        ]
        .concat(),
    );
    vm.load_program(&prog).expect("load program");
    let err = vm
        .run()
        .expect_err("mismatched inner TLV type should fail pointer decoding");
    assert!(
        matches!(err, ivm::VMError::NoritoInvalid),
        "expected NoritoInvalid for mismatched TLV type, got {err:?}"
    );
}
#[test]
fn tlv_expected_type_rejects_high_register_bits_without_truncation() {
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    let inner = tlv(PointerType::Name, b"rose");
    let outer = tlv(PointerType::NoritoBytes, &inner);
    let ptr = vm.alloc_input_tlv(&outer).expect("allocate outer TLV");
    vm.set_register(10, ptr);
    vm.set_register(11, (1_u64 << 16) | u64::from(PointerType::Name as u16));
    let prog = common::assemble(
        &[
            encoding::wide::encode_sys(
                ivm::instruction::wide::system::SCALL,
                syscalls::SYSCALL_POINTER_FROM_NORITO as u8,
            )
            .to_le_bytes(),
            encoding::wide::encode_halt().to_le_bytes(),
        ]
        .concat(),
    );
    vm.load_program(&prog).expect("load program");
    assert!(matches!(vm.run(), Err(ivm::VMError::NoritoInvalid)));
}
