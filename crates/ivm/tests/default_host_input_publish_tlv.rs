//! DefaultHost: INPUT_PUBLISH_TLV rejects invalid pointer-ABI envelopes.
use crate::common;
use ivm::{IVM, VMError, syscalls};
fn make_tlv(type_id: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(7 + payload.len() + 32);
    v.extend_from_slice(&type_id.to_be_bytes());
    v.push(1);
    v.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    v.extend_from_slice(payload.as_ref());
    let h: [u8; 32] = iroha_crypto::Hash::new(payload).into();
    v.extend_from_slice(&h);
    v
}
#[test]
fn default_host_input_publish_rejects_unknown_type_id() {
    let mut vm = IVM::new(u64::MAX);
    let tlv = make_tlv(0x00FF, b"oops");
    let ptr = vm.alloc_input_tlv(&tlv).expect("alloc tlv");
    let prog = common::assemble_syscalls(&[syscalls::SYSCALL_INPUT_PUBLISH_TLV as u8]);
    vm.load_program(&prog).expect("load");
    vm.set_register(10, ptr);
    let err = vm
        .run()
        .expect_err("unknown pointer type should be rejected");
    assert!(matches!(err, VMError::NoritoInvalid));
}
