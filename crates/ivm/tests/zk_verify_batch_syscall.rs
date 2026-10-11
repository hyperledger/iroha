//! `DefaultHost` implements standalone `ZK_VERIFY_BATCH` status-vector output.
use iroha_data_model::zk::{BackendTag, OpenVerifyEnvelope};
use ivm::{
    IVMHost, PointerType, VMError,
    host::{self, DefaultHost, ZkVerifyLimits},
    syscalls,
};
fn make_tlv(type_id: PointerType, payload: &[u8]) -> Vec<u8> {
    let mut tlv = Vec::with_capacity(7 + payload.len() + 32);
    tlv.extend_from_slice(&(type_id as u16).to_be_bytes());
    tlv.push(1);
    tlv.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    tlv.extend_from_slice(payload);
    let h: [u8; 32] = iroha_crypto::Hash::new(payload).into();
    tlv.extend_from_slice(&h);
    tlv
}
fn canonical_batch_envelope(seed: u8) -> OpenVerifyEnvelope {
    OpenVerifyEnvelope::new(
        BackendTag::NativePipaRPasta,
        ivm::host::LABEL_BATCH,
        [seed; 32],
        vec![seed, seed.wrapping_add(1)],
        vec![seed.wrapping_add(2), seed.wrapping_add(3)],
    )
}
fn batch_payload(envs: Vec<OpenVerifyEnvelope>) -> Vec<u8> {
    norito::to_bytes(&envs).expect("encode batch payload")
}
fn decode_statuses(vm: &ivm::IVM) -> Vec<u8> {
    let output = vm
        .memory
        .validate_tlv(vm.register(10))
        .expect("batch output tlv");
    assert_eq!(output.type_id, PointerType::NoritoBytes);
    norito::decode_from_bytes(output.payload).expect("status vector")
}
#[test]
fn zk_verify_batch_syscall_returns_status_vector_in_default_host() {
    let payload = batch_payload(vec![
        canonical_batch_envelope(1),
        canonical_batch_envelope(5),
    ]);
    let tlv = make_tlv(PointerType::NoritoBytes, &payload);
    let cfg = ZkVerifyLimits {
        max_verify_batch: 8,
        ..ZkVerifyLimits::default()
    };
    let mut vm = ivm::IVM::new(u64::MAX);
    let mut host = DefaultHost::new().with_zk_verify_limits(cfg);
    let ptr = vm.alloc_input_tlv(&tlv).expect("alloc tlv");
    vm.set_register(10, ptr);
    host.syscall(syscalls::SYSCALL_ZK_VERIFY_BATCH, &mut vm)
        .expect("syscall ok");
    assert_ne!(vm.register(10), 0);
    assert_eq!(vm.register(11), host::ERR_BACKEND);
    assert_eq!(vm.register(12), 0);
    assert_eq!(decode_statuses(&vm), vec![0, 0]);
}
#[test]
fn zk_verify_batch_syscall_rejects_non_norito_pointer_before_backend_status() {
    let payload = batch_payload(vec![canonical_batch_envelope(1)]);
    let tlv = make_tlv(PointerType::Blob, &payload);
    let mut vm = ivm::IVM::new(u64::MAX);
    let mut host = DefaultHost::new();
    let ptr = vm.alloc_input_tlv(&tlv).expect("alloc tlv");
    vm.set_register(10, ptr);
    let err = host
        .syscall(syscalls::SYSCALL_ZK_VERIFY_BATCH, &mut vm)
        .expect_err("non-NoritoBytes pointer must be rejected");
    assert_eq!(err, VMError::NoritoInvalid);
}
