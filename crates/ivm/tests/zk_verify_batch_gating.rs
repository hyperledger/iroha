//! `DefaultHost` applies batch-verifier gates for `ZK_VERIFY_BATCH`.
use iroha_data_model::zk::{BackendTag, OpenVerifyEnvelope};
use ivm::{
    IVMHost, PointerType,
    host::{self, DefaultHost, ZkVerifyLimits},
    syscalls,
};
fn make_tlv(payload: &[u8]) -> Vec<u8> {
    let mut tlv = Vec::with_capacity(7 + payload.len() + 32);
    tlv.extend_from_slice(&(PointerType::NoritoBytes as u16).to_be_bytes());
    tlv.push(1);
    tlv.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    tlv.extend_from_slice(payload);
    let h: [u8; 32] = iroha_crypto::Hash::new(payload).into();
    tlv.extend_from_slice(&h);
    tlv
}
fn decode_statuses(vm: &ivm::IVM) -> Vec<u8> {
    let output = vm
        .memory
        .validate_tlv(vm.register(10))
        .expect("batch output tlv");
    assert_eq!(output.type_id, PointerType::NoritoBytes);
    norito::decode_from_bytes(output.payload).expect("status vector")
}
fn canonical_envelope(seed: u8) -> OpenVerifyEnvelope {
    OpenVerifyEnvelope::new(
        BackendTag::NativePipaRPasta,
        ivm::host::LABEL_BATCH,
        [seed; 32],
        vec![seed, seed.wrapping_add(1)],
        vec![seed.wrapping_add(2), seed.wrapping_add(3)],
    )
}
#[test]
fn verify_batch_enforces_batch_size_before_per_item_gates() {
    let payload = norito::to_bytes(&vec![canonical_envelope(1), canonical_envelope(5)])
        .expect("encode batch");
    let tlv = make_tlv(&payload);
    let cfg = ZkVerifyLimits {
        max_verify_batch: 1,
        ..ZkVerifyLimits::default()
    };
    let mut vm = ivm::IVM::new(u64::MAX);
    let mut host = DefaultHost::new().with_zk_verify_limits(cfg);
    let ptr = vm.alloc_input_tlv(&tlv).expect("alloc tlv");
    vm.set_register(10, ptr);
    host.syscall(syscalls::SYSCALL_ZK_VERIFY_BATCH, &mut vm)
        .expect("syscall ok");
    assert_eq!(vm.register(10), 0);
    assert_eq!(vm.register(11), host::ERR_BATCH);
    assert_eq!(vm.register(12), u64::MAX);
}
#[test]
fn verify_batch_returns_fail_closed_status_without_verifier_registry() {
    let payload = norito::to_bytes(&vec![canonical_envelope(9)]).expect("encode batch");
    let tlv = make_tlv(&payload);
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
    assert_eq!(decode_statuses(&vm), vec![0]);
}
