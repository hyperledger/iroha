//! Standalone STARK envelopes cannot replace an authenticated verifier.
#![cfg(feature = "ivm_zk_tests")]
use iroha_data_model::zk::{BackendTag, OpenVerifyEnvelope};
use ivm::{IVMHost, gas::ZkGasScheduleV1, syscalls};
fn canonical_goldilocks_envelope() -> OpenVerifyEnvelope {
    OpenVerifyEnvelope::new(
        BackendTag::Stark,
        "stark/fri/goldilocks-test-v1",
        [1; 32],
        vec![1, 2, 3],
        vec![4, 5, 6],
    )
}
fn tlv_from_payload(payload: &[u8]) -> Vec<u8> {
    let mut tlv = Vec::with_capacity(2 + 1 + 4 + payload.len() + 32);
    tlv.extend_from_slice(&u16::to_be_bytes(ivm::PointerType::NoritoBytes as u16));
    tlv.push(1);
    tlv.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    tlv.extend_from_slice(payload);
    let hash: [u8; 32] = iroha_crypto::Hash::new(payload).into();
    tlv.extend_from_slice(&hash);
    tlv
}
fn run_default_host(envelope: &OpenVerifyEnvelope) -> (u64, u64, u64) {
    let payload = norito::to_bytes(envelope).expect("encode canonical envelope");
    let tlv = tlv_from_payload(&payload);
    let mut vm = ivm::IVM::new(u64::MAX);
    let mut host = ivm::host::DefaultHost::new();
    let ptr = vm.alloc_input_tlv(&tlv).expect("alloc tlv");
    vm.set_register(10, ptr);
    let gas = host
        .syscall(syscalls::SYSCALL_ZK_VOTE_VERIFY_BALLOT, &mut vm)
        .expect("syscall ok");
    let expected =
        ZkGasScheduleV1::default().actual_single_gas(payload.len(), envelope.public_inputs.len());
    assert_eq!(gas, expected);
    (vm.register(10), vm.register(11), gas)
}
#[test]
fn zk_verify_ballot_goldilocks_default_host_fails_closed() {
    let (verified, status, _) = run_default_host(&canonical_goldilocks_envelope());
    assert_eq!(verified, 0);
    assert_eq!(status, ivm::host::ERR_BACKEND);
}
