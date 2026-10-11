//! Canonical standalone proof syscall bounds and authority rejection.
use iroha_data_model::zk::{BackendTag, OpenVerifyEnvelope};
use ivm::{
    IVM, IVMHost, Memory, PointerType,
    gas::ZkGasScheduleV1,
    host::{self, DefaultHost, ZkVerifyLimits},
    syscalls,
};
fn make_tlv(type_id: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(7 + payload.len() + 32);
    out.extend_from_slice(&type_id.to_be_bytes());
    out.push(1);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    let hash: [u8; 32] = iroha_crypto::Hash::new(payload).into();
    out.extend_from_slice(&hash);
    out
}
fn canonical_envelope(backend: BackendTag, circuit_id: &str) -> OpenVerifyEnvelope {
    OpenVerifyEnvelope::new(backend, circuit_id, [1; 32], vec![1, 2, 3], vec![4, 5, 6])
}
fn encode_envelope(envelope: &OpenVerifyEnvelope) -> Vec<u8> {
    norito::to_bytes(envelope).expect("encode canonical envelope")
}
fn run_verify(number: u32, host: &mut DefaultHost, vm: &mut IVM, payload: &[u8]) -> u64 {
    let tlv = make_tlv(PointerType::NoritoBytes as u16, payload);
    vm.memory.preload_input(0, &tlv).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    host.syscall(number, vm).expect("syscall ok")
}
fn actual_verify_gas(envelope: &OpenVerifyEnvelope, payload_len: usize) -> u64 {
    ZkGasScheduleV1::default().actual_single_gas(payload_len, envelope.public_inputs.len())
}
fn label_for_syscall(number: u32) -> &'static str {
    match number {
        syscalls::SYSCALL_ZK_VOTE_VERIFY_BALLOT => host::LABEL_VOTE_BALLOT,
        syscalls::SYSCALL_ZK_VOTE_VERIFY_TALLY => host::LABEL_VOTE_TALLY,
        _ => host::LABEL_VOTE_BALLOT,
    }
}
const VERIFY_SYSCALLS: [u32; 2] = [
    syscalls::SYSCALL_ZK_VOTE_VERIFY_BALLOT,
    syscalls::SYSCALL_ZK_VOTE_VERIFY_TALLY,
];
#[test]
fn default_host_fails_closed_for_canonical_pasta_envelopes() {
    let mut vm = IVM::new(u64::MAX);
    let mut host = DefaultHost::new().with_zk_verify_limits(ZkVerifyLimits {
        ..ZkVerifyLimits::default()
    });
    for number in VERIFY_SYSCALLS {
        let envelope = canonical_envelope(BackendTag::NativePipaRPasta, label_for_syscall(number));
        let payload = encode_envelope(&envelope);
        let gas = run_verify(number, &mut host, &mut vm, &payload);
        assert_eq!(gas, actual_verify_gas(&envelope, payload.len()));
        assert_eq!(vm.register(10), 0);
        assert_eq!(
            vm.register(11),
            host::ERR_BACKEND,
            "standalone host has no verifier-key registry for {number:x}"
        );
    }
}
#[test]
fn verify_syscalls_publish_only_defined_fail_closed_statuses() {
    let mut vm = IVM::new(u64::MAX);
    let mut host = DefaultHost::new();
    for number in VERIFY_SYSCALLS {
        let envelope = canonical_envelope(BackendTag::NativePipaRPasta, label_for_syscall(number));
        let payload = encode_envelope(&envelope);
        run_verify(number, &mut host, &mut vm, &payload);
        assert_eq!(vm.register(10), 0);
        assert_eq!(vm.register(11), host::ERR_BACKEND);
    }
}
#[test]
fn verify_syscalls_backend_tag_matrix_is_fail_closed() {
    let mut vm = IVM::new(u64::MAX);
    let mut host = DefaultHost::new();
    for backend in [BackendTag::NativePipaRPasta, BackendTag::Stark] {
        let envelope = canonical_envelope(backend, host::LABEL_VOTE_BALLOT);
        let payload = encode_envelope(&envelope);
        run_verify(
            syscalls::SYSCALL_ZK_VOTE_VERIFY_BALLOT,
            &mut host,
            &mut vm,
            &payload,
        );
        assert_eq!(vm.register(10), 0);
        assert_eq!(vm.register(11), host::ERR_BACKEND);
    }
}
#[test]
fn verify_syscalls_reject_nonportable_circuit_id() {
    let mut vm = IVM::new(u64::MAX);
    let mut host = DefaultHost::new();
    let envelope = canonical_envelope(BackendTag::NativePipaRPasta, "bad label");
    let payload = encode_envelope(&envelope);
    let gas = run_verify(
        syscalls::SYSCALL_ZK_VOTE_VERIFY_BALLOT,
        &mut host,
        &mut vm,
        &payload,
    );
    assert_eq!(gas, actual_verify_gas(&envelope, payload.len()));
    assert_eq!(vm.register(10), 0);
    assert_eq!(vm.register(11), host::ERR_DECODE);
}
#[test]
fn verify_syscalls_reject_over_envelope_and_proof_limits() {
    let envelope = canonical_envelope(BackendTag::NativePipaRPasta, host::LABEL_VOTE_BALLOT);
    let payload = encode_envelope(&envelope);
    assert!(payload.len() > 16);
    let mut vm = IVM::new(u64::MAX);
    let mut host = DefaultHost::new().with_zk_verify_limits(ZkVerifyLimits {
        max_envelope_bytes: 16,
        ..ZkVerifyLimits::default()
    });
    let gas = run_verify(
        syscalls::SYSCALL_ZK_VOTE_VERIFY_BALLOT,
        &mut host,
        &mut vm,
        &payload,
    );
    assert_eq!(gas, ivm::gas::zk_verify_gas(payload.len()));
    assert_eq!(vm.register(10), 0);
    assert_eq!(vm.register(11), host::ERR_ENVELOPE_SIZE);
    let mut oversized_proof =
        canonical_envelope(BackendTag::NativePipaRPasta, host::LABEL_VOTE_BALLOT);
    oversized_proof.proof_bytes = vec![7; 65];
    let payload = encode_envelope(&oversized_proof);
    let mut vm = IVM::new(u64::MAX);
    let mut host = DefaultHost::new().with_zk_verify_limits(ZkVerifyLimits {
        max_proof_bytes: 64,
        ..ZkVerifyLimits::default()
    });
    let gas = run_verify(
        syscalls::SYSCALL_ZK_VOTE_VERIFY_BALLOT,
        &mut host,
        &mut vm,
        &payload,
    );
    assert_eq!(gas, actual_verify_gas(&oversized_proof, payload.len()));
    assert_eq!(vm.register(10), 0);
    assert_eq!(vm.register(11), host::ERR_PROOF_LEN);
}
