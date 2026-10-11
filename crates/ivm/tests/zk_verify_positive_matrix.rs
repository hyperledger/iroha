//! Canonical standalone proof syscall bounds and authority rejection.
use iroha_data_model::zk::{BackendTag, OpenVerifyEnvelope};
use ivm::{IVMHost, syscalls};
fn build_env(public_input_len: usize) -> Vec<u8> {
    let envelope = OpenVerifyEnvelope::new(
        BackendTag::NativePipaRPasta,
        ivm::host::LABEL_VOTE_BALLOT,
        [1; 32],
        vec![1; public_input_len],
        vec![2, 3, 4],
    );
    norito::to_bytes(&envelope).expect("encode canonical envelope")
}
fn make_tlv(type_id: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(7 + payload.len() + 32);
    out.extend_from_slice(&type_id.to_be_bytes());
    out.push(1);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload.as_ref());
    let h: [u8; 32] = iroha_crypto::Hash::new(payload).into();
    out.extend_from_slice(&h);
    out
}
#[test]
fn default_host_fails_closed_for_canonical_input_size_matrix() {
    let mut vm = ivm::IVM::new(u64::MAX);
    let cfg = ivm::host::ZkVerifyLimits {
        ..Default::default()
    };
    let mut host = ivm::host::DefaultHost::new().with_zk_verify_limits(cfg);
    for public_input_len in [8, 16] {
        let env = build_env(public_input_len);
        let tlv = make_tlv(ivm::PointerType::NoritoBytes as u16, &env);
        let ptr = vm.alloc_input_tlv(&tlv).expect("alloc tlv");
        vm.set_register(10, ptr);
        let _ = host
            .syscall(syscalls::SYSCALL_ZK_VOTE_VERIFY_BALLOT, &mut vm)
            .expect("syscall ok");
        assert_eq!(vm.register(10), 0);
        assert_eq!(
            vm.register(11),
            ivm::host::ERR_BACKEND,
            "standalone host must fail closed without a verifier-key registry"
        );
    }
}
