//! VRF exact-network binding and display-chain separation tests.
#![cfg(feature = "ivm_vrf_tests")]
use crate::common;
use ivm::{self, IVM, IVMHost, Memory, PointerType};
fn build_vrf_req(
    variant: u8,
    pk_len: usize,
    proof_len: usize,
    network_id: iroha_data_model::NetworkId,
    input: &[u8],
) -> Vec<u8> {
    use ivm::vrf::VrfVerifyRequest;
    let req = VrfVerifyRequest {
        variant,
        pk: vec![0u8; pk_len],
        proof: vec![0u8; proof_len],
        network_id,
        input: input.to_vec(),
    };
    let body = norito::to_bytes(&req).expect("encode req");
    let mut tlv = Vec::with_capacity(7 + body.len() + 32);
    tlv.extend_from_slice(&(PointerType::NoritoBytes as u16).to_be_bytes());
    tlv.push(1);
    tlv.extend_from_slice(&(body.len() as u32).to_be_bytes());
    tlv.extend_from_slice(&body);
    let h: [u8; 32] = iroha_crypto::Hash::new(&body).into();
    tlv.extend_from_slice(&h);
    tlv
}
#[test]
fn vrf_verify_network_mismatch_sets_err_network() {
    let expected_network_id = common::test_network_id(0x31);
    let different_network_id = common::test_network_id(0x32);
    let host = ivm::host::DefaultHost::new().with_network_id(expected_network_id);
    let mut vm = IVM::new(0);
    vm.set_host(host);
    // Use variant 1 and lengths that reach the exact-network admission check.
    let tlv = build_vrf_req(1, 48, 96, different_network_id, b"msg");
    vm.memory.preload_input(0, &tlv).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    let _ = unsafe {
        let host_ptr = vm
            .host_mut_any()
            .unwrap()
            .downcast_mut::<ivm::host::DefaultHost>()
            .unwrap() as *mut ivm::host::DefaultHost;
        (*host_ptr).syscall(ivm::syscalls::SYSCALL_VRF_VERIFY, &mut vm)
    }
    .expect("syscall ok");
    assert_eq!(vm.register(10), 0);
    assert_eq!(vm.register(11), 8, "ERR_NETWORK");
}
#[test]
fn display_chain_label_cannot_supply_vrf_network_context() {
    let claimed_network_id = common::test_network_id(0x31);
    let host = ivm::host::DefaultHost::new().with_chain_id(b"same-label".to_vec());
    let mut vm = IVM::new(0);
    vm.set_host(host);
    let tlv = build_vrf_req(1, 48, 96, claimed_network_id, b"msg");
    vm.memory.preload_input(0, &tlv).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    let _ = unsafe {
        let host_ptr = vm
            .host_mut_any()
            .unwrap()
            .downcast_mut::<ivm::host::DefaultHost>()
            .unwrap() as *mut ivm::host::DefaultHost;
        (*host_ptr).syscall(ivm::syscalls::SYSCALL_VRF_VERIFY, &mut vm)
    }
    .expect("syscall ok");
    assert_eq!(vm.register(10), 0);
    assert_eq!(vm.register(11), 8, "ERR_NETWORK");
}
// Gated by feature at crate level
