//! VRF envelope type, decoding, and verification-status tests.
#![cfg(feature = "ivm_vrf_tests")]
use crate::common;
use group::prime::PrimeCurveAffine;
use ivm::{self, IVM, IVMHost, Memory, PointerType};
fn build_tlv(ty: PointerType, payload: &[u8]) -> Vec<u8> {
    let payload = common::payload_for_type(ty, payload);
    let mut tlv = Vec::with_capacity(7 + payload.len() + 32);
    tlv.extend_from_slice(&(ty as u16).to_be_bytes());
    tlv.push(1); // version
    tlv.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    tlv.extend_from_slice(payload.as_ref());
    let h: [u8; 32] = iroha_crypto::Hash::new(&payload).into();
    tlv.extend_from_slice(&h);
    tlv
}
#[test]
fn vrf_verify_wrong_tlv_type_sets_err_type() {
    // DefaultHost with no special config
    let host = ivm::host::DefaultHost::new();
    let mut vm = IVM::new(0);
    vm.set_host(host);
    // Put a JSON TLV (wrong type) in INPUT and set r10
    let payload = br#"{"backend":"halo2/ipa"}"#;
    let tlv = build_tlv(PointerType::Json, payload);
    vm.memory.preload_input(0, &tlv).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    // Call VRF_VERIFY; expect type error status in r11 and r10=0
    let _ = unsafe {
        let host_ptr = vm
            .host_mut_any()
            .unwrap()
            .downcast_mut::<ivm::host::DefaultHost>()
            .unwrap() as *mut ivm::host::DefaultHost;
        (*host_ptr).syscall(ivm::syscalls::SYSCALL_VRF_VERIFY, &mut vm)
    }
    .expect("syscall ok");
    assert_eq!(vm.register(10), 0, "r10 should be 0 (no output)");
    assert_eq!(vm.register(11), 1, "r11 should be ERR_TYPE=1");
}
#[test]
fn vrf_verify_malformed_payload_sets_err_decode() {
    let host = ivm::host::DefaultHost::new();
    let mut vm = IVM::new(0);
    vm.set_host(host);
    // Put a NoritoBytes TLV with empty payload (malformed for VrfVerifyRequest)
    let tlv = build_tlv(PointerType::NoritoBytes, &[]);
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
    assert_eq!(vm.register(10), 0, "r10 should be 0 (no output)");
    assert_eq!(vm.register(11), 2, "r11 should be ERR_DECODE=2");
}
#[test]
fn vrf_verify_with_valid_lengths_and_network_yields_verify_error() {
    use blstrs::{G1Affine, G2Affine};
    let network_id = common::test_network_id(0x61);
    let host = ivm::host::DefaultHost::new().with_network_id(network_id);
    let mut vm = IVM::new(0);
    vm.set_host(host);
    // Build a request with decompressible pk/proof and a matching network identity.
    let pk = G1Affine::generator().to_compressed();
    let sig = G2Affine::generator().to_compressed();
    let req = ivm::vrf::VrfVerifyRequest {
        variant: 1,
        pk: pk.to_vec(),
        proof: sig.to_vec(),
        network_id,
        input: b"hello".to_vec(),
    };
    let body = norito::to_bytes(&req).expect("encode");
    let tlv = build_tlv(ivm::PointerType::NoritoBytes, &body);
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
    // Expect verification failure (ERR_VERIFY=6), although decompression and lengths were fine
    assert_eq!(vm.register(10), 0);
    assert_eq!(vm.register(11), 6, "ERR_VERIFY");
}
