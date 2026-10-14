//! VRF batch-syscall verification and exact-network admission tests.
#![cfg(feature = "ivm_vrf_tests")]
use crate::common;
use blstrs::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use common::assemble_syscalls;
use group::{Curve, Group, prime::PrimeCurveAffine};
use ivm::vrf::{VrfVerifyBatchRequest, VrfVerifyRequest};
use ivm::{IVM, Memory, PointerType, host::DefaultHost};
fn vrf_batch_vm_gas(payload_len: usize) -> u64 {
    ivm::gas::vrf_verify_gas(
        u64::try_from(ivm::vrf::MAX_VRF_VERIFY_BATCH_ITEMS_V1).expect("VRF batch cap fits u64"),
        u64::try_from(payload_len).unwrap_or(u64::MAX),
    )
    .saturating_add(1_024)
}
fn hash_to_g1(msg: &[u8]) -> G1Affine {
    const DST: &[u8] = b"BLS12381G1_XMD:SHA-256_SSWU_RO_IROHA_VRF_V1";
    G1Projective::hash_to_curve(msg, DST, &[]).to_affine()
}
fn hash_to_g2(msg: &[u8]) -> G2Affine {
    const DST: &[u8] = b"BLS12381G2_XMD:SHA-256_SSWU_RO_IROHA_VRF_V1";
    G2Projective::hash_to_curve(msg, DST, &[]).to_affine()
}
fn make_tlv(type_id: u16, payload: &[u8]) -> Vec<u8> {
    use iroha_crypto::Hash;
    let mut out = Vec::with_capacity(7 + payload.len() + 32);
    out.extend_from_slice(&type_id.to_be_bytes());
    out.push(1);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload.as_ref());
    let h: [u8; 32] = Hash::new(payload).into();
    out.extend_from_slice(&h);
    out
}
fn run_vrf_verify_batch(req: VrfVerifyBatchRequest) -> (u64, u64, u64) {
    let network_id = req.items.first().map(|item| item.network_id);
    let body = norito::to_bytes(&req).expect("encode batch");
    let tlv_env = make_tlv(PointerType::NoritoBytes as u16, &body);
    let mut vm = IVM::new(vrf_batch_vm_gas(body.len()));
    if let Some(network_id) = network_id {
        vm.set_host(DefaultHost::new().with_network_id(network_id));
    }
    vm.memory.preload_input(0, &tlv_env).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    let prog = assemble_syscalls(&[ivm::syscalls::SYSCALL_VRF_VERIFY_BATCH as u8]);
    vm.load_program(&prog).unwrap();
    vm.run().unwrap();
    (vm.register(10), vm.register(11), vm.register(12))
}
#[test]
fn syscall_vrf_verify_batch_two_items_ok() {
    // Item 1: Normal (SigInG2)
    let sk1 = {
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = (i as u8) + 1;
        }
        Scalar::from_bytes_be(&b).unwrap()
    };
    let pk1 = (G1Projective::generator() * sk1)
        .to_affine()
        .to_compressed();
    let network_id = common::test_network_id(0x51);
    let network_bytes = network_id.as_bytes();
    let input1 = b"in1";
    let mut in1 = Vec::new();
    in1.extend_from_slice(b"iroha:vrf:v1:input|");
    in1.extend_from_slice(network_bytes);
    in1.push(b'|');
    in1.extend_from_slice(input1);
    let msg1: [u8; 32] = iroha_crypto::Hash::new(&in1).into();
    let sig1 = (G2Projective::from(hash_to_g2(&msg1)) * sk1)
        .to_affine()
        .to_compressed();
    let mut y1buf = Vec::new();
    y1buf.extend_from_slice(b"iroha:vrf:v1:output");
    y1buf.extend_from_slice(&sig1);
    let exp1: [u8; 32] = iroha_crypto::Hash::new(&y1buf).into();
    // Item 2: Small (SigInG1)
    let sk2 = {
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = (i as u8) + 11;
        }
        Scalar::from_bytes_be(&b).unwrap()
    };
    let pk2 = (G2Projective::generator() * sk2)
        .to_affine()
        .to_compressed();
    let input2 = b"in2";
    let mut in2 = Vec::new();
    in2.extend_from_slice(b"iroha:vrf:v1:input|");
    in2.extend_from_slice(network_bytes);
    in2.push(b'|');
    in2.extend_from_slice(input2);
    let msg2: [u8; 32] = iroha_crypto::Hash::new(&in2).into();
    let sig2 = (G1Projective::from(hash_to_g1(&msg2)) * sk2)
        .to_affine()
        .to_compressed();
    let mut y2buf = Vec::new();
    y2buf.extend_from_slice(b"iroha:vrf:v1:output");
    y2buf.extend_from_slice(&sig2);
    let exp2: [u8; 32] = iroha_crypto::Hash::new(&y2buf).into();
    let req = VrfVerifyBatchRequest {
        items: vec![
            VrfVerifyRequest {
                variant: 1,
                pk: pk1.to_vec(),
                proof: sig1.to_vec(),
                network_id,
                input: input1.to_vec(),
            },
            VrfVerifyRequest {
                variant: 2,
                pk: pk2.to_vec(),
                proof: sig2.to_vec(),
                network_id,
                input: input2.to_vec(),
            },
        ],
    };
    let body = norito::to_bytes(&req).expect("encode batch");
    let tlv_env = make_tlv(PointerType::NoritoBytes as u16, &body);
    let mut vm = IVM::new(vrf_batch_vm_gas(body.len()));
    vm.set_host(DefaultHost::new().with_network_id(network_id));
    vm.memory.preload_input(0, &tlv_env).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    let prog = assemble_syscalls(&[ivm::syscalls::SYSCALL_VRF_VERIFY_BATCH as u8]);
    vm.load_program(&prog).unwrap();
    vm.run().unwrap();
    assert_eq!(vm.register(11), 0, "status ok");
    let p = vm.register(10);
    let tlv = vm.memory.validate_tlv(p).expect("valid tlv");
    assert_eq!(tlv.type_id, PointerType::NoritoBytes);
    let outs: Vec<[u8; 32]> = norito::decode_from_bytes(tlv.payload).expect("decode outs");
    assert_eq!(outs.len(), 2);
    assert_eq!(outs[0], exp1);
    assert_eq!(outs[1], exp2);
}
#[test]
fn syscall_vrf_verify_batch_fail_index_is_reported() {
    // One good, one bad (mismatched variant/length), expect r11!=0 and r12==1
    let sk1 = {
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = (i as u8) + 1;
        }
        Scalar::from_bytes_be(&b).unwrap()
    };
    let pk1 = (G1Projective::generator() * sk1)
        .to_affine()
        .to_compressed();
    let network_id = common::test_network_id(0x51);
    let network_bytes = network_id.as_bytes();
    let input1 = b"in1";
    let mut in1 = Vec::new();
    in1.extend_from_slice(b"iroha:vrf:v1:input|");
    in1.extend_from_slice(network_bytes);
    in1.push(b'|');
    in1.extend_from_slice(input1);
    let msg1: [u8; 32] = iroha_crypto::Hash::new(&in1).into();
    let sig1 = (G2Projective::from(hash_to_g2(&msg1)) * sk1)
        .to_affine()
        .to_compressed();
    // Bad item: use G1 sig but claim variant 1 (expects G2 sig). Build a fake but valid-length G1 encoding.
    let bad_sig_g1 = G1Affine::generator().to_compressed();
    let req = VrfVerifyBatchRequest {
        items: vec![
            VrfVerifyRequest {
                variant: 1,
                pk: pk1.to_vec(),
                proof: sig1.to_vec(),
                network_id,
                input: input1.to_vec(),
            },
            VrfVerifyRequest {
                variant: 1,
                pk: pk1.to_vec(),
                proof: bad_sig_g1.to_vec(),
                network_id,
                input: input1.to_vec(),
            },
        ],
    };
    let body = norito::to_bytes(&req).expect("encode batch");
    let tlv_env = make_tlv(PointerType::NoritoBytes as u16, &body);
    let mut vm = IVM::new(vrf_batch_vm_gas(body.len()));
    vm.set_host(DefaultHost::new().with_network_id(network_id));
    vm.memory.preload_input(0, &tlv_env).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    let prog = assemble_syscalls(&[ivm::syscalls::SYSCALL_VRF_VERIFY_BATCH as u8]);
    vm.load_program(&prog).unwrap();
    vm.run().unwrap();
    assert_ne!(vm.register(11), 0, "status must be error");
    assert_eq!(vm.register(12), 1, "failing index must be 1");
}
#[test]
fn syscall_vrf_verify_batch_network_mismatch_reports_index() {
    // Host enforces an exact network identity; the second item claims another network.
    // Expect: r11 = 8 (ERR_NETWORK) and r12 = index of first mismatch.
    let host_network_id = common::test_network_id(0x51);
    let bad_network_id = common::test_network_id(0x52);
    // Item 1: Valid (SigInG2) with the correct network identity.
    let sk1 = {
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = (i as u8) + 3;
        }
        Scalar::from_bytes_be(&b).unwrap()
    };
    let pk1 = (G1Projective::generator() * sk1)
        .to_affine()
        .to_compressed();
    let input1 = b"in-ok";
    let mut in1 = Vec::new();
    in1.extend_from_slice(b"iroha:vrf:v1:input|");
    in1.extend_from_slice(host_network_id.as_bytes());
    in1.push(b'|');
    in1.extend_from_slice(input1);
    let msg1: [u8; 32] = iroha_crypto::Hash::new(&in1).into();
    let sig1 = (G2Projective::from(hash_to_g2(&msg1)) * sk1)
        .to_affine()
        .to_compressed();
    // Item 2: proof content is irrelevant because the host rejects the
    // mismatched network identity before verification.
    let sk2 = {
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = (i as u8) + 17;
        }
        Scalar::from_bytes_be(&b).unwrap()
    };
    let pk2 = (G2Projective::generator() * sk2)
        .to_affine()
        .to_compressed();
    let input2 = b"in-bad";
    let mut in2 = Vec::new();
    in2.extend_from_slice(b"iroha:vrf:v1:input|");
    in2.extend_from_slice(bad_network_id.as_bytes());
    in2.push(b'|');
    in2.extend_from_slice(input2);
    let msg2: [u8; 32] = iroha_crypto::Hash::new(&in2).into();
    let sig2 = (G1Projective::from(hash_to_g1(&msg2)) * sk2)
        .to_affine()
        .to_compressed();
    let req = VrfVerifyBatchRequest {
        items: vec![
            VrfVerifyRequest {
                variant: 1,
                pk: pk1.to_vec(),
                proof: sig1.to_vec(),
                network_id: host_network_id,
                input: input1.to_vec(),
            },
            VrfVerifyRequest {
                variant: 2,
                pk: pk2.to_vec(),
                proof: sig2.to_vec(),
                network_id: bad_network_id,
                input: input2.to_vec(),
            },
        ],
    };
    let body = norito::to_bytes(&req).expect("encode batch");
    let tlv_env = make_tlv(PointerType::NoritoBytes as u16, &body);
    let mut vm = IVM::new(vrf_batch_vm_gas(body.len()));
    vm.set_host(DefaultHost::new().with_network_id(host_network_id));
    vm.memory.preload_input(0, &tlv_env).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    let prog = assemble_syscalls(&[ivm::syscalls::SYSCALL_VRF_VERIFY_BATCH as u8]);
    vm.load_program(&prog).unwrap();
    vm.run().unwrap();
    assert_eq!(vm.register(11), 8, "status must be ERR_NETWORK (8)");
    assert_eq!(vm.register(12), 1, "failing index must be 1");
    assert_eq!(vm.register(10), 0, "output pointer must be 0 on error");
}
#[test]
fn syscall_vrf_verify_batch_rejects_inert_material_with_index() {
    let network_id = common::test_network_id(0x51);
    let input = b"ivm:vrf:batch-inert";
    let cases = [
        (
            VrfVerifyRequest {
                variant: 1,
                pk: vec![0u8; 48],
                proof: G2Affine::generator().to_compressed().to_vec(),
                network_id,
                input: input.to_vec(),
            },
            4,
            "all-zero normal public key",
        ),
        (
            VrfVerifyRequest {
                variant: 1,
                pk: G1Affine::generator().to_compressed().to_vec(),
                proof: vec![0u8; 96],
                network_id,
                input: input.to_vec(),
            },
            5,
            "all-zero normal proof",
        ),
        (
            VrfVerifyRequest {
                variant: 2,
                pk: G2Affine::identity().to_compressed().to_vec(),
                proof: G1Affine::generator().to_compressed().to_vec(),
                network_id,
                input: input.to_vec(),
            },
            4,
            "identity small public key",
        ),
        (
            VrfVerifyRequest {
                variant: 2,
                pk: G2Affine::generator().to_compressed().to_vec(),
                proof: G1Affine::identity().to_compressed().to_vec(),
                network_id,
                input: input.to_vec(),
            },
            5,
            "identity small proof",
        ),
    ];
    for (item, expected_status, label) in cases {
        let req = VrfVerifyBatchRequest { items: vec![item] };
        let (output_ptr, status, failed_index) = run_vrf_verify_batch(req);
        assert_eq!(output_ptr, 0, "{label} must not return output");
        assert_eq!(status, expected_status, "{label} status");
        assert_eq!(failed_index, 0, "{label} failed index");
    }
}
