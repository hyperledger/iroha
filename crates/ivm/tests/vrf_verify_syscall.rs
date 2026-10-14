//! VRF syscall verification and exact-network binding tests.
use crate::common;
use ivm::{IVM, Memory, PointerType};
// Helpers: BLS Hash-to-curve mirroring host logic
use blstrs::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use common::assemble_syscalls;
use group::{Curve, Group, prime::PrimeCurveAffine};
use ivm::vrf::VrfVerifyRequest;
fn vrf_vm_gas(payload_len: usize) -> u64 {
    ivm::gas::vrf_verify_gas(1, u64::try_from(payload_len).unwrap_or(u64::MAX))
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
fn run_vrf_verify(req: VrfVerifyRequest) -> (u64, u64) {
    let network_id = req.network_id;
    let body = norito::to_bytes(&req).expect("encode vrf request");
    let tlv_env = make_tlv(PointerType::NoritoBytes as u16, &body);
    let mut vm = IVM::new(vrf_vm_gas(body.len()));
    vm.set_host(ivm::host::DefaultHost::new().with_network_id(network_id));
    vm.memory.preload_input(0, &tlv_env).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    let prog = assemble_syscalls(&[ivm::syscalls::SYSCALL_VRF_VERIFY as u8]);
    vm.load_program(&prog).unwrap();
    vm.run().unwrap();
    (vm.register(10), vm.register(11))
}
#[test]
fn syscall_vrf_verify_normal_returns_expected_output() {
    // Deterministic secret key from seed 0x01..0x20
    let mut seed32 = [0u8; 32];
    for (i, b) in seed32.iter_mut().enumerate() {
        *b = (i as u8) + 1;
    }
    let sk = Scalar::from_bytes_be(&seed32).expect("scalar from seed");
    let pk = (G1Projective::generator() * sk).to_affine();
    let pk_bytes = pk.to_compressed();
    // Input and message prehash (with exact network identity).
    let input = b"ivm:vrf:test";
    let network_id = common::test_network_id(0x41);
    let network_bytes = network_id.as_bytes();
    let mut in_buf =
        Vec::with_capacity(b"iroha:vrf:v1:input|".len() + network_bytes.len() + 1 + input.len());
    in_buf.extend_from_slice(b"iroha:vrf:v1:input|");
    in_buf.extend_from_slice(network_bytes);
    in_buf.push(b'|');
    in_buf.extend_from_slice(input);
    let msg: [u8; 32] = iroha_crypto::Hash::new(&in_buf).into();
    // Signature in G2: sigma = H2(msg)^sk
    let h = hash_to_g2(&msg);
    let sigma = (G2Projective::from(h) * sk).to_affine().to_compressed();
    // Expected output: y = Hash("iroha:vrf:v1:output" || sigma)
    let mut out_buf = Vec::with_capacity(b"iroha:vrf:v1:output".len() + sigma.len());
    out_buf.extend_from_slice(b"iroha:vrf:v1:output");
    out_buf.extend_from_slice(&sigma);
    let y_exp: [u8; 32] = iroha_crypto::Hash::new(&out_buf).into();
    // Build Norito envelope and TLV
    let req = VrfVerifyRequest {
        variant: 1,
        pk: pk_bytes.to_vec(),
        proof: sigma.to_vec(),
        network_id,
        input: input.to_vec(),
    };
    let body = norito::to_bytes(&req).expect("encode vrf request");
    let tlv_env = make_tlv(PointerType::NoritoBytes as u16, &body);
    let mut vm = IVM::new(vrf_vm_gas(body.len()));
    vm.set_host(ivm::host::DefaultHost::new().with_network_id(network_id));
    vm.memory.preload_input(0, &tlv_env).expect("preload input");
    let p_env = Memory::INPUT_START;
    vm.set_register(10, p_env);
    let prog = assemble_syscalls(&[ivm::syscalls::SYSCALL_VRF_VERIFY as u8]);
    vm.load_program(&prog).unwrap();
    vm.run().unwrap();
    let p_out = vm.register(10);
    let status = vm.register(11);
    assert_eq!(status, 0, "status must be OK");
    assert!(p_out != 0, "must return output pointer on success");
    // Validate returned TLV
    let tlv = vm.memory.validate_tlv(p_out).expect("valid tlv");
    assert_eq!(tlv.type_id, PointerType::Blob);
    assert_eq!(tlv.payload.len(), 32);
    assert_eq!(tlv.payload, &y_exp);
}
#[test]
fn syscall_vrf_verify_network_mismatch_rejected() {
    use blstrs::{G2Projective, Scalar};
    // Prover side: build a valid tuple for network A.
    let sk = {
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = (i as u8) + 7;
        }
        Scalar::from_bytes_be(&b).unwrap()
    };
    let pk_g1 = (G1Projective::generator() * sk).to_affine().to_compressed();
    let input = b"in";
    let network_a = common::test_network_id(0x41);
    let network_b = common::test_network_id(0x42);
    let mut m = Vec::new();
    m.extend_from_slice(b"iroha:vrf:v1:input|");
    m.extend_from_slice(network_a.as_bytes());
    m.push(b'|');
    m.extend_from_slice(input);
    let msg: [u8; 32] = iroha_crypto::Hash::new(&m).into();
    let sig = (G2Projective::from(hash_to_g2(&msg)) * sk)
        .to_affine()
        .to_compressed();
    // A host configured for network B must reject a network-A envelope.
    let req = VrfVerifyRequest {
        variant: 1,
        pk: pk_g1.to_vec(),
        proof: sig.to_vec(),
        network_id: network_a,
        input: input.to_vec(),
    };
    let body = norito::to_bytes(&req).expect("encode req");
    let tlv_env = make_tlv(PointerType::NoritoBytes as u16, &body);
    let mut vm = IVM::new(vrf_vm_gas(body.len()));
    vm.set_host(ivm::host::DefaultHost::new().with_network_id(network_b));
    vm.memory.preload_input(0, &tlv_env).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    let prog = assemble_syscalls(&[ivm::syscalls::SYSCALL_VRF_VERIFY as u8]);
    vm.load_program(&prog).unwrap();
    vm.run().unwrap();
    assert_eq!(vm.register(10), 0, "no output pointer on network mismatch");
    assert_eq!(vm.register(11), 8, "ERR_NETWORK=8");
}
#[test]
fn syscall_vrf_verify_rejects_wrong_proof_length() {
    // Deterministic secret key
    let mut seed32 = [0u8; 32];
    for (i, b) in seed32.iter_mut().enumerate() {
        *b = (i as u8) + 3;
    }
    let sk = Scalar::from_bytes_be(&seed32).expect("scalar from seed");
    let pk = (G1Projective::generator() * sk).to_affine();
    let pk_bytes = pk.to_compressed();
    // Input prehash
    let input = b"ivm:vrf:test:neg";
    let network_id = common::test_network_id(0x41);
    let network_bytes = network_id.as_bytes();
    let mut in_buf =
        Vec::with_capacity(b"iroha:vrf:v1:input|".len() + network_bytes.len() + 1 + input.len());
    in_buf.extend_from_slice(b"iroha:vrf:v1:input|");
    in_buf.extend_from_slice(network_bytes);
    in_buf.push(b'|');
    in_buf.extend_from_slice(input);
    let msg: [u8; 32] = iroha_crypto::Hash::new(&in_buf).into();
    // Construct a G1 signature (48 bytes), but claim variant=1 (SigInG2 required)
    let h1 = hash_to_g1(&msg);
    let sig_g1 = (G1Projective::from(h1) * sk).to_affine().to_compressed();
    let req = VrfVerifyRequest {
        variant: 1,
        pk: pk_bytes.to_vec(),
        proof: sig_g1.to_vec(),
        network_id,
        input: input.to_vec(),
    };
    let body = norito::to_bytes(&req).expect("encode");
    let tlv_env = make_tlv(PointerType::NoritoBytes as u16, &body);
    let mut vm = IVM::new(vrf_vm_gas(body.len()));
    vm.set_host(ivm::host::DefaultHost::new().with_network_id(network_id));
    vm.memory.preload_input(0, &tlv_env).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    let prog = assemble_syscalls(&[ivm::syscalls::SYSCALL_VRF_VERIFY as u8]);
    vm.load_program(&prog).unwrap();
    vm.run().unwrap();
    assert_eq!(vm.register(10), 0, "no output on failure");
    let status = vm.register(11);
    // Expect ERR_PROOF (5) or ERR_VERIFY (6) depending on exact failure point
    assert!(status == 5 || status == 6, "unexpected status: {status}");
}
#[test]
fn syscall_vrf_verify_rejects_inert_normal_material_before_pairing() {
    let network_id = common::test_network_id(0x41);
    let input = b"ivm:vrf:inert";
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
                variant: 1,
                pk: G1Affine::identity().to_compressed().to_vec(),
                proof: G2Affine::generator().to_compressed().to_vec(),
                network_id,
                input: input.to_vec(),
            },
            4,
            "identity normal public key",
        ),
        (
            VrfVerifyRequest {
                variant: 1,
                pk: G1Affine::generator().to_compressed().to_vec(),
                proof: G2Affine::identity().to_compressed().to_vec(),
                network_id,
                input: input.to_vec(),
            },
            5,
            "identity normal proof",
        ),
    ];
    for (req, expected_status, label) in cases {
        let (output_ptr, status) = run_vrf_verify(req);
        assert_eq!(output_ptr, 0, "{label} must not return output");
        assert_eq!(status, expected_status, "{label} status");
    }
}
#[test]
fn syscall_vrf_verify_rejects_inert_small_material_before_pairing() {
    let network_id = common::test_network_id(0x41);
    let input = b"ivm:vrf:inert-small";
    let cases = [
        (
            VrfVerifyRequest {
                variant: 2,
                pk: vec![0u8; 96],
                proof: G1Affine::generator().to_compressed().to_vec(),
                network_id,
                input: input.to_vec(),
            },
            4,
            "all-zero small public key",
        ),
        (
            VrfVerifyRequest {
                variant: 2,
                pk: G2Affine::generator().to_compressed().to_vec(),
                proof: vec![0u8; 48],
                network_id,
                input: input.to_vec(),
            },
            5,
            "all-zero small proof",
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
    for (req, expected_status, label) in cases {
        let (output_ptr, status) = run_vrf_verify(req);
        assert_eq!(output_ptr, 0, "{label} must not return output");
        assert_eq!(status, expected_status, "{label} status");
    }
}
