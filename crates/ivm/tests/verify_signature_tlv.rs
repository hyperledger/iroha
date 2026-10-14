//! Signature verification opcode/syscall tests using TLVs.
use crate::common;
use common::assemble;
use ivm::signature::{Ed25519BatchEntry, Ed25519BatchRequest};
use ivm::{IVM, Memory, PointerType, VMError, encoding, instruction};
const ED25519_SMALL_ORDER_POINT: [u8; 32] = [
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
const ED25519_NON_CANONICAL_IDENTITY: [u8; 32] = [
    0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];
const ED25519_NON_CANONICAL_NON_SMALL_ORDER_POINT: [u8; 32] = [
    0xf0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];
fn make_tlv(type_id: u16, payload: &[u8]) -> Vec<u8> {
    use iroha_crypto::Hash;
    let mut out = Vec::with_capacity(7 + payload.len() + 32);
    out.extend_from_slice(&type_id.to_be_bytes());
    out.push(1); // version
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload.as_ref());
    let h: [u8; 32] = Hash::new(payload).into();
    out.extend_from_slice(&h);
    out
}
fn direct_signature_program(opcode: u8) -> (u32, Vec<u8>) {
    let word = encoding::wide::encode_rr(opcode, 3, 1, 2);
    let mut code = word.to_le_bytes().to_vec();
    code.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    (word, code)
}
fn aliased_signature_operand_vm(opcode: u8, payload_len: usize, gas: u64) -> IVM {
    let tlv = make_tlv(PointerType::Blob as u16, &vec![0xA5; payload_len]);
    let mut vm = IVM::new(gas);
    vm.memory
        .preload_input(0, &tlv)
        .expect("aliased signature operand fits INPUT");
    for register in 1..=3 {
        vm.set_register(register, Memory::INPUT_START);
    }
    let (_, code) = direct_signature_program(opcode);
    vm.memory.load_code(&code).unwrap();
    vm
}
fn ed25519_test_key(tag: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[tag; 32])
}
#[test]
fn direct_signature_opcodes_charge_each_aliased_payload_before_hashing() {
    const PAYLOAD_LEN: usize = 48 * 1024;
    for opcode in [
        instruction::wide::crypto::ED25519VERIFY,
        instruction::wide::crypto::ECDSAVERIFY,
        instruction::wide::crypto::DILITHIUMVERIFY,
    ] {
        let (word, _) = direct_signature_program(opcode);
        let base = ivm::gas::cost_of(word).expect("signature opcode must be scheduled");
        let payload_len = u64::try_from(PAYLOAD_LEN).unwrap();
        let surcharge = ivm::gas::signature_opcode_extra_gas(payload_len, payload_len, payload_len)
            .expect("test surcharge fits u64");

        let mut exact = aliased_signature_operand_vm(opcode, PAYLOAD_LEN, base + surcharge);
        exact
            .run()
            .expect("the exact byte-linear signature budget must succeed");
        assert_eq!(exact.gas_remaining, 0, "opcode {opcode:#x}");
        assert_eq!(exact.register(3), 0, "oversized key material must reject");

        let mut short = aliased_signature_operand_vm(opcode, PAYLOAD_LEN, base + surcharge - 1);
        assert!(
            matches!(short.run(), Err(VMError::OutOfGas)),
            "opcode {opcode:#x}"
        );
        assert_eq!(
            short.gas_remaining,
            surcharge - 1,
            "the surcharge must fail atomically after the fixed opcode debit"
        );
    }
}

#[test]
fn direct_signature_opcodes_reject_unknown_tlv_version_without_byte_surcharge() {
    const PAYLOAD_LEN: usize = 48 * 1024;
    for opcode in [
        instruction::wide::crypto::ED25519VERIFY,
        instruction::wide::crypto::ECDSAVERIFY,
        instruction::wide::crypto::DILITHIUMVERIFY,
    ] {
        let (word, code) = direct_signature_program(opcode);
        let base = ivm::gas::cost_of(word).expect("signature opcode must be scheduled");
        let mut tlv = make_tlv(PointerType::Blob as u16, &vec![0xA5; PAYLOAD_LEN]);
        tlv[2] = 2; // unsupported pointer-ABI envelope version

        let mut vm = IVM::new(base);
        vm.memory
            .preload_input(0, &tlv)
            .expect("unknown-version signature operand fits INPUT");
        for register in 1..=3 {
            vm.set_register(register, Memory::INPUT_START);
        }
        vm.memory.load_code(&code).unwrap();

        vm.run()
            .expect("a header-rejected envelope must consume only the opcode base");
        assert_eq!(vm.gas_remaining, 0, "opcode {opcode:#x}");
        assert_eq!(vm.register(3), 0, "unknown TLV versions must reject");
    }
}

#[test]
fn direct_signature_preflight_reports_private_memory_after_a_malformed_operand() {
    let opcode = instruction::wide::crypto::ED25519VERIFY;
    let signature_word = encoding::wide::encode_rr(opcode, 3, 1, 2);
    let private_store = encoding::wide::encode_store(instruction::wide::memory::STORE64, 20, 21, 0);
    let mut program = ivm::ProgramMetadata {
        mode: ivm::ivm_mode::ZK,
        max_cycles: 32,
        ..ivm::ProgramMetadata::default()
    }
    .encode();
    for word in [private_store, signature_word, encoding::wide::encode_halt()] {
        program.extend_from_slice(&word.to_le_bytes());
    }
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&program)
        .expect("load ZK signature fixture");

    let payload = [0x5A; 8];
    let tlv = make_tlv(PointerType::Blob as u16, &payload);
    let tlv_pointer = Memory::STACK_START + 1;
    vm.store_bytes(tlv_pointer, &tlv)
        .expect("store stack-owned TLV fixture");
    vm.set_register(20, Memory::STACK_START + 8);
    vm.set_register(21, u64::from_le_bytes(payload));
    vm.registers.set_tag(21, true);

    vm.set_register(1, 0); // malformed public message pointer
    vm.set_register(2, tlv_pointer); // later private signature range
    vm.set_register(3, 0);
    assert!(matches!(vm.run(), Err(VMError::PrivacyViolation)));
}

#[test]
fn direct_signature_preflight_classifies_overflowing_public_pointers_as_malformed() {
    let opcode = instruction::wide::crypto::ED25519VERIFY;
    let signature_word = encoding::wide::encode_rr(opcode, 3, 1, 2);
    let private_store = encoding::wide::encode_store(instruction::wide::memory::STORE64, 20, 21, 0);
    let mut program = ivm::ProgramMetadata {
        mode: ivm::ivm_mode::ZK,
        max_cycles: 32,
        ..ivm::ProgramMetadata::default()
    }
    .encode();
    for word in [private_store, signature_word, encoding::wide::encode_halt()] {
        program.extend_from_slice(&word.to_le_bytes());
    }
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&program)
        .expect("load ZK signature overflow fixture");
    vm.set_register(20, Memory::STACK_START + 8);
    vm.set_register(21, 0x5A5A_A5A5);
    vm.registers.set_tag(21, true);
    for register in 1..=3 {
        vm.set_register(register, u64::MAX);
    }

    vm.run()
        .expect("overflowing public pointers are malformed, not private");
    assert_eq!(vm.register(3), 0);
}
fn ed25519_signature_with_replacement_r(
    signing_key: &ed25519_dalek::SigningKey,
    message: &[u8],
    replacement_r: &[u8; 32],
) -> [u8; 64] {
    use ed25519_dalek::Signer;
    let mut signature = signing_key.sign(message).to_bytes();
    signature[..32].copy_from_slice(replacement_r);
    signature
}
fn run_syscall_verify_signature_blob(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
    scheme: u64,
) -> u64 {
    let msg_tlv = make_tlv(PointerType::Blob as u16, message);
    let sig_tlv = make_tlv(PointerType::Blob as u16, signature);
    let pk_tlv = make_tlv(PointerType::Blob as u16, public_key);
    let mut vm = IVM::new(10_000);
    vm.memory.preload_input(0, &msg_tlv).expect("preload input");
    let p_msg = Memory::INPUT_START;
    let p_sig = p_msg + msg_tlv.len() as u64 + 8;
    let p_pk = p_sig + sig_tlv.len() as u64 + 8;
    vm.memory
        .preload_input(msg_tlv.len() as u64 + 8, &sig_tlv)
        .expect("preload input");
    vm.memory
        .preload_input((msg_tlv.len() + sig_tlv.len()) as u64 + 16, &pk_tlv)
        .expect("preload input");
    vm.set_register(10, p_msg);
    vm.set_register(11, p_sig);
    vm.set_register(12, p_pk);
    vm.set_register(13, scheme);
    let halt = encoding::wide::encode_halt();
    let syscall = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm::syscalls::SYSCALL_VERIFY_SIGNATURE as u8,
    );
    let mut prog = Vec::new();
    prog.extend_from_slice(&syscall.to_le_bytes());
    prog.extend_from_slice(&halt.to_le_bytes());
    let prog = assemble(&prog);
    vm.load_program(&prog).unwrap();
    vm.run().unwrap();
    vm.register(10)
}
fn run_syscall_verify_signature_ed25519(
    message_type: PointerType,
    message: &[u8],
    key_tag: u8,
) -> Result<u64, VMError> {
    use ed25519_dalek::Signer;
    let sk = ed25519_test_key(key_tag);
    let pk_bytes = sk.verifying_key().to_bytes();
    let sig = sk.sign(message);
    let msg_payload = match message_type {
        PointerType::Json => {
            let raw = std::str::from_utf8(message).expect("json message utf8");
            let json = iroha_primitives::json::Json::from_str_norito(raw).expect("valid json");
            norito::to_bytes(&json).expect("encode json payload")
        }
        _ => message.to_vec(),
    };
    let msg_tlv = make_tlv(message_type as u16, &msg_payload);
    let sig_tlv = make_tlv(PointerType::Blob as u16, &sig.to_bytes());
    let pk_tlv = make_tlv(PointerType::Blob as u16, &pk_bytes);
    let mut vm = IVM::new(10_000);
    vm.memory.preload_input(0, &msg_tlv).expect("preload input");
    let p_msg = Memory::INPUT_START;
    let p_sig = p_msg + msg_tlv.len() as u64 + 8;
    let p_pk = p_sig + sig_tlv.len() as u64 + 8;
    vm.memory
        .preload_input(msg_tlv.len() as u64 + 8, &sig_tlv)
        .expect("preload input");
    vm.memory
        .preload_input((msg_tlv.len() + sig_tlv.len()) as u64 + 16, &pk_tlv)
        .expect("preload input");
    vm.set_register(10, p_msg);
    vm.set_register(11, p_sig);
    vm.set_register(12, p_pk);
    vm.set_register(13, 1); // scheme 1 = Ed25519
    let halt = encoding::wide::encode_halt();
    let syscall = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm::syscalls::SYSCALL_VERIFY_SIGNATURE as u8,
    );
    let mut prog = Vec::new();
    prog.extend_from_slice(&syscall.to_le_bytes());
    prog.extend_from_slice(&halt.to_le_bytes());
    let prog = assemble(&prog);
    vm.load_program(&prog).unwrap();
    vm.run()?;
    Ok(vm.register(10))
}
#[test]
fn verify_signature_helper_rejects_all_zero_signature_material() {
    use ivm::signature::{SignatureScheme, verify_signature};
    use pqcrypto_mldsa::mldsa65 as dilithium;
    use pqcrypto_traits::sign::PublicKey;
    let ed_key = ed25519_test_key(0x41);
    assert!(
        !verify_signature(
            SignatureScheme::Ed25519,
            b"ivm-ed25519-zero",
            &[0u8; 64],
            &ed_key.verifying_key().to_bytes(),
        ),
        "all-zero Ed25519 signature material must fail"
    );
    let (ml_public_key, _) = dilithium::keypair();
    let ml_signature = vec![0u8; dilithium::signature_bytes()];
    assert!(
        !verify_signature(
            SignatureScheme::MlDsa,
            b"ivm-mldsa-zero",
            &ml_signature,
            ml_public_key.as_bytes(),
        ),
        "all-zero ML-DSA signature material must fail"
    );
}
#[test]
fn verify_signature_helper_rejects_all_zero_mldsa_public_key_material() {
    use ivm::signature::{SignatureScheme, verify_signature};
    use pqcrypto_mldsa::mldsa65 as dilithium;
    use pqcrypto_traits::sign::DetachedSignature;
    let (_, secret_key) = dilithium::keypair();
    let message = b"ivm-mldsa-zero-public-key";
    let signature = dilithium::detached_sign(message, &secret_key);
    let public_key = vec![0u8; dilithium::public_key_bytes()];
    assert!(
        !verify_signature(
            SignatureScheme::MlDsa,
            message,
            signature.as_bytes(),
            &public_key,
        ),
        "all-zero ML-DSA public-key material must fail"
    );
}
#[test]
fn syscall_verify_signature_ed25519_rejects_weak_public_key_material() {
    use ed25519_dalek::Signer;
    let message = b"ivm-ed25519-weak-public-key";
    let signing_key = ed25519_test_key(0x42);
    let signature = signing_key.sign(message);
    assert_eq!(
        run_syscall_verify_signature_blob(message, &signature.to_bytes(), &[0u8; 32], 1),
        0
    );
}
#[test]
fn syscall_verify_signature_ed25519_rejects_malformed_public_key_material() {
    use ed25519_dalek::Signer;
    let message = b"ivm-ed25519-malformed-public-key";
    let signing_key = ed25519_test_key(0x47);
    let signature = signing_key.sign(message).to_bytes();
    for (label, public_key) in [
        ("small-order", ED25519_SMALL_ORDER_POINT),
        ("noncanonical", ED25519_NON_CANONICAL_IDENTITY),
        (
            "noncanonical-non-small-order",
            ED25519_NON_CANONICAL_NON_SMALL_ORDER_POINT,
        ),
    ] {
        assert_eq!(
            run_syscall_verify_signature_blob(message, &signature, &public_key, 1),
            0,
            "{label} public key must reject"
        );
    }
}
#[test]
fn syscall_verify_signature_ed25519_rejects_malformed_signature_r() {
    let message = b"ivm-ed25519-malformed-r";
    let signing_key = ed25519_test_key(0x45);
    let public_key = signing_key.verifying_key().to_bytes();
    for (label, replacement_r) in [
        ("small-order", ED25519_SMALL_ORDER_POINT),
        ("noncanonical", ED25519_NON_CANONICAL_IDENTITY),
    ] {
        let signature = ed25519_signature_with_replacement_r(&signing_key, message, &replacement_r);
        assert_eq!(
            run_syscall_verify_signature_blob(message, &signature, &public_key, 1),
            0,
            "{label} signature R must reject"
        );
    }
}
#[test]
fn syscall_verify_signature_rejects_wide_scheme_code_without_truncation() {
    use ed25519_dalek::Signer;
    let message = b"ivm-ed25519-wide-scheme-code";
    let signing_key = ed25519_test_key(0x46);
    let public_key = signing_key.verifying_key().to_bytes();
    let signature = signing_key.sign(message).to_bytes();
    assert_eq!(
        run_syscall_verify_signature_blob(message, &signature, &public_key, 1),
        1,
        "control signature must verify under the canonical scheme code"
    );
    assert_eq!(
        run_syscall_verify_signature_blob(message, &signature, &public_key, 0x101),
        0,
        "a wide register value must not alias the Ed25519 scheme after narrowing"
    );
}
#[test]
fn syscall_verify_signature_secp256k1_via_tlv() {
    use iroha_crypto::{EcdsaSecp256k1Sha256, KeyGenOption};
    let (pk, sk) = EcdsaSecp256k1Sha256::keypair(KeyGenOption::UseSeed(vec![0x11; 32]));
    let pk_bytes = pk.to_sec1_bytes();
    let msg = b"ivm-secp256k1";
    let sig_bytes = EcdsaSecp256k1Sha256::sign(msg, &sk);
    let msg_tlv = make_tlv(PointerType::Blob as u16, msg);
    let sig_tlv = make_tlv(PointerType::Blob as u16, &sig_bytes);
    let pk_tlv = make_tlv(PointerType::Blob as u16, &pk_bytes);
    let mut vm = IVM::new(10_000);
    vm.memory.preload_input(0, &msg_tlv).expect("preload input");
    let p_msg = Memory::INPUT_START;
    let p_sig = p_msg + msg_tlv.len() as u64 + 8;
    let p_pk = p_sig + sig_tlv.len() as u64 + 8;
    vm.memory
        .preload_input(msg_tlv.len() as u64 + 8, &sig_tlv)
        .expect("preload input");
    vm.memory
        .preload_input((msg_tlv.len() + sig_tlv.len()) as u64 + 16, &pk_tlv)
        .expect("preload input");
    vm.set_register(10, p_msg);
    vm.set_register(11, p_sig);
    vm.set_register(12, p_pk);
    vm.set_register(13, 2); // scheme 2 = Secp256k1
    let halt = encoding::wide::encode_halt();
    let syscall = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm::syscalls::SYSCALL_VERIFY_SIGNATURE as u8,
    );
    let mut prog = Vec::new();
    prog.extend_from_slice(&syscall.to_le_bytes());
    prog.extend_from_slice(&halt.to_le_bytes());
    let prog = assemble(&prog);
    vm.load_program(&prog).unwrap();
    vm.run().unwrap();
    assert_eq!(vm.register(10), 1);
}
#[test]
fn syscall_verify_signature_rejects_all_zero_ed25519_signature_material() {
    let key = ed25519_test_key(0x42);
    let result = run_syscall_verify_signature_blob(
        b"ivm-ed25519-zero-syscall",
        &[0u8; 64],
        &key.verifying_key().to_bytes(),
        1,
    );
    assert_eq!(result, 0);
}
#[test]
fn syscall_verify_signature_rejects_all_zero_mldsa_signature_material() {
    use pqcrypto_mldsa::mldsa65 as dilithium;
    use pqcrypto_traits::sign::PublicKey;
    let (public_key, _) = dilithium::keypair();
    let signature = vec![0u8; dilithium::signature_bytes()];
    let result = run_syscall_verify_signature_blob(
        b"ivm-mldsa-zero-syscall",
        &signature,
        public_key.as_bytes(),
        3,
    );
    assert_eq!(result, 0);
}
#[test]
fn syscall_verify_signature_rejects_all_zero_mldsa_public_key_material() {
    use pqcrypto_mldsa::mldsa65 as dilithium;
    use pqcrypto_traits::sign::DetachedSignature;
    let (_, secret_key) = dilithium::keypair();
    let message = b"ivm-mldsa-zero-public-key-syscall";
    let signature = dilithium::detached_sign(message, &secret_key);
    let public_key = vec![0u8; dilithium::public_key_bytes()];
    let result = run_syscall_verify_signature_blob(message, signature.as_bytes(), &public_key, 3);
    assert_eq!(result, 0);
}
#[test]
fn syscall_verify_signature_dilithium_via_tlv() {
    use pqcrypto_mldsa::mldsa65 as dilithium;
    use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
    let (pk, sk) = dilithium::keypair();
    let msg = b"ivm-dilithium";
    let sig = dilithium::detached_sign(msg, &sk);
    let msg_tlv = make_tlv(PointerType::Blob as u16, msg);
    let sig_tlv = make_tlv(PointerType::Blob as u16, sig.as_bytes());
    let pk_tlv = make_tlv(PointerType::Blob as u16, pk.as_bytes());
    let mut vm = IVM::new(10_000);
    vm.memory.preload_input(0, &msg_tlv).expect("preload input");
    let p_msg = Memory::INPUT_START;
    let p_sig = p_msg + msg_tlv.len() as u64 + 8;
    let p_pk = p_sig + sig_tlv.len() as u64 + 8;
    vm.memory
        .preload_input(msg_tlv.len() as u64 + 8, &sig_tlv)
        .expect("preload input");
    vm.memory
        .preload_input((msg_tlv.len() + sig_tlv.len()) as u64 + 16, &pk_tlv)
        .expect("preload input");
    vm.set_register(10, p_msg);
    vm.set_register(11, p_sig);
    vm.set_register(12, p_pk);
    vm.set_register(13, 3); // scheme 3 = Dilithium
    let halt = encoding::wide::encode_halt();
    let syscall = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        ivm::syscalls::SYSCALL_VERIFY_SIGNATURE as u8,
    );
    let mut prog = Vec::new();
    prog.extend_from_slice(&syscall.to_le_bytes());
    prog.extend_from_slice(&halt.to_le_bytes());
    let prog = assemble(&prog);
    vm.load_program(&prog).unwrap();
    vm.run().unwrap();
    assert_eq!(vm.register(10), 1);
}
#[test]
fn opcode_verify_ed25519_rejects_all_zero_signature_material() {
    let sk = ed25519_test_key(0x43);
    let pk_bytes = sk.verifying_key().to_bytes();
    let msg = b"ivm-op-ed25519-zero";
    let sig_tlv = make_tlv(PointerType::Blob as u16, &[0u8; 64]);
    let msg_tlv = make_tlv(PointerType::Blob as u16, msg);
    let pk_tlv = make_tlv(PointerType::Blob as u16, &pk_bytes);
    let mut vm = IVM::new(10_000);
    vm.memory.preload_input(0, &msg_tlv).expect("preload input");
    let p_msg = Memory::INPUT_START;
    let p_sig = p_msg + msg_tlv.len() as u64 + 8;
    let p_pk = p_sig + sig_tlv.len() as u64 + 8;
    vm.memory
        .preload_input(msg_tlv.len() as u64 + 8, &sig_tlv)
        .expect("preload input");
    vm.memory
        .preload_input((msg_tlv.len() + sig_tlv.len()) as u64 + 16, &pk_tlv)
        .expect("preload input");
    vm.set_register(1, p_msg);
    vm.set_register(2, p_sig);
    vm.set_register(3, p_pk);
    let word = encoding::wide::encode_rr(instruction::wide::crypto::ED25519VERIFY, 3, 1, 2);
    let halt = encoding::wide::encode_halt().to_le_bytes();
    let mut code = Vec::new();
    code.extend_from_slice(&word.to_le_bytes());
    code.extend_from_slice(&halt);
    vm.memory.load_code(&code).unwrap();
    vm.run().unwrap();
    assert_eq!(vm.register(3), 0);
}
#[test]
fn opcode_verify_ed25519_rejects_malformed_public_key_material() {
    use ed25519_dalek::Signer;
    let sk = ed25519_test_key(0x48);
    let msg = b"ivm-op-ed25519-malformed-public-key";
    let signature = sk.sign(msg).to_bytes();
    for (label, public_key) in [
        ("small-order", ED25519_SMALL_ORDER_POINT),
        ("noncanonical", ED25519_NON_CANONICAL_IDENTITY),
        (
            "noncanonical-non-small-order",
            ED25519_NON_CANONICAL_NON_SMALL_ORDER_POINT,
        ),
    ] {
        let sig_tlv = make_tlv(PointerType::Blob as u16, &signature);
        let msg_tlv = make_tlv(PointerType::Blob as u16, msg);
        let pk_tlv = make_tlv(PointerType::Blob as u16, &public_key);
        let mut vm = IVM::new(10_000);
        vm.memory.preload_input(0, &msg_tlv).expect("preload input");
        let p_msg = Memory::INPUT_START;
        let p_sig = p_msg + msg_tlv.len() as u64 + 8;
        let p_pk = p_sig + sig_tlv.len() as u64 + 8;
        vm.memory
            .preload_input(msg_tlv.len() as u64 + 8, &sig_tlv)
            .expect("preload input");
        vm.memory
            .preload_input((msg_tlv.len() + sig_tlv.len()) as u64 + 16, &pk_tlv)
            .expect("preload input");
        vm.set_register(1, p_msg);
        vm.set_register(2, p_sig);
        vm.set_register(3, p_pk);
        let word = encoding::wide::encode_rr(instruction::wide::crypto::ED25519VERIFY, 3, 1, 2);
        let halt = encoding::wide::encode_halt().to_le_bytes();
        let mut code = Vec::new();
        code.extend_from_slice(&word.to_le_bytes());
        code.extend_from_slice(&halt);
        vm.memory.load_code(&code).unwrap();
        vm.run().unwrap();
        assert_eq!(vm.register(3), 0, "{label} public key must reject");
    }
}
#[test]
fn opcode_verify_ed25519_rejects_malformed_signature_r() {
    let sk = ed25519_test_key(0x46);
    let pk_bytes = sk.verifying_key().to_bytes();
    let msg = b"ivm-op-ed25519-malformed-r";
    for (label, replacement_r) in [
        ("small-order", ED25519_SMALL_ORDER_POINT),
        ("noncanonical", ED25519_NON_CANONICAL_IDENTITY),
    ] {
        let signature = ed25519_signature_with_replacement_r(&sk, msg, &replacement_r);
        let sig_tlv = make_tlv(PointerType::Blob as u16, &signature);
        let msg_tlv = make_tlv(PointerType::Blob as u16, msg);
        let pk_tlv = make_tlv(PointerType::Blob as u16, &pk_bytes);
        let mut vm = IVM::new(10_000);
        vm.memory.preload_input(0, &msg_tlv).expect("preload input");
        let p_msg = Memory::INPUT_START;
        let p_sig = p_msg + msg_tlv.len() as u64 + 8;
        let p_pk = p_sig + sig_tlv.len() as u64 + 8;
        vm.memory
            .preload_input(msg_tlv.len() as u64 + 8, &sig_tlv)
            .expect("preload input");
        vm.memory
            .preload_input((msg_tlv.len() + sig_tlv.len()) as u64 + 16, &pk_tlv)
            .expect("preload input");
        vm.set_register(1, p_msg);
        vm.set_register(2, p_sig);
        vm.set_register(3, p_pk);
        let word = encoding::wide::encode_rr(instruction::wide::crypto::ED25519VERIFY, 3, 1, 2);
        let halt = encoding::wide::encode_halt().to_le_bytes();
        let mut code = Vec::new();
        code.extend_from_slice(&word.to_le_bytes());
        code.extend_from_slice(&halt);
        vm.memory.load_code(&code).unwrap();
        vm.run().unwrap();
        assert_eq!(vm.register(3), 0, "{label} signature R must reject");
    }
}
#[test]
fn opcode_verify_ed25519_via_tlv() {
    use ed25519_dalek::Signer;
    let sk = ed25519_test_key(1);
    let pk_bytes = sk.verifying_key().to_bytes();
    let msg = b"ivm-op-ed25519";
    let sig = sk.sign(msg);
    let msg_tlv = make_tlv(PointerType::Blob as u16, msg);
    let sig_tlv = make_tlv(PointerType::Blob as u16, &sig.to_bytes());
    let pk_tlv = make_tlv(PointerType::Blob as u16, &pk_bytes);
    let mut vm = IVM::new(10_000);
    vm.memory.preload_input(0, &msg_tlv).expect("preload input");
    let p_msg = Memory::INPUT_START;
    let p_sig = p_msg + msg_tlv.len() as u64 + 8;
    let p_pk = p_sig + sig_tlv.len() as u64 + 8;
    vm.memory
        .preload_input(msg_tlv.len() as u64 + 8, &sig_tlv)
        .expect("preload input");
    vm.memory
        .preload_input((msg_tlv.len() + sig_tlv.len()) as u64 + 16, &pk_tlv)
        .expect("preload input");
    vm.set_register(1, p_msg);
    vm.set_register(2, p_sig);
    vm.set_register(3, p_pk);
    let op = instruction::wide::crypto::ED25519VERIFY;
    let word = encoding::wide::encode_rr(op, 3, 1, 2); // rd holds pk pointer initially
    let halt = encoding::wide::encode_halt().to_le_bytes();
    let mut code = Vec::new();
    code.extend_from_slice(&word.to_le_bytes());
    code.extend_from_slice(&halt);
    vm.memory.load_code(&code).unwrap();
    vm.run().unwrap();
    assert_eq!(vm.register(3), 1);
}
#[test]
fn opcode_verify_ed25519_batch_reports_all_zero_signature_index() {
    use ed25519_dalek::Signer;
    let sk = ed25519_test_key(0x44);
    let pk_bytes = sk.verifying_key().to_bytes();
    let entries = vec![
        Ed25519BatchEntry {
            message: b"ok-a".to_vec(),
            signature: sk.sign(b"ok-a").to_bytes().to_vec(),
            public_key: pk_bytes.to_vec(),
        },
        Ed25519BatchEntry {
            message: b"zero-b".to_vec(),
            signature: vec![0u8; 64],
            public_key: pk_bytes.to_vec(),
        },
    ];
    let request = Ed25519BatchRequest { entries };
    let payload = norito::to_bytes(&request).expect("encode request");
    let tlv = make_tlv(PointerType::NoritoBytes as u16, &payload);
    let mut vm = IVM::new(10_000);
    let ptr = vm.alloc_input_tlv(&tlv).expect("alloc request");
    vm.set_register(1, ptr);
    vm.set_register(2, 123);
    let word = encoding::wide::encode_rr(instruction::wide::crypto::ED25519BATCHVERIFY, 6, 1, 2);
    let halt = encoding::wide::encode_halt().to_le_bytes();
    let mut code = Vec::new();
    code.extend_from_slice(&word.to_le_bytes());
    code.extend_from_slice(&halt);
    vm.memory.load_code(&code).unwrap();
    vm.run().unwrap();
    assert_eq!(vm.register(6), 0, "batch should fail");
    assert_eq!(vm.register(2), 1, "all-zero entry flagged as failing");
}
#[test]
fn opcode_verify_ed25519_batch_reports_malformed_signature_r_index() {
    use ed25519_dalek::Signer;
    let sk = ed25519_test_key(0x47);
    let pk_bytes = sk.verifying_key().to_bytes();
    for (label, replacement_r) in [
        ("small-order", ED25519_SMALL_ORDER_POINT),
        ("noncanonical", ED25519_NON_CANONICAL_IDENTITY),
    ] {
        let malformed_message = format!("{label}-r-b").into_bytes();
        let entries = vec![
            Ed25519BatchEntry {
                message: b"ok-a".to_vec(),
                signature: sk.sign(b"ok-a").to_bytes().to_vec(),
                public_key: pk_bytes.to_vec(),
            },
            Ed25519BatchEntry {
                message: malformed_message.clone(),
                signature: ed25519_signature_with_replacement_r(
                    &sk,
                    &malformed_message,
                    &replacement_r,
                )
                .to_vec(),
                public_key: pk_bytes.to_vec(),
            },
        ];
        let request = Ed25519BatchRequest { entries };
        let payload = norito::to_bytes(&request).expect("encode request");
        let tlv = make_tlv(PointerType::NoritoBytes as u16, &payload);
        let mut vm = IVM::new(10_000);
        let ptr = vm.alloc_input_tlv(&tlv).expect("alloc request");
        vm.set_register(1, ptr);
        vm.set_register(2, 123);
        let word =
            encoding::wide::encode_rr(instruction::wide::crypto::ED25519BATCHVERIFY, 6, 1, 2);
        let halt = encoding::wide::encode_halt().to_le_bytes();
        let mut code = Vec::new();
        code.extend_from_slice(&word.to_le_bytes());
        code.extend_from_slice(&halt);
        vm.memory.load_code(&code).unwrap();
        vm.run().unwrap();
        assert_eq!(vm.register(6), 0, "{label} batch should fail");
        assert_eq!(vm.register(2), 1, "{label} R entry flagged as failing");
    }
}
#[test]
fn opcode_verify_ed25519_batch_via_tlv_success() {
    use ed25519_dalek::Signer;
    let sk = ed25519_test_key(2);
    let pk_bytes = sk.verifying_key().to_bytes();
    let entries = ["entry-a", "entry-b"]
        .iter()
        .map(|msg| {
            let msg_bytes = msg.as_bytes();
            let sig = sk.sign(msg_bytes);
            Ed25519BatchEntry {
                message: msg_bytes.to_vec(),
                signature: sig.to_bytes().to_vec(),
                public_key: pk_bytes.to_vec(),
            }
        })
        .collect();
    let request = Ed25519BatchRequest { entries };
    let payload = norito::to_bytes(&request).expect("encode request");
    let tlv = make_tlv(PointerType::NoritoBytes as u16, &payload);
    let mut vm = IVM::new(10_000);
    let ptr = vm.alloc_input_tlv(&tlv).expect("alloc request");
    vm.set_register(1, ptr);
    vm.set_register(2, 9); // failure index register
    let word = encoding::wide::encode_rr(instruction::wide::crypto::ED25519BATCHVERIFY, 5, 1, 2);
    let halt = encoding::wide::encode_halt().to_le_bytes();
    let mut code = Vec::new();
    code.extend_from_slice(&word.to_le_bytes());
    code.extend_from_slice(&halt);
    vm.memory.load_code(&code).unwrap();
    vm.run().unwrap();
    assert_eq!(vm.register(5), 1, "batch should verify");
    assert_eq!(vm.register(2), 0, "failure index cleared on success");
}
#[test]
fn opcode_verify_ed25519_batch_via_tlv_reports_failure_index() {
    use ed25519_dalek::Signer;
    let sk = ed25519_test_key(3);
    let pk_bytes = sk.verifying_key().to_bytes();
    let mut bad_sig = sk.sign(b"entry-bad").to_bytes().to_vec();
    bad_sig[0] ^= 0x42;
    let entries = vec![
        Ed25519BatchEntry {
            message: b"ok-a".to_vec(),
            signature: sk.sign(b"ok-a").to_bytes().to_vec(),
            public_key: pk_bytes.to_vec(),
        },
        Ed25519BatchEntry {
            message: b"bad-b".to_vec(),
            signature: bad_sig,
            public_key: pk_bytes.to_vec(),
        },
    ];
    let request = Ed25519BatchRequest { entries };
    let payload = norito::to_bytes(&request).expect("encode request");
    let tlv = make_tlv(PointerType::NoritoBytes as u16, &payload);
    let mut vm = IVM::new(10_000);
    let ptr = vm.alloc_input_tlv(&tlv).expect("alloc request");
    vm.set_register(1, ptr);
    vm.set_register(2, 123);
    let word = encoding::wide::encode_rr(instruction::wide::crypto::ED25519BATCHVERIFY, 6, 1, 2);
    let halt = encoding::wide::encode_halt().to_le_bytes();
    let mut code = Vec::new();
    code.extend_from_slice(&word.to_le_bytes());
    code.extend_from_slice(&halt);
    vm.memory.load_code(&code).unwrap();
    vm.run().unwrap();
    assert_eq!(vm.register(6), 0, "batch should fail");
    assert_eq!(vm.register(2), 1, "second entry flagged as failing");
}
#[test]
fn opcode_verify_ed25519_batch_debits_payload_before_hash_validation() {
    use ed25519_dalek::Signer;
    let sk = ed25519_test_key(4);
    let message = b"meter-before-hash";
    let request = Ed25519BatchRequest {
        entries: vec![Ed25519BatchEntry {
            message: message.to_vec(),
            signature: sk.sign(message).to_bytes().to_vec(),
            public_key: sk.verifying_key().to_bytes().to_vec(),
        }],
    };
    let payload = norito::to_bytes(&request).expect("encode request");
    let mut tlv = make_tlv(PointerType::NoritoBytes as u16, &payload);
    *tlv.last_mut().expect("TLV checksum") ^= 1;
    let word = encoding::wide::encode_rr(instruction::wide::crypto::ED25519BATCHVERIFY, 5, 1, 2);
    let base_gas = ivm::gas::cost_of(word).expect("ED25519BATCHVERIFY opcode must be scheduled");
    let payload_gas = ivm::gas::ed25519_batch_extra_gas(payload.len() as u64, 0);
    let initial_gas = base_gas + payload_gas - 1;
    let mut vm = IVM::new(initial_gas);
    let ptr = vm.alloc_input_tlv(&tlv).expect("alloc request");
    vm.set_register(1, ptr);
    let halt = encoding::wide::encode_halt().to_le_bytes();
    let mut code = Vec::new();
    code.extend_from_slice(&word.to_le_bytes());
    code.extend_from_slice(&halt);
    vm.load_program(&assemble(&code)).unwrap();
    assert!(matches!(vm.run(), Err(VMError::OutOfGas)));
    assert_eq!(vm.gas_remaining, payload_gas - 1);
}
#[test]
fn opcode_verify_ed25519_batch_rejects_oversized_payload_before_hashing() {
    let payload = vec![0u8; ivm::gas::ED25519_BATCH_MAX_PAYLOAD_BYTES + 1];
    let mut tlv = make_tlv(PointerType::NoritoBytes as u16, &payload);
    *tlv.last_mut().expect("TLV checksum") ^= 1;
    let word = encoding::wide::encode_rr(instruction::wide::crypto::ED25519BATCHVERIFY, 5, 1, 2);
    let initial_gas = 10_000;
    let mut vm = IVM::new(initial_gas);
    let ptr = vm.alloc_host_tlv(&tlv).expect("alloc oversized request");
    vm.set_register(1, ptr);
    vm.set_register(2, 123);
    let halt = encoding::wide::encode_halt().to_le_bytes();
    let mut code = Vec::new();
    code.extend_from_slice(&word.to_le_bytes());
    code.extend_from_slice(&halt);
    vm.load_program(&assemble(&code)).unwrap();
    vm.run().unwrap();
    assert_eq!(vm.register(5), 0);
    assert_eq!(vm.register(2), 0);
    assert_eq!(
        initial_gas - vm.gas_remaining,
        ivm::gas::cost_of(word).expect("ED25519BATCHVERIFY opcode must be scheduled")
    );
}
#[test]
fn opcode_verify_secp256k1_via_tlv() {
    use iroha_crypto::{EcdsaSecp256k1Sha256, KeyGenOption};
    let (pk, sk) = EcdsaSecp256k1Sha256::keypair(KeyGenOption::UseSeed(vec![0x22; 32]));
    let pk_bytes = pk.to_sec1_bytes();
    let msg = b"ivm-op-secp256k1";
    let sig_bytes = EcdsaSecp256k1Sha256::sign(msg, &sk);
    let msg_tlv = make_tlv(PointerType::Blob as u16, msg);
    let sig_tlv = make_tlv(PointerType::Blob as u16, &sig_bytes);
    let pk_tlv = make_tlv(PointerType::Blob as u16, &pk_bytes);
    let mut vm = IVM::new(10_000);
    vm.memory.preload_input(0, &msg_tlv).expect("preload input");
    let p_msg = Memory::INPUT_START;
    let p_sig = p_msg + msg_tlv.len() as u64 + 8;
    let p_pk = p_sig + sig_tlv.len() as u64 + 8;
    vm.memory
        .preload_input(msg_tlv.len() as u64 + 8, &sig_tlv)
        .expect("preload input");
    vm.memory
        .preload_input((msg_tlv.len() + sig_tlv.len()) as u64 + 16, &pk_tlv)
        .expect("preload input");
    vm.set_register(1, p_msg);
    vm.set_register(2, p_sig);
    vm.set_register(3, p_pk);
    let op = instruction::wide::crypto::ECDSAVERIFY;
    let word = encoding::wide::encode_rr(op, 3, 1, 2);
    let halt = encoding::wide::encode_halt().to_le_bytes();
    let mut code = Vec::new();
    code.extend_from_slice(&word.to_le_bytes());
    code.extend_from_slice(&halt);
    vm.memory.load_code(&code).unwrap();
    vm.run().unwrap();
    assert_eq!(vm.register(3), 1);
}
#[test]
fn secp256k1_verify_rejects_high_s_signature() {
    use iroha_crypto::{EcdsaSecp256k1Sha256, KeyGenOption};
    use ivm::signature::{SignatureScheme, verify_signature};
    use k256::ecdsa::Signature;
    let (pk, sk) = EcdsaSecp256k1Sha256::keypair(KeyGenOption::UseSeed(vec![0x33; 32]));
    let msg = b"ivm-high-s";
    let sig = EcdsaSecp256k1Sha256::sign(msg, &sk);
    let signature = Signature::from_slice(&sig).expect("signature parse");
    let high_s = Signature::from_scalars(signature.r(), -signature.s()).expect("high-S signature");
    let high_s_bytes = high_s.to_vec();
    assert!(
        !verify_signature(
            SignatureScheme::Secp256k1,
            msg,
            &high_s_bytes,
            pk.to_sec1_bytes().as_ref()
        ),
        "high-S signatures must be rejected"
    );
}
#[test]
fn opcode_verify_dilithium_rejects_all_zero_signature_material() {
    use pqcrypto_mldsa::mldsa65 as dilithium;
    use pqcrypto_traits::sign::PublicKey;
    let (pk, _) = dilithium::keypair();
    let msg = b"ivm-op-dilithium-zero";
    let signature = vec![0u8; dilithium::signature_bytes()];
    let msg_tlv = make_tlv(PointerType::Blob as u16, msg);
    let sig_tlv = make_tlv(PointerType::Blob as u16, &signature);
    let pk_tlv = make_tlv(PointerType::Blob as u16, pk.as_bytes());
    let mut vm = IVM::new(20_000);
    vm.memory.preload_input(0, &msg_tlv).expect("preload input");
    let p_msg = Memory::INPUT_START;
    let p_sig = p_msg + msg_tlv.len() as u64 + 8;
    let p_pk = p_sig + sig_tlv.len() as u64 + 8;
    vm.memory
        .preload_input(msg_tlv.len() as u64 + 8, &sig_tlv)
        .expect("preload input");
    vm.memory
        .preload_input((msg_tlv.len() + sig_tlv.len()) as u64 + 16, &pk_tlv)
        .expect("preload input");
    vm.set_register(1, p_msg);
    vm.set_register(2, p_sig);
    vm.set_register(3, p_pk);
    let word = encoding::wide::encode_rr(instruction::wide::crypto::DILITHIUMVERIFY, 3, 1, 2);
    let halt = encoding::wide::encode_halt().to_le_bytes();
    let mut code = Vec::new();
    code.extend_from_slice(&word.to_le_bytes());
    code.extend_from_slice(&halt);
    vm.memory.load_code(&code).unwrap();
    vm.run().unwrap();
    assert_eq!(vm.register(3), 0);
}
#[test]
fn opcode_verify_dilithium_rejects_all_zero_public_key_material() {
    use pqcrypto_mldsa::mldsa65 as dilithium;
    use pqcrypto_traits::sign::DetachedSignature;
    let (_, secret_key) = dilithium::keypair();
    let msg = b"ivm-op-dilithium-zero-public-key";
    let sig = dilithium::detached_sign(msg, &secret_key);
    let public_key = vec![0u8; dilithium::public_key_bytes()];
    let msg_tlv = make_tlv(PointerType::Blob as u16, msg);
    let sig_tlv = make_tlv(PointerType::Blob as u16, sig.as_bytes());
    let pk_tlv = make_tlv(PointerType::Blob as u16, &public_key);
    let mut vm = IVM::new(20_000);
    vm.memory.preload_input(0, &msg_tlv).expect("preload input");
    let p_msg = Memory::INPUT_START;
    let p_sig = p_msg + msg_tlv.len() as u64 + 8;
    let p_pk = p_sig + sig_tlv.len() as u64 + 8;
    vm.memory
        .preload_input(msg_tlv.len() as u64 + 8, &sig_tlv)
        .expect("preload input");
    vm.memory
        .preload_input((msg_tlv.len() + sig_tlv.len()) as u64 + 16, &pk_tlv)
        .expect("preload input");
    vm.set_register(1, p_msg);
    vm.set_register(2, p_sig);
    vm.set_register(3, p_pk);
    let word = encoding::wide::encode_rr(instruction::wide::crypto::DILITHIUMVERIFY, 3, 1, 2);
    let halt = encoding::wide::encode_halt().to_le_bytes();
    let mut code = Vec::new();
    code.extend_from_slice(&word.to_le_bytes());
    code.extend_from_slice(&halt);
    vm.memory.load_code(&code).unwrap();
    vm.run().unwrap();
    assert_eq!(vm.register(3), 0);
}
#[test]
fn opcode_verify_dilithium_via_tlv() {
    use pqcrypto_mldsa::mldsa65 as dilithium;
    use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
    let (pk, sk) = dilithium::keypair();
    let msg = b"ivm-op-dilithium";
    let sig = dilithium::detached_sign(msg, &sk);
    let msg_tlv = make_tlv(PointerType::Blob as u16, msg);
    let sig_tlv = make_tlv(PointerType::Blob as u16, sig.as_bytes());
    let pk_tlv = make_tlv(PointerType::Blob as u16, pk.as_bytes());
    let mut vm = IVM::new(20_000);
    vm.memory.preload_input(0, &msg_tlv).expect("preload input");
    let p_msg = Memory::INPUT_START;
    let p_sig = p_msg + msg_tlv.len() as u64 + 8;
    let p_pk = p_sig + sig_tlv.len() as u64 + 8;
    vm.memory
        .preload_input(msg_tlv.len() as u64 + 8, &sig_tlv)
        .expect("preload input");
    vm.memory
        .preload_input((msg_tlv.len() + sig_tlv.len()) as u64 + 16, &pk_tlv)
        .expect("preload input");
    vm.set_register(1, p_msg);
    vm.set_register(2, p_sig);
    vm.set_register(3, p_pk);
    let op = instruction::wide::crypto::DILITHIUMVERIFY;
    let word = encoding::wide::encode_rr(op, 3, 1, 2);
    let halt = encoding::wide::encode_halt().to_le_bytes();
    let mut code = Vec::new();
    code.extend_from_slice(&word.to_le_bytes());
    code.extend_from_slice(&halt);
    vm.memory.load_code(&code).unwrap();
    vm.run().unwrap();
    assert_eq!(vm.register(3), 1);
}
#[test]
fn syscall_verify_signature_ed25519_via_tlv() {
    let msg = b"ivm-ed25519";
    assert_eq!(
        run_syscall_verify_signature_ed25519(PointerType::Blob, msg, 5)
            .expect("canonical Blob message must verify"),
        1
    );
}
#[test]
fn syscall_verify_signature_rejects_norito_message_tlv() {
    let message = br#"{"amount":123,"dpn_id":"dpn-live"}"#;
    assert!(matches!(
        run_syscall_verify_signature_ed25519(PointerType::NoritoBytes, message, 6),
        Err(VMError::NoritoInvalid)
    ));
}
#[test]
fn syscall_verify_signature_rejects_json_message_tlv() {
    let message = br#"{"amount":456,"dpn_id":"dpn-json"}"#;
    assert!(matches!(
        run_syscall_verify_signature_ed25519(PointerType::Json, message, 7),
        Err(VMError::NoritoInvalid)
    ));
}
