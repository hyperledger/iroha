//! Kotodama integration tests for SM3/SM2 syscalls.
use crate::common;
use hex::decode;
use iroha_crypto::{Hash, Sm2PrivateKey, Sm2PublicKey, Sm3Digest};
use iroha_model_base::name::Name;
use iroha_primitives::json::Json;
use ivm::{IVM, PointerType, ProgramMetadata};
use kotodama_lang::compiler::Compiler as KotodamaCompiler;
use std::collections::BTreeMap;
fn new_sm_host() -> ivm::host::DefaultHost {
    ivm::host::DefaultHost::new().with_sm_enabled(true)
}
fn make_tlv(pointer_type: PointerType, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(7 + payload.len() + 32);
    out.extend_from_slice(&(pointer_type as u16).to_be_bytes());
    out.push(1);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload.as_ref());
    let h: [u8; 32] = Hash::new(payload).into();
    out.extend_from_slice(&h);
    out
}
fn install_sm_entrypoint(
    vm: &mut IVM,
    program: &[u8],
    entrypoint_name: &str,
    byte_fields: &[(&str, &[u8])],
    integer_fields: &[(&str, i64)],
) {
    let parsed = ProgramMetadata::parse(program).expect("parse SM contract artifact");
    let entrypoint = parsed
        .contract_interface
        .as_ref()
        .expect("SM contract interface")
        .entrypoints
        .iter()
        .find(|entrypoint| entrypoint.name == entrypoint_name)
        .unwrap_or_else(|| panic!("missing SM entrypoint `{entrypoint_name}`"));
    let schema = entrypoint
        .argument_schema
        .as_ref()
        .expect("parameterized SM entrypoint schema");
    let mut payload = norito::json::Map::new();
    for (name, value) in byte_fields {
        payload.insert(
            (*name).to_owned(),
            norito::json::Value::String(format!("0x{}", hex::encode(value))),
        );
    }
    for (name, value) in integer_fields {
        payload.insert(
            (*name).to_owned(),
            norito::json::Value::String(value.to_string()),
        );
    }
    let record = ivm_abi::arguments::encode_argument_record_from_json(
        schema,
        &Json::from(norito::json::Value::Object(payload)),
    )
    .expect("encode SM entrypoint argument record");
    let key: Name = ivm_abi::arguments::ENTRYPOINT_ARGUMENT_RECORD_PUBLIC_INPUT_KEY
        .parse()
        .expect("public input key");
    vm.set_host(new_sm_host().with_public_inputs(BTreeMap::from([(
        key,
        make_tlv(PointerType::NoritoBytes, &record),
    )])));
    vm.load_program(program).expect("load SM contract artifact");
    common::select_kotodama_entrypoint(vm, program, entrypoint_name);
}
#[test]
fn kotodama_sm3_hash_returns_expected_digest() {
    let src = r#"
        seiyaku Sm3Hash {
        view fn sm_hash(bytes msg) authorize(anyone) -> bytes {
            return crypto::sm3(msg);
        }
        }
    "#;
    let code = KotodamaCompiler::new()
        .compile_source(src)
        .expect("compile sm3 hash contract");
    let message = b"kotodama-sm3";
    let expected = Sm3Digest::hash(message);
    let mut vm = IVM::new(u64::MAX);
    install_sm_entrypoint(&mut vm, &code, "sm_hash", &[("msg", message)], &[]);
    vm.run().expect("vm run");
    let out_ptr = vm.public_call_result_word(0).expect("completed SM result");
    assert_ne!(out_ptr, 0, "crypto::sm3 should return a bytes pointer");
    let tlv = vm
        .memory
        .validate_tlv(out_ptr)
        .expect("validate digest pointer");
    assert_eq!(tlv.type_id, PointerType::Blob);
    assert_eq!(tlv.payload, expected.as_bytes());
}
fn compile_sm2_verify() -> Vec<u8> {
    let src = r#"
        seiyaku Sm2Verify {
        view fn verify(bytes msg, bytes sig, bytes pk) authorize(anyone) -> bool {
            return crypto::sm2::verify(message: msg, signature: sig, public_key: pk);
        }
        }
    "#;
    KotodamaCompiler::new()
        .compile_source(src)
        .expect("compile sm2 verify contract")
}
fn compile_sm2_verify_with_distid() -> Vec<u8> {
    let src = r#"
        seiyaku Sm2VerifyWithDistid {
        view fn verify_with_distid(bytes msg, bytes sig, bytes pk, bytes distid) authorize(anyone) -> bool {
            return crypto::sm2::verify(message: msg, signature: sig, public_key: pk, distid: distid);
        }
        }
    "#;
    KotodamaCompiler::new()
        .compile_source(src)
        .expect("compile sm2 verify with distid contract")
}
fn compile_sm4_gcm_seal() -> Vec<u8> {
    let src = r#"
        seiyaku Sm4GcmSeal {
        view fn seal(bytes key, bytes nonce, bytes aad, bytes pt) authorize(anyone) -> bytes {
            return crypto::sm4_gcm::seal(key: key, nonce: nonce, aad: aad, payload: pt);
        }
        }
    "#;
    KotodamaCompiler::new()
        .compile_source(src)
        .expect("compile sm4 gcm seal contract")
}
fn compile_sm4_gcm_open() -> Vec<u8> {
    let src = r#"
        seiyaku Sm4GcmOpen {
        view fn open(bytes key, bytes nonce, bytes aad, bytes ct) authorize(anyone) -> bytes {
            return crypto::sm4_gcm::open(key: key, nonce: nonce, aad: aad, payload: ct);
        }
        }
    "#;
    KotodamaCompiler::new()
        .compile_source(src)
        .expect("compile sm4 gcm open contract")
}
fn compile_sm4_ccm_seal() -> Vec<u8> {
    let src = r#"
        seiyaku Sm4CcmSeal {
        view fn seal(bytes key, bytes nonce, bytes aad, bytes pt, int tag_len) authorize(anyone) -> bytes {
            return crypto::sm4_ccm::seal(key: key, nonce: nonce, aad: aad, payload: pt, tag_length: tag_len);
        }
        }
    "#;
    KotodamaCompiler::new()
        .compile_source(src)
        .expect("compile sm4 ccm seal contract")
}
fn compile_sm4_ccm_open() -> Vec<u8> {
    let src = r#"
        seiyaku Sm4CcmOpen {
        view fn open(bytes key, bytes nonce, bytes aad, bytes ct, int tag_len) authorize(anyone) -> bytes {
            return crypto::sm4_ccm::open(key: key, nonce: nonce, aad: aad, payload: ct, tag_length: tag_len);
        }
        }
    "#;
    KotodamaCompiler::new()
        .compile_source(src)
        .expect("compile sm4 ccm open contract")
}
fn new_sm2_key() -> (Sm2PrivateKey, Sm2PublicKey) {
    let secret = [0x42u8; 32];
    let private =
        Sm2PrivateKey::new(Sm2PublicKey::DEFAULT_DISTID, secret).expect("construct private key");
    let public = private.public_key();
    (private, public)
}
#[test]
fn kotodama_sm2_verify_accepts_valid_signature() {
    let code = compile_sm2_verify();
    let (private, public) = new_sm2_key();
    let message = b"kotodama-sm2";
    let sig_bytes = private.sign(message).to_bytes();
    let pk_bytes = public.to_sec1_bytes(false);
    let mut vm = IVM::new(u64::MAX);
    install_sm_entrypoint(
        &mut vm,
        &code,
        "verify",
        &[
            ("msg", message),
            ("sig", sig_bytes.as_ref()),
            ("pk", &pk_bytes),
        ],
        &[],
    );
    vm.run().expect("vm run");
    assert_eq!(
        vm.public_call_result_word(0).expect("completed SM result"),
        1,
        "crypto::sm2::verify should succeed"
    );
}
#[test]
fn kotodama_sm2_verify_rejects_malformed_signature() {
    let code = compile_sm2_verify();
    let (private, public) = new_sm2_key();
    let message = b"kotodama-sm2";
    let mut sig_bytes = private.sign(message).to_bytes();
    sig_bytes[0] ^= 0xFF;
    let pk_bytes = public.to_sec1_bytes(false);
    let mut vm = IVM::new(u64::MAX);
    install_sm_entrypoint(
        &mut vm,
        &code,
        "verify",
        &[
            ("msg", message),
            ("sig", sig_bytes.as_ref()),
            ("pk", &pk_bytes),
        ],
        &[],
    );
    vm.run().expect("vm run");
    assert_eq!(
        vm.public_call_result_word(0).expect("completed SM result"),
        0,
        "malformed signature must fail"
    );
}
#[test]
fn kotodama_sm2_verify_rejects_signature_for_other_message() {
    let code = compile_sm2_verify();
    let (private, public) = new_sm2_key();
    let message = b"kotodama-sm2";
    let sig_bytes = private.sign(message).to_bytes();
    let pk_bytes = public.to_sec1_bytes(false);
    let other_message = b"kotodama-sm2-nonce-reuse";
    let mut vm = IVM::new(u64::MAX);
    install_sm_entrypoint(
        &mut vm,
        &code,
        "verify",
        &[
            ("msg", other_message),
            ("sig", sig_bytes.as_ref()),
            ("pk", &pk_bytes),
        ],
        &[],
    );
    vm.run().expect("vm run");
    assert_eq!(
        vm.public_call_result_word(0).expect("completed SM result"),
        0,
        "signature tied to different message must be rejected"
    );
}
#[test]
fn kotodama_sm2_verify_with_distid_enforces_identifier() {
    let code = compile_sm2_verify_with_distid();
    let distid = "kotodama-dist-0001";
    let private =
        Sm2PrivateKey::new(distid.to_string(), [0x24u8; 32]).expect("construct private key");
    let public = private.public_key();
    let message = b"kotodama-sm2-dist";
    let sig_bytes = private.sign(message).to_bytes();
    let pk_bytes = public.to_sec1_bytes(false);
    let dist_bytes = distid.as_bytes();
    let wrong_dist = b"other-dist";
    // Success with matching distid
    let mut vm = IVM::new(u64::MAX);
    install_sm_entrypoint(
        &mut vm,
        &code,
        "verify_with_distid",
        &[
            ("msg", message),
            ("sig", sig_bytes.as_ref()),
            ("pk", &pk_bytes),
            ("distid", dist_bytes),
        ],
        &[],
    );
    vm.run().expect("vm run");
    assert_eq!(
        vm.public_call_result_word(0).expect("completed SM result"),
        1,
        "matching distid should verify"
    );
    // Failure with mismatched distid
    let mut vm_fail = IVM::new(u64::MAX);
    install_sm_entrypoint(
        &mut vm_fail,
        &code,
        "verify_with_distid",
        &[
            ("msg", message),
            ("sig", sig_bytes.as_ref()),
            ("pk", &pk_bytes),
            ("distid", wrong_dist),
        ],
        &[],
    );
    vm_fail.run().expect("vm run");
    assert_eq!(
        vm_fail
            .public_call_result_word(0)
            .expect("completed SM result"),
        0,
        "mismatched distid must cause verification failure"
    );
}
#[test]
fn kotodama_sm4_gcm_seal_matches_vector() {
    let code = compile_sm4_gcm_seal();
    let key = decode("0123456789abcdeffedcba9876543210").expect("hex key");
    let nonce = decode("00001234567800000000abcd").expect("hex nonce");
    let aad = decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").expect("hex aad");
    let plaintext = decode("d9313225f88406e5a55909c5aff5269a").expect("hex plaintext");
    let expected_cipher = decode("6468017fde4979a107326ee77d8a265c").expect("hex cipher");
    let expected_tag = decode("cadf422b1af7ec6df46004dc8d3ba855").expect("hex tag");
    let mut vm = IVM::new(u64::MAX);
    install_sm_entrypoint(
        &mut vm,
        &code,
        "seal",
        &[
            ("key", &key),
            ("nonce", &nonce),
            ("aad", &aad),
            ("pt", &plaintext),
        ],
        &[],
    );
    vm.run().expect("vm run");
    let out_ptr = vm.public_call_result_word(0).expect("completed SM result");
    assert_ne!(out_ptr, 0, "seal should produce output blob");
    let tlv = vm
        .memory
        .validate_tlv(out_ptr)
        .expect("validate ciphertext blob");
    assert_eq!(tlv.type_id, PointerType::Blob);
    assert_eq!(
        &tlv.payload[..expected_cipher.len()],
        expected_cipher.as_slice()
    );
    assert_eq!(
        &tlv.payload[expected_cipher.len()..],
        expected_tag.as_slice()
    );
}
#[test]
fn kotodama_sm4_gcm_open_returns_plaintext() {
    let code = compile_sm4_gcm_open();
    let key = decode("0123456789abcdeffedcba9876543210").expect("hex key");
    let nonce = decode("00001234567800000000abcd").expect("hex nonce");
    let aad = decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").expect("hex aad");
    let plaintext = decode("d9313225f88406e5a55909c5aff5269a").expect("hex plaintext");
    let cipher = decode("6468017fde4979a107326ee77d8a265c").expect("hex cipher");
    let tag = decode("cadf422b1af7ec6df46004dc8d3ba855").expect("hex tag");
    let mut cipher_tag = cipher.clone();
    cipher_tag.extend_from_slice(&tag);
    let mut vm = IVM::new(u64::MAX);
    install_sm_entrypoint(
        &mut vm,
        &code,
        "open",
        &[
            ("key", &key),
            ("nonce", &nonce),
            ("aad", &aad),
            ("ct", &cipher_tag),
        ],
        &[],
    );
    vm.run().expect("vm run");
    let out_ptr = vm.public_call_result_word(0).expect("completed SM result");
    assert_ne!(out_ptr, 0, "open should return plaintext blob");
    let tlv = vm
        .memory
        .validate_tlv(out_ptr)
        .expect("validate plaintext blob");
    assert_eq!(tlv.type_id, PointerType::Blob);
    assert_eq!(tlv.payload, plaintext.as_slice());
}
#[test]
fn kotodama_sm4_gcm_open_rejects_bad_tag() {
    let code = compile_sm4_gcm_open();
    let key = decode("0123456789abcdeffedcba9876543210").expect("hex key");
    let nonce = decode("00001234567800000000abcd").expect("hex nonce");
    let aad = decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").expect("hex aad");
    let cipher = decode("6468017fde4979a107326ee77d8a265c").expect("hex cipher");
    let mut tag = decode("cadf422b1af7ec6df46004dc8d3ba855").expect("hex tag");
    tag[0] ^= 0xFF;
    let mut cipher_tag = cipher.clone();
    cipher_tag.extend_from_slice(&tag);
    let mut vm = IVM::new(u64::MAX);
    install_sm_entrypoint(
        &mut vm,
        &code,
        "open",
        &[
            ("key", &key),
            ("nonce", &nonce),
            ("aad", &aad),
            ("ct", &cipher_tag),
        ],
        &[],
    );
    assert!(matches!(vm.run(), Err(ivm::VMError::NoritoInvalid)));
    assert!(
        vm.call_result_word_count().is_err(),
        "a failed open cannot return bytes"
    );
}
#[test]
fn kotodama_sm4_ccm_seal_matches_vector() {
    let code = compile_sm4_ccm_seal();
    let key = decode("404142434445464748494a4b4c4d4e4f").expect("hex key");
    let nonce = decode("10111213141516").expect("hex nonce");
    let aad = decode("000102030405060708090a0b0c0d0e0f").expect("hex aad");
    let plaintext = decode("202122232425262728292a2b2c2d2e2f").expect("hex plaintext");
    let expected_cipher = decode("a9550cebab5f227d9590e8979caafd1f").expect("hex cipher");
    let expected_tag = decode("03a1f305").expect("hex tag");
    let mut vm = IVM::new(u64::MAX);
    install_sm_entrypoint(
        &mut vm,
        &code,
        "seal",
        &[
            ("key", &key),
            ("nonce", &nonce),
            ("aad", &aad),
            ("pt", &plaintext),
        ],
        &[(
            "tag_len",
            i64::try_from(expected_tag.len()).expect("tag length fits i64"),
        )],
    );
    vm.run().expect("vm run");
    let out_ptr = vm.public_call_result_word(0).expect("completed SM result");
    assert_ne!(out_ptr, 0, "seal should produce output blob");
    let tlv = vm
        .memory
        .validate_tlv(out_ptr)
        .expect("validate ciphertext blob");
    assert_eq!(tlv.type_id, PointerType::Blob);
    assert_eq!(
        &tlv.payload[..expected_cipher.len()],
        expected_cipher.as_slice()
    );
    assert_eq!(
        &tlv.payload[expected_cipher.len()..],
        expected_tag.as_slice()
    );
}
#[test]
fn kotodama_sm4_ccm_open_returns_plaintext() {
    let code = compile_sm4_ccm_open();
    let key = decode("404142434445464748494a4b4c4d4e4f").expect("hex key");
    let nonce = decode("10111213141516").expect("hex nonce");
    let aad = decode("000102030405060708090a0b0c0d0e0f").expect("hex aad");
    let plaintext = decode("202122232425262728292a2b2c2d2e2f").expect("hex plaintext");
    let cipher = decode("a9550cebab5f227d9590e8979caafd1f").expect("hex cipher");
    let tag = decode("03a1f305").expect("hex tag");
    let mut cipher_tag = cipher.clone();
    cipher_tag.extend_from_slice(&tag);
    let mut vm = IVM::new(u64::MAX);
    install_sm_entrypoint(
        &mut vm,
        &code,
        "open",
        &[
            ("key", &key),
            ("nonce", &nonce),
            ("aad", &aad),
            ("ct", &cipher_tag),
        ],
        &[(
            "tag_len",
            i64::try_from(tag.len()).expect("tag length fits i64"),
        )],
    );
    vm.run().expect("vm run");
    let out_ptr = vm.public_call_result_word(0).expect("completed SM result");
    assert_ne!(out_ptr, 0, "open should produce plaintext blob");
    let tlv = vm
        .memory
        .validate_tlv(out_ptr)
        .expect("validate plaintext blob");
    assert_eq!(tlv.type_id, PointerType::Blob);
    assert_eq!(tlv.payload, plaintext.as_slice());
}
#[test]
fn kotodama_sm4_ccm_open_rejects_bad_tag() {
    let code = compile_sm4_ccm_open();
    let key = decode("404142434445464748494a4b4c4d4e4f").expect("hex key");
    let nonce = decode("10111213141516").expect("hex nonce");
    let aad = decode("000102030405060708090a0b0c0d0e0f").expect("hex aad");
    let cipher = decode("a9550cebab5f227d9590e8979caafd1f").expect("hex cipher");
    let mut tag = decode("03a1f305").expect("hex tag");
    tag[0] ^= 0x01;
    let mut cipher_tag = cipher.clone();
    cipher_tag.extend_from_slice(&tag);
    let mut vm = IVM::new(u64::MAX);
    install_sm_entrypoint(
        &mut vm,
        &code,
        "open",
        &[
            ("key", &key),
            ("nonce", &nonce),
            ("aad", &aad),
            ("ct", &cipher_tag),
        ],
        &[(
            "tag_len",
            i64::try_from(tag.len()).expect("tag length fits i64"),
        )],
    );
    assert!(matches!(vm.run(), Err(ivm::VMError::NoritoInvalid)));
    assert!(
        vm.call_result_word_count().is_err(),
        "a failed CCM open cannot return bytes"
    );
}
