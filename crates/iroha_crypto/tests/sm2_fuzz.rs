//! Deterministic regression tests for SM2 key generation and signatures.
#![cfg(feature = "sm")]
use super::sm2_negative_vector_fixture::{NegativeVector, apply_mutation, load_negative_vectors};
use hex::decode as hex_decode;
use iroha_crypto::{
    Algorithm, Error, KeyPair, Signature, Sm2PrivateKey, Sm2PublicKey, Sm2Signature,
};
use norito::json::Value;
use sm2::dsa::{Signature as Sm2RawSignature, signature::hazmat::PrehashVerifier};
use sm3::{Digest, Sm3};
use std::sync::{Arc, OnceLock};
#[derive(Clone, Debug)]
struct WycheproofCase {
    distid: String,
    public_sec1: Vec<u8>,
    message: Vec<u8>,
    signature_der: Vec<u8>,
    expect_valid: bool,
}
static WYCHEPROOF_CASES: OnceLock<Arc<Vec<WycheproofCase>>> = OnceLock::new();
static WYCHEPROOF_VALID_CASES: OnceLock<Arc<Vec<WycheproofCase>>> = OnceLock::new();
static NEGATIVE_VECTORS: OnceLock<Arc<Vec<NegativeVector>>> = OnceLock::new();
fn decode_hex(value: &str) -> Vec<u8> {
    if value.is_empty() {
        Vec::new()
    } else {
        hex_decode(value).unwrap_or_else(|err| panic!("invalid hex '{value}': {err}"))
    }
}
fn load_wycheproof_cases() -> Arc<Vec<WycheproofCase>> {
    WYCHEPROOF_CASES
        .get_or_init(|| {
            let raw = include_str!("fixtures/wycheproof_sm2.json");
            let value: Value =
                norito::json::from_str(raw).expect("parse Wycheproof SM2 fixture JSON");
            let groups = value["testGroups"]
                .as_array()
                .expect("Wycheproof SM2 testGroups array");
            let mut cases = Vec::new();
            for group in groups {
                let distid = group["distid"]
                    .as_str()
                    .unwrap_or("1234567812345678")
                    .to_owned();
                let public_hex = group["key"]["uncompressed"]
                    .as_str()
                    .expect("Wycheproof SM2 key missing");
                let public_sec1 = decode_hex(public_hex);
                let tests = group["tests"]
                    .as_array()
                    .expect("Wycheproof SM2 tests array missing");
                for test in tests {
                    let msg_hex = test["msg"].as_str().expect("Wycheproof SM2 msg missing");
                    let message = decode_hex(msg_hex);
                    let sig_hex = test["sig"]
                        .as_str()
                        .expect("Wycheproof SM2 signature missing");
                    let signature_der = decode_hex(sig_hex);
                    let expect_valid = matches!(
                        test["result"].as_str().map(str::to_ascii_lowercase),
                        Some(ref result) if result == "valid"
                    );
                    cases.push(WycheproofCase {
                        distid: distid.clone(),
                        public_sec1: public_sec1.clone(),
                        message,
                        signature_der,
                        expect_valid,
                    });
                }
            }
            Arc::new(cases)
        })
        .clone()
}
fn load_valid_wycheproof_cases() -> Arc<Vec<WycheproofCase>> {
    WYCHEPROOF_VALID_CASES
        .get_or_init(|| {
            let all = load_wycheproof_cases();
            Arc::new(
                all.iter()
                    .filter(|case| case.expect_valid)
                    .cloned()
                    .collect(),
            )
        })
        .clone()
}
fn load_negative_vectors_arc() -> Arc<Vec<NegativeVector>> {
    NEGATIVE_VECTORS
        .get_or_init(|| Arc::new(load_negative_vectors()))
        .clone()
}
fn byte_array_32(seed: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (idx, byte) in out.iter_mut().enumerate() {
        let idx = u8::try_from(idx).expect("byte array index fits in u8");
        *byte = seed.wrapping_add(1).wrapping_add(idx.wrapping_mul(17));
    }
    out
}
fn byte_array_16(seed: u8) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (idx, byte) in out.iter_mut().enumerate() {
        let idx = u8::try_from(idx).expect("byte array index fits in u8");
        *byte = seed.wrapping_add(idx.wrapping_mul(29));
    }
    out
}
fn sample_message(seed: u8) -> Vec<u8> {
    let len = (seed as usize % 63) + 1;
    (0..len)
        .map(|idx| {
            let idx = u8::try_from(idx).expect("sample message length fits in u8");
            seed.wrapping_mul(13).wrapping_add(idx)
        })
        .collect()
}
#[test]
fn sm2_invalid_rs_are_rejected() {
    let private =
        Sm2PrivateKey::from_seed(Sm2PublicKey::DEFAULT_DISTID, &byte_array_32(0xAA)).expect("key");
    let keypair = KeyPair::try_from_seed(vec![0xAB; 32], Algorithm::Sm2)
        .expect("fixture seed derives SM2 keypair");
    let keypair_public = keypair.public_key();
    let public = private.public_key();
    let invalid_signatures = [
        [0_u8; Sm2Signature::LENGTH],
        [0xFF; Sm2Signature::LENGTH],
        byte_array_32(1).repeat(2).try_into().expect("64 bytes"),
    ];
    for bytes in invalid_signatures {
        let signature = Signature::from_bytes(&bytes);
        assert!(matches!(
            signature.verify(keypair_public, b"fuzz"),
            Err(Error::Parse(_) | Error::BadSignature)
        ));
        if let Ok(sm2_signature) = Sm2Signature::from_bytes(&bytes) {
            assert!(matches!(
                public.verify(b"fuzz", &sm2_signature),
                Err(Error::BadSignature)
            ));
        }
    }
}
#[test]
fn sm2_wrong_distid_is_rejected() {
    let secret = [0xAA; 32];
    let private = Sm2PrivateKey::new(Sm2PublicKey::DEFAULT_DISTID, secret).expect("key");
    let message = b"sm2 fuzz";
    let signature = private.sign(message);
    let pk_bytes = private.public_key().to_sec1_bytes(false);
    for distid in [byte_array_16(0), byte_array_16(3), byte_array_16(0x7F)] {
        let distid_suffix = u128::from_be_bytes(distid);
        let alt_distid = format!("ALT-{distid_suffix:032X}");
        let altered = Sm2PublicKey::from_sec1_bytes(&alt_distid, &pk_bytes)
            .expect("distid alteration should yield valid key point");
        assert!(matches!(
            altered.verify(message, &signature),
            Err(Error::BadSignature)
        ));
    }
}
#[test]
fn sm2_valid_signature_roundtrip() {
    for seed in [1_u8, 2, 7, 31, 127, 255] {
        let sk = Sm2PrivateKey::from_seed(Sm2PublicKey::DEFAULT_DISTID, &byte_array_32(seed))
            .expect("seeded key");
        let message = sample_message(seed);
        let signature = sk.sign(&message);
        let pk = sk.public_key();
        assert!(pk.verify(&message, &signature).is_ok());
    }
}
#[test]
fn sm2_compute_z_matches_signing_key() {
    for seed in [1_u8, 2, 7, 31, 127, 255] {
        let distid_entropy = byte_array_16(seed);
        let distid = format!(
            "device:{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            distid_entropy[0],
            distid_entropy[1],
            distid_entropy[2],
            distid_entropy[3],
            distid_entropy[4],
            distid_entropy[5],
            distid_entropy[6],
            distid_entropy[7]
        );
        let private = match Sm2PrivateKey::from_seed(&distid, &byte_array_32(seed)) {
            Ok(private) => private,
            Err(_) => continue,
        };
        let public = private.public_key();
        let za = public
            .compute_z(&distid)
            .expect("compute ZA for generated key");
        let message = sample_message(seed);
        let signature = private.sign(&message);
        let mut hasher = Sm3::new();
        hasher.update(za);
        hasher.update(&message);
        let digest = hasher.finalize();
        let raw = Sm2RawSignature::from_bytes(&signature.as_bytes())
            .expect("signature converts to raw SM2 form");
        public
            .as_inner()
            .verify_prehash(digest.as_slice(), &raw)
            .expect("prehash verification must succeed");
    }
}
#[test]
fn sm2_upstream_negative_vectors_fail() {
    let private = Sm2PrivateKey::from_seed(Sm2PublicKey::DEFAULT_DISTID, b"sm2-negative-vectors")
        .expect("deterministic key");
    for vector in load_negative_vectors_arc().iter() {
        let outcome = apply_mutation(vector, &private);
        if outcome.public_parse_failed {
            continue;
        }
        if outcome.expect_signature_parse_error {
            if let Ok(bytes) = outcome.signature_bytes.clone().try_into() {
                assert!(
                    Sm2Signature::from_bytes(&bytes).is_err(),
                    "Negative vector `{}` should fail to parse",
                    vector.label
                );
            } else {
                assert_ne!(outcome.signature_bytes.len(), Sm2Signature::LENGTH);
            }
            continue;
        }
        let sig_bytes: [u8; Sm2Signature::LENGTH] = outcome
            .signature_bytes
            .clone()
            .try_into()
            .expect("mutation should retain 64-byte signature");
        let signature = Sm2Signature::from_bytes(&sig_bytes)
            .expect("mutation marked for verification should parse");
        let verify_result = outcome
            .public_key
            .verify(&outcome.verify_message, &signature);
        assert!(
            verify_result.is_err(),
            "Negative vector `{}` unexpectedly verified",
            vector.label
        );
    }
}
#[test]
fn sm2_wycheproof_cases_hold() {
    for case in load_wycheproof_cases().iter() {
        let public = match Sm2PublicKey::from_sec1_bytes(&case.distid, &case.public_sec1) {
            Ok(public) => public,
            Err(_) => continue,
        };
        match Sm2Signature::from_der(&case.signature_der) {
            Ok(signature) => {
                let verify = public.verify(&case.message, &signature);
                if case.expect_valid {
                    assert!(verify.is_ok());
                } else {
                    assert!(verify.is_err());
                }
            }
            Err(_) => {
                assert!(!case.expect_valid);
            }
        }
    }
}
#[test]
fn sm2_wycheproof_detects_deterministic_tampering() {
    for case in load_valid_wycheproof_cases().iter() {
        let public = match Sm2PublicKey::from_sec1_bytes(&case.distid, &case.public_sec1) {
            Ok(public) => public,
            Err(_) => continue,
        };
        let signature =
            Sm2Signature::from_der(&case.signature_der).expect("valid Wycheproof signature");
        if !case.message.is_empty() {
            let mut tampered_message = case.message.clone();
            let idx = tampered_message.len() / 2;
            tampered_message[idx] ^= 0x80;
            let verify = public.verify(&tampered_message, &signature);
            assert!(verify.is_err());
        }
        let mut tampered_signature = case.signature_der.clone();
        if !tampered_signature.is_empty() {
            let idx = tampered_signature.len() - 1;
            tampered_signature[idx] ^= if tampered_signature[idx] == 0 {
                0x01
            } else {
                0x80
            };
            if let Ok(tampered) = Sm2Signature::from_der(&tampered_signature) {
                let verify = public.verify(&case.message, &tampered);
                assert!(verify.is_err());
            }
        }
    }
}
#[test]
fn sm2_truncated_signature_is_rejected() {
    for case in load_valid_wycheproof_cases().iter() {
        let public = match Sm2PublicKey::from_sec1_bytes(&case.distid, &case.public_sec1) {
            Ok(public) => public,
            Err(_) => continue,
        };
        let mut truncated = case.signature_der.clone();
        if truncated.len() < 2 {
            continue;
        }
        truncated.truncate(truncated.len() - 2);
        if let Ok(sig) = Sm2Signature::from_der(&truncated) {
            let verify = public.verify(&case.message, &sig);
            assert!(verify.is_err());
        }
    }
}
#[test]
fn sm2_bitflip_signature_is_rejected() {
    for case in load_valid_wycheproof_cases().iter() {
        let public = match Sm2PublicKey::from_sec1_bytes(&case.distid, &case.public_sec1) {
            Ok(public) => public,
            Err(_) => continue,
        };
        let mut tampered = case.signature_der.clone();
        if tampered.is_empty() {
            continue;
        }
        let idx = tampered.len() - 1;
        tampered[idx] ^= if tampered[idx] == 0 { 0x01 } else { 0x80 };
        if let Ok(sig) = Sm2Signature::from_der(&tampered) {
            let verify = public.verify(&case.message, &sig);
            assert!(verify.is_err());
        }
    }
}
