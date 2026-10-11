//! Regression tests for SM3 and SM4 helpers.
#![cfg(feature = "sm")]
use super::sm4_wycheproof_fixture::{Sm4WycheproofMode, load_sm4_wycheproof_cases};
use hex::decode as hex_decode;
use iroha_crypto::{Sm3Digest, Sm4Key};
fn hex_to_vec(input: &str) -> Vec<u8> {
    if input.is_empty() {
        Vec::new()
    } else {
        hex_decode(input).unwrap_or_else(|err| panic!("invalid hex {input}: {err}"))
    }
}
fn hex_to_array<const N: usize>(input: &str) -> [u8; N] {
    let bytes = hex_to_vec(input);
    bytes
        .as_slice()
        .try_into()
        .unwrap_or_else(|_| panic!("expected {N} bytes"))
}
#[test]
fn sm3_known_hashes() {
    let cases = [
        (
            "",
            "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b",
        ),
        (
            "abc",
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
        ),
        (
            "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
            "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
        ),
    ];
    for (input, expected_hex) in cases {
        let digest = Sm3Digest::hash(input.as_bytes());
        let expected = hex_to_array::<32>(expected_hex);
        assert_eq!(
            digest.as_bytes(),
            &expected,
            "SM3 digest mismatch for input '{input}'"
        );
    }
}
#[test]
fn sm4_ecb_vectors() {
    let cases = [
        (
            "0123456789abcdeffedcba9876543210",
            "0123456789abcdeffedcba9876543210",
        ),
        (
            "0123456789abcdeffedcba9876543210",
            "000102030405060708090a0b0c0d0e0f",
        ),
        (
            "0123456789abcdeffedcba9876543210",
            "ffeeddccbbaa99887766554433221100",
        ),
    ];
    for (key_hex, pt_hex) in cases {
        let key = Sm4Key::new(hex_to_array::<16>(key_hex));
        let plaintext = hex_to_array::<16>(pt_hex);
        let ciphertext = key.encrypt_block(&plaintext);
        let decrypted = key.decrypt_block(&ciphertext);
        assert_eq!(
            decrypted, plaintext,
            "SM4 round-trip mismatch for plaintext {pt_hex}"
        );
    }
}
#[test]
fn sm4_gcm_vector() {
    let key = Sm4Key::new(hex_to_array::<16>("0123456789abcdeffedcba9876543210"));
    let nonce = hex_to_array::<12>("00001234567800000000abcd");
    let aad = hex_to_vec("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    let plaintext = hex_to_vec("d9313225f88406e5a55909c5aff5269a");
    let (ciphertext, tag) = key
        .encrypt_gcm(&nonce, &aad, &plaintext)
        .expect("SM4-GCM encrypt");
    let decrypted = key
        .decrypt_gcm(&nonce, &aad, &ciphertext, &tag)
        .expect("SM4-GCM decrypt");
    assert_eq!(decrypted, plaintext, "SM4-GCM round-trip mismatch");
}
#[test]
fn sm4_gcm_rejects_modified_tag() {
    let key = Sm4Key::new(hex_to_array::<16>("0123456789abcdeffedcba9876543210"));
    let nonce = hex_to_array::<12>("00001234567800000000abcd");
    let aad = hex_to_vec("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    let plaintext = hex_to_vec("d9313225f88406e5a55909c5aff5269a");
    let (ciphertext, mut tag) = key
        .encrypt_gcm(&nonce, &aad, &plaintext)
        .expect("SM4-GCM encrypt");
    tag[0] ^= 0xFF;
    let result = key.decrypt_gcm(&nonce, &aad, &ciphertext, &tag);
    assert!(
        result.is_err(),
        "modified tag must cause decryption failure"
    );
}
#[test]
fn sm4_gcm_wycheproof_invalid_cases() {
    for case in load_sm4_wycheproof_cases()
        .into_iter()
        .filter(|case| case.mode == Sm4WycheproofMode::Gcm)
    {
        let key = Sm4Key::new(case.key);
        let nonce: [u8; 12] = case
            .nonce
            .as_slice()
            .try_into()
            .unwrap_or_else(|_| panic!("GCM test {} must use 12-byte nonce", case.tc_id));
        let tag: [u8; 16] = case
            .tag
            .as_slice()
            .try_into()
            .unwrap_or_else(|_| panic!("GCM test {} must use 16-byte tag", case.tc_id));
        let result = key.decrypt_gcm(&nonce, &case.aad, &case.ciphertext, &tag);
        assert!(
            result.is_err(),
            "Wycheproof SM4-GCM case {} ({}) unexpectedly succeeded",
            case.tc_id,
            case.comment
        );
    }
}
#[test]
fn sm4_ccm_wycheproof_invalid_cases() {
    for case in load_sm4_wycheproof_cases()
        .into_iter()
        .filter(|case| case.mode == Sm4WycheproofMode::Ccm)
    {
        let key = Sm4Key::new(case.key);
        let result = key.decrypt_ccm(&case.nonce, &case.aad, &case.ciphertext, &case.tag);
        assert!(
            result.is_err(),
            "Wycheproof SM4-CCM case {} ({}) unexpectedly succeeded",
            case.tc_id,
            case.comment
        );
    }
}
#[test]
fn sm4_ccm_vector() {
    let key = Sm4Key::new(hex_to_array::<16>("404142434445464748494a4b4c4d4e4f"));
    let nonce = hex_to_vec("10111213141516");
    let aad = hex_to_vec("000102030405060708090a0b0c0d0e0f");
    let plaintext = hex_to_vec("202122232425262728292a2b2c2d2e2f");
    let (ciphertext, tag) = key
        .encrypt_ccm(&nonce, &aad, &plaintext, 4)
        .expect("SM4-CCM encryption should succeed");
    let decrypted = key
        .decrypt_ccm(&nonce, &aad, &ciphertext, &tag)
        .expect("SM4-CCM decryption should succeed");
    assert_eq!(decrypted, plaintext);
    assert_eq!(ciphertext, hex_to_vec("a9550cebab5f227d9590e8979caafd1f"));
    assert_eq!(tag, hex_to_vec("03a1f305"));
}
#[test]
fn sm4_ccm_rejects_bad_tag() {
    let key = Sm4Key::new(hex_to_array::<16>("404142434445464748494a4b4c4d4e4f"));
    let nonce = hex_to_vec("10111213141516");
    let aad = hex_to_vec("000102030405060708090a0b0c0d0e0f");
    let plaintext = hex_to_vec("202122232425262728292a2b2c2d2e2f");
    let (ciphertext, mut tag) = key
        .encrypt_ccm(&nonce, &aad, &plaintext, 4)
        .expect("SM4-CCM encryption should succeed");
    tag[0] ^= 0x01;
    assert!(
        key.decrypt_ccm(&nonce, &aad, &ciphertext, &tag).is_err(),
        "SM4-CCM must reject altered tag"
    );
}
mod deterministic_tamper_tests {
    use super::*;
    fn array16(seed: u8) -> [u8; 16] {
        let mut out = [0u8; 16];
        for (idx, byte) in out.iter_mut().enumerate() {
            let idx = u8::try_from(idx).expect("array16 index fits in u8");
            *byte = seed.wrapping_add(idx.wrapping_mul(17));
        }
        out
    }
    fn array12(seed: u8) -> [u8; 12] {
        let mut out = [0u8; 12];
        for (idx, byte) in out.iter_mut().enumerate() {
            let idx = u8::try_from(idx).expect("array12 index fits in u8");
            *byte = seed.wrapping_add(idx.wrapping_mul(23));
        }
        out
    }
    fn bytes(seed: u8, len: usize) -> Vec<u8> {
        (0..len)
            .map(|idx| {
                let idx = u8::try_from(idx).expect("test vector length fits in u8");
                seed.wrapping_mul(31).wrapping_add(idx)
            })
            .collect()
    }
    #[test]
    fn sm4_gcm_rejects_tampered_ciphertext() {
        for seed in [0_u8, 1, 7, 31, 127, 255] {
            let key_bytes = array16(seed);
            let nonce_bytes = array12(seed);
            let aad = bytes(seed.wrapping_add(1), seed as usize % 32);
            let plaintext = bytes(seed.wrapping_add(2), (seed as usize % 64) + 1);
            let key = Sm4Key::new(key_bytes);
            let (ciphertext, tag) = key
                .encrypt_gcm(&nonce_bytes, &aad, &plaintext)
                .expect("SM4-GCM encrypt");
            let mut tampered = ciphertext.clone();
            let idx = seed as usize % tampered.len();
            tampered[idx] ^= 0x01;
            assert!(
                key.decrypt_gcm(&nonce_bytes, &aad, &tampered, &tag)
                    .is_err()
            );
        }
    }
    #[test]
    fn sm4_gcm_rejects_tampered_tag() {
        for seed in [0_u8, 1, 7, 31, 127, 255] {
            let key_bytes = array16(seed);
            let nonce_bytes = array12(seed);
            let aad = bytes(seed.wrapping_add(1), seed as usize % 32);
            let plaintext = bytes(seed.wrapping_add(2), (seed as usize % 64) + 1);
            let key = Sm4Key::new(key_bytes);
            let (ciphertext, mut tag) = key
                .encrypt_gcm(&nonce_bytes, &aad, &plaintext)
                .expect("SM4-GCM encrypt");
            let idx = seed as usize % tag.len();
            tag[idx] ^= 0x80;
            assert!(
                key.decrypt_gcm(&nonce_bytes, &aad, &ciphertext, &tag)
                    .is_err()
            );
        }
    }
    #[test]
    fn sm4_ccm_rejects_tampered_tag() {
        for seed in [0_u8, 1, 7, 31, 127, 255] {
            let key_bytes = array16(seed);
            let nonce_bytes = array12(seed);
            let aad = bytes(seed.wrapping_add(1), seed as usize % 32);
            let plaintext = bytes(seed.wrapping_add(2), (seed as usize % 48) + 1);
            let key = Sm4Key::new(key_bytes);
            let (ciphertext, mut tag) = key
                .encrypt_ccm(&nonce_bytes, &aad, &plaintext, 10)
                .expect("SM4-CCM encrypt");
            let idx = seed as usize % tag.len();
            tag[idx] ^= 0x01;
            assert!(
                key.decrypt_ccm(&nonce_bytes, &aad, &ciphertext, &tag)
                    .is_err()
            );
        }
    }
}
