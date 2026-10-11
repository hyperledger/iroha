//! Deterministic tests for SM4 AEAD helpers.
#![cfg(feature = "sm")]
use super::sm4_wycheproof_fixture::{Sm4WycheproofMode, load_sm4_wycheproof_cases};
use iroha_crypto::Sm4Key;
const TAG_LENGTHS: [usize; 7] = [4, 6, 8, 10, 12, 14, 16];
fn u8_index(idx: usize) -> u8 {
    u8::try_from(idx).expect("test helper index fits in u8")
}
fn key(seed: u8) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (idx, byte) in out.iter_mut().enumerate() {
        *byte = seed.wrapping_add(u8_index(idx).wrapping_mul(19));
    }
    out
}
fn nonce12(seed: u8) -> [u8; 12] {
    let mut out = [0u8; 12];
    for (idx, byte) in out.iter_mut().enumerate() {
        *byte = seed.wrapping_add(u8_index(idx).wrapping_mul(23));
    }
    out
}
fn bytes(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|idx| seed.wrapping_mul(31).wrapping_add(u8_index(idx)))
        .collect()
}
#[test]
fn sm4_wycheproof_invalid_cases_are_rejected() {
    for case in load_sm4_wycheproof_cases() {
        let key = Sm4Key::new(case.key);
        match case.mode {
            Sm4WycheproofMode::Gcm => {
                let nonce: [u8; 12] =
                    case.nonce.as_slice().try_into().unwrap_or_else(|_| {
                        panic!("GCM test {} must use 12-byte nonce", case.tc_id)
                    });
                let tag: [u8; 16] = case
                    .tag
                    .as_slice()
                    .try_into()
                    .unwrap_or_else(|_| panic!("GCM test {} must use 16-byte tag", case.tc_id));
                assert!(
                    key.decrypt_gcm(&nonce, &case.aad, &case.ciphertext, &tag)
                        .is_err(),
                    "SM4-GCM Wycheproof case {} ({}) unexpectedly succeeded",
                    case.tc_id,
                    case.comment
                );
            }
            Sm4WycheproofMode::Ccm => {
                assert!(
                    key.decrypt_ccm(&case.nonce, &case.aad, &case.ciphertext, &case.tag)
                        .is_err(),
                    "SM4-CCM Wycheproof case {} ({}) unexpectedly succeeded",
                    case.tc_id,
                    case.comment
                );
            }
        }
    }
}
#[test]
fn sm4_gcm_detects_tampering_deterministic() {
    for seed in [0_u8, 1, 7, 31, 127, 255] {
        let key = Sm4Key::new(key(seed));
        let nonce = nonce12(seed);
        let aad = bytes(seed.wrapping_add(1), seed as usize % 32);
        let plaintext = bytes(seed.wrapping_add(2), (seed as usize % 63) + 1);
        let (ciphertext, tag) = key
            .encrypt_gcm(&nonce, &aad, &plaintext)
            .expect("encrypt_gcm should succeed with 16-byte key");
        let mut tampered_tag = tag;
        let idx = seed as usize % tampered_tag.len();
        tampered_tag[idx] ^= 0x01;
        assert!(
            key.decrypt_gcm(&nonce, &aad, &ciphertext, &tampered_tag)
                .is_err(),
            "SM4-GCM must reject when tag byte {idx} is flipped",
        );
        let mut tampered_cipher = ciphertext.clone();
        tampered_cipher[0] ^= 0x80;
        assert!(
            key.decrypt_gcm(&nonce, &aad, &tampered_cipher, &tag)
                .is_err(),
            "SM4-GCM must reject when ciphertext is modified",
        );
    }
}
#[test]
fn sm4_ccm_detects_tampering_deterministic() {
    for seed in [0_u8, 1, 7, 31, 127, 255] {
        for tag_len in TAG_LENGTHS {
            let key = Sm4Key::new(key(seed));
            let nonce = bytes(seed.wrapping_add(3), 7 + (seed as usize % 7));
            let aad = bytes(seed.wrapping_add(4), seed as usize % 32);
            let plaintext = bytes(seed.wrapping_add(5), (seed as usize % 63) + 1);
            let (ciphertext, tag) = key
                .encrypt_ccm(&nonce, &aad, &plaintext, tag_len)
                .expect("encrypt_ccm should succeed for supported tag lengths");
            let mut tampered_cipher = ciphertext.clone();
            tampered_cipher[0] ^= 0x40;
            assert!(
                key.decrypt_ccm(&nonce, &aad, &tampered_cipher, &tag)
                    .is_err(),
                "SM4-CCM must reject modified ciphertext",
            );
            let mut tampered_tag = tag.clone();
            let idx = seed as usize % tampered_tag.len();
            tampered_tag[idx] ^= 0x02;
            assert!(
                key.decrypt_ccm(&nonce, &aad, &ciphertext, &tampered_tag)
                    .is_err(),
                "SM4-CCM must reject altered tag",
            );
            if tag.len() > 1 {
                let truncated_tag = &tampered_tag[..tampered_tag.len() - 1];
                assert!(
                    key.decrypt_ccm(&nonce, &aad, &ciphertext, truncated_tag)
                        .is_err(),
                    "SM4-CCM must reject truncated tags",
                );
            }
        }
    }
}
