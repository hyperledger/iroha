//! Iroha patch tests: the always-public portable backend (`aes::soft`) and the
//! feature-selected top-level types agree with FIPS 197 Appendix C and with
//! each other, with and without the `hardware` feature.

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use hex_literal::hex;

/// FIPS 197 Appendix C plaintext, shared by C.1, C.2 and C.3.
const PLAINTEXT: [u8; 16] = hex!("00112233445566778899aabbccddeeff");
/// FIPS 197 Appendix C.1 (AES-128).
const KEY_128: [u8; 16] = hex!("000102030405060708090a0b0c0d0e0f");
const CIPHERTEXT_128: [u8; 16] = hex!("69c4e0d86a7b0430d8cdb78070b4c55a");
/// FIPS 197 Appendix C.2 (AES-192).
const KEY_192: [u8; 24] = hex!("000102030405060708090a0b0c0d0e0f1011121314151617");
const CIPHERTEXT_192: [u8; 16] = hex!("dda97ca4864cdfe06eaf70a0ec0d7191");
/// FIPS 197 Appendix C.3 (AES-256).
const KEY_256: [u8; 32] =
    hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
const CIPHERTEXT_256: [u8; 16] = hex!("8ea2b7ca516745bfeafc49904b496089");

/// Compile-time reachability of the portable module. This file is also built
/// by `cargo test --no-default-features`, which proves the path exists without
/// the `hardware` feature.
const _: fn() = || {
    fn key_init<T: KeyInit + BlockEncrypt + BlockDecrypt>() {}
    fn enc<T: KeyInit + BlockEncrypt>() {}
    fn dec<T: KeyInit + BlockDecrypt>() {}
    key_init::<aes::soft::Aes128>();
    key_init::<aes::soft::Aes192>();
    key_init::<aes::soft::Aes256>();
    enc::<aes::soft::Aes128Enc>();
    enc::<aes::soft::Aes192Enc>();
    enc::<aes::soft::Aes256Enc>();
    dec::<aes::soft::Aes128Dec>();
    dec::<aes::soft::Aes192Dec>();
    dec::<aes::soft::Aes256Dec>();
};

/// Without `hardware` (or with `--cfg aes_force_soft`) the top-level types are
/// the portable types themselves, not wrappers.
#[cfg(any(not(feature = "hardware"), aes_force_soft))]
const _: fn(aes::Aes128, aes::Aes192, aes::Aes256) -> (
    aes::soft::Aes128,
    aes::soft::Aes192,
    aes::soft::Aes256,
) = |a, b, c| (a, b, c);

/// Deterministic SplitMix64 byte stream; test inputs only.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let word = self.next().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
    }
}

macro_rules! backend_tests {
    ($name:ident, $cipher:ident, $enc:ident, $dec:ident, $key:expr, $ciphertext:expr, $seed:expr) => {
        mod $name {
            use super::*;

            #[test]
            fn fips_197_appendix_c() {
                let key = GenericArray::from($key);

                let mut block = GenericArray::from(PLAINTEXT);
                aes::soft::$cipher::new(&key).encrypt_block(&mut block);
                assert_eq!(block.as_slice(), &$ciphertext[..], "portable encrypt");
                aes::soft::$cipher::new(&key).decrypt_block(&mut block);
                assert_eq!(block.as_slice(), &PLAINTEXT[..], "portable decrypt");

                let mut block = GenericArray::from(PLAINTEXT);
                aes::$cipher::new(&key).encrypt_block(&mut block);
                assert_eq!(block.as_slice(), &$ciphertext[..], "default encrypt");
                aes::$cipher::new(&key).decrypt_block(&mut block);
                assert_eq!(block.as_slice(), &PLAINTEXT[..], "default decrypt");

                let mut block = GenericArray::from(PLAINTEXT);
                aes::soft::$enc::new(&key).encrypt_block(&mut block);
                assert_eq!(block.as_slice(), &$ciphertext[..], "portable Enc");
                aes::soft::$dec::new(&key).decrypt_block(&mut block);
                assert_eq!(block.as_slice(), &PLAINTEXT[..], "portable Dec");

                let mut block = GenericArray::from(PLAINTEXT);
                aes::$enc::new(&key).encrypt_block(&mut block);
                assert_eq!(block.as_slice(), &$ciphertext[..], "default Enc");
                aes::$dec::new(&key).decrypt_block(&mut block);
                assert_eq!(block.as_slice(), &PLAINTEXT[..], "default Dec");
            }

            #[test]
            fn portable_and_default_agree_on_random_blocks() {
                let mut rng = SplitMix64($seed);
                for _ in 0..64 {
                    let mut key = $key;
                    rng.fill(&mut key);
                    let key = GenericArray::from(key);
                    let portable = aes::soft::$cipher::new(&key);
                    let default = aes::$cipher::new(&key);

                    let mut plain = [0u8; 16];
                    rng.fill(&mut plain);
                    let mut a = GenericArray::from(plain);
                    let mut b = a;
                    portable.encrypt_block(&mut a);
                    default.encrypt_block(&mut b);
                    assert_eq!(a, b, "single-block encrypt");
                    assert_ne!(a.as_slice(), &plain[..]);
                    // Cross-decrypt: each backend inverts the other.
                    default.decrypt_block(&mut a);
                    portable.decrypt_block(&mut b);
                    assert_eq!(a.as_slice(), &plain[..]);
                    assert_eq!(b.as_slice(), &plain[..]);

                    // 19 blocks exercises the parallel paths plus a tail.
                    let mut many = [GenericArray::from([0u8; 16]); 19];
                    for block in many.iter_mut() {
                        rng.fill(block.as_mut_slice());
                    }
                    let original = many;
                    let mut other = many;
                    portable.encrypt_blocks(&mut many);
                    default.encrypt_blocks(&mut other);
                    assert_eq!(many, other, "multi-block encrypt");
                    default.decrypt_blocks(&mut many);
                    portable.decrypt_blocks(&mut other);
                    assert_eq!(many, original);
                    assert_eq!(other, original);
                }
            }
        }
    };
}

backend_tests!(aes128, Aes128, Aes128Enc, Aes128Dec, KEY_128, CIPHERTEXT_128, 0x0128);
backend_tests!(aes192, Aes192, Aes192Enc, Aes192Dec, KEY_192, CIPHERTEXT_192, 0x0192);
backend_tests!(aes256, Aes256, Aes256Enc, Aes256Dec, KEY_256, CIPHERTEXT_256, 0x0256);

/// Reports which backend the default types resolved to in this test build, so
/// a `hardware` run that silently compared the portable backend with itself is
/// visible in `--nocapture` output and fails where detection is guaranteed.
#[test]
fn default_backend_matches_feature_selection() {
    let key = GenericArray::from(KEY_128);
    let portable = core::mem::size_of_val(&aes::soft::Aes128::new(&key));
    let default = core::mem::size_of_val(&aes::Aes128::new(&key));
    if cfg!(any(not(feature = "hardware"), aes_force_soft)) {
        assert_eq!(portable, default);
    } else if cfg!(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "aarch64"
    )) {
        // The autodetecting type is a distinct wrapper around both backends.
        assert_ne!(
            core::any::type_name::<aes::Aes128>(),
            core::any::type_name::<aes::soft::Aes128>()
        );
    }
}
