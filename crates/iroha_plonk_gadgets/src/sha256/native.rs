//! Native SHA-256 (FIPS 180-4) and the spread arithmetic the chip mirrors.
//!
//! Everything here is the reference the chip is tested against and the
//! witness generator it runs: the compression function, padding, the
//! interleaved ("spread") form of 32-bit words, and the KAGEMUSHA digest
//! codec (a Pasta field element as the 32-byte canonical little-endian
//! message of one SHA-256 block).

use iroha_pasta::PastaField;

/// Words of a SHA-256 message block.
pub const BLOCK_WORDS: usize = 16;

/// Words of a SHA-256 chaining state.
pub const STATE_WORDS: usize = 8;

/// Rounds of the compression function (and words of the message schedule).
pub const ROUNDS: usize = 64;

/// The initial hash value `H(0)` (FIPS 180-4 section 5.3.3).
pub const SHA256_IV: [u32; STATE_WORDS] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// The round constants `K_t` (FIPS 180-4 section 4.2.2).
pub const SHA256_K: [u32; ROUNDS] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// `spread(2^32 - 1)`: every even bit of a 64-bit word set.
pub const SPREAD_ONES: u64 = 0x5555_5555_5555_5555;

/// `Σ0(x) = ROTR2 ⊕ ROTR13 ⊕ ROTR22`.
#[must_use]
pub const fn big_sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

/// `Σ1(x) = ROTR6 ⊕ ROTR11 ⊕ ROTR25`.
#[must_use]
pub const fn big_sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

/// `σ0(x) = ROTR7 ⊕ ROTR18 ⊕ SHR3`.
#[must_use]
pub const fn small_sigma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

/// `σ1(x) = ROTR17 ⊕ ROTR19 ⊕ SHR10`.
#[must_use]
pub const fn small_sigma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

/// `Ch(e, f, g) = (e ∧ f) ⊕ (¬e ∧ g)`.
#[must_use]
pub const fn ch(e: u32, f: u32, g: u32) -> u32 {
    (e & f) ^ (!e & g)
}

/// `Maj(a, b, c) = (a ∧ b) ⊕ (a ∧ c) ⊕ (b ∧ c)`.
#[must_use]
pub const fn maj(a: u32, b: u32, c: u32) -> u32 {
    (a & b) ^ (a & c) ^ (b & c)
}

/// The message schedule `W_0 .. W_63` of one block.
#[must_use]
pub fn schedule(block: &[u32; BLOCK_WORDS]) -> [u32; ROUNDS] {
    let mut w = [0_u32; ROUNDS];
    w[..BLOCK_WORDS].copy_from_slice(block);
    for t in BLOCK_WORDS..ROUNDS {
        w[t] = small_sigma1(w[t - 2])
            .wrapping_add(w[t - 7])
            .wrapping_add(small_sigma0(w[t - 15]))
            .wrapping_add(w[t - 16]);
    }
    w
}

/// The SHA-256 compression function: the chaining state after one block.
#[must_use]
#[allow(clippy::many_single_char_names)] // the FIPS 180-4 working variables
pub fn compress(state: &[u32; STATE_WORDS], block: &[u32; BLOCK_WORDS]) -> [u32; STATE_WORDS] {
    let w = schedule(block);
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for t in 0..ROUNDS {
        let t1 = h
            .wrapping_add(big_sigma1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(SHA256_K[t])
            .wrapping_add(w[t]);
        let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    let mut out = *state;
    for (word, add) in out.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *word = word.wrapping_add(add);
    }
    out
}

/// The padded blocks of `message` (FIPS 180-4 section 5.1.1), or `None`
/// when its bit length does not fit 64 bits.
#[must_use]
pub fn pad(message: &[u8]) -> Option<Vec<[u32; BLOCK_WORDS]>> {
    let bit_len = u64::try_from(message.len()).ok()?.checked_mul(8)?;
    let mut bytes = message.to_vec();
    bytes.push(0x80);
    while bytes.len() % 64 != 56 {
        bytes.push(0);
    }
    bytes.extend_from_slice(&bit_len.to_be_bytes());
    Some(
        bytes
            .chunks_exact(64)
            .map(|chunk| {
                let mut block = [0_u32; BLOCK_WORDS];
                for (word, bytes) in block.iter_mut().zip(chunk.chunks_exact(4)) {
                    *word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                }
                block
            })
            .collect(),
    )
}

/// The big-endian bytes of a chaining state (the digest after the last
/// block).
#[must_use]
pub fn state_bytes(state: &[u32; STATE_WORDS]) -> [u8; 32] {
    let mut out = [0_u8; 32];
    for (bytes, word) in out.chunks_exact_mut(4).zip(state) {
        bytes.copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// SHA-256 of `message`, or `None` when its bit length does not fit 64
/// bits.
#[must_use]
pub fn sha256(message: &[u8]) -> Option<[u8; 32]> {
    let state = pad(message)?
        .iter()
        .fold(SHA256_IV, |state, block| compress(&state, block));
    Some(state_bytes(&state))
}

/// The interleaved form of `x`: bit `i` of `x` becomes bit `2 i`.
#[must_use]
pub const fn spread(x: u32) -> u64 {
    let mut v = x as u64;
    v = (v | (v << 16)) & 0x0000_ffff_0000_ffff;
    v = (v | (v << 8)) & 0x00ff_00ff_00ff_00ff;
    v = (v | (v << 4)) & 0x0f0f_0f0f_0f0f_0f0f;
    v = (v | (v << 2)) & 0x3333_3333_3333_3333;
    (v | (v << 1)) & SPREAD_ONES
}

/// The even bits of `s` packed back into a word (the inverse of
/// [`spread`] on spread values).
#[must_use]
pub const fn compact(s: u64) -> u32 {
    let mut v = s & SPREAD_ONES;
    v = (v | (v >> 1)) & 0x3333_3333_3333_3333;
    v = (v | (v >> 2)) & 0x0f0f_0f0f_0f0f_0f0f;
    v = (v | (v >> 4)) & 0x00ff_00ff_00ff_00ff;
    v = (v | (v >> 8)) & 0x0000_ffff_0000_ffff;
    v = (v | (v >> 16)) & 0x0000_0000_ffff_ffff;
    let bytes = v.to_le_bytes();
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// The even and odd halves of a spread sum `s = spread(x) + 2 spread(y)`:
/// `(x, y)`. For a sum of up to three spread words every base-4 digit is
/// at most 3, so `x` is their bitwise XOR and `y` their bitwise majority.
#[must_use]
pub const fn split(s: u64) -> (u32, u32) {
    (compact(s), compact(s >> 1))
}

/// `spread(ROTR2 x) + spread(ROTR13 x) + spread(ROTR22 x)`: the spread sum
/// whose even half is `Σ0(x)`.
#[must_use]
pub const fn big_sigma0_spread_sum(x: u32) -> u64 {
    spread(x.rotate_right(2)) + spread(x.rotate_right(13)) + spread(x.rotate_right(22))
}

/// The spread sum whose even half is `Σ1(x)`.
#[must_use]
pub const fn big_sigma1_spread_sum(x: u32) -> u64 {
    spread(x.rotate_right(6)) + spread(x.rotate_right(11)) + spread(x.rotate_right(25))
}

/// The spread sum whose even half is `σ0(x)`.
#[must_use]
pub const fn small_sigma0_spread_sum(x: u32) -> u64 {
    spread(x.rotate_right(7)) + spread(x.rotate_right(18)) + spread(x >> 3)
}

/// The spread sum whose even half is `σ1(x)`.
#[must_use]
pub const fn small_sigma1_spread_sum(x: u32) -> u64 {
    spread(x.rotate_right(17)) + spread(x.rotate_right(19)) + spread(x >> 10)
}

/// The canonical little-endian 32-bit limbs of a Pasta field element.
#[must_use]
pub fn canonical_u32_limbs<D: PastaField>(value: &D) -> [u32; 8] {
    let limbs = value.to_canonical_limbs();
    let mut out = [0_u32; 8];
    for (pair, limb) in out.chunks_exact_mut(2).zip(limbs) {
        let bytes = limb.to_le_bytes();
        pair[0] = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        pair[1] = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    }
    out
}

/// The 32-byte canonical (little-endian) encoding of a digest `m`: the
/// signing message of a KAGEMUSHA P-256 signature (wire record section 3.2).
#[must_use]
pub fn digest_message<D: PastaField>(m: &D) -> [u8; 32] {
    let mut out = [0_u8; 32];
    for (bytes, limb) in out.chunks_exact_mut(4).zip(canonical_u32_limbs(m)) {
        bytes.copy_from_slice(&limb.to_le_bytes());
    }
    out
}

/// The one padded SHA-256 block of the 32-byte message of `m`: the message
/// as eight big-endian words, then `0x80000000`, six zero words and the bit
/// length 256.
#[must_use]
pub fn digest_block<D: PastaField>(m: &D) -> [u32; BLOCK_WORDS] {
    let bytes = digest_message(m);
    let mut block = [0_u32; BLOCK_WORDS];
    for (word, chunk) in block.iter_mut().zip(bytes.chunks_exact(4)) {
        *word = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    block[8..].copy_from_slice(&DIGEST_PADDING);
    block
}

/// Words 8..16 of a block holding a 32-byte message: the `0x80` marker, six
/// zero words and the bit length 256.
pub const DIGEST_PADDING: [u32; 8] = [0x8000_0000, 0, 0, 0, 0, 0, 0, 256];

/// SHA-256 of the 32-byte message of `m` (one compression from the IV).
#[must_use]
pub fn sha256_of_digest<D: PastaField>(m: &D) -> [u8; 32] {
    state_bytes(&compress(&SHA256_IV, &digest_block(m)))
}

#[cfg(test)]
mod tests {
    use iroha_pasta::{Fp, Fq};
    use sha2::{Digest as _, Sha256};

    use super::*;

    /// A deterministic word stream (`SplitMix64`).
    fn words(seed: u64, count: usize) -> Vec<u32> {
        let mut state = seed;
        (0..count)
            .map(|_| {
                state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
                let mut z = state;
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                u32::try_from((z ^ (z >> 31)) >> 32).unwrap_or(0)
            })
            .collect()
    }

    #[test]
    fn fips180_vectors_and_sha2_parity() {
        assert_eq!(
            sha256(b"abc").map(|d| d.to_vec()),
            Some(
                [
                    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d,
                    0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10,
                    0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
                ]
                .to_vec()
            )
        );
        for len in [0_usize, 1, 3, 31, 32, 55, 56, 63, 64, 65, 119, 120, 200] {
            let message: Vec<u8> = (0..len)
                .map(|index| u8::try_from((index * 37 + 11) % 256).unwrap_or(0))
                .collect();
            let expected: [u8; 32] = Sha256::digest(&message).into();
            assert_eq!(sha256(&message), Some(expected), "length {len}");
        }
    }

    #[test]
    fn padding_shapes() {
        assert_eq!(pad(b"").map(|blocks| blocks.len()), Some(1));
        assert_eq!(pad(&[0; 55]).map(|blocks| blocks.len()), Some(1));
        assert_eq!(pad(&[0; 56]).map(|blocks| blocks.len()), Some(2));
        let one = pad(&[0xab; 32]).expect("padded");
        assert_eq!(one.len(), 1);
        assert_eq!(one[0][..8], [0xabab_abab; 8]);
        assert_eq!(one[0][8..], DIGEST_PADDING);
    }

    #[test]
    fn spread_compact_and_split() {
        assert_eq!(spread(0), 0);
        assert_eq!(spread(u32::MAX), SPREAD_ONES);
        assert_eq!(spread(0b1011), 0b0100_0101);
        for x in words(1, 64) {
            assert_eq!(compact(spread(x)), x);
            let reference = (0..32).fold(0_u64, |acc, bit| {
                acc | (u64::from((x >> bit) & 1) << (2 * bit))
            });
            assert_eq!(spread(x), reference);
        }
        let sample = words(2, 96);
        for chunk in sample.chunks_exact(3) {
            let [a, b, c] = [chunk[0], chunk[1], chunk[2]];
            let (even, odd) = split(spread(a) + spread(b) + spread(c));
            assert_eq!(even, a ^ b ^ c);
            assert_eq!(odd, maj(a, b, c));
            assert_eq!(compact(big_sigma0_spread_sum(a)), big_sigma0(a));
            assert_eq!(compact(big_sigma1_spread_sum(a)), big_sigma1(a));
            assert_eq!(compact(small_sigma0_spread_sum(a)), small_sigma0(a));
            assert_eq!(compact(small_sigma1_spread_sum(a)), small_sigma1(a));
            let (_, ch_p) = split(spread(a) + spread(b));
            let (_, ch_q) = split(SPREAD_ONES - spread(a) + spread(c));
            assert_eq!(ch_p + ch_q, ch(a, b, c));
        }
    }

    #[test]
    fn compress_matches_sha2_on_random_one_block_messages() {
        let sample = words(3, 16 * 8);
        for block in sample.chunks_exact(16) {
            let block: [u32; 16] = block.try_into().expect("16 words");
            let mut bytes = Vec::new();
            for word in block {
                bytes.extend_from_slice(&word.to_be_bytes());
            }
            // One compression of an arbitrary block equals SHA-256 of the
            // 64 raw bytes up to the second (padding) block, so compare the
            // full two-block hash.
            let padding = pad(&bytes).expect("padded");
            assert_eq!(padding.len(), 2);
            assert_eq!(padding[0], block);
            let state = compress(&compress(&SHA256_IV, &block), &padding[1]);
            let expected: [u8; 32] = Sha256::digest(&bytes).into();
            assert_eq!(state_bytes(&state), expected);
        }
    }

    fn digest_codec<D: PastaField>() {
        for value in [
            D::ZERO,
            D::ONE,
            -D::ONE,
            D::from(0x0102_0304_u64),
            D::from_u128(u128::MAX),
        ] {
            let bytes = digest_message(&value);
            assert_eq!(bytes, value.to_repr(), "canonical little-endian");
            let expected: [u8; 32] = Sha256::digest(bytes).into();
            assert_eq!(sha256_of_digest(&value), expected);
            assert_eq!(sha256(&bytes), Some(expected));
            let block = digest_block(&value);
            assert_eq!(
                block[0],
                u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
            );
            assert_eq!(block[8..], DIGEST_PADDING);
        }
        let limbs = canonical_u32_limbs(&-D::ONE);
        assert_eq!(limbs[7], 0x4000_0000);
        assert_eq!(limbs[0], 0);
    }

    #[test]
    fn digest_codec_matches_sha2_in_both_fields() {
        digest_codec::<Fp>();
        digest_codec::<Fq>();
    }
}
