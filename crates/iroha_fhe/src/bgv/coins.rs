//! Entropy, the domain-separated coin stream and the samplers.
//!
//! # Entropy
//!
//! Every key generation, switching-key generation and encryption draws one
//! seed of [`COIN_SEED_BYTES`] bytes from the operating system. A failed
//! draw, or a draw whose bytes are all equal (a stuck source), fails the
//! operation with [`BgvError::EntropyUnavailable`]; nothing is sampled from a
//! fallback.
//!
//! # Coin stream
//!
//! A stream is the BLAKE3 extendable output of
//! `derive_key(`[`COIN_STREAM_CONTEXT`]`, material)` with
//! `material = identity (32) || purpose (1) || key_tag (u32 LE) || digit (u32 LE) || seed (64)`.
//! `identity` is the profile identity, `purpose` a [`CoinPurpose`] tag,
//! `key_tag` zero for the relinearization key and the Galois element for a
//! Galois key (zero elsewhere), and `digit` the key-switching digit (zero
//! elsewhere). Each sampled object reads its own stream from its first byte.
//!
//! # Samplers
//!
//! - **Uniform ternary** (secret key, encryption mask): one byte `b` per
//!   candidate; `b = 255` is rejected, otherwise the coefficient is
//!   `(b mod 3) - 1`. Each of -1, 0, 1 has probability exactly 1/3.
//! - **Centered binomial** with parameter `eta <= 24` (every error): six bytes
//!   per coefficient, read as a little-endian 48-bit integer `x`; the
//!   coefficient is `popcount(x mod 2^eta) - popcount((x >> eta) mod 2^eta)`.
//!   Its support is exactly `[-eta, eta]` and its variance `eta / 2`. With the
//!   pinned [`ERROR_ETA`]` = 21` the standard deviation is `sqrt(10.5)`, about
//!   3.24, the default error of Microsoft SEAL.
//! - **Uniform residue** (public masks): eight bytes per candidate, read as a
//!   little-endian integer and truncated to the bit length of the prime; a
//!   candidate not below the prime is rejected. A polynomial over several
//!   primes is sampled limb by limb, coefficient by coefficient, from one
//!   stream.
//!
//! The byte-to-coefficient maps are branch-free. Rejections depend on the
//! rejected candidates only, which are discarded and independent of the
//! accepted ones.
//!
//! # Where the secrets live
//!
//! The seed of an operation regenerates everything the operation samples: a
//! key-generation seed and the public profile identity give the secret key,
//! and an encryption seed gives the mask and the errors, hence the plaintext.
//! The seed, the BLAKE3 state that absorbs it, the extendable-output state,
//! the buffered stream bytes and the bytes of the word being assembled
//! therefore live in one heap block (`CoinState`) with one owner (`Coins`).
//! The operating system writes the seed directly into that block. Dropping
//! the owner overwrites the whole block, padding included, before it is
//! released: on success, on an error return and on unwind.
//! `tests/bgv_clearing.rs` observes every such block as the allocator
//! receives it.
//!
//! What this owner cannot cover: the stack frames of BLAKE3's compression
//! function, the value `finalize_xof` returns before it is stored in the
//! block, and machine words in registers while a coefficient is computed.
//! Those are transient copies the compiler and the hash implementation
//! create; no test observes them.
use super::BgvError;
use std::mem::ManuallyDrop;
use zeroize::{Zeroize as _, Zeroizing};

/// Bytes of operating-system entropy behind one operation.
pub const COIN_SEED_BYTES: usize = 64;
/// Centered binomial parameter of the pinned candidates.
pub const ERROR_ETA: u32 = 21;
/// Largest magnitude of an error coefficient under [`ERROR_ETA`].
pub const ERROR_BOUND: u64 = 21;
/// Largest centered binomial parameter the six-byte sampler supports.
pub const MAX_ERROR_ETA: u32 = 24;
/// BLAKE3 `derive_key` context of every coin stream.
pub const COIN_STREAM_CONTEXT: &str = "iroha_fhe bgv v1 coin stream";

/// What a coin stream is sampled for; the tag enters the stream derivation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CoinPurpose {
    /// The ternary secret key.
    SecretKey,
    /// The uniform polynomial `a` of the public key.
    PublicKeyMask,
    /// The error of the public key.
    PublicKeyError,
    /// The ternary mask `u` of an encryption.
    EncryptionMask,
    /// The error added to `c0`.
    EncryptionError0,
    /// The error added to `c1`.
    EncryptionError1,
    /// The uniform polynomial of one switching-key digit.
    SwitchingKeyMask,
    /// The error of one switching-key digit.
    SwitchingKeyError,
}

impl CoinPurpose {
    /// The tag byte in the stream derivation.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::SecretKey => 1,
            Self::PublicKeyMask => 2,
            Self::PublicKeyError => 3,
            Self::EncryptionMask => 4,
            Self::EncryptionError0 => 5,
            Self::EncryptionError1 => 6,
            Self::SwitchingKeyMask => 7,
            Self::SwitchingKeyError => 8,
        }
    }
}

/// A source of operation seeds.
pub(super) trait EntropySource {
    /// Fill `seed` with fresh entropy or fail.
    fn fill(&mut self, seed: &mut [u8; COIN_SEED_BYTES]) -> Result<(), BgvError>;
}

/// The operating-system generator.
pub(super) struct OsEntropy;

impl EntropySource for OsEntropy {
    fn fill(&mut self, seed: &mut [u8; COIN_SEED_BYTES]) -> Result<(), BgvError> {
        getrandom::fill(seed).map_err(|_| BgvError::EntropyUnavailable)
    }
}

/// Bytes buffered from the stream at a time.
const STREAM_BUFFER_BYTES: usize = 1024;

/// Every secret behind the coins of one operation, in one heap block.
///
/// The block holds plain data only: byte arrays, a counter and two BLAKE3
/// states. Nothing in it owns memory or runs a destructor, which the constant
/// assertion below pins, so overwriting it with zero bytes clears it
/// completely.
struct CoinState {
    /// The operation seed, written by the entropy source.
    seed: [u8; COIN_SEED_BYTES],
    /// Scratch that absorbs the stream material; cleared once the stream is open.
    ///
    /// The hasher keeps its chaining values in an inline array type that has a
    /// destructor although it owns no memory. `ManuallyDrop` keeps that
    /// destructor from ever running on the cleared block.
    hasher: ManuallyDrop<blake3::Hasher>,
    /// Extendable output of the open stream.
    reader: blake3::OutputReader,
    /// Stream bytes read ahead of the samplers.
    buffer: [u8; STREAM_BUFFER_BYTES],
    /// The bytes of the word a sampler is assembling.
    word: [u8; 8],
    /// Index of the next unread byte of `buffer`.
    position: usize,
}

/// Size of the heap block behind [`Coins`]; the clearing test watches blocks of this size.
pub(super) const COIN_STATE_BYTES: usize = size_of::<CoinState>();

// `zeroize_flat_type` requires a type without destructors.
const _: () = assert!(!std::mem::needs_drop::<CoinState>());

// The clearing test tells this block from every polynomial buffer by its size: it holds more
// than the seed and the stream buffer, and it is not a multiple of a polynomial limb.
const _: () = assert!(
    COIN_STATE_BYTES > COIN_SEED_BYTES + STREAM_BUFFER_BYTES
        && !COIN_STATE_BYTES.is_multiple_of(1024)
);

impl CoinState {
    /// Overwrite the whole block with zero bytes, padding included.
    #[allow(
        unsafe_code,
        reason = "whole-block clearing of plain data, padding included, needs a raw write"
    )]
    fn wipe(&mut self) {
        // SAFETY: `self` is a valid, exclusively borrowed `CoinState`. The type holds byte
        // arrays, a `usize` and two BLAKE3 states, which are plain data: no reference and no
        // owned allocation, and no destructor runs on it (asserted above). The all-zero bit
        // pattern is a value of each field: zeroed arrays and counters, an empty inline
        // array of chaining values, and the first variant of the BLAKE3 platform tag, which
        // carries no data.
        unsafe { zeroize::zeroize_flat_type(std::ptr::from_mut(self)) }
    }
}

/// The coins of one operation: the seed and the stream state, cleared on drop.
pub(super) struct Coins {
    state: Box<CoinState>,
}

impl Drop for Coins {
    fn drop(&mut self) {
        self.state.wipe();
    }
}

impl Coins {
    /// Draw the seed of one operation and refuse a failed or stuck source.
    ///
    /// The source writes into the clearing block, which is released cleared
    /// when the draw is refused.
    pub(super) fn draw(entropy: &mut dyn EntropySource) -> Result<Self, BgvError> {
        // Built from public constants; the first secret byte is written in place below.
        let mut coins = Self {
            state: Box::new(CoinState {
                seed: [0_u8; COIN_SEED_BYTES],
                hasher: ManuallyDrop::new(blake3::Hasher::new()),
                reader: blake3::Hasher::new().finalize_xof(),
                buffer: [0_u8; STREAM_BUFFER_BYTES],
                word: [0_u8; 8],
                position: STREAM_BUFFER_BYTES,
            }),
        };
        entropy.fill(&mut coins.state.seed)?;
        let first = coins.state.seed[0];
        // Not secret-dependent control flow that matters: a stuck source has no entropy.
        if coins.state.seed.iter().all(|&byte| byte == first) {
            return Err(BgvError::EntropyUnavailable);
        }
        Ok(coins)
    }

    /// Open the stream of one sampled object.
    pub(super) fn stream(
        &mut self,
        identity: &[u8; 32],
        purpose: CoinPurpose,
        key_tag: u32,
        digit: u32,
    ) -> CoinStream<'_> {
        let state = &mut *self.state;
        state.hasher = ManuallyDrop::new(blake3::Hasher::new_derive_key(COIN_STREAM_CONTEXT));
        state.hasher.update(identity);
        state.hasher.update(&[purpose.tag()]);
        state.hasher.update(&key_tag.to_le_bytes());
        state.hasher.update(&digit.to_le_bytes());
        state.hasher.update(&state.seed);
        state.reader = state.hasher.finalize_xof();
        // The absorbed seed leaves the scratch as soon as the stream is open.
        state.hasher.zeroize();
        state.position = STREAM_BUFFER_BYTES;
        CoinStream { state }
    }

    /// The seed, for the tests of this module.
    #[cfg(test)]
    pub(super) const fn seed(&self) -> &[u8; COIN_SEED_BYTES] {
        &self.state.seed
    }
}

/// One domain-separated stream of coins, reading through the state of its [`Coins`].
pub(super) struct CoinStream<'coins> {
    state: &'coins mut CoinState,
}

impl CoinStream<'_> {
    /// The next `COUNT` bytes of the stream as a little-endian integer; `COUNT <= 8`.
    fn next_le<const COUNT: usize>(&mut self) -> u64 {
        let state = &mut *self.state;
        state.word = [0_u8; 8];
        for slot in state.word.iter_mut().take(COUNT) {
            if state.position == STREAM_BUFFER_BYTES {
                state.reader.fill(&mut state.buffer);
                state.position = 0;
            }
            *slot = state.buffer[state.position];
            state.position += 1;
        }
        u64::from_le_bytes(state.word)
    }

    /// Fill `output` with uniform ternary coefficients in `{-1, 0, 1}`.
    pub(super) fn ternary(mut self, output: &mut [i64]) {
        for coefficient in output {
            let mut byte = Zeroizing::new(self.next_le::<1>());
            while *byte == 255 {
                *byte = self.next_le::<1>();
            }
            *coefficient = (*byte % 3).cast_signed() - 1;
        }
    }

    /// Fill `output` with centered binomial coefficients in `[-eta, eta]`; `eta <= 24`.
    pub(super) fn centered_binomial(mut self, eta: u32, output: &mut [i64]) {
        let eta = eta.min(MAX_ERROR_ETA);
        let mask = (1_u64 << eta) - 1;
        for coefficient in output {
            let bits = Zeroizing::new(self.next_le::<6>());
            let positive = i64::from((*bits & mask).count_ones());
            let negative = i64::from(((*bits >> eta) & mask).count_ones());
            *coefficient = positive - negative;
        }
    }

    /// Fill `output` with uniform residues: `moduli.len()` limbs of `degree` words, limb-major.
    pub(super) fn uniform(mut self, moduli: &[u64], degree: usize, output: &mut [u64]) {
        for (limb, &modulus) in output.chunks_exact_mut(degree.max(1)).zip(moduli) {
            let mask = u64::MAX >> modulus.leading_zeros().min(63);
            for residue in limb {
                let mut candidate = self.next_le::<8>() & mask;
                while candidate >= modulus {
                    candidate = self.next_le::<8>() & mask;
                }
                *residue = candidate;
            }
        }
    }
}

/// Canonical residue of a small signed coefficient with `|value| < modulus`, branch-free.
pub(super) fn small_residue(value: i64, modulus: u64) -> u64 {
    let bits = value.cast_unsigned();
    let negative_mask = 0_u64.wrapping_sub(bits >> 63);
    bits.wrapping_add(modulus & negative_mask)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// A seed with distinct bytes.
    pub fn seed(tag: u8) -> [u8; COIN_SEED_BYTES] {
        std::array::from_fn(|index| {
            tag.wrapping_add(u8::try_from(index).unwrap_or(0))
                .wrapping_mul(31)
        })
    }

    /// A source that hands out scripted results.
    pub struct ScriptedEntropy {
        pub results: Vec<Option<[u8; COIN_SEED_BYTES]>>,
        pub calls: usize,
    }

    impl EntropySource for ScriptedEntropy {
        fn fill(&mut self, seed: &mut [u8; COIN_SEED_BYTES]) -> Result<(), BgvError> {
            let result = self.results.get(self.calls).copied().flatten();
            self.calls += 1;
            *seed = result.ok_or(BgvError::EntropyUnavailable)?;
            Ok(())
        }
    }

    const IDENTITY: [u8; 32] = [7; 32];

    /// The coins of the scripted seed `seed(tag)`.
    fn coins(tag: u8) -> Coins {
        Coins::draw(&mut ScriptedEntropy {
            results: vec![Some(seed(tag))],
            calls: 0,
        })
        .expect("coins")
    }

    #[test]
    fn purpose_tags_are_distinct_and_pinned() {
        let tags = [
            CoinPurpose::SecretKey,
            CoinPurpose::PublicKeyMask,
            CoinPurpose::PublicKeyError,
            CoinPurpose::EncryptionMask,
            CoinPurpose::EncryptionError0,
            CoinPurpose::EncryptionError1,
            CoinPurpose::SwitchingKeyMask,
            CoinPurpose::SwitchingKeyError,
        ]
        .map(CoinPurpose::tag);
        assert_eq!(tags, [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn operating_system_entropy_fills_a_seed() {
        let first = Coins::draw(&mut OsEntropy).expect("entropy");
        let second = Coins::draw(&mut OsEntropy).expect("entropy");
        assert_ne!(first.seed(), second.seed());
        assert!(first.seed().iter().any(|&byte| byte != first.seed()[0]));
    }

    #[test]
    fn a_failed_or_stuck_source_fails_closed() {
        let mut failing = ScriptedEntropy {
            results: vec![None],
            calls: 0,
        };
        assert_eq!(
            Coins::draw(&mut failing).err(),
            Some(BgvError::EntropyUnavailable)
        );
        for stuck in [0_u8, 0xFF, 0x5A] {
            let mut source = ScriptedEntropy {
                results: vec![Some([stuck; COIN_SEED_BYTES])],
                calls: 0,
            };
            assert_eq!(
                Coins::draw(&mut source).err(),
                Some(BgvError::EntropyUnavailable)
            );
        }
        let mut good = ScriptedEntropy {
            results: vec![Some(seed(3))],
            calls: 0,
        };
        assert_eq!(Coins::draw(&mut good).expect("seed").seed(), &seed(3));
        assert_eq!(good.calls, 1);
    }

    #[test]
    fn the_stream_is_the_blake3_derive_key_output() {
        let mut material = Vec::new();
        material.extend_from_slice(&IDENTITY);
        material.push(7);
        material.extend_from_slice(&0x0102_0304_u32.to_le_bytes());
        material.extend_from_slice(&9_u32.to_le_bytes());
        material.extend_from_slice(&seed(1));
        let mut hasher = blake3::Hasher::new_derive_key(COIN_STREAM_CONTEXT);
        hasher.update(&material);
        let mut expected = [0_u8; 2 * STREAM_BUFFER_BYTES + 5];
        hasher.finalize_xof().fill(&mut expected);
        let mut coins = coins(1);
        let mut stream = coins.stream(&IDENTITY, CoinPurpose::SwitchingKeyMask, 0x0102_0304, 9);
        // Reads of every width walk the same byte sequence across buffer refills.
        let mut offset = 0;
        while offset + 8 <= expected.len() {
            let width = 1 + offset % 8;
            let mut word = [0_u8; 8];
            word[..width].copy_from_slice(&expected[offset..offset + width]);
            let value = match width {
                1 => stream.next_le::<1>(),
                2 => stream.next_le::<2>(),
                3 => stream.next_le::<3>(),
                4 => stream.next_le::<4>(),
                5 => stream.next_le::<5>(),
                6 => stream.next_le::<6>(),
                7 => stream.next_le::<7>(),
                _ => stream.next_le::<8>(),
            };
            assert_eq!(value, u64::from_le_bytes(word), "offset {offset}");
            offset += width;
        }
    }

    /// The first eight bytes of one stream of the scripted seed `seed(tag)`.
    fn first_word(
        tag: u8,
        identity: &[u8; 32],
        purpose: CoinPurpose,
        key_tag: u32,
        digit: u32,
    ) -> u64 {
        coins(tag)
            .stream(identity, purpose, key_tag, digit)
            .next_le::<8>()
    }

    #[test]
    fn every_derivation_field_separates_the_stream() {
        let mask = CoinPurpose::SwitchingKeyMask;
        let base = first_word(1, &IDENTITY, mask, 3, 1);
        assert_eq!(base, first_word(1, &IDENTITY, mask, 3, 1));
        assert_ne!(
            base,
            first_word(1, &IDENTITY, CoinPurpose::SwitchingKeyError, 3, 1)
        );
        assert_ne!(base, first_word(1, &IDENTITY, mask, 5, 1));
        assert_ne!(base, first_word(1, &IDENTITY, mask, 3, 2));
        assert_ne!(base, first_word(2, &IDENTITY, mask, 3, 1));
        assert_ne!(base, first_word(1, &[8; 32], mask, 3, 1));
    }

    #[test]
    fn each_stream_of_one_seed_starts_at_its_first_byte() {
        // A stream opened after another one was read part of the way owes nothing to it.
        let mut shared = coins(1);
        let mut first = shared.stream(&IDENTITY, CoinPurpose::EncryptionMask, 0, 0);
        let leading = first.next_le::<8>();
        let _ = first.next_le::<3>();
        let second = shared
            .stream(&IDENTITY, CoinPurpose::EncryptionError0, 0, 0)
            .next_le::<8>();
        assert_eq!(
            second,
            first_word(1, &IDENTITY, CoinPurpose::EncryptionError0, 0, 0)
        );
        assert_ne!(second, leading);
        // Reopening the first stream replays it from the start.
        assert_eq!(
            shared
                .stream(&IDENTITY, CoinPurpose::EncryptionMask, 0, 0)
                .next_le::<8>(),
            leading
        );
    }

    #[test]
    fn the_hasher_scratch_is_cleared_once_a_stream_is_open() {
        // A cleared hasher finalizes to one fixed digest; a hasher that still held the
        // absorbed stream material would finalize to the first bytes of the stream.
        let mut cleared = blake3::Hasher::new();
        cleared.zeroize();
        let mut coins = coins(1);
        let _ = coins.stream(&IDENTITY, CoinPurpose::SecretKey, 0, 0);
        assert_eq!(coins.state.hasher.finalize(), cleared.finalize());
        let mut absorbed = blake3::Hasher::new_derive_key(COIN_STREAM_CONTEXT);
        absorbed.update(&IDENTITY);
        absorbed.update(&[CoinPurpose::SecretKey.tag()]);
        absorbed.update(&[0; 8]);
        absorbed.update(&seed(1));
        assert_ne!(absorbed.finalize(), cleared.finalize());
        // The seed stays in the block for the next stream of the same operation.
        assert_eq!(coins.seed(), &seed(1));
    }

    #[test]
    fn wiping_clears_the_seed_the_buffer_and_the_word() {
        let mut coins = coins(1);
        let mut output = [0_i64; 16];
        coins
            .stream(&IDENTITY, CoinPurpose::SecretKey, 0, 0)
            .ternary(&mut output);
        // The block held the seed, stream bytes and the last sampled byte.
        assert_eq!(coins.state.seed, seed(1));
        assert!(coins.state.buffer.iter().any(|&byte| byte != 0));
        assert!(coins.state.position > 0 && coins.state.position < STREAM_BUFFER_BYTES);
        coins.state.wipe();
        assert_eq!(coins.state.seed, [0_u8; COIN_SEED_BYTES]);
        assert_eq!(coins.state.buffer, [0_u8; STREAM_BUFFER_BYTES]);
        assert_eq!(coins.state.word, [0_u8; 8]);
        assert_eq!(coins.state.position, 0);
        assert_eq!(COIN_STATE_BYTES, size_of::<CoinState>());
    }

    /// The bytes a sampler reads, re-derived directly from BLAKE3.
    fn raw(purpose: CoinPurpose, len: usize) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new_derive_key(COIN_STREAM_CONTEXT);
        hasher.update(&IDENTITY);
        hasher.update(&[purpose.tag()]);
        hasher.update(&[0; 8]);
        hasher.update(&seed(1));
        let mut bytes = vec![0_u8; len];
        hasher.finalize_xof().fill(&mut bytes);
        bytes
    }

    #[test]
    fn ternary_sampler_follows_its_specification() {
        let mut output = vec![9_i64; 5000];
        coins(1)
            .stream(&IDENTITY, CoinPurpose::SecretKey, 0, 0)
            .ternary(&mut output);
        let bytes = raw(CoinPurpose::SecretKey, 6000);
        let expected: Vec<i64> = bytes
            .iter()
            .filter(|&&byte| byte != 255)
            .map(|&byte| i64::from(byte % 3) - 1)
            .take(output.len())
            .collect();
        assert_eq!(output, expected);
        // 5000 draws: each value near 1667; a rejected byte occurred (255 has rate 1/256).
        for value in [-1_i64, 0, 1] {
            let count = output
                .iter()
                .filter(|&&coefficient| coefficient == value)
                .count();
            assert!((1500..1850).contains(&count), "{value}: {count}");
        }
        assert!(bytes[..5020].contains(&255));
    }

    #[test]
    fn centered_binomial_sampler_follows_its_specification() {
        for eta in [1_u32, 21, 24] {
            let mut output = vec![99_i64; 4000];
            coins(1)
                .stream(&IDENTITY, CoinPurpose::PublicKeyError, 0, 0)
                .centered_binomial(eta, &mut output);
            let bytes = raw(CoinPurpose::PublicKeyError, 6 * output.len());
            let mut sum = 0_i64;
            let mut squares = 0_i64;
            for (index, &coefficient) in output.iter().enumerate() {
                let mut word = [0_u8; 8];
                word[..6].copy_from_slice(&bytes[6 * index..6 * index + 6]);
                let bits = u64::from_le_bytes(word);
                let mask = (1_u64 << eta) - 1;
                let expected = i64::from((bits & mask).count_ones())
                    - i64::from(((bits >> eta) & mask).count_ones());
                assert_eq!(coefficient, expected);
                assert!(coefficient.unsigned_abs() <= u64::from(eta));
                sum += coefficient;
                squares += coefficient * coefficient;
            }
            // Mean zero and variance eta / 2, within loose statistical margins.
            let count = i64::try_from(output.len()).expect("count");
            assert!(
                sum.abs() * 10 < count * i64::from(eta),
                "eta {eta} sum {sum}"
            );
            let variance_times_two = 2 * squares / count;
            assert!(
                (i64::from(eta) - 2..=i64::from(eta) + 2).contains(&variance_times_two),
                "eta {eta} variance*2 {variance_times_two}"
            );
        }
        // A parameter above the supported maximum is clamped, never out of range.
        let mut clamped = vec![0_i64; 64];
        coins(1)
            .stream(&IDENTITY, CoinPurpose::PublicKeyError, 0, 0)
            .centered_binomial(40, &mut clamped);
        let mut expected = vec![0_i64; 64];
        coins(1)
            .stream(&IDENTITY, CoinPurpose::PublicKeyError, 0, 0)
            .centered_binomial(24, &mut expected);
        assert_eq!(clamped, expected);
    }

    #[test]
    fn uniform_sampler_follows_its_specification() {
        // A 50-bit prime, a 60-bit prime and a prime just above a power of two (high rejection).
        let moduli = [562_950_180_667_393_u64, 576_460_752_472_375_297, 257];
        let degree = 600;
        let mut output = vec![0_u64; moduli.len() * degree];
        coins(1)
            .stream(&IDENTITY, CoinPurpose::PublicKeyMask, 0, 0)
            .uniform(&moduli, degree, &mut output);
        let bytes = raw(CoinPurpose::PublicKeyMask, 8 * 4 * output.len());
        let mut words = bytes
            .chunks_exact(8)
            .map(|chunk| u64::from_le_bytes(chunk.try_into().expect("eight bytes")));
        let mut rejected = 0_usize;
        for (limb, &modulus) in moduli.iter().enumerate() {
            let mask = (1_u64 << (64 - modulus.leading_zeros())) - 1;
            for coefficient in 0..degree {
                let expected = loop {
                    let candidate = words.next().expect("word") & mask;
                    if candidate < modulus {
                        break candidate;
                    }
                    rejected += 1;
                };
                assert_eq!(output[limb * degree + coefficient], expected);
            }
        }
        // 257 needs nine bits, so about half of its candidates are rejected.
        assert!(rejected > 400, "rejected {rejected}");
        // The largest supported modulus keeps a 62-bit mask.
        let mut top = [0_u64; 4];
        coins(1)
            .stream(&IDENTITY, CoinPurpose::PublicKeyMask, 0, 0)
            .uniform(&[(1 << 62) - 57], 4, &mut top);
        assert!(top.iter().all(|&residue| residue < (1 << 62) - 57));
    }

    #[test]
    fn small_residues_are_canonical() {
        for modulus in [257_u64, 562_950_180_667_393] {
            assert_eq!(small_residue(0, modulus), 0);
            assert_eq!(small_residue(1, modulus), 1);
            assert_eq!(small_residue(-1, modulus), modulus - 1);
            assert_eq!(small_residue(21, modulus), 21);
            assert_eq!(small_residue(-21, modulus), modulus - 21);
            assert_eq!(small_residue(-128, modulus), modulus - 128);
        }
    }
}
