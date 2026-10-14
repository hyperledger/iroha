//! AES-CTR based pseudorandom generator (FAEST v3.0 section 3.3, Figure 3.6).
//!
//! `PRG(sd, iv, twk; m)` encrypts counter blocks with AES-`lambda` keyed by the seed
//! `sd`. The 128-bit `iv` is four little-endian 32-bit words. The tweak is added to
//! word 3 and the block counter `0, 1, 2, ...` to word 0, each modulo `2^32` and
//! without carry into a neighbouring word. The ciphertext blocks are concatenated
//! and truncated to `m` bits; when `m` is not a multiple of 8 the last byte keeps
//! its low-order bits and the bits above are zero.
//!
//! # Backends
//!
//! [`Prg::new`] uses the portable, constant-time fixsliced AES unless the crate's
//! `accel` feature is enabled, in which case it uses the autodetecting hardware AES
//! of the `aes` crate. [`Prg::new_portable`] always uses the portable AES. Both
//! produce identical bytes. Key schedules are erased on drop.

use core::fmt;

use aes::{
    Block,
    cipher::{BlockEncrypt, KeyInit},
};
use thiserror::Error;
use zeroize::Zeroize;

use crate::params::{IV_BYTES, SecurityLevel};

/// AES block size in bytes.
const BLOCK_BYTES: usize = 16;
/// Number of counter blocks encrypted per batch.
const BATCH_BLOCKS: usize = 8;
/// Largest output in bytes: `2^32` blocks.
const MAX_OUTPUT_BYTES: u64 = (1 << 32) * 16;

/// Errors of the pseudorandom generator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PrgError {
    /// The seed is not 16, 24 or 32 bytes long.
    #[error("the seed must be 16, 24 or 32 bytes long, got {actual}")]
    InvalidSeedLength {
        /// Supplied length in bytes.
        actual: usize,
    },
    /// The output buffer does not hold exactly the requested number of bits.
    #[error("{bits} output bits need a buffer of {expected} bytes, got {actual}")]
    InvalidOutputLength {
        /// Requested output length in bits.
        bits: usize,
        /// Required buffer length in bytes.
        expected: usize,
        /// Supplied buffer length in bytes.
        actual: usize,
    },
    /// More than `2^32` blocks were requested from one call.
    #[error("one call yields at most 2^32 blocks, {bytes} bytes requested")]
    OutputTooLong {
        /// Requested output length in bytes.
        bytes: usize,
    },
}

/// Batch encryption with a fixed key, object-safe over the AES variants.
trait Encryptor: Send + Sync {
    fn encrypt(&self, blocks: &mut [Block]);
}

macro_rules! impl_encryptor {
    ($($cipher:ty),+ $(,)?) => {
        $(impl Encryptor for $cipher {
            fn encrypt(&self, blocks: &mut [Block]) {
                self.encrypt_blocks(blocks);
            }
        })+
    };
}

impl_encryptor!(aes::soft::Aes128, aes::soft::Aes192, aes::soft::Aes256);

/// The hardware-autodetecting AES of the `aes` crate, compiled only with `accel`.
///
/// On targets without a hardware backend `aes::Aes128` is the portable type itself,
/// so the autodetecting types are wrapped to keep the trait implementations apart.
#[cfg(feature = "accel")]
mod accelerated {
    use super::{Block, BlockEncrypt, Encryptor};

    macro_rules! wrap {
        ($($name:ident),+) => {
            $(
                /// AES with run-time hardware detection.
                pub(super) struct $name(pub(super) aes::$name);

                impl Encryptor for $name {
                    fn encrypt(&self, blocks: &mut [Block]) {
                        self.0.encrypt_blocks(blocks);
                    }
                }
            )+
        };
    }

    wrap!(Aes128, Aes192, Aes256);
}

/// Which AES implementation a [`Prg`] runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Backend {
    /// Portable constant-time fixsliced AES; always available.
    Portable,
    /// Hardware AES with run-time detection; only with the `accel` feature.
    Accelerated,
}

impl Backend {
    /// The backend [`Prg::new`] selects in this build.
    pub const DEFAULT: Self = if cfg!(feature = "accel") {
        Self::Accelerated
    } else {
        Self::Portable
    };
}

/// The FAEST pseudorandom generator keyed by one seed.
pub struct Prg {
    cipher: Box<dyn Encryptor>,
    level: SecurityLevel,
    backend: Backend,
}

impl fmt::Debug for Prg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Prg")
            .field("level", &self.level)
            .field("backend", &self.backend)
            .finish_non_exhaustive()
    }
}

fn level_of(seed: &[u8]) -> Result<SecurityLevel, PrgError> {
    SecurityLevel::from_bytes(seed.len()).ok_or(PrgError::InvalidSeedLength { actual: seed.len() })
}

fn invalid_seed(seed: &[u8]) -> PrgError {
    PrgError::InvalidSeedLength { actual: seed.len() }
}

impl Prg {
    /// Key the generator with `seed`, whose length selects AES-128, AES-192 or
    /// AES-256, on the default backend of this build ([`Backend::DEFAULT`]).
    ///
    /// # Errors
    /// Returns [`PrgError::InvalidSeedLength`] unless `seed` is 16, 24 or 32 bytes.
    pub fn new(seed: &[u8]) -> Result<Self, PrgError> {
        #[cfg(feature = "accel")]
        {
            let level = level_of(seed)?;
            let cipher: Box<dyn Encryptor> = match level {
                SecurityLevel::L128 => Box::new(accelerated::Aes128(
                    aes::Aes128::new_from_slice(seed).map_err(|_| invalid_seed(seed))?,
                )),
                SecurityLevel::L192 => Box::new(accelerated::Aes192(
                    aes::Aes192::new_from_slice(seed).map_err(|_| invalid_seed(seed))?,
                )),
                SecurityLevel::L256 => Box::new(accelerated::Aes256(
                    aes::Aes256::new_from_slice(seed).map_err(|_| invalid_seed(seed))?,
                )),
            };
            Ok(Self {
                cipher,
                level,
                backend: Backend::Accelerated,
            })
        }
        #[cfg(not(feature = "accel"))]
        {
            Self::new_portable(seed)
        }
    }

    /// Key the generator with `seed` on the portable constant-time AES, whatever
    /// features are enabled.
    ///
    /// # Errors
    /// Returns [`PrgError::InvalidSeedLength`] unless `seed` is 16, 24 or 32 bytes.
    pub fn new_portable(seed: &[u8]) -> Result<Self, PrgError> {
        let level = level_of(seed)?;
        let cipher: Box<dyn Encryptor> = match level {
            SecurityLevel::L128 => {
                Box::new(aes::soft::Aes128::new_from_slice(seed).map_err(|_| invalid_seed(seed))?)
            }
            SecurityLevel::L192 => {
                Box::new(aes::soft::Aes192::new_from_slice(seed).map_err(|_| invalid_seed(seed))?)
            }
            SecurityLevel::L256 => {
                Box::new(aes::soft::Aes256::new_from_slice(seed).map_err(|_| invalid_seed(seed))?)
            }
        };
        Ok(Self {
            cipher,
            level,
            backend: Backend::Portable,
        })
    }

    /// The security level selected by the seed length.
    pub fn level(&self) -> SecurityLevel {
        self.level
    }

    /// The AES implementation in use.
    pub fn backend(&self) -> Backend {
        self.backend
    }

    /// Fill `out` with the first `8 * out.len()` output bits of
    /// `PRG(sd, iv, tweak; .)`.
    ///
    /// # Errors
    /// Returns [`PrgError::OutputTooLong`] if `out` is longer than `2^32` blocks.
    pub fn fill(&self, iv: &[u8; IV_BYTES], tweak: u32, out: &mut [u8]) -> Result<(), PrgError> {
        if !u64::try_from(out.len()).is_ok_and(|bytes| bytes <= MAX_OUTPUT_BYTES) {
            return Err(PrgError::OutputTooLong { bytes: out.len() });
        }
        let [i0, i1, i2, i3, middle @ .., i12, i13, i14, i15] = *iv;
        let low = u32::from_le_bytes([i0, i1, i2, i3]);
        let high = u32::from_le_bytes([i12, i13, i14, i15]).wrapping_add(tweak);

        let mut blocks = [Block::default(); BATCH_BLOCKS];
        let mut counter = 0u32;
        for chunk in out.chunks_mut(BATCH_BLOCKS * BLOCK_BYTES) {
            let used = chunk.len().div_ceil(BLOCK_BYTES);
            for block in &mut blocks[..used] {
                block[..4].copy_from_slice(&low.wrapping_add(counter).to_le_bytes());
                block[4..12].copy_from_slice(&middle);
                block[12..].copy_from_slice(&high.to_le_bytes());
                // At most 2^32 blocks are produced, so the wrap never repeats a block.
                counter = counter.wrapping_add(1);
            }
            self.cipher.encrypt(&mut blocks[..used]);
            for (piece, block) in chunk.chunks_mut(BLOCK_BYTES).zip(&blocks) {
                piece.copy_from_slice(&block[..piece.len()]);
            }
        }
        for block in &mut blocks {
            block.as_mut_slice().zeroize();
        }
        Ok(())
    }

    /// Write `PRG(sd, iv, tweak; bits)` to `out`: `ceil(bits / 8)` bytes, with the
    /// bits of the last byte at or above `bits mod 8` cleared when `bits` is not a
    /// multiple of 8.
    ///
    /// # Errors
    /// Returns [`PrgError::InvalidOutputLength`] unless `out` is exactly
    /// `ceil(bits / 8)` bytes long and [`PrgError::OutputTooLong`] if that exceeds
    /// `2^32` blocks.
    pub fn fill_bits(
        &self,
        iv: &[u8; IV_BYTES],
        tweak: u32,
        bits: usize,
        out: &mut [u8],
    ) -> Result<(), PrgError> {
        let expected = bits.div_ceil(8);
        if out.len() != expected {
            return Err(PrgError::InvalidOutputLength {
                bits,
                expected,
                actual: out.len(),
            });
        }
        self.fill(iv, tweak, out)?;
        if let Some(last) = out.last_mut() {
            *last &= 0xff >> ((8 - bits % 8) % 8);
        }
        Ok(())
    }
}

/// One-shot `PRG(seed, iv, tweak; bits)` on the default backend.
///
/// # Errors
/// As [`Prg::new`] and [`Prg::fill_bits`].
pub fn prg(
    seed: &[u8],
    iv: &[u8; IV_BYTES],
    tweak: u32,
    bits: usize,
    out: &mut [u8],
) -> Result<(), PrgError> {
    Prg::new(seed)?.fill_bits(iv, tweak, bits, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const IV: [u8; 16] = [
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe,
        0xff,
    ];

    fn seed(level: SecurityLevel) -> Vec<u8> {
        (0u8..32).take(level.bytes()).collect()
    }

    fn output(prg: &Prg, iv: &[u8; 16], tweak: u32, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        prg.fill(iv, tweak, &mut out).expect("short output");
        out
    }

    #[test]
    fn level_of_maps_seed_lengths() {
        assert_eq!(level_of(&[0; 16]), Ok(SecurityLevel::L128));
        assert_eq!(level_of(&[0; 24]), Ok(SecurityLevel::L192));
        assert_eq!(level_of(&[0; 32]), Ok(SecurityLevel::L256));
        assert_eq!(
            level_of(&[0; 17]),
            Err(PrgError::InvalidSeedLength { actual: 17 })
        );
        assert_eq!(
            invalid_seed(&[0; 3]),
            PrgError::InvalidSeedLength { actual: 3 }
        );
    }

    #[test]
    fn construction_rejects_bad_seed_lengths() {
        for len in [0, 15, 17, 31, 33, 64] {
            let seed = vec![0u8; len];
            assert_eq!(
                Prg::new(&seed).map(|_| ()),
                Err(PrgError::InvalidSeedLength { actual: len })
            );
            assert_eq!(
                Prg::new_portable(&seed).map(|_| ()),
                Err(PrgError::InvalidSeedLength { actual: len })
            );
        }
    }

    #[test]
    fn construction_reports_level_and_backend() {
        for level in SecurityLevel::ALL {
            let default = Prg::new(&seed(level)).expect("valid seed");
            assert_eq!(default.level(), level);
            assert_eq!(default.backend(), Backend::DEFAULT);
            let portable = Prg::new_portable(&seed(level)).expect("valid seed");
            assert_eq!(portable.level(), level);
            assert_eq!(portable.backend(), Backend::Portable);
            assert!(format!("{default:?}").starts_with("Prg { level: "));
        }
        assert_eq!(
            Backend::DEFAULT == Backend::Accelerated,
            cfg!(feature = "accel")
        );
    }

    /// FIPS 197 Appendix C: with a zero counter word and zero tweak the first block
    /// is the plain AES encryption of the IV.
    #[test]
    fn first_block_is_the_aes_encryption_of_the_iv() {
        let plaintext: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let expected: [(SecurityLevel, [u8; 16]); 3] = [
            (
                SecurityLevel::L128,
                [
                    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70,
                    0xb4, 0xc5, 0x5a,
                ],
            ),
            (
                SecurityLevel::L192,
                [
                    0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec,
                    0x0d, 0x71, 0x91,
                ],
            ),
            (
                SecurityLevel::L256,
                [
                    0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b,
                    0x49, 0x60, 0x89,
                ],
            ),
        ];
        for (level, ciphertext) in expected {
            for prg in [
                Prg::new(&seed(level)).expect("valid seed"),
                Prg::new_portable(&seed(level)).expect("valid seed"),
            ] {
                assert_eq!(output(&prg, &plaintext, 0, 16), ciphertext, "{level:?}");
            }
        }
    }

    #[test]
    fn counter_and_tweak_are_added_to_separate_words_modulo_2_to_32() {
        for level in SecurityLevel::ALL {
            let prg = Prg::new(&seed(level)).expect("valid seed");
            let stream = output(&prg, &IV, 0, 64);
            // Block i is the first block of the IV whose word 0 is advanced by i,
            // wrapping inside the word: f3f2f1f0 + 1, then + 2, ...
            for (i, block) in stream.chunks(16).enumerate() {
                let mut iv = IV;
                let word = u32::from_le_bytes([iv[0], iv[1], iv[2], iv[3]])
                    .wrapping_add(u32::try_from(i).expect("small"));
                iv[..4].copy_from_slice(&word.to_le_bytes());
                assert_eq!(output(&prg, &iv, 0, 16), block);
            }
            // Word 0 wraps without carrying into word 1.
            let mut wrapping = IV;
            wrapping[..4].copy_from_slice(&[0xff; 4]);
            let mut wrapped = IV;
            wrapped[..4].copy_from_slice(&[0x00; 4]);
            assert_eq!(
                output(&prg, &wrapping, 0, 32)[16..],
                output(&prg, &wrapped, 0, 16)[..]
            );
            // The tweak is added to word 3, wrapping inside the word.
            let tweak = 0x0102_0304;
            let mut tweaked = IV;
            let word = u32::from_le_bytes([IV[12], IV[13], IV[14], IV[15]]).wrapping_add(tweak);
            tweaked[12..].copy_from_slice(&word.to_le_bytes());
            assert_eq!(output(&prg, &IV, tweak, 48), output(&prg, &tweaked, 0, 48));
            assert_ne!(output(&prg, &IV, tweak, 16), output(&prg, &IV, 0, 16));
        }
    }

    #[test]
    fn output_is_prefix_consistent_across_lengths() {
        for level in SecurityLevel::ALL {
            let prg = Prg::new(&seed(level)).expect("valid seed");
            let long = output(&prg, &IV, 7, 16 * 19 + 5);
            for len in [0, 1, 15, 16, 17, 127, 128, 129, 200, long.len()] {
                assert_eq!(output(&prg, &IV, 7, len), long[..len], "{level:?} {len}");
            }
        }
    }

    #[test]
    fn bit_lengths_truncate_the_last_byte_to_its_low_bits() {
        let prg = Prg::new(&seed(SecurityLevel::L128)).expect("valid seed");
        let full = output(&prg, &IV, 3, 134);
        for bits in [1usize, 7, 8, 9, 127, 128, 129, 750, 1070] {
            let mut out = vec![0xffu8; bits.div_ceil(8)];
            prg.fill_bits(&IV, 3, bits, &mut out).expect("exact buffer");
            let (last, head) = out.split_last().expect("non-empty");
            assert_eq!(head, &full[..head.len()]);
            let mask = 0xffu8 >> ((8 - bits % 8) % 8);
            assert_eq!(*last, full[head.len()] & mask, "{bits}");
        }
        let mut empty = [];
        assert_eq!(prg.fill_bits(&IV, 3, 0, &mut empty), Ok(()));
    }

    #[test]
    fn wrong_output_buffers_are_rejected() {
        let keyed = Prg::new(&seed(SecurityLevel::L192)).expect("valid seed");
        let mut out = [0u8; 4];
        assert_eq!(
            keyed.fill_bits(&IV, 0, 33, &mut out),
            Err(PrgError::InvalidOutputLength {
                bits: 33,
                expected: 5,
                actual: 4
            })
        );
        assert_eq!(
            keyed.fill_bits(&IV, 0, 24, &mut out),
            Err(PrgError::InvalidOutputLength {
                bits: 24,
                expected: 3,
                actual: 4
            })
        );
        assert_eq!(
            prg(&[0; 5], &IV, 0, 32, &mut out),
            Err(PrgError::InvalidSeedLength { actual: 5 })
        );
    }

    #[test]
    fn one_shot_matches_the_keyed_generator() {
        for level in SecurityLevel::ALL {
            let keyed = Prg::new(&seed(level)).expect("valid seed");
            let mut expected = [0u8; 94];
            keyed
                .fill_bits(&IV, 99, 750, &mut expected)
                .expect("exact buffer");
            let mut out = [0u8; 94];
            prg(&seed(level), &IV, 99, 750, &mut out).expect("valid call");
            assert_eq!(out, expected);
        }
    }

    #[test]
    fn default_and_portable_backends_agree() {
        for level in SecurityLevel::ALL {
            let default = Prg::new(&seed(level)).expect("valid seed");
            let portable = Prg::new_portable(&seed(level)).expect("valid seed");
            for (tweak, len) in [
                (0u32, 1usize),
                (1, 16),
                (u32::MAX, 129),
                (0x8000_0000, 1000),
            ] {
                assert_eq!(
                    output(&default, &IV, tweak, len),
                    output(&portable, &IV, tweak, len),
                    "{level:?} {tweak} {len}"
                );
            }
        }
    }
}
