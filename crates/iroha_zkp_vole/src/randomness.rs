//! The prover's randomness: the root seed `r` and the public `iv_pre`.
//!
//! A proof consumes one [`Tape`]: `r` (`lambda / 8` bytes, secret) seeds the vector
//! commitment and the mask generator of `VOLECommit`, and `iv_pre` (16 bytes,
//! published in the proof) gives `iv = H_4(iv_pre || mu)`. Two ways to obtain one:
//!
//! * [`Tape::derive`], reference mode: `(r, iv_pre) = H_3(secret || mu || rho)` as
//!   in FAEST.Sign (specification Figure 8.2). `secret` is the one-way-function key
//!   `k` alone (`lambda / 8` bytes, not `x || k`), `mu` is `2 * lambda / 8` bytes and
//!   `rho` is absorbed exactly as supplied, with no padding and no truncation. The
//!   specification defines `rho` as `lambda` bits and deterministic signing as
//!   `rho = 0^lambda`, that is `lambda / 8` zero bytes; the official test vectors
//!   pass 16 bytes at every security level, which is why the length is the
//!   caller's. An empty `rho` is accepted but is not a mode of the specification.
//!   The output is `lambda / 8 + 16` bytes: `r` first, `iv_pre` last.
//! * [`Tape::explicit`]: the caller supplies `r` and `iv_pre`, for example from a
//!   fresh proving tape. Nothing is hashed. The caller is responsible for the
//!   freshness, uniformity and independence of the bytes; reusing a tape for two
//!   different statements or witnesses reveals the witness.
//!
//! * [`Tape::extended`]: as [`Tape::explicit`] at `lambda = 256`, with the public
//!   32-byte salt of the extended construction ([`crate::variant`]). It is the
//!   only way to give a tape a salt, and a tape with a salt is accepted by an
//!   extended proof context only. The salt must be fresh and uniform per proof
//!   like the rest of the tape. The extended construction never uses `H_3`.
//!
//! `r` is erased when the tape is dropped. `iv_pre` and the salt are public once
//! the proof is out; the tape's copies are erased with it all the same.

use core::fmt;

use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    hash::{HashError, Hasher, Namespace, Oracle},
    params::{IV_BYTES, SecurityLevel},
    variant::{Binding, Construction, SALT_BYTES, VariantError},
};

/// Largest `lambda / 8`.
const MAX_LAMBDA_BYTES: usize = 32;

/// Which input had the wrong length in a [`RandomnessError::InvalidLength`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Input {
    /// The root seed `r`, `lambda / 8` bytes.
    Root,
    /// `mu`, `2 * lambda / 8` bytes.
    Mu,
}

/// Errors of the randomness derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RandomnessError {
    /// An input does not have the length the security level fixes for it.
    #[error("{input:?} must be {expected} bytes long, got {actual}")]
    InvalidLength {
        /// The input concerned.
        input: Input,
        /// Required length in bytes.
        expected: usize,
        /// Length supplied.
        actual: usize,
    },
    /// The secret input of `H_3` is empty.
    #[error("the secret input of H_3 is empty")]
    EmptySecret,
    /// A hash function rejected a call.
    #[error(transparent)]
    Hash(#[from] HashError),
    /// A salted tape was requested at a level where the extended construction is
    /// not defined.
    #[error(transparent)]
    Variant(#[from] VariantError),
}

/// The randomness of one proof: the secret root seed `r`, the public `iv_pre`
/// and, for the extended construction, the public salt.
pub struct Tape {
    level: SecurityLevel,
    /// `r` in the first `lambda / 8` bytes.
    root: [u8; MAX_LAMBDA_BYTES],
    iv_pre: [u8; IV_BYTES],
    /// The salt; meaningful only when `construction` is extended.
    salt: [u8; SALT_BYTES],
    construction: Construction,
}

impl fmt::Debug for Tape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tape")
            .field("level", &self.level)
            .field("construction", &self.construction)
            .field("iv_pre", &self.iv_pre)
            .finish_non_exhaustive()
    }
}

impl Zeroize for Tape {
    fn zeroize(&mut self) {
        self.root.zeroize();
        self.iv_pre.zeroize();
        self.salt.zeroize();
    }
}

impl Drop for Tape {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Tape {}

impl Tape {
    /// The tape with the caller's `root` (`lambda / 8` bytes) and `iv_pre`.
    ///
    /// # Errors
    /// Returns [`RandomnessError::InvalidLength`] unless `root` is `lambda / 8`
    /// bytes long.
    pub fn explicit(
        level: SecurityLevel,
        root: &[u8],
        iv_pre: &[u8; IV_BYTES],
    ) -> Result<Self, RandomnessError> {
        let lb = level.bytes();
        if root.len() != lb {
            return Err(RandomnessError::InvalidLength {
                input: Input::Root,
                expected: lb,
                actual: root.len(),
            });
        }
        let mut tape = Self {
            level,
            root: [0; MAX_LAMBDA_BYTES],
            iv_pre: *iv_pre,
            salt: [0; SALT_BYTES],
            construction: Construction::Faest,
        };
        tape.root[..lb].copy_from_slice(root);
        Ok(tape)
    }

    /// The tape of an extended proof: the caller's `root` (`lambda / 8` bytes),
    /// `iv_pre` and public `salt`. Nothing is hashed.
    ///
    /// # Errors
    /// Returns [`RandomnessError::Variant`] unless `level` is `lambda = 256` and
    /// [`RandomnessError::InvalidLength`] unless `root` is 32 bytes long.
    pub fn extended(
        level: SecurityLevel,
        root: &[u8],
        iv_pre: &[u8; IV_BYTES],
        salt: &[u8; SALT_BYTES],
    ) -> Result<Self, RandomnessError> {
        Construction::Extended.check_level(level)?;
        let mut tape = Self::explicit(level, root, iv_pre)?;
        tape.salt = *salt;
        tape.construction = Construction::Extended;
        Ok(tape)
    }

    /// Reference mode: `(r, iv_pre) = H_3(secret || mu || rho)` inside `namespace`.
    ///
    /// # Errors
    /// Returns [`RandomnessError::EmptySecret`] if `secret` is empty and
    /// [`RandomnessError::InvalidLength`] unless `mu` is `2 * lambda / 8` bytes
    /// long.
    pub fn derive(
        namespace: Namespace<'_>,
        level: SecurityLevel,
        secret: &[u8],
        mu: &[u8],
        rho: &[u8],
    ) -> Result<Self, RandomnessError> {
        let lb = level.bytes();
        if secret.is_empty() {
            return Err(RandomnessError::EmptySecret);
        }
        if mu.len() != 2 * lb {
            return Err(RandomnessError::InvalidLength {
                input: Input::Mu,
                expected: 2 * lb,
                actual: mu.len(),
            });
        }
        let mut hasher = Hasher::new_in(namespace, level, Oracle::H3);
        hasher.update(secret);
        hasher.update(mu);
        hasher.update(rho);
        let mut output = hasher.finalize_xof();
        let mut tape = Self {
            level,
            root: [0; MAX_LAMBDA_BYTES],
            iv_pre: [0; IV_BYTES],
            salt: [0; SALT_BYTES],
            construction: Construction::Faest,
        };
        output.squeeze(&mut tape.root[..lb]);
        output.squeeze(&mut tape.iv_pre);
        Ok(tape)
    }

    /// The security level the tape was made for.
    pub fn level(&self) -> SecurityLevel {
        self.level
    }

    /// The root seed `r`, `lambda / 8` bytes. **Secret.**
    pub fn root(&self) -> &[u8] {
        &self.root[..self.level.bytes()]
    }

    /// `iv_pre`. Public: it is part of the proof.
    pub fn iv_pre(&self) -> &[u8; IV_BYTES] {
        &self.iv_pre
    }

    /// The construction the tape was made for: [`Construction::Extended`] for
    /// [`Tape::extended`], [`Construction::Faest`] otherwise.
    pub const fn construction(&self) -> Construction {
        self.construction
    }

    /// The construction together with the salt it binds, as the layers below
    /// take it. Public: the salt is part of the proof.
    pub const fn binding(&self) -> Binding<'_> {
        match self.construction {
            Construction::Faest => Binding::Faest,
            Construction::Extended => Binding::Extended { salt: &self.salt },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SHAKE of `level` computed by the independent `sha3` crate.
    fn shake(level: SecurityLevel, parts: &[&[u8]], len: usize) -> Vec<u8> {
        use sha3::digest::{ExtendableOutput, Update, XofReader};
        let mut out = vec![0u8; len];
        if level == SecurityLevel::L128 {
            let mut sponge = sha3::Shake128::default();
            for part in parts {
                sponge.update(part);
            }
            sponge.finalize_xof().read(&mut out);
        } else {
            let mut sponge = sha3::Shake256::default();
            for part in parts {
                sponge.update(part);
            }
            sponge.finalize_xof().read(&mut out);
        }
        out
    }

    #[test]
    fn derivation_is_h3_of_secret_mu_and_rho_as_supplied() {
        let prefixes: [&[u8]; 3] = [b"", &[0x19; 77], b"other"];
        for level in SecurityLevel::ALL {
            let lb = level.bytes();
            let secret = vec![0xa1u8; lb];
            let mu = vec![0xb2u8; 2 * lb];
            let mut roots = Vec::new();
            for prefix in prefixes {
                let namespace = Namespace::new(prefix).expect("bounded");
                // 16 bytes (the official vectors), lambda bits (the specification),
                // and nothing.
                for rho in [&[0xc3u8; 16][..], &vec![0u8; lb], &[]] {
                    let tape = Tape::derive(namespace, level, &secret, &mu, rho).expect("valid");
                    let expected = shake(level, &[prefix, &secret, &mu, rho, &[0x03]], lb + 16);
                    assert_eq!(tape.root(), &expected[..lb]);
                    assert_eq!(tape.iv_pre()[..], expected[lb..]);
                    assert_eq!(tape.level(), level);
                    assert!(tape.root[lb..].iter().all(|&byte| byte == 0));
                }
                let tape = Tape::derive(namespace, level, &secret, &mu, &[]).expect("valid");
                roots.push(tape.root().to_vec());
            }
            roots.sort();
            roots.dedup();
            assert_eq!(roots.len(), prefixes.len());
            // Padding `rho` with zeros is a different input.
            let short =
                Tape::derive(Namespace::REFERENCE, level, &secret, &mu, &[0; 16]).expect("valid");
            let long =
                Tape::derive(Namespace::REFERENCE, level, &secret, &mu, &[0; 17]).expect("valid");
            assert_ne!(short.root(), long.root());
        }
    }

    #[test]
    fn malformed_inputs_are_typed_errors() {
        let reference = Namespace::REFERENCE;
        assert_eq!(
            Tape::derive(reference, SecurityLevel::L128, &[], &[0; 32], &[]).err(),
            Some(RandomnessError::EmptySecret)
        );
        assert_eq!(
            Tape::derive(reference, SecurityLevel::L192, &[1; 24], &[0; 32], &[]).err(),
            Some(RandomnessError::InvalidLength {
                input: Input::Mu,
                expected: 48,
                actual: 32
            })
        );
        for level in SecurityLevel::ALL {
            let lb = level.bytes();
            for actual in [0, lb - 1, lb + 1] {
                assert_eq!(
                    Tape::explicit(level, &vec![0u8; actual], &[0; 16]).err(),
                    Some(RandomnessError::InvalidLength {
                        input: Input::Root,
                        expected: lb,
                        actual
                    })
                );
            }
        }
    }

    #[test]
    fn explicit_tapes_carry_the_bytes_and_are_erased() {
        fn erases_on_drop<T: ZeroizeOnDrop>() {}
        erases_on_drop::<Tape>();
        for level in SecurityLevel::ALL {
            let lb = level.bytes();
            let root: Vec<u8> = (1..=lb)
                .map(|byte| u8::try_from(byte).expect("small"))
                .collect();
            let mut tape = Tape::explicit(level, &root, &[0x7e; 16]).expect("valid");
            assert_eq!(tape.root(), root);
            assert_eq!(tape.iv_pre(), &[0x7e; 16]);
            let shown = format!("{tape:?}");
            assert!(shown.contains("iv_pre") && !shown.contains("root"));
            tape.zeroize();
            assert_eq!(tape.root, [0; MAX_LAMBDA_BYTES]);
            assert_eq!(tape.iv_pre, [0; IV_BYTES]);
        }
    }

    #[test]
    fn only_extended_tapes_carry_a_salt() {
        let level = SecurityLevel::L256;
        let mu = [0xb2u8; 64];
        let plain = Tape::explicit(level, &[1; 32], &[2; 16]).expect("valid");
        assert_eq!(plain.construction(), Construction::Faest);
        assert_eq!(plain.binding(), Binding::Faest);
        let derived = Tape::derive(Namespace::REFERENCE, level, &[1; 32], &mu, &[]).expect("valid");
        assert_eq!(derived.binding(), Binding::Faest);

        let salt: [u8; SALT_BYTES] = core::array::from_fn(|at| u8::try_from(at).expect("small"));
        let mut tape = Tape::extended(level, &[1; 32], &[2; 16], &salt).expect("valid");
        assert_eq!(tape.construction(), Construction::Extended);
        assert_eq!(tape.binding(), Binding::Extended { salt: &salt });
        assert_eq!(tape.root(), [1; 32]);
        assert_eq!(tape.iv_pre(), &[2; 16]);
        assert_eq!(tape.level(), level);
        let shown = format!("{tape:?}");
        assert!(shown.contains("Extended") && !shown.contains("root"));
        // The whole buffer is erased, the public salt included.
        tape.zeroize();
        assert_eq!(tape.root, [0; MAX_LAMBDA_BYTES]);
        assert_eq!(tape.iv_pre, [0; IV_BYTES]);
        assert_eq!(tape.salt, [0; SALT_BYTES]);
    }

    #[test]
    fn extended_tapes_exist_at_lambda_256_only() {
        for level in [SecurityLevel::L128, SecurityLevel::L192] {
            assert_eq!(
                Tape::extended(level, &vec![0u8; level.bytes()], &[0; 16], &[0; 32]).err(),
                Some(RandomnessError::Variant(VariantError::UnsupportedLevel {
                    lambda: level.bits()
                }))
            );
        }
        assert_eq!(
            Tape::extended(SecurityLevel::L256, &[0; 31], &[0; 16], &[0; 32]).err(),
            Some(RandomnessError::InvalidLength {
                input: Input::Root,
                expected: 32,
                actual: 31
            })
        );
    }
}
