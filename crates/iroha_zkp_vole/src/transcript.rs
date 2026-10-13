//! The Fiat-Shamir transcript of FAEST v3.0 (section 8, Figures 8.2 and 8.3): the
//! derivation of `iv` and the chain of the three challenges.
//!
//! Every function takes the [`Namespace`] of the proof and evaluates its oracle
//! inside it; with [`Namespace::REFERENCE`] the inputs are exactly those of the
//! specification. With `B = lambda / 8` and all lengths in bytes:
//!
//! | value | oracle | message, in order | output |
//! |---|---|---|---|
//! | `mu` | `H_2^0` | the statement and message bytes | `2B` |
//! | `iv` | `H_4` | `iv_pre` (16), `mu` (`2B`) | 16 |
//! | `chall_1` | `H_2^1` | `mu` (`2B`), `com` (`2B`), `c_1 .. c_{tau-1}` (`ell / 8` each), `c_mult` (`n_mask` rows), `iv_pre` (16) | `8B + 8` |
//! | `chall_2` | `H_2^2` | `chall_1`, `u~` (`4B`), `V~` (`4B`), `d` (`ell / 8`) | `3B + 8` |
//! | `chall_3` | `H_2^3` | `chall_2`, `a~_0 .. a~_{d_zk-1}` (`d_zk * B`), the counter (4, little-endian) | `B` |
//!
//! `mu` is an input of everything below it. Reference mode computes it as
//! `H_2^0(pk || msg)`; another relation defines its own statement encoding, and
//! may compute `mu` with [`message_digest`] or in any other way that yields `2B`
//! bytes. The verifier uses `D = Q~ + Delta * u~` in the place of `V~`.
//!
//! [`Challenge3`] absorbs everything before the counter once, so the grinding loop
//! of the prover costs one sponge clone and one finalisation per counter.
//!
//! # Extended construction
//!
//! [`challenge_1_as`] takes a [`Binding`]. With [`Binding::Extended`] the 32-byte
//! salt of the proof is appended to the message of `chall_1`, after `iv_pre`:
//! `mu`, `com`, `c_1 .. c_{tau-1}`, `c_mult`, `iv_pre` (16), `salt` (32). The
//! domain byte and the output length are the same, and no other row of the table
//! changes: the salt does not enter `mu`, `iv`, `chall_2` or `chall_3` directly.
//!
//! Everything in the transcript is public.

use thiserror::Error;

use crate::{
    hash::{HashError, Hasher, Namespace, Oracle},
    params::{IV_BYTES, ProofParams, SecurityLevel, VoleParams},
    variant::{Binding, VariantError},
    vole::{corrections_bytes, mult_corrections_bytes},
};

/// Which transcript input had the wrong length in a
/// [`TranscriptError::InvalidLength`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Input {
    /// `mu`, `2 * lambda / 8` bytes.
    Mu,
    /// The vector commitment `com`, `2 * lambda / 8` bytes.
    Commitment,
    /// The corrections `c_1 .. c_{tau-1}`.
    Corrections,
    /// The gate corrections `c_mult`.
    MultCorrections,
    /// `chall_1`, `8 * lambda / 8 + 8` bytes.
    Challenge1,
    /// `u~`, four field elements.
    UTilde,
    /// `V~` (or the verifier's `D`), four field elements.
    VTilde,
    /// The masked witness `d`, `ell / 8` bytes.
    MaskedWitness,
    /// `chall_2`, `3 * lambda / 8 + 8` bytes.
    Challenge2,
    /// `a~_0 .. a~_{d_zk-1}`, `d_zk` field elements.
    Coefficients,
    /// The output buffer of `chall_3`, `lambda / 8` bytes.
    Challenge3,
}

/// Errors of the transcript functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TranscriptError {
    /// An input does not have the length the row fixes for it.
    #[error("{input:?} must be {expected} bytes long, got {actual}")]
    InvalidLength {
        /// The input concerned.
        input: Input,
        /// Required length in bytes.
        expected: usize,
        /// Length supplied.
        actual: usize,
    },
    /// A hash function rejected a call.
    #[error(transparent)]
    Hash(#[from] HashError),
    /// The extended construction was requested on a row where it is not defined.
    #[error(transparent)]
    Variant(#[from] VariantError),
}

fn check_length(input: Input, expected: usize, actual: usize) -> Result<(), TranscriptError> {
    if expected == actual {
        Ok(())
    } else {
        Err(TranscriptError::InvalidLength {
            input,
            expected,
            actual,
        })
    }
}

/// `mu = H_2^0(parts[0] || parts[1] || ...)` inside `namespace`: `2 * lambda / 8`
/// bytes. Reference mode passes the public key and the message.
///
/// # Errors
/// Only if the hash layer rejects the call, which no input causes.
pub fn message_digest(
    namespace: Namespace<'_>,
    level: SecurityLevel,
    parts: &[&[u8]],
) -> Result<Vec<u8>, TranscriptError> {
    let mut hasher = Hasher::new_in(namespace, level, Oracle::H2Mu);
    for part in parts {
        hasher.update(part);
    }
    let mut mu = vec![0u8; hasher.output_bytes()];
    hasher.finalize(&mut mu)?;
    Ok(mu)
}

/// `iv = H_4(iv_pre || mu)` inside `namespace`.
///
/// # Errors
/// Returns [`TranscriptError::InvalidLength`] unless `mu` is `2 * lambda / 8`
/// bytes long.
pub fn derive_iv(
    namespace: Namespace<'_>,
    level: SecurityLevel,
    iv_pre: &[u8; IV_BYTES],
    mu: &[u8],
) -> Result<[u8; IV_BYTES], TranscriptError> {
    check_length(Input::Mu, 2 * level.bytes(), mu.len())?;
    let mut hasher = Hasher::new_in(namespace, level, Oracle::H4);
    hasher.update(iv_pre);
    hasher.update(mu);
    let mut iv = [0u8; IV_BYTES];
    hasher.finalize(&mut iv)?;
    Ok(iv)
}

/// `chall_1 = H_2^1(mu || com || c_1 || ... || c_{tau-1} || c_mult || iv_pre)`
/// inside `namespace`, in the FAEST construction: `8 * lambda / 8 + 8` bytes.
///
/// # Errors
/// Returns [`TranscriptError::InvalidLength`] naming the first input whose length
/// is not the one the row fixes.
pub fn challenge_1(
    namespace: Namespace<'_>,
    params: &ProofParams,
    mu: &[u8],
    commitment: &[u8],
    corrections: &[u8],
    mult_corrections: &[u8],
    iv_pre: &[u8; IV_BYTES],
) -> Result<Vec<u8>, TranscriptError> {
    challenge_1_as(
        namespace,
        Binding::Faest,
        params,
        &Challenge1Input {
            mu,
            commitment,
            corrections,
            mult_corrections,
            iv_pre,
        },
    )
}

/// The message parts of `chall_1` that every construction absorbs.
#[derive(Debug, Clone, Copy)]
pub struct Challenge1Input<'a> {
    /// `mu`, `2 * lambda / 8` bytes.
    pub mu: &'a [u8],
    /// The vector commitment `com`, `2 * lambda / 8` bytes.
    pub commitment: &'a [u8],
    /// `c_1 || ... || c_{tau-1}`.
    pub corrections: &'a [u8],
    /// `c_mult`.
    pub mult_corrections: &'a [u8],
    /// `iv_pre`.
    pub iv_pre: &'a [u8; IV_BYTES],
}

/// `chall_1` inside `namespace` under `binding`.
///
/// With [`Binding::Faest`] this is [`challenge_1`]. With [`Binding::Extended`]
/// the message is `mu || com || c_1 || ... || c_{tau-1} || c_mult || iv_pre ||
/// salt`.
///
/// # Errors
/// Returns [`TranscriptError::Variant`] where the construction is not defined and
/// [`TranscriptError::InvalidLength`] naming the first input whose length is not
/// the one the row fixes.
pub fn challenge_1_as(
    namespace: Namespace<'_>,
    binding: Binding<'_>,
    params: &ProofParams,
    input: &Challenge1Input<'_>,
) -> Result<Vec<u8>, TranscriptError> {
    let Challenge1Input {
        mu,
        commitment,
        corrections,
        mult_corrections,
        iv_pre,
    } = *input;
    binding.construction().check_row(params.vole())?;
    let vole = params.vole();
    let level = vole.lambda();
    let lb = level.bytes();
    check_length(Input::Mu, 2 * lb, mu.len())?;
    check_length(Input::Commitment, 2 * lb, commitment.len())?;
    check_length(
        Input::Corrections,
        corrections_bytes(params),
        corrections.len(),
    )?;
    check_length(
        Input::MultCorrections,
        mult_corrections_bytes(vole),
        mult_corrections.len(),
    )?;
    let mut hasher = Hasher::new_in(namespace, level, Oracle::H2Chall1);
    hasher.update(mu);
    hasher.update(commitment);
    hasher.update(corrections);
    hasher.update(mult_corrections);
    hasher.update(iv_pre);
    if let Some(salt) = binding.salt() {
        hasher.update(salt);
    }
    let mut challenge = vec![0u8; vole.chall1_bytes()];
    hasher.finalize(&mut challenge)?;
    Ok(challenge)
}

/// `chall_2 = H_2^2(chall_1 || u~ || V~ || d)` inside `namespace`:
/// `3 * lambda / 8 + 8` bytes. The verifier passes `D = Q~ + Delta * u~` as
/// `v_tilde`.
///
/// # Errors
/// Returns [`TranscriptError::InvalidLength`] naming the first input whose length
/// is not the one the row fixes.
pub fn challenge_2(
    namespace: Namespace<'_>,
    params: &ProofParams,
    challenge_1: &[u8],
    u_tilde: &[u8],
    v_tilde: &[u8],
    masked_witness: &[u8],
) -> Result<Vec<u8>, TranscriptError> {
    let vole = params.vole();
    let level = vole.lambda();
    let lb = level.bytes();
    check_length(Input::Challenge1, vole.chall1_bytes(), challenge_1.len())?;
    check_length(Input::UTilde, 4 * lb, u_tilde.len())?;
    check_length(Input::VTilde, 4 * lb, v_tilde.len())?;
    check_length(
        Input::MaskedWitness,
        params.witness_bytes(),
        masked_witness.len(),
    )?;
    let mut hasher = Hasher::new_in(namespace, level, Oracle::H2Chall2);
    hasher.update(challenge_1);
    hasher.update(u_tilde);
    hasher.update(v_tilde);
    hasher.update(masked_witness);
    let mut challenge = vec![0u8; vole.chall2_bytes()];
    hasher.finalize(&mut challenge)?;
    Ok(challenge)
}

/// `chall_3 = H_2^3(chall_2 || a~_0 || ... || a~_{d_zk-1} || counter)` with
/// everything before the counter already absorbed.
#[derive(Debug, Clone)]
pub struct Challenge3 {
    hasher: Hasher,
}

impl Challenge3 {
    /// Absorb the namespace prefix, `chall_2` and the `d_zk` coefficients
    /// `a~_0 .. a~_{d_zk-1}` (`lambda / 8` bytes each).
    ///
    /// # Errors
    /// Returns [`TranscriptError::InvalidLength`] naming the first input whose
    /// length is not the one the row fixes.
    pub fn new(
        namespace: Namespace<'_>,
        params: &VoleParams,
        challenge_2: &[u8],
        coefficients: &[u8],
    ) -> Result<Self, TranscriptError> {
        let level = params.lambda();
        check_length(Input::Challenge2, params.chall2_bytes(), challenge_2.len())?;
        check_length(
            Input::Coefficients,
            params.d_zk() * level.bytes(),
            coefficients.len(),
        )?;
        let mut hasher = Hasher::new_in(namespace, level, Oracle::H2Chall3);
        hasher.update(challenge_2);
        hasher.update(coefficients);
        Ok(Self { hasher })
    }

    /// The challenge for `counter`, absorbed as four little-endian bytes, written
    /// to `out` (`lambda / 8` bytes). The counter is hashed exactly once.
    ///
    /// # Errors
    /// Returns [`TranscriptError::InvalidLength`] unless `out` is `lambda / 8`
    /// bytes long.
    pub fn at(&self, counter: u32, out: &mut [u8]) -> Result<(), TranscriptError> {
        check_length(Input::Challenge3, self.hasher.output_bytes(), out.len())?;
        let mut hasher = self.hasher.clone();
        hasher.update_u32_le(counter);
        hasher.finalize(out)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{FAEST_128F, FAEST_192F, FAEST_256F, FAEST_256S, FaestParams};

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

    fn pattern(len: usize, salt: u8) -> Vec<u8> {
        (0..len)
            .map(|at| u8::try_from(at % 251).expect("below 251").wrapping_mul(37) ^ salt)
            .collect()
    }

    const SETS: [FaestParams; 4] = [FAEST_128F, FAEST_192F, FAEST_256F, FAEST_256S];
    const PREFIXES: [&[u8]; 3] = [b"", &[0xc4; 77], b"another role"];

    #[test]
    fn mu_and_iv_have_the_layouts_of_the_table() {
        for set in SETS {
            let level = set.vole().lambda();
            let lb = level.bytes();
            let iv_pre: [u8; 16] = pattern(16, 1).try_into().expect("16 bytes");
            let (mut mus, mut ivs) = (Vec::new(), Vec::new());
            for prefix in PREFIXES {
                let namespace = Namespace::new(prefix).expect("bounded");
                let mu = message_digest(namespace, level, &[b"public key", b"", b"message"])
                    .expect("valid call");
                assert_eq!(
                    mu,
                    shake(level, &[prefix, b"public keymessage", &[0x08]], 2 * lb)
                );
                // The same `mu` in every namespace isolates the prefix of `H_4`.
                let fixed = pattern(2 * lb, 2);
                let iv = derive_iv(namespace, level, &iv_pre, &fixed).expect("valid call");
                assert_eq!(
                    iv[..],
                    shake(level, &[prefix, &iv_pre, &fixed, &[0x04]], 16)[..]
                );
                mus.push(mu);
                ivs.push(iv.to_vec());
            }
            for seen in [&mut mus, &mut ivs] {
                seen.sort();
                seen.dedup();
                assert_eq!(seen.len(), PREFIXES.len());
            }
            assert_eq!(
                derive_iv(
                    Namespace::REFERENCE,
                    level,
                    &iv_pre,
                    &pattern(2 * lb + 1, 2)
                ),
                Err(TranscriptError::InvalidLength {
                    input: Input::Mu,
                    expected: 2 * lb,
                    actual: 2 * lb + 1
                })
            );
        }
    }

    #[test]
    fn the_challenge_chain_has_the_layouts_of_the_table() {
        for set in SETS {
            let params = ProofParams::new(*set.vole(), 1000, 1500).expect("valid row");
            let vole = params.vole();
            let level = vole.lambda();
            let lb = level.bytes();
            let mu = pattern(2 * lb, 3);
            let com = pattern(2 * lb, 4);
            let corrections = pattern(corrections_bytes(&params), 5);
            let mult = pattern(mult_corrections_bytes(vole), 6);
            let iv_pre: [u8; 16] = pattern(16, 7).try_into().expect("16 bytes");
            let u_tilde = pattern(4 * lb, 8);
            let v_tilde = pattern(4 * lb, 9);
            let d = pattern(125, 10);
            let coefficients = pattern(7 * lb, 11);
            // Fixed predecessors isolate the prefix of each oracle.
            let fixed_1 = pattern(8 * lb + 8, 12);
            let fixed_2 = pattern(3 * lb + 8, 13);
            let mut seen: [Vec<Vec<u8>>; 3] = [Vec::new(), Vec::new(), Vec::new()];
            for prefix in PREFIXES {
                let namespace = Namespace::new(prefix).expect("bounded");
                let first =
                    challenge_1(namespace, &params, &mu, &com, &corrections, &mult, &iv_pre)
                        .expect("valid call");
                assert_eq!(
                    first,
                    shake(
                        level,
                        &[prefix, &mu, &com, &corrections, &mult, &iv_pre, &[0x09]],
                        8 * lb + 8
                    )
                );
                let second = challenge_2(namespace, &params, &fixed_1, &u_tilde, &v_tilde, &d)
                    .expect("valid call");
                assert_eq!(
                    second,
                    shake(
                        level,
                        &[prefix, &fixed_1, &u_tilde, &v_tilde, &d, &[0x0a]],
                        3 * lb + 8
                    )
                );
                let grinder =
                    Challenge3::new(namespace, vole, &fixed_2, &coefficients).expect("valid call");
                let mut third = vec![0u8; lb];
                for counter in [0u32, 1, 0x0102_0304, u32::MAX] {
                    grinder.at(counter, &mut third).expect("valid call");
                    assert_eq!(
                        third,
                        shake(
                            level,
                            &[
                                prefix,
                                &fixed_2,
                                &coefficients,
                                &counter.to_le_bytes(),
                                &[0x0b]
                            ],
                            lb
                        )
                    );
                }
                seen[0].push(first);
                seen[1].push(second);
                seen[2].push(third);
            }
            for outputs in &mut seen {
                outputs.sort();
                outputs.dedup();
                assert_eq!(outputs.len(), PREFIXES.len());
            }
        }
    }

    #[test]
    fn each_input_length_is_checked() {
        let reference = Namespace::REFERENCE;
        let params = ProofParams::new(*FAEST_128F.vole(), 256, 300).expect("valid row");
        let vole = params.vole();
        let (mu, com) = (vec![0u8; 32], vec![0u8; 32]);
        let corrections = vec![0u8; corrections_bytes(&params)];
        let mult = vec![0u8; mult_corrections_bytes(vole)];
        let iv_pre = [0u8; 16];
        let invalid = |input, expected, actual| {
            Err(TranscriptError::InvalidLength {
                input,
                expected,
                actual,
            })
        };
        assert_eq!(
            challenge_1(
                reference,
                &params,
                &mu[1..],
                &com,
                &corrections,
                &mult,
                &iv_pre
            ),
            invalid(Input::Mu, 32, 31)
        );
        assert_eq!(
            challenge_1(
                reference,
                &params,
                &mu,
                &com[1..],
                &corrections,
                &mult,
                &iv_pre
            ),
            invalid(Input::Commitment, 32, 31)
        );
        assert_eq!(
            challenge_1(
                reference,
                &params,
                &mu,
                &com,
                &corrections[1..],
                &mult,
                &iv_pre
            ),
            invalid(Input::Corrections, 16 * 32, 16 * 32 - 1)
        );
        assert_eq!(
            challenge_1(
                reference,
                &params,
                &mu,
                &com,
                &corrections,
                &mult[1..],
                &iv_pre
            ),
            invalid(Input::MultCorrections, 390, 389)
        );
        let (first, tilde, d) = (vec![0u8; 136], vec![0u8; 64], vec![0u8; 32]);
        assert_eq!(
            challenge_2(reference, &params, &first[1..], &tilde, &tilde, &d),
            invalid(Input::Challenge1, 136, 135)
        );
        assert_eq!(
            challenge_2(reference, &params, &first, &tilde[1..], &tilde, &d),
            invalid(Input::UTilde, 64, 63)
        );
        assert_eq!(
            challenge_2(reference, &params, &first, &tilde, &tilde[1..], &d),
            invalid(Input::VTilde, 64, 63)
        );
        assert_eq!(
            challenge_2(reference, &params, &first, &tilde, &tilde, &d[1..]),
            invalid(Input::MaskedWitness, 32, 31)
        );
        let (second, coefficients) = (vec![0u8; 56], vec![0u8; 7 * 16]);
        assert_eq!(
            Challenge3::new(reference, vole, &second[1..], &coefficients).err(),
            Some(TranscriptError::InvalidLength {
                input: Input::Challenge2,
                expected: 56,
                actual: 55
            })
        );
        assert_eq!(
            Challenge3::new(reference, vole, &second, &coefficients[1..]).err(),
            Some(TranscriptError::InvalidLength {
                input: Input::Coefficients,
                expected: 112,
                actual: 111
            })
        );
        let grinder = Challenge3::new(reference, vole, &second, &coefficients).expect("valid");
        assert_eq!(
            grinder.at(0, &mut [0u8; 15]),
            Err(TranscriptError::InvalidLength {
                input: Input::Challenge3,
                expected: 16,
                actual: 15
            })
        );
        assert_eq!(
            check_length(Input::Mu, 1, 1),
            Ok(()),
            "equal lengths are accepted"
        );
    }

    #[test]
    fn extended_challenge_1_appends_the_salt_after_iv_pre() {
        let iv_pre: [u8; 16] = pattern(16, 5).try_into().expect("16 bytes");
        let salt: [u8; 32] = pattern(32, 0xa9).try_into().expect("32 bytes");
        for set in [FAEST_256F, FAEST_256S] {
            let params = ProofParams::new(*set.vole(), 1000, 1500).expect("valid row");
            let vole = params.vole();
            let level = vole.lambda();
            let mu = pattern(64, 1);
            let com = pattern(64, 2);
            let corrections = pattern(corrections_bytes(&params), 3);
            let mult = pattern(mult_corrections_bytes(vole), 4);
            let input = Challenge1Input {
                mu: &mu,
                commitment: &com,
                corrections: &corrections,
                mult_corrections: &mult,
                iv_pre: &iv_pre,
            };
            for prefix in PREFIXES {
                let namespace = Namespace::new(prefix).expect("bounded");
                let extended = challenge_1_as(
                    namespace,
                    Binding::Extended { salt: &salt },
                    &params,
                    &input,
                )
                .expect("valid call");
                assert_eq!(
                    extended,
                    shake(
                        level,
                        &[
                            prefix,
                            &mu,
                            &com,
                            &corrections,
                            &mult,
                            &iv_pre,
                            &salt,
                            &[0x09]
                        ],
                        264
                    )
                );
                let faest =
                    challenge_1_as(namespace, Binding::Faest, &params, &input).expect("valid call");
                assert_eq!(
                    Ok(&faest),
                    challenge_1(namespace, &params, &mu, &com, &corrections, &mult, &iv_pre)
                        .as_ref()
                );
                assert_ne!(faest, extended);
                let mut other = salt;
                other[31] ^= 0x80;
                assert_ne!(
                    challenge_1_as(
                        namespace,
                        Binding::Extended { salt: &other },
                        &params,
                        &input
                    )
                    .expect("valid call"),
                    extended
                );
            }
        }
        let params = ProofParams::new(*FAEST_128F.vole(), 1000, 1500).expect("valid row");
        let input = Challenge1Input {
            mu: &[0; 32],
            commitment: &[0; 32],
            corrections: &vec![0u8; corrections_bytes(&params)],
            mult_corrections: &vec![0u8; mult_corrections_bytes(params.vole())],
            iv_pre: &iv_pre,
        };
        assert_eq!(
            challenge_1_as(
                Namespace::REFERENCE,
                Binding::Extended { salt: &salt },
                &params,
                &input
            ),
            Err(TranscriptError::Variant(VariantError::UnsupportedLevel {
                lambda: 128
            }))
        );
    }
}
