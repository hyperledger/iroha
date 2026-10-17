//! Plain FAEST v3.0 on the generic engine: the AES and Even-Mansour one-way
//! functions, their relation, key generation, signing and verification for the
//! twelve standard parameter sets, byte-compatible with the official reference
//! (`tests/fixtures/faest_v3_0_2/owf_tvs.txt` and `faest_tvs.txt`).
//!
//! This module exists so that every layer of the backend can be checked against
//! the official vectors. It is **experimental and unqualified**, like the rest of
//! the crate, and is not a product signature scheme.
//!
//! # Keys
//!
//! `sk = x || k` and `pk = x || y` with `y = OWF_k(x)`
//! ([`one_way_function`]): `x` is 16 bytes for FAEST and `lambda / 8` bytes for
//! FAEST-EM, `k` is `lambda / 8` bytes, and `y` is one or two AES blocks, or
//! `lambda / 8` bytes for FAEST-EM.
//!
//! **Key validity.** `FAEST.KeyGen` (specification Figure 8.1) resamples `k`
//! until its first two bits are not both one, and the relation contains the
//! constraint `k[0] * k[1] = 0`. [`SecretKey::generate`] applies the rule to the
//! caller's randomness, and [`SecretKey::from_bytes`] refuses an imported key
//! that violates it with [`FaestError::InvalidSecretKey`]: no signature of such a
//! key would verify.
//!
//! # Signing and verifying
//!
//! ```text
//! mu          = H_2^0(pk || msg)
//! (r, iv_pre) = H_3(k || mu || rho)
//! w           = ExtendWitness(k, x)
//! signature   = proof of the one-way-function relation for (pk, w) under mu
//!               with the tape (r, iv_pre)                      ([`crate::proof`])
//! ```
//!
//! `rho` is absorbed exactly as supplied. The specification defines it as
//! `lambda` uniformly random bits and deterministic signing as `rho = 0^lambda`
//! ([`SecretKey::sign_deterministic`]); the official vectors pass 16 bytes at
//! every security level, which is why no length is imposed here.
//!
//! [`verify`] is a total function of the public key, the message and the
//! signature bytes: every input is untrusted, nothing panics, and every error is
//! a rejection.
//!
//! # Secrets
//!
//! The secret key and the extended witness are erased on drop. The one-way
//! function and the witness are computed by the private cipher module, whose S-box is
//! arithmetic and whose control flow depends on the parameter set only. Whether
//! an imported key satisfies the key rule is public (it is the function's
//! result).

mod cipher;
mod relation;

use core::fmt;

use thiserror::Error;
use zeroize::Zeroizing;

pub use self::relation::OwfRelation;
use crate::{
    field::{Gf128, Gf192, Gf256},
    hash::Namespace,
    params::{FaestParams, OwfParams, SecurityLevel},
    proof::{self, ProofContext, ProofError},
    randomness::{RandomnessError, Tape},
    transcript::{self, TranscriptError},
};

/// Attempts [`SecretKey::generate`] makes to draw a key that satisfies the key
/// rule. A uniform source fails all of them with probability `4^-128`.
pub const KEY_GENERATION_ATTEMPTS: usize = 128;

/// Which input had the wrong length in a [`FaestError::InvalidLength`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Input {
    /// The one-way-function key `k`, `lambda / 8` bytes.
    Key,
    /// The one-way-function input `x`.
    Block,
    /// The secret key `x || k`.
    SecretKey,
    /// The public key `x || y`.
    PublicKey,
}

/// Errors of plain FAEST. From [`verify`], every error is a rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum FaestError {
    /// An input does not have the length the parameter set fixes for it.
    #[error("{input:?} must be {expected} bytes long, got {actual}")]
    InvalidLength {
        /// The input concerned.
        input: Input,
        /// Required length in bytes.
        expected: usize,
        /// Length supplied.
        actual: usize,
    },
    /// The first two bits of the key `k` are both one: not a key that
    /// `FAEST.KeyGen` can output.
    #[error("the secret key violates the key rule k[0] * k[1] = 0")]
    InvalidSecretKey,
    /// The randomness source gave no valid key in
    /// [`KEY_GENERATION_ATTEMPTS`] draws.
    #[error("the randomness source produced no valid key")]
    KeyGeneration,
    /// The proof layer failed, or rejected the signature.
    #[error(transparent)]
    Proof(#[from] ProofError),
    /// A transcript hash was misused.
    #[error(transparent)]
    Transcript(#[from] TranscriptError),
    /// The proving tape could not be derived.
    #[error(transparent)]
    Randomness(#[from] RandomnessError),
}

fn check_length(input: Input, expected: usize, actual: usize) -> Result<(), FaestError> {
    if expected == actual {
        Ok(())
    } else {
        Err(FaestError::InvalidLength {
            input,
            expected,
            actual,
        })
    }
}

/// The one-way function of `owf`: `y = AES_k(x)`, with the second block
/// `AES_k(x + 1)` (bit 0 of `x` flipped) at `lambda` of 192 and 256, or
/// `y = Rijndael_x(k) + k` for FAEST-EM.
///
/// `key` is secret. The key rule is **not** applied here: this is the function
/// itself, defined for every key.
///
/// # Errors
/// Returns [`FaestError::InvalidLength`] unless `key` is `lambda / 8` bytes and
/// `input` is [`OwfParams::input_bytes`] bytes long.
pub fn one_way_function(owf: OwfParams, key: &[u8], input: &[u8]) -> Result<Vec<u8>, FaestError> {
    check_length(Input::Key, owf.lambda().bytes(), key.len())?;
    check_length(Input::Block, owf.input_bytes(), input.len())?;
    Ok(cipher::evaluate(owf, key, input))
}

/// The extended witness of `key` for the public `input`: [`OwfParams::ell`] bits
/// as bytes, in the layout of [`OwfRelation`]. **Secret**; erased on drop.
///
/// The key rule is not applied here; a witness of a key that violates it fails
/// the first constraint of the relation.
///
/// # Errors
/// As [`one_way_function`].
pub fn extend_witness(
    owf: OwfParams,
    key: &[u8],
    input: &[u8],
) -> Result<Zeroizing<Vec<u8>>, FaestError> {
    check_length(Input::Key, owf.lambda().bytes(), key.len())?;
    check_length(Input::Block, owf.input_bytes(), input.len())?;
    Ok(cipher::extend_witness(owf, key, input))
}

/// Whether the key `k` satisfies the key rule: its first two bits are not both
/// one.
fn key_is_valid(key: &[u8]) -> bool {
    key.first().is_some_and(|byte| byte & 3 != 3)
}

/// A FAEST public key `pk = x || y` of one parameter set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    params: FaestParams,
    bytes: Vec<u8>,
}

impl PublicKey {
    /// The public key of `params` encoded by `bytes`.
    ///
    /// Every byte string of the right length is a public key; whether a secret
    /// key exists for it is not decidable here.
    ///
    /// # Errors
    /// Returns [`FaestError::InvalidLength`] unless `bytes` is
    /// [`FaestParams::public_key_bytes`] bytes long.
    pub fn from_bytes(params: &FaestParams, bytes: &[u8]) -> Result<Self, FaestError> {
        check_length(Input::PublicKey, params.public_key_bytes(), bytes.len())?;
        Ok(Self {
            params: *params,
            bytes: bytes.to_vec(),
        })
    }

    /// The parameter set.
    pub const fn params(&self) -> &FaestParams {
        &self.params
    }

    /// The encoding `x || y`.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Verify `signature` on `message`: [`verify`] with this key.
    ///
    /// # Errors
    /// As [`verify`].
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), FaestError> {
        verify(&self.params, &self.bytes, message, signature)
    }
}

/// A FAEST secret key `sk = x || k` of one parameter set, with its public key.
/// Erased on drop.
#[derive(Clone)]
pub struct SecretKey {
    public: PublicKey,
    bytes: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey")
            .field("params", &self.public.params.name())
            .finish_non_exhaustive()
    }
}

impl SecretKey {
    /// `FAEST.KeyGen`: draw `k` until it satisfies the key rule, then `x`, from
    /// `random`, which must fill its argument with uniformly random bytes.
    ///
    /// `random` is called with a buffer of `lambda / 8` bytes once per attempt at
    /// `k`, then once with a buffer of [`OwfParams::input_bytes`] bytes.
    ///
    /// # Errors
    /// Returns [`FaestError::KeyGeneration`] if [`KEY_GENERATION_ATTEMPTS`]
    /// draws all violate the key rule, which means the source is not random.
    pub fn generate(
        params: &FaestParams,
        mut random: impl FnMut(&mut [u8]),
    ) -> Result<Self, FaestError> {
        let owf = params.owf();
        let input_bytes = owf.input_bytes();
        let mut bytes = Zeroizing::new(vec![0u8; params.secret_key_bytes()]);
        let (input, key) = bytes
            .split_at_mut_checked(input_bytes)
            .ok_or(FaestError::KeyGeneration)?;
        let mut valid = false;
        for _ in 0..KEY_GENERATION_ATTEMPTS {
            random(key);
            if key_is_valid(key) {
                valid = true;
                break;
            }
        }
        if !valid {
            return Err(FaestError::KeyGeneration);
        }
        random(input);
        Self::from_bytes(params, &bytes)
    }

    /// Import the secret key of `params` encoded by `bytes` (`x || k`).
    ///
    /// # Errors
    /// Returns [`FaestError::InvalidLength`] unless `bytes` is
    /// [`FaestParams::secret_key_bytes`] bytes long, and
    /// [`FaestError::InvalidSecretKey`] if `k` violates the key rule.
    pub fn from_bytes(params: &FaestParams, bytes: &[u8]) -> Result<Self, FaestError> {
        check_length(Input::SecretKey, params.secret_key_bytes(), bytes.len())?;
        let owf = *params.owf();
        let (input, key) = bytes
            .split_at_checked(owf.input_bytes())
            .ok_or(FaestError::InvalidSecretKey)?;
        if !key_is_valid(key) {
            return Err(FaestError::InvalidSecretKey);
        }
        let mut public = Vec::with_capacity(params.public_key_bytes());
        public.extend_from_slice(input);
        public.extend_from_slice(&one_way_function(owf, key, input)?);
        Ok(Self {
            public: PublicKey::from_bytes(params, &public)?,
            bytes: Zeroizing::new(bytes.to_vec()),
        })
    }

    /// The parameter set.
    pub const fn params(&self) -> &FaestParams {
        &self.public.params
    }

    /// The encoding `x || k`. **Secret.**
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The public key `x || OWF_k(x)`.
    pub const fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// The public one-way-function input `x` and the key `k`.
    fn parts(&self) -> (&[u8], &[u8]) {
        let split = self.public.params.owf().input_bytes().min(self.bytes.len());
        self.bytes.split_at(split)
    }

    /// The extended witness of the key ([`extend_witness`]). **Secret.**
    ///
    /// # Errors
    /// None for a key built by this type; the signature is that of
    /// [`extend_witness`].
    pub fn witness(&self) -> Result<Zeroizing<Vec<u8>>, FaestError> {
        let (input, key) = self.parts();
        extend_witness(*self.public.params.owf(), key, input)
    }

    /// `FAEST.Sign`: the signature of `message` with the signing randomness
    /// `rho`, absorbed as supplied (see the module documentation). The result is
    /// [`FaestParams::signature_bytes`] bytes long and deterministic in the key,
    /// the message and `rho`.
    ///
    /// # Errors
    /// Returns [`FaestError::Proof`] with [`ProofError::GrindingExhausted`] if no
    /// counter gives an acceptable challenge; other errors do not occur for a
    /// key built by this type.
    pub fn sign(&self, message: &[u8], rho: &[u8]) -> Result<Vec<u8>, FaestError> {
        let params = &self.public.params;
        let level = params.vole().lambda();
        let (input, key) = self.parts();
        let public = self.public.as_bytes();
        let mu = transcript::message_digest(Namespace::REFERENCE, level, &[public, message])?;
        let tape = Tape::derive(Namespace::REFERENCE, level, key, &mu, rho)?;
        let witness = extend_witness(*params.owf(), key, input)?;
        let context = ProofContext::reference(*params.vole());
        let relation = OwfRelation::new(*params.owf());
        Ok(match level {
            SecurityLevel::L128 => {
                proof::prove::<Gf128, _>(&context, &relation, public, &mu, &witness, &tape)
            }
            SecurityLevel::L192 => {
                proof::prove::<Gf192, _>(&context, &relation, public, &mu, &witness, &tape)
            }
            SecurityLevel::L256 => {
                proof::prove::<Gf256, _>(&context, &relation, public, &mu, &witness, &tape)
            }
        }?)
    }

    /// Deterministic signing as the specification defines it: `rho = 0^lambda`.
    ///
    /// # Errors
    /// As [`Self::sign`].
    pub fn sign_deterministic(&self, message: &[u8]) -> Result<Vec<u8>, FaestError> {
        let zeros = [0u8; 32];
        let lambda_bytes = self.public.params.vole().lambda().bytes().min(zeros.len());
        self.sign(message, &zeros[..lambda_bytes])
    }
}

/// `FAEST.Verify`: accept iff `signature` is a valid signature of `message`
/// under `public_key` on the parameter set `params`.
///
/// Total on its inputs, all of which are untrusted: a public key or a signature
/// of the wrong length, non-canonical encodings and an invalid proof are all
/// errors, and nothing panics.
///
/// # Errors
/// * [`FaestError::InvalidLength`] for a public key of the wrong length;
/// * [`FaestError::Proof`] for every other rejection: [`ProofError::Codec`] for a
///   signature of the wrong length or with non-canonical padding or challenge,
///   [`ProofError::Vole`] for a rejected opening, and
///   [`ProofError::ChallengeMismatch`] for a signature that does not verify.
pub fn verify(
    params: &FaestParams,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), FaestError> {
    check_length(
        Input::PublicKey,
        params.public_key_bytes(),
        public_key.len(),
    )?;
    let level = params.vole().lambda();
    let mu = transcript::message_digest(Namespace::REFERENCE, level, &[public_key, message])?;
    let context = ProofContext::reference(*params.vole());
    let relation = OwfRelation::new(*params.owf());
    Ok(match level {
        SecurityLevel::L128 => {
            proof::verify::<Gf128, _>(&context, &relation, public_key, &mu, signature)
        }
        SecurityLevel::L192 => {
            proof::verify::<Gf192, _>(&context, &relation, public_key, &mu, signature)
        }
        SecurityLevel::L256 => {
            proof::verify::<Gf256, _>(&context, &relation, public_key, &mu, signature)
        }
    }?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        codec::CodecError,
        params::{FAEST_128F, FAEST_192F, FAEST_EM_128F, FAEST_PARAMETER_SETS},
    };

    /// A deterministic stand-in for a randomness source.
    fn source(seed: u8) -> impl FnMut(&mut [u8]) {
        let mut state = 0x1234_5678_u32 ^ (u32::from(seed) << 16);
        move |buffer: &mut [u8]| {
            for byte in buffer {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                *byte = state.to_le_bytes()[2];
            }
        }
    }

    #[test]
    fn generated_keys_have_the_sizes_of_the_set_and_satisfy_the_key_rule() {
        for set in &FAEST_PARAMETER_SETS {
            for seed in 0..8 {
                let secret = SecretKey::generate(set, source(seed)).expect("random source");
                assert_eq!(secret.params(), set);
                assert_eq!(secret.as_bytes().len(), set.secret_key_bytes());
                let public = secret.public_key();
                assert_eq!(public.params(), set);
                assert_eq!(public.as_bytes().len(), set.public_key_bytes());
                let (input, key) = secret.parts();
                assert!(key_is_valid(key));
                assert_eq!(public.as_bytes()[..input.len()], *input);
                assert_eq!(
                    public.as_bytes()[input.len()..],
                    one_way_function(*set.owf(), key, input).expect("valid lengths")
                );
                // Import of the encoding gives the same key pair.
                let imported = SecretKey::from_bytes(set, secret.as_bytes()).expect("valid key");
                assert_eq!(imported.public_key(), public);
                assert_eq!(
                    PublicKey::from_bytes(set, public.as_bytes()).as_ref(),
                    Ok(public)
                );
                assert_eq!(
                    8 * secret.witness().expect("valid key").len(),
                    set.owf().ell()
                );
            }
        }
    }

    #[test]
    fn key_generation_resamples_invalid_keys_and_gives_up_on_a_constant_source() {
        let set = &FAEST_128F;
        // Three invalid draws, then a valid one, then x.
        let mut draws = 0;
        let secret = SecretKey::generate(set, |buffer: &mut [u8]| {
            draws += 1;
            buffer.fill(if draws <= 3 { 0xff } else { 0x5a });
        })
        .expect("the fourth draw is valid");
        assert_eq!(draws, 5);
        assert!(secret.as_bytes().iter().all(|&byte| byte == 0x5a));

        let mut draws = 0;
        let outcome = SecretKey::generate(set, |buffer: &mut [u8]| {
            draws += 1;
            buffer.fill(0xff);
        });
        assert_eq!(outcome.err(), Some(FaestError::KeyGeneration));
        assert_eq!(draws, KEY_GENERATION_ATTEMPTS);
    }

    #[test]
    fn the_key_rule_is_on_the_first_two_bits_of_k() {
        assert!(key_is_valid(&[0x00]));
        assert!(key_is_valid(&[0x01, 0xff]));
        assert!(key_is_valid(&[0xfe]));
        assert!(!key_is_valid(&[0x03]));
        assert!(!key_is_valid(&[0xff, 0x00]));
        assert!(!key_is_valid(&[]));
    }

    #[test]
    fn import_refuses_wrong_lengths_and_keys_that_violate_the_key_rule() {
        for set in &FAEST_PARAMETER_SETS {
            let secret = SecretKey::generate(set, source(3)).expect("random source");
            let bytes = secret.as_bytes();
            let key_at = set.owf().input_bytes();
            for low in 0..4u8 {
                let mut other = bytes.to_vec();
                other[key_at] = (other[key_at] & 0xfc) | low;
                let imported = SecretKey::from_bytes(set, &other);
                if low == 3 {
                    assert_eq!(imported.err(), Some(FaestError::InvalidSecretKey));
                } else {
                    assert!(imported.is_ok(), "{} low bits {low}", set.name());
                }
            }
            // The rule is on k, not on x.
            let mut other = bytes.to_vec();
            other[0] |= 3;
            assert!(SecretKey::from_bytes(set, &other).is_ok());
            for len in [0, bytes.len() - 1, bytes.len() + 1] {
                let mut other = bytes.to_vec();
                other.resize(len, 0);
                assert_eq!(
                    SecretKey::from_bytes(set, &other).err(),
                    Some(FaestError::InvalidLength {
                        input: Input::SecretKey,
                        expected: bytes.len(),
                        actual: len
                    })
                );
            }
            let public = secret.public_key().as_bytes();
            assert_eq!(
                PublicKey::from_bytes(set, &public[1..]).err(),
                Some(FaestError::InvalidLength {
                    input: Input::PublicKey,
                    expected: public.len(),
                    actual: public.len() - 1
                })
            );
        }
    }

    #[test]
    fn the_one_way_function_and_the_witness_check_their_input_lengths() {
        let owf = *FAEST_192F.owf();
        let (key, input) = ([7u8; 24], [9u8; 16]);
        let output = one_way_function(owf, &key, &input).expect("valid lengths");
        assert_eq!(output.len(), 32);
        assert_eq!(
            extend_witness(owf, &key, &input)
                .expect("valid lengths")
                .len(),
            216
        );
        assert_eq!(
            one_way_function(owf, &key[1..], &input),
            Err(FaestError::InvalidLength {
                input: Input::Key,
                expected: 24,
                actual: 23
            })
        );
        assert_eq!(
            extend_witness(owf, &key, &input[..15]).map(|witness| witness.len()),
            Err(FaestError::InvalidLength {
                input: Input::Block,
                expected: 16,
                actual: 15
            })
        );
        // The Even-Mansour input is a whole block of lambda bits.
        assert_eq!(
            one_way_function(*FAEST_EM_128F.owf(), &[1; 16], &[2; 16])
                .expect("valid lengths")
                .len(),
            16
        );
    }

    #[test]
    fn signatures_verify_and_are_bound_to_key_message_and_randomness() {
        for set in [&FAEST_128F, &FAEST_EM_128F] {
            let secret = SecretKey::generate(set, source(11)).expect("random source");
            let public = secret.public_key();
            let signature = secret.sign(b"message", &[1; 16]).expect("signing succeeds");
            assert_eq!(signature.len(), set.signature_bytes());
            assert_eq!(public.verify(b"message", &signature), Ok(()));
            assert_eq!(
                verify(set, public.as_bytes(), b"message", &signature),
                Ok(())
            );
            // Deterministic in (key, message, rho); rho changes the signature.
            assert_eq!(secret.sign(b"message", &[1; 16]).as_ref(), Ok(&signature));
            assert_ne!(secret.sign(b"message", &[2; 16]).as_ref(), Ok(&signature));
            // The specification's deterministic mode is rho = 0^lambda.
            let deterministic = secret.sign_deterministic(b"message").expect("signing");
            assert_eq!(
                secret.sign(b"message", &[0; 16]).as_ref(),
                Ok(&deterministic)
            );
            assert_ne!(secret.sign(b"message", &[]).as_ref(), Ok(&deterministic));
            assert_eq!(public.verify(b"message", &deterministic), Ok(()));

            assert_eq!(
                public.verify(b"massage", &signature),
                Err(FaestError::Proof(ProofError::ChallengeMismatch))
            );
            let other = SecretKey::generate(set, source(12)).expect("random source");
            assert!(other.public_key().verify(b"message", &signature).is_err());
            assert_eq!(
                verify(set, &public.as_bytes()[1..], b"message", &signature),
                Err(FaestError::InvalidLength {
                    input: Input::PublicKey,
                    expected: set.public_key_bytes(),
                    actual: set.public_key_bytes() - 1
                })
            );
            assert_eq!(
                public.verify(b"message", &signature[1..]),
                Err(FaestError::Proof(ProofError::Codec(
                    CodecError::InvalidLength {
                        expected: signature.len(),
                        actual: signature.len() - 1
                    }
                )))
            );
            assert_eq!(
                public.verify(b"message", &[]),
                Err(FaestError::Proof(ProofError::Codec(
                    CodecError::InvalidLength {
                        expected: signature.len(),
                        actual: 0
                    }
                )))
            );
        }
    }

    #[test]
    fn secret_keys_do_not_print_their_bytes() {
        let secret = SecretKey::generate(&FAEST_128F, source(1)).expect("random source");
        assert_eq!(
            format!("{secret:?}"),
            "SecretKey { params: \"FAEST-128f\", .. }"
        );
    }
}
