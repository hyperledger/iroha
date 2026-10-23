//! Test-only entry points: seeded entropy, explicit coins, secret-derived probes and faults.
//!
//! This module is compiled only under
//! `cfg(any(test, feature = "bgv-test-fixtures"))`. The feature is enabled
//! from dev-dependencies alone, so nothing here exists in a production build.
//! It gives tests three things the production interface must not offer:
//!
//! - **Reproducible coins.** [`FixtureEntropy`] replaces the operating system
//!   as the source of operation seeds; the `*_from_coins` functions take the
//!   sampled polynomials themselves. Both feed the single production
//!   implementation, so a known-answer vector exercises the shipped code.
//! - **Secret-derived probes.** [`secret_coefficients`] and
//!   [`inner_product_words`] let an independent oracle compute the exact noise
//!   of a ciphertext. Production code never measures noise.
//! - **Faults.** [`arm_fault`] makes the next operation that reaches a named
//!   point panic, so erasure on unwind can be observed.
//!
//! # Fixture entropy
//!
//! Draw `i` (from zero) of [`FixtureEntropy`] is the first 64 bytes of the
//! BLAKE3 extendable output of
//! `derive_key(`[`FIXTURE_ENTROPY_CONTEXT`]`, master (64) || i (u32 LE))`.
use super::{
    BgvError, BgvProfile, Ciphertext, EvaluationKeys, KeySet, Plaintext, PublicKey, SecretKey,
    SwitchingKey, SwitchingKeyKind,
    coins::{COIN_SEED_BYTES, EntropySource},
    poly::RnsPoly,
    threshold::{DealerKeyShares, SecretKeyShare, ThresholdContext, ThresholdError},
};
use zeroize::Zeroizing;

pub use super::fault::{FaultPoint, arm as arm_fault, disarm as disarm_fault};

/// BLAKE3 `derive_key` context of the fixture entropy.
pub const FIXTURE_ENTROPY_CONTEXT: &str = "iroha_fhe bgv v1 fixture entropy";

/// Size in bytes of the heap block that holds the seed and the stream state of
/// one operation ([`super::coins`]). The clearing test watches blocks of this size.
pub const COIN_STATE_BYTES: usize = super::coins::COIN_STATE_BYTES;

/// How a [`FixtureEntropy`] stops delivering seeds.
#[derive(Clone, Copy, Debug)]
enum Breakdown {
    /// Every draw succeeds.
    Never,
    /// Draw number `from` and every later one report a failure.
    Unavailable { from: u32 },
    /// Draw number `from` and every later one deliver a seed of one repeated byte.
    Stuck { from: u32, byte: u8 },
}

/// A deterministic source of operation seeds, optionally breaking down after some draws.
#[derive(Clone, Copy, Debug)]
pub struct FixtureEntropy {
    master: [u8; COIN_SEED_BYTES],
    draws: u32,
    breakdown: Breakdown,
}

impl FixtureEntropy {
    /// A source that never fails.
    #[must_use]
    pub const fn new(master: [u8; COIN_SEED_BYTES]) -> Self {
        Self {
            master,
            draws: 0,
            breakdown: Breakdown::Never,
        }
    }

    /// A source whose draw number `successes` (from zero) and every later one fail.
    #[must_use]
    pub const fn failing_after(master: [u8; COIN_SEED_BYTES], successes: u32) -> Self {
        Self {
            master,
            draws: 0,
            breakdown: Breakdown::Unavailable { from: successes },
        }
    }

    /// A source whose draw number `successes` (from zero) and every later one
    /// deliver a seed made of `byte` only, as a stuck generator would.
    #[must_use]
    pub const fn stuck_after(master: [u8; COIN_SEED_BYTES], successes: u32, byte: u8) -> Self {
        Self {
            master,
            draws: 0,
            breakdown: Breakdown::Stuck {
                from: successes,
                byte,
            },
        }
    }

    /// Number of draws requested so far, including failed ones.
    #[must_use]
    pub const fn draws(&self) -> u32 {
        self.draws
    }

    /// The seed of draw `index`.
    #[must_use]
    pub fn seed(&self, index: u32) -> [u8; COIN_SEED_BYTES] {
        let mut hasher = blake3::Hasher::new_derive_key(FIXTURE_ENTROPY_CONTEXT);
        hasher.update(&self.master);
        hasher.update(&index.to_le_bytes());
        let mut seed = [0_u8; COIN_SEED_BYTES];
        hasher.finalize_xof().fill(&mut seed);
        seed
    }
}

impl EntropySource for FixtureEntropy {
    fn fill(&mut self, seed: &mut [u8; COIN_SEED_BYTES]) -> Result<(), BgvError> {
        let index = self.draws;
        self.draws += 1;
        match self.breakdown {
            Breakdown::Unavailable { from } if index >= from => {
                return Err(BgvError::EntropyUnavailable);
            }
            Breakdown::Stuck { from, byte } if index >= from => *seed = [byte; COIN_SEED_BYTES],
            _ => *seed = self.seed(index),
        }
        Ok(())
    }
}

/// [`SecretKey::generate`] with fixture entropy (one draw).
///
/// # Errors
/// As [`SecretKey::generate`].
pub fn secret_key(
    profile: &BgvProfile,
    entropy: &mut FixtureEntropy,
) -> Result<SecretKey, BgvError> {
    SecretKey::generate_with(profile, entropy)
}

/// [`PublicKey::generate`] with fixture entropy (one draw).
///
/// # Errors
/// As [`PublicKey::generate`].
pub fn public_key(
    profile: &BgvProfile,
    secret: &SecretKey,
    entropy: &mut FixtureEntropy,
) -> Result<PublicKey, BgvError> {
    PublicKey::generate_with(profile, secret, entropy)
}

/// Switching-key generation with fixture entropy (one draw).
///
/// # Errors
/// As [`SwitchingKey::generate_relinearization`] and [`SwitchingKey::generate_galois`].
pub fn switching_key(
    profile: &BgvProfile,
    secret: &SecretKey,
    kind: SwitchingKeyKind,
    entropy: &mut FixtureEntropy,
) -> Result<SwitchingKey, BgvError> {
    SwitchingKey::generate_with(profile, secret, kind, entropy)
}

/// [`EvaluationKeys::generate`] with fixture entropy (one draw per key).
///
/// # Errors
/// As [`EvaluationKeys::generate`].
pub fn evaluation_keys(
    profile: &BgvProfile,
    secret: &SecretKey,
    galois_elements: &[u32],
    entropy: &mut FixtureEntropy,
) -> Result<EvaluationKeys, BgvError> {
    EvaluationKeys::generate_with(profile, secret, galois_elements, entropy)
}

/// [`KeySet::generate`] with fixture entropy.
///
/// # Errors
/// As [`KeySet::generate`].
pub fn key_set(
    profile: &BgvProfile,
    galois_elements: &[u32],
    entropy: &mut FixtureEntropy,
) -> Result<KeySet, BgvError> {
    KeySet::generate_with(profile, galois_elements, entropy)
}

/// [`PublicKey::encrypt`] with fixture entropy (one draw).
///
/// # Errors
/// As [`PublicKey::encrypt`].
pub fn encrypt(
    profile: &BgvProfile,
    public: &PublicKey,
    plaintext: &Plaintext,
    entropy: &mut FixtureEntropy,
) -> Result<Ciphertext, BgvError> {
    public.encrypt_with(profile, plaintext, entropy)
}

/// The secret key with explicit ternary coefficients.
///
/// # Errors
/// [`BgvError::LengthMismatch`] or [`BgvError::NonCanonical`].
pub fn secret_key_from_coefficients(
    profile: &BgvProfile,
    coefficients: &[i64],
) -> Result<SecretKey, BgvError> {
    SecretKey::from_coefficients(profile, Zeroizing::new(coefficients.to_vec()))
}

/// The public key with an explicit mask (coefficient form over the main primes) and error.
///
/// # Errors
/// [`BgvError::ProfileMismatch`] or [`BgvError::LengthMismatch`].
pub fn public_key_from_coins(
    profile: &BgvProfile,
    secret: &SecretKey,
    mask: &[u64],
    error: &[i64],
) -> Result<PublicKey, BgvError> {
    let mask = RnsPoly::from_words(mask.to_vec(), profile.degree())?;
    PublicKey::from_coins(profile, secret, mask, error)
}

/// A switching key with one explicit mask (coefficient form over the main and
/// special primes) and error per digit.
///
/// # Errors
/// As the production generator, plus [`BgvError::LengthMismatch`].
pub fn switching_key_from_coins(
    profile: &BgvProfile,
    secret: &SecretKey,
    kind: SwitchingKeyKind,
    coins: &[(Vec<u64>, Vec<i64>)],
) -> Result<SwitchingKey, BgvError> {
    let coins = coins
        .iter()
        .map(|(mask, error)| {
            Ok((
                RnsPoly::from_words(mask.clone(), profile.degree())?,
                Zeroizing::new(error.clone()),
            ))
        })
        .collect::<Result<Vec<_>, BgvError>>()?;
    SwitchingKey::from_coins(profile, secret, kind, coins)
}

/// Encryption with an explicit ternary mask and explicit errors.
///
/// # Errors
/// [`BgvError::ProfileMismatch`] or [`BgvError::LengthMismatch`].
pub fn encrypt_from_coins(
    profile: &BgvProfile,
    public: &PublicKey,
    plaintext: &Plaintext,
    mask: &[i64],
    error0: &[i64],
    error1: &[i64],
) -> Result<Ciphertext, BgvError> {
    public.encrypt_from_coins(profile, plaintext, mask, error0, error1)
}

/// The ternary coefficients of a secret key. Secret; for oracles only.
#[must_use]
pub fn secret_coefficients(secret: &SecretKey) -> Vec<i64> {
    secret.coefficients().to_vec()
}

/// Canonical residues of `c0 + c1*s + c2*s^2` modulo `Q_l`, limb-major. Secret-derived.
///
/// An oracle reconstructs the centered value from these words to obtain the
/// exact noise of a ciphertext.
///
/// # Errors
/// [`BgvError::ProfileMismatch`].
pub fn inner_product_words(
    profile: &BgvProfile,
    secret: &SecretKey,
    ciphertext: &Ciphertext,
) -> Result<Vec<u64>, BgvError> {
    secret.check_profile(profile)?;
    ciphertext.check_profile(profile)?;
    Ok(secret.inner_product(profile, ciphertext)?.words().to_vec())
}

/// Split a consumed secret key with reproducible coins through the production dealer.
///
/// # Errors
/// Returns a profile mismatch, checked size overflow, insufficient secret-buffer
/// limit, or entropy failure from the production dealer. The consumed key clears
/// on refusal.
pub fn threshold_dealer<'profile>(
    profile: &'profile BgvProfile,
    context: ThresholdContext,
    secret: SecretKey,
    max_secret_bytes: usize,
    entropy: &mut FixtureEntropy,
) -> Result<DealerKeyShares<'profile>, ThresholdError> {
    DealerKeyShares::split_with(profile, context, secret, max_secret_bytes, entropy)
}

/// Copy an offline share's coefficient-form main/special RNS words for a test oracle.
///
/// The returned secret buffer clears on drop. No production caller can use this probe.
#[must_use]
pub fn threshold_share_words(share: &SecretKeyShare) -> Zeroizing<Vec<u64>> {
    Zeroizing::new(share.words_for_fixture().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::BgvParameters;

    fn profile() -> BgvProfile {
        BgvProfile::new(BgvParameters::derive(4, 257, (30, 3), (31, 2), 2).expect("parameters"))
            .expect("profile")
    }

    fn master(tag: u8) -> [u8; COIN_SEED_BYTES] {
        std::array::from_fn(|index| tag ^ u8::try_from(index).unwrap_or(0))
    }

    #[test]
    fn fixture_entropy_is_deterministic_and_counts_draws() {
        let mut entropy = FixtureEntropy::new(master(1));
        let mut first = [0_u8; COIN_SEED_BYTES];
        let mut second = [0_u8; COIN_SEED_BYTES];
        entropy.fill(&mut first).expect("draw");
        entropy.fill(&mut second).expect("draw");
        assert_eq!(entropy.draws(), 2);
        assert_ne!(first, second);
        assert_eq!(first, entropy.seed(0));
        assert_eq!(second, entropy.seed(1));
        assert_ne!(FixtureEntropy::new(master(2)).seed(0), first);
        // The derivation is the documented one.
        let mut hasher = blake3::Hasher::new_derive_key(FIXTURE_ENTROPY_CONTEXT);
        hasher.update(&master(1));
        hasher.update(&1_u32.to_le_bytes());
        let mut expected = [0_u8; COIN_SEED_BYTES];
        hasher.finalize_xof().fill(&mut expected);
        assert_eq!(second, expected);
        let mut failing = FixtureEntropy::failing_after(master(1), 1);
        let mut seed = [0_u8; COIN_SEED_BYTES];
        assert_eq!(failing.fill(&mut seed), Ok(()));
        assert_eq!(failing.fill(&mut seed), Err(BgvError::EntropyUnavailable));
        assert_eq!(failing.fill(&mut seed), Err(BgvError::EntropyUnavailable));
        assert_eq!(failing.draws(), 3);
        // A stuck source delivers its byte; the production draw refuses such a seed.
        let mut stuck = FixtureEntropy::stuck_after(master(1), 1, 0x5A);
        assert_eq!(stuck.fill(&mut seed), Ok(()));
        assert_eq!(seed, stuck.seed(0));
        assert_eq!(stuck.fill(&mut seed), Ok(()));
        assert_eq!(seed, [0x5A; COIN_SEED_BYTES]);
        let profile = profile();
        let mut stuck = FixtureEntropy::stuck_after(master(1), 0, 0x5A);
        assert_eq!(
            secret_key(&profile, &mut stuck).err(),
            Some(BgvError::EntropyUnavailable)
        );
        assert_eq!(COIN_STATE_BYTES, crate::bgv::coins::COIN_STATE_BYTES);
    }

    #[test]
    fn seeded_generators_reproduce_and_round_trip() {
        let profile = profile();
        let build = || {
            let mut entropy = FixtureEntropy::new(master(3));
            let keys = key_set(&profile, &[5], &mut entropy).expect("keys");
            let plaintext = Plaintext::new(&profile, (0..16).collect()).expect("plaintext");
            let ciphertext =
                encrypt(&profile, &keys.public, &plaintext, &mut entropy).expect("ciphertext");
            (keys, plaintext, ciphertext, entropy.draws())
        };
        let (keys, plaintext, ciphertext, draws) = build();
        let (again, _, ciphertext_again, _) = build();
        assert_eq!(draws, 5);
        assert_eq!(keys.public, again.public);
        assert_eq!(keys.evaluation, again.evaluation);
        assert_eq!(ciphertext, ciphertext_again);
        assert_eq!(
            keys.secret
                .decrypt(&profile, &ciphertext)
                .expect("plaintext"),
            plaintext
        );
        // The single-key generators draw the same seeds in the same order.
        let mut entropy = FixtureEntropy::new(master(3));
        let secret = secret_key(&profile, &mut entropy).expect("secret");
        let public = public_key(&profile, &secret, &mut entropy).expect("public");
        let relinearization = switching_key(
            &profile,
            &secret,
            SwitchingKeyKind::Relinearization,
            &mut entropy,
        )
        .expect("key");
        assert_eq!(
            secret_coefficients(&secret),
            secret_coefficients(&keys.secret)
        );
        assert_eq!(public, keys.public);
        assert_eq!(&relinearization, keys.evaluation.relinearization());
        let mut entropy = FixtureEntropy::new(master(3));
        let _ = secret_key(&profile, &mut entropy).expect("secret");
        let _ = public_key(&profile, &secret, &mut entropy).expect("public");
        let evaluation = evaluation_keys(&profile, &secret, &[5], &mut entropy).expect("keys");
        assert_eq!(evaluation, keys.evaluation);
    }

    #[test]
    fn explicit_coins_drive_the_production_equations() {
        let profile = profile();
        let secret_values: Vec<i64> = (0..16).map(|index| (index % 3) - 1).collect();
        let secret = secret_key_from_coefficients(&profile, &secret_values).expect("secret");
        assert_eq!(secret_coefficients(&secret), secret_values);
        // A zero mask and zero error give the public key (0, 0).
        let public = public_key_from_coins(&profile, &secret, &[0; 48], &[0; 16]).expect("public");
        assert_eq!(
            public.canonical_words(&profile).expect("words"),
            vec![0; 96]
        );
        assert_eq!(
            public_key_from_coins(&profile, &secret, &[0; 47], &[0; 16]).err(),
            Some(BgvError::LengthMismatch {
                expected: 16,
                found: 47
            })
        );
        // With that key, encryption with error e0 gives c0 = t*e0 + m and c1 = t*e1.
        let plaintext = Plaintext::constant(&profile, 7).expect("plaintext");
        let mut error0 = [0_i64; 16];
        error0[0] = 2;
        let mut error1 = [0_i64; 16];
        error1[3] = -1;
        let ciphertext =
            encrypt_from_coins(&profile, &public, &plaintext, &[1; 16], &error0, &error1)
                .expect("ciphertext");
        let words = ciphertext.canonical_words();
        let prime = profile.parameters().main_primes[0];
        assert_eq!(words[0], 7 + 2 * 257);
        assert_eq!(words[48 + 3], prime - 257);
        // The probe returns c0 + c1*s; here s[3] = -1... evaluated by the definition.
        let inner = inner_product_words(&profile, &secret, &ciphertext).expect("inner");
        let mut expected = vec![0_i128; 16];
        expected[0] = 7 + 2 * 257;
        for (index, &value) in secret_values.iter().enumerate() {
            // (-t * X^3) * s: X^3 * X^index.
            let position = index + 3;
            let term = -257 * i128::from(value);
            if position >= 16 {
                expected[position - 16] -= term;
            } else {
                expected[position] += term;
            }
        }
        let expected: Vec<u64> = expected
            .iter()
            .map(|&value| crate::modular::reduce_i128_to_u64_mod(value, prime))
            .collect();
        assert_eq!(&inner[..16], expected);
        // Switching keys with zero coins are the bare gadget times the source.
        let coins = vec![(vec![0_u64; 80], vec![0_i64; 16]); 2];
        let key = switching_key_from_coins(&profile, &secret, SwitchingKeyKind::Galois(5), &coins)
            .expect("key");
        let key_words = key.canonical_words(&profile).expect("words");
        // Digit 1 covers only q2: its b is zero on q0.
        assert!(key_words[2 * 80..2 * 80 + 16].iter().all(|&word| word == 0));
        assert!(key_words[..16].iter().any(|&word| word != 0));
        let other = BgvProfile::new(
            BgvParameters::derive(4, 257, (30, 2), (31, 2), 2).expect("parameters"),
        )
        .expect("profile");
        assert_eq!(
            inner_product_words(&other, &secret, &ciphertext).err(),
            Some(BgvError::ProfileMismatch)
        );
    }
}

/// Refusals of the fixture-only encryption equation oracle.
pub use super::encryption_witness::EncryptionWitnessError;

/// Clearing, non-cloneable encryption coins borrowing their original inputs.
///
/// This fixture cannot serialize or expose its coefficients. Its check is an
/// offline equation oracle, not a proof or an admitted network capability.
///
/// ```compile_fail
/// use iroha_fhe::bgv::fixtures::EncryptionWitness;
/// fn duplicate(value: EncryptionWitness<'_>) { let _ = value.clone(); }
/// ```
pub struct EncryptionWitness<'a>(super::encryption_witness::EncryptionWitness<'a>);

impl std::fmt::Debug for EncryptionWitness<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("[REDACTED BGV encryption witness]")
    }
}

impl EncryptionWitness<'_> {
    /// Check bounded coins and the exact fresh encryption of the borrowed inputs.
    ///
    /// Full key and plaintext equality prevent statement substitution, even for
    /// a zero mask. This does not prove honest key/coin generation. The oracle
    /// is variable-time and must not serve as a remotely observable verifier.
    ///
    /// # Errors
    /// Working-buffer refusal, altered statement, out-of-range coins, malformed
    /// shapes or a ciphertext differing in any component or noise metadata.
    pub fn check(
        &self,
        profile: &BgvProfile,
        key: &PublicKey,
        plaintext: &Plaintext,
        ciphertext: &Ciphertext,
        working_buffer_limit: usize,
    ) -> Result<(), EncryptionWitnessError> {
        self.0
            .check(profile, key, plaintext, ciphertext, working_buffer_limit)
    }
}

/// Conservative owned buffer payload bytes for witness generation/checking.
///
/// Includes three sampled arrays, four arithmetic RNS polynomials and the coin
/// state. Borrowed inputs, public metadata, allocator overhead and compiler or
/// stack copies are excluded. This is not a whole-request resource certificate.
///
/// # Errors
/// Checked size arithmetic overflow.
pub fn encryption_witness_working_bytes(
    profile: &BgvProfile,
) -> Result<usize, EncryptionWitnessError> {
    super::encryption_witness::preflight(profile, usize::MAX)
}

/// Encrypt once while retaining the same clearing coins used by ordinary encryption.
///
/// Checks the working-buffer payload ceiling before sampling or allocating any
/// secret arrays. Exactly one seed and the original three tagged streams are
/// used. The witness borrows the profile, complete key and plaintext unchanged.
///
/// # Errors
/// Working-buffer refusal, mismatched inputs, entropy failure or BGV arithmetic.
pub fn encrypt_with_witness<'a>(
    profile: &'a BgvProfile,
    key: &'a PublicKey,
    plaintext: &'a Plaintext,
    entropy: &mut FixtureEntropy,
    working_buffer_limit: usize,
) -> Result<(Ciphertext, EncryptionWitness<'a>), EncryptionWitnessError> {
    super::encryption_witness::preflight(profile, working_buffer_limit)?;
    let witness =
        super::encryption_witness::EncryptionWitness::sample(profile, key, plaintext, entropy)?;
    let ciphertext = witness.encrypt()?;
    Ok((ciphertext, EncryptionWitness(witness)))
}
