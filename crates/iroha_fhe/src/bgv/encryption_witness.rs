//! Clearing sampled encryption witnesses and a fixture-only equation oracle.
//!
//! Ordinary encryption uses this same owner and drops it immediately. Retained
//! witnesses borrow the exact original key and plaintext, own only the three
//! sampled arrays, and cannot be cloned or serialized. The oracle is not a
//! proof, admission capability, randomness certification or circuit sanitizer.
// TODO(R.11): authenticated client/key relations with a hiding proof backend,
// honest-generation provenance and a reviewed circuit-private construction.
use super::{
    BgvError, BgvProfile, Ciphertext, Plaintext, PublicKey,
    coins::{CoinPurpose, Coins, EntropySource},
};
use zeroize::Zeroizing;

pub(super) struct EncryptionWitness<'a> {
    profile: &'a BgvProfile,
    key: &'a PublicKey,
    plaintext: &'a Plaintext,
    mask: Zeroizing<Vec<i64>>,
    error0: Zeroizing<Vec<i64>>,
    error1: Zeroizing<Vec<i64>>,
}

impl<'a> EncryptionWitness<'a> {
    pub(super) fn sample(
        profile: &'a BgvProfile,
        key: &'a PublicKey,
        plaintext: &'a Plaintext,
        entropy: &mut dyn EntropySource,
    ) -> Result<Self, BgvError> {
        key.check_profile(profile)?;
        plaintext.check_profile(profile)?;
        let mut coins = Coins::draw(entropy)?;
        let degree = profile.degree();
        let eta = profile.parameters().error_eta;
        let identity = profile.identity();
        let mut mask = Zeroizing::new(vec![0_i64; degree]);
        coins
            .stream(identity, CoinPurpose::EncryptionMask, 0, 0)
            .ternary(&mut mask);
        let mut error0 = Zeroizing::new(vec![0_i64; degree]);
        coins
            .stream(identity, CoinPurpose::EncryptionError0, 0, 0)
            .centered_binomial(eta, &mut error0);
        let mut error1 = Zeroizing::new(vec![0_i64; degree]);
        coins
            .stream(identity, CoinPurpose::EncryptionError1, 0, 0)
            .centered_binomial(eta, &mut error1);
        Ok(Self {
            profile,
            key,
            plaintext,
            mask,
            error0,
            error1,
        })
    }

    pub(super) fn encrypt(&self) -> Result<Ciphertext, BgvError> {
        self.key.encrypt_from_coins(
            self.profile,
            self.plaintext,
            &self.mask,
            &self.error0,
            &self.error1,
        )
    }
}

#[cfg(any(test, feature = "bgv-test-fixtures"))]
mod reference {
    use super::super::coins::COIN_STATE_BYTES;
    use super::*;
    use thiserror::Error;

    /// A refusal by the offline encryption-equation fixture, never admission.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
    pub enum EncryptionWitnessError {
        /// The checked working-buffer payload calculation overflowed.
        #[error("encryption witness working-buffer size overflow")]
        SizeOverflow,
        /// The caller's explicit working-buffer payload ceiling is insufficient.
        #[error("encryption witness requires {required} working-buffer bytes, limit is {limit}")]
        BufferLimit {
            /// Conservative simultaneous owned buffer payload bytes.
            required: usize,
            /// Caller-supplied ceiling.
            limit: usize,
        },
        /// The supplied profile, full key or plaintext differs from the borrowed original.
        #[error("encryption witness statement differs from its original inputs")]
        StatementMismatch,
        /// An encryption mask coefficient is not ternary.
        #[error("encryption witness mask coefficient {index} is not ternary")]
        MaskOutOfRange {
            /// Coefficient index, without revealing the coefficient value.
            index: usize,
        },
        /// An encryption error exceeds the profile's centered-binomial bound.
        #[error("encryption witness error {component} coefficient {index} exceeds its bound")]
        ErrorOutOfRange {
            /// Error component, zero or one.
            component: usize,
            /// Coefficient index, without revealing the coefficient value.
            index: usize,
        },
        /// The complete ciphertext differs from the prescribed fresh encryption.
        #[error("encryption witness equation or fresh ciphertext shape differs")]
        RelationMismatch,
        /// Original sampling, shape or arithmetic failure.
        #[error(transparent)]
        Bgv(#[from] BgvError),
    }

    /// Conservative payload bound, not a whole-process/RSS or admission limit.
    pub(in super::super) fn working_buffer_bytes(degree: usize, limbs: usize) -> Option<usize> {
        // Three final-size sampled arrays plus four simultaneous RNS polynomials
        // in encrypt_from_coins (mask, c0, c1, message). NTTs work in-place.
        // Include the coin state conservatively although it is already dropped
        // before the arithmetic begins. Borrowed inputs, public shape metadata,
        // allocator overhead and compiler/stack copies are outside this measure.
        let samples = degree.checked_mul(3)?.checked_mul(size_of::<i64>())?;
        let polys = degree
            .checked_mul(limbs)?
            .checked_mul(4)?
            .checked_mul(size_of::<u64>())?;
        samples.checked_add(polys)?.checked_add(COIN_STATE_BYTES)
    }

    pub(in super::super) fn preflight(
        profile: &BgvProfile,
        limit: usize,
    ) -> Result<usize, EncryptionWitnessError> {
        let required = working_buffer_bytes(profile.degree(), profile.top_level() + 1)
            .ok_or(EncryptionWitnessError::SizeOverflow)?;
        if required > limit {
            return Err(EncryptionWitnessError::BufferLimit { required, limit });
        }
        Ok(required)
    }

    impl EncryptionWitness<'_> {
        pub(in super::super) fn check(
            &self,
            profile: &BgvProfile,
            key: &PublicKey,
            plaintext: &Plaintext,
            ciphertext: &Ciphertext,
            limit: usize,
        ) -> Result<(), EncryptionWitnessError> {
            preflight(profile, limit)?;
            if profile.identity() != self.profile.identity()
                || key != self.key
                || plaintext != self.plaintext
            {
                return Err(EncryptionWitnessError::StatementMismatch);
            }
            for values in [&self.mask, &self.error0, &self.error1] {
                if values.len() != profile.degree() {
                    return Err(BgvError::LengthMismatch {
                        expected: profile.degree(),
                        found: values.len(),
                    }
                    .into());
                }
            }
            if let Some(index) = self
                .mask
                .iter()
                .position(|&value| !(-1..=1).contains(&value))
            {
                return Err(EncryptionWitnessError::MaskOutOfRange { index });
            }
            for (component, values) in [&self.error0, &self.error1].into_iter().enumerate() {
                if let Some(index) = values
                    .iter()
                    .position(|value| value.unsigned_abs() > profile.error_bound())
                {
                    return Err(EncryptionWitnessError::ErrorOutOfRange { component, index });
                }
            }
            // Equality includes identity, top level, component count, every
            // residue and exact fresh public noise metadata. A decoded claimed
            // bound is never accepted as proof of this equation.
            if self.encrypt()? != *ciphertext {
                return Err(EncryptionWitnessError::RelationMismatch);
            }
            Ok(())
        }
    }
}

#[cfg(any(test, feature = "bgv-test-fixtures"))]
pub use reference::EncryptionWitnessError;
#[cfg(any(test, feature = "bgv-test-fixtures"))]
pub(super) use reference::preflight;
#[cfg(test)]
use reference::working_buffer_bytes;

#[cfg(test)]
mod tests {
    //! Independent small-ring oracle and adversarial witness checks.
    use super::*;
    use crate::{
        bgv::{
            BgvParameters, NoiseBound,
            fixtures::{self, FixtureEntropy},
        },
        natural::Natural,
    };

    type Refusal = EncryptionWitnessError;

    fn profile() -> BgvProfile {
        BgvProfile::new(BgvParameters::derive(4, 257, (30, 3), (31, 2), 2).expect("parameters"))
            .expect("profile")
    }

    fn entropy(tag: u8) -> FixtureEntropy {
        FixtureEntropy::new(std::array::from_fn(|i| {
            tag.wrapping_add(u8::try_from(i).expect("small").wrapping_mul(11))
        }))
    }

    fn key(profile: &BgvProfile) -> PublicKey {
        let secret = fixtures::secret_key(profile, &mut entropy(1)).expect("secret");
        fixtures::public_key(profile, &secret, &mut entropy(2)).expect("key")
    }

    // Independent signed integer schoolbook multiplication in Z[X]/(X^N+1).
    // This test uses no modular, NTT, small_residue or BGV arithmetic helper.
    fn product(left: &[u64], right: &[i64], modulus: u64) -> Vec<u64> {
        let n = left.len();
        let mut out = vec![0_i128; n];
        for (i, &a) in left.iter().enumerate() {
            for (j, &b) in right.iter().enumerate() {
                let term = i128::from(a) * i128::from(b);
                if i + j < n {
                    out[i + j] += term;
                } else {
                    out[i + j - n] -= term;
                }
            }
        }
        out.into_iter()
            .map(|x| u64::try_from(x.rem_euclid(i128::from(modulus))).expect("residue"))
            .collect()
    }

    #[test]
    fn retained_encryption_matches_ordinary_streams_and_independent_ring_equations() {
        let p = profile();
        let k = key(&p);
        let m =
            Plaintext::new(&p, (0..16).map(|i| (i * 37 + 250) % 257).collect()).expect("plaintext");
        let mut rng = entropy(3);
        let w = EncryptionWitness::sample(&p, &k, &m, &mut rng).expect("sample");
        assert_eq!(rng.draws(), 1);
        let c = w.encrypt().expect("encrypt");
        w.check(&p, &k, &m, &c, usize::MAX).expect("relation");
        assert_eq!(
            fixtures::encrypt(&p, &k, &m, &mut entropy(3)).expect("ordinary"),
            c
        );
        let words = k.canonical_words(&p).expect("key words");
        let n = p.degree();
        let limbs = p.top_level() + 1;
        let mut expected = Vec::new();
        for component in 0..2 {
            for (limb, &q) in p.parameters().main_primes.iter().enumerate() {
                let offset = (component * limbs + limb) * n;
                let convolution = product(&words[offset..offset + n], &w.mask, q);
                for (i, &value) in convolution.iter().enumerate() {
                    let error = if component == 0 {
                        w.error0[i]
                    } else {
                        w.error1[i]
                    };
                    let raw = m.coefficients()[i];
                    let message = if component == 1 {
                        0
                    } else if raw > 128 {
                        i128::from(raw) - 257
                    } else {
                        i128::from(raw)
                    };
                    let result = (i128::from(value) + 257 * i128::from(error) + message)
                        .rem_euclid(i128::from(q));
                    expected.push(u64::try_from(result).expect("canonical residue"));
                }
            }
        }
        assert_eq!(c.canonical_words(), expected);
        let oracle =
            Ciphertext::from_canonical_words(&p, p.top_level(), 2, &expected, c.noise_bound())
                .expect("oracle frame");
        assert_eq!(
            c.to_bytes(&p).expect("bytes"),
            oracle.to_bytes(&p).expect("oracle bytes")
        );
        assert_eq!(
            PublicKey::from_bytes(&p, &k.to_bytes(&p).expect("key bytes")).expect("decoded key"),
            k
        );
    }

    #[test]
    fn witness_bounds_refuse_equations_with_out_of_range_coins() {
        let p = profile();
        let k = key(&p);
        let m = Plaintext::constant(&p, 7).expect("message");
        let mut w = EncryptionWitness::sample(&p, &k, &m, &mut entropy(3)).expect("witness");
        for value in [-2, 2, i64::MIN, i64::MAX] {
            w.mask[0] = value;
            // Use the honest ciphertext: bound checks must precede arithmetic on invalid coins.
            let c = fixtures::encrypt(&p, &k, &m, &mut entropy(3)).expect("ciphertext");
            assert_eq!(
                w.check(&p, &k, &m, &c, usize::MAX),
                Err(Refusal::MaskOutOfRange { index: 0 })
            );
        }
        w.mask[0] = 0;
        let bound = i64::try_from(p.error_bound()).expect("small eta");
        for component in 0..2 {
            for value in [-bound - 1, bound + 1, i64::MIN, i64::MAX] {
                let error = if component == 0 {
                    &mut w.error0
                } else {
                    &mut w.error1
                };
                error[1] = value;
                let c = fixtures::encrypt(&p, &k, &m, &mut entropy(3)).expect("ciphertext");
                assert_eq!(
                    w.check(&p, &k, &m, &c, usize::MAX),
                    Err(Refusal::ErrorOutOfRange {
                        component,
                        index: 1
                    })
                );
            }
            let error = if component == 0 {
                &mut w.error0
            } else {
                &mut w.error1
            };
            error[1] = 0;
        }
        // Both closed error boundaries and all ternary values remain valid.
        w.mask[..3].copy_from_slice(&[-1, 0, 1]);
        w.error0[..2].copy_from_slice(&[-bound, bound]);
        w.error1[..2].copy_from_slice(&[bound, -bound]);
        let c = w.encrypt().expect("bounded ciphertext");
        w.check(&p, &k, &m, &c, usize::MAX).expect("closed bounds");
    }

    #[test]
    fn witness_lengths_are_checked_before_arithmetic() {
        let p = profile();
        let k = key(&p);
        let m = Plaintext::constant(&p, 7).expect("message");
        for which in 0..3 {
            let mut w = EncryptionWitness::sample(&p, &k, &m, &mut entropy(3)).expect("witness");
            let c = w.encrypt().expect("ciphertext");
            let buffer = match which {
                0 => &mut w.mask,
                1 => &mut w.error0,
                _ => &mut w.error1,
            };
            buffer.pop();
            assert_eq!(
                w.check(&p, &k, &m, &c, usize::MAX),
                Err(Refusal::Bgv(BgvError::LengthMismatch {
                    expected: 16,
                    found: 15
                }))
            );
        }
    }

    #[test]
    fn witness_binds_full_key_plaintext_and_profile_even_for_zero_mask() {
        let p = profile();
        let k = key(&p);
        let m = Plaintext::constant(&p, 7).expect("message");
        let mut w = EncryptionWitness::sample(&p, &k, &m, &mut entropy(3)).expect("witness");
        w.mask.fill(0);
        let c = w.encrypt().expect("ciphertext");
        let mut words = k.canonical_words(&p).expect("words");
        words[0] = (words[0] + 1) % p.parameters().main_primes[0];
        let changed = PublicKey::from_canonical_words(&p, &words).expect("altered key");
        // The equation alone is unchanged with u=0; the borrowed original key still binds.
        assert_eq!(
            changed
                .encrypt_from_coins(&p, &m, &w.mask, &w.error0, &w.error1)
                .expect("same equation"),
            c
        );
        assert_eq!(
            w.check(&p, &changed, &m, &c, usize::MAX),
            Err(Refusal::StatementMismatch)
        );
        let different = Plaintext::constant(&p, 8).expect("message");
        assert_eq!(
            w.check(&p, &k, &different, &c, usize::MAX),
            Err(Refusal::StatementMismatch)
        );
        let foreign = BgvProfile::new(
            BgvParameters::derive(4, 257, (30, 2), (31, 2), 2).expect("parameters"),
        )
        .expect("other");
        assert_eq!(
            w.check(&foreign, &k, &m, &c, usize::MAX),
            Err(Refusal::StatementMismatch)
        );
    }

    #[test]
    fn witness_refuses_ciphertext_residue_shape_and_noise_substitutions() {
        let p = profile();
        let k = key(&p);
        let m = Plaintext::constant(&p, 7).expect("message");
        let w = EncryptionWitness::sample(&p, &k, &m, &mut entropy(3)).expect("witness");
        let c = w.encrypt().expect("ciphertext");
        for index in [0, 47, 48, 95] {
            let mut words = c.canonical_words();
            let q = p.parameters().main_primes[(index / 16) % 3];
            words[index] = (words[index] + 1) % q;
            let changed = Ciphertext::from_canonical_words(&p, 2, 2, &words, c.noise_bound())
                .expect("canonical altered");
            assert_eq!(
                w.check(&p, &k, &m, &changed, usize::MAX),
                Err(Refusal::RelationMismatch)
            );
        }
        let zero = NoiseBound::new(Natural::from_u64(0));
        let changed = Ciphertext::from_canonical_words(&p, 2, 2, &c.canonical_words(), &zero)
            .expect("claimed zero noise");
        assert_eq!(
            w.check(&p, &k, &m, &changed, usize::MAX),
            Err(Refusal::RelationMismatch)
        );
        for (level, components) in [(1, 2), (2, 3)] {
            let shape = p
                .plan_claimed(level, components, p.fresh_noise().clone())
                .expect("shape");
            let polys = (0..components)
                .map(|_| super::super::poly::RnsPoly::zero(level + 1, 16))
                .collect();
            let changed = Ciphertext::from_shape(&p, shape, polys);
            assert_eq!(
                w.check(&p, &k, &m, &changed, usize::MAX),
                Err(Refusal::RelationMismatch)
            );
        }
        let mut invalid = c.canonical_words();
        invalid[0] = p.parameters().main_primes[0];
        assert_eq!(
            Ciphertext::from_canonical_words(&p, 2, 2, &invalid, c.noise_bound()).err(),
            Some(BgvError::NonCanonical { index: 0 })
        );
    }

    #[test]
    fn witness_resource_boundary_precedes_entropy_and_checks_overflow() {
        let p = profile();
        let k = key(&p);
        let m = Plaintext::constant(&p, 7).expect("message");
        let required = fixtures::encryption_witness_working_bytes(&p).expect("bound");
        assert_eq!(
            required,
            3 * 16 * 8 + 4 * 3 * 16 * 8 + super::super::coins::COIN_STATE_BYTES
        );
        for (degree, limbs) in [(usize::MAX, 1), (16, usize::MAX), (usize::MAX / 24, 1)] {
            assert_eq!(working_buffer_bytes(degree, limbs), None);
        }
        let mut rng = entropy(3);
        assert_eq!(
            fixtures::encrypt_with_witness(&p, &k, &m, &mut rng, required - 1).err(),
            Some(Refusal::BufferLimit {
                required,
                limit: required - 1
            })
        );
        assert_eq!(rng.draws(), 0);
        let (c, w) =
            fixtures::encrypt_with_witness(&p, &k, &m, &mut rng, required).expect("exact limit");
        assert_eq!(rng.draws(), 1);
        w.check(&p, &k, &m, &c, required).expect("exact check");
        assert_eq!(
            w.check(&p, &k, &m, &c, required - 1),
            Err(Refusal::BufferLimit {
                required,
                limit: required - 1
            })
        );
        assert_eq!(format!("{w:?}"), "[REDACTED BGV encryption witness]");
        let mut failing = FixtureEntropy::failing_after([3; 64], 0);
        assert_eq!(
            fixtures::encrypt_with_witness(&p, &k, &m, &mut failing, required).err(),
            Some(Refusal::Bgv(BgvError::EntropyUnavailable))
        );
        assert_eq!(failing.draws(), 1);
    }
}
