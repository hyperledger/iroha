//! Deterministic size and work model of a profile.
//!
//! Everything here is a function of the public geometry of a profile: the
//! ring degree, the number of main and special primes, the digit size and the
//! level. Nothing is measured and nothing depends on a key, a plaintext or a
//! host. Measured times and memory are recorded by the cost measurement test
//! and reported beside these numbers; the two are never mixed.
//!
//! # Sizes
//!
//! A residue is eight bytes. Every size is the length of a canonical frame
//! the crate encodes and decodes: [`super::Ciphertext::encoded_len`],
//! [`super::PublicKey::encoded_len`], [`super::SwitchingKey::encoded_len`],
//! [`super::EvaluationKeys::encoded_len`] and
//! [`super::SecretKey::custody_len`]. A public key is `2 * (L + 1) * N`
//! residues and a switching key `digits * 2 * (L + 1 + K) * N` residues after
//! their headers. Keys are stored uncompressed: the uniform halves are not
//! replaced by seeds.
//!
//! # Work units
//!
//! One unit is one multiplication of two word residues. With `n = N`, a
//! forward transform of one limb is `F = (n/2) * log2(n)` units, an inverse
//! transform `F + n`, and a limb-wide product or multiply-accumulate `n`.
//! Exact conversion of a digit of `d` primes into `m` other primes costs
//! `n * (d + d*(d-1)/2 + m*d)`, and the congruence-preserving division of
//! `k` kept limbs by `d` dropped primes `n * (2*d + d*(d-1)/2 + k*(d + 2))`.
//! Additions, subtractions, permutations and copies are not counted. The
//! formulas below compose these per operation exactly as the code performs
//! them, so the model changes only when the algorithm does.
use super::{BgvError, BgvProfile, Ciphertext, EvaluationKeys, PublicKey, SecretKey, SwitchingKey};

/// Bytes of one residue.
pub const RESIDUE_BYTES: u64 = 8;

/// The deterministic cost model of one profile.
#[derive(Clone, Copy, Debug)]
pub struct CostModel<'profile> {
    profile: &'profile BgvProfile,
}

fn word(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

impl<'profile> CostModel<'profile> {
    /// The model of `profile`.
    #[must_use]
    pub const fn new(profile: &'profile BgvProfile) -> Self {
        Self { profile }
    }

    fn degree(self) -> u64 {
        word(self.profile.degree())
    }

    fn special(self) -> u64 {
        word(self.profile.special_count())
    }

    fn check_level(self, level: usize) -> Result<u64, BgvError> {
        self.profile.level(level)?;
        Ok(word(level) + 1)
    }

    /// Units of one forward transform of one limb: `(n/2) * log2(n)`.
    #[must_use]
    pub fn forward_transform_units(self) -> u64 {
        self.degree() / 2 * u64::from(self.profile.degree().ilog2())
    }

    /// Units of one inverse transform of one limb: forward plus the scaling by `n^-1`.
    #[must_use]
    pub fn inverse_transform_units(self) -> u64 {
        self.forward_transform_units() + self.degree()
    }

    /// Units of the exact conversion of a digit of `digit` primes into `targets` primes.
    #[must_use]
    pub fn conversion_units(self, digit: u64, targets: u64) -> u64 {
        self.degree() * (digit + digit * digit.saturating_sub(1) / 2 + targets * digit)
    }

    /// Units of the congruence-preserving division of `kept` limbs by `dropped` primes.
    #[must_use]
    pub fn scale_down_units(self, kept: u64, dropped: u64) -> u64 {
        self.degree()
            * (2 * dropped + dropped * dropped.saturating_sub(1) / 2 + kept * (dropped + 2))
    }

    /// Canonical frame bytes of a ciphertext.
    ///
    /// # Errors
    /// [`BgvError::LevelOutOfRange`] or [`BgvError::ComponentCount`].
    pub fn ciphertext_bytes(self, level: usize, components: usize) -> Result<u64, BgvError> {
        Ciphertext::encoded_len(self.profile, level, components).map(word)
    }

    /// Frame bytes of the public key.
    #[must_use]
    pub fn public_key_bytes(self) -> u64 {
        word(PublicKey::encoded_len(self.profile))
    }

    /// Frame bytes of one switching key.
    #[must_use]
    pub fn switching_key_bytes(self) -> u64 {
        word(SwitchingKey::encoded_len(self.profile))
    }

    /// Frame bytes of the relinearization key and `galois_keys` Galois keys.
    #[must_use]
    pub fn evaluation_key_bytes(self, galois_keys: usize) -> u64 {
        word(EvaluationKeys::encoded_len(self.profile, galois_keys))
    }

    /// Custody-frame bytes of the secret key.
    #[must_use]
    pub fn secret_key_bytes(self) -> u64 {
        word(SecretKey::custody_len(self.profile))
    }

    /// Bytes of a ciphertext held in memory at `level`: its residues without a frame.
    ///
    /// # Errors
    /// [`BgvError::LevelOutOfRange`].
    pub fn ciphertext_residue_bytes(
        self,
        level: usize,
        components: usize,
    ) -> Result<u64, BgvError> {
        let limbs = self.check_level(level)?;
        Ok(RESIDUE_BYTES * word(components) * limbs * self.degree())
    }

    /// Units of one hybrid key switch at `level`.
    ///
    /// # Errors
    /// [`BgvError::LevelOutOfRange`].
    pub fn key_switch_units(self, level: usize) -> Result<u64, BgvError> {
        let limbs = self.check_level(level)?;
        let extended = limbs + self.special();
        let context = self.profile.level(level)?;
        let per_digit: u64 = context
            .digits
            .iter()
            .map(|digit| {
                let size = word(digit.len);
                self.conversion_units(size, extended - size)
                    + extended * self.forward_transform_units()
                    + 2 * extended * self.degree()
            })
            .sum();
        Ok(per_digit
            + 2 * extended * self.inverse_transform_units()
            + 2 * self.scale_down_units(limbs, self.special()))
    }

    /// Units of the tensor product of two two-component ciphertexts at `level`.
    ///
    /// # Errors
    /// [`BgvError::LevelOutOfRange`].
    pub fn tensor_units(self, level: usize) -> Result<u64, BgvError> {
        let limbs = self.check_level(level)?;
        Ok(limbs
            * (4 * self.forward_transform_units()
                + 4 * self.degree()
                + 3 * self.inverse_transform_units()))
    }

    /// Units of one ciphertext multiplication with relinearization at `level`.
    ///
    /// # Errors
    /// [`BgvError::LevelOutOfRange`].
    pub fn multiplication_units(self, level: usize) -> Result<u64, BgvError> {
        Ok(self.tensor_units(level)? + self.key_switch_units(level)?)
    }

    /// Units of one plaintext multiplication of a two-component ciphertext at `level`.
    ///
    /// # Errors
    /// [`BgvError::LevelOutOfRange`].
    pub fn plaintext_multiplication_units(self, level: usize) -> Result<u64, BgvError> {
        let limbs = self.check_level(level)?;
        Ok(limbs
            * (3 * self.forward_transform_units()
                + 2 * self.degree()
                + 2 * self.inverse_transform_units()))
    }

    /// Units of one automorphism with its key switch at `level`.
    ///
    /// # Errors
    /// [`BgvError::LevelOutOfRange`].
    pub fn automorphism_units(self, level: usize) -> Result<u64, BgvError> {
        self.key_switch_units(level)
    }

    /// Units of dropping the last prime of a two-component ciphertext at `level`.
    ///
    /// # Errors
    /// [`BgvError::LevelOutOfRange`] or [`BgvError::NoLevelLeft`] at level zero.
    pub fn switch_down_units(self, level: usize) -> Result<u64, BgvError> {
        let limbs = self.check_level(level)?;
        if level == 0 {
            return Err(BgvError::NoLevelLeft);
        }
        Ok(2 * self.scale_down_units(limbs - 1, 1))
    }

    /// Units of one public-key encryption at the top level.
    #[must_use]
    pub fn encryption_units(self) -> u64 {
        let limbs = word(self.profile.top_level()) + 1;
        limbs
            * (self.forward_transform_units()
                + 2 * self.degree()
                + 2 * self.inverse_transform_units()
                + 2 * self.degree())
    }

    /// Units of decrypting a two-component ciphertext at `level`.
    ///
    /// # Errors
    /// [`BgvError::LevelOutOfRange`].
    pub fn decryption_units(self, level: usize) -> Result<u64, BgvError> {
        let limbs = self.check_level(level)?;
        Ok(limbs
            * (self.forward_transform_units() + self.degree() + self.inverse_transform_units())
            + self.conversion_units(limbs, 1))
    }

    /// Words of the largest scratch of one key switch at `level`: two
    /// accumulators, one extended digit and its converted limbs.
    ///
    /// # Errors
    /// [`BgvError::LevelOutOfRange`].
    pub fn key_switch_scratch_words(self, level: usize) -> Result<u64, BgvError> {
        let limbs = self.check_level(level)?;
        let extended = limbs + self.special();
        let smallest_digit = self
            .profile
            .level(level)?
            .digits
            .iter()
            .map(|digit| word(digit.len))
            .min()
            .unwrap_or(0);
        Ok((4 * extended - smallest_digit) * self.degree())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::{BgvCandidate, BgvParameters};

    fn toy() -> BgvProfile {
        BgvProfile::new(BgvParameters::derive(4, 257, (30, 3), (31, 2), 2).expect("parameters"))
            .expect("profile")
    }

    #[test]
    fn kernel_units_follow_their_formulas() {
        let profile = toy();
        let model = CostModel::new(&profile);
        // n = 16: F = 8 * 4.
        assert_eq!(model.forward_transform_units(), 32);
        assert_eq!(model.inverse_transform_units(), 48);
        assert_eq!(model.conversion_units(1, 4), 16 * (1 + 4));
        assert_eq!(model.conversion_units(2, 3), 16 * (2 + 1 + 6));
        assert_eq!(model.scale_down_units(3, 2), 16 * (4 + 1 + 12));
        assert_eq!(model.scale_down_units(1, 1), 16 * (2 + 3));
        assert_eq!(word(7), 7);
    }

    #[test]
    fn sizes_match_the_encoded_objects() {
        let profile = toy();
        let model = CostModel::new(&profile);
        assert_eq!(model.ciphertext_bytes(2, 2), Ok(36 + 16 + 8 * 2 * 3 * 16));
        assert_eq!(
            model.ciphertext_bytes(3, 2),
            Err(BgvError::LevelOutOfRange { level: 3, top: 2 })
        );
        assert_eq!(
            model.ciphertext_bytes(2, 1),
            Err(BgvError::ComponentCount { found: 1 })
        );
        assert_eq!(model.public_key_bytes(), 32 + 8 * 2 * 3 * 16);
        // Two digits, two polynomials, five limbs.
        assert_eq!(model.switching_key_bytes(), 37 + 8 * 2 * 2 * 5 * 16);
        assert_eq!(
            model.evaluation_key_bytes(7),
            8 * model.switching_key_bytes()
        );
        // Sixteen ternary coefficients at two bits each.
        assert_eq!(model.secret_key_bytes(), 32 + 4);
        assert_eq!(model.ciphertext_residue_bytes(2, 2), Ok(8 * 2 * 3 * 16));
        assert_eq!(model.ciphertext_residue_bytes(0, 3), Ok(8 * 3 * 16));
        assert_eq!(
            model.ciphertext_residue_bytes(3, 2),
            Err(BgvError::LevelOutOfRange { level: 3, top: 2 })
        );
        // Every size is the length of the frame the crate actually encodes.
        let keys = crate::bgv::KeySet::generate(&profile, &[3, 5]).expect("keys");
        let length = |bytes: Vec<u8>| word(bytes.len());
        assert_eq!(
            length(keys.public.to_bytes(&profile).expect("frame")),
            model.public_key_bytes()
        );
        assert_eq!(
            length(
                keys.evaluation
                    .relinearization()
                    .to_bytes(&profile)
                    .expect("frame")
            ),
            model.switching_key_bytes()
        );
        assert_eq!(
            length(keys.evaluation.to_bytes(&profile).expect("frame")),
            model.evaluation_key_bytes(2)
        );
        assert_eq!(
            word(keys.secret.to_custody_bytes(&profile).expect("frame").len()),
            model.secret_key_bytes()
        );
        let plaintext = crate::bgv::Plaintext::constant(&profile, 1).expect("plaintext");
        let ciphertext = keys
            .public
            .encrypt(&profile, &plaintext)
            .expect("ciphertext");
        assert_eq!(
            length(ciphertext.to_bytes(&profile).expect("frame")),
            model.ciphertext_bytes(2, 2).expect("size")
        );
    }

    #[test]
    fn operation_units_compose_the_kernel_units() {
        let profile = toy();
        let model = CostModel::new(&profile);
        let (forward, inverse, n) = (32_u64, 48_u64, 16_u64);
        // Level 2: three limbs, digits {q0, q1} and {q2}, two special primes.
        let extended = 5_u64;
        let digit_two = n * (2 + 1 + 3 * 2) + extended * forward + 2 * extended * n;
        let digit_one = n * (1 + 4) + extended * forward + 2 * extended * n;
        let key_switch = digit_two + digit_one + 2 * extended * inverse + 2 * n * (4 + 1 + 3 * 4);
        assert_eq!(model.key_switch_units(2), Ok(key_switch));
        assert_eq!(model.automorphism_units(2), Ok(key_switch));
        let tensor = 3 * (4 * forward + 4 * n + 3 * inverse);
        assert_eq!(model.tensor_units(2), Ok(tensor));
        assert_eq!(model.multiplication_units(2), Ok(tensor + key_switch));
        assert_eq!(
            model.plaintext_multiplication_units(2),
            Ok(3 * (3 * forward + 2 * n + 2 * inverse))
        );
        assert_eq!(model.switch_down_units(2), Ok(2 * n * (2 + 2 * 3)));
        assert_eq!(model.switch_down_units(0), Err(BgvError::NoLevelLeft));
        assert_eq!(
            model.encryption_units(),
            3 * (forward + 2 * n + 2 * inverse + 2 * n)
        );
        assert_eq!(
            model.decryption_units(2),
            Ok(3 * (forward + n + inverse) + n * (3 + 3 + 3))
        );
        // Level 0: one limb, one digit of one prime.
        assert_eq!(
            model.key_switch_units(0),
            Ok(n * (1 + 2) + 3 * forward + 6 * n + 6 * inverse + 2 * n * (4 + 1 + 4))
        );
        assert_eq!(model.key_switch_scratch_words(2), Ok((20 - 1) * n));
        assert_eq!(model.key_switch_scratch_words(1), Ok((16 - 2) * n));
        let out_of_range = Err(BgvError::LevelOutOfRange { level: 3, top: 2 });
        assert_eq!(model.key_switch_units(3), out_of_range);
        assert_eq!(model.tensor_units(3), out_of_range);
        assert_eq!(model.multiplication_units(3), out_of_range);
        assert_eq!(model.plaintext_multiplication_units(3), out_of_range);
        assert_eq!(model.automorphism_units(3), out_of_range);
        assert_eq!(model.switch_down_units(3), out_of_range);
        assert_eq!(model.decryption_units(3), out_of_range);
        assert_eq!(model.key_switch_scratch_words(3), out_of_range);
    }

    #[test]
    fn candidate_sizes_are_the_documented_ones() {
        let affine = BgvProfile::candidate(BgvCandidate::AffineF257).expect("profile");
        let model = CostModel::new(&affine);
        // Two components of six limbs of 2^14 residues: 1.5 MiB plus the frame.
        assert_eq!(
            model.ciphertext_bytes(5, 2),
            Ok(36 + 8 * 5 + 8 * 2 * 6 * 16_384)
        );
        // Three digits, two polynomials, eight limbs: 6 MiB plus the frame.
        assert_eq!(model.switching_key_bytes(), 37 + 8 * 3 * 2 * 8 * 16_384);
        assert_eq!(model.public_key_bytes(), 32 + 8 * 2 * 6 * 16_384);
    }
}
