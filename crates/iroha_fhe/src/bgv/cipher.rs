//! Plaintexts, ciphertexts, encryption, decryption and the canonical encoding.
//!
//! A [`Plaintext`] is a polynomial with canonical coefficients in `[0, t)` in
//! a clearing owner, together with a public bound of its centered norms. A
//! [`Ciphertext`] is two (or, for an unrelinearized product, three) residue
//! polynomials at one level with its public [`NoiseBound`].
//!
//! # Canonical encoding
//!
//! Words: the components in order, each limb-major over `q_0, ..., q_l`, every
//! residue canonical. Bytes ([`Ciphertext::to_bytes`]): the profile identity
//! (32), the level (`u16` little-endian), the component count (`u8`), a zero
//! byte, the noise bound as [`BgvProfile::noise_bound_words`] little-endian
//! words, then every residue as a little-endian `u64`. The length depends only
//! on the profile, the level and the component count. Decoding rejects another
//! identity, a level above the top, a component count other than two or three,
//! a non-zero reserved byte, a noise bound above the level capacity, a
//! non-canonical residue and any other length.
//!
//! The frame is a fixed layout of words. The Norito wire types that carry it,
//! and their bounded admission, belong to the consumers. Key frames are in
//! the keys module.
// TODO(R.11, R.12, C.9): wire types, bounded framing and the proofs that make a
// decoded noise bound valid. Nothing in this module authenticates a frame.
//!
//! The noise bound in a frame is a claim of whoever produced the frame. It is
//! a valid bound only when the frame is authenticated as the output of a
//! well-formed encryption or of admitted operations on such outputs; this
//! module cannot establish that, and the proofs that do belong to the
//! consumers.
use super::{
    BgvError, BgvProfile, CiphertextShape, NoiseBound, PublicKey, SecretKey,
    coins::{EntropySource, OsEntropy, small_residue},
    encryption_witness::EncryptionWitness,
    fault::{self, FaultPoint},
    poly::{RnsPoly, extend_le_bytes, words_from_le_bytes},
};
use crate::{
    constant_time::{FixedModulus, equal_bit_u64, greater_than_bit_u64, select_u64},
    natural::Natural,
    rns_chain::RnsBasis,
};
use zeroize::Zeroizing;

/// Public bounds of the centered coefficients of a plaintext polynomial.
///
/// Noise accounting uses these bounds, never the coefficients. A bound must
/// therefore be derivable from public information: the encoding and the shape
/// of the operand, not its hidden values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PlaintextBound {
    /// Bound of the largest centered magnitude.
    pub linf: u64,
    /// Bound of the sum of centered magnitudes.
    pub l1: u64,
}

/// A plaintext polynomial modulo `t` in a clearing owner.
///
/// Equality compares the coefficients without an early exit: its running
/// time depends on the public profile and bound, not on where two plaintexts
/// differ.
#[derive(Clone)]
pub struct Plaintext {
    identity: [u8; 32],
    /// Canonical coefficients in `[0, t)`.
    coefficients: Zeroizing<Vec<u64>>,
    bound: PlaintextBound,
}

impl PartialEq for Plaintext {
    fn eq(&self, other: &Self) -> bool {
        // The profile, the declared bound and the length are public.
        if self.identity != other.identity
            || self.bound != other.bound
            || self.coefficients.len() != other.coefficients.len()
        {
            return false;
        }
        let difference = self
            .coefficients
            .iter()
            .zip(other.coefficients.iter())
            .fold(0_u64, |difference, (&lhs, &rhs)| difference | (lhs ^ rhs));
        equal_bit_u64(difference, 0) == 1
    }
}

impl Eq for Plaintext {}

impl std::fmt::Debug for Plaintext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Plaintext")
            .field("bound", &self.bound)
            .finish_non_exhaustive()
    }
}

/// Centered magnitude of a canonical coefficient, branch-free.
fn centered_magnitude(coefficient: u64, plaintext_modulus: u64) -> u64 {
    let negative = greater_than_bit_u64(coefficient, (plaintext_modulus - 1) / 2);
    select_u64(coefficient, plaintext_modulus - coefficient, negative)
}

impl Plaintext {
    /// The bound every plaintext of the profile satisfies:
    /// `linf = (t-1)/2`, `l1 = N*(t-1)/2`.
    #[must_use]
    pub fn worst_case_bound(profile: &BgvProfile) -> PlaintextBound {
        let half = (profile.plaintext_modulus() - 1) / 2;
        PlaintextBound {
            linf: half,
            // `N <= 2^17` and `half < 2^30`.
            l1: half * u64::try_from(profile.degree()).unwrap_or(u64::MAX),
        }
    }

    /// The bound of a constant polynomial: `linf = l1 = (t-1)/2`, whatever the constant.
    #[must_use]
    pub fn constant_bound(profile: &BgvProfile) -> PlaintextBound {
        let half = (profile.plaintext_modulus() - 1) / 2;
        PlaintextBound {
            linf: half,
            l1: half,
        }
    }

    fn checked(
        profile: &BgvProfile,
        coefficients: Vec<u64>,
        bound: PlaintextBound,
    ) -> Result<Self, BgvError> {
        let coefficients = Zeroizing::new(coefficients);
        if coefficients.len() != profile.degree() {
            return Err(BgvError::LengthMismatch {
                expected: profile.degree(),
                found: coefficients.len(),
            });
        }
        let plaintext_modulus = profile.plaintext_modulus();
        if let Some(index) = coefficients
            .iter()
            .position(|&coefficient| coefficient >= plaintext_modulus)
        {
            return Err(BgvError::NonCanonical { index });
        }
        Ok(Self {
            identity: *profile.identity(),
            coefficients,
            bound,
        })
    }

    /// A plaintext with the worst-case bound. Takes ownership so the buffer is cleared on drop.
    ///
    /// # Errors
    /// [`BgvError::LengthMismatch`] or [`BgvError::NonCanonical`].
    pub fn new(profile: &BgvProfile, coefficients: Vec<u64>) -> Result<Self, BgvError> {
        Self::checked(profile, coefficients, Self::worst_case_bound(profile))
    }

    /// The constant polynomial `value`, with the bound of every constant.
    ///
    /// # Errors
    /// [`BgvError::NonCanonical`] when `value >= t`.
    pub fn constant(profile: &BgvProfile, value: u64) -> Result<Self, BgvError> {
        let mut coefficients = vec![0_u64; profile.degree()];
        coefficients[0] = value;
        Self::checked(profile, coefficients, Self::constant_bound(profile))
    }

    /// A plaintext with a declared bound, which the coefficients must satisfy.
    ///
    /// The declared bound becomes public through the noise bound of every
    /// result. Declare only what the public shape of the operand implies.
    ///
    /// # Errors
    /// [`BgvError::LengthMismatch`], [`BgvError::NonCanonical`] or
    /// [`BgvError::PlaintextBoundExceeded`].
    pub fn with_public_bound(
        profile: &BgvProfile,
        coefficients: Vec<u64>,
        bound: PlaintextBound,
    ) -> Result<Self, BgvError> {
        let plaintext = Self::checked(profile, coefficients, bound)?;
        let plaintext_modulus = profile.plaintext_modulus();
        let mut linf = 0_u64;
        let mut l1 = 0_u64;
        for &coefficient in plaintext.coefficients.iter() {
            let magnitude = centered_magnitude(coefficient, plaintext_modulus);
            linf = linf.max(magnitude);
            l1 = l1.saturating_add(magnitude);
        }
        if linf > bound.linf || l1 > bound.l1 {
            return Err(BgvError::PlaintextBoundExceeded);
        }
        Ok(plaintext)
    }

    /// Canonical coefficients in `[0, t)`.
    #[must_use]
    pub fn coefficients(&self) -> &[u64] {
        &self.coefficients
    }

    /// The public norm bound.
    #[must_use]
    pub const fn bound(&self) -> PlaintextBound {
        self.bound
    }

    /// The identity of the profile this plaintext belongs to.
    #[must_use]
    pub const fn profile_identity(&self) -> &[u8; 32] {
        &self.identity
    }

    pub(super) fn check_profile(&self, profile: &BgvProfile) -> Result<(), BgvError> {
        if &self.identity == profile.identity() {
            Ok(())
        } else {
            Err(BgvError::ProfileMismatch)
        }
    }

    /// Residues of the centered coefficients over the first `limbs` main primes, coefficient form.
    pub(super) fn centered_residues(&self, profile: &BgvProfile, limbs: usize) -> RnsPoly {
        let plaintext_modulus = profile.plaintext_modulus();
        let half = (plaintext_modulus - 1) / 2;
        let mut poly = RnsPoly::zero(limbs, profile.degree());
        for limb in 0..limbs {
            let prime = profile.main_plan(limb).prime();
            for (slot, &coefficient) in poly.limb_mut(limb).iter_mut().zip(self.coefficients.iter())
            {
                // `coefficient < t < prime`: a value above the half lifts to `coefficient - t`.
                let negative = greater_than_bit_u64(coefficient, half);
                *slot = select_u64(
                    coefficient,
                    coefficient + (prime - plaintext_modulus),
                    negative,
                );
            }
        }
        poly
    }
}

/// A ciphertext at one level with its public noise bound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ciphertext {
    identity: [u8; 32],
    level: usize,
    /// Two or three polynomials over `q_0, ..., q_level` in coefficient form.
    components: Vec<RnsPoly>,
    noise: NoiseBound,
}

/// Bytes of the fixed frame header before the noise bound.
const FRAME_HEADER_BYTES: usize = 32 + 2 + 1 + 1;

impl Ciphertext {
    /// A ciphertext of an admitted shape with its residues.
    pub(super) fn from_shape(
        profile: &BgvProfile,
        shape: CiphertextShape,
        components: Vec<RnsPoly>,
    ) -> Self {
        debug_assert_eq!(shape.components(), components.len());
        Self {
            identity: *profile.identity(),
            level: shape.level(),
            components,
            noise: NoiseBound::new(shape.into_bound()),
        }
    }

    /// The noiseless embedding `(m, 0)` of a plaintext at `level`.
    ///
    /// It hides nothing: use it only for values the evaluator is allowed to
    /// know, such as constants of the function it evaluates.
    ///
    /// # Errors
    /// [`BgvError::ProfileMismatch`], [`BgvError::LevelOutOfRange`] or
    /// [`BgvError::NoiseBudgetExceeded`].
    pub fn trivial(
        profile: &BgvProfile,
        plaintext: &Plaintext,
        level: usize,
    ) -> Result<Self, BgvError> {
        plaintext.check_profile(profile)?;
        let shape = profile.plan_trivial(level)?;
        let c0 = plaintext.centered_residues(profile, level + 1);
        let c1 = RnsPoly::zero(level + 1, profile.degree());
        Ok(Self::from_shape(profile, shape, vec![c0, c1]))
    }

    /// The identity of the profile this ciphertext belongs to.
    #[must_use]
    pub const fn profile_identity(&self) -> &[u8; 32] {
        &self.identity
    }

    /// The level: the index of the last main prime of the modulus.
    #[must_use]
    pub const fn level(&self) -> usize {
        self.level
    }

    /// Number of components: two, or three for an unrelinearized product.
    #[must_use]
    pub fn component_count(&self) -> usize {
        self.components.len()
    }

    /// The public noise bound.
    #[must_use]
    pub const fn noise_bound(&self) -> &NoiseBound {
        &self.noise
    }

    pub(super) fn components(&self) -> &[RnsPoly] {
        &self.components
    }

    pub(super) fn check_profile(&self, profile: &BgvProfile) -> Result<(), BgvError> {
        if &self.identity == profile.identity() {
            Ok(())
        } else {
            Err(BgvError::ProfileMismatch)
        }
    }

    /// Canonical words: the components in order, each limb-major in coefficient form.
    #[must_use]
    pub fn canonical_words(&self) -> Vec<u64> {
        let mut words =
            Vec::with_capacity(self.components.len() * self.components[0].words().len());
        for component in &self.components {
            words.extend_from_slice(component.words());
        }
        words
    }

    /// Rebuild a ciphertext from canonical words and a claimed noise bound.
    ///
    /// The bound is the caller's claim; see the module documentation.
    ///
    /// # Errors
    /// [`BgvError::LevelOutOfRange`], [`BgvError::ComponentCount`],
    /// [`BgvError::LengthMismatch`], [`BgvError::NonCanonical`] or
    /// [`BgvError::NoiseBudgetExceeded`].
    pub fn from_canonical_words(
        profile: &BgvProfile,
        level: usize,
        components: usize,
        words: &[u64],
        noise: &NoiseBound,
    ) -> Result<Self, BgvError> {
        profile.level(level)?;
        if !(2..=3).contains(&components) {
            return Err(BgvError::ComponentCount { found: components });
        }
        let degree = profile.degree();
        let component_words = (level + 1) * degree;
        if words.len() != components * component_words {
            return Err(BgvError::LengthMismatch {
                expected: components * component_words,
                found: words.len(),
            });
        }
        for (index, &word) in words.iter().enumerate() {
            let limb = (index % component_words) / degree;
            if word >= profile.main_plan(limb).prime() {
                return Err(BgvError::NonCanonical { index });
            }
        }
        let polys = words
            .chunks_exact(component_words)
            .map(|chunk| RnsPoly::from_words(chunk.to_vec(), degree))
            .collect::<Result<Vec<_>, _>>()?;
        let shape = profile.plan_claimed(level, components, noise.as_natural().clone())?;
        Ok(Self::from_shape(profile, shape, polys))
    }

    /// Length in bytes of the canonical frame of a ciphertext.
    ///
    /// # Errors
    /// [`BgvError::LevelOutOfRange`] or [`BgvError::ComponentCount`].
    pub fn encoded_len(
        profile: &BgvProfile,
        level: usize,
        components: usize,
    ) -> Result<usize, BgvError> {
        profile.level(level)?;
        if !(2..=3).contains(&components) {
            return Err(BgvError::ComponentCount { found: components });
        }
        Ok(FRAME_HEADER_BYTES
            + 8 * profile.noise_bound_words()
            + 8 * components * (level + 1) * profile.degree())
    }

    /// The canonical byte frame.
    ///
    /// # Errors
    /// [`BgvError::ProfileMismatch`].
    pub fn to_bytes(&self, profile: &BgvProfile) -> Result<Vec<u8>, BgvError> {
        self.check_profile(profile)?;
        let mut bytes = Vec::with_capacity(Self::encoded_len(
            profile,
            self.level,
            self.components.len(),
        )?);
        bytes.extend_from_slice(&self.identity);
        bytes.extend_from_slice(
            &u16::try_from(self.level)
                .map_err(|_| BgvError::Kernel)?
                .to_le_bytes(),
        );
        bytes.push(u8::try_from(self.components.len()).map_err(|_| BgvError::Kernel)?);
        bytes.push(0);
        let noise_words = self.noise.as_natural().words_le();
        for index in 0..profile.noise_bound_words() {
            bytes.extend_from_slice(&noise_words.get(index).copied().unwrap_or(0).to_le_bytes());
        }
        for component in &self.components {
            extend_le_bytes(&mut bytes, component.words());
        }
        Ok(bytes)
    }

    /// Decode a canonical byte frame.
    ///
    /// # Errors
    /// [`BgvError::MalformedFrame`] for a short frame or a non-zero reserved
    /// byte, [`BgvError::ProfileMismatch`], and the errors of
    /// [`Self::from_canonical_words`].
    pub fn from_bytes(profile: &BgvProfile, bytes: &[u8]) -> Result<Self, BgvError> {
        let (header, body) = bytes
            .split_at_checked(FRAME_HEADER_BYTES)
            .ok_or(BgvError::MalformedFrame)?;
        if &header[..32] != profile.identity() {
            return Err(BgvError::ProfileMismatch);
        }
        let level = usize::from(u16::from_le_bytes([header[32], header[33]]));
        let components = usize::from(header[34]);
        if header[35] != 0 {
            return Err(BgvError::MalformedFrame);
        }
        let expected = Self::encoded_len(profile, level, components)?;
        if bytes.len() != expected {
            return Err(BgvError::LengthMismatch {
                expected,
                found: bytes.len(),
            });
        }
        let words = words_from_le_bytes(body);
        let (noise_words, residues) = words.split_at(profile.noise_bound_words());
        Self::from_canonical_words(
            profile,
            level,
            components,
            residues,
            &NoiseBound::new(Natural::from_words_le(noise_words)),
        )
    }
}

impl PublicKey {
    /// Encrypt a plaintext at the top level with operating-system entropy.
    ///
    /// # Errors
    /// [`BgvError::ProfileMismatch`] or [`BgvError::EntropyUnavailable`].
    pub fn encrypt(
        &self,
        profile: &BgvProfile,
        plaintext: &Plaintext,
    ) -> Result<Ciphertext, BgvError> {
        self.encrypt_with(profile, plaintext, &mut OsEntropy)
    }

    pub(super) fn encrypt_with(
        &self,
        profile: &BgvProfile,
        plaintext: &Plaintext,
        entropy: &mut dyn EntropySource,
    ) -> Result<Ciphertext, BgvError> {
        EncryptionWitness::sample(profile, self, plaintext, entropy)?.encrypt()
    }

    /// Encrypt with an explicit ternary mask and explicit errors.
    ///
    /// # Errors
    /// [`BgvError::ProfileMismatch`] or [`BgvError::LengthMismatch`].
    pub(super) fn encrypt_from_coins(
        &self,
        profile: &BgvProfile,
        plaintext: &Plaintext,
        mask: &[i64],
        error0: &[i64],
        error1: &[i64],
    ) -> Result<Ciphertext, BgvError> {
        self.check_profile(profile)?;
        plaintext.check_profile(profile)?;
        let degree = profile.degree();
        for coins in [mask, error0, error1] {
            if coins.len() != degree {
                return Err(BgvError::LengthMismatch {
                    expected: degree,
                    found: coins.len(),
                });
            }
        }
        fault::reached(FaultPoint::EncryptionAfterSampling);
        let level = profile.top_level();
        let limbs = level + 1;
        let plan_of = |limb: usize| profile.main_plan(limb);
        // The mask in evaluation form is secret; it clears when this scope ends.
        let mut mask_evaluation = RnsPoly::zero(limbs, degree);
        for limb in 0..limbs {
            let prime = plan_of(limb).prime();
            for (slot, &coefficient) in mask_evaluation.limb_mut(limb).iter_mut().zip(mask) {
                *slot = small_residue(coefficient, prime);
            }
        }
        mask_evaluation.forward(plan_of)?;
        let (b, a) = self.components();
        let mut c0 = b.clone();
        c0.pointwise_mul_assign(&mask_evaluation, plan_of)?;
        c0.inverse(plan_of)?;
        let mut c1 = a.clone();
        c1.pointwise_mul_assign(&mask_evaluation, plan_of)?;
        c1.inverse(plan_of)?;
        let message = plaintext.centered_residues(profile, limbs);
        let plaintext_modulus = profile.plaintext_modulus();
        for limb in 0..limbs {
            let fixed: FixedModulus = plan_of(limb).fixed();
            let scale = plaintext_modulus % fixed.modulus;
            for ((slot, &error), &message_value) in c0
                .limb_mut(limb)
                .iter_mut()
                .zip(error0)
                .zip(message.limb(limb))
            {
                let scaled = fixed.multiply(small_residue(error, fixed.modulus), scale);
                *slot = fixed.add_canonical(fixed.add_canonical(*slot, scaled), message_value);
            }
            for (slot, &error) in c1.limb_mut(limb).iter_mut().zip(error1) {
                let scaled = fixed.multiply(small_residue(error, fixed.modulus), scale);
                *slot = fixed.add_canonical(*slot, scaled);
            }
        }
        Ok(Ciphertext::from_shape(
            profile,
            profile.plan_fresh()?,
            vec![c0, c1],
        ))
    }
}

impl SecretKey {
    /// Decrypt a ciphertext of two or three components.
    ///
    /// Returns `(c0 + c1*s + c2*s^2 centered modulo Q_l) mod t`. The result is
    /// the plaintext whenever the true noise is within the level capacity,
    /// which the public noise bound guarantees for admitted operations on
    /// well-formed inputs.
    ///
    /// # Errors
    /// [`BgvError::ProfileMismatch`].
    pub fn decrypt(
        &self,
        profile: &BgvProfile,
        ciphertext: &Ciphertext,
    ) -> Result<Plaintext, BgvError> {
        self.check_profile(profile)?;
        ciphertext.check_profile(profile)?;
        let inner = self.inner_product(profile, ciphertext)?;
        fault::reached(FaultPoint::DecryptionAfterInnerProduct);
        let degree = profile.degree();
        let context = profile.level(ciphertext.level())?;
        let mut coefficients = Zeroizing::new(vec![0_u64; degree]);
        let level_basis: &RnsBasis = &context.basis;
        level_basis.convert_centered(
            inner.words(),
            degree,
            std::slice::from_ref(&context.plaintext_target),
            &mut coefficients,
        )?;
        Plaintext::checked(
            profile,
            std::mem::take(&mut *coefficients),
            Plaintext::worst_case_bound(profile),
        )
    }

    /// `c0 + c1*s + c2*s^2` modulo `Q_l` in coefficient form. Secret-dependent.
    pub(super) fn inner_product(
        &self,
        profile: &BgvProfile,
        ciphertext: &Ciphertext,
    ) -> Result<RnsPoly, BgvError> {
        let limbs = ciphertext.level() + 1;
        let plan_of = |limb: usize| profile.main_plan(limb);
        let secret = self.evaluation().prefix(limbs);
        let components = ciphertext.components();
        // Horner in `s`: ((c2*s + c1)*s) in evaluation form, then `+ c0` in coefficient form.
        let mut accumulator = RnsPoly::zero(limbs, profile.degree());
        for component in components.iter().skip(1).rev() {
            let mut evaluation = component.clone();
            evaluation.forward(plan_of)?;
            accumulator.add_assign(&evaluation, plan_of)?;
            accumulator.pointwise_mul_assign(&secret, plan_of)?;
        }
        accumulator.inverse(plan_of)?;
        accumulator.add_assign(&components[0], plan_of)?;
        Ok(accumulator)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::{
        BgvParameters,
        coins::tests::{ScriptedEntropy, seed},
    };

    fn profile() -> BgvProfile {
        BgvProfile::new(BgvParameters::derive(4, 257, (30, 3), (31, 2), 2).expect("parameters"))
            .expect("profile")
    }

    fn entropy(tag: u8) -> ScriptedEntropy {
        ScriptedEntropy {
            results: vec![Some(seed(tag))],
            calls: 0,
        }
    }

    fn keys(profile: &BgvProfile) -> (SecretKey, PublicKey) {
        let secret = SecretKey::generate_with(profile, &mut entropy(1)).expect("secret");
        let public = PublicKey::generate_with(profile, &secret, &mut entropy(2)).expect("public");
        (secret, public)
    }

    fn message(profile: &BgvProfile) -> Vec<u64> {
        (0..profile.degree() as u64)
            .map(|index| (index * 37 + 250) % 257)
            .collect()
    }

    #[test]
    fn plaintext_constructors_validate_and_bound() {
        let profile = profile();
        let worst = Plaintext::worst_case_bound(&profile);
        assert_eq!(
            worst,
            PlaintextBound {
                linf: 128,
                l1: 128 * 16
            }
        );
        assert_eq!(
            Plaintext::constant_bound(&profile),
            PlaintextBound { linf: 128, l1: 128 }
        );
        let plaintext = Plaintext::new(&profile, message(&profile)).expect("plaintext");
        assert_eq!(plaintext.coefficients(), message(&profile));
        assert_eq!(plaintext.bound(), worst);
        assert_eq!(
            format!("{plaintext:?}"),
            format!("Plaintext {{ bound: {worst:?}, .. }}")
        );
        assert_eq!(
            Plaintext::new(&profile, vec![0; 15]).err(),
            Some(BgvError::LengthMismatch {
                expected: 16,
                found: 15
            })
        );
        let mut coefficients = vec![0_u64; 16];
        coefficients[9] = 257;
        assert_eq!(
            Plaintext::new(&profile, coefficients).err(),
            Some(BgvError::NonCanonical { index: 9 })
        );
        let constant = Plaintext::constant(&profile, 256).expect("constant");
        assert_eq!(constant.coefficients()[0], 256);
        assert!(constant.coefficients()[1..].iter().all(|&c| c == 0));
        assert_eq!(constant.bound(), Plaintext::constant_bound(&profile));
        assert_eq!(
            Plaintext::constant(&profile, 257).err(),
            Some(BgvError::NonCanonical { index: 0 })
        );
        // 3 and 255 (= -2) have centered magnitudes 3 and 2.
        let mut small = vec![0_u64; 16];
        small[1] = 3;
        small[7] = 255;
        let tight = PlaintextBound { linf: 3, l1: 5 };
        let bounded =
            Plaintext::with_public_bound(&profile, small.clone(), tight).expect("bounded");
        assert_eq!(bounded.bound(), tight);
        for loose in [
            PlaintextBound { linf: 2, l1: 5 },
            PlaintextBound { linf: 3, l1: 4 },
        ] {
            assert_eq!(
                Plaintext::with_public_bound(&profile, small.clone(), loose).err(),
                Some(BgvError::PlaintextBoundExceeded)
            );
        }
        assert_eq!(centered_magnitude(128, 257), 128);
        assert_eq!(centered_magnitude(129, 257), 128);
        assert_eq!(centered_magnitude(0, 257), 0);
        // Centered residues: 255 lifts to -2 modulo each prime.
        let residues = bounded.centered_residues(&profile, 2);
        for limb in 0..2 {
            let prime = profile.main_plan(limb).prime();
            assert_eq!(residues.limb(limb)[1], 3);
            assert_eq!(residues.limb(limb)[7], prime - 2);
        }
    }

    #[test]
    fn plaintext_equality_covers_profile_bound_and_every_coefficient() {
        let profile = profile();
        let base = Plaintext::new(&profile, message(&profile)).expect("plaintext");
        assert_eq!(base, base.clone());
        // A difference in the first, a middle or the last coefficient.
        for index in [0_usize, 7, 15] {
            let mut coefficients = message(&profile);
            coefficients[index] = (coefficients[index] + 1) % 257;
            assert_ne!(
                Plaintext::new(&profile, coefficients).expect("plaintext"),
                base
            );
        }
        // The same coefficients under another declared bound or another profile differ.
        let constant = Plaintext::constant(&profile, 5).expect("constant");
        let mut coefficients = vec![0_u64; 16];
        coefficients[0] = 5;
        assert_ne!(
            Plaintext::new(&profile, coefficients.clone()).expect("plaintext"),
            constant
        );
        assert_eq!(
            Plaintext::with_public_bound(
                &profile,
                coefficients.clone(),
                Plaintext::constant_bound(&profile)
            )
            .expect("plaintext"),
            constant
        );
        let other = BgvProfile::new(
            BgvParameters::derive(4, 257, (30, 2), (31, 2), 2).expect("parameters"),
        )
        .expect("profile");
        assert_ne!(Plaintext::constant(&other, 5).expect("constant"), constant);
    }

    #[test]
    fn encryption_round_trips_and_carries_the_fresh_bound() {
        let profile = profile();
        let (secret, public) = keys(&profile);
        let plaintext = Plaintext::new(&profile, message(&profile)).expect("plaintext");
        let ciphertext = public
            .encrypt_with(&profile, &plaintext, &mut entropy(3))
            .expect("ciphertext");
        assert_eq!(ciphertext.level(), 2);
        assert_eq!(ciphertext.component_count(), 2);
        assert_eq!(ciphertext.profile_identity(), profile.identity());
        assert_eq!(ciphertext.noise_bound().as_natural(), profile.fresh_noise());
        assert_eq!(
            secret.decrypt(&profile, &ciphertext).expect("plaintext"),
            plaintext
        );
        // Same coins, same ciphertext; fresh entropy, another ciphertext, same plaintext.
        let replay = public
            .encrypt_with(&profile, &plaintext, &mut entropy(3))
            .expect("ciphertext");
        assert_eq!(replay, ciphertext);
        let fresh = public.encrypt(&profile, &plaintext).expect("ciphertext");
        assert_ne!(fresh, ciphertext);
        assert_eq!(
            secret.decrypt(&profile, &fresh).expect("plaintext"),
            plaintext
        );
        // The ciphertext is not the plaintext in the clear.
        assert_ne!(
            &ciphertext.canonical_words()[..16],
            plaintext.coefficients()
        );
    }

    #[test]
    fn encryption_fails_closed_without_entropy_and_validates_coins() {
        let profile = profile();
        let (_, public) = keys(&profile);
        let plaintext = Plaintext::new(&profile, message(&profile)).expect("plaintext");
        let mut failing = ScriptedEntropy {
            results: vec![None],
            calls: 0,
        };
        assert_eq!(
            public
                .encrypt_with(&profile, &plaintext, &mut failing)
                .err(),
            Some(BgvError::EntropyUnavailable)
        );
        let zeros = [0_i64; 16];
        for (mask, error0, error1) in [
            (&zeros[..15], &zeros[..], &zeros[..]),
            (&zeros[..], &zeros[..15], &zeros[..]),
            (&zeros[..], &zeros[..], &zeros[..15]),
        ] {
            assert_eq!(
                public
                    .encrypt_from_coins(&profile, &plaintext, mask, error0, error1)
                    .err(),
                Some(BgvError::LengthMismatch {
                    expected: 16,
                    found: 15
                })
            );
        }
        // With zero coins the ciphertext is the noiseless embedding (m, 0).
        let plain = public
            .encrypt_from_coins(&profile, &plaintext, &zeros, &zeros, &zeros)
            .expect("ciphertext");
        let trivial = Ciphertext::trivial(&profile, &plaintext, 2).expect("trivial");
        assert_eq!(plain.canonical_words(), trivial.canonical_words());
        assert_eq!(trivial.noise_bound().as_natural(), &Natural::from_u64(128));
    }

    #[test]
    fn objects_of_another_profile_are_refused() {
        let profile = profile();
        let other = BgvProfile::new(
            BgvParameters::derive(4, 257, (30, 2), (31, 2), 2).expect("parameters"),
        )
        .expect("profile");
        let (secret, public) = keys(&profile);
        let plaintext = Plaintext::new(&profile, message(&profile)).expect("plaintext");
        let foreign = Plaintext::new(&other, message(&other)).expect("plaintext");
        let ciphertext = public.encrypt(&profile, &plaintext).expect("ciphertext");
        let mismatch = Some(BgvError::ProfileMismatch);
        assert_eq!(public.encrypt(&other, &foreign).err(), mismatch);
        assert_eq!(public.encrypt(&profile, &foreign).err(), mismatch);
        assert_eq!(secret.decrypt(&other, &ciphertext).err(), mismatch);
        assert_eq!(Ciphertext::trivial(&profile, &foreign, 0).err(), mismatch);
        assert_eq!(ciphertext.to_bytes(&other).err(), mismatch);
        let (other_secret, _) = keys(&other);
        assert_eq!(other_secret.decrypt(&profile, &ciphertext).err(), mismatch);
        assert_eq!(
            Ciphertext::trivial(&profile, &plaintext, 3).err(),
            Some(BgvError::LevelOutOfRange { level: 3, top: 2 })
        );
    }

    #[test]
    fn canonical_words_round_trip_and_reject_malformed_input() {
        let profile = profile();
        let (_, public) = keys(&profile);
        let plaintext = Plaintext::new(&profile, message(&profile)).expect("plaintext");
        let ciphertext = public
            .encrypt_with(&profile, &plaintext, &mut entropy(3))
            .expect("ciphertext");
        let words = ciphertext.canonical_words();
        assert_eq!(words.len(), 2 * 3 * 16);
        let rebuilt =
            Ciphertext::from_canonical_words(&profile, 2, 2, &words, ciphertext.noise_bound())
                .expect("rebuilt");
        assert_eq!(rebuilt, ciphertext);
        let bound = || ciphertext.noise_bound().clone();
        assert_eq!(
            Ciphertext::from_canonical_words(&profile, 3, 2, &words, &bound()).err(),
            Some(BgvError::LevelOutOfRange { level: 3, top: 2 })
        );
        for components in [0_usize, 1, 4] {
            assert_eq!(
                Ciphertext::from_canonical_words(&profile, 2, components, &words, &bound()).err(),
                Some(BgvError::ComponentCount { found: components })
            );
        }
        assert_eq!(
            Ciphertext::from_canonical_words(&profile, 2, 2, &words[1..], &bound()).err(),
            Some(BgvError::LengthMismatch {
                expected: 96,
                found: 95
            })
        );
        // A residue equal to its prime is not canonical; the index is that of the word.
        let mut non_canonical = words.clone();
        let index = 48 + 16 + 3;
        non_canonical[index] = profile.main_plan(1).prime();
        assert_eq!(
            Ciphertext::from_canonical_words(&profile, 2, 2, &non_canonical, &bound()).err(),
            Some(BgvError::NonCanonical { index })
        );
        // A claimed bound above the capacity is refused; the capacity itself is accepted.
        let capacity = profile.capacity(2).expect("capacity").clone();
        assert!(
            Ciphertext::from_canonical_words(
                &profile,
                2,
                2,
                &words,
                &NoiseBound::new(capacity.clone())
            )
            .is_ok()
        );
        assert_eq!(
            Ciphertext::from_canonical_words(
                &profile,
                2,
                2,
                &words,
                &NoiseBound::new(capacity.add_u64(1))
            )
            .err(),
            Some(BgvError::NoiseBudgetExceeded { level: 2 })
        );
        // Three components at a lower level use the same layout.
        let smallest = profile.main_plan(0).prime();
        let reduced: Vec<u64> = words.iter().map(|&word| word % smallest).collect();
        let three = Ciphertext::from_canonical_words(&profile, 1, 3, &reduced, &bound())
            .expect("three components");
        assert_eq!(three.component_count(), 3);
        assert_eq!(three.level(), 1);
        assert_eq!(three.canonical_words(), reduced);
    }

    #[test]
    fn byte_frames_round_trip_and_reject_malformed_input() {
        let profile = profile();
        let (_, public) = keys(&profile);
        let plaintext = Plaintext::new(&profile, message(&profile)).expect("plaintext");
        let ciphertext = public.encrypt(&profile, &plaintext).expect("ciphertext");
        let bytes = ciphertext.to_bytes(&profile).expect("bytes");
        // Three 30-bit primes: an 89-bit capacity needs two words.
        assert_eq!(profile.noise_bound_words(), 2);
        let expected_len = 36 + 16 + 8 * 96;
        assert_eq!(bytes.len(), expected_len);
        assert_eq!(Ciphertext::encoded_len(&profile, 2, 2), Ok(expected_len));
        assert_eq!(
            Ciphertext::encoded_len(&profile, 0, 3),
            Ok(36 + 16 + 8 * 48)
        );
        assert_eq!(
            Ciphertext::encoded_len(&profile, 3, 2),
            Err(BgvError::LevelOutOfRange { level: 3, top: 2 })
        );
        assert_eq!(
            Ciphertext::encoded_len(&profile, 2, 4),
            Err(BgvError::ComponentCount { found: 4 })
        );
        assert_eq!(&bytes[..32], profile.identity());
        assert_eq!(&bytes[32..36], &[2, 0, 2, 0]);
        assert_eq!(
            Ciphertext::from_bytes(&profile, &bytes),
            Ok(ciphertext.clone())
        );
        assert_eq!(
            Ciphertext::from_bytes(&profile, &bytes[..35]).err(),
            Some(BgvError::MalformedFrame)
        );
        let mutated = |index: usize, value: u8| {
            let mut copy = bytes.clone();
            copy[index] = value;
            Ciphertext::from_bytes(&profile, &copy).err()
        };
        assert_eq!(mutated(0, bytes[0] ^ 1), Some(BgvError::ProfileMismatch));
        assert_eq!(mutated(35, 1), Some(BgvError::MalformedFrame));
        assert_eq!(
            mutated(32, 3),
            Some(BgvError::LevelOutOfRange { level: 3, top: 2 })
        );
        assert_eq!(mutated(34, 1), Some(BgvError::ComponentCount { found: 1 }));
        // Another valid level or component count implies another length.
        assert_eq!(
            mutated(32, 1),
            Some(BgvError::LengthMismatch {
                expected: 36 + 16 + 8 * 64,
                found: expected_len
            })
        );
        // The top byte of the noise bound set: the claim exceeds the capacity.
        assert_eq!(
            mutated(36 + 15, 0xFF),
            Some(BgvError::NoiseBudgetExceeded { level: 2 })
        );
        // The top byte of the first residue set: not canonical.
        assert_eq!(
            mutated(36 + 16 + 7, 0xFF),
            Some(BgvError::NonCanonical { index: 0 })
        );
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(
            Ciphertext::from_bytes(&profile, &longer).err(),
            Some(BgvError::LengthMismatch {
                expected: expected_len,
                found: expected_len + 1
            })
        );
    }

    #[test]
    fn decryption_evaluates_three_components_at_the_secret() {
        let profile = profile();
        let (secret, _) = keys(&profile);
        // (c0, c1, c2) = (5, 0, 1): c0 + c2*s^2 decrypts to 5 + s^2 mod t.
        let degree = profile.degree();
        let mut words = vec![0_u64; 3 * 2 * degree];
        for limb in 0..2 {
            words[limb * degree] = 5;
            words[2 * 2 * degree + limb * degree] = 1;
        }
        let ciphertext = Ciphertext::from_canonical_words(
            &profile,
            1,
            3,
            &words,
            &NoiseBound::new(Natural::from_u64(1000)),
        )
        .expect("ciphertext");
        let mut expected = vec![0_i64; degree];
        for (i, &lhs) in secret.coefficients().iter().enumerate() {
            for (j, &rhs) in secret.coefficients().iter().enumerate() {
                if i + j >= degree {
                    expected[i + j - degree] -= lhs * rhs;
                } else {
                    expected[i + j] += lhs * rhs;
                }
            }
        }
        expected[0] += 5;
        let expected: Vec<u64> = expected
            .iter()
            .map(|&value| u64::try_from(value.rem_euclid(257)).expect("residue"))
            .collect();
        assert_eq!(
            secret
                .decrypt(&profile, &ciphertext)
                .expect("plaintext")
                .coefficients(),
            expected
        );
    }
}
