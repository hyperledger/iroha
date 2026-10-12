//! Secret, public and switching keys and their canonical encodings.
//!
//! Every key binds the identity of the profile it was generated for. Keys are
//! held in evaluation form; their canonical encoding is coefficient form.
//!
//! - Secret key: ternary `s`.
//! - Public key over the main primes: `(b, a)` with `b = -a*s + t*e`.
//! - Switching key from `s'` to `s` over the main and special primes: one
//!   pair `(b_j, a_j)` per digit `j` with `b_j = -a_j*s + t*e_j + g_j*s'`,
//!   where `g_j` is `P` modulo the main primes of digit `j` and zero modulo
//!   every other prime. `s' = s^2` for relinearization and `s' = s(X^k)` for
//!   the Galois element `k`.
//!
//! The public generators draw operating-system entropy. Generators that take
//! explicit coins are the single implementation behind them and are reachable
//! from outside this module only through [`super::fixtures`].
//!
//! # Canonical encodings
//!
//! Words are canonical residues in coefficient form, limb-major. Bytes are
//! little-endian. Every length depends on the profile only, and every decoder
//! rejects another profile identity, any other length and a residue that is
//! not below its prime.
//!
//! - **Public key** ([`PublicKey::to_bytes`]): the profile identity (32), then
//!   `b` and `a` over the main primes.
//! - **Switching key** ([`SwitchingKey::to_bytes`]): the profile identity (32),
//!   the kind tag (`0` relinearization, `1` Galois), the Galois element as a
//!   `u32` (zero for the relinearization key), then per digit `b_j` and `a_j`
//!   over the main primes followed by the special primes.
//! - **Evaluation keys** ([`EvaluationKeys::to_bytes`]): the switching-key
//!   frame of the relinearization key, then the frames of the Galois keys in
//!   strictly ascending order of their elements.
//! - **Secret key** ([`SecretKey::to_custody_bytes`]): the profile identity
//!   (32), then two bits per coefficient, four coefficients per byte from the
//!   low bits up: `00` is zero, `01` is one, `10` is minus one and `11` is
//!   malformed. The frame is returned in, and accepted from, a clearing
//!   buffer. It is the key in the clear: wrapping it for storage, access
//!   control and the lifetime of every copy belong to the custody owner.
//!
//! A decoded public or switching key is well formed as an encoding only.
//! Whether it satisfies its key equation with a bounded error is not decided
//! here: nothing in this module authenticates a frame.
// TODO(R.11, C.4, C.9): the proofs that a registered public or evaluation key is well
// formed, bounded custody of key frames and the Norito wire types that carry them.
use super::{
    BgvError, BgvProfile,
    coins::{CoinPurpose, Coins, EntropySource, OsEntropy, small_residue},
    fault::{self, FaultPoint},
    poly::{RnsPoly, extend_le_bytes, words_from_le_bytes},
};
use crate::{automorphism, constant_time::FixedModulus, ntt_plan::NegacyclicPlan};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// Bytes of a key frame before anything else: the profile identity.
const KEY_FRAME_IDENTITY_BYTES: usize = 32;
/// Bytes of the kind tag and the Galois element of a switching-key frame.
const SWITCHING_KEY_TAG_BYTES: usize = 5;
/// Kind tag of a relinearization key.
const KIND_TAG_RELINEARIZATION: u8 = 0;
/// Kind tag of a Galois key.
const KIND_TAG_GALOIS: u8 = 1;
/// Ternary coefficients one byte of a secret-key custody frame holds.
const CUSTODY_COEFFICIENTS_PER_BYTE: usize = 4;

/// Decode `count` polynomials of `limbs` limbs from canonical coefficient-form
/// words into evaluation form; limb `i` uses `plan_of(i)`.
///
/// # Errors
/// [`BgvError::LengthMismatch`] or [`BgvError::NonCanonical`] with the index of
/// the first residue that is not below its prime.
fn decode_polys<'plan>(
    words: &[u64],
    count: usize,
    limbs: usize,
    degree: usize,
    plan_of: impl Fn(usize) -> &'plan NegacyclicPlan,
) -> Result<Vec<RnsPoly>, BgvError> {
    let poly_words = limbs * degree;
    if words.len() != count * poly_words {
        return Err(BgvError::LengthMismatch {
            expected: count * poly_words,
            found: words.len(),
        });
    }
    for (index, &word) in words.iter().enumerate() {
        if word >= plan_of((index % poly_words) / degree).prime() {
            return Err(BgvError::NonCanonical { index });
        }
    }
    let mut polys = Vec::with_capacity(count);
    for chunk in words.chunks_exact(poly_words) {
        let mut poly = RnsPoly::from_words(chunk.to_vec(), degree)?;
        poly.forward(&plan_of)?;
        polys.push(poly);
    }
    Ok(polys)
}

/// Split a key frame into its identity-checked body.
///
/// # Errors
/// [`BgvError::LengthMismatch`] for any length other than `expected` and
/// [`BgvError::ProfileMismatch`] for another identity.
fn frame_body<'frame>(
    profile: &BgvProfile,
    bytes: &'frame [u8],
    expected: usize,
) -> Result<&'frame [u8], BgvError> {
    if bytes.len() != expected {
        return Err(BgvError::LengthMismatch {
            expected,
            found: bytes.len(),
        });
    }
    let (identity, body) = bytes
        .split_at_checked(KEY_FRAME_IDENTITY_BYTES)
        .ok_or(BgvError::MalformedFrame)?;
    if identity != profile.identity() {
        return Err(BgvError::ProfileMismatch);
    }
    Ok(body)
}

/// The ternary secret key. Its buffers clear on drop.
pub struct SecretKey {
    identity: [u8; 32],
    /// Coefficients in `{-1, 0, 1}`.
    coefficients: Zeroizing<Vec<i64>>,
    /// Evaluation form over the main primes followed by the special primes.
    evaluation: RnsPoly,
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecretKey")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

/// Small signed coefficients as residues of every listed transform, in evaluation form.
fn small_to_evaluation(
    profile: &BgvProfile,
    coefficients: &[i64],
    limbs: usize,
) -> Result<RnsPoly, BgvError> {
    let mut poly = RnsPoly::zero(limbs, profile.degree());
    for limb in 0..limbs {
        let plan = profile.full_plan(limb);
        for (slot, &coefficient) in poly.limb_mut(limb).iter_mut().zip(coefficients) {
            *slot = small_residue(coefficient, plan.prime());
        }
    }
    poly.forward(|limb| profile.full_plan(limb))?;
    Ok(poly)
}

impl SecretKey {
    /// Generate a secret key from operating-system entropy.
    ///
    /// # Errors
    /// [`BgvError::EntropyUnavailable`].
    pub fn generate(profile: &BgvProfile) -> Result<Self, BgvError> {
        Self::generate_with(profile, &mut OsEntropy)
    }

    pub(super) fn generate_with(
        profile: &BgvProfile,
        entropy: &mut dyn EntropySource,
    ) -> Result<Self, BgvError> {
        let mut coins = Coins::draw(entropy)?;
        let mut coefficients = Zeroizing::new(vec![0_i64; profile.degree()]);
        coins
            .stream(profile.identity(), CoinPurpose::SecretKey, 0, 0)
            .ternary(&mut coefficients);
        Self::from_coefficients(profile, coefficients)
    }

    /// Build the key of explicit ternary coefficients.
    ///
    /// # Errors
    /// [`BgvError::LengthMismatch`] or [`BgvError::NonCanonical`] for a
    /// coefficient outside `{-1, 0, 1}`.
    pub(super) fn from_coefficients(
        profile: &BgvProfile,
        coefficients: Zeroizing<Vec<i64>>,
    ) -> Result<Self, BgvError> {
        if coefficients.len() != profile.degree() {
            return Err(BgvError::LengthMismatch {
                expected: profile.degree(),
                found: coefficients.len(),
            });
        }
        // Reports only the position of a malformed fixture coefficient.
        if let Some(index) = coefficients
            .iter()
            .position(|coefficient| !(-1..=1).contains(coefficient))
        {
            return Err(BgvError::NonCanonical { index });
        }
        let evaluation = small_to_evaluation(profile, &coefficients, profile.full_limbs())?;
        fault::reached(FaultPoint::SecretKeyAfterSampling);
        Ok(Self {
            identity: *profile.identity(),
            coefficients,
            evaluation,
        })
    }

    /// The identity of the profile this key belongs to.
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

    /// Length in bytes of the custody frame of a secret key of `profile`.
    #[must_use]
    pub fn custody_len(profile: &BgvProfile) -> usize {
        KEY_FRAME_IDENTITY_BYTES + profile.degree() / CUSTODY_COEFFICIENTS_PER_BYTE
    }

    /// The custody frame: the key in the clear, in a buffer that clears on drop.
    ///
    /// The layout is in the module documentation. Encoding is branch-free in
    /// the coefficients.
    ///
    /// # Errors
    /// [`BgvError::ProfileMismatch`].
    pub fn to_custody_bytes(&self, profile: &BgvProfile) -> Result<Zeroizing<Vec<u8>>, BgvError> {
        self.check_profile(profile)?;
        // Allocated once at its final size, so no intermediate copy of the frame exists.
        let mut bytes = Zeroizing::new(vec![0_u8; Self::custody_len(profile)]);
        let (identity, body) = bytes.split_at_mut(KEY_FRAME_IDENTITY_BYTES);
        identity.copy_from_slice(&self.identity);
        for (byte, group) in body
            .iter_mut()
            .zip(self.coefficients.chunks(CUSTODY_COEFFICIENTS_PER_BYTE))
        {
            for (position, &coefficient) in group.iter().enumerate() {
                // -1, 0, 1 as two's-complement low bits are 11, 00, 01; fold 11 to 10.
                let low = coefficient.cast_unsigned() & 3;
                let code = low - (low >> 1);
                *byte |= u8::try_from(code << (2 * position)).unwrap_or(0);
            }
        }
        Ok(bytes)
    }

    /// Rebuild a secret key from its custody frame.
    ///
    /// Takes the clearing buffer by value: the caller's copy of the frame is
    /// cleared when this function returns, whatever the outcome. Decoding is
    /// branch-free in the coefficients and reports a malformed code without
    /// its position.
    ///
    /// # Errors
    /// [`BgvError::LengthMismatch`], [`BgvError::ProfileMismatch`] or
    /// [`BgvError::MalformedFrame`] for the code `11`.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "owning the clearing buffer clears the caller's copy of the frame on every exit"
    )]
    pub fn from_custody_bytes(
        profile: &BgvProfile,
        bytes: Zeroizing<Vec<u8>>,
    ) -> Result<Self, BgvError> {
        let body = frame_body(profile, &bytes, Self::custody_len(profile))?;
        let mut coefficients = Zeroizing::new(vec![0_i64; profile.degree()]);
        let mut malformed = 0_u8;
        for (&byte, group) in body
            .iter()
            .zip(coefficients.chunks_mut(CUSTODY_COEFFICIENTS_PER_BYTE))
        {
            for (position, coefficient) in group.iter_mut().enumerate() {
                let code = (byte >> (2 * position)) & 3;
                let one = code & 1;
                let minus_one = code >> 1;
                malformed |= one & minus_one;
                *coefficient = i64::from(one) - i64::from(minus_one);
            }
        }
        if malformed != 0 {
            return Err(BgvError::MalformedFrame);
        }
        Self::from_coefficients(profile, coefficients)
    }

    /// Evaluation form over the main primes followed by the special primes.
    pub(super) const fn evaluation(&self) -> &RnsPoly {
        &self.evaluation
    }

    /// The ternary coefficients.
    pub(super) fn coefficients(&self) -> &[i64] {
        &self.coefficients
    }
}

/// The public encryption key `(b, a)` with `b = -a*s + t*e` modulo the main primes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    identity: [u8; 32],
    /// Evaluation form over the main primes.
    b: RnsPoly,
    /// Evaluation form over the main primes.
    a: RnsPoly,
}

impl PublicKey {
    /// Generate the public key of `secret` from operating-system entropy.
    ///
    /// # Errors
    /// [`BgvError::ProfileMismatch`] or [`BgvError::EntropyUnavailable`].
    pub fn generate(profile: &BgvProfile, secret: &SecretKey) -> Result<Self, BgvError> {
        Self::generate_with(profile, secret, &mut OsEntropy)
    }

    pub(super) fn generate_with(
        profile: &BgvProfile,
        secret: &SecretKey,
        entropy: &mut dyn EntropySource,
    ) -> Result<Self, BgvError> {
        secret.check_profile(profile)?;
        let mut coins = Coins::draw(entropy)?;
        let degree = profile.degree();
        let main = &profile.parameters().main_primes;
        let mut mask = RnsPoly::zero(main.len(), degree);
        coins
            .stream(profile.identity(), CoinPurpose::PublicKeyMask, 0, 0)
            .uniform(main, degree, mask.words_mut());
        let mut error = Zeroizing::new(vec![0_i64; degree]);
        coins
            .stream(profile.identity(), CoinPurpose::PublicKeyError, 0, 0)
            .centered_binomial(profile.parameters().error_eta, &mut error);
        Self::from_coins(profile, secret, mask, &error)
    }

    /// Build the key from an explicit mask (coefficient form) and error.
    ///
    /// # Errors
    /// [`BgvError::ProfileMismatch`] or [`BgvError::LengthMismatch`].
    pub(super) fn from_coins(
        profile: &BgvProfile,
        secret: &SecretKey,
        mask: RnsPoly,
        error: &[i64],
    ) -> Result<Self, BgvError> {
        secret.check_profile(profile)?;
        let main_limbs = profile.top_level() + 1;
        check_coin_shape(profile, &mask, main_limbs, error)?;
        fault::reached(FaultPoint::PublicKeyAfterSampling);
        let mut a = mask;
        a.forward(|limb| profile.main_plan(limb))?;
        let b = masked_error(profile, secret, &a, error, main_limbs)?;
        Ok(Self {
            identity: *profile.identity(),
            b,
            a,
        })
    }

    /// The identity of the profile this key belongs to.
    #[must_use]
    pub const fn profile_identity(&self) -> &[u8; 32] {
        &self.identity
    }

    /// Canonical encoding: `b` then `a` in coefficient form, limb-major over the main primes.
    ///
    /// # Errors
    /// [`BgvError::ProfileMismatch`].
    pub fn canonical_words(&self, profile: &BgvProfile) -> Result<Vec<u64>, BgvError> {
        self.check_profile(profile)?;
        let mut words = Vec::with_capacity(2 * self.b.words().len());
        for component in [&self.b, &self.a] {
            let mut coefficient = component.clone();
            coefficient.inverse(|limb| profile.main_plan(limb))?;
            words.extend_from_slice(coefficient.words());
        }
        Ok(words)
    }

    /// Rebuild a public key from its canonical words.
    ///
    /// The result is well formed as an encoding only; see the module
    /// documentation.
    ///
    /// # Errors
    /// [`BgvError::LengthMismatch`] or [`BgvError::NonCanonical`].
    pub fn from_canonical_words(profile: &BgvProfile, words: &[u64]) -> Result<Self, BgvError> {
        let mut polys = decode_polys(
            words,
            2,
            profile.top_level() + 1,
            profile.degree(),
            |limb| profile.main_plan(limb),
        )?;
        let a = polys.pop().ok_or(BgvError::Kernel)?;
        let b = polys.pop().ok_or(BgvError::Kernel)?;
        Ok(Self {
            identity: *profile.identity(),
            b,
            a,
        })
    }

    /// Length in bytes of the canonical frame of a public key of `profile`.
    #[must_use]
    pub fn encoded_len(profile: &BgvProfile) -> usize {
        KEY_FRAME_IDENTITY_BYTES + 8 * 2 * (profile.top_level() + 1) * profile.degree()
    }

    /// The canonical byte frame.
    ///
    /// # Errors
    /// [`BgvError::ProfileMismatch`].
    pub fn to_bytes(&self, profile: &BgvProfile) -> Result<Vec<u8>, BgvError> {
        let words = self.canonical_words(profile)?;
        let mut bytes = Vec::with_capacity(Self::encoded_len(profile));
        bytes.extend_from_slice(&self.identity);
        extend_le_bytes(&mut bytes, &words);
        Ok(bytes)
    }

    /// Decode a canonical byte frame.
    ///
    /// # Errors
    /// [`BgvError::LengthMismatch`], [`BgvError::ProfileMismatch`] or
    /// [`BgvError::NonCanonical`].
    pub fn from_bytes(profile: &BgvProfile, bytes: &[u8]) -> Result<Self, BgvError> {
        let body = frame_body(profile, bytes, Self::encoded_len(profile))?;
        Self::from_canonical_words(profile, &words_from_le_bytes(body))
    }

    pub(super) fn check_profile(&self, profile: &BgvProfile) -> Result<(), BgvError> {
        if &self.identity == profile.identity() {
            Ok(())
        } else {
            Err(BgvError::ProfileMismatch)
        }
    }

    /// `(b, a)` in evaluation form.
    pub(super) const fn components(&self) -> (&RnsPoly, &RnsPoly) {
        (&self.b, &self.a)
    }
}

fn check_coin_shape(
    profile: &BgvProfile,
    mask: &RnsPoly,
    limbs: usize,
    error: &[i64],
) -> Result<(), BgvError> {
    let degree = profile.degree();
    if mask.words().len() != limbs * degree {
        return Err(BgvError::LengthMismatch {
            expected: limbs * degree,
            found: mask.words().len(),
        });
    }
    if error.len() != degree {
        return Err(BgvError::LengthMismatch {
            expected: degree,
            found: error.len(),
        });
    }
    Ok(())
}

/// `-a*s + t*e` in evaluation form over the first `limbs` limbs of the full basis.
fn masked_error(
    profile: &BgvProfile,
    secret: &SecretKey,
    mask_evaluation: &RnsPoly,
    error: &[i64],
    limbs: usize,
) -> Result<RnsPoly, BgvError> {
    // The scratch holds `t*e` and then `-a*s + t*e`, both secret-dependent until returned.
    let mut output = small_to_evaluation(profile, error, limbs)?;
    let plaintext = profile.plaintext_modulus();
    for limb in 0..limbs {
        let fixed: FixedModulus = profile.full_plan(limb).fixed();
        let scale = plaintext % fixed.modulus;
        let secret_limb = secret.evaluation().limb(limb);
        for ((slot, &mask_value), &secret_value) in output
            .limb_mut(limb)
            .iter_mut()
            .zip(mask_evaluation.limb(limb))
            .zip(secret_limb)
        {
            *slot = fixed.sub_canonical(
                fixed.multiply(*slot, scale),
                fixed.multiply(mask_value, secret_value),
            );
        }
    }
    Ok(output)
}

/// What a switching key switches from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SwitchingKeyKind {
    /// From `s^2`: relinearizes a tensor product.
    Relinearization,
    /// From `s(X^k)`: completes the automorphism with Galois element `k`.
    Galois(u32),
}

impl SwitchingKeyKind {
    /// The `key_tag` of the coin-stream derivation: zero, or the Galois element.
    #[must_use]
    pub const fn coin_tag(self) -> u32 {
        match self {
            Self::Relinearization => 0,
            Self::Galois(element) => element,
        }
    }

    /// The kind tag and the element field of a switching-key frame.
    const fn frame_tag(self) -> (u8, u32) {
        match self {
            Self::Relinearization => (KIND_TAG_RELINEARIZATION, 0),
            Self::Galois(element) => (KIND_TAG_GALOIS, element),
        }
    }

    /// The kind a frame declares, validated against the profile.
    ///
    /// # Errors
    /// [`BgvError::MalformedFrame`] for an unknown tag or a relinearization
    /// frame with a non-zero element field, and
    /// [`BgvError::InvalidGaloisElement`].
    fn from_frame_tag(profile: &BgvProfile, tag: u8, element: u32) -> Result<Self, BgvError> {
        match (tag, element) {
            (KIND_TAG_RELINEARIZATION, 0) => Ok(Self::Relinearization),
            (KIND_TAG_GALOIS, element) => {
                galois_power(profile, element)?;
                Ok(Self::Galois(element))
            }
            _ => Err(BgvError::MalformedFrame),
        }
    }
}

/// A hybrid RNS switching key: one pair per digit over the main and special primes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwitchingKey {
    identity: [u8; 32],
    kind: SwitchingKeyKind,
    /// `(b_j, a_j)` in evaluation form over the main primes followed by the special primes.
    digits: Vec<(RnsPoly, RnsPoly)>,
}

/// Validate a Galois element: an odd unit of `Z / 2N` other than one.
pub(super) fn galois_power(profile: &BgvProfile, element: u32) -> Result<usize, BgvError> {
    if element <= 1 {
        return Err(BgvError::InvalidGaloisElement);
    }
    automorphism::validate_power(profile.degree(), element)
        .map_err(|_| BgvError::InvalidGaloisElement)
}

/// The image of small signed coefficients under `X -> X^power`.
fn small_automorphism(coefficients: &[i64], power: usize) -> Zeroizing<Vec<i64>> {
    let degree = coefficients.len();
    let mut output = Zeroizing::new(vec![0_i64; degree]);
    for (index, &coefficient) in coefficients.iter().enumerate() {
        let exponent = (index * power) % (2 * degree);
        if exponent >= degree {
            output[exponent - degree] = -coefficient;
        } else {
            output[exponent] = coefficient;
        }
    }
    output
}

impl SwitchingKey {
    /// Generate the relinearization key of `secret` from operating-system entropy.
    ///
    /// # Errors
    /// [`BgvError::ProfileMismatch`] or [`BgvError::EntropyUnavailable`].
    pub fn generate_relinearization(
        profile: &BgvProfile,
        secret: &SecretKey,
    ) -> Result<Self, BgvError> {
        Self::generate_with(
            profile,
            secret,
            SwitchingKeyKind::Relinearization,
            &mut OsEntropy,
        )
    }

    /// Generate the Galois key of `secret` for `element` from operating-system entropy.
    ///
    /// # Errors
    /// [`BgvError::InvalidGaloisElement`], [`BgvError::ProfileMismatch`] or
    /// [`BgvError::EntropyUnavailable`].
    pub fn generate_galois(
        profile: &BgvProfile,
        secret: &SecretKey,
        element: u32,
    ) -> Result<Self, BgvError> {
        Self::generate_with(
            profile,
            secret,
            SwitchingKeyKind::Galois(element),
            &mut OsEntropy,
        )
    }

    pub(super) fn generate_with(
        profile: &BgvProfile,
        secret: &SecretKey,
        kind: SwitchingKeyKind,
        entropy: &mut dyn EntropySource,
    ) -> Result<Self, BgvError> {
        secret.check_profile(profile)?;
        if let SwitchingKeyKind::Galois(element) = kind {
            galois_power(profile, element)?;
        }
        let mut seeded = Coins::draw(entropy)?;
        let degree = profile.degree();
        let moduli: Vec<u64> = (0..profile.full_limbs())
            .map(|limb| profile.full_plan(limb).prime())
            .collect();
        let mut coins = Vec::with_capacity(profile.digit_count());
        for digit in 0..profile.digit_count() {
            let digit_tag = u32::try_from(digit).map_err(|_| BgvError::Kernel)?;
            let mut mask = RnsPoly::zero(moduli.len(), degree);
            seeded
                .stream(
                    profile.identity(),
                    CoinPurpose::SwitchingKeyMask,
                    kind.coin_tag(),
                    digit_tag,
                )
                .uniform(&moduli, degree, mask.words_mut());
            let mut error = Zeroizing::new(vec![0_i64; degree]);
            seeded
                .stream(
                    profile.identity(),
                    CoinPurpose::SwitchingKeyError,
                    kind.coin_tag(),
                    digit_tag,
                )
                .centered_binomial(profile.parameters().error_eta, &mut error);
            coins.push((mask, error));
        }
        Self::from_coins(profile, secret, kind, coins)
    }

    /// Build the key from one explicit mask (coefficient form) and error per digit.
    ///
    /// # Errors
    /// [`BgvError::ProfileMismatch`], [`BgvError::InvalidGaloisElement`] or
    /// [`BgvError::LengthMismatch`].
    pub(super) fn from_coins(
        profile: &BgvProfile,
        secret: &SecretKey,
        kind: SwitchingKeyKind,
        coins: Vec<(RnsPoly, Zeroizing<Vec<i64>>)>,
    ) -> Result<Self, BgvError> {
        secret.check_profile(profile)?;
        if coins.len() != profile.digit_count() {
            return Err(BgvError::LengthMismatch {
                expected: profile.digit_count(),
                found: coins.len(),
            });
        }
        let limbs = profile.full_limbs();
        let source = match kind {
            SwitchingKeyKind::Relinearization => {
                let mut square = secret.evaluation().clone();
                square.pointwise_mul_assign(secret.evaluation(), |limb| profile.full_plan(limb))?;
                square
            }
            SwitchingKeyKind::Galois(element) => {
                let power = galois_power(profile, element)?;
                let image = small_automorphism(secret.coefficients(), power);
                small_to_evaluation(profile, &image, limbs)?
            }
        };
        let digit_primes = profile.parameters().digit_primes;
        let main_limbs = profile.top_level() + 1;
        let mut digits = Vec::with_capacity(coins.len());
        for (digit, (mask, error)) in coins.into_iter().enumerate() {
            check_coin_shape(profile, &mask, limbs, &error)?;
            let mut a = mask;
            a.forward(|limb| profile.full_plan(limb))?;
            let mut b = masked_error(profile, secret, &a, &error, limbs)?;
            let first = digit * digit_primes;
            for limb in first..(first + digit_primes).min(main_limbs) {
                let fixed: FixedModulus = profile.full_plan(limb).fixed();
                let gadget = profile.special_product_mod_main(limb);
                for (slot, &source_value) in b.limb_mut(limb).iter_mut().zip(source.limb(limb)) {
                    *slot = fixed.add_canonical(*slot, fixed.multiply(source_value, gadget));
                }
            }
            digits.push((b, a));
            if digit == 0 {
                fault::reached(FaultPoint::SwitchingKeyAfterFirstDigit);
            }
        }
        Ok(Self {
            identity: *profile.identity(),
            kind,
            digits,
        })
    }

    /// What this key switches from.
    #[must_use]
    pub const fn kind(&self) -> SwitchingKeyKind {
        self.kind
    }

    /// The identity of the profile this key belongs to.
    #[must_use]
    pub const fn profile_identity(&self) -> &[u8; 32] {
        &self.identity
    }

    /// Canonical encoding: per digit `b_j` then `a_j` in coefficient form,
    /// limb-major over the main primes followed by the special primes.
    ///
    /// # Errors
    /// [`BgvError::ProfileMismatch`].
    pub fn canonical_words(&self, profile: &BgvProfile) -> Result<Vec<u64>, BgvError> {
        self.check_profile(profile)?;
        let mut words = Vec::new();
        for (b, a) in &self.digits {
            for component in [b, a] {
                let mut coefficient = component.clone();
                coefficient.inverse(|limb| profile.full_plan(limb))?;
                words.extend_from_slice(coefficient.words());
            }
        }
        Ok(words)
    }

    /// Rebuild a switching key of `kind` from its canonical words.
    ///
    /// The result is well formed as an encoding only; see the module
    /// documentation.
    ///
    /// # Errors
    /// [`BgvError::InvalidGaloisElement`], [`BgvError::LengthMismatch`] or
    /// [`BgvError::NonCanonical`].
    pub fn from_canonical_words(
        profile: &BgvProfile,
        kind: SwitchingKeyKind,
        words: &[u64],
    ) -> Result<Self, BgvError> {
        if let SwitchingKeyKind::Galois(element) = kind {
            galois_power(profile, element)?;
        }
        let mut polys = decode_polys(
            words,
            2 * profile.digit_count(),
            profile.full_limbs(),
            profile.degree(),
            |limb| profile.full_plan(limb),
        )?
        .into_iter();
        let mut digits = Vec::with_capacity(profile.digit_count());
        while let (Some(b), Some(a)) = (polys.next(), polys.next()) {
            digits.push((b, a));
        }
        Ok(Self {
            identity: *profile.identity(),
            kind,
            digits,
        })
    }

    /// Length in bytes of the canonical frame of a switching key of `profile`.
    #[must_use]
    pub fn encoded_len(profile: &BgvProfile) -> usize {
        KEY_FRAME_IDENTITY_BYTES
            + SWITCHING_KEY_TAG_BYTES
            + 8 * profile.digit_count() * 2 * profile.full_limbs() * profile.degree()
    }

    /// The canonical byte frame.
    ///
    /// # Errors
    /// [`BgvError::ProfileMismatch`].
    pub fn to_bytes(&self, profile: &BgvProfile) -> Result<Vec<u8>, BgvError> {
        let mut bytes = Vec::with_capacity(Self::encoded_len(profile));
        self.append_frame(profile, &mut bytes)?;
        Ok(bytes)
    }

    /// Append the canonical byte frame to `bytes`.
    fn append_frame(&self, profile: &BgvProfile, bytes: &mut Vec<u8>) -> Result<(), BgvError> {
        let words = self.canonical_words(profile)?;
        let (tag, element) = self.kind.frame_tag();
        bytes.extend_from_slice(&self.identity);
        bytes.push(tag);
        bytes.extend_from_slice(&element.to_le_bytes());
        extend_le_bytes(bytes, &words);
        Ok(())
    }

    /// Decode a canonical byte frame.
    ///
    /// # Errors
    /// [`BgvError::LengthMismatch`], [`BgvError::ProfileMismatch`],
    /// [`BgvError::MalformedFrame`] for an unknown kind tag or a
    /// relinearization frame with a non-zero element field,
    /// [`BgvError::InvalidGaloisElement`] or [`BgvError::NonCanonical`].
    pub fn from_bytes(profile: &BgvProfile, bytes: &[u8]) -> Result<Self, BgvError> {
        let body = frame_body(profile, bytes, Self::encoded_len(profile))?;
        let (tag, residues) = body
            .split_at_checked(SWITCHING_KEY_TAG_BYTES)
            .ok_or(BgvError::MalformedFrame)?;
        let element = u32::from_le_bytes([tag[1], tag[2], tag[3], tag[4]]);
        let kind = SwitchingKeyKind::from_frame_tag(profile, tag[0], element)?;
        Self::from_canonical_words(profile, kind, &words_from_le_bytes(residues))
    }

    pub(super) fn check_profile(&self, profile: &BgvProfile) -> Result<(), BgvError> {
        if &self.identity == profile.identity() {
            Ok(())
        } else {
            Err(BgvError::ProfileMismatch)
        }
    }

    /// `(b_j, a_j)` of digit `digit` in evaluation form.
    pub(super) fn digit(&self, digit: usize) -> Option<&(RnsPoly, RnsPoly)> {
        self.digits.get(digit)
    }
}

/// The public evaluation keys: one relinearization key and any number of Galois keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvaluationKeys {
    relinearization: SwitchingKey,
    galois: BTreeMap<u32, SwitchingKey>,
}

impl EvaluationKeys {
    /// Generate the relinearization key and one Galois key per element.
    ///
    /// Every key draws its own operating-system entropy. A repeated element is
    /// generated once.
    ///
    /// # Errors
    /// [`BgvError::InvalidGaloisElement`], [`BgvError::ProfileMismatch`] or
    /// [`BgvError::EntropyUnavailable`].
    pub fn generate(
        profile: &BgvProfile,
        secret: &SecretKey,
        galois_elements: &[u32],
    ) -> Result<Self, BgvError> {
        Self::generate_with(profile, secret, galois_elements, &mut OsEntropy)
    }

    pub(super) fn generate_with(
        profile: &BgvProfile,
        secret: &SecretKey,
        galois_elements: &[u32],
        entropy: &mut dyn EntropySource,
    ) -> Result<Self, BgvError> {
        for &element in galois_elements {
            galois_power(profile, element)?;
        }
        let relinearization = SwitchingKey::generate_with(
            profile,
            secret,
            SwitchingKeyKind::Relinearization,
            entropy,
        )?;
        let mut galois = BTreeMap::new();
        for &element in galois_elements {
            if let std::collections::btree_map::Entry::Vacant(slot) = galois.entry(element) {
                slot.insert(SwitchingKey::generate_with(
                    profile,
                    secret,
                    SwitchingKeyKind::Galois(element),
                    entropy,
                )?);
            }
        }
        Ok(Self {
            relinearization,
            galois,
        })
    }

    /// Assemble evaluation keys from a relinearization key and Galois keys.
    ///
    /// # Errors
    /// [`BgvError::ProfileMismatch`], and [`BgvError::WrongSwitchingKey`] when
    /// `relinearization` is a Galois key, a key of `galois` is not one, or two
    /// keys of `galois` have the same element.
    pub fn from_keys(
        profile: &BgvProfile,
        relinearization: SwitchingKey,
        galois: impl IntoIterator<Item = SwitchingKey>,
    ) -> Result<Self, BgvError> {
        relinearization.check_profile(profile)?;
        if relinearization.kind() != SwitchingKeyKind::Relinearization {
            return Err(BgvError::WrongSwitchingKey);
        }
        let mut by_element = BTreeMap::new();
        for key in galois {
            key.check_profile(profile)?;
            let SwitchingKeyKind::Galois(element) = key.kind() else {
                return Err(BgvError::WrongSwitchingKey);
            };
            if by_element.insert(element, key).is_some() {
                return Err(BgvError::WrongSwitchingKey);
            }
        }
        Ok(Self {
            relinearization,
            galois: by_element,
        })
    }

    /// Length in bytes of the canonical frame of evaluation keys with `galois_keys` Galois keys.
    #[must_use]
    pub fn encoded_len(profile: &BgvProfile, galois_keys: usize) -> usize {
        (galois_keys + 1) * SwitchingKey::encoded_len(profile)
    }

    /// The canonical byte frame: the relinearization key, then the Galois keys
    /// in ascending order of their elements.
    ///
    /// # Errors
    /// [`BgvError::ProfileMismatch`].
    pub fn to_bytes(&self, profile: &BgvProfile) -> Result<Vec<u8>, BgvError> {
        let mut bytes = Vec::with_capacity(Self::encoded_len(profile, self.galois.len()));
        self.relinearization.append_frame(profile, &mut bytes)?;
        for key in self.galois.values() {
            key.append_frame(profile, &mut bytes)?;
        }
        Ok(bytes)
    }

    /// Decode a canonical byte frame.
    ///
    /// The number of Galois keys follows from the length. A caller that
    /// accepts frames from outside bounds that length first.
    ///
    /// # Errors
    /// [`BgvError::LengthMismatch`] when the length is not a positive multiple
    /// of the switching-key frame, [`BgvError::WrongSwitchingKey`] when the
    /// first frame is not the relinearization key or a later one is not a
    /// Galois key, [`BgvError::MalformedFrame`] when the Galois elements are
    /// not strictly ascending, and the errors of [`SwitchingKey::from_bytes`].
    pub fn from_bytes(profile: &BgvProfile, bytes: &[u8]) -> Result<Self, BgvError> {
        let frame = SwitchingKey::encoded_len(profile);
        if bytes.is_empty() || !bytes.len().is_multiple_of(frame) {
            return Err(BgvError::LengthMismatch {
                expected: frame,
                found: bytes.len(),
            });
        }
        let mut frames = bytes.chunks_exact(frame);
        let relinearization =
            SwitchingKey::from_bytes(profile, frames.next().ok_or(BgvError::MalformedFrame)?)?;
        if relinearization.kind() != SwitchingKeyKind::Relinearization {
            return Err(BgvError::WrongSwitchingKey);
        }
        let mut galois = BTreeMap::new();
        let mut previous = None;
        for chunk in frames {
            let key = SwitchingKey::from_bytes(profile, chunk)?;
            let SwitchingKeyKind::Galois(element) = key.kind() else {
                return Err(BgvError::WrongSwitchingKey);
            };
            if previous.is_some_and(|earlier| earlier >= element) {
                return Err(BgvError::MalformedFrame);
            }
            previous = Some(element);
            galois.insert(element, key);
        }
        Ok(Self {
            relinearization,
            galois,
        })
    }

    /// The relinearization key.
    #[must_use]
    pub const fn relinearization(&self) -> &SwitchingKey {
        &self.relinearization
    }

    /// The Galois key for `element`, when one was generated.
    #[must_use]
    pub fn galois(&self, element: u32) -> Option<&SwitchingKey> {
        self.galois.get(&element)
    }

    /// The Galois elements with a key, ascending.
    #[must_use]
    pub fn galois_elements(&self) -> Vec<u32> {
        self.galois.keys().copied().collect()
    }
}

/// A secret key with its public and evaluation keys.
#[derive(Debug)]
pub struct KeySet {
    /// The secret key.
    pub secret: SecretKey,
    /// The public encryption key.
    pub public: PublicKey,
    /// The public evaluation keys.
    pub evaluation: EvaluationKeys,
}

impl KeySet {
    /// Generate a complete key set from operating-system entropy.
    ///
    /// Draws one seed for the secret key, one for the public key and one per
    /// switching key. When any draw fails nothing is returned and the secret
    /// key generated so far is cleared.
    ///
    /// # Errors
    /// [`BgvError::InvalidGaloisElement`] or [`BgvError::EntropyUnavailable`].
    pub fn generate(profile: &BgvProfile, galois_elements: &[u32]) -> Result<Self, BgvError> {
        Self::generate_with(profile, galois_elements, &mut OsEntropy)
    }

    pub(super) fn generate_with(
        profile: &BgvProfile,
        galois_elements: &[u32],
        entropy: &mut dyn EntropySource,
    ) -> Result<Self, BgvError> {
        for &element in galois_elements {
            galois_power(profile, element)?;
        }
        let secret = SecretKey::generate_with(profile, entropy)?;
        let public = PublicKey::generate_with(profile, &secret, entropy)?;
        let evaluation = EvaluationKeys::generate_with(profile, &secret, galois_elements, entropy)?;
        Ok(Self {
            secret,
            public,
            evaluation,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::{
        BgvParameters,
        coins::tests::{ScriptedEntropy, seed},
    };
    use crate::modular;

    fn profile() -> BgvProfile {
        BgvProfile::new(BgvParameters::derive(4, 257, (30, 3), (31, 2), 2).expect("parameters"))
            .expect("profile")
    }

    fn entropy(count: u8) -> ScriptedEntropy {
        ScriptedEntropy {
            results: (0..count).map(|tag| Some(seed(tag + 1))).collect(),
            calls: 0,
        }
    }

    /// Coefficient form of one evaluation-form limb.
    fn coefficients(profile: &BgvProfile, poly: &RnsPoly, limb: usize) -> Vec<u64> {
        let mut values = poly.limb(limb).to_vec();
        profile
            .full_plan(limb)
            .inverse(&mut values)
            .expect("inverse");
        values
    }

    /// Schoolbook negacyclic product modulo one prime.
    fn product(lhs: &[u64], rhs: &[u64], prime: u64) -> Vec<u64> {
        crate::polynomial::negacyclic_mul_mod_schoolbook(lhs, rhs, lhs.len(), prime)
    }

    fn secret_residues(secret: &SecretKey, prime: u64) -> Vec<u64> {
        secret
            .coefficients()
            .iter()
            .map(|&coefficient| modular::reduce_i128_to_u64_mod(i128::from(coefficient), prime))
            .collect()
    }

    /// Centered value of a residue.
    fn centered(value: u64, prime: u64) -> i128 {
        crate::rounding::center_lift(value, prime)
    }

    #[test]
    fn secret_key_is_ternary_and_bound_to_its_profile() {
        let profile = profile();
        let secret = SecretKey::generate_with(&profile, &mut entropy(1)).expect("secret");
        assert_eq!(secret.profile_identity(), profile.identity());
        assert_eq!(secret.coefficients().len(), 16);
        assert!(secret.coefficients().iter().all(|c| (-1..=1).contains(c)));
        for limb in 0..profile.full_limbs() {
            let prime = profile.full_plan(limb).prime();
            assert_eq!(
                coefficients(&profile, secret.evaluation(), limb),
                secret_residues(&secret, prime)
            );
        }
        assert_eq!(secret.check_profile(&profile), Ok(()));
        let other = BgvProfile::new(
            BgvParameters::derive(4, 257, (30, 2), (31, 2), 2).expect("parameters"),
        )
        .expect("profile");
        assert_eq!(secret.check_profile(&other), Err(BgvError::ProfileMismatch));
        // The debug form never prints key material.
        let debug = format!("{secret:?}");
        assert!(debug.starts_with("SecretKey { identity: ["));
        assert!(!debug.contains("coefficients"));
        // Operating-system entropy produces a different key each time.
        let first = SecretKey::generate(&profile).expect("secret");
        let second = SecretKey::generate(&profile).expect("secret");
        assert_ne!(first.coefficients(), second.coefficients());
    }

    #[test]
    fn explicit_secret_coefficients_are_validated() {
        let profile = profile();
        assert_eq!(
            SecretKey::from_coefficients(&profile, Zeroizing::new(vec![0; 15])).err(),
            Some(BgvError::LengthMismatch {
                expected: 16,
                found: 15
            })
        );
        let mut coefficients = vec![0_i64; 16];
        coefficients[5] = 2;
        assert_eq!(
            SecretKey::from_coefficients(&profile, Zeroizing::new(coefficients)).err(),
            Some(BgvError::NonCanonical { index: 5 })
        );
    }

    #[test]
    fn public_key_satisfies_its_equation_with_a_bounded_error() {
        let profile = profile();
        let secret = SecretKey::generate_with(&profile, &mut entropy(1)).expect("secret");
        let public = PublicKey::generate_with(&profile, &secret, &mut entropy(2)).expect("public");
        assert_eq!(public.profile_identity(), profile.identity());
        let (b, a) = public.components();
        let words = public.canonical_words(&profile).expect("words");
        assert_eq!(words.len(), 2 * 3 * 16);
        let mut errors: Option<Vec<i128>> = None;
        for limb in 0..3 {
            let prime = profile.main_plan(limb).prime();
            let b_coefficients = coefficients(&profile, b, limb);
            let a_coefficients = coefficients(&profile, a, limb);
            assert_eq!(&words[limb * 16..(limb + 1) * 16], b_coefficients);
            assert_eq!(&words[(3 + limb) * 16..(4 + limb) * 16], a_coefficients);
            // b + a*s = t*e with |e| <= 21, the same e in every limb.
            let a_s = product(&a_coefficients, &secret_residues(&secret, prime), prime);
            let t_inverse = modular::mod_inv_prime_u64(257, prime).expect("inverse");
            let error: Vec<i128> = b_coefficients
                .iter()
                .zip(&a_s)
                .map(|(&b_value, &a_s_value)| {
                    let scaled = modular::add_mod_u64(b_value, a_s_value, prime);
                    centered(modular::mul_mod_u64(scaled, t_inverse, prime), prime)
                })
                .collect();
            assert!(error.iter().all(|value| value.abs() <= 21));
            assert!(error.iter().any(|&value| value != 0));
            if let Some(previous) = &errors {
                assert_eq!(previous, &error);
            }
            errors = Some(error);
        }
        // The same seed gives the same key; another seed gives another.
        let replay = PublicKey::generate_with(&profile, &secret, &mut entropy(2)).expect("public");
        assert_eq!(public, replay);
        let mut other_seed = ScriptedEntropy {
            results: vec![Some(seed(9))],
            calls: 0,
        };
        let other = PublicKey::generate_with(&profile, &secret, &mut other_seed).expect("public");
        assert_ne!(public, other);
        assert!(PublicKey::generate(&profile, &secret).is_ok());
    }

    /// Check `b_j + a_j*s = t*e_j + g_j*s'` for every digit and limb.
    fn check_switching_key(
        profile: &BgvProfile,
        secret: &SecretKey,
        key: &SwitchingKey,
        source: &[i64],
    ) {
        let main_limbs = profile.top_level() + 1;
        let digit_primes = profile.parameters().digit_primes;
        for digit in 0..profile.digit_count() {
            let (b, a) = key.digit(digit).expect("digit");
            let mut errors: Option<Vec<i128>> = None;
            for limb in 0..profile.full_limbs() {
                let prime = profile.full_plan(limb).prime();
                let s = secret_residues(secret, prime);
                let source_residues: Vec<u64> = source
                    .iter()
                    .map(|&value| modular::reduce_i128_to_u64_mod(i128::from(value), prime))
                    .collect();
                let in_digit = limb < main_limbs
                    && (digit * digit_primes..(digit + 1) * digit_primes).contains(&limb);
                let gadget = if in_digit {
                    profile.special_product_mod_main(limb)
                } else {
                    0
                };
                let a_s = product(&coefficients(profile, a, limb), &s, prime);
                let t_inverse = modular::mod_inv_prime_u64(257, prime).expect("inverse");
                let error: Vec<i128> = coefficients(profile, b, limb)
                    .iter()
                    .zip(&a_s)
                    .zip(&source_residues)
                    .map(|((&b_value, &a_s_value), &source_value)| {
                        let without_gadget = modular::sub_mod_u64(
                            modular::add_mod_u64(b_value, a_s_value, prime),
                            modular::mul_mod_u64(gadget, source_value, prime),
                            prime,
                        );
                        centered(
                            modular::mul_mod_u64(without_gadget, t_inverse, prime),
                            prime,
                        )
                    })
                    .collect();
                assert!(
                    error.iter().all(|value| value.abs() <= 21),
                    "digit {digit} limb {limb}"
                );
                if let Some(previous) = &errors {
                    assert_eq!(previous, &error, "digit {digit} limb {limb}");
                }
                errors = Some(error);
            }
        }
        assert!(key.digit(profile.digit_count()).is_none());
    }

    /// `s^2` and `s(X^k)` as small integer polynomials.
    fn square(secret: &[i64]) -> Vec<i64> {
        let degree = secret.len();
        let mut output = vec![0_i64; degree];
        for (i, &lhs) in secret.iter().enumerate() {
            for (j, &rhs) in secret.iter().enumerate() {
                if i + j >= degree {
                    output[i + j - degree] -= lhs * rhs;
                } else {
                    output[i + j] += lhs * rhs;
                }
            }
        }
        output
    }

    #[test]
    fn switching_keys_satisfy_their_equations() {
        let profile = profile();
        let secret = SecretKey::generate_with(&profile, &mut entropy(1)).expect("secret");
        let relinearization = SwitchingKey::generate_with(
            &profile,
            &secret,
            SwitchingKeyKind::Relinearization,
            &mut entropy(2),
        )
        .expect("relinearization");
        assert_eq!(relinearization.kind(), SwitchingKeyKind::Relinearization);
        assert_eq!(relinearization.profile_identity(), profile.identity());
        check_switching_key(
            &profile,
            &secret,
            &relinearization,
            &square(secret.coefficients()),
        );
        for element in [3_u32, 5, 31] {
            let key = SwitchingKey::generate_with(
                &profile,
                &secret,
                SwitchingKeyKind::Galois(element),
                &mut entropy(2),
            )
            .expect("galois");
            assert_eq!(key.kind(), SwitchingKeyKind::Galois(element));
            let image = small_automorphism(secret.coefficients(), element as usize);
            check_switching_key(&profile, &secret, &key, &image);
            // The Galois element separates the coin streams of two keys from one seed.
            assert_ne!(
                key.digit(0).expect("digit").1,
                relinearization.digit(0).expect("digit").1
            );
        }
        let words = relinearization.canonical_words(&profile).expect("words");
        assert_eq!(words.len(), 2 * 2 * 5 * 16);
        let (b, _) = relinearization.digit(0).expect("digit");
        assert_eq!(&words[..16], coefficients(&profile, b, 0));
        assert!(SwitchingKey::generate_relinearization(&profile, &secret).is_ok());
        assert!(SwitchingKey::generate_galois(&profile, &secret, 5).is_ok());
    }

    #[test]
    fn galois_elements_and_coin_shapes_are_validated() {
        let profile = profile();
        let secret = SecretKey::generate_with(&profile, &mut entropy(1)).expect("secret");
        for element in [0_u32, 1, 2, 32, 33, 64] {
            assert_eq!(
                galois_power(&profile, element),
                Err(BgvError::InvalidGaloisElement),
                "element {element}"
            );
            assert_eq!(
                SwitchingKey::generate_galois(&profile, &secret, element).err(),
                Some(BgvError::InvalidGaloisElement)
            );
        }
        assert_eq!(galois_power(&profile, 31), Ok(31));
        assert_eq!(SwitchingKeyKind::Relinearization.coin_tag(), 0);
        assert_eq!(SwitchingKeyKind::Galois(5).coin_tag(), 5);
        assert_eq!(
            small_automorphism(&[1, -1, 0, 1], 3).as_slice(),
            // X -> X^3 in degree 4: 1 - X^3 + X^9 = 1 - X^3 + X (X^8 = 1).
            &[1, 1, 0, -1]
        );
        let mask = || RnsPoly::zero(5, 16);
        let error = || Zeroizing::new(vec![0_i64; 16]);
        assert_eq!(
            SwitchingKey::from_coins(
                &profile,
                &secret,
                SwitchingKeyKind::Relinearization,
                vec![(mask(), error())]
            )
            .err(),
            Some(BgvError::LengthMismatch {
                expected: 2,
                found: 1
            })
        );
        assert_eq!(
            SwitchingKey::from_coins(
                &profile,
                &secret,
                SwitchingKeyKind::Relinearization,
                vec![(RnsPoly::zero(4, 16), error()), (mask(), error())]
            )
            .err(),
            Some(BgvError::LengthMismatch {
                expected: 80,
                found: 64
            })
        );
        assert_eq!(
            SwitchingKey::from_coins(
                &profile,
                &secret,
                SwitchingKeyKind::Relinearization,
                vec![(mask(), Zeroizing::new(vec![0; 3])), (mask(), error())]
            )
            .err(),
            Some(BgvError::LengthMismatch {
                expected: 16,
                found: 3
            })
        );
        assert_eq!(
            PublicKey::from_coins(&profile, &secret, RnsPoly::zero(5, 16), &[0; 16]).err(),
            Some(BgvError::LengthMismatch {
                expected: 48,
                found: 80
            })
        );
        assert_eq!(check_coin_shape(&profile, &mask(), 5, &[0; 16]), Ok(()));
    }

    #[test]
    fn keys_of_another_profile_are_refused() {
        let profile = profile();
        let other = BgvProfile::new(
            BgvParameters::derive(4, 257, (30, 2), (31, 2), 2).expect("parameters"),
        )
        .expect("profile");
        let secret = SecretKey::generate_with(&profile, &mut entropy(1)).expect("secret");
        assert_eq!(
            PublicKey::generate(&other, &secret).err(),
            Some(BgvError::ProfileMismatch)
        );
        assert_eq!(
            SwitchingKey::generate_relinearization(&other, &secret).err(),
            Some(BgvError::ProfileMismatch)
        );
        let public = PublicKey::generate(&profile, &secret).expect("public");
        assert_eq!(
            public.canonical_words(&other).err(),
            Some(BgvError::ProfileMismatch)
        );
        let key = SwitchingKey::generate_relinearization(&profile, &secret).expect("key");
        assert_eq!(
            key.canonical_words(&other).err(),
            Some(BgvError::ProfileMismatch)
        );
        assert_eq!(key.check_profile(&profile), Ok(()));
        assert_eq!(public.check_profile(&profile), Ok(()));
    }

    #[test]
    fn public_key_words_and_frames_round_trip_and_reject_malformed_input() {
        let profile = profile();
        let secret = SecretKey::generate_with(&profile, &mut entropy(1)).expect("secret");
        let public = PublicKey::generate_with(&profile, &secret, &mut entropy(2)).expect("public");
        let words = public.canonical_words(&profile).expect("words");
        assert_eq!(
            PublicKey::from_canonical_words(&profile, &words),
            Ok(public.clone())
        );
        let bytes = public.to_bytes(&profile).expect("bytes");
        assert_eq!(bytes.len(), PublicKey::encoded_len(&profile));
        assert_eq!(bytes.len(), 32 + 8 * 2 * 3 * 16);
        assert_eq!(&bytes[..32], profile.identity());
        assert_eq!(&bytes[32..40], &words[0].to_le_bytes());
        assert_eq!(PublicKey::from_bytes(&profile, &bytes), Ok(public.clone()));
        // Any other length, another identity and a non-canonical residue are refused.
        assert_eq!(
            PublicKey::from_canonical_words(&profile, &words[1..]).err(),
            Some(BgvError::LengthMismatch {
                expected: 96,
                found: 95
            })
        );
        // Word 48 + 16 + 3 is coefficient 3 of the second limb of `a`.
        let mut non_canonical = words.clone();
        let index = 48 + 16 + 3;
        non_canonical[index] = profile.main_plan(1).prime();
        assert_eq!(
            PublicKey::from_canonical_words(&profile, &non_canonical).err(),
            Some(BgvError::NonCanonical { index })
        );
        non_canonical[index] -= 1;
        assert!(PublicKey::from_canonical_words(&profile, &non_canonical).is_ok());
        for length in [0, 31, bytes.len() - 1] {
            assert_eq!(
                PublicKey::from_bytes(&profile, &bytes[..length]).err(),
                Some(BgvError::LengthMismatch {
                    expected: bytes.len(),
                    found: length
                })
            );
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(matches!(
            PublicKey::from_bytes(&profile, &longer),
            Err(BgvError::LengthMismatch { .. })
        ));
        let mut foreign = bytes.clone();
        foreign[0] ^= 1;
        assert_eq!(
            PublicKey::from_bytes(&profile, &foreign).err(),
            Some(BgvError::ProfileMismatch)
        );
        let mut high = bytes.clone();
        high[32 + 7] = 0xFF;
        assert_eq!(
            PublicKey::from_bytes(&profile, &high).err(),
            Some(BgvError::NonCanonical { index: 0 })
        );
        let other = BgvProfile::new(
            BgvParameters::derive(4, 257, (30, 2), (31, 2), 2).expect("parameters"),
        )
        .expect("profile");
        assert_eq!(
            public.to_bytes(&other).err(),
            Some(BgvError::ProfileMismatch)
        );
        assert!(PublicKey::from_bytes(&other, &bytes).is_err());
    }

    #[test]
    fn switching_key_words_and_frames_round_trip_and_reject_malformed_input() {
        let profile = profile();
        let secret = SecretKey::generate_with(&profile, &mut entropy(1)).expect("secret");
        let frame_len = SwitchingKey::encoded_len(&profile);
        assert_eq!(frame_len, 37 + 8 * 2 * 2 * 5 * 16);
        for kind in [
            SwitchingKeyKind::Relinearization,
            SwitchingKeyKind::Galois(5),
        ] {
            let key =
                SwitchingKey::generate_with(&profile, &secret, kind, &mut entropy(2)).expect("key");
            let words = key.canonical_words(&profile).expect("words");
            assert_eq!(
                SwitchingKey::from_canonical_words(&profile, kind, &words),
                Ok(key.clone())
            );
            let bytes = key.to_bytes(&profile).expect("bytes");
            assert_eq!(bytes.len(), frame_len);
            assert_eq!(&bytes[..32], profile.identity());
            let (tag, element) = kind.frame_tag();
            assert_eq!(bytes[32], tag);
            assert_eq!(&bytes[33..37], &element.to_le_bytes());
            assert_eq!(&bytes[37..45], &words[0].to_le_bytes());
            assert_eq!(SwitchingKey::from_bytes(&profile, &bytes), Ok(key.clone()));
            // The same residues under another kind are another key.
            let other_kind = SwitchingKeyKind::Galois(31);
            assert_ne!(
                SwitchingKey::from_canonical_words(&profile, other_kind, &words).expect("key"),
                key
            );
            assert_eq!(
                SwitchingKey::from_canonical_words(&profile, kind, &words[..words.len() - 1]).err(),
                Some(BgvError::LengthMismatch {
                    expected: 320,
                    found: 319
                })
            );
            // Word 80 + 4 * 16 is the first coefficient of the first special limb of `a_0`.
            let mut non_canonical = words.clone();
            let index = 80 + 4 * 16;
            non_canonical[index] = profile.full_plan(4).prime();
            assert_eq!(
                SwitchingKey::from_canonical_words(&profile, kind, &non_canonical).err(),
                Some(BgvError::NonCanonical { index })
            );
            assert_eq!(
                SwitchingKey::from_bytes(&profile, &bytes[..frame_len - 1]).err(),
                Some(BgvError::LengthMismatch {
                    expected: frame_len,
                    found: frame_len - 1
                })
            );
            let mut foreign = bytes.clone();
            foreign[31] ^= 0x80;
            assert_eq!(
                SwitchingKey::from_bytes(&profile, &foreign).err(),
                Some(BgvError::ProfileMismatch)
            );
            let mut unknown = bytes.clone();
            unknown[32] = 2;
            assert_eq!(
                SwitchingKey::from_bytes(&profile, &unknown).err(),
                Some(BgvError::MalformedFrame)
            );
        }
        assert_eq!(
            SwitchingKey::from_canonical_words(&profile, SwitchingKeyKind::Galois(4), &[]).err(),
            Some(BgvError::InvalidGaloisElement)
        );
        // Frame tags: a relinearization frame carries a zero element, a Galois frame a unit.
        assert_eq!(SwitchingKeyKind::Relinearization.frame_tag(), (0, 0));
        assert_eq!(SwitchingKeyKind::Galois(5).frame_tag(), (1, 5));
        assert_eq!(
            SwitchingKeyKind::from_frame_tag(&profile, 0, 0),
            Ok(SwitchingKeyKind::Relinearization)
        );
        assert_eq!(
            SwitchingKeyKind::from_frame_tag(&profile, 1, 31),
            Ok(SwitchingKeyKind::Galois(31))
        );
        assert_eq!(
            SwitchingKeyKind::from_frame_tag(&profile, 0, 5),
            Err(BgvError::MalformedFrame)
        );
        assert_eq!(
            SwitchingKeyKind::from_frame_tag(&profile, 1, 4),
            Err(BgvError::InvalidGaloisElement)
        );
        assert_eq!(
            SwitchingKeyKind::from_frame_tag(&profile, 1, 1),
            Err(BgvError::InvalidGaloisElement)
        );
        assert_eq!(
            SwitchingKeyKind::from_frame_tag(&profile, 7, 0),
            Err(BgvError::MalformedFrame)
        );
        let relinearization =
            SwitchingKey::generate_relinearization(&profile, &secret).expect("key");
        let mut bytes = relinearization.to_bytes(&profile).expect("bytes");
        bytes[33] = 5;
        assert_eq!(
            SwitchingKey::from_bytes(&profile, &bytes).err(),
            Some(BgvError::MalformedFrame)
        );
    }

    #[test]
    fn evaluation_keys_assemble_from_keys_and_frames() {
        let profile = profile();
        let secret = SecretKey::generate_with(&profile, &mut entropy(1)).expect("secret");
        let keys = EvaluationKeys::generate_with(&profile, &secret, &[31, 5], &mut entropy(3))
            .expect("keys");
        let relinearization = keys.relinearization().clone();
        let galois = |element: u32| keys.galois(element).expect("key").clone();
        // Order of the supplied Galois keys does not matter.
        assert_eq!(
            EvaluationKeys::from_keys(&profile, relinearization.clone(), [galois(31), galois(5)]),
            Ok(keys.clone())
        );
        assert_eq!(
            EvaluationKeys::from_keys(&profile, relinearization.clone(), [])
                .expect("keys")
                .galois_elements(),
            Vec::<u32>::new()
        );
        let wrong = Some(BgvError::WrongSwitchingKey);
        assert_eq!(
            EvaluationKeys::from_keys(&profile, galois(5), []).err(),
            wrong
        );
        assert_eq!(
            EvaluationKeys::from_keys(&profile, relinearization.clone(), [relinearization.clone()])
                .err(),
            wrong
        );
        assert_eq!(
            EvaluationKeys::from_keys(&profile, relinearization.clone(), [galois(5), galois(5)])
                .err(),
            wrong
        );
        let other = BgvProfile::new(
            BgvParameters::derive(4, 257, (30, 2), (31, 2), 2).expect("parameters"),
        )
        .expect("profile");
        assert_eq!(
            EvaluationKeys::from_keys(&other, relinearization.clone(), []).err(),
            Some(BgvError::ProfileMismatch)
        );
        let other_secret = SecretKey::generate(&other).expect("secret");
        let foreign = SwitchingKey::generate_galois(&other, &other_secret, 5).expect("key");
        assert_eq!(
            EvaluationKeys::from_keys(&profile, relinearization.clone(), [foreign]).err(),
            Some(BgvError::ProfileMismatch)
        );
        // The frame is the relinearization frame followed by the Galois frames, ascending.
        let frame = SwitchingKey::encoded_len(&profile);
        let bytes = keys.to_bytes(&profile).expect("bytes");
        assert_eq!(bytes.len(), EvaluationKeys::encoded_len(&profile, 2));
        assert_eq!(bytes.len(), 3 * frame);
        assert_eq!(
            &bytes[..frame],
            relinearization.to_bytes(&profile).expect("frame")
        );
        assert_eq!(
            &bytes[frame..2 * frame],
            galois(5).to_bytes(&profile).expect("frame")
        );
        assert_eq!(
            &bytes[2 * frame..],
            galois(31).to_bytes(&profile).expect("frame")
        );
        assert_eq!(
            EvaluationKeys::from_bytes(&profile, &bytes),
            Ok(keys.clone())
        );
        assert_eq!(
            EvaluationKeys::from_bytes(&profile, &bytes[..frame])
                .expect("keys")
                .galois_elements(),
            Vec::<u32>::new()
        );
        for length in [0, frame - 1, frame + 1] {
            assert_eq!(
                EvaluationKeys::from_bytes(&profile, &bytes[..length]).err(),
                Some(BgvError::LengthMismatch {
                    expected: frame,
                    found: length
                })
            );
        }
        // A Galois key first, a relinearization key later, and unsorted or repeated elements.
        let reordered = |order: [usize; 3]| -> Vec<u8> {
            order
                .iter()
                .flat_map(|&index| bytes[index * frame..(index + 1) * frame].to_vec())
                .collect()
        };
        assert_eq!(
            EvaluationKeys::from_bytes(&profile, &reordered([1, 0, 2])).err(),
            wrong
        );
        assert_eq!(
            EvaluationKeys::from_bytes(&profile, &reordered([0, 0, 2])).err(),
            wrong
        );
        assert_eq!(
            EvaluationKeys::from_bytes(&profile, &reordered([0, 2, 1])).err(),
            Some(BgvError::MalformedFrame)
        );
        assert_eq!(
            EvaluationKeys::from_bytes(&profile, &reordered([0, 1, 1])).err(),
            Some(BgvError::MalformedFrame)
        );
        assert_eq!(keys.to_bytes(&other).err(), Some(BgvError::ProfileMismatch));
    }

    #[test]
    fn secret_key_custody_frame_round_trips_and_rejects_malformed_input() {
        let profile = profile();
        // Every coefficient value in every position of a byte.
        let coefficients: Vec<i64> = [1, -1, 0, 0, -1, 1, 1, 1, 0, 0, 0, -1, -1, -1, 1, 0].to_vec();
        let secret = SecretKey::from_coefficients(&profile, Zeroizing::new(coefficients.clone()))
            .expect("secret");
        let frame = secret.to_custody_bytes(&profile).expect("frame");
        assert_eq!(frame.len(), SecretKey::custody_len(&profile));
        assert_eq!(frame.len(), 32 + 4);
        assert_eq!(&frame[..32], profile.identity());
        // 00 zero, 01 one, 10 minus one; four coefficients per byte from the low bits up.
        assert_eq!(
            &frame[32..],
            &[0b00_00_10_01, 0b01_01_01_10, 0b10_00_00_00, 0b00_01_10_10]
        );
        let restored = SecretKey::from_custody_bytes(&profile, frame.clone()).expect("secret");
        assert_eq!(restored.coefficients(), coefficients);
        assert_eq!(restored.evaluation(), secret.evaluation());
        assert_eq!(restored.profile_identity(), profile.identity());
        // A generated key survives the round trip.
        let generated = SecretKey::generate_with(&profile, &mut entropy(1)).expect("secret");
        let again = SecretKey::from_custody_bytes(
            &profile,
            generated.to_custody_bytes(&profile).expect("frame"),
        )
        .expect("secret");
        assert_eq!(again.coefficients(), generated.coefficients());
        // The code 11 is malformed in every position, and its position is not reported.
        for byte in 32..36 {
            for position in 0..4 {
                let mut malformed = frame.clone();
                malformed[byte] |= 3 << (2 * position);
                assert_eq!(
                    SecretKey::from_custody_bytes(&profile, malformed).err(),
                    Some(BgvError::MalformedFrame)
                );
            }
        }
        for length in [0, 35, 37] {
            let mut resized = frame.clone();
            resized.resize(length, 0);
            assert_eq!(
                SecretKey::from_custody_bytes(&profile, resized).err(),
                Some(BgvError::LengthMismatch {
                    expected: 36,
                    found: length
                })
            );
        }
        let mut foreign = frame.clone();
        foreign[5] ^= 1;
        assert_eq!(
            SecretKey::from_custody_bytes(&profile, foreign).err(),
            Some(BgvError::ProfileMismatch)
        );
        let other = BgvProfile::new(
            BgvParameters::derive(4, 257, (30, 2), (31, 2), 2).expect("parameters"),
        )
        .expect("profile");
        assert_eq!(
            secret.to_custody_bytes(&other).err(),
            Some(BgvError::ProfileMismatch)
        );
    }

    #[test]
    fn keys_rebuilt_from_frames_encrypt_evaluate_and_decrypt() {
        // Five primes leave room for one multiplication.
        let profile = BgvProfile::new(
            BgvParameters::derive(4, 257, (30, 5), (31, 2), 2).expect("parameters"),
        )
        .expect("profile");
        let (secret_frame, public_frame, evaluation_frame) = {
            let keys = KeySet::generate_with(&profile, &[5], &mut entropy(7)).expect("keys");
            (
                keys.secret.to_custody_bytes(&profile).expect("frame"),
                keys.public.to_bytes(&profile).expect("frame"),
                keys.evaluation.to_bytes(&profile).expect("frame"),
            )
        };
        // Only bytes cross this line, as between two processes.
        let secret = SecretKey::from_custody_bytes(&profile, secret_frame).expect("secret");
        let public = PublicKey::from_bytes(&profile, &public_frame).expect("public");
        let evaluation = EvaluationKeys::from_bytes(&profile, &evaluation_frame).expect("keys");
        let three = crate::bgv::Plaintext::constant(&profile, 3).expect("plaintext");
        let seven = crate::bgv::Plaintext::constant(&profile, 7).expect("plaintext");
        let lhs = public.encrypt(&profile, &three).expect("ciphertext");
        let rhs = public.encrypt(&profile, &seven).expect("ciphertext");
        let product = profile
            .multiply(&lhs, &rhs, evaluation.relinearization())
            .expect("product");
        assert_eq!(
            secret
                .decrypt(&profile, &product)
                .expect("plaintext")
                .coefficients()[0],
            21
        );
        let rotated = profile
            .apply_galois(&lhs, evaluation.galois(5).expect("key"))
            .expect("rotated");
        assert_eq!(
            secret
                .decrypt(&profile, &rotated)
                .expect("plaintext")
                .coefficients()[0],
            3
        );
    }

    #[test]
    fn key_set_generation_draws_one_seed_per_key_and_fails_closed() {
        let profile = profile();
        let mut source = entropy(5);
        let keys = KeySet::generate_with(&profile, &[5, 31, 5], &mut source).expect("keys");
        // Secret, public, relinearization and two distinct Galois keys.
        assert_eq!(source.calls, 5);
        assert_eq!(keys.evaluation.galois_elements(), vec![5, 31]);
        assert_eq!(
            keys.evaluation.relinearization().kind(),
            SwitchingKeyKind::Relinearization
        );
        assert_eq!(
            keys.evaluation.galois(31).map(SwitchingKey::kind),
            Some(SwitchingKeyKind::Galois(31))
        );
        assert!(keys.evaluation.galois(3).is_none());
        assert!(format!("{keys:?}").starts_with("KeySet { secret: SecretKey"));
        // An invalid element is refused before any entropy is drawn.
        let mut untouched = entropy(5);
        assert_eq!(
            KeySet::generate_with(&profile, &[5, 4], &mut untouched).err(),
            Some(BgvError::InvalidGaloisElement)
        );
        assert_eq!(untouched.calls, 0);
        let secret = SecretKey::generate_with(&profile, &mut entropy(1)).expect("secret");
        assert_eq!(
            EvaluationKeys::generate_with(&profile, &secret, &[4], &mut untouched).err(),
            Some(BgvError::InvalidGaloisElement)
        );
        assert_eq!(untouched.calls, 0);
        // Entropy that fails at any draw yields no key set.
        for available in 0..5_u8 {
            let mut failing = entropy(available);
            assert_eq!(
                KeySet::generate_with(&profile, &[5, 31], &mut failing).err(),
                Some(BgvError::EntropyUnavailable),
                "available {available}"
            );
            assert_eq!(failing.calls, usize::from(available) + 1);
        }
        assert!(KeySet::generate(&profile, &[5]).is_ok());
        assert!(EvaluationKeys::generate(&profile, &secret, &[]).is_ok());
    }
}
