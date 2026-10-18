//! Prover-only integer sampling for revised Jindo.
//!
//! The first-release sampler is entirely integer-defined. Its one admissible Gaussian width is a
//! closed profile identifier and every probability comparison consumes one explicitly big-endian
//! 256-bit draw. Every rejection loop is bounded and fails closed for adversarial randomness.
#[cfg(test)]
use super::field::JindoFieldElementV1;
use super::{
    JINDO_ENCODING_BASE_V1, JINDO_RING_DEGREE_V1,
    parameters::JindoGaussianWidthV1,
    ring::{JINDO_INNER_MODULI_V1, JindoPrimeModulusV1, JindoRnsPolynomialV1},
};
use crate::privacy_engines::prover_randomness::{
    HealthCheckedCryptoRngV1, ProverRandomnessErrorV1,
};
use p256::elliptic_curve::bigint::{Encoding as _, Limb, NonZero, U128, U256, U512, U1024};
use rand_core_06::{CryptoRng, RngCore};
use std::sync::OnceLock;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};
const MAX_GAUSSIAN_ATTEMPTS_V1: usize = 4_096;
const MAX_UNIFORM_REJECTION_ATTEMPTS_V1: usize = 4_096;
#[cfg(test)]
const MAX_FIELD_REJECTION_ATTEMPTS_V1: usize = 65_536;
// The integer-decay tables split x into floor(x), the next twelve fractional
// bits, and a remainder below 2^-12.  For the unit Taylor series, 1/97! is
// below 2^-502; the 32-term fractional seed has still smaller remainder.  The
// independently pinned Q256 seeds are within one ulp.  Thus 128 integer-table
// products contribute fewer than 2^8 ulps, and 4095 fractional-table products
// fewer than 2^13 ulps, including half-ulp product rounding.  The 16-term
// residual has analytic remainder below 2^-252.  Including its arithmetic and
// both final products, total evaluation error stays below 2^16 Q256 ulps,
// i.e. below 2^-240.
const FRACTION_TABLE_BITS_V1: usize = 12;
const FRACTION_TABLE_LEN_V1: usize = 1 << FRACTION_TABLE_BITS_V1;
const MAX_DECAY_INTEGER_V1: usize = 128;
const UNIT_DECAY_SERIES_TERMS_V1: usize = 96;
const FRACTION_STEP_SERIES_TERMS_V1: usize = 32;
const RESIDUAL_DECAY_SERIES_TERMS_V1: usize = 16;
const Q128_FRACTION_BITS_V1: usize = 128;
const Q256_FRACTION_BITS_V1: usize = 256;
/// Signed fixed-point value whose magnitude is encoded with 128 fraction bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SignedQ128V1 {
    negative: bool,
    magnitude: U256,
}
impl SignedQ128V1 {
    const ZERO: Self = Self {
        negative: false,
        magnitude: U256::ZERO,
    };
    fn new(negative: bool, magnitude: U256) -> Self {
        Self {
            negative: negative && magnitude != U256::ZERO,
            magnitude,
        }
    }
    fn from_i64(value: i64) -> Self {
        Self::new(
            value.is_negative(),
            U256::from_u128(u128::from(value.unsigned_abs())).shl_vartime(Q128_FRACTION_BITS_V1),
        )
    }
    fn negated(self) -> Self {
        Self::new(!self.negative, self.magnitude)
    }
    fn floor_i128(self) -> Result<i128, JindoSamplingErrorV1> {
        let (integer, fraction) = self.magnitude.split();
        let integer = u128::from(integer);
        let has_fraction = fraction != U128::ZERO;
        signed_integer_part_v1(self.negative, integer, has_fraction, false)
    }
    fn ceil_i128(self) -> Result<i128, JindoSamplingErrorV1> {
        let (integer, fraction) = self.magnitude.split();
        let integer = u128::from(integer);
        let has_fraction = fraction != U128::ZERO;
        signed_integer_part_v1(self.negative, integer, has_fraction, true)
    }
}
impl Zeroize for SignedQ128V1 {
    fn zeroize(&mut self) {
        self.negative = false;
        self.magnitude = U256::ZERO;
    }
}
/// Bounded prover-side sampling failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum JindoSamplingErrorV1 {
    /// The operating-system or caller-supplied cryptographic RNG failed.
    #[error("Jindo cryptographic random source is unavailable")]
    RandomnessUnavailable,
    /// The source emitted a catastrophic constant or short-period prefix.
    #[error("Jindo cryptographic random source failed its health check")]
    RandomnessHealthCheckFailed,
    /// The supplied randomness stream failed every bounded rejection attempt.
    #[error("Jindo Gaussian rejection sampler exhausted its fixed attempt budget")]
    RejectionBudgetExhausted,
    /// A sampled coefficient exceeded the fixed signed representation.
    #[error("Jindo Gaussian sample exceeded the fixed signed coefficient range")]
    SampleOutOfRange,
    /// Uniform coefficient-field sampling exhausted its fixed retry budget.
    #[error("Jindo coefficient-field rejection sampler exhausted its fixed attempt budget")]
    FieldRejectionBudgetExhausted,
    /// The fixed-point decay evaluator escaped the closed probability range.
    #[error("Jindo Gaussian acceptance threshold escaped the closed Q256 probability range")]
    InvalidAcceptanceThreshold,
    /// A rejection-sampling inner product escaped the reviewed integer range.
    #[error("Jindo rejection arithmetic exceeded the fixed integer range")]
    ArithmeticOverflow,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DecayThresholdV1 {
    UnitProbability,
    Finite(U256),
}
pub(super) fn health_checked_jindo_rng_v1<R>(
    rng: &mut R,
) -> Result<HealthCheckedCryptoRngV1<'_, R>, JindoSamplingErrorV1>
where
    R: CryptoRng + RngCore,
{
    HealthCheckedCryptoRngV1::new(rng).map_err(|error| match error {
        ProverRandomnessErrorV1::Unavailable => JindoSamplingErrorV1::RandomnessUnavailable,
        ProverRandomnessErrorV1::Unhealthy => JindoSamplingErrorV1::RandomnessHealthCheckFailed,
    })
}
/// Sample one uniform canonical coefficient-field element.
#[cfg(test)]
fn sample_uniform_field_element_v1<R>(
    rng: &mut R,
) -> Result<JindoFieldElementV1, JindoSamplingErrorV1>
where
    R: CryptoRng + RngCore,
{
    for _ in 0..MAX_FIELD_REJECTION_ATTEMPTS_V1 {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        fill_random_bytes_v1(rng, bytes.as_mut())?;
        if let Some(value) = JindoFieldElementV1::from_canonical_bytes(*bytes) {
            return Ok(value);
        }
    }
    Err(JindoSamplingErrorV1::FieldRejectionBudgetExhausted)
}
/// Sample one discrete-Gaussian integer by bounded uniform rejection.
///
/// The proposal is exactly the integer points whose distance from the Q128
/// center is at most fourteen exact Q64 widths.  The omitted mass is below
/// `2^-140`.  Acceptance weights are evaluated in Q256 and compared to one
/// 256-bit threshold draw.  Across the complete support, threshold
/// quantization, center rounding, Q256 evaluation, and tail truncation have
/// conservative total statistical distance below `2^-118`.
fn sample_discrete_gaussian_v1<R>(
    center: SignedQ128V1,
    width: JindoGaussianWidthV1,
    rng: &mut R,
) -> Result<i64, JindoSamplingErrorV1>
where
    R: CryptoRng + RngCore,
{
    // These are exactly the integer points satisfying
    // `abs(candidate - center) <= 14 * sigma`:
    // `[ceil(center - 14*sigma), floor(center + 14*sigma)]`.
    let radius = SignedQ128V1::new(
        false,
        U256::from_u128(width.sigma_q64() * 14).shl_vartime(64),
    );
    let lower = add_signed_q128_v1(center, radius.negated()).ceil_i128()?;
    let upper = add_signed_q128_v1(center, radius).floor_i128()?;
    let lower = i64::try_from(lower).map_err(|_| JindoSamplingErrorV1::SampleOutOfRange)?;
    let upper = i64::try_from(upper).map_err(|_| JindoSamplingErrorV1::SampleOutOfRange)?;
    let proposal_width = u64::try_from(i128::from(upper) - i128::from(lower) + 1)
        .map_err(|_| JindoSamplingErrorV1::SampleOutOfRange)?;
    if proposal_width == 0 {
        return Err(JindoSamplingErrorV1::SampleOutOfRange);
    }
    for _ in 0..MAX_GAUSSIAN_ATTEMPTS_V1 {
        let offset = sample_bounded_u64_v1(proposal_width, rng)?;
        let candidate = i128::from(lower) + i128::from(offset);
        let candidate =
            i64::try_from(candidate).map_err(|_| JindoSamplingErrorV1::SampleOutOfRange)?;
        let exponent_q256 = gaussian_exponent_q256_v1(candidate, center, width)?;
        let threshold = decay_threshold_u256_v1(exponent_q256)?;
        let mut acceptance_bytes = Zeroizing::new([0_u8; 32]);
        fill_random_bytes_v1(rng, acceptance_bytes.as_mut())?;
        let draw = U256::from_be_bytes(*acceptance_bytes);
        if match threshold {
            DecayThresholdV1::UnitProbability => true,
            DecayThresholdV1::Finite(value) => draw < value,
        } {
            return Ok(candidate);
        }
    }
    Err(JindoSamplingErrorV1::RejectionBudgetExhausted)
}
/// Sample one independent small Gaussian application-ring polynomial.
pub fn sample_gaussian_polynomial_v1<R>(
    width: JindoGaussianWidthV1,
    moduli: [JindoPrimeModulusV1; 2],
    rng: &mut R,
) -> Result<JindoRnsPolynomialV1, JindoSamplingErrorV1>
where
    R: CryptoRng + RngCore,
{
    let mut coefficients = Zeroizing::new([0_i128; JINDO_RING_DEGREE_V1]);
    for coefficient in coefficients.iter_mut() {
        *coefficient = i128::from(sample_discrete_gaussian_v1(SignedQ128V1::ZERO, width, rng)?);
    }
    Ok(JindoRnsPolynomialV1::from_balanced_coefficients(
        *coefficients,
        moduli,
    ))
}
/// Sample a polynomial with independent coefficients uniform in `[0,b)`.
pub fn sample_uniform_encoding_polynomial_v1<R>(
    rng: &mut R,
) -> Result<JindoRnsPolynomialV1, JindoSamplingErrorV1>
where
    R: CryptoRng + RngCore,
{
    let mut coefficients = Zeroizing::new([0_i128; JINDO_RING_DEGREE_V1]);
    for coefficient in coefficients.iter_mut() {
        *coefficient = i128::from(sample_bounded_u64_v1(JINDO_ENCODING_BASE_V1, rng)?);
    }
    Ok(JindoRnsPolynomialV1::from_balanced_coefficients(
        *coefficients,
        JINDO_INNER_MODULI_V1,
    ))
}
/// Sample a polynomial with independent coefficients uniform in `[-b,b)`.
pub fn sample_mlwe_polynomial_v1<R>(
    rng: &mut R,
) -> Result<JindoRnsPolynomialV1, JindoSamplingErrorV1>
where
    R: CryptoRng + RngCore,
{
    let range = JINDO_ENCODING_BASE_V1
        .checked_mul(2)
        .ok_or(JindoSamplingErrorV1::SampleOutOfRange)?;
    let mut coefficients = Zeroizing::new([0_i128; JINDO_RING_DEGREE_V1]);
    for coefficient in coefficients.iter_mut() {
        *coefficient =
            i128::from(sample_bounded_u64_v1(range, rng)?) - i128::from(JINDO_ENCODING_BASE_V1);
    }
    Ok(JindoRnsPolynomialV1::from_balanced_coefficients(
        *coefficients,
        JINDO_INNER_MODULI_V1,
    ))
}
/// Apply the exact `M=6/5` Lyubashevsky rejection test.
///
/// `exponent_numerator` is `-||v||^2 - 2<y,v>` and the exponent denominator
/// is `2 sigma^2`, with the exact half-integer `sigma=8241321404272819/2`.
pub fn accept_aggregation_rejection_v1<R>(
    exponent_numerator: i128,
    rng: &mut R,
) -> Result<bool, JindoSamplingErrorV1>
where
    R: CryptoRng + RngCore,
{
    const SIGMA_TWICE: u128 = 8_241_321_404_272_819;
    let denominator = SIGMA_TWICE
        .checked_mul(SIGMA_TWICE)
        .ok_or(JindoSamplingErrorV1::ArithmeticOverflow)?;
    let magnitude = exponent_numerator.unsigned_abs();
    // |e|/(2 sigma^2) = 2|e|/SIGMA_TWICE^2.
    let scaled = U512::from_u128(magnitude).shl_vartime(Q256_FRACTION_BITS_V1 + 1);
    let denominator = U512::from_u128(denominator);
    let nonzero = Option::<NonZero<U512>>::from(NonZero::new(denominator))
        .ok_or(JindoSamplingErrorV1::ArithmeticOverflow)?;
    let (quotient, remainder) = scaled.div_rem(&nonzero);
    let exponent_q256 = if remainder.shl_vartime(1) >= denominator {
        quotient.wrapping_add(&U512::ONE)
    } else {
        quotient
    };
    let decay = decay_q256_v1(exponent_q256);
    let five = U512::from_u64(5).shl_vartime(Q256_FRACTION_BITS_V1);
    let six = Option::<NonZero<Limb>>::from(NonZero::new(Limb::from_u32(6)))
        .ok_or(JindoSamplingErrorV1::ArithmeticOverflow)?;
    let five_six = five.div_rem_limb(six).0;
    let threshold = if exponent_numerator <= 0 {
        q256_mul_round_v1(decay, five_six)
    } else if decay <= five_six {
        U512::ONE.shl_vartime(Q256_FRACTION_BITS_V1)
    } else {
        let scaled: U1024 = U1024::from(&five_six).shl_vartime(Q256_FRACTION_BITS_V1);
        let divisor = U1024::from(&decay);
        let nonzero = Option::<NonZero<U1024>>::from(NonZero::new(divisor))
            .ok_or(JindoSamplingErrorV1::InvalidAcceptanceThreshold)?;
        let quotient = scaled.div_rem(&nonzero).0;
        let (high, low) = quotient.split();
        if high != U512::ZERO {
            return Err(JindoSamplingErrorV1::InvalidAcceptanceThreshold);
        }
        low
    };
    let threshold = classify_decay_threshold_v1(threshold)?;
    let mut bytes = Zeroizing::new([0_u8; 32]);
    fill_random_bytes_v1(rng, bytes.as_mut())?;
    let draw = U256::from_be_bytes(*bytes);
    Ok(match threshold {
        DecayThresholdV1::UnitProbability => true,
        DecayThresholdV1::Finite(value) => draw < value,
    })
}
pub fn sample_bounded_u64_v1(
    bound: u64,
    rng: &mut impl RngCore,
) -> Result<u64, JindoSamplingErrorV1> {
    debug_assert!(bound > 0);
    let acceptance_limit = u64::MAX - (u64::MAX % bound);
    for _ in 0..MAX_UNIFORM_REJECTION_ATTEMPTS_V1 {
        let mut bytes = [0_u8; 8];
        fill_random_bytes_v1(rng, &mut bytes)?;
        let candidate = u64::from_be_bytes(bytes);
        if candidate < acceptance_limit {
            return Ok(candidate % bound);
        }
    }
    Err(JindoSamplingErrorV1::RejectionBudgetExhausted)
}
fn fill_random_bytes_v1(
    rng: &mut impl RngCore,
    destination: &mut [u8],
) -> Result<(), JindoSamplingErrorV1> {
    rng.try_fill_bytes(destination)
        .map_err(|_| JindoSamplingErrorV1::RandomnessUnavailable)
}
fn signed_integer_part_v1(
    negative: bool,
    integer: u128,
    has_fraction: bool,
    ceiling: bool,
) -> Result<i128, JindoSamplingErrorV1> {
    let increment = has_fraction && (negative != ceiling);
    let magnitude = integer
        .checked_add(u128::from(increment))
        .ok_or(JindoSamplingErrorV1::SampleOutOfRange)?;
    if !negative {
        return i128::try_from(magnitude).map_err(|_| JindoSamplingErrorV1::SampleOutOfRange);
    }
    if magnitude == (1_u128 << 127) {
        return Ok(i128::MIN);
    }
    let magnitude =
        i128::try_from(magnitude).map_err(|_| JindoSamplingErrorV1::SampleOutOfRange)?;
    Ok(-magnitude)
}
fn add_signed_q128_v1(left: SignedQ128V1, right: SignedQ128V1) -> SignedQ128V1 {
    if left.negative == right.negative {
        // Callers add an encoding center below two to a profile radius below
        // 2^33, all in Q128, so this U256 addition is below 2^162.
        return SignedQ128V1::new(left.negative, left.magnitude.wrapping_add(&right.magnitude));
    }
    match left.magnitude.cmp(&right.magnitude) {
        core::cmp::Ordering::Greater => {
            SignedQ128V1::new(left.negative, left.magnitude.wrapping_sub(&right.magnitude))
        }
        core::cmp::Ordering::Less => SignedQ128V1::new(
            right.negative,
            right.magnitude.wrapping_sub(&left.magnitude),
        ),
        core::cmp::Ordering::Equal => SignedQ128V1::ZERO,
    }
}
fn absolute_delta_q128_v1(candidate: i64, center: SignedQ128V1) -> U256 {
    let candidate = SignedQ128V1::from_i64(candidate);
    if candidate.negative == center.negative {
        if candidate.magnitude >= center.magnitude {
            candidate.magnitude.wrapping_sub(&center.magnitude)
        } else {
            center.magnitude.wrapping_sub(&candidate.magnitude)
        }
    } else {
        // Candidate magnitude is below 2^63 in Q128 and an admitted encoding
        // center is below two, so this addition is below 2^192.
        candidate.magnitude.wrapping_add(&center.magnitude)
    }
}
fn gaussian_exponent_q256_v1(
    candidate: i64,
    center: SignedQ128V1,
    width: JindoGaussianWidthV1,
) -> Result<U512, JindoSamplingErrorV1> {
    let delta_q128 = absolute_delta_q128_v1(candidate, center);
    let squared_delta_q256: U512 = delta_q128.mul(&delta_q128);
    if squared_delta_q256.bits_vartime() > U512::BITS - Q128_FRACTION_BITS_V1 {
        return Err(JindoSamplingErrorV1::SampleOutOfRange);
    }
    let numerator = squared_delta_q256.shl_vartime(Q128_FRACTION_BITS_V1);
    let sigma_q64 = U128::from_u128(width.sigma_q64());
    let sigma_squared_q128: U256 = sigma_q64.mul(&sigma_q64);
    let denominator = U512::from(&sigma_squared_q128.shl_vartime(1));
    let Some(nonzero_denominator) = Option::<NonZero<U512>>::from(NonZero::new(denominator)) else {
        return Err(JindoSamplingErrorV1::SampleOutOfRange);
    };
    let (quotient, remainder) = numerator.div_rem(&nonzero_denominator);
    Ok(if remainder.shl_vartime(1) >= denominator {
        // Admissible endpoints are below exponent 99 (pinned in tests), hence
        // the rounded result is below 99 * 2^256.
        quotient.wrapping_add(&U512::ONE)
    } else {
        quotient
    })
}
fn q256_mul_round_v1(left: U512, right: U512) -> U512 {
    // All decay operands are in `[0, 2^256]`; the product plus half an ulp is
    // below 2^513 and therefore exact in U1024.
    let product: U1024 = left.mul(&right);
    let rounded = product
        .wrapping_add(&U1024::ONE.shl_vartime(Q256_FRACTION_BITS_V1 - 1))
        .shr_vartime(Q256_FRACTION_BITS_V1);
    let (high, low) = rounded.split();
    debug_assert_eq!(high, U512::ZERO);
    low
}
fn q256_div_small_round_v1(value: U512, divisor: u64) -> U512 {
    debug_assert!(divisor > 0);
    let Ok(divisor_word) = u32::try_from(divisor) else {
        return U512::ZERO;
    };
    let divisor_limb = Limb::from_u32(divisor_word);
    let Some(nonzero_divisor) = Option::<NonZero<Limb>>::from(NonZero::new(divisor_limb)) else {
        return U512::ZERO;
    };
    // `value <= 2^256` and `divisor <= 96`, so the rounding addition cannot
    // approach the U512 boundary.
    value
        .wrapping_add(&U512::from_u64(divisor >> 1))
        .div_rem_limb(nonzero_divisor)
        .0
}
fn small_decay_q256_v1(value: U512, terms: usize) -> U512 {
    let one = U512::ONE.shl_vartime(Q256_FRACTION_BITS_V1);
    let mut sum = one;
    let mut term = one;
    for index in 1..=terms {
        let Ok(divisor) = u64::try_from(index) else {
            return U512::ZERO;
        };
        term = q256_div_small_round_v1(q256_mul_round_v1(term, value), divisor);
        if term == U512::ZERO {
            break;
        }
        if index % 2 == 0 {
            // For `value <= 1`, alternating partial sums remain in `[0, 1]`
            // after the second term; these fixed-point operations cannot wrap.
            sum = sum.wrapping_add(&term);
        } else {
            sum = sum.wrapping_sub(&term);
        }
    }
    sum
}
fn integer_decay_table_q256_v1() -> &'static [U512; MAX_DECAY_INTEGER_V1 + 1] {
    static TABLE: OnceLock<[U512; MAX_DECAY_INTEGER_V1 + 1]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let one = U512::ONE.shl_vartime(Q256_FRACTION_BITS_V1);
        let decay_one = small_decay_q256_v1(one, UNIT_DECAY_SERIES_TERMS_V1);
        let mut table = [U512::ZERO; MAX_DECAY_INTEGER_V1 + 1];
        table[0] = one;
        for index in 1..table.len() {
            table[index] = q256_mul_round_v1(table[index - 1], decay_one);
        }
        table
    })
}
fn fraction_decay_table_q256_v1() -> &'static [U512; FRACTION_TABLE_LEN_V1] {
    static TABLE: OnceLock<Box<[U512; FRACTION_TABLE_LEN_V1]>> = OnceLock::new();
    TABLE.get_or_init(build_fraction_decay_table_q256_v1)
}
fn build_fraction_decay_table_q256_v1() -> Box<[U512; FRACTION_TABLE_LEN_V1]> {
    let one = U512::ONE.shl_vartime(Q256_FRACTION_BITS_V1);
    let step = U512::ONE.shl_vartime(Q256_FRACTION_BITS_V1 - FRACTION_TABLE_BITS_V1);
    let decay_step = small_decay_q256_v1(step, FRACTION_STEP_SERIES_TERMS_V1);
    // The 256 KiB public table stays on the heap throughout initialization
    // and publication; no fixed array passes through a native caller's stack.
    let mut table = vec![U512::ZERO; FRACTION_TABLE_LEN_V1];
    table[0] = one;
    for index in 1..table.len() {
        table[index] = q256_mul_round_v1(table[index - 1], decay_step);
    }
    table
        .into_boxed_slice()
        .try_into()
        .unwrap_or_else(|_| unreachable!("fixed fractional-decay table length"))
}
fn decay_q256_v1(value: U512) -> U512 {
    let bytes = value.to_be_bytes();
    if bytes[..31].iter().any(|byte| *byte != 0) {
        return U512::ZERO;
    }
    let integer_byte = bytes[31];
    let integer = usize::from(integer_byte);
    if integer > MAX_DECAY_INTEGER_V1 {
        return U512::ZERO;
    }
    let fraction_word = (u16::from(bytes[32]) << 4) | u16::from(bytes[33] >> 4);
    let fraction_index = usize::from(fraction_word);
    let integer_part = U512::from_u64(u64::from(integer_byte)).shl_vartime(Q256_FRACTION_BITS_V1);
    let fraction_part = U512::from_u64(u64::from(fraction_word))
        .shl_vartime(Q256_FRACTION_BITS_V1 - FRACTION_TABLE_BITS_V1);
    let residual = value
        // Integer and fractional parts are extracted from `value` itself, so
        // both subtractions are ordered and exact.
        .wrapping_sub(&integer_part)
        .wrapping_sub(&fraction_part);
    let residual_decay = small_decay_q256_v1(residual, RESIDUAL_DECAY_SERIES_TERMS_V1);
    q256_mul_round_v1(
        q256_mul_round_v1(
            integer_decay_table_q256_v1()[integer],
            fraction_decay_table_q256_v1()[fraction_index],
        ),
        residual_decay,
    )
}
fn classify_decay_threshold_v1(value: U512) -> Result<DecayThresholdV1, JindoSamplingErrorV1> {
    let (high, low) = value.split();
    if high == U256::ZERO {
        return Ok(DecayThresholdV1::Finite(low));
    }
    if high == U256::ONE && low == U256::ZERO {
        return Ok(DecayThresholdV1::UnitProbability);
    }
    Err(JindoSamplingErrorV1::InvalidAcceptanceThreshold)
}
fn decay_threshold_u256_v1(value: U512) -> Result<DecayThresholdV1, JindoSamplingErrorV1> {
    classify_decay_threshold_v1(decay_q256_v1(value))
}
// INTEGER_ONLY_PRODUCTION_END
#[cfg(test)]
#[path = "sampling_integer_tests.rs"]
mod tests;
