//! Byte-faithful, bounded holder-randomness sampler from pinned LaZeR.
//!
//! LaZeR's `polyvec_grandom(..., log2o = 1)` uses one AES-256-CTR stream per
//! degree-64 polynomial and a Gaussian-1.55 sign cache shared across those
//! streams.  This module preserves that byte layout while replacing every
//! unbounded retry with a public ceiling.  AES is CPU-only safe Rust with a
//! fixed-control-flow algebraic S-box; neither secret-indexed tables nor
//! accelerator/device dispatch are used.
use super::{holder_aes256::ConstantTimeAes256KeyV1, ring::ApplicationPolynomialV1};
use rand_core_06::{CryptoRng, RngCore};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};
pub(crate) const CREDENTIAL_RANDOMNESS_POLYNOMIALS_V1: usize = 16;
pub(crate) const CREDENTIAL_RANDOMNESS_NORM_SQUARED_BOUND_V1: u64 =
    super::params::RANDOMNESS_NORM_SQUARED_BOUND_V1;
pub(crate) const MAX_CREDENTIAL_RANDOMNESS_VECTOR_ATTEMPTS_V1: u32 = 64;
pub(crate) const MAX_CREDENTIAL_RANDOMNESS_COEFFICIENT_PROPOSALS_V1: u32 = 256;
pub(crate) const BOOTLE_CREDENTIAL_RANDOMNESS_PROFILE_DESCRIPTOR_V1: &[u8] = b"lazer-10eafeca4cd53ff4fc54193dce904dbd0026fefd-polyvec-grandom-v1|ring:R64-q12289|shape:16x64|sigma:1.55*2|seed:32|rng:AES-256-CTR-domain-le64-zero64-counter-be128|domains:(outer<<32)|(poly+1)|rounding:8-bytes-lsb-first-per-poly|cdf155:21-pairs-u64le|berexp:fdlibm-exp-small-u64le|sign-cache:issuance-local-persistent-across-polynomials-and-vector-retries|norm2<=11881|vector-attempts:64|coefficient-proposals:256|aes:cpu-only-fixed-control-flow-algebraic-sbox";
const DEGREE_V1: usize = 64;
const CDF_155_V1: [(u64, u64); 21] = [
    (0x9731_fa96_ce33_beaa, 0x95f2_8503_ccbd_a2bd),
    (0x4214_fc88_358f_5c62, 0x562d_6660_c3b9_627a),
    (0x147e_977a_5722_be70, 0xc3cb_0844_13c6_ee77),
    (0x0464_0a00_62b0_29f1, 0xf767_4972_e3a7_3e45),
    (0x00a3_9452_8f41_0338, 0xff27_d653_80a1_4596),
    (0x0010_001e_4da9_5f7f, 0x3594_a26e_72c0_4c13),
    (0x0001_0b80_b7d8_b376, 0xc18e_52fe_afb7_88e6),
    (0x0000_0b9d_275b_606f, 0xc6c1_9755_53ef_ed8f),
    (0x0000_0055_93dd_7d68, 0x8ec1_eaed_32a0_5634),
    (0x0000_0001_a14e_f431, 0x1fbf_da53_c04c_c460),
    (0x0000_0000_0541_1dc0, 0xf7a2_8b70_dbd1_16df),
    (0x0000_0000_000b_2fbf, 0xa8f5_ea4d_dcbb_fb6d),
    (0x0000_0000_0000_0fb8, 0xfabc_64e1_00b3_9745),
    (0x0000_0000_0000_000e, 0x9561_792d_b7c6_525f),
    (0, 0x08ec_d772_5eb8_7a20),
    (0, 0x0003_9a7e_0798_ac30),
    (0, 0x0000_00f5_afb9_e664),
    (0, 0x0000_0000_2b29_083d),
    (0, 0x0000_0000_0005_0040),
    (0, 0x0000_0000_0000_0062),
    (0, 0),
];
pub(crate) struct CredentialRandomnessV1 {
    polynomials: [ApplicationPolynomialV1; CREDENTIAL_RANDOMNESS_POLYNOMIALS_V1],
    norm_squared: u64,
}
impl CredentialRandomnessV1 {
    #[cfg(test)]
    pub(crate) const fn polynomials(
        &self,
    ) -> &[ApplicationPolynomialV1; CREDENTIAL_RANDOMNESS_POLYNOMIALS_V1] {
        &self.polynomials
    }
    #[cfg(test)]
    pub(crate) const fn norm_squared(&self) -> u64 {
        self.norm_squared
    }
    pub(crate) fn into_polynomials(
        mut self,
    ) -> [ApplicationPolynomialV1; CREDENTIAL_RANDOMNESS_POLYNOMIALS_V1] {
        core::mem::replace(
            &mut self.polynomials,
            [ApplicationPolynomialV1::ZERO; CREDENTIAL_RANDOMNESS_POLYNOMIALS_V1],
        )
    }
}
impl core::fmt::Debug for CredentialRandomnessV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("CredentialRandomnessV1(<redacted>)")
    }
}
impl Zeroize for CredentialRandomnessV1 {
    fn zeroize(&mut self) {
        self.polynomials.zeroize();
        self.norm_squared.zeroize();
    }
}
impl Drop for CredentialRandomnessV1 {
    fn drop(&mut self) {
        self.zeroize();
    }
}
pub(crate) fn sample_credential_randomness_v1<R: CryptoRng + RngCore>(
    rng: &mut R,
) -> Result<CredentialRandomnessV1, CredentialRandomnessErrorV1> {
    let mut seed = Zeroizing::new([0_u8; 32]);
    rng.try_fill_bytes(seed.as_mut())
        .map_err(|_| CredentialRandomnessErrorV1::RandomnessUnavailable)?;
    sample_credential_randomness_from_seed_v1(&*seed).map(|(sample, _)| sample)
}
pub(crate) fn sample_credential_randomness_from_seed_v1(
    seed: &[u8; 32],
) -> Result<
    (
        CredentialRandomnessV1,
        [u32; CREDENTIAL_RANDOMNESS_POLYNOMIALS_V1],
    ),
    CredentialRandomnessErrorV1,
> {
    sample_credential_randomness_from_seed_with_limits_v1(
        seed,
        MAX_CREDENTIAL_RANDOMNESS_VECTOR_ATTEMPTS_V1,
        MAX_CREDENTIAL_RANDOMNESS_COEFFICIENT_PROPOSALS_V1,
    )
}
fn sample_credential_randomness_from_seed_with_limits_v1(
    seed: &[u8; 32],
    vector_attempts: u32,
    coefficient_proposals: u32,
) -> Result<
    (
        CredentialRandomnessV1,
        [u32; CREDENTIAL_RANDOMNESS_POLYNOMIALS_V1],
    ),
    CredentialRandomnessErrorV1,
> {
    sample_credential_randomness_from_seed_bounded_v1(
        seed,
        vector_attempts,
        coefficient_proposals,
        CREDENTIAL_RANDOMNESS_NORM_SQUARED_BOUND_V1,
    )
    .map(|(sample, proposals, _, _)| (sample, proposals))
}
fn sample_credential_randomness_from_seed_bounded_v1(
    seed: &[u8; 32],
    vector_attempts: u32,
    coefficient_proposals: u32,
    norm_squared_bound: u64,
) -> Result<
    (
        CredentialRandomnessV1,
        [u32; CREDENTIAL_RANDOMNESS_POLYNOMIALS_V1],
        u32,
        u8,
    ),
    CredentialRandomnessErrorV1,
> {
    if vector_attempts == 0 || coefficient_proposals == 0 {
        return Err(CredentialRandomnessErrorV1::SamplingExhausted);
    }
    if norm_squared_bound > CREDENTIAL_RANDOMNESS_NORM_SQUARED_BOUND_V1 {
        return Err(CredentialRandomnessErrorV1::InternalInvariant);
    }
    let encryption_key = ConstantTimeAes256KeyV1::new(seed);
    let mut sign_cache = GaussianSignCacheV1::new();
    let mut second_attempt_sign_position = None;
    for outer_domain in 0..vector_attempts {
        if outer_domain == 1 {
            second_attempt_sign_position = Some(sign_cache.position);
        }
        let mut centered = Box::new(Zeroizing::new(
            [[0_i64; DEGREE_V1]; CREDENTIAL_RANDOMNESS_POLYNOMIALS_V1],
        ));
        let mut norm_squared = 0_u64;
        let mut proposals = [0_u32; CREDENTIAL_RANDOMNESS_POLYNOMIALS_V1];
        for polynomial_index in 0..CREDENTIAL_RANDOMNESS_POLYNOMIALS_V1 {
            let domain = (u64::from(outer_domain) << 32)
                | u64::try_from(polynomial_index + 1)
                    .expect("credential polynomial index fits u64");
            let mut stream = Aes256CtrV1::new(&encryption_key, domain);
            let mut rounding = Zeroizing::new([0_u8; 8]);
            stream.fill(rounding.as_mut());
            for coefficient_index in 0..DEGREE_V1 {
                let fractional =
                    i32::from((rounding[coefficient_index / 8] >> (coefficient_index % 8)) & 1);
                let (gaussian, used) = gaussian_155_v1(
                    &mut stream,
                    &mut sign_cache,
                    f64::from(fractional) * 0.5,
                    coefficient_proposals,
                )?;
                proposals[polynomial_index] = proposals[polynomial_index]
                    .checked_add(used)
                    .ok_or(CredentialRandomnessErrorV1::InternalInvariant)?;
                let sample = i64::from(gaussian)
                    .checked_mul(2)
                    .and_then(|value| value.checked_sub(i64::from(fractional)))
                    .ok_or(CredentialRandomnessErrorV1::InternalInvariant)?;
                centered[polynomial_index][coefficient_index] = sample;
                norm_squared = norm_squared
                    .checked_add(
                        u64::try_from(sample * sample)
                            .map_err(|_| CredentialRandomnessErrorV1::InternalInvariant)?,
                    )
                    .ok_or(CredentialRandomnessErrorV1::InternalInvariant)?;
            }
        }
        if norm_squared <= norm_squared_bound {
            let polynomials = core::array::from_fn(|index| {
                ApplicationPolynomialV1::from_centered_coefficients(centered[index])
            });
            return Ok((
                CredentialRandomnessV1 {
                    polynomials,
                    norm_squared,
                },
                proposals,
                outer_domain,
                second_attempt_sign_position.unwrap_or(64),
            ));
        }
    }
    Err(CredentialRandomnessErrorV1::SamplingExhausted)
}
struct GaussianSignCacheV1 {
    bits: u64,
    position: u8,
}
impl GaussianSignCacheV1 {
    const fn new() -> Self {
        Self {
            bits: 0,
            position: 64,
        }
    }
    fn next(&mut self, stream: &mut Aes256CtrV1<'_>) -> u32 {
        if self.position >= 64 {
            let mut bytes = Zeroizing::new([0_u8; 8]);
            stream.fill(bytes.as_mut());
            self.bits = u64::from_le_bytes(*bytes);
            self.position = 0;
        }
        let bit = u32::try_from(self.bits & 1).expect("one bit fits u32");
        self.bits >>= 1;
        self.position += 1;
        bit
    }
}
impl Drop for GaussianSignCacheV1 {
    fn drop(&mut self) {
        self.bits.zeroize();
        self.position.zeroize();
    }
}
fn gaussian_155_v1(
    stream: &mut Aes256CtrV1<'_>,
    signs: &mut GaussianSignCacheV1,
    center: f64,
    proposal_limit: u32,
) -> Result<(i32, u32), CredentialRandomnessErrorV1> {
    for proposal in 1..=proposal_limit {
        let branch = i32::try_from(signs.next(stream)).expect("one bit fits i32");
        let magnitude = i32::try_from(cdf_155_sample_v1(stream))
            .map_err(|_| CredentialRandomnessErrorV1::InternalInvariant)?;
        let sample = ((-branch) & (2 * magnitude)) - magnitude + branch;
        let exponent = gaussian_155_rejection_exponent_v1(sample, branch, center);
        if ber_exp_v1(stream, exponent) {
            return Ok((sample, proposal));
        }
    }
    Err(CredentialRandomnessErrorV1::CoefficientSamplingExhausted)
}
/// Difference of target and proposal squared distances for the sampled branch.
fn gaussian_155_rejection_exponent_v1(sample: i32, branch: i32, center: f64) -> f64 {
    const DOUBLE_SIGMA_SQUARED_RECIPROCAL: f64 = 1.0 / (2.0 * 1.55 * 1.55);
    let sample_f64 = f64::from(sample);
    let base_f64 = f64::from(sample - branch);
    let centered_distance = sample_f64 - center;
    let target_squared_distance = centered_distance * centered_distance;
    let proposal_squared_distance = base_f64 * base_f64;
    (target_squared_distance - proposal_squared_distance) * DOUBLE_SIGMA_SQUARED_RECIPROCAL
}
fn cdf_155_sample_v1(stream: &mut Aes256CtrV1<'_>) -> usize {
    let mut bytes = Zeroizing::new([0_u8; 16]);
    stream.fill(bytes.as_mut());
    let high = u64::from_le_bytes(bytes[..8].try_into().expect("fixed slice"));
    let low = u64::from_le_bytes(bytes[8..].try_into().expect("fixed slice"));
    let mut index = 0;
    while high <= CDF_155_V1[index].0 && (high < CDF_155_V1[index].0 || low < CDF_155_V1[index].1) {
        index += 1;
    }
    index
}
fn ber_exp_v1(stream: &mut Aes256CtrV1<'_>, mut exponent: f64) -> bool {
    const LN_2: f64 = f64::from_bits(0x3fe6_2e42_fefa_39ef);
    let mut bytes = Zeroizing::new([0_u8; 16]);
    stream.fill(bytes.as_mut());
    let first = u64::from_le_bytes(bytes[..8].try_into().expect("fixed slice"));
    let mut power = (exponent * (1.0 / LN_2)) as u64;
    exponent -= LN_2 * power as f64;
    power = power.min(63);
    let low_bits = first ^ ((first >> power) << power);
    let first_accepts = low_bits == 0;
    let second =
        u64::from_le_bytes(bytes[8..].try_into().expect("fixed slice")) & ((1_u64 << 53) - 1);
    let threshold = (exp_small_v1(-exponent) * (1_u64 << 53) as f64) as u64;
    first_accepts && second < threshold
}
fn exp_small_v1(value: f64) -> f64 {
    const C1: f64 = 1.666_666_666_666_660_2e-1;
    const C2: f64 = -2.777_777_777_701_559_3e-3;
    const C3: f64 = 6.613_756_321_437_934e-5;
    const C4: f64 = -1.653_390_220_546_525_2e-6;
    const C5: f64 = 4.138_136_797_057_238_5e-8;
    let square = value * value;
    let reduced =
        value - square * (C1 + square * (C2 + square * (C3 + square * (C4 + square * C5))));
    1.0 - ((value * reduced) / (reduced - 2.0) - value)
}
struct Aes256CtrV1<'a> {
    encryption_key: &'a ConstantTimeAes256KeyV1,
    counter: [u8; 16],
    cache: [u8; 16],
    cursor: usize,
}
impl<'a> Aes256CtrV1<'a> {
    fn new(encryption_key: &'a ConstantTimeAes256KeyV1, domain: u64) -> Self {
        let mut counter = [0_u8; 16];
        counter[..8].copy_from_slice(&domain.to_le_bytes());
        Self {
            encryption_key,
            counter,
            cache: [0; 16],
            cursor: 16,
        }
    }
    fn fill(&mut self, output: &mut [u8]) {
        for byte in output {
            if self.cursor == self.cache.len() {
                self.cache = self.encryption_key.encrypt_block(self.counter);
                increment_be(&mut self.counter);
                self.cursor = 0;
            }
            *byte = self.cache[self.cursor];
            self.cursor += 1;
        }
    }
}
impl Drop for Aes256CtrV1<'_> {
    fn drop(&mut self) {
        self.counter.zeroize();
        self.cache.zeroize();
        self.cursor.zeroize();
    }
}
fn increment_be(counter: &mut [u8; 16]) {
    let mut carry = 1_u8;
    for byte in counter.iter_mut().rev() {
        let (sum, overflow) = byte.overflowing_add(carry);
        *byte = sum;
        carry = u8::from(overflow);
    }
}
/// Bounded failure from the exact credential-randomness sampler.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub(crate) enum CredentialRandomnessErrorV1 {
    #[error("credential-randomness source is unavailable")]
    RandomnessUnavailable,
    #[error("credential-randomness Gaussian coefficient exhausted its proposal budget")]
    CoefficientSamplingExhausted,
    #[error("credential-randomness vector exhausted its norm-retry budget")]
    SamplingExhausted,
    #[error("credential-randomness internal invariant failed")]
    InternalInvariant,
}
#[cfg(test)]
mod tests {
    use super::*;
    use rand_core_06::Error as RngError;
    use sha2::{Digest as _, Sha256};
    struct FailingRng;
    impl RngCore for FailingRng {
        fn next_u32(&mut self) -> u32 {
            panic!("credential sampling must use the fallible RNG interface")
        }
        fn next_u64(&mut self) -> u64 {
            panic!("credential sampling must use the fallible RNG interface")
        }
        fn fill_bytes(&mut self, _destination: &mut [u8]) {
            panic!("credential sampling must use the fallible RNG interface")
        }
        fn try_fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), RngError> {
            Err(RngError::new("injected credential-sampling RNG failure"))
        }
    }
    impl CryptoRng for FailingRng {}
    #[test]
    fn gaussian_rejection_exponent_matches_exact_branch_and_center_numerators() {
        // The CDF terminator bounds magnitudes by 20; rounding supplies only 0 or 1/2.
        for twice_center in [0_i32, 1] {
            for branch in [0_i32, 1] {
                for magnitude in 0_i32..=20 {
                    let sample = if branch == 0 {
                        -magnitude
                    } else {
                        magnitude + 1
                    };
                    let offset = if branch == 0 {
                        twice_center
                    } else {
                        2 - twice_center
                    };
                    let exact_numerator = 4 * magnitude * offset + offset * offset;
                    let expected = (f64::from(exact_numerator) / 4.0) * (1.0 / (2.0 * 1.55 * 1.55));
                    let actual = gaussian_155_rejection_exponent_v1(
                        sample,
                        branch,
                        f64::from(twice_center) / 2.0,
                    );
                    assert_eq!(
                        actual.to_bits(),
                        expected.to_bits(),
                        "magnitude={magnitude}, branch={branch}, twice_center={twice_center}"
                    );
                    assert!(actual >= 0.0);
                }
            }
        }
    }
    #[test]
    fn pinned_lazer_seed_matches_first_polynomial_and_full_vector_digest() {
        let seed = core::array::from_fn(|index| u8::try_from(index).expect("index fits u8"));
        let (sample, proposals) =
            sample_credential_randomness_from_seed_v1(&seed).expect("pinned sample");
        let expected_first: [i64; 64] = [
            -5, 7, 1, -2, 10, -2, 1, 3, -1, 0, 5, 2, -3, -3, 4, 1, 1, 2, 0, -3, -5, 0, -4, 2, 0, 2,
            -1, -6, 2, 2, 4, 1, 0, -1, -2, -1, -2, -1, 1, 2, 1, 6, 2, -4, -1, -2, -4, 0, -5, 0, 0,
            0, -2, 2, -1, 0, 0, -4, 3, 1, 3, 2, -2, -2,
        ];
        let actual_first = sample.polynomials()[0].coefficients().map(|value| {
            if value > 6_144 {
                i64::from(value) - 12_289
            } else {
                i64::from(value)
            }
        });
        assert_eq!(actual_first, expected_first);
        assert_eq!(
            proposals,
            [
                79, 78, 83, 77, 82, 79, 79, 76, 81, 85, 86, 83, 79, 76, 81, 80
            ]
        );
        assert_eq!(sample.norm_squared(), 10_601);
        let mut bytes = Zeroizing::new(Vec::with_capacity(2 * 16 * 64));
        for polynomial in sample.polynomials() {
            for value in polynomial.coefficients() {
                let centered = if *value > 6_144 {
                    i16::try_from(i32::from(*value) - 12_289).expect("small centered sample")
                } else {
                    i16::try_from(*value).expect("small centered sample")
                };
                bytes.extend_from_slice(&centered.to_le_bytes());
            }
        }
        assert_eq!(
            Sha256::digest(bytes.as_slice()).as_slice(),
            hex::decode("a816e84a61ab8b2efd0f68739d24ede2f27ec463f86bdde17cbc7f881bc49026")
                .expect("hex")
        );
    }
    #[test]
    fn cdf_threshold_pairs_are_pinned() {
        let mut bytes = Vec::with_capacity(CDF_155_V1.len() * 16);
        for (high, low) in CDF_155_V1 {
            bytes.extend_from_slice(&high.to_be_bytes());
            bytes.extend_from_slice(&low.to_be_bytes());
        }
        assert_eq!(
            Sha256::digest(bytes).as_slice(),
            hex::decode("8cbe05f6150e101c19670a43cec6870813908bcc834be676a38a422281344d21")
                .expect("hex")
        );
    }
    #[test]
    fn public_caps_fail_closed_and_accepted_norm_is_bounded() {
        let seed = core::array::from_fn(|index| u8::try_from(index).expect("index fits u8"));
        assert_eq!(
            CREDENTIAL_RANDOMNESS_NORM_SQUARED_BOUND_V1,
            super::super::params::RANDOMNESS_NORM_SQUARED_BOUND_V1
        );
        assert!(matches!(
            sample_credential_randomness_from_seed_with_limits_v1(&seed, 0, 256),
            Err(CredentialRandomnessErrorV1::SamplingExhausted)
        ));
        assert!(matches!(
            sample_credential_randomness_from_seed_with_limits_v1(&seed, 64, 0),
            Err(CredentialRandomnessErrorV1::SamplingExhausted)
        ));
        assert!(matches!(
            sample_credential_randomness_from_seed_with_limits_v1(&seed, 64, 1),
            Err(CredentialRandomnessErrorV1::CoefficientSamplingExhausted)
        ));
        let (sample, _) = sample_credential_randomness_from_seed_v1(&seed).expect("sample");
        assert!(sample.norm_squared() <= CREDENTIAL_RANDOMNESS_NORM_SQUARED_BOUND_V1);
    }
    #[test]
    fn failing_rng_is_reported_without_using_infallible_methods() {
        assert!(matches!(
            sample_credential_randomness_v1(&mut FailingRng),
            Err(CredentialRandomnessErrorV1::RandomnessUnavailable)
        ));
    }
    #[test]
    fn forced_norm_retry_advances_domain_and_preserves_sign_cache() {
        let seed = core::array::from_fn(|index| u8::try_from(index).expect("index fits u8"));
        let (sample, _, accepted_outer_domain, second_attempt_sign_position) =
            sample_credential_randomness_from_seed_bounded_v1(&seed, 64, 256, 10_600)
                .expect("a later bounded vector meets the forced lower norm");
        assert!(accepted_outer_domain > 0);
        assert_eq!(second_attempt_sign_position, 4);
        assert!(sample.norm_squared() <= 10_600);
    }
}
