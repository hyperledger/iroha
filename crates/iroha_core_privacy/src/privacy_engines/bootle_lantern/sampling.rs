//! Bounded native randomness and integer-defined discrete-Gaussian sampling.
//!
//! The first profile has four closed sampling roles.  Gaussian widths,
//! truncation limits, rejection formulas, vector shapes, and rejection
//! constants are selected together, so callers cannot combine parameters from
//! different roles.  Every probability is evaluated in Q256, every decision
//! consumes one explicitly big-endian 256-bit draw, and every retry loop has a
//! fixed public ceiling.
use super::{
    params::{
        APPLICATION_RING_DEGREE_V1, GAUSSIAN_SIGMA_DENOMINATOR_V1, GAUSSIAN_SIGMA_NUMERATOR_V1,
        GAUSSIAN_TRUNCATION_BOUNDS_V1, MAX_GAUSSIAN_COEFFICIENT_ATTEMPTS_V1,
        MAX_PROJECTION_SAMPLING_ATTEMPTS_PER_PROVE_ATTEMPT_V1, MAX_PROOF_SAMPLING_ATTEMPTS_V1,
        MAX_RESPONSE_SAMPLING_ATTEMPTS_PER_PROVE_ATTEMPT_V1, MAX_UNIFORM_REJECTION_ATTEMPTS_V1,
        PROOF_MODULUS_V1, REJECTION_M_Q256_LIMBS_V1, TBOX_M1_V1, TBOX_M2_V1,
    },
    ring::ProofPolynomialV1,
};
use crate::privacy_engines::prover_randomness::{
    CURVE_PROVER_RANDOMNESS_POLICY_V1, HealthCheckedCryptoRngV1, ProverRandomnessErrorV1,
};
use p256::elliptic_curve::bigint::{Encoding as _, Limb, NonZero, U256, U512, U1024};
use rand_core_06::{CryptoRng, RngCore};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::sync::OnceLock;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};
const RANDOMNESS_DOMAIN_V1: &[u8] = b"iroha.privacy.bootle-lantern.prover-randomness.v1";
const SAMPLING_PROFILE_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha.privacy.bootle-lantern.sampling-profile-digest.v1";
const DECAY_TABLES_DIGEST_DOMAIN_V1: &[u8] = b"iroha.privacy.bootle-lantern.decay-tables-digest.v1";
/// Canonical algorithm/schema identity for the complete fixed prover sampler.
pub(crate) const BOOTLE_SAMPLING_PROFILE_DESCRIPTOR_V1: &[u8] = b"bootle-lantern-sampling-v1|seed:health-checked-crypto-rng-32|expand:SHAKE256(frame-u32be(domain)+frame-u32be(seed32)+frame-u32be(stage)+frame-u32be(stream-u64be))|uniform:u64be-largest-multiple-rejection|ternary:byte<255-mod3|gaussian:randomized-rounding-base-CDT-31/20+exact-rational-Q256-correction+strict-truncation|rejection:standard-or-bimodal-exact-dot-norm+Q256-threshold+strict-draw-less-than|decay:integer-table+fraction-table+residual-alternating-series-nearest-rounding|binding:all-domains+dimensions+caps+sigma+truncation+M-limbs+full-CDT+decay-geometry";
const Q256_FRACTION_BITS_V1: usize = 256;
const GAUSSIAN_VARIANCE_NUMERATOR_V1: u64 =
    GAUSSIAN_SIGMA_NUMERATOR_V1 * GAUSSIAN_SIGMA_NUMERATOR_V1;
const GAUSSIAN_HALF_VARIANCE_DENOMINATOR_V1: u64 =
    GAUSSIAN_SIGMA_DENOMINATOR_V1 * GAUSSIAN_SIGMA_DENOMINATOR_V1 / 2;
// The decay kernel splits x into floor(x), twelve fractional seed bits, and a
// residual below 2^-12.  The independently pinned Q256 seeds are within one
// ulp.  The 96-term unit series has remainder below 2^-504, the fractional
// seed series has a smaller remainder, and the 16-term residual series has
// remainder below 2^-252.  Including table accumulation and rounded products,
// the absolute evaluation error is below 2^16 Q256 ulps, i.e. below 2^-240.
const FRACTION_TABLE_BITS_V1: usize = 12;
const FRACTION_TABLE_LEN_V1: usize = 1 << FRACTION_TABLE_BITS_V1;
const MAX_DECAY_INTEGER_V1: usize = 178;
const UNIT_DECAY_SERIES_TERMS_V1: usize = 96;
const FRACTION_STEP_SERIES_TERMS_V1: usize = 32;
const RESIDUAL_DECAY_SERIES_TERMS_V1: usize = 16;
// Q256 nearest-integer tails for the distribution on non-negative integers
// proportional to exp(-200*m^2/961), which is the exact base width 31/20.
// Each entry is P[M > index] * 2^256.  They were generated at 600 decimal
// digits and independently checked with bc's arbitrary-precision elementary
// functions.  The first rounded-zero tail is index 29; the omitted M >= 30
// mass is below 2^-271.
const CDF_155_Q256_V1: [U256; 30] = [
    U256::from_be_hex("9731fa96ce33beaa95f28503ccbda2bcce489feb4248e1357ab2bd2c54034865"),
    U256::from_be_hex("4214fc88358f5c62562d6660c3b96279a4a9401a1a0bee29197d9e99bdb9b340"),
    U256::from_be_hex("147e977a5722be70c3cb084413c6ee772103c2d5b2895c46de68bbce39f01d34"),
    U256::from_be_hex("04640a0062b029f1f7674972e3a73e4577b61c0ba4260265efa1fc903cb8bdcf"),
    U256::from_be_hex("00a394528f410338ff27d65380a14595a41ca1f704c0fb03aa665da9ea485fad"),
    U256::from_be_hex("0010001e4da95f7f3594a26e72c04c13573de1990ed768ad6b421353953ba4ba"),
    U256::from_be_hex("00010b80b7d8b376c18e52feafb788e65c15698f0542da634ec8bc7af0903e6b"),
    U256::from_be_hex("00000b9d275b606fc6c1975553efed8f1d3b1b4a86f82161a935b62228abe520"),
    U256::from_be_hex("0000005593dd7d688ec1eaed32a05633fedebbbdc65828235594331c93359373"),
    U256::from_be_hex("00000001a14ef4311fbfda53c04cc4602bfdaa4cb728a1b27c1d74f84e8d9d30"),
    U256::from_be_hex("0000000005411dc0f7a28b70dbd116df213e4f1024f5da2b044cdb9b47b54e30"),
    U256::from_be_hex("00000000000b2fbfa8f5ea4ddcbbfb6ccdb9c189fe5429038300959a74a19e98"),
    U256::from_be_hex("0000000000000fb8fabc64e100b397453e250dfdebad1c09d6ff6fecb2770d2f"),
    U256::from_be_hex("000000000000000e9561792db7c6525eeac15e1e3d5648b91c195b2d908d0af7"),
    U256::from_be_hex("000000000000000008ecd7725eb87a2069931a9325df6532b6e19f3f2e47868a"),
    U256::from_be_hex("000000000000000000039a7e0798ac2fd999a284490a8720fa6d53b945c0bb58"),
    U256::from_be_hex("0000000000000000000000f5afb9e664232f9ceab439306933e3ee520b219122"),
    U256::from_be_hex("0000000000000000000000002b29083ce62e26a54aa1555be706b6a1236c0fbd"),
    U256::from_be_hex("0000000000000000000000000005003f89c4d244c169245a2607c2d40babd7b9"),
    U256::from_be_hex("00000000000000000000000000000061d732711c4d79e6d1b62a1564bf718428"),
    U256::from_be_hex("0000000000000000000000000000000004ee80074565786022970db0f57cd273"),
    U256::from_be_hex("00000000000000000000000000000000000029f87dcc63173c0f70083ed55367"),
    U256::from_be_hex("0000000000000000000000000000000000000000eb949486f458d32c785fdbc2"),
    U256::from_be_hex("00000000000000000000000000000000000000000003681af9356319f4082fc4"),
    U256::from_be_hex("00000000000000000000000000000000000000000000000851491377baa192f6"),
    U256::from_be_hex("000000000000000000000000000000000000000000000000000d64ba367a4dbc"),
    U256::from_be_hex("0000000000000000000000000000000000000000000000000000000e39604401"),
    U256::from_be_hex("000000000000000000000000000000000000000000000000000000000009f689"),
    U256::from_be_hex("0000000000000000000000000000000000000000000000000000000000000005"),
    U256::ZERO,
];
/// Closed sampling roles for the first Bootle/Lantern profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BootleSamplingProfileV1 {
    /// Standard rejection for the `z1` response.
    ResponseZ1,
    /// Bimodal rejection for the `z2` response.
    ResponseZ2,
    /// Bimodal rejection for the projected `z3` response.
    ProjectionZ3,
    /// Bimodal rejection for the projected `z4` response.
    ProjectionZ4,
}
impl BootleSamplingProfileV1 {
    const ALL: [Self; 4] = [
        Self::ResponseZ1,
        Self::ResponseZ2,
        Self::ProjectionZ3,
        Self::ProjectionZ4,
    ];
    const fn index(self) -> usize {
        match self {
            Self::ResponseZ1 => 0,
            Self::ResponseZ2 => 1,
            Self::ProjectionZ3 => 2,
            Self::ProjectionZ4 => 3,
        }
    }
    const fn log2_sigma(self) -> u8 {
        match self {
            Self::ResponseZ1 => 23,
            Self::ResponseZ2 => 12,
            Self::ProjectionZ3 => 18,
            Self::ProjectionZ4 => 29,
        }
    }
    const fn rejection_kind(self) -> RejectionKindV1 {
        match self {
            Self::ResponseZ1 => RejectionKindV1::Standard,
            Self::ResponseZ2 | Self::ProjectionZ3 | Self::ProjectionZ4 => RejectionKindV1::Bimodal,
        }
    }
    pub(crate) const fn expected_polynomials(self) -> usize {
        match self {
            Self::ResponseZ1 => TBOX_M1_V1,
            Self::ResponseZ2 => TBOX_M2_V1,
            Self::ProjectionZ3 | Self::ProjectionZ4 => 256 / APPLICATION_RING_DEGREE_V1,
        }
    }
    const fn expected_coefficients(self) -> usize {
        self.expected_polynomials() * APPLICATION_RING_DEGREE_V1
    }
    const fn truncation_bound(self) -> i64 {
        GAUSSIAN_TRUNCATION_BOUNDS_V1[self.index()]
    }
    fn rejection_m_q256(self) -> U512 {
        // The profile limbs are fixed u64 values, not target-sized bigint words.
        let mut bytes = [0_u8; 64];
        for (chunk, limb) in bytes
            .chunks_exact_mut(8)
            .zip(REJECTION_M_Q256_LIMBS_V1[self.index()])
        {
            chunk.copy_from_slice(&limb.to_le_bytes());
        }
        U512::from_le_bytes(bytes)
    }
    const fn fraction_domain(self) -> &'static [u8] {
        match self {
            Self::ResponseZ1 => b"gaussian-z1-fraction-v1",
            Self::ResponseZ2 => b"gaussian-z2-fraction-v1",
            Self::ProjectionZ3 => b"gaussian-z3-fraction-v1",
            Self::ProjectionZ4 => b"gaussian-z4-fraction-v1",
        }
    }
    const fn sign_domain(self) -> &'static [u8] {
        match self {
            Self::ResponseZ1 => b"gaussian-z1-sign-v1",
            Self::ResponseZ2 => b"gaussian-z2-sign-v1",
            Self::ProjectionZ3 => b"gaussian-z3-sign-v1",
            Self::ProjectionZ4 => b"gaussian-z4-sign-v1",
        }
    }
    const fn cdf_domain(self) -> &'static [u8] {
        match self {
            Self::ResponseZ1 => b"gaussian-z1-cdf-v1",
            Self::ResponseZ2 => b"gaussian-z2-cdf-v1",
            Self::ProjectionZ3 => b"gaussian-z3-cdf-v1",
            Self::ProjectionZ4 => b"gaussian-z4-cdf-v1",
        }
    }
    const fn gaussian_accept_domain(self) -> &'static [u8] {
        match self {
            Self::ResponseZ1 => b"gaussian-z1-accept-v1",
            Self::ResponseZ2 => b"gaussian-z2-accept-v1",
            Self::ProjectionZ3 => b"gaussian-z3-accept-v1",
            Self::ProjectionZ4 => b"gaussian-z4-accept-v1",
        }
    }
    const fn rejection_domain(self) -> &'static [u8] {
        match self {
            Self::ResponseZ1 => b"response-z1-rejection-v1",
            Self::ResponseZ2 => b"response-z2-rejection-v1",
            Self::ProjectionZ3 => b"projection-z3-rejection-v1",
            Self::ProjectionZ4 => b"projection-z4-rejection-v1",
        }
    }
}
#[derive(Clone)]
struct BootleSamplingProfileBindingV1 {
    algorithm_descriptor: &'static [u8],
    randomness_domain: &'static [u8],
    producer_randomness_policy: &'static [u8],
    ring_degree: usize,
    proof_modulus: u64,
    uniform_rejection_attempts: u32,
    gaussian_coefficient_attempts: u32,
    proof_sampling_attempts: u32,
    projection_sampling_attempts: u32,
    response_sampling_attempts: u32,
    sigma_numerator: u64,
    sigma_denominator: u64,
    q256_fraction_bits: usize,
    fraction_table_bits: usize,
    max_decay_integer: usize,
    unit_decay_series_terms: usize,
    fraction_step_series_terms: usize,
    residual_decay_series_terms: usize,
    log2_sigma: [u8; 4],
    expected_polynomials: [usize; 4],
    rejection_kinds: [u8; 4],
    truncation_bounds: [i64; 4],
    rejection_m_q256_limbs: [[u64; 5]; 4],
    cdf_155_q256: [U256; 30],
    decay_tables_digest: [u8; 32],
    fraction_domains: [&'static [u8]; 4],
    sign_domains: [&'static [u8]; 4],
    cdf_domains: [&'static [u8]; 4],
    gaussian_accept_domains: [&'static [u8]; 4],
    rejection_domains: [&'static [u8]; 4],
}
fn bootle_sampling_profile_binding_v1() -> BootleSamplingProfileBindingV1 {
    let profiles = BootleSamplingProfileV1::ALL;
    BootleSamplingProfileBindingV1 {
        algorithm_descriptor: BOOTLE_SAMPLING_PROFILE_DESCRIPTOR_V1,
        randomness_domain: RANDOMNESS_DOMAIN_V1,
        producer_randomness_policy: CURVE_PROVER_RANDOMNESS_POLICY_V1,
        ring_degree: APPLICATION_RING_DEGREE_V1,
        proof_modulus: PROOF_MODULUS_V1,
        uniform_rejection_attempts: MAX_UNIFORM_REJECTION_ATTEMPTS_V1,
        gaussian_coefficient_attempts: MAX_GAUSSIAN_COEFFICIENT_ATTEMPTS_V1,
        proof_sampling_attempts: MAX_PROOF_SAMPLING_ATTEMPTS_V1,
        projection_sampling_attempts: MAX_PROJECTION_SAMPLING_ATTEMPTS_PER_PROVE_ATTEMPT_V1,
        response_sampling_attempts: MAX_RESPONSE_SAMPLING_ATTEMPTS_PER_PROVE_ATTEMPT_V1,
        sigma_numerator: GAUSSIAN_SIGMA_NUMERATOR_V1,
        sigma_denominator: GAUSSIAN_SIGMA_DENOMINATOR_V1,
        q256_fraction_bits: Q256_FRACTION_BITS_V1,
        fraction_table_bits: FRACTION_TABLE_BITS_V1,
        max_decay_integer: MAX_DECAY_INTEGER_V1,
        unit_decay_series_terms: UNIT_DECAY_SERIES_TERMS_V1,
        fraction_step_series_terms: FRACTION_STEP_SERIES_TERMS_V1,
        residual_decay_series_terms: RESIDUAL_DECAY_SERIES_TERMS_V1,
        log2_sigma: profiles.map(BootleSamplingProfileV1::log2_sigma),
        expected_polynomials: profiles.map(BootleSamplingProfileV1::expected_polynomials),
        rejection_kinds: profiles.map(|profile| match profile.rejection_kind() {
            RejectionKindV1::Standard => 0,
            RejectionKindV1::Bimodal => 1,
        }),
        truncation_bounds: GAUSSIAN_TRUNCATION_BOUNDS_V1,
        rejection_m_q256_limbs: REJECTION_M_Q256_LIMBS_V1,
        cdf_155_q256: CDF_155_Q256_V1,
        decay_tables_digest: decay_tables_digest_v1(),
        fraction_domains: profiles.map(BootleSamplingProfileV1::fraction_domain),
        sign_domains: profiles.map(BootleSamplingProfileV1::sign_domain),
        cdf_domains: profiles.map(BootleSamplingProfileV1::cdf_domain),
        gaussian_accept_domains: profiles.map(BootleSamplingProfileV1::gaussian_accept_domain),
        rejection_domains: profiles.map(BootleSamplingProfileV1::rejection_domain),
    }
}
fn absorb_sampling_profile_field_v1(state: &mut Shake256, label: &[u8], value: &[u8]) {
    absorb_frame(state, label);
    absorb_frame(state, value);
}
fn usize_to_u64_be_v1(value: usize) -> [u8; 8] {
    u64::try_from(value)
        .expect("fixed sampling-profile value fits u64")
        .to_be_bytes()
}
fn sampling_profile_digest_from_binding_v1(binding: &BootleSamplingProfileBindingV1) -> [u8; 32] {
    let mut state = Shake256::default();
    absorb_frame(&mut state, SAMPLING_PROFILE_DIGEST_DOMAIN_V1);
    absorb_sampling_profile_field_v1(
        &mut state,
        b"algorithm_descriptor",
        binding.algorithm_descriptor,
    );
    absorb_sampling_profile_field_v1(&mut state, b"randomness_domain", binding.randomness_domain);
    absorb_sampling_profile_field_v1(
        &mut state,
        b"producer_randomness_policy",
        binding.producer_randomness_policy,
    );
    absorb_sampling_profile_field_v1(
        &mut state,
        b"ring_degree",
        &usize_to_u64_be_v1(binding.ring_degree),
    );
    absorb_sampling_profile_field_v1(
        &mut state,
        b"proof_modulus",
        &binding.proof_modulus.to_be_bytes(),
    );
    for (label, value) in [
        (
            b"uniform_rejection_attempts".as_slice(),
            binding.uniform_rejection_attempts,
        ),
        (
            b"gaussian_coefficient_attempts".as_slice(),
            binding.gaussian_coefficient_attempts,
        ),
        (
            b"proof_sampling_attempts".as_slice(),
            binding.proof_sampling_attempts,
        ),
        (
            b"projection_sampling_attempts".as_slice(),
            binding.projection_sampling_attempts,
        ),
        (
            b"response_sampling_attempts".as_slice(),
            binding.response_sampling_attempts,
        ),
    ] {
        absorb_sampling_profile_field_v1(&mut state, label, &value.to_be_bytes());
    }
    for (label, value) in [
        (b"sigma_numerator".as_slice(), binding.sigma_numerator),
        (b"sigma_denominator".as_slice(), binding.sigma_denominator),
    ] {
        absorb_sampling_profile_field_v1(&mut state, label, &value.to_be_bytes());
    }
    for (label, value) in [
        (b"q256_fraction_bits".as_slice(), binding.q256_fraction_bits),
        (
            b"fraction_table_bits".as_slice(),
            binding.fraction_table_bits,
        ),
        (b"max_decay_integer".as_slice(), binding.max_decay_integer),
        (
            b"unit_decay_series_terms".as_slice(),
            binding.unit_decay_series_terms,
        ),
        (
            b"fraction_step_series_terms".as_slice(),
            binding.fraction_step_series_terms,
        ),
        (
            b"residual_decay_series_terms".as_slice(),
            binding.residual_decay_series_terms,
        ),
    ] {
        absorb_sampling_profile_field_v1(&mut state, label, &usize_to_u64_be_v1(value));
    }
    absorb_sampling_profile_field_v1(&mut state, b"log2_sigma", &binding.log2_sigma);
    absorb_frame(&mut state, b"expected_polynomials");
    for value in binding.expected_polynomials {
        absorb_frame(&mut state, &usize_to_u64_be_v1(value));
    }
    absorb_sampling_profile_field_v1(&mut state, b"rejection_kinds", &binding.rejection_kinds);
    absorb_frame(&mut state, b"truncation_bounds");
    for value in binding.truncation_bounds {
        absorb_frame(&mut state, &value.to_be_bytes());
    }
    absorb_frame(&mut state, b"rejection_m_q256_limbs_le");
    for profile in binding.rejection_m_q256_limbs {
        for limb in profile {
            absorb_frame(&mut state, &limb.to_be_bytes());
        }
    }
    absorb_frame(&mut state, b"cdf_155_q256_be");
    for threshold in binding.cdf_155_q256 {
        absorb_frame(&mut state, &threshold.to_be_bytes());
    }
    absorb_sampling_profile_field_v1(
        &mut state,
        b"decay_tables_digest",
        &binding.decay_tables_digest,
    );
    for (label, domains) in [
        (b"fraction_domains".as_slice(), binding.fraction_domains),
        (b"sign_domains".as_slice(), binding.sign_domains),
        (b"cdf_domains".as_slice(), binding.cdf_domains),
        (
            b"gaussian_accept_domains".as_slice(),
            binding.gaussian_accept_domains,
        ),
        (b"rejection_domains".as_slice(), binding.rejection_domains),
    ] {
        absorb_frame(&mut state, label);
        for domain in domains {
            absorb_frame(&mut state, domain);
        }
    }
    let mut output = [0_u8; 32];
    let mut reader = state.finalize_xof();
    reader.read(&mut output);
    output
}
/// Digest of every fixed sampling distribution, domain, cap, and approximation.
#[must_use]
pub(crate) fn bootle_sampling_profile_digest_v1() -> [u8; 32] {
    static DIGEST: OnceLock<[u8; 32]> = OnceLock::new();
    *DIGEST.get_or_init(|| {
        sampling_profile_digest_from_binding_v1(&bootle_sampling_profile_binding_v1())
    })
}
fn decay_tables_digest_v1() -> [u8; 32] {
    let mut state = Shake256::default();
    absorb_frame(&mut state, DECAY_TABLES_DIGEST_DOMAIN_V1);
    absorb_frame(&mut state, b"integer_decay_table_q256_be");
    for value in integer_decay_table_q256_v1() {
        absorb_frame(&mut state, &value.to_be_bytes());
    }
    absorb_frame(&mut state, b"fraction_decay_table_q256_be");
    for value in fraction_decay_table_q256_v1() {
        absorb_frame(&mut state, &value.to_be_bytes());
    }
    let mut output = [0_u8; 32];
    let mut reader = state.finalize_xof();
    reader.read(&mut output);
    output
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RejectionKindV1 {
    Standard,
    Bimodal,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BernoulliThresholdV1 {
    Never,
    Finite(U256),
    Always,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SignedQ256V1 {
    negative: bool,
    magnitude: U512,
}
impl SignedQ256V1 {
    fn new(negative: bool, magnitude: U512) -> Self {
        Self {
            negative: negative && magnitude != U512::ZERO,
            magnitude,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SignedMagnitudeV1 {
    negative: bool,
    magnitude: U256,
}
impl SignedMagnitudeV1 {
    fn difference(lhs: U256, rhs: U256) -> Self {
        match lhs.cmp(&rhs) {
            core::cmp::Ordering::Less => Self {
                negative: true,
                magnitude: rhs.wrapping_sub(&lhs),
            },
            core::cmp::Ordering::Equal => Self {
                negative: false,
                magnitude: U256::ZERO,
            },
            core::cmp::Ordering::Greater => Self {
                negative: false,
                magnitude: lhs.wrapping_sub(&rhs),
            },
        }
    }
}
/// Domain-separated deterministic expansion of one caller-provided seed.
pub(crate) struct ProofRandomnessV1 {
    seed: Zeroizing<[u8; 32]>,
    stream: u64,
}
impl core::fmt::Debug for ProofRandomnessV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProofRandomnessV1(<redacted>)")
    }
}
impl Drop for ProofRandomnessV1 {
    fn drop(&mut self) {
        self.seed.zeroize();
        self.stream.zeroize();
    }
}
impl ProofRandomnessV1 {
    /// Collect a fresh seed from a fallible cryptographic RNG.
    ///
    /// # Errors
    ///
    /// Propagates RNG failure and rejects constant or short-period catastrophic-health sentinels.
    pub(crate) fn from_rng<R: CryptoRng + RngCore>(rng: &mut R) -> Result<Self, SamplingErrorV1> {
        let mut checked_rng = HealthCheckedCryptoRngV1::new(rng).map_err(|error| match error {
            ProverRandomnessErrorV1::Unavailable => SamplingErrorV1::RandomnessUnavailable,
            ProverRandomnessErrorV1::Unhealthy => SamplingErrorV1::RandomnessHealthCheckFailed,
        })?;
        let mut seed = Zeroizing::new([0_u8; 32]);
        checked_rng
            .try_fill_bytes(seed.as_mut())
            .map_err(|_| SamplingErrorV1::RandomnessUnavailable)?;
        if *seed == [0; 32] || seed.iter().all(|byte| *byte == seed[0]) {
            seed.zeroize();
            return Err(SamplingErrorV1::RandomnessHealthCheckFailed);
        }
        Ok(Self { seed, stream: 0 })
    }
    /// Construct a deterministic stream for known-answer and differential
    /// tests.  This is deliberately crate-private so production callers must
    /// supply a `CryptoRng`.
    #[cfg(test)]
    pub(crate) fn for_test(seed: [u8; 32]) -> Result<Self, SamplingErrorV1> {
        if seed == [0; 32] || seed.iter().all(|byte| *byte == seed[0]) {
            return Err(SamplingErrorV1::RandomnessHealthCheckFailed);
        }
        Ok(Self {
            seed: Zeroizing::new(seed),
            stream: 0,
        })
    }
    /// Fill bytes from a separately framed SHAKE256 stream.
    pub(crate) fn fill_bytes(&mut self, domain: &[u8], output: &mut [u8]) {
        let mut state = Shake256::default();
        absorb_frame(&mut state, RANDOMNESS_DOMAIN_V1);
        absorb_frame(&mut state, self.seed.as_slice());
        absorb_frame(&mut state, domain);
        absorb_frame(&mut state, &self.stream.to_be_bytes());
        self.stream = self
            .stream
            .checked_add(1)
            .expect("fixed proof work cannot exhaust u64 streams");
        let mut reader = state.finalize_xof();
        reader.read(output);
    }
    /// Draw one unbiased sign in `{ -1, +1 }`.
    pub(crate) fn sign(&mut self, domain: &[u8]) -> i64 {
        let mut byte = [0_u8; 1];
        self.fill_bytes(domain, &mut byte);
        if byte[0] & 1 == 0 { 1 } else { -1 }
    }
    /// Draw one unbiased ternary coefficient within the fixed work budget.
    ///
    /// # Errors
    ///
    /// Returns [`SamplingErrorV1::UniformSamplingExhausted`] if every bounded
    /// proposal is the sole rejected byte value.
    pub(crate) fn ternary(&mut self, domain: &[u8]) -> Result<i64, SamplingErrorV1> {
        for _ in 0..MAX_UNIFORM_REJECTION_ATTEMPTS_V1 {
            let mut byte = [0_u8; 1];
            self.fill_bytes(domain, &mut byte);
            if byte[0] < 255 {
                return Ok(i64::from(byte[0] % 3) - 1);
            }
        }
        Err(SamplingErrorV1::UniformSamplingExhausted)
    }
    /// Draw one uniform proof-ring polynomial.
    pub(crate) fn uniform_polynomial(
        &mut self,
        domain: &[u8],
    ) -> Result<ProofPolynomialV1, SamplingErrorV1> {
        let mut coefficients = [0_u64; APPLICATION_RING_DEGREE_V1];
        for coefficient in &mut coefficients {
            *coefficient = self.uniform_modulus(domain, PROOF_MODULUS_V1)?;
        }
        ProofPolynomialV1::new(coefficients).map_err(|_| SamplingErrorV1::InternalInvariant)
    }
    /// Draw one polynomial with independent ternary coefficients.
    pub(crate) fn ternary_polynomial(
        &mut self,
        domain: &[u8],
    ) -> Result<ProofPolynomialV1, SamplingErrorV1> {
        let mut coefficients = [0_i64; APPLICATION_RING_DEGREE_V1];
        for coefficient in &mut coefficients {
            *coefficient = self.ternary(domain)?;
        }
        Ok(ProofPolynomialV1::from_centered_coefficients(coefficients))
    }
    /// Draw one centered discrete-Gaussian polynomial for a closed profile.
    pub(crate) fn gaussian_polynomial(
        &mut self,
        profile: BootleSamplingProfileV1,
    ) -> Result<ProofPolynomialV1, SamplingErrorV1> {
        let mut coefficients = [0_i64; APPLICATION_RING_DEGREE_V1];
        for coefficient in &mut coefficients {
            *coefficient = self.gaussian_coefficient(profile)?;
        }
        Ok(ProofPolynomialV1::from_centered_coefficients(coefficients))
    }
    /// Apply the rejection decision fixed by `profile`.
    ///
    /// The exact sampled variance is `961 * 2^(2k) / 400`; no rounded
    /// variance is admitted at this boundary.  Q256 decay and ratio
    /// quantization contribute less than `2^-232` statistical distance per
    /// decision.  Even under the shared proof work ceiling, aggregate
    /// implementation distance is below `2^-195`.
    pub(crate) fn accept_rejection(
        &mut self,
        z: &[i64],
        shift: &[i64],
        profile: BootleSamplingProfileV1,
    ) -> Result<bool, SamplingErrorV1> {
        if z.len() != profile.expected_coefficients() || shift.len() != z.len() {
            return Err(SamplingErrorV1::InvalidRejectionShape);
        }
        let (dot, norm) = dot_and_norm(z, shift)?;
        let threshold = match profile.rejection_kind() {
            RejectionKindV1::Standard => standard_rejection_threshold_v1(dot, norm, profile),
            RejectionKindV1::Bimodal => bimodal_rejection_threshold_v1(dot, norm, profile),
        };
        Ok(self.bernoulli_q256(profile.rejection_domain(), threshold))
    }
    fn gaussian_coefficient(
        &mut self,
        profile: BootleSamplingProfileV1,
    ) -> Result<i64, SamplingErrorV1> {
        let scale = 1_u64 << profile.log2_sigma();
        let fractional = self.uniform_modulus(profile.fraction_domain(), scale)?;
        for _ in 0..MAX_GAUSSIAN_COEFFICIENT_ATTEMPTS_V1 {
            let positive_branch = self.sign(profile.sign_domain()) < 0;
            let magnitude = self.cdf155_sample(profile.cdf_domain());
            let candidate = if positive_branch {
                i64::from(magnitude) + 1
            } else {
                -i64::from(magnitude)
            };
            let exponent = gaussian_correction_exponent_q256_v1(
                u64::from(magnitude),
                positive_branch,
                fractional,
                scale,
            );
            if self.bernoulli_q256(
                profile.gaussian_accept_domain(),
                decay_threshold_v1(exponent),
            ) {
                let sample = candidate
                    .checked_mul(i64::try_from(scale).expect("closed scale fits i64"))
                    .and_then(|scaled| {
                        scaled.checked_sub(
                            i64::try_from(fractional).expect("fractional value fits i64"),
                        )
                    })
                    .ok_or(SamplingErrorV1::ArithmeticOverflow)?;
                if sample.unsigned_abs()
                    <= u64::try_from(profile.truncation_bound())
                        .expect("closed truncation bound is positive")
                {
                    return Ok(sample);
                }
            }
        }
        Err(SamplingErrorV1::GaussianSamplingExhausted)
    }
    fn cdf155_sample(&mut self, domain: &[u8]) -> u32 {
        let mut bytes = [0_u8; 32];
        self.fill_bytes(domain, &mut bytes);
        cdf155_index_v1(U256::from_be_bytes(bytes))
    }
    fn bernoulli_q256(&mut self, domain: &[u8], threshold: BernoulliThresholdV1) -> bool {
        let mut bytes = [0_u8; 32];
        self.fill_bytes(domain, &mut bytes);
        let draw = U256::from_be_bytes(bytes);
        match threshold {
            BernoulliThresholdV1::Never => false,
            BernoulliThresholdV1::Finite(threshold) => draw < threshold,
            BernoulliThresholdV1::Always => true,
        }
    }
    fn uniform_modulus(&mut self, domain: &[u8], modulus: u64) -> Result<u64, SamplingErrorV1> {
        if modulus == 0 {
            return Err(SamplingErrorV1::InternalInvariant);
        }
        let range = 1_u128 << 64;
        let modulus_wide = u128::from(modulus);
        let limit = (range / modulus_wide) * modulus_wide;
        for _ in 0..MAX_UNIFORM_REJECTION_ATTEMPTS_V1 {
            let mut bytes = [0_u8; 8];
            self.fill_bytes(domain, &mut bytes);
            let candidate = u128::from(u64::from_be_bytes(bytes));
            if candidate < limit {
                return Ok(
                    u64::try_from(candidate % modulus_wide).expect("residue below a u64 modulus")
                );
            }
        }
        Err(SamplingErrorV1::UniformSamplingExhausted)
    }
}
fn absorb_frame(state: &mut Shake256, bytes: &[u8]) {
    let length = u32::try_from(bytes.len()).expect("fixed randomness frame fits u32");
    state.update(&length.to_be_bytes());
    state.update(bytes);
}
fn cdf155_index_v1(draw: U256) -> u32 {
    let mut sample = 0_usize;
    while sample + 1 < CDF_155_Q256_V1.len() && draw < CDF_155_Q256_V1[sample] {
        sample += 1;
    }
    u32::try_from(sample).expect("fixed CDF index fits u32")
}
fn gaussian_correction_exponent_q256_v1(
    magnitude: u64,
    positive_branch: bool,
    fractional: u64,
    scale: u64,
) -> U512 {
    debug_assert!(fractional < scale);
    let offset = if positive_branch {
        scale - fractional
    } else {
        fractional
    };
    // For the negative branch:
    //   D = f * (2*m*s + f).
    // For the positive branch, with r = s-f:
    //   D = r * (2*m*s + r).
    // In both cases x = 200*D/(961*s^2), without subtracting close squares.
    let offset = U256::from_u64(offset);
    let linear = U256::from_u64(magnitude)
        .wrapping_mul(&U256::from_u64(scale))
        .shl_vartime(1)
        .wrapping_add(&offset);
    let delta: U512 = offset.mul(&linear);
    let numerator = delta
        .wrapping_mul(&U512::from_u64(GAUSSIAN_HALF_VARIANCE_DENOMINATOR_V1))
        .shl_vartime(Q256_FRACTION_BITS_V1);
    let denominator = U512::from_u128(
        u128::from(scale) * u128::from(scale) * u128::from(GAUSSIAN_VARIANCE_NUMERATOR_V1),
    );
    rational_to_q256_round_v1(numerator, denominator)
}
fn standard_rejection_threshold_v1(
    dot: i128,
    norm: u128,
    profile: BootleSamplingProfileV1,
) -> BernoulliThresholdV1 {
    let norm = U256::from_u128(norm);
    let twice_dot = U256::from_u128(dot.unsigned_abs()).shl_vartime(1);
    let numerator = if dot.is_negative() {
        SignedMagnitudeV1 {
            negative: false,
            magnitude: norm.wrapping_add(&twice_dot),
        }
    } else {
        SignedMagnitudeV1::difference(norm, twice_dot)
    };
    let exponent =
        scaled_profile_exponent_q256_v1(numerator, GAUSSIAN_HALF_VARIANCE_DENOMINATOR_V1, profile);
    let decay = decay_q256_v1(exponent.magnitude);
    if exponent.negative {
        ratio_threshold_q256_v1(decay, profile.rejection_m_q256())
    } else {
        ratio_threshold_q256_v1(
            q256_one_v1(),
            q256_mul_round_v1(profile.rejection_m_q256(), decay),
        )
    }
}
fn bimodal_rejection_threshold_v1(
    dot: i128,
    norm: u128,
    profile: BootleSamplingProfileV1,
) -> BernoulliThresholdV1 {
    let absolute_dot = U256::from_u128(dot.unsigned_abs());
    let twice_dot = absolute_dot.shl_vartime(1);
    let difference = scaled_profile_exponent_q256_v1(
        SignedMagnitudeV1::difference(twice_dot, U256::from_u128(norm)),
        GAUSSIAN_HALF_VARIANCE_DENOMINATOR_V1,
        profile,
    );
    let twice_t = unsigned_profile_exponent_q256_v1(
        absolute_dot,
        4 * GAUSSIAN_HALF_VARIANCE_DENOMINATOR_V1,
        profile,
    );
    let difference_decay = decay_q256_v1(difference.magnitude);
    let twice_t_decay = decay_q256_v1(twice_t);
    let one_plus_twice_t_decay = q256_one_v1().wrapping_add(&twice_t_decay);
    if difference.negative {
        // d = |<z,v>|/sigma^2 - ||v||^2/(2*sigma^2) < 0:
        // p = 2 / (M * exp(d) * (1 + exp(-2|<z,v>|/sigma^2))).
        let denominator = q256_mul_round_v1(
            q256_mul_round_v1(profile.rejection_m_q256(), difference_decay),
            one_plus_twice_t_decay,
        );
        ratio_threshold_q256_v1(q256_one_v1().shl_vartime(1), denominator)
    } else {
        // d >= 0:
        // p = 2*exp(-d) / (M * (1 + exp(-2|<z,v>|/sigma^2))).
        let denominator = q256_mul_round_v1(profile.rejection_m_q256(), one_plus_twice_t_decay);
        ratio_threshold_q256_v1(difference_decay.shl_vartime(1), denominator)
    }
}
fn scaled_profile_exponent_q256_v1(
    value: SignedMagnitudeV1,
    factor: u64,
    profile: BootleSamplingProfileV1,
) -> SignedQ256V1 {
    SignedQ256V1::new(
        value.negative,
        unsigned_profile_exponent_q256_v1(value.magnitude, factor, profile),
    )
}
fn unsigned_profile_exponent_q256_v1(
    value: U256,
    factor: u64,
    profile: BootleSamplingProfileV1,
) -> U512 {
    let product: U512 = value.mul(&U256::from_u64(factor));
    let numerator = product.shl_vartime(Q256_FRACTION_BITS_V1);
    let denominator = U512::from_u64(GAUSSIAN_VARIANCE_NUMERATOR_V1)
        .shl_vartime(usize::from(profile.log2_sigma()) * 2);
    rational_to_q256_round_v1(numerator, denominator)
}
fn rational_to_q256_round_v1(numerator: U512, denominator: U512) -> U512 {
    let nonzero = Option::<NonZero<U512>>::from(NonZero::new(denominator))
        .expect("closed rational denominator is non-zero");
    let (quotient, remainder) = numerator.div_rem(&nonzero);
    if remainder.shl_vartime(1) >= denominator {
        quotient.wrapping_add(&U512::ONE)
    } else {
        quotient
    }
}
fn q256_one_v1() -> U512 {
    U512::ONE.shl_vartime(Q256_FRACTION_BITS_V1)
}
fn q256_mul_round_v1(left: U512, right: U512) -> U512 {
    // All callers prove operands below 6 * 2^256.  The product and half-ulp
    // rounding term therefore fit U1024, and the rounded result fits U512.
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
    let divisor = u32::try_from(divisor).expect("fixed Taylor divisor fits u32");
    let nonzero = Option::<NonZero<Limb>>::from(NonZero::new(Limb::from_u32(divisor)))
        .expect("fixed Taylor divisor is non-zero");
    value
        .wrapping_add(&U512::from_u64(u64::from(divisor >> 1)))
        .div_rem_limb(nonzero)
        .0
}
fn small_decay_q256_v1(value: U512, terms: usize) -> U512 {
    let mut sum = q256_one_v1();
    let mut term = sum;
    for index in 1..=terms {
        let divisor = u64::try_from(index).expect("fixed series length fits u64");
        term = q256_div_small_round_v1(q256_mul_round_v1(term, value), divisor);
        if term == U512::ZERO {
            break;
        }
        if index % 2 == 0 {
            sum = sum.wrapping_add(&term);
        } else {
            sum = sum.wrapping_sub(&term);
        }
    }
    sum
}
fn integer_decay_table_q256_v1() -> &'static [U512; MAX_DECAY_INTEGER_V1 + 1] {
    static TABLE: OnceLock<Box<[U512; MAX_DECAY_INTEGER_V1 + 1]>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let one = q256_one_v1();
        let decay_one = small_decay_q256_v1(one, UNIT_DECAY_SERIES_TERMS_V1);
        let mut table = vec![U512::ZERO; MAX_DECAY_INTEGER_V1 + 1];
        table[0] = one;
        for index in 1..table.len() {
            table[index] = q256_mul_round_v1(table[index - 1], decay_one);
        }
        table
            .into_boxed_slice()
            .try_into()
            .unwrap_or_else(|_| unreachable!("fixed integer-decay table length"))
    })
}
fn fraction_decay_table_q256_v1() -> &'static [U512; FRACTION_TABLE_LEN_V1] {
    // Keep the 256 KiB table heap-owned. Returning a fixed array from the
    // `OnceLock` initializer makes unoptimized builds materialize several
    // full-size return buffers on the caller's stack, which is unsafe for FFI
    // callers with legitimately small native thread stacks.
    static TABLE: OnceLock<Box<[U512; FRACTION_TABLE_LEN_V1]>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let one = q256_one_v1();
        let step = U512::ONE.shl_vartime(Q256_FRACTION_BITS_V1 - FRACTION_TABLE_BITS_V1);
        let decay_step = small_decay_q256_v1(step, FRACTION_STEP_SERIES_TERMS_V1);
        let mut table = vec![U512::ZERO; FRACTION_TABLE_LEN_V1];
        table[0] = one;
        for index in 1..table.len() {
            table[index] = q256_mul_round_v1(table[index - 1], decay_step);
        }
        table
            .into_boxed_slice()
            .try_into()
            .unwrap_or_else(|_| unreachable!("fixed fractional-decay table length"))
    })
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
fn decay_threshold_v1(value: U512) -> BernoulliThresholdV1 {
    let (high, low) = decay_q256_v1(value).split();
    if high != U256::ZERO {
        BernoulliThresholdV1::Always
    } else if low == U256::ZERO {
        BernoulliThresholdV1::Never
    } else {
        BernoulliThresholdV1::Finite(low)
    }
}
fn ratio_threshold_q256_v1(numerator: U512, denominator: U512) -> BernoulliThresholdV1 {
    if numerator == U512::ZERO {
        return BernoulliThresholdV1::Never;
    }
    if denominator == U512::ZERO || numerator >= denominator {
        return BernoulliThresholdV1::Always;
    }
    let scaled = U1024::from(&numerator).shl_vartime(Q256_FRACTION_BITS_V1);
    let denominator = U1024::from(&denominator);
    let nonzero = Option::<NonZero<U1024>>::from(NonZero::new(denominator))
        .expect("ordered ratio denominator is non-zero");
    let quotient = scaled.div_rem(&nonzero).0;
    let (high, low) = quotient.split();
    debug_assert_eq!(high, U512::ZERO);
    let (high, low) = low.split();
    debug_assert_eq!(high, U256::ZERO);
    if low == U256::ZERO {
        BernoulliThresholdV1::Never
    } else {
        BernoulliThresholdV1::Finite(low)
    }
}
fn dot_and_norm(lhs: &[i64], rhs: &[i64]) -> Result<(i128, u128), SamplingErrorV1> {
    let mut dot = 0_i128;
    let mut norm = 0_u128;
    for (lhs, rhs) in lhs.iter().copied().zip(rhs.iter().copied()) {
        dot = dot
            .checked_add(i128::from(lhs) * i128::from(rhs))
            .ok_or(SamplingErrorV1::ArithmeticOverflow)?;
        let magnitude = u128::from(rhs.unsigned_abs());
        norm = norm
            .checked_add(
                magnitude
                    .checked_mul(magnitude)
                    .ok_or(SamplingErrorV1::ArithmeticOverflow)?,
            )
            .ok_or(SamplingErrorV1::ArithmeticOverflow)?;
    }
    Ok((dot, norm))
}
/// Bounded sampling failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum SamplingErrorV1 {
    /// The external cryptographic RNG failed.
    #[error("Bootle/Lantern cryptographic randomness is unavailable")]
    RandomnessUnavailable,
    /// The seed matched a catastrophic stuck-RNG sentinel.
    #[error("Bootle/Lantern cryptographic randomness failed its health check")]
    RandomnessHealthCheckFailed,
    /// A Gaussian vector was requested with the wrong closed profile shape.
    #[error("Bootle/Lantern Gaussian vector shape does not match its closed profile")]
    InvalidGaussianShape,
    /// A rejection vector did not have the exact closed profile shape.
    #[error("Bootle/Lantern rejection vector shape does not match its closed profile")]
    InvalidRejectionShape,
    /// Uniform rejection exceeded its fixed work budget.
    #[error("Bootle/Lantern uniform sampling exhausted its fixed work budget")]
    UniformSamplingExhausted,
    /// Gaussian rejection exceeded its fixed work budget.
    #[error("Bootle/Lantern Gaussian sampling exhausted its fixed work budget")]
    GaussianSamplingExhausted,
    /// Checked integer arithmetic overflowed.
    #[error("Bootle/Lantern sampling arithmetic overflowed")]
    ArithmeticOverflow,
    /// A fixed internal invariant failed.
    #[error("Bootle/Lantern sampling internal invariant failed")]
    InternalInvariant,
}
// INTEGER_ONLY_PRODUCTION_END
#[cfg(test)]
#[path = "sampling_integer_tests.rs"]
mod tests;
