use super::*;
use rand_core_06::{CryptoRng, Error as RngError, RngCore};
use zeroize::Zeroizing;
struct TestRng {
    state: u64,
    fail: bool,
    stuck: Option<u8>,
}
impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0_u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }
    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0_u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }
    fn fill_bytes(&mut self, destination: &mut [u8]) {
        self.try_fill_bytes(destination)
            .expect("infallible test invocation");
    }
    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RngError> {
        if self.fail {
            return Err(RngError::new("injected failure"));
        }
        if let Some(byte) = self.stuck {
            destination.fill(byte);
            return Ok(());
        }
        for byte in destination {
            self.state ^= self.state << 13;
            self.state ^= self.state >> 7;
            self.state ^= self.state << 17;
            *byte = self.state as u8;
        }
        Ok(())
    }
}
impl CryptoRng for TestRng {}
fn test_seed() -> [u8; 32] {
    core::array::from_fn(|index| u8::try_from(index + 1).expect("index fits"))
}
fn test_randomness() -> ProofRandomnessV1 {
    ProofRandomnessV1::for_test(test_seed()).expect("healthy deterministic seed")
}
fn finite_threshold(value: BernoulliThresholdV1) -> U256 {
    match value {
        BernoulliThresholdV1::Finite(value) => value,
        other => panic!("expected finite threshold, got {other:?}"),
    }
}
fn absolute_difference(left: U256, right: U256) -> U256 {
    if left >= right {
        left.wrapping_sub(&right)
    } else {
        right.wrapping_sub(&left)
    }
}
fn rational_q256(numerator: u64, denominator: u64) -> U512 {
    rational_to_q256_round_v1(
        U512::from_u64(numerator).shl_vartime(Q256_FRACTION_BITS_V1),
        U512::from_u64(denominator),
    )
}
#[test]
fn external_rng_failure_and_stuck_sentinels_fail_closed() {
    let mut failed = TestRng {
        state: 1,
        fail: true,
        stuck: None,
    };
    assert!(matches!(
        ProofRandomnessV1::from_rng(&mut failed),
        Err(SamplingErrorV1::RandomnessUnavailable)
    ));
    for byte in [0, 1, 0xA5, u8::MAX] {
        let mut stuck = TestRng {
            state: 1,
            fail: false,
            stuck: Some(byte),
        };
        assert!(matches!(
            ProofRandomnessV1::from_rng(&mut stuck),
            Err(SamplingErrorV1::RandomnessHealthCheckFailed)
        ));
    }
}
#[test]
fn successful_proof_seed_is_owned_by_zeroizing_storage() {
    fn require_zeroizing_seed(_: &Zeroizing<[u8; 32]>) {}
    let mut rng = TestRng {
        state: 1,
        fail: false,
        stuck: None,
    };
    let mut randomness = ProofRandomnessV1::from_rng(&mut rng).expect("healthy proof seed");
    require_zeroizing_seed(&randomness.seed);
    assert_ne!(*randomness.seed, [0; 32]);
    randomness.seed.zeroize();
    assert_eq!(*randomness.seed, [0; 32]);
}
#[test]
fn deterministic_stream_is_domain_position_and_seed_separated() {
    let mut first = test_randomness();
    let mut replay = test_randomness();
    let mut other_domain = test_randomness();
    let mut other_seed = ProofRandomnessV1::for_test(core::array::from_fn(|index| {
        u8::try_from(index + 2).expect("index fits")
    }))
    .expect("healthy");
    let mut a = [0_u8; 64];
    let mut b = [0_u8; 64];
    let mut c = [0_u8; 64];
    let mut d = [0_u8; 64];
    first.fill_bytes(b"a", &mut a);
    replay.fill_bytes(b"a", &mut b);
    replay.fill_bytes(b"a", &mut c);
    other_domain.fill_bytes(b"b", &mut d);
    assert_eq!(a, b);
    assert_ne!(b, c);
    assert_ne!(a, d);
    other_seed.fill_bytes(b"a", &mut d);
    assert_ne!(a, d);
    assert_eq!(first.stream, 1);
    assert_eq!(replay.stream, 2);
}
#[test]
fn secret_randomness_diagnostics_are_invariant_and_fully_redacted() {
    let mut first = test_randomness();
    let mut second = ProofRandomnessV1::for_test(core::array::from_fn(|index| {
        u8::try_from(index + 33).expect("index fits")
    }))
    .expect("healthy distinct deterministic seed");
    let initial = format!("{first:?}");
    let mut output = Zeroizing::new([0_u8; 7]);
    first.fill_bytes(b"advance-secret-stream", output.as_mut());
    second.fill_bytes(b"another-secret-stream", output.as_mut());
    second.fill_bytes(b"another-secret-stream", output.as_mut());
    assert_eq!(initial, "ProofRandomnessV1(<redacted>)");
    assert_eq!(format!("{first:?}"), initial);
    assert_eq!(format!("{second:?}"), initial);
}
#[test]
fn closed_profiles_pin_width_shape_truncation_and_rejection_kind() {
    assert_eq!(GAUSSIAN_VARIANCE_NUMERATOR_V1, 961);
    assert_eq!(GAUSSIAN_HALF_VARIANCE_DENOMINATOR_V1, 200);
    let expected = [
        (23, TBOX_M1_V1, 260_046_848, RejectionKindV1::Standard),
        (12, TBOX_M2_V1, 126_976, RejectionKindV1::Bimodal),
        (18, 4, 8_126_464, RejectionKindV1::Bimodal),
        (29, 4, 16_642_998_272, RejectionKindV1::Bimodal),
    ];
    let expected_m = [
        U512::from_be_hex(
            "0000000000000000000000000000000000000000000000000000000000000002525a3cfaad84dba188d3db399d7cba7187e2dbce1f9e0ae5c102bc9489308bdb",
        ),
        U512::from_be_hex(
            "0000000000000000000000000000000000000000000000000000000000000002b50320d11ea2904dd033f7370d3d7a9a41ac2e32ff9006bc0a50068a0275c213",
        ),
        U512::from_be_hex(
            "0000000000000000000000000000000000000000000000000000000000000001090d5b073c49c0fa7a6d236608c702d7ad989e2a101d591a78500b750a66c82b",
        ),
        U512::from_be_hex(
            "0000000000000000000000000000000000000000000000000000000000000001050c780feb4d8f4b0e66a8373efe8b4d5eb9d92fd94c2ba4ca446a2290077cea",
        ),
    ];
    for ((profile, expected), expected_m) in BootleSamplingProfileV1::ALL
        .into_iter()
        .zip(expected)
        .zip(expected_m)
    {
        assert_eq!(profile.log2_sigma(), expected.0);
        assert_eq!(profile.expected_polynomials(), expected.1);
        assert_eq!(profile.truncation_bound(), expected.2);
        assert_eq!(profile.rejection_kind(), expected.3);
        assert_eq!(profile.truncation_bound(), 31_i64 << profile.log2_sigma());
        let m = profile.rejection_m_q256();
        assert_eq!(
            m, expected_m,
            "limbs must encode the canonical BE Q256 value"
        );
        assert_eq!(m.to_be_bytes(), expected_m.to_be_bytes());
        assert!(m > q256_one_v1());
        assert!(m < U512::from_u64(3).shl_vartime(Q256_FRACTION_BITS_V1));
    }
}
#[test]
fn q256_cdf_constants_and_boundaries_are_canonical() {
    assert_eq!(
        CDF_155_Q256_V1[0],
        U256::from_be_hex("9731fa96ce33beaa95f28503ccbda2bcce489feb4248e1357ab2bd2c54034865")
    );
    assert_eq!(
        CDF_155_Q256_V1[14],
        U256::from_be_hex("000000000000000008ecd7725eb87a2069931a9325df6532b6e19f3f2e47868a")
    );
    assert_eq!(CDF_155_Q256_V1[28], U256::from_u64(5));
    assert_eq!(CDF_155_Q256_V1[29], U256::ZERO);
    assert!(
        CDF_155_Q256_V1[..29]
            .windows(2)
            .all(|window| window[0] > window[1])
    );
    assert_eq!(cdf155_index_v1(U256::MAX), 0);
    assert_eq!(cdf155_index_v1(U256::ZERO), 29);
    for (index, threshold) in CDF_155_Q256_V1[..29].iter().copied().enumerate() {
        assert_eq!(
            cdf155_index_v1(threshold),
            u32::try_from(index).expect("index")
        );
        assert_eq!(
            cdf155_index_v1(threshold.wrapping_sub(&U256::ONE)),
            u32::try_from(index + 1).expect("index")
        );
    }
}
#[test]
fn gaussian_correction_uses_exact_nonnegative_rationals() {
    let scale = 1_u64 << 12;
    assert_eq!(
        gaussian_correction_exponent_q256_v1(0, false, 0, scale),
        U512::ZERO
    );
    let first_positive = gaussian_correction_exponent_q256_v1(0, true, 0, scale);
    assert_eq!(first_positive, rational_q256(200, 961));
    let largest = gaussian_correction_exponent_q256_v1(29, true, 0, scale);
    assert_eq!(largest, rational_q256(11_800, 961));
    for magnitude in [0, 1, 7, 29] {
        for offset in [1, 17, scale / 2, scale - 1] {
            let negative = gaussian_correction_exponent_q256_v1(magnitude, false, offset, scale);
            let positive =
                gaussian_correction_exponent_q256_v1(magnitude, true, scale - offset, scale);
            assert_eq!(negative, positive);
        }
    }
}
#[test]
fn q256_decay_matches_independent_high_precision_vectors() {
    let cases = [
        (
            rational_q256(1, 4_096),
            "fff0007ffd555fffddde38e2be2d82d549cb030fde4780c8ba5d4c942f9675d8",
        ),
        (
            rational_q256(200, 961),
            "cfe698df22a86b0a40fb2662f0ae2944301e21197eea6b3062b70f01799154e9",
        ),
        (
            rational_q256(11_800, 961),
            "00004dfef2cc9f98627791e99c8ea0382d1c4cb253b1a7194f2762c227344d01",
        ),
        (
            rational_q256(1, 4),
            "c75f7cf564105743415cbc9d6368f3b96071095abeaf430dbc067f714a3c1787",
        ),
        (
            rational_q256(1, 2),
            "9b4597e37cb04ff3d675a35530cdd767e347bf8ad0e80abbce4ae95861014318",
        ),
        (
            U512::from_u64(1).shl_vartime(Q256_FRACTION_BITS_V1),
            "5e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a507daee",
        ),
        (
            U512::from_u64(10).shl_vartime(Q256_FRACTION_BITS_V1),
            "0002f9af36ac8f93538b648eaa1310e5f2bdf1d29cb282668b9a7147cc4dc89b",
        ),
        (
            U512::from_u64(178).shl_vartime(Q256_FRACTION_BITS_V1),
            "0000000000000000000000000000000000000000000000000000000000000001",
        ),
    ];
    let error_bound = U256::from_u64(1 << 16);
    for (input, expected) in cases {
        let (high, actual) = decay_q256_v1(input).split();
        assert_eq!(high, U256::ZERO);
        let expected = U256::from_be_hex(expected);
        assert!(
            absolute_difference(actual, expected) <= error_bound,
            "decay vector exceeded the analytic error budget"
        );
    }
    assert_eq!(decay_q256_v1(U512::ZERO), q256_one_v1());
    assert_eq!(
        decay_q256_v1(U512::from_u64(179).shl_vartime(Q256_FRACTION_BITS_V1)),
        U512::ZERO
    );
}
#[test]
fn q256_decay_is_monotone_through_the_full_cutoff() {
    let mut previous = decay_q256_v1(U512::ZERO);
    for eighths in 1..=(179 * 8) {
        let input = U512::from_u64(eighths).shl_vartime(Q256_FRACTION_BITS_V1 - 3);
        let current = decay_q256_v1(input);
        assert!(current <= previous, "decay increased at eighth {eighths}");
        if eighths <= 160 * 8 {
            assert!(
                current < previous,
                "decay was not strict at eighth {eighths}"
            );
        }
        previous = current;
    }
    assert_eq!(previous, U512::ZERO);
}
#[test]
fn ratio_thresholds_pin_zero_one_half_and_saturation() {
    let one = q256_one_v1();
    assert_eq!(
        ratio_threshold_q256_v1(U512::ZERO, one),
        BernoulliThresholdV1::Never
    );
    assert_eq!(
        ratio_threshold_q256_v1(one, U512::ZERO),
        BernoulliThresholdV1::Always
    );
    assert_eq!(
        ratio_threshold_q256_v1(one, one),
        BernoulliThresholdV1::Always
    );
    assert_eq!(
        ratio_threshold_q256_v1(one, one.shl_vartime(1)),
        BernoulliThresholdV1::Finite(U256::ONE.shl_vartime(255))
    );
}
#[test]
fn bernoulli_draws_are_big_endian_fixed_width_and_boundary_exact() {
    let domain = b"bernoulli-boundary-test";
    let mut probe = test_randomness();
    let mut bytes = [0_u8; 32];
    probe.fill_bytes(domain, &mut bytes);
    let draw = U256::from_be_bytes(bytes);
    assert_ne!(draw, U256::MAX);
    let mut equal = test_randomness();
    assert!(!equal.bernoulli_q256(domain, BernoulliThresholdV1::Finite(draw)));
    assert_eq!(equal.stream, 1);
    let mut below = test_randomness();
    assert!(below.bernoulli_q256(
        domain,
        BernoulliThresholdV1::Finite(draw.wrapping_add(&U256::ONE))
    ));
    assert_eq!(below.stream, 1);
    let mut endpoints = test_randomness();
    assert!(!endpoints.bernoulli_q256(domain, BernoulliThresholdV1::Never));
    assert!(endpoints.bernoulli_q256(domain, BernoulliThresholdV1::Always));
    assert_eq!(endpoints.stream, 2);
}
#[test]
fn zero_rejection_inputs_match_exact_reciprocal_m_vectors() {
    let expected = [
        "6e43b86d2c9d946b4935e73a954371244cbaee995c6658159bda577c18227438",
        "5e911eb9e7b02c21235392d2e2d38fc66431ab1b7d58e8aa7a3e072aaa8c954c",
        "f741c9a6880d42a876219fb54501fbdfadd787e1acab7709636bbc8c4ebbfd5b",
        "fb0c870902bd79ae6c1fb6d6fa71ce251211834771cceed366b5e357ffaa2c1b",
    ];
    for (profile, expected) in BootleSamplingProfileV1::ALL.into_iter().zip(expected) {
        let threshold = match profile.rejection_kind() {
            RejectionKindV1::Standard => standard_rejection_threshold_v1(0, 0, profile),
            RejectionKindV1::Bimodal => bimodal_rejection_threshold_v1(0, 0, profile),
        };
        let threshold = finite_threshold(threshold);
        assert_eq!(threshold, U256::from_be_hex(expected));
        // Independent integer oracle: each zero-input threshold is exactly
        // floor(2^512 / M_q256), not a rounded reciprocal or a limb truncation.
        let m = profile.rejection_m_q256();
        let threshold = U512::from(&threshold);
        let lower: U1024 = m.mul(&threshold);
        let upper: U1024 = m.mul(&threshold.wrapping_add(&U512::ONE));
        let numerator = U1024::ONE.shl_vartime(512);
        assert!(lower <= numerator, "reciprocal floor exceeds exact ratio");
        assert!(
            numerator < upper,
            "reciprocal floor loses integer precision"
        );
    }
}
#[test]
fn standard_and_bimodal_thresholds_match_independent_decimal_vectors() {
    // For z1, raw = 961*2^41 gives exponent +/- 25/4 exactly.
    let raw = 961_i128 << 41;
    assert_eq!(
        standard_rejection_threshold_v1(
            0,
            u128::try_from(raw).expect("positive"),
            BootleSamplingProfileV1::ResponseZ1
        ),
        BernoulliThresholdV1::Always
    );
    let standard_negative = finite_threshold(standard_rejection_threshold_v1(
        raw,
        u128::try_from(raw).expect("positive"),
        BootleSamplingProfileV1::ResponseZ1,
    ));
    let standard_reference =
        U256::from_be_hex("00367e08a8d34d4ae0b11a7eb9fbdb857150ef30cd7220e42945a45a08ee3cf4");
    // For z2, dot = 961*2^17 gives t = 25/8.  With norm=dot,
    // n=25/16 and the decision exercises the d>=0 formula.
    let dot = 961_i128 << 17;
    let norm = u128::try_from(dot).expect("positive");
    let bimodal = finite_threshold(bimodal_rejection_threshold_v1(
        dot,
        norm,
        BootleSamplingProfileV1::ResponseZ2,
    ));
    let bimodal_negative_dot = finite_threshold(bimodal_rejection_threshold_v1(
        -dot,
        norm,
        BootleSamplingProfileV1::ResponseZ2,
    ));
    let bimodal_reference =
        U256::from_be_hex("279175c2b0d61da9ea26af60e98a8428aaaceea05c4e4cc19db0a129544f2c57");
    let tolerance = U256::from_u64(1 << 22);
    assert!(absolute_difference(standard_negative, standard_reference) <= tolerance);
    assert!(absolute_difference(bimodal, bimodal_reference) <= tolerance);
    assert_eq!(bimodal, bimodal_negative_dot);
    assert_eq!(
        bimodal_rejection_threshold_v1(dot, norm * 4, BootleSamplingProfileV1::ResponseZ2),
        BernoulliThresholdV1::Always
    );
}
#[test]
fn adversarial_underflow_overflow_product_case_rejects_instead_of_accepting_nan() {
    let profile = BootleSamplingProfileV1::ProjectionZ3;
    let mut z = vec![0_i64; profile.expected_coefficients()];
    let mut shift = vec![0_i64; profile.expected_coefficients()];
    z[0] = 1_000_000_000_000;
    shift[0] = 1_000_000_000_000;
    assert_eq!(
        bimodal_rejection_threshold_v1(
            1_000_000_000_000_000_000_000_000,
            1_000_000_000_000_000_000_000_000,
            profile
        ),
        BernoulliThresholdV1::Never
    );
    let mut randomness = test_randomness();
    assert!(
        !randomness
            .accept_rejection(&z, &shift, profile)
            .expect("well-shaped adversarial decision")
    );
    assert_eq!(randomness.stream, 1);
    z[0] = 0;
    let mut saturation = test_randomness();
    assert!(
        saturation
            .accept_rejection(&z, &shift, profile)
            .expect("well-shaped saturation decision")
    );
    assert_eq!(saturation.stream, 1);
}
#[test]
fn standard_extreme_exponents_saturate_in_the_correct_direction() {
    let profile = BootleSamplingProfileV1::ResponseZ1;
    let mut z = vec![0_i64; profile.expected_coefficients()];
    let mut shift = vec![0_i64; profile.expected_coefficients()];
    shift[0] = 1_000_000_000_000;
    let mut positive = test_randomness();
    assert!(
        positive
            .accept_rejection(&z, &shift, profile)
            .expect("positive exponent")
    );
    z[0] = shift[0];
    let mut negative = test_randomness();
    assert!(
        !negative
            .accept_rejection(&z, &shift, profile)
            .expect("negative exponent")
    );
}
#[test]
fn rejection_shapes_and_arithmetic_overflow_fail_before_randomness_is_used() {
    let mut randomness = test_randomness();
    assert_eq!(
        randomness.accept_rejection(&[0], &[0], BootleSamplingProfileV1::ProjectionZ3),
        Err(SamplingErrorV1::InvalidRejectionShape)
    );
    assert_eq!(randomness.stream, 0);
    let profile = BootleSamplingProfileV1::ResponseZ1;
    let extreme = vec![i64::MAX; profile.expected_coefficients()];
    assert_eq!(
        randomness.accept_rejection(&extreme, &extreme, profile),
        Err(SamplingErrorV1::ArithmeticOverflow)
    );
    assert_eq!(randomness.stream, 0);
}
#[test]
fn uniform_power_of_two_draws_have_no_spurious_rejection_block() {
    let mut randomness = test_randomness();
    for _ in 0..128 {
        let before = randomness.stream;
        let value = randomness
            .uniform_modulus(b"power-of-two-uniform-test", 1_u64 << 29)
            .expect("power-of-two sample");
        assert!(value < 1_u64 << 29);
        assert_eq!(randomness.stream, before + 1);
    }
}
#[test]
fn gaussian_polynomials_are_reproducible_canonical_and_bounded() {
    let mut first = test_randomness();
    let mut replay = test_randomness();
    let mut first_outputs = Vec::new();
    let mut replay_outputs = Vec::new();
    let expected_prefixes = [
        [
            7_045_864,
            -3_580_401,
            8_171_066,
            3_708_989,
            -11_099_415,
            700_666,
            1_901_060,
            107_340,
            -4_261_869,
            7_425_071,
            279_086,
            2_034_265,
            924_859,
            23_363_252,
            9_813_317,
            14_720_392,
        ],
        [
            10_111, 4_697, 4_240, -7_907, -2_531, 4_995, 548, 703, 4_127, -5_167, -286, -5_455,
            -6_995, 6_300, 6_879, 5_265,
        ],
        [
            264_230, 396_340, -375_124, 114_155, -433_683, 262_771, 39_863, 208_118, -998_368,
            458_699, -421_434, 255_256, -17_140, -79_241, -683_098, 365_405,
        ],
        [
            -23_311_492,
            -14_087_782,
            526_782_449,
            432_135_224,
            -126_231_312,
            -268_611_225,
            -57_010_365,
            -711_701_628,
            1_492_427_111,
            -899_937_798,
            -1_749_705_466,
            788_044_118,
            -2_140_297_874,
            1_144_701_228,
            915_041_709,
            2_454_426_709,
        ],
    ];
    let expected_streams = [286, 611, 942, 1_234];
    for (profile_index, profile) in BootleSamplingProfileV1::ALL.into_iter().enumerate() {
        let first_polynomial = first.gaussian_polynomial(profile).expect("Gaussian");
        let replay_polynomial = replay
            .gaussian_polynomial(profile)
            .expect("Gaussian replay");
        assert_eq!(first_polynomial, replay_polynomial);
        assert_eq!(
            core::array::from_fn::<_, 16, _>(|index| {
                first_polynomial.centered_coefficient(index)
            }),
            expected_prefixes[profile_index]
        );
        assert_eq!(first.stream, expected_streams[profile_index]);
        assert_eq!(replay.stream, expected_streams[profile_index]);
        for index in 0..APPLICATION_RING_DEGREE_V1 {
            assert!(
                first_polynomial.centered_coefficient(index).unsigned_abs()
                    <= u64::try_from(profile.truncation_bound()).expect("positive")
            );
        }
        assert!(
            first_polynomial
                .coefficients()
                .iter()
                .all(|coefficient| *coefficient < PROOF_MODULUS_V1)
        );
        first_outputs.push(first_polynomial);
        replay_outputs.push(replay_polynomial);
    }
    assert_eq!(first_outputs, replay_outputs);
    assert_eq!(first.stream, replay.stream);
    assert!(first.stream >= 4 * APPLICATION_RING_DEGREE_V1 as u64);
}
#[test]
fn z4_gaussian_kat_coefficient_13_is_reconstructed_from_pinned_raw_draws() {
    // The fourth polynomial starts at stream 942. Accounting for the two
    // pinned extra proposals after coefficients 5 and 10 puts coefficient
    // 13's fractional draw at stream 1000. Pin the framed SHAKE output itself
    // and reconstruct the coefficient without calling gaussian_coefficient.
    let mut randomness = test_randomness();
    randomness.stream = 1_000;
    let mut fraction_bytes = [0_u8; 8];
    randomness.fill_bytes(b"gaussian-z4-fraction-v1", &mut fraction_bytes);
    assert_eq!(
        fraction_bytes,
        [0xd5, 0x56, 0xbd, 0xd9, 0x1b, 0xc5, 0x3e, 0xd4]
    );
    let scale = 1_u64 << 29;
    let fractional = u64::from_be_bytes(fraction_bytes) % scale;
    assert_eq!(fractional, 465_911_508);
    let mut sign_bytes = [0_u8; 1];
    randomness.fill_bytes(b"gaussian-z4-sign-v1", &mut sign_bytes);
    assert_eq!(sign_bytes, [0x41]);
    assert_eq!(sign_bytes[0] & 1, 1, "odd draw selects the positive branch");
    let mut cdf_bytes = [0_u8; 32];
    randomness.fill_bytes(b"gaussian-z4-cdf-v1", &mut cdf_bytes);
    assert_eq!(
        cdf_bytes,
        [
            0x3a, 0x2f, 0x91, 0xe9, 0xa3, 0x04, 0x61, 0x2e, 0x7a, 0xf5, 0xf1, 0xce, 0x28, 0xf7,
            0xa5, 0xca, 0xbb, 0x9d, 0x49, 0xde, 0xa0, 0x6e, 0xfe, 0xe9, 0xbe, 0x9a, 0x29, 0x2d,
            0x05, 0xd6, 0x9e, 0x83,
        ]
    );
    let cdf_draw = U256::from_be_bytes(cdf_bytes);
    assert!(cdf_draw < CDF_155_Q256_V1[0]);
    assert!(cdf_draw < CDF_155_Q256_V1[1]);
    assert!(cdf_draw >= CDF_155_Q256_V1[2]);
    let magnitude = 2_i64;
    let mut accept_bytes = [0_u8; 32];
    randomness.fill_bytes(b"gaussian-z4-accept-v1", &mut accept_bytes);
    assert_eq!(
        accept_bytes,
        [
            0x16, 0x45, 0x33, 0x4d, 0x96, 0x15, 0x91, 0x59, 0xf5, 0x45, 0xb2, 0xf4, 0x11, 0xb4,
            0xdf, 0x94, 0x9d, 0x11, 0xb0, 0xeb, 0x69, 0x81, 0x03, 0x7c, 0x47, 0x69, 0x2a, 0xf4,
            0x18, 0xc9, 0x9a, 0xfd,
        ]
    );
    // Independently evaluated floor(exp(-200*D/(961*s^2))*2^256), where
    // D=(s-f)*(2*m*s+s-f). The raw acceptance draw is far below this bound.
    let ideal_acceptance_floor =
        U256::from_be_hex("e47ea296d803ad0cbf21ed310ac31c2a5fa1bb5f76fc5cf4095764be1f85c125");
    assert!(U256::from_be_bytes(accept_bytes) < ideal_acceptance_floor);
    let candidate = magnitude + 1;
    let reconstructed = candidate
        .checked_mul(i64::try_from(scale).expect("fixed scale fits i64"))
        .and_then(|scaled| {
            scaled.checked_sub(i64::try_from(fractional).expect("fraction fits i64"))
        })
        .expect("fixed KAT arithmetic");
    assert_eq!(reconstructed, 1_144_701_228);
    assert_eq!(randomness.stream, 1_004);
}
#[test]
fn gaussian_retry_and_probability_error_budgets_have_integer_margins() {
    // The event branch=negative, magnitude=0 alone has probability above
    // (1/2)*(2/5)*(4/5) = 4/25.  Therefore per-attempt failure is below
    // 21/25, and every four failures cost more than one bit.
    let one = q256_one_v1();
    let cdf_zero = U512::from(&CDF_155_Q256_V1[0]);
    assert!(cdf_zero.wrapping_mul(&U512::from_u64(5)) < one.wrapping_mul(&U512::from_u64(3)));
    let base_acceptance = decay_q256_v1(rational_q256(200, 961));
    assert!(
        base_acceptance.wrapping_mul(&U512::from_u64(5)) > one.wrapping_mul(&U512::from_u64(4))
    );
    assert!(2_u128 * 21_u128.pow(4) < 25_u128.pow(4));
    assert_eq!(MAX_GAUSSIAN_COEFFICIENT_ATTEMPTS_V1, 4_096);
    assert_eq!(MAX_GAUSSIAN_COEFFICIENT_ATTEMPTS_V1 / 4, 1_024);
    let response_coefficients =
        u128::try_from((TBOX_M1_V1 + TBOX_M2_V1) * APPLICATION_RING_DEGREE_V1)
            .expect("fixed dimensions");
    let maximum_proposals =
        response_coefficients * u128::from(MAX_GAUSSIAN_COEFFICIENT_ATTEMPTS_V1) * 4_096;
    assert!(maximum_proposals < 1_u128 << 37);
    // A per-decision decay error below 2^-240 therefore aggregates below
    // 2^-203.  The 30-threshold CDT contributes less than 2^-214.
    assert_eq!(240 - 37, 203);
    assert!(252 - 37 >= 214);
}
#[test]
fn decay_tables_initialize_on_a_bounded_native_thread_stack() {
    const CALLER_STACK_BYTES: usize = 512 * 1024;
    let digest = std::thread::Builder::new()
        .name("bootle-decay-table-small-stack".to_owned())
        .stack_size(CALLER_STACK_BYTES)
        .spawn(|| {
            let integer = integer_decay_table_q256_v1();
            let fraction = fraction_decay_table_q256_v1();
            assert_eq!(integer.len(), MAX_DECAY_INTEGER_V1 + 1);
            assert_eq!(fraction.len(), FRACTION_TABLE_LEN_V1);
            assert!(core::ptr::eq(integer, integer_decay_table_q256_v1()));
            assert!(core::ptr::eq(fraction, fraction_decay_table_q256_v1()));
            decay_tables_digest_v1()
        })
        .expect("bounded-stack test thread must spawn")
        .join()
        .expect("decay-table initialization must not exhaust the caller stack");
    assert_ne!(digest, [0; 32]);
    assert_eq!(
        hex::encode(digest),
        "ccffc4215f89cd7903a81d7f6353bf619791c7b68dba00287e2f010495ecbfbd"
    );
}
#[test]
fn complete_sampling_profile_digest_is_one_field_mutation_closed() {
    let baseline = bootle_sampling_profile_binding_v1();
    let baseline_digest = sampling_profile_digest_from_binding_v1(&baseline);
    assert_ne!(baseline_digest, [0; 32]);
    assert_eq!(baseline_digest, bootle_sampling_profile_digest_v1());
    assert_eq!(
        hex::encode(baseline.decay_tables_digest),
        "ccffc4215f89cd7903a81d7f6353bf619791c7b68dba00287e2f010495ecbfbd"
    );
    assert_eq!(
        hex::encode(baseline_digest),
        "6e037c7342b327b75df5621f999506799174254ca7a7846d7549a6526f6ef897"
    );
    macro_rules! assert_mutation {
        ($label:literal, |$profile:ident| $mutation:expr) => {{
            let mut changed = baseline.clone();
            let $profile: &mut BootleSamplingProfileBindingV1 = &mut changed;
            $mutation;
            assert_ne!(
                baseline_digest,
                sampling_profile_digest_from_binding_v1(&changed),
                "sampling-profile mutation was not bound: {}",
                $label
            );
        }};
    }
    assert_mutation!("algorithm_descriptor", |profile| profile
        .algorithm_descriptor =
        b"mutated");
    assert_mutation!("randomness_domain", |profile| profile.randomness_domain =
        b"mutated");
    assert_mutation!("producer_randomness_policy", |profile| profile
        .producer_randomness_policy =
        b"mutated");
    assert_mutation!("ring_degree", |profile| profile.ring_degree += 1);
    assert_mutation!("proof_modulus", |profile| profile.proof_modulus -= 1);
    assert_mutation!("uniform_rejection_attempts", |profile| profile
        .uniform_rejection_attempts -=
        1);
    assert_mutation!("gaussian_coefficient_attempts", |profile| profile
        .gaussian_coefficient_attempts -=
        1);
    assert_mutation!("proof_sampling_attempts", |profile| profile
        .proof_sampling_attempts -=
        1);
    assert_mutation!("projection_sampling_attempts", |profile| profile
        .projection_sampling_attempts -=
        1);
    assert_mutation!("response_sampling_attempts", |profile| profile
        .response_sampling_attempts -=
        1);
    assert_mutation!("sigma_numerator", |profile| profile.sigma_numerator -= 1);
    assert_mutation!("sigma_denominator", |profile| profile.sigma_denominator -=
        1);
    assert_mutation!("q256_fraction_bits", |profile| {
        profile.q256_fraction_bits -= 1
    });
    assert_mutation!("fraction_table_bits", |profile| {
        profile.fraction_table_bits -= 1
    });
    assert_mutation!("max_decay_integer", |profile| {
        profile.max_decay_integer -= 1
    });
    assert_mutation!("unit_decay_series_terms", |profile| profile
        .unit_decay_series_terms -=
        1);
    assert_mutation!("fraction_step_series_terms", |profile| profile
        .fraction_step_series_terms -=
        1);
    assert_mutation!("residual_decay_series_terms", |profile| profile
        .residual_decay_series_terms -=
        1);
    assert_mutation!("decay_tables_digest", |profile| {
        profile.decay_tables_digest[0] ^= 1
    });
    for index in 0..BootleSamplingProfileV1::ALL.len() {
        let mut changed = baseline.clone();
        changed.log2_sigma[index] ^= 1;
        assert_ne!(
            baseline_digest,
            sampling_profile_digest_from_binding_v1(&changed),
            "log2 sigma role {index} was not bound"
        );
        let mut changed = baseline.clone();
        changed.expected_polynomials[index] += 1;
        assert_ne!(
            baseline_digest,
            sampling_profile_digest_from_binding_v1(&changed),
            "expected polynomial count role {index} was not bound"
        );
        let mut changed = baseline.clone();
        changed.rejection_kinds[index] ^= 1;
        assert_ne!(
            baseline_digest,
            sampling_profile_digest_from_binding_v1(&changed),
            "rejection kind role {index} was not bound"
        );
        let mut changed = baseline.clone();
        changed.truncation_bounds[index] -= 1;
        assert_ne!(
            baseline_digest,
            sampling_profile_digest_from_binding_v1(&changed),
            "truncation bound role {index} was not bound"
        );
        let mut changed = baseline.clone();
        changed.rejection_m_q256_limbs[index][0] ^= 1;
        assert_ne!(
            baseline_digest,
            sampling_profile_digest_from_binding_v1(&changed),
            "rejection M role {index} was not bound"
        );
        for domains in 0..5 {
            let mut changed = baseline.clone();
            match domains {
                0 => changed.fraction_domains[index] = b"mutated",
                1 => changed.sign_domains[index] = b"mutated",
                2 => changed.cdf_domains[index] = b"mutated",
                3 => changed.gaussian_accept_domains[index] = b"mutated",
                4 => changed.rejection_domains[index] = b"mutated",
                _ => unreachable!(),
            }
            assert_ne!(
                baseline_digest,
                sampling_profile_digest_from_binding_v1(&changed),
                "domain family {domains}, role {index} was not bound"
            );
        }
    }
    for index in 0..baseline.cdf_155_q256.len() {
        let mut changed = baseline.clone();
        changed.cdf_155_q256[index] = changed.cdf_155_q256[index].wrapping_add(&U256::ONE);
        assert_ne!(
            baseline_digest,
            sampling_profile_digest_from_binding_v1(&changed),
            "CDF threshold {index} was not bound"
        );
    }
}
#[test]
fn staged_randomness_api_is_crate_private_and_retry_caps_have_distinct_roles() {
    let sampling = include_str!("sampling.rs")
        .split("// INTEGER_ONLY_PRODUCTION_END")
        .next()
        .expect("production marker");
    assert!(!sampling.contains("pub struct ProofRandomnessV1"));
    assert!(sampling.contains("pub(crate) struct ProofRandomnessV1"));
    for method in [
        "from_rng",
        "fill_bytes",
        "sign",
        "ternary",
        "uniform_polynomial",
        "ternary_polynomial",
    ] {
        assert!(
            sampling.contains(&format!("pub(crate) fn {method}")),
            "staged sampler method `{method}` must remain crate-private"
        );
    }
    let ternary = sampling
        .split("pub(crate) fn ternary(")
        .nth(1)
        .expect("ternary source")
        .split("pub(crate) fn uniform_polynomial")
        .next()
        .expect("ternary body");
    assert!(ternary.contains("MAX_UNIFORM_REJECTION_ATTEMPTS_V1"));
    assert!(!ternary.contains("MAX_GAUSSIAN_COEFFICIENT_ATTEMPTS_V1"));
    let gaussian = sampling
        .split("fn gaussian_coefficient(")
        .nth(1)
        .expect("Gaussian source")
        .split("fn cdf155_sample")
        .next()
        .expect("Gaussian body");
    assert!(gaussian.contains("MAX_GAUSSIAN_COEFFICIENT_ATTEMPTS_V1"));
    assert!(!gaussian.contains("for _ in 0..MAX_UNIFORM_REJECTION_ATTEMPTS_V1"));
    let uniform = sampling
        .split("fn uniform_modulus(")
        .nth(1)
        .expect("uniform source");
    assert!(uniform.contains("MAX_UNIFORM_REJECTION_ATTEMPTS_V1"));
    assert!(!uniform.contains("MAX_GAUSSIAN_COEFFICIENT_ATTEMPTS_V1"));
}
#[test]
fn production_sampler_sources_exclude_native_float_and_transcendental_paths() {
    let sampling = include_str!("sampling.rs")
        .split("// INTEGER_ONLY_PRODUCTION_END")
        .next()
        .expect("production marker");
    let params = include_str!("params.rs")
        .split_once("#[cfg(test)]\nmod tests {")
        .expect("parameter production/test module boundary")
        .0;
    let proof = include_str!("proof.rs")
        .split("// INTEGER_ONLY_PROOF_PRODUCTION_END")
        .next()
        .expect("proof production section");
    let forbidden = [
        ["f", "32"].concat(),
        ["f", "64"].concat(),
        [".", "exp("].concat(),
        [".", "cosh("].concat(),
        [".", "powi("].concat(),
        ["pow", "f("].concat(),
        ["libm", "::"].concat(),
        ["GAUSSIAN_", "1_VARIANCE"].concat(),
        ["REJECTION_M_", "LIMBS"].concat(),
    ];
    for (name, source) in [("sampling", sampling), ("params", params), ("proof", proof)] {
        for token in &forbidden {
            assert!(
                !source.contains(token),
                "{name} contains forbidden token {token}"
            );
        }
    }
}
