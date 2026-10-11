//! Closed consensus parameters for the first Bootle/Lantern profile.
/// Application ring degree.
pub const APPLICATION_RING_DEGREE_V1: usize = 64;
/// Application ring modulus.
pub const APPLICATION_MODULUS_V1: u16 = 12_289;
/// Number of application equations.
pub const APPLICATION_ROWS_V1: usize = 8;
#[cfg(test)]
/// Number of credential attributes.
pub const ATTRIBUTE_COUNT_V1: usize = 8;
/// Number of application witness polynomials before norm padding.
pub const APPLICATION_WITNESS_POLYNOMIALS_V1: usize = 48;
/// Internal Lantern/LNP22 proof modulus.
pub const PROOF_MODULUS_V1: u64 = 1_125_899_906_843_221;
/// Canonical inverse of two modulo the internal proof modulus.
pub const PROOF_INVERSE_TWO_V1: u64 = 562_949_953_421_611;
#[cfg(test)]
/// Canonical inverse of four modulo the internal proof modulus.
pub const PROOF_INVERSE_FOUR_V1: u64 = 844_424_930_132_416;
/// Canonical inverse of the application modulus modulo the proof modulus.
pub const APPLICATION_MODULUS_INVERSE_IN_PROOF_V1: u64 = 305_914_215_066_280;
/// Exact quotient bound used when lifting the eight application equations from `R_p` into `R_q`.
pub const APPLICATION_RELATION_QUOTIENT_BOUND_V1: u64 = 30_064;
/// Canonical wire width of one proof residue.
pub const PROOF_RESIDUE_BYTES_V1: usize = 7;
/// Compression exponent used by the mathematical ABDLOP relation.
pub const DECOMPOSITION_BITS_V1: u8 = 15;
/// Compression gamma.
pub const COMPRESSION_GAMMA_V1: u64 = 16_531_490;
/// Compression modulus.
pub const COMPRESSION_MODULUS_V1: u64 = 68_106_378;
/// Internal short-message dimension including two norm-padding polynomials.
pub const TBOX_M1_V1: usize = 50;
/// Internal mask dimension.
pub const TBOX_M2_V1: usize = 64;
/// Extended-message dimension.
pub const TBOX_LEXT_V1: usize = 12;
/// Module-SIS commitment dimension.
pub const TBOX_KMSIS_V1: usize = 20;
/// Number of binary witness polynomials.
pub const BINARY_POLYNOMIALS_V1: usize = 16;
#[cfg(test)]
/// Number of exact application relations.
pub const EXACT_RELATIONS_V1: usize = 8;
#[cfg(test)]
/// Number of norm statements.
pub const NORM_STATEMENTS_V1: usize = 2;
/// Maximum column count of either fixed-profile ternary projection matrix.
///
/// The larger matrix projects all 50 short-witness polynomials coefficient by
/// coefficient. Both transcript row expansion and whole-matrix allocation
/// enforce this same cap before performing size arithmetic or reserving memory.
pub(crate) const MAX_PROJECTION_COLUMNS_V1: usize = TBOX_M1_V1 * APPLICATION_RING_DEGREE_V1;
/// Challenge coefficient magnitude.
pub const CHALLENGE_OMEGA_V1: i64 = 8;
/// Conservative base-two challenge-set size used by the proof theorem.
pub const CHALLENGE_SET_BITS_V1: u16 = 129;
/// Exponent `k` in the integer-ring challenge norm from LNP22 equation (19).
pub const CHALLENGE_NORM_POWER_V1: u8 = 32;
/// Root degree `2k` in the integer-ring challenge norm.
pub const CHALLENGE_NORM_ROOT_DEGREE_V1: u8 = 64;
/// Challenge rejection parameter `eta`.
pub const CHALLENGE_ETA_V1: u16 = 140;
/// Maximum rejected uniform draws for one coefficient before failing closed.
pub const MAX_UNIFORM_REJECTION_ATTEMPTS_V1: u32 = 4_096;
/// Maximum complete challenge candidates read sequentially from one XOF.
pub const MAX_CHALLENGE_CANDIDATE_ATTEMPTS_V1: u32 = 4_096;
/// Exact squared bound on the credential randomness vector.
pub const RANDOMNESS_NORM_SQUARED_BOUND_V1: u64 = 11_881;
/// Exact squared bound on the signature preimage.
pub const SIGNATURE_NORM_SQUARED_BOUND_V1: u64 = 34_034_726;
/// Response squared-norm bound.
pub const RESPONSE_NORM_SQUARED_BOUND_V1: u64 = 143_158_532_224_272_924;
/// `z1` squared-norm bound computed as `floor(2 * 50 * 64 * 962 * 2^(2*23) / 400)`.
pub const Z1_NORM_SQUARED_BOUND_V1: u64 = 1_083_115_710_382_604_288;
/// `z3` squared-norm bound.
pub const Z3_NORM_SQUARED_BOUND_V1: u64 = 113_676_554_463_109;
/// `z4` infinity-norm bound.
pub const Z4_INFINITY_NORM_BOUND_V1: u64 = 13_314_398_617;
/// Exact truncation bounds `20 * sigma = 31 * 2^k` for native sampling.
pub const GAUSSIAN_TRUNCATION_BOUNDS_V1: [i64; 4] =
    [260_046_848, 126_976, 8_126_464, 16_642_998_272];
/// Exact Gaussian numerator in `sigma = 31 * 2^k / 20`.
pub const GAUSSIAN_SIGMA_NUMERATOR_V1: u64 = 31;
/// Exact Gaussian denominator in `sigma = 31 * 2^k / 20`.
pub const GAUSSIAN_SIGMA_DENOMINATOR_V1: u64 = 20;
/// Little-endian limbs of `ceil(M * 2^256)` for the four rejection decisions.
///
/// The constants were generated at 600 decimal digits from the exact profile inputs. In particular,
/// the third value uses the integer squared witness bound `34_034_726`, rather than first rounding
/// its square root through a machine-number parameter generator. Ceiling is intentional: each
/// encoded value is a one-sided upper bound on the theorem's rejection constant, with excess below
/// `2^-256`.
pub const REJECTION_M_Q256_LIMBS_V1: [[u64; 5]; 4] = [
    [
        13_907_885_945_416_354_779,
        9_791_630_218_197_076_709,
        9_859_465_049_745_963_633,
        5_934_122_506_364_705_697,
        2,
    ],
    [
        743_101_128_332_657_171,
        4_732_208_105_030_420_156,
        15_002_606_599_518_648_986,
        13_043_305_028_329_312_333,
        2,
    ],
    [
        8_669_441_880_001_792_043,
        12_508_921_868_517_726_490,
        8_821_746_166_229_566_167,
        652_277_607_672_955_130,
        1,
    ],
    [
        14_574_890_990_755_609_834,
        6_825_725_509_789_035_428,
        1_037_701_719_389_014_861,
        363_797_679_677_738_827,
        1,
    ],
];
/// Internal CRT primes. These are an implementation optimization and never
/// appear on the wire or define consensus residues.
pub const INTERNAL_CRT_PRIMES_V1: [u64; 3] = [
    1_125_899_906_840_833,
    1_125_899_906_839_937,
    1_125_899_906_837_633,
];
/// Primitive order-128 roots used to twist 64-point cyclic NTTs into
/// negacyclic NTTs under the three internal CRT primes.
pub const INTERNAL_CRT_NEGACYCLIC_ROOTS_V1: [u64; 3] = [
    900_675_728_376_939,
    739_582_794_740_178,
    939_297_152_150_952,
];
/// Multiplicative inverses of [`INTERNAL_CRT_NEGACYCLIC_ROOTS_V1`].
pub const INTERNAL_CRT_NEGACYCLIC_ROOT_INVERSES_V1: [u64; 3] = [
    477_721_967_291_069,
    373_074_842_565_665,
    612_960_912_415_571,
];
/// Multiplicative inverses of 64 under the three internal CRT primes.
pub const INTERNAL_CRT_RING_DEGREE_INVERSES_V1: [u64; 3] = [
    1_108_307_720_796_445,
    1_108_307_720_795_563,
    1_108_307_720_793_295,
];
/// Garner inverses `p0^-1 mod p1` and `(p0 * p1)^-1 mod p2`.
pub const INTERNAL_CRT_GARNER_INVERSES_V1: [u64; 2] = [963_800_478_288_205, 296_975_494_591_860];
/// `(p0 * p1) mod q`, pinned to avoid any multi-limb arithmetic at runtime.
pub const INTERNAL_CRT_FIRST_TWO_PRODUCT_MOD_PROOF_MODULUS_V1: u64 = 7_842_192;
/// `(p0 * p1 * p2) mod q`, used when the centered CRT representative is negative.
pub const INTERNAL_CRT_PRODUCT_MOD_PROOF_MODULUS_V1: u64 = 1_125_856_084_674_325;
/// Shared maximum number of projection- and response-mask rejection draws
/// across one top-level proof invocation.
///
/// Nested proof stages must reserve from this single budget; this is not a per-loop allowance.
pub const MAX_PROOF_SAMPLING_ATTEMPTS_V1: u32 = 4_096;
/// Maximum projection-mask draws before refreshing the whole-proof witness.
///
/// The fixed rejection constants give joint baseline acceptance above
/// `0.947168`; 64 consecutive rejection-decision failures are below `2^-256`.
pub const MAX_PROJECTION_SAMPLING_ATTEMPTS_PER_PROVE_ATTEMPT_V1: u32 = 64;
/// Maximum response-mask draws before refreshing the whole-proof witness.
///
/// The fixed rejection constants give joint baseline acceptance above
/// `0.159`; 1,024 consecutive rejection-decision failures are below `2^-256`.
pub const MAX_RESPONSE_SAMPLING_ATTEMPTS_PER_PROVE_ATTEMPT_V1: u32 = 1_024;
/// Maximum Gaussian proposal attempts for one coefficient.
pub const MAX_GAUSSIAN_COEFFICIENT_ATTEMPTS_V1: u32 = 4_096;
/// Pinned mathematical and implementation source profile.
///
/// The issuer is a concrete Falcon-512/NTRU specialization of the BLNS application relation. This
/// label deliberately does not claim that the full BLNS main-construction security reduction
/// applies to the specialization. The portable Falcon key-generation and recursive ffSampling core
/// is derived from the pinned Unlicense `rust-fn-dsa` workspace revision; the holder sampler and
/// Lantern proof relation follow the pinned LaZeR revision.
pub const SOURCE_PROFILE_V1: &[u8] = b"BLNS-specialization-no-main-construction-reduction:eprint-2023-560|LaZeR-10eafeca4cd53ff4fc54193dce904dbd0026fefd|rust-fn-dsa-workspace-0.3-daf14859b5aa3f8d75c42966ba7de83e6eb59997-Unlicense|portable-safe-rust-no-SIMD";
#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::bigint::{Encoding as _, U512, U1024};
    fn rejection_m_q256(index: usize) -> U512 {
        let mut bytes = [0_u8; 64];
        for (chunk, limb) in bytes
            .chunks_exact_mut(8)
            .zip(REJECTION_M_Q256_LIMBS_V1[index])
        {
            chunk.copy_from_slice(&limb.to_le_bytes());
        }
        U512::from_le_bytes(bytes)
    }
    fn joint_acceptance_exceeds(
        first: usize,
        second: usize,
        numerator: u64,
        denominator: u64,
    ) -> bool {
        // M_i is pinned as A_i / 2^256.  Joint baseline acceptance is
        // 1/(M_first*M_second), so p > n/d iff
        // n*A_first*A_second < d*2^512.
        let product: U1024 = rejection_m_q256(first).mul(&rejection_m_q256(second));
        let lhs = product.wrapping_mul(&U1024::from_u64(numerator));
        let rhs = U1024::from_u64(denominator).shl_vartime(512);
        lhs < rhs
    }
    #[test]
    fn modular_inverse_constants_are_exact() {
        assert_eq!(
            (u128::from(PROOF_INVERSE_TWO_V1) * 2) % u128::from(PROOF_MODULUS_V1),
            1
        );
        assert_eq!(
            (u128::from(PROOF_INVERSE_FOUR_V1) * 4) % u128::from(PROOF_MODULUS_V1),
            1
        );
        assert_eq!(
            (u128::from(APPLICATION_MODULUS_INVERSE_IN_PROOF_V1)
                * u128::from(APPLICATION_MODULUS_V1))
                % u128::from(PROOF_MODULUS_V1),
            1
        );
    }
    #[test]
    fn compression_identity_is_exact() {
        assert_eq!(
            u128::from(COMPRESSION_GAMMA_V1) * u128::from(COMPRESSION_MODULUS_V1) + 1,
            u128::from(PROOF_MODULUS_V1)
        );
    }
    #[test]
    fn profile_dimensions_are_internally_consistent() {
        assert_eq!(APPLICATION_ROWS_V1, EXACT_RELATIONS_V1);
        assert_eq!(
            APPLICATION_WITNESS_POLYNOMIALS_V1 + NORM_STATEMENTS_V1,
            TBOX_M1_V1
        );
        assert_eq!(TBOX_M2_V1 - TBOX_KMSIS_V1, 44);
        assert_eq!(BINARY_POLYNOMIALS_V1, ATTRIBUTE_COUNT_V1 * 2);
        assert_eq!(
            u16::from(CHALLENGE_NORM_POWER_V1) * 2,
            u16::from(CHALLENGE_NORM_ROOT_DEGREE_V1)
        );
        assert!(CHALLENGE_NORM_POWER_V1.is_power_of_two());
        assert!(MAX_UNIFORM_REJECTION_ATTEMPTS_V1 > 0);
        assert!(MAX_CHALLENGE_CANDIDATE_ATTEMPTS_V1 > 0);
    }
    #[test]
    fn rejection_constants_use_exact_inputs_and_one_sided_q256_rounding() {
        // Rounding the exact-input M3 constant back to Q128 gives these
        // limbs.  The pinned upstream generator instead produced
        // [7_569_140_089_676_268_920, 652_277_607_672_955_118, 1] after a
        // binary machine-number square-root detour.
        let exact_m3 = REJECTION_M_Q256_LIMBS_V1[2];
        let round_up = u64::from(exact_m3[1] >> 63 != 0);
        assert_eq!(
            [exact_m3[2] + round_up, exact_m3[3], exact_m3[4]],
            [8_821_746_166_229_566_168, 652_277_607_672_955_130, 1]
        );
        assert_ne!(
            [exact_m3[2] + round_up, exact_m3[3], exact_m3[4]],
            [7_569_140_089_676_268_920, 652_277_607_672_955_118, 1]
        );
    }
    #[test]
    fn local_rejection_caps_have_integer_proved_failure_margins() {
        const DENOMINATOR: u64 = 1_000_000;
        const PROJECTION_ACCEPTANCE_NUMERATOR: u64 = 947_168;
        const RESPONSE_ACCEPTANCE_NUMERATOR: u64 = 159_109;
        assert!(joint_acceptance_exceeds(
            2,
            3,
            PROJECTION_ACCEPTANCE_NUMERATOR,
            DENOMINATOR
        ));
        assert!(joint_acceptance_exceeds(
            0,
            1,
            RESPONSE_ACCEPTANCE_NUMERATOR,
            DENOMINATOR
        ));
        // Projection rejection is below 52,832 / 1,000,000 < 1/16.
        let projection_rejection_numerator = DENOMINATOR - PROJECTION_ACCEPTANCE_NUMERATOR;
        assert!(16_u128 * u128::from(projection_rejection_numerator) < u128::from(DENOMINATOR));
        assert_eq!(MAX_PROJECTION_SAMPLING_ATTEMPTS_PER_PROVE_ATTEMPT_V1, 64);
        // Response rejection is below 840,891 / 1,000,000, whose fourth
        // power is below 1/2.  Thus 1,024 failures are below 2^-256.
        let response_rejection_numerator = DENOMINATOR - RESPONSE_ACCEPTANCE_NUMERATOR;
        assert!(
            2_u128 * u128::from(response_rejection_numerator).pow(4)
                < u128::from(DENOMINATOR).pow(4)
        );
        assert_eq!(MAX_RESPONSE_SAMPLING_ATTEMPTS_PER_PROVE_ATTEMPT_V1, 1_024);
        assert_eq!(MAX_PROOF_SAMPLING_ATTEMPTS_V1, 4_096);
    }
}
