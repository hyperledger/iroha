#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
use super::super::{comm::PRNG, table_assets::read_u32_le};
// ========================================================================
// Gaussian sampling for (f,g)
// ========================================================================
// This code samples the secret polynomials f and g deterministically
// from a given seed. The polynomial coefficients follow a given
// Gaussian distribution centred on zero. A PRNG (type parameter) is used
// to produce random 16-bit samples which are then used in a CDT table.
const GTAB_8: [u16; 48] = [
    1, 3, 6, 11, 22, 40, 73, 129, 222, 371, 602, 950, 1460, 2183, 3179, 4509, 6231, 8395, 11032,
    14150, 17726, 21703, 25995, 30487, 35048, 39540, 43832, 47809, 51385, 54503, 57140, 59304,
    61026, 62356, 63352, 64075, 64585, 64933, 65164, 65313, 65406, 65462, 65495, 65513, 65524,
    65529, 65532, 65534,
];
const GTAB_9: [u16; 34] = [
    1, 4, 11, 28, 65, 146, 308, 615, 1164, 2083, 3535, 5692, 8706, 12669, 17574, 23285, 29542,
    35993, 42250, 47961, 52866, 56829, 59843, 62000, 63452, 64371, 64920, 65227, 65389, 65470,
    65507, 65524, 65531, 65534,
];
const GTAB_10: [u16; 24] = [
    2, 8, 28, 94, 280, 742, 1761, 3753, 7197, 12472, 19623, 28206, 37329, 45912, 53063, 58338,
    61782, 63774, 64793, 65255, 65441, 65507, 65527, 65533,
];
/// Sample an odd-parity f or g polynomial of degree 2^logn, for 1 <= logn <= 10.
///
/// Each of at most `max_attempts` attempts starts one polynomial candidate.
/// An out-of-range coefficient or even parity rejects that candidate. A failed
/// attempt may leave a written prefix in `polynomial`; callers must discard
/// its contents when this function returns false.
///
/// # Panics
///
/// Panics if `logn` is outside 1..=10 or the output length is not 2^logn.
pub fn sample_f_bounded<T: PRNG>(
    logn: u32,
    rng: &mut T,
    polynomial: &mut [i8],
    max_attempts: u32,
) -> bool {
    assert!((1..=10).contains(&logn));
    let degree = 1 << logn;
    assert!(polynomial.len() == degree);
    let (tab, zz) = match logn {
        9 => (&GTAB_9[..], 1),
        10 => (&GTAB_10[..], 1),
        _ => (&GTAB_8[..], 1 << (8 - logn)),
    };
    let kmax = read_u32_le(&(tab.len() >> 1).to_le_bytes(), 0).cast_signed();
    'candidate: for _ in 0..max_attempts {
        let mut parity = 0;
        let mut index = 0;
        while index < degree {
            let mut coefficient = 0;
            for _ in 0..zz {
                let draw = u32::from(rng.next_u16());
                coefficient -= kmax;
                for &threshold in tab {
                    coefficient += (u32::from(threshold).wrapping_sub(draw) >> 31).cast_signed();
                }
            }
            // For reduced/test degrees 2^5 or less, the coefficient may
            // exceed [-127, +127]. Reject the whole candidate so this
            // retry consumes an attempt. Degrees 2^6 and greater cannot
            // enter this branch, including the production degree 512.
            if !(-127..=127).contains(&coefficient) {
                continue 'candidate;
            }
            polynomial[index] = coefficient.to_le_bytes()[0].cast_signed();
            index += 1;
            parity ^= coefficient.cast_unsigned();
        }
        // We need an odd parity (so that the resultant of f with X^n+1 is
        // an odd integer).
        if (parity & 1) != 0 {
            return true;
        }
    }
    false
}
#[cfg(test)]
mod tests {
    use super::*;
    struct EvenParityPrng {
        u16_calls: u32,
    }
    impl PRNG for EvenParityPrng {
        fn new(_seed: &[u8]) -> Self {
            Self { u16_calls: 0 }
        }
        fn next_u8(&mut self) -> u8 {
            0
        }
        fn next_u16(&mut self) -> u16 {
            self.u16_calls += 1;
            0
        }
        fn next_u64(&mut self) -> u64 {
            0
        }
        fn zeroize(&mut self) {
            self.u16_calls = 0;
        }
    }
    #[test]
    fn parity_sampler_stops_at_exact_public_attempt_cap() {
        const ATTEMPTS: u32 = 3;
        let mut rng = EvenParityPrng::new(&[]);
        let mut polynomial = [0_i8; 512];
        assert!(!sample_f_bounded(9, &mut rng, &mut polynomial, ATTEMPTS));
        assert_eq!(rng.u16_calls, ATTEMPTS * 512);
        assert!(polynomial.iter().all(|coefficient| *coefficient == -17));
        let calls_before_zero_budget = rng.u16_calls;
        assert!(!sample_f_bounded(9, &mut rng, &mut polynomial, 0));
        assert_eq!(rng.u16_calls, calls_before_zero_budget);
    }

    struct ScriptedPrng {
        draws: Vec<u16>,
        consumed: usize,
    }
    impl PRNG for ScriptedPrng {
        fn new(_seed: &[u8]) -> Self {
            Self {
                draws: Vec::new(),
                consumed: 0,
            }
        }
        fn next_u8(&mut self) -> u8 {
            panic!("keygen Gaussian uses only 16-bit draws")
        }
        fn next_u16(&mut self) -> u16 {
            let draw = self.draws[self.consumed];
            self.consumed += 1;
            draw
        }
        fn next_u64(&mut self) -> u64 {
            panic!("keygen Gaussian uses only 16-bit draws")
        }
        fn zeroize(&mut self) {
            self.draws.fill(0);
        }
    }

    #[test]
    fn coefficient_thresholds_match_integer_cdf_and_odd_parity_at_every_degree() {
        for logn in 1..=10 {
            let degree = 1_usize << logn;
            let (table, draws_per_coefficient) = match logn {
                9 => (&GTAB_9[..], 1),
                10 => (&GTAB_10[..], 1),
                _ => (&GTAB_8[..], 1 << (8 - logn)),
            };
            let half = i32::try_from(table.len() / 2).expect("small constant table");
            let cdf = |draw| {
                i32::try_from(table.iter().filter(|&&threshold| threshold < draw).count())
                    .expect("small constant table")
                    - half
            };
            assert_eq!(cdf(32768), 0);
            let plus_one_draw = table[table.len() / 2] + 1;
            assert_eq!(cdf(plus_one_draw), 1);
            let mut boundaries = vec![0, u16::MAX];
            for &threshold in table {
                boundaries.extend([
                    threshold.saturating_sub(1),
                    threshold,
                    threshold.saturating_add(1),
                ]);
            }
            for boundary in boundaries {
                let first = cdf(boundary);
                let second = i32::from(first % 2 == 0);
                let mut rng = ScriptedPrng {
                    draws: vec![32768; degree * draws_per_coefficient],
                    consumed: 0,
                };
                rng.draws[0] = boundary;
                if second != 0 {
                    rng.draws[draws_per_coefficient] = plus_one_draw;
                }
                let mut polynomial = vec![91_i8; degree];
                assert!(sample_f_bounded(logn, &mut rng, &mut polynomial, 1));
                assert_eq!(i32::from(polynomial[0]), first);
                assert_eq!(i32::from(polynomial[1]), second);
                assert!(polynomial[2..].iter().all(|&coefficient| coefficient == 0));
                assert_eq!(rng.consumed, degree * draws_per_coefficient);
                assert_ne!(
                    polynomial
                        .iter()
                        .map(|&coefficient| i32::from(coefficient))
                        .sum::<i32>()
                        % 2,
                    0
                );
            }
        }
    }

    struct GuardedOutOfRangePrng {
        calls: usize,
        limit: usize,
    }
    impl PRNG for GuardedOutOfRangePrng {
        fn new(_seed: &[u8]) -> Self {
            Self { calls: 0, limit: 0 }
        }
        fn next_u8(&mut self) -> u8 {
            panic!("keygen Gaussian uses only 16-bit draws")
        }
        fn next_u16(&mut self) -> u16 {
            assert!(
                self.calls < self.limit,
                "coefficient rejection escaped the polynomial attempt budget"
            );
            self.calls += 1;
            0
        }
        fn next_u64(&mut self) -> u64 {
            panic!("keygen Gaussian uses only 16-bit draws")
        }
        fn zeroize(&mut self) {
            self.calls = 0;
        }
    }

    fn assert_reduced_degree_coefficient_refusal_is_bounded(logn: u32) {
        let degree = 1_usize << logn;
        let draws_per_coefficient = 1_usize << (8 - logn);
        // A zero draw contributes -24 each time, outside the sampler's accepted
        // [-127, 127] interval for each reduced degree under test.
        assert!(24 * draws_per_coefficient > 127);
        for attempts in [0_u32, 1, 3] {
            let expected_draws =
                usize::try_from(attempts).expect("small test budget") * draws_per_coefficient;
            let mut rng = GuardedOutOfRangePrng {
                calls: 0,
                limit: expected_draws,
            };
            let mut polynomial = vec![91_i8; degree];
            assert!(!sample_f_bounded(logn, &mut rng, &mut polynomial, attempts));
            assert_eq!(rng.calls, expected_draws);
            assert_eq!(polynomial, vec![91_i8; degree]);
        }
    }

    #[test]
    fn reduced_degree_2_coefficient_refusal_stops_at_candidate_budget() {
        assert_reduced_degree_coefficient_refusal_is_bounded(1);
    }
    #[test]
    fn reduced_degree_4_coefficient_refusal_stops_at_candidate_budget() {
        assert_reduced_degree_coefficient_refusal_is_bounded(2);
    }
    #[test]
    fn reduced_degree_8_coefficient_refusal_stops_at_candidate_budget() {
        assert_reduced_degree_coefficient_refusal_is_bounded(3);
    }
    #[test]
    fn reduced_degree_16_coefficient_refusal_stops_at_candidate_budget() {
        assert_reduced_degree_coefficient_refusal_is_bounded(4);
    }
    #[test]
    fn reduced_degree_32_coefficient_refusal_stops_at_candidate_budget() {
        assert_reduced_degree_coefficient_refusal_is_bounded(5);
    }

    #[test]
    fn reduced_degree_coefficient_refusal_restarts_the_complete_candidate() {
        for logn in 1..=5 {
            let degree = 1_usize << logn;
            let draws_per_coefficient = 1_usize << (8 - logn);
            let refused_prefix_draws = 2 * draws_per_coefficient;
            let expected_draws = refused_prefix_draws + degree * draws_per_coefficient;
            let mut draws = vec![32768; expected_draws];
            // The first candidate writes +1, then rejects an out-of-range
            // second coefficient. The second candidate must restart at index 0.
            draws[0] = 35049;
            draws[draws_per_coefficient..refused_prefix_draws].fill(0);
            draws[refused_prefix_draws + draws_per_coefficient] = 35049;
            let mut rng = ScriptedPrng { draws, consumed: 0 };
            let mut polynomial = vec![91_i8; degree];
            assert!(sample_f_bounded(logn, &mut rng, &mut polynomial, 2));
            let mut expected = vec![0_i8; degree];
            expected[1] = 1;
            assert_eq!(polynomial, expected);
            assert_eq!(rng.consumed, expected_draws);
        }
    }

    #[test]
    fn reduced_degree_candidate_exhaustion_retains_only_its_written_prefix() {
        for logn in 1..=5 {
            let degree = 1_usize << logn;
            let draws_per_coefficient = 1_usize << (8 - logn);
            let expected_draws = 2 * draws_per_coefficient;
            // A forbidden same-coefficient retry could accept zero from the
            // unused tail and return true after the candidate budget expired.
            let mut draws = vec![32768; expected_draws + draws_per_coefficient];
            draws[0] = 35049;
            draws[draws_per_coefficient..expected_draws].fill(0);
            let mut rng = ScriptedPrng { draws, consumed: 0 };
            let mut polynomial = vec![91_i8; degree];
            assert!(!sample_f_bounded(logn, &mut rng, &mut polynomial, 1));
            assert_eq!(polynomial[0], 1);
            assert!(polynomial[1..].iter().all(|&coefficient| coefficient == 91));
            assert_eq!(rng.consumed, expected_draws);
        }
    }
}
