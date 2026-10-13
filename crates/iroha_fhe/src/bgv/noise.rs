//! Public worst-case noise bounds and the decryption-failure condition.
//!
//! For a ciphertext at level `l`, let `v` be the centered representative of
//! `c0 + c1*s` modulo `Q_l` (plus `c2*s^2` for an unrelinearized product).
//! While the invariant below holds, `v = m + t*e` over the integers with `m`
//! the centered plaintext, so `v mod t` is the plaintext. Every ciphertext
//! carries a [`NoiseBound`] `V` with `||v||_inf <= V`.
//!
//! # What the bound is computed from
//!
//! Only public quantities: the ring degree `N`, the plaintext modulus `t`,
//! the error bound `B` (the centered binomial parameter), the primes, and the
//! sequence of operations. The secret key enters through the worst case
//! `||s||_1 <= N` only; plaintext operands enter through a declared public
//! norm bound, never through their values. No function here takes a key, a
//! coin or a decrypted value, so a bound cannot leak one.
//!
//! # Transfer rules
//!
//! With `||a*b||_inf <= ||a||_1 * ||b||_inf <= N * ||a||_inf * ||b||_inf` in
//! `Z[X] / (X^N + 1)`:
//!
//! | Operation | Bound of the result |
//! | --- | --- |
//! | fresh public-key encryption | `(t-1)/2 + t*B*(2N + 1)` ([`fresh_noise`]) |
//! | noiseless embedding of a plaintext | `(t-1)/2` ([`plaintext_noise`]) |
//! | addition, subtraction | `V_a + V_b` |
//! | negation | `V` |
//! | plaintext addition, subtraction | `V + (t-1)/2` |
//! | plaintext multiplication by `p` | `V * W`, `W >= ||p||_1` declared |
//! | tensor product | `N * V_a * V_b` ([`product_noise`]) |
//! | relinearization, automorphism | `V + E_ks(l)` ([`key_switch_noise`]) |
//! | modulus switch dropping `q_l` | `floor((V + t*(q_l-1)/2*(1+N)) / q_l)` ([`switch_down_noise`]) |
//!
//! Fresh encryption: `v = m + t*(e*u + e0 + e1*s)` with `u`, `s` ternary and
//! every error coefficient in `[-B, B]`, so `||e*u|| <= N*B`, `||e0|| <= B`
//! and `||e1*s|| <= N*B`.
//!
//! Key switching at level `l` with digits `d_j` (centered, `|d_j| <= (Q_j-1)/2`
//! for the digit modulus `Q_j` at that level), key errors `e_j` and the
//! division by the special modulus `P`: before the division the switched sum
//! is `P*d*s' + t*sum_j d_j*e_j`; the division subtracts `delta_0 + delta_1*s`
//! with `|delta_i| <= t*(P-1)/2` and divides exactly by `P`. The added term is
//! `(t*sum_j d_j*e_j - delta_0 - delta_1*s) / P`, a multiple of `t`, with
//! `E_ks(l) = floor((t*N*B*sum_j floor(Q_j/2) + t*(P-1)/2*(1+N)) / P)`.
//!
//! Modulus switching: `v' = (v - delta_0 - delta_1*s) / q_l` exactly, with
//! `|delta_i| <= t*(q_l-1)/2`.
//!
//! # Admission and the failure condition
//!
//! An operation is admitted only when the bound of every ciphertext it
//! produces is at most the capacity `(Q_l - 1) / 2` of its level. Decryption
//! is correct exactly when `||v||_inf <= (Q_l - 1) / 2`: then the centered
//! reduction modulo `Q_l` returns `v` itself. It fails when a coefficient of
//! the true `m + t*e` exceeds the capacity, because the reduction then adds a
//! multiple of `Q_l = 1 (mod t)` and shifts the plaintext.
//!
//! # Failure probability
//!
//! The rules above are deterministic given `||e||_inf <= B` for every sampled
//! error and ternary `s`, `u`. The centered binomial sampler has support
//! exactly `[-B, B]`, so the tail event `|e_i| > B` has probability zero and
//! an admitted sequence over honestly sampled keys and ciphertexts never
//! fails to decrypt. For a sampler with a non-zero tail `p_tail = Pr[|e_i| >
//! B]`, the failure probability is at most `p_tail` times the number of error
//! coefficients drawn over the key lifetime (union bound); that case does not
//! arise for the pinned sampler. The bound says nothing about a ciphertext or
//! key that was not produced by these samplers: admitting one needs a proof
//! of well-formedness, which is outside this module.
use crate::natural::Natural;

/// An exact public upper bound of `||c0 + c1*s||_inf` (centered modulo `Q_l`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NoiseBound(Natural);

impl NoiseBound {
    /// Wrap a bound.
    #[must_use]
    pub const fn new(bound: Natural) -> Self {
        Self(bound)
    }

    /// The bound as an exact integer.
    #[must_use]
    pub const fn as_natural(&self) -> &Natural {
        &self.0
    }

    /// Bit length of the bound.
    #[must_use]
    pub fn bits(&self) -> usize {
        self.0.bit_len()
    }
}

/// `usize` as a word; ring degrees are at most `2^17`.
fn degree_word(degree: usize) -> u64 {
    u64::try_from(degree).unwrap_or(u64::MAX)
}

/// Bound of a noiseless plaintext embedding and of a plaintext addend: `(t - 1) / 2`.
#[must_use]
pub fn plaintext_noise(plaintext_modulus: u64) -> Natural {
    Natural::from_u64((plaintext_modulus.max(1) - 1) / 2)
}

/// Bound of a fresh public-key encryption: `(t-1)/2 + t*B*(2N + 1)`.
#[must_use]
pub fn fresh_noise(degree: usize, plaintext_modulus: u64, error_bound: u64) -> Natural {
    Natural::from_u64(plaintext_modulus)
        .mul_u64(error_bound)
        .mul(&Natural::from_u64(degree_word(degree)).mul_u64(2).add_u64(1))
        .add(&plaintext_noise(plaintext_modulus))
}

/// Bound of a tensor product: `N * V_a * V_b`.
#[must_use]
pub fn product_noise(lhs: &Natural, rhs: &Natural, degree: usize) -> Natural {
    lhs.mul(rhs).mul_u64(degree_word(degree))
}

/// Bound of the noise one hybrid key switch adds.
///
/// `digit_moduli` are the exact digit moduli present at the level and
/// `special_primes` the special basis:
/// `floor((t*N*B*sum_j floor(Q_j/2) + t*(P-1)/2*(1+N)) / P)`.
#[must_use]
pub fn key_switch_noise(
    degree: usize,
    plaintext_modulus: u64,
    error_bound: u64,
    digit_moduli: &[Natural],
    special_primes: &[u64],
) -> Natural {
    let degree = degree_word(degree);
    let digit_halves = digit_moduli.iter().fold(Natural::zero(), |sum, modulus| {
        sum.add(&modulus.half_floor())
    });
    let key_error_term = digit_halves
        .mul_u64(plaintext_modulus)
        .mul_u64(degree)
        .mul_u64(error_bound);
    let special = Natural::product_of(special_primes);
    let rounding_term = special
        .half_floor()
        .mul_u64(plaintext_modulus)
        .mul(&Natural::from_u64(degree).add_u64(1));
    // Dividing by each prime in turn is the floor division by their product.
    special_primes
        .iter()
        .fold(key_error_term.add(&rounding_term), |quotient, &prime| {
            quotient.div_floor_u64(prime).unwrap_or_default()
        })
}

/// Bound after dropping `dropped_prime`: `floor((V + t*(q-1)/2*(1+N)) / q)`.
#[must_use]
pub fn switch_down_noise(
    bound: &Natural,
    degree: usize,
    plaintext_modulus: u64,
    dropped_prime: u64,
) -> Natural {
    let rounding = Natural::from_u64(dropped_prime.max(1) - 1)
        .half_floor()
        .mul_u64(plaintext_modulus)
        .mul(&Natural::from_u64(degree_word(degree)).add_u64(1));
    bound
        .add(&rounding)
        .div_floor_u64(dropped_prime)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_and_plaintext_bounds_match_their_formulas() {
        assert_eq!(plaintext_noise(257), Natural::from_u64(128));
        assert_eq!(plaintext_noise(3), Natural::from_u64(1));
        assert_eq!(plaintext_noise(0), Natural::zero());
        // N = 16: 128 + 257 * 21 * 33.
        assert_eq!(fresh_noise(16, 257, 21), Natural::from_u64(178_229));
        // N = 2^16: 128 + 257 * 21 * 131073.
        assert_eq!(
            fresh_noise(1 << 16, 257, 21),
            Natural::from_u64(128 + 257 * 21 * 131_073)
        );
        let bound = NoiseBound::new(Natural::from_u64(178_229));
        assert_eq!(bound.as_natural(), &Natural::from_u64(178_229));
        assert_eq!(bound.bits(), 18);
        assert!(bound < NoiseBound::new(Natural::from_u64(178_230)));
    }

    #[test]
    fn product_bound_is_degree_times_both_bounds() {
        assert_eq!(
            product_noise(&Natural::from_u64(1000), &Natural::from_u64(7), 16),
            Natural::from_u64(112_000)
        );
        let wide = Natural::from_u128(u128::MAX);
        assert_eq!(
            product_noise(&wide, &wide, 1 << 16),
            wide.mul(&wide).mul_u64(1 << 16)
        );
        assert_eq!(product_noise(&Natural::zero(), &wide, 16), Natural::zero());
    }

    #[test]
    fn key_switch_bound_matches_wide_arithmetic() {
        // Digits 1009 * 1013 and 1019; special 2003 * 2011; t = 5, B = 2, N = 8.
        let digits = [Natural::from_u64(1009 * 1013), Natural::from_u64(1019)];
        let special = [2003_u64, 2011];
        let product = 2003_u128 * 2011;
        let halves = (1009 * 1013_u128) / 2 + 1019 / 2;
        let numerator = 5 * 8 * 2 * halves + 5 * ((product - 1) / 2) * 9;
        assert_eq!(
            key_switch_noise(8, 5, 2, &digits, &special),
            Natural::from_u128(numerator / product)
        );
        // With no digit only the rounding of the division by P remains: floor(t*(1+N)/2 - ...).
        assert_eq!(
            key_switch_noise(8, 5, 2, &[], &special),
            Natural::from_u128(5 * ((product - 1) / 2) * 9 / product)
        );
        // A special modulus much smaller than the digits makes the key error dominate.
        let small = key_switch_noise(8, 5, 2, &digits, &[2003]);
        assert!(small > key_switch_noise(8, 5, 2, &digits, &special));
    }

    #[test]
    fn switch_down_bound_matches_wide_arithmetic() {
        let prime = 1_000_003_u64;
        for bound in [0_u128, 1, 999_999, 1 << 40, (1 << 90) + 12_345] {
            let expected = (bound + 257 * (u128::from(prime - 1) / 2) * 17) / u128::from(prime);
            assert_eq!(
                switch_down_noise(&Natural::from_u128(bound), 16, 257, prime),
                Natural::from_u128(expected)
            );
        }
        // The floor is at most t * (1 + N) / 2 above the scaled bound.
        assert_eq!(
            switch_down_noise(&Natural::zero(), 16, 257, prime),
            Natural::from_u64(257 * 17 / 2)
        );
        assert_eq!(degree_word(16), 16);
    }
}
