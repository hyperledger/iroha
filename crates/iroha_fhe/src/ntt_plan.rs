//! Precomputed constant-time negacyclic transform for one NTT prime.
//!
//! [`NegacyclicPlan`] pins the powers of a primitive `2n`-th root of unity
//! `psi` modulo an odd prime below `2^62` and runs the merged negacyclic
//! transform of Longa and Naehrig: the twist by `psi^i` is folded into the
//! butterflies, so no separate twisting pass and no bit-reversal pass exist.
//!
//! Layout, fixed for every target:
//!
//! - [`NegacyclicPlan::forward`] takes coefficients in natural order and
//!   leaves evaluations in bit-reversed order: output `k` is the value of the
//!   polynomial at `psi^(2 * bitrev(k) + 1)`.
//! - [`NegacyclicPlan::inverse`] is its exact inverse, including the division
//!   by `n`.
//! - Point-wise products of two forward transforms are the transform of the
//!   negacyclic product, whatever the evaluation order.
//!
//! Every butterfly is one Montgomery product by a pinned twiddle plus one
//! branch-free addition and subtraction ([`FixedModulus`]), and the index
//! schedule depends only on the length. The transform is therefore
//! constant-time in the coefficient values and serves secret polynomials. All
//! outputs are canonical residues. This is the deterministic scalar path; no
//! accelerated kernel exists for moduli above `2^32` yet.
// TODO: add NEON/AVX2/Metal/CUDA butterflies for 50 to 60-bit moduli once a
// profile is fixed (plan decision a2.1); each must return the words of this
// scalar path, which stays the fallback.
use crate::{constant_time::FixedModulus, modular};
use thiserror::Error;

/// Exclusive upper bound of a plan modulus.
pub const PLAN_MODULUS_BOUND: u64 = 1 << 62;

/// Failure to build a [`NegacyclicPlan`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum NttPlanError {
    /// The degree is not a power of two of at least two.
    #[error("transform degree must be a power of two of at least two")]
    UnsupportedDegree,
    /// The modulus is even, below three or not below `2^62`.
    #[error("transform modulus must be an odd prime in [3, 2^62)")]
    ModulusOutOfRange,
    /// The modulus is composite.
    #[error("transform modulus must be prime")]
    CompositeModulus,
    /// `psi` is not a primitive `2n`-th root of unity modulo the modulus.
    #[error("psi must be a primitive 2n-th root of unity")]
    RootNotPrimitive,
    /// A slice does not have exactly `n` coefficients.
    #[error("expected {expected} coefficients, found {found}")]
    LengthMismatch {
        /// The plan degree.
        expected: usize,
        /// The slice length.
        found: usize,
    },
}

/// Pinned transform constants of one prime and one power-of-two degree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NegacyclicPlan {
    fixed: FixedModulus,
    degree: usize,
    psi: u64,
    /// `psi^bitrev(k)` in Montgomery form, index `k` in `0..n`.
    forward_twiddles: Vec<u64>,
    /// `psi^-bitrev(k)` in Montgomery form, index `k` in `0..n`.
    inverse_twiddles: Vec<u64>,
    /// `n^-1` in Montgomery form.
    inverse_degree: u64,
}

/// `value * 2^64 mod modulus` for any word.
fn to_montgomery(fixed: FixedModulus, value: u64) -> u64 {
    fixed.montgomery_reduce_u128(u128::from(value) * u128::from(fixed.montgomery_r_squared))
}

/// `value * constant mod modulus` for any word and a Montgomery-form constant.
fn mul_by_montgomery_constant(fixed: FixedModulus, value: u64, constant: u64) -> u64 {
    fixed.montgomery_reduce_u128(u128::from(value) * u128::from(constant))
}

impl NegacyclicPlan {
    /// Pin the transform of degree `degree` modulo the prime `modulus` with root `psi`.
    ///
    /// # Errors
    /// [`NttPlanError::UnsupportedDegree`], [`NttPlanError::ModulusOutOfRange`],
    /// [`NttPlanError::CompositeModulus`] or [`NttPlanError::RootNotPrimitive`].
    pub fn new(degree: usize, modulus: u64, psi: u64) -> Result<Self, NttPlanError> {
        if degree < 2 || !degree.is_power_of_two() {
            return Err(NttPlanError::UnsupportedDegree);
        }
        if modulus >= PLAN_MODULUS_BOUND {
            return Err(NttPlanError::ModulusOutOfRange);
        }
        let fixed = FixedModulus::derive(modulus).ok_or(NttPlanError::ModulusOutOfRange)?;
        if !modular::is_prime_u64(modulus) {
            return Err(NttPlanError::CompositeModulus);
        }
        let order = u64::try_from(degree)
            .ok()
            .and_then(|degree| degree.checked_mul(2))
            .ok_or(NttPlanError::UnsupportedDegree)?;
        if !modular::is_primitive_root_of_order(modulus, psi, order) {
            return Err(NttPlanError::RootNotPrimitive);
        }
        let inverse_psi =
            modular::mod_inv_prime_u64(psi, modulus).ok_or(NttPlanError::RootNotPrimitive)?;
        let inverse_degree = modular::mod_inv_prime_u64(order / 2, modulus)
            .ok_or(NttPlanError::UnsupportedDegree)?;
        let bits = degree.ilog2();
        let mut forward_twiddles = vec![0_u64; degree];
        let mut inverse_twiddles = vec![0_u64; degree];
        let mut forward_power = 1_u64;
        let mut inverse_power = 1_u64;
        for exponent in 0..degree {
            let slot = exponent.reverse_bits() >> (usize::BITS - bits);
            forward_twiddles[slot] = to_montgomery(fixed, forward_power);
            inverse_twiddles[slot] = to_montgomery(fixed, inverse_power);
            forward_power = fixed.multiply(forward_power, psi);
            inverse_power = fixed.multiply(inverse_power, inverse_psi);
        }
        Ok(Self {
            fixed,
            degree,
            psi,
            forward_twiddles,
            inverse_twiddles,
            inverse_degree: to_montgomery(fixed, inverse_degree),
        })
    }

    /// The prime modulus.
    #[must_use]
    pub const fn prime(&self) -> u64 {
        self.fixed.modulus
    }

    /// The branch-free arithmetic of the modulus.
    #[must_use]
    pub const fn fixed(&self) -> FixedModulus {
        self.fixed
    }

    /// The transform degree `n`.
    #[must_use]
    pub const fn degree(&self) -> usize {
        self.degree
    }

    /// The pinned primitive `2n`-th root of unity.
    #[must_use]
    pub const fn psi(&self) -> u64 {
        self.psi
    }

    fn check_len(&self, values: &[u64]) -> Result<(), NttPlanError> {
        if values.len() == self.degree {
            Ok(())
        } else {
            Err(NttPlanError::LengthMismatch {
                expected: self.degree,
                found: values.len(),
            })
        }
    }

    /// Forward transform in place: natural-order coefficients to bit-reversed evaluations.
    ///
    /// Operands must be canonical residues.
    ///
    /// # Errors
    /// [`NttPlanError::LengthMismatch`], leaving `values` untouched.
    pub fn forward(&self, values: &mut [u64]) -> Result<(), NttPlanError> {
        self.check_len(values)?;
        let fixed: FixedModulus = self.fixed;
        let mut span = self.degree;
        let mut groups = 1_usize;
        while groups < self.degree {
            span /= 2;
            for (group, chunk) in values.chunks_exact_mut(2 * span).enumerate() {
                let twiddle = self.forward_twiddles[groups + group];
                let (low, high) = chunk.split_at_mut(span);
                for (left, right) in low.iter_mut().zip(high.iter_mut()) {
                    let product = mul_by_montgomery_constant(fixed, *right, twiddle);
                    let left_value = *left;
                    *left = fixed.add_canonical(left_value, product);
                    *right = fixed.sub_canonical(left_value, product);
                }
            }
            groups *= 2;
        }
        Ok(())
    }

    /// Inverse transform in place: bit-reversed evaluations to natural-order coefficients.
    ///
    /// Operands must be canonical residues.
    ///
    /// # Errors
    /// [`NttPlanError::LengthMismatch`], leaving `values` untouched.
    pub fn inverse(&self, values: &mut [u64]) -> Result<(), NttPlanError> {
        self.check_len(values)?;
        let fixed: FixedModulus = self.fixed;
        let mut span = 1_usize;
        let mut groups = self.degree / 2;
        while groups >= 1 {
            for (group, chunk) in values.chunks_exact_mut(2 * span).enumerate() {
                let twiddle = self.inverse_twiddles[groups + group];
                let (low, high) = chunk.split_at_mut(span);
                for (left, right) in low.iter_mut().zip(high.iter_mut()) {
                    let left_value = *left;
                    let right_value = *right;
                    *left = fixed.add_canonical(left_value, right_value);
                    *right = mul_by_montgomery_constant(
                        fixed,
                        fixed.sub_canonical(left_value, right_value),
                        twiddle,
                    );
                }
            }
            span *= 2;
            groups /= 2;
        }
        for value in values.iter_mut() {
            *value = mul_by_montgomery_constant(fixed, *value, self.inverse_degree);
        }
        Ok(())
    }

    /// `lhs[i] = lhs[i] * rhs[i]` for canonical residues.
    ///
    /// # Errors
    /// [`NttPlanError::LengthMismatch`], leaving `lhs` untouched.
    pub fn pointwise_mul_assign(&self, lhs: &mut [u64], rhs: &[u64]) -> Result<(), NttPlanError> {
        self.check_len(lhs)?;
        self.check_len(rhs)?;
        let fixed: FixedModulus = self.fixed;
        for (left, &right) in lhs.iter_mut().zip(rhs) {
            *left = fixed.multiply(*left, right);
        }
        Ok(())
    }

    /// `accumulator[i] += lhs[i] * rhs[i]` for canonical residues.
    ///
    /// # Errors
    /// [`NttPlanError::LengthMismatch`], leaving `accumulator` untouched.
    pub fn pointwise_mul_add_assign(
        &self,
        accumulator: &mut [u64],
        lhs: &[u64],
        rhs: &[u64],
    ) -> Result<(), NttPlanError> {
        self.check_len(accumulator)?;
        self.check_len(lhs)?;
        self.check_len(rhs)?;
        let fixed: FixedModulus = self.fixed;
        for ((slot, &left), &right) in accumulator.iter_mut().zip(lhs).zip(rhs) {
            *slot = fixed.add_canonical(*slot, fixed.multiply(left, right));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        modular::{WordModulus, primitive_root_of_order_with_candidate_limit},
        ntt::forward_negacyclic_ntt_with,
        polynomial::negacyclic_mul_mod_schoolbook,
    };

    /// The first chain prime of the N = 2^14, t = 257 candidate: `1 mod 2 * 2^14 * 257`.
    const PRIME_50: u64 = 562_950_180_667_393;
    /// A 60-bit prime `1 mod 2 * 2^16 * 257`.
    const PRIME_60: u64 = 576_460_752_472_375_297;

    fn plan(degree: usize, modulus: u64) -> NegacyclicPlan {
        let psi = primitive_root_of_order_with_candidate_limit(modulus, 2 * degree as u64, 1 << 16)
            .expect("root");
        NegacyclicPlan::new(degree, modulus, psi).expect("plan")
    }

    fn sample(degree: usize, modulus: u64, seed: u64) -> Vec<u64> {
        let mut state = seed | 1;
        (0..degree)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                // Mix boundary residues in with the pseudo-random ones.
                match state >> 61 {
                    0 => 0,
                    1 => modulus - 1,
                    _ => state % modulus,
                }
            })
            .collect()
    }

    #[test]
    fn construction_rejects_invalid_parameters() {
        let psi = plan(16, PRIME_50).psi();
        assert_eq!(
            NegacyclicPlan::new(0, PRIME_50, psi),
            Err(NttPlanError::UnsupportedDegree)
        );
        assert_eq!(
            NegacyclicPlan::new(1, PRIME_50, psi),
            Err(NttPlanError::UnsupportedDegree)
        );
        assert_eq!(
            NegacyclicPlan::new(12, PRIME_50, psi),
            Err(NttPlanError::UnsupportedDegree)
        );
        assert_eq!(
            NegacyclicPlan::new(16, 1 << 62, psi),
            Err(NttPlanError::ModulusOutOfRange)
        );
        assert_eq!(
            NegacyclicPlan::new(16, 2, 1),
            Err(NttPlanError::ModulusOutOfRange)
        );
        assert_eq!(
            NegacyclicPlan::new(16, PRIME_50 + 2, psi),
            Err(NttPlanError::CompositeModulus)
        );
        // psi^2 has order n, not 2n.
        let square = crate::modular::mul_mod_u64(psi, psi, PRIME_50);
        assert_eq!(
            NegacyclicPlan::new(16, PRIME_50, square),
            Err(NttPlanError::RootNotPrimitive)
        );
        assert_eq!(
            NegacyclicPlan::new(16, PRIME_50, 0),
            Err(NttPlanError::RootNotPrimitive)
        );
        let built = plan(16, PRIME_50);
        assert_eq!(built.prime(), PRIME_50);
        assert_eq!(built.degree(), 16);
        assert_eq!(built.fixed().modulus, PRIME_50);
    }

    #[test]
    fn forward_is_the_reference_transform_in_bit_reversed_order() {
        for (degree, modulus) in [
            (2_usize, PRIME_50),
            (8, PRIME_50),
            (64, PRIME_60),
            (128, 257),
        ] {
            let plan = plan(degree, modulus);
            let coefficients = sample(degree, modulus, 0x51 + degree as u64);
            let mut tabled = coefficients.clone();
            plan.forward(&mut tabled).expect("forward");
            let mut reference = coefficients.clone();
            forward_negacyclic_ntt_with(&mut reference, &WordModulus(modulus), plan.psi())
                .expect("reference");
            let bits = degree.ilog2();
            for (index, &value) in tabled.iter().enumerate() {
                let natural = index.reverse_bits() >> (usize::BITS - bits);
                assert_eq!(value, reference[natural], "degree {degree} index {index}");
                assert!(value < modulus);
            }
            plan.inverse(&mut tabled).expect("inverse");
            assert_eq!(tabled, coefficients);
        }
    }

    #[test]
    fn pointwise_product_is_the_schoolbook_negacyclic_product() {
        for (degree, modulus) in [(4_usize, PRIME_50), (32, PRIME_60), (128, 257)] {
            let plan = plan(degree, modulus);
            let lhs = sample(degree, modulus, 3);
            let rhs = sample(degree, modulus, 7);
            let expected = negacyclic_mul_mod_schoolbook(&lhs, &rhs, degree, modulus);
            let mut lhs_eval = lhs.clone();
            let mut rhs_eval = rhs.clone();
            plan.forward(&mut lhs_eval).expect("forward");
            plan.forward(&mut rhs_eval).expect("forward");
            let mut accumulated = vec![0_u64; degree];
            plan.pointwise_mul_add_assign(&mut accumulated, &lhs_eval, &rhs_eval)
                .expect("accumulate");
            plan.pointwise_mul_add_assign(&mut accumulated, &lhs_eval, &rhs_eval)
                .expect("accumulate");
            plan.pointwise_mul_assign(&mut lhs_eval, &rhs_eval)
                .expect("product");
            plan.inverse(&mut lhs_eval).expect("inverse");
            assert_eq!(lhs_eval, expected);
            plan.inverse(&mut accumulated).expect("inverse");
            let doubled: Vec<u64> = expected
                .iter()
                .map(|&value| crate::modular::add_mod_u64(value, value, modulus))
                .collect();
            assert_eq!(accumulated, doubled);
        }
    }

    #[test]
    fn wrong_lengths_are_rejected_without_touching_the_input() {
        let plan = plan(8, PRIME_50);
        let mut short = vec![1_u64; 7];
        let mismatch = Err(NttPlanError::LengthMismatch {
            expected: 8,
            found: 7,
        });
        assert_eq!(plan.forward(&mut short), mismatch);
        assert_eq!(plan.inverse(&mut short), mismatch);
        assert_eq!(short, vec![1_u64; 7]);
        let mut full = vec![2_u64; 8];
        assert_eq!(plan.pointwise_mul_assign(&mut full, &short), mismatch);
        assert_eq!(plan.pointwise_mul_assign(&mut short, &full), mismatch);
        assert_eq!(
            plan.pointwise_mul_add_assign(&mut full, &short, &short),
            mismatch
        );
        let full_copy = full.clone();
        assert_eq!(
            plan.pointwise_mul_add_assign(&mut short, &full_copy, &full_copy),
            mismatch
        );
        assert_eq!(
            plan.pointwise_mul_add_assign(&mut full, &full_copy, &short),
            mismatch
        );
        assert_eq!(full, vec![2_u64; 8]);
    }

    #[test]
    fn montgomery_helpers_reduce_any_word() {
        let fixed = FixedModulus::derive(PRIME_60).expect("fixed");
        for value in [0_u64, 1, PRIME_60 - 1, PRIME_60, u64::MAX, 1 << 63] {
            let constant = to_montgomery(fixed, 7);
            assert_eq!(
                mul_by_montgomery_constant(fixed, value, constant),
                crate::modular::mul_mod_u64(value, 7, PRIME_60)
            );
            assert_eq!(
                mul_by_montgomery_constant(fixed, 1, to_montgomery(fixed, value)),
                value % PRIME_60
            );
        }
    }
}
