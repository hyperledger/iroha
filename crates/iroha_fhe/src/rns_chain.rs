//! Arbitrary-chain RNS: exact basis conversion and congruence-preserving scaling.
//!
//! [`crate::rns`] reconstructs through `u128` and therefore stops at chains
//! whose product fits 128 bits. This module has no such limit. A basis is any
//! number (up to [`MAX_BASIS_PRIMES`]) of distinct odd primes below `2^62`,
//! and every operation stays in word residues:
//!
//! - **Mixed-radix digits** ([`RnsBasis::mixed_radix_in_place`]). The
//!   canonical representative `x` in `[0, Q)` of a residue vector is written
//!   `x = a_0 + a_1*q_0 + a_2*q_0*q_1 + ...` with `0 <= a_i < q_i` (Garner).
//!   The digits are exact, so nothing is approximated and no overshoot by a
//!   multiple of `Q` can occur.
//! - **Basis conversion** ([`RnsBasis::convert_centered`],
//!   [`RnsBasis::convert_canonical`]). The residue of `x`, or of its centered
//!   representative, modulo any odd target modulus is `sum_i a_i * W_i` with
//!   pinned weights `W_i = q_0*...*q_(i-1) mod target`.
//! - **Congruence-preserving scale-down** ([`CongruentScaleDown`]). For a
//!   polynomial `c` known modulo `B*D` and a scale `t` coprime to `D`, the
//!   result is `c' = (c - t*w) / D` modulo `B`, where `w` is the centered
//!   representative of `c * t^-1` modulo `D`. Then `c'*D = c (mod t)` and
//!   `|t*w| <= t*(D-1)/2`. With `t = 1` this is exact division with rounding
//!   to nearest. A BGV modulus switch and the division by the special modulus
//!   of hybrid key switching are this operation with `t` the plaintext
//!   modulus.
//!
//! # Centered representatives and ties
//!
//! Every basis product `Q` is odd, so the centered representative of `x` is
//! unique: `x` when `x <= (Q-1)/2` and `x - Q` otherwise. No tie exists and no
//! rounding rule is needed. `(Q-1)/2` has the mixed-radix digits
//! `(q_i-1)/2`, so the comparison is a digit-wise lexicographic comparison
//! and `Q` itself is never built.
//!
//! # Secrets
//!
//! Residue arithmetic uses the branch-free Montgomery kernels of
//! [`FixedModulus`]; the half comparison uses branch-free selects; loop bounds
//! depend only on the basis size and the degree. Conversion and scaling are
//! therefore constant-time in the residue values and serve secret-dependent
//! polynomials. Per-coefficient scratch lives in clearing buffers.
//! [`RnsBasis::reconstruct_canonical`] and [`RnsBasis::reconstruct_centered`]
//! return [`Natural`] values and are for public data only.
use crate::{
    constant_time::{FixedModulus, equal_bit_u64, greater_than_bit_u64, select_u64},
    modular,
    natural::Natural,
};
use thiserror::Error;
use zeroize::Zeroizing;

/// Largest number of primes in one basis.
pub const MAX_BASIS_PRIMES: usize = 64;

/// Exclusive upper bound of a basis prime.
pub const BASIS_PRIME_BOUND: u64 = 1 << 62;

/// Failure of an arbitrary-chain RNS operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum RnsChainError {
    /// The basis has no prime.
    #[error("basis is empty")]
    EmptyBasis,
    /// The basis has more primes than [`MAX_BASIS_PRIMES`].
    #[error("basis has more than {max} primes")]
    TooManyPrimes {
        /// The supported maximum.
        max: usize,
    },
    /// A basis prime is even, below three or not below `2^62`.
    #[error("basis prime {index} is not an odd value in [3, 2^62)")]
    PrimeOutOfRange {
        /// Index of the prime.
        index: usize,
    },
    /// A basis prime is composite.
    #[error("basis prime {index} is composite")]
    CompositePrime {
        /// Index of the prime.
        index: usize,
    },
    /// A prime occurs twice, within one basis or across two bases that must be disjoint.
    #[error("prime {index} occurs twice")]
    DuplicatePrime {
        /// Index of the second occurrence.
        index: usize,
    },
    /// A target modulus is even, below three or not below `2^63`.
    #[error("target modulus is not an odd value in [3, 2^63)")]
    TargetOutOfRange,
    /// A conversion target was built for a basis of another size.
    #[error("conversion target belongs to a basis of {target} primes, not {basis}")]
    TargetBasisMismatch {
        /// Primes of the basis the target was built for.
        target: usize,
        /// Primes of the basis it was used with.
        basis: usize,
    },
    /// A slice has the wrong number of words.
    #[error("expected {expected} words, found {found}")]
    LengthMismatch {
        /// Required length.
        expected: usize,
        /// Supplied length.
        found: usize,
    },
    /// The scale is zero or a multiple of a dropped prime.
    #[error("scale is not invertible modulo dropped prime {index}")]
    ScaleNotInvertible {
        /// Index of the dropped prime.
        index: usize,
    },
    /// A size computation left the index range.
    #[error("size exceeds the supported range")]
    SizeOverflow,
}

/// `value * 2^64 mod modulus` for any word.
fn to_montgomery(fixed: FixedModulus, value: u64) -> u64 {
    fixed.montgomery_reduce_u128(u128::from(value) * u128::from(fixed.montgomery_r_squared))
}

/// `value * constant mod modulus` for any word and a Montgomery-form constant.
fn mul_const(fixed: FixedModulus, value: u64, constant: u64) -> u64 {
    fixed.montgomery_reduce_u128(u128::from(value) * u128::from(constant))
}

fn check_len(found: usize, expected: usize) -> Result<(), RnsChainError> {
    if found == expected {
        Ok(())
    } else {
        Err(RnsChainError::LengthMismatch { expected, found })
    }
}

fn limb_major_len(limbs: usize, degree: usize) -> Result<usize, RnsChainError> {
    limbs.checked_mul(degree).ok_or(RnsChainError::SizeOverflow)
}

/// Validate one basis prime and return its branch-free arithmetic.
fn basis_prime(prime: u64, index: usize) -> Result<FixedModulus, RnsChainError> {
    if prime >= BASIS_PRIME_BOUND {
        return Err(RnsChainError::PrimeOutOfRange { index });
    }
    let fixed = FixedModulus::derive(prime).ok_or(RnsChainError::PrimeOutOfRange { index })?;
    if !modular::is_prime_u64(prime) {
        return Err(RnsChainError::CompositePrime { index });
    }
    Ok(fixed)
}

/// An ordered basis of distinct odd primes with its mixed-radix constants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RnsBasis {
    moduli: Vec<FixedModulus>,
    /// `earlier_inverses[i][j] = q_j^-1 mod q_i` in Montgomery form, `j < i`.
    earlier_inverses: Vec<Vec<u64>>,
    /// `lifts[i]`: the smallest multiple of `q_i` that is at least `2^62`.
    lifts: Vec<u64>,
    /// `(q_i - 1) / 2`: the mixed-radix digits of `(Q - 1) / 2`.
    half_digits: Vec<u64>,
    /// One in Montgomery form: multiplying by it reduces any word modulo `q_i`.
    ones: Vec<u64>,
}

/// Pinned weights that carry a basis into one target modulus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConversionTarget {
    fixed: FixedModulus,
    /// `q_0 * ... * q_(i-1) mod target` in Montgomery form.
    weights: Vec<u64>,
    /// `Q mod target`.
    product: u64,
}

impl ConversionTarget {
    /// The target modulus.
    #[must_use]
    pub const fn target_modulus(&self) -> u64 {
        self.fixed.modulus
    }
}

impl RnsBasis {
    /// Validate and pin a basis.
    ///
    /// # Errors
    /// [`RnsChainError::EmptyBasis`], [`RnsChainError::TooManyPrimes`],
    /// [`RnsChainError::PrimeOutOfRange`], [`RnsChainError::CompositePrime`]
    /// or [`RnsChainError::DuplicatePrime`], in that order per prime.
    pub fn new(primes: &[u64]) -> Result<Self, RnsChainError> {
        if primes.is_empty() {
            return Err(RnsChainError::EmptyBasis);
        }
        if primes.len() > MAX_BASIS_PRIMES {
            return Err(RnsChainError::TooManyPrimes {
                max: MAX_BASIS_PRIMES,
            });
        }
        let mut moduli = Vec::with_capacity(primes.len());
        for (index, &prime) in primes.iter().enumerate() {
            let fixed = basis_prime(prime, index)?;
            if primes[..index].contains(&prime) {
                return Err(RnsChainError::DuplicatePrime { index });
            }
            moduli.push(fixed);
        }
        let mut earlier_inverses = Vec::with_capacity(primes.len());
        let mut lifts = Vec::with_capacity(primes.len());
        let mut half_digits = Vec::with_capacity(primes.len());
        let mut ones = Vec::with_capacity(primes.len());
        for (index, &fixed) in moduli.iter().enumerate() {
            let prime = fixed.modulus;
            let mut row = Vec::with_capacity(index);
            for &earlier in &primes[..index] {
                // Distinct primes are coprime, so the inverse exists.
                let inverse = modular::mod_inv_prime_u64(earlier % prime, prime)
                    .ok_or(RnsChainError::DuplicatePrime { index })?;
                row.push(to_montgomery(fixed, inverse));
            }
            earlier_inverses.push(row);
            lifts.push(BASIS_PRIME_BOUND.div_ceil(prime) * prime);
            half_digits.push((prime - 1) / 2);
            ones.push(to_montgomery(fixed, 1));
        }
        Ok(Self {
            moduli,
            earlier_inverses,
            lifts,
            half_digits,
            ones,
        })
    }

    /// Number of primes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.moduli.len()
    }

    /// Always `false`: a basis has at least one prime.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.moduli.is_empty()
    }

    /// The primes in basis order.
    #[must_use]
    pub fn primes(&self) -> Vec<u64> {
        self.moduli.iter().map(|fixed| fixed.modulus).collect()
    }

    /// The exact product `Q` of the basis.
    #[must_use]
    pub fn product(&self) -> Natural {
        Natural::product_of(&self.primes())
    }

    /// `(Q - 1) / 2`: the largest magnitude of a centered representative.
    #[must_use]
    pub fn half_product(&self) -> Natural {
        self.product().half_floor()
    }

    /// Replace the residues of one coefficient by its mixed-radix digits.
    ///
    /// `residues[i]` is read modulo prime `i`; an unreduced word is reduced
    /// exactly. On return `residues[i]` is the digit `a_i` in `[0, q_i)` with
    /// `x = sum_i a_i * q_0 * ... * q_(i-1)` the canonical representative.
    ///
    /// # Errors
    /// [`RnsChainError::LengthMismatch`], leaving `residues` untouched.
    pub fn mixed_radix_in_place(&self, residues: &mut [u64]) -> Result<(), RnsChainError> {
        check_len(residues.len(), self.len())?;
        for index in 0..residues.len() {
            let fixed = self.moduli[index];
            let lift = self.lifts[index];
            let (digits, rest) = residues.split_at_mut(index);
            let mut accumulator = mul_const(fixed, rest[0], self.ones[index]);
            for (&digit, &inverse) in digits.iter().zip(&self.earlier_inverses[index]) {
                // `accumulator < q_i < 2^62 <= lift < 2^63` and `digit < 2^62`, so the
                // word below is positive, does not wrap and is `accumulator - digit mod q_i`.
                accumulator = mul_const(fixed, accumulator + lift - digit, inverse);
            }
            rest[0] = accumulator;
        }
        Ok(())
    }

    /// One exactly when the mixed-radix digits denote a value above `(Q - 1) / 2`.
    ///
    /// Digits beyond the basis size are ignored and missing digits count as zero.
    #[must_use]
    pub fn exceeds_half_bit(&self, digits: &[u64]) -> u64 {
        let mut greater = 0_u64;
        let mut equal = 1_u64;
        for (&digit, &half) in digits.iter().zip(&self.half_digits).rev() {
            greater |= equal & greater_than_bit_u64(digit, half);
            equal &= equal_bit_u64(digit, half);
        }
        greater
    }

    /// Pin the weights that carry this basis into `modulus`.
    ///
    /// The target may be any odd modulus in `[3, 2^63)`; it need not be prime
    /// and may be one of the basis primes.
    ///
    /// # Errors
    /// [`RnsChainError::TargetOutOfRange`].
    pub fn conversion_target(&self, modulus: u64) -> Result<ConversionTarget, RnsChainError> {
        let fixed = FixedModulus::derive(modulus).ok_or(RnsChainError::TargetOutOfRange)?;
        let mut weights = Vec::with_capacity(self.len());
        let mut weight = 1_u64;
        for basis_prime in &self.moduli {
            weights.push(to_montgomery(fixed, weight));
            weight = modular::mul_mod_u64(weight, basis_prime.modulus % modulus, modulus);
        }
        Ok(ConversionTarget {
            fixed,
            weights,
            product: weight,
        })
    }

    /// Residue of mixed-radix digits modulo a target, optionally of the centered representative.
    fn digits_to_target(digits: &[u64], negative: u64, target: &ConversionTarget) -> u64 {
        let fixed: FixedModulus = target.fixed;
        let mut value = 0_u64;
        for (&digit, &weight) in digits.iter().zip(&target.weights) {
            value = fixed.add_canonical(value, mul_const(fixed, digit, weight));
        }
        select_u64(value, fixed.sub_canonical(value, target.product), negative)
    }

    fn convert(
        &self,
        source: &[u64],
        degree: usize,
        targets: &[ConversionTarget],
        output: &mut [u64],
        centered: bool,
    ) -> Result<(), RnsChainError> {
        check_len(source.len(), limb_major_len(self.len(), degree)?)?;
        check_len(output.len(), limb_major_len(targets.len(), degree)?)?;
        for target in targets {
            if target.weights.len() != self.len() {
                return Err(RnsChainError::TargetBasisMismatch {
                    target: target.weights.len(),
                    basis: self.len(),
                });
            }
        }
        let mut digits = Zeroizing::new([0_u64; MAX_BASIS_PRIMES]);
        let digits = &mut digits[..self.len()];
        for coefficient in 0..degree {
            for (limb, digit) in digits.iter_mut().enumerate() {
                *digit = source[limb * degree + coefficient];
            }
            self.mixed_radix_in_place(digits)?;
            let negative = if centered {
                self.exceeds_half_bit(digits)
            } else {
                0
            };
            for (limb, target) in targets.iter().enumerate() {
                output[limb * degree + coefficient] =
                    Self::digits_to_target(digits, negative, target);
            }
        }
        Ok(())
    }

    /// Exact residues of the centered representative in every target modulus.
    ///
    /// `source` is limb-major: `len() * degree` residues, limb `i` modulo
    /// prime `i`. `output` receives `targets.len() * degree` canonical
    /// residues, limb-major in target order. The centered representative lies
    /// in `[-(Q-1)/2, (Q-1)/2]`.
    ///
    /// # Errors
    /// [`RnsChainError::LengthMismatch`], [`RnsChainError::SizeOverflow`] or
    /// [`RnsChainError::TargetBasisMismatch`]. Every check precedes the first
    /// write, so `output` is untouched on an error.
    pub fn convert_centered(
        &self,
        source: &[u64],
        degree: usize,
        targets: &[ConversionTarget],
        output: &mut [u64],
    ) -> Result<(), RnsChainError> {
        self.convert(source, degree, targets, output, true)
    }

    /// Exact residues of the canonical representative in `[0, Q)` in every target modulus.
    ///
    /// Layout and errors are those of [`Self::convert_centered`].
    ///
    /// # Errors
    /// As [`Self::convert_centered`].
    pub fn convert_canonical(
        &self,
        source: &[u64],
        degree: usize,
        targets: &[ConversionTarget],
        output: &mut [u64],
    ) -> Result<(), RnsChainError> {
        self.convert(source, degree, targets, output, false)
    }

    /// The canonical representative in `[0, Q)` of one coefficient. Public data only.
    ///
    /// # Errors
    /// [`RnsChainError::LengthMismatch`].
    pub fn reconstruct_canonical(&self, residues: &[u64]) -> Result<Natural, RnsChainError> {
        let mut digits = residues.to_vec();
        self.mixed_radix_in_place(&mut digits)?;
        let mut value = Natural::zero();
        let mut weight = Natural::one();
        for (&digit, fixed) in digits.iter().zip(&self.moduli) {
            value = value.add(&weight.mul_u64(digit));
            weight = weight.mul_u64(fixed.modulus);
        }
        Ok(value)
    }

    /// Sign and magnitude of the centered representative of one coefficient. Public data only.
    ///
    /// Returns `(negative, magnitude)` with `magnitude <= (Q - 1) / 2`; zero is not negative.
    ///
    /// # Errors
    /// [`RnsChainError::LengthMismatch`].
    pub fn reconstruct_centered(&self, residues: &[u64]) -> Result<(bool, Natural), RnsChainError> {
        let canonical = self.reconstruct_canonical(residues)?;
        if canonical <= self.half_product() {
            return Ok((false, canonical));
        }
        // `canonical < Q`, so the subtraction cannot fail.
        let magnitude = self
            .product()
            .checked_sub(&canonical)
            .ok_or(RnsChainError::SizeOverflow)?;
        Ok((true, magnitude))
    }
}

/// Exact division by a dropped basis that preserves the residue modulo a scale.
///
/// For a polynomial `c` given by its residues modulo the kept primes `B` and
/// the dropped primes `D`, [`Self::apply`] replaces the kept residues by those
/// of `c' = (c - t*w) / D`, where `w` is the centered representative of
/// `c * t^-1` modulo `D` and `t` is the scale. The division is exact because
/// `t*w = c (mod D)`. `c' * D = c (mod t)`, so when `D = 1 (mod t)` the residue
/// modulo `t` is unchanged, and `|c' - c/D| <= t/2`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CongruentScaleDown {
    dropped: RnsBasis,
    kept: Vec<FixedModulus>,
    scale: u64,
    /// `t^-1 mod d_i` in Montgomery form.
    scale_inverse_mod_dropped: Vec<u64>,
    /// The dropped basis carried into each kept prime.
    targets: Vec<ConversionTarget>,
    /// `t mod b` in Montgomery form.
    scale_mod_kept: Vec<u64>,
    /// `D^-1 mod b` in Montgomery form.
    dropped_inverse_mod_kept: Vec<u64>,
}

impl CongruentScaleDown {
    /// Pin the constants for dropping `dropped` from a polynomial over `kept` and `dropped`.
    ///
    /// # Errors
    /// The errors of [`RnsBasis::new`] for either list (kept primes are
    /// reported with their own index), [`RnsChainError::DuplicatePrime`] when a
    /// kept prime is also dropped, or [`RnsChainError::ScaleNotInvertible`].
    pub fn new(kept: &[u64], dropped: &[u64], scale: u64) -> Result<Self, RnsChainError> {
        let dropped_basis = RnsBasis::new(dropped)?;
        if kept.len() > MAX_BASIS_PRIMES {
            return Err(RnsChainError::TooManyPrimes {
                max: MAX_BASIS_PRIMES,
            });
        }
        let mut kept_moduli = Vec::with_capacity(kept.len());
        for (index, &prime) in kept.iter().enumerate() {
            let fixed = basis_prime(prime, index)?;
            if kept[..index].contains(&prime) || dropped.contains(&prime) {
                return Err(RnsChainError::DuplicatePrime { index });
            }
            kept_moduli.push(fixed);
        }
        let mut scale_inverse_mod_dropped = Vec::with_capacity(dropped.len());
        for (index, fixed) in dropped_basis.moduli.iter().enumerate() {
            let inverse = modular::mod_inv_prime_u64(scale % fixed.modulus, fixed.modulus)
                .ok_or(RnsChainError::ScaleNotInvertible { index })?;
            scale_inverse_mod_dropped.push(to_montgomery(*fixed, inverse));
        }
        let mut targets = Vec::with_capacity(kept.len());
        let mut scale_mod_kept = Vec::with_capacity(kept.len());
        let mut dropped_inverse_mod_kept = Vec::with_capacity(kept.len());
        for (index, &fixed) in kept_moduli.iter().enumerate() {
            let target = dropped_basis.conversion_target(fixed.modulus)?;
            let inverse = modular::mod_inv_prime_u64(target.product, fixed.modulus)
                .ok_or(RnsChainError::DuplicatePrime { index })?;
            dropped_inverse_mod_kept.push(to_montgomery(fixed, inverse));
            scale_mod_kept.push(to_montgomery(fixed, scale % fixed.modulus));
            targets.push(target);
        }
        Ok(Self {
            dropped: dropped_basis,
            kept: kept_moduli,
            scale,
            scale_inverse_mod_dropped,
            targets,
            scale_mod_kept,
            dropped_inverse_mod_kept,
        })
    }

    /// Number of kept primes.
    #[must_use]
    pub fn kept_len(&self) -> usize {
        self.kept.len()
    }

    /// Number of dropped primes.
    #[must_use]
    pub fn dropped_len(&self) -> usize {
        self.dropped.len()
    }

    /// The scale `t`.
    #[must_use]
    pub const fn scale(&self) -> u64 {
        self.scale
    }

    /// The dropped basis.
    #[must_use]
    pub const fn dropped(&self) -> &RnsBasis {
        &self.dropped
    }

    /// Replace the kept residues of `c` by those of `(c - t*w) / D`.
    ///
    /// `kept_residues` holds `kept_len() * degree` and `dropped_residues`
    /// `dropped_len() * degree` residues, both limb-major. Unreduced words
    /// are reduced exactly; the results are canonical.
    ///
    /// # Errors
    /// [`RnsChainError::LengthMismatch`] or [`RnsChainError::SizeOverflow`],
    /// leaving `kept_residues` untouched.
    pub fn apply(
        &self,
        kept_residues: &mut [u64],
        dropped_residues: &[u64],
        degree: usize,
    ) -> Result<(), RnsChainError> {
        check_len(
            kept_residues.len(),
            limb_major_len(self.kept.len(), degree)?,
        )?;
        check_len(
            dropped_residues.len(),
            limb_major_len(self.dropped.len(), degree)?,
        )?;
        let mut digits = Zeroizing::new([0_u64; MAX_BASIS_PRIMES]);
        let digits = &mut digits[..self.dropped.len()];
        for coefficient in 0..degree {
            for (limb, digit) in digits.iter_mut().enumerate() {
                *digit = mul_const(
                    self.dropped.moduli[limb],
                    dropped_residues[limb * degree + coefficient],
                    self.scale_inverse_mod_dropped[limb],
                );
            }
            self.dropped.mixed_radix_in_place(digits)?;
            let negative = self.dropped.exceeds_half_bit(digits);
            for (limb, kept) in self.kept.iter().enumerate() {
                let fixed: FixedModulus = *kept;
                let centered = RnsBasis::digits_to_target(digits, negative, &self.targets[limb]);
                let correction = mul_const(fixed, centered, self.scale_mod_kept[limb]);
                let slot = &mut kept_residues[limb * degree + coefficient];
                *slot = mul_const(
                    fixed,
                    fixed.sub_canonical(*slot, correction),
                    self.dropped_inverse_mod_kept[limb],
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SMALL: [u64; 4] = [97, 193, 257, 769];

    /// Integers that cover the centered range of the small basis, including its ends.
    fn small_values() -> Vec<i128> {
        let product: i128 = SMALL.iter().map(|&prime| i128::from(prime)).product();
        let half = (product - 1) / 2;
        let mut values = vec![0, 1, -1, half, -half, half - 1, 1 - half, 256, -256];
        let mut state = 0x9E37_79B9_7F4A_7C15_u64;
        for _ in 0..200 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            values.push(i128::from(state >> 1) % (2 * half + 1) - half);
        }
        values
    }

    fn residues_of(value: i128, primes: &[u64]) -> Vec<u64> {
        primes
            .iter()
            .map(|&prime| modular::reduce_i128_to_u64_mod(value, prime))
            .collect()
    }

    #[test]
    fn basis_validation_reports_the_first_defect() {
        assert_eq!(RnsBasis::new(&[]), Err(RnsChainError::EmptyBasis));
        assert_eq!(
            RnsBasis::new(&[97; MAX_BASIS_PRIMES + 1]),
            Err(RnsChainError::TooManyPrimes {
                max: MAX_BASIS_PRIMES
            })
        );
        assert_eq!(
            RnsBasis::new(&[97, 2]),
            Err(RnsChainError::PrimeOutOfRange { index: 1 })
        );
        assert_eq!(
            RnsBasis::new(&[1]),
            Err(RnsChainError::PrimeOutOfRange { index: 0 })
        );
        assert_eq!(
            RnsBasis::new(&[(1 << 62) + 1]),
            Err(RnsChainError::PrimeOutOfRange { index: 0 })
        );
        assert_eq!(
            RnsBasis::new(&[97, 99]),
            Err(RnsChainError::CompositePrime { index: 1 })
        );
        assert_eq!(
            RnsBasis::new(&[97, 193, 97]),
            Err(RnsChainError::DuplicatePrime { index: 2 })
        );
        let basis = RnsBasis::new(&SMALL).expect("basis");
        assert_eq!(basis.len(), 4);
        assert!(!basis.is_empty());
        assert_eq!(basis.primes(), SMALL);
        assert_eq!(basis.product().to_u128(), Some(97 * 193 * 257 * 769_u128));
        assert_eq!(
            basis.half_product().to_u128(),
            Some((97 * 193 * 257 * 769_u128 - 1) / 2)
        );
    }

    #[test]
    fn mixed_radix_digits_are_the_garner_digits() {
        let basis = RnsBasis::new(&SMALL).expect("basis");
        let product: i128 = SMALL.iter().map(|&prime| i128::from(prime)).product();
        for value in small_values() {
            let canonical = value.rem_euclid(product);
            let mut digits = residues_of(value, &SMALL);
            basis.mixed_radix_in_place(&mut digits).expect("digits");
            let mut rest = canonical;
            for (&digit, &prime) in digits.iter().zip(&SMALL) {
                assert_eq!(i128::from(digit), rest % i128::from(prime));
                rest /= i128::from(prime);
            }
            assert_eq!(rest, 0);
            assert_eq!(
                basis.exceeds_half_bit(&digits),
                u64::from(canonical > (product - 1) / 2),
                "value {value}"
            );
            let residues = residues_of(value, &SMALL);
            assert_eq!(
                basis.reconstruct_canonical(&residues).expect("natural"),
                Natural::from_u128(canonical.unsigned_abs())
            );
            let (negative, magnitude) = basis.reconstruct_centered(&residues).expect("centered");
            assert_eq!(negative, value < 0);
            assert_eq!(magnitude, Natural::from_u128(value.unsigned_abs()));
        }
        let mut short = [0_u64; 3];
        assert_eq!(
            basis.mixed_radix_in_place(&mut short),
            Err(RnsChainError::LengthMismatch {
                expected: 4,
                found: 3
            })
        );
        assert_eq!(
            basis.reconstruct_canonical(&short),
            Err(RnsChainError::LengthMismatch {
                expected: 4,
                found: 3
            })
        );
        assert_eq!(
            basis.reconstruct_centered(&short),
            Err(RnsChainError::LengthMismatch {
                expected: 4,
                found: 3
            })
        );
    }

    #[test]
    fn conversion_returns_exact_centered_and_canonical_residues() {
        let basis = RnsBasis::new(&SMALL).expect("basis");
        let product: i128 = SMALL.iter().map(|&prime| i128::from(prime)).product();
        // A prime of the basis, a foreign prime, a composite and a 62-bit modulus.
        let target_moduli = [257_u64, 12_289, 15, (1 << 62) + 1];
        let targets: Vec<ConversionTarget> = target_moduli
            .iter()
            .map(|&modulus| basis.conversion_target(modulus).expect("target"))
            .collect();
        assert_eq!(targets[1].target_modulus(), 12_289);
        let values = small_values();
        let degree = values.len();
        let mut source = vec![0_u64; SMALL.len() * degree];
        for (coefficient, &value) in values.iter().enumerate() {
            for (limb, &prime) in SMALL.iter().enumerate() {
                source[limb * degree + coefficient] = modular::reduce_i128_to_u64_mod(value, prime);
            }
        }
        let mut centered = vec![0_u64; targets.len() * degree];
        basis
            .convert_centered(&source, degree, &targets, &mut centered)
            .expect("centered");
        let mut canonical = vec![0_u64; targets.len() * degree];
        basis
            .convert_canonical(&source, degree, &targets, &mut canonical)
            .expect("canonical");
        for (coefficient, &value) in values.iter().enumerate() {
            for (limb, &modulus) in target_moduli.iter().enumerate() {
                assert_eq!(
                    centered[limb * degree + coefficient],
                    modular::reduce_i128_to_u64_mod(value, modulus)
                );
                assert_eq!(
                    canonical[limb * degree + coefficient],
                    modular::reduce_i128_to_u64_mod(value.rem_euclid(product), modulus)
                );
            }
        }
    }

    #[test]
    fn conversion_rejects_wrong_shapes_and_foreign_targets() {
        let basis = RnsBasis::new(&SMALL).expect("basis");
        let other = RnsBasis::new(&SMALL[..2]).expect("basis");
        let target = basis.conversion_target(12_289).expect("target");
        let foreign = other.conversion_target(12_289).expect("target");
        let source = vec![0_u64; 8];
        let mut output = vec![0_u64; 2];
        assert_eq!(
            basis.convert_centered(&source[..7], 2, std::slice::from_ref(&target), &mut output),
            Err(RnsChainError::LengthMismatch {
                expected: 8,
                found: 7
            })
        );
        assert_eq!(
            basis.convert_centered(&source, 2, std::slice::from_ref(&target), &mut output[..1]),
            Err(RnsChainError::LengthMismatch {
                expected: 2,
                found: 1
            })
        );
        assert_eq!(
            basis.convert_canonical(&source, 2, &[foreign], &mut output),
            Err(RnsChainError::TargetBasisMismatch {
                target: 2,
                basis: 4
            })
        );
        assert_eq!(
            basis.convert_centered(&source, usize::MAX, &[target], &mut output),
            Err(RnsChainError::SizeOverflow)
        );
        for modulus in [0_u64, 1, 2, 4, 1 << 63] {
            assert_eq!(
                basis.conversion_target(modulus),
                Err(RnsChainError::TargetOutOfRange)
            );
        }
    }

    /// `(c - t*w) / D` with `w` the centered representative of `c * t^-1 mod D`.
    fn reference_scale_down(value: i128, dropped: i128, scale: i128) -> i128 {
        let mut inverse = 0_i128;
        for candidate in 1..dropped {
            if candidate * scale % dropped == 1 {
                inverse = candidate;
            }
        }
        let mut centered = (value * inverse).rem_euclid(dropped);
        if centered > (dropped - 1) / 2 {
            centered -= dropped;
        }
        let numerator = value - scale * centered;
        assert_eq!(numerator % dropped, 0);
        numerator / dropped
    }

    #[test]
    fn scale_down_divides_exactly_and_preserves_the_scale_residue() {
        // Dropped primes are 1 mod 5, so the residue modulo the scale 5 is unchanged.
        let kept = [97_u64, 193];
        for (dropped, scale) in [(vec![11_u64], 5_u64), (vec![11, 31], 5), (vec![11, 31], 1)] {
            let dropped_product: i128 = dropped.iter().map(|&prime| i128::from(prime)).product();
            let plan = CongruentScaleDown::new(&kept, &dropped, scale).expect("plan");
            assert_eq!(plan.kept_len(), 2);
            assert_eq!(plan.dropped_len(), dropped.len());
            assert_eq!(plan.scale(), scale);
            assert_eq!(plan.dropped().primes(), dropped);
            let total = 97 * 193 * dropped_product;
            let values: Vec<i128> = (-(total - 1) / 2..=(total - 1) / 2)
                .step_by(usize::try_from(total / 997 + 1).expect("step"))
                .chain([(total - 1) / 2, -(total - 1) / 2, 0, 1, -1])
                .collect();
            let degree = values.len();
            let mut kept_residues = vec![0_u64; kept.len() * degree];
            let mut dropped_residues = vec![0_u64; dropped.len() * degree];
            for (coefficient, &value) in values.iter().enumerate() {
                for (limb, &prime) in kept.iter().enumerate() {
                    kept_residues[limb * degree + coefficient] =
                        modular::reduce_i128_to_u64_mod(value, prime);
                }
                for (limb, &prime) in dropped.iter().enumerate() {
                    dropped_residues[limb * degree + coefficient] =
                        modular::reduce_i128_to_u64_mod(value, prime);
                }
            }
            plan.apply(&mut kept_residues, &dropped_residues, degree)
                .expect("apply");
            let scale_wide = i128::from(scale);
            for (coefficient, &value) in values.iter().enumerate() {
                let expected = reference_scale_down(value, dropped_product, scale_wide);
                for (limb, &prime) in kept.iter().enumerate() {
                    assert_eq!(
                        kept_residues[limb * degree + coefficient],
                        modular::reduce_i128_to_u64_mod(expected, prime),
                        "value {value} dropped {dropped:?} scale {scale}"
                    );
                }
                // The scale residue is preserved and the rounding error is at most t / 2.
                assert_eq!(
                    expected.rem_euclid(scale_wide),
                    value.rem_euclid(scale_wide)
                );
                assert!(
                    (expected * dropped_product - value).abs() * 2 <= scale_wide * dropped_product
                );
            }
        }
    }

    #[test]
    fn scale_down_rejects_invalid_plans_and_shapes() {
        assert_eq!(
            CongruentScaleDown::new(&[97], &[], 5),
            Err(RnsChainError::EmptyBasis)
        );
        assert_eq!(
            CongruentScaleDown::new(&[97, 11], &[11], 5),
            Err(RnsChainError::DuplicatePrime { index: 1 })
        );
        assert_eq!(
            CongruentScaleDown::new(&[97, 97], &[11], 5),
            Err(RnsChainError::DuplicatePrime { index: 1 })
        );
        assert_eq!(
            CongruentScaleDown::new(&[97, 99], &[11], 5),
            Err(RnsChainError::CompositePrime { index: 1 })
        );
        assert_eq!(
            CongruentScaleDown::new(&[97; MAX_BASIS_PRIMES + 1], &[11], 5),
            Err(RnsChainError::TooManyPrimes {
                max: MAX_BASIS_PRIMES
            })
        );
        assert_eq!(
            CongruentScaleDown::new(&[97], &[11, 31], 31),
            Err(RnsChainError::ScaleNotInvertible { index: 1 })
        );
        assert_eq!(
            CongruentScaleDown::new(&[97], &[11], 0),
            Err(RnsChainError::ScaleNotInvertible { index: 0 })
        );
        let plan = CongruentScaleDown::new(&[97, 193], &[11], 5).expect("plan");
        let mut kept = vec![1_u64; 4];
        assert_eq!(
            plan.apply(&mut kept, &[0; 3], 2),
            Err(RnsChainError::LengthMismatch {
                expected: 2,
                found: 3
            })
        );
        assert_eq!(
            plan.apply(&mut kept[..3], &[0; 2], 2),
            Err(RnsChainError::LengthMismatch {
                expected: 4,
                found: 3
            })
        );
        assert_eq!(
            plan.apply(&mut kept, &[0; 2], usize::MAX),
            Err(RnsChainError::SizeOverflow)
        );
        assert_eq!(kept, vec![1_u64; 4]);
        // An empty kept basis is valid: nothing remains after the division.
        let empty = CongruentScaleDown::new(&[], &[11], 5).expect("plan");
        assert_eq!(empty.apply(&mut [], &[3, 4], 2), Ok(()));
    }

    #[test]
    fn montgomery_helpers_reduce_any_word() {
        let fixed = FixedModulus::derive(769).expect("fixed");
        for value in [0_u64, 1, 768, 769, u64::MAX] {
            assert_eq!(
                mul_const(fixed, value, to_montgomery(fixed, 5)),
                modular::mul_mod_u64(value, 5, 769)
            );
        }
        assert_eq!(check_len(3, 3), Ok(()));
        assert_eq!(limb_major_len(3, 4), Ok(12));
        assert_eq!(
            limb_major_len(usize::MAX, 2),
            Err(RnsChainError::SizeOverflow)
        );
        assert_eq!(basis_prime(769, 4).map(|fixed| fixed.modulus), Ok(769));
        assert_eq!(
            basis_prime(771, 4),
            Err(RnsChainError::CompositePrime { index: 4 })
        );
    }
}
