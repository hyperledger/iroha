//! Canonical negacyclic rings used by the fixed Bootle/Lantern profile.
//!
//! Both rings are represented in coefficient form in
//! `R_m = Z_m[X] / (X^64 + 1)`. Constructors reject rather than reduce
//! externally supplied residues. Arithmetic methods always return canonical
//! residues and use explicit modular operations, so debug and release builds
//! have identical overflow behavior.
use super::params::{
    APPLICATION_MODULUS_V1, APPLICATION_RING_DEGREE_V1,
    INTERNAL_CRT_FIRST_TWO_PRODUCT_MOD_PROOF_MODULUS_V1, INTERNAL_CRT_GARNER_INVERSES_V1,
    INTERNAL_CRT_NEGACYCLIC_ROOT_INVERSES_V1, INTERNAL_CRT_NEGACYCLIC_ROOTS_V1,
    INTERNAL_CRT_PRIMES_V1, INTERNAL_CRT_PRODUCT_MOD_PROOF_MODULUS_V1,
    INTERNAL_CRT_RING_DEGREE_INVERSES_V1, PROOF_MODULUS_V1,
};
// The fixed-modulus Montgomery arithmetic, its branch-free selects, the schoolbook product and
// the transform skeleton are owned by `iroha_fhe`; this module pins the profile constants and
// binds them to it.
use iroha_fhe::constant_time::{CenteredCrt3, FixedModulus, greater_than_bit_u64, select_i64};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};
/// Montgomery constants of the application modulus `12_289`.
const APPLICATION_FIXED_MODULUS_V1: FixedModulus = FixedModulus {
    modulus: APPLICATION_MODULUS_V1 as u64,
    montgomery_negative_inverse: 3_435_966_895_981_867_007,
    montgomery_r_squared: 6_606,
};
const PROOF_FIXED_MODULUS_V1: FixedModulus = FixedModulus {
    modulus: PROOF_MODULUS_V1,
    montgomery_negative_inverse: 4_655_614_974_089_172_227,
    montgomery_r_squared: 95_672_812_437_504,
};
const INTERNAL_CRT_FIXED_MODULI_V1: [FixedModulus; 3] = [
    FixedModulus {
        modulus: INTERNAL_CRT_PRIMES_V1[0],
        montgomery_negative_inverse: 8_444_618_314_856_986_879,
        montgomery_r_squared: 861_055_311_937_536,
    },
    FixedModulus {
        modulus: INTERNAL_CRT_PRIMES_V1[1],
        montgomery_negative_inverse: 2_456_608_423_348_909_439,
        montgomery_r_squared: 812_195_763_980_927,
    },
    FixedModulus {
        modulus: INTERNAL_CRT_PRIMES_V1[2],
        montgomery_negative_inverse: 5_276_763_958_930_549_887,
        montgomery_r_squared: 1_057_249_418_043_771,
    },
];
/// Centered three-prime reconstruction into the proof modulus for the pinned profile.
const INTERNAL_CENTERED_CRT_V1: CenteredCrt3 = CenteredCrt3 {
    primes: INTERNAL_CRT_FIXED_MODULI_V1,
    garner_inverses: INTERNAL_CRT_GARNER_INVERSES_V1,
    target: PROOF_FIXED_MODULUS_V1,
    first_two_product_mod_target: INTERNAL_CRT_FIRST_TWO_PRODUCT_MOD_PROOF_MODULUS_V1,
    product_mod_target: INTERNAL_CRT_PRODUCT_MOD_PROOF_MODULUS_V1,
};
/// Power of the involution `X -> X^-1` in `Z[X] / (X^64 + 1)`.
const INVERSE_AUTOMORPHISM_POWER_V1: usize = 2 * APPLICATION_RING_DEGREE_V1 - 1;
/// One canonical polynomial in `Z_12289[X] / (X^64 + 1)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApplicationPolynomialV1 {
    coefficients: [u16; APPLICATION_RING_DEGREE_V1],
}
impl ApplicationPolynomialV1 {
    /// Additive identity.
    pub const ZERO: Self = Self {
        coefficients: [0; APPLICATION_RING_DEGREE_V1],
    };
    /// Construct from canonical application-ring residues.
    ///
    /// # Errors
    ///
    /// Returns an error at the first coefficient at least `12_289`.
    pub fn new(coefficients: [u16; APPLICATION_RING_DEGREE_V1]) -> Result<Self, RingErrorV1> {
        if let Some((index, coefficient)) = coefficients
            .iter()
            .copied()
            .enumerate()
            .find(|(_, coefficient)| *coefficient >= APPLICATION_MODULUS_V1)
        {
            return Err(RingErrorV1::NonCanonicalApplicationCoefficient {
                index: u8::try_from(index).expect("ring index fits u8"),
                coefficient: u64::from(coefficient),
            });
        }
        Ok(Self { coefficients })
    }
    /// Construct a constant polynomial from a canonical residue.
    ///
    /// # Errors
    ///
    /// Returns an error when `constant >= 12_289`.
    pub fn constant(constant: u16) -> Result<Self, RingErrorV1> {
        if constant >= APPLICATION_MODULUS_V1 {
            return Err(RingErrorV1::NonCanonicalApplicationCoefficient {
                index: 0,
                coefficient: u64::from(constant),
            });
        }
        let mut coefficients = [0; APPLICATION_RING_DEGREE_V1];
        coefficients[0] = constant;
        Ok(Self { coefficients })
    }
    /// Construct from the unique centered integer lift of each coefficient.
    #[must_use]
    pub fn from_centered_coefficients(coefficients: [i64; APPLICATION_RING_DEGREE_V1]) -> Self {
        let mut output = [0_u16; APPLICATION_RING_DEGREE_V1];
        for (output, coefficient) in output.iter_mut().zip(coefficients) {
            *output =
                application_residue(APPLICATION_FIXED_MODULUS_V1.canonicalize_i64(coefficient));
        }
        Self {
            coefficients: output,
        }
    }
    /// Encode one direct 64-bit attribute as little-endian binary coefficients.
    #[must_use]
    pub fn from_direct_attribute(attribute: [u8; 8]) -> Self {
        let mut coefficients = [0_u16; APPLICATION_RING_DEGREE_V1];
        for (index, coefficient) in coefficients.iter_mut().enumerate() {
            *coefficient = u16::from((attribute[index / 8] >> (index % 8)) & 1);
        }
        Self { coefficients }
    }
    /// Decode a binary polynomial back to its direct 64-bit attribute.
    ///
    /// # Errors
    ///
    /// Rejects the first coefficient other than zero or one.
    pub fn to_direct_attribute(self) -> Result<[u8; 8], RingErrorV1> {
        let mut attribute = [0_u8; 8];
        for (index, coefficient) in self.coefficients.iter().copied().enumerate() {
            if coefficient > 1 {
                return Err(RingErrorV1::NonBinaryCoefficient {
                    index: u8::try_from(index).expect("ring index fits u8"),
                    coefficient: u64::from(coefficient),
                });
            }
            attribute[index / 8] |=
                u8::try_from(coefficient).expect("binary coefficient fits u8") << (index % 8);
        }
        Ok(attribute)
    }
    /// Borrow canonical residues.
    #[must_use]
    pub const fn coefficients(&self) -> &[u16; APPLICATION_RING_DEGREE_V1] {
        &self.coefficients
    }
    /// Return whether this polynomial is the additive identity.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.coefficients
            .iter()
            .all(|coefficient| *coefficient == 0)
    }
    /// Add in the application ring.
    #[must_use]
    pub fn add(self, rhs: Self) -> Self {
        let mut output = [0_u16; APPLICATION_RING_DEGREE_V1];
        for ((output, lhs), rhs) in output
            .iter_mut()
            .zip(self.coefficients)
            .zip(rhs.coefficients)
        {
            *output = application_residue(
                APPLICATION_FIXED_MODULUS_V1.add_canonical(u64::from(lhs), u64::from(rhs)),
            );
        }
        Self {
            coefficients: output,
        }
    }
    /// Subtract in the application ring.
    #[must_use]
    pub fn sub(self, rhs: Self) -> Self {
        let mut output = [0_u16; APPLICATION_RING_DEGREE_V1];
        for ((output, lhs), rhs) in output
            .iter_mut()
            .zip(self.coefficients)
            .zip(rhs.coefficients)
        {
            *output = application_residue(
                APPLICATION_FIXED_MODULUS_V1.sub_canonical(u64::from(lhs), u64::from(rhs)),
            );
        }
        Self {
            coefficients: output,
        }
    }
    /// Negate in the application ring.
    #[must_use]
    pub fn negate(self) -> Self {
        Self::ZERO.sub(self)
    }
    /// Widen the residues to the word form of the shared kernels, in a clearing buffer.
    fn widened(&self) -> Zeroizing<[u64; APPLICATION_RING_DEGREE_V1]> {
        let mut wide = Zeroizing::new([0_u64; APPLICATION_RING_DEGREE_V1]);
        for (wide, coefficient) in wide.iter_mut().zip(self.coefficients) {
            *wide = u64::from(coefficient);
        }
        wide
    }
    /// Narrow canonical residues produced by the shared kernels.
    fn from_canonical_words(words: &[u64; APPLICATION_RING_DEGREE_V1]) -> Self {
        let mut coefficients = [0_u16; APPLICATION_RING_DEGREE_V1];
        for (coefficient, word) in coefficients.iter_mut().zip(words) {
            *coefficient = application_residue(*word);
        }
        Self { coefficients }
    }
    /// Multiply modulo `X^64 + 1`.
    #[must_use]
    pub fn multiply(self, rhs: Self) -> Self {
        let lhs = self.widened();
        let rhs = rhs.widened();
        let mut product = Zeroizing::new([0_u64; APPLICATION_RING_DEGREE_V1]);
        iroha_fhe::polynomial::negacyclic_mul_schoolbook_into_with(
            &*lhs,
            &*rhs,
            &APPLICATION_FIXED_MODULUS_V1,
            &mut *product,
        )
        .expect("both operands have the ring degree");
        Self::from_canonical_words(&product)
    }
    /// Multiply by a signed integer in the application ring.
    #[must_use]
    pub fn scale_centered(self, scalar: i64) -> Self {
        let scalar = APPLICATION_FIXED_MODULUS_V1.canonicalize_i64(scalar);
        let mut output = [0_u16; APPLICATION_RING_DEGREE_V1];
        for (output, coefficient) in output.iter_mut().zip(self.coefficients) {
            *output = application_residue(
                APPLICATION_FIXED_MODULUS_V1.multiply(u64::from(coefficient), scalar),
            );
        }
        Self {
            coefficients: output,
        }
    }
    /// Apply the involution `X -> X^-1` in the negacyclic ring.
    #[must_use]
    pub fn automorphism(self) -> Self {
        let input = self.widened();
        let mut image = Zeroizing::new([0_u64; APPLICATION_RING_DEGREE_V1]);
        iroha_fhe::automorphism::apply_into_with(
            &*input,
            INVERSE_AUTOMORPHISM_POWER_V1,
            &APPLICATION_FIXED_MODULUS_V1,
            &mut *image,
        )
        .expect("fixed ring degree and involution power are in range");
        Self::from_canonical_words(&image)
    }
    /// Return a centered coefficient in `[-6144, 6144]`.
    #[must_use]
    pub fn centered_coefficient(&self, index: usize) -> i16 {
        let residue = self.coefficients[index];
        let non_negative = i64::from(residue);
        let negative = non_negative - i64::from(APPLICATION_MODULUS_V1);
        let centered = select_i64(
            non_negative,
            negative,
            greater_than_bit_u64(u64::from(residue), u64::from(APPLICATION_MODULUS_V1 / 2)),
        );
        i16::try_from(centered).expect("centered application residue fits i16")
    }
    /// Exact squared Euclidean norm of the centered lift.
    #[must_use]
    pub fn centered_squared_norm(&self) -> u64 {
        self.coefficients
            .iter()
            .enumerate()
            .map(|(index, _)| {
                let coefficient = i64::from(self.centered_coefficient(index));
                u64::try_from(coefficient * coefficient).expect("square is non-negative")
            })
            .sum()
    }
}
impl Zeroize for ApplicationPolynomialV1 {
    fn zeroize(&mut self) {
        self.coefficients.zeroize();
    }
}
/// One canonical polynomial in `Z_q[X] / (X^64 + 1)` for the internal
/// Lantern proof modulus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofPolynomialV1 {
    coefficients: [u64; APPLICATION_RING_DEGREE_V1],
}
impl ProofPolynomialV1 {
    /// Additive identity.
    pub const ZERO: Self = Self {
        coefficients: [0; APPLICATION_RING_DEGREE_V1],
    };
    /// Construct from canonical internal proof-ring residues.
    ///
    /// # Errors
    ///
    /// Returns an error at the first coefficient at least `q`.
    pub fn new(coefficients: [u64; APPLICATION_RING_DEGREE_V1]) -> Result<Self, RingErrorV1> {
        if let Some((index, coefficient)) = coefficients
            .iter()
            .copied()
            .enumerate()
            .find(|(_, coefficient)| *coefficient >= PROOF_MODULUS_V1)
        {
            return Err(RingErrorV1::NonCanonicalProofCoefficient {
                index: u8::try_from(index).expect("ring index fits u8"),
                coefficient,
            });
        }
        Ok(Self { coefficients })
    }
    /// Construct a constant polynomial from a canonical residue.
    ///
    /// # Errors
    ///
    /// Returns an error when `constant >= q`.
    pub fn constant(constant: u64) -> Result<Self, RingErrorV1> {
        if constant >= PROOF_MODULUS_V1 {
            return Err(RingErrorV1::NonCanonicalProofCoefficient {
                index: 0,
                coefficient: constant,
            });
        }
        let mut coefficients = [0; APPLICATION_RING_DEGREE_V1];
        coefficients[0] = constant;
        Ok(Self { coefficients })
    }
    #[cfg(test)]
    /// Construct a constant polynomial from any centered integer.
    #[must_use]
    pub fn constant_centered(constant: i64) -> Self {
        let mut coefficients = [0_u64; APPLICATION_RING_DEGREE_V1];
        coefficients[0] = PROOF_FIXED_MODULUS_V1.canonicalize_i64(constant);
        Self { coefficients }
    }
    /// Construct from arbitrary centered integer coefficients.
    #[must_use]
    pub fn from_centered_coefficients(coefficients: [i64; APPLICATION_RING_DEGREE_V1]) -> Self {
        let mut output = [0_u64; APPLICATION_RING_DEGREE_V1];
        for (output, coefficient) in output.iter_mut().zip(coefficients) {
            *output = PROOF_FIXED_MODULUS_V1.canonicalize_i64(coefficient);
        }
        Self {
            coefficients: output,
        }
    }
    /// Embed one application-ring polynomial through its centered lift.
    #[must_use]
    pub fn from_application_centered(polynomial: ApplicationPolynomialV1) -> Self {
        let mut coefficients = [0_i64; APPLICATION_RING_DEGREE_V1];
        for (index, coefficient) in coefficients.iter_mut().enumerate() {
            *coefficient = i64::from(polynomial.centered_coefficient(index));
        }
        Self::from_centered_coefficients(coefficients)
    }
    /// Borrow canonical residues.
    #[must_use]
    pub const fn coefficients(&self) -> &[u64; APPLICATION_RING_DEGREE_V1] {
        &self.coefficients
    }
    /// Return whether this polynomial is the additive identity.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.coefficients
            .iter()
            .all(|coefficient| *coefficient == 0)
    }
    /// Add in the internal proof ring.
    #[must_use]
    pub fn add(self, rhs: Self) -> Self {
        let mut output = [0_u64; APPLICATION_RING_DEGREE_V1];
        for ((output, lhs), rhs) in output
            .iter_mut()
            .zip(self.coefficients)
            .zip(rhs.coefficients)
        {
            *output = PROOF_FIXED_MODULUS_V1.add_canonical(lhs, rhs);
        }
        Self {
            coefficients: output,
        }
    }
    /// Subtract in the internal proof ring.
    #[must_use]
    pub fn sub(self, rhs: Self) -> Self {
        let mut output = [0_u64; APPLICATION_RING_DEGREE_V1];
        for ((output, lhs), rhs) in output
            .iter_mut()
            .zip(self.coefficients)
            .zip(rhs.coefficients)
        {
            *output = PROOF_FIXED_MODULUS_V1.sub_canonical(lhs, rhs);
        }
        Self {
            coefficients: output,
        }
    }
    /// Negate in the internal proof ring.
    #[must_use]
    pub fn negate(self) -> Self {
        Self::ZERO.sub(self)
    }
    /// Multiply modulo `X^64 + 1`.
    #[must_use]
    pub fn multiply(self, rhs: Self) -> Self {
        let lhs = Zeroizing::new(self);
        let rhs = Zeroizing::new(rhs);
        Self {
            coefficients: multiply_negacyclic_crt_ntt_v1(&lhs.coefficients, &rhs.coefficients),
        }
    }
    /// Quadratic-time reference multiplication retained only as a test oracle.
    #[cfg(test)]
    fn multiply_schoolbook(self, rhs: Self) -> Self {
        let mut output = [0_u64; APPLICATION_RING_DEGREE_V1];
        for (lhs_index, lhs) in self.coefficients.iter().copied().enumerate() {
            for (rhs_index, rhs) in rhs.coefficients.iter().copied().enumerate() {
                let product = PROOF_FIXED_MODULUS_V1.multiply(lhs, rhs);
                let degree = lhs_index + rhs_index;
                if degree < APPLICATION_RING_DEGREE_V1 {
                    output[degree] = PROOF_FIXED_MODULUS_V1.add_canonical(output[degree], product);
                } else {
                    output[degree - APPLICATION_RING_DEGREE_V1] = PROOF_FIXED_MODULUS_V1
                        .sub_canonical(output[degree - APPLICATION_RING_DEGREE_V1], product);
                }
            }
        }
        Self {
            coefficients: output,
        }
    }
    /// Multiply by a signed integer in the proof ring.
    #[must_use]
    pub fn scale_centered(self, scalar: i64) -> Self {
        let scalar = PROOF_FIXED_MODULUS_V1.canonicalize_i64(scalar);
        self.scale_canonical_unchecked(scalar)
    }
    /// Multiply by one canonical proof-field scalar.
    ///
    /// # Errors
    ///
    /// Rejects a scalar outside `[0,q)`.
    pub fn scale_canonical(self, scalar: u64) -> Result<Self, RingErrorV1> {
        if scalar >= PROOF_MODULUS_V1 {
            return Err(RingErrorV1::NonCanonicalProofScalar { scalar });
        }
        Ok(self.scale_canonical_unchecked(scalar))
    }
    fn scale_canonical_unchecked(self, scalar: u64) -> Self {
        let mut output = [0_u64; APPLICATION_RING_DEGREE_V1];
        for (output, coefficient) in output.iter_mut().zip(self.coefficients) {
            *output = PROOF_FIXED_MODULUS_V1.multiply(coefficient, scalar);
        }
        Self {
            coefficients: output,
        }
    }
    /// Apply the involution `X -> X^-1` in the negacyclic ring.
    #[must_use]
    pub fn automorphism(self) -> Self {
        let mut output = [0_u64; APPLICATION_RING_DEGREE_V1];
        iroha_fhe::automorphism::apply_into_with(
            &self.coefficients,
            INVERSE_AUTOMORPHISM_POWER_V1,
            &PROOF_FIXED_MODULUS_V1,
            &mut output,
        )
        .expect("fixed ring degree and involution power are in range");
        Self {
            coefficients: output,
        }
    }
    /// Multiply by `X^power` modulo `X^64 + 1`.
    #[must_use]
    pub fn multiply_by_monomial(self, power: usize) -> Self {
        let reduced_power = power % (2 * APPLICATION_RING_DEGREE_V1);
        if reduced_power == 0 {
            return self;
        }
        let mut output = [0_u64; APPLICATION_RING_DEGREE_V1];
        for (index, coefficient) in self.coefficients.iter().copied().enumerate() {
            let degree = index + reduced_power;
            let wraps = degree / APPLICATION_RING_DEGREE_V1;
            let destination = degree % APPLICATION_RING_DEGREE_V1;
            output[destination] = if wraps % 2 == 0 {
                coefficient
            } else {
                PROOF_FIXED_MODULUS_V1.sub_canonical(0, coefficient)
            };
        }
        Self {
            coefficients: output,
        }
    }
    /// Return a centered coefficient in `[-floor(q/2), floor(q/2)]`.
    #[must_use]
    pub fn centered_coefficient(&self, index: usize) -> i64 {
        let residue = self.coefficients[index];
        let non_negative = u64::cast_signed(residue);
        let negative = non_negative - u64::cast_signed(PROOF_MODULUS_V1);
        select_i64(
            non_negative,
            negative,
            greater_than_bit_u64(residue, PROOF_MODULUS_V1 / 2),
        )
    }
    /// Exact squared Euclidean norm of the centered lift.
    #[must_use]
    pub fn centered_squared_norm(&self) -> u128 {
        self.coefficients
            .iter()
            .enumerate()
            .map(|(index, _)| {
                let coefficient = i128::from(self.centered_coefficient(index));
                i128::cast_unsigned(coefficient * coefficient)
            })
            .sum()
    }
}
impl Zeroize for ProofPolynomialV1 {
    fn zeroize(&mut self) {
        self.coefficients.zeroize();
    }
}
fn multiply_negacyclic_crt_ntt_v1(
    lhs: &[u64; APPLICATION_RING_DEGREE_V1],
    rhs: &[u64; APPLICATION_RING_DEGREE_V1],
) -> [u64; APPLICATION_RING_DEGREE_V1] {
    let mut crt_coefficients = Zeroizing::new([[0_u64; APPLICATION_RING_DEGREE_V1]; 3]);
    for prime_index in 0..INTERNAL_CRT_PRIMES_V1.len() {
        let fixed_modulus: FixedModulus = INTERNAL_CRT_FIXED_MODULI_V1[prime_index];
        let mut lhs_ntt = Zeroizing::new(*lhs);
        let mut rhs_ntt = Zeroizing::new(*rhs);
        // Every canonical q-residue is less than twice every CRT prime, so
        // one fixed-time conditional subtraction is an exact reduction.
        for coefficient in lhs_ntt.iter_mut().chain(rhs_ntt.iter_mut()) {
            *coefficient = fixed_modulus.reduce_once(*coefficient);
        }
        forward_negacyclic_ntt_v1(
            &mut lhs_ntt,
            fixed_modulus,
            INTERNAL_CRT_NEGACYCLIC_ROOTS_V1[prime_index],
        );
        forward_negacyclic_ntt_v1(
            &mut rhs_ntt,
            fixed_modulus,
            INTERNAL_CRT_NEGACYCLIC_ROOTS_V1[prime_index],
        );
        for (lhs, rhs) in lhs_ntt.iter_mut().zip(rhs_ntt.iter().copied()) {
            *lhs = fixed_modulus.multiply(*lhs, rhs);
        }
        inverse_negacyclic_ntt_v1(
            &mut lhs_ntt,
            fixed_modulus,
            INTERNAL_CRT_NEGACYCLIC_ROOT_INVERSES_V1[prime_index],
            INTERNAL_CRT_RING_DEGREE_INVERSES_V1[prime_index],
        );
        crt_coefficients[prime_index].copy_from_slice(&*lhs_ntt);
    }
    core::array::from_fn(|coefficient_index| {
        centered_crt_reconstruct_mod_q_v1([
            crt_coefficients[0][coefficient_index],
            crt_coefficients[1][coefficient_index],
            crt_coefficients[2][coefficient_index],
        ])
    })
}
/// Bind the fixed ring degree to the shared forward transform.
fn forward_negacyclic_ntt_v1(
    values: &mut [u64; APPLICATION_RING_DEGREE_V1],
    fixed_modulus: FixedModulus,
    negacyclic_root: u64,
) {
    iroha_fhe::ntt::forward_negacyclic_ntt_with(values, &fixed_modulus, negacyclic_root)
        .expect("the ring degree is a power of two");
}
/// Bind the fixed ring degree to the shared inverse transform.
fn inverse_negacyclic_ntt_v1(
    values: &mut [u64; APPLICATION_RING_DEGREE_V1],
    fixed_modulus: FixedModulus,
    inverse_negacyclic_root: u64,
    inverse_degree: u64,
) {
    iroha_fhe::ntt::inverse_negacyclic_ntt_with(
        values,
        &fixed_modulus,
        inverse_negacyclic_root,
        inverse_degree,
    )
    .expect("the ring degree is a power of two");
}
/// Bind the pinned three-prime profile to the shared centered reconstruction.
fn centered_crt_reconstruct_mod_q_v1(residues: [u64; 3]) -> u64 {
    INTERNAL_CENTERED_CRT_V1.reconstruct_mod_target(residues)
}
/// Narrow one canonical application residue produced by the shared arithmetic.
fn application_residue(word: u64) -> u16 {
    u16::try_from(word).expect("reduced application residue fits u16")
}
#[cfg(test)]
fn multiply_mod_reference_u64(lhs: u64, rhs: u64, modulus: u64) -> u64 {
    u64::try_from(u128::from(lhs) * u128::from(rhs) % u128::from(modulus))
        .expect("reduced product fits u64")
}
#[cfg(test)]
fn add_mod_reference_u64(lhs: u64, rhs: u64, modulus: u64) -> u64 {
    u64::try_from((u128::from(lhs) + u128::from(rhs)) % u128::from(modulus))
        .expect("reduced sum fits u64")
}
#[cfg(test)]
fn sub_mod_reference_u64(lhs: u64, rhs: u64, modulus: u64) -> u64 {
    if lhs >= rhs {
        lhs - rhs
    } else {
        modulus - (rhs - lhs)
    }
}
#[cfg(test)]
fn modular_power_reference_u64(mut base: u64, mut exponent: u64, modulus: u64) -> u64 {
    let mut output = 1_u64;
    while exponent != 0 {
        if exponent & 1 == 1 {
            output = multiply_mod_reference_u64(output, base, modulus);
        }
        base = multiply_mod_reference_u64(base, base, modulus);
        exponent >>= 1;
    }
    output
}
#[cfg(test)]
fn canonicalize_i128_reference(value: i128, modulus: u64) -> u64 {
    let modulus = i128::from(modulus);
    let mut residue = value % modulus;
    if residue < 0 {
        residue += modulus;
    }
    u64::try_from(residue).expect("canonical residue fits u64")
}
/// Canonical ring failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum RingErrorV1 {
    /// An application-ring residue is not in `[0, 12_289)`.
    #[error("application polynomial coefficient {index} has non-canonical residue {coefficient}")]
    NonCanonicalApplicationCoefficient {
        /// Coefficient index.
        index: u8,
        /// Rejected residue.
        coefficient: u64,
    },
    /// An internal proof-ring residue is not in `[0, q)`.
    #[error("proof polynomial coefficient {index} has non-canonical residue {coefficient}")]
    NonCanonicalProofCoefficient {
        /// Coefficient index.
        index: u8,
        /// Rejected residue.
        coefficient: u64,
    },
    /// A proof-field scalar was not in `[0,q)`.
    #[error("proof scalar has non-canonical residue {scalar}")]
    NonCanonicalProofScalar {
        /// Rejected scalar.
        scalar: u64,
    },
    /// A direct attribute polynomial was not binary.
    #[error("direct attribute coefficient {index} is {coefficient}, not zero or one")]
    NonBinaryCoefficient {
        /// Coefficient index.
        index: u8,
        /// Rejected residue.
        coefficient: u64,
    },
}
#[cfg(test)]
mod tests {
    use super::*;
    fn application_monomial(index: usize, coefficient: u16) -> ApplicationPolynomialV1 {
        let mut coefficients = [0_u16; APPLICATION_RING_DEGREE_V1];
        coefficients[index] = coefficient;
        ApplicationPolynomialV1::new(coefficients).expect("canonical monomial")
    }
    fn proof_monomial(index: usize, coefficient: u64) -> ProofPolynomialV1 {
        let mut coefficients = [0_u64; APPLICATION_RING_DEGREE_V1];
        coefficients[index] = coefficient;
        ProofPolynomialV1::new(coefficients).expect("canonical monomial")
    }
    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut value = *state;
        value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        value ^ (value >> 31)
    }
    fn random_proof_polynomial(state: &mut u64) -> ProofPolynomialV1 {
        ProofPolynomialV1::new(core::array::from_fn(|_| {
            splitmix64(state) % PROOF_MODULUS_V1
        }))
        .expect("random residues are canonical")
    }
    fn crt_residues_from_centered(value: i128) -> [u64; 3] {
        INTERNAL_CRT_PRIMES_V1.map(|prime| canonicalize_i128_reference(value, prime))
    }
    fn mixed_radix_residues(digits: [u64; 3]) -> [u64; 3] {
        INTERNAL_CRT_PRIMES_V1.map(|modulus| {
            add_mod_reference_u64(
                add_mod_reference_u64(
                    digits[0] % modulus,
                    multiply_mod_reference_u64(
                        INTERNAL_CRT_PRIMES_V1[0] % modulus,
                        digits[1] % modulus,
                        modulus,
                    ),
                    modulus,
                ),
                multiply_mod_reference_u64(
                    multiply_mod_reference_u64(
                        INTERNAL_CRT_PRIMES_V1[0] % modulus,
                        INTERNAL_CRT_PRIMES_V1[1] % modulus,
                        modulus,
                    ),
                    digits[2] % modulus,
                    modulus,
                ),
                modulus,
            )
        })
    }
    fn mixed_radix_mod_q(digits: [u64; 3]) -> u64 {
        add_mod_reference_u64(
            add_mod_reference_u64(
                digits[0],
                multiply_mod_reference_u64(INTERNAL_CRT_PRIMES_V1[0], digits[1], PROOF_MODULUS_V1),
                PROOF_MODULUS_V1,
            ),
            multiply_mod_reference_u64(
                INTERNAL_CRT_FIRST_TWO_PRODUCT_MOD_PROOF_MODULUS_V1,
                digits[2],
                PROOF_MODULUS_V1,
            ),
            PROOF_MODULUS_V1,
        )
    }
    fn is_prime_u64(candidate: u64) -> bool {
        const BASES: [u64; 7] = [2, 325, 9_375, 28_178, 450_775, 9_780_504, 1_795_265_022];
        if candidate < 2 {
            return false;
        }
        for divisor in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
            if candidate == divisor {
                return true;
            }
            if candidate.is_multiple_of(divisor) {
                return false;
            }
        }
        let shift = (candidate - 1).trailing_zeros();
        let odd_part = (candidate - 1) >> shift;
        'base: for base in BASES {
            let base = base % candidate;
            if base == 0 {
                continue;
            }
            let mut witness = modular_power_reference_u64(base, odd_part, candidate);
            if witness == 1 || witness == candidate - 1 {
                continue;
            }
            for _ in 1..shift {
                witness = multiply_mod_reference_u64(witness, witness, candidate);
                if witness == candidate - 1 {
                    continue 'base;
                }
            }
            return false;
        }
        true
    }
    #[test]
    fn fixed_modulus_arithmetic_matches_independent_reference_at_boundaries_and_randomly() {
        let fixed_moduli = [
            APPLICATION_FIXED_MODULUS_V1,
            PROOF_FIXED_MODULUS_V1,
            INTERNAL_CRT_FIXED_MODULI_V1[0],
            INTERNAL_CRT_FIXED_MODULI_V1[1],
            INTERNAL_CRT_FIXED_MODULI_V1[2],
        ];
        let mut random_state = 0x4D4F_4E54_474F_4D45;
        for fixed_modulus in fixed_moduli {
            let modulus = fixed_modulus.modulus;
            assert_eq!(
                modulus.wrapping_mul(fixed_modulus.montgomery_negative_inverse),
                u64::MAX
            );
            let montgomery_radix_modulus = (1_u128 << 64) % u128::from(modulus);
            assert_eq!(
                fixed_modulus.montgomery_r_squared,
                u64::try_from(
                    montgomery_radix_modulus * montgomery_radix_modulus % u128::from(modulus)
                )
                .expect("reference residue fits u64")
            );
            for value in [0, 1, modulus - 1, modulus, modulus + 1, 2 * modulus - 1] {
                assert_eq!(
                    fixed_modulus.reduce_once(value),
                    value % modulus,
                    "single reduction failed for modulus {modulus} and value {value}"
                );
            }
            for value in [
                0,
                1,
                modulus - 1,
                modulus,
                modulus + 1,
                u64::MAX / 2,
                u64::MAX - 1,
                u64::MAX,
            ] {
                assert_eq!(
                    fixed_modulus.reduce_u64(value),
                    value % modulus,
                    "full reduction failed for modulus {modulus} and value {value}"
                );
            }
            let boundaries = [0, 1, modulus / 2, modulus / 2 + 1, modulus - 2, modulus - 1];
            for lhs in boundaries {
                for rhs in boundaries {
                    assert_eq!(
                        fixed_modulus.add_canonical(lhs, rhs),
                        add_mod_reference_u64(lhs, rhs, modulus)
                    );
                    assert_eq!(
                        fixed_modulus.sub_canonical(lhs, rhs),
                        sub_mod_reference_u64(lhs, rhs, modulus)
                    );
                    assert_eq!(
                        fixed_modulus.multiply(lhs, rhs),
                        multiply_mod_reference_u64(lhs, rhs, modulus)
                    );
                }
            }
            for _ in 0..512 {
                let lhs = splitmix64(&mut random_state) % modulus;
                let rhs = splitmix64(&mut random_state) % modulus;
                assert_eq!(
                    fixed_modulus.add_canonical(lhs, rhs),
                    add_mod_reference_u64(lhs, rhs, modulus)
                );
                assert_eq!(
                    fixed_modulus.sub_canonical(lhs, rhs),
                    sub_mod_reference_u64(lhs, rhs, modulus)
                );
                assert_eq!(
                    fixed_modulus.multiply(lhs, rhs),
                    multiply_mod_reference_u64(lhs, rhs, modulus)
                );
            }
        }
    }
    #[test]
    fn pinned_fixed_moduli_carry_the_montgomery_constants_of_their_modulus() {
        assert_eq!(
            APPLICATION_FIXED_MODULUS_V1.modulus,
            u64::from(APPLICATION_MODULUS_V1)
        );
        for fixed_modulus in [
            APPLICATION_FIXED_MODULUS_V1,
            PROOF_FIXED_MODULUS_V1,
            INTERNAL_CRT_FIXED_MODULI_V1[0],
            INTERNAL_CRT_FIXED_MODULI_V1[1],
            INTERNAL_CRT_FIXED_MODULI_V1[2],
        ] {
            assert!(
                fixed_modulus.is_consistent(),
                "pinned constants of {}",
                fixed_modulus.modulus
            );
        }
    }
    /// Independent `u32` reference for the application ring. It shares no code with `iroha_fhe`.
    fn application_multiply_reference(
        lhs: &ApplicationPolynomialV1,
        rhs: &ApplicationPolynomialV1,
    ) -> [u16; APPLICATION_RING_DEGREE_V1] {
        let modulus = u32::from(APPLICATION_MODULUS_V1);
        let mut output = [0_u32; APPLICATION_RING_DEGREE_V1];
        for (lhs_index, lhs) in lhs.coefficients().iter().copied().enumerate() {
            for (rhs_index, rhs) in rhs.coefficients().iter().copied().enumerate() {
                let product = u32::from(lhs) * u32::from(rhs) % modulus;
                let degree = lhs_index + rhs_index;
                if degree < APPLICATION_RING_DEGREE_V1 {
                    output[degree] = (output[degree] + product) % modulus;
                } else {
                    let index = degree - APPLICATION_RING_DEGREE_V1;
                    output[index] = (output[index] + modulus - product) % modulus;
                }
            }
        }
        output.map(|coefficient| u16::try_from(coefficient).expect("reduced residue fits u16"))
    }
    fn random_application_polynomial(state: &mut u64) -> ApplicationPolynomialV1 {
        ApplicationPolynomialV1::new(core::array::from_fn(|_| {
            u16::try_from(splitmix64(state) % u64::from(APPLICATION_MODULUS_V1))
                .expect("reduced residue fits u16")
        }))
        .expect("random residues are canonical")
    }
    #[test]
    fn application_ring_matches_the_independent_reference_on_boundary_and_random_polynomials() {
        let modulus = APPLICATION_MODULUS_V1;
        let wide_modulus = i64::from(modulus);
        let mut random_state = 0x4150_502D_5249_4E47;
        let mut polynomials = vec![
            ApplicationPolynomialV1::ZERO,
            ApplicationPolynomialV1::constant(1).expect("one"),
            ApplicationPolynomialV1::new([modulus - 1; APPLICATION_RING_DEGREE_V1])
                .expect("minus-one residues are canonical"),
            ApplicationPolynomialV1::new(core::array::from_fn(|index| {
                [0, 1, modulus - 1, modulus / 2, modulus / 2 + 1][index % 5]
            }))
            .expect("boundary residues are canonical"),
            application_monomial(63, modulus - 1),
        ];
        for _ in 0..12 {
            polynomials.push(random_application_polynomial(&mut random_state));
        }
        for lhs in &polynomials {
            for rhs in &polynomials {
                let product = lhs.multiply(*rhs);
                assert_eq!(
                    product.coefficients(),
                    &application_multiply_reference(lhs, rhs)
                );
                assert_eq!(product, rhs.multiply(*lhs));
                let sum = lhs.add(*rhs);
                let difference = lhs.sub(*rhs);
                for index in 0..APPLICATION_RING_DEGREE_V1 {
                    let (left, right) = (
                        i64::from(lhs.coefficients()[index]),
                        i64::from(rhs.coefficients()[index]),
                    );
                    assert_eq!(
                        i64::from(sum.coefficients()[index]),
                        (left + right).rem_euclid(wide_modulus)
                    );
                    assert_eq!(
                        i64::from(difference.coefficients()[index]),
                        (left - right).rem_euclid(wide_modulus)
                    );
                }
            }
            for scalar in [
                i64::MIN,
                i64::MIN + 1,
                -wide_modulus - 1,
                -wide_modulus,
                -1,
                0,
                1,
                wide_modulus - 1,
                wide_modulus,
                wide_modulus + 1,
                i64::MAX,
            ] {
                let scaled = lhs.scale_centered(scalar);
                let reduced_scalar = i128::from(scalar).rem_euclid(i128::from(modulus));
                for index in 0..APPLICATION_RING_DEGREE_V1 {
                    assert_eq!(
                        i128::from(scaled.coefficients()[index]),
                        i128::from(lhs.coefficients()[index]) * reduced_scalar
                            % i128::from(modulus),
                        "scalar {scalar} index {index}"
                    );
                }
            }
            // X -> X^-1: the constant term stays and coefficient i is minus coefficient 64 - i.
            let image = lhs.automorphism();
            assert_eq!(image.coefficients()[0], lhs.coefficients()[0]);
            for index in 1..APPLICATION_RING_DEGREE_V1 {
                let source = lhs.coefficients()[APPLICATION_RING_DEGREE_V1 - index];
                assert_eq!(image.coefficients()[index], (modulus - source) % modulus);
            }
        }
    }
    #[test]
    fn fixed_time_centering_matches_reference_for_all_signed_boundaries() {
        for value in [
            i64::MIN,
            i64::MIN + 1,
            -u64::cast_signed(PROOF_MODULUS_V1) - 1,
            -u64::cast_signed(PROOF_MODULUS_V1),
            -u64::cast_signed(PROOF_MODULUS_V1) + 1,
            -1,
            0,
            1,
            u64::cast_signed(PROOF_MODULUS_V1) - 1,
            u64::cast_signed(PROOF_MODULUS_V1),
            u64::cast_signed(PROOF_MODULUS_V1) + 1,
            i64::MAX - 1,
            i64::MAX,
        ] {
            assert_eq!(
                PROOF_FIXED_MODULUS_V1.canonicalize_i64(value),
                canonicalize_i128_reference(i128::from(value), PROOF_MODULUS_V1),
                "centering failed for {value}"
            );
        }
    }
    #[test]
    fn crt_ntt_profile_constants_are_exact_and_support_unique_reconstruction() {
        for prime_index in 0..INTERNAL_CRT_PRIMES_V1.len() {
            let prime = INTERNAL_CRT_PRIMES_V1[prime_index];
            let fixed_modulus = INTERNAL_CRT_FIXED_MODULI_V1[prime_index];
            let root = INTERNAL_CRT_NEGACYCLIC_ROOTS_V1[prime_index];
            assert!(is_prime_u64(prime));
            assert_eq!(fixed_modulus.power(root, 64), prime - 1);
            assert_eq!(fixed_modulus.power(root, 128), 1);
            assert_eq!(
                fixed_modulus.multiply(root, INTERNAL_CRT_NEGACYCLIC_ROOT_INVERSES_V1[prime_index]),
                1
            );
            assert_eq!(
                fixed_modulus.multiply(
                    u64::try_from(APPLICATION_RING_DEGREE_V1).expect("degree fits u64"),
                    INTERNAL_CRT_RING_DEGREE_INVERSES_V1[prime_index],
                ),
                1
            );
            assert!(PROOF_MODULUS_V1 < 2 * prime);
        }
        let [prime_zero, prime_one, prime_two] = INTERNAL_CRT_PRIMES_V1;
        assert_eq!(
            multiply_mod_reference_u64(
                prime_zero % prime_one,
                INTERNAL_CRT_GARNER_INVERSES_V1[0],
                prime_one
            ),
            1
        );
        assert_eq!(
            multiply_mod_reference_u64(
                multiply_mod_reference_u64(prime_zero, prime_one, prime_two),
                INTERNAL_CRT_GARNER_INVERSES_V1[1],
                prime_two
            ),
            1
        );
        assert_eq!(
            multiply_mod_reference_u64(prime_zero, prime_one, PROOF_MODULUS_V1),
            INTERNAL_CRT_FIRST_TWO_PRODUCT_MOD_PROOF_MODULUS_V1
        );
        assert_eq!(
            multiply_mod_reference_u64(
                INTERNAL_CRT_FIRST_TWO_PRODUCT_MOD_PROOF_MODULUS_V1,
                prime_two,
                PROOF_MODULUS_V1
            ),
            INTERNAL_CRT_PRODUCT_MOD_PROOF_MODULUS_V1
        );
        // Twice the largest possible absolute schoolbook coefficient is
        // strictly below P=p0*p1*p2. Division keeps this check inside u128.
        let maximum_residue = u128::from(PROOF_MODULUS_V1 - 1);
        let twice_coefficient_bound = 2
            * u128::try_from(APPLICATION_RING_DEGREE_V1).expect("degree fits u128")
            * maximum_residue
            * maximum_residue;
        let first_two_product = u128::from(prime_zero) * u128::from(prime_one);
        assert!(twice_coefficient_bound / first_two_product < u128::from(prime_two));
    }
    #[test]
    fn negacyclic_ntt_round_trips_boundary_and_random_inputs_under_every_prime() {
        let mut random_state = 0x4E54_542D_524F_554E;
        for prime_index in 0..INTERNAL_CRT_PRIMES_V1.len() {
            let prime = INTERNAL_CRT_PRIMES_V1[prime_index];
            let fixed_modulus = INTERNAL_CRT_FIXED_MODULI_V1[prime_index];
            let inputs = [
                [0_u64; APPLICATION_RING_DEGREE_V1],
                core::array::from_fn(|index| if index % 2 == 0 { prime - 1 } else { 1 }),
                core::array::from_fn(|_| splitmix64(&mut random_state) % prime),
            ];
            for input in inputs {
                let mut transformed = input;
                forward_negacyclic_ntt_v1(
                    &mut transformed,
                    fixed_modulus,
                    INTERNAL_CRT_NEGACYCLIC_ROOTS_V1[prime_index],
                );
                assert!(transformed.iter().all(|coefficient| *coefficient < prime));
                inverse_negacyclic_ntt_v1(
                    &mut transformed,
                    fixed_modulus,
                    INTERNAL_CRT_NEGACYCLIC_ROOT_INVERSES_V1[prime_index],
                    INTERNAL_CRT_RING_DEGREE_INVERSES_V1[prime_index],
                );
                assert_eq!(transformed, input);
            }
        }
    }
    #[test]
    fn centered_crt_reconstruction_handles_sign_and_exact_boundaries() {
        let maximum_coefficient = i128::try_from(APPLICATION_RING_DEGREE_V1)
            .expect("degree fits i128")
            * i128::from(PROOF_MODULUS_V1 - 1)
            * i128::from(PROOF_MODULUS_V1 - 1);
        for value in [
            -maximum_coefficient,
            -maximum_coefficient + 1,
            -i128::from(PROOF_MODULUS_V1) - 1,
            -i128::from(PROOF_MODULUS_V1),
            -i128::from(PROOF_MODULUS_V1) + 1,
            -1,
            0,
            1,
            i128::from(PROOF_MODULUS_V1) - 1,
            i128::from(PROOF_MODULUS_V1),
            i128::from(PROOF_MODULUS_V1) + 1,
            maximum_coefficient - 1,
            maximum_coefficient,
        ] {
            assert_eq!(
                centered_crt_reconstruct_mod_q_v1(crt_residues_from_centered(value)),
                canonicalize_i128_reference(value, PROOF_MODULUS_V1),
                "failed to reconstruct centered value {value}"
            );
        }
        let [prime_zero, prime_one, prime_two] = INTERNAL_CRT_PRIMES_V1;
        let half_digits = [
            (prime_zero - 1) / 2,
            (prime_one - 1) / 2,
            (prime_two - 1) / 2,
        ];
        let half_mod_q = mixed_radix_mod_q(half_digits);
        assert_eq!(
            centered_crt_reconstruct_mod_q_v1(mixed_radix_residues(half_digits)),
            half_mod_q
        );
        let just_above_half = [half_digits[0] + 1, half_digits[1], half_digits[2]];
        assert_eq!(
            centered_crt_reconstruct_mod_q_v1(mixed_radix_residues(just_above_half)),
            sub_mod_reference_u64(
                mixed_radix_mod_q(just_above_half),
                INTERNAL_CRT_PRODUCT_MOD_PROOF_MODULUS_V1,
                PROOF_MODULUS_V1
            )
        );
        assert_eq!(
            centered_crt_reconstruct_mod_q_v1(mixed_radix_residues([
                prime_zero - 1,
                prime_one - 1,
                prime_two - 1,
            ])),
            PROOF_MODULUS_V1 - 1
        );
    }
    #[test]
    fn constructors_reject_modulus_and_larger_residues_at_exact_index() {
        for coefficient in [APPLICATION_MODULUS_V1, u16::MAX] {
            let mut coefficients = [0_u16; APPLICATION_RING_DEGREE_V1];
            coefficients[63] = coefficient;
            assert_eq!(
                ApplicationPolynomialV1::new(coefficients),
                Err(RingErrorV1::NonCanonicalApplicationCoefficient {
                    index: 63,
                    coefficient: u64::from(coefficient)
                })
            );
        }
        for coefficient in [PROOF_MODULUS_V1, PROOF_MODULUS_V1 + 1, u64::MAX] {
            let mut coefficients = [0_u64; APPLICATION_RING_DEGREE_V1];
            coefficients[41] = coefficient;
            assert_eq!(
                ProofPolynomialV1::new(coefficients),
                Err(RingErrorV1::NonCanonicalProofCoefficient {
                    index: 41,
                    coefficient
                })
            );
        }
    }
    #[test]
    fn direct_attributes_use_little_endian_bits_and_reject_nonbinary_values() {
        for attribute in [
            [0_u8; 8],
            [u8::MAX; 8],
            [0x81, 0x42, 0x24, 0x18, 0x18, 0x24, 0x42, 0x81],
        ] {
            let polynomial = ApplicationPolynomialV1::from_direct_attribute(attribute);
            assert_eq!(
                polynomial.to_direct_attribute().expect("binary polynomial"),
                attribute
            );
        }
        let polynomial = application_monomial(37, 2);
        assert_eq!(
            polynomial.to_direct_attribute(),
            Err(RingErrorV1::NonBinaryCoefficient {
                index: 37,
                coefficient: 2
            })
        );
    }
    #[test]
    fn application_negacyclic_wrap_is_subtractive_and_canonical() {
        let x = application_monomial(1, 1);
        let x63 = application_monomial(63, 1);
        let product = x.multiply(x63);
        assert_eq!(
            product,
            ApplicationPolynomialV1::constant(APPLICATION_MODULUS_V1 - 1)
                .expect("canonical minus one")
        );
        assert_eq!(product.centered_coefficient(0), -1);
        assert_eq!(product.centered_squared_norm(), 1);
    }
    #[test]
    fn proof_negacyclic_wrap_is_subtractive_and_canonical() {
        let x = proof_monomial(1, 1);
        let x63 = proof_monomial(63, 1);
        let product = x.multiply(x63);
        assert_eq!(
            product,
            ProofPolynomialV1::constant(PROOF_MODULUS_V1 - 1).expect("canonical minus one")
        );
        assert_eq!(product.centered_coefficient(0), -1);
        assert_eq!(product.centered_squared_norm(), 1);
    }
    #[test]
    fn proof_ntt_multiplication_is_exact_for_every_monomial_pair() {
        for lhs_index in 0..APPLICATION_RING_DEGREE_V1 {
            for rhs_index in 0..APPLICATION_RING_DEGREE_V1 {
                let product = proof_monomial(lhs_index, 1).multiply(proof_monomial(rhs_index, 1));
                let degree = lhs_index + rhs_index;
                let mut expected = [0_u64; APPLICATION_RING_DEGREE_V1];
                expected[degree % APPLICATION_RING_DEGREE_V1] =
                    if degree < APPLICATION_RING_DEGREE_V1 {
                        1
                    } else {
                        PROOF_MODULUS_V1 - 1
                    };
                assert_eq!(
                    product.coefficients(),
                    &expected,
                    "incorrect X^{lhs_index} * X^{rhs_index}"
                );
            }
        }
    }
    #[test]
    fn proof_ntt_matches_schoolbook_for_sign_and_residue_boundaries() {
        let positive_half = PROOF_MODULUS_V1 / 2;
        let negative_half = positive_half + 1;
        let boundary_polynomials = [
            ProofPolynomialV1::ZERO,
            ProofPolynomialV1::new([PROOF_MODULUS_V1 - 1; APPLICATION_RING_DEGREE_V1])
                .expect("minus-one residues are canonical"),
            ProofPolynomialV1::new(core::array::from_fn(|index| {
                if index % 2 == 0 {
                    positive_half
                } else {
                    negative_half
                }
            }))
            .expect("centered boundary residues are canonical"),
            ProofPolynomialV1::new(core::array::from_fn(|index| {
                [0, 1, PROOF_MODULUS_V1 - 1, positive_half, negative_half][index % 5]
            }))
            .expect("boundary residues are canonical"),
            proof_monomial(63, PROOF_MODULUS_V1 - 1),
        ];
        for lhs in boundary_polynomials {
            for rhs in boundary_polynomials {
                let product = lhs.multiply(rhs);
                assert_eq!(product, lhs.multiply_schoolbook(rhs));
                assert!(
                    product
                        .coefficients()
                        .iter()
                        .all(|coefficient| *coefficient < PROOF_MODULUS_V1)
                );
            }
        }
        let boundary_coefficients = [1, positive_half, negative_half, PROOF_MODULUS_V1 - 1];
        let boundary_indices = [0, 1, 31, 32, 63];
        for lhs_index in boundary_indices {
            for rhs_index in boundary_indices {
                for lhs_coefficient in boundary_coefficients {
                    for rhs_coefficient in boundary_coefficients {
                        let lhs = proof_monomial(lhs_index, lhs_coefficient);
                        let rhs = proof_monomial(rhs_index, rhs_coefficient);
                        assert_eq!(
                            lhs.multiply(rhs),
                            lhs.multiply_schoolbook(rhs),
                            "boundary monomials failed at ({lhs_index}, {rhs_index}) \
                             with ({lhs_coefficient}, {rhs_coefficient})"
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn proof_ntt_matches_schoolbook_for_deterministic_random_polynomials() {
        let mut random_state = 0x4352_542D_4449_4646;
        for sample in 0..128 {
            let lhs = random_proof_polynomial(&mut random_state);
            let rhs = random_proof_polynomial(&mut random_state);
            let product = lhs.multiply(rhs);
            assert_eq!(
                product,
                lhs.multiply_schoolbook(rhs),
                "random differential sample {sample} failed"
            );
            assert!(
                product
                    .coefficients()
                    .iter()
                    .all(|coefficient| *coefficient < PROOF_MODULUS_V1)
            );
            if sample % 8 == 0 {
                assert_eq!(product, rhs.multiply(lhs));
            }
        }
    }
    #[test]
    fn proof_ntt_distributivity_holds_for_deterministic_random_polynomials() {
        let mut random_state = 0x4352_542D_4449_5354;
        for sample in 0..48 {
            let lhs = random_proof_polynomial(&mut random_state);
            let rhs = random_proof_polynomial(&mut random_state);
            let addend = random_proof_polynomial(&mut random_state);
            assert_eq!(
                lhs.multiply(rhs.add(addend)),
                lhs.multiply(rhs).add(lhs.multiply(addend)),
                "random distributivity sample {sample} failed"
            );
        }
    }
    #[test]
    fn ring_laws_hold_on_adversarial_boundary_polynomials() {
        let mut application_boundary = [0_u16; APPLICATION_RING_DEGREE_V1];
        let mut proof_boundary = [0_u64; APPLICATION_RING_DEGREE_V1];
        for index in 0..APPLICATION_RING_DEGREE_V1 {
            application_boundary[index] = if index % 2 == 0 {
                APPLICATION_MODULUS_V1 - 1
            } else {
                1
            };
            proof_boundary[index] = if index % 2 == 0 {
                PROOF_MODULUS_V1 - 1
            } else {
                1
            };
        }
        let a = ApplicationPolynomialV1::new(application_boundary).expect("canonical");
        let q = ProofPolynomialV1::new(proof_boundary).expect("canonical");
        let application_one = ApplicationPolynomialV1::constant(1).expect("one");
        let proof_one = ProofPolynomialV1::constant(1).expect("one");
        assert_eq!(a.add(a.negate()), ApplicationPolynomialV1::ZERO);
        assert_eq!(a.multiply(application_one), a);
        assert_eq!(a.sub(a), ApplicationPolynomialV1::ZERO);
        assert_eq!(q.add(q.negate()), ProofPolynomialV1::ZERO);
        assert_eq!(q.multiply(proof_one), q);
        assert_eq!(q.sub(q), ProofPolynomialV1::ZERO);
        assert!(
            a.coefficients()
                .iter()
                .all(|coefficient| *coefficient < APPLICATION_MODULUS_V1)
        );
        assert!(
            q.coefficients()
                .iter()
                .all(|coefficient| *coefficient < PROOF_MODULUS_V1)
        );
    }
    #[test]
    fn distributivity_holds_for_wrapping_terms_in_both_rings() {
        let a = application_monomial(63, APPLICATION_MODULUS_V1 - 1);
        let b = application_monomial(1, APPLICATION_MODULUS_V1 - 1);
        let c = application_monomial(32, 7);
        assert_eq!(a.multiply(b.add(c)), a.multiply(b).add(a.multiply(c)));
        let a = proof_monomial(63, PROOF_MODULUS_V1 - 1);
        let b = proof_monomial(1, PROOF_MODULUS_V1 - 1);
        let c = proof_monomial(32, 7);
        assert_eq!(a.multiply(b.add(c)), a.multiply(b).add(a.multiply(c)));
    }
    #[test]
    fn centered_lifts_scaling_automorphism_and_monomials_are_exact() {
        let application =
            ApplicationPolynomialV1::from_centered_coefficients(core::array::from_fn(|index| {
                if index == 0 {
                    -1
                } else if index == 63 {
                    7
                } else {
                    0
                }
            }));
        assert_eq!(application.centered_coefficient(0), -1);
        assert_eq!(application.centered_coefficient(63), 7);
        assert_eq!(application.automorphism().automorphism(), application);
        assert_eq!(
            application.scale_centered(-3),
            application.multiply(
                ApplicationPolynomialV1::constant(APPLICATION_MODULUS_V1 - 3).expect("canonical")
            )
        );
        let proof = ProofPolynomialV1::from_application_centered(application);
        assert_eq!(proof.centered_coefficient(0), -1);
        assert_eq!(proof.centered_coefficient(63), 7);
        assert_eq!(proof.automorphism().automorphism(), proof);
        assert_eq!(
            proof.scale_centered(-3),
            proof.multiply(ProofPolynomialV1::constant(PROOF_MODULUS_V1 - 3).expect("canonical"))
        );
        let x = proof_monomial(1, 1);
        assert_eq!(
            x.multiply_by_monomial(63),
            ProofPolynomialV1::constant(PROOF_MODULUS_V1 - 1).expect("minus one")
        );
        assert_eq!(x.multiply_by_monomial(128), x);
    }
    #[test]
    fn zeroize_erases_every_residue() {
        let mut application =
            ApplicationPolynomialV1::from_centered_coefficients([7; APPLICATION_RING_DEGREE_V1]);
        let mut proof =
            ProofPolynomialV1::from_centered_coefficients([-9; APPLICATION_RING_DEGREE_V1]);
        application.zeroize();
        proof.zeroize();
        assert!(application.is_zero());
        assert!(proof.is_zero());
    }
}
