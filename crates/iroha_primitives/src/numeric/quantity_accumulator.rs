//! Allocation-free canonical quantity sums and one exactly admitted final magnitude.

use super::{
    BigInt, BigIntAdmissionCloneError, Numeric, NumericOperationError, QUANTITY_SUM_RELATION_LIMBS,
    Quantity, aligned_quantity_sum_limbs,
};
use std::alloc::Layout;

/// Bounded, allocation-free aggregate of canonical nonnegative quantities.
///
/// Every addition has the same result-domain checks as [`Quantity::checked_add`].
/// Arithmetic scratch stays on the stack. A caller can inspect the exact final
/// heap layout, reserve it from its original pool, and materialize once while
/// retaining that charge until the returned quantity drops.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuantityAccumulator {
    limbs: [u64; QUANTITY_SUM_RELATION_LIMBS],
    scale: u32,
}

impl Default for QuantityAccumulator {
    fn default() -> Self {
        Self::zero()
    }
}

impl QuantityAccumulator {
    /// Start with the canonical zero without allocating.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            limbs: [0; QUANTITY_SUM_RELATION_LIMBS],
            scale: 0,
        }
    }

    /// Copy a canonical quantity into bounded inline arithmetic scratch.
    #[must_use]
    pub fn from_quantity(quantity: &Quantity) -> Self {
        Self {
            limbs: aligned_quantity_sum_limbs(quantity, quantity.scale())
                .expect("a canonical quantity fits the inline magnitude"),
            scale: quantity.scale(),
        }
    }

    /// Whether this aggregate is the canonical zero, without materializing it.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|limb| *limb == 0)
    }

    /// Subtract a borrowed quantity without allocating arithmetic scratch.
    ///
    /// # Errors
    /// Preserves the original aggregate on underflow or canonical-domain overflow.
    pub fn try_sub(&mut self, quantity: &Quantity) -> Result<(), NumericOperationError> {
        self.try_sub_accumulator(&Self::from_quantity(quantity))
    }

    /// Subtract another inline aggregate, normalizing only the final difference.
    ///
    /// # Errors
    /// Preserves both operands on underflow or canonical-domain overflow.
    pub fn try_sub_accumulator(&mut self, other: &Self) -> Result<(), NumericOperationError> {
        let scale = self.scale.max(other.scale);
        let mut difference = Self::align_limbs(self.limbs, self.scale, scale)?;
        let rhs = Self::align_limbs(other.limbs, other.scale, scale)?;
        let mut borrow = false;
        for (limb, rhs) in difference.iter_mut().zip(rhs) {
            let (value, first) = limb.overflowing_sub(rhs);
            let (value, second) = value.overflowing_sub(u64::from(borrow));
            *limb = value;
            borrow = first || second;
        }
        if borrow {
            // Match ordinary decimal subtraction's error order: canonical-domain
            // overflow precedes the nominal nonnegative-quantity check. The
            // wrapped two's-complement difference gives the absolute magnitude
            // without allocating a signed BigInt.
            let mut carry = true;
            for limb in &mut difference {
                let (value, overflow) = (!*limb).overflowing_add(u64::from(carry));
                *limb = value;
                carry = overflow;
            }
            Self::normalize(difference, scale, true)?;
            return Err(NumericOperationError::QuantityUnderflow);
        }
        let mut result = Self::zero();
        result.add_aligned(difference, scale)?;
        *self = result;
        Ok(())
    }

    /// Compare against a borrowed canonical quantity without heap scratch.
    #[must_use]
    pub fn cmp_quantity(&self, other: &Quantity) -> core::cmp::Ordering {
        self.cmp_value(&Self::from_quantity(other))
    }

    /// Add a borrowed quantity without cloning it or allocating scratch.
    ///
    /// # Errors
    /// Refuses a result outside the signed 512-bit canonical mantissa domain.
    /// On refusal the previous aggregate remains intact.
    pub fn try_add(&mut self, quantity: &Quantity) -> Result<(), NumericOperationError> {
        let scale = self.scale.max(quantity.scale());
        let rhs = aligned_quantity_sum_limbs(quantity, scale)
            .ok_or(NumericOperationError::MantissaOverflow)?;
        self.add_aligned(rhs, scale)
    }

    /// Add a second complete canonical aggregate without materializing either.
    ///
    /// # Errors
    /// Refuses an unrepresentable canonical sum and preserves both operands.
    pub fn try_add_accumulator(&mut self, other: &Self) -> Result<(), NumericOperationError> {
        let scale = self.scale.max(other.scale);
        let rhs = Self::align_limbs(other.limbs, other.scale, scale)?;
        self.add_aligned(rhs, scale)
    }

    /// Compare canonical aggregates without materializing either magnitude.
    #[must_use]
    pub fn cmp_value(&self, other: &Self) -> core::cmp::Ordering {
        let scale = self.scale.max(other.scale);
        // A 511-bit canonical mantissa aligned through at most 28 decimal places
        // fits the same ten stack limbs used by the canonical sum relation.
        let left = Self::align_limbs(self.limbs, self.scale, scale)
            .expect("canonical decimal alignment fits stack limbs");
        let right = Self::align_limbs(other.limbs, other.scale, scale)
            .expect("canonical decimal alignment fits stack limbs");
        left.iter().rev().cmp(right.iter().rev())
    }

    /// Multiply by basis points, rounding toward zero at this aggregate's scale.
    ///
    /// Arithmetic stays inline and preserves the original aggregate on refusal.
    /// # Errors
    /// Refuses a ratio above 10,000 basis points or a noncanonical result.
    pub fn try_scale_basis_points(
        &mut self,
        basis_points: u16,
    ) -> Result<(), NumericOperationError> {
        if basis_points > 10_000 {
            return Err(NumericOperationError::NonCanonical);
        }
        let mut product = self.limbs;
        let mut carry = 0_u128;
        for limb in &mut product {
            let value = u128::from(*limb) * u128::from(basis_points) + carry;
            *limb = u64::try_from(value & u128::from(u64::MAX)).expect("masked product limb");
            carry = value >> 64;
        }
        if carry != 0 {
            return Err(NumericOperationError::MantissaOverflow);
        }
        let mut remainder = 0_u128;
        for limb in product.iter_mut().rev() {
            let value = (remainder << 64) | u128::from(*limb);
            *limb = u64::try_from(value / 10_000).expect("basis-point quotient limb");
            remainder = value % 10_000;
        }
        let mut result = Self::zero();
        result.add_aligned(product, self.scale)?;
        *self = result;
        Ok(())
    }

    fn align_limbs(
        mut limbs: [u64; QUANTITY_SUM_RELATION_LIMBS],
        from: u32,
        to: u32,
    ) -> Result<[u64; QUANTITY_SUM_RELATION_LIMBS], NumericOperationError> {
        for _ in from..to {
            let mut carry = 0_u128;
            for limb in &mut limbs {
                let product = u128::from(*limb) * 10 + carry;
                *limb = u64::try_from(product & u128::from(u64::MAX)).expect("masked decimal limb");
                carry = product >> 64;
            }
            if carry != 0 {
                return Err(NumericOperationError::MantissaOverflow);
            }
        }
        Ok(limbs)
    }

    fn add_aligned(
        &mut self,
        rhs: [u64; QUANTITY_SUM_RELATION_LIMBS],
        scale: u32,
    ) -> Result<(), NumericOperationError> {
        let mut sum = Self::align_limbs(self.limbs, self.scale, scale)?;
        let mut carry = 0_u128;
        for (limb, rhs) in sum.iter_mut().zip(rhs) {
            let value = u128::from(*limb) + u128::from(rhs) + carry;
            *limb = u64::try_from(value & u128::from(u64::MAX)).expect("masked addition limb");
            carry = value >> 64;
        }
        if carry != 0 {
            return Err(NumericOperationError::MantissaOverflow);
        }
        *self = Self::normalize(sum, scale, false)?;
        Ok(())
    }

    fn normalize(
        mut sum: [u64; QUANTITY_SUM_RELATION_LIMBS],
        mut scale: u32,
        negative: bool,
    ) -> Result<Self, NumericOperationError> {
        if sum.iter().all(|limb| *limb == 0) {
            scale = 0;
        }
        while scale != 0 {
            let mut quotient = [0_u64; QUANTITY_SUM_RELATION_LIMBS];
            let mut remainder = 0_u128;
            for index in (0..sum.len()).rev() {
                let value = (remainder << 64) | u128::from(sum[index]);
                quotient[index] = u64::try_from(value / 10).expect("division quotient limb");
                remainder = value % 10;
            }
            if remainder != 0 {
                break;
            }
            sum = quotient;
            scale -= 1;
        }
        let negative_minimum =
            negative && sum[7] == 1_u64 << 63 && sum[..7].iter().all(|limb| *limb == 0);
        if sum[8..].iter().any(|limb| *limb != 0) || (sum[7] >> 63 != 0 && !negative_minimum) {
            return Err(NumericOperationError::MantissaOverflow);
        }
        Ok(Self { limbs: sum, scale })
    }

    /// Exact native-digit backing needed by [`Self::try_into_quantity`].
    ///
    /// # Errors
    /// Refuses an unrepresentable physical allocation layout.
    pub fn admission_layout(&self) -> Result<Layout, BigIntAdmissionCloneError> {
        BigInt::unsigned_words_admission_layout(&self.limbs)
    }

    /// Materialize through one exact fallible allocation, with no heap scratch.
    ///
    /// The caller must reserve and retain the matching original-pool charge;
    /// this method neither acquires a pool charge nor substitutes another pool.
    /// Zero needs no heap allocation.
    ///
    /// # Errors
    /// Refuses an unrepresentable layout or a physical allocator refusal.
    pub fn try_into_quantity(self) -> Result<Quantity, BigIntAdmissionCloneError> {
        Ok(Quantity(Numeric {
            mantissa: BigInt::try_from_unsigned_words_for_admission(&self.limbs)?,
            scale: self.scale,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr as _;

    #[test]
    fn inline_subtraction_preserves_canonical_results_and_both_operands_on_refusal() {
        let max = Quantity::try_from_numeric(Numeric::new(
            BigInt::from_inner((super::super::UnboundedBigInt::from(1_u64) << 511_usize) - 1_u8)
                .unwrap(),
            0,
        ))
        .unwrap();
        let values = [
            Quantity::zero(),
            Quantity::one(),
            "0.0000000000000000000000000001".parse().unwrap(),
            "18446744073709551616.25".parse().unwrap(),
            max,
        ];
        for left in &values {
            for right in &values {
                let mut result = QuantityAccumulator::from_quantity(left);
                let original = result;
                let rhs = QuantityAccumulator::from_quantity(right);
                assert_eq!(result.is_zero(), left.is_zero());
                assert_eq!(result.cmp_quantity(right), left.cmp(right));
                let expected = left.checked_sub(right);
                let actual = result.try_sub(right);
                match expected {
                    Ok(expected) => {
                        actual.unwrap();
                        assert_eq!(result.try_into_quantity().unwrap(), expected);
                        let mut second = original;
                        second.try_sub_accumulator(&rhs).unwrap();
                        assert_eq!(result, second);
                    }
                    Err(expected) => {
                        assert_eq!(actual, Err(expected));
                        assert_eq!(result, original);
                    }
                }
                assert_eq!(rhs, QuantityAccumulator::from_quantity(right));
            }
        }
        // 0.2 - (2^511 + 2) / 10 normalizes to mantissa -2^511 at scale 1. That signed
        // minimum is representable, so the refusal is underflow, not mantissa overflow.
        let minimum_magnitude = Quantity::try_from_numeric(Numeric::new(
            BigInt::from_inner(
                ((super::super::UnboundedBigInt::from(1_u64) << 511_usize) + 2_u8) / 10_u8,
            )
            .unwrap(),
            0,
        ))
        .unwrap();
        let fifth = Quantity::from_str("0.2").unwrap();
        assert_eq!(
            fifth.checked_sub(&minimum_magnitude),
            Err(NumericOperationError::QuantityUnderflow)
        );
        let mut result = QuantityAccumulator::from_quantity(&fifth);
        let original = result;
        assert_eq!(
            result.try_sub(&minimum_magnitude),
            Err(NumericOperationError::QuantityUnderflow)
        );
        assert_eq!(result, original);
        let rhs = QuantityAccumulator::from_quantity(&minimum_magnitude);
        assert_eq!(
            result.try_sub_accumulator(&rhs),
            Err(NumericOperationError::QuantityUnderflow)
        );
        assert_eq!(result, original);
        assert_eq!(rhs, QuantityAccumulator::from_quantity(&minimum_magnitude));
    }

    #[test]
    fn inline_scaled_comparison_matches_unbounded_products_at_full_width() {
        use super::super::UnboundedBigInt;
        let max = (UnboundedBigInt::from(1_u64) << 511_usize) - 1_u8;
        for left_scale in 0..=28 {
            let left = Quantity::try_from_numeric(Numeric::new(
                BigInt::from_inner(max.clone()).unwrap(),
                left_scale,
            ))
            .unwrap();
            for right_scale in 0..=28 {
                let right = Quantity::try_from_numeric(Numeric::new(
                    BigInt::from_inner(&max - 2_u8).unwrap(),
                    right_scale,
                ))
                .unwrap();
                for (a, b) in [
                    (0, 0),
                    (0, u64::MAX),
                    (1, 10_000),
                    (10_000, 9_999),
                    (u64::MAX, 1),
                    (u64::MAX, u64::MAX),
                ] {
                    let scale = left.scale().max(right.scale());
                    let expected_left = left.mantissa().inner()
                        * a
                        * UnboundedBigInt::from(10_u8).pow(scale - left.scale());
                    let expected_right = right.mantissa().inner()
                        * b
                        * UnboundedBigInt::from(10_u8).pow(scale - right.scale());
                    assert_eq!(
                        left.cmp_mul_u64(a, &right, b),
                        expected_left.cmp(&expected_right)
                    );
                }
            }
        }
    }

    #[test]
    fn inline_comparison_and_basis_points_match_canonical_mixed_scale_arithmetic() {
        let values = [
            "0",
            "1",
            "1.0000000000000000000000000001",
            "99.01",
            "100000000000000000000000000000000000000000000000000001",
        ];
        for left in values {
            let left = Quantity::from_str(left).unwrap();
            let mut sum = QuantityAccumulator::zero();
            sum.try_add(&left).unwrap();
            for right in values {
                let right = Quantity::from_str(right).unwrap();
                let mut rhs = QuantityAccumulator::zero();
                rhs.try_add(&right).unwrap();
                assert_eq!(sum.cmp_value(&rhs), left.cmp(&right));
            }
            for bps in [0, 1, 1_234, 9_999, 10_000] {
                let mut actual = sum;
                actual.try_scale_basis_points(bps).unwrap();
                let expected = left
                    .try_mul_div_decimal_round(
                        &Numeric::from(u64::from(bps)),
                        &Numeric::from(10_000_u64),
                        left.scale(),
                        super::super::RoundingMode::TowardZero,
                    )
                    .unwrap();
                assert_eq!(actual.try_into_quantity().unwrap(), expected);
            }
            assert!(sum.try_scale_basis_points(10_001).is_err());
            assert_eq!(sum.try_into_quantity().unwrap(), left);
        }
    }

    #[test]
    fn bounded_sum_matches_canonical_arithmetic_at_every_scale_and_carry() {
        let mut state = 0x23ac_514a_9853_0041_u64;
        for scale in 0..=28 {
            let mut sum = QuantityAccumulator::zero();
            let mut expected = Quantity::zero();
            for _ in 0..64 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let amount = Quantity::try_from_numeric(Numeric::new(
                    BigInt::from_i128(i128::from(state)),
                    scale,
                ))
                .unwrap();
                expected = expected.checked_add(&amount).unwrap();
                sum.try_add(&amount).unwrap();
                let actual = sum.try_into_quantity().unwrap();
                assert_eq!(actual, expected);
                assert_eq!(
                    actual.admission_clone_layout().unwrap(),
                    sum.admission_layout().unwrap()
                );
                let wire = norito::to_bytes(&actual).unwrap();
                assert_eq!(
                    norito::decode_from_bytes::<Quantity>(&wire).unwrap(),
                    actual
                );
            }
        }
    }

    #[test]
    fn mixed_scale_normalization_zero_and_large_operands_match() {
        let mut sum = QuantityAccumulator::default();
        assert_eq!(sum.admission_layout().unwrap().size(), 0);
        assert_eq!(sum.try_into_quantity().unwrap(), Quantity::zero());
        let mut expected = Quantity::zero();
        for text in [
            "0",
            "0.0000000000000000000000000001",
            "999999999999999999999999999999999",
            "0.9999999999999999999999999999",
            "0",
            "1",
        ] {
            let amount = Quantity::from_str(text).unwrap();
            expected = expected.checked_add(&amount).unwrap();
            sum.try_add(&amount).unwrap();
            assert_eq!(sum.try_into_quantity().unwrap(), expected);
        }
    }

    #[test]
    fn separately_accumulated_exposure_preserves_original_grouping_and_refusal() {
        let max = Quantity::try_from_numeric(Numeric::new(
            BigInt::from_twos_bytes(&[vec![0xff; 63], vec![0x7f]].concat()).unwrap(),
            0,
        ))
        .unwrap();
        let bonded = max.checked_sub(&Quantity::one()).unwrap();
        let half = Quantity::from_str("0.5").unwrap();
        let mut left = QuantityAccumulator::zero();
        left.try_add(&bonded).unwrap();
        let mut pending = QuantityAccumulator::zero();
        pending.try_add(&half).unwrap();
        let unchanged = left;
        assert!(left.try_add_accumulator(&pending).is_err());
        assert_eq!(left, unchanged);
        pending.try_add(&half).unwrap();
        let original_pending = pending;
        left.try_add_accumulator(&pending).unwrap();
        assert_eq!(pending, original_pending);
        assert_eq!(left.try_into_quantity().unwrap(), max);
        assert_eq!(
            left.try_add_accumulator(&pending),
            Err(NumericOperationError::MantissaOverflow)
        );
        assert_eq!(left.try_into_quantity().unwrap(), max);
    }
    #[test]
    fn overflow_retains_original_sum() {
        let max = Quantity::try_from_numeric(Numeric::new(
            BigInt::from_twos_bytes(&[vec![0xff; 63], vec![0x7f]].concat()).unwrap(),
            0,
        ))
        .unwrap();
        let mut sum = QuantityAccumulator::zero();
        sum.try_add(&max).unwrap();
        let before = sum;
        assert_eq!(
            sum.try_add(&Quantity::one()),
            Err(NumericOperationError::MantissaOverflow)
        );
        assert_eq!(sum, before);
        assert_eq!(sum.try_into_quantity().unwrap(), max);
    }
}
