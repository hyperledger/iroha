//! Exact, bounded-work pro-rata arithmetic for SCCP quarantine reconciliation (§4.10 R4).
//!
//! Products use four 64-bit limbs and division scans exactly 256 bits. No floating point,
//! allocation or platform-specific reduction changes the result across validators.

/// Compute a claim's payout, including cumulative rounding and the remaining-backing cap.
///
/// Returns `None` for an invalid rate (`denominator == 0` or `backing > denominator`). The
/// face sum may exceed `u128`: two separate 256-bit products and their remainders avoid a
/// 257-bit intermediate while computing the exact difference of floors.
#[must_use]
pub fn payout(
    backing: u128,
    denominator: u128,
    settled_face: u128,
    amount: u128,
    available: u128,
) -> Option<u128> {
    if denominator == 0 || backing > denominator {
        return None;
    }
    let (_, prior_remainder) = mul_div(settled_face, backing, denominator);
    let (quotient, amount_remainder) = mul_div(amount, backing, denominator);
    let (remainders, carry) = prior_remainder.overflowing_add(amount_remainder);
    let rounds_up = carry || remainders >= denominator;
    // Because backing <= denominator, the incremental rounded payout is <= amount.
    let uncapped = quotient.checked_add(u128::from(rounds_up))?;
    Some(uncapped.min(available))
}

/// Multiply two u128 values into their exact four-limb little-endian product.
fn multiply(a: u128, b: u128) -> [u64; 4] {
    let low_limb = |value: u128| {
        u64::try_from(value & u128::from(u64::MAX)).expect("masked lower limb fits u64")
    };
    let a = [
        low_limb(a),
        u64::try_from(a >> 64).expect("upper limb fits u64"),
    ];
    let b = [
        low_limb(b),
        u64::try_from(b >> 64).expect("upper limb fits u64"),
    ];
    let mut limbs = [0u64; 4];
    for (i, a) in a.into_iter().enumerate() {
        let mut carry = 0u128;
        for (j, b) in b.into_iter().enumerate() {
            let product = u128::from(a) * u128::from(b) + u128::from(limbs[i + j]) + carry;
            limbs[i + j] = low_limb(product);
            carry = product >> 64;
        }
        limbs[i + 2] = u64::try_from(carry).expect("product carry fits one limb");
    }
    limbs
}

/// Exact quotient and remainder of `a*b/d`, with the precondition `b <= d` and `d > 0`.
fn mul_div(a: u128, b: u128, d: u128) -> (u128, u128) {
    let product = multiply(a, b);
    let mut remainder = 0u128;
    let mut quotient = 0u128;
    for bit in (0..256).rev() {
        let carry = remainder >> 127 != 0;
        remainder = (remainder << 1) | u128::from((product[bit / 64] >> (bit % 64)) & 1);
        if carry || remainder >= d {
            remainder = remainder.wrapping_sub(d);
            debug_assert!(bit < 128, "a*b/d <= a, so the quotient fits u128");
            quotient |= 1u128 << bit;
        }
    }
    (quotient, remainder)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_limb_products_cover_carries() {
        assert_eq!(multiply(0, u128::MAX), [0; 4]);
        assert_eq!(
            multiply(u128::MAX, u128::MAX),
            [1, 0, u64::MAX - 1, u64::MAX]
        );
        assert_eq!(multiply(1u128 << 64, 1u128 << 64), [0, 0, 1, 0]);
    }

    #[test]
    fn division_matches_small_exact_arithmetic() {
        for d in 1..60u128 {
            for b in 0..=d {
                for a in [0, 1, d - 1, d, d + 1, 127, 1024, 65535] {
                    assert_eq!(mul_div(a, b, d), (a * b / d, a * b % d));
                }
            }
        }
    }

    #[test]
    fn payout_handles_full_width_face_sum_and_remainder_carry() {
        let max = u128::MAX;
        assert_eq!(payout(max, max, max, max, max), Some(max));
        assert_eq!(payout(max - 1, max, max - 1, max - 1, max), Some(max - 2));
        assert_eq!(payout(1, 3, max, max, max), Some(max / 3));
        assert_eq!(payout(1, 2, max, max, max), Some(1u128 << 127));
        assert_eq!(payout(0, 1, max, max, max), Some(0));
        assert_eq!(payout(1, 0, 0, 1, 1), None);
        assert_eq!(payout(2, 1, 0, 1, 1), None);
    }

    #[test]
    fn cumulative_rounding_pays_exact_backing_in_any_partition() {
        for parts in [[1u128, 2, 4, 3], [3, 4, 2, 1], [10, 0, 0, 0]] {
            let mut face = 0;
            let mut left = 7;
            for amount in parts {
                let paid = payout(7, 10, face, amount, left).unwrap();
                face += amount;
                left -= paid;
            }
            assert_eq!(left, 0);
            assert_eq!(payout(7, 10, face, 100, left), Some(0));
        }
        assert_eq!(payout(7, 10, 0, 10, 2), Some(2));
    }
}
