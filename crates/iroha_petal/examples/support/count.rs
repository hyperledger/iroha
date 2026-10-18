//! Explicit integer-to-float conversion for example reports and random samples.

/// Convert an unsigned count using exact u32 limbs, rounding only beyond 53 bits.
///
/// # Panics
/// Panics if `count` cannot be represented by u64.
pub fn count_as_f64(count: impl TryInto<u64>) -> f64 {
    let count = count
        .try_into()
        .unwrap_or_else(|_| panic!("count fits u64"));
    let high = u32::try_from(count >> 32).expect("upper count limb fits u32");
    let low = u32::try_from(count & u64::from(u32::MAX)).expect("lower count limb fits u32");
    f64::from(high) * 4_294_967_296.0 + f64::from(low)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_and_53_bit_samples_keep_exact_integer_boundaries() {
        for (count, expected) in [
            (0, 0.0_f64),
            (u64::from(u32::MAX), 4_294_967_295.0),
            (u64::from(u32::MAX) + 1, 4_294_967_296.0),
            ((1_u64 << 53) - 1, 9_007_199_254_740_991.0),
            (1_u64 << 53, 9_007_199_254_740_992.0),
            (u64::MAX, 18_446_744_073_709_551_616.0),
        ] {
            assert_eq!(count_as_f64(count).to_bits(), expected.to_bits());
        }
        assert_eq!(count_as_f64(42_usize).to_bits(), 42.0_f64.to_bits());
    }
}
