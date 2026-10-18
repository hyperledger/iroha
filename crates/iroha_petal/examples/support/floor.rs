//! Checked conversion of finite nonnegative floating-point example quantities.

/// Truncate a finite nonnegative float, refusing values outside u64.
///
/// Decode its integer bits explicitly so no cast silently saturates invalid input.
pub fn floor_u64(value: f64) -> Option<u64> {
    if !value.is_finite() || value < 0.0 {
        return None;
    }
    if value < 1.0 {
        return Some(0);
    }
    let bits = value.to_bits();
    let exponent = u32::try_from((bits >> 52) & 0x7FF)
        .ok()?
        .checked_sub(1023)?;
    if exponent >= 64 {
        return None;
    }
    let significand = (bits & ((1_u64 << 52) - 1)) | (1_u64 << 52);
    Some(if exponent <= 52 {
        significand >> (52 - exponent)
    } else {
        significand << (exponent - 52)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finite_conversion_preserves_floor_and_refuses_invalid_inputs() {
        for value in [
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            -0.5,
            18_446_744_073_709_551_616.0,
        ] {
            assert_eq!(floor_u64(value), None);
        }
        assert_eq!(floor_u64(-0.0), Some(0));
        assert_eq!(floor_u64(f64::MIN_POSITIVE), Some(0));
        assert_eq!(floor_u64(f64::from_bits(1)), Some(0));
        assert_eq!(floor_u64(0.999_999), Some(0));
        assert_eq!(floor_u64(1.0), Some(1));
        assert_eq!(floor_u64(59_999.999_999), Some(59_999));
        assert_eq!(floor_u64(60_000.0), Some(60_000));
        assert_eq!(floor_u64(9_007_199_254_740_991.0), Some((1_u64 << 53) - 1));
        assert_eq!(floor_u64(9_007_199_254_740_992.0), Some(1_u64 << 53));
        assert_eq!(
            floor_u64(f64::from_bits(0x43EF_FFFF_FFFF_FFFF)),
            Some(u64::MAX - 2047)
        );
    }
}
