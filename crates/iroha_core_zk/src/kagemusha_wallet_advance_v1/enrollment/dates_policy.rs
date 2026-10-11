//! Finite original Core E1 dates, independent of a phone hardware clock.

pub(super) fn valid(issued: u64, expires: u64) -> bool {
    issued != 0
        && expires
            .checked_sub(issued)
            .is_some_and(|lifetime| lifetime > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_finite_original_dates_are_accepted() {
        assert!(valid(1, 2));
        assert!(valid(1, 600_001));
        assert!(valid(1, 600_002));
        assert!(valid(1, u64::MAX));
        assert!(valid(u64::MAX - 600_000, u64::MAX));
    }
    #[test]
    fn missing_nonpositive_and_wrapped_dates_are_rejected() {
        assert!(!valid(0, 1));
        assert!(!valid(1, 1));
        assert!(!valid(2, 1));
        assert!(!valid(u64::MAX, 1));
    }
}
