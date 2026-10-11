//! Consensus-visible tags and register conventions for Kotodama V1 numbers.
//!
//! These values are part of ABI V1. Their numeric discriminants are stable and
//! must be changed together with the ABI hash and golden tests.
pub use iroha_data_model::executor::fault::{NumericFaultV1, PointerAbiFaultV1};
/// Stable rounding-mode tags supplied to rounded decimal operations in `r13`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u64)]
pub enum RoundingModeV1 {
    /// Truncate toward zero.
    TowardZero = 0,
    /// Round away from zero whenever the discarded remainder is nonzero.
    AwayFromZero = 1,
    /// Round toward negative infinity.
    Floor = 2,
    /// Round toward positive infinity.
    Ceil = 3,
    /// Round to nearest, resolving ties toward an even mantissa.
    NearestEven = 4,
    /// Round to nearest, resolving ties away from zero.
    NearestAway = 5,
    /// Round to nearest, resolving ties toward zero.
    NearestTowardZero = 6,
}
impl RoundingModeV1 {
    /// Decode a stable ABI tag.
    #[must_use]
    pub const fn from_tag(tag: u64) -> Option<Self> {
        Some(match tag {
            0 => Self::TowardZero,
            1 => Self::AwayFromZero,
            2 => Self::Floor,
            3 => Self::Ceil,
            4 => Self::NearestEven,
            5 => Self::NearestAway,
            6 => Self::NearestTowardZero,
            _ => return None,
        })
    }
    /// Return the stable ABI tag.
    #[must_use]
    pub const fn tag(self) -> u64 {
        self as u64
    }
}
/// Result pointer/value register for numeric syscalls.
pub const NUMERIC_RESULT_REGISTER: usize = 10;
/// Status register: zero on success, otherwise a [`NumericFaultV1`] tag.
pub const NUMERIC_STATUS_REGISTER: usize = 11;
/// Requested decimal scale register for rounded operations.
pub const NUMERIC_SCALE_REGISTER: usize = 12;
/// Rounding-mode register for rounded operations.
pub const NUMERIC_ROUNDING_REGISTER: usize = 13;
/// Failure-mode register for arithmetic operations: zero traps, one returns status.
pub const NUMERIC_FAILURE_MODE_REGISTER: usize = 14;
/// Trap on an arithmetic-domain failure.
pub const NUMERIC_FAILURE_TRAP: u64 = 0;
/// Return an arithmetic-domain failure in `r11` without trapping.
pub const NUMERIC_FAILURE_STATUS: u64 = 1;
#[cfg(test)]
mod tests {
    use super::{NumericFaultV1, PointerAbiFaultV1, RoundingModeV1};
    #[test]
    fn numeric_fault_tags_are_complete_and_stable() {
        for tag in 1..=13 {
            assert_eq!(
                NumericFaultV1::from_tag(tag).map(NumericFaultV1::tag),
                Some(tag)
            );
        }
        assert_eq!(NumericFaultV1::from_tag(0), None);
        assert_eq!(NumericFaultV1::from_tag(14), None);
    }
    #[test]
    fn rounding_tags_are_complete_and_stable() {
        for tag in 0..=6 {
            assert_eq!(
                RoundingModeV1::from_tag(tag).map(RoundingModeV1::tag),
                Some(tag)
            );
        }
        assert_eq!(RoundingModeV1::from_tag(7), None);
    }
    #[test]
    fn pointer_fault_tags_are_complete_and_stable() {
        for tag in 1..=11 {
            assert_eq!(
                PointerAbiFaultV1::from_tag(tag).map(PointerAbiFaultV1::tag),
                Some(tag)
            );
        }
        assert_eq!(PointerAbiFaultV1::from_tag(0), None);
        assert_eq!(PointerAbiFaultV1::from_tag(12), None);
    }
}
