//! Canonical in-memory layout for compiler-owned Kotodama sums.
//!
//! `Option<T>` and `Result<T, E>` use one raw heap handle. The allocation is
//! `[tag: u64][active payload words...]`, reserved to the larger branch width
//! but populated only for the branch selected by the tag. This keeps nested
//! aggregate values fixed-width without constructing inactive placeholders.
use core::fmt;
/// Number of fixed header words in a sum allocation.
pub const SUM_HEADER_WORDS_V1: u64 = 1;
/// Width of one ABI word in bytes.
pub const SUM_WORD_BYTES_V1: u64 = 8;
/// Invalid compiler-owned sum layout or branch selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SumLayoutErrorV1 {
    /// Layout arithmetic exceeds the address space.
    SizeOverflow,
    /// A runtime discriminant was not exactly zero or one.
    InvalidTag(u64),
    /// The active payload width differs from the selected branch schema.
    ActiveWidthMismatch {
        /// Width required by the selected branch.
        expected: u64,
        /// Width supplied by the value.
        actual: u64,
    },
}
impl fmt::Display for SumLayoutErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SizeOverflow => formatter.write_str("V1 sum allocation size overflow"),
            Self::InvalidTag(tag) => {
                write!(formatter, "V1 sum tag {tag} is not exactly zero or one")
            }
            Self::ActiveWidthMismatch { expected, actual } => write!(
                formatter,
                "V1 sum active payload has {actual} words; selected branch requires {expected}"
            ),
        }
    }
}
impl std::error::Error for SumLayoutErrorV1 {}
/// Validated fixed allocation layout for an active-only two-branch sum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SumLayoutV1 {
    false_words: u64,
    true_words: u64,
}
impl SumLayoutV1 {
    /// Construct a layout from the flattened widths of the false and true branches.
    ///
    /// # Errors
    ///
    /// Rejects widths whose maximum allocation cannot be represented by `u64`.
    pub fn try_new(false_words: u64, true_words: u64) -> Result<Self, SumLayoutErrorV1> {
        let layout = Self {
            false_words,
            true_words,
        };
        layout.allocation_bytes()?;
        Ok(layout)
    }
    /// Construct the canonical layout for `Option<T>`.
    ///
    /// The false (`none`) branch has no payload and the true (`some`) branch
    /// contains the flattened `T` words.
    pub fn option(some_words: u64) -> Result<Self, SumLayoutErrorV1> {
        Self::try_new(0, some_words)
    }
    /// Flattened payload width selected by `tag`.
    ///
    /// # Errors
    ///
    /// Rejects tags other than zero and one.
    pub const fn active_words(self, tag: u64) -> Result<u64, SumLayoutErrorV1> {
        match tag {
            0 => Ok(self.false_words),
            1 => Ok(self.true_words),
            invalid => Err(SumLayoutErrorV1::InvalidTag(invalid)),
        }
    }
    /// Maximum branch width reserved by the allocation.
    #[must_use]
    pub const fn payload_capacity_words(self) -> u64 {
        if self.false_words >= self.true_words {
            self.false_words
        } else {
            self.true_words
        }
    }
    /// Total bytes in the single contiguous allocation.
    ///
    /// # Errors
    ///
    /// Returns [`SumLayoutErrorV1::SizeOverflow`] on arithmetic overflow.
    pub fn allocation_bytes(self) -> Result<u64, SumLayoutErrorV1> {
        SUM_HEADER_WORDS_V1
            .checked_add(self.payload_capacity_words())
            .and_then(|words| words.checked_mul(SUM_WORD_BYTES_V1))
            .ok_or(SumLayoutErrorV1::SizeOverflow)
    }
    /// Validate the exact active payload width for `tag`.
    ///
    /// # Errors
    ///
    /// Rejects an invalid tag or a width not equal to the selected branch.
    pub fn validate_active_width(self, tag: u64, actual: u64) -> Result<(), SumLayoutErrorV1> {
        let expected = self.active_words(tag)?;
        if actual == expected {
            Ok(())
        } else {
            Err(SumLayoutErrorV1::ActiveWidthMismatch { expected, actual })
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn option_and_result_layouts_reserve_only_the_larger_branch() {
        let option = SumLayoutV1::option(3).expect("Option layout");
        assert!(matches!(option.active_words(0), Ok(0)));
        assert!(matches!(option.active_words(1), Ok(3)));
        assert!(matches!(option.allocation_bytes(), Ok(32)));
        let result = SumLayoutV1::try_new(5, 2).expect("Result layout");
        assert!(matches!(result.active_words(0), Ok(5)));
        assert!(matches!(result.active_words(1), Ok(2)));
        assert!(matches!(result.allocation_bytes(), Ok(48)));
    }
    #[test]
    fn tags_widths_and_overflow_fail_closed() {
        let layout = SumLayoutV1::try_new(1, 2).expect("layout");
        assert_eq!(layout.active_words(2), Err(SumLayoutErrorV1::InvalidTag(2)));
        assert_eq!(
            layout.validate_active_width(1, 1),
            Err(SumLayoutErrorV1::ActiveWidthMismatch {
                expected: 2,
                actual: 1,
            })
        );
        assert_eq!(
            SumLayoutV1::try_new(u64::MAX, 0),
            Err(SumLayoutErrorV1::SizeOverflow)
        );
    }
}
