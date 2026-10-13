//! Canonical in-memory layout for compiler-owned bounded Kotodama lists.
//!
//! A list handle points at one contiguous deterministic heap allocation:
//! `[len: u64][capacity: u64][element words...]`. Elements are flattened into
//! a compiler-known, fixed number of 64-bit ABI words. The source type and boundary schema carry
//! the element type and capacity; no runtime type tag is inferred from memory contents.
use core::fmt;
/// Minimum source-level list capacity.
pub const LIST_MIN_CAPACITY_V1: u8 = 1;
/// Maximum source-level list capacity.
pub const LIST_MAX_CAPACITY_V1: u8 = 64;
/// Number of fixed header words in a list allocation.
pub const LIST_HEADER_WORDS_V1: u64 = 2;
/// Width of one ABI word in bytes.
pub const LIST_WORD_BYTES_V1: u64 = 8;
/// Invalid compiler-owned list layout or access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListLayoutErrorV1 {
    /// Capacity is outside `1..=64`.
    InvalidCapacity(u64),
    /// An element must occupy at least one ABI word.
    ZeroElementWords,
    /// Layout arithmetic exceeds the address space.
    SizeOverflow,
    /// Index is outside the compile-time capacity.
    CapacityOutOfBounds {
        /// Requested element index.
        index: u64,
        /// Compile-time list capacity.
        capacity: u8,
    },
    /// Index is not present in the current logical length.
    LengthOutOfBounds {
        /// Requested element index.
        index: u64,
        /// Current logical length.
        len: u64,
    },
}
impl fmt::Display for ListLayoutErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCapacity(capacity) => write!(
                formatter,
                "V1 List capacity {capacity} is outside {LIST_MIN_CAPACITY_V1}..={LIST_MAX_CAPACITY_V1}"
            ),
            Self::ZeroElementWords => formatter.write_str("V1 List elements occupy zero ABI words"),
            Self::SizeOverflow => formatter.write_str("V1 List allocation size overflow"),
            Self::CapacityOutOfBounds { index, capacity } => write!(
                formatter,
                "V1 List index {index} exceeds capacity {capacity}"
            ),
            Self::LengthOutOfBounds { index, len } => {
                write!(
                    formatter,
                    "V1 List index {index} is not present at length {len}"
                )
            }
        }
    }
}
impl std::error::Error for ListLayoutErrorV1 {}
/// Validated contiguous list layout known to compiler and VM tooling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ListLayoutV1 {
    capacity: u8,
    element_words: u64,
}
impl ListLayoutV1 {
    /// Construct a validated layout.
    ///
    /// # Errors
    ///
    /// Rejects capacities outside `1..=64`, zero-width elements, and layouts
    /// whose byte size cannot be represented by `u64`.
    pub fn try_new(capacity: u64, element_words: u64) -> Result<Self, ListLayoutErrorV1> {
        let capacity = u8::try_from(capacity)
            .ok()
            .filter(|capacity| (LIST_MIN_CAPACITY_V1..=LIST_MAX_CAPACITY_V1).contains(capacity))
            .ok_or(ListLayoutErrorV1::InvalidCapacity(capacity))?;
        if element_words == 0 {
            return Err(ListLayoutErrorV1::ZeroElementWords);
        }
        let layout = Self {
            capacity,
            element_words,
        };
        layout.allocation_bytes()?;
        Ok(layout)
    }
    /// Compile-time capacity.
    #[must_use]
    pub const fn capacity(self) -> u8 {
        self.capacity
    }
    /// Flattened width of one element in ABI words.
    #[must_use]
    pub const fn element_words(self) -> u64 {
        self.element_words
    }
    /// Total size of the single contiguous heap allocation.
    ///
    /// # Errors
    ///
    /// Returns [`ListLayoutErrorV1::SizeOverflow`] on address arithmetic overflow.
    pub fn allocation_bytes(self) -> Result<u64, ListLayoutErrorV1> {
        LIST_HEADER_WORDS_V1
            .checked_add(
                u64::from(self.capacity)
                    .checked_mul(self.element_words)
                    .ok_or(ListLayoutErrorV1::SizeOverflow)?,
            )
            .and_then(|words| words.checked_mul(LIST_WORD_BYTES_V1))
            .ok_or(ListLayoutErrorV1::SizeOverflow)
    }
    /// Byte offset of a capacity-checked element slot from the list handle.
    ///
    /// # Errors
    ///
    /// Rejects indexes at or above the compile-time capacity.
    pub fn slot_offset(self, index: u64) -> Result<u64, ListLayoutErrorV1> {
        if index >= u64::from(self.capacity) {
            return Err(ListLayoutErrorV1::CapacityOutOfBounds {
                index,
                capacity: self.capacity,
            });
        }
        LIST_HEADER_WORDS_V1
            .checked_add(
                index
                    .checked_mul(self.element_words)
                    .ok_or(ListLayoutErrorV1::SizeOverflow)?,
            )
            .and_then(|words| words.checked_mul(LIST_WORD_BYTES_V1))
            .ok_or(ListLayoutErrorV1::SizeOverflow)
    }
    /// Byte offset of an element that is present at `len`.
    ///
    /// # Errors
    ///
    /// Rejects malformed lengths, capacity overflow, and absent indexes.
    pub fn present_slot_offset(self, len: u64, index: u64) -> Result<u64, ListLayoutErrorV1> {
        if len > u64::from(self.capacity) {
            return Err(ListLayoutErrorV1::CapacityOutOfBounds {
                index: len,
                capacity: self.capacity,
            });
        }
        if index >= len {
            return Err(ListLayoutErrorV1::LengthOutOfBounds { index, len });
        }
        self.slot_offset(index)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_v1_capacity_has_one_contiguous_layout() {
        for capacity in LIST_MIN_CAPACITY_V1..=LIST_MAX_CAPACITY_V1 {
            for element_words in 1..=16 {
                let layout = ListLayoutV1::try_new(u64::from(capacity), element_words)
                    .expect("valid bounded layout");
                assert_eq!(
                    (layout.allocation_bytes()).expect("expected successful fixture result"),
                    (2 + u64::from(capacity) * element_words) * 8
                );
                for index in 0..u64::from(capacity) {
                    assert_eq!(
                        (layout.slot_offset(index)).expect("expected successful fixture result"),
                        (2 + index * element_words) * 8
                    );
                }
            }
        }
    }
    #[test]
    fn invalid_capacities_widths_and_arithmetic_fail_closed() {
        assert!(matches!(
            ListLayoutV1::try_new(0, 1),
            Err(ListLayoutErrorV1::InvalidCapacity(0))
        ));
        assert!(matches!(
            ListLayoutV1::try_new(65, 1),
            Err(ListLayoutErrorV1::InvalidCapacity(65))
        ));
        assert_eq!(
            ListLayoutV1::try_new(1, 0),
            Err(ListLayoutErrorV1::ZeroElementWords)
        );
        assert_eq!(
            ListLayoutV1::try_new(64, u64::MAX),
            Err(ListLayoutErrorV1::SizeOverflow)
        );
    }
    #[test]
    fn reads_distinguish_capacity_from_logical_length() {
        let layout = ListLayoutV1::try_new(4, 2).expect("layout");
        assert!(matches!(layout.present_slot_offset(2, 1), Ok(32)));
        assert!(matches!(
            layout.present_slot_offset(2, 2),
            Err(ListLayoutErrorV1::LengthOutOfBounds { index: 2, len: 2 })
        ));
        assert!(matches!(
            layout.slot_offset(4),
            Err(ListLayoutErrorV1::CapacityOutOfBounds {
                index: 4,
                capacity: 4
            })
        ));
        assert!(matches!(
            layout.present_slot_offset(5, 0),
            Err(ListLayoutErrorV1::CapacityOutOfBounds {
                index: 5,
                capacity: 4
            })
        ));
    }
}
