//! The sealed public list `L` of credential commitments and its flat digest `R`
//! (evaluation record sections 6.2 and 6.4).
//!
//! A list has `3 <= S <= 1000` entries of 128 bytes in strictly increasing
//! unsigned bytewise order, hence without duplicates. There is no tree, no leaf
//! or node hashing and no padding:
//!
//! ```text
//! R = SHA3-512(Frame("PARL/LIST/v1"; P16, B, u16_le(S), concat(L)))
//! ```
//!
//! This module validates and hashes. Who sealed a list, and for which body, is
//! authenticated by the caller.

use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    framing::{COMMITMENT_BYTES, Commitment, Digest64, FramingError, frame_digest},
    profile::P16,
};

/// Smallest list size `S`.
pub const MIN_LIST_SIZE: usize = 3;
/// Largest list size `S`.
pub const MAX_LIST_SIZE: usize = 1000;

/// Why a list is not a sealed list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ListError {
    /// The number of entries is outside `3 ..= 1000`.
    #[error("a sealed list has {MIN_LIST_SIZE} to {MAX_LIST_SIZE} entries, got {actual}")]
    Size {
        /// Number of entries supplied.
        actual: usize,
    },
    /// Entry `index` is not strictly greater than entry `index - 1` (out of
    /// order, or a duplicate).
    #[error("list entry {index} is not strictly greater than the entry before it")]
    Order {
        /// Index of the offending entry.
        index: usize,
    },
    /// Concatenated entries whose length is not a multiple of 128 bytes.
    #[error("{actual} bytes are not a whole number of 128-byte entries")]
    EntryLength {
        /// Length supplied.
        actual: usize,
    },
}

/// Check that `entries` is a sealed list.
///
/// # Errors
/// [`ListError::Size`] or [`ListError::Order`] with the first offending index.
pub fn validate(entries: &[Commitment]) -> Result<(), ListError> {
    if !(MIN_LIST_SIZE..=MAX_LIST_SIZE).contains(&entries.len()) {
        return Err(ListError::Size {
            actual: entries.len(),
        });
    }
    for (index, pair) in entries.windows(2).enumerate() {
        if pair[0] >= pair[1] {
            return Err(ListError::Order { index: index + 1 });
        }
    }
    Ok(())
}

/// `concat(L)`.
pub fn concat(entries: &[Commitment]) -> Vec<u8> {
    let mut out = Vec::with_capacity(entries.len() * COMMITMENT_BYTES);
    for entry in entries {
        out.extend_from_slice(entry.as_bytes());
    }
    out
}

/// Split concatenated entries. Nothing but the length is checked.
///
/// # Errors
/// [`ListError::EntryLength`] unless the length is a multiple of 128.
pub fn split(bytes: &[u8]) -> Result<Vec<Commitment>, ListError> {
    if !bytes.len().is_multiple_of(COMMITMENT_BYTES) {
        return Err(ListError::EntryLength {
            actual: bytes.len(),
        });
    }
    Ok(bytes
        .chunks_exact(COMMITMENT_BYTES)
        .map(|chunk| {
            let mut entry = [0u8; COMMITMENT_BYTES];
            entry.copy_from_slice(chunk);
            Commitment(entry)
        })
        .collect())
}

/// `R` for the body digest `body_digest` and `entries`, **without** validating
/// the list: `S` is the number of entries, which must fit 16 bits.
///
/// # Errors
/// [`FramingError::TooManyFields`] is never returned; a list of more than 65,535
/// entries gives [`FramingError::FieldTooLong`] with its entry count.
pub fn digest_unvalidated(
    body_digest: &Digest64,
    entries: &[Commitment],
) -> Result<Digest64, FramingError> {
    let size = u16::try_from(entries.len()).map_err(|_| FramingError::FieldTooLong {
        actual: u64::try_from(entries.len()).unwrap_or(u64::MAX),
    })?;
    frame_digest(
        b"PARL/LIST/v1",
        &[
            &P16,
            body_digest.as_bytes(),
            &size.to_le_bytes(),
            &concat(entries),
        ],
    )
}

/// `0xffff` if the two commitments are equal and `0` otherwise, from all 128
/// bytes without a data-dependent branch or early exit.
fn equality_mask(left: &Commitment, right: &Commitment) -> u16 {
    let mut difference = 0u8;
    for (a, b) in left.as_bytes().iter().zip(right.as_bytes()) {
        difference |= a ^ b;
    }
    // 0 -> 0xffff (borrow into the high byte), 1 ..= 255 -> 0x0000.
    let borrow = (u16::from(core::hint::black_box(difference)).wrapping_sub(1)) >> 8;
    0u16.wrapping_sub(borrow & 1)
}

/// A validated sealed list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedList {
    entries: Vec<Commitment>,
}

impl SealedList {
    /// The sealed list with exactly `entries`, in the order given.
    ///
    /// # Errors
    /// As [`validate`]. Entries are never sorted or deduplicated here.
    pub fn new(entries: Vec<Commitment>) -> Result<Self, ListError> {
        validate(&entries)?;
        Ok(Self { entries })
    }

    /// The sealed list of the commitments in `entries`, sorted. For the party
    /// that seals a list.
    ///
    /// # Errors
    /// As [`validate`]; a duplicate is [`ListError::Order`].
    pub fn from_unsorted(mut entries: Vec<Commitment>) -> Result<Self, ListError> {
        entries.sort_unstable();
        Self::new(entries)
    }

    /// The list size `S`.
    pub fn size(&self) -> usize {
        self.entries.len()
    }

    /// The entries, in order.
    pub fn entries(&self) -> &[Commitment] {
        &self.entries
    }

    /// The position of `commitment` in the list, or `None` if it is not an
    /// entry.
    ///
    /// Every entry is public; *which* entry is the caller's own is the voter's
    /// anonymity, so the position is **secret**. The search is a scan of all `S`
    /// entries that compares all 128 bytes of each one with XOR and OR, folds
    /// the position in with masks and has no early exit: its control flow and
    /// its memory accesses depend on `S` only. Whether the commitment is a
    /// member at all is not secret and decides the `Option`. The returned
    /// position is the caller's to protect; it is what [`crate::vote::prove`]
    /// takes.
    pub fn position(&self, commitment: &Commitment) -> Option<u16> {
        let mut found = Zeroizing::new(0u16);
        let mut position = Zeroizing::new(0u16);
        for (index, entry) in (0u16..).zip(&self.entries) {
            let mask = equality_mask(entry, commitment);
            *found |= mask;
            *position |= mask & index;
        }
        // Membership is public; the position stays in the masked value.
        (*found != 0).then_some(*position)
    }

    /// `R` for the body digest `body_digest`.
    ///
    /// # Errors
    /// Only if the frame cannot be built, which a validated list never causes.
    pub fn digest(&self, body_digest: &Digest64) -> Result<Digest64, FramingError> {
        digest_unvalidated(body_digest, &self.entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(tag: u16) -> Commitment {
        let mut bytes = [0u8; COMMITMENT_BYTES];
        bytes[..2].copy_from_slice(&tag.to_be_bytes());
        bytes[127] = 1;
        Commitment(bytes)
    }

    fn entries(count: u16) -> Vec<Commitment> {
        (0..count).map(entry).collect()
    }

    #[test]
    fn the_size_bounds_are_three_and_one_thousand() {
        for count in [0u16, 1, 2, 1001, 2000] {
            assert_eq!(
                validate(&entries(count)),
                Err(ListError::Size {
                    actual: usize::from(count)
                })
            );
            assert_eq!(
                SealedList::new(entries(count)).err(),
                Some(ListError::Size {
                    actual: usize::from(count)
                })
            );
        }
        for count in [3u16, 4, 999, 1000] {
            assert_eq!(validate(&entries(count)), Ok(()));
            assert_eq!(
                SealedList::new(entries(count)).expect("valid").size(),
                usize::from(count)
            );
        }
    }

    #[test]
    fn the_order_is_strict_and_unsigned_bytewise() {
        let mut list = entries(5);
        list.swap(1, 2);
        assert_eq!(validate(&list), Err(ListError::Order { index: 2 }));
        let mut list = entries(5);
        list[4] = list[3];
        assert_eq!(validate(&list), Err(ListError::Order { index: 4 }));
        // 0x7f.. < 0x80..: bytes compare as unsigned.
        let mut low = [0u8; COMMITMENT_BYTES];
        let mut high = [0u8; COMMITMENT_BYTES];
        low[0] = 0x7f;
        high[0] = 0x80;
        let mut top = [0xffu8; COMMITMENT_BYTES];
        assert_eq!(
            validate(&[Commitment(low), Commitment(high), Commitment(top)]),
            Ok(())
        );
        // A difference in the last byte only decides.
        top[127] = 0xfe;
        assert_eq!(
            validate(&[Commitment(low), Commitment([0xff; 128]), Commitment(top)]),
            Err(ListError::Order { index: 2 })
        );
        // Sorting is the sealer's job; duplicates survive sorting and are refused.
        let mut shuffled = entries(6);
        shuffled.reverse();
        assert_eq!(
            SealedList::new(shuffled.clone()).err(),
            Some(ListError::Order { index: 1 })
        );
        let sealed = SealedList::from_unsorted(shuffled).expect("sortable");
        assert_eq!(sealed.entries(), &entries(6)[..]);
        assert_eq!(
            SealedList::from_unsorted(vec![entry(1), entry(2), entry(1)]).err(),
            Some(ListError::Order { index: 1 })
        );
    }

    #[test]
    fn concat_and_split_are_inverse() {
        let list = entries(7);
        let bytes = concat(&list);
        assert_eq!(bytes.len(), 7 * 128);
        assert_eq!(split(&bytes), Ok(list));
        assert_eq!(split(&[]), Ok(Vec::new()));
        assert_eq!(
            split(&bytes[..129]),
            Err(ListError::EntryLength { actual: 129 })
        );
    }

    #[test]
    fn the_digest_is_the_frame_of_the_record() {
        use sha3::Digest;
        let list = SealedList::new(entries(3)).expect("valid");
        let body = Digest64([0x42; 64]);
        let mut frame = b"\x0c\x00PARL/LIST/v1\x04\x00".to_vec();
        frame.extend_from_slice(&16u32.to_le_bytes());
        frame.extend_from_slice(&P16);
        frame.extend_from_slice(&64u32.to_le_bytes());
        frame.extend_from_slice(&[0x42; 64]);
        frame.extend_from_slice(&2u32.to_le_bytes());
        frame.extend_from_slice(&3u16.to_le_bytes());
        frame.extend_from_slice(&384u32.to_le_bytes());
        frame.extend_from_slice(&concat(list.entries()));
        let expected: [u8; 64] = sha3::Sha3_512::digest(&frame).into();
        assert_eq!(list.digest(&body), Ok(Digest64(expected)));
        assert_eq!(
            digest_unvalidated(&body, list.entries()),
            Ok(Digest64(expected))
        );
        // Another body, another order and another size give other digests.
        assert_ne!(list.digest(&Digest64([0x43; 64])), Ok(Digest64(expected)));
        let mut swapped = entries(3);
        swapped.swap(0, 1);
        assert_ne!(digest_unvalidated(&body, &swapped), Ok(Digest64(expected)));
        assert_ne!(
            digest_unvalidated(&body, &entries(4)),
            Ok(Digest64(expected))
        );
        assert_eq!(
            digest_unvalidated(&body, &vec![entry(0); 65_536]),
            Err(FramingError::FieldTooLong { actual: 65_536 })
        );
    }

    #[test]
    fn positions_are_found_by_value_at_the_first_middle_and_last_entry() {
        let list = SealedList::new(entries(100)).expect("valid");
        assert_eq!(list.position(&entry(0)), Some(0));
        assert_eq!(list.position(&entry(57)), Some(57));
        assert_eq!(list.position(&entry(99)), Some(99));
        assert_eq!(list.position(&entry(100)), None);
        // Every position of the largest list, and of the smallest.
        let list = SealedList::new(entries(1000)).expect("valid");
        for tag in 0..1000u16 {
            assert_eq!(list.position(&entry(tag)), Some(tag));
        }
        assert_eq!(list.position(&entry(1000)), None);
        let list = SealedList::new(entries(3)).expect("valid");
        assert_eq!(
            [0u16, 1, 2, 3].map(|tag| list.position(&entry(tag))),
            [Some(0), Some(1), Some(2), None]
        );
    }

    #[test]
    fn an_entry_that_differs_in_one_byte_only_is_not_matched() {
        let list = SealedList::new(entries(10)).expect("valid");
        // Equal to entry 4 in its first 127 bytes.
        let mut near = entry(4);
        near.0[127] ^= 0x80;
        assert_eq!(list.position(&near), None);
        // Equal in its last 127 bytes, and in all but one bit in the middle.
        let mut near = entry(4);
        near.0[0] ^= 1;
        assert_eq!(list.position(&near), None);
        let mut near = entry(4);
        near.0[64] ^= 0x10;
        assert_eq!(list.position(&near), None);
    }

    #[test]
    fn the_equality_mask_is_all_ones_or_zero() {
        let a = entry(7);
        assert_eq!(equality_mask(&a, &a), 0xffff);
        for byte in [0usize, 1, 63, 126, 127] {
            for bit in [0x01u8, 0x80, 0xff] {
                let mut b = a;
                b.0[byte] ^= bit;
                assert_eq!(equality_mask(&a, &b), 0, "byte {byte}");
                assert_eq!(equality_mask(&b, &a), 0, "byte {byte}");
            }
        }
    }
}
