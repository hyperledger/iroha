//! SCCP v1 history accumulator (spec §3.5).
//!
//! Taira keeps an append-only list of every SCCP-bearing block (message count > 0), in height
//! order, with `history_leaf(height, sccp_root, message_count)` leaves. `history_root(size)` is
//! the promote-odd root (§3.4) over the first `size` leaves and `history_root(0)` is zero.
//!
//! The promote-odd tree equals a right-bagged Merkle mountain range: with the perfect-subtree
//! roots `P_a, P_b, …, P_z` of the binary decomposition of `size` (largest first),
//! `root = node(P_a, node(P_b, … node(P_y, P_z)))`. [`HistoryAccumulatorV1`] therefore keeps only
//! the peaks and appends and computes the root in `O(log size)`. Verifiers use
//! [`super::merkle::merkle_root`] with `(leaf_index, history_size)`; `size ≤ 2^32` keeps paths at
//! 32 siblings or fewer.

use super::{
    constants::{MAX_HISTORY_PATH, MAX_HISTORY_SIZE},
    hashes::node,
    merkle::{MerkleError, PromoteOddTree, merkle_root},
};

unit_error! {
    /// History accumulator errors.
    pub enum HistoryError {
        /// The accumulator already holds `2^32` leaves.
        Full => "the SCCP history accumulator holds 2^32 leaves",
        /// The stored peak count does not equal the popcount of the size.
        PeakCountMismatch => "history peaks do not match the binary decomposition of the size",
        /// The size exceeds `2^32`.
        SizeTooLarge => "history size exceeds 2^32",
    }
}

/// Append-only history accumulator kept as right-bagged peaks.
///
/// `peaks[i]` is the root of the `i`-th perfect subtree in the binary decomposition of `size`,
/// largest first; `peaks.len() == size.count_ones()`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct HistoryAccumulatorV1 {
    size: u64,
    peaks: Vec<[u8; 32]>,
}

impl HistoryAccumulatorV1 {
    /// The empty accumulator (`history_root(0) = 0`).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            size: 0,
            peaks: Vec::new(),
        }
    }

    /// Restore an accumulator from stored state.
    ///
    /// # Errors
    ///
    /// Returns [`HistoryError::SizeTooLarge`] for `size > 2^32` and
    /// [`HistoryError::PeakCountMismatch`] unless `peaks.len() == size.count_ones()`.
    pub fn from_parts(size: u64, peaks: Vec<[u8; 32]>) -> Result<Self, HistoryError> {
        Self::validate_parts(size, peaks.len())?;
        Ok(Self { size, peaks })
    }

    /// Build the accumulator over `leaves` by appending them in order.
    ///
    /// # Errors
    ///
    /// Returns [`HistoryError::Full`] beyond `2^32` leaves.
    pub fn from_leaves(leaves: &[[u8; 32]]) -> Result<Self, HistoryError> {
        let mut accumulator = Self::new();
        for leaf in leaves {
            accumulator.append(leaf)?;
        }
        Ok(accumulator)
    }

    /// Number of appended leaves (`history_size`).
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Perfect-subtree roots, largest first.
    #[must_use]
    pub fn peaks(&self) -> &[[u8; 32]] {
        &self.peaks
    }

    /// Append one history leaf in `O(log size)`.
    ///
    /// # Errors
    ///
    /// Returns [`HistoryError::Full`] when `size = 2^32`.
    pub fn append(&mut self, leaf: &[u8; 32]) -> Result<(), HistoryError> {
        if self.size >= MAX_HISTORY_SIZE {
            return Err(HistoryError::Full);
        }
        let mut carry = *leaf;
        let mut height = 0;
        while (self.size >> height) & 1 == 1 {
            let left = self
                .peaks
                .pop()
                .expect("a set size bit always has a stored peak");
            carry = node(&left, &carry);
            height += 1;
        }
        self.peaks.push(carry);
        self.size += 1;
        Ok(())
    }

    /// `history_root(size)`: the right-bagged peaks, or zero when empty.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        Self::root_from_parts(self.size, &self.peaks).expect("owned accumulator invariant")
    }

    /// Read a canonical root from borrowed stored peaks without allocating a second graph.
    ///
    /// # Errors
    /// Rejects a size above `2^32` or a peak count that differs from its popcount.
    pub fn root_from_parts(size: u64, peaks: &[[u8; 32]]) -> Result<[u8; 32], HistoryError> {
        Self::validate_parts(size, peaks.len())?;
        let mut peaks = peaks.iter().rev();
        let Some(last) = peaks.next() else {
            return Ok([0; 32]);
        };
        Ok(peaks.fold(*last, |acc, peak| node(peak, &acc)))
    }
    fn validate_parts(size: u64, peak_count: usize) -> Result<(), HistoryError> {
        if size > MAX_HISTORY_SIZE {
            return Err(HistoryError::SizeTooLarge);
        }
        if peak_count != size.count_ones() as usize {
            return Err(HistoryError::PeakCountMismatch);
        }
        Ok(())
    }
}

/// `history_root` over a full leaf list: the promote-odd root, or zero for no leaves.
///
/// # Errors
///
/// Returns [`HistoryError::SizeTooLarge`] beyond `2^32` leaves.
pub fn history_root(leaves: &[[u8; 32]]) -> Result<[u8; 32], HistoryError> {
    if leaves.len() as u64 > MAX_HISTORY_SIZE {
        return Err(HistoryError::SizeTooLarge);
    }
    Ok(PromoteOddTree::new(leaves).map_or([0; 32], |tree| tree.root()))
}

/// The history path of leaf `index` in the history of `leaves` (all leaves up to the size the
/// verified native finality header names).
///
/// # Errors
///
/// Returns [`MerkleError::Empty`], [`MerkleError::IndexOutOfRange`] or
/// [`MerkleError::TooManyLeaves`] beyond `2^32` leaves.
pub fn history_path(leaves: &[[u8; 32]], index: u64) -> Result<Vec<[u8; 32]>, MerkleError> {
    if leaves.len() as u64 > MAX_HISTORY_SIZE {
        return Err(MerkleError::TooManyLeaves);
    }
    let index = usize::try_from(index).map_err(|_| MerkleError::IndexOutOfRange)?;
    PromoteOddTree::new(leaves)?.path(index)
}

/// Verify that `leaf` is history leaf `index` of the history whose root is `history_root` at
/// `history_size` (§5.1.3 historical mode).
///
/// # Errors
///
/// Returns a [`MerkleError`] for a size above `2^32`, a path longer than 32 siblings, a
/// positional mismatch or a different root.
pub fn verify_history_inclusion(
    leaf: &[u8; 32],
    index: u64,
    history_size: u64,
    path: &[[u8; 32]],
    history_root: &[u8; 32],
) -> Result<(), MerkleError> {
    if history_size > MAX_HISTORY_SIZE {
        return Err(MerkleError::TooManyLeaves);
    }
    if path.len() > MAX_HISTORY_PATH {
        return Err(MerkleError::PathTooLong);
    }
    let computed = merkle_root(leaf, index, history_size, path)?;
    if &computed == history_root {
        Ok(())
    } else {
        Err(MerkleError::RootMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::hashes::history_leaf;

    fn leaves(count: u64) -> Vec<[u8; 32]> {
        (0..count)
            .map(|index| history_leaf(10 + index * 3, &[u8::try_from(index % 251).unwrap(); 32], 1))
            .collect()
    }

    #[test]
    fn accumulator_equals_promote_odd_tree_for_sizes_1_to_40() {
        let all = leaves(40);
        let mut accumulator = HistoryAccumulatorV1::new();
        assert_eq!(accumulator.root(), [0; 32]);
        assert_eq!(history_root(&[]).unwrap(), [0; 32]);
        for size in 1..=40_u64 {
            let len = usize::try_from(size).unwrap();
            accumulator.append(&all[len - 1]).unwrap();
            let prefix = &all[..len];
            assert_eq!(accumulator.size(), size);
            assert_eq!(accumulator.peaks().len(), size.count_ones() as usize);
            assert_eq!(
                accumulator.root(),
                history_root(prefix).unwrap(),
                "size {size}"
            );
            for index in 0..size {
                let path = history_path(prefix, index).unwrap();
                assert!(path.len() <= MAX_HISTORY_PATH);
                verify_history_inclusion(
                    &prefix[usize::try_from(index).unwrap()],
                    index,
                    size,
                    &path,
                    &accumulator.root(),
                )
                .unwrap();
            }
        }
    }

    #[test]
    fn peaks_are_perfect_subtree_roots() {
        let all = leaves(6);
        let accumulator = HistoryAccumulatorV1::from_leaves(&all).unwrap();
        // 6 = 4 + 2
        assert_eq!(
            accumulator.peaks(),
            &[
                node(&node(&all[0], &all[1]), &node(&all[2], &all[3])),
                node(&all[4], &all[5]),
            ]
        );
        assert_eq!(
            accumulator.root(),
            node(&accumulator.peaks()[0], &accumulator.peaks()[1])
        );
    }

    #[test]
    fn from_parts_checks_shape_and_bound() {
        let accumulator = HistoryAccumulatorV1::from_leaves(&leaves(5)).unwrap();
        let restored =
            HistoryAccumulatorV1::from_parts(accumulator.size(), accumulator.peaks().to_vec())
                .unwrap();
        assert_eq!(restored, accumulator);
        assert_eq!(
            HistoryAccumulatorV1::from_parts(5, vec![[0; 32]]),
            Err(HistoryError::PeakCountMismatch)
        );
        assert_eq!(
            HistoryAccumulatorV1::from_parts(MAX_HISTORY_SIZE + 1, vec![[0; 32]; 2]),
            Err(HistoryError::SizeTooLarge)
        );
        let mut full = HistoryAccumulatorV1::from_parts(MAX_HISTORY_SIZE, vec![[7; 32]]).unwrap();
        assert_eq!(full.append(&[1; 32]), Err(HistoryError::Full));
        assert_eq!(full.root(), [7; 32]);
    }

    #[test]
    fn verification_rejects_bad_inputs() {
        let all = leaves(7);
        let accumulator = HistoryAccumulatorV1::from_leaves(&all).unwrap();
        let path = history_path(&all, 3).unwrap();
        assert_eq!(
            verify_history_inclusion(&all[3], 3, 7, &path, &[0; 32]),
            Err(MerkleError::RootMismatch)
        );
        assert_eq!(
            verify_history_inclusion(&all[3], 3, MAX_HISTORY_SIZE + 1, &path, &accumulator.root()),
            Err(MerkleError::TooManyLeaves)
        );
        assert_eq!(
            verify_history_inclusion(&all[3], 3, 7, &[[0; 32]; 33], &accumulator.root()),
            Err(MerkleError::PathTooLong)
        );
        assert_eq!(history_path(&all, 7), Err(MerkleError::IndexOutOfRange));
        assert_eq!(history_path(&[], 0), Err(MerkleError::Empty));
    }
    #[test]
    fn borrowed_root_matches_owned_and_rejects_every_invalid_shape() {
        let mut original = HistoryAccumulatorV1::new();
        let mut leaves = Vec::new();
        for index in 0u64..257 {
            assert_eq!(
                HistoryAccumulatorV1::root_from_parts(original.size(), original.peaks()),
                history_root(&leaves)
            );
            assert_eq!(
                HistoryAccumulatorV1::root_from_parts(original.size(), original.peaks()),
                Ok(original.root())
            );
            let extra = vec![[0; 32]; original.peaks().len() + 1];
            assert_eq!(
                HistoryAccumulatorV1::root_from_parts(original.size(), &extra),
                Err(HistoryError::PeakCountMismatch)
            );
            let leaf = [index.to_le_bytes()[0]; 32];
            original.append(&leaf).unwrap();
            leaves.push(leaf);
        }
        assert_eq!(
            HistoryAccumulatorV1::root_from_parts(MAX_HISTORY_SIZE + 1, &[[0; 32]; 2]),
            Err(HistoryError::SizeTooLarge)
        );
        assert_eq!(HistoryAccumulatorV1::root_from_parts(0, &[]), Ok([0; 32]));
    }
}
