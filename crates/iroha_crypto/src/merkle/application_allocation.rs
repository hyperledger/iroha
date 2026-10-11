//! One fallible, premeasurable node allocation for canonical application trees.

use super::{HashOf, MerkleError, MerkleHashScheme, MerkleTree};

impl<T> MerkleTree<T> {
    /// Requested node backing for an exact number of typed application leaves.
    ///
    /// This includes every cached parent and ragged-edge padding. Callers can
    /// reserve the complete scratch backing before hashing or allocating.
    ///
    /// # Errors
    /// Refuses an overflowing or unaddressable node layout.
    pub fn application_node_allocation_bytes(leaf_count: usize) -> Result<usize, MerkleError> {
        let count = Self::application_node_count(leaf_count)?;
        std::alloc::Layout::array::<Option<HashOf<T>>>(count)
            .map(|layout| layout.size())
            .map_err(|_| MerkleError::AllocationUnavailable)
    }

    fn application_node_count(leaf_count: usize) -> Result<usize, MerkleError> {
        if leaf_count == 0 {
            return Ok(0);
        }
        leaf_count
            .checked_next_power_of_two()
            .and_then(|slots| slots.checked_sub(1))
            .and_then(|parents| parents.checked_add(leaf_count))
            .ok_or(MerkleError::AllocationUnavailable)
    }

    /// Build a canonical application tree in one fixed, fallible backing.
    ///
    /// The ordinary application leaf/internal domains and ragged promotion are
    /// reused exactly. No temporary leaf queue or second node array is created.
    /// The iterator's promised size is checked before writing beyond the backing.
    ///
    /// # Errors
    /// Refuses an overflowing layout, allocation failure or false iterator length.
    pub fn try_from_typed_leaves<I>(mut leaves: I) -> Result<Self, MerkleError>
    where
        I: ExactSizeIterator<Item = HashOf<T>>,
    {
        let leaf_count = leaves.len();
        Self::application_node_allocation_bytes(leaf_count)?;
        let count = Self::application_node_count(leaf_count)?;
        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(count)
            .map_err(|_| MerkleError::AllocationUnavailable)?;
        nodes.resize(count, None);
        let offset = count - leaf_count;
        for slot in &mut nodes[offset..] {
            let leaf = leaves.next().ok_or_else(|| {
                MerkleError::InvalidLayout(
                    "application leaf iterator was shorter than declared".into(),
                )
            })?;
            *slot = Some(Self::leaf_hash(&leaf));
        }
        if leaves.next().is_some() {
            return Err(MerkleError::InvalidLayout(
                "application leaf iterator was longer than declared".into(),
            ));
        }
        for parent in (0..offset).rev() {
            let left = nodes.get((parent << 1) + 1).and_then(Option::as_ref);
            let right = nodes.get((parent << 1) + 2).and_then(Option::as_ref);
            nodes[parent] = Self::pair_hash(left, right);
        }
        Ok(Self {
            hash_scheme: MerkleHashScheme::ApplicationV1,
            nodes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Hash;

    #[test]
    fn fixed_application_backing_preserves_every_root_count_and_path() {
        for count in 0..=129 {
            let leaves = (0_u64..count)
                .map(|index| HashOf::<u64>::from_untyped_unchecked(Hash::new(index.to_le_bytes())))
                .collect::<Vec<_>>();
            let ordinary = leaves.iter().copied().collect::<MerkleTree<_>>();
            let fixed = MerkleTree::try_from_typed_leaves(leaves.iter().copied()).unwrap();
            assert_eq!(fixed, ordinary);
            assert_eq!(fixed.commitment(), ordinary.commitment());
            assert_eq!(
                fixed.allocated_bytes(),
                MerkleTree::<u64>::application_node_allocation_bytes(
                    usize::try_from(count).unwrap()
                )
                .unwrap()
            );
            for (index, leaf) in leaves.iter().enumerate() {
                let index = u32::try_from(index).unwrap();
                let proof = fixed.get_proof(index).unwrap();
                assert_eq!(Some(proof.clone()), ordinary.get_proof(index));
                assert!(proof.verify(leaf, &fixed.commitment().unwrap()));
            }
        }
        assert!(MerkleTree::<u64>::application_node_allocation_bytes(usize::MAX).is_err());
    }

    struct Miscounted {
        actual: std::vec::IntoIter<HashOf<u64>>,
        claimed: usize,
    }
    impl Iterator for Miscounted {
        type Item = HashOf<u64>;
        fn next(&mut self) -> Option<Self::Item> {
            self.actual.next()
        }
        fn size_hint(&self) -> (usize, Option<usize>) {
            (self.claimed, Some(self.claimed))
        }
    }
    impl ExactSizeIterator for Miscounted {}

    #[test]
    fn fixed_application_backing_rejects_false_iterator_geometry() {
        let leaf = HashOf::<u64>::from_untyped_unchecked(Hash::new(b"leaf"));
        for (actual, claimed) in [(0, 1), (1, 0), (1, 2), (2, 1)] {
            assert!(
                MerkleTree::try_from_typed_leaves(Miscounted {
                    actual: vec![leaf; actual].into_iter(),
                    claimed,
                })
                .is_err()
            );
        }
    }
}
