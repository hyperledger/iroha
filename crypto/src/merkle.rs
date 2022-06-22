//! Merkle tree implementation.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};
#[cfg(feature = "std")]
use std::collections::VecDeque;

use iroha_schema::prelude::*;

use crate::HashOf;

/// [Merkle Tree](https://en.wikipedia.org/wiki/Merkle_tree) used to validate `T`
#[derive(Debug)]
pub struct MerkleTree<T>(Vec<Option<HashOf<T>>>);

/// Iterator over leaves of [`MerkleTree`]
pub struct LeafHashIterator<T> {
    tree: MerkleTree<T>,
    next: usize,
}

/// Complete binary trees.
trait CompleteBTree<T> {
    fn len(&self) -> usize;

    fn get(&self, idx: usize) -> Option<&T>;

    /// Get the reference of the `idx`-th leaf node.
    fn get_leaf(&self, idx: usize) -> Option<&T> {
        let offset = 2_usize.pow(self.height()) - 1;
        offset.checked_add(idx).and_then(|i| self.get(i))
    }

    fn height(&self) -> u32 {
        (usize::BITS - self.len().leading_zeros()).saturating_sub(1)
    }

    fn max_nodes_at_height(&self) -> usize {
        2_usize.pow(self.height() + 1) - 1
    }

    fn parent(&self, idx: usize) -> Option<usize> {
        if 0 == idx {
            return None;
        }
        let idx = (idx - 1).div_euclid(2);
        (idx < self.len()).then(|| idx)
    }

    fn l_child(&self, idx: usize) -> Option<usize> {
        let idx = 2 * idx + 1;
        (idx < self.len()).then(|| idx)
    }

    fn r_child(&self, idx: usize) -> Option<usize> {
        let idx = 2 * idx + 2;
        (idx < self.len()).then(|| idx)
    }

    fn get_l_child(&self, idx: usize) -> Option<&T> {
        self.l_child(idx).and_then(|i| self.get(i))
    }

    fn get_r_child(&self, idx: usize) -> Option<&T> {
        self.r_child(idx).and_then(|i| self.get(i))
    }
}

impl<T> CompleteBTree<Option<HashOf<T>>> for MerkleTree<T> {
    fn len(&self) -> usize {
        self.0.len()
    }

    fn get(&self, idx: usize) -> Option<&Option<HashOf<T>>> {
        self.0.get(idx)
    }
}

#[cfg(feature = "std")]
impl<T> FromIterator<HashOf<T>> for MerkleTree<T> {
    fn from_iter<I: IntoIterator<Item = HashOf<T>>>(iter: I) -> Self {
        let mut queue = iter.into_iter().map(Some).collect::<VecDeque<_>>();

        let height = usize::BITS - queue.len().saturating_sub(1).leading_zeros();
        let n_complement = 2_usize.pow(height) - queue.len();
        for _ in 0..n_complement {
            queue.push_back(None);
        }

        let mut tree = Vec::with_capacity(2_usize.pow(height + 1));
        while let Some(r_node) = queue.pop_back() {
            match queue.pop_back() {
                Some(l_node) => {
                    queue.push_front(Self::nodes_pair_hash(&l_node, &r_node));
                    tree.push(r_node);
                    tree.push(l_node);
                }
                None => {
                    tree.push(r_node);
                    break;
                }
            }
        }
        tree.reverse();

        for _ in 0..n_complement {
            tree.pop();
        }

        Self(tree)
    }
}

impl<T> IntoIterator for MerkleTree<T> {
    type Item = HashOf<T>;
    type IntoIter = LeafHashIterator<T>;

    fn into_iter(self) -> Self::IntoIter {
        LeafHashIterator::new(self)
    }
}

impl<T: IntoSchema> IntoSchema for MerkleTree<T> {
    fn type_name() -> String {
        format!("{}::MerkleTree<{}>", module_path!(), T::type_name())
    }
    fn schema(map: &mut MetaMap) {
        map.entry(Self::type_name()).or_insert_with(|| {
            // BFS ordered list of leaf nodes
            Metadata::Vec(VecMeta {
                ty: HashOf::<T>::type_name(),
                sorted: true,
            })
        });
        if !map.contains_key(&HashOf::<T>::type_name()) {
            HashOf::<T>::schema(map);
        }
    }
}

impl<T> Default for MerkleTree<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> MerkleTree<T> {
    /// Construct [`MerkleTree`].
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Get the hash of [`MerkleTree`] as the hash of its root node.
    pub fn hash(&self) -> Option<HashOf<Self>> {
        self.get(0).and_then(|node| node.map(HashOf::transmute))
    }

    /// Get the `idx`-th leaf hash.
    pub fn get_leaf_hash(&self, idx: usize) -> Option<HashOf<T>> {
        if let Some(node) = self.get_leaf(idx) {
            return *node;
        }
        None
    }

    /// Add `hash` to the tail of the tree.
    #[cfg(feature = "std")]
    pub fn add(&mut self, hash: HashOf<T>) {
        // If the tree is perfect, increment its height to double the leaf capacity.
        if self.max_nodes_at_height() == self.len() {
            let mut new_array = vec![None];
            let mut array = self.0.clone();
            for depth in 0..self.height() {
                let capacity_at_depth = 2_usize.pow(depth);
                let tail = array.split_off(capacity_at_depth);
                array.extend([None].iter().cycle().take(capacity_at_depth));
                new_array.append(&mut array);
                array = tail;
            }
            new_array.append(&mut array);
            self.0 = new_array;
        }

        self.0.push(Some(hash));
        self.update(self.len().saturating_sub(1))
    }

    #[cfg(feature = "std")]
    #[allow(clippy::expect_used)]
    fn update(&mut self, idx: usize) {
        let mut node = match self.get(idx) {
            Some(node) => *node,
            None => return,
        };
        let mut idx = idx;
        while let Some(parent_idx) = self.parent(idx) {
            let (l_node, r_node_opt) = match idx % 2 {
                0 => (
                    self.get_l_child(parent_idx).expect("Infallible"),
                    Some(&node),
                ),
                1 => (&node, self.get_r_child(parent_idx)),
                _ => unreachable!(),
            };
            let parent_node = match r_node_opt {
                Some(r_node) => Self::nodes_pair_hash(l_node, r_node),
                None => *l_node,
            };
            let parent_mut = self.0.get_mut(parent_idx).expect("Infallible");
            *parent_mut = parent_node;
            idx = parent_idx;
            node = parent_node;
        }
    }

    #[cfg(feature = "std")]
    fn nodes_pair_hash(
        l_node: &Option<HashOf<T>>,
        r_node: &Option<HashOf<T>>,
    ) -> Option<HashOf<T>> {
        let (l_hash, r_hash) = match (l_node, r_node) {
            (Some(l_hash), Some(r_hash)) => (l_hash, r_hash),
            (Some(l_hash), None) => return Some(*l_hash),
            (None, Some(_)) => unreachable!(),
            (None, None) => return None,
        };
        let sum: Vec<_> = l_hash
            .as_ref()
            .iter()
            .zip(r_hash.as_ref().iter())
            .map(|(l, r)| l.wrapping_add(*r))
            .collect();
        Some(crate::Hash::new(sum).typed())
    }
}

impl<T> Iterator for LeafHashIterator<T> {
    type Item = HashOf<T>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let opt = match self.tree.get(self.next) {
            Some(node) => *node,
            None => return None,
        };
        self.next += 1;
        opt
    }
}

impl<T> LeafHashIterator<T> {
    #[inline]
    fn new(tree: MerkleTree<T>) -> Self {
        let next = 2_usize.pow(tree.height()) - 1;
        Self { tree, next }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Hash;

    fn test_hashes(n_hashes: u8) -> Vec<HashOf<()>> {
        (1..=n_hashes)
            .map(|i| Hash::prehashed([i; Hash::LENGTH]).typed())
            .collect()
    }

    #[test]
    fn construction() {
        let tree = test_hashes(5).into_iter().collect::<MerkleTree<_>>();
        //               #-: iteration order
        //               9b: first 2 hex of hash
        //         ______/\______
        //       #-              #-
        //       0a              05
        //     __/\__          __/\__
        //   #-      #-      #-      #-
        //   fc      17      05      **
        //   /\      /\      /
        // #0  #1  #2  #3  #4
        // 01  02  03  04  05
        assert_eq!(tree.height(), 3);
        assert_eq!(tree.len(), 12);
        assert!(matches!(tree.get(6), Some(None)));
        assert!(matches!(tree.get(11), Some(Some(_))));
        assert!(matches!(tree.get(12), None));
    }

    #[test]
    fn iteration() {
        const N_LEAVES: u8 = 5;

        let hashes = test_hashes(N_LEAVES);
        let tree = hashes.clone().into_iter().collect::<MerkleTree<_>>();

        for i in 0..N_LEAVES as usize * 2 {
            assert_eq!(tree.get_leaf_hash(i).as_ref(), hashes.get(i))
        }
        for (testee_hash, tester_hash) in tree.into_iter().zip(hashes) {
            assert_eq!(testee_hash, tester_hash);
        }
    }

    #[test]
    fn reproduction() {
        const N_LEAVES: u8 = 5;

        let hashes = test_hashes(N_LEAVES);
        let tree = hashes.clone().into_iter().collect::<MerkleTree<_>>();

        let mut tree_reproduced = MerkleTree::new();
        for leaf_hash in hashes {
            tree_reproduced.add(leaf_hash);
        }

        assert_eq!(tree_reproduced.hash(), tree.hash());
        for (testee_leaf, tester_leaf) in tree_reproduced.into_iter().zip(tree.into_iter()) {
            assert_eq!(testee_leaf, tester_leaf);
        }
    }
}
