//! Merkle tree implementation.

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, format, string::String, vec, vec::Vec};
#[cfg(feature = "std")]
use std::collections::VecDeque;

use iroha_schema::prelude::*;

use crate::HashOf;

/// [Merkle Tree](https://en.wikipedia.org/wiki/Merkle_tree) used to validate and prove data at
/// each block height.
/// Our implementation uses binary hash tree.
#[derive(Debug)]
pub struct MerkleTree<T, const HASH_LENGTH: usize> {
    root_node: Node<T, HASH_LENGTH>,
}

impl<T: IntoSchema, const HASH_LENGTH: usize> IntoSchema for MerkleTree<T, HASH_LENGTH> {
    fn type_name() -> String {
        format!("{}::MerkleTree<{}>", module_path!(), T::type_name())
    }
    fn schema(map: &mut MetaMap) {
        map.entry(Self::type_name()).or_insert_with(|| {
            // BFS ordered list of leaf nodes
            Metadata::Vec(VecMeta {
                ty: HashOf::<T, HASH_LENGTH>::type_name(),
                sorted: true,
            })
        });
        if !map.contains_key(&HashOf::<T, HASH_LENGTH>::type_name()) {
            HashOf::<T, HASH_LENGTH>::schema(map);
        }
    }
}

/// Represents subtree rooted by the current node
#[derive(Debug)]
pub struct Subtree<T, const HASH_LENGTH: usize> {
    /// Left subtree
    left: Box<Node<T, HASH_LENGTH>>,
    /// Right subtree
    right: Box<Node<T, HASH_LENGTH>>,
    /// Hash of the node
    hash: HashOf<Node<T, HASH_LENGTH>, HASH_LENGTH>,
}

/// Represents leaf node
#[derive(Debug)]
pub struct Leaf<T, const HASH_LENGTH: usize> {
    /// Hash of the node
    hash: HashOf<T, HASH_LENGTH>,
}

/// Binary Tree's node with possible variants: Subtree, Leaf (with data or links to data) and Empty.
#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
pub enum Node<T, const HASH_LENGTH: usize> {
    /// Node is root of a subtree
    Subtree(Subtree<T, HASH_LENGTH>),
    /// Leaf node
    Leaf(Leaf<T, HASH_LENGTH>),
    /// Empty node
    Empty,
}

#[derive(Debug)]
/// BFS iterator over the Merkle tree
pub struct BreadthFirstIter<'itm, T, const HASH_LENGTH: usize> {
    queue: Vec<&'itm Node<T, HASH_LENGTH>>,
}

#[cfg(feature = "std")]
impl<U, const HASH_LENGTH: usize> FromIterator<HashOf<U, HASH_LENGTH>> for MerkleTree<U, HASH_LENGTH> {
    fn from_iter<T: IntoIterator<Item = HashOf<U, HASH_LENGTH>>>(iter: T) -> Self {
        let mut hashes = iter.into_iter().collect::<Vec<_>>();
        hashes.sort_unstable();
        let mut nodes = hashes
            .into_iter()
            .map(|hash| Node::Leaf(Leaf { hash }))
            .collect::<VecDeque<_>>();
        if nodes.len() % 2 != 0 {
            nodes.push_back(Node::Empty);
        }
        while nodes.len() > 1 {
            if let Some(node_a) = nodes.pop_front() {
                let pop_front = nodes.pop_front();
                nodes.push_back(match pop_front {
                    Some(node_b) => Node::from_nodes(node_a, node_b),
                    None => Node::from_node(node_a),
                });
            }
        }
        Self {
            root_node: nodes.pop_front().unwrap_or(Node::Empty),
        }
    }
}

impl<T, const HASH_LENGTH: usize> MerkleTree<T, HASH_LENGTH> {
    /// Constructs new instance of the merkle tree
    pub const fn new() -> Self {
        MerkleTree {
            root_node: Node::Empty,
        }
    }

    /// Returns leaf node
    pub fn get_leaf(&self, idx: usize) -> Option<HashOf<T, HASH_LENGTH>> {
        self.root_node.get_leaf_inner(idx).ok()
    }

    /// Return the `Hash` of the root node.
    pub const fn root_hash(&self) -> HashOf<Self, HASH_LENGTH> {
        self.root_node.hash().transmute()
    }

    /// Returns BFS iterator over the tree
    pub fn iter(&self) -> BreadthFirstIter<T, HASH_LENGTH> {
        BreadthFirstIter::new(&self.root_node)
    }

    /// Inserts hash into the tree
    #[cfg(feature = "std")]
    #[must_use]
    pub fn add(&self, hash: HashOf<T, HASH_LENGTH>) -> Self {
        self.iter()
            .filter_map(Node::leaf_hash)
            .chain(core::iter::once(hash))
            .collect()
    }
}

impl<T, const HASH_LENGTH: usize> Default for MerkleTree<T, HASH_LENGTH> {
    fn default() -> Self {
        MerkleTree::new()
    }
}

impl<T, const HASH_LENGTH: usize> Node<T, HASH_LENGTH> {
    #[cfg(feature = "std")]
    fn from_nodes(left: Self, right: Self) -> Self {
        Self::Subtree(Subtree {
            hash: Self::nodes_pair_hash(&left, &right),
            left: Box::new(left),
            right: Box::new(right),
        })
    }

    fn get_leaf_inner(&self, idx: usize) -> Result<HashOf<T, HASH_LENGTH>, usize> {
        match self {
            Node::Leaf(Leaf { hash }) if idx == 0 => Ok(*hash),
            Node::Subtree(Subtree { left, right, .. }) => match left.get_leaf_inner(idx) {
                Ok(hash) => Ok(hash),
                Err(seen) => right
                    .get_leaf_inner(idx - seen)
                    .map_err(|index| index + seen),
            },
            Node::Leaf { .. } | Node::Empty => Err(1),
        }
    }

    #[cfg(feature = "std")]
    fn from_node(left: Self) -> Self {
        Self::Subtree(Subtree {
            hash: left.hash(),
            left: Box::new(left),
            right: Box::new(Node::Empty),
        })
    }

    /// Return the `Hash` of the root node.
    pub const fn hash(&self) -> HashOf<Self, HASH_LENGTH> {
        match self {
            Node::Subtree(Subtree { hash, .. }) => *hash,
            Node::Leaf(Leaf { hash }) => (*hash).transmute(),
            Node::Empty => crate::Hash::zeroed().typed(),
        }
    }

    /// Returns leaf node hash
    pub const fn leaf_hash(&self) -> Option<HashOf<T, HASH_LENGTH>> {
        if let Self::Leaf(Leaf { hash }) = *self {
            Some(hash)
        } else {
            None
        }
    }

    #[cfg(feature = "std")]
    fn nodes_pair_hash(left: &Self, right: &Self) -> HashOf<Self, HASH_LENGTH> {
        let left_hash = left.hash();
        let right_hash = right.hash();
        let sum: Vec<_> = left_hash
            .as_ref()
            .iter()
            .zip(right_hash.as_ref().iter())
            .map(|(l, r)| l.saturating_add(*r))
            .collect();
        crate::Hash::new(sum).typed()
    }
}

impl<'itm, T, const HASH_LENGTH: usize> BreadthFirstIter<'itm, T, HASH_LENGTH> {
    fn new(root_node: &'itm Node<T, HASH_LENGTH>) -> Self {
        BreadthFirstIter {
            queue: vec![root_node],
        }
    }
}

/// `Iterator` impl for `BreadthFirstIter` case of iteration over `MerkleTree`.
/// `'a` lifetime specified for `Node`. Because `Node` is recursive data structure with self
/// composition in case of `Node::Subtree` we use `Box` to know size of each `Node` object in
/// memory.
impl<'itm, T, const HASH_LENGTH: usize> Iterator for BreadthFirstIter<'itm, T, HASH_LENGTH> {
    type Item = &'itm Node<T, HASH_LENGTH>;

    fn next(&mut self) -> Option<Self::Item> {
        match &self.queue.pop() {
            Some(node) => {
                if let Node::Subtree(Subtree { left, right, .. }) = *node {
                    self.queue.push(&*left);
                    self.queue.push(&*right);
                }
                Some(node)
            }
            None => None,
        }
    }
}

impl<'itm, T, const HASH_LENGTH: usize> IntoIterator for &'itm MerkleTree<T, HASH_LENGTH> {
    type Item = &'itm Node<T, HASH_LENGTH>;
    type IntoIter = BreadthFirstIter<'itm, T, HASH_LENGTH>;

    fn into_iter(self) -> Self::IntoIter {
        BreadthFirstIter::new(&self.root_node)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Hash;
    
    const HASH_LENGTH: usize = 32;

    #[test]
    fn tree_with_two_layers_should_reach_all_nodes() {
        let tree = MerkleTree::<(), HASH_LENGTH> {
            root_node: Node::Subtree(Subtree {
                left: Box::new(Node::Leaf(Leaf {
                    hash: Hash::prehashed([1; HASH_LENGTH]).typed(),
                })),
                right: Box::new(Node::Leaf(Leaf {
                    hash: Hash::prehashed([2; HASH_LENGTH]).typed(),
                })),
                hash: Hash::prehashed([3; HASH_LENGTH]).typed(),
            }),
        };
        assert_eq!(3, tree.into_iter().count());
    }

    fn get_hashes(hash: [u8; HASH_LENGTH]) -> impl Iterator<Item = HashOf<(), HASH_LENGTH>> {
        let hash = Hash::prehashed(hash).typed();
        std::iter::repeat_with(move || hash)
    }

    #[test]
    fn four_hashes_should_built_seven_nodes() {
        let merkle_tree = get_hashes([1_u8; HASH_LENGTH])
            .take(4)
            .collect::<MerkleTree<_, HASH_LENGTH>>();
        assert_eq!(7, merkle_tree.into_iter().count());
    }

    #[test]
    fn three_hashes_should_built_seven_nodes() {
        let merkle_tree = get_hashes([1_u8; HASH_LENGTH])
            .take(3)
            .collect::<MerkleTree<_, HASH_LENGTH>>();
        assert_eq!(7, merkle_tree.into_iter().count());
    }

    #[test]
    fn same_root_hash_for_same_hashes() {
        let merkle_tree_1 = [
            Hash::prehashed([1_u8; HASH_LENGTH]),
            Hash::prehashed([2_u8; HASH_LENGTH]),
            Hash::prehashed([3_u8; HASH_LENGTH]),
        ]
        .into_iter()
        .map(Hash::typed)
        .collect::<MerkleTree<(), HASH_LENGTH>>();
        let merkle_tree_2 = [
            Hash::prehashed([2_u8; HASH_LENGTH]),
            Hash::prehashed([1_u8; HASH_LENGTH]),
            Hash::prehashed([3_u8; HASH_LENGTH]),
        ]
        .into_iter()
        .map(Hash::typed)
        .collect::<MerkleTree<(), HASH_LENGTH>>();
        assert_eq!(merkle_tree_1.root_hash(), merkle_tree_2.root_hash());
    }

    #[test]
    fn different_root_hash_for_different_hashes() {
        let merkle_tree_1 = [
            Hash::prehashed([1_u8; HASH_LENGTH]),
            Hash::prehashed([2_u8; HASH_LENGTH]),
            Hash::prehashed([3_u8; HASH_LENGTH]),
        ]
        .into_iter()
        .map(Hash::typed)
        .collect::<MerkleTree<(), HASH_LENGTH>>();
        let merkle_tree_2 = [
            Hash::prehashed([1_u8; HASH_LENGTH]),
            Hash::prehashed([4_u8; HASH_LENGTH]),
            Hash::prehashed([5_u8; HASH_LENGTH]),
        ]
        .into_iter()
        .map(Hash::typed)
        .collect::<MerkleTree<(), HASH_LENGTH>>();
        assert_ne!(merkle_tree_1.root_hash(), merkle_tree_2.root_hash());
    }

    #[test]
    fn get_leaf() {
        let hash1 = Hash::prehashed([1; HASH_LENGTH]).typed();
        let hash2 = Hash::prehashed([2; HASH_LENGTH]).typed();
        let hash3 = Hash::prehashed([3; HASH_LENGTH]).typed();
        assert!(hash1 < hash2 && hash2 < hash3);

        let tree = [hash1, hash2, hash3]
            .into_iter()
            .collect::<MerkleTree<(), HASH_LENGTH>>();
        assert_eq!(tree.get_leaf(0), Some(hash1));
        assert_eq!(tree.get_leaf(1), Some(hash2));
        assert_eq!(tree.get_leaf(2), Some(hash3));
        assert_eq!(tree.get_leaf(3), None);
    }

    #[test]
    fn add() {
        let hash1 = Hash::prehashed([1; HASH_LENGTH]).typed();
        let hash2 = Hash::prehashed([2; HASH_LENGTH]).typed();
        let hash3 = Hash::prehashed([3; HASH_LENGTH]).typed();
        let hash4 = Hash::prehashed([4; HASH_LENGTH]).typed();
        assert!(hash1 < hash2 && hash2 < hash3 && hash3 < hash4);

        let tree = [hash1, hash2, hash4]
            .into_iter()
            .collect::<MerkleTree<(), HASH_LENGTH>>();
        let tree = tree.add(hash3);
        assert_eq!(tree.get_leaf(0), Some(hash1));
        assert_eq!(tree.get_leaf(1), Some(hash2));
        assert_eq!(tree.get_leaf(2), Some(hash3));
        assert_eq!(tree.get_leaf(3), Some(hash4));
        assert_eq!(tree.get_leaf(4), None);
    }
}
