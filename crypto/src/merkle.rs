//! Merkle tree implementation.

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, collections::vec_deque::VecDeque, format, string::String, vec};
#[cfg(feature = "std")]
use std::collections::VecDeque;

use iroha_schema::prelude::*;

use crate::HashOf;

/// [Merkle Tree](https://en.wikipedia.org/wiki/Merkle_tree) used to validate and prove data at
/// each block height. Implemented as a binary hash tree.
#[derive(Debug)]
pub struct MerkleTree<T> {
    root_node: Node<T>,
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

/// Represents a subtree rooted by the current node.
#[derive(Debug)]
struct Subtree<T> {
    /// Left child node.
    left: Box<Node<T>>,
    /// Right child node.
    right: Box<Node<T>>,
    /// Hash of this node.
    hash: HashOf<Node<T>>,
}

/// Represents a leaf node.
#[derive(Debug)]
struct Leaf<T> {
    /// Hash of this node.
    hash: HashOf<T>,
}

/// Binary tree node: [`Subtree`], [`Leaf`] (with data or links to data), or `Empty`.
#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
enum Node<T> {
    /// [`Subtree`] node.
    Subtree(Subtree<T>),
    /// [`Leaf`] node.
    Leaf(Leaf<T>),
    /// Empty node.
    Empty,
}

#[derive(Debug)]
/// BFS iterator over [`MerkleTree`].
struct BreadthFirstIter<'itm, T> {
    queue: VecDeque<&'itm Node<T>>,
}

#[cfg(feature = "std")]
impl<T> FromIterator<HashOf<T>> for MerkleTree<T> {
    fn from_iter<I: IntoIterator<Item = HashOf<T>>>(iter: I) -> Self {
        let mut nodes = iter
            .into_iter()
            .map(|hash| Node::Leaf(Leaf { hash }))
            .collect::<VecDeque<_>>();
        nodes.make_contiguous().sort_unstable_by_key(Node::hash);

        let n_leaves = nodes.len();
        let mut base_len = 0;
        for depth in 0.. {
            base_len = 2_usize.pow(depth);
            if n_leaves <= base_len {
                break;
            }
        }
        for _ in n_leaves..base_len {
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

impl<T> MerkleTree<T> {
    /// Construct [`MerkleTree`].
    pub const fn new() -> Self {
        MerkleTree {
            root_node: Node::Empty,
        }
    }

    /// Get the hash of the `idx`-th leaf node.
    pub fn get_leaf(&self, idx: usize) -> Option<HashOf<T>> {
        self.leaves().nth(idx)
    }

    /// Get the hashes of the leaf nodes.
    pub fn leaves(&self) -> impl Iterator<Item = HashOf<T>> + '_ {
        self.iter().filter_map(Node::leaf_hash)
    }

    /// Get the hash of the root node.
    pub const fn root_hash(&self) -> HashOf<Self> {
        self.root_node.hash().transmute()
    }

    /// Get a BFS iterator over the tree.
    fn iter(&self) -> BreadthFirstIter<T> {
        BreadthFirstIter::new(&self.root_node)
    }

    /// Insert `hash` into the tree.
    #[cfg(feature = "std")]
    #[must_use]
    pub fn add(&self, hash: HashOf<T>) -> Self {
        self.leaves().chain(core::iter::once(hash)).collect()
    }
}

impl<T> Default for MerkleTree<T> {
    fn default() -> Self {
        MerkleTree::new()
    }
}

impl<T> Node<T> {
    #[cfg(feature = "std")]
    fn from_nodes(left: Self, right: Self) -> Self {
        Self::Subtree(Subtree {
            hash: Self::nodes_pair_hash(&left, &right),
            left: Box::new(left),
            right: Box::new(right),
        })
    }

    #[cfg(feature = "std")]
    fn from_node(left: Self) -> Self {
        Self::Subtree(Subtree {
            hash: left.hash(),
            left: Box::new(left),
            right: Box::new(Node::Empty),
        })
    }

    /// Get the hash of this node.
    const fn hash(&self) -> HashOf<Self> {
        match self {
            Node::Subtree(Subtree { hash, .. }) => *hash,
            Node::Leaf(Leaf { hash }) => (*hash).transmute(),
            Node::Empty => crate::Hash::zeroed().typed(),
        }
    }

    /// Get the hash of this node as a leaf.
    const fn leaf_hash(&self) -> Option<HashOf<T>> {
        if let Self::Leaf(Leaf { hash }) = *self {
            Some(hash)
        } else {
            None
        }
    }

    #[cfg(feature = "std")]
    fn nodes_pair_hash(left: &Self, right: &Self) -> HashOf<Self> {
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

    fn children(&self) -> Option<[&Self; 2]> {
        if let Node::Subtree(subtree) = self {
            return Some([&*subtree.left, &*subtree.right]);
        }
        None
    }
}

impl<'itm, T> BreadthFirstIter<'itm, T> {
    #[inline]
    fn new(root: &'itm Node<T>) -> Self {
        Self {
            queue: VecDeque::from(vec![root]),
        }
    }
}

/// `Iterator` impl for `BreadthFirstIter` case of iteration over `MerkleTree`.
/// `'itm` lifetime specified for `Node`. Because `Node` is recursive data structure with self
/// composition in case of `Node::Subtree` we use `Box` to know size of each `Node` object in
/// memory.
impl<'itm, T> Iterator for BreadthFirstIter<'itm, T> {
    type Item = &'itm Node<T>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(node) = self.queue.pop_front() {
            if let Some(children) = node.children() {
                self.queue.extend(children);
            }
            Some(node)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Hash;

    #[test]
    fn tree_with_two_layers_should_reach_all_nodes() {
        let tree = MerkleTree::<()> {
            root_node: Node::Subtree(Subtree {
                left: Box::new(Node::Leaf(Leaf {
                    hash: Hash::prehashed([1; Hash::LENGTH]).typed(),
                })),
                right: Box::new(Node::Leaf(Leaf {
                    hash: Hash::prehashed([2; Hash::LENGTH]).typed(),
                })),
                hash: Hash::prehashed([3; Hash::LENGTH]).typed(),
            }),
        };
        assert_eq!(3, tree.iter().count());
    }

    fn get_hashes(hash: [u8; Hash::LENGTH]) -> impl Iterator<Item = HashOf<()>> {
        let hash = Hash::prehashed(hash).typed();
        std::iter::repeat_with(move || hash)
    }

    #[test]
    fn four_hashes_should_built_seven_nodes() {
        let merkle_tree = get_hashes([1_u8; Hash::LENGTH])
            .take(4)
            .collect::<MerkleTree<_>>();
        assert_eq!(7, merkle_tree.iter().count());
    }

    #[test]
    fn three_hashes_should_built_seven_nodes() {
        let merkle_tree = get_hashes([1_u8; Hash::LENGTH])
            .take(3)
            .collect::<MerkleTree<_>>();
        assert_eq!(7, merkle_tree.iter().count());
    }

    #[test]
    fn same_root_hash_for_same_hashes() {
        let merkle_tree_1 = [
            Hash::prehashed([1_u8; Hash::LENGTH]),
            Hash::prehashed([2_u8; Hash::LENGTH]),
            Hash::prehashed([3_u8; Hash::LENGTH]),
        ]
        .into_iter()
        .map(Hash::typed)
        .collect::<MerkleTree<()>>();
        let merkle_tree_2 = [
            Hash::prehashed([2_u8; Hash::LENGTH]),
            Hash::prehashed([1_u8; Hash::LENGTH]),
            Hash::prehashed([3_u8; Hash::LENGTH]),
        ]
        .into_iter()
        .map(Hash::typed)
        .collect::<MerkleTree<()>>();
        assert_eq!(merkle_tree_1.root_hash(), merkle_tree_2.root_hash());
    }

    #[test]
    fn different_root_hash_for_different_hashes() {
        let merkle_tree_1 = [
            Hash::prehashed([1_u8; Hash::LENGTH]),
            Hash::prehashed([2_u8; Hash::LENGTH]),
            Hash::prehashed([3_u8; Hash::LENGTH]),
        ]
        .into_iter()
        .map(Hash::typed)
        .collect::<MerkleTree<()>>();
        let merkle_tree_2 = [
            Hash::prehashed([1_u8; Hash::LENGTH]),
            Hash::prehashed([4_u8; Hash::LENGTH]),
            Hash::prehashed([5_u8; Hash::LENGTH]),
        ]
        .into_iter()
        .map(Hash::typed)
        .collect::<MerkleTree<()>>();
        assert_ne!(merkle_tree_1.root_hash(), merkle_tree_2.root_hash());
    }

    #[test]
    fn get_leaf() {
        let hash1 = Hash::prehashed([1; Hash::LENGTH]).typed();
        let hash2 = Hash::prehashed([2; Hash::LENGTH]).typed();
        let hash3 = Hash::prehashed([3; Hash::LENGTH]).typed();
        let hash4 = Hash::prehashed([4; Hash::LENGTH]).typed();
        let hash5 = Hash::prehashed([5; Hash::LENGTH]).typed();
        assert!(hash1 < hash2 && hash2 < hash3);

        let tree = [hash1, hash2, hash3, hash4, hash5]
            .into_iter()
            .collect::<MerkleTree<()>>();
        assert_eq!(tree.get_leaf(0), Some(hash1));
        assert_eq!(tree.get_leaf(1), Some(hash2));
        assert_eq!(tree.get_leaf(2), Some(hash3));
        assert_eq!(tree.get_leaf(3), Some(hash4));
        assert_eq!(tree.get_leaf(4), Some(hash5));
        assert_eq!(tree.get_leaf(5), None);
    }

    #[test]
    fn add() {
        let hash1 = Hash::prehashed([1; Hash::LENGTH]).typed();
        let hash2 = Hash::prehashed([2; Hash::LENGTH]).typed();
        let hash3 = Hash::prehashed([3; Hash::LENGTH]).typed();
        let hash4 = Hash::prehashed([4; Hash::LENGTH]).typed();
        let hash5 = Hash::prehashed([5; Hash::LENGTH]).typed();
        assert!(hash1 < hash2 && hash2 < hash3 && hash3 < hash4);

        let tree = [hash1, hash2, hash4, hash5]
            .into_iter()
            .collect::<MerkleTree<()>>();
        let tree = tree.add(hash3);
        assert_eq!(tree.get_leaf(0), Some(hash1));
        assert_eq!(tree.get_leaf(1), Some(hash2));
        assert_eq!(tree.get_leaf(2), Some(hash3));
        assert_eq!(tree.get_leaf(3), Some(hash4));
        assert_eq!(tree.get_leaf(4), Some(hash5));
        assert_eq!(tree.get_leaf(5), None);
    }

    impl<T> MerkleTree<T> {
        fn size(&self) -> usize {
            self.iter().count()
        }

        fn depth(&self) -> u32 {
            usize::BITS - self.size().leading_zeros()
        }

        fn leaves_start_at(&self) -> Option<usize> {
            self.depth().checked_sub(1).map(|x| 2_usize.pow(x) - 1)
        }
    }

    fn test_hashes(n_hashes: u8) -> Vec<HashOf<()>> {
        (1..=n_hashes)
            .map(|i| Hash::prehashed([i; Hash::LENGTH]).typed())
            .collect()
    }

    #[test]
    fn geometry() {
        let tree = test_hashes(5).into_iter().collect::<MerkleTree<_>>();
        //               #0: iteration order
        //               e4: first 2 hex of hash
        //         ______/\______
        //       #1              #2
        //       c0              c1
        //     __/\__          __/\__
        //   #3      #4      #5      #6
        //   fc      17      f6      89
        //   /\      /\      /\      /\
        // #7  #8  #9  #a  #b  #c  #d  #e
        // 01  02  03  04  05  00  00  00
        assert_eq!(tree.size(), 15);
        assert_eq!(tree.depth(), 4);
        assert_eq!(tree.leaves_start_at(), Some(7));
    }

    #[test]
    fn leaves() {
        const N_LEAVES: u8 = 5;

        let hashes = test_hashes(N_LEAVES);
        let tree = hashes.clone().into_iter().collect::<MerkleTree<_>>();

        for (testee_hash, tester_hash) in tree.leaves().zip(hashes) {
            assert_eq!(testee_hash, tester_hash);
        }
    }

    #[test]
    fn reconstruction() {
        const N_LEAVES: u8 = 5;

        let tree = test_hashes(N_LEAVES).into_iter().collect::<MerkleTree<_>>();
        let tree_reconstructed = tree.leaves().collect::<MerkleTree<_>>();

        for (testee_node, tester_node) in tree_reconstructed.iter().zip(tree.iter()) {
            assert_eq!(testee_node.hash(), tester_node.hash());
        }
    }
}
