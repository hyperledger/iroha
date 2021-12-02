//! Merkle tree implementation

use std::collections::VecDeque;

use iroha_crypto::{Hash, HashOf};

/// [Merkle Tree](https://en.wikipedia.org/wiki/Merkle_tree) used to validate and prove data at
/// each block height.
/// Our implementation uses binary hash tree.
#[derive(Debug)]
pub struct MerkleTree<T> {
    root_node: Node<T>,
}

/// Binary Tree's node with possible variants: Subtree, Leaf (with data or links to data) and Empty.
#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
pub enum Node<T> {
    /// Node is root of a subtree
    Subtree {
        /// Left subtree
        left: Box<Self>,
        /// Right subtree
        right: Box<Self>,
        /// Hash of the node
        hash: HashOf<Self>,
    },
    /// Leaf node
    Leaf {
        /// Hash of the node
        hash: HashOf<T>,
    },
    /// Empty node
    Empty,
}

#[derive(Debug)]
/// BFS iterator over the Merkle tree
pub struct BreadthFirstIter<'a, T> {
    queue: Vec<&'a Node<T>>,
}

impl<U> FromIterator<HashOf<U>> for MerkleTree<U> {
    fn from_iter<T: IntoIterator<Item = HashOf<U>>>(iter: T) -> Self {
        let mut hashes = iter.into_iter().collect::<Vec<_>>();
        hashes.sort_unstable();
        let mut nodes = hashes
            .into_iter()
            .map(|hash| Node::Leaf { hash })
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

impl<T> MerkleTree<T> {
    /// Constructs new instance of the merkle tree
    pub const fn new() -> Self {
        MerkleTree {
            root_node: Node::Empty,
        }
    }

    /// Returns leaf node
    pub fn get_leaf(&self, idx: usize) -> Option<HashOf<T>> {
        self.root_node.get_leaf_inner(idx).ok()
    }

    /// Return the `Hash` of the root node.
    pub fn root_hash(&self) -> HashOf<Self> {
        self.root_node.hash().transmute()
    }

    /// Returns BFS iterator over the tree
    pub fn iter(&self) -> BreadthFirstIter<T> {
        BreadthFirstIter::new(&self.root_node)
    }

    /// Inserts hash into the tree
    pub fn add(&self, hash: HashOf<T>) -> Self {
        self.iter()
            .filter_map(Node::leaf_hash)
            .chain(std::iter::once(hash))
            .collect()
    }
}

impl<T> Default for MerkleTree<T> {
    fn default() -> Self {
        MerkleTree::new()
    }
}

impl<T> Node<T> {
    fn from_nodes(left: Self, right: Self) -> Self {
        Self::Subtree {
            hash: Self::nodes_pair_hash(&left, &right),
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    fn get_leaf_inner(&self, idx: usize) -> Result<HashOf<T>, usize> {
        use Node::*;

        match self {
            Leaf { hash } if idx == 0 => Ok(*hash),
            Subtree { left, right, .. } => match left.get_leaf_inner(idx) {
                Ok(hash) => Ok(hash),
                Err(seen) => right
                    .get_leaf_inner(idx - seen)
                    .map_err(|index| index + seen),
            },
            Leaf { .. } | Empty => Err(1),
        }
    }

    fn from_node(left: Self) -> Self {
        Self::Subtree {
            hash: left.hash(),
            left: Box::new(left),
            right: Box::new(Node::Empty),
        }
    }

    /// Return the `Hash` of the root node.
    pub fn hash(&self) -> HashOf<Self> {
        use Node::*;
        match self {
            Subtree { hash, .. } => *hash,
            Leaf { hash } => (*hash).transmute(),
            Empty => HashOf::from_hash(Hash([0; 32])),
        }
    }

    /// Returns leaf node hash
    pub const fn leaf_hash(&self) -> Option<HashOf<T>> {
        if let Self::Leaf { hash } = *self {
            Some(hash)
        } else {
            None
        }
    }

    fn nodes_pair_hash(left: &Self, right: &Self) -> HashOf<Self> {
        let left_hash = left.hash();
        let right_hash = right.hash();
        let sum: Vec<_> = left_hash
            .as_ref()
            .iter()
            .zip(right_hash.as_ref().iter())
            .map(|(l, r)| l.saturating_add(*r))
            .take(32)
            .collect();
        HashOf::from_hash(Hash::new(&sum))
    }
}

impl<'a, T> BreadthFirstIter<'a, T> {
    fn new(root_node: &'a Node<T>) -> Self {
        BreadthFirstIter {
            queue: vec![root_node],
        }
    }
}

/// `Iterator` impl for `BreadthFirstIter` case of iteration over `MerkleTree`.
/// `'a` lifetime specified for `Node`. Because `Node` is recursive data structure with self
/// composition in case of `Node::Subtree` we use `Box` to know size of each `Node` object in
/// memory.
impl<'a, T> Iterator for BreadthFirstIter<'a, T> {
    type Item = &'a Node<T>;

    fn next(&mut self) -> Option<Self::Item> {
        match &self.queue.pop() {
            Some(node) => {
                if let Node::Subtree { left, right, .. } = *node {
                    self.queue.push(&*left);
                    self.queue.push(&*right);
                }
                Some(node)
            }
            None => None,
        }
    }
}

impl<'a, T> IntoIterator for &'a MerkleTree<T> {
    type Item = &'a Node<T>;
    type IntoIter = BreadthFirstIter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        BreadthFirstIter::new(&self.root_node)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_with_two_layers_should_reach_all_nodes() {
        let tree = MerkleTree {
            root_node: Node::Subtree {
                left: Box::new(Node::Leaf {
                    hash: HashOf::<()>::from_hash(Hash([0; 32])),
                }),
                right: Box::new(Node::Leaf {
                    hash: HashOf::from_hash(Hash([0; 32])),
                }),
                hash: HashOf::from_hash(Hash([0; 32])),
            },
        };
        assert_eq!(3, tree.into_iter().count());
    }

    fn get_hashes(hash: Hash) -> impl Iterator<Item = HashOf<()>> {
        let hash = HashOf::<()>::from_hash(hash);
        std::iter::repeat_with(move || hash)
    }

    #[test]
    fn four_hashes_should_built_seven_nodes() {
        let merkle_tree = get_hashes(Hash([1_u8; 32]))
            .take(4)
            .collect::<MerkleTree<_>>();
        assert_eq!(7, merkle_tree.into_iter().count());
    }

    #[test]
    fn three_hashes_should_built_seven_nodes() {
        let merkle_tree = get_hashes(Hash([1_u8; 32]))
            .take(3)
            .collect::<MerkleTree<_>>();
        assert_eq!(7, merkle_tree.into_iter().count());
    }

    #[test]
    fn same_root_hash_for_same_hashes() {
        let merkle_tree_1 = vec![
            HashOf::<()>::from_hash(Hash([1_u8; 32])),
            HashOf::from_hash(Hash([2_u8; 32])),
            HashOf::from_hash(Hash([3_u8; 32])),
        ]
        .into_iter()
        .collect::<MerkleTree<_>>();
        let merkle_tree_2 = vec![
            HashOf::<()>::from_hash(Hash([2_u8; 32])),
            HashOf::from_hash(Hash([1_u8; 32])),
            HashOf::from_hash(Hash([3_u8; 32])),
        ]
        .into_iter()
        .collect::<MerkleTree<_>>();
        assert_eq!(merkle_tree_1.root_hash(), merkle_tree_2.root_hash());
    }

    #[test]
    fn different_root_hash_for_different_hashes() {
        let merkle_tree_1 = vec![
            HashOf::<()>::from_hash(Hash([1_u8; 32])),
            HashOf::from_hash(Hash([2_u8; 32])),
            HashOf::from_hash(Hash([3_u8; 32])),
        ]
        .into_iter()
        .collect::<MerkleTree<_>>();
        let merkle_tree_2 = vec![
            HashOf::<()>::from_hash(Hash([1_u8; 32])),
            HashOf::from_hash(Hash([4_u8; 32])),
            HashOf::from_hash(Hash([5_u8; 32])),
        ]
        .into_iter()
        .collect::<MerkleTree<_>>();
        assert_ne!(merkle_tree_1.root_hash(), merkle_tree_2.root_hash());
    }

    #[test]
    fn get_leaf() {
        let tree = vec![
            HashOf::<()>::from_hash(Hash([1; 32])),
            HashOf::from_hash(Hash([2; 32])),
            HashOf::from_hash(Hash([3; 32])),
        ]
        .into_iter()
        .collect::<MerkleTree<_>>();
        assert_eq!(tree.get_leaf(0), Some(HashOf::from_hash(Hash([1; 32]))));
        assert_eq!(tree.get_leaf(1), Some(HashOf::from_hash(Hash([2; 32]))));
        assert_eq!(tree.get_leaf(2), Some(HashOf::from_hash(Hash([3; 32]))));
        assert_eq!(tree.get_leaf(3), None);
    }

    #[test]
    fn add() {
        let tree = vec![Hash([1_u8; 32]), Hash([2_u8; 32]), Hash([4_u8; 32])]
            .into_iter()
            .map(HashOf::<()>::from_hash)
            .collect::<MerkleTree<_>>();
        let tree = tree.add(HashOf::from_hash(Hash([3_u8; 32])));
        assert_eq!(tree.get_leaf(0), Some(HashOf::from_hash(Hash([1; 32]))));
        assert_eq!(tree.get_leaf(1), Some(HashOf::from_hash(Hash([2; 32]))));
        assert_eq!(tree.get_leaf(2), Some(HashOf::from_hash(Hash([3; 32]))));
        assert_eq!(tree.get_leaf(3), Some(HashOf::from_hash(Hash([4; 32]))));
        assert_eq!(tree.get_leaf(4), None);
    }
}
