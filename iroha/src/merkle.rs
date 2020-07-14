use crate::prelude::*;
use std::collections::VecDeque;

/// [Merkle Tree](https://en.wikipedia.org/wiki/Merkle_tree) used to validate and prove data at
/// each block height.
/// Our implementation uses binary hash tree.
#[derive(Debug)]
pub struct MerkleTree {
    root_node: Node,
}

impl MerkleTree {
    pub fn new() -> Self {
        MerkleTree {
            root_node: Node::Empty,
        }
    }

    /// Builds a Merkle Tree from an array of `Hash` values values. For example of `Block` and `Transaction` hashes.
    pub fn build(self, hashes: &[Hash]) -> Self {
        let mut hashes: Vec<Hash> = hashes.to_vec();
        hashes.sort();
        let mut nodes: VecDeque<Node> =
            hashes.into_iter().map(|hash| Node::Leaf { hash }).collect();
        if nodes.len() % 2 != 0 {
            nodes.push_back(Node::Empty);
        }
        while nodes.len() > 1 {
            if let Some(node1) = nodes.pop_front() {
                let pop_front = nodes.pop_front();
                nodes.push_back(match pop_front {
                    Some(node2) => Node::from_nodes(node1, node2),
                    None => Node::from_node(node1),
                });
            }
        }
        MerkleTree {
            root_node: nodes.pop_front().unwrap_or(Node::Empty),
        }
    }

    /// Return the `Hash` of the root node.
    pub fn root_hash(&self) -> Hash {
        self.root_node.hash()
    }
}

impl Default for MerkleTree {
    fn default() -> Self {
        MerkleTree::new()
    }
}

/// Binary Tree's node with possible variants: Subtree, Leaf (with data or links to data) and Empty.
#[derive(Debug)]
pub enum Node {
    Subtree {
        left: Box<Node>,
        right: Box<Node>,
        hash: Hash,
    },
    Leaf {
        hash: Hash,
    },
    Empty,
}

#[allow(clippy::wrong_self_convention)]
impl Node {
    fn from_nodes(left: Self, right: Self) -> Self {
        Self::Subtree {
            hash: Self::nodes_pair_hash(&left, &right),
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    fn from_node(left: Self) -> Self {
        Self::Subtree {
            hash: left.hash(),
            left: Box::new(left),
            right: Box::new(Node::Empty),
        }
    }

    fn hash(&self) -> Hash {
        match &self {
            Self::Subtree { hash, .. } => *hash,
            Self::Leaf { hash } => *hash,
            Self::Empty => [0; 32],
        }
    }

    fn nodes_pair_hash(left: &Self, right: &Self) -> Hash {
        use ursa::blake2::{
            digest::{Input, VariableOutput},
            VarBlake2b,
        };
        let left_hash = left.hash();
        let right_hash = right.hash();
        let sum: Vec<_> = left_hash
            .iter()
            .zip(right_hash.iter())
            .map(|(left, right)| left.saturating_add(*right))
            .take(32)
            .collect();
        let vector = VarBlake2b::new(32)
            .expect("Failed to initialize VarBlake2b.")
            .chain(sum)
            .vec_result();
        let mut hash = [0; 32];
        hash.copy_from_slice(&vector);
        hash
    }
}

pub struct BreadthFirstIter<'a> {
    queue: Vec<&'a Node>,
}

impl<'a> BreadthFirstIter<'a> {
    fn new(root_node: &'a Node) -> Self {
        BreadthFirstIter {
            queue: vec![root_node],
        }
    }
}

/// `Iterator` impl for `BreadthFirstIter` case of iteration over `MerkleTree`.
/// `'a` lifetime specified for `Node`. Because `Node` is recursive data structure with self
/// composition in case of `Node::Subtree` we use `Box` to know size of each `Node` object in
/// memory.
impl<'a> Iterator for BreadthFirstIter<'a> {
    type Item = &'a Node;

    fn next(&mut self) -> Option<Self::Item> {
        match &self.queue.pop() {
            Some(node) => {
                if let Node::Subtree { left, right, .. } = node {
                    self.queue.push(&*left);
                    self.queue.push(&*right);
                }
                Some(node)
            }
            None => None,
        }
    }
}

impl<'a> IntoIterator for &'a MerkleTree {
    type Item = &'a Node;
    type IntoIter = BreadthFirstIter<'a>;

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
                left: Box::new(Node::Leaf { hash: [0; 32] }),
                right: Box::new(Node::Leaf { hash: [0; 32] }),
                hash: [0; 32],
            },
        };
        assert_eq!(3, tree.into_iter().count());
    }

    #[test]
    fn four_hashes_should_built_seven_nodes() {
        let hash = [1u8; 32];
        let hashes = [hash, hash, hash, hash];
        let merkle_tree = MerkleTree::new().build(&hashes);
        assert_eq!(7, merkle_tree.into_iter().count());
    }

    #[test]
    fn three_hashes_should_built_seven_nodes() {
        let hash = [1u8; 32];
        let hashes = [hash, hash, hash];
        let merkle_tree = MerkleTree::new().build(&hashes);
        assert_eq!(7, merkle_tree.into_iter().count());
    }

    #[test]
    fn same_root_hash_for_same_hashes() {
        let merkle_tree_1 = MerkleTree::new().build(&[[1u8; 32], [2u8; 32], [3u8; 32]]);
        let merkle_tree_2 = MerkleTree::new().build(&[[2u8; 32], [1u8; 32], [3u8; 32]]);
        assert_eq!(merkle_tree_1.root_hash(), merkle_tree_2.root_hash());
    }

    #[test]
    fn different_root_hash_for_different_hashes() {
        let merkle_tree_1 = MerkleTree::new().build(&[[1u8; 32], [2u8; 32], [3u8; 32]]);
        let merkle_tree_2 = MerkleTree::new().build(&[[1u8; 32], [4u8; 32], [5u8; 32]]);
        assert_ne!(merkle_tree_1.root_hash(), merkle_tree_2.root_hash());
    }
}
