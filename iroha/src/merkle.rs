use crate::prelude::*;

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

    /// Builds a Merkle Tree from sorted array of `ValidBlocks`.
    //TODO: should we check or sort blocks here?
    pub fn build(&mut self, blocks: &[&ValidBlock]) {
        //hm, can we write map(ValidBlock::hash) in Rust?
        let mut nodes: std::collections::VecDeque<Node> = blocks
            .iter()
            .map(|block| Node::Leaf { hash: block.hash() })
            .collect();
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
        self.root_node = nodes.pop_front().unwrap_or(Node::Empty);
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
    fn four_blocks_should_built_seven_nodes() {
        let block = PendingBlock::new(Vec::new())
            .chain_first()
            .sign(&[0; 32], &[0; 64])
            .expect("Failed to sign blocks.")
            .validate(&WorldStateView::new(Peer::new(
                "127.0.0.1:8080".to_string(),
                &Vec::new(),
            )))
            .expect("Failed to validate block.");
        let blocks = [&block, &block, &block, &block];
        let mut merkle_tree = MerkleTree::new();
        merkle_tree.build(&blocks);
        assert_eq!(7, merkle_tree.into_iter().count());
    }

    #[test]
    fn three_blocks_should_built_seven_nodes() {
        let block = PendingBlock::new(Vec::new())
            .chain_first()
            .sign(&[0; 32], &[0; 64])
            .expect("Failed to sign blocks.")
            .validate(&WorldStateView::new(Peer::new(
                "127.0.0.1:8080".to_string(),
                &Vec::new(),
            )))
            .expect("Failed to validate block.");
        let blocks = [&block, &block, &block, &block];
        let mut merkle_tree = MerkleTree::new();
        merkle_tree.build(&blocks);
        assert_eq!(7, merkle_tree.into_iter().count());
    }
}
