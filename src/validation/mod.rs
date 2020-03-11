pub mod stateful;
pub mod stateless;

/// [Merkle Tree](https://en.wikipedia.org/wiki/Merkle_tree) used to validate and prove data at
/// each block height.
/// Our implementation uses binary hash tree.
struct MerkleTree {
    root_node: Node,
}

/// Binary Tree's node with possible variants: Subtree, Leaf (with data or links to data) and Empty.
enum Node {
    Subtree { left: Box<Node>, right: Box<Node> },
    Leaf { data: Vec<u8> },
    Empty,
}

struct BreadthFirstIter<'a> {
    current: &'a Node,
}

impl<'a> BreadthFirstIter<'a> {
    fn new(node: &'a Node) -> Self {
        BreadthFirstIter { current: node }
    }
}

/// `Iterator` impl for `BreadthFirstIter` case of iteration over `MerkleTree`.
/// `'a` lifetime specified for `Node`. Because `Node` is recursive data structure with self
/// composition in case of `Node::Subtree` we use `Box` to know size of each `Node` object in
/// memory.
impl<'a> Iterator for BreadthFirstIter<'a> {
    type Item = &'a Node;

    fn next(&mut self) -> Option<Self::Item> {
        match &self.current {
            Node::Subtree { left, right } => {
                self.current = &*left;
                Some(&*left)
            }
            Node::Leaf { data } => None,
            Node::Empty => None,
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

#[test]
#[ignore]
fn tree_with_two_layers_should_reach_all_nodes() {
    let tree = MerkleTree {
        root_node: Node::Subtree {
            left: Box::new(Node::Leaf { data: vec![] }),
            right: Box::new(Node::Leaf { data: vec![] }),
        },
    };
    assert_eq!(3, tree.into_iter().count());
}
