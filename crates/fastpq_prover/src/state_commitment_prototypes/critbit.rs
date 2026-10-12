//! Path-compressed binary radix (crit-bit) Merkle tree over bit strings.
//!
//! A branch stores the index of the first bit in which its two subtrees
//! differ; every key below it agrees on all earlier bits, has that bit clear
//! in the left subtree and set in the right one. The shape is therefore a
//! function of the key set alone, and an in-order walk visits the keys in bit
//! order. A branch digest is `compress(DOMAIN_BRANCH, crit, left, right)`.
//!
//! Updates only mark the touched path; [`CritbitTree::rehash`] recomputes each
//! dirty branch once, so a change set costs one compression per distinct
//! branch on its paths.

use core::marker::PhantomData;

use super::{
    DOMAIN_BRANCH,
    hash::{Digest, HashProfile, ZERO_DIGEST},
};

/// A key read as a bit string. Bits past the end of a key read as zero.
pub(super) trait BitKey: Clone + Eq {
    /// Bit `index` of the key.
    fn bit(&self, index: u32) -> bool;

    /// Index of the first bit in which the keys differ, or `None` when equal.
    fn first_difference(&self, other: &Self) -> Option<u32>;
}

#[derive(Clone)]
enum Node<K> {
    Leaf {
        key: K,
        digest: Digest,
    },
    Branch {
        crit: u32,
        left: u32,
        right: u32,
        digest: Digest,
        dirty: bool,
    },
    Free,
}

/// Read-only view of one node.
pub(super) enum NodeView<'a, K> {
    /// A committed key with its leaf digest.
    Leaf { key: &'a K, digest: Digest },
    /// A branch with its children.
    Branch {
        crit: u32,
        left: u32,
        right: u32,
        digest: Digest,
    },
}

/// One branch on a root-to-leaf path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PathStep {
    /// Branching bit index of the branch.
    pub(super) crit: u32,
    /// Digest of the child that is not on the path.
    pub(super) sibling: Digest,
    /// Whether the path continues in the right child.
    pub(super) right: bool,
}

/// Digest of a branch.
pub(super) fn branch_digest<H: HashProfile>(crit: u32, left: &Digest, right: &Digest) -> Digest {
    H::compress(DOMAIN_BRANCH, u64::from(crit), left, right)
}

/// Fold a leaf digest up a path given bottom-up.
pub(super) fn fold_path<H: HashProfile>(
    leaf: Digest,
    steps: impl IntoIterator<Item = PathStep>,
) -> Digest {
    steps.into_iter().fold(leaf, |digest, step| {
        if step.right {
            branch_digest::<H>(step.crit, &step.sibling, &digest)
        } else {
            branch_digest::<H>(step.crit, &digest, &step.sibling)
        }
    })
}

/// The tree: an arena of nodes with a free list.
pub(super) struct CritbitTree<K, H> {
    nodes: Vec<Node<K>>,
    free: Vec<u32>,
    root: Option<u32>,
    leaves: u64,
    profile: PhantomData<H>,
}

impl<K: Clone, H> Clone for CritbitTree<K, H> {
    fn clone(&self) -> Self {
        Self {
            nodes: self.nodes.clone(),
            free: self.free.clone(),
            root: self.root,
            leaves: self.leaves,
            profile: PhantomData,
        }
    }
}

impl<K: BitKey, H: HashProfile> CritbitTree<K, H> {
    pub(super) fn new() -> Self {
        Self {
            nodes: Vec::new(),
            free: Vec::new(),
            root: None,
            leaves: 0,
            profile: PhantomData,
        }
    }

    /// Number of committed keys.
    pub(super) fn len(&self) -> u64 {
        self.leaves
    }

    /// Leaves and branches the arena holds, counted node by node.
    pub(super) fn counts(&self) -> (u64, u64) {
        self.nodes
            .iter()
            .fold((0, 0), |(leaves, branches), node| match node {
                Node::Leaf { .. } => (leaves + 1, branches),
                Node::Branch { .. } => (leaves, branches + 1),
                Node::Free => (leaves, branches),
            })
    }

    /// Index of the root node, or `None` for the empty tree.
    pub(super) fn root_index(&self) -> Option<u32> {
        self.root
    }

    /// View of the node at `index`.
    pub(super) fn node(&self, index: u32) -> NodeView<'_, K> {
        match &self.nodes[index as usize] {
            Node::Leaf { key, digest } => NodeView::Leaf {
                key,
                digest: *digest,
            },
            Node::Branch {
                crit,
                left,
                right,
                digest,
                ..
            } => NodeView::Branch {
                crit: *crit,
                left: *left,
                right: *right,
                digest: *digest,
            },
            Node::Free => unreachable!("a reachable node is never on the free list"),
        }
    }

    /// Digest of the node at `index`. The tree must be rehashed.
    pub(super) fn digest(&self, index: u32) -> Digest {
        match self.node(index) {
            NodeView::Leaf { digest, .. } | NodeView::Branch { digest, .. } => digest,
        }
    }

    /// Root digest; [`ZERO_DIGEST`] for the empty tree. The tree must be rehashed.
    pub(super) fn root(&self) -> Digest {
        self.root.map_or(ZERO_DIGEST, |root| self.digest(root))
    }

    fn allocate(&mut self, node: Node<K>) -> u32 {
        if let Some(index) = self.free.pop() {
            self.nodes[index as usize] = node;
            index
        } else {
            self.nodes.push(node);
            u32::try_from(self.nodes.len() - 1).expect("prototype trees hold fewer than 2^32 nodes")
        }
    }

    fn release(&mut self, index: u32) {
        self.nodes[index as usize] = Node::Free;
        self.free.push(index);
    }

    fn mark_dirty(&mut self, index: u32) {
        if let Node::Branch { dirty, .. } = &mut self.nodes[index as usize] {
            *dirty = true;
        }
    }

    /// Follow `key`'s bits to a leaf, recording the branches passed.
    fn descend(&self, key: &K) -> Option<(u32, Vec<u32>)> {
        let mut index = self.root?;
        let mut branches = Vec::new();
        while let Node::Branch {
            crit, left, right, ..
        } = &self.nodes[index as usize]
        {
            branches.push(index);
            index = if key.bit(*crit) { *right } else { *left };
        }
        Some((index, branches))
    }

    fn leaf_key(&self, index: u32) -> &K {
        match &self.nodes[index as usize] {
            Node::Leaf { key, .. } => key,
            _ => unreachable!("descent ends at a leaf"),
        }
    }

    /// Insert `key` or replace its leaf digest.
    pub(super) fn set(&mut self, key: K, digest: Digest) {
        let Some((leaf, branches)) = self.descend(&key) else {
            let index = self.allocate(Node::Leaf { key, digest });
            self.root = Some(index);
            self.leaves = 1;
            return;
        };
        let Some(crit) = key.first_difference(self.leaf_key(leaf)) else {
            if let Node::Leaf { digest: stored, .. } = &mut self.nodes[leaf as usize] {
                if *stored == digest {
                    return;
                }
                *stored = digest;
            }
            for branch in branches {
                self.mark_dirty(branch);
            }
            return;
        };
        // The new branch goes above the first node on the search path whose
        // branching bit is not before `crit`.
        let mut parent: Option<(u32, bool)> = None;
        let mut below = self.root.expect("a nonempty tree has a root");
        for branch in branches {
            let Node::Branch {
                crit: existing,
                left,
                right,
                ..
            } = &self.nodes[branch as usize]
            else {
                unreachable!("the search path holds branches")
            };
            if *existing > crit {
                break;
            }
            let side = key.bit(*existing);
            below = if side { *right } else { *left };
            parent = Some((branch, side));
            self.mark_dirty(branch);
        }
        let side = key.bit(crit);
        let leaf = self.allocate(Node::Leaf { key, digest });
        let (left, right) = if side { (below, leaf) } else { (leaf, below) };
        let branch = self.allocate(Node::Branch {
            crit,
            left,
            right,
            digest: ZERO_DIGEST,
            dirty: true,
        });
        self.replace_child(parent, branch);
        self.leaves += 1;
    }

    fn replace_child(&mut self, parent: Option<(u32, bool)>, child: u32) {
        match parent {
            None => self.root = Some(child),
            Some((index, side)) => {
                if let Node::Branch { left, right, .. } = &mut self.nodes[index as usize] {
                    if side {
                        *right = child;
                    } else {
                        *left = child;
                    }
                }
            }
        }
    }

    /// Remove `key`; returns whether it was present.
    pub(super) fn remove(&mut self, key: &K) -> bool {
        let Some((leaf, branches)) = self.descend(key) else {
            return false;
        };
        if self.leaf_key(leaf) != key {
            return false;
        }
        self.release(leaf);
        self.leaves -= 1;
        let Some((&last, above)) = branches.split_last() else {
            self.root = None;
            return true;
        };
        let Node::Branch { left, right, .. } = &self.nodes[last as usize] else {
            unreachable!("the search path holds branches")
        };
        let sibling = if *left == leaf { *right } else { *left };
        self.release(last);
        let parent = above.last().map(|&index| {
            let Node::Branch { right, .. } = &self.nodes[index as usize] else {
                unreachable!("the search path holds branches")
            };
            (index, *right == last)
        });
        self.replace_child(parent, sibling);
        for &branch in above {
            self.mark_dirty(branch);
        }
        true
    }

    /// Recompute every dirty branch digest, children first.
    pub(super) fn rehash(&mut self) {
        let Some(root) = self.root else { return };
        // Explicit post-order walk over the dirty branches only.
        let mut stack = vec![(root, false)];
        while let Some((index, children_done)) = stack.pop() {
            let Node::Branch {
                crit,
                left,
                right,
                dirty,
                ..
            } = &self.nodes[index as usize]
            else {
                continue;
            };
            if !*dirty {
                continue;
            }
            let (crit, left, right) = (*crit, *left, *right);
            if children_done {
                let value = branch_digest::<H>(crit, &self.digest(left), &self.digest(right));
                if let Node::Branch { digest, dirty, .. } = &mut self.nodes[index as usize] {
                    *digest = value;
                    *dirty = false;
                }
            } else {
                stack.push((index, true));
                stack.push((left, false));
                stack.push((right, false));
            }
        }
    }

    fn steps(&self, key: &K, branches: &[u32]) -> Vec<PathStep> {
        branches
            .iter()
            .map(|&index| {
                let Node::Branch {
                    crit, left, right, ..
                } = &self.nodes[index as usize]
                else {
                    unreachable!("the search path holds branches")
                };
                let side = key.bit(*crit);
                PathStep {
                    crit: *crit,
                    sibling: self.digest(if side { *left } else { *right }),
                    right: side,
                }
            })
            .collect()
    }

    /// The leaf that the bits of `key` lead to, with its digest and its
    /// root-to-leaf path. `None` for the empty tree. The leaf's key equals
    /// `key` exactly when `key` is committed.
    pub(super) fn search(&self, key: &K) -> Option<(&K, Digest, Vec<PathStep>)> {
        let (leaf, branches) = self.descend(key)?;
        Some((
            self.leaf_key(leaf),
            self.digest(leaf),
            self.steps(key, &branches),
        ))
    }

    /// The smallest key below the node at `index`.
    pub(super) fn leftmost(&self, mut index: u32) -> &K {
        loop {
            match &self.nodes[index as usize] {
                Node::Leaf { key, .. } => return key,
                Node::Branch { left, .. } => index = *left,
                Node::Free => unreachable!("a reachable node is never on the free list"),
            }
        }
    }

    /// The largest key below the node at `index`.
    pub(super) fn rightmost(&self, mut index: u32) -> &K {
        loop {
            match &self.nodes[index as usize] {
                Node::Leaf { key, .. } => return key,
                Node::Branch { right, .. } => index = *right,
                Node::Free => unreachable!("a reachable node is never on the free list"),
            }
        }
    }

    /// Longest root-to-leaf path in branches.
    pub(super) fn max_depth(&self) -> u32 {
        let Some(root) = self.root else { return 0 };
        let mut deepest = 0;
        let mut stack = vec![(root, 0_u32)];
        while let Some((index, depth)) = stack.pop() {
            match &self.nodes[index as usize] {
                Node::Leaf { .. } => deepest = deepest.max(depth),
                Node::Branch { left, right, .. } => {
                    stack.push((*left, depth + 1));
                    stack.push((*right, depth + 1));
                }
                Node::Free => {}
            }
        }
        deepest
    }
}

/// A 256-bit address read most significant bit first.
impl BitKey for Digest {
    fn bit(&self, index: u32) -> bool {
        let word = (index / 64) as usize;
        word < 4 && (self[word] >> (63 - index % 64)) & 1 == 1
    }

    fn first_difference(&self, other: &Self) -> Option<u32> {
        (0_u32..)
            .zip(self.iter().zip(other))
            .find(|(_, (left, right))| left != right)
            .map(|(word, (left, right))| word * 64 + (left ^ right).leading_zeros())
    }
}

/// A byte string under the order-preserving, prefix-free bit encoding: every
/// byte is preceded by a set continuation bit and the string ends with a clear
/// one, so `"a" < "a\0" < "ab"` in bit order exactly as in byte order and no
/// key is a prefix of another.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ByteKey(pub(super) Vec<u8>);

impl ByteKey {
    /// Bit `index` of the encoding of `bytes`.
    pub(super) fn encoded_bit(bytes: &[u8], index: u32) -> bool {
        let position = (index / 9) as usize;
        let offset = index % 9;
        match bytes.get(position) {
            None => false,
            Some(_) if offset == 0 => true,
            Some(byte) => (byte >> (8 - offset)) & 1 == 1,
        }
    }

    /// Number of bits of the encoding of a key of `length` bytes.
    #[cfg(test)]
    pub(super) fn encoded_bits(length: usize) -> u64 {
        9 * length as u64 + 1
    }
}

impl BitKey for ByteKey {
    fn bit(&self, index: u32) -> bool {
        Self::encoded_bit(&self.0, index)
    }

    fn first_difference(&self, other: &Self) -> Option<u32> {
        let common = self.0.len().min(other.0.len());
        let position = self.0[..common]
            .iter()
            .zip(&other.0[..common])
            .position(|(left, right)| left != right);
        let bit = |byte: usize| {
            9 * u32::try_from(byte).expect("prototype keys are far shorter than 2^28 bytes")
        };
        let index = match position {
            Some(position) => {
                bit(position) + 1 + (self.0[position] ^ other.0[position]).leading_zeros()
            }
            None if self.0.len() == other.0.len() => return None,
            // The shorter key ends here; the longer one continues.
            None => bit(common),
        };
        Some(index)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::state_commitment_prototypes::hash::{Blake2bProfile, digest_from_bytes};

    type Tree = CritbitTree<ByteKey, Blake2bProfile>;

    fn leaf(seed: usize) -> Digest {
        digest_from_bytes(&[u8::try_from(seed).expect("a small test seed"); 32])
    }

    fn in_order(tree: &Tree) -> Vec<Vec<u8>> {
        fn walk(tree: &Tree, index: u32, out: &mut Vec<Vec<u8>>) {
            match tree.node(index) {
                NodeView::Leaf { key, .. } => out.push(key.0.clone()),
                NodeView::Branch { left, right, .. } => {
                    walk(tree, left, out);
                    walk(tree, right, out);
                }
            }
        }
        let mut out = Vec::new();
        if let Some(root) = tree.root_index() {
            walk(tree, root, &mut out);
        }
        out
    }

    #[test]
    fn byte_key_encoding_is_order_preserving_and_prefix_free() {
        let keys: [&[u8]; 9] = [
            b"",
            b"\0",
            b"\0\0",
            b"a",
            b"a\0",
            b"ab",
            b"b",
            b"\xff",
            b"\xff\xff",
        ];
        for (left_index, left) in keys.iter().enumerate() {
            for (right_index, right) in keys.iter().enumerate() {
                let (left_key, right_key) = (ByteKey(left.to_vec()), ByteKey(right.to_vec()));
                let difference = left_key.first_difference(&right_key);
                assert_eq!(difference, right_key.first_difference(&left_key));
                if left_index == right_index {
                    assert_eq!(difference, None);
                    continue;
                }
                let index = difference.expect("distinct keys differ");
                assert!(u64::from(index) < ByteKey::encoded_bits(left.len().max(right.len())));
                for earlier in 0..index {
                    assert_eq!(left_key.bit(earlier), right_key.bit(earlier));
                }
                // The key with the clear bit is the smaller byte string.
                assert_eq!(!left_key.bit(index) && right_key.bit(index), left < right);
            }
        }
        assert!(!ByteKey(b"a".to_vec()).bit(1_000));
    }

    #[test]
    fn digest_keys_read_most_significant_bit_first() {
        let low: Digest = [0, 0, 0, 1];
        let high: Digest = [1 << 63, 0, 0, 0];
        assert!(high.bit(0) && !low.bit(0));
        assert!(low.bit(255) && !high.bit(255));
        assert!(!low.bit(256));
        assert_eq!(low.first_difference(&high), Some(0));
        assert_eq!(low.first_difference(&[0, 0, 0, 3]), Some(254));
        assert_eq!(low.first_difference(&low), None);
    }

    #[test]
    fn shape_and_root_are_functions_of_the_key_set() {
        let keys: Vec<Vec<u8>> = [
            &b""[..],
            b"a",
            b"ab",
            b"ab\0",
            b"b",
            b"\xff",
            b"\xff\xff",
            b"abc",
            b"\0",
        ]
        .iter()
        .map(|key| key.to_vec())
        .collect();
        let mut forward = Tree::new();
        for (index, key) in keys.iter().enumerate() {
            forward.set(ByteKey(key.clone()), leaf(index));
        }
        forward.rehash();
        let mut backward = Tree::new();
        for (index, key) in keys.iter().enumerate().rev() {
            backward.set(ByteKey(b"junk".to_vec()), leaf(0xee));
            backward.set(ByteKey(key.clone()), leaf(0xaa));
            backward.set(ByteKey(key.clone()), leaf(index));
            assert!(backward.remove(&ByteKey(b"junk".to_vec())));
            backward.rehash();
        }
        assert_eq!(forward.root(), backward.root());
        assert_eq!(forward.len(), keys.len() as u64);
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(in_order(&forward), sorted);
        assert_eq!(in_order(&backward), sorted);
        assert_eq!(forward.leftmost(forward.root_index().unwrap()).0, sorted[0]);
        assert_eq!(
            forward.rightmost(forward.root_index().unwrap()).0,
            *sorted.last().unwrap()
        );
        assert!(forward.max_depth() >= 4);

        // Every path folds to the root, and a changed leaf changes it.
        for (index, key) in keys.iter().enumerate() {
            let (found, digest, steps) = forward.search(&ByteKey(key.clone())).unwrap();
            assert_eq!(found.0, *key);
            assert_eq!(digest, leaf(index));
            assert!(steps.windows(2).all(|pair| pair[0].crit < pair[1].crit));
            let folded = fold_path::<Blake2bProfile>(digest, steps.iter().rev().copied());
            assert_eq!(folded, forward.root());
            let other = fold_path::<Blake2bProfile>(leaf(0x55), steps.iter().rev().copied());
            assert_ne!(other, forward.root());
        }
        // An absent key leads to another leaf.
        let (found, _, _) = forward.search(&ByteKey(b"aa".to_vec())).unwrap();
        assert_ne!(found.0, b"aa");
        assert!(!forward.remove(&ByteKey(b"aa".to_vec())));
    }

    #[test]
    fn random_updates_match_a_cold_build_and_reuse_freed_nodes() {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move |bound: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            usize::try_from(state % bound as u64).expect("below a usize bound")
        };
        let mut model: BTreeMap<Vec<u8>, usize> = BTreeMap::new();
        let mut tree = Tree::new();
        for round in 0..400 {
            let length = next(4);
            let key: Vec<u8> = (0..length)
                .map(|_| u8::try_from(next(3)).expect("below three"))
                .collect();
            if next(3) == 0 {
                assert_eq!(
                    tree.remove(&ByteKey(key.clone())),
                    model.remove(&key).is_some()
                );
            } else {
                let value = next(250);
                tree.set(ByteKey(key.clone()), leaf(value));
                model.insert(key, value);
            }
            if round % 7 == 0 {
                tree.rehash();
                let mut cold = Tree::new();
                for (key, value) in &model {
                    cold.set(ByteKey(key.clone()), leaf(*value));
                }
                cold.rehash();
                assert_eq!(tree.root(), cold.root(), "round {round}");
                assert_eq!(tree.len(), model.len() as u64);
                assert_eq!(in_order(&tree), model.keys().cloned().collect::<Vec<_>>());
            }
        }
        // The arena never grows beyond the nodes of the largest tree it held,
        // and it holds one branch per leaf but one.
        assert!(tree.nodes.len() <= 2 * 121);
        let (leaves, branches) = tree.counts();
        assert_eq!(leaves, tree.len());
        assert_eq!(branches, leaves.saturating_sub(1));
        assert_eq!(
            tree.nodes.len() - tree.free.len(),
            usize::try_from(leaves + branches).unwrap()
        );
        let copy = tree.clone();
        assert_eq!((copy.root(), copy.counts()), (tree.root(), tree.counts()));
        let mut empty = Tree::new();
        assert_eq!(empty.counts(), (0, 0));
        assert_eq!(empty.root(), ZERO_DIGEST);
        empty.rehash();
        assert!(empty.search(&ByteKey(Vec::new())).is_none());
        assert_eq!(empty.max_depth(), 0);
    }
}
