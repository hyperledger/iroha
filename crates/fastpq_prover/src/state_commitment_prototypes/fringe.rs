//! Complete-range witness shared by the binary trees with sorted leaves.
//!
//! The witness is the part of the tree that covers the interval, in postfix
//! order: a subtree is given either by its digest alone (hidden) or opened down
//! to its leaves. Read left to right, the leaves of an accepted witness are
//!
//! ```text
//! hidden*  [predecessor]  claimed*  [successor]  hidden*
//! ```
//!
//! `predecessor` is a disclosed leaf below the interval and `successor` one at
//! or above its upper bound. Hidden subtrees need the disclosed leaf on their
//! side, so every hidden key lies outside the interval, and no subtree is
//! hidden between two revealed leaves, so the claimed entries are every leaf
//! between the two boundaries. Because the leaves of the committed tree are in
//! key order, that is every committed entry of the interval.
//!
//! [`open`] returns the opened tree itself, children before parents, so the
//! in-circuit program of [`super::circuit`] evaluates exactly the hashes the
//! native verifier computes, each once.

use super::{
    Reject,
    codec::{Reader, Writer},
    hash::{Digest, HashProfile, ZERO_DIGEST},
    key_digest, leaf_digest,
};

const TOKEN_HIDDEN: u8 = 0;
const TOKEN_CLAIMED: u8 = 1;
const TOKEN_BOUNDARY: u8 = 2;
const TOKEN_BRANCH: u8 = 3;

/// Postfix writer of one range witness.
#[derive(Default)]
pub(super) struct Builder {
    tokens: usize,
    body: Writer,
}

impl Builder {
    /// A subtree given by its digest alone.
    pub(super) fn hidden(&mut self, digest: &Digest) {
        self.tokens += 1;
        self.body.u8(TOKEN_HIDDEN);
        self.body.digest(digest);
    }

    /// The next claimed entry; its bytes come from the statement.
    pub(super) fn claimed(&mut self) {
        self.tokens += 1;
        self.body.u8(TOKEN_CLAIMED);
    }

    /// A disclosed leaf outside the interval.
    pub(super) fn boundary(&mut self, key: &[u8], value: &Digest) {
        self.tokens += 1;
        self.body.u8(TOKEN_BOUNDARY);
        self.body.bytes(key);
        self.body.digest(value);
    }

    /// A branch over the two subtrees written last.
    pub(super) fn branch(&mut self, aux: u32) {
        self.tokens += 1;
        self.body.u8(TOKEN_BRANCH);
        self.body.u32(aux);
    }

    /// The witness bytes: the token count, then the tokens.
    pub(super) fn finish(self) -> Vec<u8> {
        let mut writer = Writer::default();
        writer.count(self.tokens);
        let mut bytes = writer.finish();
        bytes.extend_from_slice(&self.body.finish());
        bytes
    }
}

/// Role of one revealed leaf of an opened witness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LeafRole {
    /// The disclosed leaf below the interval.
    Predecessor,
    /// Claimed entry `index` of the statement.
    Claimed(usize),
    /// The disclosed leaf at or above the upper bound.
    Successor,
}

/// One revealed leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct OpenLeaf {
    /// Role of the leaf in the statement.
    pub(super) role: LeafRole,
    /// Key bytes of the leaf.
    pub(super) key: Vec<u8>,
    /// Value digest of the leaf.
    pub(super) value_digest: Digest,
}

/// One node of an opened witness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum OpenNode {
    /// A subtree given by its digest alone.
    Hidden,
    /// Revealed leaf `index` of [`Opened::leaves`].
    Leaf(usize),
    /// A branch with its auxiliary word over two earlier nodes.
    Branch {
        /// Auxiliary word of the branch digest.
        aux: u32,
        /// Index of the left child.
        left: usize,
        /// Index of the right child.
        right: usize,
    },
}

/// A range witness that satisfies every structural rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Opened {
    /// Digest the witness reconstructs; `ZERO_DIGEST` for the empty tree.
    pub(super) root: Digest,
    /// Revealed leaves, left to right.
    pub(super) leaves: Vec<OpenLeaf>,
    /// Every node with its digest, children before parents. The last node is
    /// the root of the tree; the list is empty for the empty tree.
    pub(super) nodes: Vec<(OpenNode, Digest)>,
}

struct Slot {
    kind: OpenNode,
    digest: Digest,
    all_hidden: bool,
}

/// Parse a range witness and check everything except the root.
///
/// `branch` returns the digest of a branch from its auxiliary word and
/// children, or `None` when the construction does not admit that word.
///
/// # Errors
/// [`Reject::Malformed`] for a noncanonical encoding and [`Reject::NotProven`]
/// when the witness cannot establish the statement at any root.
pub(super) fn open<H: HashProfile>(
    lower: &[u8],
    upper: Option<&[u8]>,
    entries: &[(&[u8], &[u8])],
    witness: &[u8],
    branch: impl Fn(u32, &Digest, &Digest) -> Option<Digest>,
) -> Result<Opened, Reject> {
    let mut reader = Reader::<H>::new(witness);
    let tokens = reader.count(1)?;
    if tokens == 0 {
        reader.finish()?;
        return if entries.is_empty() {
            Ok(Opened {
                root: ZERO_DIGEST,
                leaves: Vec::new(),
                nodes: Vec::new(),
            })
        } else {
            Err(Reject::NotProven)
        };
    }
    let mut slots: Vec<Slot> = Vec::new();
    let mut stack: Vec<usize> = Vec::new();
    let mut leaves: Vec<OpenLeaf> = Vec::new();
    let (mut left_hidden, mut right_hidden) = (false, false);
    let (mut has_predecessor, mut has_successor) = (false, false);
    let mut claimed = 0;
    for _ in 0..tokens {
        let slot = match reader.u8()? {
            TOKEN_HIDDEN => {
                let digest = reader.digest()?;
                if leaves.is_empty() {
                    left_hidden = true;
                } else {
                    right_hidden = true;
                }
                Slot {
                    kind: OpenNode::Hidden,
                    digest,
                    all_hidden: true,
                }
            }
            TOKEN_CLAIMED => {
                if right_hidden || has_successor {
                    return Err(Reject::Malformed);
                }
                let (key, value) = entries.get(claimed).ok_or(Reject::NotProven)?;
                let value_digest = super::value_digest::<H>(value);
                leaves.push(OpenLeaf {
                    role: LeafRole::Claimed(claimed),
                    key: key.to_vec(),
                    value_digest,
                });
                claimed += 1;
                Slot {
                    kind: OpenNode::Leaf(leaves.len() - 1),
                    digest: leaf_digest::<H>(&key_digest::<H>(key), &value_digest),
                    all_hidden: false,
                }
            }
            TOKEN_BOUNDARY => {
                let key = reader.bytes()?;
                let value_digest = reader.digest()?;
                if right_hidden || has_successor {
                    return Err(Reject::Malformed);
                }
                let role = if key < lower {
                    // The predecessor is the first revealed leaf.
                    if !leaves.is_empty() {
                        return Err(Reject::Malformed);
                    }
                    has_predecessor = true;
                    LeafRole::Predecessor
                } else if upper.is_some_and(|upper| key >= upper) {
                    // The successor follows every claimed entry.
                    if claimed != entries.len() {
                        return Err(Reject::NotProven);
                    }
                    has_successor = true;
                    LeafRole::Successor
                } else {
                    // A disclosed leaf inside the interval is an unclaimed entry.
                    return Err(Reject::NotProven);
                };
                leaves.push(OpenLeaf {
                    role,
                    key: key.to_vec(),
                    value_digest,
                });
                Slot {
                    kind: OpenNode::Leaf(leaves.len() - 1),
                    digest: leaf_digest::<H>(&key_digest::<H>(key), &value_digest),
                    all_hidden: false,
                }
            }
            TOKEN_BRANCH => {
                let aux = reader.u32()?;
                let right = stack.pop().ok_or(Reject::Malformed)?;
                let left = stack.pop().ok_or(Reject::Malformed)?;
                // A branch over two hidden subtrees is given by its own digest.
                if slots[left].all_hidden && slots[right].all_hidden {
                    return Err(Reject::Malformed);
                }
                let digest = branch(aux, &slots[left].digest, &slots[right].digest)
                    .ok_or(Reject::Malformed)?;
                Slot {
                    kind: OpenNode::Branch { aux, left, right },
                    digest,
                    all_hidden: false,
                }
            }
            _ => return Err(Reject::Malformed),
        };
        stack.push(slots.len());
        slots.push(slot);
    }
    reader.finish()?;
    let [root] = stack[..] else {
        return Err(Reject::Malformed);
    };
    if claimed != entries.len()
        || (left_hidden && !has_predecessor)
        || (right_hidden && !has_successor)
    {
        return Err(Reject::NotProven);
    }
    Ok(Opened {
        root: slots[root].digest,
        leaves,
        nodes: slots
            .into_iter()
            .map(|slot| (slot.kind, slot.digest))
            .collect(),
    })
}

/// Crafted range witnesses for the negative tests of this module and of the
/// in-circuit programs: a prover that follows no rule but the encoding.
#[cfg(test)]
pub(super) mod forge {
    use super::{Builder, OpenNode, Opened};

    /// What a crafted witness does with one revealed leaf of an opened tree.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(in super::super) enum Role {
        /// Hide the leaf behind its digest.
        Hidden,
        /// Present the leaf as the next claimed entry.
        Claimed,
        /// Disclose the leaf's key and value digest.
        Boundary,
    }

    /// Whether no leaf below `node` stays revealed.
    fn all_hidden(opened: &Opened, node: usize, roles: &[Role]) -> bool {
        match opened.nodes[node].0 {
            OpenNode::Hidden => true,
            OpenNode::Leaf(leaf) => roles[leaf] == Role::Hidden,
            OpenNode::Branch { left, right, .. } => {
                all_hidden(opened, left, roles) && all_hidden(opened, right, roles)
            }
        }
    }

    fn emit(
        opened: &Opened,
        node: usize,
        roles: &[Role],
        swapped: Option<usize>,
        out: &mut Builder,
    ) {
        let (kind, digest) = opened.nodes[node];
        // A subtree without a revealed leaf is given by its digest.
        if all_hidden(opened, node, roles) {
            out.hidden(&digest);
            return;
        }
        match kind {
            OpenNode::Hidden => unreachable!("a hidden node has no revealed leaf"),
            OpenNode::Leaf(leaf) => {
                if roles[leaf] == Role::Claimed {
                    out.claimed();
                } else {
                    let leaf = &opened.leaves[leaf];
                    out.boundary(&leaf.key, &leaf.value_digest);
                }
            }
            OpenNode::Branch { aux, left, right } => {
                let (first, second) = if swapped == Some(node) {
                    (right, left)
                } else {
                    (left, right)
                };
                emit(opened, first, roles, swapped, out);
                emit(opened, second, roles, swapped, out);
                out.branch(aux);
            }
        }
    }

    /// The witness that gives every revealed leaf of `opened` the stated role
    /// and keeps every digest of the tree. `swapped` names one branch whose
    /// children are written in the opposite order, so a hidden right sibling
    /// appears on the left of its revealed neighbour; the true tree hashes
    /// them in the original order.
    pub(in super::super) fn reemit(
        opened: &Opened,
        roles: &[Role],
        swapped: Option<usize>,
    ) -> Vec<u8> {
        assert_eq!(roles.len(), opened.leaves.len(), "one role per leaf");
        let mut out = Builder::default();
        if let Some(top) = opened.nodes.len().checked_sub(1) {
            emit(opened, top, roles, swapped, &mut out);
        }
        out.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        forge::{
            Role::{self, Boundary, Claimed, Hidden},
            reemit,
        },
        *,
    };
    use crate::state_commitment_prototypes::{
        Change, DOMAIN_BRANCH, Engine,
        btree::MerkleBTree,
        entry_leaf,
        hash::{Blake2bProfile, Poseidon2Profile},
        immediate_successor,
        radix::RadixTree,
        value_digest,
    };

    type H = Blake2bProfile;

    fn branch(aux: u32, left: &Digest, right: &Digest) -> Option<Digest> {
        (aux < 100).then(|| H::compress(DOMAIN_BRANCH, u64::from(aux), left, right))
    }

    const A: (&[u8], &[u8]) = (b"a", b"1");
    const B: (&[u8], &[u8]) = (b"b", b"2");
    const C: (&[u8], &[u8]) = (b"c", b"3");
    const D: (&[u8], &[u8]) = (b"d", b"4");

    fn leaf(entry: (&[u8], &[u8])) -> Digest {
        entry_leaf::<H>(entry.0, entry.1)
    }

    fn disclose(out: &mut Builder, entry: (&[u8], &[u8])) {
        out.boundary(entry.0, &value_digest::<H>(entry.1));
    }

    /// Root of the toy tree `((a b) (c d))` with branch words 1, 2 and 0.
    fn root() -> Digest {
        let left = branch(1, &leaf(A), &leaf(B)).unwrap();
        let right = branch(2, &leaf(C), &leaf(D)).unwrap();
        branch(0, &left, &right).unwrap()
    }

    /// The digest a witness hashes to when no structural rule is applied.
    fn hash_only(entries: &[(&[u8], &[u8])], witness: &[u8]) -> Digest {
        let mut reader = Reader::<H>::new(witness);
        let mut stack = Vec::new();
        let mut claimed = entries.iter();
        for _ in 0..reader.count(1).unwrap() {
            let digest = match reader.u8().unwrap() {
                TOKEN_HIDDEN => reader.digest().unwrap(),
                TOKEN_CLAIMED => leaf(*claimed.next().unwrap()),
                TOKEN_BOUNDARY => {
                    let key = reader.bytes().unwrap();
                    leaf_digest::<H>(&key_digest::<H>(key), &reader.digest().unwrap())
                }
                _ => {
                    let aux = reader.u32().unwrap();
                    let right = stack.pop().unwrap();
                    let left = stack.pop().unwrap();
                    branch(aux, &left, &right).unwrap()
                }
            };
            stack.push(digest);
        }
        reader.finish().unwrap();
        assert_eq!(stack.len(), 1);
        stack[0]
    }

    fn open_toy(
        lower: &[u8],
        upper: Option<&[u8]>,
        entries: &[(&[u8], &[u8])],
        witness: &[u8],
    ) -> Result<Opened, Reject> {
        open::<H>(lower, upper, entries, witness, branch)
    }

    #[test]
    fn honest_shapes_open_to_the_root_with_the_tree_they_hash() {
        // The complete tree, and the same leaves under another branch word.
        let tree = |word: u32| {
            let mut out = Builder::default();
            out.claimed();
            out.claimed();
            out.branch(word);
            out.claimed();
            out.claimed();
            out.branch(2);
            out.branch(0);
            out
        };
        let (complete, out) = (tree(1), tree(3));
        let opened = open_toy(b"", None, &[A, B, C, D], &complete.finish()).unwrap();
        assert_eq!(opened.root, root());
        assert_eq!(opened.leaves.len(), 4);
        assert_eq!(opened.nodes.len(), 7);
        assert_eq!(
            opened.nodes[6],
            (
                OpenNode::Branch {
                    aux: 0,
                    left: 2,
                    right: 5
                },
                root()
            )
        );
        assert_eq!(opened.nodes[1], (OpenNode::Leaf(1), leaf(B)));
        assert_eq!(opened.leaves[3].role, LeafRole::Claimed(3));
        assert_eq!(opened.leaves[2].key, b"c");
        assert_eq!(opened.leaves[2].value_digest, value_digest::<H>(b"3"));
        // Another branch word is another tree.
        assert_ne!(
            open_toy(b"", None, &[A, B, C, D], &out.finish())
                .unwrap()
                .root,
            root()
        );

        // `[b, d)` is `{b, c}` between the disclosed `a` and `d`.
        let mut bounded = Builder::default();
        disclose(&mut bounded, A);
        bounded.claimed();
        bounded.branch(1);
        bounded.claimed();
        disclose(&mut bounded, D);
        bounded.branch(2);
        bounded.branch(0);
        let opened = open_toy(b"b", Some(b"d"), &[B, C], &bounded.finish()).unwrap();
        assert_eq!(opened.root, root());
        let roles: Vec<LeafRole> = opened.leaves.iter().map(|leaf| leaf.role).collect();
        assert_eq!(
            roles,
            [
                LeafRole::Predecessor,
                LeafRole::Claimed(0),
                LeafRole::Claimed(1),
                LeafRole::Successor
            ]
        );

        // Hidden subtrees on both sides, each behind its disclosed leaf: the
        // empty range `[b\0, c)`.
        let mut empty = Builder::default();
        empty.hidden(&leaf(A));
        disclose(&mut empty, B);
        empty.branch(1);
        disclose(&mut empty, C);
        empty.hidden(&leaf(D));
        empty.branch(2);
        empty.branch(0);
        let witness = empty.finish();
        let opened = open_toy(b"b\0", Some(b"c"), &[], &witness).unwrap();
        assert_eq!(opened.root, root());
        assert_eq!(opened.nodes[0], (OpenNode::Hidden, leaf(A)));
        // The same witness re-emitted from its opened tree is the same bytes.
        assert_eq!(
            reemit(&opened, &[Role::Boundary, Role::Boundary], None),
            witness
        );

        // The empty tree.
        let none = Builder::default().finish();
        let opened = open_toy(b"", None, &[], &none).unwrap();
        assert_eq!((opened.root, opened.nodes.len()), (ZERO_DIGEST, 0));
        assert_eq!(open_toy(b"", None, &[A], &none), Err(Reject::NotProven));
    }

    /// One crafted case: the statement, the roles of `a b c d` and the
    /// expected refusal.
    type Case<'a> = (
        &'a [u8],
        Option<&'a [u8]>,
        &'a [(&'a [u8], &'a [u8])],
        [Role; 4],
        Reject,
    );

    /// Every way of hiding a committed entry of the interval, or of leaving a
    /// hidden subtree unbounded, is refused although the witness hashes to the
    /// true root.
    #[test]
    fn crafted_omissions_are_refused_at_the_true_root() {
        let complete = {
            let mut out = Builder::default();
            out.claimed();
            out.claimed();
            out.branch(1);
            out.claimed();
            out.claimed();
            out.branch(2);
            out.branch(0);
            open_toy(b"", None, &[A, B, C, D], &out.finish()).unwrap()
        };
        let cases: [Case<'_>; 9] = [
            // A hidden leaf between a claimed entry and the successor: `[a, c)`
            // without `b`. This is the completeness rule.
            (
                b"a",
                Some(b"c"),
                &[A],
                [Claimed, Hidden, Boundary, Hidden],
                Reject::Malformed,
            ),
            // A hidden leaf between two claimed entries.
            (
                b"a",
                None,
                &[A, C, D],
                [Claimed, Hidden, Claimed, Claimed],
                Reject::Malformed,
            ),
            // A hidden leaf between the predecessor and a claimed entry.
            (
                b"b",
                None,
                &[C, D],
                [Boundary, Hidden, Claimed, Claimed],
                Reject::Malformed,
            ),
            // A hidden left subtree without a predecessor.
            (
                b"",
                None,
                &[C, D],
                [Hidden, Hidden, Claimed, Claimed],
                Reject::NotProven,
            ),
            // A hidden right subtree without a successor.
            (
                b"",
                None,
                &[A, B],
                [Claimed, Claimed, Hidden, Hidden],
                Reject::NotProven,
            ),
            // A disclosed leaf inside the interval is an unclaimed entry.
            (
                b"a",
                None,
                &[A, C, D],
                [Claimed, Boundary, Claimed, Claimed],
                Reject::NotProven,
            ),
            // A second disclosed leaf after the successor.
            (
                b"a",
                Some(b"b"),
                &[A],
                [Claimed, Boundary, Boundary, Hidden],
                Reject::Malformed,
            ),
            // The successor before every claimed entry was consumed.
            (
                b"a",
                Some(b"b"),
                &[A, C],
                [Claimed, Boundary, Hidden, Hidden],
                Reject::NotProven,
            ),
            // A second disclosed leaf below the interval.
            (
                b"c",
                None,
                &[C, D],
                [Boundary, Boundary, Claimed, Claimed],
                Reject::Malformed,
            ),
        ];
        for (index, (lower, upper, entries, roles, expected)) in cases.into_iter().enumerate() {
            let witness = reemit(&complete, &roles, None);
            assert_eq!(
                open_toy(lower, upper, entries, &witness),
                Err(expected),
                "case {index}"
            );
            // The crafted witness hashes to the true root: only a structural
            // rule refuses it.
            assert_eq!(hash_only(entries, &witness), root(), "case {index}");
        }
        // A claimed token after the successor: it names no entry of the
        // statement, so there is nothing it could hash.
        let witness = reemit(&complete, &[Claimed, Boundary, Claimed, Hidden], None);
        assert_eq!(
            open_toy(b"a", Some(b"b"), &[A], &witness),
            Err(Reject::Malformed)
        );
        // B-tree absence is the empty range `[key, key ‖ 0)`: the committed `b`
        // hidden between the disclosed `a` and `c`.
        let witness = reemit(&complete, &[Boundary, Hidden, Boundary, Hidden], None);
        assert_eq!(
            open_toy(b"b", Some(&immediate_successor(b"b")), &[], &witness),
            Err(Reject::Malformed)
        );
        // Without the hidden leaf the same two disclosed leaves prove absence
        // of a key between them in the tree `{a, c}`.
        let small = {
            let mut out = Builder::default();
            out.claimed();
            out.claimed();
            out.branch(1);
            open_toy(b"", None, &[A, C], &out.finish()).unwrap()
        };
        let witness = reemit(&small, &[Boundary, Boundary], None);
        assert_eq!(
            open_toy(b"b", Some(&immediate_successor(b"b")), &[], &witness)
                .unwrap()
                .root,
            small.root
        );
    }

    #[test]
    fn noncanonical_encodings_are_malformed() {
        let token = |build: &dyn Fn(&mut Builder)| {
            let mut out = Builder::default();
            build(&mut out);
            out.finish()
        };
        // A branch over two hidden subtrees is given by its own digest.
        let hidden_pair = token(&|out| {
            out.hidden(&leaf(A));
            out.hidden(&leaf(B));
            out.branch(1);
            disclose(out, C);
            out.branch(0);
        });
        assert_eq!(
            open_toy(b"b\0", Some(b"c"), &[], &hidden_pair),
            Err(Reject::Malformed)
        );
        // A branch without two operands, and two roots.
        let underflow = token(&|out| {
            out.claimed();
            out.branch(1);
        });
        assert_eq!(
            open_toy(b"", None, &[A], &underflow),
            Err(Reject::Malformed)
        );
        let two_roots = token(&|out| {
            out.claimed();
            out.claimed();
        });
        assert_eq!(
            open_toy(b"", None, &[A, B], &two_roots),
            Err(Reject::Malformed)
        );
        // A branch word the construction does not admit.
        let word = token(&|out| {
            out.claimed();
            out.claimed();
            out.branch(100);
        });
        assert_eq!(open_toy(b"", None, &[A, B], &word), Err(Reject::Malformed));
        // More claimed tokens than entries, fewer tokens than entries.
        let pair = token(&|out| {
            out.claimed();
            out.claimed();
            out.branch(1);
        });
        assert_eq!(open_toy(b"", None, &[A], &pair), Err(Reject::NotProven));
        assert_eq!(
            open_toy(b"", None, &[A, B, C], &pair),
            Err(Reject::NotProven)
        );
        // An unknown token, a trailing byte and a truncated witness.
        let mut unknown = pair.clone();
        unknown[4] = 9;
        assert_eq!(
            open_toy(b"", None, &[A, B], &unknown),
            Err(Reject::Malformed)
        );
        let mut trailing = pair.clone();
        trailing.push(0);
        assert_eq!(
            open_toy(b"", None, &[A, B], &trailing),
            Err(Reject::Malformed)
        );
        for length in 0..pair.len() {
            assert!(open_toy(b"", None, &[A, B], &pair[..length]).is_err());
        }
        // A noncanonical digest of an algebraic profile.
        let noncanonical = token(&|out| {
            out.hidden(&[u64::MAX; 4]);
            disclose(out, B);
            out.branch(1);
        });
        assert_eq!(
            open::<Poseidon2Profile>(b"c", None, &[], &noncanonical, |_, left, _| Some(*left)),
            Err(Reject::Malformed)
        );
    }

    /// The same omissions against the two engines that use this witness, on
    /// their real trees: the crafted witness keeps every digest of the honest
    /// one, so it hashes to the committed root, and is refused.
    fn engines_refuse_crafted_omissions<E: Engine<Hash = H>>(
        open_range: impl Fn(&[u8], Option<&[u8]>, &[(&[u8], &[u8])], &[u8]) -> Result<Opened, Reject>,
    ) {
        let content: [(&[u8], &[u8]); 6] = [A, B, C, D, (b"e", b"5"), (b"f", b"6")];
        let mut engine = E::new();
        let changes: Vec<Change<'_>> = content
            .iter()
            .map(|(key, value)| (*key, Some(*value)))
            .collect();
        engine.apply(&changes);
        let root = engine.structure_root();
        let honest = engine.prove_range(b"", None);
        assert_eq!(E::range_root(b"", None, &content, &honest), Ok(root));
        let complete = open_range(b"", None, &content, &honest).unwrap();
        assert_eq!(complete.root, root);
        assert_eq!(complete.leaves.len(), content.len());

        // `[a, c)` holds `a` and `b`; the witness hides `b` before the
        // successor `c`.
        let omitted = reemit(
            &complete,
            &[Claimed, Hidden, Boundary, Hidden, Hidden, Hidden],
            None,
        );
        assert_eq!(
            E::range_root(b"a", Some(b"c"), &[A], &omitted),
            Err(Reject::Malformed)
        );
        // The honest witness of that interval proves both entries and not one.
        let honest = engine.prove_range(b"a", Some(b"c"));
        assert_eq!(E::range_root(b"a", Some(b"c"), &[A, B], &honest), Ok(root));
        assert!(E::range_root(b"a", Some(b"c"), &[A], &honest).is_err());

        // A hidden entry between two claimed ones, a hidden left subtree
        // without a predecessor and a hidden right subtree without a successor.
        let gap = reemit(
            &complete,
            &[Claimed, Claimed, Hidden, Claimed, Claimed, Claimed],
            None,
        );
        assert_eq!(
            E::range_root(b"", None, &[A, B, D, content[4], content[5]], &gap),
            Err(Reject::Malformed)
        );
        let headless = reemit(
            &complete,
            &[Hidden, Claimed, Claimed, Claimed, Claimed, Claimed],
            None,
        );
        assert_eq!(
            E::range_root(b"", None, &content[1..], &headless),
            Err(Reject::NotProven)
        );
        let tailless = reemit(
            &complete,
            &[Claimed, Claimed, Claimed, Claimed, Claimed, Hidden],
            None,
        );
        assert_eq!(
            E::range_root(b"", None, &content[..5], &tailless),
            Err(Reject::NotProven)
        );
        // A disclosed leaf inside the interval.
        let inside = reemit(
            &complete,
            &[Claimed, Boundary, Claimed, Claimed, Claimed, Claimed],
            None,
        );
        assert_eq!(
            E::range_root(b"", None, &[A, C, D, content[4], content[5]], &inside),
            Err(Reject::NotProven)
        );
        // Each crafted witness keeps the honest digests: with every leaf
        // claimed again it is the honest witness.
        assert_eq!(
            reemit(&complete, &[Claimed; 6], None),
            engine.prove_range(b"", None)
        );
    }

    #[test]
    fn radix_tree_refuses_crafted_omissions() {
        engines_refuse_crafted_omissions::<RadixTree<H>>(RadixTree::<H>::open_range);
        // The absent-key form of the radix tree is a path, not this witness.
    }

    #[test]
    fn merkle_btree_refuses_crafted_omissions_and_false_absence() {
        type Tree = MerkleBTree<H>;
        engines_refuse_crafted_omissions::<Tree>(Tree::open_range);
        // Absence of the committed `b`: the two neighbours disclosed and `b`
        // hidden between them.
        let content = [A, B, C, D];
        let mut tree = Tree::new();
        let changes: Vec<Change<'_>> = content
            .iter()
            .map(|(key, value)| (*key, Some(*value)))
            .collect();
        tree.apply(&changes);
        let complete = Tree::open_range(b"", None, &content, &tree.prove_range(b"", None)).unwrap();
        let forged = reemit(
            &complete,
            &[Role::Boundary, Role::Hidden, Role::Boundary, Role::Hidden],
            None,
        );
        assert_eq!(Tree::absence_root(b"b", &forged), Err(Reject::Malformed));
        assert!(tree.prove_absence(b"b").is_none());
        // A true absence between the same neighbours of another tree verifies.
        let mut other = Tree::new();
        other.apply(&[(A.0, Some(A.1)), (C.0, Some(C.1))]);
        let witness = other.prove_absence(b"b").unwrap();
        assert_eq!(
            Tree::absence_root(b"b", &witness),
            Ok(other.structure_root())
        );
    }
}
