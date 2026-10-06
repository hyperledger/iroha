//! Candidate 1: path-compressed sparse radix Merkle tree in key order.
//!
//! The tree is a crit-bit tree over the order-preserving, prefix-free bit
//! encoding of the composite key (`ByteKey`), so its leaves are in canonical
//! key order and its shape depends on the key set alone.
//!
//! - **Inclusion**: the branches on the leaf's path with their sibling digests.
//!   Directions are bits of the key and are not carried.
//! - **Absence**: the path that the bits of the absent key select, with the
//!   leaf it ends at disclosed. A committed key would be that leaf. The
//!   directions are read from the absent key, so a disclosed leaf that is not
//!   on the absent key's search path does not fold to the root; no separate
//!   check of the disclosed key's own bits is needed.
//! - **Complete range**: the shared postfix witness of the `fringe` module.
//!
//! An update rehashes one branch per level of each touched path. The depth is
//! about `log2(n)` for scattered keys and at most `9·len + 1` for adversarial
//! keys of `len` bytes.
//!
//! TODO(G.3): prototype for measurement only; delete or replace by the
//! selected construction.

use std::collections::BTreeMap;

use super::{
    Change, Engine, Reject, Storage,
    codec::{Reader, Writer},
    critbit::{ByteKey, CritbitTree, NodeView, PathStep, branch_digest, fold_path},
    entry_leaf, fringe,
    hash::{DIGEST_BYTES, Digest, HashProfile, ZERO_DIGEST},
    key_digest, keys_below, keys_from, leaf_digest, value_digest,
};

const ABSENCE_EMPTY: u8 = 0;
const ABSENCE_LEAF: u8 = 1;

/// Storage model: a persisted leaf keeps its digest and its value digest.
pub const MODEL_LEAF_BYTES: u64 = 64;
/// Storage model: a persisted branch keeps its digest, its 4-byte branching
/// bit index and two 4-byte child references.
pub const MODEL_BRANCH_BYTES: u64 = 44;

/// The radix tree with the value digest of every committed key.
pub struct RadixTree<H> {
    entries: BTreeMap<Vec<u8>, Digest>,
    tree: CritbitTree<ByteKey, H>,
}

impl<H> Clone for RadixTree<H> {
    fn clone(&self) -> Self {
        Self {
            entries: self.entries.clone(),
            tree: self.tree.clone(),
        }
    }
}

fn write_path(writer: &mut Writer, steps: &[PathStep]) {
    writer.count(steps.len());
    for step in steps {
        writer.u32(step.crit);
        writer.digest(&step.sibling);
    }
}

/// Read a root-to-leaf path whose directions are the bits of `key`, and
/// return it bottom-up. Branching bits must strictly increase toward the leaf.
fn read_path<H: HashProfile>(
    reader: &mut Reader<'_, H>,
    key: &[u8],
) -> Result<Vec<PathStep>, Reject> {
    let count = reader.count(4 + DIGEST_BYTES)?;
    let mut steps = Vec::with_capacity(count);
    let mut previous: Option<u32> = None;
    for _ in 0..count {
        let crit = reader.u32()?;
        let sibling = reader.digest()?;
        if previous.is_some_and(|previous| previous >= crit) {
            return Err(Reject::Malformed);
        }
        previous = Some(crit);
        steps.push(PathStep {
            crit,
            sibling,
            right: ByteKey::encoded_bit(key, crit),
        });
    }
    steps.reverse();
    Ok(steps)
}

/// The disclosed leaf and path of an absence witness of a nonempty tree.
pub(super) struct AbsenceOpening {
    /// Key of the leaf the absent key's bits lead to.
    pub(super) key: Vec<u8>,
    /// Value digest of that leaf.
    pub(super) value_digest: Digest,
    /// Path of that leaf, bottom-up.
    pub(super) path: Vec<PathStep>,
}

impl<H: HashProfile> RadixTree<H> {
    /// Parse an inclusion witness into the leaf's bottom-up path.
    pub(super) fn open_inclusion(key: &[u8], witness: &[u8]) -> Result<Vec<PathStep>, Reject> {
        let mut reader = Reader::<H>::new(witness);
        let steps = read_path(&mut reader, key)?;
        reader.finish()?;
        Ok(steps)
    }

    /// Parse an absence witness. `None` is the witness of the empty tree.
    pub(super) fn open_absence(
        key: &[u8],
        witness: &[u8],
    ) -> Result<Option<AbsenceOpening>, Reject> {
        let mut reader = Reader::<H>::new(witness);
        match reader.u8()? {
            ABSENCE_EMPTY => {
                reader.finish()?;
                Ok(None)
            }
            ABSENCE_LEAF => {
                let found = reader.bytes()?;
                let value_digest = reader.digest()?;
                let path = read_path(&mut reader, key)?;
                reader.finish()?;
                if found == key {
                    return Err(Reject::NotProven);
                }
                // The directions of `path` are the bits of the absent key.
                // A disclosed leaf off that search path folds to another
                // digest, so the root comparison refuses it.
                Ok(Some(AbsenceOpening {
                    key: found.to_vec(),
                    value_digest,
                    path,
                }))
            }
            _ => Err(Reject::Malformed),
        }
    }

    /// Parse a range witness into its opened tree.
    pub(super) fn open_range(
        lower: &[u8],
        upper: Option<&[u8]>,
        entries: &[(&[u8], &[u8])],
        witness: &[u8],
    ) -> Result<fringe::Opened, Reject> {
        fringe::open::<H>(lower, upper, entries, witness, |crit, left, right| {
            Some(branch_digest::<H>(crit, left, right))
        })
    }

    fn emit(
        &self,
        index: u32,
        lower: &[u8],
        upper: Option<&[u8]>,
        first: Option<&[u8]>,
        last: Option<&[u8]>,
        out: &mut fringe::Builder,
    ) {
        match self.tree.node(index) {
            NodeView::Leaf { key, digest } => {
                let key = key.0.as_slice();
                if first.is_some_and(|first| key < first) || last.is_some_and(|last| key > last) {
                    out.hidden(&digest);
                } else if key < lower || upper.is_some_and(|upper| key >= upper) {
                    out.boundary(key, &self.entries[key]);
                } else {
                    out.claimed();
                }
            }
            NodeView::Branch {
                crit,
                left,
                right,
                digest,
            } => {
                let outside = first
                    .is_some_and(|first| self.tree.rightmost(index).0.as_slice() < first)
                    || last.is_some_and(|last| self.tree.leftmost(index).0.as_slice() > last);
                if outside {
                    out.hidden(&digest);
                } else {
                    self.emit(left, lower, upper, first, last, out);
                    self.emit(right, lower, upper, first, last, out);
                    out.branch(crit);
                }
            }
        }
    }
}

impl<H: HashProfile> Engine for RadixTree<H> {
    type Hash = H;

    const CONSTRUCTION: &'static str = "sparse-radix-critbit-merkle/key-order/v0";

    fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            tree: CritbitTree::new(),
        }
    }

    fn apply(&mut self, changes: &[Change<'_>]) {
        for (key, value) in changes {
            match value {
                Some(value) => {
                    let digest = value_digest::<H>(value);
                    if self.entries.get(*key) == Some(&digest) {
                        continue;
                    }
                    self.entries.insert(key.to_vec(), digest);
                    self.tree.set(
                        ByteKey(key.to_vec()),
                        leaf_digest::<H>(&key_digest::<H>(key), &digest),
                    );
                }
                None => {
                    if self.entries.remove(*key).is_some() {
                        self.tree.remove(&ByteKey(key.to_vec()));
                    }
                }
            }
        }
        self.tree.rehash();
    }

    fn structure_root(&self) -> Digest {
        self.tree.root()
    }

    fn len(&self) -> u64 {
        self.tree.len()
    }

    fn prove_inclusion(&self, key: &[u8]) -> Option<Vec<u8>> {
        if !self.entries.contains_key(key) {
            return None;
        }
        let (_, _, steps) = self.tree.search(&ByteKey(key.to_vec()))?;
        let mut writer = Writer::default();
        write_path(&mut writer, &steps);
        Some(writer.finish())
    }

    fn prove_absence(&self, key: &[u8]) -> Option<Vec<u8>> {
        if self.entries.contains_key(key) {
            return None;
        }
        let mut writer = Writer::default();
        match self.tree.search(&ByteKey(key.to_vec())) {
            None => writer.u8(ABSENCE_EMPTY),
            Some((found, _, steps)) => {
                writer.u8(ABSENCE_LEAF);
                writer.bytes(&found.0);
                writer.digest(&self.entries[&found.0]);
                write_path(&mut writer, &steps);
            }
        }
        Some(writer.finish())
    }

    fn prove_range(&self, lower: &[u8], upper: Option<&[u8]>) -> Vec<u8> {
        let mut out = fringe::Builder::default();
        if let Some(root) = self.tree.root_index() {
            let first = self.entries.range::<[u8], _>(keys_below(lower)).next_back();
            let last =
                upper.and_then(|upper| self.entries.range::<[u8], _>(keys_from(upper)).next());
            self.emit(
                root,
                lower,
                upper,
                first.map(|(key, _)| key.as_slice()),
                last.map(|(key, _)| key.as_slice()),
                &mut out,
            );
        }
        out.finish()
    }

    fn inclusion_root(key: &[u8], value: &[u8], witness: &[u8]) -> Result<Digest, Reject> {
        let path = Self::open_inclusion(key, witness)?;
        Ok(fold_path::<H>(entry_leaf::<H>(key, value), path))
    }

    fn absence_root(key: &[u8], witness: &[u8]) -> Result<Digest, Reject> {
        Ok(match Self::open_absence(key, witness)? {
            None => ZERO_DIGEST,
            Some(opening) => fold_path::<H>(
                leaf_digest::<H>(&key_digest::<H>(&opening.key), &opening.value_digest),
                opening.path,
            ),
        })
    }

    fn range_root(
        lower: &[u8],
        upper: Option<&[u8]>,
        entries: &[(&[u8], &[u8])],
        witness: &[u8],
    ) -> Result<Digest, Reject> {
        Self::open_range(lower, upper, entries, witness).map(|opened| opened.root)
    }

    fn storage(&self) -> Storage {
        // Counted from the node arena, not derived from the entry count.
        let (leaves, branches) = self.tree.counts();
        Storage {
            entries: self.entries.len() as u64,
            digests: 2 * leaves + branches,
            structure_bytes: leaves * MODEL_LEAF_BYTES + branches * MODEL_BRANCH_BYTES,
            // The prototype's sorted map only shortcuts neighbour lookups that
            // the tree itself answers in one descent.
            auxiliary_bytes: 0,
            max_depth: self.tree.max_depth(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_commitment_prototypes::hash::Blake2bProfile;

    type Tree = RadixTree<Blake2bProfile>;

    fn tree(keys: &[&[u8]]) -> Tree {
        let mut tree = Tree::new();
        let changes: Vec<Change<'_>> = keys.iter().map(|key| (*key, Some(&b"v"[..]))).collect();
        tree.apply(&changes);
        tree
    }

    /// The storage model counts the nodes the arena holds: one leaf per entry
    /// and one branch per leaf but one, also after removals.
    #[test]
    fn storage_model_counts_the_nodes_of_the_arena() {
        let keys: [&[u8]; 6] = [b"a", b"ab", b"b", b"ba", b"c", b"\xff"];
        let mut tree = tree(&keys);
        assert_eq!(tree.tree.counts(), (6, 5));
        let storage = tree.storage();
        assert_eq!((storage.entries, storage.digests), (6, 2 * 6 + 5));
        assert_eq!(storage.structure_bytes, 6 * 64 + 5 * 44);
        assert_eq!(storage.auxiliary_bytes, 0);
        tree.apply(&[(b"ab", None), (b"c", None), (b"new", Some(b"v"))]);
        assert_eq!(tree.tree.counts(), (5, 4));
        assert_eq!(tree.storage().structure_bytes, 5 * 64 + 4 * 44);
        let copy = tree.clone();
        assert_eq!(copy.structure_root(), tree.structure_root());
        assert_eq!(copy.storage(), tree.storage());
        assert_eq!(Tree::new().storage(), Storage::default());
    }

    /// An absence witness that discloses a leaf off the absent key's search
    /// path is well formed, opens, and folds to a digest that is not the root.
    #[test]
    fn off_path_absence_leaf_opens_and_does_not_fold_to_the_root() {
        let tree = tree(&[b"a", b"b", b"c", b"d"]);
        let root = tree.structure_root();
        // The honest witness of the absent `bb` ends at a committed neighbour.
        let honest = tree.prove_absence(b"bb").unwrap();
        assert_eq!(Tree::absence_root(b"bb", &honest), Ok(root));
        // Claim the committed `c` absent by disclosing `a` with its real path.
        let mut forged = Writer::default();
        forged.u8(ABSENCE_LEAF);
        forged.bytes(b"a");
        forged.digest(&value_digest::<Blake2bProfile>(b"v"));
        let (_, _, steps) = tree.tree.search(&ByteKey(b"a".to_vec())).unwrap();
        write_path(&mut forged, &steps);
        let forged = forged.finish();
        let opening = Tree::open_absence(b"c", &forged)
            .expect("the witness is canonical")
            .expect("the tree is not empty");
        assert_eq!(opening.key, b"a");
        // The sides are bits of `c`, which leave the path of `a`.
        assert!(
            opening
                .path
                .iter()
                .any(|step| ByteKey::encoded_bit(b"a", step.crit) != step.right)
        );
        let folded = Tree::absence_root(b"c", &forged).unwrap();
        assert_ne!(folded, root);
        // The same disclosure for its own key is refused outright.
        assert_eq!(Tree::absence_root(b"a", &forged), Err(Reject::NotProven));
        // The empty tree and an unknown tag.
        assert_eq!(
            Tree::absence_root(b"k", &Tree::new().prove_absence(b"k").unwrap()),
            Ok(ZERO_DIGEST)
        );
        assert_eq!(Tree::absence_root(b"k", &[7]), Err(Reject::Malformed));
    }
}
