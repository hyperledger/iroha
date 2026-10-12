//! Candidate 3: indexed linked-leaf Merkle map.
//!
//! Every leaf binds its key digest, its value digest and the key digest of the
//! next key in canonical order, so the committed keys form one authenticated
//! sorted list from a lower sentinel to an upper sentinel. The leaves live in a
//! compressed sparse Merkle tree addressed by key digest, so a leaf's position
//! depends on its key alone, never on insertion order.
//!
//! - **Inclusion**: the successor's key digest and the leaf's address path.
//! - **Absence**: the leaf whose key and successor bracket the absent key,
//!   with both keys disclosed, and its address path. No second path is needed.
//! - **Complete range**: the bracketing leaf below the interval, every claimed
//!   leaf with its address path and the disclosed successor of the last one;
//!   each leaf's successor digest must be the next claimed key.
//!
//! An insertion or removal rewrites two leaves (the key's and its
//! predecessor's); a value update rewrites one. The sorted key index that
//! finds neighbours is not authenticated: the leaves carry the order.
//!
//! TODO(G.3): prototype for measurement only; delete or replace by the
//! selected construction.

use core::ops::Bound;
use std::collections::{BTreeMap, BTreeSet};

use super::{
    Change, DOMAIN_BOUND_END, DOMAIN_BOUND_HEAD, DOMAIN_KEY, DOMAIN_LINK, Engine, Reject, Storage,
    codec::{Reader, Writer},
    critbit::{BitKey, CritbitTree, PathStep, fold_path},
    hash::{DIGEST_BYTES, Digest, HashProfile, ZERO_DIGEST},
    key_digest, keys_below, leaf_digest, value_digest,
};

const BOUND_HEAD: u8 = 0;
const BOUND_KEY: u8 = 1;
const BOUND_END: u8 = 2;

/// Storage model: a persisted leaf keeps its digest, its address and its
/// value digest.
pub const MODEL_LEAF_BYTES: u64 = 96;
/// Storage model: a persisted branch keeps its digest, its 4-byte branching
/// bit index and two 4-byte child references.
pub const MODEL_BRANCH_BYTES: u64 = 44;
/// Storage model: the unauthenticated sorted index keeps one 8-byte key
/// reference per entry.
pub const MODEL_INDEX_ENTRY_BYTES: u64 = 8;

/// One end of a link: a committed key or a sentinel. The derived order is the
/// canonical one: the lower sentinel, the keys in byte order, the upper sentinel.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Link {
    /// Below every key.
    Head,
    /// A committed key.
    Key(Vec<u8>),
    /// Above every key.
    End,
}

impl Link {
    /// Domain and bytes whose byte-string hash is the digest a leaf binds for
    /// this end.
    pub(super) fn preimage(&self) -> (u64, &[u8]) {
        match self {
            Self::Head => (DOMAIN_BOUND_HEAD, &[]),
            Self::Key(key) => (DOMAIN_KEY, key),
            Self::End => (DOMAIN_BOUND_END, &[]),
        }
    }

    /// Digest that a leaf binds for this end.
    pub(super) fn digest<H: HashProfile>(&self) -> Digest {
        let (domain, bytes) = self.preimage();
        H::hash_bytes(domain, bytes)
    }

    fn write(&self, writer: &mut Writer) {
        match self {
            Self::Head => writer.u8(BOUND_HEAD),
            Self::Key(key) => {
                writer.u8(BOUND_KEY);
                writer.bytes(key);
            }
            Self::End => writer.u8(BOUND_END),
        }
    }

    fn read<H: HashProfile>(reader: &mut Reader<'_, H>) -> Result<Self, Reject> {
        match reader.u8()? {
            BOUND_HEAD => Ok(Self::Head),
            BOUND_KEY => Ok(Self::Key(reader.bytes()?.to_vec())),
            BOUND_END => Ok(Self::End),
            _ => Err(Reject::Malformed),
        }
    }

    /// Whether this end lies strictly below `key`.
    fn is_below(&self, key: &[u8]) -> bool {
        match self {
            Self::Head => true,
            Self::Key(own) => own.as_slice() < key,
            Self::End => false,
        }
    }

    /// Whether this end lies at or above `bound`; `None` is unbounded.
    fn is_at_or_above(&self, bound: Option<&[u8]>) -> bool {
        match (self, bound) {
            (Self::End, _) => true,
            (Self::Key(own), Some(bound)) => own.as_slice() >= bound,
            (Self::Key(_), None) | (Self::Head, _) => false,
        }
    }
}

/// Digest of a linked leaf.
pub(super) fn link_leaf<H: HashProfile>(key: &Digest, value: &Digest, next: &Digest) -> Digest {
    H::compress(DOMAIN_LINK, 0, &leaf_digest::<H>(key, value), next)
}

/// One disclosed leaf of a witness with its address path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct LinkedLeaf {
    /// The leaf's own end: the lower sentinel or a key.
    pub(super) own: Link,
    /// Digest of the leaf's own end: its address.
    pub(super) own_digest: Digest,
    /// The leaf's value digest; zero for the sentinel.
    pub(super) value_digest: Digest,
    /// Key digest of the leaf's successor.
    pub(super) next_digest: Digest,
    /// Address path, bottom-up.
    pub(super) path: Vec<PathStep>,
}

impl LinkedLeaf {
    fn root<H: HashProfile>(&self) -> Digest {
        fold_path::<H>(
            link_leaf::<H>(&self.own_digest, &self.value_digest, &self.next_digest),
            self.path.iter().copied(),
        )
    }
}

/// The map: a sorted index of key and value digests and the address tree.
pub struct LinkedLeafMap<H> {
    index: BTreeMap<Vec<u8>, (Digest, Digest)>,
    tree: CritbitTree<Digest, H>,
}

impl<H> Clone for LinkedLeafMap<H> {
    fn clone(&self) -> Self {
        Self {
            index: self.index.clone(),
            tree: self.tree.clone(),
        }
    }
}

/// What a complete-range witness would carry and hash if the address paths of
/// its leaves shared their common nodes (a multiproof), which the prototype
/// witness does not do: it carries one whole path per leaf.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SharedPaths {
    /// Leaves of the witness: the bracketing leaf and one per claimed entry.
    pub leaves: u64,
    /// Path steps the prototype witness carries, one sibling digest each.
    pub carried_steps: u64,
    /// Distinct branches on the union of the paths: the compressions a
    /// verifier of the shared form computes above the leaves.
    pub distinct_branches: u64,
    /// Sibling digests the shared form still has to carry: those that are
    /// neither another leaf of the witness nor a branch on the union.
    pub carried_siblings: u64,
}

fn write_path(writer: &mut Writer, steps: &[PathStep]) {
    writer.count(steps.len());
    for step in steps {
        writer.u32(step.crit);
        writer.digest(&step.sibling);
    }
}

/// Read a root-to-leaf address path and return it bottom-up.
fn read_path<H: HashProfile>(
    reader: &mut Reader<'_, H>,
    address: &Digest,
) -> Result<Vec<PathStep>, Reject> {
    let count = reader.count(4 + DIGEST_BYTES)?;
    let mut steps = Vec::with_capacity(count);
    let mut previous: Option<u32> = None;
    for _ in 0..count {
        let crit = reader.u32()?;
        let sibling = reader.digest()?;
        if crit >= 256 || previous.is_some_and(|previous| previous >= crit) {
            return Err(Reject::Malformed);
        }
        previous = Some(crit);
        steps.push(PathStep {
            crit,
            sibling,
            right: address.bit(crit),
        });
    }
    steps.reverse();
    Ok(steps)
}

impl<H: HashProfile> LinkedLeafMap<H> {
    fn address_path(&self, address: &Digest) -> Vec<PathStep> {
        self.tree
            .search(address)
            .expect("the address tree always holds the lower sentinel")
            .2
    }

    /// The end that follows `own` in the sorted index.
    fn successor(&self, own: &Link) -> Link {
        let next = match own {
            Link::Head => self.index.keys().next(),
            Link::Key(key) => self
                .index
                .range::<[u8], _>((Bound::Excluded(key.as_slice()), Bound::Unbounded))
                .next()
                .map(|(key, _)| key),
            Link::End => None,
        };
        next.map_or(Link::End, |key| Link::Key(key.clone()))
    }

    /// The end that precedes `key` in the sorted index.
    fn predecessor(&self, key: &[u8]) -> Link {
        self.index
            .range::<[u8], _>(keys_below(key))
            .next_back()
            .map_or(Link::Head, |(key, _)| Link::Key(key.clone()))
    }

    /// Key digest and value digest of a present end.
    fn digests(&self, own: &Link) -> (Digest, Digest) {
        match own {
            Link::Head => (own.digest::<H>(), ZERO_DIGEST),
            Link::Key(key) => self.index[key],
            Link::End => unreachable!("the upper sentinel has no leaf"),
        }
    }

    fn successor_digest(&self, own: &Link) -> Digest {
        match self.successor(own) {
            Link::Key(key) => self.index[&key].0,
            end => end.digest::<H>(),
        }
    }

    /// Parse an inclusion witness: the successor digest and the bottom-up path.
    pub(super) fn open_inclusion(key: &[u8], witness: &[u8]) -> Result<LinkedLeaf, Reject> {
        let mut reader = Reader::<H>::new(witness);
        let next_digest = reader.digest()?;
        let own = Link::Key(key.to_vec());
        let own_digest = own.digest::<H>();
        let path = read_path(&mut reader, &own_digest)?;
        reader.finish()?;
        Ok(LinkedLeaf {
            own,
            own_digest,
            // The statement supplies the value; the caller fills it in.
            value_digest: ZERO_DIGEST,
            next_digest,
            path,
        })
    }

    fn read_bracket(reader: &mut Reader<'_, H>) -> Result<(Link, Digest), Reject> {
        let own = Link::read(reader)?;
        let value_digest = match own {
            Link::Head => ZERO_DIGEST,
            Link::Key(_) => reader.digest()?,
            Link::End => return Err(Reject::Malformed),
        };
        Ok((own, value_digest))
    }

    /// Parse an absence witness: the bracketing leaf with both ends disclosed.
    /// Returns the leaf and its disclosed successor.
    pub(super) fn open_absence(key: &[u8], witness: &[u8]) -> Result<(LinkedLeaf, Link), Reject> {
        let mut reader = Reader::<H>::new(witness);
        let (own, value_digest) = Self::read_bracket(&mut reader)?;
        let next = Link::read(&mut reader)?;
        if next == Link::Head {
            return Err(Reject::Malformed);
        }
        let own_digest = own.digest::<H>();
        let path = read_path(&mut reader, &own_digest)?;
        reader.finish()?;
        if !own.is_below(key) || !next.is_at_or_above(Some(&super::immediate_successor(key))) {
            return Err(Reject::NotProven);
        }
        let next_digest = next.digest::<H>();
        Ok((
            LinkedLeaf {
                own,
                own_digest,
                value_digest,
                next_digest,
                path,
            },
            next,
        ))
    }

    /// Parse a range witness: the bracketing leaf below the interval, then one
    /// leaf per claimed entry, each linked to the next. Returns the leaves and
    /// the disclosed successor of the last one.
    pub(super) fn open_range(
        lower: &[u8],
        upper: Option<&[u8]>,
        entries: &[(&[u8], &[u8])],
        witness: &[u8],
    ) -> Result<(Vec<LinkedLeaf>, Link), Reject> {
        let mut reader = Reader::<H>::new(witness);
        let (own, bracket_value) = Self::read_bracket(&mut reader)?;
        let mut leaves = Vec::with_capacity(entries.len() + 1);
        let own_digest = own.digest::<H>();
        let path = read_path(&mut reader, &own_digest)?;
        leaves.push(LinkedLeaf {
            own,
            own_digest,
            value_digest: bracket_value,
            next_digest: ZERO_DIGEST,
            path,
        });
        for (key, value) in entries {
            let own = Link::Key(key.to_vec());
            let own_digest = own.digest::<H>();
            // Each leaf is the successor of the one before it.
            leaves
                .last_mut()
                .expect("the bracketing leaf was pushed")
                .next_digest = own_digest;
            let path = read_path(&mut reader, &own_digest)?;
            leaves.push(LinkedLeaf {
                own,
                own_digest,
                value_digest: value_digest::<H>(value),
                next_digest: ZERO_DIGEST,
                path,
            });
        }
        let last = Link::read(&mut reader)?;
        reader.finish()?;
        if last == Link::Head {
            return Err(Reject::Malformed);
        }
        if !leaves[0].own.is_below(lower) || !last.is_at_or_above(upper) {
            return Err(Reject::NotProven);
        }
        leaves
            .last_mut()
            .expect("the bracketing leaf was pushed")
            .next_digest = last.digest::<H>();
        Ok((leaves, last))
    }
}

impl<H: HashProfile> Engine for LinkedLeafMap<H> {
    type Hash = H;

    const CONSTRUCTION: &'static str = "indexed-linked-leaf-merkle-map/hashed-address-critbit/v0";

    fn new() -> Self {
        let mut map = Self {
            index: BTreeMap::new(),
            tree: CritbitTree::new(),
        };
        let head = Link::Head.digest::<H>();
        map.tree.set(
            head,
            link_leaf::<H>(&head, &ZERO_DIGEST, &Link::End.digest::<H>()),
        );
        map.tree.rehash();
        map
    }

    fn apply(&mut self, changes: &[Change<'_>]) {
        let mut touched: BTreeSet<Vec<u8>> = BTreeSet::new();
        for (key, value) in changes {
            match value {
                Some(value) => {
                    let digest = value_digest::<H>(value);
                    match self.index.get_mut(*key) {
                        Some((_, stored)) if *stored == digest => continue,
                        Some((_, stored)) => *stored = digest,
                        None => {
                            self.index
                                .insert(key.to_vec(), (key_digest::<H>(key), digest));
                        }
                    }
                    touched.insert(key.to_vec());
                }
                None => {
                    if let Some((address, _)) = self.index.remove(*key) {
                        self.tree.remove(&address);
                        touched.insert(key.to_vec());
                    }
                }
            }
        }
        // A touched key's own leaf and its predecessor's leaf are rewritten
        // against the final order.
        let mut relink: BTreeSet<Link> = BTreeSet::new();
        for key in &touched {
            if self.index.contains_key(key) {
                relink.insert(Link::Key(key.clone()));
            }
            relink.insert(self.predecessor(key));
        }
        for own in relink {
            let (address, value) = self.digests(&own);
            let next = self.successor_digest(&own);
            self.tree
                .set(address, link_leaf::<H>(&address, &value, &next));
        }
        self.tree.rehash();
    }

    fn structure_root(&self) -> Digest {
        self.tree.root()
    }

    fn len(&self) -> u64 {
        self.index.len() as u64
    }

    fn prove_inclusion(&self, key: &[u8]) -> Option<Vec<u8>> {
        let (address, _) = self.index.get(key)?;
        let mut writer = Writer::default();
        writer.digest(&self.successor_digest(&Link::Key(key.to_vec())));
        write_path(&mut writer, &self.address_path(address));
        Some(writer.finish())
    }

    fn prove_absence(&self, key: &[u8]) -> Option<Vec<u8>> {
        if self.index.contains_key(key) {
            return None;
        }
        let own = self.predecessor(key);
        let (address, value) = self.digests(&own);
        let mut writer = Writer::default();
        own.write(&mut writer);
        if own != Link::Head {
            writer.digest(&value);
        }
        self.successor(&own).write(&mut writer);
        write_path(&mut writer, &self.address_path(&address));
        Some(writer.finish())
    }

    fn prove_range(&self, lower: &[u8], upper: Option<&[u8]>) -> Vec<u8> {
        let own = self.predecessor(lower);
        let (address, value) = self.digests(&own);
        let mut writer = Writer::default();
        own.write(&mut writer);
        if own != Link::Head {
            writer.digest(&value);
        }
        write_path(&mut writer, &self.address_path(&address));
        let end = upper.map_or(Bound::Unbounded, Bound::Excluded);
        let mut last = own;
        for (key, (address, _)) in self.index.range::<[u8], _>((Bound::Included(lower), end)) {
            write_path(&mut writer, &self.address_path(address));
            last = Link::Key(key.clone());
        }
        self.successor(&last).write(&mut writer);
        writer.finish()
    }

    fn inclusion_root(key: &[u8], value: &[u8], witness: &[u8]) -> Result<Digest, Reject> {
        let mut leaf = Self::open_inclusion(key, witness)?;
        leaf.value_digest = value_digest::<H>(value);
        Ok(leaf.root::<H>())
    }

    fn absence_root(key: &[u8], witness: &[u8]) -> Result<Digest, Reject> {
        Ok(Self::open_absence(key, witness)?.0.root::<H>())
    }

    fn range_root(
        lower: &[u8],
        upper: Option<&[u8]>,
        entries: &[(&[u8], &[u8])],
        witness: &[u8],
    ) -> Result<Digest, Reject> {
        let (leaves, _) = Self::open_range(lower, upper, entries, witness)?;
        let root = leaves[0].root::<H>();
        if leaves[1..].iter().all(|leaf| leaf.root::<H>() == root) {
            Ok(root)
        } else {
            Err(Reject::NotProven)
        }
    }

    fn storage(&self) -> Storage {
        let entries = self.index.len() as u64;
        // One leaf per entry plus the sentinel and one branch per leaf but
        // one, counted from the address tree's arena.
        let (leaves, branches) = self.tree.counts();
        Storage {
            entries,
            // Leaf digest, address and value digest per leaf; one per branch.
            digests: 3 * leaves + branches,
            structure_bytes: leaves * MODEL_LEAF_BYTES + branches * MODEL_BRANCH_BYTES,
            auxiliary_bytes: entries * MODEL_INDEX_ENTRY_BYTES,
            max_depth: self.tree.max_depth(),
        }
    }
}

impl<H: HashProfile> LinkedLeafMap<H> {
    /// Count what the shared-path form of an accepted complete-range witness
    /// would hash and carry. `None` when the witness is not canonical for the
    /// statement. The count folds every path, so it costs as much hashing as
    /// verification does.
    #[must_use]
    pub fn shared_paths(
        lower: &[u8],
        upper: Option<&[u8]>,
        entries: &[(&[u8], &[u8])],
        witness: &[u8],
    ) -> Option<SharedPaths> {
        let (leaves, _) = Self::open_range(lower, upper, entries, witness).ok()?;
        let mut computed: BTreeSet<Digest> = BTreeSet::new();
        let mut siblings: BTreeSet<Digest> = BTreeSet::new();
        let mut branches: BTreeSet<Digest> = BTreeSet::new();
        let mut carried_steps = 0;
        for leaf in &leaves {
            let mut digest =
                link_leaf::<H>(&leaf.own_digest, &leaf.value_digest, &leaf.next_digest);
            computed.insert(digest);
            for step in &leaf.path {
                carried_steps += 1;
                siblings.insert(step.sibling);
                digest = fold_path::<H>(digest, core::iter::once(*step));
                computed.insert(digest);
                branches.insert(digest);
            }
        }
        Some(SharedPaths {
            leaves: leaves.len() as u64,
            carried_steps,
            distinct_branches: branches.len() as u64,
            carried_siblings: siblings.difference(&computed).count() as u64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_commitment_prototypes::{hash::Blake2bProfile, workload::SplitMix64};

    type Map = LinkedLeafMap<Blake2bProfile>;
    type Content = Vec<(Vec<u8>, Vec<u8>)>;

    fn map(count: usize) -> (Map, Content) {
        let mut generator = SplitMix64::new(11);
        let mut content: Content = (0..count)
            .map(|_| {
                let mut key = vec![0_u8; 8];
                generator.fill(&mut key);
                (key, vec![7])
            })
            .collect();
        content.sort();
        let changes: Vec<Change<'_>> = content
            .iter()
            .map(|(key, value)| (key.as_slice(), Some(value.as_slice())))
            .collect();
        let mut map = Map::new();
        map.apply(&changes);
        (map, content)
    }

    /// The storage model counts the leaves and branches of the address tree:
    /// the sentinel is a leaf, and a branch joins every leaf but one.
    #[test]
    fn storage_model_counts_the_nodes_of_the_address_tree() {
        let (mut map, content) = map(40);
        assert_eq!(map.tree.counts(), (41, 40));
        let storage = map.storage();
        assert_eq!(storage.entries, 40);
        assert_eq!(storage.digests, 3 * 41 + 40);
        assert_eq!(storage.structure_bytes, 41 * 96 + 40 * 44);
        assert_eq!(storage.auxiliary_bytes, 40 * 8);
        map.apply(&[(content[3].0.as_slice(), None)]);
        assert_eq!(map.tree.counts(), (40, 39));
        let copy = map.clone();
        assert_eq!(copy.structure_root(), map.structure_root());
        assert_eq!(copy.storage(), map.storage());
        // The empty map holds the sentinel alone.
        let empty = Map::new().storage();
        assert_eq!((empty.entries, empty.digests), (0, 3));
        assert_eq!((empty.structure_bytes, empty.auxiliary_bytes), (96, 0));
    }

    /// Sharing the address paths of a range hashes every branch of their union
    /// once and carries only the siblings outside it.
    #[test]
    fn shared_paths_count_the_union_of_the_address_paths() {
        let (map, content) = map(200);
        let root = map.structure_root();
        let run = &content[20..60];
        let (lower, upper) = (run[0].0.as_slice(), content[60].0.as_slice());
        let entries: Vec<(&[u8], &[u8])> = run
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice()))
            .collect();
        let witness = map.prove_range(lower, Some(upper));
        assert_eq!(
            Map::range_root(lower, Some(upper), &entries, &witness),
            Ok(root)
        );
        let shared = Map::shared_paths(lower, Some(upper), &entries, &witness).unwrap();
        assert_eq!(shared.leaves, 41);
        // Every leaf carries its whole path; the union is much smaller, and a
        // tree over 41 leaves joins them with at least 40 branches.
        assert!(shared.carried_steps > 41 * 5, "{shared:?}");
        assert!(shared.distinct_branches >= 40, "{shared:?}");
        assert!(
            shared.distinct_branches < shared.carried_steps / 2,
            "{shared:?}"
        );
        assert!(
            shared.carried_siblings < shared.carried_steps / 2,
            "{shared:?}"
        );
        // A binary tree: the branches of the union have twice as many child
        // slots as branches, filled by the leaves, the lower branches and the
        // carried siblings.
        assert_eq!(
            2 * shared.distinct_branches,
            shared.leaves + (shared.distinct_branches - 1) + shared.carried_siblings
        );
        // One leaf alone shares nothing.
        let single = map.prove_range(b"", Some(content[0].0.as_slice()));
        let alone = Map::shared_paths(b"", Some(content[0].0.as_slice()), &[], &single).unwrap();
        assert_eq!(alone.leaves, 1);
        assert_eq!(alone.distinct_branches, alone.carried_steps);
        assert_eq!(alone.carried_siblings, alone.carried_steps);
        // A witness that is not one of the statement has no count.
        assert_eq!(
            Map::shared_paths(lower, Some(upper), &entries[1..], &witness),
            None
        );
    }
}
