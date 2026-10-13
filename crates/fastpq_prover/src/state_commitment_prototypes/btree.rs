//! Candidate 2: canonical sorted Merkle B-tree with content-defined pages.
//!
//! A classical B-tree's shape depends on its insertion history, and a fixed
//! left-packed layout rewrites every page after an insertion. This candidate
//! keeps the layout a function of the key set by letting the keys choose the
//! page boundaries: a key ends a page of level `l` when its key digest has at
//! least `l + 1` leading zero nibbles, so a page holds sixteen items on
//! average at every level. Level 0 is the sorted entries; level `l + 1` holds
//! one item per page of level `l`, keyed by the page's last key; the root is
//! the single item of the first level that has one.
//!
//! A page digest is the Merkle tree hash of its items (left subtree: the
//! largest power of two below the item count), so the whole structure is one
//! binary tree over the sorted leaves and a path carries about four siblings
//! per level instead of fifteen.
//!
//! - **Inclusion**: the sibling digests of the leaf's path with their sides.
//! - **Absence** and **complete range**: the postfix witness of
//!   the `fringe` module; absence is the empty range `[key, key ‖ 0x00)`.
//!
//! An update rehashes every page on the path of each touched key (about
//! fifteen compressions per level), and a key that becomes or stops being a
//! boundary also rehashes the following page. Page sizes are geometric, not
//! bounded: a party that chooses keys can grind long pages.
//!
//! TODO(G.3): prototype for measurement only; delete or replace by the
//! selected construction.

use core::{marker::PhantomData, ops::Bound};
use std::collections::{BTreeMap, BTreeSet};

use super::{
    Change, DOMAIN_PAGE_NODE, Engine, Reject, Storage,
    codec::{Reader, Writer},
    critbit::PathStep,
    entry_leaf, fringe,
    hash::{DIGEST_BYTES, Digest, HashProfile, ZERO_DIGEST},
    immediate_successor, key_digest, keys_below, keys_from, leaf_digest, value_digest,
};

/// Leading zero nibbles a key digest needs per level to end a page there.
const NIBBLE_BITS: u32 = 4;

/// Storage model: a persisted entry keeps its leaf digest, its value digest
/// and its one-byte boundary count.
pub const MODEL_ENTRY_BYTES: u64 = 65;
/// Storage model: a persisted upper item keeps its page digest, an 8-byte
/// reference to its last key and its one-byte boundary count. Page-internal
/// nodes are recomputed, not stored.
pub const MODEL_UPPER_ITEM_BYTES: u64 = 41;

#[derive(Clone, Copy)]
struct Item {
    digest: Digest,
    /// Number of levels at which the item's key ends a page.
    boundary: u8,
}

/// The B-tree: one sorted map of items per level.
pub struct MerkleBTree<H> {
    values: BTreeMap<Vec<u8>, Digest>,
    levels: Vec<BTreeMap<Vec<u8>, Item>>,
    profile: PhantomData<H>,
}

impl<H> Clone for MerkleBTree<H> {
    fn clone(&self) -> Self {
        Self {
            values: self.values.clone(),
            levels: self.levels.clone(),
            profile: PhantomData,
        }
    }
}

fn node<H: HashProfile>(left: &Digest, right: &Digest) -> Digest {
    H::compress(DOMAIN_PAGE_NODE, 0, left, right)
}

/// Number of levels at which a key ends a page.
fn boundary_levels(key_digest: &Digest) -> u8 {
    u8::try_from(key_digest[3].leading_zeros() / NIBBLE_BITS).expect("at most sixteen nibbles")
}

/// Size of the left subtree of a Merkle tree over `count >= 2` items.
fn split(count: usize) -> usize {
    1 << (usize::BITS - 1 - (count - 1).leading_zeros())
}

/// Merkle tree hash of a nonempty list of digests.
fn tree_hash<H: HashProfile>(items: &[Digest]) -> Digest {
    if let [single] = items {
        *single
    } else {
        let (left, right) = items.split_at(split(items.len()));
        node::<H>(&tree_hash::<H>(left), &tree_hash::<H>(right))
    }
}

/// Bottom-up path of item `index` inside a page.
fn page_path<H: HashProfile>(items: &[Digest], index: usize, out: &mut Vec<PathStep>) {
    if items.len() < 2 {
        return;
    }
    let (left, right) = items.split_at(split(items.len()));
    if index < left.len() {
        page_path::<H>(left, index, out);
        out.push(PathStep {
            crit: 0,
            sibling: tree_hash::<H>(right),
            right: false,
        });
    } else {
        page_path::<H>(right, index - left.len(), out);
        out.push(PathStep {
            crit: 0,
            sibling: tree_hash::<H>(left),
            right: true,
        });
    }
}

fn fold<H: HashProfile>(leaf: Digest, path: &[PathStep]) -> Digest {
    path.iter().fold(leaf, |digest, step| {
        if step.right {
            node::<H>(&step.sibling, &digest)
        } else {
            node::<H>(&digest, &step.sibling)
        }
    })
}

/// The interval of revealed keys of one range witness.
struct Reveal<'a> {
    lower: &'a [u8],
    upper: Option<&'a [u8]>,
    first: Option<&'a [u8]>,
    last: Option<&'a [u8]>,
}

impl Reveal<'_> {
    /// Whether every key in `[min, max]` is outside the revealed interval.
    fn hides(&self, min: &[u8], max: &[u8]) -> bool {
        self.first.is_some_and(|first| max < first) || self.last.is_some_and(|last| min > last)
    }
}

impl<H: HashProfile> MerkleBTree<H> {
    /// Index of the level that holds the root item.
    fn top(&self) -> usize {
        self.levels.len() - 1
    }

    /// The items of the page of `level` that contains `key`, in order.
    fn page(&self, level: usize, key: &[u8]) -> Vec<(&Vec<u8>, Item)> {
        let threshold = u8::try_from(level + 1).expect("at most seventeen levels");
        let items = &self.levels[level];
        let start = items
            .range::<[u8], _>(keys_below(key))
            .rev()
            .find(|(_, item)| item.boundary >= threshold)
            .map(|(key, _)| key.as_slice());
        let from = start.map_or(Bound::Unbounded, Bound::Excluded);
        let mut page = Vec::new();
        for (candidate, item) in items.range::<[u8], _>((from, Bound::Unbounded)) {
            page.push((candidate, *item));
            if item.boundary >= threshold && candidate.as_slice() >= key {
                break;
            }
        }
        page
    }

    /// Recompute the pages of `level` that hold a dirty key and return the
    /// keys of the next level whose item changed.
    fn rebuild(&mut self, level: usize, dirty: &BTreeSet<Vec<u8>>) -> BTreeSet<Vec<u8>> {
        let threshold = u8::try_from(level + 1).expect("at most seventeen levels");
        let (lower, upper) = self.levels.split_at_mut(level + 1);
        let (current, next) = (&lower[level], &mut upper[0]);
        let mut removed: BTreeMap<Vec<u8>, Digest> = BTreeMap::new();
        // Keys that were page ends before this rebuild.
        let mut ended: BTreeSet<Vec<u8>> = BTreeSet::new();
        let mut changed = BTreeSet::new();
        let mut covered: Option<Vec<u8>> = None;
        for key in dirty {
            let ends_page = current
                .get(key)
                .is_some_and(|item| item.boundary >= threshold);
            let inside = covered.as_ref().is_some_and(|end| key <= end);
            // A key that newly ends a page also changes the page after it. A
            // key ends a page by its digest, so one that ended a page before
            // has the same page after it as before.
            let extend = ends_page && !ended.contains(key) && (inside || !next.contains_key(key));
            if inside && !(extend && covered.as_ref() == Some(key)) {
                continue;
            }
            let start = if inside {
                // The page that ends at this key was just recomputed.
                Some(key.clone())
            } else {
                current
                    .range::<[u8], _>(keys_below(key.as_slice()))
                    .rev()
                    .find(|(_, item)| item.boundary >= threshold)
                    .map(|(key, _)| key.clone())
            };
            let after = if extend || inside {
                Bound::Excluded(key.as_slice())
            } else {
                Bound::Included(key.as_slice())
            };
            let end = current
                .range::<[u8], _>((after, Bound::Unbounded))
                .find(|(_, item)| item.boundary >= threshold)
                .map(|(key, _)| key.clone())
                .or_else(|| current.keys().next_back().cloned());
            let from = start.as_deref().map_or(Bound::Unbounded, Bound::Excluded);
            let stale_end = match &end {
                Some(end) if end > key => end.clone(),
                _ => key.clone(),
            };
            let stale: Vec<Vec<u8>> = next
                .range::<[u8], _>((from, Bound::Included(stale_end.as_slice())))
                .map(|(key, _)| key.clone())
                .collect();
            for key in stale {
                if let Some(item) = next.remove(&key) {
                    removed.insert(key.clone(), item.digest);
                    ended.insert(key);
                }
            }
            if let Some(end) = &end {
                let mut page = Vec::new();
                for (candidate, item) in
                    current.range::<[u8], _>((from, Bound::Included(end.as_slice())))
                {
                    page.push(item.digest);
                    if item.boundary >= threshold || candidate == end {
                        let digest = tree_hash::<H>(&page);
                        page.clear();
                        if removed.remove(candidate) != Some(digest) {
                            changed.insert(candidate.clone());
                        }
                        next.insert(
                            candidate.clone(),
                            Item {
                                digest,
                                boundary: item.boundary,
                            },
                        );
                    }
                }
            }
            covered = Some(stale_end);
        }
        changed.extend(removed.into_keys());
        changed
    }

    /// Bottom-up path of a committed key.
    fn path(&self, key: &[u8]) -> Vec<PathStep> {
        let mut steps = Vec::new();
        let mut position = key.to_vec();
        for level in 0..self.top() {
            let page = self.page(level, &position);
            let digests: Vec<Digest> = page.iter().map(|(_, item)| item.digest).collect();
            let index = page
                .iter()
                .position(|(candidate, _)| candidate.as_slice() == position.as_slice())
                .expect("a committed key is in its page");
            page_path::<H>(&digests, index, &mut steps);
            position = page.last().expect("a page is not empty").0.clone();
        }
        steps
    }

    /// The smallest entry key below the item `key` of `level`.
    fn smallest_below(&self, level: usize, key: &[u8]) -> &[u8] {
        if level == 0 {
            return self.levels[0]
                .get_key_value(key)
                .expect("an item of level 0 is an entry")
                .0;
        }
        let previous = self.levels[level]
            .range::<[u8], _>(keys_below(key))
            .next_back();
        let from = previous.map_or(Bound::Unbounded, |(key, _)| Bound::Excluded(key.as_slice()));
        self.levels[0]
            .range::<[u8], _>((from, Bound::Unbounded))
            .next()
            .expect("an item covers at least one entry")
            .0
    }

    fn emit_items(
        &self,
        level: usize,
        items: &[(&Vec<u8>, Item)],
        reveal: &Reveal<'_>,
        out: &mut fringe::Builder,
    ) {
        let (first_key, _) = items[0];
        let last_key = items[items.len() - 1].0;
        if reveal.hides(self.smallest_below(level, first_key), last_key) {
            let digests: Vec<Digest> = items.iter().map(|(_, item)| item.digest).collect();
            out.hidden(&tree_hash::<H>(&digests));
            return;
        }
        if items.len() > 1 {
            let (left, right) = items.split_at(split(items.len()));
            self.emit_items(level, left, reveal, out);
            self.emit_items(level, right, reveal, out);
            out.branch(0);
        } else if level > 0 {
            // One item of an upper level is the page of the level below.
            let page = self.page(level - 1, first_key);
            self.emit_items(level - 1, &page, reveal, out);
        } else if first_key.as_slice() < reveal.lower
            || reveal
                .upper
                .is_some_and(|upper| first_key.as_slice() >= upper)
        {
            out.boundary(first_key, &self.values[first_key]);
        } else {
            out.claimed();
        }
    }

    /// Parse an inclusion witness into the leaf's bottom-up path.
    pub(super) fn open_inclusion(witness: &[u8]) -> Result<Vec<PathStep>, Reject> {
        let mut reader = Reader::<H>::new(witness);
        let count = reader.count(1 + DIGEST_BYTES)?;
        let mut path = Vec::with_capacity(count);
        for _ in 0..count {
            let right = match reader.u8()? {
                0 => false,
                1 => true,
                _ => return Err(Reject::Malformed),
            };
            path.push(PathStep {
                crit: 0,
                sibling: reader.digest()?,
                right,
            });
        }
        reader.finish()?;
        Ok(path)
    }

    /// Parse a range witness into its opened tree.
    pub(super) fn open_range(
        lower: &[u8],
        upper: Option<&[u8]>,
        entries: &[(&[u8], &[u8])],
        witness: &[u8],
    ) -> Result<fringe::Opened, Reject> {
        fringe::open::<H>(lower, upper, entries, witness, Self::branch)
    }

    /// A branch of the binary tree carries no auxiliary word.
    fn branch(aux: u32, left: &Digest, right: &Digest) -> Option<Digest> {
        (aux == 0).then(|| node::<H>(left, right))
    }
}

impl<H: HashProfile> Engine for MerkleBTree<H> {
    type Hash = H;

    const CONSTRUCTION: &'static str = "sorted-merkle-btree/content-defined-pages-16/v0";

    fn new() -> Self {
        Self {
            values: BTreeMap::new(),
            levels: vec![BTreeMap::new()],
            profile: PhantomData,
        }
    }

    fn apply(&mut self, changes: &[Change<'_>]) {
        let mut dirty = BTreeSet::new();
        for (key, value) in changes {
            match value {
                Some(value) => {
                    let digest = value_digest::<H>(value);
                    if self.values.get(*key) == Some(&digest) {
                        continue;
                    }
                    let key_digest = key_digest::<H>(key);
                    self.values.insert(key.to_vec(), digest);
                    self.levels[0].insert(
                        key.to_vec(),
                        Item {
                            digest: leaf_digest::<H>(&key_digest, &digest),
                            boundary: boundary_levels(&key_digest),
                        },
                    );
                    dirty.insert(key.to_vec());
                }
                None => {
                    if self.values.remove(*key).is_some() {
                        self.levels[0].remove(*key);
                        dirty.insert(key.to_vec());
                    }
                }
            }
        }
        let mut level = 0;
        while !dirty.is_empty() {
            if self.levels[level].is_empty() {
                self.levels.truncate(1);
                break;
            }
            if level >= 1 && self.levels[level].len() == 1 {
                self.levels.truncate(level + 1);
                break;
            }
            if self.levels.len() == level + 1 {
                self.levels.push(BTreeMap::new());
                dirty = self.levels[level].keys().cloned().collect();
            }
            dirty = self.rebuild(level, &dirty);
            level += 1;
        }
    }

    fn structure_root(&self) -> Digest {
        if self.levels[0].is_empty() {
            return ZERO_DIGEST;
        }
        self.levels[self.top()]
            .values()
            .next()
            .expect("the top level of a nonempty tree holds the root item")
            .digest
    }

    fn len(&self) -> u64 {
        self.values.len() as u64
    }

    fn prove_inclusion(&self, key: &[u8]) -> Option<Vec<u8>> {
        if !self.values.contains_key(key) {
            return None;
        }
        let path = self.path(key);
        let mut writer = Writer::default();
        writer.count(path.len());
        for step in path {
            writer.u8(u8::from(step.right));
            writer.digest(&step.sibling);
        }
        Some(writer.finish())
    }

    fn prove_absence(&self, key: &[u8]) -> Option<Vec<u8>> {
        if self.values.contains_key(key) {
            return None;
        }
        Some(self.prove_range(key, Some(&immediate_successor(key))))
    }

    fn prove_range(&self, lower: &[u8], upper: Option<&[u8]>) -> Vec<u8> {
        let mut out = fringe::Builder::default();
        if !self.levels[0].is_empty() {
            let first = self.values.range::<[u8], _>(keys_below(lower)).next_back();
            let last =
                upper.and_then(|upper| self.values.range::<[u8], _>(keys_from(upper)).next());
            let reveal = Reveal {
                lower,
                upper,
                first: first.map(|(key, _)| key.as_slice()),
                last: last.map(|(key, _)| key.as_slice()),
            };
            let top = self.top();
            let root: Vec<(&Vec<u8>, Item)> = self.levels[top]
                .iter()
                .map(|(key, item)| (key, *item))
                .collect();
            self.emit_items(top, &root, &reveal, &mut out);
        }
        out.finish()
    }

    fn inclusion_root(key: &[u8], value: &[u8], witness: &[u8]) -> Result<Digest, Reject> {
        let path = Self::open_inclusion(witness)?;
        Ok(fold::<H>(entry_leaf::<H>(key, value), &path))
    }

    fn absence_root(key: &[u8], witness: &[u8]) -> Result<Digest, Reject> {
        let upper = immediate_successor(key);
        Self::range_root(key, Some(&upper), &[], witness)
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
        let entries = self.values.len() as u64;
        let upper_items: u64 = self.levels[1..]
            .iter()
            .map(|level| level.len() as u64)
            .sum();
        let mut max_depth = 0_u32;
        for (level, items) in self.levels.iter().enumerate().take(self.top()) {
            let threshold = u8::try_from(level + 1).expect("at most seventeen levels");
            let (mut longest, mut run) = (0_usize, 0_usize);
            for item in items.values() {
                run += 1;
                if item.boundary >= threshold {
                    longest = longest.max(run);
                    run = 0;
                }
            }
            longest = longest.max(run).max(1);
            max_depth += usize::BITS - (longest - 1).leading_zeros();
        }
        Storage {
            entries,
            // The value digest and the level-0 item of every entry, and every
            // upper item; counted from the maps that hold them.
            digests: entries + self.levels[0].len() as u64 + upper_items,
            structure_bytes: entries * MODEL_ENTRY_BYTES + upper_items * MODEL_UPPER_ITEM_BYTES,
            auxiliary_bytes: 0,
            max_depth,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_commitment_prototypes::{
        hash::{Blake2bProfile, take_hash_work},
        workload::SplitMix64,
    };

    /// A cold build hashes every page exactly once: one compression per entry
    /// leaf and, at every level, one per item beyond the first of each page.
    #[test]
    fn cold_build_hashes_every_page_exactly_once() {
        let mut generator = SplitMix64::new(9);
        let entries: Vec<(Vec<u8>, Vec<u8>)> = (0..3_000)
            .map(|_| {
                let mut key = vec![0_u8; 12];
                generator.fill(&mut key);
                (key, vec![1, 2, 3])
            })
            .collect();
        let changes: Vec<Change<'_>> = entries
            .iter()
            .map(|(key, value)| (key.as_slice(), Some(value.as_slice())))
            .collect();
        let mut tree = MerkleBTree::<Blake2bProfile>::new();
        let _ = take_hash_work();
        tree.apply(&changes);
        let work = take_hash_work();
        let entries = tree.len();
        assert_eq!(entries, 3_000);
        assert!(tree.top() >= 3, "3,000 keys need several levels");
        let nodes: u64 = (0..tree.top())
            .map(|level| (tree.levels[level].len() - tree.levels[level + 1].len()) as u64)
            .sum();
        assert_eq!(work.byte_hashes, 2 * entries);
        assert_eq!(work.compressions, entries + nodes);

        // One rewritten value rehashes only the pages on its path.
        let (key, _) = changes[1_234];
        tree.apply(&[(key, Some(b"changed"))]);
        let update = take_hash_work();
        assert_eq!(update.byte_hashes, 2);
        let path_pages: u64 = {
            let mut position = key.to_vec();
            let mut total = 0;
            for level in 0..tree.top() {
                let page = tree.page(level, &position);
                total += page.len() as u64 - 1;
                position = page.last().unwrap().0.clone();
            }
            total
        };
        assert_eq!(update.compressions, 1 + path_pages);
        // Rewriting the same value again changes nothing and hashes only the value.
        tree.apply(&[(key, Some(b"changed"))]);
        assert_eq!(take_hash_work().compressions, 0);

        // The storage model counts the items the levels hold. The binary tree
        // over the leaves has `entries - 1` nodes; only one per page of each
        // level is kept, the page-internal ones are recomputed.
        let storage = tree.storage();
        let upper: u64 = tree.levels[1..]
            .iter()
            .map(|level| level.len() as u64)
            .sum();
        assert_eq!(tree.levels[0].len() as u64, entries);
        assert_eq!(storage.entries, entries);
        assert_eq!(storage.digests, 2 * entries + upper);
        assert_eq!(storage.structure_bytes, entries * 65 + upper * 41);
        assert_eq!(nodes, entries - 1, "one binary node per leaf but one");
        assert!(upper < nodes / 8, "pages hold about sixteen items");
        let copy = tree.clone();
        assert_eq!(copy.structure_root(), tree.structure_root());
        assert_eq!(copy.storage(), storage);
        assert_eq!(
            MerkleBTree::<Blake2bProfile>::new().storage(),
            Storage::default()
        );
    }

    #[test]
    fn tree_hash_splits_at_the_largest_power_of_two_below_the_count() {
        assert_eq!(
            [2, 3, 4, 5, 8, 9, 16, 17].map(split),
            [1, 2, 2, 4, 4, 8, 8, 16]
        );
        let items: Vec<Digest> = (1..=5_u64).map(|word| [word; 4]).collect();
        let pair = |left: &Digest, right: &Digest| node::<Blake2bProfile>(left, right);
        let expected = pair(
            &pair(&pair(&items[0], &items[1]), &pair(&items[2], &items[3])),
            &items[4],
        );
        assert_eq!(tree_hash::<Blake2bProfile>(&items), expected);
        assert_eq!(tree_hash::<Blake2bProfile>(&items[..1]), items[0]);
        for index in 0..items.len() {
            let mut path = Vec::new();
            page_path::<Blake2bProfile>(&items, index, &mut path);
            assert_eq!(fold::<Blake2bProfile>(items[index], &path), expected);
        }
        assert_eq!(boundary_levels(&[0, 0, 0, u64::MAX]), 0);
        assert_eq!(boundary_levels(&[0, 0, 0, u64::MAX >> 8]), 2);
        assert_eq!(boundary_levels(&[u64::MAX, 0, 0, 0]), 16);
    }
}
