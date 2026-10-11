//! `O(log n)` history paths and roots for the read API (`specs/sccp.md` §3.5, §6).
//!
//! State keeps the history leaves and the peaks of the current size only, so a path within an
//! older `history_root(S)` needs interior nodes that state does not store. Rebuilding the
//! promote-odd tree on every request would hash the entire history per public GET. Instead a
//! process-wide [`HistoryNodeCache`] keeps the roots of every complete perfect subtree of at
//! least `2^MIN_LEVEL` leaves; smaller subtrees are hashed from the stored leaves on demand
//! (fewer than `2^MIN_LEVEL` leaves each).
//!
//! The cache only accelerates: every answer equals the promote-odd computation over the stored
//! leaves. Before each use the cache is synchronised with the reading view and validated by
//! recomputing the view's peaks from cached nodes and comparing them with the stored peaks.
//! Every perfect subtree inside `[0, size)` lies inside one peak, so equal peaks (keccak
//! collision resistance) prove every cached node the request can touch; a mismatch (a reverted
//! block or a replaced state) rebuilds the cache from the view. Appends cost amortised `O(1)`,
//! a path `O(log n)` cached reads plus fewer than `2^MIN_LEVEL` leaf hashes per level.

use super::super::store;
use crate::state::WorldReadOnly;
use iroha_sccp::v1::{hashes::node, merkle::promote_odd_root};
use std::sync::{LazyLock, Mutex, PoisonError};

/// Lowest cached level: subtrees of `2^MIN_LEVEL` leaves and more are cached.
const MIN_LEVEL: u32 = 5;

/// Leaves per cached chunk.
const CHUNK: u64 = 1 << MIN_LEVEL;

/// Why a history read cannot be served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HistoryReadError {
    /// The requested size exceeds the stored history.
    SizeOutOfRange,
    /// The leaf index is not below the requested size.
    IndexOutOfRange,
    /// The stored leaves do not reproduce the stored peaks.
    Inconsistent,
}

/// The stored history a cache reads from.
pub(super) trait HistorySource {
    /// Stored accumulator size.
    fn size(&self) -> u64;
    /// Stored peaks, largest first.
    fn peaks(&self) -> Vec<[u8; 32]>;
    /// Leaves `start..end` (all below [`Self::size`]).
    fn leaves(&self, start: u64, end: u64) -> Vec<[u8; 32]>;
}

/// [`HistorySource`] over committed or executing world state.
pub(super) struct WorldHistory<'world, W: WorldReadOnly + ?Sized>(pub &'world W);

impl<W: WorldReadOnly + ?Sized> HistorySource for WorldHistory<'_, W> {
    fn size(&self) -> u64 {
        store::history::get(self.0).size
    }

    fn peaks(&self) -> Vec<[u8; 32]> {
        store::history::get(self.0).peaks.clone()
    }

    fn leaves(&self, start: u64, end: u64) -> Vec<[u8; 32]> {
        store::history_leaves::range(self.0, start..end)
            .map(|(_, (_, leaf))| *leaf)
            .collect()
    }
}

/// Roots of the complete perfect subtrees of at least `2^MIN_LEVEL` leaves.
#[derive(Debug, Default)]
pub(super) struct HistoryNodeCache {
    /// Leaves folded into `levels`, a multiple of [`CHUNK`].
    covered: u64,
    /// `levels[i][p]`: root of the level-`MIN_LEVEL + i` subtree at position `p`.
    levels: Vec<Vec<[u8; 32]>>,
}

fn position_index(position: u64) -> Option<usize> {
    usize::try_from(position).ok()
}

impl HistoryNodeCache {
    /// Forget every cached node.
    fn reset(&mut self) {
        self.covered = 0;
        self.levels.clear();
    }

    /// Append `root` at cached level `level`, folding completed pairs upwards.
    fn push(&mut self, level: usize, root: [u8; 32]) {
        if self.levels.len() == level {
            self.levels.push(Vec::new());
        }
        let nodes = &mut self.levels[level];
        nodes.push(root);
        if nodes.len().is_multiple_of(2) {
            let parent = node(&nodes[nodes.len() - 2], &nodes[nodes.len() - 1]);
            self.push(level + 1, parent);
        }
    }

    /// Fold every complete chunk of leaves below `size` that is not cached yet.
    fn extend(&mut self, source: &dyn HistorySource, size: u64) {
        while self.covered.saturating_add(CHUNK) <= size {
            let leaves = source.leaves(self.covered, self.covered + CHUNK);
            let root = promote_odd_root(&leaves).unwrap_or([0; 32]);
            self.push(0, root);
            self.covered += CHUNK;
        }
    }

    /// Root of the perfect subtree of `level` at `position`, which lies inside the stored
    /// leaves: cached at `MIN_LEVEL` and above, otherwise hashed from the leaves.
    fn perfect(&self, source: &dyn HistorySource, level: u32, position: u64) -> [u8; 32] {
        if level >= MIN_LEVEL {
            let cached = usize::try_from(level - MIN_LEVEL)
                .ok()
                .and_then(|index| self.levels.get(index))
                .zip(position_index(position))
                .and_then(|(nodes, position)| nodes.get(position));
            if let Some(root) = cached {
                return *root;
            }
        }
        let start = position << level;
        promote_odd_root(&source.leaves(start, start + (1 << level))).unwrap_or([0; 32])
    }

    /// The perfect subtrees decomposing `start..end`, largest first; `start` is aligned to the
    /// largest power of two not above `end - start`.
    fn decomposition(&self, source: &dyn HistorySource, start: u64, end: u64) -> Vec<[u8; 32]> {
        let length = end - start;
        let mut offset = start;
        let mut roots = Vec::new();
        for level in (0..u64::BITS).rev() {
            if (length >> level) & 1 == 1 {
                roots.push(self.perfect(source, level, offset >> level));
                offset += 1 << level;
            }
        }
        roots
    }

    /// Promote-odd root over the leaves `start..end` (a right-bagged decomposition).
    fn range_root(&self, source: &dyn HistorySource, start: u64, end: u64) -> [u8; 32] {
        let roots = self.decomposition(source, start, end);
        let mut roots = roots.iter().rev();
        let Some(last) = roots.next() else {
            return [0; 32];
        };
        roots.fold(*last, |bagged, root| node(root, &bagged))
    }

    /// Bring the cache up to the source and validate it against the stored peaks, rebuilding
    /// it when they differ.
    fn sync(&mut self, source: &dyn HistorySource) -> Result<u64, HistoryReadError> {
        let size = source.size();
        let stored = source.peaks();
        self.extend(source, size);
        if self.decomposition(source, 0, size) == stored {
            return Ok(size);
        }
        self.reset();
        self.extend(source, size);
        if self.decomposition(source, 0, size) == stored {
            Ok(size)
        } else {
            Err(HistoryReadError::Inconsistent)
        }
    }

    /// `history_root(size)` for `size` up to the synchronised size.
    fn root(&self, source: &dyn HistorySource, size: u64) -> [u8; 32] {
        if size == 0 {
            return [0; 32];
        }
        self.range_root(source, 0, size)
    }

    /// The §3.4 positional path of leaf `index` in the history of `size` leaves.
    fn path(&self, source: &dyn HistorySource, index: u64, size: u64) -> Vec<[u8; 32]> {
        let mut path = Vec::new();
        let (mut level, mut position, mut count) = (0_u32, index, size);
        while count > 1 {
            if position % 2 == 1 {
                path.push(self.perfect(source, level, position - 1));
            } else if position + 1 < count {
                let start = (position + 1) << level;
                let end = ((position + 2) << level).min(size);
                path.push(if end - start == 1 << level {
                    self.perfect(source, level, position + 1)
                } else {
                    self.range_root(source, start, end)
                });
            }
            position >>= 1;
            count = count.div_ceil(2);
            level += 1;
        }
        path
    }

    /// `(history_root(size), path of index)` after synchronising with `source`.
    pub(super) fn root_and_path(
        &mut self,
        source: &dyn HistorySource,
        index: u64,
        size: u64,
    ) -> Result<([u8; 32], Vec<[u8; 32]>), HistoryReadError> {
        let stored = self.sync(source)?;
        if size > stored {
            return Err(HistoryReadError::SizeOutOfRange);
        }
        if index >= size {
            return Err(HistoryReadError::IndexOutOfRange);
        }
        Ok((self.root(source, size), self.path(source, index, size)))
    }
}

/// The process-wide cache Torii's reads share.
static CACHE: LazyLock<Mutex<HistoryNodeCache>> =
    LazyLock::new(|| Mutex::new(HistoryNodeCache::default()));

/// `(history_root(size), path of leaf index)` within the history stored in `world`.
pub(super) fn root_and_path(
    world: &(impl WorldReadOnly + ?Sized),
    index: u64,
    size: u64,
) -> Result<([u8; 32], Vec<[u8; 32]>), HistoryReadError> {
    let mut cache = CACHE.lock().unwrap_or_else(PoisonError::into_inner);
    cache.root_and_path(&WorldHistory(world), index, size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;
    use iroha_sccp::v1::{
        hashes::history_leaf,
        history::{HistoryAccumulatorV1, history_path, history_root},
    };

    /// An in-memory history that counts the leaves it hands out.
    struct Leaves {
        leaves: Vec<[u8; 32]>,
        peaks: Vec<[u8; 32]>,
        reads: Cell<u64>,
    }

    impl Leaves {
        fn new(seed: u8, count: u64) -> Self {
            Self::from_leaves(
                (0..count)
                    .map(|index| history_leaf(index * 2 + 1, &[seed; 32], 1))
                    .collect(),
            )
        }

        fn from_leaves(leaves: Vec<[u8; 32]>) -> Self {
            let peaks = HistoryAccumulatorV1::from_leaves(&leaves)
                .expect("bounded")
                .peaks()
                .to_vec();
            Self {
                leaves,
                peaks,
                reads: Cell::new(0),
            }
        }
    }

    impl HistorySource for Leaves {
        fn size(&self) -> u64 {
            self.leaves.len() as u64
        }

        fn peaks(&self) -> Vec<[u8; 32]> {
            self.peaks.clone()
        }

        fn leaves(&self, start: u64, end: u64) -> Vec<[u8; 32]> {
            self.reads.set(self.reads.get() + (end - start));
            self.leaves[usize::try_from(start).unwrap()..usize::try_from(end).unwrap()].to_vec()
        }
    }

    #[test]
    fn paths_and_roots_equal_the_promote_odd_tree() {
        let source = Leaves::new(1, 150);
        let mut cache = HistoryNodeCache::default();
        // Every size up to three chunks, and the chunk and power-of-two edges above.
        for size in (1..=70_u64).chain([95, 96, 97, 127, 128, 129, 150]) {
            let prefix = &source.leaves[..usize::try_from(size).unwrap()];
            for index in 0..size {
                let (root, path) = cache.root_and_path(&source, index, size).expect("in range");
                assert_eq!(root, history_root(prefix).unwrap(), "size {size}");
                assert_eq!(
                    path,
                    history_path(prefix, index).unwrap(),
                    "size {size} index {index}"
                );
            }
        }
        assert_eq!(cache.covered, 128, "four full 32-leaf chunks");
    }

    #[test]
    fn requests_outside_the_stored_history_are_refused() {
        let source = Leaves::new(2, 40);
        let mut cache = HistoryNodeCache::default();
        assert_eq!(
            cache.root_and_path(&source, 0, 41),
            Err(HistoryReadError::SizeOutOfRange)
        );
        assert_eq!(
            cache.root_and_path(&source, 10, 10),
            Err(HistoryReadError::IndexOutOfRange)
        );
    }

    #[test]
    fn a_warm_cache_reads_far_fewer_leaves_than_the_history() {
        let source = Leaves::new(3, 4_096);
        let mut cache = HistoryNodeCache::default();
        cache.root_and_path(&source, 0, 4_096).expect("warm-up");
        source.reads.set(0);
        let (_, path) = cache.root_and_path(&source, 1_234, 4_000).expect("path");
        assert_eq!(path, history_path(&source.leaves[..4_000], 1_234).unwrap());
        assert!(
            source.reads.get() < 1_024,
            "a warm path read {} leaves",
            source.reads.get()
        );
    }

    #[test]
    fn a_replaced_history_rebuilds_the_cache() {
        let mut cache = HistoryNodeCache::default();
        let first = Leaves::new(4, 100);
        cache.root_and_path(&first, 5, 100).expect("first");
        // A different history (a reverted or replaced chain) of a smaller and a larger size.
        for size in [90_u64, 130] {
            let replaced = Leaves::new(5, size);
            let (root, path) = cache.root_and_path(&replaced, 70, size).expect("rebuilt");
            assert_eq!(root, history_root(&replaced.leaves).unwrap());
            assert_eq!(path, history_path(&replaced.leaves, 70).unwrap());
        }
    }

    #[test]
    fn an_older_view_of_the_same_history_reuses_the_cache() {
        let mut cache = HistoryNodeCache::default();
        let newer = Leaves::new(6, 200);
        cache.root_and_path(&newer, 0, 200).expect("newer");
        let older = Leaves::from_leaves(newer.leaves[..150].to_vec());
        let (root, path) = cache.root_and_path(&older, 149, 150).expect("older");
        assert_eq!(root, history_root(&older.leaves).unwrap());
        assert_eq!(path, history_path(&older.leaves, 149).unwrap());
        assert_eq!(cache.covered, 192, "no rebuild for a consistent prefix");
    }

    #[test]
    fn inconsistent_stored_peaks_are_reported() {
        struct Broken(Leaves);
        impl HistorySource for Broken {
            fn size(&self) -> u64 {
                self.0.size()
            }
            fn peaks(&self) -> Vec<[u8; 32]> {
                vec![[9; 32]; self.0.peaks().len()]
            }
            fn leaves(&self, start: u64, end: u64) -> Vec<[u8; 32]> {
                self.0.leaves(start, end)
            }
        }
        let mut cache = HistoryNodeCache::default();
        assert_eq!(
            cache.root_and_path(&Broken(Leaves::new(7, 33)), 0, 33),
            Err(HistoryReadError::Inconsistent)
        );
    }
}
