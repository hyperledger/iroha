//! Original history assertions, now exercising the sole funded implementation.

use super::*;
use core::cell::Cell;
use iroha_allocation::AllocationBudget;
use iroha_sccp::v1::constants::MAX_HISTORY_SIZE;
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

impl BorrowedHistorySource for Leaves {
    fn size(&self) -> u64 {
        self.leaves.len() as u64
    }

    fn peaks(&self) -> &[[u8; 32]] {
        &self.peaks
    }

    fn leaf(&self, index: u64) -> Option<[u8; 32]> {
        self.reads.set(self.reads.get() + 1);
        self.leaves.get(usize::try_from(index).unwrap()).copied()
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
    assert_eq!(cache.inner.covered, 128, "four full 32-leaf chunks");
}

#[test]
fn requests_outside_the_stored_history_are_refused() {
    let source = Leaves::new(2, 40);
    let mut cache = HistoryNodeCache::default();
    assert_eq!(
        cache.root_and_path(&source, 0, 41),
        Err(Failure::SizeOutOfRange)
    );
    assert_eq!(
        cache.root_and_path(&source, 10, 10),
        Err(Failure::IndexOutOfRange)
    );
}

#[test]
fn invalid_requests_do_not_acquire_history_or_mutate_cached_nodes() {
    let source = Leaves::new(2, 96);
    let mut cache = HistoryNodeCache::default();
    for (index, size, error) in [
        (0, 97, Failure::SizeOutOfRange),
        (0, u64::MAX, Failure::SizeOutOfRange),
        (0, 0, Failure::IndexOutOfRange),
        (32, 32, Failure::IndexOutOfRange),
    ] {
        assert_eq!(cache.root_and_path(&source, index, size), Err(error));
        assert_eq!(source.reads.get(), 0);
        assert_eq!(cache.inner.covered, 0);
        assert!(
            cache
                .inner
                .nodes
                .as_ref()
                .is_none_or(|nodes| nodes.as_slice().is_empty())
        );
    }
    cache.root_and_path(&source, 0, 96).unwrap();
    source.reads.set(0);
    let covered = cache.inner.covered;
    let nodes = cache.inner.nodes.as_ref().unwrap().as_slice().to_vec();
    assert_eq!(
        cache.root_and_path(&source, 0, 97),
        Err(Failure::SizeOutOfRange)
    );
    assert_eq!(source.reads.get(), 0);
    assert_eq!(cache.inner.covered, covered);
    assert_eq!(cache.inner.nodes.as_ref().unwrap().as_slice(), nodes);
}

#[test]
fn malformed_history_size_or_peak_count_refuses_before_leaf_acquisition() {
    struct Malformed {
        size: u64,
        peaks: Vec<[u8; 32]>,
    }
    impl BorrowedHistorySource for Malformed {
        fn size(&self) -> u64 {
            self.size
        }
        fn peaks(&self) -> &[[u8; 32]] {
            assert!(
                self.size <= MAX_HISTORY_SIZE,
                "oversized source needs no peaks"
            );
            &self.peaks
        }
        fn leaf(&self, _: u64) -> Option<[u8; 32]> {
            panic!("malformed accumulator must not acquire leaves");
        }
    }
    let mut cache = HistoryNodeCache::default();
    for source in [
        Malformed {
            size: MAX_HISTORY_SIZE + 1,
            peaks: vec![],
        },
        Malformed {
            size: u64::MAX,
            peaks: vec![],
        },
        Malformed {
            size: MAX_HISTORY_SIZE,
            peaks: vec![],
        },
        Malformed {
            size: 64,
            peaks: vec![[1; 32]; 2],
        },
    ] {
        assert_eq!(
            cache.root_and_path(&source, 0, 1),
            Err(Failure::Inconsistent)
        );
        assert_eq!(cache.inner.covered, 0);
        assert!(
            cache
                .inner
                .nodes
                .as_ref()
                .is_none_or(|nodes| nodes.as_slice().is_empty())
        );
    }
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
    assert_eq!(
        cache.inner.covered, 192,
        "no rebuild for a consistent prefix"
    );
}

#[test]
fn inconsistent_stored_peaks_are_reported() {
    struct Broken {
        source: Leaves,
        peaks: Vec<[u8; 32]>,
    }
    impl BorrowedHistorySource for Broken {
        fn size(&self) -> u64 {
            self.source.size()
        }
        fn peaks(&self) -> &[[u8; 32]] {
            &self.peaks
        }
        fn leaf(&self, index: u64) -> Option<[u8; 32]> {
            self.source.leaf(index)
        }
    }
    let mut cache = HistoryNodeCache::default();
    assert_eq!(
        cache.root_and_path(
            &Broken {
                source: Leaves::new(7, 33),
                peaks: vec![[9; 32]; 2]
            },
            0,
            33
        ),
        Err(Failure::Inconsistent)
    );
}

#[derive(Debug, PartialEq, Eq)]
enum Failure {
    SizeOutOfRange,
    IndexOutOfRange,
    Inconsistent,
}
struct HistoryNodeCache {
    inner: SccpHistoryNodeCache,
    budget: AllocationBudget,
}
impl Default for HistoryNodeCache {
    fn default() -> Self {
        Self {
            inner: SccpHistoryNodeCache::new(),
            budget: AllocationBudget::new(1 << 20),
        }
    }
}
impl HistoryNodeCache {
    fn root_and_path(
        &mut self,
        source: &dyn BorrowedHistorySource,
        index: u64,
        size: u64,
    ) -> Result<([u8; 32], Vec<[u8; 32]>), Failure> {
        let mut operation = || -> Result<_, SccpHistoryReadError> {
            let draft = self.inner.draft(source, index, size, &self.budget)?;
            let (mut request, mut backing) = reserve_operation(
                &self.budget,
                draft.request_demand()?,
                &self.budget,
                draft.cache_demand()?,
            )?;
            draft.materialize(&mut request, &mut backing)
        };
        match operation() {
            Ok(path) => Ok((path.root(), path.path().to_vec())),
            Err(SccpHistoryReadError::SizeOutOfRange) => Err(Failure::SizeOutOfRange),
            Err(SccpHistoryReadError::IndexOutOfRange) => Err(Failure::IndexOutOfRange),
            Err(SccpHistoryReadError::Inconsistent) => Err(Failure::Inconsistent),
            Err(error) => panic!("unexpected bounded fixture refusal: {error:?}"),
        }
    }
}
