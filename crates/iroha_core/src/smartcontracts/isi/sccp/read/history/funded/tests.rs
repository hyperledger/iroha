//! Canonical history parity, bounded warm reads and exact original-pool cache custody.

use super::*;
use iroha_allocation::release::ReleaseRegistration;
use iroha_sccp::v1::merkle::PromoteOddTree;
use std::{
    cell::Cell,
    panic::{AssertUnwindSafe, catch_unwind},
    task::{Context, Poll, Waker},
};

struct Source {
    leaves: Vec<Hash>,
    accumulator: HistoryAccumulatorV1,
    reads: Cell<usize>,
    panic_at: Cell<Option<u64>>,
}
impl Source {
    fn new(size: usize, seed: u8) -> Self {
        let leaves: Vec<_> = (0..size)
            .map(|index| {
                let mut leaf = [seed; 32];
                leaf[..8].copy_from_slice(&(index as u64).to_le_bytes());
                leaf
            })
            .collect();
        let accumulator = HistoryAccumulatorV1::from_leaves(&leaves).unwrap();
        Self {
            leaves,
            accumulator,
            reads: Cell::new(0),
            panic_at: Cell::new(None),
        }
    }
}
impl BorrowedHistorySource for Source {
    fn size(&self) -> u64 {
        self.accumulator.size()
    }
    fn peaks(&self) -> &[Hash] {
        self.accumulator.peaks()
    }
    fn leaf(&self, index: u64) -> Option<Hash> {
        self.reads.set(self.reads.get() + 1);
        assert_ne!(
            self.panic_at.get(),
            Some(index),
            "controlled borrowed source unwind"
        );
        self.leaves.get(index as usize).copied()
    }
}
fn path(
    cache: &mut SccpHistoryNodeCache,
    source: &Source,
    index: u64,
    size: u64,
    cache_budget: &AllocationBudget,
    request_budget: &AllocationBudget,
) -> Result<RetainedSccpHistoryPath, SccpHistoryReadError> {
    let draft = cache.draft(source, index, size, cache_budget)?;
    let (mut request, mut backing) = reserve_operation(
        request_budget,
        draft.request_demand()?,
        cache_budget,
        draft.cache_demand()?,
    )?;
    draft.materialize(&mut request, &mut backing)
}

#[test]
fn funded_history_matches_every_odd_path_and_reuses_original_backing() {
    let durable = AllocationBudget::new(1 << 20);
    let request = AllocationBudget::new(1 << 20);
    let mut cache = SccpHistoryNodeCache::new();
    for size in [1, 2, 3, 31, 32, 33, 63, 64, 65, 127, 128, 129, 257] {
        let source = Source::new(size, 7);
        let canonical = PromoteOddTree::new(&source.leaves).unwrap();
        for index in 0..size {
            let result = path(
                &mut cache,
                &source,
                index as u64,
                size as u64,
                &durable,
                &request,
            )
            .unwrap();
            assert_eq!(result.root(), canonical.root());
            assert_eq!(result.path(), canonical.path(index).unwrap());
            assert!(result.path.belongs_to(&request));
        }
        assert_eq!(request.reserved_bytes(), 0);
        if let Some(nodes) = &cache.nodes {
            assert!(nodes.belongs_to(&durable));
            assert_eq!(durable.reserved_bytes(), nodes.capacity() * 32);
        }
    }
    let original_pointer = cache.nodes.as_ref().unwrap().as_slice().as_ptr();
    // An older immutable view and a prefix under a newer view both remain valid.
    for source in [Source::new(64, 7), Source::new(257, 7)] {
        let canonical = PromoteOddTree::new(&source.leaves[..63]).unwrap();
        let retained = path(&mut cache, &source, 62, 63, &durable, &request).unwrap();
        assert_eq!(retained.root(), canonical.root());
        assert_eq!(retained.path(), canonical.path(62).unwrap());
        assert_eq!(
            cache.nodes.as_ref().unwrap().as_slice().as_ptr(),
            original_pointer
        );
    }
    drop(cache);
    assert_eq!(durable.reserved_bytes(), 0);
    assert_eq!(request.reserved_bytes(), 0);
}

#[test]
fn funded_history_warm_work_is_bounded_and_replaced_source_reauthenticates() {
    let durable = AllocationBudget::new(1 << 20);
    let request = AllocationBudget::new(1 << 20);
    let mut cache = SccpHistoryNodeCache::new();
    let source = Source::new(16_387, 11);
    drop(path(&mut cache, &source, 8193, source.size(), &durable, &request).unwrap());
    let backing = cache.nodes.as_ref().unwrap().as_slice().as_ptr();
    source.reads.set(0);
    let retained = path(&mut cache, &source, 8193, source.size(), &durable, &request).unwrap();
    assert!(
        source.reads.get() < 512,
        "warm read revisited {} leaves",
        source.reads.get()
    );
    assert_eq!(retained.root(), source.accumulator.root());
    let retained_pointer = retained.path.as_slice().as_ptr();
    // A different request admission owns a different response graph, while durable cache
    // backing survives the first request's final reader and original source view.
    let next_request = AllocationBudget::new(1 << 20);
    let replaced = Source::new(16_387, 19);
    let next = path(
        &mut cache,
        &replaced,
        8193,
        replaced.size(),
        &durable,
        &next_request,
    )
    .unwrap();
    assert_eq!(next.root(), replaced.accumulator.root());
    assert_ne!(next.root(), retained.root());
    assert_eq!(cache.nodes.as_ref().unwrap().as_slice().as_ptr(), backing);
    drop(source);
    assert_eq!(retained.path.as_slice().as_ptr(), retained_pointer);
    assert_eq!(request.reserved_bytes(), retained.path.capacity() * 32);
    drop(next);
    assert_eq!(next_request.reserved_bytes(), 0);
    drop(retained);
    assert_eq!(request.reserved_bytes(), 0);
    drop(cache);
    assert_eq!(durable.reserved_bytes(), 0);
}

#[test]
fn funded_history_refusal_keeps_original_wait_and_never_publishes_a_prefix() {
    for distinct in [false, true] {
        let durable = AllocationBudget::new(1 << 16);
        let request = if distinct {
            AllocationBudget::new(1 << 16)
        } else {
            durable.clone()
        };
        let source = Source::new(129, 7);
        let mut cache = SccpHistoryNodeCache::new();
        let mut reservation = durable
            .try_reserve(ReleaseRegistration::allocation_layout())
            .unwrap();
        let mut waiter = ReleaseRegistration::from_reservation(&mut reservation).unwrap();
        drop(reservation);
        let occupied = durable.reserved_bytes();
        let external = durable
            .try_reserve_bytes(durable.limit_bytes() - occupied)
            .unwrap();
        let error = path(&mut cache, &source, 128, source.size(), &durable, &request)
            .err()
            .unwrap();
        let SccpHistoryReadError::Admission(AllocationRefusal::Capacity {
            release,
            reserved_bytes,
            limit_bytes,
            ..
        }) = &error
        else {
            panic!("lost capacity: {error:?}")
        };
        assert_eq!(*reserved_bytes, durable.limit_bytes());
        assert_eq!(*limit_bytes, durable.limit_bytes());
        assert_eq!(cache.covered, 0);
        assert!(cache.nodes.is_none());
        assert_eq!(
            source.reads.get(),
            0,
            "no source graph is built before both admissions"
        );
        if distinct {
            assert_eq!(request.reserved_bytes(), 0);
        }
        let mut cx = Context::from_waker(Waker::noop());
        assert_eq!(waiter.poll_wait(release, &mut cx), Poll::Pending);
        drop(external);
        assert_eq!(waiter.poll_wait(release, &mut cx), Poll::Ready(()));
        let retained = path(&mut cache, &source, 128, source.size(), &durable, &request).unwrap();
        assert_eq!(retained.root(), source.accumulator.root());
        drop(retained);
        drop(cache);
        assert_eq!(durable.reserved_bytes(), occupied);
        waiter.cancel();
    }
}

#[test]
fn funded_history_rejects_foreign_pool_corruption_and_refunds_partial_unwind() {
    let durable = AllocationBudget::new(1 << 16);
    let request = AllocationBudget::new(1 << 16);
    let source = Source::new(129, 7);
    let mut cache = SccpHistoryNodeCache::new();
    source.panic_at.set(Some(65));
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let _ = path(&mut cache, &source, 128, source.size(), &durable, &request);
        }))
        .is_err()
    );
    assert_eq!(cache.covered, 0);
    assert!(cache.nodes.as_ref().unwrap().as_slice().is_empty());
    assert_eq!(
        durable.reserved_bytes(),
        cache.nodes.as_ref().unwrap().capacity() * 32
    );
    assert_eq!(request.reserved_bytes(), 0);
    source.panic_at.set(None);
    let valid = path(&mut cache, &source, 128, source.size(), &durable, &request).unwrap();
    assert_eq!(valid.root(), source.accumulator.root());
    drop(valid);
    assert!(matches!(
        path(&mut cache, &source, 128, source.size(), &request, &request),
        Err(SccpHistoryReadError::ForeignPool)
    ));
    let mut corrupt = Source::new(129, 8);
    corrupt.leaves[64][0] ^= 1;
    assert!(matches!(
        path(
            &mut cache,
            &corrupt,
            128,
            corrupt.size(),
            &durable,
            &request
        ),
        Err(SccpHistoryReadError::Inconsistent)
    ));
    assert_eq!(cache.covered, 0);
    assert!(cache.nodes.as_ref().unwrap().as_slice().is_empty());
    assert_eq!(request.reserved_bytes(), 0);
    drop(cache);
    assert_eq!(durable.reserved_bytes(), 0);
}

#[test]
fn funded_history_rejects_invalid_shape_bounds_and_overflow_before_admission() {
    let pool = AllocationBudget::new(0);
    let mut cache = SccpHistoryNodeCache::new();
    let mut source = Source::new(1, 7);
    assert!(matches!(
        path(&mut cache, &source, 1, 1, &pool, &pool),
        Err(SccpHistoryReadError::IndexOutOfRange)
    ));
    assert!(matches!(
        path(&mut cache, &source, 0, 2, &pool, &pool),
        Err(SccpHistoryReadError::SizeOutOfRange)
    ));
    source.leaves.clear();
    assert!(matches!(
        reserve_operation(&pool, usize::MAX, &pool, 1),
        Err(AllocationRefusal::DemandOverflow)
    ));
    assert_eq!(source.reads.get(), 0);
    assert_eq!(pool.reserved_bytes(), 0);
    // Maximum protocol geometry is representable without constructing its history graph.
    assert_eq!(
        node_count(MAX_HISTORY_SIZE / CHUNK).unwrap(),
        (MAX_HISTORY_SIZE / CHUNK * 2 - 1) as usize
    );
    assert_eq!(path_len(0, MAX_HISTORY_SIZE), 32);
}

#[test]
fn funded_history_never_publishes_a_path_rebound_from_native_root_or_leaf() {
    let cache_budget = AllocationBudget::new(1 << 16);
    let request_budget = AllocationBudget::new(1 << 16);
    let source = Source::new(129, 7);
    let mut cache = SccpHistoryNodeCache::new();
    let root = source.accumulator.root();
    let leaf = source.leaves[64];
    for (expected_root, expected_leaf) in [([0; 32], leaf), (root, [0; 32])] {
        let draft = cache
            .draft(&source, 64, source.size(), &cache_budget)
            .unwrap();
        let (mut request, mut backing) = reserve_operation(
            &request_budget,
            draft.request_demand().unwrap(),
            &cache_budget,
            draft.cache_demand().unwrap(),
        )
        .unwrap();
        assert!(matches!(
            draft.materialize_checked(
                &mut request,
                &mut backing,
                Some((expected_root, expected_leaf))
            ),
            Err(SccpHistoryReadError::Inconsistent)
        ));
        drop(request);
        drop(backing);
        assert_eq!(cache.covered, 0);
        assert!(cache.nodes.as_ref().unwrap().as_slice().is_empty());
        assert_eq!(request_budget.reserved_bytes(), 0);
    }
    let draft = cache
        .draft(&source, 64, source.size(), &cache_budget)
        .unwrap();
    let (mut request, mut backing) = reserve_operation(
        &request_budget,
        draft.request_demand().unwrap(),
        &cache_budget,
        draft.cache_demand().unwrap(),
    )
    .unwrap();
    let path = draft
        .materialize_checked(&mut request, &mut backing, Some((root, leaf)))
        .unwrap();
    assert_eq!(path.root(), root);
    assert_eq!(cache.covered, 128);
    drop((path, request, backing, cache));
    assert_eq!(request_budget.reserved_bytes(), 0);
    assert_eq!(cache_budget.reserved_bytes(), 0);
}

#[test]
fn funded_history_unchanged_peaks_cannot_publish_a_changed_selected_leaf() {
    let durable = AllocationBudget::new(1 << 16);
    let request = AllocationBudget::new(1 << 16);
    let mut cache = SccpHistoryNodeCache::new();
    let source = Source::new(129, 7);
    let retained = path(&mut cache, &source, 64, source.size(), &durable, &request).unwrap();
    let original_root = retained.root();
    let mut corrupt = Source::new(129, 7);
    corrupt.leaves[64][0] ^= 1;
    // The cache still matches the unchanged committed peaks. The selected leaf's
    // independent path must reject before the mutation is marked complete.
    assert!(matches!(
        path(&mut cache, &corrupt, 64, corrupt.size(), &durable, &request),
        Err(SccpHistoryReadError::Inconsistent)
    ));
    assert_eq!(cache.covered, 0);
    assert!(cache.nodes.as_ref().unwrap().as_slice().is_empty());
    assert_eq!(retained.root(), original_root);
    let retry = path(&mut cache, &source, 64, source.size(), &durable, &request).unwrap();
    assert_eq!(retry.root(), retained.root());
    assert_eq!(retry.path(), retained.path());
    drop((retained, retry, cache));
    assert_eq!(durable.reserved_bytes(), 0);
    assert_eq!(request.reserved_bytes(), 0);
}
