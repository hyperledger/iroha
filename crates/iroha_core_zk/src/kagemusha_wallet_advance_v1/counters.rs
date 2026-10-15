//! Storage work counters for on-device measurement (observation only).
//!
//! Each thread keeps its own in-memory counters; the provider, the state-owner archive and the
//! persistent indexes run synchronously on the calling thread, so the counters of one
//! operation are the work it performed itself. They hold public counts and monotonic
//! durations only, are never written to custody, a carrier or any signed structure, and no
//! code path reads them to decide admission, readiness, an error or a retry.

use std::{cell::Cell, time::Instant};

/// Storage work counted on the current thread.
///
/// Every field is a count of calls, except the `*_nanos` fields (monotonic time spent in the
/// matching sync calls) and [`Self::index_max_depth`]. The four sync classes are disjoint.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KagemushaWalletStorageCountersV1 {
    /// `ArchiveStore::get` calls on the provider archive.
    pub archive_gets: u64,
    /// `ArchiveStore::put` calls on the provider archive.
    pub archive_puts: u64,
    /// `ArchiveStore::remove` calls on the provider archive.
    pub archive_removes: u64,
    /// Archive puts of bytes this process already published durably at the same key: answered
    /// by the exact-bytes memo without a read, a write or a sync.
    pub archive_put_memo_hits: u64,
    /// Archive object reads answered from the current archive phase's authenticated objects.
    pub archive_object_cache_hits: u64,
    /// Durable-store file reads.
    pub reads: u64,
    /// Durable-store directory listings.
    pub listings: u64,
    /// Names published by create-new (a paired publication counts each name).
    pub write_new: u64,
    /// Byte-identical republications on a fresh inode.
    pub rewrite_same: u64,
    /// Replacements of exact current content with other bytes.
    pub replace_exact: u64,
    /// Durable file and empty-directory removals.
    pub removals: u64,
    /// Data syncs of staged files before publication.
    pub staged_syncs: u64,
    /// Time spent in staged-file syncs.
    pub staged_sync_nanos: u64,
    /// Parent-directory syncs that make a publication durable (`sync_after_publish` and the
    /// single sync of a paired publication).
    pub publish_syncs: u64,
    /// Time spent in publication syncs.
    pub publish_sync_nanos: u64,
    /// Every other directory sync (removals, existing directories, explicit syncs).
    pub dir_syncs: u64,
    /// Time spent in other directory syncs.
    pub dir_sync_nanos: u64,
    /// Syncs of existing named files.
    pub file_syncs: u64,
    /// Time spent in named-file syncs.
    pub file_sync_nanos: u64,
    /// Protected-storage state probes (a platform upcall on Android and iOS).
    pub storage_probes: u64,
    /// Slot reconciliations (cached or full).
    pub reconciles: u64,
    /// Full slot reconciliations from disk.
    pub full_reconciles: u64,
    /// Persistent index nodes read and authenticated.
    pub index_node_loads: u64,
    /// Persistent index nodes published.
    pub index_node_saves: u64,
    /// Persistent index lookups, updates, removals and predecessor searches.
    pub index_walks: u64,
    /// Most nodes loaded by one index lookup, update or removal (its path depth).
    pub index_max_depth: u64,
    /// Persistent map insertions.
    pub map_inserts: u64,
    /// Persistent map removals.
    pub map_removes: u64,
}

/// Sync classes timed by the durable store.
#[derive(Debug, Clone, Copy)]
pub(crate) enum SyncClassV1 {
    Staged,
    Publish,
    Dir,
    File,
}

/// Counted storage events without a duration.
#[derive(Debug, Clone, Copy)]
pub(crate) enum EventV1 {
    ArchiveGet,
    ArchivePut,
    ArchiveRemove,
    ArchivePutMemoHit,
    ArchiveObjectCacheHit,
    Read,
    Listing,
    WriteNew(u64),
    RewriteSame,
    ReplaceExact,
    Removal,
    StorageProbe,
    Reconcile,
    FullReconcile,
    IndexNodeLoad,
    IndexNodeSave,
    MapInsert,
    MapRemove,
}

const ZERO: KagemushaWalletStorageCountersV1 = KagemushaWalletStorageCountersV1 {
    archive_gets: 0,
    archive_puts: 0,
    archive_removes: 0,
    archive_put_memo_hits: 0,
    archive_object_cache_hits: 0,
    reads: 0,
    listings: 0,
    write_new: 0,
    rewrite_same: 0,
    replace_exact: 0,
    removals: 0,
    staged_syncs: 0,
    staged_sync_nanos: 0,
    publish_syncs: 0,
    publish_sync_nanos: 0,
    dir_syncs: 0,
    dir_sync_nanos: 0,
    file_syncs: 0,
    file_sync_nanos: 0,
    storage_probes: 0,
    reconciles: 0,
    full_reconciles: 0,
    index_node_loads: 0,
    index_node_saves: 0,
    index_walks: 0,
    index_max_depth: 0,
    map_inserts: 0,
    map_removes: 0,
};

thread_local! {
    static COUNTERS: Cell<KagemushaWalletStorageCountersV1> = const { Cell::new(ZERO) };
}

// Counting never fails or panics: a thread whose local storage is gone counts nothing.
fn update(change: impl FnOnce(&mut KagemushaWalletStorageCountersV1)) {
    let _ = COUNTERS.try_with(|cell| {
        let mut counters = cell.get();
        change(&mut counters);
        cell.set(counters);
    });
}

fn bump(field: &mut u64, amount: u64) {
    *field = field.saturating_add(amount);
}

/// Count one storage event on the current thread.
pub(crate) fn count(event: EventV1) {
    update(|c| match event {
        EventV1::ArchiveGet => bump(&mut c.archive_gets, 1),
        EventV1::ArchivePut => bump(&mut c.archive_puts, 1),
        EventV1::ArchiveRemove => bump(&mut c.archive_removes, 1),
        EventV1::ArchivePutMemoHit => bump(&mut c.archive_put_memo_hits, 1),
        EventV1::ArchiveObjectCacheHit => bump(&mut c.archive_object_cache_hits, 1),
        EventV1::Read => bump(&mut c.reads, 1),
        EventV1::Listing => bump(&mut c.listings, 1),
        EventV1::WriteNew(names) => bump(&mut c.write_new, names),
        EventV1::RewriteSame => bump(&mut c.rewrite_same, 1),
        EventV1::ReplaceExact => bump(&mut c.replace_exact, 1),
        EventV1::Removal => bump(&mut c.removals, 1),
        EventV1::StorageProbe => bump(&mut c.storage_probes, 1),
        EventV1::Reconcile => bump(&mut c.reconciles, 1),
        EventV1::FullReconcile => bump(&mut c.full_reconciles, 1),
        EventV1::IndexNodeLoad => bump(&mut c.index_node_loads, 1),
        EventV1::IndexNodeSave => bump(&mut c.index_node_saves, 1),
        EventV1::MapInsert => bump(&mut c.map_inserts, 1),
        EventV1::MapRemove => bump(&mut c.map_removes, 1),
    });
}

/// Run one sync call, counting it and its monotonic duration whatever its result.
pub(crate) fn sync<T>(class: SyncClassV1, call: impl FnOnce() -> T) -> T {
    let started = Instant::now();
    let result = call();
    let nanos = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    update(|c| {
        let (calls, time) = match class {
            SyncClassV1::Staged => (&mut c.staged_syncs, &mut c.staged_sync_nanos),
            SyncClassV1::Publish => (&mut c.publish_syncs, &mut c.publish_sync_nanos),
            SyncClassV1::Dir => (&mut c.dir_syncs, &mut c.dir_sync_nanos),
            SyncClassV1::File => (&mut c.file_syncs, &mut c.file_sync_nanos),
        };
        bump(calls, 1);
        bump(time, nanos);
    });
    result
}

/// Probe protected storage through `platform`, counting the upcall.
pub(crate) fn probe_storage<P: super::KagemushaWalletPlatformV1 + ?Sized>(
    platform: &P,
) -> Result<(), super::KagemushaWalletUnavailableV1> {
    count(EventV1::StorageProbe);
    platform.storage_state()
}

/// One persistent index walk; dropping it records the walk and, for a single-path walk, the
/// number of nodes it loaded as its depth.
pub(crate) struct IndexWalkV1 {
    loads: u64,
    path: bool,
}

impl IndexWalkV1 {
    /// Start a lookup, update or removal (`path`) or a predecessor search.
    pub(crate) fn start(path: bool) -> Self {
        Self {
            loads: KagemushaWalletStorageCountersV1::current().index_node_loads,
            path,
        }
    }
}

impl Drop for IndexWalkV1 {
    fn drop(&mut self) {
        let (loads, path) = (self.loads, self.path);
        update(|c| {
            bump(&mut c.index_walks, 1);
            if path {
                let depth = c.index_node_loads.saturating_sub(loads);
                c.index_max_depth = c.index_max_depth.max(depth);
            }
        });
    }
}

// Restores the enclosing observation, including when the observed operation unwinds.
struct ObservationV1 {
    outer: KagemushaWalletStorageCountersV1,
}

impl Drop for ObservationV1 {
    fn drop(&mut self) {
        let outer = self.outer;
        update(|c| *c = outer.merged(*c));
    }
}

impl KagemushaWalletStorageCountersV1 {
    /// Cumulative counters of the calling thread.
    #[must_use]
    pub fn current() -> Self {
        COUNTERS.try_with(Cell::get).unwrap_or(ZERO)
    }

    /// Run `operation` and return its result with the storage work it performed on the
    /// calling thread. Enclosing observations and [`Self::current`] still include that work.
    pub fn observe<T>(operation: impl FnOnce() -> T) -> (T, Self) {
        let observation = ObservationV1 {
            outer: COUNTERS.try_with(|cell| cell.replace(ZERO)).unwrap_or(ZERO),
        };
        let value = operation();
        let inner = Self::current();
        drop(observation);
        (value, inner)
    }

    /// Sync calls of every class.
    #[must_use]
    pub fn fsync_class_calls(&self) -> u64 {
        self.staged_syncs
            .saturating_add(self.publish_syncs)
            .saturating_add(self.dir_syncs)
            .saturating_add(self.file_syncs)
    }

    /// Time spent in sync calls of every class.
    #[must_use]
    pub fn fsync_class_nanos(&self) -> u64 {
        self.staged_sync_nanos
            .saturating_add(self.publish_sync_nanos)
            .saturating_add(self.dir_sync_nanos)
            .saturating_add(self.file_sync_nanos)
    }

    /// Named public counts and durations, in declaration order, for logs.
    #[must_use]
    pub fn fields(&self) -> [(&'static str, u64); 28] {
        [
            ("archive_gets", self.archive_gets),
            ("archive_puts", self.archive_puts),
            ("archive_removes", self.archive_removes),
            ("archive_put_memo_hits", self.archive_put_memo_hits),
            ("archive_object_cache_hits", self.archive_object_cache_hits),
            ("reads", self.reads),
            ("listings", self.listings),
            ("write_new", self.write_new),
            ("rewrite_same", self.rewrite_same),
            ("replace_exact", self.replace_exact),
            ("removals", self.removals),
            ("staged_syncs", self.staged_syncs),
            ("staged_sync_nanos", self.staged_sync_nanos),
            ("publish_syncs", self.publish_syncs),
            ("publish_sync_nanos", self.publish_sync_nanos),
            ("dir_syncs", self.dir_syncs),
            ("dir_sync_nanos", self.dir_sync_nanos),
            ("file_syncs", self.file_syncs),
            ("file_sync_nanos", self.file_sync_nanos),
            ("storage_probes", self.storage_probes),
            ("reconciles", self.reconciles),
            ("full_reconciles", self.full_reconciles),
            ("index_node_loads", self.index_node_loads),
            ("index_node_saves", self.index_node_saves),
            ("index_walks", self.index_walks),
            ("index_max_depth", self.index_max_depth),
            ("map_inserts", self.map_inserts),
            ("map_removes", self.map_removes),
        ]
    }

    fn merged(self, other: Self) -> Self {
        let sum = |a: u64, b: u64| a.saturating_add(b);
        Self {
            archive_gets: sum(self.archive_gets, other.archive_gets),
            archive_puts: sum(self.archive_puts, other.archive_puts),
            archive_removes: sum(self.archive_removes, other.archive_removes),
            archive_put_memo_hits: sum(self.archive_put_memo_hits, other.archive_put_memo_hits),
            archive_object_cache_hits: sum(
                self.archive_object_cache_hits,
                other.archive_object_cache_hits,
            ),
            reads: sum(self.reads, other.reads),
            listings: sum(self.listings, other.listings),
            write_new: sum(self.write_new, other.write_new),
            rewrite_same: sum(self.rewrite_same, other.rewrite_same),
            replace_exact: sum(self.replace_exact, other.replace_exact),
            removals: sum(self.removals, other.removals),
            staged_syncs: sum(self.staged_syncs, other.staged_syncs),
            staged_sync_nanos: sum(self.staged_sync_nanos, other.staged_sync_nanos),
            publish_syncs: sum(self.publish_syncs, other.publish_syncs),
            publish_sync_nanos: sum(self.publish_sync_nanos, other.publish_sync_nanos),
            dir_syncs: sum(self.dir_syncs, other.dir_syncs),
            dir_sync_nanos: sum(self.dir_sync_nanos, other.dir_sync_nanos),
            file_syncs: sum(self.file_syncs, other.file_syncs),
            file_sync_nanos: sum(self.file_sync_nanos, other.file_sync_nanos),
            storage_probes: sum(self.storage_probes, other.storage_probes),
            reconciles: sum(self.reconciles, other.reconciles),
            full_reconciles: sum(self.full_reconciles, other.full_reconciles),
            index_node_loads: sum(self.index_node_loads, other.index_node_loads),
            index_node_saves: sum(self.index_node_saves, other.index_node_saves),
            index_walks: sum(self.index_walks, other.index_walks),
            index_max_depth: self.index_max_depth.max(other.index_max_depth),
            map_inserts: sum(self.map_inserts, other.map_inserts),
            map_removes: sum(self.map_removes, other.map_removes),
        }
    }
}

#[cfg(test)]
#[path = "counters_tests.rs"]
mod tests;
