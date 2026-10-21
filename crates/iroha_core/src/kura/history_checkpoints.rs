//! Node-local checkpoints of authenticated native execution identities.
//!
//! Reading the execution of a committed block requires its native identity:
//! the Iroha header hash, the native core header hash and the certified result
//! `R`. The State keeps only the tip's identity, so a reader authenticates
//! older blocks by walking parent links down from the tip, paying for every
//! newer block. Checkpoints let off-chain readers (Torii collections and the
//! explorer) start a descending walk just above their target instead:
//!
//! * *sparse* checkpoints keep selected [`HISTORY_CHECKPOINT_INTERVAL`]-th heights
//!   in finite native backing; a retained neighboring checkpoint shortens a cold walk;
//! * *recent* entries keep the last [`RECENT_CAPACITY`] heights that walks
//!   verified, so a reader paging downward starts one block above its target.
//!
//! An identity is recorded only after it was authenticated: by a verified
//! descending walk, by the startup verification of the native prefix, or when
//! an authorized execution advances the tip. A reader trusts an entry only
//! while its Iroha hash equals the reader's committed hash journal at that
//! height, so an entry left by an abandoned block is ignored and dropped.
//! Checkpoints are never persisted, decoded or consulted by consensus:
//! on-chain readers keep walking from the tip, so metered work never depends
//! on node-local state.
mod finite;

use iroha_allocation::AllocationBudget;

use iroha_crypto::HashOf;
use iroha_data_model::block::BlockHeader;
use iroha_sumeragi::types::Hash32;
use parking_lot::RwLock;

/// Heights between consecutive sparse checkpoint candidates. Eviction can require a longer
/// authenticated walk, which remains subject to the reader's independent work limit.
pub const HISTORY_CHECKPOINT_INTERVAL: u64 = 64;

/// Recently verified heights kept for readers paging through history.
pub const RECENT_CAPACITY: usize = 4096;

/// Entries examined per lookup before falling back to the tip.
#[cfg(test)]
const LOOKUP_CANDIDATES: usize = 4;

/// The authenticated native identity of one committed height.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryCheckpoint {
    /// Exact Iroha header identity of the block.
    pub iroha_hash: HashOf<BlockHeader>,
    /// Exact native core header identity.
    pub core_hash: Hash32,
    /// Exact certified execution result.
    pub result: Hash32,
}

/// Fixed native sparse/recent identities in an independent node-cache pool.
///
/// Full capacity evicts only optional least-recently-observed entries. Allocator refusal
/// leaves this cache empty; no query, consensus, tip or authenticated identity changes.
pub struct HistoryCheckpoints {
    inner: RwLock<Option<finite::Storage>>,
}
impl std::fmt::Debug for HistoryCheckpoints {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("HistoryCheckpoints")
            .field("enabled", &self.inner.read().is_some())
            .finish()
    }
}
impl Default for HistoryCheckpoints {
    fn default() -> Self {
        Self::new(iroha_config::parameters::defaults::kura::HISTORY_CHECKPOINT_CACHE_CAPACITY.get())
    }
}

impl HistoryCheckpoints {
    /// Initialize complete fixed backing in its own finite pool before publication.
    /// Invalid native layout or physical refusal declines this optional cache.
    pub fn new(capacity: usize) -> Self {
        let storage = (capacity != 0
            && capacity
                <= iroha_config::parameters::defaults::kura::MAX_HISTORY_CHECKPOINT_CACHE_CAPACITY)
            .then(|| finite::Geometry::for_count(capacity))
            .flatten()
            .and_then(|geometry| {
                let pool = AllocationBudget::new(geometry.backing_bytes);
                finite::Storage::new(geometry, &pool).ok()
            });
        Self {
            inner: RwLock::new(storage),
        }
    }

    /// Whether `height` keeps a sparse checkpoint.
    #[must_use]
    pub const fn is_checkpoint_height(height: u64) -> bool {
        height != 0 && height.is_multiple_of(HISTORY_CHECKPOINT_INTERVAL)
    }

    /// Record an identity a reader just verified: as a recent entry, and as a
    /// sparse checkpoint when `height` is a checkpoint height.
    pub fn record(&self, height: u64, checkpoint: HistoryCheckpoint) {
        if let Some(entries) = self.inner.write().as_mut() {
            entries.record(height, checkpoint, Self::is_checkpoint_height(height));
        }
    }

    /// Record an authenticated identity as a sparse checkpoint only (startup
    /// verification and tip advances, which would otherwise churn the recent
    /// entries).
    pub fn record_sparse(&self, height: u64, checkpoint: HistoryCheckpoint) {
        if !Self::is_checkpoint_height(height) {
            return;
        }
        if let Some(entries) = self.inner.write().as_mut() {
            entries.record_sparse(height, checkpoint);
        }
    }

    /// The nearest entries at or above `target` and at or below `ceiling`,
    /// nearest first; callers verify each against their hash journal.
    #[must_use]
    pub(crate) fn candidates(&self, target: u64, ceiling: u64) -> finite::Candidates {
        self.inner
            .read()
            .as_ref()
            .map_or_else(finite::Candidates::default, |entries| {
                entries.candidates(target, ceiling)
            })
    }

    /// Drop `checkpoint` at `height` after it contradicted a hash journal.
    pub fn forget(&self, height: u64, checkpoint: &HistoryCheckpoint) {
        if let Some(entries) = self.inner.write().as_mut() {
            entries.forget(height, checkpoint);
        }
    }

    /// Number of sparse checkpoints.
    #[cfg(test)]
    #[must_use]
    pub fn sparse_len(&self) -> usize {
        self.inner
            .read()
            .as_ref()
            .map_or(0, finite::Storage::sparse_len)
    }

    /// Number of recent entries.
    #[cfg(test)]
    #[must_use]
    pub fn recent_len(&self) -> usize {
        self.inner
            .read()
            .as_ref()
            .map_or(0, finite::Storage::recent_len)
    }

    /// Forget every entry, as after a restart without the startup walk.
    #[cfg(any(test, feature = "iroha-core-tests"))]
    pub fn clear(&self) {
        if let Some(entries) = self.inner.write().as_mut() {
            entries.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::Hash;

    fn checkpoint(seed: u64) -> HistoryCheckpoint {
        let byte = u8::try_from(seed % 251).expect("fits");
        HistoryCheckpoint {
            iroha_hash: HashOf::from_untyped_unchecked(Hash::prehashed([byte; 32])),
            core_hash: Hash32([byte; 32]),
            result: Hash32([byte.wrapping_add(1); 32]),
        }
    }

    #[test]
    fn checkpoint_cache_rejects_invalid_counts_without_native_backing() {
        for count in [
            0,
            iroha_config::parameters::defaults::kura::MAX_HISTORY_CHECKPOINT_CACHE_CAPACITY + 1,
            usize::MAX,
        ] {
            let cache = HistoryCheckpoints::new(count);
            cache.record_sparse(HISTORY_CHECKPOINT_INTERVAL, checkpoint(1));
            assert_eq!(cache.sparse_len(), 0);
            assert!(cache.candidates(1, HISTORY_CHECKPOINT_INTERVAL).is_empty());
        }
    }

    #[test]
    fn sparse_records_keep_only_checkpoint_heights() {
        let checkpoints = HistoryCheckpoints::default();
        checkpoints.record_sparse(1, checkpoint(1));
        checkpoints.record_sparse(HISTORY_CHECKPOINT_INTERVAL - 1, checkpoint(2));
        assert_eq!(checkpoints.sparse_len(), 0);
        checkpoints.record_sparse(HISTORY_CHECKPOINT_INTERVAL, checkpoint(3));
        checkpoints.record(2 * HISTORY_CHECKPOINT_INTERVAL, checkpoint(4));
        assert_eq!(checkpoints.sparse_len(), 2);
        assert_eq!(checkpoints.recent_len(), 1, "only walk records are recent");
    }

    #[test]
    fn candidates_are_the_nearest_at_or_above_the_target() {
        let checkpoints = HistoryCheckpoints::default();
        let interval = HISTORY_CHECKPOINT_INTERVAL;
        for step in 1..=8 {
            checkpoints.record_sparse(step * interval, checkpoint(step));
        }
        checkpoints.record(interval + 3, checkpoint(99));
        let found = checkpoints.candidates(interval + 1, 8 * interval);
        assert_eq!(found.len(), LOOKUP_CANDIDATES);
        assert_eq!(
            found[0],
            (interval + 3, checkpoint(99)),
            "a recent entry is nearest"
        );
        assert_eq!(found[1].0, 2 * interval);
        assert!(
            checkpoints
                .candidates(7 * interval + 1, 7 * interval)
                .is_empty()
        );
        assert_eq!(
            checkpoints.candidates(interval, 3 * interval)[0].0,
            interval,
            "an entry at the target itself is the nearest"
        );
    }

    #[test]
    fn recent_entries_are_bounded_and_evicted_oldest_first() {
        let checkpoints = HistoryCheckpoints::default();
        let first = 1_000_001;
        for height in first..first + RECENT_CAPACITY as u64 + 10 {
            checkpoints.record(height, checkpoint(height));
        }
        assert_eq!(checkpoints.recent_len(), RECENT_CAPACITY);
        assert!(
            checkpoints
                .candidates(first, first + 9)
                .iter()
                .all(|(height, _)| HistoryCheckpoints::is_checkpoint_height(*height)),
            "the oldest recent entries were evicted"
        );
        assert_eq!(
            checkpoints.candidates(first + 10, first + 10)[0].0,
            first + 10
        );
    }

    #[test]
    fn contradicted_entries_are_replaced_or_forgotten() {
        let checkpoints = HistoryCheckpoints::default();
        let height = HISTORY_CHECKPOINT_INTERVAL;
        checkpoints.record(height, checkpoint(1));
        checkpoints.record(height, checkpoint(2));
        assert_eq!(checkpoints.candidates(1, height)[0].1, checkpoint(2));
        checkpoints.forget(height, &checkpoint(1));
        assert_eq!(
            checkpoints.sparse_len(),
            1,
            "only the exact stale entry is dropped"
        );
        checkpoints.forget(height, &checkpoint(2));
        assert_eq!(checkpoints.sparse_len(), 0);
        assert_eq!(checkpoints.recent_len(), 0);
    }
}
