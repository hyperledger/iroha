//! Fixed native checkpoint backing. Optional cache entries never acquire query/consensus credit.

use core::{alloc::Layout, ops::Index};

use iroha_allocation::{AllocationBudget, ChargedBuffer, ChargedBufferError};

use super::{HistoryCheckpoint, RECENT_CAPACITY};

const CANDIDATES: usize = 4;

/// A checkpoint owns only fixed hash values. No epoch, key or execution graph is copied here.
#[derive(Clone, Copy)]
struct Record {
    height: u64,
    checkpoint: HistoryCheckpoint,
    recency: u64,
}

/// Exact whole-array backing geometry before either array is allocated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Geometry {
    pub(super) sparse_capacity: usize,
    pub(super) recent_capacity: usize,
    pub(super) backing_bytes: usize,
}
impl Geometry {
    pub(super) fn for_count(slots: usize) -> Option<Self> {
        let backing_bytes = Layout::array::<Record>(slots).ok()?.size();
        Some(Self {
            sparse_capacity: slots - (slots / 2).min(RECENT_CAPACITY),
            recent_capacity: (slots / 2).min(RECENT_CAPACITY),
            backing_bytes,
        })
    }
}

pub(super) struct Storage {
    sparse: ChargedBuffer<Record>,
    recent: ChargedBuffer<Record>,
    recency: u64,
}
impl Storage {
    pub(super) fn new(
        geometry: Geometry,
        original: &AllocationBudget,
    ) -> Result<Self, ChargedBufferError> {
        // If either allocation refuses, the earlier backing is dropped and refunded. There
        // is no partial cache publication and no attempt to borrow a query/consensus pool.
        let sparse = ChargedBuffer::new(geometry.sparse_capacity, original)?;
        let recent = ChargedBuffer::new(geometry.recent_capacity, original)?;
        Ok(Self {
            sparse,
            recent,
            recency: 0,
        })
    }

    fn next_recency(&mut self) -> u64 {
        if self.recency == u64::MAX {
            // Rebase only local optional eviction metadata, with fixed backing and no sorting
            // allocation. Hash identities, authenticated tip and consensus state are untouched.
            for record in self.sparse.as_mut_slice() {
                record.recency = 0;
            }
            for record in self.recent.as_mut_slice() {
                record.recency = 0;
            }
            self.recency = 0;
        }
        self.recency += 1;
        self.recency
    }

    pub(super) fn record(&mut self, height: u64, checkpoint: HistoryCheckpoint, sparse: bool) {
        let recency = self.next_recency();
        let record = Record {
            height,
            checkpoint,
            recency,
        };
        if sparse {
            insert(&mut self.sparse, record);
        }
        insert(&mut self.recent, record);
    }

    pub(super) fn record_sparse(&mut self, height: u64, checkpoint: HistoryCheckpoint) {
        let recency = self.next_recency();
        insert(
            &mut self.sparse,
            Record {
                height,
                checkpoint,
                recency,
            },
        );
    }

    pub(super) fn candidates(&self, target: u64, ceiling: u64) -> Candidates {
        let mut found = Candidates::default();
        if target > ceiling {
            return found;
        }
        for records in [&self.recent, &self.sparse] {
            let start = records
                .as_slice()
                .partition_point(|row| row.height < target);
            for row in records.as_slice()[start..].iter().take(CANDIDATES) {
                if row.height > ceiling {
                    break;
                }
                found.insert((row.height, row.checkpoint));
            }
        }
        found
    }

    pub(super) fn forget(&mut self, height: u64, checkpoint: &HistoryCheckpoint) {
        for records in [&mut self.sparse, &mut self.recent] {
            if let Ok(index) = records
                .as_slice()
                .binary_search_by_key(&height, |row| row.height)
                && records.as_slice()[index].checkpoint == *checkpoint
            {
                remove(records, index);
            }
        }
    }

    #[cfg(test)]
    pub(super) fn sparse_len(&self) -> usize {
        self.sparse.as_slice().len()
    }
    #[cfg(test)]
    pub(super) fn recent_len(&self) -> usize {
        self.recent.as_slice().len()
    }
    #[cfg(test)]
    pub(super) fn clear(&mut self) {
        while self.sparse.pop().is_some() {}
        while self.recent.pop().is_some() {}
        self.recency = 0;
    }
}

fn remove(records: &mut ChargedBuffer<Record>, index: usize) {
    records.as_mut_slice().copy_within(index + 1.., index);
    records.pop();
}

fn insert(records: &mut ChargedBuffer<Record>, record: Record) {
    if records.capacity() == 0 {
        return;
    }
    if let Ok(index) = records
        .as_slice()
        .binary_search_by_key(&record.height, |row| row.height)
    {
        records.as_mut_slice()[index] = record;
        return;
    }
    if records.as_slice().len() == records.capacity() {
        let oldest = records
            .as_slice()
            .iter()
            .enumerate()
            .min_by_key(|(_, row)| row.recency)
            .map(|(index, _)| index)
            .expect("a full nonempty region has an optional eviction candidate");
        remove(records, oldest);
    }
    let index = records
        .as_slice()
        .partition_point(|row| row.height < record.height);
    let old_len = records.as_slice().len();
    records.push_reserved(record);
    records
        .as_mut_slice()
        .copy_within(index..old_len, index + 1);
    records.as_mut_slice()[index] = record;
}

/// The bounded lookup result lives entirely on the caller's stack.
#[derive(Clone, Copy, Default)]
pub(crate) struct Candidates {
    values: [Option<(u64, HistoryCheckpoint)>; CANDIDATES],
    length: usize,
}
impl Candidates {
    fn insert(&mut self, value: (u64, HistoryCheckpoint)) {
        if self.iter().any(|row| *row == value) {
            return;
        }
        let index = self
            .iter()
            .position(|row| row.0 >= value.0)
            .unwrap_or(self.length);
        if index == CANDIDATES {
            return;
        }
        let new_len = (self.length + 1).min(CANDIDATES);
        for destination in (index + 1..new_len).rev() {
            self.values[destination] = self.values[destination - 1];
        }
        self.values[index] = Some(value);
        self.length = new_len;
    }
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.length
    }
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.length == 0
    }
    pub(crate) fn iter(&self) -> impl Iterator<Item = &(u64, HistoryCheckpoint)> {
        self.values[..self.length]
            .iter()
            .map(|row| row.as_ref().expect("initialized candidate"))
    }
}
impl Index<usize> for Candidates {
    type Output = (u64, HistoryCheckpoint);
    fn index(&self, index: usize) -> &Self::Output {
        self.values[..self.length][index]
            .as_ref()
            .expect("initialized candidate")
    }
}
impl IntoIterator for Candidates {
    type Item = (u64, HistoryCheckpoint);
    type IntoIter = core::iter::Flatten<core::array::IntoIter<Option<Self::Item>, CANDIDATES>>;
    fn into_iter(self) -> Self::IntoIter {
        self.values.into_iter().flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Hash, HashOf};
    use iroha_sumeragi::types::Hash32;

    fn checkpoint(seed: u64) -> HistoryCheckpoint {
        let bytes = [seed.to_le_bytes()[0]; 32];
        HistoryCheckpoint {
            iroha_hash: HashOf::from_untyped_unchecked(Hash::prehashed(bytes)),
            core_hash: Hash32(bytes),
            result: Hash32(bytes),
        }
    }

    #[test]
    fn whole_cache_native_geometry_and_refusal_preserve_the_original_pool() {
        let bytes = 12 * Layout::new::<Record>().size() + Layout::new::<Record>().size() - 1;
        let geometry = Geometry::for_count(bytes / Layout::new::<Record>().size()).unwrap();
        assert_eq!(geometry.sparse_capacity, 6);
        assert_eq!(geometry.recent_capacity, 6);
        assert_eq!(geometry.backing_bytes, 12 * Layout::new::<Record>().size());
        let pool = AllocationBudget::new(geometry.backing_bytes - 1);
        assert!(Storage::new(geometry, &pool).is_err());
        assert_eq!(
            pool.reserved_bytes(),
            0,
            "partial constructor backing is refunded"
        );
        pool.set_limit_bytes(geometry.backing_bytes);
        let mut cache = Storage::new(geometry, &pool).unwrap();
        let original_charge = pool.reserved_bytes();
        for height in 1..1000 {
            cache.record(height, checkpoint(height), true);
        }
        assert_eq!(cache.sparse_len(), 6);
        assert_eq!(cache.recent_len(), 6);
        assert_eq!(
            pool.reserved_bytes(),
            original_charge,
            "insert/evict allocate no backing"
        );
        drop(cache);
        assert_eq!(pool.reserved_bytes(), 0);
    }

    #[test]
    fn sparse_capacity_evicts_oldest_observed_identity_and_remains_usable() {
        let geometry = Geometry {
            sparse_capacity: 2,
            recent_capacity: 0,
            backing_bytes: 2 * Layout::new::<Record>().size(),
        };
        let pool = AllocationBudget::new(geometry.backing_bytes);
        let mut cache = Storage::new(geometry, &pool).unwrap();
        cache.record_sparse(64, checkpoint(1));
        cache.record_sparse(128, checkpoint(2));
        cache.record_sparse(64, checkpoint(3));
        cache.record_sparse(192, checkpoint(4));
        assert!(cache.candidates(128, 128).is_empty());
        assert_eq!(cache.candidates(64, 64)[0].1, checkpoint(3));
        assert_eq!(cache.candidates(192, 192)[0].1, checkpoint(4));
        cache.forget(64, &checkpoint(1));
        assert_eq!(
            cache.sparse_len(),
            2,
            "foreign identity cannot evict current metadata"
        );
        cache.forget(64, &checkpoint(3));
        assert_eq!(cache.sparse_len(), 1);
    }

    #[test]
    fn candidate_merge_is_native_fixed_backing_sorted_unique_and_bounded() {
        let geometry = Geometry::for_count(16).unwrap();
        let pool = AllocationBudget::new(geometry.backing_bytes);
        let mut cache = Storage::new(geometry, &pool).unwrap();
        for height in (1..=8).rev() {
            cache.record(height, checkpoint(height), true);
        }
        let charge = pool.reserved_bytes();
        let candidates = cache.candidates(2, 8);
        assert_eq!(candidates.len(), 4);
        assert_eq!(
            candidates.into_iter().map(|row| row.0).collect::<Vec<_>>(),
            [2, 3, 4, 5]
        );
        assert_eq!(pool.reserved_bytes(), charge);
        cache.recency = u64::MAX;
        cache.record_sparse(9, checkpoint(9));
        assert_eq!(cache.candidates(9, 9)[0].0, 9);
    }
}
