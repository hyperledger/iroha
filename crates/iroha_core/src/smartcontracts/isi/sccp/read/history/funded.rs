//! Explicit original-pool custody for reusable SCCP history nodes and their paths.
//! The integrating owner must retain both this cache and its real enclosing admission.
//! A per-request allocation charge alone cannot authorize a process-global cache lifetime.

use super::super::super::store;
use crate::state::WorldReadOnly;
use iroha_allocation::{
    AllocationBudget, AllocationRefusal, AllocationReservation, ChargedBuffer, PrepaidBufferError,
};
use iroha_sccp::v1::{constants::MAX_HISTORY_SIZE, hashes::node, history::HistoryAccumulatorV1};
use std::alloc::Layout;

const MIN_LEVEL: u32 = 5;
const CHUNK: u64 = 1 << MIN_LEVEL;
// Derive physical element counts from the same fixed level without narrowing heights.
const CHUNK_LEN: usize = 1 << MIN_LEVEL;
type Hash = [u8; 32];

/// Typed failure without replacing the caller's original capacity/release observation.
#[derive(Debug, thiserror::Error)]
pub enum SccpHistoryReadError {
    /// The requested size lies outside the stored history.
    #[error("SCCP history size is out of range")]
    SizeOutOfRange,
    /// The index is not below the selected size.
    #[error("SCCP history index is outside the selected size")]
    IndexOutOfRange,
    /// No stored commitment exists at the requested block.
    #[error("no SCCP commitment at the requested height")]
    MissingCommitment,
    /// Stored leaves, peaks or cached nodes do not reproduce one consistent history.
    #[error("SCCP history leaves do not match the accumulator")]
    Inconsistent,
    /// Cached physical backing belongs to a different original pool.
    #[error("SCCP history cache belongs to a different original pool")]
    ForeignPool,
    /// Complete operation admission refused before cache mutation or physical allocation.
    #[error(transparent)]
    Admission(#[from] AllocationRefusal),
    /// A physical allocation failed inside the original prepayment.
    #[error(transparent)]
    Backing(#[from] PrepaidBufferError),
}

/// Explicit cache of every complete perfect subtree of at least 32 leaves.
///
/// Backing is prepaid and retained in its original pool. No global singleton or request
/// lease is created here. Nodes use append-only postorder; doubling physical capacity gives
/// amortized constant-time append without a separately allocated level/offset graph.
#[derive(Default)]
pub struct SccpHistoryNodeCache {
    covered: u64,
    nodes: Option<ChargedBuffer<Hash>>,
}

/// Root and path retaining the same physical buffer until the last reader drops it.
pub struct RetainedSccpHistoryPath {
    root: Hash,
    path: ChargedBuffer<Hash>,
}
impl RetainedSccpHistoryPath {
    /// Computed history root, to be bound independently to the original certified X.
    #[must_use]
    pub fn root(&self) -> Hash {
        self.root
    }
    /// Borrow the positional path without copying or extracting its allocation.
    #[must_use]
    pub fn path(&self) -> &[Hash] {
        self.path.as_slice()
    }
    pub(crate) fn into_buffer(self) -> ChargedBuffer<Hash> {
        self.path
    }
}

pub(crate) trait BorrowedHistorySource {
    fn size(&self) -> u64;
    fn peaks(&self) -> &[Hash];
    fn leaf(&self, index: u64) -> Option<Hash>;
}
pub(crate) struct WorldHistory<'a, W: WorldReadOnly + ?Sized>(pub &'a W);
impl<W: WorldReadOnly + ?Sized> BorrowedHistorySource for WorldHistory<'_, W> {
    fn size(&self) -> u64 {
        store::history::get(self.0).size
    }
    fn peaks(&self) -> &[Hash] {
        &store::history::get(self.0).peaks
    }
    fn leaf(&self, index: u64) -> Option<Hash> {
        store::history_leaves::get(self.0, &index).map(|(_, leaf)| *leaf)
    }
}

pub(crate) struct HistoryDraft<'a> {
    cache: &'a mut SccpHistoryNodeCache,
    source: &'a dyn BorrowedHistorySource,
    index: u64,
    size: u64,
    new_capacity: Option<usize>,
    path_len: usize,
}

pub(crate) fn path_len(mut index: u64, mut count: u64) -> usize {
    let mut length = 0;
    while count > 1 {
        if index % 2 == 1 || index + 1 < count {
            length += 1;
        }
        index >>= 1;
        count = count.div_ceil(2);
    }
    length
}
fn array_bytes(count: usize) -> Result<usize, AllocationRefusal> {
    Ok(Layout::array::<Hash>(count)
        .map_err(|_| AllocationRefusal::DemandOverflow)?
        .size())
}
fn node_count(chunks: u64) -> Result<usize, SccpHistoryReadError> {
    usize::try_from(
        chunks
            .checked_mul(2)
            .and_then(|twice| twice.checked_sub(u64::from(chunks.count_ones())))
            .ok_or(SccpHistoryReadError::Inconsistent)?,
    )
    .map_err(|_| AllocationRefusal::DemandOverflow.into())
}
// Postorder position of one completed chunk-tree subtree. Its completion appends this
// root, then any larger carries; subtract only those larger carries from the final length.
fn node_index(level: u32, position: u64) -> Option<usize> {
    let completed = position.checked_add(1)?.checked_shl(level)?;
    let count = completed
        .checked_mul(2)?
        .checked_sub(u64::from(completed.count_ones()))?;
    let later_carries = completed.trailing_zeros().checked_sub(level)?;
    usize::try_from(count.checked_sub(1 + u64::from(later_carries))?).ok()
}

impl SccpHistoryNodeCache {
    /// Construct an allocation-free empty cache; its first real caller supplies custody.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a funded path after checking the source's canonical peaks and bounds.
    ///
    /// # Errors
    /// Preserves source errors, original admission refusal and physical allocation errors.
    pub fn root_and_path(
        &mut self,
        world: &(impl WorldReadOnly + ?Sized),
        index: u64,
        size: u64,
        cache_budget: &AllocationBudget,
        request_budget: &AllocationBudget,
    ) -> Result<RetainedSccpHistoryPath, SccpHistoryReadError> {
        let source = WorldHistory(world);
        let draft = self.draft(&source, index, size, cache_budget)?;
        let (mut request, mut cache) = reserve_operation(
            request_budget,
            draft.request_demand()?,
            cache_budget,
            draft.cache_demand()?,
        )?;
        draft.materialize(&mut request, &mut cache)
    }

    pub(crate) fn draft<'a>(
        &'a mut self,
        source: &'a dyn BorrowedHistorySource,
        index: u64,
        size: u64,
        budget: &AllocationBudget,
    ) -> Result<HistoryDraft<'a>, SccpHistoryReadError> {
        if size > source.size() {
            return Err(SccpHistoryReadError::SizeOutOfRange);
        }
        if index >= size {
            return Err(SccpHistoryReadError::IndexOutOfRange);
        }
        if source.size() > MAX_HISTORY_SIZE {
            return Err(SccpHistoryReadError::Inconsistent);
        }
        HistoryAccumulatorV1::root_from_parts(source.size(), source.peaks())
            .map_err(|_| SccpHistoryReadError::Inconsistent)?;
        if self
            .nodes
            .as_ref()
            .is_some_and(|nodes| !nodes.belongs_to(budget))
        {
            return Err(SccpHistoryReadError::ForeignPool);
        }
        let needed = node_count(source.size() / CHUNK)?;
        let capacity = self.nodes.as_ref().map_or(0, ChargedBuffer::capacity);
        let new_capacity = if needed > capacity {
            Some(
                needed
                    .checked_next_power_of_two()
                    .ok_or(AllocationRefusal::DemandOverflow)?,
            )
        } else {
            None
        };
        Ok(HistoryDraft {
            cache: self,
            source,
            index,
            size,
            new_capacity,
            path_len: path_len(index, size),
        })
    }

    fn reset(&mut self) {
        self.covered = 0;
        if let Some(nodes) = &mut self.nodes {
            nodes.truncate(0);
        }
    }
    fn cached(&self, level: u32, position: u64) -> Result<Hash, SccpHistoryReadError> {
        let index =
            node_index(level - MIN_LEVEL, position).ok_or(SccpHistoryReadError::Inconsistent)?;
        self.nodes
            .as_ref()
            .and_then(|nodes| nodes.as_slice().get(index))
            .copied()
            .ok_or(SccpHistoryReadError::Inconsistent)
    }
    fn small_root(
        source: &dyn BorrowedHistorySource,
        start: u64,
        end: u64,
        scratch: &mut ChargedBuffer<Hash>,
    ) -> Result<Hash, SccpHistoryReadError> {
        let count = usize::try_from(
            end.checked_sub(start)
                .ok_or(SccpHistoryReadError::Inconsistent)?,
        )
        .map_err(|_| SccpHistoryReadError::Inconsistent)?;
        if count == 0 || count > CHUNK_LEN {
            return Err(SccpHistoryReadError::Inconsistent);
        }
        scratch.truncate(0);
        for index in start..end {
            scratch.push_reserved(
                source
                    .leaf(index)
                    .ok_or(SccpHistoryReadError::Inconsistent)?,
            );
        }
        let mut count = count;
        while count > 1 {
            let cells = scratch.as_mut_slice();
            for parent in 0..count.div_ceil(2) {
                let child = parent * 2;
                cells[parent] = if child + 1 < count {
                    node(&cells[child], &cells[child + 1])
                } else {
                    cells[child]
                };
            }
            count = count.div_ceil(2);
        }
        Ok(scratch.as_slice()[0])
    }
    fn extend(
        &mut self,
        source: &dyn BorrowedHistorySource,
        scratch: &mut ChargedBuffer<Hash>,
    ) -> Result<(), SccpHistoryReadError> {
        while self.covered + CHUNK <= source.size() {
            let chunk = self.covered / CHUNK;
            let mut carry = Self::small_root(source, self.covered, self.covered + CHUNK, scratch)?;
            let mut level = 0;
            self.nodes
                .as_mut()
                .ok_or(SccpHistoryReadError::Inconsistent)?
                .push_reserved(carry);
            while (chunk >> level) & 1 == 1 {
                let left = self.cached(MIN_LEVEL + level, (chunk >> level) - 1)?;
                carry = node(&left, &carry);
                self.nodes
                    .as_mut()
                    .ok_or(SccpHistoryReadError::Inconsistent)?
                    .push_reserved(carry);
                level += 1;
            }
            self.covered += CHUNK;
        }
        Ok(())
    }
    fn perfect(
        &self,
        source: &dyn BorrowedHistorySource,
        level: u32,
        position: u64,
        scratch: &mut ChargedBuffer<Hash>,
    ) -> Result<Hash, SccpHistoryReadError> {
        if level >= MIN_LEVEL {
            return self.cached(level, position);
        }
        let start = position << level;
        Self::small_root(source, start, start + (1 << level), scratch)
    }
    fn range_root(
        &self,
        source: &dyn BorrowedHistorySource,
        start: u64,
        end: u64,
        scratch: &mut ChargedBuffer<Hash>,
    ) -> Result<Hash, SccpHistoryReadError> {
        let length = end
            .checked_sub(start)
            .ok_or(SccpHistoryReadError::Inconsistent)?;
        let mut peaks = [[0; 32]; 33];
        let mut used = 0;
        let mut offset = start;
        for level in (0..=32).rev() {
            if (length >> level) & 1 != 0 {
                peaks[used] = self.perfect(source, level, offset >> level, scratch)?;
                offset += 1 << level;
                used += 1;
            }
        }
        let (last, prefix) = peaks[..used]
            .split_last()
            .ok_or(SccpHistoryReadError::Inconsistent)?;
        Ok(prefix
            .iter()
            .rev()
            .fold(*last, |right, left| node(left, &right)))
    }
    fn matches_peaks(
        &self,
        source: &dyn BorrowedHistorySource,
        scratch: &mut ChargedBuffer<Hash>,
    ) -> Result<bool, SccpHistoryReadError> {
        let mut offset = 0;
        let mut index = 0;
        for level in (0..=32).rev() {
            if (source.size() >> level) & 1 != 0 {
                if source.peaks().get(index)
                    != Some(&self.perfect(source, level, offset >> level, scratch)?)
                {
                    return Ok(false);
                }
                offset += 1 << level;
                index += 1;
            }
        }
        Ok(true)
    }
}

/// Reserve both real owners before constructing any request or cache graph. When both
/// identities are the same, a single acquisition avoids a cleanup-generated self-wake.
pub(crate) fn reserve_operation(
    request: &AllocationBudget,
    request_bytes: usize,
    cache: &AllocationBudget,
    cache_bytes: usize,
) -> Result<(AllocationReservation, AllocationReservation), AllocationRefusal> {
    if request.same_pool(cache) {
        let demand = request_bytes
            .checked_add(cache_bytes)
            .ok_or(AllocationRefusal::DemandOverflow)?;
        let mut all = request.try_reserve_bytes(demand)?;
        let cache = all
            .try_partition_bytes(cache_bytes)
            .map_err(|_| AllocationRefusal::DemandOverflow)?;
        Ok((all, cache))
    } else {
        let request = request.try_reserve_bytes(request_bytes)?;
        // A failure here releases only the different request pool; it cannot notify the
        // captured original cache-pool capacity observation.
        let cache = cache.try_reserve_bytes(cache_bytes)?;
        Ok((request, cache))
    }
}

struct Mutation<'a> {
    cache: &'a mut SccpHistoryNodeCache,
    complete: bool,
}
impl Drop for Mutation<'_> {
    fn drop(&mut self) {
        // A partial appended prefix cannot be read after a source panic. Keep its backing
        // and charge together, resetting only initialization/metadata until a valid rebuild.
        if !self.complete {
            self.cache.reset();
        }
    }
}

impl HistoryDraft<'_> {
    pub(crate) fn cache_demand(&self) -> Result<usize, AllocationRefusal> {
        array_bytes(self.new_capacity.unwrap_or(0))
    }
    pub(crate) fn request_demand(&self) -> Result<usize, AllocationRefusal> {
        array_bytes(CHUNK_LEN)?
            .checked_add(array_bytes(self.path_len)?)
            .ok_or(AllocationRefusal::DemandOverflow)
    }
    pub(crate) fn materialize(
        self,
        reservation: &mut AllocationReservation,
        cache_reservation: &mut AllocationReservation,
    ) -> Result<RetainedSccpHistoryPath, SccpHistoryReadError> {
        self.materialize_checked(reservation, cache_reservation, None)
    }
    pub(crate) fn materialize_checked(
        self,
        reservation: &mut AllocationReservation,
        cache_reservation: &mut AllocationReservation,
        expected: Option<(Hash, Hash)>,
    ) -> Result<RetainedSccpHistoryPath, SccpHistoryReadError> {
        // All actual allocations precede cache mutation; a physical failure preserves it.
        let mut scratch = ChargedBuffer::from_reservation(CHUNK_LEN, reservation)?;
        let mut path = ChargedBuffer::from_reservation(self.path_len, reservation)?;
        let replacement = if let Some(capacity) = self.new_capacity {
            let mut nodes = ChargedBuffer::from_reservation(capacity, cache_reservation)?;
            if let Some(old) = &self.cache.nodes {
                for node in old.as_slice() {
                    nodes.push_reserved(*node);
                }
            }
            Some(nodes)
        } else {
            None
        };
        let mut mutation = Mutation {
            cache: self.cache,
            complete: false,
        };
        if let Some(nodes) = replacement {
            mutation.cache.nodes = Some(nodes);
        }
        let result = (|| {
            mutation.cache.extend(self.source, &mut scratch)?;
            if !mutation.cache.matches_peaks(self.source, &mut scratch)? {
                mutation.cache.reset();
                mutation.cache.extend(self.source, &mut scratch)?;
                if !mutation.cache.matches_peaks(self.source, &mut scratch)? {
                    return Err(SccpHistoryReadError::Inconsistent);
                }
            }
            let root = mutation
                .cache
                .range_root(self.source, 0, self.size, &mut scratch)?;
            let (mut level, mut position, mut count) = (0, self.index, self.size);
            while count > 1 {
                if position % 2 == 1 {
                    path.push_reserved(mutation.cache.perfect(
                        self.source,
                        level,
                        position - 1,
                        &mut scratch,
                    )?);
                } else if position + 1 < count {
                    let start = (position + 1) << level;
                    let end = ((position + 2) << level).min(self.size);
                    path.push_reserved(mutation.cache.range_root(
                        self.source,
                        start,
                        end,
                        &mut scratch,
                    )?);
                }
                position >>= 1;
                count = count.div_ceil(2);
                level += 1;
            }
            // Peaks can authenticate cached perfect subtrees while a currently selected
            // source leaf disagrees with that cached subtree. Verify the selected original
            // leaf as well before any caller can publish a logically complete cache.
            let selected_leaf = self
                .source
                .leaf(self.index)
                .ok_or(SccpHistoryReadError::Inconsistent)?;
            iroha_sccp::v1::history::verify_history_inclusion(
                &selected_leaf,
                self.index,
                self.size,
                path.as_slice(),
                &root,
            )
            .map_err(|_| SccpHistoryReadError::Inconsistent)?;
            if let Some((expected_root, expected_leaf)) = expected {
                if root != expected_root {
                    return Err(SccpHistoryReadError::Inconsistent);
                }
                iroha_sccp::v1::history::verify_history_inclusion(
                    &expected_leaf,
                    self.index,
                    self.size,
                    path.as_slice(),
                    &expected_root,
                )
                .map_err(|_| SccpHistoryReadError::Inconsistent)?;
            }
            Ok(RetainedSccpHistoryPath { root, path })
        })();
        mutation.complete = result.is_ok();
        result
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod original_tests;
