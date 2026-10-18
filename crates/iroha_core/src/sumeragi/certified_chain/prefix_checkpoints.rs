//! State-funded resume points for completed native finality proof production.
//!
//! Every use rechecks the original pinned frame hash, canonical wire identity,
//! root scope and instance. The retained schedule and once-constructed native
//! authority carry the original State pool through their last shared reference.
//! Request working-set charges never escape through this cache. Optional cache
//! refusal neither rejects a proof nor changes a payment's execution result.
//!
//! Checkpoints remain process-local: they are never serialized, accepted from a
//! peer, or consulted by consensus execution. Each subsequent height uses the
//! existing native verifier, and the final raw-source join starts at the retained
//! frame's parent. An unchanged pinned hash chain and canonical frame bind every
//! retained schedule and authority to the same completed original prefix.

use iroha_allocation::{AllocationBudget, ChargedBuffer, ChargedShared};
use iroha_data_model::sumeragi_finality::ScheduledSlot;

use super::retained_query_authority::{
    RetainedQueryAuthority, buffer_refusal, invariant, schedule_refusal, shared_refusal,
};
use super::*;

/// Retained completed prefixes; one additional prepaid slot covers insertion before eviction.
const MAX_CHECKPOINTS: usize = 256;

/// One original completed native prefix with independent persistent custody.
pub(crate) struct PrefixCheckpoint {
    height: u64,
    block_hash: HashOf<IrohaHeader>,
    wire: (u64, Hash),
    schedule: schedule::RetainedConsensusSchedule,
    authority: ChargedShared<RetainedQueryAuthority>,
    proof_source: Hash,
    parent_source: Hash,
    instance: Hash32,
    root_scope: SumeragiRootScope,
}
impl PrefixCheckpoint {
    /// Height of the retained frame.
    pub(crate) fn height(&self) -> u64 {
        self.height
    }
    /// Original source fence immediately before this retained frame.
    pub(crate) fn join_start(&self) -> (u64, Hash) {
        (self.height - 1, self.parent_source)
    }
    #[cfg(test)]
    pub(crate) fn shares_authority_with(&self, other: &Self) -> bool {
        ChargedShared::ptr_eq(&self.authority, &other.authority)
    }
    fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.schedule.belongs_to(budget)
            && self.authority.belongs_to(budget)
            && RetainedQueryAuthority::belongs_to(&self.authority, budget)
    }
}

/// Bounded sorted storage; exact fixed capacity and every shared entry are prepaid.
#[derive(Default)]
pub(crate) struct FinalityPrefixCheckpoints {
    entries: parking_lot::Mutex<Option<ChargedBuffer<ChargedShared<PrefixCheckpoint>>>>,
}
impl FinalityPrefixCheckpoints {
    /// Start with no backing or retained authority.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Admit fixed storage from this exact State pool before any insertion.
    pub(crate) fn prepare(&self, budget: &AllocationBudget) -> Result<(), ExecutionDeferred> {
        budget.with_deferred_refund_notifications(|_| {
            let mut entries = self.entries.lock();
            match entries.as_ref() {
                Some(original) if original.belongs_to(budget) => Ok(()),
                Some(_) => Err(invariant()),
                None => {
                    *entries = Some(
                        ChargedBuffer::new(MAX_CHECKPOINTS + 1, budget).map_err(buffer_refusal)?,
                    );
                    Ok(())
                }
            }
        })
    }
    /// Borrow the nearest original point strictly below the requested height.
    pub(crate) fn resume_point(
        &self,
        height: u64,
        budget: &AllocationBudget,
    ) -> Option<ChargedShared<PrefixCheckpoint>> {
        let entries = self.entries.lock();
        let entries = entries.as_ref()?;
        if !entries.belongs_to(budget) {
            return None;
        }
        let at = entries
            .as_slice()
            .partition_point(|entry| entry.height < height);
        at.checked_sub(1)
            .map(|index| entries.as_slice()[index].clone())
    }
    /// Retire the changed retained frame and every later point.
    pub(crate) fn forget_from(&self, height: u64, budget: &AllocationBudget) {
        budget.with_deferred_refund_notifications(|_| {
            let mut entries = self.entries.lock();
            if let Some(entries) = entries
                .as_mut()
                .filter(|entries| entries.belongs_to(budget))
            {
                let at = entries
                    .as_slice()
                    .partition_point(|entry| entry.height < height);
                entries.truncate(at);
            }
        });
    }
    /// Keep the completed original point, thinning only beyond the unchanged cap.
    pub(crate) fn retain(
        &self,
        checkpoint: ChargedShared<PrefixCheckpoint>,
        budget: &AllocationBudget,
    ) -> Result<(), ExecutionDeferred> {
        if !checkpoint.belongs_to(budget) || !PrefixCheckpoint::belongs_to(&checkpoint, budget) {
            return Err(invariant());
        }
        budget.with_deferred_refund_notifications(|_| {
            let mut entries = self.entries.lock();
            let entries = entries
                .as_mut()
                .filter(|entries| entries.belongs_to(budget))
                .ok_or_else(invariant)?;
            match entries
                .as_slice()
                .binary_search_by_key(&checkpoint.height, |entry| entry.height)
            {
                Ok(index) => {
                    entries.as_mut_slice()[index] = checkpoint;
                }
                Err(index) => {
                    entries.push_reserved(checkpoint);
                    entries.as_mut_slice()[index..].rotate_right(1);
                    if entries.as_slice().len() > MAX_CHECKPOINTS {
                        let index = densest_index(entries.as_slice(), |entry| entry.height)
                            .expect("overflowing ladder has an older entry");
                        entries.as_mut_slice()[index..].rotate_left(1);
                        drop(entries.pop());
                    }
                }
            }
            Ok(())
        })
    }
    #[cfg(test)]
    pub(crate) fn heights(&self) -> Vec<u64> {
        self.entries
            .lock()
            .as_ref()
            .map_or_else(Vec::new, |entries| {
                entries
                    .as_slice()
                    .iter()
                    .map(|entry| entry.height)
                    .collect()
            })
    }
}

// Same earliest tie and newest-preserving policy, without allocating eviction scratch.
fn densest_index<T>(entries: &[T], height: impl Fn(&T) -> u64) -> Option<usize> {
    let mut densest = None;
    for index in 0..entries.len().saturating_sub(1) {
        let previous = index.checked_sub(1).map_or(0, |at| height(&entries[at]));
        let span = height(&entries[index + 1]) - previous;
        if densest.is_none_or(|(smallest, _)| span < smallest) {
            densest = Some((span, index));
        }
    }
    densest.map(|(_, index)| index)
}

fn admit_schedule_clone(
    schedule: &schedule::ConsensusSchedule,
    height: u64,
) -> Result<(), ExecutionAttemptError<ChainReadError>> {
    let slots = schedule.entries();
    norito::core::reserve_decode_allocation(
        slots
            .len()
            .saturating_mul(std::mem::size_of::<ScheduledSlot>()),
    )
    .map_err(|error| read_decode_error(height, error))?;
    for slot in slots {
        if let ScheduledSlot::Ready(config) = slot {
            query_reader::admit_epoch_clone(&config.epoch, height)?;
        }
    }
    Ok(())
}

impl<V: StateReadOnly + ?Sized> CertifiedChain<'_, V> {
    pub(crate) fn configure_query_cache(&self, owner: QueryCacheOwner) {
        *self.query_cache.lock() = Some(owner);
    }
    pub(crate) fn refuse_query_cache(&self, original: ExecutionDeferred) {
        if let Some(owner) = self.query_cache.lock().as_mut() {
            owner.refuse(original);
        }
    }
    pub(crate) fn take_query_cache_refusal(&self) -> Option<ExecutionDeferred> {
        self.query_cache
            .lock()
            .as_mut()
            .and_then(QueryCacheOwner::take_refusal)
    }
    pub(crate) fn resume_proof_prefix(
        &self,
        checkpoint: &ChargedShared<PrefixCheckpoint>,
    ) -> Result<bool, ExecutionAttemptError<ChainReadError>> {
        if self.proof_source_genesis.is_none()
            || self.terminal.is_some()
            || checkpoint.height <= GENESIS_HEIGHT
            || checkpoint.instance != self.instance
            || checkpoint.root_scope != self.root_scope
        {
            return Ok(false);
        }
        {
            let owner = self.query_cache.lock();
            let Some(owner) = owner.as_ref() else {
                return Ok(false);
            };
            if !checkpoint.belongs_to(&owner.budget)
                || !PrefixCheckpoint::belongs_to(checkpoint, &owner.budget)
            {
                return Ok(false);
            }
        }
        let mut cursor = self.prefix.lock();
        if cursor.is_some() {
            return Ok(false);
        }
        let block = self.source.block(checkpoint.height)?;
        if block.hash() != checkpoint.block_hash
            || block.canonical_wire_identity().ok() != Some(checkpoint.wire)
        {
            return Ok(false);
        }
        let mut validation = EpochValidationScope::new();
        let tip =
            read_frame_with_validation(block, checkpoint.height, self.root_scope, &mut validation)?;
        admit_schedule_clone(checkpoint.schedule.canonical(), checkpoint.height)?;
        *cursor = Some(VerifiedPrefix {
            tip,
            schedule: checkpoint.schedule.canonical().clone(),
            authority: PrefixAuthority::Retained(checkpoint.authority.clone()),
            validation,
            proof_source: Some(checkpoint.proof_source),
        });
        Ok(true)
    }
    pub(crate) fn proof_prefix_checkpoint(
        &self,
        parent_source: Hash,
    ) -> Result<Option<ChargedShared<PrefixCheckpoint>>, ExecutionDeferred> {
        if self.proof_source_genesis.is_none() || self.terminal.is_some() {
            return Ok(None);
        }
        let budget = {
            let owner = self.query_cache.lock();
            let Some(owner) = owner.as_ref().filter(|owner| owner.enabled()) else {
                return Ok(None);
            };
            owner.budget.clone()
        };
        let cursor = self.prefix.lock();
        let Some(prefix) = cursor.as_ref() else {
            return Ok(None);
        };
        let height = prefix.tip.height;
        let Some(proof_source) = prefix.proof_source else {
            return Ok(None);
        };
        let Some(wire) = prefix.tip.block().canonical_wire_identity().ok() else {
            return Ok(None);
        };
        if height <= GENESIS_HEIGHT
            || proof_source_append(parent_source, height, wire.0, wire.1) != proof_source
        {
            return Ok(None);
        }
        let Some(authority) = prefix.authority.retained() else {
            return Ok(None);
        };
        if !authority.belongs_to(&budget)
            || !RetainedQueryAuthority::belongs_to(&authority, &budget)
        {
            return Err(invariant());
        }
        let mut shell = budget
            .try_reserve(ChargedShared::<PrefixCheckpoint>::allocation_layout())
            .map_err(ExecutionDeferred::from)?;
        let schedule = schedule::RetainedConsensusSchedule::admit(&prefix.schedule, &budget)
            .map_err(schedule_refusal)?;
        let value = PrefixCheckpoint {
            height,
            block_hash: prefix.tip.block_hash(),
            wire,
            schedule,
            authority,
            proof_source,
            parent_source,
            instance: self.instance,
            root_scope: self.root_scope,
        };
        ChargedShared::from_reservation(value, &mut shell)
            .map(Some)
            .map_err(|(value, error)| {
                drop(value);
                shared_refusal(error)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ladder(heights: impl IntoIterator<Item = u64>) -> Vec<u64> {
        let mut entries = Vec::new();
        for height in heights {
            entries.push(height);
            while entries.len() > MAX_CHECKPOINTS {
                let at = densest_index(&entries, |height| *height).unwrap();
                entries.remove(at);
            }
        }
        entries
    }

    #[test]
    fn eviction_keeps_newest_point_and_an_even_bounded_ladder() {
        for walked in [300_u64, 1_000, 10_000] {
            let entries = ladder(1..=walked);
            let heights = entries.clone();
            assert_eq!(heights.len(), MAX_CHECKPOINTS);
            assert_eq!(
                heights.last(),
                Some(&walked),
                "the newest prefix always survives"
            );
            let widest = heights
                .iter()
                .scan(0, |previous, height| {
                    let gap = height - *previous;
                    *previous = *height;
                    Some(gap)
                })
                .max()
                .unwrap();
            // An even ladder resumes any earlier height within a small multiple of
            // walked / MAX_CHECKPOINTS frames.
            let even = walked.div_ceil(MAX_CHECKPOINTS as u64);
            assert!(widest <= 2 * even, "walked {walked}: widest gap {widest}");
        }
    }

    #[test]
    fn eviction_never_removes_the_only_or_newest_point() {
        let one = [7_u64];
        assert_eq!(densest_index(&one, |height| *height), None);
        let mut two = vec![7_u64, 9];
        let at = densest_index(&two, |height| *height).unwrap();
        two.remove(at);
        assert_eq!(two, [9]);
    }
}
