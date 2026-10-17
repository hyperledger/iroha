//! Bounded node-local resume points for finite finality proof production.
//!
//! A finite proof walk authenticates its complete prefix from signed genesis. Readers that
//! page through history, such as a verifier extending its own checkpoint one page at a
//! time, would otherwise replay that prefix for every request, so one proof would cost
//! time linear in its height and a paged scan quadratic time. This store retains the
//! constant-size outcome of completed producer walks so a later walk continues from the
//! nearest earlier height instead of from genesis.
//!
//! A checkpoint holds only values a completed native walk established at its height: the
//! pinned block hash and certificate-inclusive canonical wire identity of that frame, the
//! native schedule and active authority after it, and the local source fence through the
//! frame and through its parent. A resume re-reads that exact frame from the caller's
//! pinned hash cut and requires the same hash and wire identity; the hash chain then pins
//! every earlier height, so the retained schedule and authority equal a fresh replay. Every
//! later height is verified natively as before, and the post-verification source join
//! starts at the resumed frame.
//!
//! Checkpoints are process-local memory. They are never persisted, serialized, accepted
//! from a peer or consulted by consensus execution, and they own no block bodies or
//! request-pool charges.

use std::collections::BTreeMap;

use iroha_data_model::sumeragi_finality::ScheduledSlot;

use super::*;

/// Retained producer walks per node. A schedule clone holds at most three epochs of
/// `MAX_VALIDATORS` members, so the full ladder stays within a few megabytes.
const MAX_CHECKPOINTS: usize = 256;

/// One completed producer prefix that a later proof walk may resume from.
pub(crate) struct PrefixCheckpoint {
    height: u64,
    block_hash: HashOf<IrohaHeader>,
    wire: (u64, Hash),
    schedule: schedule::ConsensusSchedule,
    authority: Arc<VerifiedAuthority>,
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

    /// The source join's starting height and fence, immediately before the retained frame.
    pub(crate) fn join_start(&self) -> (u64, Hash) {
        (self.height - 1, self.parent_source)
    }
}

/// Bounded ladder of completed producer prefixes for one node State.
#[derive(Default)]
pub(crate) struct FinalityPrefixCheckpoints {
    entries: parking_lot::Mutex<BTreeMap<u64, Arc<PrefixCheckpoint>>>,
}

impl FinalityPrefixCheckpoints {
    /// An empty ladder; the first walk of each region starts at signed genesis.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The nearest retained prefix strictly below `height`.
    pub(crate) fn resume_point(&self, height: u64) -> Option<Arc<PrefixCheckpoint>> {
        self.entries
            .lock()
            .range(..height)
            .next_back()
            .map(|(_, checkpoint)| Arc::clone(checkpoint))
    }

    /// Drop the point at `height` and every later point after its frame stopped matching.
    pub(crate) fn forget_from(&self, height: u64) {
        drop(self.entries.lock().split_off(&height));
    }

    /// Retain a completed producer prefix, thinning the ladder beyond its bound.
    pub(crate) fn retain(&self, checkpoint: PrefixCheckpoint) {
        let mut entries = self.entries.lock();
        entries.insert(checkpoint.height, Arc::new(checkpoint));
        while entries.len() > MAX_CHECKPOINTS {
            evict_densest(&mut entries);
        }
    }

    #[cfg(test)]
    pub(crate) fn heights(&self) -> Vec<u64> {
        self.entries.lock().keys().copied().collect()
    }
}

/// Remove the older point whose neighbours are closest together. The newest point always
/// survives, and older random reads keep an evenly spread ladder.
fn evict_densest<T>(entries: &mut BTreeMap<u64, T>) {
    let heights = entries.keys().copied().collect::<Vec<_>>();
    let mut densest: Option<(u64, u64)> = None;
    for index in 0..heights.len().saturating_sub(1) {
        let previous = index.checked_sub(1).map_or(0, |previous| heights[previous]);
        let span = heights[index + 1] - previous;
        if densest.is_none_or(|(smallest, _)| span < smallest) {
            densest = Some((span, heights[index]));
        }
    }
    if let Some((_, height)) = densest {
        entries.remove(&height);
    }
}

/// Count a retained schedule clone against the active decode stage, as a fresh walk would.
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
    /// Install `checkpoint` as this producer's cursor before its first target.
    ///
    /// Returns `false`, leaving the cursor empty, when the checkpoint belongs to another
    /// source or its frame no longer has the retained pinned hash and wire identity.
    pub(crate) fn resume_proof_prefix(
        &self,
        checkpoint: &PrefixCheckpoint,
    ) -> Result<bool, ExecutionAttemptError<ChainReadError>> {
        if self.proof_source_genesis.is_none()
            || self.terminal.is_some()
            || checkpoint.height <= GENESIS_HEIGHT
            || checkpoint.instance != self.instance
            || checkpoint.root_scope != self.root_scope
        {
            return Ok(false);
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
        admit_schedule_clone(&checkpoint.schedule, checkpoint.height)?;
        *cursor = Some(VerifiedPrefix {
            tip,
            schedule: checkpoint.schedule.clone(),
            authority: Arc::clone(&checkpoint.authority),
            validation,
            proof_source: Some(checkpoint.proof_source),
        });
        Ok(true)
    }

    /// Export the completed producer cursor as a resume point.
    ///
    /// `parent_source` is the post-verification source join's fence through the cursor
    /// tip's parent; it must extend to exactly the cursor's own fence.
    pub(crate) fn proof_prefix_checkpoint(&self, parent_source: Hash) -> Option<PrefixCheckpoint> {
        if self.proof_source_genesis.is_none() || self.terminal.is_some() {
            return None;
        }
        let cursor = self.prefix.lock();
        let prefix = cursor.as_ref()?;
        let height = prefix.tip.height;
        let proof_source = prefix.proof_source?;
        let wire = prefix.tip.block().canonical_wire_identity().ok()?;
        if height <= GENESIS_HEIGHT
            || proof_source_append(parent_source, height, wire.0, wire.1) != proof_source
        {
            return None;
        }
        Some(PrefixCheckpoint {
            height,
            block_hash: prefix.tip.block_hash(),
            wire,
            schedule: prefix.schedule.clone(),
            authority: Arc::clone(&prefix.authority),
            proof_source,
            parent_source,
            instance: self.instance,
            root_scope: self.root_scope,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ladder(heights: impl IntoIterator<Item = u64>) -> BTreeMap<u64, u64> {
        let mut entries = BTreeMap::new();
        for height in heights {
            entries.insert(height, height);
            while entries.len() > MAX_CHECKPOINTS {
                evict_densest(&mut entries);
            }
        }
        entries
    }

    #[test]
    fn eviction_keeps_newest_point_and_an_even_bounded_ladder() {
        for walked in [300_u64, 1_000, 10_000] {
            let entries = ladder(1..=walked);
            let heights = entries.keys().copied().collect::<Vec<_>>();
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
        let mut one = BTreeMap::from([(7_u64, 7_u64)]);
        evict_densest(&mut one);
        assert_eq!(one.keys().copied().collect::<Vec<_>>(), [7]);
        let mut two = BTreeMap::from([(3_u64, 3_u64), (9, 9)]);
        evict_densest(&mut two);
        assert_eq!(two.keys().copied().collect::<Vec<_>>(), [9]);
    }
}
