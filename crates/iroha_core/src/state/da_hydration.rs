//! Atomic reconstruction and publication of the State DA query projections.

use super::*;

/// Original replacement-rewind notifications retained by the executing owner.
/// Physical hydration guards remain short; their notices outlive every MV writer.
pub(super) struct DaRewindReleases<'state> {
    indexes: LaneLifecycleReleases<'state>,
    write_fence: crate::publication_lock::DeferredPublicationFence<'state, ()>,
    refunds: iroha_allocation::AllocationRefundBatch,
}

impl<'state> DaRewindReleases<'state> {
    pub(super) fn new(state: &'state State) -> Self {
        Self {
            indexes: LaneLifecycleReleases::new(state),
            write_fence: state.state_write_lock.defer_notifications(),
            refunds: state.ivm_execution_budget().deferred_refund_batch(),
        }
    }
}

/// Retain the original cold-read refunds through the caller's physical writers.
fn with_da_rebuild_refunds<R>(
    refunds: &mut iroha_allocation::AllocationRefundBatch,
    operation: impl FnOnce() -> R,
) -> R {
    #[cfg(all(test, sumeragi_core_mutation = "HC75"))]
    {
        let _ = refunds;
        operation()
    }
    #[cfg(not(all(test, sumeragi_core_mutation = "HC75")))]
    refunds.with_scope(|_| operation())
}

/// Errors surfaced while rebuilding DA indexes from the committed block log.
#[derive(Debug, ThisError)]
pub enum DaIndexHydrationError {
    /// Original local capacity refusal; retry without publishing or caching an invalid verdict.
    #[error("DA history acquisition deferred: {0}")]
    Deferred(crate::execution_attempt::ExecutionDeferred),
    /// Completed canonical reconstruction failure, safe to retain as a verdict.
    #[error(transparent)]
    Completed(#[from] DaIndexHydrationFailure),
}

/// A completed DA reconstruction verdict, excluding every local execution refusal.
///
/// The hydration marker retains only this type. Cloning a stored verdict cannot
/// clone or reconstruct an unfinished decoder, allocator, or native verifier owner.
#[derive(Debug, Clone, PartialEq, Eq, ThisError)]
pub enum DaIndexHydrationFailure {
    /// A completed canonical storage read failed independently of local allocation capacity.
    #[error("DA block storage at height {height} is invalid: {reason}")]
    Storage {
        /// Exact original slot whose read failed.
        height: NonZeroU64,
        /// Completed storage diagnostic, never a formatted local capacity refusal.
        reason: String,
    },
    /// A committed WSV hash has no corresponding non-hash-only Kura body.
    #[error("committed DA block body at height {height} is missing from Kura")]
    MissingBlock {
        /// One-based committed block height.
        height: NonZeroU64,
    },
    /// A Kura body does not authenticate against the fixed committed WSV hash.
    #[error(
        "DA block body at height {height} does not match committed WSV hash: expected {expected:?}, found {actual:?}"
    )]
    BlockHashMismatch {
        /// One-based committed block height.
        height: NonZeroU64,
        /// Header hash committed in the WSV prefix.
        expected: HashOf<BlockHeader>,
        /// Header hash decoded from the Kura body.
        actual: HashOf<BlockHeader>,
    },
    /// A Kura body's signed header does not declare its committed WSV slot height.
    #[error("DA block body at WSV height {expected} declares header height {actual}")]
    BlockHeightMismatch {
        /// One-based committed WSV slot height.
        expected: NonZeroU64,
        /// Height declared by the signed Kura block header.
        actual: NonZeroU64,
    },
    /// DA shard cursor replay failed.
    #[error("DA shard cursor hydration failed: {0}")]
    ShardCursor(#[from] DaShardCursorError),
    /// DA receipt cursor replay failed.
    #[error("DA receipt cursor hydration failed: {0}")]
    ReceiptCursor(#[from] DaReceiptCursorError),
    /// Confidential-compute receipt replay failed.
    #[error("DA confidential-compute hydration failed: {0}")]
    ConfidentialCompute(#[from] ConfidentialComputeError),
}

/// Retain only completed observations; unfinished attempts always move to their caller.
fn completed_hydration_verdict(
    result: &Result<(), DaIndexHydrationError>,
) -> Option<Result<(), DaIndexHydrationFailure>> {
    match result {
        Ok(()) => Some(Ok(())),
        Err(DaIndexHydrationError::Completed(failure)) => Some(Err(failure.clone())),
        Err(DaIndexHydrationError::Deferred(_)) => None,
    }
}

/// Complete DA query projection built locally from one committed WSV hash prefix.
struct HydratedDaIndexes {
    commitments: DaCommitmentStore,
    confidential_compute: ConfidentialComputeStore,
    receipt_cursors: DaReceiptCursorIndex,
    shard_cursors: DaShardCursorIndex,
    pin_intents: DaPinStore,
}

impl HydratedDaIndexes {
    fn new(
        lane_config: &iroha_config::parameters::actual::LaneConfig,
        canonical_reset_heights: &BTreeMap<LaneId, u64>,
    ) -> Self {
        let mut shard_cursors = DaShardCursorIndex::new(lane_config);
        shard_cursors.merge_canonical_reset_heights(canonical_reset_heights);
        Self {
            commitments: DaCommitmentStore::default(),
            confidential_compute: ConfidentialComputeStore::default(),
            receipt_cursors: DaReceiptCursorIndex::default(),
            shard_cursors,
            pin_intents: DaPinStore::default(),
        }
    }
}

impl State {
    /// Publish one successfully rebuilt DA projection while every component is write-locked.
    fn publish_hydrated_da_indexes(
        &self,
        hydrated: HydratedDaIndexes,
        releases: &mut LaneLifecycleReleases<'_>,
    ) {
        let HydratedDaIndexes {
            commitments,
            confidential_compute,
            receipt_cursors,
            shard_cursors,
            pin_intents,
        } = hydrated;
        // Keep this acquisition order aligned with snapshot/test readers that hold more than
        // one DA guard. No published field changes until all five write guards are owned.
        let mut published_commitments = releases.commitments.write();
        let mut published_confidential_compute = releases.confidential_compute.write();
        let mut published_receipt_cursors = releases.receipt_cursors.write();
        let mut published_shard_cursors = releases.shard_cursors.write();
        let mut published_pin_intents = releases.pin_intents.write();
        *published_commitments = commitments;
        *published_confidential_compute = confidential_compute;
        *published_receipt_cursors = receipt_cursors;
        *published_shard_cursors = shard_cursors;
        *published_pin_intents = pin_intents;
    }

    fn persist_hydrated_da_shard_cursor_journal(&self, releases: &mut LaneLifecycleReleases<'_>) {
        let path = self.da_shard_cursor_journal_path();
        if path.as_os_str().is_empty() {
            return;
        }
        let lane_config = self
            .canonical_runtime
            .view()
            .nexus_projection(&releases.nexus.read())
            .expect("persisted canonical runtime must be valid")
            .lane_config;
        let snapshot =
            DaShardCursorJournal::from_index(&lane_config, &releases.shard_cursors.read(), &path);
        if let Err(err) = snapshot.persist() {
            warn!(?err, path = %path.display(), "failed to persist DA shard cursor journal");
        }
    }

    pub(crate) fn ensure_da_indexes_hydrated(&self) -> Result<(), DaIndexHydrationError> {
        self.ensure_da_indexes_hydrated_with_journal_publication(true)
    }

    /// Rebuild an isolated replay State's exact committed prefix without publishing
    /// its DA journal to the shared Kura directory. A cached result is preserved;
    /// an absent cache must still authenticate and reconstruct all five indexes.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "TODO: connect isolated replay prevalidation; rebuild exact DA indexes without publishing its journal into the shared live Kura directory"
        )
    )]
    pub(super) fn ensure_da_indexes_hydrated_for_replay_prevalidation(
        &self,
    ) -> Result<(), DaIndexHydrationError> {
        self.ensure_da_indexes_hydrated_with_journal_publication(false)
    }

    fn ensure_da_indexes_hydrated_with_journal_publication(
        &self,
        persist_journal: bool,
    ) -> Result<(), DaIndexHydrationError> {
        {
            let guard = self.da_indexes_hydrated.read();
            if let Some(result) = guard.as_ref() {
                return result.clone().map_err(DaIndexHydrationError::Completed);
            }
        }
        // This owner is declared before all reader notices and physical guards,
        // so cold Kura allocation refunds cannot reenter beneath either fence.
        let mut refunds = self.ivm_execution_budget().deferred_refund_batch();
        let mut releases = LaneLifecycleReleases::new(self);
        let mut write_fence = self.state_write_lock.defer_notifications();
        let _hydration_guard = self.da_index_hydration_fence.lock();
        if let Some(result) = releases.hydrated.read().as_ref() {
            return result.clone().map_err(DaIndexHydrationError::Completed);
        }
        let _state_write_guard = write_fence.lock();
        with_da_rebuild_refunds(&mut refunds, || {
            let result =
                self.build_da_indexes_from_kura(None, &mut releases)
                    .map(|mut hydrated| {
                        hydrated.pin_intents = self.da_pin_cache_from_world(&mut releases.world);
                        self.publish_hydrated_da_indexes(hydrated, &mut releases);
                        if persist_journal {
                            self.persist_hydrated_da_shard_cursor_journal(&mut releases);
                        }
                    });
            if let Err(err) = &result {
                warn!(?err, "failed to hydrate DA indexes from Kura");
            }
            // Cache only completed verdicts; the original unfinished owner moves
            // directly to the caller and cannot inhabit this marker's type.
            *releases.hydrated.write() = completed_hydration_verdict(&result);
            result
        })
    }

    /// Force a rebuild of DA indexes from the Kura block log, truncating at `target_height` when provided.
    #[cfg(test)]
    pub(crate) fn rewind_da_indexes_to_height(
        &self,
        target_height: u64,
    ) -> Result<(), DaIndexHydrationError> {
        let mut releases = DaRewindReleases::new(self);
        self.rewind_da_indexes_to_height_with_releases(target_height, &mut releases)
    }

    /// Use the caller's exact notification owner while replacement MV writers remain held.
    pub(super) fn rewind_da_indexes_to_height_with_releases(
        &self,
        target_height: u64,
        releases: &mut DaRewindReleases<'_>,
    ) -> Result<(), DaIndexHydrationError> {
        let DaRewindReleases {
            indexes: releases,
            write_fence,
            refunds,
        } = releases;
        let _hydration_guard = self.da_index_hydration_fence.lock();
        // Make concurrent accessors join this fenced rebuild instead of observing the
        // previous cached success while the committed projection is being rewound.
        *releases.hydrated.write() = None;
        let _state_write_guard = write_fence.lock();
        with_da_rebuild_refunds(refunds, || {
            let result = self
                .build_da_indexes_from_kura(Some(target_height), releases)
                .map(|hydrated| {
                    self.publish_hydrated_da_indexes(hydrated, releases);
                    self.persist_hydrated_da_shard_cursor_journal(releases);
                });
            if let Err(err) = &result {
                warn!(?err, target_height, "failed to rewind DA indexes from Kura");
            }
            // Cache only completed verdicts; the original unfinished owner moves
            // directly to the caller and cannot inhabit this marker's type.
            *releases.hydrated.write() = completed_hydration_verdict(&result);
            result
        })
    }

    #[allow(clippy::too_many_lines)]
    fn build_da_indexes_from_kura(
        &self,
        target_height: Option<u64>,
        releases: &mut LaneLifecycleReleases<'_>,
    ) -> Result<HydratedDaIndexes, DaIndexHydrationError> {
        // The caller holds the original State writer, so this complete catalog
        // projection is stable. Its reader notice belongs to the enclosing
        // rebuild and must not call a waiter beneath that writer.
        let catalog = runtime_catalog_from_parameters(self.world.parameters.view().get())
            .expect("persisted canonical runtime catalog must be valid");
        let nexus = self
            .canonical_runtime
            .view()
            .nexus_projection_with_catalog(&releases.nexus.read(), catalog.as_ref())
            .expect("persisted canonical runtime and catalog must be valid");
        let execution_budget = self.ivm_execution_budget();
        let lane_config = &nexus.lane_config;
        let incarnation_resets = self
            .lane_incarnation_activation_heights_snapshot()
            .into_iter()
            .filter(|(_, activation_height)| *activation_height > 0)
            .collect::<BTreeMap<_, _>>();
        let mut hydrated = HydratedDaIndexes::new(lane_config, &incarnation_resets);
        let journal_path = self.da_shard_cursor_journal_path();
        let persisted_journal = if journal_path.as_os_str().is_empty() {
            None
        } else {
            match DaShardCursorJournal::load(lane_config, &journal_path) {
                Ok(journal) => Some(journal),
                Err(err) => {
                    warn!(
                        ?err,
                        path = %journal_path.display(),
                        "failed to load persisted DA shard cursor journal; continuing with ledger replay"
                    );
                    None
                }
            }
        };
        // Clone the hash list up front so we do not hold the block-hash lock while
        // loading blocks from Kura (avoids lock-order inversions with Kura writers).
        let mut committed_hash_prefix: Vec<HashOf<BlockHeader>> = self
            .block_hashes
            .view_retaining(&mut releases.hashes)
            .iter()
            .copied()
            .collect();
        let replay_len = target_height
            .map(|limit| usize::try_from(limit).unwrap_or(usize::MAX))
            .map_or(committed_hash_prefix.len(), |limit| {
                committed_hash_prefix.len().min(limit)
            });
        committed_hash_prefix.truncate(replay_len);
        let replay_height = u64::try_from(replay_len).unwrap_or(u64::MAX);
        if let Some(journal) = persisted_journal.as_ref() {
            hydrated.shard_cursors.merge_canonical_reset_heights(
                &Self::journal_reset_heights_at_or_below(journal, replay_height),
            );
        }
        if replay_len == 0 {
            if let Some(journal) = persisted_journal.as_ref() {
                self.restore_da_cursors_from_journal(
                    &mut hydrated.shard_cursors,
                    lane_config,
                    journal,
                    0,
                )
                .map_err(DaIndexHydrationFailure::ShardCursor)?;
            }
            return Ok(hydrated);
        }
        let mut saw_da_commitments = false;
        for (idx, expected_hash) in committed_hash_prefix.iter().enumerate() {
            let height = idx + 1;
            let height_u64 = u64::try_from(height).expect("committed block height must fit u64");
            let height_u64 = NonZeroU64::new(height_u64).expect("block height is non-zero");
            let height_usize = NonZeroUsize::new(height).expect("block height is non-zero");
            let Some(block) = self
                .kura
                .get_block(height_usize, &execution_budget)
                .map_err(|error| match error {
                    crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                        DaIndexHydrationError::Deferred(reason)
                    }
                    crate::execution_attempt::ExecutionAttemptError::Rejected(error) => {
                        DaIndexHydrationFailure::Storage {
                            height: height_u64,
                            reason: error.to_string(),
                        }
                        .into()
                    }
                })?
            else {
                return Err(DaIndexHydrationFailure::MissingBlock { height: height_u64 }.into());
            };
            let block_hash = block.hash();
            if block_hash != *expected_hash {
                return Err(DaIndexHydrationFailure::BlockHashMismatch {
                    height: height_u64,
                    expected: *expected_hash,
                    actual: block_hash,
                }
                .into());
            }
            if block.header().height() != height_u64 {
                return Err(DaIndexHydrationFailure::BlockHeightMismatch {
                    expected: height_u64,
                    actual: block.header().height(),
                }
                .into());
            }
            if let Some(bundle) = block.as_ref().da_commitments() {
                saw_da_commitments = true;
                let policy_context = crate::da::ActiveLaneProofPolicyContext::new(&nexus);
                let active_commitments = bundle
                    .commitments()
                    .iter()
                    .filter_map(|record| {
                        let validation = policy_context
                            .enforce_commitment_at_height(record, height_u64.get())
                            .map_err(crate::da::DaCommitmentValidationError::from)
                            .and_then(|()| {
                                crate::da::validate_confidential_compute_record(
                                    lane_config,
                                    record,
                                )
                                .map(|_| ())
                                .map_err(crate::da::DaCommitmentValidationError::from)
                            });
                        match validation {
                            Ok(())
                                if hydrated
                                    .shard_cursors
                                    .canonical_reset_height_for_lane(record.lane_id)
                                    .is_none_or(|reset_height| {
                                        height_u64.get() > reset_height
                                    }) =>
                            {
                                Some(record.clone())
                            }
                            Ok(()) => {
                                warn!(
                                    height,
                                    lane = %record.lane_id.as_u32(),
                                    epoch = record.epoch,
                                    sequence = record.sequence,
                                    "skipping DA commitment index materialization for an earlier lane incarnation"
                                );
                                None
                            }
                            Err(err) => {
                                warn!(
                                    ?err,
                                    height,
                                    lane = %record.lane_id.as_u32(),
                                    epoch = record.epoch,
                                    sequence = record.sequence,
                                    "skipping DA commitment index materialization for inactive lane after lifecycle update"
                                );
                                None
                            }
                        }
                    })
                    .collect::<Vec<_>>();
                let query_visible_keys: BTreeSet<_> = active_commitments
                    .iter()
                    .map(DaCommitmentKey::from_record)
                    .collect();
                let identity_visible_keys: BTreeSet<_> = bundle
                    .commitments()
                    .iter()
                    .filter(|record| {
                        let key = DaCommitmentKey::from_record(record);
                        hydrated
                            .shard_cursors
                            .canonical_reset_height_for_lane(record.lane_id)
                            .is_none_or(|reset_height| height_u64.get() > reset_height)
                            && (query_visible_keys.contains(&key)
                                || nexus
                                    .lane_catalog
                                    .lanes()
                                    .iter()
                                    .all(|lane| lane.id != record.lane_id))
                    })
                    .map(DaCommitmentKey::from_record)
                    .collect();
                hydrated.commitments.insert_bundle_with_visibility_filter(
                    height_u64.get(),
                    bundle.clone(),
                    |record| identity_visible_keys.contains(&DaCommitmentKey::from_record(record)),
                    |record| query_visible_keys.contains(&DaCommitmentKey::from_record(record)),
                );
                if let Err(err) = self.advance_da_shard_cursors_into(
                    &mut hydrated.shard_cursors,
                    lane_config,
                    height_u64.get(),
                    active_commitments.iter(),
                ) {
                    warn!(
                        ?err,
                        height, "failed to advance shard cursor index while hydrating from Kura"
                    );
                    return Err(DaIndexHydrationFailure::ShardCursor(err).into());
                }
                if let Err(err) = self.advance_da_receipt_cursors_into(
                    &mut hydrated.receipt_cursors,
                    height_u64.get(),
                    active_commitments.iter(),
                ) {
                    warn!(
                        ?err,
                        height, "failed to advance receipt cursor index while hydrating from Kura"
                    );
                    return Err(DaIndexHydrationFailure::ReceiptCursor(err).into());
                }
                if let Err(err) = Self::record_confidential_compute_into(
                    &mut hydrated.confidential_compute,
                    lane_config,
                    height_u64.get(),
                    bundle.commitments(),
                    |record| query_visible_keys.contains(&DaCommitmentKey::from_record(record)),
                ) {
                    warn!(
                        ?err,
                        height, "failed to hydrate confidential-compute receipts from Kura"
                    );
                    return Err(DaIndexHydrationFailure::ConfidentialCompute(err).into());
                }
            }
            if let Some(bundle) = block.as_ref().da_pin_intents() {
                let _ = self.ingest_committed_pin_intents_from_kura_into(
                    &nexus,
                    &mut hydrated.pin_intents,
                    &hydrated.shard_cursors,
                    height_u64.get(),
                    bundle.intents.clone(),
                );
            }
        }
        if let Some(journal) = persisted_journal {
            if !saw_da_commitments || hydrated.shard_cursors.is_empty() {
                self.restore_da_cursors_from_journal(
                    &mut hydrated.shard_cursors,
                    lane_config,
                    &journal,
                    replay_height,
                )
                .map_err(DaIndexHydrationFailure::ShardCursor)?;
            }
            for entry in journal.entries() {
                if replay_height != 0 && entry.last_block_height > replay_height {
                    warn!(
                        lane = %entry.lane_id.as_u32(),
                        shard = %entry.shard_id.as_u32(),
                        cursor_height = entry.last_block_height,
                        replay_height,
                        "persisted DA shard cursor ahead of ledger height; skipping comparison"
                    );
                    continue;
                }
                let shard_id = entry.shard_id.as_u32();
                match hydrated.shard_cursors.get(shard_id, entry.lane_id) {
                    Some(cursor)
                        if (cursor.epoch, cursor.sequence) >= (entry.epoch, entry.sequence) => {}
                    Some(cursor) => {
                        warn!(
                            lane = %entry.lane_id.as_u32(),
                            shard = %shard_id,
                            observed = ?(cursor.epoch, cursor.sequence),
                            persisted = ?(entry.epoch, entry.sequence),
                            "persisted DA shard cursor was ahead of ledger replay; overwriting with ledger state"
                        );
                        #[cfg(feature = "telemetry")]
                        self.telemetry.record_da_shard_cursor_event(
                            "journal_regression",
                            entry.lane_id.as_u32(),
                            shard_id,
                            cursor.last_block_height,
                        );
                    }
                    None => {
                        warn!(
                            lane = %entry.lane_id.as_u32(),
                            shard = %shard_id,
                            persisted_epoch = entry.epoch,
                            persisted_sequence = entry.sequence,
                            "persisted DA shard cursor missing from ledger replay; clearing entry"
                        );
                        #[cfg(feature = "telemetry")]
                        self.telemetry.record_da_shard_cursor_event(
                            "journal_missing",
                            entry.lane_id.as_u32(),
                            shard_id,
                            0,
                        );
                    }
                }
            }
        }
        Ok(hydrated)
    }
}

#[cfg(test)]
#[path = "da_hydration_release_tests.rs"]
mod release_tests;
