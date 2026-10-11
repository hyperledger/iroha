//! The sole resumable State publisher retains original effects through local refusal.
//!
//! A deferred attempt keeps the same typed original fields in their immutable frozen
//! phase, with all execution, membership and attempt-local writers released. Retry
//! reacquires their exact original predecessors; no view or execution replaces them.
//! TODO: complete nested EBR/control allocation admission. Geometry remains irreversible.

use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

#[path = "publication/retained_musubi.rs"]
mod retained_musubi;
#[path = "publication/retained_musubi_group.rs"]
mod retained_musubi_group;
#[path = "publication/retained_rows.rs"]
mod retained_rows;
#[cfg(test)]
pub(super) use retained_musubi::RetainedPackageReadError;
#[cfg(test)]
pub(super) use retained_musubi::retained_package_control_layout_for_test;
#[cfg(test)]
pub(super) use retained_musubi_group::RetainedMusubiGroupReadError;
#[cfg(test)]
pub(super) use retained_musubi_group::retained_musubi_group_control_layout_for_test;

/// Local result of attempting publication of the exact retained State.
#[derive(Debug)]
pub(crate) enum StatePublicationOutcome {
    /// Every original State and post-publication effect completed once.
    Published,
    /// Local resource refusal before irreversible progress; this same owner may retry.
    Deferred(TransactionsBlockError),
    /// Invalid authority, stale predecessor, irreversible progress or poisoned attempt.
    RecoveryRequired(TransactionsBlockError),
}

impl StatePublicationOutcome {
    fn into_result(self) -> Result<(), TransactionsBlockError> {
        match self {
            Self::Published => Ok(()),
            Self::Deferred(error) | Self::RecoveryRequired(error) => Err(error),
        }
    }
}

/// All original detached effects and notices live beside, never inside a borrow of,
/// the State fields. No physical guard borrows this struct across an attempt return.
pub(super) struct StatePublication<'state> {
    effect_cleanup: effect_publication::StateEffectLocks<'state>,
    lifecycle_index_releases: LaneLifecycleReleases<'state>,
    publication_notice: StateViewPublication<'state>,
    world_effects: Option<world_commit::PreparedWorldEffects>,
    world_cut: Option<
        iroha_allocation::ChargedShared<
            world_projection::world_state_accumulator::world_state_cut::CutCapsule,
        >,
    >,
    // Actual completed tail survives only its final shell's local refusal.
    // Original generation and predecessor checks still run before every retry.
    world_cut_pending:
        Option<world_projection::world_state_accumulator::world_state_cut::PendingCutCapsule>,
    world_cut_prepared: bool,
    // Pure validation success belongs only to these immutable original fields.
    // Generation and exact predecessor installation still run on every attempt.
    musubi_live_validated: bool,
    // Complete validation includes the later universal pass. Keep the partial
    // live success beside this same original owner if universal admission refuses.
    musubi_validated: bool,
    // All read/index owners retire before the exact original scope in this plan.
    package_read: Option<retained_musubi::RetainedPackageRead>,
    musubi_group_read: Option<retained_musubi_group::RetainedMusubiGroupRead>,
    tiered_snapshot: Option<tiered_publication::PreparedTieredSnapshot>,
    da_effects: Option<carrier_da_effects::PreparedDaCommitmentEffects>,
    lifecycle_effects: Option<carrier_lifecycle_effects::PreparedLaneLifecycleEffects>,
    da_post_publication: Option<carrier_da_effects::DaCommitmentPostPublication>,
    lifecycle_post_publication: Option<carrier_lifecycle_effects::LaneLifecyclePostPublication>,
    commit_fence: crate::publication_lock::DeferredPublicationFence<'state, ()>,
    write_fence: crate::publication_lock::DeferredPublicationFence<'state, ()>,
    lifecycle_fence: crate::publication_lock::DeferredPublicationFence<'state, ()>,
    predecessor_generation: Option<u64>,
    effects_captured: bool,
    fields_frozen: bool,
    irreversible: bool,
    published: bool,
    poisoned: bool,
    refunds: Option<(
        iroha_allocation::AllocationRefundBatch,
        iroha_allocation::AllocationRefundBatch,
        iroha_allocation::AllocationRefundBatch,
    )>,
}

impl<'state> StatePublication<'state> {
    fn new(state: &'state State) -> Self {
        Self {
            effect_cleanup: effect_publication::StateEffectLocks::new(state),
            lifecycle_index_releases: LaneLifecycleReleases::new(state),
            publication_notice: state.state_view_publication(),
            world_effects: None,
            world_cut: None,
            world_cut_pending: None,
            world_cut_prepared: false,
            musubi_live_validated: false,
            musubi_validated: false,
            package_read: None,
            musubi_group_read: None,
            tiered_snapshot: None,
            da_effects: None,
            lifecycle_effects: None,
            da_post_publication: None,
            lifecycle_post_publication: None,
            commit_fence: state.state_commit_lock.defer_notifications(),
            write_fence: state.state_write_lock.defer_notifications(),
            lifecycle_fence: state.lane_lifecycle_lock.defer_notifications(),
            predecessor_generation: None,
            effects_captured: false,
            fields_frozen: false,
            irreversible: false,
            published: false,
            poisoned: false,
            refunds: Some((
                state.ivm_execution_budget().deferred_refund_batch(),
                state.transactions.budget.deferred_refund_batch(),
                state.block_hashes.budget.deferred_refund_batch(),
            )),
        }
    }
}

impl<'state> StateBlock<'state> {
    /// Try the sole publication engine while retaining this original allocation.
    /// Only `Deferred` grants another attempt; callers never mutate a pending owner.
    pub(crate) fn try_publish(&mut self) -> StatePublicationOutcome {
        self.try_publish_inner()
    }

    /// Existing consuming callers explicitly abandon their original on any refusal.
    /// This convenience delegates once to the same engine used by native retry.
    pub(super) fn commit_inner(mut self) -> Result<(), TransactionsBlockError> {
        self.try_publish_inner().into_result()
    }

    fn try_publish_inner(&mut self) -> StatePublicationOutcome {
        let mut original = self
            .publication
            .take()
            .unwrap_or_else(|| StatePublication::new(self.state_ref));
        if original.published {
            self.publication = Some(original);
            return StatePublicationOutcome::Published;
        }
        if original.poisoned {
            self.publication = Some(original);
            return StatePublicationOutcome::RecoveryRequired(
                TransactionsBlockError::PublicationRecoveryRequired,
            );
        }
        // Structural read capture grants no publication authority. The materializer
        // must explicitly retire every read/index before the unchanged engine runs.
        // Invoking publication earlier is a local ordering invariant, never a
        // fabricated writer wait or consensus rejection. Keep the original owner.
        if original
            .package_read
            .as_ref()
            .is_some_and(|plan| !plan.retired)
            || original
                .musubi_group_read
                .as_ref()
                .is_some_and(|plan| !plan.retired)
        {
            self.publication = Some(original);
            return StatePublicationOutcome::Deferred(TransactionsBlockError::ExecutionDeferred(
                ivm::error::ExecutionDeferral::LocalInvariantViolation.into(),
            ));
        }
        // The original phase is restored even on unwind. No detached effect is lost
        // to a call-local destructor, and the actual panic remains a local failure.
        let (mut execution, mut membership, mut hashes) = original
            .refunds
            .take()
            .expect("original pool refund custody");
        let result = catch_unwind(AssertUnwindSafe(|| {
            execution.with_scope(|_| {
                membership.with_scope(|_| {
                    hashes.with_scope(|_| {
                        let result = self.attempt_original_publication(&mut original);
                        if original.fields_frozen && !original.irreversible {
                            // The attempt has returned: every State/effect fence is free.
                            // Recover all original cursors before retiring any notice.
                            self.recover_original_publication_fields();
                            self.retire_original_publication_notices();
                        }
                        result
                    })
                })
            })
        }));
        original.refunds = Some((execution, membership, hashes));
        let result = match result {
            Ok(Ok(())) => StatePublicationOutcome::Published,
            Ok(Err(error)) => {
                let retryable = original.fields_frozen
                    && !original.irreversible
                    && matches!(
                        &error,
                        TransactionsBlockError::ExecutionDeferred(_)
                            | TransactionsBlockError::BlockHashesBusy(_)
                            | TransactionsBlockError::PublicationBusy(_)
                            | TransactionsBlockError::MembershipAdmission(
                                storage_transactions::MembershipAdmissionError::Busy(_)
                            )
                    );
                if retryable {
                    #[cfg(all(test, sumeragi_core_mutation = "HC178"))]
                    {
                        // Restore loss of the successful live prefix on refusal.
                        original.musubi_live_validated = false;
                    }
                    #[cfg(all(test, sumeragi_core_mutation = "HC177"))]
                    {
                        // Restore the discarded successful validation stage.
                        original.musubi_validated = false;
                    }
                    StatePublicationOutcome::Deferred(error)
                } else {
                    original.poisoned = true;
                    StatePublicationOutcome::RecoveryRequired(error)
                }
            }
            Err(payload) => {
                original.poisoned = true;
                self.publication = Some(original);
                mv::BlockRetirement::release_writers(self);
                resume_unwind(payload);
            }
        };
        let terminal = original.poisoned || original.published;
        self.publication = Some(original);
        if terminal {
            mv::BlockRetirement::release_writers(self);
        }
        result
    }

    fn attempt_original_publication(
        &mut self,
        original: &mut StatePublication<'state>,
    ) -> Result<(), TransactionsBlockError> {
        self.require_storage_admission()
            .map_err(TransactionsBlockError::LocalStateStorage)?;
        let StatePublication {
            effect_cleanup,
            lifecycle_index_releases,
            publication_notice,
            world_effects,
            world_cut,
            world_cut_pending,
            world_cut_prepared,
            musubi_live_validated,
            musubi_validated,
            package_read: _,
            musubi_group_read: _,
            tiered_snapshot,
            da_effects,
            lifecycle_effects,
            da_post_publication,
            lifecycle_post_publication,
            commit_fence,
            write_fence,
            lifecycle_fence,
            predecessor_generation,
            effects_captured,
            fields_frozen,
            irreversible,
            published,
            poisoned: _,
            refunds: _,
        } = original;
        let this = self;
        let mut effect_locks = effect_cleanup.physical_scope();
        const STATE_VIEW_LOCK_THRESHOLD: Duration = Duration::from_millis(10);
        if world_effects.is_none() {
            if let Err(error) = this.verify_execution_output_publication() {
                error!(
                    ?error,
                    "execution output publication authorization is invalid"
                );
                return Err(TransactionsBlockError::ExecutionOutputCapacity);
            }
            if let Err(error) = this.validate_direct_home_rows() {
                error!(
                    ?error,
                    "direct asset homes differ from their live definition incarnations"
                );
                return Err(TransactionsBlockError::ExecutionOutputCapacity);
            }
            if let Err(error) = this.validate_owned_runtime_catalog_overlay() {
                error!(
                    ?error,
                    "runtime catalog differs from captured policy or original journals before publication"
                );
                return Err(TransactionsBlockError::AutoscaleLaneLifecycle);
            }
            if let Err(error) = this.verify_sumeragi_lane_state_publication() {
                error!(
                    ?error,
                    "lane consensus metadata does not match its captured state"
                );
                return Err(TransactionsBlockError::LaneConsensusContexts);
            }
            // Extracting the witness does not end the overlay's lifetime. Retain the
            // applied-source seal through publication so a later transaction cannot
            // commit effects omitted from the already-extracted witness. Untouched
            // setup overlays do not acquire a finalized inventory and remain valid.
            if this.fastpq_source_inventory.is_some() {
                let source_check = this
                    .verified_fastpq_source_inventory_for_capture()
                    .and_then(|inventory| this.verify_cached_ordinary_witness_content(&inventory));
                if let Err(error) = source_check {
                    error!(
                        block_height = this._curr_block.height().get(),
                        block = %this._curr_block.hash(),
                        ?error,
                        "finalized FASTPQ source ownership is invalid before state commit"
                    );
                    return Err(TransactionsBlockError::FastpqSourceInventory);
                }
            }
            this.finalize_axt_asset_incarnations()
                .map_err(|_| TransactionsBlockError::AxtAssetIncarnation)?;
            this.finalize_axt_policy_transition_ratchets()
                .map_err(|_| TransactionsBlockError::AxtCounterRatchet)?;
        }
        let block_height = this._curr_block.height().get();
        let block_header_hash = this._curr_block.hash();
        let current_axt_slot =
            current_axt_slot_from_block(&this._curr_block, this.nexus.axt.slot_length_ms);
        let axt_replay_retention_slots = this.nexus.axt.replay_retention_slots.get();
        if world_effects.is_none() {
            this.prune_axt_replay_ledger(current_axt_slot, axt_replay_retention_slots);
        }
        let state_ref = this.state_ref;
        #[cfg(feature = "telemetry")]
        let telemetry_origin = this
            .committed_telemetry_origin()
            .map_err(|_| TransactionsBlockError::WorldCommitPreparation)?;
        // Borrow disjoint fields; the original State keeps its complete inventory
        // armed through every refusal, preparation and publication unwind.
        let world_cut_capture = this.world_cut_capture.as_ref();
        let StateBlockFields {
            local_storage_refusal: _,
            _read_releases: _,
            // Keep the linear finality/output and native-source owners alive
            // through publication of every original journal below.
            execution_output_plan: _publication_owner,
            runtime_policy,
            canonical_runtime,
            native_execution_tip,
            world,
            block_hashes,
            transactions,
            commit_topology: committed_topology,
            prev_commit_topology: prev_committed_topology,
            lane_incarnation_activation_heights,
            zk: _,
            nexus,
            pending_da_commitments,
            pending_da_pin_intents,
            pending_autoscale_lifecycle,
            #[cfg(feature = "telemetry")]
            pending_parliament_telemetry_events,
            pending_public_lane_slash_observability,
            _curr_block,
            #[cfg(feature = "zk-preverify")]
                zk_dedup: _,
            ..
        } = this.fields.as_mut().expect("original executing State");
        #[cfg(feature = "telemetry")]
        let committed_parliament_attempt_counts = world
            .parliament_attempt_counts
            .is_dirty()
            .then(|| *world.parliament_attempt_counts.get());
        #[cfg(feature = "telemetry")]
        let committed_citizens_total = world.citizens.is_dirty().then(|| {
            u64::try_from(world.citizens.len())
                .expect("committed Parliament citizen count must fit into u64")
        });
        let _state_commit_lock = commit_fence.lock();
        let current_generation = state_ref.state_view_generation();
        if current_generation % 2 != 0
            || predecessor_generation.is_some_and(|expected| expected != current_generation)
        {
            return Err(TransactionsBlockError::SnapshotObservationChanged);
        }
        predecessor_generation.get_or_insert(current_generation);
        let mut preflight_state_write_lock_wait = Duration::ZERO;
        let mut preflight_state_write_lock_hold = Duration::ZERO;
        let mut tx_validate_hold = Duration::ZERO;
        if world_effects.is_none() {
            let tx_validate_result;
            (
                preflight_state_write_lock_wait,
                preflight_state_write_lock_hold,
                tx_validate_hold,
                tx_validate_result,
            ) = {
                let state_write_lock_wait_start = Instant::now();
                let _state_write_lock = write_fence.lock();
                let state_write_lock_wait = state_write_lock_wait_start.elapsed();
                let state_write_lock_hold_start = Instant::now();
                let tx_validate_start = Instant::now();
                let tx_validate_result = transactions.try_prepare_publication();
                let tx_validate_hold = tx_validate_start.elapsed();
                (
                    state_write_lock_wait,
                    state_write_lock_hold_start.elapsed(),
                    tx_validate_hold,
                    tx_validate_result,
                )
            };
            // The admitted action is one-shot. Its original writer remains here
            // through the World tail, then joins the complete immutable freeze.
            tx_validate_result?;
        }
        let autoscale_lifecycle_guard = if pending_autoscale_lifecycle.is_some() {
            Some(lifecycle_fence.lock())
        } else {
            None
        };
        if world_effects.is_none() {
            let predecessor_nexus = canonical_runtime
                .get_before_block()
                .nexus_projection(&runtime_policy.nexus)
                .map_err(|_| TransactionsBlockError::AutoscaleLaneLifecycle)?;
            if let Some(pending) = &pending_autoscale_lifecycle {
                let staking_validation_result = {
                    ensure_pending_autoscale_lifecycle_staking_is_safe(
                        world,
                        &predecessor_nexus,
                        pending,
                        block_height,
                    )
                };
                if let Err(err) = staking_validation_result {
                    error!(
                        block_height,
                        block = %block_header_hash,
                        ?err,
                        "final block overlay makes the staged lane lifecycle unsafe"
                    );
                    return Err(TransactionsBlockError::AutoscaleLaneLifecycle);
                }
            }
        }
        if world_effects.is_none() {
            // Complete every remaining World write before geometry or State publication.
            // The move-only owner exposes only reads until consuming the exact overlay.
            if let Some(pending) = &pending_autoscale_lifecycle {
                nexus.lane_catalog = pending.catalog_update.updated_catalog.clone();
                nexus.lane_config = pending.catalog_update.updated_lane_config.clone();
                nexus.dataspace_catalog = pending.catalog_update.updated_dataspace_catalog.clone();
            }
            let effects = world_commit::PreparedWorldCommit::prepare_overlay_mutations(
                world,
                block_height,
                &nexus,
                &lane_incarnation_activation_heights,
                pending_da_pin_intents.as_ref(),
                pending_autoscale_lifecycle.as_ref(),
            )
            .map_err(|error| {
                error!(
                    block_height,
                    ?error,
                    "failed to prepare the exact World commit"
                );
                match error {
                    crate::execution_attempt::ExecutionAttemptError::Rejected(_) => {
                        TransactionsBlockError::WorldCommitPreparation
                    }
                    crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                        TransactionsBlockError::ExecutionDeferred(reason)
                    }
                }
            })?;
            // The last World write: fold the block's complete change set, including every
            // deterministic tail write above, into the stored World state accumulator, the
            // parent World state root of the next execution result (§4.1, Appendix E, E51).
            world
                .advance_state_accumulator(_curr_block.is_genesis())
                .map_err(|error| {
                    error!(
                        block_height,
                        ?error,
                        "failed to advance the World state accumulator"
                    );
                    TransactionsBlockError::WorldCommitPreparation
                })?;
            *world_effects = Some(effects);
        }
        if !*fields_frozen {
            // All final private writes completed once above. Install every original
            // capture slot before releasing any physical execution writer.
            world.begin_freeze();
            canonical_runtime.begin_freeze();
            native_execution_tip.begin_freeze();
            prev_committed_topology.begin_freeze();
            committed_topology.begin_freeze();
            transactions.finish_freeze()?;
            world.finish_freeze();
            canonical_runtime.finish_freeze();
            native_execution_tip.finish_freeze();
            prev_committed_topology.finish_freeze();
            committed_topology.finish_freeze();
            *fields_frozen = true;
        }
        if !*world_cut_prepared {
            // Frozen journals retain exact preimages on resource refusal; never
            // rerun tail writes or capture a replacement overlay during retry.
            *world_cut = match world_cut_capture {
                Some(capture) => {
                    let tip = native_execution_tip
                        .get()
                        .ok_or(TransactionsBlockError::WorldCommitPreparation)?;
                    let generation = current_generation
                        .checked_add(2)
                        .ok_or(TransactionsBlockError::SnapshotObservationChanged)?;
                    let prepared = match world_cut_pending.take() {
                        Some(pending) => pending
                            .try_share()
                            .map_err(|(pending, error)| (Some(pending), error)),
                        None => capture.prepare_retained(
                            world,
                            tip,
                            generation,
                            &state_ref.ivm_execution_budget(),
                        ),
                    };
                    match prepared {
                        Ok(capsule) => Some(capsule),
                        Err((pending, error)) => {
                            *world_cut_pending = pending;
                            #[cfg(all(test, sumeragi_core_mutation = "HC179"))]
                            {
                                // Restore loss of the actually completed original tail.
                                *world_cut_pending = None;
                            }
                            return Err(match error {
                                world_projection::world_state_accumulator::world_state_cut::CutError::Deferred(reason) => TransactionsBlockError::ExecutionDeferred(reason),
                                world_projection::world_state_accumulator::world_state_cut::CutError::Invalid(reason) => {
                                    error!(block_height, %reason, "original World cut does not reconstruct certified R");
                                    TransactionsBlockError::WorldCommitPreparation
                                }
                            });
                        }
                    }
                }
                None => None,
            };
            *world_cut_prepared = true;
        }
        // This prefix is deliberately not cached: preserve its original priority
        // before every Musubi check and later publication attempt.
        world_commit::PreparedWorldCommit::validate_prepared_policy_transition(world).map_err(
            |error| match error {
                crate::execution_attempt::ExecutionAttemptError::Rejected(_) => {
                    TransactionsBlockError::WorldCommitPreparation
                }
                crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                    TransactionsBlockError::ExecutionDeferred(reason)
                }
            },
        )?;
        if !*musubi_live_validated {
            world_commit::PreparedWorldCommit::validate_prepared_musubi_live(
                world,
                &state_ref.ivm_execution_budget(),
            )
            .map_err(|error| match error {
                crate::execution_attempt::ExecutionAttemptError::Rejected(_) => {
                    TransactionsBlockError::WorldCommitPreparation
                }
                crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                    TransactionsBlockError::ExecutionDeferred(reason)
                }
            })?;
            // This flag retains only complete live-pass success on the original
            // frozen source. Its scratch is already retired by that validator.
            *musubi_live_validated = true;
        }
        if !*musubi_validated {
            world_commit::PreparedWorldCommit::validate_prepared_musubi_universal(
                world,
                &state_ref.ivm_execution_budget(),
            )
            .map_err(|error| match error {
                crate::execution_attempt::ExecutionAttemptError::Rejected(_) => {
                    TransactionsBlockError::WorldCommitPreparation
                }
                crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                    TransactionsBlockError::ExecutionDeferred(reason)
                }
            })?;
            // Only complete success advances this stage. A partial validator
            // refusal preserves its original cause and admits no success marker.
            *musubi_validated = true;
        }
        // TODO: retain unfinished work inside each validator as well as complete
        // passes; only successful same-cut phases survive this narrow retry seam.
        // TODO: connect finite retained materialization and incremental dependency
        // authority to StatePublication; this pure-stage reuse is not a State root.
        if tiered_snapshot.is_none() {
            *tiered_snapshot = Some(tiered_publication::PreparedTieredSnapshot::prepare(
                world,
                &state_ref.tiered_snapshot_worker,
            ));
        }
        if !*effects_captured {
            if let Some(pending) = pending_da_commitments.take() {
                match carrier_da_effects::PreparedDaCommitmentEffects::try_prepare(
                    pending,
                    &nexus,
                    canonical_runtime.get(),
                    &state_ref.ivm_execution_budget(),
                ) {
                    Ok(prepared) => *da_effects = Some(prepared),
                    Err((pending, error)) => {
                        *pending_da_commitments = Some(pending);
                        return Err(TransactionsBlockError::ExecutionDeferred(error));
                    }
                }
            }
            *lifecycle_effects = pending_autoscale_lifecycle.as_ref().map(|pending| {
                carrier_lifecycle_effects::PreparedLaneLifecycleEffects::prepare(pending, &nexus)
            });
            *effects_captured = true;
        }
        #[cfg(test)]
        if FAIL_AFTER_PREPARATION.with(|flag| flag.replace(false)) {
            *irreversible = true;
            return Err(TransactionsBlockError::PublicationRecoveryRequired);
        }
        let autoscale_storage_hold = if let Some(pending) = &pending_autoscale_lifecycle {
            let autoscale_start = Instant::now();
            {
                *irreversible = true;
            }
            let geometry_result = {
                state_ref.apply_committed_autoscale_lane_geometry(
                    pending,
                    block_height,
                    block_header_hash,
                    lifecycle_index_releases,
                )
            };
            if let Err(err) = geometry_result {
                error!(
                    block_height,
                    ?err,
                    "failed to validate staged autoscale lane storage during state commit"
                );
                return Err(TransactionsBlockError::from(err));
            }
            autoscale_start.elapsed()
        } else {
            Duration::ZERO
        };
        {
            let state_write_lock_wait_start = Instant::now();
            let _state_write_lock = write_fence.lock();
            let state_write_lock_wait =
                preflight_state_write_lock_wait + state_write_lock_wait_start.elapsed();
            // First install the same complete original inventory; only then may
            // any participant acquire physical publication authority.
            world
                .install_frozen_publication(&state_ref.world)
                .map_err(|_| TransactionsBlockError::SnapshotObservationChanged)?;
            canonical_runtime
                .install_frozen_publication(&state_ref.canonical_runtime)
                .map_err(|_| TransactionsBlockError::SnapshotObservationChanged)?;
            native_execution_tip
                .install_frozen_publication(&state_ref.native_execution_tip)
                .map_err(|_| TransactionsBlockError::SnapshotObservationChanged)?;
            prev_committed_topology
                .install_frozen_publication(&state_ref.prev_commit_topology)
                .map_err(|_| TransactionsBlockError::SnapshotObservationChanged)?;
            committed_topology
                .install_frozen_publication(&state_ref.commit_topology)
                .map_err(|_| TransactionsBlockError::SnapshotObservationChanged)?;
            transactions.install_frozen_publication(&state_ref.transactions);
            transactions
                .try_prepare_frozen_publication()
                .map_err(original_preparation_error)?;
            block_hashes
                .try_prepare_publication()
                .map_err(|error| match error {
                    mv::PublicationPreparationError::Busy(wait) => {
                        TransactionsBlockError::BlockHashesBusy(wait)
                    }
                    _ => TransactionsBlockError::SnapshotObservationChanged,
                })?;
            world
                .try_prepare_frozen_publication()
                .map_err(original_preparation_error)?;
            canonical_runtime
                .try_prepare_frozen_publication()
                .map_err(original_preparation_error)?;
            native_execution_tip
                .try_prepare_frozen_publication()
                .map_err(original_preparation_error)?;
            prev_committed_topology
                .try_prepare_frozen_publication()
                .map_err(original_preparation_error)?;
            committed_topology
                .try_prepare_frozen_publication()
                .map_err(original_preparation_error)?;
            // Every source and original scalar cut is now retained under the State
            // writer. Consuming installation or visibility failure is terminal.
            *irreversible = true;
            effect_locks.prepare_blocking();
            let _view_generation = publication_notice.begin();
            let state_write_lock_hold_start = Instant::now();
            let tx_commit_start = Instant::now();
            transactions.publish_prepared();
            let tx_commit_hold = tx_commit_start.elapsed();
            // Membership was admitted before every fallible resource step.
            // The exact retained journals now publish under one State writer.
            canonical_runtime.publish_prepared();
            native_execution_tip.publish_prepared();
            let prev_topology_start = Instant::now();
            prev_committed_topology.publish_prepared();
            let prev_topology_hold = prev_topology_start.elapsed();
            let commit_topology_start = Instant::now();
            committed_topology.publish_prepared();
            let commit_topology_hold = commit_topology_start.elapsed();
            let world_start = Instant::now();
            // Hash predecessor acquisition completed before this visibility interval.
            // All original World writes publish under the same State generation.
            world.publish_prepared();
            let world_hold = world_start.elapsed();
            let block_hashes_start = Instant::now();
            block_hashes.publish_prepared();
            // Original capsule is visible only with the same tip, World and
            // block-hash publication. Raw/non-native commits retire authority;
            // decoded restores start absent and must replay genuine execution.
            *state_ref.native_world_cut.lock() = world_cut.take();
            let block_hashes_hold = block_hashes_start.elapsed();
            world_effects
                .take()
                .expect("original prepared World effects")
                .publish(
                    state_ref,
                    effect_locks
                        .da_pin_intents
                        .as_mut()
                        .expect("prepared pin cache"),
                    &mut lifecycle_index_releases.world,
                );
            #[cfg(feature = "telemetry")]
            state_ref
                .telemetry
                .set_musubi_replication_shortfall_releases(
                    *state_ref
                        .world
                        .musubi_replication_shortfall_releases
                        .view()
                        .get(),
                );
            let autoscale_hold = if let Some(prepared) = lifecycle_effects.take() {
                let autoscale_start = Instant::now();
                *lifecycle_post_publication =
                    Some(prepared.publish(state_ref, &mut effect_locks, &_view_generation, true));
                autoscale_storage_hold + autoscale_start.elapsed()
            } else {
                autoscale_storage_hold
            };
            let da_commitments_hold = if let Some(effects) = da_effects.take() {
                let da_start = Instant::now();
                *da_post_publication = Some(effects.publish(
                    state_ref,
                    &mut effect_locks,
                    &nexus.lane_config,
                    &_view_generation,
                    true,
                ));
                da_start.elapsed()
            } else {
                Duration::ZERO
            };
            **effect_locks
                .latest_block_header
                .as_mut()
                .expect("prepared header") = Some(*_curr_block);
            let state_write_lock_hold =
                preflight_state_write_lock_hold + state_write_lock_hold_start.elapsed();
            #[cfg(feature = "telemetry")]
            state_ref
                .telemetry
                .observe_state_commit_write_lock(state_write_lock_wait, state_write_lock_hold);
            let (mut max_component, mut max_hold) = ("prev_commit_topology", prev_topology_hold);
            if tx_validate_hold > max_hold {
                max_component = "transactions_validate";
                max_hold = tx_validate_hold;
            }
            if da_commitments_hold > max_hold {
                max_component = "da_commitments";
                max_hold = da_commitments_hold;
            }
            if autoscale_hold > max_hold {
                max_component = "autoscale_lifecycle";
                max_hold = autoscale_hold;
            }
            if commit_topology_hold > max_hold {
                max_component = "commit_topology";
                max_hold = commit_topology_hold;
            }
            if tx_commit_hold > max_hold {
                max_component = "transactions";
                max_hold = tx_commit_hold;
            }
            if block_hashes_hold > max_hold {
                max_component = "block_hashes";
                max_hold = block_hashes_hold;
            }

            if world_hold > max_hold {
                max_component = "world";
                max_hold = world_hold;
            }
            if state_write_lock_wait >= STATE_VIEW_LOCK_THRESHOLD
                || state_write_lock_hold >= STATE_VIEW_LOCK_THRESHOLD
                || max_hold >= STATE_VIEW_LOCK_THRESHOLD
            {
                debug!(
                    block_height,
                    state_write_lock_wait_us = state_write_lock_wait.as_micros(),
                    state_write_lock_hold_us = state_write_lock_hold.as_micros(),
                    prev_commit_topology_us = prev_topology_hold.as_micros(),
                    commit_topology_us = commit_topology_hold.as_micros(),
                    transactions_validate_us = tx_validate_hold.as_micros(),
                    da_commitments_us = da_commitments_hold.as_micros(),
                    autoscale_lifecycle_us = autoscale_hold.as_micros(),
                    transactions_commit_us = tx_commit_hold.as_micros(),
                    block_hashes_commit_us = block_hashes_hold.as_micros(),
                    world_commit_us = world_hold.as_micros(),
                    max_component,
                    max_component_us = max_hold.as_micros(),
                    "state write lock held (block commit)"
                );
            }
        }
        if let Some(post) = lifecycle_post_publication.as_mut() {
            post.capture_snapshot(
                state_ref,
                effect_locks
                    .da_shard_cursors
                    .as_ref()
                    .expect("prepared shard cursors"),
            );
        }
        if let Some(post) = da_post_publication.as_mut() {
            post.capture_snapshot(
                state_ref,
                &nexus.lane_config,
                effect_locks
                    .da_shard_cursors
                    .as_ref()
                    .expect("prepared shard cursors"),
            );
        }
        effect_locks.release_writers();
        if let Some(post) = lifecycle_post_publication.take() {
            post.publish(state_ref);
        }
        if let Some(post) = da_post_publication.take() {
            post.publish(state_ref);
        }
        drop(autoscale_lifecycle_guard);
        {
            for slash in pending_public_lane_slash_observability.iter() {
                crate::status::record_public_lane_bonded_delta(
                    slash.lane_id,
                    &slash.bonded_amount,
                    false,
                );
                if !slash.pending_unbond_amount.is_zero() {
                    crate::status::record_public_lane_pending_unbond_delta(
                        slash.lane_id,
                        &slash.pending_unbond_amount,
                        false,
                    );
                }
                crate::status::record_public_lane_slash(slash.lane_id);
                #[cfg(feature = "telemetry")]
                {
                    state_ref.telemetry.record_public_lane_validator_status(
                        slash.lane_id,
                        Some(&slash.previous_status),
                        &slash.slashed_status,
                    );
                    state_ref
                        .telemetry
                        .decrease_public_lane_bonded(slash.lane_id, &slash.bonded_amount);
                    if !slash.pending_unbond_amount.is_zero() {
                        state_ref.telemetry.decrease_public_lane_pending_unbond(
                            slash.lane_id,
                            &slash.pending_unbond_amount,
                        );
                    }
                    state_ref.telemetry.record_public_lane_slash(slash.lane_id);
                }
            }
        }
        #[cfg(feature = "telemetry")]
        {
            // Canonical Kura replay rebuilds exact gauges but must not count a
            // historical transition for a second time after node restart.
            if telemetry_origin == crate::sumeragi::executor::CommitTelemetryOrigin::Forward {
                for &(transition, no_result_kind) in pending_parliament_telemetry_events.iter() {
                    state_ref
                        .telemetry
                        .record_committed_parliament_transition(transition, no_result_kind);
                }
            }
            if let Some(counts) = committed_parliament_attempt_counts {
                let (status_counts, stage_counts) = counts.telemetry_counts();
                state_ref
                    .telemetry
                    .set_parliament_attempt_counts(status_counts, stage_counts);
            }
            if let Some(citizens_total) = committed_citizens_total {
                state_ref.telemetry.record_citizens_total(citizens_total);
            }
        }
        // Run the retained persistence plan outside the State writer lock.
        tiered_snapshot
            .take()
            .expect("original prepared tiered snapshot")
            .publish(state_ref);
        {
            state_ref.enforce_nexus_storage_budget(block_height);
            {
                state_ref.persist_query_index_status(block_height, Some(block_header_hash));
            }
        }
        drop(_state_commit_lock);

        *published = true;
        Ok(())
    }
}

#[cfg(test)]
impl StateBlock<'_> {
    /// The original publisher has completed the deterministic World tail and frozen it.
    /// Snapshot fixture projections must read that exact cut without replaying its writes.
    pub(super) fn has_finalized_world_tail_for_snapshot(&self) -> bool {
        self.publication
            .as_ref()
            .is_some_and(|publication| publication.fields_frozen)
    }
}

#[cfg(test)]
impl State {
    /// Real history-lock contention after original validation; no fabricated refusal.
    pub(crate) fn with_publication_blocked_for_test<R>(&self, action: impl FnOnce() -> R) -> R {
        self.transactions
            .with_physical_publication_blocked_for_test(action)
    }

    /// Hold the actual logical membership writer after freezing the original execution.
    pub(crate) fn with_membership_publication_blocked_for_test<R>(
        &self,
        action: impl FnOnce() -> R,
    ) -> R {
        self.transactions
            .with_membership_publication_blocked_for_test(action)
    }

    /// Hold the actual native hash writer for a later-prefix refusal test.
    pub(crate) fn with_hash_publication_blocked_for_test<R>(
        &self,
        action: impl FnOnce() -> R,
    ) -> R {
        let blocker = self.block_hashes.released.guard(
            self.block_hashes
                .map()
                .expect("fixture hash owner")
                .acquire_writer(),
        );
        let result = action();
        drop(blocker);
        result
    }

    /// Exact original configured pool occupancy, including retained private successors.
    pub(crate) fn publication_pool_usage_for_test(&self) -> (usize, usize, usize) {
        (
            self.ivm_execution_budget().reserved_bytes(),
            self.transactions.budget.reserved_bytes(),
            self.block_hashes.budget.reserved_bytes(),
        )
    }

    /// Enable the real snapshot capture on this disposable fixture's actual backend.
    pub(crate) fn enable_publication_snapshot_for_test(&self, path: &std::path::Path) {
        *self.tiered_snapshot_worker.inner.backend.lock() =
            TieredStateBackend::new(true, 0, 1, 0, Some(path.to_path_buf()), None, 0, 0);
    }

    /// Observe the actual snapshot payload capture and retirement, not a mock publisher.
    pub(crate) fn observe_publication_captures_for_test<R>(
        action: impl FnOnce(PublicationCaptureProbe) -> R,
    ) -> R {
        tiered_publication::capture_observer::observe(|counts| {
            action(PublicationCaptureProbe(counts))
        })
    }
}

/// Test observation of the actual retained tiered snapshot payload.
#[cfg(test)]
pub(crate) struct PublicationCaptureProbe(Arc<tiered_publication::capture_observer::Counts>);
#[cfg(test)]
impl PublicationCaptureProbe {
    /// Number of original captures and completed owner retirements.
    pub(crate) fn counts(&self) -> (usize, usize) {
        (self.0.captured(), self.0.released())
    }
}

#[cfg(test)]
impl StateBlock<'_> {
    /// Read the same retained preparation identities without giving mutation authority.
    pub(crate) fn publication_identity_for_test(&self) -> (usize, usize, bool) {
        let p = self
            .publication
            .as_ref()
            .expect("original publication phase");
        (
            p.world_effects
                .as_ref()
                .map_or(0, |e| std::ptr::from_ref(e) as usize),
            p.tiered_snapshot
                .as_ref()
                .and_then(|s| s.payload_for_test())
                .map_or(0, |s| std::ptr::from_ref(s) as usize),
            p.effects_captured,
        )
    }
}

#[cfg(test)]
std::thread_local! {
    static FAIL_AFTER_PREPARATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
#[cfg(test)]
impl StateBlock<'_> {
    /// Inject a terminal failure only after the real original preparation has completed.
    pub(crate) fn fail_publication_after_preparation_for_test() {
        FAIL_AFTER_PREPARATION.with(|flag| flag.set(true));
    }
}

/// Physical local refusal never changes consensus validity or authenticates new state.
fn original_preparation_error(
    error: mv::PublicationPreparationError<core::convert::Infallible>,
) -> TransactionsBlockError {
    match error {
        mv::PublicationPreparationError::Busy(wait) => {
            TransactionsBlockError::PublicationBusy(wait)
        }
        mv::PublicationPreparationError::Changed | mv::PublicationPreparationError::Poisoned => {
            TransactionsBlockError::SnapshotObservationChanged
        }
        mv::PublicationPreparationError::Admission(never) => match never {},
    }
}

impl StateBlock<'_> {
    /// Recover every installed original participant before any release callback.
    fn recover_original_publication_fields(&mut self) {
        let fields = self
            .fields
            .as_mut()
            .expect("original retained State fields");
        fields.world.recover_installed_frozen_publication();
        fields
            .native_execution_tip
            .recover_installed_frozen_publication();
        fields
            .canonical_runtime
            .recover_installed_frozen_publication();
        fields
            .prev_commit_topology
            .recover_installed_frozen_publication();
        fields
            .commit_topology
            .recover_installed_frozen_publication();
        fields.transactions.recover_installed_frozen_publication();
        fields.block_hashes.recover_attempt_for_retry();
    }

    fn retire_original_publication_notices(&mut self) {
        let fields = self
            .fields
            .as_mut()
            .expect("original retained State fields");
        fields.world.retire_frozen_cleanup();
        fields.canonical_runtime.retire_frozen_cleanup();
        fields.native_execution_tip.retire_frozen_cleanup();
        fields.prev_commit_topology.retire_frozen_cleanup();
        fields.commit_topology.retire_frozen_cleanup();
        fields.transactions.retire_frozen_cleanup();
        fields.block_hashes.retire_retry_notices();
    }
}

#[cfg(test)]
#[path = "replay_retirement_probe.rs"]
mod replay_retirement_probe;

#[cfg(test)]
impl StateBlock<'_> {
    /// Inspect actual completed capsule custody, not a copied source authority.
    pub(crate) fn completed_world_cut_identity_for_test(
        &self,
    ) -> Option<world_projection::world_state_accumulator::world_state_cut::CutIdentityForTest>
    {
        let original = self.publication.as_ref()?;
        original
            .world_cut_pending
            .as_ref()
            .map(|pending| pending.identity_for_test())
            .or_else(|| {
                original
                    .world_cut
                    .as_ref()
                    .map(|capsule| capsule.identity_for_test())
            })
    }
}

#[cfg(test)]
impl State {
    /// Read actual fence availability after the original publication attempt returned.
    pub(crate) fn publication_fences_available_for_test(&self) -> (bool, bool) {
        (
            self.state_write_lock.try_lock().is_some(),
            self.state_commit_lock.try_lock().is_some(),
        )
    }
}
