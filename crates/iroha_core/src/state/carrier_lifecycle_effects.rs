//! Retained lifecycle projections, separate from State visibility and post work.
//!
//! Preparation uses the original accepted lifecycle under the enclosing carrier's
//! admission. These values grant no publication authority. Runtime index mutation
//! and cursor snapshot allocation still require their own complete admission.

use super::*;

/// Exact immutable manifest/privacy and reset projections, with no State borrow.
pub(super) struct PreparedLaneLifecycleEffects {
    manifests: LaneManifestRegistryHandle,
    privacy: LanePrivacyRegistryHandle,
    lanes_to_reset: BTreeSet<LaneId>,
    active_reset_lanes: BTreeSet<LaneId>,
    lane_config: iroha_config::parameters::actual::LaneConfig,
    transition: PendingAutoscaleTransition,
    transition_height: u64,
    #[cfg(feature = "telemetry")]
    nexus: iroha_config::parameters::actual::Nexus,
}

/// Original post-publication work, consumed after closing the State generation.
/// The enclosing commit/lifecycle fences must remain held through this work.
pub(super) struct LaneLifecyclePostPublication {
    lane_config: iroha_config::parameters::actual::LaneConfig,
    persist_cursor_journal: bool,
    snapshot: Option<DaShardCursorJournal>,
    captured: bool,
    transition: PendingAutoscaleTransition,
    transition_height: u64,
    #[cfg(feature = "telemetry")]
    nexus: iroha_config::parameters::actual::Nexus,
}

impl PreparedLaneLifecycleEffects {
    /// Capture once under the caller's existing admission, without reading State
    /// or creating an alternative capacity policy. The retained manifest owner
    /// remains the source of the privacy projection throughout publication.
    pub(super) fn prepare(
        pending: &PendingAutoscaleLaneLifecycle,
        nexus: &iroha_config::parameters::actual::Nexus,
    ) -> Self {
        #[cfg(not(feature = "telemetry"))]
        let _ = nexus;
        Self {
            manifests: Arc::clone(&pending.updated_lane_manifests),
            privacy: Arc::new(LanePrivacyRegistry::from_manifest_registry(
                &pending.updated_lane_manifests,
            )),
            lanes_to_reset: pending.catalog_update.lanes_to_reset.clone(),
            active_reset_lanes: State::active_reset_lanes(
                &pending.catalog_update.lanes_to_reset,
                &pending.catalog_update.updated_lane_config,
            ),
            lane_config: pending.catalog_update.updated_lane_config.clone(),
            transition: pending.transition.clone(),
            transition_height: pending.transition_height,
            #[cfg(feature = "telemetry")]
            nexus: nexus.clone(),
        }
    }

    /// Install retained projections inside the caller's original generation.
    /// Process reset precedes same-carrier DA metric updates. Cursor disk I/O,
    /// catalog telemetry and logging remain owned by the returned continuation;
    /// replay prevalidation suppresses process reset and cursor persistence.
    pub(super) fn publish(
        self,
        state: &State,
        indexes: &mut effect_publication::StateEffectLocks<'_>,
        _publication: &StateViewGenerationWriteGuard<'_>,
        publish_process_runtime: bool,
    ) -> LaneLifecyclePostPublication {
        indexes.install_registries(self.manifests, self.privacy);
        let mapping_changed = self.transition.requires_geometry();
        if mapping_changed {
            // Physical geometry retains no cursor guards. Publish its exact mapping
            // through this already-acquired index with the rest of the carrier.
            indexes
                .da_shard_cursors
                .as_mut()
                .expect("prepared shard cursors")
                .sync_mapping(&self.lane_config);
        }
        if !self.lanes_to_reset.is_empty() {
            indexes
                .da_commitments
                .as_mut()
                .expect("prepared commitments")
                .prune_lanes(&self.lanes_to_reset);
            indexes
                .da_confidential_compute
                .as_mut()
                .expect("prepared confidential compute")
                .prune_lanes(&self.lanes_to_reset);
            indexes
                .da_pin_intents
                .as_mut()
                .expect("prepared pins")
                .prune_lanes(&self.lanes_to_reset);
            indexes
                .da_receipt_cursors
                .as_mut()
                .expect("prepared receipt cursors")
                .prune_lanes(&self.lanes_to_reset);
            indexes
                .da_shard_cursors
                .as_mut()
                .expect("prepared shard cursors")
                .prune_lanes(&self.lanes_to_reset);
        }
        if publish_process_runtime {
            state.publish_lane_scoped_runtime_reset(&self.lanes_to_reset);
        }
        let records_reset = !self.active_reset_lanes.is_empty() && self.transition_height != 0;
        if records_reset {
            indexes
                .da_shard_cursors
                .as_mut()
                .expect("prepared shard cursors")
                .mark_lanes_canonically_reset(&self.active_reset_lanes, self.transition_height);
        }
        let persist_cursor_journal = publish_process_runtime
            && (records_reset
                || ((mapping_changed || !self.lanes_to_reset.is_empty())
                    && indexes
                        .da_indexes_hydrated
                        .as_ref()
                        .expect("prepared hydration status")
                        .is_some()));
        LaneLifecyclePostPublication {
            lane_config: self.lane_config,
            persist_cursor_journal,
            snapshot: None,
            captured: false,
            transition: self.transition,
            transition_height: self.transition_height,
            #[cfg(feature = "telemetry")]
            nexus: self.nexus,
        }
    }
}

impl LaneLifecyclePostPublication {
    /// Capture the final cursor image using the original acquired index, after
    /// all same-carrier DA updates and before releasing any index guard.
    pub(super) fn capture_snapshot(&mut self, state: &State, cursors: &DaShardCursorIndex) {
        assert!(
            !self.captured,
            "original lifecycle cursor snapshot captured once"
        );
        self.captured = true;
        if self.persist_cursor_journal {
            let path = state.da_shard_cursor_journal_path();
            if !path.as_os_str().is_empty() {
                self.snapshot = Some(DaShardCursorJournal::from_index(
                    &self.lane_config,
                    cursors,
                    &path,
                ));
            }
        }
    }

    /// Finish under the original commit/lifecycle fences after generation close.
    /// Capture the final cursor index after all same-carrier DA effects, using
    /// this lifecycle's retained mapping rather than a newer live Nexus view.
    pub(super) fn publish(self, state: &State) {
        assert!(
            self.captured,
            "original lifecycle cursor snapshot precedes release"
        );
        #[cfg(not(feature = "telemetry"))]
        let _ = state;
        if let Some(snapshot) = self.snapshot {
            if let Err(err) = snapshot.persist() {
                warn!(?err, "failed to persist DA shard cursor journal");
            }
        }
        // Preserve existing lifecycle telemetry and log behavior even for replay
        // prevalidation; only cursor/process publication was suppressed before.
        #[cfg(feature = "telemetry")]
        {
            state
                .telemetry
                .set_nexus_catalogs(&self.nexus.lane_catalog, &self.nexus.dataspace_catalog);
            if let Some(event) = state.telemetry.record_nexus_config_diff(&self.nexus) {
                match norito::json::to_string(&event) {
                    Ok(payload) => {
                        iroha_logger::telemetry!(msg = "nexus.config.diff", event = payload);
                    }
                    Err(err) => {
                        iroha_logger::error!(
                            ?err,
                            "failed to serialize autoscale nexus config diff event for telemetry log"
                        );
                    }
                }
            }
        }
        self.transition.log(self.transition_height);
    }
}
