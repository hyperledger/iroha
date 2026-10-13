// One process-owned lane geometry operation. Local I/O errors return to the
// caller without discarding either storage plan or recapturing moved paths.

struct LaneGeometryPublication {
    raw: Option<crate::kura::RawGeometryAttempt>,
    tiered: Option<tiered::TieredGeometryAttempt>,
    previous: LaneConfig,
    current: LaneConfig,
    previous_incarnations: BTreeMap<LaneId, Hash>,
    current_incarnations: BTreeMap<LaneId, Hash>,
    previous_activation_heights: BTreeMap<LaneId, u64>,
    current_activation_heights: BTreeMap<LaneId, u64>,
    previous_lineage_root: Hash,
    current_lineage_root: Hash,
    replaced: BTreeSet<LaneId>,
    transition_height: u64,
    cursors_updated: bool,
    publish_cursors: bool,
}

fn geometry_lease_error(error: crate::kura::KuraPublicationPreparationError) -> LaneLifecycleError {
    match error {
        crate::kura::KuraPublicationPreparationError::Busy { field, wait } => {
            LaneLifecycleError::PublicationBusy { field, wait }
        }
        crate::kura::KuraPublicationPreparationError::Storage(error) => {
            LaneLifecycleError::GeometryStorage(error)
        }
    }
}

impl State {
    fn resume_lane_geometry_publication(
        &self,
        request: &crate::kura::GeometryBindingRequest<'_>,
        replaced: &BTreeSet<LaneId>,
        mut releases: Option<&mut LaneLifecycleReleases<'_>>,
        original_lease: Option<&crate::kura::KuraPublicationLease<'_>>,
    ) -> Result<(), LaneLifecycleError> {
        // TODO(S6): native close/release authority must precede physical retirement.
        // Refuse before retaining a tiered plan or claiming any raw storage owner.
        request
            .validate_additions_only(replaced)
            .map_err(LaneLifecycleError::GeometryStorage)?;
        let mut local_releases = crate::kura::KuraPublicationReleases::new(&self.kura);
        let publish_cursors = releases.is_some();
        let mut slot = self.geometry_publication.lock();
        if let Some(original) = slot.as_ref() {
            let updated_incarnations = request.updated_incarnations;
            if original.publish_cursors != publish_cursors
                || !lane_config_entries_match(&original.previous, request.previous)
                || !lane_config_entries_match(&original.current, request.updated)
                || original.previous_incarnations != *request.previous_incarnations
                || original.current_incarnations != *updated_incarnations
                || original.previous_activation_heights != *request.previous_activation_heights
                || original.current_activation_heights != *request.updated_activation_heights
                || original.previous_lineage_root != request.previous_lineage_root
                || original.current_lineage_root != request.updated_lineage_root
                || original.transition_height != request.transition_height
                || original.replaced != *replaced
                || original
                    .raw
                    .as_ref()
                    .is_some_and(|raw| !raw.matches_request(request, replaced))
            {
                return Err(LaneLifecycleError::Storage(
                    "another exact lane geometry operation is already retained".to_owned(),
                ));
            }
        } else {
            *slot = Some(LaneGeometryPublication {
                raw: None,
                tiered: None,
                previous: request.previous.clone(),
                current: request.updated.clone(),
                previous_incarnations: request.previous_incarnations.clone(),
                current_incarnations: request.updated_incarnations.clone(),
                previous_activation_heights: request.previous_activation_heights.clone(),
                current_activation_heights: request.updated_activation_heights.clone(),
                previous_lineage_root: request.previous_lineage_root,
                current_lineage_root: request.updated_lineage_root,
                replaced: replaced.clone(),
                transition_height: request.transition_height,
                cursors_updated: false,
                publish_cursors,
            });
        }
        let original = slot.as_mut().ok_or_else(|| {
            LaneLifecycleError::Storage("lane geometry operation was not installed".to_owned())
        })?;
        if original.tiered.is_none() {
            let diff = lane_topology_diff(request.previous, request.updated, replaced);
            original.tiered = Some(
                self.tiered_backend
                    .lock()
                    .prepare_lane_geometry_attempt(
                        request.previous,
                        request.updated,
                        &diff.replacements,
                        &diff.relabelled,
                    )
                    .map_err(|error| {
                        LaneLifecycleError::Storage(format!("tiered preparation: {error:#}"))
                    })?,
            );
        }
        if original.raw.is_none() {
            let cleanup = releases
                .as_mut()
                .map(|releases| &mut releases.geometry)
                .unwrap_or(&mut local_releases);
            let scoped_lease = geometry_scoped_lease(&self.kura, original_lease, cleanup)?;
            let lease = original_lease
                .or(scoped_lease.as_deref())
                .expect("one original geometry lease");
            original.raw = Some(
                lease
                    .begin_raw_geometry_attempt(request, replaced)
                    .map_err(LaneLifecycleError::GeometryStorage)?,
            );
        }
        let raw = original.raw.as_mut().ok_or_else(|| {
            LaneLifecycleError::Storage("missing retained raw geometry owner".to_owned())
        })?;
        // Catalog retry must not send an already chosen publication direction
        // through apply again. Its completed tiered plan is retained too.
        if !matches!(
            raw.phase(),
            crate::kura::RawGeometryPhase::PublishingCatalog
                | crate::kura::RawGeometryPhase::CatalogPublished
        ) {
            let cleanup = releases
                .as_mut()
                .map(|releases| &mut releases.geometry)
                .unwrap_or(&mut local_releases);
            let scoped_lease = geometry_scoped_lease(&self.kura, original_lease, cleanup)?;
            let lease = original_lease
                .or(scoped_lease.as_deref())
                .expect("one original geometry lease");
            raw.resume_under(lease)
                .map_err(LaneLifecycleError::GeometryStorage)?;
        }
        let tiered = original.tiered.as_mut().ok_or_else(|| {
            LaneLifecycleError::Storage("missing retained tiered geometry owner".to_owned())
        })?;
        // A completed plan only reauthenticates its original paths. A local
        // identity refusal cannot reopen progress after catalog publication.
        let tiered_result =
            if tiered.is_applied() && !cfg!(all(test, sumeragi_core_mutation = "HC255")) {
                tiered.authenticate_applied(&self.tiered_backend.lock())
            } else {
                tiered.resume(&mut self.tiered_backend.lock())
            };
        tiered_result.map_err(|error| {
            LaneLifecycleError::Storage(format!("retained tiered geometry: {error:#}"))
        })?;
        if !original.cursors_updated {
            if let Some(releases) = releases.as_mut() {
                releases.shard_cursors.write().sync_mapping(request.updated);
                let should_persist = releases.hydrated.read().is_some();
                original.cursors_updated = true;
                if should_persist {
                    self.persist_lane_lifecycle_cursor_journal(releases);
                }
            } else {
                // Replay and carrier callers own cursor publication separately;
                // physical geometry has no authority to reacquire their indexes.
                original.cursors_updated = true;
            }
        }
        Ok(())
    }

    fn finish_lane_geometry_publication(
        &self,
        current: &LaneConfig,
        incarnations: &BTreeMap<LaneId, Hash>,
        activation_heights: &BTreeMap<LaneId, u64>,
        lineage_root: Hash,
        configured_baseline: Option<Hash>,
        original_lease: Option<&crate::kura::KuraPublicationLease<'_>>,
        mut releases: Option<&mut LaneLifecycleReleases<'_>>,
    ) -> Result<(), LaneGeometryCatalogPublicationFailure> {
        let mut local_releases = crate::kura::KuraPublicationReleases::new(&self.kura);
        let mut finish = || -> Result<(), LaneLifecycleError> {
            let mut slot = self.geometry_publication.lock();
            let original = slot.as_mut().ok_or_else(|| {
                LaneLifecycleError::Storage(
                    "catalog publication requires its original retained geometry operation"
                        .to_owned(),
                )
            })?;
            let raw = original.raw.as_mut().ok_or_else(|| {
                LaneLifecycleError::Storage(
                    "catalog publication has no original raw geometry owner".to_owned(),
                )
            })?;
            if !lane_config_entries_match(&original.current, current)
                || original.current_incarnations != *incarnations
                || original.current_activation_heights != *activation_heights
                || original.current_lineage_root != lineage_root
                || !original
                    .tiered
                    .as_ref()
                    .is_some_and(|tiered| tiered.is_applied())
                || !original.cursors_updated
            {
                return Err(LaneLifecycleError::Storage(
                    "catalog publication differs from its original completed geometry operation"
                        .to_owned(),
                ));
            }
            let cleanup = releases
                .as_mut()
                .map(|releases| &mut releases.geometry)
                .unwrap_or(&mut local_releases);
            let scoped_lease = geometry_scoped_lease(&self.kura, original_lease, cleanup)?;
            let lease = original_lease
                .or(scoped_lease.as_deref())
                .expect("one original geometry lease");
            let tiered = original.tiered.as_ref().ok_or_else(|| {
                LaneLifecycleError::Storage(
                    "catalog publication has no original tiered geometry owner".to_owned(),
                )
            })?;
            if !cfg!(all(test, sumeragi_core_mutation = "HC254")) {
                // Refuse changed paths before choosing a durable publication direction.
                tiered
                    .authenticate_applied(&self.tiered_backend.lock())
                    .map_err(|error| {
                        LaneLifecycleError::Storage(format!(
                            "tiered publication identity: {error:#}"
                        ))
                    })?;
            }
            if raw.phase() != crate::kura::RawGeometryPhase::CatalogPublished {
                raw.publish_catalog_under(lease, configured_baseline)
                    .map_err(LaneLifecycleError::GeometryStorage)?;
            }
            if !cfg!(all(test, sumeragi_core_mutation = "HC254")) {
                // A completed phase is not physical identity evidence. Rejoin both
                // retained owners before releasing them, including after a retry.
                raw.reauthenticate_catalog_under(lease, configured_baseline)
                    .map_err(LaneLifecycleError::GeometryStorage)?;
                tiered
                    .authenticate_applied(&self.tiered_backend.lock())
                    .map_err(|error| {
                        LaneLifecycleError::Storage(format!(
                            "tiered completion identity: {error:#}"
                        ))
                    })?;
            }
            *slot = None;
            Ok(())
        };
        finish().map_err(|error| LaneGeometryCatalogPublicationFailure {
            error,
            // The owner chooses and retains a publication direction, including
            // a rename whose directory sync failed. Never reconstruct rollback.
            rollback_safe: false,
        })
    }

    fn rollback_owned_lane_geometry(
        &self,
        previous: &LaneConfig,
        current: &LaneConfig,
        incarnations: &BTreeMap<LaneId, Hash>,
        activation_heights: &BTreeMap<LaneId, u64>,
        lineage_root: Hash,
        replaced: &BTreeSet<LaneId>,
        transition_height: u64,
        releases: &mut LaneLifecycleReleases<'_>,
    ) -> Result<(), LaneLifecycleError> {
        let mut slot = self.geometry_publication.lock();
        let original = slot.as_mut().ok_or_else(|| {
            LaneLifecycleError::Storage(
                "rollback requires the original retained geometry operation".to_owned(),
            )
        })?;
        if !lane_config_entries_match(&original.previous, previous)
            || !lane_config_entries_match(&original.current, current)
            || original.previous_incarnations != *incarnations
            || original.previous_activation_heights != *activation_heights
            || original.previous_lineage_root != lineage_root
            || original.replaced != *replaced
            || original.transition_height != transition_height
        {
            return Err(LaneLifecycleError::Storage(
                "rollback differs from its original geometry owner".to_owned(),
            ));
        }
        if let Some(error) = original.raw.as_ref().and_then(|raw| raw.recovery_refusal()) {
            return Err(LaneLifecycleError::GeometryStorage(error));
        }
        // Finish a pending apply write before choosing reversal; the raw owner
        // refuses to switch direction while that exact write remains unsettled.
        if original.raw.as_ref().is_some_and(|raw| {
            raw.has_pending_journal_write()
                && raw.phase() != crate::kura::RawGeometryPhase::RollingBack
        }) {
            return Err(LaneLifecycleError::Storage(
                "original geometry write must finish before rollback".to_owned(),
            ));
        }
        if let Some(tiered) = original.tiered.as_mut() {
            tiered
                .rollback(&mut self.tiered_backend.lock())
                .map_err(|error| {
                    LaneLifecycleError::Storage(format!("retained tiered rollback: {error:#}"))
                })?;
        }
        if let Some(raw) = original.raw.as_mut() {
            let lease = geometry_scoped_lease(&self.kura, None, &mut releases.geometry)?
                .expect("standalone original geometry lease");
            raw.rollback_under(&lease)
                .map_err(LaneLifecycleError::GeometryStorage)?;
        }
        if original.publish_cursors {
            releases.shard_cursors.write().sync_mapping(previous);
        }
        *slot = None;
        if releases.hydrated.read().is_some() {
            self.persist_lane_lifecycle_cursor_journal(releases);
        }
        Ok(())
    }
}

struct TieredStartupGeometry {
    configuration: iroha_config::parameters::actual::TieredState,
    lanes: LaneConfig,
    attempt: tiered::TieredGeometryAttempt,
}
impl TieredStartupGeometry {
    fn matches(
        &self,
        cfg: &iroha_config::parameters::actual::TieredState,
        lanes: &LaneConfig,
    ) -> bool {
        let original = &self.configuration;
        original.enabled == cfg.enabled
            && original.hot_retained_keys == cfg.hot_retained_keys
            && original.hot_retained_bytes.get() == cfg.hot_retained_bytes.get()
            && original.hot_retained_grace_snapshots == cfg.hot_retained_grace_snapshots
            && original.cold_store_root == cfg.cold_store_root
            && original.da_store_root == cfg.da_store_root
            && original.max_snapshots == cfg.max_snapshots
            && original.max_cold_bytes.get() == cfg.max_cold_bytes.get()
            && lane_config_entries_match(&self.lanes, lanes)
    }
}

/// One exact lifecycle preflight retained beneath the caller's original fences.
/// Physical application cannot reconstruct policy or read State effect indexes.
struct PreparedCommittedLaneGeometry<'pending> {
    state: &'pending State,
    pending: &'pending PendingAutoscaleLaneLifecycle,
    block_height: u64,
}

impl PreparedCommittedLaneGeometry<'_> {
    fn apply(
        self,
        lease: &crate::kura::KuraPublicationLease<'_>,
    ) -> Result<(), LaneLifecycleError> {
        if !self.pending.transition.requires_geometry() {
            return Ok(());
        }
        let update = &self.pending.catalog_update;
        let request = crate::kura::GeometryBindingRequest {
            previous: &update.previous_lane_config,
            updated: &update.updated_lane_config,
            previous_incarnations: &update.previous_lane_incarnations,
            updated_incarnations: &update.updated_lane_incarnations,
            previous_activation_heights: &update.previous_lane_incarnation_activation_heights,
            updated_activation_heights: &update.updated_lane_incarnation_activation_heights,
            previous_lineage_root: lane_incarnation_lineage_root(
                &self.state.network_id,
                &update.previous_lane_incarnation_lineage,
            ),
            updated_lineage_root: lane_incarnation_lineage_root(
                &self.state.network_id,
                &update.updated_lane_incarnation_lineage,
            ),
            transition_height: self.block_height,
        };
        // The carrier owns all effect-index writers. Its lifecycle continuation
        // syncs the mapping inside State visibility and persists the final cursor
        // journal after same-carrier DA changes. Geometry must not reacquire them.
        self.state.resume_lane_geometry_publication(
            &request,
            &update.replaced_lane_ids,
            None,
            Some(lease),
        )?;
        self.state
            .finish_lane_geometry_publication(
                &update.updated_lane_config,
                &update.updated_lane_incarnations,
                &update.updated_lane_incarnation_activation_heights,
                request.updated_lineage_root,
                None,
                Some(lease),
                None,
            )
            // The retained physical owner always chooses its publication direction.
            // Catalog failure retains that owner for recovery; it cannot roll back.
            .map_err(|failure| failure.error)
    }
}

/// Carrier publication borrows its already acquired lease. Standalone startup
/// retains its existing scoped lease; both use the identical guarded engine.
fn geometry_scoped_lease<'kura, 'releases>(
    kura: &'kura Kura,
    original: Option<&crate::kura::KuraPublicationLease<'_>>,
    releases: &'releases mut crate::kura::KuraPublicationReleases,
) -> Result<Option<crate::kura::ScopedKuraPublicationLease<'kura, 'releases>>, LaneLifecycleError> {
    if let Some(lease) = original {
        if !lease.belongs_to(kura) {
            return Err(LaneLifecycleError::Storage(
                "geometry lease belongs to another Kura".to_owned(),
            ));
        }
        Ok(None)
    } else {
        kura.try_scoped_publication_lease(releases)
            .map(Some)
            .map_err(geometry_lease_error)
    }
}
