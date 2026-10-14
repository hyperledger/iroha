//! Physical recovery of exact immutable instances already owned by a durable journal.
use super::*;

impl Kura {
    /// Finish only journal-admitted empty creations before any auxiliary inventory reads.
    /// This does not publish an active catalog or derive an identity from configuration.
    pub(in crate::kura) fn recover_journal_owned_lane_instances_on_startup(&self) -> Result<()> {
        self.durable_mutation_authorized()?;
        // Each original release source outlives every acquired physical guard,
        // including partial acquisition, returned storage errors and unwind.
        #[cfg(not(all(test, sumeragi_core_mutation = "HC354")))]
        let (
            mut prune_releases,
            mut canonical_releases,
            mut geometry_releases,
            mut sidecar_releases,
        ) = (
            self.prune_lock.defer_notifications(),
            self.canonical_chain_lock.defer_notifications(),
            self.lane_geometry_lock.defer_notifications(),
            self.sidecar_lock.defer_notifications(),
        );
        #[cfg(not(all(test, sumeragi_core_mutation = "HC354")))]
        let _prune_guard = prune_releases.lock();
        #[cfg(all(test, sumeragi_core_mutation = "HC354"))]
        let _prune_guard = self.prune_lock.lock();
        #[cfg(test)]
        tests::original_recovery_release_tests::fence_boundary(1);
        #[cfg(not(all(test, sumeragi_core_mutation = "HC354")))]
        let _canonical_guard = canonical_releases.lock();
        #[cfg(all(test, sumeragi_core_mutation = "HC354"))]
        let _canonical_guard = self.canonical_chain_lock.lock();
        #[cfg(test)]
        tests::original_recovery_release_tests::fence_boundary(2);
        #[cfg(not(all(test, sumeragi_core_mutation = "HC354")))]
        let _geometry_guard = geometry_releases.lock();
        #[cfg(all(test, sumeragi_core_mutation = "HC354"))]
        let _geometry_guard = self.lane_geometry_lock.lock();
        #[cfg(test)]
        tests::original_recovery_release_tests::fence_boundary(3);
        #[cfg(not(all(test, sumeragi_core_mutation = "HC354")))]
        let _sidecar_guard = sidecar_releases.lock();
        #[cfg(all(test, sumeragi_core_mutation = "HC354"))]
        let _sidecar_guard = self.sidecar_lock.lock();
        #[cfg(test)]
        tests::original_recovery_release_tests::fence_boundary(4);
        self.durable_mutation_authorized()?;
        let journal = self.read_lane_geometry_journal()?;
        if journal.configured_primary_binding.is_none()
            && journal.records.is_empty()
            && self.exact_durable_blocks_count()? == 0
        {
            return Ok(());
        }
        let locations = self.retained_lane_instance_bindings(&journal)?;
        let mut resumable = journal
            .records
            .iter()
            .filter(|record| record.phase == LaneGeometryPhase::Intent)
            .flat_map(|record| &record.operations)
            .map(|operation| &operation.created)
            .map(LaneGeometryBinding::identity)
            .collect::<BTreeSet<_>>();
        // A later intent cannot recreate an object that an earlier committed
        // reference or predecessor already requires to exist.
        for binding in journal.records.iter().flat_map(|record| {
            record.previous_bindings.iter().chain(
                record
                    .updated_bindings
                    .iter()
                    .filter(move |_| record.phase != LaneGeometryPhase::Intent),
            )
        }) {
            resumable.remove(&binding.identity());
        }
        let h0_creation = self.exact_durable_blocks_count()? == 0 && journal.records.is_empty();
        if h0_creation {
            if let Some(primary) = &journal.configured_primary_binding {
                let blocks = self.binding_blocks_path(primary);
                if !self.validate_path_kind(&blocks, true)?
                    || !self.validate_path_kind(&blocks.join(MARKER_FILE_NAME), false)?
                {
                    resumable.insert(primary.identity());
                }
            }
        }
        // Validate every completed/rolled-back object before writing any new
        // target. An absent auxiliary directory never excuses a missing original storage.
        for location in &locations {
            self.require_lane_instance_network(location)?;
            if !resumable.contains(&location.identity()) {
                self.authenticate_existing_lane_instance_on_startup(location)?;
            }
        }
        for location in &locations {
            if resumable.contains(&location.identity()) {
                self.prepare_journal_owned_lane_instance(
                    location,
                    GeometryEvidencePolicy::AllowJournalIntentProvisioning,
                )?;
                self.require_retained_lane_instance_storage(location)?;
            }
        }
        // No phase, current reference, or active producer capability is changed.
        Ok(())
    }

    fn authenticate_existing_lane_instance_on_startup(
        &self,
        binding: &LaneGeometryBinding,
    ) -> Result<()> {
        let mut captured = self.preflight_lane_instance_open(binding)?;
        self.reverify_lane_instance_parents(&captured)?;
        let blocks = self.binding_blocks_path(binding);
        #[cfg(test)]
        super::super::configured_primary_open_identity_swap_boundary(&blocks)?;
        self.reverify_lane_instance_parents(&captured)?;
        Self::reverify_storage_open_path(&mut captured.paths, &blocks, false)?;
        self.require_retained_lane_instance_storage(binding)?;
        self.reverify_lane_instance_parents(&captured)?;
        Self::reverify_storage_open_path(&mut captured.paths, &blocks, false)
    }

    pub(super) fn require_lane_instance_network(
        &self,
        binding: &LaneGeometryBinding,
    ) -> Result<()> {
        // Before State is available the durable, configured-catalog-authenticated
        // journal is the recovery owner. Once bound, its original network must
        // also equal the independently authenticated State/snapshot network.
        if self
            .lane_storage_network
            .lock()
            .is_some_and(|network| network != binding.network_id)
        {
            return Err(self.geometry_error(
                ErrorKind::InvalidData,
                "retained lane instance differs from the authenticated network",
            ));
        }
        Ok(())
    }

    pub(super) fn require_retained_lane_instance_storage(
        &self,
        binding: &LaneGeometryBinding,
    ) -> Result<()> {
        self.require_lane_instance_network(binding)?;
        let blocks = self.binding_blocks_path(binding);
        self.require_complete_geometry_binding_at(binding, &blocks)?;
        // TODO: Replace unused per-instance base journals with a dedicated native custody
        // record. Current canonical bodies have a separate chain-scoped owner; retained
        // instance identity still requires these exact empty files and original marker.
        for name in [DATA_FILE_NAME, INDEX_FILE_NAME, HASHES_FILE_NAME] {
            read_preflight_file_bounded(&blocks.join(name), 0)?;
        }
        let count_path = blocks.join(COUNT_FILE_NAME);
        let bytes = read_preflight_file_bounded(&count_path, MAX_BLOCK_STORE_COMMIT_MARKER_BYTES)?;
        let marker = norito::decode_canonical::<BlockStoreCommitMarker>(&bytes)
            .map_err(Error::NoritoFrame)?;
        if marker.version != BlockStoreCommitMarker::VERSION
            || marker.count != 0
            || marker.tip_hash.is_some()
        {
            return Err(self.geometry_error(
                ErrorKind::InvalidData,
                "immutable instance base journal is not the canonical empty scaffold",
            ));
        }
        let marker = self.read_lane_marker(&blocks.join(MARKER_FILE_NAME))?;
        self.require_lane_marker_value(&marker, &blocks, binding)?;
        Ok(())
    }
}
