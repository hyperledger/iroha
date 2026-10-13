/// Shared physical publication accounting under the original Kura fences.
impl Kura {
    /// Snapshot canonical blocks that are still represented only in memory.
    ///
    /// Callers hold `prune_lock` and `canonical_chain_lock`. This helper must
    /// run before either the lane-geometry or sidecar lock is acquired because
    /// the durable-index snapshot takes the original block-store metadata locks.
    /// Nonblocking publication preparation retains its snapshot in the lease.
    fn pending_canonical_capacity_bytes_under_prune_and_canonical_guards(&self) -> Result<u64> {
        if self.max_disk_usage_bytes == 0 || self.store_root.as_os_str().is_empty() {
            return Ok(0);
        }
        let (persisted_count, unindexed_bytes) = self.persisted_count_and_unindexed_bytes()?;
        self.pending_block_bytes(persisted_count, unindexed_bytes)
    }
    fn sync_bound_evidence_namespace(
        &self,
        namespace: &BoundProgressNamespace,
        kind: &str,
    ) -> Result<()> {
        for (index, directory) in namespace.directories.iter().enumerate() {
            let result = if index == 0 {
                sync_indexed_sidecar_dir_handle(&directory.file)
            } else {
                sync_progress_sidecar_ancestor_dir_handle(&directory.file)
            };
            if let Err(error) = result {
                iroha_logger::warn!(
                    ?error,
                    path = ?directory.expected_path,
                    kind,
                    "failed to sync descriptor-bound evidence namespace"
                );
                return Err(Self::invalid_lane_artifact_error(
                    namespace.data_path.clone(),
                    format!("{kind} directory durability sync failed"),
                ));
            }
        }
        // Standalone evidence publication and pair pruning necessarily change
        // the immediate directory timestamps. Retain the descriptor-bound
        // directory-object invariant without applying the indexed-pair
        // helper's pre-mutation timestamp snapshot after the mutation.
        if !Self::progress_mutation_namespace_unchanged(namespace) {
            return Err(Self::invalid_lane_artifact_error(
                namespace.data_path.clone(),
                format!("{kind} directory durability sync failed"),
            ));
        }
        Ok(())
    }

    /// Admit an exact additional disk peak while preserving every live physical owner.
    fn validate_publication_disk_peak_locked(
        &self,
        pending: u64,
        additional: u64,
        path: &Path,
    ) -> Result<()> {
        if self.max_disk_usage_bytes == 0 || self.store_root.as_os_str().is_empty() {
            return Ok(());
        }
        let used = self.kura_total_disk_usage_bytes()?;
        let required = [pending, additional, self.membership_storage.pending_bytes()]
            .into_iter()
            .try_fold(used, u64::checked_add)
            .ok_or_else(|| {
                Self::invalid_lane_artifact_error(
                    path.to_path_buf(),
                    "physical publication capacity overflowed",
                )
            })?;
        if required > self.max_disk_usage_bytes {
            return Err(Error::StorageBudgetExceeded {
                limit: self.max_disk_usage_bytes,
                used,
                required,
            });
        }
        Ok(())
    }
    /// Check the already reserved original owners before any additional filesystem mutation.
    fn check_publication_capacity_under_prune_and_canonical_guards(&self) -> Result<()> {
        let pending = self.pending_canonical_capacity_bytes_under_prune_and_canonical_guards()?;
        self.validate_publication_disk_peak_locked(pending, 0, &self.store_root)
    }
    fn validate_and_publish_configured_kura_capacity_after_startup_recovery(
        &self,
        complete: bool,
    ) -> Result<()> {
        // Preserve the exact physical sources until every acquired fence and
        // the outer refusal-accounting invalidation have finished.
        #[cfg(not(all(test, sumeragi_core_mutation = "HC356")))]
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
        let publication = (|| -> Result<()> {
            #[cfg(not(all(test, sumeragi_core_mutation = "HC356")))]
            let _prune = prune_releases.lock();
            #[cfg(all(test, sumeragi_core_mutation = "HC356"))]
            let _prune = self.prune_lock.lock();
            #[cfg(test)]
            capacity_release_tests::fence_boundary(1);
            self.ensure_prune_recovery_not_required()?;
            #[cfg(not(all(test, sumeragi_core_mutation = "HC356")))]
            let _canonical = canonical_releases.lock();
            #[cfg(all(test, sumeragi_core_mutation = "HC356"))]
            let _canonical = self.canonical_chain_lock.lock();
            #[cfg(test)]
            capacity_release_tests::fence_boundary(2);
            let pending = if complete {
                self.pending_canonical_capacity_bytes_under_prune_and_canonical_guards()?
            } else {
                0
            };
            #[cfg(not(all(test, sumeragi_core_mutation = "HC356")))]
            let _geometry = geometry_releases.lock();
            #[cfg(all(test, sumeragi_core_mutation = "HC356"))]
            let _geometry = self.lane_geometry_lock.lock();
            #[cfg(test)]
            capacity_release_tests::fence_boundary(3);
            #[cfg(not(all(test, sumeragi_core_mutation = "HC356")))]
            let _sidecar = sidecar_releases.lock();
            #[cfg(all(test, sumeragi_core_mutation = "HC356"))]
            let _sidecar = self.sidecar_lock.lock();
            #[cfg(test)]
            capacity_release_tests::fence_boundary(4);
            if complete {
                self.validate_publication_disk_peak_locked(pending, 0, &self.store_root)?;
            }
            let (used, total) = self.kura_disk_usage_bytes_with_total()?;
            self.disk_usage.store(used, Ordering::Release);
            self.disk_usage_total.store(total, Ordering::Release);
            self.disk_usage_initialized.store(true, Ordering::Release);
            self.disk_usage_total_initialized
                .store(true, Ordering::Release);
            self.disk_usage_total_last_refresh
                .store(Self::now_unix_secs(), Ordering::Relaxed);
            Ok(())
        })();
        if publication.is_err() {
            self.disk_usage_initialized.store(false, Ordering::Release);
            self.disk_usage_total_initialized
                .store(false, Ordering::Release);
            self.invalidate_durable_budget_snapshot();
        }
        publication
    }
}

/// Original physical notification custody for startup recovery capacity accounting.
#[cfg(test)]
mod capacity_release_tests {
    include!("capacity_release_tests.rs");
}
