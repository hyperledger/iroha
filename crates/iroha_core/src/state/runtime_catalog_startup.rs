impl State {
    /// Install a frozen manifest source against the startup or replay catalog.
    ///
    /// The caller must supply the catalog reconstructed from configured genesis
    /// authority or the authenticated replay state. Validation holds the State writer.
    /// An identical complete authority retains the original State handles and generation,
    /// including during the post-replay Queue handoff. Only an actual source change begins
    /// a publication; refused sources leave the certified World cut unchanged.
    ///
    /// # Errors
    /// Rejects status-only registries, altered source bodies or digests,
    /// mismatched catalog bindings, and incomplete active-lane coverage.
    pub fn install_materialized_lane_manifests_for_catalog(
        &self,
        manifests: &LaneManifestRegistryHandle,
        catalog: &LaneCatalog,
        governance: &iroha_config::parameters::actual::GovernanceCatalog,
    ) -> Result<(), LaneLifecycleError> {
        let mut publication_notice = self.state_view_publication();
        let mut releases = LaneLifecycleReleases::new(self);
        let mut state_write_release = self.state_write_lock.defer_notifications();
        let _state_write_lock = state_write_release.lock();
        let candidate_bytes = manifests
            .canonical_materialized_authority_preimage(catalog, governance)
            .map_err(runtime_catalog_invalid)?;
        manifests
            .validate_active_coverage_for_catalog(catalog)
            .map_err(|error| LaneLifecycleError::ManifestPolicyUnavailable {
                lane: error.lane,
                reason: error.message(),
            })?;
        {
            let current = releases.manifests.read();
            if current
                .canonical_materialized_authority_preimage(catalog, governance)
                .is_ok_and(|current_bytes| current_bytes == candidate_bytes)
            {
                return Ok(());
            }
        }
        let privacy = Arc::new(LanePrivacyRegistry::from_manifest_registry(manifests));
        let publication = publication_notice.begin();
        self.install_prepared_lane_manifests_in_publication(
            Arc::clone(manifests),
            privacy,
            &publication,
            &mut releases,
        );
        Ok(())
    }

    /// Accept a semantic-preserving refresh without replacing installed State authority.
    ///
    /// Queue and telemetry own refreshed local paths and diagnostics. State retains the
    /// original immutable sources after authenticating the candidate's complete materialized
    /// authority under its writer. Neither acceptance nor refusal publishes a new State
    /// generation: an unchanged manifest must not invalidate the certified World cut.
    pub(crate) fn install_lane_manifests_if_consensus_compatible(
        &self,
        manifests: &LaneManifestRegistryHandle,
    ) -> bool {
        let mut releases = LaneLifecycleReleases::new(self);
        let mut state_write_release = self.state_write_lock.defer_notifications();
        let _state_write_lock = state_write_release.lock();
        let nexus = self
            .canonical_runtime
            .view()
            .nexus_projection(&releases.nexus.read())
            .expect("persisted canonical runtime must be valid");
        let Ok(candidate_bytes) = manifests
            .canonical_materialized_authority_preimage(&nexus.lane_catalog, &nexus.governance)
        else {
            return false;
        };
        let current = releases.manifests.read();
        let Ok(current_bytes) = current
            .canonical_materialized_authority_preimage(&nexus.lane_catalog, &nexus.governance)
        else {
            return false;
        };
        current_bytes == candidate_bytes
    }

    /// Derive effective dataspaces from the configured baseline and protected committed catalog.
    ///
    /// This read-only projection can be checked before an imported snapshot authorizes runtime
    /// publication. It never promotes restored or locally supplied additions into static policy.
    ///
    /// # Errors
    /// Rejects malformed committed additions or a configured physical baseline
    /// that differs from retained snapshot or post-genesis authority.
    pub fn nexus_with_committed_catalog(
        &self,
        mut nexus: iroha_config::parameters::actual::Nexus,
    ) -> Result<iroha_config::parameters::actual::Nexus, LaneLifecycleError> {
        let runtime = runtime_catalog_from_world(&self.world.view())?;
        nexus.dataspace_catalog =
            runtime_catalog_dataspaces(&nexus.configured_dataspace_catalog, runtime.as_ref())?;
        // An absent overlay still has an authoritative physical baseline once
        // State is restored or committed. Only fresh H0 construction/replay may
        // replace placeholder defaults with the configured initial baseline.
        if self.nexus_runtime_restored_from_snapshot || self.committed_height() != 0 {
            let retained = self.nexus_snapshot();
            if SnapshotNexusOwnerPolicy::from_nexus(&nexus).dataspaces
                != SnapshotNexusOwnerPolicy::from_nexus(&retained).dataspaces
            {
                return Err(runtime_catalog_invalid(
                    "configured catalog differs from retained physical dataspace authority",
                ));
            }
        }
        Ok(nexus)
    }

    /// Reconstruct effective manifests from frozen baseline sources and committed additions.
    ///
    /// # Errors
    /// Rejects changed baseline policy, inconsistent effective dataspaces, or invalid manifests.
    pub fn lane_manifests_with_committed_catalog(
        &self,
        baseline: &LaneManifestRegistryHandle,
        nexus: &iroha_config::parameters::actual::Nexus,
    ) -> Result<LaneManifestRegistryHandle, LaneLifecycleError> {
        baseline
            .validate_materialized_source_projection()
            .map_err(runtime_catalog_invalid)?;
        let runtime = runtime_catalog_from_world(&self.world.view())?;
        let expected_dataspaces =
            runtime_catalog_dataspaces(&nexus.configured_dataspace_catalog, runtime.as_ref())?;
        if expected_dataspaces != nexus.dataspace_catalog {
            return Err(runtime_catalog_invalid(
                "effective dataspaces differ from the committed catalog",
            ));
        }
        let registry = match runtime {
            Some(runtime) => {
                if runtime.baseline_manifests_hash
                    != Hash::prehashed(baseline.baseline_consensus_policy_digest())
                {
                    return Err(runtime_catalog_invalid(
                        "configured manifest baseline differs from committed catalog authority",
                    ));
                }
                baseline
                    .with_runtime_additions(
                        &runtime.manifests,
                        &nexus.lane_catalog,
                        &nexus.dataspace_catalog,
                        &nexus.governance,
                    )
                    .map_err(runtime_catalog_invalid)?
            }
            None => baseline
                .with_runtime_additions(
                    &[],
                    &nexus.lane_catalog,
                    &nexus.dataspace_catalog,
                    &nexus.governance,
                )
                .map_err(runtime_catalog_invalid)?,
        };
        registry
            .validate_active_coverage_for_catalog(&nexus.lane_catalog)
            .map_err(|error| LaneLifecycleError::ManifestPolicyUnavailable {
                lane: error.lane,
                reason: error.message(),
            })?;
        registry
            .canonical_materialized_authority_preimage(&nexus.lane_catalog, &nexus.governance)
            .map_err(runtime_catalog_invalid)?;
        Ok(Arc::new(registry))
    }
}
