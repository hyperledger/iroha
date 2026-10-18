//! Sole MV owner and scoped projections of canonical lane lifecycle state.
//!
//! The configured Nexus policy and manifest baseline are inputs to projection.
//! Effective lanes, retained lineage and autoscale history belong to the Cell;
//! effective dataspaces and manifests belong to the same scoped World catalog.

use super::*;

#[cfg(test)]
std::thread_local! {
    static RUNTIME_REPLACEMENT_ACQUISITION: std::cell::RefCell<Option<std::sync::mpsc::Sender<()>>>
        = const { std::cell::RefCell::new(None) };
}

/// Observe the actual next acquisition boundary without substituting a writer.
#[cfg(test)]
pub(super) fn observe_next_runtime_replacement_for_test(observer: std::sync::mpsc::Sender<()>) {
    RUNTIME_REPLACEMENT_ACQUISITION.with(|slot| {
        assert!(slot.borrow_mut().replace(observer).is_none());
    });
}

pub(super) struct CanonicalRuntimeProjection {
    pub(super) nexus: iroha_config::parameters::actual::Nexus,
    pub(super) incarnations: BTreeMap<LaneId, Hash>,
    pub(super) activation_heights: BTreeMap<LaneId, u64>,
    pub(super) lineage: BTreeMap<LaneId, LaneIncarnationLineage>,
    pub(super) samples: VecDeque<AutoscaleSampleRecord>,
    pub(super) manifests: LaneManifestRegistryHandle,
    pub(super) privacy: LanePrivacyRegistryHandle,
}

/// Immutable inputs for checking a carrier's runtime projections after execution.
/// The actual World/Cell undo journals still own its dynamic predecessor.
pub(super) struct CapturedRuntimePolicy {
    pub(super) nexus: iroha_config::parameters::actual::Nexus,
    pub(super) manifests: LaneManifestRegistryHandle,
    pub(super) compliance: Option<Arc<LaneComplianceEngine>>,
    pub(super) zk_hash: [u8; 32],
}

impl CapturedRuntimePolicy {
    pub(super) fn capture(
        projection: &CanonicalRuntimeProjection,
        zk: &iroha_config::parameters::actual::Zk,
        compliance: Option<Arc<LaneComplianceEngine>>,
    ) -> Self {
        Self {
            nexus: projection.nexus.clone(),
            manifests: Arc::clone(&projection.manifests),
            compliance,
            zk_hash: compute_zk_consensus_policy_hash(zk),
        }
    }
}

#[path = "canonical_runtime/acquisition.rs"]
mod acquisition;
pub(super) use acquisition::{AcquiredRuntimeBlock, AcquiredRuntimeBlockFields};

// TODO: complete-State capture must consume these originals with all World,
// membership, policy and authenticated-history owners before publishing a root.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "complete-State producer retains committed undo before overlay initialization"
    )
)]
#[path = "canonical_runtime/original_cells.rs"]
mod original_cells;

impl SnapshotNexusRuntime {
    pub(super) fn nexus_projection(
        &self,
        baseline: &iroha_config::parameters::actual::Nexus,
    ) -> Result<iroha_config::parameters::actual::Nexus, LaneLifecycleError> {
        if self.version != Self::VERSION {
            return Err(runtime_catalog_invalid(
                "unsupported canonical runtime record version",
            ));
        }
        if self.lanes.windows(2).any(|pair| pair[0].id >= pair[1].id)
            || self
                .lane_incarnation_lineage
                .windows(2)
                .any(|pair| pair[0].lane_id >= pair[1].lane_id)
        {
            return Err(runtime_catalog_invalid(
                "canonical runtime lanes and lineage must be strictly ordered",
            ));
        }
        let mut nexus = baseline.clone();
        let lane_count = std::num::NonZeroU32::new(self.lane_count)
            .ok_or_else(|| runtime_catalog_invalid("canonical runtime lane count is zero"))?;
        nexus.lane_catalog = LaneCatalog::new(lane_count, self.lanes.clone())?;
        nexus.lane_config =
            iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
        nexus.staking.public_validator_mode = self.owner_policy.public_validator_mode.into();
        nexus.staking.restricted_validator_mode =
            self.owner_policy.restricted_validator_mode.into();
        nexus.staking.max_validators = std::num::NonZeroU32::new(self.owner_policy.max_validators)
            .ok_or_else(|| runtime_catalog_invalid("canonical runtime max validators is zero"))?;
        nexus.routing_policy.default_lane = self.owner_policy.routing_default_lane;
        nexus.routing_policy.default_dataspace = self.owner_policy.routing_default_dataspace;
        nexus.autoscale.enabled = self.owner_policy.autoscale_enabled;
        nexus.autoscale.min_lane_id =
            std::num::NonZeroU32::new(self.owner_policy.autoscale_min_lane_id)
                .ok_or_else(|| runtime_catalog_invalid("canonical runtime minimum lane is zero"))?;
        nexus.autoscale.max_lane_id_exclusive =
            std::num::NonZeroU32::new(self.owner_policy.autoscale_max_lane_id_exclusive)
                .ok_or_else(|| runtime_catalog_invalid("canonical runtime maximum lane is zero"))?;
        nexus.autoscale.last_transition_height = self.autoscale_last_transition_height;
        nexus.autoscale.scale_out_window_blocks =
            std::num::NonZeroU16::new(self.autoscale_scale_out_window_blocks).ok_or_else(|| {
                runtime_catalog_invalid("canonical runtime scale-out window is zero")
            })?;
        nexus.autoscale.scale_in_window_blocks =
            std::num::NonZeroU16::new(self.autoscale_scale_in_window_blocks).ok_or_else(|| {
                runtime_catalog_invalid("canonical runtime scale-in window is zero")
            })?;
        if usize::try_from(self.autoscale_sample_history_cap).ok()
            != Some(autoscale_sample_history_cap(&nexus.autoscale))
            || self.autoscale_sample_history.len() > autoscale_sample_history_cap(&nexus.autoscale)
        {
            return Err(runtime_catalog_invalid(
                "canonical runtime sample cap differs from its retained window policy",
            ));
        }
        // This ownership projection is checked against the scoped protected World
        // catalog before execution. Internal lane-geometry readers may also use it
        // during publication without recursively waiting on their generation guard.
        // Complete metadata readers must use `nexus_projection_with_catalog`.
        nexus.dataspace_catalog = DataSpaceCatalog::new(
            self.owner_policy
                .dataspaces
                .iter()
                .map(|entry| iroha_data_model::nexus::DataSpaceMetadata {
                    id: entry.id,
                    alias: entry.alias.clone(),
                    fault_tolerance: entry.fault_tolerance,
                    description: baseline
                        .dataspace_catalog
                        .by_id(entry.id)
                        .and_then(|entry| entry.description.clone()),
                })
                .collect(),
        )
        .map_err(runtime_catalog_invalid)?;
        Ok(nexus)
    }

    pub(super) fn nexus_projection_with_catalog(
        &self,
        baseline: &iroha_config::parameters::actual::Nexus,
        catalog: Option<&iroha_data_model::nexus::NexusRuntimeCatalogV1>,
    ) -> Result<iroha_config::parameters::actual::Nexus, LaneLifecycleError> {
        let mut nexus = self.nexus_projection(baseline)?;
        nexus.dataspace_catalog =
            runtime_catalog_dataspaces(&nexus.configured_dataspace_catalog, catalog)?;
        if SnapshotNexusOwnerPolicy::from_nexus(&nexus) != self.owner_policy {
            return Err(runtime_catalog_invalid(
                "canonical runtime ownership differs from its scoped World catalog",
            ));
        }
        Ok(nexus)
    }

    pub(super) fn lineage_projection(&self) -> BTreeMap<LaneId, LaneIncarnationLineage> {
        self.lane_incarnation_lineage
            .iter()
            .map(|entry| {
                (
                    entry.lane_id,
                    LaneIncarnationLineage {
                        generation: entry.generation,
                        incarnation: entry.incarnation,
                        activation_height: entry.activation_height,
                    },
                )
            })
            .collect()
    }

    pub(super) fn active_incarnations(&self) -> Result<BTreeMap<LaneId, Hash>, LaneLifecycleError> {
        let lineage = &self.lane_incarnation_lineage;
        if lineage
            .windows(2)
            .any(|pair| pair[0].lane_id >= pair[1].lane_id)
        {
            return Err(runtime_catalog_invalid(
                "canonical runtime lanes and lineage must be strictly ordered",
            ));
        }
        let mut active = BTreeMap::new();
        for lane in &self.lanes {
            let index = lineage
                .binary_search_by_key(&lane.id, |entry| entry.lane_id)
                .map_err(|_| {
                    runtime_catalog_invalid(format!(
                        "active lane {} is missing retained lineage",
                        lane.id
                    ))
                })?;
            active.insert(lane.id, lineage[index].incarnation);
        }
        Ok(active)
    }

    pub(super) fn active_activation_heights(
        &self,
    ) -> Result<BTreeMap<LaneId, u64>, LaneLifecycleError> {
        let lineage = &self.lane_incarnation_lineage;
        if lineage
            .windows(2)
            .any(|pair| pair[0].lane_id >= pair[1].lane_id)
        {
            return Err(runtime_catalog_invalid(
                "canonical runtime lanes and lineage must be strictly ordered",
            ));
        }
        let mut active = BTreeMap::new();
        for lane in &self.lanes {
            let index = lineage
                .binary_search_by_key(&lane.id, |entry| entry.lane_id)
                .map_err(|_| {
                    runtime_catalog_invalid(format!(
                        "active lane {} is missing retained lineage",
                        lane.id
                    ))
                })?;
            active.insert(lane.id, lineage[index].activation_height);
        }
        Ok(active)
    }
}

impl State {
    /// Install a fixture's physical dataspace baseline through validated H0 configuration.
    ///
    /// Updating the process-local Nexus cache does not update canonical World/Cell
    /// projections. Fixtures which add alias namespaces must use the same baseline
    /// installation boundary as fresh node startup.
    #[cfg(test)]
    pub(crate) fn set_dataspace_catalog_for_testing(&mut self, catalog: DataSpaceCatalog) {
        assert_eq!(self.committed_height(), 0, "dataspace fixtures require H0");
        let mut nexus = self.nexus_snapshot();
        nexus.dataspace_catalog = catalog.clone();
        nexus.configured_dataspace_catalog = catalog;
        self.set_nexus_from_config(nexus)
            .expect("install valid pre-genesis fixture dataspace baseline");
    }

    /// Seed the canonical read model for isolated routing tests, including corrupt snapshots.
    ///
    /// This deliberately skips startup and lifecycle validation so negative router tests can
    /// inspect malformed policies. It does not install physical lane storage and must not be
    /// used by execution, commit, recovery, or storage fixtures. The `iroha-core-tests`
    /// capability also permits cross-crate negative routing fixtures to use this same owner.
    #[cfg(any(test, feature = "iroha-core-tests"))]
    pub fn install_synthetic_routing_snapshot_for_testing(
        &self,
        mut nexus: iroha_config::parameters::actual::Nexus,
    ) {
        assert!(
            runtime_catalog_from_world(&self.world.view())
                .unwrap()
                .is_none()
        );
        nexus.configured_dataspace_catalog = nexus.dataspace_catalog.clone();
        nexus.lane_config =
            iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
        let lineage = derive_static_lane_incarnations(&nexus.lane_catalog)
            .into_iter()
            .map(|(lane_id, incarnation)| {
                (
                    lane_id,
                    LaneIncarnationLineage {
                        generation: 0,
                        incarnation,
                        activation_height: 0,
                    },
                )
            })
            .collect();
        self.install_canonical_runtime_projection(&nexus, &lineage, &VecDeque::new())
            .expect("synthetic routing snapshot has complete lane lineage");
        *self.nexus.write() = nexus;
    }

    /// Acquire the original same-cut runtime writers before State publication fences.
    pub(super) fn acquire_canonical_runtime_replacement(
        &self,
    ) -> mv::cell::CurrentReplacement<'_, SnapshotNexusRuntime> {
        #[cfg(test)]
        RUNTIME_REPLACEMENT_ACQUISITION.with(|observer| {
            if let Some(observer) = observer.borrow_mut().take() {
                let _ = observer.send(());
            }
        });
        self.canonical_runtime.current_replacement()
    }

    // Same-cut bootstrap/validated configuration installation only. Signed lifecycle
    // and autoscale carrier transitions use refresh_canonical_runtime on MV overlays.
    // The direct lifecycle caller is cfg(test), retaining its explicit fixture scope.
    pub(super) fn install_canonical_runtime_projection(
        &self,
        nexus: &iroha_config::parameters::actual::Nexus,
        lineage: &BTreeMap<LaneId, LaneIncarnationLineage>,
        samples: &VecDeque<AutoscaleSampleRecord>,
    ) -> Result<(), LaneLifecycleError> {
        Self::install_canonical_runtime_projection_with_owner(
            self.acquire_canonical_runtime_replacement(),
            nexus,
            lineage,
            samples,
        )
    }

    /// Install through writers acquired before any enclosing State fences.
    /// The owner preserves the original undo and is consumed before later World
    /// cleanup, whose constructors acquire World before the runtime writers.
    pub(super) fn install_canonical_runtime_projection_with_owner(
        runtime: mv::cell::CurrentReplacement<'_, SnapshotNexusRuntime>,
        nexus: &iroha_config::parameters::actual::Nexus,
        lineage: &BTreeMap<LaneId, LaneIncarnationLineage>,
        samples: &VecDeque<AutoscaleSampleRecord>,
    ) -> Result<(), LaneLifecycleError> {
        let incarnations = nexus
            .lane_catalog
            .lanes()
            .iter()
            .map(|lane| {
                lineage
                    .get(&lane.id)
                    .map(|entry| (lane.id, entry.incarnation))
                    .ok_or_else(|| {
                        runtime_catalog_invalid(format!(
                            "active lane {} is missing retained lineage",
                            lane.id
                        ))
                    })
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let activation = nexus
            .lane_catalog
            .lanes()
            .iter()
            .map(|lane| {
                lineage
                    .get(&lane.id)
                    .map(|entry| (lane.id, entry.activation_height))
                    .ok_or_else(|| {
                        runtime_catalog_invalid(format!(
                            "active lane {} is missing retained lineage",
                            lane.id
                        ))
                    })
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        validate_lane_incarnation_lineage(
            &nexus.lane_catalog,
            &incarnations,
            &activation,
            lineage,
        )?;
        if samples.len() > autoscale_sample_history_cap(&nexus.autoscale) {
            return Err(runtime_catalog_invalid(
                "runtime sample history exceeds its policy cap",
            ));
        }
        let record = SnapshotNexusRuntime::from_nexus_with_autoscale_history(
            nexus,
            &incarnations,
            &activation,
            samples,
            lineage,
        );
        // Startup revalidation is not a new carrier: an unchanged installation
        // must preserve the retained tip undo instead of committing a no-op block.
        if runtime.get() != &record {
            runtime.publish(record);
        }
        Ok(())
    }

    pub(super) fn project_canonical_runtime(
        &self,
        record: &SnapshotNexusRuntime,
        world: &impl WorldReadOnly,
    ) -> Result<CanonicalRuntimeProjection, LaneLifecycleError> {
        let baseline = self.lane_manifests.read().clone();
        self.project_canonical_runtime_with_manifests(record, world, &baseline)
    }

    pub(super) fn project_canonical_runtime_with_manifests(
        &self,
        record: &SnapshotNexusRuntime,
        world: &impl WorldReadOnly,
        baseline: &LaneManifestRegistryHandle,
    ) -> Result<CanonicalRuntimeProjection, LaneLifecycleError> {
        Self::project_canonical_runtime_from_inputs(record, world, baseline, &self.nexus.read())
    }

    pub(super) fn project_canonical_runtime_from_inputs(
        record: &SnapshotNexusRuntime,
        world: &impl WorldReadOnly,
        baseline: &LaneManifestRegistryHandle,
        configured: &iroha_config::parameters::actual::Nexus,
    ) -> Result<CanonicalRuntimeProjection, LaneLifecycleError> {
        let catalog = runtime_catalog_from_world(world)?;
        let nexus = crate::pipeline_gas_policy::with_root_fees(
            record.nexus_projection_with_catalog(configured, catalog.as_ref())?,
            world.state_parameters(),
        );
        if let Some(catalog) = &catalog
            && catalog.baseline_manifests_hash
                != Hash::prehashed(baseline.baseline_consensus_policy_digest())
        {
            return Err(runtime_catalog_invalid(
                "manifest baseline differs from canonical World catalog",
            ));
        }
        let manifests = if let Some(catalog) = &catalog {
            Arc::new(
                baseline
                    .with_runtime_additions(
                        &catalog.manifests,
                        &nexus.lane_catalog,
                        &nexus.dataspace_catalog,
                        &nexus.governance,
                    )
                    .map_err(runtime_catalog_invalid)?,
            )
        } else {
            rebind_lane_manifests_for_lifecycle(
                baseline.as_ref(),
                &nexus.lane_catalog,
                &nexus.governance,
            )?
        };
        let incarnations = record.active_incarnations()?;
        let activation_heights = record.active_activation_heights()?;
        let lineage = record.lineage_projection();
        validate_lane_incarnation_lineage(
            &nexus.lane_catalog,
            &incarnations,
            &activation_heights,
            &lineage,
        )?;
        let privacy = Arc::new(LanePrivacyRegistry::from_manifest_registry(
            manifests.as_ref(),
        ));
        Ok(CanonicalRuntimeProjection {
            nexus,
            incarnations,
            activation_heights,
            lineage,
            samples: record.autoscale_sample_history.iter().copied().collect(),
            manifests,
            privacy,
        })
    }

    pub(super) fn acquire_canonical_runtime_block(
        &self,
        replacement: bool,
    ) -> Result<AcquiredRuntimeBlock<'_>, StateAdmissionError> {
        loop {
            let generation = self.state_view_generation();
            if !generation.is_multiple_of(2) {
                std::thread::yield_now();
                continue;
            }
            // Capture immutable index inputs before acquiring any native writer.
            // Their release callbacks may retry those writers synchronously. The
            // final generation check joins the manifest baseline to the acquired
            // World.
            let baseline = self.lane_manifests.read().clone();
            // All constructors use the same order. Every guard is dropped before
            // retry; a World-only generation check cannot bind the predecessor.
            // Hash construction detaches its private tree before waiting for World.
            let block_hashes = self.block_hashes.try_next_block(replacement)?;
            let membership = self.transactions.prepare_next_block(replacement)?;
            // Projection payloads outlive joint physical retirement on refusal
            // and unwind. Every Cell slot remains in this caller while initializing.
            let projection_result;
            let mut projection;
            let mut pending =
                acquisition::RuntimeBlockAcquisition::new(self, block_hashes, membership);
            if let Err(error) = pending.initialize(replacement) {
                // The same original prepared generation returns to its sole
                // preparation slot only after every physical sibling releases.
                pending.retain_refused_membership();
                return Err(error);
            }
            projection_result = self.project_canonical_runtime_with_manifests(
                pending.canonical_runtime().get(),
                pending.world(),
                &baseline,
            );
            if !is_stable_state_view_generation(generation, self.state_view_generation()) {
                // One owner unlocks all physical siblings before any native wake,
                // payload cleanup, or original hash-budget refund can run.
                drop(pending);
                drop(projection_result);
                std::thread::yield_now();
                continue;
            }
            projection = Some(
                projection_result.expect("persisted canonical runtime projection must be valid"),
            );
            pending.world_mut().dataspace_catalog = projection
                .as_ref()
                .expect("original prepared runtime projection")
                .nexus
                .dataspace_catalog
                .clone();
            return Ok(pending.finish(&mut projection));
        }
    }
}

impl StateBlock<'_> {
    pub(super) fn validate_canonical_runtime_projection(&self) -> Result<(), String> {
        if self.nexus.lane_config
            != iroha_config::parameters::actual::LaneConfig::from_catalog(&self.nexus.lane_catalog)
        {
            return Err(
                "derived lane configuration differs from its canonical lane catalog".to_owned(),
            );
        }
        validate_lane_incarnation_lineage(
            &self.nexus.lane_catalog,
            &self.lane_incarnations,
            &self.lane_incarnation_activation_heights,
            &self.lane_incarnation_lineage,
        )
        .map_err(|error| error.to_string())?;
        let projected = SnapshotNexusRuntime::from_nexus_with_autoscale_history(
            &self.nexus,
            &self.lane_incarnations,
            &self.lane_incarnation_activation_heights,
            &self.autoscale_sample_history,
            &self.lane_incarnation_lineage,
        );
        if self.canonical_runtime.get() != &projected {
            return Err("runtime working projection differs from its sole MV owner".to_owned());
        }
        Ok(())
    }

    /// Stage only this scope's already-validated lifecycle projection in its actual MV owner.
    pub(super) fn refresh_canonical_runtime(&mut self) {
        let record = SnapshotNexusRuntime::from_nexus_with_autoscale_history(
            &self.nexus,
            &self.lane_incarnations,
            &self.lane_incarnation_activation_heights,
            &self.autoscale_sample_history,
            &self.lane_incarnation_lineage,
        );
        if self.canonical_runtime.get() != &record {
            *self.canonical_runtime.get_mut() = record;
        }
    }
}

#[cfg(test)]
#[path = "canonical_runtime_tests.rs"]
mod tests;

impl StateTransaction<'_, '_> {
    /// Stage an accepted lifecycle candidate without publishing it before transaction apply.
    pub(super) fn refresh_canonical_runtime(&mut self) {
        let samples = self
            .canonical_runtime
            .autoscale_sample_history
            .iter()
            .copied()
            .collect();
        let record = SnapshotNexusRuntime::from_nexus_with_autoscale_history(
            &self.nexus,
            &self.lane_incarnations,
            &self.lane_incarnation_activation_heights,
            &samples,
            &self.lane_incarnation_lineage,
        );
        if self.canonical_runtime.get() != &record {
            *self.canonical_runtime.get_mut() = record;
        }
    }
}
