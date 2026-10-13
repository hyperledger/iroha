//! Narrow synchronous authorization reads from one stable native State publication.
//!
//! The configured catalog and runtime lane owner are borrowed. Only the protected catalog
//! payload is decoded, under the caller's original cumulative codec context. No full Nexus
//! projection, derived catalog graph, block body, or retrying callback is constructed here.

use super::*;
use iroha_data_model::nexus::{
    DataSpaceCatalogRead, DataSpaceMetadata, NexusRuntimeCatalogV1, RuntimeDataSpaceAdditionV1,
};
use norito::core::DecodeBudgetContext;

/// Borrowed effective dataspace catalog joined to the committed canonical runtime owner.
///
/// Construction is private to the stable State reader. Neither malformed protected state
/// nor mismatched baseline/additions can be interpreted as configured catalog absence.
pub struct AuthorizationDataSpaceCatalog<'view> {
    baseline: &'view DataSpaceCatalog,
    additions: &'view [RuntimeDataSpaceAdditionV1],
}
impl DataSpaceCatalogRead for AuthorizationDataSpaceCatalog<'_> {
    fn by_alias(&self, alias: &str) -> Option<&DataSpaceMetadata> {
        self.baseline.by_alias(alias).or_else(|| {
            self.additions
                .iter()
                .map(|entry| &entry.descriptor)
                .find(|entry| entry.alias == alias)
        })
    }
    fn by_id(&self, id: DataSpaceId) -> Option<&DataSpaceMetadata> {
        self.baseline.by_id(id).or_else(|| {
            self.additions
                .iter()
                .map(|entry| &entry.descriptor)
                .find(|entry| entry.id == id)
        })
    }
}
impl<'view> AuthorizationDataSpaceCatalog<'view> {
    fn admit(
        baseline: &'view DataSpaceCatalog,
        catalog: Option<&'view NexusRuntimeCatalogV1>,
        runtime: &SnapshotNexusRuntime,
        baseline_manifests_hash: Hash,
    ) -> Result<Self, LaneLifecycleError> {
        if runtime.version != SnapshotNexusRuntime::VERSION {
            return Err(runtime_catalog_invalid(
                "unsupported canonical runtime record version",
            ));
        }
        let additions = if let Some(catalog) = catalog {
            let baseline_hash = iroha_data_model::nexus::try_dataspace_catalog_hash(baseline)
                .map_err(runtime_catalog_invalid)?;
            if baseline_hash != catalog.baseline_dataspaces_hash {
                return Err(runtime_catalog_invalid(
                    "configured dataspace baseline differs from committed catalog authority",
                ));
            }
            if catalog.baseline_manifests_hash != baseline_manifests_hash {
                return Err(runtime_catalog_invalid(
                    "manifest baseline differs from canonical World catalog",
                ));
            }
            &catalog.dataspaces[..]
        } else {
            &[]
        };
        for entry in additions {
            if baseline.by_id(entry.descriptor.id).is_some()
                || baseline.by_alias(&entry.descriptor.alias).is_some()
            {
                return Err(runtime_catalog_invalid(
                    "committed dataspace addition replaces a configured identity",
                ));
            }
        }
        let entries = Self {
            baseline,
            additions,
        };
        let count = baseline
            .entries()
            .len()
            .checked_add(additions.len())
            .ok_or_else(|| runtime_catalog_invalid("effective dataspace count overflow"))?;
        if count != runtime.owner_policy.dataspaces.len()
            || runtime
                .owner_policy
                .dataspaces
                .windows(2)
                .any(|pair| pair[0].id >= pair[1].id)
            || runtime.owner_policy.dataspaces.iter().any(|owner| {
                entries.by_id(owner.id).is_none_or(|entry| {
                    entry.alias != owner.alias || entry.fault_tolerance != owner.fault_tolerance
                })
            })
        {
            return Err(runtime_catalog_invalid(
                "canonical runtime ownership differs from its scoped World catalog",
            ));
        }
        if runtime.lane_count == 0
            || runtime.lanes.is_empty()
            || runtime.lanes.len() > iroha_data_model::nexus::MAX_ACTIVE_EXECUTION_LANES
            || runtime
                .lanes
                .windows(2)
                .any(|pair| pair[0].id >= pair[1].id)
            || runtime.lanes.iter().enumerate().any(|(index, lane)| {
                lane.id.as_u32() >= runtime.lane_count
                    || lane.alias.trim().is_empty()
                    || lane.validate_policy_surface().is_err()
                    || entries.by_id(lane.dataspace_id).is_none()
                    || runtime.lanes[..index]
                        .iter()
                        .any(|previous| previous.alias == lane.alias)
            })
        {
            return Err(runtime_catalog_invalid(
                "canonical active lane catalog is malformed",
            ));
        }
        Ok(entries)
    }
}

/// Borrowed authorization sources from one completed State publication.
///
/// This value is supplied only to a synchronous callback. Its World, catalog, and lanes
/// cannot escape that borrow. An explicitly owned result must retain its caller's admission.
pub struct AuthorizationRead<'view, 'state> {
    world: &'view WorldView<'state>,
    catalog: AuthorizationDataSpaceCatalog<'view>,
    lanes: &'view [iroha_data_model::nexus::LaneConfig],
    height: usize,
    ledger_time_ms: u64,
    generation: u64,
}
impl<'view, 'state> AuthorizationRead<'view, 'state> {
    /// Borrow the original World indexes and encoded protected records.
    /// The independently validated effective catalog is available through [`Self::catalog`].
    pub fn world(&self) -> &WorldView<'state> {
        self.world
    }
    /// Borrow exact configured and committed dataspace bindings without cloning metadata.
    pub fn catalog(&self) -> &AuthorizationDataSpaceCatalog<'view> {
        &self.catalog
    }
    /// Borrow the canonical active lane owner for route-first visibility membership.
    pub fn active_lanes(&self) -> &[iroha_data_model::nexus::LaneConfig] {
        self.lanes
    }
    /// Exact committed height joined to the same State publication.
    pub fn height(&self) -> usize {
        self.height
    }
    /// Deterministic authenticated ledger time; zero is permitted only before genesis.
    pub fn ledger_time_ms(&self) -> u64 {
        self.ledger_time_ms
    }
    /// Exact even State publication generation captured by this view.
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

impl State {
    /// Try one stable, synchronous authorization read using the caller's original codec owner.
    ///
    /// Protected payloads and the callback execute inside `context`; no new counter grants
    /// additional capacity. The callback runs exactly once after the generation join. There
    /// is no internal retry, async suspension, full Nexus clone, or stale baseline fallback.
    ///
    /// # Errors
    /// Returns the original physical reader's release notice on contention, or rejects
    /// malformed protected state, catalog ownership, and authenticated tip/time disagreement.
    pub fn try_with_authorization_view<'state, R>(
        &'state self,
        context: &DecodeBudgetContext,
        work: impl for<'view> FnOnce(AuthorizationRead<'view, 'state>) -> R,
    ) -> Result<R, StateViewError> {
        context.with(|| {
            let generation_release = self.state_write_lock.observe_release();
            let generation = self.state_view_generation();
            if !generation.is_multiple_of(2) {
                return Err(StateViewError::Busy(generation_release));
            }
            // Release notices outlive every physical source guard, including on refusal/unwind.
            let mut world_releases = view_acquisition::WorldReadReleases::new(&self.world);
            let mut hashes_releases = self.block_hashes.reader_release_batch();
            let mut header_releases = self.latest_block_header.defer_notifications();
            let mut nexus_releases = self.nexus.defer_notifications();
            let mut manifest_releases = self.lane_manifests.defer_notifications();
            let hashes = self.block_hashes.try_view_retaining(&mut hashes_releases)?;
            let header = header_releases.try_read_or_wait()?;
            let world = self
                .world
                .try_authorization_view_retaining(&mut world_releases)?;
            let runtime = self.canonical_runtime.view();
            let native_tip = self.native_execution_tip.view();
            let configured = nexus_releases.try_read_or_wait()?;
            let manifests = manifest_releases.try_read_or_wait()?;
            let catalog = runtime_catalog_from_world(&world);
            // Inspect typed projection errors only after establishing a stable source snapshot.
            if !is_stable_state_view_generation(generation, self.state_view_generation()) {
                return Err(StateViewError::Busy(generation_release));
            }
            let catalog = catalog?;
            let catalog = AuthorizationDataSpaceCatalog::admit(
                &configured.configured_dataspace_catalog,
                catalog.as_ref(),
                runtime.get(),
                Hash::prehashed(manifests.baseline_consensus_policy_digest()),
            )?;
            let height = hashes.len();
            let latest_hash = hashes.last().copied();
            let ledger_time_ms = if height == 0 {
                if header.is_some() || native_tip.get().is_some() {
                    return Err(runtime_catalog_invalid(
                        "pre-genesis authorization has a committed tip",
                    )
                    .into());
                }
                0
            } else {
                header
                    .as_ref()
                    .filter(|header| Some(header.hash()) == latest_hash)
                    .map(|header| {
                        u64::try_from(header.creation_time().as_millis()).unwrap_or(u64::MAX)
                    })
                    .or_else(|| {
                        let tip = (*native_tip.get())?;
                        (Some(tip.iroha_hash()) == latest_hash
                            && usize::try_from(tip.height()).ok() == Some(height))
                        .then_some(tip.creation_time_ms())
                    })
                    .ok_or_else(|| {
                        runtime_catalog_invalid(
                            "authorization ledger time has no authenticated committed tip",
                        )
                    })?
            };
            if !is_stable_state_view_generation(generation, self.state_view_generation()) {
                return Err(StateViewError::Busy(generation_release));
            }
            Ok(work(AuthorizationRead {
                world: &world,
                catalog,
                lanes: &runtime.lanes,
                height,
                ledger_time_ms,
                generation,
            }))
        })
    }
}

#[cfg(test)]
#[path = "authorization_read_tests.rs"]
mod tests;
