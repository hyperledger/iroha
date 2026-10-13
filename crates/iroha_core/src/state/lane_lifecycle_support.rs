/// Validate physical routing catalogs against the native consensus committee bounds.
///
/// The former merge-ledger envelope budget is not an authority for native lanes:
/// each lane now certifies its own bounded payload before the global chain merges it.
fn validate_lane_authority_geometry(
    lanes: &LaneCatalog,
    dataspaces: &DataSpaceCatalog,
) -> Result<(), LaneLifecycleError> {
    if lanes.lanes().is_empty() || lanes.lanes().len() > MAX_ACTIVE_EXECUTION_LANES {
        return Err(LaneLifecycleError::CommitteeGeometry(
            "active lane count exceeds the protocol bound".to_owned(),
        ));
    }
    for lane in lanes.lanes() {
        let dataspace = dataspaces
            .by_id(lane.dataspace_id)
            .ok_or(LaneLifecycleError::UnknownDataspace(lane.dataspace_id))?;
        if !(1..=10).contains(&dataspace.fault_tolerance) {
            return Err(LaneLifecycleError::CommitteeGeometry(format!(
                "lane {} requires 1 <= f <= 10 for its 3f + 1 committee",
                lane.id
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod native_lane_geometry_tests {
    use super::*;

    #[test]
    fn physical_routes_require_a_dataspace_with_native_committee_geometry() {
        let lanes = LaneCatalog::default();
        assert!(validate_lane_authority_geometry(&lanes, &DataSpaceCatalog::default()).is_ok());
        let foreign = DataSpaceCatalog::new(vec![iroha_data_model::nexus::DataSpaceMetadata {
            id: DataSpaceId::new(1),
            alias: "foreign".to_owned(),
            description: None,
            fault_tolerance: 1,
        }])
        .expect("valid foreign dataspace");
        assert!(matches!(
            validate_lane_authority_geometry(&lanes, &foreign),
            Err(LaneLifecycleError::UnknownDataspace(DataSpaceId::UNIVERSAL))
        ));
    }
}

struct LaneTopologyDiff<'a> {
    #[cfg(test)]
    added: Vec<&'a iroha_config::parameters::actual::LaneConfigEntry>,
    #[cfg(test)]
    retired: Vec<&'a iroha_config::parameters::actual::LaneConfigEntry>,
    replacements: Vec<(
        &'a iroha_config::parameters::actual::LaneConfigEntry,
        &'a iroha_config::parameters::actual::LaneConfigEntry,
    )>,
    relabelled: Vec<(
        &'a iroha_config::parameters::actual::LaneConfigEntry,
        &'a iroha_config::parameters::actual::LaneConfigEntry,
    )>,
}
#[derive(Clone)]
struct LaneLifecycleCatalogUpdate {
    previous_catalog: LaneCatalog,
    previous_dataspace_catalog: DataSpaceCatalog,
    updated_dataspace_catalog: DataSpaceCatalog,
    previous_routing_policy: LaneRoutingPolicy,
    previous_autoscale: iroha_config::parameters::actual::Autoscale,
    updated_catalog: LaneCatalog,
    previous_lane_config: iroha_config::parameters::actual::LaneConfig,
    updated_lane_config: iroha_config::parameters::actual::LaneConfig,
    previous_lane_incarnations: BTreeMap<LaneId, Hash>,
    updated_lane_incarnations: BTreeMap<LaneId, Hash>,
    previous_lane_incarnation_lineage: BTreeMap<LaneId, LaneIncarnationLineage>,
    updated_lane_incarnation_lineage: BTreeMap<LaneId, LaneIncarnationLineage>,
    previous_lane_incarnation_activation_heights: BTreeMap<LaneId, u64>,
    updated_lane_incarnation_activation_heights: BTreeMap<LaneId, u64>,
    lanes_to_reset: BTreeSet<LaneId>,
    replaced_lane_ids: BTreeSet<LaneId>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LaneIncarnationLineage {
    pub(crate) generation: u64,
    pub(crate) incarnation: Hash,
    pub(crate) activation_height: u64,
}
struct ConfiguredPrimaryReplayGeometry {
    catalog: LaneCatalog,
    lane_config: iroha_config::parameters::actual::LaneConfig,
    incarnations: BTreeMap<LaneId, Hash>,
    activation_heights: BTreeMap<LaneId, u64>,
    lineage: BTreeMap<LaneId, LaneIncarnationLineage>,
    primary_incarnation: Hash,
}
const STATIC_LANE_INCARNATION_DOMAIN: &[u8] = b"iroha:nexus:lane-incarnation:static:v2\0";
const CONFIG_LANE_INCARNATION_DOMAIN: &[u8] = b"iroha:nexus:lane-incarnation:config:v1\0";
const LIFECYCLE_LANE_INCARNATION_DOMAIN: &[u8] = b"iroha:nexus:lane-incarnation:lifecycle:v1\0";
const LANE_INCARNATION_LINEAGE_ROOT_DOMAIN: &[u8] =
    b"iroha:nexus:lane-incarnation-lineage-root:v1\0";
pub(crate) fn lane_incarnation_lineage_root(
    network_id: &iroha_data_model::NetworkId,
    lineage: &BTreeMap<LaneId, LaneIncarnationLineage>,
) -> Hash {
    let entries = lineage
        .iter()
        .map(|(&lane_id, entry)| {
            (
                lane_id,
                entry.generation,
                entry.incarnation,
                entry.activation_height,
            )
        })
        .collect::<Vec<_>>();
    let encoded = (network_id.clone(), entries).encode();
    Hash::new_from_chunks(&[LANE_INCARNATION_LINEAGE_ROOT_DOMAIN, encoded.as_slice()])
}
#[cfg(test)]
const SYNTHETIC_LANE_LIFECYCLE_HEADER_DOMAIN: &[u8] =
    b"iroha:nexus:lane-incarnation:synthetic-header:v1\0";
fn lane_incarnation_is_zero(incarnation: Hash) -> bool {
    incarnation.as_ref().iter().all(|byte| *byte == 0)
}
#[cfg(test)]
fn synthetic_lane_lifecycle_header_hash(
    network_id: &iroha_data_model::NetworkId,
    current_block_height: u64,
    plan: &iroha_data_model::nexus::LaneLifecyclePlan,
) -> HashOf<BlockHeader> {
    let encoded = (network_id.clone(), current_block_height, plan.clone()).encode();
    HashOf::from_untyped_unchecked(Hash::new_from_chunks(&[
        SYNTHETIC_LANE_LIFECYCLE_HEADER_DOMAIN,
        encoded.as_slice(),
    ]))
}
/// Derive the generation-zero lane identities committed by genesis.
///
/// Exact network identity is deliberately absent: `NetworkId` is the final signed-genesis hash,
/// while these values participate in the Nexus/AMX commitment embedded in that same signed block.
/// Including it would require a cryptographic fixed point. Transactions and live height and
/// availability carriers authenticate `NetworkId` separately, while later lifecycle derivation
/// remains network-bound, so this non-circular genesis seed does not weaken replay protection.
pub(crate) fn derive_static_lane_incarnations(catalog: &LaneCatalog) -> BTreeMap<LaneId, Hash> {
    let catalog_hash = merge_lane_consensus_catalog_hash(catalog);
    catalog
        .lanes()
        .iter()
        .map(|lane| {
            let encoded = (catalog_hash, lane.id, merge_lane_config_hash(lane)).encode();
            (
                lane.id,
                Hash::new_from_chunks(&[STATIC_LANE_INCARNATION_DOMAIN, encoded.as_slice()]),
            )
        })
        .collect()
}
fn configured_primary_replay_geometry(
    configured_lane_catalog: &LaneCatalog,
) -> Result<ConfiguredPrimaryReplayGeometry, LaneLifecycleError> {
    let primary = configured_lane_catalog
        .lanes()
        .first()
        .cloned()
        .ok_or_else(|| {
            LaneLifecycleError::ConfiguredCatalogBaseline(
                "configured lane catalog has no primary lane".to_owned(),
            )
        })?;
    let catalog = LaneCatalog::new(configured_lane_catalog.lane_count(), vec![primary])
        .map_err(|error| LaneLifecycleError::ConfiguredCatalogBaseline(error.to_string()))?;
    let incarnations = derive_static_lane_incarnations(&catalog);
    let primary_incarnation = incarnations.get(&LaneId::SINGLE).copied().ok_or_else(|| {
        LaneLifecycleError::ConfiguredCatalogBaseline(
            "configured primary catalog does not contain lane zero".to_owned(),
        )
    })?;
    let activation_heights = BTreeMap::from([(LaneId::SINGLE, 0)]);
    let lineage = BTreeMap::from([(
        LaneId::SINGLE,
        LaneIncarnationLineage {
            generation: 0,
            incarnation: primary_incarnation,
            activation_height: 0,
        },
    )]);
    let lane_config = iroha_config::parameters::actual::LaneConfig::from_catalog(&catalog);
    Ok(ConfiguredPrimaryReplayGeometry {
        catalog,
        lane_config,
        incarnations,
        activation_heights,
        lineage,
        primary_incarnation,
    })
}
fn validate_lane_incarnation_map(
    catalog: &LaneCatalog,
    incarnations: &BTreeMap<LaneId, Hash>,
) -> Result<(), LaneLifecycleError> {
    let expected: BTreeSet<_> = catalog.lanes().iter().map(|lane| lane.id).collect();
    let actual: BTreeSet<_> = incarnations.keys().copied().collect();
    if expected != actual {
        return Err(LaneLifecycleError::LaneIncarnationState(format!(
            "active lane ids {expected:?} do not match incarnation ids {actual:?}"
        )));
    }
    if let Some(lane) = incarnations
        .iter()
        .find_map(|(lane, incarnation)| lane_incarnation_is_zero(*incarnation).then_some(*lane))
    {
        return Err(LaneLifecycleError::LaneIncarnationState(format!(
            "lane {lane} has an all-zero incarnation commitment"
        )));
    }
    let mut unique = BTreeSet::new();
    if let Some((lane, _)) = incarnations
        .iter()
        .find(|(_, incarnation)| !unique.insert(**incarnation))
    {
        return Err(LaneLifecycleError::LaneIncarnationState(format!(
            "lane {lane} reuses another active lane's incarnation commitment"
        )));
    }
    Ok(())
}
fn validate_lane_incarnation_lineage(
    catalog: &LaneCatalog,
    active_incarnations: &BTreeMap<LaneId, Hash>,
    active_activation_heights: &BTreeMap<LaneId, u64>,
    lineage: &BTreeMap<LaneId, LaneIncarnationLineage>,
) -> Result<(), LaneLifecycleError> {
    validate_lane_incarnation_map(catalog, active_incarnations)?;
    validate_lane_incarnation_activation_heights(catalog, active_activation_heights)?;
    let mut unique = BTreeSet::new();
    for (&lane_id, entry) in lineage {
        if lane_incarnation_is_zero(entry.incarnation) {
            return Err(LaneLifecycleError::LaneIncarnationState(format!(
                "retained lineage lane {lane_id} has an all-zero incarnation commitment"
            )));
        }
        if !unique.insert(entry.incarnation) {
            return Err(LaneLifecycleError::LaneIncarnationState(format!(
                "retained lineage lane {lane_id} reuses another lane's latest incarnation commitment"
            )));
        }
    }
    for (&lane_id, &incarnation) in active_incarnations {
        let Some(entry) = lineage.get(&lane_id) else {
            return Err(LaneLifecycleError::LaneIncarnationState(format!(
                "active lane {lane_id} is missing its retained incarnation lineage"
            )));
        };
        if entry.incarnation != incarnation
            || active_activation_heights.get(&lane_id) != Some(&entry.activation_height)
        {
            return Err(LaneLifecycleError::LaneIncarnationState(format!(
                "active lane {lane_id} incarnation or activation does not match its retained lineage"
            )));
        }
    }
    Ok(())
}
fn derive_config_lane_incarnation(
    network_id: &iroha_data_model::NetworkId,
    previous_catalog: &LaneCatalog,
    current_block_height: u64,
    lane: &iroha_data_model::nexus::LaneConfig,
    prior: LaneIncarnationLineage,
    next_generation: u64,
    updated_catalog_hash: Hash,
) -> Hash {
    let previous_catalog_hash = merge_lane_consensus_catalog_hash(previous_catalog);
    let encoded = (
        network_id.clone(),
        previous_catalog_hash,
        updated_catalog_hash,
        current_block_height,
        lane.id,
        merge_lane_config_hash(lane),
        prior.generation,
        prior.incarnation,
        prior.activation_height,
        next_generation,
    )
        .encode();
    Hash::new_from_chunks(&[CONFIG_LANE_INCARNATION_DOMAIN, encoded.as_slice()])
}
fn validate_lane_incarnation_activation_heights(
    catalog: &LaneCatalog,
    activation_heights: &BTreeMap<LaneId, u64>,
) -> Result<(), LaneLifecycleError> {
    let expected: BTreeSet<_> = catalog.lanes().iter().map(|lane| lane.id).collect();
    let actual: BTreeSet<_> = activation_heights.keys().copied().collect();
    if expected != actual {
        return Err(LaneLifecycleError::LaneIncarnationState(format!(
            "active lane ids {expected:?} do not match incarnation activation ids {actual:?}"
        )));
    }
    Ok(())
}
fn derive_lifecycle_lane_incarnation_activation_heights(
    previous_catalog: &LaneCatalog,
    updated_catalog: &LaneCatalog,
    previous: &BTreeMap<LaneId, u64>,
    plan: &iroha_data_model::nexus::LaneLifecyclePlan,
    committing_height: u64,
) -> Result<BTreeMap<LaneId, u64>, LaneLifecycleError> {
    validate_lane_incarnation_activation_heights(previous_catalog, previous)?;
    let additions: BTreeSet<_> = plan.additions.iter().map(|lane| lane.id).collect();
    let updated = updated_catalog
        .lanes()
        .iter()
        .map(|lane| {
            let activation_height = if additions.contains(&lane.id) {
                committing_height
            } else {
                previous.get(&lane.id).copied().ok_or_else(|| {
                    LaneLifecycleError::LaneIncarnationState(format!(
                        "unchanged lane {} is missing its activation height",
                        lane.id
                    ))
                })?
            };
            Ok((lane.id, activation_height))
        })
        .collect::<Result<BTreeMap<_, _>, LaneLifecycleError>>()?;
    validate_lane_incarnation_activation_heights(updated_catalog, &updated)?;
    Ok(updated)
}
fn lane_lifecycle_incarnation_root(
    catalog: &LaneCatalog,
    incarnations: &BTreeMap<LaneId, Hash>,
) -> Result<Hash, LaneLifecycleError> {
    let entries = iroha_data_model::nexus::LaneLifecycleParameterV1::canonical_incarnations(
        catalog,
        incarnations,
    )
    .map_err(|err| LaneLifecycleError::LaneIncarnationState(err.to_string()))?;
    Ok(iroha_data_model::nexus::LaneLifecycleParameterV1::incarnation_root(&entries))
}
fn derive_lifecycle_lane_incarnations(
    network_id: &iroha_data_model::NetworkId,
    committing_header_hash: HashOf<BlockHeader>,
    previous_catalog: &LaneCatalog,
    updated_catalog: &LaneCatalog,
    previous_incarnations: &BTreeMap<LaneId, Hash>,
    previous_activation_heights: &BTreeMap<LaneId, u64>,
    previous_lineage: &BTreeMap<LaneId, LaneIncarnationLineage>,
    plan: &iroha_data_model::nexus::LaneLifecyclePlan,
) -> Result<BTreeMap<LaneId, Hash>, LaneLifecycleError> {
    validate_lane_incarnation_lineage(
        previous_catalog,
        previous_incarnations,
        previous_activation_heights,
        previous_lineage,
    )?;
    let changed_lanes: BTreeSet<_> = plan.additions.iter().map(|lane| lane.id).collect();
    let previous_catalog_hash = merge_lane_consensus_catalog_hash(previous_catalog);
    let mut updated = BTreeMap::new();
    for lane in updated_catalog.lanes() {
        let incarnation = if changed_lanes.contains(&lane.id) {
            let prior = previous_lineage.get(&lane.id).copied();
            let prior_present = [u8::from(prior.is_some())];
            let prior = prior.unwrap_or_else(|| LaneIncarnationLineage {
                generation: 0,
                incarnation: Hash::prehashed([0; Hash::LENGTH]),
                activation_height: 0,
            });
            let next_generation = if prior_present[0] == 0 {
                0
            } else {
                prior.generation.checked_add(1).ok_or_else(|| {
                    LaneLifecycleError::LaneIncarnationState(format!(
                        "lane {} incarnation generation overflow",
                        lane.id
                    ))
                })?
            };
            let encoded = (
                network_id.clone(),
                previous_catalog_hash,
                lane.id,
                merge_lane_config_hash(lane),
                prior.generation,
                prior.incarnation,
                prior.activation_height,
                next_generation,
            )
                .encode();
            Hash::new_from_chunks(&[
                LIFECYCLE_LANE_INCARNATION_DOMAIN,
                committing_header_hash.as_ref(),
                prior_present.as_slice(),
                encoded.as_slice(),
            ])
        } else {
            previous_incarnations
                .get(&lane.id)
                .copied()
                .ok_or_else(|| {
                    LaneLifecycleError::LaneIncarnationState(format!(
                        "unchanged lane {} is missing its prior incarnation",
                        lane.id
                    ))
                })?
        };
        if lane_incarnation_is_zero(incarnation) {
            return Err(LaneLifecycleError::LaneIncarnationState(format!(
                "derived all-zero incarnation for lane {}",
                lane.id
            )));
        }
        updated.insert(lane.id, incarnation);
    }
    validate_lane_incarnation_map(updated_catalog, &updated)?;
    Ok(updated)
}
struct PendingDaCommitmentBundle {
    block_height: u64,
    bundle: iroha_data_model::da::commitment::DaCommitmentBundle,
}
struct PendingDaPinIntentBundle {
    block_height: u64,
    intents: Vec<iroha_data_model::da::pin_intent::DaPinIntent>,
    quota_writes: crate::da::quota::DaIngestQuotaWrites,
}
#[derive(Default)]
struct DaPinIntentIndexPruneKeys {
    tickets: BTreeSet<StorageTicketId>,
    aliases: BTreeSet<String>,
    manifests: BTreeSet<ManifestDigest>,
    lane_epochs: BTreeSet<(LaneId, u64, u64)>,
}
impl DaPinIntentIndexPruneKeys {
    fn is_empty(&self) -> bool {
        self.tickets.is_empty()
            && self.aliases.is_empty()
            && self.manifests.is_empty()
            && self.lane_epochs.is_empty()
    }
}
#[derive(Clone)]
struct PendingAutoscaleLaneLifecycle {
    catalog_update: LaneLifecycleCatalogUpdate,
    updated_lane_manifests: LaneManifestRegistryHandle,
    plan: iroha_data_model::nexus::LaneLifecyclePlan,
    transition: PendingAutoscaleTransition,
    transition_height: u64,
    expected_incarnation_root: Hash,
    runtime_catalog: Option<iroha_data_model::nexus::NexusRuntimeCatalogV1>,
}
/// Physical catalog additions retain data and do not drive logical lane closure.
#[derive(Clone, Debug, Eq, PartialEq)]
enum PendingAutoscaleTransition {
    Manual,
}
impl PendingAutoscaleTransition {
    fn name(&self) -> &'static str {
        "catalog-addition"
    }
    fn log(&self, height: u64) {
        info!(height, "applied authenticated physical catalog addition");
    }
    const fn requires_geometry(&self) -> bool {
        true
    }
}

/// Physical storage identifiers and history remain after native logical lane closure.
fn ensure_physical_catalog_additions_only(
    plan: &iroha_data_model::nexus::LaneLifecyclePlan,
) -> Result<(), LaneLifecycleError> {
    if let Some(lane) = plan.retire.first() {
        return Err(LaneLifecycleError::UnsafeRetirement {
            lane: *lane,
            reason: "physical catalog retirement is unsupported; native lane closure retains its data",
        });
    }
    Ok(())
}

fn ensure_no_retired_physical_drain_metadata(
    lane: &iroha_data_model::nexus::LaneConfig,
) -> Result<(), LaneLifecycleError> {
    if lane.metadata.contains_key(AUTOSCALE_META_DRAIN_STATE) {
        return Err(LaneLifecycleError::InvalidAutoscaleManagedLane {
            lane: lane.id,
            reason: "autoscale.drain_state is retired; native lane state owns closure",
        });
    }
    Ok(())
}

/// Physical catalogs retain every existing lane while native logical closure advances.
fn ensure_physical_lane_ids_retained(
    previous: &[iroha_data_model::nexus::LaneConfig],
    updated: &[iroha_data_model::nexus::LaneConfig],
) -> Result<(), LaneLifecycleError> {
    for lane in previous {
        if !updated.iter().any(|candidate| candidate.id == lane.id) {
            return Err(LaneLifecycleError::UnsafeRetirement {
                lane: lane.id,
                reason: "physical catalog retirement is unsupported; native lane closure retains its data",
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod physical_catalog_addition_tests {
    use super::*;
    #[test]
    fn retired_drain_metadata_never_creates_an_open_physical_route() {
        let mut lane = iroha_data_model::nexus::LaneConfig::default();
        ensure_no_retired_physical_drain_metadata(&lane).unwrap();
        lane.metadata
            .insert(AUTOSCALE_META_DRAIN_STATE.into(), "{}".into());
        assert!(ensure_no_retired_physical_drain_metadata(&lane).is_err());
        assert!(!autoscale_lane_accepts_proposal_height(&lane, 1));
        assert!(!autoscale_lane_accepts_proposal_height(&lane, u64::MAX));
    }

    #[test]
    fn configuration_cannot_drop_a_physical_lane() {
        let first = iroha_data_model::nexus::LaneConfig::default();
        let mut extra = first.clone();
        extra.id = LaneId::new(7);
        let original = [first.clone(), extra.clone()];
        ensure_physical_lane_ids_retained(std::slice::from_ref(&first), &original).unwrap();
        ensure_physical_lane_ids_retained(&original, &[extra, first.clone()]).unwrap();
        assert!(matches!(
            ensure_physical_lane_ids_retained(&original, &[first]),
            Err(LaneLifecycleError::UnsafeRetirement { lane, .. }) if lane == LaneId::new(7)
        ));
    }

    #[test]
    fn physical_retirement_is_rejected_before_geometry_or_custody_changes() {
        let mut plan = iroha_data_model::nexus::LaneLifecyclePlan {
            additions: Vec::new(),
            retire: Vec::new(),
        };
        ensure_physical_catalog_additions_only(&plan).unwrap();
        plan.retire.push(LaneId::new(7));
        assert!(
            matches!(ensure_physical_catalog_additions_only(&plan), Err(LaneLifecycleError::UnsafeRetirement { lane, .. }) if lane == LaneId::new(7))
        );
    }
}

const LIVE_SHARED_DATASPACE_STAKING_OWNER_CHANGE_REASON: &str =
    "it contains live shared-dataspace staking state across a canonical owner reset or change";
const LIVE_LANE_STAKING_CUSTODY_REASON: &str =
    "it retains active validator state or bonded or pending-unbond stake custody";

fn static_staking_owner_for_dataspace_at_height(
    nexus: &iroha_config::parameters::actual::Nexus,
    dataspace_id: DataSpaceId,
    block_height: u64,
) -> Option<LaneId> {
    nexus
        .lane_catalog
        .lanes()
        .iter()
        .filter(|lane| !lane_uses_reserved_autoscale_metadata(lane))
        .filter(|lane| {
            nexus_active_lane_dataspace_at_height(lane.id, nexus, block_height)
                == Some(dataspace_id)
        })
        .filter(|lane| {
            matches!(
                nexus.staking.validator_mode(lane.id, &nexus.lane_catalog),
                iroha_config::parameters::actual::LaneValidatorMode::StakeElected
            )
        })
        .map(|lane| lane.id)
        .min()
}

fn live_staking_projection_lane_for_lanes(
    world: &impl WorldReadOnly,
    lanes: &BTreeSet<LaneId>,
    block_height: u64,
) -> Option<LaneId> {
    let validator_lanes = world
        .public_lane_validators()
        .iter()
        .filter(|(_, record)| {
            record
                .deactivation_height
                .is_none_or(|deactivation_height| {
                    deactivation_height < record.activation_height
                        || block_height < deactivation_height
                })
                || !record.total_stake.is_zero()
                || !record.self_stake.is_zero()
        })
        .filter_map(|(key, record)| {
            lanes
                .contains(&key.0)
                .then_some(key.0)
                .or_else(|| lanes.contains(&record.lane_id).then_some(record.lane_id))
        });
    let share_lanes = world
        .public_lane_stake_shares()
        .iter()
        .filter(|(_, share)| !share.bonded.is_zero() || !share.pending_unbonds.is_empty())
        .filter_map(|(key, share)| {
            lanes
                .contains(&key.0)
                .then_some(key.0)
                .or_else(|| lanes.contains(&share.lane_id).then_some(share.lane_id))
        });
    validator_lanes.chain(share_lanes).min()
}

fn ensure_live_shared_dataspace_staking_owner_is_not_reset(
    world: &impl WorldReadOnly,
    nexus: &iroha_config::parameters::actual::Nexus,
    prospective_nexus: &iroha_config::parameters::actual::Nexus,
    lanes_to_reset: &BTreeSet<LaneId>,
    block_height: u64,
) -> Result<(), LaneLifecycleError> {
    if let Some(live_lane) =
        live_staking_projection_lane_for_lanes(world, lanes_to_reset, block_height)
    {
        return Err(LaneLifecycleError::UnsafeRetirement {
            lane: live_lane,
            reason: LIVE_LANE_STAKING_CUSTODY_REASON,
        });
    }

    // Automatic reward history survives principal exit. Keep its claim lane
    // available until funded liabilities and unclosed historical earnings retire.
    if let Some(lane) = crate::validation_fee_rewards::unsettled_reward_lane(world, lanes_to_reset)?
    {
        return Err(LaneLifecycleError::UnsafeRetirement {
            lane,
            reason: "automatic staking reward obligations remain unsettled",
        });
    }

    let dataspaces = nexus
        .lane_catalog
        .lanes()
        .iter()
        .filter(|lane| !lane_uses_reserved_autoscale_metadata(lane))
        .map(|lane| lane.dataspace_id)
        .collect::<BTreeSet<_>>();
    for dataspace_id in dataspaces {
        let current_owner =
            static_staking_owner_for_dataspace_at_height(nexus, dataspace_id, block_height);
        let prospective_owner = static_staking_owner_for_dataspace_at_height(
            prospective_nexus,
            dataspace_id,
            block_height,
        );
        let current_dataspace_lanes = nexus
            .lane_catalog
            .lanes()
            .iter()
            .filter(|lane| {
                lane.dataspace_id == dataspace_id && !lane_uses_reserved_autoscale_metadata(lane)
            })
            .map(|lane| lane.id)
            .collect::<BTreeSet<_>>();
        let prospective_dataspace_lanes = prospective_nexus
            .lane_catalog
            .lanes()
            .iter()
            .filter(|lane| {
                lane.dataspace_id == dataspace_id && !lane_uses_reserved_autoscale_metadata(lane)
            })
            .map(|lane| lane.id)
            .collect::<BTreeSet<_>>();
        let full_dataspace_retirement = prospective_dataspace_lanes.is_empty()
            && current_dataspace_lanes
                .iter()
                .all(|lane| lanes_to_reset.contains(lane));
        if full_dataspace_retirement {
            continue;
        }
        let sibling_survives = prospective_nexus
            .lane_catalog
            .lanes()
            .iter()
            .any(|candidate| {
                Some(candidate.id) != current_owner
                    && !lane_uses_reserved_autoscale_metadata(candidate)
                    && nexus_active_lane_dataspace_at_height(
                        candidate.id,
                        prospective_nexus,
                        block_height,
                    ) == Some(dataspace_id)
                    && matches!(
                        prospective_nexus
                            .staking
                            .validator_mode(candidate.id, &prospective_nexus.lane_catalog),
                        iroha_config::parameters::actual::LaneValidatorMode::StakeElected
                    )
            });
        let owner_changes = current_owner != prospective_owner;
        let owner_is_reset_while_sibling_survives =
            current_owner.is_some_and(|lane| lanes_to_reset.contains(&lane) && sibling_survives);
        if !owner_changes && !owner_is_reset_while_sibling_survives {
            continue;
        }

        let relevant_lanes = if owner_changes {
            current_dataspace_lanes
        } else {
            BTreeSet::from([current_owner.expect("reset owner must exist")])
        };
        if let Some(live_lane) =
            live_staking_projection_lane_for_lanes(world, &relevant_lanes, block_height)
        {
            return Err(LaneLifecycleError::UnsafeRetirement {
                lane: current_owner.unwrap_or(live_lane),
                reason: LIVE_SHARED_DATASPACE_STAKING_OWNER_CHANGE_REASON,
            });
        }
    }

    Ok(())
}

fn ensure_pending_autoscale_lifecycle_staking_is_safe(
    world: &impl WorldReadOnly,
    nexus: &iroha_config::parameters::actual::Nexus,
    pending: &PendingAutoscaleLaneLifecycle,
    block_height: u64,
) -> Result<(), LaneLifecycleError> {
    let mut prospective_nexus = nexus.clone();
    prospective_nexus.lane_catalog = pending.catalog_update.updated_catalog.clone();
    prospective_nexus.lane_config = pending.catalog_update.updated_lane_config.clone();
    prospective_nexus.dataspace_catalog = pending.catalog_update.updated_dataspace_catalog.clone();
    ensure_live_shared_dataspace_staking_owner_is_not_reset(
        world,
        nexus,
        &prospective_nexus,
        &pending.catalog_update.lanes_to_reset,
        block_height,
    )
}
