//! Typed lane-route authority resolution results.

use std::collections::BTreeSet;

use iroha_data_model::{NetworkId, account::AccountId};
use iroha_model_base::peer::PeerId;
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
use iroha_primitives::numeric::Quantity;
use mv::storage::StorageReadOnly;
use thiserror::Error;

use super::{
    ResolvedLaneAuthorityInputs, State, WorldReadOnly, bounded_authority,
    consensus_lane_dataspace_at_height, decode_autoscale_lane_committee,
    lane_claims_autoscale_managed, lane_uses_reserved_autoscale_metadata,
    nexus_active_lane_dataspace_at_height, nexus_lane_active_for_authority,
    nexus_lane_committee_size, nexus_manifest_authority_eligible_lanes_at_height,
    nexus_staking_authority_lane_at_height, peer_has_live_consensus_key_for_lane,
    public_lane_validator_record_matches_key,
};
use crate::governance::manifest::{GovernanceRules, LaneManifestRegistry};

/// Exact lane/dataspace route whose consensus authority is being resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaneAuthorityRoute {
    lane_id: LaneId,
    dataspace_id: DataSpaceId,
}

impl LaneAuthorityRoute {
    /// Construct an exact lane/dataspace authority route.
    #[must_use]
    pub const fn new(lane_id: LaneId, dataspace_id: DataSpaceId) -> Self {
        Self {
            lane_id,
            dataspace_id,
        }
    }

    /// Lane bound to this route.
    #[must_use]
    pub const fn lane_id(self) -> LaneId {
        self.lane_id
    }

    /// Dataspace bound to this route.
    #[must_use]
    pub const fn dataspace_id(self) -> DataSpaceId {
        self.dataspace_id
    }
}

/// Canonical exact `3f+1` authority resolved for one route and height.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaneAuthorityCommittee {
    route: LaneAuthorityRoute,
    authority_height: u64,
    fault_tolerance: u32,
    validators: Vec<PeerId>,
}

impl LaneAuthorityCommittee {
    /// Construct a committee after exact route, geometry, and source validation.
    pub(super) fn new(
        route: LaneAuthorityRoute,
        authority_height: u64,
        fault_tolerance: u32,
        validators: Vec<PeerId>,
    ) -> Self {
        Self {
            route,
            authority_height,
            fault_tolerance,
            validators,
        }
    }

    /// Exact route authorized by this committee.
    #[must_use]
    pub const fn route(&self) -> LaneAuthorityRoute {
        self.route
    }

    /// Consensus height whose route, epoch seed, and live pool were resolved.
    #[must_use]
    pub const fn authority_height(&self) -> u64 {
        self.authority_height
    }

    /// Dataspace fault tolerance used to derive the exact committee size.
    #[must_use]
    pub const fn fault_tolerance(&self) -> u32 {
        self.fault_tolerance
    }

    /// Canonically ordered exact `3f+1` validators.
    #[must_use]
    pub fn validators(&self) -> &[PeerId] {
        &self.validators
    }

    /// Consume this authority and return its canonical validators.
    #[must_use]
    pub fn into_validators(self) -> Vec<PeerId> {
        self.validators
    }
}

/// Fail-closed error while resolving canonical lane authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum LaneAuthorityError {
    /// The requested dataspace is absent from the committed catalog.
    #[error("lane authority dataspace {dataspace_id} is not configured")]
    UnknownDataspace {
        /// Missing dataspace identifier.
        dataspace_id: DataSpaceId,
    },
    /// The lane is not active on the requested dataspace at this height.
    #[error(
        "lane {lane_id} is not active on dataspace {dataspace_id} at authority height {authority_height}"
    )]
    InactiveRoute {
        /// Requested lane.
        lane_id: LaneId,
        /// Requested dataspace.
        dataspace_id: DataSpaceId,
        /// Requested consensus height.
        authority_height: u64,
    },
    /// The dataspace's configured `f` cannot form a protocol-bounded `3f+1` committee.
    #[error(
        "dataspace {dataspace_id} fault tolerance {fault_tolerance} does not define a valid bounded 3f+1 lane committee"
    )]
    InvalidGeometry {
        /// Dataspace whose geometry is invalid.
        dataspace_id: DataSpaceId,
        /// Configured Byzantine fault tolerance.
        fault_tolerance: u32,
    },
    /// Manifest/staking authority inputs are inconsistent with the exact route.
    #[error(
        "lane {lane_id} dataspace {dataspace_id} has inconsistent manifest or staking authority at height {authority_height}"
    )]
    InvalidAuthoritySource {
        /// Requested lane.
        lane_id: LaneId,
        /// Requested dataspace.
        dataspace_id: DataSpaceId,
        /// Requested consensus height.
        authority_height: u64,
    },
    /// An oversubscribed pool has no published threshold-beacon history yet.
    #[error(
        "lane {lane_id} dataspace {dataspace_id} awaits threshold-beacon selection entropy at height {authority_height}"
    )]
    SelectionEntropyUnavailable {
        /// Requested lane.
        lane_id: LaneId,
        /// Requested dataspace.
        dataspace_id: DataSpaceId,
        /// Requested consensus height.
        authority_height: u64,
    },
    /// The live canonical pool cannot fill the exact `3f+1` committee.
    #[error(
        "lane {lane_id} dataspace {dataspace_id} requires {required} validators at height {authority_height}, but its canonical pool has {actual}"
    )]
    UndersizedPool {
        /// Requested lane.
        lane_id: LaneId,
        /// Requested dataspace.
        dataspace_id: DataSpaceId,
        /// Requested consensus height.
        authority_height: u64,
        /// Exact `3f+1` size.
        required: usize,
        /// Unique validators available from the canonical source.
        actual: usize,
    },
    /// An immutable autoscale pin does not have the dataspace's exact `3f+1` shape.
    #[error(
        "autoscale lane {lane_id} dataspace {dataspace_id} pins {actual} validators, expected exactly {required}"
    )]
    InvalidAutoscalePin {
        /// Autoscale lane.
        lane_id: LaneId,
        /// Bound dataspace.
        dataspace_id: DataSpaceId,
        /// Exact `3f+1` size.
        required: usize,
        /// Pinned validator count.
        actual: usize,
    },
    /// Canonical peer encoding failed while deriving the seeded committee order.
    #[error("failed to encode a lane authority peer canonically")]
    CanonicalPeerEncoding,
}

/// Snapshot the bounded authority inputs for one active lane and height.
pub(super) fn inputs_from_nexus(
    lane_id: LaneId,
    validator_mode: iroha_config::parameters::actual::LaneValidatorMode,
    nexus: &iroha_config::parameters::actual::Nexus,
    block_height: u64,
) -> Option<ResolvedLaneAuthorityInputs> {
    let dataspace_id = State::nexus_authoritative_lane_dataspace(lane_id, nexus)?;
    nexus_lane_active_for_authority(lane_id, dataspace_id, nexus, block_height).then_some(())?;
    let lane = nexus
        .lane_catalog
        .lanes()
        .iter()
        .find(|lane| lane.id == lane_id)?;
    // Snapshot only the protocol-bounded authority material. Cloning the
    // full lane would duplicate arbitrary dashboard metadata on every
    // routed query even though authority resolution never reads it.
    let autoscale_validator_set = lane_claims_autoscale_managed(lane).then(|| {
        decode_autoscale_lane_committee(lane)
            .ok()
            .flatten()
            .map_or_else(Vec::new, |committee| committee.validator_set)
    });
    let manifest_authority_lanes = nexus_manifest_authority_eligible_lanes_at_height(
        lane_id,
        dataspace_id,
        nexus,
        block_height,
    );
    let staking_authority_lanes = if lane_uses_reserved_autoscale_metadata(lane) {
        matches!(
            validator_mode,
            iroha_config::parameters::actual::LaneValidatorMode::StakeElected
        )
        .then_some(BTreeSet::from([lane_id]))
        .unwrap_or_default()
    } else {
        nexus
            .lane_catalog
            .lanes()
            .iter()
            .filter(|candidate| !lane_uses_reserved_autoscale_metadata(candidate))
            .filter(|candidate| {
                nexus_active_lane_dataspace_at_height(candidate.id, nexus, block_height)
                    == Some(dataspace_id)
            })
            .filter(|candidate| {
                matches!(
                    nexus
                        .staking
                        .validator_mode(candidate.id, &nexus.lane_catalog),
                    iroha_config::parameters::actual::LaneValidatorMode::StakeElected
                )
            })
            .map(|candidate| candidate.id)
            .collect()
    };
    let staking_owner_lane = if lane_uses_reserved_autoscale_metadata(lane) {
        Some(lane_id)
    } else {
        nexus_staking_authority_lane_at_height(lane_id, nexus, block_height)
    };
    Some(ResolvedLaneAuthorityInputs {
        bounded: bounded_authority::LaneAuthorityInputs {
            dataspace_id,
            autoscale_validator_set,
            validator_mode,
            minimum_stake: nexus.staking.min_validator_stake.clone(),
            max_validators: nexus.staking.max_validators.get(),
        },
        manifest_authority_lanes,
        staking_authority_lanes,
        staking_owner_lane,
    })
}

/// Resolve the unique manifest authority source for one exact lane route.
pub(super) fn manifest_rules_for_lane<'a>(
    lane_id: LaneId,
    manifest_registry: &'a LaneManifestRegistry,
    inputs: &ResolvedLaneAuthorityInputs,
) -> Result<Option<&'a GovernanceRules>, ()> {
    manifest_registry
        .dataspace_authority_rules_for_lanes(
            lane_id,
            inputs.bounded.dataspace_id,
            &inputs.manifest_authority_lanes,
        )
        .map_err(|_| ())
}

/// Resolve one physical dataspace's live stake projection.
///
/// Lane-keyed stake rows are canonical storage projections of dataspace-wide
/// authority. Empty sibling projections are ignored, while more than one
/// non-empty projection fails closed instead of retaining duplicate state
/// that a later lane-local mutation can split. Autoscale rows stay exact-lane;
/// their immutable peer committee is resolved before this helper.
fn live_dataspace_stake_candidates(
    world: &impl WorldReadOnly,
    target_lane: LaneId,
    inputs: &ResolvedLaneAuthorityInputs,
    block_height: u64,
) -> Option<Vec<(AccountId, PeerId, Quantity)>> {
    live_stake_candidates_for_lanes(
        world,
        target_lane,
        &inputs.staking_authority_lanes,
        inputs.staking_owner_lane,
        &inputs.bounded.minimum_stake,
        inputs.bounded.max_validators,
        block_height,
    )
}

/// Resolve one canonical live stake projection across dataspace sibling lanes.
pub(super) fn live_stake_candidates_for_lanes(
    world: &impl WorldReadOnly,
    target_lane: LaneId,
    source_lanes: &BTreeSet<LaneId>,
    canonical_owner: Option<LaneId>,
    minimum_stake: &Quantity,
    configured_limit: u32,
    block_height: u64,
) -> Option<Vec<(AccountId, PeerId, Quantity)>> {
    let limit = bounded_authority::staking_validator_limit_from(configured_limit)?;
    let mut selected = Vec::with_capacity(limit);
    let mut selected_projection = None;
    for (key, record) in world.public_lane_validators().iter() {
        if !source_lanes.contains(&key.0)
            || !public_lane_validator_record_matches_key(key, record)
            || !crate::smartcontracts::isi::staking::validator_election_eligible_at_height(
                record,
                block_height,
            )
            || !crate::smartcontracts::isi::staking::meets_min_stake(
                &record.self_stake,
                minimum_stake,
            )
            .unwrap_or(false)
            || !world.peers().iter().any(|peer| peer == &record.peer_id)
            || !peer_has_live_consensus_key_for_lane(
                world,
                &record.peer_id,
                block_height,
                target_lane,
            )
        {
            continue;
        }
        if selected_projection.is_some_and(|lane| lane != key.0) {
            return None;
        }
        selected_projection = Some(key.0);
        bounded_authority::insert_unique_by(
            &mut selected,
            record,
            limit,
            |lhs, rhs| lhs.validator == rhs.validator,
            |lhs, rhs| {
                rhs.total_stake
                    .cmp(&lhs.total_stake)
                    .then_with(|| lhs.validator.cmp(&rhs.validator))
                    .then_with(|| lhs.peer_id.cmp(&rhs.peer_id))
            },
        );
    }
    if selected_projection.is_some() && selected_projection != canonical_owner {
        return None;
    }
    Some(
        selected
            .into_iter()
            .map(|record| {
                (
                    record.validator.clone(),
                    record.peer_id.clone(),
                    record.total_stake.clone(),
                )
            })
            .collect(),
    )
}

/// Project stake-ranked candidates into a unique peer pool without reordering them.
pub(super) fn ranked_stake_peer_pool(
    candidates: Vec<(AccountId, PeerId, Quantity)>,
) -> Vec<PeerId> {
    let mut peers = Vec::with_capacity(candidates.len());
    for (_, peer_id, _) in candidates {
        if !peers.contains(&peer_id) {
            peers.push(peer_id);
        }
    }
    peers
}

/// Resolve validator accounts for test-only lane authority diagnostics.
#[cfg(test)]
pub(super) fn validator_accounts_with_inputs(
    world: &impl WorldReadOnly,
    lane_id: LaneId,
    manifest_registry: &LaneManifestRegistry,
    inputs: &ResolvedLaneAuthorityInputs,
    block_height: u64,
) -> Vec<AccountId> {
    let rules = match manifest_rules_for_lane(lane_id, manifest_registry, inputs) {
        Ok(rules) => rules,
        Err(()) => return Vec::new(),
    };
    if let Some(rules) = rules {
        if !rules.validator_bindings.is_empty() {
            let bindings = bounded_authority::live_manifest_validator_bindings(
                world,
                lane_id,
                &rules.validator_bindings,
                &rules.validators,
                block_height,
            );
            return bindings
                .into_iter()
                .map(|binding| binding.validator)
                .collect();
        }
        return bounded_authority::live_manifest_validator_account_peers(
            world,
            lane_id,
            &rules.validators,
            block_height,
        )
        .into_iter()
        .map(|(validator, _)| validator)
        .collect();
    }
    if inputs.staking_authority_lanes.len() == 1
        && inputs.staking_authority_lanes.contains(&lane_id)
        && inputs.staking_owner_lane == Some(lane_id)
        && matches!(
            inputs.bounded.validator_mode,
            iroha_config::parameters::actual::LaneValidatorMode::StakeElected
        )
    {
        return bounded_authority::stake_elected_validator_accounts(
            world,
            lane_id,
            &inputs.bounded.minimum_stake,
            inputs.bounded.max_validators,
            block_height,
        );
    }
    live_dataspace_stake_candidates(world, lane_id, inputs, block_height)
        .unwrap_or_default()
        .into_iter()
        .map(|(account, _, _)| account)
        .collect()
}

/// Resolve the canonical live manifest/stake pool or immutable autoscale pin.
pub(super) fn peer_pool_with_inputs(
    world: &impl WorldReadOnly,
    lane_id: LaneId,
    manifest_registry: &LaneManifestRegistry,
    inputs: &ResolvedLaneAuthorityInputs,
    block_height: u64,
) -> Result<Vec<PeerId>, ()> {
    if let Some(validator_set) = &inputs.bounded.autoscale_validator_set {
        // An autoscale lane has one immutable committee for its full
        // incarnation. Never apply current-world peer/key/manifest or
        // topology filters here: delayed QCs from this pinned authority
        // must remain verifiable after roster churn.
        return Ok(validator_set.clone());
    }
    let rules = manifest_rules_for_lane(lane_id, manifest_registry, inputs)?;
    if let Some(rules) = rules {
        if !rules.validator_bindings.is_empty() {
            let bindings = bounded_authority::live_manifest_validator_bindings(
                world,
                lane_id,
                &rules.validator_bindings,
                &rules.validators,
                block_height,
            );
            return Ok(bindings
                .into_iter()
                .map(|binding| binding.peer_id)
                .collect());
        }
        return Ok(bounded_authority::live_manifest_validator_account_peers(
            world,
            lane_id,
            &rules.validators,
            block_height,
        )
        .into_iter()
        .map(|(_, peer)| peer)
        .collect());
    }
    if inputs.staking_authority_lanes.len() == 1
        && inputs.staking_authority_lanes.contains(&lane_id)
        && inputs.staking_owner_lane == Some(lane_id)
        && matches!(
            inputs.bounded.validator_mode,
            iroha_config::parameters::actual::LaneValidatorMode::StakeElected
        )
    {
        return Ok(bounded_authority::stake_elected_peer_ids(
            world,
            lane_id,
            &inputs.bounded.minimum_stake,
            inputs.bounded.max_validators,
            block_height,
        ));
    }
    let Some(candidates) = live_dataspace_stake_candidates(world, lane_id, inputs, block_height)
    else {
        return Err(());
    };
    Ok(ranked_stake_peer_pool(candidates))
}

/// Resolve the peers authoritative for an active route: the global committee.
///
/// Every transaction executes in the global Sumeragi block, so lanes and dataspaces are routing
/// labels. An active route binds the exact authenticated epoch committee retained for
/// `authority_height`, in canonical order, shared with QueuePlan admission. Live registrations
/// cannot replace that authority. The reported fault tolerance is the global `(n − 1) / 3`.
///
/// # Errors
/// The dataspace is unknown, the lane is inactive, or the retained authenticated schedule is
/// absent, malformed, pending its boundary, or does not cover `authority_height`.
pub(crate) fn resolve_global_route(
    world: &impl WorldReadOnly,
    route: LaneAuthorityRoute,
    nexus: &iroha_config::parameters::actual::Nexus,
    authority_height: u64,
) -> Result<LaneAuthorityCommittee, LaneAuthorityError> {
    if nexus
        .dataspace_catalog
        .by_id(route.dataspace_id())
        .is_none()
    {
        return Err(LaneAuthorityError::UnknownDataspace {
            dataspace_id: route.dataspace_id(),
        });
    }
    if consensus_lane_dataspace_at_height(route.lane_id(), nexus, authority_height)
        != Some(route.dataspace_id())
    {
        return Err(LaneAuthorityError::InactiveRoute {
            lane_id: route.lane_id(),
            dataspace_id: route.dataspace_id(),
            authority_height,
        });
    }
    if world.consensus_schedule().entries().is_empty() {
        return Err(LaneAuthorityError::UndersizedPool {
            lane_id: route.lane_id(),
            dataspace_id: route.dataspace_id(),
            authority_height,
            required: 4,
            actual: 0,
        });
    }
    let validators = crate::sumeragi::schedule::scheduled_committee(world, authority_height)
        .map_err(|_| LaneAuthorityError::InvalidAuthoritySource {
            lane_id: route.lane_id(),
            dataspace_id: route.dataspace_id(),
            authority_height,
        })?;
    let fault_tolerance = validators
        .len()
        .checked_sub(1)
        .map(|faulty| faulty / 3)
        .and_then(|faulty| u32::try_from(faulty).ok())
        .ok_or_else(|| LaneAuthorityError::UndersizedPool {
            lane_id: route.lane_id(),
            dataspace_id: route.dataspace_id(),
            authority_height,
            required: 1,
            actual: validators.len(),
        })?;
    Ok(LaneAuthorityCommittee::new(
        route,
        authority_height,
        fault_tolerance,
        validators,
    ))
}

/// Resolve an exact deterministic `3f+1` route committee from immutable state inputs.
pub(super) fn resolve_from_sources(
    world: &impl WorldReadOnly,
    network_id: &NetworkId,
    route: LaneAuthorityRoute,
    manifest_registry: &LaneManifestRegistry,
    nexus: &iroha_config::parameters::actual::Nexus,
    authority_height: u64,
) -> Result<LaneAuthorityCommittee, LaneAuthorityError> {
    let dataspace = nexus
        .dataspace_catalog
        .by_id(route.dataspace_id())
        .ok_or_else(|| LaneAuthorityError::UnknownDataspace {
            dataspace_id: route.dataspace_id(),
        })?;
    if consensus_lane_dataspace_at_height(route.lane_id(), nexus, authority_height)
        != Some(route.dataspace_id())
    {
        return Err(LaneAuthorityError::InactiveRoute {
            lane_id: route.lane_id(),
            dataspace_id: route.dataspace_id(),
            authority_height,
        });
    }
    let fault_tolerance = dataspace.fault_tolerance;
    let required = nexus_lane_committee_size(nexus, route.dataspace_id()).ok_or_else(|| {
        LaneAuthorityError::InvalidGeometry {
            dataspace_id: route.dataspace_id(),
            fault_tolerance,
        }
    })?;
    let validator_mode = nexus
        .staking
        .validator_mode(route.lane_id(), &nexus.lane_catalog);
    let inputs = inputs_from_nexus(route.lane_id(), validator_mode, nexus, authority_height)
        .filter(|inputs| inputs.bounded.dataspace_id == route.dataspace_id())
        .ok_or_else(|| LaneAuthorityError::InvalidAuthoritySource {
            lane_id: route.lane_id(),
            dataspace_id: route.dataspace_id(),
            authority_height,
        })?;
    let is_autoscale_pin = inputs.bounded.autoscale_validator_set.is_some();
    let pool = peer_pool_with_inputs(
        world,
        route.lane_id(),
        manifest_registry,
        &inputs,
        authority_height,
    )
    .map_err(|()| LaneAuthorityError::InvalidAuthoritySource {
        lane_id: route.lane_id(),
        dataspace_id: route.dataspace_id(),
        authority_height,
    })?;
    let unique_count = pool.iter().collect::<BTreeSet<_>>().len();
    if unique_count != pool.len() {
        return Err(LaneAuthorityError::InvalidAuthoritySource {
            lane_id: route.lane_id(),
            dataspace_id: route.dataspace_id(),
            authority_height,
        });
    }
    if is_autoscale_pin {
        if pool.len() != required || pool.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(LaneAuthorityError::InvalidAutoscalePin {
                lane_id: route.lane_id(),
                dataspace_id: route.dataspace_id(),
                required,
                actual: pool.len(),
            });
        }
        return Ok(LaneAuthorityCommittee::new(
            route,
            authority_height,
            fault_tolerance,
            pool,
        ));
    }
    if pool.len() < required {
        return Err(LaneAuthorityError::UndersizedPool {
            lane_id: route.lane_id(),
            dataspace_id: route.dataspace_id(),
            authority_height,
            required,
            actual: pool.len(),
        });
    }
    // An exact-size pool has no selectable alternatives: every live candidate
    // is a committee member for every possible seed. Requiring a prior pulse in
    // that case creates an impossible first-post-genesis cycle (the transaction
    // installing the first beacon session itself needs a route committee) while
    // adding no entropy or bias resistance. This is not a fallback seed: any
    // oversubscribed pool still requires a verified threshold-beacon pulse.
    let mut validators = if pool.len() == required {
        for peer in &pool {
            norito::encode_canonical(peer)
                .map_err(|_| LaneAuthorityError::CanonicalPeerEncoding)?;
        }
        pool
    } else {
        // No selection can be made before the first threshold-beacon pulse.
        // Only entirely empty stores denote pending initialization: a missing
        // singleton amid other entries or inconsistent history remains invalid.
        if world.global_beacon_latest_pulse().iter().next().is_none()
            && world.global_beacon_pulses().iter().next().is_none()
        {
            return Err(LaneAuthorityError::SelectionEntropyUnavailable {
                lane_id: route.lane_id(),
                dataspace_id: route.dataspace_id(),
                authority_height,
            });
        }
        let seed = State::lane_relay_committee_seed_from_sources(
            world,
            network_id,
            route.dataspace_id(),
            route.lane_id(),
            authority_height,
        )
        .map_err(|_| LaneAuthorityError::InvalidAuthoritySource {
            lane_id: route.lane_id(),
            dataspace_id: route.dataspace_id(),
            authority_height,
        })?;
        State::lane_relay_committee_from_pool(&pool, required, seed)
            .map_err(|_| LaneAuthorityError::CanonicalPeerEncoding)?
    };
    if validators.len() != required {
        return Err(LaneAuthorityError::UndersizedPool {
            lane_id: route.lane_id(),
            dataspace_id: route.dataspace_id(),
            authority_height,
            required,
            actual: validators.len(),
        });
    }
    validators.sort();
    Ok(LaneAuthorityCommittee::new(
        route,
        authority_height,
        fault_tolerance,
        validators,
    ))
}

#[cfg(test)]
mod global_route_tests {
    use iroha_crypto::{Algorithm, KeyPair};

    use super::*;
    use crate::{kura::Kura, query::store::LiveQueryStore, state::World};

    fn state_with_validators(seeds: &[u8]) -> std::sync::Arc<State> {
        if seeds.len() == 4 {
            let chain = crate::sumeragi::test_chain::CertifiedTestChain::start(
                crate::sumeragi::test_chain::TestChainConfig::new(World::default(), 1_000),
            )
            .expect("authenticated four-validator genesis");
            return std::sync::Arc::clone(chain.state());
        }
        let mut state = State::new(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let keys = seeds
            .iter()
            .map(|seed| KeyPair::from_seed(vec![*seed; 32], Algorithm::BlsNormal))
            .collect::<Vec<_>>();
        {
            let mut world = state.world.block();
            let mut peers = world.peers_mut_for_testing().transaction();
            for key in &keys {
                peers.push(PeerId::new(key.public_key().clone()));
            }
            peers.apply();
            world.commit();
        }
        for key in &keys {
            let pop = iroha_crypto::bls_normal_pop_prove(key.private_key()).expect("PoP");
            state
                .world
                .register_validator_pop_for_testing(key.public_key().clone(), pop);
        }
        std::sync::Arc::new(state)
    }

    #[test]
    fn an_active_route_is_served_by_the_global_committee() {
        let state = state_with_validators(&[0xD1, 0xD2, 0xD3, 0xD4]);
        let route = LaneAuthorityRoute::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL);
        let expected =
            crate::sumeragi::schedule::scheduled_committee(state.view().world(), 3).unwrap();
        assert_eq!(expected.len(), 4);
        let committee = state.resolve_route_authority_at_height(route, 3).unwrap();
        assert_eq!(committee.route(), route);
        assert_eq!(committee.authority_height(), 3);
        assert_eq!(committee.fault_tolerance(), 1);
        assert_eq!(committee.validators(), expected.as_slice());
        assert_eq!(
            state.resolve_route_authority(route).unwrap().validators(),
            expected.as_slice(),
            "the committed-height read names the same committee"
        );
    }

    #[test]
    fn unknown_inactive_or_unstaffed_routes_have_no_authority() {
        let state = state_with_validators(&[0xD5]);
        assert!(matches!(
            state.resolve_route_authority_at_height(
                LaneAuthorityRoute::new(LaneId::SINGLE, DataSpaceId::new(77)),
                3
            ),
            Err(LaneAuthorityError::UnknownDataspace { .. })
        ));
        assert!(matches!(
            state.resolve_route_authority_at_height(
                LaneAuthorityRoute::new(LaneId::new(9), DataSpaceId::UNIVERSAL),
                3
            ),
            Err(LaneAuthorityError::InactiveRoute { .. })
        ));
        assert!(
            matches!(
                state.resolve_route_authority_at_height(
                    LaneAuthorityRoute::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                    3
                ),
                Err(LaneAuthorityError::UndersizedPool { actual: 0, .. })
            ),
            "a lone live registration cannot invent authenticated voting authority"
        );
        let empty = state_with_validators(&[]);
        assert!(matches!(
            empty.resolve_route_authority_at_height(
                LaneAuthorityRoute::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                3
            ),
            Err(LaneAuthorityError::UndersizedPool { actual: 0, .. })
        ));
    }
}
