//! Regression coverage for signed private-root startup geometry and unchanged global admission.

use std::num::NonZeroU32;

use iroha_config::parameters::actual::{LaneRoutingMatcher, LaneRoutingRule};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    NetworkId,
    nexus::{
        DataSpaceCatalog, DataSpaceMetadata, LaneCatalog, LaneCatalogError, LaneConfig as Lane,
    },
};
use iroha_model_base::topology::DataSpaceId;

use super::*;

fn scope(dataspace_id: DataSpaceId) -> SumeragiRootScope {
    SumeragiRootScope::Dataspace {
        parent_network_id: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"private startup topology parent",
        ))),
        dataspace_id,
    }
}

fn fixture() -> (Nexus, SumeragiRootScope) {
    let id = DataSpaceId::new(u64::MAX);
    let mut nexus = Nexus::default();
    nexus.dataspace_catalog = DataSpaceCatalog::new(vec![DataSpaceMetadata {
        id,
        alias: "private".to_owned(),
        ..DataSpaceMetadata::default()
    }])
    .unwrap();
    nexus.configured_dataspace_catalog = nexus.dataspace_catalog.clone();
    set_lanes(
        &mut nexus,
        1,
        vec![Lane {
            dataspace_id: id,
            visibility: LaneVisibility::Restricted,
            ..Lane::default()
        }],
    );
    nexus.routing_policy.default_dataspace = id;
    (nexus, scope(id))
}

fn set_lanes(nexus: &mut Nexus, count: u32, lanes: Vec<Lane>) {
    nexus.lane_catalog = LaneCatalog::new(NonZeroU32::new(count).unwrap(), lanes).unwrap();
    nexus.configured_lane_catalog = nexus.lane_catalog.clone();
    nexus.lane_config = LaneConfig::from_catalog(&nexus.lane_catalog);
}

#[test]
fn signed_permissioned_private_root_accepts_exact_full_width_scope() {
    let (mut nexus, scope) = fixture();
    assert!(nexus.uses_multilane_catalogs());
    validate(&nexus, ConsensusMode::Permissioned, scope).unwrap();
    nexus.routing_policy.rules.push(LaneRoutingRule {
        lane: LaneId::SINGLE,
        dataspace: Some(scope.dataspace_id()),
        matcher: LaneRoutingMatcher::default(),
    });
    validate(&nexus, ConsensusMode::Permissioned, scope).unwrap();
}

#[test]
fn global_custom_topology_still_requires_signed_npos_mode() {
    validate(
        &Nexus::default(),
        ConsensusMode::Permissioned,
        SumeragiRootScope::Global,
    )
    .unwrap();
    let (nexus, _) = fixture();
    assert!(
        validate(
            &nexus,
            ConsensusMode::Permissioned,
            SumeragiRootScope::Global
        )
        .is_err()
    );
    validate(&nexus, ConsensusMode::Npos, SumeragiRootScope::Global).unwrap();
}

#[test]
fn private_root_rejects_unsupported_signed_npos_mode() {
    let (nexus, scope) = fixture();
    assert!(validate(&nexus, ConsensusMode::Npos, scope).is_err());
}

#[test]
fn private_scope_rejects_universal_or_other_catalog_identity() {
    let (nexus, _) = fixture();
    for id in [DataSpaceId::UNIVERSAL, DataSpaceId::new(17)] {
        assert!(validate(&nexus, ConsensusMode::Permissioned, scope(id)).is_err());
    }
    let (mut nexus, scope) = fixture();
    let mut entries = nexus.dataspace_catalog.entries().to_vec();
    entries.push(DataSpaceMetadata::default());
    nexus.dataspace_catalog = DataSpaceCatalog::new(entries).unwrap();
    nexus.configured_dataspace_catalog = nexus.dataspace_catalog.clone();
    assert!(validate(&nexus, ConsensusMode::Permissioned, scope).is_err());
}

#[test]
fn private_root_rejects_multilane_or_foreign_lane_geometry() {
    let (nexus, scope) = fixture();
    // The catalog itself rejects a restricted universal lane. Keep that exact
    // refusal, then use a valid foreign dataspace to reach startup validation.
    let mut universal = nexus.lane_catalog.lanes()[0].clone();
    universal.dataspace_id = DataSpaceId::UNIVERSAL;
    assert!(matches!(
        LaneCatalog::new(NonZeroU32::new(1).unwrap(), vec![universal]),
        Err(LaneCatalogError::RestrictedUniversalLane(LaneId::SINGLE))
    ));
    for variant in 0..6 {
        let mut candidate = nexus.clone();
        let mut lane = candidate.lane_catalog.lanes()[0].clone();
        let mut count = 1;
        match variant {
            0 => lane.dataspace_id = DataSpaceId::new(17),
            1 => lane.visibility = LaneVisibility::Public,
            2 => lane.storage = LaneStorageProfile::CommitmentOnly,
            3 => count = 2,
            4 => {
                lane.id = LaneId::new(1);
                count = 2;
            }
            5 => {
                set_lanes(
                    &mut candidate,
                    2,
                    vec![
                        lane.clone(),
                        Lane {
                            id: LaneId::new(1),
                            alias: "second".to_owned(),
                            ..lane
                        },
                    ],
                );
                assert!(validate(&candidate, ConsensusMode::Permissioned, scope).is_err());
                continue;
            }
            _ => unreachable!(),
        }
        set_lanes(&mut candidate, count, vec![lane]);
        assert!(
            validate(&candidate, ConsensusMode::Permissioned, scope).is_err(),
            "variant {variant}"
        );
    }
}

#[test]
fn private_root_rejects_foreign_routes_and_rebound_catalogs() {
    let (nexus, scope) = fixture();
    for variant in 0..6 {
        let mut candidate = nexus.clone();
        match variant {
            0 => candidate.routing_policy.default_dataspace = DataSpaceId::UNIVERSAL,
            1 => candidate.routing_policy.default_lane = LaneId::new(1),
            2 => candidate.routing_policy.rules.push(LaneRoutingRule {
                lane: LaneId::SINGLE,
                dataspace: Some(DataSpaceId::UNIVERSAL),
                matcher: LaneRoutingMatcher::default(),
            }),
            3 => candidate.configured_lane_catalog = LaneCatalog::default(),
            4 => candidate.configured_dataspace_catalog = DataSpaceCatalog::default(),
            5 => candidate.lane_config = LaneConfig::default(),
            _ => unreachable!(),
        }
        assert!(
            validate(&candidate, ConsensusMode::Permissioned, scope).is_err(),
            "variant {variant}"
        );
    }
}

#[test]
fn private_root_rejects_autoscale_state_including_malformed_markers() {
    let (nexus, scope) = fixture();
    let mut candidate = nexus.clone();
    candidate.autoscale.enabled = true;
    assert!(validate(&candidate, ConsensusMode::Permissioned, scope).is_err());
    candidate = nexus.clone();
    candidate.autoscale.last_transition_height = 1;
    assert!(validate(&candidate, ConsensusMode::Permissioned, scope).is_err());
    for marker in [
        AUTOSCALE_META_MANAGED,
        AUTOSCALE_META_CREATED_HEIGHT,
        AUTOSCALE_META_DRAIN_STATE,
        AUTOSCALE_META_COMMITTEE,
    ] {
        let mut candidate = nexus.clone();
        let mut lane = candidate.lane_catalog.lanes()[0].clone();
        lane.metadata.insert(marker.to_owned(), "false".to_owned());
        set_lanes(&mut candidate, 1, vec![lane]);
        assert!(
            validate(&candidate, ConsensusMode::Permissioned, scope).is_err(),
            "marker {marker}"
        );
    }
}
