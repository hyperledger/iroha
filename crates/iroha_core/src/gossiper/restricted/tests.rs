//! Restricted dissemination uses the native incarnation and exact live participant keys.

use super::*;
use crate::{
    queue::{RoutingDecision, RoutingPlan},
    state::{World, derive_committee_key_id, derive_validator_key_id},
    sumeragi::schedule::canonical_committee,
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    consensus::{ConsensusKeyRecord, ConsensusKeyStatus},
    parameter::system::SumeragiParameters,
    sumeragi_lanes::{SumeragiLaneFrontier, SumeragiLaneMember, SumeragiLaneRecord},
};
use mv::storage::StorageReadOnly as _;
use std::collections::BTreeSet;

pub(in crate::gossiper) fn install_members(
    world: &World,
    first_seed: u8,
    participant: bool,
) -> Vec<SumeragiLaneMember> {
    let mut block = world.block();
    let mut members = BTreeMap::new();
    for seed in first_seed..first_seed + 4 {
        let key = KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal).unwrap();
        let pop = iroha_crypto::bls_normal_pop_prove(key.private_key()).unwrap();
        let id = if participant {
            derive_committee_key_id(key.public_key())
        } else {
            derive_validator_key_id(key.public_key())
        };
        block
            .consensus_keys_by_pk
            .insert(key.public_key().to_string(), vec![id.clone()]);
        block.consensus_keys.insert(
            id.clone(),
            ConsensusKeyRecord {
                id,
                public_key: key.public_key().clone(),
                pop: Some(pop.clone()),
                activation_height: 0,
                expiry_height: None,
                replaces: None,
                status: ConsensusKeyStatus::Active,
            },
        );
        members.insert(PeerId::new(key.public_key().clone()), pop);
    }
    block.commit();
    canonical_committee(members.keys().cloned())
        .unwrap()
        .into_iter()
        .map(|peer| SumeragiLaneMember {
            pop: members[&peer].clone(),
            peer,
        })
        .collect()
}

pub(in crate::gossiper) fn install_lane(
    world: &World,
    lane: u32,
    members: Vec<SumeragiLaneMember>,
) {
    let mut block = world.block();
    block.sumeragi_lanes.get_mut().upsert(SumeragiLaneRecord {
        lane: LaneId::new(lane),
        dataspace: DataSpaceId::new(9),
        incarnation: [u8::try_from(lane).expect("fixture value fits u8"); 32],
        params: SumeragiParameters::default(),
        da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
        committee: members,
        created_at: 1,
        active_from: 3,
        closing: None,
        anchor_freshness: 16,
        merged: SumeragiLaneFrontier::default(),
        merged_at: 3,
        rescued: 0,
    });
    block.commit();
}

fn route(lane: u32) -> GossipRoute {
    GossipRoute {
        lane_id: LaneId::new(lane),
        dataspace_id: DataSpaceId::new(9),
    }
}

fn peers(members: &[SumeragiLaneMember]) -> BTreeSet<PeerId> {
    members.iter().map(|member| member.peer.clone()).collect()
}

#[test]
fn disjoint_global_and_native_committees_deliver_only_to_native_members() {
    let world = World::new();
    let global = install_members(&world, 1, false);
    let native = install_members(&world, 11, true);
    install_lane(&world, 2, native.clone());
    let online = peers(&global).union(&peers(&native)).cloned().collect();
    let selected = targets(&world.view(), 5, route(2), &online, None, 42).unwrap();
    assert_eq!(
        selected.into_iter().collect::<BTreeSet<_>>(),
        peers(&native)
    );
    assert!(peers(&global).is_disjoint(&peers(&native)));
    // Global connectivity must never become an alternative delivery authority.
    assert_eq!(
        targets(&world.view(), 5, route(2), &peers(&global), None, 42),
        Err(DROP_REASON_NO_RESTRICTED_TARGETS)
    );
}

#[test]
fn fanout_caps_and_connectivity_only_narrow_the_native_committee() {
    let world = World::new();
    let members = install_members(&world, 11, true);
    install_lane(&world, 2, members.clone());
    let online: BTreeSet<_> = members
        .iter()
        .take(3)
        .map(|member| member.peer.clone())
        .collect();
    let selected = targets(
        &world.view(),
        5,
        route(2),
        &online,
        NonZeroUsize::new(2),
        42,
    )
    .unwrap();
    assert_eq!(selected.len(), 2);
    assert!(selected.iter().all(|peer| online.contains(peer)));
    assert_eq!(
        selected,
        targets(
            &world.view(),
            5,
            route(2),
            &online,
            NonZeroUsize::new(2),
            42
        )
        .unwrap()
    );
}

#[test]
fn missing_inactive_closing_or_mismatched_lane_fails_closed() {
    let world = World::new();
    let members = install_members(&world, 11, true);
    let online = peers(&members);
    assert_eq!(
        targets(&world.view(), 5, route(2), &online, None, 0),
        Err("missing_native_lane")
    );
    install_lane(&world, 2, members);
    assert_eq!(
        targets(&world.view(), 2, route(2), &online, None, 0),
        Err("inactive_native_lane")
    );
    let mut wrong_dataspace = route(2);
    wrong_dataspace.dataspace_id = DataSpaceId::new(10);
    assert_eq!(
        targets(&world.view(), 5, wrong_dataspace, &online, None, 0),
        Err("native_lane_dataspace_mismatch")
    );
    let mut block = world.block();
    block
        .sumeragi_lanes
        .get_mut()
        .lane_mut(LaneId::new(2))
        .unwrap()
        .closing = Some(5);
    block.commit();
    assert!(targets(&world.view(), 4, route(2), &online, None, 0).is_ok());
    assert_eq!(
        targets(&world.view(), 5, route(2), &online, None, 0),
        Err("inactive_native_lane")
    );
}

#[test]
fn current_incarnation_replaces_old_committee_without_sibling_union() {
    let world = World::new();
    let original = install_members(&world, 11, true);
    let replacement = install_members(&world, 21, true);
    install_lane(&world, 2, original.clone());
    install_lane(&world, 3, replacement.clone());
    let online: BTreeSet<_> = peers(&original)
        .union(&peers(&replacement))
        .cloned()
        .collect();
    assert_eq!(
        targets(&world.view(), 5, route(2), &online, None, 0)
            .unwrap()
            .into_iter()
            .collect::<BTreeSet<_>>(),
        peers(&original)
    );
    let mut block = world.block();
    let record = block
        .sumeragi_lanes
        .get_mut()
        .lane_mut(LaneId::new(2))
        .unwrap();
    record.incarnation = [42; 32];
    record.committee = replacement.clone();
    block.commit();
    assert_eq!(
        targets(&world.view(), 5, route(2), &online, None, 0)
            .unwrap()
            .into_iter()
            .collect::<BTreeSet<_>>(),
        peers(&replacement)
    );
}

#[test]
fn nonlive_wrong_role_or_different_pop_keys_cannot_receive_restricted_bodies() {
    let world = World::new();
    let members = install_members(&world, 11, true);
    install_lane(&world, 2, members.clone());
    let mut block = world.block();
    for (index, member) in members.iter().enumerate() {
        let id = derive_committee_key_id(member.peer.public_key());
        let mut record = block.consensus_keys.get(&id).unwrap().clone();
        match index {
            0 => record.expiry_height = Some(5),
            1 => record.activation_height = 6,
            2 => record.pop = Some(vec![0; 96]),
            _ => {
                block.consensus_keys.remove(id);
                continue;
            }
        }
        block.consensus_keys.insert(id, record);
    }
    block.commit();
    assert_eq!(
        targets(&world.view(), 5, route(2), &peers(&members), None, 0),
        Err(DROP_REASON_NO_RESTRICTED_TARGETS)
    );
    let mut block = world.block();
    for member in &members {
        let id = derive_committee_key_id(member.peer.public_key());
        block.consensus_keys.insert(
            id.clone(),
            ConsensusKeyRecord {
                id,
                public_key: member.peer.public_key().clone(),
                pop: Some(member.pop.clone()),
                activation_height: 0,
                expiry_height: None,
                replaces: None,
                status: ConsensusKeyStatus::Disabled,
            },
        );
    }
    block.commit();
    assert_eq!(
        targets(&world.view(), 5, route(2), &peers(&members), None, 0),
        Err(DROP_REASON_NO_RESTRICTED_TARGETS)
    );
    let validators = install_members(&world, 31, false);
    install_lane(&world, 2, validators.clone());
    assert_eq!(
        targets(&world.view(), 5, route(2), &peers(&validators), None, 0),
        Err(DROP_REASON_NO_RESTRICTED_TARGETS)
    );
}

#[test]
fn invalid_committee_cannot_define_restricted_recipients() {
    let world = World::new();
    let mut members = install_members(&world, 11, true);
    members[3] = members[0].clone();
    install_lane(&world, 2, members.clone());
    assert_eq!(
        targets(&world.view(), 5, route(2), &peers(&members), None, 0),
        Err("invalid_native_lane_committee")
    );
}

#[test]
fn sibling_lanes_in_one_dataspace_never_share_a_payload_batch() {
    let mut entries = Vec::new();
    for lane in [2, 3, 2] {
        let (signed, tx) = super::super::tests::build_transaction(&format!("lane-{lane}"));
        let routing = RoutingDecision::new(LaneId::new(lane), DataSpaceId::new(9));
        entries.push(GossipBatchEntry {
            payload: super::super::tests::payload_for(&signed),
            tx,
            routing,
            routing_plan: RoutingPlan::single(routing),
        });
    }
    let grouped = group_by_route(entries);
    assert_eq!(grouped.len(), 2);
    assert_eq!(grouped[&(DataSpaceId::new(9), LaneId::new(2))].len(), 2);
    for ((dataspace, lane), entries) in grouped {
        let batch = super::super::partition_gossip_batch(
            10,
            usize::MAX,
            super::super::GossipPlane::Restricted,
            entries,
        );
        assert!(!batch.message.txs.is_empty());
        assert!(
            batch
                .message
                .routes
                .iter()
                .all(|route| route.lane_id == lane && route.dataspace_id == dataspace)
        );
    }
}

#[test]
fn restricted_receiver_must_be_a_live_member_of_the_current_incarnation() {
    let mut gossiper =
        super::super::tests::closed_test_gossiper(std::num::NonZeroU32::new(1).unwrap());
    let native = install_members(&gossiper.state.world, 11, true);
    let unrelated = install_members(&gossiper.state.world, 31, false);
    install_lane(&gossiper.state.world, 2, native.clone());
    let mut block = gossiper.state.world.block();
    block
        .sumeragi_lanes
        .get_mut()
        .lane_mut(LaneId::new(2))
        .unwrap()
        .active_from = 0;
    block.commit();
    gossiper.self_peer_id = native[0].peer.clone();
    assert_eq!(gossiper.validate_restricted_recipient(route(2)), Ok(()));
    gossiper.self_peer_id = unrelated[0].peer.clone();
    assert_eq!(
        gossiper.validate_restricted_recipient(route(2)),
        Err("not_native_lane_member")
    );
}
