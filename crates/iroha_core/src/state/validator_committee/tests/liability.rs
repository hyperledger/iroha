//! Restored ownership and pending-stake liability follow authenticated service history.

use super::*;
use std::collections::BTreeMap;

fn liability_fixture() -> (World, AccountId, PeerId) {
    let owner = iroha_test_samples::ALICE_ID.clone();
    let peer = PeerId::new(
        KeyPair::from_seed(vec![0xC1; 32], Algorithm::BlsNormal)
            .public_key()
            .clone(),
    );
    let mut world = World::new();
    world.public_lane_validators.insert(
        (LaneId::SINGLE, owner.clone()),
        PublicLaneValidatorRecord {
            lane_id: LaneId::SINGLE,
            validator: owner.clone(),
            peer_id: peer.clone(),
            stake_account: owner.clone(),
            total_stake: Quantity::from(100u64),
            self_stake: Quantity::from(100u64),
            metadata: Metadata::default(),
            status: PublicLaneValidatorStatus::Exiting(0),
            activation_height: 1,
            election_exit_height: Some(21),
            deactivation_height: None,
        },
    );
    let request_id = Hash::new(b"restored pending stake");
    world.public_lane_stake_shares.insert(
        (LaneId::SINGLE, owner.clone(), owner.clone()),
        PublicLaneStakeShare {
            lane_id: LaneId::SINGLE,
            validator: owner.clone(),
            staker: owner.clone(),
            bonded: Quantity::from(100u64),
            pending_unbonds: BTreeMap::from([(
                request_id,
                PublicLaneUnbonding {
                    request_id,
                    amount: Quantity::from(10u64),
                    release_at_ms: 0,
                    slashable_through_height: 30,
                    liability_release_height: 33,
                },
            )]),
            metadata: Metadata::default(),
        },
    );
    (world, owner, peer)
}

#[test]
fn committee_restore_requires_unique_live_owner_with_open_tenure() {
    let (mut world, owner, peer) = liability_fixture();
    let obligations = BTreeMap::from([(peer.clone(), 30)]);
    assert!(
        validate_retained_staking_obligations(&world.view(), &obligations, &obligations).is_ok()
    );
    let key = (LaneId::SINGLE, owner);
    let original = world
        .public_lane_validators
        .view()
        .get(&key)
        .unwrap()
        .clone();
    let mut ended = original.clone();
    ended.deactivation_height = Some(21);
    world.public_lane_validators.insert(key.clone(), ended);
    assert!(
        validate_retained_staking_obligations(&world.view(), &obligations, &obligations).is_err()
    );
    world
        .public_lane_validators
        .insert(key.clone(), original.clone());
    let other = iroha_test_samples::BOB_ID.clone();
    let mut duplicate = original;
    duplicate.validator = other.clone();
    world
        .public_lane_validators
        .insert((LaneId::SINGLE, other.clone()), duplicate);
    assert!(
        validate_retained_staking_obligations(&world.view(), &obligations, &obligations).is_err()
    );
    let mut validators = world.public_lane_validators.block();
    validators.remove((LaneId::SINGLE, other));
    validators.remove(key);
    validators.commit();
    assert!(
        validate_retained_staking_obligations(&world.view(), &obligations, &obligations).is_err()
    );
}

#[test]
fn committee_restore_cannot_shorten_historical_unbond_liability() {
    let (mut world, owner, peer) = liability_fixture();
    let historical = BTreeMap::from([(peer, 30)]);
    let live = BTreeMap::new();
    let key = (LaneId::SINGLE, owner.clone(), owner);
    let original = world
        .public_lane_stake_shares
        .view()
        .get(&key)
        .unwrap()
        .clone();
    assert!(validate_retained_staking_obligations(&world.view(), &historical, &live).is_ok());
    for (service_cut, liability_cut) in [(29, 33), (30, 29)] {
        let mut shortened = original.clone();
        let pending = shortened.pending_unbonds.values_mut().next().unwrap();
        pending.slashable_through_height = service_cut;
        pending.liability_release_height = liability_cut;
        world
            .public_lane_stake_shares
            .insert(key.clone(), shortened);
        assert!(validate_retained_staking_obligations(&world.view(), &historical, &live).is_err());
    }
}

#[test]
fn committee_obligation_union_never_shortens_a_retained_seat() {
    let (_, _, peer) = liability_fixture();
    let mut obligations = BTreeMap::new();
    add_obligations(&mut obligations, [peer.clone()], 30);
    add_obligations(&mut obligations, [peer.clone()], 20);
    assert_eq!(obligations.get(&peer), Some(&30));
    add_obligations(&mut obligations, [peer.clone()], 40);
    assert_eq!(obligations.get(&peer), Some(&40));
}
