//! Generation planning, captured registration tenure and destination-progress controls.
//!
//! These exercise the rule after authenticated height-input acquisition; they do not grant
//! a test-supplied key list consensus authority or replace the schedule's own tests.

use super::*;
use crate::smartcontracts::isi::sccp::test_support::{
    authority, blank_state, header, sample_generation, sample_route,
};
use iroha_crypto::{Algorithm, KeyPair, PublicKey};
use iroha_data_model::{
    bridge::SccpNetworkV1,
    nexus::{PublicLaneValidatorRecord, PublicLaneValidatorStatus},
    parameter::system::ConsensusMode,
    sccp::{
        light_client::{
            SccpLcFreezeReasonV1, SccpLcHeadV1, SccpLcParliamentFreezeV1, SccpLcPointV1,
            SccpLightClientParamsV1, SccpLightClientV1,
        },
        registry::SccpRouteActivationV1,
    },
};
use iroha_model_base::{metadata::Metadata, peer::PeerId};
use iroha_primitives::numeric::Quantity;

fn inputs(
    height: u64,
    keys: impl AsRef<[[u8; 48]]>,
    next: Option<Vec<[u8; 48]>>,
) -> SccpHeightInputsV1 {
    SccpHeightInputsV1 {
        mode: ConsensusMode::Npos,
        height,
        epoch: 0,
        epoch_end_height: if next.is_some() { height } else { u64::MAX },
        keys: super::super::height::SccpHeightKeysV1::try_from_slice(keys.as_ref()).unwrap(),
        next_keys: next
            .map(|keys| super::super::height::SccpHeightKeysV1::try_from_slice(&keys).unwrap()),
    }
}

fn other_keys() -> Vec<[u8; 48]> {
    let mut keys = (5..=8)
        .map(|seed| {
            let pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal).unwrap();
            <[u8; 48]>::try_from(pair.public_key().try_to_bytes().unwrap().1).unwrap()
        })
        .collect::<Vec<_>>();
    keys.sort();
    keys
}

fn install(stx: &mut StateTransaction<'_, '_>, record: SccpCommitteeGenerationV1) {
    store::parameters::set(stx, Some(SccpParametersV1::taira_default()));
    store::committee_current::set(stx, record.generation);
    store::liability_clock::set(stx, record.start_lc);
    store::committee_generations::insert(stx, record.generation, record).unwrap();
}

fn snapshot(world: &impl WorldReadOnly) -> (Vec<(u64, SccpCommitteeGenerationV1)>, u64, u64) {
    (
        store::committee_generations::iter(world)
            .map(|(key, value)| (*key, value.clone()))
            .collect(),
        *store::committee_current::get(world),
        *store::liability_clock::get(world),
    )
}

#[test]
fn dropped_genesis_and_rotation_plans_publish_nothing() {
    let state = blank_state();
    let mut block = state.block(header(1));
    let mut stx = block.transaction();
    store::parameters::set(&mut stx, Some(SccpParametersV1::taira_default()));
    let keys = sample_generation(1, 1).keys;
    let before = snapshot(&*stx.world);
    let plan = plan_generation_step(&stx, &header(1), &inputs(1, keys.clone(), None), None)
        .expect("generation admission")
        .expect("genesis plan");
    assert_eq!(plan.step().generation, 1);
    assert_eq!(snapshot(&*stx.world), before);
    drop(plan);
    assert_eq!(snapshot(&*stx.world), before);
    plan_generation_step(&stx, &header(1), &inputs(1, keys, None), None)
        .expect("generation admission")
        .unwrap()
        .publish(&mut stx)
        .expect("generation publication admission");
    assert_eq!(*store::committee_current::get(&*stx.world), 1);
    assert_eq!(*store::liability_clock::get(&*stx.world), 4_000);
    assert_eq!(
        store::committee_generations::get(&*stx.world, &1),
        Some(&sample_generation(1, 1))
    );

    let before = snapshot(&*stx.world);
    let plan = plan_generation_step(
        &stx,
        &header(2),
        &inputs(2, sample_generation(1, 1).keys, Some(other_keys())),
        Some(4_000),
    )
    .expect("generation admission")
    .unwrap();
    assert_eq!(plan.step().generation, 1);
    assert_ne!(plan.step().next_committee_root, [0; 32]);
    drop(plan);
    assert_eq!(snapshot(&*stx.world), before);
}

#[test]
fn key_change_publishes_outgoing_header_and_exact_successor_atomically() {
    let state = blank_state();
    let mut block = state.block(header(4));
    let mut stx = block.transaction();
    let original = sample_generation(1, 1);
    install(&mut stx, original.clone());
    store::liability_clock::set(&mut stx, 12_345);
    let following = other_keys();
    let before = snapshot(&*stx.world);
    let plan = plan_generation_step(
        &stx,
        &header(4),
        &inputs(4, original.keys.clone(), Some(following.clone())),
        Some(12_000),
    )
    .expect("generation admission")
    .unwrap();
    assert_eq!(snapshot(&*stx.world), before);
    let step = plan.step();
    assert_eq!(step.generation, 1);
    assert_eq!(step.committee_root, original.committee_root);
    assert_eq!(
        step.next_committee_root,
        committee_root(&following).unwrap()
    );
    assert_eq!(step.successor_validity_ms, original.validity_ms);
    plan.publish(&mut stx)
        .expect("generation publication admission");
    let old = store::committee_generations::get(&*stx.world, &1).unwrap();
    let mut expected_old = original;
    expected_old.end = Some(SccpGenerationEndV1 {
        end_height: 4,
        end_timestamp_ms: 16_000,
        next_committee_root: step.next_committee_root,
        successor_validity_ms: step.successor_validity_ms,
    });
    assert_eq!(old, &expected_old);
    let next = store::committee_generations::get(&*stx.world, &2).unwrap();
    assert_eq!(next.cause, SccpGenerationCauseV1::KeyChange);
    assert_eq!(next.keys, following);
    assert_eq!(
        (next.start_height, next.start_timestamp_ms, next.start_lc),
        (5, 16_000, 12_345)
    );
    assert_eq!(next.deadline_ms, 16_000 + step.successor_validity_ms);
    assert!(next.end.is_none() && next.dest_cleared_lc.is_none());
    assert!(next.is_well_formed());
    assert_eq!(*store::committee_current::get(&*stx.world), 2);
    assert_eq!(*store::liability_clock::get(&*stx.world), 12_345);
}

#[test]
fn heartbeat_is_inclusive_keeps_keys_and_respects_parent_degraded_due_gate() {
    let state = blank_state();
    let mut block = state.block(header(4));
    let mut stx = block.transaction();
    let original = sample_generation(1, 1);
    install(&mut stx, original.clone());
    let due =
        original.start_timestamp_ms + SccpParametersV1::taira_default().committee_heartbeat_ms;
    assert!(!heartbeat_due(&*stx.world, due - 1));
    assert!(heartbeat_due(&*stx.world, due));
    store::degraded_run::set(&mut stx, 2);
    assert!(!heartbeat_due(&*stx.world, due));
    store::degraded_run::set(&mut stx, 1);
    assert!(heartbeat_due(&*stx.world, due));
    let mut h = header(4);
    h.creation_time_ms = due - 1;
    let input = inputs(4, original.keys.clone(), None);
    let early = plan_generation_step(&stx, &h, &input, Some(12_000))
        .expect("generation admission")
        .unwrap();
    assert_eq!(early.step().next_committee_root, [0; 32]);
    drop(early);
    h.creation_time_ms = due;
    let plan = plan_generation_step(&stx, &h, &input, Some(12_000))
        .expect("generation admission")
        .unwrap();
    assert_eq!(plan.step().generation, 1);
    assert_eq!(plan.step().next_committee_root, original.committee_root);
    plan.publish(&mut stx)
        .expect("generation publication admission");
    let next = store::committee_generations::get(&*stx.world, &2).unwrap();
    assert_eq!(next.cause, SccpGenerationCauseV1::Heartbeat);
    assert_eq!(next.keys, original.keys);
    assert_eq!((next.start_height, next.start_timestamp_ms), (5, due));
}

#[test]
fn resync_uses_parent_end_and_current_start_without_claiming_rotation() {
    let state = blank_state();
    let mut block = state.block(header(4));
    let mut stx = block.transaction();
    let original = sample_generation(1, 1);
    install(&mut stx, original);
    store::liability_clock::set(&mut stx, 12_345);
    let keys = other_keys();
    let input = inputs(4, keys.clone(), None);
    let before = snapshot(&*stx.world);
    assert!(
        plan_generation_step(&stx, &header(4), &input, None)
            .expect("generation admission")
            .is_none()
    );
    assert_eq!(snapshot(&*stx.world), before);
    let plan = plan_generation_step(&stx, &header(4), &input, Some(12_000))
        .expect("generation admission")
        .unwrap();
    assert_eq!(plan.step().generation, 2);
    assert_eq!(plan.step().committee_root, committee_root(&keys).unwrap());
    assert_eq!(plan.step().next_committee_root, [0; 32]);
    assert_eq!(plan.step().successor_validity_ms, 0);
    assert_eq!(snapshot(&*stx.world), before);
    plan.publish(&mut stx)
        .expect("generation publication admission");
    let end = store::committee_generations::get(&*stx.world, &1)
        .unwrap()
        .end
        .unwrap();
    assert_eq!((end.end_height, end.end_timestamp_ms), (3, 12_000));
    assert_eq!(end.next_committee_root, committee_root(&keys).unwrap());
    let next = store::committee_generations::get(&*stx.world, &2).unwrap();
    assert_eq!(next.cause, SccpGenerationCauseV1::Resync);
    assert_eq!(
        (next.start_height, next.start_timestamp_ms, next.start_lc),
        (4, 16_000, 12_345)
    );
    assert_eq!(next.keys, keys);
}

#[test]
fn resync_then_boundary_handoff_preserves_both_new_generations() {
    let state = blank_state();
    let mut block = state.block(header(4));
    let mut stx = block.transaction();
    let original = sample_generation(1, 1);
    let following = original.keys.clone();
    install(&mut stx, original);
    let keys = other_keys();
    let plan = plan_generation_step(
        &stx,
        &header(4),
        &inputs(4, keys, Some(following.clone())),
        Some(12_000),
    )
    .expect("generation admission")
    .unwrap();
    assert_eq!(plan.step().generation, 2);
    assert_eq!(
        plan.step().next_committee_root,
        committee_root(&following).unwrap()
    );
    plan.publish(&mut stx)
        .expect("generation publication admission");
    assert_eq!(*store::committee_current::get(&*stx.world), 3);
    let resync = store::committee_generations::get(&*stx.world, &2).unwrap();
    assert_eq!(resync.cause, SccpGenerationCauseV1::Resync);
    assert_eq!(resync.start_height, 4);
    assert_eq!(resync.end.unwrap().end_height, 4);
    let following = store::committee_generations::get(&*stx.world, &3).unwrap();
    assert_eq!(following.cause, SccpGenerationCauseV1::KeyChange);
    assert_eq!(following.start_height, 5);
    assert!(
        store::committee_generations::iter(&*stx.world).all(|(_, record)| record.is_well_formed())
    );
}

#[test]
fn malformed_height_keys_boundary_and_generation_overflow_never_write() {
    let state = blank_state();
    let mut block = state.block(header(4));
    let mut stx = block.transaction();
    let original = sample_generation(1, 1);
    install(&mut stx, original.clone());
    let valid = inputs(4, original.keys, None);
    let mut cases = Vec::new();
    let mut bad = valid.clone();
    bad.height = 3;
    cases.push(bad);
    let mut bad = valid.clone();
    bad.keys.swap(0, 1);
    cases.push(bad);
    let mut bad = valid.clone();
    bad.keys[1] = bad.keys[0];
    cases.push(bad);
    let mut bad = valid.clone();
    bad.keys[0] = [0; 48];
    cases.push(bad);
    let mut bad = valid.clone();
    bad.epoch_end_height = 4;
    cases.push(bad);
    let mut bad = valid.clone();
    bad.next_keys =
        Some(super::super::height::SccpHeightKeysV1::try_from_slice(&other_keys()).unwrap());
    cases.push(bad);
    let mut bad = inputs(4, valid.keys.clone(), Some(other_keys()));
    let mut shortened = bad.next_keys.as_ref().unwrap().to_vec();
    shortened.pop();
    bad.next_keys =
        Some(super::super::height::SccpHeightKeysV1::try_from_slice(&shortened).unwrap());
    cases.push(bad);
    let before = snapshot(&*stx.world);
    for bad in cases {
        assert!(
            plan_generation_step(&stx, &header(4), &bad, Some(12_000))
                .expect("generation admission")
                .is_none()
        );
        assert_eq!(snapshot(&*stx.world), before);
    }
    install(&mut stx, sample_generation(u64::MAX, 1));
    let before = snapshot(&*stx.world);
    assert!(
        plan_generation_step(
            &stx,
            &header(4),
            &inputs(4, valid.keys, Some(other_keys())),
            Some(12_000)
        )
        .expect("generation admission")
        .is_none()
    );
    assert_eq!(snapshot(&*stx.world), before);
}

fn registration(key: [u8; 48], owner_seed: u8, activation: u64) -> PublicLaneValidatorRecord {
    let validator = authority(owner_seed);
    PublicLaneValidatorRecord {
        lane_id: LaneId::SINGLE,
        peer_id: PeerId::new(PublicKey::from_bytes(Algorithm::BlsNormal, &key).unwrap()),
        stake_account: validator.clone(),
        validator,
        total_stake: Quantity::from(1_000_u64),
        self_stake: Quantity::from(1_000_u64),
        metadata: Metadata::default(),
        status: PublicLaneValidatorStatus::PendingActivation(activation),
        activation_height: activation,
        election_exit_height: None,
        deactivation_height: None,
    }
}

#[test]
fn successor_captures_next_height_tenure_not_executing_height_or_later_lookup() {
    let state = blank_state();
    let mut block = state.block(header(4));
    let mut stx = block.transaction();
    stx.nexus.staking.public_validator_mode =
        iroha_config::parameters::actual::LaneValidatorMode::StakeElected;
    assert!(stx.is_lane_active_for_authority(LaneId::SINGLE));
    assert_eq!(
        stx.staking_authority_lane(LaneId::SINGLE),
        Some(LaneId::SINGLE)
    );
    let old = sample_generation(1, 1);
    install(&mut stx, old.clone());
    let following = other_keys();
    let included = registration(following[0], 30, 5);
    let mut ended = registration(following[1], 31, 1);
    ended.status = PublicLaneValidatorStatus::Active;
    ended.deactivation_height = Some(5);
    let mut invalid = registration(following[2], 32, 5);
    invalid.status = PublicLaneValidatorStatus::PendingActivation(6);
    for record in [included.clone(), ended, invalid] {
        stx.world
            .public_lane_validators
            .insert((record.lane_id, record.validator.clone()), record);
    }
    // A row under another account key must not resolve the otherwise missing fourth key.
    let mismatched = registration(following[3], 33, 5);
    stx.world
        .public_lane_validators
        .insert((LaneId::SINGLE, authority(34)), mismatched);
    plan_generation_step(
        &stx,
        &header(4),
        &inputs(4, old.keys, Some(following)),
        Some(12_000),
    )
    .expect("generation admission")
    .unwrap()
    .publish(&mut stx)
    .expect("generation publication admission");
    let expected = vec![
        Some(SccpGenerationMemberV1 {
            lane_id: LaneId::SINGLE,
            validator: included.validator.clone(),
            activation_height: 5,
        }),
        None,
        None,
        None,
    ];
    assert_eq!(
        store::committee_generations::get(&*stx.world, &2)
            .unwrap()
            .members,
        expected
    );
    stx.world
        .public_lane_validators
        .remove((included.lane_id, included.validator));
    assert_eq!(
        store::committee_generations::get(&*stx.world, &2)
            .unwrap()
            .members,
        expected,
        "captured members cannot change with later lookup state"
    );
}

#[test]
fn duplicate_registration_never_wins_by_iteration_order() {
    let state = blank_state();
    let mut block = state.block(header(4));
    let mut stx = block.transaction();
    stx.nexus.staking.public_validator_mode =
        iroha_config::parameters::actual::LaneValidatorMode::StakeElected;
    let key = sample_generation(1, 1).keys[0];
    let first = registration(key, 40, 1);
    let second = registration(key, 41, 1);
    for record in [first.clone(), second.clone()] {
        stx.world
            .public_lane_validators
            .insert((record.lane_id, record.validator.clone()), record);
    }
    assert!(
        captured_members(&stx, &[key], 4)
            .iter()
            .all(Option::is_none)
    );
    stx.world
        .public_lane_validators
        .remove((second.lane_id, second.validator));
    let members = captured_members(&stx, &[key], 4);
    let member = members[0].expect("the unique registration is captured");
    assert_eq!(member.lane_id, first.lane_id);
    assert_eq!(member.validator, &first.validator);
    assert_eq!(member.activation_height, 1);
    assert!(members[1..].iter().all(Option::is_none));
}

#[test]
fn zero_activation_is_unresolved_without_preventing_the_authenticated_handoff() {
    let state = blank_state();
    let mut block = state.block(header(4));
    let mut stx = block.transaction();
    stx.nexus.staking.public_validator_mode =
        iroha_config::parameters::actual::LaneValidatorMode::StakeElected;
    let original = sample_generation(1, 1);
    install(&mut stx, original.clone());
    let following = other_keys();
    let mut invalid = registration(following[0], 42, 0);
    invalid.status = PublicLaneValidatorStatus::Active;
    stx.world
        .public_lane_validators
        .insert((invalid.lane_id, invalid.validator.clone()), invalid);
    assert!(
        captured_members(&stx, &[following[0]], 5)
            .iter()
            .all(Option::is_none)
    );
    plan_generation_step(
        &stx,
        &header(4),
        &inputs(4, original.keys, Some(following)),
        Some(12_000),
    )
    .expect("generation admission")
    .expect("an unresolved binding does not revoke authenticated consensus keys")
    .publish(&mut stx)
    .expect("generation publication admission");
    let successor = store::committee_generations::get(&*stx.world, &2).unwrap();
    assert_eq!(successor.members, vec![None; 4]);
    assert!(successor.is_well_formed());
    assert_eq!(*store::committee_current::get(&*stx.world), 2);
}

fn ended_generation() -> SccpCommitteeGenerationV1 {
    let mut record = sample_generation(1, 1);
    record.end = Some(SccpGenerationEndV1 {
        end_height: 2,
        end_timestamp_ms: 8_000,
        next_committee_root: record.committee_root,
        successor_validity_ms: record.validity_ms,
    });
    record
}

fn light_client(network: SccpNetworkV1, time: u64) -> SccpLightClientV1 {
    SccpLightClientV1 {
        params: SccpLightClientParamsV1::defaults_for(network).unwrap(),
        head: SccpLcHeadV1 {
            latest_set_id: 1,
            latest_finalized: SccpLcPointV1 {
                source_height: 1,
                block_hash: [1; 32],
                source_time_ms: time,
            },
            last_progress_taira_ms: 1,
        },
        frozen: None,
        state_hash: [2; 32],
    }
}

#[test]
fn destination_clearance_requires_every_nonretired_route_strictly_past_deadline() {
    let state = blank_state();
    let mut block = state.block(header(4));
    let mut stx = block.transaction();
    let record = ended_generation();
    install(&mut stx, record.clone());
    store::committee_current::set(&mut stx, 2);
    store::liability_clock::set(&mut stx, 12_345);
    let eth = SccpNetworkV1::EthereumMainnet;
    let bsc = SccpNetworkV1::BscMainnet;
    // Staged revisions participate, not just a currently active revision.
    store::routes::insert(&mut stx, eth, sample_route(eth)).unwrap();
    store::routes::insert(&mut stx, bsc, sample_route(bsc)).unwrap();
    store::light_clients::insert(&mut stx, eth, light_client(eth, record.deadline_ms + 1)).unwrap();
    clear_destination_progress(&mut stx).expect("progress admission");
    assert_eq!(
        store::committee_generations::get(&*stx.world, &1),
        Some(&record),
        "missing second client blocks clearance"
    );
    store::light_clients::insert(&mut stx, bsc, light_client(bsc, record.deadline_ms)).unwrap();
    clear_destination_progress(&mut stx).expect("progress admission");
    assert_eq!(
        store::committee_generations::get(&*stx.world, &1),
        Some(&record),
        "equality is not progress past the deadline"
    );
    let mut frozen = light_client(bsc, record.deadline_ms + 1);
    frozen.frozen = Some(SccpLcFreezeReasonV1::Parliament(SccpLcParliamentFreezeV1 {
        proposal_id: [9; 32],
    }));
    store::light_clients::insert(&mut stx, bsc, frozen).unwrap();
    clear_destination_progress(&mut stx).expect("progress admission");
    assert_eq!(
        store::committee_generations::get(&*stx.world, &1),
        Some(&record)
    );
    store::light_clients::insert(&mut stx, bsc, light_client(bsc, record.deadline_ms + 1)).unwrap();
    clear_destination_progress(&mut stx).expect("progress admission");
    let mut expected = record;
    expected.dest_cleared_lc = Some(12_345);
    assert_eq!(
        store::committee_generations::get(&*stx.world, &1),
        Some(&expected)
    );
    store::liability_clock::set(&mut stx, 16_000);
    clear_destination_progress(&mut stx).expect("progress admission");
    assert_eq!(
        store::committee_generations::get(&*stx.world, &1),
        Some(&expected),
        "clearance is captured once without extending its grace window"
    );
}

#[test]
fn retired_only_and_no_routes_clear_without_a_client_but_live_sibling_revision_blocks() {
    let state = blank_state();
    let mut block = state.block(header(4));
    let mut stx = block.transaction();
    let record = ended_generation();
    install(&mut stx, record.clone());
    store::committee_current::set(&mut stx, 2);
    clear_destination_progress(&mut stx).expect("progress admission");
    assert_eq!(
        store::committee_generations::get(&*stx.world, &1)
            .unwrap()
            .dest_cleared_lc,
        Some(record.start_lc)
    );
    store::committee_generations::insert(&mut stx, 1, record.clone()).unwrap();
    let network = SccpNetworkV1::EthereumMainnet;
    let mut route = sample_route(network);
    let mut staged = route.revisions.get(&1).unwrap().clone();
    staged.revision = 2;
    route.revisions.get_mut(&1).unwrap().activation = SccpRouteActivationV1::Retired;
    route.revisions.insert(2, staged);
    store::routes::insert(&mut stx, network, route.clone()).unwrap();
    clear_destination_progress(&mut stx).expect("progress admission");
    assert_eq!(
        store::committee_generations::get(&*stx.world, &1),
        Some(&record)
    );
    route.revisions.get_mut(&2).unwrap().activation = SccpRouteActivationV1::Retired;
    store::routes::insert(&mut stx, network, route).unwrap();
    clear_destination_progress(&mut stx).expect("progress admission");
    assert_eq!(
        store::committee_generations::get(&*stx.world, &1)
            .unwrap()
            .dest_cleared_lc,
        Some(record.start_lc)
    );
}

#[test]
fn destination_progress_visits_first_64_candidates_even_when_none_clear() {
    let state = blank_state();
    let mut block = state.block(header(4));
    let mut stx = block.transaction();
    let original = ended_generation();
    install(&mut stx, original.clone());
    store::committee_current::set(&mut stx, 66);
    for generation in 2..=65 {
        let mut record = original.clone();
        record.generation = generation;
        if generation == 65 {
            record.start_timestamp_ms = 0;
            record.start_lc = 0;
            record.deadline_ms = record.validity_ms;
            record.liable_until_lc = record.validity_ms + record.grace_ms;
        }
        store::committee_generations::insert(&mut stx, generation, record).unwrap();
    }
    let network = SccpNetworkV1::EthereumMainnet;
    store::routes::insert(&mut stx, network, sample_route(network)).unwrap();
    store::light_clients::insert(
        &mut stx,
        network,
        light_client(network, original.deadline_ms),
    )
    .unwrap();
    clear_destination_progress(&mut stx).expect("progress admission");
    assert!(
        store::committee_generations::iter(&*stx.world)
            .all(|(_, value)| value.dest_cleared_lc.is_none()),
        "the clearable 65th candidate is not visited past 64 blocked records"
    );
    store::light_clients::insert(
        &mut stx,
        network,
        light_client(network, original.deadline_ms + 1),
    )
    .unwrap();
    clear_destination_progress(&mut stx).expect("progress admission");
    for generation in 1..=65 {
        assert_eq!(
            store::committee_generations::get(&*stx.world, &generation)
                .unwrap()
                .dest_cleared_lc,
            (generation <= 64).then_some(original.start_lc)
        );
    }
    clear_destination_progress(&mut stx).expect("progress admission");
    assert_eq!(
        store::committee_generations::get(&*stx.world, &65)
            .unwrap()
            .dest_cleared_lc,
        Some(original.start_lc)
    );
}

#[test]
fn original_generation_capacity_is_not_an_inactive_plan_or_catchable_commit() {
    use crate::state::{StateStorageAdmissionError, storage_transactions::TransactionsBlockError};
    let state = blank_state();
    let mut block = state.block(header(1));
    let mut stx = block.transaction();
    store::parameters::set(&mut stx, Some(SccpParametersV1::taira_default()));
    let before = snapshot(&*stx.world);
    let budget = stx
        .world
        .sccp_committee_generations
        .allocation_budget()
        .clone();
    let old_limit = budget.limit_bytes();
    budget.set_limit_bytes(budget.reserved_bytes());
    let input = inputs(1, sample_generation(1, 1).keys, None);
    assert!(matches!(
        plan_generation_step(&stx, &header(1), &input, None),
        Err(GenerationAdmissionError::Storage(
            mv::storage::AdmittedStorageError::Allocation(_)
        ))
    ));
    assert_eq!(snapshot(&*stx.world), before);
    assert!(store::committee_generations::insert(&mut stx, 1, sample_generation(1, 1)).is_err());
    assert!(matches!(
        stx.require_storage_admission(),
        Err(StateStorageAdmissionError::SccpGeneration(_))
    ));
    budget.set_limit_bytes(old_limit);
    // Restoring capacity never clears the first refusal in this original attempt.
    stx.apply();
    assert!(matches!(
        block.commit_world_overlay_for_testing(),
        Err(TransactionsBlockError::LocalStateStorage(
            StateStorageAdmissionError::SccpGeneration(_)
        ))
    ));
    assert!(store::committee_generations::get(state.view().world(), &1).is_none());
}
