//! Actual BLS candidate-pool, exact XOR reserve and threshold-pulse source regressions.

use super::*;
use crate::{beacon::signed_pulses_fixture_for_roster_and_anchors, state::World};
use iroha_crypto::{Hash, HashOf, KeyPair};
use iroha_data_model::{
    IntoKeyValue, Registrable,
    account::{Account, AccountId},
    asset::{Asset, AssetDefinition, AssetId},
    block::{BlockHeader, consensus::SumeragiRootScope},
    consensus::{ConsensusKeyId, ConsensusKeyStatus},
    nexus::{PublicLaneStakeShare, PublicLaneValidatorStatus},
    parameter::{
        Parameter,
        system::{ConsensusMode, SumeragiNposParameters},
    },
    sumeragi::epoch::{
        ValidatorCommitteeMemberV1, ValidatorEpochAuthorizationV1, ValidatorGenerationV1,
    },
};
use iroha_model_base::metadata::Metadata;
use iroha_primitives::numeric::NumericSpec;
use std::{collections::BTreeMap, num::NonZeroU64};

fn keys(count: usize) -> Vec<KeyPair> {
    let mut keys = (1..=count)
        .map(|index| KeyPair::from_seed(vec![index as u8; 32], Algorithm::BlsNormal))
        .collect::<Vec<_>>();
    keys.sort_by(|a, b| a.public_key().cmp(b.public_key()));
    keys
}

// These source tests seed canonical ledger rows directly; they do not claim full transaction
// execution/finality. Every reserve, asset, real key and proof is independently checked by the
// same production source reader. Boundary rollback/publication is exercised by its owner tests.
fn custody_pool(count: usize) -> (World, ValidatorElectionPolicyV1, Vec<KeyPair>, AssetId) {
    let mut world = World::new();
    let keys = keys(count);
    let parameters = SumeragiNposParameters {
        min_self_bond: Quantity::from(10_u64),
        min_nomination_bond: Quantity::one(),
        epoch_length_blocks: NonZeroU64::new(10).unwrap(),
        evidence_horizon_blocks: 1,
        slashing_delay_blocks: 1,
        ..SumeragiNposParameters::default()
    };
    let policy = ValidatorElectionPolicyV1::from_npos_parameters(&parameters).unwrap();
    {
        let mut entry = world.parameters.block();
        entry
            .get_mut()
            .set_parameter(Parameter::Custom(parameters.into_custom_parameter()));
        entry.commit();
    }
    let escrow = AccountId::new(keys[0].public_key().clone());
    let asset = AssetId::new(policy.xor_asset_definition_id.clone(), escrow.clone());
    let definition = AssetDefinition::new(
        policy.xor_asset_definition_id.clone(),
        "Network XOR",
        NumericSpec::fractional(9),
        AssetBalancePolicy::Global,
        None,
    )
    .build(&escrow);
    let id = definition.id.clone();
    world.asset_definitions.insert(id, definition);
    for (index, pair) in keys.iter().enumerate() {
        let owner = AccountId::new(pair.public_key().clone());
        let (id, account) = Account::new(owner.clone()).build(&owner).into_key_value();
        world.accounts.insert(id, account);
        let peer = PeerId::new(pair.public_key().clone());
        let key = (LaneId::SINGLE, owner.clone());
        world.public_lane_validators.insert(
            key.clone(),
            PublicLaneValidatorRecord {
                lane_id: LaneId::SINGLE,
                validator: owner.clone(),
                peer_id: peer.clone(),
                stake_account: owner.clone(),
                total_stake: Quantity::from(10_u64),
                self_stake: Quantity::from(10_u64),
                metadata: Metadata::default(),
                status: PublicLaneValidatorStatus::Active,
                activation_height: 1,
                election_exit_height: None,
                deactivation_height: None,
            },
        );
        world.public_lane_stake_shares.insert(
            (LaneId::SINGLE, owner.clone(), owner.clone()),
            PublicLaneStakeShare {
                lane_id: LaneId::SINGLE,
                validator: owner.clone(),
                staker: owner,
                bonded: Quantity::from(10_u64),
                pending_unbonds: BTreeMap::new(),
                metadata: Metadata::default(),
            },
        );
        world
            .public_lane_stake_custody
            .insert(key, (asset.clone(), Quantity::from(10_u64)));
        let id = ConsensusKeyId::new(ConsensusKeyRole::Validator, format!("candidate-{index}"));
        world.consensus_keys.insert(
            id.clone(),
            ConsensusKeyRecord {
                id,
                public_key: pair.public_key().clone(),
                pop: Some(iroha_crypto::bls_normal_pop_prove(pair.private_key()).unwrap()),
                activation_height: 1,
                expiry_height: None,
                replaces: None,
                status: ConsensusKeyStatus::Active,
            },
        );
    }
    let backing = Quantity::from(count as u64 * 10);
    world
        .public_lane_stake_reserves
        .insert(asset.clone(), backing.clone());
    let (id, value) = Asset::new(asset.clone(), backing).into_key_value();
    world.assets.insert(id, value);
    (world, policy, keys, asset)
}

fn network() -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
        b"native selection source unit fixture",
    )))
}

#[test]
fn genuine_candidate_pools_choose_largest_equal_vote_committee() {
    for (pool, expected) in [(4, 4), (5, 4), (8, 7), (11, 10), (32, 31)] {
        let (world, policy, _, _) = custody_pool(pool);
        let view = world.view();
        let budget = AllocationBudget::new(1 << 20);
        let source = CheckedElectionView::new(&view, &policy, &budget).unwrap();
        let picked = source.select(network(), 1, [7; 32], 21, 30).unwrap();
        let actual = picked
            .seats()
            .map(|seat| seat.record.peer_id.clone())
            .collect::<Vec<_>>();
        assert_eq!(actual.len(), expected);
        assert!(actual.windows(2).all(|pair| pair[0] < pair[1]));
        let mut independently_ranked = view
            .public_lane_validators()
            .iter()
            .map(|(_, record)| {
                (
                    validator_seat_rank(network(), 1, 3, [7; 32], &record.peer_id).unwrap(),
                    record.peer_id.clone(),
                )
            })
            .collect::<Vec<_>>();
        independently_ranked.sort();
        let mut expected_peers = independently_ranked
            .into_iter()
            .take(expected)
            .map(|(_, peer)| peer)
            .collect::<Vec<_>>();
        expected_peers.sort();
        assert_eq!(actual, expected_peers);
        assert!(budget.reserved_bytes() > 0);
        drop(source);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn frozen_floors_and_exit_obligations_do_not_follow_mutable_configuration() {
    let (mut world, policy, keys, _) = custody_pool(5);
    let peer = PeerId::new(keys[0].public_key().clone());
    let owner = AccountId::new(peer.public_key().clone());
    let mut record = world
        .public_lane_validators
        .view()
        .get(&(LaneId::SINGLE, owner.clone()))
        .unwrap()
        .clone();
    record.election_exit_height = Some(20);
    world
        .public_lane_validators
        .insert((LaneId::SINGLE, owner), record);
    {
        let mut entry = world.parameters.block();
        let mut changed = SumeragiNposParameters::default();
        changed.min_self_bond = Quantity::from(1000_u64);
        entry
            .get_mut()
            .set_parameter(Parameter::Custom(changed.into_custom_parameter()));
        entry.commit();
    }
    let view = world.view();
    let budget = AllocationBudget::new(1 << 20);
    let source = CheckedElectionView::new(&view, &policy, &budget).unwrap();
    assert!(
        source.eligible(&peer, 21, 30).is_none(),
        "requested exit excludes a new election"
    );
    assert!(
        source.ready(&peer, 21, 30).is_some(),
        "frozen seat retains its original floor and obligations"
    );
    assert_eq!(
        source
            .select(network(), 1, [7; 32], 21, 30)
            .unwrap()
            .seats()
            .len(),
        4
    );
}

#[test]
fn source_rejects_false_backing_bad_pops_and_unfunded_reference_index() {
    let (mut world, policy, _, asset) = custody_pool(5);
    let zero = AllocationBudget::new(0);
    assert!(CheckedElectionView::new(&world.view(), &policy, &zero).is_err());
    assert_eq!(zero.reserved_bytes(), 0);
    let budget = AllocationBudget::new(1 << 20);
    let (id, value) = Asset::new(asset.clone(), Quantity::from(49_u64)).into_key_value();
    world.assets.insert(id, value);
    assert!(CheckedElectionView::new(&world.view(), &policy, &budget).is_err());
    let (id, value) = Asset::new(asset, Quantity::from(50_u64)).into_key_value();
    world.assets.insert(id, value);
    let (id, mut key) = world
        .consensus_keys
        .view()
        .iter()
        .next()
        .map(|(id, key)| (id.clone(), key.clone()))
        .unwrap();
    key.pop.as_mut().unwrap()[0] ^= 1;
    world.consensus_keys.insert(id, key);
    let view = world.view();
    let source = CheckedElectionView::new(&view, &policy, &budget).unwrap();
    assert!(
        source.select(network(), 1, [7; 32], 21, 30).is_err(),
        "corrupt proof must not silently reroll selection"
    );
}

// Explicit component source only; certified-prefix fixtures derive all five fields from history.
fn component_pulse_context(
    current: &ValidatorEpochContextV1,
) -> iroha_data_model::consensus::GlobalThresholdBeaconPulseContextV1 {
    iroha_data_model::consensus::GlobalThresholdBeaconPulseContextV1 {
        epoch: current.authorization.epoch,
        epoch_context_id: current.context_id().unwrap(),
        ..crate::beacon::pulse_context_fixture_v1()
    }
}

fn pulse_fixture() -> (World, ValidatorEpochContextV1, Vec<HashOf<BlockHeader>>) {
    let pairs = keys(4);
    let hashes = (1..=9)
        .map(|height: u64| HashOf::from_untyped_unchecked(Hash::new(height.to_le_bytes())))
        .collect::<Vec<_>>();
    let anchor = GlobalThresholdBeaconChainAnchorV1 {
        height: 8,
        block_hash: hashes[7],
    };
    let committee = pairs
        .iter()
        .map(|pair| ValidatorCommitteeMemberV1 {
            validator: PeerId::new(pair.public_key().clone()),
            proof_of_possession: iroha_crypto::bls_normal_pop_prove(pair.private_key()).unwrap(),
        })
        .collect::<Vec<_>>();
    let generation = ValidatorGenerationV1::from_committee(network(), 0, &committee);
    let authorization = ValidatorEpochAuthorizationV1::genesis(&generation, 10).unwrap();
    let current = ValidatorEpochContextV1 {
        da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
        version: 1,
        network_id: network(),
        mode: ConsensusMode::Npos,
        authorization,
        committee,
        leader_seed: [5; 32],
    };
    current.validate().unwrap();
    // This component fixture supplies an explicit pulse source binding. Native
    // prefix tests separately derive these identities from the certified parent.
    let pulse_context = component_pulse_context(&current);
    let budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
    let (record, mut pulses) = signed_pulses_fixture_for_roster_and_anchors(
        network(),
        &pairs,
        &[(anchor, pulse_context)],
        &budget,
    );
    let pulse = pulses.pop().unwrap();
    let mut world = World::new();
    world
        .global_beacon_active_session
        .insert(GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY, pulse.session_id);
    world
        .global_beacon_key_sessions
        .insert(pulse.session_id, record);
    world.global_beacon_latest_pulse.insert(
        GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY,
        validate_persisted_global_threshold_beacon_pulse_v1(&pulse).unwrap(),
    );
    world.global_beacon_pulses.insert(pulse.pulse_id, pulse);
    (world, current, hashes)
}

#[test]
fn activation_generation_identity_uses_original_pool_and_exact_ordered_bls_roster() {
    let (_, current, _) = pulse_fixture();
    let original = current.context_id().unwrap();
    let budget = AllocationBudget::new(0);
    assert!(matches!(
        super::owned::generation_id(current.network_id, 1, &current.committee, &budget),
        Err(BoundaryCaptureError::Admission(_))
    ));
    assert_eq!(budget.reserved_bytes(), 0);
    budget.set_limit_bytes(1 << 20);
    let target = ValidatorGenerationV1::from_committee(current.network_id, 1, &current.committee);
    let expected = target.generation_id().unwrap();
    assert_eq!(
        super::owned::generation_id(current.network_id, 1, &current.committee, &budget).unwrap(),
        expected
    );
    assert_eq!(
        budget.reserved_bytes(),
        0,
        "temporary roster must release every charge"
    );
    assert_ne!(expected, current.authorization.authority_id);
    assert_ne!(
        super::owned::generation_id(current.network_id, 2, &current.committee, &budget).unwrap(),
        expected
    );
    let foreign = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"foreign generation network",
    )));
    assert_ne!(
        super::owned::generation_id(foreign, 1, &current.committee, &budget).unwrap(),
        expected
    );
    for control in 0..4 {
        let mut committee = current.committee.clone();
        match control {
            0 => {
                committee.pop();
            }
            1 => committee.swap(0, 1),
            2 => committee[1] = committee[0].clone(),
            _ => {
                committee[0].validator = PeerId::new(
                    KeyPair::from_seed(vec![0xF1; 32], Algorithm::Ed25519)
                        .public_key()
                        .clone(),
                );
            }
        }
        assert!(
            matches!(
                super::owned::generation_id(current.network_id, 1, &committee, &budget),
                Err(BoundaryCaptureError::Invalid(_))
            ),
            "control {control}"
        );
        assert_eq!(
            budget.reserved_bytes(),
            0,
            "rejected roster must release every charge"
        );
    }
    assert_eq!(current.context_id().unwrap(), original);
}

#[test]
fn fresh_entropy_requires_actual_threshold_pulse_and_exact_prestate_parent() {
    let (mut world, current, hashes) = pulse_fixture();
    let verified = authenticated_boundary_entropy(&world.view(), &hashes, &current, 10).unwrap();
    assert_ne!(verified.leader_seed, verified.election_seed);
    assert_eq!(
        Some(verified.beacon.session_id),
        world.view().active_global_beacon_key_session()
    );
    assert!(authenticated_boundary_entropy(&world.view(), &hashes[..8], &current, 10).is_err());
    let mut wrong_parent = hashes.clone();
    wrong_parent[7] = HashOf::from_untyped_unchecked(Hash::new(b"another certified parent"));
    assert!(authenticated_boundary_entropy(&world.view(), &wrong_parent, &current, 10).is_err());
    let pulse = world
        .global_beacon_pulses
        .view()
        .iter()
        .next()
        .unwrap()
        .1
        .clone();
    for mutation in 0..9 {
        let mut bad = pulse.clone();
        match mutation {
            0 => bad.signature[0] ^= 1,
            1 => bad.seed[0] ^= 1,
            2 => bad.height -= 1,
            3 => bad.transcript_hash[0] ^= 1,
            4 => bad.context.instance[0] ^= 1,
            5 => bad.context.epoch += 1,
            6 => bad.context.epoch_context_id[0] ^= 1,
            7 => bad.context.parent_consensus_hash[0] ^= 1,
            _ => bad.context.parent_result[0] ^= 1,
        }
        world.global_beacon_pulses.insert(pulse.pulse_id, bad);
        assert!(
            authenticated_boundary_entropy(&world.view(), &hashes, &current, 10).is_err(),
            "mutation {mutation}"
        );
    }
    world.global_beacon_pulses.insert(pulse.pulse_id, pulse);
    assert!(authenticated_boundary_entropy(&world.view(), &hashes, &current, 10).is_ok());
}

pub(super) fn boundary_fixture(
    pool: usize,
) -> (
    World,
    ValidatorElectionPolicyV1,
    ValidatorEpochContextV1,
    Vec<HashOf<BlockHeader>>,
) {
    let (mut world, policy, _, _) = custody_pool(pool);
    let (beacon_world, current, hashes) = pulse_fixture();
    let view = beacon_world.view();
    for (id, record) in view.global_beacon_key_sessions().iter() {
        world.global_beacon_key_sessions.insert(*id, record.clone());
    }
    for (id, pulse) in view.global_beacon_pulses().iter() {
        world.global_beacon_pulses.insert(*id, *pulse);
    }
    for (id, value) in view.global_beacon_active_session().iter() {
        world.global_beacon_active_session.insert(*id, *value);
    }
    for (id, value) in view.global_beacon_latest_pulse().iter() {
        world.global_beacon_latest_pulse.insert(*id, value.clone());
    }
    use crate::sumeragi::schedule::{
        ChainParamsRecord, ConsensusSchedule, RetainedConsensusSchedule, ScheduledConfig,
        ScheduledSlot,
    };
    let params = ChainParamsRecord::from_parameters(world.view().parameters().sumeragi());
    let graph = ConsensusSchedule::from_owned_entries(vec![
        ScheduledSlot::Ready(ScheduledConfig {
            height: 9,
            epoch: current.clone(),
            params,
        }),
        ScheduledSlot::Ready(ScheduledConfig {
            height: 10,
            epoch: current.clone(),
            params,
        }),
        ScheduledSlot::PendingBoundary {
            height: 11,
            boundary_height: 10,
            predecessor_context_id: current.context_id().unwrap(),
            params,
        },
    ])
    .unwrap();
    let retained =
        RetainedConsensusSchedule::admit(&graph, &AllocationBudget::new(1 << 20)).unwrap();
    let mut cell = world.consensus_schedule.block();
    *cell.get_mut() = retained;
    cell.commit();
    (world, policy, current, hashes)
}

#[test]
fn boundary_retains_incumbent_and_freezes_real_pool_with_original_allocation_custody() {
    let (world, policy, current, hashes) = boundary_fixture(8);
    let budget = AllocationBudget::new(1 << 20);
    let captured = freeze_boundary(&world.view(), &hashes, &current, &policy, 10, &budget)
        .unwrap()
        .unwrap();
    assert_eq!(captured.current(), &current);
    assert_eq!(captured.boundary().next.generation(), current.generation());
    assert_eq!(captured.boundary().next.committee, current.committee);
    let future = captured.boundary().preparation.as_ref().unwrap();
    assert_eq!(future.committee.len(), 7);
    assert_eq!(
        future.authority_generation,
        current.authorization.authority_generation + 1
    );
    assert_eq!(
        (
            future.selection_epoch,
            future.target_epoch,
            future.first_height,
            future.last_height
        ),
        (0, 2, 21, 30)
    );
    assert_eq!(future.eligibility, policy);
    assert!(captured.retains_peer(&current.committee[0].validator));
    assert_ne!(
        captured.current().committee.as_ptr(),
        current.committee.as_ptr()
    );
    assert_ne!(
        captured.current().committee[0].proof_of_possession.as_ptr(),
        current.committee[0].proof_of_possession.as_ptr()
    );
    let retained = budget.reserved_bytes();
    assert!(retained > 0);
    drop(world);
    drop(current);
    captured
        .boundary()
        .validate_against(captured.current())
        .unwrap();
    assert_eq!(budget.reserved_bytes(), retained);
    drop(captured);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn frozen_boundary_refusal_returns_original_pool_and_does_not_need_fresh_incumbent_keys() {
    let (mut world, policy, current, hashes) = boundary_fixture(4);
    let budget = AllocationBudget::new(0);
    assert!(matches!(
        freeze_boundary(&world.view(), &hashes, &current, &policy, 10, &budget),
        Err(crate::execution_attempt::ExecutionAttemptError::Rejected(
            BoundaryCaptureError::Admission(_)
        ))
    ));
    assert_eq!(budget.reserved_bytes(), 0);
    let old = world
        .consensus_keys
        .view()
        .iter()
        .map(|(id, key)| (id.clone(), key.clone()))
        .collect::<Vec<_>>();
    for (id, mut key) in old {
        key.expiry_height = Some(10);
        world.consensus_keys.insert(id, key);
    }
    budget.set_limit_bytes(1 << 20);
    let captured = freeze_boundary(&world.view(), &hashes, &current, &policy, 10, &budget)
        .unwrap()
        .unwrap();
    assert_eq!(captured.boundary().next.generation(), current.generation());
    assert_eq!(captured.boundary().next.committee, current.committee);
    assert!(captured.boundary().preparation.is_none());
    assert_eq!(
        captured.boundary().next.authorization.decision,
        iroha_data_model::sumeragi::epoch::ValidatorEpochDecisionV1::Retain
    );
    drop(captured);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn retained_world_schedule_shares_one_original_graph_and_refunds_after_last_owner() {
    use crate::sumeragi::schedule::{
        ChainParamsRecord, ConsensusSchedule, RetainedConsensusSchedule,
    };
    let (_, current, _) = pulse_fixture();
    let params = ChainParamsRecord::from_parameters(
        &iroha_data_model::parameter::system::SumeragiParameters::default(),
    );
    let source = ConsensusSchedule::from_genesis(current, params).unwrap();
    let budget = AllocationBudget::new(1 << 20);
    let retained = RetainedConsensusSchedule::admit(&source, &budget).unwrap();
    let occupied = budget.reserved_bytes();
    assert!(occupied > 0);
    assert_eq!(
        norito::encode_canonical(&retained).unwrap(),
        norito::encode_canonical(&source).unwrap()
    );
    assert_eq!(
        norito::json::to_json(&retained).unwrap(),
        norito::json::to_json(&source).unwrap()
    );
    budget.set_limit_bytes(0);
    let cloned = retained.clone();
    assert!(std::ptr::eq(retained.canonical(), cloned.canonical()));
    assert_eq!(budget.reserved_bytes(), occupied);
    assert!(RetainedConsensusSchedule::admit(&source, &budget).is_err());
    assert_eq!(budget.reserved_bytes(), occupied);
    drop(retained);
    assert_eq!(budget.reserved_bytes(), occupied);
    drop(cloned);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn native_control_capture_verifies_transported_threshold_pulse_without_local_aggregation() {
    let (mut world, current, hashes) = pulse_fixture();
    let pulse = *world.global_beacon_pulses.view().iter().next().unwrap().1;
    {
        let mut pulses = world.global_beacon_pulses.block();
        pulses.remove(pulse.pulse_id);
        pulses.commit();
        let mut latest = world.global_beacon_latest_pulse.block();
        latest.remove(GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY);
        latest.commit();
    }
    let view = world.view();
    let captured = crate::sumeragi::epoch_beacon::capture(
        SumeragiRootScope::Global,
        &view,
        &hashes[..8],
        &current,
        9,
        Some(pulse),
        Some(component_pulse_context(&current)),
    )
    .unwrap();
    assert_eq!(captured.pulse(), Some(pulse));
    // This genuine signed global pulse cannot grant custody to a private root.
    assert!(
        crate::sumeragi::epoch_beacon::capture(
            SumeragiRootScope::Dataspace {
                parent_network_id: current.network_id,
                dataspace_id: iroha_model_base::topology::DataSpaceId::new((1_u64 << 40) + 7),
            },
            &view,
            &hashes[..8],
            &current,
            9,
            Some(pulse),
            Some(component_pulse_context(&current)),
        )
        .unwrap_err()
        .contains("private root cannot own global"),
    );
    assert_eq!(
        captured.link(),
        Some(validate_persisted_global_threshold_beacon_pulse_v1(&pulse).unwrap())
    );
    assert!(
        crate::sumeragi::epoch_beacon::capture(
            SumeragiRootScope::Global,
            &view,
            &hashes[..8],
            &current,
            9,
            None,
            Some(component_pulse_context(&current)),
        )
        .is_err()
    );
    // Presence is determined by the authenticated scheduling context, not by having a proof.
    assert!(
        crate::sumeragi::epoch_beacon::capture(
            SumeragiRootScope::Global,
            &view,
            &hashes[..7],
            &current,
            8,
            Some(pulse),
            Some(component_pulse_context(&current)),
        )
        .is_err()
    );
    assert!(
        crate::sumeragi::epoch_beacon::capture(
            SumeragiRootScope::Global,
            &view,
            &hashes[..7],
            &current,
            8,
            None,
            Some(component_pulse_context(&current)),
        )
        .unwrap()
        .pulse()
        .is_none()
    );
    for mutation in 0..5 {
        let mut changed = pulse;
        match mutation {
            0 => changed.signature[0] ^= 1,
            1 => changed.seed[0] ^= 1,
            2 => changed.transcript_hash[0] ^= 1,
            3 => changed.height -= 1,
            _ => {
                changed.finalized_chain_anchor.block_hash =
                    HashOf::from_untyped_unchecked(Hash::new(b"another predecessor"))
            }
        }
        assert!(
            crate::sumeragi::epoch_beacon::capture(
                SumeragiRootScope::Global,
                &view,
                &hashes[..8],
                &current,
                9,
                Some(changed),
                Some(component_pulse_context(&current)),
            )
            .is_err(),
            "mutation {mutation}"
        );
    }
    drop(view);
    world.global_beacon_pulses.insert(pulse.pulse_id, pulse);
    assert!(
        crate::sumeragi::epoch_beacon::capture(
            SumeragiRootScope::Global,
            &world.view(),
            &hashes[..8],
            &current,
            9,
            Some(pulse),
            Some(component_pulse_context(&current)),
        )
        .is_err()
    );
}

#[test]
fn restore_installs_exact_current_and_undo_graph_owners_without_deep_cloning() {
    if crate::unit_test_support::run_in_isolated_harness(
        "sumeragi::epoch_election::tests::restore_installs_exact_current_and_undo_graph_owners_without_deep_cloning",
    ) {
        return;
    }
    use crate::sumeragi::schedule::{
        ChainParamsRecord, ConsensusSchedule, RetainedConsensusSchedule,
    };
    let (_, epoch, _) = pulse_fixture();
    let params = ChainParamsRecord::from_parameters(
        &iroha_data_model::parameter::system::SumeragiParameters::default(),
    );
    let current_dto = ConsensusSchedule::from_genesis(epoch.clone(), params).unwrap();
    let mut prior_params = params;
    prior_params.max_block_bytes -= 1;
    let undo_dto = ConsensusSchedule::from_genesis(epoch, prior_params).unwrap();
    let budget = AllocationBudget::new(1 << 20);
    let current = RetainedConsensusSchedule::admit(&current_dto, &budget).unwrap();
    let undo = RetainedConsensusSchedule::admit(&undo_dto, &budget).unwrap();
    let current_pointer = std::ptr::from_ref(current.canonical());
    let undo_pointer = std::ptr::from_ref(undo.canonical());
    let occupied = budget.reserved_bytes();
    // This regression isolates canonical payload custody. EBR/control admission is a separate
    // prerequisite; these explicit untracked test charges do not claim to fund those owners.
    let cell = mv::cell::Cell::from_values_charged(
        current,
        Some(undo),
        mv::cell::CellAllocationCharges::new(
            concread::ebrcell::Untracked,
            concread::ebrcell::Untracked,
        ),
    );
    budget.set_limit_bytes(0);
    assert_eq!(
        std::ptr::from_ref(cell.view().get().canonical()),
        current_pointer
    );
    let reverted = cell.block_and_revert();
    assert_eq!(std::ptr::from_ref(reverted.get().canonical()), undo_pointer);
    assert_eq!(reverted.get().canonical(), &undo_dto);
    assert_eq!(budget.reserved_bytes(), occupied);
    drop(reverted);
    assert_eq!(cell.view().get().canonical(), &current_dto);
    // Dropping the Cell retires its EBR generations; their original payload
    // reservations remain live until readers release the epoch and it is collected.
    let pinned = crossbeam_epoch::pin();
    drop(cell);
    pinned.flush();
    assert_eq!(budget.reserved_bytes(), occupied);
    drop(pinned);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while budget.reserved_bytes() != 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "retired schedule graph reservations were not reclaimed"
        );
        crossbeam_epoch::pin().flush();
        std::thread::yield_now();
    }
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn prepared_boundary_readiness_requires_every_frozen_seat_custody() {
    // Source component: genuine attempt-bound beacon-share proofs and an independently
    // reconciled global XOR ledger. Certified boundary publication remains a separate gate.
    let fixture = crate::state::validator_committee::tests::fixture(7);
    let mut transition = fixture.transition;
    let (mut world, policy, pairs, asset) = custody_pool(8);
    {
        let original = fixture.world.view();
        for (id, record) in original.global_beacon_key_sessions().iter() {
            world.global_beacon_key_sessions.insert(*id, record.clone());
        }
    }
    // The frozen policy's self-bond is 1,000 XOR, while the newer selecting policy
    // admits ten. A later floor change cannot reinterpret an already frozen target.
    assert_eq!(
        transition.preparation.eligibility.min_self_bond,
        Quantity::from(1_000_u64)
    );
    for pair in &pairs {
        let owner = AccountId::new(pair.public_key().clone());
        let key = (LaneId::SINGLE, owner.clone());
        let mut validator = world
            .public_lane_validators
            .view()
            .get(&key)
            .unwrap()
            .clone();
        validator.self_stake = Quantity::from(1_000_u64);
        validator.total_stake = Quantity::from(1_000_u64);
        world.public_lane_validators.insert(key.clone(), validator);
        let share_key = (LaneId::SINGLE, owner.clone(), owner);
        let mut share = world
            .public_lane_stake_shares
            .view()
            .get(&share_key)
            .unwrap()
            .clone();
        share.bonded = Quantity::from(1_000_u64);
        world.public_lane_stake_shares.insert(share_key, share);
        world
            .public_lane_stake_custody
            .insert(key, (asset.clone(), Quantity::from(1_000_u64)));
    }
    world
        .public_lane_stake_reserves
        .insert(asset.clone(), Quantity::from(8_000_u64));
    let (id, balance) = Asset::new(asset.clone(), Quantity::from(8_000_u64)).into_key_value();
    world.assets.insert(id, balance);
    let budget = AllocationBudget::new(1 << 20);
    {
        let view = world.view();
        crate::state::validator_committee::verify_progress(&view, &transition).unwrap();
        let source = CheckedElectionView::new(&view, &policy, &budget).unwrap();
        assert!(super::plan::prepared_committee_ready(&source, &transition));
        let credentials = transition.credentials.take();
        let readiness = std::mem::take(&mut transition.readiness);
        crate::state::validator_committee::verify_progress(&view, &transition).unwrap();
        assert!(!super::plan::prepared_committee_ready(&source, &transition));
        transition.credentials = credentials;
        transition.readiness = readiness;
        let saved = transition.readiness.pop().unwrap();
        crate::state::validator_committee::verify_progress(&view, &transition).unwrap();
        assert!(
            !super::plan::prepared_committee_ready(&source, &transition),
            "even six genuine readiness proofs cannot activate seven target seats"
        );
        transition.readiness.push(saved);
    }
    assert_eq!(budget.reserved_bytes(), 0);
    // Fail each exact target seat independently while the other six remain funded.
    // The reduced ledger is still valid under today's policy and fully backed.
    for seat in &transition.preparation.committee {
        let owner = AccountId::new(seat.validator.public_key().clone());
        let key = (LaneId::SINGLE, owner.clone());
        let share_key = (LaneId::SINGLE, owner.clone(), owner);
        let original_validator = world
            .public_lane_validators
            .view()
            .get(&key)
            .unwrap()
            .clone();
        let original_share = world
            .public_lane_stake_shares
            .view()
            .get(&share_key)
            .unwrap()
            .clone();
        let mut validator = original_validator.clone();
        validator.self_stake = Quantity::from(999_u64);
        validator.total_stake = Quantity::from(999_u64);
        world.public_lane_validators.insert(key.clone(), validator);
        let mut share = original_share.clone();
        share.bonded = Quantity::from(999_u64);
        world
            .public_lane_stake_shares
            .insert(share_key.clone(), share);
        world
            .public_lane_stake_custody
            .insert(key.clone(), (asset.clone(), Quantity::from(999_u64)));
        world
            .public_lane_stake_reserves
            .insert(asset.clone(), Quantity::from(7_999_u64));
        let (id, balance) = Asset::new(asset.clone(), Quantity::from(7_999_u64)).into_key_value();
        world.assets.insert(id, balance);
        {
            let view = world.view();
            crate::state::validator_committee::verify_progress(&view, &transition).unwrap();
            let source = CheckedElectionView::new(&view, &policy, &budget).unwrap();
            assert!(
                !super::plan::prepared_committee_ready(&source, &transition),
                "one target with insufficient frozen custody must retain the incumbent"
            );
        }
        assert_eq!(budget.reserved_bytes(), 0);
        world
            .public_lane_validators
            .insert(key.clone(), original_validator);
        world
            .public_lane_stake_shares
            .insert(share_key, original_share);
        world
            .public_lane_stake_custody
            .insert(key, (asset.clone(), Quantity::from(1_000_u64)));
        world
            .public_lane_stake_reserves
            .insert(asset.clone(), Quantity::from(8_000_u64));
        let (id, balance) = Asset::new(asset.clone(), Quantity::from(8_000_u64)).into_key_value();
        world.assets.insert(id, balance);
    }
    let view = world.view();
    let source = CheckedElectionView::new(&view, &policy, &budget).unwrap();
    assert!(super::plan::prepared_committee_ready(&source, &transition));
}
