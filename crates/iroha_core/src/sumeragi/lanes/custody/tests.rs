//! Exact tenure retention across lane retirement and peer reuse.
use super::*;
use crate::state::{World, WorldBlock};
fn custody_budget() -> AllocationBudget {
    AllocationBudget::new(1024 * 1024)
}
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    account::AccountId,
    asset::{AssetDefinitionId, AssetId},
    nexus::PublicLaneValidatorStatus,
};
use iroha_model_base::{metadata::Metadata, peer::PeerId};

fn record() -> PublicLaneValidatorRecord {
    let key = KeyPair::from_seed(vec![11; 32], Algorithm::Ed25519);
    let account = AccountId::new(key.public_key().clone());
    PublicLaneValidatorRecord {
        lane_id: LaneId::SINGLE,
        validator: account.clone(),
        peer_id: PeerId::new(key.public_key().clone()),
        stake_account: account,
        total_stake: 100_u32.into(),
        self_stake: 100_u32.into(),
        metadata: Metadata::default(),
        status: PublicLaneValidatorStatus::Active,
        activation_height: 1,
        election_exit_height: None,
        deactivation_height: None,
    }
}
fn obligation(record: &PublicLaneValidatorRecord, incarnation: u8) -> SumeragiLaneCustody {
    let definition = AssetDefinitionId::derive_from_components(
        iroha_model_base::domain::DomainId::try_new("custody", "test").unwrap(),
        "xor".parse().unwrap(),
    );
    let asset = AssetId::new(definition, record.validator.clone());
    let signers = vec![SumeragiLaneSignerCustody {
        signer: 0,
        binding: SumeragiLaneStakeBinding::from_record(record, &asset).unwrap(),
    }]
    .try_into()
    .unwrap();
    SumeragiLaneCustody {
        lane: LaneId::new(1),
        incarnation: [incarnation; 32],
        instance: [incarnation + 1; 32],
        created_at: 10,
        merged: iroha_data_model::sumeragi_lanes::SumeragiLaneFrontier::default(),
        signer_count: 1,
        signers,
        evidence_horizon: 7,
        slashing_delay: 3,
        retired_at: None,
    }
}
#[test]
fn lane_obligation_never_moves_to_a_later_registration_sharing_key_and_account() {
    let original_world = World::default();
    let mut world = original_world.block();
    let mut original = record();
    world
        .sumeragi_lanes
        .get_mut()
        .custody
        .push(obligation(&original, 1));
    assert!(retains_registration(&world, &original, u64::MAX).unwrap());
    original.activation_height = 2;
    assert!(!retains_registration(&world, &original, 12).unwrap());
}
#[test]
fn every_original_incarnation_must_finish_its_delay_before_custody_releases() {
    let original_world = World::default();
    let mut world = original_world.block();
    let original = record();
    let mut first = obligation(&original, 1);
    first.retired_at = Some(20);
    world.sumeragi_lanes.get_mut().custody = vec![first, obligation(&original, 2)];
    assert!(retains_registration(&world, &original, 30).unwrap());
    world.sumeragi_lanes.get_mut().custody[1].retired_at = Some(25);
    assert!(retains_registration(&world, &original, 34).unwrap());
    assert!(!retains_registration(&world, &original, 35).unwrap());
}
#[test]
fn malformed_original_deadline_cannot_release_retained_custody() {
    let original_world = World::default();
    let mut world = original_world.block();
    let original = record();
    let mut invalid = obligation(&original, 1);
    invalid.retired_at = Some(u64::MAX);
    world.sumeragi_lanes.get_mut().custody.push(invalid);
    assert!(retains_registration(&world, &original, u64::MAX).unwrap());
}

fn parameters(world: &mut WorldBlock<'_>, horizon: u64, delay: u64) {
    use iroha_data_model::parameter::{Parameter, system::SumeragiNposParameters};
    world.parameters.get_mut().set_parameter(Parameter::Custom(
        SumeragiNposParameters {
            evidence_horizon_blocks: horizon,
            slashing_delay_blocks: delay,
            ..SumeragiNposParameters::default()
        }
        .into_custom_parameter(),
    ));
}

fn lane(original: &PublicLaneValidatorRecord) -> SumeragiLaneRecord {
    use iroha_data_model::{
        parameter::system::SumeragiParameters,
        sumeragi_lanes::{SumeragiLaneFrontier, SumeragiLaneMember},
    };
    SumeragiLaneRecord {
        lane: LaneId::new(1),
        dataspace: iroha_model_base::topology::DataSpaceId::new(0),
        incarnation: [1; 32],
        params: SumeragiParameters::default(),
        committee: vec![SumeragiLaneMember {
            peer: original.peer_id.clone(),
            pop: vec![],
        }],
        created_at: 10,
        active_from: 12,
        closing: None,
        anchor_freshness: 4,
        merged: SumeragiLaneFrontier::default(),
        merged_at: 12,
        rescued: 0,
        da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
    }
}

fn fund(world: &mut WorldBlock<'_>, original: &PublicLaneValidatorRecord) {
    let asset = AssetId::new(
        AssetDefinitionId::derive_from_components(
            iroha_model_base::domain::DomainId::try_new("custody", "test").unwrap(),
            "xor".parse().unwrap(),
        ),
        original.validator.clone(),
    );
    let key = (original.lane_id, original.validator.clone());
    world
        .public_lane_validators
        .insert(key.clone(), original.clone());
    world
        .public_lane_stake_custody
        .insert(key, (asset, 100_u32.into()));
}

#[test]
fn original_signer_binding_requires_positive_custody_and_survives_policy_member_order() {
    let original_world = World::default();
    let mut world = original_world.block();
    let original = record();
    let mut lane = lane(&original);
    let other = KeyPair::from_seed(vec![9; 32], Algorithm::Ed25519);
    lane.committee
        .push(iroha_data_model::sumeragi_lanes::SumeragiLaneMember {
            peer: PeerId::new(other.public_key().clone()),
            pop: vec![],
        });
    lane.committee.sort_by(|a, b| b.peer.cmp(&a.peer));
    assert!(
        pin_signers(&world, &Nexus::default(), &lane, true, &custody_budget())
            .unwrap()
            .as_slice()
            .is_empty()
    );
    fund(&mut world, &original);
    let bindings = pin_signers(&world, &Nexus::default(), &lane, true, &custody_budget()).unwrap();
    assert_eq!(bindings.as_slice().len(), 1);
    let expected = u32::from(
        lane.committee
            .iter()
            .any(|member| member.peer < original.peer_id),
    );
    assert_eq!(bindings.as_slice()[0].signer, expected);
    // The physical lane has no independently selected mutable staking owner: fixed
    // committee reuse of a global key alone must not manufacture financial authority.
    assert!(
        pin_signers(&world, &Nexus::default(), &lane, false, &custody_budget())
            .unwrap()
            .as_slice()
            .is_empty()
    );
    world
        .public_lane_stake_custody
        .get_mut(&(original.lane_id, original.validator.clone()))
        .unwrap()
        .1 = 0_u32.into();
    assert!(
        pin_signers(&world, &Nexus::default(), &lane, true, &custody_budget())
            .unwrap()
            .as_slice()
            .is_empty()
    );
}

#[test]
fn retirement_marks_exact_boundary_and_policy_extension_precedes_withdrawal() {
    let original_world = World::default();
    let mut world = original_world.block();
    let original = record();
    parameters(&mut world, 7, 3);
    let mut state = SumeragiLaneState::default();
    let mut lane = lane(&original);
    lane.closing = Some(15); // 15 + 4 + 1 = 20.
    state.lanes.push(lane);
    state.custody.push(obligation(&original, 1));
    prepare_retirement(&mut state, &world, 19).unwrap();
    assert_eq!(state.custody[0].retired_at, None);
    prepare_retirement(&mut state, &world, 20).unwrap();
    assert_eq!(state.custody[0].retired_at, Some(20));
    world.sumeragi_lanes.get_mut().custody = state.custody.clone();
    assert!(!retains_registration(&world, &original, 30).unwrap());
    parameters(&mut world, 8, 4);
    assert!(
        retains_registration(&world, &original, 30).unwrap(),
        "same-block extension must already retain custody"
    );
    state.lanes.clear();
    prepare_retirement(&mut state, &world, 30).unwrap();
    assert_eq!(state.custody[0].release_height().unwrap(), Some(32));
    parameters(&mut world, 1, 1);
    prepare_retirement(&mut state, &world, 31).unwrap();
    assert_eq!(
        state.custody[0].release_height().unwrap(),
        Some(32),
        "policy cannot shorten existing liability"
    );
    prepare_retirement(&mut state, &world, 32).unwrap();
    assert!(state.custody.is_empty());
}

#[test]
fn creation_pins_once_and_capacity_is_reclaimed_only_after_retirement_delay() {
    use iroha_crypto::{Hash, HashOf};
    let original_world = World::default();
    let mut world = original_world.block();
    parameters(&mut world, 7, 3);
    let original = record();
    let network = iroha_data_model::NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
        Hash::prehashed([3; 32]),
    ));
    let mut state = SumeragiLaneState {
        lanes: vec![lane(&original)],
        ..SumeragiLaneState::default()
    };
    pin_created(
        &mut state,
        &world,
        &Nexus::default(),
        &network,
        "custody-test",
        None,
        10,
        &custody_budget(),
    )
    .unwrap();
    assert_eq!(state.custody.len(), 1);
    assert!(state.custody[0].signers.as_slice().is_empty());
    assert_eq!(
        creation_capacity(&state, &world).unwrap(),
        MAX_LANE_CUSTODY_OBLIGATIONS - 1
    );
    assert!(
        pin_created(
            &mut state,
            &world,
            &Nexus::default(),
            &network,
            "custody-test",
            None,
            10,
            &custody_budget(),
        )
        .is_err()
    );
    fund(&mut world, &original);
    pin_created(
        &mut state,
        &world,
        &Nexus::default(),
        &network,
        "custody-test",
        None,
        11,
        &custody_budget(),
    )
    .unwrap();
    assert!(
        state.custody[0].signers.as_slice().is_empty(),
        "later funds cannot rewrite the creation-time forensic decision"
    );
    state.custody[0].retired_at = Some(20);
    state.lanes.clear();
    prepare_retirement(&mut state, &world, 29).unwrap();
    assert_eq!(
        creation_capacity(&state, &world).unwrap(),
        MAX_LANE_CUSTODY_OBLIGATIONS - 1
    );
    prepare_retirement(&mut state, &world, 30).unwrap();
    assert_eq!(
        creation_capacity(&state, &world).unwrap(),
        MAX_LANE_CUSTODY_OBLIGATIONS
    );
}

#[test]
fn pending_original_evidence_delays_reclamation_without_native_height_arithmetic() {
    use iroha_crypto::Hash;
    use iroha_data_model::block::consensus::{
        Evidence, EvidenceAttribution, EvidencePenaltyStatus, EvidenceRecord,
    };
    let original_world = World::default();
    let mut world = original_world.block();
    parameters(&mut world, 7, 3);
    let original = record();
    let mut row = obligation(&original, 1);
    row.retired_at = Some(20);
    let mut state = SumeragiLaneState {
        custody: vec![row.clone()],
        ..SumeragiLaneState::default()
    };
    // Predicate-only retained-table fixture. Empty bytes grant no evidence authority and
    // are never submitted to admission; this test exercises lifetime dispatch only.
    let key = Hash::new(b"original pending custody fixture");
    world.consensus_evidence.insert(
        key,
        crate::state::RetainedEvidenceRecord::from_fixture(
            EvidenceRecord {
                evidence: Evidence { native: vec![] },
                attribution: EvidenceAttribution {
                    scope: iroha_data_model::block::consensus::EvidenceScope::Root,
                    instance: row.instance,
                    height: u64::MAX,
                    epoch: 0,
                    context_id: [3; 32],
                    authority_generation: [3; 32],
                    offenders: vec![],
                    safety_violation: false,
                },
                recorded_at_height: 27,
                recorded_at_view: 0,
                recorded_at_ms: 0,
                penalty_status: EvidencePenaltyStatus::Pending,
            },
            &iroha_allocation::AllocationBudget::new(1 << 20),
        )
        .unwrap(),
    );
    world.sumeragi_lanes.get_mut().custody = state.custody.clone();
    assert!(retains_registration(&world, &original, 30).unwrap());
    prepare_retirement(&mut state, &world, 30).unwrap();
    assert_eq!(state.custody.len(), 1);
    world
        .consensus_evidence
        .get_mut(&key)
        .unwrap()
        .penalty_status = EvidencePenaltyStatus::Applied { height: 30 };
    prepare_retirement(&mut state, &world, 30).unwrap();
    assert_eq!(
        state.custody.len(),
        1,
        "terminal report retains reauthentication provenance"
    );
    assert!(
        !retains_registration(&world, &original, 30).unwrap(),
        "completed penalty permits release"
    );
    world.consensus_evidence.remove(key);
    prepare_retirement(&mut state, &world, 31).unwrap();
    assert!(state.custody.is_empty());
}

#[test]
fn retirement_keeps_the_final_same_carrier_merge_after_the_live_record_is_removed() {
    use iroha_data_model::sumeragi_lanes::SumeragiLaneFrontier;
    let original_world = World::default();
    let mut world = original_world.block();
    parameters(&mut world, 7, 3);
    let original = record();
    let mut live = lane(&original);
    live.closing = Some(15); // A=4: exact retirement at global height 20.
    let final_merge = SumeragiLaneFrontier {
        height: 900,
        block_hash: [0xA1; 32],
        result: [0xB1; 32],
    };
    live.merged = final_merge;
    live.merged_at = 20;
    let mut state = SumeragiLaneState {
        lanes: vec![live],
        custody: vec![obligation(&original, 1)],
        ..SumeragiLaneState::default()
    };
    prepare_retirement(&mut state, &world, 20).unwrap();
    assert_eq!(state.custody[0].retired_at, Some(20));
    assert_eq!(state.custody[0].merged, final_merge);
    state.lanes.clear();
    prepare_retirement(&mut state, &world, 27).unwrap();
    assert_eq!(state.custody[0].merged, final_merge);
    assert!(state.custody[0].admits_at(27).unwrap());
    assert!(state.custody[0].covers_native_subject(901).unwrap());
    assert!(!state.custody[0].covers_native_subject(902).unwrap());
}

#[test]
fn an_existing_frontier_cannot_regress_or_switch_hash_or_result_at_the_same_native_height() {
    use iroha_data_model::sumeragi_lanes::SumeragiLaneFrontier;
    let original_world = World::default();
    let mut world = original_world.block();
    parameters(&mut world, 7, 3);
    let original = record();
    let frontier = SumeragiLaneFrontier {
        height: 9,
        block_hash: [1; 32],
        result: [2; 32],
    };
    let mut row = obligation(&original, 1);
    row.merged = frontier;
    for replacement in [
        SumeragiLaneFrontier {
            height: 8,
            ..frontier
        },
        SumeragiLaneFrontier {
            block_hash: [3; 32],
            ..frontier
        },
        SumeragiLaneFrontier {
            result: [3; 32],
            ..frontier
        },
    ] {
        let mut live = lane(&original);
        live.merged = replacement;
        let mut state = SumeragiLaneState {
            lanes: vec![live],
            custody: vec![row.clone()],
            ..SumeragiLaneState::default()
        };
        assert_eq!(
            prepare_retirement(&mut state, &world, 20),
            Err(crate::execution_attempt::ExecutionAttemptError::Rejected(
                CustodyViolation::Frontier
            ))
        );
        assert_eq!(state.custody[0].merged, frontier);
    }
}

fn signer_demand(count: usize) -> usize {
    std::alloc::Layout::array::<SumeragiLaneSignerCustody>(count)
        .unwrap()
        .size()
        + SumeragiLaneCustodySigners::control_layout().size()
}

#[test]
fn original_signer_pinning_refuses_then_retries_the_same_pool_and_stake_cut() {
    let original_world = World::default();
    let mut world = original_world.block();
    let original = record();
    let lane = lane(&original);
    fund(&mut world, &original);
    let demand = signer_demand(1);
    let pool = AllocationBudget::new(demand - 1);
    let Attempt::Deferred(original_refusal) =
        pin_signers(&world, &Nexus::default(), &lane, true, &pool).unwrap_err()
    else {
        panic!("native signer resource refusal is unfinished, never a custody rejection");
    };
    let Some(iroha_allocation::AllocationRefusal::Capacity {
        requested_bytes,
        reserved_bytes,
        limit_bytes,
        release,
    }) = original_refusal.allocation_refusal()
    else {
        panic!("native shared-control refusal retains its original finite-pool owner");
    };
    assert_eq!(
        *requested_bytes,
        SumeragiLaneCustodySigners::control_layout().size()
    );
    assert_eq!(
        *reserved_bytes,
        std::mem::size_of::<SumeragiLaneSignerCustody>()
    );
    assert_eq!(*limit_bytes, demand - 1);
    let wait_pool = AllocationBudget::new(1 << 10);
    let mut registration = crate::unit_test_support::release_registration(&wait_pool);
    assert_eq!(
        registration.poll_wait(
            release,
            &mut std::task::Context::from_waker(std::task::Waker::noop())
        ),
        std::task::Poll::Ready(()),
        "partial native signer backing actually refunded after the refused control probe"
    );
    assert_eq!(pool.reserved_bytes(), 0, "partial backing refunds");
    assert_eq!(world.public_lane_validators().len(), 1);
    pool.set_limit_bytes(demand);
    let owner = pin_signers(&world, &Nexus::default(), &lane, true, &pool).unwrap();
    assert!(owner.admitted_to(&pool));
    assert_eq!(
        owner.as_slice(),
        obligation(&original, 1).signers.as_slice()
    );
    let retained = owner.clone();
    assert_eq!(retained.as_slice().as_ptr(), owner.as_slice().as_ptr());
    drop(owner);
    assert_eq!(pool.reserved_bytes(), demand);
    drop(retained);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn original_signer_state_handoff_retains_backing_and_refuses_foreign_pool() {
    let mut source = SumeragiLaneState::default();
    source.custody.push(obligation(&record(), 1));
    let original = source.custody[0].signers.as_slice().as_ptr();
    let demand = signer_demand(1);
    let pool = AllocationBudget::new(demand - 1);
    assert!(admit_state(&source, &pool).is_err());
    assert_eq!(source.custody[0].signers.as_slice().as_ptr(), original);
    assert_eq!(pool.reserved_bytes(), 0);
    pool.set_limit_bytes(demand);
    let admitted = admit_state(&source, &pool).unwrap();
    assert_eq!(admitted, source);
    assert_eq!(pool.reserved_bytes(), demand);
    let pointer = admitted.custody[0].signers.as_slice().as_ptr();
    let retained = admit_state(&admitted, &pool).unwrap();
    assert_eq!(retained.custody[0].signers.as_slice().as_ptr(), pointer);
    assert_eq!(pool.reserved_bytes(), demand);
    let foreign = AllocationBudget::new(demand);
    assert!(matches!(
        admit_state(&admitted, &foreign),
        Err(LaneStateAdmissionError::Signers(
            CustodySignersAdmissionError::ForeignBudget
        ))
    ));
    assert_eq!(foreign.reserved_bytes(), 0);
    drop(admitted);
    assert_eq!(pool.reserved_bytes(), demand);
    drop(retained);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn original_signer_world_handoff_admits_both_generations_before_replacing_either() {
    let mut current = SumeragiLaneState::default();
    current.custody.push(obligation(&record(), 1));
    let mut previous = SumeragiLaneState::default();
    previous.custody.push(obligation(&record(), 2));
    let current_ptr = current.custody[0].signers.as_slice().as_ptr();
    let previous_ptr = previous.custody[0].signers.as_slice().as_ptr();
    let mut world = World::default();
    world.sumeragi_lanes = mv::cell::Cell::from_values_charged(
        current.clone(),
        Some(previous.clone()),
        mv::cell::CellAllocationCharges::new(
            concread::ebrcell::Untracked,
            concread::ebrcell::Untracked,
        ),
    );
    let demand = signer_demand(1) * 2;
    let pool = AllocationBudget::new(demand - 1);
    assert!(admit_world_state(&mut world, &pool).is_err());
    assert_eq!(pool.reserved_bytes(), 0);
    assert_eq!(
        world.sumeragi_lanes.view().custody[0]
            .signers
            .as_slice()
            .as_ptr(),
        current_ptr
    );
    assert_eq!(
        world
            .sumeragi_lanes
            .predecessor_view()
            .get()
            .as_ref()
            .unwrap()
            .custody[0]
            .signers
            .as_slice()
            .as_ptr(),
        previous_ptr
    );
    pool.set_limit_bytes(demand);
    admit_world_state(&mut world, &pool).unwrap();
    assert_eq!(*world.sumeragi_lanes.view().get(), current);
    assert_eq!(
        *world.sumeragi_lanes.predecessor_view().get(),
        Some(previous)
    );
    assert!(
        world.sumeragi_lanes.view().custody[0]
            .signers
            .admitted_to(&pool)
    );
    assert!(
        world
            .sumeragi_lanes
            .predecessor_view()
            .get()
            .as_ref()
            .unwrap()
            .custody[0]
            .signers
            .admitted_to(&pool)
    );
    assert_eq!(pool.reserved_bytes(), demand);
    let pointer = world.sumeragi_lanes.view().custody[0]
        .signers
        .as_slice()
        .as_ptr();
    {
        // The actual World overlay copies Cell values; World itself is move-only.
        let block = world.block();
        assert_eq!(
            block.sumeragi_lanes.get().custody[0]
                .signers
                .as_slice()
                .as_ptr(),
            pointer,
        );
        assert_eq!(pool.reserved_bytes(), demand);
    }
    admit_world_state(&mut world, &pool).unwrap();
    assert_eq!(pool.reserved_bytes(), demand);
    let foreign = AllocationBudget::new(demand);
    assert!(matches!(
        admit_world_state(&mut world, &foreign),
        Err(LaneStateAdmissionError::Signers(
            CustodySignersAdmissionError::ForeignBudget
        ))
    ));
    assert_eq!(
        world.sumeragi_lanes.view().custody[0]
            .signers
            .as_slice()
            .as_ptr(),
        pointer
    );
    assert_eq!(foreign.reserved_bytes(), 0);
    // World/Cell reclamation can be deferred by EBR; immediate last-owner refunds are
    // asserted separately above on the immutable signer owner itself.
}

#[test]
fn original_signer_state_constructor_refuses_before_cloning_unfunded_world() {
    let mut world = World::default();
    world.sumeragi_lanes = mv::cell::Cell::new({
        let mut lanes = SumeragiLaneState::default();
        lanes.custody.push(obligation(&record(), 1));
        lanes
    });
    let source = world.sumeragi_lanes.view().custody[0].signers.clone();
    let pointer = source.as_slice().as_ptr();
    let pool = AllocationBudget::new(0);
    let result = crate::state::State::try_new_with_chain_and_network_id_with_default_telemetry(
        pool.clone(),
        world,
        crate::kura::Kura::blank_kura_for_testing(),
        crate::query::store::LiveQueryStore::start_test(),
        "custody-test".parse().unwrap(),
        iroha_data_model::NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::prehashed([3; 32])),
        ),
    );
    assert!(matches!(
        result,
        Err(crate::state::MergeLedgerCommitError::NativeLaneCustodyAdmission(_))
    ));
    assert_eq!(pool.reserved_bytes(), 0);
    assert_eq!(source.as_slice().as_ptr(), pointer);
}

#[test]
fn sample_state_admission_refuses_unfunded_source() {
    let source = SumeragiLaneState {
        samples: vec![iroha_data_model::sumeragi_lanes::SumeragiLaneSample {
            height: 1,
            time_ms: 10,
            transactions: 3,
            lanes: 1,
        }]
        .try_into()
        .unwrap(),
        ..SumeragiLaneState::default()
    };
    let original = iroha_allocation::AllocationBudget::new(0);
    assert!(
        admit_state(&source, &original).is_err(),
        "sample backing and its retained control require original-pool admission"
    );
    assert_eq!(original.reserved_bytes(), 0);
    assert_eq!(source.samples[0].transactions, 3);
}

#[test]
fn original_sample_state_constructor_refuses_with_typed_sample_cause() {
    use iroha_data_model::sumeragi_lanes::{LaneSamplesAdmissionError, SumeragiLaneSample};
    let mut world = World::default();
    world.sumeragi_lanes = mv::cell::Cell::new(SumeragiLaneState {
        samples: vec![SumeragiLaneSample {
            height: 1,
            time_ms: 1,
            transactions: 1,
            lanes: 1,
        }]
        .try_into()
        .unwrap(),
        ..SumeragiLaneState::default()
    });
    let source = world.sumeragi_lanes.view().samples.clone();
    let pointer = source.as_ptr();
    let pool = AllocationBudget::new(0);
    let result = crate::state::State::try_new_with_chain_and_network_id_with_default_telemetry(
        pool.clone(),
        world,
        crate::kura::Kura::blank_kura_for_testing(),
        crate::query::store::LiveQueryStore::start_test(),
        "sample-owner-test".parse().unwrap(),
        iroha_data_model::NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::prehashed([3; 32])),
        ),
    );
    assert!(matches!(
        result,
        Err(
            crate::state::MergeLedgerCommitError::NativeLaneCustodyAdmission(
                LaneStateAdmissionError::Samples(LaneSamplesAdmissionError::Admission(_))
            )
        )
    ));
    assert_eq!(pool.reserved_bytes(), 0);
    assert_eq!(
        source.as_ptr(),
        pointer,
        "borrowed test owner outlives consuming constructor refusal"
    );
}

#[test]
fn original_sample_world_handoff_admits_both_generations_before_replacing_either() {
    use iroha_data_model::sumeragi_lanes::{
        LaneSamplesAdmissionError, SumeragiLaneSample, SumeragiLaneSamples,
    };
    let make = |height| SumeragiLaneState {
        samples: vec![SumeragiLaneSample {
            height,
            time_ms: height,
            transactions: 1,
            lanes: 1,
        }]
        .try_into()
        .unwrap(),
        ..SumeragiLaneState::default()
    };
    let current = make(2);
    let previous = make(1);
    let current_pointer = current.samples.as_ptr();
    let previous_pointer = previous.samples.as_ptr();
    let mut world = World::default();
    world.sumeragi_lanes = mv::cell::Cell::from_values_charged(
        current.clone(),
        Some(previous.clone()),
        mv::cell::CellAllocationCharges::new(
            concread::ebrcell::Untracked,
            concread::ebrcell::Untracked,
        ),
    );
    let demand = 2
        * (std::mem::size_of::<SumeragiLaneSample>()
            + SumeragiLaneSamples::control_layout().size());
    let pool = AllocationBudget::new(demand - 1);
    assert!(matches!(
        admit_world_state(&mut world, &pool),
        Err(LaneStateAdmissionError::Samples(
            LaneSamplesAdmissionError::Admission(_)
        ))
    ));
    assert_eq!(
        pool.reserved_bytes(),
        0,
        "partial current owner refunds on predecessor refusal"
    );
    assert_eq!(
        world.sumeragi_lanes.view().samples.as_ptr(),
        current_pointer
    );
    assert_eq!(
        world
            .sumeragi_lanes
            .predecessor_view()
            .get()
            .as_ref()
            .unwrap()
            .samples
            .as_ptr(),
        previous_pointer
    );
    pool.set_limit_bytes(demand);
    admit_world_state(&mut world, &pool).unwrap();
    assert_eq!(*world.sumeragi_lanes.view().get(), current);
    assert_eq!(
        *world.sumeragi_lanes.predecessor_view().get(),
        Some(previous)
    );
    assert_eq!(pool.reserved_bytes(), demand);
    let retained_pointer = world.sumeragi_lanes.view().samples.as_ptr();
    pool.set_limit_bytes(0);
    admit_world_state(&mut world, &pool).unwrap();
    assert_eq!(
        world.sumeragi_lanes.view().samples.as_ptr(),
        retained_pointer
    );
    assert_eq!(pool.reserved_bytes(), demand);
    let foreign = AllocationBudget::new(demand);
    assert!(matches!(
        admit_world_state(&mut world, &foreign),
        Err(LaneStateAdmissionError::Samples(
            LaneSamplesAdmissionError::ForeignBudget
        ))
    ));
    assert_eq!(foreign.reserved_bytes(), 0);
    assert_eq!(
        world.sumeragi_lanes.view().samples.as_ptr(),
        retained_pointer
    );
}

/// Actual admission owners cross every native adapter without losing their pool observation.
#[test]
fn lane_pool_refusal_adapters_preserve_exact_original_release_and_nonwaiting_demands() {
    use iroha_allocation::{AllocationRefusal, PrepaidBufferError};
    use iroha_data_model::sumeragi_lanes::LaneSamplesAdmissionError;
    use std::task::{Context, Poll, Waker};
    let pool = AllocationBudget::new(64);
    let occupied = pool.try_reserve_bytes(64).unwrap();
    let huge =
        std::alloc::Layout::from_size_align(usize::try_from(isize::MAX).unwrap(), 1).unwrap();
    let refusals = [
        pool.try_reserve_bytes(1).unwrap_err(),
        pool.try_reserve_bytes(65).unwrap_err(),
        pool.try_reserve_layouts([huge, huge, huge]).unwrap_err(),
    ];
    assert!(matches!(refusals[0], AllocationRefusal::Capacity { .. }));
    assert!(matches!(
        refusals[1],
        AllocationRefusal::ExceedsLimit { .. }
    ));
    assert_eq!(refusals[2], AllocationRefusal::DemandOverflow);
    for original in &refusals {
        for error in [
            LaneStateAdmissionError::Signers(CustodySignersAdmissionError::Backing(
                ChargedBufferError::Admission(original.clone()),
            )),
            LaneStateAdmissionError::Signers(CustodySignersAdmissionError::ControlAdmission(
                original.clone(),
            )),
            LaneStateAdmissionError::Samples(LaneSamplesAdmissionError::Admission(
                original.clone(),
            )),
            LaneStateAdmissionError::Samples(LaneSamplesAdmissionError::Backing(
                PrepaidBufferError::Allocation(ChargedBufferError::Admission(original.clone())),
            )),
        ] {
            let Attempt::Deferred(retained) = state_admission_attempt_error(error) else {
                panic!("original native admission cannot manufacture a completed verdict");
            };
            assert_eq!(retained.reason(), ExecutionDeferral::ActiveMemoryCapacity);
            assert_eq!(retained.allocation_refusal(), Some(original));
        }
    }
    let AllocationRefusal::Capacity { release, .. } = &refusals[0] else {
        unreachable!()
    };
    let wait_pool = AllocationBudget::new(1 << 10);
    let mut registration = crate::unit_test_support::release_registration(&wait_pool);
    let mut context = Context::from_waker(Waker::noop());
    assert_eq!(registration.poll_wait(release, &mut context), Poll::Pending);
    let foreign = AllocationBudget::new(1);
    drop(foreign.try_reserve_bytes(1).unwrap());
    assert_eq!(registration.poll_wait(release, &mut context), Poll::Pending);
    assert_eq!(pool.reserved_bytes(), 64);
    drop(occupied);
    assert_eq!(
        registration.poll_wait(release, &mut context),
        Poll::Ready(())
    );
    assert_eq!(pool.reserved_bytes(), 0);
    drop(registration);
    assert_eq!(wait_pool.reserved_bytes(), 0);
}

/// Category controls use genuine prepaid-shortage errors; allocator variants are adapter
/// controls only and do not claim a forced physical-allocation or successful-admission test.
#[test]
fn lane_admission_invariants_never_masquerade_as_allocator_or_semantic_failures() {
    use iroha_allocation::{ChargedShared, PrepaidBufferError};
    use iroha_data_model::sumeragi_lanes::{LaneSamplesAdmissionError, SumeragiLaneSample};
    let pool = AllocationBudget::new(0);
    let mut empty = pool.try_reserve_bytes(0).unwrap();
    let backing_shortage = ChargedBuffer::<SumeragiLaneSample>::from_reservation(1, &mut empty)
        .err()
        .expect("original zero remainder cannot fund a native sample");
    assert!(matches!(
        backing_shortage,
        PrepaidBufferError::Reservation(_)
    ));
    assert_eq!(empty.remaining_bytes(), 0);
    let original_rows = ChargedBuffer::<SumeragiLaneSignerCustody>::new(0, &pool).unwrap();
    let (returned_rows, control_shortage) =
        ChargedShared::from_reservation(original_rows, &mut empty)
            .err()
            .expect("original zero remainder cannot fund the native control");
    assert!(returned_rows.belongs_to(&pool));
    assert!(returned_rows.as_slice().is_empty());
    assert!(matches!(
        control_shortage,
        PrepaidSharedError::Reservation(_)
    ));
    assert_eq!(empty.remaining_bytes(), 0);
    for error in [
        LaneStateAdmissionError::Signers(CustodySignersAdmissionError::ForeignBudget),
        LaneStateAdmissionError::Signers(CustodySignersAdmissionError::ControlAllocation(
            control_shortage,
        )),
        LaneStateAdmissionError::Samples(LaneSamplesAdmissionError::ForeignBudget),
        LaneStateAdmissionError::Samples(LaneSamplesAdmissionError::Backing(backing_shortage)),
        LaneStateAdmissionError::Samples(LaneSamplesAdmissionError::Control(control_shortage)),
    ] {
        let Attempt::Deferred(original) = state_admission_attempt_error(error) else {
            panic!("local native owner defect cannot become a protocol rejection");
        };
        assert_eq!(
            original.reason(),
            ExecutionDeferral::LocalInvariantViolation
        );
        assert!(original.allocation_refusal().is_none());
        let step = super::super::step::LaneStepError::from(Attempt::Deferred(original.clone()));
        assert_eq!(step, super::super::step::LaneStepError::Deferred(original));
    }
    for error in [
        LaneStateAdmissionError::Signers(CustodySignersAdmissionError::Backing(
            ChargedBufferError::Allocator {
                requested_bytes: 64,
            },
        )),
        LaneStateAdmissionError::Signers(CustodySignersAdmissionError::ControlAllocation(
            PrepaidSharedError::Allocator {
                requested_bytes: 64,
            },
        )),
        LaneStateAdmissionError::Samples(LaneSamplesAdmissionError::Backing(
            PrepaidBufferError::Allocation(ChargedBufferError::Allocator {
                requested_bytes: 64,
            }),
        )),
        LaneStateAdmissionError::Samples(LaneSamplesAdmissionError::Control(
            PrepaidSharedError::Allocator {
                requested_bytes: 64,
            },
        )),
    ] {
        let Attempt::Deferred(original) = state_admission_attempt_error(error) else {
            panic!("physical native allocation failure cannot be a semantic verdict");
        };
        assert_eq!(original.reason(), ExecutionDeferral::AllocationUnavailable);
        assert!(original.allocation_refusal().is_none());
    }
    assert_eq!(
        state_admission_attempt_error(LaneStateAdmissionError::Signers(
            CustodySignersAdmissionError::Invalid
        )),
        Attempt::Rejected(CustodyViolation::Signers)
    );
    assert_eq!(
        super::super::step::LaneStepError::from(Attempt::Rejected(CustodyViolation::Signers)),
        super::super::step::LaneStepError::Custody(CustodyViolation::Signers)
    );
    drop(returned_rows);
    drop(empty);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn original_lane_state_admission_refusal_keeps_sample_and_signer_cut() {
    use iroha_data_model::sumeragi_lanes::{SumeragiLaneSample, SumeragiLaneSamples};
    for signer_source in [true, false] {
        let mut source = SumeragiLaneState::default();
        let demand = if signer_source {
            source.custody.push(obligation(&record(), 1));
            signer_demand(1)
        } else {
            source.samples = vec![SumeragiLaneSample {
                height: 1,
                time_ms: 10,
                transactions: 3,
                lanes: 1,
            }]
            .try_into()
            .unwrap();
            std::mem::size_of::<SumeragiLaneSample>() + SumeragiLaneSamples::control_layout().size()
        };
        let original = source.clone();
        let source_pointer = if signer_source {
            source.custody[0].signers.as_slice().as_ptr().cast::<u8>()
        } else {
            source.samples.as_ptr().cast::<u8>()
        };
        let pool = AllocationBudget::new(0);
        let Attempt::Deferred(refusal) =
            state_admission_attempt_error(admit_state(&source, &pool).unwrap_err())
        else {
            panic!("actual native State source returns the exact local admission");
        };
        let Some(iroha_allocation::AllocationRefusal::ExceedsLimit {
            requested_bytes,
            limit_bytes: 0,
        }) = refusal.allocation_refusal()
        else {
            panic!(
                "a source demand exceeding the real finite ceiling cannot invent a release wait"
            );
        };
        assert_eq!(
            *requested_bytes,
            if signer_source {
                std::mem::size_of::<SumeragiLaneSignerCustody>()
            } else {
                demand
            }
        );
        assert_eq!(source, original);
        assert_eq!(pool.reserved_bytes(), 0);
        pool.set_limit_bytes(demand);
        let admitted = admit_state(&source, &pool).unwrap();
        assert_eq!(admitted, source);
        assert_eq!(pool.reserved_bytes(), demand);
        let pointer = if signer_source {
            admitted.custody[0].signers.as_slice().as_ptr().cast::<u8>()
        } else {
            admitted.samples.as_ptr().cast::<u8>()
        };
        let same = admit_state(&admitted, &pool).unwrap();
        assert_eq!(
            if signer_source {
                same.custody[0].signers.as_slice().as_ptr().cast::<u8>()
            } else {
                same.samples.as_ptr().cast::<u8>()
            },
            pointer
        );
        let foreign = AllocationBudget::new(demand);
        let Attempt::Deferred(defect) =
            state_admission_attempt_error(admit_state(&admitted, &foreign).unwrap_err())
        else {
            panic!("a foreign native pool is a local ownership defect");
        };
        assert_eq!(defect.reason(), ExecutionDeferral::LocalInvariantViolation);
        assert!(defect.allocation_refusal().is_none());
        assert_eq!(foreign.reserved_bytes(), 0);
        assert_eq!(pool.reserved_bytes(), demand);
        assert_eq!(
            if signer_source {
                source.custody[0].signers.as_slice().as_ptr().cast::<u8>()
            } else {
                source.samples.as_ptr().cast::<u8>()
            },
            source_pointer
        );
        drop(admitted);
        assert_eq!(pool.reserved_bytes(), demand);
        drop(same);
        assert_eq!(pool.reserved_bytes(), 0);
        assert_eq!(source, original);
    }
}

#[test]
fn original_signer_creation_refusal_preserves_exact_stake_cut_and_last_owner_charge() {
    use iroha_data_model::sumeragi_lanes::{SumeragiLaneAutoscale, SumeragiLaneMember};
    let original_world = World::default();
    let mut world = original_world.block();
    parameters(&mut world, 7, 3);
    let mut selected = lane(&record());
    selected.lane = LaneId::new(16);
    selected.committee.clear();
    for seed in 11..15 {
        let key = KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal);
        let mut original = record();
        original.validator = AccountId::new(key.public_key().clone());
        original.stake_account = original.validator.clone();
        original.peer_id = PeerId::new(key.public_key().clone());
        fund(&mut world, &original);
        selected.committee.push(SumeragiLaneMember {
            peer: original.peer_id,
            pop: iroha_crypto::bls_normal_pop_prove(key.private_key()).unwrap(),
        });
    }
    let mut policy = SumeragiLanePolicy::for_chain(
        iroha_data_model::parameter::system::SumeragiParameters::default(),
        iroha_sumeragi::availability::recommended_data_availability_layout(),
    );
    policy.autoscale = Some(SumeragiLaneAutoscale {
        min_lane: LaneId::new(16),
        max_lane_exclusive: LaneId::new(20),
        dataspace: iroha_model_base::topology::DataSpaceId::UNIVERSAL,
        committee_size: 4,
        per_lane_target_tps: 10,
        window: 8,
        scale_out_permille: 800,
        scale_in_permille: 200,
        cooldown: 3,
    });
    assert!(policy.validate().is_ok());
    let network = iroha_data_model::NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::prehashed([3; 32])),
    );
    let mut state = SumeragiLaneState {
        lanes: vec![selected],
        ..SumeragiLaneState::default()
    };
    let original = state.clone();
    let demand = signer_demand(4);
    let pool = AllocationBudget::new(demand - 1);
    let Attempt::Deferred(refusal) = pin_created(
        &mut state,
        &world,
        &Nexus::default(),
        &network,
        "custody-test",
        Some(&policy),
        10,
        &pool,
    )
    .unwrap_err() else {
        panic!("actual created lane keeps the native signer refusal local");
    };
    let Some(iroha_allocation::AllocationRefusal::Capacity {
        requested_bytes,
        reserved_bytes,
        limit_bytes,
        ..
    }) = refusal.allocation_refusal()
    else {
        panic!("actual created lane retains the original refused shared-control demand");
    };
    assert_eq!(
        *requested_bytes,
        SumeragiLaneCustodySigners::control_layout().size()
    );
    assert_eq!(
        *reserved_bytes,
        4 * std::mem::size_of::<SumeragiLaneSignerCustody>()
    );
    assert_eq!(*limit_bytes, demand - 1);
    assert_eq!(state, original);
    assert_eq!(pool.reserved_bytes(), 0);
    assert_eq!(world.public_lane_validators().len(), 4);
    assert!(
        world
            .public_lane_stake_custody()
            .iter()
            .all(|(_, (_, amount))| *amount == 100_u32.into())
    );
    pool.set_limit_bytes(demand);
    pin_created(
        &mut state,
        &world,
        &Nexus::default(),
        &network,
        "custody-test",
        Some(&policy),
        10,
        &pool,
    )
    .unwrap();
    assert_eq!(state.custody.len(), 1);
    assert_eq!(state.custody[0].signer_count, 4);
    assert_eq!(state.custody[0].signers.as_slice().len(), 4);
    assert!(state.custody[0].validate().is_ok());
    assert!(state.custody[0].signers.admitted_to(&pool));
    let retained = state.custody[0].signers.clone();
    let pointer = retained.as_slice().as_ptr();
    assert_eq!(state.custody[0].signers.as_slice().as_ptr(), pointer);
    assert_eq!(pool.reserved_bytes(), demand);
    drop(state);
    assert_eq!(retained.as_slice().as_ptr(), pointer);
    assert_eq!(pool.reserved_bytes(), demand);
    drop(retained);
    assert_eq!(pool.reserved_bytes(), 0);
}
