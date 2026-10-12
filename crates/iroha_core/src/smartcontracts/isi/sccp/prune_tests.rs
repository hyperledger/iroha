//! Native L5 source facts, original owner admission and transaction refusal controls.

use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World},
};
use iroha_allocation::AllocationRefusal;
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    account::AccountId,
    block::BlockHeader,
    bridge::SccpNetworkV1,
    sccp::{
        committee::{SccpCommitteeGenerationV1, SccpGenerationCauseV1, SccpGenerationEndV1},
        deployment::{SccpDeploymentV1, SccpEvmDeploymentV1},
        light_client::{SccpLcHeadV1, SccpLcPointV1, SccpLightClientParamsV1, SccpLightClientV1},
        params::SccpParametersV1,
        registry::{SccpRouteRevisionV1, SccpRouteV1},
    },
    sumeragi_finality::certified_result::committee_root,
};
use std::num::NonZeroU64;

fn state() -> State {
    State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    )
}

fn header() -> BlockHeader {
    BlockHeader::new(NonZeroU64::new(100).unwrap(), None, None, 4_000, 0)
}

fn generation(id: u64) -> SccpCommitteeGenerationV1 {
    let parameters = SccpParametersV1::taira_default();
    let mut keys: Vec<[u8; 48]> = (1..=4)
        .map(|seed| {
            let key = KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal);
            key.public_key()
                .try_to_bytes()
                .unwrap()
                .1
                .try_into()
                .unwrap()
        })
        .collect();
    keys.sort();
    let value = SccpCommitteeGenerationV1 {
        generation: id,
        committee_root: committee_root(&keys).unwrap(),
        keys,
        members: vec![None; 4],
        cause: if id == 1 {
            SccpGenerationCauseV1::Genesis
        } else {
            SccpGenerationCauseV1::Heartbeat
        },
        start_height: id,
        start_timestamp_ms: 1_000,
        start_lc: 1_000,
        validity_ms: parameters.committee_validity_ms,
        deadline_ms: 1_000 + parameters.committee_validity_ms,
        grace_ms: parameters.forgery_evidence_grace_ms,
        progress_cap_ms: parameters.destination_progress_cap_ms,
        liable_until_lc: 1_000
            + parameters.committee_validity_ms
            + parameters.forgery_evidence_grace_ms,
        dest_cleared_lc: None,
        end: Some(SccpGenerationEndV1 {
            end_height: id + 1,
            end_timestamp_ms: 2_000,
            next_committee_root: [7; 32],
            successor_validity_ms: parameters.committee_validity_ms,
        }),
    };
    value.validate().unwrap();
    value
}

fn seed(stx: &mut StateTransaction<'_, '_>, count: u64) {
    store::parameters::set(stx, Some(SccpParametersV1::taira_default()));
    *stx.world.sccp_committee_current.get_mut() = count + 1;
    *stx.world.sccp_liability_clock.get_mut() = 3_000;
    let budget = stx.execution_budget();
    for id in 1..=count + 1 {
        let mut record = generation(id);
        if id == count + 1 {
            record.end = None;
        }
        let owner = Retained::admit_claim(&record, &budget).unwrap();
        stx.world
            .sccp_committee_generations
            .try_insert_admitted(id, owner)
            .unwrap();
    }
}

fn route(network: SccpNetworkV1) -> SccpRouteV1 {
    let key = KeyPair::from_seed(vec![9; 32], Algorithm::Ed25519);
    let mut route = SccpRouteV1::empty(network, AccountId::new(key.public_key().clone())).unwrap();
    route.revisions.insert(
        1,
        SccpRouteRevisionV1::staged(
            1,
            SccpDeploymentV1::Evm(SccpEvmDeploymentV1 {
                address: [3; 20],
                runtime_code_hash: [4; 32],
            }),
            1_000_000_000_000,
            1,
        ),
    );
    route
}

fn client(network: SccpNetworkV1, time: u64) -> SccpLightClientV1 {
    let params = SccpLightClientParamsV1::defaults_for(network).unwrap();
    let head = SccpLcHeadV1 {
        latest_set_id: 1,
        latest_finalized: SccpLcPointV1 {
            source_height: 100,
            block_hash: [3; 32],
            source_time_ms: time,
        },
        last_progress_taira_ms: 0,
    };
    SccpLightClientV1 {
        params,
        head,
        frozen: None,
        state_hash: iroha_sccp::light_client::state::state_hash(&params, &head, None),
    }
}

#[test]
fn absent_sccp_is_noop_and_missing_native_pruning_custody_is_explicit() {
    let state = state();
    let mut block = state.block(header());
    let mut stx = block.transaction();
    post_generation_work(&mut stx).unwrap();
    assert!(stx.world.take_external_events().is_empty());
    assert_eq!(
        native_pruning_status(),
        NativePruningStatus::Deferred(NativePruningPrerequisite::ForgeryRecordsAndAnchors)
    );
}

#[test]
fn no_routes_clear_at_most_sixty_four_ended_generations_then_resume_without_deleting() {
    let state = state();
    let mut block = state.block(header());
    let mut stx = block.transaction();
    seed(&mut stx, 65);
    assert_eq!(clear_destinations(&mut stx).unwrap(), 64);
    assert_eq!(stx.world.take_external_events().len(), 64);
    for id in 1..=64 {
        assert_eq!(
            stx.world
                .sccp_committee_generations
                .get(&id)
                .unwrap()
                .dest_cleared_lc,
            Some(3_000)
        );
    }
    assert_eq!(
        stx.world
            .sccp_committee_generations
            .get(&65)
            .unwrap()
            .dest_cleared_lc,
        None
    );
    assert_eq!(clear_destinations(&mut stx).unwrap(), 1);
    assert_eq!(stx.world.take_external_events().len(), 1);
    assert_eq!(clear_destinations(&mut stx).unwrap(), 0);
    assert!(stx.world.take_external_events().is_empty());
    assert_eq!(stx.world.sccp_committee_generations.len(), 66);
    assert_eq!(
        stx.world
            .sccp_committee_generations
            .get(&66)
            .unwrap()
            .dest_cleared_lc,
        None,
        "the live current generation is never an ended L5 candidate"
    );
}

#[test]
fn nonretired_routes_require_active_finalized_heads_strictly_past_deadline() {
    let state = state();
    let mut block = state.block(header());
    let mut stx = block.transaction();
    seed(&mut stx, 1);
    let deadline = generation(1).deadline_ms;
    let network = SccpNetworkV1::EthereumMainnet;
    let mut route = route(network);
    for activation in [
        SccpRouteActivationV1::Staged,
        SccpRouteActivationV1::Bidirectional,
        SccpRouteActivationV1::Paused,
        SccpRouteActivationV1::InboundOnly,
    ] {
        route.revisions.get_mut(&1).unwrap().activation = activation;
        store::routes::insert(&mut stx, network, route.clone()).unwrap();
        assert_eq!(
            destination_progress(&*stx.world)[0],
            plan::DestinationProgress::Unavailable
        );
        assert_eq!(clear_destinations(&mut stx).unwrap(), 0);
    }
    store::light_clients::insert(&mut stx, network, client(network, deadline)).unwrap();
    assert_eq!(clear_destinations(&mut stx).unwrap(), 0);
    let mut active = client(network, deadline + 1);
    active.frozen = Some(
        iroha_data_model::sccp::light_client::SccpLcFreezeReasonV1::Parliament(
            iroha_data_model::sccp::light_client::SccpLcParliamentFreezeV1 {
                proposal_id: [8; 32],
            },
        ),
    );
    active.state_hash = iroha_sccp::light_client::state::state_hash(
        &active.params,
        &active.head,
        active.frozen.as_ref(),
    );
    store::light_clients::insert(&mut stx, network, active).unwrap();
    assert_eq!(clear_destinations(&mut stx).unwrap(), 0);
    store::light_clients::insert(&mut stx, network, client(network, deadline + 1)).unwrap();
    assert_eq!(clear_destinations(&mut stx).unwrap(), 1);
    assert_eq!(
        stx.world
            .sccp_committee_generations
            .get(&1)
            .unwrap()
            .dest_cleared_lc,
        Some(3_000)
    );
}

#[test]
fn lifecycle_capacity_refusal_keeps_original_row_and_sticky_source_without_events() {
    let state = state();
    let mut block = state.block(header());
    let mut stx = block.transaction();
    seed(&mut stx, 1);
    let original = stx
        .world
        .sccp_committee_generations
        .get(&1)
        .unwrap()
        .clone();
    let pool = stx.execution_budget();
    let old_limit = pool.limit_bytes();
    pool.set_limit_bytes(pool.reserved_bytes());
    let error = clear_destinations(&mut stx).unwrap_err();
    let BlockValidationError::StateStorageAdmission(original_error) = error else {
        panic!("typed local storage refusal")
    };
    assert!(matches!(
        original_error,
        StateStorageAdmissionError::SccpGeneration(SccpGenerationLocalError::Admission(
            AllocationRefusal::Capacity { .. }
        ))
    ));
    assert_eq!(stx.require_storage_admission(), Err(original_error.clone()));
    assert!(std::ptr::eq(
        stx.world
            .sccp_committee_generations
            .get(&1)
            .unwrap()
            .record(),
        original.record()
    ));
    assert!(stx.world.take_external_events().is_empty());
    pool.set_limit_bytes(old_limit);
    assert!(
        matches!(
            clear_destinations(&mut stx),
            Err(BlockValidationError::StateStorageAdmission(_))
        ),
        "refunding capacity cannot clear a sticky attempt refusal"
    );
    stx.apply();
    assert_eq!(block.require_storage_admission(), Err(original_error));
    assert!(
        block.world.sccp_committee_generations.get(&1).is_none(),
        "the rejected transaction cannot publish even its earlier generation seed"
    );
}

#[test]
fn retired_only_route_does_not_require_a_light_client() {
    let state = state();
    let mut block = state.block(header());
    let mut stx = block.transaction();
    seed(&mut stx, 1);
    let network = SccpNetworkV1::EthereumMainnet;
    let mut retired = route(network);
    retired.revisions.get_mut(&1).unwrap().activation = SccpRouteActivationV1::Retired;
    store::routes::insert(&mut stx, network, retired).unwrap();
    assert_eq!(
        destination_progress(&*stx.world),
        [plan::DestinationProgress::Irrelevant; 3]
    );
    assert_eq!(clear_destinations(&mut stx).unwrap(), 1);
}

#[test]
fn later_lifecycle_copy_refusal_precedes_every_generation_map_write() {
    let state = state();
    let mut block = state.block(header());
    let mut stx = block.transaction();
    seed(&mut stx, 2);
    let originals = [
        stx.world
            .sccp_committee_generations
            .get(&1)
            .unwrap()
            .clone(),
        stx.world
            .sccp_committee_generations
            .get(&2)
            .unwrap()
            .clone(),
    ];
    let pool = stx.execution_budget();
    let old_limit = pool.limit_bytes();
    let reserved = pool.reserved_bytes();
    let first_copy_bytes = originals[0].allocation_bytes().unwrap();
    pool.set_limit_bytes(reserved + first_copy_bytes);
    let one_copy = originals[0]
        .with_lifecycle(originals[0].end, Some(3_000), &pool)
        .expect("the bound admits exactly one lifecycle copy");
    assert_eq!(pool.reserved_bytes(), reserved + first_copy_bytes);
    drop(one_copy);
    let result = clear_destinations(&mut stx);
    pool.set_limit_bytes(old_limit);
    assert!(matches!(
        result,
        Err(BlockValidationError::StateStorageAdmission(_))
    ));
    for original in originals {
        assert!(std::ptr::eq(
            stx.world
                .sccp_committee_generations
                .get(&original.generation)
                .unwrap()
                .record(),
            original.record(),
        ));
    }
    assert_eq!(
        pool.reserved_bytes(),
        reserved,
        "earlier prepared copy is released after refusal"
    );
    assert!(stx.world.take_external_events().is_empty());
}
