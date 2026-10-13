//! Retained native offence, monotone attestation and permanent quarantine controls.

use super::*;
use crate::smartcontracts::isi::sccp::{
    forgery::{
        execute_forgery,
        tests::{active_member_chain, future},
    },
    governance::enact,
    test_support::{blank_state, header, install_generation, sample_generation_at, sample_route},
};
use crate::state::StateReadOnly;
use iroha_data_model::{
    block::BlockHeader,
    bridge::SccpNetworkV1,
    sccp::governance::{SccpGovernanceActionV1, SccpGovernanceProposalV1},
};
use std::num::NonZeroU64;

const NETWORK: SccpNetworkV1 = SccpNetworkV1::EthereumMainnet;

fn attest_action(at: SccpDeploymentProgressV1) -> SccpAttestDeploymentProgressActionV1 {
    SccpAttestDeploymentProgressActionV1 {
        network: NETWORK,
        revision: 1,
        at,
    }
}

#[test]
fn native_offence_release_and_later_attestation_never_lower_the_floor() {
    let (chain, keys) = active_member_chain();
    let evidence = future(&chain, &keys);
    let parent = chain.state().view().native_execution_tip().unwrap();
    let header = BlockHeader::new(
        NonZeroU64::new(parent.height() + 1).unwrap(),
        Some(parent.iroha_hash()),
        None,
        parent.creation_time_ms() + 1000,
        0,
    );
    let mut block = chain.state().block(header);
    let mut stx = block.transaction_for_callback_testing();
    store::routes::insert(&mut stx, NETWORK, sample_route(NETWORK)).unwrap();
    execute_forgery(&evidence, &mut stx).unwrap();
    let mut route = store::routes::get(&*stx.world, &NETWORK).unwrap().clone();
    assert!(route.revisions[&1].forgery_held(store::forgery_max_generation(&*stx.world)));
    let root = store::committee_generations::get(&*stx.world, &1)
        .unwrap()
        .committee_root;
    let events = stx.world.internal_event_buf.len();
    let proposal = SccpGovernanceProposalV1 {
        network_id: *stx.network_id(),
        base_revisions: Vec::new(),
        actions: vec![SccpGovernanceActionV1::AttestSccpDeploymentProgress(
            attest_action(SccpDeploymentProgressV1::Frozen),
        )],
    };
    // Effect component receives a cause; this is not a claim that the unavailable
    // production Parliament ballot admitted or certified the proposal.
    enact(
        &mut stx,
        &proposal,
        [3; 32],
        ControlCauseV1::for_test([1; 32], [2; 32]),
    )
    .unwrap();
    route = store::routes::get(&*stx.world, &NETWORK).unwrap().clone();
    assert_eq!(route.revisions[&1].forgery_floor, u64::MAX);
    assert!(!route.revisions[&1].forgery_held(store::forgery_max_generation(&*stx.world)));
    assert!(stx.world.internal_event_buf.len() > events);
    attest(
        &mut stx,
        &attest_action(SccpDeploymentProgressV1::Generation {
            generation: 1,
            committee_root: root,
        }),
    )
    .unwrap();
    assert_eq!(
        store::routes::get(&*stx.world, &NETWORK).unwrap().revisions[&1].forgery_floor,
        u64::MAX,
        "SCCP attestation must never lower the retained forgery floor"
    );
}

#[test]
fn attestation_authenticates_generation_root_and_refuses_unknown_revision() {
    let state = blank_state();
    let mut block = state.block(header(5));
    let mut stx = block.transaction();
    store::routes::insert(&mut stx, NETWORK, sample_route(NETWORK)).unwrap();
    let generation = sample_generation_at(1, 1);
    install_generation(&mut stx, 1, generation.clone()).unwrap();
    store::committee_current::set(&mut stx, 1);
    let before = store::routes::get(&*stx.world, &NETWORK).unwrap().clone();
    let events = stx.world.internal_event_buf.len();
    for at in [
        SccpDeploymentProgressV1::Generation {
            generation: 0,
            committee_root: generation.committee_root,
        },
        SccpDeploymentProgressV1::Generation {
            generation: 2,
            committee_root: generation.committee_root,
        },
        SccpDeploymentProgressV1::Generation {
            generation: 1,
            committee_root: [0x55; 32],
        },
    ] {
        assert!(attest(&mut stx, &attest_action(at)).is_err());
        assert_eq!(store::routes::get(&*stx.world, &NETWORK), Some(&before));
        assert_eq!(stx.world.internal_event_buf.len(), events);
    }
    let mut unknown = attest_action(SccpDeploymentProgressV1::Frozen);
    unknown.revision = 99;
    assert!(attest(&mut stx, &unknown).is_err());
    store::committee_current::set(&mut stx, 2);
    assert!(
        attest(
            &mut stx,
            &attest_action(SccpDeploymentProgressV1::Generation {
                generation: 2,
                committee_root: [0x55; 32]
            })
        )
        .is_err()
    );
    assert_eq!(store::routes::get(&*stx.world, &NETWORK), Some(&before));
}

#[test]
fn quarantine_retains_its_original_cause_across_replays_and_progress() {
    let state = blank_state();
    let mut block = state.block(header(5));
    let mut stx = block.transaction();
    store::routes::insert(&mut stx, NETWORK, sample_route(NETWORK)).unwrap();
    let target = SccpRouteRevisionActionV1 {
        network: NETWORK,
        revision: 1,
    };
    quarantine(
        &mut stx,
        &target,
        ControlCauseV1::for_test([1; 32], [2; 32]),
    )
    .unwrap();
    let original = store::routes::get(&*stx.world, &NETWORK).unwrap().revisions[&1].quarantine;
    assert_eq!(
        original,
        Some(SccpQuarantineV1 {
            certificate_id: [1; 32],
            since_height: 5
        })
    );
    let events = stx.world.internal_event_buf.len();
    quarantine(
        &mut stx,
        &target,
        ControlCauseV1::for_test([3; 32], [4; 32]),
    )
    .unwrap();
    assert_eq!(
        store::routes::get(&*stx.world, &NETWORK).unwrap().revisions[&1].quarantine,
        original,
        "SCCP quarantine must preserve its original permanent cause"
    );
    assert_eq!(stx.world.internal_event_buf.len(), events);
    attest(&mut stx, &attest_action(SccpDeploymentProgressV1::Frozen)).unwrap();
    assert_eq!(
        store::routes::get(&*stx.world, &NETWORK).unwrap().revisions[&1].quarantine,
        original
    );
    assert!(
        quarantine(
            &mut stx,
            &SccpRouteRevisionActionV1 {
                revision: 99,
                ..target
            },
            ControlCauseV1::for_test([5; 32], [6; 32])
        )
        .is_err()
    );
}

#[test]
fn quarantined_retirement_requires_the_single_completed_reconciliation_window() {
    use crate::smartcontracts::isi::sccp::reconciliation;
    use iroha_data_model::sccp::{
        governance::SccpOpenReconciliationActionV1, params::SccpParametersV1,
        registry::SccpRouteActivationV1,
    };
    let state = blank_state();
    let mut block = state.block(header(5));
    let mut stx = block.transaction();
    store::parameters::set(&mut stx, Some(SccpParametersV1::taira_default()));
    let mut route = sample_route(NETWORK);
    route.revisions.get_mut(&1).unwrap().activation = SccpRouteActivationV1::InboundOnly;
    store::routes::insert(&mut stx, NETWORK, route).unwrap();
    let target = SccpRouteRevisionActionV1 {
        network: NETWORK,
        revision: 1,
    };
    let cause = ControlCauseV1::for_test([1; 32], [2; 32]);
    quarantine(&mut stx, &target, cause).unwrap();
    let retire = SccpGovernanceProposalV1 {
        network_id: *stx.network_id(),
        base_revisions: vec![],
        actions: vec![SccpGovernanceActionV1::RetireRevision(target)],
    };
    let opening = SccpGovernanceProposalV1 {
        network_id: *stx.network_id(),
        base_revisions: vec![],
        actions: vec![SccpGovernanceActionV1::OpenSccpReconciliation(
            SccpOpenReconciliationActionV1 {
                network: NETWORK,
                revision: 1,
                window_ms: 1,
            },
        )],
    };
    assert!(
        enact(&mut stx, &retire, [3; 32], cause)
            .expect_err("SCCP quarantined retirement must await reconciliation")
            .to_string()
            .contains("reconciled before retirement")
    );
    enact(&mut stx, &opening, [4; 32], cause).unwrap();
    assert!(!reconciliation::is_reconciled(&*stx.world, NETWORK, 1));
    assert!(enact(&mut stx, &opening, [4; 32], cause).is_err());
    assert!(enact(&mut stx, &retire, [3; 32], cause).is_err());
    assert!(!reconciliation::end_one(&mut stx, NETWORK, 1).unwrap());
    stx.apply();
    block.commit_world_overlay_for_testing().unwrap();
    let mut block = state.block(header(6));
    let mut stx = block.transaction();
    // This directly tests the rank-3 reducer. The production shared pass must acquire
    // its original higher-rank receipt before it can call this reducer.
    assert!(reconciliation::end_one(&mut stx, NETWORK, 1).unwrap());
    assert!(reconciliation::is_reconciled(&*stx.world, NETWORK, 1));
    enact(&mut stx, &retire, [3; 32], cause).unwrap();
    let route = store::routes::get(&*stx.world, &NETWORK).unwrap();
    assert_eq!(
        route.revisions[&1].activation,
        SccpRouteActivationV1::Retired
    );
    assert_eq!(
        route.revisions[&1].quarantine.unwrap().certificate_id,
        [1; 32]
    );
}
