//! Atomic route installation behind both unavailable production launch gates.
//!
//! A genuine committed Global tip supplies the chain identity. Explicit retained committee
//! fixture data exercises registration consumers without claiming ballot or launch authority.

use super::*;
use crate::{
    smartcontracts::isi::sccp::test_support::{
        authority, install_generation, sample_generation_at, sample_pin,
    },
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_data_model::{
    block::BlockHeader,
    events::{EventBox, data::DataEvent},
    sccp::{
        deployment::SccpEvmDeploymentV1, events::SccpRevisionActivationChangedV1,
        generation::SccpGenerationMemberV1, params::SccpParametersV1,
        registry::SccpRouteRevisionV1,
    },
};
use iroha_model_base::topology::LaneId;
use iroha_sccp::v1::evm_abi::ConstructorArgsV1;
use std::num::NonZeroU64;

const NETWORK: SccpNetworkV1 = SccpNetworkV1::EthereumMainnet;
const CERTIFICATE_ID: [u8; 32] = [0x43; 32];
const EFFECT_HASH: [u8; 32] = [0x45; 32];

fn chain_and_header() -> (CertifiedTestChain, BlockHeader) {
    let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000))
        .expect("genuine committed Global parent");
    let parent = chain.state().view().native_execution_tip().unwrap();
    let header = BlockHeader::new(
        NonZeroU64::new(parent.height() + 1).unwrap(),
        Some(parent.iroha_hash()),
        None,
        parent.creation_time_ms() + 1_000,
        0,
    );
    (chain, header)
}

fn initialize(stx: &mut StateTransaction<'_, '_>, instance: [u8; 32]) -> SccpRegisterRouteActionV1 {
    store::parameters::set(stx, Some(SccpParametersV1::taira_default()));
    escrow::create_route_escrows(stx).expect("empty route escrows");
    let mut generation = sample_generation_at(1, 1);
    generation.members = (1..=4)
        .map(|seed| {
            Some(SccpGenerationMemberV1 {
                lane_id: LaneId::new(0),
                validator: authority(seed),
                activation_height: 1,
            })
        })
        .collect();
    install_generation(stx, 1, generation.clone()).expect("retained resolved committee fixture");
    store::committee_current::set(stx, 1);
    let constructor = ConstructorArgsV1 {
        taira_network_id: *stx.network_id().as_bytes(),
        consensus_instance: instance,
        network: NETWORK,
        route_revision: 1,
        max_wrapped_supply: 1_000_000_000_000,
        pin: sample_pin(&generation),
    };
    let register = SccpRegisterRouteActionV1 {
        network: NETWORK,
        revision: constructor.route_revision,
        deployment: SccpDeploymentV1::Evm(SccpEvmDeploymentV1 {
            address: constructor.address(),
            runtime_code_hash: [8; 32],
        }),
        initial_committee: constructor.pin,
        max_wrapped_supply: constructor.max_wrapped_supply,
    };
    registration::validate_available(stx, &register).expect("all native P1-P5 checks pass");
    register
}

fn proposal(
    stx: &StateTransaction<'_, '_>,
    register: &SccpRegisterRouteActionV1,
) -> SccpGovernanceProposalV1 {
    SccpGovernanceProposalV1 {
        network_id: *stx.network_id(),
        base_revisions: vec![(SccpGovernanceSubjectV1::Route(NETWORK), 0).into()],
        actions: vec![SccpGovernanceActionV1::RegisterRoute(*register)],
    }
}

fn casting_open() -> GovernanceAnchorV1 {
    GovernanceAnchorV1 {
        height: 1,
        position: 0,
        timestamp_ms: 1_000,
    }
}

fn sccp_events(events: Vec<EventBox>) -> Vec<SccpEvent> {
    events
        .into_iter()
        .filter_map(|event| match event {
            EventBox::Data(event) => match event.as_ref() {
                DataEvent::Sccp(event) => Some(event.clone()),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

#[test]
fn registration_installs_the_complete_staged_revision_and_enactment_effects() {
    let (chain, header) = chain_and_header();
    let mut block = chain.state().block(header);
    let (register, proposal) = {
        let mut stx = block.transaction_for_callback_testing();
        let register = initialize(&mut stx, chain.instance().0);
        let proposal = proposal(&stx, &register);
        stx.apply();
        (register, proposal)
    };
    block.world.take_external_events();
    let before = store::routes::get(&block.world, &NETWORK).unwrap().clone();
    {
        let mut stx = block.transaction_for_callback_testing();
        super::tests::with_launch_gates((true, true), || {
            enact(
                &mut stx,
                CERTIFICATE_ID,
                EFFECT_HASH,
                casting_open(),
                &proposal,
            )
        })
        .expect("both launch gates authorize the complete installation");
        stx.apply();
    }
    let mut expected = before;
    expected.revisions.insert(
        register.revision,
        SccpRouteRevisionV1::staged(
            register.revision,
            register.deployment,
            register.initial_committee,
            register.max_wrapped_supply,
            header.height().get(),
        ),
    );
    assert_eq!(store::routes::get(&block.world, &NETWORK), Some(&expected));
    let revision = expected.revisions.get(&1).unwrap();
    assert_eq!(
        revision.forgery_floor,
        register.initial_committee.generation
    );
    assert_eq!(revision.quarantine, None);
    assert_eq!(revision.liability, 0);
    assert_eq!(revision.next_outbound_nonce, 0);
    assert_eq!(revision.next_control_nonce, 1);
    assert!(!revision.destination_frozen);
    assert!(!revision.destination_paused);
    assert!(!revision.ever_activated);
    assert_eq!(
        store::destination_words::get(&block.world, &register.deployment.destination_word()),
        Some(&(NETWORK, register.revision))
    );
    assert_eq!(
        store::governance_revision(&block.world, &SccpGovernanceSubjectV1::Route(NETWORK)),
        1
    );
    assert!(store::control_messages::is_empty(&block.world));
    assert!(store::pending_counts::is_empty(&block.world));
    let proposal_id = ProposalKind::SccpRouteGovernance(SccpRouteGovernanceProposal {
        proposal: Box::new(proposal.clone()),
    })
    .fingerprint();
    assert_eq!(
        sccp_events(block.world.take_external_events()),
        vec![
            SccpEvent::RevisionActivationChanged(SccpRevisionActivationChangedV1 {
                network: NETWORK,
                revision: 1,
                from: None,
                to: Some(SccpRouteActivationV1::Staged),
            }),
            SccpEvent::GovernanceEnacted(SccpGovernanceEnactedV1 {
                proposal_id,
                subjects: vec![SccpGovernanceSubjectV1::Route(NETWORK)],
            }),
        ]
    );
}

#[test]
fn registration_rolls_back_every_effect_when_a_later_action_fails() {
    let (chain, header) = chain_and_header();
    let mut block = chain.state().block(header);
    let (register, mut proposal) = {
        let mut stx = block.transaction_for_callback_testing();
        let register = initialize(&mut stx, chain.instance().0);
        let proposal = proposal(&stx, &register);
        stx.apply();
        (register, proposal)
    };
    block.world.take_external_events();
    let before = store::routes::get(&block.world, &NETWORK).unwrap().clone();
    proposal.actions.push(SccpGovernanceActionV1::RemoveStaged(
        SccpRouteRevisionActionV1 {
            network: NETWORK,
            revision: 2,
        },
    ));
    {
        let mut stx = block.transaction_for_callback_testing();
        let error = super::tests::with_launch_gates((true, true), || {
            enact(
                &mut stx,
                CERTIFICATE_ID,
                EFFECT_HASH,
                casting_open(),
                &proposal,
            )
        })
        .expect_err("the second action fails after installation");
        assert!(error.to_string().contains("action 1"), "{error}");
        assert!(
            store::routes::get(&*stx.world, &NETWORK)
                .unwrap()
                .revisions
                .contains_key(&1)
        );
        assert!(store::destination_words::contains(
            &*stx.world,
            &register.deployment.destination_word()
        ));
        // The Parliament effect owner drops the entire child on any failed action.
    }
    assert_eq!(store::routes::get(&block.world, &NETWORK), Some(&before));
    assert!(store::destination_words::is_empty(&block.world));
    assert_eq!(
        store::governance_revision(&block.world, &SccpGovernanceSubjectV1::Route(NETWORK)),
        0
    );
    assert!(block.world.take_external_events().is_empty());
}

#[test]
fn registration_and_earlier_subject_increment_roll_back_when_a_later_counter_overflows() {
    use iroha_data_model::sccp::governance::SccpSetDestinationPausedActionV1;

    let (chain, header) = chain_and_header();
    let mut block = chain.state().block(header);
    let route_subject = SccpGovernanceSubjectV1::Route(NETWORK);
    let control_subject = SccpGovernanceSubjectV1::RouteControl(NETWORK);
    let (register, mut proposal) = {
        let mut stx = block.transaction_for_callback_testing();
        let register = initialize(&mut stx, chain.instance().0);
        // Defensive source-state fixture: normal proposal admission's exact-JSON integer
        // bound cannot authorize this head. The effect consumer must still roll back safely.
        store::set_governance_revision(&mut stx, control_subject, u64::MAX);
        let proposal = proposal(&stx, &register);
        stx.apply();
        (register, proposal)
    };
    block.world.take_external_events();
    let before = store::routes::get(&block.world, &NETWORK).unwrap().clone();
    proposal
        .base_revisions
        .push((control_subject, u64::MAX).into());
    proposal
        .actions
        .push(SccpGovernanceActionV1::SetDestinationPaused(
            SccpSetDestinationPausedActionV1 {
                network: NETWORK,
                revision: 2,
                paused: true,
            },
        ));
    {
        let mut stx = block.transaction_for_callback_testing();
        let error = super::tests::with_launch_gates((true, true), || {
            enact(
                &mut stx,
                CERTIFICATE_ID,
                EFFECT_HASH,
                casting_open(),
                &proposal,
            )
        })
        .expect_err("later subject overflow discards the complete effect transaction");
        assert!(
            error.to_string().contains("subject revision overflows"),
            "{error}"
        );
        assert!(
            store::routes::get(&*stx.world, &NETWORK)
                .unwrap()
                .revisions
                .contains_key(&1)
        );
        assert!(store::destination_words::contains(
            &*stx.world,
            &register.deployment.destination_word()
        ));
        assert_eq!(store::governance_revision(&*stx.world, &route_subject), 1);
        assert_eq!(
            store::governance_revision(&*stx.world, &control_subject),
            u64::MAX
        );
    }
    assert_eq!(store::routes::get(&block.world, &NETWORK), Some(&before));
    assert!(store::destination_words::is_empty(&block.world));
    assert_eq!(store::governance_revision(&block.world, &route_subject), 0);
    assert_eq!(
        store::governance_revision(&block.world, &control_subject),
        u64::MAX
    );
    assert!(block.world.take_external_events().is_empty());
}

#[test]
fn registration_with_real_launch_gates_fails_closed_without_state_or_events() {
    assert!(!super::super::parliament_iface::parliament_binding_ballot_available());
    assert!(!sccp_reconciliation_available());
    let (chain, header) = chain_and_header();
    let mut block = chain.state().block(header);
    let mut stx = block.transaction_for_callback_testing();
    let register = initialize(&mut stx, chain.instance().0);
    let proposal = proposal(&stx, &register);
    let before = store::routes::get(&*stx.world, &NETWORK).unwrap().clone();
    stx.world.take_external_events();
    let result = enact(
        &mut stx,
        CERTIFICATE_ID,
        EFFECT_HASH,
        casting_open(),
        &proposal,
    );
    assert!(
        result.is_err(),
        "SCCP registration must remain closed while either launch gate is unavailable"
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("launch/reconciliation authority")
    );
    assert_eq!(store::routes::get(&*stx.world, &NETWORK), Some(&before));
    assert!(store::destination_words::is_empty(&*stx.world));
    assert_eq!(
        store::governance_revision(&*stx.world, &SccpGovernanceSubjectV1::Route(NETWORK)),
        0
    );
    assert!(stx.world.take_external_events().is_empty());
}

#[test]
fn registration_requires_both_launch_gates_even_after_native_preconditions() {
    let (chain, header) = chain_and_header();
    let mut block = chain.state().block(header);
    let mut stx = block.transaction_for_callback_testing();
    let register = initialize(&mut stx, chain.instance().0);
    let proposal = proposal(&stx, &register);
    let before = store::routes::get(&*stx.world, &NETWORK).unwrap().clone();
    stx.world.take_external_events();
    for gates in [(true, false), (false, true)] {
        let result = super::tests::with_launch_gates(gates, || {
            enact(
                &mut stx,
                CERTIFICATE_ID,
                EFFECT_HASH,
                casting_open(),
                &proposal,
            )
        });
        assert!(
            result.is_err(),
            "SCCP registration must require both launch gates after native preconditions pass"
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("launch/reconciliation authority")
        );
        assert_eq!(store::routes::get(&*stx.world, &NETWORK), Some(&before));
        assert!(store::destination_words::is_empty(&*stx.world));
        assert_eq!(
            store::governance_revision(&*stx.world, &SccpGovernanceSubjectV1::Route(NETWORK)),
            0
        );
        assert!(stx.world.take_external_events().is_empty());
    }
}
