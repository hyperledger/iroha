//! Wire parity, original graph identity and original-pool refusal for governance metadata.

use super::*;
use crate::smartcontracts::isi::sccp::{
    governance::{PreflightRejection, preflight_attempt_in},
    read,
    test_support::{authority, blank_state, header, sample_proposal, sample_route},
};
use iroha_data_model::{
    governance::types::SccpRouteGovernanceProposal, sccp::governance::SccpGovernanceSubjectV1,
};
use std::time::Duration;

fn control(stop: &AtomicBool) -> SccpNativeReadControl<'_> {
    SccpNativeReadControl {
        deadline: Instant::now() + Duration::from_secs(30),
        stop,
    }
}

fn parity<
    A: norito::core::NoritoSerialize + JsonSerialize,
    B: norito::core::NoritoSerialize + JsonSerialize,
>(
    a: &A,
    b: &B,
) {
    assert_eq!(
        norito::core::to_bytes(a).unwrap(),
        norito::core::to_bytes(b).unwrap()
    );
    assert_eq!(
        norito::json::to_json(a).unwrap(),
        norito::json::to_json(b).unwrap()
    );
}

#[test]
fn registry_and_revisions_borrow_original_graphs_and_preserve_every_codec() {
    let state = blank_state();
    let mut block = state.block(header(40));
    let mut stx = block.transaction();
    let route = sample_route(SccpNetworkV1::EthereumMainnet);
    let network = route.network;
    store::routes::insert(&mut stx, network, route.clone()).unwrap();
    store::governance_revisions::insert(&mut stx, SccpGovernanceSubjectV1::Parameters, 3).unwrap();
    let pool = AllocationBudget::new(4096);
    let stop = AtomicBool::new(false);
    let registry = registry(&stx, &pool, control(&stop)).unwrap();
    let original = store::routes::get(stx.world(), &network).unwrap();
    assert!(std::ptr::eq(registry.data().0[0].0, original));
    assert!(std::ptr::eq(
        &raw const registry.data().0[0].revisions,
        &raw const original.revisions
    ));
    parity(registry.data(), &vec![route]);
    let revisions = revisions(&stx, &pool, control(&stop)).unwrap();
    parity(revisions.data(), &read::governance_revisions(stx.world()));
    assert!(pool.reserved_bytes() > 0);
    drop((registry, revisions));
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn proposal_pages_and_every_phase_borrow_graphs_preserve_order_and_admissibility() {
    let state = blank_state();
    let mut block = state.block(header(40));
    let mut stx = block.transaction();
    store::governance_revisions::insert(&mut stx, SccpGovernanceSubjectV1::Parameters, 1).unwrap();
    let statuses = [
        GovernanceProposalStatus::Proposed,
        GovernanceProposalStatus::Rejected,
        GovernanceProposalStatus::Enacted,
        GovernanceProposalStatus::Superseded,
        GovernanceProposalStatus::ExecutionFailed,
        GovernanceProposalStatus::Proposed,
        GovernanceProposalStatus::Proposed,
    ];
    for (index, status) in statuses.into_iter().enumerate() {
        let mut proposal = sample_proposal(stx.network_id);
        proposal.base_revisions[0].revision = u64::from(index % 2 == 0);
        stx.world.governance_proposals.insert(
            [u8::try_from(index).expect("fixture value fits u8"); 32],
            GovernanceProposalRecord {
                proposer: authority(u8::try_from(index).expect("fixture value fits u8") + 1),
                kind: ProposalKind::SccpRouteGovernance(SccpRouteGovernanceProposal {
                    proposal: Box::new(proposal),
                }),
                created_height: if index == 0 { 9 } else { 7 },
                status,
            },
        );
    }
    let pool = AllocationBudget::new(4096);
    let stop = AtomicBool::new(false);
    let page = proposals(&stx, &pool, control(&stop)).unwrap();
    parity(page.data(), &read::governance_proposals(stx.world()));
    assert_eq!(
        page.data()
            .0
            .iter()
            .map(|row| row.content_id.as_bytes()[0])
            .collect::<Vec<_>>(),
        [5, 6, 0]
    );
    for index in 0..statuses.len() {
        let id = [u8::try_from(index).expect("fixture value fits u8"); 32];
        let detail = proposal(&stx, id, &pool, control(&stop)).unwrap();
        let original = stx.world().governance_proposals().get(&id).unwrap();
        let ProposalKind::SccpRouteGovernance(record) = &original.kind else {
            panic!("proposal")
        };
        assert!(std::ptr::eq(
            detail.data().proposal.0,
            record.proposal.as_ref()
        ));
        assert!(std::ptr::eq(
            detail.data().proposer.0,
            &raw const original.proposer
        ));
        assert_eq!(detail.data().admissible, index % 2 == 0);
        assert_eq!(
            preflight_attempt_in(stx.world(), &record.proposal).is_ok(),
            detail.data().admissible
        );
        if index % 2 != 0 {
            assert_eq!(
                preflight_rejection_in(stx.world(), &record.proposal),
                Some(PreflightRejection::Stale {
                    subject: SccpGovernanceSubjectV1::Parameters,
                    current: 1,
                    base: 0,
                })
            );
        }
        parity(
            detail.data(),
            &read::governance_proposal(stx.world(), id).unwrap(),
        );
    }
    drop(page);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn original_pool_release_is_required_for_retry_and_cancellation_keeps_source_intact() {
    let state = blank_state();
    let mut block = state.block(header(40));
    let mut stx = block.transaction();
    let proposal_value = sample_proposal(stx.network_id);
    stx.world.governance_proposals.insert(
        [1; 32],
        GovernanceProposalRecord {
            proposer: authority(1),
            created_height: 1,
            status: GovernanceProposalStatus::Proposed,
            kind: ProposalKind::SccpRouteGovernance(SccpRouteGovernanceProposal {
                proposal: Box::new(proposal_value),
            }),
        },
    );
    let route = sample_route(SccpNetworkV1::EthereumMainnet);
    store::routes::insert(&mut stx, route.network, route).unwrap();
    store::governance_revisions::insert(&mut stx, SccpGovernanceSubjectV1::Parameters, 1).unwrap();
    let pool = AllocationBudget::new(4096);
    let stop = AtomicBool::new(false);
    let blocked = pool.try_reserve_bytes(4096).unwrap();
    for _ in 0..2 {
        assert!(matches!(
            registry(&stx, &pool, control(&stop)),
            Err(SccpNativeReadError::Allocation(_))
        ));
        assert!(matches!(
            revisions(&stx, &pool, control(&stop)),
            Err(SccpNativeReadError::Allocation(_))
        ));
        assert!(matches!(
            proposals(&stx, &pool, control(&stop)),
            Err(SccpNativeReadError::Allocation(_))
        ));
        assert!(matches!(
            proposal(&stx, [1; 32], &pool, control(&stop)),
            Err(SccpNativeReadError::Allocation(_))
        ));
        let unrelated = AllocationBudget::new(4096);
        drop(unrelated.try_reserve_bytes(4096).unwrap());
    }
    drop(blocked);
    let registry = registry(&stx, &pool, control(&stop)).unwrap();
    let revisions = revisions(&stx, &pool, control(&stop)).unwrap();
    let proposals = proposals(&stx, &pool, control(&stop)).unwrap();
    let detail = proposal(&stx, [1; 32], &pool, control(&stop)).unwrap();
    assert!(pool.reserved_bytes() > 0);
    drop((registry, revisions, proposals, detail));
    assert_eq!(pool.reserved_bytes(), 0);
    assert!(matches!(
        proposal(&stx, [2; 32], &pool, control(&stop)),
        Err(SccpNativeReadError::NotFound(_))
    ));
    stop.store(true, Ordering::Release);
    assert!(matches!(
        proposal(&stx, [1; 32], &pool, control(&stop)),
        Err(SccpNativeReadError::Cancelled)
    ));
    stop.store(false, Ordering::Release);
    let expired = SccpNativeReadControl {
        deadline: Instant::now(),
        stop: &stop,
    };
    assert!(matches!(
        proposal(&stx, [1; 32], &pool, expired),
        Err(SccpNativeReadError::Deadline)
    ));
    assert_eq!(stx.world().governance_proposals().iter().count(), 1);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn proposal_diagnostics_preserve_frozen_heads_and_ordered_activation_intents() {
    use crate::governance::parliament::{ParliamentAttemptStateV1, parliament_attempt_policy_v1};
    use iroha_data_model::{
        governance::types::{
            GovernanceAttemptId, GovernanceAttemptStatusV1, GovernanceExpectedHeadPresentV1,
            GovernanceExpectedHeadV1, GovernanceStageV1,
        },
        sccp::{
            governance::{
                SccpGovernanceActionV1 as Action, SccpRouteRevisionActionV1,
                SccpSetTairaPausedActionV1, SccpSwitchRevisionActionV1,
            },
            registry::SccpRouteActivationV1 as Activation,
        },
    };
    let state = blank_state();
    let mut block = state.block(header(40));
    let mut stx = block.transaction();
    let network = SccpNetworkV1::EthereumMainnet;
    let mut route = sample_route(network);
    let mut successor = route.revisions[&1];
    successor.revision = 2;
    route.revisions.insert(2, successor);
    store::routes::insert(&mut stx, network, route).unwrap();
    store::parameters::set(
        &mut stx,
        Some(iroha_data_model::sccp::params::SccpParametersV1::taira_default()),
    );
    let mut body = sample_proposal(stx.network_id);
    body.actions.extend([
        Action::ActivateRevision(SccpRouteRevisionActionV1 {
            network,
            revision: 1,
        }),
        Action::SwitchRevision(SccpSwitchRevisionActionV1 {
            network,
            from: 1,
            to: 2,
        }),
        Action::SetTairaPaused(SccpSetTairaPausedActionV1 {
            network,
            paused: true,
        }),
        Action::DeactivateOutbound(SccpRouteRevisionActionV1 {
            network,
            revision: 2,
        }),
        Action::SetTairaPaused(SccpSetTairaPausedActionV1 {
            network,
            paused: false,
        }),
        Action::RetireRevision(SccpRouteRevisionActionV1 {
            network,
            revision: 2,
        }),
        Action::RemoveStaged(SccpRouteRevisionActionV1 {
            network,
            revision: 1,
        }),
    ]);
    let kind = ProposalKind::SccpRouteGovernance(SccpRouteGovernanceProposal {
        proposal: Box::new(body),
    });
    let content = ProposalContentId::new(kind.fingerprint());
    let (risk_tier, required) = parliament_attempt_policy_v1(&kind);
    let frozen = GovernanceExpectedHeadV1::Present(GovernanceExpectedHeadPresentV1 {
        subject_id: kind.governed_subject_id_v1().unwrap(),
        version: 77,
        head_root: [0x35; 32],
    });
    let attempt = GovernanceAttemptV1 {
        id: GovernanceAttemptId::derive_v1(content, 0),
        proposal_content_id: content,
        sequence: 0,
        risk_tier,
        stage: GovernanceStageV1::Qualification,
        status: GovernanceAttemptStatusV1::Active,
    };
    let original = ParliamentAttemptStateV1::try_new(
        attempt,
        1,
        1,
        3,
        kind.effect_preimage_hash_v1(),
        frozen,
        required,
    )
    .unwrap();
    stx.world.parliament_attempts.insert(attempt.id, original);
    stx.world.governance_proposals.insert(
        *content.as_bytes(),
        GovernanceProposalRecord {
            proposer: authority(1),
            kind,
            created_height: 7,
            status: GovernanceProposalStatus::Proposed,
        },
    );
    store::governance_revisions::insert(&mut stx, SccpGovernanceSubjectV1::Parameters, 900)
        .unwrap();
    let pool = AllocationBudget::new(16_384);
    let stop = AtomicBool::new(false);
    let detail = proposal(&stx, *content.as_bytes(), &pool, control(&stop)).unwrap();
    assert_eq!(detail.data().attempts.len(), 1);
    assert_eq!(detail.data().attempts[0].attempt, attempt);
    assert_eq!(detail.data().attempts[0].expected_head, frozen);
    assert_eq!(detail.data().attempts[0].terminal_height, None);
    assert_eq!(detail.data().attempts[0].superseding_head, None);
    assert_eq!(detail.data().attempts[0].execution_failure_root, None);
    assert!(!detail.data().admissible);
    assert_eq!(
        detail.data().parameters_before,
        *store::parameters::get(stx.world())
    );
    let changes = &detail.data().activation_diff;
    assert_eq!(changes.len(), 8);
    assert_eq!(
        (
            changes[0].revision,
            changes[0].current,
            changes[0].requested
        ),
        (
            Some(1),
            Some(Activation::Staged),
            Some(Activation::Bidirectional)
        )
    );
    assert_eq!((changes[1].action_index, changes[2].action_index), (2, 2));
    assert_eq!(
        (changes[3].revision, changes[3].requested),
        (Some(2), Some(Activation::Paused))
    );
    assert_eq!(
        changes[5].revision, None,
        "no live target after deactivation"
    );
    assert_eq!(changes[6].requested, Some(Activation::Retired));
    assert_eq!(changes[7].requested, None);
    let encoded = norito::core::to_bytes(detail.data()).unwrap();
    let decoded: SccpGovernanceProposalDetailV1 = norito::decode_from_bytes(&encoded).unwrap();
    assert_eq!(decoded.attempts, detail.data().attempts);
    assert_eq!(decoded.activation_diff, *changes);
    let json = norito::json::to_json(detail.data()).unwrap();
    assert_eq!(
        norito::json::from_str::<SccpGovernanceProposalDetailV1>(&json).unwrap(),
        decoded
    );
    let ready = readiness(&stx, &stx.gov, &pool, control(&stop)).unwrap();
    assert_eq!(ready.data().active_attempts.len(), 1);
    assert_eq!(ready.data().active_attempts[0].attempt, attempt);
    assert!(!ready.data().active_attempts[0].due_available);
    assert_eq!(ready.data().active_attempts[0].next_due_height, None);
    assert_eq!(ready.data().active_attempts[0].next_due_timestamp_ms, None);
    drop((detail, ready));
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn readiness_preserves_unavailable_authority_and_original_pool_refusals() {
    use iroha_sccp::api::SccpGovernanceReadinessV1;
    let state = blank_state();
    let mut block = state.block(header(40));
    let mut stx = block.transaction();
    stx.gov.rules_committee_size = 19;
    let pool = AllocationBudget::new(4096);
    let stop = AtomicBool::new(false);
    let held = pool.try_reserve_bytes(4096).unwrap();
    assert!(matches!(
        readiness(&stx, &stx.gov, &pool, control(&stop)),
        Err(SccpNativeReadError::Allocation(_))
    ));
    drop(held);
    let ready = readiness(&stx, &stx.gov, &pool, control(&stop)).unwrap();
    assert_eq!(ready.data().eligible_citizens, None);
    assert_eq!(ready.data().attempt_latency_ms, None);
    assert_eq!(ready.data().body_sizes.rules_committee, 19);
    assert_eq!(
        ready.data().body_sizes.policy_jury,
        u64::try_from(stx.gov.policy_jury_size).unwrap()
    );
    assert!(!ready.data().parliament_binding_ballot_available);
    assert!(!ready.data().reconciliation_available);
    assert_eq!(ready.data().active_beacon_session, None);
    assert!(!ready.data().beacon_matches_current_roster);
    assert!(ready.data().active_attempts.is_empty());
    let bytes = norito::core::to_bytes(ready.data()).unwrap();
    assert_eq!(
        norito::decode_from_bytes::<SccpGovernanceReadinessV1>(&bytes).unwrap(),
        *ready.data()
    );
    let json = norito::json::to_json(ready.data()).unwrap();
    assert_eq!(
        norito::json::from_str::<SccpGovernanceReadinessV1>(&json).unwrap(),
        *ready.data()
    );
    drop(ready);
    assert_eq!(pool.reserved_bytes(), 0);
    stx.world
        .global_beacon_active_session
        .insert(crate::state::GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY, [7; 32]);
    let missing = readiness(&stx, &stx.gov, &pool, control(&stop)).unwrap();
    assert_eq!(missing.data().active_beacon_session, Some([7; 32]));
    assert!(!missing.data().beacon_matches_current_roster);
    drop(missing);
    stop.store(true, Ordering::Release);
    assert!(matches!(
        readiness(&stx, &stx.gov, &pool, control(&stop)),
        Err(SccpNativeReadError::Cancelled)
    ));
    stop.store(false, Ordering::Release);
    let expired = SccpNativeReadControl {
        deadline: Instant::now(),
        stop: &stop,
    };
    assert!(matches!(
        readiness(&stx, &stx.gov, &pool, expired),
        Err(SccpNativeReadError::Deadline)
    ));
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn readiness_authenticates_active_beacon_against_the_exact_original_roster() {
    use crate::{
        state::World,
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };
    use iroha_crypto::{Algorithm, KeyPair};
    let mut keys = (1..=4)
        .map(|seed| KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal).unwrap())
        .collect::<Vec<_>>();
    keys.sort_by(|a, b| a.public_key().cmp(b.public_key()));
    let mut config = TestChainConfig::new(World::default(), 1_000);
    config.validator_keys = Some(keys.clone());
    let mut chain = CertifiedTestChain::start(config).unwrap();
    // The fixture submits actual clock-account Log transactions; each retained height
    // has its original certified body and availability in Kura.
    for _ in 0..4 {
        chain.commit(Vec::new());
    }
    let mut block = chain.state().block(header(6));
    let mut stx = block.transaction();
    let (record, _) = crate::beacon::signed_pulses_fixture_for_roster_and_anchors(
        stx.network_id,
        &keys,
        &[],
        &stx.execution_budget(),
    );
    let id = record.session.session_id;
    stx.world.global_beacon_key_sessions.insert(id, record);
    stx.world
        .global_beacon_active_session
        .insert(crate::state::GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY, id);
    let pool = AllocationBudget::new(4096);
    let stop = AtomicBool::new(false);
    let ready = readiness(&stx, &stx.gov, &pool, control(&stop)).unwrap();
    assert!(ready.data().beacon_matches_current_roster);
    assert!(!ready.data().parliament_binding_ballot_available);
    assert!(!ready.data().reconciliation_available);
    drop(ready);
    stx.commit_topology.swap(0, 1);
    assert!(
        !readiness(&stx, &stx.gov, &pool, control(&stop))
            .unwrap()
            .data()
            .beacon_matches_current_roster
    );
    stx.commit_topology.swap(0, 1);
    stx.world
        .global_beacon_key_sessions
        .get_mut(&id)
        .unwrap()
        .retired_at_height = Some(5);
    assert!(
        !readiness(&stx, &stx.gov, &pool, control(&stop))
            .unwrap()
            .data()
            .beacon_matches_current_roster
    );
    assert_eq!(pool.reserved_bytes(), 0);
}
