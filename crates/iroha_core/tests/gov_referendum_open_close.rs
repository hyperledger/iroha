//! Tests for automatic ReferendumOpened/ReferendumClosed events via height triggers.

#![allow(
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::items_after_statements
)]
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{
        GovernanceLockCustody, GovernanceLockRecord, GovernanceLocksForReferendum,
        GovernanceReferendumRecord, GovernanceReferendumStatus, State, World, WorldReadOnly,
    },
};
use iroha_data_model::{
    Registrable,
    block::BlockHeader,
    events::data::governance::GovernanceEvent,
    prelude::{Account, Domain},
};
use iroha_model_base::domain::DomainId;
use mv::storage::StorageReadOnly;
#[test]
fn referendum_open_and_close_by_height() {
    use nonzero_ext::nonzero;
    // Build minimal state.
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain: Domain = Domain::new(domain_id.clone()).build(&iroha_test_samples::ALICE_ID);
    let account: Account =
        Account::new(iroha_test_samples::ALICE_ID.clone()).build(&iroha_test_samples::ALICE_ID);
    let world = World::with([domain], [account], []);
    let mut state = State::new_for_testing(world, kura, query_handle);
    let mut governance = state.gov.clone();
    // This lifecycle projection deliberately retains a zero-weight position.
    governance.min_bond_amount = 0_u64.into();
    governance.bond_escrow_account = iroha_test_samples::CARPENTER_ID.clone();
    governance.slash_receiver_account = iroha_test_samples::SAMPLE_GENESIS_ACCOUNT_ID.clone();
    state.set_gov(governance);
    // Block H=1: create a proposed referendum with explicit [2,3] window.
    let header1 = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let rid = "standalone-window".to_owned();
    {
        let mut sblock1 = state.block(header1);
        let mut stx1 = sblock1.transaction();
        iroha_core::query::standalone_plain_test_fixture::fund_voter(
            &mut stx1,
            &iroha_test_samples::ALICE_ID,
            1_000_000_u64.into(),
            0,
        );
        let static_policy = stx1.static_execution_policy();
        stx1.world.governance_referenda_mut().insert(
            rid.clone(),
            GovernanceReferendumRecord {
                h_start: 2,
                h_end: 3,
                status: GovernanceReferendumStatus::Proposed,
                mode: iroha_core::state::GovernanceReferendumMode::Plain,
                plain_context: iroha_core::query::standalone_plain_test_fixture::context(
                    &static_policy.gov,
                    0,
                ),
                plain_result:
                    iroha_data_model::governance::conviction::PlainVotingResultV1::Pending,
            },
        );
        stx1.apply();
        let has_opened_at_h1 = sblock1.world.take_external_events().iter().any(|event| {
            matches!(
                event,
                iroha_data_model::events::EventBox::Data(payload)
                    if matches!(
                        payload.as_ref(),
                        iroha_data_model::events::data::DataEvent::Governance(
                            GovernanceEvent::ReferendumOpened(_)
                        )
                    )
            )
        });
        assert!(!has_opened_at_h1);
        sblock1
            .commit_empty_block_for_testing()
            .expect("commit block at H=1");
    }
    {
        let view = state.view();
        let referendum = view
            .world()
            .governance_referenda()
            .get(&rid)
            .cloned()
            .expect("referendum should persist after H=1");
        assert_eq!(referendum.status, GovernanceReferendumStatus::Proposed);
    }
    // Block H=2: opens.
    let header2 = BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    let custody = GovernanceLockCustody {
        escrowed: true,
        asset_definition_id: state.gov.voting_asset_id.clone(),
        bond_escrow_account: state.gov.bond_escrow_account.clone(),
        slash_receiver_account: state.gov.slash_receiver_account.clone(),
    };
    {
        let mut sblock2 = state.block(header2);
        let has_opened_event_at_h2 = sblock2.world.take_external_events().iter().any(|event| {
            matches!(
                event,
                iroha_data_model::events::EventBox::Data(payload)
                    if matches!(
                        payload.as_ref(),
                        iroha_data_model::events::data::DataEvent::Governance(
                            GovernanceEvent::ReferendumOpened(_)
                        )
                )
            )
        });
        let mut transaction = sblock2.transaction();
        let mut locks = GovernanceLocksForReferendum::default();
        locks.locks.insert(
            iroha_test_samples::ALICE_ID.clone(),
            GovernanceLockRecord {
                owner: iroha_test_samples::ALICE_ID.clone(),
                amount: 0_u64.into(),
                slashed: 0_u64.into(),
                expiry_height: 102,
                direction: 0,
                duration_blocks: 100,
                custody,
            },
        );
        transaction
            .world
            .governance_locks_mut()
            .insert(rid.clone(), locks);
        transaction.apply();
        sblock2
            .commit_empty_block_for_testing()
            .expect("commit block at H=2");
        let status_open_at_h2 = state
            .view()
            .world()
            .governance_referenda()
            .get(&rid)
            .is_some_and(|record| record.status == GovernanceReferendumStatus::Open);
        assert!(status_open_at_h2);
        assert!(has_opened_event_at_h2 || status_open_at_h2);
    }
    // Block H=3: the inclusive end height remains open.
    let header3 = BlockHeader::new(nonzero!(3_u64), None, None, 0, 0);
    let mut sblock3 = state.block(header3);
    let has_closed_event_at_h3 = sblock3.world.take_external_events().iter().any(|event| {
        matches!(
            event,
            iroha_data_model::events::EventBox::Data(payload)
                if matches!(
                    payload.as_ref(),
                    iroha_data_model::events::data::DataEvent::Governance(
                        GovernanceEvent::ReferendumClosed(_)
                    )
            )
        )
    });
    sblock3
        .commit_empty_block_for_testing()
        .expect("commit block at H=3");
    let status_open_at_h3 = state
        .view()
        .world()
        .governance_referenda()
        .get(&rid)
        .is_some_and(|record| record.status == GovernanceReferendumStatus::Open);
    assert!(status_open_at_h3);
    assert!(!has_closed_event_at_h3);
    // Block H=4: closes at h_end + 1.
    let header4 = BlockHeader::new(nonzero!(4_u64), None, None, 0, 0);
    let mut sblock4 = state.block(header4);
    let events_at_h4 = sblock4.world.take_external_events();
    let has_closed_event_at_h4 = events_at_h4.iter().any(|event| {
        matches!(
            event,
            iroha_data_model::events::EventBox::Data(payload)
                if matches!(
                    payload.as_ref(),
                    iroha_data_model::events::data::DataEvent::Governance(
                        GovernanceEvent::ReferendumClosed(_)
                    )
                )
        )
    });
    let decision = events_at_h4
        .iter()
        .find_map(|event| match event.as_data_event() {
            Some(iroha_data_model::events::data::DataEvent::Governance(
                GovernanceEvent::ReferendumDecided(decision),
            )) => Some(decision),
            _ => None,
        });
    let decision = decision.expect("standalone close must emit its exact referendum decision");
    assert_eq!(decision.referendum_id, rid);
    assert_eq!(
        (decision.approve, decision.reject, decision.abstain),
        (0, 0, 0)
    );
    assert!(
        !decision.approved,
        "a nonzero approval threshold cannot approve an empty decisive tally"
    );
    assert!(
        !events_at_h4.iter().any(|event| matches!(
            event.as_data_event(),
            Some(iroha_data_model::events::data::DataEvent::Governance(
                GovernanceEvent::ProposalRejected(_)
            ))
        )),
        "standalone closure must never masquerade as a typed proposal decision"
    );
    sblock4
        .commit_empty_block_for_testing()
        .expect("commit block at H=4");
    assert!(has_closed_event_at_h4);
    let view = state.view();
    let closed = view
        .world()
        .governance_referenda()
        .get(&rid)
        .cloned()
        .expect("the outstanding lock must retain the closed referendum");
    assert_eq!(closed.status, GovernanceReferendumStatus::Closed);
    assert_eq!(
        closed.mode,
        iroha_core::state::GovernanceReferendumMode::Plain
    );
    drop(view);
    // The canonical decision is emitted at closure. Its retained Closed state must prevent
    // subsequent heights from recalculating or emitting another decision for this referendum.
    let mut next = state.block(BlockHeader::new(nonzero!(5_u64), None, None, 0, 0));
    assert!(
        !next
            .world
            .take_external_events()
            .iter()
            .any(|event| matches!(
                event.as_data_event(),
                Some(iroha_data_model::events::data::DataEvent::Governance(
                    GovernanceEvent::ReferendumDecided(decision)
                )) if decision.referendum_id == rid
            ))
    );
}
