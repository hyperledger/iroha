//! A scheduled plain referendum emits `ReferendumOpened` with the correct window.

use core::num::NonZeroU64;
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute,
    state::{GovernanceReferendumRecord, GovernanceReferendumStatus, State, World},
};
use iroha_data_model::{
    Registrable,
    block::BlockHeader,
    events::data::{DataEvent, governance::GovernanceEvent},
    isi::governance::CastPlainBallot,
    permission::Permission,
    prelude::{Account, Domain, Grant},
};
use iroha_executor_data_model::permission::governance::CanSubmitGovernanceBallot;
use iroha_test_samples::ALICE_ID;
#[test]
fn plain_ballot_emits_open_event_with_window() {
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let domain_id: iroha_model_base::domain::DomainId =
        iroha_model_base::domain::DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain: Domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
    let account: Account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
    let world = World::with([domain], [account], []);
    let mut state = State::new_for_testing(world, kura, query);
    let mut cfg = state.gov.clone();
    cfg.plain_voting_enabled = true;
    cfg.min_bond_amount = 0_u64.into();
    cfg.conviction_step_blocks = 1;
    cfg.bond_escrow_account = iroha_test_samples::CARPENTER_ID.clone();
    cfg.slash_receiver_account = iroha_test_samples::SAMPLE_GENESIS_ACCOUNT_ID.clone();
    state.set_gov(cfg);
    let chain = crate::block::tests::component_chain(state);
    let state = chain.state();
    let rid = "plain-open-event".to_string();
    chain.setup_world_at(0, |stx| {
        let ballot_perm: Permission = CanSubmitGovernanceBallot {
            referendum_id: rid.clone(),
        }
        .into();
        Grant::account_permission(ballot_perm, ALICE_ID.clone())
            .execute(&ALICE_ID, stx)
            .expect("grant ballot permission");
        iroha_core::query::standalone_plain_test_fixture::fund_voter(
            stx,
            &iroha_test_samples::ALICE_ID,
            1_000_000_u64.into(),
            0,
        );
        let static_policy = stx.static_execution_policy();
        stx.world.governance_referenda_mut().insert(
            rid.clone(),
            GovernanceReferendumRecord {
                h_start: 2,
                h_end: 6,
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
    });

    let header = BlockHeader::new(
        NonZeroU64::new(2).unwrap(),
        state.view().latest_block_hash(),
        None,
        0,
        0,
    );
    let mut sblock = state.block(header);
    let mut stx = sblock.transaction_for_fastpq_protocol_testing();
    CastPlainBallot {
        referendum_id: rid.clone(),
        direction: 0,
        owner: ALICE_ID.clone(),
        amount: 1_u64.into(),
        duration_blocks: 4,
    }
    .execute(&ALICE_ID, &mut stx)
    .expect("ballot ok");
    stx.apply();
    let events = sblock.world.take_external_events();
    let opened = events.iter().find_map(|event| match event.as_data_event() {
        Some(DataEvent::Governance(GovernanceEvent::ReferendumOpened(opened))) => {
            Some(opened.clone())
        }
        _ => None,
    });
    let opened = opened.expect("expected ReferendumOpened event");
    assert_eq!(opened.h_start, 2);
    assert_eq!(opened.h_end, 6);
}
