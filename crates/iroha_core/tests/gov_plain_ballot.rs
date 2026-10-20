//! Governance plain ballot test: emits `BallotAccepted` with weight.

use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute,
    state::{State, World},
};
use iroha_data_model::{
    Registrable,
    block::BlockHeader,
    events::data::{DataEvent, governance::GovernanceEvent},
    isi::governance::{CastPlainBallot, UpdatePlainConviction},
    permission::Permission,
    prelude::{Account, Domain, Grant},
};
use iroha_executor_data_model::permission::governance::CanSubmitGovernanceBallot;
use iroha_model_base::domain::DomainId;
use iroha_test_samples::ALICE_ID;
use nonzero_ext::nonzero;
#[test]
fn plain_ballot_emits_ballot_accepted_with_weight() {
    // Build minimal state/transaction
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain: Domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
    let account: Account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
    let world = World::with([domain], [account], []);
    let mut state = State::new_for_testing(world, kura, query_handle);
    let mut gov_cfg = state.gov.clone();
    gov_cfg.plain_voting_enabled = true;
    gov_cfg.min_bond_amount = 0_u64.into();
    gov_cfg.conviction_step_blocks = 1;
    gov_cfg.bond_escrow_account = iroha_test_samples::CARPENTER_ID.clone();
    gov_cfg.slash_receiver_account = iroha_test_samples::SAMPLE_GENESIS_ACCOUNT_ID.clone();
    state.set_gov(gov_cfg);
    // Build a minimal header for transaction context
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut sblock = state.block(header);
    let mut stx = sblock.transaction();
    iroha_core::query::standalone_plain_test_fixture::fund_voter(
        &mut stx,
        &iroha_test_samples::ALICE_ID,
        1_000_000_u64.into(),
        0,
    );
    let plain_context = iroha_core::query::standalone_plain_test_fixture::context(&stx.gov, 0);
    stx.world.governance_referenda_mut().insert(
        "ref-1".to_string(),
        iroha_core::state::GovernanceReferendumRecord {
            h_start: 1,
            // At H=1, the shortest ballot below expires at H=11 and must
            // remain active through this inclusive referendum boundary.
            h_end: 11,
            status: iroha_core::state::GovernanceReferendumStatus::Open,
            mode: iroha_core::state::GovernanceReferendumMode::Plain,
            plain_context,
            plain_result: iroha_data_model::governance::conviction::PlainVotingResultV1::Pending,
        },
    );
    let perm: Permission = CanSubmitGovernanceBallot {
        referendum_id: "ref-1".to_string(),
    }
    .into();
    Grant::account_permission(perm, ALICE_ID.clone())
        .execute(&ALICE_ID, &mut stx)
        .expect("grant ballot permission");
    let amount: u128 = 25;
    let duration_blocks = 10;
    let instr = CastPlainBallot {
        referendum_id: "ref-1".to_string(),
        direction: 0,
        owner: ALICE_ID.clone(),
        amount: amount.into(),
        duration_blocks,
    };
    instr
        .clone()
        .execute(&ALICE_ID, &mut stx)
        .expect("plain ballot ok");
    let events = stx.world.take_external_events();
    let step = stx.gov.conviction_step_blocks.max(1);
    let factor = (1u64 + (duration_blocks / step)).min(stx.gov.max_conviction);
    let expected_weight = 5u128.saturating_mul(u128::from(factor));
    // Expect BallotAccepted with conviction-adjusted weight.
    let mut saw_ok = false;
    for event in events {
        if let Some(DataEvent::Governance(GovernanceEvent::BallotAccepted(ev))) =
            event.as_data_event()
        {
            assert_eq!(ev.referendum_id, "ref-1");
            assert_eq!(ev.weight, Some(expected_weight));
            saw_ok = true;
            break;
        }
    }
    assert!(saw_ok, "expected a BallotAccepted event");
    // Extend the existing conviction position without resubmitting its choice.
    let instr2 = UpdatePlainConviction {
        referendum_id: "ref-1".to_string(),
        owner: ALICE_ID.clone(),
        amount: amount.into(),
        duration_blocks: 200,
    };
    instr2
        .execute(&ALICE_ID, &mut stx)
        .expect("conviction update ok");
    let events2 = stx.world.take_external_events();
    assert!(events2.iter().any(|event| matches!(
        event.as_data_event(),
        Some(DataEvent::Governance(GovernanceEvent::LockExtended(_)))
    )));
}
