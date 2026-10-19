//! Governance referendum window guard tests (plain ballots).

use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute,
    state::{State, World},
};
use iroha_data_model::{
    Registrable,
    block::BlockHeader,
    isi::governance::CastPlainBallot,
    permission::Permission,
    prelude::{Account, Domain, Grant},
};
use iroha_executor_data_model::permission::governance::CanSubmitGovernanceBallot;
use iroha_model_base::domain::DomainId;
use iroha_test_samples::ALICE_ID;
use nonzero_ext::nonzero;
#[test]
fn plain_ballot_rejected_outside_window() {
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
    state.set_gov(gov_cfg);
    {
        // Block height below start
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
            "ref-window".to_string(),
            iroha_core::state::GovernanceReferendumRecord {
                h_start: 5,
                h_end: 6,
                status: iroha_core::state::GovernanceReferendumStatus::Proposed,
                mode: iroha_core::state::GovernanceReferendumMode::Plain,
                plain_context,
                plain_result:
                    iroha_data_model::governance::conviction::PlainVotingResultV1::Pending,
            },
        );
        let ballot_perm: Permission = CanSubmitGovernanceBallot {
            referendum_id: "ref-window".to_string(),
        }
        .into();
        Grant::account_permission(ballot_perm, ALICE_ID.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect("grant ballot permission");
        let ballot = CastPlainBallot {
            referendum_id: "ref-window".to_string(),
            direction: 0,
            owner: ALICE_ID.clone(),
            amount: 10_u64.into(),
            duration_blocks: 10,
        };
        let err = ballot
            .clone()
            .execute(&ALICE_ID, &mut stx)
            .expect_err("ballot before window must fail");
        assert!(
            err.to_string().contains("not active") || err.to_string().contains("referendum"),
            "unexpected error: {err}"
        );
    }
    {
        // Advance to block after end, ensure still rejected
        let header_late = BlockHeader::new(nonzero!(7_u64), None, None, 0, 0);
        let mut sblock_late = state.block(header_late);
        let mut stx_late = sblock_late.transaction();
        // Reinsert referendum (state.block() took a snapshot)
        iroha_core::query::standalone_plain_test_fixture::fund_voter(
            &mut stx_late,
            &ALICE_ID,
            1_000_000_u64.into(),
            0,
        );
        let plain_context =
            iroha_core::query::standalone_plain_test_fixture::context(&stx_late.gov, 0);
        stx_late.world.governance_referenda_mut().insert(
            "ref-window".to_string(),
            iroha_core::state::GovernanceReferendumRecord {
                h_start: 5,
                h_end: 6,
                status: iroha_core::state::GovernanceReferendumStatus::Closed,
                mode: iroha_core::state::GovernanceReferendumMode::Plain,
                plain_context,
                plain_result:
                    iroha_data_model::governance::conviction::PlainVotingResultV1::Decided(
                        iroha_data_model::governance::conviction::PlainVotingDecisionV1 {
                            approve: 0,
                            reject: 0,
                            abstain: 0,
                            approved: false,
                        },
                    ),
            },
        );
        let late_perm: Permission = CanSubmitGovernanceBallot {
            referendum_id: "ref-window".to_string(),
        }
        .into();
        Grant::account_permission(late_perm, ALICE_ID.clone())
            .execute(&ALICE_ID, &mut stx_late)
            .expect("grant ballot permission (late)");
        let ballot = CastPlainBallot {
            referendum_id: "ref-window".to_string(),
            direction: 0,
            owner: ALICE_ID.clone(),
            amount: 10_u64.into(),
            duration_blocks: 10,
        };
        let err_late = ballot
            .execute(&ALICE_ID, &mut stx_late)
            .expect_err("ballot after window must fail");
        assert!(
            err_late.to_string().contains("not active")
                || err_late.to_string().contains("referendum"),
            "unexpected error: {err_late}"
        );
    }
}
