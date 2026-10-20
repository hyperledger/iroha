//! Plain ballot must fail when referendum is missing or closed.

use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute,
    state::{State, World, WorldReadOnly},
};
use iroha_data_model::{
    Registrable,
    block::BlockHeader,
    isi::{
        error::{InstructionExecutionError, InvalidParameterError},
        governance::CastPlainBallot,
    },
    permission::Permission,
    prelude::{Account, Domain, Grant},
};
use iroha_executor_data_model::permission::governance::CanSubmitGovernanceBallot;
use iroha_model_base::domain::DomainId;
use iroha_test_samples::ALICE_ID;
use mv::storage::StorageReadOnly;
use nonzero_ext::nonzero;
#[test]
fn plain_ballot_rejected_when_referendum_absent_or_closed() {
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
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut sblock = state.block(header);
    let mut stx = sblock.transaction();
    for referendum_id in ["missing", "closed"] {
        let ballot_perm: Permission = CanSubmitGovernanceBallot {
            referendum_id: referendum_id.to_string(),
        }
        .into();
        Grant::account_permission(ballot_perm, ALICE_ID.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect("grant exact ballot permission");
    }
    iroha_core::query::standalone_plain_test_fixture::fund_voter(
        &mut stx,
        &ALICE_ID,
        1_000_000_u64.into(),
        0,
    );
    let balances_before: Vec<_> = stx
        .world
        .assets()
        .iter()
        .map(|(id, balance)| (id.clone(), balance.clone()))
        .collect();
    stx.world.take_external_events();
    // No referendum exists; exact permission and real funding are already valid.
    let ballot = CastPlainBallot {
        referendum_id: "missing".to_string(),
        direction: 0,
        owner: ALICE_ID.clone(),
        amount: 10_u64.into(),
        duration_blocks: 10,
    };
    let err = ballot
        .clone()
        .execute(&ALICE_ID, &mut stx)
        .expect_err("ballot should fail when referendum is absent");
    assert!(
        matches!(err, InstructionExecutionError::InvalidParameter(
        InvalidParameterError::SmartContract(ref reason)
    ) if reason == "referendum not found"),
        "unexpected error: {err:?}"
    );
    assert!(stx.world.governance_locks().get("missing").is_none());
    assert!(stx.world.take_external_events().is_empty());
    // Insert a closed referendum and ensure rejection
    let plain_context = iroha_core::query::standalone_plain_test_fixture::context(&stx.gov, 0);
    stx.world.governance_referenda_mut().insert(
        "closed".to_string(),
        iroha_core::state::GovernanceReferendumRecord {
            h_start: 0,
            h_end: 5,
            status: iroha_core::state::GovernanceReferendumStatus::Closed,
            mode: iroha_core::state::GovernanceReferendumMode::Plain,
            plain_context,
            plain_result: iroha_data_model::governance::conviction::PlainVotingResultV1::Decided(
                iroha_data_model::governance::conviction::PlainVotingDecisionV1 {
                    approve: 0,
                    reject: 0,
                    abstain: 0,
                    approved: false,
                },
            ),
        },
    );
    let ballot_closed = CastPlainBallot {
        referendum_id: "closed".to_string(),
        direction: 0,
        owner: ALICE_ID.clone(),
        amount: 10_u64.into(),
        duration_blocks: 10,
    };
    let err_closed = ballot_closed
        .execute(&ALICE_ID, &mut stx)
        .expect_err("ballot should fail when referendum is closed");
    assert!(
        matches!(err_closed, InstructionExecutionError::InvariantViolation(ref reason)
        if reason.as_ref() == "referendum closed"),
        "unexpected error: {err_closed:?}"
    );
    assert!(stx.world.governance_locks().get("closed").is_none());
    assert_eq!(
        stx.world
            .assets()
            .iter()
            .map(|(id, balance)| (id.clone(), balance.clone()))
            .collect::<Vec<_>>(),
        balances_before
    );
    assert!(
        stx.world
            .take_external_events()
            .iter()
            .all(|event| !matches!(
                event.as_data_event(),
                Some(iroha_data_model::events::data::DataEvent::Governance(
                    iroha_data_model::events::data::governance::GovernanceEvent::BallotAccepted(_)
                ))
            ))
    );
}
