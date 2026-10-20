//! Enforce minimum lock duration for plain ballots.

use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute,
    state::{State, World},
};
use iroha_crypto::KeyPair;
use iroha_data_model::{
    Registrable, account::Account, block::BlockHeader, events::data::governance::GovernanceEvent,
    isi::Grant, isi::governance::CastPlainBallot, permission::Permission,
};
use iroha_executor_data_model::permission::governance::CanSubmitGovernanceBallot;
use iroha_test_samples::ALICE_ID;
use nonzero_ext::nonzero;
fn checked_random_plain_ballot_keypair() -> KeyPair {
    KeyPair::try_random().expect("generate checked plain ballot keypair")
}
#[test]
fn plain_ballot_fixture_uses_checked_randomness() {
    let _key_pair = checked_random_plain_ballot_keypair();
}
#[test]
fn plain_ballot_rejected_when_duration_below_min() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let world = World::with([], [Account::new(ALICE_ID.clone()).build(&ALICE_ID)], []);
    let mut state = State::new_for_testing(world, kura, query_handle);
    // Set min step > requested duration
    let mut cfg = state.gov.clone();
    cfg.plain_voting_enabled = true;
    cfg.min_bond_amount = 0_u64.into();
    cfg.conviction_step_blocks = 100;
    state.set_gov(cfg);
    let _kp = checked_random_plain_ballot_keypair();
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut sblock = state.block(header);
    let mut stx = sblock.transaction();
    let permission: Permission = CanSubmitGovernanceBallot {
        referendum_id: "rid-min-dur".into(),
    }
    .into();
    Grant::account_permission(permission, ALICE_ID.clone())
        .execute(&ALICE_ID, &mut stx)
        .expect("grant exact ballot permission");
    let plain_context = iroha_core::query::standalone_plain_test_fixture::context(&stx.gov, 0);
    stx.world.governance_referenda_mut().insert(
        "rid-min-dur".into(),
        iroha_core::state::GovernanceReferendumRecord {
            h_start: 1,
            h_end: 2,
            status: iroha_core::state::GovernanceReferendumStatus::Open,
            mode: iroha_core::state::GovernanceReferendumMode::Plain,
            plain_context,
            plain_result: iroha_data_model::governance::conviction::PlainVotingResultV1::Pending,
        },
    );
    let instr = CastPlainBallot {
        referendum_id: "rid-min-dur".to_string(),
        direction: 0,
        owner: ALICE_ID.clone(),
        amount: 100_u64.into(),
        duration_blocks: 10,
    };
    let err = instr.execute(&ALICE_ID, &mut stx).unwrap_err();
    let s = format!("{err}");
    assert!(s.contains("lock duration shorter"));
    let evs = stx.world.take_external_events();
    assert!(evs.iter().any(|e| matches!(
        e,
        iroha_data_model::events::EventBox::Data(ev)
            if matches!(
                ev.as_ref(),
                iroha_data_model::events::data::DataEvent::Governance(
                    GovernanceEvent::BallotRejected(_)
                )
            )
    )));
}
