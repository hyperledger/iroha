//! Plain voting disabled policy gate test.

use core::num::NonZeroU64;
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute,
    state::{State, World, WorldReadOnly},
};
use iroha_data_model::{
    Registrable,
    account::Account,
    isi::Grant,
    isi::{
        error::{InstructionExecutionError, InvalidParameterError},
        governance::CastPlainBallot,
    },
    permission::Permission,
};
use iroha_executor_data_model::permission::governance::CanSubmitGovernanceBallot;
use iroha_test_samples::ALICE_ID;
use mv::storage::StorageReadOnly;
#[test]
fn plain_ballot_rejected_when_disabled() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let world = World::with([], [Account::new(ALICE_ID.clone()).build(&ALICE_ID)], []);
    let mut state = State::new_for_testing(world, kura, query_handle);
    // Disable plain voting
    let mut cfg = state.gov.clone();
    cfg.plain_voting_enabled = false;
    cfg.min_bond_amount = 0_u64.into();
    cfg.conviction_step_blocks = 1;
    cfg.bond_escrow_account = iroha_test_samples::CARPENTER_ID.clone();
    cfg.slash_receiver_account = iroha_test_samples::SAMPLE_GENESIS_ACCOUNT_ID.clone();
    state.set_gov(cfg);
    let header =
        iroha_data_model::block::BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    let mut sblock = state.block(header);
    let mut stx = sblock.transaction();
    let permission: Permission = CanSubmitGovernanceBallot {
        referendum_id: "rid-disabled".into(),
    }
    .into();
    Grant::account_permission(permission, ALICE_ID.clone())
        .execute(&ALICE_ID, &mut stx)
        .expect("grant exact ballot permission");
    iroha_core::query::standalone_plain_test_fixture::fund_voter(
        &mut stx,
        &ALICE_ID,
        1_000_000_u64.into(),
        0,
    );
    stx.world.governance_referenda_mut().insert(
        "rid-disabled".into(),
        iroha_core::state::GovernanceReferendumRecord {
            h_start: 1,
            h_end: 11,
            status: iroha_core::state::GovernanceReferendumStatus::Open,
            mode: iroha_core::state::GovernanceReferendumMode::Plain,
            plain_context: iroha_core::query::standalone_plain_test_fixture::context(&stx.gov, 0),
            plain_result: iroha_data_model::governance::conviction::PlainVotingResultV1::Pending,
        },
    );
    let balances_before: Vec<_> = stx
        .world
        .assets()
        .iter()
        .map(|(id, balance)| (id.clone(), balance.clone()))
        .collect();
    stx.world.take_external_events();
    let instr = CastPlainBallot {
        referendum_id: "rid-disabled".to_string(),
        direction: 0,
        owner: ALICE_ID.clone(),
        amount: 1000_u64.into(),
        duration_blocks: 10,
    };
    let err = instr.execute(&ALICE_ID, &mut stx).unwrap_err();
    assert!(
        matches!(err, InstructionExecutionError::InvalidParameter(
        InvalidParameterError::SmartContract(ref reason)
    ) if reason == "plain voting mode disabled by policy"),
        "unexpected error: {err:?}"
    );
    assert_eq!(
        stx.world
            .assets()
            .iter()
            .map(|(id, balance)| (id.clone(), balance.clone()))
            .collect::<Vec<_>>(),
        balances_before
    );
    assert!(stx.world.governance_locks().get("rid-disabled").is_none());
    // The early policy guard rejects before any ballot or custody event.
    assert!(stx.world.take_external_events().is_empty());
}
