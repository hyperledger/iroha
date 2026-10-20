//! Immutable plain casts and explicit authority-bound conviction updates.

use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute,
    state::{State, World, WorldReadOnly},
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
use iroha_test_samples::{ALICE_ID, BOB_ID};
use mv::storage::StorageReadOnly;
use nonzero_ext::nonzero;
#[test]
fn plain_ballot_is_immutable_and_conviction_updates_extend_only() {
    // Minimal state
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain: Domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
    let alice_account: Account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
    let world = World::with([domain], [alice_account], []);
    let mut state = State::new_for_testing(world, kura, query_handle);
    let mut gov_cfg = state.gov.clone();
    gov_cfg.plain_voting_enabled = true;
    gov_cfg.min_bond_amount = 0_u64.into();
    gov_cfg.conviction_step_blocks = 1;
    gov_cfg.bond_escrow_account = iroha_test_samples::CARPENTER_ID.clone();
    gov_cfg.slash_receiver_account = iroha_test_samples::SAMPLE_GENESIS_ACCOUNT_ID.clone();
    state.set_gov(gov_cfg);
    // Build a signed block header at H=1
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut sblock = state.block(header);
    let mut stx = sblock.transaction();
    let rid = "rid-revote".to_string();
    let ballot_perm: Permission = CanSubmitGovernanceBallot {
        referendum_id: rid.clone(),
    }
    .into();
    Grant::account_permission(ballot_perm, ALICE_ID.clone())
        .execute(&ALICE_ID, &mut stx)
        .expect("grant ballot permission");
    iroha_core::query::standalone_plain_test_fixture::fund_voter(
        &mut stx,
        &iroha_test_samples::ALICE_ID,
        1_000_000_u64.into(),
        0,
    );
    let plain_context = iroha_core::query::standalone_plain_test_fixture::context(&stx.gov, 0);
    stx.world.governance_referenda_mut().insert(
        rid.clone(),
        iroha_core::state::GovernanceReferendumRecord {
            h_start: 1,
            // Keep the shortest update valid for the inclusive referendum
            // window so the monotonic-lock check is the rejecting contract.
            h_end: 11,
            status: iroha_core::state::GovernanceReferendumStatus::Open,
            mode: iroha_core::state::GovernanceReferendumMode::Plain,
            plain_context,
            plain_result: iroha_data_model::governance::conviction::PlainVotingResultV1::Pending,
        },
    );
    let update_without_cast = UpdatePlainConviction {
        referendum_id: rid.clone(),
        owner: ALICE_ID.clone(),
        amount: 100_u64.into(),
        duration_blocks: 200,
    }
    .execute(&ALICE_ID, &mut stx)
    .expect_err("conviction cannot create an initial ballot");
    assert!(
        update_without_cast
            .to_string()
            .contains("requires an existing plain ballot")
    );
    assert!(stx.world.governance_locks().get(&rid).is_none());
    // First vote by ALICE
    let first = CastPlainBallot {
        referendum_id: rid.clone(),
        direction: 0,
        owner: ALICE_ID.clone(),
        amount: 100_u64.into(),
        duration_blocks: 200,
    };
    first
        .execute(&ALICE_ID, &mut stx)
        .expect("first ballot should succeed");
    let events = stx.world.take_external_events();
    assert!(events.iter().any(|event| matches!(
        event.as_data_event(),
        Some(DataEvent::Governance(GovernanceEvent::LockCreated(_)))
    )));
    // A second cast cannot silently update the original position.
    let second_cast = CastPlainBallot {
        referendum_id: rid.clone(),
        direction: 0,
        owner: ALICE_ID.clone(),
        amount: 120_u64.into(),
        duration_blocks: 400,
    };
    let duplicate_error = second_cast.execute(&ALICE_ID, &mut stx).unwrap_err();
    assert!(
        duplicate_error
            .to_string()
            .contains("plain ballot already cast")
    );
    assert_eq!(
        stx.world.governance_locks().get(&rid).unwrap().locks[&*ALICE_ID].amount,
        100_u64.into()
    );
    stx.world.take_external_events();
    // A conviction update with shorter duration should be rejected.
    let shorter = UpdatePlainConviction {
        referendum_id: rid.clone(),
        owner: ALICE_ID.clone(),
        amount: 100_u64.into(),
        duration_blocks: 10,
    };
    let err = shorter.execute(&ALICE_ID, &mut stx).unwrap_err();
    let s = format!("{err}");
    assert!(s.contains("conviction update cannot reduce"));
    let evs_rej = stx.world.take_external_events();
    assert!(evs_rej.iter().any(|event| matches!(
        event.as_data_event(),
        Some(DataEvent::Governance(GovernanceEvent::BallotRejected(_)))
    )));
    // A conviction update with smaller amount should be rejected.
    let smaller = UpdatePlainConviction {
        referendum_id: rid.clone(),
        owner: ALICE_ID.clone(),
        amount: 50_u64.into(),
        duration_blocks: 200,
    };
    let err2 = smaller.execute(&ALICE_ID, &mut stx).unwrap_err();
    let s2 = format!("{err2}");
    assert!(s2.contains("conviction update cannot reduce"));
    // Extending the lock changes conviction but retains the choice.
    let extend = UpdatePlainConviction {
        referendum_id: rid.clone(),
        owner: ALICE_ID.clone(),
        amount: 120_u64.into(),
        duration_blocks: 400,
    };
    extend
        .execute(&ALICE_ID, &mut stx)
        .expect("extend should succeed");
    let evs_ext = stx.world.take_external_events();
    assert!(evs_ext.iter().any(|event| matches!(
        event.as_data_event(),
        Some(DataEvent::Governance(GovernanceEvent::LockExtended(_)))
    )));
    let retained = stx
        .world
        .governance_locks()
        .get(&rid)
        .and_then(|locks| locks.locks.get(&ALICE_ID))
        .expect("authority-bound lock retained");
    assert_eq!(retained.owner, *ALICE_ID);
    assert_eq!(retained.direction, 0);
    assert_eq!(retained.amount, 120_u64.into());
    assert_eq!(retained.expiry_height, 401);
    let mismatched_owner = UpdatePlainConviction {
        referendum_id: rid.clone(),
        owner: BOB_ID.clone(),
        amount: 120_u64.into(),
        duration_blocks: 400,
    }
    .execute(&ALICE_ID, &mut stx)
    .expect_err("ballot owner must equal authority");
    assert!(
        mismatched_owner
            .to_string()
            .contains("owner must equal authority")
    );
    assert!(
        !stx.world
            .governance_locks()
            .get(&rid)
            .unwrap()
            .locks
            .contains_key(&BOB_ID)
    );
}
