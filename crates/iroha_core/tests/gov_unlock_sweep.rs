//! Automatic unlock sweep at block height.

use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{
        GovernanceLockCustody, GovernanceLockRecord, GovernanceLocksForReferendum,
        GovernanceReferendumRecord, GovernanceReferendumStatus, State, World, WorldReadOnly,
    },
};
use iroha_crypto::KeyPair;
use iroha_data_model::{
    Registrable, account::Account, block::BlockHeader, events::data::governance::GovernanceEvent,
};
use iroha_test_samples::ALICE_ID;
use mv::storage::StorageReadOnly;
use nonzero_ext::nonzero;
fn checked_random_governance_unlock_keypair() -> KeyPair {
    KeyPair::try_random().expect("generate checked governance unlock keypair")
}
#[test]
fn governance_unlock_fixture_uses_checked_randomness() {
    let _key_pair = checked_random_governance_unlock_keypair();
}
#[test]
fn unlocks_after_expiry_height() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let alice = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
    let mut state = State::new_for_testing(World::with([], [alice], []), kura, query_handle);
    let mut governance = state.gov.clone();
    // This sweep fixture retains an explicit zero-bond, zero-weight position.
    governance.min_bond_amount = 0_u64.into();
    governance.conviction_step_blocks = 1;
    governance.bond_escrow_account = iroha_test_samples::CARPENTER_ID.clone();
    governance.slash_receiver_account = iroha_test_samples::SAMPLE_GENESIS_ACCOUNT_ID.clone();
    state.set_gov(governance);
    let _kp = checked_random_governance_unlock_keypair();
    // Block H=1: insert a lock expiring at H=2 (will unlock at H>=3 per current policy)
    let header1 = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    {
        let mut sblock1 = state.block(header1);
        let mut stx = sblock1.transaction();
        iroha_core::query::standalone_plain_test_fixture::fund_voter(
            &mut stx,
            &iroha_test_samples::ALICE_ID,
            1_000_000_u64.into(),
            0,
        );
        stx.world.governance_referenda_mut().insert(
            "rid-unlock".to_owned(),
            GovernanceReferendumRecord {
                h_start: 0,
                h_end: 0,
                status: GovernanceReferendumStatus::Closed,
                mode: iroha_core::state::GovernanceReferendumMode::Plain,
                plain_context: iroha_core::query::standalone_plain_test_fixture::context(
                    &stx.gov, 0,
                ),
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
        let mut map = GovernanceLocksForReferendum::default();
        map.locks.insert(
            ALICE_ID.clone(),
            GovernanceLockRecord {
                owner: ALICE_ID.clone(),
                amount: 0_u64.into(),
                slashed: 0_u64.into(),
                expiry_height: 2,
                direction: 0,
                duration_blocks: 2,
                custody: GovernanceLockCustody {
                    escrowed: true,
                    asset_definition_id: state.gov.voting_asset_id.clone(),
                    bond_escrow_account: state.gov.bond_escrow_account.clone(),
                    slash_receiver_account: state.gov.slash_receiver_account.clone(),
                },
            },
        );
        stx.world
            .governance_locks_mut()
            .insert("rid-unlock".to_string(), map);
        stx.apply();
        // Drain events (none expected yet)
        sblock1.world.take_external_events();
        sblock1
            .commit_empty_block_for_testing()
            .expect("commit block at H=1");
    }
    // Block H=2: still not unlocked
    let header2 = BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    {
        let mut sblock2 = state.block(header2);
        let evs2 = sblock2.world.take_external_events();
        assert!(evs2.iter().all(|e| {
            !matches!(
                e,
                iroha_data_model::events::EventBox::Data(ev)
                    if matches!(
                        ev.as_ref(),
                        iroha_data_model::events::data::DataEvent::Governance(
                            GovernanceEvent::LockUnlocked(_)
                        )
                    )
            )
        }));
        sblock2
            .commit_empty_block_for_testing()
            .expect("commit block at H=2");
    }
    // Block H=3: unlock should occur
    let header3 = BlockHeader::new(nonzero!(3_u64), None, None, 0, 0);
    {
        let mut sblock3 = state.block(header3);
        let evs3 = sblock3.world.take_external_events();
        assert!(evs3.iter().any(|e| matches!(
            e,
            iroha_data_model::events::EventBox::Data(ev)
                if matches!(
                    ev.as_ref(),
                    iroha_data_model::events::data::DataEvent::Governance(
                        GovernanceEvent::LockUnlocked(_)
                    )
                )
        )));
        sblock3
            .commit_empty_block_for_testing()
            .expect("commit block at H=3");
    }
    let view = state.view();
    let world = view.world();
    assert!(world.governance_locks().get("rid-unlock").is_none());
    assert_eq!(
        world
            .governance_referenda()
            .get("rid-unlock")
            .expect("unlock preserves the referendum history")
            .status,
        GovernanceReferendumStatus::Closed
    );
}
