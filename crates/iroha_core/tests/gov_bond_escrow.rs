//! Governance bond escrow locking test.

//!
//! Ensures plain ballots move the configured bond amount into the escrow account.
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute,
    state::{State, World, WorldReadOnly},
};
use iroha_data_model::{
    Registrable,
    asset::{Asset, AssetDefinition},
    block::BlockHeader,
    domain::Domain,
    permission::Permission,
    prelude::{AssetDefinitionId, AssetId, Grant},
};
use iroha_executor_data_model::permission::governance::CanSubmitGovernanceBallot;
use iroha_model_base::domain::DomainId;
use iroha_primitives::numeric::Quantity;
use iroha_test_samples::{ALICE_ID, BOB_ID};
use mv::storage::StorageReadOnly;
use nonzero_ext::nonzero;
#[test]
fn plain_ballot_locks_bond_into_escrow() {
    // Typed governance movements record transcripts even without a transaction call hash.
    let _witness_guard = iroha_core::exec_witness::exec_witness_guard();
    let alice_id = &*ALICE_ID;
    let bob_id = &*BOB_ID;
    let wonderland: iroha_model_base::domain::DomainId =
        iroha_model_base::domain::DomainId::try_new("wonderland", "universal").expect("domain");
    // Build a minimal world with XOR-like asset and escrow account.
    let domain = Domain::new(wonderland.clone()).build(alice_id);
    let alice_account = iroha_data_model::account::Account::new(ALICE_ID.clone()).build(alice_id);
    let escrow_account = iroha_data_model::account::Account::new(BOB_ID.clone()).build(bob_id);
    let def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "xor".parse().unwrap(),
        );
    let asset_def = AssetDefinition::numeric(
        def_id.clone(),
        "xor".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(alice_id);
    let alice_asset = Asset::new(
        AssetId::new(def_id.clone(), ALICE_ID.clone()),
        Quantity::from(1_000_u64),
    );
    let escrow_asset = Asset::new(
        AssetId::new(def_id.clone(), BOB_ID.clone()),
        Quantity::from(0_u64),
    );
    let world = World::with_assets(
        [domain],
        [alice_account, escrow_account],
        [asset_def],
        [alice_asset, escrow_asset],
        [],
    );
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let mut state = State::new_for_testing(world, kura, query_handle);
    // Configure governance to require a 10-unit bond into the escrow account (BOB).
    let mut gov_cfg = state.gov.clone();
    gov_cfg.plain_voting_enabled = true;
    gov_cfg.voting_asset_id = def_id.clone();
    gov_cfg.min_bond_amount = 10_u64.into();
    gov_cfg.bond_escrow_account = BOB_ID.clone();
    gov_cfg.slash_receiver_account = BOB_ID.clone();
    state.set_gov(gov_cfg);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut sblock = state.block(header);
    let mut stx = sblock.transaction();
    // Grant ballot permission to ALICE for this referendum.
    let perm: Permission = CanSubmitGovernanceBallot {
        referendum_id: "rid-bond-lock".to_string(),
    }
    .into();
    Grant::account_permission(perm, ALICE_ID.clone())
        .execute(&ALICE_ID, &mut stx)
        .expect("grant CanSubmitGovernanceBallot");
    // Seed the already-open plain referendum visible at this block height.
    iroha_core::query::standalone_plain_test_fixture::fund_voter(
        &mut stx,
        &iroha_test_samples::ALICE_ID,
        1_000_000_u64.into(),
        0,
    );
    let plain_context = iroha_core::query::standalone_plain_test_fixture::context(&stx.gov, 0);
    stx.world.governance_referenda_mut().insert(
        "rid-bond-lock".to_string(),
        iroha_core::state::GovernanceReferendumRecord {
            h_start: 1,
            h_end: 5,
            status: iroha_core::state::GovernanceReferendumStatus::Open,
            mode: iroha_core::state::GovernanceReferendumMode::Plain,
            plain_context,
            plain_result: iroha_data_model::governance::conviction::PlainVotingResultV1::Pending,
        },
    );
    let instr = iroha_data_model::isi::governance::CastPlainBallot {
        referendum_id: "rid-bond-lock".to_string(),
        owner: ALICE_ID.clone(),
        direction: 0,
        amount: 10_u64.into(),
        duration_blocks: 200,
    };
    instr
        .clone()
        .execute(&ALICE_ID, &mut stx)
        .expect("ballot should lock bond");
    let alice_asset_id = AssetId::new(def_id.clone(), ALICE_ID.clone());
    let escrow_asset_id = AssetId::new(def_id, BOB_ID.clone());
    let alice_balance = stx
        .world
        .asset_mut(&alice_asset_id)
        .expect("alice asset")
        .clone();
    let escrow_balance = stx
        .world
        .asset_mut(&escrow_asset_id)
        .expect("escrow asset")
        .clone();
    assert_eq!(alice_balance.into_inner(), Quantity::from(990_u64));
    assert_eq!(escrow_balance.into_inner(), Quantity::from(10_u64));
    let escrow_perm: Permission = CanSubmitGovernanceBallot {
        referendum_id: "rid-bond-lock".to_string(),
    }
    .into();
    Grant::account_permission(escrow_perm, BOB_ID.clone())
        .execute(&ALICE_ID, &mut stx)
        .expect("grant escrow ballot permission for the negative case");
    let self_custodied = iroha_data_model::isi::governance::CastPlainBallot {
        referendum_id: "rid-bond-lock".to_string(),
        owner: BOB_ID.clone(),
        direction: 0,
        amount: 10_u64.into(),
        duration_blocks: 200,
    }
    .execute(&BOB_ID, &mut stx)
    .expect_err("the configured custody account must not create a nominal self-lock");
    assert!(
        self_custodied
            .to_string()
            .contains("custody accounts cannot cast bonded ballots")
    );
    assert!(
        !stx.world
            .governance_locks()
            .get("rid-bond-lock")
            .is_some_and(|locks| locks.locks.contains_key(&BOB_ID))
    );
    assert_eq!(
        stx.world
            .asset_mut(&escrow_asset_id)
            .expect("escrow asset after rejected self-lock")
            .clone()
            .into_inner(),
        Quantity::from(10_u64)
    );
}
