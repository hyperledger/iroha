//! `CreateElection` must reject when a matching referendum exists in Plain mode.

use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute,
    state::{State, World, WorldReadOnly},
};
use iroha_data_model::{
    Registrable, account::Account, asset::AssetDefinition, block::BlockHeader, domain::Domain,
    isi::zk::CreateElection, permission::Permission, prelude::Grant, proof::VerifyingKeyId,
};
use iroha_executor_data_model::permission::governance::CanManageParliament;
use iroha_model_base::domain::DomainId;
use mv::storage::StorageReadOnly;
use nonzero_ext::nonzero;
#[test]
fn create_election_rejects_plain_conflict() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain");
    let domain = Domain::new(domain_id.clone()).build(&iroha_test_samples::ALICE_ID);
    let account =
        Account::new(iroha_test_samples::ALICE_ID.clone()).build(&iroha_test_samples::ALICE_ID);
    let world = World::with([domain], [account], Vec::<AssetDefinition>::new());
    let state = State::new_for_testing(world, kura, query_handle);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut sblock = state.block(header);
    let mut stx = sblock.transaction();
    // Seed a Plain referendum with the same id
    iroha_core::query::standalone_plain_test_fixture::fund_voter(
        &mut stx,
        &iroha_test_samples::ALICE_ID,
        1_000_000_u64.into(),
        0,
    );
    stx.world.governance_referenda_mut().insert(
        "ref-conflict".to_string(),
        iroha_core::state::GovernanceReferendumRecord {
            h_start: 0,
            h_end: 10,
            status: iroha_core::state::GovernanceReferendumStatus::Proposed,
            mode: iroha_core::state::GovernanceReferendumMode::Plain,
            plain_context: iroha_core::query::standalone_plain_test_fixture::context(&stx.gov, 0),
            plain_result: iroha_data_model::governance::conviction::PlainVotingResultV1::Pending,
        },
    );
    let vk_id = VerifyingKeyId::new("halo2/ipa", "unqualified");
    let perm_parliament: Permission = CanManageParliament.into();
    Grant::account_permission(perm_parliament, iroha_test_samples::ALICE_ID.clone())
        .execute(&iroha_test_samples::ALICE_ID, &mut stx)
        .expect("grant parliament permission");
    let create = CreateElection {
        election_id: "ref-conflict".to_string(),
        options: 2,
        eligible_root: [0u8; 32],
        start_ts: 0,
        end_ts: 0,
        vk_ballot: vk_id.clone(),
        vk_tally: vk_id,
        domain_tag: "gov:ballot:v1".to_string(),
    };
    let err = create
        .execute(&iroha_test_samples::ALICE_ID, &mut stx)
        .expect_err("plain-mode referendum conflict should fail");
    let s = format!("{err}");
    assert!(s.contains("mode mismatch"), "unexpected error message: {s}");
    assert!(stx.world.elections().get("ref-conflict").is_none());
    assert_eq!(
        stx.world
            .governance_referenda()
            .get("ref-conflict")
            .expect("retained referendum")
            .mode,
        iroha_core::state::GovernanceReferendumMode::Plain
    );
}
