//! State and permissions for rejected-input election fixtures.
//! No helper creates an admitted election or a valid proof.
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute,
    state::{State, StateTransaction, World},
};
use iroha_data_model::{
    Registrable, account::Account, domain::Domain, permission::Permission, prelude::Grant,
};
use iroha_executor_data_model::permission::governance::{
    CanEnactGovernance, CanManageParliament, CanSubmitGovernanceBallot,
};
use iroha_model_base::domain::DomainId;
use iroha_primitives::json::Json;
use iroha_test_samples::ALICE_ID;

pub(super) fn state() -> State {
    let account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
    let domain =
        Domain::new(DomainId::try_new("wonderland", "universal").expect("domain")).build(&ALICE_ID);
    let mut state = State::new_for_testing(
        World::with([domain], [account], []),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    // Isolate proof/lock admission from citizenship and asset escrow accounting.
    state.gov.citizenship_bond_amount = 0_u64.into();
    state.gov.min_bond_amount = 0_u64.into();
    state
        .edit_zk_for_testing(|zk| zk.halo2.enabled = true)
        .expect("fixture ZK settings install");
    state
}

pub(super) fn grant_permissions(transaction: &mut StateTransaction<'_, '_>, referendum: &str) {
    for permission in [
        Permission::new("CanManageVerifyingKeys".to_owned(), Json::new(())),
        CanManageParliament.into(),
        CanEnactGovernance.into(),
        CanSubmitGovernanceBallot {
            referendum_id: referendum.to_owned(),
        }
        .into(),
    ] {
        Grant::account_permission(permission, ALICE_ID.clone())
            .execute(&ALICE_ID, transaction)
            .expect("grant exact fixture permission");
    }
    transaction.world.take_external_events();
}
