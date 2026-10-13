//! Independently owned contract-subject fixtures shared only by Core tests.
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::code::ContractSubjectBinding,
    state::{State, World},
};
use iroha_data_model::{
    account::{AccountDetails, AccountValue},
    smart_contract::ContractAddress,
};
use iroha_test_samples::{ALICE_ID, BOB_ID};

/// Existing independent V1 vector with eight rejected candidate points.
pub(crate) fn address() -> ContractAddress {
    "irohac1qyqqqqqqqqqqqqpze5aq5vfxha4qlvu4q80e0ff4yesw50c37z96q"
        .parse()
        .unwrap()
}
/// A distinct admitted contract address.
pub(crate) fn other_address() -> ContractAddress {
    "irohac1qyqqqqqqqqqqqq8y2pcrtkxvkrn5nt74kjjkjcst6kc56qcqa2dqp"
        .parse()
        .unwrap()
}
/// Minimal retained direct binding.
pub(crate) fn binding() -> ContractSubjectBinding {
    ContractSubjectBinding::new_direct(&address(), ALICE_ID.clone())
}
/// Current and predecessor start from the same valid inactive binding.
pub(crate) fn world() -> World {
    let mut world = World::default();
    let address = address();
    let binding = binding();
    for account in [ALICE_ID.clone(), BOB_ID.clone(), binding.subject.clone()] {
        world
            .accounts
            .insert(account, AccountValue::new(AccountDetails::default()));
    }
    world
        .contract_subject_addresses
        .insert(binding.subject.clone(), address.clone());
    world.contract_subject_bindings.insert(address, binding);
    world
}
/// Use the production constructor before any test injects index corruption.
pub(crate) fn state() -> State {
    State::new_for_testing(
        world(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    )
}
