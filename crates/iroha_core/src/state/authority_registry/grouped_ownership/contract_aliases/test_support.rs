//! Shared original contract alias/lease codec inputs, with no deployment or current authority.

use super::*;
use iroha_data_model::{IntoKeyValue, account::Account, prelude::Registrable};
use iroha_model_base::topology::DataSpaceId;
use iroha_test_samples::ALICE_ID;

pub(in crate::state) fn address(nonce: u64) -> ContractAddress {
    ContractAddress::derive(
        &crate::state::DEFAULT_TEST_NETWORK_ID,
        &ALICE_ID,
        nonce,
        DataSpaceId::UNIVERSAL,
    )
    .unwrap()
}

pub(in crate::state) fn record(name: &str) -> ContractAliasBindingRecord {
    ContractAliasBindingRecord {
        alias: format!("{name}::universal").parse().unwrap(),
        lease_expiry_ms: None,
        grace_until_ms: None,
        bound_at_ms: 1,
    }
}

pub(in crate::state) fn fixture() -> World {
    let mut world = World::default();
    let (id, account) = Account::new(ALICE_ID.clone())
        .build(&ALICE_ID)
        .into_key_value();
    world.accounts.insert(id, account);
    world
        .contract_alias_bindings
        .insert(address(0), record("router"));
    world.rebuild_contract_alias_indexes().unwrap();
    world
}
