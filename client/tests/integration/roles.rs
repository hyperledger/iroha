#![allow(clippy::restriction)]

use std::{str::FromStr as _, time::Duration};

use eyre::{eyre, Result};
use iroha_client::client::{self, Client};
use iroha_core::{prelude::AllowAll, smartcontracts::permissions::ValidatorBuilder};
use iroha_data_model::prelude::*;
use iroha_permissions_validators::public_blockchain::{
    key_value::{CanRemoveKeyValueInUserMetadata, CanSetKeyValueInUserMetadata},
    transfer,
};
use test_network::{Peer as TestPeer, *};
use tokio::runtime::Runtime;

#[test]
fn add_role_to_limit_transfer_count() -> Result<()> {
    const PERIOD_MS: u64 = 5000;
    const COUNT: u32 = 2;

    // Setting up client and peer.
    // Peer has a special permission validator we need for this test
    let rt = Runtime::test();
    let (_peer, mut test_client) = rt.block_on(<TestPeer>::start_test_with_permissions(
        ValidatorBuilder::new()
            .with_recursive_validator(transfer::ExecutionCountFitsInLimit)
            .all_should_succeed(),
        AllowAll.into(),
    ));
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let alice_id = <Account as Identifiable>::Id::from_str("alice@wonderland")?;
    let bob_id = <Account as Identifiable>::Id::from_str("bob@wonderland")?;
    let rose_definition_id = <AssetDefinition as Identifiable>::Id::from_str("rose#wonderland")?;
    let alice_rose_id =
        <Asset as Identifiable>::Id::new(rose_definition_id.clone(), alice_id.clone());
    let bob_rose_id = <Asset as Identifiable>::Id::new(rose_definition_id, bob_id.clone());
    let role_id = <Role as Identifiable>::Id::from_str("non_privileged_user")?;
    let rose_value = get_asset_value(&mut test_client, alice_rose_id.clone())?;

    // Alice already has roses from genesis
    assert!(rose_value > COUNT + 1);

    // Registering Bob
    let register_bob = RegisterBox::new(Account::new(bob_id, []));
    test_client.submit_blocking(register_bob)?;

    // Registering new role which sets `Transfer` execution count limit to
    // `COUNT` for every `PERIOD_MS` milliseconds
    let permission_token =
        transfer::CanTransferOnlyFixedNumberOfTimesPerPeriod::new(PERIOD_MS.into(), COUNT);
    let register_role = RegisterBox::new(Role::new(role_id.clone(), vec![permission_token]));
    test_client.submit_blocking(register_role)?;

    // Granting new role to Alice
    let grant_role = GrantBox::new(role_id, alice_id);
    test_client.submit_blocking(grant_role)?;

    // Exhausting limit
    let transfer_rose = TransferBox::new(alice_rose_id.clone(), Value::U32(1), bob_rose_id.clone());
    for _ in 0..COUNT {
        test_client.submit_blocking(transfer_rose.clone())?;
    }
    let new_alice_rose_value = get_asset_value(&mut test_client, alice_rose_id.clone())?;
    let new_bob_rose_value = get_asset_value(&mut test_client, bob_rose_id.clone())?;
    assert_eq!(new_alice_rose_value, rose_value - COUNT);
    assert_eq!(new_bob_rose_value, COUNT);

    // Checking that Alice can't do one more transfer
    if test_client.submit_blocking(transfer_rose.clone()).is_ok() {
        return Err(eyre!("Transfer passed when it shouldn't"));
    }

    // Waiting for a new period
    std::thread::sleep(Duration::from_millis(PERIOD_MS));

    // Transfering one more rose from Alice to Bob
    test_client.submit_blocking(transfer_rose)?;
    let new_alice_rose_value = get_asset_value(&mut test_client, alice_rose_id)?;
    let new_bob_rose_value = get_asset_value(&mut test_client, bob_rose_id)?;
    assert_eq!(new_alice_rose_value, rose_value - COUNT - 1);
    assert_eq!(new_bob_rose_value, COUNT + 1);

    Ok(())
}

fn get_asset_value(client: &mut Client, asset_id: AssetId) -> Result<u32> {
    let asset = client.request(client::asset::by_id(asset_id))?;
    Ok(*TryAsRef::<u32>::try_as_ref(asset.value())?)
}

#[test]
fn register_empty_role() -> Result<()> {
    let (_rt, _peer, mut test_client) = <TestPeer>::start_test_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let role_id = "root".parse().expect("Valid");
    let register_role = RegisterBox::new(NewRole::new(role_id).build());

    test_client.submit(register_role)?;
    Ok(())
}

#[test]
fn register_role_with_empty_token_params() -> Result<()> {
    let (_rt, _peer, mut test_client) = <TestPeer>::start_test_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let role_id = "root".parse().expect("Valid");
    let token = PermissionToken::new("token".parse().expect("Valid"));
    let role = NewRole::new(role_id).add_permission(token).build();

    test_client.submit(RegisterBox::new(role))?;
    Ok(())
}

// TODO: When we have more sane default permissions, see if we can
// test more about whether or not roles actually work.

/// Test meant to mirror the test of the same name in the Iroha Kotlin
/// SDK. This doesn't actually test the functionality of the role
/// granted, merely that the role can be constructed and
/// registered. Once @appetrosyan (me) is onboarded into the Kotlin
/// SDK, I'll update both tests to actually verify functionality.
#[test]
fn register_metadata_role() -> Result<()> {
    let (_rt, _peer, mut test_client) = <TestPeer>::start_test_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let bob_id = <Account as Identifiable>::Id::from_str("bob@wonderland")?;
    let register_bob = RegisterBox::new(Account::new(bob_id.clone(), []));
    test_client.submit_blocking(register_bob)?;

    let role_id = "USER_METADATA_ACCESS".parse().expect("Valid");

    let role = iroha_data_model::role::NewRole::new(role_id)
        .add_permission(CanSetKeyValueInUserMetadata::new(bob_id.clone()))
        .add_permission(CanRemoveKeyValueInUserMetadata::new(bob_id))
        .build();
    let register_role = RegisterBox::new(role);
    test_client.submit(register_role)?;
    Ok(())
}
