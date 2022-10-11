#![allow(clippy::restriction)]

use std::{str::FromStr as _, time::Duration};

use eyre::{eyre, Result};
use iroha_client::client::{self, Client};
use iroha_core::prelude::*;
use iroha_data_model::prelude::*;
use iroha_permissions_validators::public_blockchain::{
    key_value::{CanRemoveKeyValueInUserMetadata, CanSetKeyValueInUserMetadata},
    transfer,
};
use test_network::*;

#[ignore = "ignore, more in #2851"]
#[test]
fn add_role_to_limit_transfer_count() -> Result<()> {
    const PERIOD_MS: u64 = 5000;
    const COUNT: u32 = 2;

    // Setting up client and peer.
    // Peer has a special permission validator we need for this test
    let (_rt, _peer, mut test_client) = <PeerBuilder>::new()
        .with_instruction_judge(Box::new(
            JudgeBuilder::with_recursive_validator(transfer::ExecutionCountFitsInLimit)
                .with_validator(AllowAll::new().into_validator())
                .no_denies()
                .at_least_one_allow()
                .build(),
        ))
        .with_query_judge(Box::new(AllowAll::new()))
        .start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let alice_id = <Account as Identifiable>::Id::from_str("alice@wonderland")?;
    let mouse_id = <Account as Identifiable>::Id::from_str("mouse@wonderland")?;
    let rose_definition_id = <AssetDefinition as Identifiable>::Id::from_str("rose#wonderland")?;
    let alice_rose_id =
        <Asset as Identifiable>::Id::new(rose_definition_id.clone(), alice_id.clone());
    let mouse_rose_id = <Asset as Identifiable>::Id::new(rose_definition_id, mouse_id.clone());
    let role_id = <Role as Identifiable>::Id::from_str("non_privileged_user")?;
    let rose_value = get_asset_value(&mut test_client, alice_rose_id.clone())?;

    // Alice already has roses from genesis
    assert!(rose_value > COUNT + 1);

    // Registering Mouse
    let register_mouse = RegisterBox::new(Account::new(mouse_id, []));
    test_client.submit_blocking(register_mouse)?;

    // Registering new role which sets `Transfer` execution count limit to
    // `COUNT` for every `PERIOD_MS` milliseconds
    let permission_token =
        transfer::CanTransferOnlyFixedNumberOfTimesPerPeriod::new(PERIOD_MS.into(), COUNT);
    let register_role =
        RegisterBox::new(Role::new(role_id.clone()).add_permission(permission_token));
    test_client.submit_blocking(register_role)?;

    // Granting new role to Alice
    let grant_role = GrantBox::new(role_id, alice_id);
    test_client.submit_blocking(grant_role)?;

    // Exhausting limit
    let transfer_rose =
        TransferBox::new(alice_rose_id.clone(), Value::U32(1), mouse_rose_id.clone());
    for _ in 0..COUNT {
        test_client.submit_blocking(transfer_rose.clone())?;
    }
    let new_alice_rose_value = get_asset_value(&mut test_client, alice_rose_id.clone())?;
    let new_mouse_rose_value = get_asset_value(&mut test_client, mouse_rose_id.clone())?;
    assert_eq!(new_alice_rose_value, rose_value - COUNT);
    assert_eq!(new_mouse_rose_value, COUNT);

    // Checking that Alice can't do one more transfer
    if test_client.submit_blocking(transfer_rose.clone()).is_ok() {
        return Err(eyre!("Transfer passed when it shouldn't"));
    }

    // Waiting for a new period
    std::thread::sleep(Duration::from_millis(PERIOD_MS));

    // Transferring one more rose from Alice to Mouse
    test_client.submit_blocking(transfer_rose)?;
    let new_alice_rose_value = get_asset_value(&mut test_client, alice_rose_id)?;
    let new_mouse_rose_value = get_asset_value(&mut test_client, mouse_rose_id)?;
    assert_eq!(new_alice_rose_value, rose_value - COUNT - 1);
    assert_eq!(new_mouse_rose_value, COUNT + 1);

    Ok(())
}

fn get_asset_value(client: &mut Client, asset_id: AssetId) -> Result<u32> {
    let asset = client.request(client::asset::by_id(asset_id))?;
    Ok(*TryAsRef::<u32>::try_as_ref(asset.value())?)
}

#[test]
fn register_empty_role() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let role_id = "root".parse().expect("Valid");
    let register_role = RegisterBox::new(Role::new(role_id));

    test_client.submit(register_role)?;
    Ok(())
}

#[test]
fn register_role_with_empty_token_params() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let role_id = "root".parse().expect("Valid");
    let token = PermissionToken::new("token".parse().expect("Valid"));
    let role = Role::new(role_id).add_permission(token);

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
///
/// @s8sato added: This test represents #2081 case.
#[test]
fn register_and_grant_role_for_metadata_access() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let alice_id = <Account as Identifiable>::Id::from_str("alice@wonderland")?;
    let mouse_id = <Account as Identifiable>::Id::from_str("mouse@wonderland")?;

    // Registering Mouse
    let mouse_key_pair = KeyPair::generate()?;
    let register_mouse = RegisterBox::new(Account::new(
        mouse_id.clone(),
        [mouse_key_pair.public_key().clone()],
    ));
    test_client.submit_blocking(register_mouse)?;

    // Registering role
    let role_id = <Role as Identifiable>::Id::from_str("ACCESS_TO_MOUSE_METADATA")?;
    let role = iroha_data_model::role::Role::new(role_id.clone())
        .add_permission(CanSetKeyValueInUserMetadata::new(mouse_id.clone()))
        .add_permission(CanRemoveKeyValueInUserMetadata::new(mouse_id.clone()));
    let register_role = RegisterBox::new(role);
    test_client.submit_blocking(register_role)?;

    // Mouse grants role to Alice
    let grant_role = GrantBox::new(role_id.clone(), alice_id.clone());
    let grant_role_tx = Transaction::new(mouse_id.clone(), vec![grant_role.into()].into(), 100_000)
        .sign(mouse_key_pair)?;
    test_client.submit_transaction_blocking(grant_role_tx)?;

    // Alice modifies Mouse's metadata
    let set_key_value = SetKeyValueBox::new(
        mouse_id,
        Name::from_str("key").expect("Valid"),
        Value::String("value".to_owned()),
    );
    test_client.submit_blocking(set_key_value)?;

    // Making request to find Alice's roles
    let found_role_ids = test_client.request(client::role::by_account_id(alice_id))?;
    assert!(found_role_ids.contains(&role_id));

    Ok(())
}

#[test]
fn unregistered_role_removed_from_account() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let role_id: <Role as Identifiable>::Id = "root".parse().expect("Valid");
    let alice_id: <Account as Identifiable>::Id = "alice@wonderland".parse().expect("Valid");
    let mouse_id: <Account as Identifiable>::Id = "mouse@wonderland".parse().expect("Valid");

    // Registering Mouse
    let register_mouse = RegisterBox::new(Account::new(mouse_id.clone(), []));
    test_client.submit_blocking(register_mouse)?;

    // Register root role
    let register_role = RegisterBox::new(
        Role::new(role_id.clone()).add_permission(CanSetKeyValueInUserMetadata::new(alice_id)),
    );
    test_client.submit_blocking(register_role)?;

    // Grant root role to Mouse
    let grant_role = GrantBox::new(role_id.clone(), mouse_id.clone());
    test_client.submit_blocking(grant_role)?;

    // Check that Mouse has root role
    let found_alice_roles = test_client.request(client::role::by_account_id(mouse_id.clone()))?;
    assert!(found_alice_roles.contains(&role_id));

    // Unregister root role
    let unregister_role = UnregisterBox::new(role_id.clone());
    test_client.submit_blocking(unregister_role)?;

    // Check that Mouse doesn't have the root role
    let found_alice_roles = test_client.request(client::role::by_account_id(mouse_id))?;
    assert!(!found_alice_roles.contains(&role_id));

    Ok(())
}
