#![allow(clippy::restriction)]

use std::str::FromStr as _;

use eyre::Result;
use iroha_client::client::{self};
use iroha_data_model::prelude::*;
use test_network::*;

#[test]
fn register_empty_role() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_695).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let role_id = "root".parse().expect("Valid");
    let register_role = RegisterBox::new(Role::new(role_id));

    test_client.submit(register_role)?;
    Ok(())
}

#[test]
fn register_role_with_empty_token_params() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_550).start_with_runtime();
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
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_700).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let alice_id = <Account as Identifiable>::Id::from_str("alice@wonderland")?;
    let mouse_id = <Account as Identifiable>::Id::from_str("mouse@wonderland")?;

    // Registering Mouse
    let mouse_key_pair = iroha_crypto::KeyPair::generate()?;
    let register_mouse = RegisterBox::new(Account::new(
        mouse_id.clone(),
        [mouse_key_pair.public_key().clone()],
    ));
    test_client.submit_blocking(register_mouse)?;

    // Registering role
    let role_id = <Role as Identifiable>::Id::from_str("ACCESS_TO_MOUSE_METADATA")?;
    let role = Role::new(role_id.clone())
        .add_permission(
            PermissionToken::new("can_set_key_value_in_user_account".parse()?)
                .with_params([("account_id".parse()?, mouse_id.clone().into())]),
        )
        .add_permission(
            PermissionToken::new("can_remove_key_value_in_user_account".parse()?)
                .with_params([("account_id".parse()?, mouse_id.clone().into())]),
        );
    let register_role = RegisterBox::new(role);
    test_client.submit_blocking(register_role)?;

    // Mouse grants role to Alice
    let grant_role = GrantBox::new(role_id.clone(), alice_id.clone());
    let grant_role_tx = TransactionBuilder::new(mouse_id.clone(), vec![grant_role.into()], 100_000)
        .sign(mouse_key_pair)?;
    test_client.submit_transaction_blocking(&grant_role_tx)?;

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
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_705).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let role_id: <Role as Identifiable>::Id = "root".parse().expect("Valid");
    let alice_id: <Account as Identifiable>::Id = "alice@wonderland".parse().expect("Valid");
    let mouse_id: <Account as Identifiable>::Id = "mouse@wonderland".parse().expect("Valid");

    // Registering Mouse
    let register_mouse = RegisterBox::new(Account::new(mouse_id.clone(), []));
    test_client.submit_blocking(register_mouse)?;

    // Register root role
    let register_role = RegisterBox::new(
        Role::new(role_id.clone()).add_permission(
            PermissionToken::new("can_set_key_value_in_user_account".parse()?)
                .with_params([("account_id".parse()?, alice_id.into())]),
        ),
    );
    test_client.submit_blocking(register_role)?;

    // Grant root role to Mouse
    let grant_role = GrantBox::new(role_id.clone(), mouse_id.clone());
    test_client.submit_blocking(grant_role)?;

    // Check that Mouse has root role
    let found_mouse_roles = test_client.request(client::role::by_account_id(mouse_id.clone()))?;
    assert!(found_mouse_roles.contains(&role_id));

    // Unregister root role
    let unregister_role = UnregisterBox::new(role_id.clone());
    test_client.submit_blocking(unregister_role)?;

    // Check that Mouse doesn't have the root role
    let found_mouse_roles = test_client.request(client::role::by_account_id(mouse_id))?;
    assert!(!found_mouse_roles.contains(&role_id));

    Ok(())
}
