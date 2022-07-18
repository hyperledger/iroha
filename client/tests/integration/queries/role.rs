#![allow(clippy::restriction)]

use std::collections::HashSet;

use eyre::Result;
use iroha_client::client;
use iroha_core::smartcontracts::isi::query::Error as QueryError;
use iroha_data_model::prelude::*;
use iroha_permissions_validators::public_blockchain::key_value::CanSetKeyValueInUserMetadata;
use test_network::*;

fn create_role_ids() -> [<Role as Identifiable>::Id; 5] {
    [
        "a".parse().expect("Valid"),
        "b".parse().expect("Valid"),
        "c".parse().expect("Valid"),
        "d".parse().expect("Valid"),
        "e".parse().expect("Valid"),
    ]
}

#[test]
fn find_roles() -> Result<()> {
    prepare_test_for_nextest!();
    let (_rt, _peer, test_client) = <PeerBuilder>::new().start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let role_ids = create_role_ids();

    // Registering roles
    let register_roles = role_ids
        .iter()
        .cloned()
        .map(|role_id| RegisterBox::new(Role::new(role_id)).into())
        .collect::<Vec<_>>();
    test_client.submit_all_blocking(register_roles)?;

    let role_ids = HashSet::from(role_ids);

    // Checking results
    let found_role_ids = test_client
        .request(client::role::all())?
        .into_iter()
        .map(|role| role.id().clone())
        .collect::<HashSet<_>>();

    assert_eq!(found_role_ids, role_ids);

    Ok(())
}

#[test]
fn find_role_ids() -> Result<()> {
    prepare_test_for_nextest!();
    let (_rt, _peer, test_client) = <PeerBuilder>::new().start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let role_ids = create_role_ids();

    // Registering roles
    let register_roles = role_ids
        .iter()
        .cloned()
        .map(|role_id| RegisterBox::new(Role::new(role_id)).into())
        .collect::<Vec<_>>();
    test_client.submit_all_blocking(register_roles)?;

    let role_ids = HashSet::from(role_ids);

    // Checking results
    let found_role_ids = test_client.request(client::role::all_ids())?;
    let found_role_ids = found_role_ids.into_iter().collect::<HashSet<_>>();

    assert_eq!(found_role_ids, role_ids);

    Ok(())
}

#[test]
fn find_role_by_id() -> Result<()> {
    prepare_test_for_nextest!();
    let (_rt, _peer, test_client) = <PeerBuilder>::new().start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let role_id: <Role as Identifiable>::Id = "root".parse().expect("Valid");
    let new_role = Role::new(role_id.clone());

    // Registering role
    let register_role = RegisterBox::new(new_role.clone());
    test_client.submit_blocking(register_role)?;

    let found_role = test_client.request(client::role::by_id(role_id))?;

    assert_eq!(found_role.id(), new_role.build().id());
    assert!(found_role.permissions().next().is_none());

    Ok(())
}

#[test]
fn find_unregistered_role_by_id() {
    prepare_test_for_nextest!();
    let (_rt, _peer, test_client) = <PeerBuilder>::new().start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let role_id: <Role as Identifiable>::Id = "root".parse().expect("Valid");

    let found_role = test_client.request(client::role::by_id(role_id));

    // Checking result
    // Not found error
    assert!(matches!(
        found_role,
        Err(client::ClientQueryError::QueryError(QueryError::Find(_)))
    ));
}

#[test]
fn find_roles_by_account_id() -> Result<()> {
    prepare_test_for_nextest!();
    let (_rt, _peer, test_client) = <PeerBuilder>::new().start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let role_ids = create_role_ids();
    let alice_id: <Account as Identifiable>::Id = "alice@wonderland".parse().expect("Valid");

    // Registering roles
    let register_roles = role_ids
        .iter()
        .cloned()
        .map(|role_id| {
            RegisterBox::new(
                Role::new(role_id)
                    .add_permission(CanSetKeyValueInUserMetadata::new(alice_id.clone())),
            )
            .into()
        })
        .collect::<Vec<_>>();
    test_client.submit_all_blocking(register_roles)?;

    // Granting roles to account
    let grant_roles = role_ids
        .iter()
        .cloned()
        .map(|role_id| GrantBox::new(role_id, alice_id.clone()).into())
        .collect::<Vec<_>>();
    test_client.submit_all_blocking(grant_roles)?;

    let role_ids = HashSet::from(role_ids);

    // Checking results
    let found_role_ids = test_client.request(client::role::by_account_id(alice_id))?;
    let found_role_ids = found_role_ids.into_iter().collect::<HashSet<_>>();

    assert_eq!(found_role_ids, role_ids);

    Ok(())
}
