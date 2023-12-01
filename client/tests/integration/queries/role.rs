use std::collections::HashSet;

use eyre::Result;
use iroha_client::{
    client::{self, QueryResult},
    data_model::{prelude::*, query::error::QueryExecutionFail},
};
use serde_json::json;
use test_network::*;

fn create_role_ids() -> [RoleId; 5] {
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
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_525).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

    let role_ids = create_role_ids();

    // Registering roles
    let register_roles = role_ids
        .iter()
        .cloned()
        .map(|role_id| RegisterExpr::new(Role::new(role_id)))
        .collect::<Vec<_>>();
    test_client.submit_all_blocking(register_roles)?;

    let role_ids = HashSet::from(role_ids);

    // Checking results
    let found_role_ids = test_client
        .request(client::role::all())?
        .collect::<QueryResult<Vec<_>>>()?
        .into_iter();

    assert!(role_ids.is_subset(
        &found_role_ids
            .map(|role| role.id().clone())
            .collect::<HashSet<_>>()
    ));

    Ok(())
}

#[test]
fn find_role_ids() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_530).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

    let role_ids = create_role_ids();

    // Registering roles
    let register_roles = role_ids
        .iter()
        .cloned()
        .map(|role_id| RegisterExpr::new(Role::new(role_id)))
        .collect::<Vec<_>>();
    test_client.submit_all_blocking(register_roles)?;

    let role_ids = HashSet::from(role_ids);

    // Checking results
    let found_role_ids = test_client
        .request(client::role::all_ids())?
        .collect::<QueryResult<Vec<_>>>()?;
    let found_role_ids = found_role_ids.into_iter().collect::<HashSet<_>>();

    assert!(role_ids.is_subset(&found_role_ids));

    Ok(())
}

#[test]
fn find_role_by_id() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_535).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

    let role_id: RoleId = "root".parse().expect("Valid");
    let new_role = Role::new(role_id.clone());

    // Registering role
    let register_role = RegisterExpr::new(new_role.clone());
    test_client.submit_blocking(register_role)?;

    let found_role = test_client.request(client::role::by_id(role_id))?;

    assert_eq!(found_role.id(), new_role.id());
    assert!(found_role.permissions().next().is_none());

    Ok(())
}

#[test]
fn find_unregistered_role_by_id() {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_540).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

    let role_id: RoleId = "root".parse().expect("Valid");

    let found_role = test_client.request(client::role::by_id(role_id));

    // Checking result
    // Not found error
    assert!(matches!(
        found_role,
        Err(client::ClientQueryError::Validation(
            ValidationFail::QueryFailed(QueryExecutionFail::Find(_))
        ))
    ));
}

#[test]
fn find_roles_by_account_id() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_545).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

    let role_ids = create_role_ids();
    let alice_id: AccountId = "alice@wonderland".parse().expect("Valid");

    // Registering roles
    let register_roles = role_ids
        .iter()
        .cloned()
        .map(|role_id| {
            RegisterExpr::new(Role::new(role_id).add_permission(PermissionToken::new(
                "CanSetKeyValueInUserAccount".parse().unwrap(),
                &json!({ "account_id": alice_id }),
            )))
        })
        .collect::<Vec<_>>();
    test_client.submit_all_blocking(register_roles)?;

    // Granting roles to account
    let grant_roles = role_ids
        .iter()
        .cloned()
        .map(|role_id| GrantExpr::new(role_id, alice_id.clone()))
        .collect::<Vec<_>>();
    test_client.submit_all_blocking(grant_roles)?;

    let role_ids = HashSet::from(role_ids);

    // Checking results
    let found_role_ids = test_client
        .request(client::role::by_account_id(alice_id))?
        .collect::<QueryResult<Vec<_>>>()?;
    let found_role_ids = found_role_ids.into_iter().collect::<HashSet<_>>();

    assert!(role_ids.is_subset(&found_role_ids));

    Ok(())
}
