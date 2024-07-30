use std::collections::HashSet;

use eyre::Result;
use iroha::{client, data_model::prelude::*};
use iroha_data_model::query::builder::SingleQueryError;
use iroha_executor_data_model::permission::account::CanSetKeyValueInAccount;
use test_network::*;
use test_samples::ALICE_ID;

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
        .map(|role_id| Register::role(Role::new(role_id)))
        .collect::<Vec<_>>();
    test_client.submit_all_blocking(register_roles)?;

    let role_ids = HashSet::from(role_ids);

    // Checking results
    let found_role_ids = test_client
        .query(client::role::all())
        .execute_all()?
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
        .map(|role_id| Register::role(Role::new(role_id)))
        .collect::<Vec<_>>();
    test_client.submit_all_blocking(register_roles)?;

    let role_ids = HashSet::from(role_ids);

    // Checking results
    let found_role_ids = test_client.query(client::role::all_ids()).execute_all()?;
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
    let register_role = Register::role(new_role.clone());
    test_client.submit_blocking(register_role)?;

    let found_role = test_client
        .query(client::role::all())
        .filter_with(|role| role.id.eq(role_id))
        .execute_single()?;

    assert_eq!(found_role.id(), new_role.id());
    assert!(found_role.permissions().next().is_none());

    Ok(())
}

#[test]
fn find_unregistered_role_by_id() {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_540).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

    let role_id: RoleId = "root".parse().expect("Valid");

    let found_role = test_client
        .query(client::role::all())
        .filter_with(|role| role.id.eq(role_id))
        .execute_single();

    // Checking result
    // Not found error
    assert!(matches!(
        found_role,
        Err(SingleQueryError::ExpectedOneGotNone)
    ));
}

#[test]
fn find_roles_by_account_id() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_545).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

    let role_ids = create_role_ids();
    let alice_id = ALICE_ID.clone();

    // Registering roles
    let register_roles = role_ids
        .iter()
        .cloned()
        .map(|role_id| {
            Register::role(Role::new(role_id).add_permission(CanSetKeyValueInAccount {
                account: alice_id.clone(),
            }))
        })
        .collect::<Vec<_>>();
    test_client.submit_all_blocking(register_roles)?;

    // Granting roles to account
    let grant_roles = role_ids
        .iter()
        .cloned()
        .map(|role_id| Grant::role(role_id, alice_id.clone()))
        .collect::<Vec<_>>();
    test_client.submit_all_blocking(grant_roles)?;

    let role_ids = HashSet::from(role_ids);

    // Checking results
    let found_role_ids = test_client
        .query(client::role::by_account_id(alice_id))
        .execute_all()?;
    let found_role_ids = found_role_ids.into_iter().collect::<HashSet<_>>();

    assert!(role_ids.is_subset(&found_role_ids));

    Ok(())
}
