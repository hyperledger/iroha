//! Tests queries for retrieving roles and their identifiers.
use eyre::Result;
use integration_tests::sandbox;
use iroha::data_model::prelude::*;
use iroha_executor_data_model::permission::account::CanModifyAccountMetadata;
use iroha_test_network::*;
use iroha_test_samples::ALICE_ID;
use std::{
    collections::HashSet,
    thread::sleep,
    time::{Duration, Instant},
};
fn create_role_ids() -> [RoleId; 5] {
    [
        "a".parse().expect("Valid"),
        "b".parse().expect("Valid"),
        "c".parse().expect("Valid"),
        "d".parse().expect("Valid"),
        "e".parse().expect("Valid"),
    ]
}
fn start_network(
    context: &'static str,
) -> Option<(sandbox::SerializedNetwork, tokio::runtime::Runtime)> {
    sandbox::start_network_blocking_or_skip(NetworkBuilder::new(), context).unwrap()
}
#[test]
fn find_roles() -> Result<()> {
    let Some((network, rt)) = start_network(stringify!(find_roles)) else {
        return Ok(());
    };
    let test_client = network.client();
    let role_ids = create_role_ids();
    // Registering roles
    let register_roles = role_ids
        .iter()
        .cloned()
        .map(|role_id| Register::role(Role::new(role_id, ALICE_ID.clone())))
        .collect::<Vec<_>>();
    if sandbox::handle_result(
        test_client.submit_all(
            register_roles,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        ),
        stringify!(find_roles),
    )?
    .is_none()
    {
        return Ok(());
    }
    rt.block_on(async { network.ensure_blocks(1).await })?;
    let role_ids = HashSet::from(role_ids);
    // Checking results
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let found_role_ids = match sandbox::handle_result(
            test_client
                .client()
                .query(FindRoles::new())
                .execute_all()
                .map_err(Into::into),
            stringify!(find_roles),
        )? {
            Some(found_role_ids) => found_role_ids
                .into_iter()
                .map(|role| role.id().clone())
                .collect::<HashSet<_>>(),
            None => return Ok(()),
        };
        if role_ids.is_subset(&found_role_ids) {
            break;
        }
        if Instant::now() >= deadline {
            assert!(
                role_ids.is_subset(&found_role_ids),
                "expected registered roles {role_ids:?} to be included in {found_role_ids:?}"
            );
        }
        sleep(Duration::from_millis(250));
    }
    Ok(())
}
#[test]
fn find_role_ids() -> Result<()> {
    let Some((network, _rt)) = start_network(stringify!(find_role_ids)) else {
        return Ok(());
    };
    let test_client = network.client();
    let role_ids = create_role_ids();
    // Registering roles
    let register_roles = role_ids
        .iter()
        .cloned()
        .map(|role_id| Register::role(Role::new(role_id, ALICE_ID.clone())))
        .collect::<Vec<_>>();
    if sandbox::handle_result(
        test_client.submit_all(
            register_roles,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        ),
        stringify!(find_role_ids),
    )?
    .is_none()
    {
        return Ok(());
    }
    let role_ids = HashSet::from(role_ids);
    // Checking results
    let found_role_ids = match sandbox::handle_result(
        test_client
            .client()
            .query(FindRoleIds::new())
            .execute_all()
            .map_err(Into::into),
        stringify!(find_role_ids),
    )? {
        Some(found_role_ids) => found_role_ids,
        None => return Ok(()),
    };
    let found_role_ids = found_role_ids.into_iter().collect::<HashSet<_>>();
    assert!(role_ids.is_subset(&found_role_ids));
    Ok(())
}
#[test]
fn find_role_by_id() -> Result<()> {
    let Some((network, _rt)) = start_network(stringify!(find_role_by_id)) else {
        return Ok(());
    };
    let test_client = network.client();
    let role_id: RoleId = "root".parse().expect("Valid");
    let new_role = Role::new(role_id.clone(), ALICE_ID.clone());
    // Registering role
    let register_role = Register::role(new_role.clone());
    if sandbox::handle_result(
        test_client.submit(
            register_role,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        ),
        stringify!(find_role_by_id),
    )?
    .is_none()
    {
        return Ok(());
    }
    let found_role = match sandbox::handle_result(
        test_client
            .client()
            .query(FindRoles::new())
            .execute_all()
            .map_err(Into::into), // lightweight DSL: filter in client
        stringify!(find_role_by_id),
    )? {
        Some(found_roles) => found_roles
            .into_iter()
            .find(|role| role.id() == &role_id)
            .expect("role should exist"),
        None => return Ok(()),
    };
    assert_eq!(found_role.id(), new_role.id());
    assert!(found_role.permissions().next().is_none());
    Ok(())
}
#[test]
fn find_unregistered_role_by_id() {
    let Some((network, _rt)) = start_network(stringify!(find_unregistered_role_by_id)) else {
        return;
    };
    let test_client = network.client();
    let role_id: RoleId = "root".parse().expect("Valid");
    let found_role = test_client
        .client()
        .query(FindRoles::new())
        .execute_all()
        .unwrap()
        .into_iter()
        .find(|role| role.id() == &role_id);
    // Not found
    assert!(found_role.is_none());
}
#[test]
fn find_roles_by_account_id() -> Result<()> {
    let Some((network, _rt)) = start_network(stringify!(find_roles_by_account_id)) else {
        return Ok(());
    };
    let test_client = network.client();
    let role_ids = create_role_ids();
    let alice_id = ALICE_ID.clone();
    // Registering roles
    let register_roles = role_ids
        .iter()
        .cloned()
        .map(|role_id| {
            Register::role(Role::new(role_id, alice_id.clone()).add_permission(
                CanModifyAccountMetadata {
                    account: alice_id.clone(),
                },
            ))
        })
        .collect::<Vec<_>>();
    if sandbox::handle_result(
        test_client.submit_all(
            register_roles,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        ),
        stringify!(find_roles_by_account_id),
    )?
    .is_none()
    {
        return Ok(());
    }
    let role_ids = HashSet::from(role_ids);
    // Checking results
    let found_role_ids = match sandbox::handle_result(
        test_client
            .client()
            .query(FindRolesByAccountId::new(alice_id))
            .execute_all()
            .map_err(Into::into),
        stringify!(find_roles_by_account_id),
    )? {
        Some(ids) => ids,
        None => return Ok(()),
    };
    let found_role_ids = found_role_ids.into_iter().collect::<HashSet<_>>();
    assert!(role_ids.is_subset(&found_role_ids));
    Ok(())
}
