use std::str::FromStr as _;

use eyre::Result;
use iroha_client::{
    client::{self, QueryResult},
    data_model::prelude::*,
};
use iroha_data_model::transaction::error::TransactionRejectionReason;
use serde_json::json;
use test_network::*;
use test_samples::{gen_account_in, ALICE_ID};

#[test]
fn register_empty_role() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_695).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let role_id = "root".parse().expect("Valid");
    let register_role = Register::role(Role::new(role_id));

    test_client.submit(register_role)?;
    Ok(())
}

#[test]
fn register_role_with_empty_token_params() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_550).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let role_id = "root".parse().expect("Valid");
    let token = Permission::new("token".parse()?, json!(null).into());
    let role = Role::new(role_id).add_permission(token);

    test_client.submit(Register::role(role))?;
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
    let chain_id = ChainId::from("0");

    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_700).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let alice_id = ALICE_ID.clone();
    let (mouse_id, mouse_keypair) = gen_account_in("wonderland");

    // Registering Mouse
    let register_mouse = Register::account(Account::new(mouse_id.clone()));
    test_client.submit_blocking(register_mouse)?;

    // Registering role
    let role_id = RoleId::from_str("ACCESS_TO_MOUSE_METADATA")?;
    let role = Role::new(role_id.clone())
        .add_permission(Permission::new(
            "CanSetKeyValueInAccount".parse()?,
            json!({ "account_id": mouse_id }).into(),
        ))
        .add_permission(Permission::new(
            "CanRemoveKeyValueInAccount".parse()?,
            json!({ "account_id": mouse_id }).into(),
        ));
    let register_role = Register::role(role);
    test_client.submit_blocking(register_role)?;

    // Mouse grants role to Alice
    let grant_role = Grant::role(role_id.clone(), alice_id.clone());
    let grant_role_tx = TransactionBuilder::new(chain_id, mouse_id.clone())
        .with_instructions([grant_role])
        .sign(&mouse_keypair);
    test_client.submit_transaction_blocking(&grant_role_tx)?;

    // Alice modifies Mouse's metadata
    let set_key_value = SetKeyValue::account(
        mouse_id,
        Name::from_str("key").expect("Valid"),
        "value".to_owned(),
    );
    test_client.submit_blocking(set_key_value)?;

    // Making request to find Alice's roles
    let found_role_ids = test_client
        .request(client::role::by_account_id(alice_id))?
        .collect::<QueryResult<Vec<_>>>()?;
    assert!(found_role_ids.contains(&role_id));

    Ok(())
}

#[test]
fn unregistered_role_removed_from_account() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_705).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let role_id: RoleId = "root".parse().expect("Valid");
    let alice_id = ALICE_ID.clone();
    let (mouse_id, _mouse_keypair) = gen_account_in("wonderland");

    // Registering Mouse
    let register_mouse = Register::account(Account::new(mouse_id.clone()));
    test_client.submit_blocking(register_mouse)?;

    // Register root role
    let register_role = Register::role(Role::new(role_id.clone()).add_permission(Permission::new(
        "CanSetKeyValueInAccount".parse()?,
        json!({ "account_id": alice_id }).into(),
    )));
    test_client.submit_blocking(register_role)?;

    // Grant root role to Mouse
    let grant_role = Grant::role(role_id.clone(), mouse_id.clone());
    test_client.submit_blocking(grant_role)?;

    // Check that Mouse has root role
    let found_mouse_roles = test_client
        .request(client::role::by_account_id(mouse_id.clone()))?
        .collect::<QueryResult<Vec<_>>>()?;
    assert!(found_mouse_roles.contains(&role_id));

    // Unregister root role
    let unregister_role = Unregister::role(role_id.clone());
    test_client.submit_blocking(unregister_role)?;

    // Check that Mouse doesn't have the root role
    let found_mouse_roles = test_client
        .request(client::role::by_account_id(mouse_id))?
        .collect::<QueryResult<Vec<_>>>()?;
    assert!(!found_mouse_roles.contains(&role_id));

    Ok(())
}

#[test]
fn role_with_invalid_permissions_is_not_accepted() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(11_025).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let role_id = RoleId::from_str("ACCESS_TO_ACCOUNT_METADATA")?;
    let rose_asset_id: AssetId = format!("rose##{}", ALICE_ID.clone())
        .parse()
        .expect("should be valid");
    let role = Role::new(role_id).add_permission(Permission::new(
        "CanSetKeyValueInAccount".parse()?,
        json!({ "account_id": rose_asset_id }).into(),
    ));

    let err = test_client
        .submit_blocking(Register::role(role))
        .expect_err("Submitting role with invalid permission token should fail");

    let rejection_reason = err
        .downcast_ref::<TransactionRejectionReason>()
        .unwrap_or_else(|| panic!("Error {err} is not TransactionRejectionReason"));

    assert!(matches!(
        rejection_reason,
        &TransactionRejectionReason::Validation(ValidationFail::NotPermitted(_))
    ));

    Ok(())
}

#[test]
#[allow(deprecated)]
fn role_permissions_are_deduplicated() {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(11_235).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let allow_alice_to_transfer_rose_1 = Permission::new(
        "CanTransferUserAsset".parse().unwrap(),
        json!({ "asset_id": "rose#wonderland#ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03@wonderland" }).into(),
    );

    // Different content, but same meaning
    let allow_alice_to_transfer_rose_2 = Permission::new(
        "CanTransferUserAsset".parse().unwrap(),
        json!({ "asset_id": "rose##ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03@wonderland" }).into(),
    );

    let role_id: RoleId = "role_id".parse().expect("Valid");
    let role = Role::new(role_id.clone())
        .add_permission(allow_alice_to_transfer_rose_1)
        .add_permission(allow_alice_to_transfer_rose_2);

    test_client
        .submit_blocking(Register::role(role))
        .expect("failed to register role");

    let role = test_client
        .request(FindRoleByRoleId::new(role_id))
        .expect("failed to find role");

    // Permission tokens are unified so only one token left
    assert_eq!(
        role.permissions().len(),
        1,
        "permission tokens for role aren't deduplicated"
    );
}

#[test]
fn grant_revoke_role_permissions() -> Result<()> {
    let chain_id = ChainId::from("0");

    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(11_245).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let alice_id = ALICE_ID.clone();
    let (mouse_id, mouse_keypair) = gen_account_in("wonderland");

    // Registering Mouse
    let register_mouse = Register::account(Account::new(mouse_id.clone()));
    test_client.submit_blocking(register_mouse)?;

    // Registering role
    let role_id = RoleId::from_str("ACCESS_TO_MOUSE_METADATA")?;
    let role = Role::new(role_id.clone());
    let register_role = Register::role(role);
    test_client.submit_blocking(register_role)?;

    // Transfer domain ownership to Mouse
    let domain_id = DomainId::from_str("wonderland")?;
    let transfer_domain = Transfer::domain(alice_id.clone(), domain_id, mouse_id.clone());
    test_client.submit_blocking(transfer_domain)?;

    // Mouse grants role to Alice
    let grant_role = Grant::role(role_id.clone(), alice_id.clone());
    let grant_role_tx = TransactionBuilder::new(chain_id.clone(), mouse_id.clone())
        .with_instructions([grant_role])
        .sign(&mouse_keypair);
    test_client.submit_transaction_blocking(&grant_role_tx)?;

    let set_key_value = SetKeyValue::account(
        mouse_id.clone(),
        Name::from_str("key").expect("Valid"),
        "value".to_owned(),
    );
    let permission = Permission::new(
        "CanSetKeyValueInAccount".parse()?,
        json!({ "account_id": mouse_id }).into(),
    );
    let grant_role_permission = Grant::role_permission(permission.clone(), role_id.clone());
    let revoke_role_permission = Revoke::role_permission(permission.clone(), role_id.clone());

    // Alice can't modify Mouse's metadata without proper permission token
    let found_permissions = test_client
        .request(FindPermissionsByAccountId::new(alice_id.clone()))?
        .collect::<QueryResult<Vec<_>>>()?;
    assert!(!found_permissions.contains(&permission));
    let _ = test_client
        .submit_blocking(set_key_value.clone())
        .expect_err("shouldn't be able to modify metadata");

    // Alice can modify Mouse's metadata after permission token is granted to role
    let grant_role_permission_tx = TransactionBuilder::new(chain_id.clone(), mouse_id.clone())
        .with_instructions([grant_role_permission])
        .sign(&mouse_keypair);
    test_client.submit_transaction_blocking(&grant_role_permission_tx)?;
    let found_permissions = test_client
        .request(FindPermissionsByAccountId::new(alice_id.clone()))?
        .collect::<QueryResult<Vec<_>>>()?;
    assert!(found_permissions.contains(&permission));
    test_client.submit_blocking(set_key_value.clone())?;

    // Alice can't modify Mouse's metadata after permission token is removed from role
    let revoke_role_permission_tx = TransactionBuilder::new(chain_id.clone(), mouse_id.clone())
        .with_instructions([revoke_role_permission])
        .sign(&mouse_keypair);
    test_client.submit_transaction_blocking(&revoke_role_permission_tx)?;
    let found_permissions = test_client
        .request(FindPermissionsByAccountId::new(alice_id.clone()))?
        .collect::<QueryResult<Vec<_>>>()?;
    assert!(!found_permissions.contains(&permission));
    let _ = test_client
        .submit_blocking(set_key_value.clone())
        .expect_err("shouldn't be able to modify metadata");

    Ok(())
}
