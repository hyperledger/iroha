use executor_custom_data_model::permissions::CanControlDomainLives;
use eyre::Result;
use iroha::{
    client,
    data_model::{prelude::*, transaction::error::TransactionRejectionReason},
};
use iroha_executor_data_model::permission::account::CanModifyAccountMetadata;
use iroha_test_network::*;
use iroha_test_samples::{gen_account_in, ALICE_ID};
use serde_json::json;

#[test]
fn register_empty_role() -> Result<()> {
    let (network, _rt) = NetworkBuilder::new().start_blocking()?;
    let test_client = network.client();

    let role_id = "root".parse().expect("Valid");
    let register_role = Register::role(Role::new(role_id, ALICE_ID.clone()));

    test_client.submit(register_role)?;
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
    let (network, _rt) = NetworkBuilder::new().start_blocking()?;
    let test_client = network.client();

    let alice_id = ALICE_ID.clone();
    let (mouse_id, mouse_keypair) = gen_account_in("wonderland");

    // Registering Mouse
    let register_mouse = Register::account(Account::new(mouse_id.clone()));
    test_client.submit_blocking(register_mouse)?;

    // Registering role
    let role_id = "ACCESS_TO_MOUSE_METADATA".parse::<RoleId>()?;
    let role =
        Role::new(role_id.clone(), mouse_id.clone()).add_permission(CanModifyAccountMetadata {
            account: mouse_id.clone(),
        });
    let register_role = Register::role(role);
    test_client.submit_blocking(register_role)?;

    // Mouse grants role to Alice
    let grant_role = Grant::account_role(role_id.clone(), alice_id.clone());
    let grant_role_tx = TransactionBuilder::new(network.chain_id(), mouse_id.clone())
        .with_instructions([grant_role])
        .sign(mouse_keypair.private_key());
    test_client.submit_transaction_blocking(&grant_role_tx)?;

    // Alice modifies Mouse's metadata
    let set_key_value = SetKeyValue::account(
        mouse_id,
        "key".parse::<Name>()?,
        "value".parse::<JsonString>()?,
    );
    test_client.submit_blocking(set_key_value)?;

    // Making request to find Alice's roles
    let found_role_ids = test_client
        .query(client::role::by_account_id(alice_id))
        .execute_all()?;
    assert!(found_role_ids.contains(&role_id));

    Ok(())
}

#[test]
fn unregistered_role_removed_from_account() -> Result<()> {
    let (network, _rt) = NetworkBuilder::new().start_blocking()?;
    let test_client = network.client();

    let role_id: RoleId = "root".parse().expect("Valid");
    let alice_id = ALICE_ID.clone();
    let (mouse_id, _mouse_keypair) = gen_account_in("wonderland");

    // Registering Mouse
    let register_mouse = Register::account(Account::new(mouse_id.clone()));
    test_client.submit_blocking(register_mouse)?;

    // Register root role
    let register_role = Register::role(
        Role::new(role_id.clone(), alice_id.clone())
            .add_permission(CanModifyAccountMetadata { account: alice_id }),
    );
    test_client.submit_blocking(register_role)?;

    // Grant root role to Mouse
    let grant_role = Grant::account_role(role_id.clone(), mouse_id.clone());
    test_client.submit_blocking(grant_role)?;

    // Check that Mouse has root role
    let found_mouse_roles = test_client
        .query(client::role::by_account_id(mouse_id.clone()))
        .execute_all()?;
    assert!(found_mouse_roles.contains(&role_id));

    // Unregister root role
    let unregister_role = Unregister::role(role_id.clone());
    test_client.submit_blocking(unregister_role)?;

    // Check that Mouse doesn't have the root role
    let found_mouse_roles = test_client
        .query(client::role::by_account_id(mouse_id.clone()))
        .execute_all()?;
    assert!(!found_mouse_roles.contains(&role_id));

    Ok(())
}

#[test]
fn role_with_invalid_permissions_is_not_accepted() -> Result<()> {
    let (network, _rt) = NetworkBuilder::new().start_blocking()?;
    let test_client = network.client();

    let role_id = "ACCESS_TO_ACCOUNT_METADATA".parse()?;
    let role = Role::new(role_id, ALICE_ID.clone()).add_permission(CanControlDomainLives);

    let err = test_client
        .submit_blocking(Register::role(role))
        .expect_err("Submitting role with non-existing permission should fail");

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
// NOTE: Permissions in this test are created explicitly as json strings
// so that they don't get deduplicated eagerly but rather in the executor
// This way, if the executor compares permissions just as JSON strings, the test will fail
fn role_permissions_are_deduplicated() {
    let (network, _rt) = NetworkBuilder::new().start_blocking().unwrap();
    let test_client = network.client();

    let allow_alice_to_transfer_rose_1 = Permission::new(
        "CanTransferAsset".parse().unwrap(),
        json!({ "asset": "rose#wonderland#ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03@wonderland" }),
    );

    // Different content, but same meaning
    let allow_alice_to_transfer_rose_2 = Permission::new(
        "CanTransferAsset".parse().unwrap(),
        json!({ "asset": "rose##ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03@wonderland" }),
    );

    let role_id: RoleId = "role_id".parse().expect("Valid");
    let role = Role::new(role_id.clone(), ALICE_ID.clone())
        .add_permission(allow_alice_to_transfer_rose_1)
        .add_permission(allow_alice_to_transfer_rose_2);

    test_client
        .submit_blocking(Register::role(role))
        .expect("failed to register role");

    let role = test_client
        .query(client::role::all())
        .filter_with(|role| role.id.eq(role_id))
        .execute_single()
        .expect("failed to find role");

    // Permissions are unified so only one is left
    assert_eq!(
        role.permissions().len(),
        1,
        "permissions for role aren't deduplicated"
    );
}

#[test]
fn grant_revoke_role_permissions() -> Result<()> {
    let (network, _rt) = NetworkBuilder::new().start_blocking()?;
    let test_client = network.client();

    let alice_id = ALICE_ID.clone();
    let (mouse_id, mouse_keypair) = gen_account_in("wonderland");

    // Registering Mouse
    let register_mouse = Register::account(Account::new(mouse_id.clone()));
    test_client.submit_blocking(register_mouse)?;

    // Registering role
    let role_id = "ACCESS_TO_MOUSE_METADATA".parse::<RoleId>()?;
    let role = Role::new(role_id.clone(), mouse_id.clone());
    let register_role = Register::role(role);
    test_client.submit_blocking(register_role)?;

    // Transfer domain ownership to Mouse
    let domain_id = "wonderland".parse::<DomainId>()?;
    let transfer_domain = Transfer::domain(alice_id.clone(), domain_id, mouse_id.clone());
    test_client.submit_blocking(transfer_domain)?;

    // Mouse grants role to Alice
    let grant_role = Grant::account_role(role_id.clone(), alice_id.clone());
    let grant_role_tx = TransactionBuilder::new(network.chain_id(), mouse_id.clone())
        .with_instructions([grant_role])
        .sign(mouse_keypair.private_key());
    test_client.submit_transaction_blocking(&grant_role_tx)?;

    let set_key_value = SetKeyValue::account(
        mouse_id.clone(),
        "key".parse()?,
        "value".parse::<JsonString>()?,
    );
    let can_set_key_value_in_mouse = CanModifyAccountMetadata {
        account: mouse_id.clone(),
    };
    let grant_role_permission =
        Grant::role_permission(can_set_key_value_in_mouse.clone(), role_id.clone());
    let revoke_role_permission =
        Revoke::role_permission(can_set_key_value_in_mouse.clone(), role_id.clone());

    // Alice can't modify Mouse's metadata without proper permission
    assert!(!test_client
        .query(client::permission::by_account_id(alice_id.clone()))
        .execute_all()?
        .iter()
        .any(|permission| {
            CanModifyAccountMetadata::try_from(permission)
                .is_ok_and(|permission| permission == can_set_key_value_in_mouse)
        }));
    let _ = test_client
        .submit_blocking(set_key_value.clone())
        .expect_err("shouldn't be able to modify metadata");

    // Alice can modify Mouse's metadata after permission is granted to role
    let grant_role_permission_tx = TransactionBuilder::new(network.chain_id(), mouse_id.clone())
        .with_instructions([grant_role_permission])
        .sign(mouse_keypair.private_key());
    test_client.submit_transaction_blocking(&grant_role_permission_tx)?;
    assert!(test_client
        .query(client::role::by_account_id(alice_id.clone()))
        .execute_all()?
        .iter()
        .any(|account_role_id| *account_role_id == role_id));
    test_client.submit_blocking(set_key_value.clone())?;

    // Alice can't modify Mouse's metadata after permission is removed from role
    let revoke_role_permission_tx = TransactionBuilder::new(network.chain_id(), mouse_id)
        .with_instructions([revoke_role_permission])
        .sign(mouse_keypair.private_key());
    test_client.submit_transaction_blocking(&revoke_role_permission_tx)?;
    assert!(!test_client
        .query(client::permission::by_account_id(alice_id.clone()))
        .execute_all()?
        .iter()
        .any(|permission| {
            CanModifyAccountMetadata::try_from(permission)
                .is_ok_and(|permission| permission == can_set_key_value_in_mouse)
        }));
    let _ = test_client
        .submit_blocking(set_key_value)
        .expect_err("shouldn't be able to modify metadata");

    Ok(())
}
