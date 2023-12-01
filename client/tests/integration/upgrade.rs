use std::{path::Path, str::FromStr as _};

use eyre::Result;
use iroha_client::{
    client::{self, Client, QueryResult},
    crypto::KeyPair,
    data_model::prelude::*,
};
use iroha_logger::info;
use serde_json::json;
use test_network::*;

#[test]
fn executor_upgrade_should_work() -> Result<()> {
    let (_rt, _peer, client) = <PeerBuilder>::new().with_port(10_795).start_with_runtime();
    wait_for_genesis_committed(&vec![client.clone()], 0);

    // Register `admin` domain and account
    let admin_domain = Domain::new("admin".parse()?);
    let register_admin_domain = RegisterExpr::new(admin_domain);
    client.submit_blocking(register_admin_domain)?;

    let admin_id: AccountId = "admin@admin".parse()?;
    let admin_keypair = KeyPair::generate()?;
    let admin_account = Account::new(admin_id.clone(), [admin_keypair.public_key().clone()]);
    let register_admin_account = RegisterExpr::new(admin_account);
    client.submit_blocking(register_admin_account)?;

    // Check that admin isn't allowed to transfer alice's rose by default
    let alice_rose: AssetId = "rose##alice@wonderland".parse()?;
    let admin_rose: AccountId = "admin@admin".parse()?;
    let transfer_alice_rose = TransferExpr::new(alice_rose, NumericValue::U32(1), admin_rose);
    let transfer_rose_tx = TransactionBuilder::new(admin_id.clone())
        .with_instructions([transfer_alice_rose.clone()])
        .sign(admin_keypair.clone())?;
    let _ = client
        .submit_transaction_blocking(&transfer_rose_tx)
        .expect_err("Should fail");

    upgrade_executor(
        &client,
        "tests/integration/smartcontracts/executor_with_admin",
    )?;

    // Check that admin can transfer alice's rose now
    // Creating new transaction instead of cloning, because we need to update it's creation time
    let transfer_rose_tx = TransactionBuilder::new(admin_id)
        .with_instructions([transfer_alice_rose])
        .sign(admin_keypair)?;
    client
        .submit_transaction_blocking(&transfer_rose_tx)
        .expect("Should succeed");

    Ok(())
}

#[test]
fn executor_upgrade_should_run_migration() -> Result<()> {
    let (_rt, _peer, client) = <PeerBuilder>::new().with_port(10_990).start_with_runtime();
    wait_for_genesis_committed(&vec![client.clone()], 0);

    let can_unregister_domain_token_id = "CanUnregisterDomain".parse().unwrap();

    // Check that `CanUnregisterDomain` exists
    let definitions = client.request(FindPermissionTokenSchema)?;
    assert!(definitions
        .token_ids()
        .iter()
        .any(|id| id == &can_unregister_domain_token_id));

    // Check that Alice has permission to unregister Wonderland
    let alice_id: AccountId = "alice@wonderland".parse().unwrap();
    let alice_tokens = client
        .request(FindPermissionTokensByAccountId::new(alice_id.clone()))?
        .collect::<QueryResult<Vec<_>>>()
        .expect("Valid");
    assert!(alice_tokens.contains(&PermissionToken::new(
        can_unregister_domain_token_id.clone(),
        &json!({ "domain_id": DomainId::from_str("wonderland").unwrap() }),
    )));

    upgrade_executor(
        &client,
        "tests/integration/smartcontracts/executor_with_custom_token",
    )?;

    // Check that `CanUnregisterDomain` doesn't exist
    let definitions = client.request(FindPermissionTokenSchema)?;
    assert!(!definitions
        .token_ids()
        .iter()
        .any(|id| id == &can_unregister_domain_token_id));

    let can_control_domain_lives_token_id = "CanControlDomainLives".parse().unwrap();

    assert!(definitions
        .token_ids()
        .iter()
        .any(|id| id == &can_control_domain_lives_token_id));

    // Check that Alice has `can_control_domain_lives` permission
    let alice_tokens = client
        .request(FindPermissionTokensByAccountId::new(alice_id))?
        .collect::<QueryResult<Vec<_>>>()
        .expect("Valid");
    assert!(alice_tokens.contains(&PermissionToken::new(
        can_control_domain_lives_token_id,
        &json!(null),
    )));

    Ok(())
}

#[test]
fn migration_fail_should_not_cause_any_effects() {
    let (_rt, _peer, client) = <PeerBuilder>::new().with_port(10_995).start_with_runtime();
    wait_for_genesis_committed(&vec![client.clone()], 0);

    let assert_domain_does_not_exist = |client: &Client, domain_id: &DomainId| {
        client
            .request(client::domain::by_id(domain_id.clone()))
            .expect_err(&format!("There should be no `{domain_id}` domain"));
    };

    // Health check. Checking that things registered in migration are not registered in the genesis

    let domain_registered_in_migration: DomainId =
        "failed_migration_test_domain".parse().expect("Valid");
    assert_domain_does_not_exist(&client, &domain_registered_in_migration);

    let _err = upgrade_executor(
        &client,
        "tests/integration/smartcontracts/executor_with_migration_fail",
    )
    .expect_err("Upgrade should fail due to migration failure");

    // Checking that things registered in migration does not exist after failed migration
    assert_domain_does_not_exist(&client, &domain_registered_in_migration);

    // The fact that query in previous assertion does not fail means that executor haven't
    // been changed, because `executor_with_migration_fail` does not allow any queries
}

fn upgrade_executor(client: &Client, executor: impl AsRef<Path>) -> Result<()> {
    info!("Building executor");

    let wasm = iroha_wasm_builder::Builder::new(executor.as_ref())
        .build()?
        .optimize()?
        .into_bytes()?;

    info!("WASM size is {} bytes", wasm.len());

    let upgrade_executor = UpgradeExpr::new(Executor::new(WasmSmartContract::from_compiled(wasm)));
    client.submit_blocking(upgrade_executor)?;

    Ok(())
}
