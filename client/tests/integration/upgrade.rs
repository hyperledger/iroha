use std::{path::Path, str::FromStr as _};

use eyre::Result;
use futures_util::TryStreamExt as _;
use iroha_client::{
    client::{self, Client, QueryResult},
    crypto::KeyPair,
    data_model::prelude::*,
};
use iroha_logger::info;
use serde_json::json;
use test_network::*;
use test_samples::ALICE_ID;
use tokio::sync::mpsc;

const ADMIN_PUBLIC_KEY_MULTIHASH: &str =
    "ed012076E5CA9698296AF9BE2CA45F525CB3BCFDEB7EE068BA56F973E9DD90564EF4FC";
const ADMIN_PRIVATE_KEY_MULTIHASH: &str = "802640A4DE33BCA99A254ED6265D1F0FB69DFE42B77F89F6C2E478498E1831BF6D81F276E5CA9698296AF9BE2CA45F525CB3BCFDEB7EE068BA56F973E9DD90564EF4FC";

#[test]
fn executor_upgrade_should_work() -> Result<()> {
    let chain_id = ChainId::from("0");
    let admin_id: AccountId = format!("{ADMIN_PUBLIC_KEY_MULTIHASH}@admin")
        .parse()
        .unwrap();
    let admin_keypair = KeyPair::new(
        admin_id.signatory().clone(),
        ADMIN_PRIVATE_KEY_MULTIHASH.parse().unwrap(),
    )
    .unwrap();

    let (_rt, _peer, client) = <PeerBuilder>::new().with_port(10_795).start_with_runtime();
    wait_for_genesis_committed(&vec![client.clone()], 0);

    // Register `admin` domain and account
    let admin_domain = Domain::new(admin_id.domain_id().clone());
    let register_admin_domain = Register::domain(admin_domain);
    client.submit_blocking(register_admin_domain)?;

    let admin_account = Account::new(admin_id.clone());
    let register_admin_account = Register::account(admin_account);
    client.submit_blocking(register_admin_account)?;

    // Check that admin isn't allowed to transfer alice's rose by default
    let alice_rose: AssetId = format!("rose##{}", ALICE_ID.clone())
        .parse()
        .expect("should be valid");
    let transfer_alice_rose = Transfer::asset_numeric(alice_rose, 1u32, admin_id.clone());
    let transfer_rose_tx = TransactionBuilder::new(chain_id.clone(), admin_id.clone())
        .with_instructions([transfer_alice_rose.clone()])
        .sign(&admin_keypair);
    let _ = client
        .submit_transaction_blocking(&transfer_rose_tx)
        .expect_err("Should fail");

    upgrade_executor(
        &client,
        "tests/integration/smartcontracts/executor_with_admin",
    )?;

    // Check that admin can transfer alice's rose now
    // Creating new transaction instead of cloning, because we need to update it's creation time
    let transfer_rose_tx = TransactionBuilder::new(chain_id, admin_id.clone())
        .with_instructions([transfer_alice_rose])
        .sign(&admin_keypair);
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
    assert!(client
        .request(FindExecutorDataModel)?
        .permissions()
        .iter()
        .any(|id| id == &can_unregister_domain_token_id));

    // Check that Alice has permission to unregister Wonderland
    let alice_id = ALICE_ID.clone();
    let alice_tokens = client
        .request(FindPermissionsByAccountId::new(alice_id.clone()))?
        .collect::<QueryResult<Vec<_>>>()
        .expect("Valid");
    assert!(alice_tokens.contains(&Permission::new(
        can_unregister_domain_token_id.clone(),
        &json!({ "domain_id": DomainId::from_str("wonderland").unwrap() }),
    )));

    upgrade_executor(
        &client,
        "tests/integration/smartcontracts/executor_with_custom_permission",
    )?;

    // Check that `CanUnregisterDomain` doesn't exist
    let data_model = client.request(FindExecutorDataModel)?;
    assert!(!data_model
        .permissions()
        .iter()
        .any(|id| id == &can_unregister_domain_token_id));

    let can_control_domain_lives_token_id = "CanControlDomainLives".parse().unwrap();

    assert!(data_model
        .permissions()
        .iter()
        .any(|id| id == &can_control_domain_lives_token_id));

    // Check that Alice has `can_control_domain_lives` permission
    let alice_tokens = client
        .request(FindPermissionsByAccountId::new(alice_id))?
        .collect::<QueryResult<Vec<_>>>()
        .expect("Valid");
    assert!(alice_tokens.contains(&Permission::new(
        can_control_domain_lives_token_id,
        &json!(null),
    )));

    Ok(())
}

#[test]
fn executor_upgrade_should_revoke_removed_permissions() -> Result<()> {
    let (_rt, _peer, client) = <PeerBuilder>::new().with_port(11_030).start_with_runtime();
    wait_for_genesis_committed(&vec![client.clone()], 0);

    // Permission which will be removed by executor
    let can_unregister_domain_token = Permission::new(
        "CanUnregisterDomain".parse()?,
        &json!({ "domain_id": DomainId::from_str("wonderland")? }),
    );

    // Register `TEST_ROLE` with permission
    let test_role_id: RoleId = "TEST_ROLE".parse()?;
    let test_role =
        Role::new(test_role_id.clone()).add_permission(can_unregister_domain_token.clone());
    client.submit_blocking(Register::role(test_role))?;

    // Check that permission exists
    assert!(client
        .request(FindExecutorDataModel)?
        .permissions()
        .contains(&can_unregister_domain_token.id));

    // Check that `TEST_ROLE` has permission
    assert!(client
        .request(FindAllRoles::new())?
        .collect::<QueryResult<Vec<_>>>()?
        .into_iter()
        .find(|role| role.id == test_role_id)
        .expect("Failed to find Role")
        .permissions
        .contains(&can_unregister_domain_token));

    // Check that Alice has permission
    let alice_id = ALICE_ID.clone();
    assert!(client
        .request(FindPermissionsByAccountId::new(alice_id.clone()))?
        .collect::<QueryResult<Vec<_>>>()?
        .contains(&can_unregister_domain_token));

    upgrade_executor(
        &client,
        "tests/integration/smartcontracts/executor_remove_permission",
    )?;

    // Check that permission doesn't exist
    assert!(!client
        .request(FindExecutorDataModel)?
        .permissions()
        .contains(&can_unregister_domain_token.id));

    // Check that `TEST_ROLE` doesn't have permission
    assert!(!client
        .request(FindAllRoles::new())?
        .collect::<QueryResult<Vec<_>>>()?
        .into_iter()
        .find(|role| role.id == test_role_id)
        .expect("Failed to find Role")
        .permissions
        .contains(&can_unregister_domain_token));

    // Check that Alice doesn't have permission
    assert!(!client
        .request(FindPermissionsByAccountId::new(alice_id.clone()))?
        .collect::<QueryResult<Vec<_>>>()?
        .contains(&can_unregister_domain_token));

    Ok(())
}

#[test]
fn migration_fail_should_not_cause_any_effects() {
    let (_rt, _peer, client) = <PeerBuilder>::new().with_port(10_999).start_with_runtime();
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

#[test]
fn migration_should_cause_upgrade_event() {
    let (rt, _peer, client) = <PeerBuilder>::new().with_port(10_996).start_with_runtime();
    wait_for_genesis_committed(&vec![client.clone()], 0);

    let (sender, mut receiver) = mpsc::channel(1);
    let events_client = client.clone();

    let _handle = rt.spawn(async move {
        let mut stream = events_client
            .listen_for_events_async([ExecutorEventFilter::new()])
            .await
            .unwrap();
        while let Some(event) = stream.try_next().await.unwrap() {
            if let EventBox::Data(DataEvent::Executor(ExecutorEvent::Upgraded(ExecutorUpgrade {
                new_data_model,
            }))) = event
            {
                let _ = sender.send(new_data_model).await;
            }
        }
    });

    upgrade_executor(
        &client,
        "tests/integration/smartcontracts/executor_with_custom_permission",
    )
    .unwrap();

    let data_model = rt
        .block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(60), receiver.recv()).await
        })
        .ok()
        .flatten()
        .expect("should receive upgraded event immediately after upgrade");

    assert!(!data_model.permissions.is_empty());
}

fn upgrade_executor(client: &Client, executor: impl AsRef<Path>) -> Result<()> {
    info!("Building executor");

    let wasm = iroha_wasm_builder::Builder::new(executor.as_ref())
        .show_output()
        .build()?
        .optimize()?
        .into_bytes()?;

    info!("WASM size is {} bytes", wasm.len());

    let upgrade_executor = Upgrade::new(Executor::new(WasmSmartContract::from_compiled(wasm)));
    client.submit_blocking(upgrade_executor)?;

    Ok(())
}
