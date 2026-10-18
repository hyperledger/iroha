//! Integration tests for role registration and assignment flows.
use executor_custom_data_model::permissions::CanControlDomainLives;
use eyre::Result;
use futures_util::future::join_all;
use integration_tests::{metrics::MetricsReader, sandbox};
use iroha::{
    blocking::Client,
    data_model::{prelude::*, transaction::error::TransactionRejectionReason},
};
use iroha_executor_data_model::permission::account::CanModifyAccountMetadata;
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use iroha_test_network::*;
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR, gen_account_in};
use std::time::{Duration, Instant};
use tokio::{fs, runtime::Runtime, time::timeout};
fn start_network(context: &'static str) -> Option<(sandbox::SerializedNetwork, Runtime)> {
    sandbox::start_network_blocking_or_skip(NetworkBuilder::new(), context).unwrap()
}
fn poll_detached_metrics(rt: &Runtime, metrics_url: &reqwest::Url) -> Result<(f64, f64, f64)> {
    let http = integration_tests::http::client();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut prepared_seen: f64 = 0.0;
    let mut merged_seen: f64 = 0.0;
    let mut fallback_seen: f64 = 0.0;
    while Instant::now() < deadline {
        let snapshot = rt.block_on(async {
            let response = http.get(metrics_url.clone()).send().await?;
            response.error_for_status()?.text().await
        })?;
        let metrics = MetricsReader::new(&snapshot);
        prepared_seen = prepared_seen.max(metrics.get("pipeline_detached_prepared"));
        merged_seen = merged_seen.max(metrics.get("pipeline_detached_merged"));
        fallback_seen = fallback_seen.max(metrics.get("pipeline_detached_fallback"));
        if merged_seen > 0.0 || fallback_seen > 0.0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok((prepared_seen, merged_seen, fallback_seen))
}
fn err_chain_contains(err: &eyre::Report, needle: &str) -> bool {
    err.chain().any(|cause| cause.to_string().contains(needle))
}
fn wait_for_role(client: &Client, role_id: &RoleId, context: &str) -> Role {
    const POLL_INTERVAL: Duration = Duration::from_millis(100);
    const TIMEOUT: Duration = Duration::from_secs(30);
    let deadline = Instant::now() + TIMEOUT;
    let mut last_observed = "roles were not queried".to_owned();
    while Instant::now() < deadline {
        match client.client().query(FindRoles::new()).execute_all() {
            Ok(roles) => {
                last_observed = format!("role_count={}", roles.len());
                if let Some(role) = roles.into_iter().find(|role| role.id() == role_id) {
                    return role;
                }
            }
            Err(err) => {
                last_observed = format!("query failed: {err}");
            }
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    panic!(
        "timed out waiting for role after {context}; role_id={role_id}; last_observed={last_observed}"
    );
}
#[test]
fn register_empty_role() -> Result<()> {
    let Some((network, _rt)) = start_network(stringify!(register_empty_role)) else {
        return Ok(());
    };
    let test_client = network.client();
    let role_id = "root".parse().expect("Valid");
    let register_role = Register::role(Role::new(role_id, ALICE_ID.clone()));
    test_client.submit(
        register_role,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    Ok(())
}
/// Test meant to mirror the test of the same name in the Iroha Kotlin SDK. This doesn't actually
/// test the functionality of the role granted, merely that the role can be constructed and
/// registered. Once @appetrosyan (me) is onboarded into the Kotlin SDK, I'll update both tests to
/// actually verify functionality. We now ensure metadata edits are rejected prior to the grant so
/// the permission check is exercised.
///
/// @s8sato added: This test represents #2081 case.
#[test]
fn register_and_grant_role_for_metadata_access() -> Result<()> {
    let Some((network, _rt)) =
        start_network(stringify!(register_and_grant_role_for_metadata_access))
    else {
        return Ok(());
    };
    let test_client = network.client();
    let alice_id = ALICE_ID.clone();
    let (mouse_id, mouse_keypair) = gen_account_in("wonderland");
    // Registering Mouse
    let register_mouse = Register::account(Account::new(mouse_id.clone()));
    test_client.submit(
        register_mouse,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    // Registering role
    let role_id = "ACCESS_TO_MOUSE_METADATA".parse::<RoleId>()?;
    let role =
        Role::new(role_id.clone(), mouse_id.clone()).add_permission(CanModifyAccountMetadata {
            account: mouse_id.clone(),
        });
    let register_role = Register::role(role);
    test_client.submit(
        register_role,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    // Transfer domain ownership to Mouse so Alice no longer has implicit owner privileges.
    let wonderland: DomainId = DomainId::try_new("wonderland", "universal")?;
    let transfer_domain = Transfer::domain(alice_id.clone(), wonderland, mouse_id.clone());
    test_client.submit(
        transfer_domain,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    // Metadata edits must fail before the permission is granted.
    let metadata_key = "key".parse::<Name>()?;
    let metadata_value = Json::from("value");
    let err = test_client
        .submit(
            SetKeyValue::account(
                mouse_id.clone(),
                metadata_key.clone(),
                metadata_value.clone(),
            ),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .expect_err("metadata update without permission should be rejected");
    assert!(
        err_chain_contains(&err, "Not permitted")
            || err_chain_contains(&err, "NotPermitted")
            || err_chain_contains(&err, "Can't set value to the metadata of another account"),
        "expected a Not permitted validation error, got: {err:?}"
    );
    // Mouse grants role to Alice
    let grant_role = Grant::account_role(role_id.clone(), alice_id.clone());
    let grant_role_tx = TransactionBuilder::new(
        network.network_id(),
        mouse_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([grant_role])
    .sign(mouse_keypair.private_key());
    test_client.submit_transaction_and_wait(&grant_role_tx)?;
    // Alice modifies Mouse's metadata
    let set_key_value = SetKeyValue::account(mouse_id, metadata_key, metadata_value);
    test_client.submit(
        set_key_value,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    // Making request to find Alice's roles
    let found_role_ids = test_client
        .client()
        .query(FindRolesByAccountId::new(alice_id))
        .execute_all()?;
    assert!(found_role_ids.contains(&role_id));
    Ok(())
}
#[test]
fn unregistered_role_removed_from_account() -> Result<()> {
    let Some((network, _rt)) = start_network(stringify!(unregistered_role_removed_from_account))
    else {
        return Ok(());
    };
    let test_client = network.client();
    let role_id: RoleId = "root".parse().expect("Valid");
    let alice_id = ALICE_ID.clone();
    let (mouse_id, _mouse_keypair) = gen_account_in("wonderland");
    // Registering Mouse
    let register_mouse = Register::account(Account::new(mouse_id.clone()));
    test_client.submit(
        register_mouse,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    // Register root role
    let register_role = Register::role(
        Role::new(role_id.clone(), alice_id.clone())
            .add_permission(CanModifyAccountMetadata { account: alice_id }),
    );
    test_client.submit(
        register_role,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    // Grant root role to Mouse
    let grant_role = Grant::account_role(role_id.clone(), mouse_id.clone());
    test_client.submit(
        grant_role,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    // Check that Mouse has root role
    let found_mouse_roles = test_client
        .client()
        .query(FindRolesByAccountId::new(mouse_id.clone()))
        .execute_all()?;
    assert!(found_mouse_roles.contains(&role_id));
    // Unregister root role
    let unregister_role = Unregister::role(role_id.clone());
    test_client.submit(
        unregister_role,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    // Check that Mouse doesn't have the root role
    let found_mouse_roles = test_client
        .client()
        .query(FindRolesByAccountId::new(mouse_id.clone()))
        .execute_all()?;
    assert!(!found_mouse_roles.contains(&role_id));
    Ok(())
}
#[test]
fn role_with_invalid_permissions_is_not_accepted() -> Result<()> {
    let Some((network, _rt)) =
        start_network(stringify!(role_with_invalid_permissions_is_not_accepted))
    else {
        return Ok(());
    };
    let test_client = network.client();
    let role_id = "ACCESS_TO_ACCOUNT_METADATA".parse()?;
    let role = Role::new(role_id, ALICE_ID.clone()).add_permission(CanControlDomainLives);
    let err = test_client
        .submit(
            Register::role(role),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .expect_err("Submitting role with non-existing permission should fail");
    if let Some(rejection_reason) = err.downcast_ref::<TransactionRejectionReason>() {
        assert!(matches!(
            rejection_reason,
            &TransactionRejectionReason::Validation(ValidationFail::NotPermitted(_))
        ));
    } else {
        assert!(
            err_chain_contains(&err, "Unknown permission")
                || err_chain_contains(&err, "NotPermitted"),
            "expected unknown permission rejection, got: {err:?}"
        );
    }
    Ok(())
}
#[test]
// The two independently constructed permissions have the same canonical V1 payload and must be
// deduplicated by the executor.
fn role_permissions_are_deduplicated() {
    let Some((network, _rt)) = start_network(stringify!(role_permissions_are_deduplicated)) else {
        return;
    };
    let test_client = network.client();
    let wonderland: DomainId =
        DomainId::try_new("wonderland", "universal").expect("wonderland domain");
    let rose_definition = AssetDefinitionId::derive_from_components(
        wonderland.clone(),
        "rose".parse().expect("valid rose name"),
    );
    let rose_asset = AssetId::new(rose_definition, ALICE_ID.clone());
    let rose_asset_lower = rose_asset.canonical_literal();
    let allow_alice_to_transfer_rose_1 = Permission::new(
        "CanTransferAsset".parse().unwrap(),
        iroha_primitives::json::Json::new(
            norito::json::object([(
                "asset",
                norito::json::to_value(&rose_asset_lower).expect("serialize asset"),
            )])
            .expect("serialize permission payload"),
        ),
    );
    // Independently construct the same canonical payload through the strict text boundary.
    let allow_alice_to_transfer_rose_2 = Permission::new(
        "CanTransferAsset".parse().unwrap(),
        iroha_primitives::json::Json::from_raw_json(format!(r#"{{"asset":"{rose_asset_lower}"}}"#))
            .expect("valid permission JSON fixture"),
    );
    let role_id: RoleId = "role_id".parse().expect("Valid");
    let role = Role::new(role_id.clone(), ALICE_ID.clone())
        .add_permission(allow_alice_to_transfer_rose_1)
        .add_permission(allow_alice_to_transfer_rose_2);
    test_client
        .submit(
            Register::role(role),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .expect("failed to register role");
    let role = wait_for_role(&test_client, &role_id, "role registration");
    // Permissions are unified so only one is left
    assert_eq!(
        role.permissions().len(),
        1,
        "permissions for role aren't deduplicated"
    );
}
#[test]
fn grant_revoke_role_permissions() -> Result<()> {
    let Some((network, _rt)) = start_network(stringify!(grant_revoke_role_permissions)) else {
        return Ok(());
    };
    let test_client = network.client();
    let alice_id = ALICE_ID.clone();
    let (mouse_id, mouse_keypair) = gen_account_in("wonderland");
    // Registering Mouse
    let register_mouse = Register::account(Account::new(mouse_id.clone()));
    test_client.submit(
        register_mouse,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    // Registering role
    let role_id = "ACCESS_TO_MOUSE_METADATA".parse::<RoleId>()?;
    let role = Role::new(role_id.clone(), mouse_id.clone());
    let register_role = Register::role(role);
    test_client.submit(
        register_role,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    // Transfer domain ownership to Mouse
    let domain_id = DomainId::try_new("wonderland", "universal")?;
    let transfer_domain = Transfer::domain(alice_id.clone(), domain_id, mouse_id.clone());
    test_client.submit(
        transfer_domain,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    // Mouse grants role to Alice
    let grant_role = Grant::account_role(role_id.clone(), alice_id.clone());
    let grant_role_tx = TransactionBuilder::new(
        network.network_id(),
        mouse_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([grant_role])
    .sign(mouse_keypair.private_key());
    test_client.submit_transaction_and_wait(&grant_role_tx)?;
    let set_key_value = SetKeyValue::account(mouse_id.clone(), "key".parse()?, Json::from("value"));
    let can_set_key_value_in_mouse = CanModifyAccountMetadata {
        account: mouse_id.clone(),
    };
    let grant_role_permission =
        Grant::role_permission(can_set_key_value_in_mouse.clone(), role_id.clone());
    let revoke_role_permission =
        Revoke::role_permission(can_set_key_value_in_mouse.clone(), role_id.clone());
    // Alice can't modify Mouse's metadata without proper permission
    assert!(
        !test_client
            .client()
            .query(FindPermissionsByAccountId::new(alice_id.clone()))
            .execute_all()?
            .iter()
            .any(|permission| {
                CanModifyAccountMetadata::try_from(permission)
                    .is_ok_and(|permission| permission == can_set_key_value_in_mouse)
            })
    );
    let _ = test_client
        .submit(
            set_key_value.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .expect_err("shouldn't be able to modify metadata");
    // Alice can modify Mouse's metadata after permission is granted to role
    let grant_role_permission_tx = TransactionBuilder::new(
        network.network_id(),
        mouse_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([grant_role_permission])
    .sign(mouse_keypair.private_key());
    test_client.submit_transaction_and_wait(&grant_role_permission_tx)?;
    assert!(
        test_client
            .client()
            .query(FindRolesByAccountId::new(alice_id.clone()))
            .execute_all()?
            .contains(&role_id)
    );
    test_client.submit(
        set_key_value.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    // Alice can't modify Mouse's metadata after permission is removed from role
    let revoke_role_permission_tx = TransactionBuilder::new(
        network.network_id(),
        mouse_id,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([revoke_role_permission])
    .sign(mouse_keypair.private_key());
    test_client.submit_transaction_and_wait(&revoke_role_permission_tx)?;
    assert!(
        !test_client
            .client()
            .query(FindPermissionsByAccountId::new(alice_id.clone()))
            .execute_all()?
            .iter()
            .any(|permission| {
                CanModifyAccountMetadata::try_from(permission)
                    .is_ok_and(|permission| permission == can_set_key_value_in_mouse)
            })
    );
    let _ = test_client
        .submit(
            set_key_value,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .expect_err("shouldn't be able to modify metadata");
    Ok(())
}
#[test]
fn role_permission_revoke_then_grant_last_wins_detached() -> Result<()> {
    let builder = NetworkBuilder::new()
        .with_peers(4)
        .with_default_block_cadence()
        .with_config_layer(|layer| {
            layer
                .write(["pipeline", "parallel_overlay"], true)
                .write(["pipeline", "parallel_apply"], true)
                .write("telemetry_profile", "full");
        });
    let Some((network, rt)) = sandbox::start_network_blocking_or_skip(
        builder,
        stringify!(role_permission_revoke_then_grant_last_wins_detached),
    )?
    else {
        return Ok(());
    };
    let test_client = network.client();
    let metrics_url = test_client.client().endpoint().join("/metrics")?;
    let alice_id = ALICE_ID.clone();
    let role_id: RoleId = "PERM_LAST_WINS".parse()?;
    test_client.submit(
        Register::role(Role::new(role_id.clone(), alice_id.clone())),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    let perm: Permission = CanModifyAccountMetadata {
        account: alice_id.clone(),
    }
    .into();
    test_client.submit(
        Grant::role_permission(perm.clone(), role_id.clone()),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    let revoke_role_permission = Revoke::role_permission(perm.clone(), role_id.clone());
    let grant_role_permission = Grant::role_permission(perm.clone(), role_id.clone());
    let tx = TransactionBuilder::new(
        network.network_id(),
        alice_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([
        InstructionBox::from(revoke_role_permission),
        InstructionBox::from(grant_role_permission),
    ])
    .sign(ALICE_KEYPAIR.private_key());
    test_client.submit_transaction_and_wait(&tx)?;
    let (prepared_seen, merged_seen, fallback_seen) = poll_detached_metrics(&rt, &metrics_url)?;
    let role = test_client
        .client()
        .query(FindRoles::new())
        .execute_all()?
        .into_iter()
        .find(|role| role.id() == &role_id)
        .expect("role should exist");
    assert!(
        role.permissions().any(|permission| permission == &perm),
        "last grant should keep permission on role"
    );
    assert!(
        prepared_seen > 0.0,
        "expected detached pipeline to prepare overlays"
    );
    assert!(
        merged_seen > 0.0,
        "expected detached merge to register in metrics"
    );
    assert_eq!(
        fallback_seen, 0.0,
        "detached fallback should not register for permission ops"
    );
    Ok(())
}
#[tokio::test]
async fn grant_unexisting_role_in_genesis_fail() {
    // Grant Alice UNEXISTING role
    let alice_id = ALICE_ID.clone();
    let role_id = "UNEXISTING".parse::<RoleId>().unwrap();
    let grant_genesis_role = Grant::account_role(role_id, alice_id);
    let Some(network) = sandbox::build_network_or_skip(
        NetworkBuilder::new()
            .with_min_peers(4)
            .with_genesis_instruction(grant_genesis_role),
        stringify!(grant_unexisting_role_in_genesis_fail),
    ) else {
        return;
    };
    let peer = network.peer();
    // Sanity-check stderr to ensure CI surfaces the expected genesis failure diagnostics (see #5423).
    let terminated_futs = network
        .peers()
        .iter()
        .map(|peer| {
            let mut events = peer.events();
            async move {
                loop {
                    match events.recv().await {
                        Ok(PeerLifecycleEvent::Terminated { .. } | PeerLifecycleEvent::Killed) => {
                            break;
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
            }
        })
        .collect::<Vec<_>>();
    for peer in network.peers() {
        if let Err(err) = peer
            .start(network.config_layers(), Some(&network.genesis()))
            .await
        {
            if let Some(reason) = integration_tests::sandbox::sandbox_reason(&err) {
                panic!(
                    "sandboxed network restriction detected while starting grant_unexisting_role_in_genesis_fail: {reason}"
                );
            }
            panic!("failed to start peer: {err:?}");
        }
    }
    timeout(Duration::from_secs(10), join_all(terminated_futs))
        .await
        .expect("must terminate immediately");
    let stderr_path = peer
        .latest_stderr_log_path()
        .expect("stderr log should be captured for failed genesis run");
    let stderr = fs::read_to_string(&stderr_path)
        .await
        .unwrap_or_else(|err| panic!("failed to read {stderr_path:?}: {err}"));
    let markers = [
        "confidential.enabled = true",
        "Failed IO operation",
        "Block confidential feature digest mismatch.",
        "Genesis transactions must not contain errors",
        "Genesis block execution failed",
        "Block contained no committed overlays",
    ];
    assert!(
        markers.iter().any(|needle| stderr.contains(needle)),
        "stderr should surface the genesis startup failure cause:\n{stderr}"
    );
}
