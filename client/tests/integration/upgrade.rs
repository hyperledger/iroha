use std::path::Path;

use executor_custom_data_model::permissions::CanControlDomainLives;
use eyre::Result;
use futures_util::TryStreamExt as _;
use iroha::{
    client::{self, Client},
    data_model::{
        parameter::{Parameter, SmartContractParameter},
        prelude::*,
    },
};
use iroha_executor_data_model::permission::{domain::CanUnregisterDomain, Permission as _};
use iroha_logger::info;
use nonzero_ext::nonzero;
use test_network::*;
use test_samples::{ALICE_ID, BOB_ID};

const ADMIN_PUBLIC_KEY_MULTIHASH: &str =
    "ed012076E5CA9698296AF9BE2CA45F525CB3BCFDEB7EE068BA56F973E9DD90564EF4FC";
const ADMIN_PRIVATE_KEY_MULTIHASH: &str =
    "802620A4DE33BCA99A254ED6265D1F0FB69DFE42B77F89F6C2E478498E1831BF6D81F2";

#[test]
fn executor_upgrade_should_work() -> Result<()> {
    let chain_id = ChainId::from("00000000-0000-0000-0000-000000000000");
    let admin_id: AccountId = format!("{ADMIN_PUBLIC_KEY_MULTIHASH}@admin")
        .parse()
        .unwrap();
    let admin_private_key = ADMIN_PRIVATE_KEY_MULTIHASH
        .parse::<iroha::crypto::PrivateKey>()
        .unwrap();

    let (_rt, _peer, client) = <PeerBuilder>::new().with_port(10_795).start_with_runtime();
    wait_for_genesis_committed(&vec![client.clone()], 0);

    // Register `admin` domain and account
    let admin_domain = Domain::new(admin_id.domain().clone());
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
        .sign(&admin_private_key);
    let _ = client
        .submit_transaction_blocking(&transfer_rose_tx)
        .expect_err("Should fail");

    upgrade_executor(&client, "../wasm_samples/executor_with_admin")?;

    // Check that admin can transfer alice's rose now
    // Creating new transaction instead of cloning, because we need to update it's creation time
    let transfer_rose_tx = TransactionBuilder::new(chain_id, admin_id.clone())
        .with_instructions([transfer_alice_rose])
        .sign(&admin_private_key);
    client
        .submit_transaction_blocking(&transfer_rose_tx)
        .expect("Should succeed");

    Ok(())
}

#[test]
fn executor_upgrade_should_run_migration() -> Result<()> {
    let (_rt, _peer, client) = <PeerBuilder>::new().with_port(10_990).start_with_runtime();
    wait_for_genesis_committed(&vec![client.clone()], 0);

    // Check that `CanUnregisterDomain` exists
    assert!(client
        .query_single(FindExecutorDataModel)?
        .permissions()
        .iter()
        .any(|permission| CanUnregisterDomain::name() == *permission));

    // Check that Alice has permission to unregister Wonderland
    let alice_id = ALICE_ID.clone();
    let alice_permissions = client
        .query(client::permission::by_account_id(alice_id.clone()))
        .execute_all()?;
    let can_unregister_domain = CanUnregisterDomain {
        domain: "wonderland".parse()?,
    };

    assert!(alice_permissions.iter().any(|permission| {
        CanUnregisterDomain::try_from(permission)
            .is_ok_and(|permission| permission == can_unregister_domain)
    }));

    upgrade_executor(&client, "../wasm_samples/executor_with_custom_permission")?;

    // Check that `CanUnregisterDomain` doesn't exist
    let data_model = client.query_single(FindExecutorDataModel)?;
    assert!(data_model
        .permissions()
        .iter()
        .all(|permission| CanUnregisterDomain::name() != *permission));

    assert!(data_model
        .permissions()
        .iter()
        .any(|permission| CanControlDomainLives::name() == *permission));

    // Check that Alice has `CanControlDomainLives` permission
    let alice_permissions = client
        .query(client::permission::by_account_id(alice_id.clone()))
        .execute_all()?;
    let can_control_domain_lives = CanControlDomainLives;
    assert!(alice_permissions.iter().any(|permission| {
        CanControlDomainLives::try_from(permission)
            .is_ok_and(|permission| permission == can_control_domain_lives)
    }));

    Ok(())
}

#[test]
fn executor_upgrade_should_revoke_removed_permissions() -> Result<()> {
    let (_rt, _peer, client) = <PeerBuilder>::new().with_port(11_030).start_with_runtime();
    wait_for_genesis_committed(&vec![client.clone()], 0);

    // Permission which will be removed by executor
    let can_unregister_domain = CanUnregisterDomain {
        domain: "wonderland".parse()?,
    };

    // Register `TEST_ROLE` with permission
    let test_role_id: RoleId = "TEST_ROLE".parse()?;
    let test_role = Role::new(test_role_id.clone()).add_permission(can_unregister_domain.clone());
    client.submit_blocking(Register::role(test_role))?;

    // Check that permission exists
    assert!(client
        .query_single(FindExecutorDataModel)?
        .permissions()
        .contains(&CanUnregisterDomain::name()));

    // Check that `TEST_ROLE` has permission
    assert!(client
        .query(client::role::all())
        .execute_all()?
        .into_iter()
        .find(|role| role.id == test_role_id)
        .expect("Failed to find Role")
        .permissions
        .iter()
        .any(|permission| {
            CanUnregisterDomain::try_from(permission)
                .is_ok_and(|permission| permission == can_unregister_domain)
        }));

    // Check that Alice has permission
    let alice_id = ALICE_ID.clone();
    assert!(client
        .query(client::permission::by_account_id(alice_id.clone()))
        .execute_all()?
        .iter()
        .any(|permission| {
            CanUnregisterDomain::try_from(permission)
                .is_ok_and(|permission| permission == can_unregister_domain)
        }));

    upgrade_executor(&client, "../wasm_samples/executor_remove_permission")?;

    // Check that permission doesn't exist
    assert!(!client
        .query_single(FindExecutorDataModel)?
        .permissions()
        .contains(&CanUnregisterDomain::name()));

    // Check that `TEST_ROLE` doesn't have permission
    assert!(!client
        .query(client::role::all())
        .execute_all()?
        .into_iter()
        .find(|role| role.id == test_role_id)
        .expect("Failed to find Role")
        .permissions
        .iter()
        .any(|permission| {
            CanUnregisterDomain::try_from(permission)
                .is_ok_and(|permission| permission == can_unregister_domain)
        }));

    // Check that Alice doesn't have permission
    assert!(!client
        .query(client::permission::by_account_id(alice_id.clone()))
        .execute_all()?
        .iter()
        .any(|permission| {
            CanUnregisterDomain::try_from(permission)
                .is_ok_and(|permission| permission == can_unregister_domain)
        }));

    Ok(())
}

#[test]
fn executor_custom_instructions_simple() -> Result<()> {
    use executor_custom_data_model::simple_isi::MintAssetForAllAccounts;

    let (_rt, _peer, client) = <PeerBuilder>::new().with_port(11_270).start_with_runtime();
    wait_for_genesis_committed(&vec![client.clone()], 0);

    upgrade_executor(
        &client,
        "../wasm_samples/executor_custom_instructions_simple",
    )?;

    let asset_definition_id: AssetDefinitionId = "rose#wonderland".parse().unwrap();

    // Give 1 rose to bob
    let bob_rose = AssetId::new(asset_definition_id.clone(), BOB_ID.clone());
    client.submit_blocking(Mint::asset_numeric(Numeric::from(1u32), bob_rose.clone()))?;

    // Check that bob has 1 rose
    assert_eq!(
        client.query_single(FindAssetQuantityById::new(bob_rose.clone()))?,
        Numeric::from(1u32)
    );

    // Give 1 rose to all
    let isi = MintAssetForAllAccounts {
        asset_definition: asset_definition_id,
        quantity: Numeric::from(1u32),
    };
    client.submit_blocking(isi)?;

    // Check that bob has 2 roses
    assert_eq!(
        client.query_single(FindAssetQuantityById::new(bob_rose.clone()))?,
        Numeric::from(2u32)
    );

    Ok(())
}

#[test]
fn executor_custom_instructions_complex() -> Result<()> {
    use executor_custom_data_model::complex_isi::{
        ConditionalExpr, CoreExpr, EvaluatesTo, Expression, Greater,
    };

    let (_rt, _peer, client) = PeerBuilder::new().with_port(11_275).start_with_runtime();
    wait_for_genesis_committed(&vec![client.clone()], 0);

    let executor_fuel_limit = SetParameter::new(Parameter::Executor(SmartContractParameter::Fuel(
        nonzero!(1_000_000_000_u64),
    )));
    client.submit_blocking(executor_fuel_limit)?;
    upgrade_executor(
        &client,
        "../wasm_samples/executor_custom_instructions_complex",
    )?;

    // Give 6 roses to bob
    let asset_definition_id: AssetDefinitionId = "rose#wonderland".parse().unwrap();
    let bob_rose = AssetId::new(asset_definition_id.clone(), BOB_ID.clone());
    client.submit_blocking(Mint::asset_numeric(Numeric::from(6u32), bob_rose.clone()))?;

    // Check that bob has 6 roses
    assert_eq!(
        client.query_single(FindAssetQuantityById::new(bob_rose.clone()))?,
        Numeric::from(6u32)
    );

    // If bob has more then 5 roses, then burn 1 rose
    let burn_bob_rose_if_more_then_5 = || -> Result<()> {
        let condition = Greater::new(
            EvaluatesTo::new_unchecked(Expression::Query(
                FindAssetQuantityById::new(bob_rose.clone()).into(),
            )),
            Numeric::from(5u32),
        );
        let then = Burn::asset_numeric(Numeric::from(1u32), bob_rose.clone());
        let then: InstructionBox = then.into();
        let then = CoreExpr::new(then);
        let isi = ConditionalExpr::new(condition, then);
        client.submit_blocking(isi)?;
        Ok(())
    };
    burn_bob_rose_if_more_then_5()?;

    // Check that bob has 5 roses
    assert_eq!(
        client.query_single(FindAssetQuantityById::new(bob_rose.clone()))?,
        Numeric::from(5u32)
    );

    burn_bob_rose_if_more_then_5()?;

    // Check that bob has 5 roses
    assert_eq!(
        client.query_single(FindAssetQuantityById::new(bob_rose.clone()))?,
        Numeric::from(5u32)
    );

    Ok(())
}

#[test]
fn migration_fail_should_not_cause_any_effects() {
    let (_rt, _peer, client) = <PeerBuilder>::new().with_port(10_998).start_with_runtime();
    wait_for_genesis_committed(&vec![client.clone()], 0);

    let assert_domain_does_not_exist = |client: &Client, domain_id: &DomainId| {
        assert!(
            client
                .query(client::domain::all())
                .filter_with(|domain| domain.id.eq(domain_id.clone()))
                .execute_single_opt()
                .expect("Query failed")
                .is_none(),
            "There should be no `{domain_id}` domain"
        );
    };

    // Health check. Checking that things registered in migration are not registered in the genesis

    let domain_registered_in_migration: DomainId =
        "failed_migration_test_domain".parse().expect("Valid");
    assert_domain_does_not_exist(&client, &domain_registered_in_migration);

    let _err = upgrade_executor(&client, "../wasm_samples/executor_with_migration_fail")
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

    let events_client = client.clone();
    let task = rt.spawn(async move {
        let mut stream = events_client
            .listen_for_events_async([ExecutorEventFilter::new()])
            .await
            .unwrap();
        while let Some(event) = stream.try_next().await.unwrap() {
            if let EventBox::Data(DataEvent::Executor(ExecutorEvent::Upgraded(ExecutorUpgrade {
                new_data_model,
            }))) = event
            {
                assert!(!new_data_model.permissions.is_empty());
                break;
            }
        }
    });

    upgrade_executor(&client, "../wasm_samples/executor_with_custom_permission").unwrap();

    rt.block_on(async {
        tokio::time::timeout(core::time::Duration::from_secs(60), task)
            .await
            .unwrap()
    })
    .expect("should receive upgraded event immediately after upgrade");
}

#[test]
fn define_custom_parameter() -> Result<()> {
    use executor_custom_data_model::parameters::DomainLimits;

    let (_rt, _peer, client) = <PeerBuilder>::new().with_port(11_325).start_with_runtime();
    wait_for_genesis_committed(&vec![client.clone()], 0);

    let long_domain_name = "0".repeat(2_usize.pow(5)).parse::<DomainId>()?;
    let create_domain = Register::domain(Domain::new(long_domain_name));
    client.submit_blocking(create_domain)?;

    upgrade_executor(&client, "../wasm_samples/executor_with_custom_parameter").unwrap();

    let too_long_domain_name = "1".repeat(2_usize.pow(5)).parse::<DomainId>()?;
    let create_domain = Register::domain(Domain::new(too_long_domain_name));
    let _err = client.submit_blocking(create_domain.clone()).unwrap_err();

    let parameter = DomainLimits {
        id_len: 2_u32.pow(6),
    }
    .into();
    let set_param_isi = SetParameter::new(parameter);
    client.submit_all_blocking::<InstructionBox>([set_param_isi.into(), create_domain.into()])?;

    Ok(())
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
