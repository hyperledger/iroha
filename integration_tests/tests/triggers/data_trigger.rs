//! Data-trigger execution and rollback scenarios.
use eyre::Result;
use integration_tests::sandbox;
use iroha::{blocking, data_model::prelude::*};
use iroha_executor_data_model::permission::account::{
    AccountAliasPermissionScope, CanManageAccountAlias,
};
use iroha_executor_data_model::permission::trigger::CanRegisterGlobalDataTrigger;
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use iroha_model_base::topology::DataSpaceId;
use iroha_test_network::*;
use iroha_test_samples::{ALICE_ID, gen_account_in};
use std::time::{Duration, Instant};
use tokio::task::spawn_blocking;
const ASSET_VALUE_POLL_INTERVAL: Duration = Duration::from_millis(100);
const ASSET_VALUE_TIMEOUT: Duration = Duration::from_secs(30);
async fn start_network(context: &'static str) -> Result<Option<sandbox::SerializedNetwork>> {
    start_custom_network(NetworkBuilder::new(), context).await
}
async fn start_custom_network(
    builder: NetworkBuilder,
    context: &'static str,
) -> Result<Option<sandbox::SerializedNetwork>> {
    let builder = builder.with_genesis_instruction(Grant::account_permission(
        Permission::from(CanRegisterGlobalDataTrigger {
            authority: ALICE_ID.clone(),
        }),
        ALICE_ID.clone(),
    ));
    sandbox::start_network_async_or_skip(builder, context).await
}
async fn run_or_skip<F, Fut>(context: &'static str, test: F) -> Result<()>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    if sandbox::handle_result(test().await, context)?.is_none() {
        return Ok(());
    }
    Ok(())
}
fn asset_value(client: &blocking::Client, asset_id: &AssetId) -> Result<Quantity> {
    let assets = client.client().query(FindAssets::new()).execute_all()?;
    let asset = assets
        .into_iter()
        .find(|asset| asset.id() == asset_id)
        .ok_or_else(|| eyre::eyre!("asset {asset_id} not found"))?;
    Ok(asset.value().clone())
}
fn wait_for_asset_value(
    client: &blocking::Client,
    asset_id: &AssetId,
    expected: &Quantity,
    context: &str,
) -> Result<Quantity> {
    let deadline = Instant::now() + ASSET_VALUE_TIMEOUT;
    let mut last_observed = "asset was not queried".to_owned();
    while Instant::now() < deadline {
        match asset_value(client, asset_id) {
            Ok(value) => {
                last_observed = value.to_string();
                if &value == expected {
                    return Ok(value);
                }
            }
            Err(error) => {
                last_observed = format!("query failed: {error}");
            }
        }
        std::thread::sleep(ASSET_VALUE_POLL_INTERVAL);
    }
    Err(eyre::eyre!(
        "timed out waiting for asset {asset_id} to equal {expected} after {context}; last_observed={last_observed}"
    ))
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_non_intersecting_execution_paths() -> Result<()> {
    let Some(network) = start_network(stringify!(two_non_intersecting_execution_paths)).await?
    else {
        return Ok(());
    };
    let test_client = network.client();
    run_or_skip(stringify!(two_non_intersecting_execution_paths), || async {
        let account_id = ALICE_ID.clone();
        let asset_definition_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal")?,
            "rose".parse()?,
        );
        let asset_id = AssetId::new(asset_definition_id, account_id.clone());
        let prev_value = spawn_blocking({
            let client = test_client.clone();
            let asset_id = asset_id.clone();
            move || asset_value(&client, &asset_id)
        })
        .await??;
        let instruction = Mint::asset_quantity(1u32, asset_id.clone());
        let alias_domain = DomainId::try_new("wonderland", "universal")?;
        let account_alias_literal = "mintrose@wonderland.universal";
        let alias_target_account = gen_account_in("wonderland").0;
        spawn_blocking({
            let client = test_client.clone();
            let alias_domain = alias_domain.clone();
            move || -> Result<()> {
                client.submit(
                    Grant::account_permission(
                        Permission::from(CanManageAccountAlias {
                            scope: AccountAliasPermissionScope::Dataspace(DataSpaceId::UNIVERSAL),
                        }),
                        ALICE_ID.clone(),
                    ),
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                )?;
                client.submit(
                    Grant::account_permission(
                        Permission::from(CanManageAccountAlias {
                            scope: AccountAliasPermissionScope::Domain(alias_domain),
                        }),
                        ALICE_ID.clone(),
                    ),
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                )?;
                Ok(())
            }
        })
        .await??;
        let register_trigger = Register::trigger(Trigger::new(
            "mint_rose_1".parse()?,
            Action::new(
                [instruction.clone()],
                Repeats::Indefinitely,
                account_id.clone(),
                AccountEventFilter::new().for_events(AccountEventSet::Created),
            )
            .expect("trigger action fixture satisfies validation invariants"),
        ));
        spawn_blocking({
            let client = test_client.clone();
            move || {
                client.submit(
                    register_trigger,
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                )
            }
        })
        .await??;
        let register_trigger = Register::trigger(Trigger::new(
            "mint_rose_2".parse()?,
            Action::new(
                [instruction],
                Repeats::Indefinitely,
                account_id,
                DomainEventFilter::new().for_events(DomainEventSet::Created),
            )
            .expect("trigger action fixture satisfies validation invariants"),
        ));
        spawn_blocking({
            let client = test_client.clone();
            move || {
                client.submit(
                    register_trigger,
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                )
            }
        })
        .await??;
        let setup_alias = account_alias_setup_instruction(
            account_alias_literal,
            &alias_target_account,
            AccountProvisionV1::Create,
            AccountAliasRoleV1::Primary,
        )?;
        spawn_blocking({
            let client = test_client.clone();
            move || {
                client.submit(
                    setup_alias,
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                )
            }
        })
        .await??;
        let expected_new_value = prev_value.checked_add(&Quantity::one()).unwrap();
        let new_value = spawn_blocking({
            let client = test_client.clone();
            let asset_id = asset_id.clone();
            move || {
                wait_for_asset_value(
                    &client,
                    &asset_id,
                    &expected_new_value,
                    "account-created trigger",
                )
            }
        })
        .await??;
        let neverland: DomainId = DomainId::try_new("neverland", "universal")?;
        let setup_neverland = domain_setup_instruction(&neverland, test_client.client().account())?;
        spawn_blocking({
            let client = test_client.clone();
            move || {
                client.submit(
                    setup_neverland,
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                )
            }
        })
        .await??;
        let expected_newer_value = new_value.checked_add(&Quantity::one()).unwrap();
        let expected_newer_value_for_wait = expected_newer_value.clone();
        let newer_value = spawn_blocking({
            let client = test_client.clone();
            let asset_id = asset_id.clone();
            move || {
                wait_for_asset_value(
                    &client,
                    &asset_id,
                    &expected_newer_value_for_wait,
                    "domain-created trigger",
                )
            }
        })
        .await??;
        assert_eq!(newer_value, expected_newer_value);
        Ok(())
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn four_peer_scoped_one_shot_data_triggers_roll_back_atomically() -> Result<()> {
    const VALIDATOR_COUNT: usize = 4;
    let context = stringify!(four_peer_scoped_one_shot_data_triggers_roll_back_atomically);
    let network = sandbox::start_network_async_or_skip(
        NetworkBuilder::new()
            .with_peers(VALIDATOR_COUNT)
            .with_auto_populated_trusted_peers(),
        context,
    )
    .await?;
    let Some(network) = sandbox::enforce_network_start_requirement(network, context)? else {
        return Ok(());
    };
    assert_eq!(network.peers().len(), VALIDATOR_COUNT);
    network.ensure_blocks(1).await?;
    let client = network.client();
    run_or_skip(context, || async {
        let rose_definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal")?,
            "rose".parse()?,
        );
        let rose = AssetId::new(rose_definition, ALICE_ID.clone());
        let scoped_marker: Name = "scoped_one_shot_marker".parse()?;
        let unrelated_marker: Name = "unrelated_account_event".parse()?;
        let scope_trigger_id: TriggerId = "00_scoped_one_shot".parse()?;
        let scope_trigger = Register::trigger(Trigger::new(
            scope_trigger_id.clone(),
            Action::new(
                [SetKeyValue::account(
                    ALICE_ID.clone(),
                    scoped_marker.clone(),
                    Json::from(true),
                )],
                Repeats::Exactly(1),
                ALICE_ID.clone(),
                AssetEventFilter::new().for_asset(rose.clone()),
            )
            .expect("exact owned-asset data-trigger action is valid"),
        ));
        spawn_blocking({
            let client = client.clone();
            move || {
                client.submit(
                    scope_trigger,
                    FeePaymentIntent::authority(Vec::new(), None),
                )
            }
        })
        .await??;

        spawn_blocking({
            let client = client.clone();
            let unrelated_marker = unrelated_marker.clone();
            move || {
                client.submit(
                    SetKeyValue::account(
                        ALICE_ID.clone(),
                        unrelated_marker,
                        Json::from("probe"),
                    ),
                    FeePaymentIntent::authority(Vec::new(), None),
                )
            }
        })
        .await??;
        let account = spawn_blocking({
            let client = client.clone();
            move || client.client().query_single(FindAccountById::new(ALICE_ID.clone()))
        })
        .await??;
        assert!(
            account.metadata().get(&scoped_marker).is_none(),
            "an unrelated account event must not fire an exact asset-scoped trigger"
        );
        let active = spawn_blocking({
            let client = client.clone();
            move || client.client().query(FindActiveTriggerIds).execute_all()
        })
        .await??;
        assert!(active.contains(&scope_trigger_id));

        spawn_blocking({
            let client = client.clone();
            let rose = rose.clone();
            move || {
                client.submit(
                    Mint::asset_quantity(1_u32, rose),
                    FeePaymentIntent::authority(Vec::new(), None),
                )
            }
        })
        .await??;
        let account = spawn_blocking({
            let client = client.clone();
            move || client.client().query_single(FindAccountById::new(ALICE_ID.clone()))
        })
        .await??;
        assert_eq!(
            account.metadata().get(&scoped_marker),
            Some(&Json::from(true)),
            "the exact owned-asset event must fire the scoped trigger"
        );
        let active = spawn_blocking({
            let client = client.clone();
            move || client.client().query(FindActiveTriggerIds).execute_all()
        })
        .await??;
        assert!(
            !active.contains(&scope_trigger_id),
            "the one-shot trigger must be depleted after exactly one matching event"
        );

        let ordering_witness: Name = "data_trigger_ordering_witness".parse()?;
        let create_witness_id: TriggerId = "10_create_ordering_witness".parse()?;
        let consume_then_fail_id: TriggerId = "20_consume_then_fail".parse()?;
        let wonderland = DomainId::try_new("wonderland", "universal")?;
        let create_witness = Register::trigger(Trigger::new(
            create_witness_id.clone(),
            Action::new(
                [SetKeyValue::account(
                    ALICE_ID.clone(),
                    ordering_witness.clone(),
                    Json::from(true),
                )],
                Repeats::Exactly(1),
                ALICE_ID.clone(),
                AssetEventFilter::new().for_asset(rose.clone()),
            )
            .expect("ordering-witness data-trigger action is valid"),
        ));
        let consume_then_fail = Register::trigger(Trigger::new(
            consume_then_fail_id.clone(),
            Action::new(
                [
                    InstructionBox::from(RemoveKeyValue::account(
                        ALICE_ID.clone(),
                        ordering_witness.clone(),
                    )),
                    InstructionBox::from(Register::domain(Domain::new(wonderland.clone()))),
                ],
                Repeats::Exactly(1),
                ALICE_ID.clone(),
                AssetEventFilter::new().for_asset(rose.clone()),
            )
            .expect("failing data-trigger action is valid"),
        ));
        spawn_blocking({
            let client = client.clone();
            move || {
                client.submit_all(
                    [create_witness, consume_then_fail],
                    FeePaymentIntent::authority(Vec::new(), None),
                )
            }
        })
        .await??;

        let rose_before = spawn_blocking({
            let client = client.clone();
            let rose = rose.clone();
            move || asset_value(&client, &rose)
        })
        .await??;
        let error = spawn_blocking({
            let client = client.clone();
            let rose = rose.clone();
            move || {
                client.submit(
                    Mint::asset_quantity(1_u32, rose),
                    FeePaymentIntent::authority(Vec::new(), None),
                )
            }
        })
        .await?
        .expect_err("the second canonically ordered data trigger must reject the transaction");
        assert!(
            format!("{error:?}").contains(&wonderland.to_string()),
            "the rejection must come from the duplicate-domain instruction after the first trigger created and the second consumed its witness: {error:?}"
        );

        let rose_after = spawn_blocking({
            let client = client.clone();
            let rose = rose.clone();
            move || asset_value(&client, &rose)
        })
        .await??;
        assert_eq!(
            rose_after, rose_before,
            "a failed data-trigger cascade must roll back its originating mint"
        );
        let account = spawn_blocking({
            let client = client.clone();
            move || client.client().query_single(FindAccountById::new(ALICE_ID.clone()))
        })
        .await??;
        assert!(account.metadata().get(&ordering_witness).is_none());
        let active = spawn_blocking({
            let client = client.clone();
            move || client.client().query(FindActiveTriggerIds).execute_all()
        })
        .await??;
        assert!(
            active.contains(&create_witness_id) && active.contains(&consume_then_fail_id),
            "atomic rollback must preserve both one-shot repeat budgets"
        );
        Ok(())
    })
    .await
}

/// # Scenario
///
/// 1. Capture the current maximum execution depth.
/// 2. Bump the maximum allowed depth via a `SetParameter` instruction.
/// 3. After the change, the maximum allowed depth remains elevated.
///
/// Note: the current execution depth cannot be inspected.
///
/// # Implications
///
/// This test illustrates a potential loophole rather than a legitimate use case.
/// Under `Repeats::Indefinitely`, the trigger would loop indefinitely.
/// Such behavior must be prevented by enforcing:
/// - permissions for executable calls (#5441) and event subscriptions (#5439)
/// - quotas or fee-based consumption (#5440)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cat_depth_and_mouse_depth() -> Result<()> {
    let Some(network) =
        start_custom_network(NetworkBuilder::new(), stringify!(cat_depth_and_mouse_depth)).await?
    else {
        return Ok(());
    };
    let test_client = network.client();
    run_or_skip(stringify!(cat_depth_and_mouse_depth), || async {
        let mut parameters = spawn_blocking({
            let client = test_client.clone();
            move || client.client().query_single(FindParameters)
        })
        .await??;
        let base_depth = parameters.smart_contract().execution_depth();
        assert!(base_depth > 0, "execution depth should be positive");
        let new_depth = base_depth
            .checked_add(110)
            .expect("execution depth increase should fit in u8");
        spawn_blocking({
            let client = test_client.clone();
            move || {
                client.submit(
                    SetParameter::new(Parameter::SmartContract(
                        iroha_data_model::parameter::SmartContractParameter::ExecutionDepth(
                            new_depth,
                        ),
                    )),
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                )
            }
        })
        .await??;
        parameters = spawn_blocking({
            let client = test_client.clone();
            move || client.client().query_single(FindParameters)
        })
        .await??;
        assert_eq!(new_depth, parameters.smart_contract().execution_depth());
        Ok(())
    })
    .await
}
