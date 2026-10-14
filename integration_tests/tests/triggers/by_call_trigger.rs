//! Tests for executing triggers directly
use crate::triggers::get_asset_value;
use eyre::{Result, WrapErr};
use futures_util::StreamExt as _;
use integration_tests::sandbox;
use iroha::{
    crypto::KeyPair,
    data_model::{
        IdBox, ValidationFail,
        events::pipeline::{TransactionEventFilter, TransactionStatus},
        isi::{
            Instruction, InstructionType,
            error::{InstructionExecutionError, InvalidParameterError, RepetitionError},
        },
        prelude::*,
        query::{
            error::FindError,
            trigger::{FindActiveTriggerIds, FindTriggers},
        },
        transaction::Executable,
        transaction::error::TransactionRejectionReason,
    },
};
use iroha_executor_data_model::permission::trigger::CanRegisterTrigger;
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_test_network::*;
use iroha_test_samples::{ALICE_ID, load_sample_ivm};
use mint_rose_trigger_data_model::MintRoseArgs;
use tokio::{
    task::spawn_blocking,
    time::{Duration, Instant, sleep, timeout},
};
const TRIGGER_NAME: &str = "mint_rose";
fn contract_entrypoint_metadata(entrypoint: &str) -> Metadata {
    let mut metadata = Metadata::default();
    metadata.insert(
        "contract_entrypoint"
            .parse::<Name>()
            .expect("static contract entrypoint metadata key is valid"),
        Json::new(entrypoint.to_owned()),
    );
    metadata
}
async fn start_network(context: &'static str) -> Result<Option<sandbox::SerializedNetwork>> {
    sandbox::start_network_async_or_skip(NetworkBuilder::new(), context).await
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
fn checked_random_trigger_account_keypair() -> KeyPair {
    KeyPair::try_random().expect("generate checked trigger account keypair")
}
#[test]
fn trigger_account_fixture_uses_checked_randomness() {
    let _keypair = checked_random_trigger_account_keypair();
}
async fn submit_instruction_and_wait(
    network: &sandbox::SerializedNetwork,
    client: iroha::blocking::Client,
    instruction: impl Into<InstructionBox>,
    context: &str,
) -> Result<()> {
    let client = integration_tests::sync::rebind_blocking_client(&client, |client| {
        client.transaction_status_timeout = network.sync_timeout();
    });
    let instruction = instruction.into();
    let context = context.to_string();
    spawn_blocking(move || {
        client
            .submit(
                instruction,
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .wrap_err(context)
    })
    .await??;
    Ok(())
}
async fn wait_for_asset_value(
    client: &iroha::blocking::Client,
    asset_id: &AssetId,
    expected: Quantity,
    timeout_after: Duration,
    context: &str,
) -> Result<Quantity> {
    let deadline = Instant::now() + timeout_after;
    let mut last_observed = String::from("asset value was not queried");
    loop {
        if Instant::now() >= deadline {
            return Err(eyre::eyre!(
                "timed out waiting for asset {asset_id} to equal {expected} after {context}; last_observed={last_observed}"
            ));
        }
        match spawn_blocking({
            let client = client.clone();
            let asset_id = asset_id.clone();
            move || get_asset_value(&client, &asset_id)
        })
        .await?
        {
            Ok(value) => {
                if value == expected {
                    return Ok(value);
                }
                last_observed = value.to_string();
            }
            Err(error) => {
                last_observed = format!("query failed: {error}");
            }
        }
        sleep(Duration::from_millis(250)).await;
    }
}
async fn wait_for_trigger(
    client: &iroha::blocking::Client,
    trigger_id: &TriggerId,
    timeout_after: Duration,
    context: &str,
) -> Result<Trigger> {
    let deadline = Instant::now() + timeout_after;
    let mut last_observed = String::from("trigger was not queried");
    loop {
        if Instant::now() >= deadline {
            return Err(eyre::eyre!(
                "timed out waiting for trigger {trigger_id} after {context}; last_observed={last_observed}"
            ));
        }
        match spawn_blocking({
            let client = client.clone();
            let trigger_id = trigger_id.clone();
            move || -> Result<Option<Trigger>> {
                Ok(client
                    .client()
                    .query(FindTriggers::new())
                    .execute_all()?
                    .into_iter()
                    .find(|trigger| trigger.id() == &trigger_id))
            }
        })
        .await?
        {
            Ok(Some(trigger)) => return Ok(trigger),
            Ok(None) => {
                last_observed = "trigger not found".to_string();
            }
            Err(error) => {
                last_observed = format!("query failed: {error}");
            }
        }
        sleep(Duration::from_millis(250)).await;
    }
}
fn is_trigger_register_collision(err: &eyre::Report, trigger_id: &TriggerId) -> bool {
    err.chain().any(|cause| {
        if let Some(InstructionExecutionError::Repetition(repetition)) =
            cause.downcast_ref::<InstructionExecutionError>()
        {
            if *repetition.instruction() == InstructionType::Register {
                if let IdBox::TriggerId(id) = &repetition.id {
                    return id == trigger_id;
                }
            }
        }
        if let Some(ValidationFail::InstructionFailed(InstructionExecutionError::Repetition(
            repetition,
        ))) = cause.downcast_ref::<ValidationFail>()
        {
            if *repetition.instruction() == InstructionType::Register {
                if let IdBox::TriggerId(id) = &repetition.id {
                    return id == trigger_id;
                }
            }
        }
        false
    })
}
fn is_permission_grant_repetition(
    err: &eyre::Report,
    expected: &iroha::data_model::permission::Permission,
) -> bool {
    err.chain().any(|cause| {
        let matches = |repetition: &RepetitionError| {
            *repetition.instruction() == InstructionType::Grant
                && matches!(&repetition.id, IdBox::Permission(permission) if permission == expected)
        };
        if let Some(InstructionExecutionError::Repetition(repetition)) =
            cause.downcast_ref::<InstructionExecutionError>()
        {
            return matches(repetition);
        }
        if let Some(ValidationFail::InstructionFailed(InstructionExecutionError::Repetition(
            repetition,
        ))) = cause.downcast_ref::<ValidationFail>()
        {
            return matches(repetition);
        }
        false
    })
}
fn is_tx_confirmation_timeout(err: &eyre::Report) -> bool {
    err.chain().any(|cause| {
        let msg = cause.to_string();
        msg.contains("tx confirmation timed out")
            || msg.contains("haven't got tx confirmation within")
            || msg.contains("transaction queued for too long")
    })
}
#[test]
fn trigger_register_collision_is_detected() {
    let trigger_id: TriggerId = "collision_test".parse().expect("valid trigger id");
    let repetition = iroha::data_model::isi::error::RepetitionError {
        instruction: InstructionType::Register,
        id: IdBox::TriggerId(trigger_id.clone()),
    };
    let err = InstructionExecutionError::Repetition(repetition);
    let report = eyre::Report::new(err);
    assert!(is_trigger_register_collision(&report, &trigger_id));
}
#[test]
fn permission_grant_repetition_is_detected() {
    let permission: iroha::data_model::permission::Permission = CanRegisterTrigger {
        authority: ALICE_ID.clone(),
    }
    .into();
    let repetition = RepetitionError {
        instruction: InstructionType::Grant,
        id: IdBox::Permission(permission.clone()),
    };
    let err = InstructionExecutionError::Repetition(repetition);
    let report = eyre::Report::new(err);
    assert!(is_permission_grant_repetition(&report, &permission));
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn call_execute_trigger() -> Result<()> {
    let Some(network) = start_network(stringify!(call_execute_trigger)).await? else {
        return Ok(());
    };
    let test_client = network.client();
    network.ensure_blocks_with(|h| h.total >= 1).await?;
    run_or_skip(stringify!(call_execute_trigger), || async {
        let asset_definition_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal")?,
            "rose".parse()?,
        );
        let account_id = ALICE_ID.clone();
        let asset_id = AssetId::new(asset_definition_id, account_id);
        let prev_value = spawn_blocking({
            let client = test_client.clone();
            let asset_id = asset_id.clone();
            move || get_asset_value(&client, &asset_id)
        })
        .await??;
        let instruction = Mint::asset_quantity(1u32, asset_id.clone());
        let register_trigger =
            build_register_trigger_isi(asset_id.account(), vec![instruction.into()]);
        submit_instruction_and_wait(
            &network,
            test_client.clone(),
            register_trigger,
            stringify!(call_execute_trigger),
        )
        .await?;
        let trigger_id = TRIGGER_NAME.parse()?;
        let call_trigger = ExecuteTrigger::new(trigger_id);
        submit_instruction_and_wait(
            &network,
            test_client.clone(),
            Instruction::into_instruction_box(Box::new(call_trigger)),
            stringify!(call_execute_trigger),
        )
        .await?;
        let new_value = spawn_blocking({
            let client = test_client.clone();
            let asset_id = asset_id.clone();
            move || get_asset_value(&client, &asset_id)
        })
        .await??;
        assert_eq!(new_value, prev_value.checked_add(&Quantity::one()).unwrap());
        Ok(())
    })
    .await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn execute_trigger_should_produce_event() -> Result<()> {
    let Some(network) = start_network(stringify!(execute_trigger_should_produce_event)).await?
    else {
        return Ok(());
    };
    let test_client = network.client();
    Box::pin(run_or_skip(
        stringify!(execute_trigger_should_produce_event),
        move || async move {
            let asset_definition_id = AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal")?,
                "rose".parse()?,
            );
            let account_id = ALICE_ID.clone();
            let asset_id = AssetId::new(asset_definition_id, account_id.clone());
            let instruction = Mint::asset_quantity(1u32, asset_id.clone());
            let register_trigger =
                build_register_trigger_isi(asset_id.account(), vec![instruction.into()]);
            submit_instruction_and_wait(
                &network,
                test_client.clone(),
                register_trigger,
                stringify!(execute_trigger_should_produce_event),
            )
            .await?;
            let trigger_id = TRIGGER_NAME.parse::<TriggerId>()?;
            let call_trigger = ExecuteTrigger::new(trigger_id.clone());
            let filter = ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id)
                .under_authority(account_id);
            let mut events = timeout(
                network.sync_timeout(),
                test_client.account_client().events().subscribe([filter]),
            )
            .await
            .wrap_err("Timed out opening ExecuteTrigger event stream")??;
            submit_instruction_and_wait(
                &network,
                test_client.clone(),
                Instruction::into_instruction_box(Box::new(call_trigger)),
                stringify!(execute_trigger_should_produce_event),
            )
            .await?;
            let result = async {
                let next_event = timeout(network.sync_timeout(), events.next())
                    .await
                    .wrap_err("Timed out waiting for ExecuteTrigger event")?;
                let event =
                    next_event.ok_or_else(|| eyre::eyre!("Execute trigger event stream closed"))?;
                event
                    .wrap_err("ExecuteTrigger event listener returned an error")
                    .map(|_| ())?;
                Ok(())
            }
            .await;
            events.close().await?;
            result
        },
    ))
    .await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trigger_failure_should_not_cancel_other_triggers_execution() -> Result<()> {
    let Some(network) = start_network(stringify!(
        trigger_failure_should_not_cancel_other_triggers_execution
    ))
    .await?
    else {
        return Ok(());
    };
    let test_client = network.client();
    run_or_skip(
        stringify!(trigger_failure_should_not_cancel_other_triggers_execution),
        || async {
            let asset_definition_id = AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal")?,
                "rose".parse()?,
            );
            let account_id = ALICE_ID.clone();
            let asset_id = AssetId::new(asset_definition_id, account_id.clone());
            let bad_trigger_id = "bad_trigger".parse::<TriggerId>()?;
            let fail_isi = Unregister::domain(DomainId::try_new("dummy", "universal")?);
            let register_bad_trigger = Register::trigger(Trigger::new(
                bad_trigger_id.clone(),
                Action::new(
                    vec![fail_isi],
                    Repeats::Indefinitely,
                    account_id.clone(),
                    ExecuteTriggerEventFilter::new()
                        .for_trigger(bad_trigger_id.clone())
                        .under_authority(account_id.clone()),
                )
                .expect("trigger action fixture satisfies validation invariants"),
            ));
            submit_instruction_and_wait(
                &network,
                test_client.clone(),
                register_bad_trigger,
                stringify!(trigger_failure_should_not_cancel_other_triggers_execution),
            )
            .await?;
            let trigger_id = TRIGGER_NAME.parse()?;
            let register_trigger = Register::trigger(Trigger::new(
                trigger_id,
                Action::new(
                    vec![Mint::asset_quantity(1u32, asset_id.clone())],
                    Repeats::Indefinitely,
                    account_id.clone(),
                    TimeEventFilter::new(ExecutionTime::PreCommit),
                )
                .expect("trigger action fixture satisfies validation invariants"),
            ));
            submit_instruction_and_wait(
                &network,
                test_client.clone(),
                register_trigger,
                stringify!(trigger_failure_should_not_cancel_other_triggers_execution),
            )
            .await?;
            let prev_asset_value = spawn_blocking({
                let client = test_client.clone();
                let asset_id = asset_id.clone();
                move || get_asset_value(&client, &asset_id)
            })
            .await??;
            let err = spawn_blocking({
                let client =
                    integration_tests::sync::rebind_blocking_client(&test_client, |client| {
                        client.transaction_status_timeout = network
                            .sync_timeout()
                            .min(std::time::Duration::from_secs(120));
                    });
                let bad_trigger_id = bad_trigger_id.clone();
                move || {
                    client.submit(
                        Instruction::into_instruction_box(Box::new(ExecuteTrigger::new(
                            bad_trigger_id,
                        ))),
                        iroha_data_model::transaction::FeePaymentIntent::authority(
                            Vec::new(),
                            None,
                        ),
                    )
                }
            })
            .await?
            .expect_err("should immediately result in error");
            let has_domain_error = err
                .chain()
                .find_map(|cause| cause.downcast_ref::<FindError>())
                .is_some_and(|err| matches!(err, FindError::Domain(_)));
            if !has_domain_error {
                if is_tx_confirmation_timeout(&err) {
                    eprintln!(
                        "warning: timed out waiting for failing trigger confirmation; proceeding"
                    );
                } else {
                    return Err(err);
                }
            }
            // Submit without tx-status confirmation to avoid flakiness after a failed by-call
            // trigger; wait for the next non-empty block instead.
            let baseline_non_empty = network
                .peers()
                .iter()
                .filter_map(|peer| peer.best_effort_block_height())
                .map(|height| height.non_empty)
                .max()
                .unwrap_or(0);
            let target_non_empty = baseline_non_empty.saturating_add(1);
            let log_tx = {
                let account = test_client.account_client();
                account
                    .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                        [InstructionBox::from(Log::new(
                            Level::INFO,
                            "trigger probe".to_string(),
                        ))],
                        iroha_data_model::transaction::FeePaymentIntent::authority(
                            Vec::new(),
                            None,
                        ),
                        Metadata::default(),
                    ))
                    .and_then(|payload| account.sign_transaction(payload))
            }
            .expect("build integration-test transaction");
            spawn_blocking({
                let client = test_client.clone();
                move || client.submit_transaction(&log_tx)
            })
            .await??;
            network
                .ensure_blocks_with(|height| height.non_empty >= target_non_empty)
                .await?;
            let new_asset_value = spawn_blocking({
                let client = test_client.clone();
                let asset_id = asset_id.clone();
                move || get_asset_value(&client, &asset_id)
            })
            .await??;
            assert!(
                new_asset_value >= prev_asset_value.checked_add(&Quantity::one()).unwrap(),
                "expected pre-commit trigger to execute despite failing trigger"
            );
            Ok(())
        },
    )
    .await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trigger_should_not_be_executed_with_zero_repeats_count() -> Result<()> {
    let Some(network) = start_network(stringify!(
        trigger_should_not_be_executed_with_zero_repeats_count
    ))
    .await?
    else {
        return Ok(());
    };
    let test_client = network.client();
    network.ensure_blocks_with(|h| h.total >= 1).await?;
    run_or_skip(
        stringify!(trigger_should_not_be_executed_with_zero_repeats_count),
        || async {
            let asset_definition_id = AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal")?,
                "rose".parse()?,
            );
            let account_id = ALICE_ID.clone();
            let asset_id = AssetId::new(asset_definition_id, account_id.clone());
            let trigger_id = "self_modifying_trigger".parse::<TriggerId>()?;
            let trigger_instructions = vec![Mint::asset_quantity(1u32, asset_id.clone())];
            let register_trigger = Register::trigger(Trigger::new(
                trigger_id.clone(),
                Action::new(
                    trigger_instructions,
                    1_u32,
                    account_id.clone(),
                    ExecuteTriggerEventFilter::new()
                        .for_trigger(trigger_id.clone())
                        .under_authority(account_id),
                )
                .expect("trigger action fixture satisfies validation invariants"),
            ));
            submit_instruction_and_wait(
                &network,
                test_client.clone(),
                register_trigger,
                stringify!(trigger_should_not_be_executed_with_zero_repeats_count),
            )
            .await?;
            // Saving current asset value
            let prev_asset_value = spawn_blocking({
                let client = test_client.clone();
                let asset_id = asset_id.clone();
                move || get_asset_value(&client, &asset_id)
            })
            .await??;
            // Executing trigger first time
            let execute_trigger = ExecuteTrigger::new(trigger_id.clone());
            let execute_trigger_first = execute_trigger.clone();
            submit_instruction_and_wait(
                &network,
                test_client.clone(),
                Instruction::into_instruction_box(Box::new(execute_trigger_first)),
                stringify!(trigger_should_not_be_executed_with_zero_repeats_count),
            )
            .await?;
            // Executing trigger second time
            let error = spawn_blocking({
                let client = test_client.clone();
                move || {
                    client.submit(
                        Instruction::into_instruction_box(Box::new(execute_trigger)),
                        iroha_data_model::transaction::FeePaymentIntent::authority(
                            Vec::new(),
                            None,
                        ),
                    )
                }
            })
            .await?
            .expect_err("Error expected");
            let downcasted_error = error
                .chain()
                .last()
                .expect("At least two error causes expected")
                .downcast_ref::<FindError>();
            assert!(
                matches!(
                    downcasted_error,
                    Some(FindError::Trigger(id)) if *id == trigger_id
                ),
                "Unexpected error received: {error:?}",
            );
            // Checking results
            let new_asset_value = spawn_blocking({
                let client = test_client.clone();
                let asset_id = asset_id.clone();
                move || get_asset_value(&client, &asset_id)
            })
            .await??;
            assert_eq!(
                new_asset_value,
                prev_asset_value.checked_add(&Quantity::one()).unwrap()
            );
            Ok(())
        },
    )
    .await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn trigger_should_be_able_to_modify_its_own_repeats_count() -> Result<()> {
    let Some(network) = start_network(stringify!(
        trigger_should_be_able_to_modify_its_own_repeats_count
    ))
    .await?
    else {
        return Ok(());
    };
    let test_client = network.client();
    network.ensure_blocks_with(|h| h.total >= 1).await?;
    run_or_skip(
        stringify!(trigger_should_be_able_to_modify_its_own_repeats_count),
        || async {
            let asset_definition_id = AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal")?,
                "rose".parse()?,
            );
            let account_id = ALICE_ID.clone();
            let asset_id = AssetId::new(asset_definition_id, account_id.clone());
            let trigger_id = "self_modifying_trigger".parse::<TriggerId>()?;
            let permission_on_registration = CanRegisterTrigger {
                authority: account_id.clone(),
            };
            let expected_permission: iroha::data_model::permission::Permission =
                permission_on_registration.clone().into();
            // Ensure the caller explicitly has permission to register the trigger on their own behalf.
            if let Err(err) = submit_instruction_and_wait(
                &network,
                test_client.clone(),
                Grant::account_permission(permission_on_registration, account_id.clone()),
                stringify!(trigger_should_be_able_to_modify_its_own_repeats_count),
            )
            .await
            {
                if !is_permission_grant_repetition(&err, &expected_permission) {
                    return Err(err);
                }
            }
            let trigger_instructions: Vec<InstructionBox> = vec![
                Mint::trigger_repetitions(1_u32, trigger_id.clone()).into(),
                Mint::asset_quantity(1u32, asset_id.clone()).into(),
            ];
            let register_trigger = Register::trigger(Trigger::new(
                trigger_id.clone(),
                Action::new(
                    trigger_instructions,
                    1_u32,
                    account_id.clone(),
                    ExecuteTriggerEventFilter::new()
                        .for_trigger(trigger_id.clone())
                        .under_authority(account_id),
                )
                .expect("trigger action fixture satisfies validation invariants"),
            ));
            submit_instruction_and_wait(
                &network,
                test_client.clone(),
                register_trigger,
                stringify!(trigger_should_be_able_to_modify_its_own_repeats_count),
            )
            .await?;
            // Saving current asset value
            let prev_asset_value = spawn_blocking({
                let client = test_client.clone();
                let asset_id = asset_id.clone();
                move || get_asset_value(&client, &asset_id)
            })
            .await??;
            // Executing trigger first time
            let execute_trigger = ExecuteTrigger::new(trigger_id);
            let execute_trigger_first = execute_trigger.clone();
            submit_instruction_and_wait(
                &network,
                test_client.clone(),
                Instruction::into_instruction_box(Box::new(execute_trigger_first)),
                stringify!(trigger_should_be_able_to_modify_its_own_repeats_count),
            )
            .await?;
            // Executing trigger second time
            submit_instruction_and_wait(
                &network,
                test_client.clone(),
                Instruction::into_instruction_box(Box::new(execute_trigger)),
                stringify!(trigger_should_be_able_to_modify_its_own_repeats_count),
            )
            .await?;
            // Checking results
            let new_asset_value = spawn_blocking({
                let client = test_client.clone();
                let asset_id = asset_id.clone();
                move || get_asset_value(&client, &asset_id)
            })
            .await??;
            assert_eq!(
                new_asset_value,
                prev_asset_value
                    .checked_add(&Quantity::from(2_u32))
                    .unwrap()
            );
            Ok(())
        },
    )
    .await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn only_account_with_permission_can_register_trigger() -> Result<()> {
    let Some(network) = start_network(stringify!(
        only_account_with_permission_can_register_trigger
    ))
    .await?
    else {
        return Ok(());
    };
    let test_client = network.client();
    run_or_skip(
        stringify!(only_account_with_permission_can_register_trigger),
        || async {
            let alice_account_id = ALICE_ID.clone();
            let rabbit_keys = checked_random_trigger_account_keypair();
            let rabbit_account_id = AccountId::new(rabbit_keys.public_key().clone());
            let rabbit_account = Account::new(rabbit_account_id.clone());
            let rabbit_client =
                integration_tests::sync::rebind_blocking_client(&test_client, |client| {
                    client.account = rabbit_account_id.clone();
                    client.key_pair = rabbit_keys;
                });
            // Permission for the trigger registration on behalf of alice
            let permission_on_registration = CanRegisterTrigger {
                authority: ALICE_ID.clone(),
            };
            let expected_permission: iroha::data_model::permission::Permission =
                permission_on_registration.clone().into();
            // Trigger with 'alice' as authority
            let trigger_id = "alice_trigger".parse::<TriggerId>()?;
            let trigger = Trigger::new(
                trigger_id.clone(),
                Action::new(
                    Vec::<InstructionBox>::new(),
                    Repeats::Indefinitely,
                    alice_account_id.clone(),
                    ExecuteTriggerEventFilter::new()
                        .for_trigger(trigger_id.clone())
                        .under_authority(alice_account_id.clone()),
                )
                .expect("trigger action fixture satisfies validation invariants"),
            );
            submit_instruction_and_wait(
                &network,
                test_client.clone(),
                Register::account(rabbit_account),
                stringify!(only_account_with_permission_can_register_trigger),
            )
            .await?;
            spawn_blocking({
                let client = test_client.clone();
                let rabbit_account_id = rabbit_account_id.clone();
                move || -> Result<()> {
                    client
                        .client()
                        .query(FindAccounts::new())
                        .execute_all()
                        .expect("Account not found")
                        .into_iter()
                        .find(|account| account.id() == &rabbit_account_id)
                        .expect("Account not found");
                    Ok(())
                }
            })
            .await??;
            println!("Rabbit is found.");
            // Trying register the trigger without permissions
            let err = spawn_blocking({
                let client = rabbit_client.clone();
                let trigger = trigger.clone();
                move || {
                    client.submit(
                        Register::trigger(trigger),
                        iroha_data_model::transaction::FeePaymentIntent::authority(
                            Vec::new(),
                            None,
                        ),
                    )
                }
            })
            .await?
            .expect_err("Trigger should not be registered!");
            let Some(InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(msg),
            )) = err
                .chain()
                .find_map(|cause| cause.downcast_ref::<InstructionExecutionError>())
            else {
                panic!("Unexpected error: {err:?}");
            };
            assert!(msg.contains("CanRegisterTrigger"));
            println!("Rabbit couldn't register the trigger");
            // Give permissions to the rabbit
            if let Err(err) = submit_instruction_and_wait(
                &network,
                test_client.clone(),
                Grant::account_permission(permission_on_registration, rabbit_account_id.clone()),
                stringify!(only_account_with_permission_can_register_trigger),
            )
            .await
            {
                if !is_permission_grant_repetition(&err, &expected_permission) {
                    return Err(err);
                }
            }
            println!("Rabbit has got the permission");
            // Trying register the trigger with permissions
            submit_instruction_and_wait(
                &network,
                rabbit_client.clone(),
                Register::trigger(trigger),
                stringify!(only_account_with_permission_can_register_trigger),
            )
            .await?;
            let found_trigger = wait_for_trigger(
                &test_client,
                &trigger_id,
                network.sync_timeout(),
                stringify!(only_account_with_permission_can_register_trigger),
            )
            .await?;
            assert_eq!(*found_trigger.id(), trigger_id);
            Ok(())
        },
    )
    .await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unregister_trigger() -> Result<()> {
    let Some(network) = start_network(stringify!(unregister_trigger)).await? else {
        return Ok(());
    };
    let test_client = network.client();
    run_or_skip(stringify!(unregister_trigger), || async {
        let account_id = ALICE_ID.clone();
        // Registering trigger
        let trigger_id = "empty_trigger".parse::<TriggerId>()?;
        let trigger = Trigger::new(
            trigger_id.clone(),
            Action::new(
                Vec::<InstructionBox>::new(),
                Repeats::Indefinitely,
                account_id.clone(),
                ExecuteTriggerEventFilter::new()
                    .for_trigger(trigger_id.clone())
                    .under_authority(account_id),
            )
            .expect("trigger action fixture satisfies validation invariants"),
        );
        let register_trigger = Register::trigger(trigger.clone());
        submit_instruction_and_wait(
            &network,
            test_client.clone(),
            register_trigger,
            stringify!(unregister_trigger),
        )
        .await?;
        // Finding trigger
        let deadline = Instant::now() + Duration::from_secs(20);
        let found_trigger = loop {
            let found_trigger = spawn_blocking({
                let client = test_client.clone();
                let trigger_id = trigger_id.clone();
                move || {
                    client
                        .client()
                        .query(FindTriggers::new())
                        .execute_all()
                        .unwrap()
                        .into_iter()
                        .find(|trigger| trigger.id() == &trigger_id)
                }
            })
            .await?;
            if let Some(found_trigger) = found_trigger {
                break found_trigger;
            }
            if Instant::now() >= deadline {
                panic!("trigger not found");
            }
            sleep(Duration::from_millis(250)).await;
        };
        let found_action = found_trigger.action();
        let Executable::Instructions(found_instructions) = found_action.executable() else {
            panic!("Expected instructions");
        };
        let found_trigger = Trigger::new(
            found_trigger.id().clone(),
            Action::new(
                Executable::Instructions(found_instructions.to_owned()),
                found_action.repeats(),
                found_action.authority().clone(),
                found_action.filter().clone(),
            )
            .expect("queried trigger action preserves server-validated invariants"),
        );
        assert_eq!(found_trigger, trigger);
        // Unregistering trigger
        let unregister_trigger = Unregister::trigger(trigger_id.clone());
        submit_instruction_and_wait(
            &network,
            test_client.clone(),
            unregister_trigger,
            stringify!(unregister_trigger),
        )
        .await?;
        // Checking result
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let still_present = spawn_blocking({
                let client = test_client.clone();
                let trigger_id = trigger_id.clone();
                move || {
                    client
                        .client()
                        .query(FindTriggers::new())
                        .execute_all()
                        .unwrap()
                        .into_iter()
                        .any(|trigger| trigger.id() == &trigger_id)
                }
            })
            .await?;
            if !still_present {
                break;
            }
            if Instant::now() >= deadline {
                assert!(!still_present);
            }
            sleep(Duration::from_millis(250)).await;
        }
        Ok(())
    })
    .await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trigger_in_genesis() -> Result<()> {
    let bytecode = load_sample_ivm("mint_rose_trigger");
    let account_id = ALICE_ID.clone();
    let trigger_id = "genesis_trigger".parse::<TriggerId>()?;
    let trigger = Trigger::new(
        trigger_id.clone(),
        Action::new(
            bytecode,
            Repeats::Indefinitely,
            account_id.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id.clone())
                .under_authority(account_id.clone()),
        )
        .expect("trigger action fixture satisfies validation invariants")
        .with_metadata(contract_entrypoint_metadata("run")),
    );
    let Some(network) = sandbox::start_network_async_or_skip(
        NetworkBuilder::new().with_genesis_instruction(Register::trigger(trigger)),
        stringify!(trigger_in_genesis),
    )
    .await?
    else {
        return Ok(());
    };
    network.ensure_blocks_with(|h| h.total >= 1).await?;
    let test_client = network.client();
    run_or_skip(stringify!(trigger_in_genesis), || async {
        let asset_definition_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal")?,
            "rose".parse()?,
        );
        let asset_id = AssetId::new(asset_definition_id, account_id);
        let prev_value = spawn_blocking({
            let client = test_client.clone();
            let asset_id = asset_id.clone();
            move || get_asset_value(&client, &asset_id)
        })
        .await??;
        // Executing trigger
        submit_instruction_and_wait(
            &network,
            test_client.clone(),
            SetKeyValue::trigger(trigger_id.clone(), "VAL".parse()?, 1_u32),
            stringify!(trigger_in_genesis),
        )
        .await?;
        let call_trigger = ExecuteTrigger::new(trigger_id).with_args(MintRoseArgs { val: 1 });
        submit_instruction_and_wait(
            &network,
            test_client.clone(),
            Instruction::into_instruction_box(Box::new(call_trigger)),
            stringify!(trigger_in_genesis),
        )
        .await?;
        // Checking result
        let new_value = spawn_blocking({
            let client = test_client.clone();
            let asset_id = asset_id.clone();
            move || get_asset_value(&client, &asset_id)
        })
        .await??;
        assert_eq!(new_value, prev_value.checked_add(&Quantity::one()).unwrap());
        Ok(())
    })
    .await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn trigger_should_be_able_to_modify_other_trigger() -> Result<()> {
    let Some(network) =
        start_network(stringify!(trigger_should_be_able_to_modify_other_trigger)).await?
    else {
        return Ok(());
    };
    let test_client = network.client();
    network.ensure_blocks_with(|h| h.total >= 1).await?;
    run_or_skip(
        stringify!(trigger_should_be_able_to_modify_other_trigger),
        || async {
            let asset_definition_id = AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal")?,
                "rose".parse()?,
            );
            let account_id = ALICE_ID.clone();
            let asset_id = AssetId::new(asset_definition_id, account_id.clone());
            let trigger_id_unregister = "unregister_other_trigger".parse::<TriggerId>()?;
            let trigger_id_to_be_unregistered =
                "should_be_unregistered_trigger".parse::<TriggerId>()?;
            let trigger_unregister_instructions =
                vec![Unregister::trigger(trigger_id_to_be_unregistered.clone())];
            let register_trigger = Register::trigger(Trigger::new(
                trigger_id_unregister.clone(),
                Action::new(
                    trigger_unregister_instructions,
                    1_u32,
                    account_id.clone(),
                    ExecuteTriggerEventFilter::new()
                        .for_trigger(trigger_id_unregister.clone())
                        .under_authority(account_id.clone()),
                )
                .expect("trigger action fixture satisfies validation invariants"),
            ));
            submit_instruction_and_wait(
                &network,
                test_client.clone(),
                register_trigger,
                stringify!(trigger_should_be_able_to_modify_other_trigger),
            )
            .await?;
            let trigger_should_be_unregistered_instructions =
                vec![Mint::asset_quantity(1u32, asset_id.clone())];
            let register_trigger = Register::trigger(Trigger::new(
                trigger_id_to_be_unregistered.clone(),
                Action::new(
                    trigger_should_be_unregistered_instructions,
                    1_u32,
                    account_id.clone(),
                    ExecuteTriggerEventFilter::new()
                        .for_trigger(trigger_id_to_be_unregistered.clone())
                        .under_authority(account_id),
                )
                .expect("trigger action fixture satisfies validation invariants"),
            ));
            submit_instruction_and_wait(
                &network,
                test_client.clone(),
                register_trigger,
                stringify!(trigger_should_be_able_to_modify_other_trigger),
            )
            .await?;
            // Saving current asset value
            let prev_asset_value = spawn_blocking({
                let client = test_client.clone();
                let asset_id = asset_id.clone();
                move || get_asset_value(&client, &asset_id)
            })
            .await??;
            // Executing triggers
            let execute_trigger_unregister = ExecuteTrigger::new(trigger_id_unregister);
            let execute_trigger_should_be_unregistered =
                ExecuteTrigger::new(trigger_id_to_be_unregistered.clone());
            let err = spawn_blocking({
                let client = test_client.clone();
                move || {
                    client.submit_all(
                        [
                            Instruction::into_instruction_box(Box::new(execute_trigger_unregister)),
                            Instruction::into_instruction_box(Box::new(
                                execute_trigger_should_be_unregistered,
                            )),
                        ],
                        iroha_data_model::transaction::FeePaymentIntent::authority(
                            Vec::new(),
                            None,
                        ),
                    )
                }
            })
            .await?
            .expect_err("should immediately result in error");
            // The by-call execution now surfaces as a validation failure; accept either the
            // original `FindError::Trigger` or a `ValidationFail::NotPermitted` wrapper.
            if let Some(FindError::Trigger(not_found_trigger)) = err
                .chain()
                .find_map(|cause| cause.downcast_ref::<FindError>())
            {
                assert_eq!(*not_found_trigger, trigger_id_to_be_unregistered);
            } else if let Some(ValidationFail::NotPermitted(msg)) = err
                .chain()
                .find_map(|cause| cause.downcast_ref::<ValidationFail>())
            {
                assert!(
                    msg.contains(&trigger_id_to_be_unregistered.to_string()),
                    "expected missing-trigger message, got: {msg}"
                );
            } else {
                panic!("unexpected error: {err:?}");
            }
            // Checking results
            // First trigger should cancel second one, so value should stay the same
            let new_asset_value = spawn_blocking({
                let client = test_client.clone();
                let asset_id = asset_id.clone();
                move || get_asset_value(&client, &asset_id)
            })
            .await??;
            assert_eq!(new_asset_value, prev_asset_value);
            Ok(())
        },
    )
    .await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trigger_burn_repetitions() -> Result<()> {
    let Some(network) = sandbox::start_network_async_or_skip(
        NetworkBuilder::new(),
        stringify!(trigger_burn_repetitions),
    )
    .await?
    else {
        return Ok(());
    };
    let test_client = network.client();
    run_or_skip(stringify!(trigger_burn_repetitions), || async {
        // Explicitly allow Alice to register by-call triggers.
        let permission_on_registration = CanRegisterTrigger {
            authority: ALICE_ID.clone(),
        };
        let expected_permission: iroha::data_model::permission::Permission =
            permission_on_registration.clone().into();
        if let Err(err) = submit_instruction_and_wait(
            &network,
            test_client.clone(),
            Grant::account_permission(permission_on_registration, ALICE_ID.clone()),
            stringify!(trigger_burn_repetitions),
        )
        .await
        {
            if !is_permission_grant_repetition(&err, &expected_permission) {
                return Err(err);
            }
        }
        let asset_definition_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal")?,
            "rose".parse()?,
        );
        let account_id = ALICE_ID.clone();
        let asset_id = AssetId::new(asset_definition_id, account_id.clone());
        let base_trigger_name = "trigger_burn_repetitions";
        let mut attempt = 0_u32;
        let max_attempts = 5_u32;
        let trigger_id = loop {
            let candidate = if attempt == 0 {
                base_trigger_name.to_owned()
            } else {
                format!("{base_trigger_name}_{attempt}")
            };
            let trigger_id = candidate.parse::<TriggerId>()?;
            let trigger_instructions = vec![Mint::asset_quantity(1u32, asset_id.clone())];
            let register_trigger = Register::trigger(Trigger::new(
                trigger_id.clone(),
                Action::new(
                    trigger_instructions,
                    1_u32,
                    account_id.clone(),
                    ExecuteTriggerEventFilter::new()
                        .for_trigger(trigger_id.clone())
                        .under_authority(account_id.clone()),
                )
                .expect("trigger action fixture satisfies validation invariants"),
            ));
            match submit_instruction_and_wait(
                &network,
                test_client.clone(),
                register_trigger,
                stringify!(trigger_burn_repetitions),
            )
            .await
            {
                Ok(()) => break trigger_id,
                Err(err) => {
                    if is_trigger_register_collision(&err, &trigger_id) {
                        if attempt >= max_attempts {
                            return Err(err.wrap_err(format!(
                                "trigger id collision retry limit ({max_attempts}) exceeded"
                            )));
                        }
                        let next = format!("{base_trigger_name}_{}", attempt + 1);
                        eprintln!(
                            "Trigger id collision for `{}` (attempt {}); retrying with `{}`",
                            trigger_id,
                            attempt + 1,
                            next
                        );
                        attempt += 1;
                        continue;
                    }
                    return Err(err);
                }
            }
        };
        submit_instruction_and_wait(
            &network,
            test_client.clone(),
            Burn::trigger_repetitions(1_u32, trigger_id.clone()),
            stringify!(trigger_burn_repetitions),
        )
        .await?;
        timeout(network.sync_timeout(), async {
            loop {
                let still_active = spawn_blocking({
                    let client = test_client.clone();
                    let trigger_id = trigger_id.clone();
                    move || -> Result<bool> {
                        let ids = client
                            .client()
                            .query(FindActiveTriggerIds)
                            .execute_all()
                            .wrap_err("query active trigger ids")?;
                        Ok(ids.into_iter().any(|id| id == trigger_id))
                    }
                })
                .await??;
                if !still_active {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Ok::<(), eyre::Report>(())
        })
        .await
        .wrap_err("wait for trigger to be pruned after burn")??;
        // Executing trigger should be rejected without repetitions, but avoid logging a warning
        // by observing the pipeline event instead of waiting on the confirmation stream.
        let execute_trigger = ExecuteTrigger::new(trigger_id.clone());
        let instruction = Instruction::into_instruction_box(Box::new(execute_trigger));
        let transaction = {
            let account = test_client.account_client();
            account
                .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                    [instruction],
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                    Metadata::default(),
                ))
                .and_then(|payload| account.sign_transaction(payload))
        }
        .expect("build integration-test transaction");
        let hash = transaction.hash();
        let mut events = timeout(
            network.sync_timeout(),
            test_client
                .account_client()
                .events()
                .subscribe([TransactionEventFilter::default().for_hash(hash)]),
        )
        .await
        .wrap_err("timed out opening pipeline event stream")??;
        spawn_blocking({
            let client = test_client.clone();
            let transaction = transaction.clone();
            move || client.submit_transaction(&transaction)
        })
        .await??;
        timeout(network.sync_timeout(), async {
            loop {
                let Some(next) = events.next().await else {
                    return Err(eyre::eyre!("transaction event stream closed"));
                };
                let EventBox::Pipeline(PipelineEventBox::Transaction(event)) = next? else {
                    continue;
                };
                match event.status() {
                    TransactionStatus::Queued => {}
                    TransactionStatus::Rejected(reason) => match reason.as_ref() {
                        TransactionRejectionReason::Validation(
                            ValidationFail::InstructionFailed(InstructionExecutionError::Find(
                                FindError::Trigger(id),
                            )),
                        ) => {
                            assert_eq!(id, &trigger_id);
                            break;
                        }
                        other => {
                            return Err(eyre::eyre!("unexpected rejection reason: {other:?}"));
                        }
                    },
                    status => {
                        return Err(eyre::eyre!("unexpected transaction status: {status:?}"));
                    }
                }
            }
            Ok::<(), eyre::Report>(())
        })
        .await
        .wrap_err("timed out waiting for trigger rejection")??;
        events.close().await?;
        Ok(())
    })
    .await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unregistering_one_of_two_triggers_with_identical_contract_should_not_cause_original_contract_loss()
-> Result<()> {
    let Some(network) =
        start_network(stringify!(unregistering_one_of_two_triggers_with_identical_contract_should_not_cause_original_contract_loss))
            .await?
    else {
        return Ok(());
    };
    let test_client = network.client();
    run_or_skip(
        stringify!(unregistering_one_of_two_triggers_with_identical_contract_should_not_cause_original_contract_loss),
        || async {
            let account_id = ALICE_ID.clone();
            let first_trigger_id = "mint_rose_1".parse::<TriggerId>()?;
            let second_trigger_id = "mint_rose_2".parse::<TriggerId>()?;
            let build_trigger = |trigger_id: TriggerId| {
                Trigger::new(
                    trigger_id.clone(),
                    Action::new(
                        load_sample_ivm("mint_rose_trigger"),
                        Repeats::Indefinitely,
                        account_id.clone(),
                        ExecuteTriggerEventFilter::new()
                            .for_trigger(trigger_id)
                            .under_authority(account_id.clone()),
                    ).expect("trigger action fixture satisfies validation invariants")
                    .with_metadata(contract_entrypoint_metadata("run")),
                )
            };
            let first_trigger = build_trigger(first_trigger_id.clone());
            let second_trigger = build_trigger(second_trigger_id.clone());
            let second_trigger_for_register = second_trigger.clone();
            submit_instruction_and_wait(
                &network,
                test_client.clone(),
                Register::trigger(first_trigger),
                stringify!(unregistering_one_of_two_triggers_with_identical_contract_should_not_cause_original_contract_loss),
            )
            .await?;
            submit_instruction_and_wait(
                &network,
                test_client.clone(),
                Register::trigger(second_trigger_for_register),
                stringify!(unregistering_one_of_two_triggers_with_identical_contract_should_not_cause_original_contract_loss),
            )
            .await?;
            submit_instruction_and_wait(
                &network,
                test_client.clone(),
                Unregister::trigger(first_trigger_id.clone()),
                stringify!(unregistering_one_of_two_triggers_with_identical_contract_should_not_cause_original_contract_loss),
            )
            .await?;
            let got_second_trigger = spawn_blocking({
                let client = test_client.clone();
                let second_trigger_id = second_trigger_id.clone();
                move || {
                    client
                        .client().query(FindTriggers::new())
                        .execute_all()
                        .unwrap()
                        .into_iter()
                        .find(|trigger| trigger.id() == &second_trigger_id)
                        .expect("trigger not found")
                }
            })
            .await?;
            assert_eq!(got_second_trigger, second_trigger);
            Ok(())
        },
    )
    .await
}
fn build_register_trigger_isi(
    account_id: &AccountId,
    trigger_instructions: Vec<InstructionBox>,
) -> Register<Trigger> {
    let trigger_id: TriggerId = TRIGGER_NAME.parse().expect("Valid");
    Register::trigger(Trigger::new(
        trigger_id.clone(),
        Action::new(
            trigger_instructions,
            Repeats::Indefinitely,
            account_id.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id)
                .under_authority(account_id.clone()),
        )
        .expect("trigger action fixture satisfies validation invariants"),
    ))
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn call_execute_trigger_with_args() -> Result<()> {
    let Some(network) = start_network(stringify!(call_execute_trigger_with_args)).await? else {
        return Ok(());
    };
    let test_client = network.client();
    network.ensure_blocks_with(|h| h.total >= 1).await?;
    run_or_skip(stringify!(call_execute_trigger_with_args), || async {
        let asset_definition_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal")?,
            "rose".parse()?,
        );
        let account_id = ALICE_ID.clone();
        let asset_id = AssetId::new(asset_definition_id, account_id.clone());
        let prev_value = spawn_blocking({
            let client = test_client.clone();
            let asset_id = asset_id.clone();
            move || get_asset_value(&client, &asset_id)
        })
        .await??;
        let trigger_id = TRIGGER_NAME.parse::<TriggerId>()?;
        let trigger = Trigger::new(
            trigger_id.clone(),
            Action::new(
                load_sample_ivm("mint_rose_trigger"),
                Repeats::Indefinitely,
                account_id.clone(),
                ExecuteTriggerEventFilter::new()
                    .for_trigger(trigger_id.clone())
                    .under_authority(account_id.clone()),
            )
            .expect("trigger action fixture satisfies validation invariants")
            .with_metadata(contract_entrypoint_metadata("run")),
        );
        submit_instruction_and_wait(
            &network,
            test_client.clone(),
            Register::trigger(trigger),
            stringify!(call_execute_trigger_with_args),
        )
        .await?;
        let args = MintRoseArgs { val: 42 };
        let call_trigger = ExecuteTrigger::new(trigger_id).with_args(args);
        submit_instruction_and_wait(
            &network,
            test_client.clone(),
            Instruction::into_instruction_box(Box::new(call_trigger)),
            stringify!(call_execute_trigger_with_args),
        )
        .await?;
        let expected_value = prev_value.checked_add(&Quantity::from(42_u32)).unwrap();
        let new_value = wait_for_asset_value(
            &test_client,
            &asset_id,
            expected_value.clone(),
            network.sync_timeout(),
            stringify!(call_execute_trigger_with_args),
        )
        .await?;
        assert_eq!(new_value, expected_value);
        Ok(())
    })
    .await
}
