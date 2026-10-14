//! Tests for notifications emitted after trigger execution.
use eyre::Result;
use futures_util::StreamExt;
use integration_tests::sandbox;
use iroha::data_model::{
    ValidationFail, events::pipeline::TransactionEventFilter, prelude::*, query::error::FindError,
};
use iroha_data_model::isi::error::{InstructionExecutionError, InvalidParameterError};
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_test_network::*;
use iroha_test_samples::ALICE_ID;
use std::time::Duration;
use tokio::{
    task::spawn_blocking,
    time::{sleep, timeout},
};
async fn trigger_completion_success_should_produce_event_scenario(network: &Network) -> Result<()> {
    let asset_definition_id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal")?,
        "rose".parse()?,
    );
    let account_id = ALICE_ID.clone();
    let asset_id = AssetId::new(asset_definition_id, account_id);
    let trigger_id = "mint_rose_event".parse::<TriggerId>()?;
    let instruction = Mint::asset_quantity(1u32, asset_id.clone());
    let register_trigger = Register::trigger(Trigger::new(
        trigger_id.clone(),
        Action::new(
            vec![instruction],
            Repeats::Indefinitely,
            asset_id.account().clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id.clone())
                .under_authority(asset_id.account().clone()),
        )
        .expect("trigger action fixture satisfies validation invariants"),
    ));
    let client = network.client();
    let register_tx = {
        let account = client.account_client();
        account
            .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                [register_trigger],
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                <_>::default(),
            ))
            .and_then(|payload| account.sign_transaction(payload))
    }
    .expect("build integration-test transaction");
    spawn_blocking(move || client.submit_transaction_and_wait(&register_tx)).await??;
    network.ensure_blocks(2).await?;
    let event_timeout = network.sync_timeout();
    let ready_client = network.client();
    let ready_tx = {
        let account = ready_client.account_client();
        account
            .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                [Log::new(
                    Level::INFO,
                    "trigger_completion_event_stream_ready".to_string(),
                )],
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                Metadata::default(),
            ))
            .and_then(|payload| account.sign_transaction(payload))
    }
    .expect("build integration-test transaction");
    let ready_hash = ready_tx.hash();
    let mut events = tokio::time::timeout(
        event_timeout,
        network.client().account_client().events().subscribe(vec![
            EventFilterBox::from(
                TriggerCompletedEventFilter::new()
                    .for_trigger(trigger_id.clone())
                    .for_outcome(TriggerCompletedOutcomeType::Success),
            ),
            EventFilterBox::from(TransactionEventFilter::default().for_hash(ready_hash)),
        ]),
    )
    .await
    .map_err(|_| {
        eyre::eyre!(
            "trigger_completion_success_should_produce_event: timed out opening trigger event stream"
        )
    })??;
    let ready_client = network.client();
    spawn_blocking(move || ready_client.submit_transaction(&ready_tx)).await??;
    timeout(event_timeout, async {
        loop {
            match events.next().await {
                Some(Ok(EventBox::Pipeline(PipelineEventBox::Transaction(event))))
                    if event.hash() == &ready_hash =>
                {
                    match event.status() {
                        TransactionStatus::Approved => break Ok(()),
                        TransactionStatus::Rejected(reason) => {
                            break Err(eyre::eyre!(
                                "handshake transaction rejected: {reason:?}"
                            ));
                        }
                        _ => {}
                    }
                }
                Some(Ok(_)) => {}
                Some(Err(err)) => break Err(eyre::Report::from(err)),
                None => break Err(eyre::eyre!("event stream ended unexpectedly")),
            }
        }
    })
    .await
    .map_err(|_| {
        eyre::eyre!("trigger_completion_success_should_produce_event: timed out waiting for event stream handshake")
    })??;
    let call_trigger = ExecuteTrigger::new(trigger_id.clone());
    let client = network.client();
    let trigger_tx = {
        let account = client.account_client();
        account
            .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                [Instruction::into_instruction_box(Box::new(call_trigger))],
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                Metadata::default(),
            ))
            .and_then(|payload| account.sign_transaction(payload))
    }
    .expect("build integration-test transaction");
    let submit_trigger = async {
        spawn_blocking(move || client.submit_transaction_and_wait(&trigger_tx)).await??;
        Ok::<(), eyre::Report>(())
    };
    let wait_event = async {
        timeout(event_timeout, async {
            loop {
                match events.next().await {
                    Some(Ok(EventBox::TriggerCompleted(event)))
                        if event.trigger_id() == &trigger_id =>
                    {
                        break Ok(());
                    }
                    Some(Ok(_)) => {}
                    Some(Err(err)) => break Err(eyre::Report::from(err)),
                    None => break Err(eyre::eyre!("event stream ended unexpectedly")),
                }
            }
        })
        .await
        .map_err(|err| {
            sandbox::sandbox_reason(&eyre::eyre!(err.to_string())).map_or_else(
                || eyre::eyre!(err),
                |reason| {
                    eyre::eyre!(
                        "sandboxed network restriction detected during {}: {reason}",
                        stringify!(trigger_completion_success_should_produce_event)
                    )
                },
            )
        })?
    };
    let event_result = tokio::try_join!(submit_trigger, wait_event);
    events.close().await?;
    event_result?;
    Ok(())
}
#[allow(clippy::too_many_lines)]
async fn trigger_completion_failure_reports_error_scenario(network: &Network) -> Result<()> {
    let account_id = ALICE_ID.clone();
    let trigger_id = "fail_box_event".parse::<TriggerId>()?;
    let fail_isi = Unregister::domain(DomainId::try_new("dummy", "universal").unwrap());
    let register_trigger = Register::trigger(Trigger::new(
        trigger_id.clone(),
        Action::new(
            vec![fail_isi],
            Repeats::Indefinitely,
            account_id.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id.clone())
                .under_authority(account_id),
        )
        .expect("trigger action fixture satisfies validation invariants"),
    ));
    let client = network.client();
    spawn_blocking(move || {
        client.submit(
            register_trigger,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
    })
    .await??;
    network.ensure_blocks(2).await?;
    let retry_delay = Duration::from_secs(2);
    let mut attempts = 0;
    let err = loop {
        let call_trigger = ExecuteTrigger::new(trigger_id.clone());
        let client = network.client();
        let err = spawn_blocking(move || {
            client.submit(
                call_trigger,
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
        })
        .await?
        .expect_err("should immediately result in error");
        let is_expected = err
            .chain()
            .any(|cause| cause.downcast_ref::<FindError>().is_some())
            || err
                .chain()
                .any(|cause| cause.downcast_ref::<InstructionExecutionError>().is_some())
            || err.chain().any(|cause| {
                matches!(
                    cause.downcast_ref::<ValidationFail>(),
                    Some(ValidationFail::NotPermitted(_))
                )
            })
            || err.chain().any(|cause| {
                matches!(
                    cause.downcast_ref::<InvalidParameterError>(),
                    Some(InvalidParameterError::SmartContract(_))
                )
            });
        if is_expected {
            break err;
        }
        let err_msg = err.to_string();
        let is_transient = err
            .chain()
            .any(|cause| cause.downcast_ref::<std::io::Error>().is_some())
            || err_msg.contains("Failed to send transaction")
            || err_msg.contains("Failed to establish event listener connection")
            || err_msg.contains("transaction.status_timeout_ms")
            || err_msg.contains("Connection refused")
            || err_msg.contains("connection refused")
            || err_msg.contains("timed out")
            || err_msg.contains("timeout");
        if attempts < 2 && is_transient {
            attempts += 1;
            sleep(retry_delay).await;
            continue;
        }
        return Err(err);
    };
    if let Some(FindError::Domain(_)) = err
        .chain()
        .find_map(|cause| cause.downcast_ref::<FindError>())
    {
        // ok
    } else if let Some(instr_err) = err
        .chain()
        .find_map(|cause| cause.downcast_ref::<InstructionExecutionError>())
    {
        match instr_err {
            InstructionExecutionError::Find(FindError::Domain(_)) => {}
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                msg,
            )) => {
                assert!(
                    msg.contains("unregister domain"),
                    "unexpected SmartContract message: {msg}"
                );
            }
            _ => {
                return Err(eyre::eyre!("unexpected instruction error: {instr_err:?}"));
            }
        }
    } else if let Some(ValidationFail::NotPermitted(msg)) = err
        .chain()
        .find_map(|cause| cause.downcast_ref::<ValidationFail>())
    {
        assert!(
            !msg.trim().is_empty(),
            "NotPermitted message should not be empty"
        );
    } else if let Some(InvalidParameterError::SmartContract(msg)) = err
        .chain()
        .find_map(|cause| cause.downcast_ref::<InvalidParameterError>())
    {
        assert!(
            msg.contains("unregister domain"),
            "unexpected SmartContract message: {msg}"
        );
    } else {
        return Err(err);
    }
    Ok(())
}
#[tokio::test]
async fn trigger_completion_event_scenarios() -> Result<()> {
    let Some(network) = sandbox::start_network_async_or_skip(
        NetworkBuilder::new().with_min_peers(4),
        stringify!(trigger_completion_event_scenarios),
    )
    .await?
    else {
        return Ok(());
    };
    trigger_completion_success_should_produce_event_scenario(&network).await?;
    trigger_completion_failure_reports_error_scenario(&network).await?;
    Ok(())
}
