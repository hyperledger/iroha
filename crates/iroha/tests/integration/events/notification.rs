use std::time::Duration;

use eyre::Result;
use futures_util::StreamExt;
use iroha::data_model::prelude::*;
use iroha_test_network::*;
use iroha_test_samples::ALICE_ID;
use tokio::{task::spawn_blocking, time::timeout};

#[tokio::test]
async fn trigger_completion_success_should_produce_event() -> Result<()> {
    let network = NetworkBuilder::new().start().await?;

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id = ALICE_ID.clone();
    let asset_id = AssetId::new(asset_definition_id, account_id);
    let trigger_id = "mint_rose".parse::<TriggerId>()?;

    let instruction = Mint::asset_numeric(1u32, asset_id.clone());
    let register_trigger = Register::trigger(Trigger::new(
        trigger_id.clone(),
        Action::new(
            vec![instruction],
            Repeats::Indefinitely,
            asset_id.account().clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id.clone())
                .under_authority(asset_id.account().clone()),
        ),
    ));
    let client = network.client();
    spawn_blocking(move || client.submit_blocking(register_trigger)).await??;

    let mut events = network
        .client()
        .listen_for_events_async([TriggerCompletedEventFilter::new()
            .for_trigger(trigger_id.clone())
            .for_outcome(TriggerCompletedOutcomeType::Success)])
        .await?;

    let call_trigger = ExecuteTrigger::new(trigger_id);
    let client = network.client();
    spawn_blocking(move || client.submit_blocking(call_trigger)).await??;

    let _ = timeout(Duration::from_secs(5), events.next()).await?;

    Ok(())
}

#[tokio::test]
async fn trigger_completion_failure_should_produce_event() -> Result<()> {
    let network = NetworkBuilder::new().start().await?;

    let account_id = ALICE_ID.clone();
    let trigger_id = "fail_box".parse::<TriggerId>()?;

    let fail_isi = Unregister::domain("dummy".parse().unwrap());
    let register_trigger = Register::trigger(Trigger::new(
        trigger_id.clone(),
        Action::new(
            vec![fail_isi],
            Repeats::Indefinitely,
            account_id.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id.clone())
                .under_authority(account_id),
        ),
    ));
    let client = network.client();
    spawn_blocking(move || client.submit_blocking(register_trigger)).await??;

    let mut events = network
        .client()
        .listen_for_events_async([TriggerCompletedEventFilter::new()
            .for_trigger(trigger_id.clone())
            .for_outcome(TriggerCompletedOutcomeType::Failure)])
        .await?;

    let call_trigger = ExecuteTrigger::new(trigger_id);
    let client = network.client();
    spawn_blocking(move || client.submit_blocking(call_trigger)).await??;

    let _ = timeout(Duration::from_secs(5), events.next()).await?;

    Ok(())
}
