use std::{str::FromStr as _, sync::mpsc, thread, time::Duration};

use eyre::{eyre, Result, WrapErr};
use iroha_client::data_model::prelude::*;
use test_network::*;

#[test]
fn trigger_completion_success_should_produce_event() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(11_050).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id: AccountId = "alice@wonderland".parse()?;
    let asset_id = AssetId::new(asset_definition_id, account_id);
    let trigger_id = TriggerId::from_str("mint_rose")?;

    let instruction = MintExpr::new(1_u32, asset_id.clone());
    let register_trigger = RegisterExpr::new(Trigger::new(
        trigger_id.clone(),
        Action::new(
            vec![InstructionExpr::from(instruction)],
            Repeats::Indefinitely,
            asset_id.account_id.clone(),
            TriggeringFilterBox::ExecuteTrigger(ExecuteTriggerEventFilter::new(
                trigger_id.clone(),
                asset_id.account_id,
            )),
        ),
    ));
    test_client.submit_blocking(register_trigger)?;

    let call_trigger = ExecuteTriggerExpr::new(trigger_id.clone());

    let thread_client = test_client.clone();
    let (sender, receiver) = mpsc::channel();
    let _handle = thread::spawn(move || -> Result<()> {
        let mut event_it = thread_client.listen_for_events(
            NotificationEventFilter::TriggerCompleted(TriggerCompletedEventFilter::new(
                Some(trigger_id),
                Some(TriggerCompletedOutcomeType::Success),
            ))
            .into(),
        )?;
        if event_it.next().is_some() {
            sender.send(())?;
            return Ok(());
        }
        Err(eyre!("No events emitted"))
    });

    test_client.submit(call_trigger)?;

    receiver
        .recv_timeout(Duration::from_secs(60))
        .wrap_err("Failed to receive event message")
}

#[test]
fn trigger_completion_failure_should_produce_event() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(11_055).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let account_id: AccountId = "alice@wonderland".parse()?;
    let trigger_id = TriggerId::from_str("fail_box")?;

    let instruction = Fail::new("Fail box");
    let register_trigger = RegisterExpr::new(Trigger::new(
        trigger_id.clone(),
        Action::new(
            vec![InstructionExpr::from(instruction)],
            Repeats::Indefinitely,
            account_id.clone(),
            TriggeringFilterBox::ExecuteTrigger(ExecuteTriggerEventFilter::new(
                trigger_id.clone(),
                account_id,
            )),
        ),
    ));
    test_client.submit_blocking(register_trigger)?;

    let call_trigger = ExecuteTriggerExpr::new(trigger_id.clone());

    let thread_client = test_client.clone();
    let (sender, receiver) = mpsc::channel();
    let _handle = thread::spawn(move || -> Result<()> {
        let mut event_it = thread_client.listen_for_events(
            NotificationEventFilter::TriggerCompleted(TriggerCompletedEventFilter::new(
                Some(trigger_id),
                Some(TriggerCompletedOutcomeType::Failure),
            ))
            .into(),
        )?;
        if event_it.next().is_some() {
            sender.send(())?;
            return Ok(());
        }
        Err(eyre!("No events emitted"))
    });

    test_client.submit(call_trigger)?;

    receiver
        .recv_timeout(Duration::from_secs(60))
        .wrap_err("Failed to receive event message")
}
