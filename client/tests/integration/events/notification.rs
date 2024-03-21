use std::{str::FromStr as _, sync::mpsc, thread, time::Duration};

use eyre::{eyre, Result, WrapErr};
use iroha_client::data_model::prelude::*;
use test_network::*;
use test_samples::ALICE_ID;

#[test]
fn trigger_completion_success_should_produce_event() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(11_050).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id = ALICE_ID.clone();
    let asset_id = AssetId::new(asset_definition_id, account_id);
    let trigger_id = TriggerId::from_str("mint_rose")?;

    let instruction = Mint::asset_numeric(1u32, asset_id.clone());
    let register_trigger = Register::trigger(Trigger::new(
        trigger_id.clone(),
        Action::new(
            vec![InstructionBox::from(instruction)],
            Repeats::Indefinitely,
            asset_id.account_id.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id.clone())
                .under_authority(asset_id.account_id),
        ),
    ));
    test_client.submit_blocking(register_trigger)?;

    let call_trigger = ExecuteTrigger::new(trigger_id.clone());

    let thread_client = test_client.clone();
    let (sender, receiver) = mpsc::channel();
    let _handle = thread::spawn(move || -> Result<()> {
        let mut event_it = thread_client.listen_for_events([TriggerCompletedEventFilter::new()
            .for_trigger(trigger_id)
            .for_outcome(TriggerCompletedOutcomeType::Success)])?;
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

    let account_id = ALICE_ID.clone();
    let trigger_id = TriggerId::from_str("fail_box")?;

    let instruction = Fail::new("Fail box".to_owned());
    let register_trigger = Register::trigger(Trigger::new(
        trigger_id.clone(),
        Action::new(
            vec![InstructionBox::from(instruction)],
            Repeats::Indefinitely,
            account_id.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id.clone())
                .under_authority(account_id),
        ),
    ));
    test_client.submit_blocking(register_trigger)?;

    let call_trigger = ExecuteTrigger::new(trigger_id.clone());

    let thread_client = test_client.clone();
    let (sender, receiver) = mpsc::channel();
    let _handle = thread::spawn(move || -> Result<()> {
        let mut event_it = thread_client.listen_for_events([TriggerCompletedEventFilter::new()
            .for_trigger(trigger_id)
            .for_outcome(TriggerCompletedOutcomeType::Failure)])?;
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
