#![allow(clippy::restriction)]

use std::{sync::mpsc, thread, time::Duration};

use eyre::{eyre, Result, WrapErr};
use iroha_client::client::{self, Client};
use iroha_data_model::prelude::*;
use test_network::{Peer as TestPeer, *};

const TRIGGER_NAME: &str = "mint_rose";

#[test]
fn call_execute_trigger() -> Result<()> {
    let (_rt, _peer, mut test_client) = <TestPeer>::start_test_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id = "alice@wonderland".parse()?;
    let asset_id = AssetId::new(asset_definition_id, account_id);
    let prev_value = get_asset_value(&mut test_client, asset_id.clone())?;

    let instruction = MintBox::new(1_u32, asset_id.clone());
    let register_trigger = build_register_trigger_isi(asset_id.clone(), vec![instruction.into()]);
    test_client.submit(register_trigger)?;

    let trigger_id = TriggerId::new(TRIGGER_NAME.parse()?);
    let call_trigger = ExecuteTriggerBox::new(trigger_id);
    test_client.submit_blocking(call_trigger)?;

    let new_value = get_asset_value(&mut test_client, asset_id)?;
    assert_eq!(new_value, prev_value + 1);

    Ok(())
}

#[test]
fn execute_trigger_should_produce_event() -> Result<()> {
    let (_rt, _peer, mut test_client) = <TestPeer>::start_test_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id: AccountId = "alice@wonderland".parse()?;
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());

    let instruction = MintBox::new(1_u32, asset_id.clone());
    let register_trigger = build_register_trigger_isi(asset_id, vec![instruction.into()]);
    test_client.submit(register_trigger)?;

    let trigger_id = TriggerId::new(TRIGGER_NAME.parse()?);
    let call_trigger = ExecuteTriggerBox::new(trigger_id.clone());

    let mut thread_client = test_client.clone();
    let (sender, receiver) = mpsc::channel();
    let _handle = thread::spawn(move || -> Result<()> {
        let mut event_it = thread_client
            .listen_for_events(ExecuteTriggerEventFilter::new(trigger_id, account_id).into())?;
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
fn infinite_recursion_should_produce_one_call_per_block() -> Result<()> {
    let (_rt, _peer, mut test_client) = <TestPeer>::start_test_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id = "alice@wonderland".parse()?;
    let asset_id = AssetId::new(asset_definition_id, account_id);
    let trigger_id = TriggerId::new(TRIGGER_NAME.parse()?);
    let call_trigger = ExecuteTriggerBox::new(trigger_id);
    let prev_value = get_asset_value(&mut test_client, asset_id.clone())?;

    let instructions = vec![
        MintBox::new(1_u32, asset_id.clone()).into(),
        call_trigger.clone().into(),
    ];
    let register_trigger = build_register_trigger_isi(asset_id.clone(), instructions);
    test_client.submit(register_trigger)?;

    test_client.submit_blocking(call_trigger)?;

    let new_value = get_asset_value(&mut test_client, asset_id)?;
    assert_eq!(new_value, prev_value + 1);

    Ok(())
}

fn get_asset_value(client: &mut Client, asset_id: AssetId) -> Result<u32> {
    let asset = client.request(client::asset::by_id(asset_id))?;
    Ok(*TryAsRef::<u32>::try_as_ref(asset.value())?)
}

fn build_register_trigger_isi(
    asset_id: AssetId,
    trigger_instructions: Vec<Instruction>,
) -> RegisterBox {
    let trigger_id: TriggerId = TRIGGER_NAME.parse().expect("Valid");

    RegisterBox::new(Trigger::new(
        trigger_id.clone(),
        Action::new(
            Executable::from(trigger_instructions),
            Repeats::Indefinitely,
            asset_id.account_id.clone(),
            EventFilter::ExecuteTrigger(ExecuteTriggerEventFilter::new(
                trigger_id,
                asset_id.account_id,
            )),
        ),
    ))
}
