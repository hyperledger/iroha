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

    let asset_definition_id = AssetDefinitionId::new("rose", "wonderland")?;
    let account_id = AccountId::new("alice", "wonderland")?;
    let asset_id = AssetId::new(asset_definition_id, account_id);
    let prev_value = get_asset_value(&mut test_client, asset_id.clone())?;

    let register_trigger = build_register_trigger_isi(TRIGGER_NAME, asset_id.clone())?;
    test_client.submit(register_trigger)?;

    let trigger_id = TriggerId::new(TRIGGER_NAME)?;
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

    let asset_definition_id = AssetDefinitionId::new("rose", "wonderland")?;
    let account_id = AccountId::new("alice", "wonderland")?;
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());

    let register_trigger = build_register_trigger_isi(TRIGGER_NAME, asset_id)?;
    test_client.submit(register_trigger)?;

    let trigger_id = TriggerId::new(TRIGGER_NAME)?;
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

fn get_asset_value(client: &mut Client, asset_id: AssetId) -> Result<u32> {
    let asset = client.request(client::asset::by_id(asset_id))?;
    Ok(*TryAsRef::<u32>::try_as_ref(&asset.value)?)
}

fn build_register_trigger_isi(name: &str, asset_id: AssetId) -> Result<RegisterBox> {
    let id = TriggerId::new(name)?;
    let instruction = MintBox::new(1_u32, asset_id.clone());
    Ok(RegisterBox::new(IdentifiableBox::from(Trigger::new(
        name,
        Action::new(
            Executable::from(vec![instruction.into()]),
            Repeats::Indefinitely,
            asset_id.account_id.clone(),
            EventFilter::ExecuteTrigger(ExecuteTriggerEventFilter::new(id, asset_id.account_id)),
        ),
    )?)))
}
