#![allow(clippy::restriction)]

use std::{
    sync::{Arc, RwLock},
    thread,
};

use eyre::Result;
use iroha_core::config::Configuration;
use iroha_data_model::prelude::*;
use test_network::{Peer as TestPeer, *};

#[test]
fn transaction_event_should_be_sent_after_it_is_committed() -> Result<()> {
    let (_rt, _peer, mut iroha_client) = <TestPeer>::start_test_with_runtime();
    let pipeline_time = Configuration::pipeline_time();

    // Given
    thread::sleep(pipeline_time);

    let asset_definition_id = AssetDefinitionId::new("xor", "wonderland");
    let create_asset = RegisterBox::new(IdentifiableBox::AssetDefinition(
        AssetDefinition::new_quantity(asset_definition_id, true).into(),
    ));
    let committed_event_received = Arc::new(RwLock::new(false));
    let committed_event_received_clone = committed_event_received.clone();
    let client_clone = iroha_client.clone();
    let _handle = thread::spawn(move || {
        client_clone.loop_on_events(
            EventFilter::Pipeline(PipelineEventFilter::by_entity(
                PipelineEntityType::Transaction,
            )),
            |event| {
                if let Ok(Event::Pipeline(event)) = event {
                    //TODO: check transaction hash
                    if event.entity_type == PipelineEntityType::Transaction
                        && event.status == PipelineStatus::Committed
                    {
                        *committed_event_received_clone
                            .write()
                            .expect("Failed to acquire lock.") = true;
                    }
                }
            },
        );
    });
    thread::sleep(pipeline_time * 2);
    //When
    iroha_client.submit(create_asset)?;
    thread::sleep(pipeline_time * 2);
    //Then
    assert!(*committed_event_received.read().unwrap());
    Ok(())
}
