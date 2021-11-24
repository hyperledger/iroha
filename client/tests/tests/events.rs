#![allow(clippy::restriction)]

use std::{
    sync::{Arc, RwLock},
    thread,
};

use eyre::Result;
use iroha_client::client::Client;
use iroha_core::config::Configuration;
use iroha_data_model::prelude::*;
use test_network::*;

const PEER_COUNT: usize = 7;

#[test]
fn transaction_event_should_be_sent_to_all_peers_from_all_peers() -> Result<()> {
    let asset_definition_id = AssetDefinitionId::new("xor", "wonderland");
    let create_asset = RegisterBox::new(IdentifiableBox::AssetDefinition(
        AssetDefinition::new_quantity(asset_definition_id).into(),
    ));
    test_with_instruction_and_status(create_asset, true)?;
    let fail = FailBox::new("Failing transaction to test Rejected event.");
    test_with_instruction_and_status(fail, false)
}

#[allow(clippy::needless_range_loop)]
fn test_with_instruction_and_status(
    instruction: impl Into<Instruction>,
    should_be_committed: bool,
) -> Result<()> {
    let instruction: Instruction = instruction.into();
    for submitting_peer in 0..PEER_COUNT {
        let (_rt, network, _) =
            <Network>::start_test_with_runtime(PEER_COUNT.try_into().unwrap(), 1);
        let pipeline_time = Configuration::pipeline_time();

        // Given
        thread::sleep(pipeline_time * 4);

        let committed_event_received = Arc::new(RwLock::new([false; PEER_COUNT]));
        let validating_event_received = Arc::new(RwLock::new([false; PEER_COUNT]));
        let rejected_event_received = Arc::new(RwLock::new([false; PEER_COUNT]));
        let peers: Vec<_> = network.peers().collect();
        let mut submitter_client = Client::test(&peers[submitting_peer].api_address);
        let transaction = submitter_client
            .build_transaction(vec![instruction.clone()], UnlimitedMetadata::new())?;
        for receiving_peer in 0..PEER_COUNT {
            let committed_event_received_clone = committed_event_received.clone();
            let validating_event_received_clone = validating_event_received.clone();
            let rejected_event_received_clone = rejected_event_received.clone();
            let listener_client = Client::test(&peers[receiving_peer].api_address);
            let hash = transaction.hash();
            let _handle = thread::spawn(move || {
                listener_client.for_each_event(
                    EventFilter::Pipeline(PipelineEventFilter::by_entity(
                        PipelineEntityType::Transaction,
                    )),
                    |event| {
                        if let Ok(Event::Pipeline(event)) = event {
                            if event.entity_type == PipelineEntityType::Transaction
                                && event.hash == *hash
                            {
                                match event.status {
                                    PipelineStatus::Committed => {
                                        committed_event_received_clone
                                            .write()
                                            .expect("Failed to acquire lock.")[receiving_peer] =
                                            true;
                                    }
                                    PipelineStatus::Validating => {
                                        validating_event_received_clone
                                            .write()
                                            .expect("Failed to acquire lock.")[receiving_peer] =
                                            true;
                                    }
                                    PipelineStatus::Rejected(_) => {
                                        rejected_event_received_clone
                                            .write()
                                            .expect("Failed to acquire lock.")[receiving_peer] =
                                            true;
                                    }
                                }
                            }
                        }
                    },
                );
            });
        }
        thread::sleep(pipeline_time * 2);
        //When
        submitter_client.submit_transaction(transaction)?;
        thread::sleep(pipeline_time * 2);
        //Then
        let committed = committed_event_received.read().unwrap();
        let validating = validating_event_received.read().unwrap();
        let rejected = rejected_event_received.read().unwrap();
        for receiving_peer in 0..PEER_COUNT {
            assert!(validating[receiving_peer]);
            if should_be_committed {
                assert!(committed[receiving_peer]);
                assert!(!rejected[receiving_peer]);
            } else {
                assert!(!committed[receiving_peer]);
                assert!(rejected[receiving_peer]);
            }
        }
    }
    Ok(())
}
