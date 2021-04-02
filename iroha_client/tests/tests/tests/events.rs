use std::{
    sync::{Arc, RwLock},
    thread,
    time::Duration,
};

use iroha::config::Configuration;
use iroha_client::{client::Client, config::Configuration as ClientConfiguration};
use iroha_data_model::prelude::*;
use test_network::Peer as TestPeer;

const CONFIGURATION_PATH: &str = "tests/test_config.json";
const CLIENT_CONFIGURATION_PATH: &str = "tests/test_client_config.json";
const GENESIS_PATH: &str = "tests/genesis.json";

#[test]
fn transaction_event_should_be_sent_after_it_is_committed() {
    let peer = TestPeer::new().expect("Failed to create peer");

    let mut configuration =
        Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
    configuration.genesis_configuration.genesis_block_path = Some(GENESIS_PATH.to_string());
    configuration.sumeragi_configuration.trusted_peers.peers =
        std::iter::once(peer.id.clone()).collect();
    let pipeline_time =
        Duration::from_millis(configuration.sumeragi_configuration.pipeline_time_ms());

    // Given
    drop(peer.start_with_config(configuration));
    thread::sleep(pipeline_time);

    let domain_name = "wonderland";
    let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
    let create_asset = RegisterBox::new(IdentifiableBox::AssetDefinition(
        AssetDefinition::new_quantity(asset_definition_id).into(),
    ));
    let mut client_config = ClientConfiguration::from_path(CLIENT_CONFIGURATION_PATH)
        .expect("Failed to load configuration.");
    client_config.torii_api_url = peer.api_address;
    let mut iroha_client = Client::new(&client_config);
    let committed_event_received = Arc::new(RwLock::new(false));
    let committed_event_received_clone = committed_event_received.clone();
    let mut client_clone = iroha_client.clone();
    let _ = thread::spawn(move || {
        for event in client_clone
            .listen_for_events(EventFilter::Pipeline(PipelineEventFilter::by_entity(
                PipelineEntityType::Transaction,
            )))
            .expect("Failed to create event iterator.")
        {
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
        }
    });
    thread::sleep(pipeline_time * 2);
    //When
    let _ = iroha_client
        .submit(create_asset.into())
        .expect("Failed to prepare state.");
    thread::sleep(pipeline_time * 2);
    //Then
    assert!(*committed_event_received
        .read()
        .expect("Failed to acquire lock."));
}
