use async_std::task;
use iroha::{config::Configuration, prelude::*};
use iroha_client::{client::Client, config::Configuration as ClientConfiguration};
use iroha_data_model::prelude::*;
use std::{
    sync::{Arc, RwLock},
    thread,
    time::Duration,
};
use tempfile::TempDir;

const CONFIGURATION_PATH: &str = "tests/test_config.json";
const CLIENT_CONFIGURATION_PATH: &str = "tests/test_client_config.json";

#[test]
fn transaction_event_should_be_sent_after_it_is_committed() {
    // Given
    thread::spawn(create_and_start_iroha);
    thread::sleep(std::time::Duration::from_millis(300));
    let configuration =
        Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
    let domain_name = "global";
    let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
    let create_asset = RegisterBox::new(IdentifiableBox::AssetDefinition(
        AssetDefinition::new(asset_definition_id).into(),
    ));
    let mut iroha_client = Client::new(
        &ClientConfiguration::from_path(CLIENT_CONFIGURATION_PATH)
            .expect("Failed to load configuration."),
    );
    let committed_event_received = Arc::new(RwLock::new(false));
    let committed_event_received_clone = committed_event_received.clone();
    let mut client_clone = iroha_client.clone();
    thread::spawn(move || {
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
    thread::sleep(Duration::from_millis(1000));
    //When
    iroha_client
        .submit(create_asset.into())
        .expect("Failed to prepare state.");
    thread::sleep(Duration::from_millis(
        &configuration.sumeragi_configuration.pipeline_time_ms() * 2,
    ));
    //Then
    assert!(*committed_event_received
        .read()
        .expect("Failed to acquire lock."));
}

fn create_and_start_iroha() {
    let temp_dir = TempDir::new().expect("Failed to create TempDir.");
    let mut configuration =
        Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
    configuration
        .kura_configuration
        .kura_block_store_path(temp_dir.path());
    let iroha = Iroha::new(configuration, AllowAll.into());
    task::block_on(iroha.start()).expect("Failed to start Iroha.");
    //Prevents temp_dir from clean up untill the end of the tests.
    #[allow(clippy::empty_loop)]
    loop {}
}
