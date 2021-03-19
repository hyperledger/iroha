use iroha::config::Configuration;
use iroha_client::{
    client::{asset, Client},
    config::Configuration as ClientConfiguration,
};
use iroha_data_model::prelude::*;
use std::{thread, time::Duration};
use test_network::Peer as TestPeer;

const CONFIGURATION_PATH: &str = "tests/test_config.json";
const CLIENT_CONFIGURATION_PATH: &str = "tests/test_client_config.json";
const GENESIS_PATH: &str = "tests/genesis.json";

#[test]
fn client_add_asset_quantity_to_existing_asset_should_increase_asset_amount() {
    let mut configuration =
        Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
    configuration.genesis_configuration.genesis_block_path = Some(GENESIS_PATH.to_string());
    let peer = TestPeer::new().expect("Failed to create peer");
    configuration.sumeragi_configuration.trusted_peers.peers =
        std::iter::once(peer.id.clone()).collect();

    let pipeline_time =
        Duration::from_millis(configuration.sumeragi_configuration.pipeline_time_ms());

    // Given
    let _ = peer.start_with_config(configuration);
    thread::sleep(pipeline_time);

    let domain_name = "wonderland";
    let mut client_config = ClientConfiguration::from_path(CLIENT_CONFIGURATION_PATH)
        .expect("Failed to load configuration.");
    client_config.torii_api_url = peer.api_address;
    let mut iroha_client = Client::new(&client_config);

    let register = ('a'..'z')
        .map(|c| c.to_string())
        .map(|name| AssetDefinitionId::new(&name, domain_name))
        .map(AssetDefinition::new)
        .map(Box::new)
        .map(IdentifiableBox::AssetDefinition)
        .map(RegisterBox::new)
        .map(Instruction::Register)
        .collect();
    let _ = iroha_client
        .submit_all(register)
        .expect("Failed to prepare state.");
    thread::sleep(pipeline_time);
    //When
    let QueryResult(assets) = iroha_client
        .request_with_pagination(
            &asset::all_definitions(),
            Pagination {
                start: Some(5),
                limit: Some(5),
            },
        )
        .expect("Failed to get assets");
    if let Value::Vec(vec) = assets {
        assert_eq!(vec.len(), 5)
    } else {
        panic!("Expected vector of assets")
    }
}
