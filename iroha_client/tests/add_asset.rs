use iroha::config::Configuration;
use iroha_client::{
    client::{self, Client},
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
    drop(peer.start_with_config(configuration));
    thread::sleep(pipeline_time);

    let domain_name = "wonderland";
    let account_name = "alice";
    let account_id = AccountId::new(account_name, domain_name);
    let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
    let create_asset = RegisterBox::new(IdentifiableBox::AssetDefinition(
        AssetDefinition::new_quantity(asset_definition_id.clone()).into(),
    ));
    let mut client_config = ClientConfiguration::from_path(CLIENT_CONFIGURATION_PATH)
        .expect("Failed to load configuration.");
    client_config.torii_api_url = peer.api_address;
    let mut iroha_client = Client::new(&client_config);
    let _ = iroha_client
        .submit(create_asset.into())
        .expect("Failed to prepare state.");
    thread::sleep(pipeline_time * 2);
    //When
    let quantity: u32 = 200;
    let mint_asset = MintBox::new(
        Value::U32(quantity),
        IdBox::AssetId(AssetId::new(
            asset_definition_id.clone(),
            account_id.clone(),
        )),
    );
    let _ = iroha_client
        .submit(mint_asset.into())
        .expect("Failed to create asset.");
    thread::sleep(pipeline_time * 2);
    //Then
    let request = client::asset::by_account_id(account_id);
    let query_result = iroha_client
        .request(&request)
        .expect("Failed to execute request.");
    if let QueryResult(Value::Vec(assets)) = query_result {
        let asset = assets
            .iter()
            .find_map(|asset| {
                if let Value::Identifiable(IdentifiableBox::Asset(ref asset)) = asset {
                    if asset.id.definition_id == asset_definition_id {
                        return Some(asset);
                    }
                }
                None
            })
            .expect("Asset should exist.");

        assert_eq!(AssetValue::Quantity(quantity), asset.value);
    } else {
        panic!("Wrong Query Result Type.");
    }
}
