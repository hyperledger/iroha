use async_std::task;
use iroha::{config::Configuration, prelude::*};
use iroha_client::{
    client::{self, Client},
    config::Configuration as ClientConfiguration,
};
use iroha_data_model::prelude::*;
use std::{path::Path, thread, time::Duration};
use tempfile::TempDir;

const CONFIGURATION_PATH: &str = "tests/test_config.json";
const CLIENT_CONFIGURATION_PATH: &str = "tests/test_client_config.json";

#[test]
fn restarted_peer_should_have_the_same_asset_amount() {
    // Given
    let temp_dir = TempDir::new().expect("Failed to create TempDir.");
    let path = temp_dir.path().to_owned();
    let peer_handle = thread::spawn(move || create_and_start_iroha(path.as_ref()));
    thread::sleep(std::time::Duration::from_millis(300));
    let configuration =
        Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
    let domain_name = "global";
    let account_name = "root";
    let account_id = AccountId::new(account_name, domain_name);
    let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
    let create_asset = RegisterBox::new(IdentifiableBox::AssetDefinition(
        AssetDefinition::new(asset_definition_id.clone()).into(),
    ));
    let mut iroha_client = Client::new(
        &ClientConfiguration::from_path(CLIENT_CONFIGURATION_PATH)
            .expect("Failed to load configuration."),
    );
    iroha_client
        .submit(create_asset.into())
        .expect("Failed to prepare state.");
    thread::sleep(Duration::from_millis(
        &configuration.sumeragi_configuration.pipeline_time_ms() * 2,
    ));
    //When
    let quantity: u32 = 200;
    let mint_asset = MintBox::new(
        Value::U32(quantity),
        IdBox::AssetId(AssetId::new(asset_definition_id, account_id.clone())),
    );
    iroha_client
        .submit(mint_asset.into())
        .expect("Failed to create asset.");
    thread::sleep(Duration::from_millis(
        &configuration.sumeragi_configuration.pipeline_time_ms() * 2,
    ));
    //Then
    let request = client::asset::by_account_id(account_id.clone());
    let query_result = iroha_client
        .request(&request)
        .expect("Failed to execute request.");
    if let QueryResult(Value::Vec(assets)) = query_result {
        assert!(!assets.is_empty());
        if let Value::Identifiable(IdentifiableBox::Asset(asset)) =
            assets.first().expect("Asset should exist.")
        {
            assert_eq!(quantity, asset.quantity);
        } else {
            panic!("Wrong Query Result Type.")
        }
    } else {
        panic!("Wrong Query Result Type.");
    }
    peer_handle
        .join()
        .expect("Failed to wait for the Iroha thread");
    thread::spawn(move || create_and_start_iroha(temp_dir.path()));
    thread::sleep(std::time::Duration::from_millis(300));
    let request = client::asset::by_account_id(account_id);
    let query_result = iroha_client
        .request(&request)
        .expect("Failed to execute request.");
    if let QueryResult(Value::Vec(assets)) = query_result {
        assert!(!assets.is_empty());
        if let Value::Identifiable(IdentifiableBox::Asset(asset)) =
            assets.first().expect("Asset should exist.")
        {
            assert_eq!(quantity, asset.quantity);
        } else {
            panic!("Wrong Query Result Type.")
        }
    } else {
        panic!("Wrong Query Result Type.");
    }
}

fn create_and_start_iroha(block_store_path: &Path) {
    let mut configuration =
        Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
    configuration
        .kura_configuration
        .kura_block_store_path(block_store_path);
    let iroha = Iroha::new(configuration.clone(), AllowAll.into());
    let _result = task::block_on(async_std::future::timeout(
        Duration::from_millis(configuration.sumeragi_configuration.pipeline_time_ms() * 6),
        iroha.start(),
    ));
}
