use async_std::task;
use iroha::{config::Configuration, prelude::*};
use iroha_client::{
    client::{self, Client},
    config::Configuration as ClientConfiguration,
};
use iroha_data_model::prelude::*;
use std::{thread, time::Duration};
use tempfile::TempDir;

const CONFIGURATION_PATH: &str = "tests/test_config.json";
const CLIENT_CONFIGURATION_PATH: &str = "tests/test_client_config.json";

#[test]
//TODO: use cucumber_rust to write `gherkin` instead of code.
fn client_add_asset_quantity_to_existing_asset_should_increase_asset_amount() {
    // Given
    thread::spawn(create_and_start_iroha);
    thread::sleep(std::time::Duration::from_millis(300));
    let configuration =
        Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
    let domain_name = "global";
    let account_name = "root";
    let account_id = AccountId::new(account_name, domain_name);
    let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
    let create_asset = RegisterBox::new(
        IdentifiableBox::AssetDefinition(AssetDefinition::new(asset_definition_id.clone()).into()),
        IdBox::DomainName(domain_name.to_string()),
    );
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
        IdBox::AssetId(AssetId::new(
            asset_definition_id.clone(),
            account_id.clone(),
        )),
    );
    iroha_client
        .submit(mint_asset.into())
        .expect("Failed to create asset.");
    thread::sleep(Duration::from_millis(
        &configuration.sumeragi_configuration.pipeline_time_ms() * 2,
    ));
    //Then
    let request = client::asset::by_account_id(account_id);
    let query_result = iroha_client
        .request(&request)
        .expect("Failed to execute request.");
    if let QueryResult::FindAssetsByAccountId(result) = query_result {
        assert!(!result.assets.is_empty());
        assert_eq!(
            quantity,
            result.assets.last().expect("Asset should exist.").quantity,
        );
    } else {
        panic!("Wrong Query Result Type.");
    }
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
