use async_std::task;
use iroha::{config::Configuration, prelude::*};
use iroha_client::{
    client::{self, Client},
    config::Configuration as ClientConfiguration,
};
use iroha_data_model::prelude::*;
use iroha_permissions_validators::public_blockchain;
use std::{thread, time::Duration};
use tempfile::TempDir;

const CONFIGURATION_PATH: &str = "tests/test_config.json";

#[test]
fn permissions_disallow_asset_transfer() {
    // Given
    thread::spawn(create_and_start_iroha);
    thread::sleep(std::time::Duration::from_millis(300));
    let configuration =
        Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
    let domain_name = "global";
    let root_id = AccountId::new("root", domain_name);
    let alice_id = AccountId::new("alice", domain_name);
    let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
    let create_asset = Register::<Domain, AssetDefinition>::new(
        AssetDefinition::new(asset_definition_id.clone()),
        domain_name.to_string(),
    );
    let register_alice =
        Register::<Domain, Account>::new(Account::new(alice_id.clone()), domain_name.to_string());
    let mut iroha_client = Client::new(
        &ClientConfiguration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration."),
    );
    iroha_client
        .submit_all(vec![create_asset.into(), register_alice.into()])
        .expect("Failed to prepare state.");
    thread::sleep(Duration::from_millis(
        &configuration.sumeragi_configuration.pipeline_time_ms() * 2,
    ));
    let quantity: u32 = 200;
    let mint_asset = Mint::<Asset, u32>::new(
        quantity,
        AssetId::new(asset_definition_id.clone(), alice_id.clone()),
    );
    iroha_client
        .submit_all(vec![mint_asset.into()])
        .expect("Failed to create asset.");
    thread::sleep(Duration::from_millis(
        &configuration.sumeragi_configuration.pipeline_time_ms() * 2,
    ));
    //When
    let transfer_asset = Transfer::<Asset, u32, Asset>::new(
        AssetId::new(asset_definition_id.clone(), alice_id.clone()),
        quantity,
        AssetId::new(asset_definition_id, root_id.clone()),
    );
    let rejection_reason = iroha_client
        .submit_blocking(transfer_asset.into())
        .expect_err("Transaction was not rejected.");
    //Then
    assert_eq!(
        rejection_reason,
        "Can't transfer assets of the other account."
    );
    let request = client::asset::by_account_id(root_id);
    let query_result = iroha_client
        .request(&request)
        .expect("Failed to execute request.");
    if let QueryResult::FindAssetsByAccountId(result) = query_result {
        assert!(result.assets.is_empty());
    } else {
        panic!("Wrong Query Result Type.");
    }
}

#[test]
fn permissions_disallow_asset_burn() {
    // Given
    thread::spawn(create_and_start_iroha);
    thread::sleep(std::time::Duration::from_millis(300));
    let configuration =
        Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
    let domain_name = "global";
    let root_id = AccountId::new("root", domain_name);
    let alice_id = AccountId::new("alice", domain_name);
    let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
    let create_asset = Register::<Domain, AssetDefinition>::new(
        AssetDefinition::new(asset_definition_id.clone()),
        domain_name.to_string(),
    );
    let register_alice =
        Register::<Domain, Account>::new(Account::new(alice_id.clone()), domain_name.to_string());
    let mut iroha_client = Client::new(
        &ClientConfiguration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration."),
    );
    iroha_client
        .submit_all(vec![create_asset.into(), register_alice.into()])
        .expect("Failed to prepare state.");
    thread::sleep(Duration::from_millis(
        &configuration.sumeragi_configuration.pipeline_time_ms() * 2,
    ));
    let quantity: u32 = 200;
    let mint_asset = Mint::<Asset, u32>::new(
        quantity,
        AssetId::new(asset_definition_id.clone(), alice_id.clone()),
    );
    iroha_client
        .submit_all(vec![mint_asset.into()])
        .expect("Failed to create asset.");
    thread::sleep(Duration::from_millis(
        &configuration.sumeragi_configuration.pipeline_time_ms() * 2,
    ));
    //When
    let transfer_asset = Burn::<Asset, u32>::new(
        quantity,
        AssetId::new(asset_definition_id.clone(), alice_id.clone()),
    );
    let rejection_reason = iroha_client
        .submit_blocking(transfer_asset.into())
        .expect_err("Transaction was not rejected.");
    //Then
    assert_eq!(rejection_reason, "Can't burn assets from another account.");
    let request = client::asset::by_account_id(root_id);
    let query_result = iroha_client
        .request(&request)
        .expect("Failed to execute request.");
    if let QueryResult::FindAssetsByAccountId(result) = query_result {
        assert!(result.assets.is_empty());
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
    let permissions = public_blockchain::default_permissions();
    let iroha = Iroha::new(configuration, permissions);
    task::block_on(iroha.start()).expect("Failed to start Iroha.");
    //Prevents temp_dir from clean up untill the end of the tests.
    #[allow(clippy::empty_loop)]
    loop {}
}
