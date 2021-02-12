use iroha::config::Configuration;
use iroha_client::{
    client::{self, Client},
    config::Configuration as ClientConfiguration,
};
use iroha_data_model::prelude::*;
use iroha_permissions_validators::public_blockchain;
use std::{thread, time::Duration};
use test_network::Peer as TestPeer;

const CONFIGURATION_PATH: &str = "tests/test_config.json";
const CLIENT_CONFIGURATION_PATH: &str = "tests/test_client_config.json";
const GENESIS_PATH: &str = "tests/genesis.json";

fn get_assets(iroha_client: &mut Client, id: &AccountId) -> Vec<Value> {
    let request = client::asset::by_account_id(id.clone());
    let query_result = iroha_client
        .request(&request)
        .expect("Failed to execute request.");
    if let QueryResult(Value::Vec(assets)) = query_result {
        assets
    } else {
        panic!("Wrong Query Result Type.");
    }
}

#[test]
fn permissions_disallow_asset_transfer() {
    let mut configuration =
        Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
    configuration.genesis_configuration.genesis_block_path = Some(GENESIS_PATH.to_string());
    let peer = TestPeer::new().expect("Failed to create peer");
    configuration.sumeragi_configuration.trusted_peers = std::iter::once(peer.id.clone()).collect();

    let pipeline_time =
        Duration::from_millis(configuration.sumeragi_configuration.pipeline_time_ms());

    // Given
    peer.start_with_config_permissions(configuration, public_blockchain::default_permissions());
    thread::sleep(pipeline_time * 5);

    let domain_name = "wonderland";
    let alice_id = AccountId::new("alice", domain_name);
    let bob_id = AccountId::new("bob", domain_name);
    let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
    let create_asset = RegisterBox::new(IdentifiableBox::AssetDefinition(
        AssetDefinition::new(asset_definition_id.clone()).into(),
    ));
    let register_bob = RegisterBox::new(IdentifiableBox::Account(
        Account::new(bob_id.clone()).into(),
    ));
    let mut client_config = ClientConfiguration::from_path(CLIENT_CONFIGURATION_PATH)
        .expect("Failed to load configuration.");
    client_config.torii_api_url = peer.api_address;
    let mut iroha_client = Client::new(&client_config);

    let alice_start_assets = get_assets(&mut iroha_client, &alice_id);

    iroha_client
        .submit_all(vec![create_asset.into(), register_bob.into()])
        .expect("Failed to prepare state.");
    thread::sleep(pipeline_time * 2);
    let quantity: u32 = 200;
    let mint_asset = MintBox::new(
        Value::U32(quantity),
        IdBox::AssetId(AssetId::new(asset_definition_id.clone(), bob_id.clone())),
    );
    iroha_client
        .submit(mint_asset.into())
        .expect("Failed to create asset.");
    thread::sleep(pipeline_time * 2);
    //When
    let transfer_asset = TransferBox::new(
        IdBox::AssetId(AssetId::new(asset_definition_id.clone(), bob_id)),
        Value::U32(quantity),
        IdBox::AssetId(AssetId::new(asset_definition_id, alice_id.clone())),
    );
    let rejection_reason = iroha_client
        .submit_blocking(transfer_asset.into())
        .expect_err("Transaction was not rejected.");
    //Then
    assert_eq!(
        rejection_reason,
        "Action not permitted: Can\'t transfer assets of the other account."
    );
    let alice_assets = get_assets(&mut iroha_client, &alice_id);
    assert_eq!(alice_assets, alice_start_assets);
}

#[test]
fn permissions_disallow_asset_burn() {
    let mut configuration =
        Configuration::from_path(CONFIGURATION_PATH).expect("Failed to load configuration.");
    configuration.genesis_configuration.genesis_block_path = Some(GENESIS_PATH.to_string());
    let peer = TestPeer::new().expect("Failed to create peer");
    configuration.sumeragi_configuration.trusted_peers = std::iter::once(peer.id.clone()).collect();

    let pipeline_time =
        Duration::from_millis(configuration.sumeragi_configuration.pipeline_time_ms());

    // Given
    peer.start_with_config_permissions(configuration, public_blockchain::default_permissions());
    thread::sleep(pipeline_time * 5);

    let domain_name = "wonderland";
    let alice_id = AccountId::new("alice", domain_name);
    let bob_id = AccountId::new("bob", domain_name);
    let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
    let create_asset = RegisterBox::new(IdentifiableBox::AssetDefinition(
        AssetDefinition::new(asset_definition_id.clone()).into(),
    ));
    let register_bob = RegisterBox::new(IdentifiableBox::Account(
        Account::new(bob_id.clone()).into(),
    ));
    let mut client_config = ClientConfiguration::from_path(CLIENT_CONFIGURATION_PATH)
        .expect("Failed to load configuration.");
    client_config.torii_api_url = peer.api_address;
    let mut iroha_client = Client::new(&client_config);

    let alice_start_assets = get_assets(&mut iroha_client, &alice_id);

    iroha_client
        .submit_all(vec![create_asset.into(), register_bob.into()])
        .expect("Failed to prepare state.");
    thread::sleep(pipeline_time * 2);
    let quantity: u32 = 200;
    let mint_asset = MintBox::new(
        Value::U32(quantity),
        IdBox::AssetId(AssetId::new(asset_definition_id.clone(), bob_id.clone())),
    );
    iroha_client
        .submit_all(vec![mint_asset.into()])
        .expect("Failed to create asset.");
    thread::sleep(pipeline_time * 2);
    //When
    let burn_asset = BurnBox::new(
        Value::U32(quantity),
        IdBox::AssetId(AssetId::new(asset_definition_id, bob_id)),
    );
    let rejection_reason = iroha_client
        .submit_blocking(burn_asset.into())
        .expect_err("Transaction was not rejected.");
    //Then
    assert_eq!(
        rejection_reason,
        "Action not permitted: Can't burn assets from another account."
    );

    let alice_assets = get_assets(&mut iroha_client, &alice_id);
    assert_eq!(alice_assets, alice_start_assets);
}
