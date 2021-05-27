#![allow(clippy::module_inception, unused_results, clippy::restriction)]

use std::{thread, time::Duration};

use iroha::{config::Configuration, prelude::*};
use iroha_client::client::{self, Client};
use iroha_data_model::prelude::*;
use tempfile::TempDir;
use test_network::*;
use test_network::{Peer as TestPeer, ShutdownRuntime, GENESIS_PATH};

#[test]
fn restarted_peer_should_have_the_same_asset_amount() {
    let temp_dir = TempDir::new().expect("Failed to create TempDir.");

    let mut configuration = Configuration::test();
    let peer = TestPeer::new().expect("Failed to create peer");
    configuration.sumeragi_configuration.trusted_peers.peers =
        std::iter::once(peer.id.clone()).collect();
    configuration.genesis_configuration.genesis_block_path = Some(GENESIS_PATH.to_owned());

    let pipeline_time =
        Duration::from_millis(configuration.sumeragi_configuration.pipeline_time_ms());

    // Given
    let peer_handle =
        peer.start_with_config_permissions_dir(configuration.clone(), AllowAll, &temp_dir);
    thread::sleep(pipeline_time);
    let domain_name = "wonderland";
    let account_name = "alice";
    let account_id = AccountId::new(account_name, domain_name);
    let asset_definition_id = AssetDefinitionId::new("xor", domain_name);
    let create_asset = RegisterBox::new(IdentifiableBox::AssetDefinition(
        AssetDefinition::new_quantity(asset_definition_id.clone()).into(),
    ));
    let mut iroha_client = Client::test(&peer.api_address);
    let _ = iroha_client
        .submit(create_asset)
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
        .submit(mint_asset)
        .expect("Failed to create asset.");
    thread::sleep(pipeline_time * 2);
    //Then
    let assets = iroha_client
        .request(client::asset::by_account_id(account_id.clone()))
        .expect("Failed to execute request.");
    let asset = assets
        .iter()
        .find(|asset| asset.id.definition_id == asset_definition_id)
        .expect("Asset should exist.");
    assert_eq!(AssetValue::Quantity(quantity), asset.value);

    peer_handle
        .send(ShutdownRuntime)
        .expect("Failed to shutdown peer.");

    thread::sleep(Duration::from_millis(2000));

    drop(peer.start_with_config_permissions_dir(configuration, AllowAll, &temp_dir));
    thread::sleep(pipeline_time);

    let account_assets = iroha_client
        .request(client::asset::by_account_id(account_id))
        .expect("Failed to execute request.");
    let account_asset = account_assets
        .iter()
        .find(|asset| asset.id.definition_id == asset_definition_id)
        .expect("Asset should exist.");

    assert_eq!(AssetValue::Quantity(quantity), account_asset.value);
}
