#![allow(clippy::restriction)]

use std::{str::FromStr, sync::Arc, thread, time::Duration};

use eyre::Result;
use iroha_client::client;
use iroha_core::prelude::*;
use iroha_data_model::prelude::*;
use tempfile::TempDir;
use test_network::{Peer as TestPeer, *};
use tokio::runtime::Runtime;

use super::Configuration;

#[test]
fn restarted_peer_should_have_the_same_asset_amount() -> Result<()> {
    prepare_test_for_nextest!();
    let temp_dir = Arc::new(TempDir::new()?);

    let mut configuration = Configuration::test();
    let mut peer = <TestPeer>::new()?;
    configuration.sumeragi.trusted_peers.peers = std::iter::once(peer.id.clone()).collect();

    let pipeline_time = Duration::from_millis(configuration.sumeragi.pipeline_time_ms());

    // Given
    let rt = Runtime::test();
    rt.block_on(
        PeerBuilder::new()
            .with_configuration(configuration.clone())
            .with_instruction_validator(AllowAll)
            .with_query_validator(AllowAll)
            .with_dir(Arc::clone(&temp_dir))
            .start_with_peer(&mut peer),
    );
    let mut iroha_client = client::Client::test(&peer.api_address, &peer.telemetry_address);

    wait_for_genesis_committed(&vec![iroha_client.clone()], 0);

    let account_id = AccountId::from_str("alice@wonderland").unwrap();
    let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland").unwrap();
    let create_asset = RegisterBox::new(AssetDefinition::quantity(asset_definition_id.clone()));
    iroha_client.submit(create_asset)?;
    thread::sleep(pipeline_time * 2);
    // When
    let quantity: u32 = 200;
    let mint_asset = MintBox::new(
        Value::U32(quantity),
        IdBox::AssetId(AssetId::new(
            asset_definition_id.clone(),
            account_id.clone(),
        )),
    );
    iroha_client.submit(mint_asset)?;
    thread::sleep(pipeline_time * 2);

    // Then
    let asset = iroha_client
        .request(client::asset::by_account_id(account_id.clone()))?
        .into_iter()
        .find(|asset| asset.id().definition_id == asset_definition_id)
        .expect("Asset not found");
    assert_eq!(AssetValue::Quantity(quantity), *asset.value());

    thread::sleep(Duration::from_millis(2000));
    drop(rt);

    thread::sleep(Duration::from_millis(2000));

    let rt = Runtime::test();

    let builder = PeerBuilder::new()
        .with_configuration(configuration)
        .with_instruction_validator(AllowAll)
        .with_query_validator(AllowAll)
        .with_dir(temp_dir);

    rt.block_on(builder.start_with_peer(&mut peer));

    let account_asset = iroha_client
        .poll_request(client::asset::by_account_id(account_id), |assets| {
            iroha_logger::error!(?assets);
            assets
                .iter()
                .any(|asset| asset.id().definition_id == asset_definition_id)
        })
        .expect("Valid")
        .into_iter()
        .find(|asset| asset.id().definition_id == asset_definition_id)
        .unwrap();

    assert_eq!(AssetValue::Quantity(quantity), *account_asset.value());
    Ok(())
}
