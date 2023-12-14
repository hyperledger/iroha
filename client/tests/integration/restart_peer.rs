use std::{str::FromStr, sync::Arc};

use eyre::Result;
use iroha_client::{
    client::{self, QueryResult},
    data_model::prelude::*,
};
use iroha_primitives::unique_vec;
use tempfile::TempDir;
use test_network::*;
use tokio::runtime::Runtime;

use super::Configuration;

#[test]
fn restarted_peer_should_have_the_same_asset_amount() -> Result<()> {
    let temp_dir = Arc::new(TempDir::new()?);

    let mut configuration = Configuration::test();
    let mut peer = <PeerBuilder>::new().with_port(10_000).build()?;
    configuration.sumeragi.trusted_peers.peers = unique_vec![peer.id.clone()];

    let account_id = AccountId::from_str("alice@wonderland").unwrap();
    let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland").unwrap();
    let create_asset =
        Register::asset_definition(AssetDefinition::quantity(asset_definition_id.clone()));
    let quantity: u32 = 200;

    let iroha_client = client::Client::test(&peer.api_address);

    {
        let rt = Runtime::test();
        rt.block_on(
            PeerBuilder::new()
                .with_configuration(configuration.clone())
                .with_dir(temp_dir.clone())
                .start_with_peer(&mut peer),
        );
        wait_for_genesis_committed(&vec![iroha_client.clone()], 0);

        iroha_client.submit_blocking(create_asset)?;
        let mint_asset = Mint::asset_quantity(
            quantity,
            AssetId::new(asset_definition_id.clone(), account_id.clone()),
        );
        iroha_client.submit_blocking(mint_asset)?;

        let assets = iroha_client
            .request(client::asset::by_account_id(account_id.clone()))?
            .collect::<QueryResult<Vec<_>>>()?;
        let asset = assets
            .into_iter()
            .find(|asset| asset.id().definition_id == asset_definition_id)
            .expect("Asset not found");
        assert_eq!(AssetValue::Quantity(quantity), *asset.value());
        peer.stop();
    }

    {
        let rt = Runtime::test();
        rt.block_on(
            PeerBuilder::new()
                .with_configuration(configuration)
                .with_dir(temp_dir)
                .start_with_peer(&mut peer),
        );
        wait_for_genesis_committed(&vec![iroha_client.clone()], 0);

        iroha_client.poll_request(client::asset::by_account_id(account_id), |result| {
            let assets = result.collect::<QueryResult<Vec<_>>>().expect("Valid");
            iroha_logger::error!(?assets);

            let account_asset = assets
                .into_iter()
                .find(|asset| asset.id().definition_id == asset_definition_id)
                .expect("Asset not found");

            AssetValue::Quantity(quantity) == *account_asset.value()
        })?
    }
    Ok(())
}
