use std::thread;

use eyre::Result;
use iroha::{
    client::{self, Client},
    data_model::prelude::*,
};
use iroha_config::parameters::actual::Root as Config;
use iroha_test_network::*;
use iroha_test_samples::ALICE_ID;
use rand::{seq::SliceRandom, thread_rng, Rng};
use tokio::runtime::Runtime;

#[test]
fn restarted_peer_should_have_the_same_asset_amount() -> Result<()> {
    let account_id = ALICE_ID.clone();
    let asset_definition_id = "xor#wonderland".parse::<AssetDefinitionId>().unwrap();
    let quantity = numeric!(200);

    let mut removed_peer = {
        let n_peers = 4;

        let (_rt, network, _) = Network::start_test_with_runtime(n_peers, Some(11_205));
        wait_for_genesis_committed(&network.clients(), 0);
        let pipeline_time = Config::pipeline_time();
        let peer_clients = Network::clients(&network);

        let create_asset =
            Register::asset_definition(AssetDefinition::numeric(asset_definition_id.clone()));
        peer_clients
            .choose(&mut thread_rng())
            .unwrap()
            .submit_blocking(create_asset)?;

        let mint_asset = Mint::asset_numeric(
            quantity,
            AssetId::new(asset_definition_id.clone(), account_id.clone()),
        );
        peer_clients
            .choose(&mut thread_rng())
            .unwrap()
            .submit_blocking(mint_asset)?;

        // Wait for observing peer to get the block
        thread::sleep(pipeline_time);

        let assets = peer_clients
            .choose(&mut thread_rng())
            .unwrap()
            .query(client::asset::all())
            .filter_with(|asset| asset.id.account.eq(account_id.clone()))
            .execute_all()?;
        let asset = assets
            .into_iter()
            .find(|asset| *asset.id().definition() == asset_definition_id)
            .expect("Asset not found");
        assert_eq!(AssetValue::Numeric(quantity), *asset.value());

        let mut all_peers: Vec<_> = core::iter::once(network.first_peer)
            .chain(network.peers.into_values())
            .collect();
        let removed_peer_idx = rand::thread_rng().gen_range(0..all_peers.len());
        let mut removed_peer = all_peers.swap_remove(removed_peer_idx);
        removed_peer.terminate();
        removed_peer
    };
    // All peers have been stopped here

    // Restart just one peer and check if it updates itself from the blockstore
    {
        let rt = Runtime::test();
        rt.block_on(
            PeerBuilder::new()
                .with_dir(removed_peer.temp_dir.as_ref().unwrap().clone())
                .start_with_peer(&mut removed_peer),
        );
        let removed_peer_client = Client::test(&removed_peer.api_address);
        wait_for_genesis_committed(&vec![removed_peer_client.clone()], 0);

        removed_peer_client.poll(|client| {
            let assets = client
                .query(client::asset::all())
                .filter_with(|asset| asset.id.account.eq(account_id.clone()))
                .execute_all()?;
            iroha_logger::error!(?assets);

            let account_asset = assets
                .into_iter()
                .find(|asset| *asset.id().definition() == asset_definition_id)
                .expect("Asset not found");

            Ok(AssetValue::Numeric(quantity) == *account_asset.value())
        })?
    }
    Ok(())
}
