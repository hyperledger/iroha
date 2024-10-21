use eyre::{OptionExt, Result};
use futures_util::stream::{FuturesUnordered, StreamExt};
use iroha::{
    client::{self},
    crypto::KeyPair,
    data_model::{
        peer::{Peer as DataModelPeer, PeerId},
        prelude::*,
    },
};
use iroha_primitives::addr::socket_addr;
use iroha_test_network::*;
use iroha_test_samples::ALICE_ID;
use tokio::task::spawn_blocking;

#[tokio::test]
async fn genesis_block_is_committed_with_some_offline_peers() -> Result<()> {
    // Given
    let alice_id = ALICE_ID.clone();
    let roses = "rose#wonderland".parse()?;
    let alice_has_roses = numeric!(13);

    // When
    let network = NetworkBuilder::new().with_peers(4).build();
    let cfg = network.config();
    let genesis = network.genesis();
    network
        .peers()
        .iter()
        // only 2 out of 4
        .take(2)
        .enumerate()
        .map(|(i, peer)| peer.start(cfg.clone(), (i == 0).then_some(genesis)))
        .collect::<FuturesUnordered<_>>()
        .collect::<Vec<_>>()
        .await;
    network.ensure_blocks(1).await?;

    // Then
    let client = network
        .peers()
        .iter()
        .find(|x| x.is_running())
        .expect("there are two running peers")
        .client();
    spawn_blocking(move || -> Result<()> {
        let assets = client
            .query(client::asset::all())
            .filter_with(|asset| asset.id.account.eq(alice_id))
            .execute_all()?;
        let asset = assets
            .iter()
            .find(|asset| *asset.id().definition() == roses)
            .ok_or_eyre("asset should be found")?;
        assert_eq!(AssetValue::Numeric(alice_has_roses), *asset.value());
        Ok(())
    })
    .await??;

    Ok(())
}

#[tokio::test]
async fn register_offline_peer() -> Result<()> {
    const N_PEERS: usize = 4;

    let network = NetworkBuilder::new().with_peers(N_PEERS).start().await?;
    check_status(&network, N_PEERS as u64 - 1).await;

    let address = socket_addr!(128.0.0.2:8085);
    let key_pair = KeyPair::random();
    let public_key = key_pair.public_key().clone();
    let peer_id = PeerId::new(address, public_key);
    let register_peer = Register::peer(DataModelPeer::new(peer_id));

    // Wait for some time to allow peers to connect
    let client = network.client();
    spawn_blocking(move || client.submit_blocking(register_peer)).await??;
    network.ensure_blocks(2).await?;

    // Make sure peers count hasn't changed
    check_status(&network, N_PEERS as u64 - 1).await;

    Ok(())
}

async fn check_status(network: &Network, expected_peers: u64) {
    for peer in network.peers() {
        let client = peer.client();
        let status = spawn_blocking(move || client.get_status())
            .await
            .expect("no panic")
            .expect("status should not fail");

        assert_eq!(status.peers, expected_peers);
    }
}
