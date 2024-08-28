use eyre::Result;
use iroha::{
    client::{self, Client},
    crypto::KeyPair,
    data_model::{
        peer::{Peer as DataModelPeer, PeerId},
        prelude::*,
    },
};
use iroha_primitives::addr::socket_addr;
use test_network::*;
use test_samples::ALICE_ID;

#[test]
fn genesis_block_is_committed_with_some_offline_peers() -> Result<()> {
    // Given
    let (rt, network, client) = NetworkBuilder::new(4, Some(10_560))
        .with_offline_peers(1)
        .create_with_runtime();
    rt.block_on(wait_for_genesis_committed_async(&network.online_clients()));

    //When
    let alice_id = ALICE_ID.clone();
    let roses = "rose#wonderland".parse()?;
    let alice_has_roses = numeric!(13);

    //Then
    let assets = client
        .query(client::asset::all())
        .filter_with(|asset| asset.id.account.eq(alice_id))
        .execute_all()?;
    let asset = assets
        .iter()
        .find(|asset| *asset.id().definition() == roses)
        .unwrap();
    assert_eq!(AssetValue::Numeric(alice_has_roses), *asset.value());
    Ok(())
}

#[test]
fn register_offline_peer() -> Result<()> {
    let n_peers = 4;

    let (rt, network, client) = Network::start_test_with_runtime(n_peers, Some(11_160));
    rt.block_on(wait_for_genesis_committed_async(&network.clients()));
    let peer_clients = Network::clients(&network);

    check_status(&rt, &peer_clients, 1);

    let address = socket_addr!(128.0.0.2:8085);
    let key_pair = KeyPair::random();
    let public_key = key_pair.public_key().clone();
    let peer_id = PeerId::new(address, public_key);
    let register_peer = Register::peer(DataModelPeer::new(peer_id));

    // Wait for some time to allow peers to connect
    client.submit_blocking(register_peer)?;

    // Make sure status hasn't change
    check_status(&rt, &peer_clients, 2);

    Ok(())
}

/// Wait for certain amount of blocks and check number of connected peers
fn check_status(rt: &tokio::runtime::Runtime, peer_clients: &[Client], expected_blocks: usize) {
    let n_peers = peer_clients.len() as u64;

    rt.block_on(wait_for_blocks_committed_async(
        peer_clients,
        expected_blocks,
    ));

    for peer_client in peer_clients {
        let status = peer_client.get_status().unwrap();

        assert_eq!(status.peers, n_peers - 1);
        assert_eq!(status.blocks, expected_blocks as u64);
    }
}
