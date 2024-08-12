use eyre::Result;
use iroha::{
    client::{self, Client},
    crypto::KeyPair,
    data_model::{
        peer::{Peer as DataModelPeer, PeerId},
        prelude::*,
    },
};
use iroha_config::parameters::actual::Root as Config;
use iroha_primitives::addr::socket_addr;
use test_network::*;
use test_samples::ALICE_ID;

#[test]
fn genesis_block_is_committed_with_some_offline_peers() -> Result<()> {
    // Given
    let (_rt, network, client) = NetworkBuilder::new(4, Some(10_560))
        .with_offline_peers(1)
        .create_with_runtime();
    wait_for_genesis_committed(&network.clients(), 1);

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

    let (_rt, network, client) = Network::start_test_with_runtime(n_peers, Some(11_160));
    wait_for_genesis_committed(&network.clients(), 0);
    let pipeline_time = Config::pipeline_time();
    let peer_clients = Network::clients(&network);

    check_status(&peer_clients, 1);

    let address = socket_addr!(128.0.0.2:8085);
    let key_pair = KeyPair::random();
    let public_key = key_pair.public_key().clone();
    let peer_id = PeerId::new(address, public_key);
    let register_peer = Register::peer(DataModelPeer::new(peer_id));

    // Wait for some time to allow peers to connect
    client.submit_blocking(register_peer)?;
    std::thread::sleep(pipeline_time * 2);

    // Make sure status hasn't change
    check_status(&peer_clients, 2);

    Ok(())
}

fn check_status(peer_clients: &[Client], expected_blocks: u64) {
    let n_peers = peer_clients.len() as u64;

    for peer_client in peer_clients {
        let status = peer_client.get_status().unwrap();

        assert_eq!(status.peers, n_peers - 1);
        assert_eq!(status.blocks, expected_blocks);
    }
}
