use eyre::Result;
use iroha_client::{
    client::{self, Client, QueryResult},
    crypto::KeyPair,
    data_model::{peer::Peer as DataModelPeer, prelude::*},
};
use iroha_config::iroha::Configuration;
use test_network::*;
use tokio::runtime::Runtime;

#[test]
fn genesis_block_is_committed_with_some_offline_peers() -> Result<()> {
    // Given
    let rt = Runtime::test();

    let (network, client) = rt.block_on(Network::start_test_with_offline_and_set_n_shifts(
        4,
        1,
        Some(10_560),
    ));
    wait_for_genesis_committed(&network.clients(), 1);

    //When
    let alice_id: AccountId = "alice@wonderland".parse()?;
    let roses = "rose#wonderland".parse()?;
    let alice_has_roses = 13;

    //Then
    let assets = client
        .request(client::asset::by_account_id(alice_id))?
        .collect::<QueryResult<Vec<_>>>()?;
    let asset = assets
        .iter()
        .find(|asset| asset.id().definition_id == roses)
        .unwrap();
    assert_eq!(AssetValue::Quantity(alice_has_roses), *asset.value());
    Ok(())
}

#[test]
fn register_offline_peer() -> Result<()> {
    let n_peers = 4;

    let (_rt, network, client) = Network::start_test_with_runtime(n_peers, Some(11_160));
    wait_for_genesis_committed(&network.clients(), 0);
    let pipeline_time = Configuration::pipeline_time();
    let peer_clients = Network::clients(&network);

    check_status(&peer_clients, 1);

    let address = "128.0.0.2:8085".parse()?;
    let key_pair = KeyPair::generate().unwrap();
    let public_key = key_pair.public_key().clone();
    let peer_id = PeerId::new(&address, &public_key);
    let register_peer = RegisterExpr::new(DataModelPeer::new(peer_id));

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
