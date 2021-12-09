#![allow(clippy::pedantic, clippy::restriction)]

use std::thread;

use iroha_client::client::Client;
use iroha_core::config::Configuration;
use iroha_data_model::{peer::Peer as DataModelPeer, prelude::*};
use test_network::*;

#[test]
fn test_status() {
    const N_PEERS: u64 = 3 * 2 + 1;
    let mut status;

    let (_rt, network, mut genesis_client) = <Network>::start_test_with_runtime(N_PEERS as u32, 1);
    wait_for_genesis_committed(network.clients(), 0);
    let pipeline_time = Configuration::pipeline_time();

    // Confirm all peers connected
    status = genesis_client.get_status().unwrap();
    assert_eq!(status.peers, N_PEERS - 1);
    assert_eq!(status.blocks, 1);

    // Unregister a peer then `status.peers` should decrement
    let peer = network.peers.values().last().unwrap();
    let peer_client = Client::test(&peer.api_address, &peer.status_address);
    let unregister_peer = UnregisterBox::new(IdBox::PeerId(peer.id.clone()));
    genesis_client.submit(unregister_peer).unwrap();
    thread::sleep(pipeline_time * 2);
    status = genesis_client.get_status().unwrap();
    assert_eq!(status.peers, N_PEERS - 2);
    assert_eq!(status.blocks, 2);
    status = peer_client.get_status().unwrap();
    assert_eq!(status.peers, 0);
    assert_eq!(status.blocks, 2);

    // Re-register the peer then `status.peers` should increment
    let register_peer = RegisterBox::new(IdentifiableBox::Peer(
        DataModelPeer::new(peer.id.clone()).into(),
    ));
    genesis_client.submit(register_peer).unwrap();
    thread::sleep(pipeline_time * 2);
    status = genesis_client.get_status().unwrap();
    assert_eq!(status.peers, N_PEERS - 1);
    assert_eq!(status.blocks, 3);
    status = peer_client.get_status().unwrap();
    assert_eq!(status.peers, N_PEERS - 1);
    assert_eq!(status.blocks, 3);
}
