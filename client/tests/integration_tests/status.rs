#![allow(clippy::pedantic, clippy::restriction)]

use std::thread;

use iroha_core::config::Configuration;
use iroha_data_model::prelude::*;
use test_network::{Network as TestNetwork, *};

#[test]
fn test_status() {
    const N_PEERS: u64 = 4;
    let mut status;

    let (rt, network, mut client) = <TestNetwork>::start_test_with_runtime(N_PEERS as u32, 1);
    wait_for_genesis_committed(network.clients(), 0);
    let pipeline_time = Configuration::pipeline_time();

    // Confirm all peers connected
    status = client.get_status().unwrap();
    assert_eq!(status.peers, N_PEERS - 1);
    assert_eq!(status.blocks, 1);

    // Add a peer then #peers should be incremented
    let (peer, _) = rt.block_on(network.add_peer());
    thread::sleep(pipeline_time * 2);
    status = client.get_status().unwrap();
    assert_eq!(status.peers, N_PEERS);
    assert_eq!(status.blocks, 2);

    // Remove the peer then #peers should be decremented
    let remove_peer = UnregisterBox::new(IdBox::PeerId(peer.id.clone()));
    client.submit(remove_peer).expect("Failed to remove peer");
    thread::sleep(pipeline_time * 2);
    status = client.get_status().unwrap();
    assert_eq!(status.peers, N_PEERS - 1);
    assert_eq!(status.blocks, 3);
}
