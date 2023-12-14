use std::thread;

use eyre::{Context, Result};
use iroha_client::{
    client::Client,
    data_model::{
        isi::{RegisterExpr, UnregisterExpr},
        peer::Peer as DataModelPeer,
        IdBox,
    },
};
use iroha_config::iroha::Configuration;
use iroha_primitives::unique_vec;
use rand::{seq::SliceRandom, thread_rng, Rng};
use test_network::*;
use tokio::runtime::Runtime;

#[ignore = "ignore, more in #2851"]
#[test]
fn connected_peers_with_f_2_1_2() -> Result<()> {
    connected_peers_with_f(2, Some(11_020))
}

#[test]
fn connected_peers_with_f_1_0_1() -> Result<()> {
    connected_peers_with_f(1, Some(11_000))
}

#[test]
fn register_new_peer() -> Result<()> {
    let (_rt, network, _) = Network::start_test_with_runtime(4, Some(11_180));
    wait_for_genesis_committed(&network.clients(), 0);
    let pipeline_time = Configuration::pipeline_time();

    let mut peer_clients: Vec<_> = Network::peers(&network)
        .zip(Network::clients(&network))
        .collect();

    check_status(&peer_clients, 1);

    // Start new peer
    let mut configuration = Configuration::test();
    configuration.sumeragi.trusted_peers.peers =
        unique_vec![peer_clients.choose(&mut thread_rng()).unwrap().0.id.clone()];
    let rt = Runtime::test();
    let new_peer = rt.block_on(
        PeerBuilder::new()
            .with_configuration(configuration)
            .with_into_genesis(WithGenesis::None)
            .with_port(11_200)
            .start(),
    );

    let register_peer = RegisterExpr::new(DataModelPeer::new(new_peer.id.clone()));
    peer_clients
        .choose(&mut thread_rng())
        .unwrap()
        .1
        .submit_blocking(register_peer)?;
    peer_clients.push((&new_peer, Client::test(&new_peer.api_address)));
    thread::sleep(pipeline_time * 2); // Wait for some time to allow peers to connect

    check_status(&peer_clients, 2);

    Ok(())
}

/// Test the number of connected peers, changing the number of faults tolerated down and up
fn connected_peers_with_f(faults: u64, start_port: Option<u16>) -> Result<()> {
    let n_peers = 3 * faults + 1;

    let (_rt, network, _) = Network::start_test_with_runtime(
        (n_peers)
            .try_into()
            .wrap_err("`faults` argument `u64` value too high, cannot convert to `u32`")?,
        start_port,
    );
    wait_for_genesis_committed(&network.clients(), 0);
    let pipeline_time = Configuration::pipeline_time();

    let mut peer_clients: Vec<_> = Network::peers(&network)
        .zip(Network::clients(&network))
        .collect();

    check_status(&peer_clients, 1);

    // Unregister a peer: committed with f = `faults` then `status.peers` decrements
    let removed_peer_idx = rand::thread_rng().gen_range(0..peer_clients.len());
    let (removed_peer, _) = &peer_clients[removed_peer_idx];
    let unregister_peer = UnregisterExpr::new(IdBox::PeerId(removed_peer.id.clone()));
    peer_clients
        .choose(&mut thread_rng())
        .unwrap()
        .1
        .submit_blocking(unregister_peer)?;
    thread::sleep(pipeline_time * 2); // Wait for some time to allow peers to connect
    let (removed_peer, removed_peer_client) = peer_clients.remove(removed_peer_idx);

    check_status(&peer_clients, 2);
    let status = removed_peer_client.get_status()?;
    // Peer might have been disconnected before getting the block
    assert!(status.blocks == 1 || status.blocks == 2);
    assert_eq!(status.peers, 0);

    // Re-register the peer: committed with f = `faults` - 1 then `status.peers` increments
    let register_peer = RegisterExpr::new(DataModelPeer::new(removed_peer.id.clone()));
    peer_clients
        .choose(&mut thread_rng())
        .unwrap()
        .1
        .submit_blocking(register_peer)?;
    peer_clients.insert(removed_peer_idx, (removed_peer, removed_peer_client));
    thread::sleep(pipeline_time * 2); // Wait for some time to allow peers to connect

    check_status(&peer_clients, 3);

    Ok(())
}

fn check_status(peer_clients: &[(&Peer, Client)], expected_blocks: u64) {
    let n_peers = peer_clients.len() as u64;

    for (_, peer_client) in peer_clients {
        let status = peer_client.get_status().unwrap();

        assert_eq!(status.peers, n_peers - 1);
        assert_eq!(status.blocks, expected_blocks);
    }
}
