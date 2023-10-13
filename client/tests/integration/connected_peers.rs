use std::thread;

use eyre::{Context, Result};
use iroha_client::client::Client;
use iroha_data_model::{
    parameter::{default::MAX_TRANSACTIONS_IN_BLOCK, ParametersBuilder},
    peer::Peer as DataModelPeer,
    prelude::*,
};
use test_network::*;

use super::Configuration;

#[ignore = "ignore, more in #2851"]
#[test]
fn connected_peers_with_f_2_1_2() -> Result<()> {
    connected_peers_with_f(2, Some(11_020))
}

#[test]
fn connected_peers_with_f_1_0_1() -> Result<()> {
    connected_peers_with_f(1, Some(11_000))
}

/// Test the number of connected peers, changing the number of faults tolerated down and up
fn connected_peers_with_f(faults: u64, start_port: Option<u16>) -> Result<()> {
    let n_peers = 3 * faults + 1;

    let (_rt, network, client) = <Network>::start_test_with_runtime(
        (n_peers)
            .try_into()
            .wrap_err("`faults` argument `u64` value too high, cannot convert to `u32`")?,
        start_port,
    );
    wait_for_genesis_committed(&network.clients(), 0);
    let pipeline_time = Configuration::pipeline_time();

    client.submit_blocking(
        ParametersBuilder::new()
            .add_parameter(MAX_TRANSACTIONS_IN_BLOCK, 1u32)?
            .into_set_parameters(),
    )?;

    // Confirm all peers connected
    let mut status = client.get_status()?;
    assert_eq!(status.peers, n_peers - 1);
    assert_eq!(status.blocks, 2);

    // Unregister a peer: committed with f = `faults`
    // then `status.peers` decrements
    let peer = network.peers.values().last().unwrap();
    let peer_client = Client::test(&peer.api_address);
    let unregister_peer = UnregisterExpr::new(IdBox::PeerId(peer.id.clone()));
    client.submit_blocking(unregister_peer)?;
    thread::sleep(pipeline_time * 2); // Wait for some time to allow peers to connect
    status = client.get_status()?;
    assert_eq!(status.peers, n_peers - 2);
    assert_eq!(status.blocks, 3);
    status = peer_client.get_status()?;
    assert_eq!(status.peers, 0);

    // Re-register the peer: committed with f = `faults` - 1 then
    // `status.peers` increments
    let register_peer = RegisterExpr::new(DataModelPeer::new(peer.id.clone()));
    client.submit_blocking(register_peer)?;
    thread::sleep(pipeline_time * 4); // Wait for some time to allow peers to connect
    status = client.get_status()?;
    assert_eq!(status.peers, n_peers - 1);
    assert_eq!(status.blocks, 4);
    status = peer_client.get_status()?;
    assert_eq!(status.peers, n_peers - 1);
    assert_eq!(status.blocks, 4);
    Ok(())
}
