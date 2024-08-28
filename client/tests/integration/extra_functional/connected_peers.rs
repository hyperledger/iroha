use std::{thread, time::Duration};

use eyre::{Context, Result};
use iroha::{
    client::Client,
    data_model::{
        isi::{Register, Unregister},
        peer::Peer as DataModelPeer,
    },
};
use iroha_config::parameters::actual::Root as Config;
use iroha_data_model::domain::Domain;
use iroha_primitives::unique_vec;
use rand::{seq::SliceRandom, thread_rng, Rng};
use test_network::*;

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
    let (rt, network, mut iroha) = Network::start_test_with_runtime(4, Some(11_180));
    iroha.transaction_ttl = Some(Duration::from_millis(u64::MAX));
    iroha.transaction_status_timeout = Duration::from_millis(u64::MAX);
    rt.block_on(wait_for_genesis_committed_async(&network.clients()));

    let mut peer_clients: Vec<_> = Network::peers(&network)
        .zip(Network::clients(&network))
        .collect();

    check_status(&peer_clients, 1);

    // Start new peer
    let mut configuration = Config::test();
    configuration.sumeragi.trusted_peers.value_mut().others =
        unique_vec![peer_clients.choose(&mut thread_rng()).unwrap().0.id.clone()];
    let new_peer = rt.block_on(
        PeerBuilder::new()
            .with_config(configuration)
            .with_into_genesis(WithGenesis::None)
            .with_port(11_225)
            .start(),
    );
    let mut new_peer_client = Client::test(&new_peer.api_address);
    new_peer_client.transaction_ttl = Some(Duration::from_millis(u64::MAX));
    new_peer_client.transaction_status_timeout = Duration::from_millis(u64::MAX);

    let register_peer = Register::peer(DataModelPeer::new(new_peer.id.clone()));
    iroha.submit_blocking(register_peer)?;

    // Submit transaction through a new peer and wait for response to check that it is functioning properly
    let isi = Register::domain(Domain::new("dummy".parse().unwrap()));
    new_peer_client
        .submit_blocking(isi)
        .expect("failed to submit transaction through new peer");

    peer_clients.push((&new_peer, new_peer_client));

    check_status(&peer_clients, 3);

    Ok(())
}

/// Test the number of connected peers, changing the number of faults tolerated down and up
fn connected_peers_with_f(faults: u64, start_port: Option<u16>) -> Result<()> {
    let n_peers = 3 * faults + 1;

    let (rt, network, mut iroha) = Network::start_test_with_runtime(
        (n_peers)
            .try_into()
            .wrap_err("`faults` argument `u64` value too high, cannot convert to `u32`")?,
        start_port,
    );
    iroha.transaction_ttl = Some(Duration::from_millis(u64::MAX));
    iroha.transaction_status_timeout = Duration::from_millis(u64::MAX);
    rt.block_on(wait_for_genesis_committed_async(&network.clients()));
    let pipeline_time = Config::pipeline_time();

    let mut peer_clients: Vec<_> = Network::peers(&network)
        .zip(Network::clients(&network))
        .collect();

    check_status(&peer_clients, 1);

    // Unregister a peer: committed with f = `faults` then `status.peers` decrements
    let removed_peer_idx = rand::thread_rng().gen_range(1..peer_clients.len());
    let (removed_peer, mut removed_peer_client) = peer_clients.remove(removed_peer_idx);
    removed_peer_client.transaction_ttl = Some(Duration::from_millis(u64::MAX));
    removed_peer_client.transaction_status_timeout = Duration::from_millis(u64::MAX);
    let unregister_peer = Unregister::peer(removed_peer.id.clone());
    iroha.submit_blocking(unregister_peer)?;

    thread::sleep(pipeline_time * 2); // Wait for some time to allow peers to disconnect

    check_status(&peer_clients, 2);
    let status = removed_peer_client.get_status()?;
    // Peer might have been disconnected before getting the block
    assert!(status.blocks == 1 || status.blocks == 2);
    assert_eq!(status.peers, 0);

    // Re-register the peer: committed with f = `faults` - 1 then `status.peers` increments
    let register_peer = Register::peer(DataModelPeer::new(removed_peer.id.clone()));
    iroha.submit_blocking(register_peer)?;

    // Submit transaction by reconnected peer to check if it's functioning
    removed_peer_client
        .submit_blocking(Register::domain(Domain::new("dummy".parse().unwrap())))
        .wrap_err("reconnected peer failed to submit transaction")?;

    peer_clients.push((removed_peer, removed_peer_client));

    check_status(&peer_clients, 4);

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
