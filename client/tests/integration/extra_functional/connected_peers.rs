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
use iroha_data_model::{domain::Domain, transaction::TransactionBuilder};
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
    let (rt, network, _) = Network::start_test_with_runtime(4, Some(11_180));
    rt.block_on(wait_for_genesis_committed_async(&network.clients(), 0));

    let mut peer_clients: Vec<_> = Network::peers(&network)
        .zip(Network::clients(&network))
        .collect();

    check_status(&peer_clients, 1);

    // Start new peer
    let mut configuration = Config::test();
    configuration.sumeragi.trusted_peers.value_mut().others =
        unique_vec![peer_clients.choose(&mut thread_rng()).unwrap().0.id.clone()];
    let rt = Runtime::test();
    let new_peer = rt.block_on(
        PeerBuilder::new()
            .with_config(configuration)
            .with_into_genesis(WithGenesis::None)
            .with_port(11_225)
            .start(),
    );
    let new_peer_client = Client::test(&new_peer.api_address);

    let register_peer = Register::peer(DataModelPeer::new(new_peer.id.clone()));
    peer_clients
        .choose(&mut thread_rng())
        .unwrap()
        .1
        .submit_blocking(register_peer)?;

    // Submit transaction through a new peer and wait for response to check that it is functioning properly
    let instructions = [Register::domain(Domain::new("dummy".parse().unwrap()))];
    let mut tx = TransactionBuilder::new(
        new_peer_client.chain.clone(),
        new_peer_client.account.clone(),
    )
    .with_instructions(instructions);
    tx.set_ttl(Duration::from_millis(u64::MAX));
    let tx = new_peer_client.sign_transaction(tx);
    new_peer_client
        .submit_transaction_blocking(&tx)
        .expect("failed to submit transaction through new peer");

    peer_clients.push((&new_peer, new_peer_client));

    check_status(&peer_clients, 3);

    Ok(())
}

/// Test the number of connected peers, changing the number of faults tolerated down and up
fn connected_peers_with_f(faults: u64, start_port: Option<u16>) -> Result<()> {
    let n_peers = 3 * faults + 1;

    let (rt, network, _) = Network::start_test_with_runtime(
        (n_peers)
            .try_into()
            .wrap_err("`faults` argument `u64` value too high, cannot convert to `u32`")?,
        start_port,
    );
    rt.block_on(wait_for_genesis_committed_async(&network.clients(), 0));
    let pipeline_time = Config::pipeline_time();

    let mut peer_clients: Vec<_> = Network::peers(&network)
        .zip(Network::clients(&network))
        .collect();

    check_status(&peer_clients, 1);

    // Unregister a peer: committed with f = `faults` then `status.peers` decrements
    let removed_peer_idx = rand::thread_rng().gen_range(0..peer_clients.len());
    let (removed_peer, _) = &peer_clients[removed_peer_idx];
    let unregister_peer = Unregister::peer(removed_peer.id.clone());
    peer_clients
        .choose(&mut thread_rng())
        .unwrap()
        .1
        .submit_blocking(unregister_peer)?;
    thread::sleep(pipeline_time * 2); // Wait for some time to allow peers to connect
    let (removed_peer, removed_peer_client) = peer_clients.remove(removed_peer_idx);

    thread::sleep(pipeline_time * 2); // Wait for some time to allow peers to disconnect

    check_status(&peer_clients, 2);
    let status = removed_peer_client.get_status()?;
    // Peer might have been disconnected before getting the block
    assert!(status.blocks == 1 || status.blocks == 2);
    assert_eq!(status.peers, 0);

    // Re-register the peer: committed with f = `faults` - 1 then `status.peers` increments
    let register_peer = Register::peer(DataModelPeer::new(removed_peer.id.clone()));
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
