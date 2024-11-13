use std::iter::once;

use assert_matches::assert_matches;
use eyre::Result;
use futures_util::{stream::FuturesUnordered, StreamExt};
use iroha::data_model::isi::{Register, Unregister};
use iroha_config_base::toml::WriteExt;
use iroha_test_network::*;
use rand::{prelude::IteratorRandom, seq::SliceRandom, thread_rng};
use tokio::{task::spawn_blocking, time::timeout};

#[tokio::test]
async fn connected_peers_with_f_2_1_2() -> Result<()> {
    connected_peers_with_f(2).await
}

#[tokio::test]
async fn connected_peers_with_f_1_0_1() -> Result<()> {
    connected_peers_with_f(1).await
}

#[tokio::test]
async fn register_new_peer() -> Result<()> {
    let network = NetworkBuilder::new().with_peers(4).start().await?;

    let peer = NetworkPeer::generate();
    peer.start(
        network
            .config()
            // only one random peer
            .write(["trusted_peers"], [network.peer().peer()]),
        None,
    )
    .await;

    let register = Register::peer(peer.peer_id());
    let client = network.client();
    spawn_blocking(move || client.submit_blocking(register)).await??;

    timeout(network.sync_timeout(), peer.once_block(2)).await?;

    Ok(())
}

/// Test the number of connected peers, changing the number of faults tolerated down and up
// Note: sometimes fails due to https://github.com/hyperledger-iroha/iroha/issues/5104
async fn connected_peers_with_f(faults: usize) -> Result<()> {
    let n_peers = 3 * faults + 1;

    let network = NetworkBuilder::new().with_peers(n_peers).start().await?;

    assert_peers_status(network.peers().iter(), 1, n_peers as u64 - 1).await;

    let mut randomized_peers = network
        .peers()
        .iter()
        .choose_multiple(&mut thread_rng(), n_peers);
    let removed_peer = randomized_peers.remove(0);

    // Unregister a peer: committed with f = `faults` then `status.peers` decrements
    let client = randomized_peers.choose(&mut thread_rng()).unwrap().client();
    let unregister_peer = Unregister::peer(removed_peer.peer_id());
    spawn_blocking(move || client.submit_blocking(unregister_peer)).await??;
    timeout(
        network.sync_timeout(),
        randomized_peers
            .iter()
            .map(|peer| peer.once_block(2))
            .collect::<FuturesUnordered<_>>()
            .collect::<Vec<_>>(),
    )
    .await?;
    assert_peers_status(randomized_peers.iter().copied(), 2, n_peers as u64 - 2).await;

    let status = removed_peer.status().await?;
    // Peer might have been disconnected before getting the block
    assert_matches!(status.blocks, 1 | 2);
    assert_eq!(status.peers, 0);

    // Re-register the peer: committed with f = `faults` - 1 then `status.peers` increments
    let register_peer = Register::peer(removed_peer.peer_id());
    let client = randomized_peers
        .iter()
        .choose(&mut thread_rng())
        .unwrap()
        .client();
    spawn_blocking(move || client.submit_blocking(register_peer)).await??;
    network.ensure_blocks(3).await?;

    assert_peers_status(
        randomized_peers.iter().copied().chain(once(removed_peer)),
        3,
        n_peers as u64 - 1,
    )
    .await;

    Ok(())
}

async fn assert_peers_status(
    peers: impl Iterator<Item = &NetworkPeer> + Send,
    expected_blocks: u64,
    expected_peers: u64,
) {
    peers
        .map(|peer| async {
            let status = peer.status().await.expect("peer should be able to reply");
            assert_eq!(
                status.peers,
                expected_peers,
                "unexpected peers for {}",
                peer.peer_id()
            );
            assert_eq!(
                status.blocks,
                expected_blocks,
                "expected blocks for {}",
                peer.peer_id()
            );
        })
        .collect::<FuturesUnordered<_>>()
        .collect::<Vec<_>>()
        .await;
}
