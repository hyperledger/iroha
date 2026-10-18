//! Connected peers count and reconfiguration under register/unregister.
use assert_matches::assert_matches;
use eyre::{Result, WrapErr, eyre};
use futures_util::{StreamExt, stream::FuturesUnordered};
use integration_tests::sandbox;
use iroha::data_model::{
    Level,
    isi::{InstructionBox, Log, Unregister, register::RegisterPeerWithPop},
    prelude::QueryBuilderExt,
    query::peer::prelude::FindPeers,
};
use iroha_test_network::*;
use rand::{SeedableRng, prelude::IteratorRandom};
use rand_chacha::ChaCha8Rng;
use std::{fmt::Write as _, time::Duration};
use tokio::{
    task::spawn_blocking,
    time::{Instant, sleep, timeout},
};
fn leader_peer<'a>(peers: impl IntoIterator<Item = &'a NetworkPeer>) -> &'a NetworkPeer {
    peers
        .into_iter()
        .min_by(|left, right| left.id().cmp(&right.id()))
        .expect("network should have at least one peer")
}
#[tokio::test]
async fn connected_peers_with_f_2_1_2() -> Result<()> {
    connected_peers_with_f(stringify!(connected_peers_with_f_2_1_2), 2).await
}
#[tokio::test]
async fn connected_peers_with_f_1_0_1() -> Result<()> {
    connected_peers_with_f(stringify!(connected_peers_with_f_1_0_1), 1).await
}
#[tokio::test]
async fn register_new_peer() -> Result<()> {
    let Some(network) = sandbox::start_network_async_or_skip(
        NetworkBuilder::new()
            .with_block_cadence(std::time::Duration::from_secs(2))
            .with_peers(4)
            .with_max_validator_capacity(5),
        stringify!(register_new_peer),
    )
    .await?
    else {
        return Ok(());
    };
    let peer = NetworkPeerBuilder::new().build(network.env());
    let submit_timeout = network
        .sync_timeout()
        .saturating_add(network.da_commit_quorum_timeout());
    let peer_sync_timeout = network
        .sync_timeout()
        .saturating_mul(2)
        .saturating_add(network.da_commit_quorum_timeout());
    let register = RegisterPeerWithPop::new(
        peer.id(),
        peer.bls_pop()
            .expect("network peer should have BLS PoP")
            .to_vec(),
    );
    let client = integration_tests::sync::rebind_blocking_client(&network.client(), |client| {
        client.transaction_status_timeout = submit_timeout;
        client.transaction_ttl = Some(submit_timeout.saturating_add(Duration::from_secs(120)));
    });
    submit_instruction_or_warn(client, register, "register_new_peer").await?;
    if sandbox::handle_result(
        network.ensure_blocks(2).await,
        stringify!(register_new_peer),
    )?
    .is_none()
    {
        return Ok(());
    }
    let genesis = network.genesis();
    peer.start(
        network.config_layers_with_additional_peers([&peer]),
        Some(&genesis),
    )
    .await?;
    if sandbox::handle_result(
        timeout(peer_sync_timeout, peer.once_block(2))
            .await
            .map_err(eyre::Report::new),
        stringify!(register_new_peer),
    )?
    .is_none()
    {
        return Ok(());
    }
    let client = integration_tests::sync::rebind_blocking_client(&network.client(), |client| {
        client.transaction_status_timeout = submit_timeout;
        client.transaction_ttl = Some(submit_timeout.saturating_add(Duration::from_secs(120)));
    });
    submit_instruction_or_warn(
        client,
        Log::new(Level::INFO, "register_new_peer_sync".to_string()),
        "register_new_peer",
    )
    .await?;
    if sandbox::handle_result(
        network.ensure_blocks(3).await,
        stringify!(register_new_peer),
    )?
    .is_none()
    {
        return Ok(());
    }
    if sandbox::handle_result(
        timeout(peer_sync_timeout, peer.once_block(3))
            .await
            .map_err(eyre::Report::new),
        stringify!(register_new_peer),
    )?
    .is_none()
    {
        return Ok(());
    }
    Ok(())
}
/// Test the number of connected peers, changing the number of faults tolerated down and up.
#[allow(clippy::too_many_lines)]
async fn connected_peers_with_f(context: &'static str, faults: usize) -> Result<()> {
    let n_peers = 3 * faults + 1;
    let builder = NetworkBuilder::new()
        .with_peers(n_peers)
        .with_block_cadence(std::time::Duration::from_secs(2));
    let Some(network) = sandbox::start_network_async_or_skip(builder, context).await? else {
        return Ok(());
    };
    // This scenario performs two roster reconfigurations and can exceed the generic sync budget on
    // loaded CI hosts.
    let sync_timeout = network.sync_timeout().saturating_mul(2);
    let da_commit_timeout = network.da_commit_quorum_timeout();
    let expected_connected = expected_connected_peers(n_peers);
    if sandbox::handle_result(
        assert_peers_status(network.peers().iter(), 1, expected_connected, sync_timeout).await,
        context,
    )?
    .is_none()
    {
        return Ok(());
    }
    let mut randomized_peers = {
        let mut rng = ChaCha8Rng::seed_from_u64(0x434f_4e4e);
        network.peers().iter().choose_multiple(&mut rng, n_peers)
    };
    let removed_peer = randomized_peers.remove(0);
    let roster_client = leader_peer(randomized_peers.iter().copied()).client();
    let submit_timeout = sync_timeout.saturating_add(da_commit_timeout);
    // Unregister a peer and wait for the roster to reflect the change.
    let unregister_peer = Unregister::peer(removed_peer.id());
    if sandbox::handle_result(
        submit_instruction_until_peer_roster(
            randomized_peers.iter().copied(),
            &roster_client,
            unregister_peer.into(),
            n_peers - 1,
            context,
            submit_timeout,
            sync_timeout,
        )
        .await,
        context,
    )?
    .is_none()
    {
        return Ok(());
    }
    wait_for_block_height(randomized_peers.iter().copied(), 2, sync_timeout).await?;
    let expected_connected = expected_connected_peers(n_peers - 1);
    if sandbox::handle_result(
        assert_peers_status(
            randomized_peers.iter().copied(),
            2,
            expected_connected,
            sync_timeout,
        )
        .await,
        context,
    )?
    .is_none()
    {
        return Ok(());
    }
    // Removed peers remain connected to continue block sync; ensure they still observe block 2.
    if sandbox::handle_result(
        wait_for_block_height(std::iter::once(removed_peer), 2, sync_timeout).await,
        context,
    )?
    .is_none()
    {
        return Ok(());
    }
    let status = removed_peer.status().await?;
    // Removed peer might see one extra commit while transitioning to follower mode.
    assert_matches!(status.blocks_non_empty, 1 | 2 | 3);
    // Re-register the peer using the same join flow as a new peer. Keeping the
    // removed peer process online while it is outside the roster is flaky on
    // 4-peer localnets; restarting it after the register block is more stable.
    removed_peer.shutdown().await;
    let re_register_timeout = sync_timeout.saturating_add(da_commit_timeout);
    let register_peer: InstructionBox = RegisterPeerWithPop::new(
        removed_peer.id(),
        removed_peer
            .bls_pop()
            .expect("network peer should have BLS PoP")
            .to_vec(),
    )
    .into();
    let client = leader_peer(randomized_peers.iter().copied()).client();
    let client = integration_tests::sync::rebind_blocking_client(&client, |client| {
        client.transaction_status_timeout = submit_timeout;
        client.transaction_ttl = Some(submit_timeout.saturating_add(Duration::from_secs(120)));
    });
    if sandbox::handle_result(
        submit_instruction_or_warn(client, register_peer, context).await,
        context,
    )?
    .is_none()
    {
        return Ok(());
    }
    if sandbox::handle_result(
        wait_for_block_height(randomized_peers.iter().copied(), 3, re_register_timeout).await,
        context,
    )?
    .is_none()
    {
        return Ok(());
    }
    let genesis = network.genesis();
    if sandbox::handle_result(
        removed_peer
            .start(
                network.config_layers_with_additional_peers([removed_peer]),
                Some(&genesis),
            )
            .await,
        context,
    )?
    .is_none()
    {
        return Ok(());
    }
    if sandbox::handle_result(
        wait_for_block_height(std::iter::once(removed_peer), 3, sync_timeout).await,
        context,
    )?
    .is_none()
    {
        return Ok(());
    }
    if sandbox::handle_result(
        wait_for_peer_roster(&roster_client, n_peers, re_register_timeout).await,
        context,
    )?
    .is_none()
    {
        return Ok(());
    }
    let expected_connected = expected_connected_peers(n_peers);
    if sandbox::handle_result(
        assert_peers_status(network.peers().iter(), 3, expected_connected, sync_timeout).await,
        context,
    )?
    .is_none()
    {
        return Ok(());
    }
    Ok(())
}
async fn assert_peers_status(
    peers: impl IntoIterator<Item = &'_ NetworkPeer>,
    expected_blocks: u64,
    expected_peers: u64,
    timeout: Duration,
) -> Result<()> {
    let peers: Vec<_> = peers.into_iter().collect();
    let deadline = Instant::now() + timeout;
    loop {
        let mismatches = peers
            .iter()
            .map(|peer| async {
                match peer.status().await {
                    Err(err) if !peer.is_running() => Some(format!(
                        "{}: peer not running; status error: {err}; stdout={:?} stderr={:?}",
                        peer.id(),
                        peer.latest_stdout_log_path(),
                        peer.latest_stderr_log_path(),
                    )),
                    Ok(status) => {
                        let fallback_height = peer.best_effort_block_height();
                        let last_peers = peer.last_known_peers();
                        let peers_ok = status.peers >= expected_peers
                            || last_peers.is_some_and(|peers| peers >= expected_peers);
                        let blocks_ok = status.blocks >= expected_blocks
                            || fallback_height
                                .is_some_and(|height| height.total >= expected_blocks);
                        if peers_ok && blocks_ok {
                            return None;
                        }
                        let mut message = format!(
                            "{}: peers={}, blocks={}, blocks_non_empty={}",
                            peer.id(),
                            status.peers,
                            status.blocks,
                            status.blocks_non_empty
                        );
                        if let Some(height) = fallback_height {
                            let _ = write!(
                                message,
                                "; fallback_blocks_total={} non_empty={}",
                                height.total, height.non_empty
                            );
                        }
                        if let Some(peers) = last_peers {
                            let _ = write!(message, "; last_known_peers={peers}");
                        }
                        Some(message)
                    }
                    Err(err) => {
                        let fallback_height = peer.best_effort_block_height();
                        let last_peers = peer.last_known_peers();
                        if let (Some(height), Some(peers)) = (fallback_height, last_peers)
                            && height.total >= expected_blocks
                            && peers >= expected_peers
                        {
                            return None;
                        }
                        let mut message = format!(
                            "{}: status error: {err}; stdout={:?} stderr={:?}",
                            peer.id(),
                            peer.latest_stdout_log_path(),
                            peer.latest_stderr_log_path()
                        );
                        if let Some(height) = fallback_height {
                            let _ = write!(
                                message,
                                "; fallback_blocks_total={} non_empty={}",
                                height.total, height.non_empty
                            );
                        }
                        if let Some(peers) = last_peers {
                            let _ = write!(message, "; last_known_peers={peers}");
                        }
                        Some(message)
                    }
                }
            })
            .collect::<FuturesUnordered<_>>()
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        if mismatches.is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(eyre!(
                "deadline has elapsed waiting for peer status: {:?}",
                mismatches
            ));
        }
        sleep(Duration::from_millis(200)).await;
    }
}
async fn wait_for_block_height(
    peers: impl IntoIterator<Item = &'_ NetworkPeer>,
    expected_blocks: u64,
    timeout: Duration,
) -> Result<()> {
    let peers: Vec<_> = peers.into_iter().collect();
    let deadline = Instant::now() + timeout;
    loop {
        let lagging = peers
            .iter()
            .map(|peer| async {
                match peer.status().await {
                    Err(err) if !peer.is_running() => Some(format!(
                        "{}: peer not running; status error: {err}; stdout={:?} stderr={:?}",
                        peer.id(),
                        peer.latest_stdout_log_path(),
                        peer.latest_stderr_log_path(),
                    )),
                    Ok(status) => {
                        let fallback_height = peer.best_effort_block_height();
                        let blocks_ok = status.blocks >= expected_blocks
                            || fallback_height
                                .is_some_and(|height| height.total >= expected_blocks);
                        if blocks_ok {
                            return None;
                        }
                        let mut message = format!(
                            "{}: blocks={}, blocks_non_empty={}",
                            peer.id(),
                            status.blocks,
                            status.blocks_non_empty
                        );
                        if let Some(height) = fallback_height {
                            let _ = write!(
                                message,
                                "; fallback_blocks_total={} non_empty={}",
                                height.total, height.non_empty
                            );
                        }
                        Some(message)
                    }
                    Err(err) => {
                        let fallback_height = peer.best_effort_block_height();
                        if fallback_height.is_some_and(|height| height.total >= expected_blocks) {
                            return None;
                        }
                        let mut message = format!(
                            "{}: status error: {err}; stdout={:?} stderr={:?}",
                            peer.id(),
                            peer.latest_stdout_log_path(),
                            peer.latest_stderr_log_path()
                        );
                        if let Some(height) = fallback_height {
                            let _ = write!(
                                message,
                                "; fallback_blocks_total={} non_empty={}",
                                height.total, height.non_empty
                            );
                        }
                        Some(message)
                    }
                }
            })
            .collect::<FuturesUnordered<_>>()
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        if lagging.is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(eyre!(
                "deadline has elapsed waiting for block height {expected_blocks}: {:?}",
                lagging
            ));
        }
        sleep(Duration::from_millis(200)).await;
    }
}
async fn submit_instruction_or_warn(
    client: iroha::blocking::Client,
    instruction: impl Into<InstructionBox>,
    context: &str,
) -> Result<()> {
    let instruction = instruction.into();
    let context = context.to_string();
    spawn_blocking(move || {
        client
            .submit(
                instruction,
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .map(|_| ())
            .wrap_err(context)
    })
    .await??;
    Ok(())
}
async fn submit_instruction_until_peer_roster(
    peers: impl IntoIterator<Item = &'_ NetworkPeer>,
    roster_client: &iroha::blocking::Client,
    instruction: InstructionBox,
    expected_roster: usize,
    context: &str,
    submit_timeout: Duration,
    timeout: Duration,
) -> Result<()> {
    let peers: Vec<_> = peers.into_iter().collect();
    let deadline = Instant::now() + timeout;
    let mut last_submit_err: Option<String> = None;
    let mut last_roster_err: Option<String> = None;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(eyre!(
                "timed out waiting for peer roster size {expected_roster}; last_submit_err={last_submit_err:?}; last_roster_err={last_roster_err:?}"
            ));
        }
        let tx_timeout = submit_timeout.min(remaining);
        let client = leader_peer(peers.iter().copied()).client();
        let client = integration_tests::sync::rebind_blocking_client(&client, |client| {
            client.transaction_status_timeout = tx_timeout;
            client.transaction_ttl = Some(tx_timeout.saturating_add(Duration::from_secs(120)));
        });
        match submit_instruction_or_warn(client, instruction.clone(), context).await {
            Ok(()) => {}
            Err(err) if is_submit_timeout_error(&err) || is_register_duplicate_error(&err) => {
                last_submit_err = Some(err.to_string());
            }
            Err(err) => return Err(err),
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(eyre!(
                "timed out waiting for peer roster size {expected_roster}; last_submit_err={last_submit_err:?}; last_roster_err={last_roster_err:?}"
            ));
        }
        let probe_timeout = remaining.min(Duration::from_secs(10));
        match wait_for_peer_roster(roster_client, expected_roster, probe_timeout).await {
            Ok(()) => return Ok(()),
            Err(err) => {
                let (matched, samples) = sample_peer_rosters(&peers, expected_roster).await;
                if matched {
                    return Ok(());
                }
                last_roster_err = Some(format!("{err}; peer_samples={samples:?}"));
                sleep(Duration::from_millis(200)).await;
            }
        }
    }
}
fn is_submit_timeout_error(err: &eyre::Report) -> bool {
    err.chain().any(|cause| {
        let message = cause.to_string();
        message.contains("queued for too long")
            || message.contains("haven't got tx confirmation within")
            || message.contains("operation timed out")
            || message.contains("timed out")
    })
}
fn is_register_duplicate_error(err: &eyre::Report) -> bool {
    err.chain().any(|cause| {
        let message = cause.to_string();
        message.contains("RepetitionError") || message.contains("Repetition of")
    })
}
fn expected_connected_peers(roster_len: usize) -> u64 {
    iroha_sumeragi::types::quorum(roster_len)
        .saturating_sub(1)
        .try_into()
        .unwrap_or(0)
}
async fn wait_for_peer_roster(
    client: &iroha::blocking::Client,
    expected: usize,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let mut last_err = None;
    let mut last_count = None;
    loop {
        let client = client.clone();
        let result = spawn_blocking(move || {
            client
                .client()
                .query(FindPeers)
                .execute_all()
                .map(|peers| peers.len())
        })
        .await?;
        match result {
            Ok(count) => {
                last_count = Some(count);
                if count == expected {
                    return Ok(());
                }
            }
            Err(err) => {
                last_err = Some(err);
            }
        }
        if Instant::now() >= deadline {
            return Err(eyre!(
                "timed out waiting for peer roster size {expected}; last_count={last_count:?} last_err={last_err:?}"
            ));
        }
        sleep(Duration::from_millis(200)).await;
    }
}
async fn sample_peer_rosters(peers: &[&NetworkPeer], expected: usize) -> (bool, Vec<String>) {
    let samples = peers
        .iter()
        .map(|peer| async {
            let peer_id = peer.id().to_string();
            let client = peer.client();
            let result = spawn_blocking(move || {
                client
                    .client()
                    .query(FindPeers)
                    .execute_all()
                    .map(|roster| roster.len())
            })
            .await;
            match result {
                Ok(Ok(count)) => (count == expected, format!("{peer_id}={count}")),
                Ok(Err(err)) => (false, format!("{peer_id}=err({err})")),
                Err(err) => (false, format!("{peer_id}=join_err({err})")),
            }
        })
        .collect::<FuturesUnordered<_>>()
        .collect::<Vec<_>>()
        .await;
    let matched = samples.iter().any(|(matched, _)| *matched);
    let details = samples.into_iter().map(|(_, detail)| detail).collect();
    (matched, details)
}
