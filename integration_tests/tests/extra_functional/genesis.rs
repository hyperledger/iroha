//! Integration tests covering multi-peer genesis submissions.
use integration_tests::sandbox;
use iroha_model_base::domain::DomainId;
use iroha_test_network::{NetworkBuilder, ensure_domain_setup_for_network};
#[tokio::test]
async fn all_peers_submit_genesis() -> eyre::Result<()> {
    multiple_genesis_peers(4, 4).await
}
#[tokio::test]
async fn multiple_genesis_4_peers_3_genesis() -> eyre::Result<()> {
    multiple_genesis_peers(4, 3).await
}
#[tokio::test]
async fn multiple_genesis_4_peers_2_genesis() -> eyre::Result<()> {
    multiple_genesis_peers(4, 2).await
}
async fn multiple_genesis_peers(n_peers: usize, n_genesis_peers: usize) -> eyre::Result<()> {
    if let Some(probe) = sandbox::start_network_async_or_skip(
        NetworkBuilder::new()
            .with_block_cadence(std::time::Duration::from_secs(2))
            .with_peers(n_peers),
        stringify!(multiple_genesis_peers),
    )
    .await?
    {
        probe.shutdown().await;
    } else {
        return Ok(());
    }
    let guard = sandbox::serial_guard();
    let network = NetworkBuilder::new()
        .with_auto_populated_trusted_peers()
        .with_block_cadence(std::time::Duration::from_secs(2))
        .with_peers(n_peers)
        .build();
    let network = sandbox::SerializedNetwork::new(network, guard);
    let start_result = network
        .start_with_genesis_submitters(0..n_genesis_peers.min(n_peers))
        .await;
    if sandbox::handle_result(start_result, stringify!(multiple_genesis_peers))?.is_none() {
        return Ok(());
    }
    let ensure = network.ensure_blocks(1).await;
    if sandbox::handle_result(ensure, stringify!(multiple_genesis_peers))?.is_none() {
        return Ok(());
    }
    let domain_id: DomainId = DomainId::try_new("foo", "universal").expect("Valid");
    let submit_result = ensure_domain_setup_for_network(&network, &domain_id);
    if sandbox::handle_result(submit_result, stringify!(multiple_genesis_peers))?.is_none() {
        return Ok(());
    }
    Ok(())
}
