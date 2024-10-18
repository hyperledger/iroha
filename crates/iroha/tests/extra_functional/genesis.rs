use eyre::Context;
use futures_util::{stream::FuturesUnordered, StreamExt};
use iroha::data_model::{
    domain::{Domain, DomainId},
    isi::Register,
};
use iroha_test_network::NetworkBuilder;
use tokio::{task::spawn_blocking, time::timeout};

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
    let network = NetworkBuilder::new().with_peers(n_peers).build();
    timeout(
        network.peer_startup_timeout(),
        network
            .peers()
            .iter()
            .enumerate()
            .map(|(i, peer)| {
                let cfg = network.config();
                let genesis = (i < n_genesis_peers).then_some(network.genesis());
                async move {
                    peer.start(cfg, genesis).await;
                    peer.once_block(1).await;
                }
            })
            .collect::<FuturesUnordered<_>>()
            .collect::<Vec<_>>(),
    )
    .await?;

    let client = network.client();
    let domain_id: DomainId = "foo".parse().expect("Valid");
    let create_domain = Register::domain(Domain::new(domain_id));
    spawn_blocking(move || client.submit_blocking(create_domain))
        .await?
        .wrap_err("Failed to register domain")?;

    Ok(())
}
