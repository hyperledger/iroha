use eyre::Result;
use iroha::{client, data_model::prelude::*};
use iroha_telemetry::metrics::Status;
use iroha_test_network::*;
use tokio::task::spawn_blocking;

fn status_eq_excluding_uptime_and_queue(lhs: &Status, rhs: &Status) -> bool {
    lhs.peers == rhs.peers
        && lhs.blocks == rhs.blocks
        && lhs.txs_approved == rhs.txs_approved
        && lhs.txs_rejected == rhs.txs_rejected
        && lhs.view_changes == rhs.view_changes
}

async fn check(client: &client::Client, blocks: u64) -> Result<()> {
    let status_json = reqwest::get(client.torii_url.join("/status").unwrap())
        .await?
        .json()
        .await?;

    let status_scale = {
        let client = client.clone();
        spawn_blocking(move || client.get_status()).await??
    };

    assert!(status_eq_excluding_uptime_and_queue(
        &status_json,
        &status_scale
    ));
    assert_eq!(status_json.blocks, blocks);

    Ok(())
}

#[tokio::test]
async fn json_and_scale_statuses_equality() -> Result<()> {
    let network = NetworkBuilder::new().start().await?;
    let client = network.client();

    check(&client, 1).await?;

    {
        let client = client.clone();
        spawn_blocking(move || {
            client.submit_blocking(Register::domain(Domain::new("looking_glass".parse()?)))
        })
    }
    .await??;
    network.ensure_blocks(2).await?;

    check(&client, 2).await?;

    Ok(())
}
