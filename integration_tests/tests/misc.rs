//! Miscellaneous integration coverage for status endpoints and helpers.
use eyre::Result;
use integration_tests::sandbox;
use iroha::blocking;
use iroha_model_base::domain::DomainId;
use iroha_test_network::*;
use iroha_torii_shared::status::Status;
use sandbox::start_network_async_or_skip;
use tokio::task::spawn_blocking;
fn status_eq_excluding_uptime_and_queue(lhs: &Status, rhs: &Status) -> bool {
    lhs.peers == rhs.peers
        && lhs.blocks == rhs.blocks
        && lhs.blocks_non_empty == rhs.blocks_non_empty
        && lhs.txs_approved == rhs.txs_approved
        && lhs.txs_rejected == rhs.txs_rejected
        && lhs.view_changes == rhs.view_changes
}
async fn check(client: &blocking::Client, min_blocks_non_empty: u64) -> Result<()> {
    let http = integration_tests::http::client();
    let body = http
        .get(client.client().endpoint().join("/status").unwrap())
        .header("Accept", "application/json")
        .send()
        .await?
        .text()
        .await?;
    let status_json: Status = norito::json::from_str(&body)
        .map_err(|err| eyre::Report::msg(format!("decode status JSON: {err}")))?;
    let status_norito = client.client().status().get().await?;
    assert!(status_eq_excluding_uptime_and_queue(
        &status_json,
        &status_norito
    ));
    assert!(
        status_json.blocks_non_empty >= min_blocks_non_empty,
        "expected blocks_non_empty >= {min_blocks_non_empty}, got {}",
        status_json.blocks_non_empty
    );
    Ok(())
}
#[tokio::test]
async fn misc_status_endpoints_smoke() -> Result<()> {
    let Some(network) = start_network_async_or_skip(
        NetworkBuilder::new().with_block_cadence(std::time::Duration::from_secs(2)),
        stringify!(misc_status_endpoints_smoke),
    )
    .await?
    else {
        return Ok(());
    };
    let client = network.client();
    // ensure_blocks_observes_genesis_progress
    network.ensure_blocks(1).await?;
    // json_and_norito_statuses_equality
    check(&client, 1).await?;
    {
        let client = client.clone();
        spawn_blocking(move || {
            let domain: DomainId = DomainId::try_new("lookingglass", "universal")?;
            client.submit(
                domain_setup_instruction(&domain, client.client().account())?,
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
        })
    }
    .await??;
    if sandbox::handle_result(
        network.ensure_blocks(2).await,
        stringify!(misc_status_endpoints_smoke),
    )?
    .is_none()
    {
        return Ok(());
    }
    check(&client, 2).await?;
    // server API version
    let response = client.client().status().version().await?;
    let version: u64 = response
        .parse()
        .expect("server API version should be a positive integer");
    assert!(version >= 1);
    // status_with_norito_accept_header
    let http = integration_tests::http::client();
    let url = network
        .client()
        .client()
        .endpoint()
        .join("/status")
        .unwrap();
    let resp = http
        .get(url)
        .header("Accept", "application/x-norito")
        .send()
        .await?;
    assert!(resp.status().is_success());
    let bytes = resp.bytes().await?;
    let _: Status = norito::decode_from_bytes(&bytes)?;
    Ok(())
}
