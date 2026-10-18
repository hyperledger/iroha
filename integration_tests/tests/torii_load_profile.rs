//! Ignored Torii HTTP hot-path load profile for focused performance validation.
use eyre::{WrapErr, ensure, eyre};
use futures_util::StreamExt as _;
use integration_tests::sandbox;
use iroha::{
    blocking::Client,
    data_model::events::{
        EventBox,
        pipeline::{PipelineEventBox, TransactionEventFilter, TransactionStatus},
    },
};
use iroha_data_model::{
    Level, NetworkId,
    isi::Log,
    query::executor::prelude::FindParameters,
    transaction::{SignedTransaction, TransactionBuilder},
};
use iroha_test_network::NetworkBuilder;
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR};
use std::{
    env,
    time::{Duration, Instant},
};
const DEFAULT_HTTP_QUERY_SAMPLES: usize = 512;
const DEFAULT_HTTP_TX_SAMPLES: usize = 256;
const DEFAULT_HTTP_COMMIT_SAMPLES: usize = 32;
const DEFAULT_HTTP_CONCURRENCY: usize = 32;
const HTTP_WARMUP_SAMPLES: usize = 16;
const EVENT_STREAM_HANDSHAKE_DELAY: Duration = Duration::from_millis(25);
fn env_usize(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}
fn bounded_concurrency(sample_count: usize, requested: usize) -> usize {
    requested.max(1).min(sample_count.max(1))
}
fn build_log_transaction(network_id: NetworkId, prefix: &str, index: usize) -> SignedTransaction {
    TransactionBuilder::new(
        network_id,
        ALICE_ID.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, format!("{prefix}-{index:04}"))])
    .sign(ALICE_KEYPAIR.private_key())
}
async fn warmup_queries(clients: &[Client], warmup_samples: usize) -> eyre::Result<()> {
    for index in 0..warmup_samples {
        let client = clients[index % clients.len()].clone();
        let params =
            tokio::task::spawn_blocking(move || client.client().query_single(FindParameters))
                .await
                .wrap_err("query warmup worker panicked")?
                .wrap_err("query warmup worker failed")?;
        std::hint::black_box(params);
    }
    Ok(())
}
async fn run_query_profile(
    clients: &[Client],
    samples: usize,
    concurrency: usize,
) -> eyre::Result<(Vec<Duration>, Duration)> {
    let concurrency = bounded_concurrency(samples, concurrency);
    let mut durations = Vec::with_capacity(samples);
    let wall_start = Instant::now();
    let mut next = 0usize;
    while next < samples {
        let batch = concurrency.min(samples - next);
        let mut handles = Vec::with_capacity(batch);
        for offset in 0..batch {
            let client = clients[(next + offset) % clients.len()].clone();
            handles.push(tokio::task::spawn_blocking(move || {
                let start = Instant::now();
                let params = client.client().query_single(FindParameters)?;
                std::hint::black_box(params);
                Ok::<Duration, eyre::Report>(start.elapsed())
            }));
        }
        for handle in handles {
            durations.push(
                handle
                    .await
                    .wrap_err("query worker panicked")?
                    .wrap_err("query worker failed")?,
            );
        }
        next += batch;
    }
    Ok((durations, wall_start.elapsed()))
}
async fn warmup_transactions(
    clients: &[Client],
    network_id: NetworkId,
    warmup_samples: usize,
) -> eyre::Result<()> {
    for index in 0..warmup_samples {
        let client = clients[index % clients.len()].clone();
        let tx = build_log_transaction(network_id, "torii-http-load-profile-warmup", index);
        let hash = tokio::task::spawn_blocking(move || client.submit_transaction(&tx))
            .await
            .wrap_err("transaction warmup worker panicked")?
            .wrap_err("transaction warmup worker failed")?;
        std::hint::black_box(hash);
    }
    Ok(())
}
async fn run_transaction_submit_profile(
    clients: &[Client],
    network_id: NetworkId,
    samples: usize,
    concurrency: usize,
) -> eyre::Result<(Vec<Duration>, Duration)> {
    let concurrency = bounded_concurrency(samples, concurrency);
    let mut durations = Vec::with_capacity(samples);
    let wall_start = Instant::now();
    let mut next = 0usize;
    while next < samples {
        let batch = concurrency.min(samples - next);
        let mut handles = Vec::with_capacity(batch);
        for offset in 0..batch {
            let client = clients[(next + offset) % clients.len()].clone();
            let tx =
                build_log_transaction(network_id, "torii-http-load-profile-submit", next + offset);
            handles.push(tokio::task::spawn_blocking(move || {
                let start = Instant::now();
                let hash = client.submit_transaction(&tx)?;
                std::hint::black_box(hash);
                Ok::<Duration, eyre::Report>(start.elapsed())
            }));
        }
        for handle in handles {
            durations.push(
                handle
                    .await
                    .wrap_err("transaction worker panicked")?
                    .wrap_err("transaction worker failed")?,
            );
        }
        next += batch;
    }
    Ok((durations, wall_start.elapsed()))
}
async fn measure_submit_to_commit(
    client: Client,
    network_id: NetworkId,
    index: usize,
    event_timeout: Duration,
) -> eyre::Result<Duration> {
    let transaction = build_log_transaction(network_id, "torii-http-load-profile-commit", index);
    let hash = transaction.hash();
    let mut events = tokio::time::timeout(
        event_timeout,
        client
            .account_client()
            .events()
            .subscribe([TransactionEventFilter::default().for_hash(hash)]),
    )
    .await
    .wrap_err("timed out opening transaction event stream")?
    .wrap_err("failed to open transaction event stream")?;
    tokio::time::sleep(EVENT_STREAM_HANDSHAKE_DELAY).await;
    let submit_client = client.clone();
    let start = Instant::now();
    let submitted_hash =
        tokio::task::spawn_blocking(move || submit_client.submit_transaction(&transaction))
            .await
            .wrap_err("commit transaction submit worker panicked")?
            .wrap_err("commit transaction submit worker failed")?;
    std::hint::black_box(submitted_hash);
    tokio::time::timeout(event_timeout, async {
        loop {
            let Some(next) = events.next().await else {
                return Err(eyre!("transaction event stream closed"));
            };
            let EventBox::Pipeline(PipelineEventBox::Transaction(event)) = next? else {
                continue;
            };
            match event.status() {
                TransactionStatus::Queued => {}
                TransactionStatus::Approved => return Ok(()),
                TransactionStatus::Rejected(reason) => {
                    return Err(eyre!("transaction rejected: {reason}"));
                }
                TransactionStatus::Expired => return Err(eyre!("transaction expired")),
            }
        }
    })
    .await
    .wrap_err("timed out waiting for transaction approval")??;
    events.close().await?;
    Ok(start.elapsed())
}
async fn run_transaction_commit_profile(
    clients: &[Client],
    network_id: NetworkId,
    samples: usize,
    concurrency: usize,
    event_timeout: Duration,
) -> eyre::Result<(Vec<Duration>, Duration)> {
    let concurrency = bounded_concurrency(samples, concurrency);
    let mut durations = Vec::with_capacity(samples);
    let wall_start = Instant::now();
    let mut next = 0usize;
    while next < samples {
        let batch = concurrency.min(samples - next);
        let mut handles = Vec::with_capacity(batch);
        for offset in 0..batch {
            let client = clients[(next + offset) % clients.len()].clone();
            handles.push(tokio::spawn(measure_submit_to_commit(
                client,
                network_id,
                next + offset,
                event_timeout,
            )));
        }
        for handle in handles {
            durations.push(
                handle
                    .await
                    .wrap_err("commit worker panicked")?
                    .wrap_err("commit worker failed")?,
            );
        }
        next += batch;
    }
    Ok((durations, wall_start.elapsed()))
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "HTTP load profile; run explicitly with --ignored --nocapture"]
async fn torii_http_hot_path_load_profile() -> eyre::Result<()> {
    let query_samples = env_usize(
        "IROHA_TORII_LOAD_PROFILE_QUERY_SAMPLES",
        DEFAULT_HTTP_QUERY_SAMPLES,
    );
    let tx_samples = env_usize(
        "IROHA_TORII_LOAD_PROFILE_TX_SAMPLES",
        DEFAULT_HTTP_TX_SAMPLES,
    );
    let commit_samples = env_usize(
        "IROHA_TORII_LOAD_PROFILE_COMMIT_SAMPLES",
        DEFAULT_HTTP_COMMIT_SAMPLES,
    );
    let concurrency = env_usize(
        "IROHA_TORII_LOAD_PROFILE_CONCURRENCY",
        DEFAULT_HTTP_CONCURRENCY,
    );
    let builder = NetworkBuilder::new()
        .with_peers(4)
        .with_config_layer(|layer| {
            layer
                .write("telemetry_profile", "operator")
                .write(["torii", "query_rate_per_authority_per_sec"], 10_000i64)
                .write(["torii", "query_burst_per_authority"], 10_000i64)
                .write(["torii", "tx_rate_per_authority_per_sec"], 10_000i64)
                .write(["torii", "tx_burst_per_authority"], 10_000i64)
                .write(["torii", "preauth_rate_per_ip_per_sec"], 20_000i64)
                .write(["torii", "preauth_burst_per_ip"], 20_000i64)
                .write(["queue", "capacity"], 4_096i64)
                .write(["queue", "capacity_per_user"], 4_096i64);
        });
    let Some(network) =
        sandbox::start_network_async_or_skip(builder, stringify!(torii_http_hot_path_load_profile))
            .await?
    else {
        return Ok(());
    };
    network
        .ensure_blocks_with(|height| height.total >= 1)
        .await?;
    let clients = network
        .peers()
        .iter()
        .map(iroha_test_network::NetworkPeer::client)
        .collect::<Vec<_>>();
    ensure!(
        clients.len() == 4,
        "expected a 4-peer Torii load profile network"
    );
    let query_warmup = HTTP_WARMUP_SAMPLES.min(query_samples);
    warmup_queries(&clients, query_warmup).await?;
    let (query_durations, query_wall_time) =
        run_query_profile(&clients, query_samples, concurrency).await?;
    iroha_torii::profile_stats::print_profile(
        "http",
        "query_find_parameters",
        query_durations,
        query_warmup,
        bounded_concurrency(query_samples, concurrency),
        query_wall_time,
    );
    let network_id = network.network_id();
    let tx_warmup = HTTP_WARMUP_SAMPLES.min(tx_samples);
    warmup_transactions(&clients, network_id, tx_warmup).await?;
    let (tx_durations, tx_wall_time) =
        run_transaction_submit_profile(&clients, network_id, tx_samples, concurrency).await?;
    iroha_torii::profile_stats::print_profile(
        "http",
        "transaction_submit",
        tx_durations,
        tx_warmup,
        bounded_concurrency(tx_samples, concurrency),
        tx_wall_time,
    );
    let event_timeout = network.sync_timeout().max(Duration::from_secs(60));
    let (commit_durations, commit_wall_time) = run_transaction_commit_profile(
        &clients,
        network_id,
        commit_samples,
        concurrency.min(DEFAULT_HTTP_COMMIT_SAMPLES),
        event_timeout,
    )
    .await?;
    iroha_torii::profile_stats::print_profile(
        "http",
        "transaction_submit_to_commit",
        commit_durations,
        0,
        bounded_concurrency(commit_samples, concurrency.min(DEFAULT_HTTP_COMMIT_SAMPLES)),
        commit_wall_time,
    );
    Ok(())
}
