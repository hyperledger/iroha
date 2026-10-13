//! Readiness smoke tests against the in-process mock Torii service.
use color_eyre::Result;
use iroha_data_model::{
    NetworkId,
    block::stream::BlockMessage,
    events::{
        EventBox,
        pipeline::{PipelineEventBox, TransactionEvent, TransactionStatus},
        stream::EventMessage,
    },
};
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
use mochi_core::{
    BlockStreamEvent, EventCategory, EventStreamEvent, ManagedBlockStream, ManagedEventStream,
    OperatorSigningContext, ReadinessOptions, ReadinessSmokePlan, SmokeCommitOptions, ToriiClient,
    ToriiError, development_signing_authorities,
};
use mochi_integration::{MockToriiBuilder, MockToriiData, MockToriiFrame};
use norito::json::Value;
use std::{
    net::{SocketAddr, TcpListener},
    num::NonZeroU64,
    path::PathBuf,
    time::Duration,
};
use tokio::time::{sleep, timeout};
fn test_network_id() -> NetworkId {
    "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0"
        .parse()
        .expect("test network id")
}
fn stream_reader(addr: SocketAddr) -> iroha::client::AccountClient {
    stream_reader_for_network(addr, test_network_id())
}
fn observer_client(addr: SocketAddr) -> Result<ToriiClient> {
    let network_id = test_network_id();
    let operator = iroha_crypto::KeyPair::from_seed(
        b"mochi-readiness-http-operator".to_vec(),
        iroha_crypto::Algorithm::Ed25519,
    );
    Ok(ToriiClient::builder(format!("http://{addr}"))?
        .with_network_id(network_id)
        .with_operator_signing_context(OperatorSigningContext::new(network_id, operator))
        .build()?)
}
fn stream_reader_for_network(
    addr: SocketAddr,
    network_id: NetworkId,
) -> iroha::client::AccountClient {
    let signer = &development_signing_authorities()[0];
    iroha::client::Client::builder(iroha::config::Config {
        chain: "mochi-local".into(),
        network_id,
        account: signer.account_id().clone(),
        key_pair: signer.key_pair().clone(),
        account_chain_discriminant: iroha_torii_shared::MINAMOTO_CHAIN_DISCRIMINANT,
        basic_auth: None,
        api_token: None,
        http_transport_policy: iroha::config::HttpTransportPolicy::Ordinary,
        torii_api_url: format!("http://{addr}/").parse().unwrap(),
        torii_request_timeout: Duration::from_secs(5),
        transaction_ttl: iroha::config::DEFAULT_TRANSACTION_TIME_TO_LIVE,
        transaction_status_timeout: iroha::config::DEFAULT_TRANSACTION_STATUS_TIMEOUT,
        transaction_add_nonce: iroha::config::DEFAULT_TRANSACTION_NONCE,
        sorafs_alias_cache: iroha::config::AliasCache::default().into_policy(),
        sorafs_anonymity_policy: Default::default(),
        sorafs_rollout_phase: Default::default(),
    })
    .build()
    .unwrap()
    .account_client()
    .unwrap()
}
fn reserve_port() -> std::io::Result<u16> {
    TcpListener::bind(("127.0.0.1", 0))
        .and_then(|listener| listener.local_addr())
        .map(|addr| addr.port())
}
#[tokio::test(flavor = "multi_thread")]
async fn readiness_smoke_succeeds_on_pipeline_event() -> Result<()> {
    let port = match reserve_port() {
        Ok(port) => port,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping readiness_smoke_succeeds_on_pipeline_event: {err}");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let reader = stream_reader(addr);
    let mock = MockToriiBuilder::new(addr)
        .stream_reader(&reader)
        .block_frame(Vec::new())
        .event_frame(Vec::new())
        .spawn()
        .await?;
    let network_id = test_network_id();
    let client = ToriiClient::new_for_network(format!("http://{}", mock.addr()), network_id)?;
    let signer = &development_signing_authorities()[0];
    let mut plan = ReadinessSmokePlan::for_signer_with_attempts(network_id, signer, 1)?;
    plan.commit_options = SmokeCommitOptions::new(Duration::from_millis(800));
    plan.status_options = ReadinessOptions::new(Duration::from_millis(500))
        .with_poll_interval(Duration::from_millis(50));
    plan.backoff = Duration::from_millis(50);
    let tx_hash = plan.tx_hashes().next().expect("hash present");
    let event = EventMessage::new(EventBox::Pipeline(PipelineEventBox::Transaction(
        TransactionEvent {
            hash: tx_hash,
            block_height: Some(NonZeroU64::new(7).expect("non-zero height")),
            lane_id: LaneId::new(0),
            dataspace_id: DataSpaceId::new(0),
            status: TransactionStatus::Approved,
        },
    )));
    let event_bytes = norito::to_bytes(&event)?;
    let readiness = client.wait_for_readiness_smoke(&reader, plan);
    let sender = async {
        sleep(Duration::from_millis(50)).await;
        mock.broadcast_event(MockToriiFrame::Binary(event_bytes));
    };
    let (outcome, _) = tokio::join!(readiness, sender);
    let outcome = outcome.expect("smoke readiness should succeed");
    assert_eq!(outcome.attempt, 1);
    assert_eq!(outcome.commit.block_height, 7);
    assert_eq!(outcome.commit.tx_hash, tx_hash);
    mock.shutdown().await?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread")]
async fn readiness_smoke_times_out_without_commit() -> Result<()> {
    let port = match reserve_port() {
        Ok(port) => port,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping readiness_smoke_times_out_without_commit: {err}");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let reader = stream_reader(addr);
    let mock = MockToriiBuilder::new(addr)
        .stream_reader(&reader)
        .block_frame(Vec::new())
        .event_frame(Vec::new())
        .spawn()
        .await?;
    let network_id = test_network_id();
    let client = ToriiClient::new_for_network(format!("http://{}", mock.addr()), network_id)?;
    let signer = &development_signing_authorities()[0];
    let mut plan = ReadinessSmokePlan::for_signer_with_attempts(network_id, signer, 1)?;
    plan.commit_options = SmokeCommitOptions::new(Duration::from_millis(150));
    plan.status_options = ReadinessOptions::new(Duration::from_millis(200))
        .with_poll_interval(Duration::from_millis(30));
    let outcome = client.wait_for_readiness_smoke(&reader, plan).await;
    match outcome {
        Err(ToriiError::Timeout { .. }) => {}
        other => panic!("expected timeout error, got {other:?}"),
    }
    mock.shutdown().await?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread")]
async fn readiness_smoke_surfaces_stream_decode_errors() -> Result<()> {
    let port = match reserve_port() {
        Ok(port) => port,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping readiness_smoke_surfaces_stream_decode_errors: {err}");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let reader = stream_reader(addr);
    let mock = MockToriiBuilder::new(addr)
        .stream_reader(&reader)
        .block_frame(vec![0xFF])
        .event_frame(Vec::new())
        .spawn()
        .await?;
    let network_id = test_network_id();
    let client = ToriiClient::new_for_network(format!("http://{}", mock.addr()), network_id)?;
    let signer = &development_signing_authorities()[0];
    let mut plan = ReadinessSmokePlan::for_signer_with_attempts(network_id, signer, 1)?;
    plan.commit_options = SmokeCommitOptions::new(Duration::from_millis(300));
    plan.status_options = ReadinessOptions::new(Duration::from_millis(200))
        .with_poll_interval(Duration::from_millis(30));
    let outcome = client.wait_for_readiness_smoke(&reader, plan).await;
    match outcome {
        Err(ToriiError::Sdk(error)) if matches!(error.as_ref(), iroha::Error::Decode { .. }) => {}
        other => panic!("expected decode error, got {other:?}"),
    }
    mock.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn streams_reject_another_network_and_an_ungranted_reader() -> Result<()> {
    let expected = stream_reader(SocketAddr::from(([127, 0, 0, 1], 0)));
    let mock = MockToriiBuilder::new(SocketAddr::from(([127, 0, 0, 1], 0)))
        .stream_reader(&expected)
        .spawn()
        .await?;
    let foreign_network = NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(b"another-genesis")),
    );
    let foreign = stream_reader_for_network(mock.addr(), foreign_network);
    let result = foreign.blocks().subscribe(NonZeroU64::MIN).await;
    assert!(matches!(
        result,
        Err(iroha::Error::Http { status: 401, .. })
    ));
    assert_eq!(mock.authenticated_stream_count(), 0);
    mock.shutdown().await?;

    let ungranted = MockToriiBuilder::new(SocketAddr::from(([127, 0, 0, 1], 0)))
        .spawn()
        .await?;
    let reader = stream_reader(ungranted.addr());
    let result = reader.blocks().subscribe(NonZeroU64::MIN).await;
    assert!(matches!(
        result,
        Err(iroha::Error::Http { status: 403, .. })
    ));
    assert_eq!(ungranted.authenticated_stream_count(), 0);
    ungranted.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn observer_reads_http_endpoints() -> Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let reader = stream_reader(addr);
    let data = MockToriiData::default();
    let mock = MockToriiBuilder::new(addr)
        .stream_reader(&reader)
        .spawn()
        .await?;
    let unsigned =
        ToriiClient::new_for_network(format!("http://{}", mock.addr()), test_network_id())?;
    assert!(matches!(
        unsigned.fetch_sumeragi_status().await,
        Err(ToriiError::SignedQueryContext(_))
    ));
    let client = observer_client(mock.addr())?;
    let status = client.fetch_status().await?;
    assert_eq!(status.peers, data.status.peers);
    let snapshot = client.fetch_status_snapshot().await?;
    assert_eq!(snapshot.status.blocks, data.status.blocks);
    let sumeragi = client.fetch_sumeragi_status().await?;
    assert_eq!(sumeragi.leader, data.sumeragi.leader);
    let diagnostics = client.fetch_sumeragi_diagnostics().await?;
    assert_eq!(diagnostics, data.sumeragi_diagnostics);
    let config = client.fetch_configuration().await?;
    assert_eq!(config, data.configuration);
    let metrics = client.fetch_metrics().await?;
    assert_eq!(metrics, data.metrics);
    let query = client.submit_query(&[0xCA, 0xFE]).await?;
    assert_eq!(query, data.query_response);
    mock.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn observer_streams_receive_authenticated_binary_frames() -> Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let reader = stream_reader(addr);
    let data = MockToriiData::default();
    let mock = MockToriiBuilder::new(addr)
        .stream_reader(&reader)
        .spawn()
        .await?;
    let reader = stream_reader(mock.addr());
    let handle = tokio::runtime::Handle::current();
    let block_stream = ManagedBlockStream::spawn(&handle, "peer0".into(), reader.clone());
    let mut block_rx = block_stream.subscribe();
    let event_stream = ManagedEventStream::spawn(&handle, "peer0".into(), reader);
    let mut event_rx = event_stream.subscribe();
    let block_event = timeout(Duration::from_secs(1), block_rx.recv())
        .await
        .expect("block event timeout")?
        .clone();
    match block_event {
        BlockStreamEvent::Block { raw_len, .. } => {
            assert_eq!(raw_len, data.block_frame.len());
        }
        other => panic!("unexpected block stream event: {other:?}"),
    }
    let event = timeout(Duration::from_secs(1), event_rx.recv())
        .await
        .expect("event stream timeout")?
        .clone();
    match event {
        EventStreamEvent::Event { raw_len, .. } => {
            assert_eq!(raw_len, data.event_frame.len());
        }
        other => panic!("unexpected event stream event: {other:?}"),
    }
    assert_eq!(mock.authenticated_stream_count(), 2);
    block_stream.abort();
    event_stream.abort();
    mock.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn observer_replays_exact_torii_fixture_streams() -> Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let reader = stream_reader(addr);
    let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/torii_replay");
    let mock = MockToriiBuilder::new(addr)
        .stream_reader(&reader)
        .fixture_dir(&fixture_dir)?
        .spawn()
        .await?;
    let client = observer_client(mock.addr())?;
    let status = client.fetch_status().await?;
    assert_eq!(status.blocks, 5);
    assert!(status.crypto.sm_helpers_available);
    assert_eq!(status.queue_size, 4);
    assert_eq!(status.governance.manifest_quorum.total_checks, 0);
    assert_eq!(status.governance.manifest_admission.total_checks, 0);
    let sumeragi = client.fetch_sumeragi_status().await?;
    assert_eq!(sumeragi.height, 10);
    assert_eq!(sumeragi.view, 4);
    assert_eq!(sumeragi.committed_height, 9);
    let diagnostics = client.fetch_sumeragi_diagnostics().await?;
    assert_eq!(diagnostics.tx_queue_depth, 4);
    assert_eq!(diagnostics.tx_queue_capacity, 1024);
    let configuration = client.fetch_configuration().await?;
    assert_eq!(
        configuration
            .get("torii")
            .and_then(|v| v.get("address"))
            .and_then(Value::as_str),
        Some("127.0.0.1:5555")
    );
    let metrics = client.fetch_metrics().await?;
    assert!(
        metrics.contains("iroha_blocks_total"),
        "metrics fixture should surface canonical counter"
    );
    let query = client.submit_query(&[0xCA, 0xFE]).await?;
    assert_eq!(query, vec![0x13, 0x37]);
    let stream_data = MockToriiData::from_fixture_dir(&fixture_dir)?;
    let expected_block: BlockMessage = norito::decode_from_bytes(&stream_data.block_frame)?;
    let expected_event: EventBox = norito::decode_from_bytes::<
        iroha_data_model::events::stream::EventMessage,
    >(&stream_data.event_frame)?
    .into();
    let reader = stream_reader(mock.addr());
    let handle = tokio::runtime::Handle::current();
    let block_stream = ManagedBlockStream::spawn(&handle, "peer0".into(), reader.clone());
    let mut block_rx = block_stream.subscribe();
    let event_stream = ManagedEventStream::spawn(&handle, "peer0".into(), reader);
    let mut event_rx = event_stream.subscribe();
    let block_event = timeout(Duration::from_secs(1), block_rx.recv())
        .await
        .expect("block event timeout")?
        .clone();
    match block_event {
        BlockStreamEvent::Block {
            summary,
            block,
            raw_len,
        } => {
            assert_eq!(raw_len, stream_data.block_frame.len());
            assert_eq!(block.as_ref(), &expected_block.0);
            assert_eq!(summary.hash_hex, block.hash().to_string());
            assert_eq!(summary.height, block.header().height().get());
            assert_eq!(summary.transaction_count, block.external_entrypoint_count());
        }
        other => panic!("unexpected block stream event: {other:?}"),
    }
    let event = timeout(Duration::from_secs(1), event_rx.recv())
        .await
        .expect("event stream timeout")?
        .clone();
    match event {
        EventStreamEvent::Event {
            summary,
            event,
            raw_len,
        } => {
            assert_eq!(raw_len, stream_data.event_frame.len());
            assert_eq!(summary.category, EventCategory::Pipeline);
            assert_eq!(event.as_ref(), &expected_event);
        }
        other => panic!("unexpected event stream event: {other:?}"),
    }
    assert_eq!(mock.authenticated_stream_count(), 2);
    block_stream.abort();
    event_stream.abort();
    mock.shutdown().await?;
    Ok(())
}
