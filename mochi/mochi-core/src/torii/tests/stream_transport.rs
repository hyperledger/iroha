//! Injected canonical SDK connections for Mochi stream fanout tests.

use super::*;
use futures::{Sink, Stream};
use iroha::stream::{StreamConnectFuture, StreamConnection, StreamRequest, StreamTransport};
use std::{
    pin::Pin,
    task::{Context, Poll},
};

pub(super) type FrameSender = tokio::sync::mpsc::UnboundedSender<iroha::Result<StreamFrame>>;

#[derive(Debug)]
pub(super) struct TestStreamTransport {
    receiver: Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<iroha::Result<StreamFrame>>>>,
    sender: FrameSender,
    pub(super) response: http::Response<Vec<u8>>,
}

impl TestStreamTransport {
    pub(super) fn channel() -> (FrameSender, Self) {
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        let response = http::Response::builder()
            .status(101)
            .header(SEC_WEBSOCKET_PROTOCOL, NORITO_V1_WEBSOCKET_SUBPROTOCOL)
            .body(Vec::new())
            .expect("canonical upgrade response");
        (
            sender.clone(),
            Self {
                receiver: Mutex::new(Some(receiver)),
                sender,
                response,
            },
        )
    }
}

struct TestSocket {
    receiver: tokio::sync::mpsc::UnboundedReceiver<iroha::Result<StreamFrame>>,
    // Keep idle scripted connections pending until their subscription is dropped.
    _sender: FrameSender,
    subscription: Vec<u8>,
}

impl Stream for TestSocket {
    type Item = iroha::Result<StreamFrame>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.receiver.poll_recv(cx)
    }
}

impl Sink<Vec<u8>> for TestSocket {
    type Error = iroha::Error;
    fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<iroha::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> iroha::Result<()> {
        assert_eq!(
            item, self.subscription,
            "exact canonical subscription bytes"
        );
        Ok(())
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<iroha::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<iroha::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl StreamTransport for TestStreamTransport {
    fn connect(&self, request: StreamRequest) -> StreamConnectFuture<'_> {
        Box::pin(async move {
            assert_eq!(request.request.method(), http::Method::GET);
            assert_eq!(
                request.request.headers()[SEC_WEBSOCKET_PROTOCOL],
                NORITO_V1_WEBSOCKET_SUBPROTOCOL
            );
            let subscription = match request.request.uri().path() {
                p if p == torii_routes::streaming::BLOCKS_WS.path() => {
                    norito::to_bytes(&BlockSubscriptionRequest::new(NonZeroU64::MIN))
                }
                p if p == torii_routes::streaming::SUBSCRIPTION_WS.path() => {
                    norito::to_bytes(&EventSubscriptionRequest::new(canonical_event_filters()))
                }
                other => panic!("unexpected SDK stream route: {other}"),
            }
            .expect("encode expected subscription");
            Ok(StreamConnection {
                response: self.response.clone(),
                socket: Box::new(TestSocket {
                    receiver: self
                        .receiver
                        .lock()
                        .expect("receiver mutex")
                        .take()
                        .expect("one connection per scripted transport"),
                    _sender: self.sender.clone(),
                    subscription,
                }),
            })
        })
    }
}

pub(super) fn reader_builder(base_url: impl AsRef<str>) -> iroha::client::ClientBuilder {
    iroha::client::Client::builder(iroha::config::Config {
        chain: "mochi-stream-tests".into(),
        network_id: test_network_id(),
        account: ALICE_ID.clone(),
        account_chain_discriminant: iroha_config::parameters::defaults::common::CHAIN_DISCRIMINANT,
        key_pair: ALICE_KEYPAIR.clone(),
        basic_auth: None,
        api_token: None,
        http_transport_policy: iroha::config::HttpTransportPolicy::Ordinary,
        torii_api_url: base_url.as_ref().parse().expect("reader endpoint"),
        torii_request_timeout: iroha::config::DEFAULT_TORII_REQUEST_TIMEOUT,
        transaction_ttl: iroha::config::DEFAULT_TRANSACTION_TIME_TO_LIVE,
        transaction_status_timeout: iroha::config::DEFAULT_TRANSACTION_STATUS_TIMEOUT,
        transaction_add_nonce: iroha::config::DEFAULT_TRANSACTION_NONCE,
        sorafs_alias_cache: iroha::config::AliasCache::default().into_policy(),
        sorafs_anonymity_policy: Default::default(),
        sorafs_rollout_phase: Default::default(),
    })
}

pub(super) fn reader(base_url: impl AsRef<str>) -> AccountClient {
    reader_builder(base_url)
        .build()
        .expect("valid reader context")
        .account_client()
        .expect("explicit Alice authority")
}

pub(super) async fn block_subscription() -> (FrameSender, iroha::client::streams::BlockStream) {
    let (sender, transport) = TestStreamTransport::channel();
    let account = reader_builder("http://127.0.0.1:8080/")
        .stream_transport(Arc::new(transport))
        .build()
        .expect("injected reader")
        .account_client()
        .expect("explicit Alice authority");
    let stream = account
        .blocks()
        .subscribe(NonZeroU64::MIN)
        .await
        .expect("injected block subscription");
    (sender, stream)
}

pub(super) async fn event_subscription() -> (FrameSender, iroha::client::streams::EventStream) {
    let (sender, transport) = TestStreamTransport::channel();
    let account = reader_builder("http://127.0.0.1:8080/")
        .stream_transport(Arc::new(transport))
        .build()
        .expect("injected reader")
        .account_client()
        .expect("explicit Alice authority");
    let stream = account
        .events()
        .subscribe(canonical_event_filters())
        .await
        .expect("injected event subscription");
    (sender, stream)
}

pub(super) fn normal_close() -> iroha::Result<StreamFrame> {
    Ok(StreamFrame::Close {
        code: Some(1000),
        reason: String::new(),
    })
}

#[test]
fn reader_configuration_and_torii_binding_are_explicit() {
    let endpoint = "http://127.0.0.1:8080/";
    let account = reader(endpoint);
    assert_eq!(account.authority(), &*ALICE_ID);
    assert_eq!(account.network_id(), &test_network_id());
    assert_eq!(account.endpoint().as_str(), endpoint);
    let client = ToriiClient::new_for_network(endpoint, test_network_id()).expect("network client");
    client
        .validate_stream_reader(&account)
        .expect("same exact context");
    let other_endpoint = reader("http://127.0.0.1:8081/");
    assert!(matches!(
        client.validate_stream_reader(&other_endpoint),
        Err(ToriiError::SignedQueryContext(_))
    ));
    let mut builder = reader_builder(endpoint);
    builder.network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"another Mochi generation",
    )));
    let other_network = builder.build().unwrap().account_client().unwrap();
    assert!(matches!(
        client.validate_stream_reader(&other_network),
        Err(ToriiError::SignedQueryContext(_))
    ));
    let unbound = ToriiClient::new(endpoint).expect("unbound client");
    assert!(matches!(
        unbound.validate_stream_reader(&account),
        Err(ToriiError::SignedQueryContext(_))
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn completed_fanout_retains_first_binary_and_normal_close() {
    let (sender, subscription) = block_subscription().await;
    let stream = BlockStream::new(subscription);
    let block = sample_block();
    let bytes = block_stream_frame(&block);
    let actual = bytes.len();
    sender.send(Ok(StreamFrame::Binary(bytes))).unwrap();
    sender.send(normal_close()).unwrap();
    timeout(Duration::from_secs(2), async {
        while !stream.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("block fanout finished before first subscriber");
    let mut receiver = stream.subscribe();
    match receiver.recv().await.unwrap() {
        BlockStreamEvent::Block {
            block: received,
            raw_len,
            ..
        } => {
            assert_eq!(received.as_ref(), &block);
            assert_eq!(raw_len, actual);
        }
        other => panic!("expected retained first block, got {other:?}"),
    }
    assert!(matches!(
        receiver.recv().await.unwrap(),
        BlockStreamEvent::Closed
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn event_fanout_retains_bounded_history_and_reports_exact_lag() {
    let (sender, subscription) = event_subscription().await;
    let stream = EventStream::new(subscription);
    for _ in 0..129 {
        sender
            .send(Ok(StreamFrame::Binary(EVENT_MESSAGE_FIXTURE.to_vec())))
            .unwrap();
    }
    sender.send(normal_close()).unwrap();
    timeout(Duration::from_secs(2), async {
        while !stream.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("event fanout finished before first subscriber");
    let mut receiver = stream.subscribe();
    assert!(matches!(receiver.recv().await, Err(RecvError::Lagged(2))));
    let expected: EventBox = time_event_fixture_message().into();
    for _ in 0..127 {
        match receiver.recv().await.unwrap() {
            EventStreamEvent::Event { event, raw_len, .. } => {
                assert_eq!(event.as_ref(), &expected);
                assert_eq!(raw_len, EVENT_MESSAGE_FIXTURE.len());
            }
            other => panic!("expected retained event, got {other:?}"),
        }
    }
    assert!(matches!(
        receiver.recv().await.unwrap(),
        EventStreamEvent::Closed
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn cancelling_pending_fanouts_drops_their_owned_sdk_connections() {
    let (block_sender, subscription) = block_subscription().await;
    let block = BlockStream::new(subscription);
    tokio::task::yield_now().await;
    block.abort();
    timeout(Duration::from_secs(1), block_sender.closed())
        .await
        .expect("block receiver released");
    assert!(block.is_finished());
    let (event_sender, subscription) = event_subscription().await;
    let event = EventStream::new(subscription);
    tokio::task::yield_now().await;
    event.abort();
    timeout(Duration::from_secs(1), event_sender.closed())
        .await
        .expect("event receiver released");
    assert!(event.is_finished());
}

#[tokio::test(flavor = "current_thread")]
async fn managed_stream_cancellation_drops_pending_connection_attempt() {
    struct Dropped(Option<tokio::sync::oneshot::Sender<()>>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }
    let started = Arc::new(Notify::new());
    let (dropped, released) = tokio::sync::oneshot::channel();
    let dropped = Arc::new(Mutex::new(Some(dropped)));
    let stream = ManagedBlockStream::spawn_with_factory(
        &tokio::runtime::Handle::current(),
        "pending-reader",
        {
            let started = Arc::clone(&started);
            move || {
                let started = Arc::clone(&started);
                let dropped = Arc::clone(&dropped);
                async move {
                    let _guard = Dropped(dropped.lock().expect("drop signal").take());
                    started.notify_one();
                    std::future::pending::<ToriiResult<iroha::client::streams::BlockStream>>().await
                }
            }
        },
    );
    timeout(Duration::from_secs(1), started.notified())
        .await
        .expect("factory polled");
    stream.abort();
    timeout(Duration::from_secs(1), released)
        .await
        .expect("factory released")
        .expect("factory drop acknowledged");
    assert!(stream.is_finished());
}

#[tokio::test(flavor = "current_thread")]
async fn transport_protocol_error_has_no_invented_binary_length() {
    let (sender, subscription) = event_subscription().await;
    let stream = EventStream::new(subscription);
    let mut receiver = stream.subscribe();
    let error = iroha::Error::StreamProtocol {
        operation: "events.stream_websocket",
        details: "Torii streams require binary messages".to_owned(),
    };
    sender.send(Err(error)).unwrap();
    match timeout(Duration::from_secs(1), receiver.recv())
        .await
        .unwrap()
        .unwrap()
    {
        EventStreamEvent::DecodeError { error: failure } => {
            assert_eq!(failure.stage, EventDecodeStage::Stream);
            assert_eq!(failure.raw_len, None);
            assert!(matches!(
                failure.source.as_deref(),
                Some(iroha::Error::StreamProtocol { operation, details })
                    if *operation == "events.stream_websocket"
                        && details == "Torii streams require binary messages"
            ));
        }
        other => panic!("expected structured protocol failure, got {other:?}"),
    }
    timeout(Duration::from_secs(1), sender.closed())
        .await
        .expect("terminal error releases socket");
    assert!(stream.is_finished());
}

#[tokio::test(flavor = "current_thread")]
async fn readiness_falls_back_only_for_throttled_upgrades_and_submits_exact_bytes() {
    #[derive(Debug)]
    struct RejectedUpgrade {
        status: u16,
        requests: Mutex<Vec<String>>,
    }
    impl StreamTransport for RejectedUpgrade {
        fn connect(&self, request: StreamRequest) -> StreamConnectFuture<'_> {
            Box::pin(async move {
                self.requests
                    .lock()
                    .expect("upgrade requests")
                    .push(request.request.uri().path().to_owned());
                let (_sender, mut transport) = TestStreamTransport::channel();
                transport.response = http::Response::builder()
                    .status(self.status)
                    .header(http::header::RETRY_AFTER, "3")
                    .body(b"upgrade unavailable".to_vec())
                    .expect("upgrade failure response");
                transport.connect(request).await
            })
        }
    }
    for status in [429, 401, 403, 503] {
        let Some(server) = try_start_mock_server() else {
            return;
        };
        let signer = &crate::compose::development_signing_authorities()[0];
        let plan = ReadinessSmokePlan::for_signer_with_attempts(test_network_id(), signer, 1)
            .expect("exact network smoke transaction");
        let transaction = &plan.transactions[0];
        transaction
            .verify_signature()
            .expect("valid signed smoke fixture");
        let signed_bytes = transaction.encode_versioned();
        let tx_hash = transaction.hash();
        let hash = encode_lower_hex(tx_hash.as_ref());
        let expected_bytes = signed_bytes.clone();
        let post = server.mock(move |when, then| {
            let when = when
                .method(POST)
                .path(torii_routes::pipeline::TRANSACTION.path());
            if status == 429 {
                when.header("content-type", NORITO_MIME_TYPE)
                    .is_true(move |request| request.body_ref() == expected_bytes.as_slice());
            }
            then.status(202);
        });
        let applied = norito::json!({
            "hash": (hash.clone()),
            "status": { "kind": "Applied", "block_height": 7 },
            "scope": "global",
            "resolved_from": "state"
        });
        let status_query = server.mock(|when, then| {
            when.method(GET)
                .path("/v1/pipeline/transactions/status")
                .query_param("hash", hash.as_str())
                .query_param("scope", "global");
            then.status(200)
                .body(norito::json::to_string(&applied).expect("Applied status"));
        });
        let transport = Arc::new(RejectedUpgrade {
            status,
            requests: Mutex::default(),
        });
        let account = reader_builder(server.url("/"))
            .stream_transport(transport.clone())
            .build()
            .expect("injected reader")
            .account_client()
            .expect("explicit reader authority");
        let client = ToriiClient::new_for_network(server.url("/"), test_network_id()).unwrap();
        let result = timeout(
            Duration::from_secs(2),
            client.submit_and_wait_for_commit(
                &account,
                transaction,
                SmokeCommitOptions::new(Duration::from_secs(1)),
            ),
        )
        .await
        .expect("bounded readiness operation");
        if status == 429 {
            let committed = result.expect("throttled streams permit exact HTTP reconciliation");
            assert_eq!(committed.tx_hash, tx_hash);
            assert_eq!(committed.block_height, 7);
            post.assert_calls(1);
            status_query.assert_calls(1);
            assert_eq!(
                *transport.requests.lock().unwrap(),
                [
                    torii_routes::streaming::BLOCKS_WS.path(),
                    torii_routes::streaming::SUBSCRIPTION_WS.path()
                ]
            );
        } else {
            assert!(matches!(result, Err(ToriiError::Sdk(error))
                if matches!(error.as_ref(), iroha::Error::Http {
                    status: actual, retry_after: Some(delay), body, ..
                } if *actual == status && *delay == Duration::from_secs(3) && body == b"upgrade unavailable")));
            post.assert_calls(0);
            status_query.assert_calls(0);
            assert_eq!(
                *transport.requests.lock().unwrap(),
                [torii_routes::streaming::BLOCKS_WS.path()]
            );
        }
        assert_eq!(transaction.hash(), tx_hash);
        assert_eq!(transaction.encode_versioned(), signed_bytes);
    }
}
