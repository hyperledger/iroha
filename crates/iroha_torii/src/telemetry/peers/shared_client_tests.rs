//! Real HTTP monitor ownership and joined blocking initialization controls.

use super::*;
use std::{
    collections::BTreeSet,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Clone)]
struct ObservedRequest {
    path: String,
    headers: BTreeMap<String, String>,
}

struct RecordingPeer {
    url: ToriiUrl,
    requests: Arc<Mutex<Vec<ObservedRequest>>>,
    shutdown: ShutdownSignal,
    worker: Option<JoinHandle<()>>,
}

impl RecordingPeer {
    async fn new(config: Vec<u8>, reject_first_config: bool, stall_first_status: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        let shutdown = ShutdownSignal::new();
        let stop = shutdown.clone();
        let worker = tokio::spawn(async move {
            let config = Arc::new(config);
            let mut status = iroha_torii_shared::status::Status::default();
            status.blocks = 2;
            status.peers = 3;
            let status = Arc::new(norito::json::to_vec(&status).unwrap());
            let config_count = Arc::new(AtomicUsize::new(0));
            let status_count = Arc::new(AtomicUsize::new(0));
            let mut connections = JoinSet::new();
            loop {
                let accepted = tokio::select! {
                    biased;
                    () = stop.receive() => break,
                    result = listener.accept() => result.unwrap(),
                };
                let mut socket = accepted.0;
                let recorded = Arc::clone(&recorded);
                let config = Arc::clone(&config);
                let status = Arc::clone(&status);
                let config_count = Arc::clone(&config_count);
                let status_count = Arc::clone(&status_count);
                let stop = stop.clone();
                connections.spawn(async move {
                    let mut head = Vec::new();
                    loop {
                        let mut byte = [0];
                        let read = tokio::select! {
                            biased;
                            () = stop.receive() => return,
                            result = socket.read(&mut byte) => result.unwrap(),
                        };
                        // A request can be cancelled before its headers reach the fixture.
                        // Only complete requests are recorded below.
                        if read == 0 {
                            return;
                        }
                        head.push(byte[0]);
                        assert!(head.len() <= 16 * 1024, "bounded fixture request headers");
                        if head.ends_with(b"\r\n\r\n") {
                            break;
                        }
                    }
                    let head = String::from_utf8(head).unwrap();
                    let mut lines = head.split("\r\n");
                    let first = lines.next().unwrap();
                    let mut words = first.split_whitespace();
                    assert_eq!(words.next(), Some("GET"));
                    let path = words.next().unwrap().to_owned();
                    let headers = lines
                        .filter(|line| !line.is_empty())
                        .map(|line| {
                            let (name, value) = line.split_once(':').unwrap();
                            (name.to_ascii_lowercase(), value.trim().to_owned())
                        })
                        .collect();
                    {
                        let mut recorded = recorded.lock().unwrap();
                        assert!(recorded.len() < 512, "bounded fixture request count");
                        recorded.push(ObservedRequest {
                            path: path.clone(),
                            headers,
                        });
                    }
                    let (code, body): (&str, &[u8]) = match path.as_str() {
                        "/v1/configuration" => {
                            let count = config_count.fetch_add(1, Ordering::SeqCst);
                            if reject_first_config && count == 0 {
                                ("403 Forbidden", b"not a configuration")
                            } else {
                                ("200 OK", &config)
                            }
                        }
                        "/v1/peers" => ("200 OK", b"[]"),
                        "/status" => {
                            let count = status_count.fetch_add(1, Ordering::SeqCst);
                            if stall_first_status && count == 0 {
                                tokio::select! {
                                    biased;
                                    () = stop.receive() => return,
                                    () = tokio::time::sleep(Duration::from_secs(1)) => {},
                                }
                                // This is the deliberately abandoned request which forces the
                                // real status timeout/reconnect. It sends no late response.
                                return;
                            }
                            ("200 OK", &status)
                        }
                        _ => panic!("unexpected monitor fixture route"),
                    };
                    let response = format!(
                        "HTTP/1.1 {code}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nSet-Cookie: fixture=must-not-be-retained\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    // The real monitor may cancel an in-flight request during shutdown.
                    if socket.write_all(response.as_bytes()).await.is_ok() {
                        let _ = socket.write_all(body).await;
                    }
                });
            }
            while let Some(result) = connections.join_next().await {
                result.unwrap();
            }
        });
        Self {
            url,
            requests,
            shutdown,
            worker: Some(worker),
        }
    }

    fn count(&self, path: &str) -> usize {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request.path == path)
            .count()
    }

    async fn finish(mut self) -> Vec<ObservedRequest> {
        self.shutdown.send();
        self.worker.take().unwrap().await.unwrap();
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for RecordingPeer {
    fn drop(&mut self) {
        self.shutdown.send();
    }
}

#[tokio::test]
async fn monitor_start_shares_one_client_across_urls_config_retry_and_status_reconnect() {
    let cfg = crate::test_utils::mk_minimal_root_cfg();
    let configuration = norito::json::to_vec(&Configuration::from(&cfg)).unwrap();
    let first = RecordingPeer::new(configuration.clone(), true, true).await;
    let second = RecordingPeer::new(configuration, false, false).await;
    let service = PeerTelemetryService::new(
        vec![first.url.clone(), second.url.clone(), first.url.clone()],
        GeoLookupConfig::disabled(),
        crate::signed_query_test_network_id(),
        Some(cfg.common.key_pair.clone()),
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let builds = Arc::clone(&calls);
    let shutdown = ShutdownSignal::new();
    let worker = service
        .start_with_http_factory(shutdown.clone(), move || {
            builds.fetch_add(1, Ordering::SeqCst);
            monitor::peer_monitor_http_client()
        })
        .unwrap();
    let observed = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if first.count("/v1/configuration") >= 3
                && first.count("/status") >= 2
                && first.count("/v1/peers") >= 1
                && second.count("/status") >= 2
                && second.count("/v1/peers") >= 1
            {
                let snapshot = service.snapshot().await;
                if snapshot.peers_info.len() == 2
                    && snapshot.peers_info.iter().all(|peer| peer.connected)
                    && snapshot.peers_status.len() == 2
                    && snapshot.peers_status.iter().all(|peer| peer.block == 2)
                {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .is_ok();
    shutdown.send();
    let exit = worker.await.unwrap();
    let first = first.finish().await;
    let second = second.finish().await;
    assert!(
        observed,
        "actual configuration retry and status reconnect must complete"
    );
    assert_eq!(exit, crate::ToriiCriticalWorkerExit::StoppedByShutdown);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(Arc::strong_count(&service), 1);

    let mut nonces = BTreeSet::new();
    let mut signatures = BTreeSet::new();
    for request in first.iter().chain(&second) {
        assert_eq!(
            request.headers.get("accept").map(String::as_str),
            Some("application/json")
        );
        assert!(!request.headers.contains_key("authorization"));
        assert!(!request.headers.contains_key("x-api-token"));
        assert!(!request.headers.contains_key("cookie"));
        if request.path == "/status" {
            for header in [
                "x-iroha-operator-public-key",
                "x-iroha-operator-timestamp-ms",
                "x-iroha-operator-nonce",
                "x-iroha-operator-signature",
            ] {
                assert!(!request.headers.contains_key(header));
            }
        } else {
            assert_eq!(
                request.headers.get("x-iroha-operator-public-key"),
                Some(&cfg.common.key_pair.public_key().to_string())
            );
            assert!(
                signatures.insert(request.headers["x-iroha-operator-signature"].clone()),
                "the shared pool must not replay a signed header set"
            );
            assert!(
                request
                    .headers
                    .contains_key("x-iroha-operator-timestamp-ms")
            );
            let nonce = request.headers.get("x-iroha-operator-nonce").unwrap();
            assert!(
                nonces.insert(nonce.clone()),
                "each real request signs a fresh nonce"
            );
        }
    }
}

#[tokio::test]
async fn monitor_shutdown_joins_blocked_initialization_without_http_or_worker_launch() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let service = PeerTelemetryService::new(
        vec![
            format!("http://{}", listener.local_addr().unwrap())
                .parse()
                .unwrap(),
        ],
        GeoLookupConfig::disabled(),
        crate::signed_query_test_network_id(),
        None,
    );
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let completed = Arc::new(AtomicBool::new(false));
    let finished = Arc::clone(&completed);
    let mut entered_tx = Some(entered_tx);
    let shutdown = ShutdownSignal::new();
    let worker = service
        .start_with_http_factory(shutdown.clone(), move || {
            entered_tx.take().unwrap().send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            let result = monitor::peer_monitor_http_client();
            finished.store(true, Ordering::SeqCst);
            result
        })
        .unwrap();
    // This current-thread Tokio executor can receive the entry while native construction is
    // held on a separate blocking worker; synchronous construction would prevent that progress.
    tokio::time::timeout(Duration::from_secs(2), entered_rx)
        .await
        .unwrap()
        .unwrap();
    shutdown.send();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let returned_before_join = worker.is_finished();
    release_tx.send(()).unwrap();
    let exit = worker.await.unwrap();
    assert!(
        !returned_before_join,
        "shutdown must retain the in-flight builder join"
    );
    assert!(completed.load(Ordering::SeqCst));
    assert_eq!(exit, crate::ToriiCriticalWorkerExit::StoppedByShutdown);
    assert_eq!(Arc::strong_count(&service), 1);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn monitor_initialization_preserves_build_backoff_and_empty_urls_do_not_initialize() {
    let empty = PeerTelemetryService::new(
        vec![],
        GeoLookupConfig::disabled(),
        crate::signed_query_test_network_id(),
        None,
    );
    assert!(
        empty
            .start_with_http_factory(ShutdownSignal::new(), || {
                panic!("empty peer URLs must not construct a transport")
            })
            .is_none()
    );

    let calls = Arc::new(AtomicUsize::new(0));
    let builds = Arc::clone(&calls);
    let started = std::time::Instant::now();
    let initialized = monitor::initialize_http_client(&ShutdownSignal::new(), move || {
        if builds.fetch_add(1, Ordering::SeqCst) == 0 {
            reqwest::Client::builder()
                .user_agent("invalid\nheader")
                .build()
        } else {
            monitor::peer_monitor_http_client()
        }
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(started.elapsed() >= Duration::from_secs(15));
    assert_eq!(initialized.1, Duration::from_secs_f64(15.0 * 1.67));
}

#[tokio::test]
async fn monitor_initialization_cancels_retry_without_rebuilding_or_dispatch() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let service = PeerTelemetryService::new(
        vec![
            format!("http://{}", listener.local_addr().unwrap())
                .parse()
                .unwrap(),
        ],
        GeoLookupConfig::disabled(),
        crate::signed_query_test_network_id(),
        None,
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let attempts = Arc::clone(&calls);
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let mut entered_tx = Some(entered_tx);
    let shutdown = ShutdownSignal::new();
    let worker = service
        .start_with_http_factory(shutdown.clone(), move || {
            attempts.fetch_add(1, Ordering::SeqCst);
            entered_tx.take().unwrap().send(()).unwrap();
            reqwest::Client::builder()
                .user_agent("invalid\nheader")
                .build()
        })
        .unwrap();
    entered_rx.await.unwrap();
    // Let the construction result reach the service and enter the ordinary 15-second wait.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!worker.is_finished());
    shutdown.send();
    let exit = tokio::time::timeout(Duration::from_secs(2), worker)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(exit, crate::ToriiCriticalWorkerExit::StoppedByShutdown);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(Arc::strong_count(&service), 1);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn monitor_initialization_preserves_factory_panic_after_shutdown() {
    let service = PeerTelemetryService::new(
        vec!["http://127.0.0.1:9".parse().unwrap()],
        GeoLookupConfig::disabled(),
        crate::signed_query_test_network_id(),
        None,
    );
    let shutdown = ShutdownSignal::new();
    let worker_shutdown = shutdown.clone();
    let worker = service
        .start_with_http_factory(shutdown, move || {
            worker_shutdown.send();
            panic!("injected peer telemetry transport initialization panic");
        })
        .unwrap();
    assert_eq!(
        worker.await.unwrap(),
        crate::ToriiCriticalWorkerExit::UnexpectedExit
    );
    assert_eq!(Arc::strong_count(&service), 1);
}

#[tokio::test]
async fn monitor_already_stopped_start_does_not_initialize() {
    let service = PeerTelemetryService::new(
        vec!["http://127.0.0.1:9".parse().unwrap()],
        GeoLookupConfig::disabled(),
        crate::signed_query_test_network_id(),
        None,
    );
    let shutdown = ShutdownSignal::new();
    shutdown.send();
    let worker = service
        .start_with_http_factory(shutdown, || {
            panic!("already stopped telemetry must not construct a transport");
        })
        .unwrap();
    assert_eq!(
        worker.await.unwrap(),
        crate::ToriiCriticalWorkerExit::StoppedByShutdown
    );
    assert_eq!(Arc::strong_count(&service), 1);
}
