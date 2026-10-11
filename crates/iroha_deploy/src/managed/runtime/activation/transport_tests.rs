//! One carrier barrier retains four peer contexts and every original local Applied check.

use super::*;
use iroha::http::{HttpTransport, Response, TransportFuture, TransportRequest};
use iroha_torii_shared::{PipelineTransactionStatus, PipelineTransactionStatusResponse};
use std::sync::Mutex;

#[derive(Clone, Copy, Debug)]
enum Fault {
    Height,
    Hash,
    Scope,
}
#[derive(Debug, Default)]
struct Captured {
    requests: Mutex<Vec<TransportRequest>>,
    expected: Vec<ManagedTransactionFinality>,
    fault: Option<(usize, Fault)>,
    cancel_after: Option<(usize, Arc<AtomicBool>)>,
    expire_after: Option<(usize, Instant)>,
    change_config: Option<(usize, std::path::PathBuf, bool)>,
}
impl HttpTransport for Captured {
    fn send_blocking(&self, _: TransportRequest) -> color_eyre::eyre::Result<Response<Vec<u8>>> {
        panic!("carrier reads retain the blocking facade's asynchronous dispatch")
    }
    fn send(&self, request: TransportRequest) -> TransportFuture<'_> {
        let query: std::collections::BTreeMap<_, _> =
            request.url.query_pairs().into_owned().collect();
        let mut requests = self.requests.lock().unwrap();
        let count = requests.len() + 1;
        let terminal = self.expected[(count - 1) / 4];
        let fault = self
            .fault
            .filter(|(at, _)| *at == count)
            .map(|(_, fault)| fault);
        let body = PipelineTransactionStatusResponse::new(
            if matches!(fault, Some(Fault::Hash)) {
                iroha_crypto::Hash::new(b"different carrier transaction").to_string()
            } else {
                query.get("hash").unwrap().clone()
            },
            PipelineTransactionStatus {
                kind: "Applied".into(),
                block_height: Some(
                    terminal.height + u64::from(matches!(fault, Some(Fault::Height))),
                ),
            },
            if matches!(fault, Some(Fault::Scope)) {
                "global".into()
            } else {
                query.get("scope").unwrap().clone()
            },
            "state".into(),
        );
        requests.push(request);
        drop(requests);
        Box::pin(async move {
            if let Some((_, path, replace)) = self
                .change_config
                .as_ref()
                .filter(|(at, _, _)| *at == count)
            {
                if *replace {
                    // Keep identical bytes and valid private custody while replacing the object.
                    let bytes = iroha_fs::read_private(path, crate::managed::MAX_METADATA).unwrap();
                    iroha_fs::PrivateDirectory::open(path.parent().unwrap())
                        .unwrap()
                        .write_atomic(
                            path.file_name().unwrap(),
                            &bytes,
                            iroha_fs::PublishMode::Replace,
                        )
                        .unwrap();
                } else {
                    // Preserve the native object and valid configuration while changing material.
                    use std::io::Write;
                    std::fs::OpenOptions::new()
                        .append(true)
                        .open(path)
                        .unwrap()
                        .write_all(b"\n# changed during the carrier barrier\n")
                        .unwrap();
                }
            }
            if let Some((_, cancelled)) = self.cancel_after.as_ref().filter(|(at, _)| *at == count)
            {
                cancelled.store(true, Ordering::Release);
            }
            if let Some((_, deadline)) = self.expire_after.filter(|(at, _)| *at == count) {
                // Deliberately uncooperative completion: a late Applied response cannot win.
                thread::sleep(
                    deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
                );
            }
            Ok(Response::builder()
                .header("Content-Type", "application/json")
                .body(norito::json::to_vec(&body)?)
                .unwrap())
        })
    }
}
pub(super) fn terminals() -> Vec<ManagedTransactionFinality> {
    (0_u64..29)
        .map(|index| {
            let height = 13 + index / 3;
            ManagedTransactionFinality {
                transaction_hash: iroha_crypto::HashOf::from_untyped_unchecked(
                    iroha_crypto::Hash::new(index.to_le_bytes()),
                ),
                height,
                block_hash: iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
                    height.to_le_bytes(),
                )),
                block_time_ms: height,
            }
        })
        .collect()
}

pub(super) fn fixture() -> (tempfile::TempDir, PreparedLocalnet) {
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "carrier-transports",
        &temporary.path().join("generation"),
        &ports,
        LocalnetServiceProfile::Standard,
        None,
    )
    .unwrap();
    (temporary, prepared)
}
pub(super) fn budget() -> Budget {
    Budget {
        started: Instant::now(),
        timeout: Duration::from_secs(120),
        startup_deadline_ns: None,
        utc_ceiling_unix_ms: None,
        cancelled: Arc::new(AtomicBool::new(false)),
        progress: Arc::new(Progress::default()),
    }
}

fn serial_carriers(
    prepared: &PreparedLocalnet,
    required: &[ManagedTransactionFinality],
    budget: &Budget,
    configure: impl Fn(iroha::client::ClientBuilder) -> iroha::client::ClientBuilder,
) -> std::result::Result<(), Failure> {
    let limit = 64 * 1024 * 1024;
    let context = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
        limit, limit, limit, limit, 64,
    ));
    context.with(|| confirm_carriers_with(prepared, required, budget, configure))
}

#[test]
fn carrier_peer_contexts_keep_original_request_identity_and_local_height_checks() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture();
    let required = terminals();
    let budget = budget();
    let transport = Arc::new(Captured {
        expected: required.clone(),
        ..Default::default()
    });
    serial_carriers(&prepared, &required, &budget, |builder| {
        builder.http_transport(transport.clone())
    })
    .unwrap();
    assert_eq!(
        Arc::strong_count(&transport),
        1,
        "completed barrier releases its contexts"
    );
    let requests = transport.requests.lock().unwrap();
    assert_eq!(requests.len(), 29 * 4);
    let mut previous_timeout = budget.timeout;
    for (index, request) in requests.iter().enumerate() {
        let peer = &prepared.peers[index % 4];
        let terminal = required[index / 4];
        assert_eq!(
            request.url.origin(),
            peer.torii_url.parse::<url::Url>().unwrap().origin()
        );
        assert!(
            request
                .url
                .query_pairs()
                .any(|(key, value)| key == "scope" && value == "local")
        );
        let expected_hash = terminal.transaction_hash.to_string();
        assert!(
            request
                .url
                .query_pairs()
                .any(|(key, value)| key == "hash" && value == expected_hash)
        );
        let timeout = request.timeout.unwrap();
        assert!(
            !timeout.is_zero() && timeout <= previous_timeout,
            "later carriers retain the original deadline"
        );
        previous_timeout = timeout;
        assert_eq!(request.method, iroha::http::Method::GET);
        assert!(request.body.is_empty());
    }
    drop(requests);
    // An error on the final carrier still prevents its next peer: earlier receipts never
    // substitute for this transaction, including transactions sharing a carrier height.
    for fault in [Fault::Height, Fault::Hash, Fault::Scope] {
        for at in [1, 29 * 4 - 1] {
            let wrong = Arc::new(Captured {
                expected: required.clone(),
                fault: Some((at, fault)),
                ..Default::default()
            });
            assert!(
                serial_carriers(&prepared, &required, &self::budget(), |builder| builder
                    .http_transport(wrong.clone()),)
                .is_err()
            );
            assert_eq!(
                wrong.requests.lock().unwrap().len(),
                at,
                "wrong carrier never advances to another peer"
            );
            assert_eq!(
                Arc::strong_count(&wrong),
                1,
                "failed barrier releases its contexts"
            );
        }
    }
}

#[test]
fn carrier_cancellation_or_expiry_prevents_reused_transport_dispatch() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture();
    let required = terminals();
    let transport = Arc::new(Captured::default());
    let cancelled = budget();
    cancelled.cancelled.store(true, Ordering::Release);
    assert!(
        serial_carriers(&prepared, &required, &cancelled, |builder| builder
            .http_transport(transport.clone()))
        .is_err()
    );
    let expired = Budget {
        started: Instant::now() - Duration::from_secs(121),
        ..budget()
    };
    assert!(
        serial_carriers(&prepared, &required, &expired, |builder| builder
            .http_transport(transport.clone()))
        .is_err()
    );
    assert!(transport.requests.lock().unwrap().is_empty());

    let cancelled = budget();
    let transport = Arc::new(Captured {
        expected: required.clone(),
        cancel_after: Some((5, Arc::clone(&cancelled.cancelled))),
        ..Default::default()
    });
    let result = serial_carriers(&prepared, &required, &cancelled, |builder| {
        builder.http_transport(transport.clone())
    });
    assert_eq!(
        result,
        Err(Failure::Activation {
            phase: Phase::Carrier0,
            cause: super::super::progress::Cause::Cancelled
        })
    );
    assert_eq!(
        transport.requests.lock().unwrap().len(),
        5,
        "cancellation during a reused peer stops all subsequent work"
    );
    assert_eq!(Arc::strong_count(&transport), 1);

    let expiring = Budget {
        timeout: Duration::from_secs(2),
        ..budget()
    };
    let transport = Arc::new(Captured {
        expected: required.clone(),
        expire_after: Some((5, expiring.started + expiring.timeout)),
        ..Default::default()
    });
    let result = serial_carriers(&prepared, &required, &expiring, |builder| {
        builder.http_transport(transport.clone())
    });
    assert_eq!(
        result,
        Err(Failure::Activation {
            phase: Phase::Carrier0,
            cause: super::super::progress::Cause::Deadline
        })
    );
    assert_eq!(
        transport.requests.lock().unwrap().len(),
        5,
        "late Applied on a reused peer cannot extend the original deadline"
    );
    assert_eq!(Arc::strong_count(&transport), 1);
}

#[test]
fn carrier_barrier_rejects_missing_originals_or_changed_committee() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, mut prepared) = fixture();
    let required = terminals();
    assert!(confirm_carriers(&prepared, &[], &budget()).is_err());
    assert!(confirm_carriers(&prepared, &[required[0]; 33], &budget()).is_err());
    prepared.peers.pop();
    assert!(confirm_carriers(&prepared, &required, &budget()).is_err());
}

// Windows retains this file with FILE_SHARE_READ only, preventing either mutation while bound.
#[cfg(unix)]
#[test]
fn carrier_reuse_refuses_replaced_or_changed_private_configuration() {
    let _guard = crate::managed::native_test_guard();
    for replace in [false, true] {
        let (_temporary, prepared) = fixture();
        let required = terminals();
        let transport = Arc::new(Captured {
            expected: required.clone(),
            change_config: Some((4, prepared.context.client_config.clone(), replace)),
            ..Default::default()
        });
        let result = serial_carriers(&prepared, &required, &budget(), |builder| {
            builder.http_transport(transport.clone())
        });
        assert!(result.is_err());
        assert_eq!(
            transport.requests.lock().unwrap().len(),
            4,
            "configuration changes refuse the next receipt before HTTP dispatch"
        );
        assert_eq!(Arc::strong_count(&transport), 1);
        // Refusal is the exact retained configuration fence, not a malformed configuration.
        prepared.context.load_client_config().unwrap();
    }
}

#[test]
fn native_carrier_reads_share_one_live_pool_and_keep_every_local_proof() {
    native_carrier_pool(false);
}

#[test]
fn joined_carrier_reads_keep_bounded_live_pool_and_every_local_proof() {
    native_carrier_pool(true);
}

fn native_carrier_pool(parallel: bool) {
    use std::{
        io::{ErrorKind, Read, Write},
        net::TcpListener,
    };
    let _guard = crate::managed::native_test_guard();
    let (_temporary, mut prepared) = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    for (index, peer) in prepared.peers.iter_mut().enumerate() {
        peer.torii_url = format!("http://{address}/peer{index}/");
    }
    let required = terminals();
    let expected = required.clone();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut connections = Vec::new();
        let mut requests = Vec::new();
        while requests.len() < expected.len() * 4 && Instant::now() < deadline {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(true).unwrap();
                    connections.push((stream, Vec::<u8>::new()));
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => panic!("carrier listener: {error}"),
            }
            for (stream, pending) in &mut connections {
                let mut buffer = [0_u8; 4096];
                match stream.read(&mut buffer) {
                    Ok(length) => pending.extend_from_slice(&buffer[..length]),
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                    Err(error) => panic!("carrier request: {error}"),
                }
                if let Some(end) = pending.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    let bytes = pending.drain(..end + 4).collect::<Vec<_>>();
                    let request = String::from_utf8(bytes).unwrap();
                    let target = request
                        .lines()
                        .next()
                        .unwrap()
                        .split_whitespace()
                        .nth(1)
                        .unwrap();
                    let url = url::Url::parse(&format!("http://{address}{target}")).unwrap();
                    let query: std::collections::BTreeMap<_, _> =
                        url.query_pairs().into_owned().collect();
                    let terminal = expected[requests.len() / 4];
                    let expected_hash = terminal.transaction_hash.to_string();
                    assert_eq!(query.get("hash").unwrap(), &expected_hash);
                    assert_eq!(query.get("scope").unwrap(), "local");
                    requests.push(url.path().to_owned());
                    let response = PipelineTransactionStatusResponse::new(
                        expected_hash,
                        PipelineTransactionStatus {
                            kind: "Applied".into(),
                            block_height: Some(terminal.height),
                        },
                        "local".into(),
                        "state".into(),
                    );
                    let body = norito::json::to_vec(&response).unwrap();
                    let headers = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                        body.len()
                    );
                    let response = [headers.as_bytes(), &body].concat();
                    let mut written = 0;
                    while written < response.len() && Instant::now() < deadline {
                        match stream.write(&response[written..]) {
                            Ok(0) => panic!("carrier response closed"),
                            Ok(length) => written += length,
                            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                                thread::sleep(Duration::from_millis(1))
                            }
                            Err(error) => panic!("carrier response: {error}"),
                        }
                    }
                    assert_eq!(written, response.len());
                }
            }
            thread::sleep(Duration::from_millis(1));
        }
        (connections.len(), requests)
    });
    let budget = Budget {
        timeout: Duration::from_secs(15),
        ..budget()
    };
    let result = if parallel {
        confirm_carriers_with(&prepared, &required, &budget, |builder| builder)
    } else {
        serial_carriers(&prepared, &required, &budget, |builder| builder)
    };
    let (connections, requests) = server.join().unwrap();
    result.unwrap();
    if parallel {
        assert!(
            (1..=4).contains(&connections),
            "one outstanding read per peer keeps a bounded pool"
        );
        assert_eq!(requests.len(), 29 * 4);
        let mut expected: Vec<_> = (0..4)
            .map(|peer| {
                format!(
                    "/peer{peer}{}",
                    iroha_torii_shared::route_catalog::pipeline::TRANSACTION_STATUS.path()
                )
            })
            .collect();
        expected.sort();
        for cohort in requests.chunks_exact(4) {
            let mut actual = cohort.to_vec();
            actual.sort();
            assert_eq!(actual, expected);
        }
    } else {
        assert_eq!(
            connections, 1,
            "the originating runtime must drive its shared pool until every carrier and peer finishes"
        );
        assert_eq!(
            requests,
            (0..29)
                .flat_map(|_| (0..4).map(|peer| format!(
                    "/peer{peer}{}",
                    iroha_torii_shared::route_catalog::pipeline::TRANSACTION_STATUS.path()
                )))
                .collect::<Vec<_>>()
        );
    }
}
