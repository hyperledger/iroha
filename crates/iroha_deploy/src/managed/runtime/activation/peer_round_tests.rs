//! Joined local Applied reads retain every peer, exact receipt and original finite barrier.

use super::transport_tests::{budget, fixture, terminals};
use super::*;
use iroha::http::{HttpTransport, Response, TransportFuture, TransportRequest};
use iroha_torii_shared::{PipelineTransactionStatus, PipelineTransactionStatusResponse};
use std::sync::{Mutex, atomic::AtomicUsize, mpsc};

#[derive(Clone, Copy, Debug)]
enum Fault {
    Hash,
    Height,
    Scope,
}

#[derive(Debug)]
struct Reads {
    origins: [String; 4],
    expected: Vec<ManagedTransactionFinality>,
    requests: Mutex<Vec<(usize, usize, TransportRequest)>>,
    completed: AtomicUsize,
    active: AtomicUsize,
    maximum_active: AtomicUsize,
    first_entered: mpsc::Sender<usize>,
    first_release: [Mutex<mpsc::Receiver<()>>; 4],
    fault: Option<(usize, usize, Fault)>,
    replace_config: Option<std::path::PathBuf>,
}

impl HttpTransport for Reads {
    fn send_blocking(&self, _: TransportRequest) -> color_eyre::eyre::Result<Response<Vec<u8>>> {
        panic!("the retained blocking facade dispatches through its original async runtime")
    }

    fn send(&self, request: TransportRequest) -> TransportFuture<'_> {
        let query: std::collections::BTreeMap<_, _> =
            request.url.query_pairs().into_owned().collect();
        let peer = self
            .origins
            .iter()
            .position(|origin| *origin == request.url.origin().ascii_serialization())
            .unwrap();
        let carrier = self
            .expected
            .iter()
            .position(|item| item.transaction_hash.to_string() == query["hash"])
            .unwrap();
        assert_eq!(query["scope"], "local");
        assert!(request.body.is_empty());
        assert_eq!(request.method, iroha::http::Method::GET);
        assert!(request.timeout.is_some_and(|timeout| !timeout.is_zero()));
        assert!(
            self.completed.load(Ordering::SeqCst) >= carrier * 4,
            "a later carrier must await all earlier peer reads"
        );
        self.requests.lock().unwrap().push((carrier, peer, request));
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.maximum_active.fetch_max(active, Ordering::SeqCst);
        Box::pin(async move {
            if carrier == 0 {
                self.first_entered.send(peer).unwrap();
                self.first_release[peer]
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(10))
                    .unwrap();
            }
            if carrier == 0 && peer == 3 {
                if let Some(path) = &self.replace_config {
                    let bytes = iroha_fs::read_private(path, crate::managed::MAX_METADATA).unwrap();
                    iroha_fs::PrivateDirectory::open(path.parent().unwrap())
                        .unwrap()
                        .write_atomic(
                            path.file_name().unwrap(),
                            &bytes,
                            iroha_fs::PublishMode::Replace,
                        )
                        .unwrap();
                }
            }
            let fault = self
                .fault
                .filter(|(at, member, _)| *at == carrier && *member == peer)
                .map(|(_, _, fault)| fault);
            let original = self.expected[carrier];
            let body = PipelineTransactionStatusResponse::new(
                if matches!(fault, Some(Fault::Hash)) {
                    iroha_crypto::Hash::new(b"foreign transaction").to_string()
                } else {
                    original.transaction_hash.to_string()
                },
                PipelineTransactionStatus {
                    kind: "Applied".into(),
                    block_height: Some(
                        original.height + u64::from(matches!(fault, Some(Fault::Height))),
                    ),
                },
                if matches!(fault, Some(Fault::Scope)) {
                    "global".into()
                } else {
                    "local".into()
                },
                "state".into(),
            );
            self.completed.fetch_add(1, Ordering::SeqCst);
            self.active.fetch_sub(1, Ordering::SeqCst);
            Ok(Response::builder()
                .header("Content-Type", "application/json")
                .body(norito::json::to_vec(&body)?)
                .unwrap())
        })
    }
}

fn reads(
    prepared: &PreparedLocalnet,
    required: Vec<ManagedTransactionFinality>,
    fault: Option<(usize, usize, Fault)>,
    replace_config: bool,
) -> (Arc<Reads>, mpsc::Receiver<usize>, [mpsc::Sender<()>; 4]) {
    let (entered, starts) = mpsc::channel();
    let channels = std::array::from_fn::<_, 4, _>(|_| mpsc::channel());
    let (releases, receivers): (Vec<_>, Vec<_>) = channels.into_iter().unzip();
    (
        Arc::new(Reads {
            origins: std::array::from_fn(|index| {
                prepared.peers[index]
                    .torii_url
                    .parse::<url::Url>()
                    .unwrap()
                    .origin()
                    .ascii_serialization()
            }),
            expected: required,
            requests: Mutex::new(Vec::new()),
            completed: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            maximum_active: AtomicUsize::new(0),
            first_entered: entered,
            first_release: receivers
                .into_iter()
                .map(Mutex::new)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            fault,
            replace_config: replace_config.then(|| prepared.context.client_config.clone()),
        }),
        starts,
        releases.try_into().unwrap(),
    )
}

fn release_first(
    starts: mpsc::Receiver<usize>,
    releases: [mpsc::Sender<()>; 4],
    before_release: impl FnOnce(),
) {
    let mut observed = (0..4)
        .map(|_| starts.recv_timeout(Duration::from_secs(10)).unwrap())
        .collect::<Vec<_>>();
    observed.sort();
    assert_eq!(
        observed,
        [0, 1, 2, 3],
        "all four borrowed peers must enter before any response is released"
    );
    before_release();
    for release in releases.into_iter().rev() {
        release.send(()).unwrap();
    }
}

#[test]
fn joined_carrier_reads_preserve_all_116_local_receipts_and_exact_failure_binding() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture();
    let required = terminals();
    for fault in [
        None,
        Some((0, 2, Fault::Hash)),
        Some((28, 1, Fault::Height)),
        Some((28, 3, Fault::Scope)),
    ] {
        let (transport, starts, releases) = reads(&prepared, required.clone(), fault, false);
        let selected = budget();
        let result = thread::scope(|scope| {
            let release = scope.spawn(|| release_first(starts, releases, || {}));
            let result = confirm_carriers_with(&prepared, &required, &selected, |builder| {
                builder.http_transport(transport.clone())
            });
            release.join().unwrap();
            result
        });
        if let Some((_, peer, _)) = fault {
            assert_eq!(
                result,
                Err(Failure::Activation {
                    phase: CARRIER_PHASES[peer],
                    cause: super::super::progress::Cause::Unconfirmed
                })
            );
        } else {
            result.unwrap();
        }
        assert_eq!(
            transport.active.load(Ordering::SeqCst),
            0,
            "no peer read outlives the barrier result"
        );
        assert_eq!(transport.maximum_active.load(Ordering::SeqCst), 4);
        assert_eq!(
            Arc::strong_count(&transport),
            1,
            "every original transport runtime closes"
        );
        let requests = transport.requests.lock().unwrap();
        let count = fault.map_or(29, |(carrier, _, _)| carrier + 1);
        assert_eq!(requests.len(), count * 4);
        for (carrier, cohort) in requests.chunks_exact(4).enumerate() {
            let mut members = cohort
                .iter()
                .map(|(observed, peer, _)| {
                    assert_eq!(*observed, carrier);
                    *peer
                })
                .collect::<Vec<_>>();
            members.sort();
            assert_eq!(members, [0, 1, 2, 3]);
        }
    }
}

#[test]
fn joined_carrier_admission_constructs_all_original_peers_before_http() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, mut prepared) = fixture();
    let required = terminals();
    let (transport, _starts, _releases) = reads(&prepared, required.clone(), None, false);
    prepared.peers[2].torii_url = "invalid endpoint".into();
    let result = confirm_carriers_with(&prepared, &required, &budget(), |builder| {
        builder.http_transport(transport.clone())
    });
    assert_eq!(
        result,
        Err(Failure::Activation {
            phase: Phase::Carrier2,
            cause: super::super::progress::Cause::Unconfirmed,
        })
    );
    assert!(transport.requests.lock().unwrap().is_empty());
    assert_eq!(Arc::strong_count(&transport), 1);
}

#[test]
fn joined_carrier_cancellation_and_expiry_close_all_peers_without_advancing() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture();
    let required = terminals();
    for cancel in [true, false] {
        let selected = Budget {
            timeout: Duration::from_secs(2),
            ..budget()
        };
        let (transport, starts, releases) = reads(&prepared, required.clone(), None, false);
        let result = thread::scope(|scope| {
            let release = scope.spawn(|| {
                release_first(starts, releases, || {
                    if cancel {
                        selected.cancelled.store(true, Ordering::Release);
                    } else {
                        thread::sleep(
                            (selected.started + selected.timeout)
                                .saturating_duration_since(Instant::now())
                                + Duration::from_millis(1),
                        );
                    }
                })
            });
            let result = confirm_carriers_with(&prepared, &required, &selected, |builder| {
                builder.http_transport(transport.clone())
            });
            release.join().unwrap();
            result
        });
        assert_eq!(
            result,
            Err(Failure::Activation {
                phase: Phase::CarrierPeers,
                cause: if cancel {
                    super::super::progress::Cause::Cancelled
                } else {
                    super::super::progress::Cause::Deadline
                }
            })
        );
        assert_eq!(transport.requests.lock().unwrap().len(), 4);
        assert_eq!(transport.completed.load(Ordering::SeqCst), 4);
        assert_eq!(transport.active.load(Ordering::SeqCst), 0);
        assert_eq!(Arc::strong_count(&transport), 1);
    }
}

#[cfg(unix)]
#[test]
fn joined_carrier_reads_refuse_replaced_original_configuration_before_next_receipt() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture();
    let required = terminals();
    let (transport, starts, releases) = reads(&prepared, required.clone(), None, true);
    let result = thread::scope(|scope| {
        let release = scope.spawn(|| release_first(starts, releases, || {}));
        let result = confirm_carriers_with(&prepared, &required, &budget(), |builder| {
            builder.http_transport(transport.clone())
        });
        release.join().unwrap();
        result
    });
    assert!(result.is_err());
    assert_eq!(transport.requests.lock().unwrap().len(), 4);
    assert_eq!(transport.completed.load(Ordering::SeqCst), 4);
    assert_eq!(Arc::strong_count(&transport), 1);
    prepared.context.load_client_config().unwrap();
}

#[test]
fn joined_peer_error_and_panic_wait_for_all_borrows_then_choose_validator_order() {
    for panic_first in [false, true] {
        let (entered, starts) = mpsc::channel();
        let channels = std::array::from_fn::<_, 4, _>(|_| mpsc::channel());
        let (releases, receivers): (Vec<_>, Vec<_>) = channels.into_iter().unzip();
        let receivers = receivers.into_iter().map(Mutex::new).collect::<Vec<_>>();
        let finished = AtomicUsize::new(0);
        let result = thread::scope(|scope| {
            let release = scope.spawn(move || {
                for _ in 0..4 {
                    starts.recv_timeout(Duration::from_secs(10)).unwrap();
                }
                for sender in releases.into_iter().rev() {
                    sender.send(()).unwrap();
                }
            });
            let result = join_carrier_peer_reads(|peer| {
                entered.send(peer).unwrap();
                receivers[peer]
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(10))
                    .unwrap();
                finished.fetch_add(1, Ordering::SeqCst);
                if panic_first && peer == 1 {
                    panic!("scheduler-only peer worker panic");
                }
                if peer == 1 || peer == 3 {
                    return Err(Failure::Activation {
                        phase: CARRIER_PHASES[peer],
                        cause: super::super::progress::Cause::Unconfirmed,
                    });
                }
                Ok(())
            });
            release.join().unwrap();
            result
        });
        assert_eq!(finished.load(Ordering::SeqCst), 4);
        assert_eq!(
            result,
            Err(Failure::Activation {
                phase: Phase::Carrier1,
                cause: super::super::progress::Cause::Unconfirmed
            })
        );
    }
}
