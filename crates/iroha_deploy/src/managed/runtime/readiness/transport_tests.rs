//! Peer-zero transport reuse with fresh compatibility, exact signing and original budgets.

use super::*;
use crate::{localnet::LocalnetServiceProfile, managed::LocalnetPorts};
use iroha::http::{HttpTransport, Response, TransportFuture, TransportRequest};
use iroha_torii_shared::{
    PipelineTransactionStatus, PipelineTransactionStatusResponse, route_catalog,
};
use iroha_version::codec::DecodeVersioned;
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};

#[derive(Debug, Default)]
struct Recording {
    requests: Mutex<Vec<TransportRequest>>,
}

impl HttpTransport for Recording {
    fn send_blocking(&self, _: TransportRequest) -> color_eyre::eyre::Result<Response<Vec<u8>>> {
        panic!("readiness must use the blocking facade's asynchronous transport")
    }

    fn send(&self, request: TransportRequest) -> TransportFuture<'_> {
        let path = request.url.path();
        let body = if path == route_catalog::diagnostic::STATUS.path() {
            let status = iroha_torii_shared::status::Status {
                blocks: 1,
                peers: 3,
                ..Default::default()
            };
            norito::json::to_vec(&status).unwrap()
        } else if path == "/v1/node/capabilities" {
            let version = iroha_data_model::DATA_MODEL_VERSION;
            let schema = hex::encode(norito::schema::identity::frame_hash::<SignedTransaction>());
            norito::json::to_vec(&norito::json!({
                "data_model_version": version,
                "signed_transaction_schema_hash_hex": schema
            }))
            .unwrap()
        } else if path == route_catalog::pipeline::TRANSACTION.path() {
            Vec::new()
        } else if path == route_catalog::pipeline::TRANSACTION_STATUS.path() {
            let query: std::collections::BTreeMap<_, _> =
                request.url.query_pairs().into_owned().collect();
            let payload = PipelineTransactionStatusResponse::new(
                query.get("hash").unwrap().clone(),
                PipelineTransactionStatus {
                    kind: "Applied".into(),
                    block_height: Some(2),
                },
                query
                    .get("scope")
                    .cloned()
                    .unwrap_or_else(|| "global".into()),
                "state".into(),
            );
            norito::json::to_vec(&payload).unwrap()
        } else {
            panic!("unexpected readiness route")
        };
        self.requests.lock().unwrap().push(request);
        let response = Response::builder()
            .status(200)
            .header("Content-Type", "application/json")
            .body(body)
            .unwrap();
        Box::pin(async move { Ok(response) })
    }
}

fn prepared(temporary: &tempfile::TempDir) -> PreparedLocalnet {
    let ports = LocalnetPorts::reserve().unwrap();
    crate::localnet::prepare_localnet_at(
        "readiness-transport",
        &temporary.path().join("generation"),
        &ports,
        LocalnetServiceProfile::Standard,
        None,
    )
    .unwrap()
}

fn original(prepared: &PreparedLocalnet) -> Native {
    native(
        prepared,
        &Budget {
            started: Instant::now(),
            timeout: Duration::from_secs(30),
            cancelled: &AtomicBool::new(false),
            progress: &Progress::default(),
            clock: &WallClock,
        },
    )
    .unwrap()
    .0
}

fn record(owner: &mut Native) -> Arc<Recording> {
    let transport = Arc::new(Recording::default());
    for client in &mut owner.clients {
        let mut builder = client
            .client()
            .to_builder()
            .http_transport(transport.clone());
        builder.headers.insert(
            "x-readiness-fixture".into(),
            "retained-transport-control".into(),
        );
        let native = builder
            .build()
            .unwrap()
            .with_request_deadline(owner.deadline);
        *client = Client::from_client(native).unwrap();
    }
    transport
}

#[test]
fn peer_zero_submission_reuses_transport_but_rechecks_compatibility_and_all_four_exact_proofs() {
    let _guard = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let prepared = prepared(&temporary);
    let mut owner = original(&prepared);
    let transport = record(&mut owner);
    // Actual status dispatch warms the original transport. A successful compatibility decision
    // on that context must still be independently probed by the rebuilt submission context.
    owner.clients[0].status().get().unwrap();
    owner.clients[0].refresh_capabilities().unwrap();
    let remaining = Duration::from_secs(7);
    let submitter = owner.submitter(remaining).unwrap();
    let source = owner.clients[0].client();
    let selected = submitter.client();
    assert!(selected.endpoint() == source.endpoint());
    assert!(selected.chain() == source.chain());
    assert!(selected.network_id() == source.network_id());
    assert!(selected.account() == source.account());
    assert!(selected.key_pair() == source.key_pair());
    assert!(selected.headers() == source.headers());
    assert!(selected.transaction_ttl() == source.transaction_ttl());
    assert_eq!(
        selected.account_chain_discriminant(),
        source.account_chain_discriminant()
    );
    assert_eq!(
        selected.torii_request_timeout(),
        source.torii_request_timeout()
    );
    assert_eq!(
        selected.add_transaction_nonce(),
        source.add_transaction_nonce()
    );
    assert_eq!(selected.transaction_status_timeout(), remaining);
    assert_eq!(source.transaction_status_timeout(), Duration::from_secs(30));
    drop(submitter);
    let expected_payment = owner.fee_payment.clone();
    let expected_account = source.account().clone();
    let expected_network = *source.network_id();
    let expected_key = source.key_pair().public_key().clone();
    let expected_headers = source.headers().clone();
    assert!(expected_headers.contains_key("authorization"));
    assert!(expected_headers.contains_key("x-readiness-fixture"));
    let progress = Progress::default();
    let budget = Budget {
        started: Instant::now(),
        timeout: Duration::from_secs(20),
        cancelled: &AtomicBool::new(false),
        progress: &progress,
        clock: &WallClock,
    };
    let hash = run(&mut owner, &budget).unwrap();
    let requests = transport.requests.lock().unwrap();
    let capabilities: Vec<_> = requests
        .iter()
        .filter(|r| r.url.path() == "/v1/node/capabilities")
        .collect();
    assert_eq!(
        capabilities.len(),
        2,
        "the new submitter must obtain its own compatibility verdict"
    );
    let posts: Vec<_> = requests
        .iter()
        .filter(|r| r.url.path() == route_catalog::pipeline::TRANSACTION.path())
        .collect();
    assert_eq!(
        posts.len(),
        1,
        "one exact signed readiness transaction, with no replacement"
    );
    let signed = SignedTransaction::decode_all_versioned(&posts[0].body).unwrap();
    assert_eq!(signed.hash(), hash);
    assert!(signed.authority() == &expected_account);
    assert!(signed.network_id() == Some(&expected_network));
    assert!(signed.fee_payment_intent() == &expected_payment);
    signed
        .signature()
        .0
        .verify(&expected_key, signed.payload())
        .unwrap();
    for (name, value) in &expected_headers {
        assert!(
            posts[0]
                .headers
                .iter()
                .any(|(actual, actual_value)| actual.as_str() == name
                    && actual_value.to_str().unwrap() == value)
        );
    }
    let local: Vec<_> = requests
        .iter()
        .filter(|r| {
            r.url.path() == route_catalog::pipeline::TRANSACTION_STATUS.path()
                && r.url
                    .query_pairs()
                    .any(|(key, value)| key == "scope" && value == "local")
        })
        .collect();
    assert_eq!(local.len(), 4);
    assert_eq!(
        local
            .iter()
            .map(|r| r.url.port().unwrap())
            .collect::<BTreeSet<_>>(),
        prepared
            .peers
            .iter()
            .map(|peer| url::Url::parse(&peer.torii_url).unwrap().port().unwrap())
            .collect()
    );
    assert!(local.iter().all(|r| {
        r.url
            .query_pairs()
            .any(|(key, value)| key == "hash" && value == hash.to_string())
    }));
    assert!(requests.iter().all(|r| {
        r.timeout.is_some_and(|timeout| {
            timeout > Duration::ZERO && timeout <= Duration::from_millis(750)
        })
    }));
    assert_eq!(progress.phase(), Phase::Mesh);
}

#[test]
fn selected_submission_endpoint_is_normalized_and_peer_zero_substitution_refuses_without_http() {
    let _guard = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let mut prepared = prepared(&temporary);
    let listeners: Vec<_> = prepared
        .peers
        .iter()
        .map(|peer| {
            let url = url::Url::parse(&peer.torii_url).unwrap();
            let listener = std::net::TcpListener::bind(("127.0.0.1", url.port().unwrap())).unwrap();
            listener.set_nonblocking(true).unwrap();
            listener
        })
        .collect();
    let original_url = prepared.peers[0].torii_url.clone();
    prepared.peers[0].torii_url = original_url.trim_end_matches('/').to_owned();
    let owner = original(&prepared);
    assert!(
        owner.clients[0].client().endpoint()
            == &prepared.context.load_client_config().unwrap().torii_api_url
    );
    drop(owner);
    prepared.peers[0].torii_url = prepared.peers[1].torii_url.clone();
    let failure = native(
        &prepared,
        &Budget {
            started: Instant::now(),
            timeout: Duration::from_secs(30),
            cancelled: &AtomicBool::new(false),
            progress: &Progress::default(),
            clock: &WallClock,
        },
    )
    .err()
    .expect("a different peer-zero endpoint cannot inherit the original submission settings");
    assert_eq!(
        failure,
        Failure {
            phase: Phase::Initialization,
            cause: Cause::Unconfirmed
        }
    );
    prepared.peers[0].torii_url = original_url;
    assert_eq!(original(&prepared).clients.len(), 4);
    for listener in listeners {
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    }
}

#[test]
fn rebuilt_submission_refuses_zero_or_elapsed_budget_and_never_extends_the_source_deadline() {
    let _guard = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let prepared = prepared(&temporary);
    let mut owner = original(&prepared);
    let transport = record(&mut owner);
    assert!(owner.submitter(Duration::ZERO).is_err());
    let original_deadline = owner.deadline;
    owner.deadline = Instant::now();
    assert!(owner.submitter(Duration::from_secs(1)).is_err());
    owner.deadline = original_deadline;
    let expired = owner.clients[0]
        .client()
        .with_request_deadline(Instant::now());
    owner.clients[0] = Client::from_client(expired).unwrap();
    assert!(owner.submit_and_confirm(Duration::from_secs(1)).is_err());
    assert!(
        transport.requests.lock().unwrap().is_empty(),
        "reapplying a later deadline cannot dispatch through an expired source"
    );
    owner.clients.clear();
    assert!(owner.submitter(Duration::from_secs(1)).is_err());
}
