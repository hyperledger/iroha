//! Request-coordinate checks through actual async transport and the inherited blocking facade.
//!
//! Carrier fixtures deliberately contain no valid certificate. Accepting their transport
//! coordinates is not finality, inclusion, freshness, or message/control authority.

use super::*;
use crate::{
    blocking,
    client::{
        capability_test_support::AsyncOnlyTransport,
        evidence_http_tests::{base_url, client_with_base_url},
    },
    http::{Response, TransportRequest},
};
use iroha_sccp::api::{SccpBlockRefV1, SccpCertificateV1};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

const MESSAGE: [u8; 32] = [0xab; 32];
const NETWORK: SccpNetworkV1 = SccpNetworkV1::EthereumMainnet;
const REVISION: u32 = 3;
const NONCE: u64 = 7;

fn certificate(height: u64) -> SccpCertificateV1 {
    SccpCertificateV1 {
        height,
        qc: [0; 116],
        aggregate_signature: [0; 96],
        header: [0; 221],
        committee: Vec::new(),
    }
}
fn block(height: u64) -> SccpBlockRefV1 {
    SccpBlockRefV1 {
        height,
        sccp_root: [3; 32],
        message_count: 1,
        history_index: 0,
        history_path: Vec::new(),
    }
}
fn message() -> SccpMessageProofBundleV1 {
    SccpMessageProofBundleV1 {
        message_id: MESSAGE,
        payload: vec![1, 2],
        deadline_ms: 500,
        leaf_index: 0,
        path: Vec::new(),
        block: block(10),
        certificate: certificate(10),
    }
}
fn control() -> SccpControlProofBundleV1 {
    SccpControlProofBundleV1 {
        network: NETWORK,
        revision: REVISION,
        control_nonce: NONCE,
        track: 1,
        parliament_paused: true,
        fast_pause_until_ms: 0,
        certificate_id: [4; 32],
        effect_hash: [5; 32],
        leaf_index: 0,
        path: Vec::new(),
        block: block(10),
        certificate: certificate(10),
    }
}
fn message_cases() -> Vec<(
    SccpProofHeightV1,
    SccpMessageProofBundleV1,
    Option<&'static str>,
)> {
    let mut historical = message();
    historical.certificate.height = 20;
    let mut wrong_id = message();
    wrong_id.message_id[0] ^= 1;
    let mut wrong_block = message();
    wrong_block.block.height = 9;
    vec![
        (SccpProofHeightV1::Record, message(), None),
        (SccpProofHeightV1::At(20), historical.clone(), None),
        (SccpProofHeightV1::Latest, historical.clone(), None),
        (SccpProofHeightV1::Record, wrong_id, Some("message_id")),
        (
            SccpProofHeightV1::At(11),
            message(),
            Some("certificate.height"),
        ),
        (
            SccpProofHeightV1::Record,
            historical,
            Some("certificate.height"),
        ),
        (
            SccpProofHeightV1::Record,
            wrong_block,
            Some("certificate.height"),
        ),
    ]
}
fn control_cases() -> Vec<(
    SccpProofHeightV1,
    SccpControlProofBundleV1,
    Option<&'static str>,
)> {
    let mut historical = control();
    historical.certificate.height = 20;
    let mut wrong_network = control();
    wrong_network.network = SccpNetworkV1::BscMainnet;
    let mut wrong_revision = control();
    wrong_revision.revision += 1;
    let mut wrong_nonce = control();
    wrong_nonce.control_nonce += 1;
    let mut wrong_block = control();
    wrong_block.block.height = 9;
    vec![
        (SccpProofHeightV1::Record, control(), None),
        (SccpProofHeightV1::At(20), historical.clone(), None),
        (SccpProofHeightV1::Latest, historical.clone(), None),
        (SccpProofHeightV1::Record, wrong_network, Some("network")),
        (SccpProofHeightV1::Record, wrong_revision, Some("revision")),
        (
            SccpProofHeightV1::Record,
            wrong_nonce,
            Some("control_nonce"),
        ),
        (
            SccpProofHeightV1::At(11),
            control(),
            Some("certificate.height"),
        ),
        (
            SccpProofHeightV1::Record,
            historical,
            Some("certificate.height"),
        ),
        (
            SccpProofHeightV1::Record,
            wrong_block,
            Some("certificate.height"),
        ),
    ]
}
fn attach(body: Vec<u8>) -> (Client, Arc<Mutex<Vec<TransportRequest>>>, Arc<AtomicUsize>) {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let completed = Arc::new(AtomicUsize::new(0));
    let transport = AsyncOnlyTransport {
        responder: Box::new(move |_| {
            Ok(Response::builder()
                .status(200)
                .header("Content-Type", "application/json")
                .body(body.clone())
                .unwrap())
        }),
        requests: Arc::clone(&requests),
        completed: Arc::clone(&completed),
        delay: Duration::ZERO,
    };
    let client = client_with_base_url(base_url())
        .to_builder()
        .http_transport(Arc::new(transport))
        .build()
        .unwrap();
    (client, requests, completed)
}
fn assert_response<T: std::fmt::Debug + PartialEq>(
    result: Result<T>,
    expected: &T,
    operation: &'static str,
    field: Option<&'static str>,
) {
    match field {
        None => assert_eq!(&result.expect("matching coordinates"), expected),
        Some(field) => match result.expect_err("a different requested coordinate must fail") {
            Error::ResponseBinding {
                operation: actual_operation,
                field: actual_field,
            } => {
                assert_eq!(actual_operation, operation);
                assert_eq!(actual_field, field);
            }
            error => panic!("wrong refusal: {error:?}"),
        },
    }
}
fn assert_request(
    requests: &Mutex<Vec<TransportRequest>>,
    completed: &AtomicUsize,
    path: &str,
    at: SccpProofHeightV1,
) {
    assert_eq!(completed.load(Ordering::SeqCst), 1);
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1, "one proof read, no probes or retry");
    let request = &requests[0];
    assert_eq!(request.method, Method::GET);
    assert_eq!(request.url.path(), path);
    assert_eq!(request.url.query(), Some(format!("at={at}").as_str()));
    assert_eq!(request.max_response_bytes, MAX_RESPONSE_BYTES);
    assert!(request.body.is_empty());
}
fn assert_invalid_height<T: std::fmt::Debug>(result: Result<T>, operation: &'static str) {
    match result.expect_err("explicit zero height is invalid before dispatch") {
        Error::InvalidRequest {
            operation: actual,
            details,
        } => {
            assert_eq!(actual, operation);
            assert!(details.contains("positive"));
        }
        error => panic!("wrong pre-dispatch refusal: {error:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn async_message_proof_binds_requested_id_and_certificate_height() {
    assert!(
        message().certificate.check_shape().is_err(),
        "carrier grants no authority"
    );
    for (at, response, field) in message_cases() {
        let (client, requests, completed) = attach(norito::json::to_vec(&response).unwrap());
        assert_response(
            client.sccp().message_proof(&MESSAGE, at).await,
            &response,
            sccp::MESSAGE_PROOF.stable_route_id(),
            field,
        );
        assert_request(
            &requests,
            &completed,
            &format!("/v1/sccp/messages/{}/proof", hex32(&MESSAGE)),
            at,
        );
    }
}
#[tokio::test(flavor = "current_thread")]
async fn async_control_proof_binds_each_location_and_certificate_height() {
    for (at, response, field) in control_cases() {
        let (client, requests, completed) = attach(norito::json::to_vec(&response).unwrap());
        assert_response(
            client
                .sccp()
                .control_proof(NETWORK, REVISION, NONCE, at)
                .await,
            &response,
            sccp::CONTROL_PROOF.stable_route_id(),
            field,
        );
        assert_request(
            &requests,
            &completed,
            "/v1/sccp/controls/ethereum-mainnet/3/7/proof",
            at,
        );
    }
}
#[tokio::test(flavor = "current_thread")]
async fn async_proof_reads_reject_zero_height_before_dispatch() {
    let (client, requests, completed) = attach(Vec::new());
    assert_invalid_height(
        client
            .sccp()
            .message_proof(&MESSAGE, SccpProofHeightV1::At(0))
            .await,
        sccp::MESSAGE_PROOF.stable_route_id(),
    );
    assert_invalid_height(
        client
            .sccp()
            .control_proof(NETWORK, REVISION, NONCE, SccpProofHeightV1::At(0))
            .await,
        sccp::CONTROL_PROOF.stable_route_id(),
    );
    assert!(requests.lock().unwrap().is_empty());
    assert_eq!(completed.load(Ordering::SeqCst), 0);
}
#[test]
fn blocking_message_proof_inherits_id_and_height_checks() {
    for (at, response, field) in message_cases() {
        let (client, requests, completed) = attach(norito::json::to_vec(&response).unwrap());
        let client = blocking::Client::from_client(client).unwrap();
        assert_response(
            client.sccp().message_proof(&MESSAGE, at),
            &response,
            sccp::MESSAGE_PROOF.stable_route_id(),
            field,
        );
        assert_request(
            &requests,
            &completed,
            &format!("/v1/sccp/messages/{}/proof", hex32(&MESSAGE)),
            at,
        );
    }
}
#[test]
fn blocking_control_proof_inherits_each_location_and_height_check() {
    for (at, response, field) in control_cases() {
        let (client, requests, completed) = attach(norito::json::to_vec(&response).unwrap());
        let client = blocking::Client::from_client(client).unwrap();
        assert_response(
            client.sccp().control_proof(NETWORK, REVISION, NONCE, at),
            &response,
            sccp::CONTROL_PROOF.stable_route_id(),
            field,
        );
        assert_request(
            &requests,
            &completed,
            "/v1/sccp/controls/ethereum-mainnet/3/7/proof",
            at,
        );
    }
}
#[test]
fn blocking_proof_reads_reject_zero_height_before_dispatch() {
    let (client, requests, completed) = attach(Vec::new());
    let client = blocking::Client::from_client(client).unwrap();
    assert_invalid_height(
        client
            .sccp()
            .message_proof(&MESSAGE, SccpProofHeightV1::At(0)),
        sccp::MESSAGE_PROOF.stable_route_id(),
    );
    assert_invalid_height(
        client
            .sccp()
            .control_proof(NETWORK, REVISION, NONCE, SccpProofHeightV1::At(0)),
        sccp::CONTROL_PROOF.stable_route_id(),
    );
    assert!(requests.lock().unwrap().is_empty());
    assert_eq!(completed.load(Ordering::SeqCst), 0);
}

#[test]
fn finality_height_is_bound_through_async_and_blocking_transport() {
    let offered = certificate(10);
    let (client, requests, _) = attach(norito::json::to_vec(&offered).unwrap());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let blocking = blocking::Client::from_client(client.clone()).unwrap();
    for (at, mismatch) in [
        (SccpFinalityAt::Latest, None),
        (SccpFinalityAt::Height(NonZeroU64::new(10).unwrap()), None),
        (
            SccpFinalityAt::Height(NonZeroU64::new(11).unwrap()),
            Some("height"),
        ),
    ] {
        assert_response(
            runtime.block_on(client.sccp().finality(at)),
            &offered,
            sccp::FINALITY.stable_route_id(),
            mismatch,
        );
        assert_response(
            blocking.sccp().finality(at),
            &offered,
            sccp::FINALITY.stable_route_id(),
            mismatch,
        );
    }
    assert_eq!(requests.lock().unwrap().len(), 6);
}
