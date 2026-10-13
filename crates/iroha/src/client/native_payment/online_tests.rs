//! Async native proof acquisition preserves the existing bounded evidence contract.

use super::*;
use crate::{
    client::{
        Client,
        evidence_http_tests::{client_with_base_url, mark_data_model_compatible},
    },
    http::{HttpTransport, Response, StatusCode, TransportFuture, TransportRequest},
    http_default::DefaultHttpTransport,
};
use iroha_data_model::sumeragi_finality::{
    SumeragiFinalityProof, test_fixtures::NativeFinalityFixture,
};
use std::{
    collections::VecDeque,
    num::NonZeroU64,
    time::{Duration, Instant},
};

#[derive(Debug)]
struct AsyncProofTransport {
    responses: Mutex<VecDeque<Response<Vec<u8>>>>,
    requests: Mutex<Vec<TransportRequest>>,
}
impl HttpTransport for AsyncProofTransport {
    fn send_blocking(&self, _: TransportRequest) -> eyre::Result<Response<Vec<u8>>> {
        panic!("native payment proof acquisition must use only the owned async transport")
    }
    fn send(&self, request: TransportRequest) -> TransportFuture<'_> {
        Box::pin(async move {
            self.requests.lock().unwrap().push(request);
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| eyre::eyre!("unexpected repeated native proof request"))
        })
    }
}

fn proof() -> SumeragiFinalityProof {
    NativeFinalityFixture::start("native-payment-async-proof")
        .genesis_proof()
        .clone()
}
fn response(proof: &SumeragiFinalityProof) -> Response<Vec<u8>> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/x-norito")
        .body(norito::encode_canonical(proof).unwrap())
        .unwrap()
}
fn busy() -> Response<Vec<u8>> {
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("retry-after", "0")
        .body(Vec::new())
        .unwrap()
}
fn source(
    responses: impl IntoIterator<Item = Response<Vec<u8>>>,
) -> (OnlinePaymentSource, Arc<AsyncProofTransport>) {
    let transport = Arc::new(AsyncProofTransport {
        responses: Mutex::new(responses.into_iter().collect()),
        requests: Mutex::new(Vec::new()),
    });
    let client = client_with_base_url("http://mock.local/provider/v1/".parse().unwrap())
        .with_test_http_transport(DefaultHttpTransport::from_shared(transport.clone()));
    mark_data_model_compatible(&client);
    (
        OnlinePaymentSource(client.account_client().unwrap()),
        transport,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_payment_online_proof_uses_owned_async_transport_inside_runtime() {
    let expected = proof();
    let (source, transport) = source([response(&expected)]);
    let observed = source
        .proof(NonZeroU64::MIN)
        .await
        .expect("native payment proof must be readable inside its async runtime");
    assert_eq!(observed, expected);
    let requests = transport.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    let path = iroha_torii_shared::route_catalog::sumeragi::BRIDGE_FINALITY
        .path()
        .replace("{height}", "1");
    assert_eq!(
        request.url,
        crate::client::join_torii_url(source.0.client().endpoint(), &path)
    );
    assert!(request.url.path().starts_with("/provider/v1/"));
    assert_eq!(
        request.max_response_bytes,
        crate::client::SUMERAGI_FINALITY_RESPONSE_MAX_BYTES
    );
    assert_eq!(request.method, http::Method::GET);
    assert!(request.body.is_empty());
}

#[tokio::test]
async fn native_payment_online_proof_rejects_wrong_height_media_and_noncanonical_frame_without_retry()
 {
    let expected = proof();
    let (source, transport) = source([response(&expected)]);
    assert!(source.proof(NonZeroU64::new(2).unwrap()).await.is_err());
    assert_eq!(transport.requests.lock().unwrap().len(), 1);

    let mut wrong_media = response(&expected);
    wrong_media
        .headers_mut()
        .insert("content-type", "application/json".parse().unwrap());
    let (source, transport) = self::source([wrong_media]);
    assert!(source.proof(NonZeroU64::MIN).await.is_err());
    assert_eq!(transport.requests.lock().unwrap().len(), 1);

    let mut noncanonical = response(&expected);
    noncanonical.body_mut().push(0);
    let (source, transport) = self::source([noncanonical]);
    assert!(source.proof(NonZeroU64::MIN).await.is_err());
    assert_eq!(transport.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn native_payment_online_proof_backpressure_preserves_deadline_and_yields_runtime() {
    let expected = proof();
    let (source, transport) = source([busy(), response(&expected)]);
    let client = source
        .0
        .client()
        .with_request_deadline(Instant::now() + Duration::from_secs(5));
    let source = OnlinePaymentSource(client.account_client().unwrap());
    let read = source.proof(NonZeroU64::MIN);
    let other_work = async {
        assert_eq!(
            transport.requests.lock().unwrap().len(),
            1,
            "proof backpressure must yield the runtime before its bounded retry"
        );
    };
    let (result, ()) = tokio::join!(read, other_work);
    assert_eq!(result.unwrap(), expected);
    let requests = transport.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].url, requests[1].url);
    assert!(requests[1].timeout.unwrap() < requests[0].timeout.unwrap());
}

#[tokio::test]
async fn native_payment_online_proof_never_invents_retry_authority_or_extends_deadline() {
    for remaining in [None, Some(Duration::from_millis(50)), Some(Duration::ZERO)] {
        let (source, transport) = source([busy()]);
        let client: Client = match remaining {
            Some(remaining) => source
                .0
                .client()
                .with_request_deadline(Instant::now() + remaining),
            None => source.0.client().clone(),
        };
        let source = OnlinePaymentSource(client.account_client().unwrap());
        assert!(source.proof(NonZeroU64::MIN).await.is_err());
        assert_eq!(
            transport.requests.lock().unwrap().len(),
            usize::from(remaining != Some(Duration::ZERO))
        );
    }
}
