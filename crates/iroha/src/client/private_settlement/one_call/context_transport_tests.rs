//! Bounded async context transport returns data only; finality authority remains separate.
use super::*;
use crate::{
    client::evidence_http_tests::{client_with_base_url, mark_data_model_compatible},
    http::{HttpTransport, TransportFuture, TransportRequest},
    http_default::DefaultHttpTransport,
};
#[derive(Debug)]
struct Transport {
    response: Mutex<Option<http::Response<Vec<u8>>>>,
    requests: Mutex<Vec<TransportRequest>>,
}
impl HttpTransport for Transport {
    fn send_blocking(&self, _: TransportRequest) -> eyre::Result<http::Response<Vec<u8>>> {
        panic!("context must use async transport")
    }
    fn send(&self, request: TransportRequest) -> TransportFuture<'_> {
        Box::pin(async move {
            self.requests.lock().unwrap().push(request);
            self.response
                .lock()
                .unwrap()
                .take()
                .ok_or_else(|| eyre::eyre!("unexpected read"))
        })
    }
}
#[tokio::test(flavor = "current_thread")]
async fn private_onecall_context_transport_binds_exact_selector_and_enforces_codec_status_and_bound()
 {
    let proof = super::artifacts::tests::context_fixture();
    let key = PrivateSettlementPoolKeyV1 {
        route: proof.pool.pool.route,
        pool_id: proof.pool.pool.pool_id,
    };
    let selectors = PrivateSettlementContextRequestV1 { pools: vec![key] };
    let proof = PrivateSettlementContextsProofV1 {
        contexts: vec![proof],
    };
    for (status, media, trailing, success) in [
        (200, "application/x-norito", false, true),
        (202, "application/x-norito", false, false),
        (200, "application/json", false, false),
        (200, "application/x-norito", true, false),
    ] {
        let mut body = norito::encode_canonical(&proof).unwrap();
        if trailing {
            body.push(0);
        }
        let transport = Arc::new(Transport {
            response: Mutex::new(Some(
                http::Response::builder()
                    .status(status)
                    .header("content-type", media)
                    .body(body)
                    .unwrap(),
            )),
            requests: Mutex::new(Vec::new()),
        });
        let client = client_with_base_url("http://context.invalid/provider/v1/".parse().unwrap())
            .with_test_http_transport(DefaultHttpTransport::from_shared(transport.clone()));
        mark_data_model_compatible(&client);
        let result = client
            .get_private_settlement_context_async(NonZeroU64::new(2).unwrap(), selectors.clone())
            .await;
        assert_eq!(result.is_ok(), success);
        if success {
            assert_eq!(
                result.unwrap(),
                proof,
                "transport must not silently replace selected originals"
            );
        }
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.method, http::Method::POST);
        assert_eq!(
            request.url.path(),
            "/provider/v1/nexus/private-settlements/context/2"
        );
        assert_eq!(request.body, norito::encode_canonical(&selectors).unwrap());
        assert_eq!(
            request.max_response_bytes,
            iroha_data_model::sumeragi_finality::MAX_WORLD_STATE_SNAPSHOT_BYTES_V1
        );
        for name in [
            "x-iroha-account",
            "x-iroha-signature",
            "x-iroha-timestamp-ms",
            "x-iroha-nonce",
        ] {
            assert!(
                request
                    .headers
                    .iter()
                    .any(|(actual, value)| actual.as_str().eq_ignore_ascii_case(name)
                        && !value.is_empty())
            );
        }
    }
}
#[tokio::test(flavor = "current_thread")]
async fn private_onecall_context_genesis_selector_never_reaches_transport() {
    let transport = Arc::new(Transport {
        response: Mutex::new(None),
        requests: Mutex::new(Vec::new()),
    });
    let client = client_with_base_url("http://context.invalid/".parse().unwrap())
        .with_test_http_transport(DefaultHttpTransport::from_shared(transport.clone()));
    let proof = super::artifacts::tests::context_fixture();
    let key = PrivateSettlementPoolKeyV1 {
        route: proof.pool.pool.route,
        pool_id: proof.pool.pool.pool_id,
    };
    assert!(
        client
            .get_private_settlement_context_async(
                NonZeroU64::new(1).unwrap(),
                PrivateSettlementContextRequestV1 { pools: vec![key] }
            )
            .await
            .is_err()
    );
    assert!(transport.requests.lock().unwrap().is_empty());
}
