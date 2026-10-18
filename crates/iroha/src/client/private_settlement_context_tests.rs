//! Bounded async context transport returns data only; finality authority remains separate.
use super::*;
use crate::{
    client::evidence_http_tests::{client_with_base_url, mark_data_model_compatible},
    http::{HttpTransport, TransportFuture, TransportRequest},
    http_default::DefaultHttpTransport,
};
use iroha_data_model::nexus::{
    PrivateSettlementContextRequestV1, PrivateSettlementContextsProofV1, PrivateSettlementPoolKeyV1,
};
use iroha_test_samples::private_settlement::context_fixture;
use std::sync::{Arc, Mutex};
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
async fn account_context_transport_binds_exact_selector_and_enforces_codec_status_and_bound() {
    let client = client_with_base_url("http://context.invalid/provider/v1/".parse().unwrap());
    let proof = context_fixture(client.network_id(), client.account());
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
        let client = client
            .clone()
            .with_test_http_transport(DefaultHttpTransport::from_shared(transport.clone()));
        mark_data_model_compatible(&client);
        let result = client
            .account_client()
            .unwrap()
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
async fn account_context_genesis_selector_never_reaches_transport() {
    let transport = Arc::new(Transport {
        response: Mutex::new(None),
        requests: Mutex::new(Vec::new()),
    });
    let client = client_with_base_url("http://context.invalid/".parse().unwrap())
        .with_test_http_transport(DefaultHttpTransport::from_shared(transport.clone()));
    let proof = context_fixture(client.network_id(), client.account());
    let key = PrivateSettlementPoolKeyV1 {
        route: proof.pool.pool.route,
        pool_id: proof.pool.pool.pool_id,
    };
    assert!(
        client
            .account_client()
            .unwrap()
            .get_private_settlement_context_async(
                NonZeroU64::new(1).unwrap(),
                PrivateSettlementContextRequestV1 { pools: vec![key] }
            )
            .await
            .is_err()
    );
    assert!(transport.requests.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn account_finality_transport_preserves_exact_height_scope_and_codec_checks() {
    use iroha_data_model::{
        block::consensus::SumeragiRootScope, testing::native_finality::NativeFinalityFixture,
    };
    let native = NativeFinalityFixture::start("account-finality-delegate");
    let proof = native.genesis_proof().clone();
    let mut client = client_with_base_url("http://context.invalid/provider/v1/".parse().unwrap());
    client.chain = native.chain_id().parse().unwrap();
    client.network_id = NetworkId::from_genesis_hash(proof.block_header.hash());
    for (height, scope, media, success) in [
        (1, SumeragiRootScope::Global, "application/x-norito", true),
        (2, SumeragiRootScope::Global, "application/x-norito", false),
        (1, SumeragiRootScope::Global, "application/json", false),
        (
            1,
            SumeragiRootScope::Dataspace {
                parent_network_id: client.network_id,
                dataspace_id: iroha_model_base::topology::DataSpaceId::new(71),
            },
            "application/x-norito",
            false,
        ),
    ] {
        let transport = Arc::new(Transport {
            response: Mutex::new(Some(
                http::Response::builder()
                    .status(200)
                    .header("content-type", media)
                    .body(norito::encode_canonical(&proof).unwrap())
                    .unwrap(),
            )),
            requests: Mutex::new(Vec::new()),
        });
        let client = client
            .clone()
            .with_test_http_transport(DefaultHttpTransport::from_shared(transport.clone()));
        mark_data_model_compatible(&client);
        let result = client
            .account_client()
            .unwrap()
            .get_sumeragi_finality_proof_async(NonZeroU64::new(height).unwrap(), scope)
            .await;
        assert_eq!(result.is_ok(), success);
        if success {
            assert_eq!(result.unwrap(), proof);
        }
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, http::Method::GET);
        assert_eq!(
            requests[0].url.path(),
            format!("/provider/v1/bridge/finality/{height}")
        );
        assert_eq!(
            requests[0].max_response_bytes,
            SUMERAGI_FINALITY_RESPONSE_MAX_BYTES
        );
    }
}
