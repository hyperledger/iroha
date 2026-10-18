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
    let client = client_with_base_url("http://context.invalid/provider/".parse().unwrap());
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
        block::{CommitCertificate, consensus::SumeragiRootScope, decode_framed_signed_block},
        sumeragi_finality::{
            CertifiedResultScope, CertifiedResultV1, SccpFinalityHeaderV1,
            certified_result::FLAG_ACTIVE, context_committee_root,
        },
        testing::native_finality::NativeFinalityFixture,
    };
    let native = NativeFinalityFixture::start("account-finality-delegate");
    let proof = native.genesis_proof().clone();
    // This result-only genesis variant tests the structural scope gate. It is
    // synthetic execution data, not authenticated genesis execution or authority.
    let mut active_block = decode_framed_signed_block(&proof.block_wire).unwrap();
    let certificate = active_block.commit_certificate().unwrap();
    let result = CertifiedResultV1::decode(
        certificate.result_preimage(),
        CertifiedResultScope::TairaGlobal,
    )
    .unwrap();
    let mut fields = result.header().fields();
    fields.flags = FLAG_ACTIVE;
    fields.generation = 1;
    fields.committee_root = context_committee_root(&result.commitment().schedule.current).unwrap();
    let active_result = CertifiedResultV1::new(
        SccpFinalityHeaderV1::from_fields(&fields).unwrap(),
        result.commitment().clone(),
        CertifiedResultScope::TairaGlobal,
    )
    .unwrap();
    let active_certificate = CommitCertificate::from_untrusted_parts(
        certificate.consensus_header().to_vec(),
        certificate.commit_qc().to_vec(),
        active_result.preimage().unwrap(),
        certificate.availability().to_vec(),
    );
    active_block.set_commit_certificate(Some(active_certificate));
    let mut active_proof = proof.clone();
    active_proof.block_wire = active_block.encode_wire().unwrap();
    let mut client = client_with_base_url("http://context.invalid/provider/".parse().unwrap());
    client.chain = native.chain_id().parse().unwrap();
    client.network_id = NetworkId::from_genesis_hash(proof.block_header.hash());
    let private_scope = SumeragiRootScope::Dataspace {
        parent_network_id: client.network_id,
        dataspace_id: iroha_model_base::topology::DataSpaceId::new(71),
    };
    for (case, response_proof, height, scope, media, success) in [
        (
            "inactive global",
            &proof,
            1,
            SumeragiRootScope::Global,
            "application/x-norito",
            true,
        ),
        (
            "wrong height",
            &proof,
            2,
            SumeragiRootScope::Global,
            "application/x-norito",
            false,
        ),
        (
            "wrong media type",
            &proof,
            1,
            SumeragiRootScope::Global,
            "application/json",
            false,
        ),
        // Inactive X is structurally valid under either scope; the independent
        // signed-genesis verifier owns exact root identity authentication.
        (
            "inactive private scope",
            &proof,
            1,
            private_scope,
            "application/x-norito",
            true,
        ),
        (
            "active global",
            &active_proof,
            1,
            SumeragiRootScope::Global,
            "application/x-norito",
            true,
        ),
        (
            "active private scope",
            &active_proof,
            1,
            private_scope,
            "application/x-norito",
            false,
        ),
    ] {
        let transport = Arc::new(Transport {
            response: Mutex::new(Some(
                http::Response::builder()
                    .status(200)
                    .header("content-type", media)
                    .body(norito::encode_canonical(response_proof).unwrap())
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
        assert_eq!(result.is_ok(), success, "{case}: {result:?}");
        if success {
            assert_eq!(&result.unwrap(), response_proof);
        } else if case == "active private scope" {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("a non-global root carries an active finality header")
            );
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
