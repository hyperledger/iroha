//! Actual canonical route authentication against a genuine native account; no inventory authority fixture.
use super::*;
use crate::{
    router::builder::{RouterBuilder, catalog_post},
    tests_runtime_handlers::{
        app_auth_test_guard, mk_app_state_for_tests, signed_network_app_headers,
    },
};
use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, DefaultBodyLimit},
    http::{Method, Request, Uri, header},
};
use iroha_core::{
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    account::AccountId,
    musubi::ArchiveId,
    sorafs::{capacity::ProviderId, pin_registry::ReplicationOrderId},
};
use iroha_torii_shared::route_catalog::{
    EnabledFeatures, RouteCatalog, sorafs::PROVIDER_ATTESTATION,
};
use std::sync::Arc;
use tower::ServiceExt as _;

fn router(app: SharedAppState) -> Router {
    let mut builder = RouterBuilder::new(
        app.clone(),
        RouteCatalog::new(&[PROVIDER_ATTESTATION]),
        EnabledFeatures::new(&["app_api"]),
    )
    .unwrap();
    builder.route(
        &PROVIDER_ATTESTATION,
        catalog_post(read_attestation)
            .layer(DefaultBodyLimit::max(4096))
            .authenticated_canonical_account_body(app.clone(), 4096),
    );
    let (router, manifest) = builder.finish().unwrap();
    router
        .layer(axum::middleware::from_fn_with_state(
            manifest.route_index(),
            crate::attach_matched_route_metadata,
        ))
        .layer(axum::middleware::from_fn(
            crate::enforce_catalog_private_no_store,
        ))
        .with_state(app)
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_inventory_route_requires_canonical_signature_and_refuses_unconfigured_local_provider()
 {
    let _guard = app_auth_test_guard(crate::app_auth::CanonicalRequestAuthConfig::default());
    let signer = KeyPair::from_seed(vec![0xBB; 32], Algorithm::Ed25519);
    let account = AccountId::new(signer.public_key().clone());
    let mut config = TestChainConfig::new(World::new(), 1_000);
    config.genesis_key = signer.clone();
    let chain = CertifiedTestChain::start(config).unwrap();
    let mut app = mk_app_state_for_tests();
    let state = Arc::get_mut(&mut app).unwrap();
    state.state = Arc::clone(chain.state());
    state.kura = Arc::clone(chain.kura());
    state.chain_id = Arc::new(chain.state().chain_id_ref().clone());
    state.signed_query_admission = Arc::new(
        crate::routing::SignedQueryAdmission::new(
            chain.network_id(),
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(120),
            std::num::NonZeroUsize::new(1_024).unwrap(),
        )
        .expect("native inventory query admission"),
    );
    assert!(state.sorafs_provider_attestation_inventory.is_none());
    assert!(state.sorafs_node.capacity_provider_id().is_none());
    let app = router(app);
    let key = MusubiProviderBundleAttestationKeyV1 {
        archive_id: ArchiveId::new([1; 32]),
        replication_order: ReplicationOrderId::new([2; 32]),
        provider_id: ProviderId::new([3; 32]),
    };
    let exact = norito::encode_canonical(&key).unwrap();
    let request = |bytes: Vec<u8>, signed: bool| {
        let uri: Uri = PROVIDER_ATTESTATION.path().parse().unwrap();
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(uri.clone())
            .header(header::CONTENT_TYPE, "application/x-norito")
            .body(Body::from(bytes.clone()))
            .unwrap();
        if signed {
            request.headers_mut().extend(signed_network_app_headers(
                &chain.network_id(),
                &account,
                &signer,
                &Method::POST,
                &uri,
                &bytes,
            ));
        }
        request.extensions_mut().insert(ConnectInfo(
            "127.0.0.1:15431".parse::<std::net::SocketAddr>().unwrap(),
        ));
        request
    };
    for (bytes, signed, status) in [
        (exact.clone(), false, StatusCode::UNAUTHORIZED),
        (exact, true, StatusCode::FORBIDDEN),
        (vec![1], true, StatusCode::BAD_REQUEST),
    ] {
        let response = app.clone().oneshot(request(bytes, signed)).await.unwrap();
        assert_eq!(response.status(), status);
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "private, no-store"
        );
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert!(
            norito::decode_canonical::<
                iroha_data_model::musubi::MusubiProviderBundleVerificationAttestationV1,
            >(&body)
            .is_err()
        );
    }
}

#[test]
fn native_inventory_working_limit_preserves_fixed_response_reservation() {
    for bytes in [0, MAX_RESPONSE - 1, MAX_RESPONSE] {
        assert!(limits(bytes).is_none());
    }
    let selected = limits(MAX_RESPONSE + 8192).unwrap();
    assert_eq!(selected.max_total_allocated_bytes(), 8192);
    assert_eq!(
        authorization(ProviderAttestationInventoryReadErrorV1::Rejected),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        authorization(ProviderAttestationInventoryReadErrorV1::Unavailable),
        StatusCode::SERVICE_UNAVAILABLE
    );
}
