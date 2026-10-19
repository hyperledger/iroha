//! Actual routed H2 context and revocation while its original worker result awaits polling.
//!
//! The blocking pool is occupied before the request's first poll. Returning the worker-owned
//! query permit proves physical producer completion, while the routed future remains unpolled.
//! This exercises a real worker-await boundary, not an injected handler hook.

use super::*;
use iroha_core::sumeragi::test_chain::{CertifiedTestChain, native_private_context_route_fixture};
use iroha_data_model::{
    nexus::PrivateSettlementContextsProofV1,
    sumeragi_finality::{FinalityValidator, SumeragiFinalityVerifier, VerifiedSumeragiBlock},
};
use iroha_executor_data_model::permission::query::CanReadAllLedgerData;
use iroha_torii_shared::route_catalog::{RouteCatalog, private_settlement::CONTEXT};
use std::{future::Future as _, sync::mpsc, task::Poll, time::Duration};

fn routed_context(app: SharedAppState) -> axum::Router {
    let mut builder = RouterBuilder::new(
        app.clone(),
        RouteCatalog::new(&[CONTEXT]),
        compiled_route_features(),
    )
    .unwrap();
    builder.route(
        &CONTEXT,
        catalog_post(handler)
            .layer(axum::extract::DefaultBodyLimit::max(
                PRIVATE_SETTLEMENT_CONTEXT_REQUEST_MAX_BYTES_V1,
            ))
            .authenticated_in_handler(HandlerAuthentication::CanonicalAccountSignature),
    );
    let (router, manifest) = builder.finish().unwrap();
    router
        .layer(axum::middleware::from_fn_with_state(
            manifest.route_index(),
            attach_matched_route_metadata,
        ))
        .layer(axum::middleware::from_fn(enforce_catalog_private_no_store))
        .with_state(app)
}

fn verified_tip(chain: &CertifiedTestChain) -> VerifiedSumeragiBlock {
    let validators = chain
        .validators()
        .iter()
        .map(|(peer, pop)| FinalityValidator {
            public_key: peer.public_key().clone(),
            proof_of_possession: pop.clone(),
        })
        .collect();
    let mut verifier = SumeragiFinalityVerifier::new(
        chain.genesis(),
        chain.state().chain_id_ref().as_str(),
        validators,
    )
    .unwrap();
    let view = chain.state().view();
    let mut last = None;
    for height in 1..=chain.height() {
        last = Some(
            verifier
                .verify(&iroha_core::sumeragi::finality::build_proof(&view, height).unwrap())
                .unwrap(),
        );
    }
    last.unwrap()
}

fn worker_boundary_case(revoke: bool) {
    // No executor scheduling or certificate shortcuts are installed in the handler. This
    // runtime only lets the test retain its own blocking-pool slot until the first poll.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let (chain, key, signer) = native_private_context_route_fixture();
        assert_eq!(chain.height(), 2);
        let verified = verified_tip(&chain);
        let account = AccountId::new(signer.public_key().clone());
        let selectors = PrivateSettlementContextRequestV1 { pools: vec![key] };
        let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests();
        let unique = Arc::get_mut(&mut app).unwrap();
        unique.state = chain.state().clone();
        unique.kura = chain.kura().clone();
        unique.chain_id = Arc::new(chain.state().chain_id_ref().clone());
        unique.query_inflight = Arc::new(tokio::sync::Semaphore::new(1));
        unique.query_heavy_inflight = Arc::new(tokio::sync::Semaphore::new(1));
        unique.query_queue_timeout = Duration::ZERO;
        if revoke {
            // A missing post-worker check would reach the real exact-byte limiter and return
            // 429 before the final synchronous permission guard. Requiring 403 distinguishes
            // the first recheck from a later guard or a generic producer refusal.
            unique.proof_egress_limiter = limits::RateLimiter::new_u64(Some(1), Some(1));
        }
        require_permission(&app, &account, &selectors).unwrap();
        let general = app.query_inflight.clone();
        let heavy = app.query_heavy_inflight.clone();
        let router = routed_context(app.clone());
        let uri: Uri = "/v1/nexus/private-settlements/context/2".parse().unwrap();
        let body = norito::encode_canonical(&selectors).unwrap();
        let mut headers = crate::tests_runtime_handlers::signed_network_app_headers(
            app.state.network_id_ref(),
            &account,
            &signer,
            &Method::POST,
            &uri,
            &body,
        );
        headers.insert(
            axum::http::header::ACCEPT,
            HeaderValue::from_static("application/x-norito"),
        );
        let mut request = axum::http::Request::builder()
            .method(Method::POST)
            .uri(uri)
            .body(Body::from(body))
            .unwrap();
        *request.headers_mut() = headers;
        request.extensions_mut().insert(axum::extract::ConnectInfo(
            "127.0.0.1:19080".parse::<std::net::SocketAddr>().unwrap(),
        ));

        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel::<()>(1);
        let blocker = tokio::task::spawn_blocking(move || {
            started_tx.send(()).unwrap();
            // Dropping release_tx on an assertion failure also releases the original slot.
            let _ = release_rx.recv();
        });
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let mut response = Box::pin(router.oneshot(request));
        let first = futures::future::poll_fn(|cx| Poll::Ready(response.as_mut().poll(cx))).await;
        assert!(first.is_pending(), "the real request is suspended");
        assert_eq!(
            general.available_permits(),
            0,
            "the actual worker owns admission"
        );
        assert_eq!(heavy.available_permits(), 0);
        drop(release_tx);
        blocker.await.unwrap();
        // Do not poll response again: only the producer is allowed to make progress here.
        let completed =
            tokio::time::timeout(Duration::from_secs(30), general.clone().acquire_owned())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(
            heavy.available_permits(),
            1,
            "physical worker released its entire admission"
        );

        if revoke {
            // Publish only the existing typed permission change through the standard test
            // World overlay. The already encoded H2 proof remains retained in the worker result;
            // this test does not claim a distributed or newly certified revocation transaction.
            let mut block = app.state.block(iroha_data_model::block::BlockHeader::new(
                std::num::NonZeroU64::new(3).unwrap(),
                None,
                None,
                2_001,
                0,
            ));
            let mut tx = block.transaction();
            assert!(
                tx.world_mut_for_testing()
                    .remove_account_permission(&account, &CanReadAllLedgerData.into(),)
            );
            tx.apply();
            block.commit_world_overlay_for_testing().unwrap();
        }
        let response = tokio::time::timeout(Duration::from_secs(5), response)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CACHE_CONTROL)
                .unwrap(),
            "private, no-store"
        );
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), MAX_WORLD_STATE_SNAPSHOT_BYTES_V1)
            .await
            .unwrap();
        if revoke {
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "post-worker revocation precedes exact-byte egress"
            );
            let expected = Error::Query(iroha_data_model::ValidationFail::NotPermitted(
                "private context full World snapshot requires all-ledger read permission".into(),
            ))
            .into_response();
            let expected = axum::body::to_bytes(expected.into_body(), 8192)
                .await
                .unwrap();
            assert_eq!(
                bytes, expected,
                "only the fixed public permission error may leave the handler"
            );
            assert!(PrivateSettlementContextsProofV1::decode_frame(&bytes).is_err());
        } else {
            assert_eq!(
                status,
                StatusCode::OK,
                "the same actual worker setup must produce a valid context"
            );
            assert!(bytes.len() > 1);
            let proof = PrivateSettlementContextsProofV1::decode_frame(&bytes).unwrap();
            proof
                .verify(
                    chain.network_id(),
                    iroha_core::state::State::native_world_schema_hash_v1().unwrap(),
                    &selectors,
                    &verified,
                )
                .unwrap();
        }
        drop(completed);
        assert_eq!(general.available_permits(), 1);
    });
}

#[test]
fn private_context_routed_worker_returns_actual_paid_certified_proof() {
    worker_boundary_case(false);
}

#[test]
fn private_context_routed_worker_revocation_returns_only_private_403() {
    worker_boundary_case(true);
}
