//! Actual paid H2 AMX route, retained physical-worker custody and current read-role revocation.
//!
//! The single blocking slot suspends the real routed worker before production. Returning
//! its actual query admission proves physical completion while the HTTP future stays unpolled.
//! A test World overlay changes role membership only after that completion. Genuine committed
//! role deletion/restart is separately exercised by the independent-root live fixture.

use super::*;
use iroha_core::sumeragi::test_chain::{CertifiedTestChain, native_amx_approval_route_fixture};
use iroha_data_model::{
    sumeragi_amx::AmxDebitApprovalProofV1,
    sumeragi_finality::{FinalityValidator, SumeragiFinalityVerifier, VerifiedSumeragiBlock},
};
use iroha_torii_shared::route_catalog::{
    RouteCatalog, contracts_and_verification_keys::AMX_DEBIT_APPROVAL_PROOF_POST,
};
use std::{future::Future as _, sync::mpsc, task::Poll, time::Duration};
use tower::ServiceExt as _;

fn routed_approval(app: SharedAppState) -> axum::Router {
    let mut builder = RouterBuilder::new(
        app.clone(),
        RouteCatalog::new(&[AMX_DEBIT_APPROVAL_PROOF_POST]),
        compiled_route_features(),
    )
    .unwrap();
    builder.route(
        &AMX_DEBIT_APPROVAL_PROOF_POST,
        catalog_post(handler)
            .layer(axum::extract::DefaultBodyLimit::max(
                MAX_AMX_DEBIT_APPROVAL_PERMISSION_BYTES_V1,
            ))
            .authenticated_in_handler(HandlerAuthentication::CanonicalAccountSignature),
    );
    let (router, manifest) = builder.finish().unwrap();
    router
        .layer(axum::middleware::from_fn(capture_response_format))
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Allowed,
    Revoked,
    EgressLimited,
    Cancelled,
}

fn worker_boundary_case(outcome: Outcome) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let (chain, approval, signer) = native_amx_approval_route_fixture();
        let verified = verified_tip(&chain);
        let account = AccountId::new(signer.public_key().clone());
        let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests();
        let unique = Arc::get_mut(&mut app).unwrap();
        unique.state = chain.state().clone();
        unique.kura = chain.kura().clone();
        unique.chain_id = Arc::new(chain.state().chain_id_ref().clone());
        unique.query_inflight = Arc::new(tokio::sync::Semaphore::new(1));
        unique.query_heavy_inflight = Arc::new(tokio::sync::Semaphore::new(1));
        unique.query_queue_timeout = Duration::ZERO;
        // The actual private-root listener still requires its independent credential.
        unique.api_token_digests = Arc::new(limits::ApiTokenDigestSet::from_tokens(["amx-worker-local-test"]));
        if matches!(outcome, Outcome::Revoked | Outcome::EgressLimited) {
            // Without the post-worker check, revocation reaches this real one-byte
            // exact-egress limiter and returns 429 before the final disclosure guard.
            unique.proof_egress_limiter = limits::RateLimiter::new_u64(Some(1), Some(1));
        }
        require_full_ledger_carrier_permission(&app, &account).unwrap();
        let general = app.query_inflight.clone();
        let heavy = app.query_heavy_inflight.clone();
        let pool = app.query_fanout_inflight.clone();
        let baseline_bytes = pool.available_bytes();
        let router = routed_approval(app.clone());
        let uri: axum::http::Uri = "/v1/amx/debit-approval/2".parse().unwrap();
        let body = norito::encode_canonical(&approval).unwrap();
        let mut headers = crate::tests_runtime_handlers::signed_network_app_headers(
            app.state.network_id_ref(), &account, &signer, &Method::POST, &uri, &body,
        );
        headers.insert(axum::http::header::ACCEPT, HeaderValue::from_static("application/x-norito"));
        headers.insert("x-api-token", HeaderValue::from_static("amx-worker-local-test"));
        let mut request = axum::http::Request::builder().method(Method::POST).uri(uri)
            .body(Body::from(body)).unwrap();
        *request.headers_mut() = headers;
        request.extensions_mut().insert(axum::extract::ConnectInfo(
            "127.0.0.1:19080".parse::<std::net::SocketAddr>().unwrap(),
        ));
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel::<()>(1);
        let blocker = tokio::task::spawn_blocking(move || {
            started_tx.send(()).unwrap();
            let _ = release_rx.recv();
        });
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let mut response = Box::pin(router.oneshot(request));
        let first = futures::future::poll_fn(|cx| Poll::Ready(response.as_mut().poll(cx))).await;
        assert!(first.is_pending(), "the original routed future is suspended");
        assert_eq!(general.available_permits(), 0);
        assert_eq!(heavy.available_permits(), 0);
        let worker_retained_bytes = pool.available_bytes();
        assert!(worker_retained_bytes < baseline_bytes);

        if outcome == Outcome::Cancelled {
            drop(response);
            assert_eq!(general.available_permits(), 0, "cancellation cannot refund the queued physical worker");
            assert_eq!(heavy.available_permits(), 0);
            assert_eq!(pool.available_bytes(), worker_retained_bytes);
            drop(release_tx);
            blocker.await.unwrap();
            let completed = tokio::time::timeout(Duration::from_secs(30), general.clone().acquire_owned()).await.unwrap().unwrap();
            assert_eq!(heavy.available_permits(), 1);
            // Joining admission can precede dropped result destruction by a few instructions.
            // Acquiring the original whole byte pool proves the final detached result was freed.
            let refunded = tokio::time::timeout(Duration::from_secs(5),
                pool.semaphore.clone().acquire_many_owned(pool.total_permits.get())).await.unwrap().unwrap();
            drop(refunded);
            assert_eq!(pool.available_bytes(), baseline_bytes);
            drop(completed);
            return;
        }
        drop(release_tx);
        blocker.await.unwrap();
        // Do not poll the HTTP future; only the physical producer may complete here.
        let completed = tokio::time::timeout(Duration::from_secs(30), general.clone().acquire_owned()).await.unwrap().unwrap();
        assert_eq!(heavy.available_permits(), 1);
        assert_eq!(pool.available_bytes(), worker_retained_bytes,
            "the original authentication and response allocations stay with the completed result");
        if outcome == Outcome::Revoked {
            let mut block = app.state.block(iroha_data_model::block::BlockHeader::new(
                std::num::NonZeroU64::new(3).unwrap(), None, None, 2_001, 0,
            ));
            let mut tx = block.transaction();
            tx.world_mut_for_testing().remove_account_roles(&account);
            tx.apply();
            block.commit_world_overlay_for_testing().unwrap();
            assert!(require_full_ledger_carrier_permission(&app, &account).is_err());
            assert!(torii_account_has_permission(app.state.view().world(), &account, &approval.permission().unwrap()),
                "read-role removal must not remove the exact direct debit approval");
        }
        let response = tokio::time::timeout(Duration::from_secs(5), response).await.unwrap().unwrap();
        assert_eq!(response.headers()[axum::http::header::CACHE_CONTROL], "private, no-store");
        assert_eq!(response.headers()[axum::http::header::CONTENT_TYPE], "application/x-norito");
        let status = response.status();
        if outcome == Outcome::Allowed {
            assert_eq!(status, StatusCode::OK, "the same physical worker must produce a genuine paid certified proof");
            assert!(pool.available_bytes() < baseline_bytes, "original response allocation survives handler completion");
            let bytes = axum::body::to_bytes(response.into_body(), MAX_AMX_DEBIT_APPROVAL_PROOF_BYTES_V1).await.unwrap();
            assert!(bytes.len() > 1);
            let proof = AmxDebitApprovalProofV1::decode_frame(&bytes).unwrap();
            proof.verify(&approval, &account, iroha_core::state::State::native_world_schema_hash_v1().unwrap(), &verified).unwrap();
            drop(bytes);
        } else {
            let (expected_status, expected_error) = if outcome == Outcome::Revoked {
                (StatusCode::FORBIDDEN, require_full_ledger_carrier_permission(&app, &account).unwrap_err())
            } else {
                (StatusCode::TOO_MANY_REQUESTS, Error::ProofRateLimited {
                    endpoint: ROUTE, retry_after_secs: app.proof_limits.retry_after.as_secs().max(1),
                })
            };
            assert_eq!(status, expected_status, "current permission is checked before exact-byte egress; authorized capacity remains typed");
            let expected = axum::body::to_bytes(expected_error.into_response().into_body(), usize::MAX).await.unwrap();
            let bytes = axum::body::to_bytes(response.into_body(), expected.len()).await.unwrap();
            assert_eq!(bytes, expected, "only the exact negotiated public error frame may leave the handler");
        }
        assert_eq!(pool.available_bytes(), baseline_bytes);
        drop(completed);
        assert_eq!(general.available_permits(), 1);
    });
}

#[test]
fn amx_approval_routed_worker_returns_actual_paid_certified_role_authorized_proof() {
    worker_boundary_case(Outcome::Allowed);
}
#[test]
fn amx_approval_routed_worker_revocation_precedes_egress_and_returns_only_private_403() {
    worker_boundary_case(Outcome::Revoked);
}
#[test]
fn amx_approval_routed_worker_authorized_egress_capacity_remains_429() {
    worker_boundary_case(Outcome::EgressLimited);
}
#[test]
fn amx_approval_routed_worker_cancellation_retains_original_admission_and_allocations() {
    worker_boundary_case(Outcome::Cancelled);
}
