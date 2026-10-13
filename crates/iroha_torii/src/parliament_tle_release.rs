//! Authenticated local partial-release service for Parliament timed opening.
//!
//! Routing and canonical account authentication are mounted in `lib.rs`. This
//! module owns only identifier validation, blocking runtime isolation, Core
//! authorization, and payload-free failure mapping.

use std::sync::Arc;

use axum::body::Body;
use iroha_core::tle_release::TleReleaseAuthorizationErrorV1;
use iroha_core::tle_release::TleReleaseCoordinatorErrorV1;
use iroha_core::tle_release::TleReleaseCoordinatorV1;
use iroha_core_timed_ovn::tle::TlePartialReleaseShareV1;
use iroha_data_model::governance::types::BallotAttemptId;

/// Consume at most one byte and enforce the partial-release zero-body contract.
///
/// This must be called only after canonical authentication. Using the raw body
/// here avoids a buffering extractor running before the access gate, while the
/// one-byte limit rejects headerless HTTP/2 bodies without admitting an
/// unbounded payload.
pub async fn require_empty_body_v1(body: Body) -> Result<(), crate::Error> {
    match axum::body::to_bytes(body, 1).await {
        Ok(bytes) if bytes.is_empty() => Ok(()),
        Ok(_) | Err(_) => Err(crate::Error::AppQueryValidation {
            code: "parliament_tle_partial_release_body_not_empty",
            message: "Parliament TLE partial-release requests must have an empty body".to_owned(),
        }),
    }
}

/// Parse one exact, nonzero Parliament ballot-attempt identifier.
fn parse_ballot_attempt_id(value: &str) -> Result<BallotAttemptId, crate::Error> {
    let ballot_attempt_id = value.parse::<BallotAttemptId>().map_err(|_| {
        crate::routing::conversion_error(
            "ballot_attempt_id must be exactly 64 lowercase hexadecimal characters".to_owned(),
        )
    })?;
    if ballot_attempt_id.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(crate::routing::conversion_error(
            "ballot_attempt_id must be non-zero".to_owned(),
        ));
    }
    Ok(ballot_attempt_id)
}

fn map_coordinator_error(error: TleReleaseCoordinatorErrorV1) -> crate::Error {
    match error {
        TleReleaseCoordinatorErrorV1::Authorization(
            TleReleaseAuthorizationErrorV1::MissingTimedOvnEvidence
            | TleReleaseAuthorizationErrorV1::MissingGovernanceAttempt
            | TleReleaseAuthorizationErrorV1::MissingBallot,
        ) => crate::Error::AppNotFound {
            code: "parliament_tle_release_not_found",
            message: "the requested Parliament TLE release state was not found".to_owned(),
        },
        TleReleaseCoordinatorErrorV1::Authorization(_) => crate::Error::AppConflict {
            code: "parliament_tle_release_not_authorized",
            message: "Core did not authorize a partial release from committed state".to_owned(),
        },
        TleReleaseCoordinatorErrorV1::SignerUnavailable => crate::Error::AppServiceUnavailable {
            code: "parliament_tle_release_signer_unavailable",
            message: "this node has no available Parliament TLE release signer".to_owned(),
        },
        TleReleaseCoordinatorErrorV1::SignerFailed => crate::Error::AppServiceUnavailable {
            code: "parliament_tle_release_signer_failed",
            message: "the Parliament TLE release signer could not produce a share".to_owned(),
        },
        TleReleaseCoordinatorErrorV1::InvalidSignerOutput => crate::Error::AppServiceUnavailable {
            code: "parliament_tle_release_signer_invalid_output",
            message: "the Parliament TLE release signer returned an invalid share".to_owned(),
        },
        TleReleaseCoordinatorErrorV1::InvalidPartialSet
        | TleReleaseCoordinatorErrorV1::InvalidFinalRelease => crate::Error::AppConflict {
            code: "parliament_tle_release_invalid_partial_set",
            message: "the Parliament TLE release partial set is invalid".to_owned(),
        },
    }
}

/// Request this node's proof-carrying partial for one committed ballot.
///
/// The route wrapper must enforce canonical account request authentication and
/// per-account admission before calling this function. It accepts no request
/// body and no caller-selected release identity, height, key session, participant
/// seat, or transcript. Core reconstructs those values from a point-in-time
/// committed query view before the runtime signer is invoked.
///
/// Signer work runs on the blocking pool because production implementations may synchronously call
/// a deployment-owned signing provider. The coordinator independently verifies the returned public
/// proof before this function returns; provider implementation details are outside the protocol.
///
/// # Errors
///
/// Returns a stable payload-free Torii error for an invalid identifier, rejected
/// Core authorization, unavailable signer, blocking-worker failure, or invalid
/// signer output.
pub async fn request_local_partial_release_v1(
    state: Arc<iroha_core::state::State>,
    coordinator: Arc<TleReleaseCoordinatorV1>,
    ballot_attempt_id: String,
    signer_admission: crate::QueryAdmissionPermit,
) -> Result<TlePartialReleaseShareV1, crate::Error> {
    let ballot_attempt_id = parse_ballot_attempt_id(&ballot_attempt_id)?;
    crate::panic_recovery::join_recoverable(crate::panic_recovery::spawn_blocking_recoverable(
        move || {
            // Keep physical signer capacity reserved even if the HTTP future is
            // cancelled and dropping its JoinHandle detaches this blocking task.
            let _signer_admission = signer_admission;
            let view = state.query_view();
            coordinator.request_partial_release(&view, ballot_attempt_id)
        },
    ))
    .await
    .map_err(|_| crate::Error::AppServiceUnavailable {
        code: "parliament_tle_release_worker_unavailable",
        message: "the Parliament TLE release worker is unavailable".to_owned(),
    })?
    .map_err(map_coordinator_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Extension, Router,
        http::{Method, Request, StatusCode, header::CONTENT_LENGTH},
        routing::post,
    };
    use http_body_util::BodyExt as _;
    use iroha_data_model::account::AccountId;
    use tower::ServiceExt as _;

    #[test]
    fn identifier_parser_rejects_noncanonical_and_zero_ids() {
        assert!(parse_ballot_attempt_id("not-a-ballot").is_err());
        assert!(parse_ballot_attempt_id(&"00".repeat(32)).is_err());
        assert!(parse_ballot_attempt_id(&"01".repeat(32)).is_ok());
    }

    #[test]
    fn coordinator_failure_mapping_exposes_only_closed_error_classes() {
        let provider_error = map_coordinator_error(TleReleaseCoordinatorErrorV1::SignerFailed);
        let rendered = provider_error.to_string();
        assert!(rendered.contains("parliament_tle_release_signer_failed"));
        assert!(!rendered.contains("handle"));
        assert!(!rendered.contains("share-metadata"));

        let early = map_coordinator_error(TleReleaseCoordinatorErrorV1::Authorization(
            TleReleaseAuthorizationErrorV1::ReleaseHeightNotReached,
        ));
        assert!(matches!(early, crate::Error::AppConflict { .. }));
        let missing = map_coordinator_error(TleReleaseCoordinatorErrorV1::Authorization(
            TleReleaseAuthorizationErrorV1::MissingTimedOvnEvidence,
        ));
        assert!(matches!(missing, crate::Error::AppNotFound { .. }));
    }

    #[test]
    fn route_passes_bounded_admission_into_the_physical_signer_task() {
        let route_source = include_str!("lib.rs");
        assert!(route_source.contains(
            "GOV_PARLIAMENT_TLE_PARTIAL_RELEASE => canonical_account_post(\
             handler_gov_parliament_tle_partial_release, app_state, 1);"
        ));
        let handler = route_source
            .split("async fn handler_gov_parliament_tle_partial_release")
            .nth(1)
            .and_then(|tail| tail.split("async fn handler_gov_citizen_status").next())
            .expect("partial-release route source");
        let access = handler
            .find("check_access(")
            .expect("canonical access gate");
        let body = handler
            .find("require_empty_body_v1(request.into_body()).await?;")
            .expect("bounded zero-body gate");
        let admission = handler
            .find("let signer_admission = acquire_query_admission(app.as_ref(), true).await?;")
            .expect("heavy admission gate");
        assert!(access < body && body < admission);
        assert!(handler.contains("ballot_attempt_id,\n        signer_admission,\n    )"));

        let service_source = include_str!("parliament_tle_release.rs");
        assert!(service_source.contains("let _signer_admission = signer_admission;"));
    }

    #[tokio::test]
    async fn route_authenticates_one_byte_before_rejecting_it_and_caps_larger_bodies() {
        async fn empty_body_gate(
            Extension(_verified): Extension<crate::app_auth::VerifiedCanonicalRequest>,
            request: Request<Body>,
        ) -> Result<StatusCode, crate::Error> {
            require_empty_body_v1(request.into_body()).await?;
            Ok(StatusCode::NO_CONTENT)
        }

        let _guard = crate::tests_runtime_handlers::app_auth_test_guard(
            crate::app_auth::CanonicalRequestAuthConfig::default(),
        );
        let key_pair = crate::tests_runtime_handlers::checked_torii_test_ed25519_keypair(
            0x5B,
            "derive Parliament partial-release auth fixture key",
        );
        let account_id = AccountId::new(key_pair.public_key().clone());
        let app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world(
            crate::tests_runtime_handlers::world_with_account(&account_id),
        );
        let route = "/v1/gov/parliament/ballots/test/partial-release";
        let router = Router::new().route(route, post(empty_body_gate)).layer(
            axum::middleware::from_fn_with_state(
                crate::CanonicalAccountBodyAuthState {
                    app,
                    max_body_bytes: 1,
                    missing_auth_code: "canonical_authentication_required",
                    missing_auth_message: "canonical account request authentication is required",
                },
                crate::enforce_canonical_account_body_authentication,
            ),
        );
        let method = Method::POST;
        let uri = route.parse().expect("partial-release URI");

        let one_byte = b"x";
        let headers = crate::tests_runtime_handlers::signed_app_headers(
            &account_id,
            &key_pair,
            &method,
            &uri,
            one_byte,
        );
        let mut request = Request::builder()
            .method(method.clone())
            .uri(uri.clone())
            .body(Body::from(one_byte.to_vec()))
            .expect("signed one-byte partial-release request");
        request.headers_mut().extend(headers);
        let response = router
            .clone()
            .oneshot(request)
            .await
            .expect("one-byte partial-release response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("one-byte rejection body")
            .to_bytes();
        let error = norito::decode_from_bytes::<crate::ErrorEnvelope>(&body)
            .expect("one-byte rejection envelope");
        assert_eq!(
            error.code(),
            "parliament_tle_partial_release_body_not_empty"
        );

        let oversized = b"xx";
        let headers = crate::tests_runtime_handlers::signed_app_headers(
            &account_id,
            &key_pair,
            &method,
            &uri,
            oversized,
        );
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::from(oversized.to_vec()))
            .expect("signed oversized partial-release request");
        request.headers_mut().extend(headers);
        let response = router
            .oneshot(request)
            .await
            .expect("oversized partial-release response");
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            response
                .headers()
                .get("x-iroha-reject-code")
                .and_then(|value| value.to_str().ok()),
            Some("request_payload_too_large")
        );
    }

    #[tokio::test]
    async fn zero_body_gate_accepts_the_normal_empty_request() {
        require_empty_body_v1(Body::empty())
            .await
            .expect("empty request body");
    }

    #[tokio::test]
    async fn zero_body_gate_rejects_headerless_http2_style_content() {
        let request = Request::builder()
            .method(Method::POST)
            .uri("/v1/gov/parliament/ballots/test/partial-release")
            .body(Body::from("x"))
            .expect("headerless streaming-style request");
        assert!(request.headers().get(CONTENT_LENGTH).is_none());
        let error = require_empty_body_v1(request.into_body())
            .await
            .expect_err("nonempty body must fail without Content-Length");
        assert!(matches!(
            error,
            crate::Error::AppQueryValidation {
                code: "parliament_tle_partial_release_body_not_empty",
                ..
            }
        ));
    }
}
