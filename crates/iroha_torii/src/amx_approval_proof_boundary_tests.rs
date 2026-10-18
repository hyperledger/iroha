//! Exact AMX read observations through Torii's real outer error middleware.
//!
//! These unsigned HTTP observations never authenticate payment state or authorize a retry
//! outside the caller's original deadline. The strict shared decoder remains unchanged.

use super::*;
use iroha_torii_shared::amx_approval_read::{
    AMX_APPROVAL_READ_FAILURE_CODE, AMX_APPROVAL_READ_FAILURE_MAX_BYTES, AmxApprovalReadFailureV1,
    AmxApprovalReadReasonV1,
};
use tower::ServiceExt as _;

async fn cross_error_boundary(
    envelope: ErrorEnvelope,
    status: StatusCode,
    format: ResponseFormat,
    retry_after: Option<&'static str>,
) -> AxResponse {
    let router = axum::Router::new()
        .route(
            "/v1/amx/debit-approval/2",
            axum::routing::post(move || {
                let envelope = envelope.clone();
                async move {
                    let mut response =
                        utils::respond_with_status_and_format(status, envelope, format);
                    if let Some(retry_after) = retry_after {
                        response.headers_mut().insert(
                            axum::http::header::RETRY_AFTER,
                            HeaderValue::from_static(retry_after),
                        );
                    }
                    response.headers_mut().insert(
                        axum::http::header::CACHE_CONTROL,
                        HeaderValue::from_static("private, no-store"),
                    );
                    response
                }
            }),
        )
        .layer(axum::middleware::from_fn(enforce_typed_error_contract));
    router
        .oneshot(
            axum::http::Request::builder()
                .method(axum::http::Method::POST)
                .uri("/v1/amx/debit-approval/2")
                .header(
                    axum::http::header::ACCEPT,
                    match format {
                        ResponseFormat::Norito => "application/x-norito",
                        ResponseFormat::Json => "application/json",
                    },
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn exact_amx_read_failures_survive_actual_error_boundary_with_their_sole_retry_owner() {
    let approval = super::tests::approval();
    let relay = iroha_test_samples::ALICE_ID.clone();
    let body = norito::encode_canonical(&approval).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        crate::app_auth::HEADER_ACCOUNT,
        relay.to_canonical_hex().unwrap().parse().unwrap(),
    );
    for (reason, observed, delay) in [
        (AmxApprovalReadReasonV1::Capacity, None, None),
        (AmxApprovalReadReasonV1::CutChanged, Some(1), None),
        (AmxApprovalReadReasonV1::Capacity, None, Some(7_000)),
    ] {
        let mut expected =
            AmxApprovalReadFailureV1::new(&approval, &relay, 2, reason, observed).unwrap();
        expected.retry_after_ms = delay;
        // Exercise the original handler producers before the actual outer middleware.
        let produced = if reason == AmxApprovalReadReasonV1::Capacity {
            let error = match delay {
                Some(_) => Error::ProofRateLimited {
                    endpoint: ROUTE,
                    retry_after_secs: 7,
                },
                None => crate::native_projection_response::capacity(),
            };
            capacity_observation(
                capacity_request_binding(&headers, &body, 2),
                Err(error),
                ResponseFormat::Norito,
            )
            .unwrap()
        } else {
            read_failure_response(
                &approval,
                &relay,
                2,
                reason,
                observed,
                ResponseFormat::Norito,
            )
            .unwrap()
        };
        assert_eq!(produced.status().as_u16(), reason.http_status());
        let bytes = axum::body::to_bytes(produced.into_body(), AMX_APPROVAL_READ_FAILURE_MAX_BYTES)
            .await
            .unwrap();
        let original: ErrorEnvelope = norito::decode_canonical(&bytes).unwrap();
        for format in [ResponseFormat::Norito, ResponseFormat::Json] {
            let response = cross_error_boundary(
                original.clone(),
                StatusCode::from_u16(reason.http_status()).unwrap(),
                format,
                None,
            )
            .await;
            assert_eq!(response.status().as_u16(), reason.http_status());
            assert_eq!(
                response.headers()[axum::http::header::CACHE_CONTROL],
                "private, no-store"
            );
            let generic_retry = response
                .headers()
                .contains_key(axum::http::header::RETRY_AFTER);
            let media = response.headers()[axum::http::header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .to_owned();
            let bytes =
                axum::body::to_bytes(response.into_body(), AMX_APPROVAL_READ_FAILURE_MAX_BYTES)
                    .await
                    .unwrap();
            let envelope: ErrorEnvelope = match format {
                ResponseFormat::Norito => {
                    assert_eq!(media, "application/x-norito");
                    assert_eq!(
                        AmxApprovalReadFailureV1::decode_response(
                            reason.http_status(),
                            &media,
                            &bytes,
                            &approval,
                            &relay,
                            2,
                        )
                        .expect("the real middleware must preserve the strict request binding"),
                        expected,
                    );
                    norito::decode_canonical(&bytes).unwrap()
                }
                ResponseFormat::Json => {
                    assert_eq!(media, "application/json; charset=utf-8");
                    norito::json::from_slice(&bytes).unwrap()
                }
            };
            assert!(
                !generic_retry,
                "the embedded exact observation owns delay, never a generic Retry-After"
            );
            let mut details = envelope.details.unwrap();
            assert_eq!(details.amx_approval_read_failure.take(), Some(expected));
            assert!(details.is_empty(), "no generic retry or foreign metadata");
        }
    }
}

#[tokio::test]
async fn invalid_amx_read_failures_remain_terminal_through_actual_error_boundary() {
    let approval = super::tests::approval();
    let relay = iroha_test_samples::ALICE_ID.clone();
    let valid = AmxApprovalReadFailureV1::new(
        &approval,
        &relay,
        2,
        AmxApprovalReadReasonV1::Capacity,
        None,
    )
    .unwrap();
    for case in 0..7 {
        let mut failure = valid;
        match case {
            0 => failure.requested_height = 1,
            1 => failure.observed_height = Some(1),
            5 => {
                failure.reason = AmxApprovalReadReasonV1::CutChanged;
                failure.observed_height = Some(3);
                failure.retry_after_ms = Some(7_000);
            }
            _ => {}
        }
        let status = if case == 2 {
            StatusCode::CONFLICT
        } else {
            StatusCode::TOO_MANY_REQUESTS
        };
        let mut envelope = failure.into_error_envelope();
        match case {
            3 => envelope.details.as_mut().unwrap().retry_after_seconds = Some(1),
            4 => envelope.details = None,
            6 => envelope.code = "query_capacity_exceeded".into(),
            _ => {}
        }
        let response =
            cross_error_boundary(envelope, status, ResponseFormat::Norito, Some("19")).await;
        assert_eq!(response.status(), status);
        let bytes = axum::body::to_bytes(response.into_body(), AMX_APPROVAL_READ_FAILURE_MAX_BYTES)
            .await
            .unwrap();
        assert!(
            AmxApprovalReadFailureV1::decode_response(
                status.as_u16(),
                "application/x-norito",
                &bytes,
                &approval,
                &relay,
                2,
            )
            .is_err(),
            "invalid handler observation {case} cannot become a read retry"
        );
        let envelope: ErrorEnvelope = norito::decode_canonical(&bytes).unwrap();
        assert_ne!(envelope.code(), AMX_APPROVAL_READ_FAILURE_CODE);
        assert!(
            envelope
                .details
                .is_none_or(|details| details.amx_approval_read_failure.is_none()),
            "refused closed detail {case} cannot escape on a generic error"
        );
    }
}

#[tokio::test]
async fn unrelated_generic_capacity_retains_original_http_retry_normalization() {
    for status in [
        StatusCode::TOO_MANY_REQUESTS,
        StatusCode::SERVICE_UNAVAILABLE,
    ] {
        let response = cross_error_boundary(
            ErrorEnvelope::new("ordinary_capacity", "Ordinary local request pressure."),
            status,
            ResponseFormat::Norito,
            Some("19"),
        )
        .await;
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()[axum::http::header::RETRY_AFTER], "19");
        let bytes = axum::body::to_bytes(response.into_body(), AMX_APPROVAL_READ_FAILURE_MAX_BYTES)
            .await
            .unwrap();
        let envelope: ErrorEnvelope = norito::decode_canonical(&bytes).unwrap();
        assert_eq!(envelope.code(), "ordinary_capacity");
        let details = envelope.details.unwrap();
        assert_eq!(details.retry_after_seconds, Some(19));
        assert!(details.amx_approval_read_failure.is_none());
    }
}
