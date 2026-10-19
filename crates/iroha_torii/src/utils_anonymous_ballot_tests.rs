// Versioned transport tests use a canonical codec fixture, never a valid-proof claim.
use super::*;
use axum::{
    body::Body,
    http::{Request, header::CONTENT_TYPE},
};
use iroha_crypto::{Hash, HashOf};
use iroha_version::codec::EncodeVersioned as _;

fn entrypoint() -> TransactionEntrypoint {
    crate::anonymous_ballot_test_support::entrypoint(
        iroha_data_model::NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"Torii anonymous wrapper fixture",
        ))),
    )
}

fn json_body(entry: &TransactionEntrypoint) -> Bytes {
    Bytes::from(format!(
        "{{\"version\":1,\"content\":{}}}",
        norito::json::to_json(entry).unwrap(),
    ))
}

fn limits(allocation: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, 64)
}

#[tokio::test]
async fn anonymous_entrypoint_extracts_through_binary_and_versioned_json_wrappers() {
    let entry = entrypoint();
    for (mime, body) in [
        (
            super::super::NORITO_MIME_TYPE,
            Bytes::from(entry.encode_versioned()),
        ),
        ("application/json", json_body(&entry)),
    ] {
        let request = Request::builder()
            .header(CONTENT_TYPE, mime)
            .body(Body::from(body))
            .unwrap();
        let JsonOrNoritoVersioned(decoded) =
            JsonOrNoritoVersioned::<TransactionEntrypoint>::from_request(request, &())
                .await
                .unwrap();
        assert_eq!(decoded, entry);
        assert!(decoded.authority_opt().is_none());
    }
}

#[test]
fn versioned_anonymous_json_preserves_nested_resource_refusal_and_restores_scope() {
    let entry = entrypoint();
    let body = json_body(&entry);
    let (decoded, usage) = norito::core::with_decode_limits_measured(limits(usize::MAX), || {
        TransactionEntrypoint::decode_versioned_json_body(&body, None)
    });
    assert_eq!(decoded.unwrap(), entry);
    let complete = usage.total_allocated_bytes();
    assert!(complete > iroha_data_model::governance::anonymous_ballot::BallotProofBytesV1::LENGTH);
    let (refused, refused_usage) =
        norito::core::with_decode_limits_measured(limits(usize::MAX), || {
            TransactionEntrypoint::decode_versioned_json_body(
                &body,
                Some((body.len(), limits(complete - 1))),
            )
        });
    let refused = refused.unwrap_err();
    assert_eq!(
        refused_usage.total_allocated_bytes(),
        complete - iroha_data_model::governance::anonymous_ballot::BallotProofBytesV1::LENGTH,
        "the refusal occurs at the inner proof reservation after the outer wrapper is funded",
    );
    assert_eq!(refused.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(refused.headers().get("x-iroha-reject-code").is_none());
    assert_eq!(
        TransactionEntrypoint::decode_versioned_json_body(&body, None).unwrap(),
        entry
    );
}

#[tokio::test]
async fn versioned_anonymous_json_extractor_honors_installed_limits() {
    let entry = entrypoint();
    let body = json_body(&entry);
    let request = Request::builder()
        .header(CONTENT_TYPE, "application/json")
        .extension(VersionedIngressLimits {
            max_body_bytes: body.len(),
            decode_limits: limits(usize::MAX),
            json_decode_limits: limits(0),
        })
        .body(Body::from(body))
        .unwrap();
    let refused = JsonOrNoritoVersioned::<TransactionEntrypoint>::from_request(request, &())
        .await
        .unwrap_err();
    assert_eq!(refused.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(refused.headers().get("x-iroha-reject-code").is_none());
}

#[test]
fn versioned_anonymous_json_rejects_malformed_content_as_bad_request() {
    for body in [
        br#"{"version":1,"content":{"AnonymousBallot":{"bytes":""}}}"#.as_slice(),
        br#"{"version":2,"content":{"AnonymousBallot":{"bytes":""}}}"#.as_slice(),
        br#"{"version":1,"content":{"AnonymousBallot":{"bytes":""}},"authority":null}"#.as_slice(),
    ] {
        let refused =
            TransactionEntrypoint::decode_versioned_json_body(&Bytes::copy_from_slice(body), None)
                .unwrap_err();
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    }
}

// These controls construct transport diagnostics and obtain a real enclosing
// budget refusal; they do not inject allocator failures into the running codec.
fn enclosing_refusal() -> norito::core::DecodeAttemptError {
    let refusal = norito::with_decode_limits_scope(limits(0), || {
        norito::core::classify_decode_attempt(|| norito::core::reserve_decode_allocation(1))
    })
    .unwrap_err();
    assert_eq!(
        refusal.kind(),
        norito::core::DecodeAttemptErrorKind::EnclosingLimit
    );
    assert_eq!(
        refusal.error().decode_resource_error(),
        Some(norito::core::DecodeResourceError::TotalAllocationExceeded {
            attempted: 1,
            limit: 0
        },)
    );
    refusal
}

async fn assert_resource_response(response: Response, status: StatusCode, code: &str) {
    assert_eq!(response.status(), status);
    assert!(response.headers().get("x-iroha-reject-code").is_none());
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    let envelope: iroha_torii_shared::ErrorEnvelope = norito::decode_from_bytes(&bytes).unwrap();
    assert_eq!(envelope.code(), code);
    assert!(
        envelope
            .details
            .as_ref()
            .is_none_or(|details| details.reject_code.is_none())
    );
}

#[tokio::test]
async fn anonymous_transport_binary_distinguishes_allocator_caps_and_invalid_input() {
    let allocation = || norito::Error::AllocationFailed { bytes: 4096 };
    for response in [
        norito_decode_rejection::<TransactionEntrypoint>(&allocation()),
        versioned_decode_rejection::<TransactionEntrypoint>(
            iroha_version::error::Error::NoritoCodec(allocation()),
        ),
        versioned_decode_rejection::<SignedTransaction>(iroha_version::error::Error::from(
            norito::core::classify_decode_attempt(|| Err::<(), _>(allocation())).unwrap_err(),
        )),
        norito_decode_rejection::<TransactionEntrypoint>(&norito::Error::Json(
            json::Error::AllocationFailed,
        )),
    ] {
        assert_resource_response(
            response,
            StatusCode::SERVICE_UNAVAILABLE,
            "request_decode_unavailable",
        )
        .await;
    }
    let wrapped_cap = norito::Error::Json(json::Error::from_decode_resource(
        enclosing_refusal().into_error(),
    ));
    assert_resource_response(
        norito_decode_rejection::<TransactionEntrypoint>(&wrapped_cap),
        StatusCode::PAYLOAD_TOO_LARGE,
        "request_payload_too_large",
    )
    .await;
    assert_resource_response(
        versioned_decode_rejection::<TransactionEntrypoint>(
            iroha_version::error::Error::NoritoCodec(wrapped_cap),
        ),
        StatusCode::PAYLOAD_TOO_LARGE,
        "request_payload_too_large",
    )
    .await;
    let original = enclosing_refusal().into_error();
    assert!(matches!(original, norito::Error::ScopedDecodeResource(_)));
    assert_resource_response(
        norito_decode_rejection::<TransactionEntrypoint>(&original),
        StatusCode::PAYLOAD_TOO_LARGE,
        "request_payload_too_large",
    )
    .await;
    assert_resource_response(
        versioned_decode_rejection::<TransactionEntrypoint>(enclosing_refusal().into()),
        StatusCode::PAYLOAD_TOO_LARGE,
        "request_payload_too_large",
    )
    .await;
    for response in [
        norito_decode_rejection::<TransactionEntrypoint>(&norito::Error::InvalidMagic),
        versioned_decode_rejection::<TransactionEntrypoint>(
            iroha_version::error::Error::NoritoCodec(norito::Error::InvalidMagic),
        ),
    ] {
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn anonymous_transport_json_distinguishes_allocator_caps_and_invalid_input() {
    for error in [
        json::Error::AllocationFailed,
        json::Error::from_decode_resource(norito::Error::AllocationFailed { bytes: 4096 }),
    ] {
        assert_resource_response(
            versioned_json_decode_rejection(error, "TransactionEntrypoint"),
            StatusCode::SERVICE_UNAVAILABLE,
            "request_decode_unavailable",
        )
        .await;
    }
    let original = json::Error::from_decode_resource(enclosing_refusal().into_error());
    assert!(matches!(original, json::Error::ScopedDecodeResource(_)));
    assert_resource_response(
        versioned_json_decode_rejection(original, "TransactionEntrypoint"),
        StatusCode::PAYLOAD_TOO_LARGE,
        "request_payload_too_large",
    )
    .await;
    assert_resource_response(
        json_decode_resource_rejection(&json::Error::AllocationFailed).unwrap(),
        StatusCode::SERVICE_UNAVAILABLE,
        "request_decode_unavailable",
    )
    .await;
    assert_eq!(
        versioned_json_decode_rejection(json::Error::InvalidUtf8, "TransactionEntrypoint").status(),
        StatusCode::BAD_REQUEST
    );
    assert!(
        json_decode_resource_rejection(&json::Error::Message(
            "AllocationFailed { bytes: 4096 }".into()
        ))
        .is_none()
    );
}
