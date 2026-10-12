//! Selector, refusal, representation and original response-custody controls.

use super::*;
use std::{sync::atomic::AtomicBool, time::Duration};

#[test]
fn selectors_are_canonical_non_genesis_and_keep_record_latest_distinct() {
    assert_eq!(proof_at(None).unwrap(), SccpNativeProofAt::Record);
    assert_eq!(proof_at(Some("record")).unwrap(), SccpNativeProofAt::Record);
    assert_eq!(proof_at(Some("latest")).unwrap(), SccpNativeProofAt::Latest);
    assert_eq!(finality_at("latest").unwrap(), None);
    for value in ["2", "18446744073709551615"] {
        let height = NonZeroU64::new(value.parse().unwrap()).unwrap();
        assert_eq!(
            proof_at(Some(value)).unwrap(),
            SccpNativeProofAt::Height(height)
        );
        assert_eq!(finality_at(value).unwrap(), Some(height));
    }
    for invalid in [
        "",
        "0",
        "1",
        "02",
        "+2",
        " 2",
        "2 ",
        "LATEST",
        "18446744073709551616",
    ] {
        assert!(proof_at(Some(invalid)).is_err(), "{invalid}");
        assert!(finality_at(invalid).is_err(), "{invalid}");
    }
    assert!(finality_at("record").is_err());
    assert_eq!(decimal("0").unwrap(), 0, "record nonces may be zero");
}

#[test]
fn rotation_cursor_is_required_and_count_has_no_unbounded_default() {
    assert!(rotations(&RotationsQuery::default()).is_err());
    let mut query = RotationsQuery {
        after_generation: Some("4".into()),
        limit: None,
    };
    assert!(matches!(
        rotations(&query).unwrap(),
        Selection::Rotations {
            after: 4,
            limit: 16
        }
    ));
    for limit in ["0", "17", "+1", "01", "18446744073709551616"] {
        query.limit = Some(limit.into());
        assert!(rotations(&query).is_err());
    }
    query.limit = Some("1".into());
    for after in ["0", "01", "+1", "-1"] {
        query.after_generation = Some(after.into());
        assert!(rotations(&query).is_err());
    }
    query.after_generation = Some(u64::MAX.to_string());
    assert!(matches!(
        rotations(&query).unwrap(),
        Selection::Rotations {
            after: u64::MAX,
            limit: 1
        }
    ));
}

#[test]
fn explicit_proof_height_is_the_only_cacheable_proof_selector() {
    let height = NonZeroU64::new(2).unwrap();
    for at in [
        SccpNativeProofAt::Record,
        SccpNativeProofAt::Latest,
        SccpNativeProofAt::Height(height),
    ] {
        let message = Selection::Message { id: [1; 32], at };
        let control = Selection::Control {
            network: SccpNetworkV1::TonMainnet,
            revision: 1,
            nonce: 0,
            at,
        };
        assert_eq!(message.route(), sccp::MESSAGE_PROOF);
        assert_eq!(control.route(), sccp::CONTROL_PROOF);
        assert_eq!(
            message.immutable(),
            matches!(at, SccpNativeProofAt::Height(_))
        );
        assert_eq!(control.immutable(), message.immutable());
    }
    assert!(Selection::Finality(Some(height)).immutable());
    assert!(!Selection::Finality(None).immutable());
    assert_eq!(Selection::Finality(None).route(), sccp::FINALITY);
    assert!(
        !Selection::Rotations {
            after: 1,
            limit: 16
        }
        .immutable()
    );
    assert_eq!(
        Selection::Rotations {
            after: 1,
            limit: 16
        }
        .route(),
        sccp::COMMITTEE_ROTATIONS
    );
}

#[tokio::test]
async fn missing_unavailable_bad_request_and_stop_are_different_responses() {
    let cases = [
        (
            SccpNativeReadError::Request("selector"),
            StatusCode::BAD_REQUEST,
            "sccp_invalid_query",
        ),
        (
            SccpNativeReadError::NotFound("record"),
            StatusCode::NOT_FOUND,
            "sccp_not_found",
        ),
        (
            SccpNativeReadError::Unavailable("source"),
            StatusCode::SERVICE_UNAVAILABLE,
            "sccp_unavailable",
        ),
        (
            SccpNativeReadError::Invalid("original binding"),
            StatusCode::SERVICE_UNAVAILABLE,
            "sccp_unavailable",
        ),
        (
            SccpNativeReadError::Inactive,
            StatusCode::SERVICE_UNAVAILABLE,
            "sccp_unavailable",
        ),
        (
            SccpNativeReadError::UnsupportedScope,
            StatusCode::SERVICE_UNAVAILABLE,
            "route_unavailable",
        ),
        (
            SccpNativeReadError::PhysicalAllocation,
            StatusCode::SERVICE_UNAVAILABLE,
            "sccp_capacity",
        ),
        (
            SccpNativeReadError::Deadline,
            StatusCode::REQUEST_TIMEOUT,
            "request_timeout",
        ),
        (
            SccpNativeReadError::Cancelled,
            StatusCode::REQUEST_TIMEOUT,
            "request_timeout",
        ),
    ];
    for (error, status, code) in cases {
        let response = source_error(error);
        assert_eq!(response.status(), status);
        assert_ne!(
            response.status(),
            StatusCode::GONE,
            "absence is not pruning evidence"
        );
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "private, no-store"
        );
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
        assert_eq!(
            json.get("code").and_then(norito::json::Value::as_str),
            Some(code)
        );
    }
}

#[test]
fn original_cancellation_and_deadline_refuse_without_starting_work() {
    let stop = AtomicBool::new(false);
    let future = SccpNativeReadControl {
        deadline: Instant::now() + Duration::from_secs(30),
        stop: &stop,
    };
    assert!(stopped(future, ResponseFormat::Json).is_none());
    stop.store(true, Ordering::Release);
    assert_eq!(
        stopped(future, ResponseFormat::Json)
            .unwrap()
            .response
            .status(),
        StatusCode::REQUEST_TIMEOUT
    );
    stop.store(false, Ordering::Release);
    let expired = SccpNativeReadControl {
        deadline: Instant::now(),
        stop: &stop,
    };
    assert_eq!(
        stopped(expired, ResponseFormat::Norito)
            .unwrap()
            .response
            .status(),
        StatusCode::REQUEST_TIMEOUT
    );
}

#[tokio::test]
async fn negotiated_exact_bytes_etag_and_last_byte_charge_stay_together() {
    let owner = HistoryProducerOwner::for_test();
    let baseline = owner.cold_frames().reserved_bytes();
    let mut etags = Vec::new();
    for format in [ResponseFormat::Json, ResponseFormat::Norito] {
        let prepared =
            encode_value(&42_u64, &owner, format, 4096, true, &HeaderMap::new()).unwrap();
        assert_eq!(prepared.response.status(), StatusCode::OK);
        let tag = prepared.response.headers()[header::ETAG].clone();
        let bytes = axum::body::to_bytes(prepared.response.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(bytes.len(), prepared.bytes);
        assert_eq!(owner.cold_frames().reserved_bytes(), baseline + bytes.len());
        match format {
            ResponseFormat::Json => assert_eq!(bytes.as_ref(), b"42"),
            ResponseFormat::Norito => {
                assert_eq!(norito::decode_from_bytes::<u64>(&bytes).unwrap(), 42)
            }
        }
        let retained = bytes.slice(..1);
        drop(bytes);
        assert!(
            owner.cold_frames().reserved_bytes() > baseline,
            "extracted slice still owns the exact backing"
        );
        drop(retained);
        assert_eq!(owner.cold_frames().reserved_bytes(), baseline);
        let mut headers = HeaderMap::new();
        headers.insert(header::IF_NONE_MATCH, tag.clone());
        let unchanged = encode_value(&42_u64, &owner, format, 4096, true, &headers).unwrap();
        assert_eq!(unchanged.response.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(unchanged.bytes, 0);
        assert_eq!(unchanged.response.headers()[header::ETAG], tag);
        assert_eq!(owner.cold_frames().reserved_bytes(), baseline);
        etags.push(tag);
    }
    assert_ne!(
        etags[0], etags[1],
        "validator hashes the selected representation"
    );
    assert!(
        encode_value(
            &42_u64,
            &owner,
            ResponseFormat::Json,
            1,
            false,
            &HeaderMap::new()
        )
        .is_err()
    );
    assert_eq!(owner.cold_frames().reserved_bytes(), baseline);
    let mutable = encode_value(
        &42_u64,
        &owner,
        ResponseFormat::Json,
        2,
        false,
        &HeaderMap::new(),
    )
    .unwrap();
    assert_eq!(
        mutable.response.headers()[header::CACHE_CONTROL],
        "no-store"
    );
    assert!(!mutable.response.headers().contains_key(header::ETAG));
}

#[tokio::test]
async fn native_handlers_reject_bad_selectors_before_source_or_worker_admission() {
    let app = crate::tests_runtime_handlers::app_with_root_scope_for_handler_test(
        iroha_core::state::World::new(),
        false,
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    let remote = "127.0.0.1:1234".parse().unwrap();
    let finality = handler_finality(
        State(app.clone()),
        Path("1".into()),
        Extension(RouteExecutionDeadline(deadline)),
        HeaderMap::new(),
        ConnectInfo(remote),
    )
    .await
    .unwrap();
    let message = handler_message_proof(
        State(app.clone()),
        Path("not-an-id".into()),
        NoritoStringQuery(ProofQuery::default()),
        Extension(RouteExecutionDeadline(deadline)),
        HeaderMap::new(),
        ConnectInfo(remote),
    )
    .await
    .unwrap();
    let control = handler_control_proof(
        State(app.clone()),
        Path(("ton-mainnet".into(), "4294967296".into(), "0".into())),
        NoritoStringQuery(ProofQuery::default()),
        Extension(RouteExecutionDeadline(deadline)),
        HeaderMap::new(),
        ConnectInfo(remote),
    )
    .await
    .unwrap();
    let rotations = handler_committee_rotations(
        State(app),
        NoritoStringQuery(RotationsQuery::default()),
        Extension(RouteExecutionDeadline(deadline)),
        HeaderMap::new(),
        ConnectInfo(remote),
    )
    .await
    .unwrap();
    for response in [finality, message, control, rotations] {
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn native_serving_preserves_original_deadline_and_refuses_absent_authority() {
    let app = crate::tests_runtime_handlers::app_with_root_scope_for_handler_test(
        iroha_core::state::World::new(),
        false,
    );
    let remote = "127.0.0.1:1234".parse().unwrap();
    let expired = serve(
        app.clone(),
        Selection::Finality(None),
        Instant::now(),
        HeaderMap::new(),
        remote,
    )
    .await
    .unwrap();
    assert_eq!(expired.status(), StatusCode::REQUEST_TIMEOUT);
    let response = serve(
        app,
        Selection::Finality(None),
        Instant::now() + Duration::from_secs(30),
        HeaderMap::new(),
        remote,
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let json: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
    assert_eq!(
        json.get("code").and_then(norito::json::Value::as_str),
        Some("sccp_unavailable")
    );
}

#[test]
fn committee_selectors_include_genesis_but_never_cache_mutable_liability() {
    for value in ["1", "2", "18446744073709551615"] {
        assert_eq!(generation_number(value).unwrap().get().to_string(), value);
    }
    for value in [
        "",
        "0",
        "01",
        "+1",
        "-1",
        " 1",
        "1 ",
        "current",
        "18446744073709551616",
    ] {
        assert!(generation_number(value).is_err(), "{value}");
    }
    assert_eq!(Selection::Committee(None).route(), sccp::CURRENT_COMMITTEE);
    assert_eq!(
        Selection::Committee(NonZeroU64::new(1)).route(),
        sccp::COMMITTEE
    );
    assert!(!Selection::Committee(None).immutable());
    assert!(!Selection::Committee(NonZeroU64::new(1)).immutable());
}

#[tokio::test]
async fn committee_handlers_preserve_query_source_deadline_and_no_store_contract() {
    let app = crate::tests_runtime_handlers::app_with_root_scope_for_handler_test(
        iroha_core::state::World::new(),
        false,
    );
    let remote = "127.0.0.1:1234".parse().unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let invalid = handler_committee(
        State(app.clone()),
        Path("0".into()),
        Extension(RouteExecutionDeadline(deadline)),
        HeaderMap::new(),
        ConnectInfo(remote),
    )
    .await
    .unwrap();
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    let expired = handler_current_committee(
        State(app.clone()),
        Extension(RouteExecutionDeadline(Instant::now())),
        HeaderMap::new(),
        ConnectInfo(remote),
    )
    .await
    .unwrap();
    assert_eq!(expired.status(), StatusCode::REQUEST_TIMEOUT);
    for response in [
        handler_current_committee(
            State(app.clone()),
            Extension(RouteExecutionDeadline(deadline)),
            HeaderMap::new(),
            ConnectInfo(remote),
        )
        .await
        .unwrap(),
        handler_committee(
            State(app),
            Path("1".into()),
            Extension(RouteExecutionDeadline(deadline)),
            HeaderMap::new(),
            ConnectInfo(remote),
        )
        .await
        .unwrap(),
    ] {
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "private, no-store"
        );
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
        assert_eq!(
            json.get("code").and_then(norito::json::Value::as_str),
            Some("sccp_unavailable")
        );
    }
    let owner = HistoryProducerOwner::for_test();
    for selection in [
        Selection::Committee(None),
        Selection::Committee(NonZeroU64::new(1)),
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(header::IF_NONE_MATCH, HeaderValue::from_static("*"));
        let response = encode_value(
            &42_u64,
            &owner,
            ResponseFormat::Json,
            4096,
            selection.immutable(),
            &headers,
        )
        .unwrap();
        assert_eq!(
            response.response.status(),
            StatusCode::OK,
            "liability is reevaluated, not a cached 304"
        );
        assert_eq!(
            response.response.headers()[header::CACHE_CONTROL],
            "no-store"
        );
        assert!(!response.response.headers().contains_key(header::ETAG));
    }
}
