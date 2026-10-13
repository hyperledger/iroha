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
            SccpNativeReadError::Pruned("committee generation"),
            StatusCode::GONE,
            "sccp_pruned",
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
        if code != "sccp_pruned" {
            assert_ne!(
                response.status(),
                StatusCode::GONE,
                "absence is not pruning evidence"
            );
        }
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
    let rotations = handler_rotations(
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

#[test]
fn hold_selectors_are_bounded_exact_pairs_and_mutable() {
    assert_eq!(hold_query(&ForgeryHoldQuery::default()).unwrap().limit, 64);
    for query in [
        ForgeryHoldQuery {
            limit: Some("65".into()),
            ..Default::default()
        },
        ForgeryHoldQuery {
            limit: Some("00".into()),
            ..Default::default()
        },
        ForgeryHoldQuery {
            revision: Some("1".into()),
            ..Default::default()
        },
        ForgeryHoldQuery {
            after_network: Some("ethereum-mainnet".into()),
            ..Default::default()
        },
        ForgeryHoldQuery {
            after_revision: Some("1".into()),
            ..Default::default()
        },
    ] {
        assert!(hold_query(&query).is_err());
    }
    let query = hold_query(&ForgeryHoldQuery {
        network: Some("ethereum-mainnet".into()),
        revision: Some("2".into()),
        after_network: Some("ethereum-mainnet".into()),
        after_revision: Some("1".into()),
        limit: Some("1".into()),
    })
    .unwrap();
    assert_eq!(query.revision, Some(2));
    assert_eq!(query.after.unwrap().revision, 1);
    assert_eq!(Selection::ForgeryHold(query).route(), sccp::FORGERY_HOLD);
    assert!(!Selection::ForgeryHold(query).immutable());
}

#[tokio::test]
async fn hold_handler_preserves_original_source_and_request_deadline() {
    let app = crate::tests_runtime_handlers::app_with_root_scope_for_handler_test(
        iroha_core::state::World::new(),
        false,
    );
    let remote = "127.0.0.1:1234".parse().unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let invalid = handler_forgery_hold(
        State(app.clone()),
        NoritoStringQuery(ForgeryHoldQuery {
            limit: Some("65".into()),
            ..Default::default()
        }),
        Extension(RouteExecutionDeadline(deadline)),
        HeaderMap::new(),
        ConnectInfo(remote),
    )
    .await
    .unwrap();
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    let expired = handler_forgery_hold(
        State(app.clone()),
        NoritoStringQuery(ForgeryHoldQuery::default()),
        Extension(RouteExecutionDeadline(Instant::now())),
        HeaderMap::new(),
        ConnectInfo(remote),
    )
    .await
    .unwrap();
    assert_eq!(expired.status(), StatusCode::REQUEST_TIMEOUT);
    let missing = handler_forgery_hold(
        State(app),
        NoritoStringQuery(ForgeryHoldQuery::default()),
        Extension(RouteExecutionDeadline(deadline)),
        HeaderMap::new(),
        ConnectInfo(remote),
    )
    .await
    .unwrap();
    assert_eq!(missing.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        missing.headers()[header::CACHE_CONTROL],
        "private, no-store"
    );
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

/// Exercise the same textual query extractor used by the mounted native handlers.
async fn extract_native_query<T>(uri: &str) -> Result<T, StatusCode>
where
    T: norito::json::JsonDeserializeOwned + Send,
{
    use axum::extract::FromRequestParts as _;
    let request = axum::http::Request::builder().uri(uri).body(()).unwrap();
    let (mut parts, _) = request.into_parts();
    NoritoStringQuery::<T>::from_request_parts(&mut parts, &())
        .await
        .map(|NoritoStringQuery(query)| query)
        .map_err(|response| response.status())
}

#[tokio::test]
async fn proof_queries_reject_retired_unknown_and_duplicate_selectors() {
    let valid: ProofQuery = extract_native_query("/v1/sccp/messages/00/proof?at=42")
        .await
        .expect("current selector decodes as text");
    assert_eq!(valid.at.as_deref(), Some("42"));
    for query in [
        "attestation=own",
        "attestation=42",
        "at=record&attestation=latest",
        "at=record&unknown=1",
        "at=record&at=latest",
    ] {
        assert_eq!(
            extract_native_query::<ProofQuery>(&format!("/v1/sccp/messages/00/proof?{query}"))
                .await
                .expect_err("proof query must reject every retired or unknown selector"),
            StatusCode::BAD_REQUEST,
            "{query}"
        );
    }
}

#[tokio::test]
async fn rotation_queries_reject_retired_unknown_and_duplicate_selectors() {
    let valid: RotationsQuery =
        extract_native_query("/v1/sccp/committees/rotations?after_generation=1&limit=2")
            .await
            .expect("current bounded rotation selectors decode as text");
    assert_eq!(valid.after_generation.as_deref(), Some("1"));
    assert_eq!(valid.limit.as_deref(), Some("2"));
    for query in [
        "after_generation=1&attestation=latest",
        "after_generation=1&unknown=1",
        "after_generation=1&after_generation=2",
        "after_generation=1&limit=1&limit=2",
    ] {
        assert_eq!(
            extract_native_query::<RotationsQuery>(&format!(
                "/v1/sccp/committees/rotations?{query}"
            ))
            .await
            .expect_err("rotation query must reject every retired or unknown selector"),
            StatusCode::BAD_REQUEST,
            "{query}"
        );
    }
}

#[tokio::test]
async fn proof_routes_reject_malformed_queries_before_unavailable_record_lookup() {
    let app = crate::tests_runtime_handlers::app_with_root_scope_for_handler_test(
        iroha_core::state::World::new(),
        false,
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    let remote = "127.0.0.1:1234".parse().unwrap();
    for at in ["own", "0", "+1", "-1", " 1", "1 ", "18446744073709551616"] {
        let query = ProofQuery {
            at: Some(at.into()),
        };
        let message = handler_message_proof(
            State(app.clone()),
            Path("01".repeat(32)),
            NoritoStringQuery(query.clone()),
            Extension(RouteExecutionDeadline(deadline)),
            HeaderMap::new(),
            ConnectInfo(remote),
        )
        .await
        .unwrap();
        let control = handler_control_proof(
            State(app.clone()),
            Path(("ethereum-mainnet".into(), "1".into(), "1".into())),
            NoritoStringQuery(query),
            Extension(RouteExecutionDeadline(deadline)),
            HeaderMap::new(),
            ConnectInfo(remote),
        )
        .await
        .unwrap();
        for response in [message, control] {
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{at}");
            assert!(!response.headers().contains_key(header::ETAG));
            let bytes = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let json: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
            assert_eq!(
                json.get("code").and_then(norito::json::Value::as_str),
                Some("sccp_invalid_query")
            );
        }
    }
}

// Finish the genuine signed genesis outside the async assertion frame on the default stack.
#[inline(never)]
fn genesis_finality_app() -> (
    SharedAppState,
    Box<iroha_core::sumeragi::test_chain::CertifiedTestChain>,
) {
    use iroha_core::{
        state::World,
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };
    let chain = Box::new(
        CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000))
            .expect("genuine signed genesis"),
    );
    assert_eq!(chain.height(), 1);
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests();
    let fixture = std::sync::Arc::get_mut(&mut app).unwrap();
    fixture.state = std::sync::Arc::clone(chain.state());
    fixture.kura = std::sync::Arc::clone(chain.kura());
    (app, chain)
}

#[tokio::test]
async fn latest_genesis_finality_is_unavailable_and_never_cacheable() {
    let (app, _chain) = genesis_finality_app();
    let remote = "127.0.0.1:1234".parse().unwrap();
    for accept in ["application/json", crate::utils::NORITO_MIME_TYPE] {
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, HeaderValue::from_static(accept));
        headers.insert(header::IF_NONE_MATCH, HeaderValue::from_static("*"));
        for (selector, status, code) in [
            ("1", StatusCode::BAD_REQUEST, "sccp_invalid_query"),
            (
                "latest",
                StatusCode::SERVICE_UNAVAILABLE,
                "sccp_unavailable",
            ),
        ] {
            let response = handler_finality(
                State(app.clone()),
                Path(selector.into()),
                Extension(RouteExecutionDeadline(
                    Instant::now() + Duration::from_secs(30),
                )),
                headers.clone(),
                ConnectInfo(remote),
            )
            .await
            .unwrap();
            assert_eq!(response.status(), status, "{selector} with {accept}");
            assert!(!response.headers().contains_key(header::ETAG));
            if selector == "latest" {
                assert_eq!(
                    response.headers()[header::CACHE_CONTROL],
                    "private, no-store"
                );
            }
            let bytes = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let error: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
            assert_eq!(
                error.get("code").and_then(norito::json::Value::as_str),
                Some(code)
            );
        }
    }
}

#[tokio::test]
async fn authenticated_rotation_expiry_has_its_dedicated_gone_response() {
    let response = source_error(SccpNativeReadError::RotationPruned);
    assert_eq!(response.status(), StatusCode::GONE);
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
        Some("sccp_rotation_pruned")
    );
}
