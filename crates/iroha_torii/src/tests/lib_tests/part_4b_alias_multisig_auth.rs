#[tokio::test]
async fn alias_routes_mount_with_required_index_authentication() {
    use tower::ServiceExt as _;

    let app =
        crate::tests_runtime_handlers::native_ingress_app_with_world_for_test(World::default());
    let mut builder = RouterBuilder::new(
        app.clone(),
        RouteCatalog::new(route_catalog::aliases::ROUTES),
        compiled_route_features(),
    )
    .expect("alias route descriptors are valid");
    // Use the actual production registration; a duplicate test router would
    // miss an authentication-policy mismatch that prevents Torii startup.
    Torii::add_alias_routes(&mut builder);
    let (router, _) = builder
        .finish()
        .expect("every alias route must mount with its declared authentication");
    let router = router.with_state(app);
    for body in [r#"{"index":0}"#, "malformed"] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(route_catalog::aliases::RESOLVE_INDEX.path())
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn alias_resolve_index_rejects_unsigned_request() {
    let keypair = checked_torii_test_ed25519_keypair(
        0x0a,
        "derive alias resolve-index unsigned authority fixture key",
    );
    let authority = AccountId::new(keypair.public_key().clone());
    let alias_label = AccountAlias::new(
        "banking".parse().expect("label"),
        Some(iroha_data_model::account::rekey::AccountAliasDomain::new(
            "centralbank".parse::<Name>().expect("domain id"),
        )),
        DataSpaceId::UNIVERSAL,
    );
    let authority_account = Account::new(authority.clone()).build(&authority);
    let domain = Domain::new(DomainId::try_new("centralbank", "universal").expect("domain id"))
        .build(&authority);
    let app = crate::tests_runtime_handlers::native_ingress_app_with_world_for_test(World::with(
        [domain],
        [authority_account],
        [],
    ));
    bind_account_alias_for_test(&app, &authority, "banking@centralbank.universal");
    assert_eq!(
        alias_label
            .to_literal(&app.state.nexus_snapshot().dataspace_catalog)
            .unwrap(),
        "banking@centralbank.universal"
    );
    let body = norito::json::to_vec(&routing::AliasResolveIndexRequestDto { index: 0 })
        .expect("encode request");
    let method = axum::http::Method::POST;
    let uri: axum::http::Uri = "/v1/aliases/resolve-index".parse().unwrap();
    let error = handler_alias_resolve_index(
        State(app.clone()),
        method.clone(),
        uri.clone(),
        HeaderMap::new(),
        axum::body::Bytes::from(body.clone()),
    )
    .await
    .expect_err("unsigned index enumeration must be rejected");
    assert!(matches!(
        &error,
        Error::AppUnauthorized {
            code: "alias_auth_required",
            ..
        }
    ));
    assert_eq!(error.into_response().status(), StatusCode::UNAUTHORIZED);

    let mut partial = HeaderMap::new();
    partial.insert(
        HEADER_ACCOUNT,
        HeaderValue::from_str(&authority.canonical_i105().unwrap()).unwrap(),
    );
    let partial_error = handler_alias_resolve_index(
        State(app.clone()),
        method.clone(),
        uri.clone(),
        partial,
        axum::body::Bytes::from(body.clone()),
    )
    .await
    .expect_err("partial signing must not downgrade to anonymous enumeration");
    assert!(
        matches!(&partial_error, Error::Query(ValidationFail::NotPermitted(message)) if message.contains("must be set together"))
    );
    assert_eq!(
        partial_error.into_response().status(),
        StatusCode::FORBIDDEN
    );

    let headers = crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        &authority,
        &keypair,
        &method,
        &uri,
        &body,
    );
    // Use a genuine well-formed signature for a different canonical request body.
    let changed_body =
        norito::json::to_vec(&routing::AliasResolveIndexRequestDto { index: 1 }).unwrap();
    let invalid_error = handler_alias_resolve_index(
        State(app),
        method,
        uri,
        headers,
        axum::body::Bytes::from(changed_body),
    )
    .await
    .expect_err("wrong-body signature must fail before alias enumeration");
    assert!(
        matches!(&invalid_error, Error::Query(ValidationFail::NotPermitted(message)) if message == "query signature failed verification")
    );
    assert_eq!(
        invalid_error.into_response().status(),
        StatusCode::FORBIDDEN
    );
}
#[tokio::test]
async fn alias_resolve_index_rejects_malformed_json_body() {
    let authority_keypair = checked_torii_test_ed25519_keypair(
        0x0b,
        "derive alias resolve-index malformed body authority fixture key",
    );
    let authority = AccountId::new(authority_keypair.public_key().clone());
    let app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    let method = axum::http::Method::POST;
    let uri: axum::http::Uri = "/v1/aliases/resolve-index"
        .parse()
        .expect("alias resolve-index uri");
    let body = b"{";
    let headers = signed_app_headers(&authority, &authority_keypair, &method, &uri, body);
    let err = handler_alias_resolve_index(
        State(app),
        method,
        uri,
        headers,
        axum::body::Bytes::from_static(body),
    )
    .await
    .expect_err("malformed resolve-index bodies should be rejected");
    match err {
        Error::Query(ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::Conversion(message),
        )) => assert!(
            !message.trim().is_empty(),
            "malformed request bodies should surface a parse diagnostic"
        ),
        other => panic!("unexpected error: {other:?}"),
    }
}
fn multisig_read_payload<T>(value: T) -> NoritoJsonWithBytes<T>
where
    T: norito::json::JsonSerialize,
{
    let raw = norito::json::to_vec(&value).expect("encode multisig read request");
    NoritoJsonWithBytes {
        value,
        raw: axum::body::Bytes::from(raw),
    }
}
#[tokio::test]
async fn contract_code_artifact_read_rejects_unsigned_requests() {
    let uri: axum::http::Uri = format!("/v1/contracts/artifacts/0/{}/bytes", "a".repeat(64))
        .parse()
        .expect("contract code URI");
    let error = match handler_get_contract_code_bytes(
        State(mk_app_state_for_tests()),
        Method::GET,
        uri,
        HeaderMap::new(),
        crate::loopback_connect_info(),
        axum::extract::Path(("0".into(), "a".repeat(64))),
    )
    .await
    {
        Ok(_) => panic!("unsigned contract artifact read must fail closed"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        Error::AppUnauthorized {
            code: "contract_code_auth_required",
            ..
        }
    ));
}
#[tokio::test]
async fn multisig_spec_rejects_unsigned_alias_selector() {
    let request = routing::MultisigSpecRequestDto {
        selector: routing::MultisigAccountSelectorDto {
            multisig_account_id: None,
            multisig_account_alias: Some("banking@centralbank.universal".to_owned()),
        },
    };
    let error = handler_post_multisig_spec(
        State(mk_app_state_for_tests()),
        Method::POST,
        routing::ENDPOINT_MULTISIG_SPEC
            .parse()
            .expect("multisig spec uri"),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        multisig_read_payload(request),
    )
    .await
    .expect_err("unsigned alias selectors must fail closed");
    assert!(matches!(
        error,
        Error::AppUnauthorized {
            code: "multisig_read_auth_required",
            ..
        }
    ));
}
#[tokio::test]
async fn multisig_proposals_query_rejects_unsigned_alias_selector() {
    let request = routing::MultisigProposalsQueryRequestDto {
        selector: routing::MultisigAccountSelectorDto {
            multisig_account_id: None,
            multisig_account_alias: Some("banking@centralbank.universal".to_owned()),
        },
        status: Vec::new(),
        cursor: None,
        limit: None,
    };
    let error = handler_post_multisig_proposals_query(
        State(mk_app_state_for_tests()),
        Method::POST,
        routing::ENDPOINT_MULTISIG_PROPOSALS_QUERY
            .parse()
            .expect("multisig proposals query uri"),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        multisig_read_payload(request),
    )
    .await
    .expect_err("unsigned alias selectors must fail closed");
    assert!(matches!(
        error,
        Error::AppUnauthorized {
            code: "multisig_read_auth_required",
            ..
        }
    ));
}
#[tokio::test]
async fn multisig_proposals_resolve_rejects_unsigned_alias_selector() {
    let request = routing::MultisigProposalsResolveRequestDto {
        selector: routing::MultisigAccountSelectorDto {
            multisig_account_id: None,
            multisig_account_alias: Some("banking@centralbank.universal".to_owned()),
        },
        proposal_id: "de".repeat(32).parse().unwrap(),
    };
    let error = handler_post_multisig_proposals_resolve(
        State(mk_app_state_for_tests()),
        Method::POST,
        routing::ENDPOINT_MULTISIG_PROPOSALS_RESOLVE
            .parse()
            .expect("multisig proposals resolve uri"),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        multisig_read_payload(request),
    )
    .await
    .expect_err("unsigned alias selectors must fail closed");
    assert!(matches!(
        error,
        Error::AppUnauthorized {
            code: "multisig_read_auth_required",
            ..
        }
    ));
}
#[tokio::test]
async fn multisig_reads_reject_unsigned_concrete_account_selectors() {
    let selector = || routing::MultisigAccountSelectorDto {
        multisig_account_id: Some((*ALICE_ID).clone()),
        multisig_account_alias: None,
    };
    let spec = handler_post_multisig_spec(
        State(mk_app_state_for_tests()),
        Method::POST,
        routing::ENDPOINT_MULTISIG_SPEC
            .parse()
            .expect("multisig spec uri"),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        multisig_read_payload(routing::MultisigSpecRequestDto {
            selector: selector(),
        }),
    )
    .await
    .expect_err("unsigned concrete spec read must fail closed")
    .into_response();
    assert_eq!(spec.status(), StatusCode::UNAUTHORIZED);
    let query = handler_post_multisig_proposals_query(
        State(mk_app_state_for_tests()),
        Method::POST,
        routing::ENDPOINT_MULTISIG_PROPOSALS_QUERY
            .parse()
            .expect("multisig proposals query uri"),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        multisig_read_payload(routing::MultisigProposalsQueryRequestDto {
            selector: selector(),
            status: Vec::new(),
            cursor: None,
            limit: None,
        }),
    )
    .await
    .expect_err("unsigned concrete proposal query must fail closed")
    .into_response();
    assert_eq!(query.status(), StatusCode::UNAUTHORIZED);
    let resolve = handler_post_multisig_proposals_resolve(
        State(mk_app_state_for_tests()),
        Method::POST,
        routing::ENDPOINT_MULTISIG_PROPOSALS_RESOLVE
            .parse()
            .expect("multisig proposals resolve uri"),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        multisig_read_payload(routing::MultisigProposalsResolveRequestDto {
            selector: selector(),
            proposal_id: ("a".repeat(64)).parse().unwrap(),
        }),
    )
    .await
    .expect_err("unsigned concrete proposal resolve must fail closed")
    .into_response();
    assert_eq!(resolve.status(), StatusCode::UNAUTHORIZED);
}
fn multisig_read_contract_test_router(app: SharedAppState) -> Router {
    Router::new()
        .route(
            route_catalog::contracts_and_verification_keys::MULTISIG_SPEC_POST.path(),
            post(handler_post_multisig_spec)
                .layer(DefaultBodyLimit::max(MULTISIG_READ_MAX_BODY_BYTES)),
        )
        .route(
            route_catalog::contracts_and_verification_keys::MULTISIG_PROPOSALS_QUERY_POST.path(),
            post(handler_post_multisig_proposals_query)
                .layer(DefaultBodyLimit::max(MULTISIG_READ_MAX_BODY_BYTES)),
        )
        .route(
            route_catalog::contracts_and_verification_keys::MULTISIG_PROPOSALS_RESOLVE_POST.path(),
            post(handler_post_multisig_proposals_resolve)
                .layer(DefaultBodyLimit::max(MULTISIG_READ_MAX_BODY_BYTES)),
        )
        .fallback(|| async { StatusCode::NOT_FOUND })
        .with_state(app)
}
fn multisig_read_contract_request(
    method: HttpMethod,
    path: &str,
    body: impl Into<Body>,
) -> Request<Body> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .header(axum::http::header::ACCEPT, "application/json")
        .body(body.into())
        .expect("multisig read contract request");
    request
        .extensions_mut()
        .insert(crate::loopback_connect_info());
    request
}
#[tokio::test]
async fn multisig_read_http_contract_is_signed_post_only_closed_and_bounded() {
    let router = multisig_read_contract_test_router(mk_app_state_for_tests());
    let alias_body = r#"{"multisig_account_alias":"banking@centralbank.universal"}"#;
    let unsigned = router
        .clone()
        .oneshot(multisig_read_contract_request(
            HttpMethod::POST,
            "/v1/multisig/spec",
            alias_body,
        ))
        .await
        .expect("unsigned spec response");
    assert_eq!(
        unsigned.status(),
        StatusCode::UNAUTHORIZED,
        "unsigned alias selectors must fail before alias resolution"
    );
    for path in [
        "/v1/multisig/spec",
        "/v1/multisig/proposals/query",
        "/v1/multisig/proposals/resolve",
    ] {
        let method_response = router
            .clone()
            .oneshot(multisig_read_contract_request(
                HttpMethod::GET,
                path,
                Body::empty(),
            ))
            .await
            .expect("method response");
        assert_eq!(
            method_response.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "{path}"
        );
    }
    for retired in [
        "/v1/multisig/proposals/lookup",
        "/v1/multisig/proposals/list",
        "/v1/multisig/proposals/get",
        "/v1/multisig/proposals/search",
    ] {
        let response = router
            .clone()
            .oneshot(multisig_read_contract_request(
                HttpMethod::POST,
                retired,
                alias_body,
            ))
            .await
            .expect("retired route response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{retired}");
    }
    for (path, body) in [
        (
            "/v1/multisig/spec",
            r#"{"multisig_account_alias":"banking@centralbank.universal","extra":true}"#,
        ),
        (
            "/v1/multisig/proposals/query",
            r#"{"multisig_account_alias":"banking@centralbank.universal","status":[],"extra":true}"#,
        ),
        (
            "/v1/multisig/proposals/resolve",
            r#"{"multisig_account_alias":"banking@centralbank.universal","proposal_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","extra":true}"#,
        ),
    ] {
        let response = router
            .clone()
            .oneshot(multisig_read_contract_request(HttpMethod::POST, path, body))
            .await
            .expect("closed-schema response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
    }
    let malformed = router
        .clone()
        .oneshot(multisig_read_contract_request(
            HttpMethod::POST,
            "/v1/multisig/proposals/query",
            r#"{"multisig_account_alias": "unterminated"#,
        ))
        .await
        .expect("malformed JSON response");
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    let mut missing_content_type = multisig_read_contract_request(
        HttpMethod::POST,
        "/v1/multisig/proposals/query",
        alias_body,
    );
    missing_content_type
        .headers_mut()
        .remove(axum::http::header::CONTENT_TYPE);
    let missing_content_type = router
        .clone()
        .oneshot(missing_content_type)
        .await
        .expect("missing Content-Type response");
    assert_eq!(
        missing_content_type.status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    let oversized = format!(
        "{{\"multisig_account_alias\":\"banking@centralbank.universal\",\"padding\":\"{}\"}}",
        "x".repeat(MULTISIG_READ_MAX_BODY_BYTES)
    );
    let oversized_response = router
        .oneshot(multisig_read_contract_request(
            HttpMethod::POST,
            "/v1/multisig/proposals/query",
            oversized,
        ))
        .await
        .expect("oversized response");
    assert_eq!(oversized_response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
#[tokio::test]
async fn multisig_read_handler_requires_api_token_and_signed_viewer_auth() {
    let mut app = mk_app_state_for_tests();
    let state = Arc::get_mut(&mut app).expect("unique app state");
    state.require_api_token = true;
    state.api_token_digests = Arc::new(limits::ApiTokenDigestSet::from_tokens(["valid-token"]));
    let router = multisig_read_contract_test_router(app);
    let canonical_account_id =
        checked_torii_test_account_id(0x0c, "derive multisig API-token policy account fixture key");
    let body = norito::json::to_vec(&routing::MultisigSpecRequestDto {
        selector: routing::MultisigAccountSelectorDto {
            multisig_account_id: Some(canonical_account_id),
            multisig_account_alias: None,
        },
    })
    .expect("encode canonical multisig selector");
    let missing = router
        .clone()
        .oneshot(multisig_read_contract_request(
            HttpMethod::POST,
            "/v1/multisig/spec",
            body.clone(),
        ))
        .await
        .expect("missing-token response");
    assert_eq!(missing.status(), StatusCode::FORBIDDEN);
    let mut authenticated =
        multisig_read_contract_request(HttpMethod::POST, "/v1/multisig/spec", body);
    authenticated
        .headers_mut()
        .insert(HEADER_API_TOKEN, HeaderValue::from_static("valid-token"));
    let still_unsigned = router
        .oneshot(authenticated)
        .await
        .expect("authenticated read response");
    assert_eq!(still_unsigned.status(), StatusCode::UNAUTHORIZED);
}
#[tokio::test]
async fn browser_read_endpoints_are_not_throttled_by_deploy_limiter() {
    let app = mk_app_state_for_tests_with_options(None, Some((1, 1)), None, None);
    let headers = HeaderMap::new();
    let remote_ip = std::net::IpAddr::from([127, 0, 0, 1]);
    let key = super::rate_limit_key(
        &headers,
        Some(remote_ip),
        "v1/contracts/state",
        app.authenticated_api_token_principal(&headers),
    );
    assert!(app.deploy_rate_limiter.allow(&key).await);
    assert!(!app.deploy_rate_limiter.allow(&key).await);
    let contract_state_response = match handler_get_contract_state(
        State(app.clone()),
        headers.clone(),
        crate::loopback_connect_info(),
        AxQuery(routing::ContractStateQuery {
            prefix: Some("missing".to_owned()),
            ..Default::default()
        }),
    )
    .await
    {
        Ok(response) => response.into_response(),
        Err(error) => error.into_response(),
    };
    assert_ne!(
        contract_state_response.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    let selector = || routing::MultisigAccountSelectorDto {
        multisig_account_id: None,
        multisig_account_alias: Some("banking@centralbank.universal".to_owned()),
    };
    let spec_request = routing::MultisigSpecRequestDto {
        selector: selector(),
    };
    let spec_response = handler_post_multisig_spec(
        State(app.clone()),
        Method::POST,
        routing::ENDPOINT_MULTISIG_SPEC
            .parse()
            .expect("multisig spec uri"),
        headers.clone(),
        crate::loopback_connect_info(),
        multisig_read_payload(spec_request),
    )
    .await
    .expect_err("unsigned alias selectors must fail closed")
    .into_response();
    assert_ne!(spec_response.status(), StatusCode::TOO_MANY_REQUESTS);
    let query_request = routing::MultisigProposalsQueryRequestDto {
        selector: selector(),
        status: Vec::new(),
        cursor: None,
        limit: None,
    };
    let query_response = handler_post_multisig_proposals_query(
        State(app.clone()),
        Method::POST,
        routing::ENDPOINT_MULTISIG_PROPOSALS_QUERY
            .parse()
            .expect("multisig proposals query uri"),
        headers.clone(),
        crate::loopback_connect_info(),
        multisig_read_payload(query_request),
    )
    .await
    .expect_err("unsigned alias selectors must fail closed")
    .into_response();
    assert_ne!(query_response.status(), StatusCode::TOO_MANY_REQUESTS);
    let resolve_request = routing::MultisigProposalsResolveRequestDto {
        selector: selector(),
        proposal_id: "de".repeat(32).parse().unwrap(),
    };
    let resolve_response = handler_post_multisig_proposals_resolve(
        State(app),
        Method::POST,
        routing::ENDPOINT_MULTISIG_PROPOSALS_RESOLVE
            .parse()
            .expect("multisig proposals resolve uri"),
        headers,
        crate::loopback_connect_info(),
        multisig_read_payload(resolve_request),
    )
    .await
    .expect_err("unsigned alias selectors must fail closed")
    .into_response();
    assert_ne!(resolve_response.status(), StatusCode::TOO_MANY_REQUESTS);
}
#[tokio::test]
async fn browser_read_endpoints_use_route_scoped_query_rate_keys() {
    let mut app = mk_app_state_for_tests();
    {
        let state = Arc::get_mut(&mut app).expect("unique app state");
        state.rate_limiter = limits::RateLimiter::new(Some(1), Some(1));
    }
    let headers = HeaderMap::new();
    let remote_ip = std::net::IpAddr::from([127, 0, 0, 1]);
    let shared_key = super::rate_limit_key(
        &headers,
        Some(remote_ip),
        "v1/contracts/state",
        app.authenticated_api_token_principal(&headers),
    );
    assert!(app.rate_limiter.allow(&shared_key).await);
    assert!(!app.rate_limiter.allow(&shared_key).await);
    let selector = || routing::MultisigAccountSelectorDto {
        multisig_account_id: None,
        multisig_account_alias: Some("banking@centralbank.universal".to_owned()),
    };
    let spec_request = routing::MultisigSpecRequestDto {
        selector: selector(),
    };
    let spec_response = handler_post_multisig_spec(
        State(app.clone()),
        Method::POST,
        routing::ENDPOINT_MULTISIG_SPEC
            .parse()
            .expect("multisig spec uri"),
        headers.clone(),
        crate::loopback_connect_info(),
        multisig_read_payload(spec_request),
    )
    .await
    .expect_err("unsigned alias selectors must fail closed")
    .into_response();
    assert_ne!(spec_response.status(), StatusCode::TOO_MANY_REQUESTS);
    let query_request = routing::MultisigProposalsQueryRequestDto {
        selector: selector(),
        status: Vec::new(),
        cursor: None,
        limit: None,
    };
    let query_response = handler_post_multisig_proposals_query(
        State(app),
        Method::POST,
        routing::ENDPOINT_MULTISIG_PROPOSALS_QUERY
            .parse()
            .expect("multisig proposals query uri"),
        headers,
        crate::loopback_connect_info(),
        multisig_read_payload(query_request),
    )
    .await
    .expect_err("unsigned alias selectors must fail closed")
    .into_response();
    assert_ne!(query_response.status(), StatusCode::TOO_MANY_REQUESTS);
}
#[tokio::test]
async fn alias_resolve_index_returns_on_chain_alias_record() {
    let authority_keypair = checked_torii_test_ed25519_keypair(
        0x0d,
        "derive alias resolve-index on-chain authority fixture key",
    );
    let authority = AccountId::new(authority_keypair.public_key().clone());
    let alias_label = AccountAlias::new(
        "banking".parse().expect("label"),
        Some(iroha_data_model::account::rekey::AccountAliasDomain::new(
            "centralbank".parse::<Name>().expect("domain id"),
        )),
        DataSpaceId::UNIVERSAL,
    );
    let authority_account = Account::new(authority.clone()).build(&authority);
    let domain = Domain::new(DomainId::try_new("centralbank", "universal").expect("domain id"))
        .build(&authority);
    let app = crate::tests_runtime_handlers::native_ingress_app_with_world_for_test(World::with(
        [domain],
        [authority_account],
        [],
    ));
    bind_primary_account_alias_for_test(&app, &authority, &alias_label);
    grant_alias_resolve_permissions(&app, &authority, &alias_label);
    let request = routing::AliasResolveIndexRequestDto { index: 0 };
    let body = norito::json::to_vec(&request).expect("encode request");
    let method = axum::http::Method::POST;
    let uri: axum::http::Uri = "/v1/aliases/resolve-index"
        .parse()
        .expect("alias resolve-index uri");
    let headers = crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        &authority,
        &authority_keypair,
        &method,
        &uri,
        &body,
    );
    let response = handler_alias_resolve_index(
        State(app),
        method,
        uri,
        headers,
        axum::body::Bytes::from(body),
    )
    .await
    .expect("handler should succeed")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    let dto: routing::AliasResolveIndexResponseDto =
        norito::json::from_slice(&body).expect("json decode");
    assert_eq!(dto.index, 0);
    assert_eq!(dto.alias, "banking@centralbank.universal");
    assert_eq!(dto.account_id, authority.to_string());
    assert_eq!(dto.source.as_deref(), Some("active_sns"));
}
#[tokio::test]
async fn alias_resolve_index_fanout_returns_single_match_from_reachable_dataspace() {
    let authority_keypair = checked_torii_test_ed25519_keypair(
        0x0e,
        "derive alias resolve-index fanout authority fixture key",
    );
    let authority = AccountId::new(authority_keypair.public_key().clone());
    let app = crate::tests_runtime_handlers::native_ingress_app_with_world_and_nexus_for_test(
        world_with_account(&authority),
        crate::tests_runtime_handlers::multiple_dataspace_nexus_for_test(),
    );
    bind_account_alias_for_test(&app, &authority, "merchant@secondary");
    let request = routing::AliasResolveIndexRequestDto { index: 0 };
    let body = norito::json::to_vec(&request).expect("encode request");
    let method = axum::http::Method::POST;
    let uri: axum::http::Uri = "/v1/aliases/resolve-index"
        .parse()
        .expect("alias resolve-index uri");
    let headers = crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        &authority,
        &authority_keypair,
        &method,
        &uri,
        &body,
    );
    let response = handler_alias_resolve_index(
        State(app),
        method,
        uri,
        headers,
        axum::body::Bytes::from(body),
    )
    .await
    .expect("handler should succeed")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-fanout-routes-attempted")
            .and_then(|value| value.to_str().ok()),
        Some("2")
    );
    assert_eq!(
        response
            .headers()
            .get("x-iroha-fanout-routes-succeeded")
            .and_then(|value| value.to_str().ok()),
        Some("1")
    );
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    let dto: routing::AliasResolveIndexResponseDto =
        norito::json::from_slice(&body).expect("json decode");
    assert_eq!(dto.index, 0);
    assert_eq!(dto.alias, "merchant@secondary");
    assert_eq!(dto.account_id, authority.to_string());
    assert_eq!(dto.source.as_deref(), Some("fanout"));
}
#[tokio::test]
async fn alias_resolve_index_fanout_returns_route_conflict_for_incompatible_bindings() {
    let authority_keypair = checked_torii_test_ed25519_keypair(
        0x0f,
        "derive alias resolve-index route-conflict authority fixture key",
    );
    let authority = AccountId::new(authority_keypair.public_key().clone());
    let app = crate::tests_runtime_handlers::native_ingress_app_with_world_and_nexus_for_test(
        world_with_account(&authority),
        crate::tests_runtime_handlers::multiple_dataspace_nexus_for_test(),
    );
    bind_account_alias_for_test(&app, &authority, "merchant@universal");
    bind_account_alias_for_test(&app, &authority, "merchant@secondary");
    let request = routing::AliasResolveIndexRequestDto { index: 0 };
    let body = norito::json::to_vec(&request).expect("encode request");
    let method = axum::http::Method::POST;
    let uri: axum::http::Uri = "/v1/aliases/resolve-index"
        .parse()
        .expect("alias resolve-index uri");
    let headers = crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        &authority,
        &authority_keypair,
        &method,
        &uri,
        &body,
    );
    let response = handler_alias_resolve_index(
        State(app),
        method,
        uri,
        headers,
        axum::body::Bytes::from(body),
    )
    .await
    .expect("handler should succeed")
    .into_response();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("route_conflict")
    );
    assert_eq!(
        response
            .headers()
            .get("x-iroha-fanout-routes-succeeded")
            .and_then(|value| value.to_str().ok()),
        Some("2")
    );
}
#[tokio::test]
async fn alias_resolve_index_returns_not_found_when_index_is_missing() {
    let authority_keypair = checked_torii_test_ed25519_keypair(
        0x20,
        "derive alias resolve-index missing authority fixture key",
    );
    let authority = AccountId::new(authority_keypair.public_key().clone());
    let authority_account = Account::new(authority.clone()).build(&authority);
    let app = crate::tests_runtime_handlers::native_ingress_app_with_world_for_test(World::with(
        [],
        [authority_account],
        [],
    ));
    let request = routing::AliasResolveIndexRequestDto { index: 0 };
    let body = norito::json::to_vec(&request).expect("encode request");
    let method = axum::http::Method::POST;
    let uri: axum::http::Uri = "/v1/aliases/resolve-index"
        .parse()
        .expect("alias resolve-index uri");
    let headers = crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        &authority,
        &authority_keypair,
        &method,
        &uri,
        &body,
    );
    let response = handler_alias_resolve_index(
        State(app),
        method,
        uri,
        headers,
        axum::body::Bytes::from(body),
    )
    .await
    .expect("handler should succeed")
    .into_response();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
#[tokio::test]
async fn alias_resolve_index_returns_permission_denied_when_denied_routes_block_miss_fallback() {
    let authority_keypair = checked_torii_test_ed25519_keypair(
        0x21,
        "derive alias resolve-index signed authority fixture key",
    );
    let authority = AccountId::new(authority_keypair.public_key().clone());
    let uaid = UniversalAccountId::from_hash(Hash::new(b"torii::alias-index-miss-offline"));
    let app = crate::tests_runtime_handlers::native_ingress_app_with_world_and_nexus_for_test(
        world_with_account_bound_to_dataspace(&authority, uaid, DataSpaceId::new(12)),
        crate::tests_runtime_handlers::private_ingress_with_offline_foreign_nexus_for_test(),
    );
    let candidates = torii_all_dataspace_routes(app.as_ref());
    let (allowed, denied) =
        torii_partition_alias_index_routes_by_permission(&app, candidates, Some(&authority), 0)
            .expect("resolve explicit alias permissions");
    assert_eq!(
        allowed,
        vec![RoutingDecision::new(LaneId::new(0), DataSpaceId::new(0))]
    );
    assert_eq!(
        denied, 2,
        "UAID visibility does not grant alias resolution permission"
    );
    let request = routing::AliasResolveIndexRequestDto { index: 0 };
    let body = norito::json::to_vec(&request).expect("encode request");
    let method = axum::http::Method::POST;
    let uri: axum::http::Uri = "/v1/aliases/resolve-index"
        .parse()
        .expect("alias resolve-index uri");
    let headers = crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        &authority,
        &authority_keypair,
        &method,
        &uri,
        &body,
    );
    let response = handler_alias_resolve_index(
        State(app),
        method,
        uri,
        headers,
        axum::body::Bytes::from(body),
    )
    .await
    .expect("handler should succeed")
    .into_response();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("permission_denied"),
    );
    assert_eq!(
        response
            .headers()
            .get("x-iroha-fanout-routes-denied")
            .and_then(|value| value.to_str().ok()),
        Some("2"),
        "both restricted routes require an explicit alias resolution permission"
    );
    assert_eq!(
        response
            .headers()
            .get("x-iroha-fanout-routes-unavailable")
            .and_then(|value| value.to_str().ok()),
        Some("0"),
        "the foreign route is denied before any proxy attempt"
    );
    assert_eq!(
        response
            .headers()
            .get("x-iroha-fanout-routes-not-found")
            .and_then(|value| value.to_str().ok()),
        Some("1"),
        "the allowed public Nexus route has no alias at this index"
    );
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    let payload = norito::decode_from_bytes::<super::ErrorEnvelope>(&body).expect("decode error");
    assert_eq!(payload.code, "permission_denied");
}
#[tokio::test]
async fn alias_resolve_index_returns_permission_denied_when_only_hidden_routes_can_resolve() {
    let caller_keypair = checked_torii_test_ed25519_keypair(
        0x22,
        "derive alias resolve-index hidden-route caller fixture key",
    );
    let caller = AccountId::new(caller_keypair.public_key().clone());
    let target = checked_torii_test_account_id(
        0x23,
        "derive alias resolve-index hidden-route target fixture key",
    );
    let uaid = UniversalAccountId::from_hash(Hash::new(b"torii::alias-index-denied-fanout"));
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        world_with_target_and_caller_bound_to_dataspace(
            &target,
            &caller,
            uaid,
            DataSpaceId::new(10),
        ),
        crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
    );
    configure_private_ingress_routes_for_test(&mut app);
    bind_account_alias_for_test(&app, &target, "merchant@restricted");
    let request = routing::AliasResolveIndexRequestDto { index: 0 };
    let body = norito::json::to_vec(&request).expect("encode request");
    let method = axum::http::Method::POST;
    let uri: axum::http::Uri = "/v1/aliases/resolve-index"
        .parse()
        .expect("alias resolve-index uri");
    let headers = signed_app_headers(&caller, &caller_keypair, &method, &uri, &body);
    let response = handler_alias_resolve_index(
        State(app),
        method,
        uri,
        headers,
        axum::body::Bytes::from(body),
    )
    .await
    .expect("handler should succeed")
    .into_response();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("permission_denied")
    );
    assert_eq!(
        response
            .headers()
            .get("x-iroha-fanout-routes-denied")
            .and_then(|value| value.to_str().ok()),
        Some("1")
    );
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    let payload = norito::decode_from_bytes::<super::ErrorEnvelope>(&body).expect("decode error");
    assert_eq!(payload.code, "permission_denied");
}
#[test]
fn api_token_evaluator_has_one_exact_header_policy() {
    let configured = limits::ApiTokenDigestSet::from_tokens(["secret"]);
    let empty = limits::ApiTokenDigestSet::default();
    let no_headers = HeaderMap::new();
    let mut supplied = HeaderMap::new();
    supplied.insert(HEADER_API_TOKEN, HeaderValue::from_static("secret"));
    assert_eq!(
        evaluate_api_token(false, &empty, &no_headers),
        ApiTokenEvaluation::Disabled
    );
    assert!(
        evaluate_api_token(false, &configured, &supplied)
            .authenticated_principal()
            .is_none(),
        "an unauthenticated header must not become a rate-limit principal"
    );
    assert_eq!(
        evaluate_api_token(true, &empty, &supplied),
        ApiTokenEvaluation::Unavailable
    );
    assert_eq!(
        evaluate_api_token(true, &configured, &no_headers),
        ApiTokenEvaluation::Invalid
    );
    let mut invalid_utf8 = HeaderMap::new();
    invalid_utf8.insert(
        HEADER_API_TOKEN,
        HeaderValue::from_bytes(&[0xff]).expect("opaque token fixture"),
    );
    assert_eq!(
        evaluate_api_token(true, &configured, &invalid_utf8),
        ApiTokenEvaluation::Invalid
    );
    let mut duplicate_valid = HeaderMap::new();
    duplicate_valid.append(HEADER_API_TOKEN, HeaderValue::from_static("secret"));
    duplicate_valid.append(HEADER_API_TOKEN, HeaderValue::from_static("secret"));
    assert_eq!(
        evaluate_api_token(true, &configured, &duplicate_valid),
        ApiTokenEvaluation::Invalid
    );
    let mut mixed_duplicate = HeaderMap::new();
    mixed_duplicate.append(HEADER_API_TOKEN, HeaderValue::from_static("secret"));
    mixed_duplicate.append(HEADER_API_TOKEN, HeaderValue::from_static("other"));
    assert_eq!(
        evaluate_api_token(true, &configured, &mixed_duplicate),
        ApiTokenEvaluation::Invalid
    );
    assert_eq!(
        evaluate_api_token(true, &configured, &supplied),
        ApiTokenEvaluation::Authenticated(limits::ApiTokenPrincipal::from_token("secret"))
    );
}
#[test]
fn validate_api_token_rejects_missing_or_unconfigured() {
    let mut app = mk_app_state_for_tests();
    let state = Arc::get_mut(&mut app).expect("unique app state");
    state.require_api_token = true;
    state.api_token_digests = Arc::new(limits::ApiTokenDigestSet::default());
    let headers = HeaderMap::new();
    assert!(validate_api_token(state, &headers).is_err());
    let mut configured_headers = HeaderMap::new();
    configured_headers.insert(HEADER_API_TOKEN, HeaderValue::from_static("secret"));
    state.api_token_digests = Arc::new(limits::ApiTokenDigestSet::from_tokens(["secret"]));
    assert!(validate_api_token(state, &configured_headers).is_ok());
}
fn assert_unconfigured_api_token_error(error: Error) {
    match error {
        Error::Query(ValidationFail::NotPermitted(message)) => {
            assert!(
                message.contains("none are configured"),
                "unexpected API-token rejection: {message}"
            );
        }
        other => panic!("unexpected API-token rejection: {other:?}"),
    }
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn direct_result_handler_fails_closed_with_no_configured_api_tokens() {
    let mut app = mk_app_state_for_tests();
    let state = Arc::get_mut(&mut app).expect("unique app state");
    state.require_api_token = true;
    state.api_token_digests = Arc::new(limits::ApiTokenDigestSet::default());
    let error =
        handler_soracloud_status(State(app), HeaderMap::new(), loopback_connect_info(), None)
            .await
            .expect_err("handler-local API-token validation must fail closed");
    assert_unconfigured_api_token_error(error);
}
#[tokio::test]
async fn direct_transaction_ingress_fails_closed_before_queue_or_rate_work() {
    let mut app = mk_app_state_for_tests();
    let state = Arc::get_mut(&mut app).expect("unique app state");
    state.require_api_token = true;
    state.api_token_digests = Arc::new(limits::ApiTokenDigestSet::default());
    let keypair = checked_torii_test_ed25519_keypair(
        0xd1,
        "derive fail-closed transaction ingress fixture key",
    );
    let transaction = TransactionBuilder::new(
        *app.state.network_id_ref(),
        AccountId::new(keypair.public_key().clone()),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .sign(keypair.private_key());
    let queue_len = app.queue.active_len();
    let error = submit_signed_transaction_for_ingress(
        Arc::clone(&app),
        HeaderMap::new(),
        None,
        transaction,
    )
    .await
    .expect_err("direct transaction ingress must fail closed");
    assert_unconfigured_api_token_error(error);
    assert_eq!(
        app.queue.active_len(),
        queue_len,
        "authentication failure must not mutate queue state"
    );
}

#[cfg(feature = "app_api")]
fn contract_call_admission_test_receipt() -> routing::ContractCallResponseDto {
    routing::ContractCallResponseDto {
        ok: true,
        submitted: false,
        dataspace: "universal".to_owned(),
        contract_address: None,
        code_hash_hex: "11".repeat(32),
        abi_hash_hex: "22".repeat(32),
        creation_time_ms: 42,
        transaction_ttl_ms: None,
        tx_hash_hex: None,
        pipeline_status: None,
        entrypoint_hash_hex: None,
        transaction_payload_b64: Some("prepared-payload".to_owned()),
        signing_message_b64: Some("prepared-signing-message".to_owned()),
        entrypoint: Some("main".to_owned()),
        operation_receipt: routing::OperationReceiptDto {
            operation_kind: "contract_call".to_owned(),
            status: "pending_signature".to_owned(),
            transport: "torii".to_owned(),
            dataspace: "universal".to_owned(),
            contract_alias: None,
            contract_address: None,
            code_hash_hex: Some("11".repeat(32)),
            abi_hash_hex: Some("22".repeat(32)),
            tx_hash_hex: None,
            entrypoint: Some("main".to_owned()),
            entrypoint_hash_hex: None,
            gas_limit: Some(5_000),
            gas_used: None,
            fee_payment: Some(iroha_data_model::transaction::FeePaymentIntent::authority(
                Vec::new(),
                std::num::NonZeroU64::new(5_000),
            )),
            payload_digest_hex: "55".repeat(32),
        },
    }
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn prepared_contract_call_requires_canonical_ingress_before_success() {
    let mut app = mk_app_state_for_tests();
    let state = Arc::get_mut(&mut app).expect("unique app state");
    state.require_api_token = true;
    state.api_token_digests = Arc::new(limits::ApiTokenDigestSet::default());
    let key = checked_torii_test_ed25519_keypair(0xe4, "contract detached dispatch fixture");
    let transaction = TransactionBuilder::new(
        *app.state.network_id_ref(),
        AccountId::new(key.public_key().clone()),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .try_sign(key.private_key())
    .expect("sign exact ingress fixture");
    let queue_len = app.queue.active_len();
    let prepared = routing::PreparedContractCallRequest {
        transaction: Some(transaction),
        response: contract_call_admission_test_receipt(),
    };
    let error = submit_prepared_contract_call(app.clone(), HeaderMap::new(), prepared)
        .await
        .expect_err("prepared receipt cannot bypass canonical ingress authentication");
    assert_unconfigured_api_token_error(error);
    assert_eq!(app.queue.active_len(), queue_len);

    let draft = contract_call_admission_test_receipt();
    let unsigned = submit_prepared_contract_call(
        app.clone(),
        HeaderMap::new(),
        routing::PreparedContractCallRequest {
            response: draft,
            transaction: None,
        },
    )
    .await
    .expect("unsigned preparation does not enter transaction ingress");
    assert_eq!(unsigned.status(), StatusCode::OK);
    assert_eq!(app.queue.active_len(), queue_len);
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn contract_call_submission_preserves_rejected_and_ambiguous_responses() {
    for status in [
        StatusCode::OK,
        StatusCode::CONFLICT,
        StatusCode::SERVICE_UNAVAILABLE,
    ] {
        let body = if status == StatusCode::SERVICE_UNAVAILABLE {
            "{\"code\":\"route_unavailable\"}"
        } else {
            "{\"code\":\"routing_plan_mismatch\"}"
        };
        let admitted = AxResponse::builder()
            .status(status)
            .header("content-type", "application/json")
            .header("x-iroha-entrypoint-hash", "entrypoint-identity")
            .header("x-iroha-signed-transaction-hash", "signed-identity")
            .body(Body::from(body))
            .expect("canonical owner response fixture");
        let expected_headers = admitted.headers().clone();
        let response = contract_call_response_after_admission(
            contract_call_admission_test_receipt(),
            admitted,
            "33".repeat(32),
            "44".repeat(32),
        );
        assert_eq!(response.status(), status);
        assert_eq!(response.headers(), &expected_headers);
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .expect("bounded response");
        assert_eq!(bytes.as_ref(), body.as_bytes());
    }
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn contract_call_submission_emits_contract_receipt_after_accepted() {
    let receipt = contract_call_admission_test_receipt();
    let mut expected = norito::json::to_value(&receipt).expect("exact prepared receipt");
    let fields = expected.as_object_mut().expect("prepared response object");
    fields.insert("submitted".to_owned(), norito::json::Value::Bool(true));
    fields.insert(
        "tx_hash_hex".to_owned(),
        norito::json::Value::String("33".repeat(32)),
    );
    fields.insert(
        "entrypoint_hash_hex".to_owned(),
        norito::json::Value::String("44".repeat(32)),
    );
    fields.insert(
        "transaction_payload_b64".to_owned(),
        norito::json::Value::Null,
    );
    fields.insert("signing_message_b64".to_owned(), norito::json::Value::Null);
    let receipt_fields = fields
        .get_mut("operation_receipt")
        .expect("receipt")
        .as_object_mut()
        .expect("receipt object");
    receipt_fields.insert(
        "status".to_owned(),
        norito::json::Value::String("submitted".to_owned()),
    );
    receipt_fields.insert(
        "tx_hash_hex".to_owned(),
        norito::json::Value::String("33".repeat(32)),
    );
    receipt_fields.insert(
        "entrypoint_hash_hex".to_owned(),
        norito::json::Value::String("44".repeat(32)),
    );
    let admitted = AxResponse::builder()
        .status(StatusCode::ACCEPTED)
        .body(Body::empty())
        .expect("accepted admission fixture");
    let response =
        contract_call_response_after_admission(receipt, admitted, "33".repeat(32), "44".repeat(32));
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 16_384)
        .await
        .expect("bounded contract receipt");
    let actual: norito::json::Value = norito::json::from_slice(&bytes).expect("decode receipt");
    assert_eq!(actual, expected);
    assert_eq!(actual["submitted"].as_bool(), Some(true));
    assert!(
        actual["pipeline_status"].is_null(),
        "certified admission does not claim local queue presence"
    );
    assert!(actual["transaction_payload_b64"].is_null());
    assert!(actual["signing_message_b64"].is_null());
}

#[test]
fn artifact_visibility_binds_private_root_and_rechecks_revoked_grants() {
    use iroha_core::smartcontracts::Execute as _;
    use iroha_data_model::smart_contract::ContractArtifactId;
    let app = crate::tests_runtime_handlers::app_with_root_scope_for_handler_test(
        iroha_core::state::World::new(),
        true,
    );
    let caller = checked_torii_test_account_id(0x75, "scoped artifact reader fixture");
    let owned = ContractArtifactId::new(
        DataSpaceId::new(u64::MAX - 1),
        Hash::new(b"scoped artifact"),
    );
    let foreign = ContractArtifactId::new(DataSpaceId::new(u64::MAX), owned.code_hash);
    let grant: Permission = CanReadAllLedgerData.into();
    {
        let mut block = app.state.block(BlockHeader::new(
            NonZeroU64::new(1).unwrap(),
            None,
            None,
            0,
            0,
        ));
        let mut transaction = block.transaction();
        iroha_data_model::isi::Register::account(Account::new(caller.clone()))
            .execute(&caller, &mut transaction)
            .expect("seed universal account");
        transaction
            .world_mut_for_testing()
            .add_account_permission(&caller, grant.clone());
        transaction.apply();
        block.commit_world_overlay_for_testing().unwrap();
    }
    require_contract_artifact_visibility(&app, &caller, owned)
        .expect("owner reader can read exact private root");
    assert!(
        require_contract_artifact_visibility(&app, &caller, foreign).is_err(),
        "even a ledger-wide read grant cannot substitute a private listener's root"
    );
    {
        let mut block = app.state.block(BlockHeader::new(
            NonZeroU64::new(2).unwrap(),
            None,
            None,
            0,
            0,
        ));
        let mut transaction = block.transaction();
        assert!(
            transaction
                .world_mut_for_testing()
                .remove_account_permission(&caller, &grant)
        );
        transaction.apply();
        block.commit_world_overlay_for_testing().unwrap();
    }
    assert!(
        require_contract_artifact_visibility(&app, &caller, owned).is_err(),
        "revocation must take effect on the next read"
    );
    let absent = mk_app_state_for_tests_with_world(world_with_account(&caller));
    assert!(
        require_contract_artifact_visibility(&absent, &caller, owned).is_err(),
        "missing immutable scope is never an implicit global root"
    );
}
