// Crate-root HTTP middleware, metadata and response-contract test modules.

#[cfg(test)]
mod matched_route_metadata_tests {
    use super::*;
    use axum::{
        Extension,
        body::Body,
        http::{Request, StatusCode, header},
    };
    use iroha_torii_shared::route_catalog::{
        AdmissionPolicy, ApiSurface, AuthenticationPolicy, EnabledFeatures, HttpMethod, Listener,
        RouteDescriptor, RouteEffect, RouteProjections,
    };
    const ITEM: RouteDescriptor = RouteDescriptor::new(
        "test.item.read",
        HttpMethod::Get,
        "/v1/tests/items/{item_id}",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_projections(RouteProjections::OPENAPI_AND_SDK);
    const CORS_ITEM: RouteDescriptor = RouteDescriptor::new(
        "test.cors_item.read",
        HttpMethod::Get,
        "/v1/tests/cors-items/{item_id}",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_cors_options(true);
    const CREDENTIAL_EXCHANGE: RouteDescriptor = RouteDescriptor::new(
        "test.operator_credential_exchange",
        HttpMethod::Post,
        "/v1/tests/operator-credential",
        ApiSurface::Operator,
        Listener::Torii,
        RouteEffect::Mutation,
        AdmissionPolicy::Operator,
    )
    .with_authentication(AuthenticationPolicy::OperatorCredentialExchange)
    .with_cors_options(true);
    const PUBLIC_CREDENTIAL_READ: RouteDescriptor = RouteDescriptor::new(
        "test.operator_credential_public_read",
        HttpMethod::Get,
        "/v1/tests/operator-credential",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::Public,
    )
    .with_cors_options(true);
    const CANONICAL_ACCOUNT_READ: RouteDescriptor = RouteDescriptor::new(
        "test.canonical_account_read",
        HttpMethod::Get,
        "/v1/tests/canonical-account",
        ApiSurface::Public,
        Listener::Torii,
        RouteEffect::ReadOnly,
        AdmissionPolicy::AuthenticatedAccount,
    )
    .with_authentication(AuthenticationPolicy::CanonicalAccountSignature);
    async fn metadata_handler(Extension(metadata): Extension<MatchedRouteMetadata>) -> Response {
        assert_eq!(metadata.stable_route_id(), "test.item.read");
        assert_eq!(metadata.path_template(), "/v1/tests/items/{item_id}");
        StatusCode::NO_CONTENT.into_response()
    }
    #[test]
    fn gateway_metrics_use_only_cataloged_bounded_labels() {
        let car = MatchedRouteMetadata::from_descriptor(route_catalog::sorafs::STORAGE_CAR);
        let labels =
            sorafs_gateway_request_metric_labels(&car, "GET").expect("gateway metric route");
        assert_eq!(labels.endpoint, route_catalog::sorafs::STORAGE_CAR.path());
        assert_eq!(labels.method, "GET");
        assert_eq!(labels.variant, "car");
        assert_eq!(labels.chunker, "unknown");
        assert_eq!(labels.profile, "unknown");
        let proof = MatchedRouteMetadata::from_descriptor(route_catalog::sorafs::PROOF_STREAM);
        let labels =
            sorafs_gateway_request_metric_labels(&proof, "POST").expect("proof metric route");
        assert_eq!(labels.variant, "proof_stream");
        assert_eq!(labels.chunker, "none");
        assert_eq!(
            labels.profile,
            sorafs_manifest::gateway_fixture::SORAFS_GATEWAY_PROFILE_VERSION
        );
        let unrelated = MatchedRouteMetadata::from_descriptor(ITEM);
        assert!(sorafs_gateway_request_metric_labels(&unrelated, "GET").is_none());
    }
    #[tokio::test]
    async fn concrete_identifier_and_cursor_never_enter_matched_route_metadata() {
        let mut builder =
            RouterBuilder::new((), RouteCatalog::new(&[ITEM]), EnabledFeatures::none())
                .expect("valid test catalog");
        builder.route(&ITEM, catalog_get(metadata_handler));
        let (router, manifest) = builder.finish().expect("complete test router");
        let router = router
            .layer(axum::middleware::from_fn_with_state(
                manifest.route_index(),
                attach_matched_route_metadata,
            ))
            .with_state(());
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/v1/tests/items/customer-secret?cursor=eyJzbmFwc2hvdCI6MTIzfQ")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let metadata = response
            .extensions()
            .get::<MatchedRouteMetadata>()
            .expect("response route metadata");
        assert_eq!(metadata.stable_route_id(), "test.item.read");
        assert_eq!(metadata.path_template(), "/v1/tests/items/{item_id}");
        assert!(!metadata.path_template().contains("customer-secret"));
        assert!(!metadata.path_template().contains("cursor"));
    }
    #[tokio::test]
    async fn host_selected_site_metadata_is_bounded_and_cannot_shadow_catalog_routes() {
        let mut builder =
            RouterBuilder::new((), RouteCatalog::new(&[ITEM]), EnabledFeatures::none())
                .expect("valid test catalog");
        builder.route(&ITEM, catalog_get(metadata_handler));
        let (router, manifest) = builder.finish().expect("complete test router");
        let router = router
            .fallback(|| async { StatusCode::NO_CONTENT })
            .layer(axum::middleware::from_fn_with_state(
                manifest.route_index(),
                attach_matched_route_metadata,
            ))
            .with_state(());

        let mut site_request = Request::builder()
            .uri("/assets/customer-secret.js")
            .body(Body::empty())
            .expect("host-selected request");
        site_request
            .extensions_mut()
            .insert(HostSelectedSorafsRoute::Path);
        let response = router
            .clone()
            .oneshot(site_request)
            .await
            .expect("host-selected response");
        let metadata = response
            .extensions()
            .get::<MatchedRouteMetadata>()
            .expect("response route metadata");
        assert_eq!(
            metadata.stable_route_id(),
            SORAFS_HOST_SITE_PATH_ROUTE.stable_route_id()
        );
        assert_eq!(metadata.path_template(), "/{*path}");
        assert_eq!(metadata.surface(), Some(ApiSurface::Public));
        assert!(!metadata.path_template().contains("customer-secret"));

        let mut catalog_request = Request::builder()
            .uri("/v1/tests/items/customer-secret")
            .body(Body::empty())
            .expect("catalog request");
        catalog_request
            .extensions_mut()
            .insert(HostSelectedSorafsRoute::Path);
        let response = router
            .oneshot(catalog_request)
            .await
            .expect("catalog response");
        let metadata = response
            .extensions()
            .get::<MatchedRouteMetadata>()
            .expect("response route metadata");
        assert_eq!(metadata.stable_route_id(), ITEM.stable_route_id());
        assert_eq!(metadata.path_template(), ITEM.path());
    }
    #[tokio::test]
    async fn host_selected_site_rejected_method_is_not_labeled_as_a_get() {
        let builder = RouterBuilder::new((), RouteCatalog::new(&[]), EnabledFeatures::none())
            .expect("valid empty test catalog");
        let (router, manifest) = builder.finish().expect("complete test router");
        let router = router
            .fallback(|| async { StatusCode::METHOD_NOT_ALLOWED })
            .layer(axum::middleware::from_fn_with_state(
                manifest.route_index(),
                attach_matched_route_metadata,
            ))
            .with_state(());
        let mut request = Request::builder()
            .method(axum::http::Method::POST)
            .uri("/")
            .body(Body::empty())
            .expect("host-selected request");
        request
            .extensions_mut()
            .insert(HostSelectedSorafsRoute::Root);
        let response = router
            .oneshot(request)
            .await
            .expect("method-not-allowed response");
        let metadata = response
            .extensions()
            .get::<MatchedRouteMetadata>()
            .expect("response route metadata");
        assert_eq!(metadata.stable_route_id(), "http.method_not_allowed");
        assert_eq!(metadata.path_template(), "/");
        assert_eq!(metadata.transport(), None);
        assert_eq!(metadata.surface(), Some(ApiSurface::Public));
    }
    #[tokio::test]
    async fn host_selected_site_bypasses_listener_token_only_when_fallback_wins() {
        let mut app = crate::mk_app_state_for_tests();
        let state = Arc::get_mut(&mut app).expect("unique test app state");
        state.require_api_token = true;
        state.api_token_digests = Arc::new(limits::ApiTokenDigestSet::from_tokens(["valid-token"]));
        state.sorafs_site_bindings = Some(Arc::new(sorafs::site::SiteBindingsDocument {
            version: 1,
            sites: vec![sorafs::site::SiteBinding {
                hostname: "site.example".to_owned(),
                manifest_digest_hex: "00".repeat(32),
                index_document: None,
                spa_fallback: None,
            }],
        }));
        let mut builder = RouterBuilder::new(
            app.clone(),
            RouteCatalog::new(&[ITEM]),
            EnabledFeatures::none(),
        )
        .expect("valid test catalog");
        builder.route(&ITEM, catalog_get(|| async { StatusCode::NO_CONTENT }));
        let (router, manifest) = builder.finish().expect("complete test router");
        let router = router
            .fallback(handler_route_not_found_or_sorafs_site)
            .layer(axum::middleware::from_fn_with_state(
                app.clone(),
                enforce_api_token,
            ))
            .layer(axum::middleware::from_fn_with_state(
                manifest.route_index(),
                attach_matched_route_metadata,
            ))
            .layer(axum::middleware::from_fn_with_state(
                app.clone(),
                mark_host_selected_sorafs_route,
            ))
            .layer(axum::middleware::from_fn_with_state(
                app.clone(),
                enforce_required_api_token_private_no_store,
            ))
            .with_state(app);

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/assets/app.js")
                    .header(header::HOST, "site.example")
                    .body(Body::empty())
                    .expect("site request"),
            )
            .await
            .expect("site response");
        assert_ne!(response.status(), StatusCode::UNAUTHORIZED);
        let metadata = response
            .extensions()
            .get::<MatchedRouteMetadata>()
            .expect("site route metadata");
        assert_eq!(
            metadata.stable_route_id(),
            SORAFS_HOST_SITE_PATH_ROUTE.stable_route_id()
        );
        assert_ne!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("private, no-store"))
        );

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::HOST, "site.example")
                    .body(Body::empty())
                    .expect("site root request"),
            )
            .await
            .expect("site root response");
        assert_ne!(response.status(), StatusCode::UNAUTHORIZED);
        let metadata = response
            .extensions()
            .get::<MatchedRouteMetadata>()
            .expect("site root route metadata");
        assert_eq!(
            metadata.stable_route_id(),
            SORAFS_HOST_SITE_ROOT_ROUTE.stable_route_id()
        );

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/v1/tests/items/customer-secret")
                    .header(header::HOST, "site.example")
                    .body(Body::empty())
                    .expect("catalog request"),
            )
            .await
            .expect("catalog response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let metadata = response
            .extensions()
            .get::<MatchedRouteMetadata>()
            .expect("catalog route metadata");
        assert_eq!(metadata.stable_route_id(), ITEM.stable_route_id());
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("private, no-store"))
        );
    }
    #[tokio::test]
    async fn credential_exchange_overwrites_conflicting_inner_cache_policy() {
        use http_body_util::BodyExt as _;

        let mut builder = RouterBuilder::new(
            (),
            RouteCatalog::new(&[CREDENTIAL_EXCHANGE]),
            EnabledFeatures::none(),
        )
        .expect("valid credential-exchange catalog");
        builder.route(
            &CREDENTIAL_EXCHANGE,
            catalog_post(|| async {
                let mut response = (StatusCode::OK, "credential-response").into_response();
                response.headers_mut().insert(
                    header::CACHE_CONTROL,
                    HeaderValue::from_static("public, max-age=86400"),
                );
                response
            })
            .authenticated_in_handler(HandlerAuthentication::OperatorCredentialExchange),
        );
        let (router, manifest) = builder.finish().expect("complete credential router");
        let router = router
            .layer(axum::middleware::from_fn_with_state(
                manifest.route_index(),
                attach_matched_route_metadata,
            ))
            .layer(axum::middleware::from_fn(enforce_catalog_private_no_store))
            .with_state(());
        let response = router
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::POST)
                    .uri(CREDENTIAL_EXCHANGE.path())
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("private, no-store"))
        );
        assert!(
            response
                .extensions()
                .get::<MatchedRouteMetadata>()
                .is_some_and(MatchedRouteMetadata::requires_private_no_store)
        );
        let body = response
            .into_body()
            .collect()
            .await
            .expect("collect credential response")
            .to_bytes();
        assert_eq!(body.as_ref(), b"credential-response");
    }
    #[cfg(feature = "app_api")]
    #[tokio::test]
    async fn early_canonical_auth_rejection_is_private_no_store() {
        let app = crate::mk_app_state_for_tests();
        let mut builder = RouterBuilder::new(
            app.clone(),
            RouteCatalog::new(&[CANONICAL_ACCOUNT_READ]),
            EnabledFeatures::none(),
        )
        .expect("valid canonical-account catalog");
        builder.route(
            &CANONICAL_ACCOUNT_READ,
            catalog_get(|| async { StatusCode::NO_CONTENT })
                .authenticated_canonical_account_body(app.clone(), 0),
        );
        let (router, manifest) = builder.finish().expect("complete canonical-account router");
        let router = router
            .layer(axum::middleware::from_fn_with_state(
                manifest.route_index(),
                attach_matched_route_metadata,
            ))
            .layer(axum::middleware::from_fn(enforce_catalog_private_no_store))
            .with_state(app);
        let response = router
            .oneshot(
                Request::builder()
                    .uri(CANONICAL_ACCOUNT_READ.path())
                    .body(Body::empty())
                    .expect("unsigned canonical-account request"),
            )
            .await
            .expect("canonical-account rejection");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("private, no-store"))
        );
        assert!(
            response
                .extensions()
                .get::<MatchedRouteMetadata>()
                .is_some_and(MatchedRouteMetadata::requires_private_no_store)
        );
    }
    fn connect_cache_policy_test_router() -> (Router, MountedRouteIndex) {
        const CONNECT_FEATURES: &[&str] = &["connect"];
        let mut builder = RouterBuilder::new(
            (),
            RouteCatalog::new(&[
                route_catalog::connect::SESSION_CREATE,
                route_catalog::connect::SESSION_STATUS,
            ]),
            EnabledFeatures::new(CONNECT_FEATURES),
        )
        .expect("valid Connect credential catalog");
        builder.route(
            &route_catalog::connect::SESSION_CREATE,
            catalog_post(|| async {
                let mut response = (StatusCode::OK, "role-and-management-tokens").into_response();
                response.headers_mut().insert(
                    header::CACHE_CONTROL,
                    HeaderValue::from_static("public, max-age=86400"),
                );
                response
            })
            .authenticated_in_handler(HandlerAuthentication::ProtocolHandshake),
        );
        builder.route(
            &route_catalog::connect::SESSION_STATUS,
            catalog_get(|| async {
                let mut response = StatusCode::UNAUTHORIZED.into_response();
                response.headers_mut().insert(
                    header::CACHE_CONTROL,
                    HeaderValue::from_static("public, max-age=86400"),
                );
                response
            })
            .authenticated_in_handler(HandlerAuthentication::ProtocolHandshake),
        );
        let (router, manifest) = builder
            .finish()
            .expect("complete Connect credential router");
        (router, manifest.route_index())
    }
    #[test]
    fn explicit_connect_cache_policy_reaches_exact_and_framework_metadata() {
        let (_, index) = connect_cache_policy_test_router();
        let preflight = index.resolve(
            &axum::http::Method::OPTIONS,
            Some(route_catalog::connect::SESSION_CREATE.path()),
        );
        assert_eq!(preflight.stable_route_id(), "http.cors_preflight");
        assert!(preflight.requires_private_no_store());
        let method_not_allowed = index.resolve(
            &axum::http::Method::DELETE,
            Some(route_catalog::connect::SESSION_STATUS.path()),
        );
        assert_eq!(
            method_not_allowed.stable_route_id(),
            "http.method_not_allowed"
        );
        assert!(method_not_allowed.requires_private_no_store());
        let head_method_not_allowed = index.resolve(
            &axum::http::Method::HEAD,
            Some(route_catalog::connect::SESSION_STATUS.path()),
        );
        assert_eq!(
            head_method_not_allowed.stable_route_id(),
            "http.method_not_allowed"
        );
        assert!(head_method_not_allowed.requires_private_no_store());
    }
    #[tokio::test]
    async fn explicit_connect_cache_policy_covers_success_error_and_framework_responses() {
        use http_body_util::BodyExt as _;

        let (router, index) = connect_cache_policy_test_router();
        let router = router
            .method_not_allowed_fallback(|| async {
                let mut response = StatusCode::METHOD_NOT_ALLOWED.into_response();
                response.headers_mut().insert(
                    header::CACHE_CONTROL,
                    HeaderValue::from_static("public, max-age=86400"),
                );
                response
            })
            .layer(axum::middleware::from_fn_with_state(
                index,
                attach_matched_route_metadata,
            ))
            .layer(axum::middleware::from_fn(enforce_catalog_private_no_store))
            .with_state(());
        let success = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::POST)
                    .uri(route_catalog::connect::SESSION_CREATE.path())
                    .body(Body::empty())
                    .expect("Connect session-create request"),
            )
            .await
            .expect("Connect session-create response");
        assert_eq!(success.status(), StatusCode::OK);
        assert_eq!(
            success.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("private, no-store"))
        );
        let body = success
            .into_body()
            .collect()
            .await
            .expect("collect Connect credential response")
            .to_bytes();
        assert_eq!(body.as_ref(), b"role-and-management-tokens");
        let rejection = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(route_catalog::connect::SESSION_STATUS.path())
                    .body(Body::empty())
                    .expect("Connect session-status request"),
            )
            .await
            .expect("Connect session-status rejection");
        assert_eq!(rejection.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            rejection.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("private, no-store"))
        );
        let framework = router
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::DELETE)
                    .uri(route_catalog::connect::SESSION_STATUS.path())
                    .body(Body::empty())
                    .expect("Connect method-not-allowed request"),
            )
            .await
            .expect("Connect method-not-allowed response");
        assert_eq!(framework.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            framework.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("private, no-store"))
        );
    }
    #[tokio::test]
    async fn framework_responses_or_cache_policy_across_methods_at_one_path() {
        let mut builder = RouterBuilder::new(
            (),
            RouteCatalog::new(&[CREDENTIAL_EXCHANGE, PUBLIC_CREDENTIAL_READ]),
            EnabledFeatures::none(),
        )
        .expect("valid mixed-method catalog");
        builder.route(
            &CREDENTIAL_EXCHANGE,
            catalog_post(|| async { StatusCode::NO_CONTENT })
                .authenticated_in_handler(HandlerAuthentication::OperatorCredentialExchange),
        );
        builder.route(
            &PUBLIC_CREDENTIAL_READ,
            catalog_get(|| async { StatusCode::NO_CONTENT }),
        );
        let (router, manifest) = builder.finish().expect("complete mixed-method router");
        let index = manifest.route_index();
        for method in [axum::http::Method::OPTIONS, axum::http::Method::DELETE] {
            let metadata = index.resolve(&method, Some(CREDENTIAL_EXCHANGE.path()));
            assert!(
                metadata.requires_private_no_store(),
                "{method} must inherit the strictest cache policy at the path"
            );
        }
        let head_method_not_allowed = index.resolve(
            &axum::http::Method::HEAD,
            Some(PUBLIC_CREDENTIAL_READ.path()),
        );
        assert_eq!(
            head_method_not_allowed.stable_route_id(),
            "http.method_not_allowed"
        );
        assert!(
            head_method_not_allowed.requires_private_no_store(),
            "HEAD is method-not-allowed and must inherit the path-wide strict cache policy"
        );
        let router = router
            .method_not_allowed_fallback(|| async {
                let mut response = StatusCode::METHOD_NOT_ALLOWED.into_response();
                response.headers_mut().insert(
                    header::CACHE_CONTROL,
                    HeaderValue::from_static("public, max-age=86400"),
                );
                response
            })
            .layer(axum::middleware::from_fn_with_state(
                index,
                attach_matched_route_metadata,
            ))
            .layer(axum::middleware::from_fn(enforce_catalog_private_no_store))
            .with_state(());
        let response = router
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::DELETE)
                    .uri(CREDENTIAL_EXCHANGE.path())
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("private, no-store"))
        );
        let metadata = response
            .extensions()
            .get::<MatchedRouteMetadata>()
            .expect("framework route metadata");
        assert_eq!(metadata.stable_route_id(), "http.method_not_allowed");
        assert!(metadata.requires_private_no_store());
    }
    #[tokio::test]
    async fn catalog_cache_boundary_leaves_public_responses_unchanged() {
        let mut builder =
            RouterBuilder::new((), RouteCatalog::new(&[ITEM]), EnabledFeatures::none())
                .expect("valid public catalog");
        builder.route(
            &ITEM,
            catalog_get(|| async {
                let mut response = StatusCode::OK.into_response();
                response.headers_mut().insert(
                    header::CACHE_CONTROL,
                    HeaderValue::from_static("public, max-age=60"),
                );
                response
            }),
        );
        let (router, manifest) = builder.finish().expect("complete public router");
        let router = router
            .layer(axum::middleware::from_fn_with_state(
                manifest.route_index(),
                attach_matched_route_metadata,
            ))
            .layer(axum::middleware::from_fn(enforce_catalog_private_no_store))
            .with_state(());
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/v1/tests/items/public")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("public, max-age=60"))
        );
        assert!(
            response
                .extensions()
                .get::<MatchedRouteMetadata>()
                .is_some_and(|metadata| !metadata.requires_private_no_store())
        );
    }
    #[test]
    fn uncataloged_resolution_keeps_only_axum_template() {
        let builder = RouterBuilder::new((), RouteCatalog::new(&[ITEM]), EnabledFeatures::none())
            .expect("valid test catalog");
        let errors = builder.finish().expect_err("missing mount must fail");
        assert_eq!(
            errors,
            vec![
                crate::router::builder::RouterAssemblyError::MissingRegistrations(vec![
                    "test.item.read"
                ])
            ]
        );
    }
    #[tokio::test]
    async fn cors_cannot_create_undeclared_options_routes() {
        use http_body_util::BodyExt as _;
        use tower_http::cors::{Any, CorsLayer};
        let mut builder = RouterBuilder::new(
            (),
            RouteCatalog::new(&[ITEM, CORS_ITEM]),
            EnabledFeatures::none(),
        )
        .expect("valid test catalog");
        builder.route(&ITEM, catalog_get(|| async { StatusCode::NO_CONTENT }));
        builder.route(&CORS_ITEM, catalog_get(|| async { StatusCode::NO_CONTENT }));
        let (router, manifest) = builder.finish().expect("complete test router");
        let router = router
            .fallback(|| async { StatusCode::NOT_FOUND })
            .layer(
                CorsLayer::new()
                    .allow_origin(Any)
                    .allow_methods([axum::http::Method::GET]),
            )
            .layer(axum::middleware::from_fn(enforce_cataloged_cors_preflight))
            .layer(axum::middleware::from_fn_with_state(
                manifest.route_index(),
                attach_matched_route_metadata,
            ))
            .with_state(());
        let preflight = |path: &'static str| {
            Request::builder()
                .method(axum::http::Method::OPTIONS)
                .uri(path)
                .header(header::ORIGIN, "https://wallet.example")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
                .header(header::ACCEPT, "application/json")
                .body(Body::empty())
                .expect("preflight")
        };
        let response = router
            .clone()
            .oneshot(preflight("/v1/tests/items/secret"))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("collect response")
            .to_bytes();
        let envelope: ErrorEnvelope =
            norito::json::from_slice(&body).expect("typed error envelope");
        assert_eq!(envelope.code(), "method_not_allowed");
        let response = router
            .clone()
            .oneshot(preflight("/v1/tests/cors-items/secret"))
            .await
            .expect("response");
        assert!(response.status().is_success());
        assert!(
            response
                .headers()
                .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        );
        let response = router
            .oneshot(preflight("/v1/tests/unknown/secret"))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

#[cfg(test)]
mod content_type_utf8_tests {
    use super::{normalize_json_content_type, normalize_json_response_content_type};
    use axum::http::{HeaderMap, HeaderValue, header::CONTENT_TYPE};
    #[test]
    fn normalizes_json_media_type_with_utf8_charset() {
        assert_eq!(
            normalize_json_content_type("application/json"),
            Some("application/json; charset=utf-8".to_string())
        );
    }
    #[test]
    fn keeps_non_charset_parameters_when_normalizing() {
        assert_eq!(
            normalize_json_content_type(
                "application/problem+json; profile=\"urn:problem\"; charset=iso-8859-1"
            ),
            Some("application/problem+json; profile=\"urn:problem\"; charset=utf-8".to_string())
        );
    }
    #[test]
    fn leaves_non_json_content_type_untouched() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=iso-8859-1"),
        );
        normalize_json_response_content_type(&mut headers);
        assert_eq!(
            headers.get(CONTENT_TYPE),
            Some(&HeaderValue::from_static("text/plain; charset=iso-8859-1"))
        );
    }
    #[test]
    fn rewrites_header_in_place_for_json_responses() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=latin1"),
        );
        normalize_json_response_content_type(&mut headers);
        assert_eq!(
            headers.get(CONTENT_TYPE),
            Some(&HeaderValue::from_static("application/json; charset=utf-8"))
        );
    }
}

#[cfg(test)]
mod response_negotiation_middleware_tests {
    use super::*;
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode, header},
        response::Response,
        routing::{get, post},
    };
    #[cfg(not(feature = "app_api"))]
    use http_body_util::BodyExt as _;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    fn native_response(content_type: &'static str) -> Response {
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, content_type)
            .body(Body::from("native"))
            .expect("native response")
    }
    fn typed_norito_response() -> Response {
        utils::respond_with_format(
            ErrorEnvelope::new("example", "typed"),
            ResponseFormat::Norito,
        )
    }
    fn native_request(
        path: &str,
        accept: &str,
        route: iroha_torii_shared::route_catalog::RouteDescriptor,
    ) -> Request<Body> {
        let mut request = Request::builder()
            .uri(path)
            .header(header::ACCEPT, accept)
            .body(Body::empty())
            .expect("request");
        request
            .extensions_mut()
            .insert(MatchedRouteMetadata::from_descriptor(route));
        request
    }
    #[tokio::test]
    async fn safe_protocol_native_media_bypasses_typed_negotiation() {
        let router = Router::new()
            .route(
                "/events",
                get(|| async { native_response("text/event-stream") }),
            )
            .route(
                "/metrics",
                get(|| async { native_response("text/plain; version=0.0.4") }),
            )
            .route(
                "/blob",
                get(|| async { native_response("application/octet-stream") }),
            )
            .layer(axum::middleware::from_fn(capture_response_format));
        for (path, accept, expected_content_type, route) in [
            (
                "/events",
                "text/event-stream",
                "text/event-stream",
                route_catalog::streaming::EVENTS_SSE,
            ),
            (
                "/events",
                "text/*",
                "text/event-stream",
                route_catalog::streaming::EVENTS_SSE,
            ),
            (
                "/events",
                "application/json;q=0.2, text/event-stream;q=0.8",
                "text/event-stream",
                route_catalog::streaming::EVENTS_SSE,
            ),
            (
                "/metrics",
                "text/plain",
                "text/plain; version=0.0.4",
                route_catalog::diagnostic::METRICS,
            ),
            (
                "/metrics",
                "*/*",
                "text/plain; version=0.0.4",
                route_catalog::diagnostic::METRICS,
            ),
            (
                "/blob",
                "application/octet-stream",
                "application/octet-stream",
                route_catalog::content_directory::CONTENT,
            ),
        ] {
            let response = router
                .clone()
                .oneshot(native_request(path, accept, route))
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::OK, "path={path}");
            assert_eq!(
                response
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
                Some(expected_content_type),
                "path={path}"
            );
            assert!(
                response.headers().get(header::VARY).is_some(),
                "native Accept validation must advertise Vary: path={path}"
            );
        }
    }
    #[tokio::test]
    async fn safe_protocol_native_media_rejects_an_explicit_mismatch() {
        let router = Router::new()
            .route(
                "/events",
                get(|| async { native_response("text/event-stream") }),
            )
            .layer(axum::middleware::from_fn(capture_response_format));
        for accept in [
            "application/json",
            "text/event-stream;q=0, */*;q=1",
            "image/*",
            "text/event-stream;q=bogus",
            "text/event-stream;q=0.000",
            "text/event-stream;q=1;q=1",
        ] {
            let response = router
                .clone()
                .oneshot(native_request(
                    "/events",
                    accept,
                    route_catalog::streaming::EVENTS_SSE,
                ))
                .await
                .expect("response");
            assert_eq!(
                response.status(),
                StatusCode::NOT_ACCEPTABLE,
                "accept={accept}"
            );
            assert!(response.headers().get(header::VARY).is_some());
        }
    }
    #[tokio::test]
    async fn safe_typed_response_still_rejects_unacceptable_media() {
        let router = Router::new()
            .route("/typed", get(|| async { typed_norito_response() }))
            .layer(axum::middleware::from_fn(capture_response_format));
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/typed")
                    .header(header::ACCEPT, "text/event-stream")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);
        assert!(response.headers().get(header::VARY).is_some());
    }
    #[tokio::test]
    async fn public_conditional_get_rejects_unacceptable_media_before_a_304_handler() {
        let calls = Arc::new(AtomicUsize::new(0));
        let handler_calls = Arc::clone(&calls);
        let router = Router::new()
            .route(
                "/v1/api/version",
                get(move || {
                    let calls = Arc::clone(&handler_calls);
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        StatusCode::NOT_MODIFIED
                    }
                }),
            )
            .layer(axum::middleware::from_fn(capture_response_format));
        let mut request = Request::builder()
            .uri("/v1/api/version")
            .header(header::ACCEPT, "image/png")
            .header(header::IF_NONE_MATCH, "\"stale-validator\"")
            .body(Body::empty())
            .expect("request");
        request
            .extensions_mut()
            .insert(MatchedRouteMetadata::from_descriptor(
                route_catalog::core::API_VERSION,
            ));
        let response = router.oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(response.headers().get(header::VARY).is_some());
    }
    #[tokio::test]
    async fn protocol_stream_establishment_errors_remain_typed_json() {
        let router = Router::new()
            .route(
                "/events",
                get(|| async {
                    utils::respond_with_status_and_format(
                        StatusCode::UNAUTHORIZED,
                        ErrorEnvelope::new("unauthorized", "authentication failed"),
                        utils::current_response_format(),
                    )
                }),
            )
            .layer(axum::middleware::from_fn(capture_response_format));
        for accept in [
            "text/event-stream",
            "text/plain",
            "application/octet-stream",
        ] {
            let response = router
                .clone()
                .oneshot(native_request(
                    "/events",
                    accept,
                    route_catalog::streaming::EVENTS_SSE,
                ))
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{accept}");
            let content_type = response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .expect("typed establishment error declares Content-Type");
            assert_eq!(
                utils::typed_response_format_for_content_type(content_type),
                Some(ResponseFormat::Json),
                "{accept}"
            );
            assert_eq!(
                response
                    .headers()
                    .get(header::VARY)
                    .and_then(|value| value.to_str().ok()),
                Some("Accept"),
                "{accept}"
            );
            let body = response
                .into_body()
                .collect()
                .await
                .expect("collect establishment error")
                .to_bytes();
            let envelope: ErrorEnvelope =
                norito::json::from_slice(&body).expect("typed JSON error envelope");
            assert_eq!(envelope.code(), "unauthorized", "{accept}");
        }
    }
    #[tokio::test]
    async fn unsafe_command_is_rejected_before_handler_side_effects() {
        let calls = Arc::new(AtomicUsize::new(0));
        let handler_calls = Arc::clone(&calls);
        let router = Router::new()
            .route(
                "/command",
                post(move || {
                    let calls = Arc::clone(&handler_calls);
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        typed_norito_response()
                    }
                }),
            )
            .layer(axum::middleware::from_fn(capture_response_format));
        let response = router
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::POST)
                    .uri("/command")
                    .header(header::ACCEPT, "image/png")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn repeated_accept_fields_are_combined_before_negotiation() {
        let router = Router::new()
            .route(
                "/command",
                post(|| async {
                    utils::respond_with_format(
                        ErrorEnvelope::new("example", "typed"),
                        utils::current_response_format(),
                    )
                }),
            )
            .layer(axum::middleware::from_fn(capture_response_format))
            .layer(axum::middleware::from_fn(coalesce_accept_headers));
        let mut request = Request::builder()
            .method(axum::http::Method::POST)
            .uri("/command")
            .body(Body::empty())
            .expect("request");
        request.headers_mut().append(
            header::ACCEPT,
            HeaderValue::from_static("application/json;q=0.4"),
        );
        request.headers_mut().append(
            header::ACCEPT,
            HeaderValue::from_static("application/x-norito;q=0.9"),
        );
        let response = router.oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/x-norito")
        );
    }
    #[tokio::test]
    async fn non_ascii_repeated_accept_field_fails_closed() {
        let router = Router::new()
            .route("/command", post(|| async { StatusCode::NO_CONTENT }))
            .layer(axum::middleware::from_fn(coalesce_accept_headers));
        let mut request = Request::builder()
            .method(axum::http::Method::POST)
            .uri("/command")
            .body(Body::empty())
            .expect("request");
        request
            .headers_mut()
            .append(header::ACCEPT, HeaderValue::from_static("application/json"));
        request.headers_mut().append(
            header::ACCEPT,
            HeaderValue::from_bytes(&[0xff]).expect("opaque header value"),
        );
        let response = router.oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
        assert!(response.headers().get(header::VARY).is_some());
    }
    #[tokio::test]
    async fn duplicate_content_type_is_rejected_before_command_handler() {
        let calls = Arc::new(AtomicUsize::new(0));
        let handler_calls = Arc::clone(&calls);
        let router = Router::new()
            .route(
                "/command",
                post(move || {
                    let calls = Arc::clone(&handler_calls);
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        StatusCode::NO_CONTENT
                    }
                }),
            )
            .layer(axum::middleware::from_fn(coalesce_accept_headers));
        let mut request = Request::builder()
            .method(axum::http::Method::POST)
            .uri("/command")
            .header(header::ACCEPT, "application/x-norito")
            .body(Body::from("{}"))
            .expect("request");
        request.headers_mut().append(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        request.headers_mut().append(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-norito"),
        );
        let response = router.oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/x-norito")
        );
        let body = response
            .into_body()
            .collect()
            .await
            .expect("collect duplicate Content-Type response")
            .to_bytes();
        let envelope: ErrorEnvelope = norito::decode_from_bytes(&body).expect("decode typed error");
        assert_eq!(envelope.code(), "request_content_type_invalid");
    }
    #[tokio::test]
    async fn handler_panic_becomes_typed_internal_error() {
        let router = Router::new()
            .route(
                "/panic",
                get(|| async {
                    assert!(
                        iroha_panic_hook::is_suppressed(),
                        "caught request panics must not trigger process shutdown"
                    );
                    panic!("adversarial test panic");
                    #[allow(unreachable_code)]
                    StatusCode::OK
                }),
            )
            .layer(axum::middleware::from_fn(catch_handler_panics))
            .layer(axum::middleware::from_fn(capture_response_format));
        for (accept, expected_content_type) in [
            ("application/json", "application/json"),
            ("application/x-norito", "application/x-norito"),
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/panic")
                        .header(header::ACCEPT, accept)
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(
                response
                    .headers()
                    .get(header::CACHE_CONTROL)
                    .and_then(|value| value.to_str().ok()),
                Some("private, no-store")
            );
            assert_eq!(
                response
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
                Some(expected_content_type)
            );
            let body = response
                .into_body()
                .collect()
                .await
                .expect("collect panic response")
                .to_bytes();
            let envelope: ErrorEnvelope = if accept == "application/json" {
                norito::json::from_slice(&body).expect("decode JSON panic envelope")
            } else {
                norito::decode_from_bytes(&body).expect("decode Norito panic envelope")
            };
            assert_eq!(envelope.code(), "internal_server_error");
            assert!(!envelope.message().contains("adversarial test panic"));
            assert!(
                !iroha_panic_hook::is_suppressed(),
                "request-local suppression must not leak after recovery"
            );
        }
    }
    #[test]
    fn route_timeout_error_is_private_and_not_cacheable() {
        let response = route_timeout_error_response(ResponseFormat::Json);
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("private, no-store")
        );
    }
}

#[cfg(test)]
mod typed_error_contract_tests {
    use super::*;
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode, header},
        response::Response,
        routing::get,
    };
    #[cfg(not(feature = "app_api"))]
    use http_body_util::BodyExt as _;
    fn with_error_contract(router: Router) -> Router {
        router.layer(axum::middleware::from_fn(enforce_typed_error_contract))
    }
    fn with_error_contract_timeout(router: Router, timeout: Duration) -> Router {
        router.layer(axum::middleware::from_fn(
            move |request: Request<Body>, next: Next| {
                enforce_typed_error_contract_with_body_timeout(request, next, timeout)
            },
        ))
    }
    async fn body_bytes(response: AxResponse) -> Bytes {
        response
            .into_body()
            .collect()
            .await
            .expect("collect response body")
            .to_bytes()
    }
    #[tokio::test]
    async fn query_asset_absence_response_preserves_exact_selector_in_both_formats() {
        use iroha_data_model::{
            ValidationFail,
            asset::AssetId,
            query::error::{FindError, QueryExecutionFail},
        };
        let asset = AssetId::new(
            AssetDefinitionId::derive_from_components(
                iroha_model_base::domain::DomainId::try_new("missing", "universal").unwrap(),
                "asset".parse().unwrap(),
            ),
            iroha_test_samples::ALICE_ID.clone(),
        );
        for format in [ResponseFormat::Norito, ResponseFormat::Json] {
            let failure = ValidationFail::QueryFailed(QueryExecutionFail::Find(FindError::Asset(
                Box::new(asset.clone()),
            )));
            let expected_message = validation_fail_message(&failure);
            let response = utils::with_current_response_format(format, async {
                Error::Query(failure).into_response()
            })
            .await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            let body = body_bytes(response).await;
            let decoded = match format {
                ResponseFormat::Norito => norito::decode_canonical_with_limits::<ErrorEnvelope>(
                    &body,
                    norito::canonical_decode_limits(body.len()),
                )
                .expect("canonical asset absence response"),
                ResponseFormat::Json => norito::json::from_slice::<ErrorEnvelope>(&body)
                    .expect("typed asset absence JSON"),
            };
            assert_eq!(decoded.code(), "query_asset_not_found");
            assert_eq!(decoded.message(), expected_message);
            assert_eq!(
                decoded.details.unwrap().query_asset_not_found,
                Some(asset.clone())
            );
        }
    }
    #[tokio::test]
    async fn query_asset_absence_is_not_inferred_from_other_validation_failures() {
        use iroha_data_model::{
            ValidationFail,
            asset::AssetId,
            isi::error::InstructionExecutionError,
            query::error::{FindError, QueryExecutionFail},
        };
        let definition = AssetDefinitionId::derive_from_components(
            iroha_model_base::domain::DomainId::try_new("missing", "universal").unwrap(),
            "asset".parse().unwrap(),
        );
        let asset = AssetId::new(definition.clone(), iroha_test_samples::ALICE_ID.clone());
        let asset_failure = QueryExecutionFail::Find(FindError::Asset(Box::new(asset)));
        for failure in [
            ValidationFail::QueryFailed(QueryExecutionFail::NotFound),
            ValidationFail::QueryFailed(QueryExecutionFail::Expired),
            ValidationFail::QueryFailed(QueryExecutionFail::Find(FindError::Account(
                iroha_test_samples::ALICE_ID.clone(),
            ))),
            ValidationFail::QueryFailed(QueryExecutionFail::Find(FindError::AssetDefinition(
                definition,
            ))),
            ValidationFail::InstructionFailed(InstructionExecutionError::Query(
                asset_failure.clone(),
            )),
            ValidationFail::NotPermitted("query denied".to_owned()),
        ] {
            let expected_status = Error::query_status_code(&failure);
            let response = Error::Query(failure).into_response();
            assert_eq!(response.status(), expected_status);
            let body = body_bytes(response).await;
            let envelope: ErrorEnvelope = norito::decode_from_bytes(&body).unwrap();
            assert_eq!(envelope.code(), "query_validation_failed");
            assert!(
                envelope
                    .details
                    .as_ref()
                    .is_none_or(|details| details.query_asset_not_found.is_none())
            );
        }
        let wrong_status = public_validation_fail_envelope(
            &ValidationFail::QueryFailed(asset_failure),
            StatusCode::BAD_REQUEST,
        );
        assert_eq!(wrong_status.code(), "query_validation_failed");
        assert!(wrong_status.details.is_none());
    }
    #[tokio::test]
    async fn signed_query_shape_refusal_reaches_clients_verbatim() {
        use iroha_core::smartcontracts::isi::query::{
            SIGNED_QUERY_SHAPE_NOT_ADMITTED, TORII_COLLECTION_ENDPOINTS,
            signed_query_shape_not_admitted,
        };
        use iroha_data_model::ValidationFail;
        let refusal =
            signed_query_shape_not_admitted("FindDomains", "has no bounded signed-query source");
        let iroha_data_model::query::error::QueryExecutionFail::Conversion(expected_message) =
            refusal.clone()
        else {
            panic!("signed-query shape refusals are conversion failures");
        };
        assert!(expected_message.starts_with(&format!(
            "{SIGNED_QUERY_SHAPE_NOT_ADMITTED}: FindDomains has no bounded signed-query source. "
        )));
        for format in [ResponseFormat::Norito, ResponseFormat::Json] {
            let failure = ValidationFail::QueryFailed(refusal.clone());
            let response = utils::with_current_response_format(format, async {
                Error::Query(failure).into_response()
            })
            .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let body = body_bytes(response).await;
            let decoded = match format {
                ResponseFormat::Norito => norito::decode_canonical_with_limits::<ErrorEnvelope>(
                    &body,
                    norito::canonical_decode_limits(body.len()),
                )
                .expect("canonical refusal response"),
                ResponseFormat::Json => {
                    norito::json::from_slice::<ErrorEnvelope>(&body).expect("typed refusal JSON")
                }
            };
            assert_eq!(decoded.code(), "query_validation_failed");
            assert_eq!(decoded.message(), expected_message);
            for endpoint in TORII_COLLECTION_ENDPOINTS {
                assert!(decoded.message().contains(endpoint), "{endpoint}");
            }
        }
    }
    #[tokio::test]
    async fn canonical_error_response_keeps_asset_selector_only_for_exact_contract() {
        let asset = iroha_data_model::asset::AssetId::new(
            AssetDefinitionId::derive_from_components(
                iroha_model_base::domain::DomainId::try_new("missing", "universal").unwrap(),
                "asset".parse().unwrap(),
            ),
            iroha_test_samples::ALICE_ID.clone(),
        );
        for (status, code, preserved) in [
            (StatusCode::NOT_FOUND, "query_asset_not_found", true),
            (StatusCode::GONE, "query_asset_not_found", false),
            (StatusCode::NOT_FOUND, "query_validation_failed", false),
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "query_asset_not_found",
                false,
            ),
        ] {
            let (parts, _) = Response::builder()
                .status(status)
                .body(Body::empty())
                .unwrap()
                .into_parts();
            let response = canonical_error_response(
                parts,
                ErrorEnvelope::new(code, "asset lookup failed").with_details(ErrorDetails {
                    query_asset_not_found: Some(asset.clone()),
                    ..Default::default()
                }),
                ResponseFormat::Norito,
                false,
            );
            let envelope: ErrorEnvelope =
                norito::decode_from_bytes(&body_bytes(response).await).unwrap();
            assert_eq!(
                envelope
                    .details
                    .and_then(|details| details.query_asset_not_found),
                preserved.then(|| asset.clone())
            );
        }
    }
    #[tokio::test]
    async fn error_body_read_deadline_fails_closed_without_blocking_other_errors() {
        let router = with_error_contract_timeout(
            Router::new()
                .route(
                    "/pending",
                    get(|| async {
                        let frames = futures::stream::pending::<
                            Result<hyper::body::Frame<Bytes>, Infallible>,
                        >();
                        Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .header(header::CONTENT_TYPE, "application/json")
                            .body(Body::new(http_body_util::StreamBody::new(frames)))
                            .expect("pending error response")
                    }),
                )
                .route(
                    "/ordinary",
                    get(|| async {
                        Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .header(header::CONTENT_TYPE, "application/json")
                            .body(Body::from(
                                r#"{"code":"invalid_request","message":"ordinary failure"}"#,
                            ))
                            .expect("ordinary error response")
                    }),
                ),
            Duration::from_millis(10),
        );

        let pending = tokio::time::timeout(
            Duration::from_secs(1),
            router.clone().oneshot(
                Request::builder()
                    .uri("/pending")
                    .header(header::ACCEPT, "application/json")
                    .body(Body::empty())
                    .expect("request"),
            ),
        )
        .await
        .expect("error boundary must not hang on a pending body")
        .expect("pending response");
        assert_eq!(pending.status(), StatusCode::BAD_REQUEST);
        let envelope: ErrorEnvelope =
            norito::json::from_slice(&body_bytes(pending).await).expect("decode fail-closed error");
        assert_eq!(envelope.code(), "bad_request");

        let ordinary = router
            .oneshot(
                Request::builder()
                    .uri("/ordinary")
                    .header(header::ACCEPT, "application/json")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("ordinary response");
        let envelope: ErrorEnvelope =
            norito::json::from_slice(&body_bytes(ordinary).await).expect("decode ordinary error");
        assert_eq!(envelope.code(), "invalid_request");
        assert_eq!(envelope.message(), "ordinary failure");
    }
    #[tokio::test]
    async fn bare_error_defaults_to_json_envelope() {
        let router = with_error_contract(
            Router::new().route("/bare", get(|| async { StatusCode::NOT_FOUND })),
        );
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/bare")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        assert!(
            content_type.starts_with("application/json"),
            "requests without Accept get JSON errors: {content_type}"
        );
        assert_eq!(
            response
                .extensions()
                .get::<utils::HttpErrorCode>()
                .map(utils::HttpErrorCode::as_str),
            Some("not_found")
        );
        assert!(
            !response.headers().contains_key("x-iroha-reject-code"),
            "a bare router-style 404 must not masquerade as an application resource miss"
        );
        let envelope: norito::json::Value =
            norito::json::from_slice(&body_bytes(response).await).expect("decode JSON error");
        assert_eq!(envelope["code"].as_str(), Some("not_found"));
    }
    #[tokio::test]
    async fn app_error_reject_codes_survive_json_and_norito_negotiation() {
        let router = Router::new()
            .route(
                "/invalid-operation",
                get(|| async {
                    Error::AppQueryValidation {
                        code: "operation_id_invalid",
                        message: "Operation id must be non-zero.".to_owned(),
                    }
                    .into_response()
                }),
            )
            .route(
                "/forbidden-auth-header",
                get(|| async {
                    Error::AppForbidden {
                        code: "auth_header_unsupported",
                        message: "This route authenticates through its signed request body; X-Iroha canonical auth headers are not accepted.".to_owned(),
                    }
                    .into_response()
                }),
            )
            .route(
                "/conflicting-operation",
                get(|| async {
                    Error::AppConflict {
                        code: "operation_id_conflict",
                        message: "Operation id is already bound to a different request."
                            .to_owned(),
                    }
                    .into_response()
                }),
            )
            .route(
                "/missing-operation",
                get(|| async {
                    Error::AppNotFound {
                        code: "operation_not_found",
                        message: "Operation is unknown on this Torii node.".to_owned(),
                    }
                    .into_response()
                }),
            )
            .route(
                "/missing-asset",
                get(|| async {
                    Error::AppNotFound {
                        code: "asset_definition_not_found",
                        message: "Asset definition does not exist.".to_owned(),
                    }
                    .into_response()
                }),
            )
            .route(
                "/proxy-missing",
                get(|| async {
                    torii_proxy_error_response(
                        StatusCode::NOT_FOUND,
                        "not_found",
                        "No authoritative dataspace returned the resource.",
                    )
                }),
            )
            .fallback(handler_route_not_found)
            .layer(axum::middleware::from_fn(capture_response_format))
            .layer(axum::middleware::from_fn(enforce_typed_error_contract));
        for (accept, expected_content_type) in [
            ("application/json", "application/json; charset=utf-8"),
            (utils::NORITO_MIME_TYPE, utils::NORITO_MIME_TYPE),
        ] {
            for (path, expected_status, expected_code, expected_message) in [
                (
                    "/invalid-operation",
                    StatusCode::BAD_REQUEST,
                    "operation_id_invalid",
                    "Operation id must be non-zero.",
                ),
                (
                    "/forbidden-auth-header",
                    StatusCode::FORBIDDEN,
                    "auth_header_unsupported",
                    "This route authenticates through its signed request body; X-Iroha canonical auth headers are not accepted.",
                ),
                (
                    "/conflicting-operation",
                    StatusCode::CONFLICT,
                    "operation_id_conflict",
                    "Operation id is already bound to a different request.",
                ),
                (
                    "/missing-operation",
                    StatusCode::NOT_FOUND,
                    "operation_not_found",
                    "Operation is unknown on this Torii node.",
                ),
                (
                    "/missing-asset",
                    StatusCode::NOT_FOUND,
                    "asset_definition_not_found",
                    "Asset definition does not exist.",
                ),
                (
                    "/proxy-missing",
                    StatusCode::NOT_FOUND,
                    "not_found",
                    "No authoritative dataspace returned the resource.",
                ),
            ] {
                let response = router
                    .clone()
                    .oneshot(
                        Request::builder()
                            .uri(path)
                            .header(header::ACCEPT, accept)
                            .body(Body::empty())
                            .expect("request"),
                    )
                    .await
                    .expect("response");
                assert_eq!(response.status(), expected_status, "path={path}");
                assert_eq!(
                    response
                        .headers()
                        .get(header::CONTENT_TYPE)
                        .and_then(|value| value.to_str().ok()),
                    Some(expected_content_type),
                    "path={path}; accept={accept}"
                );
                assert_eq!(
                    response
                        .headers()
                        .get("x-iroha-reject-code")
                        .and_then(|value| value.to_str().ok()),
                    Some(expected_code),
                    "the header must carry the app error's exact code; path={path}; accept={accept}"
                );
                let body = body_bytes(response).await;
                let envelope: ErrorEnvelope = if accept == "application/json" {
                    norito::json::from_slice(&body).expect("decode negotiated JSON error")
                } else {
                    norito::decode_from_bytes(&body).expect("decode negotiated Norito error")
                };
                assert_eq!(envelope.code(), expected_code, "path={path}");
                assert_eq!(envelope.message(), expected_message, "path={path}");
            }
            let retired_product = ["line", "off"].into_iter().rev().collect::<String>();
            let retired_path = format!("/v1/{retired_product}/operations/deadbeef");
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(retired_path)
                        .header(header::ACCEPT, accept)
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert!(
                !response.headers().contains_key("x-iroha-reject-code"),
                "an unmatched route must not claim operation_not_found; accept={accept}"
            );
            let body = body_bytes(response).await;
            let envelope: ErrorEnvelope = if accept == "application/json" {
                norito::json::from_slice(&body).expect("decode route JSON error")
            } else {
                norito::decode_from_bytes(&body).expect("decode route Norito error")
            };
            assert_eq!(envelope.code(), "route_not_found");
        }
    }
    #[tokio::test]
    async fn declared_error_format_is_decoded_then_reencoded_to_negotiated_accept() {
        let router = Router::new()
            .route(
                "/declared-json",
                get(|| async {
                    utils::respond_with_status_and_format(
                        StatusCode::CONFLICT,
                        ErrorEnvelope::new("declared_json_error", "JSON source envelope"),
                        ResponseFormat::Json,
                    )
                }),
            )
            .route(
                "/declared-norito",
                get(|| async {
                    utils::respond_with_status_and_format(
                        StatusCode::BAD_REQUEST,
                        ErrorEnvelope::new("declared_norito_error", "Norito source envelope"),
                        ResponseFormat::Norito,
                    )
                }),
            )
            .layer(axum::middleware::from_fn(capture_response_format))
            .layer(axum::middleware::from_fn(enforce_typed_error_contract));
        for (path, accept, expected_status, expected_content_type, expected_code) in [
            (
                "/declared-json",
                "application/x-norito",
                StatusCode::CONFLICT,
                utils::NORITO_MIME_TYPE,
                "declared_json_error",
            ),
            (
                "/declared-norito",
                "application/json",
                StatusCode::BAD_REQUEST,
                "application/json; charset=utf-8",
                "declared_norito_error",
            ),
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header(header::ACCEPT, accept)
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(response.status(), expected_status, "path={path}");
            assert_eq!(
                response
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
                Some(expected_content_type),
                "path={path}"
            );
            assert_eq!(
                response
                    .headers()
                    .get(header::VARY)
                    .and_then(|value| value.to_str().ok()),
                Some("Accept"),
                "path={path}"
            );
            let body = body_bytes(response).await;
            let envelope: ErrorEnvelope = if accept == "application/json" {
                norito::json::from_slice(&body).expect("decode negotiated JSON error")
            } else {
                norito::decode_from_bytes(&body).expect("decode negotiated Norito error")
            };
            assert_eq!(envelope.code(), expected_code, "path={path}");
        }
    }
    #[tokio::test]
    async fn failed_negotiation_uses_deterministic_json_after_declared_norito_decode() {
        let router = Router::new()
            .route(
                "/error",
                get(|| async {
                    utils::respond_with_status_and_format(
                        StatusCode::BAD_REQUEST,
                        ErrorEnvelope::new(
                            "declared_norito_error",
                            "preserved across negotiation failure",
                        ),
                        ResponseFormat::Norito,
                    )
                }),
            )
            // Exercise the response boundary itself: request negotiation rejects
            // unacceptable public requests before this handler can execute.
            .layer(axum::middleware::from_fn(enforce_typed_error_contract));
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/error")
                    .header(header::ACCEPT, "image/png")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/json; charset=utf-8")
        );
        let envelope: ErrorEnvelope = norito::json::from_slice(&body_bytes(response).await)
            .expect("decode deterministic JSON fallback");
        assert_eq!(envelope.code(), "declared_norito_error");
        assert_eq!(envelope.message(), "preserved across negotiation failure");
    }
    #[tokio::test]
    async fn ad_hoc_json_error_is_replaced_without_leaking_original_body() {
        let router = with_error_contract(Router::new().route(
            "/dynamic",
            get(|| async {
                Response::builder()
                    .status(StatusCode::CONFLICT)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"error":"internal secret"}"#))
                    .expect("dynamic response")
            }),
        ));
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/dynamic")
                    .header(header::ACCEPT, "application/json")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = body_bytes(response).await;
        assert!(!String::from_utf8_lossy(&body).contains("internal secret"));
        let envelope: ErrorEnvelope =
            norito::json::from_slice(&body).expect("decode canonical JSON error");
        assert_eq!(envelope.code(), "conflict");
    }
    #[tokio::test]
    async fn syntactically_valid_internal_errors_are_redacted_for_every_representation() {
        const MARKER: &str = "private_internal_marker_7f40";
        let router = Router::new()
            .route(
                "/json-internal",
                get(|| async {
                    let mut response = utils::respond_with_status_and_format(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        ErrorEnvelope::new("private_internal_marker", MARKER).with_details(
                            ErrorDetails {
                                hint: Some(MARKER.to_owned()),
                                ..Default::default()
                            },
                        ),
                        ResponseFormat::Json,
                    );
                    response.headers_mut().insert(
                        HeaderName::from_static("x-iroha-reject-code"),
                        HeaderValue::from_static("PRIVATE:MARKER"),
                    );
                    response
                }),
            )
            .route(
                "/norito-internal",
                get(|| async {
                    utils::respond_with_status_and_format(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        ErrorEnvelope::new("private_internal_marker", MARKER),
                        ResponseFormat::Norito,
                    )
                }),
            )
            .layer(axum::middleware::from_fn(enforce_typed_error_contract));
        for (path, accept) in [
            ("/json-internal", "application/json"),
            ("/norito-internal", utils::NORITO_MIME_TYPE),
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header(header::ACCEPT, accept)
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            assert!(!response.headers().contains_key("x-iroha-reject-code"));
            let body = body_bytes(response).await;
            assert!(!String::from_utf8_lossy(&body).contains(MARKER));
            let envelope: ErrorEnvelope = if accept == "application/json" {
                norito::json::from_slice(&body).expect("decode JSON internal error")
            } else {
                norito::decode_from_bytes(&body).expect("decode Norito internal error")
            };
            assert_eq!(envelope.code(), "internal_server_error");
            assert_eq!(envelope.message(), "Torii could not complete the request.");
            assert!(envelope.details.is_none());
        }
    }
    #[tokio::test]
    async fn unknown_error_members_are_discarded_at_the_response_boundary() {
        let router = with_error_contract(Router::new().route(
            "/unknown-members",
            get(|| async {
                Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"code":"bad_request","message":"invalid","secret":"top-level","details":{"secret":"nested"}}"#,
                    ))
                    .expect("dynamic response")
            }),
        ));
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/unknown-members")
                    .header(header::ACCEPT, "application/json")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let body = body_bytes(response).await;
        assert!(!String::from_utf8_lossy(&body).contains("secret"));
        let envelope: ErrorEnvelope =
            norito::json::from_slice(&body).expect("decode canonical JSON error");
        assert_eq!(envelope.code(), "bad_request");
        assert!(envelope.details.is_none());
    }
    #[tokio::test]
    async fn invalid_public_error_code_moves_to_typed_reject_details() {
        let router = with_error_contract(Router::new().route(
            "/invalid-code",
            get(|| async {
                utils::respond_with_status_and_format(
                    StatusCode::BAD_REQUEST,
                    ErrorEnvelope::new("PRTRY:BAD", "rejected"),
                    ResponseFormat::Json,
                )
            }),
        ));
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/invalid-code")
                    .header(header::ACCEPT, "application/json")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let envelope: ErrorEnvelope = norito::json::from_slice(&body_bytes(response).await)
            .expect("decode canonical JSON error");
        assert_eq!(envelope.code(), "bad_request");
        assert_eq!(
            envelope.details.and_then(|details| details.reject_code),
            Some("PRTRY:BAD".to_owned())
        );
    }
    #[test]
    fn fee_error_detail_sanitizer_enforces_public_codes_and_canonical_values() {
        let mut details = FeeErrorDetails {
            code: FeeRejectionCode::VaultInsufficient.as_str().to_owned(),
            retryable: true,
            program_id: Some("not-a-program".to_owned()),
            program_revision: Some(0),
            asset_definition_id: Some("not-an-asset".to_owned()),
            required: Some("01".to_owned()),
            available: Some("4".to_owned()),
            rule_id: Some("not a name".to_owned()),
            observation_height: Some(42),
            remediation: Some("fund the program vault".to_owned()),
        };
        assert!(sanitize_fee_error_details(&mut details));
        assert!(details.program_id.is_none());
        assert!(details.program_revision.is_none());
        assert!(details.asset_definition_id.is_none());
        assert!(details.required.is_none());
        assert_eq!(details.available.as_deref(), Some("4"));
        assert!(details.rule_id.is_none());
        assert_eq!(details.observation_height, Some(42));
        details.code = "private/reason".to_owned();
        assert!(!sanitize_fee_error_details(&mut details));
    }
    #[tokio::test]
    async fn error_boundary_discards_unbounded_or_unsafe_detail_text() {
        let oversized = "x".repeat(utils::MAX_ERROR_DETAIL_CHARACTERS + 1);
        let unsafe_code = format!("private\n{oversized}");
        let router = with_error_contract(Router::new().route(
            "/unsafe-details",
            get(move || {
                let unsafe_code = unsafe_code.clone();
                let oversized = oversized.clone();
                async move {
                    utils::respond_with_status_and_format(
                        StatusCode::BAD_REQUEST,
                        ErrorEnvelope::new(
                            unsafe_code,
                            "m".repeat(utils::MAX_ERROR_MESSAGE_CHARACTERS + 1),
                        )
                        .with_details(ErrorDetails {
                            layer: Some("private\nlayer".to_owned()),
                            reject_code: Some("secret/code".to_owned()),
                            queue: Some(QueueErrorSnapshot {
                                state: "secret-state".to_owned(),
                                queued: 1,
                                capacity: 1,
                                saturated: true,
                            }),
                            endpoint: Some("/v1/private?token=secret".to_owned()),
                            field: Some(oversized),
                            expected: Some("secret\0expected".to_owned()),
                            actual: Some(" secret".to_owned()),
                            profile: Some("secret\nprofile".to_owned()),
                            entrypoint_hash: Some("secret\u{85}entrypoint".to_owned()),
                            tx_hash: Some("secret\u{85}hash".to_owned()),
                            last_status: Some("secret\rstatus".to_owned()),
                            hint: Some("secret\thint".to_owned()),
                            axt: Some(AxtErrorDetails {
                                code: Some("secret/code".to_owned()),
                                reason: Some("secret\nreason".to_owned()),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                        ResponseFormat::Json,
                    )
                }
            }),
        ));
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/unsafe-details")
                    .header(header::ACCEPT, "application/json")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let body = body_bytes(response).await;
        assert!(!String::from_utf8_lossy(&body).contains("secret"));
        let envelope: ErrorEnvelope =
            norito::json::from_slice(&body).expect("decode canonical JSON error");
        assert_eq!(envelope.code(), "bad_request");
        assert_eq!(envelope.message(), "The request is invalid.");
        assert!(envelope.details.is_none());
    }
    #[tokio::test]
    async fn invalid_public_error_messages_are_replaced_for_json_and_norito() {
        let router = Router::new()
            .route(
                "/empty-json-message",
                get(|| async {
                    utils::respond_with_status_and_format(
                        StatusCode::BAD_REQUEST,
                        ErrorEnvelope::new("invalid_request", ""),
                        ResponseFormat::Json,
                    )
                }),
            )
            .route(
                "/control-norito-message",
                get(|| async {
                    utils::respond_with_status_and_format(
                        StatusCode::BAD_REQUEST,
                        ErrorEnvelope::new("invalid_request", "line\nbreak"),
                        ResponseFormat::Norito,
                    )
                }),
            )
            .layer(axum::middleware::from_fn(enforce_typed_error_contract));
        for (path, accept) in [
            ("/empty-json-message", "application/json"),
            ("/control-norito-message", utils::NORITO_MIME_TYPE),
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header(header::ACCEPT, accept)
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            let body = body_bytes(response).await;
            let envelope: ErrorEnvelope = if accept == "application/json" {
                norito::json::from_slice(&body).expect("decode JSON error")
            } else {
                norito::decode_from_bytes(&body).expect("decode Norito error")
            };
            assert_eq!(envelope.code(), "invalid_request");
            assert_eq!(envelope.message(), "The request is invalid.");
            assert!(utils::is_valid_error_message(envelope.message()));
        }
    }
    #[tokio::test]
    async fn retryable_errors_receive_matching_header_and_details() {
        for status in [
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::SERVICE_UNAVAILABLE,
        ] {
            let router = with_error_contract(Router::new().route(
                "/retry",
                get(move || async move {
                    utils::respond_with_status_and_format(
                        status,
                        ErrorEnvelope::new("capacity_exhausted", "retry later"),
                        ResponseFormat::Json,
                    )
                }),
            ));
            let response = router
                .oneshot(
                    Request::builder()
                        .uri("/retry")
                        .header(header::ACCEPT, "application/json")
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(
                response.headers().get(header::RETRY_AFTER),
                Some(&HeaderValue::from_static("1"))
            );
            let envelope: ErrorEnvelope = norito::json::from_slice(&body_bytes(response).await)
                .expect("decode retryable envelope");
            assert_eq!(
                envelope
                    .details
                    .and_then(|details| details.retry_after_seconds),
                Some(1)
            );
        }
    }
    #[tokio::test]
    async fn unauthorized_error_receives_challenge_header() {
        let router = with_error_contract(
            Router::new().route("/auth", get(|| async { StatusCode::UNAUTHORIZED })),
        );
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/auth")
                    .header(header::ACCEPT, "application/json")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert!(response.headers().contains_key(header::WWW_AUTHENTICATE));
        let envelope: ErrorEnvelope = norito::json::from_slice(&body_bytes(response).await)
            .expect("decode unauthorized envelope");
        assert_eq!(envelope.code(), "unauthorized");
    }
    #[tokio::test]
    async fn head_error_advertises_typed_length_without_emitting_a_body() {
        let router = with_error_contract(
            Router::new().route("/head", get(|| async { StatusCode::NOT_FOUND })),
        );
        let response = router
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::HEAD)
                    .uri("/head")
                    .header(header::ACCEPT, "application/json")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(
            response
                .headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<usize>().ok())
                .is_some_and(|length| length > 0)
        );
        assert!(body_bytes(response).await.is_empty());
    }
    #[tokio::test]
    async fn oversized_and_malformed_typed_errors_fail_closed() {
        let oversized = vec![b'x'; MAX_TYPED_ERROR_BODY_BYTES + 1];
        let router = with_error_contract(
            Router::new()
                .route(
                    "/oversized",
                    get(move || {
                        let oversized = oversized.clone();
                        async move {
                            Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .header(header::CONTENT_TYPE, "application/json")
                                .body(Body::from(oversized))
                                .expect("oversized response")
                        }
                    }),
                )
                .route(
                    "/malformed",
                    get(|| async {
                        Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .header(header::CONTENT_TYPE, utils::NORITO_MIME_TYPE)
                            .body(Body::from(vec![0xff, 0x00, 0x7f]))
                            .expect("malformed response")
                    }),
                ),
        );
        for (path, status, code) in [
            (
                "/oversized",
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_server_error",
            ),
            ("/malformed", StatusCode::BAD_REQUEST, "bad_request"),
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header(header::ACCEPT, "application/json")
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(response.status(), status);
            let envelope: ErrorEnvelope = norito::json::from_slice(&body_bytes(response).await)
                .expect("decode fail-closed envelope");
            assert_eq!(envelope.code(), code);
        }
    }
    fn reviewed_sse_error_response() -> Response {
        let mut response = Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header(header::CONTENT_TYPE, "text/event-stream")
            .header("x-iroha-stream-error", "stream_resume_unsupported")
            .body(Body::from("reviewed resume rejection"))
            .expect("native response");
        response
            .extensions_mut()
            .insert(ReviewedProtocolNativeError::StreamResumeUnsupported);
        response
    }
    fn reviewed_mcp_error_response() -> Response {
        mcp::jsonrpc_transport_error_response(
            ReviewedMcpJsonRpcError::InvalidRequest,
            mcp::jsonrpc_invalid_request("reviewed MCP rejection"),
        )
    }
    #[tokio::test]
    async fn unmarked_protocol_error_cannot_bypass_typed_boundary() {
        let router = with_error_contract(Router::new().route(
            "/native",
            get(|| async {
                Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .header(header::CONTENT_TYPE, "text/plain")
                    .body(Body::from("upstream protocol secret"))
                    .expect("native response")
            }),
        ));
        let mut request = Request::builder()
            .uri("/native")
            .header(header::ACCEPT, "application/json")
            .body(Body::empty())
            .expect("request");
        request
            .extensions_mut()
            .insert(MatchedRouteMetadata::from_descriptor(
                route_catalog::sorafs::CID_ROOT,
            ));
        let response = router.oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = body_bytes(response).await;
        assert!(!String::from_utf8_lossy(&body).contains("secret"));
        let envelope: ErrorEnvelope =
            norito::json::from_slice(&body).expect("decode canonical error");
        assert_eq!(envelope.code(), "bad_gateway");
    }
    #[tokio::test]
    async fn exact_reviewed_sse_error_is_preserved_and_accept_checked() {
        let router = with_error_contract(
            Router::new().route("/native", get(|| async { reviewed_sse_error_response() })),
        );
        let request = |accept: &'static str| {
            let mut request = Request::builder()
                .uri("/native")
                .header(header::ACCEPT, accept)
                .body(Body::empty())
                .expect("request");
            request
                .extensions_mut()
                .insert(MatchedRouteMetadata::from_descriptor(
                    route_catalog::streaming::EVENTS_SSE,
                ));
            request
        };
        let response = router
            .clone()
            .oneshot(request("text/event-stream"))
            .await
            .expect("reviewed response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response
                .extensions()
                .get::<utils::HttpErrorCode>()
                .map(utils::HttpErrorCode::as_str),
            Some("stream_resume_unsupported")
        );
        assert!(
            response
                .extensions()
                .get::<ReviewedProtocolNativeError>()
                .is_none()
        );
        assert_eq!(
            body_bytes(response).await.as_ref(),
            b"reviewed resume rejection"
        );
        let response = router
            .oneshot(request("image/png"))
            .await
            .expect("native negotiation rejection");
        assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);
        assert!(response.headers().get("x-iroha-stream-error").is_none());
        let body = body_bytes(response).await;
        assert!(!String::from_utf8_lossy(&body).contains("reviewed resume rejection"));
        let envelope: ErrorEnvelope =
            norito::json::from_slice(&body).expect("decode native negotiation rejection");
        assert_eq!(envelope.code(), "response_not_acceptable");
    }
    #[tokio::test]
    async fn exact_reviewed_mcp_error_is_preserved_and_accept_checked() {
        let router = with_error_contract(
            Router::new().route("/native", get(|| async { reviewed_mcp_error_response() })),
        );
        let request = |accept: &'static str| {
            let mut request = Request::builder()
                .uri("/native")
                .header(header::ACCEPT, accept)
                .body(Body::empty())
                .expect("request");
            request
                .extensions_mut()
                .insert(MatchedRouteMetadata::from_descriptor(
                    route_catalog::mcp_transport::JSON_RPC,
                ));
            request
        };
        let response = router
            .clone()
            .oneshot(request("application/json, text/event-stream"))
            .await
            .expect("reviewed response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers().get(MCP_NATIVE_ERROR_HEADER),
            Some(&HeaderValue::from_static("invalid_request"))
        );
        assert_eq!(
            response
                .extensions()
                .get::<utils::HttpErrorCode>()
                .map(utils::HttpErrorCode::as_str),
            Some("invalid_request")
        );
        assert!(
            response
                .extensions()
                .get::<ReviewedProtocolNativeError>()
                .is_none()
        );
        let body: Value = norito::json::from_slice(&body_bytes(response).await)
            .expect("decode preserved JSON-RPC error");
        assert_eq!(
            body.get("error")
                .and_then(|error| error.get("data"))
                .and_then(|data| data.get("error_code"))
                .and_then(Value::as_str),
            Some("invalid_request")
        );

        let response = router
            .oneshot(request("image/png"))
            .await
            .expect("native negotiation rejection");
        assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);
        assert!(response.headers().get(MCP_NATIVE_ERROR_HEADER).is_none());
        let body = body_bytes(response).await;
        assert!(!String::from_utf8_lossy(&body).contains("reviewed MCP rejection"));
        let envelope: ErrorEnvelope =
            norito::json::from_slice(&body).expect("decode native negotiation rejection");
        assert_eq!(envelope.code(), "response_not_acceptable");
    }
    #[tokio::test]
    async fn reviewed_mcp_marker_fails_closed_on_route_status_media_or_marker_mismatch() {
        #[derive(Clone, Copy)]
        enum Mismatch {
            Route,
            Status,
            Media,
            Header,
            Unmarked,
        }
        for mismatch in [
            Mismatch::Route,
            Mismatch::Status,
            Mismatch::Media,
            Mismatch::Header,
            Mismatch::Unmarked,
        ] {
            let router = with_error_contract(Router::new().route(
                "/native",
                get(move || async move {
                    let mut response = reviewed_mcp_error_response();
                    match mismatch {
                        Mismatch::Route => {}
                        Mismatch::Status => {
                            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                        }
                        Mismatch::Media => {
                            response.headers_mut().insert(
                                header::CONTENT_TYPE,
                                HeaderValue::from_static("text/plain"),
                            );
                        }
                        Mismatch::Header => {
                            response.headers_mut().insert(
                                HeaderName::from_static(MCP_NATIVE_ERROR_HEADER),
                                HeaderValue::from_static("origin_forbidden"),
                            );
                        }
                        Mismatch::Unmarked => {
                            response
                                .extensions_mut()
                                .remove::<ReviewedProtocolNativeError>();
                        }
                    }
                    response
                }),
            ));
            let mut request = Request::builder()
                .uri("/native")
                .header(header::ACCEPT, "application/json")
                .body(Body::empty())
                .expect("request");
            request
                .extensions_mut()
                .insert(MatchedRouteMetadata::from_descriptor(
                    if matches!(mismatch, Mismatch::Route) {
                        route_catalog::sorafs::CID_ROOT
                    } else {
                        route_catalog::mcp_transport::JSON_RPC
                    },
                ));
            let response = router.oneshot(request).await.expect("response");
            assert!(response.headers().get(MCP_NATIVE_ERROR_HEADER).is_none());
            let status = response.status();
            let body = body_bytes(response).await;
            assert!(!String::from_utf8_lossy(&body).contains("reviewed MCP rejection"));
            let envelope: ErrorEnvelope =
                norito::json::from_slice(&body).expect("decode canonical error");
            if status == StatusCode::INTERNAL_SERVER_ERROR {
                assert_eq!(envelope.code(), "internal_server_error");
            } else {
                assert_eq!(envelope.code(), "bad_request");
            }
        }
    }
    #[tokio::test]
    async fn reviewed_marker_is_route_bound() {
        let router = with_error_contract(
            Router::new().route("/native", get(|| async { reviewed_sse_error_response() })),
        );
        let mut request = Request::builder()
            .uri("/native")
            .header(header::ACCEPT, "application/json")
            .body(Body::empty())
            .expect("request");
        request
            .extensions_mut()
            .insert(MatchedRouteMetadata::from_descriptor(
                route_catalog::sorafs::CID_ROOT,
            ));
        let response = router.oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get("x-iroha-stream-error").is_none());
        let body = body_bytes(response).await;
        assert!(!String::from_utf8_lossy(&body).contains("reviewed resume rejection"));
        let envelope: ErrorEnvelope =
            norito::json::from_slice(&body).expect("decode canonical error");
        assert_eq!(envelope.code(), "bad_request");
    }
}

#[cfg(test)]
mod request_id_middleware_tests {
    use super::*;
    use axum::{
        Router,
        body::Body,
        http::{HeaderValue, Request, StatusCode},
        routing::get,
    };
    use std::collections::HashSet;
    fn request_id(response: &axum::response::Response) -> &str {
        response
            .headers()
            .get(REQUEST_ID_HEADER)
            .and_then(|value| value.to_str().ok())
            .expect("response request id")
    }
    fn assert_server_generated(request_id: &str) {
        assert_eq!(request_id.len(), 64);
        assert!(
            request_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }
    #[tokio::test]
    async fn preserves_valid_client_request_id_on_response() {
        let router = Router::new()
            .route("/ok", get(|| async { StatusCode::NO_CONTENT }))
            .layer(axum::middleware::from_fn(attach_request_id));
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/ok")
                    .header(REQUEST_ID_HEADER, "client-request_42")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(request_id(&response), "client-request_42");
    }
    #[tokio::test]
    async fn replaces_combined_control_and_overlength_request_ids() {
        let router = Router::new()
            .route("/ok", get(|| async { StatusCode::NO_CONTENT }))
            .layer(axum::middleware::from_fn(attach_request_id));
        let mut ids = Vec::new();
        let overlong = "x".repeat(MAX_REQUEST_ID_LENGTH + 1);
        for supplied in [
            HeaderValue::from_static("contains spaces"),
            HeaderValue::from_static("first,second"),
            HeaderValue::from_bytes(b"client\tid").expect("horizontal tab header"),
            HeaderValue::from_str(&overlong).expect("overlength header"),
        ] {
            let mut request = Request::builder()
                .uri("/ok")
                .body(Body::empty())
                .expect("request");
            request.headers_mut().insert(REQUEST_ID_HEADER, supplied);
            let response = router.clone().oneshot(request).await.expect("response");
            let generated = request_id(&response).to_owned();
            assert_server_generated(&generated);
            ids.push(generated);
        }
        let unique = ids.iter().collect::<HashSet<_>>();
        assert_eq!(unique.len(), ids.len());
    }
    #[tokio::test]
    async fn repeated_valid_request_id_fields_are_replaced_not_ambiguously_echoed() {
        let router = Router::new()
            .route("/ok", get(|| async { StatusCode::NO_CONTENT }))
            .layer(axum::middleware::from_fn(attach_request_id));
        let mut request = Request::builder()
            .uri("/ok")
            .body(Body::empty())
            .expect("request");
        request.headers_mut().append(
            REQUEST_ID_HEADER,
            HeaderValue::from_static("first-valid-id"),
        );
        request.headers_mut().append(
            REQUEST_ID_HEADER,
            HeaderValue::from_static("second-valid-id"),
        );
        let response = router.oneshot(request).await.expect("response");
        let generated = request_id(&response);
        assert_server_generated(generated);
        assert_ne!(generated, "first-valid-id");
        assert_ne!(generated, "second-valid-id");
    }
}
