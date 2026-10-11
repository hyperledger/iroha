// Exact principal binding for account-authenticated application drafts and receipts.
#[cfg(feature = "app_api")]
macro_rules! authenticated_application_query {
    ($handler:expr, $app_state:expr, $max_body_bytes:expr) => {
        catalog_post($handler).authenticated_canonical_account_body($app_state, $max_body_bytes)
    };
}
// The owner PRF handlers authenticate the original method, URI and bytes themselves.
// Keep the bounded body and private response policy without consuming the nonce twice.
#[cfg(feature = "app_api")]
macro_rules! identifier_owner_query {
    ($handler:expr, $max_body_bytes:expr) => {
        catalog_post($handler)
            .layer(axum::extract::DefaultBodyLimit::max(
                $max_body_bytes.min(16_384),
            ))
            .layer(axum::middleware::map_response(
                |mut response: AxResponse| async move {
                    install_canonical_account_private_cache_headers(&mut response);
                    response
                },
            ))
            .authenticated_in_handler(HandlerAuthentication::CanonicalAccountSignature)
    };
}
macro_rules! optional_dataspace_application_query {
    ($handler:expr, $app_state:expr, $max_body_bytes:expr) => {
        catalog_post($handler)
            .optionally_authenticated_canonical_account_body($app_state, $max_body_bytes)
    };
}
macro_rules! define_authenticated_application_query_mount {
    ($name:ident, $route:ident, $handler:ident) => {
        #[cfg(feature = "app_api")]
        fn $name(builder: &mut RouterBuilder, app_state: SharedAppState, max_body_bytes: usize) {
            builder.route(
                &route_catalog::application_api::$route,
                authenticated_application_query!($handler, app_state, max_body_bytes),
            );
        }
    };
}
macro_rules! define_optional_dataspace_application_query_mount {
    ($name:ident, $route:ident, $handler:ident) => {
        #[cfg(feature = "app_api")]
        fn $name(builder: &mut RouterBuilder, app_state: SharedAppState, max_body_bytes: usize) {
            builder.route(
                &route_catalog::application_api::$route,
                optional_dataspace_application_query!($handler, app_state, max_body_bytes),
            );
        }
    };
}
define_optional_dataspace_application_query_mount!(
    mount_account_transactions_query,
    ACCOUNTS_BY_ACCOUNT_ID_TRANSACTIONS_QUERY_POST,
    handler_account_transactions_query
);
define_optional_dataspace_application_query_mount!(
    mount_account_assets_query,
    ACCOUNTS_BY_ACCOUNT_ID_ASSETS_QUERY_POST,
    handler_account_assets_query
);
define_optional_dataspace_application_query_mount!(
    mount_domains_query,
    DOMAINS_QUERY_POST,
    handler_domains_query
);
define_optional_dataspace_application_query_mount!(
    mount_accounts_query,
    ACCOUNTS_QUERY_POST,
    handler_accounts_query
);
#[cfg(feature = "app_api")]
fn mount_transactions_query(
    builder: &mut RouterBuilder,
    app_state: SharedAppState,
    max_body_bytes: usize,
) {
    builder.route(
        &route_catalog::application_api::TRANSACTIONS_QUERY_POST,
        optional_dataspace_application_query!(
            handler_transactions_query,
            app_state,
            max_body_bytes
        ),
    );
}
define_authenticated_application_query_mount!(
    mount_repo_agreements_query,
    REPO_AGREEMENTS_QUERY_POST,
    handler_repo_agreements_query
);
define_optional_dataspace_application_query_mount!(
    mount_asset_definitions_query,
    ASSETS_DEFINITIONS_QUERY_POST,
    handler_assets_definitions_query
);
define_optional_dataspace_application_query_mount!(
    mount_nfts_query,
    NFTS_QUERY_POST,
    handler_nfts_query
);
define_optional_dataspace_application_query_mount!(
    mount_rwas_query,
    RWAS_QUERY_POST,
    handler_rwas_query
);
#[cfg(feature = "app_api")]
fn mount_signed_proof_query(builder: &mut RouterBuilder) {
    builder.route(
        &route_catalog::application_api::PROOFS_QUERY_POST,
        catalog_post(handler_proofs_query)
            .authenticated_in_handler(HandlerAuthentication::CanonicalSignedBody),
    );
}
#[cfg(feature = "app_api")]
macro_rules! mount_authenticated_asset_holder_routes {
    ($torii:expr, $builder:expr) => {{
        let max_body_bytes = $torii.transaction_max_content_len;
        $builder.route(
            &route_catalog::telemetry::ASSET_HOLDERS,
            catalog_get(handler_asset_holders)
                .authenticated_in_handler(HandlerAuthentication::OptionalCanonicalAccountSignature),
        );
        $builder.route(
            &route_catalog::telemetry::ASSET_HOLDERS_QUERY,
            optional_dataspace_application_query!(
                handler_asset_holders_query,
                $builder.state().clone(),
                max_body_bytes
            ),
        );
    }};
}
#[cfg(feature = "app_api")]
fn add_authenticated_application_compute_routes(
    builder: &mut RouterBuilder,
    app_state: SharedAppState,
    max_body_bytes: usize,
) {
    builder.route(
        &route_catalog::application_api::SPACE_DIRECTORY_MANIFESTS_POST,
        catalog_post(handler_authenticated_space_directory_manifest_publish)
            .authenticated_canonical_account_body(app_state.clone(), max_body_bytes),
    );
    builder.route(
        &route_catalog::application_api::SPACE_DIRECTORY_MANIFESTS_REVOKE_POST,
        catalog_post(handler_authenticated_space_directory_manifest_revoke)
            .authenticated_canonical_account_body(app_state.clone(), max_body_bytes),
    );
    builder.route(
        &route_catalog::application_api::RAM_LFE_PROGRAMS_BY_PROGRAM_ID_EXECUTE_POST,
        identifier_owner_query!(handler_ram_lfe_execute, max_body_bytes),
    );
    builder.route(
        &route_catalog::application_api::RAM_LFE_RECEIPTS_VERIFY_POST,
        catalog_post(handler_ram_lfe_receipt_verify)
            .authenticated_canonical_account_body(app_state.clone(), max_body_bytes),
    );
    builder.route(
        &route_catalog::application_api::ACCOUNTS_BY_ACCOUNT_ID_IDENTIFIERS_CLAIM_RECEIPT_POST,
        identifier_owner_query!(handler_identifier_claim_receipt, max_body_bytes),
    );
    builder.route(
        &route_catalog::application_api::IDENTIFIERS_RESOLVE_POST,
        identifier_owner_query!(handler_identifier_resolve, max_body_bytes),
    );
}
#[cfg(feature = "app_api")]
async fn handler_authenticated_space_directory_manifest_publish(
    State(app): State<SharedAppState>,
    axum::extract::Extension(verified): axum::extract::Extension<
        crate::app_auth::VerifiedCanonicalRequest,
    >,
    headers: axum::http::HeaderMap,
    remote: axum::extract::ConnectInfo<std::net::SocketAddr>,
    request: crate::utils::extractors::NoritoJson<crate::routing::SpaceDirectoryManifestPublishDto>,
) -> Result<impl IntoResponse, Error> {
    require_runtime_governance_account(
        &request.0.authority,
        &verified.account,
        "space-directory manifest publication draft",
    )?;
    handler_space_directory_manifest_publish(State(app), headers, remote, request).await
}
#[cfg(feature = "app_api")]
async fn handler_authenticated_space_directory_manifest_revoke(
    State(app): State<SharedAppState>,
    axum::extract::Extension(verified): axum::extract::Extension<
        crate::app_auth::VerifiedCanonicalRequest,
    >,
    headers: axum::http::HeaderMap,
    remote: axum::extract::ConnectInfo<std::net::SocketAddr>,
    request: crate::utils::extractors::NoritoJson<crate::routing::SpaceDirectoryManifestRevokeDto>,
) -> Result<impl IntoResponse, Error> {
    require_runtime_governance_account(
        &request.0.authority,
        &verified.account,
        "space-directory manifest revocation draft",
    )?;
    handler_space_directory_manifest_revoke(State(app), headers, remote, request).await
}
#[cfg(all(test, feature = "app_api"))]
mod application_account_auth_tests {
    use super::*;
    use iroha_data_model::ValidationFail;
    use iroha_test_samples::{ALICE_ID, BOB_ID};
    #[tokio::test]
    async fn owner_prf_routes_authenticate_original_bytes_once_and_reject_replay() {
        use axum::{
            body::Body,
            http::{Method, Request, StatusCode},
        };
        use iroha_torii_shared::route_catalog::{
            EnabledFeatures, RouteCatalog, application_api::*,
        };
        use tower::ServiceExt as _;

        let _guard = crate::tests_runtime_handlers::app_auth_test_guard(
            crate::app_auth::CanonicalRequestAuthConfig::default(),
        );
        let key = crate::tests_runtime_handlers::checked_torii_test_ed25519_keypair(
            0x72,
            "owner PRF route authentication regression",
        );
        let account = iroha_data_model::account::AccountId::new(key.public_key().clone());
        let app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world(
            crate::tests_runtime_handlers::world_with_account(&account),
        );
        let router_for_body_limit = |max_body_bytes| {
            let mut builder = RouterBuilder::new(
                app.clone(),
                RouteCatalog::new(&[
                    SPACE_DIRECTORY_MANIFESTS_POST,
                    SPACE_DIRECTORY_MANIFESTS_REVOKE_POST,
                    RAM_LFE_PROGRAMS_BY_PROGRAM_ID_EXECUTE_POST,
                    RAM_LFE_RECEIPTS_VERIFY_POST,
                    ACCOUNTS_BY_ACCOUNT_ID_IDENTIFIERS_CLAIM_RECEIPT_POST,
                    IDENTIFIERS_RESOLVE_POST,
                ]),
                EnabledFeatures::new(&["app_api"]),
            )
            .expect("owner PRF route catalog");
            add_authenticated_application_compute_routes(&mut builder, app.clone(), max_body_bytes);
            let (router, _) = builder
                .finish()
                .expect("exact production authentication policies");
            router.with_state(app.clone())
        };
        let router = router_for_body_limit(32_768);
        let claim_uri = format!("/v1/accounts/{account}/identifiers/claim-receipt");
        let identifier_body = br#"{ "phase": "prepare", "policy_id": "string#retail", "normalized_input": "alice", "input_nonce": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }"#.to_vec();
        let execute_body = br#"{ "normalized_input": "alice", "input_nonce": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }"#.to_vec();
        for (path, body) in [
            (claim_uri.as_str(), identifier_body.clone()),
            ("/v1/identifiers/resolve", identifier_body.clone()),
            ("/v1/ram-lfe/programs/string_retail/execute", execute_body),
        ] {
            let uri: axum::http::Uri = path.parse().expect("exact request URI");
            let headers = crate::tests_runtime_handlers::signed_network_app_headers(
                app.state.network_id_ref(),
                &account,
                &key,
                &Method::POST,
                &uri,
                &body,
            );
            let request = || {
                let mut request = Request::builder()
                    .method(Method::POST)
                    .uri(uri.clone())
                    .extension(crate::loopback_connect_info())
                    .body(Body::from(body.clone()))
                    .expect("original signed body");
                request.headers_mut().extend(headers.clone());
                request
            };
            let response = router
                .clone()
                .oneshot(request())
                .await
                .expect("first request");
            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "a valid signature must reach the missing policy, without a second nonce admission"
            );
            assert_eq!(
                response.headers()[axum::http::header::CACHE_CONTROL],
                "private, no-store"
            );
            let replay = router
                .clone()
                .oneshot(request())
                .await
                .expect("replayed request");
            assert_eq!(replay.status(), StatusCode::FORBIDDEN);
            assert_eq!(
                replay.headers()[axum::http::header::CACHE_CONTROL],
                "private, no-store"
            );
        }
        let wrong_account_uri = format!("/v1/accounts/{}/identifiers/claim-receipt", *BOB_ID);
        for (signed_path, actual_path, tamper_body, expected) in [
            (
                claim_uri.clone(),
                claim_uri.clone(),
                true,
                StatusCode::FORBIDDEN,
            ),
            (
                claim_uri.clone(),
                format!("{claim_uri}?unexpected=1"),
                false,
                StatusCode::BAD_REQUEST,
            ),
            (
                claim_uri.clone(),
                wrong_account_uri,
                false,
                StatusCode::FORBIDDEN,
            ),
        ] {
            let signed_uri: axum::http::Uri = signed_path.parse().expect("signed URI");
            let headers = crate::tests_runtime_handlers::signed_network_app_headers(
                app.state.network_id_ref(),
                &account,
                &key,
                &Method::POST,
                &signed_uri,
                &identifier_body,
            );
            let mut body = identifier_body.clone();
            if tamper_body {
                body.push(b' ');
            }
            let mut request = Request::builder()
                .method(Method::POST)
                .uri(actual_path)
                .extension(crate::loopback_connect_info())
                .body(Body::from(body))
                .expect("changed request");
            request.headers_mut().extend(headers);
            let response = router
                .clone()
                .oneshot(request)
                .await
                .expect("refused request");
            assert_eq!(response.status(), expected);
            assert_eq!(
                response.headers()[axum::http::header::CACHE_CONTROL],
                "private, no-store"
            );
        }
        for (configured_limit, effective_limit) in [(32_768, 16_384), (1_024, 1_024)] {
            let router = router_for_body_limit(configured_limit);
            for path in [
                claim_uri.as_str(),
                "/v1/identifiers/resolve",
                "/v1/ram-lfe/programs/string_retail/execute",
            ] {
                let response = router
                    .clone()
                    .oneshot(
                        Request::builder()
                            .method(Method::POST)
                            .uri(path)
                            .extension(crate::loopback_connect_info())
                            .body(Body::from(vec![b'x'; effective_limit + 1]))
                            .expect("oversized request"),
                    )
                    .await
                    .expect("bounded body rejection");
                assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
                assert_eq!(
                    response.headers()[axum::http::header::CACHE_CONTROL],
                    "private, no-store"
                );
                assert_eq!(
                    response.headers()[axum::http::header::VARY],
                    crate::content::CANONICAL_CONTENT_AUTH_VARY
                );
            }
        }
    }
    #[test]
    fn application_authority_binding_rejects_substitution() {
        require_runtime_governance_account(
            &ALICE_ID,
            &ALICE_ID,
            "space-directory manifest publication draft",
        )
        .expect("the exact authenticated authority must be accepted");
        let error = require_runtime_governance_account(
            &BOB_ID,
            &ALICE_ID,
            "space-directory manifest revocation draft",
        )
        .expect_err("another authority must be rejected");
        assert!(matches!(
            error,
            Error::Query(ValidationFail::NotPermitted(message))
                if message.contains("space-directory manifest revocation draft authority")
        ));
    }
}

define_optional_dataspace_application_query_mount!(
    mount_account_permissions_query,
    ACCOUNTS_BY_ACCOUNT_ID_PERMISSIONS_QUERY_POST,
    handler_account_permissions_query
);
define_optional_dataspace_application_query_mount!(
    mount_uaid_manifests_query,
    SPACE_DIRECTORY_UAIDS_BY_UAID_MANIFESTS_QUERY_POST,
    handler_space_directory_manifests_query
);

define_optional_dataspace_application_query_mount!(
    mount_account_history_query,
    ACCOUNTS_BY_ACCOUNT_ID_HISTORY_QUERY_POST,
    handler_account_history_query
);
