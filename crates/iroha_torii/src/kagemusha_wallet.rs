//! Account-authenticated recovery of ordinary Load receipts from committed state.
//! Returned data requires independent block-finality verification before wallet use.
use super::*;
use iroha_allocation::AllocationBudget;
use iroha_core::kagemusha_wallet_v1::CommittedLoadReceipts;

struct IssuanceBody {
    bytes: iroha_allocation::ChargedBuffer<u8>,
    _memory: QueryFanoutMemoryReservation,
}
impl AsRef<[u8]> for IssuanceBody {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}
const ROUTE: &str = "/v1/kagemusha/{scheme}/wallets/{wallet}/loads/{request}";
const FINALITY_ROUTE: &str = "/v1/kagemusha/{scheme}/wallets/{wallet}/loads/{request}/finality";
const EPOCH_ROUTE: &str =
    "/v1/kagemusha/{scheme}/wallets/{wallet}/loads/{request}/epochs/{boundary}";
#[derive(Clone, Copy)]
enum Original {
    Receipt,
    Finality,
    Epoch(u64),
}
fn selector(value: &str) -> Result<[u8; 32], Error> {
    let mut bytes = [0; 32];
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || hex::decode_to_slice(value, &mut bytes).is_err()
        || bytes == [0; 32]
    {
        return Err(conversion_error(
            "KAGEMUSHA identity must be canonical nonzero lowercase 32-byte hex".into(),
        ));
    }
    Ok(bytes)
}
fn unavailable() -> Error {
    Error::AppServiceUnavailable {
        code: "kagemusha_issuance_unavailable",
        message: "The payer's finalized issuance record is unavailable.".into(),
    }
}
fn boundary_selector(value: &str) -> Result<u64, Error> {
    let height = value.parse::<u64>().map_err(|_| {
        conversion_error("epoch boundary must be a canonical non-genesis height".into())
    })?;
    if height < 2 || height.to_string() != value {
        return Err(conversion_error(
            "epoch boundary must be a canonical non-genesis height".into(),
        ));
    }
    Ok(height)
}
fn finality_unavailable() -> Error {
    Error::AppServiceUnavailable {
        code: "kagemusha_load_finality_unavailable",
        message: "The payer's native Load finality evidence is unavailable.".into(),
    }
}
pub(crate) async fn handler(
    State(app): State<SharedAppState>,
    axum::extract::Path((scheme, wallet, request)): axum::extract::Path<(String, String, String)>,
    headers: HeaderMap,
    axum::Extension(auth): axum::Extension<crate::app_auth::VerifiedCanonicalRequest>,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> Result<AxResponse, Error> {
    read(
        app,
        scheme,
        wallet,
        request,
        headers,
        auth.account,
        remote,
        Original::Receipt,
    )
    .await
}
pub(crate) async fn finality_handler(
    State(app): State<SharedAppState>,
    axum::extract::Path((scheme, wallet, request)): axum::extract::Path<(String, String, String)>,
    headers: HeaderMap,
    axum::Extension(auth): axum::Extension<crate::app_auth::VerifiedCanonicalRequest>,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> Result<AxResponse, Error> {
    read(
        app,
        scheme,
        wallet,
        request,
        headers,
        auth.account,
        remote,
        Original::Finality,
    )
    .await
}
pub(crate) async fn epoch_handler(
    State(app): State<SharedAppState>,
    axum::extract::Path((scheme, wallet, request, boundary)): axum::extract::Path<(
        String,
        String,
        String,
        String,
    )>,
    headers: HeaderMap,
    axum::Extension(auth): axum::Extension<crate::app_auth::VerifiedCanonicalRequest>,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> Result<AxResponse, Error> {
    read(
        app,
        scheme,
        wallet,
        request,
        headers,
        auth.account,
        remote,
        Original::Epoch(boundary_selector(&boundary)?),
    )
    .await
}
async fn read(
    app: SharedAppState,
    scheme: String,
    wallet: String,
    request: String,
    headers: HeaderMap,
    payer: AccountId,
    remote: std::net::SocketAddr,
    original: Original,
) -> Result<AxResponse, Error> {
    let route = match original {
        Original::Receipt => ROUTE,
        Original::Finality => FINALITY_ROUTE,
        Original::Epoch(_) => EPOCH_ROUTE,
    };
    let unavailable: fn() -> Error = match original {
        Original::Finality | Original::Epoch(_) => finality_unavailable,
        _ => unavailable,
    };
    let scheme = selector(&scheme)?;
    let wallet = selector(&wallet)?;
    let request = selector(&request)?;
    // The route's zero-byte canonical-account middleware authenticates the selected
    // network and consumes the nonce exactly once before this handler. No request
    // bytes, public aliases or caller-supplied receipt fields can select authority.
    // A named epoch boundary selects only DATA; the phone must authenticate it.
    let principal = validate_api_token(app.as_ref(), &headers)?.authenticated_principal();
    // This endpoint preserves the canonical binary issuance frame. There is no JSON fallback
    // that could replace the exact original terms with an unbound projection.
    if !matches!(
        negotiate_heavy_query_response_format(&headers),
        Ok(ResponseFormat::Norito)
    ) {
        return Ok((StatusCode::NOT_ACCEPTABLE, "Accept application/x-norito").into_response());
    }
    let key = rate_limit_key(&headers, Some(remote.ip()), route, principal);
    rate_limit_requests_with_cost(&app, &key, FINALITY_HEAVY_QUERY_RATE_COST).await?;
    let admission = acquire_query_admission(app.as_ref(), true).await?;
    let bytes = app.query_fanout_working_set_bytes;
    let memory = app
        .query_fanout_inflight
        .try_acquire_parts([
            u64::try_from(bytes).map_err(|_| crate::native_projection_response::capacity())?
        ])
        .ok_or_else(crate::native_projection_response::capacity)?;
    let memory = QueryFanoutMemoryReservation::new(memory);
    let maximum = app.torii_proxy_max_response_bytes.min(bytes / 16);
    let state = app.state.clone();
    let finality_timeout = app.proof_limits.request_timeout;
    let response =
        routing::run_admitted_blocking(admission, "KAGEMUSHA issuance worker failed", move || {
            let budget = AllocationBudget::new(bytes);
            let limits = norito::DecodeLimits::new(maximum, maximum, maximum * 4, maximum * 4, 128);
            let _decoded = budget
                .try_reserve_bytes(maximum * 4)
                .map_err(|_| crate::native_projection_response::capacity())?;
            let view = state.view();
            let source =
                CommittedLoadReceipts::new(&view, maximum, limits).map_err(|_| unavailable())?;
            let bytes = if matches!(original, Original::Finality | Original::Epoch(_)) {
                let receipt = source
                    .receipt_for(&payer, &scheme, &wallet, &request)
                    .map_err(|_| unavailable())?;
                let deadline = std::time::Instant::now()
                    .checked_add(finality_timeout)
                    .ok_or_else(unavailable)?;
                let (original, frame_limit) = if let Original::Epoch(boundary) = original {
                    (
                        crate::kagemusha_wallet_finality::epoch(
                            &view, &payer, &receipt, boundary, &budget, deadline,
                        )
                        .map_err(|_| unavailable())?,
                        iroha_data_model::sumeragi_finality::MAX_COMMIT_CERTIFICATE_BYTES_V1,
                    )
                } else {
                    (
                        crate::kagemusha_wallet_finality::evidence(
                            &view, &source, &payer, &receipt, &budget, deadline,
                        )
                        .map_err(|_| unavailable())?,
                        iroha_data_model::kagemusha::KAGEMUSHA_WALLET_LOAD_FINALITY_MAX_BYTES_V1,
                    )
                };
                if original.as_slice().is_empty()
                    || original.as_slice().len() > maximum.min(frame_limit)
                {
                    return Err(unavailable());
                }
                original
            } else {
                let receipt = source
                    .receipt_for(&payer, &scheme, &wallet, &request)
                    .map_err(|_| unavailable())?;
                crate::native_projection_response::encode_canonical(
                    &receipt,
                    maximum.min(512),
                    &budget,
                    unavailable,
                )?
            };
            let body = IssuanceBody {
                bytes,
                _memory: memory,
            };
            let mut response = AxResponse::new(Body::from(Bytes::from_owner(body)));
            response.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/x-norito"),
            );
            response.headers_mut().insert(
                axum::http::header::CACHE_CONTROL,
                HeaderValue::from_static("private, no-store"),
            );
            Ok(response)
        })
        .await?;
    proof_response_with_exact_egress(
        app.as_ref(),
        &headers,
        Some(remote.ip()),
        route,
        response,
        true,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_selector_requires_canonical_non_genesis_height() {
        assert_eq!(boundary_selector("2").unwrap(), 2);
        assert_eq!(boundary_selector(&u64::MAX.to_string()).unwrap(), u64::MAX);
        for invalid in [
            "",
            "0",
            "1",
            "02",
            "+2",
            "-2",
            "2.0",
            "18446744073709551616",
        ] {
            assert!(boundary_selector(invalid).is_err(), "accepted {invalid:?}");
        }
    }

    fn read_router(app: SharedAppState) -> axum::Router {
        use crate::router::builder::{RouterBuilder, catalog_get};
        use iroha_torii_shared::route_catalog::{
            EnabledFeatures, RouteCatalog, contracts_and_verification_keys as routes,
        };
        const ROUTES: &[iroha_torii_shared::route_catalog::RouteDescriptor] = &[
            routes::KAGEMUSHA_LOAD_ISSUANCE_GET,
            routes::KAGEMUSHA_LOAD_FINALITY_GET,
            routes::KAGEMUSHA_LOAD_EPOCH_GET,
        ];
        let mut builder = RouterBuilder::new(
            app.clone(),
            RouteCatalog::new(ROUTES),
            EnabledFeatures::new(&["app_api"]),
        )
        .unwrap();
        builder.route(
            &ROUTES[0],
            catalog_get(handler).authenticated_canonical_account_body(app.clone(), 0),
        );
        builder.route(
            &ROUTES[1],
            catalog_get(finality_handler).authenticated_canonical_account_body(app.clone(), 0),
        );
        builder.route(
            &ROUTES[2],
            catalog_get(epoch_handler).authenticated_canonical_account_body(app.clone(), 0),
        );
        builder.finish().unwrap().0.with_state(app)
    }
    #[tokio::test]
    async fn load_original_http_requires_exact_network_auth_binary_accept_and_finality() {
        use crate::tests_runtime_handlers::{
            app_auth_test_guard, mk_app_state_for_tests_with_world, signed_network_app_headers,
            world_with_account,
        };
        use tower::ServiceExt as _;
        let _guard = app_auth_test_guard(crate::app_auth::CanonicalRequestAuthConfig::default());
        let key =
            iroha_crypto::KeyPair::from_seed(vec![0x73; 32], iroha_crypto::Algorithm::Ed25519);
        let payer = AccountId::new(key.public_key().clone());
        let app = mk_app_state_for_tests_with_world(world_with_account(&payer));
        let router = read_router(app.clone());
        for suffix in ["", "/finality", "/epochs/2"] {
            let uri: axum::http::Uri = format!(
                "/v1/kagemusha/{}/wallets/{}/loads/{}{suffix}",
                "11".repeat(32),
                "22".repeat(32),
                "33".repeat(32)
            )
            .parse()
            .unwrap();
            for (authenticated, accept, expected) in [
                (false, "application/x-norito", StatusCode::UNAUTHORIZED),
                (true, "application/json", StatusCode::NOT_ACCEPTABLE),
                (
                    true,
                    "application/x-norito",
                    StatusCode::SERVICE_UNAVAILABLE,
                ),
            ] {
                let mut request = axum::http::Request::builder()
                    .method("GET")
                    .uri(uri.clone())
                    .body(Body::empty())
                    .unwrap();
                if authenticated {
                    *request.headers_mut() = signed_network_app_headers(
                        app.state.network_id_ref(),
                        &payer,
                        &key,
                        &axum::http::Method::GET,
                        &uri,
                        &[],
                    );
                }
                request
                    .headers_mut()
                    .insert(axum::http::header::ACCEPT, HeaderValue::from_static(accept));
                request.extensions_mut().insert(axum::extract::ConnectInfo(
                    "127.0.0.1:19090".parse::<std::net::SocketAddr>().unwrap(),
                ));
                let response = router.clone().oneshot(request).await.unwrap();
                assert_eq!(response.status(), expected, "{uri}");
            }
        }
    }
    #[tokio::test]
    async fn finality_routes_require_empty_exact_network_signed_get_and_binary_accept() {
        use crate::tests_runtime_handlers::{
            app_auth_test_guard, mk_app_state_for_tests_with_world, signed_network_app_headers,
            world_with_account,
        };
        use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
        use iroha_data_model::{NetworkId, block::BlockHeader};
        use tower::ServiceExt as _;
        let _guard = app_auth_test_guard(crate::app_auth::CanonicalRequestAuthConfig::default());
        let key = KeyPair::from_seed(vec![0x74; 32], Algorithm::Ed25519);
        let payer = AccountId::new(key.public_key().clone());
        let app = mk_app_state_for_tests_with_world(world_with_account(&payer));
        let router = read_router(app.clone());
        for suffix in ["finality", "epochs/2"] {
            let uri: axum::http::Uri = format!(
                "/v1/kagemusha/{}/wallets/{}/loads/{}/{suffix}",
                "11".repeat(32),
                "22".repeat(32),
                "33".repeat(32)
            )
            .parse()
            .unwrap();
            let foreign = NetworkId::from_genesis_hash(
                HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0x53; 32])),
            );
            for (authenticated, network, body, accept, expected) in [
                (
                    false,
                    *app.state.network_id_ref(),
                    Vec::new(),
                    "application/x-norito",
                    StatusCode::UNAUTHORIZED,
                ),
                (
                    true,
                    foreign,
                    Vec::new(),
                    "application/x-norito",
                    StatusCode::FORBIDDEN,
                ),
                (
                    true,
                    *app.state.network_id_ref(),
                    vec![1],
                    "application/x-norito",
                    StatusCode::PAYLOAD_TOO_LARGE,
                ),
                (
                    true,
                    *app.state.network_id_ref(),
                    Vec::new(),
                    "application/json",
                    StatusCode::NOT_ACCEPTABLE,
                ),
                (
                    true,
                    *app.state.network_id_ref(),
                    Vec::new(),
                    "application/x-norito",
                    StatusCode::SERVICE_UNAVAILABLE,
                ),
            ] {
                let mut request = axum::http::Request::builder()
                    .method("GET")
                    .uri(uri.clone())
                    .body(Body::from(body.clone()))
                    .unwrap();
                if authenticated {
                    *request.headers_mut() = signed_network_app_headers(
                        &network,
                        &payer,
                        &key,
                        &axum::http::Method::GET,
                        &uri,
                        &body,
                    );
                }
                request
                    .headers_mut()
                    .insert(axum::http::header::ACCEPT, HeaderValue::from_static(accept));
                request.extensions_mut().insert(axum::extract::ConnectInfo(
                    "127.0.0.1:19090".parse::<std::net::SocketAddr>().unwrap(),
                ));
                let response = router.clone().oneshot(request).await.unwrap();
                assert_eq!(
                    response.status(),
                    expected,
                    "authenticated={authenticated}, network_matches={}, body_bytes={}, accept={accept}",
                    network == *app.state.network_id_ref(),
                    body.len(),
                );
                if expected == StatusCode::SERVICE_UNAVAILABLE {
                    assert_eq!(
                        response.headers()["x-iroha-reject-code"],
                        "kagemusha_load_finality_unavailable"
                    );
                    assert!(
                        response.headers()[axum::http::header::CACHE_CONTROL]
                            .to_str()
                            .unwrap()
                            .contains("no-store")
                    );
                    let bytes = axum::body::to_bytes(response.into_body(), 16_384)
                        .await
                        .unwrap();
                    assert!(
                    iroha_data_model::kagemusha::KagemushaWalletLoadFinalityV1::decode_canonical(
                        &bytes
                    )
                    .is_err()
                );
                }
            }
            for method in [axum::http::Method::POST, axum::http::Method::HEAD] {
                let response = router
                    .clone()
                    .oneshot(
                        axum::http::Request::builder()
                            .method(method)
                            .uri(uri.clone())
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
            }
            let changed: axum::http::Uri = uri
                .to_string()
                .replace(&"33".repeat(32), &"34".repeat(32))
                .parse()
                .unwrap();
            let mut request = axum::http::Request::builder()
                .method("GET")
                .uri(changed)
                .body(Body::empty())
                .unwrap();
            *request.headers_mut() = signed_network_app_headers(
                app.state.network_id_ref(),
                &payer,
                &key,
                &axum::http::Method::GET,
                &uri,
                &[],
            );
            request.headers_mut().insert(
                axum::http::header::ACCEPT,
                HeaderValue::from_static("application/x-norito"),
            );
            request.extensions_mut().insert(axum::extract::ConnectInfo(
                "127.0.0.1:19090".parse::<std::net::SocketAddr>().unwrap(),
            ));
            assert_eq!(
                router.clone().oneshot(request).await.unwrap().status(),
                StatusCode::FORBIDDEN,
                "the request path is bound by the canonical signature",
            );
        }
    }

    #[test]
    fn issuance_selectors_are_exact_and_nonzero() {
        assert_eq!(selector(&"ab".repeat(32)).unwrap(), [0xab; 32]);
        for invalid in [
            "AB".repeat(32),
            "00".repeat(32),
            "ab".repeat(31),
            format!("{} ", "ab".repeat(32)),
        ] {
            assert!(selector(&invalid).is_err());
        }
    }
}
