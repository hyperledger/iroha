//! Account-authenticated recovery of ordinary Load receipts and of direct ledger finality for
//! the caller's own Activate and Unload attempts from committed state: the attempts it signed,
//! and the Unloads whose claim pays it, which any signer may relay.
//! Returned data requires independent block-finality verification before wallet use.
use super::*;
use iroha_allocation::AllocationBudget;
use iroha_core::{
    kagemusha_wallet_v1::CommittedLoadReceipts,
    state::{KagemushaLedgerEntryOwnerV1, StateReadOnlyWithTransactions as _},
};
use iroha_data_model::{
    kagemusha::KAGEMUSHA_WALLET_LEDGER_FINALITY_MAX_BYTES_V1,
    sumeragi_finality::MAX_COMMIT_CERTIFICATE_BYTES_V1, transaction::TransactionEntrypoint,
};

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
const LEDGER_FINALITY_ROUTE: &str =
    "/v1/kagemusha/{scheme}/wallets/{wallet}/ledger/{entrypoint}/finality";
const LEDGER_EPOCH_ROUTE: &str =
    "/v1/kagemusha/{scheme}/wallets/{wallet}/ledger/{entrypoint}/epochs/{boundary}";
#[derive(Clone, Copy)]
enum Original {
    Receipt,
    Finality,
    Epoch(u64),
}
/// Direct ledger finality original of one committed Activate or Unload attempt.
#[derive(Clone, Copy)]
enum LedgerOriginal {
    Finality,
    Epoch(u64),
}
impl LedgerOriginal {
    const fn route(self) -> &'static str {
        match self {
            Self::Finality => LEDGER_FINALITY_ROUTE,
            Self::Epoch(_) => LEDGER_EPOCH_ROUTE,
        }
    }
    /// Complete canonical response bound, derived from the consensus limits.
    const fn frame_limit(self) -> usize {
        match self {
            Self::Finality => KAGEMUSHA_WALLET_LEDGER_FINALITY_MAX_BYTES_V1,
            Self::Epoch(_) => MAX_COMMIT_CERTIFICATE_BYTES_V1,
        }
    }
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
/// The one answer for an absent entry and for every committed input that is not the caller's
/// own Activate or Unload naming this wallet, so the routes are no existence or outcome oracle.
fn ledger_entry_not_committed() -> Error {
    Error::AppNotFound {
        code: "kagemusha_ledger_entry_not_committed",
        message: "No committed KAGEMUSHA ledger attempt of this account names this wallet.".into(),
    }
}
fn ledger_finality_unavailable() -> Error {
    Error::AppServiceUnavailable {
        code: "kagemusha_ledger_finality_unavailable",
        message: "The account's KAGEMUSHA ledger finality evidence is unavailable.".into(),
    }
}
/// Only an input absent from its committed block is an absence. Limits, storage, a missing
/// output join and local decoder refusals are retryable unavailability, never a verdict.
fn ledger_entry_error(error: BlockProofError) -> Error {
    if matches!(error, BlockProofError::EntrypointNotFound { .. }) {
        ledger_entry_not_committed()
    } else {
        ledger_finality_unavailable()
    }
}
/// The one owner rule of both routes (`is_attempt_of`, which the finality read applies as its
/// inclusion predicate): the External input carries an explicit Activate or Unload whose frame
/// names `wallet` under `scheme`, and the caller signed the input or, for an Unload, is the
/// account its claim pays. A relayed Unload is served to its relayer and to its claim account;
/// every other caller gets the same 404 as an absent entry.
fn require_ledger_attempt(
    owner: &KagemushaLedgerEntryOwnerV1,
    caller: &AccountId,
    scheme: &[u8; 32],
    wallet: &[u8; 32],
) -> Result<(), Error> {
    if owner.is_attempt_of(caller, scheme, wallet) {
        Ok(())
    } else {
        Err(ledger_entry_not_committed())
    }
}
/// The entrypoint selector is the exact canonical hash: lowercase, nonzero and marked.
fn entrypoint_selector(value: &str) -> Result<HashOf<TransactionEntrypoint>, Error> {
    Hash::from_marked_bytes(selector(value)?)
        .map(HashOf::from_untyped_unchecked)
        .ok_or_else(|| {
            conversion_error("KAGEMUSHA ledger entrypoint must be a canonical Iroha hash".into())
        })
}
/// Torii's configured block-proof ceilings for one ledger original; `response` bounds the
/// inclusion before its output row is copied.
///
/// The body is read through the checkpoint-resumed authenticator, which walks down from the
/// nearest verified checkpoint (at most one 64-block checkpoint interval and the target), so
/// the configured source ceilings bound every request independently of the chain height.
fn ledger_proof_limits(state: &CoreState, response: u64) -> BlockProofLimits {
    BlockProofLimits {
        max_response_bytes: response,
        ..super::block_proof_limits(state)
    }
}
/// A worker whose request deadline has elapsed reads no ledger body.
fn require_ledger_deadline(deadline: std::time::Instant) -> Result<(), Error> {
    if std::time::Instant::now() < deadline {
        Ok(())
    } else {
        Err(ledger_finality_unavailable())
    }
}
pub async fn handler(
    State(app): State<SharedAppState>,
    axum::extract::Path((scheme, wallet, request)): axum::extract::Path<(String, String, String)>,
    headers: HeaderMap,
    axum::Extension(auth): axum::Extension<crate::app_auth::VerifiedCanonicalRequest>,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> Result<AxResponse, Error> {
    read(
        app,
        (scheme, wallet, request),
        headers,
        auth.account,
        remote,
        Original::Receipt,
    )
    .await
}
pub async fn finality_handler(
    State(app): State<SharedAppState>,
    axum::extract::Path((scheme, wallet, request)): axum::extract::Path<(String, String, String)>,
    headers: HeaderMap,
    axum::Extension(auth): axum::Extension<crate::app_auth::VerifiedCanonicalRequest>,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> Result<AxResponse, Error> {
    read(
        app,
        (scheme, wallet, request),
        headers,
        auth.account,
        remote,
        Original::Finality,
    )
    .await
}
pub async fn epoch_handler(
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
        (scheme, wallet, request),
        headers,
        auth.account,
        remote,
        Original::Epoch(boundary_selector(&boundary)?),
    )
    .await
}
pub async fn ledger_finality_handler(
    State(app): State<SharedAppState>,
    axum::extract::Path((scheme, wallet, entrypoint)): axum::extract::Path<(
        String,
        String,
        String,
    )>,
    headers: HeaderMap,
    axum::Extension(auth): axum::Extension<crate::app_auth::VerifiedCanonicalRequest>,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> Result<AxResponse, Error> {
    ledger_read(
        app,
        (scheme, wallet, entrypoint),
        headers,
        auth.account,
        remote,
        LedgerOriginal::Finality,
    )
    .await
}
pub async fn ledger_epoch_handler(
    State(app): State<SharedAppState>,
    axum::extract::Path((scheme, wallet, entrypoint, boundary)): axum::extract::Path<(
        String,
        String,
        String,
        String,
    )>,
    headers: HeaderMap,
    axum::Extension(auth): axum::Extension<crate::app_auth::VerifiedCanonicalRequest>,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> Result<AxResponse, Error> {
    ledger_read(
        app,
        (scheme, wallet, entrypoint),
        headers,
        auth.account,
        remote,
        LedgerOriginal::Epoch(boundary_selector(&boundary)?),
    )
    .await
}
async fn read(
    app: SharedAppState,
    (scheme, wallet, request): (String, String, String),
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
async fn ledger_read(
    app: SharedAppState,
    (scheme, wallet, entrypoint): (String, String, String),
    headers: HeaderMap,
    caller: AccountId,
    remote: std::net::SocketAddr,
    original: LedgerOriginal,
) -> Result<AxResponse, Error> {
    let route = original.route();
    let scheme = selector(&scheme)?;
    let wallet = selector(&wallet)?;
    let entry_hash = entrypoint_selector(&entrypoint)?;
    // The route's zero-byte canonical-account middleware authenticates the selected network
    // and consumes the nonce exactly once before this handler. The caller is the only
    // authority selector; the path selects DATA, which the phone authenticates itself.
    let principal = validate_api_token(app.as_ref(), &headers)?.authenticated_principal();
    // The original certificate and inclusion are preserved as one canonical binary frame.
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
    let maximum = app
        .torii_proxy_max_response_bytes
        .min(bytes / 16)
        .min(original.frame_limit());
    let state = app.state.clone();
    let finality_timeout = app.proof_limits.request_timeout;
    let response = routing::run_admitted_blocking(
        admission,
        "KAGEMUSHA ledger finality worker failed",
        move || {
            let budget = AllocationBudget::new(bytes);
            let deadline = std::time::Instant::now()
                .checked_add(finality_timeout)
                .ok_or_else(ledger_finality_unavailable)?;
            // The committed index comes first: an absent entry reads no body, certificate or
            // World graph and answers exactly as every foreign or non-attempt input does.
            // Genesis inputs are never attempts and have no compact certificate.
            let height = state
                .view()
                .transactions()
                .get(&entry_hash)
                .and_then(|height| u64::try_from(height.get()).ok())
                .and_then(NonZeroU64::new)
                .filter(|height| height.get() >= 2)
                .ok_or_else(ledger_entry_not_committed)?;
            let response_limit =
                u64::try_from(maximum).map_err(|_| ledger_finality_unavailable())?;
            let limits = ledger_proof_limits(&state, response_limit);
            // Source frames are charged to this request's pool, and the walk's cumulative
            // decoder allowance is its admitted working set.
            let history = iroha_core::state::CanonicalHistoryReadBudget::new(
                budget.clone(),
                norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
                    bytes,
                    bytes,
                    bytes,
                    bytes,
                    norito::core::MAX_VALUE_NESTING_DEPTH,
                )),
            );
            let bytes = match original {
                LedgerOriginal::Finality => {
                    require_ledger_deadline(deadline)?;
                    // The one owner rule runs on the projection, before any Merkle path is
                    // built or the output row is copied; a refusal answers the same 404.
                    let found = state
                        .kagemusha_ledger_inclusion_for_entry(
                            height,
                            entry_hash,
                            limits,
                            &history,
                            |owner| owner.is_attempt_of(&caller, &scheme, &wallet),
                        )
                        .map_err(ledger_entry_error)?
                        .ok_or_else(ledger_entry_not_committed)?;
                    crate::kagemusha_wallet_finality::ledger_evidence(
                        &state.view(),
                        height.get(),
                        entry_hash,
                        found.inclusion,
                        &budget,
                        deadline,
                    )
                    .map_err(|_| ledger_finality_unavailable())?
                }
                LedgerOriginal::Epoch(boundary) => {
                    // Cheapest first: a boundary at or after the entry is refused before any
                    // body read, with the same answer as an absent entry.
                    if boundary >= height.get() {
                        return Err(ledger_entry_not_committed());
                    }
                    require_ledger_deadline(deadline)?;
                    // One bounded body read: no output copy and no Merkle path.
                    let owner = state
                        .kagemusha_ledger_entry_owner(height, entry_hash, limits, &history)
                        .map_err(ledger_entry_error)?;
                    require_ledger_attempt(&owner, &caller, &scheme, &wallet)?;
                    crate::kagemusha_wallet_finality::epoch_boundary(
                        &state.view(),
                        height.get(),
                        boundary,
                        &budget,
                        deadline,
                    )
                    .map_err(|_| ledger_finality_unavailable())?
                }
            };
            if bytes.as_slice().is_empty() || bytes.as_slice().len() > maximum {
                return Err(ledger_finality_unavailable());
            }
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
        },
    )
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
    fn ledger_selectors_routes_and_response_bounds_are_exact() {
        use iroha_torii_shared::route_catalog::contracts_and_verification_keys as routes;
        assert_eq!(
            LEDGER_FINALITY_ROUTE,
            routes::KAGEMUSHA_LEDGER_FINALITY_GET.path()
        );
        assert_eq!(
            LEDGER_EPOCH_ROUTE,
            routes::KAGEMUSHA_LEDGER_EPOCH_GET.path()
        );
        assert_eq!(LedgerOriginal::Finality.route(), LEDGER_FINALITY_ROUTE);
        assert_eq!(LedgerOriginal::Epoch(2).route(), LEDGER_EPOCH_ROUTE);
        // The finality response bound is the derived envelope bound, not a measurement.
        assert_eq!(
            LedgerOriginal::Finality.frame_limit(),
            KAGEMUSHA_WALLET_LEDGER_FINALITY_MAX_BYTES_V1
        );
        assert_eq!(LedgerOriginal::Finality.frame_limit(), 1_327_104);
        assert_eq!(
            LedgerOriginal::Epoch(2).frame_limit(),
            MAX_COMMIT_CERTIFICATE_BYTES_V1
        );
        assert_eq!(
            entrypoint_selector(&"ab".repeat(32)).unwrap(),
            HashOf::<TransactionEntrypoint>::from_untyped_unchecked(Hash::prehashed([0xab; 32]))
        );
        for invalid in [
            // The Iroha hash marker (least significant bit) is absent.
            format!("{}aa", "ab".repeat(31)),
            "AB".repeat(32),
            "00".repeat(32),
            "ab".repeat(31),
            format!("{} ", "ab".repeat(32)),
        ] {
            assert!(
                entrypoint_selector(&invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
    }

    #[test]
    fn ledger_proof_limits_keep_the_configured_block_proof_ceilings() {
        let app = crate::tests_runtime_handlers::mk_app_state_for_tests();
        let base = super::super::block_proof_limits(&app.state);
        // Only the response bound is the route's own; nothing derives from the chain height.
        assert_eq!(
            ledger_proof_limits(&app.state, 7),
            BlockProofLimits {
                max_response_bytes: 7,
                ..base
            }
        );
        // The default source ceiling covers a cold walk of one 64-block checkpoint interval
        // plus the target.
        assert!(base.max_source_blocks > 64, "{base:?}");
    }

    #[tokio::test]
    async fn ledger_attempt_selection_answers_one_404_for_every_foreign_or_absent_input() {
        use iroha_core::state::{
            BlockProofResource, KagemushaLedgerAttemptKindV1, KagemushaLedgerAttemptV1,
        };
        use iroha_crypto::{Algorithm, KeyPair};
        let account = |seed: u8| {
            AccountId::new(
                KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
                    .public_key()
                    .clone(),
            )
        };
        let (caller, other, claimant) = (account(0x71), account(0x72), account(0x73));
        let (scheme, wallet) = ([0x11; 32], [0x22; 32]);
        let (other_scheme, other_wallet) = ([0x33; 32], [0x44; 32]);
        // The caller signed this input. Its Unload relays a claim that pays `claimant`.
        let owner = KagemushaLedgerEntryOwnerV1 {
            authority: caller.clone(),
            attempts: vec![
                KagemushaLedgerAttemptV1 {
                    scheme: other_scheme,
                    kind: KagemushaLedgerAttemptKindV1::Activate,
                    wallet: other_wallet,
                },
                KagemushaLedgerAttemptV1 {
                    scheme,
                    kind: KagemushaLedgerAttemptKindV1::Unload {
                        account: claimant.clone(),
                    },
                    wallet,
                },
            ],
        };
        let non_attempt = KagemushaLedgerEntryOwnerV1 {
            authority: caller.clone(),
            attempts: Vec::new(),
        };
        // Both routes apply this one rule: the finality read as the inclusion predicate it
        // checks before building any path, the epoch read on its owner projection. The relayer
        // and the claim account both own the relayed Unload, so the claim naming another
        // account does not make the relayer's own query fail; the Activate stays the signer's.
        for (reader, path_scheme, path_wallet) in [
            (&caller, &scheme, &wallet),
            (&claimant, &scheme, &wallet),
            (&caller, &other_scheme, &other_wallet),
        ] {
            assert!(owner.is_attempt_of(reader, path_scheme, path_wallet));
            require_ledger_attempt(&owner, reader, path_scheme, path_wallet).unwrap();
        }
        let refused = [
            // A third account's request for the relayed Unload's exact wallet.
            (&owner, &other, &scheme, &wallet),
            // The claim account owns only the Unload its claim names: not the input's
            // Activate, and not a cross-attempt pair.
            (&owner, &claimant, &other_scheme, &other_wallet),
            (&owner, &claimant, &scheme, &other_wallet),
            (&owner, &claimant, &other_scheme, &wallet),
            // The caller's input naming another wallet or scheme, or a cross-attempt pair.
            (&owner, &caller, &scheme, &[0x66; 32]),
            (&owner, &caller, &[0x77; 32], &wallet),
            (&owner, &caller, &scheme, &other_wallet),
            // The caller's committed input without an Activate or Unload.
            (&non_attempt, &caller, &scheme, &wallet),
            (&non_attempt, &claimant, &scheme, &wallet),
        ];
        let mut refusals = Vec::new();
        for (projection, reader, path_scheme, path_wallet) in refused {
            // The finality read refuses before any path; the epoch read answers the 404.
            assert!(!projection.is_attempt_of(reader, path_scheme, path_wallet));
            refusals.push(
                require_ledger_attempt(projection, reader, path_scheme, path_wallet).unwrap_err(),
            );
        }
        let height = NonZeroU64::new(3).unwrap();
        let entry_hash = HashOf::from_untyped_unchecked(Hash::prehashed([0x55; 32]));
        // An input absent from its block, and an entry absent from the index.
        refusals.push(ledger_entry_error(BlockProofError::EntrypointNotFound {
            entry_hash,
            block_height: height,
        }));
        refusals.push(ledger_entry_not_committed());
        let mut observed = Vec::new();
        for refusal in refusals {
            let (parts, body) = refusal.into_response().into_parts();
            assert_eq!(parts.status, StatusCode::NOT_FOUND);
            assert_eq!(
                parts.headers["x-iroha-reject-code"],
                "kagemusha_ledger_entry_not_committed"
            );
            observed.push((
                parts.headers,
                axum::body::to_bytes(body, 16_384).await.unwrap(),
            ));
        }
        assert!(
            observed.iter().all(|response| response == &observed[0]),
            "every 404 is byte-identical"
        );
        let hash = |byte| HashOf::from_untyped_unchecked(Hash::prehashed([byte; 32]));
        for error in [
            BlockProofError::HeightOutOfRange(height),
            BlockProofError::BlockNotFound(height),
            BlockProofError::BlockHashMismatch {
                block_height: height,
                expected: hash(1),
                actual: hash(3),
            },
            BlockProofError::BlockHeightMismatch {
                requested: height,
                actual: NonZeroU64::MIN,
            },
            BlockProofError::Storage {
                block_height: height,
                reason: "native frame unavailable".into(),
            },
            BlockProofError::InvalidOutputs {
                block_height: height,
                reason: "Network input has no exact output join".into(),
            },
            BlockProofError::CapacityExceeded {
                block_height: height,
                resource: BlockProofResource::SourceBlocks,
                actual: 4,
                limit: 3,
            },
            BlockProofError::MissingResults(height),
        ] {
            let response = ledger_entry_error(error).into_response();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(
                response.headers()["x-iroha-reject-code"],
                "kagemusha_ledger_finality_unavailable"
            );
        }
    }

    fn ledger_router(app: SharedAppState) -> axum::Router {
        use crate::router::builder::{RouterBuilder, catalog_get};
        use iroha_torii_shared::route_catalog::{
            EnabledFeatures, RouteCatalog, contracts_and_verification_keys as routes,
        };
        const ROUTES: &[iroha_torii_shared::route_catalog::RouteDescriptor] = &[
            routes::KAGEMUSHA_LEDGER_FINALITY_GET,
            routes::KAGEMUSHA_LEDGER_EPOCH_GET,
        ];
        let mut builder = RouterBuilder::new(
            app.clone(),
            RouteCatalog::new(ROUTES),
            EnabledFeatures::new(&["app_api"]),
        )
        .unwrap();
        builder.route(
            &ROUTES[0],
            catalog_get(ledger_finality_handler)
                .authenticated_canonical_account_body(app.clone(), 0),
        );
        builder.route(
            &ROUTES[1],
            catalog_get(ledger_epoch_handler).authenticated_canonical_account_body(app.clone(), 0),
        );
        builder.finish().unwrap().0.with_state(app)
    }

    /// A genuine certified chain whose H3 is one committed External input of `caller` with no
    /// KAGEMUSHA attempt, served by a Torii app over the same State and Kura.
    fn ledger_fixture(
        caller: &iroha_crypto::KeyPair,
        foreign: &iroha_crypto::KeyPair,
    ) -> (
        SharedAppState,
        iroha_core::sumeragi::test_chain::CertifiedTestChain,
        HashOf<TransactionEntrypoint>,
    ) {
        use iroha_core::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
        use iroha_data_model::{
            Registrable as _,
            account::Account,
            isi::{InstructionBox, Log},
            level::Level,
        };
        let accounts = [caller, foreign].map(|key| {
            let id = AccountId::new(key.public_key().clone());
            Account::new(id.clone()).build(&id)
        });
        let world = iroha_core::state::World::with([], accounts, []);
        let mut chain = CertifiedTestChain::start(TestChainConfig::new(world, 1_000)).unwrap();
        let mut entry = None;
        for height in 2..=3_u64 {
            let transaction = chain.sign(
                caller,
                [InstructionBox::from(Log::new(
                    Level::TRACE,
                    format!("ledger route fixture {height}"),
                ))],
                height * 1_000 - 1,
            );
            entry = Some(transaction.hash_as_entrypoint());
            assert_eq!(chain.commit_at(height * 1_000, vec![transaction]), [true]);
        }
        assert_eq!(chain.height(), 3);
        (ledger_app(&chain), chain, entry.unwrap())
    }

    /// A Torii app over `chain`'s State and Kura whose signed-request admission names the
    /// chain's own network, as the canonical-account middleware requires.
    fn ledger_app(chain: &iroha_core::sumeragi::test_chain::CertifiedTestChain) -> SharedAppState {
        use std::sync::Arc;
        let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests();
        let unique = Arc::get_mut(&mut app).unwrap();
        unique.state = Arc::clone(chain.state());
        unique.kura = Arc::clone(chain.kura());
        unique.chain_id = Arc::new(chain.state().chain_id_ref().clone());
        unique.signed_query_admission = Arc::new(
            crate::routing::SignedQueryAdmission::new(
                chain.network_id(),
                std::time::Duration::from_secs(1),
                std::time::Duration::from_secs(120),
                std::num::NonZeroUsize::new(1_024).unwrap(),
            )
            .unwrap(),
        );
        app
    }

    async fn ledger_get(
        router: &axum::Router,
        app: &SharedAppState,
        key: &iroha_crypto::KeyPair,
        uri: &str,
        accept: &'static str,
        signed: bool,
    ) -> (StatusCode, HeaderMap, Bytes) {
        use tower::ServiceExt as _;
        let uri: axum::http::Uri = uri.parse().unwrap();
        let mut request = axum::http::Request::builder()
            .method("GET")
            .uri(uri.clone())
            .body(Body::empty())
            .unwrap();
        if signed {
            *request.headers_mut() = crate::tests_runtime_handlers::signed_network_app_headers(
                app.state.network_id_ref(),
                &AccountId::new(key.public_key().clone()),
                key,
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
        let (parts, body) = router.clone().oneshot(request).await.unwrap().into_parts();
        (
            parts.status,
            parts.headers,
            axum::body::to_bytes(body, 2 * KAGEMUSHA_WALLET_LEDGER_FINALITY_MAX_BYTES_V1)
                .await
                .unwrap(),
        )
    }

    #[tokio::test]
    async fn ledger_routes_answer_one_404_and_refuse_late_boundaries_without_body_reads() {
        use iroha_crypto::{Algorithm, KeyPair};
        let _guard = crate::tests_runtime_handlers::app_auth_test_guard(
            crate::app_auth::CanonicalRequestAuthConfig::default(),
        );
        let caller = KeyPair::from_seed(vec![0x75; 32], Algorithm::Ed25519);
        let foreign = KeyPair::from_seed(vec![0x76; 32], Algorithm::Ed25519);
        let (app, chain, entry) = ledger_fixture(&caller, &foreign);
        let router = ledger_router(app.clone());
        let hex_of = |hash: &HashOf<TransactionEntrypoint>| {
            let bytes: &[u8; 32] = hash.as_ref();
            hex::encode(bytes)
        };
        let path = |hash: &HashOf<TransactionEntrypoint>, suffix: &str| {
            format!(
                "/v1/kagemusha/{}/wallets/{}/ledger/{}/{suffix}",
                "11".repeat(32),
                "22".repeat(32),
                hex_of(hash),
            )
        };
        let absent =
            HashOf::<TransactionEntrypoint>::from_untyped_unchecked(Hash::prehashed([0x5b; 32]));
        let binary = "application/x-norito";
        let expected = ledger_get(
            &router,
            &app,
            &caller,
            &path(&absent, "finality"),
            binary,
            true,
        )
        .await;
        assert_eq!(expected.0, StatusCode::NOT_FOUND);
        assert_eq!(
            expected.1["x-iroha-reject-code"],
            "kagemusha_ledger_entry_not_committed"
        );
        assert!(
            expected.1[axum::http::header::CACHE_CONTROL]
                .to_str()
                .unwrap()
                .contains("no-store")
        );
        assert!(
            iroha_data_model::kagemusha::KagemushaWalletLedgerFinalityV1::decode_canonical(
                &expected.2
            )
            .is_err()
        );
        let identical_404 = |observed: &(StatusCode, HeaderMap, Bytes), uri: &str| {
            assert_eq!(observed.0, expected.0, "{uri}");
            for name in ["x-iroha-reject-code", "content-type", "cache-control"] {
                assert_eq!(observed.1.get(name), expected.1.get(name), "{uri}: {name}");
            }
            assert_eq!(observed.2, expected.2, "{uri}: byte-identical 404 body");
        };
        for (key, uri) in [
            // An entry absent from the committed index, under the epoch route.
            (&caller, path(&absent, "epochs/2")),
            // The caller's own committed input carries no Activate or Unload.
            (&caller, path(&entry, "finality")),
            (&caller, path(&entry, "epochs/2")),
            // Another authenticated account asks for the caller's committed input.
            (&foreign, path(&entry, "finality")),
            (&foreign, path(&entry, "epochs/2")),
            // A boundary at or after the entry.
            (&caller, path(&entry, "epochs/3")),
            (&caller, path(&entry, "epochs/4")),
        ] {
            identical_404(
                &ledger_get(&router, &app, key, &uri, binary, true).await,
                &uri,
            );
        }
        let uri = path(&entry, "finality");
        assert_eq!(
            ledger_get(&router, &app, &caller, &uri, binary, false)
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            ledger_get(&router, &app, &caller, &uri, "application/json", true)
                .await
                .0,
            StatusCode::NOT_ACCEPTABLE
        );
        let absent_hex = hex_of(&absent);
        for invalid in [
            path(&absent, "finality").replace(&"11".repeat(32), &"00".repeat(32)),
            path(&absent, "finality").replace(&absent_hex, &absent_hex.to_uppercase()),
            path(&absent, "finality").replace(&absent_hex, &"5a".repeat(32)),
            path(&entry, "epochs/1"),
            path(&entry, "epochs/02"),
        ] {
            assert_eq!(
                ledger_get(&router, &app, &caller, &invalid, binary, true)
                    .await
                    .0,
                StatusCode::BAD_REQUEST,
                "{invalid}"
            );
        }
        // A worker whose deadline has elapsed refuses before any body read: the caller's own
        // committed input without an attempt answers 503, not the 404 that reading its body
        // would give, while the index and boundary refusals keep the identical 404.
        let mut expired = ledger_app(&chain);
        std::sync::Arc::get_mut(&mut expired)
            .unwrap()
            .proof_limits
            .request_timeout = std::time::Duration::ZERO;
        let expired_router = ledger_router(expired.clone());
        for uri in [path(&entry, "finality"), path(&entry, "epochs/2")] {
            let observed = ledger_get(&expired_router, &expired, &caller, &uri, binary, true).await;
            assert_eq!(observed.0, StatusCode::SERVICE_UNAVAILABLE, "{uri}");
            assert_eq!(
                observed.1["x-iroha-reject-code"], "kagemusha_ledger_finality_unavailable",
                "{uri}"
            );
        }
        for uri in [path(&entry, "epochs/3"), path(&absent, "finality")] {
            identical_404(
                &ledger_get(&expired_router, &expired, &caller, &uri, binary, true).await,
                &uri,
            );
        }
        // Make every read of the inclusion block observable: its native frame no longer
        // decodes. A boundary at or after the entry still answers the identical 404, so it
        // read no body; a boundary before the entry reaches the body read and is refused.
        chain
            .kura()
            .corrupt_native_frame_for_test(std::num::NonZeroUsize::new(3).unwrap());
        for uri in [
            path(&entry, "epochs/3"),
            path(&entry, "epochs/4"),
            path(&absent, "epochs/2"),
        ] {
            identical_404(
                &ledger_get(&router, &app, &caller, &uri, binary, true).await,
                &uri,
            );
        }
        for uri in [path(&entry, "epochs/2"), path(&entry, "finality")] {
            let observed = ledger_get(&router, &app, &caller, &uri, binary, true).await;
            assert_eq!(observed.0, StatusCode::SERVICE_UNAVAILABLE, "{uri}");
            assert_eq!(
                observed.1["x-iroha-reject-code"], "kagemusha_ledger_finality_unavailable",
                "{uri}"
            );
        }
        drop(chain);
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
