//! Pre-decode admission for SoraNet privacy telemetry collectors.
use crate::operator_signatures::AuthenticatedOperatorPublicKey;
#[cfg(feature = "telemetry")]
use crate::{
    Error, NoritoJson,
    routing::{self, RecordSoranetPrivacyEventDto, RecordSoranetPrivacyShareDto},
};
use crate::{SharedAppState, limits, utils};
#[cfg(feature = "telemetry")]
use axum::extract::Extension;
use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use iroha_data_model::soranet::privacy_metrics::{
    SoranetPrivacyCollectorIdV1, derive_soranet_privacy_collector_id,
};
use iroha_torii_shared::ErrorEnvelope;
use std::net::IpAddr;
/// Maximum encoded body accepted by either SoraNet privacy ingest route.
pub const SORANET_PRIVACY_INGEST_MAX_BODY_BYTES: usize = 128 * 1024;
const RETIRED_SORANET_PRIVACY_TOKEN_HEADERS: [&str; 2] = ["x-soranet-privacy-token", "x-api-token"];
#[derive(Clone)]
/// Route-local state for the signed collector's secondary admission guard.
pub struct SoranetPrivacyCollectorAuthState {
    /// Shared Torii configuration, limiter, and telemetry handles.
    pub(crate) app: SharedAppState,
    /// Stable endpoint label used by rejection telemetry.
    pub(crate) endpoint: &'static str,
}
#[derive(Clone, Copy, Debug)]
/// Marker inserted only after a collector passes secondary privacy admission.
pub struct VerifiedSoranetPrivacyCollector(SoranetPrivacyCollectorIdV1);
fn collector_id_for_operator(
    operator: &AuthenticatedOperatorPublicKey,
) -> SoranetPrivacyCollectorIdV1 {
    derive_soranet_privacy_collector_id(&operator.0)
}
fn privacy_reject(status: StatusCode, code: &'static str, message: impl Into<String>) -> Response {
    let payload = ErrorEnvelope::new(code, message.into());
    (status, utils::NoritoBody(payload)).into_response()
}
async fn enforce_soranet_privacy_ingest(
    app: &SharedAppState,
    headers: &HeaderMap,
    remote: Option<IpAddr>,
    endpoint: &'static str,
    operator: &AuthenticatedOperatorPublicKey,
) -> Result<(), Response> {
    let ingest_cfg = &app.soranet_privacy_ingest;
    #[cfg(not(feature = "telemetry"))]
    let _ = endpoint;
    if !ingest_cfg.enabled {
        #[cfg(feature = "telemetry")]
        app.telemetry
            .record_soranet_privacy_ingest_reject(endpoint, "disabled");
        return Err(privacy_reject(
            StatusCode::SERVICE_UNAVAILABLE,
            "soranet_privacy_disabled",
            "soranet privacy ingestion is disabled",
        ));
    }
    if app.soranet_privacy_allow_nets.is_empty()
        || !limits::is_allowed_by_cidr(headers, remote, &app.soranet_privacy_allow_nets)
    {
        #[cfg(feature = "telemetry")]
        app.telemetry
            .record_soranet_privacy_ingest_reject(endpoint, "namespace_blocked");
        return Err(privacy_reject(
            StatusCode::FORBIDDEN,
            "soranet_privacy_namespace_blocked",
            "submitter not in allowed namespace",
        ));
    }
    if RETIRED_SORANET_PRIVACY_TOKEN_HEADERS
        .iter()
        .any(|name| headers.contains_key(*name))
    {
        #[cfg(feature = "telemetry")]
        app.telemetry
            .record_soranet_privacy_ingest_reject(endpoint, "retired_token");
        return Err(privacy_reject(
            StatusCode::BAD_REQUEST,
            "soranet_privacy_token_retired",
            "bearer collector credentials are retired; use an exact operator request signature",
        ));
    }
    let rate_key = operator.0.to_string();
    let enforce_rate = ingest_cfg.rate_per_sec.is_some();
    if !limits::allow_conditionally(&app.soranet_privacy_rate_limiter, &rate_key, enforce_rate)
        .await
    {
        #[cfg(feature = "telemetry")]
        app.telemetry
            .record_soranet_privacy_ingest_reject(endpoint, "rate_limited");
        return Err(privacy_reject(
            StatusCode::TOO_MANY_REQUESTS,
            "soranet_privacy_rate_limited",
            "soranet privacy ingest is rate limited",
        ));
    }
    Ok(())
}
/// Authenticate one collector request before any request-body extractor runs.
pub async fn enforce_soranet_privacy_collector_authentication(
    State(state): State<SoranetPrivacyCollectorAuthState>,
    mut request: axum::http::Request<Body>,
    next: Next,
) -> Response {
    let remote = request
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|connect| connect.0.ip());
    let Some(operator) = request
        .extensions()
        .get::<AuthenticatedOperatorPublicKey>()
        .cloned()
    else {
        return privacy_reject(
            StatusCode::UNAUTHORIZED,
            "soranet_privacy_operator_signature_required",
            "missing authenticated operator request signature",
        );
    };
    if let Err(response) = enforce_soranet_privacy_ingest(
        &state.app,
        request.headers(),
        remote,
        state.endpoint,
        &operator,
    )
    .await
    {
        return response;
    }
    request
        .extensions_mut()
        .insert(VerifiedSoranetPrivacyCollector(collector_id_for_operator(
            &operator,
        )));
    next.run(request).await
}
#[cfg(feature = "telemetry")]
/// Record one authenticated SoraNet privacy event.
pub async fn handler_post_soranet_privacy_event(
    State(app): State<SharedAppState>,
    Extension(_collector): Extension<VerifiedSoranetPrivacyCollector>,
    request: NoritoJson<RecordSoranetPrivacyEventDto>,
) -> Result<Response, Error> {
    routing::handle_post_soranet_privacy_event(app.telemetry.clone(), request)
        .await
        .map(IntoResponse::into_response)
}
#[cfg(feature = "telemetry")]
/// Record one authenticated SoraNet privacy collector share.
pub async fn handler_post_soranet_privacy_share(
    State(app): State<SharedAppState>,
    Extension(collector): Extension<VerifiedSoranetPrivacyCollector>,
    request: NoritoJson<RecordSoranetPrivacyShareDto>,
) -> Result<Response, Error> {
    if request.0.share.collector_id != collector.0 {
        app.telemetry
            .record_soranet_privacy_ingest_reject("share", "collector_identity_mismatch");
        return Ok(privacy_reject(
            StatusCode::FORBIDDEN,
            "soranet_privacy_collector_identity_mismatch",
            "collector_id does not match the authenticated operator public key",
        ));
    }
    routing::handle_post_soranet_privacy_share(app.telemetry.clone(), request)
        .await
        .map(IntoResponse::into_response)
}
#[cfg(all(test, feature = "telemetry"))]
/// Exercise event admission and the authenticated handler in direct unit tests.
pub async fn test_handler_post_soranet_privacy_event_with_ingress(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    ConnectInfo(remote): ConnectInfo<std::net::SocketAddr>,
    Extension(operator): Extension<AuthenticatedOperatorPublicKey>,
    request: NoritoJson<RecordSoranetPrivacyEventDto>,
) -> Result<Response, Error> {
    if let Err(response) =
        enforce_soranet_privacy_ingest(&app, &headers, Some(remote.ip()), "event", &operator).await
    {
        return Ok(response);
    }
    handler_post_soranet_privacy_event(
        State(app),
        Extension(VerifiedSoranetPrivacyCollector(collector_id_for_operator(
            &operator,
        ))),
        request,
    )
    .await
}
#[cfg(all(test, feature = "telemetry"))]
/// Exercise share admission and the authenticated handler in direct unit tests.
pub async fn test_handler_post_soranet_privacy_share_with_ingress(
    State(app): State<SharedAppState>,
    headers: HeaderMap,
    ConnectInfo(remote): ConnectInfo<std::net::SocketAddr>,
    Extension(operator): Extension<AuthenticatedOperatorPublicKey>,
    request: NoritoJson<RecordSoranetPrivacyShareDto>,
) -> Result<Response, Error> {
    if let Err(response) =
        enforce_soranet_privacy_ingest(&app, &headers, Some(remote.ip()), "share", &operator).await
    {
        return Ok(response);
    }
    handler_post_soranet_privacy_share(
        State(app),
        Extension(VerifiedSoranetPrivacyCollector(collector_id_for_operator(
            &operator,
        ))),
        request,
    )
    .await
}
