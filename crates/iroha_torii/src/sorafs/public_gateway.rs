//! Public, local-only SoraFS CID and site gateway routes.
//!
//! These routes are deliberately independent of Torii's optional application
//! API.  They never accept a client storage token: a canonical manifest already
//! present in the node's authoritative local store is the complete public-read
//! capability.  Every request retains one bounded concurrency permit through
//! manifest validation, policy admission, and payload readback.

#[cfg(not(feature = "app_api"))]
use axum::body::Body;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
#[cfg(not(feature = "app_api"))]
use iroha_core::state::StateReadOnly as _;
use std::sync::LazyLock;
#[cfg(not(feature = "app_api"))]
use std::{
    net::SocketAddr,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Semaphore, SemaphorePermit};

use crate::{JsonBody, SharedAppState, json_entry, json_object};

const MAX_PUBLIC_GATEWAY_INFLIGHT: usize = 64;
#[cfg(not(feature = "app_api"))]
const MAX_SITE_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;
#[cfg(not(feature = "app_api"))]
const MAX_LOCAL_MANIFEST_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
#[cfg(not(feature = "app_api"))]
const DEFAULT_FILE_LIST_LIMIT: usize = 50;
#[cfg(not(feature = "app_api"))]
const MAX_FILE_LIST_LIMIT: usize = 500;
const CLIENT_STORAGE_TOKEN_HEADERS: [&str; 2] = ["x-sorafs-stream-token", "x-sorafs-token-id"];

static PUBLIC_GATEWAY_INFLIGHT: LazyLock<Semaphore> =
    LazyLock::new(|| Semaphore::new(MAX_PUBLIC_GATEWAY_INFLIGHT));

fn json_error(status: StatusCode, code: &'static str, message: impl Into<String>) -> Response {
    (
        status,
        JsonBody(json_object(vec![
            json_entry("error", code),
            json_entry("message", message.into()),
        ])),
    )
        .into_response()
}

#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn reject_client_storage_tokens(headers: &HeaderMap) -> Result<(), Response> {
    if CLIENT_STORAGE_TOKEN_HEADERS
        .iter()
        .any(|name| headers.contains_key(*name))
    {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "client_storage_token_forbidden",
            "public SoraFS gateway reads do not accept client storage tokens",
        ));
    }
    Ok(())
}

#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn try_acquire_public_gateway_permit(
    semaphore: &Semaphore,
) -> Result<SemaphorePermit<'_>, Response> {
    semaphore.try_acquire().map_err(|_| {
        let mut response = json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "gateway_busy",
            "the public SoraFS gateway is at its concurrency limit",
        );
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        response
    })
}

#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn acquire_public_gateway_permit() -> Result<SemaphorePermit<'static>, Response> {
    try_acquire_public_gateway_permit(&PUBLIC_GATEWAY_INFLIGHT)
}

/// Serve the host-selected site manifest without an application principal.
pub async fn handle_get_sorafs_site_manifest(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    raw_query: axum::extract::RawQuery,
) -> Response {
    if let Err(response) = reject_client_storage_tokens(&headers) {
        return response;
    }
    let _permit = match acquire_public_gateway_permit() {
        Ok(permit) => permit,
        Err(response) => return response,
    };
    handle_get_sorafs_site_manifest_inner(State(state), headers, raw_query).await
}

/// Resolve one locally available CID without an application principal.
pub async fn handle_get_sorafs_cid_lookup(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    Path(cid): Path<String>,
    raw_query: axum::extract::RawQuery,
) -> Response {
    if let Err(response) = reject_client_storage_tokens(&headers) {
        return response;
    }
    let _permit = match acquire_public_gateway_permit() {
        Ok(permit) => permit,
        Err(response) => return response,
    };
    handle_get_sorafs_cid_lookup_inner(State(state), headers, Path(cid), raw_query).await
}

/// Serve the root document for one locally available CID.
pub async fn handle_get_sorafs_cid_root(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    uri: Uri,
    Path(cid): Path<String>,
) -> Response {
    if let Err(response) = reject_client_storage_tokens(&headers) {
        return response;
    }
    let _permit = match acquire_public_gateway_permit() {
        Ok(permit) => permit,
        Err(response) => return response,
    };
    handle_get_sorafs_cid_root_inner(State(state), headers, uri, Path(cid)).await
}

/// Serve a bounded path or byte range under one locally available CID.
pub async fn handle_get_sorafs_cid_path(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    uri: Uri,
    Path((cid, raw_path)): Path<(String, String)>,
) -> Response {
    if let Err(response) = reject_client_storage_tokens(&headers) {
        return response;
    }
    let _permit = match acquire_public_gateway_permit() {
        Ok(permit) => permit,
        Err(response) => return response,
    };
    handle_get_sorafs_cid_path_inner(State(state), headers, uri, Path((cid, raw_path))).await
}

/// Serve the root document selected by the request's canonical host.
pub async fn handle_get_sorafs_site_root(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = reject_client_storage_tokens(&headers) {
        return response;
    }
    let _permit = match acquire_public_gateway_permit() {
        Ok(permit) => permit,
        Err(response) => return response,
    };
    handle_get_sorafs_site_root_inner(State(state), headers).await
}

/// Serve a bounded path selected by the request's canonical host.
pub async fn handle_get_sorafs_site_path(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    Path(raw_path): Path<String>,
) -> Response {
    if let Err(response) = reject_client_storage_tokens(&headers) {
        return response;
    }
    let _permit = match acquire_public_gateway_permit() {
        Ok(permit) => permit,
        Err(response) => return response,
    };
    handle_get_sorafs_site_path_inner(State(state), headers, Path(raw_path)).await
}

/// Return whether the canonical request host selects a configured public SoraFS site.
pub fn request_host_selects_site(state: &SharedAppState, headers: &HeaderMap) -> bool {
    request_host_selects_site_inner(state, headers)
}

#[cfg(feature = "app_api")]
fn request_host_selects_site_inner(state: &SharedAppState, headers: &HeaderMap) -> bool {
    super::api::request_host_selects_sorafs_site(state, headers)
}

#[cfg(not(feature = "app_api"))]
fn request_host_selects_site_inner(state: &SharedAppState, headers: &HeaderMap) -> bool {
    let Some(host) = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(super::site::normalize_host_header)
    else {
        return false;
    };
    let cid_host = state.sorafs_gateway_config.untrusted_hosting.enabled
        && [
            state
                .sorafs_gateway_config
                .untrusted_hosting
                .cid_host_suffixes
                .live
                .as_str(),
            state
                .sorafs_gateway_config
                .untrusted_hosting
                .cid_host_suffixes
                .taira
                .as_str(),
        ]
        .into_iter()
        .filter(|suffix| !suffix.trim().is_empty())
        .any(|suffix| {
            let suffix = suffix.trim().trim_end_matches('.').to_ascii_lowercase();
            host.strip_suffix(&format!(".{suffix}"))
                .is_some_and(|label| !label.is_empty() && !label.contains('.'))
        });
    if cid_host
        || state
            .sorafs_site_bindings
            .as_deref()
            .and_then(|bindings| super::site::find_site_binding(bindings, &host))
            .is_some()
    {
        return true;
    }
    let state_view = state.state.view();
    super::site::has_authoritative_public_site_host(state_view.world(), &host)
}

// Keep the established full gateway implementation when the app API is
// present.  The outer functions above still provide the feature-independent
// anonymous route, token rejection, and end-to-end concurrency admission.
#[cfg(feature = "app_api")]
async fn handle_get_sorafs_site_manifest_inner(
    state: State<SharedAppState>,
    headers: HeaderMap,
    raw_query: axum::extract::RawQuery,
) -> Response {
    super::api::handle_get_sorafs_site_manifest(state, headers, raw_query).await
}

#[cfg(feature = "app_api")]
async fn handle_get_sorafs_cid_lookup_inner(
    state: State<SharedAppState>,
    headers: HeaderMap,
    cid: Path<String>,
    raw_query: axum::extract::RawQuery,
) -> Response {
    super::api::handle_get_sorafs_cid_lookup(state, headers, cid, raw_query).await
}

#[cfg(feature = "app_api")]
async fn handle_get_sorafs_cid_root_inner(
    state: State<SharedAppState>,
    headers: HeaderMap,
    uri: Uri,
    cid: Path<String>,
) -> Response {
    super::api::handle_get_sorafs_cid_root(state, headers, uri, cid).await
}

#[cfg(feature = "app_api")]
async fn handle_get_sorafs_cid_path_inner(
    state: State<SharedAppState>,
    headers: HeaderMap,
    uri: Uri,
    path: Path<(String, String)>,
) -> Response {
    super::api::handle_get_sorafs_cid_path(state, headers, uri, path).await
}

#[cfg(feature = "app_api")]
async fn handle_get_sorafs_site_root_inner(
    state: State<SharedAppState>,
    headers: HeaderMap,
) -> Response {
    super::api::handle_get_sorafs_site_root(state, headers).await
}

#[cfg(feature = "app_api")]
async fn handle_get_sorafs_site_path_inner(
    state: State<SharedAppState>,
    headers: HeaderMap,
    path: Path<String>,
) -> Response {
    super::api::handle_get_sorafs_site_path(state, headers, path).await
}

#[cfg(not(feature = "app_api"))]
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
#[cfg(not(feature = "app_api"))]
use iroha_data_model::sorafs::pin_registry::ManifestDigest;
#[cfg(not(feature = "app_api"))]
use iroha_logger::warn;
#[cfg(not(feature = "app_api"))]
use norito::json::{Map, Value};
#[cfg(not(feature = "app_api"))]
use sorafs_manifest::{decode_manifest_v1_canonical, validate_manifest};
#[cfg(not(feature = "app_api"))]
use sorafs_node::{
    NodeStorageError,
    store::{StorageError, StoredFileRecord, StoredManifest},
};

#[cfg(not(feature = "app_api"))]
fn storage_disabled_response() -> Response {
    json_error(
        StatusCode::NOT_FOUND,
        "sorafs_storage_disabled",
        "SoraFS storage is not enabled on this node",
    )
}

#[cfg(not(feature = "app_api"))]
fn node_storage_error_response(error: NodeStorageError) -> Response {
    match error {
        NodeStorageError::Disabled => storage_disabled_response(),
        NodeStorageError::Storage(StorageError::ManifestNotFound { .. }) => json_error(
            StatusCode::NOT_FOUND,
            "content_not_found",
            "the requested SoraFS content is not locally available",
        ),
        NodeStorageError::Storage(_) | NodeStorageError::Scheduler(_) => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "storage_unavailable",
            "the local SoraFS store could not complete the request",
        ),
    }
}

#[cfg(not(feature = "app_api"))]
fn parse_file_list_limit(raw_query: Option<&str>) -> Result<usize, Response> {
    let Some(raw) = raw_query else {
        return Ok(DEFAULT_FILE_LIST_LIMIT);
    };
    if raw.len() > 128 || raw.contains('%') {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_query",
            "the SoraFS gateway query is not canonical",
        ));
    }
    let mut limit = None;
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key != "limit" || limit.is_some() {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "invalid_query",
                "only one limit query parameter is accepted",
            ));
        }
        if value.is_empty()
            || !value.bytes().all(|byte| byte.is_ascii_digit())
            || (value.len() > 1 && value.starts_with('0'))
        {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "invalid_query",
                "limit must be a canonical positive integer",
            ));
        }
        let parsed = value.parse::<usize>().map_err(|_| {
            json_error(
                StatusCode::BAD_REQUEST,
                "invalid_query",
                "limit exceeds the supported range",
            )
        })?;
        if !(1..=MAX_FILE_LIST_LIMIT).contains(&parsed) {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "invalid_query",
                format!("limit must be between 1 and {MAX_FILE_LIST_LIMIT}"),
            ));
        }
        limit = Some(parsed);
    }
    Ok(limit.unwrap_or(DEFAULT_FILE_LIST_LIMIT))
}

#[cfg(not(feature = "app_api"))]
fn canonical_content_cid(raw: &str) -> Option<Vec<u8>> {
    let decoded = super::site::decode_content_cid(raw)?;
    (super::site::encode_content_cid(&decoded) == raw).then_some(decoded)
}

#[cfg(not(feature = "app_api"))]
fn resolve_local_cid(state: &SharedAppState, cid: &str) -> Result<StoredManifest, Response> {
    if !state.sorafs_node.is_enabled() {
        return Err(storage_disabled_response());
    }
    let cid_bytes = canonical_content_cid(cid).ok_or_else(|| {
        json_error(
            StatusCode::BAD_REQUEST,
            "invalid_cid",
            "content CID must use its canonical spelling",
        )
    })?;
    state
        .sorafs_node
        .manifest_metadata_by_cid(&cid_bytes)
        .map_err(node_storage_error_response)?
        .ok_or_else(|| {
            json_error(
                StatusCode::NOT_FOUND,
                "content_not_found",
                "the requested SoraFS content is not locally available",
            )
        })
}

#[cfg(not(feature = "app_api"))]
fn parse_manifest_digest(raw: &str) -> Result<[u8; 32], Response> {
    if raw.len() != 64 || raw.bytes().any(|byte| !byte.is_ascii_hexdigit()) {
        return Err(json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "invalid_site_binding",
            "the configured SoraFS site binding has an invalid manifest digest",
        ));
    }
    let mut digest = [0_u8; 32];
    hex::decode_to_slice(raw, &mut digest).map_err(|_| {
        json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "invalid_site_binding",
            "the configured SoraFS site binding has an invalid manifest digest",
        )
    })?;
    if hex::encode(digest) != raw {
        return Err(json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "invalid_site_binding",
            "the configured SoraFS site binding digest is not canonical",
        ));
    }
    Ok(digest)
}

#[cfg(not(feature = "app_api"))]
#[derive(Debug)]
struct ResolvedHost {
    hostname: String,
    index_document: String,
    spa_fallback: bool,
    stored: StoredManifest,
}

#[cfg(not(feature = "app_api"))]
fn cid_from_host(
    host: &str,
    config: &iroha_config::parameters::actual::SorafsGatewayUntrustedHosting,
) -> Result<Option<String>, Response> {
    if !config.enabled {
        return Ok(None);
    }
    for suffix in [
        config.cid_host_suffixes.live.as_str(),
        config.cid_host_suffixes.taira.as_str(),
    ] {
        let suffix = suffix.trim().trim_end_matches('.').to_ascii_lowercase();
        let Some(cid) = host.strip_suffix(&format!(".{suffix}")) else {
            continue;
        };
        if cid.is_empty() || cid.contains('.') || canonical_content_cid(cid).is_none() {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "invalid_cid_host",
                "the CID-derived host is not canonical",
            ));
        }
        return Ok(Some(cid.to_owned()));
    }
    Ok(None)
}

#[cfg(not(feature = "app_api"))]
fn resolve_local_host(
    state: &SharedAppState,
    headers: &HeaderMap,
) -> Result<ResolvedHost, Response> {
    if !state.sorafs_node.is_enabled() {
        return Err(storage_disabled_response());
    }
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(super::site::normalize_host_header)
        .ok_or_else(|| {
            json_error(
                StatusCode::BAD_REQUEST,
                "invalid_host",
                "a canonical Host header is required",
            )
        })?;
    if let Some(cid) = cid_from_host(&host, &state.sorafs_gateway_config.untrusted_hosting)? {
        return Ok(ResolvedHost {
            hostname: host,
            index_document: "index.html".to_owned(),
            spa_fallback: true,
            stored: resolve_local_cid(state, &cid)?,
        });
    }
    let authoritative = {
        let state_view = state.state.view();
        super::site::authoritative_app_site_binding(state_view.world(), &host)
    };
    match authoritative {
        Ok(Some(binding)) => {
            let digest = parse_manifest_digest(&binding.manifest_digest_hex)?;
            let stored = state
                .sorafs_node
                .manifest_metadata_by_digest(&digest)
                .map_err(node_storage_error_response)?;
            return Ok(ResolvedHost {
                hostname: binding.hostname,
                index_document: binding.index_document,
                spa_fallback: binding.spa_fallback,
                stored,
            });
        }
        Ok(None) => {}
        Err(error) => {
            warn!(%error, %host, "invalid ledger-authoritative SoraCloud static-site binding");
            return Err(json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "authoritative_site_binding_invalid",
                "the ledger-authoritative SoraCloud site binding is invalid",
            ));
        }
    }
    let binding = state
        .sorafs_site_bindings
        .as_deref()
        .and_then(|bindings| super::site::find_site_binding(bindings, &host))
        .ok_or_else(|| {
            json_error(
                StatusCode::NOT_FOUND,
                "site_not_found",
                "the requested host has no local SoraFS site binding",
            )
        })?;
    let digest = parse_manifest_digest(&binding.manifest_digest_hex)?;
    let stored = state
        .sorafs_node
        .manifest_metadata_by_digest(&digest)
        .map_err(node_storage_error_response)?;
    Ok(ResolvedHost {
        hostname: host,
        index_document: binding.index_document().to_owned(),
        spa_fallback: binding.spa_fallback_enabled(),
        stored,
    })
}

#[cfg(not(feature = "app_api"))]
async fn validate_canonical_local_manifest(stored: &StoredManifest) -> Result<(), Response> {
    let stored = stored.clone();
    let task = crate::panic_recovery::spawn_blocking_recoverable(move || {
        let manifest_bytes = stored.load_manifest_bytes().map_err(|_| {
            json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "manifest_unavailable",
                "the local SoraFS manifest could not be read",
            )
        })?;
        if manifest_bytes.len() > MAX_LOCAL_MANIFEST_RESPONSE_BYTES {
            return Err(json_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "manifest_too_large",
                "the local SoraFS manifest exceeds the public gateway limit",
            ));
        }
        let manifest = decode_manifest_v1_canonical(&manifest_bytes).map_err(|_| {
            json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "manifest_not_canonical",
                "the local SoraFS manifest is not canonical",
            )
        })?;
        validate_manifest(&manifest, &sorafs_manifest::PinPolicyConstraints::default()).map_err(
            |_| {
                json_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "manifest_invalid",
                    "the local SoraFS manifest failed semantic validation",
                )
            },
        )?;
        let digest = ManifestDigest::from_manifest(&manifest).map_err(|_| {
            json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "manifest_invalid",
                "the local SoraFS manifest digest could not be derived",
            )
        })?;
        if digest.as_bytes() != stored.manifest_digest()
            || manifest.root_cid.as_slice() != stored.manifest_cid()
        {
            return Err(json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "manifest_identity_mismatch",
                "the local SoraFS manifest does not match its authoritative index",
            ));
        }
        Ok(())
    });
    match crate::panic_recovery::join_recoverable(task).await {
        Ok(result) => result,
        Err(error) => {
            warn!(
                ?error,
                "public SoraFS manifest validation failed in its worker"
            );
            Err(json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "manifest_validation_unavailable",
                "the local SoraFS manifest could not be validated",
            ))
        }
    }
}

#[cfg(not(feature = "app_api"))]
fn effective_remote(headers: &HeaderMap) -> Result<SocketAddr, Response> {
    crate::limits::effective_remote_ip(headers, None)
        .map(|ip| SocketAddr::new(ip, 0))
        .ok_or_else(|| {
            json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "request_identity_unavailable",
                "the gateway request identity is unavailable",
            )
        })
}

#[cfg(not(feature = "app_api"))]
fn policy_violation_response(violation: super::gateway::PolicyViolation) -> Response {
    use super::gateway::{PolicyViolation, RateLimitError};
    match violation {
        PolicyViolation::ManifestEnvelopeMissing => json_error(
            StatusCode::PRECONDITION_REQUIRED,
            "manifest_envelope_required",
            "manifest envelope validation failed",
        ),
        PolicyViolation::MissingProviderId => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "provider_id_unavailable",
            "the local provider identity is unavailable",
        ),
        PolicyViolation::AdmissionUnavailable => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "admission_unavailable",
            "the provider admission registry is unavailable",
        ),
        PolicyViolation::ProviderNotAdmitted { .. } => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "provider_not_admitted",
            "the local provider is not admitted by governance",
        ),
        PolicyViolation::RateLimited(error) => {
            let retry_after = match error {
                RateLimitError::Limited { retry_after } => Some(retry_after),
                RateLimitError::Banned { retry_after } => retry_after,
            };
            let mut response = json_error(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "the public SoraFS gateway rate limit was exceeded",
            );
            if let Some(retry_after) = retry_after {
                let seconds = retry_after.as_secs().max(1).to_string();
                if let Ok(value) = HeaderValue::from_str(&seconds) {
                    response.headers_mut().insert(header::RETRY_AFTER, value);
                }
            }
            response
        }
    }
}

#[cfg(not(feature = "app_api"))]
fn compliance_unavailable_response() -> Response {
    let mut response = json_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "gateway_compliance_unavailable",
        "the governed SoraFS gateway compliance policy is unavailable",
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store, max-age=0"),
    );
    response
}

#[cfg(not(feature = "app_api"))]
fn enforce_compliance_subject(
    state: &SharedAppState,
    kind: sorafs_manifest::gateway_compliance::GatewayComplianceSubjectKindV1,
    subject: &str,
    observed_at_unix: u64,
) -> Result<(), Response> {
    let controller = state
        .sorafs_gateway_compliance_controller
        .as_ref()
        .ok_or_else(compliance_unavailable_response)?;
    let decision = controller
        .evaluate_serving(kind, subject, observed_at_unix)
        .map_err(|error| {
            warn!(
                ?error,
                "governed public SoraFS compliance evaluation failed closed"
            );
            compliance_unavailable_response()
        })?;
    compliance_decision_response(decision)
}

#[cfg(not(feature = "app_api"))]
fn compliance_decision_response(
    decision: super::gateway::GatewayComplianceDecision,
) -> Result<(), Response> {
    use super::gateway::{GatewayComplianceDecisionSource, GatewayComplianceDisposition};

    match (decision.disposition, decision.source) {
        (
            GatewayComplianceDisposition::Allow,
            GatewayComplianceDecisionSource::NoMatch
            | GatewayComplianceDecisionSource::AcceptedAppeal,
        ) => Ok(()),
        (
            GatewayComplianceDisposition::Deny,
            source @ (GatewayComplianceDecisionSource::Baseline
            | GatewayComplianceDecisionSource::LegalSafetyHold),
        ) => {
            let source = match source {
                GatewayComplianceDecisionSource::Baseline => "baseline",
                GatewayComplianceDecisionSource::LegalSafetyHold => "legal_safety_hold",
                _ => unreachable!("denial source was matched above"),
            };
            let digest = decision
                .catalog_digest
                .ok_or_else(compliance_unavailable_response)?;
            let mut response = (
                StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
                JsonBody(json_object(vec![
                    json_entry("error", "gateway_compliance_denied"),
                    json_entry("source", source),
                    json_entry("catalog_digest_hex", hex::encode(digest)),
                ])),
            )
                .into_response();
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("private, no-store, max-age=0"),
            );
            Err(response)
        }
        _ => Err(compliance_unavailable_response()),
    }
}

#[cfg(not(feature = "app_api"))]
async fn enforce_local_pre_read(
    state: &SharedAppState,
    headers: &HeaderMap,
    stored: &StoredManifest,
) -> Result<(), Response> {
    use super::gateway::{CanonicalHost, ClientFingerprint, PolicyDecision, RequestContext};
    validate_canonical_local_manifest(stored).await?;
    let provider_id = state
        .sorafs_node
        .capacity_usage()
        .provider_id
        .ok_or_else(|| {
            json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "provider_id_unavailable",
                "the authoritative local SoraFS provider identity is unavailable",
            )
        })?;
    let remote = effective_remote(headers)?;
    let fingerprint = ClientFingerprint::from_identifier(&remote.ip().to_string());
    let mut context = RequestContext::new(&fingerprint, SystemTime::now(), Instant::now())
        .with_provider_id(&provider_id)
        .with_manifest_digest(stored.manifest_digest())
        .with_content_cid(stored.manifest_cid())
        // Canonical bytes from the authoritative local store are the public
        // envelope.  No client-supplied token or envelope is consulted.
        .with_manifest_envelope(true)
        .with_remote_addr(remote);
    if let Some(host) = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(CanonicalHost::parse_authority)
    {
        context = context.with_canonical_host(host);
    }
    // The public gateway does not infer a governed region from a client
    // header. Region-aware admission remains an authenticated ingress concern.
    let observed_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| compliance_unavailable_response())?
        .as_secs();
    use sorafs_manifest::gateway_compliance::GatewayComplianceSubjectKindV1;
    enforce_compliance_subject(
        state,
        GatewayComplianceSubjectKindV1::ManifestDigest,
        &hex::encode(stored.manifest_digest()),
        observed_at_unix,
    )?;
    enforce_compliance_subject(
        state,
        GatewayComplianceSubjectKindV1::Cid,
        &super::site::encode_content_cid(stored.manifest_cid()),
        observed_at_unix,
    )?;
    enforce_compliance_subject(
        state,
        GatewayComplianceSubjectKindV1::Provider,
        &hex::encode(provider_id),
        observed_at_unix,
    )?;
    let policy = state.sorafs_gateway_policy.as_ref().ok_or_else(|| {
        json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "gateway_policy_unavailable",
            "the public SoraFS gateway policy is unavailable",
        )
    })?;
    match policy.evaluate(&context) {
        PolicyDecision::Allow => {}
        PolicyDecision::Deny(violation) => return Err(policy_violation_response(violation)),
    }
    Ok(())
}

#[cfg(not(feature = "app_api"))]
fn file_json(file: &StoredFileRecord) -> Value {
    let mut object = Map::new();
    object.insert(
        "path".into(),
        Value::Array(file.path.iter().cloned().map(Value::String).collect()),
    );
    object.insert("offset".into(), Value::from(file.offset));
    object.insert("size".into(), Value::from(file.size));
    object.insert("first_chunk".into(), Value::from(file.first_chunk as u64));
    object.insert("chunk_count".into(), Value::from(file.chunk_count as u64));
    Value::Object(object)
}

#[cfg(not(feature = "app_api"))]
fn manifest_listing(stored: &StoredManifest, limit: usize) -> (Vec<Value>, usize, bool) {
    let count = stored.files().len();
    let files = stored.files().iter().take(limit).map(file_json).collect();
    (files, count, count > limit)
}

#[cfg(not(feature = "app_api"))]
async fn handle_get_sorafs_site_manifest_inner(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> Response {
    let limit = match parse_file_list_limit(raw_query.as_deref()) {
        Ok(limit) => limit,
        Err(response) => return response,
    };
    let resolved = match resolve_local_host(&state, &headers) {
        Ok(resolved) => resolved,
        Err(response) => return response,
    };
    if let Err(response) = enforce_local_pre_read(&state, &headers, &resolved.stored).await {
        return response;
    }
    let stored = resolved.stored.clone();
    let task = crate::panic_recovery::spawn_blocking_recoverable(move || {
        stored.load_manifest_bytes().map_err(|_| {
            json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "manifest_unavailable",
                "the local SoraFS manifest could not be read",
            )
        })
    });
    let manifest_bytes = match crate::panic_recovery::join_recoverable(task).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(response)) => return response,
        Err(_) => {
            return json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "manifest_unavailable",
                "the local SoraFS manifest read failed",
            );
        }
    };
    if manifest_bytes.len() > MAX_LOCAL_MANIFEST_RESPONSE_BYTES {
        return json_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "manifest_too_large",
            "the local SoraFS manifest exceeds the public gateway limit",
        );
    }
    let (files, file_count, truncated_files) = manifest_listing(&resolved.stored, limit);
    JsonBody(json_object(vec![
        json_entry("hostname", resolved.hostname),
        json_entry(
            "content_cid",
            super::site::encode_content_cid(resolved.stored.manifest_cid()),
        ),
        json_entry(
            "manifest_digest_hex",
            hex::encode(resolved.stored.manifest_digest()),
        ),
        json_entry("manifest_id_hex", resolved.stored.manifest_id()),
        json_entry("manifest_b64", BASE64_STANDARD.encode(manifest_bytes)),
        json_entry("index_document", resolved.index_document),
        json_entry("spa_fallback", resolved.spa_fallback),
        json_entry("file_count", file_count as u64),
        json_entry("returned_file_count", files.len() as u64),
        json_entry("limit", limit as u64),
        json_entry("truncated_files", truncated_files),
        json_entry("files", Value::Array(files)),
    ]))
    .into_response()
}

#[cfg(not(feature = "app_api"))]
async fn handle_get_sorafs_site_root_inner(
    state: State<SharedAppState>,
    headers: HeaderMap,
) -> Response {
    handle_get_sorafs_site_path_inner(state, headers, Path(String::new())).await
}

#[cfg(not(feature = "app_api"))]
async fn handle_get_sorafs_site_path_inner(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    Path(raw_path): Path<String>,
) -> Response {
    let resolved = match resolve_local_host(&state, &headers) {
        Ok(resolved) => resolved,
        Err(response) => return response,
    };
    if let Err(response) = enforce_local_pre_read(&state, &headers, &resolved.stored).await {
        return response;
    }
    let Some(mut path) =
        super::site::path_components_for_request(&raw_path, resolved.index_document.as_str())
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let spa_fallback = resolved.spa_fallback
        && !raw_path
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .contains('.');
    if resolved.stored.file_by_path(&path).is_none() && spa_fallback {
        path = vec![resolved.index_document.clone()];
    }
    let mut response = read_site_file(&state, &resolved.stored, &path, &headers).await;
    if response.status().is_success()
        && let Ok(value) = HeaderValue::from_str(&super::site::encode_content_cid(
            resolved.stored.manifest_cid(),
        ))
    {
        response
            .headers_mut()
            .insert(header::HeaderName::from_static("x-sora-content-cid"), value);
    }
    response
}

#[cfg(not(feature = "app_api"))]
async fn handle_get_sorafs_cid_lookup_inner(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    Path(cid): Path<String>,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> Response {
    let limit = match parse_file_list_limit(raw_query.as_deref()) {
        Ok(limit) => limit,
        Err(response) => return response,
    };
    let stored = match resolve_local_cid(&state, &cid) {
        Ok(stored) => stored,
        Err(response) => return response,
    };
    if let Err(response) = enforce_local_pre_read(&state, &headers, &stored).await {
        return response;
    }
    let (files, file_count, truncated_files) = manifest_listing(&stored, limit);
    JsonBody(json_object(vec![
        json_entry(
            "content_cid",
            super::site::encode_content_cid(stored.manifest_cid()),
        ),
        json_entry("manifest_digest_hex", hex::encode(stored.manifest_digest())),
        json_entry("manifest_id_hex", stored.manifest_id()),
        json_entry("file_count", file_count as u64),
        json_entry("returned_file_count", files.len() as u64),
        json_entry("limit", limit as u64),
        json_entry("truncated_files", truncated_files),
        json_entry("files", Value::Array(files)),
    ]))
    .into_response()
}

#[cfg(not(feature = "app_api"))]
async fn handle_get_sorafs_cid_root_inner(
    state: State<SharedAppState>,
    headers: HeaderMap,
    uri: Uri,
    Path(cid): Path<String>,
) -> Response {
    handle_get_sorafs_cid_path_inner(state, headers, uri, Path((cid, String::new()))).await
}

#[cfg(not(feature = "app_api"))]
#[derive(Clone, Copy, Debug)]
struct ResponseRange {
    offset: u64,
    length: usize,
    partial: bool,
}

#[cfg(not(feature = "app_api"))]
fn range_not_satisfiable(file_size: u64) -> Response {
    let mut response = json_error(
        StatusCode::RANGE_NOT_SATISFIABLE,
        "range_not_satisfiable",
        "the requested SoraFS byte range is not satisfiable",
    );
    if let Ok(value) = HeaderValue::from_str(&format!("bytes */{file_size}")) {
        response.headers_mut().insert(header::CONTENT_RANGE, value);
    }
    response
        .headers_mut()
        .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    response
}

#[cfg(not(feature = "app_api"))]
fn response_range(headers: &HeaderMap, file_size: u64) -> Result<ResponseRange, Response> {
    let mut values = headers.get_all(header::RANGE).iter();
    let Some(value) = values.next() else {
        if file_size > MAX_SITE_RESPONSE_BYTES {
            return Err(json_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "response_too_large",
                format!(
                    "SoraFS files larger than {MAX_SITE_RESPONSE_BYTES} bytes require one bounded range"
                ),
            ));
        }
        return Ok(ResponseRange {
            offset: 0,
            length: usize::try_from(file_size).map_err(|_| range_not_satisfiable(file_size))?,
            partial: false,
        });
    };
    if values.next().is_some() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_range",
            "duplicate Range headers are not accepted",
        ));
    }
    let raw = value.to_str().map_err(|_| {
        json_error(
            StatusCode::BAD_REQUEST,
            "invalid_range",
            "Range must contain ASCII",
        )
    })?;
    let spec = raw
        .strip_prefix("bytes=")
        .filter(|value| !value.contains(','));
    let Some((start, end)) = spec.and_then(|value| value.split_once('-')) else {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "invalid_range",
            "exactly one bytes range is supported",
        ));
    };
    if file_size == 0 {
        return Err(range_not_satisfiable(file_size));
    }
    let (start, end) = if start.is_empty() {
        let suffix = end
            .parse::<u64>()
            .ok()
            .filter(|value| *value != 0)
            .ok_or_else(|| range_not_satisfiable(file_size))?;
        (file_size.saturating_sub(suffix), file_size - 1)
    } else {
        let start = start
            .parse::<u64>()
            .map_err(|_| range_not_satisfiable(file_size))?;
        let end = if end.is_empty() {
            file_size - 1
        } else {
            end.parse::<u64>()
                .map_err(|_| range_not_satisfiable(file_size))?
                .min(file_size - 1)
        };
        (start, end)
    };
    if start >= file_size || end < start {
        return Err(range_not_satisfiable(file_size));
    }
    let length = end
        .checked_sub(start)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| range_not_satisfiable(file_size))?;
    if length > MAX_SITE_RESPONSE_BYTES {
        return Err(json_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "response_too_large",
            format!("SoraFS byte ranges are limited to {MAX_SITE_RESPONSE_BYTES} bytes"),
        ));
    }
    Ok(ResponseRange {
        offset: start,
        length: usize::try_from(length).map_err(|_| range_not_satisfiable(file_size))?,
        partial: true,
    })
}

#[cfg(not(feature = "app_api"))]
async fn read_site_file(
    state: &SharedAppState,
    stored: &StoredManifest,
    path: &[String],
    headers: &HeaderMap,
) -> Response {
    let Some(file) = stored.file_by_path(path) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let range = match response_range(headers, file.size) {
        Ok(range) => range,
        Err(response) => return response,
    };
    let Some(offset) = file.offset.checked_add(range.offset) else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "invalid_stored_range",
            "the stored SoraFS file range overflowed",
        );
    };
    let node = state.sorafs_node.clone();
    let manifest_id = stored.manifest_id().to_owned();
    let task = crate::panic_recovery::spawn_blocking_recoverable(move || {
        node.read_payload_range(&manifest_id, offset, range.length)
    });
    let bytes = match crate::panic_recovery::join_recoverable(task).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(error)) => return node_storage_error_response(error),
        Err(error) => {
            warn!(?error, "public SoraFS payload read failed in its worker");
            return json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "storage_unavailable",
                "the local SoraFS payload read failed",
            );
        }
    };
    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = if range.partial {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };
    let content_type = super::site::content_type_for_path(path);
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&range.length.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("0")),
    );
    response
        .headers_mut()
        .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    response.headers_mut().insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    if content_type == "application/octet-stream" {
        response.headers_mut().insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_static("attachment"),
        );
    }
    if range.partial {
        let end = range
            .offset
            .saturating_add(u64::try_from(range.length).unwrap_or_default())
            .saturating_sub(1);
        if let Ok(value) =
            HeaderValue::from_str(&format!("bytes {}-{end}/{}", range.offset, file.size))
        {
            response.headers_mut().insert(header::CONTENT_RANGE, value);
        }
    }
    response
}

#[cfg(not(feature = "app_api"))]
fn is_cid_derived_origin(
    headers: &HeaderMap,
    cid: &str,
    config: &iroha_config::parameters::actual::SorafsGatewayUntrustedHosting,
) -> bool {
    if !config.enabled {
        return false;
    }
    let Some(host) = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(super::site::normalize_host_header)
    else {
        return false;
    };
    [
        config.cid_host_suffixes.taira.as_str(),
        config.cid_host_suffixes.live.as_str(),
    ]
    .into_iter()
    .filter(|suffix| !suffix.is_empty())
    .any(|suffix| {
        host == format!(
            "{cid}.{}",
            suffix.trim().trim_end_matches('.').to_ascii_lowercase()
        )
    })
}

#[cfg(not(feature = "app_api"))]
fn active_content_redirect(
    headers: &HeaderMap,
    uri: &Uri,
    cid: &str,
    config: &iroha_config::parameters::actual::SorafsGatewayUntrustedHosting,
) -> Option<Response> {
    if !config.enabled || !config.path_gateway_redirect {
        return None;
    }
    if config.redirect_html_only
        && !headers
            .get(header::ACCEPT)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value.split(',').any(|entry| {
                    matches!(
                        entry.trim().split(';').next().unwrap_or_default().trim(),
                        "text/html" | "application/xhtml+xml"
                    )
                })
            })
    {
        return None;
    }
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(super::site::normalize_host_header)?;
    let suffix = [
        config.cid_host_suffixes.taira.as_str(),
        config.cid_host_suffixes.live.as_str(),
    ]
    .into_iter()
    .find(|suffix| {
        suffix
            .strip_prefix("sorafs.")
            .map(str::trim)
            .map(|value| value.trim_end_matches('.').to_ascii_lowercase())
            .is_some_and(|path_gateway_host| path_gateway_host == host)
    })?;
    let prefix = format!("/sorafs/cid/{cid}");
    let path = if uri.path() == prefix {
        "/"
    } else {
        uri.path().strip_prefix(&format!("{prefix}/"))?
    };
    let mut location = format!(
        "https://{cid}.{}{}{}",
        suffix.trim().trim_end_matches('.').to_ascii_lowercase(),
        if path.starts_with('/') { "" } else { "/" },
        path
    );
    if let Some(query) = uri.query() {
        location.push('?');
        location.push_str(query);
    }
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::PERMANENT_REDIRECT;
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(&location).unwrap_or_else(|_| HeaderValue::from_static("/")),
    );
    Some(response)
}

#[cfg(not(feature = "app_api"))]
async fn handle_get_sorafs_cid_path_inner(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    uri: Uri,
    Path((cid, raw_path)): Path<(String, String)>,
) -> Response {
    let stored = match resolve_local_cid(&state, &cid) {
        Ok(stored) => stored,
        Err(response) => return response,
    };
    if let Err(response) = enforce_local_pre_read(&state, &headers, &stored).await {
        return response;
    }
    let Some(path) = super::site::path_components_for_request(&raw_path, "index.html") else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let hosting = &state.sorafs_gateway_config.untrusted_hosting;
    if stored.file_by_path(&path).is_some_and(|_| {
        iroha_torii_shared::content_mime::is_active_media_type(super::site::content_type_for_path(
            &path,
        ))
    }) && !is_cid_derived_origin(&headers, &cid, hosting)
    {
        if let Some(response) = active_content_redirect(&headers, &uri, &cid, hosting) {
            return response;
        }
        return json_error(
            StatusCode::MISDIRECTED_REQUEST,
            "isolated_origin_required",
            "active CID content is available only from its CID-derived isolated origin",
        );
    }
    let mut response = read_site_file(&state, &stored, &path, &headers).await;
    if response.status().is_success() {
        if let Ok(value) =
            HeaderValue::from_str(&super::site::encode_content_cid(stored.manifest_cid()))
        {
            response
                .headers_mut()
                .insert(header::HeaderName::from_static("x-sora-content-cid"), value);
        }
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=31536000, immutable"),
        );
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_gateway_rejects_both_client_storage_token_headers() {
        for name in CLIENT_STORAGE_TOKEN_HEADERS {
            let mut headers = HeaderMap::new();
            headers.insert(name, HeaderValue::from_static("client-secret"));
            let response = reject_client_storage_tokens(&headers)
                .expect_err("a client storage token must be rejected");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{name}");
        }
    }

    #[test]
    fn public_gateway_concurrency_limit_fails_fast_with_retry_after() {
        let semaphore = Semaphore::new(1);
        let permit = try_acquire_public_gateway_permit(&semaphore)
            .unwrap_or_else(|_| panic!("the first gateway request must acquire the only permit"));
        let response = match try_acquire_public_gateway_permit(&semaphore) {
            Ok(_) => panic!("a second gateway request must not exceed the concurrency bound"),
            Err(response) => response,
        };
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.headers().get(header::RETRY_AFTER),
            Some(&HeaderValue::from_static("1"))
        );
        drop(permit);
        assert!(try_acquire_public_gateway_permit(&semaphore).is_ok());
    }

    #[cfg(feature = "app_api")]
    #[tokio::test]
    async fn every_public_gateway_entrypoint_rejects_client_storage_tokens() {
        let state = crate::mk_app_state_for_tests();
        let cid = "client-token-must-win";
        for name in CLIENT_STORAGE_TOKEN_HEADERS {
            let mut headers = HeaderMap::new();
            headers.insert(name, HeaderValue::from_static("client-secret"));
            let responses = [
                handle_get_sorafs_site_manifest(
                    State(state.clone()),
                    headers.clone(),
                    axum::extract::RawQuery(None),
                )
                .await,
                handle_get_sorafs_cid_lookup(
                    State(state.clone()),
                    headers.clone(),
                    Path(cid.to_owned()),
                    axum::extract::RawQuery(None),
                )
                .await,
                handle_get_sorafs_cid_root(
                    State(state.clone()),
                    headers.clone(),
                    format!("/sorafs/cid/{cid}").parse().expect("CID root URI"),
                    Path(cid.to_owned()),
                )
                .await,
                handle_get_sorafs_cid_path(
                    State(state.clone()),
                    headers.clone(),
                    format!("/sorafs/cid/{cid}/asset.bin")
                        .parse()
                        .expect("CID path URI"),
                    Path((cid.to_owned(), "asset.bin".to_owned())),
                )
                .await,
                handle_get_sorafs_site_root(State(state.clone()), headers.clone()).await,
                handle_get_sorafs_site_path(
                    State(state.clone()),
                    headers,
                    Path("asset.bin".to_owned()),
                )
                .await,
            ];
            for response in responses {
                assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{name}");
            }
        }
    }

    #[cfg(not(feature = "app_api"))]
    #[test]
    fn no_app_api_gateway_primitives_keep_local_reads_canonical_isolated_and_bounded() {
        let cid = super::super::site::encode_content_cid(&[0x01, 0x71, 0x1f, 0x20]);
        assert_eq!(
            canonical_content_cid(&cid),
            Some(vec![0x01, 0x71, 0x1f, 0x20])
        );
        assert_eq!(canonical_content_cid(&cid.to_ascii_uppercase()), None);

        let mut hosting =
            iroha_config::parameters::actual::SorafsGatewayUntrustedHosting::default();
        hosting.enabled = true;
        hosting.cid_host_suffixes.taira = "sorafs.taira.sora.org".to_owned();
        assert_eq!(
            cid_from_host(&format!("{cid}.sorafs.taira.sora.org"), &hosting)
                .expect("canonical CID host"),
            Some(cid.clone())
        );
        let invalid_host = format!("{}.sorafs.taira.sora.org", cid.to_ascii_uppercase());
        assert_eq!(
            cid_from_host(&invalid_host, &hosting)
                .expect_err("a noncanonical CID host must fail")
                .status(),
            StatusCode::BAD_REQUEST
        );

        assert_eq!(
            super::super::site::path_components_for_request("assets/app.js", "index.html"),
            Some(vec!["assets".to_owned(), "app.js".to_owned()])
        );
        assert_eq!(
            super::super::site::path_components_for_request("../secret", "index.html"),
            None
        );
        let mut origin_headers = HeaderMap::new();
        origin_headers.insert(
            header::HOST,
            HeaderValue::from_str(&format!("{cid}.sorafs.taira.sora.org"))
                .expect("CID host header"),
        );
        assert!(is_cid_derived_origin(&origin_headers, &cid, &hosting));
        origin_headers.insert(header::HOST, HeaderValue::from_static("taira.sora.org"));
        assert!(!is_cid_derived_origin(&origin_headers, &cid, &hosting));

        let mut remote_headers = HeaderMap::new();
        remote_headers.insert(
            header::HeaderName::from_static(crate::limits::REMOTE_ADDR_HEADER),
            HeaderValue::from_static("203.0.113.7"),
        );
        remote_headers.insert(
            header::HeaderName::from_static(crate::limits::FORWARDED_FOR_HEADER),
            HeaderValue::from_static("198.51.100.99"),
        );
        assert_eq!(
            effective_remote(&remote_headers)
                .expect("ingress-normalized remote")
                .ip()
                .to_string(),
            "203.0.113.7"
        );

        let mut headers = HeaderMap::new();
        headers.insert(header::RANGE, HeaderValue::from_static("bytes=2-5"));
        let range = response_range(&headers, 8).expect("bounded range");
        assert_eq!(range.offset, 2);
        assert_eq!(range.length, 4);
        assert!(range.partial);
        headers.insert(header::RANGE, HeaderValue::from_static("bytes=0-1,4-5"));
        assert_eq!(
            response_range(&headers, 8)
                .expect_err("multiple ranges must fail")
                .status(),
            StatusCode::BAD_REQUEST
        );
        headers.clear();
        assert_eq!(
            response_range(&headers, MAX_SITE_RESPONSE_BYTES + 1)
                .expect_err("an unbounded oversized response must fail")
                .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    #[cfg(not(feature = "app_api"))]
    #[test]
    fn no_app_api_gateway_maps_governed_takedowns_and_provider_denials() {
        use super::super::gateway::{
            GatewayComplianceDecision, GatewayComplianceDecisionSource,
            GatewayComplianceDisposition, PolicyViolation,
        };

        let decision = GatewayComplianceDecision {
            disposition: GatewayComplianceDisposition::Deny,
            source: GatewayComplianceDecisionSource::LegalSafetyHold,
            reference_id: None,
            catalog_digest: Some([0xAB; 32]),
            catalog_sequence: 7,
            catalog_valid_until_unix: 4_102_444_800,
        };
        let response = compliance_decision_response(decision)
            .expect_err("a governed legal/safety hold must deny readback");
        assert_eq!(response.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("private, no-store, max-age=0"))
        );

        let response = policy_violation_response(PolicyViolation::ProviderNotAdmitted {
            provider_id: [0xCD; 32],
        });
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let response = policy_violation_response(PolicyViolation::RateLimited(
            super::super::gateway::RateLimitError::Banned {
                retry_after: Some(std::time::Duration::from_secs(3)),
            },
        ));
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response.headers().get(header::RETRY_AFTER),
            Some(&HeaderValue::from_static("3"))
        );
    }
}
