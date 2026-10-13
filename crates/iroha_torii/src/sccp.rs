//! SCCP v1 public read API (`specs/sccp.md` §6).
//!
//! Every honest peer serves identical bytes derived only from committed state; wallets and
//! destinations never trust them and verify every bundle themselves. Responses are Norito or
//! JSON by `Accept`. Proofs select a committed certificate with `?at=record|latest|<H>`.
//! The checkpoint cover answers `410` when the head covers the height but no checkpoint at or above
//! it is retained. Immutable responses (proof bundles, history paths of an explicit size and
//! final message states) carry a strong `ETag` over the selected representation and answer a
//! matching `If-None-Match` with `304`.
//!
//! Metadata, committee and proof routes acquire one committed view and retain the original
//! request allocation, deadline and cancellation ownership through response publication.

pub mod native;
pub use native::{
    handler_capabilities, handler_committee, handler_control_proof, handler_controls,
    handler_current_committee, handler_evidence, handler_evidence_anchor, handler_evidence_page,
    handler_fast_pause, handler_finality, handler_forgery_hold, handler_governance,
    handler_governance_proposal, handler_governance_proposals, handler_governance_readiness,
    handler_light_client, handler_light_client_checkpoints, handler_light_client_sets,
    handler_light_clients, handler_message, handler_message_proof, handler_messages_recent,
    handler_outbound, handler_registry, handler_rotations,
};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse as _, Response},
};
#[cfg(test)]
use iroha_core::smartcontracts::isi::sccp::{
    read::{MAX_CONTROLS_PAGE, MAX_OUTBOUND_PAGE, MAX_RECENT_MESSAGES, SccpReadError},
    store,
};
use iroha_core::{
    smartcontracts::isi::sccp::read::{self, SccpDirectionV1},
    state::StateReadOnly,
};
use iroha_data_model::bridge::SccpNetworkV1;
use norito::json::{Map, Value};

// The query DTOs keep every value as its decimal or keyword text and parse it in the handler, so
// they are extracted without scalar coercion (`NoritoStringQuery`): a coercing extractor would
// turn `?from_nonce=1` into a JSON number that an `Option<String>` field refuses.
use crate::{JsonBody, NoritoStringQuery, SharedAppState, utils::extractors::ExtractAccept};

/// `?direction=outbound|inbound&network=&before=&limit=` of the recent-messages route.
#[derive(Debug, Default, Clone, crate::json_macros::JsonDeserialize)]
pub struct RecentQuery {
    /// `outbound` (default) or `inbound`.
    #[norito(default)]
    pub direction: Option<String>,
    /// External network profile key filter.
    #[norito(default)]
    pub network: Option<String>,
    /// `next_before` cursor of the previous page.
    #[norito(default)]
    pub before: Option<String>,
    /// Page size, at most 50.
    #[norito(default)]
    pub limit: Option<String>,
}

/// `?from_nonce=&limit=` of the outbound-by-nonce route.
#[derive(Debug, Default, Clone, crate::json_macros::JsonDeserialize)]
pub struct OutboundQuery {
    /// First nonce (default 0).
    #[norito(default)]
    pub from_nonce: Option<String>,
    /// Page size, at most 256.
    #[norito(default)]
    pub limit: Option<String>,
}

/// `?after_nonce=&limit=` of the controls route.
#[derive(Debug, Default, Clone, crate::json_macros::JsonDeserialize)]
pub struct ControlsQuery {
    /// Controls above this nonce (default 0: every control).
    #[norito(default)]
    pub after_nonce: Option<String>,
    /// Page size, at most 64.
    #[norito(default)]
    pub limit: Option<String>,
}

/// `?covering=N` of the checkpoint route.
#[derive(Debug, Default, Clone, crate::json_macros::JsonDeserialize)]
pub struct CoveringQuery {
    /// Source height to anchor (required).
    #[norito(default)]
    pub covering: Option<String>,
}

/// `?size=S` of the history route.
#[derive(Debug, Default, Clone, crate::json_macros::JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct HistoryQuery {
    /// History size (default: the current size).
    #[norito(default)]
    pub size: Option<String>,
}

#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn parse_number<T: core::str::FromStr>(text: Option<&str>, default: T) -> Result<T, Response> {
    text.map_or(Ok(default), |text| {
        text.parse().map_err(|_| {
            error(
                StatusCode::BAD_REQUEST,
                "sccp_invalid_query",
                format!("`{text}` is not a decimal number"),
            )
        })
    })
}

fn error(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    let mut body = Map::new();
    body.insert("code".into(), Value::from(code.to_owned()));
    body.insert("message".into(), Value::from(message.into()));
    (status, JsonBody(Value::Object(body))).into_response()
}

#[cfg(test)]
fn read_error(read: &SccpReadError) -> Response {
    match read {
        SccpReadError::NotFound(_) => {
            error(StatusCode::NOT_FOUND, "sccp_not_found", read.to_string())
        }
        SccpReadError::Pruned(_) => error(StatusCode::GONE, "sccp_pruned", read.to_string()),
        SccpReadError::Invalid(_) => error(
            StatusCode::BAD_REQUEST,
            "sccp_invalid_query",
            read.to_string(),
        ),
    }
}

#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn format(accept: Option<&ExtractAccept>) -> Result<crate::utils::ResponseFormat, Response> {
    crate::utils::negotiate_response_format(accept.map(|value| &value.0))
}

#[cfg(test)]
fn respond<T>(accept: Option<&ExtractAccept>, value: T) -> Response
where
    T: norito::json::JsonSerialize + norito::core::NoritoSerialize + 'static,
{
    match format(accept) {
        Ok(format) => crate::utils::respond_with_format(value, format),
        Err(response) => response,
    }
}

#[cfg(test)]
fn respond_result<T>(accept: Option<&ExtractAccept>, result: Result<T, SccpReadError>) -> Response
where
    T: norito::json::JsonSerialize + norito::core::NoritoSerialize + 'static,
{
    match result {
        Ok(value) => respond(accept, value),
        Err(failure) => read_error(&failure),
    }
}

fn validator_headers(response: &mut Response, etag: &str) {
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(etag) {
        headers.insert(header::ETAG, value);
    }
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, no-cache"),
    );
    crate::append_vary_accept(headers);
}

/// Respond with an immutable record: a strong `ETag` over the negotiated representation, and
/// `304 Not Modified` for a matching `If-None-Match`.
#[cfg(test)]
fn respond_immutable<T>(accept: Option<&ExtractAccept>, headers: &HeaderMap, value: T) -> Response
where
    T: norito::json::JsonSerialize + norito::core::NoritoSerialize + 'static,
{
    use crate::utils::ResponseFormat;
    let format = match format(accept) {
        Ok(format) => format,
        Err(response) => return response,
    };
    let encoded = match format {
        ResponseFormat::Norito => {
            let mut bytes = Vec::new();
            norito::core::to_bytes_in(&value, &mut bytes)
                .ok()
                .map(|()| (crate::utils::NORITO_MIME_TYPE, bytes))
        }
        ResponseFormat::Json => norito::json::to_vec(&value)
            .ok()
            .map(|bytes| ("application/json", bytes)),
    };
    let Some((content_type, body)) = encoded else {
        // Let the shared encoder report the serialization failure.
        return crate::utils::respond_with_format(value, format);
    };
    // SCCP owns the validator for the exact negotiated response bytes.
    let etag = format!("\"{}\"", blake3::hash(&body).to_hex());
    let mut response = if crate::utils::if_none_match_matches(headers, &etag) {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        let mut response = axum::body::Body::from(body).into_response();
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
        response
    };
    validator_headers(&mut response, &etag);
    response
}

#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn parse_word(text: &str) -> Result<[u8; 32], Response> {
    let bytes = hex::decode(text.strip_prefix("0x").unwrap_or(text))
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok());
    bytes.ok_or_else(|| {
        error(
            StatusCode::BAD_REQUEST,
            "sccp_invalid_query",
            "expected a 32-byte hex identifier",
        )
    })
}

#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn parse_network(text: &str) -> Result<SccpNetworkV1, Response> {
    SccpNetworkV1::from_profile_key(text)
        .filter(|network| network.is_external())
        .ok_or_else(|| {
            error(
                StatusCode::BAD_REQUEST,
                "sccp_invalid_query",
                format!("`{text}` is not an external SCCP network"),
            )
        })
}

#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn parse_direction(text: Option<&str>) -> Result<SccpDirectionV1, Response> {
    text.map_or(Ok(SccpDirectionV1::Outbound), |text| {
        SccpDirectionV1::parse(text).ok_or_else(|| {
            error(
                StatusCode::BAD_REQUEST,
                "sccp_invalid_query",
                "direction must be `outbound` or `inbound`",
            )
        })
    })
}

// ---------------------------------------------------------------------------------------------
// Responses over a state view
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
fn metadata_fixture_response<T>(
    accept: Option<&ExtractAccept>,
    headers: &HeaderMap,
    immutable: impl FnOnce(&T) -> bool,
    produce: impl FnOnce(
        &iroha_allocation::AllocationBudget,
        read::native::SccpNativeReadControl<'_>,
    )
        -> Result<read::native::SccpNativeDataV1<T>, read::native::SccpNativeReadError>,
) -> Response
where
    T: norito::json::JsonSerialize + norito::core::NoritoSerialize,
{
    let owner = crate::history_producer::HistoryProducerOwner::for_test();
    let stop = std::sync::atomic::AtomicBool::new(false);
    let control = read::native::SccpNativeReadControl {
        deadline: std::time::Instant::now() + std::time::Duration::from_secs(30),
        stop: &stop,
    };
    match produce(owner.cold_frames(), control) {
        Ok(value) => respond_funded(
            &owner,
            accept,
            headers,
            value.data(),
            immutable(value.data()),
        ),
        Err(error) => native::source_error(error),
    }
}

/// Current or explicit generation over one immutable view, with original graph custody.
#[cfg(test)]
pub fn committee_response(
    view: &(impl StateReadOnly + ?Sized),
    generation: Option<u64>,
    accept: Option<&ExtractAccept>,
) -> Response {
    let result = generation.map_or_else(
        || read::current_committee(view.world()),
        |generation| read::committee(view.world(), generation),
    );
    respond_result(accept, result)
}

/// `GET /v1/sccp/messages/{message_id}` over `view`; final states carry an `ETag`.
#[cfg(test)]
pub fn message_response(
    view: &(impl StateReadOnly + ?Sized),
    message_id: &str,
    accept: Option<&ExtractAccept>,
    headers: &HeaderMap,
) -> Response {
    let message_id = match parse_word(message_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    metadata_fixture_response(
        accept,
        headers,
        read::native::message_metadata::Message::is_final,
        |budget, control| {
            read::native::message_metadata::message(view, message_id, budget, control)
        },
    )
}

/// `GET /v1/sccp/messages/recent` over `view`.
#[cfg(test)]
pub fn recent_response(
    view: &(impl StateReadOnly + ?Sized),
    query: &RecentQuery,
    accept: Option<&ExtractAccept>,
) -> Response {
    let direction = match parse_direction(query.direction.as_deref()) {
        Ok(direction) => direction,
        Err(response) => return response,
    };
    let network = match query.network.as_deref().map(parse_network).transpose() {
        Ok(network) => network,
        Err(response) => return response,
    };
    let limit = match parse_number(query.limit.as_deref(), MAX_RECENT_MESSAGES) {
        Ok(limit) => limit,
        Err(response) => return response,
    };
    let before = match query
        .before
        .as_deref()
        .map(|cursor| read::native::message_metadata::recent_cursor(direction, cursor))
        .transpose()
    {
        Ok(before) => before,
        Err(error) => return native::source_error(error),
    };
    metadata_fixture_response(
        accept,
        &HeaderMap::new(),
        |_| false,
        |budget, control| {
            read::native::message_metadata::recent(
                view, direction, network, before, limit, budget, control,
            )
        },
    )
}

/// `GET /v1/sccp/outbound/{network}/{revision}` over `view`.
#[cfg(test)]
pub fn outbound_response(
    view: &(impl StateReadOnly + ?Sized),
    network: &str,
    revision: u32,
    query: &OutboundQuery,
    accept: Option<&ExtractAccept>,
) -> Response {
    let (network, from_nonce, limit) = match (
        parse_network(network),
        parse_number(query.from_nonce.as_deref(), 0_u64),
        parse_number(query.limit.as_deref(), MAX_OUTBOUND_PAGE),
    ) {
        (Ok(network), Ok(from_nonce), Ok(limit)) => (network, from_nonce, limit),
        (Err(response), _, _) | (_, Err(response), _) | (_, _, Err(response)) => return response,
    };
    metadata_fixture_response(
        accept,
        &HeaderMap::new(),
        |_| false,
        |budget, control| {
            read::native::message_metadata::outbound_page(
                view, network, revision, from_nonce, limit, budget, control,
            )
        },
    )
}

/// `GET /v1/sccp/controls/{network}/{revision}` over `view`.
#[cfg(test)]
pub fn controls_response(
    view: &(impl StateReadOnly + ?Sized),
    network: &str,
    revision: u32,
    query: &ControlsQuery,
    accept: Option<&ExtractAccept>,
) -> Response {
    let (network, after_nonce, limit) = match (
        parse_network(network),
        parse_number(query.after_nonce.as_deref(), 0_u64),
        parse_number(query.limit.as_deref(), MAX_CONTROLS_PAGE),
    ) {
        (Ok(network), Ok(after_nonce), Ok(limit)) => (network, after_nonce, limit),
        (Err(response), _, _) | (_, Err(response), _) | (_, _, Err(response)) => return response,
    };
    metadata_fixture_response(
        accept,
        &HeaderMap::new(),
        |_| false,
        |budget, control| {
            read::native::message_metadata::controls_page(
                view,
                network,
                revision,
                after_nonce,
                limit,
                budget,
                control,
            )
        },
    )
}

fn history_read_error(failure: read::SccpHistoryReadError) -> Response {
    use read::SccpHistoryReadError as Failure;
    match failure {
        Failure::MissingCommitment => error(
            StatusCode::NOT_FOUND,
            "sccp_not_found",
            "no SCCP commitment at the requested height",
        ),
        Failure::SizeOutOfRange | Failure::IndexOutOfRange => error(
            StatusCode::BAD_REQUEST,
            "sccp_invalid_query",
            failure.to_string(),
        ),
        Failure::Admission(_) | Failure::Backing(_) => {
            crate::native_projection_response::capacity().into_response()
        }
        Failure::Inconsistent | Failure::ForeignPool => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "sccp_history_inconsistent",
            "stored history cannot be served from its original owner",
        ),
    }
}

/// Encode directly from a borrowed funded graph; every returned byte retains the actual
/// admitted query owner, including a slice extracted after the HTTP body has been dropped.
fn respond_funded<T>(
    owner: &crate::history_producer::HistoryProducerOwner,
    accept: Option<&ExtractAccept>,
    headers: &HeaderMap,
    value: &T,
    immutable: bool,
) -> Response
where
    T: norito::json::JsonSerialize + norito::core::NoritoSerialize,
{
    use crate::utils::ResponseFormat;
    let selected = match format(accept) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let (content_type, bytes) = match selected {
        ResponseFormat::Norito => {
            let encoded = match owner
                .scope(|| norito::core::to_bytes_bounded(value, owner.response_bytes()))
            {
                Ok(bytes) => bytes,
                Err(_) => return crate::native_projection_response::capacity().into_response(),
            };
            (
                crate::utils::NORITO_MIME_TYPE,
                crate::response_memory_custody::owned(encoded, owner),
            )
        }
        ResponseFormat::Json => {
            let encoded = match owner
                .scope(|| norito::json::to_json_bounded_boxed(value, owner.response_bytes()))
            {
                Ok(bytes) => bytes,
                Err(_) => return crate::native_projection_response::capacity().into_response(),
            };
            (
                "application/json",
                crate::response_memory_custody::owned(encoded, owner),
            )
        }
    };
    let bytes = match bytes {
        Ok(bytes) => bytes,
        Err(_) => return crate::native_projection_response::capacity().into_response(),
    };
    let etag = immutable.then(|| format!("\"{}\"", blake3::hash(&bytes).to_hex()));
    let mut response = if etag
        .as_ref()
        .is_some_and(|etag| crate::utils::if_none_match_matches(headers, etag))
    {
        drop(bytes);
        // The encoded history has retired; this bodyless response owns no query data.
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        let mut response = match crate::response_memory_custody::json(bytes, owner) {
            Ok(response) => response,
            Err(_) => return crate::native_projection_response::capacity().into_response(),
        };
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
        response
    };
    if let Some(etag) = etag {
        validator_headers(&mut response, &etag);
    }
    response
}

/// `GET /v1/sccp/history/{height}?size=S` under its original query and application owners.
pub fn history_response(
    view: &(impl StateReadOnly + ?Sized),
    height: u64,
    query: &HistoryQuery,
    accept: Option<&ExtractAccept>,
    headers: &HeaderMap,
    (cache, cache_budget): (
        &mut read::SccpHistoryNodeCache,
        &iroha_allocation::AllocationBudget,
    ),
    owner: &crate::history_producer::HistoryProducerOwner,
) -> Response {
    let size = match query
        .size
        .as_deref()
        .map(|text| parse_number(Some(text), 0_u64))
        .transpose()
    {
        Ok(size) => size,
        Err(response) => return response,
    };
    let result = owner.scope(|| {
        read::history_path_view(
            view.world(),
            height,
            size,
            cache,
            cache_budget,
            owner.cold_frames(),
        )
    });
    match result {
        Ok(path) => respond_funded(owner, accept, headers, path.view(), size.is_some()),
        Err(failure) => history_read_error(failure),
    }
}

/// `GET /v1/sccp/light-clients/{network}` over `view`.
#[cfg(test)]
pub fn light_client_response(
    view: &(impl StateReadOnly + ?Sized),
    network: &str,
    accept: Option<&ExtractAccept>,
) -> Response {
    match parse_network(network) {
        Ok(network) => metadata_fixture_response(
            accept,
            &HeaderMap::new(),
            |_| false,
            |budget, control| {
                read::native::light_client_metadata::detail(view, network, budget, control)
            },
        ),
        Err(response) => response,
    }
}

/// `GET /v1/sccp/light-clients/{network}/checkpoints?covering=N` over `view`.
#[cfg(test)]
pub fn checkpoints_response(
    view: &(impl StateReadOnly + ?Sized),
    network: &str,
    query: &CoveringQuery,
    accept: Option<&ExtractAccept>,
) -> Response {
    let Some(covering) = query.covering.as_deref() else {
        return error(
            StatusCode::BAD_REQUEST,
            "sccp_invalid_query",
            "`covering` (a source height) is required",
        );
    };
    match (parse_network(network), parse_number(Some(covering), 0_u64)) {
        (Ok(network), Ok(covering)) => metadata_fixture_response(
            accept,
            &HeaderMap::new(),
            |_| false,
            |budget, control| {
                read::native::light_client_metadata::checkpoints(
                    view, network, covering, budget, control,
                )
            },
        ),
        (Err(response), _) | (_, Err(response)) => response,
    }
}

/// `GET /v1/sccp/governance/proposals/{proposal_id}` over `view`.
#[cfg(test)]
pub fn governance_proposal_response(
    view: &(impl StateReadOnly + ?Sized),
    proposal_id: &str,
    accept: Option<&ExtractAccept>,
) -> Response {
    let content_id = match parse_word(proposal_id) {
        Ok(content_id) => content_id,
        Err(response) => return response,
    };
    metadata_fixture_response(
        accept,
        &HeaderMap::new(),
        |_| false,
        |budget, control| {
            read::native::governance_metadata::proposal(view, content_id, budget, control)
        },
    )
}

// ---------------------------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------------------------

/// `GET /v1/sccp/history/{height}?size=`.
pub async fn handler_history(
    State(app): State<SharedAppState>,
    Path(height): Path<u64>,
    NoritoStringQuery(query): NoritoStringQuery<HistoryQuery>,
    headers: HeaderMap,
    accept: Option<ExtractAccept>,
) -> Response {
    let owner = match crate::history_producer::HistoryProducerOwner::current() {
        Ok(owner) => owner,
        Err(error) => return error.into_response(),
    };
    let mut cache = app
        .sccp_history
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    history_response(
        &app.state.view(),
        height,
        &query,
        accept.as_ref(),
        &headers,
        (&mut cache, &app.sccp_history_budget),
        &owner,
    )
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod response_custody_tests {
    use super::*;

    const WORKING: usize = 48_000_000;

    fn owner(
        pool: &crate::ByteWeightedMemoryPool,
    ) -> crate::history_producer::HistoryProducerOwner {
        let reservation = crate::QueryFanoutMemoryReservation::from_admitted_fanout(
            pool.try_acquire_parts([WORKING as u64]).unwrap(),
            crate::QueryFanoutMemoryEnvelope::for_body_admission(WORKING).unwrap(),
            pool.generation(),
        )
        .unwrap();
        crate::history_producer::HistoryProducerOwner::from_reservation(&reservation).unwrap()
    }

    #[tokio::test]
    async fn conditional_history_response_releases_retired_query_data() {
        let pool = crate::ByteWeightedMemoryPool::new(WORKING).unwrap();
        let owner = owner(&pool);
        let response = respond_funded(&owner, None, &HeaderMap::new(), &17_u64, true);
        let etag = response.headers().get(header::ETAG).unwrap().clone();
        drop(response);
        let mut headers = HeaderMap::new();
        headers.insert(header::IF_NONE_MATCH, etag.clone());
        let response = respond_funded(&owner, None, &headers, &17_u64, true);
        assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(response.headers().get(header::ETAG), Some(&etag));
        drop(owner);
        assert!(
            pool.try_acquire_parts([WORKING as u64]).is_some(),
            "a bodyless validator response must not retain the retired query"
        );
        assert!(
            axum::body::to_bytes(response.into_body(), 0)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn unsupported_history_representation_releases_query_but_preserves_typed_error() {
        let pool = crate::ByteWeightedMemoryPool::new(WORKING).unwrap();
        let owner = owner(&pool);
        let accept = ExtractAccept(HeaderValue::from_static("text/plain"));
        let response = respond_funded(&owner, Some(&accept), &HeaderMap::new(), &17_u64, false);
        assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);
        drop(owner);
        assert!(
            pool.try_acquire_parts([WORKING as u64]).is_some(),
            "negotiation errors have no retained history backing"
        );
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let error: Value = norito::json::from_slice(&body).unwrap();
        assert_eq!(
            error.get("code").and_then(Value::as_str),
            Some("response_not_acceptable")
        );
    }
}
