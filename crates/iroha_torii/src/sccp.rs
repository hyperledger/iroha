//! SCCP v1 public read API (`specs/sccp.md` §6).
//!
//! Every honest peer serves identical bytes derived only from committed state; wallets and
//! destinations never trust them and verify every bundle themselves. Responses are Norito or
//! JSON by `Accept`. Proof routes answer `409 sccp_attestation_pending` until the chosen
//! subject is attested and `410 sccp_pruned` once its signatures were pruned by retention; the
//! checkpoint cover answers `410` when the head covers the height but no checkpoint at or above
//! it is retained. Immutable responses (proof bundles, history paths of an explicit size and
//! final message states) carry a strong `ETag` over the selected representation and answer a
//! matching `If-None-Match` with `304`.
//!
//! Each handler is a thin extractor over a `*_response` function of a state view, so the
//! seeded-state tests exercise exactly what the routes serve.
//!
//! TODO(ws35): attestation and bridge-key views (being redesigned), the remaining §6 governance
//! targets (`/proposals?status&after` filters, diffs, readiness), and the Kura fallback for
//! pruned signatures.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse as _, Response},
};
use iroha_core::{
    smartcontracts::isi::sccp::{
        read::{
            self, MAX_CONTROLS_PAGE, MAX_OUTBOUND_PAGE, MAX_RECENT_MESSAGES,
            SccpAttestationChoiceV1, SccpDirectionV1, SccpReadError,
        },
        store,
    },
    state::{StateReadOnly, WorldReadOnly},
};
use iroha_data_model::bridge::SccpNetworkV1;
use norito::json::{Map, Value};

// The query DTOs keep every value as its decimal or keyword text and parse it in the handler, so
// they are extracted without scalar coercion (`NoritoStringQuery`): a coercing extractor would
// turn `?from_nonce=1` into a JSON number that an `Option<String>` field refuses.
use crate::{JsonBody, NoritoStringQuery, SharedAppState, utils::extractors::ExtractAccept};

/// `?attestation=own|latest|<height>` of the proof routes (default `own`).
#[derive(Debug, Default, Clone, crate::json_macros::JsonDeserialize)]
pub(crate) struct AttestationQuery {
    /// Which subject attests the leaf.
    #[norito(default)]
    pub attestation: Option<String>,
}

/// `?after_generation=G&limit=N` of the rotation-chain route (decimal strings).
#[derive(Debug, Default, Clone, crate::json_macros::JsonDeserialize)]
pub(crate) struct RotationQuery {
    /// Generation to rotate from (default 1).
    #[norito(default)]
    pub after_generation: Option<String>,
    /// Page size, at most 16.
    #[norito(default)]
    pub limit: Option<String>,
}

/// `?direction=outbound|inbound&network=&before=&limit=` of the recent-messages route.
#[derive(Debug, Default, Clone, crate::json_macros::JsonDeserialize)]
pub(crate) struct RecentQuery {
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
pub(crate) struct OutboundQuery {
    /// First nonce (default 0).
    #[norito(default)]
    pub from_nonce: Option<String>,
    /// Page size, at most 256.
    #[norito(default)]
    pub limit: Option<String>,
}

/// `?after_nonce=&limit=` of the controls route.
#[derive(Debug, Default, Clone, crate::json_macros::JsonDeserialize)]
pub(crate) struct ControlsQuery {
    /// Controls above this nonce (default 0: every control).
    #[norito(default)]
    pub after_nonce: Option<String>,
    /// Page size, at most 64.
    #[norito(default)]
    pub limit: Option<String>,
}

/// `?covering=N` of the checkpoint route.
#[derive(Debug, Default, Clone, crate::json_macros::JsonDeserialize)]
pub(crate) struct CoveringQuery {
    /// Source height to anchor (required).
    #[norito(default)]
    pub covering: Option<String>,
}

/// `?size=S` of the history route.
#[derive(Debug, Default, Clone, crate::json_macros::JsonDeserialize)]
pub(crate) struct HistoryQuery {
    /// History size (default: the current size).
    #[norito(default)]
    pub size: Option<String>,
}

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

fn read_error(read: &SccpReadError) -> Response {
    match read {
        SccpReadError::NotFound(_) => {
            error(StatusCode::NOT_FOUND, "sccp_not_found", read.to_string())
        }
        SccpReadError::Pending(_) => error(
            StatusCode::CONFLICT,
            "sccp_attestation_pending",
            read.to_string(),
        ),
        SccpReadError::Pruned(_) => error(StatusCode::GONE, "sccp_pruned", read.to_string()),
        SccpReadError::Invalid(_) => error(
            StatusCode::BAD_REQUEST,
            "sccp_invalid_query",
            read.to_string(),
        ),
    }
}

fn format(accept: Option<&ExtractAccept>) -> Result<crate::utils::ResponseFormat, Response> {
    crate::utils::negotiate_response_format(accept.map(|value| &value.0))
}

fn respond<T>(accept: Option<&ExtractAccept>, value: T) -> Response
where
    T: norito::json::JsonSerialize + norito::core::NoritoSerialize + 'static,
{
    match format(accept) {
        Ok(format) => crate::utils::respond_with_format(value, format),
        Err(response) => response,
    }
}

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

fn parse_choice(query: &AttestationQuery) -> Result<SccpAttestationChoiceV1, Response> {
    query
        .attestation
        .as_deref()
        .map_or(Ok(SccpAttestationChoiceV1::Own), |text| {
            SccpAttestationChoiceV1::parse(text).ok_or_else(|| {
                error(
                    StatusCode::BAD_REQUEST,
                    "sccp_invalid_query",
                    "attestation must be `own`, `latest` or a height",
                )
            })
        })
}

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

/// `GET /v1/sccp/capabilities` over `view`, listing this release's SCCP path templates.
pub(crate) fn capabilities_response(
    view: &(impl StateReadOnly + ?Sized),
    accept: Option<&ExtractAccept>,
) -> Response {
    let mut capabilities = read::capabilities(view);
    capabilities.path_templates = iroha_torii_shared::route_catalog::sccp::ROUTES
        .iter()
        .map(|route| route.path().to_owned())
        .collect();
    respond(accept, capabilities)
}

/// `GET /v1/sccp/messages/{message_id}` over `view`; final states carry an `ETag`.
pub(crate) fn message_response(
    view: &(impl StateReadOnly + ?Sized),
    message_id: &str,
    accept: Option<&ExtractAccept>,
    headers: &HeaderMap,
) -> Response {
    let message_id = match parse_word(message_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    let status = read::message_status(view.world(), &message_id);
    if status.is_final() {
        respond_immutable(accept, headers, status)
    } else {
        respond(accept, status)
    }
}

/// `GET /v1/sccp/messages/recent` over `view`.
pub(crate) fn recent_response(
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
    respond_result(
        accept,
        read::recent_messages(
            view.world(),
            direction,
            network,
            query.before.as_deref(),
            limit,
        ),
    )
}

/// `GET /v1/sccp/outbound/{network}/{revision}` over `view`.
pub(crate) fn outbound_response(
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
    respond_result(
        accept,
        read::outbound_page(view.world(), network, revision, from_nonce, limit),
    )
}

/// `GET /v1/sccp/controls/{network}/{revision}` over `view`.
pub(crate) fn controls_response(
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
    respond_result(
        accept,
        read::controls_page(view.world(), network, revision, after_nonce, limit),
    )
}

/// `GET /v1/sccp/messages/{message_id}/proof` over `view` (`ETag`ged).
pub(crate) fn message_proof_response(
    view: &(impl StateReadOnly + ?Sized),
    message_id: &str,
    query: &AttestationQuery,
    accept: Option<&ExtractAccept>,
    headers: &HeaderMap,
) -> Response {
    let (message_id, choice) = match (parse_word(message_id), parse_choice(query)) {
        (Ok(id), Ok(choice)) => (id, choice),
        (Err(response), _) | (_, Err(response)) => return response,
    };
    match read::message_proof(view, &message_id, choice) {
        Ok(bundle) => respond_immutable(accept, headers, bundle),
        Err(failure) => read_error(&failure),
    }
}

/// `GET /v1/sccp/controls/{network}/{revision}/{control_nonce}/proof` over `view`
/// (`ETag`ged).
pub(crate) fn control_proof_response(
    view: &(impl StateReadOnly + ?Sized),
    (network, revision, control_nonce): (&str, u32, u64),
    query: &AttestationQuery,
    accept: Option<&ExtractAccept>,
    headers: &HeaderMap,
) -> Response {
    let (network, choice) = match (parse_network(network), parse_choice(query)) {
        (Ok(network), Ok(choice)) => (network, choice),
        (Err(response), _) | (_, Err(response)) => return response,
    };
    match read::control_proof(view, network, revision, control_nonce, choice) {
        Ok(bundle) => respond_immutable(accept, headers, bundle),
        Err(failure) => read_error(&failure),
    }
}

/// `GET /v1/sccp/history/{height}?size=S` over `view`; an explicit size is `ETag`ged.
pub(crate) fn history_response(
    view: &(impl StateReadOnly + ?Sized),
    height: u64,
    query: &HistoryQuery,
    accept: Option<&ExtractAccept>,
    headers: &HeaderMap,
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
    match read::history_path_view(view.world(), height, size) {
        Ok(path) if size.is_some() => respond_immutable(accept, headers, path),
        Ok(path) => respond(accept, path),
        Err(failure) => read_error(&failure),
    }
}

/// `GET /v1/sccp/light-clients/{network}` over `view`.
pub(crate) fn light_client_response(
    view: &(impl StateReadOnly + ?Sized),
    network: &str,
    accept: Option<&ExtractAccept>,
) -> Response {
    match parse_network(network) {
        Ok(network) => respond_result(accept, read::light_client_detail(view, network)),
        Err(response) => response,
    }
}

/// `GET /v1/sccp/light-clients/{network}/checkpoints?covering=N` over `view`.
pub(crate) fn checkpoints_response(
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
        (Ok(network), Ok(covering)) => respond_result(
            accept,
            read::checkpoint_cover(view.world(), network, covering),
        ),
        (Err(response), _) | (_, Err(response)) => response,
    }
}

/// `GET /v1/sccp/governance/proposals/{proposal_id}` over `view`.
pub(crate) fn governance_proposal_response(
    view: &(impl StateReadOnly + ?Sized),
    proposal_id: &str,
    accept: Option<&ExtractAccept>,
) -> Response {
    match parse_word(proposal_id) {
        Ok(content_id) => {
            respond_result(accept, read::governance_proposal(view.world(), content_id))
        }
        Err(response) => response,
    }
}

fn roster_response(
    world: &(impl WorldReadOnly + ?Sized),
    network_id: &[u8; 32],
    generation: u64,
    accept: Option<&ExtractAccept>,
) -> Response {
    match read::roster_view(world, network_id, generation) {
        Some(roster) => respond(accept, roster),
        None => read_error(&SccpReadError::NotFound(format!("generation {generation}"))),
    }
}

// ---------------------------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------------------------

/// `GET /v1/sccp/capabilities`.
pub(crate) async fn handler_capabilities(
    State(app): State<SharedAppState>,
    accept: Option<ExtractAccept>,
) -> Response {
    capabilities_response(&app.state.view(), accept.as_ref())
}

/// `GET /v1/sccp/registry`: every route with its escrow, stranded balance and revisions.
pub(crate) async fn handler_registry(
    State(app): State<SharedAppState>,
    accept: Option<ExtractAccept>,
) -> Response {
    let routes: Vec<_> = {
        let view = app.state.view();
        store::routes::iter(view.world())
            .map(|(_, route)| route.clone())
            .collect()
    };
    respond(accept.as_ref(), routes)
}

/// `GET /v1/sccp/messages/{message_id}`: the outbound, inbound or unknown status union.
pub(crate) async fn handler_message(
    State(app): State<SharedAppState>,
    Path(message_id): Path<String>,
    headers: HeaderMap,
    accept: Option<ExtractAccept>,
) -> Response {
    message_response(&app.state.view(), &message_id, accept.as_ref(), &headers)
}

/// `GET /v1/sccp/messages/recent?direction=&network=&before=&limit=`.
pub(crate) async fn handler_messages_recent(
    State(app): State<SharedAppState>,
    NoritoStringQuery(query): NoritoStringQuery<RecentQuery>,
    accept: Option<ExtractAccept>,
) -> Response {
    recent_response(&app.state.view(), &query, accept.as_ref())
}

/// `GET /v1/sccp/outbound/{network}/{revision}?from_nonce=&limit=`.
pub(crate) async fn handler_outbound(
    State(app): State<SharedAppState>,
    Path((network, revision)): Path<(String, u32)>,
    NoritoStringQuery(query): NoritoStringQuery<OutboundQuery>,
    accept: Option<ExtractAccept>,
) -> Response {
    outbound_response(
        &app.state.view(),
        &network,
        revision,
        &query,
        accept.as_ref(),
    )
}

/// `GET /v1/sccp/controls/{network}/{revision}?after_nonce=&limit=`.
pub(crate) async fn handler_controls(
    State(app): State<SharedAppState>,
    Path((network, revision)): Path<(String, u32)>,
    NoritoStringQuery(query): NoritoStringQuery<ControlsQuery>,
    accept: Option<ExtractAccept>,
) -> Response {
    controls_response(
        &app.state.view(),
        &network,
        revision,
        &query,
        accept.as_ref(),
    )
}

/// `GET /v1/sccp/messages/{message_id}/proof?attestation=`.
pub(crate) async fn handler_message_proof(
    State(app): State<SharedAppState>,
    Path(message_id): Path<String>,
    NoritoStringQuery(query): NoritoStringQuery<AttestationQuery>,
    headers: HeaderMap,
    accept: Option<ExtractAccept>,
) -> Response {
    message_proof_response(
        &app.state.view(),
        &message_id,
        &query,
        accept.as_ref(),
        &headers,
    )
}

/// `GET /v1/sccp/controls/{network}/{revision}/{control_nonce}/proof?attestation=`.
pub(crate) async fn handler_control_proof(
    State(app): State<SharedAppState>,
    Path((network, revision, control_nonce)): Path<(String, u32, u64)>,
    NoritoStringQuery(query): NoritoStringQuery<AttestationQuery>,
    headers: HeaderMap,
    accept: Option<ExtractAccept>,
) -> Response {
    control_proof_response(
        &app.state.view(),
        (&network, revision, control_nonce),
        &query,
        accept.as_ref(),
        &headers,
    )
}

/// `GET /v1/sccp/history/{height}?size=`.
pub(crate) async fn handler_history(
    State(app): State<SharedAppState>,
    Path(height): Path<u64>,
    NoritoStringQuery(query): NoritoStringQuery<HistoryQuery>,
    headers: HeaderMap,
    accept: Option<ExtractAccept>,
) -> Response {
    history_response(&app.state.view(), height, &query, accept.as_ref(), &headers)
}

/// `GET /v1/sccp/light-clients`: every installed light client with its head and freeze state.
pub(crate) async fn handler_light_clients(
    State(app): State<SharedAppState>,
    accept: Option<ExtractAccept>,
) -> Response {
    let light_clients = read::light_clients(app.state.view().world());
    respond(accept.as_ref(), light_clients)
}

/// `GET /v1/sccp/light-clients/{network}`: one light client with its freshness and stored data.
pub(crate) async fn handler_light_client(
    State(app): State<SharedAppState>,
    Path(network): Path<String>,
    accept: Option<ExtractAccept>,
) -> Response {
    light_client_response(&app.state.view(), &network, accept.as_ref())
}

/// `GET /v1/sccp/light-clients/{network}/sets`: the stored consensus sets of one light client.
pub(crate) async fn handler_light_client_sets(
    State(app): State<SharedAppState>,
    Path(network): Path<String>,
    accept: Option<ExtractAccept>,
) -> Response {
    match parse_network(&network) {
        Ok(network) => respond(
            accept.as_ref(),
            read::light_client_sets(app.state.view().world(), network),
        ),
        Err(response) => response,
    }
}

/// `GET /v1/sccp/light-clients/{network}/checkpoints?covering=N`.
pub(crate) async fn handler_light_client_checkpoints(
    State(app): State<SharedAppState>,
    Path(network): Path<String>,
    NoritoStringQuery(query): NoritoStringQuery<CoveringQuery>,
    accept: Option<ExtractAccept>,
) -> Response {
    checkpoints_response(&app.state.view(), &network, &query, accept.as_ref())
}

/// `GET /v1/sccp/governance`: the nonzero per-subject governance revisions.
pub(crate) async fn handler_governance(
    State(app): State<SharedAppState>,
    accept: Option<ExtractAccept>,
) -> Response {
    let revisions = read::governance_revisions(app.state.view().world());
    respond(accept.as_ref(), revisions)
}

/// `GET /v1/sccp/governance/proposals`: every open SCCP proposal, oldest first, with its
/// admissibility and newest Parliament attempt.
pub(crate) async fn handler_governance_proposals(
    State(app): State<SharedAppState>,
    accept: Option<ExtractAccept>,
) -> Response {
    let proposals = read::governance_proposals(app.state.view().world());
    respond(accept.as_ref(), proposals)
}

/// `GET /v1/sccp/governance/proposals/{proposal_id}`: one SCCP proposal in any phase.
pub(crate) async fn handler_governance_proposal(
    State(app): State<SharedAppState>,
    Path(proposal_id): Path<String>,
    accept: Option<ExtractAccept>,
) -> Response {
    governance_proposal_response(&app.state.view(), &proposal_id, accept.as_ref())
}

/// `GET /v1/sccp/rosters/current`.
pub(crate) async fn handler_roster_current(
    State(app): State<SharedAppState>,
    accept: Option<ExtractAccept>,
) -> Response {
    let view = app.state.view();
    let generation = *store::roster_current::get(view.world());
    match read::roster_view(view.world(), view.network_id().as_bytes(), generation) {
        Some(roster) => respond(accept.as_ref(), roster),
        None => read_error(&SccpReadError::NotFound("no roster generation yet".into())),
    }
}

/// `GET /v1/sccp/rosters/{generation}`.
pub(crate) async fn handler_roster(
    State(app): State<SharedAppState>,
    Path(generation): Path<u64>,
    accept: Option<ExtractAccept>,
) -> Response {
    let view = app.state.view();
    roster_response(
        view.world(),
        view.network_id().as_bytes(),
        generation,
        accept.as_ref(),
    )
}

/// `GET /v1/sccp/rosters/rotations?after_generation=&limit=`.
pub(crate) async fn handler_rotations(
    State(app): State<SharedAppState>,
    NoritoStringQuery(query): NoritoStringQuery<RotationQuery>,
    accept: Option<ExtractAccept>,
) -> Response {
    let (after_generation, limit) = match (
        parse_number(query.after_generation.as_deref(), 1_u64),
        parse_number(query.limit.as_deref(), read::MAX_ROTATION_STEPS),
    ) {
        (Ok(after_generation), Ok(limit)) => (after_generation, limit),
        (Err(response), _) | (_, Err(response)) => return response,
    };
    let chain = read::rotation_chain(&app.state.view(), after_generation, limit);
    respond(accept.as_ref(), chain)
}

#[cfg(test)]
mod tests;
