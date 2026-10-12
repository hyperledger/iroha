//! Original native certificate DATA under one admitted request and destination-independent source.

use std::{net::SocketAddr, num::NonZeroU64, sync::atomic::Ordering, time::Instant};

use axum::{
    Extension,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
};
use iroha_core::smartcontracts::isi::sccp::read::native::{
    self as read, MAX_NATIVE_ROTATIONS, SccpNativeDataV1, SccpNativeProofAt, SccpNativeReadControl,
    SccpNativeReadError,
};
use iroha_data_model::bridge::SccpNetworkV1;
use iroha_torii_shared::route_catalog::{RouteDescriptor, sccp};

use crate::{
    Error, NoritoStringQuery, SharedAppState,
    finality_interval::{PreparedResponse, RouteExecutionDeadline},
    history_producer::HistoryProducerOwner,
    native_projection_response,
    utils::ResponseFormat,
};

/// `at=record|latest|<height>`; absent selects the record's own committed height.
#[derive(Debug, Default, Clone, crate::json_macros::JsonDeserialize)]
pub(crate) struct ProofQuery {
    #[norito(default)]
    /// Explicit certificate selector, without scalar JSON coercion.
    pub at: Option<String>,
}

/// Catch-up starts with the destination's current generation's outgoing transition.
#[derive(Debug, Default, Clone, crate::json_macros::JsonDeserialize)]
pub(crate) struct RotationsQuery {
    #[norito(default)]
    /// Destination current generation; the first handoff is signed by this generation.
    pub after_generation: Option<String>,
    #[norito(default)]
    /// Bounded transition count (default 16).
    pub limit: Option<String>,
}

#[derive(Debug, Clone, Copy)]
enum Selection {
    Message {
        id: [u8; 32],
        at: SccpNativeProofAt,
    },
    Control {
        network: SccpNetworkV1,
        revision: u32,
        nonce: u64,
        at: SccpNativeProofAt,
    },
    Finality(Option<NonZeroU64>),
    Committee(Option<NonZeroU64>),
    Rotations {
        after: u64,
        limit: usize,
    },
}

impl Selection {
    fn route(self) -> RouteDescriptor {
        match self {
            Self::Message { .. } => sccp::MESSAGE_PROOF,
            Self::Control { .. } => sccp::CONTROL_PROOF,
            Self::Finality(_) => sccp::FINALITY,
            Self::Committee(None) => sccp::CURRENT_COMMITTEE,
            Self::Committee(Some(_)) => sccp::COMMITTEE,
            Self::Rotations { .. } => sccp::COMMITTEE_ROTATIONS,
        }
    }

    fn immutable(self) -> bool {
        matches!(
            self,
            Self::Finality(Some(_))
                | Self::Message {
                    at: SccpNativeProofAt::Height(_),
                    ..
                }
                | Self::Control {
                    at: SccpNativeProofAt::Height(_),
                    ..
                }
        )
    }
}

fn invalid(message: &'static str) -> Response {
    super::error(StatusCode::BAD_REQUEST, "sccp_invalid_query", message)
}

fn decimal(text: &str) -> Result<u64, Response> {
    text.parse::<u64>()
        .ok()
        .filter(|value| value.to_string() == text)
        .ok_or_else(|| invalid("selector must be a canonical decimal u64"))
}

fn certificate_height(text: &str) -> Result<NonZeroU64, Response> {
    decimal(text).and_then(|height| {
        NonZeroU64::new(height)
            .filter(|h| h.get() >= 2)
            .ok_or_else(|| invalid("a Commit certificate requires a non-genesis height"))
    })
}

fn generation_number(text: &str) -> Result<NonZeroU64, Response> {
    decimal(text).and_then(|number| {
        NonZeroU64::new(number).ok_or_else(|| invalid("generation must be nonzero"))
    })
}

fn proof_at(text: Option<&str>) -> Result<SccpNativeProofAt, Response> {
    match text.unwrap_or("record") {
        "record" => Ok(SccpNativeProofAt::Record),
        "latest" => Ok(SccpNativeProofAt::Latest),
        height => certificate_height(height).map(SccpNativeProofAt::Height),
    }
}

fn finality_at(text: &str) -> Result<Option<NonZeroU64>, Response> {
    match text {
        "latest" => Ok(None),
        height => certificate_height(height).map(Some),
    }
}

fn rotations(query: &RotationsQuery) -> Result<Selection, Response> {
    let after = query
        .after_generation
        .as_deref()
        .ok_or_else(|| invalid("after_generation is required"))
        .and_then(decimal)?;
    if after == 0 {
        return Err(invalid("after_generation must be nonzero"));
    }
    let limit = query
        .limit
        .as_deref()
        .map(decimal)
        .transpose()?
        .unwrap_or(MAX_NATIVE_ROTATIONS as u64);
    if !(1..=MAX_NATIVE_ROTATIONS as u64).contains(&limit) {
        return Err(invalid("limit must be between 1 and 16"));
    }
    Ok(Selection::Rotations {
        after,
        limit: limit as usize,
    })
}

fn source_error(error: SccpNativeReadError) -> Response {
    use iroha_core::sumeragi::finality::NativeCommitCertificateReadErrorV1;
    use iroha_data_model::sumeragi_finality::{
        CommitmentError, certified_result::CertifiedResultError,
    };
    let (status, code) = match &error {
        SccpNativeReadError::Request(_) => (StatusCode::BAD_REQUEST, "sccp_invalid_query"),
        SccpNativeReadError::NotFound(_) => (StatusCode::NOT_FOUND, "sccp_not_found"),
        SccpNativeReadError::Pruned(_) => (StatusCode::GONE, "sccp_pruned"),
        SccpNativeReadError::UnsupportedScope => {
            (StatusCode::SERVICE_UNAVAILABLE, "route_unavailable")
        }
        SccpNativeReadError::Deadline
        | SccpNativeReadError::Cancelled
        | SccpNativeReadError::Source(NativeCommitCertificateReadErrorV1::Deadline) => {
            (StatusCode::REQUEST_TIMEOUT, "request_timeout")
        }
        SccpNativeReadError::Allocation(_)
        | SccpNativeReadError::PhysicalAllocation
        | SccpNativeReadError::DecodeResource(_)
        | SccpNativeReadError::Source(NativeCommitCertificateReadErrorV1::Allocation)
        | SccpNativeReadError::CertifiedResult(CertifiedResultError::Body(
            CommitmentError::Resource(_),
        )) => (StatusCode::SERVICE_UNAVAILABLE, "sccp_capacity"),
        SccpNativeReadError::Source(NativeCommitCertificateReadErrorV1::Frame(frame))
            if frame.decode_resource_error().is_some() =>
        {
            (StatusCode::SERVICE_UNAVAILABLE, "sccp_capacity")
        }
        // No local source failure or unimplemented source is evidence of pruning or absence.
        _ => (StatusCode::SERVICE_UNAVAILABLE, "sccp_unavailable"),
    };
    let mut response = super::error(status, code, error.to_string());
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response
}

fn stopped(control: SccpNativeReadControl<'_>, format: ResponseFormat) -> Option<PreparedResponse> {
    (Instant::now() >= control.deadline || control.stop.load(Ordering::Acquire)).then(|| {
        PreparedResponse {
            response: crate::route_timeout_error_response(format),
            bytes: 0,
        }
    })
}

fn encode<T: norito::core::NoritoSerialize + norito::json::JsonSerialize>(
    data: SccpNativeDataV1<T>,
    owner: &HistoryProducerOwner,
    format: ResponseFormat,
    maximum: usize,
    immutable: bool,
    headers: &HeaderMap,
) -> Result<PreparedResponse, Error> {
    let response = encode_value(data.data(), owner, format, maximum, immutable, headers);
    // Every source DTO allocation is destroyed before its same-pool charge is released.
    drop(data);
    response
}

fn encode_value<T: norito::core::NoritoSerialize + norito::json::JsonSerialize>(
    value: &T,
    owner: &HistoryProducerOwner,
    format: ResponseFormat,
    maximum: usize,
    immutable: bool,
    headers: &HeaderMap,
) -> Result<PreparedResponse, Error> {
    let encoded = owner.scope(|| {
        native_projection_response::encode(
            value,
            format,
            maximum.min(owner.response_bytes()),
            owner.cold_frames(),
            native_projection_response::capacity,
        )
    })?;
    let etag = immutable.then(|| format!("\"{}\"", blake3::hash(encoded.as_ref()).to_hex()));
    if let Some(etag) = etag.as_ref()
        && crate::utils::if_none_match_matches(headers, etag)
    {
        use axum::response::IntoResponse as _;
        drop(encoded);
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        super::validator_headers(&mut response, etag);
        return Ok(PreparedResponse { response, bytes: 0 });
    }
    let bytes = encoded.as_ref().len();
    let body = crate::response_memory_custody::owned(encoded, owner)
        .map_err(|_| native_projection_response::capacity())?;
    let mut response = crate::response_memory_custody::json(body, owner)
        .map_err(|_| native_projection_response::capacity())?;
    if matches!(format, ResponseFormat::Norito) {
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(crate::utils::NORITO_MIME_TYPE),
        );
    }
    if let Some(etag) = etag.as_ref() {
        super::validator_headers(&mut response, etag);
    } else {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        crate::append_vary_accept(response.headers_mut());
    }
    Ok(PreparedResponse { response, bytes })
}

async fn serve(
    app: SharedAppState,
    selection: Selection,
    deadline: Instant,
    headers: HeaderMap,
    remote: SocketAddr,
) -> Result<Response, Error> {
    let principal = crate::validate_api_token(app.as_ref(), &headers)?.authenticated_principal();
    let format = match crate::negotiate_heavy_query_response_format(&headers) {
        Ok(format) => format,
        Err(response) => return Ok(response),
    };
    if Instant::now() >= deadline {
        return Ok(crate::route_timeout_error_response(format));
    }
    let route = selection.route();
    let key = crate::rate_limit_key(&headers, Some(remote.ip()), route.path(), principal);
    crate::rate_limit_requests_with_cost(&app, &key, crate::FINALITY_HEAVY_QUERY_RATE_COST).await?;
    let mut admission = crate::acquire_query_admission(app.as_ref(), true).await?;
    if admission._fanout_memory.is_none() {
        admission._fanout_memory = Some(match crate::try_acquire_new_query_fanout_memory(&app) {
            Ok(reservation) => reservation,
            Err(response) => return Ok(response),
        });
    }
    let owner = HistoryProducerOwner::from_admission(&admission)?;
    let state = app.state.clone();
    let maximum = app
        .torii_proxy_max_response_bytes
        .min(owner.response_bytes());
    let request_headers = headers.clone();
    let prepared = crate::finality_interval::run_with_stop(admission, owner, move |owner, stop| {
        let control = SccpNativeReadControl {
            deadline,
            stop: &stop,
        };
        if let Some(response) = stopped(control, format) {
            return Ok(response);
        }
        let output = owner.scope(|| {
            read::with_state_view(&state, control, |view| {
                let budget = owner.cold_frames();
                // Encode while original response DATA and its reservation are still retained.
                Ok(match selection {
                    Selection::Committee(generation) => encode_value(
                        &match generation {
                            None => read::current_committee(view, control)?,
                            Some(generation) => read::committee(view, generation, control)?,
                        },
                        &owner,
                        format,
                        maximum,
                        false, // Even an ended generation has mutable current-view liability.
                        &request_headers,
                    ),
                    Selection::Finality(height) => encode(
                        read::finality(view, height, budget, control)?,
                        &owner,
                        format,
                        maximum,
                        selection.immutable(),
                        &request_headers,
                    ),
                    Selection::Message { id, at } => encode(
                        read::message_proof(view, id, at, budget, control)?,
                        &owner,
                        format,
                        maximum,
                        selection.immutable(),
                        &request_headers,
                    ),
                    Selection::Control {
                        network,
                        revision,
                        nonce,
                        at,
                    } => encode(
                        read::control_proof(view, network, revision, nonce, at, budget, control)?,
                        &owner,
                        format,
                        maximum,
                        selection.immutable(),
                        &request_headers,
                    ),
                    Selection::Rotations { after, limit } => encode(
                        read::committee_rotations(view, after, limit, budget, control)?,
                        &owner,
                        format,
                        maximum,
                        false,
                        &request_headers,
                    ),
                })
            })
        });
        if let Some(response) = stopped(control, format) {
            return Ok(response);
        }
        match output {
            Ok(response) => response,
            Err(error) => Ok(PreparedResponse {
                response: source_error(error),
                bytes: 0,
            }),
        }
    })
    .await?;
    crate::enforce_proof_egress(
        app.as_ref(),
        &headers,
        Some(remote.ip()),
        route.stable_route_id(),
        u64::try_from(prepared.bytes).map_err(|_| native_projection_response::capacity())?,
        true,
    )
    .await?;
    Ok(prepared.response)
}

/// Full current committee DATA from the captured committed view, never a trust pin.
pub(crate) async fn handler_current_committee(
    State(app): State<SharedAppState>,
    Extension(RouteExecutionDeadline(deadline)): Extension<RouteExecutionDeadline>,
    headers: HeaderMap,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Result<Response, Error> {
    serve(app, Selection::Committee(None), deadline, headers, remote).await
}

/// One retained generation with liability computed from that same committed view.
pub(crate) async fn handler_committee(
    State(app): State<SharedAppState>,
    Path(generation): Path<String>,
    Extension(RouteExecutionDeadline(deadline)): Extension<RouteExecutionDeadline>,
    headers: HeaderMap,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Result<Response, Error> {
    match generation_number(&generation) {
        Ok(generation) => {
            serve(
                app,
                Selection::Committee(Some(generation)),
                deadline,
                headers,
                remote,
            )
            .await
        }
        Err(response) => Ok(response),
    }
}

/// Native original certificate at one explicit height or the durable tip.
pub(crate) async fn handler_finality(
    State(app): State<SharedAppState>,
    Path(height): Path<String>,
    Extension(RouteExecutionDeadline(deadline)): Extension<RouteExecutionDeadline>,
    headers: HeaderMap,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Result<Response, Error> {
    match finality_at(&height) {
        Ok(height) => serve(app, Selection::Finality(height), deadline, headers, remote).await,
        Err(response) => Ok(response),
    }
}

/// Native proof of one outbound record, retaining its canonical payload.
pub(crate) async fn handler_message_proof(
    State(app): State<SharedAppState>,
    Path(id): Path<String>,
    NoritoStringQuery(query): NoritoStringQuery<ProofQuery>,
    Extension(RouteExecutionDeadline(deadline)): Extension<RouteExecutionDeadline>,
    headers: HeaderMap,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Result<Response, Error> {
    match (super::parse_word(&id), proof_at(query.at.as_deref())) {
        (Ok(id), Ok(at)) => {
            serve(
                app,
                Selection::Message { id, at },
                deadline,
                headers,
                remote,
            )
            .await
        }
        (Err(response), _) | (_, Err(response)) => Ok(response),
    }
}

/// Native proof of a control record; an unavailable native producer refuses explicitly.
pub(crate) async fn handler_control_proof(
    State(app): State<SharedAppState>,
    Path((network, revision, nonce)): Path<(String, String, String)>,
    NoritoStringQuery(query): NoritoStringQuery<ProofQuery>,
    Extension(RouteExecutionDeadline(deadline)): Extension<RouteExecutionDeadline>,
    headers: HeaderMap,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Result<Response, Error> {
    let selection = (|| {
        let network = super::parse_network(&network)?;
        let revision = u32::try_from(decimal(&revision)?)
            .ok()
            .filter(|v| *v != 0)
            .ok_or_else(|| invalid("revision must be a nonzero u32"))?;
        let nonce = decimal(&nonce)?;
        let at = proof_at(query.at.as_deref())?;
        Ok(Selection::Control {
            network,
            revision,
            nonce,
            at,
        })
    })();
    match selection {
        Ok(selection) => serve(app, selection, deadline, headers, remote).await,
        Err(response) => Ok(response),
    }
}

/// Ordered original certificates for the destination's current generation catch-up.
pub(crate) async fn handler_rotations(
    State(app): State<SharedAppState>,
    NoritoStringQuery(query): NoritoStringQuery<RotationsQuery>,
    Extension(RouteExecutionDeadline(deadline)): Extension<RouteExecutionDeadline>,
    headers: HeaderMap,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Result<Response, Error> {
    match rotations(&query) {
        Ok(selection) => serve(app, selection, deadline, headers, remote).await,
        Err(response) => Ok(response),
    }
}

#[cfg(test)]
mod tests;
