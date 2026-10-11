//! Bounded authenticated HTTP intake; no raw platform verdict or signer selector is exposed.
use super::*;
use axum::{
    body::Body,
    extract::State,
    http::{HeaderValue, Request, StatusCode},
    response::{IntoResponse as _, Response},
};

fn failure(error: IssuerError) -> Response {
    use iroha_torii_shared::kagemusha_enrollment::EnrollmentServiceOutcomeV1 as Outcome;
    let outcome = match error {
        IssuerError::Refused(reason)
        | IssuerError::Journal(
            iroha_core::kagemusha_wallet_v1::enrollment_journal::EnrollmentJournalErrorV1::Ineligible(reason),
        ) => Some(Outcome::Refused(reason)),
        IssuerError::DeliveryWithheld(reason) => Some(Outcome::DeliveryWithheld(reason)),
        IssuerError::OutcomeUnknown => Some(Outcome::OutcomeUnknown),
        _ => None,
    };
    let status = match (error, outcome) {
        (_, Some(outcome)) => {
            StatusCode::from_u16(outcome.status()).unwrap_or(StatusCode::SERVICE_UNAVAILABLE)
        }
        (IssuerError::Invalid, None) => StatusCode::BAD_REQUEST,
        (IssuerError::Selection, None) => StatusCode::FORBIDDEN,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    };
    let mut response = (status, "enrollment operation unavailable or rejected").into_response();
    if let Some((name, value)) = outcome.map(|outcome| outcome.header()) {
        if let Ok(value) = HeaderValue::from_str(&value) {
            response.headers_mut().insert(name, value);
        }
    }
    response
}
pub(crate) async fn handler(
    State(app): State<crate::SharedAppState>,
    request: Request<Body>,
) -> Response {
    let mut response = handle(app, request).await.unwrap_or_else(failure);
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response
}
async fn handle(app: crate::SharedAppState, request: Request<Body>) -> Result<Response> {
    let service = app
        .kagemusha_enrollment
        .as_ref()
        .ok_or(IssuerError::Unavailable)?
        .clone();
    // Admission precedes body collection and remains held while the blocking owner operates.
    let permit = service
        .slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| IssuerError::Unavailable)?;
    let (parts, body) = request.into_parts();
    if parts.method != axum::http::Method::POST
        || parts.uri.path() != ENROLLMENT_SERVICE_ROUTE_V1
        || parts.uri.query().is_some()
    {
        return Err(IssuerError::Invalid);
    }
    let mut types = parts
        .headers
        .get_all(axum::http::header::CONTENT_TYPE)
        .iter();
    if types
        .next()
        .is_none_or(|value| value != crate::utils::NORITO_MIME_TYPE)
        || types.next().is_some()
    {
        return Err(IssuerError::Invalid);
    }
    crate::validate_bounded_content_length(&parts.headers, ENROLLMENT_SERVICE_REQUEST_MAX_BYTES_V1)
        .map_err(|_| IssuerError::Invalid)?;
    let body = tokio::time::timeout(
        service.body_timeout,
        axum::body::to_bytes(body, ENROLLMENT_SERVICE_REQUEST_MAX_BYTES_V1),
    )
    .await
    .map_err(|_| IssuerError::Unavailable)?
    .map_err(|_| IssuerError::Invalid)?;
    let call = HttpCall {
        method: parts.method,
        uri: parts.uri,
        headers: parts.headers,
        body,
    };
    let original = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        service
            .owner
            .execute(call)?
            .canonical_wire()
            .map_err(|_| IssuerError::Invalid)
    })
    .await
    .map_err(|_| IssuerError::Unavailable)??;
    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static(crate::utils::NORITO_MIME_TYPE),
        )],
        original,
    )
        .into_response())
}
