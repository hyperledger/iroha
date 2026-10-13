//! Authenticated, projection-only SoraFS hedging and billing HTTP boundary.
//!
//! Every data read is served only while the supervised finalized-ledger projector passes its live
//! head and freshness fence; payload-free health remains observable while unready. Statement
//! ownership comes exclusively from Torii's canonical account-signature authentication; callers
//! cannot supply an account identifier in a query or body. The only mutation is an owner
//! acknowledgement carrying one bounded external-authority proof. Pricing feeds, policy changes,
//! signer material, and hedge execution are deliberately absent from this V1 surface.

use crate::{JsonBody, SharedAppState};
use axum::{
    body::{Body, Bytes},
    extract::{Path, RawQuery, Request, State},
    http::{
        HeaderMap, HeaderValue, Method, StatusCode, Uri,
        header::{CACHE_CONTROL, CONTENT_TYPE, VARY},
    },
    response::{IntoResponse, Response},
};
use iroha_core::state::WorldReadOnly;
use iroha_data_model::{account::AccountId, role::RoleId};
use iroha_torii_shared::sorafs_hedging_billing_api::{
    BILLING_ACKNOWLEDGEMENT_PROOF_MAX_BYTES_V1,
    BillingAcknowledgementProofV1 as BillingAcknowledgementProofBodyV1,
};
use norito::{DecodeLimits, NoritoSerialize, derive::JsonSerialize};
use sorafs_node::hedging_billing_service::{
    BILLING_ACKNOWLEDGEMENT_PROOF_MAX_BYTES_V1 as SERVICE_BILLING_ACKNOWLEDGEMENT_PROOF_MAX_BYTES_V1,
    BillingPublishedStatementRequestV1, BillingStatementAcknowledgementRequestV1,
    BillingStatementListRequestV1, HEDGING_BILLING_RUNTIME_API_MAX_PAGE_ITEMS_V1,
    HedgingBillingProjectionPageRequestV1, HedgingBillingRuntimeApiErrorV1,
    HedgingBillingRuntimeApiV1, SIGNED_GOVERNED_BILLING_STATEMENT_MAX_BYTES_V1,
};
use std::{
    sync::{Arc, LazyLock},
    time::{SystemTime, UNIX_EPOCH},
};
#[cfg(test)]
pub const BILLING_STATUS_ROUTE_V1: &str = "/v1/sorafs/billing/status";
#[cfg(test)]
pub const BILLING_STATEMENTS_ROUTE_V1: &str = "/v1/sorafs/billing/statements";
#[cfg(test)]
pub const BILLING_STATEMENT_ROUTE_V1: &str = "/v1/sorafs/billing/statements/{statement_id}";
#[cfg(test)]
pub const BILLING_STATEMENT_ACKNOWLEDGEMENTS_ROUTE_V1: &str =
    "/v1/sorafs/billing/statements/{statement_id}/acknowledgements";
#[cfg(test)]
pub const BILLING_RECONCILIATION_ROUTE_V1: &str = "/v1/sorafs/billing/reconciliation";
#[cfg(test)]
pub const HEDGING_EXPOSURE_ROUTE_V1: &str = "/v1/sorafs/hedging/exposure";
#[cfg(test)]
pub const HEDGING_INTENTS_ROUTE_V1: &str = "/v1/sorafs/hedging/intents";
pub const SORAFS_BILLING_MANAGER_ROLE_V1: &str = "sorafs_billing_manager";
pub const SORAFS_TREASURY_OBSERVER_ROLE_V1: &str = "sorafs_treasury_observer";
pub const SORAFS_HEDGING_OBSERVER_ROLE_V1: &str = "sorafs_hedging_observer";
const EXPECTED_CHECKPOINT_PARAMETER: &str = "expected_checkpoint_fingerprint";
const AFTER_STATEMENT_PARAMETER: &str = "after_statement_id";
const AFTER_PROJECTION_PARAMETER: &str = "after";
const LIMIT_PARAMETER: &str = "limit";
const MAX_QUERY_BYTES_V1: usize = 1_024;
const MAX_QUERY_PARAMETERS_V1: usize = 3;
const MAX_JSON_RESPONSE_BYTES_V1: usize = 1024 * 1024;
const ACKNOWLEDGEMENT_WRAPPER_BYTES_V1: usize = 4 * 1024;
const MAX_ACKNOWLEDGEMENT_BODY_BYTES_V1: usize =
    BILLING_ACKNOWLEDGEMENT_PROOF_MAX_BYTES_V1 + ACKNOWLEDGEMENT_WRAPPER_BYTES_V1;
const MAX_PUBLISHED_STATEMENT_RESPONSE_BYTES_V1: usize =
    SIGNED_GOVERNED_BILLING_STATEMENT_MAX_BYTES_V1 + 2 * 1024 * 1024;
const MAX_BLOCKING_OPERATIONS_V1: usize = 32;
const _: () = assert!(
    BILLING_ACKNOWLEDGEMENT_PROOF_MAX_BYTES_V1
        == SERVICE_BILLING_ACKNOWLEDGEMENT_PROOF_MAX_BYTES_V1
);
const CANONICAL_AUTH_VARY_V1: &str =
    "X-Iroha-Account, X-Iroha-Signature, X-Iroha-Timestamp-Ms, X-Iroha-Nonce, X-Iroha-Witness";
static BILLING_MANAGER_ROLE_ID_V1: LazyLock<RoleId> = LazyLock::new(|| {
    SORAFS_BILLING_MANAGER_ROLE_V1
        .parse()
        .expect("SoraFS billing manager role id is valid")
});
static TREASURY_OBSERVER_ROLE_ID_V1: LazyLock<RoleId> = LazyLock::new(|| {
    SORAFS_TREASURY_OBSERVER_ROLE_V1
        .parse()
        .expect("SoraFS treasury observer role id is valid")
});
static HEDGING_OBSERVER_ROLE_ID_V1: LazyLock<RoleId> = LazyLock::new(|| {
    SORAFS_HEDGING_OBSERVER_ROLE_V1
        .parse()
        .expect("SoraFS hedging observer role id is valid")
});
static HEDGING_BILLING_BLOCKING_PERMITS_V1: LazyLock<Arc<tokio::sync::Semaphore>> =
    LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(MAX_BLOCKING_OPERATIONS_V1)));
#[derive(Debug, JsonSerialize)]
struct HedgingBillingApiErrorResponseV1 {
    schema: String,
    code: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueryInputError {
    TooLong,
    TooManyParameters,
    NonCanonical,
    UnknownParameter,
    DuplicateParameter,
    MissingParameter,
    InvalidLimit,
    InvalidDigest,
    ZeroDigest,
    UnexpectedQuery,
}
impl QueryInputError {
    const fn code(self) -> &'static str {
        match self {
            Self::TooLong => "query_too_long",
            Self::TooManyParameters => "too_many_query_parameters",
            Self::NonCanonical => "noncanonical_query",
            Self::UnknownParameter => "unknown_query_parameter",
            Self::DuplicateParameter => "duplicate_query_parameter",
            Self::MissingParameter => "required_query_parameter_missing",
            Self::InvalidLimit => "invalid_page_limit",
            Self::InvalidDigest => "invalid_lower_hex_digest",
            Self::ZeroDigest => "zero_digest_forbidden",
            Self::UnexpectedQuery => "unexpected_query",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OwnerStatementPageQueryV1 {
    expected_checkpoint_fingerprint: [u8; 32],
    after_statement_id: Option<[u8; 32]>,
    limit: u16,
}
impl OwnerStatementPageQueryV1 {
    fn parse(raw: Option<&str>) -> Result<Self, QueryInputError> {
        let mut expected_checkpoint_fingerprint = None;
        let mut after_statement_id = None;
        let mut limit = None;
        for (key, value) in bounded_query_pairs(raw)? {
            match key.as_str() {
                EXPECTED_CHECKPOINT_PARAMETER => set_once(
                    &mut expected_checkpoint_fingerprint,
                    parse_lower_hex_digest(&value, true)?,
                )?,
                AFTER_STATEMENT_PARAMETER => set_once(
                    &mut after_statement_id,
                    parse_lower_hex_digest(&value, true)?,
                )?,
                LIMIT_PARAMETER => set_once(&mut limit, parse_page_limit(&value)?)?,
                _ => return Err(QueryInputError::UnknownParameter),
            }
        }
        Ok(Self {
            expected_checkpoint_fingerprint: expected_checkpoint_fingerprint
                .ok_or(QueryInputError::MissingParameter)?,
            after_statement_id,
            limit: limit.ok_or(QueryInputError::MissingParameter)?,
        })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProjectionPageQueryV1 {
    expected_checkpoint_fingerprint: [u8; 32],
    after: Option<[u8; 32]>,
    limit: u16,
}
impl ProjectionPageQueryV1 {
    fn parse(raw: Option<&str>) -> Result<Self, QueryInputError> {
        let mut expected_checkpoint_fingerprint = None;
        let mut after = None;
        let mut limit = None;
        for (key, value) in bounded_query_pairs(raw)? {
            match key.as_str() {
                EXPECTED_CHECKPOINT_PARAMETER => set_once(
                    &mut expected_checkpoint_fingerprint,
                    parse_lower_hex_digest(&value, true)?,
                )?,
                AFTER_PROJECTION_PARAMETER => {
                    set_once(&mut after, parse_lower_hex_digest(&value, true)?)?
                }
                LIMIT_PARAMETER => set_once(&mut limit, parse_page_limit(&value)?)?,
                _ => return Err(QueryInputError::UnknownParameter),
            }
        }
        Ok(Self {
            expected_checkpoint_fingerprint: expected_checkpoint_fingerprint
                .ok_or(QueryInputError::MissingParameter)?,
            after,
            limit: limit.ok_or(QueryInputError::MissingParameter)?,
        })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProjectionAnchorQueryV1 {
    expected_checkpoint_fingerprint: [u8; 32],
}
impl ProjectionAnchorQueryV1 {
    fn parse(raw: Option<&str>) -> Result<Self, QueryInputError> {
        let mut expected_checkpoint_fingerprint = None;
        for (key, value) in bounded_query_pairs(raw)? {
            match key.as_str() {
                EXPECTED_CHECKPOINT_PARAMETER => set_once(
                    &mut expected_checkpoint_fingerprint,
                    parse_lower_hex_digest(&value, true)?,
                )?,
                _ => return Err(QueryInputError::UnknownParameter),
            }
        }
        Ok(Self {
            expected_checkpoint_fingerprint: expected_checkpoint_fingerprint
                .ok_or(QueryInputError::MissingParameter)?,
        })
    }
}
pub async fn handle_get_sorafs_billing_status(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    RawQuery(raw_query): RawQuery,
) -> Response {
    private_no_store_response(billing_status_inner(state, headers, method, uri, raw_query).await)
}
async fn billing_status_inner(
    state: SharedAppState,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    raw_query: Option<String>,
) -> Response {
    if let Err(response) = require_method(&method, Method::GET) {
        return response;
    }
    let _verified = match require_canonical_auth(&state, &headers, &method, &uri, &[]) {
        Ok(verified) => verified,
        Err(response) => return response,
    };
    // Every authenticated owner or observer needs the exact current anchor to
    // bootstrap a projection-bound read. The response is payload-free and
    // contains only health/counter data; manager-only reconciliation remains a
    // separate endpoint.
    if let Err(error) = reject_query(raw_query.as_deref()) {
        return query_error_response(error);
    }
    let runtime = match runtime(&state) {
        Ok(runtime) => runtime,
        Err(response) => return response,
    };
    match run_runtime_call(move || runtime.daemon_status()).await {
        Ok(status) => bounded_json_response(status),
        Err(response) => response,
    }
}
pub async fn handle_get_sorafs_billing_statements(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    RawQuery(raw_query): RawQuery,
) -> Response {
    private_no_store_response(
        billing_statements_inner(state, headers, method, uri, raw_query).await,
    )
}
async fn billing_statements_inner(
    state: SharedAppState,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    raw_query: Option<String>,
) -> Response {
    if let Err(response) = require_method(&method, Method::GET) {
        return response;
    }
    let verified = match require_canonical_auth(&state, &headers, &method, &uri, &[]) {
        Ok(verified) => verified,
        Err(response) => return response,
    };
    let query = match OwnerStatementPageQueryV1::parse(raw_query.as_deref()) {
        Ok(query) => query,
        Err(error) => return query_error_response(error),
    };
    let owner_account_id = match canonical_account_bytes(&verified.account) {
        Ok(owner) => owner,
        Err(response) => return response,
    };
    let runtime = match runtime(&state) {
        Ok(runtime) => runtime,
        Err(response) => return response,
    };
    let request = BillingStatementListRequestV1 {
        owner_account_id,
        after_statement_id: query.after_statement_id,
        limit: query.limit,
        expected_checkpoint_fingerprint: query.expected_checkpoint_fingerprint,
    };
    match run_runtime_call(move || runtime.list_statements(&request)).await {
        Ok(page) => bounded_json_response(page),
        Err(response) => response,
    }
}
pub async fn handle_get_sorafs_billing_statement(
    State(state): State<SharedAppState>,
    Path(statement_id_hex): Path<String>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    RawQuery(raw_query): RawQuery,
) -> Response {
    private_no_store_response(
        billing_statement_inner(state, statement_id_hex, headers, method, uri, raw_query).await,
    )
}
async fn billing_statement_inner(
    state: SharedAppState,
    statement_id_hex: String,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    raw_query: Option<String>,
) -> Response {
    if let Err(response) = require_method(&method, Method::GET) {
        return response;
    }
    let verified = match require_canonical_auth(&state, &headers, &method, &uri, &[]) {
        Ok(verified) => verified,
        Err(response) => return response,
    };
    let statement_id = match parse_lower_hex_digest(&statement_id_hex, true) {
        Ok(statement_id) => statement_id,
        Err(error) => return query_error_response(error),
    };
    let query = match ProjectionAnchorQueryV1::parse(raw_query.as_deref()) {
        Ok(query) => query,
        Err(error) => return query_error_response(error),
    };
    let owner_account_id = match canonical_account_bytes(&verified.account) {
        Ok(owner) => owner,
        Err(response) => return response,
    };
    let runtime = match runtime(&state) {
        Ok(runtime) => runtime,
        Err(response) => return response,
    };
    let request = BillingPublishedStatementRequestV1 {
        owner_account_id,
        statement_id,
        expected_checkpoint_fingerprint: query.expected_checkpoint_fingerprint,
    };
    let published = match run_runtime_call(move || runtime.published_statement(&request)).await {
        Ok(published) => published,
        Err(response) => return response,
    };
    match encode_norito_bounded(published, MAX_PUBLISHED_STATEMENT_RESPONSE_BYTES_V1).await {
        Ok(bytes) => binary_response(bytes, crate::utils::NORITO_MIME_TYPE),
        Err(response) => response,
    }
}
pub async fn handle_post_sorafs_billing_statement_acknowledgement(
    State(state): State<SharedAppState>,
    Path(statement_id_hex): Path<String>,
    request: Request,
) -> Response {
    let (parts, body) = request.into_parts();
    let body = match axum::body::to_bytes(body, MAX_ACKNOWLEDGEMENT_BODY_BYTES_V1).await {
        Ok(body) => body,
        Err(_) => {
            return private_no_store_response(fixed_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "acknowledgement_proof_body_too_large",
            ));
        }
    };
    let raw_query = parts.uri.query().map(str::to_owned);
    private_no_store_response(
        billing_statement_acknowledgement_inner(
            state,
            statement_id_hex,
            parts.headers,
            parts.method,
            parts.uri,
            raw_query,
            body,
        )
        .await,
    )
}
async fn billing_statement_acknowledgement_inner(
    state: SharedAppState,
    statement_id_hex: String,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    raw_query: Option<String>,
    body: Bytes,
) -> Response {
    if let Err(response) = require_method(&method, Method::POST) {
        return response;
    }
    if let Err(response) = validate_norito_request_headers_and_bound(&headers, &body) {
        return response;
    }
    let verified = match require_canonical_auth(&state, &headers, &method, &uri, body.as_ref()) {
        Ok(verified) => verified,
        Err(response) => return response,
    };
    let statement_id = match parse_lower_hex_digest(&statement_id_hex, true) {
        Ok(statement_id) => statement_id,
        Err(error) => return query_error_response(error),
    };
    let query = match ProjectionAnchorQueryV1::parse(raw_query.as_deref()) {
        Ok(query) => query,
        Err(error) => return query_error_response(error),
    };
    let owner_account_id = match canonical_account_bytes(&verified.account) {
        Ok(owner) => owner,
        Err(response) => return response,
    };
    let proof = match decode_acknowledgement_proof(body.as_ref()) {
        Ok(proof) => proof,
        Err(response) => return response,
    };
    let server_time_unix = match server_time_unix() {
        Ok(server_time_unix) => server_time_unix,
        Err(response) => return response,
    };
    let runtime = match runtime(&state) {
        Ok(runtime) => runtime,
        Err(response) => return response,
    };
    let request = BillingStatementAcknowledgementRequestV1 {
        expected_checkpoint_fingerprint: query.expected_checkpoint_fingerprint,
        statement_id,
        owner_account_id,
        request_nonce: proof.request_nonce,
        authentication_proof: proof.authentication_proof,
    };
    match run_runtime_call(move || runtime.acknowledge_statement(&request, server_time_unix)).await
    {
        Ok(response) => bounded_json_response(response),
        Err(response) => response,
    }
}
pub async fn handle_get_sorafs_billing_reconciliation(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    RawQuery(raw_query): RawQuery,
) -> Response {
    private_no_store_response(
        billing_reconciliation_inner(state, headers, method, uri, raw_query).await,
    )
}
async fn billing_reconciliation_inner(
    state: SharedAppState,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    raw_query: Option<String>,
) -> Response {
    if let Err(response) = require_method(&method, Method::GET) {
        return response;
    }
    let verified = match require_canonical_auth(&state, &headers, &method, &uri, &[]) {
        Ok(verified) => verified,
        Err(response) => return response,
    };
    if let Err(response) = require_billing_manager(&state, &verified.account) {
        return response;
    }
    if let Err(error) = reject_query(raw_query.as_deref()) {
        return query_error_response(error);
    }
    let runtime = match runtime(&state) {
        Ok(runtime) => runtime,
        Err(response) => return response,
    };
    match run_runtime_call(move || runtime.reconciliation_status()).await {
        Ok(status) => bounded_json_response(status),
        Err(response) => response,
    }
}
pub async fn handle_get_sorafs_hedging_exposure(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    RawQuery(raw_query): RawQuery,
) -> Response {
    private_no_store_response(
        hedging_projection_inner(
            state,
            headers,
            method,
            uri,
            raw_query,
            ProjectionKind::Exposure,
        )
        .await,
    )
}
pub async fn handle_get_sorafs_hedging_intents(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    RawQuery(raw_query): RawQuery,
) -> Response {
    private_no_store_response(
        hedging_projection_inner(
            state,
            headers,
            method,
            uri,
            raw_query,
            ProjectionKind::Intents,
        )
        .await,
    )
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProjectionKind {
    Exposure,
    Intents,
}
async fn hedging_projection_inner(
    state: SharedAppState,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    raw_query: Option<String>,
    kind: ProjectionKind,
) -> Response {
    if let Err(response) = require_method(&method, Method::GET) {
        return response;
    }
    let verified = match require_canonical_auth(&state, &headers, &method, &uri, &[]) {
        Ok(verified) => verified,
        Err(response) => return response,
    };
    if let Err(response) = require_treasury_or_hedging_observer(&state, &verified.account) {
        return response;
    }
    let query = match ProjectionPageQueryV1::parse(raw_query.as_deref()) {
        Ok(query) => query,
        Err(error) => return query_error_response(error),
    };
    let runtime = match runtime(&state) {
        Ok(runtime) => runtime,
        Err(response) => return response,
    };
    let request = HedgingBillingProjectionPageRequestV1 {
        expected_checkpoint_fingerprint: query.expected_checkpoint_fingerprint,
        after: query.after,
        limit: query.limit,
    };
    match kind {
        ProjectionKind::Exposure => {
            match run_runtime_call(move || runtime.exposure_page(&request)).await {
                Ok(page) => bounded_json_response(page),
                Err(response) => response,
            }
        }
        ProjectionKind::Intents => {
            match run_runtime_call(move || runtime.hedge_intent_page(&request)).await {
                Ok(page) => bounded_json_response(page),
                Err(response) => response,
            }
        }
    }
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn runtime(state: &SharedAppState) -> Result<Arc<dyn HedgingBillingRuntimeApiV1>, Response> {
    state
        .sorafs_hedging_billing_runtime
        .clone()
        .ok_or_else(runtime_unavailable_response)
}
async fn run_runtime_call<T, F>(operation: F) -> Result<T, Response>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, HedgingBillingRuntimeApiErrorV1> + Send + 'static,
{
    let permit = Arc::clone(&HEDGING_BILLING_BLOCKING_PERMITS_V1)
        .try_acquire_owned()
        .map_err(|_| {
            fixed_error(
                StatusCode::TOO_MANY_REQUESTS,
                "hedging_billing_runtime_busy",
            )
        })?;
    crate::panic_recovery::join_recoverable(crate::panic_recovery::spawn_blocking_recoverable(
        move || {
            let _permit = permit;
            operation()
        },
    ))
    .await
    .map_err(|_| runtime_unavailable_response())?
    .map_err(runtime_error_response)
}
async fn encode_norito_bounded<T>(value: T, max_bytes: usize) -> Result<Vec<u8>, Response>
where
    T: NoritoSerialize + Send + 'static,
{
    let permit = Arc::clone(&HEDGING_BILLING_BLOCKING_PERMITS_V1)
        .try_acquire_owned()
        .map_err(|_| {
            fixed_error(
                StatusCode::TOO_MANY_REQUESTS,
                "hedging_billing_runtime_busy",
            )
        })?;
    crate::panic_recovery::join_recoverable(crate::panic_recovery::spawn_blocking_recoverable(
        move || {
            let _permit = permit;
            let bytes = norito::to_bytes(&value).map_err(|_| ())?;
            if bytes.len() > max_bytes {
                return Err(());
            }
            Ok(bytes)
        },
    ))
    .await
    .map_err(|_| runtime_unavailable_response())?
    .map_err(|()| runtime_unavailable_response())
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn require_canonical_auth(
    state: &SharedAppState,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    body: &[u8],
) -> Result<crate::app_auth::VerifiedCanonicalRequest, Response> {
    let authentication_owner =
        match crate::history_producer::HistoryProducerOwner::authentication_read(state) {
            Ok(owner) => owner,
            Err(error) => {
                return Err(error.into_response());
            }
        };

    match crate::app_auth::verify_canonical_network_request(
        &state.state,
        state.state.network_id_ref(),
        headers,
        crate::app_auth::CanonicalRequestParts { method, uri, body },
        None,
        authentication_owner.allocation_context(),
    ) {
        Ok(Some(verified)) => Ok(verified),
        Ok(None) | Err(_) => Err(fixed_error(
            StatusCode::UNAUTHORIZED,
            "canonical_authentication_required",
        )),
    }
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn require_billing_manager(state: &SharedAppState, account: &AccountId) -> Result<(), Response> {
    let world = state.state.world_view();
    if world
        .account_roles_iter(account)
        .any(|role| role == &*BILLING_MANAGER_ROLE_ID_V1)
    {
        Ok(())
    } else {
        Err(fixed_error(
            StatusCode::FORBIDDEN,
            "billing_manager_role_required",
        ))
    }
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn require_treasury_or_hedging_observer(
    state: &SharedAppState,
    account: &AccountId,
) -> Result<(), Response> {
    let world = state.state.world_view();
    if world
        .account_roles_iter(account)
        .any(|role| role == &*TREASURY_OBSERVER_ROLE_ID_V1 || role == &*HEDGING_OBSERVER_ROLE_ID_V1)
    {
        Ok(())
    } else {
        Err(fixed_error(
            StatusCode::FORBIDDEN,
            "treasury_or_hedging_observer_role_required",
        ))
    }
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn canonical_account_bytes(account: &AccountId) -> Result<Vec<u8>, Response> {
    let literal = account.canonical_i105().map_err(|_| {
        fixed_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "canonical_account_encoding_unavailable",
        )
    })?;
    let parsed = AccountId::parse_encoded(&literal).map_err(|_| {
        fixed_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "canonical_account_encoding_unavailable",
        )
    })?;
    if parsed.to_string() != literal || parsed.subject_id() != account.subject_id() {
        return Err(fixed_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "canonical_account_encoding_unavailable",
        ));
    }
    Ok(literal.into_bytes())
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn validate_norito_request_headers_and_bound(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(), Response> {
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    if content_type != Some(crate::utils::NORITO_MIME_TYPE) {
        return Err(fixed_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "canonical_norito_content_type_required",
        ));
    }
    if body.is_empty() {
        return Err(fixed_error(
            StatusCode::BAD_REQUEST,
            "acknowledgement_proof_body_required",
        ));
    }
    if body.len() > MAX_ACKNOWLEDGEMENT_BODY_BYTES_V1 {
        return Err(fixed_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "acknowledgement_proof_body_too_large",
        ));
    }
    Ok(())
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn decode_acknowledgement_proof(
    body: &[u8],
) -> Result<BillingAcknowledgementProofBodyV1, Response> {
    if body.is_empty() || body.len() > MAX_ACKNOWLEDGEMENT_BODY_BYTES_V1 {
        return Err(fixed_error(
            StatusCode::BAD_REQUEST,
            "invalid_bounded_canonical_norito_acknowledgement",
        ));
    }
    let limits = DecodeLimits::new(
        MAX_ACKNOWLEDGEMENT_BODY_BYTES_V1,
        MAX_ACKNOWLEDGEMENT_BODY_BYTES_V1,
        MAX_ACKNOWLEDGEMENT_BODY_BYTES_V1,
        MAX_ACKNOWLEDGEMENT_BODY_BYTES_V1.saturating_mul(2),
        16,
    );
    let request =
        norito::decode_from_bytes_with_limits::<BillingAcknowledgementProofBodyV1>(body, limits)
            .map_err(|_| {
                fixed_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_bounded_canonical_norito_acknowledgement",
                )
            })?;
    let canonical = norito::to_bytes(&request).map_err(|_| {
        fixed_error(
            StatusCode::BAD_REQUEST,
            "invalid_bounded_canonical_norito_acknowledgement",
        )
    })?;
    if canonical != body
        || request.request_nonce == [0; 32]
        || request.authentication_proof.is_empty()
        || request.authentication_proof.len() > BILLING_ACKNOWLEDGEMENT_PROOF_MAX_BYTES_V1
    {
        return Err(fixed_error(
            StatusCode::BAD_REQUEST,
            "invalid_bounded_canonical_norito_acknowledgement",
        ));
    }
    Ok(request)
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn server_time_unix() -> Result<u64, Response> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| runtime_unavailable_response())?
        .as_secs();
    if now == 0 || now == u64::MAX {
        return Err(runtime_unavailable_response());
    }
    Ok(now)
}
fn bounded_query_pairs(raw: Option<&str>) -> Result<Vec<(String, String)>, QueryInputError> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    if raw.len() > MAX_QUERY_BYTES_V1 {
        return Err(QueryInputError::TooLong);
    }
    if raw.is_empty() || raw.bytes().any(|byte| matches!(byte, b'%' | b'+')) {
        return Err(QueryInputError::NonCanonical);
    }
    let mut pairs = Vec::new();
    for (index, segment) in raw.split('&').enumerate() {
        if index >= MAX_QUERY_PARAMETERS_V1 {
            return Err(QueryInputError::TooManyParameters);
        }
        if segment.is_empty() {
            return Err(QueryInputError::NonCanonical);
        }
        let Some((key, value)) = segment.split_once('=') else {
            return Err(QueryInputError::NonCanonical);
        };
        if key.is_empty() || value.is_empty() || value.contains('=') {
            return Err(QueryInputError::NonCanonical);
        }
        pairs.push((key.to_owned(), value.to_owned()));
    }
    Ok(pairs)
}
fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), QueryInputError> {
    if slot.is_some() {
        return Err(QueryInputError::DuplicateParameter);
    }
    *slot = Some(value);
    Ok(())
}
fn parse_page_limit(value: &str) -> Result<u16, QueryInputError> {
    if value.is_empty()
        || value.len() > 3
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(QueryInputError::InvalidLimit);
    }
    let limit = value
        .parse::<u16>()
        .map_err(|_| QueryInputError::InvalidLimit)?;
    if !(1..=HEDGING_BILLING_RUNTIME_API_MAX_PAGE_ITEMS_V1).contains(&limit) {
        return Err(QueryInputError::InvalidLimit);
    }
    Ok(limit)
}
fn parse_lower_hex_digest(value: &str, reject_zero: bool) -> Result<[u8; 32], QueryInputError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(QueryInputError::InvalidDigest);
    }
    let mut digest = [0_u8; 32];
    hex::decode_to_slice(value, &mut digest).map_err(|_| QueryInputError::InvalidDigest)?;
    if reject_zero && digest == [0; 32] {
        return Err(QueryInputError::ZeroDigest);
    }
    Ok(digest)
}
fn reject_query(raw: Option<&str>) -> Result<(), QueryInputError> {
    if raw.is_some_and(|query| !query.is_empty()) {
        Err(QueryInputError::UnexpectedQuery)
    } else {
        Ok(())
    }
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn require_method(actual: &Method, expected: Method) -> Result<(), Response> {
    if actual == expected {
        Ok(())
    } else {
        Err(fixed_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
        ))
    }
}
fn runtime_error_response(error: HedgingBillingRuntimeApiErrorV1) -> Response {
    match error {
        HedgingBillingRuntimeApiErrorV1::InvalidRequest => {
            fixed_error(StatusCode::BAD_REQUEST, "invalid_hedging_billing_request")
        }
        HedgingBillingRuntimeApiErrorV1::ProjectionChanged => {
            fixed_error(StatusCode::CONFLICT, "hedging_billing_projection_changed")
        }
        HedgingBillingRuntimeApiErrorV1::StatementUnavailableToOwner => {
            fixed_error(StatusCode::NOT_FOUND, "billing_statement_not_found")
        }
        HedgingBillingRuntimeApiErrorV1::AcknowledgementConflict => {
            fixed_error(StatusCode::CONFLICT, "billing_acknowledgement_conflict")
        }
        HedgingBillingRuntimeApiErrorV1::ResourceExhausted => fixed_error(
            StatusCode::TOO_MANY_REQUESTS,
            "hedging_billing_resource_exhausted",
        ),
        HedgingBillingRuntimeApiErrorV1::Unavailable => runtime_unavailable_response(),
    }
}
fn runtime_unavailable_response() -> Response {
    fixed_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "hedging_billing_runtime_unavailable",
    )
}
fn query_error_response(error: QueryInputError) -> Response {
    fixed_error(StatusCode::BAD_REQUEST, error.code())
}
fn fixed_error(status: StatusCode, code: &'static str) -> Response {
    (
        status,
        JsonBody(HedgingBillingApiErrorResponseV1 {
            schema: "sorafs.hedging_billing.error.v1".to_owned(),
            code: code.to_owned(),
        }),
    )
        .into_response()
}
fn bounded_json_response<T>(value: T) -> Response
where
    T: norito::json::JsonSerialize,
{
    let bytes = match norito::json::to_vec(&value) {
        Ok(bytes) if bytes.len() <= MAX_JSON_RESPONSE_BYTES_V1 => bytes,
        Ok(_) | Err(_) => return runtime_unavailable_response(),
    };
    binary_response(bytes, "application/json")
}
fn binary_response(bytes: Vec<u8>, content_type: &'static str) -> Response {
    let mut response = Response::new(Body::from(bytes));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}
fn private_no_store_response(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    headers.insert(VARY, HeaderValue::from_static(CANONICAL_AUTH_VARY_V1));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hedging_billing_auth_rejects_foreign_exact_network() {
        let _guard = crate::tests_runtime_handlers::app_auth_test_guard(
            crate::app_auth::CanonicalRequestAuthConfig::default(),
        );
        let method = Method::POST;
        let uri: Uri = "/v1/sorafs/finance/owner-statements"
            .parse()
            .expect("hedging billing URI");
        let body = b"{}";
        let (state, headers) = crate::tests_runtime_handlers::foreign_network_signed_app_fixture(
            &method, &uri, body, 0xD3, 0xE3,
        );
        let response = require_canonical_auth(&state, &headers, &method, &uri, body)
            .expect_err("foreign-network billing authorization must fail closed");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    fn digest_hex(byte: u8) -> String {
        hex::encode([byte; 32])
    }
    #[test]
    fn statement_page_query_is_bounded_and_rejects_aliases() {
        let checkpoint = digest_hex(0x11);
        let after = digest_hex(0x22);
        let raw = format!(
            "{LIMIT_PARAMETER}=100&{AFTER_STATEMENT_PARAMETER}={after}&\
             {EXPECTED_CHECKPOINT_PARAMETER}={checkpoint}"
        );
        let parsed = OwnerStatementPageQueryV1::parse(Some(&raw)).expect("bounded query");
        assert_eq!(parsed.limit, 100);
        assert_eq!(parsed.after_statement_id, Some([0x22; 32]));
        assert_eq!(parsed.expected_checkpoint_fingerprint, [0x11; 32]);
        let alias = format!("checkpoint={checkpoint}&limit=1");
        assert_eq!(
            OwnerStatementPageQueryV1::parse(Some(&alias)),
            Err(QueryInputError::UnknownParameter)
        );
        let duplicate = format!(
            "{EXPECTED_CHECKPOINT_PARAMETER}={checkpoint}&\
             {EXPECTED_CHECKPOINT_PARAMETER}={checkpoint}&limit=1"
        );
        assert_eq!(
            OwnerStatementPageQueryV1::parse(Some(&duplicate)),
            Err(QueryInputError::DuplicateParameter)
        );
        let noncanonical = [
            "",
            "limit",
            "limit=",
            "=1",
            "limit=1&",
            "&limit=1",
            "limit=1&&after_statement_id=abc",
            "limit=%31",
            "lim%69t=1",
            "limit=+1",
            "limit=1=1",
        ];
        for raw in noncanonical {
            assert_eq!(
                bounded_query_pairs(Some(raw)),
                Err(QueryInputError::NonCanonical),
                "query unexpectedly accepted: {raw:?}"
            );
        }
    }
    #[test]
    fn page_limit_requires_canonical_decimal_in_exact_range() {
        for invalid in ["", "0", "00", "01", "101", "+1", "-1", "1.0", " 1"] {
            assert_eq!(
                parse_page_limit(invalid),
                Err(QueryInputError::InvalidLimit),
                "{invalid:?}"
            );
        }
        assert_eq!(parse_page_limit("1"), Ok(1));
        assert_eq!(parse_page_limit("100"), Ok(100));
    }
    #[test]
    fn routes_require_the_exact_http_method() {
        assert!(require_method(&Method::GET, Method::GET).is_ok());
        assert_eq!(
            require_method(&Method::HEAD, Method::GET)
                .expect_err("HEAD must not dispatch a GET operation")
                .status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            require_method(&Method::GET, Method::POST)
                .expect_err("GET must not dispatch a POST operation")
                .status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
    }
    #[test]
    fn digest_parser_requires_exact_nonzero_lower_hex() {
        let valid = digest_hex(0xab);
        assert_eq!(parse_lower_hex_digest(&valid, true), Ok([0xab; 32]));
        assert_eq!(
            parse_lower_hex_digest(&valid.to_ascii_uppercase(), true),
            Err(QueryInputError::InvalidDigest)
        );
        assert_eq!(
            parse_lower_hex_digest(&format!("0x{valid}"), true),
            Err(QueryInputError::InvalidDigest)
        );
        assert_eq!(
            parse_lower_hex_digest(&"00".repeat(32), true),
            Err(QueryInputError::ZeroDigest)
        );
    }
    #[test]
    fn projection_query_rejects_bombs_missing_anchor_and_unknown_cursor() {
        let checkpoint = digest_hex(0x31);
        assert_eq!(
            ProjectionPageQueryV1::parse(Some("limit=1")),
            Err(QueryInputError::MissingParameter)
        );
        let unknown = format!(
            "{EXPECTED_CHECKPOINT_PARAMETER}={checkpoint}&limit=1&after_cursor={}",
            digest_hex(0x32)
        );
        assert_eq!(
            ProjectionPageQueryV1::parse(Some(&unknown)),
            Err(QueryInputError::UnknownParameter)
        );
        let oversized = "x".repeat(MAX_QUERY_BYTES_V1 + 1);
        assert_eq!(
            ProjectionPageQueryV1::parse(Some(&oversized)),
            Err(QueryInputError::TooLong)
        );
    }
    #[test]
    fn acknowledgement_body_is_exact_bounded_canonical_norito_and_debug_redacted() {
        let request = BillingAcknowledgementProofBodyV1 {
            request_nonce: [0x91; 32],
            authentication_proof: vec![0xa5; 64],
        };
        let bytes = norito::to_bytes(&request).expect("canonical proof request");
        let decoded = decode_acknowledgement_proof(&bytes).expect("bounded decode");
        assert_eq!(decoded, request);
        let debug = format!("{request:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("165"));
        let empty = norito::to_bytes(&BillingAcknowledgementProofBodyV1 {
            request_nonce: [0x91; 32],
            authentication_proof: Vec::new(),
        })
        .expect("empty proof encoding");
        assert_eq!(
            decode_acknowledgement_proof(&empty)
                .expect_err("empty proof must fail")
                .status(),
            StatusCode::BAD_REQUEST
        );
        let oversized = norito::to_bytes(&BillingAcknowledgementProofBodyV1 {
            request_nonce: [0x91; 32],
            authentication_proof: vec![0; BILLING_ACKNOWLEDGEMENT_PROOF_MAX_BYTES_V1 + 1],
        })
        .expect("oversized proof encoding");
        assert_eq!(
            decode_acknowledgement_proof(&oversized)
                .expect_err("oversized proof must fail")
                .status(),
            StatusCode::BAD_REQUEST
        );
        let zero_nonce = norito::to_bytes(&BillingAcknowledgementProofBodyV1 {
            request_nonce: [0; 32],
            authentication_proof: vec![0xa5],
        })
        .expect("zero-nonce proof encoding");
        assert_eq!(
            decode_acknowledgement_proof(&zero_nonce)
                .expect_err("zero idempotency nonce must fail")
                .status(),
            StatusCode::BAD_REQUEST
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            decode_acknowledgement_proof(&trailing)
                .expect_err("trailing bytes must fail")
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            decode_acknowledgement_proof(&bytes[..bytes.len() - 1])
                .expect_err("truncation must fail")
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    #[test]
    fn acknowledgement_requires_exact_norito_media_type_and_bound() {
        let body = vec![1];
        let mut headers = HeaderMap::new();
        assert_eq!(
            validate_norito_request_headers_and_bound(&headers, &body)
                .expect_err("missing content type")
                .status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-norito; version=1"),
        );
        assert_eq!(
            validate_norito_request_headers_and_bound(&headers, &body)
                .expect_err("parameters are not the exact media type")
                .status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static(crate::utils::NORITO_MIME_TYPE),
        );
        validate_norito_request_headers_and_bound(&headers, &body).expect("exact media type");
        assert_eq!(
            validate_norito_request_headers_and_bound(
                &headers,
                &vec![0; MAX_ACKNOWLEDGEMENT_BODY_BYTES_V1 + 1],
            )
            .expect_err("body bound")
            .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }
    #[test]
    fn runtime_errors_preserve_oracle_safe_owner_not_found_and_retry_classes() {
        assert_eq!(
            runtime_error_response(HedgingBillingRuntimeApiErrorV1::ProjectionChanged).status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            runtime_error_response(HedgingBillingRuntimeApiErrorV1::StatementUnavailableToOwner)
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            runtime_error_response(HedgingBillingRuntimeApiErrorV1::AcknowledgementConflict)
                .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            runtime_error_response(HedgingBillingRuntimeApiErrorV1::Unavailable).status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    #[test]
    fn every_response_is_private_and_varies_on_all_canonical_auth_headers() {
        let response = private_no_store_response(StatusCode::OK.into_response());
        assert_eq!(
            response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("private, no-store"))
        );
        let vary = response
            .headers()
            .get(VARY)
            .and_then(|value| value.to_str().ok())
            .expect("vary header");
        for header in [
            "X-Iroha-Account",
            "X-Iroha-Signature",
            "X-Iroha-Timestamp-Ms",
            "X-Iroha-Nonce",
            "X-Iroha-Witness",
        ] {
            assert!(vary.contains(header), "missing {header}");
        }
    }
    #[test]
    fn v1_route_inventory_has_no_execution_or_feed_mutation() {
        assert_eq!(BILLING_STATUS_ROUTE_V1, "/v1/sorafs/billing/status");
        assert_eq!(BILLING_STATEMENTS_ROUTE_V1, "/v1/sorafs/billing/statements");
        assert_eq!(
            BILLING_STATEMENT_ROUTE_V1,
            "/v1/sorafs/billing/statements/{statement_id}"
        );
        assert_eq!(
            BILLING_STATEMENT_ACKNOWLEDGEMENTS_ROUTE_V1,
            "/v1/sorafs/billing/statements/{statement_id}/acknowledgements"
        );
        assert_eq!(
            BILLING_RECONCILIATION_ROUTE_V1,
            "/v1/sorafs/billing/reconciliation"
        );
        assert_eq!(HEDGING_EXPOSURE_ROUTE_V1, "/v1/sorafs/hedging/exposure");
        assert_eq!(HEDGING_INTENTS_ROUTE_V1, "/v1/sorafs/hedging/intents");
        for route in [
            BILLING_STATUS_ROUTE_V1,
            BILLING_STATEMENTS_ROUTE_V1,
            BILLING_STATEMENT_ROUTE_V1,
            BILLING_STATEMENT_ACKNOWLEDGEMENTS_ROUTE_V1,
            BILLING_RECONCILIATION_ROUTE_V1,
            HEDGING_EXPOSURE_ROUTE_V1,
            HEDGING_INTENTS_ROUTE_V1,
        ] {
            assert!(!route.contains("execute"));
            assert!(!route.contains("feed"));
            assert!(!route.contains("config"));
        }
    }
}
