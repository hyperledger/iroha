//! Authenticated Torii API and embedded shell for the SFM-4b3 evidence viewer.
//!
//! Canonical account signatures identify callers. WebAuthn assertions and
//! rotating grants remain runtime-only; response bodies and durable receipts
//! contain payload-free metadata or canonical Norito envelopes only.
use crate::{JsonBody, SharedAppState};
use axum::{
    body::{Body, Bytes},
    extract::{Path, State},
    http::{
        HeaderMap, HeaderValue, Method, StatusCode, Uri,
        header::{
            CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, PRAGMA,
        },
    },
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use iroha_core::state::WorldReadOnly;
use iroha_data_model::role::RoleId;
use norito::json::{self, Map, Value};
use sorafs_node::{
    ModerationEvidenceViewerAccessKind,
    evidence_viewer::{
        EVIDENCE_VIEWER_MAX_OPAQUE_TOKEN_BYTES_V1, EVIDENCE_VIEWER_MAX_WEBAUTHN_ASSERTION_BYTES_V1,
        EvidenceViewerAuditStatusV1, EvidenceViewerChallengeRequestV1, EvidenceViewerErrorV1,
        EvidenceViewerLegalHoldV1, EvidenceViewerManifestV1, EvidenceViewerReceiptCursorV1,
        EvidenceViewerReceiptKindV1, EvidenceViewerRetentionRecordV1, EvidenceViewerRoleV1,
        EvidenceViewerSessionRequestV1, EvidenceViewerSignedCheckpointAnchorV1,
        EvidenceViewerSignedCompactionArchiveHeadV1, EvidenceViewerSignedReceiptV1,
        EvidenceViewerTransparencyProjectionV1, OpaqueEvidenceViewerSecretV1,
    },
};
use std::{collections::BTreeMap, sync::LazyLock, time::UNIX_EPOCH};
const MAX_JSON_BODY_BYTES: usize = 128 * 1024;
const MAX_AUDIT_PAGE: usize = 256;
const MAX_AUDIT_QUERY_BYTES: usize = 512;
const MAX_RETENTION_PAGE: usize = 256;
const HEADER_EVIDENCE_GRANT: &str = "x-sorafs-evidence-grant";
const HEADER_EVIDENCE_CHALLENGE: &str = "x-sorafs-evidence-challenge";
const HEADER_EVIDENCE_RECEIPT_DIGEST: &str = "x-sorafs-evidence-receipt-digest";
const HEADER_EVIDENCE_WATERMARK_DIGEST: &str = "x-sorafs-evidence-watermark-digest";
const EXPOSED_EVIDENCE_HEADERS: &str = "X-SoraFS-Evidence-Grant, X-SoraFS-Evidence-Challenge, \
     X-SoraFS-Evidence-Receipt-Digest, X-SoraFS-Evidence-Watermark-Digest";
const REQUEST_DIGEST_DOMAIN_V1: &[u8] = b"sorafs.torii.evidence-viewer.request.v1";
const EVIDENCE_AUDITOR_ROLE_V1: &str = "sorafs_evidence_auditor";
const LEGAL_REVIEWER_ROLE_V1: &str = "sorafs_legal_reviewer";
static EVIDENCE_AUDITOR_ROLE_ID: LazyLock<RoleId> = LazyLock::new(|| {
    EVIDENCE_AUDITOR_ROLE_V1
        .parse()
        .expect("SoraFS evidence auditor role id is valid")
});
static LEGAL_REVIEWER_ROLE_ID: LazyLock<RoleId> = LazyLock::new(|| {
    LEGAL_REVIEWER_ROLE_V1
        .parse()
        .expect("SoraFS legal reviewer role id is valid")
});
#[derive(crate::json_macros::JsonDeserialize, crate::json_macros::JsonSerialize)]
#[norito(deny_unknown_fields)]
pub struct EvidenceChallengeRequestDto {
    case_id: String,
    round_id: String,
    quarantine_id_hex: String,
    role: String,
    purpose: String,
    idempotency_key_hex: String,
}
#[derive(crate::json_macros::JsonDeserialize, crate::json_macros::JsonSerialize)]
#[norito(deny_unknown_fields)]
pub struct EvidenceSessionRequestDto {
    case_id: String,
    round_id: String,
    quarantine_id_hex: String,
    role: String,
    purpose: String,
    webauthn_assertion_b64: String,
    idempotency_key_hex: String,
}
#[derive(crate::json_macros::JsonDeserialize, crate::json_macros::JsonSerialize)]
#[norito(deny_unknown_fields)]
pub struct EvidenceInteractionRequestDto {
    kind: String,
    event_metadata_digest_hex: Option<String>,
    idempotency_key_hex: String,
}
#[derive(crate::json_macros::JsonDeserialize, crate::json_macros::JsonSerialize)]
#[norito(deny_unknown_fields)]
pub struct EvidenceLegalHoldRequestDto {
    case_id: String,
    round_id: String,
    quarantine_id_hex: String,
    authority_digest_hex: String,
    idempotency_key_hex: String,
}
#[derive(crate::json_macros::JsonDeserialize, crate::json_macros::JsonSerialize)]
#[norito(deny_unknown_fields)]
pub struct EvidenceLegalHoldReleaseRequestDto {
    case_id: String,
    round_id: String,
    idempotency_key_hex: String,
}
#[derive(crate::json_macros::JsonDeserialize, crate::json_macros::JsonSerialize)]
#[norito(deny_unknown_fields)]
pub struct EvidenceRetentionRequestDto {
    case_id: String,
    round_id: String,
    quarantine_id_hex: String,
    retain_until_unix_ms: u64,
    idempotency_key_hex: String,
}
#[derive(crate::json_macros::JsonDeserialize, crate::json_macros::JsonSerialize)]
#[norito(deny_unknown_fields)]
pub struct EvidenceErasureRequestDto {
    case_id: String,
    round_id: String,
    quarantine_id_hex: String,
    idempotency_key_hex: String,
}
/// Issue an exact case/round/object/account/role-bound WebAuthn challenge.
pub async fn handle_post_evidence_session_challenge(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Response {
    let Some(service) = state.sorafs_evidence_viewer.as_ref() else {
        return service_disabled();
    };
    let verified = match require_canonical_auth(&state, &headers, &method, &uri, &body) {
        Ok(verified) => verified,
        Err(response) => return response,
    };
    let request: EvidenceChallengeRequestDto = match decode_json(&body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    let role = match parse_role(&request.role) {
        Ok(role) => role,
        Err(response) => return response,
    };
    let quarantine_id = match parse_hex_fixed::<16>(&request.quarantine_id_hex, "quarantine_id_hex")
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let idempotency_key =
        match parse_nonzero_digest(&request.idempotency_key_hex, "idempotency_key_hex") {
            Ok(value) => value,
            Err(response) => return response,
        };
    let now_unix_ms = network_time_now_ms();
    let issued = match service.issue_challenge(EvidenceViewerChallengeRequestV1 {
        case_id: request.case_id,
        round_id: request.round_id,
        quarantine_id,
        viewer_account: verified.account.to_string(),
        role,
        purpose: request.purpose,
        idempotency_key,
        now_unix_ms,
    }) {
        Ok(issued) => issued,
        Err(error) => return service_error(error),
    };
    let mut response = secure_json_response(
        StatusCode::CREATED,
        object([
            ("schema", "sorafs.evidence.challenge.v1".into()),
            ("challenge_id_hex", hex::encode(issued.challenge_id).into()),
            ("expires_at_unix_ms", issued.expires_at_unix_ms.into()),
        ]),
    );
    if let Err(response_error) = insert_secret_header(
        &mut response,
        HEADER_EVIDENCE_CHALLENGE,
        issued.challenge.expose(),
    ) {
        return response_error;
    }
    response
}
/// Consume a WebAuthn assertion and return one case-bound rotating-grant session.
pub async fn handle_post_evidence_session(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Response {
    let Some(service) = state.sorafs_evidence_viewer.as_ref() else {
        return service_disabled();
    };
    let verified = match require_canonical_auth(&state, &headers, &method, &uri, &body) {
        Ok(verified) => verified,
        Err(response) => return response,
    };
    let request: EvidenceSessionRequestDto = match decode_json(&body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    let role = match parse_role(&request.role) {
        Ok(role) => role,
        Err(response) => return response,
    };
    let quarantine_id = match parse_hex_fixed::<16>(&request.quarantine_id_hex, "quarantine_id_hex")
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let idempotency_key =
        match parse_nonzero_digest(&request.idempotency_key_hex, "idempotency_key_hex") {
            Ok(value) => value,
            Err(response) => return response,
        };
    let challenge = match challenge_from_headers(&headers) {
        Ok(challenge) => challenge,
        Err(response) => return response,
    };
    let mut assertion = match BASE64_STANDARD.decode(request.webauthn_assertion_b64.as_bytes()) {
        Ok(assertion)
            if !assertion.is_empty()
                && assertion.len() <= EVIDENCE_VIEWER_MAX_WEBAUTHN_ASSERTION_BYTES_V1 =>
        {
            assertion
        }
        _ => return fixed_error(StatusCode::BAD_REQUEST, "invalid_webauthn_assertion"),
    };
    let now_unix_ms = network_time_now_ms();
    let result = service.create_session(EvidenceViewerSessionRequestV1 {
        case_id: request.case_id,
        round_id: request.round_id,
        quarantine_id,
        viewer_account: verified.account.to_string(),
        role,
        purpose: request.purpose,
        challenge,
        webauthn_assertion: std::mem::take(&mut assertion),
        idempotency_key,
        now_unix_ms,
    });
    assertion.fill(0);
    let issued = match result {
        Ok(issued) => issued,
        Err(error) => return service_error(error),
    };
    let session_b64 = match canonical_norito_b64(&issued.session) {
        Ok(encoded) => encoded,
        Err(response) => return response,
    };
    let receipt = match receipt_value(&issued.receipt) {
        Ok(receipt) => receipt,
        Err(response) => return response,
    };
    let mut response = secure_json_response(
        StatusCode::CREATED,
        object([
            ("schema", "sorafs.evidence.session.v1".into()),
            (
                "session_id_hex",
                hex::encode(issued.session.local_session.session_id).into(),
            ),
            (
                "expires_at_unix_ms",
                issued.session.local_session.expires_at_unix_ms.into(),
            ),
            ("session_norito_b64", session_b64.into()),
            ("receipt", receipt),
        ]),
    );
    if let Err(response_error) =
        insert_secret_header(&mut response, HEADER_EVIDENCE_GRANT, issued.grant.expose())
    {
        return response_error;
    }
    response
}
/// Return the case-bound payload-free manifest and rotate the grant.
pub async fn handle_get_evidence_manifest(
    State(state): State<SharedAppState>,
    Path(session_id_hex): Path<String>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> Response {
    let Some(service) = state.sorafs_evidence_viewer.as_ref() else {
        return service_disabled();
    };
    let verified = match require_canonical_auth(&state, &headers, &method, &uri, &[]) {
        Ok(verified) => verified,
        Err(response) => return response,
    };
    let session_id = match parse_hex_fixed::<16>(&session_id_hex, "session_id_hex") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let query = match exact_query(&uri, &["idempotency_key_hex"]) {
        Ok(query) => query,
        Err(response) => return response,
    };
    let idempotency_key =
        match parse_nonzero_digest(query["idempotency_key_hex"].as_str(), "idempotency_key_hex") {
            Ok(value) => value,
            Err(response) => return response,
        };
    let grant = match grant_from_headers(&headers) {
        Ok(grant) => grant,
        Err(response) => return response,
    };
    let account = verified.account.to_string();
    let request_digest = request_digest(&method, &uri, &[], &account);
    let outcome = match service.manifest(
        session_id,
        &account,
        &grant,
        idempotency_key,
        request_digest,
        network_time_now_ms(),
    ) {
        Ok(outcome) => outcome,
        Err(error) => return service_error(error),
    };
    let manifest = match manifest_value(&outcome.manifest) {
        Ok(manifest) => manifest,
        Err(response) => return response,
    };
    let receipt = match receipt_value(&outcome.receipt) {
        Ok(receipt) => receipt,
        Err(response) => return response,
    };
    let mut response = secure_json_response(
        StatusCode::OK,
        object([
            ("schema", "sorafs.evidence.manifest.v1".into()),
            ("manifest", manifest),
            ("receipt", receipt),
        ]),
    );
    if let Err(response_error) = insert_secret_header(
        &mut response,
        HEADER_EVIDENCE_GRANT,
        outcome.rotated_grant.expose(),
    ) {
        return response_error;
    }
    response
}
/// Authenticate, decrypt, durably receipt, and return one bounded byte range.
pub async fn handle_get_evidence_segment(
    State(state): State<SharedAppState>,
    Path(session_id_hex): Path<String>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> Response {
    let Some(service) = state.sorafs_evidence_viewer.as_ref() else {
        return service_disabled();
    };
    let verified = match require_canonical_auth(&state, &headers, &method, &uri, &[]) {
        Ok(verified) => verified,
        Err(response) => return response,
    };
    let session_id = match parse_hex_fixed::<16>(&session_id_hex, "session_id_hex") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let query = match exact_query(&uri, &["start", "end", "idempotency_key_hex"]) {
        Ok(query) => query,
        Err(response) => return response,
    };
    let start = match parse_u64(query["start"].as_str(), "start") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let end = match parse_u64(query["end"].as_str(), "end") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let idempotency_key =
        match parse_nonzero_digest(query["idempotency_key_hex"].as_str(), "idempotency_key_hex") {
            Ok(value) => value,
            Err(response) => return response,
        };
    let grant = match grant_from_headers(&headers) {
        Ok(grant) => grant,
        Err(response) => return response,
    };
    let account = verified.account.to_string();
    let outcome = match service.read_range(
        session_id,
        &account,
        &grant,
        start,
        end,
        idempotency_key,
        request_digest(&method, &uri, &[], &account),
        network_time_now_ms(),
    ) {
        Ok(outcome) => outcome,
        Err(error) => return service_error(error),
    };
    let total = outcome.range.record.payload_len;
    let content_type = outcome
        .range
        .record
        .content_type
        .as_deref()
        .unwrap_or("application/octet-stream");
    let content_range = format!("bytes {}-{}/{}", start, end.saturating_sub(1), total);
    let content_length = outcome.range.payload.len().to_string();
    let mut response = Response::new(Body::from(outcome.range.payload));
    *response.status_mut() = StatusCode::PARTIAL_CONTENT;
    let response_headers = response.headers_mut();
    response_headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_str(content_type)
            .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
    );
    response_headers.insert(
        CONTENT_RANGE,
        HeaderValue::from_str(&content_range)
            .unwrap_or_else(|_| HeaderValue::from_static("bytes */0")),
    );
    if let Ok(value) = HeaderValue::from_str(&content_length) {
        response_headers.insert(CONTENT_LENGTH, value);
    }
    response_headers.insert(CONTENT_DISPOSITION, HeaderValue::from_static("inline"));
    secure_private_headers(&mut response);
    if let Err(response_error) = insert_secret_header(
        &mut response,
        HEADER_EVIDENCE_GRANT,
        outcome.rotated_grant.expose(),
    ) {
        return response_error;
    }
    insert_hex_header(
        &mut response,
        HEADER_EVIDENCE_RECEIPT_DIGEST,
        outcome.receipt.receipt_digest,
    );
    insert_hex_header(
        &mut response,
        HEADER_EVIDENCE_WATERMARK_DIGEST,
        outcome.watermark_metadata_digest,
    );
    response
}
/// Append one signed payload-free browser interaction and rotate the grant.
pub async fn handle_post_evidence_log(
    State(state): State<SharedAppState>,
    Path(session_id_hex): Path<String>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Response {
    let Some(service) = state.sorafs_evidence_viewer.as_ref() else {
        return service_disabled();
    };
    let verified = match require_canonical_auth(&state, &headers, &method, &uri, &body) {
        Ok(verified) => verified,
        Err(response) => return response,
    };
    let session_id = match parse_hex_fixed::<16>(&session_id_hex, "session_id_hex") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let request: EvidenceInteractionRequestDto = match decode_json(&body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    let kind = match parse_interaction_kind(&request.kind) {
        Ok(kind) => kind,
        Err(response) => return response,
    };
    let metadata_digest = match request.event_metadata_digest_hex {
        Some(value) => match parse_nonzero_digest(&value, "event_metadata_digest_hex") {
            Ok(value) => Some(value),
            Err(response) => return response,
        },
        None => None,
    };
    let idempotency_key =
        match parse_nonzero_digest(&request.idempotency_key_hex, "idempotency_key_hex") {
            Ok(value) => value,
            Err(response) => return response,
        };
    let grant = match grant_from_headers(&headers) {
        Ok(grant) => grant,
        Err(response) => return response,
    };
    let account = verified.account.to_string();
    let (rotated_grant, receipt) = match service.record_interaction(
        session_id,
        &account,
        &grant,
        kind,
        metadata_digest,
        idempotency_key,
        request_digest(&method, &uri, &body, &account),
        network_time_now_ms(),
    ) {
        Ok(outcome) => outcome,
        Err(error) => return service_error(error),
    };
    let receipt = match receipt_value(&receipt) {
        Ok(receipt) => receipt,
        Err(response) => return response,
    };
    let mut response = secure_json_response(
        StatusCode::ACCEPTED,
        object([
            ("schema", "sorafs.evidence.access_event.v1".into()),
            ("receipt", receipt),
        ]),
    );
    if let Err(response_error) =
        insert_secret_header(&mut response, HEADER_EVIDENCE_GRANT, rotated_grant.expose())
    {
        return response_error;
    }
    response
}
/// Place one legal hold with a signed payload-free receipt.
pub async fn handle_post_evidence_legal_hold(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Response {
    let Some(service) = state.sorafs_evidence_viewer.as_ref() else {
        return service_disabled();
    };
    let verified = match require_canonical_auth(&state, &headers, &method, &uri, &body) {
        Ok(verified) => verified,
        Err(response) => return response,
    };
    if let Err(response) = require_explicit_legal_role(&state, &verified.account) {
        return response;
    }
    let request: EvidenceLegalHoldRequestDto = match decode_json(&body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    let quarantine_id = match parse_hex_fixed::<16>(&request.quarantine_id_hex, "quarantine_id_hex")
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let authority_digest =
        match parse_nonzero_digest(&request.authority_digest_hex, "authority_digest_hex") {
            Ok(value) => value,
            Err(response) => return response,
        };
    let idempotency_key =
        match parse_nonzero_digest(&request.idempotency_key_hex, "idempotency_key_hex") {
            Ok(value) => value,
            Err(response) => return response,
        };
    let (hold, receipt) = match service.place_legal_hold(
        &request.case_id,
        &request.round_id,
        quarantine_id,
        &verified.account.to_string(),
        authority_digest,
        idempotency_key,
        network_time_now_ms(),
    ) {
        Ok(outcome) => outcome,
        Err(error) => return service_error(error),
    };
    legal_hold_response(StatusCode::CREATED, &hold, &receipt)
}
/// Release one legal hold with a signed payload-free receipt.
pub async fn handle_post_evidence_legal_hold_release(
    State(state): State<SharedAppState>,
    Path(hold_id_hex): Path<String>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Response {
    let Some(service) = state.sorafs_evidence_viewer.as_ref() else {
        return service_disabled();
    };
    let verified = match require_canonical_auth(&state, &headers, &method, &uri, &body) {
        Ok(verified) => verified,
        Err(response) => return response,
    };
    if let Err(response) = require_explicit_legal_role(&state, &verified.account) {
        return response;
    }
    let hold_id = match parse_hex_fixed::<16>(&hold_id_hex, "hold_id_hex") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let request: EvidenceLegalHoldReleaseRequestDto = match decode_json(&body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    let idempotency_key =
        match parse_nonzero_digest(&request.idempotency_key_hex, "idempotency_key_hex") {
            Ok(value) => value,
            Err(response) => return response,
        };
    let account = verified.account.to_string();
    let (hold, receipt) = match service.release_legal_hold(
        &request.case_id,
        &request.round_id,
        hold_id,
        &account,
        idempotency_key,
        request_digest(&method, &uri, &body, &account),
        network_time_now_ms(),
    ) {
        Ok(outcome) => outcome,
        Err(error) => return service_error(error),
    };
    legal_hold_response(StatusCode::OK, &hold, &receipt)
}
/// Record one signed retention decision.
pub async fn handle_post_evidence_retention(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Response {
    let Some(service) = state.sorafs_evidence_viewer.as_ref() else {
        return service_disabled();
    };
    let verified = match require_canonical_auth(&state, &headers, &method, &uri, &body) {
        Ok(verified) => verified,
        Err(response) => return response,
    };
    if let Err(response) = require_explicit_legal_role(&state, &verified.account) {
        return response;
    }
    let request: EvidenceRetentionRequestDto = match decode_json(&body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    let quarantine_id = match parse_hex_fixed::<16>(&request.quarantine_id_hex, "quarantine_id_hex")
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let idempotency_key =
        match parse_nonzero_digest(&request.idempotency_key_hex, "idempotency_key_hex") {
            Ok(value) => value,
            Err(response) => return response,
        };
    let account = verified.account.to_string();
    let (record, receipt) = match service.record_retention(
        &request.case_id,
        &request.round_id,
        quarantine_id,
        &account,
        request.retain_until_unix_ms,
        idempotency_key,
        request_digest(&method, &uri, &body, &account),
        network_time_now_ms(),
    ) {
        Ok(outcome) => outcome,
        Err(error) => return service_error(error),
    };
    retention_response(&record, &receipt)
}
/// Return the bounded due-erasure projection to explicit legal reviewers.
pub async fn handle_get_evidence_retention(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> Response {
    let Some(service) = state.sorafs_evidence_viewer.as_ref() else {
        return service_disabled();
    };
    let verified = match require_canonical_auth(&state, &headers, &method, &uri, &[]) {
        Ok(verified) => verified,
        Err(response) => return response,
    };
    if let Err(response) = require_explicit_legal_role(&state, &verified.account) {
        return response;
    }
    let query = match optional_query(&uri, &["limit"]) {
        Ok(query) => query,
        Err(response) => return response,
    };
    let limit = match query.get("limit") {
        Some(value) => match parse_usize_bounded(value, "limit", MAX_RETENTION_PAGE) {
            Ok(value) => value,
            Err(response) => return response,
        },
        None => 100,
    };
    let due = match service.retention_due(network_time_now_ms(), limit) {
        Ok(due) => due,
        Err(error) => return service_error(error),
    };
    secure_json_response(
        StatusCode::OK,
        object([
            ("schema", "sorafs.evidence.retention_due.v1".into()),
            ("count", u64::try_from(due.len()).unwrap_or(u64::MAX).into()),
            (
                "quarantine_ids_hex",
                Value::Array(
                    due.into_iter()
                        .map(|id| Value::from(hex::encode(id)))
                        .collect(),
                ),
            ),
        ]),
    )
}
/// Execute irreversible erasure unless an active legal hold has precedence.
pub async fn handle_post_evidence_erasure(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Response {
    let Some(service) = state.sorafs_evidence_viewer.as_ref() else {
        return service_disabled();
    };
    let verified = match require_canonical_auth(&state, &headers, &method, &uri, &body) {
        Ok(verified) => verified,
        Err(response) => return response,
    };
    if let Err(response) = require_explicit_legal_role(&state, &verified.account) {
        return response;
    }
    let request: EvidenceErasureRequestDto = match decode_json(&body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    let quarantine_id = match parse_hex_fixed::<16>(&request.quarantine_id_hex, "quarantine_id_hex")
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let idempotency_key =
        match parse_nonzero_digest(&request.idempotency_key_hex, "idempotency_key_hex") {
            Ok(value) => value,
            Err(response) => return response,
        };
    let account = verified.account.to_string();
    let now_unix_ms = match healthy_network_time_now_ms() {
        Ok(now_unix_ms) => now_unix_ms,
        Err(response) => return response,
    };
    let (erasure, receipt) = match service.erase(
        &request.case_id,
        &request.round_id,
        quarantine_id,
        &account,
        idempotency_key,
        request_digest(&method, &uri, &body, &account),
        now_unix_ms,
    ) {
        Ok(outcome) => outcome,
        Err(error) => return service_error(error),
    };
    let erasure_b64 = match canonical_norito_b64(&erasure) {
        Ok(encoded) => encoded,
        Err(response) => return response,
    };
    let receipt = match receipt_value(&receipt) {
        Ok(receipt) => receipt,
        Err(response) => return response,
    };
    secure_json_response(
        StatusCode::OK,
        object([
            ("schema", "sorafs.evidence.erasure.v1".into()),
            (
                "quarantine_id_hex",
                hex::encode(erasure.quarantine_id).into(),
            ),
            (
                "erasure_commit_digest_hex",
                hex::encode(erasure.erasure_commit_digest).into(),
            ),
            ("erasure_norito_b64", erasure_b64.into()),
            ("receipt", receipt),
        ]),
    )
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EvidenceAuditQueryV1 {
    expected_checkpoint_digest: [u8; 32],
    predecessor: Option<EvidenceViewerReceiptCursorV1>,
    limit: usize,
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn parse_evidence_audit_query(uri: &Uri) -> Result<EvidenceAuditQueryV1, Response> {
    let raw = uri
        .query()
        .ok_or_else(|| fixed_error(StatusCode::BAD_REQUEST, "invalid_query"))?;
    if raw.is_empty()
        || raw.len() > MAX_AUDIT_QUERY_BYTES
        || raw.bytes().any(|byte| matches!(byte, b'%' | b'+'))
    {
        return Err(fixed_error(StatusCode::BAD_REQUEST, "invalid_query"));
    }
    let segments = raw.split('&').collect::<Vec<_>>();
    let (checkpoint_digest, predecessor, limit) = match segments.as_slice() {
        [checkpoint, limit] => (
            canonical_query_segment(checkpoint, "expected_checkpoint_digest_hex")?,
            None,
            canonical_query_segment(limit, "limit")?,
        ),
        [checkpoint, sequence, receipt_digest, limit] => {
            let sequence = canonical_query_segment(sequence, "after_sequence")?;
            let sequence = parse_u64(sequence, "after_sequence")?;
            if sequence == 0 {
                return Err(fixed_error(StatusCode::BAD_REQUEST, "after_sequence"));
            }
            let receipt_digest =
                canonical_query_segment(receipt_digest, "after_receipt_digest_hex")?;
            (
                canonical_query_segment(checkpoint, "expected_checkpoint_digest_hex")?,
                Some(EvidenceViewerReceiptCursorV1 {
                    sequence,
                    receipt_digest: parse_nonzero_digest(
                        receipt_digest,
                        "after_receipt_digest_hex",
                    )?,
                }),
                canonical_query_segment(limit, "limit")?,
            )
        }
        _ => return Err(fixed_error(StatusCode::BAD_REQUEST, "invalid_query")),
    };
    Ok(EvidenceAuditQueryV1 {
        expected_checkpoint_digest: parse_nonzero_digest(
            checkpoint_digest,
            "expected_checkpoint_digest_hex",
        )?,
        predecessor,
        limit: parse_usize_bounded(limit, "limit", MAX_AUDIT_PAGE)?,
    })
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn canonical_query_segment<'a>(segment: &'a str, expected_key: &str) -> Result<&'a str, Response> {
    let (key, value) = segment
        .split_once('=')
        .ok_or_else(|| fixed_error(StatusCode::BAD_REQUEST, "invalid_query"))?;
    if key != expected_key || value.is_empty() || value.contains('=') {
        Err(fixed_error(StatusCode::BAD_REQUEST, "invalid_query"))
    } else {
        Ok(value)
    }
}
/// Return a bounded exact-cursor projection of signed, hash-chained, payload-free receipts.
pub async fn handle_get_evidence_audit(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> Response {
    let Some(service) = state.sorafs_evidence_viewer.as_ref() else {
        return service_disabled();
    };
    let verified = match require_canonical_auth(&state, &headers, &method, &uri, &[]) {
        Ok(verified) => verified,
        Err(response) => return response,
    };
    if let Err(response) = require_explicit_audit_or_legal_role(&state, &verified.account) {
        return response;
    }
    let query = match parse_evidence_audit_query(&uri) {
        Ok(query) => query,
        Err(response) => return response,
    };
    let projection = match service.transparency_projection(
        query.expected_checkpoint_digest,
        query.predecessor,
        query.limit,
    ) {
        Ok(projection) => projection,
        Err(error) => return service_error(error),
    };
    audit_projection_response(&projection)
}
/// Return the payload-free durable audit status to explicit auditors or legal reviewers.
pub async fn handle_get_evidence_status(
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> Response {
    let Some(service) = state.sorafs_evidence_viewer.as_ref() else {
        return service_disabled();
    };
    let verified = match require_canonical_auth(&state, &headers, &method, &uri, &[]) {
        Ok(verified) => verified,
        Err(response) => return response,
    };
    if let Err(response) = require_explicit_audit_or_legal_role(&state, &verified.account) {
        return response;
    }
    if uri.query().is_some() {
        return fixed_error(StatusCode::BAD_REQUEST, "unexpected_query");
    }
    let status = match service.audit_status() {
        Ok(status) => status,
        Err(error) => return service_error(error),
    };
    audit_status_response(&status)
}
/// Serve the no-cache embedded same-origin viewer shell.
pub async fn handle_get_evidence_viewer() -> Response {
    static_asset_response("text/html; charset=utf-8", EVIDENCE_VIEWER_HTML)
}
/// Serve the immutable-in-binary, no-cache viewer stylesheet.
pub async fn handle_get_evidence_viewer_css() -> Response {
    static_asset_response("text/css; charset=utf-8", EVIDENCE_VIEWER_CSS)
}
/// Serve the immutable-in-binary, no-cache viewer controller.
pub async fn handle_get_evidence_viewer_js() -> Response {
    static_asset_response("text/javascript; charset=utf-8", EVIDENCE_VIEWER_JS)
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
fn require_explicit_audit_or_legal_role(
    state: &SharedAppState,
    account: &iroha_data_model::account::AccountId,
) -> Result<(), Response> {
    let world = state.state.world_view();
    let authorized = world
        .account_roles_iter(account)
        .any(|role| role == &*EVIDENCE_AUDITOR_ROLE_ID || role == &*LEGAL_REVIEWER_ROLE_ID);
    if authorized {
        Ok(())
    } else {
        Err(fixed_error(
            StatusCode::FORBIDDEN,
            "explicit_evidence_auditor_or_legal_role_required",
        ))
    }
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn require_explicit_legal_role(
    state: &SharedAppState,
    account: &iroha_data_model::account::AccountId,
) -> Result<(), Response> {
    let world = state.state.world_view();
    if world
        .account_roles_iter(account)
        .any(|role| role == &*LEGAL_REVIEWER_ROLE_ID)
    {
        Ok(())
    } else {
        Err(fixed_error(
            StatusCode::FORBIDDEN,
            "explicit_legal_reviewer_role_required",
        ))
    }
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn decode_json<T: norito::json::JsonDeserializeOwned>(body: &[u8]) -> Result<T, Response> {
    if body.is_empty() || body.len() > MAX_JSON_BODY_BYTES {
        return Err(fixed_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "invalid_request_size",
        ));
    }
    json::from_slice(body)
        .map_err(|_| fixed_error(StatusCode::BAD_REQUEST, "invalid_canonical_json"))
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn parse_role(value: &str) -> Result<EvidenceViewerRoleV1, Response> {
    match value {
        "juror" => Ok(EvidenceViewerRoleV1::Juror),
        "auditor" => Ok(EvidenceViewerRoleV1::Auditor),
        "legal" => Ok(EvidenceViewerRoleV1::Legal),
        _ => Err(fixed_error(StatusCode::BAD_REQUEST, "invalid_viewer_role")),
    }
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn parse_interaction_kind(value: &str) -> Result<ModerationEvidenceViewerAccessKind, Response> {
    match value {
        "viewed" => Ok(ModerationEvidenceViewerAccessKind::Viewed),
        "seeked" => Ok(ModerationEvidenceViewerAccessKind::Seeked),
        "paused" => Ok(ModerationEvidenceViewerAccessKind::Paused),
        "screenshot_attempted" => Ok(ModerationEvidenceViewerAccessKind::ScreenshotAttempted),
        "download_attempted" => Ok(ModerationEvidenceViewerAccessKind::DownloadAttempted),
        "annotated" => Ok(ModerationEvidenceViewerAccessKind::Annotated),
        "attestation_failed" => Ok(ModerationEvidenceViewerAccessKind::AttestationFailed),
        _ => Err(fixed_error(
            StatusCode::BAD_REQUEST,
            "invalid_access_event_kind",
        )),
    }
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn parse_hex_fixed<const N: usize>(value: &str, code: &'static str) -> Result<[u8; N], Response> {
    if value.len() != N.saturating_mul(2)
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(fixed_error(StatusCode::BAD_REQUEST, code));
    }
    let bytes = hex::decode(value).map_err(|_| fixed_error(StatusCode::BAD_REQUEST, code))?;
    bytes
        .try_into()
        .map_err(|_| fixed_error(StatusCode::BAD_REQUEST, code))
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn parse_nonzero_digest(value: &str, code: &'static str) -> Result<[u8; 32], Response> {
    let digest = parse_hex_fixed::<32>(value, code)?;
    if digest == [0; 32] {
        Err(fixed_error(StatusCode::BAD_REQUEST, code))
    } else {
        Ok(digest)
    }
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn parse_u64(value: &str, code: &'static str) -> Result<u64, Response> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(fixed_error(StatusCode::BAD_REQUEST, code));
    }
    value
        .parse()
        .map_err(|_| fixed_error(StatusCode::BAD_REQUEST, code))
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn parse_usize_bounded(value: &str, code: &'static str, maximum: usize) -> Result<usize, Response> {
    let parsed = parse_u64(value, code)?;
    let parsed = usize::try_from(parsed).map_err(|_| fixed_error(StatusCode::BAD_REQUEST, code))?;
    if parsed == 0 || parsed > maximum {
        Err(fixed_error(StatusCode::BAD_REQUEST, code))
    } else {
        Ok(parsed)
    }
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn exact_query(uri: &Uri, required: &[&'static str]) -> Result<BTreeMap<String, String>, Response> {
    let values = optional_query(uri, required)?;
    if required.iter().all(|key| values.contains_key(*key)) && values.len() == required.len() {
        Ok(values)
    } else {
        Err(fixed_error(StatusCode::BAD_REQUEST, "invalid_query"))
    }
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn optional_query(
    uri: &Uri,
    allowed: &[&'static str],
) -> Result<BTreeMap<String, String>, Response> {
    let mut values = BTreeMap::new();
    if let Some(raw) = uri.query() {
        if raw.is_empty()
            || raw.len() > MAX_AUDIT_QUERY_BYTES
            || raw.bytes().any(|byte| matches!(byte, b'%' | b'+'))
        {
            return Err(fixed_error(StatusCode::BAD_REQUEST, "invalid_query"));
        }
        for (index, segment) in raw.split('&').enumerate() {
            if index >= allowed.len() || segment.is_empty() {
                return Err(fixed_error(StatusCode::BAD_REQUEST, "invalid_query"));
            }
            let Some((key, value)) = segment.split_once('=') else {
                return Err(fixed_error(StatusCode::BAD_REQUEST, "invalid_query"));
            };
            if key.is_empty()
                || value.is_empty()
                || value.contains('=')
                || !allowed.contains(&key)
                || values.insert(key.to_owned(), value.to_owned()).is_some()
            {
                return Err(fixed_error(StatusCode::BAD_REQUEST, "invalid_query"));
            }
        }
    }
    Ok(values)
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn grant_from_headers(headers: &HeaderMap) -> Result<OpaqueEvidenceViewerSecretV1, Response> {
    secret_from_headers(
        headers,
        HEADER_EVIDENCE_GRANT,
        "evidence_grant_required",
        "invalid_evidence_grant",
    )
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn challenge_from_headers(headers: &HeaderMap) -> Result<OpaqueEvidenceViewerSecretV1, Response> {
    secret_from_headers(
        headers,
        HEADER_EVIDENCE_CHALLENGE,
        "evidence_challenge_required",
        "invalid_evidence_challenge",
    )
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn secret_from_headers(
    headers: &HeaderMap,
    name: &'static str,
    missing_code: &'static str,
    invalid_code: &'static str,
) -> Result<OpaqueEvidenceViewerSecretV1, Response> {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .ok_or_else(|| fixed_error(StatusCode::UNAUTHORIZED, missing_code))?;
    if values.next().is_some() {
        return Err(fixed_error(StatusCode::UNAUTHORIZED, invalid_code));
    }
    let value = value
        .to_str()
        .map_err(|_| fixed_error(StatusCode::UNAUTHORIZED, invalid_code))?;
    if value.len() > EVIDENCE_VIEWER_MAX_OPAQUE_TOKEN_BYTES_V1 {
        return Err(fixed_error(StatusCode::UNAUTHORIZED, invalid_code));
    }
    OpaqueEvidenceViewerSecretV1::new(value.to_owned())
        .map_err(|_| fixed_error(StatusCode::UNAUTHORIZED, invalid_code))
}
fn request_digest(method: &Method, uri: &Uri, body: &[u8], account: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(REQUEST_DIGEST_DOMAIN_V1);
    hash_component(&mut hasher, method.as_str().as_bytes());
    hash_component(&mut hasher, uri.path().as_bytes());
    hash_component(&mut hasher, uri.query().unwrap_or_default().as_bytes());
    hash_component(&mut hasher, account.as_bytes());
    hasher.update(blake3::hash(body).as_bytes());
    *hasher.finalize().as_bytes()
}
fn hash_component(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(value);
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn canonical_norito_b64<T: norito::core::NoritoSerialize>(value: &T) -> Result<String, Response> {
    norito::to_bytes(value)
        .map(|bytes| BASE64_STANDARD.encode(bytes))
        .map_err(|_| {
            fixed_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "canonical_encoding_unavailable",
            )
        })
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn manifest_value(manifest: &EvidenceViewerManifestV1) -> Result<Value, Response> {
    Ok(object([
        (
            "manifest_norito_b64",
            canonical_norito_b64(manifest)?.into(),
        ),
        ("session_id_hex", hex::encode(manifest.session_id).into()),
        ("case_id", manifest.case_id.clone().into()),
        ("round_id", manifest.round_id.clone().into()),
        (
            "quarantine_id_hex",
            hex::encode(manifest.quarantine_id).into(),
        ),
        ("object_id_hex", hex::encode(manifest.object_id).into()),
        (
            "evidence_digest_hex",
            hex::encode(manifest.evidence_digest).into(),
        ),
        ("payload_len", manifest.payload_len.into()),
        (
            "content_type",
            manifest
                .content_type
                .clone()
                .map_or(Value::Null, Value::from),
        ),
        ("max_range_bytes", manifest.max_range_bytes.into()),
        ("role", manifest.role.as_str().into()),
        (
            "purpose_digest_hex",
            hex::encode(manifest.purpose_digest).into(),
        ),
        (
            "visible_watermark",
            manifest.visible_watermark.clone().into(),
        ),
        (
            "watermark_metadata_digest_hex",
            hex::encode(manifest.watermark_metadata_digest).into(),
        ),
        ("expires_at_unix_ms", manifest.expires_at_unix_ms.into()),
        ("finalized_height", manifest.finalized_height.into()),
        (
            "finalized_block_hash_hex",
            hex::encode(manifest.finalized_block_hash).into(),
        ),
    ]))
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn receipt_value(receipt: &EvidenceViewerSignedReceiptV1) -> Result<Value, Response> {
    Ok(object([
        ("schema", "sorafs.evidence.signed_receipt.v1".into()),
        ("receipt_norito_b64", canonical_norito_b64(receipt)?.into()),
        ("sequence", receipt.body.sequence.into()),
        ("kind", receipt_kind_label(receipt.body.kind).into()),
        (
            "receipt_digest_hex",
            hex::encode(receipt.receipt_digest).into(),
        ),
        (
            "previous_receipt_digest_hex",
            hex::encode(receipt.body.previous_receipt_digest).into(),
        ),
        ("issued_at_unix_ms", receipt.body.issued_at_unix_ms.into()),
        ("signer_handle", receipt.signer_handle.clone().into()),
        (
            "signer_public_key_hex",
            hex::encode(receipt.signer_public_key).into(),
        ),
        ("signature_hex", hex::encode(receipt.signature).into()),
    ]))
}
fn receipt_cursor_value(cursor: EvidenceViewerReceiptCursorV1) -> Value {
    object([
        ("sequence", cursor.sequence.into()),
        (
            "receipt_digest_hex",
            hex::encode(cursor.receipt_digest).into(),
        ),
    ])
}
fn checkpoint_anchor_value(anchor: &EvidenceViewerSignedCheckpointAnchorV1) -> Value {
    object([
        ("version", u64::from(anchor.version).into()),
        ("checkpoint_generation", anchor.checkpoint_generation.into()),
        (
            "predecessor_checkpoint_revision_hex",
            anchor
                .predecessor_checkpoint_revision
                .map_or(Value::Null, |digest| hex::encode(digest).into()),
        ),
        (
            "predecessor_checkpoint_digest_hex",
            anchor
                .predecessor_checkpoint_digest
                .map_or(Value::Null, |digest| hex::encode(digest).into()),
        ),
        (
            "checkpoint_digest_hex",
            hex::encode(anchor.checkpoint_digest).into(),
        ),
        ("receipt_count", anchor.receipt_count.into()),
        (
            "chain_head",
            anchor.chain_head.map_or(Value::Null, receipt_cursor_value),
        ),
        (
            "compaction_archive_head_digest_hex",
            anchor
                .compaction_archive_head_digest
                .map_or(Value::Null, |digest| hex::encode(digest).into()),
        ),
        (
            "checkpoint_store_handle",
            anchor.checkpoint_store_handle.clone().into(),
        ),
        (
            "checkpoint_store_revision",
            anchor.checkpoint_store_revision.into(),
        ),
        (
            "checkpoint_store_policy_digest_hex",
            hex::encode(anchor.checkpoint_store_policy_digest).into(),
        ),
        ("signer_handle", anchor.signer_handle.clone().into()),
        (
            "signer_public_key_hex",
            hex::encode(anchor.signer_public_key).into(),
        ),
        ("signature_hex", hex::encode(anchor.signature).into()),
    ])
}
fn compaction_archive_head_value(head: &EvidenceViewerSignedCompactionArchiveHeadV1) -> Value {
    object([
        ("version", u64::from(head.version).into()),
        ("generation", head.generation.into()),
        (
            "predecessor_head_digest_hex",
            head.predecessor_head_digest
                .map_or(Value::Null, |digest| hex::encode(digest).into()),
        ),
        (
            "predecessor_operation_id_hex",
            head.predecessor_operation_id
                .map_or(Value::Null, |digest| hex::encode(digest).into()),
        ),
        ("operation_id_hex", hex::encode(head.operation_id).into()),
        (
            "source_checkpoint_generation",
            head.source_checkpoint_generation.into(),
        ),
        (
            "source_checkpoint_revision_hex",
            hex::encode(head.source_checkpoint_revision).into(),
        ),
        (
            "source_checkpoint_anchor",
            checkpoint_anchor_value(&head.source_checkpoint_anchor),
        ),
        (
            "compacted_through_unix_ms",
            head.compacted_through_unix_ms.into(),
        ),
        ("maximum_records", u64::from(head.maximum_records).into()),
        ("challenge_count", u64::from(head.challenge_count).into()),
        ("session_count", u64::from(head.session_count).into()),
        (
            "compacted_payload_digest_hex",
            hex::encode(head.compacted_payload_digest).into(),
        ),
        ("archive_handle", head.archive_handle.clone().into()),
        ("archive_revision", head.archive_revision.into()),
        (
            "archive_policy_digest_hex",
            hex::encode(head.archive_policy_digest).into(),
        ),
        ("archive_id_hex", hex::encode(head.archive_id).into()),
        (
            "archive_public_key_hex",
            hex::encode(head.archive_public_key).into(),
        ),
        ("signer_handle", head.signer_handle.clone().into()),
        (
            "signer_public_key_hex",
            hex::encode(head.signer_public_key).into(),
        ),
        ("signature_hex", hex::encode(head.signature).into()),
        ("head_digest_hex", hex::encode(head.head_digest).into()),
        (
            "archive_signature_hex",
            hex::encode(head.archive_signature).into(),
        ),
    ])
}
fn audit_projection_response(projection: &EvidenceViewerTransparencyProjectionV1) -> Response {
    let receipts = match projection
        .receipts
        .iter()
        .map(receipt_value)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(receipts) => receipts,
        Err(response) => return response,
    };
    let projection_norito_b64 = match canonical_norito_b64(projection) {
        Ok(encoded) => encoded,
        Err(response) => return response,
    };
    secure_json_response(
        StatusCode::OK,
        object([
            (
                "schema",
                "sorafs.evidence.audit_transparency_projection.v1".into(),
            ),
            ("version", u64::from(projection.version).into()),
            ("projection_norito_b64", projection_norito_b64.into()),
            (
                "checkpoint_anchor",
                checkpoint_anchor_value(&projection.checkpoint_anchor),
            ),
            (
                "compaction_archive_head",
                projection
                    .compaction_archive_head
                    .as_ref()
                    .map_or(Value::Null, compaction_archive_head_value),
            ),
            (
                "predecessor",
                projection
                    .predecessor
                    .map_or(Value::Null, receipt_cursor_value),
            ),
            ("page_limit", u64::from(projection.page_limit).into()),
            ("has_more", projection.has_more.into()),
            (
                "next_cursor",
                projection
                    .next_cursor
                    .map_or(Value::Null, receipt_cursor_value),
            ),
            (
                "projection_digest_hex",
                hex::encode(projection.projection_digest).into(),
            ),
            ("receipts", Value::Array(receipts)),
        ]),
    )
}
fn receipt_kind_label(kind: EvidenceViewerReceiptKindV1) -> &'static str {
    match kind {
        EvidenceViewerReceiptKindV1::ChallengeIssued => "challenge_issued",
        EvidenceViewerReceiptKindV1::SessionIssued => "session_issued",
        EvidenceViewerReceiptKindV1::ManifestAccessed => "manifest_accessed",
        EvidenceViewerReceiptKindV1::RangeAccessed => "range_accessed",
        EvidenceViewerReceiptKindV1::InteractionRecorded => "interaction_recorded",
        EvidenceViewerReceiptKindV1::LegalHoldPlaced => "legal_hold_placed",
        EvidenceViewerReceiptKindV1::LegalHoldReleased => "legal_hold_released",
        EvidenceViewerReceiptKindV1::RetentionEvaluated => "retention_evaluated",
        EvidenceViewerReceiptKindV1::ErasureCompleted => "erasure_completed",
        EvidenceViewerReceiptKindV1::ErasureDeniedLegalHold => "erasure_denied_legal_hold",
    }
}
fn legal_hold_response(
    status: StatusCode,
    hold: &EvidenceViewerLegalHoldV1,
    receipt: &EvidenceViewerSignedReceiptV1,
) -> Response {
    let hold_b64 = match canonical_norito_b64(hold) {
        Ok(encoded) => encoded,
        Err(response) => return response,
    };
    let receipt = match receipt_value(receipt) {
        Ok(receipt) => receipt,
        Err(response) => return response,
    };
    secure_json_response(
        status,
        object([
            ("schema", "sorafs.evidence.legal_hold.v1".into()),
            ("hold_id_hex", hex::encode(hold.hold_id).into()),
            ("quarantine_id_hex", hex::encode(hold.quarantine_id).into()),
            ("legal_hold_norito_b64", hold_b64.into()),
            ("receipt", receipt),
        ]),
    )
}
fn retention_response(
    record: &EvidenceViewerRetentionRecordV1,
    receipt: &EvidenceViewerSignedReceiptV1,
) -> Response {
    let record_b64 = match canonical_norito_b64(record) {
        Ok(encoded) => encoded,
        Err(response) => return response,
    };
    let receipt = match receipt_value(receipt) {
        Ok(receipt) => receipt,
        Err(response) => return response,
    };
    secure_json_response(
        StatusCode::OK,
        object([
            ("schema", "sorafs.evidence.retention.v1".into()),
            (
                "quarantine_id_hex",
                hex::encode(record.quarantine_id).into(),
            ),
            ("retain_until_unix_ms", record.retain_until_unix_ms.into()),
            ("legal_hold_precedence", record.legal_hold_precedence.into()),
            ("retention_norito_b64", record_b64.into()),
            ("receipt", receipt),
        ]),
    )
}
fn audit_status_response(status: &EvidenceViewerAuditStatusV1) -> Response {
    let encoded = match canonical_norito_b64(status) {
        Ok(encoded) => encoded,
        Err(response) => return response,
    };
    secure_json_response(
        StatusCode::OK,
        object([
            ("schema", "sorafs.evidence.audit_status.v1".into()),
            ("status_norito_b64", encoded.into()),
            ("challenge_count", status.challenge_count.into()),
            ("session_count", status.session_count.into()),
            ("receipt_count", status.receipt_count.into()),
            (
                "active_legal_hold_count",
                status.active_legal_hold_count.into(),
            ),
            ("retention_count", status.retention_count.into()),
            ("erasure_count", status.erasure_count.into()),
            (
                "checkpoint_anchor",
                checkpoint_anchor_value(&status.checkpoint_anchor),
            ),
        ]),
    )
}
fn object<const N: usize>(entries: [(&str, Value); N]) -> Value {
    let mut map = Map::new();
    for (key, value) in entries {
        map.insert(key.to_owned(), value);
    }
    Value::Object(map)
}
fn secure_json_response(status: StatusCode, body: Value) -> Response {
    let mut response = (status, JsonBody(body)).into_response();
    secure_private_headers(&mut response);
    response
}
fn fixed_error(status: StatusCode, code: &'static str) -> Response {
    secure_json_response(
        status,
        object([
            ("schema", "sorafs.evidence.error.v1".into()),
            ("error", code.into()),
        ]),
    )
}
fn service_disabled() -> Response {
    fixed_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "evidence_viewer_unavailable",
    )
}
fn service_error(error: EvidenceViewerErrorV1) -> Response {
    let (status, code) = match error {
        EvidenceViewerErrorV1::InvalidConfig
        | EvidenceViewerErrorV1::InvalidCheckpoint
        | EvidenceViewerErrorV1::CheckpointUnavailable
        | EvidenceViewerErrorV1::StateUnavailable
        | EvidenceViewerErrorV1::RuntimeUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "evidence_viewer_unavailable",
        ),
        EvidenceViewerErrorV1::InvalidRequest => {
            (StatusCode::BAD_REQUEST, "invalid_evidence_request")
        }
        EvidenceViewerErrorV1::CheckpointChanged => {
            (StatusCode::CONFLICT, "evidence_checkpoint_changed")
        }
        EvidenceViewerErrorV1::Forbidden => {
            (StatusCode::FORBIDDEN, "evidence_authorization_denied")
        }
        EvidenceViewerErrorV1::AuthenticationRejected => {
            (StatusCode::UNAUTHORIZED, "evidence_authentication_rejected")
        }
        EvidenceViewerErrorV1::NotFound => (StatusCode::NOT_FOUND, "evidence_resource_not_found"),
        EvidenceViewerErrorV1::SessionInactive => {
            (StatusCode::CONFLICT, "evidence_session_inactive")
        }
        EvidenceViewerErrorV1::LegalHoldPrecedence => {
            (StatusCode::CONFLICT, "legal_hold_precedence")
        }
        EvidenceViewerErrorV1::RetentionActive => {
            (StatusCode::CONFLICT, "evidence_retention_active")
        }
        EvidenceViewerErrorV1::ResourceExhausted => {
            (StatusCode::TOO_MANY_REQUESTS, "evidence_resource_exhausted")
        }
    };
    fixed_error(status, code)
}
fn secure_private_headers(response: &mut Response) {
    let headers = response.headers_mut();
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("private, no-store, no-cache, must-revalidate, max-age=0"),
    );
    headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert("expires", HeaderValue::from_static("0"));
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'; \
             object-src 'none'; worker-src 'none'; manifest-src 'none'",
        ),
    );
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static(
            "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), \
             clipboard-read=(), clipboard-write=()",
        ),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        "access-control-expose-headers",
        HeaderValue::from_static(EXPOSED_EVIDENCE_HEADERS),
    );
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn insert_secret_header(
    response: &mut Response,
    name: &'static str,
    value: &str,
) -> Result<(), Response> {
    let mut value = HeaderValue::from_str(value).map_err(|_| {
        fixed_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "runtime_secret_unavailable",
        )
    })?;
    value.set_sensitive(true);
    response.headers_mut().insert(name, value);
    Ok(())
}
fn insert_hex_header(response: &mut Response, name: &'static str, value: [u8; 32]) {
    if let Ok(value) = HeaderValue::from_str(&hex::encode(value)) {
        response.headers_mut().insert(name, value);
    }
}
fn static_asset_response(content_type: &'static str, body: &'static str) -> Response {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    secure_private_headers(&mut response);
    response.headers_mut().insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'; \
             script-src 'self'; style-src 'self'; connect-src 'none'; img-src 'none'; \
             media-src 'none'; object-src 'none'; worker-src 'none'; manifest-src 'none'",
        ),
    );
    response.headers_mut().insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    response.headers_mut().insert(
        "cross-origin-embedder-policy",
        HeaderValue::from_static("require-corp"),
    );
    response
        .headers_mut()
        .insert("x-frame-options", HeaderValue::from_static("SAMEORIGIN"));
    response
}
fn network_time_now_ms() -> u64 {
    iroha_core::time::now()
        .now
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default()
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn healthy_network_time_now_ms() -> Result<u64, Response> {
    healthy_network_time_ms(iroha_core::time::now())
}
#[expect(
    clippy::result_large_err,
    reason = "HTTP rejections retain the complete Axum response at this transport boundary."
)]
fn healthy_network_time_ms(status: iroha_core::time::NetworkTimeStatus) -> Result<u64, Response> {
    if !status.health.healthy || status.fallback {
        return Err(fixed_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "network_time_unhealthy",
        ));
    }
    status
        .now
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or_else(|| fixed_error(StatusCode::SERVICE_UNAVAILABLE, "network_time_unavailable"))
}
const EVIDENCE_VIEWER_HTML: &str = include_str!("assets/evidence_viewer_v1/index.html");
const EVIDENCE_VIEWER_CSS: &str = include_str!("assets/evidence_viewer_v1/app.css");
const EVIDENCE_VIEWER_JS: &str = include_str!("assets/evidence_viewer_v1/app.js");
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn evidence_auth_rejects_foreign_exact_network() {
        let _guard = crate::tests_runtime_handlers::app_auth_test_guard(
            crate::app_auth::CanonicalRequestAuthConfig::default(),
        );
        let method = Method::POST;
        let uri: Uri = "/v1/evidence/interactions"
            .parse()
            .expect("evidence interaction URI");
        let body = b"{}";
        let (state, headers) = crate::tests_runtime_handlers::foreign_network_signed_app_fixture(
            &method, &uri, body, 0xD1, 0xE1,
        );
        let response = require_canonical_auth(&state, &headers, &method, &uri, body)
            .expect_err("foreign-network evidence authorization must fail closed");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    #[test]
    fn irreversible_erasure_time_fails_closed_on_nts_fallback() {
        let status = iroha_core::time::NetworkTimeStatus {
            now: UNIX_EPOCH,
            offset_ms: 0,
            confidence_ms: 0,
            sample_count: 0,
            peer_count: 0,
            fallback: true,
            health: iroha_core::time::NtsHealth {
                min_samples_ok: false,
                offset_ok: true,
                confidence_ok: true,
                healthy: false,
            },
        };
        let response = healthy_network_time_ms(status).expect_err("fallback time must fail closed");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
    #[test]
    fn embedded_viewer_is_no_store_and_disables_offline_execution() {
        let response = static_asset_response("text/html; charset=utf-8", EVIDENCE_VIEWER_HTML);
        let cache_control = response
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok())
            .expect("cache-control");
        assert!(cache_control.contains("no-store"));
        let csp = response
            .headers()
            .get("content-security-policy")
            .and_then(|value| value.to_str().ok())
            .expect("content security policy");
        assert!(csp.contains("worker-src 'none'"));
        assert!(csp.contains("connect-src 'none'"));
        assert!(csp.contains("frame-ancestors 'self'"));
        assert!(!EVIDENCE_VIEWER_HTML.contains("download"));
        assert!(!EVIDENCE_VIEWER_JS.contains("localStorage"));
        assert!(!EVIDENCE_VIEWER_JS.contains("indexedDB"));
        assert!(!EVIDENCE_VIEWER_JS.contains("serviceWorker"));
        assert!(!EVIDENCE_VIEWER_JS.contains("caches."));
    }
    #[test]
    fn evidence_hex_and_event_inputs_are_canonical_and_bounded() {
        assert_eq!(
            parse_hex_fixed::<2>("00ff", "hex").expect("canonical lowercase"),
            [0, 255]
        );
        assert!(parse_hex_fixed::<2>("00FF", "hex").is_err());
        assert!(parse_hex_fixed::<2>("ff", "hex").is_err());
        assert!(parse_nonzero_digest(&"00".repeat(32), "digest").is_err());
        assert!(parse_interaction_kind("viewed").is_ok());
        assert!(parse_interaction_kind("session_expired").is_err());
    }
    #[test]
    fn evidence_simple_queries_have_one_bounded_literal_wire_spelling() {
        let digest = hex::encode([0xab; 32]);
        let canonical: Uri =
            format!("/v1/evidence/sessions/00/manifest?idempotency_key_hex={digest}")
                .parse()
                .expect("canonical evidence query URI");
        assert_eq!(
            exact_query(&canonical, &["idempotency_key_hex"]).expect("canonical evidence query")["idempotency_key_hex"],
            digest
        );

        let invalid_queries = [
            String::new(),
            "idempotency_key_hex".to_owned(),
            "idempotency_key_hex=".to_owned(),
            format!("idempotency_key_hex={digest}&"),
            format!("&idempotency_key_hex={digest}"),
            format!("idempotency_key_hex={digest}&&limit=1"),
            format!("idempotency_key_hex={digest}&idempotency_key_hex={digest}"),
            format!("idempotency_key_hex={digest}=suffix"),
            format!("idempotency_key_hex=%61{}", &digest[1..]),
            format!("idempotency+key+hex={digest}"),
            format!("unknown={digest}"),
            "x".repeat(MAX_AUDIT_QUERY_BYTES + 1),
        ];
        for raw in invalid_queries {
            let uri: Uri = format!("/v1/evidence/sessions/00/manifest?{raw}")
                .parse()
                .expect("query corpus is URI-safe");
            assert!(
                exact_query(&uri, &["idempotency_key_hex"]).is_err(),
                "query unexpectedly accepted: {raw}"
            );
        }
    }
    #[test]
    fn evidence_audit_query_has_one_canonical_checkpoint_bound_wire() {
        let checkpoint_digest = [0xCE; 32];
        let checkpoint_digest_hex = hex::encode(checkpoint_digest);
        let genesis = parse_evidence_audit_query(
            &format!(
                "/v1/evidence/audit?expected_checkpoint_digest_hex={checkpoint_digest_hex}&limit=256"
            )
                .parse()
                .expect("genesis audit URI"),
        )
        .expect("genesis cursor");
        assert_eq!(
            genesis,
            EvidenceAuditQueryV1 {
                expected_checkpoint_digest: checkpoint_digest,
                predecessor: None,
                limit: 256,
            }
        );
        let receipt_digest = [0xAB; 32];
        let exact_uri = format!(
            "/v1/evidence/audit?expected_checkpoint_digest_hex={checkpoint_digest_hex}&after_sequence=7&after_receipt_digest_hex={}&limit=1",
            hex::encode(receipt_digest)
        )
        .parse()
        .expect("exact audit cursor URI");
        assert_eq!(
            parse_evidence_audit_query(&exact_uri).expect("exact predecessor cursor"),
            EvidenceAuditQueryV1 {
                expected_checkpoint_digest: checkpoint_digest,
                predecessor: Some(EvidenceViewerReceiptCursorV1 {
                    sequence: 7,
                    receipt_digest,
                }),
                limit: 1,
            }
        );
        let valid_digest = hex::encode([0xCD; 32]);
        let invalid_queries = [
            String::new(),
            "limit=1".to_owned(),
            format!("expected_checkpoint_digest_hex={checkpoint_digest_hex}"),
            format!("expected_checkpoint_digest_hex={}&limit=1", "00".repeat(32)),
            format!("expected_checkpoint_digest_hex={}&limit=1", "CE".repeat(32)),
            format!("expected_checkpoint_digest_hex={checkpoint_digest_hex}&after_sequence=7"),
            format!(
                "expected_checkpoint_digest_hex={checkpoint_digest_hex}&after_receipt_digest_hex={valid_digest}&limit=1"
            ),
            format!(
                "expected_checkpoint_digest_hex={checkpoint_digest_hex}&after_sequence=0&after_receipt_digest_hex={valid_digest}&limit=1"
            ),
            format!(
                "expected_checkpoint_digest_hex={checkpoint_digest_hex}&after_sequence=07&after_receipt_digest_hex={valid_digest}&limit=1"
            ),
            format!(
                "expected_checkpoint_digest_hex={checkpoint_digest_hex}&after_sequence=7&after_receipt_digest_hex={}&limit=1",
                "00".repeat(32)
            ),
            format!(
                "expected_checkpoint_digest_hex={checkpoint_digest_hex}&after_sequence=7&after_receipt_digest_hex={}&limit=1",
                "AB".repeat(32)
            ),
            format!(
                "expected_checkpoint_digest_hex={checkpoint_digest_hex}&after_sequence=7&after_receipt_digest_hex={}&limit=1",
                "ab".repeat(31)
            ),
            format!(
                "expected_checkpoint_digest_hex={checkpoint_digest_hex}&after_sequence=7&after_receipt_digest_hex={valid_digest}&after_receipt_digest_hex={valid_digest}&limit=1"
            ),
            format!(
                "expected_checkpoint_digest_hex={checkpoint_digest_hex}&after_sequence=7&after_receipt_digest_hex={valid_digest}&legacy=1"
            ),
            format!("expected_checkpoint_digest_hex={checkpoint_digest_hex}&limit=0"),
            format!(
                "expected_checkpoint_digest_hex={checkpoint_digest_hex}&limit={}",
                MAX_AUDIT_PAGE + 1
            ),
            format!("limit=1&expected_checkpoint_digest_hex={checkpoint_digest_hex}"),
            format!(
                "expected_checkpoint_digest_hex={checkpoint_digest_hex}&after_receipt_digest_hex={valid_digest}&after_sequence=7&limit=1"
            ),
            format!("expected_checkpoint_digest_hex={checkpoint_digest_hex}&limit=1&"),
            format!("expected_checkpoint_digest_hex={checkpoint_digest_hex}&&limit=1"),
            format!("%65xpected_checkpoint_digest_hex={checkpoint_digest_hex}&limit=1"),
            format!("expected_checkpoint_digest_hex={checkpoint_digest_hex}+&limit=1"),
            format!(
                "expected_checkpoint_digest_hex={checkpoint_digest_hex}&after_sequence=7&after_receipt_digest_hex={valid_digest}"
            ),
        ];
        for query in invalid_queries {
            let uri = format!("/v1/evidence/audit?{query}")
                .parse()
                .expect("adversarial audit URI");
            let response =
                parse_evidence_audit_query(&uri).expect_err("invalid cursor must fail closed");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{query}");
        }
        assert_eq!(
            parse_evidence_audit_query(
                &"/v1/evidence/audit"
                    .parse()
                    .expect("missing-query audit URI")
            )
            .expect_err("missing query must fail closed")
            .status(),
            StatusCode::BAD_REQUEST
        );
        let oversized = format!(
            "/v1/evidence/audit?expected_checkpoint_digest_hex={checkpoint_digest_hex}&limit=1{}",
            "x".repeat(MAX_AUDIT_QUERY_BYTES)
        )
        .parse()
        .expect("oversized-query audit URI");
        assert_eq!(
            parse_evidence_audit_query(&oversized)
                .expect_err("oversized query must fail closed")
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    #[tokio::test]
    async fn evidence_audit_response_exposes_only_exact_cursors() {
        let cursor = EvidenceViewerReceiptCursorV1 {
            sequence: 9,
            receipt_digest: [0xA9; 32],
        };
        let projection = EvidenceViewerTransparencyProjectionV1 {
            version: 1,
            checkpoint_anchor: EvidenceViewerSignedCheckpointAnchorV1 {
                version: 1,
                checkpoint_generation: 9,
                predecessor_checkpoint_revision: Some([0xE8; 32]),
                predecessor_checkpoint_digest: Some([0xC6; 32]),
                checkpoint_digest: [0xC7; 32],
                receipt_count: 9,
                chain_head: Some(cursor),
                compaction_archive_head_digest: None,
                checkpoint_store_handle: "sealed-cas:production-evidence-checkpoint".to_owned(),
                checkpoint_store_revision: 3,
                checkpoint_store_policy_digest: [0xA7; 32],
                signer_handle: "provider:production-evidence-checkpoint".to_owned(),
                signer_public_key: [0xB7; 32],
                signature: [0x97; 64],
            },
            compaction_archive_head: None,
            predecessor: Some(cursor),
            page_limit: 17,
            receipts: Vec::new(),
            next_cursor: Some(cursor),
            has_more: false,
            projection_digest: [0xD7; 32],
        };
        let response = audit_projection_response(&projection);
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .expect("collect audit projection response");
        let value: Value = json::from_slice(&body).expect("decode audit projection response");
        let cursor_digest_hex = hex::encode(cursor.receipt_digest);
        let projection_digest_hex = hex::encode(projection.projection_digest);
        assert_eq!(
            value.get("schema").and_then(Value::as_str),
            Some("sorafs.evidence.audit_transparency_projection.v1")
        );
        for field in ["predecessor", "next_cursor"] {
            let exact = value
                .get(field)
                .and_then(Value::as_object)
                .unwrap_or_else(|| panic!("{field} exact cursor"));
            assert_eq!(exact.get("sequence").and_then(Value::as_u64), Some(9));
            assert_eq!(
                exact.get("receipt_digest_hex").and_then(Value::as_str),
                Some(cursor_digest_hex.as_str())
            );
        }
        assert_eq!(
            value.get("projection_digest_hex").and_then(Value::as_str),
            Some(projection_digest_hex.as_str())
        );
        assert_eq!(value.get("has_more").and_then(Value::as_bool), Some(false));
        assert_eq!(value.get("page_limit").and_then(Value::as_u64), Some(17));
        assert!(
            value
                .get("projection_norito_b64")
                .and_then(Value::as_str)
                .is_some()
        );
        let anchor = value
            .get("checkpoint_anchor")
            .and_then(Value::as_object)
            .expect("signed checkpoint anchor");
        let checkpoint_digest_hex = hex::encode([0xC7; 32]);
        assert_eq!(
            anchor.get("checkpoint_generation").and_then(Value::as_u64),
            Some(9)
        );
        assert_eq!(anchor.get("receipt_count").and_then(Value::as_u64), Some(9));
        assert_eq!(
            anchor.get("checkpoint_digest_hex").and_then(Value::as_str),
            Some(checkpoint_digest_hex.as_str())
        );
        assert!(
            value
                .get("compaction_archive_head")
                .is_some_and(Value::is_null)
        );
        assert!(
            value
                .get("receipts")
                .and_then(Value::as_array)
                .is_some_and(std::vec::Vec::is_empty)
        );
        assert!(value.get("after_sequence").is_none());
        assert!(value.get("next_after").is_none());
        assert!(value.get("next_sequence").is_none());
        assert!(value.get("limit").is_none());
    }
    #[tokio::test]
    async fn evidence_status_exposes_one_exact_signed_checkpoint_anchor() {
        let cursor = EvidenceViewerReceiptCursorV1 {
            sequence: 4,
            receipt_digest: [0xA4; 32],
        };
        let status = EvidenceViewerAuditStatusV1 {
            version: 1,
            challenge_count: 2,
            session_count: 3,
            receipt_count: 4,
            active_legal_hold_count: 1,
            erasure_count: 0,
            retention_count: 1,
            checkpoint_anchor: EvidenceViewerSignedCheckpointAnchorV1 {
                version: 1,
                checkpoint_generation: 4,
                predecessor_checkpoint_revision: Some([0xE3; 32]),
                predecessor_checkpoint_digest: Some([0xC3; 32]),
                checkpoint_digest: [0xC4; 32],
                receipt_count: 4,
                chain_head: Some(cursor),
                compaction_archive_head_digest: None,
                checkpoint_store_handle: "sealed-cas:production-evidence-checkpoint".to_owned(),
                checkpoint_store_revision: 3,
                checkpoint_store_policy_digest: [0xA4; 32],
                signer_handle: "provider:production-evidence-checkpoint".to_owned(),
                signer_public_key: [0xB4; 32],
                signature: [0x94; 64],
            },
        };
        let response = audit_status_response(&status);
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .expect("collect audit status response");
        let value: Value = json::from_slice(&body).expect("decode audit status response");
        let anchor = value
            .get("checkpoint_anchor")
            .and_then(Value::as_object)
            .expect("signed checkpoint anchor");
        assert_eq!(anchor.get("receipt_count").and_then(Value::as_u64), Some(4));
        assert_eq!(
            anchor
                .get("chain_head")
                .and_then(Value::as_object)
                .and_then(|head| head.get("sequence"))
                .and_then(Value::as_u64),
            Some(4)
        );
        assert!(
            value
                .get("status_norito_b64")
                .and_then(Value::as_str)
                .is_some()
        );
        for retired_duplicate in [
            "latest_receipt_sequence",
            "latest_receipt_digest_hex",
            "checkpoint_digest_hex",
            "receipt_signer_handle",
            "receipt_signer_public_key_hex",
        ] {
            assert!(
                value.get(retired_duplicate).is_none(),
                "status must expose signer/head data only through the exact anchor"
            );
        }
    }
    #[test]
    fn changed_checkpoint_is_an_explicit_restart_conflict() {
        let response = service_error(EvidenceViewerErrorV1::CheckpointChanged);
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }
    #[test]
    fn opaque_response_headers_are_marked_sensitive() {
        let mut response = Response::new(Body::empty());
        insert_secret_header(&mut response, HEADER_EVIDENCE_GRANT, "opaque-token")
            .expect("valid secret header");
        assert!(
            response
                .headers()
                .get(HEADER_EVIDENCE_GRANT)
                .expect("grant header")
                .is_sensitive()
        );
    }
    #[test]
    fn opaque_request_secrets_reject_duplicate_header_lines() {
        let grant_parser: fn(&HeaderMap) -> Result<OpaqueEvidenceViewerSecretV1, Response> =
            grant_from_headers;
        for (name, parse) in [
            (HEADER_EVIDENCE_GRANT, grant_parser),
            (HEADER_EVIDENCE_CHALLENGE, challenge_from_headers),
        ] {
            let mut headers = HeaderMap::new();
            headers.append(name, HeaderValue::from_static("first-secret"));
            headers.append(name, HeaderValue::from_static("second-secret"));

            let response = match parse(&headers) {
                Ok(_) => panic!("duplicate secret headers must fail closed"),
                Err(response) => response,
            };
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
    }
    #[tokio::test]
    async fn active_retention_is_a_payload_free_conflict() {
        let response = service_error(EvidenceViewerErrorV1::RetentionActive);
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let cache_control = response
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok())
            .expect("cache-control");
        assert!(cache_control.contains("no-store"));
        let body = axum::body::to_bytes(response.into_body(), 1_024)
            .await
            .expect("collect retention error");
        let body = std::str::from_utf8(&body).expect("error body is UTF-8 JSON");
        assert!(body.contains("sorafs.evidence.error.v1"));
        assert!(body.contains("evidence_retention_active"));
        assert!(!body.contains("quarantine"));
        assert!(!body.contains("account"));
    }
}
