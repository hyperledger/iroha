//! Canonical `transaction dispatch` outcome-unknown evidence and ambiguity classification.

use super::{
    APPLICATION_JSON, APPLICATION_NORITO, ErrorEnvelope, SIGNED_TRANSACTION_HASH_HEADER,
    TRANSACTION_DISPATCH_OUTCOME_UNKNOWN_ENVELOPE_CODE,
    TRANSACTION_DISPATCH_OUTCOME_UNKNOWN_REJECT_CODE, TRANSACTION_ENTRYPOINT_HASH_HEADER,
    TransactionDispatchOutcomeUnknownIdentity, exact_single_response_header,
};
use crate::http::{Response, StatusCode};
use eyre::Result;
use norito::{decode_from_bytes, to_bytes};

fn decode_canonical_transaction_dispatch_error_envelope(
    response: &Response<Vec<u8>>,
) -> Result<ErrorEnvelope, String> {
    let content_types = response
        .headers()
        .get_all(http::header::CONTENT_TYPE)
        .iter()
        .collect::<Vec<_>>();
    if content_types.len() != 1 {
        return Err(
            "transaction dispatch outcome-unknown content-type header is missing or duplicated"
                .to_owned(),
        );
    }
    let content_type = content_types[0].to_str().map_err(|_| {
        "transaction dispatch outcome-unknown content-type header is not valid text".to_owned()
    })?;
    let envelope = match content_type {
        APPLICATION_NORITO => {
            decode_from_bytes::<ErrorEnvelope>(response.body()).map_err(|_| {
                "transaction dispatch outcome-unknown Norito envelope is invalid".to_owned()
            })?
        }
        APPLICATION_JSON => {
            norito::json::from_slice::<ErrorEnvelope>(response.body()).map_err(|_| {
                "transaction dispatch outcome-unknown JSON envelope is invalid".to_owned()
            })?
        }
        _ => {
            return Err(
                "transaction dispatch outcome-unknown content type is not canonical Norito or JSON"
                    .to_owned(),
            );
        }
    };
    let canonical = if content_type == APPLICATION_NORITO {
        to_bytes(&envelope).map_err(|_| {
            "transaction dispatch outcome-unknown Norito envelope cannot be encoded".to_owned()
        })?
    } else {
        norito::json::to_vec(&envelope).map_err(|_| {
            "transaction dispatch outcome-unknown JSON envelope cannot be encoded".to_owned()
        })?
    };
    if canonical != response.body().as_slice() {
        return Err(
            "transaction dispatch outcome-unknown envelope bytes are not canonical".to_owned(),
        );
    }
    Ok(envelope)
}
pub(super) fn classify(
    response: &Response<Vec<u8>>,
    expected: &TransactionDispatchOutcomeUnknownIdentity,
) -> Result<Option<TransactionDispatchOutcomeUnknownIdentity>, String> {
    let envelope = decode_canonical_transaction_dispatch_error_envelope(response);
    if !claims_outcome_unknown(response) {
        return Ok(None);
    }
    let reject_headers = response
        .headers()
        .get_all("x-iroha-reject-code")
        .iter()
        .collect::<Vec<_>>();
    if response.status() != StatusCode::SERVICE_UNAVAILABLE {
        return Err(
            "transaction dispatch outcome-unknown evidence did not use 503 Service Unavailable"
                .to_owned(),
        );
    }
    if reject_headers.len() != 1
        || !reject_headers[0]
            .to_str()
            .is_ok_and(|value| value == TRANSACTION_DISPATCH_OUTCOME_UNKNOWN_REJECT_CODE)
    {
        return Err(
            "transaction dispatch outcome-unknown reject-code header is missing, duplicated, or invalid"
                .to_owned(),
        );
    }
    let envelope = envelope?;
    if envelope.code() != TRANSACTION_DISPATCH_OUTCOME_UNKNOWN_ENVELOPE_CODE {
        return Err("transaction dispatch outcome-unknown envelope code is invalid".to_owned());
    }
    let details = envelope.details.as_ref().ok_or_else(|| {
        "transaction dispatch outcome-unknown envelope is missing details".to_owned()
    })?;
    if details.reject_code.as_deref() != Some(TRANSACTION_DISPATCH_OUTCOME_UNKNOWN_REJECT_CODE) {
        return Err(
            "transaction dispatch outcome-unknown envelope reject code is invalid".to_owned(),
        );
    }
    let expected_entrypoint_hash = expected.entrypoint_hash.to_string();
    let entrypoint_hash_header = exact_single_response_header(
        response,
        TRANSACTION_ENTRYPOINT_HASH_HEADER,
    )
    .map_err(|_| {
        "transaction dispatch outcome-unknown entrypoint header is missing, duplicated, or invalid"
            .to_owned()
    })?;
    if entrypoint_hash_header != expected_entrypoint_hash {
        return Err(
            "transaction dispatch outcome-unknown entrypoint header does not match the submitted transaction"
                .to_owned(),
        );
    }
    if details.entrypoint_hash.as_deref() != Some(expected_entrypoint_hash.as_str()) {
        return Err(
            "transaction dispatch outcome-unknown entrypoint identity is missing or does not match the submitted transaction"
                .to_owned(),
        );
    }
    let expected_signed_transaction_hash = expected.signed_transaction_hash.to_string();
    let signed_transaction_hash_header =
        exact_single_response_header(response, SIGNED_TRANSACTION_HASH_HEADER).map_err(|_| {
            "transaction dispatch outcome-unknown signed-transaction header is missing, duplicated, or invalid"
                .to_owned()
        })?;
    if signed_transaction_hash_header != expected_signed_transaction_hash {
        return Err(
            "transaction dispatch outcome-unknown signed-transaction header does not match the submitted transaction"
                .to_owned(),
        );
    }
    if details.tx_hash.as_deref() != Some(expected_signed_transaction_hash.as_str()) {
        return Err(
            "transaction dispatch outcome-unknown signed-transaction identity is missing or does not match the submitted transaction"
                .to_owned(),
        );
    }
    Ok(Some(expected.clone()))
}
fn claims_outcome_unknown(response: &Response<Vec<u8>>) -> bool {
    // Claim detection is deliberately more permissive than evidence acceptance. A proxy that
    // damages the content type, byte canonicality, or one identity field still cannot turn an
    // indeterminate admission into a definite rejection that callers may safely resubmit.
    let claimed_envelope = decode_from_bytes::<ErrorEnvelope>(response.body())
        .ok()
        .or_else(|| norito::json::from_slice::<ErrorEnvelope>(response.body()).ok());
    let envelope_claims_outcome_unknown = claimed_envelope.as_ref().is_some_and(|envelope| {
        envelope.code() == TRANSACTION_DISPATCH_OUTCOME_UNKNOWN_ENVELOPE_CODE
            || envelope.details.as_ref().is_some_and(|details| {
                details.reject_code.as_deref()
                    == Some(TRANSACTION_DISPATCH_OUTCOME_UNKNOWN_REJECT_CODE)
            })
    });
    let body_claims_outcome_unknown = [
        TRANSACTION_DISPATCH_OUTCOME_UNKNOWN_ENVELOPE_CODE,
        TRANSACTION_DISPATCH_OUTCOME_UNKNOWN_REJECT_CODE,
    ]
    .into_iter()
    .any(|claim| {
        response
            .body()
            .windows(claim.len())
            .any(|window| window == claim.as_bytes())
    });
    let header_claims_outcome_unknown = response
        .headers()
        .get_all("x-iroha-reject-code")
        .iter()
        .any(|value| {
            value.to_str().is_ok_and(|value| {
                value == TRANSACTION_DISPATCH_OUTCOME_UNKNOWN_REJECT_CODE
                    || value == TRANSACTION_DISPATCH_OUTCOME_UNKNOWN_ENVELOPE_CODE
            })
        });
    // Successful transaction dispatch responses legitimately carry both identity headers. On a rejection,
    // those headers are reserved for outcome-unknown, so even damaged code/body evidence must
    // keep the locally computed identity ambiguous.
    let rejection_identity_headers_claim_outcome_unknown =
        !matches!(response.status(), StatusCode::OK | StatusCode::ACCEPTED)
            && (response
                .headers()
                .contains_key(TRANSACTION_ENTRYPOINT_HASH_HEADER)
                || response
                    .headers()
                    .contains_key(SIGNED_TRANSACTION_HASH_HEADER));
    envelope_claims_outcome_unknown
        || body_claims_outcome_unknown
        || header_claims_outcome_unknown
        || rejection_identity_headers_claim_outcome_unknown
}

/// What one canonical Torii rejection proves about a single dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DefiniteDispatchResult {
    /// The exact transaction is already queued or committed.
    AlreadyKnown,
    /// Admission refused the transaction: this dispatch did not admit it.
    Refused,
    /// Backpressure: not admitted, and the same signed bytes may be sent again.
    Deferred,
}

/// One rejection Torii emits for a transaction it did not admit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DefiniteDispatchRow {
    /// Exact HTTP status.
    pub(super) status: u16,
    /// Exact `ErrorEnvelope` code.
    pub(super) envelope_code: &'static str,
    /// Exact `x-iroha-reject-code` header value.
    pub(super) reject_code: &'static str,
    /// Whether the envelope details repeat the reject code.
    pub(super) details_repeat_reject_code: bool,
    /// What the rejection proves.
    pub(super) result: DefiniteDispatchResult,
}

const fn definite(
    status: u16,
    envelope_code: &'static str,
    reject_code: &'static str,
    details_repeat_reject_code: bool,
    result: DefiniteDispatchResult,
) -> DefiniteDispatchRow {
    DefiniteDispatchRow {
        status,
        envelope_code,
        reject_code,
        details_repeat_reject_code,
        result,
    }
}

/// Closed table of validated non-admissions.
///
/// It mirrors Torii's queue and stateless-admission rejections
/// (`crates/iroha_torii/src/queue_rejection_metadata.rs`); a test fails when a
/// queue rejection there is not classified here. Any response outside this
/// table proves nothing about admission and stays ambiguous: the node-side
/// failures `queue_governance_invalid`, `queue_nexus_fee_config_invalid` and
/// `queue_admission_invariant` and `sccp_forgery_unavailable` are deliberately absent.
pub(super) const DEFINITE_DISPATCH_ROWS: &[DefiniteDispatchRow] = {
    use DefiniteDispatchResult::{AlreadyKnown, Deferred, Refused};
    &[
        definite(
            409,
            "already_committed",
            "PRTRY:ALREADY_COMMITTED",
            true,
            AlreadyKnown,
        ),
        definite(
            409,
            "already_enqueued",
            "PRTRY:ALREADY_ENQUEUED",
            true,
            AlreadyKnown,
        ),
        definite(
            429,
            "admission_deferred",
            "PRTRY:ADMISSION_DEFERRED",
            false,
            Deferred,
        ),
        definite(429, "queue_full", "PRTRY:QUEUE_FULL", true, Deferred),
        definite(
            429,
            "queue_latency_saturated",
            "PRTRY:QUEUE_LATENCY",
            true,
            Deferred,
        ),
        definite(
            429,
            "per_user_queue_limit",
            "PRTRY:QUEUE_RATE",
            true,
            Deferred,
        ),
        definite(
            429,
            "sccp_forgery_throttled",
            "PRTRY:SCCP_FORGERY_THROTTLED",
            true,
            Deferred,
        ),
        // A duplicate offence does not identify this exact signed carrier as admitted.
        definite(
            409,
            "sccp_evidence_duplicate",
            "PRTRY:SCCP_EVIDENCE_DUPLICATE",
            true,
            Refused,
        ),
        definite(
            400,
            "sccp_evidence_rejected",
            "PRTRY:SCCP_EVIDENCE_REJECTED",
            true,
            Refused,
        ),
        definite(400, "transaction_expired", "ED07", true, Refused),
        definite(
            400,
            "transaction_rejected",
            "transaction_rejected",
            true,
            Refused,
        ),
        definite(
            400,
            "unsupported_transaction_admission",
            "PRTRY:UNSUPPORTED_TRANSACTION_ADMISSION",
            true,
            Refused,
        ),
        definite(
            400,
            "queue_unresolved_route",
            "PRTRY:ROUTE_UNRESOLVED",
            true,
            Refused,
        ),
        definite(
            403,
            "unregistered_authority",
            "PRTRY:UNREGISTERED_AUTHORITY",
            true,
            Refused,
        ),
        definite(
            403,
            "queue_governance_rejected",
            "PRTRY:QUEUE_GOVERNANCE_REJECTED",
            true,
            Refused,
        ),
        definite(
            403,
            "queue_lane_compliance_denied",
            "PRTRY:QUEUE_LANE_COMPLIANCE_DENIED",
            true,
            Refused,
        ),
        definite(
            403,
            "queue_lane_privacy_proof_rejected",
            "PRTRY:QUEUE_LANE_PRIVACY_PROOF_REJECTED",
            true,
            Refused,
        ),
        definite(
            422,
            "queue_nexus_fee_rejected",
            "PRTRY:NEXUS_FEE_ADMISSION_REJECTED",
            true,
            Refused,
        ),
    ]
};

/// Classify a non-acknowledging response as a validated non-admission, or `None`.
///
/// The response must carry exactly one canonical error envelope, exactly one
/// `x-iroha-reject-code` header, and status, envelope code and reject code must
/// match one table row exactly. A response that claims an unknown outcome is
/// handled by [`classify`] first and never reaches this function as a refusal.
pub(super) fn classify_definite(response: &Response<Vec<u8>>) -> Option<DefiniteDispatchResult> {
    if claims_outcome_unknown(response) {
        return None;
    }
    let envelope = decode_canonical_transaction_dispatch_error_envelope(response).ok()?;
    let reject_code = exact_single_response_header(response, "x-iroha-reject-code").ok()?;
    let details_reject_code = envelope
        .details
        .as_ref()
        .and_then(|details| details.reject_code.as_deref());
    DEFINITE_DISPATCH_ROWS
        .iter()
        .find(|row| {
            response.status().as_u16() == row.status
                && envelope.code() == row.envelope_code
                && reject_code == row.reject_code
                && details_reject_code == row.details_repeat_reject_code.then_some(row.reject_code)
        })
        .map(|row| row.result)
}
