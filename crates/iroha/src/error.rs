//! Canonical structured errors returned by the Rust SDK.

use std::time::Duration;

use iroha_crypto::PublicKey;
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    transaction::{TransactionDomain, signed::TransactionSignatureError},
};
pub use iroha_torii_shared::status::StatusFailureReason;
use iroha_torii_shared::{
    ErrorEnvelope,
    list_query::{LIST_QUERY_MEMBERS, ListQueryError},
};
use norito::json::{Map, Value};
use thiserror::Error;

/// Canonical result returned by structured Rust SDK operations.
pub type Result<T> = core::result::Result<T, Error>;

/// Machine-readable cause of a transport failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportErrorKind {
    /// The underlying I/O failure category, recovered from the complete cause chain.
    Io(std::io::ErrorKind),
    /// A transport failure without a standard I/O cause.
    Other,
}

/// Canonical structured Rust SDK error family.
///
/// Operations that have not yet migrated to this family remain an explicit
/// first-release redesign gap; new structured operation errors belong here.
/// Each error owns its original response or decoder cause. Inspect variants and
/// their fields; errors are moved rather than cloned or compared as whole values.
#[derive(Debug, Error)]
pub enum Error {
    /// The default HTTP transport could not be constructed.
    #[error("HTTP transport construction failed: {details}")]
    TransportConstruction {
        /// Construction diagnostic without runtime credentials.
        details: String,
    },
    /// The immutable client context has an invalid endpoint or authority binding.
    #[error(transparent)]
    Context(#[from] crate::client::AuthorityContextError),
    /// A request cannot be represented or violates a local operation contract.
    #[error("{operation} request is invalid: {details}")]
    InvalidRequest {
        /// Canonical operation whose request failed.
        operation: &'static str,
        /// Local validation diagnostic.
        details: String,
    },
    /// Canonical HTTP request authentication could not be produced.
    #[error("{operation} request signing failed: {details}")]
    RequestSigning {
        /// Canonical operation whose authentication failed.
        operation: &'static str,
        /// Signing diagnostic without private key material.
        details: String,
    },
    /// One HTTP dispatch or response read failed.
    #[error("{operation} transport failed: {details}")]
    Transport {
        /// Canonical operation whose dispatch failed.
        operation: &'static str,
        /// Transport failure category, independent of display formatting.
        kind: TransportErrorKind,
        /// Transport diagnostic.
        details: String,
    },
    /// The operation deadline expired.
    #[error("{operation} timed out")]
    Timeout {
        /// Canonical operation whose deadline expired.
        operation: &'static str,
    },
    /// A collection query was rejected locally before dispatch.
    ///
    /// [`ListQueryError::code`] is the code Torii would return for the same query.
    #[error("{operation} query is invalid: {error}")]
    InvalidListQuery {
        /// Canonical operation whose query failed validation.
        operation: &'static str,
        /// The offending control and how to fix it.
        error: ListQueryError,
    },
    /// Torii rejected the request with its canonical `{code, message, details}` envelope.
    #[error(
        "{operation} returned HTTP {status}: {code}: {message}",
        status = .error.status(),
        code = .error.code(),
        message = .error.message()
    )]
    Api {
        /// Canonical operation rejected by Torii.
        operation: &'static str,
        /// Decoded envelope with its HTTP status and response hints.
        error: Box<ApiError>,
    },
    /// Torii returned a non-successful HTTP response without a decodable error envelope.
    #[error("{operation} returned HTTP {status}")]
    Http {
        /// Canonical operation rejected by Torii.
        operation: &'static str,
        /// HTTP status code.
        status: u16,
        /// One valid Retry-After delta in seconds, when supplied. This never triggers a retry.
        retry_after: Option<std::time::Duration>,
        /// Exact bounded API response body, including machine-readable error fields.
        body: Vec<u8>,
    },
    /// GET `/status` is unavailable, with no retained response body or arbitrary header text.
    #[error(
        "diagnostic.status returned HTTP 503 ({reason_code})",
        reason_code = .reason.map_or("unclassified", StatusFailureReason::code)
    )]
    StatusUnavailable {
        /// Recognized producer reason; missing, invalid or unknown codes are unclassified.
        reason: Option<StatusFailureReason>,
        /// One valid Retry-After delta in seconds. This never triggers a retry.
        retry_after: Option<std::time::Duration>,
    },
    /// The response cannot be decoded under the operation's canonical schema.
    #[error("{operation} response decoding failed: {details}")]
    Decode {
        /// Canonical operation whose response failed.
        operation: &'static str,
        /// Codec or content-negotiation diagnostic.
        details: String,
    },
    /// Canonical response decoding failed, preserving the original attempt and its scope.
    #[error("{operation} canonical response decoding failed: {source}")]
    CanonicalDecode {
        /// Canonical operation whose response failed.
        operation: &'static str,
        /// Original canonical decoder failure, classified before its scopes unwind.
        #[source]
        source: norito::core::DecodeAttemptError,
    },
    /// A native finality frame is invalid or its original decoder resources are unavailable.
    #[error("{operation} native finality decoding failed: {source}")]
    NativeFinalityDecode {
        /// Canonical operation whose native source failed.
        operation: &'static str,
        /// Original native decoder failure; malformed input and local refusal remain distinct.
        #[source]
        source: iroha_data_model::sumeragi::finality::NativeFinalityDecodeError,
    },
    /// A WebSocket peer violated the canonical stream protocol.
    #[error("{operation} stream protocol failed: {details}")]
    StreamProtocol {
        /// Canonical stream operation.
        operation: &'static str,
        /// Protocol diagnostic without request credentials.
        details: String,
    },
    /// A WebSocket stream ended without normal completion.
    #[error("{operation} stream closed with code {code:?}: {reason}")]
    StreamClosed {
        /// Canonical stream operation.
        operation: &'static str,
        /// Peer close status, or absence of a valid close handshake.
        code: Option<u16>,
        /// Bounded peer diagnostic.
        reason: String,
    },
    /// The KAGEMUSHA enrollment service reported a closed non-success outcome: a terminal
    /// refusal with its reason, withheld delivery of an Issued outcome, or an unknown outcome
    /// after a possible effect. Identical HTTP statuses carry different outcomes.
    #[error("{operation} reported enrollment outcome {outcome:?}")]
    EnrollmentOutcome {
        /// Canonical operation that reported the outcome.
        operation: &'static str,
        /// Exact closed outcome read from the response headers.
        outcome: iroha_torii_shared::kagemusha_enrollment::EnrollmentServiceOutcomeV1,
    },
    /// A returned draft or read result does not match the exact request.
    #[error("{operation} response does not bind {field}")]
    ResponseBinding {
        /// Canonical operation whose response is inconsistent.
        operation: &'static str,
        /// Exact field or invariant that failed verification.
        field: &'static str,
    },
    /// A transport attempted to retain more than the configured response bound.
    #[error("response exceeds the {maximum} byte limit")]
    ResponseTooLarge {
        /// Maximum permitted response bytes.
        maximum: usize,
        /// Observed length, when representable and available.
        actual: Option<usize>,
    },
    /// The explicit blocking facade cannot run in the caller's runtime.
    #[error(transparent)]
    Blocking(#[from] crate::blocking::BlockingCallError),
    /// The owned blocking runtime could not be constructed.
    #[error("blocking runtime construction failed: {details}")]
    BlockingRuntimeConstruction {
        /// Runtime builder diagnostic.
        details: String,
    },
    /// Local transaction preparation failed.
    #[error("transaction preparation failed: {0}")]
    TransactionPreparation(#[from] TransactionPreparationError),
    /// Local transaction signing failed.
    #[error("transaction signing failed: {0}")]
    TransactionSigning(#[from] TransactionSigningError),
}

impl Error {
    /// Stable machine-readable code of a Torii rejection or of a locally rejected
    /// collection query, for example `invalid_filter`.
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::Api { error, .. } => Some(error.code()),
            Self::InvalidListQuery { error, .. } => Some(error.code()),
            _ => None,
        }
    }

    /// The decoded Torii error envelope, when Torii returned one.
    #[must_use]
    pub fn api_error(&self) -> Option<&ApiError> {
        match self {
            Self::Api { error, .. } => Some(error),
            _ => None,
        }
    }

    /// HTTP status of a Torii rejection.
    #[must_use]
    pub fn http_status(&self) -> Option<u16> {
        match self {
            Self::Api { error, .. } => Some(error.status()),
            Self::Http { status, .. } => Some(*status),
            Self::StatusUnavailable { .. } => Some(503),
            _ => None,
        }
    }
}

/// Largest response body inspected for a Torii error envelope.
const MAX_ERROR_ENVELOPE_BYTES: usize = 64 * 1024;
/// Torii's machine-readable rejection-code header.
const REJECT_CODE_HEADER: &str = "x-iroha-reject-code";

/// Torii's canonical `{code, message, details}` error envelope with its HTTP status.
///
/// `code` is stable and machine-readable; `message` is meant for people.
/// Collection queries reject malformed controls with HTTP 400 and one of the
/// list-query codes (`invalid_query`, `invalid_filter`, `invalid_sort`,
/// `invalid_select`, `invalid_aggregate`, `invalid_limit`, `invalid_cursor`,
/// `invalid_include_total`); [`Self::list_query_control`] names the control.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiError {
    status: u16,
    code: String,
    message: String,
    details: Option<ApiErrorDetails>,
    reject_code: Option<String>,
    retry_after: Option<Duration>,
}

impl ApiError {
    /// Construct an envelope, for example to test error handling.
    #[must_use]
    pub fn new(status: u16, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status,
            code: code.into(),
            message: message.into(),
            details: None,
            reject_code: None,
            retry_after: None,
        }
    }

    /// Attach structured details.
    #[must_use]
    pub fn with_details(mut self, details: ApiErrorDetails) -> Self {
        self.details = Some(details);
        self
    }

    /// Decode the envelope of a failed response; `None` when the body is not one.
    ///
    /// JSON and canonical Norito envelopes are accepted. Unknown envelope members
    /// and detail members are retained or ignored, never rejected.
    pub(crate) fn from_response(response: &http::Response<Vec<u8>>) -> Option<Self> {
        let status = response.status();
        let body = response.body();
        if status.is_success() || body.is_empty() || body.len() > MAX_ERROR_ENVELOPE_BYTES {
            return None;
        }
        let headers = response.headers();
        let mut content_types = headers.get_all(http::header::CONTENT_TYPE).iter();
        let media_type = match (content_types.next(), content_types.next()) {
            (None, _) => None,
            (Some(value), None) => Some(
                value
                    .to_str()
                    .ok()?
                    .split(';')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_ascii_lowercase(),
            ),
            (Some(_), Some(_)) => return None,
        };
        let (code, message, details) = match media_type.as_deref() {
            Some("application/x-norito") => norito_envelope(body)?,
            None | Some("application/json") => json_envelope(body)?,
            Some(other) if other.starts_with("application/") && other.ends_with("+json") => {
                json_envelope(body)?
            }
            Some(_) => return None,
        };
        if code.is_empty() {
            return None;
        }
        Some(Self {
            status: status.as_u16(),
            code,
            message,
            details,
            reject_code: single_header(headers, REJECT_CODE_HEADER),
            retry_after: retry_after(headers),
        })
    }

    /// HTTP status code.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Stable machine-readable code, for example `invalid_cursor`.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Human-readable explanation, including a fix where one is obvious.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Structured context, when Torii supplied it.
    #[must_use]
    pub const fn details(&self) -> Option<&ApiErrorDetails> {
        self.details.as_ref()
    }

    /// The `x-iroha-reject-code` response header, when Torii sent exactly one.
    #[must_use]
    pub fn reject_code(&self) -> Option<&str> {
        self.reject_code.as_deref()
    }

    /// One valid `Retry-After` delta; a hint for caller policy that never causes a retry.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }

    /// The list-query control a collection-query code refers to: `filter` for
    /// `invalid_filter`, `cursor` for `invalid_cursor`, `query` for
    /// `invalid_query`, and `None` for every other code.
    #[must_use]
    pub fn list_query_control(&self) -> Option<&'static str> {
        LIST_QUERY_MEMBERS
            .into_iter()
            .chain(["query"])
            .find(|control| ListQueryError::new(control, String::new()).code() == self.code)
    }
}

/// Structured `details` member of a Torii error envelope.
///
/// Collection-query errors set [`Self::field`] to the offending control; when a
/// data field is at fault, [`Self::actual`] names it and [`Self::expected`]
/// lists the accepted fields. Other members remain available through
/// [`Self::get`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ApiErrorDetails(Map);

impl ApiErrorDetails {
    /// Wrap the members of a `details` object.
    #[must_use]
    pub const fn new(members: Map) -> Self {
        Self(members)
    }

    /// The request control or field at fault (`details.field`).
    #[must_use]
    pub fn field(&self) -> Option<&str> {
        self.text("field")
    }

    /// What was expected (`details.expected`), for example the accepted fields.
    #[must_use]
    pub fn expected(&self) -> Option<&str> {
        self.text("expected")
    }

    /// What was received (`details.actual`).
    #[must_use]
    pub fn actual(&self) -> Option<&str> {
        self.text("actual")
    }

    /// Actionable guidance (`details.hint`).
    #[must_use]
    pub fn hint(&self) -> Option<&str> {
        self.text("hint")
    }

    /// Any member of the `details` object.
    #[must_use]
    pub fn get(&self, member: &str) -> Option<&Value> {
        self.0.get(member)
    }

    /// Every member of the `details` object.
    #[must_use]
    pub const fn members(&self) -> &Map {
        &self.0
    }

    fn text(&self, member: &str) -> Option<&str> {
        self.0.get(member).and_then(Value::as_str)
    }
}

type DecodedEnvelope = (String, String, Option<ApiErrorDetails>);

fn json_envelope(body: &[u8]) -> Option<DecodedEnvelope> {
    let Value::Object(mut envelope) =
        norito::json::parse_value(core::str::from_utf8(body).ok()?).ok()?
    else {
        return None;
    };
    let Some(Value::String(code)) = envelope.remove("code") else {
        return None;
    };
    let Some(Value::String(message)) = envelope.remove("message") else {
        return None;
    };
    let details = match envelope.remove("details") {
        None | Some(Value::Null) => None,
        Some(Value::Object(details)) => Some(ApiErrorDetails(details)),
        Some(_) => return None,
    };
    Some((code, message, details))
}

fn norito_envelope(body: &[u8]) -> Option<DecodedEnvelope> {
    let envelope = norito::decode_canonical_with_limits::<ErrorEnvelope>(
        body,
        norito::canonical_decode_limits(body.len()),
    )
    .ok()?;
    let details = match envelope.details {
        None => None,
        Some(details) => match norito::json::to_value(&details).ok()? {
            Value::Object(members) => Some(ApiErrorDetails(members)),
            _ => return None,
        },
    };
    Some((envelope.code, envelope.message, details))
}

fn single_header(headers: &http::HeaderMap, name: &str) -> Option<String> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?.trim();
    (values.next().is_none() && !value.is_empty()).then(|| value.to_owned())
}

/// Classify a non-successful response: its typed envelope when Torii sent one,
/// otherwise the bounded raw body.
pub fn http_error(operation: &'static str, response: http::Response<Vec<u8>>) -> Error {
    if let Some(error) = ApiError::from_response(&response) {
        return Error::Api {
            operation,
            error: Box::new(error),
        };
    }
    Error::Http {
        operation,
        status: response.status().as_u16(),
        retry_after: retry_after(response.headers()),
        body: response.into_body(),
    }
}

/// Typed cause of a local account transaction preparation failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum TransactionPreparationError {
    /// The operating system entropy source failed while producing a nonce.
    #[error("nonce entropy source failed: {details}")]
    NonceEntropy {
        /// Complete entropy-source diagnostic.
        details: String,
    },
    /// Sixteen consecutive entropy samples produced the invalid zero nonce.
    #[error("nonce entropy source returned zero repeatedly")]
    NonceEntropyExhausted,
    /// The prepared payload violated a signature-bound transaction invariant.
    #[error("payload invariant failed: {source}")]
    InvalidPayload {
        /// Canonical data-model validation cause.
        #[source]
        source: TransactionSignatureError,
    },
    /// The declared proof attachments violated the signed attachment schema.
    #[error("signed attachments are invalid: {source}")]
    InvalidAttachments {
        /// Canonical data-model schema violation.
        #[source]
        source: iroha_data_model::transaction::SignedAttachmentErrorV1,
    },
}

/// Typed cause of a local account transaction signing failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum TransactionSigningError {
    /// A multisignature member context cannot create a complete direct signature.
    #[error("multisignature account `{authority}` requires an external threshold signature")]
    DirectSigningUnavailable {
        /// Bound multisignature authority.
        authority: AccountId,
    },
    /// The payload belongs to a different network or to the genesis-only domain.
    #[error("signing domain `{actual:?}` does not match network `{expected}`")]
    NetworkMismatch {
        /// Network bound to the immutable account context.
        expected: NetworkId,
        /// Domain carried by the exact payload.
        actual: TransactionDomain,
    },
    /// The payload authority differs from the immutable account context.
    #[error("authority `{actual}` does not match bound account `{expected}`")]
    AuthorityMismatch {
        /// Authority bound to the immutable account context.
        expected: AccountId,
        /// Authority carried by the exact payload.
        actual: AccountId,
    },
    /// Direct signing requires a single-key payload authority.
    #[error("authority `{authority}` cannot receive a direct signature")]
    AuthorityNotDirect {
        /// Non-direct authority carried by the payload.
        authority: AccountId,
    },
    /// The payload's direct controller differs from the context signing key.
    #[error("signing key does not control the exact payload authority")]
    KeyMismatch {
        /// Public key required by the payload authority.
        expected: PublicKey,
        /// Public key owned by the immutable account context.
        actual: PublicKey,
    },
    /// The supplied exact payload could not be reconstructed for signing.
    #[error("payload is not signable: {source}")]
    InvalidPayload {
        /// Canonical data-model validation cause.
        #[source]
        source: TransactionSignatureError,
    },
    /// The cryptographic signing backend rejected the payload.
    #[error("signature backend failed: {source}")]
    Signature {
        /// Canonical data-model signing cause.
        #[source]
        source: TransactionSignatureError,
    },
}

/// Parse the supported delta-seconds form without accepting duplicate or ambiguous hints.
pub fn retry_after(headers: &http::HeaderMap) -> Option<std::time::Duration> {
    let mut values = headers.get_all(http::header::RETRY_AFTER).iter();
    let raw = values.next()?.to_str().ok()?;
    if values.next().is_some() || raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    raw.parse::<u64>().ok().map(std::time::Duration::from_secs)
}

#[cfg(test)]
mod tests {
    #[test]
    fn retry_after_preserves_only_unambiguous_delta_seconds() {
        use http::{HeaderMap, HeaderValue, header::RETRY_AFTER};
        use std::time::Duration;
        let mut headers = HeaderMap::new();
        assert_eq!(super::retry_after(&headers), None);
        for (raw, expected) in [
            ("3", Some(Duration::from_secs(3))),
            ("0", Some(Duration::ZERO)),
            ("-1", None),
            ("+1", None),
            ("1,2", None),
            (" 1", None),
            ("", None),
            ("18446744073709551616", None),
            ("Wed, 21 Oct 2015 07:28:00 GMT", None),
        ] {
            headers.insert(RETRY_AFTER, HeaderValue::from_static(raw));
            assert_eq!(super::retry_after(&headers), expected, "{raw:?}");
        }
        headers.insert(RETRY_AFTER, HeaderValue::from_static("3"));
        headers.append(RETRY_AFTER, HeaderValue::from_static("3"));
        assert_eq!(super::retry_after(&headers), None);
    }
}
