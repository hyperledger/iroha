//! Utilities for Norito encoding and Axum integration.
use axum::{
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{CONTENT_TYPE, IF_NONE_MATCH},
    },
    response::{IntoResponse, Response},
};
use iroha_data_model::{
    query::{SignedQuery, json_wrappers::SignedQueryJson},
    transaction::{SignedTransaction, TransactionEntrypoint},
};
use iroha_torii_shared::ErrorEnvelope;
use iroha_version::Version;
#[cfg(test)]
use norito::json;
use norito::{
    json::{JsonSerialize, Value},
    prelude::*,
};
use std::{
    any::{Any, TypeId},
    future::Future,
    sync::Arc,
};
/// MIME used in Torii for Norito encoding
// note: no elegant way to associate it with generic `NoritoBody<T>`
pub const NORITO_MIME_TYPE: &str = "application/x-norito";
const JSON_MIME_TYPE: &str = "application/json";
pub(crate) const MAX_ERROR_MESSAGE_CHARACTERS: usize = 1024;
pub(crate) const MAX_ERROR_DETAIL_CHARACTERS: usize = 1024;
pub(crate) const MAX_REJECT_CODE_BYTES: usize = 128;

/// Current wall-clock time in Unix milliseconds, saturating at `u64::MAX`.
///
/// A clock before the Unix epoch reports `0`.
#[must_use]
pub(crate) fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
/// Count the leading zero bits of a big-endian byte string.
#[must_use]
pub(crate) fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut total = 0u32;
    for byte in bytes {
        if *byte == 0 {
            total += 8;
            continue;
        }
        total += byte.leading_zeros();
        break;
    }
    total
}
/// Whether `ip` is a globally routable unicast address (no private, loopback, link-local,
/// multicast, documentation, benchmarking, shared, reserved, or transition ranges).
#[must_use]
pub(crate) fn is_public_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => is_public_ipv4(ip),
        std::net::IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}
fn is_public_ipv4(ip: std::net::Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || a == 0
        || a >= 240
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && (18..=19).contains(&b)))
}
fn is_public_ipv6(ip: std::net::Ipv6Addr) -> bool {
    let segments = ip.segments();
    let documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;
    let documentation_v2 = segments[0] == 0x3fff && (segments[1] & 0xf000) == 0;
    let orchid = segments[0] == 0x2001 && (segments[1] & 0xfff0) == 0x0010;
    let transition = (segments[0] == 0x2001 && segments[1] == 0)
        || segments[0] == 0x2002
        || ip.to_ipv4_mapped().is_some();
    !((segments[0] & 0xe000) != 0x2000
        || ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || documentation
        || documentation_v2
        || orchid
        || transition)
}
/// Return whether any syntactically valid `If-None-Match` validator weakly matches `etag`.
///
/// Entity-tag opaque values are case-sensitive. A wildcard is accepted only as the sole
/// validator, matching the HTTP field grammar.
#[must_use]
pub(crate) fn if_none_match_matches(headers: &HeaderMap, etag: &str) -> bool {
    let Some(expected) = http_entity_tag_opaque(etag.as_bytes()) else {
        return false;
    };
    let mut token_count = 0_usize;
    let mut wildcard = false;
    let mut matched = false;
    for value in headers.get_all(IF_NONE_MATCH).iter() {
        let mut remaining = value.as_bytes();
        loop {
            while remaining
                .first()
                .is_some_and(|byte| matches!(*byte, b' ' | b'\t'))
            {
                remaining = &remaining[1..];
            }
            if remaining.is_empty() {
                return false;
            }
            token_count = match token_count.checked_add(1) {
                Some(count) => count,
                None => return false,
            };
            if let Some(rest) = remaining.strip_prefix(b"*") {
                wildcard = true;
                remaining = rest;
            } else {
                let after_prefix = remaining.strip_prefix(b"W/").unwrap_or(remaining);
                let Some(after_quote) = after_prefix.strip_prefix(b"\"") else {
                    return false;
                };
                let Some(closing_quote) = after_quote.iter().position(|byte| *byte == b'"') else {
                    return false;
                };
                let token_len = remaining.len() - after_quote.len() + closing_quote + 1;
                let token = &remaining[..token_len];
                let Some(candidate) = http_entity_tag_opaque(token) else {
                    return false;
                };
                matched |= candidate == expected;
                remaining = &remaining[token_len..];
            }
            while remaining
                .first()
                .is_some_and(|byte| matches!(*byte, b' ' | b'\t'))
            {
                remaining = &remaining[1..];
            }
            if remaining.is_empty() {
                break;
            }
            let Some(rest) = remaining.strip_prefix(b",") else {
                return false;
            };
            remaining = rest;
        }
    }
    token_count != 0 && if wildcard { token_count == 1 } else { matched }
}

fn http_entity_tag_opaque(tag: &[u8]) -> Option<&[u8]> {
    let tag = tag.strip_prefix(b"W/").unwrap_or(tag);
    let opaque = tag.strip_prefix(b"\"")?.strip_suffix(b"\"")?;
    opaque
        .iter()
        .all(|byte| *byte == 0x21 || (0x23..=0x7e).contains(byte) || *byte >= 0x80)
        .then_some(opaque)
}

#[cfg(test)]
mod cache_validator_tests {
    use super::if_none_match_matches;
    use axum::http::{HeaderMap, HeaderValue, header::IF_NONE_MATCH};

    #[test]
    fn if_none_match_supports_lists_repeated_fields_weak_tags_and_wildcard() {
        let mut headers = HeaderMap::new();
        headers.append(IF_NONE_MATCH, HeaderValue::from_static("\"stale\""));
        headers.append(
            IF_NONE_MATCH,
            HeaderValue::from_static("W/\"proof:abc\", \"other\""),
        );
        assert!(if_none_match_matches(&headers, "\"proof:abc\""));

        let mut quoted_comma = HeaderMap::new();
        quoted_comma.insert(
            IF_NONE_MATCH,
            HeaderValue::from_static("\"stale\", W/\"proof,abc\""),
        );
        assert!(if_none_match_matches(&quoted_comma, "\"proof,abc\""));

        let mut obs_text = HeaderMap::new();
        obs_text.insert(
            IF_NONE_MATCH,
            HeaderValue::from_bytes(b"\"\x80\", \"proof:abc\"").unwrap(),
        );
        assert!(if_none_match_matches(&obs_text, "\"proof:abc\""));

        let mut wildcard = HeaderMap::new();
        wildcard.insert(IF_NONE_MATCH, HeaderValue::from_static("*"));
        assert!(if_none_match_matches(&wildcard, "\"proof:abc\""));
    }

    #[test]
    fn if_none_match_rejects_case_changes_and_malformed_lists() {
        for value in [
            "\"PROOF:ABC\"",
            "\"proof:abc\"junk",
            "*, \"proof:abc\"",
            "\"stale\", malformed, \"proof:abc\"",
            "\"stale\",",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                IF_NONE_MATCH,
                HeaderValue::from_bytes(value.as_bytes()).unwrap(),
            );
            assert!(!if_none_match_matches(&headers, "\"proof:abc\""), "{value}");
        }
    }
}

/// Bounded stable error code copied into response extensions for telemetry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HttpErrorCode(Arc<str>);
impl HttpErrorCode {
    /// Return the bounded metric-label value.
    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
    pub(crate) fn new(code: &str) -> Self {
        if is_valid_error_code(code) {
            Self(Arc::from(code))
        } else {
            Self(Arc::from("invalid_error_code"))
        }
    }
    pub(crate) fn from_envelope(envelope: &ErrorEnvelope) -> Self {
        Self::new(envelope.code())
    }
}
/// Return whether a public error code is a bounded lower-snake-case identifier.
#[must_use]
pub(crate) fn is_valid_error_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= 64
        && code.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || (byte == b'_' && index > 0)
        })
}
/// Return whether a public error message is safe, exact human-readable text.
///
/// Messages are deliberately not stable identifiers, but the public envelope
/// still requires a non-empty value without surrounding whitespace or control
/// characters so every first-party SDK observes the same finite contract.
#[must_use]
pub(crate) fn is_valid_error_message(message: &str) -> bool {
    is_valid_bounded_public_text(message, MAX_ERROR_MESSAGE_CHARACTERS)
}
/// Return whether a public detail string is bounded exact text.
#[must_use]
pub(crate) fn is_valid_error_detail_text(value: &str) -> bool {
    is_valid_bounded_public_text(value, MAX_ERROR_DETAIL_CHARACTERS)
}
/// Return whether a protocol/domain rejection identifier is safe to expose.
#[must_use]
pub(crate) fn is_valid_reject_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= MAX_REJECT_CODE_BYTES
        && code
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}
fn is_valid_bounded_public_text(value: &str, max_characters: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_characters.saturating_mul(4)
        && value.trim() == value
        && value.chars().take(max_characters + 1).count() <= max_characters
        && !value.chars().any(char::is_control)
}
#[cfg(test)]
mod public_error_grammar_tests {
    use super::{MAX_ERROR_MESSAGE_CHARACTERS, is_valid_error_message, is_valid_reject_code};
    #[test]
    fn error_messages_require_exact_non_control_text() {
        for valid in [
            "invalid request",
            "再試行してください",
            "proof rejected: 42",
        ] {
            assert!(is_valid_error_message(valid), "valid message: {valid:?}");
        }
        for invalid in [
            "",
            " leading",
            "trailing ",
            "line\nbreak",
            "nul\0byte",
            "\u{85}",
        ] {
            assert!(
                !is_valid_error_message(invalid),
                "invalid message: {invalid:?}"
            );
        }
        assert!(!is_valid_error_message(
            &"x".repeat(MAX_ERROR_MESSAGE_CHARACTERS + 1)
        ));
        assert!(is_valid_error_message(
            &"界".repeat(MAX_ERROR_MESSAGE_CHARACTERS)
        ));
    }
    #[test]
    fn reject_codes_are_bounded_printable_identifiers() {
        for valid in ["queue_full", "PRTRY:BAD", "ISO-20022.CODE"] {
            assert!(is_valid_reject_code(valid), "valid code: {valid:?}");
        }
        for invalid in ["", " leading", "has/slash", "line\nbreak", "quote\""] {
            assert!(!is_valid_reject_code(invalid), "invalid code: {invalid:?}");
        }
        assert!(!is_valid_reject_code(&"x".repeat(129)));
    }
}
fn serialization_failure_response(format: ResponseFormat) -> Response {
    let envelope = ErrorEnvelope::new(
        "response_serialization_failed",
        "Torii could not encode the response payload.",
    );
    let (content_type, bytes) = match format {
        ResponseFormat::Norito => {
            let mut bytes = Vec::new();
            if let Err(error) = norito::core::to_bytes_in(&envelope, &mut bytes) {
                iroha_logger::error!(?error, "failed to encode fallback Norito error envelope");
                bytes.clear();
            }
            (NORITO_MIME_TYPE, bytes)
        }
        ResponseFormat::Json => {
            let bytes = norito::json::to_vec(&envelope).unwrap_or_else(|error| {
                iroha_logger::error!(?error, "failed to encode fallback JSON error envelope");
                Vec::new()
            });
            (JSON_MIME_TYPE, bytes)
        }
    };
    let mut response = Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header(CONTENT_TYPE, content_type)
        .body(axum::body::Body::from(bytes))
        .expect("build response serialization error");
    response
        .extensions_mut()
        .insert(HttpErrorCode::from_envelope(&envelope));
    response
}
fn telemetry_error_code<T: Any>(value: &T) -> Option<HttpErrorCode> {
    let value: &dyn Any = value;
    value
        .downcast_ref::<ErrorEnvelope>()
        .map(HttpErrorCode::from_envelope)
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct MediaParameter {
    name: String,
    value: String,
    quoted: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedMediaType {
    type_name: String,
    subtype: String,
    parameters: Vec<MediaParameter>,
}
impl ParsedMediaType {
    fn essence(&self) -> String {
        format!("{}/{}", self.type_name, self.subtype)
    }
    fn has_concrete_type(&self) -> bool {
        !self.type_name.contains('*') && !self.subtype.contains('*')
    }
    fn has_valid_range_wildcards(&self) -> bool {
        match (self.type_name.as_str(), self.subtype.as_str()) {
            ("*", "*") => true,
            ("*", _) => false,
            (type_name, "*") => !type_name.contains('*'),
            _ => self.has_concrete_type(),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MediaParseError {
    InvalidSyntax,
    DuplicateParameter,
    InvalidQuality,
}
fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}
fn is_optional_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t')
}
fn is_quoted_text_byte(byte: u8) -> bool {
    matches!(byte, b'\t' | b' ' | b'!' | b'#'..=b'[' | b']'..=b'~')
}
fn is_quoted_pair_byte(byte: u8) -> bool {
    matches!(byte, b'\t' | b' '..=b'~')
}
fn trim_optional_whitespace(raw: &str) -> &str {
    raw.trim_matches(|character| matches!(character, ' ' | '\t'))
}
struct MediaCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> MediaCursor<'a> {
    fn new(raw: &'a str) -> Result<Self, MediaParseError> {
        if !raw.is_ascii() {
            return Err(MediaParseError::InvalidSyntax);
        }
        Ok(Self {
            bytes: raw.as_bytes(),
            position: 0,
        })
    }
    fn at_end(&self) -> bool {
        self.position == self.bytes.len()
    }
    fn current(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }
    fn skip_optional_whitespace(&mut self) {
        while self.current().is_some_and(is_optional_whitespace) {
            self.position += 1;
        }
    }
    fn consume(&mut self, expected: u8) -> Result<(), MediaParseError> {
        if self.current() != Some(expected) {
            return Err(MediaParseError::InvalidSyntax);
        }
        self.position += 1;
        Ok(())
    }
    fn token(&mut self) -> Result<&'a str, MediaParseError> {
        let start = self.position;
        while self.current().is_some_and(is_http_token_byte) {
            self.position += 1;
        }
        if self.position == start {
            return Err(MediaParseError::InvalidSyntax);
        }
        // `MediaCursor::new` rejects non-ASCII input, so token boundaries are
        // always UTF-8 boundaries.
        Ok(std::str::from_utf8(&self.bytes[start..self.position])
            .expect("ASCII media token is valid UTF-8"))
    }
    fn parameter_value(&mut self) -> Result<(String, bool), MediaParseError> {
        if self.current() != Some(b'"') {
            return self.token().map(|value| (value.to_owned(), false));
        }
        self.position += 1;
        let mut decoded = String::new();
        loop {
            let byte = self.current().ok_or(MediaParseError::InvalidSyntax)?;
            match byte {
                b'"' => {
                    self.position += 1;
                    return Ok((decoded, true));
                }
                b'\\' => {
                    self.position += 1;
                    let escaped = self.current().ok_or(MediaParseError::InvalidSyntax)?;
                    if !is_quoted_pair_byte(escaped) {
                        return Err(MediaParseError::InvalidSyntax);
                    }
                    decoded.push(char::from(escaped));
                    self.position += 1;
                }
                value if is_quoted_text_byte(value) => {
                    decoded.push(char::from(value));
                    self.position += 1;
                }
                _ => return Err(MediaParseError::InvalidSyntax),
            }
        }
    }
}
fn parse_media_type(raw: &str) -> Result<ParsedMediaType, MediaParseError> {
    let mut cursor = MediaCursor::new(raw)?;
    cursor.skip_optional_whitespace();
    let type_name = cursor.token()?.to_ascii_lowercase();
    cursor.consume(b'/')?;
    let subtype = cursor.token()?.to_ascii_lowercase();
    let mut parameters: Vec<MediaParameter> = Vec::new();
    loop {
        cursor.skip_optional_whitespace();
        if cursor.at_end() {
            break;
        }
        cursor.consume(b';')?;
        cursor.skip_optional_whitespace();
        let name = cursor.token()?.to_ascii_lowercase();
        // Whitespace around `=` is not part of the HTTP parameter grammar.
        cursor.consume(b'=')?;
        let (value, quoted) = cursor.parameter_value()?;
        if parameters.iter().any(|parameter| parameter.name == name) {
            return Err(MediaParseError::DuplicateParameter);
        }
        parameters.push(MediaParameter {
            name,
            value,
            quoted,
        });
    }
    Ok(ParsedMediaType {
        type_name,
        subtype,
        parameters,
    })
}
fn is_json_subtype(subtype: &str) -> bool {
    subtype == "json"
        || subtype
            .strip_suffix("+json")
            .is_some_and(|prefix| !prefix.is_empty())
}
fn has_supported_json_charset(parameters: &[MediaParameter]) -> bool {
    parameters.iter().all(|parameter| {
        parameter.name != "charset" || parameter.value.eq_ignore_ascii_case("utf-8")
    })
}
/// Classify a response `Content-Type` as one of Torii's two typed representations.
///
/// Protocol-native media types such as SSE, Prometheus text, WebSocket upgrades,
/// raw blobs, hosted content, and concrete structured-suffix JSON types return
/// `None` and retain their exact media-type negotiation rules.
#[must_use]
pub fn typed_response_format_for_content_type(raw: &str) -> Option<ResponseFormat> {
    let media_type = parse_media_type(raw).ok()?;
    if !media_type.has_concrete_type()
        || media_type
            .parameters
            .iter()
            .any(|parameter| parameter.name == "q")
    {
        return None;
    }
    if media_type.type_name == "application"
        && media_type.subtype == "json"
        && has_supported_json_charset(&media_type.parameters)
    {
        return Some(ResponseFormat::Json);
    }
    if media_type.type_name == "application" && media_type.subtype == "x-norito" {
        return Some(ResponseFormat::Norito);
    }
    None
}
/// Preferred response encoding negotiated from the `Accept` header.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ResponseFormat {
    /// Use Norito binary encoding.
    Norito,
    /// Use JSON encoding backed by the Norito JSON codec.
    Json,
}
tokio::task_local! {
    static CURRENT_RESPONSE_FORMAT: ResponseFormat;
}
/// Run a future with the response format negotiated for the current request.
pub async fn with_current_response_format<F>(format: ResponseFormat, future: F) -> F::Output
where
    F: Future,
{
    CURRENT_RESPONSE_FORMAT.scope(format, future).await
}
/// Return the response format associated with the current request.
///
/// Code paths outside an HTTP request use Norito, matching Torii's default wire preference.
pub fn current_response_format() -> ResponseFormat {
    CURRENT_RESPONSE_FORMAT
        .try_with(|format| *format)
        .unwrap_or(ResponseFormat::Norito)
}
/// Supported representation declared by a typed request body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TypedRequestContentFormat {
    /// Norito-backed JSON encoded as UTF-8.
    Json,
    /// Native Norito binary encoding.
    Norito,
}
/// Classify one stored first-release typed media value using the same strict
/// grammar as HTTP request admission.
///
/// JSON permits no parameter or exactly `charset=utf-8`; native Norito is parameter-free. Empty,
/// malformed, duplicate, quality-weighted, and structured-suffix values fail closed.
pub(crate) fn strict_typed_content_format(raw: &str) -> Option<TypedRequestContentFormat> {
    let declared = trim_optional_whitespace(raw);
    if declared.is_empty() {
        return None;
    }
    let media_type = parse_media_type(declared).ok()?;
    if !media_type.has_concrete_type() || media_type.type_name != "application" {
        return None;
    }
    if media_type.subtype == "json"
        && match media_type.parameters.as_slice() {
            [] => true,
            [parameter] => {
                parameter.name == "charset" && parameter.value.eq_ignore_ascii_case("utf-8")
            }
            _ => false,
        }
    {
        return Some(TypedRequestContentFormat::Json);
    }
    if media_type.subtype == "x-norito" && media_type.parameters.is_empty() {
        return Some(TypedRequestContentFormat::Norito);
    }
    None
}
/// Return whether `raw` is exactly one parameter-free concrete media type.
pub(crate) fn is_parameter_free_media_type(
    raw: &str,
    expected_type: &str,
    expected_subtype: &str,
) -> bool {
    let declared = trim_optional_whitespace(raw);
    parse_media_type(declared).is_ok_and(|media_type| {
        media_type.has_concrete_type()
            && media_type.type_name == expected_type
            && media_type.subtype == expected_subtype
            && media_type.parameters.is_empty()
    })
}
fn typed_request_media_rejection(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> Response {
    respond_with_status_and_format(
        status,
        ErrorEnvelope::new(code, message),
        current_response_format(),
    )
}
/// Validate and classify a typed request's `Content-Type` without reading its body.
///
/// The header must occur exactly once and be either `application/json` (with no parameter or one
/// `charset=utf-8`) or parameter-free `application/x-norito`. This helper is shared by early
/// admission middleware and body extractors so unsupported media cannot reach idempotency handling
/// or body collection through a divergent second parsing path.
#[allow(clippy::result_large_err)]
pub(crate) fn typed_request_content_format(
    headers: &axum::http::HeaderMap,
) -> Result<TypedRequestContentFormat, Response> {
    let mut content_types = headers.get_all(CONTENT_TYPE).iter();
    let Some(value) = content_types.next() else {
        return Err(typed_request_media_rejection(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "request_content_type_missing",
            format!("missing Content-Type; use application/json or {NORITO_MIME_TYPE}"),
        ));
    };
    if content_types.next().is_some() {
        return Err(typed_request_media_rejection(
            StatusCode::BAD_REQUEST,
            "request_content_type_invalid",
            "Content-Type must appear exactly once.",
        ));
    }
    let declared = value.to_str().map_err(|_| {
        typed_request_media_rejection(
            StatusCode::BAD_REQUEST,
            "request_content_type_invalid",
            "Content-Type is not valid ASCII.",
        )
    })?;
    let declared = trim_optional_whitespace(declared);
    if declared.is_empty() {
        return Err(typed_request_media_rejection(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "request_content_type_missing",
            format!("missing Content-Type; use application/json or {NORITO_MIME_TYPE}"),
        ));
    }
    let media_type = parse_media_type(declared).map_err(|_| {
        typed_request_media_rejection(
            StatusCode::BAD_REQUEST,
            "request_content_type_invalid",
            "Content-Type has invalid media-type syntax.",
        )
    })?;
    if !media_type.has_concrete_type() {
        return Err(typed_request_media_rejection(
            StatusCode::BAD_REQUEST,
            "request_content_type_invalid",
            "Content-Type must declare one concrete media type.",
        ));
    }
    let request_format = if media_type.type_name == "application" {
        if media_type.subtype == "json"
            && match media_type.parameters.as_slice() {
                [] => true,
                [parameter] => {
                    parameter.name == "charset" && parameter.value.eq_ignore_ascii_case("utf-8")
                }
                _ => false,
            }
        {
            Some(TypedRequestContentFormat::Json)
        } else if media_type.subtype == "x-norito" && media_type.parameters.is_empty() {
            Some(TypedRequestContentFormat::Norito)
        } else {
            None
        }
    } else {
        None
    };
    request_format.ok_or_else(|| {
        typed_request_media_rejection(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "request_content_type_unsupported",
            format!(
                "unsupported Content-Type `{declared}`; use application/json or {NORITO_MIME_TYPE}"
            ),
        )
    })
}
/// Validate the canonical first-release JSON request representation.
///
/// This requires exactly one `Content-Type` header and accepts only `application/json` with an
/// optional UTF-8 charset. It deliberately rejects structured-suffix JSON and native Norito so an
/// endpoint cannot advertise a narrower protocol than it actually enforces.
#[allow(clippy::result_large_err)]
pub(crate) fn canonical_json_request_content_type(
    headers: &axum::http::HeaderMap,
) -> Result<(), Response> {
    match typed_request_content_format(headers)? {
        TypedRequestContentFormat::Json => Ok(()),
        TypedRequestContentFormat::Norito => Err(typed_request_media_rejection(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "request_content_type_unsupported",
            "unsupported Content-Type `application/x-norito`; use application/json",
        )),
    }
}
/// Validate the canonical first-release native Norito request representation.
///
/// Native-only endpoints accept one parameter-free media type; JSON and
/// parameterized Norito declarations are deliberately not second protocols.
#[allow(clippy::result_large_err)]
pub(crate) fn norito_request_content_type(headers: &axum::http::HeaderMap) -> Result<(), Response> {
    let mut content_types = headers.get_all(CONTENT_TYPE).iter();
    let Some(value) = content_types.next() else {
        return Err(typed_request_media_rejection(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "request_content_type_missing",
            format!("missing Content-Type; use {NORITO_MIME_TYPE}"),
        ));
    };
    if content_types.next().is_some() {
        return Err(typed_request_media_rejection(
            StatusCode::BAD_REQUEST,
            "request_content_type_invalid",
            "Content-Type must appear exactly once.",
        ));
    }
    let declared = value.to_str().map_err(|_| {
        typed_request_media_rejection(
            StatusCode::BAD_REQUEST,
            "request_content_type_invalid",
            "Content-Type is not valid ASCII.",
        )
    })?;
    let declared = trim_optional_whitespace(declared);
    if declared.is_empty() {
        return Err(typed_request_media_rejection(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "request_content_type_missing",
            format!("missing Content-Type; use {NORITO_MIME_TYPE}"),
        ));
    }
    let media_type = parse_media_type(declared).map_err(|_| {
        typed_request_media_rejection(
            StatusCode::BAD_REQUEST,
            "request_content_type_invalid",
            "Content-Type has invalid media-type syntax.",
        )
    })?;
    if !media_type.has_concrete_type() {
        return Err(typed_request_media_rejection(
            StatusCode::BAD_REQUEST,
            "request_content_type_invalid",
            "Content-Type must declare one concrete media type.",
        ));
    }
    if media_type.type_name == "application"
        && media_type.subtype == "x-norito"
        && media_type.parameters.is_empty()
    {
        return Ok(());
    }
    Err(typed_request_media_rejection(
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "request_content_type_unsupported",
        format!("unsupported Content-Type; use {NORITO_MIME_TYPE}"),
    ))
}
fn not_acceptable(message: impl Into<String>) -> Response {
    // When no requested representation can be selected there is no negotiated
    // format to honor. The first-release contract uses a typed JSON envelope as
    // the deterministic fallback for the 406 itself.
    respond_with_status_and_format(
        StatusCode::NOT_ACCEPTABLE,
        iroha_torii_shared::ErrorEnvelope::new("response_not_acceptable", message),
        ResponseFormat::Json,
    )
}
fn parse_accept_qvalue(raw: &str) -> Option<u16> {
    let (whole, fraction) = raw.split_once('.').map_or((raw, ""), |parts| parts);
    if fraction.len() > 3 || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let padded_fraction = match fraction.len() {
        0 => 0,
        1 => fraction.parse::<u16>().ok()?.checked_mul(100)?,
        2 => fraction.parse::<u16>().ok()?.checked_mul(10)?,
        3 => fraction.parse::<u16>().ok()?,
        _ => return None,
    };
    match whole {
        "0" => Some(padded_fraction),
        "1" if padded_fraction == 0 => Some(1_000),
        _ => None,
    }
}
fn split_accept_list(raw: &str) -> Result<Vec<&str>, MediaParseError> {
    if !raw.is_ascii() {
        return Err(MediaParseError::InvalidSyntax);
    }
    let bytes = raw.as_bytes();
    let mut entries = Vec::new();
    let mut start = 0;
    let mut position = 0;
    let mut in_quotes = false;
    while position < bytes.len() {
        let byte = bytes[position];
        if in_quotes {
            match byte {
                b'"' => {
                    in_quotes = false;
                    position += 1;
                }
                b'\\' => {
                    position += 1;
                    let escaped = bytes
                        .get(position)
                        .copied()
                        .ok_or(MediaParseError::InvalidSyntax)?;
                    if !is_quoted_pair_byte(escaped) {
                        return Err(MediaParseError::InvalidSyntax);
                    }
                    position += 1;
                }
                value if is_quoted_text_byte(value) => position += 1,
                _ => return Err(MediaParseError::InvalidSyntax),
            }
            continue;
        }
        match byte {
            b'"' => {
                in_quotes = true;
                position += 1;
            }
            b',' => {
                let entry = trim_optional_whitespace(&raw[start..position]);
                if !entry.is_empty() {
                    entries.push(entry);
                }
                position += 1;
                start = position;
            }
            b'\t' | b' '..=b'~' => position += 1,
            _ => return Err(MediaParseError::InvalidSyntax),
        }
    }
    if in_quotes {
        return Err(MediaParseError::InvalidSyntax);
    }
    let entry = trim_optional_whitespace(&raw[start..]);
    if !entry.is_empty() {
        entries.push(entry);
    }
    if entries.is_empty() {
        return Err(MediaParseError::InvalidSyntax);
    }
    Ok(entries)
}
#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct MediaSpecificity {
    type_level: u8,
    parameter_count: usize,
}
#[derive(Clone, Debug)]
struct ParsedAcceptRange {
    media_type: ParsedMediaType,
    quality: u16,
}
fn parse_accept_ranges(raw: &str) -> Result<Vec<ParsedAcceptRange>, MediaParseError> {
    split_accept_list(raw)?
        .into_iter()
        .map(|entry| {
            let mut media_type = parse_media_type(entry)?;
            if !media_type.has_valid_range_wildcards() {
                return Err(MediaParseError::InvalidSyntax);
            }
            let quality_index = media_type
                .parameters
                .iter()
                .position(|parameter| parameter.name == "q");
            let quality = quality_index.map_or(Ok(1_000), |index| {
                let parameter = &media_type.parameters[index];
                if parameter.quoted {
                    return Err(MediaParseError::InvalidQuality);
                }
                parse_accept_qvalue(&parameter.value).ok_or(MediaParseError::InvalidQuality)
            })?;
            // Parameters after `q` are Accept extensions. They are required to
            // be syntactically valid and unique, but do not constrain the
            // selected representation.
            if let Some(index) = quality_index {
                media_type.parameters.truncate(index);
            }
            Ok(ParsedAcceptRange {
                media_type,
                quality,
            })
        })
        .collect()
}
#[allow(clippy::result_large_err)]
fn parse_accept_header(header: &HeaderValue) -> Result<Vec<ParsedAcceptRange>, Response> {
    let raw = header.to_str().map_err(|_| {
        not_acceptable(
            "invalid Accept header encoding; supported: application/json, application/x-norito",
        )
    })?;
    parse_accept_ranges(raw).map_err(|error| {
        let message = match error {
            MediaParseError::InvalidQuality => "invalid q-value in Accept header",
            MediaParseError::DuplicateParameter => "duplicate parameter in Accept header",
            MediaParseError::InvalidSyntax => "malformed Accept header",
        };
        not_acceptable(message)
    })
}
fn typed_range_specificity(
    media_type: &ParsedMediaType,
    format: ResponseFormat,
) -> Option<MediaSpecificity> {
    // A structured-suffix JSON range is compatible with Torii's JSON
    // representation, but the canonical `application/json` range remains
    // more specific when both are present.
    let type_level = match (media_type.type_name.as_str(), media_type.subtype.as_str()) {
        ("*", "*") => 0,
        ("application", "*") => 1,
        ("application", subtype) => match format {
            ResponseFormat::Json if subtype == "json" => 3,
            ResponseFormat::Json if is_json_subtype(subtype) => 2,
            ResponseFormat::Norito if subtype == "x-norito" => 3,
            _ => return None,
        },
        _ => return None,
    };
    let parameters_match = media_type.parameters.iter().all(|parameter| match format {
        ResponseFormat::Json => {
            parameter.name == "charset" && parameter.value.eq_ignore_ascii_case("utf-8")
        }
        ResponseFormat::Norito => parameter.name == "version" && parameter.value == "1",
    });
    parameters_match.then_some(MediaSpecificity {
        type_level,
        parameter_count: media_type.parameters.len(),
    })
}
fn parameter_values_match(name: &str, left: &str, right: &str) -> bool {
    if name == "charset" {
        left.eq_ignore_ascii_case(right)
    } else {
        left == right
    }
}
fn native_range_specificity(
    media_type: &ParsedMediaType,
    actual: &ParsedMediaType,
) -> Option<MediaSpecificity> {
    let type_level = if media_type.type_name == "*" && media_type.subtype == "*" {
        0
    } else if media_type.type_name == actual.type_name && media_type.subtype == "*" {
        1
    } else if media_type.type_name == actual.type_name && media_type.subtype == actual.subtype {
        2
    } else {
        return None;
    };
    let parameters_match = media_type.parameters.iter().all(|expected| {
        actual.parameters.iter().any(|candidate| {
            candidate.name == expected.name
                && parameter_values_match(&expected.name, &expected.value, &candidate.value)
        })
    });
    parameters_match.then_some(MediaSpecificity {
        type_level,
        parameter_count: media_type.parameters.len(),
    })
}
/// Negotiate the response format from an optional `Accept` header value.
///
/// Omitted headers and wildcard-only ranges select JSON, so ordinary HTTP
/// clients read JSON without negotiating; Norito clients ask for
/// `application/x-norito` explicitly, and an equal explicit preference for
/// both keeps the binary-first tie-break.
///
/// Returns an HTTP response carrying status `406 Not Acceptable` when the header
/// explicitly forbids both JSON and Norito or contains an invalid q-value.
#[allow(clippy::result_large_err)] // callers expect to bubble the full HTTP response on negotiation failure
pub fn negotiate_response_format(accept: Option<&HeaderValue>) -> Result<ResponseFormat, Response> {
    negotiate_response_format_with_default(accept, ResponseFormat::Json)
}
#[allow(clippy::result_large_err)] // callers expect to bubble the full HTTP response on negotiation failure
fn negotiate_response_format_with_default(
    accept: Option<&HeaderValue>,
    default_format: ResponseFormat,
) -> Result<ResponseFormat, Response> {
    let Some(header) = accept else {
        return Ok(default_format);
    };
    let parsed_ranges = parse_accept_header(header)?;
    #[derive(Copy, Clone, Debug)]
    struct MediaRange {
        quality: u16,
        specificity: MediaSpecificity,
        index: usize,
        matches_json: bool,
        matches_norito: bool,
    }
    let mut ranges = Vec::new();
    for (index, range) in parsed_ranges.iter().enumerate() {
        let json_specificity = typed_range_specificity(&range.media_type, ResponseFormat::Json);
        let norito_specificity = typed_range_specificity(&range.media_type, ResponseFormat::Norito);
        if let Some(specificity) = json_specificity {
            ranges.push(MediaRange {
                quality: range.quality,
                specificity,
                index,
                matches_json: true,
                matches_norito: false,
            });
        }
        if let Some(specificity) = norito_specificity {
            ranges.push(MediaRange {
                quality: range.quality,
                specificity,
                index,
                matches_json: false,
                matches_norito: true,
            });
        }
    }
    #[derive(Copy, Clone)]
    struct EffectivePreference {
        format: ResponseFormat,
        quality: u16,
        specificity: MediaSpecificity,
    }
    let effective = |format: ResponseFormat| {
        ranges
            .iter()
            .filter(|range| match format {
                ResponseFormat::Json => range.matches_json,
                ResponseFormat::Norito => range.matches_norito,
            })
            // RFC-style precedence: the most-specific media range determines
            // the quality for a representation. This is important for an
            // explicit `q=0`, which must not be undone by a wildcard.
            .max_by_key(|range| (range.specificity, core::cmp::Reverse(range.index)))
            .map(|range| EffectivePreference {
                format,
                quality: range.quality,
                specificity: range.specificity,
            })
    };
    let json = effective(ResponseFormat::Json).filter(|candidate| candidate.quality > 0);
    let norito = effective(ResponseFormat::Norito).filter(|candidate| candidate.quality > 0);
    let selected = match (json, norito) {
        (Some(json), Some(norito)) => {
            if json.quality > norito.quality {
                json
            } else if norito.quality > json.quality {
                norito
            } else if json.specificity > norito.specificity {
                json
            } else if norito.specificity > json.specificity {
                norito
            } else if json.specificity.type_level == 3 {
                // Equal explicit preferences use Torii's binary-first tie
                // break. Wildcard-only ties use the interoperable JSON
                // representation while an omitted header retains the
                // endpoint's default.
                norito
            } else {
                json
            }
        }
        (Some(candidate), None) | (None, Some(candidate)) => candidate,
        (None, None) => {
            return Err(not_acceptable(
                "unsupported Accept header; use application/json or application/x-norito",
            ));
        }
    };
    if selected.quality == 0 {
        return Err(not_acceptable(
            "unsupported Accept header; use application/json or application/x-norito",
        ));
    }
    Ok(selected.format)
}
/// Validate `Accept` for JSON-only dynamic endpoints.
///
/// Dynamic `norito::json::Value` payloads do not have a stable Norito schema,
/// so JSON-only routes accept omitted, wildcard, and JSON-compatible `Accept`
/// values, but reject clients that explicitly ask for Norito without accepting
/// JSON.
#[allow(clippy::result_large_err)] // callers bubble the full HTTP response on negotiation failure
pub fn negotiate_json_only_response(accept: Option<&HeaderValue>) -> Result<(), Response> {
    negotiate_single_typed_response(accept, ResponseFormat::Json)
}
/// Validate `Accept` for a response that is available only as Norito.
///
/// The most-specific matching range wins, so an explicit `application/x-norito;q=0`
/// cannot be overridden by a positive wildcard.
#[cfg(test)]
#[allow(clippy::result_large_err)] // callers bubble the full HTTP response on negotiation failure
pub fn negotiate_norito_only_response(accept: Option<&HeaderValue>) -> Result<(), Response> {
    negotiate_single_typed_response(accept, ResponseFormat::Norito)
}
/// Validate whether `format` is acceptable without selecting between representations.
///
/// This is used after safe requests run so protocol-native handlers can advertise their
/// actual media type instead of being rejected by the JSON/Norito negotiation layer.
#[allow(clippy::result_large_err)] // callers bubble the full HTTP response on negotiation failure
pub fn ensure_typed_response_format_acceptable(
    accept: Option<&HeaderValue>,
    format: ResponseFormat,
) -> Result<(), Response> {
    negotiate_single_typed_response(accept, format)
}
/// Validate a protocol-native response media type against `Accept`.
///
/// The handler remains responsible for selecting its actual SSE, metrics,
/// artifact, image, or other native representation. This check applies the
/// client's exact media ranges after a safe handler has produced that response.
#[allow(clippy::result_large_err)]
pub fn ensure_response_media_type_acceptable(
    accept: Option<&HeaderValue>,
    actual_content_type: &str,
) -> Result<(), Response> {
    let actual = parse_media_type(actual_content_type)
        .map_err(|_| not_acceptable("response Content-Type is invalid and cannot be negotiated"))?;
    if !actual.has_concrete_type()
        || actual
            .parameters
            .iter()
            .any(|parameter| parameter.name == "q")
        || (actual.type_name == "application"
            && is_json_subtype(&actual.subtype)
            && !has_supported_json_charset(&actual.parameters))
    {
        return Err(not_acceptable(
            "response Content-Type is invalid and cannot be negotiated",
        ));
    }
    let Some(header) = accept else {
        return Ok(());
    };
    let parsed_ranges = parse_accept_header(header)?;
    let mut effective: Option<(MediaSpecificity, usize, u16)> = None;
    for (index, range) in parsed_ranges.iter().enumerate() {
        let Some(specificity) = native_range_specificity(&range.media_type, &actual) else {
            continue;
        };
        if effective.is_none_or(|(current_specificity, current_index, _)| {
            specificity > current_specificity
                || (specificity == current_specificity && index < current_index)
        }) {
            effective = Some((specificity, index, range.quality));
        }
    }
    if effective.is_some_and(|(_, _, quality)| quality > 0) {
        return Ok(());
    }
    Err(not_acceptable(format!(
        "requested content type is not acceptable for this endpoint; response uses {}",
        actual.essence()
    )))
}
#[allow(clippy::result_large_err)] // callers bubble the full HTTP response on negotiation failure
fn negotiate_single_typed_response(
    accept: Option<&HeaderValue>,
    format: ResponseFormat,
) -> Result<(), Response> {
    let Some(header) = accept else {
        return Ok(());
    };
    let supported = match format {
        ResponseFormat::Json => JSON_MIME_TYPE,
        ResponseFormat::Norito => NORITO_MIME_TYPE,
    };
    let parsed_ranges = parse_accept_header(header)?;
    let mut effective: Option<(MediaSpecificity, usize, u16)> = None;
    for (index, range) in parsed_ranges.iter().enumerate() {
        let Some(specificity) = typed_range_specificity(&range.media_type, format) else {
            continue;
        };
        if effective.is_none_or(|(current_specificity, current_index, _)| {
            specificity > current_specificity
                || (specificity == current_specificity && index < current_index)
        }) {
            effective = Some((specificity, index, range.quality));
        }
    }
    if effective.is_some_and(|(_, _, quality)| quality > 0) {
        return Ok(());
    }
    Err(not_acceptable(format!(
        "requested content type is not acceptable for this endpoint; supported: {supported}"
    )))
}
/// Encode a response payload using the negotiated format.
pub fn respond_with_format<T>(value: T, format: ResponseFormat) -> Response
where
    T: JsonSerialize + norito::core::NoritoSerialize + 'static,
{
    respond_with_status_and_format(StatusCode::OK, value, format)
}
/// Failure to encode a response inside a caller-owned body reservation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BoundedResponseEncodeError {
    /// The exact canonical Norito frame is larger than the reserved body.
    BodyTooLarge {
        /// Exact encoded body length.
        encoded_bytes: usize,
        /// Maximum admitted body length.
        max_body_bytes: usize,
    },
    /// The checked JSON representation exceeded the reserved body.
    ///
    /// The bounded JSON counter stops at the first overrun, so it deliberately
    /// does not materialize or report the complete attacker-influenced length.
    JsonBodyTooLarge {
        /// Maximum admitted JSON body length.
        max_body_bytes: usize,
    },
    /// Canonical serialization failed before a body was constructed.
    ///
    /// Deliberately carries no serializer text: codec errors can embed
    /// attacker-controlled values, and formatting them while the response is
    /// still resident would escape the caller's body reservation.
    Serialization,
}
impl core::fmt::Display for BoundedResponseEncodeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BodyTooLarge {
                encoded_bytes,
                max_body_bytes,
            } => write!(
                formatter,
                "encoded response requires {encoded_bytes} bytes but the admitted body limit is {max_body_bytes} bytes"
            ),
            Self::JsonBodyTooLarge { max_body_bytes } => write!(
                formatter,
                "JSON response exceeds the admitted {max_body_bytes}-byte body limit"
            ),
            Self::Serialization => formatter.write_str("canonical response serialization failed"),
        }
    }
}
impl std::error::Error for BoundedResponseEncodeError {}
/// Encode a response only after a non-allocating exact size preflight.
///
/// Canonical Norito and checked Norito JSON both count against the hard body
/// limit before allocating their exactly sized destination. Custom JSON field
/// writers remain an explicit certification boundary: unsupported legacy
/// serializers fail without falling back to an unbounded `String`.
pub(crate) fn respond_with_format_bounded<T>(
    value: T,
    format: ResponseFormat,
    max_body_bytes: usize,
) -> Result<Response, BoundedResponseEncodeError>
where
    T: JsonSerialize + norito::core::NoritoSerialize + 'static,
{
    let error_code = telemetry_error_code(&value);
    let (content_type, body) = match format {
        ResponseFormat::Norito => (
            NORITO_MIME_TYPE,
            axum::body::Body::from(encode_norito_bounded(&value, max_body_bytes)?),
        ),
        ResponseFormat::Json => {
            let json =
                encode_json_bounded(&value, max_body_bytes).map_err(|error| match error {
                    norito::json::BoundedJsonError::BodyTooLarge => {
                        BoundedResponseEncodeError::JsonBodyTooLarge { max_body_bytes }
                    }
                    norito::json::BoundedJsonError::Unsupported
                    | norito::json::BoundedJsonError::AllocationFailed
                    | norito::json::BoundedJsonError::DecodeResource(_)
                    | norito::json::BoundedJsonError::ScopedDecodeResource(_)
                    | norito::json::BoundedJsonError::LengthMismatch => {
                        BoundedResponseEncodeError::Serialization
                    }
                })?;
            (JSON_MIME_TYPE, axum::body::Body::from(json))
        }
    };
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, HeaderValue::from_static(content_type))
        .body(body)
        .expect("build bounded response");
    if let Some(error_code) = error_code {
        response.extensions_mut().insert(error_code);
    }
    Ok(response)
}
/// Encode one canonical Norito frame into an exactly pre-sized bounded buffer.
pub(crate) fn encode_norito_bounded<T>(
    value: &T,
    max_body_bytes: usize,
) -> Result<Vec<u8>, BoundedResponseEncodeError>
where
    T: norito::core::NoritoSerialize,
{
    match norito::core::to_bytes_bounded(value, max_body_bytes) {
        Ok(bytes) => Ok(bytes),
        Err(norito::core::BoundedEncodeError::FrameTooLarge {
            encoded_bytes,
            max_bytes,
        }) => Err(BoundedResponseEncodeError::BodyTooLarge {
            encoded_bytes,
            max_body_bytes: max_bytes,
        }),
        Err(
            norito::core::BoundedEncodeError::AllocationFailed { .. }
            | norito::core::BoundedEncodeError::Serialization(_),
        ) => Err(BoundedResponseEncodeError::Serialization),
    }
}
/// Encode canonical JSON with a count-first hard destination ceiling.
///
/// The returned string is allocated only after the checked sink has measured
/// the complete representation and accepted it against `max_body_bytes`.
pub(crate) fn encode_json_bounded<T>(
    value: &T,
    max_body_bytes: usize,
) -> Result<String, norito::json::BoundedJsonError>
where
    T: JsonSerialize + ?Sized,
{
    norito::json::to_json_bounded(value, max_body_bytes)
}
/// Encode a response payload using the given HTTP status and negotiated format.
pub fn respond_with_status_and_format<T>(
    status: StatusCode,
    value: T,
    format: ResponseFormat,
) -> Response
where
    T: JsonSerialize + norito::core::NoritoSerialize + 'static,
{
    let error_code = telemetry_error_code(&value);
    let mut response = match format {
        ResponseFormat::Norito => {
            let mut bytes = Vec::new();
            match norito::core::to_bytes_in(&value, &mut bytes) {
                Ok(()) => Response::builder()
                    .status(status)
                    .header(CONTENT_TYPE, HeaderValue::from_static(NORITO_MIME_TYPE))
                    .body(axum::body::Body::from(bytes))
                    .expect("build Norito response"),
                Err(err) => {
                    iroha_logger::error!(?err, "failed to serialise response payload");
                    serialization_failure_response(ResponseFormat::Norito)
                }
            }
        }
        ResponseFormat::Json => match norito::json::to_vec(&value) {
            Ok(bytes) => Response::builder()
                .status(status)
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .body(axum::body::Body::from(bytes))
                .expect("build JSON response"),
            Err(err) => {
                iroha_logger::error!(?err, "failed to serialise response payload");
                serialization_failure_response(ResponseFormat::Json)
            }
        },
    };
    if let Some(error_code) = error_code {
        response.extensions_mut().insert(error_code);
    }
    response
}
/// Encode a dynamically constructed Norito JSON value as JSON.
pub fn respond_json_value(value: Value) -> Response {
    respond_json_value_with_status(StatusCode::OK, value)
}
/// Encode a dynamically constructed Norito JSON value as JSON with an HTTP status.
pub fn respond_json_value_with_status(status: StatusCode, value: Value) -> Response {
    match norito::json::to_vec(&value) {
        Ok(bytes) => Response::builder()
            .status(status)
            .header(CONTENT_TYPE, HeaderValue::from_static(JSON_MIME_TYPE))
            .body(axum::body::Body::from(bytes))
            .expect("build JSON response"),
        Err(err) => {
            iroha_logger::error!(?err, "failed to serialise response payload");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to serialise response",
            )
                .into_response()
        }
    }
}
/// Encode a dynamically constructed JSON document using the negotiated response format.
///
/// Dynamic values do not carry a stable Norito object schema. For Norito responses, the
/// JSON document is encoded as a Norito string so clients still receive a checksummed
/// Norito envelope without relying on a dynamic schema.
#[cfg(test)]
pub fn respond_json_document_with_status_and_format(
    status: StatusCode,
    value: Value,
    format: ResponseFormat,
) -> Response {
    match format {
        ResponseFormat::Json => respond_json_value_with_status(status, value),
        ResponseFormat::Norito => match norito::json::to_string(&value) {
            Ok(json) => respond_with_status_and_format(status, json, ResponseFormat::Norito),
            Err(err) => {
                iroha_logger::error!(?err, "failed to serialise response payload");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to serialise response",
                )
                    .into_response()
            }
        },
    }
}
/// Encode a dynamically constructed Norito JSON value.
///
/// Dynamic values do not carry a stable Norito schema, so they remain JSON-only.
/// Use [`respond_with_format`] for typed DTOs that support both JSON and Norito.
pub fn respond_value_with_format(value: Value, _format: ResponseFormat) -> Response {
    respond_json_value(value)
}
#[cfg(test)]
#[path = "tests/utils_response_format.rs"]
mod response_format_tests;
/// Structure to reply using Norito encoding
#[derive(Debug)]
pub struct NoritoBody<T>(pub T);
impl<T: NoritoSerialize + Send + 'static> IntoResponse for NoritoBody<T> {
    fn into_response(self) -> Response {
        let error_code = telemetry_error_code(&self.0);
        // Encode with Norito header + checksum so clients can reliably decode.
        let mut buf = Vec::new();
        norito::core::to_bytes_in(&self.0, &mut buf).expect("norito serialization failed");
        let mut res = Response::new(buf.into());
        res.headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static(NORITO_MIME_TYPE));
        if let Some(error_code) = error_code {
            res.extensions_mut().insert(error_code);
        }
        res
    }
}
/// Structure to reply with a dynamically constructed JSON value.
///
/// Prefer typed DTOs plus [`NoritoBody`] or [`JsonBody`] for dual-format routes.
#[derive(Debug)]
pub struct JsonValueBody(pub Value);
impl IntoResponse for JsonValueBody {
    fn into_response(self) -> Response {
        respond_json_value(self.0)
    }
}
/// Structure to reply using Norito-backed JSON encoding.
#[derive(Debug)]
pub struct JsonBody<T>(pub T);
impl<T: JsonSerialize + Send + 'static> IntoResponse for JsonBody<T> {
    fn into_response(self) -> Response {
        let error_code = telemetry_error_code(&self.0);
        // Serialize using Norito's JSON codec and attach the appropriate MIME type header.
        let buf = norito::json::to_vec(&self.0).expect("json serialization failed");
        let mut res = Response::new(buf.into());
        res.headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if let Some(error_code) = error_code {
            res.extensions_mut().insert(error_code);
        }
        res
    }
}
pub mod extractors {
    use super::*;
    use axum::{
        body::Bytes,
        extract::{FromRequest, FromRequestParts, OptionalFromRequestParts, Request},
        http::StatusCode,
    };
    use norito::{
        core::NoritoDeserialize,
        json::{self, JsonDeserializeOwned, Number, Value},
    };
    use urlencoding::decode;

    /// Maximum raw query text accepted by the generic V1 query extractors.
    ///
    /// This matches the authenticated request and routed-read ceilings. The
    /// bound is checked before percent decoding or allocating decoded fields.
    const TORII_QUERY_MAX_RAW_BYTES_V1: usize = 64 * 1024;
    /// Maximum number of fields accepted by the generic V1 query extractors.
    const TORII_QUERY_MAX_PAIRS_V1: usize = 64;

    #[derive(Debug)]
    enum QueryDecodeError {
        Capacity {
            resource: &'static str,
            attempted: usize,
            limit: usize,
        },
        Invalid(&'static str),
        Schema(String),
    }

    fn query_rejection(error: QueryDecodeError) -> Response {
        match error {
            QueryDecodeError::Capacity {
                resource,
                attempted,
                limit,
            } => typed_request_rejection(
                StatusCode::PAYLOAD_TOO_LARGE,
                "query_capacity_exceeded",
                format!(
                    "Query parameters exceed the V1 {resource} bound (attempted {attempted}, limit {limit})."
                ),
            ),
            QueryDecodeError::Invalid(message) => {
                typed_request_rejection(StatusCode::BAD_REQUEST, "request_query_invalid", message)
            }
            QueryDecodeError::Schema(reason) => typed_request_rejection(
                StatusCode::BAD_REQUEST,
                "request_query_invalid",
                format!("Query parameters do not match the endpoint schema: {reason}"),
            ),
        }
    }
    fn typed_request_rejection(
        status: StatusCode,
        code: &'static str,
        message: impl Into<String>,
    ) -> Response {
        super::respond_with_status_and_format(
            status,
            iroha_torii_shared::ErrorEnvelope::new(code, message),
            super::current_response_format(),
        )
    }
    fn typed_body_rejection(rejection: axum::extract::rejection::BytesRejection) -> Response {
        let status = rejection.into_response().status();
        if status == StatusCode::PAYLOAD_TOO_LARGE {
            return typed_request_rejection(
                status,
                "request_payload_too_large",
                "The request body exceeds the configured size limit.",
            );
        }
        typed_request_rejection(
            status,
            "request_body_unreadable",
            "The request body could not be read.",
        )
    }
    async fn admitted_typed_body<S>(req: Request, state: &S) -> Result<Bytes, Response>
    where
        Bytes: FromRequest<S, Rejection = axum::extract::rejection::BytesRejection>,
        S: Send + Sync,
    {
        #[cfg(feature = "app_api")]
        if let Some(body) = crate::admitted_app_routed_read_body(&req) {
            return Ok(body);
        }
        Bytes::from_request(req, state)
            .await
            .map_err(typed_body_rejection)
    }
    /// Extractor of Norito-encoded, versioned data from the request body.
    ///
    /// Missing or unsupported `Content-Type` yields `415 Unsupported Media Type`;
    /// decode failures surface as `400 Bad Request` to distinguish payload issues from negotiation.
    #[derive(Clone, Copy, Debug)]
    pub struct Norito<T>(pub T);
    /// Server-owned bounds installed before an ordinary Norito body is read.
    #[derive(Clone, Copy, Debug)]
    pub(crate) struct NoritoIngressLimits {
        /// Maximum raw request body retained by the extractor.
        pub(crate) max_body_bytes: usize,
        /// Aggregate allocation and structural limits for Norito decoding.
        pub(crate) decode_limits: norito::DecodeLimits,
    }
    impl<S, T> FromRequest<S> for Norito<T>
    where
        Bytes: FromRequest<S, Rejection = axum::extract::rejection::BytesRejection>,
        S: Send + Sync,
        T: SupportsNoritoDecode + Send + 'static,
    {
        type Rejection = Response;
        async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
            let ingress_limits = req.extensions().get::<NoritoIngressLimits>().copied();
            super::norito_request_content_type(req.headers())?;
            let body = match ingress_limits {
                Some(limits) => axum::body::to_bytes(req.into_body(), limits.max_body_bytes)
                    .await
                    .map_err(|_| {
                        typed_request_rejection(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "request_payload_too_large",
                            format!(
                                "The request body exceeds its admitted {}-byte memory limit.",
                                limits.max_body_bytes
                            ),
                        )
                    })?,
                None => Bytes::from_request(req, state)
                    .await
                    .map_err(typed_body_rejection)?,
            };
            let decode = || T::decode_norito(body.as_ref());
            let decoded = match ingress_limits {
                Some(limits) => norito::with_decode_limits(limits.decode_limits, decode),
                None => decode(),
            };
            decoded
                .map(Norito)
                .map_err(|error| norito_decode_rejection::<T>(&error))
        }
    }
    /// Extractor of Norito-encoded, versioned data from the request body.
    ///
    /// Missing or unsupported `Content-Type` yields `415 Unsupported Media Type`;
    /// decode failures surface as `400 Bad Request` to distinguish payload issues from negotiation.
    #[cfg(test)]
    #[derive(Clone, Copy, Debug)]
    pub struct NoritoVersioned<T>(pub T);
    /// Extractor of raw Norito bytes from the request body.
    ///
    /// Missing or unsupported `Content-Type` yields `415 Unsupported Media Type`.
    /// Callers that need exact payload bytes can decode the returned buffer with
    /// the schema-specific Norito decoder.
    #[derive(Clone, Debug)]
    pub struct NoritoBytes(pub Bytes);
    impl<S> FromRequest<S> for NoritoBytes
    where
        Bytes: FromRequest<S, Rejection = axum::extract::rejection::BytesRejection>,
        S: Send + Sync,
    {
        type Rejection = Response;
        async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
            super::norito_request_content_type(req.headers())?;
            Bytes::from_request(req, state)
                .await
                .map(NoritoBytes)
                .map_err(typed_body_rejection)
        }
    }
    #[cfg(test)]
    impl<S, T> FromRequest<S> for NoritoVersioned<T>
    where
        Bytes: FromRequest<S, Rejection = axum::extract::rejection::BytesRejection>,
        S: Send + Sync,
        // Accept payloads encoded with Norito + iroha_version leading byte
        T: iroha_version::codec::DecodeVersioned,
        T: 'static,
    {
        type Rejection = Response;
        async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
            super::norito_request_content_type(req.headers())?;
            let body = Bytes::from_request(req, state)
                .await
                .map_err(typed_body_rejection)?;
            match <T as iroha_version::codec::DecodeVersioned>::decode_all_versioned(&body) {
                Ok(val) => Ok(NoritoVersioned(val)),
                Err(versioned_err) => Err((
                    axum::http::StatusCode::BAD_REQUEST,
                    format!("Could not decode versioned request: {versioned_err}"),
                )
                    .into_response()),
            }
        }
    }
    fn version_from_json_value(value: &Value) -> Option<u8> {
        match value {
            Value::Number(number) => u8::try_from(number.as_u64()?).ok(),
            Value::Null
            | Value::Bool(_)
            | Value::String(_)
            | Value::Array(_)
            | Value::Object(_) => None,
        }
    }
    #[allow(clippy::result_large_err)]
    fn decode_versioned_json<T>(body: &Bytes, expected: &'static str) -> Result<T, Response>
    where
        T: JsonDeserializeOwned + Version,
    {
        let value = json::from_slice::<Value>(body.as_ref()).map_err(|e| {
            (StatusCode::BAD_REQUEST, format!("invalid JSON body: {e}")).into_response()
        })?;
        let object = value.as_object().ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid JSON body: expected versioned {expected} object"),
            )
                .into_response()
        })?;
        if let Some(unknown) = object
            .keys()
            .find(|key| !matches!(key.as_str(), "version" | "content"))
        {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("invalid JSON body: unknown versioned envelope field `{unknown}`"),
            )
                .into_response());
        }
        let version = object
            .get("version")
            .and_then(version_from_json_value)
            .ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    "invalid JSON body: missing numeric `version` field",
                )
                    .into_response()
            })?;
        if !T::supported_versions().contains(&version) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("unsupported JSON payload version `{version}` for {expected}"),
            )
                .into_response());
        }
        let content = object.get("content").ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "invalid JSON body: missing `content` field",
            )
                .into_response()
        })?;
        json::from_value::<T>(content.clone()).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid JSON {expected} content: {e}"),
            )
                .into_response()
        })
    }
    /// Helper trait exposing versioned JSON decoding for selected Torii ingress payloads.
    pub trait SupportsVersionedJsonDecode: Sized {
        /// Decode a JSON request body carrying a versioned payload.
        fn decode_versioned_json_body(
            body: &Bytes,
            ingress_limits: Option<(usize, norito::DecodeLimits)>,
        ) -> Result<Self, Response>;
    }
    fn signed_transaction_decode_rejection(message: impl Into<String>) -> Response {
        let mut response = super::respond_with_status_and_format(
            StatusCode::BAD_REQUEST,
            iroha_torii_shared::ErrorEnvelope::new(
                "invalid_transaction_payload",
                format!(
                    "transaction payload could not be decoded: {}",
                    message.into()
                ),
            ),
            super::current_response_format(),
        );
        response.headers_mut().insert(
            "x-iroha-reject-code",
            HeaderValue::from_static("invalid_transaction_payload"),
        );
        response
    }
    impl SupportsVersionedJsonDecode for SignedTransaction {
        fn decode_versioned_json_body(
            body: &Bytes,
            _ingress_limits: Option<(usize, norito::DecodeLimits)>,
        ) -> Result<Self, Response> {
            decode_versioned_json::<Self>(body, "SignedTransaction").map_err(|_| {
                signed_transaction_decode_rejection(
                    "invalid canonical JSON SignedTransaction representation",
                )
            })
        }
    }
    impl SupportsVersionedJsonDecode for TransactionEntrypoint {
        fn decode_versioned_json_body(
            body: &Bytes,
            _ingress_limits: Option<(usize, norito::DecodeLimits)>,
        ) -> Result<Self, Response> {
            decode_versioned_json::<Self>(body, "TransactionEntrypoint")
        }
    }
    impl SupportsVersionedJsonDecode for SignedQuery {
        fn decode_versioned_json_body(
            body: &Bytes,
            ingress_limits: Option<(usize, norito::DecodeLimits)>,
        ) -> Result<Self, Response> {
            decode_signed_query_json_with_limits(body, ingress_limits)
        }
    }
    /// Extractor for versioned request bodies supporting both Norito and JSON payloads.
    #[derive(Clone, Copy, Debug)]
    pub struct JsonOrNoritoVersioned<T>(pub T);
    /// Server-owned bounds installed by a pre-body admission extractor.
    #[derive(Clone, Copy, Debug)]
    pub(crate) struct VersionedIngressLimits {
        /// Maximum raw request body retained by the extractor.
        pub(crate) max_body_bytes: usize,
        /// Aggregate allocation and structural limits for Norito decoding.
        pub(crate) decode_limits: norito::DecodeLimits,
        /// Two-unit allocation and structural limits for JSON decoding.
        pub(crate) json_decode_limits: norito::DecodeLimits,
    }
    fn signed_query_json_fallback_limits(body_bytes: usize) -> norito::DecodeLimits {
        let elements = body_bytes.saturating_mul(8);
        norito::DecodeLimits::new(
            elements,
            body_bytes,
            elements,
            body_bytes.saturating_mul(2),
            norito::core::MAX_VALUE_NESTING_DEPTH,
        )
    }
    fn signed_query_json_rejection(resource_limit: bool) -> Response {
        if resource_limit {
            return typed_request_rejection(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_payload_too_large",
                "The signed-query JSON body exceeded its admitted decode resource limit.",
            );
        }
        typed_request_rejection(
            StatusCode::BAD_REQUEST,
            "invalid_query_payload",
            "The signed-query JSON body is not a valid canonical query representation.",
        )
    }
    fn decode_signed_query_json_with_limits(
        body: &Bytes,
        ingress_limits: Option<(usize, norito::DecodeLimits)>,
    ) -> Result<SignedQuery, Response> {
        let (max_body_bytes, decode_limits) = ingress_limits.map_or_else(
            || {
                let body_bytes = body.len();
                (body_bytes, signed_query_json_fallback_limits(body_bytes))
            },
            |limits| limits,
        );
        json::preflight_slice(
            body.as_ref(),
            json::JsonPreflightLimits::from_decode_limits(max_body_bytes, decode_limits),
        )
        .map_err(|error| signed_query_json_rejection(error.resource_kind().is_some()))?;
        let decoded = norito::with_decode_limits_scope(decode_limits, || {
            json::from_slice::<SignedQueryJson>(body.as_ref())
        })
        .map_err(|error| signed_query_json_rejection(error.is_decode_resource_limit()))?;
        decoded.try_into().map_err(
            |error: iroha_data_model::query::SignedQueryValidationError| {
                signed_query_json_rejection(error.is_decode_resource_limit())
            },
        )
    }
    fn versioned_decode_rejection<T: 'static>(
        versioned_err: iroha_version::error::Error,
    ) -> Response {
        if versioned_err.is_decode_resource_limit() {
            return typed_request_rejection(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_payload_too_large",
                "The versioned Norito body exceeded its admitted decode resource limit.",
            );
        }
        if TypeId::of::<T>() == TypeId::of::<SignedQuery>() {
            return typed_request_rejection(
                StatusCode::BAD_REQUEST,
                "invalid_query_payload",
                "The signed-query Norito body is not a valid canonical query representation.",
            );
        }
        let message = format!("Could not decode versioned request: {versioned_err}");
        if TypeId::of::<T>() == TypeId::of::<SignedTransaction>() {
            return signed_transaction_decode_rejection(message);
        }
        (StatusCode::BAD_REQUEST, message).into_response()
    }
    impl<S, T> FromRequest<S> for JsonOrNoritoVersioned<T>
    where
        Bytes: FromRequest<S, Rejection = axum::extract::rejection::BytesRejection>,
        S: Send + Sync,
        T: iroha_version::codec::DecodeVersioned + SupportsVersionedJsonDecode + 'static,
    {
        type Rejection = Response;
        async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
            let ingress_limits = req.extensions().get::<VersionedIngressLimits>().copied();
            let format = super::typed_request_content_format(req.headers())?;
            let body = match ingress_limits {
                Some(limits) => axum::body::to_bytes(req.into_body(), limits.max_body_bytes)
                    .await
                    .map_err(|_| {
                        typed_request_rejection(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "request_payload_too_large",
                            format!(
                                "The request body exceeds its admitted {}-byte memory limit.",
                                limits.max_body_bytes
                            ),
                        )
                    })?,
                None => Bytes::from_request(req, state)
                    .await
                    .map_err(typed_body_rejection)?,
            };
            match format {
                super::TypedRequestContentFormat::Norito => {
                    let decode = || {
                        <T as iroha_version::codec::DecodeVersioned>::decode_all_versioned(&body)
                    };
                    match ingress_limits {
                        Some(limits) => {
                            norito::with_decode_limits_scope(limits.decode_limits, decode)
                        }
                        None => decode(),
                    }
                    .map(JsonOrNoritoVersioned)
                    .map_err(versioned_decode_rejection::<T>)
                }
                super::TypedRequestContentFormat::Json => {
                    let json_limits = ingress_limits
                        .map(|limits| (limits.max_body_bytes, limits.json_decode_limits));
                    T::decode_versioned_json_body(&body, json_limits).map(JsonOrNoritoVersioned)
                }
            }
        }
    }
    /// Extractor of Accept header
    #[cfg_attr(not(feature = "telemetry"), allow(unused))]
    pub struct ExtractAccept(pub HeaderValue);
    impl<S> FromRequestParts<S> for ExtractAccept
    where
        S: Send + Sync,
    {
        type Rejection = (StatusCode, &'static str);
        fn from_request_parts(
            parts: &mut axum::http::request::Parts,
            _state: &S,
        ) -> impl core::future::Future<Output = Result<Self, Self::Rejection>> + Send {
            let res = parts
                .headers
                .get(axum::http::header::ACCEPT)
                .cloned()
                .map(ExtractAccept)
                .ok_or((StatusCode::BAD_REQUEST, "`Accept` header is missing"));
            core::future::ready(res)
        }
    }
    impl<S> OptionalFromRequestParts<S> for ExtractAccept
    where
        S: Send + Sync,
    {
        type Rejection = (StatusCode, &'static str);
        fn from_request_parts(
            parts: &mut axum::http::request::Parts,
            _state: &S,
        ) -> impl core::future::Future<Output = Result<Option<Self>, Self::Rejection>> + Send
        {
            let value = parts
                .headers
                .get(axum::http::header::ACCEPT)
                .cloned()
                .map(ExtractAccept);
            core::future::ready(Ok(value))
        }
    }
    /// Helper trait exposing Norito decoding for extractor-bound types.
    pub trait SupportsNoritoDecode: Sized {
        fn decode_norito(bytes: &[u8]) -> Result<Self, norito::Error>;
    }
    impl<T> SupportsNoritoDecode for T
    where
        T: norito::NoritoSerialize,
        for<'a> T: NoritoDeserialize<'a>,
    {
        fn decode_norito(bytes: &[u8]) -> Result<Self, norito::Error> {
            norito::decode_from_bytes::<T>(bytes)
        }
    }
    #[allow(clippy::result_large_err)] // extraction needs to return a fully-formed HTTP rejection response
    fn decode_as_json<T: JsonDeserializeOwned>(body: &Bytes) -> Result<T, Response> {
        #[cfg(feature = "app_api")]
        if let Some(decoded) = crate::decode_current_app_routed_read_json::<T>(body) {
            return decoded;
        }
        norito::json::from_slice::<T>(body.as_ref()).map_err(|e| {
            typed_request_rejection(
                StatusCode::BAD_REQUEST,
                "request_json_invalid",
                format!("Invalid JSON body: {e}"),
            )
        })
    }
    fn payload_kind_label<T: 'static>() -> &'static str {
        if TypeId::of::<T>() == TypeId::of::<SignedTransaction>() {
            "signed_transaction"
        } else if TypeId::of::<T>() == TypeId::of::<SignedQuery>() {
            "signed_query"
        } else {
            "other"
        }
    }
    fn record_payload_decode_failure<T: 'static>(error: &norito::Error) {
        record_norito_decode_failure(payload_kind_label::<T>(), error);
    }
    fn norito_decode_rejection<T: 'static>(error: &norito::Error) -> Response {
        record_payload_decode_failure::<T>(error);
        if error.is_decode_resource_limit() {
            return typed_request_rejection(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_payload_too_large",
                "The Norito body exceeded its admitted decode resource limit.",
            );
        }
        typed_request_rejection(
            StatusCode::BAD_REQUEST,
            "request_norito_invalid",
            format!("Invalid Norito body: {error}"),
        )
    }
    #[allow(clippy::result_large_err)] // extraction needs to return a fully-formed HTTP rejection response
    fn decode_as_norito<T: SupportsNoritoDecode + 'static>(body: &Bytes) -> Result<T, Response> {
        #[cfg(feature = "app_api")]
        if let Some(decoded) = crate::decode_current_app_routed_read_norito::<T>(body) {
            return decoded;
        }
        T::decode_norito(body.as_ref()).map_err(|error| norito_decode_rejection::<T>(&error))
    }
    #[cfg(feature = "telemetry")]
    fn record_norito_decode_failure(payload_kind: &'static str, error: &norito::Error) {
        iroha_telemetry::metrics::global_or_default()
            .inc_torii_norito_decode_failure(payload_kind, classify_norito_error(error));
    }
    #[cfg(feature = "telemetry")]
    fn classify_norito_error(error: &norito::Error) -> &'static str {
        use norito::Error;
        match error {
            Error::InvalidMagic => "invalid_magic",
            Error::UnsupportedVersion { .. } => "unsupported_version",
            Error::UnsupportedMinorVersion { .. } => "unsupported_minor_version",
            Error::UnsupportedCompression { .. } => "unsupported_compression",
            Error::LengthMismatch => "length_mismatch",
            Error::ArchiveLengthExceeded { .. } => "archive_length_exceeded",
            Error::ChecksumMismatch => "checksum_mismatch",
            Error::SchemaMismatch => "schema_mismatch",
            Error::UnsupportedFeature(flag) => match *flag {
                "layout flag" => "unsupported_feature_layout_flag",
                _ => "unsupported_feature",
            },
            Error::MissingPayloadContext => "missing_payload_context",
            Error::MissingLayoutFlags => "missing_layout_flags",
            Error::InvalidUtf8 => "invalid_utf8",
            Error::InvalidTag { .. } => "invalid_tag",
            Error::InvalidNonZero => "invalid_non_zero",
            Error::DecodePanic { .. } => "decode_panic",
            Error::Misaligned { .. } => "misaligned",
            Error::Io(_) => "io_error",
            Error::Message(_) => "message",
            _ => "other",
        }
    }
    #[cfg(not(feature = "telemetry"))]
    fn record_norito_decode_failure(_: &'static str, _: &norito::Error) {}
    #[allow(clippy::result_large_err)]
    /// Decode an already-admitted typed body after a caller-specific
    /// authentication boundary has run.
    pub(crate) fn decode_body_as_norito_or_json<
        T: JsonDeserializeOwned + SupportsNoritoDecode + 'static,
    >(
        body: &Bytes,
        format: super::TypedRequestContentFormat,
    ) -> Result<T, Response> {
        match format {
            super::TypedRequestContentFormat::Json => decode_as_json::<T>(body),
            super::TypedRequestContentFormat::Norito => decode_as_norito::<T>(body),
        }
    }
    /// Extractor for request bodies supporting both Norito and JSON payloads.
    #[derive(Clone, Copy, Debug)]
    pub struct NoritoJson<T>(pub T);
    impl<S, T> FromRequest<S> for NoritoJson<T>
    where
        Bytes: FromRequest<S, Rejection = axum::extract::rejection::BytesRejection>,
        S: Send + Sync,
        T: JsonDeserializeOwned + Send + 'static,
        T: SupportsNoritoDecode,
    {
        type Rejection = Response;
        async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
            let format = super::typed_request_content_format(req.headers())?;
            let body = admitted_typed_body(req, state).await?;
            decode_body_as_norito_or_json::<T>(&body, format).map(NoritoJson)
        }
    }
    /// Extractor for one canonical native-Norito request body.
    #[derive(Clone, Copy, Debug)]
    pub struct NoritoOnly<T>(pub T);
    impl<S, T> FromRequest<S> for NoritoOnly<T>
    where
        Bytes: FromRequest<S, Rejection = axum::extract::rejection::BytesRejection>,
        S: Send + Sync,
        T: SupportsNoritoDecode + Send + 'static,
    {
        type Rejection = Response;
        async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
            super::norito_request_content_type(req.headers())?;
            let body = Bytes::from_request(req, state)
                .await
                .map_err(typed_body_rejection)?;
            decode_as_norito::<T>(&body).map(NoritoOnly)
        }
    }
    /// Extractor that returns both the decoded payload and the raw request body.
    #[derive(Clone, Debug)]
    pub struct NoritoJsonWithBytes<T> {
        /// Parsed payload decoded from Norito or JSON.
        pub value: T,
        /// Raw request body bytes as sent over the wire.
        pub raw: Bytes,
    }
    impl<S, T> FromRequest<S> for NoritoJsonWithBytes<T>
    where
        Bytes: FromRequest<S, Rejection = axum::extract::rejection::BytesRejection>,
        S: Send + Sync,
        T: JsonDeserializeOwned + Send + 'static,
        T: SupportsNoritoDecode,
    {
        type Rejection = Response;
        async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
            let format = super::typed_request_content_format(req.headers())?;
            let body = admitted_typed_body(req, state).await?;
            decode_body_as_norito_or_json::<T>(&body, format)
                .map(|value| NoritoJsonWithBytes { value, raw: body })
        }
    }
    /// Extractor enforcing JSON payloads decoded with the Norito JSON codec.
    ///
    /// The request must declare exactly one canonical JSON media type before
    /// the body is read; missing, duplicate, or alternate declarations fail closed.
    #[derive(Clone, Debug)]
    pub struct JsonOnly<T>(pub T);
    impl<S, T> FromRequest<S> for JsonOnly<T>
    where
        Bytes: FromRequest<S, Rejection = axum::extract::rejection::BytesRejection>,
        S: Send + Sync,
        T: JsonDeserializeOwned + Send,
    {
        type Rejection = Response;
        async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
            super::canonical_json_request_content_type(req.headers())?;
            let body = admitted_typed_body(req, state).await?;
            decode_as_json::<T>(&body).map(JsonOnly)
        }
    }
    /// Extractor for canonical form-encoded URL queries decoded into
    /// `JsonDeserialize` types.
    ///
    /// An absent query decodes as an empty object. A present query must contain
    /// one to 64 unique, non-empty `key=value` pairs and at most 64 KiB of raw
    /// text. Components must use the one canonical
    /// `application/x-www-form-urlencoded` spelling: spaces are `+`, literal
    /// plus signs and all other escaped bytes use uppercase percent escapes,
    /// and bytes that can be written literally are not escaped.
    #[derive(Clone, Debug)]
    pub struct NoritoQuery<T>(pub T);
    impl<S, T> FromRequestParts<S> for NoritoQuery<T>
    where
        S: Send + Sync,
        T: JsonDeserializeOwned + Send,
    {
        type Rejection = Response;
        async fn from_request_parts(
            parts: &mut axum::http::request::Parts,
            _state: &S,
        ) -> Result<Self, Self::Rejection> {
            let query = parts.uri.query();
            if query == Some("") {
                return Err(query_rejection(QueryDecodeError::Invalid(
                    "A present query string must contain at least one key=value pair.",
                )));
            }
            #[cfg(feature = "app_api")]
            if let Some(decoded) =
                crate::decode_current_app_routed_read_query::<T>(query.unwrap_or_default(), true)
            {
                return decoded.map(NoritoQuery);
            }
            match decode_query::<T>(query) {
                Ok(value) => Ok(NoritoQuery(value)),
                Err(error) => Err(query_rejection(error)),
            }
        }
    }
    /// Extractor for canonical form-encoded URL queries decoded into
    /// `JsonDeserialize` types without scalar type coercion.
    #[derive(Clone, Debug)]
    pub struct NoritoStringQuery<T>(pub T);
    impl<S, T> FromRequestParts<S> for NoritoStringQuery<T>
    where
        S: Send + Sync,
        T: JsonDeserializeOwned + Send,
    {
        type Rejection = Response;
        async fn from_request_parts(
            parts: &mut axum::http::request::Parts,
            _state: &S,
        ) -> Result<Self, Self::Rejection> {
            let query = parts.uri.query();
            if query == Some("") {
                return Err(query_rejection(QueryDecodeError::Invalid(
                    "A present query string must contain at least one key=value pair.",
                )));
            }
            #[cfg(feature = "app_api")]
            if let Some(decoded) =
                crate::decode_current_app_routed_read_query::<T>(query.unwrap_or_default(), false)
            {
                return decoded.map(NoritoStringQuery);
            }
            match decode_string_query::<T>(query) {
                Ok(value) => Ok(NoritoStringQuery(value)),
                Err(error) => Err(query_rejection(error)),
            }
        }
    }
    fn decode_query<T: JsonDeserializeOwned>(query: Option<&str>) -> Result<T, QueryDecodeError> {
        let pairs = query_pairs(query)?;
        reject_duplicate_query_keys(&pairs)?;
        let mut object = json::Map::new();
        for (key, value) in pairs {
            object.insert(key, scalar_to_value(&value));
        }
        json::from_value(Value::Object(object))
            .map_err(|err| QueryDecodeError::Schema(err.to_string()))
    }
    fn decode_string_query<T: JsonDeserializeOwned>(
        query: Option<&str>,
    ) -> Result<T, QueryDecodeError> {
        let pairs = query_pairs(query)?;
        reject_duplicate_query_keys(&pairs)?;
        let mut object = json::Map::new();
        for (key, value) in pairs {
            object.insert(key, Value::String(value));
        }
        json::from_value(Value::Object(object))
            .map_err(|err| QueryDecodeError::Schema(err.to_string()))
    }
    fn reject_duplicate_query_keys(pairs: &[(String, String)]) -> Result<(), QueryDecodeError> {
        // Structured query DTOs have exactly one value per field. Keep this
        // check local to the DTO decoders so protocol-specific parsers can
        // still define ordered or repeated-key semantics explicitly.
        let mut seen = std::collections::BTreeSet::new();
        for (key, _) in pairs {
            if !seen.insert(key.as_str()) {
                return Err(QueryDecodeError::Invalid(
                    "Query parameters contain a duplicate decoded key.",
                ));
            }
        }
        Ok(())
    }
    fn query_pairs(query: Option<&str>) -> Result<Vec<(String, String)>, QueryDecodeError> {
        let Some(query) = query else {
            return Ok(Vec::new());
        };
        if query.is_empty() {
            return Err(QueryDecodeError::Invalid(
                "A present query string must contain at least one key=value pair.",
            ));
        }
        if query.len() > TORII_QUERY_MAX_RAW_BYTES_V1 {
            return Err(QueryDecodeError::Capacity {
                resource: "raw-byte",
                attempted: query.len(),
                limit: TORII_QUERY_MAX_RAW_BYTES_V1,
            });
        }

        let mut pairs = Vec::new();
        for segment in query.split('&') {
            if pairs.len() == TORII_QUERY_MAX_PAIRS_V1 {
                return Err(QueryDecodeError::Capacity {
                    resource: "pair-count",
                    attempted: TORII_QUERY_MAX_PAIRS_V1 + 1,
                    limit: TORII_QUERY_MAX_PAIRS_V1,
                });
            }
            if segment.is_empty() {
                return Err(QueryDecodeError::Invalid(
                    "Query parameters must not contain empty segments.",
                ));
            }
            let Some((raw_key, raw_value)) = segment.split_once('=') else {
                return Err(QueryDecodeError::Invalid(
                    "Every query parameter must use key=value framing.",
                ));
            };
            if raw_key.is_empty() || raw_value.is_empty() {
                return Err(QueryDecodeError::Invalid(
                    "Query parameter names and values must be non-empty.",
                ));
            }
            pairs.push((decode_component(raw_key)?, decode_component(raw_value)?));
        }
        Ok(pairs)
    }
    fn decode_component(input: &str) -> Result<String, QueryDecodeError> {
        // Ordinary RFC 3986 / HTML-form decoding: escapes may use either
        // hexadecimal case and may escape any byte, and `+` and `%20` are
        // both spaces. Duplicate-key checks, caches and request signatures
        // all work on the decoded pairs, so alternate spellings of one
        // component are equivalent rather than distinct requests.
        let bytes = input.as_bytes();
        let mut position = 0;
        while position < bytes.len() {
            match bytes[position] {
                b'%' => {
                    let escape = bytes.get(position + 1..position + 3);
                    if !escape.is_some_and(|digits| digits.iter().all(u8::is_ascii_hexdigit)) {
                        return Err(QueryDecodeError::Invalid(
                            "Query parameters contain an incomplete percent escape; write a literal `%` as `%25`.",
                        ));
                    }
                    position += 3;
                }
                byte if byte.is_ascii_graphic() => position += 1,
                _ => {
                    return Err(QueryDecodeError::Invalid(
                        "Query parameters must percent-encode spaces, control characters and non-ASCII bytes.",
                    ));
                }
            }
        }
        let replaced = input.replace('+', " ");
        let decoded = decode(&replaced)
            .map(std::borrow::Cow::into_owned)
            .map_err(|_| QueryDecodeError::Invalid("Query components must decode as UTF-8."))?;
        if decoded.chars().any(char::is_control) {
            return Err(QueryDecodeError::Invalid(
                "Query components must not contain control characters.",
            ));
        }
        Ok(decoded)
    }
    fn scalar_to_value(raw: &str) -> Value {
        if raw == "null" {
            Value::Null
        } else if raw == "true" {
            Value::Bool(true)
        } else if raw == "false" {
            Value::Bool(false)
        } else if canonical_unsigned_decimal(raw)
            && let Ok(u) = raw.parse::<u64>()
        {
            Value::Number(Number::from(u))
        } else if canonical_negative_decimal(raw)
            && let Ok(i) = raw.parse::<i64>()
        {
            Value::Number(Number::from(i))
        } else {
            Value::String(raw.to_owned())
        }
    }
    fn canonical_unsigned_decimal(raw: &str) -> bool {
        raw == "0"
            || raw.as_bytes().split_first().is_some_and(|(first, rest)| {
                matches!(*first, b'1'..=b'9') && rest.iter().all(u8::is_ascii_digit)
            })
    }
    fn canonical_negative_decimal(raw: &str) -> bool {
        raw.strip_prefix('-')
            .is_some_and(|magnitude| magnitude != "0" && canonical_unsigned_decimal(magnitude))
    }
    #[cfg(test)]
    pub(crate) mod tests {
        use super::*;
        use axum::{
            body::Body,
            extract::{DefaultBodyLimit, FromRequestParts},
            http::{HeaderValue, Request, StatusCode, header::CONTENT_TYPE},
        };
        use http_body_util::BodyExt as _;
        use iroha_version::{RawVersioned, UnsupportedVersion, Version};
        use norito::core::{NoritoDeserialize, NoritoSerialize};
        #[derive(norito::NoritoSchema)]
        #[norito_schema(name = "iroha_torii::utils::extractors::tests::Dummy")]
        #[derive(
            Clone,
            Debug,
            PartialEq,
            NoritoSerialize,
            NoritoDeserialize,
            crate::json_macros::JsonSerialize,
            crate::json_macros::JsonDeserialize,
        )]

        struct Dummy(u32);
        #[test]
        fn bounded_decode_resource_failures_are_terminal_payload_limits() {
            let norito_response =
                norito_decode_rejection::<Dummy>(&norito::Error::TotalAllocationExceeded {
                    attempted: 2,
                    limit: 1,
                });
            assert_eq!(norito_response.status(), StatusCode::PAYLOAD_TOO_LARGE);
            let versioned_response = versioned_decode_rejection::<Dummy>(
                iroha_version::error::Error::NoritoResourceLimit(
                    norito::core::DecodeResourceError::TotalAllocationExceeded {
                        attempted: 1,
                        limit: 0,
                    },
                ),
            );
            assert_eq!(versioned_response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        }
        #[tokio::test]
        async fn signed_query_versioned_decode_rejection_does_not_reflect_codec_text() {
            let marker = "attacker-controlled-versioned-diagnostic";
            let response = versioned_decode_rejection::<SignedQuery>(
                iroha_version::error::Error::NoritoCodec(marker.repeat(32)),
            );
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let body = response
                .into_body()
                .collect()
                .await
                .expect("collect fixed decode rejection")
                .to_bytes();
            assert!(
                !body
                    .windows(marker.len())
                    .any(|window| window == marker.as_bytes())
            );
            let envelope: iroha_torii_shared::ErrorEnvelope =
                norito::decode_from_bytes(&body).expect("decode fixed Norito rejection envelope");
            assert_eq!(envelope.code(), "invalid_query_payload");
        }
        #[test]
        fn signed_query_json_raw_limit_accepts_exact_and_rejects_one_extra_byte() {
            let body = Bytes::from_static(b"null");
            let decode_limits = norito::DecodeLimits::new(
                body.len(),
                body.len(),
                body.len(),
                body.len() * 2,
                norito::core::MAX_VALUE_NESTING_DEPTH,
            );
            let exact = VersionedIngressLimits {
                max_body_bytes: body.len(),
                decode_limits,
                json_decode_limits: decode_limits,
            };
            let exact_error = match decode_signed_query_json_with_limits(
                &body,
                Some((exact.max_body_bytes, exact.json_decode_limits)),
            ) {
                Ok(_) => panic!("null is not a signed query"),
                Err(response) => response,
            };
            assert_eq!(
                exact_error.status(),
                StatusCode::BAD_REQUEST,
                "the exact raw-body boundary must reach syntax/type validation"
            );
            let one_byte_too_small = VersionedIngressLimits {
                max_body_bytes: body.len() - 1,
                ..exact
            };
            let oversized_error = match decode_signed_query_json_with_limits(
                &body,
                Some((
                    one_byte_too_small.max_body_bytes,
                    one_byte_too_small.json_decode_limits,
                )),
            ) {
                Ok(_) => panic!("one raw byte above the limit must fail"),
                Err(response) => response,
            };
            assert_eq!(oversized_error.status(), StatusCode::PAYLOAD_TOO_LARGE);
        }
        #[derive(Clone, Debug, PartialEq, crate::json_macros::JsonDeserialize)]
        struct StringQueryForTest {
            numeric_hex: Option<String>,
            leading_zero_hex: Option<String>,
            null_like: Option<String>,
            bool_like: Option<String>,
            label: Option<String>,
        }
        #[derive(Clone, Debug, PartialEq, crate::json_macros::JsonDeserialize)]
        struct RequiredQueryForTest {
            asset_definition_id: String,
        }
        #[tokio::test]
        async fn malformed_query_uses_typed_error_envelope() {
            let (mut parts, _) = Request::builder()
                .uri("/?unexpected=value")
                .body(())
                .expect("request")
                .into_parts();
            let response = super::super::with_current_response_format(
                super::super::ResponseFormat::Json,
                NoritoQuery::<RequiredQueryForTest>::from_request_parts(&mut parts, &()),
            )
            .await
            .expect_err("missing required query field must fail");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                response.headers().get(CONTENT_TYPE),
                Some(&HeaderValue::from_static("application/json"))
            );
            let bytes = response
                .into_body()
                .collect()
                .await
                .expect("collect typed query error")
                .to_bytes();
            let envelope: iroha_torii_shared::ErrorEnvelope =
                norito::json::from_slice(&bytes).expect("decode typed query error");
            assert_eq!(envelope.code(), "request_query_invalid");
        }
        #[tokio::test]
        async fn duplicate_query_fields_are_rejected_in_any_spelling() {
            // Alternate percent-encodings decode to the same key, so they are
            // duplicates rather than distinct parameters.
            for (query, expected_message) in [
                (
                    "asset_definition_id=first&asset_definition_id=second",
                    "duplicate decoded key",
                ),
                (
                    "asset_definition_id=first&asset%5fdefinition%5fid=second",
                    "duplicate decoded key",
                ),
                (
                    "asset_definition_id=first&%61sset_definition_id=second",
                    "duplicate decoded key",
                ),
                (
                    "asset_definition_id=first&asset%5Fdefinition%5Fid=second",
                    "duplicate decoded key",
                ),
            ] {
                let request = Request::builder()
                    .uri(format!("/?{query}"))
                    .body(())
                    .expect("request");
                let (mut parts, _) = request.into_parts();
                let response = super::super::with_current_response_format(
                    super::super::ResponseFormat::Json,
                    NoritoQuery::<RequiredQueryForTest>::from_request_parts(&mut parts, &()),
                )
                .await
                .expect_err("duplicate query field must fail");
                assert_eq!(response.status(), StatusCode::BAD_REQUEST, "query={query}");
                let bytes = response
                    .into_body()
                    .collect()
                    .await
                    .expect("collect duplicate-query error")
                    .to_bytes();
                let envelope: iroha_torii_shared::ErrorEnvelope =
                    norito::json::from_slice(&bytes).expect("decode duplicate-query error");
                assert_eq!(envelope.code(), "request_query_invalid", "query={query}");
                assert!(
                    envelope.message().contains(expected_message),
                    "query={query}, envelope={envelope:?}"
                );
            }
        }
        #[tokio::test]
        async fn malformed_percent_encoding_uses_typed_query_error() {
            for malformed in ["%", "%2", "%GG"] {
                for query in [
                    format!("asset_definition_id={malformed}"),
                    format!("{malformed}=value"),
                ] {
                    let request = Request::builder()
                        .uri(format!("/?{query}"))
                        .body(())
                        .expect("request URI");
                    let (mut parts, _) = request.into_parts();
                    let response = super::super::with_current_response_format(
                        super::super::ResponseFormat::Json,
                        NoritoQuery::<RequiredQueryForTest>::from_request_parts(&mut parts, &()),
                    )
                    .await
                    .expect_err("malformed percent escape must fail closed");
                    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "query={query}");
                    let bytes = response
                        .into_body()
                        .collect()
                        .await
                        .expect("collect malformed-query response")
                        .to_bytes();
                    let envelope: iroha_torii_shared::ErrorEnvelope =
                        norito::json::from_slice(&bytes).expect("decode typed query error");
                    assert_eq!(envelope.code(), "request_query_invalid");
                    assert!(
                        envelope.message().contains("percent escape"),
                        "query={query}, envelope={envelope:?}"
                    );
                }
            }
        }
        #[test]
        fn query_plus_and_percent_encoded_plus_have_distinct_form_semantics() {
            let space: StringQueryForTest =
                super::decode_string_query(Some("label=alpha+beta")).expect("form-space query");
            assert_eq!(space.label.as_deref(), Some("alpha beta"));
            let plus: StringQueryForTest =
                super::decode_string_query(Some("label=alpha%2Bbeta")).expect("literal-plus query");
            assert_eq!(plus.label.as_deref(), Some("alpha+beta"));
        }
        #[test]
        fn generic_query_accepts_rfc3986_spellings() {
            for (query, expected) in [
                ("label=alpha%20beta", "alpha beta"),
                ("label=%61lpha", "alpha"),
                ("label=alpha%2bbeta", "alpha+beta"),
                ("label=alpha/beta", "alpha/beta"),
                ("label=alpha:beta", "alpha:beta"),
                ("label=alpha~beta", "alpha~beta"),
                ("label=alpha%C2%A0beta", "alpha\u{a0}beta"),
            ] {
                let decoded: StringQueryForTest = super::decode_string_query(Some(query))
                    .unwrap_or_else(|err| panic!("{query:?} decodes: {err:?}"));
                assert_eq!(decoded.label.as_deref(), Some(expected), "{query:?}");
            }
            for query in [
                "label=alpha%0Abeta",
                "label=alpha beta",
                "label=alpha💖beta",
            ] {
                assert!(
                    super::decode_string_query::<StringQueryForTest>(Some(query)).is_err(),
                    "query {query:?} must be rejected"
                );
            }
            let decoded: StringQueryForTest =
                super::decode_string_query(Some("label=alpha%F0%9F%92%96beta"))
                    .expect("uppercase UTF-8 escapes are canonical");
            assert_eq!(decoded.label.as_deref(), Some("alpha💖beta"));
            let decoded: StringQueryForTest = super::decode_string_query(Some("label=alpha*beta"))
                .expect("the form asterisk is a canonical literal");
            assert_eq!(decoded.label.as_deref(), Some("alpha*beta"));
            let decoded: StringQueryForTest =
                super::decode_string_query(Some("label=alpha%7Ebeta"))
                    .expect("tilde is canonically escaped by form encoding");
            assert_eq!(decoded.label.as_deref(), Some("alpha~beta"));
        }
        #[test]
        fn generic_query_rejects_empty_and_ambiguous_framing() {
            for query in ["", "&", "label", "=value", "label=", "label=x&"] {
                assert!(
                    super::query_pairs(Some(query)).is_err(),
                    "query {query:?} must be rejected"
                );
            }
            assert_eq!(
                super::query_pairs(Some("label=x=")).expect("`=` inside a value"),
                vec![("label".to_owned(), "x=".to_owned())]
            );
            assert!(super::query_pairs(None).expect("absent query").is_empty());
        }
        #[test]
        fn generic_query_capacity_boundaries_are_exact() {
            let exact_pairs = (0..super::TORII_QUERY_MAX_PAIRS_V1)
                .map(|index| format!("k{index}=v"))
                .collect::<Vec<_>>()
                .join("&");
            assert_eq!(
                super::query_pairs(Some(&exact_pairs))
                    .expect("exact pair-count boundary")
                    .len(),
                super::TORII_QUERY_MAX_PAIRS_V1
            );
            let excessive_pairs = format!("{exact_pairs}&overflow=v");
            assert!(matches!(
                super::query_pairs(Some(&excessive_pairs)),
                Err(super::QueryDecodeError::Capacity {
                    resource: "pair-count",
                    ..
                })
            ));

            let exact_bytes = format!("k={}", "a".repeat(super::TORII_QUERY_MAX_RAW_BYTES_V1 - 2));
            assert!(super::query_pairs(Some(&exact_bytes)).is_ok());
            let excessive_bytes = format!("{exact_bytes}a");
            assert!(matches!(
                super::query_pairs(Some(&excessive_bytes)),
                Err(super::QueryDecodeError::Capacity {
                    resource: "raw-byte",
                    ..
                })
            ));
        }
        #[test]
        fn generic_query_scalar_coercion_accepts_only_canonical_spellings() {
            assert_eq!(super::scalar_to_value("null"), Value::Null);
            assert_eq!(super::scalar_to_value("true"), Value::Bool(true));
            assert_eq!(super::scalar_to_value("false"), Value::Bool(false));
            assert_eq!(
                super::scalar_to_value("0"),
                Value::Number(Number::from(0_u64))
            );
            assert_eq!(
                super::scalar_to_value("42"),
                Value::Number(Number::from(42_u64))
            );
            assert_eq!(
                super::scalar_to_value("-42"),
                Value::Number(Number::from(-42_i64))
            );
            for alias in [
                "NULL", "TRUE", "False", "00", "01", "-0", "+1", "1.0", "1e0",
            ] {
                assert_eq!(
                    super::scalar_to_value(alias),
                    Value::String(alias.to_owned()),
                    "scalar alias {alias:?} must remain text"
                );
            }
        }
        #[tokio::test]
        async fn duplicate_string_query_fields_are_rejected_before_deserialization() {
            let request = Request::builder()
                .uri("/?asset_definition_id=first&asset_definition_id=second")
                .body(())
                .expect("request");
            let (mut parts, _) = request.into_parts();
            let response = super::super::with_current_response_format(
                super::super::ResponseFormat::Json,
                NoritoStringQuery::<RequiredQueryForTest>::from_request_parts(&mut parts, &()),
            )
            .await
            .expect_err("duplicate string query field must fail");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let bytes = response
                .into_body()
                .collect()
                .await
                .expect("collect duplicate string-query error")
                .to_bytes();
            let envelope: iroha_torii_shared::ErrorEnvelope =
                norito::json::from_slice(&bytes).expect("decode duplicate string-query error");
            assert_eq!(envelope.code(), "request_query_invalid");
            assert!(envelope.message().contains("duplicate decoded key"));
        }
        impl Version for Dummy {
            fn version(&self) -> u8 {
                1
            }
            fn supported_versions() -> std::ops::Range<u8> {
                1..2
            }
        }
        impl iroha_version::codec::DecodeVersioned for Dummy {
            fn decode_all_versioned(input: &[u8]) -> iroha_version::error::Result<Self> {
                let (version, rest) = input
                    .split_first()
                    .ok_or(iroha_version::error::Error::NotVersioned)?;
                if *version != 1 {
                    return Err(iroha_version::error::Error::UnsupportedVersion(Box::new(
                        UnsupportedVersion::new(*version, RawVersioned::NoritoBytes(rest.to_vec())),
                    )));
                }
                norito::decode_from_bytes(rest).map_err(Into::into)
            }
        }
        #[test]
        fn versioned_json_requires_numeric_version_and_exact_envelope_fields() {
            let canonical = Bytes::from_static(br#"{"version":1,"content":[42]}"#);
            assert_eq!(
                decode_versioned_json::<Dummy>(&canonical, "Dummy")
                    .expect("canonical numeric V1 envelope"),
                Dummy(42)
            );

            for (label, body) in [
                (
                    "string version",
                    br#"{"version":"1","content":[42]}"#.as_slice(),
                ),
                (
                    "unknown envelope field",
                    br#"{"version":1,"content":[42],"legacy":true}"#.as_slice(),
                ),
            ] {
                let response =
                    decode_versioned_json::<Dummy>(&Bytes::copy_from_slice(body), "Dummy")
                        .expect_err(label);
                assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{label}");
            }
        }
        #[tokio::test]
        async fn decodes_versioned_payload() {
            let mut payload = vec![1];
            payload
                .extend_from_slice(&norito::to_bytes(&Dummy(42)).expect("encode versioned dummy"));
            let req = Request::builder()
                .header(CONTENT_TYPE, super::super::NORITO_MIME_TYPE)
                .body(Body::from(payload))
                .unwrap();
            let extracted = NoritoVersioned::<Dummy>::from_request(req, &())
                .await
                .expect("extract versioned");
            assert_eq!(extracted.0, Dummy(42));
        }
        #[tokio::test]
        async fn rejects_missing_content_type() {
            let body = norito::to_bytes(&Dummy(7)).expect("encode bare dummy");
            let req = Request::new(Body::from(body));
            let err = NoritoVersioned::<Dummy>::from_request(req, &())
                .await
                .expect_err("missing content-type should be rejected");
            assert_eq!(err.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        }
        #[tokio::test]
        async fn surfaces_decode_error() {
            let req = Request::builder()
                .header(CONTENT_TYPE, super::super::NORITO_MIME_TYPE)
                .body(Body::from(vec![2]))
                .expect("request");
            let err = NoritoVersioned::<Dummy>::from_request(req, &())
                .await
                .expect_err("should fail");
            assert_eq!(err.status(), StatusCode::BAD_REQUEST);
            let body_bytes = http_body_util::BodyExt::collect(err.into_body())
                .await
                .expect("collect error body")
                .to_bytes();
            let body_text = String::from_utf8(body_bytes.to_vec()).expect("response text");
            assert!(
                body_text.contains("Could not decode versioned request"),
                "body should describe decode failure: {body_text}"
            );
            assert!(
                body_text.to_ascii_lowercase().contains("version"),
                "body should mention versioned decode reason: {body_text}"
            );
        }
        #[tokio::test]
        async fn norito_string_query_preserves_numeric_looking_strings() {
            let numeric_hex = "11".repeat(32);
            let leading_zero_hex = format!("{}1", "0".repeat(63));
            let request = Request::builder()
                .uri(format!(
                    "/test?numeric_hex={numeric_hex}&leading_zero_hex={leading_zero_hex}&null_like=null&bool_like=true&label=alpha+beta"
                ))
                .body(())
                .expect("request");
            let (mut parts, _) = request.into_parts();
            let NoritoStringQuery(decoded) =
                NoritoStringQuery::<StringQueryForTest>::from_request_parts(&mut parts, &())
                    .await
                    .expect("string query should decode");
            assert_eq!(decoded.numeric_hex.as_deref(), Some(numeric_hex.as_str()));
            assert_eq!(
                decoded.leading_zero_hex.as_deref(),
                Some(leading_zero_hex.as_str())
            );
            assert_eq!(decoded.null_like.as_deref(), Some("null"));
            assert_eq!(decoded.bool_like.as_deref(), Some("true"));
            assert_eq!(decoded.label.as_deref(), Some("alpha beta"));
        }
        #[tokio::test]
        async fn signed_transaction_versioned_decode_error_returns_error_envelope() {
            let req = Request::builder()
                .header(CONTENT_TYPE, super::super::NORITO_MIME_TYPE)
                .body(Body::from(Vec::<u8>::new()))
                .expect("request");
            let err = JsonOrNoritoVersioned::<SignedTransaction>::from_request(req, &())
                .await
                .expect_err("should fail");
            assert_eq!(err.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                err.headers().get(CONTENT_TYPE),
                Some(&HeaderValue::from_static(super::super::NORITO_MIME_TYPE))
            );
            assert_eq!(
                err.headers()
                    .get("x-iroha-reject-code")
                    .and_then(|value| value.to_str().ok()),
                Some("invalid_transaction_payload")
            );
            let body = http_body_util::BodyExt::collect(err.into_body())
                .await
                .expect("collect error body")
                .to_bytes();
            let envelope: iroha_torii_shared::ErrorEnvelope =
                norito::decode_from_bytes(&body).expect("decode error envelope");
            assert_eq!(envelope.code(), "invalid_transaction_payload");
            assert!(
                envelope
                    .message()
                    .contains("transaction payload could not be decoded"),
                "unexpected error envelope: {envelope:?}"
            );
        }
        #[tokio::test]
        async fn signed_transaction_json_decode_error_uses_the_same_exact_contract() {
            let req = Request::builder()
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(br#"{"version":1,"content":{}}"#.as_slice()))
                .expect("request");
            let err = JsonOrNoritoVersioned::<SignedTransaction>::from_request(req, &())
                .await
                .expect_err("malformed canonical JSON transaction should fail");
            assert_eq!(err.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                err.headers()
                    .get("x-iroha-reject-code")
                    .and_then(|value| value.to_str().ok()),
                Some("invalid_transaction_payload")
            );
            let body = http_body_util::BodyExt::collect(err.into_body())
                .await
                .expect("collect error body")
                .to_bytes();
            let envelope: iroha_torii_shared::ErrorEnvelope =
                norito::decode_from_bytes(&body).expect("decode error envelope");
            assert_eq!(envelope.code(), "invalid_transaction_payload");
            assert!(
                envelope
                    .message()
                    .contains("transaction payload could not be decoded"),
                "unexpected error envelope: {envelope:?}"
            );
        }
        #[tokio::test]
        async fn content_type_matrix_maps_to_status_codes() {
            let versioned_ok = {
                let mut payload = vec![1];
                payload.extend_from_slice(
                    &norito::to_bytes(&Dummy(11)).expect("encode versioned dummy"),
                );
                payload
            };
            let bare_ok = norito::to_bytes(&Dummy(7)).expect("encode bare dummy");
            let cases = [
                (
                    "missing",
                    None,
                    bare_ok.clone(),
                    Err(StatusCode::UNSUPPORTED_MEDIA_TYPE),
                    None,
                ),
                (
                    "wrong",
                    Some("text/plain"),
                    bare_ok.clone(),
                    Err(StatusCode::UNSUPPORTED_MEDIA_TYPE),
                    None,
                ),
                (
                    "versioned decode fail",
                    Some(super::super::NORITO_MIME_TYPE),
                    vec![2_u8],
                    Err(StatusCode::BAD_REQUEST),
                    Some("versioned"),
                ),
                (
                    "bare norito is rejected",
                    Some(super::super::NORITO_MIME_TYPE),
                    bare_ok,
                    Err(StatusCode::BAD_REQUEST),
                    Some("versioned"),
                ),
                (
                    "norito with parameters is rejected",
                    Some("application/x-norito; charset=utf-8"),
                    versioned_ok.clone(),
                    Err(StatusCode::UNSUPPORTED_MEDIA_TYPE),
                    None,
                ),
                (
                    "plain norito succeeds",
                    Some(super::super::NORITO_MIME_TYPE),
                    versioned_ok,
                    Ok(Dummy(11)),
                    None,
                ),
            ];
            for (label, content_type, payload, expected, snippet) in cases {
                let mut builder = Request::builder();
                if let Some(ct) = content_type {
                    builder = builder.header(CONTENT_TYPE, ct);
                }
                let req = builder.body(Body::from(payload)).expect("request");
                let result = NoritoVersioned::<Dummy>::from_request(req, &()).await;
                match expected {
                    Ok(expected_payload) => {
                        let ok = result.unwrap_or_else(|resp| {
                            panic!("{label} should succeed, got {}", resp.status())
                        });
                        assert_eq!(ok.0, expected_payload, "case `{label}` payload mismatch");
                    }
                    Err(expected_status) => {
                        let err = result.expect_err(label);
                        assert_eq!(err.status(), expected_status, "case `{label}`");
                        if let Some(snippet) = snippet {
                            let body = http_body_util::BodyExt::collect(err.into_body())
                                .await
                                .expect("collect body")
                                .to_bytes();
                            let text = String::from_utf8_lossy(&body);
                            assert!(
                                text.to_ascii_lowercase()
                                    .contains(&snippet.to_ascii_lowercase()),
                                "case `{label}` should mention `{snippet}`: {text}"
                            );
                        }
                    }
                }
            }
        }
        #[test]
        fn negotiate_accept_header_prefers_norito() {
            let header =
                HeaderValue::from_static("application/json;q=0.5, application/x-norito;q=0.9");
            let format = super::super::negotiate_response_format(Some(&header)).expect("format");
            assert_eq!(format, super::super::ResponseFormat::Norito);
        }
        #[test]
        fn negotiate_accept_header_honors_json() {
            let header = HeaderValue::from_static("application/json");
            let format = super::super::negotiate_response_format(Some(&header)).expect("format");
            assert_eq!(format, super::super::ResponseFormat::Json);
        }
        #[test]
        fn negotiate_accept_header_defaults_json() {
            let format = super::super::negotiate_response_format(None).expect("format");
            assert_eq!(format, super::super::ResponseFormat::Json);
        }
        #[test]
        fn negotiate_accept_header_wildcards_default_json() {
            for raw in ["*/*", "application/*"] {
                let header = HeaderValue::from_static(raw);
                let format =
                    super::super::negotiate_response_format(Some(&header)).expect("format");
                assert_eq!(format, super::super::ResponseFormat::Json, "header={raw}");
            }
        }
        #[test]
        fn negotiate_accept_header_explicit_zero_overrides_wildcard() {
            let header = HeaderValue::from_static("application/x-norito;q=0, */*;q=1");
            let format = super::super::negotiate_response_format(Some(&header)).expect("format");
            assert_eq!(format, super::super::ResponseFormat::Json);
        }
        #[test]
        fn negotiate_accept_header_uses_wildcard_quality_per_representation() {
            let header = HeaderValue::from_static("application/json;q=0.8, */*;q=0.9");
            let format = super::super::negotiate_response_format(Some(&header)).expect("format");
            assert_eq!(format, super::super::ResponseFormat::Norito);
        }
        #[test]
        fn negotiate_accept_header_prefers_more_specific_equal_quality() {
            let header = HeaderValue::from_static("application/json, application/*");
            let format = super::super::negotiate_response_format(Some(&header)).expect("format");
            assert_eq!(format, super::super::ResponseFormat::Json);
        }
        #[test]
        fn negotiate_uses_first_equally_specific_range() {
            let header = HeaderValue::from_static(
                "application/json;q=0.2, application/json;q=0.9, application/x-norito;q=0.5",
            );
            let format = super::super::negotiate_response_format(Some(&header)).expect("format");
            assert_eq!(format, super::super::ResponseFormat::Norito);
        }
        #[test]
        fn negotiate_accept_header_treats_structured_suffix_as_json_compatible() {
            let header = HeaderValue::from_static("application/vnd.api+json");
            assert_eq!(
                super::super::negotiate_response_format(Some(&header)).expect("format"),
                super::super::ResponseFormat::Json
            );
        }
        #[test]
        fn negotiate_canonical_range_overrides_suffix_quality() {
            let header = HeaderValue::from_static(
                "application/vnd.api+json;q=1, application/json;q=0.4, application/x-norito;q=0.5",
            );
            assert_eq!(
                super::super::negotiate_response_format(Some(&header)).expect("format"),
                super::super::ResponseFormat::Norito,
                "a canonical JSON range remains more specific than a suffix-compatible range"
            );
            let header = HeaderValue::from_static(
                "application/vnd.api+json;q=1, application/json;q=0, */*;q=0.5",
            );
            assert_eq!(
                super::super::negotiate_response_format(Some(&header)).expect("format"),
                super::super::ResponseFormat::Norito,
                "an exact application/json rejection must override its wildcard match"
            );
        }
        #[test]
        fn negotiate_rejects_unsupported_media_type() {
            let header = HeaderValue::from_static("text/plain");
            let err = super::super::negotiate_response_format(Some(&header)).unwrap_err();
            assert_eq!(err.status(), StatusCode::NOT_ACCEPTABLE);
        }
        #[test]
        fn negotiate_rejects_invalid_q_value() {
            for raw in [
                "application/json;q=2",
                "application/json;q=.5",
                "application/json;q=0.1234",
                "application/json;q=1.001",
                "application/json;q=-0.1",
                "application/json;q",
                "application/json;q=0.5;q=0.7",
            ] {
                let header = raw
                    .parse::<HeaderValue>()
                    .expect("syntactically valid header bytes");
                let err = super::super::negotiate_response_format(Some(&header))
                    .expect_err("malformed q-value must fail closed");
                assert_eq!(err.status(), StatusCode::NOT_ACCEPTABLE, "header={raw}");
            }
        }
        #[test]
        fn negotiate_accepts_exact_http_qvalue_boundaries() {
            for raw in [
                "application/json;q=0",
                "application/json;q=0.",
                "application/json;q=0.000",
                "application/json;q=0.001",
                "application/json;q=0.999",
                "application/json;q=1",
                "application/json;q=1.",
                "application/json;q=1.000",
            ] {
                let header = raw
                    .parse::<HeaderValue>()
                    .expect("syntactically valid header bytes");
                let result = super::super::negotiate_response_format(Some(&header));
                if matches!(
                    raw,
                    "application/json;q=0" | "application/json;q=0." | "application/json;q=0.000"
                ) {
                    assert!(result.is_err(), "zero quality forbids the only range");
                } else {
                    assert_eq!(
                        result.expect("valid q-value"),
                        super::super::ResponseFormat::Json,
                        "header={raw}"
                    );
                }
            }
        }
        #[test]
        fn accept_parser_keeps_quoted_commas_and_escapes_inside_one_entry() {
            let header = HeaderValue::from_static(
                r#"application/json;profile="a,b\"c";q=0.4, application/x-norito;q=0.8;note="x,y""#,
            );
            let format = super::super::negotiate_response_format(Some(&header))
                .expect("quoted comma must not split an Accept entry");
            assert_eq!(format, super::super::ResponseFormat::Norito);
            let header =
                HeaderValue::from_static(r#"application/json;q=0.8;note="one,two\\three""#);
            let format = super::super::negotiate_response_format(Some(&header))
                .expect("valid quoted Accept extension");
            assert_eq!(format, super::super::ResponseFormat::Json);
        }
        #[test]
        fn accept_parser_rejects_malformed_or_duplicate_parameters() {
            for raw in [
                "application/json;profile",
                "application/json;=value",
                "application/json;profile=",
                "application/json;profile =value",
                "application/json;profile= value",
                "application/json;profile=one;PROFILE=two",
                "application/json;",
                "application/json;;q=1",
                "application/json q=1",
                "application/json;q=1;Q=0.5",
                "*/json",
                "application/*+json",
                "application/json*",
            ] {
                let header = HeaderValue::from_str(raw).expect("valid header field bytes");
                let error = super::super::negotiate_response_format(Some(&header))
                    .expect_err("malformed parameter grammar must fail closed");
                assert_eq!(error.status(), StatusCode::NOT_ACCEPTABLE, "header={raw}");
            }
        }
        #[test]
        fn accept_parser_rejects_bad_quotes_and_quoted_qvalues() {
            for raw in [
                r#"application/json;profile="unterminated"#,
                r#"application/json;profile="closed"trailing"#,
                r#"application/json;profile="trailing\""#,
                r#"application/json;q="0.5""#,
            ] {
                let header = HeaderValue::from_str(raw).expect("valid header field bytes");
                let error = super::super::negotiate_response_format(Some(&header))
                    .expect_err("invalid quoted-string grammar must fail closed");
                assert_eq!(error.status(), StatusCode::NOT_ACCEPTABLE, "header={raw}");
            }
            for raw in [
                "application/json;profile=\"bad\\\u{7f}\"",
                "application/json;profile=\"bad\u{7f}\"",
                "application/json;profile=\"bad\rvalue\"",
                "application/json;profile=\"välue\"",
            ] {
                assert!(
                    super::super::parse_accept_ranges(raw).is_err(),
                    "strict ASCII quoted-string parser must reject {raw:?}"
                );
            }
        }
        #[test]
        fn accept_parser_ignores_empty_list_members_but_rejects_empty_lists() {
            for raw in ["", " ", ",", " , \t , "] {
                let header = HeaderValue::from_str(raw).expect("valid header field bytes");
                let error = super::super::negotiate_response_format(Some(&header))
                    .expect_err("an Accept list needs at least one media range");
                assert_eq!(error.status(), StatusCode::NOT_ACCEPTABLE, "header={raw:?}");
            }
            for (raw, expected) in [
                (",application/json", super::super::ResponseFormat::Json),
                ("application/json,", super::super::ResponseFormat::Json),
                (
                    "application/json,,application/x-norito",
                    super::super::ResponseFormat::Norito,
                ),
                (
                    "text/plain, \t , application/json",
                    super::super::ResponseFormat::Json,
                ),
            ] {
                let header = HeaderValue::from_str(raw).expect("valid header field bytes");
                assert_eq!(
                    super::super::negotiate_response_format(Some(&header))
                        .expect("empty list members are ignored"),
                    expected,
                    "header={raw:?}"
                );
            }
        }
        #[test]
        fn accept_specificity_includes_matching_media_parameters() {
            let header = HeaderValue::from_static(
                "application/json;q=0, application/json;charset=utf-8;q=0.8, application/x-norito;q=0.7",
            );
            assert_eq!(
                super::super::negotiate_response_format(Some(&header)).expect("format"),
                super::super::ResponseFormat::Json
            );
            let header = HeaderValue::from_static("application/*;q=0, */*;q=1");
            assert_eq!(
                super::super::negotiate_response_format(Some(&header))
                    .expect_err("more-specific zero must override all-type wildcard")
                    .status(),
                StatusCode::NOT_ACCEPTABLE
            );
            let header =
                HeaderValue::from_static("application/json;charset=iso-8859-1;q=0, */*;q=1");
            assert_eq!(
                super::super::negotiate_response_format(Some(&header)).expect("format"),
                super::super::ResponseFormat::Json,
                "the incompatible charset range does not override the all-type wildcard"
            );
        }
        #[test]
        fn json_accept_charset_is_utf8_only() {
            for raw in [
                "application/json;charset=utf-8",
                "application/json;charset=UTF-8",
                "application/json;charset=\"Utf-8\"",
            ] {
                let header = HeaderValue::from_str(raw).expect("Accept header");
                assert_eq!(
                    super::super::negotiate_response_format(Some(&header)).expect("UTF-8 JSON"),
                    super::super::ResponseFormat::Json,
                    "header={raw}"
                );
            }
            for raw in [
                "application/json;charset=latin1",
                "application/json;charset=\"\"",
                "application/json;charset=utf-8;CHARSET=utf-8",
            ] {
                let header = HeaderValue::from_str(raw).expect("Accept header");
                assert_eq!(
                    super::super::negotiate_response_format(Some(&header))
                        .expect_err("unsupported or duplicate charset must fail")
                        .status(),
                    StatusCode::NOT_ACCEPTABLE,
                    "header={raw}"
                );
            }
        }
        #[test]
        fn negotiate_accept_is_case_insensitive_and_allows_supported_media_parameters() {
            for (raw, expected) in [
                (
                    "Application/JSON; Charset=UTF-8",
                    super::super::ResponseFormat::Json,
                ),
                (
                    "Application/X-Norito; Version=1",
                    super::super::ResponseFormat::Norito,
                ),
            ] {
                let header = HeaderValue::from_static(raw);
                assert_eq!(
                    super::super::negotiate_response_format(Some(&header)).expect("format"),
                    expected,
                    "header={raw}"
                );
            }
            for raw in [
                "application/x-norito;version=2",
                "application/x-norito;profile=torii-v1",
                "application/json;profile=torii-v1",
            ] {
                let header = HeaderValue::from_static(raw);
                assert_eq!(
                    super::super::negotiate_response_format(Some(&header))
                        .expect_err("unsupported media parameter must not match")
                        .status(),
                    StatusCode::NOT_ACCEPTABLE,
                    "header={raw}"
                );
            }
        }
        #[test]
        fn negotiate_json_only_accepts_missing_json_and_wildcards() {
            assert!(super::super::negotiate_json_only_response(None).is_ok());
            let json = HeaderValue::from_static("application/json");
            assert!(super::super::negotiate_json_only_response(Some(&json)).is_ok());
            for raw in ["application/*", "*/*"] {
                let wildcard = HeaderValue::from_static(raw);
                assert!(
                    super::super::negotiate_json_only_response(Some(&wildcard)).is_ok(),
                    "header={raw}"
                );
            }
            let suffix = HeaderValue::from_static("application/problem+json");
            assert!(super::super::negotiate_json_only_response(Some(&suffix)).is_ok());
        }
        #[test]
        fn negotiate_json_only_rejects_nonmatching_concrete_types() {
            for raw in ["application/x-norito", "text/plain"] {
                let header = HeaderValue::from_static(raw);
                let err = super::super::negotiate_json_only_response(Some(&header))
                    .expect_err("the concrete type is not JSON-compatible");
                assert_eq!(err.status(), StatusCode::NOT_ACCEPTABLE, "header={raw}");
            }
        }
        #[test]
        fn negotiate_json_only_exact_zero_overrides_wildcard() {
            let header = HeaderValue::from_static("application/json;q=0, */*;q=1");
            let err = super::super::negotiate_json_only_response(Some(&header)).unwrap_err();
            assert_eq!(err.status(), StatusCode::NOT_ACCEPTABLE);
            let header =
                HeaderValue::from_static("application/problem+json;q=0, application/*;q=0.7");
            let err = super::super::negotiate_json_only_response(Some(&header))
                .expect_err("a suffix-compatible q=0 must override the type wildcard");
            assert_eq!(err.status(), StatusCode::NOT_ACCEPTABLE);
            let header = HeaderValue::from_static(
                "application/problem+json;q=1, application/json;q=0, */*;q=0.5",
            );
            let err = super::super::negotiate_json_only_response(Some(&header))
                .expect_err("a suffix-compatible range must not undo canonical JSON q=0");
            assert_eq!(err.status(), StatusCode::NOT_ACCEPTABLE);
        }
        #[test]
        fn negotiate_norito_only_honors_specific_zero_and_application_wildcard() {
            let wildcard = HeaderValue::from_static("application/*;q=0.7");
            assert!(super::super::negotiate_norito_only_response(Some(&wildcard)).is_ok());
            let explicit_zero = HeaderValue::from_static("application/x-norito;q=0, */*;q=1");
            let err = super::super::negotiate_norito_only_response(Some(&explicit_zero))
                .expect_err("specific q=0 must override wildcard");
            assert_eq!(err.status(), StatusCode::NOT_ACCEPTABLE);
        }
        #[test]
        fn protocol_media_negotiation_honors_type_wildcards_and_specific_zero() {
            for accepted in ["text/event-stream", "text/*", "*/*"] {
                let header = accepted.parse::<HeaderValue>().expect("Accept header");
                super::super::ensure_response_media_type_acceptable(
                    Some(&header),
                    "text/event-stream; charset=utf-8",
                )
                .expect("matching native media type");
            }
            let header = HeaderValue::from_static("text/event-stream;q=0, */*;q=1");
            let error = super::super::ensure_response_media_type_acceptable(
                Some(&header),
                "text/event-stream",
            )
            .expect_err("specific zero must override wildcard");
            assert_eq!(error.status(), StatusCode::NOT_ACCEPTABLE);
        }
        #[test]
        fn protocol_media_negotiation_keeps_structured_suffix_types_exact() {
            let exact = HeaderValue::from_static("application/problem+json");
            super::super::ensure_response_media_type_acceptable(
                Some(&exact),
                "application/problem+json; charset=utf-8",
            )
            .expect("the exact structured-suffix media type must match");
            let wildcard = HeaderValue::from_static("application/*");
            super::super::ensure_response_media_type_acceptable(
                Some(&wildcard),
                "application/problem+json; charset=utf-8",
            )
            .expect("an application wildcard must match a suffix representation");
            let plain_json = HeaderValue::from_static("application/json");
            assert_eq!(
                super::super::ensure_response_media_type_acceptable(
                    Some(&plain_json),
                    "application/problem+json; charset=utf-8",
                )
                .expect_err("application/json is not application/problem+json")
                .status(),
                StatusCode::NOT_ACCEPTABLE
            );
            let exact_zero =
                HeaderValue::from_static("application/problem+json;q=0, application/*;q=1");
            assert_eq!(
                super::super::ensure_response_media_type_acceptable(
                    Some(&exact_zero),
                    "application/problem+json",
                )
                .expect_err("an exact q=0 must override a positive type wildcard")
                .status(),
                StatusCode::NOT_ACCEPTABLE
            );
        }
        #[test]
        fn protocol_media_negotiation_matches_strict_quoted_parameters() {
            let header = HeaderValue::from_static(
                r#"text/event-stream;profile="one,two\"three";q=0.7, */*;q=0.1"#,
            );
            super::super::ensure_response_media_type_acceptable(
                Some(&header),
                r#"text/event-stream; charset=utf-8; profile="one,two\"three""#,
            )
            .expect("matching decoded quoted parameter");
            let mismatched =
                HeaderValue::from_static(r#"text/event-stream;profile="different,value";q=1"#);
            assert_eq!(
                super::super::ensure_response_media_type_acceptable(
                    Some(&mismatched),
                    r#"text/event-stream;profile="one,two""#,
                )
                .expect_err("mismatched media parameter must not match")
                .status(),
                StatusCode::NOT_ACCEPTABLE
            );
        }
        #[test]
        fn protocol_media_negotiation_rejects_malformed_headers_and_actual_types() {
            for raw in [
                "text/event-stream;profile",
                "text/event-stream;profile=one;PROFILE=two",
            ] {
                let header = HeaderValue::from_str(raw).expect("header field bytes");
                assert_eq!(
                    super::super::ensure_response_media_type_acceptable(
                        Some(&header),
                        "text/event-stream",
                    )
                    .expect_err("malformed Accept must fail")
                    .status(),
                    StatusCode::NOT_ACCEPTABLE,
                    "header={raw}"
                );
            }
            let trailing_empty = HeaderValue::from_static("text/event-stream,");
            super::super::ensure_response_media_type_acceptable(
                Some(&trailing_empty),
                "text/event-stream",
            )
            .expect("an empty trailing list member is ignored");
            let wildcard = HeaderValue::from_static("*/*");
            for actual in [
                "text/event-stream;profile",
                "text/event-stream;profile=one;PROFILE=two",
                "application/json;charset=latin1",
                "application/*",
            ] {
                assert_eq!(
                    super::super::ensure_response_media_type_acceptable(Some(&wildcard), actual,)
                        .expect_err("invalid actual Content-Type must fail")
                        .status(),
                    StatusCode::NOT_ACCEPTABLE,
                    "actual={actual}"
                );
                assert_eq!(
                    super::super::ensure_response_media_type_acceptable(None, actual)
                        .expect_err("invalid actual Content-Type is invalid without Accept too")
                        .status(),
                    StatusCode::NOT_ACCEPTABLE,
                    "actual={actual}"
                );
            }
        }
        #[test]
        fn protocol_media_negotiation_rejects_unrelated_media() {
            let header = HeaderValue::from_static("application/json, image/*;q=0.5");
            let error = super::super::ensure_response_media_type_acceptable(
                Some(&header),
                "application/octet-stream",
            )
            .expect_err("unrelated media ranges must not match");
            assert_eq!(error.status(), StatusCode::NOT_ACCEPTABLE);
        }
        #[test]
        fn typed_response_content_type_classifier_excludes_protocol_media() {
            assert_eq!(
                super::super::typed_response_format_for_content_type(
                    "application/problem+json; charset=utf-8"
                ),
                None,
                "structured-suffix responses retain their concrete media type"
            );
            assert_eq!(
                super::super::typed_response_format_for_content_type(
                    "application/x-norito; profile=torii-v1"
                ),
                Some(super::super::ResponseFormat::Norito)
            );
            for native in [
                "text/event-stream",
                "text/plain; version=0.0.4",
                "application/octet-stream",
                "image/png",
            ] {
                assert_eq!(
                    super::super::typed_response_format_for_content_type(native),
                    None,
                    "protocol media type must not enter typed negotiation: {native}"
                );
            }
        }
        #[test]
        fn typed_response_content_type_classifier_enforces_strict_syntax_and_charset() {
            for valid in ["application/json; charset=utf-8"] {
                assert_eq!(
                    super::super::typed_response_format_for_content_type(valid),
                    Some(super::super::ResponseFormat::Json),
                    "valid={valid}"
                );
            }
            for invalid in [
                "application/json; charset=latin1",
                "application/json; charset=utf-8; CHARSET=utf-8",
                "application/json; charset =utf-8",
                "application/json; charset= utf-8",
                "application/json; profile=\"unterminated",
                "application/json;q=1",
                "APPLICATION/PROBLEM+JSON; CHARSET=\"UTF-8\"; profile=torii",
                "application/*+json",
                "*/json",
            ] {
                assert_eq!(
                    super::super::typed_response_format_for_content_type(invalid),
                    None,
                    "invalid={invalid}"
                );
            }
        }
        #[test]
        fn typed_request_content_type_is_the_exact_first_release_pair() {
            for (raw, expected) in [
                (
                    "application/json",
                    super::super::TypedRequestContentFormat::Json,
                ),
                (
                    "application/json;charset=utf-8",
                    super::super::TypedRequestContentFormat::Json,
                ),
                (
                    "application/json;charset=\"UTF-8\"",
                    super::super::TypedRequestContentFormat::Json,
                ),
                (
                    super::super::NORITO_MIME_TYPE,
                    super::super::TypedRequestContentFormat::Norito,
                ),
            ] {
                let mut headers = axum::http::HeaderMap::new();
                headers.insert(
                    CONTENT_TYPE,
                    HeaderValue::from_str(raw).expect("Content-Type"),
                );
                assert_eq!(
                    super::super::typed_request_content_format(&headers).expect("supported type"),
                    expected,
                    "content_type={raw}"
                );
            }
            for raw in [
                "application/problem+json",
                "application/json;profile=torii",
                "application/json;charset=utf-8;profile=torii",
                "application/json;charset=latin1",
                "application/x-norito;charset=utf-8",
                "application/x-norito;profile=torii-v1",
            ] {
                let mut headers = axum::http::HeaderMap::new();
                headers.insert(
                    CONTENT_TYPE,
                    HeaderValue::from_str(raw).expect("Content-Type"),
                );
                assert_eq!(
                    super::super::typed_request_content_format(&headers)
                        .expect_err("unsupported request media parameters")
                        .status(),
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "content_type={raw}"
                );
            }
        }
        #[test]
        fn native_norito_request_content_type_is_canonical_only() {
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(
                CONTENT_TYPE,
                HeaderValue::from_static(super::super::NORITO_MIME_TYPE),
            );
            super::super::norito_request_content_type(&headers)
                .expect("canonical native Norito media type");
            for raw in [
                "application/json",
                "application/json;charset=utf-8",
                "application/x-norito;charset=utf-8",
                "application/octet-stream",
            ] {
                headers.insert(
                    CONTENT_TYPE,
                    HeaderValue::from_str(raw).expect("Content-Type"),
                );
                assert_eq!(
                    super::super::norito_request_content_type(&headers)
                        .expect_err("native Norito requests have one wire representation")
                        .status(),
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "content_type={raw}"
                );
            }
        }
        #[cfg(feature = "app_api")]
        #[test]
        fn canonical_norito_decoder_accepts_only_the_canonical_layout() {
            let value = vec![3_u64, 5, 8, 13, 21];
            let canonical = norito::encode_canonical(&value).expect("encode canonical fixture");
            assert_eq!(
                norito::decode_canonical::<Vec<u64>>(&canonical).expect("decode canonical fixture"),
                value
            );
            let alternate_flags =
                norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
            let alternate = {
                let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
                norito::to_bytes(&value).expect("encode alternate-layout fixture")
            };
            assert_ne!(alternate, canonical);
            assert!(matches!(
                norito::decode_canonical::<Vec<u64>>(&alternate),
                Err(norito::Error::NonCanonicalEncoding)
            ));
            let compressed =
                norito::to_compressed_bytes(&value, Some(norito::CompressionConfig::default()))
                    .expect("encode compressed fixture");
            assert!(matches!(
                norito::decode_canonical::<Vec<u64>>(&compressed),
                Err(norito::Error::NonCanonicalEncoding)
            ));
            let mut trailing = canonical;
            trailing.push(0);
            assert!(norito::decode_canonical::<Vec<u64>>(&trailing).is_err());
        }
        #[cfg(feature = "app_api")]
        #[test]
        fn canonical_norito_decoder_rejects_forged_counts_before_allocation() {
            const FORGED_LENGTH: u64 = 1 << 40;
            let frame = norito::core::frame_bare_with_header_flags::<Vec<u64>>(
                &FORGED_LENGTH.to_le_bytes(),
                norito::core::default_encode_flags(),
            )
            .expect("frame forged count with a valid checksum");
            assert!(matches!(
                norito::decode_canonical::<Vec<u64>>(&frame),
                Err(norito::Error::SequenceLengthExceeded { .. }
                    | norito::Error::TotalElementsExceeded { .. }
                    | norito::Error::TotalAllocationExceeded { .. })
            ));
            // Keep the forged count within the element limits but omit most
            // of its length prefixes. Structural preflight must reject this
            // truncation before reserving storage for elements or their spans.
            const ALLOCATION_COUNT: u64 = 128;
            let mut allocation_payload = ALLOCATION_COUNT.to_le_bytes().to_vec();
            allocation_payload.resize(allocation_payload.len() + ALLOCATION_COUNT as usize - 1, 0);
            let allocation_frame = norito::core::frame_bare_with_header_flags::<Vec<u64>>(
                &allocation_payload,
                norito::core::default_encode_flags(),
            )
            .expect("frame forged allocation with a valid checksum");
            let defaults = norito::canonical_decode_limits(allocation_frame.len());
            let preflight_only = norito::DecodeLimits::new(
                defaults.max_sequence_elements(),
                defaults.max_field_bytes(),
                defaults.max_total_elements(),
                allocation_frame.len() * 2,
                defaults.max_nesting_depth(),
            );
            // Enough for frame handling, but not for 128 spans or u64 values:
            // allocating either first would report a resource refusal instead.
            assert!(matches!(
                norito::with_decode_limits(preflight_only, || {
                    Ok(norito::decode_canonical::<Vec<u64>>(&allocation_frame))
                }),
                Ok(Err(norito::Error::LengthMismatch))
            ));
        }
        #[cfg(feature = "app_api")]
        #[test]
        fn canonical_norito_decoder_rejects_large_owned_elements_before_allocation() {
            // Absent large inline values have a small, valid encoding but
            // still require their full element size in the owned output Vec.
            type Element = Option<[u64; 1024]>;
            let values = vec![None::<[u64; 1024]>; 128];
            let frame = norito::encode_canonical(&values).expect("canonical compact values");
            let limits = norito::canonical_decode_limits(frame.len());
            let backing_bytes = values.len() * core::mem::size_of::<Element>();
            assert!(backing_bytes > limits.max_total_allocated_bytes());
            assert!(matches!(
                norito::decode_canonical::<Vec<Element>>(&frame),
                Err(norito::Error::TotalAllocationExceeded { .. })
            ));
            // The canonical API must keep its mandatory envelope even when
            // callers supply looser limits. A separately funded frame decode
            // and exact re-encode prove these original bytes are well formed.
            let funded = norito::DecodeLimits::new(
                limits.max_sequence_elements(),
                limits.max_field_bytes(),
                limits.max_total_elements(),
                limits.max_total_allocated_bytes() + backing_bytes,
                limits.max_nesting_depth(),
            );
            assert!(matches!(
                norito::decode_canonical_with_limits::<Vec<Element>>(&frame, funded),
                Err(norito::Error::TotalAllocationExceeded { .. })
            ));
            let decoded = norito::decode_from_bytes_with_limits::<Vec<Element>>(&frame, funded)
                .expect("the same frame with explicitly funded output storage");
            assert_eq!(decoded, values);
            norito::verify_exact_canonical_frame(&decoded, &frame)
                .expect("the valid frame has the exact canonical bytes");
        }
        #[tokio::test]
        async fn typed_request_content_type_errors_have_exact_status_and_code() {
            for (raw, expected_status, expected_code) in [
                (
                    "application/json;profile=\"unterminated",
                    StatusCode::BAD_REQUEST,
                    "request_content_type_invalid",
                ),
                (
                    "application/json;charset=utf-8;CHARSET=utf-8",
                    StatusCode::BAD_REQUEST,
                    "request_content_type_invalid",
                ),
                (
                    "application/json;charset =utf-8",
                    StatusCode::BAD_REQUEST,
                    "request_content_type_invalid",
                ),
                (
                    "application/*",
                    StatusCode::BAD_REQUEST,
                    "request_content_type_invalid",
                ),
                (
                    "application/problem+json",
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "request_content_type_unsupported",
                ),
                (
                    "application/json;profile=torii",
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "request_content_type_unsupported",
                ),
                (
                    "application/json;charset=latin1",
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "request_content_type_unsupported",
                ),
                (
                    "application/x-norito;profile=torii-v1",
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "request_content_type_unsupported",
                ),
            ] {
                let mut headers = axum::http::HeaderMap::new();
                headers.insert(
                    CONTENT_TYPE,
                    HeaderValue::from_str(raw).expect("Content-Type field bytes"),
                );
                let response = super::super::with_current_response_format(
                    super::super::ResponseFormat::Json,
                    async {
                        super::super::typed_request_content_format(&headers)
                            .expect_err("invalid or unsupported request Content-Type")
                    },
                )
                .await;
                assert_eq!(response.status(), expected_status, "content_type={raw}");
                let body = response
                    .into_body()
                    .collect()
                    .await
                    .expect("collect Content-Type error")
                    .to_bytes();
                let envelope: iroha_torii_shared::ErrorEnvelope =
                    norito::json::from_slice(&body).expect("decode Content-Type error");
                assert_eq!(envelope.code(), expected_code, "content_type={raw}");
            }
            let missing_headers = axum::http::HeaderMap::new();
            let missing = super::super::with_current_response_format(
                super::super::ResponseFormat::Json,
                async {
                    super::super::typed_request_content_format(&missing_headers)
                        .expect_err("missing Content-Type")
                },
            )
            .await;
            assert_eq!(missing.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
            let body = missing
                .into_body()
                .collect()
                .await
                .expect("collect missing Content-Type error")
                .to_bytes();
            let envelope: iroha_torii_shared::ErrorEnvelope =
                norito::json::from_slice(&body).expect("decode missing Content-Type error");
            assert_eq!(envelope.code(), "request_content_type_missing");
            let mut duplicate_headers = axum::http::HeaderMap::new();
            duplicate_headers.append(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            duplicate_headers.append(
                CONTENT_TYPE,
                HeaderValue::from_static(super::super::NORITO_MIME_TYPE),
            );
            let duplicate = super::super::with_current_response_format(
                super::super::ResponseFormat::Json,
                async {
                    super::super::typed_request_content_format(&duplicate_headers)
                        .expect_err("duplicate Content-Type")
                },
            )
            .await;
            assert_eq!(duplicate.status(), StatusCode::BAD_REQUEST);
            let body = duplicate
                .into_body()
                .collect()
                .await
                .expect("collect duplicate Content-Type error")
                .to_bytes();
            let envelope: iroha_torii_shared::ErrorEnvelope =
                norito::json::from_slice(&body).expect("decode duplicate Content-Type error");
            assert_eq!(envelope.code(), "request_content_type_invalid");
        }
        #[tokio::test]
        async fn norito_json_accepts_binary_body() {
            #[derive(norito::NoritoSchema)]
            #[norito_schema(
                name = "iroha_torii::utils::extractors::tests::norito_json_accepts_binary_body::Payload"
            )]
            #[derive(
                Clone,
                Debug,
                PartialEq,
                NoritoSerialize,
                NoritoDeserialize,
                crate::json_macros::JsonSerialize,
                crate::json_macros::JsonDeserialize,
            )]

            struct Payload {
                value: u32,
            }
            let body_bytes = crate::frame_test_support::assert_current_frame(
                &Payload { value: 42 },
                "iroha_torii::utils::extractors::tests::norito_json_accepts_binary_body::Payload",
            );
            let mut wrong_owner = body_bytes.clone();
            wrong_owner[6] ^= 1;
            for invalid in [wrong_owner, body_bytes[..body_bytes.len() - 1].to_vec()] {
                let request = Request::builder()
                    .method("POST")
                    .header(CONTENT_TYPE, super::super::NORITO_MIME_TYPE)
                    .body(Body::from(invalid))
                    .expect("invalid typed frame request");
                let error = NoritoJson::<Payload>::from_request(request, &())
                    .await
                    .expect_err("wrong-owner and truncated frames must fail");
                assert_eq!(error.status(), StatusCode::BAD_REQUEST);
            }
            let req = Request::builder()
                .method("POST")
                .header(CONTENT_TYPE, super::super::NORITO_MIME_TYPE)
                .body(Body::from(body_bytes))
                .expect("build request");
            let extracted = NoritoJson::<Payload>::from_request(req, &())
                .await
                .expect("extract norito");
            assert_eq!(extracted.0.value, 42);
        }
        #[tokio::test]
        async fn norito_json_accepts_json_body() {
            #[derive(norito::NoritoSchema)]
            #[norito_schema(
                name = "iroha_torii::utils::extractors::tests::norito_json_accepts_json_body::Payload"
            )]
            #[derive(
                Clone,
                Debug,
                PartialEq,
                NoritoSerialize,
                NoritoDeserialize,
                crate::json_macros::JsonSerialize,
                crate::json_macros::JsonDeserialize,
            )]

            struct Payload {
                value: u32,
            }
            let body_bytes = norito::json::to_vec(&Payload { value: 7 }).expect("json encode");
            let req = Request::builder()
                .method("POST")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(body_bytes))
                .expect("build request");
            let extracted = NoritoJson::<Payload>::from_request(req, &())
                .await
                .expect("extract json");
            assert_eq!(extracted.0.value, 7);
        }
        #[tokio::test]
        async fn norito_json_body_limit_uses_typed_error_envelope() {
            #[derive(norito::NoritoSchema)]
            #[norito_schema(
                name = "iroha_torii::utils::extractors::tests::norito_json_body_limit_uses_typed_error_envelope::Payload"
            )]
            #[derive(
                Clone,
                Debug,
                NoritoSerialize,
                NoritoDeserialize,
                crate::json_macros::JsonSerialize,
                crate::json_macros::JsonDeserialize,
            )]

            struct Payload {
                value: u32,
            }
            let body_bytes = norito::json::to_vec(&Payload { value: 7 }).expect("json encode");
            for (format, expected_content_type) in [
                (
                    super::super::ResponseFormat::Json,
                    super::super::JSON_MIME_TYPE,
                ),
                (
                    super::super::ResponseFormat::Norito,
                    super::super::NORITO_MIME_TYPE,
                ),
            ] {
                let mut req = Request::builder()
                    .method("POST")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(body_bytes.clone()))
                    .expect("build request");
                DefaultBodyLimit::max(4).apply(&mut req);
                let response = super::super::with_current_response_format(
                    format,
                    NoritoJson::<Payload>::from_request(req, &()),
                )
                .await
                .expect_err("oversized typed request must fail");
                assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
                assert_eq!(
                    response.headers().get(CONTENT_TYPE),
                    Some(&HeaderValue::from_static(expected_content_type))
                );
                let body = http_body_util::BodyExt::collect(response.into_body())
                    .await
                    .expect("collect typed body-limit response")
                    .to_bytes();
                let envelope: iroha_torii_shared::ErrorEnvelope =
                    match format {
                        super::super::ResponseFormat::Json => norito::json::from_slice(&body)
                            .expect("decode JSON body-limit envelope"),
                        super::super::ResponseFormat::Norito => norito::decode_from_bytes(&body)
                            .expect("decode Norito body-limit envelope"),
                    };
                assert_eq!(envelope.code(), "request_payload_too_large");
            }
        }
        #[tokio::test]
        async fn json_only_rejects_unsupported_media_before_body_admission() {
            #[derive(Clone, Debug, PartialEq, crate::json_macros::JsonDeserialize)]
            struct Payload {
                value: u32,
            }
            let was_polled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let stream_was_polled = std::sync::Arc::clone(&was_polled);
            let stalled = futures::stream::poll_fn(move |_| {
                stream_was_polled.store(true, std::sync::atomic::Ordering::SeqCst);
                std::task::Poll::<
                    Option<Result<axum::body::Bytes, std::convert::Infallible>>,
                >::Pending
            });
            let request = Request::builder()
                .method("POST")
                .header(CONTENT_TYPE, "text/plain")
                .body(Body::from_stream(stalled))
                .expect("build stalled unsupported-media request");
            let rejection = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                JsonOnly::<Payload>::from_request(request, &()),
            )
            .await
            .expect("unsupported media must not wait for the body")
            .expect_err("unsupported media must fail");
            assert_eq!(rejection.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
            assert!(!was_polled.load(std::sync::atomic::Ordering::SeqCst));

            let mut oversized = Request::builder()
                .method("POST")
                .header(CONTENT_TYPE, "application/octet-stream")
                .body(Body::from("oversized"))
                .expect("build oversized unsupported-media request");
            DefaultBodyLimit::max(1).apply(&mut oversized);
            let rejection = JsonOnly::<Payload>::from_request(oversized, &())
                .await
                .expect_err("unsupported media must precede the body limit");
            assert_eq!(rejection.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

            let duplicate = Request::builder()
                .method("POST")
                .header(CONTENT_TYPE, "application/json")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from("{\"value\":9}"))
                .expect("build duplicate Content-Type request");
            let rejection = JsonOnly::<Payload>::from_request(duplicate, &())
                .await
                .expect_err("duplicate media declarations must fail closed");
            assert_eq!(rejection.status(), StatusCode::BAD_REQUEST);
        }
        #[tokio::test]
        async fn json_only_accepts_exact_json_representations() {
            #[derive(Clone, Debug, PartialEq, crate::json_macros::JsonDeserialize)]
            struct Payload {
                value: u32,
            }
            for content_type in [
                "application/json",
                "application/json;charset=utf-8",
                "application/json; charset=\"UTF-8\"",
            ] {
                let req = Request::builder()
                    .method("POST")
                    .header(CONTENT_TYPE, content_type)
                    .body(Body::from(r#"{"value":9}"#))
                    .expect("build canonical JSON request");
                let extracted = JsonOnly::<Payload>::from_request(req, &())
                    .await
                    .expect("extract canonical JSON");
                assert_eq!(extracted.0.value, 9, "content_type={content_type}");
            }
        }
        #[tokio::test]
        async fn json_only_rejects_noncanonical_media_before_body_decode() {
            #[derive(Clone, Debug, PartialEq, crate::json_macros::JsonDeserialize)]
            struct Payload {
                value: u32,
            }
            for (content_type, expected_status, expected_code) in [
                (
                    Some("application/x-norito"),
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "request_content_type_unsupported",
                ),
                (
                    Some("application/problem+json"),
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "request_content_type_unsupported",
                ),
                (
                    Some("application/json;profile=torii"),
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "request_content_type_unsupported",
                ),
                (
                    Some("application/json;charset=utf-8;CHARSET=utf-8"),
                    StatusCode::BAD_REQUEST,
                    "request_content_type_invalid",
                ),
                (
                    None,
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "request_content_type_missing",
                ),
            ] {
                let mut builder = Request::builder().method("POST");
                if let Some(content_type) = content_type {
                    builder = builder.header(CONTENT_TYPE, content_type);
                }
                let request = builder
                    .body(Body::from("not a JSON body"))
                    .expect("build rejected request");
                let response = super::super::with_current_response_format(
                    super::super::ResponseFormat::Json,
                    JsonOnly::<Payload>::from_request(request, &()),
                )
                .await
                .expect_err("noncanonical media must be rejected");
                assert_eq!(
                    response.status(),
                    expected_status,
                    "content_type={content_type:?}"
                );
                let body = response
                    .into_body()
                    .collect()
                    .await
                    .expect("collect canonical JSON rejection")
                    .to_bytes();
                let envelope: iroha_torii_shared::ErrorEnvelope =
                    norito::json::from_slice(&body).expect("decode canonical JSON rejection");
                assert_eq!(
                    envelope.code(),
                    expected_code,
                    "content_type={content_type:?}"
                );
            }
            let mut duplicate = Request::builder()
                .method("POST")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from("not a JSON body"))
                .expect("build duplicate Content-Type request");
            duplicate
                .headers_mut()
                .append(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            let response = super::super::with_current_response_format(
                super::super::ResponseFormat::Json,
                JsonOnly::<Payload>::from_request(duplicate, &()),
            )
            .await
            .expect_err("duplicate Content-Type must be rejected");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let body = response
                .into_body()
                .collect()
                .await
                .expect("collect duplicate Content-Type rejection")
                .to_bytes();
            let envelope: iroha_torii_shared::ErrorEnvelope =
                norito::json::from_slice(&body).expect("decode duplicate Content-Type rejection");
            assert_eq!(envelope.code(), "request_content_type_invalid");
        }
        #[tokio::test]
        async fn norito_json_rejects_unsupported_content_type() {
            #[derive(norito::NoritoSchema)]
            #[norito_schema(
                name = "iroha_torii::utils::extractors::tests::norito_json_rejects_unsupported_content_type::Payload"
            )]
            #[derive(
                Clone,
                Debug,
                NoritoSerialize,
                NoritoDeserialize,
                crate::json_macros::JsonSerialize,
                crate::json_macros::JsonDeserialize,
            )]

            struct Payload;
            let req = Request::builder()
                .method("POST")
                .header(CONTENT_TYPE, "text/plain")
                .body(Body::from("hello"))
                .expect("build request");
            let err = NoritoJson::<Payload>::from_request(req, &())
                .await
                .expect_err("unsupported content-type");
            assert_eq!(err.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        }
        #[tokio::test]
        async fn norito_json_rejects_missing_content_type() {
            #[derive(norito::NoritoSchema)]
            #[norito_schema(
                name = "iroha_torii::utils::extractors::tests::norito_json_rejects_missing_content_type::Payload"
            )]
            #[derive(
                Clone,
                Debug,
                NoritoSerialize,
                NoritoDeserialize,
                crate::json_macros::JsonSerialize,
                crate::json_macros::JsonDeserialize,
            )]

            struct Payload;
            let req = Request::builder()
                .method("POST")
                .body(Body::from("{}"))
                .expect("build request");
            let err = NoritoJson::<Payload>::from_request(req, &())
                .await
                .expect_err("missing content-type");
            assert_eq!(err.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        }
        #[tokio::test]
        async fn norito_json_rejects_invalid_content_type_before_body_collection() {
            #[derive(norito::NoritoSchema)]
            #[norito_schema(
                name = "iroha_torii::utils::extractors::tests::norito_json_rejects_invalid_content_type_before_body_collection::Payload"
            )]
            #[derive(
                Clone,
                Debug,
                NoritoSerialize,
                NoritoDeserialize,
                crate::json_macros::JsonSerialize,
                crate::json_macros::JsonDeserialize,
            )]

            struct Payload;
            let mut duplicate = Request::builder()
                .method("POST")
                .body(Body::from("oversized"))
                .expect("build duplicate-header request");
            duplicate
                .headers_mut()
                .append(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            duplicate.headers_mut().append(
                CONTENT_TYPE,
                HeaderValue::from_static(super::super::NORITO_MIME_TYPE),
            );
            DefaultBodyLimit::max(1).apply(&mut duplicate);
            let duplicate_error = NoritoJson::<Payload>::from_request(duplicate, &())
                .await
                .expect_err("duplicate Content-Type must fail");
            assert_eq!(duplicate_error.status(), StatusCode::BAD_REQUEST);
            let mut non_ascii = Request::builder()
                .method("POST")
                .header(
                    CONTENT_TYPE,
                    HeaderValue::from_bytes(&[0x80]).expect("opaque header value"),
                )
                .body(Body::from("oversized"))
                .expect("build non-ASCII-header request");
            DefaultBodyLimit::max(1).apply(&mut non_ascii);
            let non_ascii_error = NoritoJson::<Payload>::from_request(non_ascii, &())
                .await
                .expect_err("non-ASCII Content-Type must fail");
            assert_eq!(non_ascii_error.status(), StatusCode::BAD_REQUEST);
        }
        #[tokio::test]
        async fn norito_json_rejects_malformed_or_non_utf8_media_before_body_collection() {
            #[derive(norito::NoritoSchema)]
            #[norito_schema(
                name = "iroha_torii::utils::extractors::tests::norito_json_rejects_malformed_or_non_utf8_media_before_body_collection::Payload"
            )]
            #[derive(
                Clone,
                Debug,
                NoritoSerialize,
                NoritoDeserialize,
                crate::json_macros::JsonSerialize,
                crate::json_macros::JsonDeserialize,
            )]

            struct Payload;
            for (content_type, expected_status) in [
                (
                    "application/json; charset=latin1",
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                ),
                (
                    "application/json; charset=utf-8; CHARSET=utf-8",
                    StatusCode::BAD_REQUEST,
                ),
                ("application/json; charset =utf-8", StatusCode::BAD_REQUEST),
                (
                    "application/json; profile=\"unterminated",
                    StatusCode::BAD_REQUEST,
                ),
                ("application/json;q=1", StatusCode::UNSUPPORTED_MEDIA_TYPE),
            ] {
                let mut request = Request::builder()
                    .method("POST")
                    .header(CONTENT_TYPE, content_type)
                    .body(Body::from("oversized"))
                    .expect("request");
                DefaultBodyLimit::max(1).apply(&mut request);
                let error = NoritoJson::<Payload>::from_request(request, &())
                    .await
                    .expect_err("invalid media type must fail before body collection");
                assert_eq!(
                    error.status(),
                    expected_status,
                    "content_type={content_type}"
                );
            }
        }
        #[tokio::test]
        async fn norito_json_with_bytes_rejects_media_type_before_body_collection() {
            #[derive(norito::NoritoSchema)]
            #[norito_schema(
                name = "iroha_torii::utils::extractors::tests::norito_json_with_bytes_rejects_media_type_before_body_collection::Payload"
            )]
            #[derive(
                Clone,
                Debug,
                NoritoSerialize,
                NoritoDeserialize,
                crate::json_macros::JsonSerialize,
                crate::json_macros::JsonDeserialize,
            )]

            struct Payload;
            let mut request = Request::builder()
                .method("POST")
                .header(CONTENT_TYPE, "text/plain")
                .body(Body::from("oversized"))
                .expect("build unsupported-media request");
            DefaultBodyLimit::max(1).apply(&mut request);
            let error = NoritoJsonWithBytes::<Payload>::from_request(request, &())
                .await
                .expect_err("unsupported Content-Type must fail");
            assert_eq!(error.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        }
        #[tokio::test]
        async fn norito_json_rejects_octet_stream_fallback() {
            #[derive(norito::NoritoSchema)]
            #[norito_schema(
                name = "iroha_torii::utils::extractors::tests::norito_json_rejects_octet_stream_fallback::Payload"
            )]
            #[derive(
                Clone,
                Debug,
                NoritoSerialize,
                NoritoDeserialize,
                crate::json_macros::JsonSerialize,
                crate::json_macros::JsonDeserialize,
            )]

            struct Payload;
            let body = norito::to_bytes(&Payload).expect("encode norito payload");
            let req = Request::builder()
                .method("POST")
                .header(CONTENT_TYPE, "application/octet-stream")
                .body(Body::from(body))
                .expect("build request");
            let err = NoritoJson::<Payload>::from_request(req, &())
                .await
                .expect_err("octet-stream content-type");
            assert_eq!(err.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        }
        #[cfg(feature = "telemetry")]
        #[tokio::test]
        async fn norito_json_decode_failure_increments_metric() {
            use iroha_telemetry::metrics::global_or_default;
            #[derive(norito::NoritoSchema)]
            #[norito_schema(
                name = "iroha_torii::utils::extractors::tests::norito_json_decode_failure_increments_metric::Payload"
            )]
            #[derive(
                Clone,
                Debug,
                PartialEq,
                NoritoSerialize,
                NoritoDeserialize,
                crate::json_macros::JsonSerialize,
                crate::json_macros::JsonDeserialize,
            )]

            struct Payload {
                value: u32,
            }
            let body = vec![0_u8; 4];
            let reason = super::classify_norito_error(
                &norito::decode_from_bytes::<Payload>(&body).expect_err("body must fail"),
            );
            let payload_kind = super::payload_kind_label::<Payload>();
            let metrics = global_or_default();
            let before = metrics
                .torii_norito_decode_failures_total
                .with_label_values(&[payload_kind, reason])
                .get();
            let req = Request::builder()
                .method("POST")
                .header(CONTENT_TYPE, super::super::NORITO_MIME_TYPE)
                .body(Body::from(body))
                .expect("build request");
            let err = NoritoJson::<Payload>::from_request(req, &())
                .await
                .expect_err("decode must fail");
            assert_eq!(err.status(), StatusCode::BAD_REQUEST);
            let after = metrics
                .torii_norito_decode_failures_total
                .with_label_values(&[payload_kind, reason])
                .get();
            assert_eq!(after, before + 1, "decode metric should increment");
        }
    }
}
