//! MCP protocol-version and Streamable HTTP request validation.
//!
//! Torii serves only the stateless 2026 protocol at `/v1/mcp`.
//! This module validates header/body agreement before semantic tool dispatch.

use axum::http::HeaderMap;
use iroha_torii_shared::mcp as wire;
use norito::json::{Map, Value};

/// Native stateless MCP protocol revision served by Torii.
pub const MODERN_PROTOCOL_VERSION: &str = wire::MODERN_PROTOCOL_VERSION;

pub const HEADER_PROTOCOL_VERSION: &str = wire::HEADER_PROTOCOL_VERSION;
pub const HEADER_METHOD: &str = wire::HEADER_METHOD;
pub const HEADER_NAME: &str = wire::HEADER_NAME;

const META_PROTOCOL_VERSION: &str = wire::META_PROTOCOL_VERSION;
const META_CLIENT_INFO: &str = wire::META_CLIENT_INFO;
const META_CLIENT_CAPABILITIES: &str = wire::META_CLIENT_CAPABILITIES;
const META_SERVER_INFO: &str = wire::META_SERVER_INFO;
const META_LOG_LEVEL: &str = "io.modelcontextprotocol/logLevel";
const META_PROGRESS_TOKEN: &str = "progressToken";
const IROHA_TOOLS_EXTENSION_ID: &str = "org.hyperledger.iroha/tools";
const MODERN_CACHE_TTL_MS: u64 = 30_000;

const JSONRPC_VERSION: &str = "2.0";
const JSONRPC_INVALID_REQUEST: i64 = -32600;
const JSONRPC_INVALID_PARAMS: i64 = -32602;
const MCP_HEADER_MISMATCH: i64 = -32020;
const MCP_MISSING_REQUIRED_CLIENT_CAPABILITY: i64 = -32021;
const MCP_UNSUPPORTED_PROTOCOL_VERSION: i64 = -32022;

/// Header and body metadata validated before semantic MCP dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedRequest {
    /// Exact JSON-RPC method mirrored by `Mcp-Method`.
    pub(crate) method: String,
}

/// Closed transport-error classes mapped to reviewed Torii HTTP responses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationErrorKind {
    /// The request object itself is malformed.
    InvalidRequest,
    /// Required per-request MCP metadata is malformed or missing.
    InvalidParams,
    /// One or more mirrored HTTP fields are missing, ambiguous, or unequal.
    HeaderMismatch,
    /// The request requires an optional capability the client did not declare.
    MissingRequiredClientCapability,
    /// The request names a protocol revision Torii does not implement.
    UnsupportedProtocolVersion,
}

/// One bounded, protocol-native error produced before tool dispatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationError {
    /// Error class used to select the reviewed HTTP response contract.
    pub(crate) kind: ValidationErrorKind,
    /// JSON-RPC error response body.
    pub(crate) payload: Value,
}

/// Validate one stateless MCP Streamable HTTP request.
pub fn validate_request(
    headers: &HeaderMap,
    request: &Value,
) -> Result<ValidatedRequest, ValidationError> {
    let request_id = response_id(request);
    validate_modern_request(headers, request, request_id)
}

fn validate_modern_request(
    headers: &HeaderMap,
    request: &Value,
    request_id: Option<Value>,
) -> Result<ValidatedRequest, ValidationError> {
    let Some(request_object) = request.as_object() else {
        return Err(invalid_request(request_id, "request must be an object"));
    };
    if request_object.get("jsonrpc").and_then(Value::as_str) != Some(JSONRPC_VERSION) {
        return Err(invalid_request(request_id, "jsonrpc must be \"2.0\""));
    }
    let Some(method) = request_object.get("method").and_then(Value::as_str) else {
        return Err(invalid_request(request_id, "method must be a string"));
    };
    if method == "notifications/initialized" {
        return Err(invalid_request(
            request_id,
            "notifications/initialized is not part of the stateless MCP protocol",
        ));
    }
    let valid_id = request_object
        .get("id")
        .is_some_and(valid_modern_request_id);
    if !valid_id && !(request_object.get("id").is_none() && method.starts_with("notifications/")) {
        return Err(invalid_request(
            request_id,
            "stateless MCP requests require a non-null string or integer id; notifications omit id",
        ));
    }
    let Some(params) = request_object.get("params").and_then(Value::as_object) else {
        return Err(invalid_params(
            request_id,
            "modern MCP requests must carry an object params field with per-request _meta",
        ));
    };
    let Some(meta) = params.get("_meta").and_then(Value::as_object) else {
        return Err(invalid_params(
            request_id,
            "modern MCP requests must carry params._meta",
        ));
    };
    if let Err(message) = validate_request_meta(meta) {
        return Err(invalid_params(request_id, message));
    }
    let Some(body_protocol) = meta.get(META_PROTOCOL_VERSION).and_then(Value::as_str) else {
        return Err(invalid_params(
            request_id,
            "params._meta must include io.modelcontextprotocol/protocolVersion",
        ));
    };
    let Some(client_capabilities) = meta
        .get(META_CLIENT_CAPABILITIES)
        .and_then(Value::as_object)
    else {
        return Err(invalid_params(
            request_id,
            "params._meta must include object io.modelcontextprotocol/clientCapabilities",
        ));
    };
    if let Err(message) = validate_client_capabilities(client_capabilities) {
        return Err(invalid_params(request_id, message));
    }
    if let Some(client_info) = meta.get(META_CLIENT_INFO)
        && let Err(message) = validate_implementation(client_info)
    {
        return Err(invalid_params(request_id, message));
    }

    let header_protocol = required_header(headers, HEADER_PROTOCOL_VERSION, request_id.clone())?;
    if header_protocol != body_protocol {
        return Err(header_mismatch(
            request_id,
            "MCP-Protocol-Version does not match params._meta protocolVersion",
        ));
    }
    if body_protocol != MODERN_PROTOCOL_VERSION {
        return Err(unsupported_protocol_version(
            request_id,
            Some(body_protocol),
        ));
    }

    let header_method = required_header(headers, HEADER_METHOD, request_id.clone())?;
    if header_method != method {
        return Err(header_mismatch(
            request_id,
            "Mcp-Method does not match the JSON-RPC method",
        ));
    }

    validate_name_header(headers, method, params, request_id.clone())?;
    if method == "tools/call_batch" && !supports_iroha_tools_extension(client_capabilities) {
        return Err(missing_required_client_capability(request_id));
    }
    Ok(ValidatedRequest {
        method: method.to_owned(),
    })
}

fn valid_modern_request_id(value: &Value) -> bool {
    match value {
        Value::String(_) | Value::Number(norito::json::native::Number::I64(_)) => true,
        Value::Number(norito::json::native::Number::U64(_)) => true,
        Value::Number(norito::json::native::Number::U128(value)) => u64::try_from(*value).is_ok(),
        _ => false,
    }
}

fn validate_name_header(
    headers: &HeaderMap,
    method: &str,
    params: &Map,
    request_id: Option<Value>,
) -> Result<(), ValidationError> {
    let source = match method {
        "tools/call" | "prompts/get" => Some("name"),
        "resources/read" => Some("uri"),
        _ => None,
    };
    let header = unique_header(headers, HEADER_NAME);
    let Some(source) = source else {
        if !matches!(header, UniqueHeader::Missing) {
            return Err(header_mismatch(
                request_id,
                "Mcp-Name is not valid for this JSON-RPC method",
            ));
        }
        return Ok(());
    };
    let Some(expected) = params.get(source).and_then(Value::as_str) else {
        return Err(header_mismatch(
            request_id,
            "Mcp-Name cannot be matched because the request name or URI is missing",
        ));
    };
    let encoded = match header {
        UniqueHeader::One(value) => value,
        UniqueHeader::Missing | UniqueHeader::Ambiguous => {
            return Err(header_mismatch(
                request_id,
                "required Mcp-Name header is missing or ambiguous",
            ));
        }
    };
    let decoded = wire::decode_mirrored_header_value(encoded).ok_or_else(|| {
        header_mismatch(
            request_id.clone(),
            "Mcp-Name is not a valid plain ASCII or base64-sentinel value",
        )
    })?;
    if decoded != expected {
        return Err(header_mismatch(
            request_id,
            "Mcp-Name does not match the request name or URI",
        ));
    }
    Ok(())
}

fn required_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
    request_id: Option<Value>,
) -> Result<&'a str, ValidationError> {
    match unique_header(headers, name) {
        UniqueHeader::One(value) => Ok(value),
        UniqueHeader::Missing | UniqueHeader::Ambiguous => Err(header_mismatch(
            request_id,
            &format!("required {name} header is missing or ambiguous"),
        )),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UniqueHeader<'a> {
    Missing,
    One(&'a str),
    Ambiguous,
}

fn unique_header<'a>(headers: &'a HeaderMap, name: &str) -> UniqueHeader<'a> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return UniqueHeader::Missing;
    };
    if values.next().is_some() {
        return UniqueHeader::Ambiguous;
    }
    value
        .to_str()
        .map_or(UniqueHeader::Ambiguous, UniqueHeader::One)
}

fn validate_request_meta(meta: &Map) -> Result<(), &'static str> {
    if meta.keys().any(|key| !valid_meta_key(key)) {
        return Err("params._meta contains a key outside the MCP metadata key grammar");
    }
    if meta
        .get(META_PROGRESS_TOKEN)
        .is_some_and(|value| !value.is_string() && !value.is_number())
    {
        return Err("params._meta progressToken must be a string or number");
    }
    if meta.get(META_LOG_LEVEL).is_some_and(|value| {
        !matches!(
            value.as_str(),
            Some(
                "debug"
                    | "info"
                    | "notice"
                    | "warning"
                    | "error"
                    | "critical"
                    | "alert"
                    | "emergency"
            )
        )
    }) {
        return Err("io.modelcontextprotocol/logLevel must be a valid logging level");
    }
    Ok(())
}

fn validate_client_capabilities(capabilities: &Map) -> Result<(), &'static str> {
    if let Some(experimental) = capabilities.get("experimental") {
        let Some(experimental) = experimental.as_object() else {
            return Err("clientCapabilities.experimental must be an object");
        };
        if experimental.values().any(|settings| !settings.is_object()) {
            return Err("clientCapabilities.experimental values must be objects");
        }
    }
    if capabilities
        .get("roots")
        .is_some_and(|roots| !roots.is_object())
    {
        return Err("clientCapabilities.roots must be an object");
    }
    if let Some(sampling) = capabilities.get("sampling") {
        let Some(sampling) = sampling.as_object() else {
            return Err("clientCapabilities.sampling must be an object");
        };
        if ["context", "tools"]
            .into_iter()
            .any(|name| sampling.get(name).is_some_and(|value| !value.is_object()))
        {
            return Err("clientCapabilities.sampling context and tools must be objects");
        }
    }
    if let Some(elicitation) = capabilities.get("elicitation") {
        let Some(elicitation) = elicitation.as_object() else {
            return Err("clientCapabilities.elicitation must be an object");
        };
        if ["form", "url"].into_iter().any(|name| {
            elicitation
                .get(name)
                .is_some_and(|value| !value.is_object())
        }) {
            return Err("clientCapabilities.elicitation form and url must be objects");
        }
    }
    if let Some(extensions) = capabilities.get("extensions") {
        let Some(extensions) = extensions.as_object() else {
            return Err("clientCapabilities.extensions must be an object");
        };
        if extensions
            .keys()
            .any(|identifier| !valid_prefixed_meta_key(identifier))
        {
            return Err(
                "clientCapabilities.extensions identifiers must be prefixed MCP metadata keys",
            );
        }
        if extensions.values().any(|settings| !settings.is_object()) {
            return Err("clientCapabilities.extensions values must be objects");
        }
    }
    Ok(())
}

fn supports_iroha_tools_extension(capabilities: &Map) -> bool {
    capabilities
        .get("extensions")
        .and_then(Value::as_object)
        .is_some_and(|extensions| extensions.contains_key(IROHA_TOOLS_EXTENSION_ID))
}

fn validate_implementation(value: &Value) -> Result<(), &'static str> {
    let Some(implementation) = value.as_object() else {
        return Err("io.modelcontextprotocol/clientInfo must be an object");
    };
    if !["name", "version"]
        .into_iter()
        .all(|field| implementation.get(field).is_some_and(Value::is_string))
    {
        return Err(
            "io.modelcontextprotocol/clientInfo must contain string name and version fields",
        );
    }
    if ["title", "description", "websiteUrl"]
        .into_iter()
        .any(|field| {
            implementation
                .get(field)
                .is_some_and(|value| !value.is_string())
        })
    {
        return Err("io.modelcontextprotocol/clientInfo optional text fields must be strings");
    }
    if let Some(icons) = implementation.get("icons") {
        let Some(icons) = icons.as_array() else {
            return Err("io.modelcontextprotocol/clientInfo.icons must be an array");
        };
        if !icons.iter().all(valid_icon) {
            return Err("io.modelcontextprotocol/clientInfo.icons contains an invalid icon");
        }
    }
    Ok(())
}

fn valid_icon(value: &Value) -> bool {
    let Some(icon) = value.as_object() else {
        return false;
    };
    icon.get("src").is_some_and(Value::is_string)
        && icon.get("mimeType").is_none_or(Value::is_string)
        && icon.get("sizes").is_none_or(|sizes| {
            sizes
                .as_array()
                .is_some_and(|sizes| sizes.iter().all(Value::is_string))
        })
        && icon
            .get("theme")
            .is_none_or(|theme| matches!(theme.as_str(), Some("light" | "dark")))
}

fn valid_prefixed_meta_key(key: &str) -> bool {
    key.contains('/') && valid_meta_key(key)
}

fn valid_meta_key(key: &str) -> bool {
    let name = match key.split_once('/') {
        Some((prefix, name)) if !prefix.is_empty() && !name.contains('/') => {
            if !prefix.split('.').all(valid_meta_prefix_label) {
                return false;
            }
            name
        }
        Some(_) => return false,
        None => key,
    };
    valid_meta_name(name)
}

fn valid_meta_prefix_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    bytes.first().is_some_and(u8::is_ascii_alphabetic)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
}

fn valid_meta_name(name: &str) -> bool {
    if name.is_empty() {
        return true;
    }
    let bytes = name.as_bytes();
    bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.'))
}

fn response_id(request: &Value) -> Option<Value> {
    request
        .as_object()
        .and_then(|object| object.get("id"))
        .filter(|value| valid_modern_request_id(value))
        .cloned()
}

fn invalid_request(id: Option<Value>, message: &str) -> ValidationError {
    ValidationError {
        kind: ValidationErrorKind::InvalidRequest,
        payload: error_response(id, JSONRPC_INVALID_REQUEST, message, None),
    }
}

fn invalid_params(id: Option<Value>, message: &str) -> ValidationError {
    ValidationError {
        kind: ValidationErrorKind::InvalidParams,
        payload: error_response(id, JSONRPC_INVALID_PARAMS, message, None),
    }
}

fn header_mismatch(id: Option<Value>, message: &str) -> ValidationError {
    ValidationError {
        kind: ValidationErrorKind::HeaderMismatch,
        payload: error_response(id, MCP_HEADER_MISMATCH, message, None),
    }
}

fn missing_required_client_capability(id: Option<Value>) -> ValidationError {
    let mut extensions = Map::new();
    extensions.insert(
        IROHA_TOOLS_EXTENSION_ID.to_owned(),
        Value::Object(Map::new()),
    );
    let mut required_capabilities = Map::new();
    required_capabilities.insert("extensions".into(), Value::Object(extensions));
    let mut data = Map::new();
    data.insert(
        "requiredCapabilities".into(),
        Value::Object(required_capabilities),
    );
    ValidationError {
        kind: ValidationErrorKind::MissingRequiredClientCapability,
        payload: error_response(
            id,
            MCP_MISSING_REQUIRED_CLIENT_CAPABILITY,
            "tools/call_batch requires the org.hyperledger.iroha/tools client extension",
            Some(Value::Object(data)),
        ),
    }
}

fn unsupported_protocol_version(id: Option<Value>, requested: Option<&str>) -> ValidationError {
    let mut data = Map::new();
    data.insert(
        "supported".into(),
        Value::Array(vec![Value::String(MODERN_PROTOCOL_VERSION.to_owned())]),
    );
    data.insert(
        "requested".into(),
        requested.map_or(Value::Null, |value| Value::String(value.to_owned())),
    );
    ValidationError {
        kind: ValidationErrorKind::UnsupportedProtocolVersion,
        payload: error_response(
            id,
            MCP_UNSUPPORTED_PROTOCOL_VERSION,
            "Unsupported protocol version",
            Some(Value::Object(data)),
        ),
    }
}

fn error_response(id: Option<Value>, code: i64, message: &str, data: Option<Value>) -> Value {
    let mut error = Map::new();
    error.insert("code".into(), Value::from(code));
    error.insert("message".into(), Value::String(message.to_owned()));
    if let Some(data) = data {
        error.insert("data".into(), data);
    }
    let mut response = Map::new();
    response.insert("jsonrpc".into(), Value::String(JSONRPC_VERSION.to_owned()));
    if let Some(id) = id {
        response.insert("id".into(), id);
    }
    response.insert("error".into(), Value::Object(error));
    Value::Object(response)
}

/// Add fields required or recommended on successful modern MCP results.
pub fn decorate_modern_response(method: &str, response: &mut Value) {
    let Some(result) = response
        .as_object_mut()
        .and_then(|response| response.get_mut("result"))
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    result
        .entry("resultType".into())
        .or_insert_with(|| Value::String("complete".to_owned()));
    let meta = result
        .entry("_meta".into())
        .or_insert_with(|| Value::Object(Map::new()));
    if !meta.is_object() {
        *meta = Value::Object(Map::new());
    }
    meta.as_object_mut()
        .expect("modern result metadata is an object")
        .insert(
            META_SERVER_INFO.into(),
            norito::json!({
                "name": "iroha-torii-mcp",
                "version": (env!("CARGO_PKG_VERSION"))
            }),
        );
    if matches!(method, "server/discover" | "tools/list") {
        result.insert("ttlMs".into(), Value::from(MODERN_CACHE_TTL_MS));
        result.insert("cacheScope".into(), Value::String("private".to_owned()));
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};

    use super::*;

    fn modern_request(method: &str, extra_params: Value) -> Value {
        let mut params = extra_params.as_object().cloned().unwrap_or_default();
        params.insert(
            "_meta".into(),
            norito::json!({
                "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {
                    "name": "protocol-test",
                    "version": "1"
                }
            }),
        );
        norito::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": (method),
            "params": (Value::Object(params))
        })
    }

    fn modern_headers(method: &'static str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_PROTOCOL_VERSION,
            HeaderValue::from_static(MODERN_PROTOCOL_VERSION),
        );
        headers.insert(HEADER_METHOD, HeaderValue::from_static(method));
        headers
    }

    #[test]
    fn modern_requests_require_matching_version_and_method_headers() {
        let request = modern_request("tools/list", norito::json!({}));
        let headers = modern_headers("tools/list");
        assert_eq!(
            validate_request(&headers, &request).expect("valid modern request"),
            ValidatedRequest {
                method: "tools/list".to_owned()
            }
        );

        let mut mismatched = headers;
        mismatched.insert(HEADER_METHOD, HeaderValue::from_static("tools/call"));
        assert_eq!(
            validate_request(&mismatched, &request)
                .expect_err("header mismatch")
                .kind,
            ValidationErrorKind::HeaderMismatch
        );
    }

    #[test]
    fn modern_tool_calls_validate_plain_and_encoded_names() {
        let request = modern_request(
            "tools/call",
            norito::json!({ "name": "iroha.health", "arguments": {} }),
        );
        let mut headers = modern_headers("tools/call");
        headers.insert(HEADER_NAME, HeaderValue::from_static("iroha.health"));
        validate_request(&headers, &request).expect("plain name");

        let tabbed_request = modern_request(
            "tools/call",
            norito::json!({ "name": "iroha.\thealth", "arguments": {} }),
        );
        headers.insert(HEADER_NAME, HeaderValue::from_static("iroha.\thealth"));
        validate_request(&headers, &tabbed_request).expect("plain name with an internal tab");

        let unicode_request = modern_request(
            "tools/call",
            norito::json!({ "name": "iroha.健康", "arguments": {} }),
        );
        headers.insert(
            HEADER_NAME,
            HeaderValue::from_static("=?base64?aXJvaGEu5YGl5bq3?="),
        );
        validate_request(&headers, &unicode_request).expect("encoded name");
    }

    #[test]
    fn modern_metadata_and_mirrored_header_failures_use_exact_error_classes() {
        let request = norito::json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/list",
            "params": {}
        });
        let headers = modern_headers("tools/list");
        let error = validate_request(&headers, &request).expect_err("metadata is required");
        assert_eq!(error.kind, ValidationErrorKind::InvalidParams);
        assert_eq!(
            error.payload.pointer("/error/code").and_then(Value::as_i64),
            Some(JSONRPC_INVALID_PARAMS)
        );
        assert_eq!(error.payload.get("id").and_then(Value::as_u64), Some(7));

        let request = modern_request("tools/list", norito::json!({}));
        let mut duplicated = modern_headers("tools/list");
        duplicated.append(HEADER_METHOD, HeaderValue::from_static("tools/list"));
        let error = validate_request(&duplicated, &request).expect_err("duplicate method header");
        assert_eq!(error.kind, ValidationErrorKind::HeaderMismatch);
        assert_eq!(
            error.payload.pointer("/error/code").and_then(Value::as_i64),
            Some(MCP_HEADER_MISMATCH)
        );
    }

    #[test]
    fn modern_metadata_accepts_the_schema_without_extra_string_constraints() {
        let mut request = modern_request("tools/list", norito::json!({}));
        request
            .pointer_mut("/params/_meta/io.modelcontextprotocol~1clientInfo")
            .expect("client info")
            .clone_from(&norito::json!({
                "name": "",
                "version": "",
                "title": "",
                "description": "",
                "websiteUrl": "",
                "icons": [
                    {
                        "src": "",
                        "mimeType": "",
                        "sizes": ["", "any"],
                        "theme": "light"
                    }
                ]
            }));
        request
            .pointer_mut("/params/_meta/io.modelcontextprotocol~1clientCapabilities")
            .expect("client capabilities")
            .clone_from(&norito::json!({
                "experimental": { "vendor.feature": {} },
                "roots": {},
                "sampling": { "context": {}, "tools": {} },
                "elicitation": { "form": {}, "url": {} },
                "extensions": { "org.hyperledger.iroha/tools": {} },
                "vendorCapability": { "enabled": true }
            }));
        validate_request(&modern_headers("tools/list"), &request)
            .expect("schema-valid empty implementation strings and capability objects");
    }

    #[test]
    fn modern_metadata_rejects_malformed_known_capability_members() {
        for capabilities in [
            norito::json!({ "experimental": { "vendor.feature": true } }),
            norito::json!({ "roots": true }),
            norito::json!({ "sampling": { "tools": true } }),
            norito::json!({ "elicitation": { "form": [] } }),
            norito::json!({ "extensions": { "org.hyperledger.iroha/tools": true } }),
            norito::json!({ "extensions": { "unprefixed": {} } }),
        ] {
            let mut request = modern_request("tools/list", norito::json!({}));
            request
                .pointer_mut("/params/_meta/io.modelcontextprotocol~1clientCapabilities")
                .expect("client capabilities")
                .clone_from(&capabilities);
            assert_eq!(
                validate_request(&modern_headers("tools/list"), &request)
                    .expect_err("malformed known capability member")
                    .kind,
                ValidationErrorKind::InvalidParams
            );
        }
    }

    #[test]
    fn modern_metadata_rejects_invalid_meta_and_implementation_shapes() {
        for (key, value) in [
            ("bad/key/again", Value::Bool(true)),
            (META_PROGRESS_TOKEN, Value::Bool(true)),
            (META_LOG_LEVEL, Value::String("verbose".to_owned())),
        ] {
            let mut request = modern_request("tools/list", norito::json!({}));
            request
                .pointer_mut("/params/_meta")
                .and_then(Value::as_object_mut)
                .expect("request metadata")
                .insert(key.to_owned(), value);
            assert_eq!(
                validate_request(&modern_headers("tools/list"), &request)
                    .expect_err("invalid request metadata")
                    .kind,
                ValidationErrorKind::InvalidParams
            );
        }

        for client_info in [
            norito::json!({ "name": "client", "version": "1", "title": 1 }),
            norito::json!({
                "name": "client",
                "version": "1",
                "icons": [{ "src": "icon.png", "theme": "midnight" }]
            }),
        ] {
            let mut request = modern_request("tools/list", norito::json!({}));
            request
                .pointer_mut("/params/_meta/io.modelcontextprotocol~1clientInfo")
                .expect("client info")
                .clone_from(&client_info);
            assert_eq!(
                validate_request(&modern_headers("tools/list"), &request)
                    .expect_err("invalid implementation metadata")
                    .kind,
                ValidationErrorKind::InvalidParams
            );
        }
    }

    #[test]
    fn modern_batch_requires_the_mutually_declared_iroha_tools_extension() {
        let mut request = modern_request("tools/call_batch", norito::json!({ "calls": [] }));
        let error = validate_request(&modern_headers("tools/call_batch"), &request)
            .expect_err("batch extension was not declared by the client");
        assert_eq!(
            error.kind,
            ValidationErrorKind::MissingRequiredClientCapability
        );
        assert_eq!(
            error.payload.pointer("/error/code").and_then(Value::as_i64),
            Some(MCP_MISSING_REQUIRED_CLIENT_CAPABILITY)
        );
        assert!(
            error
                .payload
                .pointer(
                    "/error/data/requiredCapabilities/extensions/org.hyperledger.iroha~1tools",
                )
                .and_then(Value::as_object)
                .is_some_and(Map::is_empty)
        );

        request
            .pointer_mut("/params/_meta/io.modelcontextprotocol~1clientCapabilities")
            .expect("client capabilities")
            .clone_from(&norito::json!({
                "extensions": { "org.hyperledger.iroha/tools": {} }
            }));
        validate_request(&modern_headers("tools/call_batch"), &request)
            .expect("mutually declared batch extension");
    }

    #[test]
    fn modern_invalid_ids_are_not_echoed_in_error_responses() {
        let mut request = modern_request("tools/list", norito::json!({}));
        request
            .as_object_mut()
            .expect("request")
            .insert("id".into(), Value::from(1.5_f64));
        let error = validate_request(&modern_headers("tools/list"), &request)
            .expect_err("fractional request id");
        assert_eq!(error.kind, ValidationErrorKind::InvalidRequest);
        assert!(error.payload.get("id").is_none());
    }

    #[test]
    fn unsupported_modern_versions_report_requested_and_supported_values() {
        let mut request = modern_request("tools/list", norito::json!({}));
        request
            .pointer_mut("/params/_meta/io.modelcontextprotocol~1protocolVersion")
            .expect("protocol metadata")
            .clone_from(&Value::String("2099-01-01".to_owned()));
        let mut headers = modern_headers("tools/list");
        headers.insert(
            HEADER_PROTOCOL_VERSION,
            HeaderValue::from_static("2099-01-01"),
        );
        let error = validate_request(&headers, &request).expect_err("unsupported version");
        assert_eq!(error.kind, ValidationErrorKind::UnsupportedProtocolVersion);
        assert_eq!(
            error.payload.pointer("/error/code").and_then(Value::as_i64),
            Some(MCP_UNSUPPORTED_PROTOCOL_VERSION)
        );
        assert_eq!(
            error
                .payload
                .pointer("/error/data/requested")
                .and_then(Value::as_str),
            Some("2099-01-01")
        );
        assert_eq!(
            error
                .payload
                .pointer("/error/data/supported/0")
                .and_then(Value::as_str),
            Some(MODERN_PROTOCOL_VERSION)
        );
    }

    #[test]
    fn retired_initialize_and_2025_header_requests_are_rejected() {
        let initialize = norito::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "legacy", "version": "1" }
            }
        });
        assert_eq!(
            validate_request(&HeaderMap::new(), &initialize)
                .expect_err("initialize handshake is retired")
                .kind,
            ValidationErrorKind::InvalidParams
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_PROTOCOL_VERSION,
            HeaderValue::from_static("2025-06-18"),
        );
        let request = norito::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2025-06-18",
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        });
        assert_eq!(
            validate_request(&headers, &request)
                .expect_err("2025 protocol is retired")
                .kind,
            ValidationErrorKind::UnsupportedProtocolVersion
        );
    }

    #[test]
    fn modern_success_decoration_is_complete_cacheable_and_identified() {
        let mut response = norito::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "tools": [], "_meta": { "iroha": {} } }
        });
        decorate_modern_response("tools/list", &mut response);
        let result = response.get("result").expect("result");
        assert_eq!(
            result.get("resultType").and_then(Value::as_str),
            Some("complete")
        );
        assert_eq!(
            result.get("cacheScope").and_then(Value::as_str),
            Some("private")
        );
        assert!(
            result
                .pointer("/_meta/io.modelcontextprotocol~1serverInfo")
                .is_some()
        );
        assert!(result.pointer("/_meta/iroha").is_some());
    }
}
