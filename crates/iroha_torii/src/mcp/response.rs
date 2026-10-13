//! JSON-RPC response envelopes and bounded JSON serialization for Torii's MCP endpoint.
//!
//! Response values remain ordinary Norito JSON until the final HTTP boundary. The bounded
//! serializer measures compact JSON exactly, caps retained batch values, and falls back to a
//! compact typed error when a response would exceed the request-scoped envelope budget.

use super::{
    JSONRPC_INTERNAL_ERROR, JSONRPC_INVALID_PARAMS, JSONRPC_INVALID_REQUEST,
    JSONRPC_METHOD_NOT_FOUND, JSONRPC_PARSE_ERROR, JSONRPC_VERSION,
    MCP_DISPATCH_CAPACITY_EXHAUSTED, MCP_RATE_LIMITED, MCP_REQUEST_TIMEOUT, MCP_RESPONSE_TOO_LARGE,
    MCP_RESPONSE_TOO_LARGE_CODE, MCP_TOOL_EXECUTION_ERROR, MCP_TOOL_EXECUTION_ERROR_CODE,
    private_no_store_response, remap_modern_application_error,
};
use axum::{
    body::Body,
    http::{StatusCode, header},
    response::Response,
};
use norito::json::{self, BoundedJsonError, FastJsonWrite, JsonWriteSink, Map, Value};

/// Build the common structured error envelope embedded in MCP failures.
pub(super) fn error_envelope_value(code: &str, message: &str, details: Option<Value>) -> Value {
    let mut envelope = Map::new();
    envelope.insert("code".into(), Value::String(code.to_owned()));
    envelope.insert("message".into(), Value::String(message.to_owned()));
    if let Some(details) = details {
        envelope.insert("details".into(), details);
    }
    Value::Object(envelope)
}

struct BoundedJsonSizeCounter {
    encoded_bytes: usize,
    max_bytes: usize,
    depth: usize,
}

impl BoundedJsonSizeCounter {
    fn new(max_bytes: usize) -> Self {
        Self {
            encoded_bytes: 0,
            max_bytes,
            depth: 0,
        }
    }

    fn admit(&mut self, additional: usize) -> Result<(), BoundedJsonError> {
        let next = self
            .encoded_bytes
            .checked_add(additional)
            .ok_or(BoundedJsonError::BodyTooLarge)?;
        if next > self.max_bytes {
            return Err(BoundedJsonError::BodyTooLarge);
        }
        self.encoded_bytes = next;
        Ok(())
    }
}

impl JsonWriteSink for BoundedJsonSizeCounter {
    fn push(&mut self, value: char) -> Result<(), BoundedJsonError> {
        self.admit(value.len_utf8())
    }

    fn push_str(&mut self, value: &str) -> Result<(), BoundedJsonError> {
        self.admit(value.len())
    }

    fn begin_container(&mut self) -> Result<(), BoundedJsonError> {
        let next = self
            .depth
            .checked_add(1)
            .ok_or(BoundedJsonError::Unsupported)?;
        if next >= json::MAX_JSON_VALUE_NESTING_DEPTH {
            return Err(BoundedJsonError::Unsupported);
        }
        self.depth = next;
        Ok(())
    }

    fn end_container(&mut self) {
        debug_assert!(self.depth > 0);
        self.depth = self.depth.saturating_sub(1);
    }
}

/// Measure the exact compact JSON using the final HTTP serializer's byte/depth bounds.
pub(super) fn bounded_json_value_len(
    value: &Value,
    max_bytes: usize,
) -> Result<usize, BoundedJsonError> {
    let mut counter = BoundedJsonSizeCounter::new(max_bytes);
    value.write_json_to(&mut counter)?;
    Ok(counter.encoded_bytes)
}

/// Accumulate one JSON array without allowing retained response values to grow
/// past the final MCP envelope budget.
pub struct BoundedJsonArray {
    values: Vec<Value>,
    encoded_bytes: usize,
    max_bytes: usize,
}

impl BoundedJsonArray {
    /// Reserve the bounded item count and account for the surrounding `[]`.
    pub(crate) fn new(capacity: usize, max_bytes: usize) -> Result<Self, BoundedJsonError> {
        if max_bytes < 2 {
            return Err(BoundedJsonError::BodyTooLarge);
        }
        let mut values = Vec::new();
        values
            .try_reserve_exact(capacity)
            .map_err(|_| BoundedJsonError::AllocationFailed)?;
        Ok(Self {
            values,
            encoded_bytes: 2,
            max_bytes,
        })
    }

    /// Retain one value only if its exact compact JSON representation fits.
    pub(crate) fn try_push(&mut self, value: Value) -> Result<(), BoundedJsonError> {
        let separator_bytes = usize::from(!self.values.is_empty());
        let remaining = self
            .max_bytes
            .checked_sub(self.encoded_bytes)
            .and_then(|remaining| remaining.checked_sub(separator_bytes))
            .ok_or(BoundedJsonError::BodyTooLarge)?;
        let value_bytes = bounded_json_value_len(&value, remaining)?;
        self.encoded_bytes = self
            .encoded_bytes
            .checked_add(separator_bytes)
            .and_then(|bytes| bytes.checked_add(value_bytes))
            .ok_or(BoundedJsonError::BodyTooLarge)?;
        self.values.push(value);
        Ok(())
    }

    /// Finish the array after every retained value has been admitted.
    pub(crate) fn into_values(self) -> Vec<Value> {
        self.values
    }
}

/// Build a successful JSON-RPC response value.
pub(super) fn jsonrpc_result_response(id: Option<Value>, result: Value) -> Value {
    let mut obj = Map::new();
    obj.insert("jsonrpc".into(), Value::String(JSONRPC_VERSION.to_owned()));
    obj.insert("id".into(), id.unwrap_or(Value::Null));
    obj.insert("result".into(), result);
    Value::Object(obj)
}

/// Build the typed internal error returned when the response budget is exceeded.
pub fn jsonrpc_response_too_large(id: Option<Value>, max_response_bytes: usize) -> Value {
    jsonrpc_error_response(
        id,
        MCP_RESPONSE_TOO_LARGE,
        "mcp response exceeds the configured envelope byte limit",
        Some(norito::json!({
            "error_code": MCP_RESPONSE_TOO_LARGE_CODE,
            "max_response_bytes": max_response_bytes
        })),
    )
}

/// Serialize a stateless MCP response behind the request byte budget using
/// application codes outside MCP's reserved server-error range.
pub fn bounded_modern_jsonrpc_http_response(
    mut payload: Value,
    max_response_bytes: usize,
) -> Response {
    remap_modern_application_error(&mut payload);
    bounded_jsonrpc_http_response_inner(payload, max_response_bytes)
}

fn bounded_jsonrpc_http_response_inner(payload: Value, max_response_bytes: usize) -> Response {
    let response_id = payload.get("id").cloned();
    let encoded = match json::to_json_bounded_boxed(&payload, max_response_bytes) {
        Ok(encoded) => encoded.into_vec(),
        Err(BoundedJsonError::BodyTooLarge) => {
            let mut error = compact_jsonrpc_response_too_large(response_id);
            remap_modern_application_error(&mut error);
            let Ok(encoded) = json::to_json_bounded_boxed(&error, max_response_bytes) else {
                return private_no_store_response(StatusCode::INTERNAL_SERVER_ERROR);
            };
            encoded.into_vec()
        }
        Err(
            BoundedJsonError::AllocationFailed
            | BoundedJsonError::DecodeResource(_)
            | BoundedJsonError::ScopedDecodeResource(_),
        ) => {
            let error = jsonrpc_error_response(
                response_id,
                JSONRPC_INTERNAL_ERROR,
                "failed to allocate MCP response storage",
                Some(norito::json!({ "error_code": "allocation_failed" })),
            );
            return private_no_store_response((StatusCode::OK, crate::utils::JsonBody(error)));
        }
        Err(BoundedJsonError::Unsupported | BoundedJsonError::LengthMismatch) => {
            let error = jsonrpc_error_response(
                response_id,
                JSONRPC_INTERNAL_ERROR,
                "failed to serialize MCP response",
                Some(norito::json!({ "error_code": "response_serialization_failed" })),
            );
            return private_no_store_response((StatusCode::OK, crate::utils::JsonBody(error)));
        }
    };
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(encoded))
        .expect("build bounded MCP JSON response");
    private_no_store_response(response)
}

fn compact_jsonrpc_response_too_large(id: Option<Value>) -> Value {
    let mut data = Map::new();
    data.insert(
        "error_code".into(),
        Value::String(MCP_RESPONSE_TOO_LARGE_CODE.to_owned()),
    );
    let mut error = Map::new();
    error.insert("code".into(), Value::from(MCP_RESPONSE_TOO_LARGE));
    error.insert(
        "message".into(),
        Value::String("response too large".to_owned()),
    );
    error.insert("data".into(), Value::Object(data));
    let mut response = Map::new();
    response.insert("jsonrpc".into(), Value::String(JSONRPC_VERSION.to_owned()));
    response.insert("id".into(), id.unwrap_or(Value::Null));
    response.insert("error".into(), Value::Object(error));
    Value::Object(response)
}

/// Build a JSON-RPC error response with Iroha's stable structured data envelope.
pub(super) fn jsonrpc_error_response(
    id: Option<Value>,
    code: i64,
    message: &str,
    data: Option<Value>,
) -> Value {
    let input_data = match data {
        Some(Value::Object(map)) => map,
        Some(other) => {
            let mut map = Map::new();
            map.insert("details".into(), other);
            map
        }
        None => Map::new(),
    };
    let label = input_data
        .get("error_code")
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| jsonrpc_error_code_label(code).to_owned());
    let mut data_object = if input_data.contains_key("code") {
        input_data.clone()
    } else {
        let mut details_object = input_data.clone();
        details_object.remove("error_code");
        let details = if details_object.is_empty() {
            Some(norito::json!({ "layer": "mcp" }))
        } else {
            Some(Value::Object(details_object))
        };
        let mut envelope = match error_envelope_value(label.as_str(), message, details) {
            Value::Object(map) => map,
            _ => Map::new(),
        };
        for (key, value) in input_data {
            envelope.entry(key).or_insert(value);
        }
        envelope
    };
    data_object
        .entry("error_code".into())
        .or_insert_with(|| Value::String(label));
    let mut err = Map::new();
    err.insert("code".into(), Value::from(code));
    err.insert("message".into(), Value::String(message.to_owned()));
    err.insert("data".into(), Value::Object(data_object));
    let mut obj = Map::new();
    obj.insert("jsonrpc".into(), Value::String(JSONRPC_VERSION.to_owned()));
    obj.insert("id".into(), id.unwrap_or(Value::Null));
    obj.insert("error".into(), Value::Object(err));
    Value::Object(obj)
}

fn jsonrpc_error_code_label(code: i64) -> &'static str {
    match code {
        JSONRPC_PARSE_ERROR => "parse_error",
        JSONRPC_INVALID_REQUEST => "invalid_request",
        JSONRPC_METHOD_NOT_FOUND => "method_not_found",
        JSONRPC_INVALID_PARAMS => "invalid_params",
        JSONRPC_INTERNAL_ERROR => "internal_error",
        MCP_TOOL_EXECUTION_ERROR => MCP_TOOL_EXECUTION_ERROR_CODE,
        MCP_RESPONSE_TOO_LARGE => MCP_RESPONSE_TOO_LARGE_CODE,
        MCP_REQUEST_TIMEOUT => "request_timeout",
        MCP_RATE_LIMITED => "rate_limited",
        MCP_DISPATCH_CAPACITY_EXHAUSTED => "dispatch_capacity_exhausted",
        _ => "unknown_error",
    }
}

/// Map an HTTP status to the stable label embedded in MCP tool results.
pub(super) fn http_status_error_code(status: u64) -> &'static str {
    match status {
        400 => "bad_request",
        401 => "unauthorized",
        403 => "forbidden",
        404 => "not_found",
        405 => "method_not_allowed",
        409 => "conflict",
        413 => "payload_too_large",
        415 => "unsupported_media_type",
        422 => "unprocessable_entity",
        429 => "rate_limited",
        500..=599 => "server_error",
        _ => "http_error",
    }
}
