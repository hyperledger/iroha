// Borrowed MCP request projections used to validate and encode source-sized
// bodies without recursively cloning the decoded JSON value tree.
#[derive(Debug)]
enum BorrowedMcpJson<'a> {
    Value(&'a Value),
    Object(BorrowedMcpJsonObject<'a>),
}

#[derive(Debug)]
struct BorrowedMcpJsonObject<'a> {
    entries: Vec<(&'a str, BorrowedMcpJson<'a>)>,
}

impl<'a> BorrowedMcpJsonObject<'a> {
    fn try_with_capacity(capacity: usize, context: &str) -> Result<Self, String> {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(capacity)
            .map_err(|_| format!("failed to reserve {context}"))?;
        Ok(Self { entries })
    }

    fn get(&self, key: &str) -> Option<&'a Value> {
        self.entries
            .iter()
            .find(|(candidate, _)| *candidate == key)
            .and_then(|(_, value)| match value {
                BorrowedMcpJson::Value(value) => Some(*value),
                BorrowedMcpJson::Object(_) => None,
            })
    }
}

impl<'a> BorrowedMcpJson<'a> {
    fn get(&self, key: &str) -> Option<&'a Value> {
        match self {
            Self::Value(value) => value.as_object().and_then(|object| object.get(key)),
            Self::Object(object) => object.get(key),
        }
    }
}

impl FastJsonWrite for BorrowedMcpJsonObject<'_> {
    fn write_json(&self, output: &mut String) {
        output.push('{');
        for (index, (key, value)) in self.entries.iter().enumerate() {
            if index != 0 {
                output.push(',');
            }
            json::write_json_string(key, output);
            output.push(':');
            value.write_json(output);
        }
        output.push('}');
    }

    fn write_json_to(&self, output: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        output.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            output.push('{')?;
            for (index, (key, value)) in self.entries.iter().enumerate() {
                if index != 0 {
                    output.push(',')?;
                }
                json::write_json_string_to(key, output)?;
                output.push(':')?;
                value.write_json_to(output)?;
            }
            output.push('}')?;
            Ok(())
        })();
        output.end_container();
        result?;
        Ok(())
    }
}

impl FastJsonWrite for BorrowedMcpJson<'_> {
    fn write_json(&self, output: &mut String) {
        match self {
            Self::Value(value) => FastJsonWrite::write_json(*value, output),
            Self::Object(object) => object.write_json(output),
        }
    }

    fn write_json_to(&self, output: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        match self {
            Self::Value(value) => FastJsonWrite::write_json_to(*value, output),
            Self::Object(object) => object.write_json_to(output),
        }
    }
}

fn encode_mcp_json_body<T: FastJsonWrite>(value: &T, context: &str) -> Result<Vec<u8>, String> {
    json::to_json_bounded_boxed(value, usize::MAX)
        .map(<[u8]>::into_vec)
        .map_err(|error| format!("{context}: {error}"))
}

fn decode_base64_any(input: &str, invalid_message: &str) -> Result<Vec<u8>, String> {
    let remainder = input.len() % 4;
    if remainder == 1 {
        return Err(invalid_message.to_owned());
    }
    let padding = if input.ends_with("==") {
        2
    } else if input.ends_with('=') {
        1
    } else {
        0
    };
    if padding != 0 && remainder != 0 {
        return Err(invalid_message.to_owned());
    }
    let decoded_len = input
        .len()
        .checked_div(4)
        .and_then(|groups| groups.checked_mul(3))
        .and_then(|bytes| {
            bytes.checked_add(match remainder {
                2 => 1,
                3 => 2,
                _ => 0,
            })
        })
        .and_then(|bytes| bytes.checked_sub(padding))
        .ok_or_else(|| invalid_message.to_owned())?;
    let mut decoded = Vec::new();
    decoded
        .try_reserve_exact(decoded_len)
        .map_err(|_| "failed to reserve decoded base64 payload".to_owned())?;
    decoded.resize(decoded_len, 0);
    for engine in [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::URL_SAFE,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(written) = engine.decode_slice(input.as_bytes(), &mut decoded)
            && written == decoded_len
        {
            return Ok(decoded);
        }
    }
    Err(invalid_message.to_owned())
}

fn build_object_body_or_default(arguments: &Map) -> Result<BorrowedMcpJson<'_>, String> {
    if let Some(body) = arguments.get("body") {
        body.as_object()
            .ok_or_else(|| "`body` must be an object".to_owned())?;
        return Ok(BorrowedMcpJson::Value(body));
    }
    Ok(BorrowedMcpJson::Object(
        BorrowedMcpJsonObject::try_with_capacity(0, "empty MCP body")?,
    ))
}

fn build_required_exact_object_body<'a>(
    arguments: &'a Map,
    allowed_fields: &[&str],
    required_fields: &[&str],
    context: &str,
) -> Result<BorrowedMcpJson<'a>, String> {
    let body = arguments
        .get("body")
        .ok_or_else(|| "`body` is required".to_owned())?;
    let body_object = body
        .as_object()
        .ok_or_else(|| "`body` must be an object".to_owned())?;
    reject_unknown_arguments(body_object, allowed_fields, context)?;
    if let Some(field) = required_fields
        .iter()
        .find(|field| body_object.get(**field).is_none_or(Value::is_null))
    {
        return Err(format!("`{field}` is required for {context}"));
    }
    Ok(BorrowedMcpJson::Value(body))
}

/// Borrow the mandatory `body` object; request payloads are never assembled
/// from top-level tool arguments.
fn build_required_object_body(arguments: &Map) -> Result<BorrowedMcpJson<'_>, String> {
    let body = arguments
        .get("body")
        .ok_or_else(|| "`body` is required".to_owned())?;
    body.as_object()
        .ok_or_else(|| "`body` must be an object".to_owned())?;
    Ok(BorrowedMcpJson::Value(body))
}

fn build_accounts_onboard_exact_body<'a>(
    arguments: &'a Map,
    allowed_fields: &[&str],
    required_fields: &[&str],
) -> Result<BorrowedMcpJson<'a>, String> {
    if let Some(field) = arguments
        .keys()
        .find(|field| !matches!(field.as_str(), "body" | "headers" | "accept"))
    {
        return Err(format!(
            "unsupported account onboarding argument `{field}`; the exact request must be supplied only in `body`"
        ));
    }
    let body = arguments
        .get("body")
        .ok_or_else(|| "`body` is required".to_owned())?;
    let body_object = body
        .as_object()
        .ok_or_else(|| "`body` must be an object".to_owned())?;
    if let Some(field) = body_object
        .keys()
        .find(|field| !allowed_fields.contains(&field.as_str()))
    {
        return Err(format!(
            "unsupported account onboarding field `{field}`; tokens, keys, and legacy identity fields are forbidden"
        ));
    }
    if let Some(field) = required_fields
        .iter()
        .find(|field| body_object.get(**field).is_none_or(Value::is_null))
    {
        return Err(format!("`{field}` is required"));
    }
    Ok(BorrowedMcpJson::Value(body))
}

fn build_accounts_onboard_plan_body(arguments: &Map) -> Result<BorrowedMcpJson<'_>, String> {
    build_accounts_onboard_exact_body(
        arguments,
        &["version", "alias", "account_id", "permissions"],
        &["version", "alias", "account_id", "permissions"],
    )
}

fn build_accounts_onboard_prepare_body(arguments: &Map) -> Result<BorrowedMcpJson<'_>, String> {
    build_accounts_onboard_exact_body(
        arguments,
        &["schema", "binding", "receipt", "fee_payment"],
        &["schema", "binding", "receipt", "fee_payment"],
    )
}

fn build_accounts_onboard_submit_body(arguments: &Map) -> Result<BorrowedMcpJson<'_>, String> {
    const FIELDS: &[&str] = &[
        "schema",
        "binding",
        "operation",
        "receipt",
        "semantic_hash_hex",
        "account_id",
        "alias",
        "disposition",
        "transaction_hash_hex",
        "signed_transaction_wire_hex",
        "signed_transaction_wire_sha256",
        "fee_payment",
        "server_signature",
    ];
    build_accounts_onboard_exact_body(arguments, FIELDS, FIELDS)
}

fn build_accounts_faucet_exact_body<'a>(
    arguments: &'a Map,
    allowed_fields: &[&str],
    required_fields: &[&str],
) -> Result<BorrowedMcpJson<'a>, String> {
    if let Some(field) = arguments
        .keys()
        .find(|field| !matches!(field.as_str(), "body" | "accept"))
    {
        return Err(format!(
            "unsupported account faucet argument `{field}`; the exact request must be supplied only in `body`"
        ));
    }
    let body = arguments
        .get("body")
        .ok_or_else(|| "`body` is required".to_owned())?;
    let body_object = body
        .as_object()
        .ok_or_else(|| "`body` must be an object".to_owned())?;
    if let Some(field) = body_object
        .keys()
        .find(|field| !allowed_fields.contains(&field.as_str()))
    {
        return Err(format!(
            "unsupported account faucet field `{field}`; only the exact proof or prepared envelope is accepted"
        ));
    }
    if let Some(field) = required_fields
        .iter()
        .find(|field| body_object.get(**field).is_none_or(Value::is_null))
    {
        return Err(format!("`{field}` is required"));
    }
    Ok(BorrowedMcpJson::Value(body))
}

fn build_accounts_faucet_prepare_body(arguments: &Map) -> Result<BorrowedMcpJson<'_>, String> {
    const FIELDS: &[&str] = &["schema", "binding", "claim", "fee_payment"];
    build_accounts_faucet_exact_body(arguments, FIELDS, FIELDS)
}

fn build_accounts_faucet_submit_body(arguments: &Map) -> Result<BorrowedMcpJson<'_>, String> {
    const FIELDS: &[&str] = &[
        "schema",
        "binding",
        "operation",
        "claim",
        "semantic_hash_hex",
        "account_id",
        "asset_definition_id",
        "asset_id",
        "amount",
        "transaction_hash_hex",
        "signed_transaction_wire_hex",
        "signed_transaction_wire_sha256",
        "fee_payment",
        "server_signature",
    ];
    build_accounts_faucet_exact_body(arguments, FIELDS, FIELDS)
}

fn require_borrowed_governance_body_string<'a>(
    body: &BorrowedMcpJson<'a>,
    field: &str,
) -> Result<&'a str, String> {
    body.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("`{field}` must be a string"))
}

fn require_borrowed_governance_selector_body<'a>(
    body: &BorrowedMcpJson<'a>,
    field: &str,
) -> Result<&'a str, String> {
    let value = require_borrowed_governance_body_string(body, field)?;
    require_governance_selector_v1(field, value)?;
    Ok(value)
}

fn try_begin_form_query(path: &mut String) -> Result<usize, String> {
    let query_start = path
        .len()
        .checked_add(1)
        .ok_or_else(|| "MCP query route length overflow".to_owned())?;
    path.try_reserve_exact(1)
        .map_err(|_| "failed to reserve MCP query route".to_owned())?;
    path.push('?');
    Ok(query_start)
}

fn try_append_form_component(output: &mut String, value: &str) {
    for component in url::form_urlencoded::byte_serialize(value.as_bytes()) {
        output.push_str(component);
    }
}

fn form_component_encoded_len(value: &str) -> Result<usize, String> {
    value.bytes().try_fold(0_usize, |length, byte| {
        let encoded_bytes = if matches!(
            byte,
            b' ' | b'*' | b'-' | b'.' | b'0'..=b'9' | b'A'..=b'Z' | b'_' | b'a'..=b'z'
        ) {
            1
        } else {
            3
        };
        length
            .checked_add(encoded_bytes)
            .ok_or_else(|| "MCP query route length overflow".to_owned())
    })
}

fn try_append_form_pair(
    output: &mut String,
    query_start: usize,
    key: &str,
    value: &str,
) -> Result<(), String> {
    let separator_bytes = usize::from(output.len() > query_start);
    let key_bytes = form_component_encoded_len(key)?;
    let value_bytes = form_component_encoded_len(value)?;
    let additional = key_bytes
        .checked_add(1)
        .and_then(|bytes| bytes.checked_add(value_bytes))
        .and_then(|bytes| bytes.checked_add(separator_bytes))
        .ok_or_else(|| "MCP query route length overflow".to_owned())?;
    output
        .try_reserve_exact(additional)
        .map_err(|_| "failed to reserve MCP query route".to_owned())?;
    if separator_bytes != 0 {
        output.push('&');
    }
    try_append_form_component(output, key);
    output.push('=');
    try_append_form_component(output, value);
    Ok(())
}

fn try_append_percent_encoded_path_component(
    output: &mut String,
    value: &str,
) -> Result<(), String> {
    let additional = percent_encoded_path_component_len(value)?;
    output
        .try_reserve_exact(additional)
        .map_err(|_| "failed to reserve MCP route template".to_owned())?;
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(char::from(byte));
        } else {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            output.push('%');
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    Ok(())
}

fn percent_encoded_path_component_len(value: &str) -> Result<usize, String> {
    value.bytes().try_fold(0_usize, |length, byte| {
        let encoded_bytes =
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                1
            } else {
                3
            };
        length
            .checked_add(encoded_bytes)
            .ok_or_else(|| "MCP route template length overflow".to_owned())
    })
}

fn append_borrowed_query_pairs<'a>(
    mut path: String,
    pairs: impl IntoIterator<Item = (&'a str, &'a Value)>,
) -> Result<String, String> {
    let mut query_start = None;
    for (key, value) in pairs {
        if value.is_null() {
            continue;
        }
        let rendered;
        let value = if let Some(value) = value.as_str() {
            value
        } else {
            rendered =
                value_to_string(value).ok_or_else(|| format!("invalid query value for `{key}`"))?;
            rendered.as_str()
        };
        let query_start = match query_start {
            Some(query_start) => query_start,
            None => *query_start.insert(try_begin_form_query(&mut path)?),
        };
        try_append_form_pair(&mut path, query_start, key, value)?;
    }
    Ok(path)
}

fn append_query_arguments(
    path: String,
    arguments: &Map,
    ignored_keys: &[&str],
) -> Result<String, String> {
    if let Some(query) = arguments.get("query") {
        let query = query
            .as_object()
            .ok_or_else(|| "`query` must be an object".to_owned())?;
        return append_borrowed_query_pairs(
            path,
            query.iter().map(|(key, value)| (key.as_str(), value)),
        );
    }
    append_borrowed_query_pairs(
        path,
        arguments
            .iter()
            .filter(|(key, _)| !ignored_keys.iter().any(|ignored| key == ignored))
            .map(|(key, value)| (key.as_str(), value)),
    )
}

fn append_explorer_history_query_arguments(
    path: String,
    arguments: &Map,
    query_fields: &[&str],
    context: &str,
) -> Result<String, String> {
    let mut allowed_root = Vec::with_capacity(query_fields.len().saturating_add(3));
    allowed_root.extend_from_slice(query_fields);
    allowed_root.extend_from_slice(&["query", "headers", "accept"]);
    reject_unknown_arguments(arguments, &allowed_root, context)?;
    if let Some(query) = arguments.get("query") {
        let query = query
            .as_object()
            .ok_or_else(|| "`query` must be an object".to_owned())?;
        reject_unknown_arguments(query, query_fields, context)?;
        if let Some(field) = query_fields
            .iter()
            .find(|field| arguments.contains_key(**field))
        {
            return Err(format!(
                "`query` and flat `{field}` cannot be supplied together"
            ));
        }
        return append_named_query_fields(path, query, query_fields);
    }
    append_named_query_fields(path, arguments, query_fields)
}

fn append_named_query_fields(
    path: String,
    arguments: &Map,
    fields: &[&str],
) -> Result<String, String> {
    append_borrowed_query_pairs(
        path,
        fields
            .iter()
            .filter_map(|field| arguments.get(*field).map(|value| (*field, value))),
    )
}

fn append_transaction_status_query(
    mut path: String,
    arguments: &Map,
    transaction_hash: &str,
) -> Result<String, String> {
    reject_unknown_arguments(
        arguments,
        &["query", "headers", "accept"],
        "transaction status request",
    )?;
    let query = arguments
        .get("query")
        .and_then(Value::as_object)
        .ok_or_else(|| "`query` must be an object".to_owned())?;
    reject_unknown_arguments(query, &["hash"], "transaction status query")?;
    let query_start = try_begin_form_query(&mut path)?;
    try_append_form_pair(
        &mut path,
        query_start,
        "hash",
        canonical_transaction_hash(transaction_hash)?,
    )?;
    try_append_form_pair(&mut path, query_start, "scope", "global")?;
    Ok(path)
}

fn transaction_status_poll_route(transaction_hash: &str) -> Result<String, String> {
    const BASE: &str = "/v1/pipeline/transactions/status?hash=";
    const SUFFIX: &str = "&scope=global";
    let transaction_hash = canonical_transaction_hash(transaction_hash)?;
    let capacity = BASE
        .len()
        .checked_add(transaction_hash.len())
        .and_then(|capacity| capacity.checked_add(SUFFIX.len()))
        .ok_or_else(|| "transaction status route length overflow".to_owned())?;
    let mut route = String::new();
    route
        .try_reserve_exact(capacity)
        .map_err(|_| "failed to reserve transaction status route".to_owned())?;
    route.push_str(BASE);
    route.push_str(transaction_hash);
    route.push_str(SUFFIX);
    Ok(route)
}

async fn dispatch_iroha_transaction_status_poll(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    transaction_hash: &str,
    extra_headers: Option<&Value>,
    accept: &str,
) -> Result<Value, String> {
    let route = transaction_status_poll_route(transaction_hash)?;
    dispatch_route_borrowed(
        app,
        inbound_headers,
        Method::GET,
        &route,
        extra_headers,
        Vec::new(),
        None,
        Some(accept),
    )
    .await
}

fn extra_headers_contain_authorization(value: &Value) -> bool {
    value.as_object().is_some_and(|headers| {
        headers.contains_key("Authorization") || headers.contains_key("authorization")
    })
}

fn connect_management_authorization_value(token: &str) -> Result<HeaderValue, String> {
    if token.len() != 43
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("management token must be canonical unpadded base64url".to_owned());
    }
    const PREFIX: &str = "Bearer ";
    let capacity = PREFIX
        .len()
        .checked_add(token.len())
        .ok_or_else(|| "management authorization length overflow".to_owned())?;
    let mut authorization = String::new();
    authorization
        .try_reserve_exact(capacity)
        .map_err(|_| "failed to reserve management authorization header".to_owned())?;
    authorization.push_str(PREFIX);
    authorization.push_str(token);
    let mut value = HeaderValue::from_str(&authorization)
        .map_err(|error| format!("invalid management authorization header: {error}"))?;
    value.set_sensitive(true);
    Ok(value)
}

#[cfg(test)]
mod service_depth_tests {
    //! Owning checked service writers keep the caller depth on exact refusals.
    use super::*;
    use crate::service_checked_writer_test_support::audit;
    use norito::json::FastJsonWrite;

    #[test]
    fn original_mcp_borrowed_object_keeps_nested_original_values_and_refusal_depth() {
        let leaf = Value::from("é");
        let mut child =
            BorrowedMcpJsonObject::try_with_capacity(1, "checked child fixture").unwrap();
        child.entries.push(("child", BorrowedMcpJson::Value(&leaf)));
        let mut source =
            BorrowedMcpJsonObject::try_with_capacity(2, "checked object fixture").unwrap();
        source
            .entries
            .push(("original", BorrowedMcpJson::Value(&leaf)));
        source
            .entries
            .push(("nested", BorrowedMcpJson::Object(child)));
        let mut expected = String::new();
        source.write_json(&mut expected);
        audit(&expected, |sink| source.write_json_to(sink));
        assert!(
            matches!(&source.entries[0].1, BorrowedMcpJson::Value(value) if std::ptr::eq(*value, &raw const leaf))
        );
    }
}
