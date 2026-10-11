//! Shared list-query ingress over Explorer's bounded, visibility-scoped scanners.
//!
//! Native scan positions remain internal. The public cursor binds the collection,
//! complete filter and current authorization scope; history positions also retain
//! their committed snapshot. Filtering an entire bounded candidate page may yield
//! an empty page with a continuation, which clients must follow.

use super::*;
use crate::collections::specs::{FieldSpec, FieldType};
use crate::collections::{CollectionError, CollectionSpec, Limits, RowPage, prepare};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use iroha_torii_shared::list_query::{CURSOR_MAX_BYTES, FilterExpr, ListQuery};
use norito::json::{Map, Value};

const fn field(name: &'static str, ty: FieldType) -> FieldSpec {
    FieldSpec {
        name,
        ty,
        sortable: false,
        account: false,
        list: false,
    }
}
use FieldType::{Bool, Json, Number, String as Text};

macro_rules! spec {
    ($name:ident, $id:literal, $tag:literal, [$($key:literal),+], $metadata:literal, [$($field:literal => $ty:ident),* $(,)?]) => {
        static $name: CollectionSpec = CollectionSpec {
            id: $id, tag: $tag, fields: &[$(field($field, $ty)),*], metadata: $metadata,
            default_sort: &[], identity: &[$($key),+], positioned: 0, ordered: false,
        };
    };
}
spec!(ACCOUNTS, "explorer_accounts", 40, ["id"], true, [
    "id" => Text, "network_prefix" => Number, "owned_domains" => Number,
    "owned_assets" => Number, "owned_nfts" => Number,
]);
spec!(DOMAINS, "explorer_domains", 41, ["id"], true, [
    "id" => Text, "logo" => Text, "owned_by" => Text, "accounts" => Number,
    "assets" => Number, "nfts" => Number,
]);
spec!(DEFINITIONS, "explorer_asset_definitions", 42, ["id"], true, [
    "id" => Text, "owning_domain" => Text, "owning_dataspace" => Text, "mintable" => Text, "logo" => Text,
    "owned_by" => Text, "assets" => Number, "total_quantity" => Number,
    "locked_quantity" => Number, "circulating_quantity" => Number,
]);
spec!(ASSETS, "explorer_assets", 43, ["id"], false, [
    "id" => Text, "definition_id" => Text, "account_id" => Text, "value" => Number,
]);
spec!(NFTS, "explorer_nfts", 44, ["id"], true, ["id" => Text, "owned_by" => Text]);
spec!(RWAS, "explorer_rwas", 45, ["id"], true, [
    "id" => Text, "owned_by" => Text, "quantity" => Number, "held_quantity" => Number,
    "primary_reference" => Text, "status" => Text, "is_frozen" => Bool, "parents" => Json,
]);
spec!(BLOCKS, "explorer_blocks", 46, ["height"], false, [
    "hash" => Text, "height" => Number, "created_at" => Text, "prev_block_hash" => Text,
    "transactions_hash" => Text, "transactions_rejected" => Number, "transactions_total" => Number,
]);
spec!(TRANSACTIONS, "explorer_transactions", 47, ["hash"], false, [
    "authority" => Text, "hash" => Text, "block" => Number, "created_at" => Text,
    "executable" => Text, "status" => Text,
]);
spec!(LATEST_TRANSACTIONS, "explorer_transactions_latest", 48, ["hash"], false, [
    "authority" => Text, "hash" => Text, "block" => Number, "created_at" => Text,
    "executable" => Text, "status" => Text,
]);
spec!(INSTRUCTIONS, "explorer_instructions", 49, ["transaction_hash", "index"], false, [
    "authority" => Text, "created_at" => Text, "kind" => Text, "box" => Json,
    "box.encoded" => Text, "box.framed_sha256" => Text, "box.json" => Json,
    "transaction_hash" => Text, "transaction_status" => Text, "block" => Number, "index" => Number,
]);
spec!(LATEST_INSTRUCTIONS, "explorer_instructions_latest", 50, ["transaction_hash", "index"], false, [
    "authority" => Text, "created_at" => Text, "kind" => Text, "box" => Json,
    "box.encoded" => Text, "box.framed_sha256" => Text, "box.json" => Json,
    "transaction_hash" => Text, "transaction_status" => Text, "block" => Number, "index" => Number,
]);

fn specification(path: &str) -> Option<&'static CollectionSpec> {
    Some(match path.strip_suffix("/query").unwrap_or(path) {
        "/v1/explorer/accounts" => &ACCOUNTS,
        "/v1/explorer/domains" => &DOMAINS,
        "/v1/explorer/asset-definitions" => &DEFINITIONS,
        "/v1/explorer/assets" => &ASSETS,
        "/v1/explorer/nfts" => &NFTS,
        "/v1/explorer/rwas" => &RWAS,
        "/v1/explorer/blocks" => &BLOCKS,
        "/v1/explorer/transactions" => &TRANSACTIONS,
        "/v1/explorer/transactions/latest" => &LATEST_TRANSACTIONS,
        "/v1/explorer/instructions" => &INSTRUCTIONS,
        "/v1/explorer/instructions/latest" => &LATEST_INSTRUCTIONS,
        _ => return None,
    })
}

fn invalid(control: &'static str, message: impl Into<String>) -> Error {
    CollectionError::from(iroha_torii_shared::list_query::ListQueryError::new(
        control, message,
    ))
    .into()
}

fn limits() -> Limits {
    Limits::from_page_limits(
        u64::from(explorer::EXPLORER_CURSOR_DEFAULT_LIMIT),
        u64::from(explorer::EXPLORER_CURSOR_MAX_LIMIT),
    )
}

/// A conjunctive equality can narrow the native scanner without changing the
/// full row predicate. Disjunctions and negations never become scan bounds.
fn conjunctive_equality<'a>(filter: Option<&'a FilterExpr>, name: &str) -> Option<&'a Value> {
    match filter? {
        FilterExpr::Eq(field, value) if field.as_str() == name => Some(value),
        FilterExpr::And(children) => children
            .iter()
            .find_map(|child| conjunctive_equality(Some(child), name)),
        _ => None,
    }
}

/// Decode either the API's raw selector or Norito's checksum-bound DTO spelling.
/// Both paths retain the native hash marker-bit and literal-checksum checks.
fn instruction_hash_selector(value: &str) -> Result<HashOf<TransactionEntrypoint>, Error> {
    if value.starts_with("hash:") {
        <HashOf<TransactionEntrypoint> as norito::json::JsonObjectKeyOwned>::from_json_key_text(
            value,
        )
        .map_err(|error| invalid("filter", format!("invalid transaction_hash: {error}")))
    } else {
        value
            .parse()
            .map_err(|error| invalid("filter", format!("invalid transaction_hash: {error}")))
    }
}

/// Compare hash identities in the same canonical spelling as the serialized rows.
/// This changes only equality/membership hash operands, not Boolean structure,
/// ordered text comparisons, projection, authorization or the cursor digest.
fn normalize_instruction_hash_identities(expr: &mut FilterExpr) -> Result<(), Error> {
    fn operand(value: &mut Value) -> Result<(), Error> {
        if let Value::String(text) = value {
            let hash = instruction_hash_selector(text)?;
            *value = norito::json::to_value(&hash)
                .map_err(|error| invalid("filter", error.to_string()))?;
        }
        Ok(())
    }
    match expr {
        FilterExpr::And(children) | FilterExpr::Or(children) => {
            for child in children {
                normalize_instruction_hash_identities(child)?;
            }
        }
        FilterExpr::Not(child) => normalize_instruction_hash_identities(child)?,
        FilterExpr::Eq(field, value) | FilterExpr::Ne(field, value)
            if field.as_str() == "transaction_hash" =>
        {
            operand(value)?
        }
        FilterExpr::In(field, values) | FilterExpr::Nin(field, values)
            if field.as_str() == "transaction_hash" =>
        {
            for value in values {
                operand(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Synthetic selectors that use maintained indexes or committed instruction semantics.
/// They are equality-only conjuncts; ordinary DTO fields accept the complete filter AST.
fn synthetic_fields(spec: &CollectionSpec) -> &'static [&'static str] {
    match spec.id {
        "explorer_accounts" => &["domain", "with_asset"],
        "explorer_nfts" | "explorer_rwas" => &["domain"],
        "explorer_transactions" | "explorer_transactions_latest" => &["asset_id"],
        "explorer_instructions" | "explorer_instructions_latest" => &["account", "asset_id"],
        _ => &[],
    }
}

fn extract_selectors(
    expr: FilterExpr,
    names: &[&str],
    selectors: &mut BTreeMap<String, String>,
) -> Result<Option<FilterExpr>, Error> {
    if let FilterExpr::And(children) = expr {
        let children = children
            .into_iter()
            .map(|expr| extract_selectors(expr, names, selectors))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        return Ok((!children.is_empty()).then_some(FilterExpr::And(children)));
    }
    if let FilterExpr::Eq(ref field, Value::String(ref value)) = expr
        && names.contains(&field.as_str())
    {
        if selectors.insert(field.0.clone(), value.clone()).is_some() {
            return Err(invalid(
                "filter",
                format!("synthetic selector `{field}` may appear only once"),
            ));
        }
        return Ok(None);
    }
    fn contains(expr: &FilterExpr, names: &[&str]) -> bool {
        match expr {
            FilterExpr::And(children) | FilterExpr::Or(children) => {
                children.iter().any(|expr| contains(expr, names))
            }
            FilterExpr::Not(expr) => contains(expr, names),
            expr => expr
                .field()
                .is_some_and(|field| names.contains(&field.as_str())),
        }
    }
    if contains(&expr, names) {
        return Err(invalid(
            "filter",
            format!(
                "synthetic selectors {} require one string equality in the top-level conjunction",
                names.join(", ")
            ),
        ));
    }
    Ok(Some(expr))
}

struct ScanQuery {
    spec: &'static CollectionSpec,
    rows: ListQuery,
    selectors: BTreeMap<String, String>,
    native: explorer::ExplorerCursorQuery,
    digest: [u8; 32],
    limits: Limits,
}

impl ScanQuery {
    fn new(
        spec: &'static CollectionSpec,
        query: ListQuery,
        visibility: [u8; 32],
        limits: Limits,
    ) -> Result<Self, Error> {
        query.validate().map_err(CollectionError::from)?;
        for (unsupported, present) in [
            ("sort", !query.sort.is_empty()),
            ("aggregate", query.aggregate.is_some()),
            ("include_total", query.include_total),
        ] {
            if present {
                return Err(invalid(
                    unsupported,
                    "bounded Explorer feeds support filter, select, limit and cursor; full-scan controls are unavailable",
                ));
            }
        }
        let filter = query
            .filter
            .as_ref()
            .map(|filter| limits.bytes.key(filter))
            .transpose()?
            .unwrap_or_default();
        let scope_bytes = b"iroha-explorer-list-query-v1\0"
            .len()
            .checked_add(spec.id.len())
            .and_then(|n| n.checked_add(1 + 32))
            .and_then(|n| n.checked_add(filter.len()))
            .ok_or_else(|| collections::memory::capacity("Explorer query digest"))?;
        collections::memory::ensure(
            collections::memory::add(scope_bytes, filter.capacity())?,
            limits.bytes.scratch_bytes,
            "Explorer query digest",
        )?;
        let mut scope = collections::memory::vector::<u8>(
            scope_bytes,
            limits.bytes.scratch_bytes,
            "Explorer query digest",
        )?;
        scope.extend_from_slice(b"iroha-explorer-list-query-v1\0");
        scope.extend_from_slice(spec.id.as_bytes());
        scope.push(0);
        scope.extend_from_slice(&visibility);
        scope.extend_from_slice(filter.as_bytes());
        let digest = *iroha_crypto::Hash::new(scope).as_ref();
        drop(filter);
        let native_cursor = query
            .cursor
            .as_deref()
            .map(|token| Self::unwrap_cursor(spec.tag, &digest, token))
            .transpose()?;
        let mut rows = query;
        rows.cursor = None;
        let mut selectors = BTreeMap::new();
        rows.filter = rows
            .filter
            .take()
            .map(|expr| extract_selectors(expr, synthetic_fields(spec), &mut selectors))
            .transpose()?
            .flatten();
        if matches!(
            spec.id,
            "explorer_instructions" | "explorer_instructions_latest"
        ) && let Some(filter) = rows.filter.as_mut()
        {
            normalize_instruction_hash_identities(filter)?;
        }
        let plan = prepare(spec, "", &rows, &limits)?;
        let native = explorer::ExplorerCursorQuery {
            cursor: native_cursor,
            limit: u32::try_from(plan.limit()).expect("bounded limit"),
        };
        Ok(Self {
            spec,
            rows,
            selectors,
            native,
            digest,
            limits,
        })
    }

    fn unwrap_cursor(tag: u8, digest: &[u8; 32], token: &str) -> Result<String, Error> {
        let fail = || {
            invalid(
                "cursor",
                "cursor must come from this Explorer collection with the same filter and authorization scope",
            )
        };
        if token.len() > CURSOR_MAX_BYTES {
            return Err(fail());
        }
        let bytes = URL_SAFE_NO_PAD.decode(token).map_err(|_| fail())?;
        if bytes.len() <= 37
            || &bytes[..4] != b"IEL1"
            || bytes[4] != tag
            || &bytes[5..37] != digest
            || URL_SAFE_NO_PAD.encode(&bytes) != token
        {
            return Err(fail());
        }
        String::from_utf8(bytes[37..].to_vec()).map_err(|_| fail())
    }

    fn wrap_cursor(&self, native: &str, scratch_bytes: usize) -> Result<String, Error> {
        let frame_bytes = 37usize
            .checked_add(native.len())
            .ok_or_else(|| collections::memory::capacity("Explorer cursor"))?;
        let encoded_bytes = base64::encoded_len(frame_bytes, false)
            .ok_or_else(|| collections::memory::capacity("Explorer cursor"))?;
        if encoded_bytes > CURSOR_MAX_BYTES {
            return Err(invalid(
                "cursor",
                "Explorer scan position exceeds the cursor bound",
            ));
        }
        collections::memory::ensure(
            collections::memory::add(frame_bytes, encoded_bytes)?,
            scratch_bytes,
            "Explorer cursor frame and encoding",
        )?;
        let mut bytes =
            collections::memory::vector::<u8>(frame_bytes, scratch_bytes, "Explorer cursor")?;
        bytes.extend_from_slice(b"IEL1");
        bytes.push(self.spec.tag);
        bytes.extend_from_slice(&self.digest);
        bytes.extend_from_slice(native.as_bytes());
        let mut encoded = collections::memory::vector::<u8>(
            encoded_bytes,
            scratch_bytes - frame_bytes,
            "Explorer cursor encoding",
        )?;
        encoded.resize(encoded_bytes, 0);
        URL_SAFE_NO_PAD
            .encode_slice(&bytes, &mut encoded)
            .map_err(|_| collections::memory::capacity("Explorer cursor"))?;
        String::from_utf8(encoded)
            .map_err(|_| collections::memory::capacity("Explorer cursor").into())
    }

    fn page(&self, scan: Value) -> Result<RowPage, Error> {
        let plan = prepare(self.spec, "", &self.rows, &self.limits)?;
        let Value::Object(mut scan) = scan else {
            return Err(invalid("query", "Explorer scan must be an object"));
        };
        let cursor = scan
            .get("pagination")
            .and_then(|meta| meta.get("next_cursor"));
        let next_cursor = match cursor {
            Some(Value::Null) => None,
            Some(Value::String(token)) if !token.is_empty() => {
                Some(self.wrap_cursor(token, plan.runtime_bytes().scratch_bytes)?)
            }
            _ => {
                return Err(invalid(
                    "query",
                    "Explorer scan did not produce a continuation boundary",
                ));
            }
        };
        let Some(Value::Array(source)) = scan.remove("items") else {
            return Err(invalid("query", "Explorer scan did not produce rows"));
        };
        let cursor_bytes = next_cursor.as_ref().map_or(0, String::capacity);
        let scratch = plan
            .runtime_bytes()
            .scratch_bytes
            .checked_sub(cursor_bytes)
            .ok_or_else(|| collections::memory::capacity("Explorer retained cursor"))?;
        let mut items =
            collections::memory::vector::<Map>(source.len(), scratch, "Explorer projection slots")?;
        let mut retained = collections::memory::slots::<Map>(items.capacity())?;
        for item in source {
            let Value::Object(row) = item else {
                return Err(invalid("query", "Explorer scan row must be an object"));
            };
            if plan.matches(&row) {
                retained =
                    collections::memory::add(retained, collections::memory::map_heap_bytes(&row)?)?;
                collections::memory::ensure(
                    retained,
                    self.limits.bytes.retained_bytes,
                    "Explorer retained page",
                )?;
                items.push(row);
            }
        }
        Ok(plan.project(RowPage {
            items,
            next_cursor,
            total: None,
        })?)
    }
}

pub(super) async fn get(
    State(app): State<SharedAppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> Result<Response, Error> {
    let caller =
        torii_visibility_account_from_headers(&app, &headers, &method, &uri, &[], "v1/explorer")?;
    let query = list_query_from_query_string(uri.query())?;
    execute(&app, &headers, remote.ip(), &uri, caller, query).await
}

pub(super) async fn post(
    State(app): State<SharedAppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    body: axum::body::Bytes,
) -> Result<Response, Error> {
    let caller = torii_visibility_account_from_headers(
        &app,
        &headers,
        &method,
        &uri,
        body.as_ref(),
        "v1/explorer/query",
    )?;
    let plan = match torii_routed_read_request_decode_plan(&app) {
        Ok(plan) => plan,
        Err(response) => return Ok(response),
    };
    let value =
        match decode_torii_proxy_json_body::<Value>(plan, body.as_ref(), "Explorer list query") {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
    execute(
        &app,
        &headers,
        remote.ip(),
        &uri,
        caller,
        list_query_from_json(value)?,
    )
    .await
}

async fn execute(
    app: &SharedAppState,
    headers: &HeaderMap,
    remote: std::net::IpAddr,
    uri: &Uri,
    caller: ToriiAccountReadVisibility,
    mut query: ListQuery,
) -> Result<Response, Error> {
    let spec =
        specification(uri.path()).ok_or_else(|| invalid("query", "unknown Explorer collection"))?;
    let visibility = caller
        .into_dataspace_context(Arc::clone(app))
        .current_visibility();
    if let Some(filter) = query.filter.as_mut() {
        let fields: &[&str] = match spec.id {
            "explorer_accounts" => &["id"],
            "explorer_domains"
            | "explorer_asset_definitions"
            | "explorer_nfts"
            | "explorer_rwas" => &["owned_by"],
            "explorer_assets" => &["account_id"],
            "explorer_transactions" | "explorer_transactions_latest" => &["authority"],
            "explorer_instructions" | "explorer_instructions_latest" => &["authority", "account"],
            _ => &[],
        };
        for field in fields {
            routing::canonicalize_filter_account_literals(
                filter,
                field,
                Some(&app.state),
                &app.telemetry_handle(),
                "/v1/explorer?filter",
            )
            .map_err(|error| invalid("filter", error.to_string()))?;
        }
    }
    let mut query_limits = limits();
    query_limits.bytes = collections::memory::BytePolicy::for_admitted_read(
        current_routed_read_memory_envelope(app)
            .map_err(|_| collections::memory::capacity("working set"))?,
        app.torii_proxy_max_response_bytes,
    );
    let query = ScanQuery::new(
        spec,
        query,
        visibility.visible_route_set_digest(),
        query_limits,
    )?;
    if !limits::is_allowed_by_cidr(headers, Some(remote), &app.api_rate_limit_bypass_nets) {
        let cost = routing::app_query_limits().rate_limit_cost(u64::from(query.native.limit));
        check_access_enforced_with_cost(app, headers, Some(remote), spec.id, true, cost).await?;
    }
    let account = |name: &str| {
        query
            .selectors
            .get(name)
            .map(|value| parse_account_id_for_endpoint(app, value, "/v1/explorer?filter"))
            .transpose()
    };
    let domain = query
        .selectors
        .get("domain")
        .map(|value| parse_domain_id(value))
        .transpose()?;
    let asset = query
        .selectors
        .get("asset_id")
        .map(|value| parse_asset_id(value))
        .transpose()?;
    let block = conjunctive_equality(query.rows.filter.as_ref(), "block").and_then(|value| {
        value
            .as_u64()
            .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
    });
    let transaction_hash = conjunctive_equality(query.rows.filter.as_ref(), "transaction_hash")
        .and_then(Value::as_str)
        .map(instruction_hash_selector)
        .transpose()?;
    let admission = acquire_query_admission(app.as_ref(), true).await?;
    let state = app.state.clone();
    let telemetry = app.telemetry.clone();
    let native = query.native.clone();
    let response = match spec.id {
        "explorer_accounts" => {
            routing::handle_v1_explorer_accounts_admitted(
                state,
                visibility,
                native,
                domain,
                query
                    .selectors
                    .get("with_asset")
                    .map(|value| parse_asset_definition_id(app, value))
                    .transpose()?,
                admission,
            )
            .await?
        }
        "explorer_domains" => {
            routing::handle_v1_explorer_domains_admitted(state, visibility, native, None, admission)
                .await?
        }
        "explorer_asset_definitions" => {
            routing::handle_v1_explorer_asset_definitions_admitted(
                state, visibility, native, None, None, admission,
            )
            .await?
        }
        "explorer_assets" => {
            routing::handle_v1_explorer_assets_admitted(
                state, visibility, native, None, None, None, admission,
            )
            .await?
        }
        "explorer_nfts" => {
            routing::handle_v1_explorer_nfts_admitted(
                state, visibility, native, None, domain, admission,
            )
            .await?
        }
        "explorer_rwas" => {
            routing::handle_v1_explorer_rwas_admitted(
                state, visibility, native, None, domain, admission,
            )
            .await?
        }
        "explorer_blocks" => {
            routing::handle_v1_explorer_blocks_admitted(
                state, telemetry, visibility, native, admission,
            )
            .await?
        }
        "explorer_transactions" => {
            routing::handle_v1_explorer_transactions_admitted(
                state, telemetry, visibility, native, None, block, None, asset, admission,
            )
            .await?
        }
        "explorer_transactions_latest" => {
            routing::handle_v1_explorer_transactions_latest_admitted(
                state, telemetry, visibility, native, None, block, None, asset, admission,
            )
            .await?
        }
        "explorer_instructions" | "explorer_instructions_latest" => {
            let filters = routing::ExplorerInstructionQuery {
                account: account("account")?,
                authority: None,
                transaction_hash,
                status: None,
                block,
                kind: None,
                asset_id: asset,
            };
            if spec.id == "explorer_instructions" {
                routing::handle_v1_explorer_instructions_admitted(
                    state, telemetry, visibility, native, filters, admission,
                )
                .await?
            } else {
                routing::handle_v1_explorer_instructions_latest_admitted(
                    state, telemetry, visibility, native, filters, admission,
                )
                .await?
            }
        }
        _ => unreachable!("closed Explorer collection table"),
    };
    if response.status() != StatusCode::OK {
        return Ok(response);
    }
    let bytes = axum::body::to_bytes(response.into_body(), query.limits.bytes.source_frame_bytes)
        .await
        .map_err(|error| invalid("query", error.to_string()))?;
    let admission = acquire_query_admission(app.as_ref(), true).await?;
    routing::run_admitted_blocking(admission, "Explorer projection worker failed", move || {
        let policy = query.limits.bytes;
        let decode_limits = norito::DecodeLimits::new(
            policy.source_frame_bytes,
            policy.row_bytes,
            policy.row_bytes,
            policy.row_bytes,
            norito::core::MAX_VALUE_NESTING_DEPTH,
        );
        norito::json::preflight_slice(
            &bytes,
            norito::json::JsonPreflightLimits::from_decode_limits(
                policy.source_frame_bytes,
                decode_limits,
            ),
        )
        .map_err(|_| collections::memory::capacity("Explorer scan graph"))?;
        let (scan, usage) = norito::core::with_decode_limits_measured(decode_limits, || {
            norito::json::from_slice::<Value>(&bytes)
        });
        let scan = scan.map_err(|error| invalid("query", error.to_string()))?;
        collections::memory::ensure(
            usage.total_allocated_bytes(),
            policy.row_bytes,
            "Explorer scan graph",
        )?;
        routing::collection_sources::row_page_response(query.page(scan)?, policy)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_torii_shared::list_query::{FieldPath, field};

    fn standalone_scan(
        spec: &'static CollectionSpec,
        query: ListQuery,
        visibility: [u8; 32],
    ) -> Result<ScanQuery, Error> {
        ScanQuery::new(spec, query, visibility, limits())
    }

    const FAUCET_HEX: &str = "38eb3689fb42390f656ac9e1fa0d02451f1f4f1a1b92c1b074f1c2b6761e8631";
    const FAUCET_LITERAL: &str =
        "hash:38EB3689FB42390F656AC9E1FA0D02451F1F4F1A1B92C1B074F1C2B6761E8631#008C";
    const LOG_LITERAL: &str =
        "hash:66BF60AB1C762607F02BBDFC834E2D832243EF413D0C24BBFF8EE3D00A2830DB#DB6C";

    fn instruction_scan_page() -> Value {
        norito::json!({"items":[
            {"transaction_hash":FAUCET_LITERAL,"index":0,"kind":"Transfer","block":8},
            {"transaction_hash":LOG_LITERAL,"index":0,"kind":"Log","block":9}
        ],"pagination":{"next_cursor":"native-next"}})
    }

    #[test]
    fn instruction_hash_identity_matches_canonical_rows_and_preserves_cursor_scope() {
        for spec in [&INSTRUCTIONS, &LATEST_INSTRUCTIONS] {
            for selector in [
                FAUCET_HEX.to_owned(),
                FAUCET_HEX.to_uppercase(),
                format!("0x{FAUCET_HEX}"),
                FAUCET_LITERAL.to_owned(),
            ] {
                let input = ListQuery::new()
                    .filter(
                        field("transaction_hash")
                            .eq(selector)
                            .and(field("block").eq(8)),
                    )
                    .select([FieldPath::from("kind")]);
                let query = standalone_scan(spec, input.clone(), [1; 32]).unwrap();
                let bound = conjunctive_equality(query.rows.filter.as_ref(), "transaction_hash")
                    .and_then(Value::as_str)
                    .unwrap();
                assert_eq!(bound, FAUCET_LITERAL);
                assert_eq!(
                    instruction_hash_selector(bound).unwrap(),
                    FAUCET_HEX.parse().unwrap()
                );
                let page = query.page(instruction_scan_page()).unwrap();
                assert_eq!(
                    page.items,
                    vec![
                        norito::json!({"kind":"Transfer"})
                            .as_object()
                            .unwrap()
                            .clone()
                    ]
                );
                let token = page.next_cursor.unwrap();
                let mut next = input.clone();
                next.cursor = Some(token.clone());
                assert_eq!(
                    standalone_scan(spec, next.clone(), [1; 32])
                        .unwrap()
                        .native
                        .cursor
                        .as_deref(),
                    Some("native-next")
                );
                assert!(standalone_scan(spec, next.clone(), [2; 32]).is_err());
                next.filter = Some(field("transaction_hash").eq(LOG_LITERAL));
                assert!(standalone_scan(spec, next, [1; 32]).is_err());
                let other = if spec.id == INSTRUCTIONS.id {
                    &LATEST_INSTRUCTIONS
                } else {
                    &INSTRUCTIONS
                };
                let mut other_query = input;
                other_query.cursor = Some(token);
                assert!(standalone_scan(other, other_query, [1; 32]).is_err());
            }
        }
    }

    #[test]
    fn instruction_hash_identity_keeps_the_real_committed_log_row() {
        let raw = "66bf60ab1c762607f02bbdfc834e2d832243ef413d0c24bbff8ee3d00a2830db";
        for spec in [&INSTRUCTIONS, &LATEST_INSTRUCTIONS] {
            for selector in [raw, LOG_LITERAL] {
                let query = standalone_scan(
                    spec,
                    ListQuery::new().filter(
                        field("transaction_hash")
                            .eq(selector)
                            .and(field("block").eq(9)),
                    ),
                    [1; 32],
                )
                .unwrap();
                let page = query.page(instruction_scan_page()).unwrap();
                assert_eq!(page.items.len(), 1);
                assert_eq!(
                    page.items[0].get("kind").and_then(Value::as_str),
                    Some("Log")
                );
                assert_eq!(
                    page.items[0]
                        .get("transaction_hash")
                        .and_then(Value::as_str),
                    Some(LOG_LITERAL)
                );
            }
        }
    }

    #[test]
    fn instruction_hash_identity_keeps_boolean_and_membership_semantics() {
        let eq = field("transaction_hash").eq(FAUCET_HEX);
        let cases = [
            (eq.clone().or(field("kind").eq("Log")), 2),
            (FilterExpr::Not(Box::new(eq)), 1),
            (field("transaction_hash").ne(FAUCET_HEX), 1),
            (
                FilterExpr::In(
                    FieldPath::from("transaction_hash"),
                    vec![Value::String(FAUCET_HEX.into())],
                ),
                1,
            ),
            (
                FilterExpr::Nin(
                    FieldPath::from("transaction_hash"),
                    vec![Value::String(FAUCET_HEX.into())],
                ),
                1,
            ),
        ];
        for (filter, count) in cases {
            let query =
                standalone_scan(&INSTRUCTIONS, ListQuery::new().filter(filter), [1; 32]).unwrap();
            assert!(conjunctive_equality(query.rows.filter.as_ref(), "transaction_hash").is_none());
            assert_eq!(
                query.page(instruction_scan_page()).unwrap().items.len(),
                count
            );
        }
    }

    #[test]
    fn instruction_hash_identity_rejects_bad_checksum_marker_and_malformed_operands() {
        for selector in [
            FAUCET_LITERAL.replace("#008C", "#0000"),
            "10".repeat(32),
            "hash:invalid".to_owned(),
            "bad-raw-hash".to_owned(),
        ] {
            for spec in [&INSTRUCTIONS, &LATEST_INSTRUCTIONS] {
                assert!(
                    standalone_scan(
                        spec,
                        ListQuery::new().filter(field("transaction_hash").eq(selector.clone())),
                        [1; 32]
                    )
                    .is_err()
                );
            }
        }
    }

    #[test]
    fn direct_home_filter_preserves_large_exact_dataspace_identity() {
        let query = standalone_scan(
            &DEFINITIONS,
            ListQuery::new().filter(field("owning_dataspace").eq("8648377547929788715")),
            [1; 32],
        )
        .expect("direct home query");
        let page = query.page(norito::json!({
            "items": [
                {"id":"direct", "owning_domain":null, "owning_dataspace":"8648377547929788715"},
                {"id":"adjacent", "owning_domain":null, "owning_dataspace":"8648377547929788716"},
                {"id":"domain", "owning_domain":"treasury.bpng", "owning_dataspace":null}
            ],
            "pagination":{"next_cursor":null}
        })).expect("filtered definitions");
        assert_eq!(page.items.len(), 1);
        assert_eq!(
            page.items[0].get("id").and_then(Value::as_str),
            Some("direct")
        );
    }

    #[test]
    fn shared_filter_projection_preserves_counters_and_empty_continuations() {
        let query = ListQuery::new()
            .filter(field("owned_assets").gte(2))
            .select([FieldPath::from("id"), FieldPath::from("owned_assets")]);
        let query = standalone_scan(&ACCOUNTS, query, [1; 32]).expect("query");
        let page = query.page(norito::json!({"items":[{"id":"alice","owned_assets":1}],"pagination":{"next_cursor":"native"}})).expect("page");
        assert!(page.items.is_empty());
        let token = page
            .next_cursor
            .expect("continue after an empty filtered page");
        let next = standalone_scan(
            &ACCOUNTS,
            ListQuery {
                cursor: Some(token.clone()),
                select: None,
                ..query.rows.clone()
            },
            [1; 32],
        )
        .expect("projection may change");
        assert_eq!(next.native.cursor.as_deref(), Some("native"));
        assert!(
            standalone_scan(
                &ACCOUNTS,
                ListQuery {
                    cursor: Some(token),
                    ..ListQuery::new()
                },
                [1; 32]
            )
            .is_err()
        );
        let page = query.page(norito::json!({"items":[{"id":"bob","owned_assets":3,"network_prefix":753}],"pagination":{"next_cursor":null}})).expect("page");
        assert_eq!(
            page.items,
            vec![
                norito::json!({"id":"bob","owned_assets":3})
                    .as_object()
                    .unwrap()
                    .clone()
            ]
        );
        assert!(page.next_cursor.is_none());
        assert!(page.total.is_none());
    }

    #[test]
    fn cursor_rejects_different_visibility_collection_and_legacy_position() {
        let query = standalone_scan(&ACCOUNTS, ListQuery::new(), [1; 32]).expect("query");
        let token = query
            .wrap_cursor("native", query.limits.bytes.scratch_bytes)
            .expect("cursor");
        for (spec, scope) in [(&ACCOUNTS, [2; 32]), (&DOMAINS, [1; 32])] {
            assert!(
                standalone_scan(
                    spec,
                    ListQuery {
                        cursor: Some(token.clone()),
                        ..ListQuery::new()
                    },
                    scope
                )
                .is_err()
            );
        }
        assert!(
            standalone_scan(
                &ACCOUNTS,
                ListQuery {
                    cursor: Some("native".into()),
                    ..ListQuery::new()
                },
                [1; 32]
            )
            .is_err()
        );
    }

    #[test]
    fn synthetic_filters_are_explicit_and_never_silently_reinterpreted() {
        let query = ListQuery::new().filter(
            field("domain")
                .eq("wonderland")
                .and(field("owned_assets").gt(1)),
        );
        let query = standalone_scan(&ACCOUNTS, query, [0; 32]).expect("conjunctive selector");
        assert_eq!(
            query.selectors.get("domain").map(String::as_str),
            Some("wonderland")
        );
        for filter in [
            field("domain").ne("wonderland"),
            field("domain").eq("a").or(field("id").eq("b")),
            field("domain").eq("a").and(field("domain").eq("b")),
        ] {
            assert!(standalone_scan(&ACCOUNTS, ListQuery::new().filter(filter), [0; 32]).is_err());
        }
        for query in [
            ListQuery {
                include_total: true,
                ..ListQuery::new()
            },
            ListQuery {
                limit: Some(101),
                ..ListQuery::new()
            },
            ListQuery::new().filter(field("unknown").eq(1)),
        ] {
            assert!(standalone_scan(&ACCOUNTS, query, [0; 32]).is_err());
        }
    }

    #[test]
    fn explorer_cursor_checks_transport_and_scratch_before_allocation() {
        let query = standalone_scan(&ACCOUNTS, ListQuery::new(), [1; 32]).unwrap();
        let frame = 37 + "native".len();
        let encoded = base64::encoded_len(frame, false).unwrap();
        assert!(query.wrap_cursor("native", frame + encoded).is_ok());
        assert!(query.wrap_cursor("native", frame + encoded - 1).is_err());
        assert!(
            query
                .wrap_cursor(&"x".repeat(CURSOR_MAX_BYTES), usize::MAX)
                .is_err()
        );
    }

    #[test]
    fn explorer_projection_enforces_admitted_retained_graph() {
        let mut bounds = limits();
        bounds.bytes.retained_bytes = 1;
        let query = ScanQuery::new(&ACCOUNTS, ListQuery::new(), [1; 32], bounds).unwrap();
        assert!(
            query
                .page(norito::json!({"items":[{"id":"alice"}],"pagination":{"next_cursor":null}}))
                .is_err()
        );
    }

    #[test]
    fn every_feed_has_one_get_and_post_schema() {
        for path in [
            "accounts",
            "domains",
            "asset-definitions",
            "assets",
            "nfts",
            "rwas",
            "blocks",
            "transactions",
            "transactions/latest",
            "instructions",
            "instructions/latest",
        ] {
            let path = format!("/v1/explorer/{path}");
            assert_eq!(
                specification(&path).expect("get").id,
                specification(&format!("{path}/query")).expect("post").id
            );
        }
    }

    #[test]
    fn only_conjunctive_equalities_narrow_history_scans() {
        let bound = field("block").eq(7).and(field("status").eq("committed"));
        assert_eq!(
            conjunctive_equality(Some(&bound), "block").and_then(Value::as_u64),
            Some(7)
        );
        let unbounded = field("block").eq(7).or(field("status").eq("committed"));
        assert!(conjunctive_equality(Some(&unbounded), "block").is_none());
    }
}
