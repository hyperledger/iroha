const OPENAPI_CONTRACT_ASSET_VERSION: u64 = 1;
const OPENAPI_CONTRACT_ASSET_LEN: usize = 10_461;
const OPENAPI_CONTRACT_ASSET_SHA256: &str =
    "9ac246108936e901e05ca09ee423e24f13508c32bea09cb7c07e3c2ea47a0ddd";
const OPENAPI_CONTRACT_SECTION_ORDER: &[&str] = &[
    "evidence.audit.description",
    "evidence.audit.success",
    "evidence.schemas",
    "pin.register.description",
    "pin.list.description",
    "pin.manifest.description",
    "pin.manifest.retired",
    "replication.description",
    "proof.por.required",
    "proof.pdp.failures",
    "proof.potr.failures",
    "bridge.proof.required",
    "bridge.attestation.required",
    "bridge.bundle.required",
    "block.header.required",
    "block.header.nullable",
    "ledger.state_finality.required",
    "ledger.state_finality.retired",
    "ledger.state_finality.retired_paths",
    "ledger.state_finality.retired_schemas",
    "fixture.header.required",
    "fixture.retired",
    "lifecycle.required",
    "status.required",
    "status.absent",
    "hf.headers",
    "app.page.required",
    "app.page.properties",
    "repo.agreement.fields",
    "collection.query.fields",
    "contract.alias.request.required",
    "contract.alias.binding.required",
    "contract.alias.binding.optional",
    "contract.alias.response.required",
    "governed.found.fields",
    "governed.inactive.fields",
    "governed.missing.fields",
];
const OPENAPI_CONTRACT_ASSET: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/openapi/tests/openapi_contracts_v1.json"
));
/// Ordered scalar field/name inventory; whitespace is only an inventory separator.
fn contract_words(inventory: &str) -> Vec<&str> {
    inventory.split_ascii_whitespace().collect()
}
fn contract_word_set(inventory: &str) -> BTreeSet<&str> {
    contract_words(inventory).into_iter().collect()
}
/// Expected type and exact scalar value; a missing or differently typed field fails.
enum ScalarContract<'a> {
    Text(&'a str),
    Unsigned(u64),
    Flag(bool),
    Length(usize),
}
#[track_caller]
fn assert_scalar(actual: Option<&Value>, expected: ScalarContract<'_>) {
    match expected {
        ScalarContract::Text(value) => assert_eq!(actual.and_then(Value::as_str), Some(value)),
        ScalarContract::Unsigned(value) => assert_eq!(actual.and_then(Value::as_u64), Some(value)),
        ScalarContract::Flag(value) => assert_eq!(actual.and_then(Value::as_bool), Some(value)),
        ScalarContract::Length(value) => {
            assert_eq!(actual.and_then(Value::as_array).map(Vec::len), Some(value))
        }
    }
}
struct SchemaShape {
    name: &'static str,
    required: &'static str,
    optional: Option<&'static str>,
}
struct PropertyRefContract {
    owner: &'static str,
    property: &'static str,
    expected: &'static str,
}
struct OperationResponseContract {
    path: &'static str,
    method: &'static str,
    status: &'static str,
    schema_ref: &'static str,
}
// Homogeneous typed data rows; each invocation expands only to a tuple array.
macro_rules! contract_rows {
    ($( $($field:expr),+; )+) => { [$(($($field),+)),+] };
}
macro_rules! scalar_contracts {
    ($( $actual:expr => $kind:ident($expected:expr $(,)?); )+) => {
        $(assert_scalar($actual, ScalarContract::$kind($expected));)+
    };
}
macro_rules! inline_shapes {
    ($schemas:expr; $( $name:expr, $required:expr, $optional:expr; )+) => {
        $(assert_strict_object_schema($schemas, $name, $required, $optional);)+
    };
}
#[track_caller]
fn assert_set<T: Ord + std::fmt::Debug>(actual: &BTreeSet<T>, expected: &BTreeSet<T>) {
    assert_eq!(actual, expected);
}
#[track_caller]
fn assert_sequence<T: PartialEq + std::fmt::Debug>(actual: &[T], expected: &[T]) {
    assert_eq!(actual, expected);
}
macro_rules! set_contracts {
    ($( $actual:expr => $expected:expr; )+) => { $(assert_set(&$actual, &$expected);)+ };
}
macro_rules! sequence_contracts {
    ($( $actual:expr => $expected:expr; )+) => { $(assert_sequence(&$actual, &$expected);)+ };
}
#[derive(Clone, Copy, Debug)]
enum MemberContract {
    Present,
    Absent,
}
#[track_caller]
fn assert_members<I>(object: &Map, fields: I, mode: MemberContract)
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    for field in fields {
        let field = field.as_ref();
        assert_eq!(
            object.contains_key(field),
            matches!(mode, MemberContract::Present),
            "{mode:?} field {field}"
        );
    }
}
#[track_caller]
fn assert_string_members(values: &[Value], fields: &[&str], mode: MemberContract) {
    for field in fields {
        assert_eq!(
            values.iter().any(|value| value.as_str() == Some(field)),
            matches!(mode, MemberContract::Present),
            "{mode:?} string {field}"
        );
    }
}
macro_rules! string_members {
    ($values:expr; $( $mode:ident => $fields:expr; )+) => { $(assert_string_members($values, $fields, MemberContract::$mode);)+ };
}
macro_rules! member_contracts {
    ($object:expr; $( $mode:ident => $fields:expr; )+) => { $(assert_members($object, $fields, MemberContract::$mode);)+ };
}
#[track_caller]
fn assert_count(actual: usize, expected: usize) {
    assert_eq!(actual, expected);
}
#[track_caller]
fn assert_text(actual: &str, expected: &str) {
    assert_eq!(actual, expected);
}
macro_rules! count_contracts {
    ($( $actual:expr => $expected:expr; )+) => { $(assert_count($actual, $expected);)+ };
}
macro_rules! text_contracts {
    ($( $actual:expr => $expected:expr; )+) => { $(assert_text(&$actual, &$expected);)+ };
}
// These table macros construct typed rows only; the runners own all assertions.
macro_rules! property_refs {
    ($schemas:expr; $( $owner:expr, $property:expr, $expected:expr; )+) => {
        assert_property_refs($schemas, &[$(PropertyRefContract { owner: $owner, property: $property, expected: $expected }),+]);
    };
}
macro_rules! response_rows {
    ($( $path:expr, $method:expr, $status:expr, $schema_ref:expr; )+) => {
        [$(OperationResponseContract { path: $path, method: $method, status: $status, schema_ref: $schema_ref }),+]
    };
}
macro_rules! response_contracts {
    ($document:expr; $( $path:expr, $method:expr, $status:expr, $schema_ref:expr; )+) => {
        assert_operation_response_contracts($document, &response_rows! { $($path, $method, $status, $schema_ref;)+ });
    };
}
macro_rules! schema_shapes {
    ($schemas:expr; $( $name:expr, $required:expr, $optional:expr; )+) => {
        assert_schema_shapes($schemas, &[$(SchemaShape { name: $name, required: $required, optional: $optional }),+]);
    };
}
#[track_caller]
fn contract_object<'a>(value: Option<&'a Value>, context: &str) -> &'a Map {
    value
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{context}: expected object"))
}
#[track_caller]
fn contract_array<'a>(value: Option<&'a Value>, context: &str) -> &'a Vec<Value> {
    value
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{context}: expected array"))
}
#[track_caller]
fn contract_text<'a>(value: Option<&'a Value>, context: &str) -> &'a str {
    value
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{context}: expected string"))
}
fn contract_asset() -> &'static Map {
    use sha2::{Digest as _, Sha256};
    static ASSET: LazyLock<Map> = LazyLock::new(|| {
        count_contracts! { OPENAPI_CONTRACT_ASSET.len() => OPENAPI_CONTRACT_ASSET_LEN; }
        assert_eq!(
            hex::encode(Sha256::digest(OPENAPI_CONTRACT_ASSET)),
            OPENAPI_CONTRACT_ASSET_SHA256,
            "OpenAPI contract asset digest drift"
        );
        let value: Value = norito::json::from_slice(OPENAPI_CONTRACT_ASSET)
            .expect("OpenAPI contract V1 asset must be valid Norito JSON");
        let root = value
            .as_object()
            .expect("OpenAPI contract asset root object");
        set_contracts! { root.keys().map(String::as_str).collect::<BTreeSet<_>>() => contract_word_set("sections version"); }
        scalar_contracts! { root.get("version") => Unsigned(OPENAPI_CONTRACT_ASSET_VERSION); }
        let sections = contract_array(root.get("sections"), "OpenAPI contract asset sections");
        count_contracts! { sections.len() => OPENAPI_CONTRACT_SECTION_ORDER.len(); }
        let mut indexed = Map::new();
        for (section, expected_id) in sections.iter().zip(OPENAPI_CONTRACT_SECTION_ORDER) {
            let section = section.as_object().expect("contract section object");
            set_contracts! { section.keys().map(String::as_str).collect::<BTreeSet<_>>() => contract_word_set("id values"); }
            let id = contract_text(section.get("id"), "section id");
            assert_eq!(id, *expected_id, "OpenAPI contract section order drift");
            let values = contract_array(section.get("values"), "contract section string inventory");
            assert!(
                !values.is_empty(),
                "contract section `{id}` must not be empty"
            );
            assert!(
                values
                    .iter()
                    .all(|value| value.as_str().is_some_and(|item| !item.is_empty())),
                "contract section `{id}` must contain only non-empty strings"
            );
            count_contracts! { values .iter() .filter_map(Value::as_str) .collect::<BTreeSet<_>>() .len() => values.len(); }
            assert!(
                indexed
                    .insert(id.to_owned(), Value::Array(values.clone()))
                    .is_none()
            );
        }
        indexed
    });
    LazyLock::force(&ASSET)
}
fn contract_strings(id: &str) -> Vec<&'static str> {
    contract_array(
        contract_asset().get(id),
        &format!("missing contract inventory `{id}`"),
    )
    .iter()
    .map(|value| value.as_str().expect("validated contract string"))
    .collect()
}
#[track_caller]
fn contract_schema<'a>(schemas: &'a Map, name: &str) -> &'a Map {
    contract_object(schemas.get(name), &format!("{name} schema"))
}
#[track_caller]
fn contract_property<'a>(schemas: &'a Map, owner: &str, property: &str) -> &'a Map {
    contract_object(
        contract_schema(schemas, owner)
            .get("properties")
            .and_then(Value::as_object)
            .and_then(|properties| properties.get(property)),
        &format!("{owner}.{property} schema"),
    )
}
fn parameters_in<'a>(parameters: &'a [Value], location: &str) -> Vec<&'a Value> {
    parameters
        .iter()
        .filter(|parameter| parameter.get("in").and_then(Value::as_str) == Some(location))
        .collect()
}
#[track_caller]
fn operation_parameters(operation: &Map) -> &Vec<Value> {
    contract_array(operation.get("parameters"), "operation parameters")
}
fn operation_parameter<'a>(operation: &'a Map, name: &str) -> &'a Value {
    operation_parameters(operation)
        .iter()
        .find(|parameter| parameter.get("name").and_then(Value::as_str) == Some(name))
        .unwrap_or_else(|| panic!("operation parameter `{name}`"))
}
#[track_caller]
fn parameter_schema(parameter: &Value) -> &Map {
    contract_object(parameter.get("schema"), "parameter schema")
}
#[track_caller]
fn operation_responses(operation: &Map) -> &Map {
    contract_object(operation.get("responses"), "operation responses")
}
#[track_caller]
fn response_content<'a>(operation: &'a Map, status: &str) -> &'a Map {
    contract_object(
        operation_responses(operation)
            .get(status)
            .and_then(Value::as_object)
            .and_then(|response| response.get("content")),
        &format!("HTTP {status} content"),
    )
}
#[track_caller]
fn request_content(operation: &Map) -> &Map {
    contract_object(
        operation
            .get("requestBody")
            .and_then(Value::as_object)
            .and_then(|body| body.get("content")),
        "request content",
    )
}
#[track_caller]
fn value_strings(value: &Value) -> Vec<&str> {
    contract_array(Some(value), "contract string array")
        .iter()
        .map(|entry| contract_text(Some(entry), "contract string entry"))
        .collect()
}
#[track_caller]
fn variant_property<'a>(variants: &'a [Value], index: usize, field: &str) -> &'a Map {
    contract_object(
        variants[index]
            .get("properties")
            .and_then(Value::as_object)
            .and_then(|properties| properties.get(field)),
        &format!("variant {index} property {field}"),
    )
}
#[track_caller]
fn assert_phrases(text: Option<&str>, phrases: &[&str]) {
    let text = text.expect("contract description string");
    for phrase in phrases {
        assert!(text.contains(phrase), "description omitted `{phrase}`");
    }
}
macro_rules! description_contracts {
    ($( $text:expr => $phrases:expr; )+) => { $(assert_phrases($text, $phrases);)+ };
}
#[track_caller]
fn assert_description_inventory(description: &str, inventory: &str) {
    assert_phrases(Some(description), &contract_strings(inventory));
}
fn assert_schema_shapes(schemas: &Map, contracts: &[SchemaShape]) {
    for contract in contracts {
        let required = contract_strings(contract.required);
        let optional = contract.optional.map(contract_strings).unwrap_or_default();
        assert_strict_object_schema(schemas, contract.name, &required, &optional);
    }
}
fn assert_property_refs(schemas: &Map, contracts: &[PropertyRefContract]) {
    for contract in contracts {
        text_contracts! { property_ref(schemas, contract.owner, contract.property) => contract.expected; }
    }
}
fn assert_operation_response_contracts(document: &Value, contracts: &[OperationResponseContract]) {
    for contract in contracts {
        let operation = openapi_operation(document, contract.path, contract.method);
        text_contracts! { operation_response_schema_ref(operation, contract.status, contract.path) => contract.schema_ref; }
    }
}
#[track_caller]
fn assert_required_inventory(schema: &Map, inventory: &str) {
    string_members! { contract_array(schema.get("required"), inventory); Present => &contract_strings(inventory); }
}
fn canonical_account_headers(required: bool) -> BTreeSet<(String, bool)> {
    canonical_account_header_requirements(required)
        .into_iter()
        .collect()
}
fn assert_canonical_header_set(operation: &Map) {
    set_contracts! { operation_header_requirements(operation).into_iter().collect::<BTreeSet<_>>() => canonical_account_headers(false); }
}
const CANONICAL_ACCOUNT_HEADER_NAMES: &str =
    "X-Iroha-Account X-Iroha-Signature X-Iroha-Timestamp-Ms X-Iroha-Nonce X-Iroha-Witness";
fn canonical_account_header_names() -> BTreeSet<&'static str> {
    contract_word_set(CANONICAL_ACCOUNT_HEADER_NAMES)
}
fn canonical_account_header_requirements(required: bool) -> Vec<(String, bool)> {
    contract_words(CANONICAL_ACCOUNT_HEADER_NAMES)
        .into_iter()
        .map(|name| (name.to_owned(), required))
        .collect()
}
fn assert_opaque_evidence_token(schema: &Map) {
    scalar_contracts! { schema.get("type") => Text("string"); schema.get("minLength") => Unsigned(1); schema.get("maxLength") => Unsigned(EVIDENCE_VIEWER_MAX_OPAQUE_TOKEN_BYTES_V1 as u64); schema.get("pattern") => Text("^[!-~]+$"); }
}
fn assert_nonzero_digest(schema: &Map) {
    scalar_contracts! { schema.get("type") => Text("string"); schema.get("minLength") => Unsigned(64); schema.get("maxLength") => Unsigned(64); schema.get("pattern") => Text("^(?!0{64}$)[0-9a-f]{64}$"); }
}
fn catalog_method_name(method: CatalogHttpMethod) -> &'static str {
    match method {
        CatalogHttpMethod::Get => "get",
        CatalogHttpMethod::Post => "post",
        CatalogHttpMethod::Put => "put",
        CatalogHttpMethod::Patch => "patch",
        CatalogHttpMethod::Delete => "delete",
        CatalogHttpMethod::Any => panic!("ANY gateway cannot enter this OpenAPI contract"),
    }
}
#[test]
fn evidence_audit_openapi_requires_and_returns_exact_cursors() {
    let document = generate_spec();
    let operation = openapi_operation(&document, "/v1/evidence/audit", "get");
    assert_description_inventory(
        contract_text(operation.get("description"), "evidence audit description"),
        "evidence.audit.description",
    );
    let parameters = operation_parameters(operation);
    count_contracts! { parameters.len() => 9; }
    let checkpoint = operation_parameter(operation, "expected_checkpoint_digest_hex");
    scalar_contracts! { checkpoint.get("required") => Flag(true); parameter_schema(checkpoint).get("pattern") => Text("^(?!0{64}$)[0-9a-f]{64}$"); }
    let after_sequence = operation_parameter(operation, "after_sequence");
    scalar_contracts! { parameter_schema(after_sequence).get("minimum") => Unsigned(1); }
    description_contracts! { after_sequence.get("description").and_then(Value::as_str) => &["together with after_receipt_digest_hex"]; }
    let after_digest = operation_parameter(operation, "after_receipt_digest_hex");
    let digest_schema = parameter_schema(after_digest);
    scalar_contracts! { digest_schema.get("minLength") => Unsigned(64); digest_schema.get("maxLength") => Unsigned(64); digest_schema.get("pattern") => Text("^(?!0{64}$)[0-9a-f]{64}$"); }
    description_contracts! { after_digest.get("description").and_then(Value::as_str) => &["together with after_sequence"]; }
    let limit = operation_parameter(operation, "limit");
    scalar_contracts! { limit.get("required") => Flag(true); parameter_schema(limit).get("minimum") => Unsigned(1); parameter_schema(limit).get("maximum") => Unsigned(256); }
    let auth_headers = parameters_in(parameters, "header")
        .into_iter()
        .filter_map(|parameter| parameter.get("name").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    set_contracts! { auth_headers => canonical_account_header_names(); }
    let success = contract_text(
        operation_responses(operation)
            .get("200")
            .and_then(Value::as_object)
            .and_then(|response| response.get("description")),
        "evidence audit success description",
    );
    assert_description_inventory(success, "evidence.audit.success");
    response_contracts!(&document;
        "/v1/evidence/audit", "get", "200", "#/components/schemas/SorafsEvidenceAuditProjectionV1";
        "/v1/evidence/status", "get", "200", "#/components/schemas/SorafsEvidenceAuditStatusV1";
    );
    let responses = operation_responses(operation);
    for status in contract_words("400 401 403 409 503") {
        member_contracts! { responses; Present => [status]; }
        text_contracts! { operation_response_schema_ref(operation, status, "/v1/evidence/audit") => "#/components/schemas/SorafsEvidenceApiErrorV1"; }
    }
    count_contracts! { operation_parameters(openapi_operation(&document, "/v1/evidence/status", "get")).len() => 5; }
    let schemas = component_schemas(&document);
    member_contracts! { schemas; Present => contract_strings("evidence.schemas"); }
}
#[test]
fn evidence_openapi_matches_authenticated_protocol_contract() {
    use iroha_torii_shared::route_catalog::AuthenticationPolicy;
    let document = generate_spec();
    let routes = RouteCatalog::new(CATALOGED_ROUTES)
        .project(
            CatalogProjection::OpenApi,
            crate::router::builder::compiled_route_features(),
        )
        .into_iter()
        .filter(|route| route.path().starts_with("/v1/evidence/"))
        .collect::<Vec<_>>();
    count_contracts! { routes.len() => 12; }
    for route in routes {
        let method = catalog_method_name(route.method());
        assert_eq!(
            route.authentication(),
            AuthenticationPolicy::CanonicalAccountSignature,
            "{method} {} catalog authentication policy",
            route.path()
        );
        let operation = openapi_operation(&document, route.path(), method);
        let auth = operation_header_requirements(operation)
            .into_iter()
            .filter(|(name, _)| name.starts_with("X-Iroha-"))
            .collect::<BTreeSet<_>>();
        set_contracts! { auth => canonical_account_headers(false); }
        let protocol = contract_rows! {
            "/v1/evidence/session/challenge", "post", "", "201", "X-SoraFS-Evidence-Challenge";
            "/v1/evidence/session", "post", "X-SoraFS-Evidence-Challenge", "201", "X-SoraFS-Evidence-Grant";
            "/v1/evidence/manifest/{session_id_hex}", "get", "X-SoraFS-Evidence-Grant", "200", "X-SoraFS-Evidence-Grant";
            "/v1/evidence/segment/{session_id_hex}", "get", "X-SoraFS-Evidence-Grant", "206", "X-SoraFS-Evidence-Grant X-SoraFS-Evidence-Receipt-Digest X-SoraFS-Evidence-Watermark-Digest";
            "/v1/evidence/log/{session_id_hex}", "post", "X-SoraFS-Evidence-Grant", "202", "X-SoraFS-Evidence-Grant";
            "/v1/evidence/legal-hold", "post", "", "201", "";
        };
        let (_, _, secret, status, response_headers) = protocol
            .into_iter()
            .find(|(path, verb, ..)| *path == route.path() && *verb == method)
            .unwrap_or_else(|| (route.path(), method, "", "200", ""));
        let secret = contract_word_set(secret);
        let expected_headers = contract_word_set(response_headers);
        let parameters = operation_parameters(operation);
        let actual_secret = parameters_in(parameters, "header")
            .into_iter()
            .filter_map(|parameter| parameter.get("name").and_then(Value::as_str))
            .filter(|name| name.starts_with("X-SoraFS-Evidence-"))
            .collect::<BTreeSet<_>>();
        set_contracts! { actual_secret => secret; }
        for name in secret {
            let parameter = operation_parameter(operation, name);
            scalar_contracts! { parameter.get("required") => Flag(true); }
            assert_opaque_evidence_token(parameter_schema(parameter));
        }
        let response = contract_object(
            operation_responses(operation).get(status),
            &format!("{method} {} {status} success response", route.path()),
        );
        let headers = response.get("headers").and_then(Value::as_object);
        let actual = headers
            .into_iter()
            .flat_map(|headers| headers.keys())
            .map(String::as_str)
            .filter(|name| name.starts_with("X-SoraFS-Evidence-"))
            .collect::<BTreeSet<_>>();
        set_contracts! { actual => expected_headers; }
        for name in expected_headers {
            let header = headers
                .and_then(|headers| headers.get(name))
                .and_then(Value::as_object)
                .unwrap_or_else(|| {
                    panic!("{method} {} {status} {name} response header", route.path())
                });
            scalar_contracts! { header.get("required") => Flag(true); }
            let schema = contract_object(header.get("schema"), "evidence response header schema");
            if matches!(
                name,
                "X-SoraFS-Evidence-Challenge" | "X-SoraFS-Evidence-Grant"
            ) {
                assert_opaque_evidence_token(schema);
            } else {
                scalar_contracts! { schema.get("$ref") => Text("#/components/schemas/SorafsEvidenceNonzeroHex32V1"); }
            }
        }
    }
    let manifest = openapi_operation(&document, "/v1/evidence/manifest/{session_id_hex}", "get");
    let queries = parameters_in(operation_parameters(manifest), "query");
    count_contracts! { queries.len() => 1; }
    scalar_contracts! { queries[0].get("name") => Text("idempotency_key_hex"); queries[0].get("required") => Flag(true); }
    assert_nonzero_digest(parameter_schema(queries[0]));
    let segment = openapi_operation(&document, "/v1/evidence/segment/{session_id_hex}", "get");
    let queries = parameters_in(operation_parameters(segment), "query");
    set_contracts! { queries .iter() .filter_map(|parameter| parameter.get("name").and_then(Value::as_str)) .collect::<BTreeSet<_>>() => contract_word_set("start end idempotency_key_hex"); }
    for name in contract_words("start end idempotency_key_hex") {
        scalar_contracts! { operation_parameter(segment, name).get("required") => Flag(true); }
    }
    for (name, minimum) in contract_rows! { "start", 0; "end", 1; } {
        let schema = parameter_schema(operation_parameter(segment, name));
        scalar_contracts! { schema.get("type") => Text("integer"); schema.get("format") => Text("uint64"); schema.get("minimum") => Unsigned(minimum); }
    }
    description_contracts! { operation_parameter(segment, "end").get("description").and_then(Value::as_str) => &["greater than start"]; }
    assert_nonzero_digest(parameter_schema(operation_parameter(
        segment,
        "idempotency_key_hex",
    )));
}
#[test]
fn sorafs_pin_register_openapi_is_caller_signed_transaction_transport() {
    let document = generate_spec();
    let operation = openapi_operation(&document, "/v1/sorafs/pin/register", "post");
    text_contracts! { operation_request_schema_ref(operation, "/v1/sorafs/pin/register") => "#/components/schemas/VersionedSignedTransactionJson"; operation_response_schema_ref(operation, "202", "/v1/sorafs/pin/register") => "#/components/schemas/SorafsPinRegisterResponseV1"; }
    let request = request_content(operation);
    set_contracts! { request.keys().map(String::as_str).collect::<BTreeSet<_>>() => contract_word_set("application/json application/x-norito"); }
    scalar_contracts! { request .get("application/x-norito") .and_then(|media| media.get("schema")) .and_then(|schema| schema.get("x-iroha-norito-schema")) => Text("SignedTransaction"); }
    sequence_contracts! { response_content(operation, "202") .keys() .map(String::as_str) .collect::<Vec<_>>() => contract_words("application/json"); }
    assert_description_inventory(
        contract_text(operation.get("description"), "pin-register description"),
        "pin.register.description",
    );
    let schemas = component_schemas(&document);
    member_contracts! { schemas; Absent => ["SorafsPinRegisterRequestV1"]; }
    inline_shapes! { schemas; "SorafsPinRegisterResponseV1", &contract_words("status tx_hash_hex manifest_digest_hex"), &[]; }
    member_contracts! { schemas; Absent => ["SorafsPinAliasV1"]; Absent => ["SorafsPinSuccessorDigestV1"]; }
}
#[test]
fn sorafs_storage_token_openapi_requires_operator_and_diagnostic_headers() {
    use iroha_torii_shared::route_catalog::AuthenticationPolicy;
    assert_eq!(
        iroha_torii_shared::route_catalog::sorafs::STORAGE_TOKEN.authentication(),
        AuthenticationPolicy::OperatorSignature
    );
    let document = generate_spec();
    let operation = openapi_operation(&document, "/v1/sorafs/storage/token", "post");
    let required = contract_words("X-Iroha-Operator-Nonce X-Iroha-Operator-Public-Key X-Iroha-Operator-Signature X-Iroha-Operator-Timestamp-Ms X-SoraFS-Client X-SoraFS-Nonce").into_iter().map(|name| (name.to_owned(), true)).collect::<BTreeSet<_>>();
    set_contracts! { operation_header_requirements(operation).into_iter().collect::<BTreeSet<_>>() => required; }
    let description = contract_text(operation.get("description"), "storage-token description");
    description_contracts! { Some(description) => &["listener-wide API-token enforcement is disabled", "client label is diagnostic"]; }
}
#[test]
fn sorafs_storage_and_inventory_openapi_matches_authenticated_catalog() {
    let document = generate_spec();
    let paths = contract_object(document.get("paths"), "OpenAPI paths");
    member_contracts! { paths; Absent => ["/v1/sorafs/storage/state"]; Absent => ["/v1/sorafs/storage/fetch"]; }
    for path in contract_words("/v1/sorafs/aliases /v1/sorafs/replication") {
        let operation = openapi_operation(&document, path, "get");
        assert_canonical_header_set(operation);
        scalar_contracts! { operation.get("security") => Length(2); }
        assert!(
            operation
                .get("x-iroha-canonical-auth-v1")
                .and_then(Value::as_object)
                .is_some(),
            "{path} canonical auth contract"
        );
    }
    let aliases = openapi_operation(&document, "/v1/sorafs/aliases", "get");
    text_contracts! { operation_response_schema_ref(aliases, "200", "aliases") => "#/components/schemas/SorafsAliasListResponseV1"; }
    let alias_queries = parameters_in(operation_parameters(aliases), "query")
        .into_iter()
        .filter_map(|parameter| parameter.get("name").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    set_contracts! { alias_queries => contract_word_set("limit offset namespace manifest_digest"); }
    let namespace = parameter_schema(operation_parameter(aliases, "namespace"));
    scalar_contracts! { namespace.get("minLength") => Unsigned(1); namespace.get("maxLength") => Unsigned(128); namespace.get("pattern") => Text("^[a-z0-9._-]+$"); }
    let schemas = component_schemas(&document);
    inline_shapes! { schemas; "SorafsAliasListResponseV1", &contract_words("attestation total_count returned_count offset limit aliases"), &[]; }
    assert_strict_object_schema(
        schemas,
        "SorafsAliasProjectionV1",
        &contract_words(concat!(
            "alias namespace name manifest_digest_hex bound_by bound_epoch expiry_epoch ",
            "proof_b64 cache_state status_label lineage cache_rotation_due ",
            "cache_age_seconds proof_generated_at_unix proof_expires_at_unix ",
            "policy_positive_ttl_secs policy_refresh_window_secs policy_hard_expiry_secs ",
            "policy_rotation_max_age_secs policy_successor_grace_secs ",
            "policy_governance_grace_secs cache_evaluation cache_decision cache_reasons"
        )),
        &contract_words("proof_expires_in_seconds"),
    );
    inline_shapes! { schemas;
        "SorafsAliasCacheEvaluationV1", &contract_words(concat!( "decision reasons ttl_expires_at ttl_expires_at_unix serve_until ", "serve_until_unix successor governance policy_successor_grace_secs ", "policy_governance_grace_secs" ))[..], &[];
        "SorafsAliasGovernanceAssessmentV1", &contract_words("ref_ids revoked frozen rotated flags effective_at_unix effective_at"), &[];
        "SorafsAliasGovernanceFlagsV1", &contract_words("revoked frozen rotated"), &[];
        "SorafsAliasLineageV1", &contract_words(concat!( "successor_of_hex head_hex depth_to_head is_head superseded_by ", "immediate_successor anomalies" )), &[];
        "SorafsAliasLineageSuccessorV1", &contract_words("digest_hex status approved_epoch approved_at status_timestamp_unix"), &[];
        "SorafsAliasSuccessorAssessmentV1", &contract_words( "exists head_hex approved approved_at approved_at_unix depth_to_head anomalies", ), &[];
    }
    scalar_contracts! { contract_schema(schemas, "SorafsAliasManifestStatusV1").get("oneOf") => Length(3); contract_schema(schemas, "SorafsAliasCacheReasonV1").get("enum") => Length(17); }
    property_refs!(schemas;
        "SorafsAliasListResponseV1", "attestation", "#/components/schemas/SorafsRegistryAttestationV1";
        "SorafsAliasProjectionV1", "manifest_digest_hex", "#/components/schemas/SorafsReplicationNonzeroHex32V1";
        "SorafsAliasProjectionV1", "lineage", "#/components/schemas/SorafsAliasLineageV1";
        "SorafsAliasProjectionV1", "cache_evaluation", "#/components/schemas/SorafsAliasCacheEvaluationV1";
    );
    let replication = openapi_operation(&document, "/v1/sorafs/replication", "get");
    let replication_queries = parameters_in(operation_parameters(replication), "query")
        .into_iter()
        .filter_map(|parameter| parameter.get("name").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    set_contracts! { replication_queries => contract_word_set("limit offset status manifest_digest"); }
    for (operation, context) in contract_rows! { aliases, "aliases"; replication, "replication"; } {
        let digest = parameter_schema(operation_parameter(operation, "manifest_digest"));
        assert_nonzero_digest(digest);
        for (name, allow_zero) in contract_rows! { "limit", false; "offset", true; } {
            let parameter = operation_parameter(operation, name);
            let canonical_decimal = contract_object(
                parameter.get("x-iroha-canonical-unsigned-decimal-v1"),
                &format!("{context} {name} canonical decimal contract"),
            );
            scalar_contracts! { canonical_decimal.get("allow_zero") => Flag(allow_zero); }
            for flag in contract_words("allow_leading_zero allow_percent_encoding allow_sign") {
                scalar_contracts! { canonical_decimal.get(flag) => Flag(false); }
            }
        }
    }
    let statuses = contract_array(
        parameter_schema(operation_parameter(replication, "status")).get("enum"),
        "replication status enum",
    )
    .iter()
    .filter_map(Value::as_str)
    .collect::<Vec<_>>();
    sequence_contracts! { statuses => contract_words("pending completed cancelled expired"); }
    for (path, expected) in contract_rows! { "/v1/sorafs/storage/car/{manifest_id}", &contract_words( "Range Sora-Dag-Scope X-SoraFS-Chunker X-SoraFS-Nonce X-SoraFS-Stream-Token", )[..]; "/v1/sorafs/storage/chunk/{manifest_id}/{chunk_digest}", &contract_words("X-SoraFS-Nonce X-SoraFS-Stream-Token")[..]; }
    {
        let headers = operation_header_requirements(openapi_operation(&document, path, "get"))
            .into_iter()
            .collect::<BTreeSet<_>>();
        for name in expected {
            assert!(
                headers.contains(&(name.to_string(), true)),
                "{path} must require {name}"
            );
        }
    }
    let car = openapi_operation(&document, "/v1/sorafs/storage/car/{manifest_id}", "get");
    let responses = operation_responses(car);
    member_contracts! { responses; Absent => ["200"]; }
    let partial_content = response_content(car, "206");
    member_contracts! { partial_content; Present => ["application/vnd.ipld.car"]; }
}
#[test]
fn sorafs_pin_list_openapi_is_finalized_bounded_keyset_readback() {
    const PATH: &str = "/v1/sorafs/pin";
    let document = generate_spec();
    let operation = openapi_operation(&document, PATH, "get");
    text_contracts! { operation_response_schema_ref(operation, "200", PATH) => "#/components/schemas/PinManifestPageV1"; }
    set_contracts! { response_content(operation, "200") .keys() .map(String::as_str) .collect::<BTreeSet<_>>() => contract_word_set("application/json application/x-norito"); }
    assert_description_inventory(
        contract_text(operation.get("description"), "pin-list description"),
        "pin.list.description",
    );
    let names = operation_parameters(operation)
        .iter()
        .filter_map(|parameter| parameter.get("name").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    set_contracts! { names => contract_word_set( "after_digest_hex expected_finalized_block_hash_hex expected_finalized_height limit max_bytes status" ); }
    assert!(!names.contains("offset"));
    let schemas = component_schemas(&document);
    inline_shapes! { schemas; "PinManifestPageV1", &contract_words("finalized_cursor charged_usage manifests has_more"), &contract_words("next_after_digest"); "PinManifestSummaryV1", &contract_words(concat!( "digest submitted_by submitted_epoch approved_epoch content_length ", "retention_epoch status" )), &contract_words("successor_of"); }
    inline_shapes! { schemas; "PinResourceUsage", &contract_words("manifest_count content_bytes"), &[]; }
    property_refs!(schemas;
        "PinManifestPageV1", "finalized_cursor", "#/components/schemas/PinManifestFinalizedCursorV1";
        "PinManifestPageV1", "charged_usage", "#/components/schemas/PinResourceUsage";
    );
}
#[test]
fn sorafs_pin_manifest_openapi_is_finalized_native_readback() {
    const PATH: &str = "/v1/sorafs/pin/{digest_hex}";
    let document = generate_spec();
    let operation = openapi_operation(&document, PATH, "get");
    text_contracts! { operation_response_schema_ref(operation, "200", PATH) => "#/components/schemas/PinManifestFinalizedRecordV1"; }
    assert_description_inventory(
        contract_text(operation.get("description"), "pin-manifest description"),
        "pin.manifest.description",
    );
    let parameters = operation_parameters(operation);
    count_contracts! { parameters.len() => 3; }
    let names = parameters
        .iter()
        .filter_map(|parameter| parameter.get("name").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    set_contracts! { names => contract_word_set("digest_hex expected_finalized_height expected_finalized_block_hash_hex"); }
    assert!(
        !names.contains("limit"),
        "the retired projection limit must not remain in the operation"
    );
    assert_nonzero_digest(parameter_schema(operation_parameter(
        operation,
        "digest_hex",
    )));
    let height = operation_parameter(operation, "expected_finalized_height");
    scalar_contracts! { height.get("in") => Text("query"); height.get("required") => Flag(false); parameter_schema(height).get("minimum") => Unsigned(1); }
    let block_hash = operation_parameter(operation, "expected_finalized_block_hash_hex");
    scalar_contracts! { block_hash.get("in") => Text("query"); block_hash.get("required") => Flag(false); }
    assert_nonzero_digest(parameter_schema(block_hash));
    let schemas = component_schemas(&document);
    inline_shapes! { schemas; "PinManifestFinalizedRecordV1", &contract_words("finalized_cursor manifest"), &[]; "PinManifestFinalizedCursorV1", &contract_words("height block_hash"), &[]; }
    inline_shapes! { schemas; "PinManifestRecord", &contract_words(concat!( "digest root_cid chunker chunk_digest_sha3_256 por_root content_length policy ", "submitted_by submitted_epoch approved_epoch alias metadata status ", "council_envelope_digest" )), &contract_words("successor_of retirement_reason pin_fee_payment"); }
    property_refs!(schemas;
        "PinManifestFinalizedRecordV1", "finalized_cursor", "#/components/schemas/PinManifestFinalizedCursorV1";
        "PinManifestFinalizedRecordV1", "manifest", "#/components/schemas/PinManifestRecord";
        "PinManifestRecord", "por_root", "#/components/schemas/PinManifestBytes32V1";
        "PinManifestRecord", "status", "#/components/schemas/PinStatus";
    );
    text_contracts! { nullable_property_ref(schemas, "PinManifestRecord", "alias") => "#/components/schemas/ManifestAliasBinding"; nullable_property_ref(schemas, "PinManifestRecord", "council_envelope_digest") => "#/components/schemas/PinManifestBytes32V1"; }
    let approved_epoch = contract_property(schemas, "PinManifestRecord", "approved_epoch");
    let approved_epoch_variants = contract_array(
        approved_epoch.get("oneOf"),
        "required nullable approval epoch schema",
    );
    assert!(approved_epoch_variants.iter().any(|variant| {
        variant.get("type").and_then(Value::as_str) == Some("integer")
            && variant.get("format").and_then(Value::as_str) == Some("uint64")
    }));
    assert!(
        approved_epoch_variants
            .iter()
            .any(|variant| { variant.get("type").and_then(Value::as_str) == Some("null") })
    );
    let content_length = contract_property(schemas, "PinManifestRecord", "content_length");
    scalar_contracts! { content_length.get("type") => Text("integer"); content_length.get("format") => Text("uint64"); }
    let response_properties = component_properties(schemas, "PinManifestFinalizedRecordV1");
    member_contracts! { response_properties; Absent => contract_strings("pin.manifest.retired"); }
    let bytes32 = contract_schema(schemas, "PinManifestBytes32V1");
    scalar_contracts! { bytes32.get("minItems") => Unsigned(32); bytes32.get("maxItems") => Unsigned(32); }
    let statuses = contract_array(
        contract_schema(schemas, "PinStatus").get("oneOf"),
        "native pin status variants",
    );
    let values = statuses
        .iter()
        .filter_map(|variant| {
            variant
                .get("properties")
                .and_then(|properties| properties.get("status"))
                .and_then(|status| status.get("const"))
                .and_then(Value::as_str)
        })
        .collect::<BTreeSet<_>>();
    set_contracts! { values => contract_word_set("Pending Approved Retired"); }
}
#[test]
fn sorafs_replication_openapi_is_a_strict_chain_authoritative_v1_projection() {
    const PATH: &str = "/v1/sorafs/replication";
    let document = generate_spec();
    let operation = openapi_operation(&document, PATH, "get");
    text_contracts! { operation_response_schema_ref(operation, "200", PATH) => "#/components/schemas/SorafsReplicationListResponseV1"; }
    assert_description_inventory(
        contract_text(operation.get("description"), "replication description"),
        "replication.description",
    );
    set_contracts! { operation_header_requirements(operation) .into_iter() .collect::<BTreeSet<_>>() => canonical_account_headers(false) .into_iter() .collect::<BTreeSet<_>>(); }
    let names = parameters_in(operation_parameters(operation), "query")
        .into_iter()
        .filter_map(|parameter| parameter.get("name").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    set_contracts! { names => contract_word_set("limit offset status manifest_digest"); }
    let status = parameter_schema(operation_parameter(operation, "status"));
    set_contracts! { value_strings(status.get("enum").expect("replication status enum")) .into_iter() .collect::<BTreeSet<_>>() => contract_word_set("pending completed cancelled expired"); }
    scalar_contracts! { parameter_schema(operation_parameter(operation, "manifest_digest")) .get("pattern") => Text("^(?!0{64}$)[0-9a-f]{64}$"); }
    let schemas = component_schemas(&document);
    inline_shapes! { schemas;
        "SorafsRegistryAttestationV1", &contract_words("block_height block_hash_hex chain_id")[..], &[];
        "SorafsReplicationAssignmentV1", &contract_words("provider_id_hex slice_gib lane"), &[];
        "SorafsReplicationSlaV1", &contract_words( "ingest_deadline_secs min_availability_percent_milli min_por_success_percent_milli", ), &[];
        "SorafsReplicationMetadataEntryV1", &contract_words("key value"), &[];
        "SorafsReplicationCanonicalOrderV1", &contract_words(concat!( "version order_id_hex manifest_cid_b64 manifest_digest_hex chunking_profile ", "target_replicas assignments issued_at deadline_at sla metadata" )), &[];
        "SorafsProviderIngestCompletionAuthorityV1", &contract_words("provider_owner completion_signer signer_policy"), &[];
        "SorafsProviderIngestFinalizedAnchorV1", &contract_words("height block_hash_hex"), &[];
        "SorafsReplicationCompletionV1", &contract_words(concat!( "provider_hex completed_by completion_epoch assignment_revision ", "completion_authority finalized_anchor" )), &[];
        "SorafsReplicationOrderProjectionV1", &contract_words(concat!( "order_id_hex manifest_digest_hex issued_by issued_epoch deadline_epoch status ", "canonical_order_b64 assignment_revision order provider_completions providers" )), &[];
        "SorafsReplicationListResponseV1", &contract_words( "attestation total_count returned_count offset limit replication_orders", ), &[];
    }
    property_refs!(schemas;
        "SorafsReplicationCompletionV1", "completion_authority", "#/components/schemas/SorafsProviderIngestCompletionAuthorityV1";
        "SorafsReplicationCompletionV1", "finalized_anchor", "#/components/schemas/SorafsProviderIngestFinalizedAnchorV1";
        "SorafsProviderIngestCompletionAuthorityV1", "signer_policy", "#/components/schemas/SorafsProviderIngestSignerPolicyV1";
        "SorafsReplicationOrderProjectionV1", "order", "#/components/schemas/SorafsReplicationCanonicalOrderV1";
        "SorafsReplicationOrderProjectionV1", "status", "#/components/schemas/SorafsReplicationOrderStatusV1";
    );
    let status_variants = contract_array(
        contract_schema(schemas, "SorafsReplicationOrderStatusV1").get("oneOf"),
        "replication lifecycle variants",
    );
    count_contracts! { status_variants.len() => 4; }
    assert!(status_variants.iter().all(|variant| {
        variant.get("additionalProperties").and_then(Value::as_bool) == Some(false)
    }));
    let state_variants = status_variants
        .iter()
        .filter_map(|variant| {
            variant
                .get("properties")
                .and_then(|properties| properties.get("state"))
                .and_then(|state| state.get("const"))
                .and_then(Value::as_str)
        })
        .collect::<BTreeSet<_>>();
    set_contracts! { state_variants => contract_word_set("pending completed cancelled expired"); status_variants[0] .get("properties") .and_then(Value::as_object) .expect("pending status properties") .keys() .map(String::as_str) .collect::<BTreeSet<_>>() => contract_word_set("state"); }
    assert!(status_variants[1..].iter().all(|variant| {
        variant
            .get("properties")
            .and_then(Value::as_object)
            .is_some_and(|properties| properties.contains_key("epoch"))
    }));
    let policies = contract_array(
        contract_schema(schemas, "SorafsProviderIngestSignerPolicyV1").get("oneOf"),
        "signer-policy variants",
    );
    count_contracts! { policies.len() => 2; }
    scalar_contracts! {
        variant_property(policies, 0, "revision").get("const") => Unsigned(1);
        variant_property(policies, 0, "predecessor_digest_hex").get("type") => Text("null");
        variant_property(policies, 1, "revision").get("minimum") => Unsigned(2);
        variant_property(policies, 1, "predecessor_digest_hex").get("$ref") => Text("#/components/schemas/SorafsReplicationNonzeroHex32V1");
        contract_property( schemas, "SorafsReplicationOrderProjectionV1", "provider_completions", ) .get("items") .and_then(|items| items.get("$ref")) => Text("#/components/schemas/SorafsReplicationCompletionV1");
        contract_property( schemas, "SorafsReplicationListResponseV1", "replication_orders", ) .get("items") .and_then(|items| items.get("$ref")) => Text("#/components/schemas/SorafsReplicationOrderProjectionV1");
        contract_property( schemas, "SorafsReplicationOrderProjectionV1", "canonical_order_b64", ) .get("maxLength") => Unsigned(349_528);
    }
}
#[test]
fn moderation_dead_letter_openapi_is_typed_bounded_and_dual_control() {
    let document = generate_spec();
    let schemas = component_schemas(&document);
    inline_shapes! { schemas;
        "SorafsModerationDeadLetterPrepareRequestV1", &contract_words("identity_hex kind action authorized_at_unix_ms")[..], &[];
        "SorafsModerationDeadLetterPrepareResponseV1", &contract_words("schema status resolution_norito_b64 signing_message_hex"), &[];
        "SorafsModerationDeadLetterApplyRequestV1", &contract_words("resolution_norito_b64 signature_hex"), &[];
        "SorafsModerationDeadLetterApplyResponseV1", &contract_words("schema status identity_hex kind action"), &[];
    }
    scalar_contracts! {
        contract_schema( schemas, "SorafsModerationDeadLetterResolutionNoritoBase64V1", ) .get("maxLength") => Unsigned( u64::try_from(SORAFS_MODERATION_DEAD_LETTER_RESOLUTION_MAX_BASE64_BYTES_V1) .expect("moderation resolution bound"), );
        contract_schema(schemas, "SorafsModerationDeadLetterKindV1").get("enum") => Length(3);
        contract_schema(schemas, "SorafsModerationDeadLetterResolutionActionV1").get("enum") => Length(2);
    }
    for (path, route, request_schema, response_schema, max_bytes) in contract_rows! {
        "/v1/sorafs/moderation/dead-letters/prepare", iroha_torii_shared::route_catalog::contracts_and_verification_keys::SORAFS_MODERATION_DEAD_LETTERS_PREPARE_POST, "#/components/schemas/SorafsModerationDeadLetterPrepareRequestV1", "#/components/schemas/SorafsModerationDeadLetterPrepareResponseV1", SORAFS_MODERATION_DEAD_LETTER_PREPARE_REQUEST_MAX_BYTES_V1;
        "/v1/sorafs/moderation/dead-letters/apply", iroha_torii_shared::route_catalog::contracts_and_verification_keys::SORAFS_MODERATION_DEAD_LETTERS_APPLY_POST, "#/components/schemas/SorafsModerationDeadLetterApplyRequestV1", "#/components/schemas/SorafsModerationDeadLetterApplyResponseV1", SORAFS_MODERATION_DEAD_LETTER_APPLY_REQUEST_MAX_BYTES_V1;
    } {
        assert!(catalog_openapi_route_enabled(CatalogHttpMethod::Post, path));
        let operation = openapi_operation(&document, path, "post");
        scalar_contracts! { operation.get("operationId") => Text(route.stable_route_id()); }
        text_contracts! { operation_request_schema_ref(operation, path) => request_schema; operation_response_schema_ref(operation, "200", path) => response_schema; }
        scalar_contracts! { operation.get("x-iroha-max-request-bytes") => Unsigned(u64::try_from(max_bytes).expect("moderation request bound")); }
        assert_canonical_header_set(operation);
        scalar_contracts! { operation.get("security") => Length(2); }
        description_contracts! { operation.get("description").and_then(Value::as_str) => &["independent"]; }
        let responses = operation_responses(operation);
        member_contracts! { responses; Present => contract_words("200 400 401 403 404 409 429 503"); }
    }
}
#[test]
fn hedging_billing_openapi_is_authenticated_bounded_and_private() {
    let document = generate_spec();
    for (path, method, catalog_method) in contract_rows! {
        "/v1/sorafs/billing/status", "get", CatalogHttpMethod::Get;
        "/v1/sorafs/billing/statements", "get", CatalogHttpMethod::Get;
        "/v1/sorafs/billing/statements/{statement_id}", "get", CatalogHttpMethod::Get;
        "/v1/sorafs/billing/statements/{statement_id}/acknowledgements", "post", CatalogHttpMethod::Post;
        "/v1/sorafs/billing/reconciliation", "get", CatalogHttpMethod::Get;
        "/v1/sorafs/hedging/exposure", "get", CatalogHttpMethod::Get;
        "/v1/sorafs/hedging/intents", "get", CatalogHttpMethod::Get;
    } {
        assert!(
            catalog_openapi_route_enabled(catalog_method, path),
            "{method} {path} catalog projection"
        );
        let operation = openapi_operation(&document, path, method);
        assert_canonical_header_set(operation);
        for (status, response) in operation_responses(operation) {
            let headers = contract_object(
                response.get("headers"),
                &format!("{method} {path} HTTP {status} private headers"),
            );
            for (name, expected) in contract_rows! {
                "Cache-Control", "private, no-store";
                "Vary", "X-Iroha-Account, X-Iroha-Signature, X-Iroha-Timestamp-Ms, X-Iroha-Nonce, X-Iroha-Witness";
            } {
                scalar_contracts! { headers.get(name).and_then(|header| header.get("schema")).and_then(|schema| schema.get("const")) => Text(expected); }
            }
        }
    }
    for path in contract_words(
        "/v1/sorafs/billing/statements /v1/sorafs/hedging/exposure /v1/sorafs/hedging/intents",
    ) {
        let operation = openapi_operation(&document, path, "get");
        let limit = operation_parameter(operation, "limit");
        scalar_contracts! { limit.get("required") => Flag(true); parameter_schema(limit).get("maximum") => Unsigned(100); operation_parameter(operation, "expected_checkpoint_fingerprint").get("required") => Flag(true); }
    }
    let statement = response_content(
        openapi_operation(
            &document,
            "/v1/sorafs/billing/statements/{statement_id}",
            "get",
        ),
        "200",
    );
    sequence_contracts! { statement.keys().map(String::as_str).collect::<Vec<_>>() => contract_words("application/x-norito"); }
    scalar_contracts! { statement .get("application/x-norito") .and_then(|media| media.get("schema")) .and_then(|schema| schema.get("x-iroha-norito-schema")) => Text("BillingPublishedStatementV1"); }
    let acknowledgement = request_content(openapi_operation(
        &document,
        "/v1/sorafs/billing/statements/{statement_id}/acknowledgements",
        "post",
    ));
    sequence_contracts! { acknowledgement .keys() .map(String::as_str) .collect::<Vec<_>>() => contract_words("application/x-norito"); }
    let schema = contract_object(
        acknowledgement
            .get("application/x-norito")
            .and_then(|media| media.get("schema")),
        "acknowledgement Norito schema",
    );
    scalar_contracts! { schema.get("x-iroha-norito-schema") => Text(BILLING_ACKNOWLEDGEMENT_PROOF_SCHEMA_NAME_V1); schema.get("x-iroha-norito-schema-hash") => Text(BILLING_ACKNOWLEDGEMENT_PROOF_SCHEMA_HASH_HEX_V1); schema.get("maxLength") => Unsigned(69_632); }
    let schemas = component_schemas(&document);
    let hedge = contract_schema(schemas, "HedgeIntentV1");
    let required = contract_array(hedge.get("required"), "hedge required");
    string_members! { required; Present => &["network_id"]; };
    string_members! { required; Absent => &["chain_id"]; };
    scalar_contracts! { contract_property(schemas, "HedgeIntentV1", "network_id").get("$ref") => Text("#/components/schemas/NetworkId"); }
    for (name, tag, expected) in contract_rows! {
        "HedgingBillingRetentionScopeV1", "scope", &contract_words("active_epoch_only")[..];
        "BillingStatementOwnerStatusV1", "status", &contract_words("published acknowledged");
        "HedgeIntentDirectionV1", "direction", &contract_words("sell_xor");
        "HedgeIntentDispositionV1", "disposition", &contract_words("executable governed_overflow");
    } {
        let actual = contract_array(contract_schema(schemas, name).get("oneOf"), "tagged enum")
            .iter()
            .filter_map(|variant| {
                variant
                    .get("properties")
                    .and_then(|properties| properties.get(tag))
                    .and_then(|tag| tag.get("const"))
                    .and_then(Value::as_str)
            })
            .collect::<BTreeSet<_>>();
        set_contracts! { actual => expected.iter().copied().collect::<BTreeSet<_>>(); }
    }
}
#[test]
fn proof_stream_openapi_matches_the_closed_canonical_envelope() {
    let document = generate_spec();
    let operation = openapi_operation(&document, "/v1/sorafs/proof/stream", "post");
    text_contracts! { operation_request_schema_ref(operation, "/v1/sorafs/proof/stream") => "#/components/schemas/SorafsProofStreamHttpRequestV1"; }
    let success = response_content(operation, "200");
    sequence_contracts! { success.keys().map(String::as_str).collect::<Vec<_>>() => contract_words("application/x-ndjson"); }
    scalar_contracts! { success .get("application/x-ndjson") .and_then(|media| media.get("x-iroha-ndjson-item-schema")) .and_then(|schema| schema.get("$ref")) => Text("#/components/schemas/SorafsProofStreamItemV1"); }
    let schemas = component_schemas(&document);
    assert!(
        document
            .get("paths")
            .and_then(Value::as_object)
            .and_then(|paths| paths.get("/v1/sorafs/storage/por-sample"))
            .is_none(),
        "retired local PoR route"
    );
    member_contracts! { schemas; Absent => ["SorafsStoragePorSampleRequestV1"]; }
    let variants = contract_array(
        contract_schema(schemas, "SorafsProofStreamHttpRequestV1").get("oneOf"),
        "proof request variants",
    )
    .iter()
    .map(|variant| contract_text(variant.get("$ref"), "proof request ref"))
    .collect::<Vec<_>>();
    sequence_contracts! { variants => contract_words(concat!( "#/components/schemas/SorafsProofStreamPorRequestV1 ", "#/components/schemas/SorafsProofStreamPdpRequestV1 ", "#/components/schemas/SorafsProofStreamPotrRequestV1" )); }
    for (name, kind, required_field, allowed, forbidden) in contract_rows! {
        "SorafsProofStreamPorRequestV1", "por", "sample_count", &contract_words("sample_count sample_seed")[..], &contract_words("challenge_id_hex deadline_ms orchestrator_job_id_hex")[..];
        "SorafsProofStreamPdpRequestV1", "pdp", "challenge_id_hex", &contract_words("challenge_id_hex")[..], &contract_words("sample_count sample_seed deadline_ms orchestrator_job_id_hex")[..];
        "SorafsProofStreamPotrRequestV1", "potr", "deadline_ms", &contract_words("deadline_ms orchestrator_job_id_hex")[..], &contract_words("challenge_id_hex sample_count sample_seed")[..];
    } {
        let schema = contract_schema(schemas, name);
        scalar_contracts! { schema.get("additionalProperties") => Flag(false); }
        let required = contract_array(schema.get("required"), "proof request required");
        string_members! { required; Present => &[required_field]; };
        if kind == "potr" {
            string_members! { required; Present => &["orchestrator_job_id_hex"]; };
        }
        let properties = contract_object(schema.get("properties"), "proof request properties");
        member_contracts! { properties; Present => contract_words("expected_finalized_height expected_finalized_block_hash_hex"); }
        if kind == "por" {
            for field in
                contract_words("expected_finalized_height expected_finalized_block_hash_hex")
            {
                string_members! { required; Present => &[field]; };
            }
        } else {
            let dependencies =
                contract_object(schema.get("dependentRequired"), "cursor dependencies");
            scalar_contracts! { dependencies .get("expected_finalized_height") .and_then(Value::as_array) .and_then(|fields| fields.first()) => Text("expected_finalized_block_hash_hex"); dependencies .get("expected_finalized_block_hash_hex") .and_then(Value::as_array) .and_then(|fields| fields.first()) => Text("expected_finalized_height"); }
        }
        scalar_contracts! { properties .get("proof_kind") .and_then(|kind| kind.get("const")) => Text(kind); }
        member_contracts! { properties; Present => allowed; Absent => forbidden; }
        scalar_contracts! {
            properties .get("nonce_b64") .and_then(|nonce| nonce.get("pattern")) => Text("^(?!A{22}==$)[A-Za-z0-9+/]{21}[AQgw]==$");
            properties .get("expected_finalized_height") .and_then(|height| height.get("minimum")) => Unsigned(1);
            properties .get("expected_finalized_block_hash_hex") .and_then(|hash| hash.get("pattern")) => Text("^(?!0{64}$)[0-9a-f]{64}$");
        }
    }
    scalar_contracts! { contract_property(schemas, "SorafsProofStreamPorRequestV1", "sample_count").get("maximum") => Unsigned(500); }
    let proof = contract_schema(schemas, "SorafsPorProofV1");
    scalar_contracts! { proof.get("additionalProperties") => Flag(false); }
    sequence_contracts! { value_strings(proof.get("required").expect("PoR required")) => contract_strings("proof.por.required"); }
    let properties = contract_object(proof.get("properties"), "PoR proof properties");
    for field in
        contract_words("chunk_digest_hex chunk_root_hex segment_digest_hex leaf_digest_hex")
    {
        scalar_contracts! { properties .get(field) .and_then(|schema| schema.get("pattern")) => Text("^[0-9a-f]{64}$"); }
    }
    let leaf = contract_object(properties.get("leaf_bytes_hex"), "leaf bytes schema");
    scalar_contracts! { leaf.get("pattern") => Text("^(?:[0-9a-f]{2})+$"); leaf.get("maxLength") => Unsigned(8_192); }
    for (field, maximum) in contract_rows! { "chunk_count", 4_194_304; "chunk_index", 4_194_303; "chunk_length", 4_194_304; "segment_index", 63; "segment_length", 65_536; "leaf_index", 15; "leaf_length", 4_096; }
    {
        scalar_contracts! { properties .get(field) .and_then(|schema| schema.get("maximum")) => Unsigned(maximum); }
    }
    for (field, maximum) in contract_rows! { "segment_leaves_hex", 16; "chunk_segments_hex", 64; } {
        let array = contract_object(properties.get(field), &format!("{field} schema"));
        scalar_contracts! { array.get("minItems") => Unsigned(1); array.get("maxItems") => Unsigned(maximum); array.get("items").and_then(|items| items.get("pattern")) => Text("^[0-9a-f]{64}$"); }
    }
    let chunk_path = contract_object(properties.get("chunk_merkle_path_hex"), "chunk path");
    scalar_contracts! { chunk_path.get("minItems") => Unsigned(0); chunk_path.get("maxItems") => Unsigned(22); }
    let item = contract_schema(schemas, "SorafsProofStreamItemV1");
    let item_properties = contract_object(item.get("properties"), "proof item properties");
    scalar_contracts! { item_properties .get("proof") .and_then(|proof| proof.get("$ref")) => Text("#/components/schemas/SorafsPorProofV1"); }
    for field in contract_words("deadline_ms recorded_at_ms") {
        scalar_contracts! { item_properties .get(field) .and_then(|schema| schema.get("minimum")) => Unsigned(1); }
    }
    let receipt = contract_object(item_properties.get("receipt_b64"), "PoTR receipt schema");
    scalar_contracts! { receipt.get("pattern") => Text("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"); }
    let validation = contract_object(
        receipt.get("x-iroha-runtime-validation"),
        "receipt validation",
    );
    scalar_contracts! { validation.get("requireByteIdenticalCanonicalReencode") => Flag(true); validation.get("requireValidatedReceipt") => Flag(true); }
    let kind_variants = contract_array(
        item.get("allOf")
            .and_then(Value::as_array)
            .and_then(|all| all.get(1))
            .and_then(|constraint| constraint.get("oneOf")),
        "proof-kind variants",
    );
    for (kind, inventory) in
        contract_rows! { "pdp", "proof.pdp.failures"; "potr", "proof.potr.failures"; }
    {
        let variant = kind_variants
            .iter()
            .find(|variant| {
                variant
                    .get("properties")
                    .and_then(|properties| properties.get("proof_kind"))
                    .and_then(|kind| kind.get("const"))
                    .and_then(Value::as_str)
                    == Some(kind)
            })
            .unwrap_or_else(|| panic!("{kind} variant"));
        let reasons = variant
            .get("properties")
            .and_then(|properties| properties.get("failure_reason"))
            .and_then(|reason| reason.get("enum"))
            .expect("failure reasons");
        sequence_contracts! { value_strings(reasons) => contract_strings(inventory); }
    }
}

#[test]
fn sorafs_account_storage_token_declares_exact_account_auth_and_explicit_policy() {
    use iroha_torii_shared::route_catalog::{AuthenticationPolicy, RouteEffect};
    let route = iroha_torii_shared::route_catalog::sorafs::STORAGE_ACCOUNT_TOKEN;
    assert_eq!(
        route.authentication(),
        AuthenticationPolicy::CanonicalAccountSignature
    );
    assert_eq!(route.effect(), RouteEffect::Mutation);
    assert!(route.requires_private_no_store());
    let document = generate_spec();
    let operation = openapi_operation(&document, "/v1/sorafs/storage/token/account", "post");
    let mut expected = canonical_account_headers(false);
    expected.insert(("X-SoraFS-Nonce".to_owned(), true));
    expected.insert(("X-SoraFS-Client".to_owned(), true));
    assert_eq!(
        operation_header_requirements(operation)
            .into_iter()
            .collect::<BTreeSet<_>>(),
        expected
    );
    assert!(
        operation_header_requirements(operation).contains(&("X-SoraFS-Nonce".to_owned(), true))
    );
    assert!(
        operation_header_requirements(operation).contains(&("X-SoraFS-Client".to_owned(), true))
    );
    let description = contract_text(
        operation.get("description"),
        "account storage-token description",
    );
    description_contracts! { Some(description) => &["registered_account_read", "current policy is rechecked", "canonical account"]; }
}
