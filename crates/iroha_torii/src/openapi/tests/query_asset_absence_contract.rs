// The documented absence contract matches the typed query error envelope.
#[test]
fn query_asset_absence_openapi_requires_the_exact_selector() {
    let document = canonical_document();
    let schemas = component_schemas(&document);
    let details = component_properties(schemas, "ErrorDetails");
    let selector = &details["query_asset_not_found"];
    assert_eq!(selector.get("type").and_then(Value::as_str), Some("string"));
    let operation = openapi_operation(&document, "/v1/query", "post");
    let missing = &operation["responses"]["404"];
    for media in ["application/json", "application/x-norito"] {
        assert_eq!(
            missing["content"][media].get("schema"),
            Some(&schema_ref("ErrorEnvelope"))
        );
    }
    let description = missing["description"].as_str().expect("absence contract");
    for required in [
        "query_asset_not_found",
        "details.query_asset_not_found",
        "exact requested AssetId",
        "Every selected dataspace route",
        "unavailable routes remain errors",
        "404 alone",
    ] {
        assert!(
            description.contains(required),
            "missing contract: {required}"
        );
    }
}

#[test]
fn query_settlement_receipt_absence_openapi_requires_the_exact_selector() {
    let document = canonical_document();
    let schemas = component_schemas(&document);
    let details = component_properties(schemas, "ErrorDetails");
    let selector = &details["query_settlement_receipt_not_found"];
    assert_eq!(selector["type"].as_str(), Some("object"));
    assert_eq!(selector["additionalProperties"].as_bool(), Some(false));
    assert_eq!(
        selector["properties"]["owner"]["type"].as_str(),
        Some("string")
    );
    assert_eq!(
        selector["properties"]["reference"]["type"].as_str(),
        Some("string")
    );
    let required = selector["required"]
        .as_array()
        .expect("complete settlement identity");
    assert_eq!(required.len(), 2);
    for field in ["owner", "reference"] {
        assert!(required.iter().any(|value| value.as_str() == Some(field)));
    }
    let operation = openapi_operation(&document, "/v1/query", "post");
    let description = operation["responses"]["404"]["description"]
        .as_str()
        .unwrap();
    for required in [
        "query_settlement_receipt_not_found",
        "details.query_settlement_receipt_not_found",
        "non-execution",
    ] {
        assert!(
            description.contains(required),
            "missing receipt absence contract: {required}"
        );
    }
}
