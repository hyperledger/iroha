//! Tests covering the `SoraFS` gateway capability refusal fixture bundle.
use integration_tests::sorafs_gateway_capability_refusal::{load_responses, load_scenarios};
use norito::json::Value;
use std::collections::{HashMap, HashSet};
#[test]
fn capability_refusal_scenarios_match_expected_ids() {
    let scenarios = load_scenarios().expect("load capability refusal scenarios");
    assert_eq!(
        scenarios.len(),
        7,
        "capability refusal fixture must contain seven scenarios"
    );
    let mut ids: HashSet<String> = HashSet::new();
    for scenario in scenarios {
        assert!(
            ids.insert(scenario.id.clone()),
            "duplicate scenario id detected: {}",
            scenario.id
        );
        assert!(
            scenario.request_fixture.is_some(),
            "scenario {} must declare a request fixture",
            scenario.id
        );
        assert!(
            scenario.response_fixture.is_some(),
            "scenario {} must declare a response fixture",
            scenario.id
        );
        assert!(
            scenario.gateway_fixture.is_some(),
            "scenario {} must declare a gateway fixture",
            scenario.id
        );
        let request_obj = scenario
            .request
            .as_ref()
            .and_then(Value::as_object)
            .cloned()
            .expect("scenario request fixture must parse as an object");
        assert!(
            request_obj.contains_key("method"),
            "scenario {} request fixture must include `method`",
            scenario.id
        );
        assert!(
            scenario
                .response
                .as_ref()
                .and_then(Value::as_object)
                .is_some(),
            "scenario {} response fixture must parse as an object",
            scenario.id
        );
        assert!(
            scenario
                .gateway
                .as_ref()
                .and_then(Value::as_object)
                .is_some(),
            "scenario {} gateway fixture must parse as an object",
            scenario.id
        );
    }
}
#[test]
fn capability_refusal_responses_have_expected_shape() {
    let responses = load_responses().expect("load capability refusal responses");
    let mut status_by_error: HashMap<String, u16> = HashMap::new();
    for response in responses {
        let body = response
            .body
            .as_object()
            .expect("capability refusal response must be an object")
            .clone();
        let error = body
            .get("error")
            .and_then(|value| value.as_str())
            .expect("capability refusal response must contain `error` field")
            .to_string();
        let reason = body
            .get("reason")
            .and_then(|value| value.as_str())
            .expect("capability refusal response must contain `reason` field");
        assert!(
            !reason.trim().is_empty(),
            "capability refusal response reason must not be empty"
        );
        let details = body
            .get("details")
            .and_then(|value| value.as_object())
            .expect("capability refusal response must contain `details` object");
        assert!(
            !details.is_empty(),
            "capability refusal response details must expose at least one field"
        );
        assert!(
            response
                .request
                .as_ref()
                .and_then(Value::as_object)
                .is_some(),
            "capability refusal response must carry request metadata"
        );
        assert!(
            response
                .gateway
                .as_ref()
                .and_then(Value::as_object)
                .is_some(),
            "capability refusal response must carry gateway metadata"
        );
        status_by_error.insert(error, response.status);
    }
    let expected = HashMap::from([
        ("unsupported_chunker".to_string(), 406),
        ("manifest_variant_missing".to_string(), 412),
        ("admission_mismatch".to_string(), 412),
        ("unsupported_capability".to_string(), 428),
        ("missing_header".to_string(), 428),
        ("unsupported_encoding".to_string(), 406),
        ("proof_mismatch".to_string(), 422),
    ]);
    assert_eq!(
        status_by_error, expected,
        "capability refusal responses must match the canonical matrix"
    );
}
