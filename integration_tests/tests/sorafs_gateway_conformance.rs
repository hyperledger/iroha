//! Tests for the `SoraFS` gateway conformance harness.
use integration_tests::{
    sorafs_gateway_capability_refusal,
    sorafs_gateway_conformance::{
        ScenarioOutcome, default_suite_report, generate_attestation, verify_attestation_envelope,
    },
};
use iroha_crypto::{Algorithm, KeyPair, Signature};
use iroha_data_model::account::AccountAddress;
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR};
use norito::json::Value;
use std::time::{Duration, UNIX_EPOCH};
#[test]
fn sorafs_gateway_conformance_suite_passes() {
    let report = default_suite_report();
    assert!(
        report.all_passed(),
        "expected canned conformance suite to pass for fixture-backed gateway simulation"
    );
}
#[test]
fn sorafs_gateway_suite_report_json_contains_expected_fields() {
    let report = default_suite_report();
    let value = report.to_json_value();
    assert!(
        value.get("profile_version").is_some(),
        "profile_version field should be present"
    );
    assert!(
        value.get("load_profile").is_some(),
        "load_profile field should be present"
    );
    assert!(
        value.get("load_report").is_some(),
        "load_report field should be present"
    );
    let scenarios = value
        .get("scenarios")
        .and_then(|v| v.as_array())
        .expect("scenarios array must be present");
    assert_eq!(
        scenarios.len(),
        report.scenario_count(),
        "scenario count mismatch between report and JSON"
    );
    let capability_fixture = sorafs_gateway_capability_refusal::load_scenarios()
        .expect("load capability refusal scenarios");
    let expected_c1 = capability_fixture
        .iter()
        .find(|scenario| scenario.id == "C1")
        .expect("C1 capability scenario present in fixtures");
    let capability_entry = scenarios
        .iter()
        .find(|scenario| {
            scenario
                .get("id")
                .and_then(Value::as_str)
                .is_some_and(|id| id == "C1")
        })
        .expect("capability scenario C1 present in suite JSON");
    let refusal = capability_entry
        .get("refusal")
        .and_then(Value::as_object)
        .expect("capability scenario JSON should include refusal payload");
    assert_eq!(
        refusal.get("status"),
        Some(&Value::from(u64::from(expected_c1.status))),
        "capability refusal JSON must include status matching fixture"
    );
    assert_eq!(
        refusal.get("error"),
        Some(&Value::from(expected_c1.error.clone())),
        "capability refusal JSON must include error code"
    );
    assert_eq!(
        refusal.get("reason"),
        Some(&Value::from(expected_c1.reason.clone())),
        "capability refusal JSON must include human-readable reason"
    );
    assert_eq!(
        refusal.get("details"),
        Some(&expected_c1.details),
        "capability refusal JSON must include details map"
    );
}
#[test]
fn sorafs_gateway_attestation_signature_verifies_and_rejects_wrong_key() {
    let report = default_suite_report();
    let signer = AccountAddress::from_account_id(&ALICE_ID).expect("Alice address encodes");
    let bundle = generate_attestation(
        &report,
        &ALICE_KEYPAIR,
        &signer,
        UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    )
    .expect("attestation generation succeeds");
    let envelope: Value =
        norito::json::from_slice(&bundle.envelope_bytes).expect("attestation envelope is JSON");
    let signature_hex = envelope
        .get("attestation")
        .and_then(Value::as_object)
        .and_then(|attestation| attestation.get("signature_hex"))
        .and_then(Value::as_str)
        .expect("attestation signature is present");
    let signature_bytes = hex::decode(signature_hex).expect("attestation signature is hex");
    let signature = Signature::try_from_bytes(&signature_bytes)
        .expect("generated attestation signature is non-empty and nonzero");
    signature
        .verify(ALICE_KEYPAIR.public_key(), &bundle.report_json)
        .expect("attestation signature verifies with Alice key");
    let verified =
        verify_attestation_envelope(&bundle.envelope_bytes).expect("attestation envelope verifies");
    assert_eq!(verified.profile_version, report.profile_version);
    assert_eq!(verified.scenario_count, report.scenario_count());
    assert_eq!(verified.algorithm, Algorithm::Ed25519);
    assert_eq!(verified.signer_account, signer.to_string());
    let wrong_key = KeyPair::try_from_seed(vec![0x5A; 32], Algorithm::Ed25519)
        .expect("derive SoraFS gateway wrong-key fixture");
    assert!(
        signature
            .verify(wrong_key.public_key(), &bundle.report_json)
            .is_err(),
        "attestation signature must reject a wrong key"
    );
}
#[test]
fn sorafs_gateway_attestation_verifier_rejects_report_tamper() {
    let report = default_suite_report();
    let signer = AccountAddress::from_account_id(&ALICE_ID).expect("Alice address encodes");
    let bundle = generate_attestation(
        &report,
        &ALICE_KEYPAIR,
        &signer,
        UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    )
    .expect("attestation generation succeeds");
    let mut envelope: Value =
        norito::json::from_slice(&bundle.envelope_bytes).expect("attestation envelope is JSON");
    envelope
        .as_object_mut()
        .and_then(|root| root.get_mut("report"))
        .and_then(Value::as_object_mut)
        .expect("report object")
        .insert("profile_version".into(), Value::from("sf1-tampered"));
    let tampered =
        norito::json::to_vec(&envelope).expect("serialize tampered attestation envelope");
    let err = verify_attestation_envelope(&tampered)
        .expect_err("tampered embedded report must fail attestation verification");
    assert!(
        err.to_string().contains("payload hash mismatch"),
        "unexpected error: {err}"
    );
}
#[test]
fn sorafs_gateway_attestation_verifier_rejects_all_zero_signature() {
    let report = default_suite_report();
    let signer = AccountAddress::from_account_id(&ALICE_ID).expect("Alice address encodes");
    let bundle = generate_attestation(
        &report,
        &ALICE_KEYPAIR,
        &signer,
        UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    )
    .expect("attestation generation succeeds");
    let mut envelope: Value =
        norito::json::from_slice(&bundle.envelope_bytes).expect("attestation envelope is JSON");
    envelope
        .as_object_mut()
        .and_then(|root| root.get_mut("attestation"))
        .and_then(Value::as_object_mut)
        .expect("attestation object")
        .insert("signature_hex".into(), Value::from("00".repeat(64)));
    let tampered =
        norito::json::to_vec(&envelope).expect("serialize tampered attestation envelope");
    let err = verify_attestation_envelope(&tampered)
        .expect_err("all-zero attestation signature must fail admission");
    assert!(
        err.to_string()
            .contains("invalid attestation signature material"),
        "unexpected error: {err}"
    );
}
#[test]
fn sorafs_gateway_unadmitted_provider_is_refused() {
    let report = default_suite_report();
    let scenario = report
        .scenario("B5")
        .expect("scenario B5 must be present in default harness");
    assert_eq!(scenario.expected_status, 412, "expected status mismatch");
    assert_eq!(scenario.observed_status, 412, "observed status mismatch");
    assert_eq!(
        scenario.observed_outcome,
        ScenarioOutcome::Refusal,
        "observed outcome mismatch"
    );
}
#[test]
fn sorafs_gateway_refusal_scenarios_match_expectations() {
    let report = default_suite_report();
    let expected = [
        ("A3", 416u16),
        ("B1", 406),
        ("B2", 428),
        ("B4", 422),
        ("B5", 412),
        ("B6", 429),
        ("C1", 406),
        ("C2", 412),
        ("C3", 412),
        ("C4", 428),
        ("C5", 428),
        ("C6", 406),
        ("C7", 422),
        ("D1", 451),
    ];
    for (id, status) in expected {
        let scenario = report
            .scenario(id)
            .unwrap_or_else(|| panic!("scenario {id} must be present in default harness"));
        assert_eq!(
            scenario.expected_outcome,
            ScenarioOutcome::Refusal,
            "expected outcome mismatch for scenario {id}"
        );
        assert_eq!(
            scenario.observed_outcome,
            ScenarioOutcome::Refusal,
            "observed outcome mismatch for scenario {id}"
        );
        assert_eq!(
            scenario.expected_status, status,
            "expected status mismatch for scenario {id}"
        );
        assert_eq!(
            scenario.observed_status, status,
            "observed status mismatch for scenario {id}"
        );
        assert!(
            scenario.passed(),
            "scenario {id} should be marked as passed after refusal validation"
        );
    }
}
#[test]
fn sorafs_gateway_capability_refusals_align_with_fixtures() {
    let report = default_suite_report();
    let scenarios = sorafs_gateway_capability_refusal::load_scenarios()
        .expect("load capability refusal scenarios");
    for scenario in scenarios {
        let entry = report.scenario(&scenario.id).unwrap_or_else(|| {
            panic!(
                "capability refusal scenario {} missing from suite",
                scenario.id
            )
        });
        assert_eq!(
            entry.expected_status, scenario.status,
            "expected status mismatch for capability scenario {}",
            scenario.id
        );
        assert_eq!(
            entry.observed_status, scenario.status,
            "observed status mismatch for capability scenario {}",
            scenario.id
        );
        assert_eq!(
            entry.expected_outcome,
            ScenarioOutcome::Refusal,
            "expected outcome should be refusal for capability scenario {}",
            scenario.id
        );
        assert_eq!(
            entry.observed_outcome,
            ScenarioOutcome::Refusal,
            "observed outcome should be refusal for capability scenario {}",
            scenario.id
        );
        let refusal = entry.refusal.as_ref().unwrap_or_else(|| {
            panic!(
                "capability scenario {} missing refusal payload",
                scenario.id
            )
        });
        assert_eq!(
            refusal.status, scenario.status,
            "refusal status mismatch for capability scenario {}",
            scenario.id
        );
        assert_eq!(
            refusal.error, scenario.error,
            "refusal error code mismatch for capability scenario {}",
            scenario.id
        );
        assert_eq!(
            refusal.reason, scenario.reason,
            "refusal reason mismatch for capability scenario {}",
            scenario.id
        );
        assert_eq!(
            refusal.details, scenario.details,
            "refusal details mismatch for capability scenario {}",
            scenario.id
        );
    }
}
