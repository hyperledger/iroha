//! Presentation and controller refusals; these fixtures create no native publication evidence.

use super::*;
use norito::json;

fn release() -> MusubiReleaseIdV1 {
    MusubiReleaseIdV1::new(
        MusubiPackageIdV1::new(
            iroha_model_base::topology::DataSpaceId::new(0),
            iroha_data_model::musubi::MusubiPackageScopeV1::Domain("dev".parse().unwrap()),
            LIBRARY_NAME.parse().unwrap(),
        ),
        "1.0.0".parse().unwrap(),
    )
}
fn detached() -> CommandDocument {
    CommandDocument {
        exit_code: Some(0),
        value: json!({"schema":"musubi-cli-output","version":1,"command":"publish","ok":true,
            "data":{"status":"detached","operation_id":(hex::encode([1u8;32])),
                "release":"dev.universal/installed-library@1.0.0",
                "structural_release":(release().to_string()),"phase":"seed-ingress"}}),
    }
}
fn tracker() -> Progress {
    Progress::from_detached(
        &detached(),
        "dev.universal/installed-library@1.0.0",
        &release(),
    )
    .unwrap()
}
fn progress(operation: &str, phase: &str, message: &str) -> CommandDocument {
    CommandDocument {
        exit_code: Some(9),
        value: json!({"schema":"musubi-cli-output","version":1,"command":"publish","ok":false,
            "error":{"code":"MUSUBI_E_PUBLISH","message":message,
                "context":{"operation_id":operation,"phase":phase}}}),
    }
}

#[test]
fn detached_parser_binds_original_release_and_nonzero_canonical_operation() {
    let mut document = detached();
    assert!(Progress::from_detached(&document, "dev.universal/other@1.0.0", &release()).is_err());
    for operation in [hex::encode([0u8; 32]), "A".repeat(64), "1".repeat(63)] {
        *document
            .value
            .get_mut("data")
            .unwrap()
            .get_mut("operation_id")
            .unwrap() = Value::from(operation);
        assert!(
            Progress::from_detached(
                &document,
                "dev.universal/installed-library@1.0.0",
                &release()
            )
            .is_err()
        );
    }
    let mut document = detached();
    document.exit_code = Some(9);
    assert!(
        Progress::from_detached(
            &document,
            "dev.universal/installed-library@1.0.0",
            &release()
        )
        .is_err()
    );
}

#[test]
fn controller_resumes_only_same_operation_nondecreasing_closed_progress() {
    let mut selected = tracker();
    let operation = selected.operation.clone();
    for phase in ["SeedIngress", "Replication", "Replication", "Readback"] {
        assert!(
            selected
                .observe(&progress(&operation, phase, PROGRESS_MESSAGE))
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(selected.phase, 4);
    for phase in [
        "SeedIngress",
        "Validation",
        "Complete",
        "Serving",
        "readback",
        "Unknown",
    ] {
        assert!(
            selected
                .observe(&progress(&operation, phase, PROGRESS_MESSAGE))
                .is_err()
        );
        assert_eq!(selected.phase, 4);
    }
    assert!(
        selected
            .observe(&progress(
                &hex::encode([2u8; 32]),
                "FinalVerification",
                PROGRESS_MESSAGE
            ))
            .is_err()
    );
    assert_eq!(selected.operation, operation);
    assert_eq!(selected.phase, 4);
}

#[test]
fn nonprogress_errors_exit_mismatch_and_foreign_envelopes_are_terminal() {
    let mut selected = tracker();
    let operation = selected.operation.clone();
    for message in [
        "publication operation failed",
        "generated namespace preflight refused or remains pending",
        "permission denied",
    ] {
        assert!(
            selected
                .observe(&progress(&operation, "Replication", message))
                .is_err()
        );
    }
    for exit in [None, Some(0), Some(5), Some(70)] {
        let mut document = progress(&operation, "Replication", PROGRESS_MESSAGE);
        document.exit_code = exit;
        assert!(selected.observe(&document).is_err());
    }
    for (key, value) in [
        ("command", Value::from("deploy")),
        ("version", Value::from(2)),
        ("schema", Value::from("other")),
        ("ok", Value::from(true)),
    ] {
        let mut document = progress(&operation, "Replication", PROGRESS_MESSAGE);
        *document.value.get_mut(key).unwrap() = value;
        assert!(selected.observe(&document).is_err());
    }
    assert_eq!(selected.phase, 1);
}

#[test]
fn completion_parser_never_treats_detachment_or_missing_native_bindings_as_complete() {
    let mut selected = tracker();
    assert!(selected.observe(&detached()).is_err());
    let mut document = detached();
    *document
        .value
        .get_mut("data")
        .unwrap()
        .get_mut("status")
        .unwrap() = Value::from("complete");
    // Presentation selection alone is not native evidence: complete data must also contain
    // the exact real network/archive/finalized checkpoint and applied transaction fields.
    assert!(selected.observe(&document).unwrap().is_some());
    assert!(Completion::parse(&document.value["data"], "original-network").is_err());
    *document
        .value
        .get_mut("data")
        .unwrap()
        .get_mut("operation_id")
        .unwrap() = Value::from(hex::encode([2u8; 32]));
    assert!(selected.observe(&document).is_err());
    *document
        .value
        .get_mut("data")
        .unwrap()
        .get_mut("operation_id")
        .unwrap() = Value::from(hex::encode([1u8; 32]));
    *document
        .value
        .get_mut("data")
        .unwrap()
        .get_mut("structural_release")
        .unwrap() = Value::from("foreign");
    assert!(selected.observe(&document).is_err());
}

#[test]
fn diagnostic_reader_refuses_truncation_oversize_and_extra_documents() {
    let raw = norito::json::to_vec(&detached().value).unwrap();
    assert!(super::super::parse_command_output(&raw).is_ok());
    assert!(super::super::parse_command_output(&raw[..raw.len() - 1]).is_err());
    let mut joined = raw.clone();
    joined.extend_from_slice(&raw);
    assert!(super::super::parse_command_output(&joined).is_err());
    let mut oversized = raw;
    oversized.resize(super::super::MAX_OUTPUT as usize + 1, b' ');
    assert!(super::super::parse_command_output(&oversized).is_err());
}

#[test]
fn elapsed_publication_deadline_refuses_before_any_owned_subprocess_or_log() {
    let mut harness = Harness::new(&std::env::current_exe().unwrap()).unwrap();
    let result = harness.command_document(&["never-executed"], Instant::now(), true);
    assert!(matches!(
        result,
        Err(super::super::super::latency::Outcome::TimedOut)
    ));
    assert_eq!(harness.sequence, 0);
    assert!(!harness.root.path().join("1.stdout").exists());
    assert!(!harness.state.exists());
}

#[test]
fn consumer_fixture_uses_only_exact_registry_dependency_and_no_local_override() {
    let source: toml::Table = toml::from_str(&library_manifest("dev.universal")).unwrap();
    assert_eq!(source["lib"]["source-dir"].as_str(), Some("src"));
    assert_eq!(
        source["lib"]["exports"].as_array().unwrap(),
        &[toml::Value::from("value")]
    );
    let consumer: toml::Table = toml::from_str(&consumer_manifest("dev.universal")).unwrap();
    let dependency = consumer["dependencies"]["published"].as_table().unwrap();
    assert_eq!(dependency.len(), 2);
    assert_eq!(
        dependency["package"].as_str(),
        Some("dev.universal/installed-library")
    );
    assert_eq!(dependency["version"].as_str(), Some("=1.0.0"));
    assert!(!consumer.contains_key("workspace"));
    assert!(CONSUMER_SOURCE.contains("published::value()"));
}

#[test]
fn publication_fixture_sources_preserve_public_and_library_function_roles() {
    use kotodama_lang::ast::{FunctionKind, Item};

    let consumer = kotodama_lang::parser::parse(CONSUMER_SOURCE)
        .expect("parse the exact cold publication consumer offline");
    let quote = consumer
        .items
        .iter()
        .find_map(|item| match item {
            Item::Function(function) if function.name == "quote" => Some(function),
            _ => None,
        })
        .unwrap();
    assert_eq!(quote.modifiers.kind, FunctionKind::View);
    assert_eq!(quote.modifiers.authorization.as_deref(), Some("anyone"));

    // Module exports remain ordinary library functions, not public entrypoints.
    let library = kotodama_lang::parser::parse(LIBRARY_SOURCE)
        .expect("parse the exact publication library offline");
    let value = library
        .items
        .iter()
        .find_map(|item| match item {
            Item::Function(function) if function.name == "value" => Some(function),
            _ => None,
        })
        .unwrap();
    assert_eq!(value.modifiers.kind, FunctionKind::Private);
    assert!(value.modifiers.authorization.is_none());
    assert!(library.exports.iter().any(|export| export.name == "value"));
}
