//! Public-session security diagnostics for Kotodama V1 `Secret<T>` flows.
use kotodama_lang::{
    compiler::{CompilerOptions, DEFAULT_MAX_CYCLES},
    diagnostic::{DiagnosticBundle, DiagnosticPhase, Severity},
    session::{CompileRequest, CompilerSession},
};
use norito::json::{self, Value};
const SOURCE_NAME: &str = "security/secret-flow.ko";
#[derive(Clone, Copy)]
struct RejectCase {
    name: &'static str,
    source: &'static str,
    code: &'static str,
    primary: &'static str,
}
include!(concat!(env!("OUT_DIR"), "/kotodama_secret_reject_cases.rs"));
fn zk_session() -> CompilerSession {
    CompilerSession::new(CompilerOptions {
        force_zk: true,
        max_cycles: DEFAULT_MAX_CYCLES,
        ..CompilerOptions::default()
    })
}
fn request(source: &str) -> CompileRequest<'_> {
    CompileRequest {
        source,
        source_name: Some(SOURCE_NAME),
    }
}
fn reject_with_check_and_build(case: RejectCase) -> DiagnosticBundle {
    let session = zk_session();
    let check = session
        .check(request(case.source))
        .expect_err("security-invalid source must fail `check`");
    let build = session
        .build(request(case.source))
        .expect_err("security-invalid source must fail `build`");
    assert_eq!(
        check, build,
        "{}: check/build diagnostics diverged",
        case.name
    );
    check
}
fn assert_rejection(case: RejectCase, bundle: &DiagnosticBundle) {
    assert_eq!(bundle.diagnostics.len(), 1, "{}: {bundle:?}", case.name);
    let diagnostic = &bundle.diagnostics[0];
    assert_eq!(diagnostic.code, case.code, "{}: {diagnostic:?}", case.name);
    assert_eq!(
        diagnostic.phase,
        DiagnosticPhase::Semantic,
        "{}: {diagnostic:?}",
        case.name
    );
    assert_eq!(diagnostic.severity, Severity::Error);
    assert!(
        !diagnostic.message.starts_with(case.code)
            && !diagnostic.message.starts_with(&format!("[{}]", case.code))
            && !diagnostic.message.contains(&format!("{}:", case.code)),
        "{}: diagnostic message embeds its stable code: {:?}",
        case.name,
        diagnostic.message
    );
    let span = diagnostic
        .primary_span
        .as_ref()
        .unwrap_or_else(|| panic!("{}: missing primary span: {diagnostic:?}", case.name));
    assert_eq!(span.source.as_deref(), Some(SOURCE_NAME), "{}", case.name);
    let range = span
        .byte_range
        .unwrap_or_else(|| panic!("{}: missing primary byte range", case.name));
    assert!(range.start < range.end, "{}: empty span", case.name);
    let start = usize::try_from(range.start).expect("source offset fits usize");
    let end = usize::try_from(range.end).expect("source offset fits usize");
    assert_eq!(
        &case.source[start..end],
        case.primary,
        "{}: primary span must identify the security-relevant construct",
        case.name
    );
    let expected_start = case
        .source
        .find(case.primary)
        .unwrap_or_else(|| panic!("{}: primary fixture text is absent", case.name));
    assert_eq!(
        (start, end),
        (expected_start, expected_start + case.primary.len()),
        "{}: primary span is not the exact intended occurrence",
        case.name
    );
}
#[test]
fn compiler_session_rejects_every_public_secret_flow_with_exact_diagnostics() {
    for case in REJECT_CASES.iter().copied() {
        let bundle = reject_with_check_and_build(case);
        assert_rejection(case, &bundle);
    }
}
#[test]
fn approved_all_secret_commitment_checks_and_builds() {
    let source = r#"seiyaku Privacy { permission UsePrivacy;
    hajimari() {}
    kaizen() {}
    kotoage fn commitment() authorize(UsePrivacy) -> int {
        let Secret<int> value = crypto::private_input(0);
        let Secret<int> blinding = crypto::private_input(1);
        return crypto::valcom(left: value, right: blinding);
    }
}"#;
    let session = zk_session();
    session
        .check(request(source))
        .expect("an all-secret approved commitment must pass `check`");
    let output = session
        .build(request(source))
        .expect("an all-secret approved commitment must produce a deployable artifact");
    assert!(!output.artifact.is_empty());
    assert_eq!(output.manifest.seiyaku_name.as_deref(), Some("Privacy"));
}
#[test]
fn human_json_and_sarif_preserve_the_same_secret_security_record() {
    let case = REJECT_CASES[0];
    let bundle = reject_with_check_and_build(case);
    assert_rejection(case, &bundle);
    let diagnostic = &bundle.diagnostics[0];
    let canonical = diagnostic.to_json_value();
    let rendered_json = bundle.render_json().expect("render JSON diagnostic");
    let json_value: Value = json::from_str(&rendered_json).expect("parse JSON diagnostic");
    assert_eq!(json_value[0], canonical);
    let rendered_sarif = bundle.render_sarif().expect("render SARIF diagnostic");
    let sarif_value: Value = json::from_str(&rendered_sarif).expect("parse SARIF diagnostic");
    assert_eq!(
        sarif_value["runs"][0]["results"][0]["properties"]["kotodama"],
        canonical
    );
    let human = bundle.render_human();
    assert!(human.contains(&format!("error[{}] semantic", diagnostic.code)));
    assert!(human.contains(&diagnostic.message));
    assert!(human.contains(SOURCE_NAME));
    let span = diagnostic
        .primary_span
        .as_ref()
        .expect("representative diagnostic has a location");
    assert!(
        span.byte_range.is_some(),
        "structured records keep exact bytes"
    );
    assert!(human.contains(&format!(
        "{SOURCE_NAME}:{}:{}",
        span.start.line, span.start.column
    )));
}
