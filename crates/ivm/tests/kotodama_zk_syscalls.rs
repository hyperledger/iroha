//! Kotodama ZK-related builtin tests for the namespaced, typed V1 surface.
#[test]
fn raw_norito_and_opaque_submission_are_not_source_apis() {
    let diagnostics = kotodama_lang::session::CompilerSession::default()
        .build(kotodama_lang::session::CompileRequest {
            source: r#"
seiyaku RawSubmission { permission Submit;
  kotoage fn submit() authorize(Submit) {
    execute_instruction(norito_bytes(b"opaque"));
  }
}
"#,
            source_name: Some("raw_submission.ko"),
        })
        .expect_err("raw Norito construction and instruction submission must fail");
    assert!(diagnostics.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "E_INTERNAL_BUILTIN"
            || diagnostic.message.contains("execute_instruction")
    }));
}
