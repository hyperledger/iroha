//! Smoke tests for the `koto` CLI against the shared IVM documentation examples.
use std::{fs, path::PathBuf, process::Command};

/// Kotodama sample sources shipped with the IVM documentation.
fn example(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../ivm/docs/examples")
        .join(name)
}

/// Cargo-provided scratch directory for integration-test outputs.
fn out_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
}

/// Private output directory for one test, so parallel builds never share sidecar custody.
fn build_dir(name: &str) -> PathBuf {
    let directory = out_dir().join(format!("cli_smoke_{name}"));
    fs::create_dir_all(&directory).expect("create test output directory");
    directory
}
#[test]
fn koto_build_meta_header_smoke() {
    // Path to the compiled CLI binary provided by Cargo.
    let bin = env!("CARGO_BIN_EXE_koto");
    let input = example("10_meta_header.ko");
    // Output into Cargo's integration-test scratch directory.
    let out = build_dir("meta").join("cli_smoke_meta.to");
    let status = Command::new(bin)
        .arg("build")
        .arg(input.as_os_str())
        .arg("--out")
        .arg(out.as_os_str())
        .arg("--max-cycles")
        .arg("2000")
        .status()
        .expect("spawn CLI");
    assert!(status.success(), "CLI did not exit successfully");
    let bytes = fs::read(&out).expect("read output .to");
    let parsed = ivm::ProgramMetadata::parse(&bytes).expect("parse header");
    let meta = parsed.metadata;
    assert_eq!(
        meta.version_minor, 1,
        "contract artifacts must emit IVM 1.1"
    );
    assert!(
        parsed.contract_interface.is_some(),
        "compiled contract must embed a CNTR section",
    );
    assert_eq!(meta.abi_version, 1);
    assert_eq!(meta.vector_length, 0);
    assert_eq!(meta.max_cycles, 2000);
    assert_eq!(meta.mode & ivm::ivm_mode::ZK, 0);
    assert_eq!(meta.mode & ivm::ivm_mode::VECTOR, 0);
}
#[test]
fn compile_tuple_return_minimal() {
    let src = "seiyaku Tuple { view fn pair(int a, int b) authorize(anyone) -> (int, int) { return (a, b); } }";
    let code = kotodama_lang::compiler::Compiler::new()
        .compile_source(src)
        .expect("compile tuple return");
    let parsed = ivm::ProgramMetadata::parse(&code).expect("parse compiled tuple contract");
    assert!(parsed.contract_interface.is_some());
}
#[test]
fn koto_build_manifest_out_smoke() {
    // Path to CLI binary and sample input
    let bin = env!("CARGO_BIN_EXE_koto");
    let input = example("10_meta_header.ko");
    // Output paths
    let out_to = build_dir("manifest").join("cli_smoke_manifest.to");
    let out_manifest = build_dir("manifest").join("cli_smoke_manifest.json");
    let status = std::process::Command::new(bin)
        .arg("build")
        .arg(input.as_os_str())
        .arg("--out")
        .arg(out_to.as_os_str())
        .arg("--manifest-out")
        .arg(out_manifest.as_os_str())
        .status()
        .expect("spawn CLI");
    assert!(status.success(), "CLI did not exit successfully");
    // Read and sanity-check manifest JSON
    let s = std::fs::read_to_string(&out_manifest).expect("read manifest json");
    assert!(s.contains("abi_hash"), "manifest JSON missing abi_hash");
    assert!(
        s.contains("compiler_fingerprint"),
        "manifest JSON missing compiler_fingerprint",
    );
}
#[test]
fn koto_build_manifest_out_stdout_smoke() {
    let bin = env!("CARGO_BIN_EXE_koto");
    let input = example("10_meta_header.ko");
    let out_to = build_dir("manifest_stdout").join("cli_smoke_manifest_stdout.to");
    let sibling_manifest =
        build_dir("manifest_stdout").join("cli_smoke_manifest_stdout.manifest.json");
    let _ = fs::remove_file(&sibling_manifest);
    let output = std::process::Command::new(bin)
        .arg("build")
        .arg(input.as_os_str())
        .arg("--out")
        .arg(out_to.as_os_str())
        .arg("--manifest-out")
        .arg("-")
        .output()
        .expect("spawn CLI");
    assert!(output.status.success(), "CLI did not exit successfully");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("abi_hash"), "stdout missing manifest JSON");
    assert!(
        stdout.contains("compiler_fingerprint"),
        "stdout missing compiler_fingerprint",
    );
    assert!(
        !sibling_manifest.exists(),
        "stdout mode must not publish an unexpected sibling manifest"
    );
}
#[test]
fn koto_build_verify_is_read_only_and_fails_on_tampering() {
    let bin = env!("CARGO_BIN_EXE_koto");
    let input = example("01_hajimari.ko");
    let target = build_dir("verify");
    let artifact = target.join("cli_smoke_verify.to");
    let manifest = target.join("cli_smoke_verify.manifest.json");
    let record = target
        .join(".fingerprints")
        .join("cli_smoke_verify.to.record");
    for path in [&artifact, &manifest, &record] {
        let _ = fs::remove_file(path);
    }
    let initial = Command::new(bin)
        .arg("build")
        .arg(&input)
        .arg("--out")
        .arg(&artifact)
        .status()
        .expect("spawn initial build");
    assert!(initial.success(), "initial build failed");
    let before = fs::metadata(&artifact)
        .expect("artifact metadata")
        .modified()
        .ok();
    let verified = Command::new(bin)
        .arg("build")
        .arg("--verify")
        .arg(&input)
        .arg("--out")
        .arg(&artifact)
        .status()
        .expect("spawn verify build");
    assert!(verified.success(), "current outputs must verify");
    assert_eq!(
        fs::metadata(&artifact)
            .expect("verified artifact metadata")
            .modified()
            .ok(),
        before,
        "verification must not rewrite a current output"
    );
    fs::write(&artifact, b"tampered").expect("tamper artifact");
    let rejected = Command::new(bin)
        .arg("build")
        .arg("--verify")
        .arg(&input)
        .arg("--out")
        .arg(&artifact)
        .status()
        .expect("spawn tamper verification");
    assert!(
        !rejected.success(),
        "tampered output must fail verification"
    );
    assert_eq!(
        fs::read(&artifact).expect("read tampered artifact"),
        b"tampered",
        "verification must never repair or otherwise mutate stale output"
    );
    for path in [&artifact, &manifest, &record] {
        let _ = fs::remove_file(path);
    }
}

/// A fresh package directory laid out like `musubi new`: `contracts/` plus `tests/`.
fn package(name: &str) -> PathBuf {
    let root = out_dir().join(format!("cli_smoke_package_{name}"));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("contracts")).expect("create contracts directory");
    fs::create_dir_all(root.join("tests")).expect("create tests directory");
    fs::write(
        root.join("contracts/counter.ko"),
        "seiyaku Counter { permission Bump; \n    state int value;\n    始まり() {\n        value = 1;\n    }\n    kotoage fn bump(int delta) authorize(Bump) -> int {\n        value = value + delta;\n        return value;\n    }\n    view fn current() authorize(anyone) -> int {\n        return value;\n    }\n}\n",
    )
    .expect("write contract");
    fs::write(
        root.join("tests/counter.test.ko"),
        "module CounterTests {\n    koto_test {\n        target: \"../contracts/counter.ko\"\n    }\n\n    fixture bumpers {\n        actor(\"alice\");\n        grant_seiyaku_permission(\"alice\", \"Bump\");\n        caller(\"alice\");\n        grant_seiyaku_lifecycle_permission(\"alice\", \"hajimari\");\n    }\n\n    #[test(fixture = \"bumpers\")]\n    fn bump_adds() {\n        test::invoke_kotoage(kotoage: \"hajimari\", arguments: {});\n        let next = test::invoke_kotoage_as(actor: \"alice\", kotoage: \"bump\", arguments: {delta: 2});\n        test::assert_eq(actual: next, expected: 3);\n    }\n\n    #[test(fixture = \"bumpers\")]\n    fn deliberately_wrong() {\n        test::invoke_kotoage(kotoage: \"hajimari\", arguments: {});\n        let next = test::invoke_kotoage_as(actor: \"alice\", kotoage: \"bump\", arguments: {delta: 2});\n        test::assert_eq(actual: next, expected: 4, message: \"bump returns the new value\");\n    }\n}\n",
    )
    .expect("write tests");
    root
}

fn koto(cwd: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_koto"))
        .current_dir(cwd)
        .args(args)
        .output()
        .expect("spawn koto")
}

#[test]
fn every_subcommand_answers_help_and_the_binary_reports_its_version() {
    let cwd = out_dir();
    for command in ["check", "build", "test", "fmt", "doc", "explain", "lsp"] {
        for flag in ["--help", "-h"] {
            let output = koto(&cwd, &[command, flag]);
            assert!(output.status.success(), "{command} {flag}");
            let help = String::from_utf8_lossy(&output.stdout);
            assert!(help.contains(&format!("Usage: koto {command}")), "{help}");
        }
    }
    let output = koto(&cwd, &["--version"]);
    assert!(output.status.success());
    let version = String::from_utf8_lossy(&output.stdout);
    assert!(version.contains("compiler: kotodama_lang/"), "{version}");
    assert!(version.contains("abi_hash: "), "{version}");
    let output = koto(&cwd, &["--help"]);
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("Exit status:"), "{help}");
}

#[test]
fn usage_errors_exit_two_with_the_subcommand_usage() {
    let output = koto(&out_dir(), &["build", "--frobnicate", "x.ko"]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Usage: koto build"), "{stderr}");
    let output = koto(&out_dir(), &["test", "--junit", "tests/x.test.ko"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "--junit takes the next argument as its path, so the source is missing"
    );
    let output = koto(&out_dir(), &["explain", "K9999"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("`K9999`"));
    // An unreadable source is an I/O failure for every subcommand, not a diagnostic.
    for command in ["check", "build", "test", "doc", "fmt"] {
        let output = koto(&out_dir(), &[command, "no_such_source.ko"]);
        assert_eq!(output.status.code(), Some(10), "koto {command}");
    }
    let output = koto(&out_dir(), &["lsp", "--source-root", "no_such_source_root"]);
    assert_eq!(
        output.status.code(),
        Some(10),
        "an unreadable language-server source root is an I/O failure: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = koto(&out_dir(), &["check", "--help"]);
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(
        help.contains(&format!(
            "[default: {}]",
            iroha_data_model::account::address::chain_discriminant()
        )),
        "--chain-discriminant states its default: {help}"
    );
}

#[test]
fn test_failures_exit_eleven_and_name_the_test_file_values_and_gas() {
    let root = package("tests");
    let junit = root.join("report.xml");
    let output = koto(
        &root,
        &[
            "test",
            "--junit",
            "report.xml",
            "--gas-report",
            "tests/counter.test.ko",
        ],
    );
    // Failing tests use musubi's test-failure status, distinct from compiler diagnostics (8).
    assert_eq!(output.status.code(), Some(11));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("ok  tests/counter.test.ko:14:8  bump_adds"),
        "{stdout}"
    );
    assert!(
        stdout.contains("FAILED  tests/counter.test.ko:21:8  deliberately_wrong"),
        "{stdout}"
    );
    assert!(
        stdout.contains(
            "assertion failed at tests/counter.test.ko:24:9: bump returns the new value\n  test::assert_eq(actual: next, expected: 4, message: \"bump returns the new value\")\n  actual:   3\n  expected: 4"
        ),
        "{stdout}"
    );
    assert!(
        !stdout.contains("assertion failed at contracts/counter.ko:"),
        "{stdout}"
    );
    assert!(stdout.contains("gas report"), "{stdout}");
    assert!(
        stdout
            .lines()
            .any(|line| line.trim_start().starts_with("bump ")),
        "{stdout}"
    );
    let report = fs::read_to_string(&junit).expect("JUnit report written to the requested path");
    assert!(
        report.contains("file=\"tests/counter.test.ko\" line=\"21\""),
        "{report}"
    );
    let output = koto(&root, &["test", "list", "tests/counter.test.ko"]);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "tests/counter.test.ko:14:8: bump_adds\ntests/counter.test.ko:21:8: deliberately_wrong\n"
    );
    let output = koto(
        &root,
        &[
            "test",
            "run",
            "--format",
            "json",
            "--filter",
            "bump_adds",
            "--exact",
            "tests/counter.test.ko",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = String::from_utf8_lossy(&output.stdout);
    assert!(
        json.contains("\"file\": \"tests/counter.test.ko\""),
        "{json}"
    );
    assert!(json.contains("\"gas\": "), "{json}");
}

#[test]
fn check_treats_test_modules_as_tests_and_fmt_walks_directories() {
    let root = package("check");
    let output = koto(
        &root,
        &["check", "tests/counter.test.ko", "contracts/counter.ko"],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("checked tests/counter.test.ko (test module for contracts/counter.ko; run `koto test tests/counter.test.ko`)"),
        "{stdout}"
    );
    fs::write(
        root.join("contracts/messy.ko"),
        "seiyaku Messy {   view fn one() authorize(anyone) -> int { return 1; }   }\n",
    )
    .expect("write unformatted source");
    let output = koto(&root, &["fmt", "--check", "."]);
    assert_eq!(output.status.code(), Some(8));
    assert!(String::from_utf8_lossy(&output.stdout).contains("would format contracts/messy.ko"));
    let output = koto(&root, &["fmt", "contracts"]);
    assert!(output.status.success());
    let output = koto(&root, &["fmt", "--check", "contracts"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn lint_levels_come_from_flags_and_the_project_manifest() {
    let root = package("lints");
    fs::write(
        root.join("contracts/linted.ko"),
        "seiyaku Linted {\n    view fn one() authorize(anyone) -> int {\n        let unused = 1;\n        return 1;\n    }\n}\n",
    )
    .expect("write linted source");
    let output = koto(&root, &["check", "contracts/linted.ko"]);
    assert!(output.status.success(), "lints warn by default");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("warning[K5013]"), "{stderr}");
    assert!(stderr.contains("--> contracts/linted.ko:3:13"), "{stderr}");
    let output = koto(&root, &["check", "--deny-warnings", "contracts/linted.ko"]);
    assert_eq!(output.status.code(), Some(8));
    assert!(String::from_utf8_lossy(&output.stderr).contains("error[K5013]"));
    let output = koto(
        &root,
        &["check", "--deny", "unused-local", "contracts/linted.ko"],
    );
    assert_eq!(output.status.code(), Some(8));
    let output = koto(
        &root,
        &["check", "--allow", "unused-local", "contracts/linted.ko"],
    );
    assert!(output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("K5013"));
    let output = koto(
        &root,
        &["check", "--deny", "unused-locl", "contracts/linted.ko"],
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("did you mean `unused-local`?"),
        "unknown lint names are usage errors with a suggestion"
    );
    let output = koto(
        &root,
        &[
            "check",
            "--allow",
            "unused-local",
            "--deny",
            "unused-local",
            "contracts/linted.ko",
        ],
    );
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn explain_and_doc_speak_kotodama() {
    let root = package("explain");
    let output = koto(&root, &["explain", "言挙げ"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("言挙げ (kotoage): "), "{stdout}");
    let output = koto(&root, &["explain", "--list"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("K2003") && stdout.contains("unused-parameter"));
    // The inline-test rejection explains where tests live, without compiler internals.
    let output = koto(&root, &["explain", "E_TEST_ONLY_PRODUCTION"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("koto_test { target:"), "{stdout}");
    assert!(stdout.contains("Fixed:"), "{stdout}");
    assert!(!stdout.contains("CompilerMode"), "{stdout}");
    let output = koto(&root, &["doc", "contracts/counter.ko"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let doc = String::from_utf8_lossy(&output.stdout);
    assert!(
        doc.contains("### `kotoage fn bump(int delta) authorize(Bump) -> int`"),
        "{doc}"
    );
    assert!(doc.contains("### `始まり()`"), "{doc}");
    assert!(doc.contains("Declared with `始まり`"), "{doc}");
    assert!(doc.contains("`{\"delta\": \"0\"}`"), "{doc}");
    assert!(!doc.contains("bump(delta: int)"), "{doc}");
}

#[test]
fn builtin_reference_requires_no_source_and_supports_machine_records() {
    let root = package("builtin-doc");
    let output = koto(&root, &["doc", "--builtins"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let markdown = String::from_utf8(output.stdout).expect("Markdown UTF-8");
    assert!(markdown.starts_with("# Kotodama builtin reference\n"));
    assert!(markdown.contains("## `ledger::asset::transfer`"));
    assert!(markdown.contains("`kotoage` / `言挙げ`"));
    let output = koto(&root, &["doc", "--builtins", "--format", "json"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let records: norito::json::Value =
        norito::json::from_slice(&output.stdout).expect("JSON reference");
    assert!(records["builtins"].as_array().unwrap().iter().any(|entry| {
        entry["source_path"].as_str() == Some("test::invoke_kotoage")
            && entry["availability"].as_str() == Some("test_function")
    }));
    for arguments in [
        vec!["doc"],
        vec!["doc", "--builtins", "contracts/counter.ko"],
        vec!["doc", "--builtins", "--source-root", "contracts"],
    ] {
        assert_eq!(koto(&root, &arguments).status.code(), Some(2));
    }
}

#[test]
fn private_witness_builds_warn_and_document_the_host_requirement() {
    let directory = build_dir("private_witness_requirements");
    let input = directory.join("prover.ko");
    fs::write(&input, "seiyaku Prover { fn witness() -> Secret<int> { crypto::private_input(0) } kotoage fn commitment() authorize(anyone) -> int { let value = witness(); crypto::valcom(left: value, right: value) } }").unwrap();
    let built = Command::new(env!("CARGO_BIN_EXE_koto"))
        .args(["build", "--zk", "--format", "json", "--out"])
        .arg(directory.join("prover.to"))
        .arg(&input)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let warning = String::from_utf8_lossy(&built.stderr);
    assert!(warning.contains("W_PROVER_PRIVATE_INPUT"));
    assert!(warning.contains("commitment"));
    for format in ["json", "markdown"] {
        let documented = Command::new(env!("CARGO_BIN_EXE_koto"))
            .args(["doc", "--zk", "--format", format])
            .arg(&input)
            .output()
            .unwrap();
        assert!(
            documented.status.success(),
            "{}",
            String::from_utf8_lossy(&documented.stderr)
        );
        let text = String::from_utf8_lossy(&documented.stdout);
        assert!(text.contains("commitment"));
        assert!(text.contains(if format == "json" {
            "\"requires_private_input_host\": true"
        } else {
            "Prover/test host required"
        }));
    }
}
