// Test body included from the parent module to keep its production source budget bounded.
use super::*;
use iroha_primitives::numeric_abi::IntValueV1;
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
static TEMP_DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);
/// Fixture environment with no constants and the default chain discriminant.
fn fixture_environment() -> FixtureEnvironment<'static> {
    static NO_CONSTS: std::sync::LazyLock<HashMap<String, Expr>> =
        std::sync::LazyLock::new(HashMap::new);
    FixtureEnvironment {
        artifacts: empty_fixture_artifacts(),
        source_name: None,
        consts: &NO_CONSTS,
        chain_discriminant: iroha_data_model::account::address::chain_discriminant(),
    }
}
fn empty_fixture_artifacts() -> &'static BTreeMap<String, ivm::PreparedContract> {
    static EMPTY: std::sync::LazyLock<BTreeMap<String, ivm::PreparedContract>> =
        std::sync::LazyLock::new(BTreeMap::new);
    &EMPTY
}
fn decode_i64_word(vm: &IVM, pointer: u64) -> i64 {
    let tlv = vm.validate_tlv(pointer).expect("validate returned int TLV");
    assert_eq!(tlv.type_id, PointerType::Int);
    IntValueV1::decode_frame(tlv.payload)
        .expect("decode returned int frame")
        .into_int()
        .try_to_i64()
        .expect("test result fits i64")
}
fn decode_pointer_state_value(payload: &[u8], kind: StateValueKindV1) -> Vec<u8> {
    let schema = StateValueSchemaV1 {
        nodes: vec![StateValueNodeV1::Leaf(kind)],
    };
    let schema_bytes = norito::encode_canonical(&schema).expect("encode canonical state schema");
    let record: StateValueRecordV1 =
        norito::decode_canonical(payload).expect("decode canonical state record");
    assert_eq!(
        record.schema_hash,
        state_value_schema_hash_v1(&schema_bytes)
    );
    assert!(schema.validate_atoms(&record.atoms));
    let [StateValueAtomV1::Pointer(envelope)] = record.atoms.as_slice() else {
        panic!("state record must contain one pointer atom");
    };
    envelope.clone()
}
fn decode_int_state_value(payload: &[u8]) -> i64 {
    let envelope = decode_pointer_state_value(payload, StateValueKindV1::Int);
    ivm::numeric_tlv::decode_int_bytes(&envelope)
        .expect("decode canonical state int")
        .try_to_i64()
        .expect("test state int fits i64")
}
struct TestTempDir {
    path: PathBuf,
}
impl TestTempDir {
    fn new() -> Self {
        let nonce = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "koto_test_bin_{}_{}_{}",
            std::process::id(),
            timestamp,
            nonce
        ));
        fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }
    fn write(&self, relative: &str, contents: &str) -> PathBuf {
        let path = self.path.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent dir");
        }
        fs::write(&path, contents).expect("write temp file");
        path
    }
}
impl Drop for TestTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
fn test_function(name: &str, fixture: Option<&str>) -> Item {
    Item::Function(kotodama_lang::ast::Function {
        name: name.to_string(),
        params: Vec::new(),
        ret_ty: None,
        body: kotodama_lang::ast::Block {
            statements: Vec::new(),
            tail: None,
        },
        modifiers: kotodama_lang::ast::FunctionModifiers {
            is_test: true,
            test_fixture: fixture.map(str::to_string),
            ..Default::default()
        },
        location: kotodama_lang::ast::SourceLocation { line: 1, column: 1 },
    })
}
fn compiled_suite_with_fixtures(fixtures: Vec<FixtureDecl>) -> CompiledSuite {
    let target_source = "seiyaku FixtureDemo { fn helper() {} #[test] fn smoke() {} }";
    let target_program = parser::parse(target_source).expect("parse fixture test target");
    let suite = DiscoveredSuite {
        artifacts: Vec::new(),
        sources: Vec::new(),
        source_root: None,
        target_path: PathBuf::from("/tmp/fixture_demo.ko"),
        target_source: target_source.to_owned(),
        target_program,
        test_modules: Vec::new(),
        tests: vec![TestCase {
            name: "smoke".to_string(),
            fixture: None,
            path: PathBuf::from("demo.test.ko"),
            line: 1,
            column: 1,
        }],
        fixtures: build_fixture_map(&fixtures).expect("build fixture map"),
        fixture_sites: HashMap::new(),
        fixture_consts: HashMap::new(),
    };
    compile_suite(&suite, false).expect("compile fixture suite")
}
#[test]
fn pure_unit_test_suite_executes_without_runtime_artifact() {
    let compiled = compiled_suite_with_fixtures(Vec::new());
    assert!(compiled.runtime.is_none());
    assert!(compiled.runtime_entrypoints.is_empty());
    let results = execute_suite(&compiled, TraceMode::Off, 1)
        .expect("execute a suite containing only private helpers and tests");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "smoke");
    assert!(
        results[0].passed,
        "unexpected failure: {:?}",
        results[0].failure
    );
    assert!(results[0].calls.is_empty());
    assert!(
        results[0].own_gas > 0,
        "a pure unit test is charged for its own execution"
    );
    assert_eq!(results[0].gas(), results[0].own_gas);
}
#[test]
fn coverage_lists_every_declared_function_including_those_without_code() {
    let temp = TestTempDir::new();
    let path = temp.write(
        "classify.ko",
        r#"seiyaku Classify {
    fn classify(int x) -> int {
        if x < 0 {
            return 0;
        }
        return 1;
    }
    fn never_called(int x) -> int {
        if x > 5 {
            return x * 3;
        }
        return x;
    }
    #[test]
    fn classifies() {
        test::assert_eq(actual: classify(x: -1), expected: 0);
    }
}
"#,
    );
    let suite = discover_suite(&path).expect("discover");
    let compiled = compile_suite(&suite, false).expect("compile");
    let results = execute_suite(&compiled, TraceMode::PcOnly, 1).expect("execute");
    let report = render_coverage_report(&compiled, &results);
    // Whatever the compiler inlines or omits, every declared non-test function has a row, and a
    // function without code of its own is never reported as covered.
    for function in ["classify", "never_called"] {
        let row = report
            .lines()
            .find(|line| line.contains(&format!("  {function}")))
            .unwrap_or_else(|| panic!("{function} row:\n{report}"));
        if row.trim_start().starts_with('-') {
            assert!(row.ends_with("(no code of its own: inlined into its callers or unused)"));
        }
    }
    assert!(
        !report.contains("  classifies"),
        "tests are not coverage targets:\n{report}"
    );
    let codeless = codeless_functions(
        &suite.target_program,
        &[CoverageFunction {
            display_name: "classify".to_owned(),
            line: 2,
            pc_start: 0,
            pc_end: 4,
        }],
    );
    assert_eq!(
        codeless,
        vec![CodelessFunction {
            display_name: "never_called".to_owned(),
            line: 8,
        }]
    );
}
#[test]
fn helper_preserves_u64_max_json_int_through_option_match() {
    let temp = TestTempDir::new();
    let target = temp.write(
        "u64_max_option_match.ko",
        include_str!("../fixtures/koto_v1/koto_test_driver_tests/001.ko")
            .strip_suffix('\n')
            .expect("fixture sentinel newline"),
    );
    let suite = discover_suite(&target).expect("discover u64 max regression suite");
    let compiled = compile_suite(&suite, false).expect("compile u64 max regression suite");
    let results =
        execute_suite(&compiled, TraceMode::Off, 1).expect("execute u64 max regression suite");
    assert_eq!(results.len(), 1);
    assert!(
        results[0].passed,
        "unexpected failure: {:?}",
        results[0].failure
    );
}
#[test]
fn compiler_owned_test_callables_preserve_artifact_verification() {
    let compiled = compiled_suite_with_fixtures(Vec::new());
    let suite_program = compiled.suite.program.prepared().artifact();
    assert_eq!(
        compiled.suite.program.prepared().code_hash(),
        compiled.suite.report.artifact_hash
    );
    let interface = compiled.suite.program.prepared().contract_interface();
    for test in &compiled.tests {
        let parsed = ProgramMetadata::parse(suite_program).unwrap();
        let relative = test.pc - parsed.prefix_len() as u64;
        let callable = interface
            .callables
            .iter()
            .find(|callable| callable.entry_pc == relative)
            .expect("each private test root has an authenticated callable descriptor");
        assert_eq!(callable.arguments, ivm_abi::call::CallSchemaV1::empty());
        assert_eq!(callable.results, ivm_abi::call::CallSchemaV1::unit());
    }
    let mut vm = IVM::new(u64::MAX);
    vm.load_koto_test_harness(&compiled.suite.program)
        .expect("authenticated test artifact loads");
    let error =
        ivm::prepare_contract(Arc::from(suite_program)).expect_err("test image cannot deploy");
    assert!(error.to_string().contains("missing required CNTR section"));
    let mut invalid_interface = interface.clone();
    invalid_interface.callables[0].frame_bytes |= 1;
    assert!(
        ivm::prepare_koto_test_contract(Arc::from(suite_program), invalid_interface).is_err(),
        "malformed test callable frame must fail admission"
    );
    let mut modified = suite_program.to_vec();
    modified.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
    let changed = ivm::prepare_koto_test_contract(Arc::from(modified), interface.clone())
        .expect("an unreachable generic opcode does not bypass hash identity");
    assert_ne!(
        changed.prepared().code_hash(),
        compiled.suite.report.artifact_hash,
        "every post-compile executable mutation changes the compiler-authenticated identity"
    );
}

#[test]
fn test_runner_uses_exact_taira_chain_discriminant() {
    const TAIRA_RECIPIENT: &str =
        "testﾜヰ8ｽuimdh9FﾂｦUｸﾈbﾕﾆヱMUYｴGｷﾙｹﾐRヱbﾐｷwﾄ6ﾃdDLPQﾋW496uﾙﾜFpﾈtHd4Hﾙﾎ45M1L5";
    let temp = TestTempDir::new();
    let target = temp.write(
        "taira_literal.ko",
        &format!(
            r#"
                seiyaku TairaLiteral {{
                    fn recipient() -> AccountId {{
                        return AccountId::parse("{TAIRA_RECIPIENT}");
                    }}

                    #[test]
                    fn exact_network_literal_roundtrips() {{
                        test::assert(
                            recipient() == AccountId::parse("{TAIRA_RECIPIENT}")
                        );
                    }}
                }}
                "#
        ),
    );
    let suite = discover_suite(&target).expect("discover Taira literal suite");
    let compiled = compile_suite_for_chain(&suite, false, 369)
        .expect("compile exact Taira literal under discriminant 369");
    let results = execute_suite_for_chain(&compiled, TraceMode::Off, 2, 369)
        .expect("execute exact Taira literal suite");
    assert!(results.iter().all(|result| result.passed));
    let mismatch = match compile_suite_for_chain(&suite, false, 753) {
        Ok(_) => panic!("Taira literal must fail under Sora discriminant 753"),
        Err(error) => error,
    };
    assert!(
        mismatch
            .to_string()
            .contains("ERR_UNEXPECTED_NETWORK_PREFIX")
    );
}
#[test]
fn zk_test_option_marks_both_test_and_runtime_artifacts() {
    let target_source = "seiyaku ZkTest { hajimari() {} #[test] fn smoke() {} }";
    let target_program = parser::parse(target_source).expect("parse ZK test target");
    let suite = DiscoveredSuite {
        artifacts: Vec::new(),
        sources: Vec::new(),
        source_root: None,
        target_path: PathBuf::from("/tmp/zk_test.ko"),
        target_source: target_source.to_owned(),
        target_program,
        test_modules: Vec::new(),
        tests: vec![TestCase {
            name: "smoke".to_owned(),
            fixture: None,
            path: PathBuf::from("demo.test.ko"),
            line: 1,
            column: 1,
        }],
        fixtures: HashMap::new(),
        fixture_sites: HashMap::new(),
        fixture_consts: HashMap::new(),
    };
    let compiled = compile_suite(&suite, true).expect("compile ZK test suite");
    for artifact in [
        compiled.suite.program.prepared().artifact(),
        compiled
            .runtime
            .as_ref()
            .expect("lifecycle target has a runtime artifact")
            .program
            .artifact(),
    ] {
        let metadata = ProgramMetadata::parse(artifact).expect("parse compiled metadata");
        assert_ne!(metadata.metadata.mode & ivm::ivm_mode::ZK, 0);
    }
}
#[test]
fn filtering_exact_and_seeded_order_are_deterministic() {
    let mut tests = vec![
        TestCase {
            name: "beta".to_owned(),
            fixture: None,
            path: PathBuf::from("demo.test.ko"),
            line: 2,
            column: 1,
        },
        TestCase {
            name: "alpha".to_owned(),
            fixture: None,
            path: PathBuf::from("demo.test.ko"),
            line: 1,
            column: 1,
        },
        TestCase {
            name: "alphabet".to_owned(),
            fixture: None,
            path: PathBuf::from("demo.test.ko"),
            line: 3,
            column: 1,
        },
    ];
    let mut options = KotoTestCliOptions::new(
        KotoTestAction::Run,
        iroha_data_model::account::address::chain_discriminant(),
    );
    options.filter = Some("alpha".to_owned());
    options.seed = 7;
    filter_and_order_tests(&mut tests, &options);
    let first = tests
        .iter()
        .map(|test| test.name.clone())
        .collect::<Vec<_>>();
    let mut repeated = vec![
        TestCase {
            name: "beta".to_owned(),
            fixture: None,
            path: PathBuf::from("demo.test.ko"),
            line: 2,
            column: 1,
        },
        TestCase {
            name: "alpha".to_owned(),
            fixture: None,
            path: PathBuf::from("demo.test.ko"),
            line: 1,
            column: 1,
        },
        TestCase {
            name: "alphabet".to_owned(),
            fixture: None,
            path: PathBuf::from("demo.test.ko"),
            line: 3,
            column: 1,
        },
    ];
    filter_and_order_tests(&mut repeated, &options);
    assert_eq!(
        first,
        repeated
            .iter()
            .map(|test| test.name.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(first.len(), 2);
}
#[test]
fn structured_request_validation_is_stage_tagged() {
    let mut request = KotoTestRunRequestV1::new("demo.ko", 753);
    request.jobs = 0;
    let error = validate_structured_request(&request).expect_err("zero workers must fail");
    assert_eq!(error.phase, KotoTestRunPhaseV1::Request);
    assert!(error.message.contains("worker count"));
    request.jobs = 1;
    request.exact = true;
    let error = validate_structured_request(&request).expect_err("exact needs a filter");
    assert_eq!(error.phase, KotoTestRunPhaseV1::Request);
    assert!(error.message.contains("requires a filter"));
    request.exact = false;
    request.chain_discriminant = 0;
    let error = validate_structured_request(&request).expect_err("zero chain must fail");
    assert_eq!(error.phase, KotoTestRunPhaseV1::Request);
    assert!(error.message.contains("1..=65535"));
}
#[test]
fn structured_filter_order_is_independent_of_discovery_order() {
    let request = KotoTestRunRequestV1 {
        target: PathBuf::from("demo.ko"),
        filter: Some("case".to_owned()),
        exact: false,
        jobs: 1,
        seed: 17,
        chain_discriminant: 753,
        zk_enabled: false,
    };
    let case = |name: &str, line| TestCase {
        name: name.to_owned(),
        fixture: None,
        path: PathBuf::from("demo.test.ko"),
        line,
        column: 1,
    };
    let mut forward = vec![case("case_z", 3), case("ignored", 2), case("case_a", 1)];
    let mut reverse = forward.iter().cloned().rev().collect::<Vec<_>>();
    filter_and_order_structured_tests(&mut forward, &request);
    filter_and_order_structured_tests(&mut reverse, &request);
    assert_eq!(
        forward
            .iter()
            .map(|test| test.name.as_str())
            .collect::<Vec<_>>(),
        reverse
            .iter()
            .map(|test| test.name.as_str())
            .collect::<Vec<_>>()
    );
    assert_eq!(forward.len(), 2);
}
#[test]
fn structured_runner_returns_ordered_logical_outcomes_without_timing() {
    let temp = TestTempDir::new();
    let target = temp.write(
        "structured.ko",
        include_str!("../fixtures/koto_v1/koto_test_driver_tests/002.ko")
            .strip_suffix('\n')
            .expect("fixture sentinel newline"),
    );
    let mut request = KotoTestRunRequestV1::new(&target, 753);
    request.jobs = 2;
    let first = run_tests_structured_v1(&request).expect("run structured suite");
    let repeated = run_tests_structured_v1(&request).expect("repeat structured suite");
    assert_eq!(first, repeated);
    assert_eq!(
        first.target,
        fs::canonicalize(target).expect("canonical target")
    );
    assert_eq!(
        first
            .cases
            .iter()
            .map(|case| case.name.as_str())
            .collect::<Vec<_>>(),
        ["a_fails", "z_passes"]
    );
    assert_eq!(first.passed(), 1);
    assert_eq!(first.failed(), 1);
    assert!(!first.is_success());
    assert!(first.cases[0].failure.is_some());
    assert!(first.cases[1].failure.is_none());
}
#[test]
fn structured_module_graph_executes_exact_dependency_and_ignores_ambient_tests() {
    let temp = TestTempDir::new();
    let target = temp.write(
        "tests/unit.ko",
        include_str!("../fixtures/koto_v1/koto_test_driver_tests/003.ko")
            .strip_suffix('\n')
            .expect("fixture sentinel newline"),
    );
    temp.write(
        "tests/ambient.test.ko",
        include_str!("../fixtures/koto_v1/koto_test_driver_tests/004.ko")
            .strip_suffix('\n')
            .expect("fixture sentinel newline"),
    );
    let dependency = "std/math@1.0.0".to_owned();
    let modules = KotoTestModuleGraphV1 {
        artifacts: Vec::new(),
        sources: Vec::new(),
        imports: vec![ImportBinding {
            alias: "calc".to_owned(),
            package: dependency.clone(),
        }],
        packages: vec![SourcePackageUnit {
            artifacts: Vec::new(),
            sources: Vec::new(),
            identity: dependency,
            modules: vec![SourceModuleUnit {
                source_name: "src/lib.ko".to_owned(),
                source: "module Math { export fn value() -> int { return 7; } }".to_owned(),
            }],
            exports: BTreeSet::from(["value".to_owned()]),
            imports: Vec::new(),
        }],
    };
    assert_eq!(
        discover_declared_test_names_v1(&target).expect("declared names"),
        ["dependency_is_exact"]
    );
    let report =
        run_tests_structured_with_modules_v1(&KotoTestRunRequestV1::new(&target, 753), &modules)
            .expect("run exact module graph");
    assert_eq!(report.cases.len(), 1);
    assert!(report.is_success());
}
#[test]
fn structured_source_root_is_bound_and_never_reopened_from_the_target_path() {
    let source_name = "tests/in-memory-supplied.ko".to_owned();
    let root = SourceModuleUnit {
        source_name: source_name.clone(),
        source: "seiyaku Supplied { #[test] fn supplied_only() { test::assert(true); } }"
            .to_owned(),
    };
    assert_eq!(
        discover_declared_test_names_source_v1(&root).expect("supplied names"),
        ["supplied_only"]
    );
    let report = run_tests_structured_source_with_modules_v1(
        &KotoTestRunRequestV1::new(&source_name, 753),
        &root,
        &KotoTestModuleGraphV1::default(),
    )
    .expect("run supplied source root");
    assert_eq!(report.target, PathBuf::from(source_name));
    assert_eq!(report.cases.len(), 1);
    assert_eq!(report.cases[0].name, "supplied_only");
    assert!(report.is_success());
    let error = run_tests_structured_source_with_modules_v1(
        &KotoTestRunRequestV1::new("tests/other.ko", 753),
        &root,
        &KotoTestModuleGraphV1::default(),
    )
    .expect_err("request/source substitution must fail");
    assert_eq!(error.phase, KotoTestRunPhaseV1::Request);
    assert!(error.message.contains("must equal"));
    let noncanonical = SourceModuleUnit {
        source_name: "tests/./in-memory-supplied.ko".to_owned(),
        source: root.source.clone(),
    };
    let error = run_tests_structured_source_with_modules_v1(
        &KotoTestRunRequestV1::new(&noncanonical.source_name, 753),
        &noncanonical,
        &KotoTestModuleGraphV1::default(),
    )
    .expect_err("noncanonical source identities must fail before compilation");
    assert_eq!(error.phase, KotoTestRunPhaseV1::Request);
    assert!(error.message.contains("canonical logical spelling"));
}
#[test]
fn structured_standalone_sources_execute_private_target_and_exact_package() {
    let target = SourceModuleUnit { source_name: "contracts/app.ko".to_owned(), source: "seiyaku App { fn reward() -> int { return calc::value(); } view fn current() authorize(anyone) -> int { return reward(); } }".to_owned() };
    let test = SourceModuleUnit { source_name: "tests/unit.ko".to_owned(), source: r#"module Tests { koto_test { target: "../contracts/app.ko" } #[test] fn exact_reward() { test::assert(reward() == 7); test::assert(calc::value() == 7); } }"#.to_owned() };
    let modules = KotoTestModuleGraphV1 {
        artifacts: Vec::new(),
        sources: Vec::new(),
        imports: vec![ImportBinding {
            alias: "calc".to_owned(),
            package: "demo/math@1.0.0".to_owned(),
        }],
        packages: vec![SourcePackageUnit {
            artifacts: Vec::new(),
            sources: Vec::new(),
            identity: "demo/math@1.0.0".to_owned(),
            modules: vec![SourceModuleUnit {
                source_name: "tests/unit.ko".to_owned(),
                source: "module Math { export fn value() -> int { return 7; } }".to_owned(),
            }],
            exports: BTreeSet::from(["value".to_owned()]),
            imports: Vec::new(),
        }],
    };
    assert_eq!(
        declared_test_target_source_v1(&test).expect("target"),
        Some(target.source_name.clone())
    );
    assert_eq!(
        discover_declared_test_names_source_set_v1(&test, Some(&target)).expect("names"),
        ["exact_reward"]
    );
    let report = run_tests_structured_source_set_with_modules_v1(
        &KotoTestRunRequestV1::new(&test.source_name, 753),
        &test,
        Some(&target),
        &modules,
    )
    .expect("immutable standalone suite");
    assert_eq!(report.passed(), 1);
    assert_eq!(report.target, PathBuf::from("contracts/app.ko"));
    let mut wrong = test.clone();
    wrong.source = wrong.source.replace("calc::value()", "missing::value()");
    let error = run_tests_structured_source_set_with_modules_v1(
        &KotoTestRunRequestV1::new(&wrong.source_name, 753),
        &wrong,
        Some(&target),
        &modules,
    )
    .expect_err("undeclared import");
    assert_eq!(error.phase, KotoTestRunPhaseV1::Compilation);
    assert!(error.message.contains("missing"));
    let diagnostics = error
        .diagnostics
        .expect("canonical compilation diagnostics");
    assert!(diagnostics.diagnostics.iter().any(|diagnostic| {
        diagnostic.message.contains("missing")
            && diagnostic
                .primary_span
                .as_ref()
                .is_some_and(|span| span.source.as_deref() == Some("tests/unit.ko"))
    }));
}
#[test]
fn structured_source_discovery_preserves_parse_diagnostics_and_fixes() {
    let root = SourceModuleUnit {
        source_name: "tests/invalid.ko".to_owned(),
        source: "module Tests { #[test] fn check() { let int value = 1 } }".to_owned(),
    };
    for error in [
        declared_test_target_source_v1(&root).expect_err("invalid target source"),
        run_tests_structured_source_with_modules_v1(
            &KotoTestRunRequestV1::new(&root.source_name, 753),
            &root,
            &KotoTestModuleGraphV1::default(),
        )
        .expect_err("invalid suite source"),
    ] {
        assert_eq!(error.phase, KotoTestRunPhaseV1::Compilation);
        let diagnostics = error.diagnostics.expect("structured parsing diagnostics");
        assert!(diagnostics.diagnostics.iter().any(|diagnostic| {
            diagnostic
                .primary_span
                .as_ref()
                .is_some_and(|span| span.source.as_deref() == Some("tests/invalid.ko"))
                && diagnostic
                    .fix
                    .as_ref()
                    .is_some_and(|fix| fix.replacement == ";")
        }));
    }
}
#[test]
fn structured_standalone_sources_reject_missing_mismatched_and_escaping_targets() {
    let source = |target: &str| SourceModuleUnit {
        source_name: "tests/unit.ko".to_owned(),
        source: format!(
            "module Tests {{ koto_test {{ target: \"{target}\" }} #[test] fn check() {{ test::assert(true); }} }}"
        ),
    };
    let test = source("../contracts/app.ko");
    assert!(
        discover_declared_test_names_source_set_v1(&test, None)
            .expect_err("missing target")
            .contains("explicitly supplied")
    );
    let wrong = SourceModuleUnit {
        source_name: "contracts/other.ko".to_owned(),
        source: "seiyaku Other {}".to_owned(),
    };
    assert!(
        discover_declared_test_names_source_set_v1(&test, Some(&wrong))
            .expect_err("wrong target")
            .contains("not supplied")
    );
    for path in ["../../outside.ko", "/tmp/outside.ko", "C:/outside.ko"] {
        assert!(
            declared_test_target_source_v1(&source(path)).is_err(),
            "{path}"
        );
    }
}
/// A discovered suite and results for report-rendering tests: a seiyaku in `contracts/` whose
/// tests live in `tests/vault.test.ko`.
fn report_fixture() -> (DiscoveredSuite, Vec<TestRunResult>) {
    let target_source = "seiyaku Vault { view fn value() authorize(anyone) -> int { return 1; } }";
    let suite = DiscoveredSuite {
        artifacts: Vec::new(),
        sources: Vec::new(),
        source_root: None,
        target_path: PathBuf::from("/work/contracts/vault.ko"),
        target_source: target_source.to_owned(),
        target_program: parser::parse(target_source).expect("parse report target"),
        test_modules: Vec::new(),
        tests: Vec::new(),
        fixtures: HashMap::new(),
        fixture_sites: HashMap::new(),
        fixture_consts: HashMap::new(),
    };
    let call = |entrypoint: &str, gas| EntrypointCall {
        entrypoint: entrypoint.to_owned(),
        gas,
        cycles: gas / 2,
        trace_steps: 0,
    };
    let results = vec![
        TestRunResult {
            name: "rejects_bad_input".to_owned(),
            path: PathBuf::from("/work/tests/vault.test.ko"),
            line: 9,
            column: 5,
            elapsed: Duration::from_millis(2),
            passed: false,
            failure: Some(
                TestFailure::new(FailureKind::Assertion, "")
                    .at(Some("/work/tests/vault.test.ko:12:9".to_owned()))
                    .detail("test::assert_eq(actual: left, expected: 71)")
                    .detail("actual:   70")
                    .detail("expected: 71"),
            ),
            harness_cycles: 10,
            own_gas: 0,
            calls: vec![call("withdraw", 1_200), call("withdraw", 1_400)],
            trace: trace_capture::TestTrace::default(),
        },
        TestRunResult {
            name: "reads_value".to_owned(),
            path: PathBuf::from("/work/tests/vault.test.ko"),
            line: 20,
            column: 5,
            elapsed: Duration::from_millis(1),
            passed: true,
            failure: None,
            harness_cycles: 5,
            own_gas: 0,
            calls: vec![call("value", 300)],
            trace: trace_capture::TestTrace::default(),
        },
    ];
    (suite, results)
}
#[test]
fn machine_reports_preserve_failure_details() {
    let (suite, results) = report_fixture();
    let json = render_test_json(&suite, &results, 42).expect("JSON report");
    let junit = render_test_junit(&suite, &results, 42);
    for report in [&json, &junit] {
        assert!(report.contains("rejects_bad_input"));
        assert!(report.contains("actual:   70"));
        assert!(report.contains("/work/tests/vault.test.ko"), "{report}");
    }
    let value: Value = json::from_str(&json).expect("one JSON document");
    let failed = &value.get("tests").and_then(Value::as_array).expect("tests")[0];
    assert_eq!(
        failed.get("file").and_then(Value::as_str),
        Some("/work/tests/vault.test.ko")
    );
    assert_eq!(failed.get("line").and_then(Value::as_u64), Some(9));
    assert_eq!(failed.get("column").and_then(Value::as_u64), Some(5));
    assert_eq!(failed.get("gas").and_then(Value::as_u64), Some(2_600));
    assert_eq!(failed.get("cycles").and_then(Value::as_u64), Some(1_310));
    assert_eq!(
        failed.pointer("/failure/kind").and_then(Value::as_str),
        Some("assertion")
    );
    assert_eq!(
        failed.pointer("/failure/location").and_then(Value::as_str),
        Some("/work/tests/vault.test.ko:12:9")
    );
    assert!(junit.contains("file=\"/work/tests/vault.test.ko\" line=\"9\""));
    assert!(junit.contains("<property name=\"gas\" value=\"2600\"/>"));
    assert!(junit.contains("type=\"assertion\""));
    assert!(!junit.contains("contracts/vault.ko\" line"));
}
#[test]
fn human_report_names_the_test_file_and_failure_details() {
    let (suite, results) = report_fixture();
    let summary = render_run_summary(&suite, &results);
    assert!(
        summary.contains("running 2 tests for seiyaku `Vault`"),
        "{summary}"
    );
    // Locations are padded to one width so test names line up.
    assert!(
        summary.contains("FAILED  /work/tests/vault.test.ko:9:5   rejects_bad_input"),
        "{summary}"
    );
    assert!(
        summary.contains("    ok  /work/tests/vault.test.ko:20:5  reads_value"),
        "{summary}"
    );
    assert!(summary.contains("gas 2,600, cycles 1,310"), "{summary}");
    assert!(summary.contains("---- rejects_bad_input (/work/tests/vault.test.ko:9:5) ----"));
    assert!(summary.contains(
        "assertion failed at /work/tests/vault.test.ko:12:9\n  test::assert_eq(actual: left, expected: 71)\n  actual:   70\n  expected: 71"
    ));
    assert!(summary.contains("result: FAILED. 1 passed; 1 failed; gas 2,900"));
    assert!(!summary.contains("contracts/vault.ko:9"));
    let gas = render_gas_report(&results);
    assert!(gas.contains("transaction admission fees excluded"));
    let withdraw = gas
        .lines()
        .find(|line| line.trim_start().starts_with("withdraw"))
        .expect("withdraw row");
    let columns = withdraw.split_whitespace().collect::<Vec<_>>();
    assert_eq!(columns, ["withdraw", "2", "1,200", "1,300", "1,400"]);
    assert_eq!(group_digits(0), "0");
    assert_eq!(group_digits(1_234_567), "1,234,567");
}
#[test]
fn discover_suite_links_inline_and_matching_standalone_tests() {
    let temp = TestTempDir::new();
    let target = temp.write(
        "contracts/demo.ko",
        include_str!("../fixtures/koto_v1/koto_test_driver_tests/005.ko")
            .strip_suffix('\n')
            .expect("fixture sentinel newline"),
    );
    temp.write(
        "contracts/demo.test.ko",
        include_str!("../fixtures/koto_v1/koto_test_driver_tests/006.ko")
            .strip_suffix('\n')
            .expect("fixture sentinel newline"),
    );
    temp.write("contracts/other.ko", "seiyaku Other { fn other() {} }");
    temp.write(
        "contracts/tests/ignored.test.ko",
        include_str!("../fixtures/koto_v1/koto_test_driver_tests/007.ko")
            .strip_suffix('\n')
            .expect("fixture sentinel newline"),
    );
    let suite = discover_suite(&target).expect("discover suite");
    let mut names = suite
        .tests
        .iter()
        .map(|test| test.name.clone())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(names, vec!["inline".to_string(), "standalone".to_string()]);
    let mut public_names = discover_test_names(&target).expect("discover public test names");
    public_names.sort();
    assert_eq!(public_names, names);
}
#[test]
fn discover_suite_from_standalone_input_uses_target_program() {
    let temp = TestTempDir::new();
    temp.write(
        "contracts/demo.ko",
        include_str!("../fixtures/koto_v1/koto_test_driver_tests/008.ko")
            .strip_suffix('\n')
            .expect("fixture sentinel newline"),
    );
    let standalone = temp.write(
        "contracts/demo.test.ko",
        include_str!("../fixtures/koto_v1/koto_test_driver_tests/009.ko")
            .strip_suffix('\n')
            .expect("fixture sentinel newline"),
    );
    let suite = discover_suite(&standalone).expect("discover suite from standalone input");
    assert_eq!(
        suite.target_path.file_name().and_then(|name| name.to_str()),
        Some("demo.ko")
    );
    assert_eq!(suite.tests.len(), 1);
    assert_eq!(suite.tests[0].name, "smoke");
}
#[test]
fn execute_suite_supports_native_contract_flow_helpers() {
    let temp = TestTempDir::new();
    let actor_seed = [9_u8; 32];
    let signing_key = SigningKey::from_bytes(&actor_seed);
    let actor_public_key = iroha_crypto::PublicKey::from_bytes(
        iroha_crypto::Algorithm::Ed25519,
        signing_key.verifying_key().as_bytes(),
    )
    .expect("public key");
    let actor_account = AccountId::new(actor_public_key)
        .canonical_i105()
        .expect("canonical actor account");
    temp.write(
        "contracts/contract_flow_demo.ko",
        include_str!("../fixtures/koto_v1/koto_test_driver_tests/010.ko")
            .strip_suffix('\n')
            .expect("fixture sentinel newline"),
    );
    let test_path = temp.write(
            "contracts/contract_flow_demo.test.ko",
            &format!(
                r#"
                module ContractFlowTests {{
                koto_test {{ target: "contract_flow_demo.ko" }}

                fixture actors {{
                    actor("issuer", AccountId::parse("{actor_account}"), "0x{seed_hex}");
                    grant_seiyaku_permission("issuer", "Test");
                    grant_seiyaku_lifecycle_permission("issuer", "hajimari");
                }}

                #[test(fixture="actors")]
                fn drive_contract_flow() {{
                    test::invoke_kotoage_as(actor: "issuer", kotoage: "hajimari", arguments: {{}});
                    test::invoke_kotoage_as(actor: "issuer", kotoage: "increment", arguments: {{}});
                    test::invoke_kotoage_as(
                        actor: "issuer",
                        kotoage: "remember_caller",
                        arguments: {{}}
                    );

                    test::expect_reject_as(actor: "issuer", kotoage: "reject_me", arguments: {{}}, expected: DemoError::Rejected);
                }}
                }}
                "#,
                actor_account = actor_account,
                seed_hex = hex::encode(actor_seed),
            ),
        );
    let suite = discover_suite(&test_path).expect("discover suite");
    let compiled = compile_suite(&suite, false).expect("compile suite");
    let mut host = build_host_for_fixture(&compiled, Some("actors")).expect("build host");
    let mut vm = IVM::new(u64::MAX);
    vm.set_trace_mode(TraceMode::PcOnly);
    let put_blob = |vm: &mut IVM, reg: usize, value: &str| {
        let ptr = vm
            .alloc_input_tlv(&make_tlv(PointerType::Blob, value.as_bytes()))
            .expect("blob tlv");
        vm.set_register(reg, ptr);
    };
    put_blob(&mut vm, 10, "issuer");
    host.syscall(TEST_SYSCALL_ACTOR_ACCOUNT, &mut vm)
        .expect("actor account syscall");
    let actor_tlv = vm
        .validate_input_tlv(vm.register(10))
        .expect("actor account tlv");
    assert_eq!(actor_tlv.type_id, PointerType::AccountId);
    let decoded_actor: AccountId =
        norito::decode_from_bytes(actor_tlv.payload).expect("decode actor account");
    assert_eq!(
        decoded_actor
            .canonical_i105()
            .expect("canonical decoded actor"),
        actor_account
    );
    put_blob(&mut vm, 10, "issuer");
    host.syscall(TEST_SYSCALL_ACTOR_PUBLIC_KEY, &mut vm)
        .expect("actor public key syscall");
    let public_key_tlv = vm
        .validate_input_tlv(vm.register(10))
        .expect("public key tlv");
    assert_eq!(public_key_tlv.type_id, PointerType::Blob);
    assert_eq!(
        public_key_tlv.payload,
        signing_key.verifying_key().as_bytes()
    );
    put_blob(&mut vm, 10, "issuer");
    let message_ptr = vm
        .alloc_input_tlv(&make_tlv(PointerType::Blob, b"native-flow"))
        .expect("message tlv");
    vm.set_register(11, message_ptr);
    host.syscall(TEST_SYSCALL_ACTOR_SIGN, &mut vm)
        .expect("actor sign syscall");
    let signature_tlv = vm
        .validate_input_tlv(vm.register(10))
        .expect("signature tlv");
    assert_eq!(signature_tlv.type_id, PointerType::Blob);
    let signature = Ed25519Signature::from_slice(signature_tlv.payload).expect("signature bytes");
    signing_key
        .verifying_key()
        .verify(b"native-flow", &signature)
        .expect("signature verifies");
    put_blob(&mut vm, 10, "issuer");
    put_blob(&mut vm, 11, "hajimari");
    vm.set_register(12, 0);
    vm.set_register(13, 0);
    let result_table = vm.alloc_heap(8).expect("result table");
    vm.set_register(14, result_table);
    vm.set_register(15, 1);
    host.syscall(TEST_SYSCALL_INVOKE_ENTRYPOINT_AS, &mut vm)
        .expect("invoke hajimari");
    put_blob(&mut vm, 10, "issuer");
    put_blob(&mut vm, 11, "increment");
    vm.set_register(12, 0);
    vm.set_register(13, 0);
    let result_table = vm.alloc_heap(8).expect("result table");
    vm.set_register(14, result_table);
    vm.set_register(15, 1);
    host.syscall(TEST_SYSCALL_INVOKE_ENTRYPOINT_AS, &mut vm)
        .expect("invoke increment");
    let counter_state = host.fixture_state("counter").expect("counter state");
    assert_eq!(decode_int_state_value(&counter_state), 5);
    put_blob(&mut vm, 10, "issuer");
    put_blob(&mut vm, 11, "remember_caller");
    vm.set_register(12, 0);
    vm.set_register(13, 0);
    let result_table = vm.alloc_heap(8).expect("result table");
    vm.set_register(14, result_table);
    vm.set_register(15, 1);
    host.syscall(TEST_SYSCALL_INVOKE_ENTRYPOINT_AS, &mut vm)
        .expect("invoke remember_caller");
    let remembered_state = host.fixture_state("last_actor").expect("last_actor state");
    let remembered_account_envelope =
        decode_pointer_state_value(&remembered_state, StateValueKindV1::AccountId);
    let remembered_account_tlv = ivm::pointer_abi::validate_tlv_bytes(&remembered_account_envelope)
        .expect("remembered account tlv");
    assert_eq!(remembered_account_tlv.type_id, PointerType::AccountId);
    let remembered: AccountId = norito::decode_from_bytes(remembered_account_tlv.payload)
        .expect("decode remembered account");
    assert_eq!(
        remembered
            .canonical_i105()
            .expect("canonical remembered account"),
        actor_account
    );
    put_blob(&mut vm, 10, "issuer");
    put_blob(&mut vm, 11, "pair");
    vm.set_register(12, 0);
    vm.set_register(13, 0);
    let result_table = vm.alloc_heap(16).expect("result table");
    vm.set_register(14, result_table);
    vm.set_register(15, 2);
    host.syscall(TEST_SYSCALL_INVOKE_ENTRYPOINT_AS, &mut vm)
        .expect("invoke pair");
    assert_eq!(vm.register(10), result_table);
    assert_eq!(vm.register(11), 2);
    assert_eq!(decode_i64_word(&vm, vm.load_u64(result_table).unwrap()), 2);
    assert_eq!(
        decode_i64_word(&vm, vm.load_u64(result_table + 8).unwrap()),
        3
    );
    put_blob(&mut vm, 10, "issuer");
    put_blob(&mut vm, 11, "reject_me");
    vm.set_register(12, 0);
    vm.set_register(13, 0);
    let expectation = kotodama_lang::testing::RejectionExpectation::Any;
    let bytes = norito::encode_canonical(&expectation).expect("encode expectation");
    let ptr = vm
        .alloc_input_tlv(&make_tlv(PointerType::Blob, &bytes))
        .expect("expectation tlv");
    vm.set_register(14, ptr);
    vm.set_register(15, 0);
    host.syscall(TEST_SYSCALL_EXPECT_REJECT_AS, &mut vm)
        .expect("expect reject");
    assert!(
        host.supplemental_trace
            .as_ref()
            .is_some_and(|trace| !trace.pcs().is_empty()),
        "expected coverage trace from nested entrypoint execution"
    );
}
#[test]
fn exact_rejection_mismatches_fail_and_restore_nested_state() {
    use iroha_data_model::smart_contract::manifest::{
        ContractErrorTypeDescriptor, ContractErrorVariantDescriptor,
    };
    use kotodama_lang::testing::{RejectionExpectation, RejectionTrap};
    let temp = TestTempDir::new();
    let scoped_asset = AssetDefinitionId::derive_from_components(
        DomainId::try_new("rejections", "universal").unwrap(),
        "unit".parse().unwrap(),
    );
    temp.write(
        "rejection.ko",
        &r#"seiyaku Rejections { permission CanCustomProbe; permission CanEnactGovernance; permission Update; permission Mint; permission manage_roles;
        error enum RejectionError { First = 1, Second = 2, }
        state int counter;
        hajimari() { counter = 7; }
        kotoage fn reset() authorize(Update) { counter = 7; }
        kotoage fn reject(int value) authorize(Update) {
            counter = value;
            require(false, RejectionError::First);
        }
        kotoage fn succeed(int value) authorize(Update) {
            counter = value;
        }
        kotoage fn govern() authorize(CanEnactGovernance) {
            counter = 99;
            require(false, RejectionError::First);
        }
        kotoage fn custom() authorize(CanCustomProbe) {
            counter = 99;
            require(false, RejectionError::First);
        }
        kotoage fn mapped() authorize(manage_roles) {
            counter = 99;
            require(false, RejectionError::First);
        }
        kotoage fn scoped() authorize(Mint) {
            counter = 99;
            require(false, RejectionError::First);
        }
    }"#,
    );
    let path = temp.write(
        "rejection.test.ko",
        &format!(
            r#"module RejectionTests {{
        koto_test {{ target: "rejection.ko" }}
        fixture allowed {{
            actor("app", AccountId::parse("{DEFAULT_CALLER}"));
            grant_seiyaku_lifecycle_permission("app", "hajimari");
            grant_seiyaku_permission("app", "Update");
            grant_seiyaku_permission("app", "CanEnactGovernance");
            grant_seiyaku_permission("app", "CanCustomProbe");
            grant_seiyaku_permission("app", "manage_roles");
            grant_seiyaku_permission("app", "Mint");
        }}
        fixture unpermitted {{
            actor("app", AccountId::parse("{DEFAULT_CALLER}"));
            grant_seiyaku_lifecycle_permission("app", "hajimari");
        }}
        #[test(fixture = "allowed")]
        fn placeholder() {{}}
    }}"#
        ),
    );
    let suite = discover_suite(&path).expect("discover rejection suite");
    let compiled = compile_suite(&suite, false).expect("compile rejection suite");
    let mut host = build_host_for_fixture(&compiled, Some("allowed")).expect("build host");
    let mut vm = IVM::new(u64::MAX);
    let put = |vm: &mut IVM, register, value: &[u8], kind| {
        let pointer = vm
            .alloc_input_tlv(&make_tlv(kind, value))
            .expect("test operand");
        vm.set_register(register, pointer);
    };
    #[derive(Clone, Copy, Debug)]
    enum Arguments {
        Empty,
        Int(i64),
        WrongCount,
        Misaligned,
        InvalidValue,
        NullTable,
    }
    let call = |host: &mut KotoTestHost,
                vm: &mut IVM,
                entrypoint: &str,
                payload: Arguments,
                expected: Option<&RejectionExpectation>| {
        put(vm, 10, b"app", PointerType::Blob);
        put(vm, 11, entrypoint.as_bytes(), PointerType::Blob);
        let (base, words) = match payload {
            Arguments::Empty => (0, 0),
            Arguments::NullTable => (0, 1),
            Arguments::WrongCount => (vm.alloc_heap(16).unwrap(), 2),
            Arguments::Misaligned => (vm.alloc_heap(16).unwrap() + 1, 1),
            Arguments::InvalidValue => {
                let base = vm.alloc_heap(8).unwrap();
                vm.store_u64(base, 42).unwrap();
                (base, 1)
            }
            Arguments::Int(value) => {
                let frame = IntValueV1::prepare_frame(&value.into())
                    .unwrap()
                    .encode_frame()
                    .unwrap();
                let value = vm
                    .alloc_input_tlv(&make_tlv(PointerType::Int, &frame))
                    .unwrap();
                let base = vm.alloc_heap(8).unwrap();
                vm.store_u64(base, value).unwrap();
                (base, 1)
            }
        };
        vm.set_register(12, base);
        vm.set_register(13, words);
        if let Some(expected) = expected {
            put(
                vm,
                14,
                &norito::encode_canonical(expected).expect("expectation"),
                PointerType::Blob,
            );
        } else {
            let result_table = vm.alloc_heap(8).expect("result table");
            vm.set_register(14, result_table);
        }
        vm.set_register(15, u64::from(expected.is_none()));
        host.syscall(
            if expected.is_some() {
                TEST_SYSCALL_EXPECT_REJECT_AS
            } else {
                TEST_SYSCALL_INVOKE_ENTRYPOINT_AS
            },
            vm,
        )
    };
    call(&mut host, &mut vm, "hajimari", Arguments::Empty, None).expect("initialize");
    let valid_payload = Arguments::Int(99);
    host.record_budget.set_limit_bytes(0);
    let deferred = call(&mut host, &mut vm, "succeed", valid_payload, None)
        .expect_err("argument capture must retain its allocation refusal");
    assert!(deferred.execution_deferral().is_some(), "{deferred:?}");
    assert_eq!(host.record_budget.reserved_bytes(), 0);
    assert_eq!(
        decode_int_state_value(&host.fixture_state("counter").unwrap()),
        7
    );
    assert!(
        host.last_test_error().is_none(),
        "resource refusal is not a source rejection"
    );
    host.record_budget.set_limit_bytes(16 * 1024 * 1024);
    let control = call(&mut host, &mut vm, "succeed", valid_payload, None);
    assert!(
        control.is_ok(),
        "successful mutation control: {control:?}: {:?}; schema: {:?}",
        host.last_test_error(),
        host.entrypoints
            .get("succeed")
            .and_then(|entry| entry.argument_schema.as_ref())
    );
    assert_eq!(
        decode_int_state_value(&host.fixture_state("counter").expect("state")),
        99
    );
    call(&mut host, &mut vm, "reset", Arguments::Empty, None).expect("reset control state");
    call(&mut host, &mut vm, "hajimari", Arguments::Empty, None)
        .expect_err("a consumed hajimari cannot be replayed");
    assert!(
        host.last_test_error()
            .expect("replay diagnostic")
            .contains("cannot be replayed")
    );
    let descriptor = ContractErrorTypeDescriptor {
        identity: "Rejections::RejectionError".to_owned(),
        variants: vec![
            ContractErrorVariantDescriptor {
                name: "First".to_owned(),
                code: 1,
            },
            ContractErrorVariantDescriptor {
                name: "Second".to_owned(),
                code: 2,
            },
        ],
    };
    let nominal = RejectionExpectation::Contract {
        descriptor: descriptor.clone(),
        code: 1,
    };
    let mut other_type = descriptor.clone();
    other_type.identity = "Other::RejectionError".to_owned();
    let mut other_schema = descriptor.clone();
    other_schema.variants[1].name = "Different".to_owned();
    assert_ne!(other_schema.schema_hash(), descriptor.schema_hash());
    for (expected, matches) in [
        (
            RejectionExpectation::Contract {
                descriptor: descriptor.clone(),
                code: 2,
            },
            false,
        ),
        (
            RejectionExpectation::Contract {
                descriptor: other_type,
                code: 1,
            },
            false,
        ),
        (
            RejectionExpectation::Contract {
                descriptor: other_schema,
                code: 1,
            },
            false,
        ),
        (nominal.clone(), true),
        (RejectionExpectation::PermissionDenied, false),
        (RejectionExpectation::InvalidArguments, false),
        (RejectionExpectation::Trap(RejectionTrap::OutOfGas), false),
        (RejectionExpectation::Any, true),
    ] {
        let caller_before = host.inner.caller_subject();
        let outcome = call(&mut host, &mut vm, "reject", valid_payload, Some(&expected));
        assert_eq!(
            outcome.is_ok(),
            matches,
            "{expected:?}: {:?}",
            host.last_test_error()
        );
        assert_eq!(
            decode_int_state_value(&host.fixture_state("counter").expect("state")),
            7
        );
        assert_eq!(host.inner.caller_subject(), caller_before);
        if !matches {
            assert!(
                host.last_test_error()
                    .expect("mismatch diagnostic")
                    .contains("expected")
            );
        }
    }
    // Even the explicitly broad helper must reject unexpected success and undo its effects.
    for expected in [&nominal, &RejectionExpectation::Any] {
        call(&mut host, &mut vm, "succeed", valid_payload, Some(expected))
            .expect_err("unexpected success");
        assert!(
            host.last_test_error()
                .expect("success diagnostic")
                .contains("but the call succeeded")
        );
        assert_eq!(
            decode_int_state_value(&host.fixture_state("counter").expect("state")),
            7
        );
    }
    let invalid_payload = Arguments::InvalidValue;
    for (expected, matches) in [
        (nominal.clone(), false),
        (RejectionExpectation::PermissionDenied, false),
        (RejectionExpectation::InvalidArguments, true),
        (RejectionExpectation::Any, true),
    ] {
        let outcome = call(
            &mut host,
            &mut vm,
            "reject",
            invalid_payload,
            Some(&expected),
        );
        assert_eq!(
            outcome.is_ok(),
            matches,
            "{expected:?}: {:?}",
            host.last_test_error()
        );
        if !matches {
            assert!(
                host.last_test_error()
                    .expect("argument stage diagnostic")
                    .contains("observed: invalid arguments")
            );
        }
        assert_eq!(
            decode_int_state_value(&host.fixture_state("counter").expect("state")),
            7
        );
    }
    let mut denied =
        build_host_for_fixture(&compiled, Some("unpermitted")).expect("unpermitted host");
    call(&mut denied, &mut vm, "hajimari", Arguments::Empty, None)
        .expect("initialize denied fixture");
    let denied_actor = denied.actor_account("app").unwrap();
    denied
        .inner
        .wsv
        .grant_permission(&denied_actor, PermissionToken::ManageRoles);
    denied
        .inner
        .wsv
        .grant_permission(&denied_actor, PermissionToken::MintAsset(scoped_asset));
    for (expected, matches) in [
        (nominal.clone(), false),
        (RejectionExpectation::InvalidArguments, false),
        (
            RejectionExpectation::Trap(RejectionTrap::RuntimePermissionDenied),
            false,
        ),
        (RejectionExpectation::PermissionDenied, true),
        (RejectionExpectation::Any, true),
    ] {
        // Authorization is checked before the deliberately invalid argument payload.
        let outcome = call(
            &mut denied,
            &mut vm,
            "reject",
            invalid_payload,
            Some(&expected),
        );
        assert_eq!(
            outcome.is_ok(),
            matches,
            "{expected:?}: {:?}",
            denied.last_test_error()
        );
        if !matches {
            assert!(
                denied
                    .last_test_error()
                    .expect("authorization stage diagnostic")
                    .contains("observed: permission denied")
            );
        }
        assert_eq!(
            decode_int_state_value(&denied.fixture_state("counter").expect("state")),
            7
        );
    }
    for (entrypoint, permission_name) in [
        ("govern", "CanEnactGovernance"),
        ("custom", "CanCustomProbe"),
        ("mapped", "manage_roles"),
        ("scoped", "Mint"),
    ] {
        // A generic exact-entrypoint grant cannot replace the distinct declared permission.
        let actor = denied.actor_account("app").unwrap();
        denied.inner.wsv.grant_permission(
            &actor,
            PermissionToken::ContractEntrypoint {
                contract: denied.contract_address.clone(),
                entrypoint: entrypoint.to_owned(),
            },
        );
        call(&mut denied, &mut vm, entrypoint, Arguments::Empty, None)
            .expect_err("missing declared permission");
        assert!(denied.last_test_error().unwrap().contains(permission_name));
        for (expected, matches) in [
            (nominal.clone(), false),
            (RejectionExpectation::InvalidArguments, false),
            (
                RejectionExpectation::Trap(RejectionTrap::RuntimePermissionDenied),
                false,
            ),
            (RejectionExpectation::PermissionDenied, true),
            (RejectionExpectation::Any, true),
        ] {
            let caller_before = denied.inner.caller_subject();
            assert_eq!(
                call(
                    &mut denied,
                    &mut vm,
                    entrypoint,
                    Arguments::WrongCount,
                    Some(&expected)
                )
                .is_ok(),
                matches,
                "{permission_name} {expected:?}: {:?}",
                denied.last_test_error()
            );
            assert_eq!(
                decode_int_state_value(&denied.fixture_state("counter").unwrap()),
                7
            );
            assert_eq!(denied.inner.caller_subject(), caller_before);
        }
        call(
            &mut host,
            &mut vm,
            entrypoint,
            Arguments::Empty,
            Some(&nominal),
        )
        .expect("declared fixture permission reaches typed rejection");
        for payload in [
            Arguments::WrongCount,
            Arguments::Misaligned,
            Arguments::NullTable,
            Arguments::InvalidValue,
        ] {
            for (expected, matches) in [
                (nominal.clone(), false),
                (RejectionExpectation::PermissionDenied, false),
                (RejectionExpectation::InvalidArguments, true),
                (RejectionExpectation::Any, true),
            ] {
                let caller_before = host.inner.caller_subject();
                assert_eq!(
                    call(&mut host, &mut vm, entrypoint, payload, Some(&expected)).is_ok(),
                    matches,
                    "{entrypoint} {payload:?} {expected:?}: {:?}",
                    host.last_test_error()
                );
                assert_eq!(
                    decode_int_state_value(&host.fixture_state("counter").unwrap()),
                    7
                );
                assert_eq!(host.inner.caller_subject(), caller_before);
            }
        }
    }
    call(&mut host, &mut vm, "succeed", valid_payload, None).expect("normal mutation control");
    call(&mut host, &mut vm, "reset", Arguments::WrongCount, None)
        .expect_err("normal zero-parameter calls reject nonempty arguments too");
    assert!(
        host.last_test_error()
            .expect("argument diagnostic")
            .contains(
                "takes no arguments, so its argument table must have zero base and zero words"
            )
    );
    assert_eq!(
        decode_int_state_value(&host.fixture_state("counter").unwrap()),
        99
    );
    call(&mut host, &mut vm, "reset", Arguments::Empty, None)
        .expect("canonical empty arguments execute");
    assert_eq!(
        decode_int_state_value(&host.fixture_state("counter").unwrap()),
        7
    );
}
#[test]
fn execute_suite_runs_compiled_contract_flow_helpers_from_standalone_test() {
    let temp = TestTempDir::new();
    let actor_seed = [9_u8; 32];
    let signing_key = SigningKey::from_bytes(&actor_seed);
    let actor_public_key = iroha_crypto::PublicKey::from_bytes(
        iroha_crypto::Algorithm::Ed25519,
        signing_key.verifying_key().as_bytes(),
    )
    .expect("public key");
    let actor_account = AccountId::new(actor_public_key)
        .canonical_i105()
        .expect("canonical actor account");
    temp.write(
        "contracts/contract_flow_demo.ko",
        include_str!("../fixtures/koto_v1/koto_test_driver_tests/011.ko")
            .strip_suffix('\n')
            .expect("fixture sentinel newline"),
    );
    let test_path = temp.write(
            "contracts/contract_flow_demo.test.ko",
            &format!(
                r#"
                module ContractFlowTests {{
                koto_test {{ target: "contract_flow_demo.ko" }}

                fixture actors {{
                    actor("issuer", AccountId::parse("{actor_account}"), "0x{seed_hex}");
                    grant_seiyaku_permission("issuer", "Test");
                    grant_seiyaku_lifecycle_permission("issuer", "hajimari");
                }}

                #[test(fixture="actors")]
                fn actor_helpers_roundtrip() {{
                    let acct = test::actor_account("issuer");
                    test::assert(acct == AccountId::parse("{actor_account}"));

                    let pk = test::actor_public_key("issuer");
                    let sig = test::actor_sign(actor: "issuer", payload: b"native-flow");
                    test::assert(pk != b"");
                    test::assert(sig != b"");
                }}

                #[test(fixture="actors")]
                fn invoke_kotoage_as_runs_the_seiyaku() {{
                    test::invoke_kotoage_as(actor: "issuer", kotoage: "hajimari", arguments: {{}});
                    test::invoke_kotoage_as(actor: "issuer", kotoage: "increment", arguments: {{}});
                    test::assert(counter == 5);

                    test::invoke_kotoage_as(actor: "issuer", kotoage: "remember_caller", arguments: {{}});
                    test::assert(last_actor == AccountId::parse("{actor_account}"));

                    let pair_result = test::invoke_kotoage_as(actor: "issuer", kotoage: "pair", arguments: {{}});
                    test::assert_eq(actual: pair_result.0, expected: 2);
                    test::assert_eq(actual: pair_result.1, expected: 3);
                }}

                #[test(fixture="actors")]
                fn expect_reject_as_captures_seiyaku_rejection() {{
                    test::invoke_kotoage_as(actor: "issuer", kotoage: "hajimari", arguments: {{}});
                    test::expect_reject_as(actor: "issuer", kotoage: "reject_me", arguments: {{}}, expected: DemoError::Rejected);
                }}

                #[test(fixture="actors")]
                fn calls_before_hajimari_are_lifecycle_rejections() {{
                    test::expect_any_reject_as(actor: "issuer", kotoage: "increment", arguments: {{}});
                    test::invoke_kotoage_as(actor: "issuer", kotoage: "hajimari", arguments: {{}});
                    test::expect_any_reject_as(actor: "issuer", kotoage: "hajimari", arguments: {{}});
                    test::assert_eq(actual: counter, expected: 1);
                }}

                }}
                "#,
                actor_account = actor_account,
                seed_hex = hex::encode(actor_seed),
            ),
        );
    let suite = discover_suite(&test_path).expect("discover suite");
    let compiled = compile_suite(&suite, false).expect("compile suite");
    let runtime = compiled
        .runtime
        .as_ref()
        .expect("standalone contract tests require a runtime artifact");
    assert_eq!(
        compiled.suite.report.artifact_hash,
        ivm::contract_code_hash(compiled.suite.program.prepared().artifact()),
        "the standalone test artifact must retain its own hash when a separate runtime artifact is present"
    );
    assert_eq!(
        runtime.report.artifact_hash,
        ivm::contract_code_hash(runtime.program.artifact()),
        "the runtime report must remain bound to the deployable runtime artifact"
    );
    assert_ne!(
        compiled.suite.report.artifact_hash, runtime.report.artifact_hash,
        "test-suite and runtime projections must retain distinct artifact identities"
    );
    let suite_metadata = ProgramMetadata::parse(compiled.suite.program.prepared().artifact())
        .expect("parse generic test-suite metadata");
    assert_eq!(
        (
            suite_metadata.metadata.version_major,
            suite_metadata.metadata.version_minor,
        ),
        (1, 1),
        "the compiler-owned test suite must remain a generic IVM 1.1 image"
    );
    let runtime_metadata = ProgramMetadata::parse(runtime.program.artifact())
        .expect("parse deployable runtime metadata");
    assert_eq!(
        (
            runtime_metadata.metadata.version_major,
            runtime_metadata.metadata.version_minor,
        ),
        (1, 1),
        "nested contract calls must use a separately compiled deployable artifact"
    );
    ivm::prepare_contract(std::sync::Arc::from(runtime.program.artifact()))
        .expect("the nested runtime artifact must satisfy production admission");
    let production_error = ivm::prepare_contract(std::sync::Arc::from(
        compiled.suite.program.prepared().artifact(),
    ))
    .expect_err("production admission must reject the generic IVM 1.1 test harness");
    assert!(
        production_error
            .to_string()
            .contains("missing required CNTR section"),
        "unexpected production-admission failure: {production_error}"
    );
    let results = execute_suite(&compiled, TraceMode::PcOnly, 2).expect("execute suite");
    let failures = results
        .iter()
        .filter(|result| !result.passed)
        .map(|result| {
            format!(
                "{}: {}",
                result.name,
                result
                    .failure
                    .as_ref()
                    .map_or_else(|| "missing failure".to_owned(), TestFailure::render)
            )
        })
        .collect::<Vec<_>>();
    assert!(
        failures.is_empty(),
        "compiled standalone tests should pass: {}",
        failures.join("; ")
    );
    assert!(
        results.iter().any(|result| result
            .trace
            .runtime
            .as_ref()
            .or(result.trace.harness.as_ref())
            .is_some_and(|trace| !trace.is_empty())),
        "expected compiled helpers to emit execution traces"
    );
}
#[test]
fn standalone_test_source_parser_rejects_public_functions() {
    let temp = TestTempDir::new();
    temp.write("demo.ko", "seiyaku Demo { fn helper() {} }");
    let test_file = temp.write(
        "demo.test.ko",
        include_str!("../fixtures/koto_v1/koto_test_driver_tests/012.ko")
            .strip_suffix('\n')
            .expect("fixture sentinel newline"),
    );
    let error = parse_program_file(&test_file)
        .expect_err("a module cannot contain a public seiyaku function");
    assert!(
        error.to_string().contains("module"),
        "unexpected error: {error}"
    );
}
#[test]
fn finalize_suite_rejects_program_without_tests() {
    let program = Program {
        permissions: Vec::new(),
        directives: Vec::new(),
        exports: Vec::new(),
        unit: kotodama_lang::ast::SourceUnit {
            kind: kotodama_lang::ast::SourceUnitKind::Module,
            name: "EmptyTests".to_string(),
        },
        items: vec![Item::Function(kotodama_lang::ast::Function {
            name: "helper".to_string(),
            params: Vec::new(),
            ret_ty: None,
            body: kotodama_lang::ast::Block {
                statements: Vec::new(),
                tail: None,
            },
            modifiers: Default::default(),
            location: kotodama_lang::ast::SourceLocation { line: 1, column: 1 },
        })],
        test_target: None,
        fixtures: Vec::new(),
    };
    let err = finalize_suite(
        PathBuf::from("/tmp/demo.ko"),
        "module EmptyTests { fn helper() {} }".to_owned(),
        program,
        Vec::new(),
    )
    .err()
    .expect("program without tests should fail");
    assert!(err.to_string().contains("no #[test] Kotodama functions"));
    assert!(
        err.to_string().contains("pass that module to `koto test`"),
        "the error says where tests live: {err}"
    );
}
#[test]
fn contract_backed_suite_preserves_runtime_coverage_and_suite_hash() {
    let source = include_str!("../fixtures/koto_v1/koto_test_driver_tests/013.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let program = parser::parse(source).expect("parse program");
    let suite = DiscoveredSuite {
        artifacts: Vec::new(),
        sources: Vec::new(),
        source_root: None,
        target_path: PathBuf::from("/tmp/demo.ko"),
        target_source: source.to_owned(),
        target_program: program,
        test_modules: Vec::new(),
        tests: vec![TestCase {
            name: "smoke".to_string(),
            fixture: None,
            path: PathBuf::from("demo.test.ko"),
            line: 6,
            column: 1,
        }],
        fixtures: HashMap::new(),
        fixture_sites: HashMap::new(),
        fixture_consts: HashMap::new(),
    };
    let compiled = compile_suite(&suite, false).expect("compile suite");
    assert_eq!(compiled.tests.len(), 1);
    let runtime = compiled
        .runtime
        .as_ref()
        .expect("contract-backed suite runtime artifact");
    assert_ne!(
        compiled.suite.report.artifact_hash, runtime.report.artifact_hash,
        "the test-suite and deployable runtime artifacts must retain distinct identities"
    );
    assert!(
        !compiled
            .suite
            .program
            .prepared()
            .contract_interface()
            .callables
            .is_empty(),
        "contract-backed suite authenticates real function roots"
    );
    let names = compiled
        .coverage_functions
        .iter()
        .map(|function| function.display_name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(names, vec!["run"]);
    let results = execute_suite(&compiled, TraceMode::Off, 1).expect("execute public wrapper");
    assert_eq!(results.len(), 1);
    assert!(results[0].passed, "{:?}", results[0].failure);
}
#[test]
fn nested_contract_effects_use_contract_subject_while_context_keeps_invoker() {
    let asset = AssetDefinitionId::derive_from_components(
        DomainId::try_new("effects", "universal").expect("asset domain"),
        "unit".parse().expect("asset name"),
    )
    .canonical_address();
    let target_source = format!(
        r#"
            seiyaku EffectIdentity {{ permission Update;
                error enum EffectError {{ WrongInvoker = 9001, }}

                kotoage fn mint(AccountId destination) authorize(Update) {{
                    require(
                        context::authority() == AccountId::parse("{DEFAULT_CALLER}"),
                        EffectError::WrongInvoker,
                    );
                    ledger::asset::mint(
                        account: destination,
                        asset_definition: AssetDefinitionId::parse("{asset}"),
                        amount: 1,
                    );
                }}
            }}
            "#,
    );
    let test_source = format!(
        r#"
            module EffectIdentityTests {{
                koto_test {{ target: "effect_identity.ko" }}

                fixture missing_subject_grant {{
                    actor("app", AccountId::parse("{DEFAULT_CALLER}"));
                    caller(AccountId::parse("{DEFAULT_CALLER}"));
                    register_asset_definition(AssetDefinitionId::parse("{asset}"));
                    grant_seiyaku_permission("app", "Update");
                }}

                fixture app_only_effect_grant {{
                    actor("app", AccountId::parse("{DEFAULT_CALLER}"));
                    caller(AccountId::parse("{DEFAULT_CALLER}"));
                    register_asset_definition(AssetDefinitionId::parse("{asset}"));
                    grant_seiyaku_permission("app", "Update");
                    grant_permission("app", "mint_asset:{asset}");
                }}

                fixture seiyaku_subject_effect_grant {{
                    actor("app", AccountId::parse("{DEFAULT_CALLER}"));
                    caller(AccountId::parse("{DEFAULT_CALLER}"));
                    register_asset_definition(AssetDefinitionId::parse("{asset}"));
                    grant_seiyaku_permission("app", "Update");
                    grant_seiyaku_effect_permission("mint_asset:{asset}");
                }}

                #[test(fixture = "missing_subject_grant")]
                fn missing_seiyaku_subject_grant_rejects() {{
                    test::expect_reject_as(
                        actor: "app",
                        kotoage: "mint",
                        arguments: {{destination: AccountId::parse("{DEFAULT_CALLER}")}},
                        expected: test::Rejection::RuntimePermissionDenied,
                    );
                }}

                #[test(fixture = "app_only_effect_grant")]
                fn application_effect_grant_does_not_authorize_contract() {{
                    test::expect_reject_as(
                        actor: "app",
                        kotoage: "mint",
                        arguments: {{destination: AccountId::parse("{DEFAULT_CALLER}")}},
                        expected: test::Rejection::RuntimePermissionDenied,
                    );
                }}

                #[test(fixture = "seiyaku_subject_effect_grant")]
                fn seiyaku_subject_effect_grant_succeeds_with_invoker_context() {{
                    test::invoke_kotoage_as(
                        actor: "app",
                        kotoage: "mint",
                        arguments: {{destination: AccountId::parse("{DEFAULT_CALLER}")}},
                    );
                }}
            }}
            "#,
    );
    let target_program = parser::parse(&target_source).expect("parse effect target");
    let test_program = parser::parse(&test_source).expect("parse effect tests");
    let suite = finalize_suite(
        PathBuf::from("/tmp/effect_identity.ko"),
        target_source,
        target_program,
        vec![DiscoveredTestModule {
            path: PathBuf::from("/tmp/effect_identity.test.ko"),
            source: test_source,
            program: test_program,
        }],
    )
    .expect("build effect identity suite");
    let compiled = compile_suite(&suite, false).expect("compile effect identity suite");
    let results =
        execute_suite(&compiled, TraceMode::Off, 1).expect("execute effect identity suite");
    assert_eq!(results.len(), 3);
    for result in results {
        assert!(
            result.passed,
            "{} failed: {}",
            result.name,
            result
                .failure
                .as_ref()
                .map_or_else(|| "unknown failure".to_owned(), TestFailure::render),
        );
    }
}
#[test]
fn build_fixture_map_rejects_duplicate_names() {
    let fixtures = vec![
        FixtureDecl {
            name: "seeded".to_string(),
            actions: Vec::new(),
        },
        FixtureDecl {
            name: "seeded".to_string(),
            actions: Vec::new(),
        },
    ];
    let err = build_fixture_map(&fixtures).expect_err("duplicate fixtures should fail");
    assert!(err.contains("duplicate fixture"));
}
#[test]
fn apply_fixture_action_rejects_unknown_action() {
    let caller = parse_account_literal(DEFAULT_CALLER).expect("caller");
    let mut host = KotoTestHost::new(
        WsvHost::new_with_subject(MockWorldStateView::default(), caller),
        None,
        HashMap::new(),
        Arc::new(SourceContext::empty("FixtureDemo")),
    );
    let mut public_inputs = BTreeMap::new();
    let err = apply_fixture_action(
        &FixtureAction {
            name: "wat".to_string(),
            args: Vec::new(),
        },
        &mut host,
        &mut public_inputs,
        &fixture_environment(),
    )
    .expect_err("unknown fixture action should fail");
    assert!(err.contains("unknown fixture action"));
}
#[test]
fn apply_fixture_action_populates_state_and_public_inputs() {
    let caller = parse_account_literal(DEFAULT_CALLER).expect("caller");
    let mut host = KotoTestHost::new(
        WsvHost::new_with_subject(MockWorldStateView::default(), caller),
        None,
        HashMap::new(),
        Arc::new(SourceContext::empty("FixtureDemo")),
    );
    let mut public_inputs = BTreeMap::new();
    apply_fixture_action(
        &FixtureAction {
            name: "state_set".to_string(),
            args: vec![
                Expr::String("demo/counter".to_string()),
                Expr::IntLiteral(7_i64.into()),
            ],
        },
        &mut host,
        &mut public_inputs,
        &fixture_environment(),
    )
    .expect("apply state_set");
    apply_fixture_action(
        &FixtureAction {
            name: "public_input".to_string(),
            args: vec![
                Expr::Call {
                    name: "Name::parse".to_string(),
                    args: vec![Expr::String("trigger_event_json".to_string())],
                    argument_names: None,
                    implicit_receiver: false,
                },
                Expr::Call {
                    name: "Json::parse".to_string(),
                    args: vec![Expr::String("{\"count\":7}".to_string())],
                    argument_names: None,
                    implicit_receiver: false,
                },
            ],
        },
        &mut host,
        &mut public_inputs,
        &fixture_environment(),
    )
    .expect("apply public_input");
    let seeded_counter = host.inner.wsv.sc_get("demo/counter").expect("seeded state");
    assert_eq!(decode_int_state_value(&seeded_counter), 7);
    let trigger_name: Name = "trigger_event_json".parse().expect("name");
    let trigger_payload = public_inputs
        .get(&trigger_name)
        .expect("trigger payload present");
    let tlv = ivm::pointer_abi::validate_tlv_bytes(trigger_payload).expect("valid tlv");
    assert_eq!(tlv.type_id, PointerType::Json);
}
#[test]
fn build_host_for_fixture_rejects_unknown_fixture() {
    let compiled = compiled_suite_with_fixtures(Vec::new());
    let err = build_host_for_fixture(&compiled, Some("missing"))
        .err()
        .expect("unknown fixture should fail");
    assert_eq!(err.kind, FailureKind::Harness);
    assert!(
        err.render().contains("unknown fixture `missing`"),
        "{}",
        err.render()
    );
}
#[test]
fn build_host_for_fixture_uses_canonical_default_caller() {
    let compiled = compiled_suite_with_fixtures(Vec::new());
    let host = build_host_for_fixture(&compiled, None).expect("build default host");
    assert_eq!(
        host.caller_subject(),
        parse_account_literal(DEFAULT_CALLER).expect("canonical default caller")
    );
}
#[test]
fn build_host_for_fixture_applies_bound_caller() {
    let fixture = FixtureDecl {
        name: "seeded".to_string(),
        actions: vec![
            FixtureAction {
                name: "caller".to_string(),
                args: vec![Expr::String(DEFAULT_CALLER.to_string())],
            },
            FixtureAction {
                name: "state_set".to_string(),
                args: vec![
                    Expr::String("demo/value".to_string()),
                    Expr::String("hello".to_string()),
                ],
            },
        ],
    };
    let compiled = compiled_suite_with_fixtures(vec![fixture]);
    let host = build_host_for_fixture(&compiled, Some("seeded")).expect("build host");
    assert_eq!(
        host.caller_subject(),
        parse_account_literal(DEFAULT_CALLER).expect("caller")
    );
    let stored = host.inner.wsv.sc_get("demo/value").expect("state value");
    let envelope = decode_pointer_state_value(&stored, StateValueKindV1::String);
    let value = ivm::pointer_abi::validate_tlv_bytes(&envelope).expect("string state TLV");
    assert_eq!(value.type_id, PointerType::Blob);
    assert_eq!(value.payload, b"hello");
}
#[test]
fn apply_fixture_action_registers_actor_seed() {
    let caller = parse_account_literal(DEFAULT_CALLER).expect("caller");
    let mut host = KotoTestHost::new(
        WsvHost::new_with_subject(MockWorldStateView::default(), caller),
        None,
        HashMap::new(),
        Arc::new(SourceContext::empty("FixtureDemo")),
    );
    let mut public_inputs = BTreeMap::new();
    let actor_seed = [7_u8; 32];
    let signing_key = SigningKey::from_bytes(&actor_seed);
    let actor_account = iroha_crypto::PublicKey::from_bytes(
        iroha_crypto::Algorithm::Ed25519,
        signing_key.verifying_key().as_bytes(),
    )
    .expect("public key")
    .to_string();
    apply_fixture_action(
        &FixtureAction {
            name: "actor".to_string(),
            args: vec![
                Expr::String("seller".to_string()),
                Expr::String(actor_account.clone()),
                Expr::String(format!("0x{}", hex::encode(actor_seed))),
            ],
        },
        &mut host,
        &mut public_inputs,
        &fixture_environment(),
    )
    .expect("register actor");
    assert!(public_inputs.is_empty());
    assert_eq!(
        host.actor_account("seller").expect("actor account"),
        parse_account_literal(&actor_account).expect("parsed actor account")
    );
    assert_eq!(
        host.actors["seller"].seed.expect("stored actor seed"),
        actor_seed
    );
}
#[test]
fn fixture_permission_grant_is_address_and_declaration_scoped() {
    let caller = parse_account_literal(DEFAULT_CALLER).expect("caller");
    let actor = caller.clone();
    let artifact = kotodama_lang::compiler::Compiler::new()
        .compile_source("seiyaku Grants { permission Apply; permission Other; kotoage fn apply() authorize(Apply) {} }")
        .expect("compile permission declarations");
    let program = ivm::prepare_contract(Arc::from(artifact)).expect("prepare contract");
    let mut host = KotoTestHost::new(
        WsvHost::new_with_subject(MockWorldStateView::default(), caller),
        Some(program),
        HashMap::new(),
        Arc::new(SourceContext::empty("FixtureDemo")),
    );
    host.register_actor("operator".to_owned(), actor.clone())
        .expect("register fixture actor");
    let mut public_inputs = BTreeMap::new();
    apply_fixture_action(
        &FixtureAction {
            name: "grant_seiyaku_permission".to_owned(),
            args: vec![
                Expr::String("operator".to_owned()),
                Expr::String("Apply".to_owned()),
            ],
        },
        &mut host,
        &mut public_inputs,
        &fixture_environment(),
    )
    .expect("grant exact fixture permission");
    let exact = PermissionToken::ContractPermission {
        contract: host.contract_address.clone(),
        permission: "Apply".parse().unwrap(),
    };
    let wrong_permission = PermissionToken::ContractPermission {
        contract: host.contract_address.clone(),
        permission: "Other".parse().unwrap(),
    };
    assert!(host.inner.wsv.has_permission(&actor, &exact));
    assert!(!host.inner.wsv.has_permission(&actor, &wrong_permission));
    host.inner.wsv.grant_permission(
        &actor,
        PermissionToken::Custom("CanInvokeContractEntrypoint".to_owned()),
    );
    assert!(
        !host.inner.wsv.has_permission(&actor, &wrong_permission),
        "name-only grants must never materialize an instance permission"
    );
    let error = apply_fixture_action(
        &FixtureAction {
            name: "grant_seiyaku_permission".to_owned(),
            args: vec![
                Expr::String("operator".to_owned()),
                Expr::String("Typo".to_owned()),
            ],
        },
        &mut host,
        &mut public_inputs,
        &fixture_environment(),
    )
    .expect_err("undeclared grants reject");
    assert!(error.contains("no declared permission `Typo`"));
}

#[test]
fn fixture_feature_actions_use_seiyaku_and_kotoage_names_only() {
    let caller = parse_account_literal(DEFAULT_CALLER).expect("caller");
    let mut host = KotoTestHost::new(
        WsvHost::new_with_subject(MockWorldStateView::default(), caller),
        None,
        HashMap::new(),
        Arc::new(SourceContext::empty("FixtureDemo")),
    );
    let mut public_inputs = BTreeMap::new();
    for retired in [
        "grant_contract_entrypoint_permission",
        "grant_seiyaku_kotoage_permission",
        "grant_contract_effect_permission",
        "grant_contract_transfer_effect_permission",
    ] {
        let error = apply_fixture_action(
            &FixtureAction {
                name: retired.to_owned(),
                args: Vec::new(),
            },
            &mut host,
            &mut public_inputs,
            &fixture_environment(),
        )
        .expect_err("English feature action must not remain compatible");
        assert!(
            error.starts_with(&format!(
                "unknown fixture action `{retired}`; the fixture actions are `actor`"
            )),
            "{error}"
        );
    }
    for (branded, arity) in [
        ("grant_seiyaku_permission", 2),
        ("grant_seiyaku_lifecycle_permission", 2),
        ("grant_seiyaku_effect_permission", 1),
        ("grant_seiyaku_transfer_effect_permission", 3),
    ] {
        let error = apply_fixture_action(
            &FixtureAction {
                name: branded.to_owned(),
                args: Vec::new(),
            },
            &mut host,
            &mut public_inputs,
            &fixture_environment(),
        )
        .expect_err("recognized branded action still requires its arguments");
        assert_eq!(
            error,
            format!("fixture action `{branded}` expects {arity} arguments, got 0")
        );
    }
    assert_eq!(
        eval_fixture_account_or_actor(&Expr::Ident("seiyaku_subject".to_owned()), &host)
            .expect("branded subject expression"),
        host.contract_subject()
    );
    assert!(
        eval_fixture_account_or_actor(&Expr::Ident("contract_subject".to_owned()), &host).is_err(),
        "English feature expression must not remain compatible"
    );
}
#[test]
fn fixture_account_metadata_uses_current_action_and_permission_names() {
    let caller = parse_account_literal(DEFAULT_CALLER).expect("caller");
    let mut host = KotoTestHost::new(
        WsvHost::new_with_subject(MockWorldStateView::default(), caller.clone()),
        None,
        HashMap::new(),
        Arc::new(SourceContext::empty("FixtureDemo")),
    );
    let mut public_inputs = BTreeMap::new();
    let mut action = FixtureAction {
        name: "set_account_metadata".to_owned(),
        args: vec![
            Expr::String(DEFAULT_CALLER.to_owned()),
            Expr::String("label".to_owned()),
            Expr::String("value".to_owned()),
        ],
    };
    apply_fixture_action(
        &action,
        &mut host,
        &mut public_inputs,
        &fixture_environment(),
    )
    .expect("set account metadata");
    assert_eq!(
        host.inner.wsv.account_detail_value(&caller, "label"),
        Some(b"value".to_vec())
    );
    action.name = "set_account_detail".to_owned();
    assert!(
        apply_fixture_action(
            &action,
            &mut host,
            &mut public_inputs,
            &fixture_environment()
        )
        .expect_err("retired action is rejected")
        .contains("unknown fixture action")
    );
    for permission in [
        parse_permission_token_name(
            &format!("set_account_metadata:{DEFAULT_CALLER}"),
            &parse_account_literal,
        ),
        parse_permission_token_json(
            &format!(r#"{{"type":"set_account_metadata","target":"{DEFAULT_CALLER}"}}"#),
            &parse_account_literal,
        ),
    ] {
        assert!(
            matches!(permission.expect("metadata permission"), PermissionToken::SetAccountDetail(account) if account == caller)
        );
    }
    assert!(
        parse_permission_token_json(
            &format!(r#"{{"type":"set_account_detail","target":"{DEFAULT_CALLER}"}}"#),
            &parse_account_literal
        )
        .is_err()
    );
}
#[test]
fn fixture_contract_effect_grant_targets_only_the_immutable_contract_subject() {
    let caller = parse_account_literal(DEFAULT_CALLER).expect("caller");
    let mut host = KotoTestHost::new(
        WsvHost::new_with_subject(MockWorldStateView::default(), caller.clone()),
        None,
        HashMap::new(),
        Arc::new(SourceContext::empty("FixtureDemo")),
    );
    host.register_actor("app".to_owned(), caller.clone())
        .expect("register app actor");
    let asset = AssetDefinitionId::derive_from_components(
        DomainId::try_new("effects", "universal").expect("domain"),
        "unit".parse().expect("asset name"),
    );
    let permission = PermissionToken::MintAsset(asset.clone());
    let mut public_inputs = BTreeMap::new();
    apply_fixture_action(
        &FixtureAction {
            name: "grant_seiyaku_effect_permission".to_owned(),
            args: vec![Expr::String(format!("mint_asset:{asset}"))],
        },
        &mut host,
        &mut public_inputs,
        &fixture_environment(),
    )
    .expect("grant contract effect permission");
    assert!(
        host.inner
            .wsv
            .has_permission(&host.contract_subject(), &permission)
    );
    assert!(
        !host.inner.wsv.has_permission(&caller, &permission),
        "contract effect grants must never leak onto the invoking application authority"
    );
}
#[test]
fn transfer_control_effects_require_exact_subject_asset_domain_and_dataspace_scope() {
    let controller = parse_account_literal(DEFAULT_CALLER).expect("controller");
    let target = AccountId::new(
        iroha_crypto::KeyPair::from_seed(vec![0x92; 32], iroha_crypto::Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    let asset = AssetDefinitionId::derive_from_components(
        DomainId::try_new("currency", "sbp").expect("asset domain"),
        "pkr".parse().expect("asset name"),
    );
    let asset_literal = asset.canonical_address();
    let mut host = KotoTestHost::new(
        WsvHost::new_with_subject(MockWorldStateView::default(), controller.clone()),
        None,
        HashMap::new(),
        Arc::new(SourceContext::empty("FixtureDemo")),
    );
    host.register_actor("controller".to_owned(), controller.clone())
        .expect("register controller");
    host.register_actor("target".to_owned(), target.clone())
        .expect("register target");
    let mut public_inputs = BTreeMap::new();
    apply_fixture_action(
        &FixtureAction {
            name: "register_asset_definition".to_owned(),
            args: vec![Expr::Call {
                name: "AssetDefinitionId::parse".to_owned(),
                args: vec![Expr::String(asset_literal.clone())],
                argument_names: None,
                implicit_receiver: false,
            }],
        },
        &mut host,
        &mut public_inputs,
        &fixture_environment(),
    )
    .expect("register control asset");
    apply_fixture_action(
        &FixtureAction {
            name: "register_account_alias".to_owned(),
            args: vec![
                Expr::String("target@hbl.sbp".to_owned()),
                Expr::String("target".to_owned()),
                Expr::IntLiteral(10_i64.into()),
            ],
        },
        &mut host,
        &mut public_inputs,
        &fixture_environment(),
    )
    .expect("register exact target alias scope");
    let availability_permission_expr = |account: &AccountId| Expr::Call {
        name: "Json::parse".to_owned(),
        args: vec![Expr::String(format!(
            r#"{{"type":"CanSetAssetTransferAvailability","account":"{account}","asset_definition":"{asset_literal}"}}"#,
        ))],
        argument_names: None,
        implicit_receiver: false,
    };
    let scoped_permission_expr = |kind: &str, domain: &str| Expr::Call {
        name: "Json::parse".to_owned(),
        args: vec![Expr::String(format!(
            r#"{{"type":"{kind}","asset_definition":"{asset_literal}","account_domain":"{domain}","account_dataspace":10}}"#,
        ))],
        argument_names: None,
        implicit_receiver: false,
    };
    let exact_holding_permission_expr = |account: &AccountId| Expr::Call {
        name: "Json::parse".to_owned(),
        args: vec![Expr::String(format!(
            r#"{{"type":"CanSetAssetHoldingLimit","account":"{account}","asset_definition":"{asset_literal}"}}"#,
        ))],
        argument_names: None,
        implicit_receiver: false,
    };
    apply_fixture_action(
        &FixtureAction {
            name: "grant_permission".to_owned(),
            args: vec![
                Expr::String("controller".to_owned()),
                availability_permission_expr(&target),
            ],
        },
        &mut host,
        &mut public_inputs,
        &fixture_environment(),
    )
    .expect("grant exact availability permission to app only");
    apply_fixture_action(
        &FixtureAction {
            name: "grant_seiyaku_effect_permission".to_owned(),
            args: vec![availability_permission_expr(&controller)],
        },
        &mut host,
        &mut public_inputs,
        &fixture_environment(),
    )
    .expect("grant wrong-account availability permission to subject");
    host.inner
        .bind_contract_runtime_context(
            controller.clone(),
            host.contract_address.clone(),
            "apply_availability".to_owned(),
        )
        .expect("bind contract runtime context");
    let call_availability = |host: &mut KotoTestHost| {
        let mut vm = IVM::new(u64::MAX);
        let account = norito::to_bytes(&target).expect("encode target account");
        let asset_bytes = norito::to_bytes(&asset).expect("encode target asset");
        let account_pointer = vm
            .alloc_input_tlv(&make_tlv(PointerType::AccountId, &account))
            .expect("allocate target account");
        let asset_pointer = vm
            .alloc_input_tlv(&make_tlv(PointerType::AssetDefinitionId, &asset_bytes))
            .expect("allocate target asset");
        vm.set_register(10, account_pointer);
        vm.set_register(11, asset_pointer);
        vm.set_register(12, 0);
        vm.set_register(13, 0);
        let reason_layout =
            ivm::sum::SumLayoutV1::option(1).expect("availability reason option layout");
        let reason_pointer = ivm::sum::allocate_words(&mut vm, reason_layout, 0, &[])
            .expect("allocate absent availability reason");
        vm.set_register(14, reason_pointer);
        host.inner.syscall(
            ivm::syscalls::SYSCALL_SET_ASSET_TRANSFER_AVAILABILITY,
            &mut vm,
        )
    };
    assert_eq!(
        call_availability(&mut host),
        Err(ivm::VMError::PermissionDenied),
        "an app grant and a wrong-account subject grant must not authorize the effect",
    );
    assert_eq!(
        host.inner.wsv.asset_transfer_availability(&target, &asset),
        None
    );
    apply_fixture_action(
        &FixtureAction {
            name: "grant_seiyaku_effect_permission".to_owned(),
            args: vec![availability_permission_expr(&target)],
        },
        &mut host,
        &mut public_inputs,
        &fixture_environment(),
    )
    .expect("grant exact availability permission to contract subject");
    call_availability(&mut host).expect("exact contract-subject availability effect succeeds");
    assert_eq!(
        host.inner.wsv.asset_transfer_availability(&target, &asset),
        Some((1, false, false))
    );
    let mut authority_vm = IVM::new(u64::MAX);
    host.inner
        .syscall(ivm::syscalls::SYSCALL_SYSVAR_AUTHORITY, &mut authority_vm)
        .expect("read invoker authority inside contract scope");
    let authority_tlv = authority_vm
        .validate_tlv(authority_vm.register(10))
        .expect("authority TLV");
    let observed_authority: AccountId =
        norito::decode_from_bytes(authority_tlv.payload).expect("decode authority");
    assert_eq!(observed_authority, controller);
    apply_fixture_action(
        &FixtureAction {
            name: "grant_seiyaku_effect_permission".to_owned(),
            args: vec![scoped_permission_expr(
                "CanSetAssetTransferDailyLimit",
                "hbl",
            )],
        },
        &mut host,
        &mut public_inputs,
        &fixture_environment(),
    )
    .expect("grant exact daily-limit permission to contract subject");
    let mut limit_vm = IVM::new(u64::MAX);
    let account = norito::to_bytes(&target).expect("encode limit target account");
    let asset_bytes = norito::to_bytes(&asset).expect("encode limit target asset");
    let account_pointer = limit_vm
        .alloc_input_tlv(&make_tlv(PointerType::AccountId, &account))
        .expect("allocate limit account");
    let asset_pointer = limit_vm
        .alloc_input_tlv(&make_tlv(PointerType::AssetDefinitionId, &asset_bytes))
        .expect("allocate limit asset");
    let cap = Quantity::from(500_u64);
    let cap_payload = QuantityValueV1::new(cap.clone())
        .encode_frame()
        .expect("encode cap quantity frame");
    let cap_pointer = limit_vm
        .alloc_input_tlv(&make_tlv(PointerType::Quantity, &cap_payload))
        .expect("allocate cap quantity");
    let cap_option = ivm::sum::allocate_words(
        &mut limit_vm,
        ivm::sum::SumLayoutV1::option(1).expect("option layout"),
        1,
        &[cap_pointer],
    )
    .expect("allocate cap option");
    limit_vm.set_register(10, account_pointer);
    limit_vm.set_register(11, asset_pointer);
    limit_vm.set_register(12, cap_option);
    host.inner
        .syscall(
            ivm::syscalls::SYSCALL_SET_ASSET_TRANSFER_DAILY_LIMIT,
            &mut limit_vm,
        )
        .expect("exact contract-subject daily limit succeeds");
    assert_eq!(
        host.inner.wsv.asset_transfer_daily_limit(&target, &asset),
        Some(Some(cap.clone()))
    );
    apply_fixture_action(
        &FixtureAction {
            name: "grant_seiyaku_effect_permission".to_owned(),
            args: vec![exact_holding_permission_expr(&target)],
        },
        &mut host,
        &mut public_inputs,
        &fixture_environment(),
    )
    .expect("grant exact holding-limit permission to contract subject");
    let mut holding_vm = IVM::new(u64::MAX);
    let account_pointer = holding_vm
        .alloc_input_tlv(&make_tlv(PointerType::AccountId, &account))
        .expect("allocate holding-limit account");
    let asset_pointer = holding_vm
        .alloc_input_tlv(&make_tlv(PointerType::AssetDefinitionId, &asset_bytes))
        .expect("allocate holding-limit asset");
    let limit_pointer = holding_vm
        .alloc_input_tlv(&make_tlv(PointerType::Quantity, &cap_payload))
        .expect("allocate holding-limit quantity");
    let limit_option = ivm::sum::allocate_words(
        &mut holding_vm,
        ivm::sum::SumLayoutV1::option(1).expect("holding option layout"),
        1,
        &[limit_pointer],
    )
    .expect("allocate holding-limit option");
    holding_vm.set_register(10, account_pointer);
    holding_vm.set_register(11, asset_pointer);
    holding_vm.set_register(12, limit_option);
    host.inner
        .syscall(
            ivm::syscalls::SYSCALL_SET_ASSET_HOLDING_LIMIT,
            &mut holding_vm,
        )
        .expect("exact contract holding limit succeeds");
    assert_eq!(
        host.inner.wsv.asset_holding_limit(&target, &asset),
        Some(Some(cap))
    );
}
#[test]
fn fixture_account_alias_registration_is_canonical_unique_and_resolvable() {
    let caller = parse_account_literal(DEFAULT_CALLER).expect("caller");
    let other = AccountId::new(
        iroha_crypto::KeyPair::from_seed(vec![0x91; 32], iroha_crypto::Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    let mut host = KotoTestHost::new(
        WsvHost::new_with_subject(MockWorldStateView::default(), caller.clone()),
        None,
        HashMap::new(),
        Arc::new(SourceContext::empty("FixtureDemo")),
    );
    host.register_actor("merchant".to_owned(), caller.clone())
        .expect("register merchant actor");
    host.register_actor("other".to_owned(), other)
        .expect("register other actor");
    let mut public_inputs = BTreeMap::new();
    let registration = FixtureAction {
        name: "register_account_alias".to_owned(),
        args: vec![
            Expr::String("merchant@hbl.sbp".to_owned()),
            Expr::String("merchant".to_owned()),
        ],
    };
    apply_fixture_action(
        &registration,
        &mut host,
        &mut public_inputs,
        &fixture_environment(),
    )
    .expect("register canonical domain-scoped account alias");
    let mut vm = IVM::new(u64::MAX);
    let pointer = vm
        .alloc_input_tlv(&make_tlv(PointerType::Blob, b"merchant@hbl.sbp"))
        .expect("allocate alias argument");
    vm.set_register(10, pointer);
    host.inner
        .syscall(ivm::syscalls::SYSCALL_RESOLVE_ACCOUNT_ALIAS, &mut vm)
        .expect("resolve seeded alias");
    let resolved_tlv = vm
        .validate_tlv(vm.register(10))
        .expect("resolved account TLV");
    assert_eq!(resolved_tlv.type_id, PointerType::AccountId);
    let resolved: AccountId =
        norito::decode_from_bytes(resolved_tlv.payload).expect("decode resolved account");
    assert_eq!(resolved, caller);
    let duplicate = apply_fixture_action(
        &registration,
        &mut host,
        &mut public_inputs,
        &fixture_environment(),
    )
    .expect_err("duplicate alias registration must fail");
    assert!(duplicate.contains("duplicate account alias registration"));
    let conflict = apply_fixture_action(
        &FixtureAction {
            name: "register_account_alias".to_owned(),
            args: vec![
                Expr::String("merchant@hbl.sbp".to_owned()),
                Expr::String("other".to_owned()),
            ],
        },
        &mut host,
        &mut public_inputs,
        &fixture_environment(),
    )
    .expect_err("conflicting alias registration must fail");
    assert!(conflict.contains("conflicting account alias registration"));
    for alias in [
        "merchant",
        "merchant@@sbp",
        "merchant@",
        "@sbp",
        "merchant@hbl.sbp.extra",
        " merchant@sbp",
        "merchant@sbp ",
    ] {
        let error = apply_fixture_action(
            &FixtureAction {
                name: "register_account_alias".to_owned(),
                args: vec![
                    Expr::String(alias.to_owned()),
                    Expr::String("merchant".to_owned()),
                ],
            },
            &mut host,
            &mut public_inputs,
            &fixture_environment(),
        )
        .expect_err("noncanonical alias registration must fail");
        assert!(!error.is_empty(), "missing rejection for `{alias}`");
    }
}
#[test]
fn helper_parsers_reject_invalid_numeric_and_mintability() {
    let environment = fixture_environment();
    let err = eval_numeric_expr(&Expr::IntLiteral((-1_i64).into()), &environment)
        .expect_err("negative quantity should fail");
    assert!(err.contains("negative balances are not allowed"));
    let err = eval_quantity_expr(&Expr::String("-1".to_owned()), &environment)
        .expect_err("negative decimal quantity should fail");
    assert!(err.contains("negative balances are not allowed"), "{err}");
    let err = eval_mintable_expr(&Expr::String("sometimes".to_string()))
        .expect_err("invalid mintability should fail");
    assert!(err.contains("unsupported mintability"));
    let err = expect_arg_count(
        &FixtureAction {
            name: "caller".to_string(),
            args: Vec::new(),
        },
        1,
    )
    .expect_err("wrong arg count should fail");
    assert!(err.contains("expects 1 arguments"));
}
#[test]
fn parse_permission_helpers_cover_targeted_and_json_forms() {
    let domain = DomainId::try_new("wonderland", "universal").expect("domain");
    let asset = AssetDefinitionId::derive_from_components(domain, "rose".parse().expect("name"));
    let token = parse_permission_token_name(&format!("mint_asset:{asset}"), &parse_account_literal)
        .expect("parse mint asset token");
    assert!(matches!(token, PermissionToken::MintAsset(id) if id == asset));
    let token = parse_permission_token_json(
        r#"{"type":"custom","name":"demo.permission"}"#,
        &parse_account_literal,
    )
    .expect("parse custom permission json");
    assert!(matches!(token, PermissionToken::Custom(name) if name == "demo.permission"));
    let err = parse_permission_token_json(r#"{"target":"missing-type"}"#, &parse_account_literal)
        .expect_err("missing type should fail");
    assert!(err.contains("missing `type`"));
    let owner = parse_account_literal(DEFAULT_CALLER).expect("asset owner");
    let bucket = AssetId::with_scope(
        asset.clone(),
        owner,
        AssetBalanceScope::Dataspace(DataSpaceId::new(10)),
    );
    let token = parse_permission_token_json(
        &format!(
            r#"{{"type":"CanTransferAsset","asset":"{}"}}"#,
            bucket.canonical_literal(),
        ),
        &parse_account_literal,
    )
    .expect("parse exact transfer bucket permission");
    assert!(matches!(token, PermissionToken::TransferAssetBucket(id) if id == bucket));
    for invalid in [
        format!(
            r#"{{"type":"CanTransferAsset","asset":"{}","asset_definition":"{}"}}"#,
            bucket.canonical_literal(),
            asset.canonical_address(),
        ),
        format!(
            r#"{{"type":"CanTransferAsset","asset":"{}#dataspace:010"}}"#,
            AssetId::new(
                asset.clone(),
                parse_account_literal(DEFAULT_CALLER).expect("owner")
            )
            .canonical_literal(),
        ),
    ] {
        parse_permission_token_json(&invalid, &parse_account_literal)
            .expect_err("ambiguous or non-canonical transfer bucket must fail");
    }
    let availability_account = parse_account_literal(DEFAULT_CALLER).expect("account");
    let availability = parse_permission_token_json(&format!(
            r#"{{"type":"CanSetAssetTransferAvailability","account":"{availability_account}","asset_definition":"{}"}}"#,
            asset.canonical_address(),
        ), &parse_account_literal)
        .expect("parse exact availability permission");
    assert!(matches!(
        availability,
        PermissionToken::SetAssetTransferAvailability {
            account,
            asset_definition,
        } if account == availability_account && asset_definition == asset
    ));
    let daily_limit = parse_permission_token_json(&format!(
            r#"{{"type":"CanSetAssetTransferDailyLimit","asset_definition":"{}","account_domain":"hbl","account_dataspace":10}}"#,
            asset.canonical_address(),
        ), &parse_account_literal)
        .expect("parse scoped daily-limit permission");
    assert!(matches!(
        daily_limit,
        PermissionToken::SetAssetTransferDailyLimit {
            asset_definition,
            account_domain,
            account_dataspace,
        } if asset_definition == asset
            && account_domain.as_ref() == "hbl"
            && account_dataspace == DataSpaceId::new(10)
    ));
    let holding_limit = parse_permission_token_json(&format!(
            r#"{{"type":"CanSetAssetHoldingLimit","account":"{availability_account}","asset_definition":"{}"}}"#,
            asset.canonical_address(),
        ), &parse_account_literal)
        .expect("parse exact holding-limit permission");
    assert!(matches!(
        holding_limit,
        PermissionToken::SetAssetHoldingLimit {
            account,
            asset_definition,
        } if account == availability_account && asset_definition == asset
    ));
    for invalid in [
        format!(
            r#"{{"type":"CanSetAssetTransferAvailability","asset_definition":"{}"}}"#,
            asset.canonical_address(),
        ),
        format!(
            r#"{{"type":"CanSetAssetTransferAvailability","account":"not-an-account","asset_definition":"{}"}}"#,
            asset.canonical_address(),
        ),
        format!(
            r#"{{"type":"CanSetAssetTransferAvailability","account":"{availability_account}","asset_definition":"{}","legacy":true}}"#,
            asset.canonical_address(),
        ),
    ] {
        parse_permission_token_json(&invalid, &parse_account_literal)
            .expect_err("legacy, ambiguous, or extra transfer-control scope must fail");
    }
}
#[test]
fn permission_and_json_helpers_reject_invalid_inputs() {
    let err = parse_permission_token_name("mint_asset:not-an-asset", &parse_account_literal)
        .expect_err("invalid targeted permission should fail");
    assert!(err.contains("invalid asset definition id"));
    let err = eval_json_payload(&[Expr::IntLiteral(7_i64.into())])
        .expect_err("non-string json should fail");
    assert!(err.contains("expects a string literal"), "{err}");
}
#[test]
fn eval_envelope_expr_encodes_pointer_variants() {
    let account_expr = Expr::Call {
        name: "AccountId::parse".to_string(),
        args: vec![Expr::String(DEFAULT_CALLER.to_string())],
        argument_names: None,
        implicit_receiver: false,
    };
    let account_ptr = eval_envelope_expr(&account_expr).expect("account envelope");
    let account_tlv = ivm::pointer_abi::validate_tlv_bytes(&account_ptr).expect("account tlv");
    assert_eq!(account_tlv.type_id, PointerType::AccountId);
    let name_expr = Expr::Call {
        name: "Name::parse".to_string(),
        args: vec![Expr::String("cursor".to_string())],
        argument_names: None,
        implicit_receiver: false,
    };
    let name_ptr = eval_envelope_expr(&name_expr).expect("name envelope");
    let name_tlv = ivm::pointer_abi::validate_tlv_bytes(&name_ptr).expect("name tlv");
    assert_eq!(name_tlv.type_id, PointerType::Name);
    let alternate_flags =
        norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
    let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
    assert_eq!(
        eval_envelope_expr(&account_expr).expect("ambient account envelope"),
        account_ptr
    );
    assert_eq!(
        eval_envelope_expr(&name_expr).expect("ambient name envelope"),
        name_ptr
    );
}
#[test]
fn fixture_evaluators_reject_retired_flat_constructor_aliases() {
    let call = |name: &str, value: &str| Expr::Call {
        name: name.to_owned(),
        args: vec![Expr::String(value.to_owned())],
        argument_names: None,
        implicit_receiver: false,
    };
    assert!(eval_account_expr(&call("account_id", DEFAULT_CALLER)).is_err());
    assert!(eval_domain_expr(&call("domain_id", "wonderland")).is_err());
    assert!(eval_asset_definition_expr(&call("asset_definition", "rose#wonderland")).is_err());
    assert!(eval_name_expr(&call("name", "cursor")).is_err());
    assert!(eval_envelope_expr(&call("json", "{}")).is_err());
    assert!(eval_actor_alias_expr(&call("name", "issuer")).is_err());
    assert!(eval_seed_expr(&call("blob", &format!("0x{}", "00".repeat(32)))).is_err());
}
#[test]
fn vm_errors_classify_into_distinct_failure_kinds_without_debug_formatting() {
    use ivm_abi::error::VmTrapKind as Trap;
    for (trap, kind) in [
        (Trap::PermissionDenied, FailureKind::PermissionDenied),
        (Trap::NumericFault, FailureKind::NumericFault),
        (Trap::OutOfGas, FailureKind::GasExhausted),
        (Trap::ExceededMaxCycles, FailureKind::GasExhausted),
        (Trap::DecodeError, FailureKind::Decode),
        (Trap::AssertionFailed, FailureKind::Assertion),
        (Trap::InvalidOpcode, FailureKind::Trap),
    ] {
        let failure = classify_vm_error(&ivm::VMError::DecodeError, Some(trap));
        assert_eq!(failure.kind, kind, "{trap:?}");
        assert!(
            !failure.render().contains("DecodeError"),
            "{}",
            failure.render()
        );
    }
    let descriptor = ivm_abi::error_types::list_error_type();
    let abort = ivm::VMError::ContractAbort {
        contract: "Vault".into(),
        name: descriptor.variants[0].name.clone(),
        message: None,
        error_type: descriptor.identity.clone(),
        schema_hash: descriptor.schema_hash(),
        code: descriptor.variants[0].code,
    };
    let failure = classify_vm_error(&abort, Some(Trap::ContractAbort));
    assert_eq!(failure.kind, FailureKind::Rejected);
    assert!(failure.message.contains(&format!(
        "`{}::{}`",
        descriptor.identity, descriptor.variants[0].name
    )));
    assert!(!failure.render().contains("schema_hash"));
}
#[test]
fn failure_rendering_has_kind_location_and_details() {
    let failure = TestFailure::new(FailureKind::Lifecycle, "pending hajimari")
        .at(Some("tests/a.test.ko:3:5".to_owned()))
        .at(Some("ignored".to_owned()))
        .detail("help: invoke it first");
    assert_eq!(
        failure.render(),
        "lifecycle violation at tests/a.test.ko:3:5: pending hajimari\n  help: invoke it first"
    );
    // Help lines follow the context lines attached after them.
    let failure = failure.detail("while the current caller called `current`");
    assert_eq!(
        failure.render(),
        "lifecycle violation at tests/a.test.ko:3:5: pending hajimari\n  while the current caller called `current`\n  help: invoke it first"
    );
    assert_eq!(FailureKind::Lifecycle.slug(), "lifecycle");
    for kind in [
        FailureKind::Assertion,
        FailureKind::Rejected,
        FailureKind::PermissionDenied,
        FailureKind::NumericFault,
        FailureKind::GasExhausted,
        FailureKind::Arguments,
        FailureKind::Decode,
        FailureKind::Lifecycle,
        FailureKind::Expectation,
        FailureKind::Harness,
        FailureKind::Trap,
    ] {
        assert!(!kind.label().is_empty() && !kind.slug().contains(' '));
    }
}
#[test]
fn coverage_helper_functions_handle_internal_and_boundary_cases() {
    assert_eq!(normalize_user_function_name("__entrypoint_impl__run"), None);
    assert_eq!(normalize_user_function_name("__lowered_internal"), None);
    assert_eq!(normalize_user_function_name("run"), Some("run"));
    let function = CoverageFunction {
        display_name: "run".to_string(),
        line: 3,
        pc_start: 10,
        pc_end: 20,
    };
    let executed = HashSet::from([9_u64, 10, 19, 20]);
    assert!(function_hit(&function, &executed));
    // Only executions inside `[pc_start, pc_end)` count toward the function's profile.
    let executions = BTreeMap::from([(9_u64, 4_u64), (10, 3), (19, 2), (20, 7)]);
    assert_eq!(executed_instructions(&function, &executions), 5);
    assert_eq!(percentage(0, 0), 100.0);
    assert_eq!(percentage(1, 4), 25.0);
}
#[test]
fn collect_tests_rejects_duplicate_test_names() {
    let program = Program {
        permissions: Vec::new(),
        directives: Vec::new(),
        exports: Vec::new(),
        unit: kotodama_lang::ast::SourceUnit {
            kind: kotodama_lang::ast::SourceUnitKind::Module,
            name: "DuplicateTests".to_string(),
        },
        items: vec![
            test_function("smoke", None),
            test_function("smoke", Some("seeded")),
        ],
        test_target: None,
        fixtures: Vec::new(),
    };
    let mut names = HashSet::new();
    let mut tests = Vec::new();
    let err = collect_tests_into(&program, Path::new("demo.ko"), &mut names, &mut tests)
        .expect_err("duplicate test names should fail");
    assert!(err.contains("duplicate test function"));
}

#[test]
fn current_caller_public_invocation_executes_nested_helpers_and_typed_returns() {
    let temp = TestTempDir::new();
    let path = temp.write("current_caller.ko", r#"
seiyaku Rewards {
    fn points(int coffees) -> int {
        if coffees < 0 { return 0; }
        return coffees * 10;
    }
    view fn quote(int coffees) authorize(anyone) -> int { return points(coffees: coffees); }
    view fn pair(int coffees) authorize(anyone) -> (int, int) { return (coffees, points(coffees: coffees)); }
    #[test]
    fn negative_quote() {
        let result = test::invoke_kotoage(kotoage: "quote", arguments: {coffees: -1});
        test::assert_eq(actual: result, expected: 0);
    }
    #[test]
    fn repeated_quote_and_tuple() {
        let first = test::invoke_kotoage(kotoage: "quote", arguments: {coffees: 3});
        let second = test::invoke_kotoage(kotoage: "quote", arguments: {coffees: 1});
        let quoted_pair = test::invoke_kotoage(kotoage: "pair", arguments: {coffees: 3});
        test::assert_eq(actual: first, expected: 30);
        test::assert_eq(actual: second, expected: 10);
        test::assert_eq(actual: quoted_pair.0, expected: 3);
        test::assert_eq(actual: quoted_pair.1, expected: 30);
    }
}
"#);
    let suite = discover_suite(&path).expect("discover current-caller tests");
    let compiled = compile_suite(&suite, false).expect("compile current-caller tests");
    let results =
        execute_suite(&compiled, TraceMode::Off, 1).expect("execute current-caller tests");
    assert_eq!(results.len(), 2);
    for result in results {
        assert!(result.passed, "{}: {:?}", result.name, result.failure);
    }
}

#[test]
fn current_caller_public_invocation_enforces_arguments_and_declared_permissions() {
    for (name, source, expected) in [
        (
            "arguments.ko",
            r#"seiyaku Arguments {
                view fn quote(int count) authorize(anyone) -> int { return count; }
                fn missing_count() -> Json { return json { other: 1 }; }
                #[test] fn malformed() {
                    test::invoke_kotoage(kotoage: "quote", arguments: missing_count());
                }
            }"#,
            "E_TEST_ARGUMENT_RECORD",
        ),
        (
            "permissions.ko",
            r#"seiyaku Permissions { permission UnrequestedBoundaryPermission;
                kotoage fn restricted() authorize(UnrequestedBoundaryPermission) {}
                #[test] fn denied() {
                    test::invoke_kotoage(kotoage: "restricted", arguments: {});
                }
            }"#,
            "lacks the `UnrequestedBoundaryPermission` permission",
        ),
    ] {
        let temp = TestTempDir::new();
        let path = temp.write(name, source);
        let suite = discover_suite(&path).expect("discover rejected public invocation");
        if name == "arguments.ko" {
            let error = compile_suite(&suite, false)
                .err()
                .expect("untyped arguments fail compilation");
            assert!(error.to_string().contains(expected), "{error}");
            continue;
        }
        let compiled = compile_suite(&suite, false).expect("compile rejected public invocation");
        let results = execute_suite(&compiled, TraceMode::Off, 1).expect("execute rejection probe");
        assert_eq!(results.len(), 1);
        assert!(!results[0].passed);
        assert!(
            results[0]
                .failure
                .as_ref()
                .unwrap()
                .render()
                .contains(expected),
            "{:?}",
            results[0].failure
        );
    }
}

#[test]
fn public_test_invocation_transfers_wide_results_through_owned_table() {
    let temp = TestTempDir::new();
    let types = std::iter::repeat_n("int", 80)
        .collect::<Vec<_>>()
        .join(", ");
    let values = (0..80)
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let source = format!(
        r#"
seiyaku WideResults {{
    view fn values() authorize(anyone) -> ( {types}) {{ return ({values}); }}
    #[test]
    fn wide() {{
        let result = test::invoke_kotoage(kotoage: "values", arguments: {{}});
        test::assert_eq(actual: result.0, expected: 0);
        test::assert_eq(actual: result.13, expected: 13);
        test::assert_eq(actual: result.64, expected: 64);
        test::assert_eq(actual: result.79, expected: 79);
    }}
}}
"#
    );
    let path = temp.write("wide_results.ko", &source);
    let suite = discover_suite(&path).expect("discover wide result test");
    let compiled = compile_suite(&suite, false).expect("compile wide result test");
    let results = execute_suite(&compiled, TraceMode::Off, 1).expect("execute wide result test");
    assert_eq!(results.len(), 1);
    assert!(results[0].passed, "{:?}", results[0].failure);
}

#[test]
fn public_test_invocation_roundtrips_nominal_empty_products() {
    let temp = TestTempDir::new();
    let path = temp.write("empty_products.ko", r#"
seiyaku EmptyProducts {
    struct Empty {}
    view fn echo(Empty value) authorize(anyone) -> Empty { value }
    view fn list(List<Empty, 2> values) authorize(anyone) -> List<Empty, 2> { values }
    #[test]
    fn roundtrip() {
        let value = test::invoke_kotoage(kotoage: "echo", arguments: {value: Empty {  }});
        test::assert(value == Empty {});
        let values = test::invoke_kotoage(kotoage: "list", arguments: {values: [Empty {  }, Empty {  }]});
        test::assert(values == [Empty {}, Empty {}]);
    }
}
"#);
    let suite = discover_suite(&path).expect("discover empty-product test");
    let compiled = compile_suite(&suite, false).expect("compile empty-product test");
    let results = execute_suite(&compiled, TraceMode::Off, 1).expect("execute empty-product test");
    assert_eq!(results.len(), 1);
    assert!(results[0].passed, "{:?}", results[0].failure);
}

#[test]
fn public_test_invocation_roundtrips_returned_state_cursor_in_typed_arguments() {
    let root = SourceModuleUnit {
        source_name: "tests/pagination.ko".to_owned(),
        source: r#"
seiyaku Pagination {
    state StateMap<int, int> Entries;
    hajimari() {
        Entries[1] = 10;
        Entries[2] = 20;
    }
    view fn page(Option<StateCursor<int>> after) authorize(anyone) -> StatePage<int, int, 1> {
        Entries.page(after: after, limit: 1)
    }
    fixture owner {
        grant_seiyaku_lifecycle_permission(AccountId::parse("sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"), "hajimari");
    }
    #[test(fixture = owner)]
    fn traverses_pages() {
        test::invoke_kotoage(kotoage: "hajimari", arguments:  {});
        let first = test::invoke_kotoage(kotoage: "page", arguments: {after: Option::none});
        test::assert_eq(actual: first.items, expected: [(1, 10)]);
        test::assert(match first.next { Option::some(_) => true, Option::none => false });
        let second = test::invoke_kotoage(kotoage: "page", arguments:  { after: first.next });
        test::assert_eq(actual: second.items, expected: [(2, 20)]);
        let terminal = test::invoke_kotoage(kotoage: "page", arguments:  { after: second.next });
        test::assert_eq(actual: terminal.items.len(), expected: 0);
        test::assert(match terminal.next { Option::some(_) => false, Option::none => true });
    }
}
"#.to_owned(),
    };
    let report = run_tests_structured_source_with_modules_v1(
        &KotoTestRunRequestV1::new(&root.source_name, 753),
        &root,
        &KotoTestModuleGraphV1::default(),
    )
    .expect("compile and execute cursor round trip");
    assert_eq!(report.passed(), 1, "{report:?}");
}

#[test]
fn invocation_alias_decoding_preserves_read_deferral_before_test_failure() {
    for target_actor in [false, true] {
        let caller = parse_account_literal(DEFAULT_CALLER).expect("caller");
        let mut host = KotoTestHost::new(
            WsvHost::new_with_subject(MockWorldStateView::default(), caller),
            None,
            HashMap::new(),
            Arc::new(SourceContext::empty("FixtureDemo")),
        );
        let budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
        let mut vm = IVM::try_new_with_memory_budget(u64::MAX, &budget).unwrap();
        let envelope = make_tlv(PointerType::Blob, b"unknown");
        vm.memory.preload_input(0, &envelope).unwrap();
        let register = if target_actor { 10 } else { 11 };
        vm.set_register(register, ivm::Memory::INPUT_START);
        let occupied = budget.reserved_bytes();
        budget.set_limit_bytes(occupied);
        let refusal = vm.memory.load_u8(ivm::Memory::INPUT_START).unwrap_err();
        assert!(matches!(refusal, ivm::VMError::AllocationDeferred(_)));
        assert_eq!(host.invoke_entrypoint(&mut vm, false), Err(refusal));
        assert_eq!(host.last_test_error(), None);
        assert_eq!(vm.register(register), ivm::Memory::INPUT_START);
        assert_eq!(budget.reserved_bytes(), occupied);
        // Restore credit and retain the deterministic unknown-actor failure.
        if target_actor {
            budget.set_limit_bytes(occupied + 8 * std::mem::size_of::<ivm::AccessRange>());
            assert_eq!(
                host.invoke_entrypoint(&mut vm, false),
                Err(ivm::VMError::AssertionFailed)
            );
            assert!(host.last_test_error().unwrap().contains("unknown actor"));
        }
        drop(vm);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn multifile_suite_discovers_and_executes_included_tests_with_local_modules() {
    let temp = TestTempDir::new();
    let root = temp.write(
        "src/app.ko",
        "seiyaku App { include \"parts/tests.ko\"; import \"math.ko\" as arith; }",
    );
    temp.write(
        "src/parts/tests.ko",
        "#[test] fn included() { test::assert(arith::value() == 7); }",
    );
    temp.write(
        "src/math.ko",
        "module Math { export fn value() -> int { return 7; } }",
    );
    temp.write("src/unrelated.ko", "this file is deliberately invalid");
    let suite = discover_suite(&root).expect("discover declared closure");
    assert_eq!(
        suite
            .tests
            .iter()
            .map(|test| test.name.as_str())
            .collect::<Vec<_>>(),
        ["included"]
    );
    assert_eq!(suite.sources.len(), 2);
    let report = run_tests_structured_v1(&KotoTestRunRequestV1::new(&root, 753))
        .expect("execute included tests");
    assert!(report.is_success());
}
#[test]
fn immutable_source_suite_uses_supplied_include_and_never_loads_ambient_file() {
    let root = SourceModuleUnit {
        source_name: "tests/app.ko".into(),
        source: "seiyaku App { include \"body.ko\"; }".into(),
    };
    let modules = KotoTestModuleGraphV1 {
        artifacts: Vec::new(),
        sources: vec![SourceModuleUnit {
            source_name: "tests/body.ko".into(),
            source: "#[test] fn included() { test::assert(true); }".into(),
        }],
        imports: Vec::new(),
        packages: Vec::new(),
    };
    let report = run_tests_structured_source_with_modules_v1(
        &KotoTestRunRequestV1::new(&root.source_name, 753),
        &root,
        &modules,
    )
    .expect("immutable included test");
    assert!(report.is_success());
    assert_eq!(report.cases.len(), 1);
}
#[test]
fn test_discovery_keeps_import_and_included_parse_errors_structured() {
    let temp = TestTempDir::new();
    let path = temp.write(
        "app.ko",
        r#"seiyaku App {
        import "feemath" as fees;
        #[test] fn check() { test::assert(true); }
    }"#,
    );
    let error = run_tests_structured_v1(&KotoTestRunRequestV1::new(&path, 753))
        .expect_err("invalid import path");
    let diagnostics = error.diagnostics.expect("import resolution diagnostics");
    assert!(
        diagnostics
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "E_INVALID_SOURCE_PATH")
    );
    assert!(
        diagnostics
            .diagnostics
            .iter()
            .all(|diagnostic| !diagnostic.message.starts_with("error["))
    );

    let root = SourceModuleUnit {
        source_name: "tests/app.ko".to_owned(),
        source: "seiyaku App { include \"body.ko\"; }".to_owned(),
    };
    let modules = KotoTestModuleGraphV1 {
        artifacts: Vec::new(),
        sources: vec![SourceModuleUnit {
            source_name: "tests/body.ko".to_owned(),
            source: "#[test] fn broken() { let int value = 1 }".to_owned(),
        }],
        ..KotoTestModuleGraphV1::default()
    };
    let error = run_tests_structured_source_with_modules_v1(
        &KotoTestRunRequestV1::new(&root.source_name, 753),
        &root,
        &modules,
    )
    .expect_err("invalid included test");
    let diagnostics = error.diagnostics.expect("included parser diagnostics");
    assert!(diagnostics.diagnostics.iter().any(|diagnostic| {
        diagnostic
            .primary_span
            .as_ref()
            .is_some_and(|span| span.source.as_deref() == Some("tests/body.ko"))
    }));
}
/// A seiyaku in `contracts/` and its standalone tests in `tests/`, the layout `musubi new` uses.
fn write_ledger_package(temp: &TestTempDir, tests: &str) -> PathBuf {
    temp.write(
        "contracts/ledger.ko",
        r#"seiyaku Ledger { permission Renew;
    error enum LedgerError { Expired = 1, }
    struct Pair { int left, string right }
    state int balance;
    hajimari() { balance = 100; }
    kaizen() {}
    kotoage fn renew(int until) authorize(Renew) {
        require(context::block_height() <= until, LedgerError::Expired);
        balance = balance + 1;
    }
    view fn height() authorize(anyone) -> int { return context::block_height(); }
    view fn time() authorize(anyone) -> int { return context::transaction_time_ms(); }
    view fn pair() authorize(anyone) -> Pair { return Pair { left: 1, right: "two" }; }
}
"#,
    );
    temp.write(
        "tests/ledger.test.ko",
        &format!(
            r#"module LedgerTests {{
    koto_test {{ target: "../contracts/ledger.ko" }}
    fixture people {{
        actor("alice");
        actor("bob");
        grant_seiyaku_permission("alice", "Renew");
        grant_seiyaku_lifecycle_permission(AccountId::parse("{DEFAULT_CALLER}"), "hajimari");
    }}
    fn activate() {{
        test::invoke_kotoage(kotoage: "hajimari", arguments: {{}});
    }}
{tests}
}}
"#
        ),
    )
}
fn run_ledger_tests(tests: &str) -> Vec<TestRunResult> {
    let temp = TestTempDir::new();
    let path = write_ledger_package(&temp, tests);
    let suite = discover_suite(&path).expect("discover ledger package without --source-root");
    let compiled = compile_suite(&suite, false).expect("compile ledger tests");
    execute_suite(&compiled, TraceMode::Off, 1).expect("execute ledger tests")
}
fn failure_of<'a>(results: &'a [TestRunResult], name: &str) -> &'a TestFailure {
    results
        .iter()
        .find(|result| result.name == name)
        .and_then(|result| result.failure.as_ref())
        .unwrap_or_else(|| panic!("`{name}` must fail"))
}
#[test]
fn block_height_and_time_are_test_controlled_and_helpers_may_use_test_builtins() {
    let results = run_ledger_tests(
        r#"
    #[test(fixture = "people")]
    fn block_height_controls_renewal() {
        activate();
        test::set_block_height(height: 10);
        test::invoke_kotoage_as(actor: "alice", kotoage: "renew", arguments: {until: 12});
        test::advance_blocks(count: 5);
        let observed_height = test::invoke_kotoage(kotoage: "height", arguments: {});
        test::assert_eq(actual: observed_height, expected: 15);
        test::expect_reject_as(actor: "alice", kotoage: "renew", arguments: {until: 12}, expected: LedgerError::Expired);
        test::set_transaction_time_ms(time_ms: 1234);
        let observed_time = test::invoke_kotoage(kotoage: "time", arguments: {});
        test::assert_eq(actual: observed_time, expected: 1234);
        test::assert_eq(actual: balance, expected: 101);
    }
"#,
    );
    assert!(
        results.iter().all(|result| result.passed),
        "{:?}",
        results
            .iter()
            .filter_map(|result| result.failure.as_ref().map(TestFailure::render))
            .collect::<Vec<_>>()
    );
    let calls = results[0]
        .calls
        .iter()
        .map(|call| call.entrypoint.as_str())
        .collect::<Vec<_>>();
    assert_eq!(calls, ["hajimari", "renew", "height", "renew", "time"]);
    assert!(
        results[0]
            .calls
            .iter()
            .all(|call| call.gas > 0 && call.cycles > 0)
    );
    assert!(results[0].gas() > 0 && results[0].cycles() > results[0].gas().min(1));
}
#[test]
fn assertions_report_location_source_message_and_typed_values() {
    let results = run_ledger_tests(
        r#"
    #[test(fixture = "people")]
    fn generic_equality_passes() {
        activate();
        let returned = test::invoke_kotoage(kotoage: "pair", arguments: {});
        test::assert_eq(actual: returned, expected: Pair { left: 1, right: "two" });
        test::assert_eq(actual: "vault", expected: "vault");
        test::assert_eq(actual: true, expected: true);
    }
    #[test(fixture = "people")]
    fn struct_mismatch() {
        activate();
        let returned = test::invoke_kotoage(kotoage: "pair", arguments: {});
        test::assert_eq(actual: returned, expected: Pair { left: 2, right: "two" }, message: "pair mismatch");
    }
    #[test(fixture = "people")]
    fn account_mismatch() {
        test::assert_eq(actual: test::actor_account("alice"), expected: test::actor_account("bob"));
    }
    #[test(fixture = "people")]
    fn plain_assert_keeps_its_message() {
        test::assert(1 > 2, message: "one is not greater than two");
    }
"#,
    );
    let passed = results
        .iter()
        .find(|result| result.name == "generic_equality_passes")
        .expect("generic test");
    assert!(
        passed.passed,
        "{:?}",
        passed.failure.as_ref().map(TestFailure::render)
    );
    let structure = failure_of(&results, "struct_mismatch");
    assert_eq!(structure.kind, FailureKind::Assertion);
    assert_eq!(structure.message, "pair mismatch");
    let location = structure.location.as_deref().expect("assertion location");
    assert!(
        location.ends_with("tests/ledger.test.ko:25:9"),
        "{location}"
    );
    assert!(
        structure.details[0].starts_with("test::assert_eq(actual: returned, expected: Pair {"),
        "{:?}",
        structure.details
    );
    assert!(
        structure
            .details
            .contains(&"actual:   Pair { left: 1, right: \"two\" }".to_owned()),
        "{:?}",
        structure.details
    );
    assert!(
        structure
            .details
            .contains(&"expected: Pair { left: 2, right: \"two\" }".to_owned()),
        "{:?}",
        structure.details
    );
    let accounts = failure_of(&results, "account_mismatch").render();
    assert!(accounts.contains("/* actor \"alice\" */"), "{accounts}");
    assert!(accounts.contains("/* actor \"bob\" */"), "{accounts}");
    assert!(accounts.contains("AccountId::parse(\""), "{accounts}");
    let plain = failure_of(&results, "plain_assert_keeps_its_message");
    assert_eq!(plain.message, "one is not greater than two");
    assert_eq!(
        plain.details,
        ["test::assert(1 > 2, message: \"one is not greater than two\")"]
    );
}
#[test]
fn helper_call_failures_are_located_at_the_call_site() {
    let results = run_ledger_tests(
        r#"
    #[test(fixture = "people")]
    fn default_caller_lacks_permission() {
        activate();
        test::invoke_kotoage(kotoage: "renew", arguments: {until: 1});
    }
    fn lookup_carol() -> AccountId {
        return test::actor_account(actor: "carol");
    }
    #[test(fixture = "people")]
    fn unknown_actor_in_helper() {
        let _who = lookup_carol();
    }
    #[test(fixture = "people")]
    fn wrong_rejection() {
        activate();
        test::expect_reject_as(
            actor: "alice",
            kotoage: "renew",
            arguments: {until: 1},
            expected: LedgerError::Expired,
        );
    }
"#,
    );
    let permission = failure_of(&results, "default_caller_lacks_permission");
    assert_eq!(permission.kind, FailureKind::PermissionDenied);
    let location = permission.location.as_deref().expect("call-site location");
    assert!(
        location.ends_with("tests/ledger.test.ko:16:9"),
        "{location}"
    );
    assert_eq!(
        permission.details[0],
        "test::invoke_kotoage(kotoage: \"renew\", arguments: {until: 1})"
    );
    let actor = failure_of(&results, "unknown_actor_in_helper");
    assert_eq!(actor.kind, FailureKind::Harness);
    assert!(
        actor.message.contains("unknown actor `carol`"),
        "{}",
        actor.render()
    );
    let location = actor
        .location
        .as_deref()
        .expect("helper call-site location");
    assert!(
        location.ends_with("tests/ledger.test.ko:19:16"),
        "{location}"
    );
    let rejection = failure_of(&results, "wrong_rejection");
    assert_eq!(rejection.kind, FailureKind::Expectation);
    let location = rejection
        .location
        .as_deref()
        .expect("multi-line call location");
    assert!(
        location.ends_with("tests/ledger.test.ko:28:9"),
        "{location}"
    );
    assert_eq!(
        rejection.details[0],
        "test::expect_reject_as(actor: \"alice\", kotoage: \"renew\", arguments: {until: 1 }, expected: LedgerError::Expired)"
    );
}
#[test]
fn unknown_actors_suggest_the_closest_declared_alias() {
    assert_eq!(closest_name("alcie", &["alice", "bob"]), Some("alice"));
    assert_eq!(closest_name("bb", &["alice", "bob"]), Some("bob"));
    assert_eq!(closest_name("carol", &["alice", "bob"]), None);
    assert_eq!(closest_name("x", &[]), None);
    let compiled = compiled_suite_with_fixtures(Vec::new());
    let mut host = build_host_for_fixture(&compiled, None).expect("default host");
    assert!(
        host.unknown_actor_message("alice")
            .contains("the test's fixture declares no actors; add `actor(\"alice\");`")
    );
    let account = account_for_seed(&derived_actor_seed("alice", 753)).expect("derived account");
    host.register_actor("alice".to_owned(), account)
        .expect("register alice");
    assert_eq!(
        host.unknown_actor_message("alcie"),
        "unknown actor `alcie`; declared actors: `alice`; did you mean `alice`?"
    );
    assert_eq!(
        host.unknown_actor_message("zed"),
        "unknown actor `zed`; declared actors: `alice`"
    );
}
#[test]
fn compared_values_render_in_kotodama_value_syntax() {
    let compiled = compiled_suite_with_fixtures(Vec::new());
    let host = build_host_for_fixture(&compiled, None).expect("default host");
    let nodes = [
        StateValueNodeV1::Option,
        StateValueNodeV1::Leaf(StateValueKindV1::Bool),
    ];
    let render = |atoms: &[StateValueAtomV1]| {
        let mut index = 0;
        host.render_value(&nodes, &mut index, &mut atoms.iter())
            .expect("render value")
    };
    assert_eq!(render(&[StateValueAtomV1::Tag(false)]), "Option::none");
    assert_eq!(
        render(&[StateValueAtomV1::Tag(true), StateValueAtomV1::Bool(true)]),
        "Option::some(true)"
    );
    assert_eq!(render_state_cursor(&[0xab, 0x01]), "StateCursor(0xab01)");
    assert_eq!(
        render_state_cursor(&[7; 40]),
        "StateCursor(0x0707070707070707\u{2026} /* 40 bytes */)"
    );
}
#[test]
fn one_line_source_collapses_layout_outside_string_literals() {
    assert_eq!(
        one_line_source("test::f(\n    a: 1,\n    b: [ 2, 3, ],\n)"),
        "test::f(a: 1, b: [2, 3])"
    );
    assert_eq!(
        one_line_source("f(s: \"keep  ( this ,)\\\" spacing\")"),
        "f(s: \"keep  ( this ,)\\\" spacing\")"
    );
    assert_eq!(one_line_source("  Point { x: 1 }  "), "Point { x: 1 }");
    // Single-line excerpts keep their spelling; multi-line ones drop comments and close braces
    // with one space.
    assert_eq!(one_line_source("f(a: [ 1 ])"), "f(a: [ 1 ])");
    assert_eq!(
        one_line_source(
            "f(\n    a: 1, // the first \"value\"\n    b: json {\n        c: 2,\n    },\n)"
        ),
        "f(a: 1, b: json { c: 2 })"
    );
    assert_eq!(
        one_line_source("f(\n    p: r\"C:\\dir\\\",\n    q: br\"\\x\",\n    s: \"a\\\"b\",\n)"),
        "f(p: r\"C:\\dir\\\", q: br\"\\x\", s: \"a\\\"b\")"
    );
    assert!(opens_raw_string("f(r") && opens_raw_string("br") && opens_raw_string("(br"));
    assert!(!opens_raw_string("bar") && !opens_raw_string("f(") && !opens_raw_string("x_r"));
}
#[test]
fn lifecycle_rejections_mirror_activation_rules() {
    let results = run_ledger_tests(
        r#"
    #[test(fixture = "people")]
    fn view_before_hajimari() {
        test::invoke_kotoage(kotoage: "height", arguments: {});
    }
    #[test(fixture = "people")]
    fn hajimari_replay() {
        activate();
        activate();
    }
    #[test(fixture = "people")]
    fn kaizen_without_replacement() {
        activate();
        test::invoke_kotoage(kotoage: "kaizen", arguments: {});
    }
"#,
    );
    for (name, expected) in [
        (
            "view_before_hajimari",
            "seiyaku `Ledger` has a pending hajimari (始まり) transition; invoke `hajimari` before `height`",
        ),
        (
            "hajimari_replay",
            "a consumed lifecycle hook cannot be replayed",
        ),
        (
            "kaizen_without_replacement",
            "kaizen (改善) runs only after an active seiyaku's code is replaced in place",
        ),
    ] {
        let failure = failure_of(&results, name);
        assert_eq!(failure.kind, FailureKind::Lifecycle, "{name}");
        assert!(
            failure.message.contains(expected),
            "{name}: {}",
            failure.render()
        );
    }
}
#[test]
fn typed_argument_records_are_checked_against_the_target_schema_at_compile_time() {
    for arguments in [
        "{ until: true }",
        "{}",
        "{ until: 12, extra: false }",
        "Json::parse(\"{}\")",
    ] {
        let temp = TestTempDir::new();
        let source = format!(
            r#"
    #[test(fixture = "people")]
    fn invalid_argument() {{
        test::invoke_kotoage_as(actor: "alice", kotoage: "renew", arguments: {arguments});
    }}
"#
        );
        let path = write_ledger_package(&temp, &source);
        let suite = discover_suite(&path).expect("discover");
        let Err(SuiteError::Diagnostics(diagnostics)) = compile_suite(&suite, false) else {
            panic!("invalid typed argument record must not compile: {arguments}");
        };
        let diagnostic = &diagnostics.diagnostics[0];
        assert_eq!(diagnostic.code, "E_TEST_ARGUMENT_RECORD", "{diagnostic:?}");
        assert!(
            diagnostic.message.contains("arguments for `renew`"),
            "{diagnostic:?}"
        );
        assert!(
            diagnostic.primary_span.is_some(),
            "argument failure must retain a source span"
        );
    }
}
/// Source text a diagnostic's primary span covers on its first line.
fn primary_text(path: &Path, diagnostic: &kotodama_lang::diagnostic::Diagnostic) -> String {
    let span = diagnostic
        .primary_span
        .as_ref()
        .expect("located diagnostic");
    let source = fs::read_to_string(path).expect("read diagnosed source");
    let line = source
        .lines()
        .nth(span.start.line - 1)
        .expect("diagnosed line");
    let end = if span.end.line == span.start.line {
        span.end.column
    } else {
        line.chars().count() + 1
    };
    line.chars()
        .skip(span.start.column - 1)
        .take(end - span.start.column)
        .collect()
}
#[test]
fn unknown_call_targets_are_located_at_the_selector_with_the_declared_selectors() {
    let temp = TestTempDir::new();
    let path = write_ledger_package(
        &temp,
        r#"
    #[test(fixture = "people")]
    fn misspelt_selector() {
        test::invoke_kotoage_as(actor: "alice", kotoage: "renw", arguments: {});
    }
"#,
    );
    let suite = discover_suite(&path).expect("discover");
    let Err(SuiteError::Diagnostics(diagnostics)) = compile_suite(&suite, false) else {
        panic!("an unknown selector must not compile");
    };
    let diagnostic = &diagnostics.diagnostics[0];
    assert_eq!(diagnostic.code, "K2002");
    assert_eq!(
        diagnostic.message,
        "the seiyaku under test has no kotoage, view, or lifecycle declaration named `renw`; did you mean \"renew\"?"
    );
    assert_eq!(primary_text(&path, diagnostic), "\"renw\"");
    let help = diagnostic.help.as_deref().expect("site help");
    assert!(
        help.contains("\"hajimari\", \"height\", \"kaizen\", \"pair\", \"renew\", \"time\""),
        "{help}"
    );
}
#[test]
fn named_actors_are_deterministic_and_fixture_errors_are_located() {
    let first = derived_actor_seed("alice", 753);
    assert_eq!(first, derived_actor_seed("alice", 753));
    assert_ne!(first, derived_actor_seed("bob", 753));
    assert_ne!(first, derived_actor_seed("alice", 369));
    let compiled = compiled_suite_with_fixtures(Vec::new());
    let mut host = build_host_for_fixture(&compiled, None).expect("default host");
    let mut inputs = BTreeMap::new();
    apply_fixture_action(
        &FixtureAction {
            name: "actor".to_owned(),
            args: vec![Expr::String("alice".to_owned())],
        },
        &mut host,
        &mut inputs,
        &fixture_environment(),
    )
    .expect("one-argument actor");
    let alice = host.actor_account("alice").expect("derived alice");
    assert_eq!(
        alice,
        account_for_seed(&derived_actor_seed(
            "alice",
            iroha_data_model::account::address::chain_discriminant()
        ))
        .unwrap()
    );
    assert!(
        host.actors["alice"].seed.is_some(),
        "derived actors can sign"
    );
    for (args, expected) in [
        (
            vec![Expr::String("carol".to_owned())],
            "`carol` is neither a declared actor nor an account literal; declared actors: `alice`",
        ),
        (
            vec![Expr::IntLiteral(5_i64.into())],
            "expected an actor alias, `seiyaku_subject`, or `AccountId::parse(\"...\")`, got the integer 5",
        ),
    ] {
        let error = apply_fixture_action(
            &FixtureAction {
                name: "caller".to_owned(),
                args,
            },
            &mut host,
            &mut inputs,
            &fixture_environment(),
        )
        .expect_err("invalid caller");
        assert_eq!(error, expected);
        assert!(
            !error.contains("Call("),
            "no Rust debug formatting: {error}"
        );
    }
    let temp = TestTempDir::new();
    let path = write_ledger_package(
        &temp,
        r#"
    fixture broken {
        actor("dave");
        caller("erin");
    }
    #[test(fixture = "broken")]
    fn uses_broken_fixture() {}
"#,
    );
    let suite = discover_suite(&path).expect("discover");
    let compiled = compile_suite(&suite, false).expect("compile");
    let results = execute_suite(&compiled, TraceMode::Off, 1).expect("execute");
    let failure = failure_of(&results, "uses_broken_fixture");
    assert_eq!(failure.kind, FailureKind::Harness);
    assert!(
        failure
            .location
            .as_deref()
            .is_some_and(|location| location.ends_with("tests/ledger.test.ko:15:9")),
        "{}",
        failure.render()
    );
    assert!(
        failure
            .message
            .starts_with("fixture `broken` action `caller`: `erin`")
    );
}
#[test]
fn misspelt_fixtures_and_actions_suggest_the_declared_name_at_their_site() {
    let compiled = compiled_suite_with_fixtures(Vec::new());
    let mut host = build_host_for_fixture(&compiled, None).expect("default host");
    let error = apply_fixture_action(
        &FixtureAction {
            name: "actr".to_owned(),
            args: vec![Expr::String("alice".to_owned())],
        },
        &mut host,
        &mut BTreeMap::new(),
        &fixture_environment(),
    )
    .expect_err("unknown action");
    assert_eq!(
        error,
        "unknown fixture action `actr`; did you mean `actor`?"
    );
    let error = apply_fixture_action(
        &FixtureAction {
            name: "frobnicate".to_owned(),
            args: Vec::new(),
        },
        &mut host,
        &mut BTreeMap::new(),
        &fixture_environment(),
    )
    .expect_err("unknown action");
    assert!(
        error.contains("the fixture actions are `actor`, `caller`"),
        "{error}"
    );
    let results = run_ledger_tests(
        r#"
    #[test(fixture = "peeple")]
    fn uses_misspelt_fixture() {}
"#,
    );
    let failure = failure_of(&results, "uses_misspelt_fixture");
    assert_eq!(failure.kind, FailureKind::Harness);
    assert_eq!(
        failure.message,
        "unknown fixture `peeple`; declared fixtures: `people`; did you mean `people`?"
    );
    assert!(
        failure
            .location
            .as_deref()
            .is_some_and(|location| location.ends_with("tests/ledger.test.ko:14:8")),
        "an unknown fixture is reported at the test that names it: {}",
        failure.render()
    );
}
#[test]
fn numeric_faults_name_their_numeric_error_variant() {
    use ivm_abi::numeric::NumericFaultV1;
    let failure = classify_vm_error(
        &ivm::VMError::NumericFault(NumericFaultV1::RepeatingDecimal),
        Some(ivm_abi::error::VmTrapKind::NumericFault),
    );
    assert_eq!(failure.kind, FailureKind::NumericFault);
    assert_eq!(
        failure.render(),
        "numeric fault: `kotodama::NumericError::RepeatingDecimal` (the exact quotient has a non-terminating decimal expansion)\n  help: choose a result scale and rounding with `div_round`"
    );
    let internal = numeric_fault_failure(NumericFaultV1::InvalidRoundingMode);
    assert!(
        internal.message.contains("ABI fault 10"),
        "{}",
        internal.render()
    );
    for tag in 1..=13 {
        let fault = NumericFaultV1::from_tag(tag).expect("defined tag");
        let rendered = numeric_fault_failure(fault).render();
        assert!(
            !rendered.contains("NumericFaultV1") && !rendered.contains(&format!("{fault:?}(")),
            "no Rust debug formatting: {rendered}"
        );
    }
}
#[test]
fn typed_argument_errors_pair_undeclared_keys_with_parameters() {
    let temp = TestTempDir::new();
    let path = write_ledger_package(
        &temp,
        r#"
    #[test(fixture = "people")]
    fn misspelt_key() {
        test::invoke_kotoage_as(actor: "alice", kotoage: "renew", arguments: { untill: 5 });
    }
"#,
    );
    let suite = discover_suite(&path).expect("discover typed argument failure");
    let error = compile_suite(&suite, false)
        .err()
        .expect("unknown parameter fails compilation");
    assert!(
        error.to_string().contains("did you mean `until`?"),
        "{error}"
    );
}

#[test]
fn compile_diagnostics_name_suite_files_as_the_cli_prints_them() {
    let temp = TestTempDir::new();
    let path = write_ledger_package(
        &temp,
        r#"
    #[test(fixture = "people")]
    fn broken() { test::assert_eq(actual: 1, expected: "x"); }
"#,
    );
    let suite = discover_suite(&path).expect("discover");
    let Err(error) = compile_suite(&suite, false) else {
        panic!("a type error must fail compilation");
    };
    let bundle = match localize_suite_diagnostics(&suite, error) {
        SuiteError::Diagnostics(bundle) => bundle,
        other => panic!("expected diagnostics, found {other}"),
    };
    let source = bundle.diagnostics[0]
        .primary_span
        .as_ref()
        .and_then(|span| span.source.clone())
        .expect("located diagnostic");
    // The scratch directory lies outside the working directory, so the path stays absolute,
    // and it names the real test-module file rather than a logical or canonical alias.
    assert_eq!(
        source,
        display_path(&suite.test_modules[0].path),
        "{}",
        bundle.render_human()
    );
    assert!(source.ends_with("tests/ledger.test.ko"), "{source}");
}
#[test]
fn fixture_numbers_accept_constant_expressions() {
    let consts = HashMap::from([
        ("SUPPLY".to_owned(), Expr::IntLiteral(40_i64.into())),
        ("FEE".to_owned(), Expr::DecimalLiteral("0.5".to_owned())),
    ]);
    let environment = FixtureEnvironment {
        artifacts: empty_fixture_artifacts(),
        source_name: None,
        consts: &consts,
        chain_discriminant: 753,
    };
    let expr = Expr::Binary {
        op: kotodama_lang::ast::BinaryOp::Sub,
        left: Box::new(Expr::Binary {
            op: kotodama_lang::ast::BinaryOp::Mul,
            left: Box::new(Expr::Ident("SUPPLY".to_owned())),
            right: Box::new(Expr::IntLiteral(3_i64.into())),
        }),
        right: Box::new(Expr::Ident("FEE".to_owned())),
    };
    assert_eq!(
        eval_quantity_expr(&expr, &environment)
            .expect("constant quantity")
            .to_string(),
        "119.5"
    );
    assert_eq!(
        eval_u64_expr(&Expr::Ident("SUPPLY".to_owned()), &environment).expect("u64"),
        40
    );
    let error = eval_quantity_expr(&Expr::Ident("missing".to_owned()), &environment)
        .expect_err("unknown names are not constants");
    assert!(error.contains("`missing` is not a constant"), "{error}");
    let error = eval_u64_expr(&Expr::Ident("FEE".to_owned()), &environment)
        .expect_err("fractions are not integers");
    assert!(error.contains("0.5"), "{error}");
    assert_eq!(format_fixed_point(&(-5_i64).into(), 2), "-0.05");
}
#[test]
fn coverage_and_trace_attribute_runtime_and_test_steps_separately() {
    let temp = TestTempDir::new();
    let path = write_ledger_package(
        &temp,
        r#"
    #[test(fixture = "people")]
    fn reads_height() {
        activate();
        test::invoke_kotoage(kotoage: "height", arguments: {});
    }
"#,
    );
    let suite = discover_suite(&path).expect("discover");
    let compiled = compile_suite(&suite, false).expect("compile");
    let results = execute_suite(&compiled, TraceMode::PcOnly, 1).expect("execute");
    let report = render_coverage_report(&compiled, &results);
    let covered = |function: &str| {
        report
            .lines()
            .find(|line| line.trim_end().ends_with(&format!("  {function}")))
            .unwrap_or_else(|| panic!("{function} row:\n{report}"))
            .trim_start()
            .starts_with("yes")
    };
    assert!(covered("hajimari") && covered("height"), "{report}");
    // Each row profiles the instructions the function executed; uncalled functions ran none.
    let instructions = |function: &str| {
        report
            .lines()
            .find(|line| line.trim_end().ends_with(&format!("  {function}")))
            .and_then(|line| line.split_whitespace().nth(2))
            .and_then(|count| count.replace(',', "").parse::<u64>().ok())
            .unwrap_or_else(|| panic!("{function} instruction count:\n{report}"))
    };
    assert!(
        report.contains("covered  line  instructions  function"),
        "{report}"
    );
    assert!(instructions("height") > 0, "{report}");
    assert_eq!(instructions("renew"), 0, "{report}");
    assert!(
        !covered("pair") && !covered("renew") && !covered("time"),
        "{report}"
    );
    let results = execute_suite(&compiled, TraceMode::DeltaRegisters, 1).expect("trace");
    let steps = trace_steps(&compiled, &results[0]);
    assert!(
        steps
            .iter()
            .any(|step| step.segment == "test" && step.function == Some("reads_height"))
    );
    assert!(
        steps
            .iter()
            .any(|step| step.segment == "call 1 `hajimari`" && step.function == Some("hajimari"))
    );
    assert!(
        steps
            .iter()
            .any(|step| step.segment == "call 2 `height`" && step.function == Some("height"))
    );
    assert!(
        steps
            .iter()
            .filter(|step| step.segment != "test")
            .all(|step| step.function != Some("reads_height")),
        "seiyaku steps never map to the test projection"
    );
    let test_source = fs::read_to_string(&path).unwrap();
    // Inlining retains the helper body's provenance; the eliminated call itself
    // has no executable instruction to attribute to its call-site line.
    for statement in [
        "test::invoke_kotoage(kotoage: \"hajimari\", arguments: {});",
        "test::invoke_kotoage(kotoage: \"height\", arguments: {});",
    ] {
        let line = test_source
            .lines()
            .position(|line| line.trim() == statement)
            .unwrap()
            + 1;
        let suffix = format!(":{line}:");
        assert!(
            steps.iter().any(|step| step.segment == "test"
                && step
                    .source
                    .as_deref()
                    .is_some_and(|source| source.contains(&suffix))),
            "executed statement {statement} retains its exact source line {line}"
        );
    }
    let first = steps.first().expect("first step");
    assert!(first.registers.iter().all(|(_, value)| *value != 0));
}

#[test]
fn result_error_returns_value_without_committing_invocation_state() {
    let temp = TestTempDir::new();
    temp.write(
        "result_rollback.ko",
        r#"
seiyaku ResultRollback { permission Update;
    state StateMap<int, int> Values;
    kotoage fn write(bool succeed) authorize(Update) -> Result<int, int> {
        Values[1] = 9;
        if succeed { return Result::ok(9); }
        return Result::err(7);
    }
    view fn value() authorize(anyone) -> int { Values.get(1).unwrap_or(0) }
}
"#,
    );
    let path = temp.write("result_rollback.test.ko", &format!(r#"
module ResultRollbackTests {{
    koto_test {{ target: "result_rollback.ko" }}
    fixture allowed {{
        actor("app", AccountId::parse("{DEFAULT_CALLER}"));
        grant_seiyaku_permission("app", "Update");
    }}
    #[test(fixture = "allowed")]
    fn rollback_and_success() {{
        let failure = test::invoke_kotoage_as(actor: "app", kotoage: "write", arguments: {{succeed: false}});
        match failure {{ Result::err(observed) => {{ test::assert_eq(actual: observed, expected: 7); }}, Result::ok(_) => {{ test::assert_eq(actual: false, expected: true); }} }}
        test::assert_eq(actual: test::invoke_kotoage(kotoage: "value", arguments: {{}}), expected: 0);
        let success = test::invoke_kotoage_as(actor: "app", kotoage: "write", arguments: {{succeed: true}});
        match success {{ Result::ok(observed) => {{ test::assert_eq(actual: observed, expected: 9); }}, Result::err(_) => {{ test::assert_eq(actual: false, expected: true); }} }}
        test::assert_eq(actual: test::invoke_kotoage(kotoage: "value", arguments: {{}}), expected: 9);
    }}
}}
"#));
    let suite = discover_suite(&path).expect("discover Result rollback test");
    let compiled = compile_suite(&suite, false).expect("compile Result rollback test");
    let results =
        execute_suite(&compiled, TraceMode::Off, 1).expect("execute Result rollback test");
    assert_eq!(results.len(), 1);
    assert!(results[0].passed, "{:?}", results[0].failure);
}

#[test]
fn option_and_result_error_bridges_evaluate_once_lazily_and_roll_back_aborts() {
    let temp = TestTempDir::new();
    temp.write(
        "bridges.ko",
        r#"seiyaku Bridges {
    error enum Old { Bad = 1 }
    error enum Failure { Missing = 7, RepeatedReceiver = 8, RepeatedError = 9 }
    struct Probe { int receivers, int errors, int value }
    state StateMap<int, int> Calls;
    fn reset() { Calls[1] = 0; Calls[2] = 0; }
    fn receiver(bool success) -> Option<int> {
        Calls[1] = Calls.get(1).unwrap_or(0) + 1;
        require(Calls.get(1).unwrap_or(0) == 1, Failure::RepeatedReceiver);
        if success { return Option::some(7); }
        Option::none
    }
    fn result_receiver(bool success) -> Result<int, Old> {
        Calls[1] = Calls.get(1).unwrap_or(0) + 1;
        require(Calls.get(1).unwrap_or(0) == 1, Failure::RepeatedReceiver);
        if success { return Result::ok(7); }
        Result::err(Old::Bad)
    }
    fn fallback() -> Failure {
        Calls[2] = Calls.get(2).unwrap_or(0) + 1;
        require(Calls.get(2).unwrap_or(0) == 1, Failure::RepeatedError);
        Failure::Missing
    }
    fn probe(int value) -> Probe {
        Probe { receivers: Calls.get(1).unwrap_or(0), errors: Calls.get(2).unwrap_or(0), value: value }
    }
    kotoage fn option_value(bool success, bool labeled) authorize(anyone) -> Probe {
        reset();
        if labeled {
            let Result<int, Failure> converted = receiver(success: success).ok_or(error: fallback());
            return probe(value: converted.unwrap_or(0));
        }
        let Result<int, Failure> converted = receiver(success: success).ok_or(fallback());
        probe(value: converted.unwrap_or(0))
    }
    kotoage fn result_value(bool success, bool labeled) authorize(anyone) -> Probe {
        reset();
        if labeled {
            let Result<int, Failure> converted = result_receiver(success: success).or_err(error: fallback());
            return probe(value: converted.unwrap_or(0));
        }
        let Result<int, Failure> converted = result_receiver(success: success).or_err(fallback());
        probe(value: converted.unwrap_or(0))
    }
    kotoage fn expect_option(bool success) authorize(anyone) -> Probe {
        reset();
        let value = receiver(success: success).expect(error: fallback());
        probe(value: value)
    }
    kotoage fn expect_result(bool success) authorize(anyone) -> Probe {
        reset();
        let value = result_receiver(success: success).expect(fallback());
        probe(value: value)
    }
    view fn counts() authorize(anyone) -> (int, int) {
        (Calls.get(1).unwrap_or(0), Calls.get(2).unwrap_or(0))
    }
}"#,
    );
    let path = temp.write(
        "bridges.test.ko",
        r#"module BridgesTests {
    koto_test { target: "bridges.ko" }
    fixture actors { actor("app"); }
    #[test(fixture = "actors")]
    fn branches_are_lazy_and_nominal_failures_roll_back() {
        test::assert_eq(actual: test::invoke_kotoage(kotoage: "option_value", arguments:  { success: true, labeled: false }), expected: Probe { receivers: 1, errors: 0, value: 7 });
        test::assert_eq(actual: test::invoke_kotoage(kotoage: "option_value", arguments:  { success: false, labeled: false }), expected: Probe { receivers: 1, errors: 1, value: 0 });
        test::assert_eq(actual: test::invoke_kotoage(kotoage: "option_value", arguments:  { success: true, labeled: true }), expected: Probe { receivers: 1, errors: 0, value: 7 });
        test::assert_eq(actual: test::invoke_kotoage(kotoage: "option_value", arguments:  { success: false, labeled: true }), expected: Probe { receivers: 1, errors: 1, value: 0 });
        test::assert_eq(actual: test::invoke_kotoage(kotoage: "result_value", arguments:  { success: true, labeled: false }), expected: Probe { receivers: 1, errors: 0, value: 7 });
        test::assert_eq(actual: test::invoke_kotoage(kotoage: "result_value", arguments:  { success: false, labeled: false }), expected: Probe { receivers: 1, errors: 1, value: 0 });
        test::assert_eq(actual: test::invoke_kotoage(kotoage: "result_value", arguments:  { success: true, labeled: true }), expected: Probe { receivers: 1, errors: 0, value: 7 });
        test::assert_eq(actual: test::invoke_kotoage(kotoage: "result_value", arguments:  { success: false, labeled: true }), expected: Probe { receivers: 1, errors: 1, value: 0 });
        test::assert_eq(actual: test::invoke_kotoage(kotoage: "expect_option", arguments:  { success: true }), expected: Probe { receivers: 1, errors: 0, value: 7 });
        test::assert_eq(actual: test::invoke_kotoage(kotoage: "expect_result", arguments:  { success: true }), expected: Probe { receivers: 1, errors: 0, value: 7 });
        test::expect_reject_as(actor: "app", kotoage: "expect_option", arguments:  { success: false }, expected: Failure::Missing);
        test::assert_eq(actual: test::invoke_kotoage(kotoage: "counts", arguments:  {}), expected: (1, 0));
        test::expect_reject_as(actor: "app", kotoage: "expect_result", arguments:  { success: false }, expected: Failure::Missing);
        test::assert_eq(actual: test::invoke_kotoage(kotoage: "counts", arguments:  {}), expected: (1, 0));
    }
}"#,
    );
    let suite = discover_suite(&path).expect("discover lazy nominal error bridge tests");
    let compiled = compile_suite(&suite, false).expect("compile lazy nominal error bridges");
    let results = execute_suite(&compiled, TraceMode::Off, 1).expect("execute lazy error bridges");
    assert_eq!(results.len(), 1);
    assert!(results[0].passed, "{:?}", results[0].failure);
}

#[test]
fn private_functions_resembling_builtins_keep_their_own_runtime_identity() {
    let temp = TestTempDir::new();
    temp.write("names.ko", r#"seiyaku Names {
        error enum Failure { Missing = 1 }
        fn min(int value) -> int { value + 100 }
        fn authority() -> int { 7 }
        fn mint_asset(int value) -> int { value + 10 }
        fn is_some(int value) -> int { value + 1 }
        fn expect(int value) -> int { value + 2 }
        view fn evaluate() authorize(anyone) -> (int, int, int, int, int, int, bool, int, bool) {
            let Option<int> value = Option::some(4);
            (min(3), authority(), mint_asset(4), is_some(5), expect(6), math::min(8, 2), value.is_some(), value.expect(Failure::Missing), context::authority() == context::authority())
        }
    }"#);
    let path=temp.write("names.test.ko",r#"module NamesTests {
        koto_test { target: "./names.ko" }
        fixture actors { actor("app"); }
        #[test(fixture = "actors")]
        fn private_and_builtin_calls_stay_distinct() {
            test::assert_eq(actual: test::invoke_kotoage(kotoage: "evaluate", arguments:  {}), expected: (103, 7, 14, 6, 8, 2, true, 4, true));
        }
    }"#);
    let suite = discover_suite(&path).expect("discover private identity suite");
    let compiled = compile_suite(&suite, false).expect("private mint_asset remains pure in a view");
    let results =
        execute_suite(&compiled, TraceMode::Off, 1).expect("execute private and builtin calls");
    assert_eq!(results.len(), 1);
    assert!(results[0].passed, "{:?}", results[0].failure);
}

#[test]
fn failed_public_test_invocation_retains_typed_artifact_fault_in_reports() {
    use iroha_data_model::executor::fault::{IvmFaultKindV1, IvmFaultPositionV1, NumericFaultV1};
    let temp = TestTempDir::new();
    let path = temp.write(
        "fault.ko",
        r#"seiyaku Faults {
        view fn quotient(int divisor) authorize(anyone) -> int { 10 / divisor }
        #[test]
        fn reports_origin() {
            test::invoke_kotoage(kotoage: "quotient", arguments:  { divisor: 0 });
        }
    }"#,
    );
    let suite = discover_suite(&path).unwrap();
    let compiled = compile_suite(&suite, false).unwrap();
    let results = execute_suite(&compiled, TraceMode::Off, 1).unwrap();
    let failure = results[0].failure.as_ref().expect("division fails");
    let fault = failure.fault.expect("canonical runtime fault");
    assert_eq!(
        fault.kind,
        IvmFaultKindV1::Numeric(NumericFaultV1::DivisionByZero)
    );
    assert_eq!(
        fault.site.code_hash,
        compiled.runtime.as_ref().unwrap().report.artifact_hash
    );
    assert!(matches!(
        fault.site.position,
        IvmFaultPositionV1::Execute { .. }
    ));
    assert!(failure.message.contains("quotient"), "{}", failure.render());
    let json = failure_json(failure);
    assert_eq!(json.get("fault"), Some(&norito::json!(fault)));
}

#[test]
fn typed_test_arguments_preserve_nominal_values_and_single_source_order_evaluation() {
    let temp = TestTempDir::new();
    let path = temp.write("typed_arguments.ko", r#"
seiyaku TypedArguments {
    enum Status { Active = 7, Inactive = 9 }
    error enum Failure { Missing = 1 }
    struct Payload { Status status; Option<Status> previous; List<Status, 2> history; Result<int, Failure> result; }
    state int order;
    hajimari() { order = 0; }
    fixture active { actor("app"); grant_seiyaku_lifecycle_permission("app", "hajimari"); }
    fn produce_first() -> int { order = order * 10 + 1; 1 }
    fn produce_second() -> int { order = order * 10 + 2; 2 }
    view fn pair(int first, int second) authorize(anyone) -> (int, int, int) { (first, second, order) }
    view fn echo(Payload payload) authorize(anyone) -> Payload { payload }
    #[test(fixture = "active")]
    fn roundtrip() {
        test::invoke_kotoage_as(actor: "app", kotoage: "hajimari", arguments: {});
        let observed_pair = test::invoke_kotoage(arguments: { second: produce_second(), first: produce_first() }, kotoage: "pair");
        test::assert_eq(actual: observed_pair, expected: (1, 2, 21));
        let payload = Payload { status: Status::Active, previous: Option::some(Status::Inactive), history: [Status::Active, Status::Inactive], result: Result::ok(27) };
        let returned = test::invoke_kotoage(kotoage: "echo", arguments: { payload });
        test::assert_eq(actual: returned, expected: payload);
    }
}
"#);
    let suite = discover_suite(&path).expect("discover typed arguments");
    let compiled = compile_suite(&suite, false).expect("compile typed arguments");
    let results = execute_suite(&compiled, TraceMode::Off, 1).expect("execute typed arguments");
    assert_eq!(results.len(), 1);
    assert!(results[0].passed, "{:?}", results[0].failure);
}

#[test]
fn native_test_events_capture_canonical_payloads_and_rollback_failed_invocations() {
    let temp = TestTempDir::new();
    let path = temp.write("events.ko", r#"
seiyaku EventTests {
    enum Status { Active = 7 }
    error enum Failure { Missing = 1 }
    event Changed { Status status; int value; }
    kotoage fn commit() authorize(anyone) { emit Changed { value: 3, status: Status::Active }; }
    kotoage fn result(bool success) authorize(anyone) -> Result<int, Failure> {
        emit Changed { value: 5, status: Status::Active };
        if success { Result::ok(1) } else { Result::err(Failure::Missing) }
    }
    kotoage fn reject() authorize(anyone) { emit Changed { value: 9, status: Status::Active }; require(false, Failure::Missing); }
    #[test]
    fn capture() {
        test::invoke_kotoage(kotoage: "commit", arguments: {});
        let failed = test::invoke_kotoage(kotoage: "result", arguments: { success: false });
        test::assert(failed.is_err());
        let succeeded = test::invoke_kotoage(kotoage: "result", arguments: { success: true });
        test::assert(succeeded.is_ok());
    }
}
"#);
    let suite = discover_suite(&path).expect("discover event tests");
    let compiled = compile_suite(&suite, false).expect("compile event tests");
    let mut host = build_host_for_fixture(&compiled, None).expect("event host");
    let mut vm = IVM::new(u64::MAX);
    vm.load_koto_test_harness(&compiled.suite.program)
        .expect("load event harness");
    vm.set_program_counter(compiled.tests[0].pc)
        .expect("jump to event test");
    vm.run_with_host(&mut host).expect("run event harness");
    assert_eq!(host.events.len(), 2, "returned Err must discard its event");
    for event in &host.events {
        assert_eq!(event.name.as_ref(), "Changed");
        assert!(matches!(
            event.payload.atoms[0],
            iroha_data_model::smart_contract::entrypoint::EntrypointValueAtomV1::EnumCode(7)
        ));
    }
    // A direct host call exercises trap rollback without needing another fixture actor.
    let actor = host.inner.caller_subject();
    host.actors.insert(
        "caller".into(),
        FixtureActor {
            account: actor,
            seed: None,
        },
    );
    for (reg, bytes) in [(10, b"caller".as_slice()), (11, b"reject".as_slice())] {
        let pointer = vm
            .alloc_input_tlv(&make_tlv(PointerType::Blob, bytes))
            .unwrap();
        vm.set_register(reg, pointer);
    }
    vm.set_register(12, 0);
    vm.set_register(13, 0);
    let output = vm.alloc_heap(8).unwrap();
    vm.set_register(14, output);
    vm.set_register(15, 1);
    host.syscall(TEST_SYSCALL_INVOKE_ENTRYPOINT_AS, &mut vm)
        .expect_err("typed rejection");
    assert_eq!(host.events.len(), 2, "trap must discard its event");
}

#[test]
fn lists_of_structs_mutate_through_stable_local_product_fields() {
    let temp = TestTempDir::new();
    let path = temp.write(
        "list_fields.ko",
        r#"
seiyaku Lists {
    struct Item { int value; }
    struct Holder { List<Item, 3> items; }
    view fn compute() authorize(anyone) -> (List<Item, 3>, List<Item, 3>) {
        var holder = Holder { items: [Item { value: 1 }] };
        holder.items.push(Item { value: 2 });
        holder.items.set(0, Item { value: 3 });
        let removed = holder.items.pop();
        let expected_removed = Option::some(Item { value: 2 });
        if removed != expected_removed { return ([], []); }
        var pair = (0, Holder { items: [] });
        pair.1.items.push(Item { value: 4 });
        (holder.items, pair.1.items)
    }
    #[test]
    fn roundtrip() {
        let pair = test::invoke_kotoage(kotoage: "compute", arguments: {});
        test::assert_eq(actual: pair.0, expected: [Item { value: 3 }]);
        test::assert_eq(actual: pair.1, expected: [Item { value: 4 }]);
    }
}
"#,
    );
    let suite = discover_suite(&path).expect("discover mutable fields");
    let compiled = compile_suite(&suite, false).expect("compile mutable fields");
    let results = execute_suite(&compiled, TraceMode::Off, 1).expect("run mutable fields");
    assert_eq!(results.len(), 1);
    assert!(results[0].passed, "{:?}", results[0].failure);
}

#[test]
fn list_boundary_widening_copies_outer_storage_and_preserves_nested_handles() {
    let temp = TestTempDir::new();
    let path = temp.write("list_widening.ko", r#"
seiyaku Lists {
    state int evaluations;
    hajimari() { evaluations = 0; }
    fixture active { actor("app"); grant_seiyaku_lifecycle_permission("app", "hajimari"); }
    error enum Failure { Missing = 1 }
    fn produced() -> List<int, 2> { evaluations += 1; [1] }
    fn append(List<int, 4> input) -> List<int, 4> {
        var output = input;
        output.push(2);
        output
    }
    fn expanded(List<int, 2> input, bool choose) -> List<int, 4> {
        if choose { input } else { [] }
    }
    fn expanded_nested(List<List<int, 2>, 1> input) -> List<List<int, 2>, 2> {
        input
    }
    kotoage fn compute() authorize(anyone) -> (int, int, int, int, int, int) {
        evaluations = 0;
        let produced_result = append(produced());
        let List<int, 2> original = [1];
        var copied = expanded(original, true);
        copied.push(3);
        let List<List<int, 2>, 1> nested = [[5]];
        var wide_nested = expanded_nested(nested);
        var shared_inner = wide_nested.get(0).expect(Failure::Missing);
        shared_inner.push(8);
        wide_nested.push([9]);
        (evaluations, produced_result.len(), original.len(), copied.len(), nested.len(), nested.get(0).expect(Failure::Missing).len())
    }
    #[test(fixture = "active")]
    fn boundaries() {
        test::invoke_kotoage_as(actor: "app", kotoage: "hajimari", arguments: {});
        let observed = test::invoke_kotoage(kotoage: "compute", arguments: {});
        test::assert_eq(actual: observed, expected: (1, 2, 1, 2, 1, 2));
    }
}
"#);
    let suite = discover_suite(&path).expect("discover capacity conversions");
    let compiled = compile_suite(&suite, false).expect("compile capacity conversions");
    let results = execute_suite(&compiled, TraceMode::Off, 1).expect("run capacity conversions");
    assert_eq!(results.len(), 1);
    assert!(results[0].passed, "{:?}", results[0].failure);
}

#[test]
fn imported_contract_methods_preserve_nominal_tables_order_and_nested_event_rollback() {
    let temp = TestTempDir::new();
    let child_source = r#"
seiyaku Pool {
    enum Status { Active = 7 }
    error enum Failure { Missing = 1 }
    struct Payload { Status status; int first; int second; }
    event Called { Payload payload; }
    kotoage fn exchange(int first, int second, bool accept) authorize(anyone) -> Result<Payload, Failure> {
        let payload = Payload { status: Status::Active, first, second };
        emit Called { payload };
        if accept { Result::ok(payload) } else { Result::err(Failure::Missing) }
    }
    view fn echo(Payload payload) authorize(anyone) -> Payload { payload }
}
"#;
    let child = CompilerSession::default()
        .build(kotodama_lang::session::CompileRequest {
            source: child_source,
            source_name: Some("pool.ko"),
        })
        .expect("compile admitted Pool interface");
    fs::write(temp.path.join("pool.to"), &child.artifact).expect("write imported artifact");
    let target = temp.write("caller.ko", r#"
seiyaku Caller {
    import seiyaku "./pool.to" as Pool;
    state int order;
    hajimari() { order = 0; }
    fn receiver(bytes _ address) -> Pool { order = order * 10 + 1; Pool::at(address: address) }
    fn first_argument() -> int { order = order * 10 + 2; 2 }
    fn second_argument() -> int { order = order * 10 + 3; 3 }
    kotoage fn relay(bytes address, bool accept) authorize(anyone) -> Result<(Pool::Payload, int), Pool::Failure> {
        let result = receiver(address).exchange(second: second_argument(), accept: accept, first: first_argument());
        match result {
            Result::ok(payload) => Result::ok((payload, order)),
            Result::err(failure) => Result::err(failure),
        }
    }
    view fn read(bytes address, Pool::Payload payload) authorize(anyone) -> Pool::Payload {
        Pool::at(address: address).echo(payload: payload)
    }
    fixture active { actor("app"); grant_seiyaku_lifecycle_permission("app", "hajimari"); }
}
"#);
    // The instance address is independent of its artifact identity; both are authenticated at A9.
    let actor = default_caller_account().unwrap();
    let address = ContractAddress::derive(
        &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
            .parse()
            .unwrap(),
        &actor,
        17,
        DataSpaceId::UNIVERSAL,
    )
    .unwrap();
    temp.write("tests/caller.test.ko", &format!(r#"
module CallerTests {{
    koto_test {{ target: "../caller.ko" }}
    #[test(fixture = "active")]
    fn nested() {{
        test::invoke_kotoage_as(actor: "app", kotoage: "hajimari", arguments: {{}});
        let failed = test::invoke_kotoage(kotoage: "relay", arguments: {{ address: b"{address}", accept: false }});
        test::assert(failed.is_err());
        let succeeded = test::invoke_kotoage(kotoage: "relay", arguments: {{ address: b"{address}", accept: true }});
        let (payload, observed_order) = succeeded.expect(Pool::Failure::Missing);
        test::assert_eq(actual: observed_order, expected: 132);
        test::assert_eq(actual: payload.first, expected: 2);
        test::assert_eq(actual: payload.second, expected: 3);
        test::assert(payload.status == Pool::Status::Active);
        let echoed = test::invoke_kotoage(kotoage: "read", arguments: {{ address: b"{address}", payload }});
        test::assert_eq(actual: echoed, expected: payload);
    }}
}}
"#));
    let suite = discover_suite(&target).expect("discover imported contract tests");
    let compiled = compile_suite(&suite, false).expect("compile imported contract tests");
    let mut host = build_host_for_fixture(&compiled, Some("active")).expect("fixture host");
    let mut control = iroha_data_model::smart_contract::ContractLifecycleControlV1::direct(actor);
    control.active_code_hash = Some(child.report.artifact_hash);
    control.retained_code_hash = control.active_code_hash;
    host.inner
        .install_contract_fixture(address, child.artifact, control, None)
        .expect("install Pool fixture");
    let mut vm = IVM::new(u64::MAX);
    vm.load_koto_test_harness(&compiled.suite.program).unwrap();
    vm.set_program_counter(compiled.tests[0].pc).unwrap();
    vm.run_with_host(&mut host)
        .expect("run typed imported methods");
    assert_eq!(
        host.events.len(),
        1,
        "failed nested and outer Results discard their events"
    );
    assert_eq!(host.events[0].name.as_ref(), "Called");
    assert_eq!(
        decode_int_state_value(&host.fixture_state("order").unwrap()),
        132
    );
}

#[test]
fn matching_private_receiver_helpers_override_native_names_and_evaluate_once() {
    let temp = TestTempDir::new();
    let path = temp.write("receiver.ko", r#"seiyaku ReceiverHelpers {
        error enum Failure { Missing = 1 }
        state int order;
        hajimari() { order = 0; }
        fixture active { actor("app"); grant_seiyaku_lifecycle_permission("app", "hajimari"); }
        fn produce() -> int { order = order * 10 + 1; 7 }
        fn left_value() -> int { order = order * 10 + 2; 2 }
        fn right_value() -> int { order = order * 10 + 3; 3 }
        fn expect(int value, int left, int right) -> int { value + left * 10 + right }
        fn len(List<int, 4> values) -> int { values.get(0).expect(Failure::Missing) + 100 }
        kotoage fn exercise() authorize(anyone) -> (int, int, int, int, bool) {
            let selected = produce().expect(right: right_value(), left: left_value());
            let List<int, 1> small = [8];
            let Option<int> optional = Option::some(9);
            (selected, order, small.len(), optional.expect(Failure::Missing), optional.is_some())
        }
        #[test(fixture = "active")]
        fn check() {
            test::invoke_kotoage_as(actor: "app", kotoage: "hajimari", arguments: {});
            test::assert_eq(actual: test::invoke_kotoage(kotoage: "exercise", arguments: {}), expected: (30, 132, 108, 9, true));
        }
    }"#);
    let suite = discover_suite(&path).unwrap();
    let compiled = compile_suite(&suite, false).unwrap();
    let results = execute_suite(&compiled, TraceMode::Off, 1).unwrap();
    assert!(results[0].passed, "{:?}", results[0].failure);
}

#[test]
fn public_value_utilities_encode_typed_values_and_preserve_utf8_and_evaluation_order() {
    let temp = TestTempDir::new();
    let path = temp.write("utilities.ko", r#"seiyaku UtilityValues {
        error enum Failure { InvalidText = 1 }
        enum Status { Ready = 9 }
        struct Payload { Status status; List<Option<int>, 2> values; Json metadata }
        state int order;
        hajimari() { order = 0; }
        fixture active { actor("app"); grant_seiyaku_lifecycle_permission("app", "hajimari"); }
        fn produce() -> Payload {
            order = order + 1;
            Payload { status: Status::Ready, values: [Option::some(7), Option::none], metadata: json { ok: true } }
        }
        kotoage fn check_values() authorize(anyone) -> bool {
            let captured = codec::encode(produce());
            let Payload expected = Payload { status: Status::Ready, values: [Option::some(7), Option::none], metadata: json { ok: true } };
            let joined = string::concat("海", "!");
            let restored = string::from_bytes(string::as_bytes(joined)).expect(Failure::InvalidText);
            captured == codec::encode(expected) && order == 1
                && restored == "海!" && string::len(restored) == 4
                && bytes::concat(b"ab", b"cd") == b"abcd"
                && string::from_bytes(b"\xff").is_none()
                && string::from(true) == "true" && string::from(-7) == "-7"
                && string::from(Name::parse("alpha")) == "alpha"
        }
        #[test(fixture = "active")]
        fn check() {
            test::invoke_kotoage_as(actor: "app", kotoage: "hajimari", arguments: {});
            test::assert(test::invoke_kotoage(kotoage: "check_values", arguments: {}));
        }
    }"#);
    let suite = discover_suite(&path).unwrap();
    let compiled = compile_suite(&suite, false).unwrap();
    let results = execute_suite(&compiled, TraceMode::Off, 1).unwrap();
    assert!(results[0].passed, "{:?}", results[0].failure);
}

#[test]
fn numeric_selection_supports_exact_decimal_and_quantity_domains_once() {
    let temp = TestTempDir::new();
    let path = temp.write(
        "selection.ko",
        r#"seiyaku NumericChoices {
        state int order;
        hajimari() { order = 0; }
        fixture active { actor("app"); grant_seiyaku_lifecycle_permission("app", "hajimari"); }
        fn low_value() -> decimal { order = order * 10 + 1; -2.5 }
        fn high_value() -> decimal { order = order * 10 + 2; 1.25 }
        kotoage fn check_values() authorize(anyone) -> bool {
            let selected = math::max(right: high_value(), left: low_value());
            let quantity low = 2.5;
            let quantity high = 3.75;
            selected == 1.25 && order == 21
                && math::min(-2.5, 1.25) == -2.5 && math::abs(-2.5) == 2.5
                && math::abs(2.5) == 2.5 && math::abs(0.0) == 0.0
                && math::min(low, high) == low && math::max(low, high) == high
                && math::abs(low) == low && math::abs(-7) == 7
        }
        #[test(fixture = "active")]
        fn check() {
            test::invoke_kotoage_as(actor: "app", kotoage: "hajimari", arguments: {});
            test::assert(test::invoke_kotoage(kotoage: "check_values", arguments: {}));
        }
    }"#,
    );
    let suite = discover_suite(&path).unwrap();
    let compiled = compile_suite(&suite, false).unwrap();
    let results = execute_suite(&compiled, TraceMode::Off, 1).unwrap();
    assert!(results[0].passed, "{:?}", results[0].failure);
}

#[test]
fn tuple_state_keys_round_trip_through_public_cursor_arguments_and_share_scalar_records() {
    let temp = TestTempDir::new();
    let path = temp.write("tuple_keys.ko", r#"seiyaku TupleKeys {
        error enum Failure { Missing = 1 }
        state StateMap<(int, (Name, bool)), int> values;
        state StateMap<int, int> scalars;
        kotoage fn seed() authorize(anyone) {
            values[(7, (Name::parse("first"), true))] = 10;
            values[(8, (Name::parse("second"), false))] = 20;
            scalars[7] = 30;
        }
        view fn page(Option<StateCursor<(int, (Name, bool))>> after) authorize(anyone) -> StatePage<(int, (Name, bool)), int, 1> {
            values.page(after: after, limit: 1)
        }
        view fn lookup() authorize(anyone) -> int {
            values.get((7, (Name::parse("first"), true))).expect(Failure::Missing) + scalars.get(7).expect(Failure::Missing)
        }
        #[test]
        fn check() {
            test::invoke_kotoage(kotoage: "seed", arguments: {});
            let first = test::invoke_kotoage(kotoage: "page", arguments: { after: Option::none });
            let second = test::invoke_kotoage(kotoage: "page", arguments: { after: first.next });
            let end = test::invoke_kotoage(kotoage: "page", arguments: { after: second.next });
            test::assert_eq(actual: first.items.len(), expected: 1);
            test::assert_eq(actual: second.items.len(), expected: 1);
            test::assert_eq(actual: end.items.len(), expected: 0);
            test::assert(end.next.is_none());
            let a = first.items.get(0).expect(Failure::Missing);
            let b = second.items.get(0).expect(Failure::Missing);
            test::assert_eq(actual: a.0.0 + b.0.0, expected: 15);
            test::assert_eq(actual: a.1 + b.1, expected: 30);
            test::assert_eq(actual: test::invoke_kotoage(kotoage: "lookup", arguments: {}), expected: 40);
        }
    }"#);
    let suite = discover_suite(&path).unwrap();
    let compiled = compile_suite(&suite, false).unwrap();
    let results = execute_suite(&compiled, TraceMode::Off, 1).unwrap();
    assert!(results[0].passed, "{:?}", results[0].failure);
}

#[test]
fn numeric_conversion_modes_preserve_faults_and_recoverable_results() {
    use iroha_data_model::executor::fault::{IvmFaultKindV1, NumericFaultV1};
    let temp = TestTempDir::new();
    let path = temp.write("conversions.ko", r#"seiyaku Conversions {
        error enum Check { WrongFault = 1 }
        view fn recover_int(int value) authorize(anyone) -> Result<quantity, NumericError> {
            quantity::try_from_int(value)
        }
        view fn recover_decimal(decimal value) authorize(anyone) -> Result<quantity, NumericError> {
            quantity::try_from_decimal(value)
        }
        view fn exact(decimal value) authorize(anyone) -> int {
            let recovered = quantity::try_from_decimal(-value);
            match recovered {
                Result::ok(_) => { require(false, Check::WrongFault); },
                Result::err(failure) => { require(failure == NumericError::NegativeQuantity, Check::WrongFault); },
            }
            decimal::to_int_exact(value)
        }
        #[test]
        fn recovered_values() {
            let integer = test::invoke_kotoage(kotoage: "recover_int", arguments: { value: -1 });
            let fraction = test::invoke_kotoage(kotoage: "recover_decimal", arguments: { value: -1.5 });
            match integer {
                Result::ok(_) => { test::assert(false); },
                Result::err(failure) => { test::assert_eq(actual: failure, expected: NumericError::NegativeQuantity); },
            }
            match fraction {
                Result::ok(_) => { test::assert(false); },
                Result::err(failure) => { test::assert_eq(actual: failure, expected: NumericError::NegativeQuantity); },
            }
            test::assert(test::invoke_kotoage(kotoage: "recover_int", arguments: { value: 1 }).is_ok());
            test::assert(test::invoke_kotoage(kotoage: "recover_decimal", arguments: { value: 1.5 }).is_ok());
            test::assert_eq(actual: test::invoke_kotoage(kotoage: "exact", arguments: { value: 2.0 }), expected: 2);
        }
        #[test]
        fn exact_conversion_traps() {
            test::invoke_kotoage(kotoage: "exact", arguments: { value: 1.5 });
        }
    }"#);
    let suite = discover_suite(&path).expect("discover conversion policy");
    let compiled = compile_suite(&suite, false).expect("compile conversion policy");
    let results = execute_suite(&compiled, TraceMode::Off, 1).expect("execute conversion policy");
    assert_eq!(results.len(), 2);
    assert_eq!(
        results.iter().filter(|result| result.passed).count(),
        1,
        "{:?}",
        results
            .iter()
            .map(|result| (&result.name, result.passed, &result.failure))
            .collect::<Vec<_>>()
    );
    let failure = results
        .iter()
        .find_map(|result| result.failure.as_ref())
        .unwrap();
    let fault = failure.fault.expect("canonical conversion fault");
    assert_eq!(
        fault.kind,
        IvmFaultKindV1::Numeric(NumericFaultV1::InexactConversion)
    );
    assert_eq!(
        fault.site.code_hash,
        compiled.runtime.as_ref().unwrap().report.artifact_hash
    );
}
