//! Include/import graph resolution and typing regressions.
use super::*;

fn file(path: &str, source: &str) -> SourceModuleUnit {
    SourceModuleUnit {
        source_name: path.into(),
        source: source.into(),
    }
}
fn project(root: &str, sources: &[(&str, &str)]) -> SourceLinkRequest {
    SourceLinkRequest {
        artifacts: Vec::new(),
        root: file("app.ko", root),
        sources: sources
            .iter()
            .map(|(path, source)| file(path, source))
            .collect(),
        imports: Vec::new(),
        packages: Vec::new(),
    }
}
fn link(request: SourceLinkRequest) -> TypedProgram {
    ModuleBuildGraph::default()
        .link(request, LinkerOptions::default())
        .unwrap_or_else(|error| panic!("{}", error.into_diagnostics().render_human()))
        .program
}
fn codes(request: SourceLinkRequest) -> Vec<String> {
    ModuleBuildGraph::default()
        .link(request, LinkerOptions::default())
        .unwrap_err()
        .into_diagnostics()
        .diagnostics
        .into_iter()
        .map(|diagnostic| diagnostic.code)
        .collect()
}
#[test]
fn project_resolution_failures_preserve_independent_type_diagnostics() {
    let request = project(
        r#"seiyaku Recover {
            import "math.ko" as arithmetic;
            include "operations.ko";
            view fn broken() authorize(anyone) -> int { missing }
            view fn valid(arithmetic::Value value) authorize(anyone) -> int { arithmetic::read(value) }
        }"#,
        &[
            (
                "operations.ko",
                "view fn wrong() authorize(anyone) -> int { true }",
            ),
            (
                "math.ko",
                "module Math { export struct Value { int amount; } export fn read(Value _ value) -> int { value.amount } }",
            ),
        ],
    );
    let diagnostics = ModuleBuildGraph::default()
        .link(request, LinkerOptions::default())
        .expect_err("both resolution and type checking fail")
        .into_diagnostics();
    assert!(
        diagnostics
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "K2002")
    );
    assert!(
        diagnostics.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "E_TAIL_TYPE_MISMATCH"
                && diagnostic
                    .primary_span
                    .as_ref()
                    .is_some_and(|span| span.source.as_deref() == Some("operations.ko"))
        }),
        "{}",
        diagnostics.render_human()
    );
    assert_eq!(
        diagnostics.diagnostics.len(),
        2,
        "{}",
        diagnostics.render_human()
    );
}

#[test]
fn package_resolution_recovery_reports_types_with_original_package_identity() {
    let request = SourcePackageGraphRequest {
        package: SourcePackageUnit {
            artifacts: Vec::new(),
            identity: "local/recover@1.0.0".into(),
            modules: vec![file(
                "lib.ko",
                "module Recover { export fn broken() -> int { missing } export fn wrong() -> int { true } }",
            )],
            sources: Vec::new(),
            imports: Vec::new(),
            exports: BTreeSet::from(["broken".into(), "wrong".into()]),
        },
        dependencies: Vec::new(),
    };
    let diagnostics = ModuleBuildGraph::default()
        .validate_package(request, LinkerOptions::default())
        .expect_err("resolution and independent typing must both fail")
        .into_diagnostics();
    assert_eq!(
        diagnostics.diagnostics.len(),
        2,
        "{}",
        diagnostics.render_human()
    );
    assert!(
        diagnostics
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "E_TAIL_TYPE_MISMATCH"),
        "{}",
        diagnostics.render_human()
    );
    assert!(diagnostics.diagnostics.iter().all(|diagnostic| {
        diagnostic
            .primary_span
            .as_ref()
            .is_some_and(|span| span.package_identity.as_deref() == Some("local/recover@1.0.0"))
    }));
}

#[test]
fn resolution_recovery_never_accepts_reduced_function_bodies() {
    let request = project(
        "seiyaku Recover { view fn broken() authorize(anyone) { missing; } view fn good() authorize(anyone) -> int { 1 } }",
        &[],
    );
    let diagnostics = ModuleBuildGraph::default()
        .link(request, LinkerOptions::default())
        .expect_err("an otherwise valid reduced graph must still fail")
        .into_diagnostics();
    assert_eq!(
        diagnostics.diagnostics.len(),
        1,
        "{}",
        diagnostics.render_human()
    );
    assert_eq!(diagnostics.diagnostics[0].code, "K2002");
}

#[test]
fn includes_share_state_types_functions_and_original_source_ranges() {
    let request = project(
        r#"seiyaku Wallet { include "./types.ko"; include "./ops.ko"; include "./types.ko"; view fn balance() authorize(anyone) -> int { read_balance() } }"#,
        &[
            (
                "types.ko",
                "error enum Failure { #[message(\"Balance is too low\")] Low = 1001; } struct Record { int amount; Failure failure; } state int funds; hajimari() { funds = 0; }",
            ),
            (
                "ops.ko",
                "fn read_balance() -> int { funds } fn failure() -> Failure { Failure::Low }",
            ),
        ],
    );
    let typed = link(request);
    assert_eq!(typed.items.len(), 4);
    assert_eq!(typed.states.len(), 1);
    assert!(
        typed
            .error_types
            .iter()
            .any(|error| error.identity.ends_with("Wallet::Failure"))
    );
    assert_eq!(typed.error_messages[0].message, "Balance is too low");
    assert_eq!(typed.source_files.len(), 3);
    let state_source = typed.states[0].source.expect("state source");
    assert_eq!(typed.source_files[&state_source.source].name(), "types.ko");
    let function = typed
        .items
        .iter()
        .find_map(|item| {
            let TypedItem::Function(function) = item;
            (function.name == "read_balance").then_some(function)
        })
        .unwrap();
    assert_eq!(
        typed.source_files[&function.source.unwrap().source].name(),
        "ops.ko"
    );
}
#[test]
fn included_constants_follow_depth_first_directive_order() {
    let valid = project(
        r#"seiyaku App { const int BASE = 2; include "sub/a.ko"; const int LAST = NEXT + 1; view fn value() authorize(anyone) -> int { LAST } }"#,
        &[("sub/a.ko", "const int NEXT = BASE + 1;")],
    );
    link(valid);
    let invalid = project(
        r#"seiyaku App { include "sub/a.ko"; const int BASE = 2; view fn value() authorize(anyone) -> int { NEXT } }"#,
        &[("sub/a.ko", "const int NEXT = BASE + 1;")],
    );
    assert!(
        !codes(invalid).is_empty(),
        "includes must not make forward constants legal"
    );
}
#[test]
fn nested_local_imports_export_functions_constants_and_nominal_types() {
    let request = project(
        r#"seiyaku App { import "lib/math.ko" as arithmetic; view fn value(arithmetic::Quote quote) authorize(anyone) -> int { arithmetic::twice(quote.amount) + arithmetic::SCALE } }"#,
        &[
            (
                "lib/math.ko",
                r#"module Math { import "../base.ko" as base; include "quote.ko"; export const int SCALE = base::FACTOR; export fn twice(int _ value) -> int { base::double(value) } }"#,
            ),
            (
                "lib/quote.ko",
                "export struct Quote { int amount; } export error enum Failure { #[message(\"Invalid quote\")] Invalid = 7; }",
            ),
            (
                "base.ko",
                "module Base { export const int FACTOR = 2; export fn double(int _ value) -> int { value * FACTOR } }",
            ),
        ],
    );
    let typed = link(request.clone());
    assert_eq!(typed.source_files.len(), 4);
    let error = typed
        .error_types
        .iter()
        .find(|error| error.identity.ends_with("::Math::Failure"))
        .expect("local error");
    assert!(error.identity.starts_with("local::"));
    assert!(error.identity.ends_with("::Math::Failure"));
    let mut alias = request.clone();
    alias.root.source = alias
        .root
        .source
        .replace("as arithmetic", "as other")
        .replace("arithmetic::", "other::");
    alias.sources.reverse();
    assert_eq!(typed.error_types, link(alias).error_types);
    let mut wording = request.clone();
    wording.sources[1].source = wording.sources[1]
        .source
        .replace("Invalid quote", "Quote invalid");
    assert_eq!(typed.error_types, link(wording).error_types);
    let mut moved = request;
    moved.root.source = moved.root.source.replace("lib/math.ko", "lib/renamed.ko");
    moved.sources[0].source_name = "lib/renamed.ko".into();
    assert_ne!(typed.error_types, link(moved).error_types);
}
#[test]
fn local_imports_require_explicit_exports_and_cannot_read_contract_state() {
    assert!(codes(project(r#"seiyaku App { import "math.ko" as arithmetic; view fn value() authorize(anyone) -> int { arithmetic::hidden() } }"#,
        &[("math.ko", "module Math { fn hidden() -> int { 1 } }")])).contains(&"E_UNEXPORTED_SYMBOL".into()));
    assert!(!codes(project(r#"seiyaku App { state int value; import "math.ko" as arithmetic; view fn read() authorize(anyone) -> int { arithmetic::read() } }"#,
        &[("math.ko", "module Math { export fn read() -> int { value } }")])).is_empty());
}
#[test]
fn graph_rejects_cycles_missing_files_and_shared_fragment_ownership() {
    let fixtures = [
        (
            project(
                r#"seiyaku App { include "a.ko"; }"#,
                &[
                    ("a.ko", r#"include "b.ko";"#),
                    ("b.ko", r#"include "a.ko";"#),
                ],
            ),
            "E_INCLUDE_CYCLE",
        ),
        (
            project(
                r#"seiyaku App { import "a.ko" as a; }"#,
                &[
                    ("a.ko", r#"module A { import "b.ko" as b; }"#),
                    ("b.ko", r#"module B { import "a.ko" as a; }"#),
                ],
            ),
            "E_LOCAL_IMPORT_CYCLE",
        ),
        (
            project(r#"seiyaku App { include "missing.ko"; }"#, &[]),
            "E_SOURCE_NOT_FOUND",
        ),
        (
            project(
                r#"seiyaku App { include "shared.ko"; import "math.ko" as arithmetic; }"#,
                &[
                    ("shared.ko", "const int ONE = 1;"),
                    ("math.ko", r#"module Math { include "shared.ko"; }"#),
                ],
            ),
            "E_SOURCE_OWNERSHIP",
        ),
        (
            project(
                r#"seiyaku App { include "module.ko"; }"#,
                &[("module.ko", "module Helper {}")],
            ),
            "E_SOURCE_UNIT_KIND",
        ),
        (
            project(r#"seiyaku App { include "../escape.ko"; }"#, &[]),
            "E_INVALID_SOURCE_PATH",
        ),
    ];
    for (request, expected) in fixtures {
        assert!(codes(request).contains(&expected.into()), "{expected}");
    }
}
#[test]
fn semantic_errors_in_fragments_retain_native_file_text() {
    let request = project(
        r#"seiyaku App { include "broken.ko"; }"#,
        &[(
            "broken.ko",
            "view fn value() authorize(anyone) -> int { true }",
        )],
    );
    let diagnostics = ModuleBuildGraph::default()
        .link(request, LinkerOptions::default())
        .unwrap_err()
        .into_diagnostics();
    assert!(diagnostics.diagnostics.iter().any(|diagnostic| {
        diagnostic
            .primary_span
            .as_ref()
            .and_then(|span| span.source.as_deref())
            == Some("broken.ko")
    }));
    assert!(diagnostics.render_human().contains("view fn value()"));
}
#[test]
fn package_constants_require_both_source_and_manifest_exports() {
    let mut request = project(
        "seiyaku App { view fn value() authorize(anyone) -> int { arithmetic::SCALE } }",
        &[],
    );
    request.imports.push(ImportBinding {
        alias: "arithmetic".into(),
        package: "demo/math@1".into(),
    });
    request.packages.push(SourcePackageUnit {
        artifacts: Vec::new(),
        identity: "demo/math@1".into(),
        modules: vec![file(
            "lib.ko",
            "module Math { export const int SCALE = 10; }",
        )],
        sources: Vec::new(),
        exports: BTreeSet::from(["SCALE".into()]),
        imports: Vec::new(),
    });
    link(request.clone());
    request.packages[0].modules[0].source = "module Math { const int SCALE = 10; }".into();
    assert!(codes(request).contains(&"E_UNEXPORTED_SYMBOL".into()));
}
#[test]
fn standalone_tests_include_helpers_and_import_local_modules() {
    let request = project(
        "seiyaku App { state int count; hajimari() { count = 0; } fn value() -> int { count } }",
        &[
            (
                "tests/checks.ko",
                "#[test] fn value_matches() { test::assert(value() == calc::ZERO); test::assert(helper() == 0); } fn helper() -> int { count }",
            ),
            (
                "tests/math.ko",
                "module Math { export const int ZERO = 0; }",
            ),
        ],
    );
    let test = file(
        "tests/unit.ko",
        r#"module Tests { koto_test { target: "../app.ko" } include "checks.ko"; import "math.ko" as calc; }"#,
    );
    let typed = ModuleBuildGraph::default()
        .link_sources_inner(
            request,
            &[test],
            LinkerOptions {
                test_builtins_enabled: true,
                include_tests: true,
                ..LinkerOptions::default()
            },
        )
        .unwrap_or_else(|error| panic!("{}", error.into_diagnostics().render_human()))
        .program;
    assert_eq!(typed.source_files.len(), 4);
    assert!(typed.items.iter().any(|item| {
        let TypedItem::Function(function) = item;
        function.name == "value_matches"
    }));
}
#[test]
fn fingerprints_cover_reachable_sources_only_but_bound_the_entire_inventory() {
    let graph = ModuleBuildGraph::default();
    let request = project(
        r#"seiyaku App { include "value.ko"; }"#,
        &[("value.ko", "view fn value() authorize(anyone) -> int { 1 }")],
    );
    let before = ModuleBuildGraph::fingerprint(&request).unwrap();
    let mut extra = request.clone();
    extra
        .sources
        .push(file("a-unused.ko", "malformed unused content"));
    let baseline_sources = graph
        .link(request.clone(), LinkerOptions::default())
        .unwrap()
        .program
        .source_files;
    let extended_sources = graph
        .link(extra.clone(), LinkerOptions::default())
        .unwrap()
        .program
        .source_files;
    assert_eq!(
        baseline_sources, extended_sources,
        "unreachable inventory cannot change source identities shared with cached reports"
    );
    assert_eq!(before, ModuleBuildGraph::fingerprint(&extra).unwrap());
    let canonical = ModuleBuildGraph::canonical_source_bundle(extra.clone()).unwrap();
    assert_eq!(canonical.sources.len(), 1);
    assert_eq!(canonical.sources[0].source_name, "value.ko");
    assert_eq!(before, ModuleBuildGraph::fingerprint(&canonical).unwrap());
    assert_eq!(
        graph
            .link(extra.clone(), LinkerOptions::default())
            .unwrap()
            .program
            .source_files
            .len(),
        2
    );
    extra.sources[0].source = "view fn value() authorize(anyone) -> int { 2 }".into();
    assert_ne!(before, ModuleBuildGraph::fingerprint(&extra).unwrap());
    extra.sources[1].source = " ".repeat(crate::source::MAX_SOURCE_BYTES + 1);
    assert_eq!(
        ModuleBuildGraph::fingerprint(&extra)
            .unwrap_err()
            .diagnostic_code(),
        "K0001"
    );
}
#[test]
fn included_contract_fragment_cannot_export_declarations() {
    assert!(
        codes(project(
            r#"seiyaku App { include "value.ko"; }"#,
            &[("value.ko", "export const int VALUE = 1;")]
        ))
        .contains(&"E_SOURCE_UNIT_KIND".into())
    );
}
#[test]
fn splitting_declarations_preserves_artifact_and_durable_interface() {
    let declarations = "error enum Failure { #[message(\"Balance too low\")] Low = 1001; } state int funds; hajimari() { funds = 0; }";
    let functions = "fn read_balance() -> int { funds } view fn balance() authorize(anyone) -> int { read_balance() } view fn failure() authorize(anyone) -> Failure { Failure::Low }";
    let session = crate::session::CompilerSession::new(crate::compiler::CompilerOptions::default());
    let single = session
        .build_source_bundle(project(
            &format!("seiyaku Wallet {{ {declarations} {functions} }}"),
            &[],
        ))
        .unwrap();
    let split = session
        .build_source_bundle(project(
            r#"seiyaku Wallet { include "state.ko"; include "functions.ko"; }"#,
            &[("state.ko", declarations), ("functions.ko", functions)],
        ))
        .unwrap();
    assert_eq!(single.contract_interface, split.contract_interface);
    assert_eq!(single.artifact, split.artifact);
}
#[test]
fn test_fingerprint_includes_test_only_companions() {
    let graph = ModuleBuildGraph::default();
    let mut request = project(
        "seiyaku App { fn value() -> int { 1 } }",
        &[(
            "checks.ko",
            "#[test] fn check() { test::assert(value() == 1); }",
        )],
    );
    let test = file(
        "tests.ko",
        r#"module Tests { koto_test { target: "app.ko" } include "checks.ko"; }"#,
    );
    let options = LinkerOptions {
        test_builtins_enabled: true,
        include_tests: true,
        ..LinkerOptions::default()
    };
    let before = graph
        .link_sources_inner(request.clone(), std::slice::from_ref(&test), options)
        .unwrap();
    request.sources[0].source = request.sources[0].source.replace("== 1", "== 2");
    let after = graph.link_sources_inner(request, &[test], options).unwrap();
    assert_ne!(before.fingerprint, after.fingerprint);
}
#[test]
fn included_argument_table_overflow_has_native_declaration_diagnostics() {
    let parameters = (0..=crate::regalloc::MAX_ARGUMENT_VALUES)
        .map(|index| format!("int p{index}"))
        .collect::<Vec<_>>()
        .join(", ");
    let fragment = format!("fn too_many({parameters}) {{}}");
    let request = project(
        r#"seiyaku App { include "large.ko"; }"#,
        &[("large.ko", &fragment)],
    );
    let diagnostics = ModuleBuildGraph::default()
        .link(request, LinkerOptions::default())
        .unwrap_err()
        .into_diagnostics();
    assert!(
        diagnostics
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "K2007"
                && diagnostic
                    .primary_span
                    .as_ref()
                    .and_then(|span| span.source.as_deref())
                    == Some("large.ko")),
        "{}",
        diagnostics.render_human()
    );
}
#[test]
fn standalone_test_source_catalog_is_retained() {
    let target = crate::session::TestSourceUnit {
        source_name: "app.ko".into(),
        source: "seiyaku App { fn value() -> int { 1 } }".into(),
    };
    let tests = crate::session::TestSourceUnit { source_name: "tests.ko".into(), source: r#"module Tests { koto_test { target: "app.ko" } error enum Failure { #[message("A test failure")] Bad = 1; } #[test] fn ok() { require(value() == 1, Failure::Bad); } }"#.into() };
    let session = crate::session::CompilerSession::new(crate::compiler::CompilerOptions {
        mode: crate::compiler::CompilerMode::Test,
        ..crate::compiler::CompilerOptions::default()
    });
    let output = session.build_test_sources(&target, &[tests]).unwrap();
    assert!(
        output
            .suite
            .contract_interface
            .error_messages
            .iter()
            .any(|entry| entry.message == "A test failure")
    );
}

#[test]
fn dependency_path_errors_point_at_native_fragment_directives() {
    let request = project(
        r#"seiyaku App { include "sub/helpers.ko"; }"#,
        &[("sub/helpers.ko", r#"include "../../escape.ko";"#)],
    );
    let diagnostics = ModuleBuildGraph::default()
        .link(request, LinkerOptions::default())
        .unwrap_err()
        .into_diagnostics();
    let diagnostic = &diagnostics.diagnostics[0];
    assert_eq!(diagnostic.code, "E_INVALID_SOURCE_PATH");
    assert_eq!(
        diagnostic
            .primary_span
            .as_ref()
            .and_then(|span| span.source.as_deref()),
        Some("sub/helpers.ko")
    );
    assert!(diagnostic.primary_source.is_some());
}

#[test]
fn canonical_package_bundle_discards_unreachable_companions() {
    let request = SourcePackageGraphRequest {
        package: SourcePackageUnit {
            artifacts: Vec::new(),
            identity: "demo/library@1".into(),
            modules: vec![file(
                "src/lib.ko",
                r#"module Library { include "parts.ko"; }"#,
            )],
            sources: vec![
                file("src/unused.ko", "invalid unused source"),
                file("src/parts.ko", "export const int VALUE = 7;"),
            ],
            exports: BTreeSet::from(["VALUE".into()]),
            imports: Vec::new(),
        },
        dependencies: Vec::new(),
    };
    let before = ModuleBuildGraph::package_fingerprint(&request).unwrap();
    let canonical = ModuleBuildGraph::canonical_source_package_bundle(request).unwrap();
    assert_eq!(canonical.package.sources.len(), 1);
    assert_eq!(canonical.package.sources[0].source_name, "src/parts.ko");
    assert_eq!(
        before,
        ModuleBuildGraph::package_fingerprint(&canonical).unwrap()
    );
    ModuleBuildGraph::default()
        .validate_package(canonical, LinkerOptions::default())
        .unwrap();
}

#[test]
fn permissions_share_include_scope_and_repeated_includes_deduplicate() {
    let typed = link(project(
        r#"seiyaku Guards { include "permissions.ko"; include "permissions.ko"; include "operations.ko"; }"#,
        &[
            (
                "permissions.ko",
                r#"permission Admin; import permission "CanSetParameters" as ChainAdmin;"#,
            ),
            (
                "operations.ko",
                "kotoage fn update() authorize(Admin) {} view fn inspect() authorize(ChainAdmin) -> int { 1 }",
            ),
        ],
    ));
    assert_eq!(typed.permissions.len(), 2);
    assert_eq!(typed.permissions[0].name.as_ref(), "Admin");
    assert_eq!(typed.permissions[1].name.as_ref(), "ChainAdmin");
    let duplicate = codes(project(
        r#"seiyaku Guards { permission Admin; include "permissions.ko"; view fn inspect() authorize(Admin) {} }"#,
        &[("permissions.ko", "permission Admin;")],
    ));
    assert!(
        duplicate
            .iter()
            .any(|code| code == "E_DUPLICATE_DECLARATION")
    );
}

#[test]
fn authorization_typo_is_a_resolved_declaration_error_with_suggestion() {
    let diagnostics = ModuleBuildGraph::default()
        .link(
            project(
                "seiyaku Guards { permission Admin; kotoage fn update() authorize(Admn) {} }",
                &[],
            ),
            LinkerOptions::default(),
        )
        .expect_err("undeclared authorization must fail")
        .into_diagnostics();
    let error = diagnostics
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "E_UNKNOWN_PERMISSION")
        .expect("permission name diagnostic");
    assert!(
        error
            .help
            .as_deref()
            .is_some_and(|help| help.contains("did you mean `Admin`")),
        "{}",
        diagnostics.render_human()
    );
}

#[test]
fn imported_lowering_names_preserve_user_and_builtin_targets() {
    let typed = link(project(
        r#"seiyaku App {
            import "helpers.ko" as helpers;
            view fn read(int value) authorize(anyone) -> int { helpers::min(value) }
        }"#,
        &[(
            "helpers.ko",
            r#"module Helpers {
            fn authority(int value) -> int { value + 100 }
            export fn min(int value) -> int { math::min(authority(value), value) }
        }"#,
        )],
    ));
    let lowered = crate::ir::lower(&typed).expect("linked typed identities lower");
    let helpers = lowered
        .functions
        .iter()
        .filter(|function| function.name.starts_with("__kotodama_link_"))
        .collect::<Vec<_>>();
    assert_eq!(
        helpers.len(),
        2,
        "both imported private functions are retained"
    );
    let user_calls = lowered
        .functions
        .iter()
        .flat_map(|function| &function.blocks)
        .flat_map(|block| &block.instrs)
        .filter(|instruction| matches!(instruction, crate::ir::Instr::Call { .. }))
        .count();
    assert_eq!(
        user_calls, 2,
        "root import and private authority remain ordinary calls"
    );
}

#[test]
fn imported_module_aliases_cannot_bypass_trigger_callback_validation() {
    let request = project(
        r#"seiyaku Callback { import "callbacks.ko" as callbacks; kotoage fn local() authorize(anyone) {} trigger wake -> callbacks::run { on time pre_commit; } }"#,
        &[("callbacks.ko", "module Callbacks { export fn run() {} }")],
    );
    assert!(
        codes(request)
            .iter()
            .any(|code| code == "E_TRIGGER_TARGET_NAMESPACE")
    );
}
#[test]
fn included_trigger_schedule_constants_keep_original_expression_identity() {
    let request = project(
        r#"seiyaku Clock { include "constants.ko"; kotoage fn run() authorize(anyone) {} trigger wake -> run { on time schedule(start_ms: START + 500, period_ms: PERIOD); } }"#,
        &[(
            "constants.ko",
            "const int START = 1_000; const int PERIOD = 60 * 1_000;",
        )],
    );
    let typed = link(request);
    assert_eq!(typed.triggers.len(), 1);
    assert!(matches!(&typed.triggers[0].filter,
        iroha_data_model::events::EventFilterBox::Time(iroha_data_model::events::time::TimeEventFilter(iroha_data_model::events::time::ExecutionTime::Schedule(schedule)))
        if schedule.start_ms == 1500 && schedule.period_ms == Some(60000)));
}

#[test]
fn ordinary_enums_keep_local_import_and_included_nominal_identity() {
    let request = project(
        r#"seiyaku App { include "status.ko"; import "data.ko" as data;
            view fn local(Status value) authorize(anyone) -> Status { value }
            view fn remote(data::Status value) authorize(anyone) -> data::Status { value }
        }"#,
        &[
            ("status.ko", "enum Status { Active = 1, Paused = 2 }"),
            (
                "data.ko",
                "module Data { export enum Status { Active = 1, Paused = 2 } }",
            ),
        ],
    );
    let typed = link(request.clone());
    assert_eq!(typed.enum_types.len(), 2);
    assert_ne!(typed.enum_types[0].identity, typed.enum_types[1].identity);
    assert!(
        typed
            .error_types
            .iter()
            .all(|error| !error.identity.ends_with("::Status"))
    );
    let mut invalid = request;
    invalid.root.source = invalid
        .root
        .source
        .replace("-> Status { value }", "-> Status { data::Status::Active }");
    assert!(
        codes(invalid)
            .iter()
            .any(|code| code == "E_TAIL_TYPE_MISMATCH")
    );
}

#[test]
fn ordinary_enum_locked_package_identity_ignores_alias_but_binds_version() {
    let make_request = |alias: &str, identity: &str| SourceLinkRequest {
        artifacts: Vec::new(),
        root: file(
            "app.ko",
            &format!(
                "seiyaku App {{ view fn echo({alias}::Status value) authorize(anyone) -> {alias}::Status {{ match value {{ {alias}::Status::Active => value, {alias}::Status::Paused => value }} }} }}"
            ),
        ),
        sources: Vec::new(),
        imports: vec![ImportBinding {
            alias: alias.into(),
            package: identity.into(),
        }],
        packages: vec![SourcePackageUnit {
            artifacts: Vec::new(),
            identity: identity.into(),
            modules: vec![file(
                "lib.ko",
                "module Data { export enum Status { Active = 1, Paused = 2 } }",
            )],
            sources: Vec::new(),
            imports: Vec::new(),
            exports: BTreeSet::from(["Status".into()]),
        }],
    };
    let original = link(make_request("data", "org/data@1.0.0"));
    let renamed = link(make_request("renamed", "org/data@1.0.0"));
    let upgraded = link(make_request("data", "org/data@2.0.0"));
    assert_eq!(original.enum_types, renamed.enum_types);
    assert_ne!(original.enum_types, upgraded.enum_types);
    assert_eq!(
        original.enum_types[0].identity,
        "org/data@1.0.0::Data::Status"
    );
}

#[test]
fn imported_aliases_cannot_repeat_one_nominal_variant_to_fake_exhaustiveness() {
    for kind in ["enum", "error enum"] {
        let library =
            format!("module Data {{ export {kind} Status {{ Active = 1, Paused = 2 }} }}");
        let request = project(
            r#"seiyaku MatchAliases {
            import "data.ko" as left;
            import "data.ko" as right;
            view fn read(left::Status value) authorize(anyone) -> int {
                match value { left::Status::Active => 1, right::Status::Active => 2 }
            }
        }"#,
            &[("data.ko", &library)],
        );
        assert!(
            codes(request)
                .iter()
                .any(|code| code == "E_MATCH_DUPLICATE_PATTERN")
        );
    }
}

#[test]
fn event_payloads_resolve_imported_nominal_types_and_included_declarations() {
    let typed = link(project(
        r#"seiyaku Events {
        import "data.ko" as data;
        include "events.ko";
        kotoage fn run(data::Status status) authorize(anyone) { emit Changed { status }; }
    }"#,
        &[
            ("events.ko", "event Changed { data::Status status; }"),
            (
                "data.ko",
                "module Data { export enum Status { Active = 1, Paused = 2 } }",
            ),
        ],
    ));
    assert_eq!(typed.events.len(), 1);
    assert!(typed.events[0].validate());
    assert!(typed.events[0].payload_type.nodes.iter().any(|node| matches!(node, iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Enum(descriptor) if typed.enum_types.contains(descriptor))));
}

#[test]
fn compiled_contract_imports_admit_exact_owner_artifacts() {
    let artifact = crate::compiler::Compiler::new()
        .compile_source("seiyaku Pool { view fn quote() authorize(anyone) -> int { 7 } }")
        .unwrap();
    let expected = ivm_artifact_admission::verify_contract_artifact(&artifact).unwrap();
    let mut request = project(
        r#"seiyaku App { import seiyaku "./interfaces/pool.to" as Pool; view fn value() authorize(anyone) -> int { 1 } }"#,
        &[],
    );
    request.artifacts.push(SourceContractArtifact {
        source_name: "interfaces/pool.to".into(),
        artifact: artifact.clone(),
    });
    let resolved = ModuleBuildGraph::default()
        .resolve_sources(request.clone())
        .unwrap();
    assert_eq!(
        resolved.root.contracts["Pool"].code_hash,
        expected.code_hash
    );
    assert_eq!(
        *resolved.root.contracts["Pool"].interface,
        expected.contract_interface
    );
    // An identically named file in another package is never visible to the root owner.
    request.artifacts.clear();
    request.packages.push(SourcePackageUnit {
        identity: "local/other@1".into(),
        artifacts: vec![SourceContractArtifact {
            source_name: "interfaces/pool.to".into(),
            artifact,
        }],
        modules: vec![file(
            "lib.ko",
            "module Other { export fn value() -> int { 3 } }",
        )],
        sources: vec![],
        exports: BTreeSet::from(["Other::value".into()]),
        imports: vec![],
    });
    let diagnostics = ModuleBuildGraph::default()
        .resolve_sources(request)
        .unwrap_err()
        .into_diagnostics();
    let diagnostic = diagnostics
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "E_CONTRACT_IMPORT_NOT_FOUND")
        .unwrap();
    assert_eq!(
        diagnostic.primary_span.as_ref().unwrap().source.as_deref(),
        Some("app.ko")
    );
}

#[test]
fn compiled_contract_imports_reject_invalid_bytes_and_alias_collisions() {
    let mut request = project(
        r#"seiyaku App { import seiyaku "./pool.to" as Pool; }"#,
        &[],
    );
    request.artifacts.push(SourceContractArtifact {
        source_name: "pool.to".into(),
        artifact: b"not a complete artifact".to_vec(),
    });
    assert!(
        codes(request)
            .iter()
            .any(|code| code == "E_CONTRACT_IMPORT_INVALID")
    );
    let artifact = crate::compiler::Compiler::new()
        .compile_source("seiyaku Pool { view fn quote() authorize(anyone) -> int { 7 } }")
        .unwrap();
    let mut request = project(
        r#"seiyaku App { import seiyaku "./pool.to" as Pool; import "helper.ko" as Pool; }"#,
        &[(
            "helper.ko",
            "module Helper { export fn value() -> int { 1 } }",
        )],
    );
    request.artifacts.push(SourceContractArtifact {
        source_name: "pool.to".into(),
        artifact,
    });
    assert!(
        codes(request)
            .iter()
            .any(|code| code == "E_DUPLICATE_IMPORT")
    );
}

#[test]
fn compiled_artifact_inventory_identity_binds_paths_bytes_and_owner() {
    let mut request = project("seiyaku App {}", &[]);
    request.artifacts.push(SourceContractArtifact {
        source_name: "interfaces/./pool.to".into(),
        artifact: vec![1, 2, 3],
    });
    let first = ModuleBuildGraph::fingerprint(&request).unwrap();
    request.artifacts[0].source_name = "interfaces/pool.to".into();
    assert_eq!(first, ModuleBuildGraph::fingerprint(&request).unwrap());
    request.artifacts[0].artifact[0] = 9;
    assert_ne!(first, ModuleBuildGraph::fingerprint(&request).unwrap());
    assert_eq!(
        resolve_contract_artifact_path("src/lib.ko", "../interfaces/pool.to").unwrap(),
        "interfaces/pool.to"
    );
    for path in ["../../pool.to", "/pool.to", "pool.ko", "pool.json"] {
        assert!(
            resolve_contract_artifact_path("src/lib.ko", path).is_err(),
            "{path}"
        );
    }
    request.artifacts.push(request.artifacts[0].clone());
    assert!(matches!(
        ModuleBuildGraph::fingerprint(&request),
        Err(SourceGraphError::DuplicateSource { .. })
    ));
}

#[test]
fn unused_empty_artifacts_reject_in_root_package_and_dependency_inventories() {
    let empty = SourceContractArtifact {
        source_name: "interfaces/./unused.to".into(),
        artifact: Vec::new(),
    };
    let assert_empty = |error: SourceGraphError, scope: &str| {
        assert_eq!(error.diagnostic_code(), "E_CONTRACT_IMPORT_INVALID");
        assert_eq!(
            error,
            SourceGraphError::EmptyArtifact {
                scope: scope.into(),
                source: "interfaces/unused.to".into(),
            }
        );
        assert!(
            error
                .into_diagnostics()
                .render_human()
                .contains("complete .to bytes")
        );
    };
    let mut root = project("seiyaku App {}", &[]);
    root.artifacts.push(empty.clone());
    assert_empty(ModuleBuildGraph::fingerprint(&root).unwrap_err(), "root");
    assert_empty(
        ModuleBuildGraph::default()
            .resolve_sources(root)
            .unwrap_err(),
        "root",
    );

    let package = SourcePackageUnit {
        identity: "local/library@1".into(),
        artifacts: vec![empty],
        modules: vec![file(
            "lib.ko",
            "module Library { export fn value() -> int { 1 } }",
        )],
        sources: vec![],
        exports: BTreeSet::from(["value".into()]),
        imports: vec![],
    };
    let local = SourcePackageGraphRequest {
        package: package.clone(),
        dependencies: vec![],
    };
    assert_empty(
        ModuleBuildGraph::package_fingerprint(&local).unwrap_err(),
        "local/library@1",
    );
    assert_empty(
        ModuleBuildGraph::default()
            .resolve_package_sources(local)
            .unwrap_err(),
        "local/library@1",
    );

    let mut root = project("seiyaku App {}", &[]);
    root.packages.push(package);
    assert_empty(
        ModuleBuildGraph::fingerprint(&root).unwrap_err(),
        "local/library@1",
    );
}
