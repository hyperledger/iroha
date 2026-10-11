//! Linker regressions for source graphs, import resolution, and deterministic diagnostics.
use super::*;
use crate::ast::Statement;
#[test]
fn every_fixed_linker_diagnostic_is_explainable_as_resolve() {
    let errors = [
        LinkError::RootMustBeSeiyaku {
            source: "root.ko".to_owned(),
        },
        LinkError::DependencyMustBeModule {
            source: "dependency.ko".to_owned(),
        },
        LinkError::DuplicatePackage {
            package: "pkg".to_owned(),
        },
        LinkError::EmptyPackage {
            package: "pkg".to_owned(),
        },
        LinkError::DuplicateModule {
            package: "pkg".to_owned(),
            module: "Math".to_owned(),
        },
        LinkError::DuplicateImport {
            scope: "root".to_owned(),
            alias: "math".to_owned(),
        },
        LinkError::ReservedImport {
            scope: "root".to_owned(),
            alias: "state".to_owned(),
        },
        LinkError::DuplicateSymbol {
            source: "module.ko".to_owned(),
            symbol: "value".to_owned(),
        },
        LinkError::UnknownPackage {
            scope: "root".to_owned(),
            package: "missing".to_owned(),
        },
        LinkError::PackageImportCycle {
            cycle: vec!["a".to_owned(), "b".to_owned(), "a".to_owned()],
        },
        LinkError::UnknownAlias {
            source: "root.ko".to_owned(),
            alias: "missing".to_owned(),
        },
        LinkError::UnexportedSymbol {
            source: "root.ko".to_owned(),
            alias: "math".to_owned(),
            symbol: "hidden".to_owned(),
        },
        LinkError::MissingExport {
            package: "pkg".to_owned(),
            symbol: "missing".to_owned(),
        },
        LinkError::AmbiguousExport {
            package: "pkg".to_owned(),
            symbol: "value".to_owned(),
        },
        LinkError::WildcardImport {
            source: "root.ko".to_owned(),
        },
        LinkError::InvalidIdentifier {
            context: "module".to_owned(),
            name: "not-valid".to_owned(),
        },
        LinkError::ReservedSymbol {
            source: "module.ko".to_owned(),
            symbol: "state".to_owned(),
        },
        LinkError::InvalidModuleItem {
            source: "module.ko".to_owned(),
            item: "state declaration".to_owned(),
        },
        LinkError::ConflictingErrorType {
            identity: "example@1::Module::Error".into(),
        },
        LinkError::ConflictingEnumType {
            identity: "example@1::Module::Status".into(),
        },
        LinkError::DuplicateMessage {
            key: "errors.failed".to_owned(),
        },
    ];
    for error in errors {
        let code = error.diagnostic_code();
        let explanation = crate::diagnostic::diagnostic_explanation(code)
            .unwrap_or_else(|| panic!("{code} must work with `koto explain`"));
        assert_eq!(
            explanation.phase,
            crate::diagnostic::DiagnosticPhase::Resolve,
            "{code}",
        );
    }
}
#[test]
fn source_graph_preserves_semantic_code_independently_of_localized_message() {
    let error = SourceGraphError::from(LinkError::Semantic {
        diagnostics: DiagnosticBundle::single(Diagnostic::error(
            "E_LIST_CAPACITY",
            DiagnosticPhase::Semantic,
            "la capacité dépasse la limite",
            None,
        )),
    });
    assert_eq!(error.diagnostic_code(), "E_LIST_CAPACITY");
    assert!(error.to_string().contains("[E_LIST_CAPACITY]"));
    assert!(error.to_string().contains("la capacité dépasse la limite"));
}
fn spanned(source: &str) -> SpannedProgram {
    let file = SourceFile::new(SourceId(0), "cache-fixture.ko", source);
    crate::parser::parse_source_spanned(&file, FrontendBudget::v1())
        .map(|(program, _)| program)
        .expect("parse spanned linker fixture")
}
fn source(name: &str, source: &str) -> ModuleUnit {
    let source_id = SourceId(
        name.bytes()
            .fold(2_166_136_261_u32, |hash, byte| {
                hash.wrapping_mul(16_777_619) ^ u32::from(byte)
            })
            .max(1),
    );
    let file = SourceFile::new(source_id, name, source);
    let (program, _) = crate::parser::parse_source_spanned(&file, FrontendBudget::v1())
        .expect("parse linker fixture");
    let imports = program
        .facts
        .calls
        .iter()
        .filter_map(|call| {
            call.name
                .split_once("::")
                .map(|(alias, _)| alias.to_owned())
        })
        .map(|alias| (alias, ()))
        .collect::<BTreeMap<_, _>>();
    ModuleUnit {
        contracts: BTreeMap::new(),
        source_name: name.to_owned(),
        program: crate::resolved::resolve_with_imports(program, &file, &imports)
            .expect("resolve linker fixture"),
    }
}
fn source_slice(source: &str, range: crate::source::TextRange) -> Option<&str> {
    source.get(usize::try_from(range.start).ok()?..usize::try_from(range.end).ok()?)
}
fn package(modules: Vec<ModuleUnit>, exports: &[&str]) -> PackageUnit {
    PackageUnit {
        identity: "std/math@1.0.0".to_owned(),
        modules,
        exports: exports.iter().map(|name| (*name).to_owned()).collect(),
        imports: Vec::new(),
    }
}
fn request(root: ModuleUnit, package: PackageUnit) -> LinkRequest {
    LinkRequest {
        local_modules: Vec::new(),
        root,
        imports: vec![ImportBinding {
            alias: "arith".to_owned(),
            package: package.identity.clone(),
        }],
        packages: vec![package],
    }
}
#[test]
fn locked_graph_order_preserves_complete_nominal_error_identity_and_schema() {
    let mut expected = None;
    // Change every independent input order; identities must not depend on the
    // linker's traversal or allocation of internal symbol names.
    for order in 0..8 {
        let mut packages = ["left", "right"]
            .into_iter()
            .map(|name| {
                let mut modules = vec![
                    source_module(
                        "errors.ko",
                        "module Errors { export error enum Fault { Denied = 1; Missing = 2; } }",
                    ),
                    source_module(
                        "more.ko",
                        "module MoreErrors { export error enum OtherFault { Denied = 1; Missing = 2; } }",
                    ),
                ];
                if order & 2 != 0 {
                    modules.reverse();
                }
                SourcePackageUnit { artifacts: Vec::new(), sources: Vec::new(),
                    identity: format!("std/{name}@1.0.0"),
                    modules,
                    exports: ["Fault", "OtherFault"]
                        .into_iter()
                        .map(str::to_owned)
                        .collect(),
                    imports: Vec::new(),
                }
            })
            .collect::<Vec<_>>();
        if order & 1 != 0 {
            packages.reverse();
        }
        let mut imports = ["left", "right"]
            .into_iter()
            .map(|name| ImportBinding {
                alias: name.to_owned(),
                package: format!("std/{name}@1.0.0"),
            })
            .collect::<Vec<_>>();
        if order & 4 != 0 {
            imports.reverse();
        }
        let linked = ModuleBuildGraph::default()
                    .link(
                        SourceLinkRequest { artifacts: Vec::new(), sources: Vec::new(),
                            root: source_module("app.ko", "seiyaku App { view fn run() authorize(anyone) -> (left::Fault, right::Fault, left::OtherFault, right::OtherFault) { (left::Fault::Denied, right::Fault::Missing, left::OtherFault::Missing, right::OtherFault::Denied) } }"),
                            imports,
                            packages,
                        },
                        LinkerOptions::default(),
                    )
                    .expect("all locked graph orders resolve the same nominal values");
        let catalog = linked
            .program
            .error_types
            .iter()
            .filter(|error| error.identity.starts_with("std/"))
            .map(|error| (error.identity.clone(), error.clone()))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            catalog.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "std/left@1.0.0::Errors::Fault",
                "std/left@1.0.0::MoreErrors::OtherFault",
                "std/right@1.0.0::Errors::Fault",
                "std/right@1.0.0::MoreErrors::OtherFault",
            ],
            "the locked package, source unit and enum define each identity",
        );
        let variant_schema = catalog.values().next().unwrap().schema_hash();
        for descriptor in catalog.values() {
            assert!(descriptor.validate());
            assert_eq!(descriptor.variant(1).unwrap().name, "Denied");
            assert_eq!(descriptor.variant(2).unwrap().name, "Missing");
            assert_eq!(descriptor.schema_hash(), variant_schema);
        }
        let output = crate::compiler::Compiler::new()
            .compile_typed_program_with_manifest_and_report_diagnostics(
                linked.program,
                Some("app.ko"),
            )
            .unwrap_or_else(|diagnostics| panic!("{}", diagnostics.render_human()));
        let interface = crate::metadata::ProgramMetadata::parse(&output.artifact)
            .expect("parse the reordered graph's artifact")
            .contract_interface
            .expect("the exact nominal catalog reaches the embedded interface");
        let embedded = interface
            .error_types
            .iter()
            .filter(|error| error.identity.starts_with("std/"))
            .map(|error| (error.identity.clone(), error.clone()))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(embedded, catalog);
        let result = interface
            .entrypoints
            .iter()
            .find(|entrypoint| entrypoint.name == "run")
            .unwrap()
            .return_schema
            .clone()
            .expect("all four nominal return values have a public schema");
        if let Some((expected_catalog, expected_result)) = &expected {
            assert_eq!(&catalog, expected_catalog, "graph order {order}");
            assert_eq!(&result, expected_result, "graph order {order}");
        } else {
            expected = Some((catalog, result));
        }
    }
}

#[test]
fn imported_nominal_types_support_construction_patterns_and_error_values() {
    let linked = ModuleBuildGraph::default().link(SourceLinkRequest { artifacts: Vec::new(), sources: Vec::new(),
            root: source_module("app.ko", "seiyaku App { view fn run() authorize(anyone) -> int { let arith::Receipt receipt = arith::Receipt { amount: 7, ignored: 9 }; let arith::Receipt { amount, .. } = receipt; let arith::Fault failure = arith::Fault::Denied; let result = match failure { arith::Fault::Denied => amount }; arith::read(receipt: arith::Receipt { amount: result, ignored: 0 }) } }"),
            imports: vec![ImportBinding { alias: "arith".into(), package: "std/math@1.0.0".into() }],
            packages: vec![SourcePackageUnit { artifacts: Vec::new(), sources: Vec::new(),
                identity: "std/math@1.0.0".into(),
                modules: vec![source_module("math.ko", "module Math { export struct Receipt { int ignored; int amount; } export error enum Fault { Denied = 1; } export fn read(Receipt receipt) -> int { let Receipt { amount, .. } = receipt; amount } }")],
                exports: ["Receipt", "Fault", "read"].into_iter().map(str::to_owned).collect(),
                imports: Vec::new(),
            }],
        }, LinkerOptions::default()).expect("exported nominal types link across aliases");
    assert!(
        linked
            .program
            .error_types
            .iter()
            .any(|ty| ty.identity == "std/math@1.0.0::Math::Fault")
    );
    let read = linked
        .program
        .items
        .iter()
        .find_map(|item| {
            let TypedItem::Function(function) = item;
            (function.param_types.len() == 1).then_some(function)
        })
        .expect("read function");
    assert!(
        matches!(&read.param_types[0].ty, Type::Struct { name, .. } if name == "std/math@1.0.0::Math::Receipt")
    );
}
#[test]
fn imported_structs_keep_locked_identity_in_public_and_durable_schemas() {
    fn compile(alias: &str, package_identity: &str) -> crate::session::CompileOutput {
        let root = format!(
            r#"seiyaku App {{ permission Writer;
                    state {alias}::Receipt saved;
                    hajimari() {{
                        saved = {alias}::Receipt {{
                            amount: 0, marker: (), outcome: Result::err({alias}::Fault::Denied)
                        }};
                    }}
                    kotoage fn echo({alias}::Receipt value) authorize(Writer) -> {alias}::Receipt {{
                        saved = value;
                        return saved;
                    }}
                    view fn readback() authorize(anyone) -> {alias}::Receipt {{ saved }}
                }}"#
        );
        let linked = ModuleBuildGraph::default()
                .link(
                    SourceLinkRequest { artifacts: Vec::new(), sources: Vec::new(),
                        root: source_module("app.ko", &root),
                        imports: vec![ImportBinding {
                            alias: alias.into(),
                            package: package_identity.into(),
                        }],
                        packages: vec![SourcePackageUnit { artifacts: Vec::new(), sources: Vec::new(),
                            identity: package_identity.into(),
                            modules: vec![source_module(
                                "math.ko",
                                "module Math { export error enum Fault { Denied = 7; } export struct Receipt { () marker; int amount; Result<(), Fault> outcome; } }",
                            )],
                            exports: ["Receipt", "Fault"]
                                .into_iter()
                                .map(str::to_owned)
                                .collect(),
                            imports: Vec::new(),
                        }],
                    },
                    LinkerOptions::default(),
                )
                .expect("link public imported value types");
        crate::compiler::Compiler::new()
            .compile_typed_program_with_manifest_and_report_diagnostics(
                linked.program,
                Some("app.ko"),
            )
            .unwrap_or_else(|diagnostics| panic!("{}", diagnostics.render_human()))
    }

    use ivm_abi::entrypoint::EntrypointValueTypeNodeV1 as Node;
    let mut schemas = Vec::new();
    for (alias, package_identity) in [
        ("arith", "std/math@1.0.0"),
        ("renamed", "std/math@1.0.0"),
        ("arith", "std/math@2.0.0"),
    ] {
        let output = compile(alias, package_identity);
        let interface = crate::metadata::ProgramMetadata::parse(&output.artifact)
            .expect("parse final imported-struct artifact")
            .contract_interface
            .expect("embedded signed interface");
        let expected_name = format!("{package_identity}::Math::Receipt");
        let expected_error = format!("{package_identity}::Math::Fault");
        let echo = interface
            .entrypoints
            .iter()
            .find(|entry| entry.name == "echo")
            .expect("public echo");
        let arguments = echo
            .argument_schema
            .as_ref()
            .expect("record argument schema");
        let result = echo.return_schema.as_ref().expect("record return schema");
        assert!(result.validate());
        assert_eq!(arguments.fields[0].ty, *result);
        assert!(matches!(&result.nodes[0], Node::Struct(node) if node.name == expected_name));
        assert!(result.nodes.iter().any(|node| {
            matches!(node, Node::Error(error) if error.identity == expected_error)
        }));
        let saved = interface
            .states
            .iter()
            .find(|state| state.name == "saved")
            .expect("durable imported struct");
        assert!(matches!(
            &saved.ty,
            crate::metadata::EmbeddedStateType::Struct { name, .. } if name == &expected_name
        ));
        assert_eq!(
            interface
                .entrypoints
                .iter()
                .find(|entry| entry.name == "readback")
                .unwrap()
                .return_schema
                .as_ref(),
            Some(result)
        );
        schemas.push(result.clone());
    }
    assert_eq!(
        schemas[0], schemas[1],
        "source import aliases do not define identity"
    );
    assert_ne!(
        schemas[0], schemas[2],
        "the locked package identity defines nominal types"
    );
}
#[test]
fn imported_types_resolve_dependency_signatures_before_identity_order() {
    let base = SourcePackageUnit {
        artifacts: Vec::new(),
        sources: Vec::new(),
        identity: "z/base@1.0.0".into(),
        modules: vec![source_module(
            "base.ko",
            "module Base { export struct Value { int amount; } }",
        )],
        exports: ["Value".to_owned()].into_iter().collect(),
        imports: Vec::new(),
    };
    let derived = SourcePackageUnit {
        artifacts: Vec::new(),
        sources: Vec::new(),
        identity: "a/derived@1.0.0".into(),
        modules: vec![source_module(
            "derived.ko",
            "module Derived { export fn read(base::Value value) -> int { let base::Value { amount } = value; amount } }",
        )],
        exports: ["read".to_owned()].into_iter().collect(),
        imports: vec![ImportBinding {
            alias: "base".into(),
            package: base.identity.clone(),
        }],
    };
    ModuleBuildGraph::default().link(SourceLinkRequest { artifacts: Vec::new(), sources: Vec::new(),
            root: source_module("app.ko", "seiyaku App { view fn run() authorize(anyone) -> int { derived::read(value: base::Value { amount: 7 }) } }"),
            imports: vec![ImportBinding { alias: "derived".into(), package: derived.identity.clone() }, ImportBinding { alias: "base".into(), package: base.identity.clone() }],
            packages: vec![derived, base],
        }, LinkerOptions::default()).expect("dependency canonical type identities agree in signatures and bodies");
}
#[test]
fn same_named_imported_errors_remain_nominally_distinct() {
    let packages = ["left", "right"]
        .into_iter()
        .map(|name| SourcePackageUnit {
            artifacts: Vec::new(),
            sources: Vec::new(),
            identity: format!("std/{name}@1.0.0"),
            modules: vec![source_module(
                "errors.ko",
                "module Errors { export error enum Fault { Denied = 1; } }",
            )],
            exports: ["Fault".to_owned()].into_iter().collect(),
            imports: Vec::new(),
        })
        .collect::<Vec<_>>();
    let imports = packages
        .iter()
        .zip(["left", "right"])
        .map(|(package, alias)| ImportBinding {
            alias: alias.into(),
            package: package.identity.clone(),
        })
        .collect();
    let error = ModuleBuildGraph::default().link(SourceLinkRequest { artifacts: Vec::new(), sources: Vec::new(),
            root: source_module("app.ko", "seiyaku App { view fn run() authorize(anyone) -> int { let left::Fault failure = left::Fault::Denied; match failure { right::Fault::Denied => 1 } } }"),
            imports, packages,
        }, LinkerOptions::default()).expect_err("equal variant names and codes do not erase nominal identity");
    assert_eq!(error.diagnostic_code(), "E_PATTERN_FAMILY");
}
#[test]
fn package_interface_fingerprint_tracks_declared_call_modes() {
    let validate = |source: &str| {
        ModuleBuildGraph::default()
            .validate_package(
                SourcePackageGraphRequest {
                    package: publish_package(vec![source_module("src/lib.ko", source)], &["quote"]),
                    dependencies: Vec::new(),
                },
                LinkerOptions::default(),
            )
            .expect("typed package")
            .interface_fingerprint
    };
    assert_ne!(
        validate("module Quotes { export fn quote(int value) -> int { value } }"),
        validate("module Quotes { export fn quote(int _ value) -> int { value } }")
    );
}
fn transitive_source_request(base_source: &str) -> SourceLinkRequest {
    let base_identity = "std/base@1.0.0".to_owned();
    let derived_identity = "std/derived@1.0.0".to_owned();
    SourceLinkRequest { artifacts: Vec::new(),
        sources: Vec::new(),
        root: SourceModuleUnit {
            source_name: "app.ko".to_owned(),
            source: "seiyaku App { view fn run() authorize(anyone) -> int { return derived::value(); } }".to_owned(),
        },
        imports: vec![ImportBinding {
            alias: "derived".to_owned(),
            package: derived_identity.clone(),
        }],
        packages: vec![
            SourcePackageUnit { artifacts: Vec::new(),
                sources: Vec::new(),
                identity: base_identity.clone(),
                modules: vec![SourceModuleUnit {
                    source_name: "base.ko".to_owned(),
                    source: base_source.to_owned(),
                }],
                exports: BTreeSet::from(["value".to_owned()]),
                imports: Vec::new(),
            },
            SourcePackageUnit { artifacts: Vec::new(),
                sources: Vec::new(),
                identity: derived_identity,
                modules: vec![SourceModuleUnit {
                    source_name: "derived.ko".to_owned(),
                    source:
                        "module Derived { export fn value() -> int { return base::value() + 1; } }"
                            .to_owned(),
                }],
                exports: BTreeSet::from(["value".to_owned()]),
                imports: vec![ImportBinding {
                    alias: "base".to_owned(),
                    package: base_identity,
                }],
            },
        ],
    }
}
#[test]
fn links_explicit_export_after_independent_type_analysis() {
    let linked = TypedLinker::default()
        .link(request(
            source(
                "app.ko",
                "seiyaku App { view fn run() authorize(anyone) -> int { return arith::add(right: 3, left: 2); } }",
            ),
            package(
                vec![source(
                    "math.ko",
                    "module Math { export fn add(int left, int right) -> int { return left + right; } }",
                )],
                &["add"],
            ),
        ))
        .expect("link typed HIR");
    assert_eq!(linked.unit.name, "App");
    assert_eq!(linked.items.len(), 2);
    let TypedItem::Function(root) = &linked.items[0];
    let TypedStatement::Return(Some(TypedExpr {
        expr:
            ExprKind::NamedCall {
                target: name,
                evaluation_order,
                ..
            },
        ..
    })) = &root.body.statements[0]
    else {
        panic!("expected linked named call")
    };
    assert_eq!(evaluation_order, &[1, 0]);
    assert!(
        name.user_name()
            .is_some_and(|name| name.starts_with(LINKED_SYMBOL_PREFIX))
    );
    let TypedItem::Function(module) = &linked.items[1];
    assert_eq!(name.user_name(), Some(module.name.as_str()));
}
#[test]
fn imported_parameters_accept_positional_and_named_calls() {
    let dependency = || {
        package(
            vec![source(
                "math.ko",
                "module Math { export fn choose(int left, int right) -> int { return left; } }",
            )],
            &["choose"],
        )
    };
    let positional = TypedLinker::default()
        .link(request(
            source(
                "app.ko",
                "seiyaku App { view fn run() authorize(anyone) -> int { return arith::choose(1, 2); } }",
            ),
            dependency(),
        ))
        .expect("imported ordinary parameters accept positional arguments");
    assert_eq!(positional.items.len(), 2);
    let linked = TypedLinker::default()
        .link(request(
            source(
                "app.ko",
                "seiyaku App { view fn run() authorize(anyone) -> int { return arith::choose(right: 2, left: 1); } }",
            ),
            dependency(),
        ))
        .expect("the reordered named imported call must link");
    let TypedItem::Function(root) = &linked.items[0];
    let TypedStatement::Return(Some(TypedExpr {
        expr:
            ExprKind::NamedCall {
                target: name,
                evaluation_order,
                ..
            },
        ..
    })) = &root.body.statements[0]
    else {
        panic!("expected linked named call")
    };
    assert_eq!(evaluation_order, &[1, 0]);
    assert!(
        name.user_name()
            .is_some_and(|name| name.starts_with(LINKED_SYMBOL_PREFIX))
    );
}
#[test]
fn rejects_unexported_and_unknown_calls() {
    let unexported_source =
        "seiyaku App { view fn run() authorize(anyone) -> int { return arith::hidden(); } }";
    let dependency = package(
        vec![source(
            "math.ko",
            "module Math { fn hidden() -> int { return 1; } }",
        )],
        &[],
    );
    let unexported = TypedLinker::default()
        .link(request(source("app.ko", unexported_source), dependency))
        .expect_err("unexported function must fail");
    assert_eq!(unexported.diagnostic_code(), "E_UNEXPORTED_SYMBOL");
    let unexported = unexported.into_diagnostics();
    let unexported_span = unexported.diagnostics[0]
        .primary_span
        .as_ref()
        .and_then(|span| span.byte_range)
        .expect("unexported call keeps its resolver name range");
    assert_eq!(
        source_slice(unexported_source, unexported_span),
        Some("arith::hidden")
    );
    let unknown_source =
        "seiyaku App { view fn run() authorize(anyone) -> int { return other::add(); } }";
    let unknown = TypedLinker::default()
        .link(request(
            source("app.ko", unknown_source),
            package(
                vec![source(
                    "math.ko",
                    "module Math { export fn add() -> int { return 1; } }",
                )],
                &["add"],
            ),
        ))
        .expect_err("unknown alias must fail");
    assert_eq!(unknown.diagnostic_code(), "E_UNKNOWN_IMPORT_ALIAS");
    let unknown = unknown.into_diagnostics();
    let unknown_span = unknown.diagnostics[0]
        .primary_span
        .as_ref()
        .and_then(|span| span.byte_range)
        .expect("unknown alias keeps its resolver name range");
    assert_eq!(
        source_slice(unknown_source, unknown_span),
        Some("other::add")
    );
}
#[test]
fn imported_call_failures_are_multi_error_spanned_and_renderer_equivalent() {
    let root_source = "seiyaku App { view fn run() authorize(anyone) -> int { return arith::hidden() + arith::also_hidden(); } }";
    let error = TypedLinker::default()
            .link(request(
                source("app.ko", root_source),
                package(
                    vec![source(
                        "math.ko",
                        "module Math { fn hidden() -> int { return 1; } fn also_hidden() -> int { return 2; } }",
                    )],
                    &[],
                ),
            ))
            .expect_err("every unexported imported call must be reported");
    let diagnostics = error.into_diagnostics();
    assert_eq!(diagnostics.diagnostics.len(), 2);
    let spellings = diagnostics
        .diagnostics
        .iter()
        .map(|diagnostic| {
            assert_eq!(diagnostic.code, "E_UNEXPORTED_SYMBOL");
            assert_eq!(diagnostic.phase, DiagnosticPhase::Resolve);
            let span = diagnostic
                .primary_span
                .as_ref()
                .expect("import diagnostic span");
            assert_eq!(span.source.as_deref(), Some("app.ko"));
            source_slice(
                root_source,
                span.byte_range.expect("import diagnostic byte range"),
            )
            .expect("resolver span slices source")
            .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        spellings,
        vec!["arith::hidden".to_owned(), "arith::also_hidden".to_owned()]
    );
    let human = diagnostics.render_human();
    assert_eq!(human.matches("error[E_UNEXPORTED_SYMBOL]").count(), 2);
    let json: norito::json::Value =
        norito::json::from_str(&diagnostics.render_json().expect("link JSON diagnostics"))
            .expect("parse link JSON diagnostics");
    let sarif: norito::json::Value =
        norito::json::from_str(&diagnostics.render_sarif().expect("link SARIF diagnostics"))
            .expect("parse link SARIF diagnostics");
    let canonical = json.as_array().expect("canonical diagnostic array");
    let results = sarif
        .pointer("/runs/0/results")
        .and_then(norito::json::Value::as_array)
        .expect("SARIF results");
    assert_eq!(canonical.len(), results.len());
    for (canonical, result) in canonical.iter().zip(results) {
        assert_eq!(result.pointer("/properties/kotodama"), Some(canonical),);
    }
}
#[test]
fn source_graph_unknown_calls_retain_every_exact_resolver_span() {
    let root_source = "seiyaku App { view fn run() authorize(anyone) -> int { return missing() + also_missing(); } }";
    let error = ModuleBuildGraph::default()
        .link(
            SourceLinkRequest {
                artifacts: Vec::new(),
                sources: Vec::new(),
                root: SourceModuleUnit {
                    source_name: "app.ko".to_owned(),
                    source: root_source.to_owned(),
                },
                imports: Vec::new(),
                packages: Vec::new(),
            },
            LinkerOptions::default(),
        )
        .expect_err("unknown calls must fail in resolved HIR");
    assert!(matches!(&error, SourceGraphError::Resolve { .. }));
    let diagnostics = error.into_diagnostics();
    let spellings = diagnostics
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code == "K2002")
        .map(|diagnostic| {
            let range = diagnostic
                .primary_span
                .as_ref()
                .and_then(|span| span.byte_range)
                .expect("unknown call name range");
            source_slice(root_source, range)
                .expect("unknown call range slices source")
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        spellings,
        vec!["missing".to_owned(), "also_missing".to_owned()]
    );
}
#[test]
fn source_graph_unknown_import_aliases_retain_every_exact_resolved_call_span() {
    let root_source = "seiyaku App { view fn run() authorize(anyone) -> int { return missing::one() + other::two(); } }";
    let error = ModuleBuildGraph::default()
        .link(
            SourceLinkRequest {
                artifacts: Vec::new(),
                sources: Vec::new(),
                root: SourceModuleUnit {
                    source_name: "app.ko".to_owned(),
                    source: root_source.to_owned(),
                },
                imports: Vec::new(),
                packages: Vec::new(),
            },
            LinkerOptions::default(),
        )
        .expect_err("unknown import aliases must fail in the typed linker");
    assert!(matches!(&error, SourceGraphError::Link(_)));
    let diagnostics = error.into_diagnostics();
    let spellings = diagnostics
        .diagnostics
        .iter()
        .map(|diagnostic| {
            assert_eq!(diagnostic.code, "E_UNKNOWN_IMPORT_ALIAS");
            let range = diagnostic
                .primary_span
                .as_ref()
                .and_then(|span| span.byte_range)
                .expect("unknown alias call-name range");
            source_slice(root_source, range)
                .expect("unknown alias range slices source")
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        spellings,
        vec!["missing::one".to_owned(), "other::two".to_owned()]
    );
}
#[test]
fn rejects_import_aliases_that_collide_with_builtin_namespaces() {
    let dependency = package(
        vec![source(
            "hash.ko",
            "module Hash { export fn sha256(bytes value) -> bytes { return value; } }",
        )],
        &["sha256"],
    );
    for alias in ["crypto", "quantity"] {
        let mut request = request(
            source(
                "app.ko",
                "seiyaku App { view fn run(bytes value) authorize(anyone) -> bytes { return crypto::sha256(value); } }",
            ),
            dependency.clone(),
        );
        request.imports[0].alias = alias.to_owned();
        let error = TypedLinker::default()
            .link(request)
            .expect_err("compiler namespace import must be rejected as ambiguous");
        assert!(
            matches!(
                error,
                LinkError::ReservedImport {
                    alias: ref rejected,
                    ..
                } if rejected == alias
            ),
            "{error:?}"
        );
    }
}
#[test]
fn rejects_ambiguous_duplicate_export() {
    let error = TypedLinker::default()
        .link(request(
            source(
                "app.ko",
                "seiyaku App { view fn run() authorize(anyone) -> int { return arith::value(); } }",
            ),
            package(
                vec![
                    source(
                        "a.ko",
                        "module A { export fn value() -> int { return 1; } }",
                    ),
                    source(
                        "b.ko",
                        "module B { export fn value() -> int { return 2; } }",
                    ),
                ],
                &["value"],
            ),
        ))
        .expect_err("ambiguous export must fail");
    assert_eq!(error.diagnostic_code(), "E_AMBIGUOUS_EXPORT");
    let diagnostics = error.into_diagnostics();
    let diagnostic = diagnostics
        .diagnostics
        .first()
        .expect("ambiguous export diagnostic");
    assert_eq!(
        diagnostic
            .primary_span
            .as_ref()
            .and_then(|span| span.source.as_deref()),
        Some("a.ko")
    );
    assert_eq!(diagnostic.labels.len(), 1);
    assert_eq!(diagnostic.labels[0].span.source.as_deref(), Some("b.ko"));
}
#[test]
fn same_private_function_name_in_two_modules_remains_module_local() {
    let linked = TypedLinker::default()
            .link(request(
                source(
                    "app.ko",
                    "seiyaku App { view fn run() authorize(anyone) -> int { return arith::left() + arith::right(); } }",
                ),
                package(
                    vec![
                        source(
                            "left.ko",
                            "module Left { fn helper() -> int { return 1; } export fn left() -> int { return helper(); } }",
                        ),
                        source(
                            "right.ko",
                            "module Right { fn helper() -> int { return 2; } export fn right() -> int { return helper(); } }",
                        ),
                    ],
                    &["left", "right"],
                ),
            ))
            .expect("private names are scoped per module");
    let names = linked
        .items
        .iter()
        .map(|item| match item {
            TypedItem::Function(function) => function.name.clone(),
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(names.len(), linked.items.len());
    assert_eq!(
        names
            .iter()
            .filter(|name| name.starts_with(LINKED_SYMBOL_PREFIX))
            .count(),
        4
    );
}
#[test]
fn rejects_compiler_reserved_declaration() {
    let package_identity = "std/math@1.0.0".to_owned();
    let error = ModuleBuildGraph::default()
            .link(
                SourceLinkRequest { artifacts: Vec::new(), sources: Vec::new(),
                    root: SourceModuleUnit {
                        source_name: "app.ko".to_owned(),
                        source:
                            "seiyaku App { view fn run() authorize(anyone) -> int { return math::ok(); } }"
                                .to_owned(),
                    },
                    imports: vec![ImportBinding {
                        alias: "math".to_owned(),
                        package: package_identity.clone(),
                    }],
                    packages: vec![SourcePackageUnit { artifacts: Vec::new(), sources: Vec::new(),
                        identity: package_identity,
                        modules: vec![SourceModuleUnit {
                            source_name: "reserved.ko".to_owned(),
                            source: "module Reserved { fn __kotodama_link_private() -> int { return 1; } export fn ok() -> int { return 1; } }".to_owned(),
                        }],
                        exports: BTreeSet::from(["ok".to_owned()]),
                        imports: Vec::new(),
                    }],
                },
                LinkerOptions::default(),
            )
            .expect_err("reserved linker prefix must fail");
    assert!(matches!(error, SourceGraphError::Resolve { .. }));
}
#[test]
fn source_graph_parses_equal_contents_once_and_reuses_cache() {
    let graph = ModuleBuildGraph::default();
    let modules = vec![
        SourceModuleUnit {
            source_name: "first.ko".to_owned(),
            source: "module Shared { fn value() -> int { return 1; } }".to_owned(),
        },
        SourceModuleUnit {
            source_name: "second.ko".to_owned(),
            source: "module Shared { fn value() -> int { return 1; } }".to_owned(),
        },
    ];
    let source_ids = stable_source_ids(
        &modules
            .iter()
            .map(|module| module.source_name.clone())
            .collect::<Vec<_>>(),
    );
    let first = graph
        .parse_sources_with_ids(&modules, &source_ids)
        .expect("parse shared contents");
    let mut first_plain = first[0].program.clone();
    let mut second_plain = first[1].program.clone();
    crate::ast::strip_program_provenance(&mut first_plain);
    crate::ast::strip_program_provenance(&mut second_plain);
    assert_eq!(
        first_plain, second_plain,
        "equal contents retain the same source-independent AST structure"
    );
    assert_ne!(
        first[0].facts.source_map.source(),
        first[1].facts.source_map.source(),
        "equal contents in distinct logical files retain distinct SourceIds"
    );
    assert_eq!(
        first[0]
            .facts
            .source_map
            .nodes()
            .map(|node| (node.id, node.kind, node.range))
            .collect::<Vec<_>>(),
        first[1]
            .facts
            .source_map
            .nodes()
            .map(|node| (node.id, node.kind, node.range))
            .collect::<Vec<_>>(),
        "content-identical parses retain the same structural NodeIds"
    );
    for parsed in &first {
        let source_id = parsed.facts.source_map.source();
        let Item::Function(function) = &parsed.program.items[0] else {
            panic!("cached module function")
        };
        let statement = &function.body.statements[0];
        assert_eq!(
            statement.source().map(|range| range.source),
            Some(source_id)
        );
        let Statement::Return(Some(value)) = statement.kind() else {
            panic!("cached module return")
        };
        assert_eq!(value.source().map(|range| range.source), Some(source_id));
        for node in [statement.source_node(), value.source_node()]
            .into_iter()
            .flatten()
        {
            assert!(
                parsed
                    .facts
                    .source_map
                    .source_range(node)
                    .is_some_and(|range| range.source == source_id
                        && Some(range) == parsed.facts.source_map.source_range(node))
            );
        }
    }
    assert_eq!(
        graph
            .parse_attempts
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    let reused = graph
        .parse_sources_with_ids(&modules, &source_ids)
        .expect("reuse parsed source cache");
    for (original, cached) in first.iter().zip(&reused) {
        assert_eq!(
            original.facts.source_map.source(),
            cached.facts.source_map.source()
        );
        assert_eq!(
            original
                .facts
                .source_map
                .nodes()
                .map(|node| (node.id, node.kind, node.range))
                .collect::<Vec<_>>(),
            cached
                .facts
                .source_map
                .nodes()
                .map(|node| (node.id, node.kind, node.range))
                .collect::<Vec<_>>()
        );
    }
    assert_eq!(
        graph
            .parse_attempts
            .load(std::sync::atomic::Ordering::Relaxed),
        1,
        "an unchanged source must not be reparsed"
    );
}
#[test]
fn reused_graph_parses_only_changes_and_rechecks_dependents() {
    let graph = ModuleBuildGraph::default();
    let first = graph
        .link(
            transitive_source_request("module Base { export fn value() -> int { return 1; } }"),
            LinkerOptions::default(),
        )
        .expect("link initial transitive graph");
    assert_eq!(graph.parse_attempt_count(), 3);
    assert_eq!(graph.link_attempt_count(), 1);
    let implementation_changed = graph
        .link(
            transitive_source_request("module Base { export fn value() -> int { return 2; } }"),
            LinkerOptions::default(),
        )
        .expect("implementation-only dependency change remains valid");
    assert_eq!(
        graph.parse_attempt_count(),
        4,
        "only the changed base module should be reparsed",
    );
    assert_eq!(
        graph.link_attempt_count(),
        2,
        "every changed graph must rerun whole-graph typed linking",
    );
    assert_ne!(first.fingerprint, implementation_changed.fingerprint);
    assert_ne!(
        first.program, implementation_changed.program,
        "the reused dependent must link against the changed implementation",
    );
    let error = graph
        .link(
            transitive_source_request(
                "module Base { export fn value(int input) -> int { return input; } }",
            ),
            LinkerOptions::default(),
        )
        .expect_err("a changed export signature must invalidate its dependent");
    assert_eq!(
        error
            .clone()
            .into_diagnostics()
            .diagnostics
            .first()
            .and_then(|diagnostic| diagnostic.primary_span.as_ref())
            .and_then(|span| span.source.as_deref()),
        Some("derived.ko"),
        "{error:?}",
    );
    assert_eq!(
        graph.parse_attempt_count(),
        5,
        "the cached root and dependent ASTs must not be reparsed",
    );
    assert_eq!(
        graph.link_attempt_count(),
        3,
        "cached parsing must never suppress dependent semantic validation",
    );
}
#[test]
fn source_graph_accumulates_independent_parse_and_resolution_failures() {
    let request = |root_source: &str, module_source: &str| SourceLinkRequest {
        artifacts: Vec::new(),
        sources: Vec::new(),
        root: SourceModuleUnit {
            source_name: "app.ko".to_owned(),
            source: root_source.to_owned(),
        },
        imports: Vec::new(),
        packages: vec![SourcePackageUnit {
            artifacts: Vec::new(),
            sources: Vec::new(),
            identity: "example/math@1.0.0".to_owned(),
            modules: vec![SourceModuleUnit {
                source_name: "src/lib.ko".to_owned(),
                source: module_source.to_owned(),
            }],
            exports: BTreeSet::new(),
            imports: Vec::new(),
        }],
    };
    let parse = ModuleBuildGraph::default()
        .link(
            request("seiyaku App { € }", "module Math { £ }"),
            LinkerOptions::default(),
        )
        .expect_err("both malformed sources must fail parsing")
        .into_diagnostics();
    let parse_owners = parse
        .diagnostics
        .iter()
        .filter_map(|diagnostic| diagnostic.primary_span.as_ref())
        .map(|span| (span.package_identity.as_deref(), span.source.as_deref()))
        .collect::<BTreeSet<_>>();
    assert!(parse_owners.contains(&(None, Some("app.ko"))));
    assert!(parse_owners.contains(&(Some("example/math@1.0.0"), Some("src/lib.ko"))));
    let resolved = ModuleBuildGraph::default()
        .link(
            request(
                "seiyaku App { view fn value() authorize(anyone) -> int { return missing_root; } }",
                "module Math { fn value() -> int { return missing_module; } }",
            ),
            LinkerOptions::default(),
        )
        .expect_err("both unknown values must fail resolution")
        .into_diagnostics();
    let resolved_owners = resolved
        .diagnostics
        .iter()
        .filter_map(|diagnostic| diagnostic.primary_span.as_ref())
        .map(|span| (span.package_identity.as_deref(), span.source.as_deref()))
        .collect::<BTreeSet<_>>();
    assert!(resolved_owners.contains(&(None, Some("app.ko"))));
    assert!(resolved_owners.contains(&(Some("example/math@1.0.0"), Some("src/lib.ko"))));
}
#[test]
fn linked_typed_hir_retains_path_and_order_stable_distinct_source_ids() {
    let request =
        transitive_source_request("module Base { export fn value() -> int { return 1; } }");
    let mut reordered = request.clone();
    reordered.packages.reverse();
    reordered.root.source_name = r".\app.ko".to_owned();
    for package in &mut reordered.packages {
        for module in &mut package.modules {
            module.source_name = format!(r".\nested\..\{}", module.source_name);
        }
    }
    let left = ModuleBuildGraph::default()
        .link(request, LinkerOptions::default())
        .expect("link canonical package order");
    let right = ModuleBuildGraph::default()
        .link(reordered, LinkerOptions::default())
        .expect("link reversed package order");
    assert_eq!(left.program.source_files, right.program.source_files);
    assert_eq!(left.program.source_files.len(), 3);
    assert_eq!(
        left.program
            .source_files
            .values()
            .map(|source| source.name().to_owned())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "app.ko".to_owned(),
            "base.ko".to_owned(),
            "derived.ko".to_owned(),
        ])
    );
    for item in &left.program.items {
        let TypedItem::Function(function) = item;
        let source = function
            .source
            .expect("linked function retains its declaration source");
        let name_source = function
            .name_source
            .expect("linked function retains its name source");
        assert!(left.program.source_files.contains_key(&source.source));
        assert!(!source.range.is_empty());
        assert!(!name_source.range.is_empty());
    }
}
#[test]
fn source_cache_defends_against_adversarial_digest_collision() {
    let graph = ModuleBuildGraph::default();
    let modules = vec![
        SourceModuleUnit {
            source_name: "left.ko".to_owned(),
            source: "module Left { fn value() -> int { return 1; } }".to_owned(),
        },
        SourceModuleUnit {
            source_name: "right.ko".to_owned(),
            source: "module Right { fn value() -> int { return 2; } }".to_owned(),
        },
    ];
    let source_ids = stable_source_ids(
        &modules
            .iter()
            .map(|module| module.source_name.clone())
            .collect::<Vec<_>>(),
    );
    let parsed = graph
        .parse_sources_with_digest(&modules, &source_ids, |_| "forced-collision".to_owned())
        .expect("exact source comparison must disambiguate a digest collision");
    assert_ne!(parsed[0].program.unit.name, parsed[1].program.unit.name);
    assert_eq!(
        graph
            .parse_attempts
            .load(std::sync::atomic::Ordering::Relaxed),
        2
    );
}
#[test]
fn parsed_source_cache_is_bounded_and_uses_lru_eviction() {
    let program = spanned("module Cached { fn value() -> int { return 1; } }");
    let mut cache = ParsedSourceCache::default();
    for index in 0..MAX_PARSED_CACHE_ENTRIES {
        cache.insert(
            format!("digest-{index}"),
            format!("source-{index}"),
            program.clone(),
        );
    }
    assert_eq!(cache.entries.len(), MAX_PARSED_CACHE_ENTRIES);
    assert!(cache.get("digest-0", "source-0").is_some());
    cache.insert("digest-new".to_owned(), "source-new".to_owned(), program);
    assert_eq!(cache.entries.len(), MAX_PARSED_CACHE_ENTRIES);
    assert!(cache.get("digest-0", "source-0").is_some());
    assert!(cache.get("digest-1", "source-1").is_none());
    assert!(cache.source_bytes <= MAX_PARSED_CACHE_SOURCE_BYTES);
}
#[test]
fn parsed_source_cache_enforces_aggregate_source_budget() {
    let program = spanned("module Cached { fn value() -> int { return 1; } }");
    let mut cache = ParsedSourceCache::default();
    for index in 0..5 {
        let suffix = u8::try_from(index).expect("test index fits in u8");
        cache.insert(
            format!("large-{index}"),
            char::from(b'a' + suffix).to_string().repeat(1024 * 1024),
            program.clone(),
        );
    }
    assert!(cache.source_bytes <= MAX_PARSED_CACHE_SOURCE_BYTES);
    assert_eq!(cache.entries.len(), 4);
    assert!(cache.get("large-0", &"a".repeat(1024 * 1024)).is_none());
    assert!(cache.get("large-4", &"e".repeat(1024 * 1024)).is_some());
}
#[test]
fn source_graph_rejects_excessive_module_count_before_parsing() {
    let modules = (0..MAX_MODULE_GRAPH_SOURCES)
        .map(|index| SourceModuleUnit {
            source_name: format!("module-{index}.ko"),
            source: "not parsed".to_owned(),
        })
        .collect();
    let request = SourceLinkRequest {
        artifacts: Vec::new(),
        sources: Vec::new(),
        root: SourceModuleUnit {
            source_name: "root.ko".to_owned(),
            source: "also not parsed".to_owned(),
        },
        imports: Vec::new(),
        packages: vec![SourcePackageUnit {
            artifacts: Vec::new(),
            sources: Vec::new(),
            identity: "oversized@1".to_owned(),
            modules,
            exports: BTreeSet::new(),
            imports: Vec::new(),
        }],
    };
    let error = validate_source_graph_budget(&request)
        .expect_err("root plus maximum modules exceeds the graph count");
    assert!(matches!(error, SourceGraphError::Budget { .. }));
}
#[test]
fn source_graph_rejects_excessive_aggregate_bytes_before_parsing() {
    let request = SourceLinkRequest {
        artifacts: Vec::new(),
        sources: Vec::new(),
        root: SourceModuleUnit {
            source_name: "root.ko".to_owned(),
            source: "x".repeat(MAX_MODULE_GRAPH_SOURCE_BYTES + 1),
        },
        imports: Vec::new(),
        packages: Vec::new(),
    };
    let error = validate_source_graph_budget(&request)
        .expect_err("oversized aggregate source must fail before parsing");
    assert!(matches!(
        error,
        SourceGraphError::Budget {
            source_bytes,
            max_source_bytes: MAX_MODULE_GRAPH_SOURCE_BYTES,
            ..
        } if source_bytes == MAX_MODULE_GRAPH_SOURCE_BYTES + 1
    ));
}
#[test]
fn graph_fingerprint_is_order_stable_and_binds_exports() {
    let root = SourceModuleUnit {
        source_name: "app.ko".to_owned(),
        source: "seiyaku App { view fn run() authorize(anyone) -> int { return arith::value(); } }"
            .to_owned(),
    };
    let package = SourcePackageUnit {
        artifacts: Vec::new(),
        sources: Vec::new(),
        identity: "std/math@1.0.0".to_owned(),
        modules: vec![SourceModuleUnit {
            source_name: "math.ko".to_owned(),
            source: "module Math { export fn value() -> int { return 1; } }".to_owned(),
        }],
        exports: ["value".to_owned()].into_iter().collect(),
        imports: Vec::new(),
    };
    let left = SourceLinkRequest {
        artifacts: Vec::new(),
        sources: Vec::new(),
        root: root.clone(),
        imports: vec![ImportBinding {
            alias: "arith".to_owned(),
            package: package.identity.clone(),
        }],
        packages: vec![package.clone()],
    };
    let mut changed = left.clone();
    changed.packages[0].exports.insert("other".to_owned());
    assert_ne!(
        ModuleBuildGraph::fingerprint(&left).expect("left graph fingerprint"),
        ModuleBuildGraph::fingerprint(&changed).expect("changed graph fingerprint"),
        "export metadata participates in the graph identity"
    );
    let mut two_imports = left;
    two_imports.imports.push(ImportBinding {
        alias: "another".to_owned(),
        package: package.identity,
    });
    let mut reordered = two_imports.clone();
    reordered.imports.reverse();
    assert_eq!(
        ModuleBuildGraph::fingerprint(&two_imports).expect("ordered graph fingerprint"),
        ModuleBuildGraph::fingerprint(&reordered).expect("reordered graph fingerprint"),
        "incidental lockfile ordering must not invalidate the graph"
    );
}
fn publish_package(modules: Vec<SourceModuleUnit>, exports: &[&str]) -> SourcePackageUnit {
    SourcePackageUnit {
        artifacts: Vec::new(),
        sources: Vec::new(),
        identity: "local/quotes@1.0.0".to_owned(),
        modules,
        exports: exports.iter().map(|name| (*name).to_owned()).collect(),
        imports: Vec::new(),
    }
}
fn source_module(name: &str, source: &str) -> SourceModuleUnit {
    SourceModuleUnit {
        source_name: name.to_owned(),
        source: source.to_owned(),
    }
}
fn boundary_list_expression() -> String {
    let depth = crate::source::MAX_NESTING_DEPTH - 2;
    format!("{}0{}", "[".repeat(depth), "]".repeat(depth))
}
fn invalid_logical_source_paths() -> Vec<(String, InvalidSourcePathReason)> {
    vec![
        (String::new(), InvalidSourcePathReason::Empty),
        (".".to_owned(), InvalidSourcePathReason::Empty),
        ("././".to_owned(), InvalidSourcePathReason::Empty),
        ("dir/..".to_owned(), InvalidSourcePathReason::Empty),
        ("...".to_owned(), InvalidSourcePathReason::DotOnlyComponent),
        (
            "/absolute/app.ko".to_owned(),
            InvalidSourcePathReason::Absolute,
        ),
        (r"\rooted.ko".to_owned(), InvalidSourcePathReason::Absolute),
        (
            r"\\server\share\app.ko".to_owned(),
            InvalidSourcePathReason::Absolute,
        ),
        (
            r"C:\source\app.ko".to_owned(),
            InvalidSourcePathReason::WindowsDrive,
        ),
        (
            "c:drive-relative.ko".to_owned(),
            InvalidSourcePathReason::WindowsDrive,
        ),
        (
            "../escape.ko".to_owned(),
            InvalidSourcePathReason::EscapesRoot,
        ),
        (
            "src/../../escape.ko".to_owned(),
            InvalidSourcePathReason::EscapesRoot,
        ),
        (
            "src/\0evil.ko".to_owned(),
            InvalidSourcePathReason::NonPortableCharacter {
                byte_offset: 4,
                character: '\0',
            },
        ),
        (
            "src/\nevil.ko".to_owned(),
            InvalidSourcePathReason::NonPortableCharacter {
                byte_offset: 4,
                character: '\n',
            },
        ),
        (
            "src/name:stream.ko".to_owned(),
            InvalidSourcePathReason::NonPortableCharacter {
                byte_offset: 8,
                character: ':',
            },
        ),
        (
            "a".repeat(MAX_LOGICAL_SOURCE_PATH_BYTES + 1),
            InvalidSourcePathReason::TooLong {
                bytes: MAX_LOGICAL_SOURCE_PATH_BYTES + 1,
                max_bytes: MAX_LOGICAL_SOURCE_PATH_BYTES,
            },
        ),
    ]
}
#[test]
fn package_graph_validates_unique_typed_export_and_locked_call() {
    let dependency_identity = "std/math@1.0.0".to_owned();
    let mut local = publish_package(
        vec![source_module(
            "src/lib.ko",
            "module Quotes { export fn quote(int value) -> int { return arith::add(left: value, right: 1); } }",
        )],
        &["quote"],
    );
    local.imports.push(ImportBinding {
        alias: "arith".to_owned(),
        package: dependency_identity.clone(),
    });
    let request = SourcePackageGraphRequest {
        package: local,
        dependencies: vec![SourcePackageUnit {
            artifacts: Vec::new(),
            sources: Vec::new(),
            identity: dependency_identity,
            modules: vec![source_module(
                "src/lib.ko",
                "module Math { export fn add(int left, int right) -> int { return left + right; } }",
            )],
            exports: BTreeSet::from(["add".to_owned()]),
            imports: Vec::new(),
        }],
    };
    let validated = ModuleBuildGraph::default()
        .validate_package(request, LinkerOptions::default())
        .expect("typed package graph");
    assert_eq!(validated.exports, BTreeSet::from(["quote".to_owned()]));
}
#[test]
fn package_interface_fingerprint_tracks_types_not_function_bodies() {
    let validate = |source: &str| {
        ModuleBuildGraph::default()
            .validate_package(
                SourcePackageGraphRequest {
                    package: publish_package(vec![source_module("src/lib.ko", source)], &["quote"]),
                    dependencies: Vec::new(),
                },
                LinkerOptions::default(),
            )
            .expect("typed package graph")
    };
    let first = validate("module Quotes { export fn quote() -> int { return 1; } }");
    let body_changed = validate("module Quotes { export fn quote() -> int { return 2; } }");
    let type_changed = validate("module Quotes { export fn quote() -> bool { return true; } }");
    assert_ne!(first.fingerprint, body_changed.fingerprint);
    assert_eq!(
        first.interface_fingerprint,
        body_changed.interface_fingerprint
    );
    assert_ne!(
        first.interface_fingerprint,
        type_changed.interface_fingerprint
    );
}
#[test]
fn standalone_test_graph_preserves_source_ownership_and_exact_imports() {
    let graph = ModuleBuildGraph::default();
    let request = SourceLinkRequest {
        artifacts: Vec::new(),
        sources: Vec::new(),
        root: source_module(
            "contracts/app.ko",
            "seiyaku App { fn reward() -> int { return calc::value(); } view fn current() authorize(anyone) -> int { return reward(); } }",
        ),
        imports: vec![ImportBinding {
            alias: "calc".to_owned(),
            package: "demo/math@1.0.0".to_owned(),
        }],
        packages: vec![SourcePackageUnit {
            artifacts: Vec::new(),
            sources: Vec::new(),
            identity: "demo/math@1.0.0".to_owned(),
            modules: vec![source_module(
                "tests/unit.ko",
                "module Math { export fn value() -> int { return 7; } }",
            )],
            exports: BTreeSet::from(["value".to_owned()]),
            imports: Vec::new(),
        }],
    };
    let test = source_module(
        "tests/unit.ko",
        r#"module Tests { koto_test { target: "../contracts/app.ko" } #[test] fn reward_is_exact() { test::assert(reward() == 7); test::assert(calc::value() == 7); } }"#,
    );
    let options = LinkerOptions {
        test_builtins_enabled: true,
        include_tests: true,
        ..LinkerOptions::default()
    };
    let linked = graph
        .link_sources_inner(request.clone(), std::slice::from_ref(&test), options)
        .expect("separate test graph");
    assert_eq!(
        linked.program.source_files.len(),
        3,
        "the package and test may share a path but never a source identity"
    );
    let tests = linked
        .program
        .items
        .iter()
        .filter_map(|item| {
            let TypedItem::Function(function) = item;
            (function.name == "reward_is_exact").then_some(function)
        })
        .collect::<Vec<_>>();
    assert_eq!(tests.len(), 1);
    let test_id = tests[0].source.expect("test declaration source").source;
    assert_eq!(linked.program.source_files[&test_id].text(), test.source);
    let mut changed = test.clone();
    changed.source = changed.source.replace("== 7", "== 8");
    let changed_graph = graph
        .link_sources_inner(request.clone(), &[changed], options)
        .expect("changed test graph");
    assert_ne!(linked.fingerprint, changed_graph.fingerprint);
    let output = graph
        .build_test_project_with_sources(
            request.clone(),
            std::slice::from_ref(&test),
            crate::compiler::CompilerOptions {
                mode: crate::compiler::CompilerMode::Test,
                ..crate::compiler::CompilerOptions::default()
            },
            "contracts/app.ko",
        )
        .expect("compile standalone source graph");
    assert!(
        output
            .runtime
            .expect("runtime projection")
            .report
            .budget_report
            .iter()
            .all(|entry| entry.function_name != "reward_is_exact")
    );
    let mut wrong = test;
    wrong.source = wrong.source.replace("calc::value()", "other::value()");
    let error = graph
        .link_sources_inner(request, &[wrong], options)
        .expect_err("unknown alias must stay rejected");
    assert!(error.to_string().contains("other"), "{error}");
}
#[test]
fn standalone_test_graph_rejects_target_duplicates_and_source_budget_overflow() {
    let request = SourceLinkRequest {
        artifacts: Vec::new(),
        sources: Vec::new(),
        root: source_module("app.ko", "seiyaku App { fn value() -> int { return 1; } }"),
        imports: Vec::new(),
        packages: Vec::new(),
    };
    let test = source_module(
        "test.ko",
        r#"module Tests { koto_test { target: "app.ko" } #[test] fn ok() { test::assert(value() == 1); } }"#,
    );
    let options = LinkerOptions {
        test_builtins_enabled: true,
        include_tests: true,
        ..LinkerOptions::default()
    };
    let graph = ModuleBuildGraph::default();
    assert!(matches!(
        graph.link_sources_inner(request.clone(), &[test.clone(), test.clone()], options),
        Err(SourceGraphError::DuplicateSource { .. })
    ));
    let mut huge = test;
    huge.source = " ".repeat(MAX_MODULE_GRAPH_SOURCE_BYTES);
    assert!(matches!(
        graph.link_sources_inner(request, &[huge], options),
        Err(SourceGraphError::Budget { .. })
    ));
    assert_eq!(
        graph.parse_attempt_count(),
        0,
        "identity and aggregate budget failures precede parsing"
    );
}
#[test]
fn linked_test_project_uses_one_exact_graph_for_suite_and_runtime() {
    let dependency_identity = "std/math@1.0.0".to_owned();
    let output = ModuleBuildGraph::default()
        .build_test_project(
            SourceLinkRequest {
                artifacts: Vec::new(),
                sources: Vec::new(),
                root: source_module(
                    "tests/unit.ko",
                    r#"
                        seiyaku App {
                            view fn current() authorize(anyone) -> int { return calc::value(); }
                            #[test]
                            fn dependency_is_linked() {
                                test::assert(calc::value() == 7);
                            }
                        }
                        "#,
                ),
                imports: vec![ImportBinding {
                    alias: "calc".to_owned(),
                    package: dependency_identity.clone(),
                }],
                packages: vec![SourcePackageUnit {
                    artifacts: Vec::new(),
                    sources: Vec::new(),
                    identity: dependency_identity,
                    modules: vec![source_module(
                        "src/lib.ko",
                        "module Math { export fn value() -> int { return 7; } }",
                    )],
                    exports: BTreeSet::from(["value".to_owned()]),
                    imports: Vec::new(),
                }],
            },
            crate::compiler::CompilerOptions {
                chain_discriminant: 753,
                mode: crate::compiler::CompilerMode::Test,
                ..crate::compiler::CompilerOptions::default()
            },
            "tests/unit.ko",
        )
        .expect("compile exact linked test graph");
    assert!(output.runtime.is_some());
    assert!(
        output
            .suite
            .report
            .budget_report
            .iter()
            .any(|entry| entry.function_name == "dependency_is_linked")
    );
    assert!(
        output
            .runtime
            .expect("public view has a runtime projection")
            .report
            .budget_report
            .iter()
            .all(|entry| entry.function_name != "dependency_is_linked")
    );
}
#[test]
fn package_and_test_graphs_handoff_from_a_small_caller() {
    let expression = boundary_list_expression();
    let module_source =
        format!("module Deep {{ export fn value() {{ let nested = {expression}; }} }}");
    let test_source = format!(
        "seiyaku Deep {{ hajimari() {{ let nested = {expression}; }} #[test] fn boundary() {{ let nested = {expression}; }} }}"
    );
    std::thread::Builder::new()
        .name("kotodama-small-package-graph-caller".to_owned())
        .stack_size(128 * 1024)
        .spawn(move || {
            let graph = ModuleBuildGraph::default();
            let validated = graph
                .validate_package(
                    SourcePackageGraphRequest {
                        package: publish_package(
                            vec![source_module("src/deep.ko", &module_source)],
                            &["value"],
                        ),
                        dependencies: Vec::new(),
                    },
                    LinkerOptions::default(),
                )
                .expect("boundary-depth package graph must validate on the compiler worker");
            assert_eq!(validated.exports, BTreeSet::from(["value".to_owned()]));

            let output = graph
                .build_test_project(
                    SourceLinkRequest {
                        artifacts: Vec::new(),
                        sources: Vec::new(),
                        root: source_module("tests/deep.ko", &test_source),
                        imports: Vec::new(),
                        packages: Vec::new(),
                    },
                    crate::compiler::CompilerOptions {
                        mode: crate::compiler::CompilerMode::Test,
                        ..crate::compiler::CompilerOptions::default()
                    },
                    "tests/deep.ko",
                )
                .expect("boundary-depth test graph must build on the compiler worker");
            assert!(!output.suite.artifact.is_empty());
            assert!(output.runtime.is_some());
        })
        .expect("spawn small package graph caller")
        .join()
        .expect("package and test graph pipelines must not consume the caller stack");
}
#[test]
fn package_graph_rejects_missing_and_ambiguous_exports() {
    let graph = ModuleBuildGraph::default();
    let missing = graph
        .validate_package(
            SourcePackageGraphRequest {
                package: publish_package(
                    vec![source_module(
                        "quotes.ko",
                        "module Quotes { fn quote() -> int { return 1; } }",
                    )],
                    &["missing"],
                ),
                dependencies: Vec::new(),
            },
            LinkerOptions::default(),
        )
        .expect_err("missing export must fail");
    assert_eq!(missing.diagnostic_code(), "E_MISSING_EXPORT", "{missing:?}");
    let first_source = "module A { export fn quote() -> int { return 1; } }";
    let second_source = "module B { export fn quote() -> int { return 2; } }";
    let ambiguous = graph
        .validate_package(
            SourcePackageGraphRequest {
                package: publish_package(
                    vec![
                        source_module("a.ko", first_source),
                        source_module("b.ko", second_source),
                    ],
                    &["quote"],
                ),
                dependencies: Vec::new(),
            },
            LinkerOptions::default(),
        )
        .expect_err("ambiguous export must fail");
    assert_eq!(
        ambiguous.diagnostic_code(),
        "E_AMBIGUOUS_EXPORT",
        "{ambiguous:?}"
    );
    let diagnostics = ambiguous.into_diagnostics();
    let diagnostic = &diagnostics.diagnostics[0];
    let primary = diagnostic
        .primary_span
        .as_ref()
        .expect("ambiguous export has a primary declaration");
    assert_eq!(primary.source.as_deref(), Some("a.ko"));
    assert_eq!(
        source_slice(
            first_source,
            primary.byte_range.expect("primary export byte range")
        ),
        Some("quote")
    );
    assert_eq!(diagnostic.labels.len(), 1);
    assert_eq!(diagnostic.labels[0].span.source.as_deref(), Some("b.ko"));
    assert_eq!(
        source_slice(
            second_source,
            diagnostic.labels[0]
                .span
                .byte_range
                .expect("related export byte range")
        ),
        Some("quote")
    );
}
#[test]
fn package_graph_rejects_invalid_types_and_bodies() {
    for (source, expected_code, expected_phase) in [
        (
            "module Quotes { export fn quote(MissingType value) -> int { return 1; } }",
            "K2002",
            DiagnosticPhase::Resolve,
        ),
        (
            "module Quotes { export fn quote() -> int { return true; } }",
            "E_RETURN_TYPE_MISMATCH",
            DiagnosticPhase::Semantic,
        ),
    ] {
        let error = ModuleBuildGraph::default()
            .validate_package(
                SourcePackageGraphRequest {
                    package: publish_package(vec![source_module("invalid.ko", source)], &["quote"]),
                    dependencies: Vec::new(),
                },
                LinkerOptions::default(),
            )
            .expect_err("invalid typed module must fail");
        assert_eq!(error.diagnostic_code(), expected_code, "{error:?}");
        let diagnostics = error.into_diagnostics();
        let diagnostic = diagnostics
            .diagnostics
            .first()
            .expect("invalid typed module has a diagnostic");
        assert_eq!(diagnostic.code, expected_code);
        assert_eq!(diagnostic.phase, expected_phase);
        let primary = diagnostic
            .primary_span
            .as_ref()
            .expect("invalid typed module retains its source owner");
        assert_eq!(
            primary.package_identity.as_deref(),
            Some("local/quotes@1.0.0")
        );
        assert_eq!(primary.source.as_deref(), Some("invalid.ko"));
    }
}
#[test]
fn package_graph_rejects_duplicate_symbols_and_module_names() {
    let duplicate_symbol = ModuleBuildGraph::default()
            .validate_package(
                SourcePackageGraphRequest {
                    package: publish_package(
                        vec![source_module(
                            "duplicate.ko",
                            "module Quotes { export fn quote() -> int { return 1; } export fn quote() -> int { return 2; } }",
                        )],
                        &["quote"],
                    ),
                    dependencies: Vec::new(),
                },
                LinkerOptions::default(),
            )
            .expect_err("duplicate symbol must fail closed");
    assert!(matches!(
        duplicate_symbol,
        SourceGraphError::Resolve { .. }
            | SourceGraphError::Link(LinkError::DuplicateSymbol { .. })
    ));
    let duplicate_module = ModuleBuildGraph::default()
        .validate_package(
            SourcePackageGraphRequest {
                package: publish_package(
                    vec![
                        source_module(
                            "a.ko",
                            "module Quotes { export fn quote() -> int { return 1; } }",
                        ),
                        source_module("b.ko", "module Quotes { fn other() -> int { return 2; } }"),
                    ],
                    &["quote"],
                ),
                dependencies: Vec::new(),
            },
            LinkerOptions::default(),
        )
        .expect_err("duplicate module name must fail");
    assert!(
        matches!(
            duplicate_module,
            SourceGraphError::Link(LinkError::DuplicateModule { .. })
        ),
        "{duplicate_module:?}"
    );
}
#[test]
fn package_graph_rejects_seiyaku_and_test_only_exports() {
    let seiyaku = ModuleBuildGraph::default()
        .validate_package(
            SourcePackageGraphRequest {
                package: publish_package(
                    vec![source_module(
                        "app.ko",
                        "seiyaku Quotes { view fn quote() authorize(anyone) -> int { return 1; } }",
                    )],
                    &["quote"],
                ),
                dependencies: Vec::new(),
            },
            LinkerOptions::default(),
        )
        .expect_err("seiyaku cannot satisfy package export");
    assert!(
        matches!(
            seiyaku,
            SourceGraphError::Link(LinkError::DependencyMustBeModule { .. })
        ),
        "{seiyaku:?}"
    );
    let test_only = ModuleBuildGraph::default()
        .validate_package(
            SourcePackageGraphRequest {
                package: publish_package(
                    vec![source_module(
                        "test.ko",
                        "module Quotes { #[test] export fn quote() -> int { return 1; } }",
                    )],
                    &["quote"],
                ),
                dependencies: Vec::new(),
            },
            LinkerOptions::default(),
        )
        .expect_err("test-only function cannot satisfy production export");
    assert_eq!(test_only.diagnostic_code(), "E_TEST_ONLY_PRODUCTION");
}
#[test]
fn package_graph_rejects_dependency_hidden_call() {
    let dependency_identity = "std/math@1.0.0".to_owned();
    let mut local = publish_package(
        vec![source_module(
            "quotes.ko",
            "module Quotes { export fn quote() -> int { return arith::hidden(); } }",
        )],
        &["quote"],
    );
    local.imports.push(ImportBinding {
        alias: "arith".to_owned(),
        package: dependency_identity.clone(),
    });
    let graph = ModuleBuildGraph::default();
    let error = graph
            .validate_package(
                SourcePackageGraphRequest {
                    package: local,
                    dependencies: vec![SourcePackageUnit { artifacts: Vec::new(), sources: Vec::new(),
                        identity: dependency_identity,
                        modules: vec![source_module(
                            "math.ko",
                            "module Math { fn hidden() -> int { return 1; } export fn visible() -> int { return 2; } }",
                        )],
                        exports: BTreeSet::from(["visible".to_owned()]),
                        imports: Vec::new(),
                    }],
                },
                LinkerOptions::default(),
            )
            .expect_err("hidden dependency call must fail");
    assert_eq!(error.diagnostic_code(), "E_UNEXPORTED_SYMBOL", "{error:?}");
}
#[test]
fn package_graph_rejects_import_cycles_without_call_cycles() {
    let local_identity = "local/quotes@1.0.0".to_owned();
    let dependency_identity = "std/math@1.0.0".to_owned();
    let mut local = publish_package(
        vec![source_module(
            "quotes.ko",
            "module Quotes { export fn quote() -> int { return 1; } }",
        )],
        &["quote"],
    );
    local.imports.push(ImportBinding {
        alias: "arith".to_owned(),
        package: dependency_identity.clone(),
    });
    let graph = ModuleBuildGraph::default();
    let error = graph
        .validate_package(
            SourcePackageGraphRequest {
                package: local,
                dependencies: vec![SourcePackageUnit {
                    artifacts: Vec::new(),
                    sources: Vec::new(),
                    identity: dependency_identity,
                    modules: vec![source_module(
                        "math.ko",
                        "module Math { export fn value() -> int { return 2; } }",
                    )],
                    exports: BTreeSet::from(["value".to_owned()]),
                    imports: vec![ImportBinding {
                        alias: "quotes".to_owned(),
                        package: local_identity,
                    }],
                }],
            },
            LinkerOptions::default(),
        )
        .expect_err("locked package cycle must fail without relying on function calls");
    assert!(
        matches!(
            error,
            SourceGraphError::Link(LinkError::PackageImportCycle { ref cycle })
                if cycle.first() == cycle.last() && cycle.len() == 3
        ),
        "{error:?}"
    );
    assert_eq!(graph.parse_attempt_count(), 0);
}
#[test]
fn package_graph_rejects_duplicate_normalized_logical_sources_before_parsing() {
    let request = SourcePackageGraphRequest {
        package: publish_package(
            vec![
                source_module("src/../lib.ko", "not parsed"),
                source_module("lib.ko", "also not parsed"),
            ],
            &[],
        ),
        dependencies: Vec::new(),
    };
    let graph = ModuleBuildGraph::default();
    let error = graph
        .validate_package(request, LinkerOptions::default())
        .expect_err("duplicate logical source key must fail before parsing");
    assert!(matches!(
        error,
        SourceGraphError::DuplicateSource { ref source, .. } if source == "lib.ko"
    ));
    assert_eq!(graph.parse_attempt_count(), 0);
    assert_eq!(graph.link_attempt_count(), 0);
}
#[test]
fn package_fingerprint_normalizes_portable_logical_source_paths() {
    let left = SourcePackageGraphRequest {
        package: publish_package(
            vec![source_module(
                "src/lib.ko",
                "module Quotes { export fn quote() -> int { return 1; } }",
            )],
            &["quote"],
        ),
        dependencies: Vec::new(),
    };
    let mut right = left.clone();
    right.package.modules[0].source_name = ".\\src\\lib.ko".to_owned();
    assert_eq!(
        ModuleBuildGraph::package_fingerprint(&left).expect("left fingerprint"),
        ModuleBuildGraph::package_fingerprint(&right).expect("right fingerprint")
    );
}
#[test]
fn source_graph_fingerprint_normalizes_root_and_package_paths() {
    let left = SourceLinkRequest {
        artifacts: Vec::new(),
        sources: Vec::new(),
        root: source_module("src/app.ko", "not parsed"),
        imports: Vec::new(),
        packages: vec![SourcePackageUnit {
            artifacts: Vec::new(),
            sources: Vec::new(),
            identity: "std/arith@1.0.0".to_owned(),
            modules: vec![source_module("src/lib.ko", "also not parsed")],
            exports: BTreeSet::new(),
            imports: Vec::new(),
        }],
    };
    let mut right = left.clone();
    right.root.source_name = r".\src\\app.ko".to_owned();
    right.packages[0].modules[0].source_name = r"src\nested\..\lib.ko".to_owned();
    assert_eq!(
        ModuleBuildGraph::fingerprint(&left).expect("canonical fingerprint"),
        ModuleBuildGraph::fingerprint(&right).expect("portable-alias fingerprint")
    );
}
#[test]
fn invalid_root_paths_fail_closed_before_any_parse_or_link_attempt() {
    for (source_name, expected_reason) in invalid_logical_source_paths() {
        let graph = ModuleBuildGraph::default();
        let error = graph
            .link(
                SourceLinkRequest {
                    artifacts: Vec::new(),
                    sources: Vec::new(),
                    root: source_module(&source_name, "not parsed"),
                    imports: Vec::new(),
                    packages: Vec::new(),
                },
                LinkerOptions::default(),
            )
            .expect_err("invalid root logical paths must fail closed");
        assert_eq!(error.diagnostic_code(), "E_INVALID_SOURCE_PATH");
        assert!(
            matches!(
                &error,
                SourceGraphError::InvalidSourcePath {
                    scope,
                    source,
                    reason,
                } if scope == "root" && source == &source_name && reason == &expected_reason
            ),
            "unexpected rejection for {source_name:?}: {error:?}"
        );
        assert_eq!(graph.parse_attempt_count(), 0);
        assert_eq!(graph.link_attempt_count(), 0);
        let rendered = error.to_string();
        assert!(!rendered.contains('\0'));
        if source_name.chars().any(char::is_control) {
            assert!(
                !rendered.contains(&format!("`{source_name}`")),
                "raw control characters must not be copied into diagnostics"
            );
            assert!(
                rendered.contains(&format!("`{}`", source_name.escape_debug())),
                "control characters must use an escaped diagnostic spelling"
            );
        }
    }
}
#[test]
fn invalid_package_paths_fail_closed_before_any_parse_or_link_attempt() {
    for (source_name, expected_reason) in invalid_logical_source_paths() {
        let graph = ModuleBuildGraph::default();
        let error = graph
            .validate_package(
                SourcePackageGraphRequest {
                    package: publish_package(vec![source_module(&source_name, "not parsed")], &[]),
                    dependencies: Vec::new(),
                },
                LinkerOptions::default(),
            )
            .expect_err("invalid package logical paths must fail closed");
        assert!(matches!(
            &error,
            SourceGraphError::InvalidSourcePath {
                scope,
                source,
                reason,
            } if scope == "local/quotes@1.0.0"
                && source == &source_name
                && reason == &expected_reason
        ));
        assert_eq!(graph.parse_attempt_count(), 0);
        assert_eq!(graph.link_attempt_count(), 0);
    }
}
#[test]
fn root_path_is_canonical_in_parse_diagnostics() {
    let graph = ModuleBuildGraph::default();
    let error = graph
        .link(
            SourceLinkRequest {
                artifacts: Vec::new(),
                sources: Vec::new(),
                root: source_module(r".\src\nested\..\app.ko", "@"),
                imports: Vec::new(),
                packages: Vec::new(),
            },
            LinkerOptions::default(),
        )
        .expect_err("invalid source text must reach the parser");
    let SourceGraphError::Parse {
        source,
        diagnostics,
    } = error
    else {
        panic!("invalid source text must produce parse diagnostics");
    };
    assert_eq!(source, "<project>");
    assert!(
        diagnostics.diagnostics.iter().all(|diagnostic| {
            diagnostic
                .primary_span
                .as_ref()
                .and_then(|span| span.source.as_deref())
                == Some("src/app.ko")
        }),
        "every aggregated diagnostic must retain the canonical root path"
    );
    assert_eq!(graph.parse_attempt_count(), 1);
    assert_eq!(graph.link_attempt_count(), 1);
}
#[test]
fn canonical_module_order_makes_parallel_parse_failure_deterministic() {
    let request = SourcePackageGraphRequest {
        package: publish_package(
            vec![source_module("z.ko", "@"), source_module("a.ko", "$")],
            &[],
        ),
        dependencies: Vec::new(),
    };
    let mut reordered = request.clone();
    reordered.package.modules.reverse();
    let first = ModuleBuildGraph::default()
        .validate_package(request, LinkerOptions::default())
        .expect_err("first malformed package must fail");
    let second = ModuleBuildGraph::default()
        .validate_package(reordered, LinkerOptions::default())
        .expect_err("reordered malformed package must fail identically");
    assert_eq!(first, second);
    let SourceGraphError::Parse {
        source,
        diagnostics,
    } = first
    else {
        panic!("malformed package must produce parse diagnostics");
    };
    assert_eq!(source, "<project>");
    let owners = diagnostics
        .diagnostics
        .iter()
        .map(|diagnostic| {
            diagnostic
                .primary_span
                .as_ref()
                .and_then(|span| span.source.as_deref())
                .expect("aggregated parse diagnostic retains its source owner")
        })
        .collect::<Vec<_>>();
    assert!(
        owners.windows(2).all(|pair| pair[0] <= pair[1]),
        "aggregated diagnostics follow canonical module order: {owners:?}"
    );
    assert_eq!(owners.first().copied(), Some("a.ko"));
    assert!(owners.contains(&"z.ko"));
}
