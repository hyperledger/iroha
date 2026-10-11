//! Confined file loading for source-declared includes and local module imports.

use super::*;
use crate::linker::SourceContractArtifact;
use crate::{
    ast::SourceDirectiveKind,
    source::{FrontendBudget, SourceId},
};
use std::collections::VecDeque;

/// Confined source companions and complete compiled interfaces belonging to one source owner.
#[derive(Clone, Debug, Default)]
pub struct SourceInventory {
    /// Reachable source fragments and reusable modules, excluding the supplied entry sources.
    pub sources: Vec<SourceModuleUnit>,
    /// Complete compiled artifacts referenced by those sources and the supplied entries.
    pub artifacts: Vec<SourceContractArtifact>,
}

pub(super) fn canonical_overlay_path(
    path: &Path,
    root: &Path,
    overlays: &BTreeMap<PathBuf, String>,
) -> Result<PathBuf, BuildError> {
    let canonical = match path.canonicalize() {
        Ok(canonical) => canonical,
        Err(_) if overlays.contains_key(path) => {
            let mut ancestor = path;
            while !ancestor.exists() {
                ancestor = ancestor.parent().ok_or_else(|| BuildError::InvalidPath {
                    path: path.into(),
                    message: "source has no existing parent".into(),
                })?;
            }
            let canonical = ancestor.canonicalize().map_err(|error| BuildError::Io {
                operation: "canonicalize Kotodama source ancestor",
                path: ancestor.into(),
                message: error.to_string(),
            })?;
            if !canonical.starts_with(root) {
                return Err(BuildError::InvalidPath {
                    path: path.into(),
                    message: "source resolves outside its source root".into(),
                });
            }
            path.to_path_buf()
        }
        Err(error) => {
            return Err(BuildError::Io {
                operation: "canonicalize Kotodama source",
                path: path.into(),
                message: error.to_string(),
            });
        }
    };
    if !canonical.starts_with(root) {
        return Err(BuildError::InvalidPath {
            path: path.into(),
            message: "source resolves outside its source root".into(),
        });
    }
    Ok(canonical)
}

/// Load the reachable companion files of explicit entry sources beneath one source root.
///
/// Paths are relative to their referring source. Only declared dependencies are opened;
/// unrelated files never participate in compilation. Open editor buffers take precedence
/// over the matching disk file, including newly created files not yet saved to disk.
pub fn load_source_inventory(
    entries: &[SourceModuleUnit],
    source_root: &Path,
    overlays: &BTreeMap<PathBuf, String>,
) -> Result<SourceInventory, BuildError> {
    load_source_inventory_scoped(entries, source_root, overlays, None)
}
/// Load a locked package's companion files while retaining package ownership in diagnostics.
pub fn load_source_package_inventory(
    entries: &[SourceModuleUnit],
    source_root: &Path,
    overlays: &BTreeMap<PathBuf, String>,
    package_identity: &str,
) -> Result<SourceInventory, BuildError> {
    load_source_inventory_scoped(entries, source_root, overlays, Some(package_identity))
}
fn load_source_inventory_scoped(
    entries: &[SourceModuleUnit],
    source_root: &Path,
    overlays: &BTreeMap<PathBuf, String>,
    package_identity: Option<&str>,
) -> Result<SourceInventory, BuildError> {
    let canonical_root = source_root.canonicalize().map_err(|error| BuildError::Io {
        operation: "canonicalize Kotodama source root",
        path: source_root.to_path_buf(),
        message: error.to_string(),
    })?;
    let entries = entries
        .iter()
        .map(|entry| {
            Ok(SourceModuleUnit {
                source_name: crate::linker::resolve_source_path("entry.ko", &entry.source_name)
                    .map_err(BuildError::SourceGraph)?,
                source: entry.source.clone(),
            })
        })
        .collect::<Result<Vec<_>, BuildError>>()?;
    let mut physical_names = BTreeMap::new();
    for entry in &entries {
        let entry_path = canonical_root.join(&entry.source_name);
        let entry_inventory = BTreeMap::from([(entry_path.clone(), String::new())]);
        let physical = canonical_overlay_path(&entry_path, &canonical_root, &entry_inventory)?;
        if let Some(first) = physical_names.insert(physical, entry.source_name.clone())
            && first != entry.source_name
        {
            return Err(BuildError::SourceGraph(SourceGraphError::DuplicateSource {
                scope: "physical source inventory".into(),
                source: entry.source_name.clone(),
            }));
        }
    }
    let mut known = entries
        .iter()
        .map(|unit| unit.source_name.clone())
        .collect::<BTreeSet<_>>();
    let mut pending = entries
        .iter()
        .cloned()
        .map(|unit| (unit, false))
        .collect::<VecDeque<_>>();
    let mut total_bytes = entries.iter().fold(0usize, |total, unit| {
        total.saturating_add(unit.source.len())
    });
    if entries.len() > MAX_MODULE_GRAPH_SOURCES || total_bytes > MAX_MODULE_GRAPH_SOURCE_BYTES {
        return Err(BuildError::SourceGraph(SourceGraphError::Budget {
            sources: entries.len(),
            source_bytes: total_bytes,
            max_sources: MAX_MODULE_GRAPH_SOURCES,
            max_source_bytes: MAX_MODULE_GRAPH_SOURCE_BYTES,
        }));
    }
    let mut companions = Vec::new();
    let mut artifacts = Vec::new();
    while let Some((unit, fragment)) = pending.pop_front() {
        let file = match package_identity {
            Some(identity) => SourceFile::new_in_package(
                SourceId(0),
                identity,
                unit.source_name.as_str(),
                unit.source.as_str(),
            ),
            None => SourceFile::new(SourceId(0), unit.source_name.as_str(), unit.source.as_str()),
        };
        let program = if fragment {
            crate::parser::parse_fragment_source(&file, FrontendBudget::v1())
        } else {
            crate::parser::parse_source(&file, FrontendBudget::v1())
        }
        .map_err(BuildError::Compile)?;
        // Both contract imports and upgrade fixtures capture immutable binary dependencies.
        // Fixture dependencies do not create a language import or a runtime filesystem lookup.
        let mut dependencies = Vec::new();
        for directive in program.directives {
            let span = SourceSpan::from_range(&file, directive.source.range);
            match directive.kind {
                SourceDirectiveKind::Include { path } => {
                    dependencies.push((Some(true), path, span))
                }
                SourceDirectiveKind::Import { path, .. } => {
                    dependencies.push((Some(false), path, span))
                }
                SourceDirectiveKind::ContractImport { path, .. } => {
                    dependencies.push((None, path, span))
                }
                SourceDirectiveKind::ContractTypeImport { .. } => {}
            }
        }
        for fixture in program.fixtures {
            for action in fixture.actions {
                if action.name != "upgrade_from" {
                    continue;
                }
                fn literal(expr: &crate::ast::Expr) -> Option<&str> {
                    match expr {
                        crate::ast::Expr::Source { expression, .. }
                        | crate::ast::Expr::Resolved { expression, .. } => literal(expression),
                        crate::ast::Expr::String(value) => Some(value),
                        _ => None,
                    }
                }
                let span = SourceSpan::from_range(
                    &file,
                    crate::source::TextRange::new(0, unit.source.len() as u32),
                );
                let path = match action.args.as_slice() {
                    [argument] => literal(argument),
                    _ => None,
                }
                .ok_or_else(|| {
                    BuildError::Compile(DiagnosticBundle::single(Diagnostic::error(
                        "E_TEST_FIXTURE_ARTIFACT",
                        DiagnosticPhase::Resolve,
                        "upgrade_from requires one literal relative .to path",
                        Some(span.clone()),
                    )))
                })?;
                dependencies.push((None, path.to_owned(), span));
            }
        }
        for (fragment, relative, directive_span) in dependencies {
            let fragment = match fragment {
                Some(fragment) => fragment,
                None => {
                    let name =
                        crate::linker::resolve_contract_artifact_path(&unit.source_name, &relative)
                            .map_err(BuildError::SourceGraph)?;
                    if !known.insert(name.clone()) {
                        continue;
                    }
                    let physical = canonical_root.join(&name);
                    // Binary interface artifacts are immutable disk inputs, never text overlays.
                    let canonical = canonical_overlay_path(&physical, &canonical_root, &BTreeMap::new()).map_err(|error| BuildError::Compile(DiagnosticBundle::single(Diagnostic::error(
            "E_CONTRACT_IMPORT_NOT_FOUND", DiagnosticPhase::Resolve, format!("cannot resolve compiled contract `{name}` within its source owner: {error}"), Some(directive_span.clone())))))?;
                    if let Some(first) = physical_names.insert(canonical.clone(), name.clone())
                        && first != name
                    {
                        return Err(BuildError::SourceGraph(SourceGraphError::DuplicateSource {
                            scope: "physical artifact inventory".into(),
                            source: name,
                        }));
                    }
                    let remaining = MAX_MODULE_GRAPH_SOURCE_BYTES.saturating_sub(total_bytes);
                    let artifact = read_bounded_file(&canonical, remaining).ok_or_else(|| BuildError::Compile(DiagnosticBundle::single(Diagnostic::error(
            "E_CONTRACT_IMPORT_INVALID", DiagnosticPhase::Resolve, format!("cannot read complete compiled contract `{name}` within the source graph byte budget"), Some(directive_span.clone())))))?;
                    total_bytes = total_bytes.saturating_add(artifact.len());
                    if known.len() > MAX_MODULE_GRAPH_SOURCES {
                        return Err(BuildError::SourceGraph(SourceGraphError::Budget {
                            sources: known.len(),
                            source_bytes: total_bytes,
                            max_sources: MAX_MODULE_GRAPH_SOURCES,
                            max_source_bytes: MAX_MODULE_GRAPH_SOURCE_BYTES,
                        }));
                    }
                    artifacts.push(SourceContractArtifact {
                        source_name: name,
                        artifact,
                    });
                    continue;
                }
            };
            let name = crate::linker::resolve_source_path(&unit.source_name, &relative).map_err(
                |error| {
                    let mut diagnostics = error.into_diagnostics();
                    for diagnostic in &mut diagnostics.diagnostics {
                        if diagnostic.primary_span.is_none() {
                            diagnostic.primary_span = Some(directive_span.clone());
                        }
                    }
                    diagnostics.capture_source(&file);
                    BuildError::Compile(diagnostics)
                },
            )?;
            if !known.insert(name.clone()) {
                continue;
            }
            let physical = canonical_root.join(&name);
            let canonical =
                canonical_overlay_path(&physical, &canonical_root, overlays).map_err(|error| {
                    match error {
                        BuildError::Io { .. } => {
                            BuildError::Compile(DiagnosticBundle::single(Diagnostic::error(
                                "E_SOURCE_NOT_FOUND",
                                DiagnosticPhase::Resolve,
                                format!("cannot resolve source `{name}`: {error}"),
                                Some(directive_span.clone()),
                            )))
                        }
                        error => error,
                    }
                })?;
            if let Some(first) = physical_names.insert(canonical.clone(), name.clone())
                && first != name
            {
                return Err(BuildError::Compile(DiagnosticBundle::single(
                    Diagnostic::error(
                        "E_DUPLICATE_SOURCE",
                        DiagnosticPhase::Resolve,
                        format!("source `{name}` resolves to the same physical file as `{first}`"),
                        Some(directive_span.clone()),
                    ),
                )));
            }
            let source = overlays
                .get(&physical)
                .or_else(|| overlays.get(&canonical))
                .cloned()
                .map_or_else(|| read_source_file(&canonical), Ok)?;
            total_bytes = total_bytes.saturating_add(source.len());
            if known.len() > MAX_MODULE_GRAPH_SOURCES || total_bytes > MAX_MODULE_GRAPH_SOURCE_BYTES
            {
                return Err(BuildError::SourceGraph(SourceGraphError::Budget {
                    sources: known.len(),
                    source_bytes: total_bytes,
                    max_sources: MAX_MODULE_GRAPH_SOURCES,
                    max_source_bytes: MAX_MODULE_GRAPH_SOURCE_BYTES,
                }));
            }
            let source = SourceModuleUnit {
                source_name: name,
                source,
            };
            pending.push_back((source.clone(), fragment));
            companions.push(source);
        }
    }
    companions.sort_by(|left, right| left.source_name.cmp(&right.source_name));
    artifacts.sort_by(|left, right| left.source_name.cmp(&right.source_name));
    Ok(SourceInventory {
        sources: companions,
        artifacts,
    })
}

/// Capture a deployable root and its declared local dependencies without package imports.
pub fn load_source_project(
    source_path: &Path,
    source_root: &Path,
    overlays: &BTreeMap<PathBuf, String>,
) -> Result<LoadedSourceProject, BuildError> {
    let canonical_root = source_root.canonicalize().map_err(|error| BuildError::Io {
        operation: "canonicalize Kotodama source root",
        path: source_root.into(),
        message: error.to_string(),
    })?;
    let physical = source_path
        .canonicalize()
        .or_else(|error| {
            if overlays.contains_key(source_path) && source_path.starts_with(&canonical_root) {
                Ok(source_path.to_path_buf())
            } else {
                Err(error)
            }
        })
        .map_err(|error| BuildError::Io {
            operation: "canonicalize Kotodama source",
            path: source_path.into(),
            message: error.to_string(),
        })?;
    let source_name = logical_source_name(&physical, &canonical_root)?;
    let source = overlays
        .get(&physical)
        .cloned()
        .map_or_else(|| read_source_file(&physical), Ok)?;
    let root = SourceModuleUnit {
        source_name,
        source,
    };
    let SourceInventory { sources, artifacts } =
        load_source_inventory(std::slice::from_ref(&root), &canonical_root, overlays)?;
    let source_paths = std::iter::once(&root)
        .chain(&sources)
        .map(|unit| {
            (
                ProjectSourceKey {
                    package_identity: None,
                    source_name: unit.source_name.clone(),
                },
                canonical_root.join(&unit.source_name),
            )
        })
        .collect();
    Ok(LoadedSourceProject {
        graph: LoadedProjectGraph::Source(SourceLinkRequest {
            artifacts,
            root,
            sources,
            imports: Vec::new(),
            packages: Vec::new(),
        }),
        source_paths,
        manifests: Vec::new(),
        lints: crate::session::LintConfig::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "kotodama-source-set-{}-{}",
                std::process::id(),
                TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&root).unwrap();
            Self(root.canonicalize().unwrap())
        }
        fn write(&self, name: &str, source: &str) -> PathBuf {
            let path = self.0.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, source).unwrap();
            path
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn compiled_import_inventory_preserves_binary_bytes_and_ignores_text_overlays() {
        let directory = Directory::new();
        let root = directory.write(
            "app.ko",
            r#"seiyaku App { import seiyaku "interfaces/pool.to" as Pool; }"#,
        );
        let artifact = directory.write("interfaces/pool.to", "artifact");
        fs::write(&artifact, [0, 255, 1, 128]).unwrap();
        let loaded = load_source_project(
            &root,
            &directory.0,
            &BTreeMap::from([(artifact, "not binary".into())]),
        )
        .unwrap();
        let graph = loaded.graph.as_source().unwrap();
        assert_eq!(
            graph.artifacts,
            vec![SourceContractArtifact {
                source_name: "interfaces/pool.to".into(),
                artifact: vec![0, 255, 1, 128]
            }]
        );
        assert!(graph.sources.is_empty());
    }
    #[test]
    fn upgrade_fixture_inventory_captures_one_immutable_confined_artifact() {
        let directory = Directory::new();
        let root = directory.write(
            "contracts/app.ko",
            r#"seiyaku App {
            fixture old { upgrade_from("../snapshots/prior.to"); }
            fixture again { upgrade_from("../snapshots/prior.to"); }
        }"#,
        );
        let path = directory.write("snapshots/prior.to", "old artifact");
        let loaded = load_source_project(&root, &directory.0, &BTreeMap::new()).unwrap();
        fs::write(&path, "changed after capture").unwrap();
        assert_eq!(
            loaded.graph.as_source().unwrap().artifacts,
            vec![SourceContractArtifact {
                source_name: "snapshots/prior.to".into(),
                artifact: b"old artifact".to_vec(),
            }]
        );
        fs::write(
            &root,
            r#"seiyaku App { fixture old { upgrade_from("../../escape.to"); } }"#,
        )
        .unwrap();
        assert!(load_source_project(&root, &directory.0, &BTreeMap::new()).is_err());
        fs::write(
            &root,
            r#"seiyaku App { fixture old { upgrade_from(variable); } }"#,
        )
        .unwrap();
        let error = load_source_project(&root, &directory.0, &BTreeMap::new()).unwrap_err();
        assert!(
            error.to_string().contains("literal relative .to path"),
            "{error}"
        );
    }
    #[test]
    fn captures_only_declared_include_and_import_closure() {
        let directory = Directory::new();
        let root = directory.write(
            "contracts/app.ko",
            "seiyaku App { include \"parts/state.ko\"; import \"../math.ko\" as Math; }",
        );
        directory.write(
            "contracts/parts/state.ko",
            "include \"../shared.ko\"; state int total;",
        );
        directory.write("contracts/shared.ko", "const int INITIAL = 0;");
        directory.write("math.ko", "module Math { export fn value() -> int { 1 } }");
        directory.write("unrelated.ko", "deliberately invalid and never read");
        let loaded = load_source_project(&root, &directory.0, &BTreeMap::new()).unwrap();
        assert_eq!(
            loaded
                .graph
                .as_source()
                .expect("source graph")
                .sources
                .iter()
                .map(|source| source.source_name.as_str())
                .collect::<Vec<_>>(),
            vec!["contracts/parts/state.ko", "contracts/shared.ko", "math.ko"]
        );
        assert_eq!(loaded.source_paths.len(), 4);
    }

    #[test]
    fn open_buffers_can_change_dependencies_and_supply_unsaved_files() {
        let directory = Directory::new();
        let root = directory.write("app.ko", "seiyaku App {}");
        let overlays = BTreeMap::from([
            (root.clone(), "seiyaku App { include \"new.ko\"; }".into()),
            (
                directory.0.join("new.ko"),
                "view fn value() authorize(anyone) -> int { 9 }".into(),
            ),
        ]);
        let loaded = load_source_project(&root, &directory.0, &overlays).unwrap();
        assert_eq!(
            loaded.graph.as_source().expect("source graph").sources[0].source_name,
            "new.ko"
        );
        assert!(
            loaded.graph.as_source().expect("source graph").sources[0]
                .source
                .contains('9')
        );
        assert!(!directory.0.join("new.ko").exists());
    }

    #[test]
    fn paths_cannot_escape_the_selected_source_root() {
        let directory = Directory::new();
        let root = directory.write("app.ko", "seiyaku App { include \"../outside.ko\"; }");
        let error = load_source_project(&root, &directory.0, &BTreeMap::new()).unwrap_err();
        assert!(error.to_string().contains("escape"));
    }

    #[test]
    fn invalid_import_paths_preserve_one_structured_diagnostic() {
        let directory = Directory::new();
        let root = directory.write("app.ko", "seiyaku App { import \"feemath\" as fees; }");
        let error = load_source_project(&root, &directory.0, &BTreeMap::new()).unwrap_err();
        let diagnostics = error.into_diagnostics().expect("compiler diagnostics");
        let diagnostic = &diagnostics.diagnostics[0];
        assert_eq!(diagnostic.code, "E_INVALID_SOURCE_PATH");
        assert!(!diagnostic.message.contains("error["));
        assert!(diagnostic.help.is_some());
        assert!(diagnostic.primary_source.is_some());
        let span = diagnostic.primary_span.as_ref().expect("import span");
        assert_eq!(span.source.as_deref(), Some("app.ko"));
        assert_eq!(
            diagnostics
                .render_human()
                .matches("error[E_INVALID_SOURCE_PATH]")
                .count(),
            1
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_dependencies_cannot_escape_the_selected_source_root() {
        let directory = Directory::new();
        let outside = Directory::new();
        let secret = outside.write("outside.ko", "state int hidden;");
        std::os::unix::fs::symlink(secret, directory.0.join("linked.ko")).unwrap();
        let root = directory.write("app.ko", "seiyaku App { include \"linked.ko\"; }");
        assert!(
            load_source_project(&root, &directory.0, &BTreeMap::new())
                .unwrap_err()
                .to_string()
                .contains("outside")
        );
    }
    #[cfg(unix)]
    #[test]
    fn source_loader_rejects_multiple_logical_names_for_one_physical_file() {
        let directory = Directory::new();
        std::fs::write(
            directory.0.join("app.ko"),
            "seiyaku App { include \"first.ko\"; include \"second.ko\"; }",
        )
        .expect("root source");
        std::fs::write(directory.0.join("first.ko"), "fn helper() {}").expect("source fragment");
        std::os::unix::fs::symlink("first.ko", directory.0.join("second.ko"))
            .expect("in-root alias");
        let error =
            load_source_project(&directory.0.join("app.ko"), &directory.0, &BTreeMap::new())
                .expect_err("physical alias must fail");
        assert!(error.to_string().contains("E_DUPLICATE_SOURCE"));
    }
}
