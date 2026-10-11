//! LSP projection of the compiler-owned semantic editor snapshot.
//!
//! Besides navigation and completion this module owns the language-server view of standalone
//! test modules: a module with `koto_test { target: ... }` (conventionally `*.test.ko`) is
//! checked in compiler test mode against its target, and its `kotoage:` selector strings are
//! references to the target's public entrypoints.
use super::*;
use kotodama_lang::{
    editor::{
        EditorSnapshot, SEMANTIC_TOKEN_MODIFIERS, SEMANTIC_TOKEN_TYPES, declared_test_target,
    },
    source::{SourceId, SourceRange},
};

/// Upper bound on standalone test modules attached to one target.
const MAX_LSP_TEST_MODULES: usize = 64;
/// Upper bound on files inspected while discovering test modules on disk.
const MAX_LSP_TEST_SCAN: usize = 512;

pub(super) struct Workspace {
    snapshot: EditorSnapshot,
    uris: BTreeMap<SourceId, String>,
    manifests: Vec<kotodama_lang::driver::ProjectManifestSource>,
    open_uris: HashSet<String>,
    versions: HashMap<String, i64>,
    rename_error: Option<String>,
}
/// Lexically normalize a path that may not exist yet.
fn normalize_path(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| {
        let mut normalized = PathBuf::new();
        for component in path.components() {
            match component {
                std::path::Component::ParentDir => {
                    normalized.pop();
                }
                std::path::Component::CurDir => {}
                component => normalized.push(component.as_os_str()),
            }
        }
        normalized
    })
}
/// The physical target named by a standalone test module, relative to the test file.
fn resolve_test_target(test_path: &Path, target: &str) -> Option<PathBuf> {
    Some(normalize_path(&test_path.parent()?.join(target)))
}
/// Whether an open document is a standalone test module, checked in compiler test mode.
pub(super) fn is_test_module(uri: &str, source: &str) -> bool {
    uri.ends_with(".test.ko") || declared_test_target(source).is_some()
}
fn collect_test_candidates(directory: &Path, recursive: bool, found: &mut BTreeSet<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    let mut entries = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        if found.len() >= MAX_LSP_TEST_SCAN {
            return;
        }
        if path.is_dir() {
            if recursive {
                collect_test_candidates(&path, true, found);
            }
        } else if path.extension().is_some_and(|extension| extension == "ko")
            && (recursive
                || path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with(".test.ko")))
        {
            found.insert(normalize_path(&path));
        }
    }
}
/// Standalone test modules whose `koto_test` target is `target`: open documents first, then
/// `*.test.ko` beside the target and every source under `tests/` beside it or at the nearest
/// enclosing Musubi package root. Discovery is bounded and deterministic.
fn discover_test_modules(
    documents: &HashMap<String, String>,
    target: &Path,
) -> Vec<(String, SourceModuleUnit)> {
    let mut sources = BTreeMap::<PathBuf, String>::new();
    for (uri, source) in documents {
        if let Some(path) = lsp_file_uri_path(uri)
            && path != target
            && declared_test_target(source).is_some()
        {
            sources.insert(path, source.clone());
        }
    }
    let mut paths = BTreeSet::new();
    if let Some(directory) = target.parent() {
        collect_test_candidates(directory, false, &mut paths);
        collect_test_candidates(&directory.join("tests"), true, &mut paths);
        if let Some(package) = directory
            .ancestors()
            .take(8)
            .find(|ancestor| ancestor.join("Musubi.toml").is_file())
        {
            collect_test_candidates(&package.join("tests"), true, &mut paths);
        }
    }
    for path in paths {
        if path != target
            && !sources.contains_key(&path)
            && let Ok(source) = read_source_file(&path)
        {
            sources.insert(path, source);
        }
    }
    sources
        .into_iter()
        .filter(|(path, source)| {
            declared_test_target(source)
                .and_then(|declared| resolve_test_target(path, &declared))
                .is_some_and(|declared| declared == target)
        })
        .take(MAX_LSP_TEST_MODULES)
        .filter_map(|(path, source)| {
            Some((
                lsp_path_file_uri(&path)?,
                SourceModuleUnit {
                    source_name: path.to_str()?.to_owned(),
                    source,
                },
            ))
        })
        .collect()
}
fn test_target_span(source: &SourceFile) -> Option<SourceSpan> {
    let target = declared_test_target(source.text())?;
    let literal = format!("{target:?}");
    let start = source.text().find(&literal)?;
    Some(SourceSpan::from_range(
        source,
        kotodama_lang::source::TextRange::new(
            u32::try_from(start).ok()?,
            u32::try_from(start + literal.len()).ok()?,
        ),
    ))
}
/// Diagnostics for one standalone test module, compiled in test mode against its target as
/// `koto test` does. Diagnostics located in the target belong to the target's own check.
pub(super) fn test_module_diagnostics(
    documents: &HashMap<String, String>,
    uri: &str,
    source: &str,
    zk_enabled: bool,
    project: Option<&LoadedSourceProject>,
    chain_discriminant: u16,
) -> DiagnosticBundle {
    let file = SourceFile::new(SourceId(0), uri, source);
    let Some(target) = declared_test_target(source) else {
        return DiagnosticBundle::single(
            Diagnostic::error(
                "E_TEST_TARGET_REQUIRED",
                DiagnosticPhase::Semantic,
                "standalone Kotodama tests require a `koto_test { target: \"...\" }` declaration",
                Some(SourceSpan::from_range(
                    &file,
                    kotodama_lang::source::TextRange::empty(0),
                )),
            )
            .with_source(&file),
        );
    };
    let Some(test_path) = lsp_file_uri_path(uri) else {
        return DiagnosticBundle::new(Vec::new());
    };
    let Some(target_path) = resolve_test_target(&test_path, &target) else {
        return DiagnosticBundle::new(Vec::new());
    };
    let target_source = lsp_path_file_uri(&target_path)
        .and_then(|target_uri| documents.get(&target_uri).cloned())
        .map_or_else(|| read_source_file(&target_path), Ok);
    let target_source = match target_source {
        Ok(target_source) => target_source,
        Err(error) => {
            let mut span = test_target_span(&file);
            if let Some(span) = &mut span {
                span.source = Some(uri.to_owned());
            }
            return DiagnosticBundle::single(Diagnostic::error(
                "E_SOURCE_NOT_FOUND",
                DiagnosticPhase::Resolve,
                format!("test target `{target}` cannot be read: {error}"),
                span,
            ));
        }
    };
    let (Some(test_name), Some(target_name)) = (test_path.to_str(), target_path.to_str()) else {
        return DiagnosticBundle::new(Vec::new());
    };
    let project = project.filter(|project| matches!(project.graph, LoadedProjectGraph::Source(_)));
    let project_root = project.and_then(|project| {
        let key = ProjectSourceKey {
            package_identity: None,
            source_name: project.graph.as_source()?.root.source_name.clone(),
        };
        project
            .source_paths
            .get(&key)
            .and_then(|path| physical_source_root(path, &key.source_name))
    });
    let logical_test_name = project_root
        .as_ref()
        .and_then(|root| logical_source_name(&test_path, root).ok());
    let test_name = logical_test_name.as_deref().unwrap_or(test_name);
    let options = CompilerOptions {
        force_zk: zk_enabled,
        chain_discriminant,
        mode: kotodama_lang::compiler::CompilerMode::Test,
        ..CompilerOptions::default()
    };
    let result =
        if let Some(project) = project {
            match lsp_project_with_open_overlays(project, documents) {
                Ok((LoadedProjectGraph::Source(mut graph), _, _, _)) => {
                    let root_name = graph.root.source_name.clone();
                    let test = SourceModuleUnit {
                        source_name: test_name.to_owned(),
                        source: source.to_owned(),
                    };
                    if let Some(root) = &project_root {
                        let overlays = documents
                            .iter()
                            .filter_map(|(uri, text)| {
                                lsp_file_uri_path(uri).map(|path| (path, text.clone()))
                            })
                            .collect();
                        match kotodama_lang::driver::load_source_inventory(
                            &[graph.root.clone(), test.clone()],
                            root,
                            &overlays,
                        ) {
                            Ok(inventory) => {
                                graph.sources = inventory.sources;
                                graph.artifacts = inventory.artifacts;
                            }
                            Err(error) => {
                                return error.into_diagnostics().unwrap_or_else(|error| {
                                    DiagnosticBundle::single(Diagnostic::error(
                                        "E_SOURCE_NOT_FOUND",
                                        DiagnosticPhase::Resolve,
                                        error.to_string(),
                                        None,
                                    ))
                                });
                            }
                        }
                    }
                    kotodama_lang::linker::ModuleBuildGraph::default()
                        .build_test_project_with_sources(graph, &[test], options, &root_name)
                }
                Ok((LoadedProjectGraph::Package(_), _, _, _)) => {
                    unreachable!("test target must be a source graph")
                }
                Err(error) => Err(error.into_diagnostics().unwrap_or_else(|error| {
                    DiagnosticBundle::single(Diagnostic::error(
                        "E_SOURCE_NOT_FOUND",
                        DiagnosticPhase::Resolve,
                        error.to_string(),
                        None,
                    ))
                })),
            }
        } else {
            CompilerSession::new(options).build_test_sources(
                &kotodama_lang::session::TestSourceUnit {
                    source_name: target_name.to_owned(),
                    source: target_source,
                },
                &[kotodama_lang::session::TestSourceUnit {
                    source_name: test_name.to_owned(),
                    source: source.to_owned(),
                }],
            )
        };
    let Err(bundle) = result else {
        return DiagnosticBundle::new(Vec::new());
    };
    let diagnostics = bundle
        .diagnostics
        .into_iter()
        .filter(|diagnostic| {
            diagnostic
                .primary_span
                .as_ref()
                .and_then(|span| span.source.as_deref())
                .is_none_or(|name| name == test_name)
        })
        .map(|mut diagnostic| {
            let remap = |span: &mut SourceSpan| {
                if span.source.as_deref().is_none_or(|name| name == test_name) {
                    span.source = Some(uri.to_owned());
                }
            };
            if let Some(span) = &mut diagnostic.primary_span {
                remap(span);
            }
            for label in &mut diagnostic.labels {
                remap(&mut label.span);
            }
            for fix in diagnostic
                .fix
                .iter_mut()
                .chain(&mut diagnostic.alternative_fixes)
            {
                remap(&mut fix.span);
            }
            diagnostic
        })
        .collect();
    DiagnosticBundle::new(diagnostics)
}
/// Replace production-mode diagnostics of open standalone test modules with their test-mode
/// diagnostics.
pub(super) fn apply_test_module_diagnostics(
    diagnostics: &mut HashMap<String, DiagnosticBundle>,
    documents: &HashMap<String, String>,
    zk_enabled: bool,
) {
    let mut tests = documents
        .iter()
        .filter(|(uri, source)| is_test_module(uri, source))
        .collect::<Vec<_>>();
    tests.sort_by(|(left, _), (right, _)| left.cmp(right));
    for (uri, source) in tests {
        diagnostics.insert(
            uri.clone(),
            test_module_diagnostics(
                documents,
                uri,
                source,
                zk_enabled,
                None,
                CompilerOptions::default().chain_discriminant,
            ),
        );
    }
}
impl Workspace {
    pub(super) fn new(
        documents: &HashMap<String, String>,
        project: Option<&LoadedSourceProject>,
        uri: &str,
        zk: bool,
    ) -> Self {
        if let Some(source) = documents.get(uri)
            && declared_test_target(source).is_some()
            && let Some(workspace) = Self::for_test_module(documents, project, uri, source, zk)
        {
            return workspace;
        }
        let local_project = project
            .is_none()
            .then(|| lsp_local_source_project(documents, Some(uri)))
            .flatten();
        let project = project.or(local_project.as_ref());
        if let Some(project) = project
            && let Some(workspace) = Self::for_project(documents, project, uri, zk)
        {
            return workspace;
        }
        let snapshot =
            EditorSnapshot::single(uri, documents.get(uri).map_or("", String::as_str), zk);
        Self {
            snapshot,
            uris: BTreeMap::from([(SourceId(0), uri.to_owned())]),
            manifests: Vec::new(),
            open_uris: documents.keys().cloned().collect(),
            versions: HashMap::new(),
            rename_error: project
                .filter(|project| {
                    project
                        .source_paths
                        .values()
                        .any(|path| lsp_file_uri_path(uri).as_ref() == Some(path))
                })
                .map(|_| {
                    "Rename requires a valid current project source graph and manifest.".into()
                }),
        }
    }
    /// The project graph containing `uri`, with the standalone tests that target its root.
    fn for_project(
        documents: &HashMap<String, String>,
        project: &LoadedSourceProject,
        uri: &str,
        zk: bool,
    ) -> Option<Self> {
        let tests = project
            .graph
            .as_source()
            .and_then(|graph| {
                project.source_paths.get(&ProjectSourceKey {
                    package_identity: None,
                    source_name: graph.root.source_name.clone(),
                })
            })
            .map(|root| discover_test_modules(documents, root))
            .unwrap_or_default();
        Self::for_project_with_tests(documents, project, uri, &tests, zk)
    }
    /// A standalone test module analyzed together with its declared target's graph.
    fn for_test_module(
        documents: &HashMap<String, String>,
        project: Option<&LoadedSourceProject>,
        uri: &str,
        source: &str,
        zk: bool,
    ) -> Option<Self> {
        let test_path = lsp_file_uri_path(uri)?;
        let target_path = resolve_test_target(&test_path, &declared_test_target(source)?)?;
        let target_uri = lsp_path_file_uri(&target_path)?;
        let overlays = documents
            .iter()
            .filter_map(|(uri, source)| lsp_file_uri_path(uri).map(|path| (path, source.clone())))
            .collect::<BTreeMap<_, _>>();
        let loaded = project
            .filter(|project| {
                project
                    .source_paths
                    .values()
                    .any(|path| *path == target_path)
            })
            .cloned()
            .or_else(|| load_source_project(&target_path, target_path.parent()?, &overlays).ok())?;
        let mut tests = discover_test_modules(documents, &target_path);
        if !tests.iter().any(|(test_uri, _)| test_uri == uri) {
            tests.push((
                uri.to_owned(),
                SourceModuleUnit {
                    source_name: test_path.to_str()?.to_owned(),
                    source: source.to_owned(),
                },
            ));
        }
        Self::for_project_with_tests(documents, &loaded, &target_uri, &tests, zk)
    }
    fn for_project_with_tests(
        documents: &HashMap<String, String>,
        project: &LoadedSourceProject,
        uri: &str,
        tests: &[(String, SourceModuleUnit)],
        zk: bool,
    ) -> Option<Self> {
        let (graph, source_uris, _, manifests) =
            lsp_project_with_open_overlays(project, documents).ok()?;
        if !source_uris.values().any(|candidate| candidate == uri) {
            return None;
        }
        let modules = tests
            .iter()
            .map(|(_, module)| module.clone())
            .collect::<Vec<_>>();
        let snapshot = match &graph {
            LoadedProjectGraph::Source(graph) => {
                EditorSnapshot::project_with_tests(graph, &modules, zk)
            }
            LoadedProjectGraph::Package(graph) => EditorSnapshot::package(graph, zk),
        };
        let mut uris = snapshot
            .sources()
            .filter_map(|source| {
                let key = ProjectSourceKey {
                    package_identity: source.package_identity().map(ToOwned::to_owned),
                    source_name: source.name().to_owned(),
                };
                source_uris.get(&key).map(|uri| (source.id(), uri.clone()))
            })
            .collect::<BTreeMap<_, _>>();
        for (id, (test_uri, _)) in snapshot.test_module_sources().zip(tests) {
            uris.insert(id, test_uri.clone());
        }
        Some(Self {
            snapshot,
            uris,
            manifests,
            open_uris: documents.keys().cloned().collect(),
            versions: HashMap::new(),
            rename_error: None,
        })
    }
    pub(super) fn with_versions(mut self, versions: &HashMap<String, i64>) -> Self {
        self.versions = versions
            .iter()
            .filter(|(uri, _)| self.open_uris.contains(*uri))
            .map(|(uri, version)| (uri.clone(), *version))
            .collect();
        self
    }
    /// Source identities and URIs covered by this workspace.
    pub(super) fn covered_uris(&self) -> impl Iterator<Item = &str> {
        self.uris.values().map(String::as_str)
    }
    fn manifest_uri(
        &self,
        manifest: &kotodama_lang::driver::ProjectManifestSource,
    ) -> Option<String> {
        let path = manifest.path();
        self.open_uris
            .iter()
            .find(|uri| lsp_file_uri_path(uri).as_deref() == Some(path))
            .cloned()
            .or_else(|| lsp_path_file_uri(path))
    }
    fn rename_plan(
        &self,
        source: SourceId,
        offset: u32,
        name: &str,
    ) -> Result<kotodama_lang::editor::EditorRename, String> {
        if let Some(error) = &self.rename_error {
            return Err(error.clone());
        }
        let plan = self.snapshot.rename(source, offset, name)?;
        if self.manifests.is_empty()
            && plan.sources.iter().any(|range| {
                self.snapshot
                    .source(range.source)
                    .is_some_and(|file| file.package_identity().is_some())
            })
        {
            return Err("Package rename requires an owned local export manifest; external locked dependencies are immutable.".into());
        }
        for export in &plan.exports {
            if !self.manifests.iter().any(|manifest| {
                manifest
                    .export_range(&export.package, &export.old_name)
                    .is_some()
            }) {
                return Err("Export rename requires an owned local export manifest; external locked dependencies are immutable.".into());
            }
        }
        // Open buffers are immutable/versioned in this workspace; unopened inputs must still
        // match the captured graph before returning any source or metadata edit.
        for (id, uri) in &self.uris {
            if self.open_uris.contains(uri) {
                continue;
            }
            let path = lsp_file_uri_path(uri).ok_or("Rename source is no longer available.")?;
            if read_source_file(&path).map_err(|error| error.to_string())?
                != self
                    .snapshot
                    .source(*id)
                    .ok_or("Rename source is unavailable.")?
                    .text()
            {
                return Err(
                    "Rename source changed on disk; reload the project before renaming.".into(),
                );
            }
        }
        for manifest in &self.manifests {
            let uri = self
                .manifest_uri(manifest)
                .ok_or("Rename manifest URI is unavailable.")?;
            if !self.open_uris.contains(&uri)
                && read_source_file(manifest.path()).map_err(|error| error.to_string())?
                    != manifest.text()
            {
                return Err(
                    "Rename manifest changed on disk; reload the project before renaming.".into(),
                );
            }
        }
        Ok(plan)
    }
    fn location(&self, source: SourceRange) -> Option<norito::json::Value> {
        Some(json_object(vec![
            (
                "uri",
                norito::json::Value::from(self.uris.get(&source.source)?.as_str()),
            ),
            (
                "range",
                lsp_text_range(self.snapshot.source(source.source)?.text(), source.range),
            ),
        ]))
    }
    fn document(&self, message: &norito::json::Value) -> Option<SourceId> {
        let uri = message.pointer("/params/textDocument/uri")?.as_str()?;
        Some(
            *self
                .uris
                .iter()
                .find(|(_, candidate)| candidate.as_str() == uri)?
                .0,
        )
    }
    fn position(&self, message: &norito::json::Value) -> Option<(SourceId, u32)> {
        let source = self.document(message)?;
        let line = message.pointer("/params/position/line")?.as_u64()?;
        let character = message.pointer("/params/position/character")?.as_u64()?;
        Some((
            source,
            utf16_offset(self.snapshot.source(source)?.text(), line, character)?,
        ))
    }
    fn document_symbol_value(
        text: &str,
        symbol: kotodama_lang::editor::EditorSymbol,
    ) -> norito::json::Value {
        json_object(vec![
            ("name", symbol.name.into()),
            ("detail", symbol.detail.into()),
            ("kind", symbol.kind.into()),
            ("range", lsp_text_range(text, symbol.range)),
            ("selectionRange", lsp_text_range(text, symbol.selection)),
            (
                "children",
                norito::json::Value::Array(
                    symbol
                        .children
                        .into_iter()
                        .map(|child| Self::document_symbol_value(text, child))
                        .collect(),
                ),
            ),
        ])
    }
    /// Responses that need only a document, not a cursor position.
    fn document_response(&self, method: &str, source: SourceId) -> Option<norito::json::Value> {
        let text = self.snapshot.source(source)?.text();
        Some(match method {
            "textDocument/documentSymbol" => norito::json::Value::Array(
                self.snapshot
                    .document_symbols(source)
                    .into_iter()
                    .map(|symbol| Self::document_symbol_value(text, symbol))
                    .collect(),
            ),
            "textDocument/foldingRange" => norito::json::Value::Array(
                self.snapshot
                    .folding_ranges(source)
                    .into_iter()
                    .filter_map(|fold| {
                        let (start, _) = lsp_offset_position(text, fold.range.start);
                        let (end, _) = lsp_offset_position(text, fold.range.end);
                        // Keep a closing delimiter visible on its own line.
                        let end = if fold.comment {
                            end
                        } else {
                            end.checked_sub(1)?
                        };
                        (end > start).then(|| {
                            let mut fields =
                                vec![("startLine", start.into()), ("endLine", end.into())];
                            if fold.comment {
                                fields.push(("kind", "comment".into()));
                            }
                            json_object(fields)
                        })
                    })
                    .collect(),
            ),
            "textDocument/semanticTokens/full" => {
                let mut data = Vec::new();
                let (mut previous_line, mut previous_start) = (0_u64, 0_u64);
                for token in self.snapshot.semantic_tokens(source) {
                    let (line, start) = lsp_offset_position(text, token.range.start);
                    let length = text
                        .get(token.range.start as usize..token.range.end as usize)
                        .map_or(0, |slice| slice.encode_utf16().count() as u64);
                    let delta_start = if line == previous_line {
                        start - previous_start
                    } else {
                        start
                    };
                    data.extend([
                        line - previous_line,
                        delta_start,
                        length,
                        u64::from(token.token_type),
                        u64::from(token.modifiers),
                    ]);
                    (previous_line, previous_start) = (line, start);
                }
                json_object(vec![(
                    "data",
                    norito::json::Value::Array(data.into_iter().map(Into::into).collect()),
                )])
            }
            "textDocument/codeLens" => {
                let uri = self.uris.get(&source)?;
                // `koto test run` needs a file on disk; unsaved buffers get no lens.
                let Some(path) =
                    lsp_file_uri_path(uri).and_then(|path| path.to_str().map(ToOwned::to_owned))
                else {
                    return Some(norito::json::Value::Array(Vec::new()));
                };
                norito::json::Value::Array(
                    self.snapshot
                        .test_lenses(source)
                        .into_iter()
                        .map(|lens| {
                            let arguments = [
                                "test",
                                "run",
                                "--filter",
                                lens.name.as_str(),
                                "--exact",
                                path.as_str(),
                            ]
                            .into_iter()
                            .map(norito::json::Value::from)
                            .collect();
                            json_object(vec![
                                ("range", lsp_text_range(text, lens.range)),
                                (
                                    "command",
                                    json_object(vec![
                                        ("title", "Run test".into()),
                                        ("command", "kotodama.runTest".into()),
                                        (
                                            "arguments",
                                            norito::json::Value::Array(vec![json_object(vec![
                                                ("uri", uri.as_str().into()),
                                                ("name", lens.name.into()),
                                                ("args", norito::json::Value::Array(arguments)),
                                            ])]),
                                        ),
                                    ]),
                                ),
                            ])
                        })
                        .collect(),
                )
            }
            _ => return None,
        })
    }
    /// Workspace symbols matching `query` in this snapshot, skipping already reported URIs.
    pub(super) fn workspace_symbols(
        &self,
        query: &str,
        reported: &mut BTreeSet<String>,
    ) -> Vec<norito::json::Value> {
        let mut symbols = Vec::new();
        let mut covered = BTreeSet::new();
        for (source, symbol, container) in self.snapshot.workspace_symbols(query) {
            let (Some(uri), Some(file)) = (self.uris.get(&source), self.snapshot.source(source))
            else {
                continue;
            };
            if reported.contains(uri) {
                continue;
            }
            covered.insert(uri.clone());
            let mut fields = vec![
                ("name", symbol.name.into()),
                ("kind", symbol.kind.into()),
                (
                    "location",
                    json_object(vec![
                        ("uri", uri.as_str().into()),
                        ("range", lsp_text_range(file.text(), symbol.selection)),
                    ]),
                ),
            ];
            if let Some(container) = container {
                fields.push(("containerName", container.into()));
            }
            symbols.push(json_object(fields));
        }
        reported.extend(covered);
        symbols
    }
    pub(super) fn response(
        &self,
        method: &str,
        message: &norito::json::Value,
    ) -> Result<norito::json::Value, String> {
        if let Some(source) = self.document(message)
            && let Some(response) = self.document_response(method, source)
        {
            return Ok(response);
        }
        let Some((source, offset)) = self.position(message) else {
            return Ok(norito::json::Value::Null);
        };
        Ok(match method {
            "textDocument/completion" => {
                let items = self
                    .snapshot
                    .completions(source, offset)
                    .into_iter()
                    .map(|completion| {
                        let mut fields = vec![
                            ("label", completion.label.into()),
                            ("kind", completion.kind.into()),
                            ("detail", completion.detail.into()),
                            ("insertText", completion.insert_text.into()),
                            (
                                "insertTextFormat",
                                norito::json::Value::from(if completion.snippet {
                                    2_u64
                                } else {
                                    1_u64
                                }),
                            ),
                            (
                                "documentation",
                                json_object(vec![
                                    ("kind", "markdown".into()),
                                    ("value", completion.documentation.into()),
                                ]),
                            ),
                        ];
                        if let Some(filter) = completion.filter_text {
                            fields.push(("filterText", filter.into()));
                        }
                        if let Some(sort) = completion.sort_text {
                            fields.push(("sortText", sort.into()));
                        }
                        json_object(fields)
                    })
                    .collect();
                // Candidates never depend on the partially typed word, so clients filter
                // locally instead of re-requesting on every keystroke.
                json_object(vec![
                    ("isIncomplete", false.into()),
                    ("items", norito::json::Value::Array(items)),
                ])
            }
            "textDocument/definition" => self
                .snapshot
                .definition(source, offset)
                .and_then(|definition| self.location(definition.source))
                .unwrap_or(norito::json::Value::Null),
            "textDocument/references" => norito::json::Value::Array(
                self.snapshot
                    .references(
                        source,
                        offset,
                        message
                            .pointer("/params/context/includeDeclaration")
                            .and_then(norito::json::Value::as_bool)
                            .unwrap_or(false),
                    )
                    .into_iter()
                    .filter_map(|source| self.location(source))
                    .collect(),
            ),
            "textDocument/documentHighlight" => {
                let text = self.snapshot.source(source).map_or("", SourceFile::text);
                norito::json::Value::Array(
                    self.snapshot
                        .highlights(source, offset)
                        .into_iter()
                        .map(|highlight| {
                            json_object(vec![
                                ("range", lsp_text_range(text, highlight.range)),
                                ("kind", highlight.kind.into()),
                            ])
                        })
                        .collect(),
                )
            }
            "textDocument/hover" => self.snapshot.hover(source, offset).map_or(
                norito::json::Value::Null,
                |(detail, documentation)| {
                    json_object(vec![(
                        "contents",
                        json_object(vec![
                            ("kind", "markdown".into()),
                            (
                                "value",
                                format!("```kotodama\n{detail}\n```\n{documentation}").into(),
                            ),
                        ]),
                    )])
                },
            ),
            "textDocument/signatureHelp" => self.snapshot.signature_help(source, offset).map_or(
                norito::json::Value::Null,
                |(signature, active)| {
                    let active = active.min(signature.parameters.len().saturating_sub(1));
                    json_object(vec![
                        (
                            "signatures",
                            norito::json::Value::Array(vec![json_object(vec![
                                ("label", signature.label().into()),
                                (
                                    "documentation",
                                    json_object(vec![
                                        ("kind", "markdown".into()),
                                        ("value", signature.documentation.clone().into()),
                                    ]),
                                ),
                                (
                                    "parameters",
                                    norito::json::Value::Array(
                                        signature
                                            .parameters
                                            .iter()
                                            .map(|parameter| {
                                                json_object(vec![(
                                                    "label",
                                                    format!(
                                                        "{} {}{}",
                                                        parameter.ty,
                                                        if parameter.named { "" } else { "_ " },
                                                        parameter.name
                                                    )
                                                    .into(),
                                                )])
                                            })
                                            .collect(),
                                    ),
                                ),
                            ])]),
                        ),
                        ("activeSignature", 0_u64.into()),
                        ("activeParameter", (active as u64).into()),
                    ])
                },
            ),
            "textDocument/prepareRename" => {
                let definition = self
                    .snapshot
                    .definition(source, offset)
                    .ok_or("No resolved declaration at this position.")?;
                self.rename_plan(source, offset, &definition.name)?;
                let range = self
                    .snapshot
                    .references(source, offset, true)
                    .into_iter()
                    .find(|range| {
                        range.source == source
                            && range.range.start <= offset
                            && offset < range.range.end
                    })
                    .ok_or("No exact identifier range at this position.")?;
                json_object(vec![
                    (
                        "range",
                        lsp_text_range(
                            self.snapshot.source(source).expect("source").text(),
                            range.range,
                        ),
                    ),
                    ("placeholder", definition.name.clone().into()),
                ])
            }
            "textDocument/rename" => {
                let name = message
                    .pointer("/params/newName")
                    .and_then(norito::json::Value::as_str)
                    .ok_or("Rename requires a newName.")?;
                let plan = self.rename_plan(source, offset, name)?;
                let mut changes = BTreeMap::<String, Vec<norito::json::Value>>::new();
                for range in plan.sources {
                    let uri = self
                        .uris
                        .get(&range.source)
                        .ok_or("Rename source is not in the exact project graph.")?;
                    let file = self
                        .snapshot
                        .source(range.source)
                        .ok_or("Rename source is unavailable.")?;
                    changes
                        .entry(uri.clone())
                        .or_default()
                        .push(json_object(vec![
                            ("range", lsp_text_range(file.text(), range.range)),
                            ("newText", name.into()),
                        ]));
                }
                for export in plan.exports {
                    let manifest = self
                        .manifests
                        .iter()
                        .find(|manifest| {
                            manifest
                                .export_range(&export.package, &export.old_name)
                                .is_some()
                        })
                        .ok_or("Owned export manifest is unavailable.")?;
                    let range = manifest
                        .export_range(&export.package, &export.old_name)
                        .ok_or("Exact export token is unavailable.")?;
                    changes
                        .entry(
                            self.manifest_uri(manifest)
                                .ok_or("Export manifest URI is unavailable.")?,
                        )
                        .or_default()
                        .push(json_object(vec![
                            ("range", lsp_text_range(manifest.text(), range)),
                            (
                                "newText",
                                norito::json::to_string(&export.new_name)
                                    .map_err(|error| error.to_string())?
                                    .into(),
                            ),
                        ]));
                }
                json_object(vec![(
                    "documentChanges",
                    norito::json::Value::Array(
                        changes
                            .into_iter()
                            .map(|(uri, edits)| {
                                let version = self
                                    .versions
                                    .get(&uri)
                                    .copied()
                                    .map_or(norito::json::Value::Null, norito::json::Value::from);
                                json_object(vec![
                                    (
                                        "textDocument",
                                        json_object(vec![
                                            ("uri", uri.into()),
                                            ("version", version),
                                        ]),
                                    ),
                                    ("edits", norito::json::Value::Array(edits)),
                                ])
                            })
                            .collect(),
                    ),
                )])
            }
            _ => norito::json::Value::Null,
        })
    }
}
/// `workspace/symbol` over the project graphs of every open document.
pub(super) fn workspace_symbol_response(
    documents: &HashMap<String, String>,
    project: Option<&LoadedSourceProject>,
    zk: bool,
    query: &str,
) -> norito::json::Value {
    let mut reported = BTreeSet::new();
    let mut symbols = Vec::new();
    let mut uris = documents.keys().cloned().collect::<Vec<_>>();
    uris.sort();
    for uri in uris {
        if reported.contains(&uri) {
            continue;
        }
        let workspace = Workspace::new(documents, project, &uri, zk);
        symbols.extend(workspace.workspace_symbols(query, &mut reported));
        reported.extend(workspace.covered_uris().map(ToOwned::to_owned));
    }
    norito::json::Value::Array(symbols)
}
/// Legend advertised for `textDocument/semanticTokens`.
pub(super) fn semantic_tokens_legend() -> norito::json::Value {
    json_object(vec![
        (
            "tokenTypes",
            norito::json::Value::Array(
                SEMANTIC_TOKEN_TYPES
                    .iter()
                    .map(|name| (*name).into())
                    .collect(),
            ),
        ),
        (
            "tokenModifiers",
            norito::json::Value::Array(
                SEMANTIC_TOKEN_MODIFIERS
                    .iter()
                    .map(|name| (*name).into())
                    .collect(),
            ),
        ),
    ])
}
fn utf16_offset(source: &str, line: u64, character: u64) -> Option<u32> {
    let line = usize::try_from(line).ok()?;
    let character = usize::try_from(character).ok()?;
    let start = if line == 0 {
        0
    } else {
        source.match_indices('\n').nth(line - 1)?.0 + 1
    };
    let text = source[start..].split('\n').next()?;
    let mut utf16 = 0;
    for (byte, ch) in text.char_indices() {
        if utf16 == character {
            return u32::try_from(start + byte).ok();
        }
        utf16 += ch.len_utf16();
        if utf16 > character {
            return None;
        }
    }
    (utf16 == character)
        .then(|| u32::try_from(start + text.len()).ok())
        .flatten()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn positions_preserve_japanese_and_reject_half_surrogates() {
        let text = "金庫😀x\n次";
        assert_eq!(utf16_offset(text, 0, 2), Some(6));
        assert_eq!(utf16_offset(text, 0, 3), None);
        assert_eq!(utf16_offset(text, 0, 4), Some(10));
        assert_eq!(utf16_offset(text, 1, 1), Some(text.len() as u32));
    }
    #[test]
    fn semantic_responses_share_identity_ranges_and_named_argument_labels() {
        let uri = "file:///editor.ko";
        let text = "module Editor { fn target(int _ first, int second) -> int { first + second } fn run() -> int { target(1, second: 2) } }";
        let documents = HashMap::from([(uri.to_owned(), text.to_owned())]);
        let workspace = Workspace::new(&documents, None, uri, false);
        let position = text.find("second: 2").unwrap();
        let request = norito::json!({"params": {"textDocument": {"uri": uri}, "position": {"line": 0, "character": position}, "context": {"includeDeclaration": true}, "newName": "increment"}});
        let definition = workspace
            .response("textDocument/definition", &request)
            .unwrap();
        assert_eq!(
            definition
                .pointer("/uri")
                .and_then(norito::json::Value::as_str),
            Some(uri)
        );
        assert_eq!(
            definition
                .pointer("/range/start/character")
                .and_then(norito::json::Value::as_u64),
            Some(text.find("second)").unwrap() as u64)
        );
        let references = workspace
            .response("textDocument/references", &request)
            .unwrap();
        assert_eq!(references.as_array().unwrap().len(), 3);
        let renamed = workspace.response("textDocument/rename", &request).unwrap();
        let edits = renamed
            .pointer("/documentChanges/0/edits")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(edits.len(), 3);
        assert!(edits.iter().all(|edit| {
            edit.pointer("/newText")
                .and_then(norito::json::Value::as_str)
                == Some("increment")
        }));
        let active_position = position + 9;
        let active = norito::json!({"params": {"textDocument": {"uri": uri}, "position": {"line": 0, "character": active_position}}});
        let signature = workspace
            .response("textDocument/signatureHelp", &active)
            .unwrap();
        assert_eq!(
            signature
                .pointer("/activeParameter")
                .and_then(norito::json::Value::as_u64),
            Some(1)
        );
        assert_eq!(
            signature
                .pointer("/signatures/0/label")
                .and_then(norito::json::Value::as_str),
            Some("target(int _ first, int second) -> int")
        );
    }
    #[test]
    fn owned_export_rename_updates_only_exact_versioned_source_and_manifest_tokens() {
        let root = std::env::temp_dir().join(format!(
            "kotodama-export-rename-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let app = root.join("金庫😀.ko");
        let module = root.join("values.ko");
        let manifest = root.join("Musubi.toml");
        let app_text = "seiyaku App { /* 金庫😀 */ view fn run() authorize(anyone) -> int { value::value() } }";
        let module_text =
            "module Values { export fn value() -> int { 7 } fn other() -> string { \"value\" } }";
        let manifest_text = r#"# test/value@1
[dependencies]
value = { path = "." }
[lib]
exports = ["v\u0061lue"]
"#;
        std::fs::write(&app, app_text).unwrap();
        std::fs::write(&module, module_text).unwrap();
        std::fs::write(&manifest, manifest_text).unwrap();
        let app_uri = lsp_path_file_uri(&app.canonicalize().unwrap()).unwrap();
        let module_uri = lsp_path_file_uri(&module.canonicalize().unwrap()).unwrap();
        let manifest_uri = lsp_path_file_uri(&manifest.canonicalize().unwrap()).unwrap();
        let manifest_overlay = manifest_text.replace("exports =", "exports  =");
        let project = fixture_project(
            &root,
            "金庫😀.ko",
            Some(("test/value@1", "value", "values.ko")),
            &manifest,
            &manifest_overlay,
            "value",
        );
        let documents = HashMap::from([
            (app_uri.clone(), app_text.to_owned()),
            (manifest_uri.clone(), manifest_overlay.clone()),
        ]);
        let versions = HashMap::from([(app_uri.clone(), 7), (manifest_uri.clone(), 4)]);
        let workspace =
            Workspace::new(&documents, Some(&project), &app_uri, false).with_versions(&versions);
        let offset = app_text.rfind("value()").unwrap();
        let character = app_text[..offset].encode_utf16().count();
        let request = norito::json!({"params": {"textDocument": {"uri": (app_uri.clone())},
            "position": {"line": 0, "character": character}, "newName": "renamed"}});
        workspace
            .response("textDocument/prepareRename", &request)
            .unwrap();
        let response = workspace.response("textDocument/rename", &request).unwrap();
        let edits = response.get("documentChanges").unwrap().as_array().unwrap();
        assert_eq!(edits.len(), 3);
        let mut rewritten = BTreeMap::from([
            (app_uri.clone(), app_text.to_owned()),
            (module_uri.clone(), module_text.to_owned()),
            (manifest_uri.clone(), manifest_overlay.clone()),
        ]);
        for document in edits {
            let uri = document
                .pointer("/textDocument/uri")
                .unwrap()
                .as_str()
                .unwrap();
            let version = document.pointer("/textDocument/version").unwrap();
            assert_eq!(version.as_i64(), versions.get(uri).copied());
            let text = rewritten.get_mut(uri).unwrap();
            let mut replacements = document
                .get("edits")
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .map(|edit| {
                    let start = edit.pointer("/range/start").unwrap();
                    let end = edit.pointer("/range/end").unwrap();
                    let start = utf16_offset(
                        text,
                        start.get("line").unwrap().as_u64().unwrap(),
                        start.get("character").unwrap().as_u64().unwrap(),
                    )
                    .unwrap() as usize;
                    let end = utf16_offset(
                        text,
                        end.get("line").unwrap().as_u64().unwrap(),
                        end.get("character").unwrap().as_u64().unwrap(),
                    )
                    .unwrap() as usize;
                    (
                        start,
                        end,
                        edit.get("newText").unwrap().as_str().unwrap().to_owned(),
                    )
                })
                .collect::<Vec<_>>();
            if uri == manifest_uri {
                assert_eq!(replacements.len(), 1);
                let (start, end, replacement) = &replacements[0];
                assert_eq!(&text[*start..*end], "\"v\\u0061lue\"");
                assert_eq!(replacement, "\"renamed\"");
            }
            replacements.sort_by_key(|(start, _, _)| std::cmp::Reverse(*start));
            for (start, end, replacement) in replacements {
                text.replace_range(start..end, &replacement);
            }
        }
        assert!(rewritten[&app_uri].contains("value::renamed()"));
        assert!(rewritten[&module_uri].contains("\"value\""));
        assert!(rewritten[&manifest_uri].contains("value = { path"));
        assert!(rewritten[&manifest_uri].contains("test/value@1"));
        let mut library = project.clone();
        let package = library.graph.as_source().unwrap().packages[0].clone();
        library.graph =
            LoadedProjectGraph::Package(kotodama_lang::linker::SourcePackageGraphRequest {
                package,
                dependencies: Vec::new(),
            });
        library
            .source_paths
            .retain(|key, _| key.package_identity.is_some());
        let library_documents = HashMap::from([
            (module_uri.clone(), module_text.to_owned()),
            (manifest_uri.clone(), manifest_overlay.clone()),
        ]);
        let library_workspace =
            Workspace::new(&library_documents, Some(&library), &module_uri, false);
        let library_character = module_text.find("value()").unwrap();
        let library_request = norito::json!({"params": {"textDocument": {"uri": (module_uri.clone())}, "position": {"line": 0, "character": library_character}, "newName": "renamed"}});
        let result = library_workspace
            .response("textDocument/rename", &library_request)
            .unwrap();
        let changes = result.get("documentChanges").unwrap().as_array().unwrap();
        assert_eq!(
            changes.len(),
            2,
            "library rename changes its source and owned manifest only"
        );
        assert!(changes.iter().any(|change| {
            change
                .pointer("/textDocument/uri")
                .and_then(norito::json::Value::as_str)
                == Some(manifest_uri.as_str())
        }));
        let mut snapshot = ProjectSnapshot {
            targets: vec![
                ProjectTarget {
                    name: "app".into(),
                    project: project.clone(),
                    test_context: None,
                },
                ProjectTarget {
                    name: "library".into(),
                    project: library.clone(),
                    test_context: None,
                },
            ],
            selected_target: None,
        };
        assert!(matches!(
            selected_project(&snapshot, &module_uri, &library_documents)
                .unwrap()
                .unwrap()
                .graph,
            LoadedProjectGraph::Package(_)
        ));
        snapshot.targets[1].project.source_paths = library
            .source_paths
            .iter()
            .map(|(key, path)| {
                (
                    ProjectSourceKey {
                        package_identity: Some("different/owner@1".into()),
                        source_name: key.source_name.clone(),
                    },
                    path.clone(),
                )
            })
            .collect();
        assert!(
            selected_project(&snapshot, &module_uri, &library_documents).is_err(),
            "different nominal ownership requires explicit selection"
        );
        let mut external = project.clone();
        external.manifests.clear();
        let external = Workspace::new(&documents, Some(&external), &app_uri, false);
        assert!(
            external
                .response("textDocument/rename", &request)
                .unwrap_err()
                .contains("immutable")
        );
        let mut invalid = documents.clone();
        invalid.insert(manifest_uri.clone(), "{".into());
        assert!(
            Workspace::new(&invalid, Some(&project), &app_uri, false)
                .response("textDocument/rename", &request)
                .is_err()
        );
        std::fs::write(&module, format!("{module_text} // newer disk version")).unwrap();
        assert!(
            workspace
                .response("textDocument/rename", &request)
                .unwrap_err()
                .contains("changed on disk")
        );
        std::fs::write(&module, module_text).unwrap();
        let closed = Workspace::new(
            &HashMap::from([(app_uri.clone(), app_text.to_owned())]),
            Some(&project),
            &app_uri,
            false,
        );
        std::fs::write(&manifest, format!("{manifest_text}\n")).unwrap();
        assert!(
            closed
                .response("textDocument/rename", &request)
                .unwrap_err()
                .contains("manifest changed")
        );
        std::fs::write(&app, &rewritten[&app_uri]).unwrap();
        std::fs::write(&module, &rewritten[&module_uri]).unwrap();
        let updated = fixture_project(
            &root,
            "金庫😀.ko",
            Some(("test/value@1", "value", "values.ko")),
            &manifest,
            &rewritten[&manifest_uri],
            "renamed",
        );
        assert!(
            EditorSnapshot::project(updated.graph.as_source().expect("source graph"), false)
                .is_complete()
        );
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn incomplete_documents_do_not_publish_rename_edits() {
        let uri = "file:///incomplete.ko";
        let text = "module Incomplete { fn run(int _ value) -> int { value + } }";
        let documents = HashMap::from([(uri.to_owned(), text.to_owned())]);
        let workspace = Workspace::new(&documents, None, uri, false);
        let position = text.find("value +").unwrap();
        let request = norito::json!({"params": {"textDocument": {"uri": uri}, "position": {"line": 0, "character": position}, "newName": "amount"}});
        assert!(workspace.response("textDocument/rename", &request).is_err());
    }
    struct SourceDirectory(PathBuf);
    impl SourceDirectory {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "kotodama-lsp-multifile-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&root).unwrap();
            Self(root.canonicalize().unwrap())
        }
        fn uri(&self, name: &str) -> String {
            lsp_path_file_uri(&self.0.join(name)).unwrap()
        }
    }
    impl Drop for SourceDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn multifile_unsaved_overlays_drive_navigation_rename_and_changed_edges() {
        let directory = SourceDirectory::new();
        let app = directory.uri("app.ko");
        let fragment = directory.uri("helpers.ko");
        let replacement = directory.uri("replacement.ko");
        let text = r#"seiyaku App { include "./helpers.ko"; view fn run() authorize(anyone) -> int { answer() } }"#;
        std::fs::write(directory.0.join("app.ko"), text).unwrap();
        let mut documents = HashMap::from([
            (app.clone(), text.into()),
            (fragment.clone(), "fn answer() -> int { 7 }".into()),
        ]);
        let project =
            lsp_local_source_project(&documents, Some(&app)).expect("unsaved declared fragment");
        let workspace = Workspace::new(&documents, Some(&project), &app, false)
            .with_versions(&HashMap::from([(app.clone(), 4), (fragment.clone(), 8)]));
        assert!(workspace.snapshot.is_complete());
        let request = norito::json!({"params":{"textDocument":{"uri":(app.clone())},"position":{"line":0,"character":(text.find("answer()").unwrap())},"newName":"value"}});
        let definition = workspace
            .response("textDocument/definition", &request)
            .unwrap();
        assert_eq!(
            definition
                .pointer("/uri")
                .and_then(norito::json::Value::as_str),
            Some(fragment.as_str())
        );
        let rename = workspace.response("textDocument/rename", &request).unwrap();
        assert_eq!(
            rename
                .pointer("/documentChanges")
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            2
        );
        let updated = text.replace("helpers.ko", "replacement.ko");
        documents.insert(app.clone(), updated.clone());
        documents.insert(replacement.clone(), "fn answer() -> int { 9 }".into());
        let workspace = Workspace::new(&documents, Some(&project), &app, false);
        assert!(workspace.snapshot.is_complete());
        let request = norito::json!({"params":{"textDocument":{"uri":(app.clone())},"position":{"line":0,"character":(updated.find("answer()").unwrap())}}});
        let definition = workspace
            .response("textDocument/definition", &request)
            .unwrap();
        assert_eq!(
            definition
                .pointer("/uri")
                .and_then(norito::json::Value::as_str),
            Some(replacement.as_str())
        );
        assert!(!workspace.uris.values().any(|uri| uri == &fragment));
    }
    #[test]
    fn multifile_missing_sources_publish_at_the_native_referring_directive() {
        let directory = SourceDirectory::new();
        std::fs::create_dir_all(directory.0.join("contracts")).unwrap();
        let app = directory.uri("contracts/app.ko");
        let fragment = directory.uri("parts.ko");
        let text = r#"seiyaku App { include "../parts.ko"; view fn run() authorize(anyone) -> int { 1 } }"#;
        let part = "// unsaved fragment\ninclude \"./missing.ko\";";
        let documents =
            HashMap::from([(app.clone(), text.into()), (fragment.clone(), part.into())]);
        let project =
            lsp_local_source_project_with_root(&documents, Some(&app), Some(&directory.0))
                .expect("retain broken graph root");
        assert_eq!(
            project
                .graph
                .as_source()
                .expect("source graph")
                .root
                .source_name,
            "contracts/app.ko"
        );
        assert!(lsp_project_with_open_overlays(&project, &documents).is_err());
        let driver = BuildDriver::new(
            CompilerSession::new(CompilerOptions::default()),
            "lsp-multifile-test",
        );
        let diagnostics = collect_lsp_workspace_diagnostics(&driver, &documents, Some(&project));
        let diagnostic = diagnostics[&fragment]
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "E_SOURCE_NOT_FOUND")
            .expect("missing dependency diagnostic");
        let span = diagnostic.primary_span.as_ref().unwrap();
        assert_eq!(span.source.as_deref(), Some(fragment.as_str()));
        assert_eq!(span.start.line, 2);
        assert!(diagnostics[&app].diagnostics.is_empty());
    }
    #[test]
    fn multifile_manifest_overlay_uses_unsaved_sources_before_loading_the_closure() {
        let directory = SourceDirectory::new();
        let app = directory.uri("app.ko");
        let manifest = directory.0.join("Musubi.toml");
        let manifest_uri = directory.uri("Musubi.toml");
        let disk = "seiyaku App { view fn run() authorize(anyone) -> int { 1 } }";
        let manifest_text = "[[contract]]\nname = \"app\"\npath = \"app.ko\"\n";
        std::fs::write(directory.0.join("app.ko"), disk).unwrap();
        std::fs::write(&manifest, manifest_text).unwrap();
        let project = fixture_project(
            &directory.0,
            "app.ko",
            None,
            &manifest,
            &format!("{manifest_text}\n"),
            "",
        );
        std::fs::write(
            directory.0.join("app.ko"),
            r#"seiyaku App { include "./missing.ko"; }"#,
        )
        .unwrap();
        let documents = HashMap::from([
            (
                app.clone(),
                r#"seiyaku App { include "./unsaved.ko"; view fn run() authorize(anyone) -> int { value() } }"#
                    .into(),
            ),
            (
                directory.uri("unsaved.ko"),
                "fn value() -> int { 3 }".into(),
            ),
            (manifest_uri, format!("{manifest_text}\n")),
        ]);
        let workspace = Workspace::new(&documents, Some(&project), &app, false);
        assert!(workspace.snapshot.is_complete());
        assert_eq!(workspace.snapshot.sources().count(), 2);
    }
    #[test]
    fn every_open_seiyaku_is_checked_as_its_own_local_graph() {
        // Several unrelated seiyaku in one directory, without a project manifest, as in a
        // folder of samples. One module is imported by two of them.
        let directory = SourceDirectory::new();
        let files = [
            (
                "counter.ko",
                "seiyaku Counter {\n    import \"./math.ko\" as shared;\n    state int value;\n    hajimari() {\n        value = shared::one();\n    }\n    view fn read() authorize(anyone) -> int { value }\n}\n",
            ),
            (
                "ledger.ko",
                "誓約 Ledger {\n    import \"./math.ko\" as shared;\n    view fn read() authorize(anyone) -> int { shared::one() }\n}\n",
            ),
            (
                "broken.ko",
                "seiyaku Broken {\n    view fn read() authorize(anyone) -> int {\n        return missing;\n    }\n}\n",
            ),
            (
                "math.ko",
                "module Math {\n    export fn one() -> int {\n        let unused = 2;\n        1\n    }\n}\n",
            ),
        ];
        for (name, text) in files {
            std::fs::write(directory.0.join(name), text).unwrap();
        }
        let documents = files
            .iter()
            .map(|(name, text)| (directory.uri(name), (*text).to_owned()))
            .collect::<HashMap<_, _>>();
        let driver = BuildDriver::new(
            CompilerSession::new(CompilerOptions::default()),
            "lsp-local-roots",
        );
        let diagnostics = collect_lsp_workspace_diagnostics(&driver, &documents, None);
        let codes = |name: &str| {
            diagnostics[&directory.uri(name)]
                .diagnostics
                .iter()
                .map(|diagnostic| diagnostic.code.clone())
                .collect::<Vec<_>>()
        };
        for name in ["counter.ko", "ledger.ko", "broken.ko", "math.ko"] {
            assert!(
                !codes(name)
                    .iter()
                    .any(|code| code == "E_MULTIPLE_SEIYAKU_ROOTS"),
                "{name}: {:?}",
                codes(name)
            );
        }
        assert!(codes("counter.ko").is_empty(), "{:?}", codes("counter.ko"));
        assert!(codes("ledger.ko").is_empty(), "{:?}", codes("ledger.ko"));
        // The unrelated seiyaku still reports its own error.
        assert_eq!(codes("broken.ko"), ["K2002"]);
        // The shared module is checked through both importers but reports its lint once.
        assert_eq!(codes("math.ko"), ["K5013"]);
        assert_eq!(
            lsp_local_source_projects_with_root(&documents, None, None, usize::MAX).len(),
            3
        );
    }
    fn request_at(uri: &str, text: &str, needle: &str, delta: usize) -> norito::json::Value {
        let offset = text.find(needle).expect("cursor needle") + delta;
        let line = text[..offset].matches('\n').count();
        let line_start = text[..offset].rfind('\n').map_or(0, |index| index + 1);
        let character = text[line_start..offset].encode_utf16().count();
        norito::json!({"params": {"textDocument": {"uri": uri}, "position": {"line": line, "character": character}, "context": {"includeDeclaration": true}}})
    }
    fn document_request(uri: &str) -> norito::json::Value {
        norito::json!({"params": {"textDocument": {"uri": uri}}})
    }
    fn labels(response: &norito::json::Value) -> Vec<String> {
        response
            .pointer("/items")
            .and_then(norito::json::Value::as_array)
            .expect("completion items")
            .iter()
            .filter_map(|item| item.get("label").and_then(norito::json::Value::as_str))
            .map(ToOwned::to_owned)
            .collect()
    }
    #[test]
    fn member_completion_works_mid_statement_and_lets_clients_filter() {
        let uri = "file:///scores.ko";
        let prefix = "seiyaku Scoreboard { permission CanBump; \n    state StateMap<int, int> Scores;\n    kotoage fn bump(int who) authorize(CanBump) {\n        ";
        for (statement, members) in [
            ("let x = Scores.", vec!["get", "contains"]),
            ("let x = Scores.g", vec!["get", "contains"]),
            ("var x = Scores.", vec!["get", "contains"]),
            ("let x = Scores.\n        return;", vec!["get", "contains"]),
            ("let v = Scores.get(who).", vec!["unwrap_or", "is_some"]),
            ("require(Scores.", vec!["get", "contains"]),
            ("require(Scores.)", vec!["get", "contains"]),
            ("require(Scores.);", vec!["get", "contains"]),
            ("return Scores.", vec!["get", "contains"]),
            (
                "Scores.get(who).\n        return;",
                vec!["unwrap_or", "is_some"],
            ),
            ("if (Scores.) {}", vec!["get", "contains"]),
            ("if Scores.", vec!["get", "contains"]),
            ("if Scores.c", vec!["get", "contains"]),
            ("for entry in Scores.", vec!["take", "page"]),
            ("helper(value: Scores.", vec!["get", "contains"]),
            (
                "helper(value: Scores.get(who).",
                vec!["unwrap_or", "is_some"],
            ),
            ("let x = Scores.;", vec!["get", "contains"]),
        ] {
            let text = format!(
                "{prefix}{statement}\n    }}\n    fn helper(int value) -> int {{ value }}\n}}\n"
            );
            let documents = HashMap::from([(uri.to_owned(), text.clone())]);
            let workspace = Workspace::new(&documents, None, uri, false);
            let dot = statement.rfind('.').expect("member access") + 1;
            let partial = statement[dot..]
                .chars()
                .take_while(char::is_ascii_alphanumeric)
                .count();
            let request = request_at(uri, &text, statement, dot + partial);
            let response = workspace
                .response("textDocument/completion", &request)
                .unwrap();
            assert_eq!(
                response.pointer("/isIncomplete"),
                Some(&norito::json::Value::from(false))
            );
            let found = labels(&response);
            for member in members {
                assert!(
                    found.iter().any(|label| label == member),
                    "`{statement}` offered {found:?}"
                );
            }
        }
    }
    #[test]
    fn completion_follows_position_and_offers_both_branded_spellings() {
        let uri = "file:///mixed.ko";
        let text = "誓約 Mixed { permission CanBump; \n    state int value;\n    始まり() {\n        value = 0;\n    }\n    \n    kotoage fn bump() authorize(CanBump) {\n        value = 1;\n        \n    }\n}\n";
        let documents = HashMap::from([(uri.to_owned(), text.to_owned())]);
        let workspace = Workspace::new(&documents, None, uri, false);
        let item_position = workspace
            .response(
                "textDocument/completion",
                &request_at(uri, text, "    \n    kotoage", 4),
            )
            .unwrap();
        let items = labels(&item_position);
        for expected in [
            "kotoage fn",
            "言挙げ fn",
            "hajimari",
            "始まり",
            "kaizen",
            "改善",
            "state",
            "view fn",
        ] {
            assert!(items.iter().any(|label| label == expected), "{items:?}");
        }
        for unexpected in ["return", "let", "seiyaku", "誓約", "crypto::sha256"] {
            assert!(!items.iter().any(|label| label == unexpected), "{items:?}");
        }
        let kanji = item_position
            .pointer("/items")
            .and_then(norito::json::Value::as_array)
            .unwrap()
            .iter()
            .find(|item| {
                item.get("label").and_then(norito::json::Value::as_str) == Some("言挙げ fn")
            })
            .unwrap();
        assert!(
            kanji
                .get("filterText")
                .and_then(norito::json::Value::as_str)
                .is_some_and(|filter| filter.contains("kotoage"))
        );
        assert!(
            kanji
                .pointer("/documentation/value")
                .and_then(norito::json::Value::as_str)
                .is_some_and(|text| text.contains("**kotoage**") && text.contains("**言挙げ**"))
        );
        let body = labels(
            &workspace
                .response(
                    "textDocument/completion",
                    &request_at(uri, text, "        \n    }\n}", 8),
                )
                .unwrap(),
        );
        for expected in ["let", "return", "value", "require", "int"] {
            assert!(body.iter().any(|label| label == expected), "{body:?}");
        }
        for unexpected in [
            "seiyaku", "誓約", "module", "import", "state", "bump", "hajimari",
        ] {
            assert!(!body.iter().any(|label| label == unexpected), "{body:?}");
        }
        let empty_uri = "file:///empty.ko";
        let empty = HashMap::from([(empty_uri.to_owned(), String::new())]);
        let top = labels(
            &Workspace::new(&empty, None, empty_uri, false)
                .response("textDocument/completion", &request_at(empty_uri, "", "", 0))
                .unwrap(),
        );
        assert_eq!(top, vec!["seiyaku", "誓約", "module"]);
    }
    #[test]
    fn hover_explains_branded_keywords_and_echoes_declaration_spellings() {
        let uri = "file:///counter.ko";
        let text = "誓約 Counter { permission CanBump; permission CanReset; \n    state int value;\n    始まり() {\n        value = 0;\n    }\n    言挙げ fn bump(int delta) authorize(CanBump) -> int {\n        value = value + delta;\n        value\n    }\n    kotoage fn reset() authorize(CanReset) {\n        value = 0;\n    }\n    view fn read() authorize(anyone) -> int { value }\n}\n";
        let documents = HashMap::from([(uri.to_owned(), text.to_owned())]);
        let workspace = Workspace::new(&documents, None, uri, false);
        let hover = |needle: &str, delta: usize| {
            workspace
                .response("textDocument/hover", &request_at(uri, text, needle, delta))
                .unwrap()
                .pointer("/contents/value")
                .and_then(norito::json::Value::as_str)
                .map(ToOwned::to_owned)
                .unwrap_or_default()
        };
        let seiyaku = hover("誓約", 0);
        assert!(seiyaku.contains("**seiyaku** / **誓約**"), "{seiyaku}");
        let documentation =
            |hover: String| hover.split_once("\n```\n").map(|(_, rest)| rest.to_owned());
        assert!(hover("言挙げ", 0).starts_with("```kotodama\n言挙げ\n```"));
        assert!(hover("kotoage", 0).starts_with("```kotodama\nkotoage\n```"));
        assert_eq!(
            documentation(hover("言挙げ", 0)),
            documentation(hover("kotoage", 0))
        );
        let bump = hover("bump", 0);
        assert!(
            bump.contains("言挙げ fn bump(int delta) authorize(CanBump) -> int"),
            "{bump}"
        );
        assert!(bump.contains("Authorization: callers need the declared permission `CanBump`."));
        let reset = hover("reset", 0);
        assert!(reset.contains("kotoage fn reset()"), "{reset}");
        let hook = hover("始まり", 0);
        assert!(hook.contains("```kotodama\n始まり()\n```"), "{hook}");
        assert!(hook.contains("CanInvokeContractEntrypoint"));
        assert!(hover("view", 0).contains("read-only"));
        assert!(hover("Counter", 0).contains("誓約 Counter"));
        for text in [seiyaku, bump, reset, hook] {
            assert!(!text.contains("Some(") && !text.contains("authorization: None"));
        }
    }
    #[test]
    fn document_features_cover_outline_folding_tokens_highlights_and_lenses() {
        let uri = "file:///features.ko";
        let text = "// Features.\n// Second line.\nseiyaku Features { permission CanSet; \n    state int value;\n    hajimari() {\n        value = 0;\n    }\n    言挙げ fn set(int next) authorize(CanSet) {\n        value = next;\n    }\n    #[test]\n    fn sets_value() {\n        test::assert(condition: true);\n    }\n}\n";
        let documents = HashMap::from([(uri.to_owned(), text.to_owned())]);
        let workspace = Workspace::new(&documents, None, uri, false);
        let symbols = workspace
            .response("textDocument/documentSymbol", &document_request(uri))
            .unwrap();
        let children = symbols
            .pointer("/0/children")
            .and_then(norito::json::Value::as_array)
            .expect("seiyaku children");
        assert!(children.iter().any(|child| {
            child.get("name").and_then(norito::json::Value::as_str) == Some("set")
                && child.get("detail").and_then(norito::json::Value::as_str)
                    == Some("言挙げ fn authorize(CanSet)")
        }));
        let folds = workspace
            .response("textDocument/foldingRange", &document_request(uri))
            .unwrap();
        let folds = folds.as_array().unwrap();
        assert!(folds.iter().any(|fold| {
            fold.get("kind").and_then(norito::json::Value::as_str) == Some("comment")
                && fold.get("startLine").and_then(norito::json::Value::as_u64) == Some(0)
        }));
        assert!(folds.iter().any(|fold| {
            fold.get("startLine").and_then(norito::json::Value::as_u64) == Some(2)
                && fold.get("endLine").and_then(norito::json::Value::as_u64) == Some(13)
        }));
        let tokens = workspace
            .response("textDocument/semanticTokens/full", &document_request(uri))
            .unwrap();
        let data = tokens
            .get("data")
            .and_then(norito::json::Value::as_array)
            .unwrap();
        assert_eq!(data.len() % 5, 0);
        let branded = SEMANTIC_TOKEN_TYPES
            .iter()
            .position(|name| *name == "brandedKeyword")
            .unwrap() as u64;
        // `seiyaku`, `hajimari` and `言挙げ` all use the one branded token type.
        assert_eq!(
            data.chunks(5)
                .filter(|token| token[3].as_u64() == Some(branded))
                .count(),
            3
        );
        let highlights = workspace
            .response(
                "textDocument/documentHighlight",
                &request_at(uri, text, "value;", 0),
            )
            .unwrap();
        assert_eq!(highlights.as_array().unwrap().len(), 3);
        let lenses = workspace
            .response("textDocument/codeLens", &document_request(uri))
            .unwrap();
        let lens = &lenses.as_array().unwrap()[0];
        assert_eq!(
            lens.pointer("/command/command")
                .and_then(norito::json::Value::as_str),
            Some("kotodama.runTest")
        );
        let arguments = lens
            .pointer("/command/arguments/0/args")
            .and_then(norito::json::Value::as_array)
            .unwrap()
            .iter()
            .filter_map(norito::json::Value::as_str)
            .collect::<Vec<_>>();
        assert_eq!(
            arguments[..5],
            ["test", "run", "--filter", "sets_value", "--exact"]
        );
        let workspace_symbols = workspace_symbol_response(&documents, None, false, "set");
        assert_eq!(
            workspace_symbols
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|symbol| symbol.get("name").and_then(norito::json::Value::as_str))
                .collect::<Vec<_>>(),
            vec!["CanSet", "set", "sets_value"]
        );
    }
    #[test]
    fn rename_refusals_name_the_blocking_diagnostic_and_ascii_rule() {
        let uri = "file:///blocked.ko";
        let text = "seiyaku Blocked {\n    state int value;\n    view fn read() authorize(anyone) -> int { value }\n}\n";
        let documents = HashMap::from([(uri.to_owned(), text.to_owned())]);
        let workspace = Workspace::new(&documents, None, uri, false);
        let mut request = request_at(uri, text, "read", 0);
        let error = workspace
            .response("textDocument/prepareRename", &request)
            .unwrap_err();
        assert!(error.contains("Rename is unavailable until"), "{error}");
        assert!(error.contains("hajimari"), "{error}");
        let fixed = text.replace(
            "    view fn",
            "    hajimari() {\n        value = 0;\n    }\n    view fn",
        );
        let documents = HashMap::from([(uri.to_owned(), fixed.clone())]);
        let workspace = Workspace::new(&documents, None, uri, false);
        request = request_at(uri, &fixed, "read", 0);
        if let Some(params) = request
            .get_mut("params")
            .and_then(norito::json::Value::as_object_mut)
        {
            params.insert("newName".into(), "読む".into());
        }
        let error = workspace
            .response("textDocument/rename", &request)
            .unwrap_err();
        assert!(error.contains("ASCII"), "{error}");
    }
    #[test]
    fn standalone_test_modules_check_in_test_mode_and_navigate_selectors() {
        let directory = SourceDirectory::new();
        std::fs::create_dir_all(directory.0.join("contracts")).unwrap();
        std::fs::create_dir_all(directory.0.join("tests")).unwrap();
        std::fs::write(directory.0.join("Musubi.toml"), "manifest-version = 1\n").unwrap();
        let contract_text = "seiyaku Club {\n    fn points(int coffees) -> int {\n        return coffees * 10;\n    }\n    view fn quote(int coffees) authorize(anyone) -> int {\n        return points(coffees: coffees);\n    }\n}\n";
        let test_text = "module ClubTests {\n    koto_test {\n        target: \"../contracts/club.ko\"\n    }\n\n    #[test]\n    fn quotes_points() {\n        let quoted = test::invoke_kotoage(\n            kotoage: \"quote\",\n            arguments: {coffees: 1},\n        );\n        test::assert_eq(actual: quoted, expected: 10);\n    }\n}\n";
        std::fs::write(directory.0.join("contracts/club.ko"), contract_text).unwrap();
        std::fs::write(directory.0.join("tests/club.test.ko"), test_text).unwrap();
        let contract = directory.uri("contracts/club.ko");
        let test = directory.uri("tests/club.test.ko");
        let documents = HashMap::from([(test.clone(), test_text.to_owned())]);
        let driver = BuildDriver::new(
            CompilerSession::new(CompilerOptions::default()),
            "lsp-test-mode",
        );
        let mut diagnostics = collect_lsp_workspace_diagnostics(&driver, &documents, None);
        apply_test_module_diagnostics(&mut diagnostics, &documents, false);
        assert!(
            diagnostics[&test].diagnostics.is_empty(),
            "{:?}",
            diagnostics[&test].diagnostics
        );
        let workspace = Workspace::new(&documents, None, &test, false);
        let definition = workspace
            .response(
                "textDocument/definition",
                &request_at(&test, test_text, "quote\"", 1),
            )
            .unwrap();
        assert_eq!(
            definition
                .pointer("/uri")
                .and_then(norito::json::Value::as_str),
            Some(contract.as_str())
        );
        let documents = HashMap::from([(contract.clone(), contract_text.to_owned())]);
        let workspace = Workspace::new(&documents, None, &contract, false);
        let references = workspace
            .response(
                "textDocument/references",
                &request_at(&contract, contract_text, "quote(", 0),
            )
            .unwrap();
        assert!(references.as_array().unwrap().iter().any(|location| {
            location.get("uri").and_then(norito::json::Value::as_str) == Some(test.as_str())
        }));
        let mut rename = request_at(&contract, contract_text, "quote(", 0);
        if let Some(params) = rename
            .get_mut("params")
            .and_then(norito::json::Value::as_object_mut)
        {
            params.insert("newName".into(), "estimate".into());
        }
        let edits = workspace.response("textDocument/rename", &rename).unwrap();
        assert!(
            edits
                .pointer("/documentChanges")
                .and_then(norito::json::Value::as_array)
                .unwrap()
                .iter()
                .any(|change| change
                    .pointer("/textDocument/uri")
                    .and_then(norito::json::Value::as_str)
                    == Some(test.as_str()))
        );
        // A broken test reports its own error in test mode, never E_TEST_ONLY_PRODUCTION.
        let broken = test_text.replace("expected: 10", "expected: missing");
        let documents = HashMap::from([(test.clone(), broken)]);
        let mut diagnostics = collect_lsp_workspace_diagnostics(&driver, &documents, None);
        apply_test_module_diagnostics(&mut diagnostics, &documents, false);
        assert!(!diagnostics[&test].diagnostics.is_empty());
        assert!(
            diagnostics[&test]
                .diagnostics
                .iter()
                .all(|diagnostic| diagnostic.code != "E_TEST_ONLY_PRODUCTION")
        );
        // Quick fixes of test-mode diagnostics edit the test document itself.
        let suffixed = test_text.replace("expected: 10", "expected: 10amt");
        let documents = HashMap::from([(test.clone(), suffixed)]);
        let mut diagnostics = collect_lsp_workspace_diagnostics(&driver, &documents, None);
        apply_test_module_diagnostics(&mut diagnostics, &documents, false);
        let fixes = diagnostics[&test]
            .diagnostics
            .iter()
            .flat_map(|diagnostic| diagnostic.fix.iter().chain(&diagnostic.alternative_fixes))
            .collect::<Vec<_>>();
        assert!(!fixes.is_empty(), "{:?}", diagnostics[&test].diagnostics);
        assert!(
            fixes
                .iter()
                .all(|fix| fix.span.source.as_deref() == Some(test.as_str()))
        );
    }
    #[test]
    fn code_actions_follow_the_requested_range_and_offer_both_spellings() {
        let session = CompilerSession::default();
        let uri = "file:///english.ko";
        let source = "contract Counter {\n    state int value;\n}\n";
        let actions = |range| {
            lsp_code_actions_from_bundle(
                collect_lsp_diagnostics(&session, uri, source),
                uri,
                source,
                range,
            )
            .as_array()
            .cloned()
            .unwrap_or_default()
        };
        let all = actions(None);
        let summary = all
            .iter()
            .map(|action| {
                (
                    action
                        .get("title")
                        .and_then(norito::json::Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    action
                        .get("isPreferred")
                        .and_then(norito::json::Value::as_bool)
                        .unwrap_or_default(),
                )
            })
            .collect::<Vec<_>>();
        assert!(
            summary.contains(&("Replace `contract` with `seiyaku`".to_owned(), true)),
            "{summary:?}"
        );
        assert!(
            summary.contains(&("Replace `contract` with `誓約`".to_owned(), false)),
            "{summary:?}"
        );
        let second_line = lsp_byte_range(
            source,
            &norito::json!({"start": {"line": 1, "character": 4}, "end": {"line": 1, "character": 9}}),
        )
        .expect("range");
        assert_eq!(
            &source[second_line.start as usize..second_line.end as usize],
            "state"
        );
        assert!(actions(Some(second_line)).is_empty());
        let first_line = lsp_byte_range(
            source,
            &norito::json!({"start": {"line": 0, "character": 0}, "end": {"line": 0, "character": 1}}),
        );
        assert_eq!(actions(first_line).len(), all.len());
    }
    #[test]
    fn served_code_actions_offer_both_branded_spellings_for_english_words() {
        // The server path: open documents are checked through the build driver, not the
        // single-source session used by `koto check`.
        let driver = BuildDriver::new(
            CompilerSession::new(CompilerOptions::default()),
            "lsp-code-actions",
        );
        let uri = "file:///english-entry.ko";
        let source = "seiyaku Counter {\n    state int value;\n    hajimari() { value = 0; }\n    entry fn bump() authorize(\"CanBump\") {\n        value = value + 1;\n    }\n}\n";
        let documents = HashMap::from([(uri.to_owned(), source.to_owned())]);
        let titles = |range: norito::json::Value| {
            lsp_project_code_action_items(&driver, &documents, None, uri, Some(&range), false)
                .as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .map(|action| {
                    (
                        action
                            .get("title")
                            .and_then(norito::json::Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        action
                            .get("isPreferred")
                            .and_then(norito::json::Value::as_bool)
                            .unwrap_or_default(),
                    )
                })
                .collect::<Vec<_>>()
        };
        let on_entry = titles(
            norito::json!({"start": {"line": 3, "character": 4}, "end": {"line": 3, "character": 9}}),
        );
        // `authorize(...)` is present, so the branded entrypoint keyword is preferred and both
        // of its spellings are offered.
        assert!(
            on_entry.contains(&("Replace `entry` with `kotoage`".to_owned(), true)),
            "{on_entry:?}"
        );
        assert!(
            on_entry.contains(&("Replace `entry` with `言挙げ`".to_owned(), false)),
            "{on_entry:?}"
        );
        assert!(
            titles(norito::json!({"start": {"line": 1, "character": 0}, "end": {"line": 1, "character": 3}}))
                .is_empty()
        );
    }
    #[test]
    fn lsp_messages_drop_rendered_excerpts_but_keep_prose_notes() {
        assert!(is_rendered_source_excerpt("contract Counter {\n^"));
        assert!(is_rendered_source_excerpt("    ledger::\n    ^~~~"));
        assert!(!is_rendered_source_excerpt("the hook runs once"));
        assert!(!is_rendered_source_excerpt("first line\nsecond line"));
        let mut diagnostic = Diagnostic::error(
            "K1001",
            DiagnosticPhase::Parse,
            "expected `;`, found identifier `ledger`",
            None,
        );
        diagnostic.notes = vec![
            "        ledger::\n        ^".to_owned(),
            "statements end with `;`".to_owned(),
        ];
        diagnostic.help = Some("insert `;`".to_owned());
        let message = lsp_diagnostic_value(&diagnostic, "")
            .get("message")
            .and_then(norito::json::Value::as_str)
            .unwrap()
            .to_owned();
        assert_eq!(
            message,
            "expected `;`, found identifier `ledger`\n\nnote: statements end with `;`\n\nhelp: insert `;`"
        );
    }
}
