//! Shared bounded language-server engine over caller-owned source graphs.
mod editor_lsp;
mod lsp_transport;
use crate::diagnostics::{documentation_url, leveled_lint, remap_project_diagnostic_sources};
use kotodama_lang::{
    compiler::CompilerOptions,
    diagnostic::{Diagnostic, DiagnosticBundle, DiagnosticPhase, SourcePosition, SourceSpan},
    driver::{
        BuildDriver, BuildError, LoadedProjectGraph, LoadedSourceProject, ProjectSourceKey,
        load_source_project, logical_source_name, read_source_file,
    },
    formatter::format_source,
    linker::SourceModuleUnit,
    session::{CompilerSession, LintConfig},
    source::{FrontendBudget, MAX_SOURCE_BYTES, SourceFile, SourceId},
};
#[cfg(test)]
use kotodama_lang::{
    diagnostic::{DiagnosticLabel, Severity},
    lexer::{V1_KEYWORDS, V1_OPERATORS},
    session::CompileRequest,
};
#[cfg(test)]
use kotodama_surface::{
    builtins::{Builtin, BuiltinSurface},
    source_policy::{V1_LIST_MEMBER_NAMES, V1_ROUNDING_PATHS, V1_SOURCE_TYPE_NAMES, V1_SUM_PATHS},
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    io::{BufRead, Write},
    path::{Path, PathBuf},
};
fn lint_diagnostic(warning: &kotodama_lang::lint::LintWarning, path: &Path) -> Diagnostic {
    warning.to_diagnostic(
        &path.display().to_string(),
        None,
        kotodama_lang::i18n::detect_language(),
    )
}
fn format_source_text(source: &str, source_name: Option<&str>) -> Result<String, String> {
    let file = SourceFile::new(SourceId(0), source_name.unwrap_or("<source>"), source);
    format_source(&file, FrontendBudget::v1()).map_err(|diagnostics| diagnostics.render_human())
}
// A source byte may expand to six escaped JSON bytes; all queues remain bounded.
const MAX_LSP_MESSAGE_BYTES: usize = MAX_SOURCE_BYTES * 6 + 256 * 1024;
const MAX_LSP_HEADER_LINE_BYTES: usize = 8 * 1024;
const MAX_LSP_HEADERS: usize = 32;
const MAX_LSP_URI_BYTES: usize = 8 * 1024;
const MAX_LSP_OPEN_DOCUMENTS: usize = 256;
const MAX_LSP_DOCUMENT_BYTES: usize = 64 * MAX_SOURCE_BYTES;
#[cfg(test)]
const V1_CONTEXTUAL_COMPLETIONS: &[(&str, u64)] = &[("json", 14), ("div_round", 2)];

/// One named build target and its authenticated, captured source graph.
#[derive(Clone, Debug)]
pub struct ProjectTarget {
    /// Stable target selector displayed in diagnostics and selected by `--contract`.
    pub name: String,
    /// Complete source graph, physical identities and editable manifest snapshots.
    pub project: LoadedSourceProject,
    /// Exact package command context for test lenses, absent for standalone sources.
    pub test_context: Option<TestContext>,
}
/// Locked package context carried by an editor test action.
#[derive(Clone, Debug)]
pub struct TestContext {
    /// Canonical workspace manifest path used by builds and tests.
    pub manifest_path: PathBuf,
    /// Namespaced package selector.
    pub package: String,
    /// Manifest contract target name.
    pub contract: String,
    /// Explicit named network selected by the project server, if any.
    pub network: Option<String>,
    /// Canonical explicit public configuration path, if any; never credential contents.
    pub config_path: Option<PathBuf>,
}
/// One reload of the caller's canonical project contract.
#[derive(Clone, Debug, Default)]
pub struct ProjectSnapshot {
    /// Every selected workspace contract or library target, in deterministic order.
    pub targets: Vec<ProjectTarget>,
    /// Explicit or manifest-selected target for otherwise ambiguous semantic requests.
    pub selected_target: Option<String>,
}
/// Supplies project authority without imposing a second persisted manifest format.
pub trait ProjectProvider {
    /// Resolve the current project using these unsaved canonical-path text overlays.
    ///
    /// The provider must preserve locked package identities, use the same resolution rules as
    /// builds, and capture exact local manifest tokens. Cached remote dependencies are immutable.
    ///
    /// # Errors
    /// Returns a diagnostic message when the current manifests, overlays or locked graph cannot
    /// be resolved into a complete project snapshot.
    fn reload(&mut self, overlays: &BTreeMap<PathBuf, String>) -> Result<ProjectSnapshot, String>;
}
/// Compiler and standalone-source context shared by the server and its caller.
#[derive(Clone, Debug)]
pub struct ServerOptions {
    /// Explicit standalone source root, when no project provider is supplied.
    pub source_root: Option<PathBuf>,
    /// Enable zero-knowledge source features.
    pub zk_enabled: bool,
    /// Canonical account network discriminant used by compilation.
    pub chain_discriminant: u16,
}
impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            source_root: None,
            zk_enabled: false,
            chain_discriminant: CompilerOptions::default().chain_discriminant,
        }
    }
}
/// Serve caller-resolved projects over standard input and output.
///
/// # Errors
/// Returns an error for invalid server options, failure to start the input reader, or a
/// transport or response-writing failure while serving requests.
pub fn run_project_stdio(
    mut options: ServerOptions,
    provider: Option<&mut dyn ProjectProvider>,
) -> Result<(), String> {
    if options.chain_discriminant == 0 {
        return Err("account chain discriminant must be non-zero".into());
    }
    if let Some(root) = &options.source_root {
        let canonical = root
            .canonicalize()
            .map_err(|error| format!("read source root `{}`: {error}", root.display()))?;
        if !canonical.is_dir() {
            return Err(format!(
                "source root `{}` must be a directory",
                root.display()
            ));
        }
        options.source_root = Some(canonical);
    }
    let inbox = lsp_transport::Inbox::new();
    let reader = inbox.clone();
    let _reader = std::thread::Builder::new()
        .name("kotodama-lsp-input".into())
        .spawn(move || reader.read_from(&mut std::io::stdin().lock()))
        .map_err(|error| format!("start LSP input reader: {error}"))?;
    let result =
        language_server_dispatch(&inbox, &mut std::io::stdout().lock(), provider, &options);
    inbox.close();
    result
}
fn reload_projects(
    provider: &mut Option<&mut dyn ProjectProvider>,
    documents: &HashMap<String, String>,
    options: &ServerOptions,
) -> Result<ProjectSnapshot, String> {
    if let Some(provider) = provider.as_deref_mut() {
        let overlays = documents
            .iter()
            .filter_map(|(uri, text)| lsp_file_uri_path(uri).map(|path| (path, text.clone())))
            .collect();
        let snapshot = provider.reload(&overlays)?;
        let mut names = BTreeSet::new();
        if snapshot
            .targets
            .iter()
            .any(|target| !names.insert(&target.name))
        {
            return Err("Project provider returned duplicate contract target selectors".into());
        }
        if let Some(selected) = &snapshot.selected_target
            && !names.contains(selected)
        {
            return Err(format!(
                "Selected contract `{selected}` is absent from the project"
            ));
        }
        Ok(snapshot)
    } else {
        Ok(ProjectSnapshot {
            targets: lsp_local_source_projects_with_root(
                documents,
                None,
                options.source_root.as_deref(),
                usize::MAX,
            )
            .into_iter()
            .map(|project| ProjectTarget {
                name: project
                    .graph
                    .as_source()
                    .expect("standalone graph")
                    .root
                    .source_name
                    .clone(),
                project,
                test_context: None,
            })
            .collect(),
            selected_target: None,
        })
    }
}
fn selected_project<'a>(
    snapshot: &'a ProjectSnapshot,
    uri: &str,
    documents: &HashMap<String, String>,
) -> Result<Option<&'a LoadedSourceProject>, String> {
    let Some(mut path) = lsp_file_uri_path(uri) else {
        return Ok(None);
    };
    let test_target = documents
        .get(uri)
        .and_then(|source| kotodama_lang::editor::declared_test_target(source));
    if let Some(target) = &test_target
        && let Some(parent) = path.parent()
    {
        let target = parent.join(target);
        path = target.canonicalize().unwrap_or(target);
    }
    let candidates = snapshot
        .targets
        .iter()
        .filter(|target| {
            if test_target.is_some() {
                target.project.graph.as_source().is_some_and(|graph| {
                    target.project.source_paths.get(&ProjectSourceKey {
                        package_identity: None,
                        source_name: graph.root.source_name.clone(),
                    }) == Some(&path)
                })
            } else {
                target
                    .project
                    .source_paths
                    .values()
                    .any(|source| source == &path)
            }
        })
        .collect::<Vec<_>>();
    if let Some(selected) = &snapshot.selected_target {
        return candidates
            .iter()
            .find(|target| &target.name == selected)
            .map(|target| Some(&target.project))
            .ok_or_else(|| format!(
                "Selected contract target `{selected}` does not own {} `{}`. Select its declared target with `musubi lsp --contract <target>` or open this source in its own project.",
                if test_target.is_some() { "the test module's exact contract root" } else { "source" },
                path.display(),
            ));
    }
    if test_target.is_some() && candidates.is_empty() && !snapshot.targets.is_empty() {
        return Err(format!(
            "Test target `{}` is not an exact contract root in this project. Set `koto_test.target` to a declared contract root or open the target's own project.",
            path.display(),
        ));
    }
    // A library's own target supplies the same nominal identity when contracts consume it.
    // An unowned companion shared by contract roots still has a different semantic scope.
    let owners = candidates
        .iter()
        .flat_map(|target| {
            target
                .project
                .source_paths
                .iter()
                .filter(|(_, source)| *source == &path)
                .map(|(key, _)| key.package_identity.clone())
        })
        .collect::<BTreeSet<_>>();
    if owners.len() == 1
        && let Some(Some(owner)) = owners.first()
    {
        let library = candidates.iter().find(|target| matches!(&target.project.graph, LoadedProjectGraph::Package(graph) if &graph.package.identity == owner));
        if let Some(library) = library {
            return Ok(Some(&library.project));
        }
    }
    match candidates.as_slice() {
        [] => Ok(None),
        [target] => Ok(Some(&target.project)),
        _ => Err(format!(
            "Source belongs to multiple contract targets: {}. Select one with `musubi lsp --contract <target>`.",
            candidates
                .iter()
                .map(|target| target.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}
fn language_server_dispatch(
    inbox: &lsp_transport::Inbox,
    transport_output: &mut impl Write,
    mut provider: Option<&mut dyn ProjectProvider>,
    options: &ServerOptions,
) -> Result<(), String> {
    let _chain_discriminant = iroha_data_model::account::address::ChainDiscriminantGuard::enter(
        options.chain_discriminant,
    );
    let zk_enabled = options.zk_enabled;
    let mut projects = reload_projects(&mut provider, &HashMap::new(), options)?;
    let mut project_error: Option<String> = None;
    let mut documents = HashMap::<String, String>::new();
    let mut versions = HashMap::<String, i64>::new();
    let mut published_diagnostic_uris = BTreeSet::new();
    let mut editor_cache = HashMap::<String, editor_lsp::Workspace>::new();
    let session = CompilerSession::new(CompilerOptions {
        force_zk: zk_enabled,
        chain_discriminant: options.chain_discriminant,
        ..CompilerOptions::default()
    });
    let driver = BuildDriver::new(session, "koto-lsp");
    while let Some(pending) = inbox.next()? {
        if inbox.reject_before_analysis(&pending, transport_output)? {
            continue;
        }
        let message = &pending.message;
        // Keep the compiler and immutable semantic workspace on this dispatcher thread.
        // The input thread can invalidate work while this operation is being analyzed.
        let mut output = Vec::new();
        let mut next_diagnostic_uris = None;
        let method = message
            .get("method")
            .and_then(norito::json::Value::as_str)
            .map(ToOwned::to_owned);
        let id = message.get("id").cloned();
        match method.as_deref() {
            Some("initialize") => {
                write_lsp_response(&mut output, id, lsp_initialize_result())?;
            }
            Some("shutdown") => {
                write_lsp_response(&mut output, id, norito::json::Value::Null)?;
            }
            Some("exit") => return Ok(()),
            Some("textDocument/didOpen") => {
                if let (Some(uri), Some(text)) = (
                    message
                        .pointer("/params/textDocument/uri")
                        .and_then(norito::json::Value::as_str),
                    message
                        .pointer("/params/textDocument/text")
                        .and_then(norito::json::Value::as_str),
                ) {
                    let version = message
                        .pointer("/params/textDocument/version")
                        .and_then(norito::json::Value::as_i64);
                    if let Some(version) = version
                        && versions
                            .get(uri)
                            .is_some_and(|previous| *previous >= version)
                    {
                        continue;
                    }
                    editor_cache.clear();
                    if let Err(message) = store_lsp_document(&mut documents, uri, text) {
                        publish_lsp_notification(
                            &mut output,
                            "window/showMessage",
                            json_object(vec![
                                ("type", norito::json::Value::from(1_u64)),
                                ("message", norito::json::Value::from(message)),
                            ]),
                        )?;
                    }
                    if documents.contains_key(uri) {
                        if let Some(version) = version {
                            versions.insert(uri.to_owned(), version);
                        }
                    } else {
                        versions.remove(uri);
                    }
                    match reload_projects(&mut provider, &documents, options) {
                        Ok(snapshot) => {
                            projects = snapshot;
                            project_error = None;
                        }
                        Err(error) => {
                            projects = ProjectSnapshot::default();
                            project_error = Some(error.clone());
                            publish_lsp_notification(
                                &mut output,
                                "window/showMessage",
                                json_object(vec![
                                    ("type", 1_u64.into()),
                                    ("message", error.into()),
                                ]),
                            )?;
                        }
                    }
                    if inbox.is_current(&pending) {
                        next_diagnostic_uris = Some(publish_lsp_project_diagnostics(
                            &mut output,
                            &driver,
                            &documents,
                            ProjectDiagnosticContext {
                                snapshot: &projects,
                                options,
                                error: project_error.as_deref(),
                            },
                            &versions,
                            &published_diagnostic_uris,
                        )?);
                    }
                }
            }
            Some("textDocument/didChange") => {
                if let (Some(uri), Some(text)) = (
                    message
                        .pointer("/params/textDocument/uri")
                        .and_then(norito::json::Value::as_str),
                    message
                        .pointer("/params/contentChanges/0/text")
                        .and_then(norito::json::Value::as_str),
                ) {
                    let version = message
                        .pointer("/params/textDocument/version")
                        .and_then(norito::json::Value::as_i64);
                    if let Some(version) = version
                        && versions
                            .get(uri)
                            .is_some_and(|previous| *previous >= version)
                    {
                        continue;
                    }
                    editor_cache.clear();
                    if let Err(message) = store_lsp_document(&mut documents, uri, text) {
                        publish_lsp_notification(
                            &mut output,
                            "window/showMessage",
                            json_object(vec![
                                ("type", norito::json::Value::from(1_u64)),
                                ("message", norito::json::Value::from(message)),
                            ]),
                        )?;
                    }
                    if documents.contains_key(uri) {
                        if let Some(version) = version {
                            versions.insert(uri.to_owned(), version);
                        }
                    } else {
                        versions.remove(uri);
                    }
                    match reload_projects(&mut provider, &documents, options) {
                        Ok(snapshot) => {
                            projects = snapshot;
                            project_error = None;
                        }
                        Err(error) => {
                            projects = ProjectSnapshot::default();
                            project_error = Some(error.clone());
                            publish_lsp_notification(
                                &mut output,
                                "window/showMessage",
                                json_object(vec![
                                    ("type", 1_u64.into()),
                                    ("message", error.into()),
                                ]),
                            )?;
                        }
                    }
                    if inbox.is_current(&pending) {
                        next_diagnostic_uris = Some(publish_lsp_project_diagnostics(
                            &mut output,
                            &driver,
                            &documents,
                            ProjectDiagnosticContext {
                                snapshot: &projects,
                                options,
                                error: project_error.as_deref(),
                            },
                            &versions,
                            &published_diagnostic_uris,
                        )?);
                    }
                }
            }
            Some("textDocument/didClose") => {
                if let Some(uri) = message
                    .pointer("/params/textDocument/uri")
                    .and_then(norito::json::Value::as_str)
                {
                    documents.remove(uri);
                    versions.remove(uri);
                    editor_cache.clear();
                    match reload_projects(&mut provider, &documents, options) {
                        Ok(snapshot) => {
                            projects = snapshot;
                            project_error = None;
                        }
                        Err(error) => {
                            projects = ProjectSnapshot::default();
                            project_error = Some(error.clone());
                            publish_lsp_notification(
                                &mut output,
                                "window/showMessage",
                                json_object(vec![
                                    ("type", 1_u64.into()),
                                    ("message", error.into()),
                                ]),
                            )?;
                        }
                    }
                    if inbox.is_current(&pending) {
                        next_diagnostic_uris = Some(publish_lsp_project_diagnostics(
                            &mut output,
                            &driver,
                            &documents,
                            ProjectDiagnosticContext {
                                snapshot: &projects,
                                options,
                                error: project_error.as_deref(),
                            },
                            &versions,
                            &published_diagnostic_uris,
                        )?);
                    }
                }
            }
            Some(
                method @ ("textDocument/completion"
                | "textDocument/hover"
                | "textDocument/signatureHelp"
                | "textDocument/definition"
                | "textDocument/references"
                | "textDocument/documentHighlight"
                | "textDocument/documentSymbol"
                | "textDocument/foldingRange"
                | "textDocument/semanticTokens/full"
                | "textDocument/codeLens"
                | "textDocument/prepareRename"
                | "textDocument/rename"),
            ) => {
                let uri = message
                    .pointer("/params/textDocument/uri")
                    .and_then(norito::json::Value::as_str)
                    .unwrap_or("");
                if let Some(error) = &project_error {
                    write_lsp_error(&mut output, id, -32602, error)?;
                    inbox.complete(&pending, transport_output, &output)?;
                    continue;
                }
                let project = match selected_project(&projects, uri, &documents) {
                    Ok(project) => project,
                    Err(error) => {
                        write_lsp_error(&mut output, id, -32602, &error)?;
                        inbox.complete(&pending, transport_output, &output)?;
                        continue;
                    }
                };
                // A locked graph may span every open URI. Retain one bounded graph snapshot,
                // rather than duplicating the full graph once for each queried document.
                editor_cache.retain(|key, _| key == uri);
                let workspace = editor_cache.entry(uri.to_owned()).or_insert_with(|| {
                    editor_lsp::Workspace::new(&documents, project, uri, zk_enabled)
                        .with_versions(&versions)
                });
                match workspace.response(method, message) {
                    Ok(mut result) => {
                        if method == "textDocument/codeLens" {
                            let context = project
                                .and_then(|project| {
                                    projects.targets.iter().find(|target| {
                                        std::ptr::eq(&raw const target.project, project)
                                    })
                                })
                                .and_then(|target| target.test_context.as_ref());
                            project_test_lenses(&mut result, context, options);
                        }
                        write_lsp_response(&mut output, id, result)?;
                    }
                    Err(error) => write_lsp_error(&mut output, id, -32602, &error)?,
                }
            }
            Some("workspace/didChangeWatchedFiles" | "textDocument/didSave") => {
                editor_cache.clear();
                match reload_projects(&mut provider, &documents, options) {
                    Ok(snapshot) => {
                        projects = snapshot;
                        project_error = None;
                    }
                    Err(error) => {
                        projects = ProjectSnapshot::default();
                        project_error = Some(error.clone());
                        publish_lsp_notification(
                            &mut output,
                            "window/showMessage",
                            json_object(vec![("type", 1_u64.into()), ("message", error.into())]),
                        )?;
                    }
                }
                if inbox.is_current(&pending) {
                    next_diagnostic_uris = Some(publish_lsp_project_diagnostics(
                        &mut output,
                        &driver,
                        &documents,
                        ProjectDiagnosticContext {
                            snapshot: &projects,
                            options,
                            error: project_error.as_deref(),
                        },
                        &versions,
                        &published_diagnostic_uris,
                    )?);
                }
            }
            Some("workspace/symbol") => {
                let query = message
                    .pointer("/params/query")
                    .and_then(norito::json::Value::as_str)
                    .unwrap_or("");
                let symbols = norito::json::Value::Array(
                    projects
                        .targets
                        .iter()
                        .flat_map(|target| {
                            editor_lsp::workspace_symbol_response(
                                &documents,
                                Some(&target.project),
                                zk_enabled,
                                query,
                            )
                            .as_array()
                            .cloned()
                            .unwrap_or_default()
                        })
                        .collect(),
                );
                write_lsp_response(&mut output, id, symbols)?;
            }
            Some("textDocument/codeAction") => {
                if let Some(error) = &project_error {
                    write_lsp_error(&mut output, id, -32602, error)?;
                    inbox.complete(&pending, transport_output, &output)?;
                    continue;
                }

                let uri = message
                    .pointer("/params/textDocument/uri")
                    .and_then(norito::json::Value::as_str)
                    .unwrap_or("");
                let project = match selected_project(&projects, uri, &documents) {
                    Ok(project) => project,
                    Err(error) => {
                        write_lsp_error(&mut output, id, -32602, &error)?;
                        inbox.complete(&pending, transport_output, &output)?;
                        continue;
                    }
                };
                let actions = if documents.contains_key(uri) {
                    lsp_project_code_action_items(
                        &driver,
                        &documents,
                        project,
                        uri,
                        message.pointer("/params/range"),
                        zk_enabled,
                    )
                } else {
                    norito::json::Value::Array(Vec::new())
                };
                write_lsp_response(&mut output, id, actions)?;
            }
            Some("textDocument/formatting") => {
                let edits = message
                    .pointer("/params/textDocument/uri")
                    .and_then(norito::json::Value::as_str)
                    .and_then(|uri| documents.get(uri))
                    .map_or_else(Vec::new, |source| {
                        let Ok(formatted) = format_source_text(source, None) else {
                            return Vec::new();
                        };
                        if formatted == source.as_str() {
                            Vec::new()
                        } else {
                            vec![json_object(vec![
                                (
                                    "range",
                                    json_object(vec![
                                        ("start", lsp_position(0_u64, 0_u64)),
                                        ("end", lsp_position(u32::MAX, 0_u64)),
                                    ]),
                                ),
                                ("newText", norito::json::Value::from(formatted)),
                            ])]
                        }
                    });
                write_lsp_response(&mut output, id, norito::json::Value::Array(edits))?;
            }
            Some(_) if id.is_some() => {
                write_lsp_error(&mut output, id, -32601, "method not found")?;
            }
            Some(_) | None => {}
        }
        if inbox.complete(&pending, transport_output, &output)?
            && let Some(uris) = next_diagnostic_uris
        {
            published_diagnostic_uris = uris;
        }
    }
    Ok(())
}
fn project_test_lenses(
    result: &mut norito::json::Value,
    context: Option<&TestContext>,
    options: &ServerOptions,
) {
    let Some(lenses) = result.as_array_mut() else {
        return;
    };
    for lens in lenses {
        let Some(command) = lens
            .get_mut("command")
            .and_then(norito::json::Value::as_object_mut)
        else {
            continue;
        };
        let Some(argument) = command
            .get("arguments")
            .and_then(norito::json::Value::as_array)
            .and_then(|args| args.first())
        else {
            continue;
        };
        let (Some(uri), Some(name)) = (
            argument.get("uri").and_then(norito::json::Value::as_str),
            argument.get("name").and_then(norito::json::Value::as_str),
        ) else {
            continue;
        };
        let mut payload = context.map_or_else(
            || {
                let mut payload = argument.clone();
                if let Some(object) = payload.as_object_mut() {
                    object.insert("tool".into(), "koto".into());
                }
                payload
            },
            |context| {
                let manifest = context.manifest_path.to_string_lossy();
                let args = [
                    "test",
                    "--manifest-path",
                    manifest.as_ref(),
                    "--package",
                    context.package.as_str(),
                    "--contract",
                    context.contract.as_str(),
                    "--filter",
                    name,
                    "--exact",
                ]
                .into_iter()
                .map(norito::json::Value::from)
                .collect();
                json_object(vec![
                    ("tool", "musubi".into()),
                    ("uri", uri.into()),
                    ("name", name.into()),
                    ("manifestPath", manifest.as_ref().into()),
                    ("package", context.package.as_str().into()),
                    ("contract", context.contract.as_str().into()),
                    (
                        "network",
                        context
                            .network
                            .as_deref()
                            .map_or(norito::json::Value::Null, Into::into),
                    ),
                    (
                        "configPath",
                        context
                            .config_path
                            .as_ref()
                            .map_or(norito::json::Value::Null, |path| {
                                path.to_string_lossy().as_ref().into()
                            }),
                    ),
                    ("args", norito::json::Value::Array(args)),
                ])
            },
        );
        if let Some(object) = payload.as_object_mut() {
            object.insert(
                "chainDiscriminant".into(),
                u64::from(options.chain_discriminant).into(),
            );
            object.insert("zk".into(), options.zk_enabled.into());
            if let Some(args) = object
                .get_mut("args")
                .and_then(norito::json::Value::as_array_mut)
            {
                args.push("--chain-discriminant".into());
                args.push(options.chain_discriminant.to_string().into());
                if options.zk_enabled {
                    args.push("--zk".into());
                }
                if let Some(context) = context {
                    args.push("--locked".into());
                    args.push("--offline".into());
                    if let Some(network) = &context.network {
                        args.push("--network".into());
                        args.push(network.as_str().into());
                    }
                    if let Some(path) = &context.config_path {
                        args.push("--config".into());
                        args.push(path.to_string_lossy().as_ref().into());
                    }
                }
            }
        }
        command.insert(
            "arguments".into(),
            norito::json::Value::Array(vec![payload]),
        );
    }
}
fn store_lsp_document(
    documents: &mut HashMap<String, String>,
    uri: &str,
    source: &str,
) -> Result<(), String> {
    if uri.len() > MAX_LSP_URI_BYTES {
        return Err(format!(
            "Kotodama document URI exceeds the {MAX_LSP_URI_BYTES}-byte language-server limit"
        ));
    }
    if source.len() > MAX_SOURCE_BYTES {
        documents.remove(uri);
        return Err(format!(
            "Kotodama document `{uri}` exceeds the {MAX_SOURCE_BYTES}-byte V1 source limit"
        ));
    }
    let previous_bytes = documents.get(uri).map_or(0, String::len);
    let total_bytes = documents
        .values()
        .fold(0_usize, |total, value| total.saturating_add(value.len()))
        .saturating_sub(previous_bytes)
        .saturating_add(source.len());
    let document_count = documents
        .len()
        .saturating_add(usize::from(!documents.contains_key(uri)));
    if document_count > MAX_LSP_OPEN_DOCUMENTS || total_bytes > MAX_LSP_DOCUMENT_BYTES {
        documents.remove(uri);
        return Err(format!(
            "Kotodama language server workspace limit reached ({MAX_LSP_OPEN_DOCUMENTS} documents/{MAX_LSP_DOCUMENT_BYTES} bytes); close unused documents"
        ));
    }
    documents.insert(uri.to_owned(), source.to_owned());
    Ok(())
}
fn read_bounded_lsp_header_line(
    input: &mut impl BufRead,
    line: &mut Vec<u8>,
) -> Result<usize, String> {
    line.clear();
    loop {
        let (consumed, terminated) = {
            let available = input
                .fill_buf()
                .map_err(|error| format!("read LSP header: {error}"))?;
            if available.is_empty() {
                return Ok(line.len());
            }
            let terminated_at = available.iter().position(|byte| *byte == b'\n');
            let consumed = terminated_at.map_or(available.len(), |index| index + 1);
            if line.len().saturating_add(consumed) > MAX_LSP_HEADER_LINE_BYTES {
                return Err(format!(
                    "LSP header line exceeds the {MAX_LSP_HEADER_LINE_BYTES}-byte limit"
                ));
            }
            line.extend_from_slice(&available[..consumed]);
            (consumed, terminated_at.is_some())
        };
        input.consume(consumed);
        if terminated {
            return Ok(line.len());
        }
    }
}
#[cfg(test)]
fn read_lsp_message(input: &mut impl BufRead) -> Result<Option<norito::json::Value>, String> {
    read_lsp_message_frame(input).map(|frame| frame.map(|(message, _)| message))
}
fn read_lsp_message_frame(
    input: &mut impl BufRead,
) -> Result<Option<(norito::json::Value, usize)>, String> {
    let mut content_length = None;
    let mut line = Vec::new();
    for _ in 0..MAX_LSP_HEADERS {
        let read = read_bounded_lsp_header_line(input, &mut line)?;
        if read == 0 {
            return if content_length.is_none() {
                Ok(None)
            } else {
                Err("unexpected EOF before the LSP header terminator".to_owned())
            };
        }
        let line =
            std::str::from_utf8(&line).map_err(|_| "LSP headers must be valid UTF-8".to_owned())?;
        let header = line.trim_end_matches(['\r', '\n']);
        if header.is_empty() {
            break;
        }
        let (name, raw) = header
            .split_once(':')
            .ok_or_else(|| "malformed LSP header; expected `name: value`".to_owned())?;
        if name.eq_ignore_ascii_case("Content-Length") {
            if content_length.is_some() {
                return Err("duplicate LSP Content-Length header".to_owned());
            }
            content_length = Some(
                raw.trim()
                    .parse::<usize>()
                    .map_err(|_| "invalid LSP Content-Length".to_owned())?,
            );
        }
    }
    if !line.ends_with(b"\n") || !line.iter().all(|byte| matches!(byte, b'\r' | b'\n')) {
        return Err(format!(
            "LSP request exceeds the {MAX_LSP_HEADERS}-header limit"
        ));
    }
    let length = content_length.ok_or_else(|| "missing LSP Content-Length".to_owned())?;
    if length > MAX_LSP_MESSAGE_BYTES {
        return Err(format!(
            "LSP message exceeds the {MAX_LSP_MESSAGE_BYTES}-byte limit"
        ));
    }
    let mut body = vec![0_u8; length];
    input
        .read_exact(&mut body)
        .map_err(|error| format!("read LSP message: {error}"))?;
    norito::json::from_slice(&body)
        .map(|message| Some((message, length)))
        .map_err(|error| format!("decode LSP JSON: {error}"))
}
fn write_lsp_message(output: &mut impl Write, message: &norito::json::Value) -> Result<(), String> {
    let body =
        norito::json::to_string(message).map_err(|error| format!("encode LSP JSON: {error}"))?;
    write!(output, "Content-Length: {}\r\n\r\n{body}", body.len())
        .map_err(|error| format!("write LSP message: {error}"))?;
    output
        .flush()
        .map_err(|error| format!("flush LSP message: {error}"))
}
fn write_lsp_response(
    output: &mut impl Write,
    id: Option<norito::json::Value>,
    result: norito::json::Value,
) -> Result<(), String> {
    write_lsp_message(
        output,
        &json_object(vec![
            ("jsonrpc", norito::json::Value::from("2.0")),
            ("id", id.unwrap_or(norito::json::Value::Null)),
            ("result", result),
        ]),
    )
}
fn write_lsp_error(
    output: &mut impl Write,
    id: Option<norito::json::Value>,
    code: i64,
    message: &str,
) -> Result<(), String> {
    write_lsp_message(
        output,
        &json_object(vec![
            ("jsonrpc", norito::json::Value::from("2.0")),
            ("id", id.unwrap_or(norito::json::Value::Null)),
            (
                "error",
                json_object(vec![
                    ("code", norito::json::Value::from(code)),
                    ("message", norito::json::Value::from(message)),
                ]),
            ),
        ]),
    )
}
fn publish_lsp_notification(
    output: &mut impl Write,
    method: &str,
    params: norito::json::Value,
) -> Result<(), String> {
    write_lsp_message(
        output,
        &json_object(vec![
            ("jsonrpc", norito::json::Value::from("2.0")),
            ("method", norito::json::Value::from(method)),
            ("params", params),
        ]),
    )
}
fn collect_lsp_project_diagnostics(
    driver: &BuildDriver,
    documents: &HashMap<String, String>,
) -> HashMap<String, DiagnosticBundle> {
    // Standalone test modules are checked in compiler test mode against their targets.
    let mut ordered = documents
        .iter()
        .filter(|(uri, source)| !editor_lsp::is_test_module(uri, source))
        .collect::<Vec<_>>();
    ordered.sort_by(|(left, _), (right, _)| left.cmp(right));
    let mut logical_to_uri = HashMap::new();
    let sources = ordered
        .iter()
        .enumerate()
        .map(|(index, (uri, source))| {
            let logical = format!("open/{index:04}.ko");
            logical_to_uri.insert(logical.clone(), (*uri).clone());
            SourceModuleUnit {
                source_name: logical,
                source: (*source).clone(),
            }
        })
        .collect::<Vec<_>>();
    let mut grouped = ordered
        .iter()
        .map(|(uri, _)| ((*uri).clone(), Vec::new()))
        .collect::<HashMap<_, Vec<Diagnostic>>>();
    match driver.check_lsp_open_sources(sources) {
        Ok(warnings) => {
            for warning in warnings {
                let Some(uri) = logical_to_uri.get(&warning.source_name) else {
                    continue;
                };
                grouped
                    .entry(uri.clone())
                    .or_default()
                    .push(lint_diagnostic(&warning.warning, Path::new(uri)));
            }
        }
        Err(error) => {
            let mut diagnostics = match error.into_diagnostics() {
                Ok(bundle) => bundle.diagnostics,
                Err(error) => vec![Diagnostic::error(
                    "K0000",
                    DiagnosticPhase::Lex,
                    error.to_string(),
                    None,
                )],
            };
            for diagnostic in &mut diagnostics {
                remap_project_diagnostic_sources(diagnostic, &logical_to_uri);
            }
            let fallback = ordered.first().map(|(uri, _)| (*uri).clone());
            for diagnostic in diagnostics {
                let owner = diagnostic
                    .primary_span
                    .as_ref()
                    .and_then(|span| span.source.clone())
                    .or_else(|| fallback.clone());
                if let Some(owner) = owner {
                    grouped.entry(owner).or_default().push(diagnostic);
                }
            }
        }
    }
    grouped
        .into_iter()
        .map(|(uri, diagnostics)| (uri, DiagnosticBundle::new(diagnostics)))
        .collect()
}
fn collect_lsp_workspace_diagnostics(
    driver: &BuildDriver,
    documents: &HashMap<String, String>,
    project: Option<&LoadedSourceProject>,
) -> HashMap<String, DiagnosticBundle> {
    // Without an explicit project every open seiyaku roots its own local graph, exactly as
    // navigation analyzes it, so unrelated seiyaku in one directory are never one check.
    let local_projects = if project.is_none() {
        lsp_local_source_projects_with_root(documents, None, None, usize::MAX)
    } else {
        Vec::new()
    };
    let projects = project
        .into_iter()
        .chain(&local_projects)
        .collect::<Vec<_>>();
    if projects.is_empty() {
        return collect_lsp_project_diagnostics(driver, documents);
    }
    let mut grouped = documents
        .keys()
        .cloned()
        .map(|uri| (uri, Vec::new()))
        .collect::<HashMap<_, Vec<Diagnostic>>>();
    let mut covered = HashSet::new();
    for project in projects {
        let (diagnostics, project_documents) =
            collect_lsp_graph_diagnostics(driver, documents, project);
        for (uri, bundle) in diagnostics {
            let published = grouped.entry(uri).or_default();
            for diagnostic in bundle.diagnostics {
                // A module imported by several open roots reports each of its errors once.
                if !published.contains(&diagnostic) {
                    published.push(diagnostic);
                }
            }
        }
        covered.extend(project_documents);
    }
    let loose_documents = documents
        .iter()
        .filter(|(uri, _)| !covered.contains(*uri))
        .map(|(uri, source)| (uri.clone(), source.clone()))
        .collect::<HashMap<_, _>>();
    for (uri, bundle) in collect_lsp_project_diagnostics(driver, &loose_documents) {
        grouped.entry(uri).or_default().extend(bundle.diagnostics);
    }
    grouped
        .into_iter()
        .map(|(uri, diagnostics)| (uri, DiagnosticBundle::new(diagnostics)))
        .collect()
}
/// Diagnostics of one project graph with the open documents overlaid, and the open documents
/// that graph accounts for. A graph whose sources cannot be loaded reports only that loading
/// error and accounts for every open document, as a failed `koto check` stops there.
fn collect_lsp_graph_diagnostics(
    driver: &BuildDriver,
    documents: &HashMap<String, String>,
    project: &LoadedSourceProject,
) -> (HashMap<String, DiagnosticBundle>, HashSet<String>) {
    let (graph, source_uris, project_documents, _) =
        match lsp_project_with_open_overlays(project, documents) {
            Ok(overlaid) => overlaid,
            Err(error) => {
                return (
                    lsp_source_loading_diagnostics(error, project, documents),
                    documents
                        .keys()
                        .filter(|uri| {
                            lsp_file_uri_path(uri).is_some_and(|path| {
                                project.source_paths.values().any(|owned| owned == &path)
                                    || project
                                        .manifests
                                        .iter()
                                        .any(|manifest| manifest.path() == path)
                            })
                        })
                        .cloned()
                        .collect(),
                );
            }
        };
    let mut grouped = HashMap::<String, Vec<Diagnostic>>::new();
    match match graph {
        LoadedProjectGraph::Source(graph) => driver.check_project(graph),
        LoadedProjectGraph::Package(graph) => driver.check_package_project(graph),
    } {
        Ok(warnings) => {
            for warning in warnings {
                let key = ProjectSourceKey {
                    package_identity: warning.package_identity.clone(),
                    source_name: warning.source_name,
                };
                let Some(uri) = source_uris.get(&key) else {
                    continue;
                };
                // The editor reports the project manifest's lint levels, as `koto check` does.
                let Some(lint) = leveled_lint(&project.lints, warning.warning) else {
                    continue;
                };
                let diagnostic = lint.to_diagnostic(
                    uri,
                    warning.package_identity.as_deref(),
                    kotodama_lang::i18n::detect_language(),
                );
                grouped.entry(uri.clone()).or_default().push(diagnostic);
            }
        }
        Err(error) => {
            let diagnostics = error.into_diagnostics().unwrap_or_else(|error| {
                DiagnosticBundle::single(Diagnostic::error(
                    "K0000",
                    DiagnosticPhase::Lex,
                    error.to_string(),
                    None,
                ))
            });
            let fallback = source_uris.values().next().cloned();
            for mut diagnostic in diagnostics.diagnostics {
                let owner = diagnostic.primary_span.as_ref().and_then(|span| {
                    let key = ProjectSourceKey {
                        package_identity: span.package_identity.clone(),
                        source_name: span.source.clone()?,
                    };
                    source_uris.get(&key).cloned()
                });
                if owner.is_none() {
                    if let Some(span) = diagnostic.primary_span.take() {
                        diagnostic.notes.push(format!(
                            "locked project error originates in {}{}",
                            span.package_identity
                                .as_deref()
                                .map_or(String::new(), |package| format!("{package}::")),
                            span.source.as_deref().unwrap_or("<source>")
                        ));
                    }
                    // Edits for a source that is not open here cannot be applied.
                    diagnostic.fix = None;
                    diagnostic.alternative_fixes.clear();
                }
                remap_lsp_locked_project_diagnostic(&mut diagnostic, &source_uris);
                if let Some(uri) = owner.or_else(|| fallback.clone()) {
                    grouped.entry(uri).or_default().push(diagnostic);
                }
            }
        }
    }
    (
        grouped
            .into_iter()
            .map(|(uri, diagnostics)| (uri, DiagnosticBundle::new(diagnostics)))
            .collect(),
        project_documents,
    )
}
fn lsp_source_loading_diagnostics(
    error: BuildError,
    project: &LoadedSourceProject,
    documents: &HashMap<String, String>,
) -> HashMap<String, DiagnosticBundle> {
    let bundle = error.into_diagnostics().unwrap_or_else(|error| {
        DiagnosticBundle::single(Diagnostic::error(
            "E_SOURCE_NOT_FOUND",
            DiagnosticPhase::Resolve,
            error.to_string(),
            None,
        ))
    });
    let root_source = project
        .source_paths
        .iter()
        .find(|(key, _)| match &project.graph {
            LoadedProjectGraph::Source(graph) => {
                key.package_identity.is_none() && key.source_name == graph.root.source_name
            }
            LoadedProjectGraph::Package(graph) => {
                key.package_identity.as_deref() == Some(graph.package.identity.as_str())
            }
        });
    let root_path = root_source.map(|(_, path)| path);
    let source_root =
        root_source.and_then(|(key, path)| physical_source_root(path, &key.source_name));
    let mut source_uris = project
        .source_paths
        .iter()
        .filter_map(|(key, path)| lsp_path_file_uri(path).map(|uri| (key.clone(), uri)))
        .collect::<BTreeMap<_, _>>();
    for diagnostic in &bundle.diagnostics {
        for span in diagnostic
            .primary_span
            .iter()
            .chain(diagnostic.labels.iter().map(|label| &label.span))
        {
            let owner_root = project
                .source_paths
                .iter()
                .find(|(key, _)| key.package_identity == span.package_identity)
                .and_then(|(key, path)| physical_source_root(path, &key.source_name))
                .or_else(|| source_root.clone());
            if let (Some(root), Some(name)) = (&owner_root, &span.source) {
                let path = root.join(name);
                if let Some(uri) = lsp_path_file_uri(&path) {
                    source_uris
                        .entry(ProjectSourceKey {
                            package_identity: span.package_identity.clone(),
                            source_name: name.clone(),
                        })
                        .or_insert(uri);
                }
            }
        }
    }
    let fallback = root_path.and_then(|path| lsp_path_file_uri(path));
    let mut grouped = documents
        .keys()
        .map(|uri| (uri.clone(), Vec::new()))
        .collect::<HashMap<_, _>>();
    for mut diagnostic in bundle.diagnostics {
        remap_lsp_locked_project_diagnostic(&mut diagnostic, &source_uris);
        if let Some(uri) = diagnostic
            .primary_span
            .as_ref()
            .and_then(|span| span.source.clone())
            .or_else(|| fallback.clone())
        {
            grouped.entry(uri).or_default().push(diagnostic);
        }
    }
    grouped
        .into_iter()
        .map(|(uri, diagnostics)| (uri, DiagnosticBundle::new(diagnostics)))
        .collect()
}
fn lsp_local_source_project(
    documents: &HashMap<String, String>,
    requested_uri: Option<&str>,
) -> Option<LoadedSourceProject> {
    lsp_local_source_project_with_root(documents, requested_uri, None)
}
fn lsp_local_source_project_with_root(
    documents: &HashMap<String, String>,
    requested_uri: Option<&str>,
    source_root: Option<&Path>,
) -> Option<LoadedSourceProject> {
    lsp_local_source_projects_with_root(documents, requested_uri, source_root, 1).pop()
}
/// Local graphs rooted at the open seiyaku documents, in path order, at most `limit` of them.
/// Each root reads its declared `include`/`import` closure relative to its own directory (or
/// `source_root`); with `requested_uri`, only graphs containing that document are returned.
fn lsp_local_source_projects_with_root(
    documents: &HashMap<String, String>,
    requested_uri: Option<&str>,
    source_root: Option<&Path>,
    limit: usize,
) -> Vec<LoadedSourceProject> {
    let overlays = documents
        .iter()
        .filter_map(|(uri, source)| lsp_file_uri_path(uri).map(|path| (path, source.clone())))
        .collect::<BTreeMap<_, _>>();
    let requested = requested_uri.and_then(lsp_file_uri_path);
    let mut ordered = overlays.iter().collect::<Vec<_>>();
    ordered.sort_by(|(left, _), (right, _)| left.cmp(right));
    let mut projects = Vec::new();
    for (path, source) in ordered {
        if projects.len() >= limit {
            break;
        }
        if !kotodama_lang::parser::parse(source)
            .is_ok_and(|program| program.unit.kind == kotodama_lang::ast::SourceUnitKind::Seiyaku)
        {
            continue;
        }
        let Some(root) = source_root.or_else(|| path.parent()) else {
            continue;
        };
        // Retain the root even while its declared closure is incomplete. Overlay loading below
        // reports the exact dependency error instead of reclassifying this contract as loose.
        let project = load_source_project(path, root, &overlays).unwrap_or_else(|_| {
            let source_name = logical_source_name(path, root)
                .unwrap_or_else(|_| path.to_string_lossy().into_owned());
            LoadedSourceProject {
                graph: LoadedProjectGraph::Source(kotodama_lang::linker::SourceLinkRequest {
                    artifacts: Vec::new(),
                    root: SourceModuleUnit {
                        source_name: source_name.clone(),
                        source: source.clone(),
                    },
                    sources: Vec::new(),
                    imports: Vec::new(),
                    packages: Vec::new(),
                }),
                source_paths: BTreeMap::from([(
                    ProjectSourceKey {
                        package_identity: None,
                        source_name,
                    },
                    path.clone(),
                )]),
                manifests: Vec::new(),
                lints: LintConfig::default(),
            }
        });
        if requested
            .as_ref()
            .is_none_or(|requested| project.source_paths.values().any(|path| path == requested))
        {
            projects.push(project);
        }
    }
    projects
}
/// Project link graph with the open editor documents overlaid: the link request, the
/// document URI of each project source, the open document URIs owned by the project, and
/// the effective project manifest.
type LspOverlaidProject = (
    LoadedProjectGraph,
    BTreeMap<ProjectSourceKey, String>,
    HashSet<String>,
    Vec<kotodama_lang::driver::ProjectManifestSource>,
);
fn physical_source_root(path: &Path, source_name: &str) -> Option<PathBuf> {
    let mut root = path.to_path_buf();
    for _ in source_name.split('/') {
        if !root.pop() {
            return None;
        }
    }
    Some(root)
}
fn lsp_project_with_open_overlays(
    project: &LoadedSourceProject,
    documents: &HashMap<String, String>,
) -> Result<LspOverlaidProject, BuildError> {
    let overlays = documents
        .iter()
        .filter_map(|(uri, text)| lsp_file_uri_path(uri).map(|path| (path, text.clone())))
        .collect::<BTreeMap<_, _>>();
    let mut project_documents = HashSet::new();
    for manifest in &project.manifests {
        for (uri, text) in documents {
            if lsp_file_uri_path(uri).as_deref() == Some(manifest.path()) {
                if text != manifest.text() {
                    return Err(BuildError::InvalidProjectManifest{path:manifest.path().to_path_buf(),message:"Manifest overlay differs from the captured project; reload the project provider before editing.".into()});
                }
                project_documents.insert(uri.clone());
            }
        }
    }
    let mut graph = project.graph.clone();
    let mut source_uris = BTreeMap::new();
    for (key, path) in &project.source_paths {
        let source = overlays
            .get(path)
            .cloned()
            .map_or_else(|| read_source_file(path), Ok)?;
        replace_project_source(&mut graph, key, &source);
        if let Some(uri) = lsp_path_file_uri(path) {
            if documents.contains_key(&uri) {
                project_documents.insert(uri.clone());
            }
            source_uris.insert(key.clone(), uri);
        }
    }
    let mut owner_roots = BTreeMap::new();
    let mut refresh_package =
        |package: &mut kotodama_lang::linker::SourcePackageUnit| -> Result<(), BuildError> {
            let root = package.modules.iter().find_map(|module| {
                let key = ProjectSourceKey {
                    package_identity: Some(package.identity.clone()),
                    source_name: module.source_name.clone(),
                };
                project
                    .source_paths
                    .get(&key)
                    .and_then(|path| physical_source_root(path, &key.source_name))
            });
            // Cached packages have no editable local path authority.
            if let Some(root) = root {
                let inventory = kotodama_lang::driver::load_source_package_inventory(
                    &package.modules,
                    &root,
                    &overlays,
                    &package.identity,
                )?;
                package.sources = inventory.sources;
                package.artifacts = inventory.artifacts;
                owner_roots.insert(Some(package.identity.clone()), root);
            }
            Ok(())
        };
    let units = match &mut graph {
        LoadedProjectGraph::Source(graph) => {
            for package in &mut graph.packages {
                refresh_package(package)?;
            }
            let key = ProjectSourceKey {
                package_identity: None,
                source_name: graph.root.source_name.clone(),
            };
            let root = project
                .source_paths
                .get(&key)
                .and_then(|path| physical_source_root(path, &key.source_name))
                .ok_or_else(|| BuildError::InvalidPath {
                    path: PathBuf::from(&key.source_name),
                    message: "project root has no physical source path".into(),
                })?;
            let inventory = kotodama_lang::driver::load_source_inventory(
                std::slice::from_ref(&graph.root),
                &root,
                &overlays,
            )?;
            graph.sources = inventory.sources;
            graph.artifacts = inventory.artifacts;
            owner_roots.insert(None, root);
            graph
                .sources
                .iter()
                .map(|source| (None, source))
                .chain(graph.packages.iter().flat_map(|package| {
                    package
                        .sources
                        .iter()
                        .map(move |source| (Some(package.identity.clone()), source))
                }))
                .collect::<Vec<_>>()
        }
        LoadedProjectGraph::Package(graph) => {
            for package in std::iter::once(&mut graph.package).chain(&mut graph.dependencies) {
                refresh_package(package)?;
            }
            std::iter::once(&graph.package)
                .chain(&graph.dependencies)
                .flat_map(|package| {
                    package
                        .sources
                        .iter()
                        .map(move |source| (Some(package.identity.clone()), source))
                })
                .collect::<Vec<_>>()
        }
    };
    for (owner, source) in units {
        let Some(root) = owner_roots.get(&owner) else {
            continue;
        };
        let path = root.join(&source.source_name);
        let uri = lsp_path_file_uri(&path).ok_or_else(|| BuildError::InvalidPath {
            path,
            message: "source URI requires a UTF-8 path".into(),
        })?;
        if documents.contains_key(&uri) {
            project_documents.insert(uri.clone());
        }
        source_uris.insert(
            ProjectSourceKey {
                package_identity: owner,
                source_name: source.source_name.clone(),
            },
            uri,
        );
    }
    Ok((
        graph,
        source_uris,
        project_documents,
        project.manifests.clone(),
    ))
}
fn lsp_path_file_uri(path: &Path) -> Option<String> {
    let text = path.to_str()?;
    let mut uri = String::from("file://");
    if !text.starts_with('/') {
        uri.push('/');
    }
    for byte in text.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'/' | b'-' | b'_' | b'.' | b'~' | b':')
        {
            uri.push(char::from(*byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(uri, "%{byte:02X}");
        }
    }
    Some(uri)
}
fn replace_project_source(
    graph: &mut LoadedProjectGraph,
    key: &ProjectSourceKey,
    source: &str,
) -> bool {
    let units = match graph {
        LoadedProjectGraph::Source(graph) => match &key.package_identity {
            None => std::iter::once(&mut graph.root)
                .chain(&mut graph.sources)
                .collect::<Vec<_>>(),
            Some(owner) => graph
                .packages
                .iter_mut()
                .filter(|package| &package.identity == owner)
                .flat_map(|package| package.modules.iter_mut().chain(&mut package.sources))
                .collect(),
        },
        LoadedProjectGraph::Package(graph) => std::iter::once(&mut graph.package)
            .chain(&mut graph.dependencies)
            .filter(|package| Some(&package.identity) == key.package_identity.as_ref())
            .flat_map(|package| package.modules.iter_mut().chain(&mut package.sources))
            .collect(),
    };
    units
        .into_iter()
        .find(|unit| unit.source_name == key.source_name)
        .is_some_and(|unit| {
            source.clone_into(&mut unit.source);
            true
        })
}
fn lsp_file_uri_path(uri: &str) -> Option<PathBuf> {
    let encoded = uri
        .strip_prefix("file://localhost")
        .or_else(|| uri.strip_prefix("file://"))?;
    if !encoded.starts_with('/') {
        // A non-empty authority names a remote host. Kotodama project sources
        // are canonical local files, so such a URI cannot own an overlay.
        return None;
    }
    let bytes = encoded.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = decode_hex_digit(*bytes.get(index + 1)?)?;
            let low = decode_hex_digit(*bytes.get(index + 2)?)?;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    let decoded = String::from_utf8(decoded).ok()?;
    #[cfg(windows)]
    let decoded = decoded
        .strip_prefix('/')
        .filter(|path| path.as_bytes().get(1) == Some(&b':'))
        .unwrap_or(&decoded);
    let path = PathBuf::from(decoded);
    path.canonicalize().ok().or_else(|| {
        let mut normalized = PathBuf::new();
        for component in path.components() {
            match component {
                std::path::Component::ParentDir => {
                    if !normalized.pop() {
                        return None;
                    }
                }
                std::path::Component::CurDir => {}
                component => normalized.push(component.as_os_str()),
            }
        }
        normalized.is_absolute().then_some(normalized)
    })
}
fn decode_hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
fn remap_lsp_locked_project_diagnostic(
    diagnostic: &mut Diagnostic,
    source_uris: &BTreeMap<ProjectSourceKey, String>,
) {
    let remap = |span: &mut SourceSpan| {
        let Some(source_name) = span.source.as_ref() else {
            return;
        };
        let key = ProjectSourceKey {
            package_identity: span.package_identity.clone(),
            source_name: source_name.clone(),
        };
        if let Some(uri) = source_uris.get(&key) {
            span.source = Some(uri.clone());
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
}
fn collect_target_diagnostics(
    driver: &BuildDriver,
    documents: &HashMap<String, String>,
    snapshot: &ProjectSnapshot,
) -> HashMap<String, DiagnosticBundle> {
    if snapshot.targets.is_empty() {
        return collect_lsp_workspace_diagnostics(driver, documents, None);
    }
    let mut grouped = HashMap::<String, DiagnosticBundle>::new();
    let mut covered = HashSet::new();
    for target in &snapshot.targets {
        let (diagnostics, owned) =
            collect_lsp_graph_diagnostics(driver, documents, &target.project);
        covered.extend(owned);
        for (uri, bundle) in diagnostics {
            let output = grouped
                .entry(uri)
                .or_insert_with(|| DiagnosticBundle::new(Vec::new()));
            for mut diagnostic in bundle.diagnostics {
                diagnostic
                    .notes
                    .push(format!("contract target: {}", target.name));
                output.diagnostics.push(diagnostic);
            }
        }
    }
    let loose = documents
        .iter()
        .filter(|(uri, _)| {
            !covered.contains(*uri)
                && Path::new(uri)
                    .extension()
                    .is_some_and(|extension| extension == "ko")
        })
        .map(|(uri, text)| (uri.clone(), text.clone()))
        .collect();
    for (uri, bundle) in collect_lsp_project_diagnostics(driver, &loose) {
        grouped
            .entry(uri)
            .or_insert_with(|| DiagnosticBundle::new(Vec::new()))
            .diagnostics
            .extend(bundle.diagnostics);
    }
    grouped
}
#[derive(Clone, Copy)]
struct ProjectDiagnosticContext<'a> {
    snapshot: &'a ProjectSnapshot,
    options: &'a ServerOptions,
    error: Option<&'a str>,
}
fn publish_lsp_project_diagnostics(
    output: &mut impl Write,
    driver: &BuildDriver,
    documents: &HashMap<String, String>,
    context: ProjectDiagnosticContext<'_>,
    versions: &HashMap<String, i64>,
    previously_published: &BTreeSet<String>,
) -> Result<BTreeSet<String>, String> {
    let ProjectDiagnosticContext {
        snapshot: projects,
        options,
        error: project_error,
    } = context;
    let mut diagnostics = project_error.map_or_else(
        || collect_target_diagnostics(driver, documents, projects),
        |message| {
            documents
                .keys()
                .map(|uri| {
                    let file = SourceFile::new(SourceId(0), uri.as_str(), documents[uri].as_str());
                    (
                        uri.clone(),
                        DiagnosticBundle::single(Diagnostic::error(
                            "E_PROJECT_RELOAD",
                            DiagnosticPhase::Resolve,
                            message,
                            Some(SourceSpan::from_range(
                                &file,
                                kotodama_lang::source::TextRange::empty(0),
                            )),
                        )),
                    )
                })
                .collect()
        },
    );
    for (uri, source) in documents
        .iter()
        .filter(|(uri, source)| project_error.is_none() && editor_lsp::is_test_module(uri, source))
    {
        let bundle = match selected_project(projects, uri, documents) {
            Ok(project) => editor_lsp::test_module_diagnostics(
                documents,
                uri,
                source,
                options.zk_enabled,
                project,
                options.chain_discriminant,
            ),
            Err(message) => DiagnosticBundle::single(Diagnostic::error(
                "E_PROJECT_TARGET_AMBIGUOUS",
                DiagnosticPhase::Resolve,
                message,
                None,
            )),
        };
        diagnostics.insert(uri.clone(), bundle);
    }
    let current_uris = documents
        .keys()
        .chain(diagnostics.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    for uri in current_uris.union(previously_published) {
        let source = documents.get(uri).map_or("", String::as_str);
        let values = diagnostics
            .get(uri)
            .into_iter()
            .flat_map(|bundle| bundle.diagnostics.iter())
            .map(|diagnostic| lsp_diagnostic_value(diagnostic, source))
            .collect();
        let mut params = vec![
            ("uri", norito::json::Value::from(uri.as_str())),
            ("diagnostics", norito::json::Value::Array(values)),
        ];
        if let Some(version) = versions.get(uri) {
            params.push(("version", (*version).into()));
        }
        publish_lsp_notification(
            output,
            "textDocument/publishDiagnostics",
            json_object(params),
        )?;
    }
    Ok(current_uris)
}
fn lsp_initialize_result() -> norito::json::Value {
    json_object(vec![
        (
            "serverInfo",
            json_object(vec![
                ("name", "koto".into()),
                ("version", env!("CARGO_PKG_VERSION").into()),
            ]),
        ),
        ("capabilities", lsp_capabilities()),
    ])
}
fn lsp_capabilities() -> norito::json::Value {
    json_object(vec![
        ("textDocumentSync", norito::json::Value::from(1_u64)),
        ("documentSymbolProvider", true.into()),
        ("workspaceSymbolProvider", true.into()),
        ("documentHighlightProvider", true.into()),
        ("foldingRangeProvider", true.into()),
        (
            "semanticTokensProvider",
            json_object(vec![
                ("legend", editor_lsp::semantic_tokens_legend()),
                ("full", true.into()),
            ]),
        ),
        (
            "codeLensProvider",
            json_object(vec![("resolveProvider", false.into())]),
        ),
        (
            "completionProvider",
            json_object(vec![
                ("resolveProvider", norito::json::Value::from(false)),
                (
                    "triggerCharacters",
                    norito::json::Value::Array(vec![".".into(), ":".into()]),
                ),
            ]),
        ),
        (
            "documentFormattingProvider",
            norito::json::Value::from(true),
        ),
        (
            "codeActionProvider",
            json_object(vec![(
                "codeActionKinds",
                norito::json::Value::Array(vec!["quickfix".into()]),
            )]),
        ),
        ("hoverProvider", true.into()),
        ("definitionProvider", true.into()),
        ("referencesProvider", true.into()),
        (
            "renameProvider",
            json_object(vec![("prepareProvider", true.into())]),
        ),
        (
            "signatureHelpProvider",
            json_object(vec![(
                "triggerCharacters",
                norito::json::Value::Array(vec!["(".into(), ",".into(), ":".into()]),
            )]),
        ),
        ("positionEncoding", "utf-16".into()),
    ])
}
#[cfg(test)]
fn collect_lsp_diagnostics(session: &CompilerSession, uri: &str, source: &str) -> DiagnosticBundle {
    // LSP validates reusable modules as well as deployable contracts. Calling
    // `build` here would add the artifact-only K4003 error to every valid
    // module document and perform unnecessary code generation while typing.
    match session.check_with_lints(CompileRequest {
        source,
        source_name: Some(uri),
    }) {
        Ok(warnings) => DiagnosticBundle::new(
            warnings
                .into_iter()
                .map(|warning| lint_diagnostic(&warning, Path::new(uri)))
                .collect(),
        ),
        Err(bundle) => bundle,
    }
}
#[cfg(test)]
fn lsp_diagnostics(session: &CompilerSession, uri: &str, source: &str) -> Vec<norito::json::Value> {
    collect_lsp_diagnostics(session, uri, source)
        .diagnostics
        .iter()
        .map(|diagnostic| lsp_diagnostic_value(diagnostic, source))
        .collect()
}
/// Whether a note is a terminal source excerpt: text lines followed by a caret underline.
fn is_rendered_source_excerpt(note: &str) -> bool {
    note.contains('\n')
        && note.lines().last().is_some_and(|underline| {
            underline.contains('^')
                && underline
                    .chars()
                    .all(|character| matches!(character, '^' | '~' | '-' | ' ' | '\t'))
        })
}
fn lsp_diagnostic_value(diagnostic: &Diagnostic, source: &str) -> norito::json::Value {
    let source = diagnostic
        .primary_source
        .as_ref()
        .map_or(source, |file| file.text());
    let range = diagnostic.primary_span.as_ref().map_or_else(
        || lsp_range(0, 0, 0, 1),
        |span| lsp_source_span_range(source, span),
    );
    let mut message = diagnostic.message.clone();
    // Editors draw the primary range themselves; terminal source excerpts are never repeated.
    for note in diagnostic
        .notes
        .iter()
        .filter(|note| !is_rendered_source_excerpt(note))
    {
        message.push_str("\n\nnote: ");
        message.push_str(note);
    }
    if let Some(help) = &diagnostic.help {
        message.push_str("\n\nhelp: ");
        message.push_str(help);
    }
    let related = diagnostic
        .labels
        .iter()
        .enumerate()
        .filter_map(|(index, label)| {
            let uri = label.span.source.as_deref()?;
            let label_source = diagnostic
                .label_sources
                .get(index)
                .and_then(Option::as_ref)
                .map_or("", |file| file.text());
            Some(json_object(vec![
                (
                    "location",
                    json_object(vec![
                        ("uri", norito::json::Value::from(uri)),
                        ("range", lsp_source_span_range(label_source, &label.span)),
                    ]),
                ),
                ("message", norito::json::Value::from(label.message.clone())),
            ]))
        })
        .collect::<Vec<_>>();
    json_object(vec![
        ("range", range),
        ("code", norito::json::Value::from(diagnostic.code.clone())),
        (
            "severity",
            norito::json::Value::from(match diagnostic.severity {
                kotodama_lang::diagnostic::Severity::Error => 1_u64,
                kotodama_lang::diagnostic::Severity::Warning => 2_u64,
            }),
        ),
        ("source", norito::json::Value::from("kotodama")),
        ("relatedInformation", norito::json::Value::Array(related)),
        (
            "codeDescription",
            json_object(vec![(
                "href",
                norito::json::Value::from(documentation_url(&diagnostic.code)),
            )]),
        ),
        ("message", norito::json::Value::from(message)),
    ])
}
#[cfg(test)]
fn lsp_code_action_items(
    session: &CompilerSession,
    uri: &str,
    source: &str,
) -> norito::json::Value {
    lsp_code_actions_from_bundle(
        collect_lsp_diagnostics(session, uri, source),
        uri,
        source,
        None,
    )
}
fn lsp_project_code_action_items(
    driver: &BuildDriver,
    documents: &HashMap<String, String>,
    project: Option<&LoadedSourceProject>,
    uri: &str,
    range: Option<&norito::json::Value>,
    zk_enabled: bool,
) -> norito::json::Value {
    let source = documents.get(uri).map_or("", String::as_str);
    let mut diagnostics = collect_lsp_workspace_diagnostics(driver, documents, project);
    editor_lsp::apply_test_module_diagnostics(&mut diagnostics, documents, zk_enabled);
    let bundle = diagnostics
        .remove(uri)
        .unwrap_or_else(|| DiagnosticBundle::new(Vec::new()));
    lsp_code_actions_from_bundle(
        bundle,
        uri,
        source,
        range.and_then(|range| lsp_byte_range(source, range)),
    )
}
/// Byte range of an LSP UTF-16 range in `source`.
fn lsp_byte_range(
    source: &str,
    range: &norito::json::Value,
) -> Option<kotodama_lang::source::TextRange> {
    let offset = |position: &str| -> Option<u32> {
        let line = usize::try_from(range.pointer(&format!("/{position}/line"))?.as_u64()?).ok()?;
        let character =
            usize::try_from(range.pointer(&format!("/{position}/character"))?.as_u64()?).ok()?;
        let start = source
            .split_inclusive('\n')
            .take(line)
            .map(str::len)
            .sum::<usize>();
        let text = source.get(start..)?.split('\n').next()?;
        let mut utf16 = 0;
        for (byte, ch) in text.char_indices() {
            if utf16 >= character {
                return u32::try_from(start + byte).ok();
            }
            utf16 += ch.len_utf16();
        }
        u32::try_from(start + text.len()).ok()
    };
    let (start, end) = (offset("start")?, offset("end")?);
    (start <= end).then(|| kotodama_lang::source::TextRange::new(start, end))
}
/// Short code-action title naming exactly what the edit does.
fn lsp_fix_title(
    source: &str,
    fix: &kotodama_lang::diagnostic::DiagnosticFix,
    code: &str,
) -> String {
    let replaced = fix
        .span
        .byte_range
        .and_then(|range| source.get(range.start as usize..range.end as usize))
        .unwrap_or_default();
    let short = |text: &str| !text.contains('\n') && text.chars().count() <= 40;
    match (
        replaced.trim().is_empty(),
        fix.replacement.trim().is_empty(),
    ) {
        (false, true) if short(replaced) => format!("Remove `{}`", replaced.trim()),
        (true, false) if short(&fix.replacement) => {
            format!("Insert `{}`", fix.replacement.trim())
        }
        (false, false) if short(replaced) && short(&fix.replacement) => format!(
            "Replace `{}` with `{}`",
            replaced.trim(),
            fix.replacement.trim()
        ),
        _ => format!("Apply the suggested {code} fix"),
    }
}
fn lsp_code_actions_from_bundle(
    bundle: DiagnosticBundle,
    uri: &str,
    source: &str,
    range: Option<kotodama_lang::source::TextRange>,
) -> norito::json::Value {
    let mut actions = Vec::new();
    for diagnostic in bundle.diagnostics {
        // Offer only fixes for diagnostics that touch the requested range.
        if let Some(requested) = range
            && diagnostic
                .primary_span
                .as_ref()
                .and_then(|span| span.byte_range)
                .is_some_and(|span| span.end < requested.start || requested.end < span.start)
        {
            continue;
        }
        let fixes = diagnostic
            .fix
            .iter()
            .map(|fix| (fix, true))
            .chain(diagnostic.alternative_fixes.iter().map(|fix| (fix, false)))
            .collect::<Vec<_>>();
        for (fix, preferred) in fixes {
            let Some(byte_range) = fix.span.byte_range else {
                continue;
            };
            let (Ok(start), Ok(end)) = (
                usize::try_from(byte_range.start),
                usize::try_from(byte_range.end),
            ) else {
                continue;
            };
            if start > end
                || end > source.len()
                || !source.is_char_boundary(start)
                || !source.is_char_boundary(end)
            {
                continue;
            }
            let edit = json_object(vec![
                ("range", lsp_text_range(source, byte_range)),
                (
                    "newText",
                    norito::json::Value::from(fix.replacement.clone()),
                ),
            ]);
            let Ok(changes) =
                norito::json::object([(uri.to_owned(), norito::json::Value::Array(vec![edit]))])
            else {
                continue;
            };
            actions.push(json_object(vec![
                (
                    "title",
                    norito::json::Value::from(lsp_fix_title(source, fix, &diagnostic.code)),
                ),
                ("kind", norito::json::Value::from("quickfix")),
                ("isPreferred", norito::json::Value::from(preferred)),
                (
                    "diagnostics",
                    norito::json::Value::Array(vec![lsp_diagnostic_value(&diagnostic, source)]),
                ),
                ("edit", json_object(vec![("changes", changes)])),
            ]));
        }
    }
    norito::json::Value::Array(actions)
}
fn lsp_source_span_range(source: &str, span: &SourceSpan) -> norito::json::Value {
    span.byte_range
        .filter(|range| range.end as usize <= source.len() && !source.is_empty())
        .map_or_else(
            || {
                let (start_line, start_character) = lsp_source_position(source, &span.start);
                let (end_line, end_character) = lsp_source_position(source, &span.end);
                lsp_range(start_line, start_character, end_line, end_character)
            },
            |range| lsp_text_range(source, range),
        )
}
fn lsp_source_position(source: &str, position: &SourcePosition) -> (u64, u64) {
    let line = position.line.saturating_sub(1);
    let column = position.column.saturating_sub(1);
    let character = source
        .split('\n')
        .nth(line)
        .filter(|_| !source.is_empty())
        .map_or(column, |text| {
            text.chars().take(column).map(char::len_utf16).sum()
        });
    (line as u64, character as u64)
}
fn lsp_text_range(source: &str, range: kotodama_lang::source::TextRange) -> norito::json::Value {
    let (start_line, start_character) = lsp_offset_position(source, range.start);
    let (end_line, end_character) = lsp_offset_position(source, range.end);
    lsp_range(start_line, start_character, end_line, end_character)
}
fn lsp_offset_position(source: &str, offset: u32) -> (u64, u64) {
    let offset = usize::try_from(offset)
        .unwrap_or(source.len())
        .min(source.len());
    let offset = if source.is_char_boundary(offset) {
        offset
    } else {
        let mut boundary = offset;
        while !source.is_char_boundary(boundary) {
            boundary = boundary.saturating_sub(1);
        }
        boundary
    };
    let prefix = &source[..offset];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() as u64;
    let line_start = prefix.rfind('\n').map_or(0, |index| index + 1);
    let character = prefix[line_start..].encode_utf16().count() as u64;
    (line, character)
}
fn lsp_range(
    start_line: u64,
    start_character: u64,
    end_line: u64,
    end_character: u64,
) -> norito::json::Value {
    json_object(vec![
        ("start", lsp_position(start_line, start_character)),
        ("end", lsp_position(end_line, end_character)),
    ])
}
#[cfg(test)]
fn lsp_completion_items() -> norito::json::Value {
    let mut labels = BTreeSet::new();
    let mut items = Vec::new();
    let mut push = |label: &'static str, kind: u64| {
        if labels.insert(label) {
            items.push(json_object(vec![
                ("label", norito::json::Value::from(label)),
                ("kind", norito::json::Value::from(kind)),
            ]));
        }
    };
    for &keyword in V1_KEYWORDS {
        push(keyword, 14);
    }
    for &operator in V1_OPERATORS {
        push(operator, 24);
    }
    for &ty in V1_SOURCE_TYPE_NAMES {
        push(ty, 7);
    }
    for &path in V1_SUM_PATHS {
        push(path, 3);
    }
    for &path in V1_ROUNDING_PATHS {
        push(path, 20);
    }
    for &member in V1_LIST_MEMBER_NAMES {
        push(member, 2);
    }
    for &(label, kind) in V1_CONTEXTUAL_COMPLETIONS {
        push(label, kind);
    }
    for (builtin, spec) in Builtin::registry() {
        match spec.surface {
            BuiltinSurface::Function => push(spec.name, 3),
            BuiltinSurface::MethodOnly => push(builtin.name(), 2),
            BuiltinSurface::FunctionOrMethod => {
                push(spec.name, 3);
                push(builtin.name(), 2);
            }
            BuiltinSurface::CompilerInternal => continue,
        }
    }
    norito::json::Value::Array(items)
}
fn lsp_position(line: impl Into<u64>, character: impl Into<u64>) -> norito::json::Value {
    json_object(vec![
        ("line", norito::json::Value::from(line.into())),
        ("character", norito::json::Value::from(character.into())),
    ])
}
fn json_object(entries: Vec<(&str, norito::json::Value)>) -> norito::json::Value {
    norito::json::object(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value)),
    )
    .unwrap_or(norito::json::Value::Null)
}
#[cfg(test)]
fn fixture_project(
    root: &Path,
    source: &str,
    package: Option<(&str, &str, &str)>,
    manifest: &Path,
    text: &str,
    export: &str,
) -> LoadedSourceProject {
    use kotodama_lang::{
        driver::ProjectManifestSource,
        linker::{ImportBinding, SourcePackageUnit},
        source::TextRange,
    };
    let mut project = load_source_project(&root.join(source), root, &BTreeMap::new()).unwrap();
    let mut exports = BTreeMap::new();
    if let Some((identity, alias, module)) = package {
        project
            .graph
            .as_source_mut()
            .expect("source graph")
            .imports
            .push(ImportBinding {
                alias: alias.into(),
                package: identity.into(),
            });
        project
            .graph
            .as_source_mut()
            .expect("source graph")
            .packages
            .push(SourcePackageUnit {
                artifacts: Vec::new(),
                identity: identity.into(),
                modules: vec![SourceModuleUnit {
                    source_name: module.into(),
                    source: read_source_file(&root.join(module)).unwrap(),
                }],
                sources: vec![],
                exports: BTreeSet::from([export.to_owned()]),
                imports: vec![],
            });
        project.source_paths.insert(
            ProjectSourceKey {
                package_identity: Some(identity.into()),
                source_name: module.into(),
            },
            root.join(module).canonicalize().unwrap(),
        );
        let token = if text.contains("\"v\\u0061lue\"") {
            "\"v\\u0061lue\"".to_owned()
        } else {
            format!("\"{export}\"")
        };
        let start = text.rfind(&token).unwrap();
        exports.insert(
            (identity.into(), export.into()),
            TextRange::new(start as u32, (start + token.len()) as u32),
        );
    }
    project.manifests = vec![ProjectManifestSource::new(
        manifest.canonicalize().unwrap(),
        text.to_owned(),
        exports,
    )];
    project
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lsp_framing_and_completion_use_canonical_syntax_tables() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#;
        let framed = format!(
            "Content-Length: {}\r\n\r\n{}",
            body.len(),
            std::str::from_utf8(body).expect("JSON is UTF-8")
        );
        let mut input = std::io::Cursor::new(framed.into_bytes());
        let message = read_lsp_message(&mut input)
            .expect("read LSP frame")
            .expect("one message");
        assert_eq!(
            message.get("method").and_then(norito::json::Value::as_str),
            Some("initialize")
        );
        assert_eq!(
            lsp_initialize_result()
                .pointer("/capabilities/codeActionProvider/codeActionKinds/0")
                .and_then(norito::json::Value::as_str),
            Some("quickfix"),
        );
        let completions = lsp_completion_items();
        let labels = completions
            .as_array()
            .expect("completion array")
            .iter()
            .filter_map(|item| item.get("label").and_then(norito::json::Value::as_str))
            .collect::<Vec<_>>();
        let completion_kind = |label: &str| {
            completions
                .as_array()
                .expect("completion array")
                .iter()
                .find(|item| item.get("label").and_then(norito::json::Value::as_str) == Some(label))
                .and_then(|item| item.get("kind"))
                .and_then(norito::json::Value::as_u64)
        };
        assert!(labels.contains(&"seiyaku"));
        assert!(labels.contains(&"kotoage"));
        assert!(labels.contains(&"hajimari"));
        assert!(labels.contains(&"kaizen"));
        assert!(labels.contains(&"誓約"));
        assert!(labels.contains(&"言挙げ"));
        assert!(labels.contains(&"始まり"));
        assert!(labels.contains(&"改善"));
        assert!(labels.contains(&"&&"));
        assert_eq!(completion_kind("json"), Some(14));
        assert_eq!(completion_kind("div_round"), Some(2));
        for current in V1_SUM_PATHS
            .iter()
            .chain(V1_ROUNDING_PATHS)
            .chain(V1_LIST_MEMBER_NAMES)
            .chain(V1_CONTEXTUAL_COMPLETIONS.iter().map(|(label, _)| label))
        {
            assert!(
                labels.contains(current),
                "missing canonical V1 completion `{current}`"
            );
        }
        for current in [
            "json",
            "int",
            "decimal",
            "quantity",
            "List",
            "AccountView",
            "AssetDefinitionView",
            "QueryPage",
            "Option::some",
            "Result::err",
            "Rounding::nearest_even",
            "div_round",
            "try_push",
            "enumerate",
            "get_int",
            "get_decimal",
            "get_quantity",
            "get_json",
            "get_name",
            "get_account_id",
            "get_asset_definition_id",
            "get_nft_id",
            "get_bytes_hex",
            "ledger::query::account",
            "ledger::query::asset",
            "ledger::query::asset_definition",
            "ledger::query::domain",
            "ledger::query::nft",
            "ledger::query::accounts",
            "ledger::query::assets",
            "ledger::query::asset_definitions",
            "ledger::query::domains",
            "ledger::query::nfts",
        ] {
            assert!(
                labels.contains(&current),
                "missing V1 completion `{current}`"
            );
        }
        assert_eq!(
            labels.iter().copied().collect::<BTreeSet<_>>().len(),
            labels.len(),
            "completion labels must be stable and duplicate-free",
        );
        for retired in [
            "contract",
            "entry",
            "init",
            "upgrade",
            "json!",
            "option::some",
            "option::none",
            "result::ok",
            "result::err",
            "Amount",
            "get_amount",
            "get_numeric",
            "json_get_int",
            "json_get_numeric",
        ] {
            assert!(!labels.contains(&retired));
        }
    }
    #[test]
    fn lsp_quick_fixes_are_exact_current_document_workspace_edits() {
        let session = CompilerSession::default();
        let uri = "file:///workspace/fixes.ko";
        let indexed = "seiyaku C { fn write() { var List<int, 2> values = [1]; values[0] = 2; } }";
        let indexed_actions = lsp_code_action_items(&session, uri, indexed);
        let indexed_action = indexed_actions
            .as_array()
            .expect("code action array")
            .iter()
            .find(|action| {
                action
                    .pointer("/diagnostics/0/code")
                    .and_then(norito::json::Value::as_str)
                    == Some("E_LIST_UNSAFE_INDEX")
            })
            .expect("checked-list quick fix");
        assert_eq!(
            indexed_action
                .pointer("/kind")
                .and_then(norito::json::Value::as_str),
            Some("quickfix")
        );
        let indexed_edit = indexed_action
            .pointer("/edit/changes")
            .and_then(|changes| changes.get(uri))
            .and_then(norito::json::Value::as_array)
            .and_then(|edits| edits.first())
            .expect("checked-list workspace edit");
        assert_eq!(
            indexed_edit
                .get("newText")
                .and_then(norito::json::Value::as_str),
            Some("values.set(index: 0, value: 2);")
        );
        let start = indexed_edit
            .pointer("/range/start/character")
            .and_then(norito::json::Value::as_u64)
            .expect("indexed edit start") as usize;
        let end = indexed_edit
            .pointer("/range/end/character")
            .and_then(norito::json::Value::as_u64)
            .expect("indexed edit end") as usize;
        assert_eq!(&indexed[start..end], "values[0] = 2;");
        let unresolved = "seiyaku C { fn f() { target(1, second: 2); } }";
        let unresolved_diagnostics = collect_lsp_diagnostics(&session, uri, unresolved);
        assert!(unresolved_diagnostics.diagnostics.iter().any(|diagnostic| {
            diagnostic.severity == Severity::Error && diagnostic.fix.is_none()
        }));
        let unresolved_actions = lsp_code_action_items(&session, uri, unresolved);
        assert!(
            unresolved_actions
                .as_array()
                .expect("code action array")
                .is_empty(),
            "an unresolved call must not receive a guessed parameter-name edit"
        );
        let positional =
            "seiyaku C { struct Pair { int left, int right } fn f() { let pair = Pair(1, 2); } }";
        let positional_actions = lsp_code_action_items(&session, uri, positional);
        let positional_action = positional_actions
            .as_array()
            .expect("code action array")
            .iter()
            .find(|action| {
                action
                    .pointer("/diagnostics/0/code")
                    .and_then(norito::json::Value::as_str)
                    == Some("E_POSITIONAL_STRUCT")
            })
            .expect("positional-struct quick fix");
        let positional_edit = positional_action
            .pointer("/edit/changes")
            .and_then(|changes| changes.get(uri))
            .and_then(norito::json::Value::as_array)
            .and_then(|edits| edits.first())
            .expect("positional-struct workspace edit");
        assert_eq!(
            positional_edit
                .get("newText")
                .and_then(norito::json::Value::as_str),
            Some("Pair { left: 1, right: 2, }")
        );
    }
    #[test]
    fn lsp_check_accepts_reusable_modules_without_artifact_codegen() {
        let session = CompilerSession::default();
        let module = lsp_diagnostics(
            &session,
            "file:///workspace/math.ko",
            "module Math { export fn value() -> int { return 1; } }",
        );
        assert!(
            module.is_empty(),
            "valid reusable modules must not receive deployable-only K4003: {module:?}",
        );
        let invalid = lsp_diagnostics(
            &session,
            "file:///workspace/broken.ko",
            "module Broken { export fn value( -> int { return 1; } }",
        );
        assert!(!invalid.is_empty());
    }
    #[test]
    fn lsp_open_documents_never_infer_cross_file_graph_authority() {
        let driver = BuildDriver::new(CompilerSession::default(), "lsp-test");
        let app_uri = "file:///workspace/app.ko";
        let module_uri = "file:///workspace/math.ko";
        let documents = HashMap::from([
            (
                app_uri.to_owned(),
                "seiyaku App { view fn run() authorize(anyone) -> int { return Math::value(); } }"
                    .to_owned(),
            ),
            (
                module_uri.to_owned(),
                "module Math { export fn value() -> int { return 1; } }".to_owned(),
            ),
        ]);
        let diagnostics = collect_lsp_project_diagnostics(&driver, &documents);
        let diagnostic = diagnostics[app_uri]
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "E_PROJECT_MANIFEST_REQUIRED")
            .expect("open root and module must require explicit graph authority");
        let span = diagnostic.primary_span.as_ref().expect("exact call span");
        assert_eq!(span.source.as_deref(), Some(app_uri));
        assert!(
            diagnostic
                .help
                .as_deref()
                .is_some_and(|help| help.contains("Musubi"))
        );
        assert!(diagnostics[module_uri].diagnostics.is_empty());
    }
    #[test]
    fn lsp_project_uses_open_overlays_on_the_exact_locked_graph() {
        let root = std::env::temp_dir().join(format!(
            "koto-lsp-project-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("create LSP project root");
        let app = root.join("app.ko");
        let module = root.join("math.ko");
        let manifest = root.join("Musubi.toml");
        std::fs::write(
            &app,
            "seiyaku App { view fn run() authorize(anyone) -> int { return Math::value(); } }",
        )
        .expect("write valid project root");
        std::fs::write(
            &module,
            "module Math { export fn value() -> int { return 7; } }",
        )
        .expect("write project module");
        let manifest_text = "[lib]\nexports = [\"value\"]\n";
        std::fs::write(&manifest, manifest_text).unwrap();
        let project = fixture_project(
            &root,
            "app.ko",
            Some(("example/math@1.0.0", "Math", "math.ko")),
            &manifest,
            manifest_text,
            "value",
        );
        let app_uri = format!(
            "file://{}",
            app.canonicalize().expect("canonical app path").display()
        );
        let overlay =
            "seiyaku App { view fn run() authorize(anyone) -> int { return Math::missing(); } }"
                .to_owned();
        let documents = HashMap::from([(app_uri.clone(), overlay.clone())]);
        let driver = BuildDriver::new(CompilerSession::default(), "lsp-project-test");
        let diagnostics = collect_lsp_workspace_diagnostics(&driver, &documents, Some(&project));
        let diagnostic = diagnostics[&app_uri]
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "E_UNEXPORTED_SYMBOL")
            .expect("open root overlay is checked against the locked package export set");
        let span = diagnostic
            .primary_span
            .as_ref()
            .expect("exact overlay span");
        assert_eq!(span.source.as_deref(), Some(app_uri.as_str()));
        assert!(span.package_identity.is_none());
        let range = span.byte_range.expect("overlay byte range");
        let start = usize::try_from(range.start).expect("range start fits usize");
        let end = usize::try_from(range.end).expect("range end fits usize");
        assert_eq!(&overlay[start..end], "Math::missing");
        assert!(
            diagnostics[&app_uri]
                .diagnostics
                .iter()
                .all(|diagnostic| diagnostic.code != "E_PROJECT_MANIFEST_REQUIRED"),
            "an explicit LSP project must provide graph authority"
        );
        // Unopened dependencies stay in the semantic graph and retain their exact text.
        let documents = HashMap::new();
        let workspace = editor_lsp::Workspace::new(&documents, Some(&project), &app_uri, false);
        let root_source = &project.graph.as_source().expect("source graph").root.source;
        let request = norito::json!({"params": {"textDocument": {"uri": (app_uri.clone())}, "position": {"line": 0, "character": (root_source.find("value()").unwrap())}, "context": {"includeDeclaration": true}, "newName": "renamed"}});
        let module_uri = lsp_path_file_uri(&module.canonicalize().unwrap()).unwrap();
        let definition = workspace
            .response("textDocument/definition", &request)
            .unwrap();
        assert_eq!(
            definition
                .pointer("/uri")
                .and_then(norito::json::Value::as_str),
            Some(module_uri.as_str())
        );
        let references = workspace
            .response("textDocument/references", &request)
            .unwrap();
        assert_eq!(references.as_array().unwrap().len(), 2);
        let renamed = workspace.response("textDocument/rename", &request).unwrap();
        assert_eq!(
            renamed
                .pointer("/documentChanges")
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            3,
            "owned exports rename the root reference, declaration, and exact manifest token together"
        );
        // Unopened source changes are reloaded from disk under the same locked manifest.
        let invalid_source =
            "module Math { /* 金庫😀 */ export fn value() -> int { return missing; } }";
        std::fs::write(&module, invalid_source).expect("write unopened dependency error");
        let diagnostics = collect_lsp_workspace_diagnostics(&driver, &documents, Some(&project));
        let diagnostic = diagnostics[&module_uri]
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "K2002")
            .expect("unopened dependency error");
        assert_eq!(
            diagnostic.primary_source.as_ref().unwrap().text(),
            invalid_source
        );
        let rendered = lsp_diagnostic_value(diagnostic, "");
        let expected_character = invalid_source[..invalid_source.find("missing").unwrap()]
            .encode_utf16()
            .count() as u64;
        assert_eq!(
            rendered
                .pointer("/range/start/character")
                .and_then(norito::json::Value::as_u64),
            Some(expected_character)
        );
        std::fs::write(
            &module,
            "module Math { /* 金庫😀 */ export fn value() -> int { 7 } fn helper(int unused) -> int { 1 } }",
        )
        .expect("write unopened dependency lint");
        let diagnostics = collect_lsp_workspace_diagnostics(&driver, &documents, Some(&project));
        let warning = diagnostics[&module_uri]
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "K5003")
            .expect("unopened dependency lint");
        assert_eq!(
            warning.primary_source.as_ref().unwrap().package_identity(),
            Some("example/math@1.0.0")
        );
        let captured = warning.primary_source.as_ref().unwrap().text();
        let range = warning.primary_span.as_ref().unwrap().byte_range.unwrap();
        assert_eq!(
            &captured[range.start as usize..range.end as usize],
            "unused"
        );
        assert_eq!(
            lsp_diagnostic_value(warning, "")
                .pointer("/range/start/character")
                .and_then(norito::json::Value::as_u64),
            Some(captured[..range.start as usize].encode_utf16().count() as u64)
        );
        std::fs::remove_dir_all(root).expect("remove LSP project root");
    }
    #[test]
    fn lsp_diagnostics_project_scalar_columns_and_captured_related_sources_to_utf16() {
        let source = SourceFile::new(SourceId(0), "file:///日本語.ko", "金庫😀x\n次😀y");
        let primary = SourceSpan {
            package_identity: None,
            source: Some(source.name().to_owned()),
            start: SourcePosition { line: 1, column: 4 },
            end: SourcePosition { line: 1, column: 5 },
            byte_range: None,
        };
        let mut diagnostic = Diagnostic::error(
            "K2002",
            DiagnosticPhase::Resolve,
            "unresolved x",
            Some(primary),
        );
        diagnostic.labels.push(DiagnosticLabel {
            span: SourceSpan {
                package_identity: None,
                source: Some(source.name().to_owned()),
                start: SourcePosition { line: 2, column: 3 },
                end: SourcePosition { line: 2, column: 4 },
                byte_range: None,
            },
            message: "関連する定義 y".to_owned(),
        });
        diagnostic
            .notes
            .push("この値は現在のスコープにありません。".to_owned());
        diagnostic.help = Some("使う前に値を宣言してください。".to_owned());
        diagnostic.capture_source(&source);
        let rendered = lsp_diagnostic_value(&diagnostic, "the editor has a newer buffer");
        assert_eq!(rendered.pointer("/range"), Some(&lsp_range(0, 4, 0, 5)));
        assert_eq!(
            rendered.pointer("/relatedInformation/0/location/range"),
            Some(&lsp_range(1, 3, 1, 4))
        );
        assert_eq!(
            rendered
                .pointer("/message")
                .and_then(norito::json::Value::as_str),
            Some(
                "unresolved x\n\nnote: この値は現在のスコープにありません。\n\nhelp: 使う前に値を宣言してください。"
            )
        );
        assert_eq!(
            rendered
                .pointer("/relatedInformation/0/message")
                .and_then(norito::json::Value::as_str),
            Some("関連する定義 y")
        );
        assert_eq!(
            lsp_source_position("", &SourcePosition { line: 3, column: 9 }),
            (2, 8)
        );
    }
    #[test]
    fn lsp_document_store_is_bounded_and_removes_rejected_updates() {
        let mut documents = HashMap::new();
        for index in 0..MAX_LSP_OPEN_DOCUMENTS {
            store_lsp_document(
                &mut documents,
                &format!("file:///workspace/{index}.ko"),
                "module M {}",
            )
            .expect("document below count limit");
        }
        let error = store_lsp_document(
            &mut documents,
            "file:///workspace/overflow.ko",
            "module Overflow {}",
        )
        .expect_err("document count must be bounded");
        assert!(error.contains("workspace limit"));
        assert!(!documents.contains_key("file:///workspace/overflow.ko"));
        let huge_uri = format!("file:///{}", "u".repeat(MAX_LSP_URI_BYTES));
        let error = store_lsp_document(&mut documents, &huge_uri, "module Uri {}")
            .expect_err("document URI must be bounded");
        assert!(error.contains("document URI exceeds"));
        let existing = "file:///workspace/0.ko";
        let oversized = "x".repeat(MAX_SOURCE_BYTES + 1);
        let error = store_lsp_document(&mut documents, existing, &oversized)
            .expect_err("oversized changed document must fail");
        assert!(error.contains("V1 source limit"));
        assert!(
            !documents.contains_key(existing),
            "a rejected update must not leave stale source available to formatting",
        );
    }
    #[test]
    fn lsp_framing_rejects_oversized_and_ambiguous_inputs_before_allocation() {
        let oversized = format!("Content-Length: {}\r\n\r\n", MAX_LSP_MESSAGE_BYTES + 1);
        let error = read_lsp_message(&mut std::io::Cursor::new(oversized.into_bytes()))
            .expect_err("oversized LSP frame must fail");
        assert!(error.contains("exceeds"), "unexpected error: {error}");
        let duplicate = b"Content-Length: 2\r\nContent-Length: 2\r\n\r\n{}";
        let error = read_lsp_message(&mut std::io::Cursor::new(duplicate))
            .expect_err("duplicate length must fail");
        assert!(error.contains("duplicate"), "unexpected error: {error}");
        let mixed_case_duplicate = b"content-length: 2\r\nCONTENT-LENGTH: 2\r\n\r\n{}";
        let error = read_lsp_message(&mut std::io::Cursor::new(mixed_case_duplicate))
            .expect_err("header names are case-insensitive");
        assert!(error.contains("duplicate"), "unexpected error: {error}");
        let lowercase = b"content-length: 2\r\n\r\n{}";
        read_lsp_message(&mut std::io::Cursor::new(lowercase))
            .expect("lowercase header is valid")
            .expect("one lowercase-header message");
        let malformed = b"Content-Length 2\r\n\r\n{}";
        let error = read_lsp_message(&mut std::io::Cursor::new(malformed))
            .expect_err("malformed header must fail closed");
        assert!(error.contains("malformed"), "unexpected error: {error}");
        let long_header = format!("{}\n", "x".repeat(MAX_LSP_HEADER_LINE_BYTES + 1));
        let error = read_lsp_message(&mut std::io::Cursor::new(long_header.into_bytes()))
            .expect_err("oversized header line must fail");
        assert!(
            error.contains("header line exceeds"),
            "unexpected error: {error}"
        );
    }
    #[test]
    fn multi_target_diagnostics_preserve_target_identity_and_semantics_require_selection() {
        let root = std::env::temp_dir().join(format!(
            "koto-multitarget-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let root = root.canonicalize().unwrap();
        std::fs::write(root.join("common.ko"), "fn common() -> int { missing }").unwrap();
        for name in ["a", "b"] {
            std::fs::write(root.join(format!("{name}.ko")),format!("seiyaku {name} {{ include \"./common.ko\"; view fn value() authorize(anyone) -> int {{ common() }} }}")).unwrap();
        }
        let targets = ["a", "b"]
            .into_iter()
            .map(|name| ProjectTarget {
                name: name.into(),
                project: load_source_project(
                    &root.join(format!("{name}.ko")),
                    &root,
                    &BTreeMap::new(),
                )
                .unwrap(),
                test_context: None,
            })
            .collect();
        let mut snapshot = ProjectSnapshot {
            targets,
            selected_target: None,
        };
        let mut documents = HashMap::new();
        let uri = lsp_path_file_uri(&root.join("common.ko")).unwrap();
        let error = selected_project(&snapshot, &uri, &documents).unwrap_err();
        assert!(error.contains("--contract"));
        assert!(error.contains("a, b"));
        let root_uri = lsp_path_file_uri(&root.join("a.ko")).unwrap();
        assert_eq!(
            selected_project(&snapshot, &root_uri, &documents)
                .unwrap()
                .unwrap()
                .graph
                .as_source()
                .expect("source graph")
                .root
                .source_name,
            "a.ko"
        );
        let lowercase = lsp_path_file_uri(&root.join("loose.ko")).unwrap();
        let uppercase = lsp_path_file_uri(&root.join("loose.KO")).unwrap();
        for source_uri in [&lowercase, &uppercase] {
            documents.insert(
                source_uri.clone(),
                "module Loose { fn value() -> int { missing } }".into(),
            );
        }
        let driver = BuildDriver::new(CompilerSession::default(), "multi-target-test");
        let diagnostics = collect_target_diagnostics(&driver, &documents, &snapshot);
        assert!(diagnostics.contains_key(&lowercase));
        assert!(
            !diagnostics.contains_key(&uppercase),
            "source extensions remain case-sensitive"
        );
        let notes = diagnostics[&uri]
            .diagnostics
            .iter()
            .flat_map(|diagnostic| diagnostic.notes.iter())
            .collect::<Vec<_>>();
        assert!(
            notes
                .iter()
                .any(|note| note.as_str() == "contract target: a")
        );
        assert!(
            notes
                .iter()
                .any(|note| note.as_str() == "contract target: b")
        );
        snapshot.selected_target = Some("b".into());
        assert_eq!(
            selected_project(&snapshot, &uri, &documents)
                .unwrap()
                .unwrap()
                .graph
                .as_source()
                .expect("source graph")
                .root
                .source_name,
            "b.ko"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn project_test_lenses_keep_exact_locked_package_command() {
        let mut result = norito::json!([{"command":{"arguments":[{"uri":"file:///workspace/tests/a.ko","name":"works","args":["test","run","--filter","works","--exact","/workspace/tests/a.ko"]}]}}]);
        project_test_lenses(
            &mut result,
            Some(&TestContext {
                manifest_path: "/workspace/Musubi.toml".into(),
                package: "local/demo".into(),
                contract: "a".into(),
                network: Some("taira".into()),
                config_path: Some("/workspace/client.toml".into()),
            }),
            &ServerOptions {
                chain_discriminant: 42,
                zk_enabled: true,
                ..ServerOptions::default()
            },
        );
        let payload = result.pointer("/0/command/arguments/0").unwrap();
        assert_eq!(
            payload.get("tool").and_then(norito::json::Value::as_str),
            Some("musubi")
        );
        assert_eq!(
            payload.get("args").unwrap(),
            &norito::json!([
                "test",
                "--manifest-path",
                "/workspace/Musubi.toml",
                "--package",
                "local/demo",
                "--contract",
                "a",
                "--filter",
                "works",
                "--exact",
                "--chain-discriminant",
                "42",
                "--zk",
                "--locked",
                "--offline",
                "--network",
                "taira",
                "--config",
                "/workspace/client.toml"
            ])
        );
    }
    fn target_selection_fixture() -> (PathBuf, ProjectSnapshot) {
        let root = std::env::temp_dir().join(format!(
            "koto-selected-target-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&root).unwrap();
        let root = root.canonicalize().unwrap();
        std::fs::write(root.join("common.ko"), "fn common() -> int { 1 }").unwrap();
        let targets = ["a", "b"].into_iter().map(|name| {
            let path = root.join(format!("{name}.ko"));
            std::fs::write(&path, format!("seiyaku {name} {{ include \"./common.ko\"; view fn value() authorize(anyone) -> int {{ common() }} }}")).unwrap();
            ProjectTarget {
                name: name.into(),
                project: load_source_project(&path, &root, &BTreeMap::new()).unwrap(),
                test_context: Some(TestContext {
                    manifest_path: root.join("Musubi.toml"),
                    package: "local/demo".into(),
                    contract: name.into(),
                    network: None,
                    config_path: None,
                }),
            }
        }).collect();
        (
            root,
            ProjectSnapshot {
                targets,
                selected_target: Some("b".into()),
            },
        )
    }
    #[test]
    fn explicit_target_selection_requires_requested_source_membership() {
        let (root, snapshot) = target_selection_fixture();
        for name in ["a.ko", "external.ko"] {
            let uri = lsp_path_file_uri(&root.join(name)).unwrap();
            let error = selected_project(&snapshot, &uri, &HashMap::new()).unwrap_err();
            assert!(error.contains("does not own source"), "{error}");
            assert!(error.contains("--contract"), "{error}");
        }
        for name in ["b.ko", "common.ko"] {
            let uri = lsp_path_file_uri(&root.join(name)).unwrap();
            let project = selected_project(&snapshot, &uri, &HashMap::new())
                .unwrap()
                .unwrap();
            assert_eq!(project.graph.as_source().unwrap().root.source_name, "b.ko");
        }
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn test_module_selection_requires_its_declared_exact_contract_root() {
        let (root, mut snapshot) = target_selection_fixture();
        let uri = lsp_path_file_uri(&root.join("checks.test.ko")).unwrap();
        for target in ["a.ko", "common.ko"] {
            let documents = HashMap::from([(
                uri.clone(),
                format!(
                    "module Checks {{ koto_test {{ target: \"./{target}\" }}\n#[test] fn works() {{}} }}"
                ),
            )]);
            let error = selected_project(&snapshot, &uri, &documents).unwrap_err();
            assert!(error.contains("exact contract root"), "{error}");
        }
        let documents = HashMap::from([(
            uri.clone(),
            "module Checks { koto_test { target: \"./b.ko\" }\n#[test] fn works() {} }".into(),
        )]);
        assert!(
            selected_project(&snapshot, &uri, &documents)
                .unwrap()
                .is_some()
        );
        snapshot.selected_target = None;
        let documents = HashMap::from([(
            uri.clone(),
            "module Checks { koto_test { target: \"./common.ko\" }\n#[test] fn works() {} }".into(),
        )]);
        assert!(
            selected_project(&snapshot, &uri, &documents)
                .unwrap_err()
                .contains("not an exact contract root")
        );
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn wrong_target_semantic_requests_return_errors_without_test_lenses() {
        struct Provider(ProjectSnapshot);
        impl ProjectProvider for Provider {
            fn reload(&mut self, _: &BTreeMap<PathBuf, String>) -> Result<ProjectSnapshot, String> {
                Ok(self.0.clone())
            }
        }
        let (root, snapshot) = target_selection_fixture();
        let uri = lsp_path_file_uri(&root.join("checks.test.ko")).unwrap();
        let mut frames = Vec::new();
        write_lsp_message(&mut frames, &norito::json!({"jsonrpc":"2.0", "method":"textDocument/didOpen", "params":{"textDocument":{"uri":(uri.clone()), "version":1, "text":"module Checks { koto_test { target: \"./a.ko\" }\n#[test] fn works() {} }"}}})).unwrap();
        for (index, method) in [
            "textDocument/codeLens",
            "textDocument/hover",
            "textDocument/codeAction",
        ]
        .into_iter()
        .enumerate()
        {
            let id = index as u64 + 1;
            write_lsp_message(&mut frames, &norito::json!({"jsonrpc":"2.0", "id":id, "method":method, "params":{"textDocument":{"uri":(uri.clone())}, "position":{"line":1,"character":12}}})).unwrap();
        }
        let inbox = lsp_transport::Inbox::new();
        inbox.read_from(&mut std::io::Cursor::new(frames));
        let mut output = Vec::new();
        language_server_dispatch(
            &inbox,
            &mut output,
            Some(&mut Provider(snapshot)),
            &ServerOptions::default(),
        )
        .unwrap();
        let mut reader = std::io::Cursor::new(output);
        let mut errors = 0;
        while let Some(message) = read_lsp_message(&mut reader).unwrap() {
            if message.get("id").is_some() {
                assert_eq!(
                    message
                        .pointer("/error/code")
                        .and_then(norito::json::Value::as_i64),
                    Some(-32602)
                );
                assert!(
                    message
                        .pointer("/error/message")
                        .and_then(norito::json::Value::as_str)
                        .unwrap()
                        .contains("exact contract root")
                );
                assert!(
                    message.get("result").is_none(),
                    "no lens or loose-buffer semantic result: {message:?}"
                );
                errors += 1;
            }
        }
        assert_eq!(errors, 3);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn standalone_lsp_rejects_missing_source_root_before_reading_stdin() {
        let absent = std::env::temp_dir().join(format!(
            "koto-absent-source-root-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        assert!(
            run_project_stdio(
                ServerOptions {
                    source_root: Some(absent),
                    ..ServerOptions::default()
                },
                None
            )
            .unwrap_err()
            .contains("read source root")
        );
    }
}
