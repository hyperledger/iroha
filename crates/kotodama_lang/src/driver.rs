//! Shared content-addressed Kotodama build driver.
//!
//! All developer entry points use this module for cache validation and output publication. A build
//! record is a commit marker: it is written only after the artifact, manifest, interface, and
//! hash-keyed sidecars have been durably published. Cache hits recompute every output digest and
//! the canonical deployable code hash before skipping compilation. Cache reads are bounded so a
//! corrupted or adversarial local target directory cannot force unbounded allocation before
//! authentication.
use crate::{
    ast::SourceUnitKind,
    diagnostic::{Diagnostic, DiagnosticBundle, DiagnosticLabel, DiagnosticPhase, SourceSpan},
    linker::{
        ImportBinding, MAX_MODULE_GRAPH_SOURCE_BYTES, MAX_MODULE_GRAPH_SOURCES, ModuleBuildGraph,
        SourceGraphError, SourceLinkRequest, SourceModuleUnit, SourcePackageGraphRequest,
        SourcePackageUnit, ValidatedSourcePackageGraph,
    },
    metadata::contract_code_hash,
    session::{CompileOutput, CompileRequest, CompilerSession},
    source::{SourceFile, SourceId, TextRange},
    spanned_ast::{AstNodeKind, SpannedProgram},
};
use iroha_crypto::Hash;
use iroha_data_model::smart_contract::manifest::ContractManifest;
use norito::json;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    error::Error,
    fmt, fs,
    path::{Component, Path, PathBuf},
    sync::{Arc, OnceLock},
};
mod source_bundle;
pub use source_bundle::{
    SourceInventory, load_source_inventory, load_source_package_inventory, load_source_project,
};
const BUILD_RECORD_SCHEMA: &str = "kotodama-build-v1";
const DEFAULT_TARGET_ROOT: &str = "target/kotodama";
const MAX_BUILD_RECORD_BYTES: usize = 4 * 1024;
const MAX_CACHED_OUTPUT_BYTES: usize = 32 * 1024 * 1024;
#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(test)]
static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static CURRENT_TOOLCHAIN_FINGERPRINT: OnceLock<String> = OnceLock::new();
/// Whether generated files may be updated or must already match exactly.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PublishMode {
    /// Atomically publish changed outputs.
    #[default]
    Write,
    /// Verify that every output and build record is current without writing.
    Verify,
}
/// Stable output paths known before compilation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishLayout {
    /// Deployable `.to` bytecode path.
    pub artifact: PathBuf,
    /// Canonical compiler manifest JSON path.
    pub manifest: PathBuf,
    /// Optional generated interface JSON path.
    pub interface: Option<PathBuf>,
    manifest_storage: ManifestStorage,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum ManifestStorage {
    #[default]
    Output,
    Sidecar,
}
impl PublishLayout {
    /// Construct standard paths below `target/kotodama/<profile>/`.
    pub fn standard(
        target_root: impl AsRef<Path>,
        profile: &str,
        stem: &str,
        include_interface: bool,
    ) -> Result<Self, BuildError> {
        validate_profile(profile)?;
        validate_stem(stem)?;
        let directory = target_root.as_ref().join(profile);
        Ok(Self {
            artifact: directory.join(format!("{stem}.to")),
            manifest: directory.join(format!("{stem}.manifest.json")),
            interface: include_interface.then(|| directory.join(format!("{stem}.interface.json"))),
            manifest_storage: ManifestStorage::Output,
        })
    }
    /// Construct standard paths below the repository default target root.
    pub fn default_target(
        profile: &str,
        stem: &str,
        include_interface: bool,
    ) -> Result<Self, BuildError> {
        Self::standard(DEFAULT_TARGET_ROOT, profile, stem, include_interface)
    }
    /// Construct a layout around an explicit artifact path.
    pub fn for_artifact(
        artifact: PathBuf,
        manifest: Option<PathBuf>,
        interface: Option<PathBuf>,
    ) -> Result<Self, BuildError> {
        let stem = artifact
            .file_stem()
            .and_then(|value| value.to_str())
            .ok_or_else(|| BuildError::InvalidPath {
                path: artifact.clone(),
                message: "artifact path must have a UTF-8 file stem".to_owned(),
            })?;
        let manifest = manifest
            .unwrap_or_else(|| output_parent(&artifact).join(format!("{stem}.manifest.json")));
        Ok(Self {
            artifact,
            manifest,
            interface,
            manifest_storage: ManifestStorage::Output,
        })
    }
    /// Keep the authenticated manifest as a content-addressed build sidecar.
    ///
    /// This is used when a frontend returns the manifest through another channel, such as `koto
    /// build --manifest-out -`. The manifest remains available to authenticate no-op builds without
    /// publishing an unexpected sibling file beside the requested artifact.
    #[must_use]
    pub fn with_sidecar_manifest(mut self) -> Self {
        self.manifest_storage = ManifestStorage::Sidecar;
        self
    }
    fn resolve(&self, artifact_hash: &str, input_fingerprint: &str) -> BuildPaths {
        let parent = output_parent(&self.artifact);
        let sidecars = parent
            .join(".sidecars")
            .join(artifact_hash)
            .join(input_fingerprint);
        let file_name = self
            .artifact
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("seiyaku.to"));
        let record = parent
            .join(".fingerprints")
            .join(format!("{}.record", file_name.to_string_lossy()));
        let manifest = match self.manifest_storage {
            ManifestStorage::Output => self.manifest.clone(),
            ManifestStorage::Sidecar => sidecars.join("manifest.json"),
        };
        BuildPaths {
            artifact: self.artifact.clone(),
            manifest,
            interface: self.interface.clone(),
            source_map: sidecars.join("source-map.json"),
            budget: sidecars.join("budget.json"),
            record,
        }
    }
    fn static_paths(&self) -> Vec<PathBuf> {
        let provisional = self.resolve("artifact", "input");
        let mut paths = vec![
            provisional.artifact,
            provisional.manifest,
            provisional.record,
        ];
        paths.extend(provisional.interface);
        paths
    }
}
/// Every output path for a completed build.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildPaths {
    /// Deployable `.to` bytecode.
    pub artifact: PathBuf,
    /// Canonical manifest JSON.
    pub manifest: PathBuf,
    /// Optional interface JSON.
    pub interface: Option<PathBuf>,
    /// Hash-keyed source map.
    pub source_map: PathBuf,
    /// Hash-keyed compiler budget report.
    pub budget: PathBuf,
    /// Transactional build commit record.
    pub record: PathBuf,
}
impl BuildPaths {
    fn all_paths(&self) -> Vec<PathBuf> {
        let mut paths = vec![
            self.artifact.clone(),
            self.manifest.clone(),
            self.source_map.clone(),
            self.budget.clone(),
            self.record.clone(),
        ];
        paths.extend(self.interface.iter().cloned());
        paths
    }
}
/// Whether compilation was skipped or performed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildStatus {
    /// Every authenticated output was already current; no file was written.
    Fresh,
    /// Compilation ran and outputs were published or verified.
    Built,
}
/// Successful content-addressed build result.
#[derive(Clone, Debug)]
pub struct BuildOutcome {
    /// Cache status.
    pub status: BuildStatus,
    /// Canonical deployable artifact hash.
    pub artifact_hash: Hash,
    /// Deployable bytes (read from cache on a fresh result).
    pub artifact: Vec<u8>,
    /// Canonical contract manifest.
    pub manifest: ContractManifest,
    /// Published or verified paths.
    pub paths: BuildPaths,
}
/// One lint finding paired with the project source that owns it.
#[derive(Clone, Debug)]
pub struct ProjectLintWarning {
    /// Locked package that owns the source, or `None` for a deployable root or
    /// diagnostics-only open document.
    pub package_identity: Option<String>,
    /// Portable logical source path.
    pub source_name: String,
    /// Canonical compiler lint finding.
    pub warning: crate::lint::LintWarning,
}
/// Immutable editable manifest snapshot supplied by the project resolver.
#[derive(Clone, Debug)]
pub struct ProjectManifestSource {
    path: PathBuf,
    text: String,
    exports: BTreeMap<(String, String), TextRange>,
}
impl ProjectManifestSource {
    /// Capture the exact manifest text and export token ranges supplied by its format parser.
    ///
    /// `path` identifies the editable local manifest. Each range includes the entire token
    /// for one resolved package export; source paths remain independently owned by the graph.
    pub fn new(
        path: PathBuf,
        text: String,
        exports: BTreeMap<(String, String), TextRange>,
    ) -> Self {
        Self {
            path,
            text,
            exports,
        }
    }
    /// Canonical path of the editable local manifest.
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// Exact manifest text used to resolve the graph and capture its token ranges.
    pub fn text(&self) -> &str {
        &self.text
    }
    /// Exact export token for one identified package, including its original quoting and escapes.
    pub fn export_range(&self, package: &str, name: &str) -> Option<TextRange> {
        self.exports
            .get(&(package.to_owned(), name.to_owned()))
            .copied()
    }
}
/// Unambiguous owner of one source in a locked Kotodama project graph.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProjectSourceKey {
    /// Locked package identity, or `None` for a standalone source graph.
    pub package_identity: Option<String>,
    /// Canonical project-relative logical source path.
    pub source_name: String,
}
/// One exact graph supplied by a project resolver.
#[derive(Clone, Debug)]
pub enum LoadedProjectGraph {
    /// A standalone source root and its explicitly bound packages.
    Source(SourceLinkRequest),
    /// A reusable library package and its locked dependency graph.
    Package(SourcePackageGraphRequest),
}
impl LoadedProjectGraph {
    /// Borrow the standalone source graph when this graph has a source root.
    pub fn as_source(&self) -> Option<&SourceLinkRequest> {
        match self {
            Self::Source(graph) => Some(graph),
            Self::Package(_) => None,
        }
    }
    /// Mutably borrow the standalone source graph when this graph has a source root.
    pub fn as_source_mut(&mut self) -> Option<&mut SourceLinkRequest> {
        match self {
            Self::Source(graph) => Some(graph),
            Self::Package(_) => None,
        }
    }
}
/// Exact source graph and editor metadata supplied by a project resolver.
#[derive(Clone, Debug)]
pub struct LoadedSourceProject {
    /// Root, imports, exports, and complete locked package graph.
    pub graph: LoadedProjectGraph,
    /// Canonical physical path for every graph-owned logical source.
    pub source_paths: BTreeMap<ProjectSourceKey, PathBuf>,
    /// Editable local manifest snapshots. An empty list gives no authority to edit exports.
    pub manifests: Vec<ProjectManifestSource>,
    /// Resolved project lint levels; the default configuration warns for every lint.
    pub lints: crate::session::LintConfig,
}

fn project_source_unit_span(
    source: &SourceModuleUnit,
    program: &SpannedProgram,
) -> Option<SourceSpan> {
    let node = program
        .facts
        .source_map
        .nodes()
        .find(|node| node.kind == AstNodeKind::SourceUnit)?;
    let file = SourceFile::new(
        program.facts.source_map.source(),
        source.source_name.as_str(),
        source.source.as_str(),
    );
    Some(SourceSpan::from_range(&file, node.range))
}
/// One ordinary source build request.
#[derive(Clone, Debug)]
pub struct SourceBuildRequest {
    /// Complete source text.
    pub source: String,
    /// Logical path used by diagnostics and sidecars.
    pub source_name: String,
    /// Build profile and output namespace.
    pub profile: String,
    /// Output layout.
    pub layout: PublishLayout,
    /// Write or verification policy.
    pub mode: PublishMode,
}
/// One locked source-module graph built lazily after cache authentication.
#[derive(Clone, Debug)]
pub struct LinkedSourceBuildRequest {
    /// Seiyaku root, explicit imports, and locked transitive module sources.
    pub graph: SourceLinkRequest,
    /// Logical root path used by diagnostics and sidecars.
    pub source_name: String,
    /// Build profile and output namespace.
    pub profile: String,
    /// Output layout.
    pub layout: PublishLayout,
    /// Write or verification policy.
    pub mode: PublishMode,
}
/// Shared compiler, cache validator, and atomic publisher.
#[derive(Clone)]
pub struct BuildDriver {
    session: CompilerSession,
    toolchain_fingerprint: String,
    graph: Arc<ModuleBuildGraph>,
}
impl fmt::Debug for BuildDriver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BuildDriver")
            .field("session", &self.session)
            .field("toolchain_fingerprint", &self.toolchain_fingerprint)
            .finish_non_exhaustive()
    }
}
impl BuildDriver {
    /// Create a driver with an explicit compiler/tool executable identity.
    pub fn new(session: CompilerSession, toolchain_fingerprint: impl Into<String>) -> Self {
        Self {
            session,
            toolchain_fingerprint: toolchain_fingerprint.into(),
            graph: Arc::new(ModuleBuildGraph::default()),
        }
    }
    /// Create a driver whose cache identity includes the complete running executable.
    pub fn for_current_executable(session: CompilerSession) -> Result<Self, BuildError> {
        if let Some(fingerprint) = CURRENT_TOOLCHAIN_FINGERPRINT.get() {
            return Ok(Self::new(session, fingerprint.clone()));
        }
        let executable = std::env::current_exe().map_err(|error| BuildError::Io {
            operation: "locate running compiler",
            path: PathBuf::from("<current executable>"),
            message: error.to_string(),
        })?;
        let bytes = fs::read(&executable).map_err(|error| BuildError::Io {
            operation: "fingerprint compiler",
            path: executable,
            message: error.to_string(),
        })?;
        let fingerprint = Hash::new_from_chunks(&[b"kotodama-toolchain-v1\0", &bytes]);
        let fingerprint = fingerprint.to_string();
        let _ = CURRENT_TOOLCHAIN_FINGERPRINT.set(fingerprint.clone());
        Ok(Self::new(
            session,
            CURRENT_TOOLCHAIN_FINGERPRINT
                .get()
                .cloned()
                .unwrap_or(fingerprint),
        ))
    }
    /// Build one source unit, authenticating all cached outputs before a hit.
    pub fn build_source(&self, request: SourceBuildRequest) -> Result<BuildOutcome, BuildError> {
        let SourceBuildRequest {
            source,
            source_name,
            profile,
            layout,
            mode,
        } = request;
        self.build_source_fields(&source, &source_name, &profile, &layout, mode)
    }
    fn build_source_fields(
        &self,
        source: &str,
        source_name: &str,
        profile: &str,
        layout: &PublishLayout,
        mode: PublishMode,
    ) -> Result<BuildOutcome, BuildError> {
        validate_profile(profile)?;
        reject_layout_collisions(layout, source_name)?;
        let input_fingerprint =
            self.input_fingerprint(b"source", source_name, profile, source.as_bytes());
        if let Some(fresh) = self.try_fresh(layout, &input_fingerprint.to_string()) {
            return Ok(fresh);
        }
        let output = self
            .session
            .build(CompileRequest {
                source,
                source_name: Some(source_name),
            })
            .map_err(BuildError::Compile)?;
        self.finish_build(output, layout, &input_fingerprint.to_string(), mode)
    }
    /// Build a locked source-module graph without compiling an authenticated hit.
    ///
    /// The graph fingerprint is cheap preflight work over bounded input bytes.
    /// Parsing, name resolution, type/effect analysis, HIR linking, and code
    /// generation all occur only after cached outputs fail authentication.
    pub fn build_linked_source(
        &self,
        graph: &ModuleBuildGraph,
        request: LinkedSourceBuildRequest,
    ) -> Result<BuildOutcome, BuildError> {
        let source_name = request.source_name.clone();
        crate::session::run_with_compiler_stack(move || {
            self.build_linked_source_inner(graph, request)
        })
        .map_err(|_| {
            BuildError::Compile(crate::session::compiler_worker_unavailable_diagnostic(
                Some(&source_name),
            ))
        })?
    }
    fn build_linked_source_inner(
        &self,
        graph: &ModuleBuildGraph,
        request: LinkedSourceBuildRequest,
    ) -> Result<BuildOutcome, BuildError> {
        let _chain_discriminant = self.session.enter_chain_discriminant();
        validate_profile(&request.profile)?;
        reject_layout_collisions(&request.layout, &request.source_name)?;
        let graph_fingerprint =
            ModuleBuildGraph::fingerprint(&request.graph).map_err(BuildError::SourceGraph)?;
        let input_fingerprint = self.input_fingerprint(
            b"typed-graph",
            &request.source_name,
            &request.profile,
            graph_fingerprint.as_ref(),
        );
        if let Some(fresh) = self.try_fresh(&request.layout, &input_fingerprint.to_string()) {
            return Ok(fresh);
        }
        let linked = graph
            .link(request.graph, self.session.linker_options())
            .map_err(BuildError::SourceGraph)?;
        if linked.fingerprint != graph_fingerprint {
            return Err(BuildError::Internal(
                "module graph identity changed between preflight and linking".to_owned(),
            ));
        }
        let output = self
            .session
            .build_typed_program(linked.program, Some(&request.source_name))
            .map_err(BuildError::Compile)?;
        self.finish_build(
            output,
            &request.layout,
            &input_fingerprint.to_string(),
            request.mode,
        )
    }
    /// Build one project through this driver's reusable typed-module graph.
    ///
    /// Frontends should prefer this entry point over constructing a private [`ModuleBuildGraph`].
    /// Keeping graph parsing, typed linking, cache authentication, and atomic publication in one
    /// driver makes repeated project operations share the same content-addressed parser cache.
    pub fn build_project(
        &self,
        request: LinkedSourceBuildRequest,
    ) -> Result<BuildOutcome, BuildError> {
        self.build_linked_source(&self.graph, request)
    }
    /// Link and compile one project without publishing generated files.
    ///
    /// Documentation and editor frontends use this to consume the exact linked
    /// contract interface emitted by the canonical compiler instead of
    /// reconstructing an interface from individual source files.
    pub fn compile_project(
        &self,
        graph: SourceLinkRequest,
        source_name: &str,
    ) -> Result<CompileOutput, BuildError> {
        crate::session::run_with_compiler_stack(move || {
            self.compile_project_inner(graph, source_name)
        })
        .map_err(|_| {
            BuildError::Compile(crate::session::compiler_worker_unavailable_diagnostic(
                Some(source_name),
            ))
        })?
    }
    fn compile_project_inner(
        &self,
        graph: SourceLinkRequest,
        source_name: &str,
    ) -> Result<CompileOutput, BuildError> {
        let _chain_discriminant = self.session.enter_chain_discriminant();
        let linked = self
            .graph
            .link(graph, self.session.linker_options())
            .map_err(BuildError::SourceGraph)?;
        self.session
            .build_typed_program(linked.program, Some(source_name))
            .map_err(BuildError::Compile)
    }
    /// Validate one reusable package through this driver's shared graph.
    pub fn validate_package_project(
        &self,
        request: SourcePackageGraphRequest,
    ) -> Result<ValidatedSourcePackageGraph, BuildError> {
        crate::session::run_with_compiler_stack(move || {
            self.validate_package_project_inner(request)
        })
        .map_err(|_| {
            BuildError::Compile(crate::session::compiler_worker_unavailable_diagnostic(
                Some("<project>"),
            ))
        })?
    }
    fn validate_package_project_inner(
        &self,
        request: SourcePackageGraphRequest,
    ) -> Result<ValidatedSourcePackageGraph, BuildError> {
        let _chain_discriminant = self.session.enter_chain_discriminant();
        self.graph
            .validate_package(request, self.session.linker_options())
            .map_err(BuildError::SourceGraph)
    }
    /// Type-check and lint a reusable package with its exact locked dependency identities.
    pub fn check_package_project(
        &self,
        graph: SourcePackageGraphRequest,
    ) -> Result<Vec<ProjectLintWarning>, BuildError> {
        crate::session::run_with_compiler_stack(move || {
            let _chain_discriminant = self.session.enter_chain_discriminant();
            self.graph
                .validate_package(graph.clone(), self.session.linker_options())
                .map_err(BuildError::SourceGraph)?;
            let resolved = self
                .graph
                .resolve_package_sources(graph)
                .map_err(BuildError::SourceGraph)?;
            let mut warnings = Vec::new();
            for unit in resolved.iter().flat_map(|package| &package.modules) {
                for program in unit.program.source_programs() {
                    let source = program
                        .source_files()
                        .next()
                        .expect("resolved program owns its source");
                    for warning in crate::lint::lint_with_sources(
                        program.program(),
                        program.lint_facts(),
                        source,
                    ) {
                        warnings.push(ProjectLintWarning {
                            package_identity: source.package_identity().map(str::to_owned),
                            source_name: source.name().to_owned(),
                            warning,
                        });
                    }
                }
            }
            warnings.sort_by(|left, right| {
                left.package_identity
                    .cmp(&right.package_identity)
                    .then_with(|| left.source_name.cmp(&right.source_name))
            });
            Ok(warnings)
        })
        .map_err(|_| {
            BuildError::Compile(crate::session::compiler_worker_unavailable_diagnostic(
                Some("<package>"),
            ))
        })?
    }
    /// Type-check and lint one exact deployable source graph without publishing files.
    ///
    /// Unlike loose/editor validation, this entry point links the supplied module aliases or
    /// exports. The supplied root imports, package exports, and transitive package imports are the
    /// complete V1 linking authority. Lints are returned for the root and every explicitly locked
    /// module with their original logical source names.
    pub fn check_project(
        &self,
        graph: SourceLinkRequest,
    ) -> Result<Vec<ProjectLintWarning>, BuildError> {
        crate::session::run_with_compiler_stack(move || self.check_project_inner(graph)).map_err(
            |_| {
                BuildError::Compile(crate::session::compiler_worker_unavailable_diagnostic(
                    Some("<project>"),
                ))
            },
        )?
    }
    fn check_project_inner(
        &self,
        graph: SourceLinkRequest,
    ) -> Result<Vec<ProjectLintWarning>, BuildError> {
        let _chain_discriminant = self.session.enter_chain_discriminant();
        let resolved = self
            .graph
            .resolve_sources(graph)
            .map_err(BuildError::SourceGraph)?;
        let mut warnings = Vec::new();
        let units = std::iter::once(&resolved.root)
            .chain(&resolved.local_modules)
            .chain(
                resolved
                    .packages
                    .iter()
                    .flat_map(|package| package.modules.iter()),
            );
        for unit in units {
            let unused_states = crate::lint::unused_state_names(unit.program.program());
            for program in unit.program.source_programs() {
                let source = program
                    .source_files()
                    .next()
                    .expect("resolved program owns its source");
                for warning in
                    crate::lint::lint_with_sources(program.program(), program.lint_facts(), source)
                {
                    if let crate::lint::LintMessage::UnusedState { name } = &warning.message
                        && !unused_states.contains(name)
                    {
                        continue;
                    }
                    warnings.push(ProjectLintWarning {
                        package_identity: source.package_identity().map(str::to_owned),
                        source_name: source.name().to_owned(),
                        warning,
                    });
                }
            }
        }
        crate::linker::TypedLinker::new(self.session.linker_options())
            .link(resolved)
            .map_err(|error| BuildError::SourceGraph(SourceGraphError::Link(error)))?;
        warnings.sort_by(|left, right| {
            left.package_identity
                .cmp(&right.package_identity)
                .then_with(|| left.source_name.cmp(&right.source_name))
        });
        Ok(warnings)
    }

    /// Check one reusable module and its explicit companion inventory without generating an artifact.
    ///
    /// The temporary check scope has no manifest exports or dependency bindings. Native
    /// source files retain unowned diagnostic identities, including imported local modules.
    pub fn check_module_sources(
        &self,
        root: SourceModuleUnit,
        sources: Vec<SourceModuleUnit>,
        artifacts: Vec<crate::linker::SourceContractArtifact>,
    ) -> Result<Vec<ProjectLintWarning>, BuildError> {
        crate::session::run_with_compiler_stack(move || {
            self.check_module_sources_inner(root, sources, artifacts)
        })
        .map_err(|_| {
            BuildError::Compile(crate::session::compiler_worker_unavailable_diagnostic(
                Some("<module>"),
            ))
        })?
    }
    fn check_module_sources_inner(
        &self,
        root: SourceModuleUnit,
        sources: Vec<SourceModuleUnit>,
        artifacts: Vec<crate::linker::SourceContractArtifact>,
    ) -> Result<Vec<ProjectLintWarning>, BuildError> {
        let _chain_discriminant = self.session.enter_chain_discriminant();
        const CHECK_IDENTITY: &str = "local-source-check";
        let request =
            ModuleBuildGraph::canonical_source_package_bundle(SourcePackageGraphRequest {
                package: SourcePackageUnit {
                    artifacts,
                    identity: CHECK_IDENTITY.into(),
                    modules: vec![root],
                    sources,
                    exports: BTreeSet::new(),
                    imports: Vec::new(),
                },
                dependencies: Vec::new(),
            })
            .map_err(BuildError::SourceGraph)?;
        let root = request.package.modules[0].clone();
        let sources = request.package.sources.clone();
        self.graph
            .validate_package(request, self.session.linker_options())
            .map_err(|error| {
                let mut bundle = error.into_diagnostics();
                for diagnostic in &mut bundle.diagnostics {
                    for span in diagnostic
                        .primary_span
                        .iter_mut()
                        .chain(diagnostic.labels.iter_mut().map(|label| &mut label.span))
                        .chain(diagnostic.fix.iter_mut().map(|fix| &mut fix.span))
                    {
                        if span.package_identity.as_deref() == Some(CHECK_IDENTITY) {
                            span.package_identity = None;
                        }
                    }
                    for source in diagnostic
                        .primary_source
                        .iter_mut()
                        .chain(diagnostic.label_sources.iter_mut().flatten())
                    {
                        if source.package_identity() == Some(CHECK_IDENTITY) {
                            *source = SourceFile::new(source.id(), source.name(), source.text());
                        }
                    }
                }
                BuildError::Compile(bundle)
            })?;
        let mut warnings = Vec::new();
        for source in std::iter::once(root).chain(sources) {
            let file = SourceFile::new(
                SourceId(0),
                source.source_name.as_str(),
                source.source.as_str(),
            );
            let (parsed, _) = crate::syntax::parser::parse_spanned_source_or_fragment(
                &file,
                crate::source::FrontendBudget::v1(),
            )
            .map_err(BuildError::Compile)?;
            for warning in crate::lint::lint_with_sources(&parsed.program, &parsed.facts, &file) {
                warnings.push(ProjectLintWarning {
                    package_identity: None,
                    source_name: source.source_name.clone(),
                    warning,
                });
            }
        }
        Ok(warnings)
    }

    /// Check explicitly listed loose sources without inventing a module graph.
    ///
    /// One deployable root is checked with an empty exact import graph. Module files are checked
    /// independently. Mixing a root and modules requires an explicit project manifest because
    /// positional order is never linking authority in strict V1.
    pub fn check_explicit_sources(
        &self,
        sources: Vec<SourceModuleUnit>,
    ) -> Result<Vec<ProjectLintWarning>, BuildError> {
        crate::session::run_with_compiler_stack(move || self.check_explicit_sources_inner(sources))
            .map_err(|_| {
                BuildError::Compile(crate::session::compiler_worker_unavailable_diagnostic(
                    Some("<project>"),
                ))
            })?
    }
    fn check_explicit_sources_inner(
        &self,
        mut sources: Vec<SourceModuleUnit>,
    ) -> Result<Vec<ProjectLintWarning>, BuildError> {
        let _chain_discriminant = self.session.enter_chain_discriminant();
        sources.sort_by(|left, right| left.source_name.cmp(&right.source_name));
        if sources.is_empty() {
            return Ok(Vec::new());
        }
        let parsed = self
            .graph
            .parse_project_sources(&sources)
            .map_err(BuildError::SourceGraph)?;
        let roots = parsed
            .iter()
            .enumerate()
            .filter_map(|(index, program)| {
                (program.program.unit.kind == SourceUnitKind::Seiyaku).then_some(index)
            })
            .collect::<Vec<_>>();
        if roots.len() > 1 {
            let spans = roots
                .iter()
                .filter_map(|index| project_source_unit_span(&sources[*index], &parsed[*index]))
                .collect::<Vec<_>>();
            let mut diagnostic = Diagnostic::error(
                "E_MULTIPLE_SEIYAKU_ROOTS",
                DiagnosticPhase::Resolve,
                "an explicit Kotodama check has more than one deployable seiyaku root",
                spans.first().cloned(),
            );
            diagnostic
                .labels
                .extend(spans.into_iter().skip(1).map(|span| DiagnosticLabel {
                    span,
                    message: "additional deployable seiyaku root".to_owned(),
                }));
            return Err(BuildError::Compile(DiagnosticBundle::single(diagnostic)));
        }
        if let Some(root) = roots.first().copied() {
            if sources.len() != 1 {
                let root_span = project_source_unit_span(&sources[root], &parsed[root]);
                let mut diagnostic = Diagnostic::error(
                    "E_PROJECT_MANIFEST_REQUIRED",
                    DiagnosticPhase::Resolve,
                    "positional source paths cannot declare Kotodama module imports or exports",
                    root_span,
                );
                for (index, source) in sources.iter().enumerate() {
                    if index == root {
                        continue;
                    }
                    if let Some(span) = project_source_unit_span(source, &parsed[index]) {
                        diagnostic.labels.push(DiagnosticLabel {
                            span,
                            message: "module requires an explicit locked project graph".to_owned(),
                        });
                    }
                }
                diagnostic.help = Some(
                    "declare package imports and exports in Musubi.toml, resolve Musubi.lock, and run `musubi check`"
                        .to_owned(),
                );
                return Err(BuildError::Compile(DiagnosticBundle::single(diagnostic)));
            }
            return self.check_project(SourceLinkRequest {
                artifacts: Vec::new(),
                sources: Vec::new(),
                root: sources.remove(root),
                imports: Vec::new(),
                packages: Vec::new(),
            });
        }
        let mut warnings = Vec::new();
        let mut diagnostics = Vec::new();
        for source in sources {
            match self.session.check_with_lints(CompileRequest {
                source: &source.source,
                source_name: Some(&source.source_name),
            }) {
                Ok(source_warnings) => warnings.extend(source_warnings.into_iter().map(
                    |warning| ProjectLintWarning {
                        package_identity: None,
                        source_name: source.source_name.clone(),
                        warning,
                    },
                )),
                Err(bundle) => diagnostics.extend(bundle.diagnostics),
            }
        }
        if diagnostics.is_empty() {
            Ok(warnings)
        } else {
            Err(BuildError::Compile(DiagnosticBundle::new(diagnostics)))
        }
    }
    /// Validate retained editor documents without inventing graph authority.
    ///
    /// Until an editor supplies an explicit version-1 project manifest, open sources have the same
    /// strict semantics as positional `koto check`: modules are independent and a root mixed with
    /// modules reports `E_PROJECT_MANIFEST_REQUIRED`. Completion remains syntax-derived.
    pub fn check_lsp_open_sources(
        &self,
        sources: Vec<SourceModuleUnit>,
    ) -> Result<Vec<ProjectLintWarning>, BuildError> {
        self.check_explicit_sources(sources)
    }
    /// Build independent source roots in parallel and return results in request order.
    pub fn build_source_batch(
        &self,
        requests: Vec<SourceBuildRequest>,
    ) -> Result<Vec<BuildOutcome>, BuildError> {
        reject_output_collisions(&requests)?;
        let jobs = std::thread::available_parallelism()
            .map_or(1, std::num::NonZeroUsize::get)
            .clamp(1, crate::session::MAX_COMPILER_WORKERS);
        let mut outcomes = Vec::with_capacity(requests.len());
        for chunk in requests.chunks(jobs) {
            let results = std::thread::scope(|scope| {
                let mut handles = Vec::with_capacity(chunk.len());
                for request in chunk {
                    let handle = std::thread::Builder::new()
                        .name("kotodama-source-build".to_owned())
                        .spawn_scoped(scope, move || {
                            self.build_source_fields(
                                &request.source,
                                &request.source_name,
                                &request.profile,
                                &request.layout,
                                request.mode,
                            )
                        })
                        .map_err(|error| {
                            BuildError::Internal(format!(
                                "could not spawn Kotodama build worker: {error}"
                            ))
                        })?;
                    handles.push(handle);
                }
                handles
                    .into_iter()
                    .map(|handle| {
                        handle.join().map_err(|_| {
                            BuildError::Internal("Kotodama build worker panicked".to_owned())
                        })?
                    })
                    .collect::<Result<Vec<_>, BuildError>>()
            })?;
            outcomes.extend(results);
        }
        Ok(outcomes)
    }
    /// Build independent project roots in parallel through one shared graph.
    pub fn build_project_batch(
        &self,
        requests: Vec<LinkedSourceBuildRequest>,
    ) -> Result<Vec<BuildOutcome>, BuildError> {
        reject_linked_output_collisions(&requests)?;
        let jobs = std::thread::available_parallelism()
            .map_or(1, std::num::NonZeroUsize::get)
            .clamp(1, crate::session::MAX_COMPILER_WORKERS);
        let mut outcomes = Vec::with_capacity(requests.len());
        for chunk in requests.chunks(jobs) {
            let results = std::thread::scope(|scope| {
                let mut handles = Vec::with_capacity(chunk.len());
                for request in chunk {
                    let handle = std::thread::Builder::new()
                        .name("kotodama-project-build".to_owned())
                        .spawn_scoped(scope, move || self.build_project(request.clone()))
                        .map_err(|error| {
                            BuildError::Internal(format!(
                                "could not spawn Kotodama project build worker: {error}"
                            ))
                        })?;
                    handles.push(handle);
                }
                handles
                    .into_iter()
                    .map(|handle| {
                        handle.join().map_err(|_| {
                            BuildError::Internal(
                                "Kotodama project build worker panicked".to_owned(),
                            )
                        })?
                    })
                    .collect::<Result<Vec<_>, BuildError>>()
            })?;
            outcomes.extend(results);
        }
        Ok(outcomes)
    }
    fn input_fingerprint(
        &self,
        kind: &[u8],
        source_name: &str,
        profile: &str,
        payload: &[u8],
    ) -> Hash {
        let mut transcript = b"kotodama-build-input-v1\0".to_vec();
        append_field(&mut transcript, kind);
        append_field(&mut transcript, self.toolchain_fingerprint.as_bytes());
        append_field(&mut transcript, self.session.policy_fingerprint().as_ref());
        append_field(&mut transcript, source_name.as_bytes());
        append_field(&mut transcript, profile.as_bytes());
        append_field(&mut transcript, payload);
        Hash::new(transcript)
    }
    fn try_fresh(&self, layout: &PublishLayout, input: &str) -> Option<BuildOutcome> {
        let provisional = layout.resolve("artifact", input);
        let record_bytes = read_bounded_file(&provisional.record, MAX_BUILD_RECORD_BYTES)?;
        let record = BuildRecord::parse(std::str::from_utf8(&record_bytes).ok()?)?;
        if record.input != input {
            return None;
        }
        let paths = layout.resolve(&record.artifact_hash, input);
        if paths.record != provisional.record {
            return None;
        }
        let artifact = read_bounded_file(&paths.artifact, MAX_CACHED_OUTPUT_BYTES)?;
        let manifest_bytes = read_bounded_file(&paths.manifest, MAX_CACHED_OUTPUT_BYTES)?;
        let source_map = read_bounded_file(&paths.source_map, MAX_CACHED_OUTPUT_BYTES)?;
        let budget = read_bounded_file(&paths.budget, MAX_CACHED_OUTPUT_BYTES)?;
        let interface = match (&paths.interface, &record.interface) {
            (Some(path), Some(_)) => Some(read_bounded_file(path, MAX_CACHED_OUTPUT_BYTES)?),
            (None, None) => None,
            _ => return None,
        };
        if output_hash("artifact", &artifact).to_string() != record.artifact
            || output_hash("manifest", &manifest_bytes).to_string() != record.manifest
            || output_hash("source-map", &source_map).to_string() != record.source_map
            || output_hash("budget", &budget).to_string() != record.budget
            || interface
                .as_ref()
                .zip(record.interface.as_ref())
                .is_some_and(|(bytes, expected)| {
                    output_hash("interface", bytes).to_string() != *expected
                })
        {
            return None;
        }
        let artifact_hash = contract_code_hash(&artifact);
        if artifact_hash.to_string() != record.artifact_hash {
            return None;
        }
        let manifest_text = std::str::from_utf8(&manifest_bytes).ok()?;
        let manifest: ContractManifest = json::from_str(manifest_text).ok()?;
        if manifest.code_hash.as_ref() != Some(&artifact_hash) {
            return None;
        }
        if !valid_sidecar(&source_map, "source-map", &record.artifact_hash)
            || !valid_sidecar(&budget, "budget", &record.artifact_hash)
            || interface
                .as_ref()
                .is_some_and(|bytes| !valid_interface(bytes, &record.artifact_hash))
        {
            return None;
        }
        Some(BuildOutcome {
            status: BuildStatus::Fresh,
            artifact_hash,
            artifact,
            manifest,
            paths,
        })
    }
    fn finish_build(
        &self,
        output: CompileOutput,
        layout: &PublishLayout,
        input: &str,
        mode: PublishMode,
    ) -> Result<BuildOutcome, BuildError> {
        let artifact_hash = contract_code_hash(&output.artifact);
        if output.report.artifact_hash != artifact_hash {
            return Err(BuildError::Internal(
                "compiler report hash does not match deployable artifact".to_owned(),
            ));
        }
        if output.manifest.code_hash.as_ref() != Some(&artifact_hash) {
            return Err(BuildError::Internal(
                "compiler manifest hash does not match deployable artifact".to_owned(),
            ));
        }
        let artifact_hash_text = artifact_hash.to_string();
        let paths = layout.resolve(&artifact_hash_text, input);
        reject_path_collisions(paths.all_paths(), "resolved Kotodama build")?;
        let manifest = json::to_json_pretty(&output.manifest)
            .map_err(|error| BuildError::Render(error.to_string()))?;
        let source_map = output
            .report
            .render_source_map_json()
            .map_err(|error| BuildError::Render(error.to_string()))?;
        let budget = output
            .report
            .render_budget_json()
            .map_err(|error| BuildError::Render(error.to_string()))?;
        let interface = paths
            .interface
            .as_ref()
            .map(|_| render_interface_json(&output.manifest))
            .transpose()?;
        let record = BuildRecord {
            input: input.to_owned(),
            artifact_hash: artifact_hash_text,
            artifact: output_hash("artifact", &output.artifact).to_string(),
            manifest: output_hash("manifest", manifest.as_bytes()).to_string(),
            source_map: output_hash("source-map", source_map.as_bytes()).to_string(),
            budget: output_hash("budget", budget.as_bytes()).to_string(),
            interface: interface
                .as_ref()
                .map(|value| output_hash("interface", value.as_bytes()).to_string()),
        };
        let record_text = record.render();
        let mut expected = vec![
            (&paths.artifact, output.artifact.as_slice()),
            (&paths.manifest, manifest.as_bytes()),
            (&paths.source_map, source_map.as_bytes()),
            (&paths.budget, budget.as_bytes()),
        ];
        if let (Some(path), Some(value)) = (&paths.interface, interface.as_ref()) {
            expected.push((path, value.as_bytes()));
        }
        match mode {
            PublishMode::Write => {
                for (path, bytes) in &expected {
                    atomic_write_if_changed(path, bytes)?;
                }
                // This commit marker is deliberately last. An interrupted build
                // can leave files behind but can never create an authenticated hit.
                atomic_write_if_changed(&paths.record, record_text.as_bytes())?;
            }
            PublishMode::Verify => {
                for (path, bytes) in &expected {
                    verify_exact(path, bytes)?;
                }
                verify_exact(&paths.record, record_text.as_bytes())?;
            }
        }
        Ok(BuildOutcome {
            status: BuildStatus::Built,
            artifact_hash,
            artifact: output.artifact,
            manifest: output.manifest,
            paths,
        })
    }
}
/// Render the canonical generated interface used by developer tooling.
pub fn render_interface_json(manifest: &ContractManifest) -> Result<String, BuildError> {
    let manifest_value =
        json::to_value(manifest).map_err(|error| BuildError::Render(error.to_string()))?;
    let entrypoints = manifest
        .entrypoints
        .as_ref()
        .map(json::to_value)
        .transpose()
        .map_err(|error| BuildError::Render(error.to_string()))?
        .unwrap_or(json::Value::Array(Vec::new()));
    let states = manifest
        .states
        .as_ref()
        .map(json::to_value)
        .transpose()
        .map_err(|error| BuildError::Render(error.to_string()))?
        .unwrap_or(json::Value::Array(Vec::new()));
    json::to_json_pretty(&norito::json!({
        "interface_version": 1_u64,
        "manifest": (manifest_value),
        "entrypoints": (entrypoints),
        "states": (states),
    }))
    .map_err(|error| BuildError::Render(error.to_string()))
}
/// Read one bounded UTF-8 Kotodama source and map I/O failures for build tools.
pub fn read_source_file(path: &Path) -> Result<String, BuildError> {
    crate::source::read_source_file(path).map_err(|error| source_read_error(path, error))
}

fn source_read_error(path: &Path, error: crate::source::SourceReadError) -> BuildError {
    match error {
        crate::source::SourceReadError::Io(error) => BuildError::Io {
            operation: "read Kotodama source",
            path: path.to_path_buf(),
            message: error.to_string(),
        },
        crate::source::SourceReadError::TooLarge { limit } => BuildError::SourceTooLarge {
            path: path.to_path_buf(),
            limit,
        },
        crate::source::SourceReadError::InvalidUtf8 {
            valid_up_to,
            error_len,
        } => BuildError::InvalidSourceUtf8 {
            path: path.to_path_buf(),
            valid_up_to,
            error_len,
        },
    }
}
/// Map one physical source path to its portable project-relative graph name.
///
/// Absolute sources must remain below `project_root`; relative sources are
/// interpreted from that root. The returned spelling always uses `/`, so the
/// same project has the same graph fingerprint on every supported host.
pub fn logical_source_name(source_path: &Path, project_root: &Path) -> Result<String, BuildError> {
    let relative = if source_path.is_absolute() {
        source_path
            .strip_prefix(project_root)
            .map_err(|_| BuildError::InvalidPath {
                path: source_path.to_path_buf(),
                message: format!(
                    "Kotodama source is outside project root `{}`",
                    project_root.display()
                ),
            })?
    } else {
        source_path
            .strip_prefix(project_root)
            .unwrap_or(source_path)
    };
    let spelling = relative
        .to_str()
        .ok_or_else(|| BuildError::InvalidPath {
            path: source_path.to_path_buf(),
            message: "Kotodama source path is not UTF-8".to_owned(),
        })?
        .replace('\\', "/");
    let mut components = Vec::new();
    for component in spelling.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if components.pop().is_none() {
                    return Err(BuildError::InvalidPath {
                        path: source_path.to_path_buf(),
                        message: "Kotodama source escapes the project root".to_owned(),
                    });
                }
            }
            value => components.push(value),
        }
    }
    if components.is_empty() {
        return Err(BuildError::InvalidPath {
            path: source_path.to_path_buf(),
            message: "Kotodama source path must name a file below the project root".to_owned(),
        });
    }
    Ok(components.join("/"))
}
/// Select the deterministic physical root for one explicitly selected source.
///
/// Sources below `preferred_root` retain that common project. A source outside it becomes a
/// one-file project rooted at its parent directory, allowing CLI tools to compile an absolute
/// source without treating unrelated siblings as implicit modules.
pub fn project_root_for_source(
    source_path: &Path,
    preferred_root: &Path,
) -> Result<PathBuf, BuildError> {
    let source = source_path.canonicalize().map_err(|error| BuildError::Io {
        operation: "canonicalize Kotodama source",
        path: source_path.to_path_buf(),
        message: error.to_string(),
    })?;
    let preferred = preferred_root
        .canonicalize()
        .map_err(|error| BuildError::Io {
            operation: "canonicalize Kotodama project root",
            path: preferred_root.to_path_buf(),
            message: error.to_string(),
        })?;
    if source.starts_with(&preferred) {
        return Ok(preferred);
    }
    source
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| BuildError::InvalidPath {
            path: source_path.to_path_buf(),
            message: "Kotodama source has no project parent directory".to_owned(),
        })
}
/// Discover every `.ko` source below a reusable package root deterministically.
///
/// Discovery ignores generated/cache directories, does not follow symlinks,
/// sorts by portable logical path, and applies the same source-count and byte
/// budgets as the typed module graph before returning caller-controlled data.
pub fn discover_source_modules(root: &Path) -> Result<Vec<SourceModuleUnit>, BuildError> {
    let root = root.canonicalize().map_err(|error| BuildError::Io {
        operation: "canonicalize Kotodama source root",
        path: root.to_path_buf(),
        message: error.to_string(),
    })?;
    let mut files = Vec::new();
    discover_source_files(&root, &root, 0, &mut files)?;
    files.sort();
    let mut modules = Vec::new();
    let mut source_bytes = 0_usize;
    for relative in files {
        if relative.extension().and_then(|value| value.to_str()) != Some("ko") {
            continue;
        }
        let path = root.join(&relative);
        let source = read_source_file(&path)?;
        source_bytes = source_bytes.saturating_add(source.len());
        modules.push(SourceModuleUnit {
            source_name: logical_source_name(&relative, Path::new("."))?,
            source,
        });
        if modules.len() > MAX_MODULE_GRAPH_SOURCES || source_bytes > MAX_MODULE_GRAPH_SOURCE_BYTES
        {
            return Err(BuildError::SourceGraph(SourceGraphError::Budget {
                sources: modules.len(),
                source_bytes,
                max_sources: MAX_MODULE_GRAPH_SOURCES,
                max_source_bytes: MAX_MODULE_GRAPH_SOURCE_BYTES,
            }));
        }
    }
    Ok(modules)
}
/// Read one deployable root and construct the canonical typed-module request.
///
/// Package manifests and lockfiles remain responsible for supplying explicit aliases, exports, and
/// authenticated package identities. When those are absent, callers pass empty collections: V1
/// never invents wildcard imports or implicit exports from nearby files.
pub fn discover_source_link_request(
    source_path: &Path,
    project_root: &Path,
    imports: Vec<ImportBinding>,
    packages: Vec<SourcePackageUnit>,
) -> Result<SourceLinkRequest, BuildError> {
    let canonical_root = canonical_project_root(project_root)?;
    let selected =
        iroha_fs::SelectedRegularFile::capture(source_path).map_err(|error| BuildError::Io {
            operation: "canonicalize Kotodama source",
            path: source_path.to_path_buf(),
            message: error.to_string(),
        })?;
    source_link_request(
        &selected,
        source_path,
        project_root,
        &canonical_root,
        imports,
        packages,
    )
}

/// Discover the declared graph from an original native selection retained through intervening work.
/// This uses the same graph construction as [`discover_source_link_request`], without reopening
/// or following a replacement root. Companion and package selection remain independently scoped.
/// # Errors
/// Returns the original source-root, source, graph and fixed-budget diagnostics, or native custody refusal.
pub fn discover_selected_source_link_request(
    source: &iroha_fs::SelectedRegularFile,
    project_root: &Path,
    imports: Vec<ImportBinding>,
    packages: Vec<SourcePackageUnit>,
) -> Result<SourceLinkRequest, BuildError> {
    let canonical_root = canonical_project_root(project_root)?;
    source_link_request(
        source,
        source.path(),
        project_root,
        &canonical_root,
        imports,
        packages,
    )
}

fn canonical_project_root(project_root: &Path) -> Result<PathBuf, BuildError> {
    project_root.canonicalize().map_err(|error| BuildError::Io {
        operation: "canonicalize Kotodama project root",
        path: project_root.to_path_buf(),
        message: error.to_string(),
    })
}

fn source_link_request(
    source: &iroha_fs::SelectedRegularFile,
    source_path: &Path,
    project_root: &Path,
    canonical_root: &Path,
    imports: Vec<ImportBinding>,
    packages: Vec<SourcePackageUnit>,
) -> Result<SourceLinkRequest, BuildError> {
    if !source.path().starts_with(canonical_root) {
        return Err(BuildError::InvalidPath {
            path: source_path.to_path_buf(),
            message: format!(
                "Kotodama source resolves outside project root `{}`",
                project_root.display()
            ),
        });
    }
    let text = crate::source::read_selected_source(source)
        .map_err(|error| source_read_error(source_path, error))?;
    let root = SourceModuleUnit {
        source_name: logical_source_name(source.path(), canonical_root)?,
        source: text,
    };
    let SourceInventory { sources, artifacts } = load_source_inventory(
        std::slice::from_ref(&root),
        canonical_root,
        &BTreeMap::new(),
    )?;
    source.revalidate().map_err(|error| {
        source_read_error(source_path, crate::source::SourceReadError::Io(error))
    })?;
    Ok(SourceLinkRequest {
        artifacts,
        sources,
        root,
        imports,
        packages,
    })
}
fn discover_source_files(
    root: &Path,
    current: &Path,
    depth: usize,
    files: &mut Vec<PathBuf>,
) -> Result<(), BuildError> {
    const MAX_DISCOVERY_DEPTH: usize = 256;
    if depth > MAX_DISCOVERY_DEPTH {
        return Err(BuildError::InvalidPath {
            path: current.to_path_buf(),
            message: format!(
                "Kotodama project discovery exceeds {MAX_DISCOVERY_DEPTH} directory levels"
            ),
        });
    }
    let entries = fs::read_dir(current).map_err(|error| BuildError::Io {
        operation: "read Kotodama source directory",
        path: current.to_path_buf(),
        message: error.to_string(),
    })?;
    let mut entries = entries
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| BuildError::Io {
            operation: "read Kotodama source directory entry",
            path: current.to_path_buf(),
            message: error.to_string(),
        })?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let name = entry.file_name();
        if matches!(name.to_str(), Some(".git" | ".musubi" | "target" | "dist")) {
            continue;
        }
        let file_type = entry.file_type().map_err(|error| BuildError::Io {
            operation: "inspect Kotodama source path",
            path: entry.path(),
            message: error.to_string(),
        })?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            discover_source_files(root, &entry.path(), depth.saturating_add(1), files)?;
        } else if file_type.is_file() {
            files.push(
                entry
                    .path()
                    .strip_prefix(root)
                    .expect("discovered source remains below its root")
                    .to_path_buf(),
            );
        }
    }
    Ok(())
}
/// Atomically replace a generated file only when its bytes changed.
///
/// Returns `true` when publication occurred. Returning `false` performs no
/// directory creation, timestamp update, or temporary-file write.
pub fn atomic_write_if_changed(path: &Path, bytes: &[u8]) -> Result<bool, BuildError> {
    if file_equals(path, bytes).unwrap_or(false) {
        return Ok(false);
    }
    let parent = output_parent(path);
    let directory =
        iroha_fs::OwnerDirectory::open_or_create(parent).map_err(|error| BuildError::Io {
            operation: "retain output directory",
            path: parent.to_path_buf(),
            message: error.to_string(),
        })?;
    let name = path.file_name().ok_or_else(|| BuildError::InvalidPath {
        path: path.to_path_buf(),
        message: "output path has no file name".to_owned(),
    })?;
    directory
        .write_atomic(name, bytes, iroha_fs::PublishMode::Replace)
        .map_err(|error| BuildError::Io {
            operation: "publish exact compiler output",
            path: path.to_path_buf(),
            message: error.to_string(),
        })?;
    Ok(true)
}
fn output_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}
fn read_bounded_file(path: &Path, limit: usize) -> Option<Vec<u8>> {
    iroha_fs::read_regular(path, limit)
        .ok()
        .map(|bytes| bytes.to_vec())
}
fn file_equals(path: &Path, expected: &[u8]) -> std::io::Result<bool> {
    match iroha_fs::read_regular(path, expected.len()) {
        Ok(bytes) => Ok(bytes.as_slice() == expected),
        Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => Ok(false),
        Err(error) => Err(error),
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct BuildRecord {
    input: String,
    artifact_hash: String,
    artifact: String,
    manifest: String,
    source_map: String,
    budget: String,
    interface: Option<String>,
}
impl BuildRecord {
    fn render(&self) -> String {
        format!(
            "schema={BUILD_RECORD_SCHEMA}\ninput={}\nartifact_hash={}\nartifact={}\nmanifest={}\nsource_map={}\nbudget={}\ninterface={}\n",
            self.input,
            self.artifact_hash,
            self.artifact,
            self.manifest,
            self.source_map,
            self.budget,
            self.interface.as_deref().unwrap_or("-"),
        )
    }
    fn parse(raw: &str) -> Option<Self> {
        let mut fields = HashMap::new();
        for line in raw.lines() {
            let (key, value) = line.split_once('=')?;
            if !matches!(
                key,
                "schema"
                    | "input"
                    | "artifact_hash"
                    | "artifact"
                    | "manifest"
                    | "source_map"
                    | "budget"
                    | "interface"
            ) || value.is_empty()
                || fields.insert(key, value).is_some()
            {
                return None;
            }
        }
        if fields.len() != 8 || fields.get("schema") != Some(&BUILD_RECORD_SCHEMA) {
            return None;
        }
        let interface = *fields.get("interface")?;
        Some(Self {
            input: (*fields.get("input")?).to_owned(),
            artifact_hash: (*fields.get("artifact_hash")?).to_owned(),
            artifact: (*fields.get("artifact")?).to_owned(),
            manifest: (*fields.get("manifest")?).to_owned(),
            source_map: (*fields.get("source_map")?).to_owned(),
            budget: (*fields.get("budget")?).to_owned(),
            interface: (interface != "-").then(|| interface.to_owned()),
        })
    }
}
fn output_hash(kind: &str, bytes: &[u8]) -> Hash {
    let length = (bytes.len() as u64).to_le_bytes();
    Hash::new_from_chunks(&[
        b"kotodama-build-output-v1\0",
        kind.as_bytes(),
        b"\0",
        &length,
        bytes,
    ])
}
fn valid_sidecar(bytes: &[u8], kind: &str, artifact_hash: &str) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let Ok(value) = json::parse_value(text) else {
        return false;
    };
    value.get("kind").and_then(json::Value::as_str) == Some(kind)
        && value.get("artifact_hash").and_then(json::Value::as_str) == Some(artifact_hash)
}
fn valid_interface(bytes: &[u8], artifact_hash: &str) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let Ok(value) = json::parse_value(text) else {
        return false;
    };
    if value.get("interface_version").and_then(json::Value::as_u64) != Some(1) {
        return false;
    }
    let Some(manifest) = value.get("manifest").cloned() else {
        return false;
    };
    let Ok(manifest) = json::from_value::<ContractManifest>(manifest) else {
        return false;
    };
    manifest
        .code_hash
        .as_ref()
        .is_some_and(|hash| hash.to_string() == artifact_hash)
}
fn append_field(transcript: &mut Vec<u8>, value: &[u8]) {
    transcript.extend_from_slice(&(value.len() as u64).to_le_bytes());
    transcript.extend_from_slice(value);
}
fn validate_profile(profile: &str) -> Result<(), BuildError> {
    let mut chars = profile.chars();
    if !chars
        .next()
        .is_some_and(|value| value.is_ascii_alphanumeric())
        || !chars.all(|value| value.is_ascii_alphanumeric() || matches!(value, '-' | '_'))
    {
        return Err(BuildError::InvalidProfile(profile.to_owned()));
    }
    Ok(())
}
fn validate_stem(stem: &str) -> Result<(), BuildError> {
    if stem.is_empty()
        || matches!(stem, "." | "..")
        || Path::new(stem).components().count() != 1
        || Path::new(stem).file_name().and_then(|value| value.to_str()) != Some(stem)
    {
        return Err(BuildError::InvalidStem(stem.to_owned()));
    }
    Ok(())
}
fn reject_output_collisions(requests: &[SourceBuildRequest]) -> Result<(), BuildError> {
    let mut owners = HashMap::<PathBuf, String>::new();
    for request in requests {
        for path in request.layout.static_paths() {
            let normalized = normalize_path(&path)?;
            if let Some(previous) = owners.insert(normalized.clone(), request.source_name.clone()) {
                return Err(BuildError::OutputCollision {
                    path: normalized,
                    first: previous,
                    second: request.source_name.clone(),
                });
            }
        }
    }
    Ok(())
}
fn reject_linked_output_collisions(
    requests: &[LinkedSourceBuildRequest],
) -> Result<(), BuildError> {
    let mut owners = HashMap::<PathBuf, String>::new();
    for request in requests {
        for path in request.layout.static_paths() {
            let normalized = normalize_path(&path)?;
            if let Some(previous) = owners.insert(normalized.clone(), request.source_name.clone()) {
                return Err(BuildError::OutputCollision {
                    path: normalized,
                    first: previous,
                    second: request.source_name.clone(),
                });
            }
        }
    }
    Ok(())
}
fn reject_layout_collisions(layout: &PublishLayout, owner: &str) -> Result<(), BuildError> {
    reject_path_collisions(layout.static_paths(), owner)
}
fn reject_path_collisions(
    paths: impl IntoIterator<Item = PathBuf>,
    owner: &str,
) -> Result<(), BuildError> {
    let mut seen = HashMap::<PathBuf, PathBuf>::new();
    for path in paths {
        let normalized = normalize_path(&path)?;
        if let Some(previous) = seen.insert(normalized.clone(), path.clone()) {
            return Err(BuildError::OutputCollision {
                path: normalized,
                first: format!("{owner}:{}", previous.display()),
                second: format!("{owner}:{}", path.display()),
            });
        }
    }
    Ok(())
}
fn normalize_path(path: &Path) -> Result<PathBuf, BuildError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| BuildError::Io {
                operation: "resolve output path",
                path: path.to_path_buf(),
                message: error.to_string(),
            })?
            .join(path)
    };
    let normalized = normalize_lexically(&absolute);
    // Resolve the longest existing prefix so two lexical paths that traverse
    // different symlinked directories cannot evade parallel-output collision
    // checks. Nonexistent output suffixes are then appended without touching
    // the filesystem.
    let mut existing = normalized.as_path();
    let mut suffix = Vec::new();
    while !existing.exists() {
        let Some(name) = existing.file_name() else {
            break;
        };
        suffix.push(name.to_owned());
        let Some(parent) = existing.parent() else {
            break;
        };
        existing = parent;
    }
    let mut physical = fs::canonicalize(existing).map_err(|error| BuildError::Io {
        operation: "resolve output directory",
        path: existing.to_path_buf(),
        message: error.to_string(),
    })?;
    for component in suffix.into_iter().rev() {
        physical.push(component);
    }
    Ok(normalize_lexically(&physical))
}
fn normalize_lexically(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}
fn verify_exact(path: &Path, expected: &[u8]) -> Result<(), BuildError> {
    match file_equals(path, expected) {
        Ok(true) => Ok(()),
        Ok(false) => Err(BuildError::LockedStale(path.to_path_buf())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(BuildError::LockedMissing(path.to_path_buf()))
        }
        Err(error) => Err(BuildError::Io {
            operation: "verify generated output",
            path: path.to_path_buf(),
            message: error.to_string(),
        }),
    }
}
/// Build driver failure.
#[derive(Clone, Debug)]
pub enum BuildError {
    /// A profile could escape or ambiguously name its target directory.
    InvalidProfile(String),
    /// A target stem was not one safe path component.
    InvalidStem(String),
    /// An output path could not be represented safely.
    InvalidPath {
        /// Rejected path.
        path: PathBuf,
        /// Reason for rejection.
        message: String,
    },
    /// A versioned Kotodama project manifest was malformed or unsafe.
    InvalidProjectManifest {
        /// Rejected manifest path.
        path: PathBuf,
        /// Stable human-readable rejection reason.
        message: String,
    },
    /// Two roots attempted to publish the same static output.
    OutputCollision {
        /// Colliding normalized output path.
        path: PathBuf,
        /// First source owner.
        first: String,
        /// Second source owner.
        second: String,
    },
    /// Canonical compiler diagnostics.
    Compile(DiagnosticBundle),
    /// Parsing, resolution, or typed-HIR linking of a source graph failed.
    SourceGraph(SourceGraphError),
    /// A source exceeded the mandatory V1 byte limit.
    SourceTooLarge {
        /// Rejected source path.
        path: PathBuf,
        /// Maximum accepted source size.
        limit: usize,
    },
    /// A source contained malformed UTF-8.
    InvalidSourceUtf8 {
        /// Rejected source path.
        path: PathBuf,
        /// Number of valid bytes before the malformed sequence.
        valid_up_to: usize,
        /// Malformed-sequence length when it was fully present.
        error_len: Option<usize>,
    },
    /// JSON or sidecar rendering failed.
    Render(String),
    /// A locked output did not exist.
    LockedMissing(PathBuf),
    /// A locked output differed from its canonical bytes.
    LockedStale(PathBuf),
    /// Filesystem operation failed.
    Io {
        /// Short operation label.
        operation: &'static str,
        /// Affected path.
        path: PathBuf,
        /// Underlying error.
        message: String,
    },
    /// Compiler/driver invariant failure.
    Internal(String),
}
impl BuildError {
    /// Recover canonical compiler diagnostics without rendering them to text.
    ///
    /// Filesystem, cache, and publication failures remain ordinary build
    /// errors; source, resolver, linker, and typed compiler failures retain
    /// their complete structured bundle for the caller's selected renderer.
    pub fn into_diagnostics(self) -> Result<DiagnosticBundle, Self> {
        match self {
            Self::Compile(diagnostics) => Ok(diagnostics),
            Self::SourceGraph(error) => Ok(error.into_diagnostics()),
            Self::InvalidProjectManifest { path, message } => {
                Ok(DiagnosticBundle::single(Diagnostic::error(
                    "E_PROJECT_MANIFEST",
                    DiagnosticPhase::Resolve,
                    format!(
                        "invalid Kotodama project manifest `{}`: {message}",
                        path.display()
                    ),
                    None,
                )))
            }
            other => Err(other),
        }
    }
}
impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProfile(profile) => write!(
                formatter,
                "invalid Kotodama build profile `{profile}`; use ASCII letters, digits, '-' or '_'"
            ),
            Self::InvalidStem(stem) => {
                write!(formatter, "invalid Kotodama output stem `{stem}`")
            }
            Self::InvalidPath { path, message } => {
                write!(
                    formatter,
                    "invalid output path `{}`: {message}",
                    path.display()
                )
            }
            Self::InvalidProjectManifest { path, message } => write!(
                formatter,
                "invalid Kotodama project manifest `{}`: {message}",
                path.display()
            ),
            Self::OutputCollision {
                path,
                first,
                second,
            } => write!(
                formatter,
                "Kotodama sources `{first}` and `{second}` both publish `{}`",
                path.display()
            ),
            Self::Compile(diagnostics) => diagnostics.render_human().fmt(formatter),
            Self::SourceGraph(error) => error.fmt(formatter),
            Self::SourceTooLarge { path, limit } => write!(
                formatter,
                "Kotodama source `{}` exceeds the {limit}-byte V1 limit",
                path.display()
            ),
            Self::InvalidSourceUtf8 {
                path,
                valid_up_to,
                error_len,
            } => match error_len {
                Some(length) => write!(
                    formatter,
                    "Kotodama source `{}` is not valid UTF-8 at byte {valid_up_to} (invalid sequence length {length})",
                    path.display()
                ),
                None => write!(
                    formatter,
                    "Kotodama source `{}` ends with an incomplete UTF-8 sequence at byte {valid_up_to}",
                    path.display()
                ),
            },
            Self::Render(message) => write!(formatter, "render Kotodama build output: {message}"),
            Self::LockedMissing(path) => {
                write!(
                    formatter,
                    "generated artifact is missing: {}",
                    path.display()
                )
            }
            Self::LockedStale(path) => {
                write!(formatter, "generated artifact is stale: {}", path.display())
            }
            Self::Io {
                operation,
                path,
                message,
            } => write!(formatter, "{operation} `{}`: {message}", path.display()),
            Self::Internal(message) => write!(formatter, "Kotodama build invariant: {message}"),
        }
    }
}
impl Error for BuildError {}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::linker::{ImportBinding, SourceModuleUnit, SourcePackageUnit};
    use std::collections::BTreeSet;
    fn temp_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "kotodama-driver-{label}-{}-{}",
            std::process::id(),
            TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
    }
    fn request(root: &Path, source: &str) -> SourceBuildRequest {
        SourceBuildRequest {
            source: source.to_owned(),
            source_name: "contracts/demo.ko".to_owned(),
            profile: "test".to_owned(),
            layout: PublishLayout::standard(root, "test", "demo", true).expect("valid test layout"),
            mode: PublishMode::Write,
        }
    }
    fn linked_request(root: &Path, module_source: &str) -> LinkedSourceBuildRequest {
        LinkedSourceBuildRequest {
            graph: SourceLinkRequest { artifacts: Vec::new(),
                sources: Vec::new(),
                root: SourceModuleUnit {
                    source_name: "contracts/app.ko".to_owned(),
                    source: "seiyaku App { view fn run() authorize(anyone) -> int { return helpers::value(); } }"
                        .to_owned(),
                },
                imports: vec![ImportBinding {
                    alias: "helpers".to_owned(),
                    package: "std/math@1.0.0".to_owned(),
                }],
                packages: vec![SourcePackageUnit { artifacts: Vec::new(),
                    sources: Vec::new(),
                    identity: "std/math@1.0.0".to_owned(),
                    modules: vec![SourceModuleUnit {
                        source_name: "modules/math.ko".to_owned(),
                        source: module_source.to_owned(),
                    }],
                    exports: BTreeSet::from(["value".to_owned()]),
                    imports: Vec::new(),
                }],
            },
            source_name: "contracts/app.ko".to_owned(),
            profile: "test".to_owned(),
            layout: PublishLayout::standard(root, "test", "app", true)
                .expect("valid linked test layout"),
            mode: PublishMode::Write,
        }
    }
    fn boundary_source_graph() -> SourceLinkRequest {
        let depth = crate::source::MAX_NESTING_DEPTH - 2;
        let expression = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
        SourceLinkRequest {
            artifacts: Vec::new(),
            sources: Vec::new(),
            root: SourceModuleUnit {
                source_name: "contracts/stack-margin.ko".to_owned(),
                source: format!(
                    "seiyaku StackMargin {{ hajimari() {{ let value = {expression}; }} }}"
                ),
            },
            imports: Vec::new(),
            packages: Vec::new(),
        }
    }
    #[test]
    fn bounded_source_reader_preserves_typed_budget_and_utf8_failures() {
        let root = temp_root("source-errors");
        fs::create_dir_all(&root).expect("create source error root");
        let oversized = root.join("oversized.ko");
        fs::write(&oversized, vec![b' '; crate::source::MAX_SOURCE_BYTES + 1])
            .expect("write oversized source");
        assert!(matches!(
            read_source_file(&oversized),
            Err(BuildError::SourceTooLarge {
                limit: crate::source::MAX_SOURCE_BYTES,
                ..
            })
        ));
        let invalid = root.join("invalid.ko");
        fs::write(&invalid, [0xff]).expect("write invalid UTF-8 source");
        assert!(matches!(
            read_source_file(&invalid),
            Err(BuildError::InvalidSourceUtf8 {
                valid_up_to: 0,
                error_len: Some(1),
                ..
            })
        ));
        fs::remove_dir_all(root).expect("remove source error root");
    }
    #[test]
    fn included_state_lints_account_for_uses_in_other_native_files() {
        let graph = SourceLinkRequest { artifacts: Vec::new(),
            root: SourceModuleUnit {
                source_name: "app.ko".into(),
                source: "seiyaku App { state int root_value; include \"body.ko\"; include \"init.ko\"; view fn from_root() authorize(anyone) -> int { return fragment_value; } }".into(),
            },
            sources: vec![SourceModuleUnit {
                source_name: "body.ko".into(),
                source: "state int fragment_value; state StateMap<int, int> unused; view fn from_fragment() authorize(anyone) -> int { return root_value; }".into(),
            }, SourceModuleUnit {
                source_name: "init.ko".into(),
                source: "hajimari() { root_value = 1; fragment_value = 2; }".into(),
            }],
            imports: Vec::new(),
            packages: Vec::new(),
        };
        let warnings = BuildDriver::new(CompilerSession::default(), "shared-state-lints")
            .check_project(graph)
            .expect("shared unit is valid");
        let unused = warnings
            .iter()
            .filter(|warning| warning.warning.code == "unused-state")
            .collect::<Vec<_>>();
        assert_eq!(unused.len(), 1);
        assert_eq!(unused[0].source_name, "body.ko");
        assert_eq!(
            unused[0].warning.message,
            crate::lint::LintMessage::UnusedState {
                name: "unused".into()
            }
        );
        assert_eq!(
            unused[0]
                .warning
                .source
                .as_ref()
                .expect("native span")
                .source_file
                .name(),
            "body.ko"
        );
    }
    #[test]
    fn standalone_module_check_uses_include_and_import_closure_without_artifact() {
        let driver = BuildDriver::new(CompilerSession::default(), "module-check");
        let root = SourceModuleUnit {
            source_name: "module.ko".into(),
            source: "module Example { include \"body.ko\"; import \"helper.ko\" as helper; }"
                .into(),
        };
        let sources = vec![
            SourceModuleUnit {
                source_name: "body.ko".into(),
                source: "export fn value(int unused) -> int { return helper::answer(); }".into(),
            },
            SourceModuleUnit {
                source_name: "helper.ko".into(),
                source: "module Helper { export fn answer() -> int { return 7; } }".into(),
            },
        ];
        let warnings = driver
            .check_module_sources(root.clone(), sources.clone(), Vec::new())
            .expect("standalone module closure");
        assert!(
            warnings
                .iter()
                .any(|warning| warning.source_name == "body.ko"
                    && warning.package_identity.is_none())
        );
        let mut invalid = sources;
        invalid[0].source = "export fn value() -> int { return missing; }".into();
        let error = driver
            .check_module_sources(root, invalid, Vec::new())
            .expect_err("source error")
            .into_diagnostics()
            .expect("structured source error");
        let span = error
            .diagnostics
            .iter()
            .find_map(|diagnostic| diagnostic.primary_span.as_ref())
            .expect("native span");
        assert_eq!(span.source.as_deref(), Some("body.ko"));
        assert!(span.package_identity.is_none());
    }
    #[test]
    fn project_manifest_snapshot_preserves_exact_export_tokens_and_owner_identity() {
        let text = "[module]\nexports = [\"v\\u0061lue\"]\n";
        let token = "\"v\\u0061lue\"";
        let start = text.find(token).expect("export token") as u32;
        let range = TextRange::new(start, start + token.len() as u32);
        let path = PathBuf::from("/workspace/math/Musubi.toml");
        let captured = ProjectManifestSource::new(
            path.clone(),
            text.into(),
            BTreeMap::from([(("example/math@1.0.0".into(), "value".into()), range)]),
        );
        assert_eq!(captured.path(), path);
        assert_eq!(captured.text(), text);
        assert_eq!(
            captured.export_range("example/math@1.0.0", "value"),
            Some(range)
        );
        assert_eq!(
            &captured.text()[range.start as usize..range.end as usize],
            token
        );
        assert!(captured.export_range("other/math@1.0.0", "value").is_none());
        assert!(
            captured
                .export_range("example/math@1.0.0", "missing")
                .is_none()
        );
    }
    #[test]
    fn shared_discovery_is_portable_sorted_and_fail_closed() {
        let root = temp_root("discovery");
        fs::create_dir_all(root.join("src/nested")).expect("create source tree");
        fs::create_dir_all(root.join("target/generated")).expect("create ignored tree");
        fs::write(
            root.join("src/z.ko"),
            "module Z { export fn value() -> int { return 1; } }",
        )
        .expect("write z module");
        fs::write(
            root.join("src/nested/a.ko"),
            "module A { export fn value() -> int { return 2; } }",
        )
        .expect("write a module");
        fs::write(root.join("src/readme.md"), "ignored").expect("write non-source");
        fs::write(
            root.join("target/generated/ignored.ko"),
            "module Ignored {}",
        )
        .expect("write generated source");
        let modules = discover_source_modules(&root).expect("discover package sources");
        assert_eq!(
            modules
                .iter()
                .map(|module| module.source_name.as_str())
                .collect::<Vec<_>>(),
            ["src/nested/a.ko", "src/z.ko"]
        );
        assert_eq!(
            logical_source_name(Path::new(r"src\nested\a.ko"), &root)
                .expect("portable relative name"),
            "src/nested/a.ko"
        );
        let outside = root.parent().expect("temporary parent").join("outside.ko");
        let error = logical_source_name(&outside, &root)
            .expect_err("absolute source outside project root must fail closed");
        assert!(matches!(error, BuildError::InvalidPath { .. }));
        fs::remove_dir_all(root).expect("remove discovery root");
    }
    #[test]
    fn lsp_open_sources_require_explicit_graph_and_reuse_cached_parses() {
        let driver = BuildDriver::new(CompilerSession::default(), "editor-test");
        let sources = vec![
            SourceModuleUnit {
                source_name: "open/app.ko".to_owned(),
                source: "seiyaku App { view fn run() authorize(anyone) -> int { return Math::value(); } }".to_owned(),
            },
            SourceModuleUnit {
                source_name: "open/math.ko".to_owned(),
                source: "module Math { export fn value() -> int { return 7; } }".to_owned(),
            },
        ];
        let error = driver
            .check_lsp_open_sources(sources.clone())
            .expect_err("the editor must not infer module linking authority");
        assert_eq!(
            error
                .into_diagnostics()
                .expect("structured error")
                .diagnostics[0]
                .code,
            "E_PROJECT_MANIFEST_REQUIRED"
        );
        assert_eq!(driver.graph.parse_attempt_count(), 2);
        driver
            .check_lsp_open_sources(sources)
            .expect_err("unchanged editor sources still require an explicit graph");
        assert_eq!(
            driver.graph.parse_attempt_count(),
            2,
            "an unchanged editor graph must reuse both parsed sources",
        );
    }
    #[test]
    fn exact_project_check_links_only_declared_imports_and_preserves_lint_owner() {
        let driver = BuildDriver::new(CompilerSession::default(), "check-test");
        let graph = SourceLinkRequest { artifacts: Vec::new(),
            sources: Vec::new(),
            root: SourceModuleUnit {
                source_name: "contracts/app.ko".to_owned(),
                source:
                    "seiyaku App { view fn run() authorize(anyone) -> int { return helpers::value(unused: 1); } }"
                        .to_owned(),
            },
            imports: vec![ImportBinding {
                alias: "helpers".to_owned(),
                package: "std/math@1.0.0".to_owned(),
            }],
            packages: vec![SourcePackageUnit { artifacts: Vec::new(),
                sources: Vec::new(),
                identity: "std/math@1.0.0".to_owned(),
                modules: vec![SourceModuleUnit {
                    source_name: "modules/math.ko".to_owned(),
                    source: "module Math { export fn value(int unused) -> int { return 7; } }"
                        .to_owned(),
                }],
                exports: BTreeSet::from(["value".to_owned()]),
                imports: Vec::new(),
            }],
        };
        let warnings = driver
            .check_project(graph.clone())
            .expect("the exact imported module graph is valid");
        assert!(warnings.iter().any(|warning| {
            warning.package_identity.as_deref() == Some("std/math@1.0.0")
                && warning.source_name == "modules/math.ko"
                && warning.warning.diagnostic_code() == "K5003"
        }));
        assert_eq!(
            driver.graph.parse_attempt_count(),
            2,
            "typed linking and lint collection must share cached parses",
        );
        let mut missing_import = graph;
        missing_import.imports.clear();
        let error = driver
            .check_project(missing_import)
            .expect_err("a nearby package must not become an implicit root import");
        let diagnostics = error.into_diagnostics().expect("structured link error");
        let diagnostic = diagnostics
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "E_UNKNOWN_IMPORT_ALIAS")
            .expect("unknown explicit import diagnostic");
        assert_eq!(
            diagnostic
                .primary_span
                .as_ref()
                .and_then(|span| span.source.as_deref()),
            Some("contracts/app.ko")
        );
    }
    #[test]
    fn graph_link_and_codegen_handoff_from_a_small_caller() {
        let graph = boundary_source_graph();
        std::thread::Builder::new()
            .name("kotodama-small-graph-caller".to_owned())
            .stack_size(128 * 1024)
            .spawn(move || {
                let linked = ModuleBuildGraph::default()
                    .link(graph.clone(), crate::linker::LinkerOptions::default())
                    .expect("boundary-depth source graph must link on the compiler worker");
                assert_eq!(linked.program.unit.name, "StackMargin");
                drop(linked);

                let output = BuildDriver::new(CompilerSession::default(), "stack-margin-test")
                    .compile_project(graph, "contracts/stack-margin.ko")
                    .expect("boundary-depth graph codegen must stay on the compiler worker");
                assert!(!output.artifact.is_empty());
            })
            .expect("spawn small graph caller")
            .join()
            .expect("graph linking and codegen must not consume the caller stack");
    }
    #[test]
    fn concurrent_boundary_graphs_do_not_deadlock_worker_gates() {
        const CALLERS: usize = 4;
        let graph = Arc::new(ModuleBuildGraph::default());
        let request = Arc::new(boundary_source_graph());
        let barrier = Arc::new(std::sync::Barrier::new(CALLERS));
        std::thread::scope(|scope| {
            let handles = (0..CALLERS)
                .map(|caller| {
                    let graph = Arc::clone(&graph);
                    let request = Arc::clone(&request);
                    let barrier = Arc::clone(&barrier);
                    std::thread::Builder::new()
                        .name(format!("kotodama-graph-gate-caller-{caller}"))
                        .stack_size(128 * 1024)
                        .spawn_scoped(scope, move || {
                            barrier.wait();
                            let linked = graph
                                .link(
                                    request.as_ref().clone(),
                                    crate::linker::LinkerOptions::default(),
                                )
                                .expect("parallel boundary source graph");
                            assert_eq!(linked.program.unit.name, "StackMargin");
                        })
                        .expect("spawn graph gate caller")
                })
                .collect::<Vec<_>>();
            for handle in handles {
                handle.join().expect("graph gate caller must not panic");
            }
        });
    }
    #[test]
    fn lsp_open_sources_reject_multiple_seiyaku_roots_with_cross_file_spans() {
        let driver = BuildDriver::new(CompilerSession::default(), "editor-test");
        let error = driver
            .check_lsp_open_sources(vec![
                SourceModuleUnit {
                    source_name: "open/a.ko".to_owned(),
                    source: "seiyaku A { view fn a() authorize(anyone) -> int { return 1; } }"
                        .to_owned(),
                },
                SourceModuleUnit {
                    source_name: "open/b.ko".to_owned(),
                    source: "seiyaku B { view fn b() authorize(anyone) -> int { return 2; } }"
                        .to_owned(),
                },
            ])
            .expect_err("one editor project cannot contain two deployable roots");
        let diagnostics = error.into_diagnostics().expect("structured project error");
        let diagnostic = &diagnostics.diagnostics[0];
        assert_eq!(diagnostic.code, "E_MULTIPLE_SEIYAKU_ROOTS");
        assert_eq!(
            diagnostic
                .primary_span
                .as_ref()
                .and_then(|span| span.source.as_deref()),
            Some("open/a.ko")
        );
        assert_eq!(diagnostic.labels.len(), 1);
        assert_eq!(
            diagnostic.labels[0].span.source.as_deref(),
            Some("open/b.ko")
        );
    }
    #[test]
    fn cache_reader_rejects_sparse_oversized_files_without_allocating_them() {
        let root = temp_root("bounded-cache");
        fs::create_dir_all(&root).expect("create bounded cache root");
        let path = root.join("hostile-cache-output");
        let file = fs::File::create(&path).expect("create sparse cache output");
        file.set_len(
            u64::try_from(MAX_CACHED_OUTPUT_BYTES)
                .expect("cache limit fits u64")
                .saturating_add(1),
        )
        .expect("extend sparse cache output");
        drop(file);
        assert!(read_bounded_file(&path, MAX_CACHED_OUTPUT_BYTES).is_none());
        assert!(atomic_write_if_changed(&path, b"repaired").expect("replace hostile cache output"));
        assert_eq!(fs::read(&path).expect("read repaired output"), b"repaired");
        fs::remove_dir_all(root).expect("remove bounded cache root");
    }
    #[test]
    fn authenticated_noop_build_writes_nothing_and_tampering_rebuilds() {
        let root = temp_root("fresh");
        let source = "seiyaku Demo { view fn ping() authorize(anyone) -> int { return 1; } }";
        let driver = BuildDriver::new(CompilerSession::default(), "test-toolchain");
        let initial = driver
            .build_source(request(&root, source))
            .expect("initial build");
        assert_eq!(initial.status, BuildStatus::Built);
        let tracked = [
            initial.paths.artifact.clone(),
            initial.paths.manifest.clone(),
            initial.paths.source_map.clone(),
            initial.paths.budget.clone(),
            initial.paths.interface.clone().expect("interface"),
            initial.paths.record.clone(),
        ];
        let before = tracked
            .iter()
            .map(|path| fs::metadata(path).expect("output metadata").modified().ok())
            .collect::<Vec<_>>();
        let fresh = driver
            .build_source(request(&root, source))
            .expect("authenticated no-op");
        assert_eq!(fresh.status, BuildStatus::Fresh);
        let after = tracked
            .iter()
            .map(|path| fs::metadata(path).expect("output metadata").modified().ok())
            .collect::<Vec<_>>();
        assert_eq!(before, after, "a fresh build must not rewrite any output");
        for path in &tracked {
            let original = fs::read(path).expect("read generated output");
            fs::write(path, b"tampered").expect("tamper generated output");
            let rebuilt = driver
                .build_source(request(&root, source))
                .expect("tampered output must rebuild");
            assert_eq!(
                rebuilt.status,
                BuildStatus::Built,
                "tampered {}",
                path.display()
            );
            if *path == rebuilt.paths.record {
                assert_ne!(fs::read(path).expect("rebuilt record"), b"tampered");
            } else {
                assert_eq!(fs::read(path).expect("rebuilt output"), original);
            }
        }
        fs::remove_dir_all(root).expect("remove test build root");
    }
    #[test]
    fn authenticated_module_graph_hit_with_fresh_driver_performs_zero_work_or_writes() {
        let root = temp_root("linked-fresh");
        let driver = BuildDriver::new(CompilerSession::default(), "test-toolchain");
        let module_v1 = "module Math { export fn value() -> int { return 1; } }";
        let first = driver
            .build_project(linked_request(&root, module_v1))
            .expect("initial linked build");
        assert_eq!(first.status, BuildStatus::Built);
        assert_eq!(driver.graph.parse_attempt_count(), 2);
        assert_eq!(driver.graph.link_attempt_count(), 1);
        let tracked = [
            first.paths.artifact.clone(),
            first.paths.manifest.clone(),
            first.paths.source_map.clone(),
            first.paths.budget.clone(),
            first.paths.interface.clone().expect("interface"),
            first.paths.record.clone(),
        ];
        let before = tracked
            .iter()
            .map(|path| fs::metadata(path).expect("output metadata").modified().ok())
            .collect::<Vec<_>>();
        let fresh_driver = BuildDriver::new(CompilerSession::default(), "test-toolchain");
        let fresh = fresh_driver
            .build_project(linked_request(&root, module_v1))
            .expect("authenticated linked no-op");
        assert_eq!(fresh.status, BuildStatus::Fresh);
        assert_eq!(
            fresh_driver.graph.parse_attempt_count(),
            0,
            "a fresh process-local graph must not parse an authenticated output hit",
        );
        assert_eq!(
            fresh_driver.graph.link_attempt_count(),
            0,
            "a fresh driver must return before typed-HIR linking or compilation",
        );
        let after = tracked
            .iter()
            .map(|path| fs::metadata(path).expect("output metadata").modified().ok())
            .collect::<Vec<_>>();
        assert_eq!(
            before, after,
            "an authenticated module-graph hit must rewrite none of its six outputs",
        );
        let changed = driver
            .build_project(linked_request(
                &root,
                "module Math { export fn value() -> int { return 2; } }",
            ))
            .expect("changed module rebuild");
        assert_eq!(changed.status, BuildStatus::Built);
        assert_eq!(
            driver.graph.parse_attempt_count(),
            3,
            "only the changed module should require a new parse",
        );
        assert_eq!(driver.graph.link_attempt_count(), 2);
        assert_ne!(first.artifact_hash, changed.artifact_hash);
        fs::remove_dir_all(root).expect("remove linked build root");
    }
    #[test]
    fn linked_build_errors_recover_the_complete_structured_bundle() {
        let root = temp_root("linked-diagnostics");
        let root_source = "seiyaku App { view fn run() authorize(anyone) -> int { return helpers::hidden() + helpers::also_hidden(); } }";
        let mut request = linked_request(
            &root,
            "module Math { fn hidden() -> int { return 1; } fn also_hidden() -> int { return 2; } }",
        );
        request.graph.root.source = root_source.to_owned();
        request.graph.packages[0].exports.clear();
        let error = BuildDriver::new(CompilerSession::default(), "test-toolchain")
            .build_linked_source(&ModuleBuildGraph::default(), request)
            .expect_err("unexported linked calls must fail before publication");
        let diagnostics = error
            .into_diagnostics()
            .expect("linked compiler failures retain diagnostics");
        assert_eq!(diagnostics.diagnostics.len(), 2);
        let mut spellings = Vec::new();
        for diagnostic in &diagnostics.diagnostics {
            assert_eq!(diagnostic.code, "E_UNEXPORTED_SYMBOL");
            assert_eq!(
                diagnostic
                    .primary_span
                    .as_ref()
                    .and_then(|span| span.source.as_deref()),
                Some("contracts/app.ko")
            );
            let range = diagnostic
                .primary_span
                .as_ref()
                .and_then(|span| span.byte_range)
                .expect("linked import diagnostic range");
            let start = usize::try_from(range.start).expect("range start fits usize");
            let end = usize::try_from(range.end).expect("range end fits usize");
            spellings.push(&root_source[start..end]);
        }
        assert_eq!(spellings, ["helpers::hidden", "helpers::also_hidden"]);
        assert!(!root.join("test/app.to").exists());
    }
    #[test]
    fn sidecar_manifest_avoids_an_unrequested_sibling_and_remains_cacheable() {
        let root = temp_root("sidecar-manifest");
        let source = "seiyaku Demo { view fn ping() authorize(anyone) -> int { return 1; } }";
        let driver = BuildDriver::new(CompilerSession::default(), "test-toolchain");
        let mut build = request(&root, source);
        let sibling_manifest = build.layout.manifest.clone();
        build.layout = build.layout.with_sidecar_manifest();
        let first = driver.build_source(build.clone()).expect("initial build");
        assert_eq!(first.status, BuildStatus::Built);
        assert!(!sibling_manifest.exists());
        assert!(first.paths.manifest.is_file());
        assert!(first.paths.manifest.to_string_lossy().contains(".sidecars"));
        let second = driver.build_source(build).expect("authenticated no-op");
        assert_eq!(second.status, BuildStatus::Fresh);
        assert_eq!(second.paths.manifest, first.paths.manifest);
        assert!(!sibling_manifest.exists());
        fs::remove_dir_all(root).expect("remove sidecar manifest root");
    }
    #[test]
    fn record_parser_rejects_duplicates_unknown_fields_and_truncation() {
        let valid = BuildRecord {
            input: "input".to_owned(),
            artifact_hash: "code".to_owned(),
            artifact: "artifact".to_owned(),
            manifest: "manifest".to_owned(),
            source_map: "source".to_owned(),
            budget: "budget".to_owned(),
            interface: None,
        }
        .render();
        assert!(BuildRecord::parse(&valid).is_some());
        assert!(BuildRecord::parse(&format!("{valid}input=again\n")).is_none());
        assert!(BuildRecord::parse(&format!("{valid}unknown=value\n")).is_none());
        assert!(BuildRecord::parse("schema=kotodama-build-v1\ninput=x\n").is_none());
    }
    #[test]
    fn batch_rejects_lexically_colliding_outputs_before_building() {
        let root = temp_root("collision");
        let source = "seiyaku Demo { view fn ping() authorize(anyone) -> int { return 1; } }";
        let first = request(&root, source);
        let mut second = request(&root, source);
        second.source_name = "contracts/other.ko".to_owned();
        second.layout.artifact = root.join("test/sub/../demo.to");
        let driver = BuildDriver::new(CompilerSession::default(), "test-toolchain");
        let error = driver
            .build_source_batch(vec![first, second])
            .expect_err("colliding output roots must fail preflight");
        assert!(matches!(error, BuildError::OutputCollision { .. }));
        assert!(!root.exists(), "preflight failure must not publish outputs");
    }
    #[test]
    fn direct_build_rejects_colliding_artifact_and_manifest_paths() {
        let root = temp_root("direct-collision");
        let output = root.join("demo.to");
        let mut build = request(
            &root,
            "seiyaku Demo { view fn ping() authorize(anyone) -> int { return 1; } }",
        );
        build.layout = PublishLayout::for_artifact(output.clone(), Some(output.clone()), None)
            .expect("construct adversarial layout");
        let driver = BuildDriver::new(CompilerSession::default(), "test-toolchain");
        let error = driver
            .build_source(build)
            .expect_err("one path cannot contain both artifact and manifest bytes");
        assert!(matches!(error, BuildError::OutputCollision { .. }));
        assert!(!output.exists());
    }
    #[cfg(unix)]
    #[test]
    fn batch_rejects_output_aliases_through_symlinked_directories() {
        use std::os::unix::fs::symlink;
        let root = temp_root("symlink-collision");
        let real = root.join("real");
        let alias = root.join("alias");
        fs::create_dir_all(&real).expect("create real output directory");
        symlink(&real, &alias).expect("create output directory alias");
        let source = "seiyaku Demo { view fn ping() authorize(anyone) -> int { return 1; } }";
        let mut first = request(&real, source);
        first.source_name = "contracts/first.ko".to_owned();
        let mut second = request(&alias, source);
        second.source_name = "contracts/second.ko".to_owned();
        let driver = BuildDriver::new(CompilerSession::default(), "test-toolchain");
        let error = driver
            .build_source_batch(vec![first, second])
            .expect_err("physical output aliases must fail before parallel publication");
        assert!(matches!(error, BuildError::OutputCollision { .. }));
        assert!(!real.join("test/demo.to").exists());
        fs::remove_dir_all(root).expect("remove symlink collision root");
    }
    #[test]
    fn profile_and_policy_are_cache_dimensions() {
        let root = temp_root("policy");
        let source = "seiyaku Demo { view fn ping() authorize(anyone) -> int { return 1; } }";
        let plain = BuildDriver::new(CompilerSession::default(), "test-toolchain");
        let zk_options = crate::compiler::CompilerOptions {
            force_zk: true,
            ..crate::compiler::CompilerOptions::default()
        };
        let zk = BuildDriver::new(CompilerSession::new(zk_options), "test-toolchain");
        let request = request(&root, source);
        let plain_key = plain.input_fingerprint(
            b"source",
            &request.source_name,
            &request.profile,
            request.source.as_bytes(),
        );
        let zk_key = zk.input_fingerprint(
            b"source",
            &request.source_name,
            &request.profile,
            request.source.as_bytes(),
        );
        assert_ne!(plain_key, zk_key);
        let release_key = plain.input_fingerprint(
            b"source",
            &request.source_name,
            "release",
            request.source.as_bytes(),
        );
        assert_ne!(plain_key, release_key);
        assert!(matches!(
            PublishLayout::standard(&root, "../escape", "demo", false),
            Err(BuildError::InvalidProfile(_))
        ));
    }
    #[test]
    fn atomic_writer_does_not_replace_equal_file() {
        let root = temp_root("atomic");
        let path = root.join("value.bin");
        assert!(atomic_write_if_changed(&path, b"same").expect("initial write"));
        assert!(!atomic_write_if_changed(&path, b"same").expect("no-op write"));
        fs::remove_dir_all(root).expect("remove atomic test root");
    }
    #[test]
    fn atomic_writer_supports_relative_leaf_outputs() {
        let path = PathBuf::from(format!(
            ".kotodama-relative-output-{}-{}",
            std::process::id(),
            TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed),
        ));
        assert_eq!(output_parent(&path), Path::new("."));
        assert!(atomic_write_if_changed(&path, b"relative").expect("publish relative output"));
        assert_eq!(fs::read(&path).expect("read relative output"), b"relative");
        fs::remove_file(path).expect("remove relative output");
    }
    #[test]
    fn atomic_writer_rejects_linked_output_without_changing_any_alias() {
        let root = temp_root("linked-output");
        let path = root.join("value.bin");
        let alias = root.join("alias.bin");
        atomic_write_if_changed(&path, b"original").expect("initial output");
        fs::hard_link(&path, &alias).expect("host supports regular hardlinks");
        assert!(atomic_write_if_changed(&path, b"different").is_err());
        assert!(read_bounded_file(&path, 64).is_none());
        assert_eq!(fs::read(&path).unwrap(), b"original");
        assert_eq!(fs::read(&alias).unwrap(), b"original");
        fs::remove_dir_all(root).expect("remove linked output root");
    }
}
