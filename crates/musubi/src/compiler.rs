//! Authenticated Musubi lock graph to canonical Kotodama compiler bridge.
//!
//! Registry sources cross this boundary only after the immutable cache has
//! re-authenticated the complete bundle against an exact lock node. Local path
//! packages and registry releases have distinct canonical compiler identities derived from
//! their structural fields. Every registry import binds to the exact consumer-lock selection.
use crate::{
    cache::{CachedCompilerPackageV1, MusubiCache},
    compiler_identity::{local_package, registry_release},
    graph::{GraphErrorV1, collect_local_members, resolve_workspace_local},
    lockfile::{LockContextV1, LockfileV1},
    manifest::{ConcreteDependency, DependencySpec, LocalTarget, PortablePath, parse_manifest},
    package::PackagePlan,
    resolver::ResolveModeV1,
    workspace::{EffectiveDependency, Workspace, WorkspaceMember},
};
use iroha_data_model::musubi::{
    MusubiContentDigestV1, MusubiDependencyKindV1, MusubiPackageSelectorV1,
    MusubiVerificationLockV1, MusubiVerificationNodeV1,
};
use ivm::{SyscallPolicy, syscalls::compute_abi_hash};
use kotodama_lang::{
    compiler::{CompilerMode, CompilerOptions},
    diagnostic::{Diagnostic, DiagnosticBundle, SourceSpan},
    driver::{
        BuildDriver, BuildError, BuildStatus, LinkedSourceBuildRequest, PublishLayout, PublishMode,
        discover_source_modules,
    },
    linker::{
        ImportBinding, ModuleBuildGraph, SourceLinkRequest, SourceModuleUnit,
        SourcePackageGraphRequest, SourcePackageUnit,
    },
    session::CompilerSession,
};
use kotodama_toolchain::koto_test_driver::declared_test_target_source_v1;
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    path::{Path, PathBuf},
};
/// Compiler operation requested by the Cargo-style command surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompilerActionV1 {
    /// Parse, type-check, link, and lint without writing artifacts.
    Check,
    /// Compile and atomically publish every selected local contract target.
    Build,
}
/// One generated contract artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompilerArtifactV1 {
    /// Selected package declaring the contract target.
    pub package: MusubiPackageSelectorV1,
    /// Exact manifest-declared contract target name.
    pub target: String,
    /// Canonical source path used in diagnostics.
    pub source: String,
    /// Published `.to` path.
    pub artifact: PathBuf,
    /// Published compiler manifest path.
    pub manifest: PathBuf,
    /// Published public interface path.
    pub interface: PathBuf,
    /// Canonical advertised public entrypoint names.
    pub entrypoints: Vec<String>,
    /// Canonical ABI hash of the built artifact.
    pub abi_hash: String,
    /// Canonical code hash.
    pub artifact_hash: String,
    /// Whether compilation ran or authenticated outputs were already fresh.
    pub fresh: bool,
}
/// Canonical typed interface proven for one reusable local package.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompilerPackageInterfaceV1 {
    /// Public package selector used by the workspace root.
    pub package: MusubiPackageSelectorV1,
    /// Domain-separated digest of the exact exported function signatures.
    pub digest: MusubiContentDigestV1,
}
/// Successful compiler graph execution summary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompilerExecutionV1 {
    /// Number of local packages whose declared library and contract sources were validated.
    pub validated_packages: usize,
    /// Number of deployable contract roots checked or built.
    pub contract_targets: usize,
    /// Canonical non-fatal lint diagnostics from checked deployable roots, in source order.
    pub warnings: Vec<Diagnostic>,
    /// Generated artifacts (empty for `check`).
    pub artifacts: Vec<CompilerArtifactV1>,
    /// Typed reusable-package interfaces in canonical package order.
    pub package_interfaces: Vec<CompilerPackageInterfaceV1>,
}
/// Stable compiler-bridge failure.
#[derive(Debug, PartialEq, Eq)]
pub enum CompilerBridgeErrorV1 {
    /// Local workspace/path graph construction failed.
    Workspace(String),
    /// The exact lock graph is missing a required parent-local edge.
    Lock(String),
    /// An authenticated cache entry is absent, corrupt, or inconsistent.
    Cache(String),
    /// A cached or local manifest/source set is not a valid V1 package.
    Package(String),
    /// The canonical Kotodama compiler rejected source with structured diagnostics.
    Diagnostics(DiagnosticBundle),
    /// The compiler driver failed outside source diagnostics (filesystem, publication, invariant).
    Compiler(String),
}
impl CompilerBridgeErrorV1 {
    /// Classify a driver failure, retaining canonical source diagnostics without rendering them.
    pub(crate) fn from_build_error(error: BuildError) -> Self {
        match error.into_diagnostics() {
            Ok(diagnostics) => Self::Diagnostics(diagnostics),
            Err(other) => Self::Compiler(other.to_string()),
        }
    }
    /// Classify a driver failure and attach one contextual note to each source diagnostic.
    fn from_build_error_with_note(error: BuildError, note: &str) -> Self {
        match Self::from_build_error(error) {
            Self::Diagnostics(mut bundle) => {
                for diagnostic in &mut bundle.diagnostics {
                    diagnostic.notes.push(note.to_owned());
                }
                Self::Diagnostics(bundle)
            }
            Self::Compiler(reason) => Self::Compiler(format!("{note}: {reason}")),
            other => other,
        }
    }
    /// Name local workspace sources in source diagnostics by their workspace-relative paths.
    ///
    /// See [`locate_workspace_diagnostic`].
    fn located(self, member_directory: &str, local_directories: &BTreeMap<String, String>) -> Self {
        match self {
            Self::Diagnostics(mut bundle) => {
                for diagnostic in &mut bundle.diagnostics {
                    locate_workspace_diagnostic(diagnostic, member_directory, local_directories);
                }
                Self::Diagnostics(bundle)
            }
            other => other,
        }
    }
}
/// Workspace-relative directory of one member, empty for the package at the workspace root.
pub fn member_directory(member: &WorkspaceMember) -> &str {
    match member.workspace_path.as_str() {
        "." => "",
        path => path,
    }
}
/// Rewrite every span of one diagnostic that points into a local workspace package.
///
/// The compiler names a contract root's sources relative to its own package and names local
/// library sources by an opaque local package identity. Musubi reports them from the workspace
/// root instead: a span without a package identity belongs to `member_directory`, and a span whose
/// identity is a local package belongs to that package's directory. Both become
/// `<directory>/<source>` without a package identity, so human, JSON and SARIF output name the
/// file the user edits. Registry package spans keep their identity and logical path.
pub fn locate_workspace_diagnostic(
    diagnostic: &mut Diagnostic,
    member_directory: &str,
    local_directories: &BTreeMap<String, String>,
) {
    let locate = |span: &mut SourceSpan| {
        let directory = match span.package_identity.as_deref() {
            None => member_directory,
            Some(identity) => match local_directories.get(identity) {
                Some(directory) => directory.as_str(),
                None => return,
            },
        };
        span.package_identity = None;
        if let Some(source) = span.source.as_mut()
            && !directory.is_empty()
            && !Path::new(source.as_str()).is_absolute()
        {
            *source = format!("{directory}/{source}");
        }
    };
    if let Some(span) = &mut diagnostic.primary_span {
        locate(span);
    }
    for label in &mut diagnostic.labels {
        locate(&mut label.span);
    }
    for fix in diagnostic
        .fix
        .iter_mut()
        .chain(diagnostic.alternative_fixes.iter_mut())
    {
        locate(&mut fix.span);
    }
}
impl fmt::Display for CompilerBridgeErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Workspace(reason) => write!(formatter, "invalid local compiler graph: {reason}"),
            Self::Lock(reason) => write!(formatter, "invalid exact compiler lock: {reason}"),
            Self::Cache(reason) => write!(formatter, "authenticated package cache error: {reason}"),
            Self::Package(reason) => write!(formatter, "invalid compiler package: {reason}"),
            Self::Diagnostics(bundle) => formatter.write_str(&bundle.render_human()),
            Self::Compiler(reason) => write!(formatter, "Kotodama compiler failed: {reason}"),
        }
    }
}
impl Error for CompilerBridgeErrorV1 {}
trait RegistryCompilerSourceV1 {
    fn load(
        &self,
        node: &MusubiVerificationNodeV1,
    ) -> Result<CachedCompilerPackageV1, CompilerBridgeErrorV1>;
}
impl RegistryCompilerSourceV1 for MusubiCache {
    fn load(
        &self,
        node: &MusubiVerificationNodeV1,
    ) -> Result<CachedCompilerPackageV1, CompilerBridgeErrorV1> {
        self.load_compiler_package(node)
            .map_err(|error| CompilerBridgeErrorV1::Cache(error.to_string()))
    }
}
impl RegistryCompilerSourceV1 for Option<&MusubiCache> {
    fn load(
        &self,
        node: &MusubiVerificationNodeV1,
    ) -> Result<CachedCompilerPackageV1, CompilerBridgeErrorV1> {
        self.ok_or_else(|| {
            CompilerBridgeErrorV1::Cache(
                "an immutable registry node requires an authenticated cache".to_owned(),
            )
        })?
        .load(node)
    }
}
/// Compiler settings shared by every selected package in one graph execution.
#[derive(Clone, Copy, Debug)]
pub struct CompilerSettingsV1<'a> {
    /// Canonical account network discriminant used by compilation.
    pub chain_discriminant: u16,
    /// Enable the Kotodama ZK source surface for every selected contract root.
    pub zk_enabled: bool,
    /// Output profile selected by the command.
    pub profile: &'a str,
}
/// Execute one compiler operation for selected workspace packages.
///
/// Local graphs need no registry cache. Every registry node requires an authenticated cache.
///
/// The settings apply uniformly to every selected contract root.
pub fn execute_compiler_graph(
    cache: Option<&MusubiCache>,
    workspace: &Workspace,
    selected: &[MusubiPackageSelectorV1],
    lock: &LockfileV1,
    action: CompilerActionV1,
    settings: CompilerSettingsV1<'_>,
) -> Result<CompilerExecutionV1, CompilerBridgeErrorV1> {
    execute_with_source(&cache, workspace, selected, lock, action, settings)
}
/// Rebuild and validate the exact clean source tree that will enter a release bundle.
///
/// Unlike ordinary workspace checking, every root import is taken from the normalized
/// publication lock. A local path dependency therefore cannot influence the packaged build.
pub fn validate_packaged_plan(
    cache: &MusubiCache,
    plan: &PackagePlan,
    verification_lock: &MusubiVerificationLockV1,
    chain_discriminant: u16,
) -> Result<MusubiContentDigestV1, CompilerBridgeErrorV1> {
    validate_packaged_with_source(cache, plan, verification_lock, chain_discriminant)
}
#[allow(
    clippy::too_many_lines,
    reason = "clean-package validation is one fail-closed compiler boundary"
)]
fn validate_packaged_with_source<S: RegistryCompilerSourceV1>(
    source: &S,
    plan: &PackagePlan,
    verification_lock: &MusubiVerificationLockV1,
    chain_discriminant: u16,
) -> Result<MusubiContentDigestV1, CompilerBridgeErrorV1> {
    if chain_discriminant == 0 {
        return Err(CompilerBridgeErrorV1::Package(
            "account chain discriminant must be non-zero".to_owned(),
        ));
    }
    verification_lock
        .validate()
        .map_err(|error| CompilerBridgeErrorV1::Lock(error.to_string()))?;
    let manifest_source = std::str::from_utf8(plan.canonical_manifest())
        .map_err(|_| CompilerBridgeErrorV1::Package("packaged manifest is not UTF-8".to_owned()))?;
    let manifest = parse_manifest(manifest_source)
        .map_err(|error| CompilerBridgeErrorV1::Package(error.to_string()))?;
    if manifest.workspace.is_some() || !manifest.dev_dependencies.is_empty() {
        return Err(CompilerBridgeErrorV1::Package(
            "clean publication manifest retains workspace or development state".to_owned(),
        ));
    }
    let package = manifest
        .resolve_package(None)
        .map_err(|error| CompilerBridgeErrorV1::Package(error.to_string()))?;
    if package.selector.name != verification_lock.root.package.name
        || package.version != verification_lock.root.version
    {
        return Err(CompilerBridgeErrorV1::Package(
            "clean package identity disagrees with its structural release root".to_owned(),
        ));
    }
    validate_manifest_dependency_edges(
        &verification_lock.root,
        &verification_lock.root_dependencies,
        &manifest.dependencies,
    )?;
    let expected_abi = compute_abi_hash(SyscallPolicy::AbiV1);
    let mut dependencies = Vec::with_capacity(verification_lock.nodes.len());
    for node in &verification_lock.nodes {
        if node.abi.abi_hash != expected_abi {
            return Err(CompilerBridgeErrorV1::Package(format!(
                "release `{}` targets a different IVM ABI V1 hash",
                node.release
            )));
        }
        dependencies.push(cached_source_package(node, source.load(node)?)?);
    }
    dependencies.sort_by(|left, right| left.identity.cmp(&right.identity));
    if dependencies
        .windows(2)
        .any(|pair| pair[0].identity == pair[1].identity)
    {
        return Err(CompilerBridgeErrorV1::Lock(
            "publication lock contains duplicate exact releases".to_owned(),
        ));
    }
    let imports = verification_lock
        .root_dependencies
        .iter()
        .map(|edge| ImportBinding {
            alias: edge.alias.to_string(),
            package: registry_release(&edge.selected),
        })
        .collect::<Vec<_>>();
    let root = manifest
        .library
        .as_ref()
        .map(|library| {
            let mut modules = Vec::new();
            for file in plan.files() {
                let Some(source_name) = relative_library_source(file.path(), &library.source_dir)
                else {
                    continue;
                };
                let source = std::str::from_utf8(file.bytes()).map_err(|_| {
                    CompilerBridgeErrorV1::Package(format!(
                        "packaged Kotodama source `{}` is not UTF-8",
                        file.path()
                    ))
                })?;
                modules.push(SourceModuleUnit {
                    source_name,
                    source: source.to_owned(),
                });
            }
            if modules.is_empty() {
                return Err(CompilerBridgeErrorV1::Package(
                    "clean publication package has no declared Kotodama library sources".to_owned(),
                ));
            }
            let (modules, mut sources) = partition_library_sources(modules)?;
            let existing_names = modules
                .iter()
                .chain(&sources)
                .map(|source| source.source_name.clone())
                .collect::<BTreeSet<_>>();
            sources.extend(
                packaged_source_inventory(plan)?
                    .into_iter()
                    .filter(|source| !existing_names.contains(&source.source_name)),
            );
            Ok(SourcePackageUnit {
                artifacts: packaged_artifact_inventory(plan),
                sources,
                identity: registry_release(&verification_lock.root),
                modules,
                exports: library.exports.iter().map(ToString::to_string).collect(),
                imports: imports.clone(),
            })
        })
        .transpose()?;
    let target_packages = root
        .iter()
        .cloned()
        .chain(dependencies.iter().cloned())
        .collect::<Vec<_>>();
    let options = CompilerOptions {
        chain_discriminant,
        mode: CompilerMode::Production,
        ..CompilerOptions::default()
    };
    validate_exact_registry_interfaces_v1(
        verification_lock.nodes.iter(),
        &dependencies,
        options.clone(),
    )
    .map_err(CompilerBridgeErrorV1::Cache)?;
    let driver = BuildDriver::for_current_executable(CompilerSession::new(options))
        .map_err(CompilerBridgeErrorV1::from_build_error)?;
    let interface_digest = match root {
        Some(root) => {
            let validated = driver
                .validate_package_project(SourcePackageGraphRequest {
                    package: root,
                    dependencies: dependencies.clone(),
                })
                .map_err(CompilerBridgeErrorV1::from_build_error)?;
            MusubiContentDigestV1::new(*validated.interface_fingerprint.as_ref())
        }
        None => contract_only_interface_digest(),
    };
    validate_packaged_contract_targets(
        &driver,
        plan,
        &manifest.contracts,
        &imports,
        &target_packages,
    )?;
    validate_packaged_test_targets(
        plan,
        &manifest.tests,
        &manifest.contracts,
        &imports,
        &target_packages,
        chain_discriminant,
    )?;
    Ok(interface_digest)
}
/// Canonical commitment stating that a source package declares no reusable library interface.
pub fn contract_only_interface_digest() -> MusubiContentDigestV1 {
    MusubiContentDigestV1::new(
        *iroha::crypto::Hash::new(b"musubi-contract-only-interface-v1\0").as_ref(),
    )
}
/// Recompute every authenticated registry package interface against one exact source graph.
///
/// The caller supplies source units copied out of authenticated immutable cache entries. This
/// helper never opens their recorded source paths. Every package is selected as the local package
/// once so its semantic interface can be compared with the corresponding exact lock commitment.
#[allow(
    single_use_lifetimes,
    clippy::needless_lifetimes,
    reason = "stable Rust requires a named lifetime for references nested in impl Trait items"
)]
pub fn validate_exact_registry_interfaces_v1<'node>(
    nodes: impl IntoIterator<Item = &'node MusubiVerificationNodeV1>,
    packages: &[SourcePackageUnit],
    options: CompilerOptions,
) -> Result<(), String> {
    if options.mode != CompilerMode::Production {
        return Err("exact registry interfaces require production compiler mode".to_owned());
    }
    let nodes = nodes.into_iter().collect::<Vec<_>>();
    if nodes.len() != packages.len() {
        return Err("authenticated registry node/package counts disagree".to_owned());
    }
    let packages_by_identity = packages
        .iter()
        .enumerate()
        .map(|(index, package)| (package.identity.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    if packages_by_identity.len() != packages.len() {
        return Err("the exact registry graph contains duplicate source identities".to_owned());
    }
    let graph = ModuleBuildGraph::default();
    let session = CompilerSession::new(options);
    for node in nodes {
        let identity = registry_release(&node.release);
        let package_index = packages_by_identity.get(identity.as_str()).ok_or_else(|| {
            format!(
                "release `{}` has no authenticated source package in the exact graph",
                node.release
            )
        })?;
        let dependencies = packages
            .iter()
            .enumerate()
            .filter(|(index, _)| index != package_index)
            .map(|(_, candidate)| candidate)
            .cloned()
            .collect();
        let validated = session
            .validate_package_graph(
                &graph,
                SourcePackageGraphRequest {
                    package: packages[*package_index].clone(),
                    dependencies,
                },
            )
            .map_err(|error| {
                format!(
                    "release `{}` failed exact typed-interface validation: {error}",
                    node.release
                )
            })?;
        if validated.interface_fingerprint.as_ref() != node.interface_digest.as_bytes() {
            return Err(format!(
                "release `{}` typed interface disagrees with its exact lock digest",
                node.release
            ));
        }
    }
    Ok(())
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PackagedTargetKindV1 {
    Contract,
    Test,
    Source,
}
impl PackagedTargetKindV1 {
    const fn label(self) -> &'static str {
        match self {
            Self::Contract => "contract",
            Self::Test => "test",
            Self::Source => "Kotodama",
        }
    }
}
fn validate_packaged_contract_targets(
    driver: &BuildDriver,
    plan: &PackagePlan,
    targets: &[LocalTarget],
    imports: &[ImportBinding],
    dependencies: &[SourcePackageUnit],
) -> Result<(), CompilerBridgeErrorV1> {
    for target in targets {
        let root = packaged_contract_source_unit(plan, &target.path)?;
        let source_name = root.source_name.clone();
        driver
            .check_project(SourceLinkRequest { artifacts: packaged_artifact_inventory(plan),
                sources: packaged_source_inventory(plan)?.into_iter().filter(|source| source.source_name != root.source_name).collect(),
                root,
                imports: imports.to_vec(),
                packages: dependencies.to_vec(),
            })
            .map_err(|error| {
                CompilerBridgeErrorV1::from_build_error_with_note(
                    error,
                    &format!(
                        "packaged contract target `{}` source `{source_name}` failed clean validation",
                        target.name
                    ),
                )
            })?;
    }
    Ok(())
}
fn validate_packaged_test_targets(
    plan: &PackagePlan,
    targets: &[LocalTarget],
    contract_targets: &[LocalTarget],
    imports: &[ImportBinding],
    dependencies: &[SourcePackageUnit],
    chain_discriminant: u16,
) -> Result<(), CompilerBridgeErrorV1> {
    let graph = ModuleBuildGraph::default();
    let mut contracts = BTreeMap::new();
    for target in contract_targets {
        let source = packaged_contract_source_unit(plan, &target.path)?;
        contracts.insert(source.source_name.clone(), source);
    }
    for target in targets {
        for root in packaged_test_source_units(plan, &target.path)? {
            let source_name = root.source_name.clone();
            let declared_target = declared_test_target_source_v1(&root).map_err(|error| {
                error.diagnostics.map_or_else(
                    || CompilerBridgeErrorV1::Package(error.message),
                    CompilerBridgeErrorV1::Diagnostics,
                )
            })?;
            let contract = declared_target.as_ref().map(|name| {
                contracts.get(name).ok_or_else(|| CompilerBridgeErrorV1::Package(format!(
                    "packaged test source `{source_name}` targets `{name}`, which is not a packaged manifest-declared contract"
                )))
            }).transpose()?;
            kotodama_toolchain::koto_test_driver::discover_declared_test_names_source_set_with_sources_v1(&root, contract, &packaged_source_inventory(plan)?).map_err(|error| {
                CompilerBridgeErrorV1::Package(format!(
                    "packaged test target `{}` source `{source_name}` is not a valid V1 test source set: {error}",
                    target.name
                ))
            })?;
            let (compile_root, test_sources) = match contract {
                Some(contract) => (contract.clone(), vec![root]),
                None => (root, Vec::new()),
            };
            let compile_source_name = compile_root.source_name.clone();
            graph
                .build_test_project_with_sources(
                    SourceLinkRequest { artifacts: packaged_artifact_inventory(plan),
                        sources: packaged_source_inventory(plan)?.into_iter().filter(|source| source.source_name != compile_root.source_name && !test_sources.iter().any(|test| test.source_name == source.source_name)).collect(),
                        root: compile_root,
                        imports: imports.to_vec(),
                        packages: dependencies.to_vec(),
                    },
                    &test_sources,
                    CompilerOptions {
                        chain_discriminant,
                        mode: CompilerMode::Test,
                        ..CompilerOptions::default()
                    },
                    &compile_source_name,
                )
                .map_err(|mut diagnostics| {
                    let note = format!(
                        "packaged test target `{}` source `{source_name}` failed clean validation against normal dependencies only; development dependencies do not propagate",
                        target.name
                    );
                    for diagnostic in &mut diagnostics.diagnostics {
                        diagnostic.notes.push(note.clone());
                    }
                    CompilerBridgeErrorV1::Diagnostics(diagnostics)
                })?;
        }
    }
    Ok(())
}
fn packaged_contract_source_unit(
    plan: &PackagePlan,
    target: &PortablePath,
) -> Result<SourceModuleUnit, CompilerBridgeErrorV1> {
    let path = target.as_str();
    let file = plan.files().iter().find(|file| file.path() == path)
        .filter(|file| has_kotodama_extension(file.path()))
        .ok_or_else(|| CompilerBridgeErrorV1::Package(format!(
            "packaged contract target `{path}` must identify one exact `.ko` source file; contract directory discovery is not supported"
        )))?;
    packaged_source_unit(path, path, file.bytes(), PackagedTargetKindV1::Contract)
}
fn packaged_artifact_inventory(
    plan: &PackagePlan,
) -> Vec<kotodama_lang::linker::SourceContractArtifact> {
    plan.files()
        .iter()
        .filter(|file| {
            Path::new(file.path())
                .extension()
                .is_some_and(|extension| extension == "to")
        })
        .map(|file| kotodama_lang::linker::SourceContractArtifact {
            source_name: file.path().to_owned(),
            artifact: file.bytes().to_vec(),
        })
        .collect()
}
fn packaged_source_inventory(
    plan: &PackagePlan,
) -> Result<Vec<SourceModuleUnit>, CompilerBridgeErrorV1> {
    plan.files()
        .iter()
        .filter(|file| has_kotodama_extension(file.path()))
        .map(|file| {
            packaged_source_unit(
                file.path(),
                file.path(),
                file.bytes(),
                PackagedTargetKindV1::Source,
            )
        })
        .collect()
}
fn sources_contains_path(sources: &[SourceModuleUnit], name: &str) -> bool {
    sources.iter().any(|source| source.source_name == name)
}
/// Identify named module or contract roots without parsing declaration fragments.
pub fn is_named_source_unit(source: &SourceModuleUnit) -> bool {
    let file = kotodama_lang::source::SourceFile::new(
        kotodama_lang::source::SourceId(0),
        source.source_name.as_str(),
        source.source.as_str(),
    );
    let lexed = kotodama_lang::syntax::lex(&file, kotodama_lang::source::FrontendBudget::v1());
    matches!(
        lexed
            .tokens
            .iter()
            .find(|token| !token.kind.is_trivia())
            .map(|token| token.kind),
        Some(
            kotodama_lang::syntax::SyntaxKind::KwModule
                | kotodama_lang::syntax::SyntaxKind::KwSeiyaku
        )
    )
}
/// Separate module roots from their included source fragments.
pub fn partition_library_sources(
    sources: Vec<SourceModuleUnit>,
) -> Result<(Vec<SourceModuleUnit>, Vec<SourceModuleUnit>), CompilerBridgeErrorV1> {
    let mut modules = Vec::new();
    let mut companions = Vec::new();
    for source in sources {
        let file = kotodama_lang::source::SourceFile::new(
            kotodama_lang::source::SourceId(0),
            source.source_name.as_str(),
            source.source.as_str(),
        );
        let lexed = kotodama_lang::syntax::lex(&file, kotodama_lang::source::FrontendBudget::v1());
        let kind = lexed
            .tokens
            .iter()
            .find(|token| !token.kind.is_trivia())
            .map(|token| token.kind);
        match kind {
            Some(kotodama_lang::syntax::SyntaxKind::KwModule) => modules.push(source),
            Some(kotodama_lang::syntax::SyntaxKind::KwSeiyaku) => {
                return Err(CompilerBridgeErrorV1::Package(format!(
                    "library source `{}` declares a deployable contract",
                    source.source_name
                )));
            }
            _ => companions.push(source),
        }
    }
    Ok((modules, companions))
}
fn packaged_test_source_units(
    plan: &PackagePlan,
    target: &PortablePath,
) -> Result<Vec<SourceModuleUnit>, CompilerBridgeErrorV1> {
    let target_path = target.as_str();
    if target_path != "."
        && let Some(file) = plan.files().iter().find(|file| file.path() == target_path)
    {
        if !has_kotodama_extension(file.path()) {
            return Err(CompilerBridgeErrorV1::Package(format!(
                "packaged test target `{target_path}` must be a `.ko` file or directory"
            )));
        }
        return packaged_source_unit(
            file.path(),
            file.path(),
            file.bytes(),
            PackagedTargetKindV1::Test,
        )
        .map(|unit| vec![unit]);
    }
    let prefix = (target_path != ".").then(|| format!("{target_path}/"));
    let mut units = Vec::new();
    // PackagePlan already bounds the entire retained source set and has bytewise-sorted paths.
    for file in plan.files() {
        let relative = match prefix.as_deref() {
            Some(prefix) => match file.path().strip_prefix(prefix) {
                Some(relative) => relative,
                None => continue,
            },
            None => file.path(),
        };
        if relative.is_empty() || !has_kotodama_extension(relative) {
            continue;
        }
        let source = packaged_source_unit(
            file.path(),
            file.path(),
            file.bytes(),
            PackagedTargetKindV1::Test,
        )?;
        if is_named_source_unit(&source) {
            units.push(source);
        }
    }
    if units.is_empty() {
        return Err(CompilerBridgeErrorV1::Package(format!(
            "packaged test target directory `{target_path}` contains no `.ko` sources"
        )));
    }
    Ok(units)
}
fn packaged_source_unit(
    packaged_path: &str,
    source_name: &str,
    bytes: &[u8],
    kind: PackagedTargetKindV1,
) -> Result<SourceModuleUnit, CompilerBridgeErrorV1> {
    let source = std::str::from_utf8(bytes).map_err(|_| {
        CompilerBridgeErrorV1::Package(format!(
            "packaged {} source `{packaged_path}` is not UTF-8",
            kind.label()
        ))
    })?;
    Ok(SourceModuleUnit {
        source_name: source_name.to_owned(),
        source: source.to_owned(),
    })
}
#[allow(
    clippy::too_many_lines,
    reason = "compiler graph authentication and execution form one deterministic workflow"
)]
struct PreparedSourceGraph {
    local_members: Vec<WorkspaceMember>,
    local_identities: BTreeMap<PathBuf, String>,
    local_directories: BTreeMap<String, String>,
    local_units: BTreeMap<String, SourcePackageUnit>,
    all_packages: Vec<SourcePackageUnit>,
}
fn prepare_source_graph<S: RegistryCompilerSourceV1>(
    source: &S,
    workspace: &Workspace,
    selected: &[MusubiPackageSelectorV1],
    lock: &LockfileV1,
    overlays: &BTreeMap<PathBuf, String>,
) -> Result<PreparedSourceGraph, CompilerBridgeErrorV1> {
    lock.validate()
        .map_err(|error| CompilerBridgeErrorV1::Lock(error.to_string()))?;
    if matches!(&lock.context, LockContextV1::Local { .. }) {
        let validated = resolve_workspace_local(
            workspace,
            selected,
            Some(lock.clone()),
            ResolveModeV1::Locked,
        )
        .map_err(|error| CompilerBridgeErrorV1::Lock(error.to_string()))?;
        if validated.is_none() {
            return Err(CompilerBridgeErrorV1::Lock(
                "local lock cannot authorize a registry dependency".to_owned(),
            ));
        }
    }
    let local_members =
        collect_local_members(workspace, selected).map_err(|error| graph_error(&error))?;
    let local_identities = local_members
        .iter()
        .map(|member| {
            (
                member.manifest_path.clone(),
                local_package(&member.package.selector, &member.package.version),
            )
        })
        .collect::<BTreeMap<_, _>>();
    if local_identities.len() != local_members.len() {
        return Err(CompilerBridgeErrorV1::Package(
            "two local packages share one manifest path".to_owned(),
        ));
    }
    let local_directories = local_members
        .iter()
        .map(|member| {
            (
                local_package(&member.package.selector, &member.package.version),
                member_directory(member).to_owned(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut local_units = BTreeMap::new();
    for member in &local_members {
        let Some(unit) = local_source_package(member, lock, &local_identities, overlays)
            .map_err(|error| error.located(member_directory(member), &local_directories))?
        else {
            continue;
        };
        if local_units.insert(unit.identity.clone(), unit).is_some() {
            return Err(CompilerBridgeErrorV1::Package(format!(
                "duplicate local identity `{}`",
                local_package(&member.package.selector, &member.package.version)
            )));
        }
    }
    let expected_abi = compute_abi_hash(SyscallPolicy::AbiV1);
    let mut registry_units = BTreeMap::new();
    for node in &lock.nodes {
        if node.abi.abi_hash != expected_abi {
            return Err(CompilerBridgeErrorV1::Package(format!(
                "release `{}` targets a different IVM ABI V1 hash",
                node.release
            )));
        }
        let cached = source.load(node)?;
        let unit = cached_source_package(node, cached)?;
        if registry_units.insert(unit.identity.clone(), unit).is_some() {
            return Err(CompilerBridgeErrorV1::Lock(format!(
                "duplicate registry release `{}`",
                node.release
            )));
        }
    }
    let all_packages = local_units
        .values()
        .chain(registry_units.values())
        .cloned()
        .collect::<Vec<_>>();
    Ok(PreparedSourceGraph {
        local_members,
        local_identities,
        local_directories,
        local_units,
        all_packages,
    })
}
fn execute_with_source<S: RegistryCompilerSourceV1>(
    source: &S,
    workspace: &Workspace,
    selected: &[MusubiPackageSelectorV1],
    lock: &LockfileV1,
    action: CompilerActionV1,
    settings: CompilerSettingsV1<'_>,
) -> Result<CompilerExecutionV1, CompilerBridgeErrorV1> {
    let CompilerSettingsV1 {
        chain_discriminant,
        zk_enabled,
        profile,
    } = settings;
    if chain_discriminant == 0 {
        return Err(CompilerBridgeErrorV1::Package(
            "account chain discriminant must be non-zero".to_owned(),
        ));
    }
    let PreparedSourceGraph {
        local_members,
        local_identities,
        local_directories,
        local_units,
        all_packages,
    } = prepare_source_graph(source, workspace, selected, lock, &BTreeMap::new())?;
    let selected_set = selected.iter().cloned().collect::<BTreeSet<_>>();
    let mut package_interfaces = Vec::with_capacity(local_members.len());
    let options = CompilerOptions {
        chain_discriminant,
        mode: CompilerMode::Production,
        force_zk: zk_enabled,
        ..CompilerOptions::default()
    };
    let driver = BuildDriver::for_current_executable(CompilerSession::new(options))
        .map_err(CompilerBridgeErrorV1::from_build_error)?;
    for member in &local_members {
        let identity = local_package(&member.package.selector, &member.package.version);
        let Some(package) = local_units.get(&identity).cloned() else {
            continue;
        };
        let dependencies = all_packages
            .iter()
            .filter(|candidate| candidate.identity != identity)
            .cloned()
            .collect();
        let validated = driver
            .validate_package_project(SourcePackageGraphRequest {
                package,
                dependencies,
            })
            .map_err(|error| {
                CompilerBridgeErrorV1::from_build_error(error)
                    .located(member_directory(member), &local_directories)
            })?;
        package_interfaces.push(CompilerPackageInterfaceV1 {
            package: member.package.selector.clone(),
            digest: MusubiContentDigestV1::new(*validated.interface_fingerprint.as_ref()),
        });
    }
    package_interfaces.sort_by(|left, right| left.package.cmp(&right.package));
    let mut result = CompilerExecutionV1 {
        validated_packages: local_members.len(),
        contract_targets: 0,
        warnings: Vec::new(),
        artifacts: Vec::new(),
        package_interfaces,
    };
    for member in local_members
        .iter()
        .filter(|member| selected_set.contains(&member.package.selector))
    {
        let target_root = package_target_root(workspace, member);
        let locate = |error: CompilerBridgeErrorV1| {
            error.located(member_directory(member), &local_directories)
        };
        let imports = local_imports(member, lock, &local_identities).map_err(locate)?;
        if matches!(action, CompilerActionV1::Check) {
            let identity = local_package(&member.package.selector, &member.package.version);
            if let Some(package) = local_units.get(&identity) {
                let lints = member_lint_config(workspace, member);
                let warnings = driver
                    .check_package_project(SourcePackageGraphRequest {
                        package: package.clone(),
                        dependencies: all_packages
                            .iter()
                            .filter(|package| package.identity != identity)
                            .cloned()
                            .collect(),
                    })
                    .map_err(CompilerBridgeErrorV1::from_build_error)
                    .map_err(locate)?;
                result
                    .warnings
                    .extend(warnings.into_iter().filter_map(|warning| {
                        let lint = match lints.level(warning.warning.code) {
                            kotodama_lang::lint::LintLevel::Allow => return None,
                            level => warning.warning.with_level(level),
                        };
                        let mut diagnostic = lint.to_diagnostic(
                            &warning.source_name,
                            warning.package_identity.as_deref(),
                            kotodama_lang::i18n::detect_language(),
                        );
                        locate_workspace_diagnostic(
                            &mut diagnostic,
                            member_directory(member),
                            &local_directories,
                        );
                        Some(diagnostic)
                    }));
            }
        }
        for target in &member.manifest.contracts {
            let root = contract_source_unit(member, &target.path).map_err(locate)?;
            result.contract_targets += 1;
            let graph = contract_source_graph(
                member,
                &target.path,
                imports.clone(),
                all_packages.clone(),
                &BTreeMap::new(),
            )
            .map_err(locate)?;
            match action {
                CompilerActionV1::Check => {
                    let language = kotodama_lang::i18n::detect_language();
                    let lints = member_lint_config(workspace, member);
                    result.warnings.extend(
                        driver
                            .check_project(graph)
                            .map_err(CompilerBridgeErrorV1::from_build_error)
                            .map_err(locate)?
                            .into_iter()
                            .filter_map(|warning| {
                                let lint = match lints.level(warning.warning.code) {
                                    kotodama_lang::lint::LintLevel::Allow => return None,
                                    level => warning.warning.with_level(level),
                                };
                                let mut diagnostic = lint.to_diagnostic(
                                    &warning.source_name,
                                    warning.package_identity.as_deref(),
                                    language,
                                );
                                locate_workspace_diagnostic(
                                    &mut diagnostic,
                                    member_directory(member),
                                    &local_directories,
                                );
                                Some(diagnostic)
                            }),
                    );
                }
                CompilerActionV1::Build => {
                    let stem = target.name.to_string();
                    let layout = PublishLayout::standard(&target_root, profile, &stem, true)
                        .map_err(CompilerBridgeErrorV1::from_build_error)?;
                    let outcome = driver
                        .build_project(LinkedSourceBuildRequest {
                            source_name: root.source_name.clone(),
                            graph,
                            profile: profile.to_owned(),
                            layout,
                            mode: PublishMode::Write,
                        })
                        .map_err(CompilerBridgeErrorV1::from_build_error)
                        .map_err(locate)?;
                    let deployment_warnings =
                        kotodama_toolchain::deployment_diagnostics::artifact_deployment_warnings(
                            &outcome.artifact,
                        )
                        .map_err(|error| {
                            CompilerBridgeErrorV1::Compiler(format!(
                                "fresh artifact failed canonical admission: {error}"
                            ))
                        })?;
                    result.warnings.extend(deployment_warnings.diagnostics);
                    result.artifacts.push(CompilerArtifactV1 {
                        package: member.package.selector.clone(),
                        target: stem,
                        source: root.source_name,
                        manifest: outcome.paths.manifest,
                        interface: outcome.paths.interface.ok_or_else(|| {
                            CompilerBridgeErrorV1::Compiler(
                                "compiler omitted the requested public interface".to_owned(),
                            )
                        })?,
                        entrypoints: outcome
                            .manifest
                            .entrypoints
                            .unwrap_or_default()
                            .into_iter()
                            .map(|entrypoint| entrypoint.name)
                            .collect(),
                        abi_hash: outcome
                            .manifest
                            .abi_hash
                            .ok_or_else(|| {
                                CompilerBridgeErrorV1::Compiler(
                                    "compiler omitted the canonical ABI hash".to_owned(),
                                )
                            })?
                            .to_string(),
                        artifact: outcome.paths.artifact,
                        artifact_hash: outcome.artifact_hash.to_string(),
                        fresh: outcome.status == BuildStatus::Fresh,
                    });
                }
            }
        }
    }
    result.warnings = DiagnosticBundle::new(std::mem::take(&mut result.warnings)).diagnostics;
    result.artifacts.sort_by(|left, right| {
        left.package
            .cmp(&right.package)
            .then_with(|| left.target.cmp(&right.target))
            .then_with(|| left.source.cmp(&right.source))
    });
    Ok(result)
}
/// Lint levels for one checked member: its own `[lints]`, else the workspace root's, else the
/// defaults (every lint warns).
fn member_lint_config(
    workspace: &Workspace,
    member: &WorkspaceMember,
) -> kotodama_lang::session::LintConfig {
    member
        .manifest
        .lints
        .clone()
        .or_else(|| workspace.root_manifest().lints.clone())
        .unwrap_or_default()
}
fn package_target_root(workspace: &Workspace, member: &WorkspaceMember) -> PathBuf {
    workspace
        .root()
        .join("target/kotodama")
        .join(member.package.selector.namespace.as_str())
        .join(member.package.selector.name.as_str())
}
fn graph_error(error: &GraphErrorV1) -> CompilerBridgeErrorV1 {
    CompilerBridgeErrorV1::Workspace(error.to_string())
}
fn local_source_package(
    member: &WorkspaceMember,
    lock: &LockfileV1,
    local_identities: &BTreeMap<PathBuf, String>,
    overlays: &BTreeMap<PathBuf, String>,
) -> Result<Option<SourcePackageUnit>, CompilerBridgeErrorV1> {
    let Some(library) = member.manifest.library.as_ref() else {
        return Ok(None);
    };
    let mut units =
        discover_source_modules(&member.package_root.join(library.source_dir.to_path_buf()))
            .map_err(CompilerBridgeErrorV1::from_build_error)?;
    for source in &mut units {
        if library.source_dir.as_str() != "." {
            source.source_name = format!("{}/{}", library.source_dir.as_str(), source.source_name);
        }
    }
    for (path, text) in overlays {
        if path.extension().is_some_and(|ext| ext == "ko")
            && path.starts_with(member.package_root.join(library.source_dir.to_path_buf()))
        {
            let relative = path
                .strip_prefix(&member.package_root)
                .map_err(|error| CompilerBridgeErrorV1::Package(error.to_string()))?;
            let name = relative.to_string_lossy().replace('\\', "/");
            if let Some(source) = units.iter_mut().find(|source| source.source_name == name) {
                source.source.clone_from(text);
            } else {
                units.push(SourceModuleUnit {
                    source_name: name,
                    source: text.clone(),
                });
            }
        }
    }
    units.sort_by(|left, right| left.source_name.cmp(&right.source_name));
    let (modules, mut sources) = partition_library_sources(units)?;
    let loaded =
        kotodama_lang::driver::load_source_inventory(&modules, &member.package_root, overlays)
            .map_err(CompilerBridgeErrorV1::from_build_error)?;
    for source in loaded.sources {
        if !sources_contains_path(&sources, &source.source_name) {
            sources.push(source);
        }
    }
    if modules.is_empty() {
        return Err(CompilerBridgeErrorV1::Package(format!(
            "local package `{}` has no Kotodama library sources",
            member.package.selector
        )));
    }
    Ok(Some(SourcePackageUnit {
        artifacts: loaded.artifacts,
        sources,
        identity: local_package(&member.package.selector, &member.package.version),
        modules,
        exports: library.exports.iter().map(ToString::to_string).collect(),
        imports: local_imports(member, lock, local_identities)?,
    }))
}
fn local_imports(
    member: &WorkspaceMember,
    lock: &LockfileV1,
    local_identities: &BTreeMap<PathBuf, String>,
) -> Result<Vec<ImportBinding>, CompilerBridgeErrorV1> {
    let root = lock
        .roots
        .binary_search_by(|root| root.package.cmp(&member.package.selector))
        .ok()
        .and_then(|index| lock.roots.get(index))
        .ok_or_else(|| {
            CompilerBridgeErrorV1::Lock(format!(
                "local package `{}` has no exact lock root",
                member.package.selector
            ))
        })?;
    let mut imports = Vec::new();
    for dependency in member.dependencies.values() {
        let package = match &dependency.local_manifest {
            Some(manifest) => local_identities.get(manifest).cloned().ok_or_else(|| {
                CompilerBridgeErrorV1::Package(format!(
                    "local path dependency `{}` is absent from the compiler graph",
                    dependency.alias
                ))
            })?,
            None => exact_edge_identity(root, dependency)?,
        };
        imports.push(ImportBinding {
            alias: dependency.alias.to_string(),
            package,
        });
    }
    imports.sort_by(|left, right| {
        left.alias
            .cmp(&right.alias)
            .then_with(|| left.package.cmp(&right.package))
    });
    Ok(imports)
}
fn exact_edge_identity(
    root: &crate::lockfile::LockedRootV1,
    dependency: &EffectiveDependency,
) -> Result<String, CompilerBridgeErrorV1> {
    let edge = root
        .dependencies
        .iter()
        .find(|edge| edge.alias == dependency.alias && edge.kind == MusubiDependencyKindV1::Normal)
        .ok_or_else(|| {
            CompilerBridgeErrorV1::Lock(format!(
                "normal dependency `{}` has no exact selected edge",
                dependency.alias
            ))
        })?;
    match &dependency.dependency {
        ConcreteDependency::Registry {
            package,
            requirement,
        } => {
            if edge.requirement != *requirement || edge.selected.package.name != package.name {
                return Err(CompilerBridgeErrorV1::Lock(format!(
                    "normal dependency `{}` disagrees with its exact edge",
                    dependency.alias
                )));
            }
        }
        ConcreteDependency::Path { .. } => {
            return Err(CompilerBridgeErrorV1::Package(format!(
                "path dependency `{}` lost its local manifest",
                dependency.alias
            )));
        }
    }
    Ok(registry_release(&edge.selected))
}
fn cached_source_package(
    node: &MusubiVerificationNodeV1,
    cached: CachedCompilerPackageV1,
) -> Result<SourcePackageUnit, CompilerBridgeErrorV1> {
    let manifest = parse_manifest(&cached.manifest)
        .map_err(|error| CompilerBridgeErrorV1::Package(error.to_string()))?;
    if manifest.workspace.is_some() || !manifest.dev_dependencies.is_empty() {
        return Err(CompilerBridgeErrorV1::Package(format!(
            "cached release `{}` contains workspace or development state",
            node.release
        )));
    }
    validate_manifest_dependency_edges(&node.release, &node.dependencies, &manifest.dependencies)?;
    let package = manifest
        .resolve_package(None)
        .map_err(|error| CompilerBridgeErrorV1::Package(error.to_string()))?;
    if package.selector.name != node.release.package.name
        || package.version != node.release.version
        || package.edition != cached.semantic_release.edition
        || package.abi_version != node.abi.abi_version
    {
        return Err(CompilerBridgeErrorV1::Package(format!(
            "cached manifest identity for `{}` is inconsistent",
            node.release
        )));
    }
    let Some(library) = manifest.library.as_ref() else {
        if !cached.semantic_release.exports.is_empty()
            || node.interface_digest != contract_only_interface_digest()
        {
            return Err(CompilerBridgeErrorV1::Package(format!(
                "contract-only release `{}` has an inconsistent absent-library interface commitment",
                node.release
            )));
        }
        return Err(CompilerBridgeErrorV1::Package(format!(
            "dependency `{}` is a contract-only release and cannot be imported as a library",
            node.release
        )));
    };
    let declared_exports = library
        .exports
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    let semantic_exports = cached
        .semantic_release
        .exports
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    if declared_exports != semantic_exports {
        return Err(CompilerBridgeErrorV1::Package(format!(
            "cached release `{}` export table disagrees with its semantic manifest",
            node.release
        )));
    }
    let inventory = cached
        .kotodama_sources
        .into_iter()
        .map(|source| SourceModuleUnit {
            source_name: source.path,
            source: source.source,
        })
        .collect::<Vec<_>>();
    let (modules, _) = partition_library_sources(
        inventory
            .iter()
            .filter(|source| {
                relative_library_source(&source.source_name, &library.source_dir).is_some()
            })
            .cloned()
            .collect(),
    )?;
    let sources = inventory
        .into_iter()
        .filter(|source| {
            !modules
                .iter()
                .any(|module| module.source_name == source.source_name)
        })
        .collect();
    if modules.is_empty() {
        return Err(CompilerBridgeErrorV1::Package(format!(
            "cached release `{}` has no declared library sources",
            node.release
        )));
    }
    let imports = node
        .dependencies
        .iter()
        .map(|edge| ImportBinding {
            alias: edge.alias.to_string(),
            package: registry_release(&edge.selected),
        })
        .collect();
    Ok(SourcePackageUnit {
        artifacts: cached.contract_artifacts,
        sources,
        identity: registry_release(&node.release),
        modules,
        exports: semantic_exports,
        imports,
    })
}
fn validate_manifest_dependency_edges(
    release: &iroha_data_model::musubi::MusubiReleaseIdV1,
    edges: &[iroha_data_model::musubi::MusubiExactDependencyEdgeV1],
    dependencies: &BTreeMap<iroha_model_base::name::Name, DependencySpec>,
) -> Result<(), CompilerBridgeErrorV1> {
    if dependencies.len() != edges.len() {
        return Err(CompilerBridgeErrorV1::Package(format!(
            "release `{release}` manifest dependency count disagrees with its exact proof"
        )));
    }
    for (alias, dependency) in dependencies {
        let DependencySpec::Concrete(ConcreteDependency::Registry {
            package,
            requirement,
        }) = dependency
        else {
            return Err(CompilerBridgeErrorV1::Package(format!(
                "release `{release}` retains a path or workspace dependency `{alias}`"
            )));
        };
        let edge = edges
            .iter()
            .find(|edge| &edge.alias == alias)
            .ok_or_else(|| {
                CompilerBridgeErrorV1::Package(format!(
                    "release `{release}` dependency `{alias}` has no exact edge"
                ))
            })?;
        if edge.kind != MusubiDependencyKindV1::Normal
            || edge.package.name != package.name
            || edge.requirement != *requirement
        {
            return Err(CompilerBridgeErrorV1::Package(format!(
                "release `{release}` dependency `{alias}` disagrees with its exact edge"
            )));
        }
    }
    Ok(())
}
fn relative_library_source(path: &str, source_dir: &PortablePath) -> Option<String> {
    if source_dir.as_str() == "." {
        return has_kotodama_extension(path).then(|| path.to_owned());
    }
    let prefix = format!("{}/", source_dir.as_str());
    path.strip_prefix(&prefix)
        .filter(|relative| has_kotodama_extension(relative) && !relative.is_empty())
        .map(|_| path.to_owned())
}
fn has_kotodama_extension(path: &str) -> bool {
    path.strip_suffix(".ko").is_some()
}
fn contract_source_graph(
    member: &WorkspaceMember,
    path: &PortablePath,
    imports: Vec<ImportBinding>,
    packages: Vec<SourcePackageUnit>,
    overlays: &BTreeMap<PathBuf, String>,
) -> Result<SourceLinkRequest, CompilerBridgeErrorV1> {
    let mut root = contract_source_unit(member, path)?;
    if let Some(text) = overlays.get(&member.package_root.join(path.to_path_buf())) {
        root.source.clone_from(text);
    }
    let kotodama_lang::driver::SourceInventory { sources, artifacts } =
        kotodama_lang::driver::load_source_inventory(
            std::slice::from_ref(&root),
            &member.package_root,
            overlays,
        )
        .map_err(CompilerBridgeErrorV1::from_build_error)?;
    Ok(SourceLinkRequest {
        artifacts,
        root,
        sources,
        imports,
        packages,
    })
}
/// Capture every selected target through the same authenticated source boundary as a build.
pub fn load_editor_projects(
    cache: Option<&MusubiCache>,
    workspace: &Workspace,
    selected: &[MusubiPackageSelectorV1],
    lock: &LockfileV1,
    overlays: &BTreeMap<PathBuf, String>,
) -> Result<Vec<kotodama_toolchain::lsp::ProjectTarget>, CompilerBridgeErrorV1> {
    use kotodama_lang::driver::{
        LoadedProjectGraph, LoadedSourceProject, ProjectManifestSource, ProjectSourceKey,
    };
    use kotodama_lang::source::TextRange;
    let PreparedSourceGraph {
        local_members,
        local_identities,
        all_packages,
        ..
    } = prepare_source_graph(&cache, workspace, selected, lock, overlays)?;
    let physical_directories = local_members
        .iter()
        .map(|member| {
            (
                local_package(&member.package.selector, &member.package.version),
                member.package_root.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut manifests = Vec::new();
    for member in &local_members {
        let path = &member.manifest_path;
        let text = overlays
            .get(path)
            .cloned()
            .map_or_else(|| kotodama_lang::driver::read_source_file(path), Ok)
            .map_err(CompilerBridgeErrorV1::from_build_error)?;
        // Policy is owned by parse_manifest; the immutable TOML tree supplies exact token ranges.
        let captured = parse_manifest(&text)
            .map_err(|error| CompilerBridgeErrorV1::Package(error.to_string()))?;
        if captured != member.manifest {
            return Err(CompilerBridgeErrorV1::Package(format!(
                "manifest `{}` changed while capturing the project; reload",
                path.display()
            )));
        }
        let document = toml_edit::Document::parse(text.as_str())
            .map_err(|error| CompilerBridgeErrorV1::Package(error.to_string()))?;
        let mut exports = BTreeMap::new();
        if let Some(values) = document
            .get("lib")
            .and_then(|lib| lib.get("exports"))
            .and_then(toml_edit::Item::as_array)
        {
            for value in values {
                let name = value.as_str().ok_or_else(|| {
                    CompilerBridgeErrorV1::Package("export must be a string".into())
                })?;
                let range = value.span().ok_or_else(|| {
                    CompilerBridgeErrorV1::Package(
                        "export token has no exact TOML source range".into(),
                    )
                })?;
                exports.insert(
                    (
                        local_package(&member.package.selector, &member.package.version),
                        name.to_owned(),
                    ),
                    TextRange::new(
                        u32::try_from(range.start).map_err(|_| {
                            CompilerBridgeErrorV1::Package(
                                "manifest source start exceeds the V1 offset bound".into(),
                            )
                        })?,
                        u32::try_from(range.end).map_err(|_| {
                            CompilerBridgeErrorV1::Package(
                                "manifest source end exceeds the V1 offset bound".into(),
                            )
                        })?,
                    ),
                );
            }
        }
        manifests.push(ProjectManifestSource::new(path.clone(), text, exports));
    }
    if !manifests
        .iter()
        .any(|manifest| manifest.path() == workspace.root_manifest_path())
    {
        let path = workspace.root_manifest_path();
        let text = overlays
            .get(path)
            .cloned()
            .map_or_else(|| kotodama_lang::driver::read_source_file(path), Ok)
            .map_err(CompilerBridgeErrorV1::from_build_error)?;
        manifests.push(ProjectManifestSource::new(
            path.to_path_buf(),
            text,
            BTreeMap::new(),
        ));
    }
    let mut targets = Vec::new();
    for member in local_members
        .iter()
        .filter(|member| selected.contains(&member.package.selector))
    {
        let imports = local_imports(member, lock, &local_identities)?;
        for target in &member.manifest.contracts {
            let graph = contract_source_graph(
                member,
                &target.path,
                imports.clone(),
                all_packages.clone(),
                overlays,
            )?;
            let mut source_paths = BTreeMap::new();
            for (owner, unit) in std::iter::once((None, &graph.root))
                .chain(graph.sources.iter().map(|source| (None, source)))
                .chain(graph.packages.iter().flat_map(|package| {
                    package
                        .modules
                        .iter()
                        .chain(&package.sources)
                        .map(move |source| (Some(package.identity.clone()), source))
                }))
            {
                let root = match &owner {
                    None => &member.package_root,
                    Some(identity) => match physical_directories.get(identity) {
                        Some(root) => root,
                        None => continue,
                    },
                };
                let path = root.join(&unit.source_name);
                let path = path.canonicalize().unwrap_or(path);
                source_paths.insert(
                    ProjectSourceKey {
                        package_identity: owner,
                        source_name: unit.source_name.clone(),
                    },
                    path,
                );
            }
            targets.push(kotodama_toolchain::lsp::ProjectTarget {
                name: format!("{}::{}", member.package.selector, target.name),
                test_context: Some(kotodama_toolchain::lsp::TestContext {
                    manifest_path: workspace.root_manifest_path().to_path_buf(),
                    package: member.package.selector.to_string(),
                    contract: target.name.to_string(),
                    network: None,
                    config_path: None,
                }),
                project: LoadedSourceProject {
                    graph: LoadedProjectGraph::Source(graph),
                    source_paths,
                    manifests: manifests.clone(),
                    lints: member_lint_config(workspace, member),
                },
            });
        }
        let identity = local_package(&member.package.selector, &member.package.version);
        if let Some(package) = all_packages
            .iter()
            .find(|package| package.identity == identity)
        {
            let graph = SourcePackageGraphRequest {
                package: package.clone(),
                dependencies: all_packages
                    .iter()
                    .filter(|package| package.identity != identity)
                    .cloned()
                    .collect(),
            };
            let mut source_paths = BTreeMap::new();
            for package in std::iter::once(&graph.package).chain(&graph.dependencies) {
                let Some(root) = physical_directories.get(&package.identity) else {
                    continue;
                };
                for unit in package.modules.iter().chain(&package.sources) {
                    let path = root.join(&unit.source_name);
                    let path = path.canonicalize().unwrap_or(path);
                    source_paths.insert(
                        ProjectSourceKey {
                            package_identity: Some(package.identity.clone()),
                            source_name: unit.source_name.clone(),
                        },
                        path,
                    );
                }
            }
            targets.push(kotodama_toolchain::lsp::ProjectTarget {
                name: format!("{}::[lib]", member.package.selector),
                test_context: None,
                project: LoadedSourceProject {
                    graph: LoadedProjectGraph::Package(graph),
                    source_paths,
                    manifests: manifests.clone(),
                    lints: member_lint_config(workspace, member),
                },
            });
        }
    }
    Ok(targets)
}
fn contract_source_unit(
    member: &WorkspaceMember,
    target: &PortablePath,
) -> Result<SourceModuleUnit, CompilerBridgeErrorV1> {
    let path = member.package_root.join(target.to_path_buf());
    let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
        CompilerBridgeErrorV1::Package(format!(
            "cannot inspect contract target `{}`: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() {
        return Err(CompilerBridgeErrorV1::Package(format!(
            "contract target `{}` is a symlink",
            path.display()
        )));
    }
    if !metadata.is_file() || !has_kotodama_extension(target.as_str()) {
        return Err(CompilerBridgeErrorV1::Package(format!(
            "contract target `{}` must identify one regular `.ko` source file; directory targets are supported only for tests",
            target.as_str()
        )));
    }
    kotodama_lang::driver::read_source_file(&path)
        .map(|source| SourceModuleUnit {
            source_name: target.to_string(),
            source,
        })
        .map_err(CompilerBridgeErrorV1::from_build_error)
}
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::{
        cache::CachedKotodamaSourceV1,
        lockfile::{LockedRootV1, LockfileV1},
        package::{PackageLayout, plan_package},
        workspace::load_workspace,
    };
    use iroha_data_model::musubi::{
        ArchiveId, MUSUBI_REGISTRY_VERSION_V1, MusubiAbiBindingV1, MusubiExactDependencyEdgeV1,
        MusubiKotodamaEditionV1, MusubiPackageIdV1, MusubiPackageScopeV1, MusubiRegistrySnapshotV1,
        MusubiReleaseDigestV1, MusubiReleaseIdV1, MusubiReleaseMetadataV1,
        MusubiSemanticReleaseManifestV1, MusubiVerificationLockV1, MusubiVerificationNodeV1,
    };
    use iroha_model_base::topology::DataSpaceId;
    use std::fs;
    use tempfile::TempDir;
    #[test]
    fn local_source_diagnostics_are_named_from_the_workspace_root() {
        use kotodama_lang::diagnostic::{
            DiagnosticFix, DiagnosticLabel, DiagnosticPhase, SourcePosition,
        };
        let span = |identity: Option<&str>, source: &str| SourceSpan {
            package_identity: identity.map(ToOwned::to_owned),
            source: Some(source.to_owned()),
            start: SourcePosition { line: 1, column: 1 },
            end: SourcePosition { line: 1, column: 2 },
            byte_range: None,
        };
        let mut diagnostic = Diagnostic::error(
            "E_TEST",
            DiagnosticPhase::Semantic,
            "located",
            Some(span(None, "contracts/app.ko")),
        );
        diagnostic.labels = vec![
            DiagnosticLabel {
                span: span(Some("musubi/local/feemath"), "src/lib.ko"),
                message: "local library".to_owned(),
            },
            DiagnosticLabel {
                span: span(Some("musubi/registry/math"), "src/lib.ko"),
                message: "registry release".to_owned(),
            },
        ];
        diagnostic.fix = Some(DiagnosticFix {
            span: span(None, "contracts/app.ko"),
            replacement: "x".to_owned(),
        });
        diagnostic.alternative_fixes = vec![DiagnosticFix {
            span: span(Some("musubi/local/root"), "src/lib.ko"),
            replacement: "y".to_owned(),
        }];
        let directories = BTreeMap::from([
            ("musubi/local/feemath".to_owned(), "libs/feemath".to_owned()),
            ("musubi/local/root".to_owned(), String::new()),
        ]);
        let located =
            CompilerBridgeErrorV1::Diagnostics(DiagnosticBundle::single(diagnostic.clone()))
                .located("app", &directories);
        let CompilerBridgeErrorV1::Diagnostics(bundle) = located else {
            panic!("diagnostics stay structured");
        };
        let located = &bundle.diagnostics[0];
        let primary = located.primary_span.as_ref().expect("primary span");
        assert_eq!(primary.source.as_deref(), Some("app/contracts/app.ko"));
        assert_eq!(primary.package_identity, None);
        assert_eq!(
            located.labels[0].span.source.as_deref(),
            Some("libs/feemath/src/lib.ko")
        );
        assert_eq!(located.labels[0].span.package_identity, None);
        assert_eq!(located.labels[1].span, diagnostic.labels[1].span);
        assert_eq!(
            located.fix.as_ref().expect("fix").span.source.as_deref(),
            Some("app/contracts/app.ko")
        );
        let root = &located.alternative_fixes[0].span;
        assert_eq!(root.source.as_deref(), Some("src/lib.ko"));
        assert_eq!(root.package_identity, None);
        let mut unchanged = diagnostic.clone();
        locate_workspace_diagnostic(&mut unchanged, "", &BTreeMap::new());
        assert_eq!(unchanged.primary_span, diagnostic.primary_span);
        assert!(matches!(
            CompilerBridgeErrorV1::Compiler("io".to_owned()).located("app", &directories),
            CompilerBridgeErrorV1::Compiler(reason) if reason == "io"
        ));
    }
    #[test]
    fn named_source_units_distinguish_test_roots_from_included_fragments() {
        for (source, expected) in [
            ("/* root */ module Tests { #[test] fn works() {} }", true),
            ("// root\nseiyaku Tests { #[test] fn works() {} }", true),
            ("#[test] fn fragment() {}", false),
            ("fn module_helper() {}", false),
            ("/* module Tests {} */", false),
            ("", false),
        ] {
            assert_eq!(
                is_named_source_unit(&SourceModuleUnit {
                    source_name: "tests/unit.ko".into(),
                    source: source.into(),
                }),
                expected,
                "source: {source}",
            );
        }
    }
    #[test]
    fn library_source_inventory_classifies_entries_without_parsing_unused_fragments() {
        let (modules, sources) = partition_library_sources(vec![
            SourceModuleUnit {
                source_name: "src/math.ko".into(),
                source: "/* library */ module Math { include \"body.ko\"; }".into(),
            },
            SourceModuleUnit {
                source_name: "src/body.ko".into(),
                source: "fn value() -> int { return 7; }".into(),
            },
            SourceModuleUnit {
                source_name: "src/unrelated.ko".into(),
                source: "this deliberately malformed unused fragment".into(),
            },
        ])
        .expect("classify inventory");
        assert_eq!(modules.len(), 1);
        assert_eq!(sources.len(), 2);
        assert!(
            partition_library_sources(vec![SourceModuleUnit {
                source_name: "src/app.ko".into(),
                source: "seiyaku App {}".into()
            }])
            .is_err()
        );
    }
    struct EmptyRegistry;
    impl RegistryCompilerSourceV1 for EmptyRegistry {
        fn load(
            &self,
            node: &MusubiVerificationNodeV1,
        ) -> Result<CachedCompilerPackageV1, CompilerBridgeErrorV1> {
            Err(CompilerBridgeErrorV1::Cache(format!(
                "unexpected node `{}`",
                node.release
            )))
        }
    }
    struct FixedRegistry {
        package: CachedCompilerPackageV1,
    }
    impl RegistryCompilerSourceV1 for FixedRegistry {
        fn load(
            &self,
            node: &MusubiVerificationNodeV1,
        ) -> Result<CachedCompilerPackageV1, CompilerBridgeErrorV1> {
            if node.release != self.package.semantic_release.release {
                return Err(CompilerBridgeErrorV1::Cache(format!(
                    "unexpected node `{}`",
                    node.release
                )));
            }
            Ok(self.package.clone())
        }
    }
    fn clean_verification_lock() -> MusubiVerificationLockV1 {
        let package = MusubiPackageIdV1::new(
            DataSpaceId::new(9),
            MusubiPackageScopeV1::DataspaceRoot,
            "demo".parse().expect("package name"),
        );
        MusubiVerificationLockV1 {
            schema: MusubiVerificationLockV1::SCHEMA.to_owned(),
            version: MUSUBI_REGISTRY_VERSION_V1,
            root: MusubiReleaseIdV1::new(package, "1.0.0".parse().expect("version")),
            root_dependencies: Vec::new(),
            nodes: Vec::new(),
        }
    }
    fn write_clean_library(root: &std::path::Path) {
        fs::create_dir_all(root.join("src")).expect("source directory");
        fs::write(root.join("src/lib.ko"), "module Demo {}").expect("library source");
    }
    #[test]
    fn validates_dependency_free_local_library_without_registry_sources() {
        let temp = TempDir::new().expect("temporary directory");
        fs::create_dir_all(temp.path().join("src")).expect("source directory");
        fs::write(
            temp.path().join("Musubi.toml"),
            r#"manifest-version = 1
[package]
namespace = "apps.sora"
name = "demo"
version = "1.0.0"
edition = "1"
abi-version = 1
[lib]
source-dir = "src"
exports = ["value"]
"#,
        )
        .expect("manifest");
        fs::write(
            temp.path().join("src/lib.ko"),
            "module Demo { export fn value() -> int { return 1; } }",
        )
        .expect("source");
        let workspace = load_workspace(temp.path()).expect("workspace");
        let selector: MusubiPackageSelectorV1 = "apps.sora/demo".parse().expect("selector");
        let lock = LockfileV1::new(
            LockContextV1::Registry {
                network_id:
                    "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0"
                        .parse()
                        .expect("network id"),
                snapshot: MusubiRegistrySnapshotV1 {
                    finalized_height: 1,
                    finalized_block_hash: [2; 32],
                    index_revision: 1,
                },
            },
            vec![LockedRootV1 {
                package: selector.clone(),
                dependencies: Vec::new(),
            }],
            Vec::new(),
        )
        .expect("lock");
        let execution = execute_with_source(
            &EmptyRegistry,
            &workspace,
            std::slice::from_ref(&selector),
            &lock,
            CompilerActionV1::Check,
            CompilerSettingsV1 {
                chain_discriminant: 1,
                zk_enabled: false,
                profile: "dev",
            },
        )
        .expect("compiler graph");
        assert_eq!(execution.validated_packages, 1);
        assert_eq!(execution.contract_targets, 0);
        assert!(execution.artifacts.is_empty());
        assert_eq!(execution.package_interfaces.len(), 1);
        assert_eq!(execution.package_interfaces[0].package, selector);
        assert!(!execution.package_interfaces[0].digest.is_zero());
    }
    #[test]
    fn library_path_filter_is_component_bounded() {
        let source_dir = PortablePath::new("src").expect("source dir");
        assert_eq!(
            relative_library_source("src/math/add.ko", &source_dir).as_deref(),
            Some("src/math/add.ko")
        );
        assert_eq!(relative_library_source("src2/add.ko", &source_dir), None);
        assert_eq!(relative_library_source("src/readme.txt", &source_dir), None);
    }
    #[test]
    fn kotodama_extension_is_an_exact_case_sensitive_portable_suffix() {
        assert!(has_kotodama_extension(".ko"));
        assert!(has_kotodama_extension("src/.ko"));
        assert!(has_kotodama_extension("src/main.ko"));
        assert!(!has_kotodama_extension("src/main.KO"));
        assert!(!has_kotodama_extension("src/main.ko.bak"));
        assert!(!has_kotodama_extension("src/mainko"));
    }
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the fixture verifies one complete authenticated dependency-interface workflow"
    )]
    fn clean_publication_recomputes_each_locked_dependency_interface() {
        let temp = TempDir::new().expect("temporary directory");
        write_clean_library(temp.path());
        let root_package = MusubiPackageIdV1::new(
            DataSpaceId::new(9),
            MusubiPackageScopeV1::DataspaceRoot,
            "demo".parse().expect("root package name"),
        );
        let dependency_package = MusubiPackageIdV1::new(
            DataSpaceId::new(10),
            MusubiPackageScopeV1::DataspaceRoot,
            "dep".parse().expect("dependency package name"),
        );
        let dependency_release = MusubiReleaseIdV1::new(
            dependency_package.clone(),
            "1.0.0".parse().expect("dependency version"),
        );
        let dependency_requirement = "^1.0.0".parse().expect("dependency requirement");
        let dependency_edge = MusubiExactDependencyEdgeV1 {
            alias: "dep".parse().expect("dependency alias"),
            kind: MusubiDependencyKindV1::Normal,
            package: dependency_package.clone(),
            requirement: dependency_requirement,
            selected: dependency_release.clone(),
        };
        let expected_abi =
            MusubiAbiBindingV1::new(compute_abi_hash(SyscallPolicy::AbiV1)).expect("ABI binding");
        let substituted_interface = MusubiContentDigestV1::new([99; 32]);
        let dependency_node = MusubiVerificationNodeV1 {
            release: dependency_release.clone(),
            release_digest: MusubiReleaseDigestV1::new([11; 32]),
            archive_id: ArchiveId::new([12; 32]),
            source_digest: MusubiContentDigestV1::new([13; 32]),
            interface_digest: substituted_interface,
            abi: expected_abi,
            dependencies: Vec::new(),
        };
        let verification_lock = MusubiVerificationLockV1 {
            schema: MusubiVerificationLockV1::SCHEMA.to_owned(),
            version: MUSUBI_REGISTRY_VERSION_V1,
            root: MusubiReleaseIdV1::new(root_package, "1.0.0".parse().expect("root version")),
            root_dependencies: vec![dependency_edge],
            nodes: vec![dependency_node],
        };
        let dependency_publication_lock = MusubiVerificationLockV1 {
            schema: MusubiVerificationLockV1::SCHEMA.to_owned(),
            version: MUSUBI_REGISTRY_VERSION_V1,
            root: dependency_release.clone(),
            root_dependencies: Vec::new(),
            nodes: Vec::new(),
        };
        let registry = FixedRegistry {
            package: CachedCompilerPackageV1 {
                contract_artifacts: Vec::new(),
                source_path: temp.path().join("authenticated-cache-path-is-not-reopened"),
                manifest: r#"manifest-version = 1
[package]
namespace = "deps.sora"
name = "dep"
version = "1.0.0"
edition = "1"
abi-version = 1
[lib]
source-dir = "src"
exports = ["value"]
"#
                .to_owned(),
                kotodama_sources: vec![CachedKotodamaSourceV1 {
                    path: "src/lib.ko".to_owned(),
                    source: "module Dep { export fn value() -> int { return 1; } }".to_owned(),
                }],
                semantic_release: MusubiSemanticReleaseManifestV1 {
                    release: dependency_release,
                    edition: MusubiKotodamaEditionV1::V1,
                    abi: expected_abi,
                    dependencies: Vec::new(),
                    exports: vec!["value".parse().expect("export name")],
                    interface_digest: substituted_interface,
                    metadata: MusubiReleaseMetadataV1::default(),
                    verification_lock_digest: dependency_publication_lock.digest(),
                },
                publication_lock: dependency_publication_lock,
            },
        };
        let manifest = r#"manifest-version = 1
[package]
namespace = "apps.sora"
name = "demo"
version = "1.0.0"
edition = "1"
abi-version = 1
[lib]
source-dir = "src"
exports = []
[dependencies]
dep = { package = "deps.sora/dep", version = "^1.0.0" }
"#;
        let mut layout = PackageLayout::new(temp.path());
        layout.set_library("src");
        let plan = plan_package(&layout, manifest, &verification_lock).expect("package plan");
        assert!(matches!(
            validate_packaged_with_source(&registry, &plan, &verification_lock, 1),
            Err(CompilerBridgeErrorV1::Cache(reason))
                if reason.contains("typed interface disagrees with its exact lock digest")
        ));
    }
    /// Package declaring two named contract files and one recursively expanded test directory.
    const NAMED_TARGETS_MANIFEST: &str = r#"manifest-version = 1
[package]
namespace = "apps.sora"
name = "demo"
version = "1.0.0"
edition = "1"
abi-version = 1
[lib]
source-dir = "src"
exports = []
[[contract]]
name = "a"
path = "contracts/nested/a.ko"
[[contract]]
name = "z"
path = "contracts/z.ko"
[[test]]
name = "tests"
path = "tests"
"#;
    /// Write the library plus nested contract and test sources beside ignored non-source files.
    fn write_named_target_fixtures(root: &std::path::Path) {
        write_clean_library(root);
        for (path, source) in [
            ("contracts/z.ko", "seiyaku Z { hajimari() {} }"),
            ("contracts/nested/a.ko", "seiyaku A { hajimari() {} }"),
            ("contracts/readme.txt", "ignored"),
            ("tests/nested/z.ko", "seiyaku ZTests { #[test] fn z() {} }"),
            ("tests/a.ko", "seiyaku ATests { #[test] fn a() {} }"),
            ("tests/readme.txt", "ignored"),
        ] {
            let path = root.join(path);
            fs::create_dir_all(path.parent().expect("fixture parent")).expect("fixture directory");
            fs::write(path, source).expect("fixture source");
        }
    }
    #[test]
    fn named_contract_targets_keep_one_source_and_artifact_while_tests_expand_directories() {
        let temp = TempDir::new().expect("temporary directory");
        write_named_target_fixtures(temp.path());
        fs::write(
            temp.path().join("tests/fragment.ko"),
            "#[test] fn fragment() {}",
        )
        .expect("companion fragment is not a separate test root");
        let manifest = NAMED_TARGETS_MANIFEST;
        let lock = clean_verification_lock();
        let mut layout = PackageLayout::new(temp.path());
        layout.set_library("src");
        layout.add_contract("contracts/nested/a.ko");
        layout.add_contract("contracts/z.ko");
        layout.add_test("tests");
        let plan = plan_package(&layout, manifest, &lock).expect("package plan");
        for path in ["contracts/nested/a.ko", "contracts/z.ko"] {
            let source = packaged_contract_source_unit(
                &plan,
                &PortablePath::new(path).expect("contract source path"),
            )
            .expect("exact contract root");
            assert_eq!(source.source_name, path);
        }
        for invalid in ["contracts", "contracts/nested", "contracts/missing.ko"] {
            assert!(
                packaged_contract_source_unit(
                    &plan,
                    &PortablePath::new(invalid).expect("invalid target fixture")
                )
                .is_err()
            );
        }
        let tests =
            packaged_test_source_units(&plan, &PortablePath::new("tests").expect("test directory"))
                .expect("test roots");
        assert_eq!(
            tests
                .iter()
                .map(|source| source.source_name.as_str())
                .collect::<Vec<_>>(),
            ["tests/a.ko", "tests/nested/z.ko"]
        );
        fs::write(temp.path().join("Musubi.toml"), manifest).expect("workspace manifest");
        let workspace = load_workspace(temp.path()).expect("exact-target workspace");
        let member = workspace.members().values().next().expect("package member");
        let selected = vec![member.package.selector.clone()];
        let local = resolve_workspace_local(&workspace, &selected, None, ResolveModeV1::UpdateLock)
            .expect("local resolution")
            .expect("local graph")
            .lockfile;
        let built = execute_with_source(
            &EmptyRegistry,
            &workspace,
            &selected,
            &local,
            CompilerActionV1::Build,
            CompilerSettingsV1 {
                chain_discriminant: 1,
                zk_enabled: false,
                profile: "dev",
            },
        )
        .expect("build exact named targets");
        assert_eq!(built.contract_targets, 2);
        assert_eq!(
            built
                .artifacts
                .iter()
                .map(|artifact| artifact.target.as_str())
                .collect::<Vec<_>>(),
            ["a", "z"]
        );
        for artifact in &built.artifacts {
            assert_eq!(
                artifact.artifact.file_stem().and_then(|stem| stem.to_str()),
                Some(artifact.target.as_str())
            );
            assert!(artifact.artifact.is_file());
        }
        fs::create_dir_all(temp.path().join("contracts/directory.ko/nested"))
            .expect("directory with .ko suffix");
        fs::write(
            temp.path().join("contracts/directory.ko/nested/extra.ko"),
            "seiyaku Extra { hajimari() {} }",
        )
        .expect("nested source");
        let directory_target =
            PortablePath::new("contracts/directory.ko").expect("directory target");
        assert!(
            contract_source_unit(member, &directory_target)
                .expect_err("a .ko directory is not one contract")
                .to_string()
                .contains("one regular `.ko` source file")
        );
        let mut directory_layout = PackageLayout::new(temp.path());
        directory_layout.add_contract(directory_target.to_path_buf());
        assert!(plan_package(&directory_layout, manifest, &lock).is_err());
    }
    #[test]
    fn invalid_packaged_contract_is_not_reopened_from_a_repaired_workspace() {
        let temp = TempDir::new().expect("temporary directory");
        write_clean_library(temp.path());
        fs::create_dir_all(temp.path().join("contracts")).expect("contract directory");
        let contract = temp.path().join("contracts/deploy.ko");
        fs::write(&contract, "seiyaku Broken { fn").expect("invalid packaged contract");
        let manifest = r#"manifest-version = 1
[package]
namespace = "apps.sora"
name = "demo"
version = "1.0.0"
edition = "1"
abi-version = 1
[lib]
source-dir = "src"
exports = []
[[contract]]
name = "deploy"
path = "contracts/deploy.ko"
"#;
        let lock = clean_verification_lock();
        let mut layout = PackageLayout::new(temp.path());
        layout.set_library("src");
        layout.add_contract("contracts/deploy.ko");
        let plan = plan_package(&layout, manifest, &lock).expect("snapshot invalid contract");
        fs::write(&contract, "seiyaku Repaired { hajimari() {} }")
            .expect("repair ambient contract");
        assert!(matches!(
            validate_packaged_with_source(&EmptyRegistry, &plan, &lock, 1),
            Err(CompilerBridgeErrorV1::Diagnostics(bundle))
                if bundle.diagnostics.iter().all(|diagnostic| diagnostic
                    .notes
                    .iter()
                    .any(|note| note.contains("packaged contract target `deploy`")))
        ));
    }
    #[test]
    fn invalid_packaged_test_bytes_are_not_reopened_from_a_repaired_workspace() {
        let temp = TempDir::new().expect("temporary directory");
        write_clean_library(temp.path());
        fs::create_dir_all(temp.path().join("tests")).expect("test directory");
        let test = temp.path().join("tests/unit.ko");
        fs::write(&test, [0xff, 0xfe]).expect("invalid packaged test bytes");
        let manifest = r#"manifest-version = 1
[package]
namespace = "apps.sora"
name = "demo"
version = "1.0.0"
edition = "1"
abi-version = 1
[lib]
source-dir = "src"
exports = []
[[test]]
name = "unit"
path = "tests/unit.ko"
"#;
        let lock = clean_verification_lock();
        let mut layout = PackageLayout::new(temp.path());
        layout.set_library("src");
        layout.add_test("tests/unit.ko");
        let plan = plan_package(&layout, manifest, &lock).expect("snapshot invalid test");
        fs::write(
            &test,
            "seiyaku Repaired { #[test] fn repaired() { test::assert(true); } }",
        )
        .expect("repair ambient test");
        let error = validate_packaged_with_source(&EmptyRegistry, &plan, &lock, 1)
            .expect_err("the invalid captured bytes must remain authoritative");
        assert!(
            matches!(
                &error,
                CompilerBridgeErrorV1::Package(reason)
                    if reason.contains("packaged Kotodama source `tests/unit.ko` is not UTF-8")
            ),
            "{error}"
        );
    }
    #[test]
    fn clean_targets_ignore_ambient_mutation_and_do_not_change_library_interface() {
        let temp = TempDir::new().expect("temporary directory");
        write_clean_library(temp.path());
        for (path, source) in [
            ("contracts/deploy.ko", "seiyaku Deploy { hajimari() {} }"),
            (
                "tests/unit.ko",
                "seiyaku Tests { #[test] fn compile_only() { test::assert(false); } }",
            ),
            ("ambient/undeclared.ko", "this is not Kotodama"),
        ] {
            let path = temp.path().join(path);
            fs::create_dir_all(path.parent().expect("fixture parent")).expect("fixture directory");
            fs::write(path, source).expect("fixture source");
        }
        let manifest = r#"manifest-version = 1
[package]
namespace = "apps.sora"
name = "demo"
version = "1.0.0"
edition = "1"
abi-version = 1
[lib]
source-dir = "src"
exports = []
[[contract]]
name = "deploy"
path = "contracts/deploy.ko"
[[test]]
name = "unit"
path = "tests/unit.ko"
"#;
        let library_only_manifest = r#"manifest-version = 1
[package]
namespace = "apps.sora"
name = "demo"
version = "1.0.0"
edition = "1"
abi-version = 1
[lib]
source-dir = "src"
exports = []
"#;
        let lock = clean_verification_lock();
        let mut layout = PackageLayout::new(temp.path());
        layout.set_library("src");
        layout.add_contract("contracts/deploy.ko");
        layout.add_test("tests/unit.ko");
        let plan = plan_package(&layout, manifest, &lock).expect("package target snapshot");
        assert!(
            !plan
                .files()
                .iter()
                .any(|file| file.path() == "ambient/undeclared.ko")
        );
        fs::write(
            temp.path().join("contracts/deploy.ko"),
            "invalid ambient contract",
        )
        .expect("mutate ambient contract");
        fs::write(temp.path().join("tests/unit.ko"), "invalid ambient test")
            .expect("mutate ambient test");
        let with_targets = validate_packaged_with_source(&EmptyRegistry, &plan, &lock, 1)
            .expect("validate immutable target snapshot");
        let mut library_layout = PackageLayout::new(temp.path());
        library_layout.set_library("src");
        let library_plan = plan_package(&library_layout, library_only_manifest, &lock)
            .expect("library-only package plan");
        let library_only = validate_packaged_with_source(&EmptyRegistry, &library_plan, &lock, 1)
            .expect("validate library-only package");
        assert_eq!(with_targets, library_only);
    }
    #[test]
    fn packaged_standalone_tests_use_only_declared_immutable_contract_sources() {
        let temp = TempDir::new().expect("temporary directory");
        write_clean_library(temp.path());
        fs::create_dir_all(temp.path().join("contracts")).expect("contract directory");
        fs::create_dir_all(temp.path().join("tests")).expect("test directory");
        fs::write(
            temp.path().join("contracts/app.ko"),
            "seiyaku App { fn reward() -> int { return 7; } }",
        )
        .expect("contract");
        fs::write(temp.path().join("tests/unit.ko"), r#"module Tests { koto_test { target: "../contracts/app.ko" } #[test] fn correct() { test::assert(reward() == 7); } }"#).expect("standalone tests");
        let manifest = r#"manifest-version = 1
[package]
namespace = "apps.sora"
name = "demo"
version = "1.0.0"
edition = "1"
abi-version = 1
[lib]
source-dir = "src"
exports = []
[[contract]]
name = "app"
path = "contracts/app.ko"
[[test]]
name = "unit"
path = "tests/unit.ko"
"#;
        let lock = clean_verification_lock();
        let mut layout = PackageLayout::new(temp.path());
        layout.set_library("src");
        layout.add_contract("contracts/app.ko");
        layout.add_test("tests/unit.ko");
        let plan = plan_package(&layout, manifest, &lock).expect("immutable package plan");
        fs::write(
            temp.path().join("contracts/app.ko"),
            "invalid replacement contract",
        )
        .expect("mutate ambient target");
        fs::write(
            temp.path().join("tests/unit.ko"),
            "invalid replacement test",
        )
        .expect("mutate ambient test");
        validate_packaged_with_source(&EmptyRegistry, &plan, &lock, 753)
            .expect("validate exact captured standalone sources");
        let parsed = parse_manifest(manifest).expect("manifest");
        assert!(
            matches!(validate_packaged_test_targets(&plan, &parsed.tests, &[], &[], &[], 753), Err(CompilerBridgeErrorV1::Package(reason)) if reason.contains("not a packaged manifest-declared contract"))
        );
    }
    #[test]
    fn packaged_test_missing_a_normal_dependency_has_a_dev_boundary_diagnostic() {
        let temp = TempDir::new().expect("temporary directory");
        write_clean_library(temp.path());
        fs::create_dir_all(temp.path().join("tests")).expect("test directory");
        fs::write(
            temp.path().join("tests/unit.ko"),
            "seiyaku Tests { #[test] fn needs_dev() { test::assert(helper::truth()); } }",
        )
        .expect("test source");
        let manifest = r#"manifest-version = 1
[package]
namespace = "apps.sora"
name = "demo"
version = "1.0.0"
edition = "1"
abi-version = 1
[lib]
source-dir = "src"
exports = []
[[test]]
name = "unit"
path = "tests/unit.ko"
"#;
        let lock = clean_verification_lock();
        let mut layout = PackageLayout::new(temp.path());
        layout.set_library("src");
        layout.add_test("tests/unit.ko");
        let plan = plan_package(&layout, manifest, &lock).expect("package plan");
        assert!(matches!(
            validate_packaged_with_source(&EmptyRegistry, &plan, &lock, 1),
            Err(CompilerBridgeErrorV1::Diagnostics(bundle))
                if bundle.diagnostics.iter().all(|diagnostic| diagnostic
                    .notes
                    .iter()
                    .any(|note| note.contains("development dependencies do not propagate")))
        ));
    }
    #[test]
    fn build_outputs_are_partitioned_by_public_package_identity() {
        let temp = TempDir::new().expect("temporary directory");
        fs::create_dir_all(temp.path().join("src")).expect("source directory");
        fs::write(
            temp.path().join("Musubi.toml"),
            r#"manifest-version = 1
[package]
namespace = "apps.sora"
name = "demo"
version = "1.0.0"
edition = "1"
abi-version = 1
[lib]
source-dir = "src"
exports = []
"#,
        )
        .expect("manifest");
        fs::write(temp.path().join("src/lib.ko"), "module Demo {}").expect("source");
        let workspace = load_workspace(temp.path()).expect("workspace");
        let member = workspace.members().values().next().expect("member");
        assert_eq!(
            package_target_root(&workspace, member),
            workspace.root().join("target/kotodama/apps.sora/demo")
        );
    }
    #[test]
    fn clean_packaged_tree_produces_a_typed_interface_digest() {
        let temp = TempDir::new().expect("temporary directory");
        fs::create_dir_all(temp.path().join("src")).expect("source directory");
        fs::write(
            temp.path().join("src/lib.ko"),
            "module Demo { export fn value() -> int { return 1; } }",
        )
        .expect("source");
        let package = MusubiPackageIdV1::new(
            DataSpaceId::new(9),
            MusubiPackageScopeV1::DataspaceRoot,
            "demo".parse().expect("package name"),
        );
        let lock = MusubiVerificationLockV1 {
            schema: MusubiVerificationLockV1::SCHEMA.to_owned(),
            version: MUSUBI_REGISTRY_VERSION_V1,
            root: MusubiReleaseIdV1::new(package, "1.0.0".parse().expect("version")),
            root_dependencies: Vec::new(),
            nodes: Vec::new(),
        };
        let manifest = r#"manifest-version = 1
[package]
namespace = "apps.sora"
name = "demo"
version = "1.0.0"
edition = "1"
abi-version = 1
[lib]
source-dir = "src"
exports = ["value"]
"#;
        let mut layout = PackageLayout::new(temp.path());
        layout.set_library("src");
        let plan = plan_package(&layout, manifest, &lock).expect("package plan");
        let digest = validate_packaged_with_source(&EmptyRegistry, &plan, &lock, 1)
            .expect("clean package validation");
        assert!(!digest.is_zero());
    }

    #[test]
    fn contract_only_publication_validates_real_sources_and_has_no_library_interface() {
        let temp = TempDir::new().expect("contract package");
        let manifest = include_str!("../../../examples/coffee-club/Musubi.toml")
            .replace("namespace = \"demo\"", "namespace = \"apps.sora\"")
            .replace("name = \"coffee-club\"", "name = \"demo\"")
            .replace("version = \"0.1.0\"", "version = \"1.0.0\"");
        fs::create_dir(temp.path().join("contracts")).expect("contract directory");
        fs::create_dir(temp.path().join("tests")).expect("test directory");
        fs::write(temp.path().join("Musubi.toml"), &manifest).expect("manifest");
        fs::write(
            temp.path().join("contracts/coffee-club.ko"),
            include_str!("../../../examples/coffee-club/contracts/coffee-club.ko"),
        )
        .expect("contract");
        fs::write(
            temp.path().join("tests/coffee-club.test.ko"),
            include_str!("../../../examples/coffee-club/tests/coffee-club.test.ko"),
        )
        .expect("public tests");
        let lock = clean_verification_lock();
        let mut layout = PackageLayout::new(temp.path());
        layout.add_contract("contracts/coffee-club.ko");
        layout.add_test("tests/coffee-club.test.ko");
        let plan = plan_package(&layout, &manifest, &lock).expect("contract-only package plan");
        let interface = validate_packaged_with_source(&EmptyRegistry, &plan, &lock, 369)
            .expect("clean public contract validation");
        assert_eq!(interface, contract_only_interface_digest());
        assert!(!interface.is_zero());
        fs::write(
            temp.path().join("contracts/coffee-club.ko"),
            "invalid ambient source",
        )
        .expect("replace ambient source");
        assert_eq!(
            validate_packaged_with_source(&EmptyRegistry, &plan, &lock, 369)
                .expect("immutable source plan"),
            interface
        );
        let invalid = plan_package(&layout, &manifest, &lock).expect("capture changed source");
        assert!(validate_packaged_with_source(&EmptyRegistry, &invalid, &lock, 369).is_err());
    }
}
