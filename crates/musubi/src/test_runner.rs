//! Authenticated workspace boundary for structured Kotodama V1 tests.
//!
//! Selected workspace roots own their test targets and development edges. The consumer lock remains
//! authoritative for exact registry selections, while every reachable registry bundle is
//! re-authenticated before it can become a compiler input. Native retained directory and file
//! authority protects source reads on Unix and Windows. Each source has a stable read snapshot;
//! this does not claim an atomic snapshot of a concurrently edited whole workspace.
use crate::{
    cache::{CachedCompilerPackageV1, MusubiCache},
    compiler::{
        locate_workspace_diagnostic, member_directory, validate_exact_registry_interfaces_v1,
    },
    compiler_identity::{local_package, registry_release},
    graph::{collect_local_members, resolve_workspace_local},
    lockfile::{LockContextV1, LockedRootV1, LockfileV1},
    manifest::{ConcreteDependency, DependencySpec, PortablePath, parse_manifest},
    package::{is_excluded_directory, is_sensitive_component},
    resolver::ResolveModeV1,
    workspace::{DependencyKind, EffectiveDependency, Workspace, WorkspaceMember},
};
#[cfg(all(test, any(unix, windows)))]
use iroha_data_model::musubi::MusubiExactDependencyEdgeV1;
use iroha_data_model::musubi::{
    MUSUBI_MAX_FILES_V1, MUSUBI_MAX_SOURCE_PAYLOAD_BYTES_V1, MusubiDependencyKindV1,
    MusubiPackageSelectorV1, MusubiReleaseIdV1, MusubiVerificationNodeV1, MusubiVersionReqV1,
};
use iroha_fs::{OwnerDirectory, RetainedFile};
use ivm::{SyscallPolicy, syscalls::compute_abi_hash};
use kotodama_lang::{
    compiler::{CompilerMode, CompilerOptions},
    diagnostic::DiagnosticBundle,
    driver::discover_source_modules,
    linker::{ImportBinding, MAX_MODULE_GRAPH_SOURCE_BYTES, SourceModuleUnit, SourcePackageUnit},
};
use kotodama_toolchain::koto_test_driver::{
    KotoTestModuleGraphV1, KotoTestRunErrorV1, KotoTestRunPhaseV1, KotoTestRunReportV1,
    KotoTestRunRequestV1, declared_test_target_source_v1,
    run_tests_structured_source_set_with_modules_v1,
};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt, fs,
    io::{self, Read as _},
    path::{Path, PathBuf},
};
/// Runtime controls for one authenticated Musubi workspace test invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceTestOptionsV1 {
    /// Optional test-name substring or exact name.
    pub filter: Option<String>,
    /// Require `filter` to match the complete test name.
    pub exact: bool,
    /// Optional manifest-declared contract target; tests of other contracts are excluded.
    pub contract: Option<String>,
    /// Maximum number of isolated VM test workers per target.
    pub jobs: usize,
    /// Deterministic per-target test ordering seed.
    pub seed: u64,
    /// Account-address chain discriminant used by compiler and VM execution.
    pub chain_discriminant: u16,
    /// Enable the Kotodama ZK compilation surface.
    pub zk_enabled: bool,
}
impl WorkspaceTestOptionsV1 {
    /// Construct canonical single-worker test controls for one chain.
    #[must_use]
    pub(crate) const fn new(chain_discriminant: u16) -> Self {
        Self {
            filter: None,
            exact: false,
            contract: None,
            jobs: 1,
            seed: 0,
            chain_discriminant,
            zk_enabled: false,
        }
    }
}
/// Structured report for one manifest-declared test target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceTestTargetReportV1 {
    /// Selected workspace package that owns this target.
    pub package: MusubiPackageSelectorV1,
    /// Parent-local manifest target name.
    pub target: String,
    /// Portable source path declared by the manifest.
    pub source: String,
    /// Non-printing IVM report for the discovered suite.
    pub report: KotoTestRunReportV1,
}
/// Complete deterministic report for all selected workspace test roots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceTestReportV1 {
    /// Target reports ordered by package, target name, and portable source path.
    pub targets: Vec<WorkspaceTestTargetReportV1>,
}
impl WorkspaceTestReportV1 {
    /// Return the total number of successful test cases.
    #[must_use]
    pub(crate) fn passed(&self) -> usize {
        self.targets
            .iter()
            .map(|target| target.report.passed())
            .sum()
    }
    /// Return the total number of failed test cases.
    #[must_use]
    pub(crate) fn failed(&self) -> usize {
        self.targets
            .iter()
            .map(|target| target.report.failed())
            .sum()
    }
    /// Return whether every selected test passed.
    #[must_use]
    pub(crate) fn is_success(&self) -> bool {
        self.failed() == 0
    }
}
/// Stable authenticated workspace test failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkspaceTestErrorV1 {
    /// Secure filesystem-backed test execution is unsupported on this platform.
    UnsupportedPlatform,
    /// Selection or local workspace state was inconsistent.
    Workspace(String),
    /// The exact consumer lock did not match the selected roots.
    Lock(String),
    /// An exact registry node failed immutable-cache re-authentication.
    Cache(String),
    /// The canonical IVM linker rejected the authenticated exact dependency graph.
    ExternalModules(String),
    /// A declared test target was not a safe regular Kotodama source file.
    Target(String),
    /// The structured runner rejected the request or found no matching tests.
    Runner(String),
    /// Kotodama rejected the test sources with canonical structured diagnostics.
    Compilation(DiagnosticBundle),
    /// Test fixtures or VM preparation failed while executing compiled tests.
    Execution(String),
}
impl WorkspaceTestErrorV1 {
    /// Classify a structured runner failure by its stable phase.
    fn from_runner(error: KotoTestRunErrorV1) -> Self {
        if let Some(diagnostics) = error.diagnostics {
            return Self::Compilation(diagnostics);
        }
        match error.phase {
            KotoTestRunPhaseV1::Execution => Self::Execution(error.message),
            KotoTestRunPhaseV1::Compilation
            | KotoTestRunPhaseV1::Request
            | KotoTestRunPhaseV1::Discovery => Self::Runner(error.message),
        }
    }
    fn located(
        mut self,
        member: &WorkspaceMember,
        local_directories: &BTreeMap<String, String>,
    ) -> Self {
        if let Self::Compilation(bundle) = &mut self {
            for diagnostic in &mut bundle.diagnostics {
                locate_workspace_diagnostic(
                    diagnostic,
                    member_directory(member),
                    local_directories,
                );
            }
        }
        self
    }
}
impl fmt::Display for WorkspaceTestErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => formatter.write_str(
                "secure Musubi workspace-test execution requires native Unix or Windows filesystem custody",
            ),
            Self::Workspace(reason) => write!(formatter, "invalid test workspace: {reason}"),
            Self::Lock(reason) => write!(formatter, "invalid exact test lock: {reason}"),
            Self::Cache(reason) => write!(formatter, "authenticated test cache error: {reason}"),
            Self::ExternalModules(reason) => {
                write!(formatter, "invalid authenticated test graph: {reason}")
            }
            Self::Target(reason) => write!(formatter, "invalid test target: {reason}"),
            Self::Runner(reason) => write!(formatter, "Kotodama test runner failed: {reason}"),
            Self::Compilation(diagnostics) => {
                write!(formatter, "Kotodama rejected the selected test sources\n{}", diagnostics.render_human())
            }
            Self::Execution(reason) => {
                write!(formatter, "Kotodama test execution failed: {reason}")
            }
        }
    }
}
impl Error for WorkspaceTestErrorV1 {}
trait AuthenticatedTestRegistryV1 {
    fn load(
        &self,
        node: &MusubiVerificationNodeV1,
    ) -> Result<SourcePackageUnit, WorkspaceTestErrorV1>;
}
impl AuthenticatedTestRegistryV1 for MusubiCache {
    fn load(
        &self,
        node: &MusubiVerificationNodeV1,
    ) -> Result<SourcePackageUnit, WorkspaceTestErrorV1> {
        self.load_compiler_package(node)
            .map_err(|error| WorkspaceTestErrorV1::Cache(error.to_string()))
            .and_then(|cached| cached_source_package(node, cached))
    }
}
impl AuthenticatedTestRegistryV1 for Option<&MusubiCache> {
    fn load(
        &self,
        node: &MusubiVerificationNodeV1,
    ) -> Result<SourcePackageUnit, WorkspaceTestErrorV1> {
        self.ok_or_else(|| {
            WorkspaceTestErrorV1::Cache(
                "registry test inputs require an authenticated cache".to_owned(),
            )
        })?
        .load(node)
    }
}
/// Run tests for exactly `selected` workspace roots after authenticating their lock graph.
///
/// Development dependencies are considered only on explicitly selected roots; registry nodes are
/// already forbidden from carrying development edges by the lock schema. This function never
/// discovers or runs tests owned by dependency packages.
///
/// # Errors
///
/// Returns [`WorkspaceTestErrorV1::UnsupportedPlatform`] outside native Unix and Windows before
/// consulting the cache, workspace, lock, options, or declared test sources. On supported hosts,
/// returns a categorized authentication, graph, compilation, or execution failure.
pub fn execute_workspace_tests_v1(
    cache: Option<&MusubiCache>,
    workspace: &Workspace,
    selected: &[MusubiPackageSelectorV1],
    lock: &LockfileV1,
    options: &WorkspaceTestOptionsV1,
) -> Result<WorkspaceTestReportV1, WorkspaceTestErrorV1> {
    ensure_test_runner_platform_supported_v1()?;
    execute_workspace_tests_with_source(&cache, workspace, selected, lock, options)
}
fn ensure_test_runner_platform_supported_v1() -> Result<(), WorkspaceTestErrorV1> {
    if cfg!(any(unix, windows)) {
        Ok(())
    } else {
        Err(WorkspaceTestErrorV1::UnsupportedPlatform)
    }
}
fn execute_workspace_tests_with_source<S: AuthenticatedTestRegistryV1>(
    source: &S,
    workspace: &Workspace,
    selected: &[MusubiPackageSelectorV1],
    lock: &LockfileV1,
    options: &WorkspaceTestOptionsV1,
) -> Result<WorkspaceTestReportV1, WorkspaceTestErrorV1> {
    validate_options(options)?;
    lock.validate()
        .map_err(|error| WorkspaceTestErrorV1::Lock(error.to_string()))?;
    let selected = canonical_selected(selected)?;
    if matches!(lock.context, LockContextV1::Local { .. }) {
        let resolved = resolve_workspace_local(
            workspace,
            &selected,
            Some(lock.clone()),
            ResolveModeV1::Locked,
        )
        .map_err(|error| WorkspaceTestErrorV1::Lock(error.to_string()))?;
        if resolved.is_none() {
            return Err(WorkspaceTestErrorV1::Lock(
                "local test graph now requires registry dependencies".to_owned(),
            ));
        }
    }
    let members = workspace
        .select_members(false, &selected, &[])
        .map_err(|error| WorkspaceTestErrorV1::Workspace(error.to_string()))?;
    let selected_set = selected.iter().cloned().collect::<BTreeSet<_>>();
    let local_members = collect_local_members(workspace, &selected)
        .map_err(|error| WorkspaceTestErrorV1::Workspace(error.to_string()))?;
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
        return Err(WorkspaceTestErrorV1::Workspace(
            "two local test packages share one manifest path".to_owned(),
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
    let roots = members
        .iter()
        .map(|member| selected_lock_root(lock, member, true))
        .collect::<Result<Vec<_>, _>>()?;
    let graph_roots = local_members
        .iter()
        .map(|member| {
            selected_lock_root(
                lock,
                member,
                selected_set.contains(&member.package.selector),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let expected_abi_hash = compute_abi_hash(SyscallPolicy::AbiV1);
    let registry_nodes = selected_registry_nodes(lock, &graph_roots)?;
    let mut registry_packages = Vec::with_capacity(registry_nodes.len());
    for node in &registry_nodes {
        if node.abi.abi_version != 1 || node.abi.abi_hash != expected_abi_hash {
            return Err(WorkspaceTestErrorV1::Lock(format!(
                "release `{}` does not bind the canonical IVM ABI V1 hash",
                node.release
            )));
        }
        let package = source.load(node)?;
        if package.identity != registry_release(&node.release) {
            return Err(WorkspaceTestErrorV1::Cache(format!(
                "release `{}` loaded under package identity `{}`",
                node.release, package.identity
            )));
        }
        registry_packages.push(package);
    }
    validate_registry_interfaces(&registry_nodes, &registry_packages, options)?;
    let mut packages = registry_packages;
    for member in &local_members {
        if let Some(package) = local_source_package(
            member,
            lock,
            selected_set.contains(&member.package.selector),
            &local_identities,
        )? {
            packages.push(package);
        }
    }
    packages.sort_by(|left, right| left.identity.cmp(&right.identity));
    if packages
        .windows(2)
        .any(|pair| pair[0].identity == pair[1].identity)
    {
        return Err(WorkspaceTestErrorV1::ExternalModules(
            "the exact test graph contains duplicate package identities".to_owned(),
        ));
    }
    if let Some(name) = &options.contract {
        let count = members
            .iter()
            .flat_map(|member| {
                member
                    .manifest
                    .contracts
                    .iter()
                    .map(move |target| (member, target))
            })
            .filter(|(member, target)| {
                target.name.as_ref() == name
                    || format!("{}::{}", member.package.selector, target.name) == *name
            })
            .count();
        if count != 1 {
            return Err(WorkspaceTestErrorV1::Target(format!(
                "contract selector `{name}` must identify exactly one selected manifest target; found {count}"
            )));
        }
    }
    let mut targets = Vec::new();
    let mut matched_filter = options.filter.is_none();
    for (member, root) in members.into_iter().zip(roots) {
        let locate = |error: WorkspaceTestErrorV1| error.located(member, &local_directories);
        let module_graph = KotoTestModuleGraphV1 {
            artifacts: Vec::new(),
            sources: Vec::new(),
            imports: test_root_imports(member, root, &local_identities)?,
            packages: packages.clone(),
        };
        let mut contract_sources = BTreeMap::new();
        let mut source_budget = DeclaredTestSourceBudgetV1::default();
        for target in &member.manifest.tests {
            for source in declared_test_sources(member, &target.path.to_path_buf())? {
                consume_test_entry_budget(&mut source_budget)?;
                source_budget.source_bytes = source_budget
                    .source_bytes
                    .saturating_add(source.unit.source.len() as u64);
                if source_budget.source_bytes > MUSUBI_MAX_SOURCE_PAYLOAD_BYTES_V1 {
                    return Err(WorkspaceTestErrorV1::Target(
                        "selected test source set exceeds the source-byte budget".to_owned(),
                    ));
                }
                let contract = declared_contract_for_test_source(
                    member,
                    &source.unit,
                    &mut contract_sources,
                    &mut source_budget,
                )
                .map_err(locate)?;
                if let Some(name) = &options.contract {
                    let target = member.manifest.contracts.iter().find(|target| {
                        target.name.as_ref() == name
                            || format!("{}::{}", member.package.selector, target.name) == *name
                    });
                    let Some(target) = target else {
                        continue;
                    };
                    let actual = contract
                        .as_ref()
                        .map_or(source.unit.source_name.as_str(), |contract| {
                            contract.source_name.as_str()
                        });
                    if actual != target.path.as_str() {
                        continue;
                    }
                }
                let mut module_graph = module_graph.clone();
                let mut entries = vec![source.unit.clone()];
                if let Some(contract) = &contract {
                    entries.push(contract.clone());
                }
                let inventory = kotodama_lang::driver::load_source_inventory(
                    &entries,
                    &member.package_root,
                    &BTreeMap::new(),
                )
                .map_err(|error| match error.into_diagnostics() {
                    Ok(diagnostics) => WorkspaceTestErrorV1::Compilation(diagnostics),
                    Err(other) => WorkspaceTestErrorV1::Runner(other.to_string()),
                })
                .map_err(locate)?;
                module_graph.sources = inventory.sources;
                module_graph.artifacts = inventory.artifacts;
                if let Some(filter) = options.filter.as_deref() {
                    let names =
                        kotodama_toolchain::koto_test_driver::discover_declared_test_names_source_set_with_sources_v1(&source.unit, contract.as_ref(), &module_graph.sources)
                            .map_err(WorkspaceTestErrorV1::Runner)?;
                    let matches = names.iter().any(|name| {
                        if options.exact {
                            name == filter
                        } else {
                            name.contains(filter)
                        }
                    });
                    if !matches {
                        continue;
                    }
                    matched_filter = true;
                }
                let mut request =
                    KotoTestRunRequestV1::new(&source.logical_path, options.chain_discriminant);
                request.filter.clone_from(&options.filter);
                request.exact = options.exact;
                request.jobs = options.jobs;
                request.seed = options.seed;
                request.zk_enabled = options.zk_enabled;
                let report = run_tests_structured_source_set_with_modules_v1(
                    &request,
                    &source.unit,
                    contract.as_ref(),
                    &module_graph,
                )
                .map_err(WorkspaceTestErrorV1::from_runner)
                .map_err(locate)?;
                targets.push(WorkspaceTestTargetReportV1 {
                    package: member.package.selector.clone(),
                    target: target.name.to_string(),
                    source: source.logical_path,
                    report,
                });
            }
        }
    }
    if !matched_filter {
        return Err(WorkspaceTestErrorV1::Runner(
            "no Kotodama tests matched the requested filter".to_owned(),
        ));
    }
    targets.sort_by(|left, right| {
        left.package
            .cmp(&right.package)
            .then_with(|| left.target.cmp(&right.target))
            .then_with(|| left.source.cmp(&right.source))
    });
    Ok(WorkspaceTestReportV1 { targets })
}
fn validate_options(options: &WorkspaceTestOptionsV1) -> Result<(), WorkspaceTestErrorV1> {
    if options.jobs == 0 {
        return Err(WorkspaceTestErrorV1::Workspace(
            "test worker count must be greater than zero".to_owned(),
        ));
    }
    if options.chain_discriminant == 0 {
        return Err(WorkspaceTestErrorV1::Workspace(
            "test chain discriminant must be in 1..=65535".to_owned(),
        ));
    }
    if options.exact && options.filter.is_none() {
        return Err(WorkspaceTestErrorV1::Workspace(
            "exact test selection requires a filter".to_owned(),
        ));
    }
    Ok(())
}
fn canonical_selected(
    selected: &[MusubiPackageSelectorV1],
) -> Result<Vec<MusubiPackageSelectorV1>, WorkspaceTestErrorV1> {
    if selected.is_empty() {
        return Err(WorkspaceTestErrorV1::Workspace(
            "at least one workspace package must be selected".to_owned(),
        ));
    }
    let mut selected = selected.to_vec();
    selected.sort();
    if selected.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(WorkspaceTestErrorV1::Workspace(
            "selected workspace packages must be unique".to_owned(),
        ));
    }
    Ok(selected)
}
fn selected_lock_root<'a>(
    lock: &'a LockfileV1,
    member: &WorkspaceMember,
    include_dev: bool,
) -> Result<&'a LockedRootV1, WorkspaceTestErrorV1> {
    let root = lock
        .roots
        .binary_search_by(|root| root.package.cmp(&member.package.selector))
        .ok()
        .and_then(|index| lock.roots.get(index))
        .ok_or_else(|| {
            WorkspaceTestErrorV1::Lock(format!(
                "selected package `{}` has no exact lock root",
                member.package.selector
            ))
        })?;
    validate_declared_edges(member, root, include_dev)?;
    Ok(root)
}
fn validate_declared_edges(
    member: &WorkspaceMember,
    root: &LockedRootV1,
    include_dev: bool,
) -> Result<(), WorkspaceTestErrorV1> {
    let mut expected = BTreeMap::new();
    for dependency in member
        .dependencies
        .values()
        .chain(member.dev_dependencies.values().filter(|_| include_dev))
    {
        if dependency.local_manifest.is_some() {
            continue;
        }
        let Some((package, requirement)) = registry_requirement(dependency)? else {
            continue;
        };
        let key = (dependency.alias.to_string(), dependency.kind);
        expected.insert(key, (package.clone(), requirement.clone()));
    }
    if expected.len() != root.dependencies.len() {
        return Err(WorkspaceTestErrorV1::Lock(format!(
            "selected package `{}` dependency declarations disagree with its exact root",
            member.package.selector
        )));
    }
    for edge in &root.dependencies {
        let key = (
            edge.alias.to_string(),
            match edge.kind {
                MusubiDependencyKindV1::Normal => crate::workspace::DependencyKind::Normal,
                MusubiDependencyKindV1::Development => {
                    crate::workspace::DependencyKind::Development
                }
            },
        );
        let Some((package, requirement)) = expected.get(&key) else {
            return Err(WorkspaceTestErrorV1::Lock(format!(
                "selected package `{}` has an unexpected exact edge `{}`",
                member.package.selector, edge.alias
            )));
        };
        if edge.package.name != package.name || edge.requirement != *requirement {
            return Err(WorkspaceTestErrorV1::Lock(format!(
                "selected package `{}` exact edge `{}` disagrees with its manifest",
                member.package.selector, edge.alias
            )));
        }
    }
    Ok(())
}
fn registry_requirement(
    dependency: &EffectiveDependency,
) -> Result<Option<(&MusubiPackageSelectorV1, &MusubiVersionReqV1)>, WorkspaceTestErrorV1> {
    match &dependency.dependency {
        ConcreteDependency::Registry {
            package,
            requirement,
        }
        | ConcreteDependency::Path {
            package: Some(package),
            requirement: Some(requirement),
            ..
        } => Ok(Some((package, requirement))),
        ConcreteDependency::Path {
            package: None,
            requirement: None,
            ..
        } => Ok(None),
        ConcreteDependency::Path { .. } => Err(WorkspaceTestErrorV1::Workspace(format!(
            "dependency `{}` has only one registry identity field",
            dependency.alias
        ))),
    }
}
fn test_root_imports(
    member: &WorkspaceMember,
    root: &LockedRootV1,
    local_identities: &BTreeMap<PathBuf, String>,
) -> Result<Vec<ImportBinding>, WorkspaceTestErrorV1> {
    let mut imports = member
        .dependencies
        .values()
        .chain(member.dev_dependencies.values())
        .map(|dependency| {
            Ok(ImportBinding {
                alias: dependency.alias.to_string(),
                package: dependency_import_identity(root, dependency, local_identities)?,
            })
        })
        .collect::<Result<Vec<_>, WorkspaceTestErrorV1>>()?;
    imports.sort_by(|left, right| {
        left.alias
            .cmp(&right.alias)
            .then_with(|| left.package.cmp(&right.package))
    });
    if imports
        .windows(2)
        .any(|pair| pair[0].alias == pair[1].alias)
    {
        return Err(WorkspaceTestErrorV1::Workspace(format!(
            "selected package `{}` repeats a normal/development import alias",
            member.package.selector
        )));
    }
    Ok(imports)
}
fn dependency_import_identity(
    root: &LockedRootV1,
    dependency: &EffectiveDependency,
    local_identities: &BTreeMap<PathBuf, String>,
) -> Result<String, WorkspaceTestErrorV1> {
    if let Some(manifest_path) = &dependency.local_manifest {
        return local_identities.get(manifest_path).cloned().ok_or_else(|| {
            WorkspaceTestErrorV1::Workspace(format!(
                "local dependency `{}` is absent from the selected test graph",
                dependency.alias
            ))
        });
    }
    let kind = match dependency.kind {
        DependencyKind::Normal => MusubiDependencyKindV1::Normal,
        DependencyKind::Development => MusubiDependencyKindV1::Development,
    };
    let edge = root
        .dependencies
        .iter()
        .find(|edge| edge.alias == dependency.alias && edge.kind == kind)
        .ok_or_else(|| {
            WorkspaceTestErrorV1::Lock(format!(
                "dependency `{}` has no exact selected edge",
                dependency.alias
            ))
        })?;
    let Some((package, requirement)) = registry_requirement(dependency)? else {
        return Err(WorkspaceTestErrorV1::Workspace(format!(
            "path dependency `{}` lost its authenticated local manifest",
            dependency.alias
        )));
    };
    if edge.package.name != package.name || edge.requirement != *requirement {
        return Err(WorkspaceTestErrorV1::Lock(format!(
            "dependency `{}` disagrees with its exact selected edge",
            dependency.alias
        )));
    }
    Ok(registry_release(&edge.selected))
}
fn local_source_package(
    member: &WorkspaceMember,
    lock: &LockfileV1,
    include_dev_in_lock: bool,
    local_identities: &BTreeMap<PathBuf, String>,
) -> Result<Option<SourcePackageUnit>, WorkspaceTestErrorV1> {
    let Some(library) = member.manifest.library.as_ref() else {
        return Ok(None);
    };
    let mut units =
        discover_source_modules(&member.package_root.join(library.source_dir.to_path_buf()))
            .map_err(|error| WorkspaceTestErrorV1::ExternalModules(error.to_string()))?;
    for source in &mut units {
        if library.source_dir.as_str() != "." {
            source.source_name = format!("{}/{}", library.source_dir.as_str(), source.source_name);
        }
    }
    let (modules, mut sources) = crate::compiler::partition_library_sources(units)
        .map_err(|error| WorkspaceTestErrorV1::ExternalModules(error.to_string()))?;
    let inventory = kotodama_lang::driver::load_source_inventory(
        &modules,
        &member.package_root,
        &BTreeMap::new(),
    )
    .map_err(|error| WorkspaceTestErrorV1::ExternalModules(error.to_string()))?;
    for source in inventory.sources {
        if !sources
            .iter()
            .any(|known| known.source_name == source.source_name)
        {
            sources.push(source);
        }
    }
    if modules.is_empty() {
        return Err(WorkspaceTestErrorV1::ExternalModules(format!(
            "local package `{}` has no declared Kotodama library sources",
            member.package.selector
        )));
    }
    let root = selected_lock_root(lock, member, include_dev_in_lock)?;
    let mut imports = member
        .dependencies
        .values()
        .map(|dependency| {
            Ok(ImportBinding {
                alias: dependency.alias.to_string(),
                package: dependency_import_identity(root, dependency, local_identities)?,
            })
        })
        .collect::<Result<Vec<_>, WorkspaceTestErrorV1>>()?;
    imports.sort_by(|left, right| {
        left.alias
            .cmp(&right.alias)
            .then_with(|| left.package.cmp(&right.package))
    });
    Ok(Some(SourcePackageUnit {
        artifacts: inventory.artifacts,
        sources,
        identity: local_package(&member.package.selector, &member.package.version),
        modules,
        exports: library.exports.iter().map(ToString::to_string).collect(),
        imports,
    }))
}
fn validate_registry_interfaces(
    nodes: &[&MusubiVerificationNodeV1],
    packages: &[SourcePackageUnit],
    options: &WorkspaceTestOptionsV1,
) -> Result<(), WorkspaceTestErrorV1> {
    validate_exact_registry_interfaces_v1(
        nodes.iter().copied(),
        packages,
        CompilerOptions {
            force_zk: options.zk_enabled,
            chain_discriminant: options.chain_discriminant,
            mode: CompilerMode::Production,
            ..CompilerOptions::default()
        },
    )
    .map_err(WorkspaceTestErrorV1::Cache)
}
fn cached_source_package(
    node: &MusubiVerificationNodeV1,
    cached: CachedCompilerPackageV1,
) -> Result<SourcePackageUnit, WorkspaceTestErrorV1> {
    let manifest = parse_manifest(&cached.manifest)
        .map_err(|error| WorkspaceTestErrorV1::Cache(error.to_string()))?;
    if manifest.workspace.is_some() || !manifest.dev_dependencies.is_empty() {
        return Err(WorkspaceTestErrorV1::Cache(format!(
            "cached release `{}` contains workspace or development state",
            node.release
        )));
    }
    validate_cached_manifest_edges(node, &manifest.dependencies)?;
    let package = manifest
        .resolve_package(None)
        .map_err(|error| WorkspaceTestErrorV1::Cache(error.to_string()))?;
    if package.selector.name != node.release.package.name
        || package.version != node.release.version
        || package.edition != cached.semantic_release.edition
        || package.abi_version != node.abi.abi_version
    {
        return Err(WorkspaceTestErrorV1::Cache(format!(
            "cached manifest identity for `{}` is inconsistent",
            node.release
        )));
    }
    let Some(library) = manifest.library.as_ref() else {
        if !cached.semantic_release.exports.is_empty()
            || node.interface_digest != crate::compiler::contract_only_interface_digest()
        {
            return Err(WorkspaceTestErrorV1::Cache(format!(
                "contract-only release `{}` has an inconsistent absent-library interface commitment",
                node.release
            )));
        }
        return Err(WorkspaceTestErrorV1::Cache(format!(
            "dependency `{}` is a contract-only release and cannot be imported as a library",
            node.release
        )));
    };
    let exports = library
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
    if exports != semantic_exports {
        return Err(WorkspaceTestErrorV1::Cache(format!(
            "cached release `{}` export table is inconsistent",
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
    let (modules, _) = crate::compiler::partition_library_sources(
        inventory
            .iter()
            .filter(|source| {
                relative_library_source(&source.source_name, &library.source_dir).is_some()
            })
            .cloned()
            .collect(),
    )
    .map_err(|error| WorkspaceTestErrorV1::Cache(error.to_string()))?;
    let sources = inventory
        .into_iter()
        .filter(|source| {
            !modules
                .iter()
                .any(|module| module.source_name == source.source_name)
        })
        .collect();
    if modules.is_empty() {
        return Err(WorkspaceTestErrorV1::Cache(format!(
            "cached release `{}` has no declared library sources",
            node.release
        )));
    }
    Ok(SourcePackageUnit {
        artifacts: cached.contract_artifacts,
        sources,
        identity: registry_release(&node.release),
        modules,
        exports,
        imports: node
            .dependencies
            .iter()
            .map(|edge| ImportBinding {
                alias: edge.alias.to_string(),
                package: registry_release(&edge.selected),
            })
            .collect(),
    })
}
fn validate_cached_manifest_edges(
    node: &MusubiVerificationNodeV1,
    dependencies: &BTreeMap<iroha_model_base::name::Name, DependencySpec>,
) -> Result<(), WorkspaceTestErrorV1> {
    if dependencies.len() != node.dependencies.len() {
        return Err(WorkspaceTestErrorV1::Cache(format!(
            "cached release `{}` dependency count disagrees with its exact lock node",
            node.release
        )));
    }
    for (alias, dependency) in dependencies {
        let DependencySpec::Concrete(ConcreteDependency::Registry {
            package,
            requirement,
        }) = dependency
        else {
            return Err(WorkspaceTestErrorV1::Cache(format!(
                "cached release `{}` retains a non-registry dependency `{alias}`",
                node.release
            )));
        };
        let edge = node
            .dependencies
            .iter()
            .find(|edge| &edge.alias == alias)
            .ok_or_else(|| {
                WorkspaceTestErrorV1::Cache(format!(
                    "cached release `{}` dependency `{alias}` has no exact edge",
                    node.release
                ))
            })?;
        if edge.kind != MusubiDependencyKindV1::Normal
            || edge.package.name != package.name
            || edge.requirement != *requirement
        {
            return Err(WorkspaceTestErrorV1::Cache(format!(
                "cached release `{}` dependency `{alias}` disagrees with its exact edge",
                node.release
            )));
        }
    }
    Ok(())
}
#[expect(
    clippy::case_sensitive_file_extension_comparisons,
    reason = "portable Musubi source paths require the canonical lowercase .ko suffix"
)]
fn relative_library_source(path: &str, source_dir: &PortablePath) -> Option<String> {
    if source_dir.as_str() == "." {
        return path.ends_with(".ko").then(|| path.to_owned());
    }
    let prefix = format!("{}/", source_dir.as_str());
    path.strip_prefix(&prefix)
        .filter(|relative| relative.ends_with(".ko") && !relative.is_empty())
        .map(ToOwned::to_owned)
}
fn selected_registry_nodes<'a>(
    lock: &'a LockfileV1,
    roots: &[&LockedRootV1],
) -> Result<Vec<&'a MusubiVerificationNodeV1>, WorkspaceTestErrorV1> {
    let by_release = lock
        .nodes
        .iter()
        .map(|node| (&node.release, node))
        .collect::<BTreeMap<_, _>>();
    let mut pending = roots
        .iter()
        .flat_map(|root| root.dependencies.iter().map(|edge| edge.selected.clone()))
        .collect::<Vec<_>>();
    let mut reachable = BTreeSet::<MusubiReleaseIdV1>::new();
    while let Some(release) = pending.pop() {
        if !reachable.insert(release.clone()) {
            continue;
        }
        let node = by_release.get(&release).ok_or_else(|| {
            WorkspaceTestErrorV1::Lock(format!(
                "selected test edge references missing node `{release}`"
            ))
        })?;
        pending.extend(node.dependencies.iter().map(|edge| edge.selected.clone()));
    }
    Ok(lock
        .nodes
        .iter()
        .filter(|node| reachable.contains(&node.release))
        .collect())
}
const MAX_TEST_SOURCE_SET_DEPTH_V1: usize = 64;
struct DeclaredTestSourceV1 {
    logical_path: String,
    unit: SourceModuleUnit,
}
#[derive(Default)]
struct DeclaredTestSourceBudgetV1 {
    entries: usize,
    source_bytes: u64,
}
fn declared_contract_for_test_source(
    member: &WorkspaceMember,
    source: &SourceModuleUnit,
    contracts: &mut BTreeMap<String, SourceModuleUnit>,
    budget: &mut DeclaredTestSourceBudgetV1,
) -> Result<Option<SourceModuleUnit>, WorkspaceTestErrorV1> {
    let Some(target) = declared_test_target_source_v1(source).map_err(|error| {
        error.diagnostics.map_or_else(
            || WorkspaceTestErrorV1::Target(error.message),
            WorkspaceTestErrorV1::Compilation,
        )
    })?
    else {
        return Ok(None);
    };
    if !member
        .manifest
        .contracts
        .iter()
        .any(|contract| contract.path.as_str() == target)
    {
        return Err(WorkspaceTestErrorV1::Target(format!(
            "test source `{}` targets `{target}`, which is not a manifest-declared contract",
            source.source_name
        )));
    }
    if let Some(contract) = contracts.get(&target) {
        return Ok(Some(contract.clone()));
    }
    let relative = Path::new(&target);
    if relative
        .extension()
        .and_then(|extension| extension.to_str())
        != Some("ko")
    {
        return Err(WorkspaceTestErrorV1::Target(
            "standalone test target must be a `.ko` contract source".to_owned(),
        ));
    }
    validate_test_ancestors(&member.package_root, relative)?;
    consume_test_entry_budget(budget)?;
    let contract = read_declared_test_source(
        &member.package_root,
        &member.package_root.join(relative),
        target.clone(),
        budget,
    )?;
    contracts.insert(target, contract.unit.clone());
    Ok(Some(contract.unit))
}
fn declared_test_sources(
    member: &WorkspaceMember,
    relative: &Path,
) -> Result<Vec<DeclaredTestSourceV1>, WorkspaceTestErrorV1> {
    validate_test_ancestors(&member.package_root, relative)?;
    let target = member.package_root.join(relative);
    let metadata = fs::symlink_metadata(&target).map_err(|error| {
        WorkspaceTestErrorV1::Target(format!(
            "cannot inspect test target `{}`: {error}",
            target.display()
        ))
    })?;
    let canonical = fs::canonicalize(&target).map_err(|error| {
        WorkspaceTestErrorV1::Target(format!(
            "cannot canonicalize test target `{}`: {error}",
            target.display()
        ))
    })?;
    if canonical != target || !canonical.starts_with(&member.package_root) {
        return Err(WorkspaceTestErrorV1::Target(format!(
            "test target `{}` changed identity or escaped package `{}`",
            target.display(),
            member.package.selector
        )));
    }
    let mut sources = Vec::new();
    let mut collisions = BTreeMap::new();
    let mut budget = DeclaredTestSourceBudgetV1::default();
    if metadata_is_safe_test_file(&target, &metadata) {
        if target.extension().and_then(|value| value.to_str()) != Some("ko") {
            return Err(WorkspaceTestErrorV1::Target(format!(
                "test target `{}` must be a `.ko` file or directory",
                target.display()
            )));
        }
        budget.entries = 1;
        let logical_path = portable_test_path(relative)?;
        register_test_path(&mut collisions, &logical_path)?;
        sources.push(read_declared_test_source(
            &member.package_root,
            &target,
            logical_path,
            &mut budget,
        )?);
    } else if metadata_is_safe_test_directory(&metadata) {
        budget.entries = 1;
        let directory = OwnerDirectory::open(&target).map_err(|error| {
            WorkspaceTestErrorV1::Target(format!("cannot retain test directory authority: {error}"))
        })?;
        collect_declared_test_directory(
            &member.package_root,
            &directory,
            relative,
            0,
            &mut collisions,
            &mut budget,
            &mut sources,
        )?;
        sources.retain(|source| crate::compiler::is_named_source_unit(&source.unit));
    } else {
        return Err(WorkspaceTestErrorV1::Target(format!(
            "test target `{}` is a symlink, reparse point, hardlink, or special file",
            target.display()
        )));
    }
    if sources.is_empty() {
        return Err(WorkspaceTestErrorV1::Target(format!(
            "test target `{}` contains no regular `.ko` source",
            target.display()
        )));
    }
    sources.sort_by(|left, right| left.logical_path.cmp(&right.logical_path));
    Ok(sources)
}
fn collect_declared_test_directory(
    package_root: &Path,
    retained: &OwnerDirectory,
    relative: &Path,
    depth: usize,
    collisions: &mut BTreeMap<String, String>,
    budget: &mut DeclaredTestSourceBudgetV1,
    sources: &mut Vec<DeclaredTestSourceV1>,
) -> Result<(), WorkspaceTestErrorV1> {
    let directory = retained.path();
    if depth > MAX_TEST_SOURCE_SET_DEPTH_V1 {
        return Err(WorkspaceTestErrorV1::Target(format!(
            "test source set exceeds {MAX_TEST_SOURCE_SET_DEPTH_V1} directory levels"
        )));
    }
    let before = fs::symlink_metadata(directory).map_err(|error| {
        WorkspaceTestErrorV1::Target(format!(
            "cannot inspect test directory `{}`: {error}",
            directory.display()
        ))
    })?;
    if !metadata_is_safe_test_directory(&before)
        || fs::canonicalize(directory).ok().as_deref() != Some(directory)
        || !directory.starts_with(package_root)
    {
        return Err(WorkspaceTestErrorV1::Target(format!(
            "test directory `{}` is not a stable real package descendant",
            directory.display()
        )));
    }
    let entries = retained
        .entries(MUSUBI_MAX_FILES_V1 as usize)
        .map_err(|error| {
            WorkspaceTestErrorV1::Target(format!(
                "cannot read test directory `{}`: {error}",
                directory.display()
            ))
        })?;
    let mut names = Vec::new();
    for entry in &entries {
        let name = entry.to_str().ok_or_else(|| {
            WorkspaceTestErrorV1::Target("test source path is not UTF-8".to_owned())
        })?;
        names.push(name.to_owned());
    }
    names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    for name in names {
        let physical = directory.join(&name);
        let child_relative = relative.join(&name);
        let metadata = fs::symlink_metadata(&physical).map_err(|error| {
            WorkspaceTestErrorV1::Target(format!(
                "cannot inspect test source `{}`: {error}",
                physical.display()
            ))
        })?;
        if metadata_is_link_or_reparse(&metadata) {
            return Err(WorkspaceTestErrorV1::Target(format!(
                "test source set contains a symlink or reparse point at `{}`",
                physical.display()
            )));
        }
        if metadata.is_dir() && is_excluded_directory(&name) {
            continue;
        }
        if is_sensitive_component(&name) {
            return Err(WorkspaceTestErrorV1::Target(format!(
                "test source set contains a credential-sensitive path at `{}`",
                physical.display()
            )));
        }
        consume_test_entry_budget(budget)?;
        let logical_path = portable_test_path(&child_relative)?;
        register_test_path(collisions, &logical_path)?;
        if metadata_is_safe_test_directory(&metadata) {
            let child = retained.open_child(&name).map_err(|error| {
                WorkspaceTestErrorV1::Target(format!("cannot retain child test directory: {error}"))
            })?;
            collect_declared_test_directory(
                package_root,
                &child,
                &child_relative,
                depth.saturating_add(1),
                collisions,
                budget,
                sources,
            )?;
        } else if metadata_is_safe_test_file(&physical, &metadata) {
            if physical.extension().and_then(|value| value.to_str()) == Some("ko") {
                sources.push(read_declared_test_source(
                    package_root,
                    &physical,
                    logical_path,
                    budget,
                )?);
            }
        } else {
            return Err(WorkspaceTestErrorV1::Target(format!(
                "test source set contains a hardlink or special file at `{}`",
                physical.display()
            )));
        }
    }
    let after = fs::symlink_metadata(directory).map_err(|error| {
        WorkspaceTestErrorV1::Target(format!(
            "cannot reinspect test directory `{}`: {error}",
            directory.display()
        ))
    })?;
    let current_entries = retained
        .entries(MUSUBI_MAX_FILES_V1 as usize)
        .map_err(|error| {
            WorkspaceTestErrorV1::Target(format!(
                "cannot revalidate test directory authority: {error}"
            ))
        })?;
    if entries != current_entries
        || !same_test_snapshot(&before, &after)
        || fs::canonicalize(directory).ok().as_deref() != Some(directory)
    {
        return Err(WorkspaceTestErrorV1::Target(format!(
            "test directory `{}` changed while its source set was read",
            directory.display()
        )));
    }
    Ok(())
}
fn read_declared_test_source(
    package_root: &Path,
    physical: &Path,
    logical_path: String,
    budget: &mut DeclaredTestSourceBudgetV1,
) -> Result<DeclaredTestSourceV1, WorkspaceTestErrorV1> {
    read_declared_test_source_with_reader(
        package_root,
        physical,
        logical_path,
        budget,
        |_, file, maximum| read_bounded_test_descriptor(file, maximum),
    )
}
fn read_bounded_test_descriptor(file: &mut fs::File, maximum: u64) -> io::Result<Vec<u8>> {
    let length = file.metadata()?.len();
    if length > maximum {
        return Err(io::Error::other("test source exceeds its byte bound"));
    }
    let length = usize::try_from(length).map_err(io::Error::other)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(io::Error::other)?;
    bytes.resize(length, 0);
    file.read_exact(&mut bytes)?;
    let mut extra = [0];
    if file.read(&mut extra)? != 0 {
        return Err(io::Error::other("test source grew during its bounded read"));
    }
    Ok(bytes)
}
fn read_declared_test_source_with_reader<F>(
    package_root: &Path,
    physical: &Path,
    logical_path: String,
    budget: &mut DeclaredTestSourceBudgetV1,
    read_file: F,
) -> Result<DeclaredTestSourceV1, WorkspaceTestErrorV1>
where
    F: FnOnce(&Path, &mut fs::File, u64) -> io::Result<Vec<u8>>,
{
    let remaining = MUSUBI_MAX_SOURCE_PAYLOAD_BYTES_V1
        .checked_sub(budget.source_bytes)
        .ok_or_else(|| {
            WorkspaceTestErrorV1::Target("test source byte budget is exhausted".to_owned())
        })?;
    let maximum = (MAX_MODULE_GRAPH_SOURCE_BYTES as u64).min(remaining);
    let before = fs::symlink_metadata(physical).map_err(|error| {
        WorkspaceTestErrorV1::Target(format!(
            "cannot inspect test source `{}`: {error}",
            physical.display()
        ))
    })?;
    if !metadata_is_safe_test_file(physical, &before)
        || before.len() > maximum
        || fs::canonicalize(physical).ok().as_deref() != Some(physical)
        || !physical.starts_with(package_root)
    {
        return Err(WorkspaceTestErrorV1::Target(format!(
            "test source `{}` is not a stable bounded regular file",
            physical.display()
        )));
    }
    let mut retained = RetainedFile::open_regular(physical).map_err(|error| {
        WorkspaceTestErrorV1::Target(format!("cannot retain bounded test source: {error}"))
    })?;
    let snapshot = retained.snapshot().map_err(|error| {
        WorkspaceTestErrorV1::Target(format!("cannot snapshot bounded test source: {error}"))
    })?;
    let bytes = read_file(physical, retained.file_mut(), maximum).map_err(|error| {
        WorkspaceTestErrorV1::Target(format!(
            "cannot securely read bounded test source `{}`: {error}",
            physical.display()
        ))
    })?;
    let after = retained.snapshot().map_err(|error| {
        WorkspaceTestErrorV1::Target(format!(
            "test source changed during its bounded read: {error}"
        ))
    })?;
    if snapshot != after || fs::canonicalize(physical).ok().as_deref() != Some(physical) {
        return Err(WorkspaceTestErrorV1::Target(format!(
            "test source `{}` changed while it was read",
            physical.display()
        )));
    }
    let source = String::from_utf8(bytes).map_err(|_| {
        WorkspaceTestErrorV1::Target(format!("test source `{}` is not UTF-8", physical.display()))
    })?;
    budget.source_bytes = budget
        .source_bytes
        .checked_add(u64::try_from(source.len()).unwrap_or(u64::MAX))
        .ok_or_else(|| {
            WorkspaceTestErrorV1::Target("test source byte count overflowed".to_owned())
        })?;
    if budget.source_bytes > MUSUBI_MAX_SOURCE_PAYLOAD_BYTES_V1 {
        return Err(WorkspaceTestErrorV1::Target(format!(
            "test source set exceeds {MUSUBI_MAX_SOURCE_PAYLOAD_BYTES_V1} UTF-8 bytes"
        )));
    }
    Ok(DeclaredTestSourceV1 {
        unit: SourceModuleUnit {
            source_name: logical_path.clone(),
            source,
        },
        logical_path,
    })
}
fn validate_test_ancestors(root: &Path, relative: &Path) -> Result<(), WorkspaceTestErrorV1> {
    let mut current = root.to_path_buf();
    for component in relative.components() {
        if let std::path::Component::Normal(name) = component {
            let name = name.to_str().ok_or_else(|| {
                WorkspaceTestErrorV1::Target("test target path is not UTF-8".to_owned())
            })?;
            if is_excluded_directory(name) || is_sensitive_component(name) {
                return Err(WorkspaceTestErrorV1::Target(format!(
                    "test target `{}` traverses an excluded or credential-sensitive path",
                    relative.display()
                )));
            }
        }
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            WorkspaceTestErrorV1::Target(format!(
                "cannot inspect test path `{}`: {error}",
                current.display()
            ))
        })?;
        if metadata_is_link_or_reparse(&metadata) {
            return Err(WorkspaceTestErrorV1::Target(format!(
                "test target `{}` traverses a symlink or reparse point",
                current.display()
            )));
        }
    }
    Ok(())
}
fn portable_test_path(relative: &Path) -> Result<String, WorkspaceTestErrorV1> {
    let mut components = Vec::new();
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            return Err(WorkspaceTestErrorV1::Target(
                "test source path is not portable and relative".to_owned(),
            ));
        };
        components.push(
            component
                .to_str()
                .ok_or_else(|| {
                    WorkspaceTestErrorV1::Target("test source path is not UTF-8".to_owned())
                })?
                .to_owned(),
        );
    }
    let raw = components.join("/");
    PortablePath::new(&raw)
        .map(|path| path.to_string())
        .map_err(|error| WorkspaceTestErrorV1::Target(error.to_string()))
}
fn register_test_path(
    collisions: &mut BTreeMap<String, String>,
    logical_path: &str,
) -> Result<(), WorkspaceTestErrorV1> {
    let key = logical_path
        .chars()
        .flat_map(char::to_lowercase)
        .collect::<String>();
    if let Some(previous) = collisions.insert(key, logical_path.to_owned())
        && previous != logical_path
    {
        return Err(WorkspaceTestErrorV1::Target(format!(
            "test source paths `{previous}` and `{logical_path}` have a portable case/Unicode collision"
        )));
    }
    Ok(())
}
fn consume_test_entry_budget(
    budget: &mut DeclaredTestSourceBudgetV1,
) -> Result<(), WorkspaceTestErrorV1> {
    budget.entries = budget.entries.saturating_add(1);
    if budget.entries > MUSUBI_MAX_FILES_V1 as usize {
        return Err(WorkspaceTestErrorV1::Target(format!(
            "test source set exceeds {MUSUBI_MAX_FILES_V1} filesystem entries"
        )));
    }
    Ok(())
}
fn metadata_is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        metadata.file_type().is_symlink()
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = metadata;
        true
    }
}
fn metadata_is_safe_test_file(path: &Path, metadata: &fs::Metadata) -> bool {
    if metadata_is_link_or_reparse(metadata) || !metadata.is_file() {
        return false;
    }
    // Native retained opens enforce the single-link and no-reparse contract on both hosts,
    // including non-Kotodama files which are inspected but never compiled.
    RetainedFile::open_regular(path).is_ok()
}
fn metadata_is_safe_test_directory(metadata: &fs::Metadata) -> bool {
    !metadata_is_link_or_reparse(metadata) && metadata.is_dir()
}
fn same_test_snapshot(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        left.dev() == right.dev()
            && left.ino() == right.ino()
            && left.file_type() == right.file_type()
            && left.len() == right.len()
            && left.mtime() == right.mtime()
            && left.mtime_nsec() == right.mtime_nsec()
            && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()
            && left.nlink() == right.nlink()
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        // The retained OwnerDirectory separately proves exact directory/ancestor identity.
        left.file_attributes() == right.file_attributes()
            && left.creation_time() == right.creation_time()
            && left.last_write_time() == right.last_write_time()
            && left.file_size() == right.file_size()
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (left, right);
        false
    }
}
#[cfg(all(test, any(unix, windows)))]
mod tests {
    use super::*;
    use crate::{
        lockfile::LockedRootV1,
        workspace::{Workspace, load_workspace},
    };
    use iroha_data_model::musubi::{
        ArchiveId, MusubiAbiBindingV1, MusubiContentDigestV1, MusubiPackageIdV1,
        MusubiPackageScopeV1, MusubiRegistrySnapshotV1, MusubiReleaseDigestV1, MusubiReleaseIdV1,
        MusubiVerificationNodeV1,
    };
    use iroha_model_base::topology::DataSpaceId;
    use kotodama_lang::{
        linker::{ModuleBuildGraph, SourcePackageGraphRequest},
        session::CompilerSession,
    };
    #[cfg(unix)]
    use std::process::Command;
    use std::{cell::RefCell, fs, path::Path};
    use tempfile::tempdir;
    struct RecordingRegistry {
        releases: RefCell<Vec<String>>,
        packages: BTreeMap<String, SourcePackageUnit>,
    }
    impl RecordingRegistry {
        fn new(packages: impl IntoIterator<Item = SourcePackageUnit>) -> Self {
            Self {
                releases: RefCell::new(Vec::new()),
                packages: packages
                    .into_iter()
                    .map(|package| (package.identity.clone(), package))
                    .collect(),
            }
        }
    }
    impl AuthenticatedTestRegistryV1 for RecordingRegistry {
        fn load(
            &self,
            node: &MusubiVerificationNodeV1,
        ) -> Result<SourcePackageUnit, WorkspaceTestErrorV1> {
            self.releases.borrow_mut().push(node.release.to_string());
            self.packages
                .get(&registry_release(&node.release))
                .cloned()
                .ok_or_else(|| {
                    WorkspaceTestErrorV1::Cache(format!(
                        "test registry is missing `{}`",
                        node.release
                    ))
                })
        }
    }
    fn write(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create fixture parent");
        }
        fs::write(path, contents).expect("write fixture");
    }
    fn declared_source_fixture(contents: &str) -> (tempfile::TempDir, Workspace) {
        let temporary = tempdir().expect("tempdir");
        write(
            &temporary.path().join("Musubi.toml"),
            &package_manifest("app", ""),
        );
        write(&temporary.path().join("src/lib.ko"), "module AppLib {}");
        write(&temporary.path().join("tests/unit.ko"), contents);
        let workspace =
            load_workspace(&temporary.path().join("Musubi.toml")).expect("workspace fixture");
        (temporary, workspace)
    }
    fn package_manifest(name: &str, dependency: &str) -> String {
        format!(
            r#"manifest-version = 1

[package]
namespace = "test"
name = "{name}"
version = "1.0.0"
edition = "1"
abi-version = 1

[lib]
source-dir = "src"
exports = []

[[test]]
name = "unit"
path = "tests/unit.ko"

{dependency}
"#
        )
    }
    fn lock(roots: Vec<LockedRootV1>, nodes: Vec<MusubiVerificationNodeV1>) -> LockfileV1 {
        LockfileV1::new(
            LockContextV1::Registry {
                network_id:
                    "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0"
                        .parse()
                        .expect("network id"),
                snapshot: MusubiRegistrySnapshotV1 {
                    finalized_height: 7,
                    finalized_block_hash: [8; 32],
                    index_revision: 3,
                },
            },
            roots,
            nodes,
        )
        .expect("valid lock")
    }
    fn structural_package(dataspace: u64, name: &str) -> MusubiPackageIdV1 {
        MusubiPackageIdV1::new(
            DataSpaceId::new(dataspace),
            MusubiPackageScopeV1::DataspaceRoot,
            name.parse().expect("package name"),
        )
    }
    fn node(
        package: MusubiPackageIdV1,
        dependencies: Vec<MusubiExactDependencyEdgeV1>,
        seed: u8,
        interface_digest: MusubiContentDigestV1,
    ) -> MusubiVerificationNodeV1 {
        MusubiVerificationNodeV1 {
            release: MusubiReleaseIdV1::new(package, "1.0.0".parse().expect("version")),
            release_digest: MusubiReleaseDigestV1::new([seed; 32]),
            archive_id: ArchiveId::new([seed.wrapping_add(1); 32]),
            source_digest: MusubiContentDigestV1::new([seed.wrapping_add(2); 32]),
            interface_digest,
            abi: MusubiAbiBindingV1::new(compute_abi_hash(SyscallPolicy::AbiV1))
                .expect("ABI binding"),
            dependencies,
        }
    }
    fn source_package(
        release: &MusubiReleaseIdV1,
        source: &str,
        exports: &[&str],
        imports: Vec<ImportBinding>,
    ) -> SourcePackageUnit {
        SourcePackageUnit {
            artifacts: Vec::new(),
            sources: Vec::new(),
            identity: registry_release(release),
            modules: vec![SourceModuleUnit {
                source_name: "src/lib.ko".to_owned(),
                source: source.to_owned(),
            }],
            exports: exports.iter().map(|export| (*export).to_owned()).collect(),
            imports,
        }
    }
    fn interface_digest(
        package: &SourcePackageUnit,
        packages: &[SourcePackageUnit],
    ) -> MusubiContentDigestV1 {
        let validated = CompilerSession::new(CompilerOptions {
            chain_discriminant: 753,
            mode: CompilerMode::Production,
            ..CompilerOptions::default()
        })
        .validate_package_graph(
            &ModuleBuildGraph::default(),
            SourcePackageGraphRequest {
                package: package.clone(),
                dependencies: packages
                    .iter()
                    .filter(|candidate| candidate.identity != package.identity)
                    .cloned()
                    .collect(),
            },
        )
        .expect("typed package fixture");
        MusubiContentDigestV1::new(*validated.interface_fingerprint.as_ref())
    }
    fn standalone_fixture(test_source: &str) -> (tempfile::TempDir, Workspace) {
        let (temporary, _) = declared_source_fixture(test_source);
        let manifest = format!(
            "{}\n[[contract]]\nname = \"app\"\npath = \"contracts/app.ko\"\n",
            package_manifest("app", "")
        );
        write(&temporary.path().join("Musubi.toml"), &manifest);
        write(
            &temporary.path().join("contracts/app.ko"),
            "seiyaku App { fn reward() -> int { return 7; } view fn current() authorize(anyone) -> int { return reward(); } }",
        );
        let workspace =
            load_workspace(&temporary.path().join("Musubi.toml")).expect("standalone workspace");
        (temporary, workspace)
    }
    #[test]
    fn local_standalone_suite_runs_without_registry_cache_or_ambient_tests() {
        let (temporary, workspace) = standalone_fixture(
            r#"module Tests { koto_test { target: "../contracts/app.ko" } #[test] fn reward_is_seven() { test::assert(reward() == 7); } }"#,
        );
        write(
            &temporary.path().join("tests/ambient.ko"),
            "this undeclared source must never be parsed",
        );
        let selected = vec!["test/app".parse().expect("selector")];
        let lock = resolve_workspace_local(&workspace, &selected, None, ResolveModeV1::UpdateLock)
            .expect("local resolver")
            .expect("local graph")
            .lockfile;
        let report = execute_workspace_tests_v1(
            None,
            &workspace,
            &selected,
            &lock,
            &WorkspaceTestOptionsV1::new(753),
        )
        .expect("native standalone suite without cache");
        assert_eq!(report.passed(), 1);
        assert_eq!(report.targets[0].source, "tests/unit.ko");
        let mut options = WorkspaceTestOptionsV1::new(753);
        options.filter = Some("reward_is_seven".to_owned());
        options.exact = true;
        assert_eq!(
            execute_workspace_tests_v1(None, &workspace, &selected, &lock, &options)
                .expect("filter standalone tests")
                .passed(),
            1
        );
        write(
            &temporary.path().join("tests/unit.ko"),
            r#"module Tests { koto_test { target: "../contracts/app.ko" } #[test] fn wrong_import() { test::assert(missing::value() == 7); } }"#,
        );
        assert!(
            matches!(execute_workspace_tests_v1(None, &workspace, &selected, &lock, &WorkspaceTestOptionsV1::new(753)), Err(WorkspaceTestErrorV1::Compilation(diagnostics)) if diagnostics.diagnostics.iter().any(|diagnostic| diagnostic.message.contains("missing")))
        );
    }
    #[test]
    fn contract_selection_excludes_same_named_tests_of_other_targets() {
        let (temporary, _) = standalone_fixture(
            r#"module Tests { koto_test { target: "../contracts/app.ko" } #[test] fn selected() { test::assert(reward() == 7); } }"#,
        );
        let manifest_path = temporary.path().join("Musubi.toml");
        let mut manifest = std::fs::read_to_string(&manifest_path).unwrap();
        manifest.push_str("\n[[contract]]\nname = \"other\"\npath = \"contracts/other.ko\"\n[[test]]\nname = \"other\"\npath = \"tests/other.ko\"\n");
        write(&manifest_path, &manifest);
        write(
            &temporary.path().join("contracts/other.ko"),
            "seiyaku Other { view fn value() authorize(anyone) -> int { 0 } }",
        );
        write(
            &temporary.path().join("tests/other.ko"),
            r#"module OtherTests { koto_test { target: "../contracts/other.ko" } #[test] fn selected() { test::assert(false); } }"#,
        );
        let workspace = load_workspace(&manifest_path).unwrap();
        let selected = vec!["test/app".parse().unwrap()];
        let lock = resolve_workspace_local(&workspace, &selected, None, ResolveModeV1::UpdateLock)
            .unwrap()
            .unwrap()
            .lockfile;
        let mut options = WorkspaceTestOptionsV1::new(753);
        options.contract = Some("app".into());
        options.filter = Some("selected".into());
        options.exact = true;
        let report =
            execute_workspace_tests_v1(None, &workspace, &selected, &lock, &options).unwrap();
        assert_eq!(report.targets.len(), 1);
        assert_eq!(report.passed(), 1);
        assert_eq!(report.failed(), 0);
        options.contract = Some("absent".into());
        assert!(execute_workspace_tests_v1(None, &workspace, &selected, &lock, &options).is_err());
    }
    #[test]
    fn standalone_contract_is_read_once_and_reused_as_immutable_source() {
        let (temporary, workspace) = standalone_fixture(
            r#"module Tests { koto_test { target: "../contracts/app.ko" } #[test] fn check() { test::assert(reward() == 7); } }"#,
        );
        let member = workspace
            .members()
            .values()
            .next()
            .expect("workspace member");
        let test = declared_test_sources(member, Path::new("tests/unit.ko"))
            .expect("test source")
            .remove(0);
        let mut sources = BTreeMap::new();
        let mut budget = DeclaredTestSourceBudgetV1::default();
        let first =
            declared_contract_for_test_source(member, &test.unit, &mut sources, &mut budget)
                .expect("contract source")
                .expect("indirect target");
        let bytes = budget.source_bytes;
        write(
            &temporary.path().join("contracts/app.ko"),
            "changed after source snapshot",
        );
        let second =
            declared_contract_for_test_source(member, &test.unit, &mut sources, &mut budget)
                .expect("reuse exact source")
                .expect("indirect target");
        assert_eq!(first, second);
        assert_eq!(budget.entries, 1);
        assert_eq!(budget.source_bytes, bytes);
    }
    #[test]
    fn standalone_contract_target_rejects_unknown_and_outside_paths() {
        for target in ["../contracts/unknown.ko", "../../outside.ko"] {
            let source = format!(
                "module Tests {{ koto_test {{ target: \"{target}\" }} #[test] fn check() {{ test::assert(true); }} }}"
            );
            let (_temporary, workspace) = standalone_fixture(&source);
            let member = workspace
                .members()
                .values()
                .next()
                .expect("workspace member");
            let test = declared_test_sources(member, Path::new("tests/unit.ko"))
                .expect("test source")
                .remove(0);
            assert!(
                matches!(
                    declared_contract_for_test_source(
                        member,
                        &test.unit,
                        &mut BTreeMap::new(),
                        &mut DeclaredTestSourceBudgetV1::default()
                    ),
                    Err(WorkspaceTestErrorV1::Target(_))
                ),
                "{target}"
            );
        }
    }
    #[cfg(unix)]
    #[test]
    fn standalone_contract_target_rejects_symlinks() {
        let (temporary, workspace) = standalone_fixture(
            r#"module Tests { koto_test { target: "../contracts/app.ko" } #[test] fn check() { test::assert(true); } }"#,
        );
        let target = temporary.path().join("contracts/app.ko");
        fs::rename(&target, temporary.path().join("real.ko")).expect("move contract");
        std::os::unix::fs::symlink("../real.ko", &target).expect("symlink target");
        let member = workspace
            .members()
            .values()
            .next()
            .expect("workspace member");
        let test = declared_test_sources(member, Path::new("tests/unit.ko"))
            .expect("test source")
            .remove(0);
        assert!(
            matches!(declared_contract_for_test_source(member, &test.unit, &mut BTreeMap::new(), &mut DeclaredTestSourceBudgetV1::default()), Err(WorkspaceTestErrorV1::Target(reason)) if reason.contains("symlink"))
        );
    }
    #[test]
    fn rejects_invalid_controls_and_ambiguous_selection() {
        let mut options = WorkspaceTestOptionsV1::new(753);
        options.jobs = 0;
        assert!(matches!(
            validate_options(&options),
            Err(WorkspaceTestErrorV1::Workspace(_))
        ));
        options.jobs = 1;
        options.exact = true;
        assert!(matches!(
            validate_options(&options),
            Err(WorkspaceTestErrorV1::Workspace(_))
        ));
        assert!(matches!(
            canonical_selected(&[]),
            Err(WorkspaceTestErrorV1::Workspace(_))
        ));
        let selector: MusubiPackageSelectorV1 = "test/app".parse().expect("selector");
        assert!(matches!(
            canonical_selected(&[selector.clone(), selector]),
            Err(WorkspaceTestErrorV1::Workspace(_))
        ));
    }
    #[test]
    fn runs_tests_only_for_the_selected_workspace_root() {
        let temp = tempdir().expect("tempdir");
        write(
            &temp.path().join("Musubi.toml"),
            r#"manifest-version = 1

[workspace]
members = ["app", "helper"]
default-members = ["app"]
"#,
        );
        for (name, assertion) in [("app", "true"), ("helper", "false")] {
            let type_name = match name {
                "app" => "App",
                "helper" => "Helper",
                _ => unreachable!("fixed fixture package"),
            };
            write(
                &temp.path().join(name).join("Musubi.toml"),
                &package_manifest(name, ""),
            );
            write(
                &temp.path().join(name).join("src/lib.ko"),
                &format!("module {type_name}Lib {{}}"),
            );
            write(
                &temp.path().join(name).join("tests/unit.ko"),
                &format!(
                    "seiyaku {type_name}Tests {{ #[test] fn selected() {{ test::assert({assertion}); }} }}"
                ),
            );
        }
        let workspace = load_workspace(&temp.path().join("Musubi.toml")).expect("workspace");
        let selected = vec![
            "test/app"
                .parse::<MusubiPackageSelectorV1>()
                .expect("selector"),
        ];
        let lock = lock(
            vec![LockedRootV1 {
                package: selected[0].clone(),
                dependencies: vec![],
            }],
            vec![],
        );
        let cache = MusubiCache::open(temp.path().join("cache")).expect("private test cache");
        let report = execute_workspace_tests_v1(
            Some(&cache),
            &workspace,
            &selected,
            &lock,
            &WorkspaceTestOptionsV1::new(753),
        )
        .expect("selected tests");
        assert_eq!(report.targets.len(), 1);
        assert_eq!(report.targets[0].package.to_string(), "test/app");
        assert_eq!(report.passed(), 1);
        assert_eq!(report.failed(), 0);
        assert!(report.is_success());
    }
    #[test]
    fn authenticates_and_executes_selected_dev_graph_with_transitive_normal_modules() {
        let temp = tempdir().expect("tempdir");
        write(
            &temp.path().join("Musubi.toml"),
            &package_manifest(
                "app",
                "[dev-dependencies]\ndep = { package = \"test/dep\", version = \"^1.0.0\" }",
            ),
        );
        write(&temp.path().join("src/lib.ko"), "module AppLib {}");
        write(
            &temp.path().join("tests/unit.ko"),
            "seiyaku AppTests { #[test] fn selected() { test::assert(dep::truth()); } }",
        );
        let workspace = load_workspace(&temp.path().join("Musubi.toml")).expect("workspace");
        let selected = vec![
            "test/app"
                .parse::<MusubiPackageSelectorV1>()
                .expect("selector"),
        ];
        let dep = structural_package(1, "dep");
        let leaf = structural_package(2, "leaf");
        let leaf_edge = MusubiExactDependencyEdgeV1 {
            alias: "leaf".parse().expect("alias"),
            kind: MusubiDependencyKindV1::Normal,
            package: leaf.clone(),
            requirement: "^1.0.0".parse().expect("requirement"),
            selected: MusubiReleaseIdV1::new(leaf.clone(), "1.0.0".parse().expect("version")),
        };
        let dev_edge = MusubiExactDependencyEdgeV1 {
            alias: "dep".parse().expect("alias"),
            kind: MusubiDependencyKindV1::Development,
            package: dep.clone(),
            requirement: "^1.0.0".parse().expect("requirement"),
            selected: MusubiReleaseIdV1::new(dep.clone(), "1.0.0".parse().expect("version")),
        };
        let dep_release =
            MusubiReleaseIdV1::new(dep.clone(), "1.0.0".parse().expect("dependency version"));
        let leaf_release =
            MusubiReleaseIdV1::new(leaf.clone(), "1.0.0".parse().expect("leaf version"));
        let leaf_unit = source_package(
            &leaf_release,
            "module Leaf { export fn truth() -> bool { return true; } }",
            &["truth"],
            Vec::new(),
        );
        let dep_unit = source_package(
            &dep_release,
            "module Dep { export fn truth() -> bool { return leaf::truth(); } }",
            &["truth"],
            vec![ImportBinding {
                alias: "leaf".to_owned(),
                package: registry_release(&leaf_release),
            }],
        );
        let package_units = vec![dep_unit.clone(), leaf_unit.clone()];
        let dep_interface = interface_digest(&dep_unit, &package_units);
        let leaf_interface = interface_digest(&leaf_unit, &package_units);
        let lock = lock(
            vec![LockedRootV1 {
                package: selected[0].clone(),
                dependencies: vec![dev_edge],
            }],
            vec![
                node(dep, vec![leaf_edge], 10, dep_interface),
                node(leaf, vec![], 20, leaf_interface),
            ],
        );
        let registry = RecordingRegistry::new(package_units);
        let report = execute_workspace_tests_with_source(
            &registry,
            &workspace,
            &selected,
            &lock,
            &WorkspaceTestOptionsV1::new(753),
        )
        .expect("exact dev graph must compile and execute");
        assert!(report.is_success());
        assert_eq!(report.targets.len(), 1);
        assert_eq!(registry.releases.borrow().len(), 2);
    }
    #[test]
    fn authenticates_registry_edges_reachable_through_a_pure_path_package_only() {
        let temp = tempdir().expect("tempdir");
        write(
            &temp.path().join("Musubi.toml"),
            r#"manifest-version = 1

[workspace]
members = ["app", "unrelated"]
default-members = ["app"]
"#,
        );
        write(
            &temp.path().join("app/Musubi.toml"),
            &package_manifest("app", "[dependencies]\nhelper = { path = \"../helper\" }"),
        );
        write(&temp.path().join("app/src/lib.ko"), "module AppLib {}");
        write(
            &temp.path().join("app/tests/unit.ko"),
            "seiyaku AppTests { #[test] fn selected() { test::assert(helper::truth()); } }",
        );
        write(
            &temp.path().join("helper/Musubi.toml"),
            r#"manifest-version = 1

[package]
namespace = "test"
name = "helper"
version = "1.0.0"
edition = "1"
abi-version = 1

[lib]
source-dir = "src"
exports = ["truth"]

[dependencies]
core = { package = "test/core", version = "^1.0.0" }
"#,
        );
        write(
            &temp.path().join("helper/src/lib.ko"),
            "module Helper { export fn truth() -> bool { return core::truth(); } }",
        );
        write(
            &temp.path().join("unrelated/Musubi.toml"),
            &package_manifest(
                "unrelated",
                "[dependencies]\nunused = { package = \"test/unused\", version = \"^1.0.0\" }",
            ),
        );
        let workspace = load_workspace(&temp.path().join("Musubi.toml")).expect("workspace");
        let app_selector: MusubiPackageSelectorV1 = "test/app".parse().expect("app selector");
        let helper_selector: MusubiPackageSelectorV1 =
            "test/helper".parse().expect("helper selector");
        let unrelated_selector: MusubiPackageSelectorV1 =
            "test/unrelated".parse().expect("unrelated selector");
        let selected = vec![app_selector.clone()];
        let core = structural_package(1, "core");
        let unused = structural_package(2, "unused");
        let core_release =
            MusubiReleaseIdV1::new(core.clone(), "1.0.0".parse().expect("core version"));
        let unused_release =
            MusubiReleaseIdV1::new(unused.clone(), "1.0.0".parse().expect("unused version"));
        let core_edge = MusubiExactDependencyEdgeV1 {
            alias: "core".parse().expect("alias"),
            kind: MusubiDependencyKindV1::Normal,
            package: core.clone(),
            requirement: "^1.0.0".parse().expect("requirement"),
            selected: core_release.clone(),
        };
        let unused_edge = MusubiExactDependencyEdgeV1 {
            alias: "unused".parse().expect("alias"),
            kind: MusubiDependencyKindV1::Normal,
            package: unused.clone(),
            requirement: "^1.0.0".parse().expect("requirement"),
            selected: unused_release.clone(),
        };
        let core_unit = source_package(
            &core_release,
            "module Core { export fn truth() -> bool { return true; } }",
            &["truth"],
            Vec::new(),
        );
        let unused_unit = source_package(
            &unused_release,
            "module Unused { export fn truth() -> bool { return false; } }",
            &["truth"],
            Vec::new(),
        );
        let core_interface = interface_digest(&core_unit, std::slice::from_ref(&core_unit));
        let unused_interface = interface_digest(&unused_unit, std::slice::from_ref(&unused_unit));
        let lock = lock(
            vec![
                LockedRootV1 {
                    package: app_selector,
                    dependencies: vec![],
                },
                LockedRootV1 {
                    package: helper_selector,
                    dependencies: vec![core_edge],
                },
                LockedRootV1 {
                    package: unrelated_selector,
                    dependencies: vec![unused_edge],
                },
            ],
            vec![
                node(core, vec![], 10, core_interface),
                node(unused, vec![], 20, unused_interface),
            ],
        );
        let registry = RecordingRegistry::new([core_unit, unused_unit]);
        let report = execute_workspace_tests_with_source(
            &registry,
            &workspace,
            &selected,
            &lock,
            &WorkspaceTestOptionsV1::new(753),
        )
        .expect("pure-path registry graph must compile and execute");
        assert!(report.is_success());
        assert_eq!(
            registry.releases.into_inner(),
            [core_release.to_string()],
            "an unrelated workspace root must not enter the selected test graph"
        );
    }
    #[test]
    fn rejects_registry_source_whose_typed_interface_disagrees_with_lock() {
        let package_id = structural_package(1, "dep");
        let release = MusubiReleaseIdV1::new(package_id.clone(), "1.0.0".parse().expect("version"));
        let package = source_package(
            &release,
            "module Dep { export fn value() -> int { return 1; } }",
            &["value"],
            Vec::new(),
        );
        let locked = node(
            package_id,
            Vec::new(),
            10,
            MusubiContentDigestV1::new([99; 32]),
        );
        let error =
            validate_registry_interfaces(&[&locked], &[package], &WorkspaceTestOptionsV1::new(753))
                .expect_err("interface substitution must fail closed");
        assert!(matches!(error, WorkspaceTestErrorV1::Cache(_)));
        assert!(error.to_string().contains("typed interface"));
    }
    #[test]
    fn directory_target_runs_only_its_bounded_canonical_source_set() {
        let temp = tempdir().expect("tempdir");
        let manifest =
            package_manifest("app", "").replace("path = \"tests/unit.ko\"", "path = \"tests\"");
        write(&temp.path().join("Musubi.toml"), &manifest);
        write(&temp.path().join("src/lib.ko"), "module AppLib {}");
        write(
            &temp.path().join("tests/z.ko"),
            "seiyaku ZTests { #[test] fn z_selected() { test::assert(true); } }",
        );
        write(
            &temp.path().join("tests/nested/a.ko"),
            "seiyaku ATests { #[test] fn a_selected() { test::assert(true); } }",
        );
        write(&temp.path().join("tests/notes.txt"), "not executable");
        write(
            &temp.path().join("tests/target/generated.ko"),
            "seiyaku Generated { #[test] fn must_not_run() { test::assert(false); } }",
        );
        write(
            &temp.path().join("ambient/failing.ko"),
            "seiyaku Ambient { #[test] fn must_not_run() { test::assert(false); } }",
        );
        let workspace = load_workspace(&temp.path().join("Musubi.toml")).expect("workspace");
        let selected = vec![
            "test/app"
                .parse::<MusubiPackageSelectorV1>()
                .expect("selector"),
        ];
        let lock = lock(
            vec![LockedRootV1 {
                package: selected[0].clone(),
                dependencies: vec![],
            }],
            vec![],
        );
        let cache = MusubiCache::open(temp.path().join("cache")).expect("private test cache");
        let report = execute_workspace_tests_v1(
            Some(&cache),
            &workspace,
            &selected,
            &lock,
            &WorkspaceTestOptionsV1::new(753),
        )
        .expect("directory target must use only its declared source set");
        assert!(report.is_success());
        assert_eq!(report.passed(), 2);
        assert_eq!(
            report
                .targets
                .iter()
                .map(|target| target.source.as_str())
                .collect::<Vec<_>>(),
            ["tests/nested/a.ko", "tests/z.ko"]
        );
    }
    #[test]
    fn directory_target_rejects_hardlinked_sources_before_execution() {
        let temp = tempdir().expect("tempdir");
        let manifest =
            package_manifest("app", "").replace("path = \"tests/unit.ko\"", "path = \"tests\"");
        write(&temp.path().join("Musubi.toml"), &manifest);
        write(&temp.path().join("src/lib.ko"), "module AppLib {}");
        let first = temp.path().join("tests/first.ko");
        write(
            &first,
            "seiyaku Tests { #[test] fn selected() { test::assert(true); } }",
        );
        fs::hard_link(&first, temp.path().join("tests/second.ko")).expect("hardlink test source");
        let workspace = load_workspace(&temp.path().join("Musubi.toml")).expect("workspace");
        let selected = vec![
            "test/app"
                .parse::<MusubiPackageSelectorV1>()
                .expect("selector"),
        ];
        let lock = lock(
            vec![LockedRootV1 {
                package: selected[0].clone(),
                dependencies: vec![],
            }],
            vec![],
        );
        let cache = MusubiCache::open(temp.path().join("cache")).expect("private test cache");
        let error = execute_workspace_tests_v1(
            Some(&cache),
            &workspace,
            &selected,
            &lock,
            &WorkspaceTestOptionsV1::new(753),
        )
        .expect_err("hardlinked test source must fail closed");
        assert!(matches!(error, WorkspaceTestErrorV1::Target(_)));
        assert!(error.to_string().contains("hardlink"));
    }
    #[test]
    fn declared_test_source_accepts_a_bounded_regular_leaf() {
        assert_eq!(ensure_test_runner_platform_supported_v1(), Ok(()));
        let (_temporary, workspace) = declared_source_fixture("module Unit {}");
        let member = workspace
            .members()
            .values()
            .next()
            .expect("workspace member");
        let source = member.package_root.join("tests/unit.ko");
        let mut budget = DeclaredTestSourceBudgetV1::default();
        let declared = read_declared_test_source(
            &member.package_root,
            &source,
            "tests/unit.ko".to_owned(),
            &mut budget,
        )
        .expect("bounded regular declared source");
        assert_eq!(declared.logical_path, "tests/unit.ko");
        assert_eq!(declared.unit.source, "module Unit {}");
        assert_eq!(budget.source_bytes, 14);
    }
    #[test]
    fn declared_source_native_snapshot_rejects_mutation_during_the_read() {
        let (_temporary, workspace) = declared_source_fixture("module Unit {}");
        let member = workspace
            .members()
            .values()
            .next()
            .expect("workspace member");
        let source = member.package_root.join("tests/unit.ko");
        let mut budget = DeclaredTestSourceBudgetV1::default();
        let result = read_declared_test_source_with_reader(
            &member.package_root,
            &source,
            "tests/unit.ko".to_owned(),
            &mut budget,
            |path, file, maximum| {
                // Windows may refuse this write while the original file handle is retained.
                // Unix permits it, and the exact native post-read snapshot must reject it.
                fs::write(path, "module Changed {}")?;
                read_bounded_test_descriptor(file, maximum)
            },
        );
        assert!(matches!(result, Err(WorkspaceTestErrorV1::Target(_))));
        assert_eq!(budget.source_bytes, 0);
    }
    #[test]
    fn bounded_test_descriptor_checks_length_before_allocation() {
        let (_temporary, workspace) = declared_source_fixture("module Unit {}");
        let member = workspace
            .members()
            .values()
            .next()
            .expect("workspace member");
        let mut retained = RetainedFile::open_regular(member.package_root.join("tests/unit.ko"))
            .expect("retained source");
        assert!(read_bounded_test_descriptor(retained.file_mut(), 13).is_err());
        assert_eq!(
            read_bounded_test_descriptor(retained.file_mut(), 14).expect("exact byte bound"),
            b"module Unit {}"
        );
    }
    #[test]
    fn declared_source_admits_the_remaining_aggregate_bound_before_reading() {
        let (_temporary, workspace) = declared_source_fixture("module Unit {}");
        let member = workspace
            .members()
            .values()
            .next()
            .expect("workspace member");
        let source = member.package_root.join("tests/unit.ko");
        let mut budget = DeclaredTestSourceBudgetV1 {
            entries: 0,
            source_bytes: MUSUBI_MAX_SOURCE_PAYLOAD_BYTES_V1 - 14,
        };
        let declared = read_declared_test_source_with_reader(
            &member.package_root,
            &source,
            "tests/unit.ko".to_owned(),
            &mut budget,
            |_, file, maximum| {
                assert_eq!(maximum, 14);
                read_bounded_test_descriptor(file, maximum)
            },
        )
        .expect("exact remaining aggregate bound");
        assert_eq!(declared.unit.source, "module Unit {}");
        assert_eq!(budget.source_bytes, MUSUBI_MAX_SOURCE_PAYLOAD_BYTES_V1);

        budget.source_bytes = MUSUBI_MAX_SOURCE_PAYLOAD_BYTES_V1 - 13;
        let result = read_declared_test_source_with_reader(
            &member.package_root,
            &source,
            "tests/unit.ko".to_owned(),
            &mut budget,
            |_, _, _| panic!("oversized source must fail before invoking its reader"),
        );
        assert!(matches!(result, Err(WorkspaceTestErrorV1::Target(_))));
        assert_eq!(budget.source_bytes, MUSUBI_MAX_SOURCE_PAYLOAD_BYTES_V1 - 13);
    }
    #[test]
    fn declared_source_reads_retained_descriptor_during_path_substitution_and_restore() {
        let (_temporary, workspace) = declared_source_fixture("module Unit {}");
        let member = workspace
            .members()
            .values()
            .next()
            .expect("workspace member");
        let source = member.package_root.join("tests/unit.ko");
        let original = member.package_root.join("tests/original.ko");
        let replacement = member.package_root.join("tests/replacement.ko");
        write(&replacement, "module Evil {}");
        let mut budget = DeclaredTestSourceBudgetV1::default();
        let result = read_declared_test_source_with_reader(
            &member.package_root,
            &source,
            "tests/unit.ko".to_owned(),
            &mut budget,
            |path, file, maximum| {
                if fs::rename(path, &original).is_ok() {
                    fs::rename(&replacement, path)?;
                    let bytes = read_bounded_test_descriptor(file, maximum)?;
                    // The named path temporarily points at another regular file of equal size.
                    // Compiler input must still come from the originally retained descriptor.
                    assert_eq!(bytes, b"module Unit {}");
                    fs::rename(path, &replacement)?;
                    fs::rename(&original, path)?;
                    Ok(bytes)
                } else {
                    // Windows prevents replacement while the non-delete-sharing handle is held.
                    read_bounded_test_descriptor(file, maximum)
                }
            },
        );
        match result {
            Ok(source) => {
                assert_eq!(source.unit.source, "module Unit {}");
                assert_eq!(budget.source_bytes, 14);
            }
            Err(error) => {
                // Platforms that record namespace changes in the native snapshot reject even
                // a restored path; none may expose the temporarily substituted source bytes.
                assert!(matches!(error, WorkspaceTestErrorV1::Target(_)));
                assert_eq!(budget.source_bytes, 0);
            }
        }
    }
    #[test]
    fn retained_test_directory_prevents_or_detects_path_replacement() {
        let (_temporary, workspace) = declared_source_fixture("module Unit {}");
        let member = workspace
            .members()
            .values()
            .next()
            .expect("workspace member");
        let path = member.package_root.join("tests");
        let retained = OwnerDirectory::open(&path).expect("retain test directory");
        let original = retained.entries(1).expect("original inventory");
        let replaced = fs::rename(&path, member.package_root.join("retired-tests"));
        let mut sources = Vec::new();
        let mut collisions = BTreeMap::new();
        let mut budget = DeclaredTestSourceBudgetV1::default();
        if replaced.is_ok() {
            fs::create_dir(&path).expect("replacement directory");
            write(&path.join("unit.ko"), "module Replaced {}");
            assert!(
                collect_declared_test_directory(
                    &member.package_root,
                    &retained,
                    Path::new("tests"),
                    0,
                    &mut collisions,
                    &mut budget,
                    &mut sources
                )
                .is_err()
            );
            assert!(sources.is_empty());
        } else {
            // Native non-delete-sharing handles prevent the namespace mutation on Windows.
            assert_eq!(retained.entries(1).expect("retained inventory"), original);
            collect_declared_test_directory(
                &member.package_root,
                &retained,
                Path::new("tests"),
                0,
                &mut collisions,
                &mut budget,
                &mut sources,
            )
            .expect("unchanged retained directory remains readable");
            assert_eq!(sources.len(), 1);
            assert_eq!(sources[0].unit.source, "module Unit {}");
        }
    }
    #[test]
    fn standalone_test_target_rejects_native_hardlinks() {
        let (_temporary, workspace) = declared_source_fixture("module Unit {}");
        let member = workspace
            .members()
            .values()
            .next()
            .expect("workspace member");
        fs::hard_link(
            member.package_root.join("tests/unit.ko"),
            member.package_root.join("alias.ko"),
        )
        .expect("hardlink fixture");
        assert!(matches!(
            declared_test_sources(member, Path::new("tests/unit.ko")),
            Err(WorkspaceTestErrorV1::Target(_))
        ));
    }
    #[cfg(unix)]
    #[test]
    fn declared_test_source_rejects_a_raced_regular_replacement() {
        let (_temporary, workspace) = declared_source_fixture("module Unit {}");
        let member = workspace
            .members()
            .values()
            .next()
            .expect("workspace member");
        let source = member.package_root.join("tests/unit.ko");
        let replacement = member.package_root.join("tests/replacement.ko");
        write(&replacement, "module Other {}");
        let mut budget = DeclaredTestSourceBudgetV1::default();
        let error = read_declared_test_source_with_reader(
            &member.package_root,
            &source,
            "tests/unit.ko".to_owned(),
            &mut budget,
            |path, file, maximum| {
                fs::remove_file(path)?;
                fs::rename(&replacement, path)?;
                read_bounded_test_descriptor(file, maximum)
            },
        )
        .err()
        .expect("raced declared-source replacement must fail");
        assert!(matches!(error, WorkspaceTestErrorV1::Target(_)));
        assert!(error.to_string().contains("changed"));
        assert_eq!(budget.source_bytes, 0);
    }
    #[cfg(unix)]
    #[test]
    fn declared_test_source_rejects_a_raced_fifo_without_blocking() {
        let (_temporary, workspace) = declared_source_fixture("module Unit {}");
        let member = workspace
            .members()
            .values()
            .next()
            .expect("workspace member");
        let source = member.package_root.join("tests/unit.ko");
        let mut budget = DeclaredTestSourceBudgetV1::default();
        let error = read_declared_test_source_with_reader(
            &member.package_root,
            &source,
            "tests/unit.ko".to_owned(),
            &mut budget,
            |path, file, maximum| {
                fs::remove_file(path)?;
                let status = Command::new("mkfifo").arg(path).status()?;
                if !status.success() {
                    return Err(io::Error::other("mkfifo failed"));
                }
                read_bounded_test_descriptor(file, maximum)
            },
        )
        .err()
        .expect("raced FIFO source must fail without hanging");
        assert!(matches!(error, WorkspaceTestErrorV1::Target(_)));
        assert!(error.to_string().contains("changed"));
        assert_eq!(budget.source_bytes, 0);
    }
    #[test]
    fn declared_test_source_rejects_an_oversized_sparse_leaf() {
        let temp = tempdir().expect("tempdir");
        write(
            &temp.path().join("Musubi.toml"),
            &package_manifest("app", ""),
        );
        write(&temp.path().join("src/lib.ko"), "module AppLib {}");
        let source = temp.path().join("tests/unit.ko");
        fs::create_dir_all(source.parent().expect("test parent")).expect("create tests");
        fs::File::create(&source)
            .expect("create sparse source")
            .set_len(MAX_MODULE_GRAPH_SOURCE_BYTES as u64 + 1)
            .expect("extend sparse source");
        let workspace = load_workspace(&temp.path().join("Musubi.toml")).expect("workspace");
        let member = workspace
            .members()
            .values()
            .next()
            .expect("workspace member");
        let error = declared_test_sources(member, Path::new("tests/unit.ko"))
            .err()
            .expect("oversized test source must fail closed");
        assert!(matches!(error, WorkspaceTestErrorV1::Target(_)));
        assert!(error.to_string().contains("bounded regular file"));
    }
    #[cfg(unix)]
    #[test]
    fn declared_test_directory_rejects_a_fifo_leaf_without_opening_it() {
        let temp = tempdir().expect("tempdir");
        let manifest =
            package_manifest("app", "").replace("path = \"tests/unit.ko\"", "path = \"tests\"");
        write(&temp.path().join("Musubi.toml"), &manifest);
        write(&temp.path().join("src/lib.ko"), "module AppLib {}");
        let fifo = temp.path().join("tests/pipe.ko");
        fs::create_dir_all(fifo.parent().expect("test parent")).expect("create tests");
        assert!(
            Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .expect("run mkfifo")
                .success(),
            "mkfifo must create the adversarial source"
        );
        let workspace = load_workspace(&temp.path().join("Musubi.toml")).expect("workspace");
        let member = workspace
            .members()
            .values()
            .next()
            .expect("workspace member");
        let error = declared_test_sources(member, Path::new("tests"))
            .err()
            .expect("FIFO test source must fail without hanging");
        assert!(matches!(error, WorkspaceTestErrorV1::Target(_)));
        assert!(error.to_string().contains("hardlink or special file"));
    }
}
#[cfg(all(test, not(any(unix, windows))))]
mod unsupported_platform_tests {
    use super::{WorkspaceTestErrorV1, ensure_test_runner_platform_supported_v1};
    #[test]
    fn workspace_test_guard_returns_the_exact_platform_error() {
        assert_eq!(
            ensure_test_runner_platform_supported_v1(),
            Err(WorkspaceTestErrorV1::UnsupportedPlatform)
        );
    }
}
